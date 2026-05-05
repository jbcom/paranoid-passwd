#!/usr/bin/env python3

import errno
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path


ANSI_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)


def clean_screen(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="ignore").replace("\r", "")
    text = ANSI_RE.sub("", text)
    return text


def normalize_match(text: str) -> str:
    return "".join(text.split())


class PtySession:
    def __init__(self, argv, env=None):
        self.argv = argv
        self.env = env or os.environ.copy()
        self.pid = None
        self.fd = None
        self.buffer = bytearray()

    def __enter__(self):
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe(self.argv[0], self.argv, self.env)
        self.pid = pid
        self.fd = fd
        winsize = struct.pack("HHHH", 40, 120, 0, 0)
        termios.tcsetwinsize(self.fd, (40, 120))
        try:
            import fcntl

            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
        except Exception:
            pass
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
        if self.pid is not None:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                os.waitpid(self.pid, 0)
            except OSError:
                pass

    def send(self, data: bytes):
        os.write(self.fd, data)

    def send_text(self, text: str):
        self.send(text.encode("utf-8"))

    def send_tab(self, count: int = 1):
        self.send(b"\t" * count)

    def send_enter(self):
        self.send(b"\r")

    def read_chunk(self):
        try:
            return os.read(self.fd, 65536)
        except OSError as error:
            if error.errno == errno.EIO:
                return b""
            raise

    def read_available(self):
        while True:
            ready, _, _ = select.select([self.fd], [], [], 0)
            if not ready:
                break
            chunk = self.read_chunk()
            if not chunk:
                break
            self.buffer.extend(chunk)

    def checkpoint(self):
        self.read_available()
        self.buffer.clear()

    def wait_for(self, needle: str, timeout: float = 10.0):
        deadline = time.time() + timeout
        normalized_needle = normalize_match(needle)
        while time.time() < deadline:
            self.read_available()
            haystack = clean_screen(self.buffer)
            if normalized_needle in normalize_match(haystack):
                return haystack
            ready, _, _ = select.select([self.fd], [], [], 0.1)
            if ready:
                chunk = self.read_chunk()
                if not chunk:
                    break
                self.buffer.extend(chunk)
        raise AssertionError(
            f"timed out waiting for {needle!r}\n\nTranscript tail:\n{clean_screen(self.buffer)[-4000:]}"
        )

    def wait_exit(self, timeout: float = 5.0) -> int:
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.read_available()
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == self.pid:
                self.pid = None
                if os.WIFEXITED(status):
                    return os.WEXITSTATUS(status)
                if os.WIFSIGNALED(status):
                    raise AssertionError(f"process terminated by signal {os.WTERMSIG(status)}")
                raise AssertionError(f"unexpected wait status {status}")
            time.sleep(0.05)
        raise AssertionError(
            f"process did not exit before timeout\n\nTranscript tail:\n{clean_screen(self.buffer)[-4000:]}"
        )


def run_checked(argv, env):
    completed = subprocess.run(
        argv,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed: {' '.join(argv)}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def generator_flow(binary: Path):
    with PtySession([str(binary), "--tui"]) as session:
        session.wait_for("Generate + Run 7-Layer Audit", timeout=10)
        session.send_tab(64)
        session.send_enter()
        session.wait_for("Primary Password", timeout=20)
        session.send_tab(2)
        session.wait_for("Charset size:", timeout=10)
        session.send_text("q")
        exit_code = session.wait_exit(timeout=5)
        if exit_code != 0:
            raise AssertionError(f"generator TUI exited with {exit_code}")


def vault_flow(binary: Path):
    with tempfile.TemporaryDirectory() as tmpdir_root:
        tmpdir = Path(tmpdir_root)
        vault_path = tmpdir / "vault.sqlite"
        backup_path = vault_path.with_suffix(".backup.json")
        env = os.environ.copy()
        env["PARANOID_MASTER_PASSWORD"] = "correct horse battery staple"
        env["PARANOID_TEST_DEVICE_STORE_DIR"] = str(tmpdir / "device-store")

        run_checked(
            [str(binary), "vault", "--cli", "--path", str(vault_path), "init"],
            env,
        )

        with PtySession([str(binary), "vault", "--path", str(vault_path)], env=env) as session:
            session.wait_for("Controls: Up/Down select items", timeout=10)

            session.send_text("a")
            session.wait_for("Required:title,username,password.", timeout=10)
            session.send_text("GitHub")
            session.send_tab()
            session.send_text("octocat")
            session.send_tab()
            session.send_text("hunter2")
            session.send_tab(3)
            session.send_text("Work")
            session.send_tab()
            session.send_text("work,code")
            session.send_tab()
            session.send_enter()
            session.wait_for("Stored login item", timeout=10)
            session.wait_for("GitHub", timeout=5)

            session.send_text("k")
            session.wait_for("Selected keyslot", timeout=5)
            session.send_text("m")
            session.wait_for("Enroll Mnemonic Slot", timeout=5)
            session.send_text("paper-backup")
            session.send_tab()
            session.send_enter()
            session.wait_for("Mnemonic Recovery Phrase", timeout=10)
            session.send_enter()
            session.wait_for("Selected keyslot", timeout=5)
            session.checkpoint()
            session.send(b"\x1b")
            session.wait_for("Selected login", timeout=5)
            session.checkpoint()

            session.send_text("x")
            session.wait_for("Export Backup", timeout=5)
            session.send_tab()
            session.checkpoint()
            session.send_enter()
            session.wait_for("Selected login", timeout=10)

            session.send_text("q")
            exit_code = session.wait_exit(timeout=5)
            if exit_code != 0:
                raise AssertionError(f"vault TUI exited with {exit_code}")

        if not backup_path.exists():
            raise AssertionError(f"expected backup export at {backup_path}")


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path-to-paranoid-passwd>", file=sys.stderr)
        return 64

    binary = Path(sys.argv[1])
    if not binary.is_file():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 1

    generator_flow(binary)
    print("  PASS  generator TUI binary flow")
    vault_flow(binary)
    print("  PASS  vault TUI binary flow")
    print("\n2 passed, 0 failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
