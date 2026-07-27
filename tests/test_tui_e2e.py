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

TIMEOUT_SCALE = max(1.0, float(os.environ.get("PARANOID_E2E_TIMEOUT_SCALE", "1")))


ANSI_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)


def clean_screen(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="ignore").replace("\r", "")
    text = ANSI_RE.sub("", text)
    return text


def normalize_match(text: str) -> str:
    return "".join(text.split())


# ratatui's crossterm backend is a diff renderer: each `terminal.draw()` only
# re-emits the cells that changed since the last frame, using CSI cursor
# positioning (`\x1b[row;colH`) to jump to each changed run rather than
# repainting the whole screen. `clean_screen`'s naive "strip ANSI, concat
# bytes" approach is correct for content a screen writes fresh every frame,
# but SILENTLY DROPS unchanged cells that share a prefix with a prior
# screen's content at the same position (e.g. two footers that both start
# with "↑↓ move  ⏎ " — ratatui leaves those columns alone, so the raw byte
# stream never re-emits them for the new screen, even though they are still
# genuinely on screen). A naive substring match against the raw stream can
# therefore report a false "not found" for text that IS visibly rendered.
#
# `TerminalGrid` replays the byte stream against a real character grid
# (cursor position + erase-display only — the only CSI kinds ratatui's
# CrosstermBackend emits, per an empirical capture of every screen this
# harness visits) so footer/state-token assertions (P8.5 (b)/(c)) check
# what is actually on screen, not an artifact of the diff-encoding.
# The optional `?` prefix marks a DEC private-mode sequence (e.g. `\x1b[?25l`
# / `\x1b[?25h` to hide/show the cursor, which crossterm's CrosstermBackend
# emits around every draw). Without matching (and discarding) the `?`, those
# 6 literal bytes fall through to `_write()` as if they were printable
# characters, silently corrupting the cursor-column tracking for the rest of
# that escape run — this was a real bug caught while re-baselining P8.5 (see
# git history for the `⊘` glyph false-negative it produced).
CSI_RE = re.compile(r"\x1b\[\??([0-9;]*)([A-Za-z])")


class TerminalGrid:
    def __init__(self, rows: int = 40, cols: int = 120):
        self.rows = rows
        self.cols = cols
        self.grid = [[" "] * cols for _ in range(rows)]
        self.cursor_row = 0
        self.cursor_col = 0
        # `feed()` is called once per `read_available()` batch, and the PTY
        # gives no guarantee that a single escape sequence (or a multi-byte
        # UTF-8 glyph — every box-drawing/arrow char this UI renders is
        # 3 bytes) lands wholly within one `os.read()` chunk. A sequence
        # split across two `feed()` calls used to lose its leading `\x1b`
        # in the second call's decode, so `CSI_RE` never matched it and the
        # raw `[38;20H`-style params fell through to `_write()` as literal
        # on-screen text (observed corrupting the vault-list footer this
        # existed to protect — the exact class of false-negative P8.5 (b)/
        # (c) assertions depend on this grid replay to catch). `_pending`
        # carries forward any bytes that might be the start of such a split
        # sequence so the next `feed()` call sees it complete.
        self._pending = b""

    def feed(self, raw: bytes):
        raw = self._pending + raw
        self._pending = b""
        # If `raw` ends mid-escape-sequence (an ESC with no terminating
        # letter yet found) or mid-UTF-8-codepoint, hold the incomplete
        # tail back rather than decoding it lossily.
        esc_start = raw.rfind(b"\x1b")
        if esc_start != -1 and not re.search(
            rb"\x1b\[\??[0-9;]*[A-Za-z]", raw[esc_start:]
        ):
            # An ESC near the end with no complete CSI terminator yet —
            # could still be arriving. Hold back from the ESC onward.
            self._pending = raw[esc_start:]
            raw = raw[:esc_start]
        else:
            # No dangling ESC; check for a truncated trailing UTF-8
            # sequence (a lead byte whose continuation bytes haven't
            # arrived yet) and hold that back too.
            trim = 0
            for back in range(1, min(4, len(raw)) + 1):
                lead = raw[-back]
                if lead & 0b1100_0000 == 0b1000_0000:
                    continue  # continuation byte, keep scanning backward
                needed = (
                    1
                    if lead < 0x80
                    else 2
                    if lead & 0b1110_0000 == 0b1100_0000
                    else 3
                    if lead & 0b1111_0000 == 0b1110_0000
                    else 4
                    if lead & 0b1111_1000 == 0b1111_0000
                    else 1
                )
                if needed > back:
                    trim = back
                break
            if trim:
                self._pending = raw[len(raw) - trim :]
                raw = raw[: len(raw) - trim]
        text = raw.decode("utf-8", errors="ignore").replace("\r", "")
        pos = 0
        for match in CSI_RE.finditer(text):
            # Plain text between the previous escape sequence and this one.
            self._write(text[pos : match.start()])
            params, kind = match.group(1), match.group(2)
            if kind == "H":
                parts = params.split(";") if params else []
                row = int(parts[0]) if len(parts) > 0 and parts[0] else 1
                col = int(parts[1]) if len(parts) > 1 and parts[1] else 1
                self.cursor_row = max(0, min(self.rows - 1, row - 1))
                self.cursor_col = max(0, min(self.cols - 1, col - 1))
            elif kind == "J":
                # ED — erase in display. `2`/absent-before-CSI-2J clears the
                # whole screen; ratatui issues this once on `terminal.clear()`
                # at startup. Any mode value clears the whole grid here —
                # conservative, and this harness never needs partial-erase
                # fidelity.
                self.grid = [[" "] * self.cols for _ in range(self.rows)]
            # `m` (SGR) and any other CSI kind carry no grid-position effect
            # for this harness's purposes; skip silently.
            pos = match.end()
        self._write(text[pos:])

    def _write(self, text: str):
        for char in text:
            if char == "\n":
                self.cursor_row = min(self.rows - 1, self.cursor_row + 1)
                self.cursor_col = 0
                continue
            if self.cursor_row >= self.rows:
                continue
            if self.cursor_col < self.cols:
                self.grid[self.cursor_row][self.cursor_col] = char
                self.cursor_col += 1

    def render_text(self) -> str:
        return "\n".join("".join(row) for row in self.grid)


class PtySession:
    def __init__(self, argv, env=None):
        self.argv = argv
        self.env = env or os.environ.copy()
        self.pid = None
        self.fd = None
        self.buffer = bytearray()
        # P8.5: a live terminal-grid replay of the same byte stream, so
        # footer/state-token assertions see the true current screen content
        # instead of the raw-byte-concat artifacts `clean_screen` produces
        # for cells ratatui's diff renderer left unchanged (see
        # `TerminalGrid`'s docstring). `_grid_consumed` tracks how much of
        # `self.buffer` has already been fed in, so re-feeding is O(new
        # bytes) even though `read_available`/`wait_for` keep appending to
        # the same growing `self.buffer`.
        self.grid = TerminalGrid()
        self._grid_consumed = 0

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
        self.sync_grid()
        self.buffer.clear()
        self._grid_consumed = 0

    def sync_grid(self):
        """Feeds any bytes appended to `self.buffer` since the last sync
        into `self.grid`, so `self.grid.render_text()` reflects the true
        current screen. Idempotent — safe to call as often as needed."""
        if self._grid_consumed < len(self.buffer):
            self.grid.feed(bytes(self.buffer[self._grid_consumed :]))
            self._grid_consumed = len(self.buffer)

    def wait_for_screen_text(self, needle: str, timeout: float = 10.0) -> str:
        """Like `wait_for`, but matches against the replayed terminal grid
        (`self.grid.render_text()`) instead of the raw concatenated byte
        stream — see `TerminalGrid`'s docstring for why this matters for
        content ratatui's diff renderer left un-re-emitted. Use this (not
        `wait_for`) for footer/state-token assertions; `wait_for` remains
        correct and unchanged for the freshly-written content every other
        flow in this file already asserts on."""
        deadline = time.time() + timeout * TIMEOUT_SCALE
        normalized_needle = normalize_match(needle)
        while time.time() < deadline:
            self.read_available()
            self.sync_grid()
            haystack = self.grid.render_text()
            if normalized_needle in normalize_match(haystack):
                return haystack
            select.select([self.fd], [], [], 0.1)
        raise AssertionError(
            f"timed out waiting for {needle!r} on the terminal grid\n\n"
            f"Grid tail:\n{self.grid.render_text()[-4000:]}"
        )

    def wait_for(self, needle: str, timeout: float = 10.0):
        # Slow shared CI runners stretch debug-build latencies (Argon2id at
        # 256 MiB, SQLite fsyncs) past wall-clock budgets tuned on dev
        # machines; PARANOID_E2E_TIMEOUT_SCALE stretches every wait uniformly
        # without loosening what must render.
        deadline = time.time() + timeout * TIMEOUT_SCALE
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
        deadline = time.time() + timeout * TIMEOUT_SCALE
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


def assert_footer(session: "PtySession", expected: str, timeout: float = 5.0):
    """P8.5 (c): the footer's exact contextual text must appear verbatim in
    the current screen (ia.md §5 per-screen footer strings), asserted
    against the real ratatui render captured through the PTY — replayed onto
    a terminal grid (`wait_for_screen_text`) rather than matched against the
    raw byte stream, since ratatui's diff renderer does not re-emit cells
    that are unchanged from the previous screen (e.g. two footers sharing a
    "↑↓ move  ⏎ " prefix), which a naive substring match over the raw stream
    would miss. See `assert_status_token_present` for the (b) monochrome-
    glyph pairing check."""
    session.wait_for_screen_text(expected, timeout=timeout)


def assert_status_token_present(session: "PtySession", glyph: str, timeout: float = 5.0):
    """P8.5 (b) monochrome-pass: `TerminalGrid.render_text()` reconstructs
    the true on-screen content with all ANSI (including color) already
    stripped, so a successful match here proves the state token survives
    with zero color — exactly system.md §1.1 "the test" ("strip all color —
    the product must remain fully usable... if a state reads only by its
    color, that is a defect")."""
    session.wait_for_screen_text(glyph, timeout=timeout)


def cross_trust_gate(session: "PtySession"):
    """Every TUI session now opens on the S1 trust gate (ia.md §2/§3:
    "trust precedes everything... no path skips S1") before the screen the
    old tests started on. `<enter>` runs the self-check and lands on
    Verified; `<enter>` again is S3's "Continue", handing control to the
    real destination screen."""
    session.wait_for("Verify this copy", timeout=10)
    session.send_enter()
    session.wait_for("Verified", timeout=10)
    session.send_enter()


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
        # Wizard redesign (evidence.md finding #6): the launch row is now a
        # single "▸ Generate" accent action (theme::accent_action,
        # ICON_ACTION) rather than the old "Generate + Run 7-Layer Audit"
        # label. The underlying FocusField order/count is unchanged, so the
        # same tab count still lands on Launch.
        session.wait_for("▸ Generate", timeout=10)
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
        # The S1 trust-gate marker (ia.md §3 short-circuit) defaults to a
        # file under $HOME; every PTY flow here must never touch the real
        # invoking user's home directory as a side effect of running tests.
        env["PARANOID_TEST_TRUST_MARKER_DIR"] = str(tmpdir / "trust-marker")

        run_checked(
            [str(binary), "vault", "--cli", "--path", str(vault_path), "init"],
            env,
        )

        with PtySession([str(binary), "vault", "--path", str(vault_path)], env=env) as session:
            cross_trust_gate(session)
            session.wait_for("Vault open", timeout=10)

            # P8.5 (c): the H (vault list) footer must match ia.md §5's
            # list-pane footer string exactly (crates/paranoid-cli/src/
            # vault_tui/footer.rs `contextual_footer` for `Screen::Vault`
            # outside search mode) — asserted against the real ratatui
            # render, not the unit-level string constant.
            assert_footer(session, "↑↓ move  ⏎ open  n new  / find  ? all keys  q quit")

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

            # P8.V.5: the working "ways in" (keyslots) navigation key was
            # rebound from `k` to `w` so it matches what the footer/`?`
            # overlay have always advertised (crates/paranoid-cli/src/
            # vault_tui/screen_state.rs `handle_vault_key`).
            session.send_text("w")
            # "Keyslot Detail" is the real panel title on `Screen::Keyslots`
            # (crates/paranoid-cli/src/vault_tui/panel_rendering.rs
            # `keyslots_panel`); "Selected keyslot" only ever appears as a
            # wrong-keyslot-type error status ("Selected keyslot is not
            # mnemonic recovery."/"...not certificate-wrapped.") that this
            # flow never triggers, so it can never actually match here.
            # The title's cells are unchanged from the frame before this
            # transition landed (P8.5 (b): ratatui's diff renderer only
            # re-emits changed cells), so `wait_for`'s raw-byte-concat
            # (`clean_screen`) can false-negative on it even though it is
            # genuinely on screen — use the grid-replay assertion instead.
            session.wait_for_screen_text("Keyslot Detail", timeout=5)
            session.send_text("m")
            session.wait_for("Enroll Mnemonic Slot", timeout=5)
            session.send_text("paper-backup")
            session.send_tab()
            session.send_enter()
            session.wait_for("Mnemonic Recovery Phrase", timeout=10)
            session.send_enter()
            session.wait_for_screen_text("Keyslot Detail", timeout=5)
            session.checkpoint()
            session.send(b"\x1b")
            # Back on `Screen::Vault`'s side detail panel with the GitHub
            # item still selected (`detail_panel` in panel_rendering.rs) —
            # "Selected login" was a real heading in the pre-P8 monolithic
            # vault_tui.rs, removed by the redesign; the current panel shows
            # the item's own title instead. Grid-replay for the same P8.5
            # (b) unchanged-cell reason as above.
            session.wait_for_screen_text("GitHub", timeout=5)
            session.checkpoint()

            session.send_text("x")
            session.wait_for("Export Backup", timeout=5)
            session.send_tab()
            session.checkpoint()
            session.send_enter()
            session.wait_for_screen_text("GitHub", timeout=10)

            session.send_text("q")
            exit_code = session.wait_exit(timeout=5)
            if exit_code != 0:
                raise AssertionError(f"vault TUI exited with {exit_code}")

        if not backup_path.exists():
            raise AssertionError(f"expected backup export at {backup_path}")

        # Second PTY session against the same vault_path: proves the login
        # and mnemonic keyslot added above survive a fresh process restart
        # (a new unlock, not the same in-memory App instance).
        with PtySession([str(binary), "vault", "--path", str(vault_path)], env=env) as restarted:
            cross_trust_gate(restarted)
            restarted.wait_for("Vault open", timeout=10)
            restarted.wait_for("GitHub", timeout=5)

            restarted.send_text("w")
            restarted.wait_for("Ways in (2)", timeout=5)

            restarted.send_text("q")
            exit_code = restarted.wait_exit(timeout=5)
            if exit_code != 0:
                raise AssertionError(
                    f"restarted vault TUI exited with {exit_code}"
                )


def add_login_item(session: PtySession, title: str, username: str, password: str):
    session.send_text("a")
    session.wait_for("Required:title,username,password.", timeout=10)
    session.send_text(title)
    session.send_tab()
    session.send_text(username)
    session.send_tab()
    session.send_text(password)
    session.send_tab(3)
    session.send_text("Work")
    session.send_tab()
    session.send_text("work,code")
    session.send_tab()
    session.send_enter()
    session.wait_for("Stored login item", timeout=10)
    session.wait_for(title, timeout=5)


def wrong_password_unlock_flow(binary: Path):
    # `p`/`m`/`b`/`c` are unconditional unlock-mode-switch shortcuts on the
    # UnlockBlocked screen (see `handle_unlock_blocked_key`), so a secret
    # typed through this PTY layer must avoid those letters or it would
    # silently switch away from Password mode mid-entry.
    correct_password = "dragonsteelfortress9"

    with tempfile.TemporaryDirectory() as tmpdir_root:
        tmpdir = Path(tmpdir_root)
        vault_path = tmpdir / "vault.sqlite"
        env = os.environ.copy()
        env["PARANOID_MASTER_PASSWORD"] = correct_password
        env["PARANOID_TEST_DEVICE_STORE_DIR"] = str(tmpdir / "device-store")
        # The S1 trust-gate marker (ia.md §3 short-circuit) defaults to a
        # file under $HOME; every PTY flow here must never touch the real
        # invoking user's home directory as a side effect of running tests.
        env["PARANOID_TEST_TRUST_MARKER_DIR"] = str(tmpdir / "trust-marker")

        run_checked(
            [str(binary), "vault", "--cli", "--path", str(vault_path), "init"],
            env,
        )

        wrong_env = env.copy()
        wrong_env["PARANOID_MASTER_PASSWORD"] = "totally wrong password"

        with PtySession(
            [str(binary), "vault", "--path", str(vault_path)], env=wrong_env
        ) as session:
            cross_trust_gate(session)
            # A wrong `PARANOID_MASTER_PASSWORD` fails the automatic unlock
            # attempted on process start, landing the TUI on the seal's
            # UnlockBlocked posture screen (read_vault_header still succeeds,
            # so the on-disk format is confirmed intact, but the unlock
            # itself is refused). brand.md §3(d): the calm-conversation
            # rewrite, not "Unlock blocked: ..." implementation vocabulary.
            session.wait_for("That didn't open the vault", timeout=10)
            session.wait_for("Unlock Vault", timeout=5)

            # Recover within the same session: Tab from the unlock-mode
            # field to the password field, type the correct secret, and
            # submit.
            session.send_tab()
            session.send_text(correct_password)
            session.send_tab()
            session.send_enter()
            session.wait_for("Vault open", timeout=10)
            session.wait_for("No vault items yet", timeout=5)

            add_login_item(session, "GitHub", "octocat", "hunter2")

            session.send_text("q")
            exit_code = session.wait_exit(timeout=5)
            if exit_code != 0:
                raise AssertionError(
                    f"wrong-password recovery TUI exited with {exit_code}"
                )


def recovery_secret_rotation_flow(binary: Path):
    initial_secret = "dragonsteelfortress9"
    rotated_secret = "graniteharborsentinel7"

    with tempfile.TemporaryDirectory() as tmpdir_root:
        tmpdir = Path(tmpdir_root)
        vault_path = tmpdir / "vault.sqlite"
        env = os.environ.copy()
        env["PARANOID_TEST_DEVICE_STORE_DIR"] = str(tmpdir / "device-store")
        # The S1 trust-gate marker (ia.md §3 short-circuit) defaults to a
        # file under $HOME; every PTY flow here must never touch the real
        # invoking user's home directory as a side effect of running tests.
        env["PARANOID_TEST_TRUST_MARKER_DIR"] = str(tmpdir / "trust-marker")

        with PtySession(
            [str(binary), "vault", "--path", str(vault_path)], env=env
        ) as session:
            cross_trust_gate(session)
            # No vault exists yet at this path: the P2.3 environment-approval
            # screen (ia.md S4 "Create vault") is the first thing shown after
            # the trust gate. <enter> accepts the default (Accept) choice,
            # landing on the reused unlock/init form pre-set to Password
            # mode.
            session.wait_for("Create vault", timeout=10)
            session.send_enter()
            session.wait_for("Unlock Vault", timeout=5)
            session.send_tab()
            session.send_text(initial_secret)
            session.send_tab()
            session.send_enter()
            session.wait_for("Vault initialized", timeout=10)
            session.wait_for("No vault items yet", timeout=5)

            # P8.V.5: navigate to keyslots ("ways in") with `w`, not the
            # stale `k` binding — see the note on the earlier occurrence.
            session.send_text("w")
            session.wait_for("Ways in", timeout=5)

            # P8.5 (c) / P8.V.4: S10 (ia.md "Ways in") footer, exact string
            # (crates/paranoid-cli/src/vault_tui/footer.rs
            # `contextual_footer` for `Screen::Keyslots`) — `k mechanics`
            # toggles the S10d drill-down; adding a way in has its own
            # `m`/`b`/`c` keys documented behind `? all keys`, not a base
            # `a add` binding.
            assert_footer(session, "↑↓ move  k mechanics  x remove  ? all keys  ⎋ back")
            session.checkpoint()

            session.send_text("p")
            session.wait_for("Rotate Recovery Secret", timeout=5)
            # The new-secret field is already focused on entry, so no
            # leading Tab (unlike the UnlockBlocked form, which starts on
            # the mode selector).
            session.send_text(rotated_secret)
            session.send_tab()
            session.send_text(rotated_secret)
            session.send_tab()
            session.checkpoint()
            session.send_enter()
            # `submit_rotate_recovery_secret` returns to `Screen::Keyslots`
            # on success — same "Keyslot Detail" panel title as above, not
            # the "Selected keyslot" error-status substring. Grid-replay
            # assertion for the same P8.5 (b) unchanged-cell reason noted
            # above (the preceding `checkpoint()` only resets what this
            # harness has consumed, not what ratatui considers "changed").
            session.wait_for_screen_text("Keyslot Detail", timeout=10)

            session.send_text("q")
            exit_code = session.wait_exit(timeout=5)
            if exit_code != 0:
                raise AssertionError(
                    f"recovery-secret rotation TUI exited with {exit_code}"
                )

        # Prove the rotated secret works by exec'ing a fresh CLI-mode
        # process against the same vault path.
        rotated_env = env.copy()
        rotated_env["PARANOID_MASTER_PASSWORD"] = rotated_secret
        run_checked(
            [str(binary), "vault", "--cli", "--path", str(vault_path), "list"],
            rotated_env,
        )

        # The pre-rotation secret must no longer unlock the vault.
        stale_env = env.copy()
        stale_env["PARANOID_MASTER_PASSWORD"] = initial_secret
        completed = subprocess.run(
            [str(binary), "vault", "--cli", "--path", str(vault_path), "list"],
            env=stale_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode == 0:
            raise AssertionError(
                "pre-rotation recovery secret unexpectedly still unlocks the vault"
            )


def panic_lock_footer_and_monochrome_flow(binary: Path):
    """P8.5 (b) + (c): fires the real Ctrl+L panic-lock hotkey through the
    PTY and asserts, against the actual ratatui render (not the Rust unit
    constant):

      - S14 (just-locked) shows the ia.md §5 minimal footer verbatim and
        the `⊘` locked state token — with color already stripped by
        `clean_screen`, so a passing match IS the monochrome-pass proof
        (system.md §1.1 "the test").
      - Any further interaction reverts to the ordinary S15 footer
        (recovery paths reachable again via `?`), and the `⊘` token stays
        present — the screen (not just the just-locked transient) carries
        the token.
    """
    with tempfile.TemporaryDirectory() as tmpdir_root:
        tmpdir = Path(tmpdir_root)
        vault_path = tmpdir / "vault.sqlite"
        env = os.environ.copy()
        env["PARANOID_MASTER_PASSWORD"] = "correct horse battery staple"
        env["PARANOID_TEST_DEVICE_STORE_DIR"] = str(tmpdir / "device-store")
        env["PARANOID_TEST_TRUST_MARKER_DIR"] = str(tmpdir / "trust-marker")

        run_checked(
            [str(binary), "vault", "--cli", "--path", str(vault_path), "init"],
            env,
        )

        with PtySession([str(binary), "vault", "--path", str(vault_path)], env=env) as session:
            cross_trust_gate(session)
            session.wait_for("Vault open", timeout=10)
            session.checkpoint()

            # Ctrl+L: the panic / quick-lock hotkey (form-feed byte 0x0c;
            # crossterm raw mode maps this to KeyCode::Char('l') +
            # KeyModifiers::CONTROL — see docs/guides/tui.md "Panic / quick-
            # lock hotkey").
            session.send(b"\x0c")
            session.wait_for("Locked.", timeout=10)

            # S14: the minimal footer, no `?` recovery door, right after the
            # lock event — ia.md §5.
            assert_footer(session, "⏎ unlock  q quit")
            # ia.md §1's title-region state token; system.md §1.1's
            # monochrome test — the glyph, not a color, marks "locked."
            assert_status_token_present(session, "⊘")
            session.checkpoint()

            # Any interaction (Tab moves off the mode selector) clears
            # just_locked and restores the ordinary S15 footer.
            session.send_tab()
            assert_footer(session, "⏎ unlock  ? other ways in  ⎋ back")
            assert_status_token_present(session, "⊘")

            session.send_text("q")
            exit_code = session.wait_exit(timeout=5)
            if exit_code != 0:
                raise AssertionError(f"panic-lock footer TUI exited with {exit_code}")


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
    print("  PASS  vault TUI binary flow (adds login + mnemonic, restart persistence)")
    wrong_password_unlock_flow(binary)
    print("  PASS  wrong-password unlock blocked, then recovered")
    recovery_secret_rotation_flow(binary)
    print("  PASS  recovery-secret rotation flow")
    panic_lock_footer_and_monochrome_flow(binary)
    print("  PASS  panic-lock footer + monochrome state-token flow")
    print("\n5 passed, 0 failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
