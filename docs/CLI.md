---
title: CLI
updated: 2026-04-14
status: current
domain: technical
---

# paranoid-passwd CLI

The `paranoid-passwd` command-line tool uses the same C cryptographic
core as the web app (`paranoid.c`, `sha256_compact.c`) with a POSIX
platform backend (`getrandom(2)` / `getentropy(3)`). It ships as a
statically-linked binary per target with sigstore-signed build
provenance.

## Install

### Verify, then extract (recommended)

```bash
# 1. Download the tarball and checksums for your platform
gh release download paranoid-passwd-v3.2.0 \
    --repo jbcom/paranoid-passwd \
    -p 'paranoid-passwd-3.2.0-darwin-arm64.tar.gz' \
    -p 'checksums.txt'

# 2. Verify the sigstore-signed provenance attestation
gh attestation verify paranoid-passwd-3.2.0-darwin-arm64.tar.gz \
    --owner jbcom

# 3. Verify SHA-256 matches the published checksums
grep 'paranoid-passwd-3.2.0-darwin-arm64.tar.gz' checksums.txt | shasum -a 256 -c -

# 4. Extract and run
tar xzf paranoid-passwd-3.2.0-darwin-arm64.tar.gz
./paranoid-passwd-3.2.0-darwin-arm64/paranoid-passwd --version
```

The `gh attestation verify` step fails unless the tarball was built by
the paranoid-passwd release workflow, signed by sigstore, and logged to
Rekor. No trust in the download URL, the maintainer's key, or TLS — the
verification walks the sigstore chain all the way to the signed build
provenance.

### Homebrew tap

```bash
brew install <tap-owner>/tap/paranoid-passwd
```

The tap repository (managed separately) pulls the attested GitHub
Release tarballs and records their SHA-256 checksums in the formula, so
the tap install chain inherits the upstream provenance guarantee.

### Wolfi apk

For Wolfi-based container images, the existing `melange.yaml` + `apko.yaml`
pipeline produces the same binary in apk form alongside the WASM artifact.

## Usage

```
paranoid-passwd [OPTIONS]

  -l, --length N           Password length (1..256, default 32)
  -c, --count N            Number of passwords (1..10, default 1)
  -s, --charset SET        Character set: built-in name or literal
                           Names: alnum | alnum-symbols | full | hex
                           Default: full (printable ASCII, 94 chars)
      --require-lower N    Minimum lowercase chars (default 0)
      --require-upper N    Minimum uppercase chars (default 0)
      --require-digit N    Minimum digit chars (default 0)
      --require-symbol N   Minimum symbol chars (default 0)
      --no-audit           Skip the statistical audit
      --quiet              Suppress stage output on stderr
  -V, --version            Print version info and exit
  -h, --help               Print help and exit
```

### Output contract

- **stdout:** N lines, each one generated password, `\n`-terminated. Nothing else.
- **stderr:** Audit stage progress (unless `--quiet`), final `audit: PASS` or `audit: FAIL`.
- **Audit scope:** the audit always runs on a fresh, library-generated
  unconstrained sample (500 passwords at the requested length). It is a
  self-test of the underlying CSPRNG and rejection sampling, not a
  validation of any specific user-visible password. When `--require-*`
  constraints are active, your visible passwords are filtered through
  the same audited generator — the audit confirms the source is sound;
  constraints inherit that soundness over the matching subset.
- **Exit codes:**
    - `0` success
    - `1` argument error or impossible constraints
    - `2` OS CSPRNG failure
    - `3` statistical audit detected bias
    - `4` internal error (e.g. out of memory)
    - `5` exhausted attempts meeting `--require-*` constraints

Because the password is only written to stdout, `paranoid-passwd > pw.txt`
captures it cleanly while leaving the audit trail visible on the terminal.

### Examples

```bash
# Default: 32-char full-ASCII with audit
paranoid-passwd

# Fast bulk generation for scripts
paranoid-passwd --length 24 --count 10 --no-audit --quiet

# Hex string (64 chars)
paranoid-passwd --charset hex --length 64

# Policy-compliant: min 2 of each type
paranoid-passwd --require-lower 2 --require-upper 2 \
                --require-digit 2 --require-symbol 2

# Pipe to clipboard on macOS
paranoid-passwd --quiet | pbcopy

# Fail loudly in CI if audit regresses
paranoid-passwd > /dev/null || exit $?
```

## What the CLI does NOT do

- Write passwords to disk (redirect stdout yourself)
- Read config files or environment variables for options
- Render colors, spinners, or TTY-adaptive output
- Offer an interactive prompt or REPL
- Touch the network — CLI is fully offline

## Artifact contract

Release artifacts follow a stable naming scheme so downstream packagers
(the Homebrew tap, Wolfi apk, third-party mirrors) can consume them
predictably:

```
paranoid-passwd-${VERSION}-${OS}-${ARCH}.tar.gz
checksums.txt
```

Where `OS` is `linux` or `darwin` and `ARCH` is `amd64` or `arm64`. Each
tarball contains a directory `paranoid-passwd-${VERSION}-${OS}-${ARCH}/`
with the binary, `LICENSE`, and `README.md`.

## Build from source

```bash
# Native for your current platform.
# The CLI binary itself links platform_posix.c + sha256_compact.c —
# zero OpenSSL dependency. The native test_native binary additionally
# links OpenSSL so the SHA-256 implementations are cross-validated
# against NIST CAVP vectors in CI.
cmake -B build/native -DCMAKE_BUILD_TYPE=Release
cmake --build build/native --target paranoid_cli
./build/native/paranoid-passwd --version

# Cross-compile to another target (requires Zig)
cmake -B build/cli-linux-arm64 \
    -DCMAKE_TOOLCHAIN_FILE=cmake/zig-cross.cmake \
    -DPARANOID_TARGET=aarch64-linux-musl \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build/cli-linux-arm64 --target paranoid_cli
```

See `docs/BUILD.md` for the full build reference.
