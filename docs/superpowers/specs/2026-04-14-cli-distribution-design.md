---
title: paranoid-passwd CLI — Design Spec
updated: 2026-04-14
status: approved
domain: technical
---

# paranoid-passwd CLI — Design Spec

## Purpose

Ship `paranoid-passwd` as a signed, attested, cross-platform CLI alongside
the existing browser-deployed WASM product. Same crypto core, same audit,
distributed via GitHub Releases with sigstore provenance so users can
verify-then-run without trusting `curl | bash`.

## Scope

**In scope:**
- One new executable (`paranoid-passwd`) in this repo, sharing the existing C core.
- Flags-in, stages-to-stderr, password-to-stdout UX.
- Cross-compilation to linux/{amd64,arm64} and darwin/{amd64,arm64} via Zig.
- GitHub Release pipeline producing tarballs + checksums + SLSA provenance.
- CLI-specific docs and tests.

**Out of scope:**
- Interactive TUI or REPL.
- Config files or environment-variable-driven configuration.
- Clipboard integration.
- Windows support (deferred; add later if requested).
- A separate library API for other languages — `paranoid.h` is already the contract.
- The Homebrew tap formula itself (lives in a separate tap repo managed by another project; we only guarantee the artifact contract).

## Non-Goals (Explicit)

- No `--output FILE` — users redirect stdout themselves. Disk-writing adds
  attack surface (file perms, swap, atomic rename) for no security benefit.
- No `--json` in v1. Add if asked; not a design lock-in.
- No colors, spinners, or TTY-adaptive output. Output is the same whether
  stdout is a terminal or a pipe.
- No OpenSSL in the CLI binary. Uses the same `sha256_compact.c` the WASM
  build uses, and `getrandom(2)` / `getentropy(3)` for CSPRNG.

## Architecture

### Layering

```
┌──────────────────────────────────────────────────┐
│  src/cli.c  (NEW, ~250 LOC)                      │
│  - getopt_long argument parsing                  │
│  - stage callbacks → stderr formatting           │
│  - final password → stdout                       │
│  - exit-code mapping                             │
└───────────────────────┬──────────────────────────┘
                        │ uses paranoid.h only
                        ▼
┌──────────────────────────────────────────────────┐
│  libparanoid (unchanged)                         │
│  - src/paranoid.c                                │
│  - include/paranoid.h                            │
└───────────────────────┬──────────────────────────┘
                        │ uses paranoid_platform.h
                        ▼
┌──────────────────────────────────────────────────┐
│  src/platform_posix.c  (NEW, ~40 LOC)            │
│  - paranoid_platform_random → getrandom/getentropy │
│  - paranoid_platform_sha256 → sha256_compact.c    │
└──────────────────────────────────────────────────┘
```

Three new files, zero edits to existing crypto code. The CLI is a
consumer of the public API defined in `paranoid.h`.

### Why a third platform backend?

Today there are two: `platform_native.c` (OpenSSL, used by the native
test binaries) and `platform_wasm.c` (WASI + `sha256_compact.c`, used by
the WASM build). The CLI wants:

- No OpenSSL dependency (static, portable binary; no DLL hell)
- Same audited SHA-256 the WASM build uses
- A real CSPRNG syscall, not WASI

So we add `platform_posix.c` that mixes the two: OS-native RNG via
`getrandom(2)` on Linux / `getentropy(3)` on macOS, plus reuse of
`sha256_compact.c` for hashing. The existing `platform_native.c` is kept
intact for OpenSSL-based test cross-validation.

CMake selects the backend at configure time:
- WASM toolchain → `platform_wasm.c` + `sha256_compact.c`
- Test build (default native) → `platform_native.c` (OpenSSL)
- CLI build → `platform_posix.c` + `sha256_compact.c`

This gives us three test paths:
1. WASM: `platform_wasm.c` + `sha256_compact` (runs in browser + E2E)
2. Native-OpenSSL: `platform_native.c` (runs `test_native`, cross-checks SHA-256)
3. Native-POSIX: `platform_posix.c` + `sha256_compact` (the CLI and its tests)

SHA-256 outputs from (2) and (3) are compared byte-for-byte in CI — a
free cross-implementation check against the FIPS 180-4 reference.

## CLI Surface

### Flags

```
paranoid-passwd [OPTIONS]

  -l, --length N           Password length (1..256, default 32)
  -c, --count N            Number of passwords (1..10, default 1)
  -s, --charset SET        Character set: name or literal
                           Built-in names: alnum | alnum-symbols | full | hex
                           Default: full
      --require-lower N    Minimum lowercase chars (default 0)
      --require-upper N    Minimum uppercase chars (default 0)
      --require-digit N    Minimum digit chars (default 0)
      --require-symbol N   Minimum symbol chars (default 0)
      --no-audit           Skip the statistical audit
      --quiet              Suppress stage output on stderr
  -V, --version            Print version info and exit
  -h, --help               Print help and exit
```

### Built-in charset names

| Name | Chars | Size |
|---|---|---|
| `alnum` | `A-Za-z0-9` | 62 |
| `alnum-symbols` | `A-Za-z0-9` plus `!@#$%^&*-_=+[]{};:,.?/` | 83 |
| `full` (default) | all printable ASCII 33–126 | 94 |
| `hex` | `0-9a-f` | 16 |

A literal charset is any string of printable ASCII; duplicates are
deduplicated by `paranoid_validate_charset()`.

### Output contract

**stdout (always):** N lines, one password each, terminated with `\n`.
Exactly this. Nothing else goes here. `paranoid-passwd > pw.txt` works.

**stderr (when not `--quiet`):**
```
[1/7] generate         OK
[2/7] sha256           OK  e3b0c442...b7852b855
[3/7] chi-squared      OK  chi2=87.42 df=93 p=0.6512
[4/7] serial-corr      OK  r=-0.0123
[5/7] collisions       OK  0/500
[6/7] entropy          OK  209.75 bits  (NIST: memorized OK, high-value OK, crypto-equiv OK)
[7/7] patterns         OK
audit: PASS
```

On audit failure: same format through the failing stage, then
`audit: FAIL (chi-squared)` or similar, then exit 3. The password still
goes to stdout because the user asked for one — but the exit code and
stderr make the failure unmissable.

`--count N` runs the audit on the batch (as the web app does), not per
password.

`--no-audit` produces only `[1/2] generate OK` / `[2/2] sha256 OK` /
`audit: skipped` on stderr.

### Version output

```
$ paranoid-passwd --version
paranoid-passwd 3.2.0
build: 2026-04-14T20:00:00Z
commit: ff5267e
zig: 0.13.0
sha256: compact (FIPS 180-4 reference)
rng: getrandom(2) [linux] | getentropy(3) [darwin]
```

Fields populated at build time via `-D` defines passed from CMake.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, audit pass (or `--no-audit` used) |
| 1 | Argument error (e.g. `--length 0`, unknown flag) |
| 2 | CSPRNG failure (maps to `paranoid_generate` returning -1) |
| 3 | Audit failed |

## Build System

### CMake additions

```cmake
# In CMakeLists.txt, after existing targets:

option(PARANOID_BUILD_CLI "Build the paranoid-passwd CLI" ON)

if(PARANOID_BUILD_CLI AND NOT CMAKE_CROSSCOMPILING_TO_WASM)
    add_library(paranoid_cli_core STATIC
        src/paranoid.c
        src/platform_posix.c
        src/sha256_compact.c)
    target_include_directories(paranoid_cli_core PUBLIC include)

    add_executable(paranoid-cli src/cli.c)
    target_link_libraries(paranoid-cli PRIVATE paranoid_cli_core)
    set_target_properties(paranoid-cli PROPERTIES
        OUTPUT_NAME paranoid-passwd)

    # Pass build metadata
    target_compile_definitions(paranoid-cli PRIVATE
        PARANOID_CLI_VERSION="${PROJECT_VERSION}"
        PARANOID_CLI_BUILD_COMMIT="${PARANOID_BUILD_COMMIT}"
        PARANOID_CLI_BUILD_DATE="${PARANOID_BUILD_DATE}")

    install(TARGETS paranoid-cli DESTINATION bin)
endif()
```

### Cross-compilation toolchain

New file `cmake/zig-cross.cmake`. Invoked as:

```
cmake -B build/cli-linux-amd64 \
    -DCMAKE_TOOLCHAIN_FILE=cmake/zig-cross.cmake \
    -DPARANOID_TARGET=x86_64-linux-musl \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build/cli-linux-amd64 --target paranoid-cli
```

Contents (~25 LOC):
- `CMAKE_C_COMPILER` = `zig;cc;-target;${PARANOID_TARGET}`
- `CMAKE_AR` = `zig;ar`
- `CMAKE_RANLIB` = `zig;ranlib`
- `CMAKE_SYSTEM_NAME` set from target triple
- `CMAKE_EXE_LINKER_FLAGS` adds `-static` for musl targets

### Target matrix

| Target | Zig triple | Static | Notes |
|---|---|---|---|
| linux/amd64 | `x86_64-linux-musl` | Yes | Primary target |
| linux/arm64 | `aarch64-linux-musl` | Yes | Graviton, Pi4, etc. |
| darwin/amd64 | `x86_64-macos-none` | libSystem dynamic (normal) | Intel Macs |
| darwin/arm64 | `aarch64-macos-none` | libSystem dynamic (normal) | Apple Silicon |

No Windows in v1. Adding is `x86_64-windows-gnu` plus conditional
compilation for `getrandom` → `BCryptGenRandom`; defer.

## Release Pipeline

### Workflow file

New `.github/workflows/cli-release.yml`. Triggers:
- Push of a release-please tag matching `paranoid-passwd-v*`
- Manual `workflow_dispatch` for dry-run

### Permissions

```yaml
permissions:
  contents: write       # upload release assets
  id-token: write       # sigstore OIDC
  attestations: write   # attest-build-provenance
```

### Job: `build`

Strategy matrix over the four targets. Each job:

1. Checkout (SHA-pinned `actions/checkout`)
2. Install Zig (same SHA env as CI)
3. Install CMake (via apt, native runner)
4. Configure + build the CLI with `zig-cross.cmake`
5. Strip binary
6. Package: `paranoid-passwd-${VERSION}-${OS}-${ARCH}.tar.gz`
   containing `paranoid-passwd/` directory with the binary, `LICENSE`,
   `README.md` excerpt, and man page
7. Compute SHA-256
8. Upload artifact for the aggregate job

### Job: `sign-and-release`

Needs: `build`. Downloads all four artifacts.

1. Concatenate all SHA-256s into `checksums.txt`
2. `actions/attest-build-provenance@<sha>` over each tarball AND `checksums.txt`
   → produces `attestations.intoto.jsonl` per artifact, signed via sigstore
3. `gh release upload` to the release-please tag:
   - Four tarballs
   - `checksums.txt`
   - Attestation bundles

Release notes are already populated by release-please; we only append
artifact links.

### Artifact naming (stable contract for the tap)

```
paranoid-passwd-3.2.0-linux-amd64.tar.gz
paranoid-passwd-3.2.0-linux-arm64.tar.gz
paranoid-passwd-3.2.0-darwin-amd64.tar.gz
paranoid-passwd-3.2.0-darwin-arm64.tar.gz
checksums.txt
```

The tap formula downloads by URL template:
`https://github.com/jbcom/paranoid-passwd/releases/download/paranoid-passwd-v{VERSION}/paranoid-passwd-{VERSION}-{OS}-{ARCH}.tar.gz`

## Testing

### New: `tests/test_cli.sh`

A shellcheck-clean bash script, invoked from CTest via `add_test`.

Cases:
1. `--help` exits 0 and prints usage
2. `--version` prints a line starting with `paranoid-passwd `
3. Bare invocation produces exactly 32 characters plus newline on stdout
4. `--length 16 --count 3` produces 3 lines, each 16 characters
5. `--charset hex --length 64` produces only `[0-9a-f]`
6. `--length 4 --require-lower 5` exits 1 (impossible)
7. `--length 0` exits 1
8. `--count 11` exits 1 (over MAX_MULTI_COUNT)
9. `--no-audit` produces no `chi-squared` line on stderr
10. `--quiet` produces empty stderr
11. `--quiet --no-audit` still produces a password on stdout
12. Exit code 0 on normal run, determined by `echo $?`

CI runs this test in the native-test job matrix, so every PR validates
CLI behavior on the Linux runner. macOS-runner CI run happens only on
release-tag push (too expensive for every PR).

### Reuse: existing `test_native`

Unchanged. The CLI does not add cryptographic code, so the existing
NIST CAVP vectors and acutest suites already cover the math. What the
CLI build *does* add is an implicit cross-check: `sha256_compact.c`
output equals OpenSSL output for the same input across all test inputs.
This check already exists implicitly in `test_sha256.c`; no new code
needed.

## Documentation

| File | Change |
|---|---|
| `docs/CLI.md` (NEW) | Install via GH Release + attestation verify. Install via tap. Flag reference. Examples. Exit-code reference. |
| `README.md` | New "CLI" section near the top with one verify-then-run example. Point to `docs/CLI.md`. |
| `docs/SUPPLY-CHAIN.md` | New "CLI release attestation" subsection: provenance chain, sigstore log, verify commands. |
| `docs/ARCHITECTURE.md` | Add the three-backend diagram (WASM / native-OpenSSL / native-POSIX). |
| `STANDARDS.md` | Note that `cli.c` is exempt from the "no hand-rolled argparse" heuristic because no argparse exists to re-use. |
| `man/paranoid-passwd.1` (NEW) | Generated from `cli.c` flag definitions at build time via a tiny awk script; installed with the binary. |
| `AGENTS.md` | Mention that the CLI is a consumer of `paranoid.h` and must never add crypto logic. |

## Risk Register

| Risk | Mitigation |
|---|---|
| `getrandom(2)` missing on older kernels | Gate with `__GLIBC_MINOR__` and fall back to `/dev/urandom` read; Wolfi and mainstream distros are fine. Add runtime check that errors exit-3 if RNG is unavailable. |
| Zig toolchain regression breaks cross-build | Zig version pinned by SHA; dependabot tracks. |
| Static musl binary segfaults at startup on some glibc systems | No — static musl is independent of host libc. This is Zig's specialty. |
| OpenSSL-vs-POSIX SHA-256 divergence | Both are tested against NIST CAVP vectors; divergence is a test failure in CI. |
| Attestation failure in release pipeline | `gh release create` still proceeds without attestation upload; workflow emits a warning. Re-running the workflow re-attests. |
| Tap repo's formula URL expectations drift | The artifact naming contract is documented in `docs/CLI.md` and the release workflow. Breaking changes require a major version bump. |

## Non-Obvious Choices

- **Audit on by default.** The web app always audits. The CLI matches.
  Users scripting bulk generation pass `--no-audit`. This encodes
  project ethos (self-auditing IS the product) into the default UX.
- **Password to stdout even on audit fail.** The alternative (swallow
  password on fail) feels safer but makes `--count 1000 | head -5` hide
  the fact that audits failed. Exit code 3 + stderr banner is the right
  signal channel.
- **No config file.** Flags are the interface. A `~/.paranoidrc` would
  be a new input source to audit and a new place for injection bugs.
- **`sha256_compact.c` over `crypto/sha256`-style stdlib.** Already
  compiled, already FIPS-annotated line by line, already in the threat
  model.

## Implementation Order

1. `src/platform_posix.c` + minimal test to prove `getrandom`/`getentropy` work
2. `src/cli.c` skeleton: `--version`, `--help`, bare invocation
3. Full flag parsing + charset resolution
4. Stage callbacks + stderr formatter
5. CMake target + install rules
6. `cmake/zig-cross.cmake`
7. `tests/test_cli.sh`
8. `.github/workflows/cli-release.yml`
9. Docs (CLI.md, README section, SUPPLY-CHAIN subsection, man page)
10. Version bump via release-please conventional-commit message

## Definition of Done

- `paranoid-passwd --version` runs on all 4 targets.
- `tests/test_cli.sh` passes in CTest on Linux; runs manually on macOS.
- A tag push produces a release with 4 tarballs, `checksums.txt`, and
  attestations that `gh attestation verify` accepts.
- `docs/CLI.md` shows the full verify-then-run path, tested end-to-end
  by the author on at least one darwin-arm64 machine.
- The existing WASM build and web app are byte-identical to their
  pre-CLI state (no regressions from adding CMake options).
