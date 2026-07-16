---
title: Contributing
updated: 2026-07-16
status: current
domain: technical
---

# Contributing to paranoid-passwd

This is a guide for human contributors. Agent-facing protocols (the LLM clean-room checklist,
zero-exception rules, hallucination patterns) live in [`AGENTS.md`](AGENTS.md) and
[`CLAUDE.md`](CLAUDE.md) — read those too if you are working on generation, crypto, or audit
math.

## 1. Dev Environment Setup

Start with the Makefile; it is the operator interface for this repo and the source of truth for
every command below.

```bash
make configure
```

`make configure` (equivalently `./configure`) runs `scripts/configure_local_toolchain.sh` and
writes `.config/paranoid-local.mk` (consumed by Make) and `.config/paranoid-local.env` (for
manual shell use). It detects the host platform, Cargo/Rustup, Docker, Xvfb/ImageMagick GUI
capture tools, Android SDK/NDK paths and NDK clang/ar/ranlib, `adb`, `emulator`, Maestro,
`wasm-pack`, and the installed Rust Android/WASM targets.

If you need the Android and WASM GUI targets installed, use:

```bash
make bootstrap-local
```

This installs the `aarch64-linux-android` and `wasm32-unknown-unknown` Rust targets with Rustup,
then reruns `make configure`.

To see what your machine was detected as:

```bash
make show-config
```

This prints `.config/paranoid-local.summary`, which tells you whether Docker, Android, and WASM
toolchains are ready before you rely on the targets that need them (`test-gui-android-check`,
`test-gui-wasm-check`, `*-emulate` targets).

### Offline, vendored builds — and why

Every Cargo invocation in this repo runs `--locked --frozen --offline` against a vendored
dependency tree in `vendor/`, wired up by `.cargo/config.toml`:

```toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

`--locked` refuses to build if `Cargo.lock` would need to change. `--frozen` refuses to touch the
network or update the lockfile at all. `--offline` refuses network access outright. Together they
mean a build either reproduces exactly what's committed or fails loudly — there is no path where
a dependency gets silently substituted or upgraded mid-build. This matters specifically because
this project treats its dependency tree (OpenSSL bindings, Argon2, statistical libraries) as part
of its security posture, not an implementation detail. Keep this invariant: do not add Cargo
commands that omit `--locked --frozen --offline`, and do not add dependencies without vendoring
them (`cargo vendor`) and updating `vendor/`.

## 2. Verification

```bash
make ci
```

`make ci` is the local equivalent of the repository's CI gate. It runs, in order:

1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets --locked --frozen --offline -- -D warnings`
3. `bash scripts/cargo_test.sh --workspace --locked --frozen --offline` (the full workspace test suite)
4. `make test-cli-contract` (builds the CLI, runs `tests/test_cli.sh` against it)
5. `make test-tui-e2e` (builds the CLI, runs `tests/test_tui_e2e.py` — a real PTY-driven TUI harness)
6. the platform GUI e2e target, when the host is Linux (`test-gui-e2e`) — skipped on other hosts
7. `make test-gui-host-check` (compile-check the host Slint GUI surface)
8. `make test-vault-e2e` (builds the CLI, runs `tests/test_vault_cli.sh`)
9. `make test-platform-signing-boundary` (`tests/test_platform_signing_verify.sh`)
10. `make verify-assurance` (hallucination checks, supply-chain checks, AI review inventory, security assurance gate — see below)
11. `python3 -m tox -e docs,docs-linkcheck` (build the Sphinx docs site and check outbound links)

Run this before opening a PR. It is what CI itself runs.

### Narrower per-crate commands

While iterating, you rarely need the full `make ci` gate. Use the crate-scoped Cargo commands
directly:

```bash
cargo build --workspace --locked --frozen --offline
cargo test -p paranoid-core --locked --frozen --offline
cargo test -p paranoid-cli --locked --frozen --offline
cargo check -p paranoid-gui --locked --frozen --offline
cargo fmt --check
cargo clippy --workspace --all-targets --locked --frozen --offline -- -D warnings
```

### `make quality` for release candidates

```bash
make quality
```

This is the release-candidate gate, stricter than `make ci`. It runs, in order:

1. `verify-deep` with `PARANOID_STRICT_EXTERNAL_TOOLS=1 PARANOID_RUN_LOCAL_SCANNERS=1` (missing
   optional scanners become fatal instead of just reported)
2. the full `ci` target
3. `test-gui-targets` (host, Android, and WASM GUI compile checks)
4. the platform-appropriate GUI visual-regression target — `test-gui-visual-regression-emulate`
   through the builder image on macOS, `test-gui-visual-regression` natively on Linux

`make verify-deep` itself runs `cargo run -p xtask --locked --frozen --offline -- verify-deep`,
the Rust-native deep-check gate (Rust toolchain policy, locked offline Cargo metadata, workspace
license/source policy, ShellCheck on repo-owned shell scripts, Python syntax checks, tracked-file
secret scanning, and local security-scanner visibility).

There is also `make quality-emulate`, which runs the same release-candidate posture inside the
Wolfi builder image instead of the host — use it to reproduce what the builder-driven CI path
sees, including scanner tools that may not be installed locally. See
[Testing](docs/reference/testing.md) for the full breakdown of what each quality gate covers.

## 3. Where Code Belongs

The workspace is seven crates plus an `xtask` dev-tooling crate. Each has one job:

| Crate | Owns |
| --- | --- |
| [`paranoid-core`](crates/paranoid-core/src/lib.rs) | Password generation, rejection sampling, OpenSSL-backed RNG/SHA-256, statistical audit math (chi-squared, serial correlation), pattern detection, compliance-framework checks |
| [`paranoid-ops`](crates/paranoid-ops/src/lib.rs) | The typed operation boundary for automation-facing generator/vault workflows — request/response envelopes, policy context |
| [`paranoid-audit`](crates/paranoid-audit/src/lib.rs) | Redacted structured audit events, JSONL sink health, federal-ready evidence |
| [`paranoid-seal`](crates/paranoid-seal/src/lib.rs) | Vault seal state machine and non-secret seal-provider posture |
| [`paranoid-vault`](crates/paranoid-vault/src/lib.rs) | Encrypted local vault storage, keyslots, item CRUD, backups, transfer packages, recovery posture |
| [`paranoid-cli`](crates/paranoid-cli/src/main.rs) | The scriptable CLI and default TUI, consuming the crates above |
| [`paranoid-gui`](crates/paranoid-gui/src/main.rs) | The Slint-native desktop GUI, consuming the same typed results |

Security-sensitive logic (RNG, hashing, KDF, audit math, rejection sampling) belongs in
`paranoid-core` only — never in the CLI, TUI, GUI, or docs tooling. See
[`CLAUDE.md`](CLAUDE.md) for the full zero-exception list; the ones most relevant to code
placement:

- Keep security-sensitive logic in `crates/paranoid-core`.
- Do not reintroduce browser, WASM, or webview runtime surfaces as a secret-handling path.
- Keep the rejection sampling boundary at `((256 / charset_len) * charset_len) - 1`: this is
  the highest acceptable random byte value for the charset. Bytes greater than this value must
  be rejected and re-drawn to avoid modulo bias.
- Keep chi-squared pass logic at `p > 0.01` and degrees of freedom at `N - 1`.
- Do not add `unsafe` Rust without explicit repository disposition and assurance-script coverage
  (`scripts/hallucination_check.sh` scans for handwritten `unsafe`; only Slint-generated code and
  exact audited platform ABI export attributes are exempt).
- Keep Cargo builds locked, frozen, offline, and backed by `vendor/`.

If you are touching generation, crypto, KDF, or statistical audit code, read the LLM clean-room
checklist in [`AGENTS.md`](AGENTS.md) first — it lists exact hallucination patterns (off-by-one
rejection sampling, inverted p-value logic) this codebase has been burned by before.

## 4. Test Layers

| Layer | What it proves | Command |
| --- | --- | --- |
| Unit (`paranoid-core`, `paranoid-ops`, `paranoid-audit`, `paranoid-seal`, `paranoid-vault`, `paranoid-cli`, `paranoid-gui`) | Generation correctness, audit math known-answers, ops/audit/seal policy, vault CRUD and keyslot logic, TUI reducer behavior, GUI component bindings | `cargo test -p <crate> --locked --frozen --offline` or `bash scripts/cargo_test.sh --workspace --locked --frozen --offline` |
| CLI contract | The generator CLI's documented flags and output against the real debug binary | `make test-cli-contract` (runs [`tests/test_cli.sh`](tests/test_cli.sh)) |
| Vault CLI e2e | Headless vault CRUD, filtering, `generate-store`, backup/transfer round-trips, recovery-secret rotation, keyslot removal guards against the real debug binary | `make test-vault-e2e` (runs [`tests/test_vault_cli.sh`](tests/test_vault_cli.sh)) |
| TUI PTY e2e | Real terminal keystrokes driving the generator wizard and vault TUI through the actual binary | `make test-tui-e2e` (runs [`tests/test_tui_e2e.py`](tests/test_tui_e2e.py)) |
| GUI checks | Host compile-check, Android/WASM compile-checks, and a real GUI-binary workflow harness under Xvfb with a captured screenshot | `make test-gui-host-check`, `make test-gui-android-check`, `make test-gui-wasm-check`, `make test-gui-e2e` / `make test-gui-e2e-emulate`, `make test-gui-visual-regression[-emulate]` |
| Platform signing boundary | Release platform-signing verifier contract | `make test-platform-signing-boundary` (runs [`tests/test_platform_signing_verify.sh`](tests/test_platform_signing_verify.sh)) |
| Assurance gate | Hallucination checks, supply-chain checks, AI review inventory, security assurance protocol wiring | `make verify-assurance` |

`make ci` runs unit, CLI contract, TUI PTY e2e, the platform-appropriate GUI e2e, the GUI host
check, vault e2e, platform signing boundary, and the assurance gate, plus the docs build. `make
quality` adds the full `test-gui-targets` matrix (host + Android + WASM) and GUI visual
regression. See [`docs/reference/testing.md`](docs/reference/testing.md) for the complete,
current breakdown of what every test file and Make target covers.

## 5. Extension Points as They Exist Today

These are the compile-time Rust surfaces you extend today. **There is no data-driven or
plugin-style registry yet** — a registry is planned future work, not a promise this document is
making. Extending any of these means editing Rust source in the owning crate, not registering a
config file or external plugin.

- **Compliance frameworks** — `FrameworkId` (an enum) and the `FRAMEWORKS` const array in
  [`crates/paranoid-core/src/lib.rs`](crates/paranoid-core/src/lib.rs). Each `ComplianceFramework`
  entry is a static struct literal (`min_length`, `min_entropy_bits`, `require_mixed_case`,
  `require_digits`, `require_symbols`). Adding a framework means adding an enum variant, a
  `FrameworkId::parse`/`as_str` arm, and a `ComplianceFramework` entry in `FRAMEWORKS` — all in
  the same commit, since `framework_by_id` assumes the array is exhaustive over the enum
  (`.expect("framework ids are static and exhaustive")`).
- **Charset presets** — `resolve_charset` in
  [`crates/paranoid-core/src/lib.rs`](crates/paranoid-core/src/lib.rs). Named presets (`alnum`,
  `alnum-symbols`, `hex`, `full`) are `match` arms returning a built string; anything else falls
  through to `validate_charset` as a literal charset. Adding a preset means adding a `match` arm.
- **Seal provider kinds** — `VaultSealProviderKind` in
  [`crates/paranoid-seal/src/lib.rs`](crates/paranoid-seal/src/lib.rs) (`PasswordRecovery`,
  `MnemonicRecovery`, `DeviceBound`, `CertificateWrapped`, `ExternalAutoUnseal`). This enum drives
  seal posture reporting and the `is_operator_recovery` / `is_certificate_unseal` /
  `is_auto_unseal` classification helpers that ops/audit policy checks against.
- **Keyslot kinds** — `VaultKeyslotKind` in
  [`crates/paranoid-vault/src/lib.rs`](crates/paranoid-vault/src/lib.rs) (`PasswordRecovery`,
  `MnemonicRecovery`, `DeviceBound`, `CertificateWrapped`). This is the persisted, serialized
  keyslot kind stored in `VaultHeader.keyslots`; it must stay aligned with
  `VaultSealProviderKind` in `paranoid-seal` since seal posture is derived from configured
  keyslots.

Adding a variant to any of these enums touches every exhaustive `match` over it — the compiler
will find them, but expect changes to ripple through CLI argument parsing, TUI/GUI rendering, and
serialization (several of these enums have `#[serde(rename_all = "snake_case")]` and, in
`VaultKeyslotKind`, backward-compat `#[serde(alias = ...)]` entries for previously persisted
vault headers). Treat any new variant as a persisted-format change if it can appear in
`VaultHeader`.

## 6. PR Conventions

- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:`,
  `docs:`, `refactor:`, `perf:`, `test:`, `ci:`, `build:`) for every commit message. This repo
  runs `release-please` (see `release-please-config.json`) off the commit history — the prefix is
  what drives `CHANGELOG.md` and version bumps, so get it right.
- PRs are squash-merged. Write commit messages during development for readability; the PR title
  and squash-merge message are what actually lands on `main` and feeds the changelog, so make
  sure it accurately reflects the whole PR content, not just the last commit.
- Docs and tests move with the code that changes them in the same PR — do not defer doc updates
  to a follow-up. If you add or change a Make target, test file, or crate responsibility, update
  the corresponding section of [`docs/reference/testing.md`](docs/reference/testing.md) and this
  file if relevant.
- Run `make ci` locally before opening a PR; it is the same gate CI runs.
