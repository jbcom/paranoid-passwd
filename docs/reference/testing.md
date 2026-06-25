---
title: Testing
---

# Testing

The native product line keeps generator, vault, and release behavior covered in tests while
keeping the retired browser app out of the product surface. Slint WASM and mobile targets are
treated as explicit Rust-native target surfaces with their own threat model and local checks.

The remaining open disposition surface is tracked separately in
[AI Review Surface](./ai-review.md) and mapped to [Assurance Claims](./assurance-claims.md).
The repository enforces that inventory with `scripts/verify_ai_review_inventory.sh` and the
claim-led gate in `scripts/security_assurance_gate.py`.

Run the full assurance gate with:

```bash
make verify-assurance
```

That command verifies the hallucination checks, supply-chain checks, open AI review inventory, and
security assurance protocol wiring.

## Local Release-Candidate Quality Gate

The Makefile remains the operator interface for local and CI workflows. Repo-owned deep checks that
need structured parsing live in the Rust-native `xtask` crate instead of ad hoc Python glue:

```bash
make verify-deep
make quality
```

- `make verify-deep` runs `cargo run -p xtask --locked --frozen --offline -- verify-deep`.
- The `xtask` gate verifies the Rust toolchain policy, locked offline Cargo metadata, workspace
  license/source policy, ShellCheck warning-or-higher results for repo-owned shell scripts, Python
  syntax for the existing docs/test harness scripts without writing bytecode, tracked-file secret
  scanning, and local visibility of security scanners.
- `make quality` runs `verify-deep`, the full `ci` target, GUI target compile checks, and the
  supported multi-viewport GUI visual-regression target for the host. On macOS it drives the Linux
  GUI harness through the local builder image; on Linux it uses the native `xvfb-run` harness. This
  target requires the local security scanner stack and runs the enforced local scanner subset.
- Optional external tools (`codeql`, `semgrep`, `cargo-deny`, `cargo-audit`, `cargo-vet`, `syft`,
  `trivy`, and `osv-scanner`) are reported when missing under `make verify-deep`; `make quality`
  sets `PARANOID_STRICT_EXTERNAL_TOOLS=1` and treats missing tools as fatal.
- `supply-chain/scanner-toolchain.env` records the scanner/tool update contract. The
  supply-chain verifier checks that Wolfi builder scanner apk versions, CodeQL action SHA pins, and
  host-local `xtask` visibility and version checks agree with that manifest. In strict mode, `xtask`
  checks ShellCheck, cargo-deny, cargo-audit, cargo-vet, and the CodeQL CLI against their manifest
  pins before running the enforced local scanner subset.
- The enforced scanner subset is `cargo audit --no-fetch --stale`, `cargo deny check`, Semgrep
  `--config auto`, and an OSV lockfile report. `cargo-deny` allows unmaintained/unsound advisories
  as warnings only when there is no safe upgrade path; OSV findings with a fixed version remain
  blocking. Trivy, Syft, CodeQL, and cargo-vet are installed/visible locally but require pinned
  policies or evidence-output handling before they become default `make quality` steps.

Python remains in the repo only where it already owns a specific workflow: Sphinx/tox docs and the
PTY-driven TUI harness. It is not the project automation layer.

## Local Build Chain Configure

The repository owns local toolchain discovery through:

```bash
./configure
make configure
make bootstrap-local
make show-config
```

`./configure` and `make configure` generate `.config/paranoid-local.mk` for Make and
`.config/paranoid-local.env` for manual shell work. The generated config detects the host platform,
Cargo/Rustup, Docker, Xvfb/ImageMagick GUI capture tools, Android SDK/NDK paths, NDK clang/ar/ranlib,
adb, emulator, Maestro, `wasm-pack`, and installed Rust Android/WASM targets. `make bootstrap-local`
installs `aarch64-linux-android` and `wasm32-unknown-unknown` with Rustup before regenerating the
config.

GUI target checks are separate from the main CI target so platform-readiness does not hide behind
remote runners:

```bash
make test-gui-host-check
make test-gui-android-check
make test-gui-wasm-check
make test-gui-targets
```

`make test-gui-android-check` currently compile-checks the Slint GUI library through the configured
NDK while keeping the native `paranoid-core` and `paranoid-vault` path linked. `make
test-gui-wasm-check` is intentionally strict and warning-clean, but it only checks the gated
non-secret Slint WASM surface. The native vault and generator crates are not linked for
`wasm32-unknown-unknown`; target-appropriate vault storage, crypto, packaging, and runtime
validation remain product work before WASM can become a supported secret-handling surface.

Current GUI platform coverage is explicit:

| GUI surface | Current gate | What it proves |
| --- | --- | --- |
| Desktop Slint | `make test-gui-e2e` or `make test-gui-e2e-emulate` | Runs the real GUI binary through the operator workflow, validates durable audit evidence, and captures a rendered screenshot. |
| Desktop viewport classes | `make test-gui-visual-regression` or `make test-gui-visual-regression-emulate` | Replays the real GUI workflow at desktop, tablet, and narrow/mobile-class viewport sizes and rejects blank or low-information screenshots. |
| Android Slint | `make test-gui-android-check` | Compile-checks the Rust-native Slint library against the configured Android NDK while preserving native core/vault linkage. Runtime emulator/Maestro coverage remains the next Android gate. |
| WASM Slint | `make test-gui-wasm-check` | Compile-checks the gated non-secret Slint WASM surface. Secret-handling WASM is not supported until target storage, crypto, and runtime validation are threat-modeled. |

## Ops, Audit, and Federal Profile Tests

The ops/audit/seal layer now has dedicated `paranoid-ops`, `paranoid-audit`, and `paranoid-seal`
crates. Current coverage proves that:

- generator automation runs through the ops boundary
- JSON reports include policy request/response audit events
- `--audit-jsonl` writes a local append-oriented JSONL audit sink
- configured audit sinks must pass a writable health check before policy treats them as available
- headless vault CLI subcommands and native vault TUI actions emit typed ops request/response events
  when an audit sink is configured
- native GUI vault operations emit typed ops request/response policy events to both in-memory
  automation evidence and configured durable JSONL sinks without copying plaintext secrets into audit
  metadata
- ops unit tests prove caller-supplied envelopes cannot downgrade the authoritative policy context
  profile, and that CLI/TUI/GUI vault-operation surfaces preserve the same operation/access metadata
- `--federal-ready` fails closed without confirmed approved-provider evidence
- federal startup evidence is emitted as JSON
- federal startup evidence includes external audit-device posture without treating configured-only
  mTLS evidence or TCP reachability as an available sink
- audit unit tests cover disabled probes, live TCP reachability probes, and the explicit ready-ack
  path required before an external audit device can satisfy required audit policy
- a stable denied federal startup fixture and an external-device-ready fixture are checked against
  the serialized evidence schema; the external audit-device and recovery-disposition wire shape is
  versioned as federal startup evidence schema `3`
- stable CLI/TUI/GUI vault operation trace fixtures pin typed ops envelopes, request/response audit
  events, and JSONL rendering for automation compatibility
- a stable mTLS process-boundary vault operation fixture pins authenticated transport evidence,
  service-account actor context, and non-secret request/response audit attributes, including
  channel-binding evidence
- live mTLS JSONL ops transport tests prove a loopback OpenSSL mTLS command exchange returns the
  same typed trace to client and server, replaces client-claimed transport evidence with
  server-observed peer-certificate evidence, and rejects an untrusted client certificate before
  policy can allow the command; the transport also rejects oversized peer-controlled JSONL frames
  instead of reading unbounded input
- audit unit tests cover the mTLS JSONL write-ack probe, including matching acknowledgement and
  mismatched challenge rejection
- typed allow/challenge/deny decisions cover sensitive vault unlock methods
- ops policy tests require seal posture evidence for federal certificate unlock, require seal
  posture evidence for device-bound unlock, and require confirmed device-bound provider
  availability before device-bound unlock can proceed; password, mnemonic, device-bound, and
  certificate unlocks are checked against their matching provider kinds instead of generic recovery
  or auto-unseal flags
- the seal state machine covers unlock, idle-lock, timeout, and relock transitions
- seal posture reports configured recovery, certificate, and auto-unseal providers without claiming
  provider availability before a health check confirms it, and helper tests keep availability
  method-specific
- headless `vault seal-status` output includes the same seal posture payload, and
  `vault seal-status --probe-providers` is covered by the vault CLI e2e script to prove
  device-bound providers become `available` only after an explicit secure-storage check
- redaction removes sensitive attributes instead of copying or hashing secrets
- hash-chain verification detects tampered event streams

The remaining test expansion is now narrower:

- keyed correlation hashes only after the approved primitive and low-entropy secret risk are
  dispositioned
- broader PTY e2e coverage for each TUI vault mutation routed through typed ops envelopes

## Core Tests

`paranoid-core` includes unit coverage for:

- SHA-256 known-answer vectors
- rejection-sampling boundaries
- charset validation
- constrained generation
- chi-squared known answers
- serial-correlation known answers
- pattern detection
- full audit pipeline output
- multi-password `GeneratedPassword` inspection and `AuditSummary` roll-up

Run them with:

```bash
cargo test -p paranoid-core --locked --frozen --offline
```

## CLI and TUI

`paranoid-cli` includes:

- TUI reducer / rendering smoke tests
- real PTY-driven binary TUI workflow coverage in
  [`tests/test_tui_e2e.py`](../../../tests/test_tui_e2e.py), proving the
  generator wizard and vault TUI can be driven end to end with actual terminal
  keystrokes
- a Linux GUI-binary workflow harness in
  [`tests/test_gui_e2e.sh`](../../../tests/test_gui_e2e.sh), proving the native
  Slint desktop app can run an operator workflow end to end under `xvfb-run`
  and leave a screenshot artifact for review
- a multi-viewport GUI visual-regression mode that replays the same workflow at desktop, tablet,
  and narrow/mobile-class viewport sizes and rejects blank or low-information captures
- vault TUI rendering and launch-policy smoke tests
- headless CLI end-to-end coverage for the documented vault workflows in
  [`tests/test_vault_cli.sh`](../../../tests/test_vault_cli.sh), including
  real binary CRUD, structured filtering, `generate-store` create and rotate
  flows, encrypted backup restore plus `--force` overwrite behavior,
  transfer-package import/export plus remap and `--replace-existing` conflict
  handling, mnemonic recovery, device-bound unlock, certificate-backed unlock,
  recovery-secret rotation, and keyslot removal guards
- vault TUI add, edit, delete, generate-and-store, generate-and-rotate, `SecureNote`, `Card`, `Identity`, folder, tag, password-history, duplicate-password visibility, native direct unlock for recovery-secret, mnemonic, device-bound, and certificate-backed paths, keyslot-enrollment, mnemonic-slot rotation, certificate-slot rewrap, keyslot-relabel, recovery-secret rotation, keyslot-removal, device-slot rebind, and structured `/` filter workflow tests
- vault TUI encrypted backup export/import round-trip tests, invalid backup restore fail-closed coverage, transfer-package export/import round-trip tests, invalid transfer import fail-closed coverage, and backup/transfer summary preview coverage
- headless encrypted transfer-package export/import coverage for recovery-secret unwrap, certificate unwrap, and conflict remapping
- vault TUI idle auto-lock regression coverage
- vault CLI coverage through the shared workspace tests
- CLI contract coverage through the shell script in [`tests/test_cli.sh`](../../../tests/test_cli.sh)
- repository verification via `scripts/hallucination_check.sh` and `scripts/supply_chain_verify.sh`
- the [Recovery Operations](../guides/recovery-operations.md) runbook is checked by
  `scripts/validate-docs.sh` and the assurance gate so lifecycle docs keep covering mnemonic
  rotation, certificate rollover, device rebind, backup/restore, transfer packages, daily
  passwordless unlock, and disaster recovery

Run them with:

```bash
cargo test -p paranoid-cli --locked --frozen --offline
cargo build -p paranoid-cli --locked --frozen --offline
tests/test_cli.sh target/debug/paranoid-passwd
tests/test_tui_e2e.py target/debug/paranoid-passwd
tests/test_gui_e2e.sh target/debug/paranoid-passwd target/debug/paranoid-passwd-gui dist/gui-e2e.png
tests/test_gui_e2e.sh target/debug/paranoid-passwd target/debug/paranoid-passwd-gui dist/gui-e2e.png "desktop=1280x1024 tablet=900x700 mobile=420x800"
tests/test_vault_cli.sh target/debug/paranoid-passwd
bash scripts/hallucination_check.sh
bash scripts/supply_chain_verify.sh
```

The headless vault e2e suite uses a debug-only file-backed device-store override
when `PARANOID_TEST_DEVICE_STORE_DIR` is set. Release builds do not include that
test backend.

`paranoid-vault` includes:

- vault init/unlock round trips
- CRUD coverage for `Login`, `SecureNote`, `Card`, and `Identity` items, including folder persistence, tag persistence, typed kind/folder/tag/query filtering, login password-history retention on rotation, and duplicate-password detection for login items
- wrong-password fail-closed coverage
- mnemonic recovery keyslot add/unlock coverage, including generated 24-word phrase shape and
  recovered 256-bit entropy checks
- mnemonic recovery keyslot rotation coverage, including fail-closed invalidation of the previous phrase
- multi-mnemonic-slot explicit-selection coverage
- mnemonic recovery fail-closed coverage for malformed phrase length, tampered keyslot metadata, and
  backup packages that omit the phrase and raw entropy
- device-bound keyslot add/unlock coverage, including missing provider material, tampered
  secure-storage material, wrong-length secure-storage material, removal cleanup, and same-device
  backup semantics that omit the provider secret
- multi-device-slot explicit-selection coverage
- certificate-wrapped keyslot add/unlock coverage, including explicit validation of supported
  algorithms, certificate metadata, and AES-GCM field shape before unwrap
- certificate-wrapped keyslot rewrap coverage, including persisted public metadata updates for fingerprint, subject, and validity, plus native session continuity when a live certificate-authenticated surface rewraps its active slot
- public certificate preview coverage for headless inspection before enrollment or rewrap
- headless keyslot-inspection parser coverage
- certificate keyslot health coverage for expired-recipient detection
- encrypted private-key certificate unlock coverage
- certificate backup coverage proving packages preserve the CMS-wrapped transport key and public
  metadata without exporting the private key or raw transport key
- password recovery-slot rotation coverage
- keyslot relabel persistence coverage
- recovery-posture summary coverage
- keyslot removal-impact analysis coverage
- non-recovery keyslot removal coverage
- device-bound keyslot rebind coverage
- generator-to-vault `generate-store` create and rotate coverage
- decrypted local summary filter coverage
- encrypted backup export/import round-trip coverage and backup-summary inspection coverage, including keyslot detail and certificate metadata
- encrypted transfer-package inspection and import coverage, including selective filters, certificate unwrap, and id remapping on conflict
- invalid-backup and tampered-ciphertext fail-closed coverage
- shared session-hardening coverage for clipboard auto-clear timing and idle-lock timing

`paranoid-gui` includes:

- shared generator request/result model coverage
- a checked-in Slint shell compiled by `build.rs` from `crates/paranoid-gui/ui/paranoid.slint`,
  with a focused Rust test that verifies the generated component bindings under locked,
  frozen, offline Cargo
- a comprehensive operator workflow test that crosses the generator and vault
  surfaces in one run, covering audit completion, vault CRUD, generate-and-rotate,
  keyslot navigation, mnemonic enrollment, backup export, and transfer export/import
- a real GUI-binary operator harness that launches the desktop app under Xvfb,
  drives the same native update path used by interactive controls, attests the
  workflow result to disk, and captures a rendered screenshot artifact
- a real GUI-binary visual-regression harness that captures desktop, tablet, and
  narrow/mobile-class screenshots from the same operator workflow
- vault refresh, CRUD, `SecureNote`, `Card`, `Identity`, folder, tag, password-history, duplicate-password visibility, structured filtering, generate-and-rotate, encrypted backup export/import, invalid backup restore fail-closed coverage, encrypted transfer export/import, invalid transfer import fail-closed coverage, and backup/transfer summary preview coverage
- native GUI keyslot inspection, mnemonic-slot rotation, certificate-slot rewrap, relabel, recovery-secret rotation, enrollment, posture-aware removal, device-slot rebind coverage, and active-session continuity after device rebind
- native GUI direct unlock coverage for recovery-secret, mnemonic, device-bound, and certificate-backed flows
- native GUI idle auto-lock coverage
- GUI launch-policy coverage for `--version` and `--help` without creating a window

The GUI crate permits Slint-generated Rust and exact Rust 2024 platform ABI export attributes to
lower the unsafe-code lint, but handwritten unsafe blocks, functions, and impls are still scanned by
`scripts/hallucination_check.sh`; security-sensitive crates remain under the workspace
`unsafe_code = "forbid"` lint.

## Docs

The docs site is part of the build:

```bash
python3 -m tox -e docs
python3 -m tox -e docs-linkcheck
```

That validates the docs tree, builds the Sphinx output under `docs/_build/html`, and checks outbound documentation links without coupling CI to the live Pages deployment.

## Release Validation

The local release path now has two explicit entry points:

```bash
make smoke-release
make release-emulate
```

- `make smoke-release` builds and smoke-tests the host-native CLI and GUI artifacts, including Linux `.deb` packages on Linux hosts, the GUI `.dmg` image on macOS hosts, and the GUI `.msi` installer on Windows hosts. DMG smoke validation mounts the image for layout inspection and stages the `.app` bundle before executable checks. MSI smoke validation uses Windows Installer administrative extraction before executable checks. Exit code 137 is retried with a bounded retry count to keep transient macOS process kills from weakening the release gate.
- `make release-emulate` drives the Linux release packaging path through the custom builder image, including `.deb` outputs.
- Linux GUI smoke validation now includes an Xvfb-backed screenshot capture of the packaged
  GUI window so the release path proves a real frame renders instead of only checking
  `--help`.
- `make test-gui-e2e` runs the actionable GUI workflow harness on Linux hosts, while
  `make test-gui-e2e-emulate` drives the same path through the custom builder image on macOS.
- `make test-gui-visual-regression` captures desktop, tablet, and narrow/mobile-class screenshots
  on Linux hosts; `make test-gui-visual-regression-emulate` runs the same visual matrix through the
  builder image on macOS.
- `scripts/release_validate.sh` is used in CI after the full matrix build to verify all CLI and GUI artifacts, Linux `.deb` packages, the Windows GUI `.msi`, package-manager manifests, and `install.sh`. Linux aggregation explicitly defers MSI payload extraction to the paired Windows published-release verifier.
- `make verify-branch-protection` checks that GitHub branch protection still matches the active Rust-native required checks.
