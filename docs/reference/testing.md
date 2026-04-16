---
title: Testing
---

# Testing

The Rust replatform keeps the audit behavior covered in native tests and removes the old browser/WASM test surface.

The remaining human-review surface is tracked separately in [Human Review Surface](./human-review.md), and the repository now enforces that inventory with `scripts/verify_human_review_inventory.sh`.

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
- vault TUI rendering and launch-policy smoke tests
- vault TUI add, edit, delete, generate-and-store, generate-and-rotate, `SecureNote`, `Card`, `Identity`, folder, tag, password-history, duplicate-password visibility, native direct unlock for recovery-secret, mnemonic, device-bound, and certificate-backed paths, keyslot-enrollment, mnemonic-slot rotation, certificate-slot rewrap, keyslot-relabel, recovery-secret rotation, keyslot-removal, device-slot rebind, and structured `/` filter workflow tests
- vault TUI encrypted backup export/import round-trip tests, invalid backup restore fail-closed coverage, transfer-package export/import round-trip tests, invalid transfer import fail-closed coverage, and backup/transfer summary preview coverage
- headless encrypted transfer-package export/import coverage for recovery-secret unwrap, certificate unwrap, and conflict remapping
- vault TUI idle auto-lock regression coverage
- vault CLI coverage through the shared workspace tests
- CLI contract coverage through the shell script in [`tests/test_cli.sh`](../../../tests/test_cli.sh)
- repository verification via `scripts/hallucination_check.sh` and `scripts/supply_chain_verify.sh`

Run them with:

```bash
cargo test -p paranoid-cli --locked --frozen --offline
cargo build -p paranoid-cli --locked --frozen --offline
tests/test_cli.sh target/debug/paranoid-passwd
bash scripts/hallucination_check.sh
bash scripts/supply_chain_verify.sh
```

`paranoid-vault` includes:

- vault init/unlock round trips
- CRUD coverage for `Login`, `SecureNote`, `Card`, and `Identity` items, including folder persistence, tag persistence, typed kind/folder/tag/query filtering, login password-history retention on rotation, and duplicate-password detection for login items
- wrong-password fail-closed coverage
- mnemonic recovery keyslot add/unlock coverage
- mnemonic recovery keyslot rotation coverage, including fail-closed invalidation of the previous phrase
- multi-mnemonic-slot explicit-selection coverage
- device-bound keyslot add/unlock coverage
- multi-device-slot explicit-selection coverage
- certificate-wrapped keyslot add/unlock coverage
- certificate-wrapped keyslot rewrap coverage, including persisted public metadata updates for fingerprint, subject, and validity, plus native session continuity when a live certificate-authenticated surface rewraps its active slot
- public certificate preview coverage for headless inspection before enrollment or rewrap
- headless keyslot-inspection parser coverage
- certificate keyslot health coverage for expired-recipient detection
- encrypted private-key certificate unlock coverage
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
- vault refresh, CRUD, `SecureNote`, `Card`, `Identity`, folder, tag, password-history, duplicate-password visibility, structured filtering, generate-and-rotate, encrypted backup export/import, invalid backup restore fail-closed coverage, encrypted transfer export/import, invalid transfer import fail-closed coverage, and backup/transfer summary preview coverage
- native GUI keyslot inspection, mnemonic-slot rotation, certificate-slot rewrap, relabel, recovery-secret rotation, enrollment, posture-aware removal, device-slot rebind coverage, and active-session continuity after device rebind
- native GUI direct unlock coverage for recovery-secret, mnemonic, device-bound, and certificate-backed flows
- native GUI idle auto-lock coverage
- GUI launch-policy coverage for `--version` and `--help` without creating a window

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

- `make smoke-release` builds and smoke-tests the host-native CLI and GUI artifacts, including Linux `.deb` packages on Linux hosts and the GUI `.dmg` image on macOS hosts.
- `make release-emulate` drives the Linux release packaging path through the custom builder image, including `.deb` outputs.
- `scripts/release_validate.sh` is used in CI after the full matrix build to verify all CLI and GUI artifacts, Linux `.deb` packages, package-manager manifests, and `install.sh`.
- `make verify-branch-protection` checks that GitHub branch protection still matches the active Rust-native required checks.
