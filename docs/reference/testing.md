---
title: Testing
---

# Testing

The Rust replatform keeps the audit behavior covered in native tests and removes the old browser/WASM test surface.

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
- CRUD coverage for login items
- wrong-password fail-closed coverage
- generator-to-vault `generate-store` coverage

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

- `make smoke-release` builds and smoke-tests the host-native archive.
- `make release-emulate` drives the Linux release packaging path through the custom builder image.
- `scripts/release_validate.sh` is used in CI after the full matrix build to verify all archives, package-manager manifests, and `install.sh`.
- `make verify-branch-protection` checks that GitHub branch protection still matches the active Rust-native required checks.
