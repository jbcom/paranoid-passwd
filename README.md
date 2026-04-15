---
title: paranoid-passwd
updated: 2026-04-15
status: current
domain: product
---

# paranoid-passwd

## The Password Generator That Trusts No One

`paranoid-passwd` is a **Rust-native password generator** with:

- a scriptable CLI
- a full-screen wizard TUI
- a cross-platform GUI crate under active parity work
- an encrypted local vault foundation
- a docs-and-downloads website published from Sphinx

The old interactive GitHub Pages app is retired. `paranoid-passwd.com` now serves documentation, installation instructions, and release links only.

Launch behavior is standardized:

- `paranoid-passwd` defaults to the TUI on an interactive terminal with no operational flags
- `paranoid-passwd` stays headless when generation or vault flags are passed, or when stdin/stdout are not interactive
- `paranoid-passwd-gui` is the dedicated app surface once GUI packaging ships

## Workspace

- [`crates/paranoid-core`](/Users/jbogaty/src/jbcom/paranoid-passwd/crates/paranoid-core/src/lib.rs)
- [`crates/paranoid-cli`](/Users/jbogaty/src/jbcom/paranoid-passwd/crates/paranoid-cli/src/main.rs)
- [`crates/paranoid-gui`](/Users/jbogaty/src/jbcom/paranoid-passwd/crates/paranoid-gui/src/main.rs)
- [`crates/paranoid-vault`](/Users/jbogaty/src/jbcom/paranoid-passwd/crates/paranoid-vault/src/lib.rs)

`paranoid-core` owns generation, rejection sampling, OpenSSL-backed RNG and hashing, statistical audit math, pattern detection, and compliance checks. The CLI, TUI, GUI, and vault flows consume typed Rust results instead of the old WASM memory bridge.

## Quick Start

Interactive:

```bash
cargo run -p paranoid-cli
```

Scriptable CLI:

```bash
cargo run -p paranoid-cli -- --cli --length 24 --count 3 --framework nist,pci_dss
```

Vault foundation:

```bash
export PARANOID_MASTER_PASSWORD='correct horse battery staple'
cargo run -p paranoid-cli -- vault init
cargo run -p paranoid-cli -- vault generate-store --title GitHub --username jon@example.com --length 24
```

Docs site:

```bash
python3 -m tox -e docs
open docs/_build/html/index.html
```

## Build and Test

```bash
make build
make test
make lint
make verify-security
make docs-build
make smoke-release
```

All Cargo commands use the vendored dependency tree through `.cargo/config.toml`.

To emulate the repository CI flow through the custom builder image:

```bash
make ci-emulate
```

To exercise the release packaging path:

```bash
make smoke-release
make release-emulate
make verify-published-release TAG=paranoid-passwd-v3.5.2
```

## Releases

Release archives are published on [GitHub Releases](https://github.com/jbcom/paranoid-passwd/releases). The docs site also hosts:

- [`https://paranoid-passwd.com/install.sh`](https://paranoid-passwd.com/install.sh)
- install and verification guides
- generated Rust API docs via `sphinxcontrib-rust`

The currently shipped release artifact is `paranoid-passwd`, which contains the scriptable CLI and the TUI entrypoint. The GUI crate is tracked in the workspace, but it is not a published release artifact yet.

## Security Posture

- RNG is delegated to OpenSSL through Rust bindings.
- Hashing uses OpenSSL-backed SHA-256.
- Rejection sampling still uses the critical boundary `(256 / N) * N - 1`.
- Chi-squared tail probabilities use `statrs` instead of the old handwritten approximation.
- Vault encryption uses Argon2id plus OpenSSL-backed AES-256-GCM.
- Cargo dependencies are vendored and CI runs Cargo in locked, frozen, offline mode.
- Security verification scripts assert the Rust-native invariants and workflow pinning.
- The browser/WASM runtime path is gone from the product surface.

The statistical thresholds and compliance policies still require human review before production use. The project continues to treat the LLM author as an adversarial contributor by design.
