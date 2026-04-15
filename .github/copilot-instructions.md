# GitHub Copilot Instructions — Agent Shim

This repository's authoritative agent instructions live in [`AGENTS.md`](../AGENTS.md).

## Current Product Surface

`paranoid-passwd` is a Rust-native password generator with:

- `crates/paranoid-core` for generation, audit math, compliance, and OpenSSL-backed RNG/SHA-256
- `crates/paranoid-cli` for the scriptable CLI and default TUI
- `crates/paranoid-gui` for the desktop GUI follow-on path
- a Sphinx docs/download site instead of an interactive browser app

## Non-Negotiable Rules

1. Treat `AGENTS.md` as the source of truth before making changes.
2. Keep security-sensitive logic in `crates/paranoid-core`.
3. Do not reintroduce browser, WASM, JavaScript, or webview runtime paths.
4. Keep rejection sampling at `(256/N)*N - 1`.
5. Keep chi-squared pass logic at `p > 0.01` with degrees of freedom `N - 1`.
6. Do not add `unsafe` Rust without explicit human approval.
7. Run `make ci` before considering work complete.

If anything here conflicts with `AGENTS.md`, follow `AGENTS.md`.
