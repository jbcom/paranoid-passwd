# GitHub Copilot Instructions — Agent Shim

This repository's authoritative agent instructions live in [`AGENTS.md`](../AGENTS.md).

## Current Product Surface

`paranoid-passwd` is a Rust-native password manager and generator with:

- `crates/paranoid-core` for generation, audit math, compliance, and OpenSSL-backed RNG/SHA-256
- `crates/paranoid-cli` for the scriptable CLI and default TUI
- `crates/paranoid-gui` for the Slint-first GUI direction, with the current Iced surface retained during migration
- a Sphinx docs/download site instead of an interactive browser app

Security assurance is claim-led. Use `docs/reference/security-assurance.md`,
`docs/reference/assurance-claims.md`, and `.github/agents/paranoid-security-auditor.md`
for security-sensitive PR review.

## Non-Negotiable Rules

1. Treat `AGENTS.md` as the source of truth before making changes.
2. Keep security-sensitive logic in `crates/paranoid-core`.
3. Do not reintroduce the retired browser app, JavaScript secret-handling logic, DOM UI, or webview runtime paths.
4. Treat any Slint WASM or mobile work as a separately gated Rust-native surface with an explicit threat model.
5. Keep rejection sampling at `(256/N)*N - 1`.
6. Keep chi-squared pass logic at `p > 0.01` with degrees of freedom `N - 1`.
7. Do not add handwritten `unsafe` Rust without explicit human approval; Slint-generated GUI code is the only current unsafe-code lint exception.
8. Run `make verify-assurance` for security-sensitive changes.
9. Run `make ci` before considering work complete.

If anything here conflicts with `AGENTS.md`, follow `AGENTS.md`.
