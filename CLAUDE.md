---
title: CLAUDE.md — Rust-Native Entry Point
updated: 2026-04-15
status: current
domain: technical
---

# paranoid-passwd — Agent Entry Point

`paranoid-passwd` is now a Rust-native password generator with:

- `paranoid-core` for generation, audit math, compliance, and OpenSSL-backed crypto delegation
- `paranoid-cli` for the scriptable CLI and default TUI
- `paranoid-gui` for the desktop GUI scaffold
- a Sphinx docs/download site instead of an interactive web app

## Quick Commands

```bash
# Local CI-equivalent verification
make ci

# Build the user-facing binary
cargo build -p paranoid-cli --locked --frozen --offline

# Launch the TUI
cargo run -p paranoid-cli

# Force scriptable CLI mode
cargo run -p paranoid-cli -- --cli --length 24 --count 3

# Build docs
python3 -m tox -e docs
```

## Zero-Exception Rules

1. Keep security-sensitive logic in `crates/paranoid-core`.
2. Do not reintroduce browser, WASM, or webview runtime surfaces.
3. Keep rejection sampling at `(256/N)*N - 1`.
4. Keep chi-squared pass logic at `p > 0.01` and degrees of freedom at `N - 1`.
5. Do not add `unsafe` Rust without explicit human approval.
6. Keep Cargo builds locked, frozen, offline, and backed by `vendor/`.

## Key Files

| Need | Location |
|------|----------|
| Agent protocols | `AGENTS.md` |
| Core logic | `crates/paranoid-core/src/lib.rs` |
| CLI/TUI | `crates/paranoid-cli/src/` |
| GUI scaffold | `crates/paranoid-gui/src/main.rs` |
| Docs site | `docs/` |
| CI/release | `.github/workflows/` |
