---
title: AGENTS.md — Rust-Native Agent Protocols
updated: 2026-04-15
status: current
domain: technical
---

# AGENTS.md — Extended Agent Protocols for paranoid-passwd

This document is mandatory context for agents working in this repository.
The project still treats the LLM as an adversarial contributor by design.

## LLM Clean Room Protocol

Before making any change, complete this self-audit:

- [ ] I acknowledge that my training data includes password breach dumps
- [ ] I will not generate randomness directly; I will delegate to the Rust core's OpenSSL-backed RNG path
- [ ] I will not implement custom cryptographic primitives
- [ ] I will not claim statistical formulas are correct without a human-verifiable source
- [ ] I will not bypass rejection sampling; the boundary remains `(256/N)*N - 1`
- [ ] I will not reintroduce browser, WASM, or JavaScript runtime paths
- [ ] I will keep security-sensitive logic in `crates/paranoid-core`, not in the CLI, TUI, GUI, or docs layer
- [ ] I will flag math/security-sensitive changes with `TODO: HUMAN_REVIEW - <reason>`

If you cannot check all boxes, stop and request human guidance.

## Zero-Exception Rules

### Never
1. Use `rand()`, `srand()`, LLM-generated randomness, or ad hoc entropy helpers
2. Implement a custom hash, cipher, KDF, or PRNG
3. Use modulo without rejection sampling
4. Reintroduce JavaScript, WASM, or webview fallbacks into the product surface
5. Move cryptographic or audit math into the TUI, GUI, docs tooling, or shell scripts
6. Unpin GitHub Actions from commit SHAs
7. Remove audit layers to simplify the UX

### Always
1. Delegate RNG and SHA-256 to the audited `paranoid-core` path
2. Keep rejection sampling at `(256/N)*N - 1`
3. Prefer `statrs` for distribution and special-function math instead of handwritten approximations
4. Add or update known-answer tests when touching audit math
5. Keep Cargo builds locked and offline against the vendored dependency tree
6. Preserve the docs-site role of GitHub Pages; it is not an application surface anymore

## Common Hallucination Patterns

These bugs can look plausible while silently weakening the product:

```rust
// Off-by-one in rejection sampling
let max_valid = (256 / n) * n;     // WRONG
let max_valid = (256 / n) * n - 1; // CORRECT

// Inverted p-value logic
let pass = p_value < 0.01; // WRONG
let pass = p_value > 0.01; // CORRECT

// Wrong degrees of freedom
let df = n;     // WRONG
let df = n - 1; // CORRECT
```

## Change Verification Checklist

Before committing:

### Source Code
- [ ] No ad hoc RNG or custom crypto primitives in new code
- [ ] Rejection sampling still uses `(256/N)*N - 1`
- [ ] Chi-squared pass logic still uses `p > 0.01`
- [ ] Chi-squared degrees of freedom remain `df = N - 1`
- [ ] Math/security-sensitive edits are marked `TODO: HUMAN_REVIEW`

### Build
- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets --locked --frozen --offline -- -D warnings`
- [ ] `cargo test --workspace --locked --frozen --offline`
- [ ] `cargo build -p paranoid-cli --locked --frozen --offline`
- [ ] `bash tests/test_cli.sh target/debug/paranoid-passwd`

### Docs
- [ ] `python3 -m tox -e docs`
- [ ] The generated Rust API docs build under `docs/api/crates/`
- [ ] `README.md` reflects user-facing changes

## Architecture Patterns

### Workspace Roles

| Crate | Responsibility |
|-------|----------------|
| `crates/paranoid-core` | password generation, OpenSSL-backed RNG/SHA-256, statistical audit, compliance checks |
| `crates/paranoid-cli` | scriptable CLI plus full-screen wizard TUI |
| `crates/paranoid-gui` | desktop GUI scaffold and follow-on parity path |

Never duplicate generation, hashing, or audit logic outside `paranoid-core`.

### Product Surface

- The interactive web app is retired.
- GitHub Pages now serves a Sphinx docs/download site only.
- The TUI is the default interactive experience.
- The CLI remains the scriptable automation surface.
- The GUI is a native desktop follow-on, not a webview wrapper.

### Dependency Trust Model

- Cargo dependencies are vendored under `vendor/`.
- Workspace Cargo commands should run with `--locked --frozen --offline`.
- `statrs` is the approved crate for distribution/special-function math.
- `openssl` is the approved native cryptography backend.
- `zeroize` is the approved secret-scrubbing helper.

## For Human Cryptographers

Focus review on:

1. `crates/paranoid-core/src/lib.rs` rejection sampling, chi-squared usage, serial correlation, and compliance thresholds
2. The OpenSSL-backed RNG / SHA-256 delegation paths in `paranoid-core`
3. Any `TODO: HUMAN_REVIEW` sites added around statistical or security logic
4. Release and supply-chain changes under `.github/`, `.cargo/`, and `vendor/`

## Documentation Map

The current public documentation lives in the Sphinx docs tree:

| Document | Content |
|----------|---------|
| `README.md` | repo-level overview and local workflow |
| `docs/index.md` | public docs landing page |
| `docs/getting-started/index.md` | install and first-run guidance |
| `docs/guides/tui.md` | TUI workflow |
| `docs/reference/architecture.md` | current native architecture |
| `docs/reference/testing.md` | Rust/TUI/docs test strategy |
| `docs/reference/supply-chain.md` | builder-first supply-chain model |
| `docs/reference/release-verification.md` | attestation and checksum verification |
