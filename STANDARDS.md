---
title: Standards
updated: 2026-04-15
status: current
domain: technical
---

# Code Standards — paranoid-passwd

## Non-Negotiable Constraints

1. Keep security-sensitive logic in `crates/paranoid-core`.
2. Do not reintroduce browser, WASM, JavaScript, or webview runtime surfaces.
3. All GitHub Actions must remain pinned to 40-character commit SHAs.
4. Cargo commands in CI and documented workflows must use `--locked --frozen --offline`.
5. The only allowed security/math TODO marker is `TODO: HUMAN_REVIEW - <reason>`.
6. Do not add `unsafe` Rust without explicit human approval.

## Workspace Responsibilities

| Crate | Responsibility |
|------|----------------|
| `paranoid-core` | generation, rejection sampling, OpenSSL-backed RNG/SHA-256, statistical audit, compliance |
| `paranoid-cli` | scriptable CLI and TUI |
| `paranoid-gui` | desktop GUI scaffold and follow-on parity work |

## Rust Style

Files: `crates/**/*.rs`

- Use `snake_case` for functions and variables, `UpperCamelCase` for types.
- Prefer small typed structs over unstructured maps or tuples for user-facing results.
- Comments should explain security or design intent, not restate obvious code.
- Keep UI crates as consumers of typed results; do not duplicate audit logic outside `paranoid-core`.
- Avoid `unwrap()` in production code.

## Security Invariants

- Rejection sampling boundary must remain `(256 / N) * N - 1`.
- Chi-squared pass condition must remain `p > 0.01`.
- Chi-squared degrees of freedom must remain `N - 1`.
- RNG and SHA-256 must remain delegated to OpenSSL through Rust bindings.
- Distribution/special-function math should use `statrs` instead of handwritten approximations where practical.

## Documentation

- Public docs live in `docs/` and must reflect the Rust-native CLI/TUI/docs-site architecture.
- `README.md`, `SECURITY.md`, `AGENTS.md`, and `CLAUDE.md` must not describe the retired web/WASM product as current.

## CI and Release

- `make ci` is the local baseline before merge.
- Required verification includes:
  - `cargo fmt --check`
  - `cargo clippy --workspace --all-targets --locked --frozen --offline -- -D warnings`
  - `cargo test --workspace --locked --frozen --offline`
  - `bash tests/test_cli.sh target/debug/paranoid-passwd`
  - `bash scripts/hallucination_check.sh`
  - `bash scripts/supply_chain_verify.sh`
  - `python3 -m tox -e docs`
