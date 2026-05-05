---
applyTo: "crates/paranoid-core/**,crates/paranoid-vault/**,.github/**,scripts/**,Makefile,.cargo/**,Cargo.lock,docs/reference/**,AGENTS.md,SECURITY.md"
---

# Security Assurance Instructions

Review changes against `docs/reference/security-assurance.md` and
`docs/reference/assurance-claims.md`.

Treat the model as a reviewer, not an approver. Findings must cite files and line numbers.
Missing evidence is blocking when a PR touches generation, audit math, vault keyslots,
release workflows, dependency policy, or security reference docs.

Required checks before merge:

- `make verify-assurance`
- `make ci` unless the change is strictly docs-only

Never waive these invariants:

- RNG and SHA-256 stay delegated to the OpenSSL-backed `paranoid-core` path.
- Rejection sampling keeps `(256/N)*N - 1`.
- Chi-squared pass logic remains `p > 0.01` with `N - 1` degrees of freedom unless a
  written claim disposition and known-answer tests land in the same PR.
- No custom crypto primitives.
- No browser, WASM, JavaScript, webview, or retired C product surface.
- External GitHub Actions remain SHA-pinned.
- Cargo CI and release commands stay locked, frozen, offline, and vendored.
- `TODO: HUMAN_REVIEW` markers are not removed without updating
  `docs/reference/human-review.md`, `docs/reference/assurance-claims.md`, and
  `scripts/verify_human_review_inventory.sh`.
