---
title: Assurance Claims
---

# Assurance Claims

This file is the claim inventory used by the security assurance protocol. Claims are
stable identifiers that pull request reviewers, CI reports, and release notes can cite.

Claim states:

- `enforced`: deterministic source checks, tests, or CI gates directly protect the claim
- `tracked-open`: the implementation exists, but the repo deliberately keeps an open
  disposition marker until the construction is strengthened or formally accepted
- `process`: the claim is about release, supply chain, or review workflow behavior

## Core Generation and Audit Claims

| Claim ID | State | Claim | Evidence |
|---------|-------|-------|----------|
| `rng.openssl-delegation` | `enforced` | Password generation RNG and SHA-256 remain delegated to `paranoid-core` OpenSSL-backed paths. | `crates/paranoid-core/src/lib.rs`; `scripts/hallucination_check.sh`; `make verify-assurance` |
| `rng.rejection-sampling-boundary` | `enforced` | Rejection sampling keeps the inclusive boundary `(256/N)*N - 1`; modulo reduction is not allowed. | `crates/paranoid-core/src/lib.rs`; `scripts/hallucination_check.sh`; core tests |
| `audit.chi-squared-tail` | `tracked-open` | The chi-squared audit uses `statrs`, degrees of freedom `N - 1`, and pass logic `p > 0.01`. | `crates/paranoid-core/src/lib.rs`; `scripts/hallucination_check.sh`; `docs/reference/human-review.md` |
| `audit.serial-correlation-estimator` | `tracked-open` | Serial-correlation reporting remains implemented in `paranoid-core` and remains explicitly tracked until the estimator is dispositioned. | `crates/paranoid-core/src/lib.rs`; `docs/reference/human-review.md`; known-answer tests |
| `surface.no-browser-runtime` | `enforced` | The product surface does not reintroduce the retired browser app, JavaScript secret-handling logic, DOM UI, webview wrappers, or retired C paths; future Slint WASM/mobile surfaces require separate threat models and release gates. | `scripts/hallucination_check.sh`; `docs/reference/architecture.md`; `.github/copilot-instructions.md` |

## Vault and Recovery Claims

| Claim ID | State | Claim | Evidence |
|---------|-------|-------|----------|
| `vault.device-bound-keyslot` | `tracked-open` | Device-bound unlock stores the raw master key only in platform secure storage and validates it with an AES-GCM verification blob. | `crates/paranoid-vault/src/lib.rs`; CLI vault TUI tests; `docs/reference/human-review.md` |
| `vault.mnemonic-recovery-keyslot` | `tracked-open` | Mnemonic recovery slots use 24-word BIP39 entropy as the current AES-256-GCM wrapping material until a disposition changes that construction. | `crates/paranoid-vault/src/lib.rs`; vault tests; `docs/reference/human-review.md` |
| `vault.certificate-wrapped-keyslot` | `tracked-open` | Certificate-wrapped keyslots use the current CMS recipient and content-encryption policy until a disposition changes that construction. | `crates/paranoid-vault/src/lib.rs`; vault tests; `docs/reference/human-review.md` |

## Supply Chain and Release Claims

| Claim ID | State | Claim | Evidence |
|---------|-------|-------|----------|
| `supply-chain.locked-offline-cargo` | `process` | Cargo commands used by CI and release verification stay locked, frozen, offline, and backed by the vendored dependency tree. | `.cargo/config.toml`; `Cargo.lock`; `vendor/`; `scripts/supply_chain_verify.sh` |
| `supply-chain.sha-pinned-actions` | `process` | External GitHub Actions remain pinned to full commit SHAs. | `.github/workflows/*.yml`; `scripts/supply_chain_verify.sh` |
| `release.payload-verification` | `process` | Release artifacts are built, inspected, smoke-tested, checksummed, and verified by repo-owned scripts. | `scripts/build_release_artifact.sh`; `scripts/release_validate.sh`; `scripts/verify_published_release.sh` |
| `assurance.pr-neutral-auditor` | `process` | PR review has a neutral security-auditor profile, path-scoped Copilot instructions, and a deterministic CI gate. | `.github/agents/paranoid-security-auditor.md`; `.github/instructions/security-assurance.instructions.md`; `.github/workflows/security-assurance.yml`; `scripts/security_assurance_gate.py` |

## Release Interpretation

`tracked-open` does not mean approved. It means the implementation is explicit, tested, and
covered by a stable claim identifier, while the repo continues to carry the source-level
`TODO: HUMAN_REVIEW` marker and the inventory check. A stable release may say those areas
are tracked and gate-protected, but it must not say they have external cryptographic or
statistical approval until a written disposition exists.

When a pull request changes an enforced or process claim, it must update the relevant gate
or documentation in the same PR. When it changes a tracked-open claim, it must update this
file, [human-review.md](./human-review.md), and the corresponding source comments or tests.
