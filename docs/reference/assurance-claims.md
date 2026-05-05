---
title: Assurance Claims
---

# Assurance Claims

This file is the claim inventory used by the security assurance protocol. Claims are
stable identifiers that pull request assessors, CI reports, and release notes can cite.

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
| `audit.chi-squared-tail` | `tracked-open` | The chi-squared audit uses `statrs`, degrees of freedom `N - 1`, and pass logic `p > 0.01`. | `crates/paranoid-core/src/lib.rs`; `scripts/hallucination_check.sh`; `docs/reference/ai-review.md` |
| `audit.serial-correlation-estimator` | `tracked-open` | Serial-correlation reporting remains implemented in `paranoid-core` and remains explicitly tracked until the estimator is dispositioned. | `crates/paranoid-core/src/lib.rs`; `docs/reference/ai-review.md`; known-answer tests |
| `surface.no-browser-runtime` | `enforced` | The product surface does not reintroduce the retired browser app, JavaScript secret-handling logic, DOM UI, webview wrappers, or retired C paths; future Slint WASM/mobile surfaces require separate threat models and release gates. | `scripts/hallucination_check.sh`; `docs/reference/architecture.md`; `.github/copilot-instructions.md` |

## Vault and Recovery Claims

| Claim ID | State | Claim | Evidence |
|---------|-------|-------|----------|
| `vault.device-bound-keyslot` | `tracked-open` | Device-bound unlock stores the raw master key only in platform secure storage and validates it with an AES-GCM verification blob. | `crates/paranoid-vault/src/lib.rs`; CLI vault TUI tests; `docs/reference/ai-review.md` |
| `vault.mnemonic-recovery-keyslot` | `tracked-open` | Mnemonic recovery slots use 24-word BIP39 entropy as the current AES-256-GCM wrapping material until a disposition changes that construction. | `crates/paranoid-vault/src/lib.rs`; vault tests; `docs/reference/ai-review.md` |
| `vault.certificate-wrapped-keyslot` | `tracked-open` | Certificate-wrapped keyslots use the current CMS recipient and content-encryption policy until a disposition changes that construction. | `crates/paranoid-vault/src/lib.rs`; vault tests; `docs/reference/ai-review.md` |
| `ops.shared-policy-boundary` | `tracked-open` | The shared ops evaluator gates adapter-initiated vault operations, consumes non-secret seal posture for unlock policy, and emits request/response audit evidence until an AI assessor disposition confirms the boundary. | `crates/paranoid-ops/src/lib.rs`; CLI vault tests; TUI vault tests; native GUI automation tests; durable GUI JSONL tests; `docs/reference/ai-review.md` |
| `ops.vault-trace-fixtures` | `enforced` | Stable CLI/TUI/GUI vault operation trace fixtures pin typed command envelopes, policy decisions, redacted request/response audit events, and JSONL rendering. | `crates/paranoid-ops/tests/ops_trace_fixtures.rs`; `crates/paranoid-ops/tests/fixtures/`; `docs/reference/testing.md` |
| `ops.mtls-process-boundary-fixture` | `enforced` | mTLS process-boundary command fixtures pin authenticated transport evidence, service-account actor context, and fail-closed policy when security-relevant commands lack authenticated transport evidence. | `crates/paranoid-ops/src/lib.rs`; `crates/paranoid-ops/tests/ops_trace_fixtures.rs`; `crates/paranoid-ops/tests/fixtures/ops_trace_mtls_process_boundary_allowed.json`; `docs/reference/testing.md` |
| `audit.external-device-health` | `tracked-open` | External audit-device configuration and TCP reachability are reported as evidence only; the mTLS JSONL write-ack probe reports ready only after a matching challenge acknowledgement. Unverified or unavailable external devices do not satisfy required audit policy while probe semantics remain tracked for AI review. | `crates/paranoid-audit/src/lib.rs`; `crates/paranoid-ops/src/lib.rs`; audit probe tests; stable federal startup fixtures; CLI evidence tests; `docs/reference/ai-review.md` |
| `seal.lifecycle-boundary` | `tracked-open` | Seal state and non-secret provider posture are owned by `paranoid-seal`, consumed by ops unlock policy, re-exported by ops for adapter stability, and emitted by `vault seal-status` without decrypting item payloads while the posture semantics remain tracked for AI review. | `crates/paranoid-seal/src/lib.rs`; `crates/paranoid-ops/src/lib.rs`; CLI vault tests; `docs/reference/ai-review.md`; `docs/reference/architecture.md` |
| `federal.control-mapping-evidence` | `process` | Federal-ready evidence is mapped to NIST SP 800-53 Rev5 families without claiming FedRAMP authorization, DoD IL5 authorization, or product FIPS validation. | `docs/reference/control-mapping.md`; `docs/reference/federal-readiness.md`; `scripts/security_assurance_gate.py` |

## Supply Chain and Release Claims

| Claim ID | State | Claim | Evidence |
|---------|-------|-------|----------|
| `supply-chain.locked-offline-cargo` | `process` | Cargo commands used by CI and release verification stay locked, frozen, offline, and backed by the vendored dependency tree. | `.cargo/config.toml`; `Cargo.lock`; `vendor/`; `scripts/supply_chain_verify.sh` |
| `supply-chain.sha-pinned-actions` | `process` | External GitHub Actions remain pinned to full commit SHAs. | `.github/workflows/*.yml`; `scripts/supply_chain_verify.sh` |
| `release.payload-verification` | `process` | Release artifacts are built, inspected, smoke-tested, checksummed, and verified by repo-owned scripts. | `scripts/build_release_artifact.sh`; `scripts/release_validate.sh`; `scripts/verify_published_release.sh` |
| `assurance.pr-neutral-ai-assessor` | `process` | PR review has a neutral AI security-assessor profile, path-scoped Copilot instructions, and a deterministic CI gate. | `.github/agents/paranoid-security-auditor.md`; `.github/instructions/security-assurance.instructions.md`; `.github/workflows/security-assurance.yml`; `scripts/security_assurance_gate.py` |
| `assurance.gui-screenshot-evidence` | `process` | UI-sensitive PR review requires the GUI e2e harness and a captured screenshot artifact. | `Makefile`; `tests/test_gui_e2e.sh`; `docs/reference/ai-review.md`; `.github/agents/paranoid-security-auditor.md` |

## Release Interpretation

`tracked-open` does not mean approved. It means the implementation is explicit, tested, and
covered by a stable claim identifier, while the repo continues to carry the source-level
`TODO: AI_REVIEW` marker and the inventory check. A stable release may say those areas
are tracked and gate-protected, but it must not say they have external cryptographic or
statistical approval until a written disposition exists.

When a pull request changes an enforced or process claim, it must update the relevant gate
or documentation in the same PR. When it changes a tracked-open claim, it must update this
file, [ai-review.md](./ai-review.md), and the corresponding source comments or tests.
