---
title: AI Review Surface
---

# AI Review Surface

This document is the explicit inventory of every open `TODO: AI_REVIEW` site in the repository.
It feeds the claim-led [security assurance protocol](./security-assurance.md) and is enforced by
the local assurance gate.

Nothing in this file implies those constructions are approved. It exists to keep the AI assessment
surface small, concrete, evidence-driven, and hard to forget while the product continues to evolve.

## Current Status

- AI review status: **open**
- expected open AI review sites: **7**
- policy: every `TODO: AI_REVIEW` location in source must be listed here and in the inventory check
- assurance mapping: each open site is represented in [assurance-claims.md](./assurance-claims.md)
  as a `tracked-open` claim

## Open Inventory

| Claim ID | Area | Location | Required AI Assessment |
|----------|------|----------|-------------------------------|
| `audit.serial-correlation-estimator` | Serial correlation audit | `crates/paranoid-core/src/lib.rs` | Verify the serial-correlation coefficient implementation matches the intended estimator and normalization using cited references and known-answer tests. |
| `audit.external-device-health` | External audit-device posture | `crates/paranoid-audit/src/lib.rs` | Verify external audit-device posture, TCP reachability probing, and mTLS JSONL write-ack readiness semantics do not overstate sink availability or federal audit coverage. |
| `ops.shared-policy-boundary` | Ops policy boundary | `crates/paranoid-ops/src/lib.rs` | Verify the shared ops evaluator is the right authorization and audit-evidence boundary for CLI, TUI, GUI, automation adapters, and seal-provider unlock policy. |
| `seal.lifecycle-boundary` | Seal lifecycle posture model | `crates/paranoid-seal/src/lib.rs` | Verify the seal/posture model represents unlock, recovery, and auto-unseal provider posture without overstating provider availability; include evidence from `crates/paranoid-ops/src/lib.rs`, CLI vault tests, and the architecture documentation because ops policy consumes this posture. |
| `vault.device-bound-keyslot` | Device-bound keyslot design | `crates/paranoid-vault/src/lib.rs` | Verify storing the raw master key in platform secure storage plus an AES-GCM verification blob is acceptable for the supported macOS, Windows, and Linux secret-store assumptions. |
| `vault.mnemonic-recovery-keyslot` | Mnemonic recovery construction | `crates/paranoid-vault/src/lib.rs` | Verify whether the current 24-word BIP39-derived material should be used directly as the AES-256-GCM wrapping key for mnemonic recovery slots, or replaced by a stronger derivation scheme. |
| `vault.certificate-wrapped-keyslot` | Certificate-wrapped keyslots | `crates/paranoid-vault/src/lib.rs` | Verify CMS recipient selection, content-encryption policy, and the broader certificate-wrapped keyslot design. |

## Dispositioned Inventory

| Claim ID | Area | Disposition | Evidence |
|----------|------|-------------|----------|
| `audit.chi-squared-tail` | Chi-squared audit | Acceptable as implemented. `paranoid-core` computes Pearson's chi-squared statistic over the fixed password charset bins, uses `df = N - 1` because no distribution parameters are estimated from the audit sample, converts the statistic through the chi-squared upper tail, and treats `p > 0.01` as the pass condition. A larger statistic is therefore more suspicious, matching the NIST/Sematech chi-square goodness-of-fit rejection rule and upper-tail critical-value table. | `crates/paranoid-core/src/lib.rs`; `chi_squared_known_answers_hold`; `chi_squared_upper_tail_threshold_brackets_one_percent_critical_value`; [NIST/Sematech chi-square goodness-of-fit test](https://www.itl.nist.gov/div898/handbook/eda/section3/eda35f.htm); [NIST/Sematech chi-square critical values](https://www.itl.nist.gov/div898/handbook/eda/section3/eda3674.htm) |

Disposition limits:

- The chi-squared audit is an implementation smoke check for gross uniformity drift in generated
  batches. It is not a certification of RNG quality and does not replace OpenSSL RNG delegation,
  rejection-sampling checks, or release assurance.
- The audit assumes the expected distribution is fixed by the supplied charset. Any future audit
  that estimates distribution parameters from the observed batch must revisit the degrees-of-freedom
  calculation before reusing this disposition.

## Required AI Assessor Output

Each open site must receive a short written AI assessor disposition backed by source evidence,
commands, artifacts, and tests. The disposition must
answer:

1. Is the current construction acceptable as implemented?
2. If yes, what assumptions or deployment limits make it acceptable?
3. If no, what concrete change is required?
4. What tests, invariants, or comments should remain after sign-off?

For UI-sensitive changes, the disposition must also cite rendered screenshot artifacts from
`make test-gui-visual-regression` on Linux or `make test-gui-visual-regression-emulate` on macOS.
The viewport classes are desktop, tablet, and narrow/mobile-class. The default artifact set is
`dist/release/gui-e2e-desktop.png`, `dist/release/gui-e2e-tablet.png`, and
`dist/release/gui-e2e-mobile.png`.

## Closeout Rules

A `TODO: AI_REVIEW` site is only ready to remove when all of the following are true:

1. The AI assessor has produced a concrete written disposition with file and test evidence.
2. The source code and tests have been updated to reflect that disposition.
3. This document has been updated to remove or revise the inventory entry.
4. `scripts/verify_ai_review_inventory.sh` passes with the new expected inventory.

## Operator Commands

List the current review markers:

```bash
rg -n "TODO: AI_REVIEW" crates
```

Verify the inventory matches the source tree:

```bash
bash scripts/verify_ai_review_inventory.sh
```

Capture the GUI evidence artifact when the PR touches UI behavior, layout, or branding:

```bash
make test-gui-visual-regression-emulate
```
