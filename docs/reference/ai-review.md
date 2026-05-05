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
- expected open AI review sites: **8**
- policy: every `TODO: AI_REVIEW` location in source must be listed here and in the inventory check
- assurance mapping: each open site is represented in [assurance-claims.md](./assurance-claims.md)
  as a `tracked-open` claim

## Open Inventory

| Area | Location | Required AI Assessment |
|------|----------|-------------------------------|
| Chi-squared audit | `crates/paranoid-core/src/lib.rs` | Verify the chi-squared upper-tail interpretation, `p > 0.01` thresholding, and how that maps to the intended generator verdict using cited math references and known-answer tests. |
| Serial correlation audit | `crates/paranoid-core/src/lib.rs` | Verify the serial-correlation coefficient implementation matches the intended estimator and normalization using cited references and known-answer tests. |
| External audit-device posture | `crates/paranoid-audit/src/lib.rs` | Verify external audit-device posture, TCP reachability probing, and ready write-ack semantics do not overstate sink availability or federal audit coverage. |
| Ops policy boundary | `crates/paranoid-ops/src/lib.rs` | Verify the shared ops evaluator is the right authorization and audit-evidence boundary for CLI, TUI, GUI, automation adapters, and seal-provider unlock policy. |
| Seal lifecycle posture model | `crates/paranoid-seal/src/lib.rs` | Verify the seal/posture model represents unlock, recovery, and auto-unseal provider posture without overstating provider availability. |
| Device-bound keyslot design | `crates/paranoid-vault/src/lib.rs` | Verify storing the raw master key in platform secure storage plus an AES-GCM verification blob is acceptable for the supported macOS, Windows, and Linux secret-store assumptions. |
| Mnemonic recovery construction | `crates/paranoid-vault/src/lib.rs` | Verify whether the current 24-word BIP39-derived material should be used directly as the AES-256-GCM wrapping key for mnemonic recovery slots, or replaced by a stronger derivation scheme. |
| Certificate-wrapped keyslots | `crates/paranoid-vault/src/lib.rs` | Verify CMS recipient selection, content-encryption policy, and the broader certificate-wrapped keyslot design. |

## Required AI Assessor Output

Each open site must receive a short written AI assessor disposition backed by source evidence,
commands, artifacts, and tests. The disposition must
answer:

1. Is the current construction acceptable as implemented?
2. If yes, what assumptions or deployment limits make it acceptable?
3. If no, what concrete change is required?
4. What tests, invariants, or comments should remain after sign-off?

For UI-sensitive changes, the disposition must also cite a rendered screenshot artifact from
`make test-gui-e2e` on Linux or `make test-gui-e2e-emulate` on macOS. The default screenshot path is
`dist/release/gui-e2e.png`.

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
make test-gui-e2e-emulate
```
