---
title: Human Review Surface
---

# Human Review Surface

This document is the explicit inventory of every open `TODO: HUMAN_REVIEW` site in the repository.
It now feeds the claim-led [security assurance protocol](./security-assurance.md) instead of
standing alone as an open-ended release blocker.

Nothing in this file implies those constructions are approved. It exists to keep the review surface
small, concrete, and hard to forget while the product continues to evolve.

## Current Status

- review status: **open**
- expected open review sites: **7**
- policy: every `TODO: HUMAN_REVIEW` location in source must be listed here and in the inventory check
- assurance mapping: each open site is represented in [assurance-claims.md](./assurance-claims.md)
  as a `tracked-open` claim

## Open Inventory

| Area | Location | What Needs Human Confirmation |
|------|----------|-------------------------------|
| Chi-squared audit | `crates/paranoid-core/src/lib.rs` | Confirm the chi-squared upper-tail interpretation, `p > 0.01` thresholding, and how that maps to the intended generator verdict. |
| Serial correlation audit | `crates/paranoid-core/src/lib.rs` | Confirm the serial-correlation coefficient implementation matches the intended estimator and normalization. |
| Ops policy boundary | `crates/paranoid-ops/src/lib.rs` | Confirm the shared ops evaluator is the right authorization and audit-evidence boundary for CLI, TUI, GUI, and automation adapters. |
| Seal lifecycle posture model | `crates/paranoid-seal/src/lib.rs` | Confirm the seal/posture model correctly represents unlock and recovery posture without overstating provider availability. |
| Device-bound keyslot design | `crates/paranoid-vault/src/lib.rs` | Confirm storing the raw master key in platform secure storage plus an AES-GCM verification blob is acceptable across macOS, Windows, and Linux secret stores. |
| Mnemonic recovery construction | `crates/paranoid-vault/src/lib.rs` | Confirm whether the current 24-word BIP39-derived material should be used directly as the AES-256-GCM wrapping key for mnemonic recovery slots, or replaced by a stronger derivation scheme. |
| Certificate-wrapped keyslots | `crates/paranoid-vault/src/lib.rs` | Confirm CMS recipient selection, content-encryption policy, and the broader certificate-wrapped keyslot design. |

## Required Review Output

Each open site should receive a short written disposition from a qualified reviewer, a maintainer
decision backed by source changes and tests, or a later external assessment. The disposition must
answer:

1. Is the current construction acceptable as implemented?
2. If yes, what assumptions or deployment limits make it acceptable?
3. If no, what concrete change is required?
4. What tests, invariants, or comments should remain after sign-off?

## Closeout Rules

A `TODO: HUMAN_REVIEW` site is only ready to remove when all of the following are true:

1. The reviewer has produced a concrete written disposition.
2. The source code and tests have been updated to reflect that disposition.
3. This document has been updated to remove or revise the inventory entry.
4. `scripts/verify_human_review_inventory.sh` passes with the new expected inventory.

## Operator Commands

List the current review markers:

```bash
rg -n "TODO: HUMAN_REVIEW" crates
```

Verify the inventory matches the source tree:

```bash
bash scripts/verify_human_review_inventory.sh
```
