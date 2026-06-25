---
title: Production Closure and Follow-Up Record
---

# Production Closure and Follow-Up Record

This document was used to track the production and assurance backlog after the
Rust-native migration. It now records the closed baseline on `main` and the
explicit future work that is not a blocker for the current product line.

The current status is: **closed for the native CLI/TUI/GUI release baseline**.

## Closed Baseline

The repo now has a Rust-native product line with:

- `paranoid-passwd` as the scriptable CLI and default interactive TUI
- `paranoid-passwd-gui` as the dedicated Slint-native GUI surface
- `paranoid-core` owning password generation, OpenSSL-backed RNG/SHA-256,
  rejection sampling, statistical audit, and compliance checks
- `paranoid-vault` owning encrypted local storage, keyslots, backups,
  transfer packages, recovery posture, and vault lifecycle operations
- `paranoid-ops`, `paranoid-audit`, and `paranoid-seal` owning typed command
  evidence, audit health, federal-ready startup evidence, seal posture, and
  method-specific provider availability
- GitHub Pages serving docs/downloads only, with the retired browser and
  JavaScript product path absent from the secret-handling surface

The production closure work that this PRD originally tracked has landed:

1. CLI, TUI, GUI, and mTLS automation evidence share typed ops policy and
   audit boundaries for covered vault operations.
   The closure record preserves the evidence anchor: seal-state transitions and seal-provider posture have unit tests and e2e coverage.
2. Federal-ready startup evidence and control mapping are deterministic and
   avoid claiming FedRAMP, FIPS, GovCloud, DoD IL5, or other authorization
   status that the project does not hold.
3. The CI/CD trust root is the digest-pinned Wolfi builder, and remote Rust CI
   runs the full local `make ci` gate inside that builder.
4. The scanner/toolchain contract is manifest-pinned and checked by the
   supply-chain verifier.
5. The AI review surface is dispositioned and gate-protected; no open
   `TODO: AI_REVIEW` sites remain.
6. Release verification covers archives, Linux `.deb` packages, macOS `.dmg`
   images, Windows GUI WiX Toolset MSI payloads, checksums, attestations,
   payload layout, platform-signing boundaries, and host-native smoke paths.
7. Recovery operations are documented and exercised by existing CLI/TUI/GUI
   and vault lifecycle tests.

## Assurance Disposition

The closed AI review areas are:

- chi-squared audit interpretation and thresholding in `paranoid-core`
- serial-correlation estimator and normalization in `paranoid-core`
- external audit-device posture in `paranoid-audit` and `paranoid-ops`
- shared ops policy boundary across CLI, TUI, GUI, and mTLS automation adapters
- seal lifecycle posture and method-specific unlock policy
- device-bound keyslot design and local secure-storage assumptions in
  `paranoid-vault`
- mnemonic recovery construction and generated 24-word BIP39 recovery-key
  assumptions in `paranoid-vault`
- certificate-wrapped keyslot design, including CMS recipient selection and
  transport-key policy in `paranoid-vault`

New AI review markers must be introduced only with matching entries in
[AI Review Surface](./ai-review.md), [Assurance Claims](./assurance-claims.md),
and `scripts/verify_ai_review_inventory.sh`.

## Release and CI Proof

The current release and CI posture is intentionally builder-first:

- `make ci` remains the local release-candidate gate.
- `make verify-assurance` enforces hallucination checks, supply-chain checks,
  AI review inventory, and assurance claims.
- `make quality-emulate` runs the release-candidate quality posture inside the
  Wolfi builder.
- `make verify-branch-protection` checks that required GitHub checks match the
  active Rust-native CI policy.
- `make verify-published-release TAG=paranoid-passwd-v3.7.0` verifies the
  currently published baseline artifact set and host smoke path.

PR #134 closed the last release-download verification mismatch by adding the
Windows GUI MSI to the per-asset Windows-host verification matrix and enforcing
that coverage through tests, docs, and the assurance gate.

The [Recovery Operations](../guides/recovery-operations.md) runbook now covers
normal keyslot enrollment, mnemonic rotation, certificate rollover, device
rebind, encrypted backup/restore, selected-item transfer, daily passwordless
unlock, disaster recovery drills, and strict federal-ready recovery boundaries.

## Current Non-Claims

The product may support customer environments that require precise evidence, but
the docs and code do not claim:

- FedRAMP authorization
- DoD IL5 authorization
- GovCloud deployment authorization
- project-level FIPS validation
- platform-signed artifacts unless the matching signed-mode release checks have
  passed for that artifact family

The current cryptographic-module statement remains limited to the documented
OpenSSL provider boundary and the evidence in
[Federal Readiness](./federal-readiness.md).

## Follow-Up Work

These items are explicit future work, not blockers for the current closed
baseline:

- runtime Android GUI and future mobile release gates after the native desktop
  GUI remains stable
- any future Slint WASM secret-handling surface, which requires a separate
  threat model, storage model, crypto boundary, and release gate
- additional Linux desktop packages such as Flatpak only if distribution needs
  justify them
- MSIX only if a Store, sandbox, or managed-update requirement appears
- external assurance reports when the project wants to upgrade in-repo
  dispositions into stronger public trust claims
- optional enterprise profiles, such as stricter OpenSSL-only recovery/KDF
  policy, if a real compliance requirement appears
- broader PTY coverage for TUI vault mutations that are already covered through
  lower-level typed ops and existing TUI/vault tests
- keyed correlation hashes only after the project has a documented primitive
  and low-entropy secret-risk disposition for that feature
- broader external auto-unseal providers beyond the current local
  device-bound and explicit audit-device readiness model

Future work must preserve the same rules as the closed baseline: no retired
browser product path, no custom cryptography, no ad hoc randomness, no modulo
sampling, no unpinned GitHub Actions, and no drift away from the Wolfi builder
trust root.

## Revalidation Checklist

Before claiming a new production closure point, run the relevant subset of:

```bash
make ci
make verify-assurance
make quality-emulate
make verify-branch-protection
make verify-published-release TAG=<current-release-tag>
```

For UI-sensitive GUI changes, also keep the multi-viewport screenshot evidence
required by [AI Review Surface](./ai-review.md) and the security-assurance
instructions.
