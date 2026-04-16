---
title: Remaining Work PRD
---

# Remaining Work PRD

This document captures the work that still remains **after** the current native-manager and release-hardening session.

It is intentionally scoped to the unfinished surface. It is not a retrospective of what already landed in the current branch.

## Executive Summary

The repo now has a real Rust-native product line:

- `paranoid-passwd` ships as a headless CLI plus default TUI experience
- `paranoid-passwd-gui` exists as a separate native GUI target
- the vault is local-first and encrypted, with `Login`, `SecureNote`, `Card`, and `Identity` items
- recovery and unlock paths now include password recovery, mnemonic recovery, device-bound unlock, and certificate-wrapped keyslots
- backup/restore, transfer packages, search, tags, folders, password history, duplicate detection, clipboard auto-clear, and idle auto-lock are implemented
- GitHub Pages serves docs/downloads only
- release verification, archive inspection, Linux `.deb`, and macOS GUI `.dmg` / `.app` packaging now exist in-repo

What remains is no longer “build the product.” It is “close the production, assurance, and platform-distribution gaps so the product can honestly be called finished to the same standard everywhere.”

## Scope

This PRD covers only the work **not handled in the current session**:

1. live release qualification on GitHub
2. human cryptography and statistics review
3. installer-grade platform packaging and signing
4. remaining recovery / lifecycle polish that depends on those reviews
5. post-GA assurance work that should not be improvised later

## Non-Goals

The following are **not** part of this PRD:

- reintroducing browser, WASM, JavaScript, or webview surfaces
- sync, browser extensions, or autofill
- cloud storage or multi-user collaboration
- weakening the current trust model to speed up packaging

## Current Baseline

The current branch should be treated as the functional baseline:

- native CLI, TUI, and GUI surfaces exist
- vault CRUD and item-kind coverage exist
- keyslot lifecycle exists
- backup/restore and transfer packages exist
- offline Cargo + vendored dependency policy exists
- docs, release verification, and supply-chain checks exist

The remaining work therefore falls into qualification, review, packaging, and closure.

## Product Goal

Ship a local-first password manager and generator whose implementation, release process, and operating guidance are all strong enough that:

1. the product is trustworthy on every supported platform
2. the recovery model is explicit and defensible
3. the release artifacts are verifiably the intended ones
4. the remaining human-review surface is closed through written sign-off, not implicit confidence

## Workstream 1: Live Release Qualification

### Problem

The repo-owned release pipeline is implemented and locally validated, but it has not yet been proven end to end through a real canary release from `main`.

### Goals

- prove the live GitHub release path matches the local builder-first validation path
- prove the docs/download site resolves to the correct published assets
- prove package-manifest publication and release verification behave correctly against a real tag

### Requirements

1. Cut one canary release from `main`.
2. Verify the published asset set includes:
   - CLI archives for every supported platform/arch
   - GUI archives for every supported platform/arch
   - Linux `.deb` packages
   - macOS GUI `.dmg` images
   - `checksums.txt`
3. Verify `scripts/verify_published_release.sh` succeeds against the published tag.
4. Verify GitHub attestation for at least one artifact from each shipped packaging family.
5. Verify docs download links and `install.sh` resolve and install the intended artifact family.
6. Verify downstream package-manager PR automation succeeded or failed loudly.

### Acceptance Criteria

- one canary release completes without manual patching of released assets
- published-release verification passes against the real tag
- no stale browser-era or otherwise unexpected assets are attached
- the release checklist in [release-checklist.md](./release-checklist.md) is sufficient for a second operator to repeat the process

## Workstream 2: Human Cryptography and Statistics Review

### Problem

The repo explicitly tracks open `TODO: HUMAN_REVIEW` sites, but those reviews are still open. Until they are dispositioned, the code is implemented but not fully signed off.

### Source of Truth

See [human-review.md](./human-review.md).

### Review Areas

1. chi-squared audit interpretation and thresholding in `paranoid-core`
2. serial-correlation estimator and normalization in `paranoid-core`
3. device-bound keyslot design and secure-storage assumptions in `paranoid-vault`
4. mnemonic recovery construction in `paranoid-vault`
5. certificate-wrapped keyslot design, including CMS recipient selection and transport-key policy in `paranoid-vault`

### Requirements

For each review area:

1. produce a written disposition
2. decide whether the current implementation is acceptable, acceptable with constraints, or requires change
3. update code comments and tests to reflect the disposition
4. remove or revise the corresponding `TODO: HUMAN_REVIEW`
5. update [human-review.md](./human-review.md) and keep `scripts/verify_human_review_inventory.sh` passing

### Acceptance Criteria

- every tracked human-review site has a concrete disposition
- no `TODO: HUMAN_REVIEW` markers remain without an entry in [human-review.md](./human-review.md)
- any required design changes from review have been implemented and tested

## Workstream 3: Installer-Grade Platform Distribution

### Problem

The repo now ships archives, Linux `.deb`, and macOS GUI `.dmg` / `.app` payloads, but it does **not** yet ship fully native installer-grade experiences across platforms.

### Goals

- move from “downloadable release payloads” to “standard install surfaces”
- preserve builder-first verification and narrow trust boundaries

### Platform Requirements

#### macOS

- sign the GUI `.app`
- notarize the app / disk image
- verify Gatekeeper-friendly install/open behavior
- decide whether CLI distribution stays archive-only or also receives a package/install shim

#### Windows

- add a native signed installer for the GUI
- decide and standardize the installer technology
  - expected contenders: WiX/MSI or MSIX
- ensure the installed app preserves the same vault/keyslot behavior as archive execution
- keep CLI distribution separate and scriptable

#### Linux

- keep `.deb` as a first-class package format
- decide whether one additional desktop-oriented package is required
  - likely candidates: AppImage or Flatpak
- if added, it must be verifiable through the same payload-inspection model

### Acceptance Criteria

- each supported desktop platform has one standard native install path
- packaging and payload verification remain repo-owned
- GUI installation guidance in the docs matches the actual shipped installers

## Workstream 4: Release and Recovery Operations Closure

### Problem

The product has strong recovery mechanics, but operational closure is still incomplete.

### Requirements

1. Document the expected operator flow for:
   - adding recovery keyslots
   - rotating mnemonic recovery
   - rewrapping certificate slots
   - rebinding device slots
   - exporting/restoring encrypted backups
   - moving selected records through transfer packages
2. Add any missing recovery-lifecycle tests uncovered by human review.
3. Ensure the docs clearly distinguish:
   - encrypted backup/restore
   - selected-item transfer
   - daily passwordless unlock
   - disaster recovery
4. Decide whether certificate slot lifecycle needs explicit expiration / rollover runbooks beyond the current health warnings.

### Acceptance Criteria

- an operator can follow the docs to maintain a vault through normal rotation and recovery events
- there is no recovery path whose safety depends on tribal knowledge

## Workstream 5: External Assurance

### Problem

Local tests and in-repo verification are strong, but external assurance is still missing.

### Requirements

1. Commission human review of the tracked crypto/statistics surface.
2. Commission review of the release and supply-chain model after the canary release passes.
3. Preserve the written outcomes inside the repo, not only in external conversations.

### Acceptance Criteria

- external review outputs are linked or summarized in the docs
- follow-up changes from external review are landed
- the remaining trust claims in the docs match those external findings

## Deferred / Optional Work

These are not blockers for the current product line, but they should stay explicit:

- optional enterprise profile using a stricter OpenSSL-only recovery/KDF mode if a real compliance requirement appears
- additional Linux desktop package formats if distribution needs justify them
- broader lifecycle policy automation, such as certificate expiry reminders, only after the core release and review work is closed

## Risks

### 1. False Sense of Completion

The code now does a lot, which makes it easy to mistake implementation completeness for production completeness. The live release and human-review gaps are still real blockers.

### 2. Recovery Model Drift

If future work changes mnemonic, certificate, or device-bound behavior without revisiting the written recovery docs, the product will become harder to operate safely.

### 3. Packaging Drift

Adding platform installers without preserving the current repo-owned validation model would weaken the supply-chain story.

## Exit Criteria

This PRD is complete when all of the following are true:

1. the current PR is merged and its release-hardening changes are on `main`
2. one real canary release from `main` passes end to end
3. the human-review inventory is fully dispositioned
4. supported desktop platforms have standard installer-grade distribution
5. docs and runbooks match the real shipped product and recovery model

## Immediate Next Actions

1. let the current PR merge once the GitHub checks complete
2. run the first canary release from `main`
3. start the human-review process using [human-review.md](./human-review.md)
4. choose the Windows installer technology and macOS signing/notarization path
5. update this PRD as those decisions are made
