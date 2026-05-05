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
- local release-candidate quality now runs through Make plus Rust-native `xtask`, with remote CI
  treated as confirmation rather than the first real verifier

What remains is no longer “build the product.” It is “close the production, assurance, and platform-distribution gaps so the product can honestly be called finished to the same standard everywhere.”

## Scope

This PRD covers only the work **not handled in the current session**:

1. completion of typed ops adoption across vault/TUI/GUI flows and seal / auto-unseal lifecycle
2. federal-ready operating profile for FedRAMP High, GovCloud, and DoD IL5 customers
3. live release qualification on GitHub
4. security assurance disposition for the remaining crypto/statistics claims
5. installer-grade platform packaging and signing
6. remaining recovery / lifecycle polish that depends on those dispositions
7. post-GA assurance work that should not be improvised later
8. vendoring or otherwise pinning the local scanner stack update process (`codeql`, `semgrep`,
   `cargo-deny`, `cargo-audit`, `cargo-vet`, `syft`, `trivy`, and `osv-scanner`) so workstation
   setup itself has the same evidence discipline as the repo gates

## Non-Goals

The following are **not** part of this PRD:

- reintroducing the retired HTML/CSS/JavaScript browser app or a webview wrapper
- sync, browser extensions, or autofill
- cloud storage or multi-user collaboration
- weakening the current trust model to speed up packaging

## Current Baseline

The current branch should be treated as the functional baseline:

- native CLI, TUI, and GUI surfaces exist
- Slint is now the committed GUI direction under the GPLv3 licensing path
- vault CRUD and item-kind coverage exist
- keyslot lifecycle exists
- backup/restore and transfer packages exist
- offline Cargo + vendored dependency policy exists
- docs, release verification, and supply-chain checks exist
- the first ops/audit/seal and federal-readiness primitives exist, and CLI/TUI/GUI vault adapters now
  share the local ops policy path for covered flows

The remaining work therefore falls into protocolization, federal readiness, qualification, review,
packaging, and closure.

## Product Goal

Ship a local-first password manager and generator whose implementation, release process, and operating guidance are all strong enough that:

1. the product is trustworthy on every supported platform
2. the recovery model is explicit and defensible
3. the release artifacts are verifiably the intended ones
4. the remaining review surface is governed by written assurance claims, deterministic gates, and
   explicit dispositions rather than implicit confidence
5. federal customers can map product behavior and evidence into their own FedRAMP High, GovCloud, or
   DoD IL5 assessment boundary without accepting vague security claims

## Next Comprehensive PR Boundary

The current ops/audit work adds typed command envelopes, allow/challenge/deny policy, JSONL audit
sinks with writable health evidence, seal-state primitives, and a federal-ready startup evidence
path. Headless vault CLI commands, native TUI actions, and native GUI automation now share that
protocol for covered vault operations rather than drifting back into UI-local patches. The next
architecture boundary should extend the same model into external audit-device health, seal /
auto-unseal provider policy, and stable assessor fixtures.

That PR should be scoped around:

- expanding `crates/paranoid-audit` beyond local JSONL writable-path health into external
  audit-device health
- CLI/TUI/GUI JSONL fixtures and additional automation output over the typed ops protocol
- seal / auto-unseal provider policy
- federal-ready profile fixtures and configured-provider evidence
- docs and tests that make the trust boundary reviewable

## Workstream 1: Ops Protocol, Audit Crate, and Seal Lifecycle

### Problem

The current surfaces share vault/core behavior, but operation orchestration, audit output, and seal
state still live too close to the presentation layers. That makes it harder to prove the command
chain, harder to produce assessor evidence, and harder to keep GUI/TUI/CLI behavior identical as the
product grows.

### Goals

- move sensitive command orchestration into `paranoid-ops`
- replace primitive logging with `paranoid-audit`
- model seal, unseal, auto-unseal, idle-lock, and recovery-required states explicitly
- make CLI, TUI, and GUI presentation adapters over the same protocol
- support automation through typed JSON and JSONL without requiring UI scraping

### Requirements

1. Expand `crates/paranoid-ops` beyond generator automation into typed command envelopes,
   actor/surface/session metadata, policy evaluation, challenge decisions, and stable command
   responses.
2. Expand `crates/paranoid-audit` beyond structured event metadata into request/response audit
   events, redaction, keyed hashing, hash-chain verification, JSON/JSONL rendering, and audit-device
   sinks.
3. Ensure every security-relevant command that reaches policy evaluation emits one request event and
   one response event with the same request id.
4. Define a typed `allow`, `challenge`, and `deny` decision model. Challenge/response is a policy
   primitive, not an LLM prompt pattern.
5. Move vault lock/unlock orchestration into an explicit seal lifecycle with states for `sealed`,
   `challenge_pending`, `unsealed`, `idle_lock_pending`, `sealed_after_timeout`, and
   `recovery_required`.
6. Treat mTLS as transport/session authorization for typed ops commands when commands cross a
   process boundary, not as UI logic.
7. Keep `paranoid-core` responsible for generation/audit math and `paranoid-vault` responsible for
   encrypted storage and keyslot mechanics.

### Acceptance Criteria

- CLI, TUI, and GUI submit the same typed ops commands for covered flows
- required audit sinks fail closed
- audit events never contain plaintext passwords, recovery phrases, private keys, or unwrapped vault
  material
- JSON and JSONL fixtures are stable and documented
- seal-state transitions have unit tests and e2e coverage through at least one interactive surface
- existing TUI and GUI operator e2e tests still pass

## Workstream 2: Federal-Ready Operating Profile

### Problem

Companies operating in FedRAMP High, GovCloud, and DoD IL5 environments need clear evidence,
configuration controls, and cryptographic-provider posture. Generic security language and generic
OpenSSL linkage are not enough.

### Goals

- make federal readiness an explicit profile, not marketing copy
- produce evidence a customer can map into its own SSP and assessment package
- ensure FIPS-related claims depend on a validated module operating in approved mode
- preserve the local-first product boundary instead of turning the project into a hosted service

### Requirements

1. Keep the federal-ready profile gate enabled in CLI automation and surface it in TUI/GUI posture
   views.
2. Verify and report the cryptographic provider path, provider version, module or platform
   certificate reference, operating system, architecture, build id, and profile at startup.
3. Fail closed when federal mode requires a FIPS provider, approved mode, or required audit sink and
   those prerequisites are missing.
4. Disposition Argon2id and BIP39 for federal mode. Either disable them in that profile, add an
   approved-algorithm recovery path, or document a customer-owned compensating-control boundary.
5. Add an evidence report that includes SBOM/provenance references, release attestation references,
   audit schema version, policy profile, and provider evidence.
6. Add a control-mapping document for relevant NIST SP 800-53 Rev5 families, especially AC, AU, CM,
   IA, SC, SI, and SR.
7. Keep wording precise: federal-ready and IL5-compatible are acceptable goals; FedRAMP authorized,
   DoD IL5 authorized, and FIPS validated product are not acceptable claims without the matching
   assessed boundary.

### Acceptance Criteria

- federal-ready mode has deterministic startup checks
- federal-ready mode emits an assessor-readable evidence artifact
- docs explain what is product responsibility versus customer assessment-boundary responsibility
- non-federal recovery paths cannot silently run under a strict federal profile
- [Federal Readiness](./federal-readiness.md) matches implemented behavior

## Workstream 3: Live Release Qualification

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

## Workstream 4: Security Assurance Disposition

### Problem

The repo explicitly tracks open `TODO: HUMAN_REVIEW` sites, but the release process should not
depend on vague human-review language. Those sites now map to named assurance claims and must
stay gate-protected until they are dispositioned.

### Source of Truth

See [security-assurance.md](./security-assurance.md), [assurance-claims.md](./assurance-claims.md),
and [human-review.md](./human-review.md).

### Review Areas

1. chi-squared audit interpretation and thresholding in `paranoid-core`
2. serial-correlation estimator and normalization in `paranoid-core`
3. device-bound keyslot design and secure-storage assumptions in `paranoid-vault`
4. mnemonic recovery construction in `paranoid-vault`
5. certificate-wrapped keyslot design, including CMS recipient selection and transport-key policy in `paranoid-vault`

### Requirements

For each review area:

1. maintain a named assurance claim
2. decide whether the current implementation is acceptable, acceptable with constraints, or requires change
3. update code comments and tests to reflect the disposition
4. keep `make verify-assurance` passing
5. remove or revise the corresponding `TODO: HUMAN_REVIEW` only when the disposition supports it
6. update [assurance-claims.md](./assurance-claims.md), [human-review.md](./human-review.md), and
   `scripts/verify_human_review_inventory.sh` together

### Acceptance Criteria

- every tracked open site has a concrete assurance claim and disposition state
- no `TODO: HUMAN_REVIEW` markers remain without an entry in [human-review.md](./human-review.md)
- `make verify-assurance` runs in CI and passes on the release candidate
- any required design changes from review have been implemented and tested

## Workstream 5: Installer-Grade Platform Distribution

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

## Workstream 6: Release and Recovery Operations Closure

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
2. Add any missing recovery-lifecycle tests uncovered by assurance disposition or external review.
3. Ensure the docs clearly distinguish:
   - encrypted backup/restore
   - selected-item transfer
   - daily passwordless unlock
   - disaster recovery
4. Decide whether certificate slot lifecycle needs explicit expiration / rollover runbooks beyond the current health warnings.

### Acceptance Criteria

- an operator can follow the docs to maintain a vault through normal rotation and recovery events
- there is no recovery path whose safety depends on tribal knowledge

## Workstream 7: External Assurance

### Problem

Local tests, in-repo verification, and neutral agent review are strong, but external assurance is
still useful for strengthening public trust claims.

### Requirements

1. Preserve the claim inventory and generated assurance reports for PRs that touch sensitive surfaces.
2. Commission external review of tracked crypto/statistics claims when the project wants to upgrade
   a `tracked-open` claim to a stronger public trust claim.
3. Commission review of the release and supply-chain model after the canary release passes.
4. Preserve the written outcomes inside the repo, not only in external conversations.

### Acceptance Criteria

- external review outputs are linked or summarized in the docs
- follow-up changes from external review are landed
- the remaining trust claims in the docs match those external findings

## Deferred / Optional Work

These are not blockers for the current product line, but they should stay explicit:

- optional enterprise profile using a stricter OpenSSL-only recovery/KDF mode if a real compliance requirement appears
- additional Linux desktop package formats if distribution needs justify them
- Slint WASM and mobile targets after the desktop Slint surface reaches parity, with separate
  threat models, automation harnesses, and release gates for each target family
- broader lifecycle policy automation, such as certificate expiry reminders, only after the core release and review work is closed

## Risks

### 1. False Sense of Completion

The code now does a lot, which makes it easy to mistake implementation completeness for production completeness. The live release, assurance-disposition, and installer gaps are still real blockers.

### 2. Recovery Model Drift

If future work changes mnemonic, certificate, or device-bound behavior without revisiting the written recovery docs, the product will become harder to operate safely.

### 3. Packaging Drift

Adding platform installers without preserving the current repo-owned validation model would weaken the supply-chain story.

### 4. Compliance Language Drift

Federal-readiness work will be valuable only if the project keeps claims precise. The product can
support FedRAMP High, GovCloud, and DoD IL5 customer environments, but it must not describe itself as
authorized or FIPS validated unless an actual assessment boundary and validated cryptographic module
configuration support that claim.

## Exit Criteria

This PRD is complete when all of the following are true:

1. the current PR is merged and its release-hardening changes are on `main`
2. the ops/audit/seal comprehensive PR is merged and covered by tests
3. the federal-ready operating profile has deterministic checks, evidence output, and precise docs
4. one real canary release from `main` passes end to end
5. the assurance claims are fully represented, gate-protected, and dispositioned to the release standard being claimed
6. supported desktop platforms have standard installer-grade distribution
7. docs and runbooks match the real shipped product and recovery model

## Immediate Next Actions

1. finish and merge the current ops/audit/federal-readiness PR with local tests, GUI screenshot
   verification, and GitHub checks
2. route vault mutations, TUI actions, and GUI actions through typed ops envelopes
3. add configured audit-device health beyond local JSONL sinks
4. add stable federal-ready JSON/JSONL fixtures and a control-mapping evidence artifact
5. run the first canary release from `main` after those architecture boundaries are stable
6. choose the Windows installer technology and macOS signing/notarization path
7. update this PRD as those decisions are made
