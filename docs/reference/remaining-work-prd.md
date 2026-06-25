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
3. CI rigor regression prevention and release follow-through
4. security assurance disposition for the remaining crypto/statistics claims
5. installer-grade platform packaging and signing
6. remaining recovery / lifecycle polish that depends on those dispositions
7. post-GA assurance work that should not be improvised later
8. maintaining the Wolfi builder as the CI/CD trust root and preventing runner-local package
   installs from replacing it
9. vendoring or otherwise pinning the local scanner stack update process (`codeql`, `semgrep`,
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
- `paranoid-passwd-v3.7.0` is the proven published-release baseline: local `make ci` passed, and
  `make verify-published-release TAG=paranoid-passwd-v3.7.0` verified the live asset set,
  checksums, attestations, and host smoke path on 2026-06-24
- the repository builder is Wolfi-based again, and remote Rust CI runs the full local `make ci`
  target inside that builder

The remaining work therefore falls into protocolization, federal readiness, CI rigor preservation,
review, packaging, and closure.

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
sinks with writable health evidence, external audit-device posture, seal-state primitives, explicit
seal-provider availability probes, an mTLS process-boundary transport, and a federal-ready startup
evidence path. Headless vault CLI commands, native TUI actions, and native GUI automation now share
that protocol for covered vault operations rather than drifting back into UI-local patches. The next
architecture boundary extends the same model into broader command coverage, the remaining vault
keyslot recovery dispositions, external/remote auto-unseal expansion, and release-grade assessor
fixtures.

That PR should be scoped around:

- CLI/TUI/GUI JSONL fixtures and additional automation output over the typed ops protocol
- external/remote auto-unseal provider policy beyond the local device-bound probe and the remaining
  recovery keyslot dispositions
- additional federal-ready profile fixtures and configured-provider evidence
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
- model seal, unseal, auto-unseal, idle-lock, and recovery-required states explicitly in
  `paranoid-seal`
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
5. Move vault lock/unlock posture into an explicit `paranoid-seal` lifecycle with states for
   `sealed`, `challenge_pending`, `unsealed`, `idle_lock_pending`, `sealed_after_timeout`, and
   `recovery_required`, plus non-secret provider evidence for recovery, certificate, device-bound,
   and external auto-unseal paths.
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
- seal-state transitions and seal-provider posture have unit tests and e2e coverage through at least
  one interactive surface
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
4. Preserve the current federal recovery disposition: Argon2id password recovery, BIP39 mnemonic
   recovery, and device-bound unlock remain default-profile features, while strict federal-ready
   policy disables them and reports the decision as startup evidence.
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

## Workstream 3: CI Rigor and Wolfi Regression Prevention

### Problem

The repo now has a proven published-release baseline, but the Rust-native branch drifted from the
older C/WASM line's stricter CI posture. That older line used Wolfi-based release infrastructure and
combined native tests, WASM validation, browser E2E, static analysis, hallucination checks,
supply-chain checks, and release verification. The current product surface is different, but the
discipline must not be weaker.

### Goals

- keep Wolfi as the CI/CD builder trust root
- make remote CI mirror local release-candidate quality instead of running a smaller subset
- preserve published-release verification as a routine regression check
- rebuild the historical rigor with Rust-native equivalents instead of stale browser-era gates

### Requirements

1. Keep the repository-owned builder on a digest-pinned Wolfi base image.
2. Keep remote Rust CI running `make ci` inside that builder.
3. Keep Linux release validation, published-release surface verification, and downloaded-asset smoke
   verification inside the same builder instead of installing ad hoc packages on the Ubuntu runner.
4. Treat `paranoid-passwd-v3.7.0` as the current live-release proof point and rerun
   `make verify-published-release TAG=paranoid-passwd-v3.7.0` or a newer tag after release-pipeline
   changes.
5. Keep the historical C/WASM gates mapped to current Rust-native equivalents:
   - native compile/test/lint through Cargo, Clippy, TUI/GUI/vault e2e, and docs/link checks
   - retired WASM browser checks replaced by target-gated Slint WASM compile checks only after a
     separate threat model
   - browser E2E replaced by native TUI/GUI operator harnesses and screenshot evidence
   - supply-chain checks, action pinning, hallucination checks, and published-release verification
     retained as hard gates
6. Finish pinning or vendoring the scanner/tooling update process. The repository now has
   `supply-chain/scanner-toolchain.env` plus supply-chain verification for the Wolfi builder
   scanner apk pins, CodeQL action SHA pins, and `xtask` host-local scanner visibility. Remaining
   work is to turn the host-local `ShellCheck`, `cargo-deny`, `cargo-audit`, `cargo-vet`, and
   `codeql` installation/update path into the same kind of versioned or vendored evidence.
7. Keep remote dependency-update PRs green and reviewable for ecosystems that the configured updater
   can actually maintain. Dependabot currently owns GitHub Actions updates only; Cargo dependency
   updates remain a maintainer re-vendor flow until the repo adopts a Cargo-vendor-aware updater.
   Explicitly inspect review threads and checks before merge.

### Acceptance Criteria

- supply-chain verification fails if the builder drifts from Wolfi or release validation reintroduces
  runner-local Linux package installs
- CI and release workflows use repo-owned scripts and the builder-first path for Linux validation
- published-release verification passes against the current release tag after workflow changes
- no stale browser-era or otherwise unexpected assets are attached to release tags
- the release checklist in [release-checklist.md](./release-checklist.md) is sufficient for a second
  operator to repeat the process

## Workstream 4: Security Assurance Disposition

### Problem

The repo explicitly tracks any open `TODO: AI_REVIEW` sites, and the release process does not
depend on vague review language. Those sites map to named assurance claims and must stay
gate-protected until they are dispositioned.

### Source of Truth

See [security-assurance.md](./security-assurance.md), [assurance-claims.md](./assurance-claims.md),
and [ai-review.md](./ai-review.md).

### Closed Review Areas

- chi-squared audit interpretation and thresholding in `paranoid-core`
- serial-correlation estimator and normalization in `paranoid-core`
- external audit-device posture in `paranoid-audit` and `paranoid-ops`
- shared ops policy boundary across CLI, TUI, GUI, and mTLS automation adapters
- seal lifecycle posture and method-specific unlock policy
- device-bound keyslot design and local secure-storage assumptions in `paranoid-vault`
- mnemonic recovery construction and generated 24-word BIP39 recovery-key assumptions in
  `paranoid-vault`
- certificate-wrapped keyslot design, including CMS recipient selection and transport-key policy in
  `paranoid-vault`

### Open Review Areas

None. New AI review markers must be added to [ai-review.md](./ai-review.md),
[assurance-claims.md](./assurance-claims.md), and `scripts/verify_ai_review_inventory.sh` in the same
change that introduces them.

### Requirements

For each open review area:

1. maintain a named assurance claim
2. decide whether the current implementation is acceptable, acceptable with constraints, or requires change
3. update code comments and tests to reflect the disposition
4. keep `make verify-assurance` passing
5. remove or revise the corresponding `TODO: AI_REVIEW` only when the disposition supports it
6. update [assurance-claims.md](./assurance-claims.md), [ai-review.md](./ai-review.md), and
   `scripts/verify_ai_review_inventory.sh` together

### Acceptance Criteria

- every tracked open site has a concrete assurance claim and disposition state
- no `TODO: AI_REVIEW` markers remain without an entry in [ai-review.md](./ai-review.md)
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
2. Commission external review of sensitive crypto/statistics claims when the project wants to
   upgrade an in-repo disposition to a stronger public trust claim.
3. Commission review of the release and supply-chain model against the `v3.7.0` proof point or the
   next release that changes the pipeline.
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

The code now does a lot, which makes it easy to mistake implementation completeness for production
completeness. CI rigor preservation, assurance-disposition, and installer gaps are still real
blockers.

### 2. Recovery Model Drift

If future work changes mnemonic, certificate, or device-bound behavior without revisiting the written recovery docs and the closed mnemonic and device-bound dispositions, the product will become harder to operate safely.

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
4. Wolfi builder enforcement, full remote `make ci`, and published-release verification remain green
   after release-pipeline changes
5. the assurance claims are fully represented, gate-protected, and dispositioned to the release standard being claimed
6. supported desktop platforms have standard installer-grade distribution
7. docs and runbooks match the real shipped product and recovery model

## Immediate Next Actions

1. extend stable JSON/JSONL traces as additional command families are covered across CLI, TUI, GUI,
   and mTLS process-boundary sessions
2. expand the remaining vault keyslot dispositions and any future external/remote auto-unseal
   policy beyond the local method-specific seal posture controls now in place
3. keep the remote dependency-update queue green and reviewable, including explicit PR thread/check
   inspection before merge
4. finish versioning or vendoring the host-local scanner/tool update path now tracked by
   `supply-chain/scanner-toolchain.env`
5. choose the Windows installer technology and macOS signing/notarization path
6. update this PRD as those decisions are made
