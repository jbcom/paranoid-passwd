---
title: Federal Readiness
---

# Federal Readiness

`paranoid-passwd` should be usable by organizations operating inside FedRAMP High, GovCloud, and
DoD Impact Level 5 environments. That is a product and evidence goal, not a certification claim.

FedRAMP authorization applies to a cloud service offering and its assessment boundary. DoD IL5
authorization depends on the DoD Cloud Computing Security Requirements Guide and the mission
owner's authorization process. This project can make itself easier to adopt in those environments by
keeping the product local-first, preserving a small trust boundary, producing assessor-friendly
evidence, and offering a federal-ready operating profile.

Primary references:

- [FedRAMP Rev5 documentation and playbooks](https://www.fedramp.gov/docs/rev5/)
- [FedRAMP Rev5 agency authorization overview](https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/getting-started/)
- [FedRAMP SSP guidance](https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/ssp/)
- [GSA Cloud Security overview for DoD CC SRG and FedRAMP+](https://cic.gsa.gov/basics/cloud-security/)
- [NIST CMVP certificate 4985 for the OpenSSL FIPS Provider](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)

## Claim Boundary

Use careful language:

- `Federal-ready operating profile` means the product has controls, evidence, and configuration
  paths intended to support federal assessment work.
- `FedRAMP compatible` means the product can be deployed inside an assessed system boundary without
  undermining the customer's control implementation.
- `DoD IL5 compatible` means the product can produce the evidence and operating behavior expected by
  organizations targeting that environment.
- `FedRAMP authorized`, `DoD IL5 authorized`, or `FIPS validated product` must not be used unless the
  exact product, build, environment, and assessment boundary support that statement.

## Federal-Ready Profile

The next comprehensive PR should introduce a federal-ready profile. It should be explicit, testable,
and fail closed when required controls are missing.

Required behavior:

- load only an approved cryptographic provider path when federal mode is requested
- verify at startup that the expected FIPS provider is available, active, and in approved mode
- emit machine-readable evidence for provider name, provider version, module certificate or platform
  certificate reference, operating system, architecture, build id, and policy profile
- require structured audit output for security-relevant commands
- reject operations when a required audit sink is unavailable
- disable or gate recovery paths that cannot be justified under the selected federal profile
- keep network access disabled by default unless an explicit mTLS-protected ops transport is
  configured
- preserve offline/vendored dependency builds, pinned workflows, checksums, attestations, SBOM, and
  payload inspection

Current OpenSSL usage is not enough by itself. The federal-ready profile must prove that the runtime
uses a validated module in its approved mode, such as an appropriate OpenSSL FIPS Provider or an
approved platform provider, and must document the tested operating environment and configuration
constraints.

## Crypto Disposition

The current vault uses Argon2id for recovery-secret derivation and BIP39 for mnemonic recovery. Those
paths are useful product features, but they must be dispositioned before a strict federal profile can
claim FIPS-aligned behavior.

The next PR should decide one of these paths:

- keep Argon2id and BIP39 in the default profile, but disable them or mark them non-federal in the
  federal-ready profile
- add a federal recovery path backed only by approved algorithms from a validated provider, then make
  that path mandatory in federal mode
- document the exact compensating-control story if a customer requires those features inside a
  broader assessed boundary

No code or docs should imply that generic OpenSSL linkage, Argon2id, BIP39, or CMS usage is
automatically enough for a federal authorization.

## Ops and Audit Controls

`paranoid-ops` and `paranoid-audit` are the right place to satisfy federal readiness without
bloating UI code. The current foundation covers generator automation reports and redacted structured
audit events; vault seal policy, required sinks, and federal profile evidence remain explicit
follow-on work.

`paranoid-ops` should continue toward:

- typed command envelopes with request id, actor, surface, session, profile, target, and operation
- policy decisions of `allow`, `challenge`, or `deny`
- challenge/response handling for sensitive operations and fresh proof requirements
- seal and auto-unseal state transitions
- mTLS policy when operations cross process boundaries
- stable JSON responses for automation and evidence capture

`paranoid-audit` should continue toward:

- request and response events for every command that reaches policy evaluation
- stable JSONL schemas suitable for SIEM ingestion
- redaction and keyed hashing for sensitive fields
- hash-chained local event streams
- explicit audit-device health and fail-closed behavior for required sinks
- fixtures that can be attached to an SSP, control implementation summary, or assessor evidence
  package

This is the replacement for primitive logging. Operational logs may still exist for troubleshooting,
but audit events must be typed, durable, redacted, and testable.

## Evidence Package

The federal-ready path should produce evidence that a customer can map into an SSP and assessment
package:

- software bill of materials
- release checksums and signatures or attestations
- build provenance and builder-image digest
- dependency-vendor manifest
- FIPS provider evidence and startup self-test report
- audit-schema reference and sample JSONL traces
- control mapping for relevant NIST SP 800-53 Rev5 families, especially AC, AU, CM, IA, SC, SI, and
  SR
- configuration baseline guidance, using DoD STIGs where applicable and CIS Level 2 only where a STIG
  is not available
- shared-responsibility notes for customers who run the product inside a larger FedRAMP or IL5
  boundary

## Non-Goals

This project should not become a hosted password service to chase FedRAMP language. The stronger
position is to remain local-first and produce clear evidence that helps customers deploy the product
inside their own controlled environment.

Not included:

- cloud sync
- browser extension or autofill
- hosted control plane
- claims of FedRAMP authorization without an assessed cloud service offering
- claims of DoD IL5 authorization without the relevant DoD authorization path
