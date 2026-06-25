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

- [FedRAMP Rev5 overview](https://www.fedramp.gov/rev5/)
- [FedRAMP Rev5 documents and templates](https://www.fedramp.gov/rev5/documents-templates/)
- [FedRAMP Rev5 agency authorization resources](https://www.fedramp.gov/rev5/agency-authorization/)
- [FedRAMP SSP template](https://www.fedramp.gov/resources/templates/FedRAMP-High-Moderate-Low-LI-SaaS-Baseline-System-Security-Plan-%28SSP%29.docx)
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

The product now has an explicit federal-ready profile entry point. It is intentionally conservative:
security-relevant operations fail closed unless the required audit sink is configured and writable
and runtime evidence confirms an approved cryptographic provider mode.

Required behavior:

- report the configured cryptographic provider path when federal mode is requested
- verify at startup whether the expected FIPS provider is confirmed in approved mode
- emit machine-readable evidence for provider name, provider version, module certificate or platform
  certificate reference, local audit-sink health, external audit-device posture, operating system,
  architecture, build id, and policy profile
- require structured audit output for security-relevant commands
- reject operations when a required audit sink is unavailable
- disable or gate recovery paths that cannot be justified under the selected federal profile
- keep network access disabled by default unless an explicit mTLS-protected ops transport is
  configured
- preserve offline/vendored dependency builds, pinned workflows, checksums, attestations, SBOM, and
  payload inspection

Current OpenSSL usage is not enough by itself. The checked-in default runtime reports OpenSSL
evidence, but it does not claim approved mode. Federal-ready operations therefore deny by default
unless the deployment provides approved-mode evidence, for example:

```bash
PARANOID_FEDERAL_APPROVED_MODE=confirmed \
PARANOID_FEDERAL_CERTIFICATE_REFERENCE="CMVP certificate <customer-owned-reference>" \
paranoid-passwd --cli --profile federal-ready --audit-jsonl audit.jsonl --length 32
```

Those environment variables are evidence inputs, not a product certification. A customer still has
to prove that its exact build, OpenSSL provider, operating environment, and assessment boundary
support the claim.

External audit-device evidence is similarly conservative. The startup report reads
`PARANOID_AUDIT_DEVICE_ENDPOINT`, `PARANOID_AUDIT_DEVICE_ID`,
`PARANOID_AUDIT_DEVICE_MTLS_CERT`, `PARANOID_AUDIT_DEVICE_MTLS_KEY`, and
`PARANOID_AUDIT_DEVICE_CA_CERT`, but configured mTLS material is not considered a healthy audit sink
until a probe returns a ready health object. `PARANOID_AUDIT_DEVICE_PROBE=tcp-connect` runs a live
transport reachability probe against `mtls://`, `tls://`, or `tcp://` endpoints. The important
boundary is that tcp-connect proves reachability, not durable audit ingestion, so the result remains
`unverified` and does not satisfy a required audit sink. `PARANOID_AUDIT_DEVICE_PROBE=mtls-jsonl-ack`
requires the configured certificate, private key, and CA certificate paths, opens an OpenSSL mTLS
connection, sends a newline-delimited JSON challenge, and reports `ready` only when the endpoint
returns the same schema version, probe name, challenge id, and `status=ready`. Without that
acknowledgement, federal-ready policy still requires a ready local JSONL sink.

Automation surfaces:

```bash
paranoid-passwd --federal-evidence
paranoid-passwd --cli --federal-ready --audit-jsonl audit.jsonl --length 32
paranoid-passwd vault --audit-jsonl vault-audit.jsonl keyslots
paranoid-passwd vault federal-evidence
paranoid-passwd vault seal-status
paranoid-passwd vault seal-status --probe-providers
```

## Crypto Disposition

The current vault uses Argon2id for recovery-secret derivation and BIP39 for mnemonic recovery.
Those paths remain useful default-profile product features, but strict federal-ready mode now treats
them as non-federal unlock methods instead of silently accepting a weak claim.

The current disposition is:

- password recovery through Argon2id is default-profile only under the strict federal-ready policy
- mnemonic recovery through BIP39 is default-profile only under the strict federal-ready policy
- device-bound unlock is default-profile only: the secure-storage provider boundary is
  dispositioned for local daily unlock, but not for portable recovery, remote auto-unseal, or the
  strict federal-ready unlock path
- certificate-wrapped unlock is the current strict federal-ready unlock path, gated by required
  audit evidence, approved-mode provider evidence, seal posture evidence, certificate-unseal
  provider evidence, and fresh operator proof

`--federal-evidence` emits this as machine-readable `recovery_disposition` evidence. Customers who
require password, mnemonic, or device-bound recovery inside a broader assessed boundary must own that
compensating-control decision outside the strict federal-ready profile. The vault CLI and TUI route
federal-ready vault unlocks through the same typed `VaultUnlock` policy check before plaintext vault
state is loaded.

No code or docs should imply that generic OpenSSL linkage, Argon2id, BIP39, or CMS usage is
automatically enough for a federal authorization.

## Ops and Audit Controls

`paranoid-ops`, `paranoid-seal`, and `paranoid-audit` are the right place to satisfy federal
readiness without bloating UI code. The current implementation covers generator automation reports,
typed command envelopes, allow/challenge/deny decisions, seal-state and provider-posture
primitives, required local JSONL sinks, federal startup evidence, redacted structured audit events,
and hash-chain evidence.

`paranoid-ops` now provides:

- typed command envelopes with request id, actor, surface, session, profile, and operation
- policy decisions of `allow`, `challenge`, or `deny`
- challenge/response handling for sensitive operations and fresh proof requirements
- vault operation access classes for metadata, decrypt, mutate, export, import, and keyslot
  lifecycle flows
- reusable vault operation policy evaluation for CLI, TUI, and native GUI adapters
- fail-closed profile validation so process-boundary or automation envelopes cannot downgrade the
  authoritative policy context
- an OpenSSL-backed TLS-1.3-minimum mTLS JSONL process-boundary command transport that fails closed
  unless a security-relevant command has authenticated peer identity and certificate fingerprint
  evidence; server-side handling replaces client-asserted transport claims with observed
  peer-certificate evidence before policy evaluation
- stable JSON responses for automation and evidence capture, including federal startup evidence
  schema `3` for external audit-device posture and strict recovery-disposition evidence

`paranoid-seal` now provides:

- typed seal-state transitions for sealed, challenge-pending, unsealed, idle-lock, timeout, and
  recovery-required states
- non-secret provider evidence for password recovery, mnemonic recovery, device-bound,
  certificate-wrapped, and future external auto-unseal paths
- posture reporting that distinguishes configured auto-unseal from confirmed provider availability
  so evidence does not overstate what the local process has actually checked
- an explicit provider-probe path for seal status; metadata-only reports keep device-bound slots at
  `configured`, while `seal-status --probe-providers` marks a device-bound provider `available` only
  after secure storage returns the unwrap material and the vault keyslot check blob verifies
- method-specific ops policy consumption, so generic auto-unseal availability cannot satisfy a
  device-bound unlock and recovery unlocks must match their own configured provider kind

`paranoid-audit` now provides:

- request and response events for every command that reaches policy evaluation
- stable JSONL schemas suitable for SIEM ingestion
- configured JSONL sink health evidence before policy treats a sink as available
- external audit-device posture over configured mTLS endpoints, live TCP reachability probes that
  remain unverified, and an mTLS JSONL write-ack probe that reports ready only after a matching
  challenge acknowledgement
- strict redaction markers for sensitive fields
- hash-chained local event streams
- fail-closed behavior for required local JSONL sinks
- fixtures that can be attached to an SSP, control implementation summary, or assessor evidence
  package

The current redaction behavior intentionally replaces sensitive values with a redaction marker
rather than hashing secrets. Keyed correlation hashes remain future work because they must use an
approved primitive and must not create offline-guessing evidence for low-entropy secrets.

This is the replacement for primitive logging. Operational logs may still exist for troubleshooting,
but audit events are typed, durable, redacted, and testable.

## Evidence Package

The federal-ready path should produce evidence that a customer can map into an SSP and assessment
package:

- software bill of materials
- release checksums and signatures or attestations
- build provenance and builder-image digest
- dependency-vendor manifest
- FIPS provider evidence and startup self-test report
- audit-schema reference and sample JSONL traces
- external audit-device endpoint, mTLS evidence posture, and health status when configured
- recovery-disposition evidence for password, mnemonic, device-bound, and certificate-wrapped
  unlock methods
- control mapping for relevant NIST SP 800-53 Rev5 families, especially AC, AU, CM, IA, SC, SI, and
  SR; see [Federal Control Mapping](./control-mapping.md)
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
