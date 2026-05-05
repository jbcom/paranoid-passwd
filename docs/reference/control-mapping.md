---
title: Federal Control Mapping
---

# Federal Control Mapping

This document is an implementation evidence map for customers evaluating `paranoid-passwd` in
FedRAMP High, GovCloud, or DoD IL5-oriented environments. It is not an authorization package, a
FedRAMP authorization claim, or a FIPS validation claim.

The product boundary is local-first: vault data, keyslot material, audit JSONL, and release evidence
remain under the operator's endpoint and assessment boundary. The project provides deterministic
controls, evidence artifacts, and precise failure modes that customers can map into their own
system security plan.

## Evidence Artifacts

| Artifact | Producer | Purpose |
|---|---|---|
| `--federal-evidence` JSON | CLI / vault CLI | Startup evidence for profile, build id, OS, architecture, audit sink posture, external audit-device posture, cryptographic provider evidence, and policy decision. |
| `--audit-jsonl` JSONL | CLI / TUI / GUI adapters | Redacted request/response policy events for security-relevant operations. |
| Ops trace fixtures | `crates/paranoid-ops/tests/fixtures/` | Stable CLI/TUI/GUI command-envelope examples for automation compatibility and assessor traceability. |
| Release checksums and attestations | Release workflow | Artifact integrity and provenance evidence for shipped archives and packages. |
| SBOM / package manifests | Release workflow | Supply-chain inventory evidence for release artifacts. |
| `make verify-assurance` report | Security assurance gate | Deterministic claim inventory with changed surfaces and required local verification commands. |
| GUI e2e screenshot | `make test-gui-e2e-emulate` | Visual evidence that the native GUI flow is actionable under Xvfb-backed automation. |

## NIST SP 800-53 Rev5 Families

| Family | Product control contribution | Customer boundary responsibility | Repo evidence |
|---|---|---|---|
| AC - Access Control | Typed ops envelopes identify actor, surface, transport, profile, command, and policy decision before security-relevant vault actions proceed. | Bind local operators, device accounts, and endpoint authorization policy to the customer's identity and endpoint controls. | `paranoid-ops`; vault CLI/TUI/GUI audit traces; `docs/reference/architecture.md` |
| AU - Audit and Accountability | Redacted JSONL audit events pair each request and response by request id, preserve operation/access metadata, and fail closed when a required local audit sink is unavailable. | Collect, retain, protect, and monitor JSONL/SIEM records according to the customer's AU control implementation. | `paranoid-audit`; `--audit-jsonl`; ops trace fixtures; `tests/test_cli.sh`; `tests/test_vault_cli.sh` |
| CM - Configuration Management | Federal-ready profile and release verification scripts make profile, build id, vendored dependencies, and release payload verification explicit. | Manage approved deployment baselines, endpoint configuration drift, and release promotion. | `make ci`; `make verify-assurance`; `scripts/release_validate.sh`; `scripts/verify_published_release.sh` |
| IA - Identification and Authentication | Vault unlock paths are explicit policy inputs: recovery secret, mnemonic recovery, device-bound, and certificate-wrapped keyslots. Federal-ready policy rejects non-federal unlock methods until they are dispositioned. | Decide which unlock methods are allowed in the assessed boundary and bind certificates/devices to organizational identity policy. | `paranoid-vault`; `paranoid-seal`; `docs/reference/federal-readiness.md` |
| SC - System and Communications Protection | Cryptographic operations stay in Rust crates using OpenSSL-backed primitives where applicable; external audit-device evidence requires configured mTLS material and treats readiness as a matching JSONL challenge acknowledgement, not TCP reachability. | Operate validated cryptographic modules in approved mode when required, protect transport endpoints, and manage certificate lifecycles. | `paranoid-core`; `paranoid-audit`; federal startup evidence |
| SI - System and Information Integrity | Local and CI gates run locked/offline builds, linting, tests, supply-chain checks, assurance inventory checks, and GUI automation evidence. | Integrate repo evidence with endpoint monitoring, vulnerability management, and incident response processes. | `.github/workflows/`; `Makefile`; `scripts/security_assurance_gate.py` |
| SR - Supply Chain Risk Management | Dependencies are vendored, GitHub Actions are SHA-pinned, release artifacts are checksummed/attested, and published releases can be verified after download. | Decide supplier acceptance, mirror artifacts if needed, and retain provenance evidence in the customer's release process. | `.cargo/config.toml`; `vendor/`; `scripts/supply_chain_verify.sh`; release verification docs |

## Non-Claims

- The project is not FedRAMP authorized.
- The project is not DoD IL5 authorized.
- The project is not a FIPS validated product.
- Generic OpenSSL linkage is not by itself evidence of approved-mode operation.
- TCP reachability to an external audit endpoint is not evidence of durable audit ingestion.
- A matching mTLS JSONL write acknowledgement is readiness evidence for the configured endpoint; it
  is not a claim about the customer's downstream retention, monitoring, or SIEM control operation.

## Minimum Federal-Ready Evidence Packet

A customer-oriented evidence packet should include:

1. the exact release tag, checksums, attestation links, and SBOM/provenance references
2. the `--federal-evidence` JSON captured on the target platform
3. a sample `--audit-jsonl` trace for the operational flow being assessed
4. the relevant ops trace fixture name and schema version
5. the configured cryptographic provider evidence and approved-mode status
6. the external audit-device posture, including whether readiness came from a matching mTLS JSONL
   write acknowledgement
7. the customer's decision for non-federal recovery paths such as Argon2id and BIP39
