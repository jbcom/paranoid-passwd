#!/usr/bin/env python3
"""Deterministic security assurance protocol gate for paranoid-passwd."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Requirement:
    path: str
    pattern: str
    description: str
    regex: bool = False


@dataclass(frozen=True)
class Claim:
    claim_id: str
    title: str
    surface: str
    requirements: tuple[Requirement, ...]


CLAIMS: tuple[Claim, ...] = (
    Claim(
        "rng.openssl-delegation",
        "OpenSSL-backed RNG and SHA-256 delegation",
        "core-security",
        (
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                r"^use openssl::\{(?=[^}]*" + "rand" + r"::rand_bytes)(?=[^}]*sha::sha256)[^}]*\};",
                "paranoid-core imports OpenSSL RNG and SHA-256",
                True,
            ),
            Requirement(
                "scripts/hallucination_check.sh",
                "core still delegates RNG and SHA-256 to OpenSSL",
                "hallucination check enforces OpenSSL delegation",
            ),
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                "pub fn random_hex_token(byte_len: usize)",
                "core exposes OpenSSL-backed random challenge token generation",
            ),
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                "rand_bytes(bytes.as_mut_slice())",
                "random challenge tokens delegate entropy to OpenSSL",
            ),
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                "random_hex_token_uses_openssl_rng_shape",
                "core tests cover random token shape and bounds",
            ),
        ),
    ),
    Claim(
        "rng.rejection-sampling-boundary",
        "Rejection sampling boundary",
        "core-security",
        (
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                "let max_valid = (256 / charset_bytes.len()) * charset_bytes.len() - 1;",
                "generation path keeps the inclusive -1 boundary",
            ),
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                "let rejection_max_valid = (256 / charset_len) * charset_len - 1;",
                "audit summary reports the same inclusive -1 boundary",
            ),
        ),
    ),
    Claim(
        "audit.chi-squared-tail",
        "Chi-squared tail interpretation",
        "core-security",
        (
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                r"^use statrs::distribution::\{ChiSquared, ContinuousCDF\};",
                "chi-squared probability comes from statrs",
                True,
            ),
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                "let chi2_pass = chi2_p_value > 0.01;",
                "pass logic rejects only low p-values",
            ),
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                "let df = charset_bytes.len().saturating_sub(1);",
                "degrees of freedom remain N - 1",
            ),
        ),
    ),
    Claim(
        "audit.serial-correlation-estimator",
        "Serial-correlation estimator tracking",
        "core-security",
        (
            Requirement(
                "docs/reference/ai-review.md",
                "Serial correlation audit",
                "open serial-correlation AI disposition remains tracked",
            ),
            Requirement(
                "scripts/verify_ai_review_inventory.sh",
                "verify the serial-correlation coefficient matches the intended estimator",
                "inventory check tracks the serial-correlation TODO",
            ),
        ),
    ),
    Claim(
        "surface.no-browser-runtime",
        "No retired browser/runtime product surface",
        "product-surface",
        (
            Requirement(
                "scripts/hallucination_check.sh",
                "retired browser/C surfaces are gone",
                "hallucination check verifies retired runtime paths are absent",
            ),
            Requirement(
                ".github/copilot-instructions.md",
                "Do not reintroduce the retired browser app, JavaScript secret-handling logic, DOM UI, or webview runtime paths.",
                "Copilot repository instructions preserve the retired browser/runtime rule",
            ),
            Requirement(
                ".github/copilot-instructions.md",
                "Treat any Slint WASM or mobile work as a separately gated Rust-native surface with an explicit threat model.",
                "Copilot repository instructions gate future Slint WASM/mobile surfaces",
            ),
        ),
    ),
    Claim(
        "vault.device-bound-keyslot",
        "Device-bound keyslot tracking",
        "vault-security",
        (
            Requirement(
                "docs/reference/ai-review.md",
                "Device-bound keyslot design",
                "open device-bound keyslot AI disposition remains tracked",
            ),
            Requirement(
                "scripts/verify_ai_review_inventory.sh",
                "device-bound keyslot design",
                "inventory check tracks the device-bound keyslot TODO",
            ),
        ),
    ),
    Claim(
        "vault.mnemonic-recovery-keyslot",
        "Mnemonic recovery keyslot tracking",
        "vault-security",
        (
            Requirement(
                "docs/reference/ai-review.md",
                "Mnemonic recovery construction",
                "open mnemonic recovery AI disposition remains tracked",
            ),
            Requirement(
                "scripts/verify_ai_review_inventory.sh",
                "24-word BIP39 entropy",
                "inventory check tracks the mnemonic recovery TODO",
            ),
        ),
    ),
    Claim(
        "vault.certificate-wrapped-keyslot",
        "Certificate-wrapped keyslot tracking",
        "vault-security",
        (
            Requirement(
                "docs/reference/ai-review.md",
                "Certificate-wrapped keyslots",
                "open certificate-wrapped keyslot AI disposition remains tracked",
            ),
            Requirement(
                "scripts/verify_ai_review_inventory.sh",
                "CMS recipient selection",
                "inventory check tracks the certificate-wrapped keyslot TODO",
            ),
        ),
    ),
    Claim(
        "ops.shared-policy-boundary",
        "Shared ops policy boundary tracking",
        "ops-security",
        (
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "TODO: AI_REVIEW - centralized policy boundary for ops/vault authorization and audit evidence across adapters.",
                "shared ops policy boundary remains tracked for AI review",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "let envelope = OpsCommandEnvelope::local(surface, context.profile, command);",
                "ops command envelopes derive profile from the authoritative policy context",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                '"session_surface".to_string()',
                "ops request/response events preserve adapter session surface metadata",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_tui.rs",
                "evaluate_vault_operation(AuditSurface::Tui",
                "TUI vault adapter routes covered operations through the shared ops evaluator",
            ),
            Requirement(
                "crates/paranoid-gui/src/lib.rs",
                "write_events_jsonl(path, evaluation.audit_events.as_slice())",
                "native GUI persists durable ops audit events when JSONL is configured",
            ),
            Requirement(
                "docs/reference/ai-review.md",
                "Ops policy boundary",
                "open ops policy boundary AI disposition remains tracked",
            ),
            Requirement(
                "scripts/verify_ai_review_inventory.sh",
                "centralized policy boundary for ops/vault authorization and audit evidence across adapters",
                "inventory check tracks the ops policy boundary TODO",
            ),
        ),
    ),
    Claim(
        "ops.vault-trace-fixtures",
        "Stable vault operation trace fixtures",
        "ops-security",
        (
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "pub struct OpsCommandTrace",
                "ops crate exposes a stable trace wrapper for command evidence",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "pub fn evaluate_ops_command_envelope",
                "ops crate can evaluate caller-provided envelopes for deterministic fixtures",
            ),
            Requirement(
                "crates/paranoid-ops/tests/ops_trace_fixtures.rs",
                "cli_mutate_vault_operation_trace_fixture_is_stable",
                "ops tests pin a CLI vault mutation trace fixture",
            ),
            Requirement(
                "crates/paranoid-ops/tests/ops_trace_fixtures.rs",
                "tui_keyslot_required_audit_denial_jsonl_fixture_is_stable",
                "ops tests pin a TUI fail-closed JSONL fixture",
            ),
            Requirement(
                "crates/paranoid-ops/tests/ops_trace_fixtures.rs",
                "gui_export_federal_ready_trace_fixture_is_stable",
                "ops tests pin a GUI federal-ready export fixture",
            ),
            Requirement(
                "crates/paranoid-ops/tests/fixtures/ops_trace_cli_mutate_allowed.json",
                '"session_surface": "cli"',
                "stable CLI fixture preserves the adapter surface",
            ),
            Requirement(
                "crates/paranoid-ops/tests/fixtures/ops_trace_tui_keyslot_required_audit_denied.audit.jsonl",
                '"decision":"deny"',
                "stable TUI JSONL fixture preserves fail-closed policy evidence",
            ),
            Requirement(
                "crates/paranoid-ops/tests/fixtures/ops_trace_gui_export_federal_ready_allowed.json",
                '"profile": "federal_ready"',
                "stable GUI fixture covers a federal-ready automation trace",
            ),
            Requirement(
                "docs/reference/testing.md",
                "stable CLI/TUI/GUI vault operation trace fixtures",
                "testing docs describe stable ops trace fixtures",
            ),
            Requirement(
                "docs/reference/assurance-claims.md",
                "`ops.vault-trace-fixtures` | `enforced`",
                "assurance claims track stable ops trace fixtures",
            ),
        ),
    ),
    Claim(
        "ops.mtls-process-boundary-fixture",
        "mTLS process-boundary command evidence",
        "ops-security",
        (
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "pub struct OpsTransportEvidence",
                "ops crate models non-secret process-boundary transport evidence",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "mtls_transport_evidence",
                "ops policy fails closed when mTLS commands lack authenticated transport evidence",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "transport_certificate_fingerprint_sha256",
                "ops audit events can record non-secret mTLS certificate fingerprint evidence",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "transport_channel_binding_sha256",
                "ops audit events can record non-secret mTLS channel-binding evidence",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "transport_warnings",
                "ops audit events can record non-secret transport warning evidence",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "mtls_process_boundary_requires_authenticated_transport_evidence",
                "ops unit tests cover missing mTLS transport evidence denial",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "authenticated_mtls_process_boundary_records_non_secret_evidence",
                "ops unit tests cover non-secret authenticated mTLS audit evidence",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "unauthenticated_mtls_process_boundary_records_transport_warnings",
                "ops unit tests cover non-secret mTLS warning audit evidence",
            ),
            Requirement(
                "crates/paranoid-ops/tests/ops_trace_fixtures.rs",
                "mtls_process_boundary_export_trace_fixture_is_stable",
                "ops trace tests pin an mTLS process-boundary fixture",
            ),
            Requirement(
                "crates/paranoid-ops/tests/fixtures/ops_trace_mtls_process_boundary_allowed.json",
                '"transport": "mtls"',
                "stable fixture preserves the mTLS process-boundary transport",
            ),
            Requirement(
                "crates/paranoid-ops/tests/fixtures/ops_trace_mtls_process_boundary_allowed.json",
                '"kind": "service_account"',
                "stable fixture preserves neutral service-account actor context",
            ),
            Requirement(
                "docs/reference/testing.md",
                "stable mTLS process-boundary vault operation fixture",
                "testing docs describe the mTLS process-boundary fixture",
            ),
            Requirement(
                "docs/reference/assurance-claims.md",
                "`ops.mtls-process-boundary-fixture` | `enforced`",
                "assurance claims track the mTLS process-boundary fixture",
            ),
        ),
    ),
    Claim(
        "audit.external-device-health",
        "External audit-device health evidence",
        "ops-security",
        (
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "ExternalDevice",
                "audit health model includes external audit-device posture",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "Unverified",
                "audit health model distinguishes configured-only devices from ready sinks",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "assess_external_audit_device_from_environment",
                "external audit-device evidence is collected through the audit crate",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "pub trait ExternalAuditDeviceProbe",
                "external audit-device live probes use an explicit probe boundary",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "TcpConnectExternalAuditDeviceProbe",
                "external audit-device transport reachability has a live probe implementation",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "MtlsJsonlAckExternalAuditDeviceProbe",
                "external audit-device has a live mTLS JSONL write-ack probe implementation",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                'EXTERNAL_AUDIT_DEVICE_MTLS_JSONL_ACK_PROBE: &str = "mtls-jsonl-ack"',
                "external audit-device mTLS JSONL ack probe mode is stable",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "probe_mtls_jsonl_write_ack",
                "external audit-device readiness uses a dedicated write-ack probe path",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "paranoid_core::random_hex_token(16)",
                "external audit-device write-ack challenges use core RNG delegation",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "validate_write_ack_response",
                "external audit-device write-ack responses are validated before ready status",
            ),
            Requirement(
                "crates/paranoid-audit/Cargo.toml",
                "openssl.workspace = true",
                "external audit-device mTLS probe uses the workspace OpenSSL dependency",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "PARANOID_AUDIT_DEVICE_PROBE",
                "external audit-device probe mode is explicit configuration",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "TODO: AI_REVIEW - confirm external audit-device posture and health semantics do not overstate sink availability or federal audit coverage.",
                "external audit-device posture remains tracked for AI review",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "missing mTLS evidence",
                "external audit-device configuration requires mTLS evidence before probe status",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "value.trim().is_empty()",
                "external audit-device mTLS evidence rejects empty environment values",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "external_audit_device_environment_lookup_never_claims_ready",
                "audit tests cover external audit-device environment lookup states",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "external_audit_device_tcp_probe_reaches_open_listener_without_claiming_ready",
                "audit tests cover live tcp probe reachability without claiming sink readiness",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "external_audit_device_probe_can_mark_ready_only_with_explicit_ack",
                "audit tests require explicit probe acknowledgment before external sink readiness",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "external_audit_device_mtls_jsonl_ack_probe_marks_ready_after_matching_ack",
                "audit tests cover mTLS JSONL write-ack readiness",
            ),
            Requirement(
                "crates/paranoid-audit/src/lib.rs",
                "external_audit_device_mtls_jsonl_ack_probe_rejects_mismatched_ack",
                "audit tests reject mismatched mTLS JSONL write-ack challenges",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "FEDERAL_STARTUP_EVIDENCE_SCHEMA_VERSION: u16 = 3",
                "federal startup evidence schema version is stable for external audit-device posture",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "pub external_audit_device: AuditSinkHealth",
                "federal startup evidence includes external audit-device posture",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "input.audit_sink.is_available()",
                "policy availability checks local audit sink readiness",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "input.external_audit_device.is_available()",
                "policy availability checks external audit device readiness",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "unverified_external_audit_device_does_not_satisfy_required_audit_control",
                "ops tests prove unverified external devices do not satisfy required audit control",
            ),
            Requirement(
                "crates/paranoid-ops/tests/federal_startup_fixtures.rs",
                "federal_startup_evidence_denied_fixture_is_stable",
                "stable federal startup evidence fixture is asserted by tests",
            ),
            Requirement(
                "crates/paranoid-ops/tests/federal_startup_fixtures.rs",
                "federal_startup_evidence_external_device_ready_fixture_is_stable",
                "stable federal startup evidence fixture covers ready external audit-device acknowledgment",
            ),
            Requirement(
                "crates/paranoid-ops/tests/fixtures/federal_startup_denied.json",
                '"external_audit_device"',
                "stable federal startup evidence fixture includes external audit posture",
            ),
            Requirement(
                "crates/paranoid-ops/tests/fixtures/federal_startup_external_device_ready.json",
                '"evidence_source": "fixture-write-ack"',
                "stable federal startup evidence fixture requires explicit external write acknowledgment",
            ),
            Requirement(
                "crates/paranoid-ops/tests/fixtures/federal_startup_denied.json",
                '"schema_version": 3',
                "stable federal startup evidence fixture uses the bumped wire schema",
            ),
            Requirement(
                "tests/test_cli.sh",
                'data["external_audit_device"]["status"] == "not_configured"',
                "CLI federal evidence contract covers external audit posture",
            ),
            Requirement(
                "docs/reference/federal-readiness.md",
                "tcp-connect proves reachability, not durable audit ingestion",
                "federal readiness docs explain external audit-device posture limits",
            ),
            Requirement(
                "docs/reference/federal-readiness.md",
                "PARANOID_AUDIT_DEVICE_PROBE=mtls-jsonl-ack",
                "federal readiness docs describe mTLS JSONL write-ack readiness",
            ),
            Requirement(
                "docs/reference/testing.md",
                "stable denied federal startup fixture",
                "testing docs cover stable federal startup fixture",
            ),
            Requirement(
                "docs/reference/testing.md",
                "audit unit tests cover the mTLS JSONL write-ack probe",
                "testing docs cover the mTLS JSONL write-ack tests",
            ),
            Requirement(
                "docs/reference/ai-review.md",
                "External audit-device posture",
                "AI review surface tracks the external audit-device posture disposition",
            ),
            Requirement(
                "docs/reference/assurance-claims.md",
                "`audit.external-device-health` | `tracked-open`",
                "assurance claim tracks the external audit-device posture disposition",
            ),
        ),
    ),
    Claim(
        "federal.recovery-disposition-evidence",
        "Federal recovery disposition evidence",
        "ops-security",
        (
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "pub struct FederalRecoveryDisposition",
                "ops owns a serializable federal recovery disposition model",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "pub recovery_disposition: FederalRecoveryDisposition",
                "federal startup evidence includes strict recovery disposition",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "strict_federal_ready_disables_non_certificate_unlock_methods",
                "ops evidence names the strict federal-ready recovery policy",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "non_federal_unlock_method:password_recovery",
                "ops policy evidence marks Argon2id password recovery as non-federal",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "non_federal_unlock_method:mnemonic_recovery",
                "ops policy evidence marks BIP39 mnemonic recovery as non-federal",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "non_federal_unlock_method:device_bound",
                "ops policy evidence marks device-bound unlock as non-federal",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "Current strict federal-ready unlock path",
                "ops evidence identifies certificate-wrapped unlock as the current controlled federal path",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                "OpsCommand::VaultUnlock { method }",
                "vault CLI evaluates the selected unlock method under federal-ready policy",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_tui.rs",
                "record_vault_unlock_policy",
                "vault TUI evaluates the selected unlock method under federal-ready policy",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "federal_recovery_disposition_marks_argon2id_and_bip39_default_profile_only",
                "ops tests pin the federal recovery disposition model",
            ),
            Requirement(
                "tests/test_vault_cli.sh",
                "federal recovery disposition gates vault unlock methods",
                "vault CLI e2e proves federal-ready unlock methods are gated",
            ),
            Requirement(
                "crates/paranoid-ops/tests/fixtures/federal_startup_denied.json",
                '"recovery_disposition"',
                "stable federal startup evidence fixture includes recovery disposition",
            ),
            Requirement(
                "crates/paranoid-ops/tests/fixtures/federal_startup_denied.json",
                "non_federal_unlock_method:mnemonic_recovery",
                "stable federal startup evidence fixture marks BIP39 recovery as non-federal",
            ),
            Requirement(
                "tests/test_cli.sh",
                'data["recovery_disposition"]["methods"]',
                "CLI federal evidence contract covers recovery disposition",
            ),
            Requirement(
                "docs/reference/federal-readiness.md",
                "`--federal-evidence` emits this as machine-readable `recovery_disposition` evidence",
                "federal readiness docs describe recovery-disposition evidence",
            ),
            Requirement(
                "docs/reference/control-mapping.md",
                "strict recovery disposition",
                "federal control mapping includes recovery-disposition evidence",
            ),
            Requirement(
                "docs/reference/assurance-claims.md",
                "`federal.recovery-disposition-evidence` | `process`",
                "assurance claims track federal recovery disposition evidence",
            ),
        ),
    ),
    Claim(
        "seal.lifecycle-boundary",
        "Seal lifecycle boundary",
        "seal-security",
        (
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                r"#\[derive\([^\n]*Serialize[^\n]*Deserialize[^\n]*\)\]\n#\[serde\([^\n]*\)\]\npub enum VaultSealState",
                "paranoid-seal owns a serializable seal state enum",
                True,
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                r"#\[derive\([^\n]*Serialize[^\n]*Deserialize[^\n]*\)\]\npub struct VaultSealPosture",
                "paranoid-seal owns a serializable non-secret seal posture model",
                True,
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                r"#\[derive\([^\n]*Serialize[^\n]*Deserialize[^\n]*\)\]\n#\[serde\([^\n]*\)\]\npub enum VaultSealProviderKind",
                "paranoid-seal models serializable seal provider kinds",
                True,
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "TODO: AI_REVIEW - confirm the seal/posture model correctly represents unlock and recovery posture without overstating provider availability.",
                "seal posture model remains tracked for AI review",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "pub use paranoid_seal::{",
                "paranoid-ops re-exports seal types for adapter stability",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                "seal_posture_for_path(&invocation.open_options.path, provider_probe);",
                "vault seal-status command evaluates seal posture with explicit provider-probe mode",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                '"seal": posture',
                "vault seal-status command includes posture in JSON output",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                "serde_json::to_writer_pretty(io::stdout(), &report)",
                "vault seal-status command serializes the posture report",
            ),
            Requirement(
                "tests/test_vault_cli.sh",
                "seal_status=\"$(source_vault seal-status)\"",
                "headless vault e2e exercises seal-status output",
            ),
            Requirement(
                "tests/test_vault_cli.sh",
                'seal = data["seal"]',
                "headless vault e2e asserts the seal posture payload",
            ),
            Requirement(
                "scripts/verify_ai_review_inventory.sh",
                "seal/posture model correctly represents unlock and recovery posture",
                "inventory check tracks the seal posture TODO",
            ),
            Requirement(
                "docs/reference/ai-review.md",
                "Seal lifecycle posture model",
                "open seal posture AI disposition remains tracked",
            ),
            Requirement(
                "docs/reference/assurance-claims.md",
                "`seal.lifecycle-boundary` | `tracked-open`",
                "assurance claim tracks the open seal posture AI disposition",
            ),
            Requirement(
                "docs/reference/testing.md",
                "`vault seal-status` output",
                "testing docs cover seal-status posture output",
            ),
            Requirement(
                "docs/reference/architecture.md",
                "`paranoid-seal` owns:",
                "architecture docs name the seal lifecycle boundary",
            ),
            Requirement(
                "docs/reference/architecture.md",
                "distinguishes configured auto-unseal from confirmed provider",
                "architecture docs document provider availability semantics",
            ),
            Requirement(
                "docs/reference/federal-readiness.md",
                "so evidence does not overstate what the local process has actually checked",
                "federal readiness docs document provider availability evidence semantics",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                "VaultSealPosture::from_providers(VaultSealState::RecoveryRequired, Vec::new())",
                "unreadable vault headers do not synthesize recovery providers",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                "seal_posture_for_unreadable_vault_does_not_synthesize_provider",
                "CLI tests cover unreadable header posture behavior",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                "seal_posture_for_initialized_vault_reports_header_providers_only",
                "CLI tests cover initialized vault posture behavior",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "posture_reports_configured_recovery_and_auto_unseal_without_claiming_availability",
                "seal crate tests cover configured versus available provider posture",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "posture_requires_operator_recovery_when_only_auto_unseal_exists",
                "seal crate tests require operator recovery coverage",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "posture_reports_confirmed_auto_unseal_availability",
                "seal crate tests cover confirmed auto-unseal availability",
            ),
            Requirement(
                "docs/reference/remaining-work-prd.md",
                "seal-state transitions and seal-provider posture have unit tests and e2e coverage",
                "remaining-work PRD tracks seal posture acceptance criteria",
            ),
            Requirement(
                "README.md",
                "`paranoid-seal` owns vault seal state and non-secret provider posture",
                "README names the seal lifecycle boundary",
            ),
            Requirement(
                "docs/conf.py",
                '"paranoid_seal": str(repo_root / "crates" / "paranoid-seal")',
                "docs build includes generated Rust API docs for paranoid-seal",
            ),
            Requirement(
                "docs/api/index.md",
                "crates/paranoid_seal/lib",
                "Rust API index links the paranoid-seal crate docs",
            ),
            Requirement(
                "Cargo.toml",
                '"crates/paranoid-seal"',
                "workspace includes the paranoid-seal crate",
            ),
            Requirement(
                "Cargo.toml",
                'paranoid-seal = { path = "crates/paranoid-seal" }',
                "workspace dependency exposes the paranoid-seal crate",
            ),
            Requirement(
                "crates/paranoid-ops/Cargo.toml",
                "paranoid-seal.workspace = true",
                "paranoid-ops depends on paranoid-seal through workspace dependency",
            ),
            Requirement(
                "crates/paranoid-seal/Cargo.toml",
                'name = "paranoid-seal"',
                "paranoid-seal crate manifest exists",
            ),
            Requirement(
                "crates/paranoid-seal/Cargo.toml",
                "serde.workspace = true",
                "paranoid-seal depends on serde through the workspace",
            ),
            Requirement(
                "crates/paranoid-seal/Cargo.toml",
                "thiserror.workspace = true",
                "paranoid-seal depends on thiserror through the workspace",
            ),
            Requirement(
                "crates/paranoid-seal/Cargo.toml",
                "[lints]",
                "paranoid-seal inherits workspace lints",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub const SEAL_SCHEMA_VERSION: u16 = 1;",
                "seal posture schema version is explicit",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "SEAL_SCHEMA_VERSION",
                "ops re-exports the seal schema version",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "pub seal_posture: Option<VaultSealPosture>",
                "ops policy context can consume non-secret seal posture evidence",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "seal_posture_evidence",
                "federal unlock policy requires seal posture evidence",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "auto_unseal_provider_available",
                "device-bound unlock policy requires available auto-unseal evidence",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "federal_certificate_unlock_requires_seal_posture_evidence",
                "ops tests prove federal certificate unlock requires seal posture evidence",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "device_bound_unlock_requires_available_auto_unseal_provider",
                "ops tests prove device-bound unlock requires confirmed auto-unseal availability",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "device_bound_unlock_requires_seal_posture_evidence",
                "ops tests prove device-bound unlock fails closed without seal posture evidence",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                '"schema_version": SEAL_SCHEMA_VERSION',
                "seal-status JSON uses the seal schema version",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub fn is_auto_unseal(self) -> bool",
                "seal provider kind exposes auto-unseal classification",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub fn is_operator_recovery(self) -> bool",
                "seal provider kind exposes operator recovery classification",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub fn is_certificate_unseal(self) -> bool",
                "seal provider kind exposes certificate unwrap classification",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub fn is_available(self) -> bool",
                "seal provider status exposes confirmed availability classification",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub fn from_providers(",
                "seal posture aggregates provider evidence",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "recovery_required: state == VaultSealState::RecoveryRequired",
                "seal posture marks recovery-required state explicitly",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "|| !operator_recovery_configured",
                "seal posture requires an operator recovery path",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "provider.status.is_available()",
                "seal posture only marks auto-unseal available after provider availability is confirmed",
            ),
            Requirement(
                "docs/reference/architecture.md",
                "`paranoid-seal` owns:",
                "architecture docs name the seal lifecycle boundary",
            ),
        ),
    ),
    Claim(
        "federal.control-mapping-evidence",
        "Federal control mapping evidence",
        "security-docs",
        (
            Requirement(
                "docs/reference/control-mapping.md",
                "NIST SP 800-53 Rev5",
                "federal control mapping names the control catalog",
            ),
            Requirement(
                "docs/reference/control-mapping.md",
                "FedRAMP High, GovCloud, or DoD IL5-oriented environments",
                "federal control mapping states the target customer context precisely",
            ),
            Requirement(
                "docs/reference/control-mapping.md",
                "The project is not FedRAMP authorized.",
                "federal control mapping preserves non-claim language",
            ),
            Requirement(
                "docs/reference/control-mapping.md",
                "TCP reachability to an external audit endpoint is not evidence of durable audit ingestion.",
                "federal control mapping preserves audit-device boundary language",
            ),
            Requirement(
                "docs/reference/control-mapping.md",
                "AC - Access Control",
                "federal control mapping covers AC",
            ),
            Requirement(
                "docs/reference/control-mapping.md",
                "AU - Audit and Accountability",
                "federal control mapping covers AU",
            ),
            Requirement(
                "docs/reference/control-mapping.md",
                "CM - Configuration Management",
                "federal control mapping covers CM",
            ),
            Requirement(
                "docs/reference/control-mapping.md",
                "IA - Identification and Authentication",
                "federal control mapping covers IA",
            ),
            Requirement(
                "docs/reference/control-mapping.md",
                "SC - System and Communications Protection",
                "federal control mapping covers SC",
            ),
            Requirement(
                "docs/reference/control-mapping.md",
                "SI - System and Information Integrity",
                "federal control mapping covers SI",
            ),
            Requirement(
                "docs/reference/control-mapping.md",
                "SR - Supply Chain Risk Management",
                "federal control mapping covers SR",
            ),
            Requirement(
                "docs/reference/federal-readiness.md",
                "Federal Control Mapping",
                "federal readiness docs link to the control mapping artifact",
            ),
            Requirement(
                "docs/reference/index.md",
                "control-mapping",
                "reference toctree includes the control mapping artifact",
            ),
            Requirement(
                "docs/reference/assurance-claims.md",
                "`federal.control-mapping-evidence` | `process`",
                "assurance claims track federal control mapping evidence",
            ),
        ),
    ),
    Claim(
        "supply-chain.locked-offline-cargo",
        "Locked offline Cargo policy",
        "supply-chain",
        (
            Requirement(
                ".cargo/config.toml",
                'replace-with = "vendored-sources"',
                "Cargo is configured to use vendored sources",
            ),
            Requirement(
                "Makefile",
                "--locked --frozen --offline",
                "Makefile exposes locked/frozen/offline Cargo gates",
            ),
        ),
    ),
    Claim(
        "supply-chain.sha-pinned-actions",
        "SHA-pinned GitHub Actions",
        "supply-chain",
        (
            Requirement(
                "scripts/supply_chain_verify.sh",
                "@[a-f0-9]{40}",
                "supply-chain verifier rejects unpinned external actions",
            ),
            Requirement(
                ".github/dependabot.yml",
                "github-actions",
                "Dependabot tracks GitHub Actions updates",
            ),
        ),
    ),
    Claim(
        "release.payload-verification",
        "Release payload verification",
        "release",
        (
            Requirement(
                "scripts/release_validate.sh",
                "validate_archive_payload",
                "release validation inspects packaged payloads",
            ),
            Requirement(
                "scripts/verify_published_release.sh",
                "gh attestation verify",
                "published release verification checks GitHub attestations",
            ),
        ),
    ),
    Claim(
        "assurance.pr-neutral-ai-assessor",
        "Neutral PR AI assurance assessor",
        "assurance-process",
        (
            Requirement(
                ".github/agents/paranoid-security-auditor.md",
                "You are a neutral AI security assurance assessor",
                "custom AI assessor profile defines the neutral role",
            ),
            Requirement(
                ".github/instructions/security-assurance.instructions.md",
                "make verify-assurance",
                "path-scoped Copilot instructions require the assurance gate",
            ),
            Requirement(
                ".github/workflows/security-assurance.yml",
                "make verify-assurance",
                "dedicated workflow runs the assurance gate",
            ),
        ),
    ),
    Claim(
        "assurance.gui-screenshot-evidence",
        "GUI screenshot evidence for UI-sensitive PRs",
        "assurance-process",
        (
            Requirement(
                "Makefile",
                "test-gui-e2e: ## Run the real GUI workflow harness under Xvfb and capture a screenshot artifact",
                "Makefile exposes the Xvfb GUI e2e screenshot harness",
            ),
            Requirement(
                "Makefile",
                "test-gui-visual-regression: ## Run GUI workflow screenshots across desktop, tablet, and narrow viewport classes",
                "Makefile exposes the multi-viewport GUI visual regression harness",
            ),
            Requirement(
                "tests/test_gui_e2e.sh",
                "GUI automation screenshot was blank or undersized",
                "GUI e2e harness fails blank or undersized screenshots",
            ),
            Requirement(
                "tests/test_gui_e2e.sh",
                "GUI e2e viewport passed",
                "GUI e2e harness reports each viewport artifact",
            ),
            Requirement(
                "docs/reference/ai-review.md",
                "dist/release/gui-e2e-desktop.png",
                "AI review surface documents the desktop GUI screenshot artifact path",
            ),
            Requirement(
                "docs/reference/ai-review.md",
                "dist/release/gui-e2e-tablet.png",
                "AI review surface documents the tablet GUI screenshot artifact path",
            ),
            Requirement(
                "docs/reference/ai-review.md",
                "dist/release/gui-e2e-mobile.png",
                "AI review surface documents the narrow/mobile-class GUI screenshot artifact path",
            ),
            Requirement(
                ".github/agents/paranoid-security-auditor.md",
                "inspect the desktop, tablet, and narrow/mobile-class screenshot artifacts",
                "AI security assessor requires multi-viewport screenshot inspection for UI-sensitive changes",
            ),
            Requirement(
                ".github/instructions/security-assurance.instructions.md",
                "plus inspection of the captured desktop",
                "path-scoped instructions require multi-viewport screenshot inspection for UI-sensitive changes",
            ),
        ),
    ),
)


GLOBAL_REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement(
        "docs/reference/security-assurance.md",
        "Security Assurance Protocol",
        "security assurance protocol reference exists",
    ),
    Requirement(
        "docs/reference/assurance-claims.md",
        "Assurance Claims",
        "assurance claim inventory exists",
    ),
    Requirement(
        "docs/reference/index.md",
        "security-assurance",
        "security assurance docs are in the reference toctree",
    ),
    Requirement(
        "docs/reference/index.md",
        "assurance-claims",
        "assurance claims docs are in the reference toctree",
    ),
    Requirement(
        "docs/reference/index.md",
        "ai-review",
        "AI review docs are in the reference toctree",
    ),
    Requirement(
        "Makefile",
        "verify-assurance:",
        "Makefile exposes the assurance gate",
    ),
)


SURFACE_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("core-security", ("crates/paranoid-core/",)),
    ("vault-security", ("crates/paranoid-vault/",)),
    ("ops-security", ("crates/paranoid-audit/", "crates/paranoid-ops/")),
    ("seal-security", ("crates/paranoid-seal/",)),
    ("supply-chain", (".cargo/", "Cargo.lock", "vendor/", ".github/", "scripts/", "Makefile")),
    ("security-docs", ("AGENTS.md", "SECURITY.md", "docs/reference/")),
)


def read_text(path: str) -> str:
    full_path = REPO_ROOT / path
    if not full_path.exists():
        raise FileNotFoundError(path)
    return full_path.read_text(encoding="utf-8")


def requirement_passes(requirement: Requirement) -> tuple[bool, str]:
    try:
        content = read_text(requirement.path)
    except FileNotFoundError:
        return False, f"{requirement.path}: missing file"

    if requirement.regex:
        if re.search(requirement.pattern, content, flags=re.MULTILINE):
            return True, f"{requirement.path}: {requirement.description}"
        return False, f"{requirement.path}: missing regex {requirement.pattern!r}"

    if requirement.pattern in content:
        return True, f"{requirement.path}: {requirement.description}"
    return False, f"{requirement.path}: missing text {requirement.pattern!r}"


def run_git(args: Iterable[str]) -> list[str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return []
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line]


def collect_changed_files(base_ref: str | None) -> list[str]:
    files: list[str] = []
    if base_ref:
        files.extend(run_git(["diff", "--name-only", f"{base_ref}...HEAD"]))
    else:
        files.extend(run_git(["diff", "--name-only", "HEAD"]))
        files.extend(run_git(["diff", "--name-only", "--cached"]))
        files.extend(run_git(["ls-files", "--others", "--exclude-standard"]))
    return sorted(set(files))


def summarize_changed_files(changed_files: list[str]) -> tuple[list[str], int]:
    vendor_count = sum(1 for path in changed_files if path.startswith("vendor/"))
    summarized = [path for path in changed_files if not path.startswith("vendor/")]
    if vendor_count:
        summarized.append(f"vendor/ ({vendor_count} changed files)")
    return summarized, vendor_count


def classify_surfaces(changed_files: list[str]) -> list[str]:
    surfaces = set()
    for path in changed_files:
        for surface, prefixes in SURFACE_RULES:
            if any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in prefixes):
                surfaces.add(surface)
    return sorted(surfaces)


def evaluate_claims() -> tuple[list[dict[str, object]], list[str]]:
    failures: list[str] = []
    claims_doc = read_text("docs/reference/assurance-claims.md")
    results: list[dict[str, object]] = []

    for claim in CLAIMS:
        evidence: list[str] = []
        claim_failures: list[str] = []

        if claim.claim_id not in claims_doc:
            claim_failures.append(f"docs/reference/assurance-claims.md: missing {claim.claim_id}")

        for requirement in claim.requirements:
            ok, message = requirement_passes(requirement)
            if ok:
                evidence.append(message)
            else:
                claim_failures.append(message)

        status = "pass" if not claim_failures else "fail"
        failures.extend(f"{claim.claim_id}: {failure}" for failure in claim_failures)
        results.append(
            {
                "id": claim.claim_id,
                "title": claim.title,
                "surface": claim.surface,
                "status": status,
                "evidence": evidence,
                "failures": claim_failures,
            }
        )

    return results, failures


def evaluate_global_requirements() -> list[str]:
    failures: list[str] = []
    for requirement in GLOBAL_REQUIREMENTS:
        ok, message = requirement_passes(requirement)
        if not ok:
            failures.append(message)
    return failures


def build_report(base_ref: str | None) -> dict[str, object]:
    changed_files = collect_changed_files(base_ref)
    report_changed_files, vendor_changed_file_count = summarize_changed_files(changed_files)
    changed_surfaces = classify_surfaces(changed_files)
    claims, claim_failures = evaluate_claims()
    global_failures = evaluate_global_requirements()
    failures = [*global_failures, *claim_failures]

    return {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "verdict": "pass" if not failures else "fail",
        "base_ref": base_ref,
        "changed_files": report_changed_files,
        "changed_file_count": len(changed_files),
        "vendor_changed_file_count": vendor_changed_file_count,
        "changed_surfaces": changed_surfaces,
        "claims": claims,
        "failures": failures,
        "required_commands": ["make verify-assurance", "make ci"],
    }


def write_json(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Security Assurance Report",
        "",
        f"- Verdict: `{report['verdict']}`",
        f"- Generated: `{report['generated_at_utc']}`",
        f"- Base ref: `{report['base_ref'] or 'local workspace'}`",
        "",
        "## Changed Surfaces",
        "",
    ]
    changed_surfaces = report["changed_surfaces"]
    if changed_surfaces:
        lines.extend(f"- `{surface}`" for surface in changed_surfaces)
    else:
        lines.append("- none detected")

    lines.extend(["", "## Claims", ""])
    for claim in report["claims"]:
        status = claim["status"]
        marker = "PASS" if status == "pass" else "FAIL"
        lines.append(f"- `{marker}` `{claim['id']}` - {claim['title']}")

    failures = report["failures"]
    if failures:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {failure}" for failure in failures)

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", help="Optional git base ref for changed-file detection")
    parser.add_argument("--json-out", type=Path, help="Write the assurance report as JSON")
    parser.add_argument("--markdown-out", type=Path, help="Write the assurance report as Markdown")
    args = parser.parse_args()

    report = build_report(args.base_ref)

    if args.json_out:
        write_json(args.json_out, report)
    if args.markdown_out:
        write_markdown(args.markdown_out, report)

    print(json.dumps(report, indent=2, sort_keys=True))

    if report["verdict"] != "pass":
        print("security assurance gate failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
