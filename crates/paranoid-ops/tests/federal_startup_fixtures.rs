use paranoid_audit::AuditSinkHealth;
use paranoid_ops::{
    FederalApprovedMode, FederalCryptoProviderEvidence, FederalStartupEvidenceInput, OpsProfile,
    collect_federal_startup_evidence_from_input,
};

#[test]
fn federal_startup_evidence_denied_fixture_is_stable() {
    let evidence = collect_federal_startup_evidence_from_input(FederalStartupEvidenceInput {
        profile: OpsProfile::FederalReady,
        product_version: "fixture-version".to_string(),
        build_commit: "fixture-commit".to_string(),
        build_date: "2026-01-01T00:00:00Z".to_string(),
        operating_system: "linux".to_string(),
        architecture: "amd64".to_string(),
        audit_sink: AuditSinkHealth::not_configured_jsonl(),
        external_audit_device: AuditSinkHealth::unverified_external_device(
            "siem-primary",
            "mtls://audit.example.invalid:6514",
            "external audit-device health probe is not implemented; configured mTLS material is evidence only",
        ),
        crypto_provider: FederalCryptoProviderEvidence {
            provider_name: "OpenSSL".to_string(),
            provider_version: "OpenSSL fixture provider".to_string(),
            provider_platform: "fixture-platform".to_string(),
            approved_mode: FederalApprovedMode::NotConfirmed,
            certificate_reference: None,
            evidence_source: "fixture".to_string(),
        },
    });

    let actual = serde_json::to_value(&evidence).expect("serialize evidence");
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/federal_startup_denied.json"))
            .expect("parse fixture");

    assert_eq!(actual, expected);
}
