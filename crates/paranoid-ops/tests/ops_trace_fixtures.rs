use paranoid_audit::{AuditEvent, AuditSurface};
use paranoid_ops::{
    FederalApprovedMode, FederalCryptoProviderEvidence, OPS_SCHEMA_VERSION, OpsActor, OpsCommand,
    OpsCommandEnvelope, OpsCommandTrace, OpsPolicyContext, OpsProfile, OpsSession, OpsTransport,
    VaultOperationAccess, evaluate_ops_command_envelope,
};

#[test]
fn cli_mutate_vault_operation_trace_fixture_is_stable() {
    let trace = fixture_trace(
        "cli.mutate",
        AuditSurface::Cli,
        OpsProfile::Default,
        OpsCommand::VaultOperation {
            name: "mutate_item".to_string(),
            access: VaultOperationAccess::Mutate,
        },
        default_context(false, false),
    );

    assert_fixture(
        &trace,
        include_str!("fixtures/ops_trace_cli_mutate_allowed.json"),
    );
}

#[test]
fn tui_keyslot_required_audit_denial_jsonl_fixture_is_stable() {
    let trace = fixture_trace(
        "tui.keyslot_denied",
        AuditSurface::Tui,
        OpsProfile::Default,
        OpsCommand::VaultOperation {
            name: "keyslot_lifecycle".to_string(),
            access: VaultOperationAccess::Keyslot,
        },
        default_context(true, false),
    );

    assert_fixture(
        &trace,
        include_str!("fixtures/ops_trace_tui_keyslot_required_audit_denied.json"),
    );
    assert_jsonl_fixture(
        &trace.audit_events,
        include_str!("fixtures/ops_trace_tui_keyslot_required_audit_denied.audit.jsonl"),
    );
}

#[test]
fn gui_export_federal_ready_trace_fixture_is_stable() {
    let trace = fixture_trace(
        "gui.export_federal",
        AuditSurface::Gui,
        OpsProfile::FederalReady,
        OpsCommand::VaultOperation {
            name: "export".to_string(),
            access: VaultOperationAccess::Export,
        },
        federal_context(true, true),
    );

    assert_fixture(
        &trace,
        include_str!("fixtures/ops_trace_gui_export_federal_ready_allowed.json"),
    );
}

fn fixture_trace(
    fixture_id: &str,
    surface: AuditSurface,
    profile: OpsProfile,
    command: OpsCommand,
    context: OpsPolicyContext,
) -> OpsCommandTrace {
    let envelope = OpsCommandEnvelope {
        schema_version: OPS_SCHEMA_VERSION,
        request_id: format!("pp.fixture.request.{fixture_id}"),
        operation_id: format!("pp.fixture.operation.{fixture_id}"),
        profile,
        actor: OpsActor::default(),
        session: OpsSession {
            session_id: format!("pp.fixture.session.{fixture_id}"),
            surface,
            transport: OpsTransport::InProcess,
        },
        command,
    };
    let mut trace = evaluate_ops_command_envelope(envelope, &context).into_trace();
    normalize_event_timestamps(&mut trace.audit_events);
    trace
}

fn default_context(audit_sink_required: bool, audit_sink_available: bool) -> OpsPolicyContext {
    OpsPolicyContext {
        profile: OpsProfile::Default,
        audit_sink_required,
        audit_sink_available,
        crypto_provider: confirmed_provider(),
        seal_posture: None,
    }
}

fn federal_context(audit_sink_required: bool, audit_sink_available: bool) -> OpsPolicyContext {
    OpsPolicyContext {
        profile: OpsProfile::FederalReady,
        audit_sink_required,
        audit_sink_available,
        crypto_provider: FederalCryptoProviderEvidence {
            provider_name: "OpenSSL".to_string(),
            provider_version: "OpenSSL fixture provider".to_string(),
            provider_platform: "fixture-platform".to_string(),
            approved_mode: FederalApprovedMode::Confirmed,
            certificate_reference: Some("CMVP fixture certificate".to_string()),
            evidence_source: "fixture".to_string(),
        },
        seal_posture: None,
    }
}

fn confirmed_provider() -> FederalCryptoProviderEvidence {
    FederalCryptoProviderEvidence::confirmed_for_tests("CMVP fixture certificate")
}

fn normalize_event_timestamps(events: &mut [AuditEvent]) {
    for event in events {
        event.occurred_at_epoch_ms = 0;
        event.timestamp_error = None;
    }
}

fn assert_fixture(trace: &OpsCommandTrace, expected_json: &str) {
    let actual = serde_json::to_value(trace).expect("serialize trace");
    let expected: serde_json::Value =
        serde_json::from_str(expected_json).expect("parse trace fixture");
    assert_eq!(actual, expected);
}

fn assert_jsonl_fixture(events: &[AuditEvent], expected_jsonl: &str) {
    let mut actual = String::new();
    for event in events {
        actual.push_str(&serde_json::to_string(event).expect("serialize audit event"));
        actual.push('\n');
    }
    assert_eq!(actual, expected_jsonl);
}
