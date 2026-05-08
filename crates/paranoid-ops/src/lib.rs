use paranoid_audit::{
    AUDIT_SCHEMA_VERSION, AuditEvent, AuditOutcome, AuditSeverity, AuditSinkHealth, AuditSubject,
    AuditSurface, AuditTrail, assess_external_audit_device_from_environment,
};
use paranoid_core::{AuditStage, AuditSummary, GenerationReport, ParanoidError, ParanoidRequest};
pub use paranoid_seal::{
    SEAL_SCHEMA_VERSION, VaultSealEvent, VaultSealMachine, VaultSealPosture,
    VaultSealProviderEvidence, VaultSealProviderKind, VaultSealProviderStatus, VaultSealState,
    VaultSealTransition, VaultSealTransitionError,
};
use serde::{Deserialize, Serialize};
use std::{
    env, process,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

mod mtls_transport;
pub use mtls_transport::*;

static LOCAL_OPERATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub const OPS_SCHEMA_VERSION: u16 = 1;
pub const OPS_TRANSPORT_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const FEDERAL_STARTUP_EVIDENCE_SCHEMA_VERSION: u16 = 2;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpsProfile {
    #[default]
    Default,
    FederalReady,
}

impl OpsProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::FederalReady => "federal_ready",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpsActorKind {
    LocalOperator,
    Automation,
    ServiceAccount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsActor {
    pub actor_id: String,
    pub kind: OpsActorKind,
}

impl Default for OpsActor {
    fn default() -> Self {
        Self {
            actor_id: "local_operator".to_string(),
            kind: OpsActorKind::LocalOperator,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpsTransport {
    InProcess,
    LocalTty,
    Mtls,
}

impl OpsTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InProcess => "in_process",
            Self::LocalTty => "local_tty",
            Self::Mtls => "mtls",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsTransportEvidence {
    pub schema_version: u16,
    pub transport: OpsTransport,
    pub authenticated: bool,
    pub peer_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_fingerprint_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_binding_sha256: Option<String>,
    pub evidence_source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl OpsTransportEvidence {
    pub fn authenticated_mtls(
        peer_identity: impl Into<String>,
        certificate_fingerprint_sha256: impl Into<String>,
        evidence_source: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: OPS_TRANSPORT_EVIDENCE_SCHEMA_VERSION,
            transport: OpsTransport::Mtls,
            authenticated: true,
            peer_identity: peer_identity.into(),
            certificate_fingerprint_sha256: Some(certificate_fingerprint_sha256.into()),
            channel_binding_sha256: None,
            evidence_source: evidence_source.into(),
            warnings: Vec::new(),
        }
    }

    pub fn unauthenticated_mtls(
        peer_identity: impl Into<String>,
        evidence_source: impl Into<String>,
        warning: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: OPS_TRANSPORT_EVIDENCE_SCHEMA_VERSION,
            transport: OpsTransport::Mtls,
            authenticated: false,
            peer_identity: peer_identity.into(),
            certificate_fingerprint_sha256: None,
            channel_binding_sha256: None,
            evidence_source: evidence_source.into(),
            warnings: vec![warning.into()],
        }
    }

    pub fn with_channel_binding_sha256(
        mut self,
        channel_binding_sha256: impl Into<String>,
    ) -> Self {
        self.channel_binding_sha256 = Some(channel_binding_sha256.into());
        self
    }

    fn is_authenticated_mtls(&self) -> bool {
        self.transport == OpsTransport::Mtls
            && self.authenticated
            && !self.peer_identity.trim().is_empty()
            && self
                .certificate_fingerprint_sha256
                .as_deref()
                .is_some_and(|fingerprint| !fingerprint.trim().is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsSession {
    pub session_id: String,
    pub surface: AuditSurface,
    pub transport: OpsTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_evidence: Option<OpsTransportEvidence>,
}

impl OpsSession {
    pub fn local(surface: AuditSurface) -> Self {
        Self {
            session_id: new_local_operation_id(),
            surface,
            transport: OpsTransport::InProcess,
            transport_evidence: None,
        }
    }

    pub fn mtls(
        surface: AuditSurface,
        session_id: impl Into<String>,
        transport_evidence: OpsTransportEvidence,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            surface,
            transport: OpsTransport::Mtls,
            transport_evidence: Some(transport_evidence),
        }
    }

    fn has_authenticated_transport_evidence(&self) -> bool {
        match self.transport {
            OpsTransport::InProcess | OpsTransport::LocalTty => true,
            OpsTransport::Mtls => self
                .transport_evidence
                .as_ref()
                .is_some_and(OpsTransportEvidence::is_authenticated_mtls),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultUnlockMethod {
    PasswordRecovery,
    MnemonicRecovery,
    DeviceBound,
    CertificateWrapped,
}

impl VaultUnlockMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PasswordRecovery => "password_recovery",
            Self::MnemonicRecovery => "mnemonic_recovery",
            Self::DeviceBound => "device_bound",
            Self::CertificateWrapped => "certificate_wrapped",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultOperationAccess {
    Metadata,
    Decrypt,
    Mutate,
    Export,
    Import,
    Keyslot,
}

impl VaultOperationAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Decrypt => "decrypt",
            Self::Mutate => "mutate",
            Self::Export => "export",
            Self::Import => "import",
            Self::Keyslot => "keyslot",
        }
    }

    fn requires_fips_evidence(self) -> bool {
        !matches!(self, Self::Metadata)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OpsCommand {
    GeneratePassword,
    VaultSealStatus {
        probe_providers: bool,
    },
    VaultUnlock {
        method: VaultUnlockMethod,
    },
    VaultOperation {
        name: String,
        access: VaultOperationAccess,
    },
    FederalEvidence,
}

impl OpsCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::GeneratePassword => "generate_password",
            Self::VaultSealStatus { .. } => "vault_seal_status",
            Self::VaultUnlock { .. } => "vault_unlock",
            Self::VaultOperation { .. } => "vault_operation",
            Self::FederalEvidence => "federal_evidence",
        }
    }

    pub fn subject(&self) -> AuditSubject {
        match self {
            Self::GeneratePassword => AuditSubject::PasswordGeneration,
            Self::VaultSealStatus { .. }
            | Self::VaultUnlock { .. }
            | Self::VaultOperation { .. } => AuditSubject::VaultOperation,
            Self::FederalEvidence => AuditSubject::ReleaseAssurance,
        }
    }

    fn is_security_relevant(&self) -> bool {
        !matches!(self, Self::FederalEvidence)
    }

    fn requires_fips_evidence(&self) -> bool {
        match self {
            Self::GeneratePassword | Self::VaultUnlock { .. } => true,
            Self::VaultOperation { access, .. } => access.requires_fips_evidence(),
            Self::VaultSealStatus { .. } | Self::FederalEvidence => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsCommandEnvelope {
    pub schema_version: u16,
    pub request_id: String,
    pub operation_id: String,
    pub profile: OpsProfile,
    pub actor: OpsActor,
    pub session: OpsSession,
    pub command: OpsCommand,
}

impl OpsCommandEnvelope {
    pub fn local(surface: AuditSurface, profile: OpsProfile, command: OpsCommand) -> Self {
        let operation_id = new_local_operation_id();
        Self {
            schema_version: OPS_SCHEMA_VERSION,
            request_id: format!("{operation_id}.request"),
            operation_id,
            profile,
            actor: OpsActor::default(),
            session: OpsSession::local(surface),
            command,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederalApprovedMode {
    Confirmed,
    NotConfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederalCryptoProviderEvidence {
    pub provider_name: String,
    pub provider_version: String,
    pub provider_platform: String,
    pub approved_mode: FederalApprovedMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_reference: Option<String>,
    pub evidence_source: String,
}

impl FederalCryptoProviderEvidence {
    pub fn collect_from_environment() -> Self {
        let approved_mode = match env::var("PARANOID_FEDERAL_APPROVED_MODE") {
            Ok(value) if matches!(value.as_str(), "1" | "true" | "confirmed") => {
                FederalApprovedMode::Confirmed
            }
            _ => FederalApprovedMode::NotConfirmed,
        };
        Self {
            provider_name: "OpenSSL".to_string(),
            provider_version: paranoid_core::openssl_version_text().to_string(),
            provider_platform: paranoid_core::openssl_platform_text().to_string(),
            approved_mode,
            certificate_reference: env::var("PARANOID_FEDERAL_CERTIFICATE_REFERENCE").ok(),
            evidence_source: "runtime".to_string(),
        }
    }

    pub fn confirmed_for_tests(certificate_reference: impl Into<String>) -> Self {
        Self {
            provider_name: "OpenSSL".to_string(),
            provider_version: "OpenSSL test provider".to_string(),
            provider_platform: env::consts::OS.to_string(),
            approved_mode: FederalApprovedMode::Confirmed,
            certificate_reference: Some(certificate_reference.into()),
            evidence_source: "test".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsPolicyContext {
    pub profile: OpsProfile,
    pub audit_sink_required: bool,
    pub audit_sink_available: bool,
    pub crypto_provider: FederalCryptoProviderEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_posture: Option<VaultSealPosture>,
}

impl OpsPolicyContext {
    pub fn default_local() -> Self {
        Self {
            profile: OpsProfile::Default,
            audit_sink_required: false,
            audit_sink_available: false,
            crypto_provider: FederalCryptoProviderEvidence::collect_from_environment(),
            seal_posture: None,
        }
    }

    pub fn federal_ready(audit_sink_available: bool) -> Self {
        Self {
            profile: OpsProfile::FederalReady,
            audit_sink_required: true,
            audit_sink_available,
            crypto_provider: FederalCryptoProviderEvidence::collect_from_environment(),
            seal_posture: None,
        }
    }

    pub fn with_seal_posture(mut self, seal_posture: VaultSealPosture) -> Self {
        self.seal_posture = Some(seal_posture);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum OpsPolicyDecision {
    Allow {
        reason: String,
    },
    Challenge {
        challenge_id: String,
        reason: String,
        required_actions: Vec<String>,
    },
    Deny {
        reason: String,
        missing_controls: Vec<String>,
    },
}

impl OpsPolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    pub fn status(&self) -> &'static str {
        match self {
            Self::Allow { .. } => "allow",
            Self::Challenge { .. } => "challenge",
            Self::Deny { .. } => "deny",
        }
    }
}

pub fn evaluate_policy(
    envelope: &OpsCommandEnvelope,
    context: &OpsPolicyContext,
) -> OpsPolicyDecision {
    let profile = envelope.profile;
    if matches!(envelope.command, OpsCommand::FederalEvidence) {
        return OpsPolicyDecision::Allow {
            reason: "federal evidence collection is allowed so missing controls can be reported"
                .to_string(),
        };
    }

    let mut missing_controls = Vec::new();
    if envelope.command.is_security_relevant()
        && (profile == OpsProfile::FederalReady || context.audit_sink_required)
        && !context.audit_sink_available
    {
        missing_controls.push("required_audit_sink".to_string());
    }
    if envelope.command.is_security_relevant()
        && !envelope.session.has_authenticated_transport_evidence()
    {
        missing_controls.push("mtls_transport_evidence".to_string());
    }

    if let OpsCommand::VaultUnlock { method } = envelope.command {
        append_seal_policy_missing_controls(method, context, &mut missing_controls);
    }

    if profile == OpsProfile::Default {
        if missing_controls.is_empty() {
            return OpsPolicyDecision::Allow {
                reason: "default profile permits local in-process operation".to_string(),
            };
        }
        return OpsPolicyDecision::Deny {
            reason: "default profile is missing required controls".to_string(),
            missing_controls,
        };
    }

    if envelope.command.requires_fips_evidence()
        && context.crypto_provider.approved_mode != FederalApprovedMode::Confirmed
    {
        missing_controls.push("fips_approved_mode".to_string());
    }
    if let OpsCommand::VaultUnlock { method } = envelope.command
        && profile == OpsProfile::FederalReady
    {
        if context.seal_posture.is_none() {
            missing_controls.push("seal_posture_evidence".to_string());
        }
        if !matches!(method, VaultUnlockMethod::CertificateWrapped) {
            missing_controls.push(format!("non_federal_unlock_method:{}", method.as_str()));
        }
    }

    if !missing_controls.is_empty() {
        return OpsPolicyDecision::Deny {
            reason: "federal-ready profile is missing required controls".to_string(),
            missing_controls,
        };
    }

    if matches!(envelope.command, OpsCommand::VaultUnlock { .. }) {
        return OpsPolicyDecision::Challenge {
            challenge_id: format!("{}.challenge.1", envelope.request_id),
            reason: "vault unlock requires fresh operator proof under federal-ready policy"
                .to_string(),
            required_actions: vec!["fresh_operator_proof".to_string()],
        };
    }

    OpsPolicyDecision::Allow {
        reason: "federal-ready controls satisfied".to_string(),
    }
}

fn append_seal_policy_missing_controls(
    method: VaultUnlockMethod,
    context: &OpsPolicyContext,
    missing_controls: &mut Vec<String>,
) {
    let Some(posture) = &context.seal_posture else {
        if matches!(method, VaultUnlockMethod::DeviceBound) {
            missing_controls.push("seal_posture_evidence".to_string());
        }
        return;
    };

    match method {
        VaultUnlockMethod::PasswordRecovery | VaultUnlockMethod::MnemonicRecovery => {
            if !posture.operator_recovery_configured {
                missing_controls.push("operator_recovery_provider".to_string());
            }
        }
        VaultUnlockMethod::DeviceBound => {
            if !posture.auto_unseal_available {
                missing_controls.push("auto_unseal_provider_available".to_string());
            }
        }
        VaultUnlockMethod::CertificateWrapped => {
            if !posture.certificate_unseal_configured {
                missing_controls.push("certificate_unseal_provider".to_string());
            }
        }
    }
}

pub fn record_ops_request<'a>(
    trail: &'a mut AuditTrail,
    envelope: &OpsCommandEnvelope,
) -> &'a mut AuditEvent {
    let event = trail.record(
        AuditSurface::Ops,
        envelope.command.subject(),
        format!("{}.request", envelope.command.name()),
        AuditOutcome::Started,
        AuditSeverity::Info,
        "typed ops command request accepted for policy evaluation",
    );
    event
        .attributes
        .insert("request_id".to_string(), envelope.request_id.clone());
    record_session_attributes(event, envelope);
    event
        .attributes
        .insert("profile".to_string(), envelope.profile.as_str().to_string());
    event
        .attributes
        .insert("command".to_string(), envelope.command.name().to_string());
    if let OpsCommand::VaultOperation { name, access } = &envelope.command {
        event
            .attributes
            .insert("vault_operation".to_string(), name.clone());
        event
            .attributes
            .insert("vault_access".to_string(), access.as_str().to_string());
    }
    if let OpsCommand::VaultSealStatus { probe_providers } = &envelope.command {
        event
            .attributes
            .insert("probe_providers".to_string(), probe_providers.to_string());
    }
    if let OpsCommand::VaultUnlock { method } = &envelope.command {
        event
            .attributes
            .insert("unlock_method".to_string(), method.as_str().to_string());
    }
    event
}

pub fn record_ops_response<'a>(
    trail: &'a mut AuditTrail,
    envelope: &OpsCommandEnvelope,
    decision: &OpsPolicyDecision,
) -> &'a mut AuditEvent {
    let (outcome, severity) = match decision {
        OpsPolicyDecision::Allow { .. } => (AuditOutcome::Success, AuditSeverity::Notice),
        OpsPolicyDecision::Challenge { .. } => (AuditOutcome::Review, AuditSeverity::Warning),
        OpsPolicyDecision::Deny { .. } => (AuditOutcome::Blocked, AuditSeverity::Error),
    };
    let event = trail.record(
        AuditSurface::Ops,
        envelope.command.subject(),
        format!("{}.response", envelope.command.name()),
        outcome,
        severity,
        "typed ops command policy response emitted",
    );
    event
        .attributes
        .insert("request_id".to_string(), envelope.request_id.clone());
    record_session_attributes(event, envelope);
    event
        .attributes
        .insert("decision".to_string(), decision.status().to_string());
    if let OpsCommand::VaultOperation { name, access } = &envelope.command {
        event
            .attributes
            .insert("vault_operation".to_string(), name.clone());
        event
            .attributes
            .insert("vault_access".to_string(), access.as_str().to_string());
    }
    if let OpsCommand::VaultSealStatus { probe_providers } = &envelope.command {
        event
            .attributes
            .insert("probe_providers".to_string(), probe_providers.to_string());
    }
    if let OpsCommand::VaultUnlock { method } = &envelope.command {
        event
            .attributes
            .insert("unlock_method".to_string(), method.as_str().to_string());
    }
    event
}

fn record_session_attributes(event: &mut AuditEvent, envelope: &OpsCommandEnvelope) {
    event.attributes.insert(
        "session_surface".to_string(),
        envelope.session.surface.as_str().to_string(),
    );
    event.attributes.insert(
        "session_transport".to_string(),
        envelope.session.transport.as_str().to_string(),
    );
    if let Some(evidence) = &envelope.session.transport_evidence {
        event.attributes.insert(
            "transport_authenticated".to_string(),
            evidence.authenticated.to_string(),
        );
        event.attributes.insert(
            "transport_evidence_source".to_string(),
            evidence.evidence_source.clone(),
        );
        event.attributes.insert(
            "transport_peer_identity".to_string(),
            evidence.peer_identity.clone(),
        );
        if let Some(fingerprint) = &evidence.certificate_fingerprint_sha256 {
            event.attributes.insert(
                "transport_certificate_fingerprint_sha256".to_string(),
                fingerprint.clone(),
            );
        }
        if let Some(channel_binding) = &evidence.channel_binding_sha256 {
            event.attributes.insert(
                "transport_channel_binding_sha256".to_string(),
                channel_binding.clone(),
            );
        }
        if !evidence.warnings.is_empty() {
            event.attributes.insert(
                "transport_warnings".to_string(),
                evidence.warnings.join("; "),
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsCommandEvaluation {
    pub envelope: OpsCommandEnvelope,
    pub decision: OpsPolicyDecision,
    pub audit_events: Vec<AuditEvent>,
}

impl OpsCommandEvaluation {
    pub fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }

    pub fn trace(&self) -> OpsCommandTrace {
        OpsCommandTrace {
            schema_version: OPS_SCHEMA_VERSION,
            envelope: self.envelope.clone(),
            decision: self.decision.clone(),
            audit_events: self.audit_events.clone(),
        }
    }

    pub fn into_trace(self) -> OpsCommandTrace {
        OpsCommandTrace {
            schema_version: OPS_SCHEMA_VERSION,
            envelope: self.envelope,
            decision: self.decision,
            audit_events: self.audit_events,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsCommandTrace {
    pub schema_version: u16,
    pub envelope: OpsCommandEnvelope,
    pub decision: OpsPolicyDecision,
    pub audit_events: Vec<AuditEvent>,
}

// TODO: AI_REVIEW - centralized policy boundary for ops/vault authorization and audit evidence across adapters.
pub fn evaluate_ops_command(
    surface: AuditSurface,
    command: OpsCommand,
    context: &OpsPolicyContext,
) -> OpsCommandEvaluation {
    let envelope = OpsCommandEnvelope::local(surface, context.profile, command);
    evaluate_ops_command_envelope(envelope, context)
}

pub fn evaluate_ops_command_envelope(
    envelope: OpsCommandEnvelope,
    context: &OpsPolicyContext,
) -> OpsCommandEvaluation {
    let mut trail = AuditTrail::for_operation(envelope.operation_id.clone());
    record_ops_request(&mut trail, &envelope);
    let decision = evaluate_policy(&envelope, context);
    record_ops_response(&mut trail, &envelope, &decision);
    OpsCommandEvaluation {
        envelope,
        decision,
        audit_events: trail.into_events(),
    }
}

pub fn evaluate_vault_operation(
    surface: AuditSurface,
    name: impl Into<String>,
    access: VaultOperationAccess,
    context: &OpsPolicyContext,
) -> OpsCommandEvaluation {
    evaluate_ops_command(
        surface,
        OpsCommand::VaultOperation {
            name: name.into(),
            access,
        },
        context,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederalStartupEvidence {
    pub schema_version: u16,
    pub profile: OpsProfile,
    pub product_version: String,
    pub build_commit: String,
    pub build_date: String,
    pub operating_system: String,
    pub architecture: String,
    pub audit_schema_version: u16,
    pub audit_sink: AuditSinkHealth,
    pub external_audit_device: AuditSinkHealth,
    pub crypto_provider: FederalCryptoProviderEvidence,
    pub policy_decision: OpsPolicyDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederalStartupEvidenceInput {
    pub profile: OpsProfile,
    pub product_version: String,
    pub build_commit: String,
    pub build_date: String,
    pub operating_system: String,
    pub architecture: String,
    pub audit_sink: AuditSinkHealth,
    pub external_audit_device: AuditSinkHealth,
    pub crypto_provider: FederalCryptoProviderEvidence,
}

impl FederalStartupEvidenceInput {
    pub fn runtime(
        profile: OpsProfile,
        audit_sink: AuditSinkHealth,
        build_commit: impl Into<String>,
        build_date: impl Into<String>,
    ) -> Self {
        Self {
            profile,
            product_version: paranoid_core::VERSION.to_string(),
            build_commit: build_commit.into(),
            build_date: build_date.into(),
            operating_system: env::consts::OS.to_string(),
            architecture: env::consts::ARCH.to_string(),
            audit_sink,
            external_audit_device: assess_external_audit_device_from_environment(),
            crypto_provider: FederalCryptoProviderEvidence::collect_from_environment(),
        }
    }
}

pub fn collect_federal_startup_evidence(
    profile: OpsProfile,
    audit_sink_available: bool,
    build_commit: impl Into<String>,
    build_date: impl Into<String>,
) -> FederalStartupEvidence {
    let audit_sink = if audit_sink_available {
        AuditSinkHealth::ready_jsonl(None)
    } else {
        AuditSinkHealth::not_configured_jsonl()
    };
    collect_federal_startup_evidence_with_audit_sink(profile, audit_sink, build_commit, build_date)
}

pub fn collect_federal_startup_evidence_with_audit_sink(
    profile: OpsProfile,
    audit_sink: AuditSinkHealth,
    build_commit: impl Into<String>,
    build_date: impl Into<String>,
) -> FederalStartupEvidence {
    let input = FederalStartupEvidenceInput::runtime(profile, audit_sink, build_commit, build_date);
    collect_federal_startup_evidence_from_input(input)
}

pub fn collect_federal_startup_evidence_from_input(
    input: FederalStartupEvidenceInput,
) -> FederalStartupEvidence {
    let context = OpsPolicyContext {
        profile: input.profile,
        audit_sink_required: input.profile == OpsProfile::FederalReady,
        audit_sink_available: input.audit_sink.is_available()
            || input.external_audit_device.is_available(),
        crypto_provider: input.crypto_provider.clone(),
        seal_posture: None,
    };
    let envelope = OpsCommandEnvelope::local(
        AuditSurface::Cli,
        input.profile,
        OpsCommand::GeneratePassword,
    );
    let policy_decision = evaluate_policy(&envelope, &context);
    FederalStartupEvidence {
        schema_version: FEDERAL_STARTUP_EVIDENCE_SCHEMA_VERSION,
        profile: input.profile,
        product_version: input.product_version,
        build_commit: input.build_commit,
        build_date: input.build_date,
        operating_system: input.operating_system,
        architecture: input.architecture,
        audit_schema_version: AUDIT_SCHEMA_VERSION,
        audit_sink: input.audit_sink,
        external_audit_device: input.external_audit_device,
        crypto_provider: input.crypto_provider,
        policy_decision,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratePasswordOperation {
    #[serde(default = "new_local_operation_id")]
    pub operation_id: String,
    pub request: ParanoidRequest,
    pub audit: bool,
}

impl GeneratePasswordOperation {
    pub fn new(request: ParanoidRequest, audit: bool) -> Self {
        Self {
            operation_id: new_local_operation_id(),
            request,
            audit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratePasswordOutcome {
    pub operation_id: String,
    pub report: GenerationReport,
    pub audit_events: Vec<AuditEvent>,
}

impl GeneratePasswordOutcome {
    pub fn automation_report(&self) -> GeneratePasswordAutomationReport<'_> {
        GeneratePasswordAutomationReport {
            schema_version: AUDIT_SCHEMA_VERSION,
            operation: "generate_password",
            operation_id: &self.operation_id,
            status: if report_pass(&self.report.audit) {
                "success"
            } else {
                "review"
            },
            report: &self.report,
            audit_events: &self.audit_events,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GeneratePasswordAutomationReport<'a> {
    pub schema_version: u16,
    pub operation: &'static str,
    pub operation_id: &'a str,
    pub status: &'static str,
    pub report: &'a GenerationReport,
    pub audit_events: &'a [AuditEvent],
}

#[derive(Debug, Error)]
#[error("{source}")]
pub struct GeneratePasswordError {
    operation_id: String,
    source: ParanoidError,
    audit_events: Vec<AuditEvent>,
}

impl GeneratePasswordError {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn source(&self) -> &ParanoidError {
        &self.source
    }

    pub fn audit_events(&self) -> &[AuditEvent] {
        &self.audit_events
    }

    pub fn failure_report(&self) -> GeneratePasswordFailureReport<'_> {
        GeneratePasswordFailureReport {
            schema_version: AUDIT_SCHEMA_VERSION,
            operation: "generate_password",
            operation_id: &self.operation_id,
            status: "error",
            error_kind: paranoid_error_kind(&self.source),
            error_message: self.source.to_string(),
            audit_events: &self.audit_events,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GeneratePasswordFailureReport<'a> {
    pub schema_version: u16,
    pub operation: &'static str,
    pub operation_id: &'a str,
    pub status: &'static str,
    pub error_kind: &'static str,
    pub error_message: String,
    pub audit_events: &'a [AuditEvent],
}

pub fn run_generate_password_operation(
    operation: GeneratePasswordOperation,
) -> Result<GeneratePasswordOutcome, GeneratePasswordError> {
    let mut trail = AuditTrail::for_operation(operation.operation_id);
    trail.record(
        AuditSurface::Ops,
        AuditSubject::PasswordGeneration,
        "generate_password.start",
        AuditOutcome::Started,
        AuditSeverity::Info,
        "password generation operation started",
    );

    let result = paranoid_core::execute_request(&operation.request, operation.audit, |stage| {
        record_stage(&mut trail, stage);
    });

    match result {
        Ok(report) => {
            let outcome = if report_pass(&report.audit) {
                AuditOutcome::Success
            } else {
                AuditOutcome::Review
            };
            let severity = if outcome == AuditOutcome::Review {
                AuditSeverity::Warning
            } else {
                AuditSeverity::Notice
            };
            trail
                .record(
                    AuditSurface::Ops,
                    AuditSubject::PasswordGeneration,
                    "generate_password.complete",
                    outcome,
                    severity,
                    "password generation operation completed",
                )
                .attributes
                .insert(
                    "password_count".to_string(),
                    report.passwords.len().to_string(),
                );
            Ok(GeneratePasswordOutcome {
                operation_id: trail.operation_id().to_string(),
                report,
                audit_events: trail.into_events(),
            })
        }
        Err(source) => {
            let operation_id = trail.operation_id().to_string();
            trail.record(
                AuditSurface::Ops,
                AuditSubject::PasswordGeneration,
                "generate_password.error",
                AuditOutcome::Failure,
                AuditSeverity::Error,
                source.to_string(),
            );
            Err(GeneratePasswordError {
                operation_id,
                source,
                audit_events: trail.into_events(),
            })
        }
    }
}

fn report_pass(audit: &Option<AuditSummary>) -> bool {
    match audit {
        Some(audit) => audit.overall_pass,
        None => true,
    }
}

pub fn new_local_operation_id() -> String {
    let sequence = LOCAL_OPERATION_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
    let time_component = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos().to_string(),
        Err(error) => format!("pre_epoch_{}", error.duration().as_nanos()),
    };
    format!(
        "pp.operation.v1.{}.{}.{}",
        process::id(),
        time_component,
        sequence
    )
}

fn record_stage(trail: &mut AuditTrail, stage: AuditStage) {
    trail
        .record(
            AuditSurface::Core,
            AuditSubject::StatisticalAudit,
            format!("audit_stage.{}", audit_stage_id(stage)),
            AuditOutcome::Success,
            AuditSeverity::Info,
            stage.label(),
        )
        .attributes
        .insert("stage".to_string(), audit_stage_id(stage).to_string());
}

fn audit_stage_id(stage: AuditStage) -> &'static str {
    match stage {
        AuditStage::Generate => "generate",
        AuditStage::ChiSquared => "chi_squared",
        AuditStage::SerialCorrelation => "serial_correlation",
        AuditStage::CollisionDetection => "collision_detection",
        AuditStage::EntropyProofs => "entropy_proofs",
        AuditStage::PatternDetection => "pattern_detection",
        AuditStage::ThreatAssessment => "threat_assessment",
        AuditStage::Complete => "complete",
    }
}

fn paranoid_error_kind(error: &ParanoidError) -> &'static str {
    match error {
        ParanoidError::InvalidArguments(_) => "invalid_arguments",
        ParanoidError::ImpossibleRequirements(_) => "impossible_requirements",
        ParanoidError::RandomFailure(_) => "random_failure",
        ParanoidError::HashFailure(_) => "hash_failure",
        ParanoidError::ExhaustedAttempts => "exhausted_attempts",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paranoid_core::{CharRequirements, CharsetSpec};

    #[test]
    fn generate_operation_records_core_audit_stages_without_secret_values() {
        let outcome = run_generate_password_operation(GeneratePasswordOperation {
            operation_id: "pp.operation.v1.test-success".to_string(),
            request: ParanoidRequest {
                length: 12,
                count: 1,
                batch_size: 12,
                charset: CharsetSpec::NamedOrLiteral("hex".to_string()),
                requirements: CharRequirements::default(),
                selected_frameworks: Vec::new(),
            },
            audit: true,
        })
        .expect("operation succeeds");

        assert_eq!(outcome.operation_id, "pp.operation.v1.test-success");
        assert_eq!(outcome.report.passwords.len(), 1);
        assert!(
            outcome
                .audit_events
                .iter()
                .any(|event| event.action == "audit_stage.chi_squared")
        );
        let generated = outcome.report.passwords[0].value.as_str();
        assert!(
            !outcome
                .audit_events
                .iter()
                .any(|event| event.message.contains(generated))
        );
        assert!(
            outcome
                .audit_events
                .iter()
                .all(|event| event.operation_id == outcome.operation_id)
        );
    }

    #[test]
    fn generate_operation_failure_keeps_audit_events_for_automation() {
        let error = run_generate_password_operation(GeneratePasswordOperation {
            operation_id: "pp.operation.v1.test-failure".to_string(),
            request: ParanoidRequest {
                length: 0,
                ..ParanoidRequest::default()
            },
            audit: true,
        })
        .expect_err("invalid request fails");

        assert_eq!(error.failure_report().error_kind, "invalid_arguments");
        assert_eq!(error.operation_id(), "pp.operation.v1.test-failure");
        assert_eq!(
            error.failure_report().operation_id,
            "pp.operation.v1.test-failure"
        );
        assert!(!error.audit_events().is_empty());
    }

    #[test]
    fn local_operation_ids_are_process_local_non_secret_identifiers() {
        let first = new_local_operation_id();
        let second = new_local_operation_id();

        assert!(first.starts_with("pp.operation.v1."));
        assert!(second.starts_with("pp.operation.v1."));
        assert_ne!(first, second);
    }

    #[test]
    fn federal_policy_fails_closed_without_required_controls() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Cli,
            OpsProfile::FederalReady,
            OpsCommand::GeneratePassword,
        );
        let context = OpsPolicyContext {
            profile: OpsProfile::FederalReady,
            audit_sink_required: true,
            audit_sink_available: false,
            crypto_provider: FederalCryptoProviderEvidence {
                provider_name: "OpenSSL".to_string(),
                provider_version: "OpenSSL test provider".to_string(),
                provider_platform: "test".to_string(),
                approved_mode: FederalApprovedMode::NotConfirmed,
                certificate_reference: None,
                evidence_source: "test".to_string(),
            },
            seal_posture: None,
        };

        let decision = evaluate_policy(&envelope, &context);

        match decision {
            OpsPolicyDecision::Deny {
                missing_controls, ..
            } => {
                assert!(missing_controls.contains(&"required_audit_sink".to_string()));
                assert!(missing_controls.contains(&"fips_approved_mode".to_string()));
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn explicit_required_audit_sink_fails_closed_in_default_profile() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Cli,
            OpsProfile::Default,
            OpsCommand::GeneratePassword,
        );
        let context = OpsPolicyContext {
            profile: OpsProfile::Default,
            audit_sink_required: true,
            audit_sink_available: false,
            crypto_provider: FederalCryptoProviderEvidence::confirmed_for_tests(
                "CMVP test certificate",
            ),
            seal_posture: None,
        };

        let decision = evaluate_policy(&envelope, &context);

        match decision {
            OpsPolicyDecision::Deny {
                missing_controls, ..
            } => {
                assert_eq!(missing_controls, vec!["required_audit_sink".to_string()]);
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn federal_policy_challenges_certificate_unlock_after_controls_pass() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Cli,
            OpsProfile::FederalReady,
            OpsCommand::VaultUnlock {
                method: VaultUnlockMethod::CertificateWrapped,
            },
        );
        let context = OpsPolicyContext {
            profile: OpsProfile::FederalReady,
            audit_sink_required: true,
            audit_sink_available: true,
            crypto_provider: FederalCryptoProviderEvidence::confirmed_for_tests(
                "CMVP test certificate",
            ),
            seal_posture: Some(VaultSealPosture::from_providers(
                VaultSealState::Sealed,
                vec![
                    VaultSealProviderEvidence::configured(
                        "password",
                        VaultSealProviderKind::PasswordRecovery,
                        "test",
                    ),
                    VaultSealProviderEvidence::configured(
                        "certificate",
                        VaultSealProviderKind::CertificateWrapped,
                        "test",
                    ),
                ],
            )),
        };

        let decision = evaluate_policy(&envelope, &context);

        match decision {
            OpsPolicyDecision::Challenge {
                required_actions, ..
            } => {
                assert!(required_actions.contains(&"fresh_operator_proof".to_string()));
            }
            other => panic!("expected challenge, got {other:?}"),
        }
    }

    #[test]
    fn federal_certificate_unlock_requires_seal_posture_evidence() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Cli,
            OpsProfile::FederalReady,
            OpsCommand::VaultUnlock {
                method: VaultUnlockMethod::CertificateWrapped,
            },
        );
        let context = OpsPolicyContext {
            profile: OpsProfile::FederalReady,
            audit_sink_required: true,
            audit_sink_available: true,
            crypto_provider: FederalCryptoProviderEvidence::confirmed_for_tests(
                "CMVP test certificate",
            ),
            seal_posture: None,
        };

        let decision = evaluate_policy(&envelope, &context);

        match decision {
            OpsPolicyDecision::Deny {
                missing_controls, ..
            } => {
                assert!(missing_controls.contains(&"seal_posture_evidence".to_string()));
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn federal_policy_denies_non_federal_unlock_methods() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Cli,
            OpsProfile::FederalReady,
            OpsCommand::VaultUnlock {
                method: VaultUnlockMethod::MnemonicRecovery,
            },
        );
        let context = OpsPolicyContext {
            profile: OpsProfile::FederalReady,
            audit_sink_required: true,
            audit_sink_available: true,
            crypto_provider: FederalCryptoProviderEvidence::confirmed_for_tests(
                "CMVP test certificate",
            ),
            seal_posture: None,
        };

        let decision = evaluate_policy(&envelope, &context);

        match decision {
            OpsPolicyDecision::Deny {
                missing_controls, ..
            } => {
                assert!(
                    missing_controls
                        .iter()
                        .any(|control| control == "non_federal_unlock_method:mnemonic_recovery")
                );
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn device_bound_unlock_requires_available_auto_unseal_provider() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Cli,
            OpsProfile::Default,
            OpsCommand::VaultUnlock {
                method: VaultUnlockMethod::DeviceBound,
            },
        );
        let context = OpsPolicyContext {
            profile: OpsProfile::Default,
            audit_sink_required: false,
            audit_sink_available: false,
            crypto_provider: FederalCryptoProviderEvidence::confirmed_for_tests(
                "CMVP test certificate",
            ),
            seal_posture: Some(VaultSealPosture::from_providers(
                VaultSealState::Sealed,
                vec![
                    VaultSealProviderEvidence::configured(
                        "password",
                        VaultSealProviderKind::PasswordRecovery,
                        "test",
                    ),
                    VaultSealProviderEvidence::configured(
                        "device",
                        VaultSealProviderKind::DeviceBound,
                        "test",
                    ),
                ],
            )),
        };

        let decision = evaluate_policy(&envelope, &context);

        match decision {
            OpsPolicyDecision::Deny {
                missing_controls, ..
            } => {
                assert_eq!(
                    missing_controls,
                    vec!["auto_unseal_provider_available".to_string()]
                );
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn device_bound_unlock_requires_seal_posture_evidence() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Cli,
            OpsProfile::Default,
            OpsCommand::VaultUnlock {
                method: VaultUnlockMethod::DeviceBound,
            },
        );
        let context = OpsPolicyContext {
            profile: OpsProfile::Default,
            audit_sink_required: false,
            audit_sink_available: false,
            crypto_provider: FederalCryptoProviderEvidence::confirmed_for_tests(
                "CMVP test certificate",
            ),
            seal_posture: None,
        };

        let decision = evaluate_policy(&envelope, &context);

        match decision {
            OpsPolicyDecision::Deny {
                missing_controls, ..
            } => {
                assert_eq!(missing_controls, vec!["seal_posture_evidence".to_string()]);
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn mtls_process_boundary_requires_authenticated_transport_evidence() {
        let mut envelope = OpsCommandEnvelope::local(
            AuditSurface::Ops,
            OpsProfile::Default,
            OpsCommand::VaultOperation {
                name: "export".to_string(),
                access: VaultOperationAccess::Export,
            },
        );
        envelope.session.transport = OpsTransport::Mtls;

        let context = OpsPolicyContext {
            profile: OpsProfile::Default,
            audit_sink_required: false,
            audit_sink_available: false,
            crypto_provider: FederalCryptoProviderEvidence::confirmed_for_tests(
                "CMVP test certificate",
            ),
            seal_posture: None,
        };

        let decision = evaluate_policy(&envelope, &context);

        match decision {
            OpsPolicyDecision::Deny {
                missing_controls, ..
            } => {
                assert_eq!(
                    missing_controls,
                    vec!["mtls_transport_evidence".to_string()]
                );
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn authenticated_mtls_process_boundary_records_non_secret_evidence() {
        let envelope = OpsCommandEnvelope {
            schema_version: OPS_SCHEMA_VERSION,
            request_id: "pp.test.request.mtls".to_string(),
            operation_id: "pp.test.operation.mtls".to_string(),
            profile: OpsProfile::Default,
            actor: OpsActor {
                actor_id: "external_assessor".to_string(),
                kind: OpsActorKind::ServiceAccount,
            },
            session: OpsSession::mtls(
                AuditSurface::Ops,
                "pp.test.session.mtls",
                mtls_test_evidence(),
            ),
            command: OpsCommand::VaultOperation {
                name: "export".to_string(),
                access: VaultOperationAccess::Export,
            },
        };
        let context = OpsPolicyContext {
            profile: OpsProfile::Default,
            audit_sink_required: false,
            audit_sink_available: false,
            crypto_provider: FederalCryptoProviderEvidence::confirmed_for_tests(
                "CMVP test certificate",
            ),
            seal_posture: None,
        };

        let evaluation = evaluate_ops_command_envelope(envelope, &context);

        assert!(evaluation.is_allowed());
        assert!(evaluation.audit_events.iter().all(|event| {
            event
                .attributes
                .get("session_transport")
                .is_some_and(|transport| transport == "mtls")
        }));
        assert!(evaluation.audit_events.iter().all(|event| {
            event
                .attributes
                .get("transport_peer_identity")
                .is_some_and(|identity| identity == "spiffe://example.test/paranoid-assessor")
        }));
        assert!(evaluation.audit_events.iter().all(|event| {
            event
                .attributes
                .get("transport_channel_binding_sha256")
                .is_some_and(|channel_binding| {
                    channel_binding
                        == "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                })
        }));
        assert!(!evaluation.audit_events.iter().any(|event| {
            event
                .attributes
                .keys()
                .any(|attribute| attribute.contains("private_key") || attribute.contains("secret"))
        }));
    }

    #[test]
    fn unauthenticated_mtls_process_boundary_records_transport_warnings() {
        let envelope = OpsCommandEnvelope {
            schema_version: OPS_SCHEMA_VERSION,
            request_id: "pp.test.request.mtls_unverified".to_string(),
            operation_id: "pp.test.operation.mtls_unverified".to_string(),
            profile: OpsProfile::Default,
            actor: OpsActor {
                actor_id: "external_assessor".to_string(),
                kind: OpsActorKind::ServiceAccount,
            },
            session: OpsSession {
                session_id: "pp.test.session.mtls_unverified".to_string(),
                surface: AuditSurface::Ops,
                transport: OpsTransport::Mtls,
                transport_evidence: Some(OpsTransportEvidence::unauthenticated_mtls(
                    "spiffe://example.test/paranoid-assessor",
                    "fixture-mtls-handshake",
                    "client certificate was not verified",
                )),
            },
            command: OpsCommand::VaultOperation {
                name: "export".to_string(),
                access: VaultOperationAccess::Export,
            },
        };
        let context = OpsPolicyContext {
            profile: OpsProfile::Default,
            audit_sink_required: false,
            audit_sink_available: false,
            crypto_provider: FederalCryptoProviderEvidence::confirmed_for_tests(
                "CMVP test certificate",
            ),
            seal_posture: None,
        };

        let evaluation = evaluate_ops_command_envelope(envelope, &context);

        assert!(!evaluation.is_allowed());
        assert!(evaluation.audit_events.iter().all(|event| {
            event
                .attributes
                .get("transport_warnings")
                .is_some_and(|warnings| warnings == "client certificate was not verified")
        }));
    }

    #[test]
    fn ops_request_and_response_events_share_request_id() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Cli,
            OpsProfile::Default,
            OpsCommand::VaultSealStatus {
                probe_providers: false,
            },
        );
        let decision = OpsPolicyDecision::Allow {
            reason: "test".to_string(),
        };
        let mut trail = AuditTrail::for_operation(envelope.operation_id.clone());

        record_ops_request(&mut trail, &envelope);
        record_ops_response(&mut trail, &envelope, &decision);

        assert_eq!(trail.events().len(), 2);
        assert_eq!(
            trail.events()[0].attributes.get("request_id"),
            Some(&envelope.request_id)
        );
        assert_eq!(
            trail.events()[1].attributes.get("request_id"),
            Some(&envelope.request_id)
        );
        assert_eq!(
            trail.events()[1]
                .attributes
                .get("decision")
                .map(String::as_str),
            Some("allow")
        );
    }

    #[test]
    fn vault_operation_events_include_operation_and_access_metadata() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Vault,
            OpsProfile::Default,
            OpsCommand::VaultOperation {
                name: "mutate_item".to_string(),
                access: VaultOperationAccess::Mutate,
            },
        );
        let decision = OpsPolicyDecision::Allow {
            reason: "test".to_string(),
        };
        let mut trail = AuditTrail::for_operation(envelope.operation_id.clone());

        record_ops_request(&mut trail, &envelope);
        record_ops_response(&mut trail, &envelope, &decision);

        assert_eq!(
            trail.events()[0]
                .attributes
                .get("vault_operation")
                .map(String::as_str),
            Some("mutate_item")
        );
        assert_eq!(
            trail.events()[0]
                .attributes
                .get("vault_access")
                .map(String::as_str),
            Some("mutate")
        );
        assert_eq!(
            trail.events()[1]
                .attributes
                .get("vault_operation")
                .map(String::as_str),
            Some("mutate_item")
        );
    }

    #[test]
    fn vault_seal_status_events_include_probe_provider_metadata() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Vault,
            OpsProfile::Default,
            OpsCommand::VaultSealStatus {
                probe_providers: true,
            },
        );
        let decision = OpsPolicyDecision::Allow {
            reason: "test".to_string(),
        };
        let mut trail = AuditTrail::for_operation(envelope.operation_id.clone());

        record_ops_request(&mut trail, &envelope);
        record_ops_response(&mut trail, &envelope, &decision);

        assert_eq!(
            trail.events()[0]
                .attributes
                .get("probe_providers")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            trail.events()[1]
                .attributes
                .get("probe_providers")
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn vault_unlock_events_include_unlock_method_metadata() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Vault,
            OpsProfile::Default,
            OpsCommand::VaultUnlock {
                method: VaultUnlockMethod::DeviceBound,
            },
        );
        let decision = OpsPolicyDecision::Allow {
            reason: "test".to_string(),
        };
        let mut trail = AuditTrail::for_operation(envelope.operation_id.clone());

        record_ops_request(&mut trail, &envelope);
        record_ops_response(&mut trail, &envelope, &decision);

        assert_eq!(
            trail.events()[0]
                .attributes
                .get("unlock_method")
                .map(String::as_str),
            Some("device_bound")
        );
        assert_eq!(
            trail.events()[1]
                .attributes
                .get("unlock_method")
                .map(String::as_str),
            Some("device_bound")
        );
    }

    #[test]
    fn evaluate_vault_operation_returns_policy_decision_and_audit_events() {
        let context = OpsPolicyContext {
            profile: OpsProfile::Default,
            audit_sink_required: false,
            audit_sink_available: false,
            crypto_provider: FederalCryptoProviderEvidence::collect_from_environment(),
            seal_posture: None,
        };

        let evaluation = evaluate_vault_operation(
            AuditSurface::Gui,
            "mutate_item",
            VaultOperationAccess::Mutate,
            &context,
        );

        assert!(evaluation.is_allowed());
        assert_eq!(evaluation.envelope.session.surface, AuditSurface::Gui);
        assert_eq!(evaluation.envelope.profile, OpsProfile::Default);
        assert_eq!(evaluation.audit_events.len(), 2);
        assert_eq!(evaluation.audit_events[0].action, "vault_operation.request");
        assert_eq!(
            evaluation.audit_events[0]
                .attributes
                .get("session_surface")
                .map(String::as_str),
            Some("gui")
        );
        assert_eq!(
            evaluation.audit_events[0]
                .attributes
                .get("session_transport")
                .map(String::as_str),
            Some("in_process")
        );
        assert_eq!(
            evaluation.audit_events[1]
                .attributes
                .get("decision")
                .map(String::as_str),
            Some("allow")
        );
        assert_eq!(
            evaluation.audit_events[1]
                .attributes
                .get("session_surface")
                .map(String::as_str),
            Some("gui")
        );
    }

    fn mtls_test_evidence() -> OpsTransportEvidence {
        OpsTransportEvidence::authenticated_mtls(
            "spiffe://example.test/paranoid-assessor",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "fixture-mtls-handshake",
        )
        .with_channel_binding_sha256(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )
    }

    #[test]
    fn seal_machine_models_idle_timeout_and_reunlock() {
        let mut seal = VaultSealMachine::default();

        assert_eq!(seal.state(), VaultSealState::Sealed);
        seal.apply(VaultSealEvent::UnlockRequested)
            .expect("unlock request");
        seal.apply(VaultSealEvent::ChallengeSatisfied)
            .expect("challenge satisfied");
        assert_eq!(seal.state(), VaultSealState::Unsealed);
        seal.apply(VaultSealEvent::IdleTimeoutStarted)
            .expect("idle start");
        assert_eq!(seal.state(), VaultSealState::IdleLockPending);
        seal.apply(VaultSealEvent::IdleTimeoutExpired)
            .expect("idle expired");
        assert_eq!(seal.state(), VaultSealState::SealedAfterTimeout);
        seal.apply(VaultSealEvent::UnlockRequested)
            .expect("unlock after timeout");
        assert_eq!(seal.state(), VaultSealState::ChallengePending);
    }

    #[test]
    fn federal_startup_evidence_reports_denied_default_runtime() {
        let evidence = collect_federal_startup_evidence_from_input(FederalStartupEvidenceInput {
            profile: OpsProfile::FederalReady,
            product_version: "test-version".to_string(),
            build_commit: "test-commit".to_string(),
            build_date: "test-date".to_string(),
            operating_system: "linux".to_string(),
            architecture: "amd64".to_string(),
            audit_sink: AuditSinkHealth::not_configured_jsonl(),
            external_audit_device: AuditSinkHealth::not_configured_external_device(),
            crypto_provider: FederalCryptoProviderEvidence {
                provider_name: "OpenSSL".to_string(),
                provider_version: "OpenSSL test provider".to_string(),
                provider_platform: "test-platform".to_string(),
                approved_mode: FederalApprovedMode::NotConfirmed,
                certificate_reference: None,
                evidence_source: "test".to_string(),
            },
        });

        assert_eq!(
            evidence.schema_version,
            FEDERAL_STARTUP_EVIDENCE_SCHEMA_VERSION
        );
        assert_eq!(evidence.profile, OpsProfile::FederalReady);
        assert_eq!(evidence.audit_schema_version, AUDIT_SCHEMA_VERSION);
        assert_eq!(
            evidence.external_audit_device,
            AuditSinkHealth::not_configured_external_device()
        );
        assert!(matches!(
            evidence.policy_decision,
            OpsPolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn unverified_external_audit_device_does_not_satisfy_required_audit_control() {
        let evidence = collect_federal_startup_evidence_from_input(FederalStartupEvidenceInput {
            profile: OpsProfile::FederalReady,
            product_version: "test-version".to_string(),
            build_commit: "test-commit".to_string(),
            build_date: "test-date".to_string(),
            operating_system: "linux".to_string(),
            architecture: "amd64".to_string(),
            audit_sink: AuditSinkHealth::not_configured_jsonl(),
            external_audit_device: AuditSinkHealth::unverified_external_device(
                "siem-primary",
                "mtls://audit.example.invalid:6514",
                "live tcp-connect probe reached endpoint; audit write acknowledgement is not implemented",
            ),
            crypto_provider: FederalCryptoProviderEvidence::confirmed_for_tests(
                "CMVP test certificate",
            ),
        });

        match evidence.policy_decision {
            OpsPolicyDecision::Deny {
                missing_controls, ..
            } => {
                assert_eq!(missing_controls, vec!["required_audit_sink".to_string()]);
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn ready_external_audit_device_can_satisfy_required_audit_control() {
        let evidence = collect_federal_startup_evidence_from_input(FederalStartupEvidenceInput {
            profile: OpsProfile::FederalReady,
            product_version: "test-version".to_string(),
            build_commit: "test-commit".to_string(),
            build_date: "test-date".to_string(),
            operating_system: "linux".to_string(),
            architecture: "amd64".to_string(),
            audit_sink: AuditSinkHealth::not_configured_jsonl(),
            external_audit_device: AuditSinkHealth::ready_external_device(
                "siem-primary",
                "mtls://audit.example.invalid:6514",
                "test",
            ),
            crypto_provider: FederalCryptoProviderEvidence::confirmed_for_tests(
                "CMVP test certificate",
            ),
        });

        assert!(matches!(
            evidence.policy_decision,
            OpsPolicyDecision::Allow { .. }
        ));
    }
}
