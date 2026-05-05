use paranoid_audit::{
    AUDIT_SCHEMA_VERSION, AuditEvent, AuditOutcome, AuditSeverity, AuditSinkHealth, AuditSubject,
    AuditSurface, AuditTrail,
};
use paranoid_core::{AuditStage, AuditSummary, GenerationReport, ParanoidError, ParanoidRequest};
use serde::{Deserialize, Serialize};
use std::{
    env, process,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

static LOCAL_OPERATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub const OPS_SCHEMA_VERSION: u16 = 1;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsSession {
    pub session_id: String,
    pub surface: AuditSurface,
    pub transport: OpsTransport,
}

impl OpsSession {
    pub fn local(surface: AuditSurface) -> Self {
        Self {
            session_id: new_local_operation_id(),
            surface,
            transport: OpsTransport::InProcess,
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
    VaultSealStatus,
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
            Self::VaultSealStatus => "vault_seal_status",
            Self::VaultUnlock { .. } => "vault_unlock",
            Self::VaultOperation { .. } => "vault_operation",
            Self::FederalEvidence => "federal_evidence",
        }
    }

    pub fn subject(&self) -> AuditSubject {
        match self {
            Self::GeneratePassword => AuditSubject::PasswordGeneration,
            Self::VaultSealStatus | Self::VaultUnlock { .. } | Self::VaultOperation { .. } => {
                AuditSubject::VaultOperation
            }
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
            Self::VaultSealStatus | Self::FederalEvidence => false,
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
}

impl OpsPolicyContext {
    pub fn default_local() -> Self {
        Self {
            profile: OpsProfile::Default,
            audit_sink_required: false,
            audit_sink_available: false,
            crypto_provider: FederalCryptoProviderEvidence::collect_from_environment(),
        }
    }

    pub fn federal_ready(audit_sink_available: bool) -> Self {
        Self {
            profile: OpsProfile::FederalReady,
            audit_sink_required: true,
            audit_sink_available,
            crypto_provider: FederalCryptoProviderEvidence::collect_from_environment(),
        }
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

    if profile == OpsProfile::Default {
        if missing_controls.is_empty() {
            return OpsPolicyDecision::Allow {
                reason: "default profile permits local in-process operation".to_string(),
            };
        }
        return OpsPolicyDecision::Deny {
            reason: "required audit controls are missing".to_string(),
            missing_controls,
        };
    }

    if envelope.command.requires_fips_evidence()
        && context.crypto_provider.approved_mode != FederalApprovedMode::Confirmed
    {
        missing_controls.push("fips_approved_mode".to_string());
    }
    if let OpsCommand::VaultUnlock { method } = envelope.command
        && !matches!(method, VaultUnlockMethod::CertificateWrapped)
    {
        missing_controls.push(format!("non_federal_unlock_method:{}", method.as_str()));
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
    event.attributes.insert(
        "session_surface".to_string(),
        envelope.session.surface.as_str().to_string(),
    );
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
    event.attributes.insert(
        "session_surface".to_string(),
        envelope.session.surface.as_str().to_string(),
    );
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
    event
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
}

// TODO: HUMAN_REVIEW - centralized policy boundary for ops/vault authorization and audit evidence across adapters.
pub fn evaluate_ops_command(
    surface: AuditSurface,
    command: OpsCommand,
    context: &OpsPolicyContext,
) -> OpsCommandEvaluation {
    let envelope = OpsCommandEnvelope::local(surface, context.profile, command);
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
    pub crypto_provider: FederalCryptoProviderEvidence,
    pub policy_decision: OpsPolicyDecision,
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
    let crypto_provider = FederalCryptoProviderEvidence::collect_from_environment();
    let context = OpsPolicyContext {
        profile,
        audit_sink_required: profile == OpsProfile::FederalReady,
        audit_sink_available: audit_sink.is_available(),
        crypto_provider: crypto_provider.clone(),
    };
    let envelope =
        OpsCommandEnvelope::local(AuditSurface::Cli, profile, OpsCommand::GeneratePassword);
    let policy_decision = evaluate_policy(&envelope, &context);
    FederalStartupEvidence {
        schema_version: OPS_SCHEMA_VERSION,
        profile,
        product_version: paranoid_core::VERSION.to_string(),
        build_commit: build_commit.into(),
        build_date: build_date.into(),
        operating_system: env::consts::OS.to_string(),
        architecture: env::consts::ARCH.to_string(),
        audit_schema_version: AUDIT_SCHEMA_VERSION,
        audit_sink,
        crypto_provider,
        policy_decision,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultSealState {
    Sealed,
    ChallengePending,
    Unsealed,
    IdleLockPending,
    SealedAfterTimeout,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultSealEvent {
    UnlockRequested,
    ChallengeIssued,
    ChallengeSatisfied,
    UnlockSucceeded,
    UnlockFailed,
    IdleTimeoutStarted,
    ActivityObserved,
    IdleTimeoutExpired,
    ManualLock,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSealTransition {
    pub from: VaultSealState,
    pub event: VaultSealEvent,
    pub to: VaultSealState,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid vault seal transition from {from:?} via {event:?}")]
pub struct VaultSealTransitionError {
    pub from: VaultSealState,
    pub event: VaultSealEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSealMachine {
    state: VaultSealState,
}

impl Default for VaultSealMachine {
    fn default() -> Self {
        Self {
            state: VaultSealState::Sealed,
        }
    }
}

impl VaultSealMachine {
    pub fn new(state: VaultSealState) -> Self {
        Self { state }
    }

    pub fn state(&self) -> VaultSealState {
        self.state
    }

    pub fn apply(
        &mut self,
        event: VaultSealEvent,
    ) -> Result<VaultSealTransition, VaultSealTransitionError> {
        let from = self.state;
        let to = self
            .next_state(event)
            .ok_or(VaultSealTransitionError { from, event })?;
        self.state = to;
        Ok(VaultSealTransition { from, event, to })
    }

    fn next_state(&self, event: VaultSealEvent) -> Option<VaultSealState> {
        match event {
            VaultSealEvent::RecoveryRequired => Some(VaultSealState::RecoveryRequired),
            VaultSealEvent::UnlockRequested => self.unlock_requested_transition(),
            VaultSealEvent::ChallengeIssued => self.challenge_issued_transition(),
            VaultSealEvent::ChallengeSatisfied | VaultSealEvent::UnlockSucceeded => {
                self.challenge_satisfied_transition()
            }
            VaultSealEvent::UnlockFailed => self.unlock_failed_transition(),
            VaultSealEvent::IdleTimeoutStarted => self.idle_timeout_started_transition(),
            VaultSealEvent::ActivityObserved => self.activity_observed_transition(),
            VaultSealEvent::IdleTimeoutExpired => self.idle_timeout_expired_transition(),
            VaultSealEvent::ManualLock => self.manual_lock_transition(),
        }
    }

    fn unlock_requested_transition(&self) -> Option<VaultSealState> {
        match self.state {
            VaultSealState::Sealed | VaultSealState::SealedAfterTimeout => {
                Some(VaultSealState::ChallengePending)
            }
            _ => None,
        }
    }

    fn challenge_issued_transition(&self) -> Option<VaultSealState> {
        match self.state {
            VaultSealState::ChallengePending => Some(VaultSealState::ChallengePending),
            _ => None,
        }
    }

    fn challenge_satisfied_transition(&self) -> Option<VaultSealState> {
        match self.state {
            VaultSealState::ChallengePending => Some(VaultSealState::Unsealed),
            _ => None,
        }
    }

    fn unlock_failed_transition(&self) -> Option<VaultSealState> {
        match self.state {
            VaultSealState::ChallengePending => Some(VaultSealState::Sealed),
            _ => None,
        }
    }

    fn idle_timeout_started_transition(&self) -> Option<VaultSealState> {
        match self.state {
            VaultSealState::Unsealed => Some(VaultSealState::IdleLockPending),
            _ => None,
        }
    }

    fn activity_observed_transition(&self) -> Option<VaultSealState> {
        match self.state {
            VaultSealState::IdleLockPending => Some(VaultSealState::Unsealed),
            _ => None,
        }
    }

    fn idle_timeout_expired_transition(&self) -> Option<VaultSealState> {
        match self.state {
            VaultSealState::IdleLockPending => Some(VaultSealState::SealedAfterTimeout),
            _ => None,
        }
    }

    fn manual_lock_transition(&self) -> Option<VaultSealState> {
        match self.state {
            VaultSealState::Unsealed | VaultSealState::IdleLockPending => {
                Some(VaultSealState::Sealed)
            }
            _ => None,
        }
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
    fn ops_request_and_response_events_share_request_id() {
        let envelope = OpsCommandEnvelope::local(
            AuditSurface::Cli,
            OpsProfile::Default,
            OpsCommand::VaultSealStatus,
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
    fn evaluate_vault_operation_returns_policy_decision_and_audit_events() {
        let context = OpsPolicyContext {
            profile: OpsProfile::Default,
            audit_sink_required: false,
            audit_sink_available: false,
            crypto_provider: FederalCryptoProviderEvidence::collect_from_environment(),
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
        let evidence = collect_federal_startup_evidence(
            OpsProfile::FederalReady,
            false,
            "test-commit",
            "test-date",
        );

        assert_eq!(evidence.profile, OpsProfile::FederalReady);
        assert_eq!(evidence.audit_schema_version, AUDIT_SCHEMA_VERSION);
        assert!(matches!(
            evidence.policy_decision,
            OpsPolicyDecision::Deny { .. }
        ));
    }
}
