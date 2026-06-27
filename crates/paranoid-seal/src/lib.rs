use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SEAL_SCHEMA_VERSION: u16 = 1;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultSealProviderKind {
    PasswordRecovery,
    MnemonicRecovery,
    DeviceBound,
    CertificateWrapped,
    ExternalAutoUnseal,
}

impl VaultSealProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PasswordRecovery => "password_recovery",
            Self::MnemonicRecovery => "mnemonic_recovery",
            Self::DeviceBound => "device_bound",
            Self::CertificateWrapped => "certificate_wrapped",
            Self::ExternalAutoUnseal => "external_auto_unseal",
        }
    }

    pub fn is_operator_recovery(self) -> bool {
        matches!(self, Self::PasswordRecovery | Self::MnemonicRecovery)
    }

    pub fn is_certificate_unseal(self) -> bool {
        matches!(self, Self::CertificateWrapped)
    }

    pub fn is_auto_unseal(self) -> bool {
        matches!(self, Self::DeviceBound | Self::ExternalAutoUnseal)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultSealProviderStatus {
    Configured,
    Available,
    Unavailable,
    Disabled,
}

impl VaultSealProviderStatus {
    pub fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSealProviderEvidence {
    pub schema_version: u16,
    pub provider_id: String,
    pub kind: VaultSealProviderKind,
    pub status: VaultSealProviderStatus,
    pub evidence_source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl VaultSealProviderEvidence {
    pub fn configured(
        provider_id: impl Into<String>,
        kind: VaultSealProviderKind,
        evidence_source: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SEAL_SCHEMA_VERSION,
            provider_id: provider_id.into(),
            kind,
            status: VaultSealProviderStatus::Configured,
            evidence_source: evidence_source.into(),
            warnings: Vec::new(),
        }
    }

    pub fn available(
        provider_id: impl Into<String>,
        kind: VaultSealProviderKind,
        evidence_source: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SEAL_SCHEMA_VERSION,
            provider_id: provider_id.into(),
            kind,
            status: VaultSealProviderStatus::Available,
            evidence_source: evidence_source.into(),
            warnings: Vec::new(),
        }
    }

    pub fn unavailable(
        provider_id: impl Into<String>,
        kind: VaultSealProviderKind,
        evidence_source: impl Into<String>,
        warning: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SEAL_SCHEMA_VERSION,
            provider_id: provider_id.into(),
            kind,
            status: VaultSealProviderStatus::Unavailable,
            evidence_source: evidence_source.into(),
            warnings: vec![warning.into()],
        }
    }

    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }
}

// Dispositioned in docs/reference/ai-review.md: this is non-secret posture evidence,
// not authorization or decrypted vault state, and provider availability is explicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSealPosture {
    pub schema_version: u16,
    pub state: VaultSealState,
    pub recovery_required: bool,
    pub operator_recovery_configured: bool,
    pub certificate_unseal_configured: bool,
    pub auto_unseal_configured: bool,
    pub auto_unseal_available: bool,
    pub provider_count: usize,
    pub providers: Vec<VaultSealProviderEvidence>,
}

impl VaultSealPosture {
    pub fn from_providers(
        state: VaultSealState,
        providers: Vec<VaultSealProviderEvidence>,
    ) -> Self {
        let operator_recovery_configured = providers
            .iter()
            .any(|provider| provider.kind.is_operator_recovery());
        let certificate_unseal_configured = providers
            .iter()
            .any(|provider| provider.kind.is_certificate_unseal());
        let auto_unseal_configured = providers
            .iter()
            .any(|provider| provider.kind.is_auto_unseal());
        let auto_unseal_available = providers
            .iter()
            .any(|provider| provider.kind.is_auto_unseal() && provider.status.is_available());

        Self {
            schema_version: SEAL_SCHEMA_VERSION,
            state,
            recovery_required: state == VaultSealState::RecoveryRequired
                || !operator_recovery_configured,
            operator_recovery_configured,
            certificate_unseal_configured,
            auto_unseal_configured,
            auto_unseal_available,
            provider_count: providers.len(),
            providers,
        }
    }

    pub fn has_configured_provider(&self, kind: VaultSealProviderKind) -> bool {
        self.providers.iter().any(|provider| {
            provider.kind == kind && provider.status != VaultSealProviderStatus::Disabled
        })
    }

    pub fn has_available_provider(&self, kind: VaultSealProviderKind) -> bool {
        self.providers
            .iter()
            .any(|provider| provider.kind == kind && provider.status.is_available())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_machine_models_idle_timeout_and_reunlock() {
        let mut seal = VaultSealMachine::default();

        assert_eq!(seal.state(), VaultSealState::Sealed);
        seal.apply(VaultSealEvent::UnlockRequested)
            .expect("unlock requested");
        seal.apply(VaultSealEvent::ChallengeSatisfied)
            .expect("challenge satisfied");
        assert_eq!(seal.state(), VaultSealState::Unsealed);
        seal.apply(VaultSealEvent::IdleTimeoutStarted)
            .expect("idle timeout started");
        assert_eq!(seal.state(), VaultSealState::IdleLockPending);
        seal.apply(VaultSealEvent::IdleTimeoutExpired)
            .expect("idle timeout expired");
        assert_eq!(seal.state(), VaultSealState::SealedAfterTimeout);
        seal.apply(VaultSealEvent::UnlockRequested)
            .expect("reunlock requested");
        assert_eq!(seal.state(), VaultSealState::ChallengePending);
    }

    #[test]
    fn seal_machine_rejects_invalid_transition() {
        let mut seal = VaultSealMachine::default();

        let error = seal
            .apply(VaultSealEvent::IdleTimeoutStarted)
            .expect_err("sealed vault cannot start idle timeout");

        assert_eq!(error.from, VaultSealState::Sealed);
        assert_eq!(error.event, VaultSealEvent::IdleTimeoutStarted);
        assert_eq!(seal.state(), VaultSealState::Sealed);
    }

    #[test]
    fn recovery_required_overrides_current_state() {
        let mut seal = VaultSealMachine::new(VaultSealState::Unsealed);

        let transition = seal
            .apply(VaultSealEvent::RecoveryRequired)
            .expect("recovery transition");

        assert_eq!(transition.from, VaultSealState::Unsealed);
        assert_eq!(transition.to, VaultSealState::RecoveryRequired);
        assert_eq!(seal.state(), VaultSealState::RecoveryRequired);
    }

    #[test]
    fn posture_reports_configured_recovery_and_auto_unseal_without_claiming_availability() {
        let posture = VaultSealPosture::from_providers(
            VaultSealState::Sealed,
            vec![
                VaultSealProviderEvidence::configured(
                    "password",
                    VaultSealProviderKind::PasswordRecovery,
                    "vault_header",
                ),
                VaultSealProviderEvidence::configured(
                    "device",
                    VaultSealProviderKind::DeviceBound,
                    "vault_header",
                ),
            ],
        );

        assert!(!posture.recovery_required);
        assert!(posture.operator_recovery_configured);
        assert!(posture.auto_unseal_configured);
        assert!(!posture.auto_unseal_available);
        assert!(posture.has_configured_provider(VaultSealProviderKind::PasswordRecovery));
        assert!(posture.has_configured_provider(VaultSealProviderKind::DeviceBound));
        assert!(!posture.has_available_provider(VaultSealProviderKind::DeviceBound));
        assert_eq!(posture.provider_count, 2);
    }

    #[test]
    fn posture_reports_confirmed_auto_unseal_availability() {
        let posture = VaultSealPosture::from_providers(
            VaultSealState::Sealed,
            vec![
                VaultSealProviderEvidence::configured(
                    "password",
                    VaultSealProviderKind::PasswordRecovery,
                    "vault_header",
                ),
                VaultSealProviderEvidence::available(
                    "device",
                    VaultSealProviderKind::DeviceBound,
                    "provider_health_check",
                ),
            ],
        );

        assert!(posture.auto_unseal_available);
        assert!(posture.has_available_provider(VaultSealProviderKind::DeviceBound));
        assert!(!posture.has_available_provider(VaultSealProviderKind::ExternalAutoUnseal));
    }

    #[test]
    fn posture_requires_operator_recovery_when_only_auto_unseal_exists() {
        let posture = VaultSealPosture::from_providers(
            VaultSealState::Sealed,
            vec![VaultSealProviderEvidence::available(
                "device",
                VaultSealProviderKind::DeviceBound,
                "provider_health_check",
            )],
        );

        assert!(posture.recovery_required);
        assert!(!posture.operator_recovery_configured);
    }

    #[test]
    fn posture_reports_certificate_configuration_without_claiming_auto_unseal() {
        let posture = VaultSealPosture::from_providers(
            VaultSealState::Sealed,
            vec![
                VaultSealProviderEvidence::configured(
                    "password",
                    VaultSealProviderKind::PasswordRecovery,
                    "vault_header",
                ),
                VaultSealProviderEvidence::configured(
                    "certificate",
                    VaultSealProviderKind::CertificateWrapped,
                    "vault_header",
                ),
            ],
        );

        assert!(posture.certificate_unseal_configured);
        assert!(!posture.auto_unseal_configured);
        assert!(!posture.auto_unseal_available);
        assert!(posture.has_configured_provider(VaultSealProviderKind::CertificateWrapped));
        assert!(!posture.has_available_provider(VaultSealProviderKind::CertificateWrapped));
    }

    #[test]
    fn posture_keeps_provider_availability_method_specific() {
        let posture = VaultSealPosture::from_providers(
            VaultSealState::Sealed,
            vec![
                VaultSealProviderEvidence::configured(
                    "device",
                    VaultSealProviderKind::DeviceBound,
                    "vault_header",
                ),
                VaultSealProviderEvidence::available(
                    "external",
                    VaultSealProviderKind::ExternalAutoUnseal,
                    "external_probe",
                ),
            ],
        );

        assert!(posture.auto_unseal_available);
        assert!(posture.has_available_provider(VaultSealProviderKind::ExternalAutoUnseal));
        assert!(!posture.has_available_provider(VaultSealProviderKind::DeviceBound));
    }

    #[test]
    fn recovery_required_state_remains_required_with_recovery_provider() {
        let posture = VaultSealPosture::from_providers(
            VaultSealState::RecoveryRequired,
            vec![VaultSealProviderEvidence::configured(
                "password",
                VaultSealProviderKind::PasswordRecovery,
                "vault_header",
            )],
        );

        assert!(posture.operator_recovery_configured);
        assert!(posture.recovery_required);
    }

    #[test]
    fn vault_seal_state_round_trips_through_serde() {
        for state in [
            VaultSealState::Sealed,
            VaultSealState::ChallengePending,
            VaultSealState::Unsealed,
            VaultSealState::IdleLockPending,
            VaultSealState::SealedAfterTimeout,
            VaultSealState::RecoveryRequired,
        ] {
            let json = serde_json::to_string(&state).expect("serialize state");
            let deserialized: VaultSealState =
                serde_json::from_str(&json).expect("deserialize state");
            assert_eq!(deserialized, state);
        }
    }

    #[test]
    fn vault_seal_event_round_trips_through_serde() {
        for event in [
            VaultSealEvent::UnlockRequested,
            VaultSealEvent::ChallengeIssued,
            VaultSealEvent::ChallengeSatisfied,
            VaultSealEvent::UnlockSucceeded,
            VaultSealEvent::UnlockFailed,
            VaultSealEvent::IdleTimeoutStarted,
            VaultSealEvent::ActivityObserved,
            VaultSealEvent::IdleTimeoutExpired,
            VaultSealEvent::ManualLock,
            VaultSealEvent::RecoveryRequired,
        ] {
            let json = serde_json::to_string(&event).expect("serialize event");
            let deserialized: VaultSealEvent =
                serde_json::from_str(&json).expect("deserialize event");
            assert_eq!(deserialized, event);
        }
    }

    #[test]
    fn vault_seal_transition_round_trips_through_serde() {
        let transition = VaultSealTransition {
            from: VaultSealState::Sealed,
            event: VaultSealEvent::UnlockRequested,
            to: VaultSealState::ChallengePending,
        };
        let json = serde_json::to_string(&transition).expect("serialize transition");
        let deserialized: VaultSealTransition =
            serde_json::from_str(&json).expect("deserialize transition");
        assert_eq!(deserialized, transition);
    }

    #[test]
    fn vault_seal_provider_evidence_round_trips_through_serde() {
        let evidence = VaultSealProviderEvidence::configured(
            "password",
            VaultSealProviderKind::PasswordRecovery,
            "vault_header",
        );
        let json = serde_json::to_string(&evidence).expect("serialize evidence");
        let deserialized: VaultSealProviderEvidence =
            serde_json::from_str(&json).expect("deserialize evidence");
        assert_eq!(deserialized, evidence);
    }

    #[test]
    fn vault_seal_posture_round_trips_through_serde() {
        let posture = VaultSealPosture::from_providers(
            VaultSealState::Sealed,
            vec![
                VaultSealProviderEvidence::configured(
                    "password",
                    VaultSealProviderKind::PasswordRecovery,
                    "vault_header",
                ),
                VaultSealProviderEvidence::available(
                    "device",
                    VaultSealProviderKind::DeviceBound,
                    "provider_health_check",
                ),
            ],
        );
        let json = serde_json::to_string(&posture).expect("serialize posture");
        let deserialized: VaultSealPosture =
            serde_json::from_str(&json).expect("deserialize posture");
        assert_eq!(deserialized, posture);
    }

    #[test]
    fn provider_evidence_unavailable_carries_warning() {
        let evidence = VaultSealProviderEvidence::unavailable(
            "device",
            VaultSealProviderKind::DeviceBound,
            "provider_health_check",
            "keyring access denied",
        );
        assert_eq!(evidence.status, VaultSealProviderStatus::Unavailable);
        assert_eq!(evidence.warnings, vec!["keyring access denied".to_string()]);
    }

    #[test]
    fn provider_evidence_with_warnings_replaces_warnings() {
        let evidence = VaultSealProviderEvidence::configured(
            "cert",
            VaultSealProviderKind::CertificateWrapped,
            "vault_header",
        )
        .with_warnings(vec!["expiring soon".to_string()]);
        assert_eq!(evidence.warnings, vec!["expiring soon".to_string()]);
    }

    #[test]
    fn disabled_provider_excluded_from_configured_providers() {
        let posture = VaultSealPosture::from_providers(
            VaultSealState::Sealed,
            vec![
                VaultSealProviderEvidence {
                    schema_version: SEAL_SCHEMA_VERSION,
                    provider_id: "disabled".to_string(),
                    kind: VaultSealProviderKind::DeviceBound,
                    status: VaultSealProviderStatus::Disabled,
                    evidence_source: "operator_override".to_string(),
                    warnings: Vec::new(),
                },
                VaultSealProviderEvidence::configured(
                    "password",
                    VaultSealProviderKind::PasswordRecovery,
                    "vault_header",
                ),
            ],
        );
        assert!(!posture.has_configured_provider(VaultSealProviderKind::DeviceBound));
        assert!(posture.has_configured_provider(VaultSealProviderKind::PasswordRecovery));
    }
}
