use crate::{
    CERTIFICATE_EXPIRY_WARNING_DAYS, VaultError, VaultHeader, VaultKeyslot, VaultKeyslotKind,
    read_vault_header, read_verified_device_keyslot_secret,
};
use paranoid_seal::{
    VaultSealMachine, VaultSealPosture, VaultSealProviderEvidence, VaultSealProviderKind,
    VaultSealState,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultRecoveryPosture {
    pub password_recovery_slots: usize,
    pub mnemonic_recovery_slots: usize,
    pub device_bound_slots: usize,
    pub certificate_wrapped_slots: usize,
    pub has_recovery_path: bool,
    pub has_certificate_path: bool,
    pub meets_recommended_posture: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultKeyslotRemovalImpact {
    pub keyslot_id: String,
    pub keyslot_kind: VaultKeyslotKind,
    pub before: VaultRecoveryPosture,
    pub after: VaultRecoveryPosture,
    pub warnings: Vec<String>,
    pub requires_explicit_confirmation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultKeyslotHealth {
    pub keyslot_id: String,
    pub keyslot_kind: VaultKeyslotKind,
    pub warnings: Vec<String>,
    pub healthy: bool,
    #[serde(default)]
    pub provider_availability: VaultKeyslotProviderAvailability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_evidence_source: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VaultKeyslotProviderAvailability {
    #[default]
    NotChecked,
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VaultKeyslotProviderProbe {
    #[default]
    MetadataOnly,
    VerifyAvailability,
}

impl VaultKeyslotProviderProbe {
    fn verifies_availability(self) -> bool {
        matches!(self, Self::VerifyAvailability)
    }
}

fn recovery_posture_for_keyslots(keyslots: &[VaultKeyslot]) -> VaultRecoveryPosture {
    let mut password_recovery_slots = 0;
    let mut mnemonic_recovery_slots = 0;
    let mut device_bound_slots = 0;
    let mut certificate_wrapped_slots = 0;

    for keyslot in keyslots {
        match keyslot.kind {
            VaultKeyslotKind::PasswordRecovery => password_recovery_slots += 1,
            VaultKeyslotKind::MnemonicRecovery => mnemonic_recovery_slots += 1,
            VaultKeyslotKind::DeviceBound => device_bound_slots += 1,
            VaultKeyslotKind::CertificateWrapped => certificate_wrapped_slots += 1,
        }
    }

    let has_recovery_path = password_recovery_slots > 0 || mnemonic_recovery_slots > 0;
    let has_certificate_path = certificate_wrapped_slots > 0;

    VaultRecoveryPosture {
        password_recovery_slots,
        mnemonic_recovery_slots,
        device_bound_slots,
        certificate_wrapped_slots,
        has_recovery_path,
        has_certificate_path,
        meets_recommended_posture: has_recovery_path && has_certificate_path,
    }
}

pub(crate) fn keyslot_health_for_slot(
    keyslot: &VaultKeyslot,
    provider_probe: VaultKeyslotProviderProbe,
) -> VaultKeyslotHealth {
    let mut warnings = Vec::new();
    let mut provider_availability = VaultKeyslotProviderAvailability::NotChecked;
    let mut provider_evidence_source = None;

    if keyslot.kind == VaultKeyslotKind::CertificateWrapped {
        match (
            keyslot.certificate_not_before_epoch,
            keyslot.certificate_not_after_epoch,
        ) {
            (Some(not_before_epoch), Some(not_after_epoch)) => {
                warnings.extend(certificate_validity_warnings(
                    not_before_epoch,
                    not_after_epoch,
                ));
            }
            _ => warnings
                .push("Certificate lifecycle metadata is incomplete for this keyslot.".to_string()),
        }
        if keyslot.certificate_subject.is_none() {
            warnings.push("Certificate subject metadata is missing for this keyslot.".to_string());
        }
        if keyslot.certificate_fingerprint_sha256.is_none() {
            warnings
                .push("Certificate fingerprint metadata is missing for this keyslot.".to_string());
        }
    }

    if keyslot.kind == VaultKeyslotKind::DeviceBound {
        let mut metadata_missing = false;
        if keyslot.device_service.is_none() {
            warnings.push("Device-bound provider service metadata is missing.".to_string());
            metadata_missing = true;
        }
        if keyslot.device_account.is_none() {
            warnings.push("Device-bound provider account metadata is missing.".to_string());
            metadata_missing = true;
        }
        if provider_probe.verifies_availability() {
            provider_evidence_source = Some("device_provider_health_check".to_string());
            if metadata_missing {
                provider_availability = VaultKeyslotProviderAvailability::Unavailable;
            } else {
                match read_verified_device_keyslot_secret(keyslot) {
                    Ok(_) => provider_availability = VaultKeyslotProviderAvailability::Available,
                    Err(error) => {
                        provider_availability = VaultKeyslotProviderAvailability::Unavailable;
                        warnings.push(format!(
                            "Device-bound provider health check failed: {error}"
                        ));
                    }
                }
            }
        }
    }

    let healthy = warnings.is_empty();

    VaultKeyslotHealth {
        keyslot_id: keyslot.id.clone(),
        keyslot_kind: keyslot.kind.clone(),
        warnings,
        healthy,
        provider_availability,
        provider_evidence_source,
    }
}

pub(crate) fn certificate_validity_warnings(
    not_before_epoch: i64,
    not_after_epoch: i64,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default();
    let soon_epoch = now_epoch + i64::from(CERTIFICATE_EXPIRY_WARNING_DAYS) * 24 * 60 * 60;

    if not_before_epoch > now_epoch {
        warnings.push("Certificate is not yet valid.".to_string());
    }
    if not_after_epoch < now_epoch {
        warnings.push("Certificate has expired.".to_string());
    } else if not_after_epoch < soon_epoch {
        warnings.push(format!(
            "Certificate expires within {CERTIFICATE_EXPIRY_WARNING_DAYS} days."
        ));
    }
    warnings
}

pub(crate) fn seal_provider_evidence_for_health(
    keyslot: &VaultKeyslot,
    health: VaultKeyslotHealth,
) -> VaultSealProviderEvidence {
    let provider_kind = seal_provider_kind(&keyslot.kind);
    let evidence_source = health
        .provider_evidence_source
        .unwrap_or_else(|| "vault_header".to_string());
    match health.provider_availability {
        VaultKeyslotProviderAvailability::Available => {
            VaultSealProviderEvidence::available(keyslot.id.clone(), provider_kind, evidence_source)
                .with_warnings(health.warnings)
        }
        VaultKeyslotProviderAvailability::Unavailable => {
            let mut warnings = health.warnings;
            if warnings.is_empty() {
                warnings.push("Provider availability probe failed.".to_string());
            }
            VaultSealProviderEvidence::unavailable(
                keyslot.id.clone(),
                provider_kind,
                evidence_source,
                warnings[0].clone(),
            )
            .with_warnings(warnings)
        }
        VaultKeyslotProviderAvailability::NotChecked => VaultSealProviderEvidence::configured(
            keyslot.id.clone(),
            provider_kind,
            evidence_source,
        )
        .with_warnings(health.warnings),
    }
}

pub(crate) fn seal_provider_kind(kind: &VaultKeyslotKind) -> VaultSealProviderKind {
    match kind {
        VaultKeyslotKind::PasswordRecovery => VaultSealProviderKind::PasswordRecovery,
        VaultKeyslotKind::MnemonicRecovery => VaultSealProviderKind::MnemonicRecovery,
        VaultKeyslotKind::DeviceBound => VaultSealProviderKind::DeviceBound,
        VaultKeyslotKind::CertificateWrapped => VaultSealProviderKind::CertificateWrapped,
    }
}

impl VaultHeader {
    pub fn recovery_posture(&self) -> VaultRecoveryPosture {
        recovery_posture_for_keyslots(&self.keyslots)
    }

    pub fn recovery_recommendations(&self) -> Vec<String> {
        let posture = self.recovery_posture();
        let mut recommendations = Vec::new();

        if posture.mnemonic_recovery_slots == 0 {
            recommendations.push(
                "Enroll at least one mnemonic recovery slot for offline disaster recovery."
                    .to_string(),
            );
        }
        if posture.device_bound_slots == 0 {
            recommendations.push(
                "Enroll at least one device-bound slot for passwordless daily unlock.".to_string(),
            );
        }
        if !posture.has_certificate_path {
            recommendations.push(
                "Enroll at least one certificate-wrapped slot to keep certificate-based unwrap available."
                    .to_string(),
            );
        }

        recommendations
    }

    pub fn assess_keyslot_health(&self, id: &str) -> Result<VaultKeyslotHealth, VaultError> {
        self.assess_keyslot_health_with_provider_probe(id, VaultKeyslotProviderProbe::MetadataOnly)
    }

    pub fn assess_keyslot_health_with_provider_probe(
        &self,
        id: &str,
        provider_probe: VaultKeyslotProviderProbe,
    ) -> Result<VaultKeyslotHealth, VaultError> {
        let keyslot = self
            .keyslots
            .iter()
            .find(|slot| slot.id == id)
            .ok_or_else(|| VaultError::ItemNotFound(format!("keyslot {id}")))?;
        Ok(keyslot_health_for_slot(keyslot, provider_probe))
    }

    pub fn keyslot_health_summaries(&self) -> Vec<VaultKeyslotHealth> {
        self.keyslot_health_summaries_with_provider_probe(VaultKeyslotProviderProbe::MetadataOnly)
    }

    pub fn keyslot_health_summaries_with_provider_probe(
        &self,
        provider_probe: VaultKeyslotProviderProbe,
    ) -> Vec<VaultKeyslotHealth> {
        self.keyslots
            .iter()
            .map(|keyslot| keyslot_health_for_slot(keyslot, provider_probe))
            .collect()
    }

    /// Derives the vault's seal posture (`paranoid-seal` state plus per-keyslot
    /// provider evidence) directly from header/keyslot data, usable without
    /// unlocking the vault. This is the single production posture-derivation
    /// site; all callers (CLI, TUI, capability detection) go through this or
    /// through `seal_posture_for_path`.
    pub fn seal_posture(&self, provider_probe: VaultKeyslotProviderProbe) -> VaultSealPosture {
        let keyslot_health = self.keyslot_health_summaries_with_provider_probe(provider_probe);
        let mut health_by_id: HashMap<String, VaultKeyslotHealth> = keyslot_health
            .into_iter()
            .map(|health| (health.keyslot_id.clone(), health))
            .collect();
        let providers = self
            .keyslots
            .iter()
            .map(|keyslot| {
                let health =
                    health_by_id
                        .remove(&keyslot.id)
                        .unwrap_or_else(|| VaultKeyslotHealth {
                            keyslot_id: keyslot.id.clone(),
                            keyslot_kind: keyslot.kind.clone(),
                            warnings: vec![
                                "Vault keyslot health summary missing for provider.".to_string(),
                            ],
                            healthy: false,
                            provider_availability: VaultKeyslotProviderAvailability::Unavailable,
                            provider_evidence_source: Some("vault_header".to_string()),
                        });
                seal_provider_evidence_for_health(keyslot, health)
            })
            .collect();

        VaultSealPosture::from_providers(VaultSealMachine::default().state(), providers)
    }

    pub fn assess_keyslot_removal(
        &self,
        id: &str,
    ) -> Result<VaultKeyslotRemovalImpact, VaultError> {
        let index = self
            .keyslots
            .iter()
            .position(|slot| slot.id == id)
            .ok_or_else(|| VaultError::ItemNotFound(format!("keyslot {id}")))?;
        let keyslot = self.keyslots[index].clone();
        let before = self.recovery_posture();
        let after = if keyslot.kind == VaultKeyslotKind::PasswordRecovery {
            before.clone()
        } else {
            let mut projected = self.keyslots.clone();
            projected.remove(index);
            recovery_posture_for_keyslots(&projected)
        };

        let mut warnings = Vec::new();
        match keyslot.kind {
            VaultKeyslotKind::PasswordRecovery => {
                warnings.push("Password recovery keyslots cannot be removed.".to_string())
            }
            VaultKeyslotKind::MnemonicRecovery if after.mnemonic_recovery_slots == 0 => {
                warnings.push(
                    "This removes the last mnemonic recovery slot and leaves no wallet-style offline recovery phrase."
                        .to_string(),
                );
            }
            VaultKeyslotKind::DeviceBound if after.device_bound_slots == 0 => {
                warnings.push(
                    "This removes the last device-bound slot and disables passwordless daily unlock."
                        .to_string(),
                );
            }
            VaultKeyslotKind::CertificateWrapped if after.certificate_wrapped_slots == 0 => {
                warnings.push(
                    "This removes the last certificate-wrapped slot and disables certificate-based unwrap."
                        .to_string(),
                );
            }
            _ => {}
        }

        if before.meets_recommended_posture && !after.meets_recommended_posture {
            warnings.push(
                "This drops the vault below the recommended posture of keeping both recovery and certificate coverage."
                    .to_string(),
            );
        }
        if before.has_recovery_path && !after.has_recovery_path {
            warnings.push("This would leave the vault without any recovery path.".to_string());
        }
        if before.has_certificate_path && !after.has_certificate_path {
            warnings.push(
                "This would leave the vault without any certificate-backed unwrap path."
                    .to_string(),
            );
        }

        Ok(VaultKeyslotRemovalImpact {
            keyslot_id: keyslot.id,
            keyslot_kind: keyslot.kind,
            before,
            after,
            requires_explicit_confirmation: !warnings.is_empty(),
            warnings,
        })
    }
}

/// Derives seal posture for the vault at `path` without unlocking it. Returns
/// whether the vault file exists alongside the derived posture: a missing or
/// unreadable vault reports `VaultSealState::RecoveryRequired` with no
/// providers, matching the corrupted/absent-header failure mode callers must
/// not distinguish from an operator's perspective.
pub fn seal_posture_for_path(
    path: &Path,
    provider_probe: VaultKeyslotProviderProbe,
) -> (bool, VaultSealPosture) {
    if !path.exists() {
        return (
            false,
            VaultSealPosture::from_providers(VaultSealState::RecoveryRequired, Vec::new()),
        );
    }

    match read_vault_header(path) {
        Ok(header) => (true, header.seal_posture(provider_probe)),
        Err(_) => (
            true,
            VaultSealPosture::from_providers(VaultSealState::RecoveryRequired, Vec::new()),
        ),
    }
}
