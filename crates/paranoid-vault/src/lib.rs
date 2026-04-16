mod native_access;

pub use native_access::{
    NativeSessionHardening, SecretString, VaultAuth, VaultOpenOptions, default_vault_path,
    read_master_password, unlock_vault_for_options,
};

use argon2::{Algorithm, Argon2, Params, Version, password_hash::SaltString};
use bip39::{Language, Mnemonic};
use openssl::{
    asn1::Asn1Time,
    cms::{CMSOptions, CmsContentInfo},
    hash::MessageDigest,
    pkey::{PKey, Private},
    rand::rand_bytes,
    stack::Stack,
    symm::{Cipher, Crypter, Mode},
    x509::{X509, X509NameRef},
};
use paranoid_core::{GenerationReport, ParanoidRequest, execute_request};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zeroize::Zeroizing;

const FORMAT_VERSION: u32 = 1;
const BACKUP_FORMAT_VERSION: u32 = 1;
const TRANSFER_FORMAT_VERSION: u32 = 1;
const MASTER_KEY_LEN: usize = 32;
const MASTER_KEY_AAD: &[u8] = b"paranoid-passwd::vault::master-key";
const CERTIFICATE_MASTER_KEY_AAD: &[u8] = b"paranoid-passwd::vault::certificate-slot::master-key";
const CERTIFICATE_TRANSFER_KEY_AAD: &[u8] =
    b"paranoid-passwd::vault::transfer::certificate-access::transfer-key";
const ITEM_AAD_PREFIX: &[u8] = b"paranoid-passwd::vault::item::";
const TRANSFER_KEY_AAD: &[u8] = b"paranoid-passwd::vault::transfer::key";
const TRANSFER_PAYLOAD_AAD: &[u8] = b"paranoid-passwd::vault::transfer::payload";
const SQLITE_APPLICATION_ID: i64 = 1_347_446_356;
const DEFAULT_MEMORY_COST_KIB: u32 = 65_536;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 1;
const PASSWORD_WRAP_ALGORITHM: &str = "argon2id+aes-256-gcm";
const MNEMONIC_WRAP_ALGORITHM: &str = "bip39-entropy+aes-256-gcm";
const LEGACY_CERTIFICATE_WRAP_ALGORITHM: &str = "cms-envelope+aes-256-cbc";
const CERTIFICATE_WRAP_ALGORITHM: &str = "cms-envelope+transport-key+aes-256-gcm";
const DEVICE_WRAP_ALGORITHM: &str = "os-keyring+aes-256-gcm-check";
const DEVICE_KEYRING_SERVICE: &str = "com.paranoid-passwd.vault";
const MNEMONIC_LANGUAGE: &str = "english";
const MNEMONIC_WORD_COUNT: u8 = 24;
const CERTIFICATE_EXPIRY_WARNING_DAYS: u32 = 30;
const MNEMONIC_AAD_PREFIX: &[u8] = b"paranoid-passwd::vault::mnemonic-slot::";
const DEVICE_AAD_PREFIX: &[u8] = b"paranoid-passwd::vault::device-slot::";
const DEVICE_CHECK_PLAINTEXT: &[u8] = b"paranoid-passwd::device-bound::v1";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("{0}")]
    InvalidArguments(String),
    #[error("vault already exists at {0}")]
    VaultExists(String),
    #[error("vault not found at {0}")]
    VaultNotFound(String),
    #[error("vault unlock failed")]
    UnlockFailed,
    #[error("vault item not found: {0}")]
    ItemNotFound(String),
    #[error("random failure: {0}")]
    RandomFailure(String),
    #[error("crypto failure: {0}")]
    CryptoFailure(String),
    #[error("certificate failure: {0}")]
    CertificateFailure(String),
    #[error("device secure storage failure: {0}")]
    DeviceStoreFailure(String),
    #[error("sqlite failure: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization failure: {0}")]
    Json(#[from] serde_json::Error),
    #[error("argon2 failure: {0}")]
    Argon2(String),
    #[error("generator failure: {0}")]
    Generator(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKdfParams {
    pub algorithm: String,
    pub memory_cost_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub derived_key_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VaultKeyslotKind {
    #[serde(alias = "Password")]
    PasswordRecovery,
    MnemonicRecovery,
    #[serde(alias = "Device")]
    DeviceBound,
    CertificateWrapped,
}

impl VaultKeyslotKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PasswordRecovery => "password_recovery",
            Self::MnemonicRecovery => "mnemonic_recovery",
            Self::DeviceBound => "device_bound",
            Self::CertificateWrapped => "certificate_wrapped",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKeyslot {
    pub id: String,
    pub kind: VaultKeyslotKind,
    #[serde(default)]
    pub label: Option<String>,
    pub wrapped_by_os_keystore: bool,
    #[serde(default = "default_password_wrap_algorithm")]
    pub wrap_algorithm: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub tag_hex: String,
    pub encrypted_master_key_hex: String,
    #[serde(default)]
    pub certificate_fingerprint_sha256: Option<String>,
    #[serde(default)]
    pub certificate_subject: Option<String>,
    #[serde(default)]
    pub certificate_not_before: Option<String>,
    #[serde(default)]
    pub certificate_not_after: Option<String>,
    #[serde(default)]
    pub certificate_not_before_epoch: Option<i64>,
    #[serde(default)]
    pub certificate_not_after_epoch: Option<i64>,
    #[serde(default)]
    pub mnemonic_language: Option<String>,
    #[serde(default)]
    pub mnemonic_words: Option<u8>,
    #[serde(default)]
    pub device_service: Option<String>,
    #[serde(default)]
    pub device_account: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MnemonicRecoveryEnrollment {
    pub keyslot: VaultKeyslot,
    pub mnemonic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub format_version: u32,
    pub created_at_epoch: i64,
    pub migration_state: String,
    pub kdf: VaultKdfParams,
    pub keyslots: Vec<VaultKeyslot>,
}

#[derive(Debug, Clone)]
struct CertificateKeyslotMetadata {
    fingerprint_sha256: String,
    subject: String,
    not_before: String,
    not_after: String,
    not_before_epoch: i64,
    not_after_epoch: i64,
}

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

fn keyslot_health_for_slot(keyslot: &VaultKeyslot) -> VaultKeyslotHealth {
    let mut warnings = Vec::new();

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

    VaultKeyslotHealth {
        keyslot_id: keyslot.id.clone(),
        keyslot_kind: keyslot.kind.clone(),
        healthy: warnings.is_empty(),
        warnings,
    }
}

fn certificate_validity_warnings(not_before_epoch: i64, not_after_epoch: i64) -> Vec<String> {
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
        let keyslot = self
            .keyslots
            .iter()
            .find(|slot| slot.id == id)
            .ok_or_else(|| VaultError::ItemNotFound(format!("keyslot {id}")))?;
        Ok(keyslot_health_for_slot(keyslot))
    }

    pub fn keyslot_health_summaries(&self) -> Vec<VaultKeyslotHealth> {
        self.keyslots.iter().map(keyslot_health_for_slot).collect()
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VaultItemKind {
    Login,
    SecureNote,
    Card,
    Identity,
}

impl VaultItemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::SecureNote => "secure_note",
            Self::Card => "card",
            Self::Identity => "identity",
        }
    }

    pub fn parse(value: &str) -> Result<Self, VaultError> {
        match value {
            "login" => Ok(Self::Login),
            "secure_note" => Ok(Self::SecureNote),
            "card" => Ok(Self::Card),
            "identity" => Ok(Self::Identity),
            _ => Err(VaultError::InvalidArguments(format!(
                "unsupported vault item kind: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultItemFilter {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub kind: Option<VaultItemKind>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct NormalizedVaultItemFilter {
    query: Option<String>,
    kind: Option<VaultItemKind>,
    folder: Option<String>,
    tag: Option<String>,
}

impl VaultItemFilter {
    fn normalized(&self) -> NormalizedVaultItemFilter {
        NormalizedVaultItemFilter {
            query: self
                .query
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase()),
            kind: self.kind.clone(),
            folder: normalize_folder(self.folder.clone()).map(|value| value.to_ascii_lowercase()),
            tag: normalize_tags(
                &self
                    .tag
                    .as_deref()
                    .map(|value| vec![value.to_string()])
                    .unwrap_or_default(),
            )
            .into_iter()
            .next()
            .map(|value| value.to_ascii_lowercase()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRecord {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureNoteRecord {
    pub title: String,
    pub content: String,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardRecord {
    pub title: String,
    pub cardholder_name: String,
    pub number: String,
    pub expiry_month: String,
    pub expiry_year: String,
    pub security_code: String,
    pub billing_zip: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub title: String,
    pub full_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultItemPayload {
    Login(LoginRecord),
    SecureNote(SecureNoteRecord),
    Card(CardRecord),
    Identity(IdentityRecord),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub kind: VaultItemKind,
    pub created_at_epoch: i64,
    pub updated_at_epoch: i64,
    pub payload: VaultItemPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItemSummary {
    pub id: String,
    pub kind: VaultItemKind,
    pub title: String,
    pub subtitle: String,
    pub location: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    pub updated_at_epoch: i64,
    #[serde(default)]
    pub duplicate_password_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBackupPackage {
    pub backup_format_version: u32,
    pub exported_at_epoch: i64,
    pub vault_format_version: u32,
    pub header: VaultHeader,
    pub items: Vec<VaultBackupItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBackupItem {
    pub id: String,
    pub kind: String,
    pub created_at_epoch: i64,
    pub updated_at_epoch: i64,
    pub nonce_hex: String,
    pub tag_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBackupSummary {
    pub backup_format_version: u32,
    pub exported_at_epoch: i64,
    pub vault_format_version: u32,
    pub header_format_version: u32,
    pub item_count: usize,
    pub login_count: usize,
    pub secure_note_count: usize,
    pub card_count: usize,
    pub identity_count: usize,
    pub keyslot_count: usize,
    pub recovery_posture: VaultRecoveryPosture,
    #[serde(default)]
    pub keyslots: Vec<VaultBackupKeyslotSummary>,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub restorable_by_current_build: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBackupKeyslotSummary {
    pub id: String,
    pub kind: VaultKeyslotKind,
    #[serde(default)]
    pub label: Option<String>,
    pub wrap_algorithm: String,
    #[serde(default)]
    pub certificate_fingerprint_sha256: Option<String>,
    #[serde(default)]
    pub certificate_subject: Option<String>,
    #[serde(default)]
    pub certificate_not_before: Option<String>,
    #[serde(default)]
    pub certificate_not_after: Option<String>,
    #[serde(default)]
    pub certificate_not_before_epoch: Option<i64>,
    #[serde(default)]
    pub certificate_not_after_epoch: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTransferPackage {
    pub transfer_format_version: u32,
    pub exported_at_epoch: i64,
    pub source_vault_format_version: u32,
    pub item_count: usize,
    pub login_count: usize,
    pub secure_note_count: usize,
    pub card_count: usize,
    pub identity_count: usize,
    #[serde(default)]
    pub filter: VaultItemFilter,
    pub access: VaultTransferAccess,
    pub payload_nonce_hex: String,
    pub payload_tag_hex: String,
    pub payload_ciphertext_hex: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultTransferAccess {
    #[serde(default)]
    pub recovery: Option<VaultTransferRecoveryAccess>,
    #[serde(default)]
    pub certificate: Option<VaultTransferCertificateAccess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTransferRecoveryAccess {
    pub wrap_algorithm: String,
    pub kdf: VaultKdfParams,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub tag_hex: String,
    pub encrypted_transfer_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTransferCertificateAccess {
    pub wrap_algorithm: String,
    #[serde(default, alias = "encrypted_transfer_key_der_hex")]
    pub wrapped_transport_key_der_hex: String,
    #[serde(default)]
    pub nonce_hex: String,
    #[serde(default)]
    pub tag_hex: String,
    #[serde(default)]
    pub encrypted_transfer_key_hex: String,
    pub certificate_fingerprint_sha256: String,
    pub certificate_subject: String,
    pub certificate_not_before: String,
    pub certificate_not_after: String,
    pub certificate_not_before_epoch: i64,
    pub certificate_not_after_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTransferSummary {
    pub transfer_format_version: u32,
    pub exported_at_epoch: i64,
    pub source_vault_format_version: u32,
    pub item_count: usize,
    pub login_count: usize,
    pub secure_note_count: usize,
    pub card_count: usize,
    pub identity_count: usize,
    #[serde(default)]
    pub filter: VaultItemFilter,
    pub has_recovery_path: bool,
    pub has_certificate_path: bool,
    #[serde(default)]
    pub certificate_fingerprint_sha256: Option<String>,
    #[serde(default)]
    pub certificate_subject: Option<String>,
    #[serde(default)]
    pub certificate_not_after: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub importable_by_current_build: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultTransferImportSummary {
    pub imported_count: usize,
    pub replaced_count: usize,
    pub remapped_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCertificatePreview {
    pub fingerprint_sha256: String,
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewLoginRecord {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateStoreLoginRecord {
    #[serde(default)]
    pub target_login_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateLoginRecord {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<Option<String>>,
    pub notes: Option<Option<String>>,
    pub folder: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSecureNoteRecord {
    pub title: String,
    pub content: String,
    pub folder: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateSecureNoteRecord {
    pub title: Option<String>,
    pub content: Option<String>,
    pub folder: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewCardRecord {
    pub title: String,
    pub cardholder_name: String,
    pub number: String,
    pub expiry_month: String,
    pub expiry_year: String,
    pub security_code: String,
    pub billing_zip: Option<String>,
    pub notes: Option<String>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateCardRecord {
    pub title: Option<String>,
    pub cardholder_name: Option<String>,
    pub number: Option<String>,
    pub expiry_month: Option<String>,
    pub expiry_year: Option<String>,
    pub security_code: Option<String>,
    pub billing_zip: Option<Option<String>>,
    pub notes: Option<Option<String>>,
    pub folder: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewIdentityRecord {
    pub title: String,
    pub full_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<String>,
    pub notes: Option<String>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateIdentityRecord {
    pub title: Option<String>,
    pub full_name: Option<String>,
    pub email: Option<Option<String>>,
    pub phone: Option<Option<String>>,
    pub address: Option<Option<String>>,
    pub notes: Option<Option<String>>,
    pub folder: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct UnlockedVault {
    path: PathBuf,
    conn: Connection,
    header: VaultHeader,
    master_key: Zeroizing<Vec<u8>>,
}

impl UnlockedVault {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    pub fn add_certificate_keyslot(
        &mut self,
        certificate_pem: &[u8],
        label: Option<String>,
    ) -> Result<VaultKeyslot, VaultError> {
        let certificate = load_certificate(certificate_pem)?;
        let metadata = certificate_keyslot_metadata(&certificate)?;
        let fingerprint = metadata.fingerprint_sha256.clone();
        if self.header.keyslots.iter().any(|slot| {
            slot.kind == VaultKeyslotKind::CertificateWrapped
                && slot.certificate_fingerprint_sha256.as_deref() == Some(fingerprint.as_str())
        }) {
            return Err(VaultError::InvalidArguments(format!(
                "certificate keyslot already exists for fingerprint {fingerprint}"
            )));
        }

        let wrapped = wrap_secret_with_certificate(
            self.master_key.as_slice(),
            &certificate,
            CERTIFICATE_MASTER_KEY_AAD,
        )?;
        let slot = VaultKeyslot {
            id: format!("cert-{}", &fingerprint[..16]),
            kind: VaultKeyslotKind::CertificateWrapped,
            label,
            wrapped_by_os_keystore: false,
            wrap_algorithm: CERTIFICATE_WRAP_ALGORITHM.to_string(),
            salt_hex: hex_encode(wrapped.wrapped_transport_key_der.as_slice()),
            nonce_hex: hex_encode(wrapped.encrypted_secret.nonce.as_slice()),
            tag_hex: hex_encode(wrapped.encrypted_secret.tag.as_slice()),
            encrypted_master_key_hex: hex_encode(wrapped.encrypted_secret.ciphertext.as_slice()),
            certificate_fingerprint_sha256: Some(fingerprint),
            certificate_subject: Some(metadata.subject),
            certificate_not_before: Some(metadata.not_before),
            certificate_not_after: Some(metadata.not_after),
            certificate_not_before_epoch: Some(metadata.not_before_epoch),
            certificate_not_after_epoch: Some(metadata.not_after_epoch),
            mnemonic_language: None,
            mnemonic_words: None,
            device_service: None,
            device_account: None,
        };

        self.header.keyslots.push(slot.clone());
        self.persist_header()?;
        Ok(slot)
    }

    pub fn rewrap_certificate_keyslot(
        &mut self,
        id: &str,
        certificate_pem: &[u8],
    ) -> Result<VaultKeyslot, VaultError> {
        let index = self
            .header
            .keyslots
            .iter()
            .position(|slot| slot.id == id)
            .ok_or_else(|| VaultError::ItemNotFound(format!("keyslot {id}")))?;
        let existing = self.header.keyslots[index].clone();
        if existing.kind != VaultKeyslotKind::CertificateWrapped {
            return Err(VaultError::InvalidArguments(format!(
                "keyslot {id} is not certificate-wrapped"
            )));
        }

        let certificate = load_certificate(certificate_pem)?;
        let metadata = certificate_keyslot_metadata(&certificate)?;
        let fingerprint = metadata.fingerprint_sha256.clone();
        if self.header.keyslots.iter().any(|slot| {
            slot.id != existing.id
                && slot.kind == VaultKeyslotKind::CertificateWrapped
                && slot.certificate_fingerprint_sha256.as_deref() == Some(fingerprint.as_str())
        }) {
            return Err(VaultError::InvalidArguments(format!(
                "certificate keyslot already exists for fingerprint {fingerprint}"
            )));
        }

        let wrapped = wrap_secret_with_certificate(
            self.master_key.as_slice(),
            &certificate,
            CERTIFICATE_MASTER_KEY_AAD,
        )?;
        let updated = VaultKeyslot {
            wrap_algorithm: CERTIFICATE_WRAP_ALGORITHM.to_string(),
            salt_hex: hex_encode(wrapped.wrapped_transport_key_der.as_slice()),
            nonce_hex: hex_encode(wrapped.encrypted_secret.nonce.as_slice()),
            tag_hex: hex_encode(wrapped.encrypted_secret.tag.as_slice()),
            encrypted_master_key_hex: hex_encode(wrapped.encrypted_secret.ciphertext.as_slice()),
            certificate_fingerprint_sha256: Some(fingerprint),
            certificate_subject: Some(metadata.subject),
            certificate_not_before: Some(metadata.not_before),
            certificate_not_after: Some(metadata.not_after),
            certificate_not_before_epoch: Some(metadata.not_before_epoch),
            certificate_not_after_epoch: Some(metadata.not_after_epoch),
            ..existing.clone()
        };

        self.header.keyslots[index] = updated.clone();
        if let Err(error) = self.persist_header() {
            self.header.keyslots[index] = existing;
            return Err(error);
        }

        Ok(updated)
    }

    pub fn add_mnemonic_keyslot(
        &mut self,
        label: Option<String>,
    ) -> Result<MnemonicRecoveryEnrollment, VaultError> {
        let slot_id = format!("mnemonic-{}", random_hex_id(8)?);
        let enrollment = self.build_mnemonic_enrollment(slot_id.as_str(), label)?;

        self.header.keyslots.push(enrollment.keyslot.clone());
        self.persist_header()?;
        Ok(enrollment)
    }

    pub fn rotate_mnemonic_keyslot(
        &mut self,
        id: &str,
    ) -> Result<MnemonicRecoveryEnrollment, VaultError> {
        let index = self
            .header
            .keyslots
            .iter()
            .position(|slot| slot.id == id)
            .ok_or_else(|| VaultError::ItemNotFound(format!("keyslot {id}")))?;
        let existing = self.header.keyslots[index].clone();
        if existing.kind != VaultKeyslotKind::MnemonicRecovery {
            return Err(VaultError::InvalidArguments(format!(
                "keyslot {id} is not mnemonic recovery"
            )));
        }

        let enrollment = self.build_mnemonic_enrollment(id, existing.label.clone())?;
        self.header.keyslots[index] = enrollment.keyslot.clone();
        if let Err(error) = self.persist_header() {
            self.header.keyslots[index] = existing;
            return Err(error);
        }

        Ok(enrollment)
    }

    pub fn add_device_keyslot(
        &mut self,
        label: Option<String>,
    ) -> Result<VaultKeyslot, VaultError> {
        let slot_id = format!("device-{}", random_hex_id(8)?);
        let device_account = format!("vault-{}", random_hex_id(16)?);
        device_store_set_secret(
            DEVICE_KEYRING_SERVICE,
            device_account.as_str(),
            self.master_key.as_slice(),
        )?;

        let check_blob = encrypt_blob(
            self.master_key.as_slice(),
            &device_slot_aad(slot_id.as_str()),
            DEVICE_CHECK_PLAINTEXT,
        )?;
        // TODO: HUMAN_REVIEW - confirm the device-bound keyslot design of storing the raw master key in OS secure storage plus an AES-GCM verification blob is acceptable across macOS, Windows, and Linux secret stores.
        let slot = VaultKeyslot {
            id: slot_id,
            kind: VaultKeyslotKind::DeviceBound,
            label,
            wrapped_by_os_keystore: true,
            wrap_algorithm: DEVICE_WRAP_ALGORITHM.to_string(),
            salt_hex: String::new(),
            nonce_hex: hex_encode(check_blob.nonce.as_slice()),
            tag_hex: hex_encode(check_blob.tag.as_slice()),
            encrypted_master_key_hex: hex_encode(check_blob.ciphertext.as_slice()),
            certificate_fingerprint_sha256: None,
            certificate_subject: None,
            certificate_not_before: None,
            certificate_not_after: None,
            certificate_not_before_epoch: None,
            certificate_not_after_epoch: None,
            mnemonic_language: None,
            mnemonic_words: None,
            device_service: Some(DEVICE_KEYRING_SERVICE.to_string()),
            device_account: Some(device_account.clone()),
        };

        self.header.keyslots.push(slot.clone());
        if let Err(error) = self.persist_header() {
            let _ = device_store_delete_secret(DEVICE_KEYRING_SERVICE, device_account.as_str());
            return Err(error);
        }
        Ok(slot)
    }

    fn build_mnemonic_enrollment(
        &self,
        slot_id: &str,
        label: Option<String>,
    ) -> Result<MnemonicRecoveryEnrollment, VaultError> {
        let mnemonic_entropy = Zeroizing::new(random_bytes(MASTER_KEY_LEN)?);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, mnemonic_entropy.as_slice())
            .map_err(|error| VaultError::InvalidArguments(error.to_string()))?;
        let wrapped = encrypt_blob(
            mnemonic_entropy.as_slice(),
            &mnemonic_slot_aad(slot_id),
            self.master_key.as_slice(),
        )?;
        // TODO: HUMAN_REVIEW - confirm using 24-word BIP39 entropy directly as the AES-256-GCM wrapping key for mnemonic recovery slots is the right recovery construction.
        let keyslot = VaultKeyslot {
            id: slot_id.to_string(),
            kind: VaultKeyslotKind::MnemonicRecovery,
            label,
            wrapped_by_os_keystore: false,
            wrap_algorithm: MNEMONIC_WRAP_ALGORITHM.to_string(),
            salt_hex: String::new(),
            nonce_hex: hex_encode(wrapped.nonce.as_slice()),
            tag_hex: hex_encode(wrapped.tag.as_slice()),
            encrypted_master_key_hex: hex_encode(wrapped.ciphertext.as_slice()),
            certificate_fingerprint_sha256: None,
            certificate_subject: None,
            certificate_not_before: None,
            certificate_not_after: None,
            certificate_not_before_epoch: None,
            certificate_not_after_epoch: None,
            mnemonic_language: Some(MNEMONIC_LANGUAGE.to_string()),
            mnemonic_words: Some(MNEMONIC_WORD_COUNT),
            device_service: None,
            device_account: None,
        };

        Ok(MnemonicRecoveryEnrollment {
            keyslot,
            mnemonic: mnemonic.to_string(),
        })
    }

    pub fn relabel_keyslot(
        &mut self,
        id: &str,
        label: Option<String>,
    ) -> Result<VaultKeyslot, VaultError> {
        let index = self
            .header
            .keyslots
            .iter()
            .position(|slot| slot.id == id)
            .ok_or_else(|| VaultError::ItemNotFound(format!("keyslot {id}")))?;
        let existing = self.header.keyslots[index].clone();
        let updated = VaultKeyslot {
            label: label
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
            ..existing.clone()
        };

        self.header.keyslots[index] = updated.clone();
        if let Err(error) = self.persist_header() {
            self.header.keyslots[index] = existing;
            return Err(error);
        }

        Ok(updated)
    }

    pub fn remove_keyslot(&mut self, id: &str, force: bool) -> Result<VaultKeyslot, VaultError> {
        let impact = self.header.assess_keyslot_removal(id)?;
        if impact.keyslot_kind == VaultKeyslotKind::PasswordRecovery {
            return Err(VaultError::InvalidArguments(
                "password recovery keyslot cannot be removed".to_string(),
            ));
        }
        if impact.requires_explicit_confirmation && !force {
            return Err(VaultError::InvalidArguments(format!(
                "refusing to remove keyslot {id} without explicit confirmation: {}",
                impact.warnings.join(" ")
            )));
        }

        let index = self
            .header
            .keyslots
            .iter()
            .position(|slot| slot.id == id)
            .ok_or_else(|| VaultError::ItemNotFound(format!("keyslot {id}")))?;
        let removed = self.header.keyslots.remove(index);
        if let Err(error) = self.persist_header() {
            self.header.keyslots.insert(index, removed.clone());
            return Err(error);
        }

        if removed.kind == VaultKeyslotKind::DeviceBound
            && let (Some(service), Some(account)) = (
                removed.device_service.as_deref(),
                removed.device_account.as_deref(),
            )
        {
            let _ = device_store_delete_secret(service, account);
        }

        Ok(removed)
    }

    pub fn rotate_password_recovery_keyslot(
        &mut self,
        new_master_password: &str,
    ) -> Result<VaultKeyslot, VaultError> {
        if new_master_password.is_empty() {
            return Err(VaultError::InvalidArguments(
                "new recovery secret must not be empty".to_string(),
            ));
        }

        let index = self
            .header
            .keyslots
            .iter()
            .position(|slot| slot.kind == VaultKeyslotKind::PasswordRecovery)
            .ok_or_else(|| {
                VaultError::InvalidArguments("vault has no password recovery keyslot".to_string())
            })?;

        let existing = self.header.keyslots[index].clone();
        let salt_bytes = random_bytes(16)?;
        let salt = SaltString::encode_b64(salt_bytes.as_slice())
            .map_err(|error| VaultError::Argon2(error.to_string()))?;
        let kek = derive_key(new_master_password, &salt, &self.header.kdf)?;
        let wrapped = encrypt_blob(kek.as_slice(), MASTER_KEY_AAD, self.master_key.as_slice())?;

        let updated = VaultKeyslot {
            salt_hex: hex_encode(salt.as_str().as_bytes()),
            nonce_hex: hex_encode(wrapped.nonce.as_slice()),
            tag_hex: hex_encode(wrapped.tag.as_slice()),
            encrypted_master_key_hex: hex_encode(wrapped.ciphertext.as_slice()),
            wrap_algorithm: PASSWORD_WRAP_ALGORITHM.to_string(),
            ..existing.clone()
        };

        self.header.keyslots[index] = updated.clone();
        if let Err(error) = self.persist_header() {
            self.header.keyslots[index] = existing;
            return Err(error);
        }

        Ok(updated)
    }

    pub fn rebind_device_keyslot(&mut self, id: &str) -> Result<VaultKeyslot, VaultError> {
        let index = self
            .header
            .keyslots
            .iter()
            .position(|slot| slot.id == id)
            .ok_or_else(|| VaultError::ItemNotFound(format!("keyslot {id}")))?;
        let existing = self.header.keyslots[index].clone();
        let previous_account = existing.device_account.clone();
        if existing.kind != VaultKeyslotKind::DeviceBound {
            return Err(VaultError::InvalidArguments(format!(
                "keyslot {id} is not device-bound"
            )));
        }

        let service = existing
            .device_service
            .clone()
            .unwrap_or_else(|| DEVICE_KEYRING_SERVICE.to_string());
        let new_account = format!("vault-{}", random_hex_id(16)?);
        device_store_set_secret(
            service.as_str(),
            new_account.as_str(),
            self.master_key.as_slice(),
        )?;

        let check_blob = encrypt_blob(
            self.master_key.as_slice(),
            &device_slot_aad(existing.id.as_str()),
            DEVICE_CHECK_PLAINTEXT,
        )?;

        let updated = VaultKeyslot {
            nonce_hex: hex_encode(check_blob.nonce.as_slice()),
            tag_hex: hex_encode(check_blob.tag.as_slice()),
            encrypted_master_key_hex: hex_encode(check_blob.ciphertext.as_slice()),
            device_service: Some(service.clone()),
            device_account: Some(new_account.clone()),
            ..existing.clone()
        };

        self.header.keyslots[index] = updated.clone();
        if let Err(error) = self.persist_header() {
            self.header.keyslots[index] = existing.clone();
            let _ = device_store_delete_secret(service.as_str(), new_account.as_str());
            return Err(error);
        }

        if let Some(previous_account) = previous_account.as_deref()
            && previous_account != new_account.as_str()
        {
            let _ = device_store_delete_secret(service.as_str(), previous_account);
        }

        Ok(updated)
    }

    pub fn add_login(&self, record: NewLoginRecord) -> Result<VaultItem, VaultError> {
        validate_login_record(&record)?;
        let folder = normalize_folder(record.folder);
        let tags = normalize_tags(record.tags.as_slice());
        let now = unix_epoch_now()?;
        let item = VaultItem {
            id: random_hex_id(16)?,
            kind: VaultItemKind::Login,
            created_at_epoch: now,
            updated_at_epoch: now,
            payload: VaultItemPayload::Login(LoginRecord {
                title: record.title,
                username: record.username,
                password: record.password,
                url: record.url,
                notes: record.notes,
                folder,
                tags,
                password_history: Vec::new(),
            }),
        };
        self.store_item(&item)?;
        Ok(item)
    }

    pub fn add_secure_note(&self, record: NewSecureNoteRecord) -> Result<VaultItem, VaultError> {
        validate_secure_note_record(&record)?;
        let folder = normalize_folder(record.folder);
        let tags = normalize_tags(record.tags.as_slice());
        let now = unix_epoch_now()?;
        let item = VaultItem {
            id: random_hex_id(16)?,
            kind: VaultItemKind::SecureNote,
            created_at_epoch: now,
            updated_at_epoch: now,
            payload: VaultItemPayload::SecureNote(SecureNoteRecord {
                title: record.title,
                content: record.content,
                folder,
                tags,
            }),
        };
        self.store_item(&item)?;
        Ok(item)
    }

    pub fn add_card(&self, record: NewCardRecord) -> Result<VaultItem, VaultError> {
        validate_card_record(&record)?;
        let folder = normalize_folder(record.folder);
        let tags = normalize_tags(record.tags.as_slice());
        let now = unix_epoch_now()?;
        let item = VaultItem {
            id: random_hex_id(16)?,
            kind: VaultItemKind::Card,
            created_at_epoch: now,
            updated_at_epoch: now,
            payload: VaultItemPayload::Card(CardRecord {
                title: record.title,
                cardholder_name: record.cardholder_name,
                number: record.number,
                expiry_month: record.expiry_month,
                expiry_year: record.expiry_year,
                security_code: record.security_code,
                billing_zip: record.billing_zip,
                notes: record.notes,
                folder,
                tags,
            }),
        };
        self.store_item(&item)?;
        Ok(item)
    }

    pub fn add_identity(&self, record: NewIdentityRecord) -> Result<VaultItem, VaultError> {
        validate_identity_record(&record)?;
        let folder = normalize_folder(record.folder);
        let tags = normalize_tags(record.tags.as_slice());
        let now = unix_epoch_now()?;
        let item = VaultItem {
            id: random_hex_id(16)?,
            kind: VaultItemKind::Identity,
            created_at_epoch: now,
            updated_at_epoch: now,
            payload: VaultItemPayload::Identity(IdentityRecord {
                title: record.title,
                full_name: record.full_name,
                email: record.email,
                phone: record.phone,
                address: record.address,
                notes: record.notes,
                folder,
                tags,
            }),
        };
        self.store_item(&item)?;
        Ok(item)
    }

    pub fn list_items(&self) -> Result<Vec<VaultItemSummary>, VaultError> {
        self.list_items_filtered(&VaultItemFilter::default())
    }

    pub fn list_items_filtered(
        &self,
        filter: &VaultItemFilter,
    ) -> Result<Vec<VaultItemSummary>, VaultError> {
        let normalized = filter.normalized();
        let items = self.load_all_items()?;
        let duplicate_counts = duplicate_password_counts(items.as_slice());
        Ok(items
            .into_iter()
            .filter(|item| item_matches_filter(item, &normalized))
            .map(|item| item_summary(&item, *duplicate_counts.get(item.id.as_str()).unwrap_or(&0)))
            .collect())
    }

    pub fn search_items(&self, query: &str) -> Result<Vec<VaultItemSummary>, VaultError> {
        self.list_items_filtered(&VaultItemFilter {
            query: Some(query.to_string()),
            ..VaultItemFilter::default()
        })
    }

    pub fn duplicate_password_count(&self, id: &str) -> Result<usize, VaultError> {
        let item = self.get_item(id)?;
        let VaultItemPayload::Login(_) = item.payload else {
            return Ok(0);
        };
        let items = self.load_all_items()?;
        let duplicate_counts = duplicate_password_counts(items.as_slice());
        Ok(*duplicate_counts.get(id).unwrap_or(&0))
    }

    fn load_all_items(&self) -> Result<Vec<VaultItem>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, created_at_epoch, updated_at_epoch, nonce, tag, ciphertext
             FROM items ORDER BY updated_at_epoch DESC, id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredVaultRow {
                id: row.get(0)?,
                kind: row.get(1)?,
                created_at_epoch: row.get(2)?,
                updated_at_epoch: row.get(3)?,
                nonce: row.get(4)?,
                tag: row.get(5)?,
                ciphertext: row.get(6)?,
            })
        })?;

        rows.map(|row| self.decrypt_row(&row?)).collect()
    }

    pub fn get_item(&self, id: &str) -> Result<VaultItem, VaultError> {
        let row = self.load_row(id)?;
        self.decrypt_row(&row)
    }

    pub fn update_login(
        &self,
        id: &str,
        update: UpdateLoginRecord,
    ) -> Result<VaultItem, VaultError> {
        let mut item = self.get_item(id)?;
        let VaultItemPayload::Login(login) = &mut item.payload else {
            return Err(VaultError::InvalidArguments(format!(
                "vault item {id} is not a login"
            )));
        };
        if let Some(title) = update.title {
            login.title = title;
        }
        if let Some(username) = update.username {
            login.username = username;
        }
        let updated_at_epoch = unix_epoch_now()?;
        if let Some(password) = update.password {
            if password != login.password {
                login.password_history.push(PasswordHistoryEntry {
                    password: login.password.clone(),
                    changed_at_epoch: updated_at_epoch,
                });
                login.password = password;
            }
        }
        if let Some(url) = update.url {
            login.url = url;
        }
        if let Some(notes) = update.notes {
            login.notes = notes;
        }
        if let Some(folder) = update.folder {
            login.folder = normalize_folder(folder);
        }
        if let Some(tags) = update.tags {
            login.tags = normalize_tags(tags.as_slice());
        }
        validate_login_record(&NewLoginRecord {
            title: login.title.clone(),
            username: login.username.clone(),
            password: login.password.clone(),
            url: login.url.clone(),
            notes: login.notes.clone(),
            folder: login.folder.clone(),
            tags: login.tags.clone(),
        })?;
        item.updated_at_epoch = updated_at_epoch;
        self.store_item(&item)?;
        Ok(item)
    }

    pub fn update_secure_note(
        &self,
        id: &str,
        update: UpdateSecureNoteRecord,
    ) -> Result<VaultItem, VaultError> {
        let mut item = self.get_item(id)?;
        let VaultItemPayload::SecureNote(note) = &mut item.payload else {
            return Err(VaultError::InvalidArguments(format!(
                "vault item {id} is not a secure note"
            )));
        };
        if let Some(title) = update.title {
            note.title = title;
        }
        if let Some(content) = update.content {
            note.content = content;
        }
        if let Some(folder) = update.folder {
            note.folder = normalize_folder(folder);
        }
        if let Some(tags) = update.tags {
            note.tags = normalize_tags(tags.as_slice());
        }
        validate_secure_note_record(&NewSecureNoteRecord {
            title: note.title.clone(),
            content: note.content.clone(),
            folder: note.folder.clone(),
            tags: note.tags.clone(),
        })?;
        item.updated_at_epoch = unix_epoch_now()?;
        self.store_item(&item)?;
        Ok(item)
    }

    pub fn update_card(&self, id: &str, update: UpdateCardRecord) -> Result<VaultItem, VaultError> {
        let mut item = self.get_item(id)?;
        let VaultItemPayload::Card(card) = &mut item.payload else {
            return Err(VaultError::InvalidArguments(format!(
                "vault item {id} is not a card"
            )));
        };
        if let Some(title) = update.title {
            card.title = title;
        }
        if let Some(cardholder_name) = update.cardholder_name {
            card.cardholder_name = cardholder_name;
        }
        if let Some(number) = update.number {
            card.number = number;
        }
        if let Some(expiry_month) = update.expiry_month {
            card.expiry_month = expiry_month;
        }
        if let Some(expiry_year) = update.expiry_year {
            card.expiry_year = expiry_year;
        }
        if let Some(security_code) = update.security_code {
            card.security_code = security_code;
        }
        if let Some(billing_zip) = update.billing_zip {
            card.billing_zip = billing_zip;
        }
        if let Some(notes) = update.notes {
            card.notes = notes;
        }
        if let Some(folder) = update.folder {
            card.folder = normalize_folder(folder);
        }
        if let Some(tags) = update.tags {
            card.tags = normalize_tags(tags.as_slice());
        }
        validate_card_record(&NewCardRecord {
            title: card.title.clone(),
            cardholder_name: card.cardholder_name.clone(),
            number: card.number.clone(),
            expiry_month: card.expiry_month.clone(),
            expiry_year: card.expiry_year.clone(),
            security_code: card.security_code.clone(),
            billing_zip: card.billing_zip.clone(),
            notes: card.notes.clone(),
            folder: card.folder.clone(),
            tags: card.tags.clone(),
        })?;
        item.updated_at_epoch = unix_epoch_now()?;
        self.store_item(&item)?;
        Ok(item)
    }

    pub fn update_identity(
        &self,
        id: &str,
        update: UpdateIdentityRecord,
    ) -> Result<VaultItem, VaultError> {
        let mut item = self.get_item(id)?;
        let VaultItemPayload::Identity(identity) = &mut item.payload else {
            return Err(VaultError::InvalidArguments(format!(
                "vault item {id} is not an identity"
            )));
        };
        if let Some(title) = update.title {
            identity.title = title;
        }
        if let Some(full_name) = update.full_name {
            identity.full_name = full_name;
        }
        if let Some(email) = update.email {
            identity.email = email;
        }
        if let Some(phone) = update.phone {
            identity.phone = phone;
        }
        if let Some(address) = update.address {
            identity.address = address;
        }
        if let Some(notes) = update.notes {
            identity.notes = notes;
        }
        if let Some(folder) = update.folder {
            identity.folder = normalize_folder(folder);
        }
        if let Some(tags) = update.tags {
            identity.tags = normalize_tags(tags.as_slice());
        }
        validate_identity_record(&NewIdentityRecord {
            title: identity.title.clone(),
            full_name: identity.full_name.clone(),
            email: identity.email.clone(),
            phone: identity.phone.clone(),
            address: identity.address.clone(),
            notes: identity.notes.clone(),
            folder: identity.folder.clone(),
            tags: identity.tags.clone(),
        })?;
        item.updated_at_epoch = unix_epoch_now()?;
        self.store_item(&item)?;
        Ok(item)
    }

    pub fn delete_item(&self, id: &str) -> Result<(), VaultError> {
        let changed = self
            .conn
            .execute("DELETE FROM items WHERE id = ?1", params![id])?;
        if changed == 0 {
            return Err(VaultError::ItemNotFound(id.to_string()));
        }
        Ok(())
    }

    pub fn generate_and_store(
        &self,
        request: &ParanoidRequest,
        record: GenerateStoreLoginRecord,
    ) -> Result<(GenerationReport, VaultItem), VaultError> {
        let report = execute_request(request, true, |_| {})
            .map_err(|error| VaultError::Generator(error.to_string()))?;
        let password = report
            .passwords
            .first()
            .map(|generated| generated.value.clone())
            .ok_or_else(|| VaultError::Generator("generator produced no passwords".to_string()))?;
        let item = if let Some(target_login_id) = record.target_login_id.as_deref() {
            let existing = self.get_item(target_login_id)?;
            let VaultItemPayload::Login(login) = existing.payload else {
                return Err(VaultError::InvalidArguments(format!(
                    "vault item {target_login_id} is not a login"
                )));
            };

            self.update_login(
                target_login_id,
                UpdateLoginRecord {
                    title: Some(record.title.unwrap_or(login.title)),
                    username: Some(record.username.unwrap_or(login.username)),
                    password: Some(password),
                    url: Some(record.url.or(login.url)),
                    notes: Some(record.notes.or(login.notes)),
                    folder: Some(record.folder.or(login.folder)),
                    tags: Some(record.tags.unwrap_or(login.tags)),
                },
            )?
        } else {
            let title = record.title.ok_or_else(|| {
                VaultError::InvalidArguments(
                    "generate-and-store requires title when creating a new login".to_string(),
                )
            })?;
            let username = record.username.ok_or_else(|| {
                VaultError::InvalidArguments(
                    "generate-and-store requires username when creating a new login".to_string(),
                )
            })?;

            self.add_login(NewLoginRecord {
                title,
                username,
                password,
                url: record.url,
                notes: record.notes,
                folder: record.folder,
                tags: record.tags.unwrap_or_default(),
            })?
        };
        Ok((report, item))
    }

    pub fn export_backup(&self, output_path: impl AsRef<Path>) -> Result<PathBuf, VaultError> {
        let output_path = output_path.as_ref();
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut stmt = self.conn.prepare(
            "SELECT id, kind, created_at_epoch, updated_at_epoch, nonce, tag, ciphertext
             FROM items ORDER BY updated_at_epoch DESC, id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(VaultBackupItem {
                id: row.get(0)?,
                kind: row.get(1)?,
                created_at_epoch: row.get(2)?,
                updated_at_epoch: row.get(3)?,
                nonce_hex: hex_encode(&row.get::<_, Vec<u8>>(4)?),
                tag_hex: hex_encode(&row.get::<_, Vec<u8>>(5)?),
                ciphertext_hex: hex_encode(&row.get::<_, Vec<u8>>(6)?),
            })
        })?;
        let items = rows.collect::<Result<Vec<_>, _>>()?;

        let package = VaultBackupPackage {
            backup_format_version: BACKUP_FORMAT_VERSION,
            exported_at_epoch: unix_epoch_now()?,
            vault_format_version: self.header.format_version,
            header: self.header.clone(),
            items,
        };
        fs::write(output_path, serde_json::to_vec_pretty(&package)?)?;
        Ok(output_path.to_path_buf())
    }

    pub fn export_transfer_package(
        &self,
        output_path: impl AsRef<Path>,
        filter: &VaultItemFilter,
        recovery_secret: Option<&str>,
        certificate_pem: Option<&[u8]>,
    ) -> Result<PathBuf, VaultError> {
        if recovery_secret.is_none() && certificate_pem.is_none() {
            return Err(VaultError::InvalidArguments(
                "transfer export requires at least one recovery path: a recovery secret or recipient certificate"
                    .to_string(),
            ));
        }
        if recovery_secret.is_some_and(str::is_empty) {
            return Err(VaultError::InvalidArguments(
                "transfer recovery secret must not be empty".to_string(),
            ));
        }

        let output_path = output_path.as_ref();
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let normalized = filter.normalized();
        let items = self
            .load_all_items()?
            .into_iter()
            .filter(|item| item_matches_filter(item, &normalized))
            .collect::<Vec<_>>();
        if items.is_empty() {
            return Err(VaultError::InvalidArguments(
                "transfer export matched no vault items".to_string(),
            ));
        }

        let transfer_key = Zeroizing::new(random_bytes(MASTER_KEY_LEN)?);
        let payload_plaintext = serde_json::to_vec(&VaultTransferPayload {
            items: items.clone(),
        })?;
        let payload = encrypt_blob(
            transfer_key.as_slice(),
            TRANSFER_PAYLOAD_AAD,
            payload_plaintext.as_slice(),
        )?;

        let recovery = if let Some(secret) = recovery_secret {
            let salt_bytes = random_bytes(16)?;
            let salt = SaltString::encode_b64(salt_bytes.as_slice())
                .map_err(|error| VaultError::Argon2(error.to_string()))?;
            let kdf = default_transfer_kdf_params();
            let kek = derive_key(secret, &salt, &kdf)?;
            let wrapped = encrypt_blob(kek.as_slice(), TRANSFER_KEY_AAD, transfer_key.as_slice())?;
            Some(VaultTransferRecoveryAccess {
                wrap_algorithm: PASSWORD_WRAP_ALGORITHM.to_string(),
                kdf,
                salt_hex: hex_encode(salt.as_str().as_bytes()),
                nonce_hex: hex_encode(wrapped.nonce.as_slice()),
                tag_hex: hex_encode(wrapped.tag.as_slice()),
                encrypted_transfer_key_hex: hex_encode(wrapped.ciphertext.as_slice()),
            })
        } else {
            None
        };

        let certificate = if let Some(certificate_pem) = certificate_pem {
            let certificate = load_certificate(certificate_pem)?;
            let metadata = certificate_keyslot_metadata(&certificate)?;
            let wrapped = wrap_secret_with_certificate(
                transfer_key.as_slice(),
                &certificate,
                CERTIFICATE_TRANSFER_KEY_AAD,
            )?;
            Some(VaultTransferCertificateAccess {
                wrap_algorithm: CERTIFICATE_WRAP_ALGORITHM.to_string(),
                wrapped_transport_key_der_hex: hex_encode(
                    wrapped.wrapped_transport_key_der.as_slice(),
                ),
                nonce_hex: hex_encode(wrapped.encrypted_secret.nonce.as_slice()),
                tag_hex: hex_encode(wrapped.encrypted_secret.tag.as_slice()),
                encrypted_transfer_key_hex: hex_encode(
                    wrapped.encrypted_secret.ciphertext.as_slice(),
                ),
                certificate_fingerprint_sha256: metadata.fingerprint_sha256,
                certificate_subject: metadata.subject,
                certificate_not_before: metadata.not_before,
                certificate_not_after: metadata.not_after,
                certificate_not_before_epoch: metadata.not_before_epoch,
                certificate_not_after_epoch: metadata.not_after_epoch,
            })
        } else {
            None
        };

        let package = summarize_transfer_items(
            filter.clone(),
            items.iter().map(|item| item.kind.clone()),
            self.header.format_version,
            unix_epoch_now()?,
            VaultTransferAccess {
                recovery,
                certificate,
            },
            payload,
        );
        fs::write(output_path, serde_json::to_vec_pretty(&package)?)?;
        Ok(output_path.to_path_buf())
    }

    pub fn backup_summary(&self) -> Result<VaultBackupSummary, VaultError> {
        let items = self.load_all_items()?;
        Ok(summarize_vault_items(
            self.header.clone(),
            unix_epoch_now()?,
            items.iter().map(|item| item.kind.clone()),
            BACKUP_FORMAT_VERSION,
            self.header.format_version,
        ))
    }

    pub fn import_transfer_package_with_password(
        &self,
        input_path: impl AsRef<Path>,
        recovery_secret: &str,
        replace_existing: bool,
    ) -> Result<VaultTransferImportSummary, VaultError> {
        if recovery_secret.is_empty() {
            return Err(VaultError::InvalidArguments(
                "transfer recovery secret must not be empty".to_string(),
            ));
        }
        let package = read_transfer_package(input_path)?;
        let access = package
            .access
            .recovery
            .clone()
            .ok_or(VaultError::UnlockFailed)?;
        let salt_raw = hex_decode(access.salt_hex.as_str())?;
        let salt_text = String::from_utf8(salt_raw).map_err(|error| {
            VaultError::InvalidArguments(format!("invalid salt encoding: {error}"))
        })?;
        let salt = SaltString::from_b64(salt_text.as_str())
            .map_err(|error| VaultError::Argon2(error.to_string()))?;
        let kek = derive_key(recovery_secret, &salt, &access.kdf)?;
        let transfer_key = decrypt_blob(
            kek.as_slice(),
            TRANSFER_KEY_AAD,
            EncryptedBlob {
                nonce: hex_decode(access.nonce_hex.as_str())?,
                tag: hex_decode(access.tag_hex.as_str())?,
                ciphertext: hex_decode(access.encrypted_transfer_key_hex.as_str())?,
            },
        )
        .map_err(|_| VaultError::UnlockFailed)?;
        let payload = decrypt_transfer_payload(&package, transfer_key.as_slice())?;
        self.import_transfer_payload(payload, replace_existing)
    }

    pub fn import_transfer_package_with_certificate(
        &self,
        input_path: impl AsRef<Path>,
        certificate_pem: &[u8],
        private_key_pem: &[u8],
        private_key_passphrase: Option<&str>,
        replace_existing: bool,
    ) -> Result<VaultTransferImportSummary, VaultError> {
        let package = read_transfer_package(input_path)?;
        let access = package
            .access
            .certificate
            .clone()
            .ok_or(VaultError::UnlockFailed)?;
        let certificate = load_certificate(certificate_pem)?;
        let fingerprint = certificate_fingerprint_hex(&certificate)?;
        if fingerprint != access.certificate_fingerprint_sha256 {
            return Err(VaultError::UnlockFailed);
        }
        let private_key = load_private_key(private_key_pem, private_key_passphrase)?;
        let transfer_key = if access.nonce_hex.is_empty() && access.tag_hex.is_empty() {
            let wrapped = hex_decode(access.wrapped_transport_key_der_hex.as_str())?;
            unwrap_legacy_secret_with_certificate(wrapped.as_slice(), &certificate, &private_key)
        } else {
            unwrap_secret_with_certificate(
                CertificateWrappedSecret {
                    wrapped_transport_key_der: hex_decode(
                        access.wrapped_transport_key_der_hex.as_str(),
                    )?,
                    encrypted_secret: EncryptedBlob {
                        nonce: hex_decode(access.nonce_hex.as_str())?,
                        tag: hex_decode(access.tag_hex.as_str())?,
                        ciphertext: hex_decode(access.encrypted_transfer_key_hex.as_str())?,
                    },
                },
                &certificate,
                &private_key,
                CERTIFICATE_TRANSFER_KEY_AAD,
            )
        }
        .map_err(|_| VaultError::UnlockFailed)?;
        let payload = decrypt_transfer_payload(&package, transfer_key.as_slice())?;
        self.import_transfer_payload(payload, replace_existing)
    }

    fn import_transfer_payload(
        &self,
        payload: VaultTransferPayload,
        replace_existing: bool,
    ) -> Result<VaultTransferImportSummary, VaultError> {
        let mut imported_count = 0;
        let mut replaced_count = 0;
        let mut remapped_count = 0;

        for mut item in payload.items {
            normalize_and_validate_item(&mut item)?;
            match self.load_row(item.id.as_str()) {
                Ok(_) if replace_existing => {
                    replaced_count += 1;
                }
                Ok(_) => {
                    remapped_count += 1;
                    item.id = next_unused_item_id(self)?;
                }
                Err(VaultError::ItemNotFound(_)) => {}
                Err(error) => return Err(error),
            }
            self.store_item(&item)?;
            imported_count += 1;
        }

        Ok(VaultTransferImportSummary {
            imported_count,
            replaced_count,
            remapped_count,
        })
    }

    fn store_item(&self, item: &VaultItem) -> Result<(), VaultError> {
        let plaintext = serde_json::to_vec(item)?;
        let encrypted = encrypt_blob(
            self.master_key.as_slice(),
            &item_aad(item.id.as_str()),
            plaintext.as_slice(),
        )?;
        self.conn.execute(
            "INSERT INTO items (id, kind, created_at_epoch, updated_at_epoch, nonce, tag, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
               kind = excluded.kind,
               updated_at_epoch = excluded.updated_at_epoch,
               nonce = excluded.nonce,
               tag = excluded.tag,
               ciphertext = excluded.ciphertext",
            params![
                item.id,
                item.kind.as_str(),
                item.created_at_epoch,
                item.updated_at_epoch,
                encrypted.nonce,
                encrypted.tag,
                encrypted.ciphertext,
            ],
        )?;
        Ok(())
    }

    fn load_row(&self, id: &str) -> Result<StoredVaultRow, VaultError> {
        self.conn
            .query_row(
                "SELECT id, kind, created_at_epoch, updated_at_epoch, nonce, tag, ciphertext
                 FROM items WHERE id = ?1",
                params![id],
                |row| {
                    Ok(StoredVaultRow {
                        id: row.get(0)?,
                        kind: row.get(1)?,
                        created_at_epoch: row.get(2)?,
                        updated_at_epoch: row.get(3)?,
                        nonce: row.get(4)?,
                        tag: row.get(5)?,
                        ciphertext: row.get(6)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| VaultError::ItemNotFound(id.to_string()))
    }

    fn decrypt_row(&self, row: &StoredVaultRow) -> Result<VaultItem, VaultError> {
        let kind = VaultItemKind::parse(&row.kind)?;
        let plaintext = decrypt_blob(
            self.master_key.as_slice(),
            &item_aad(row.id.as_str()),
            EncryptedBlob {
                nonce: row.nonce.clone(),
                tag: row.tag.clone(),
                ciphertext: row.ciphertext.clone(),
            },
        )?;
        let mut item = serde_json::from_slice::<VaultItem>(plaintext.as_slice())?;
        item.kind = kind;
        item.id = row.id.clone();
        item.created_at_epoch = row.created_at_epoch;
        item.updated_at_epoch = row.updated_at_epoch;
        Ok(item)
    }

    fn persist_header(&self) -> Result<(), VaultError> {
        let affected = self.conn.execute(
            "UPDATE metadata SET value = ?1 WHERE key = 'header_json'",
            params![serde_json::to_string(&self.header)?],
        )?;
        if affected != 1 {
            return Err(VaultError::InvalidArguments(format!(
                "expected to persist exactly one vault header row, updated {affected}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct StoredVaultRow {
    id: String,
    kind: String,
    created_at_epoch: i64,
    updated_at_epoch: i64,
    nonce: Vec<u8>,
    tag: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug)]
struct EncryptedBlob {
    nonce: Vec<u8>,
    tag: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug)]
struct CertificateWrappedSecret {
    wrapped_transport_key_der: Vec<u8>,
    encrypted_secret: EncryptedBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultTransferPayload {
    items: Vec<VaultItem>,
}

pub fn restore_vault_backup(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    overwrite: bool,
) -> Result<VaultHeader, VaultError> {
    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();
    let package: VaultBackupPackage = serde_json::from_slice(&fs::read(input_path)?)?;

    if package.backup_format_version != BACKUP_FORMAT_VERSION {
        return Err(VaultError::InvalidArguments(format!(
            "unsupported backup format version: {}",
            package.backup_format_version
        )));
    }
    if package.vault_format_version != FORMAT_VERSION {
        return Err(VaultError::InvalidArguments(format!(
            "unsupported vault format version in backup: {}",
            package.vault_format_version
        )));
    }
    if package.header.format_version != FORMAT_VERSION {
        return Err(VaultError::InvalidArguments(format!(
            "unsupported header format version in backup: {}",
            package.header.format_version
        )));
    }

    if output_path.exists() {
        if !overwrite {
            return Err(VaultError::VaultExists(output_path.display().to_string()));
        }
        fs::remove_file(output_path)?;
    }
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(output_path)?;
    configure_connection(&conn)?;
    create_schema(&conn)?;
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('header_json', ?1)",
        params![serde_json::to_string(&package.header)?],
    )?;
    for item in &package.items {
        conn.execute(
            "INSERT INTO items (id, kind, created_at_epoch, updated_at_epoch, nonce, tag, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                item.id,
                item.kind,
                item.created_at_epoch,
                item.updated_at_epoch,
                hex_decode(item.nonce_hex.as_str())?,
                hex_decode(item.tag_hex.as_str())?,
                hex_decode(item.ciphertext_hex.as_str())?,
            ],
        )?;
    }
    Ok(package.header)
}

pub fn inspect_vault_backup(
    input_path: impl AsRef<Path>,
) -> Result<VaultBackupSummary, VaultError> {
    let package: VaultBackupPackage = serde_json::from_slice(&fs::read(input_path.as_ref())?)?;
    Ok(summarize_backup_package(&package))
}

pub fn inspect_vault_transfer(
    input_path: impl AsRef<Path>,
) -> Result<VaultTransferSummary, VaultError> {
    let package: VaultTransferPackage = serde_json::from_slice(&fs::read(input_path.as_ref())?)?;
    Ok(summarize_transfer_package(&package))
}

pub fn init_vault(
    path: impl AsRef<Path>,
    master_password: &str,
) -> Result<VaultHeader, VaultError> {
    let path = path.as_ref();
    if path.exists() {
        return Err(VaultError::VaultExists(path.display().to_string()));
    }
    if master_password.is_empty() {
        return Err(VaultError::InvalidArguments(
            "master password must not be empty".to_string(),
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(path)?;
    configure_connection(&conn)?;
    create_schema(&conn)?;

    let salt_bytes = random_bytes(16)?;
    let salt = SaltString::encode_b64(salt_bytes.as_slice())
        .map_err(|error| VaultError::Argon2(error.to_string()))?;
    let params = VaultKdfParams {
        algorithm: "argon2id".to_string(),
        memory_cost_kib: DEFAULT_MEMORY_COST_KIB,
        iterations: DEFAULT_ITERATIONS,
        parallelism: DEFAULT_PARALLELISM,
        derived_key_len: MASTER_KEY_LEN,
    };
    let kek = derive_key(master_password, &salt, &params)?;
    let master_key = random_bytes(MASTER_KEY_LEN)?;
    let wrapped = encrypt_blob(kek.as_slice(), MASTER_KEY_AAD, master_key.as_slice())?;

    let header = VaultHeader {
        format_version: FORMAT_VERSION,
        created_at_epoch: unix_epoch_now()?,
        migration_state: "ready".to_string(),
        kdf: params,
        keyslots: vec![VaultKeyslot {
            id: "recovery".to_string(),
            kind: VaultKeyslotKind::PasswordRecovery,
            label: Some("password-recovery".to_string()),
            wrapped_by_os_keystore: false,
            wrap_algorithm: PASSWORD_WRAP_ALGORITHM.to_string(),
            salt_hex: hex_encode(salt.as_str().as_bytes()),
            nonce_hex: hex_encode(&wrapped.nonce),
            tag_hex: hex_encode(&wrapped.tag),
            encrypted_master_key_hex: hex_encode(&wrapped.ciphertext),
            certificate_fingerprint_sha256: None,
            certificate_subject: None,
            certificate_not_before: None,
            certificate_not_after: None,
            certificate_not_before_epoch: None,
            certificate_not_after_epoch: None,
            mnemonic_language: None,
            mnemonic_words: None,
            device_service: None,
            device_account: None,
        }],
    };

    conn.execute(
        "INSERT INTO metadata (key, value) VALUES (?1, ?2)",
        params!["header_json", serde_json::to_string(&header)?],
    )?;

    Ok(header)
}

pub fn read_vault_header(path: impl AsRef<Path>) -> Result<VaultHeader, VaultError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(VaultError::VaultNotFound(path.display().to_string()));
    }
    let conn = Connection::open(path)?;
    configure_connection(&conn)?;
    read_header(&conn)
}

pub fn unlock_vault(
    path: impl AsRef<Path>,
    master_password: &str,
) -> Result<UnlockedVault, VaultError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(VaultError::VaultNotFound(path.display().to_string()));
    }
    let conn = Connection::open(path)?;
    configure_connection(&conn)?;
    let header = read_header(&conn)?;
    let keyslot = header
        .keyslots
        .iter()
        .find(|keyslot| keyslot.kind == VaultKeyslotKind::PasswordRecovery)
        .ok_or_else(|| {
            VaultError::InvalidArguments("vault has no password recovery keyslot".to_string())
        })?;
    let salt_raw = hex_decode(keyslot.salt_hex.as_str())?;
    let salt_text = String::from_utf8(salt_raw)
        .map_err(|error| VaultError::InvalidArguments(format!("invalid salt encoding: {error}")))?;
    let salt = SaltString::from_b64(salt_text.as_str())
        .map_err(|error| VaultError::Argon2(error.to_string()))?;
    let kek = derive_key(master_password, &salt, &header.kdf)?;
    let master_key = decrypt_blob(
        kek.as_slice(),
        MASTER_KEY_AAD,
        EncryptedBlob {
            nonce: hex_decode(keyslot.nonce_hex.as_str())?,
            tag: hex_decode(keyslot.tag_hex.as_str())?,
            ciphertext: hex_decode(keyslot.encrypted_master_key_hex.as_str())?,
        },
    )
    .map_err(|_| VaultError::UnlockFailed)?;

    Ok(UnlockedVault {
        path: path.to_path_buf(),
        conn,
        header,
        master_key: Zeroizing::new(master_key),
    })
}

pub fn unlock_vault_with_certificate(
    path: impl AsRef<Path>,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    private_key_passphrase: Option<&str>,
) -> Result<UnlockedVault, VaultError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(VaultError::VaultNotFound(path.display().to_string()));
    }

    let conn = Connection::open(path)?;
    configure_connection(&conn)?;
    let header = read_header(&conn)?;

    let certificate = load_certificate(certificate_pem)?;
    let fingerprint = certificate_fingerprint_hex(&certificate)?;
    let keyslot = header
        .keyslots
        .iter()
        .find(|keyslot| {
            keyslot.kind == VaultKeyslotKind::CertificateWrapped
                && keyslot.certificate_fingerprint_sha256.as_deref() == Some(fingerprint.as_str())
        })
        .ok_or(VaultError::UnlockFailed)?;
    let private_key = load_private_key(private_key_pem, private_key_passphrase)?;
    let master_key = if keyslot.wrap_algorithm == LEGACY_CERTIFICATE_WRAP_ALGORITHM
        && keyslot.salt_hex.is_empty()
        && keyslot.nonce_hex.is_empty()
        && keyslot.tag_hex.is_empty()
    {
        let wrapped = hex_decode(keyslot.encrypted_master_key_hex.as_str())?;
        unwrap_legacy_secret_with_certificate(wrapped.as_slice(), &certificate, &private_key)
    } else {
        unwrap_secret_with_certificate(
            CertificateWrappedSecret {
                wrapped_transport_key_der: hex_decode(keyslot.salt_hex.as_str())?,
                encrypted_secret: EncryptedBlob {
                    nonce: hex_decode(keyslot.nonce_hex.as_str())?,
                    tag: hex_decode(keyslot.tag_hex.as_str())?,
                    ciphertext: hex_decode(keyslot.encrypted_master_key_hex.as_str())?,
                },
            },
            &certificate,
            &private_key,
            CERTIFICATE_MASTER_KEY_AAD,
        )
    }
    .map_err(|_| VaultError::UnlockFailed)?;

    Ok(UnlockedVault {
        path: path.to_path_buf(),
        conn,
        header,
        master_key: Zeroizing::new(master_key),
    })
}

pub fn unlock_vault_with_mnemonic(
    path: impl AsRef<Path>,
    mnemonic_phrase: &str,
    slot_id: Option<&str>,
) -> Result<UnlockedVault, VaultError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(VaultError::VaultNotFound(path.display().to_string()));
    }

    let conn = Connection::open(path)?;
    configure_connection(&conn)?;
    let header = read_header(&conn)?;
    let keyslot = select_mnemonic_keyslot(&header, slot_id)?;
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)
        .map_err(|_| VaultError::UnlockFailed)?;
    let mnemonic_entropy = mnemonic.to_entropy();
    if mnemonic_entropy.len() != MASTER_KEY_LEN {
        return Err(VaultError::UnlockFailed);
    }

    let master_key = decrypt_blob(
        mnemonic_entropy.as_slice(),
        &mnemonic_slot_aad(keyslot.id.as_str()),
        EncryptedBlob {
            nonce: hex_decode(keyslot.nonce_hex.as_str())?,
            tag: hex_decode(keyslot.tag_hex.as_str())?,
            ciphertext: hex_decode(keyslot.encrypted_master_key_hex.as_str())?,
        },
    )
    .map_err(|_| VaultError::UnlockFailed)?;

    Ok(UnlockedVault {
        path: path.to_path_buf(),
        conn,
        header,
        master_key: Zeroizing::new(master_key),
    })
}

pub fn unlock_vault_with_device(
    path: impl AsRef<Path>,
    slot_id: Option<&str>,
) -> Result<UnlockedVault, VaultError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(VaultError::VaultNotFound(path.display().to_string()));
    }

    let conn = Connection::open(path)?;
    configure_connection(&conn)?;
    let header = read_header(&conn)?;
    let keyslot = select_device_keyslot(&header, slot_id)?;
    let service = keyslot.device_service.as_deref().ok_or_else(|| {
        VaultError::InvalidArguments(format!(
            "device keyslot {} has no service metadata",
            keyslot.id
        ))
    })?;
    let account = keyslot.device_account.as_deref().ok_or_else(|| {
        VaultError::InvalidArguments(format!(
            "device keyslot {} has no account metadata",
            keyslot.id
        ))
    })?;
    let master_key = Zeroizing::new(device_store_get_secret(service, account)?);
    let plaintext = decrypt_blob(
        master_key.as_slice(),
        &device_slot_aad(keyslot.id.as_str()),
        EncryptedBlob {
            nonce: hex_decode(keyslot.nonce_hex.as_str())?,
            tag: hex_decode(keyslot.tag_hex.as_str())?,
            ciphertext: hex_decode(keyslot.encrypted_master_key_hex.as_str())?,
        },
    )
    .map_err(|_| VaultError::UnlockFailed)?;
    if plaintext.as_slice() != DEVICE_CHECK_PLAINTEXT {
        return Err(VaultError::UnlockFailed);
    }

    Ok(UnlockedVault {
        path: path.to_path_buf(),
        conn,
        header,
        master_key,
    })
}

fn create_schema(conn: &Connection) -> Result<(), VaultError> {
    let pragmas = sqlite_format_pragmas_sql();
    conn.execute_batch(
        format!(
            "BEGIN;
         {pragmas}
         CREATE TABLE metadata (
           key TEXT PRIMARY KEY,
           value TEXT NOT NULL
         );
         CREATE TABLE items (
           id TEXT PRIMARY KEY,
           kind TEXT NOT NULL,
           created_at_epoch INTEGER NOT NULL,
           updated_at_epoch INTEGER NOT NULL,
           nonce BLOB NOT NULL,
           tag BLOB NOT NULL,
           ciphertext BLOB NOT NULL
         );
         COMMIT;"
        )
        .as_str(),
    )?;
    Ok(())
}

fn configure_connection(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA secure_delete = ON;
         PRAGMA temp_store = MEMORY;
         PRAGMA journal_mode = DELETE;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(())
}

fn read_header(conn: &Connection) -> Result<VaultHeader, VaultError> {
    let application_id: i64 = conn.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let user_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let header_json: String = conn.query_row(
        "SELECT value FROM metadata WHERE key = 'header_json'",
        [],
        |row| row.get(0),
    )?;
    let header: VaultHeader = serde_json::from_str(&header_json)?;
    if header.format_version != FORMAT_VERSION {
        return Err(VaultError::InvalidArguments(format!(
            "unsupported vault format version: {}",
            header.format_version
        )));
    }

    if application_id == 0 && user_version == 0 {
        let pragmas = sqlite_format_pragmas_sql();
        conn.execute_batch(pragmas.as_str())?;
    } else {
        if application_id != SQLITE_APPLICATION_ID {
            return Err(VaultError::InvalidArguments(format!(
                "unexpected vault application_id: {application_id}"
            )));
        }
        if user_version != i64::from(FORMAT_VERSION) {
            return Err(VaultError::InvalidArguments(format!(
                "unsupported vault schema version: {user_version}"
            )));
        }
    }

    Ok(header)
}

fn derive_key(
    master_password: &str,
    salt: &SaltString,
    params: &VaultKdfParams,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let argon_params = Params::new(
        params.memory_cost_kib,
        params.iterations,
        params.parallelism,
        Some(params.derived_key_len),
    )
    .map_err(|error| VaultError::Argon2(error.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut derived = Zeroizing::new(vec![0_u8; params.derived_key_len]);
    argon
        .hash_password_into(
            master_password.as_bytes(),
            salt.as_salt().as_str().as_bytes(),
            derived.as_mut_slice(),
        )
        .map_err(|error| VaultError::Argon2(error.to_string()))?;
    Ok(derived)
}

fn default_transfer_kdf_params() -> VaultKdfParams {
    VaultKdfParams {
        algorithm: "argon2id".to_string(),
        memory_cost_kib: DEFAULT_MEMORY_COST_KIB,
        iterations: DEFAULT_ITERATIONS,
        parallelism: DEFAULT_PARALLELISM,
        derived_key_len: MASTER_KEY_LEN,
    }
}

fn encrypt_blob(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<EncryptedBlob, VaultError> {
    let cipher = Cipher::aes_256_gcm();
    let nonce = random_bytes(12)?;
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce.as_slice()))
        .map_err(|error| VaultError::CryptoFailure(error.to_string()))?;
    crypter
        .aad_update(aad)
        .map_err(|error| VaultError::CryptoFailure(error.to_string()))?;
    let mut ciphertext = vec![0_u8; plaintext.len() + cipher.block_size()];
    let mut count = crypter
        .update(plaintext, ciphertext.as_mut_slice())
        .map_err(|error| VaultError::CryptoFailure(error.to_string()))?;
    count += crypter
        .finalize(&mut ciphertext[count..])
        .map_err(|error| VaultError::CryptoFailure(error.to_string()))?;
    ciphertext.truncate(count);
    let mut tag = vec![0_u8; 16];
    crypter
        .get_tag(tag.as_mut_slice())
        .map_err(|error| VaultError::CryptoFailure(error.to_string()))?;
    Ok(EncryptedBlob {
        nonce,
        tag,
        ciphertext,
    })
}

fn decrypt_blob(key: &[u8], aad: &[u8], blob: EncryptedBlob) -> Result<Vec<u8>, VaultError> {
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(blob.nonce.as_slice()))
        .map_err(|error| VaultError::CryptoFailure(error.to_string()))?;
    crypter
        .aad_update(aad)
        .map_err(|error| VaultError::CryptoFailure(error.to_string()))?;
    crypter
        .set_tag(blob.tag.as_slice())
        .map_err(|error| VaultError::CryptoFailure(error.to_string()))?;
    let mut plaintext = vec![0_u8; blob.ciphertext.len() + cipher.block_size()];
    let mut count = crypter
        .update(blob.ciphertext.as_slice(), plaintext.as_mut_slice())
        .map_err(|error| VaultError::CryptoFailure(error.to_string()))?;
    count += crypter
        .finalize(&mut plaintext[count..])
        .map_err(|error| VaultError::CryptoFailure(error.to_string()))?;
    plaintext.truncate(count);
    Ok(plaintext)
}

fn validate_login_record(record: &NewLoginRecord) -> Result<(), VaultError> {
    if record.title.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault title must not be empty".to_string(),
        ));
    }
    if record.username.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault username must not be empty".to_string(),
        ));
    }
    if record.password.is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault password must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_secure_note_record(record: &NewSecureNoteRecord) -> Result<(), VaultError> {
    if record.title.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault secure note title must not be empty".to_string(),
        ));
    }
    if record.content.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault secure note content must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_card_record(record: &NewCardRecord) -> Result<(), VaultError> {
    if record.title.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault card title must not be empty".to_string(),
        ));
    }
    if record.cardholder_name.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault cardholder name must not be empty".to_string(),
        ));
    }
    if record.number.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault card number must not be empty".to_string(),
        ));
    }
    if record.expiry_month.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault expiry month must not be empty".to_string(),
        ));
    }
    if record.expiry_year.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault expiry year must not be empty".to_string(),
        ));
    }
    if record.security_code.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault security code must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_identity_record(record: &NewIdentityRecord) -> Result<(), VaultError> {
    if record.title.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault identity title must not be empty".to_string(),
        ));
    }
    if record.full_name.trim().is_empty() {
        return Err(VaultError::InvalidArguments(
            "vault identity full name must not be empty".to_string(),
        ));
    }
    if record
        .email
        .as_deref()
        .map(str::trim)
        .is_some_and(str::is_empty)
    {
        return Err(VaultError::InvalidArguments(
            "vault identity email must not be empty when provided".to_string(),
        ));
    }
    if record
        .phone
        .as_deref()
        .map(str::trim)
        .is_some_and(str::is_empty)
    {
        return Err(VaultError::InvalidArguments(
            "vault identity phone must not be empty when provided".to_string(),
        ));
    }
    Ok(())
}

fn card_number_preview(number: &str) -> String {
    let trimmed = number.trim();
    let tail: String = trimmed
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if tail.is_empty() {
        "card".to_string()
    } else {
        format!("•••• {tail}")
    }
}

fn item_summary(item: &VaultItem, duplicate_password_count: usize) -> VaultItemSummary {
    match &item.payload {
        VaultItemPayload::Login(login) => VaultItemSummary {
            id: item.id.clone(),
            kind: item.kind.clone(),
            title: login.title.clone(),
            subtitle: login.username.clone(),
            location: login.url.clone(),
            folder: login.folder.clone(),
            updated_at_epoch: item.updated_at_epoch,
            duplicate_password_count,
        },
        VaultItemPayload::SecureNote(note) => VaultItemSummary {
            id: item.id.clone(),
            kind: item.kind.clone(),
            title: note.title.clone(),
            subtitle: secure_note_preview(&note.content),
            location: None,
            folder: note.folder.clone(),
            updated_at_epoch: item.updated_at_epoch,
            duplicate_password_count: 0,
        },
        VaultItemPayload::Card(card) => VaultItemSummary {
            id: item.id.clone(),
            kind: item.kind.clone(),
            title: card.title.clone(),
            subtitle: format!(
                "{} · {}",
                card.cardholder_name,
                card_number_preview(&card.number)
            ),
            location: Some(format!("{}/{}", card.expiry_month, card.expiry_year)),
            folder: card.folder.clone(),
            updated_at_epoch: item.updated_at_epoch,
            duplicate_password_count: 0,
        },
        VaultItemPayload::Identity(identity) => VaultItemSummary {
            id: item.id.clone(),
            kind: item.kind.clone(),
            title: identity.title.clone(),
            subtitle: identity.full_name.clone(),
            location: identity.email.clone().or_else(|| identity.phone.clone()),
            folder: identity.folder.clone(),
            updated_at_epoch: item.updated_at_epoch,
            duplicate_password_count: 0,
        },
    }
}

fn duplicate_password_counts(items: &[VaultItem]) -> HashMap<String, usize> {
    let mut password_totals = HashMap::<String, usize>::new();
    for item in items {
        if let VaultItemPayload::Login(login) = &item.payload {
            *password_totals.entry(login.password.clone()).or_insert(0) += 1;
        }
    }

    let mut duplicate_counts = HashMap::new();
    for item in items {
        if let VaultItemPayload::Login(login) = &item.payload {
            let total = password_totals
                .get(login.password.as_str())
                .copied()
                .unwrap_or(0);
            if total > 1 {
                duplicate_counts.insert(item.id.clone(), total - 1);
            }
        }
    }

    duplicate_counts
}

fn summarize_backup_package(package: &VaultBackupPackage) -> VaultBackupSummary {
    let kinds = package
        .items
        .iter()
        .map(|item| VaultItemKind::parse(&item.kind));
    summarize_vault_item_kind_results(
        package.header.clone(),
        package.exported_at_epoch,
        kinds,
        package.backup_format_version,
        package.vault_format_version,
    )
}

fn summarize_transfer_items<I>(
    filter: VaultItemFilter,
    kinds: I,
    source_vault_format_version: u32,
    exported_at_epoch: i64,
    access: VaultTransferAccess,
    payload: EncryptedBlob,
) -> VaultTransferPackage
where
    I: IntoIterator<Item = VaultItemKind>,
{
    let mut item_count = 0;
    let mut login_count = 0;
    let mut secure_note_count = 0;
    let mut card_count = 0;
    let mut identity_count = 0;

    for kind in kinds {
        item_count += 1;
        match kind {
            VaultItemKind::Login => login_count += 1,
            VaultItemKind::SecureNote => secure_note_count += 1,
            VaultItemKind::Card => card_count += 1,
            VaultItemKind::Identity => identity_count += 1,
        }
    }

    VaultTransferPackage {
        transfer_format_version: TRANSFER_FORMAT_VERSION,
        exported_at_epoch,
        source_vault_format_version,
        item_count,
        login_count,
        secure_note_count,
        card_count,
        identity_count,
        filter,
        access,
        payload_nonce_hex: hex_encode(payload.nonce.as_slice()),
        payload_tag_hex: hex_encode(payload.tag.as_slice()),
        payload_ciphertext_hex: hex_encode(payload.ciphertext.as_slice()),
    }
}

fn summarize_transfer_package(package: &VaultTransferPackage) -> VaultTransferSummary {
    let mut warnings = Vec::new();
    let importable_by_current_build = package.transfer_format_version == TRANSFER_FORMAT_VERSION
        && package.source_vault_format_version == FORMAT_VERSION;

    if package.transfer_format_version != TRANSFER_FORMAT_VERSION {
        warnings.push(format!(
            "Transfer format version {} is not supported by the current build.",
            package.transfer_format_version
        ));
    }
    if package.source_vault_format_version != FORMAT_VERSION {
        warnings.push(format!(
            "Source vault format version {} is not supported by the current build.",
            package.source_vault_format_version
        ));
    }
    if package.access.recovery.is_none() {
        warnings
            .push("Transfer package does not include a recovery-secret unwrap path.".to_string());
    }
    if package.access.certificate.is_none() {
        warnings.push("Transfer package does not include a certificate unwrap path.".to_string());
    }
    if let Some(certificate) = &package.access.certificate {
        warnings.extend(
            certificate_validity_warnings(
                certificate.certificate_not_before_epoch,
                certificate.certificate_not_after_epoch,
            )
            .into_iter()
            .map(|warning| format!("certificate access: {warning}")),
        );
    }

    VaultTransferSummary {
        transfer_format_version: package.transfer_format_version,
        exported_at_epoch: package.exported_at_epoch,
        source_vault_format_version: package.source_vault_format_version,
        item_count: package.item_count,
        login_count: package.login_count,
        secure_note_count: package.secure_note_count,
        card_count: package.card_count,
        identity_count: package.identity_count,
        filter: package.filter.clone(),
        has_recovery_path: package.access.recovery.is_some(),
        has_certificate_path: package.access.certificate.is_some(),
        certificate_fingerprint_sha256: package
            .access
            .certificate
            .as_ref()
            .map(|certificate| certificate.certificate_fingerprint_sha256.clone()),
        certificate_subject: package
            .access
            .certificate
            .as_ref()
            .map(|certificate| certificate.certificate_subject.clone()),
        certificate_not_after: package
            .access
            .certificate
            .as_ref()
            .map(|certificate| certificate.certificate_not_after.clone()),
        warnings,
        importable_by_current_build,
    }
}

fn summarize_vault_items<I>(
    header: VaultHeader,
    exported_at_epoch: i64,
    kinds: I,
    backup_format_version: u32,
    vault_format_version: u32,
) -> VaultBackupSummary
where
    I: IntoIterator<Item = VaultItemKind>,
{
    summarize_vault_item_kind_results(
        header,
        exported_at_epoch,
        kinds.into_iter().map(Ok),
        backup_format_version,
        vault_format_version,
    )
}

fn summarize_vault_item_kind_results<I>(
    header: VaultHeader,
    exported_at_epoch: i64,
    kinds: I,
    backup_format_version: u32,
    vault_format_version: u32,
) -> VaultBackupSummary
where
    I: IntoIterator<Item = Result<VaultItemKind, VaultError>>,
{
    let mut item_count = 0;
    let mut login_count = 0;
    let mut secure_note_count = 0;
    let mut card_count = 0;
    let mut identity_count = 0;
    let mut warnings = Vec::new();
    let mut restorable_by_current_build = backup_format_version == BACKUP_FORMAT_VERSION
        && vault_format_version == FORMAT_VERSION
        && header.format_version == FORMAT_VERSION;

    for kind in kinds {
        item_count += 1;
        match kind {
            Ok(VaultItemKind::Login) => login_count += 1,
            Ok(VaultItemKind::SecureNote) => secure_note_count += 1,
            Ok(VaultItemKind::Card) => card_count += 1,
            Ok(VaultItemKind::Identity) => identity_count += 1,
            Err(error) => {
                warnings.push(error.to_string());
                restorable_by_current_build = false;
            }
        }
    }

    if backup_format_version != BACKUP_FORMAT_VERSION {
        warnings.push(format!(
            "Backup format version {backup_format_version} is not supported by the current build."
        ));
    }
    if vault_format_version != FORMAT_VERSION {
        warnings.push(format!(
            "Vault format version {vault_format_version} is not supported by the current build."
        ));
    }
    if header.format_version != FORMAT_VERSION {
        warnings.push(format!(
            "Header format version {} is not supported by the current build.",
            header.format_version
        ));
    }

    let recovery_posture = header.recovery_posture();
    let keyslots = header
        .keyslots
        .iter()
        .map(|keyslot| VaultBackupKeyslotSummary {
            id: keyslot.id.clone(),
            kind: keyslot.kind.clone(),
            label: keyslot.label.clone(),
            wrap_algorithm: keyslot.wrap_algorithm.clone(),
            certificate_fingerprint_sha256: keyslot.certificate_fingerprint_sha256.clone(),
            certificate_subject: keyslot.certificate_subject.clone(),
            certificate_not_before: keyslot.certificate_not_before.clone(),
            certificate_not_after: keyslot.certificate_not_after.clone(),
            certificate_not_before_epoch: keyslot.certificate_not_before_epoch,
            certificate_not_after_epoch: keyslot.certificate_not_after_epoch,
        })
        .collect();
    for health in header.keyslot_health_summaries() {
        for warning in health.warnings {
            warnings.push(format!("keyslot {}: {warning}", health.keyslot_id));
        }
    }

    VaultBackupSummary {
        backup_format_version,
        exported_at_epoch,
        vault_format_version,
        header_format_version: header.format_version,
        item_count,
        login_count,
        secure_note_count,
        card_count,
        identity_count,
        keyslot_count: header.keyslots.len(),
        recovery_posture,
        keyslots,
        warnings,
        restorable_by_current_build,
    }
}

fn item_matches_filter(item: &VaultItem, filter: &NormalizedVaultItemFilter) -> bool {
    if filter.kind.as_ref().is_some_and(|kind| &item.kind != kind) {
        return false;
    }

    if filter
        .folder
        .as_deref()
        .is_some_and(|folder| !item_has_folder(item, folder))
    {
        return false;
    }

    if filter
        .tag
        .as_deref()
        .is_some_and(|tag| !item_has_tag(item, tag))
    {
        return false;
    }

    filter
        .query
        .as_deref()
        .is_none_or(|query| item_matches_query(item, query))
}

fn read_transfer_package(input_path: impl AsRef<Path>) -> Result<VaultTransferPackage, VaultError> {
    let package: VaultTransferPackage = serde_json::from_slice(&fs::read(input_path.as_ref())?)?;
    if package.transfer_format_version != TRANSFER_FORMAT_VERSION {
        return Err(VaultError::InvalidArguments(format!(
            "unsupported transfer format version: {}",
            package.transfer_format_version
        )));
    }
    if package.source_vault_format_version != FORMAT_VERSION {
        return Err(VaultError::InvalidArguments(format!(
            "unsupported source vault format version in transfer package: {}",
            package.source_vault_format_version
        )));
    }
    if package.access.recovery.is_none() && package.access.certificate.is_none() {
        return Err(VaultError::InvalidArguments(
            "transfer package has no supported unwrap path".to_string(),
        ));
    }
    Ok(package)
}

fn decrypt_transfer_payload(
    package: &VaultTransferPackage,
    transfer_key: &[u8],
) -> Result<VaultTransferPayload, VaultError> {
    let plaintext = decrypt_blob(
        transfer_key,
        TRANSFER_PAYLOAD_AAD,
        EncryptedBlob {
            nonce: hex_decode(package.payload_nonce_hex.as_str())?,
            tag: hex_decode(package.payload_tag_hex.as_str())?,
            ciphertext: hex_decode(package.payload_ciphertext_hex.as_str())?,
        },
    )
    .map_err(|_| VaultError::UnlockFailed)?;
    Ok(serde_json::from_slice(plaintext.as_slice())?)
}

fn normalize_and_validate_item(item: &mut VaultItem) -> Result<(), VaultError> {
    match &mut item.payload {
        VaultItemPayload::Login(login) => {
            if item.kind != VaultItemKind::Login {
                return Err(VaultError::InvalidArguments(format!(
                    "vault item {} payload kind mismatch",
                    item.id
                )));
            }
            login.folder = normalize_folder(login.folder.clone());
            login.tags = normalize_tags(login.tags.as_slice());
            validate_login_record(&NewLoginRecord {
                title: login.title.clone(),
                username: login.username.clone(),
                password: login.password.clone(),
                url: login.url.clone(),
                notes: login.notes.clone(),
                folder: login.folder.clone(),
                tags: login.tags.clone(),
            })?;
        }
        VaultItemPayload::SecureNote(note) => {
            if item.kind != VaultItemKind::SecureNote {
                return Err(VaultError::InvalidArguments(format!(
                    "vault item {} payload kind mismatch",
                    item.id
                )));
            }
            note.folder = normalize_folder(note.folder.clone());
            note.tags = normalize_tags(note.tags.as_slice());
            validate_secure_note_record(&NewSecureNoteRecord {
                title: note.title.clone(),
                content: note.content.clone(),
                folder: note.folder.clone(),
                tags: note.tags.clone(),
            })?;
        }
        VaultItemPayload::Card(card) => {
            if item.kind != VaultItemKind::Card {
                return Err(VaultError::InvalidArguments(format!(
                    "vault item {} payload kind mismatch",
                    item.id
                )));
            }
            card.folder = normalize_folder(card.folder.clone());
            card.tags = normalize_tags(card.tags.as_slice());
            validate_card_record(&NewCardRecord {
                title: card.title.clone(),
                cardholder_name: card.cardholder_name.clone(),
                number: card.number.clone(),
                expiry_month: card.expiry_month.clone(),
                expiry_year: card.expiry_year.clone(),
                security_code: card.security_code.clone(),
                billing_zip: card.billing_zip.clone(),
                notes: card.notes.clone(),
                folder: card.folder.clone(),
                tags: card.tags.clone(),
            })?;
        }
        VaultItemPayload::Identity(identity) => {
            if item.kind != VaultItemKind::Identity {
                return Err(VaultError::InvalidArguments(format!(
                    "vault item {} payload kind mismatch",
                    item.id
                )));
            }
            identity.folder = normalize_folder(identity.folder.clone());
            identity.tags = normalize_tags(identity.tags.as_slice());
            validate_identity_record(&NewIdentityRecord {
                title: identity.title.clone(),
                full_name: identity.full_name.clone(),
                email: identity.email.clone(),
                phone: identity.phone.clone(),
                address: identity.address.clone(),
                notes: identity.notes.clone(),
                folder: identity.folder.clone(),
                tags: identity.tags.clone(),
            })?;
        }
    }
    Ok(())
}

fn item_has_folder(item: &VaultItem, normalized_folder: &str) -> bool {
    item_folder(item)
        .map(|value| value.eq_ignore_ascii_case(normalized_folder))
        .unwrap_or(false)
}

fn item_has_tag(item: &VaultItem, normalized_tag: &str) -> bool {
    item_tags(item)
        .iter()
        .any(|tag| tag.eq_ignore_ascii_case(normalized_tag))
}

fn item_folder(item: &VaultItem) -> Option<&str> {
    match &item.payload {
        VaultItemPayload::Login(login) => login.folder.as_deref(),
        VaultItemPayload::SecureNote(note) => note.folder.as_deref(),
        VaultItemPayload::Card(card) => card.folder.as_deref(),
        VaultItemPayload::Identity(identity) => identity.folder.as_deref(),
    }
}

fn item_tags(item: &VaultItem) -> &[String] {
    match &item.payload {
        VaultItemPayload::Login(login) => &login.tags,
        VaultItemPayload::SecureNote(note) => &note.tags,
        VaultItemPayload::Card(card) => &card.tags,
        VaultItemPayload::Identity(identity) => &identity.tags,
    }
}

fn item_matches_query(item: &VaultItem, normalized_query: &str) -> bool {
    field_matches(&item.id, normalized_query)
        || field_matches(item.kind.as_str(), normalized_query)
        || match &item.payload {
            VaultItemPayload::Login(login) => {
                field_matches(&login.title, normalized_query)
                    || field_matches(&login.username, normalized_query)
                    || login
                        .folder
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
                    || login
                        .tags
                        .iter()
                        .any(|tag| field_matches(tag, normalized_query))
                    || login
                        .url
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
                    || login
                        .notes
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
            }
            VaultItemPayload::SecureNote(note) => {
                field_matches(&note.title, normalized_query)
                    || field_matches(&note.content, normalized_query)
                    || note
                        .folder
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
                    || note
                        .tags
                        .iter()
                        .any(|tag| field_matches(tag, normalized_query))
            }
            VaultItemPayload::Card(card) => {
                field_matches(&card.title, normalized_query)
                    || field_matches(&card.cardholder_name, normalized_query)
                    || field_matches(&card.number, normalized_query)
                    || field_matches(&card.expiry_month, normalized_query)
                    || field_matches(&card.expiry_year, normalized_query)
                    || field_matches(&card.security_code, normalized_query)
                    || card
                        .billing_zip
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
                    || card
                        .notes
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
                    || card
                        .folder
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
                    || card
                        .tags
                        .iter()
                        .any(|tag| field_matches(tag, normalized_query))
            }
            VaultItemPayload::Identity(identity) => {
                field_matches(&identity.title, normalized_query)
                    || field_matches(&identity.full_name, normalized_query)
                    || identity
                        .email
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
                    || identity
                        .phone
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
                    || identity
                        .address
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
                    || identity
                        .notes
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
                    || identity
                        .folder
                        .as_deref()
                        .map(|value| field_matches(value, normalized_query))
                        .unwrap_or(false)
                    || identity
                        .tags
                        .iter()
                        .any(|tag| field_matches(tag, normalized_query))
            }
        }
}

fn field_matches(value: &str, normalized_query: &str) -> bool {
    value.to_ascii_lowercase().contains(normalized_query)
}

fn secure_note_preview(content: &str) -> String {
    let normalized = content
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if normalized.is_empty() {
        return "secure note".to_string();
    }
    let mut preview = String::new();
    for ch in normalized.chars().take(48) {
        preview.push(ch);
    }
    if normalized.chars().count() > 48 {
        preview.push('…');
    }
    preview
}

fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for tag in tags {
        let trimmed = tag.trim();
        if trimmed.is_empty() {
            continue;
        }
        if normalized
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(trimmed))
        {
            continue;
        }
        normalized.push(trimmed.to_string());
    }
    normalized
}

fn normalize_folder(folder: Option<String>) -> Option<String> {
    folder.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn random_hex_id(len: usize) -> Result<String, VaultError> {
    Ok(hex_encode(random_bytes(len)?.as_slice()))
}

fn next_unused_item_id(vault: &UnlockedVault) -> Result<String, VaultError> {
    loop {
        let candidate = random_hex_id(16)?;
        match vault.load_row(candidate.as_str()) {
            Ok(_) => continue,
            Err(VaultError::ItemNotFound(_)) => return Ok(candidate),
            Err(error) => return Err(error),
        }
    }
}

fn random_bytes(len: usize) -> Result<Vec<u8>, VaultError> {
    let mut bytes = vec![0_u8; len];
    rand_bytes(bytes.as_mut_slice())
        .map_err(|error| VaultError::RandomFailure(error.to_string()))?;
    Ok(bytes)
}

fn load_certificate(certificate_pem: &[u8]) -> Result<X509, VaultError> {
    X509::from_pem(certificate_pem)
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))
}

fn load_private_key(
    private_key_pem: &[u8],
    passphrase: Option<&str>,
) -> Result<PKey<Private>, VaultError> {
    let result = match passphrase {
        Some(passphrase) => {
            PKey::private_key_from_pem_passphrase(private_key_pem, passphrase.as_bytes())
        }
        None => PKey::private_key_from_pem(private_key_pem),
    };
    result.map_err(|error| VaultError::CertificateFailure(error.to_string()))
}

fn certificate_fingerprint_hex(certificate: &X509) -> Result<String, VaultError> {
    let digest = certificate
        .digest(MessageDigest::sha256())
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))?;
    Ok(hex_encode(digest.as_ref()))
}

fn certificate_keyslot_metadata(
    certificate: &X509,
) -> Result<CertificateKeyslotMetadata, VaultError> {
    Ok(CertificateKeyslotMetadata {
        fingerprint_sha256: certificate_fingerprint_hex(certificate)?,
        subject: format_x509_name(certificate.subject_name()),
        not_before: certificate.not_before().to_string(),
        not_after: certificate.not_after().to_string(),
        not_before_epoch: certificate_time_to_epoch(certificate.not_before())?,
        not_after_epoch: certificate_time_to_epoch(certificate.not_after())?,
    })
}

fn certificate_time_to_epoch(time: &openssl::asn1::Asn1TimeRef) -> Result<i64, VaultError> {
    let epoch = Asn1Time::from_unix(0)
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))?;
    let diff = epoch
        .diff(time)
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))?;
    let days = i64::from(diff.days);
    let secs = i64::from(diff.secs);
    days.checked_mul(24 * 60 * 60)
        .and_then(|base| base.checked_add(secs))
        .ok_or_else(|| VaultError::CertificateFailure("certificate time overflow".to_string()))
}

fn format_x509_name(name: &X509NameRef) -> String {
    let parts = name
        .entries()
        .map(|entry| {
            let field = entry.object().nid().short_name().unwrap_or("UNKNOWN");
            let value = entry
                .data()
                .as_utf8()
                .map(|value| value.to_string())
                .unwrap_or_else(|_| hex_encode(entry.data().as_slice()));
            format!("{field}={value}")
        })
        .collect::<Vec<_>>();
    if parts.is_empty() {
        "UNKNOWN".to_string()
    } else {
        parts.join(", ")
    }
}

pub fn inspect_certificate_pem(
    certificate_pem: &[u8],
) -> Result<VaultCertificatePreview, VaultError> {
    let certificate = load_certificate(certificate_pem)?;
    let metadata = certificate_keyslot_metadata(&certificate)?;
    Ok(VaultCertificatePreview {
        fingerprint_sha256: metadata.fingerprint_sha256,
        subject: metadata.subject,
        not_before: metadata.not_before,
        not_after: metadata.not_after,
    })
}

fn wrap_secret_with_certificate(
    secret: &[u8],
    certificate: &X509,
    aad: &[u8],
) -> Result<CertificateWrappedSecret, VaultError> {
    let transport_key = Zeroizing::new(random_bytes(MASTER_KEY_LEN)?);
    let wrapped_transport_key_der =
        cms_encrypt_with_certificate(transport_key.as_slice(), certificate)?;
    let encrypted_secret = encrypt_blob(transport_key.as_slice(), aad, secret)?;
    Ok(CertificateWrappedSecret {
        wrapped_transport_key_der,
        encrypted_secret,
    })
}

fn cms_encrypt_with_certificate(
    plaintext: &[u8],
    certificate: &X509,
) -> Result<Vec<u8>, VaultError> {
    let mut certs =
        Stack::new().map_err(|error| VaultError::CertificateFailure(error.to_string()))?;
    certs
        .push(certificate.to_owned())
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))?;
    let envelope =
        CmsContentInfo::encrypt(&certs, plaintext, Cipher::aes_256_cbc(), CMSOptions::BINARY)
            .map_err(|error| VaultError::CertificateFailure(error.to_string()))?;
    // TODO: HUMAN_REVIEW - confirm CMS recipient selection and content-encryption policy for certificate-wrapped keyslots.
    envelope
        .to_der()
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))
}

fn unwrap_secret_with_certificate(
    wrapped: CertificateWrappedSecret,
    certificate: &X509,
    private_key: &PKey<Private>,
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let transport_key = Zeroizing::new(unwrap_legacy_secret_with_certificate(
        wrapped.wrapped_transport_key_der.as_slice(),
        certificate,
        private_key,
    )?);
    decrypt_blob(transport_key.as_slice(), aad, wrapped.encrypted_secret)
}

fn unwrap_legacy_secret_with_certificate(
    wrapped_der: &[u8],
    certificate: &X509,
    private_key: &PKey<Private>,
) -> Result<Vec<u8>, VaultError> {
    let envelope = CmsContentInfo::from_der(wrapped_der)
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))?;
    envelope
        .decrypt(private_key, certificate)
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))
}

fn item_aad(id: &str) -> Vec<u8> {
    let mut aad = ITEM_AAD_PREFIX.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn device_slot_aad(id: &str) -> Vec<u8> {
    let mut aad = DEVICE_AAD_PREFIX.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn mnemonic_slot_aad(id: &str) -> Vec<u8> {
    let mut aad = MNEMONIC_AAD_PREFIX.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn unix_epoch_now() -> Result<i64, VaultError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| VaultError::InvalidArguments(error.to_string()))?;
    i64::try_from(duration.as_secs())
        .map_err(|error| VaultError::InvalidArguments(error.to_string()))
}

fn default_password_wrap_algorithm() -> String {
    PASSWORD_WRAP_ALGORITHM.to_string()
}

fn sqlite_format_pragmas_sql() -> String {
    format!(
        "PRAGMA application_id = {SQLITE_APPLICATION_ID};\nPRAGMA user_version = {FORMAT_VERSION};"
    )
}

fn select_mnemonic_keyslot<'a>(
    header: &'a VaultHeader,
    slot_id: Option<&str>,
) -> Result<&'a VaultKeyslot, VaultError> {
    let mnemonic_slots = header
        .keyslots
        .iter()
        .filter(|slot| slot.kind == VaultKeyslotKind::MnemonicRecovery)
        .collect::<Vec<_>>();
    match slot_id {
        Some(slot_id) => mnemonic_slots
            .into_iter()
            .find(|slot| slot.id == slot_id)
            .ok_or_else(|| {
                VaultError::InvalidArguments(format!("unknown mnemonic keyslot: {slot_id}"))
            }),
        None => match mnemonic_slots.as_slice() {
            [] => Err(VaultError::InvalidArguments(
                "vault has no mnemonic recovery keyslot".to_string(),
            )),
            [slot] => Ok(*slot),
            _ => Err(VaultError::InvalidArguments(
                "vault has multiple mnemonic recovery keyslots; pass --mnemonic-slot ID"
                    .to_string(),
            )),
        },
    }
}

fn select_device_keyslot<'a>(
    header: &'a VaultHeader,
    slot_id: Option<&str>,
) -> Result<&'a VaultKeyslot, VaultError> {
    let device_slots = header
        .keyslots
        .iter()
        .filter(|slot| slot.kind == VaultKeyslotKind::DeviceBound)
        .collect::<Vec<_>>();
    match slot_id {
        Some(slot_id) => device_slots
            .into_iter()
            .find(|slot| slot.id == slot_id)
            .ok_or_else(|| {
                VaultError::InvalidArguments(format!("unknown device keyslot: {slot_id}"))
            }),
        None => match device_slots.as_slice() {
            [] => Err(VaultError::InvalidArguments(
                "vault has no device-bound keyslot".to_string(),
            )),
            [slot] => Ok(*slot),
            _ => Err(VaultError::InvalidArguments(
                "vault has multiple device-bound keyslots; pass --device-slot ID".to_string(),
            )),
        },
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
#[cfg(not(test))]
fn device_store_set_secret(service: &str, account: &str, secret: &[u8]) -> Result<(), VaultError> {
    let entry = keyring::Entry::new(service, account)
        .map_err(|error| VaultError::DeviceStoreFailure(error.to_string()))?;
    entry
        .set_secret(secret)
        .map_err(|error| VaultError::DeviceStoreFailure(error.to_string()))
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
#[cfg(not(test))]
fn device_store_get_secret(service: &str, account: &str) -> Result<Vec<u8>, VaultError> {
    let entry = keyring::Entry::new(service, account)
        .map_err(|error| VaultError::DeviceStoreFailure(error.to_string()))?;
    entry.get_secret().map_err(|error| match error {
        keyring::Error::NoEntry => VaultError::UnlockFailed,
        other => VaultError::DeviceStoreFailure(other.to_string()),
    })
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
#[cfg(not(test))]
fn device_store_delete_secret(service: &str, account: &str) -> Result<(), VaultError> {
    let entry = keyring::Entry::new(service, account)
        .map_err(|error| VaultError::DeviceStoreFailure(error.to_string()))?;
    entry.delete_credential().map_err(|error| match error {
        keyring::Error::NoEntry => VaultError::UnlockFailed,
        other => VaultError::DeviceStoreFailure(other.to_string()),
    })
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
#[cfg(not(test))]
fn device_store_set_secret(
    _service: &str,
    _account: &str,
    _secret: &[u8],
) -> Result<(), VaultError> {
    Err(VaultError::DeviceStoreFailure(
        "device-bound secure storage is unsupported on this platform".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
#[cfg(not(test))]
fn device_store_get_secret(_service: &str, _account: &str) -> Result<Vec<u8>, VaultError> {
    Err(VaultError::DeviceStoreFailure(
        "device-bound secure storage is unsupported on this platform".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
#[cfg(not(test))]
fn device_store_delete_secret(_service: &str, _account: &str) -> Result<(), VaultError> {
    Err(VaultError::DeviceStoreFailure(
        "device-bound secure storage is unsupported on this platform".to_string(),
    ))
}

#[cfg(test)]
fn device_store_set_secret(service: &str, account: &str, secret: &[u8]) -> Result<(), VaultError> {
    let mut store = test_device_store().lock().map_err(|_| {
        VaultError::DeviceStoreFailure("device test store lock poisoned".to_string())
    })?;
    store.insert(device_store_key(service, account), secret.to_vec());
    Ok(())
}

#[cfg(test)]
fn device_store_get_secret(service: &str, account: &str) -> Result<Vec<u8>, VaultError> {
    let store = test_device_store().lock().map_err(|_| {
        VaultError::DeviceStoreFailure("device test store lock poisoned".to_string())
    })?;
    store
        .get(&device_store_key(service, account))
        .cloned()
        .ok_or(VaultError::UnlockFailed)
}

#[cfg(test)]
fn device_store_delete_secret(service: &str, account: &str) -> Result<(), VaultError> {
    let mut store = test_device_store().lock().map_err(|_| {
        VaultError::DeviceStoreFailure("device test store lock poisoned".to_string())
    })?;
    store
        .remove(&device_store_key(service, account))
        .map(|_| ())
        .ok_or(VaultError::UnlockFailed)
}

#[cfg(test)]
fn device_store_key(service: &str, account: &str) -> String {
    format!("{service}\u{0}{account}")
}

#[cfg(test)]
fn test_device_store() -> &'static Mutex<std::collections::HashMap<String, Vec<u8>>> {
    static STORE: OnceLock<Mutex<std::collections::HashMap<String, Vec<u8>>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(input: &str) -> Result<Vec<u8>, VaultError> {
    if input.len() % 2 != 0 {
        return Err(VaultError::InvalidArguments(
            "hex input must have even length".to_string(),
        ));
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|error| VaultError::InvalidArguments(error.to_string()))?;
            u8::from_str_radix(text, 16)
                .map_err(|error| VaultError::InvalidArguments(error.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509Name},
    };
    use tempfile::tempdir;

    #[test]
    fn init_unlock_and_login_crud_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        let header = init_vault(&path, "correct horse battery staple").expect("init");
        assert_eq!(header.format_version, FORMAT_VERSION);

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let item = vault
            .add_login(NewLoginRecord {
                title: "Example".to_string(),
                username: "jon@example.com".to_string(),
                password: "Sup3r$ecret!".to_string(),
                url: Some("https://example.com".to_string()),
                notes: Some("phase-3 smoke".to_string()),
                folder: Some("Personal".to_string()),
                tags: vec!["personal".to_string(), "email".to_string()],
            })
            .expect("add");
        let listed = vault.list_items().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].title, "Example");
        assert_eq!(listed[0].folder.as_deref(), Some("Personal"));

        let fetched = vault.get_item(&item.id).expect("show");
        let VaultItemPayload::Login(login) = fetched.payload else {
            panic!("expected login payload");
        };
        assert_eq!(login.username, "jon@example.com");
        assert_eq!(
            login.tags,
            vec!["personal".to_string(), "email".to_string()]
        );

        let updated = vault
            .update_login(
                &item.id,
                UpdateLoginRecord {
                    title: Some("Example Updated".to_string()),
                    password: Some("Sup3r$ecret!#2".to_string()),
                    folder: Some(Some("Primary".to_string())),
                    tags: Some(vec!["primary".to_string(), "email".to_string()]),
                    ..UpdateLoginRecord::default()
                },
            )
            .expect("update");
        let VaultItemPayload::Login(login) = updated.payload else {
            panic!("expected login payload");
        };
        assert_eq!(login.title, "Example Updated");
        assert_eq!(login.password, "Sup3r$ecret!#2");
        assert_eq!(login.tags, vec!["primary".to_string(), "email".to_string()]);
        assert_eq!(login.password_history.len(), 1);
        assert_eq!(login.password_history[0].password, "Sup3r$ecret!");

        vault.delete_item(&item.id).expect("delete");
        assert!(vault.list_items().expect("list").is_empty());
    }

    #[test]
    fn secure_note_crud_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let item = vault
            .add_secure_note(NewSecureNoteRecord {
                title: "Recovery Plan".to_string(),
                content: "Keep paper copy in the safe.".to_string(),
                folder: Some("Recovery".to_string()),
                tags: vec!["recovery".to_string(), "paper".to_string()],
            })
            .expect("add note");
        let listed = vault.list_items().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, VaultItemKind::SecureNote);
        assert_eq!(listed[0].title, "Recovery Plan");

        let fetched = vault.get_item(&item.id).expect("show");
        let VaultItemPayload::SecureNote(note) = fetched.payload else {
            panic!("expected secure note");
        };
        assert_eq!(note.content, "Keep paper copy in the safe.");
        assert_eq!(note.tags, vec!["recovery".to_string(), "paper".to_string()]);

        let updated = vault
            .update_secure_note(
                &item.id,
                UpdateSecureNoteRecord {
                    content: Some("Move paper copy to the fire safe.".to_string()),
                    folder: Some(Some("Ops".to_string())),
                    tags: Some(vec!["recovery".to_string(), "safe".to_string()]),
                    ..UpdateSecureNoteRecord::default()
                },
            )
            .expect("update note");
        let VaultItemPayload::SecureNote(note) = updated.payload else {
            panic!("expected secure note");
        };
        assert_eq!(note.content, "Move paper copy to the fire safe.");
        assert_eq!(note.tags, vec!["recovery".to_string(), "safe".to_string()]);
    }

    #[test]
    fn card_crud_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let item = vault
            .add_card(NewCardRecord {
                title: "Primary Visa".to_string(),
                cardholder_name: "Jon Bogaty".to_string(),
                number: "4111111111111111".to_string(),
                expiry_month: "08".to_string(),
                expiry_year: "2031".to_string(),
                security_code: "123".to_string(),
                billing_zip: Some("60601".to_string()),
                notes: Some("travel card".to_string()),
                folder: Some("Wallet".to_string()),
                tags: vec!["finance".to_string(), "travel".to_string()],
            })
            .expect("add card");
        let listed = vault.list_items().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, VaultItemKind::Card);
        assert!(listed[0].subtitle.contains("•••• 1111"));

        let fetched = vault.get_item(&item.id).expect("show");
        let VaultItemPayload::Card(card) = fetched.payload else {
            panic!("expected card");
        };
        assert_eq!(card.cardholder_name, "Jon Bogaty");
        assert_eq!(card.tags, vec!["finance".to_string(), "travel".to_string()]);

        let updated = vault
            .update_card(
                &item.id,
                UpdateCardRecord {
                    billing_zip: Some(Some("90210".to_string())),
                    notes: Some(Some("updated note".to_string())),
                    folder: Some(Some("Travel".to_string())),
                    tags: Some(vec!["wallet".to_string()]),
                    ..UpdateCardRecord::default()
                },
            )
            .expect("update");
        let VaultItemPayload::Card(card) = updated.payload else {
            panic!("expected card");
        };
        assert_eq!(card.billing_zip.as_deref(), Some("90210"));
        assert_eq!(card.notes.as_deref(), Some("updated note"));
        assert_eq!(card.tags, vec!["wallet".to_string()]);
    }

    #[test]
    fn identity_crud_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let item = vault
            .add_identity(NewIdentityRecord {
                title: "Primary Identity".to_string(),
                full_name: "Jon Bogaty".to_string(),
                email: Some("jon@example.com".to_string()),
                phone: Some("+1-555-0100".to_string()),
                address: Some("123 Main St, Chicago, IL".to_string()),
                notes: Some("passport copy in safe".to_string()),
                folder: Some("Identity".to_string()),
                tags: vec!["personal".to_string(), "recovery".to_string()],
            })
            .expect("add identity");
        let listed = vault.list_items().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, VaultItemKind::Identity);
        assert_eq!(listed[0].subtitle, "Jon Bogaty");

        let fetched = vault.get_item(&item.id).expect("show");
        let VaultItemPayload::Identity(identity) = fetched.payload else {
            panic!("expected identity");
        };
        assert_eq!(identity.email.as_deref(), Some("jon@example.com"));
        assert_eq!(
            identity.tags,
            vec!["personal".to_string(), "recovery".to_string()]
        );

        let updated = vault
            .update_identity(
                &item.id,
                UpdateIdentityRecord {
                    phone: Some(Some("+1-555-0199".to_string())),
                    notes: Some(Some("updated identity note".to_string())),
                    folder: Some(Some("Travel".to_string())),
                    tags: Some(vec!["wallet".to_string()]),
                    ..UpdateIdentityRecord::default()
                },
            )
            .expect("update");
        let VaultItemPayload::Identity(identity) = updated.payload else {
            panic!("expected identity");
        };
        assert_eq!(identity.phone.as_deref(), Some("+1-555-0199"));
        assert_eq!(identity.notes.as_deref(), Some("updated identity note"));
        assert_eq!(identity.tags, vec!["wallet".to_string()]);
    }

    #[test]
    fn search_items_filters_decrypted_records() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: Some("https://github.com".to_string()),
                notes: Some("source hosting".to_string()),
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string(), "code".to_string()],
            })
            .expect("add github");
        vault
            .add_login(NewLoginRecord {
                title: "Bank".to_string(),
                username: "jon".to_string(),
                password: "Sup3r$ecret!".to_string(),
                url: Some("https://bank.example".to_string()),
                notes: Some("monthly bills".to_string()),
                folder: Some("Finance".to_string()),
                tags: vec!["finance".to_string()],
            })
            .expect("add bank");
        vault
            .add_secure_note(NewSecureNoteRecord {
                title: "Travel checklist".to_string(),
                content: "Passport copy in the red folder.".to_string(),
                folder: Some("Travel".to_string()),
                tags: vec!["travel".to_string(), "docs".to_string()],
            })
            .expect("add note");
        vault
            .add_card(NewCardRecord {
                title: "Backup Mastercard".to_string(),
                cardholder_name: "Jon Bogaty".to_string(),
                number: "5555444433331111".to_string(),
                expiry_month: "11".to_string(),
                expiry_year: "2030".to_string(),
                security_code: "999".to_string(),
                billing_zip: Some("73301".to_string()),
                notes: Some("backup travel wallet".to_string()),
                folder: Some("Travel".to_string()),
                tags: vec!["travel".to_string(), "finance".to_string()],
            })
            .expect("add card");
        vault
            .add_identity(NewIdentityRecord {
                title: "Personal Identity".to_string(),
                full_name: "Jon Bogaty".to_string(),
                email: Some("jon@example.com".to_string()),
                phone: Some("+1-555-0100".to_string()),
                address: Some("Chicago".to_string()),
                notes: Some("travel profile".to_string()),
                folder: Some("Travel".to_string()),
                tags: vec!["travel".to_string(), "identity".to_string()],
            })
            .expect("add identity");

        let github = vault.search_items("octo").expect("search github");
        assert_eq!(github.len(), 1);
        assert_eq!(github[0].title, "GitHub");

        let bank = vault.search_items("bills").expect("search bank");
        assert_eq!(bank.len(), 1);
        assert_eq!(bank[0].title, "Bank");

        let travel = vault.search_items("travel").expect("search note tag");
        assert_eq!(travel.len(), 3);
        assert!(travel.iter().any(|item| item.title == "Travel checklist"));
        assert!(travel.iter().any(|item| item.title == "Backup Mastercard"));
        assert!(travel.iter().any(|item| item.title == "Personal Identity"));

        let work_folder = vault.search_items("work").expect("search work folder");
        assert_eq!(work_folder.len(), 1);
        assert_eq!(work_folder[0].title, "GitHub");
    }

    #[test]
    fn list_items_filtered_supports_kind_folder_tag_and_query() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: Some("https://github.com".to_string()),
                notes: Some("source hosting".to_string()),
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string(), "code".to_string()],
            })
            .expect("add github");
        vault
            .add_login(NewLoginRecord {
                title: "GitLab".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: Some("https://gitlab.com".to_string()),
                notes: Some("mirror".to_string()),
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string(), "code".to_string()],
            })
            .expect("add gitlab");
        vault
            .add_card(NewCardRecord {
                title: "Travel Card".to_string(),
                cardholder_name: "Jon Bogaty".to_string(),
                number: "5555444433331111".to_string(),
                expiry_month: "11".to_string(),
                expiry_year: "2030".to_string(),
                security_code: "999".to_string(),
                billing_zip: None,
                notes: Some("backup travel wallet".to_string()),
                folder: Some("Travel".to_string()),
                tags: vec!["travel".to_string(), "finance".to_string()],
            })
            .expect("add card");

        let filtered = vault
            .list_items_filtered(&VaultItemFilter {
                kind: Some(VaultItemKind::Login),
                folder: Some("work".to_string()),
                tag: Some("CODE".to_string()),
                query: Some("git".to_string()),
            })
            .expect("filter");
        assert_eq!(filtered.len(), 2);
        assert!(
            filtered
                .iter()
                .all(|item| item.kind == VaultItemKind::Login)
        );
        assert!(
            filtered
                .iter()
                .all(|item| item.folder.as_deref() == Some("Work"))
        );

        let travel_cards = vault
            .list_items_filtered(&VaultItemFilter {
                kind: Some(VaultItemKind::Card),
                folder: Some("travel".to_string()),
                tag: Some("finance".to_string()),
                query: None,
            })
            .expect("travel cards");
        assert_eq!(travel_cards.len(), 1);
        assert_eq!(travel_cards[0].title, "Travel Card");
    }

    #[test]
    fn duplicate_password_counts_mark_reused_login_passwords() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let github = vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add github");
        let gitlab = vault
            .add_login(NewLoginRecord {
                title: "GitLab".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add gitlab");
        let bank = vault
            .add_login(NewLoginRecord {
                title: "Bank".to_string(),
                username: "jon".to_string(),
                password: "Sup3r$ecret!".to_string(),
                url: None,
                notes: None,
                folder: Some("Finance".to_string()),
                tags: vec!["finance".to_string()],
            })
            .expect("add bank");

        let listed = vault.list_items().expect("list");
        let github_summary = listed
            .iter()
            .find(|item| item.id == github.id)
            .expect("github summary");
        let gitlab_summary = listed
            .iter()
            .find(|item| item.id == gitlab.id)
            .expect("gitlab summary");
        let bank_summary = listed
            .iter()
            .find(|item| item.id == bank.id)
            .expect("bank summary");

        assert_eq!(github_summary.duplicate_password_count, 1);
        assert_eq!(gitlab_summary.duplicate_password_count, 1);
        assert_eq!(bank_summary.duplicate_password_count, 0);
        assert_eq!(
            vault
                .duplicate_password_count(&github.id)
                .expect("github count"),
            1
        );
        assert_eq!(
            vault
                .duplicate_password_count(&bank.id)
                .expect("bank count"),
            0
        );
    }

    #[test]
    fn export_restore_round_trip_preserves_encrypted_vault_contents() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("vault.sqlite");
        let backup = dir.path().join("vault-backup.ppv.json");
        let restored = dir.path().join("restored.sqlite");
        init_vault(&source, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        let device_slot = vault
            .add_device_keyslot(Some("daily".to_string()))
            .expect("device slot");
        vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: Some("https://github.com".to_string()),
                notes: Some("source hosting".to_string()),
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add login");
        vault
            .add_identity(NewIdentityRecord {
                title: "Personal Identity".to_string(),
                full_name: "Jon Bogaty".to_string(),
                email: Some("jon@example.com".to_string()),
                phone: Some("+1-555-0100".to_string()),
                address: Some("Chicago".to_string()),
                notes: Some("recovery profile".to_string()),
                folder: Some("Identity".to_string()),
                tags: vec!["identity".to_string()],
            })
            .expect("add identity");

        vault.export_backup(&backup).expect("export backup");
        let header = restore_vault_backup(&backup, &restored, false).expect("restore backup");
        assert!(header.keyslots.len() >= 2);

        let restored_vault = unlock_vault_with_device(&restored, Some(device_slot.id.as_str()))
            .expect("unlock restored");
        let items = restored_vault.list_items().expect("list restored");
        assert_eq!(items.len(), 2);
        assert!(items.iter().any(|item| item.title == "GitHub"));
        assert!(items.iter().any(|item| item.title == "Personal Identity"));
    }

    #[test]
    fn inspect_backup_reports_counts_and_posture() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("vault.sqlite");
        let backup = dir.path().join("vault-backup.ppv.json");
        init_vault(&source, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        vault
            .add_device_keyslot(Some("daily".to_string()))
            .expect("device slot");
        vault
            .add_certificate_keyslot(
                test_certificate_pair().0.as_slice(),
                Some("laptop".to_string()),
            )
            .expect("cert slot");
        vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add login");
        vault
            .add_secure_note(NewSecureNoteRecord {
                title: "Recovery".to_string(),
                content: "paper copy in safe".to_string(),
                folder: Some("Recovery".to_string()),
                tags: vec!["recovery".to_string()],
            })
            .expect("add note");
        vault.export_backup(&backup).expect("export backup");

        let summary = inspect_vault_backup(&backup).expect("inspect");
        assert!(summary.restorable_by_current_build);
        assert_eq!(summary.item_count, 2);
        assert_eq!(summary.login_count, 1);
        assert_eq!(summary.secure_note_count, 1);
        assert_eq!(summary.card_count, 0);
        assert_eq!(summary.identity_count, 0);
        assert!(summary.recovery_posture.has_recovery_path);
        assert!(summary.recovery_posture.has_certificate_path);
        assert!(summary.recovery_posture.meets_recommended_posture);
        assert_eq!(summary.keyslots.len(), summary.keyslot_count);
        let certificate_slot = summary
            .keyslots
            .iter()
            .find(|keyslot| keyslot.kind == VaultKeyslotKind::CertificateWrapped)
            .expect("certificate slot summary");
        assert_eq!(certificate_slot.label.as_deref(), Some("laptop"));
        assert_eq!(
            certificate_slot.certificate_subject.as_deref(),
            Some("CN=paranoid-passwd.test")
        );
        assert!(certificate_slot.certificate_not_after.is_some());
    }

    #[test]
    fn export_transfer_inspect_reports_selection_and_access_paths() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("source.sqlite");
        let transfer = dir.path().join("vault-transfer.ppvt.json");
        init_vault(&source, "correct horse battery staple").expect("init");

        let (certificate_pem, _) = test_certificate_pair();
        let vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["prod".to_string()],
            })
            .expect("add login");
        vault
            .add_secure_note(NewSecureNoteRecord {
                title: "Recovery".to_string(),
                content: "paper copy".to_string(),
                folder: Some("Recovery".to_string()),
                tags: vec!["offline".to_string()],
            })
            .expect("add note");

        vault
            .export_transfer_package(
                &transfer,
                &VaultItemFilter {
                    kind: Some(VaultItemKind::Login),
                    folder: Some("Work".to_string()),
                    tag: Some("prod".to_string()),
                    query: None,
                },
                Some("transfer secret"),
                Some(certificate_pem.as_slice()),
            )
            .expect("export transfer");

        let summary = inspect_vault_transfer(&transfer).expect("inspect transfer");
        assert!(summary.importable_by_current_build);
        assert_eq!(summary.item_count, 1);
        assert_eq!(summary.login_count, 1);
        assert_eq!(summary.secure_note_count, 0);
        assert_eq!(summary.filter.kind, Some(VaultItemKind::Login));
        assert_eq!(summary.filter.folder.as_deref(), Some("Work"));
        assert_eq!(summary.filter.tag.as_deref(), Some("prod"));
        assert!(summary.has_recovery_path);
        assert!(summary.has_certificate_path);
        assert_eq!(
            summary.certificate_subject.as_deref(),
            Some("CN=paranoid-passwd.test")
        );
    }

    #[test]
    fn import_transfer_with_password_remaps_conflicting_ids() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("source.sqlite");
        let target = dir.path().join("target.sqlite");
        let transfer = dir.path().join("vault-transfer.ppvt.json");
        init_vault(&source, "correct horse battery staple").expect("init source");
        init_vault(&target, "correct horse battery staple").expect("init target");

        let source_vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        let exported_item = source_vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: Some("https://github.com".to_string()),
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["prod".to_string()],
            })
            .expect("add login");
        source_vault
            .export_transfer_package(
                &transfer,
                &VaultItemFilter::default(),
                Some("transfer secret"),
                None,
            )
            .expect("export transfer");

        let target_vault = unlock_vault(&target, "correct horse battery staple").expect("unlock");
        target_vault
            .store_item(&exported_item)
            .expect("seed conflicting id");
        let summary = target_vault
            .import_transfer_package_with_password(&transfer, "transfer secret", false)
            .expect("import transfer");
        assert_eq!(
            summary,
            VaultTransferImportSummary {
                imported_count: 1,
                replaced_count: 0,
                remapped_count: 1,
            }
        );

        let items = target_vault.list_items().expect("list items");
        assert_eq!(items.len(), 2);
        assert_eq!(
            items.iter().filter(|item| item.title == "GitHub").count(),
            2
        );
    }

    #[test]
    fn import_transfer_with_certificate_unlocks_selected_payload() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("source.sqlite");
        let target = dir.path().join("target.sqlite");
        let transfer = dir.path().join("vault-transfer.ppvt.json");
        init_vault(&source, "correct horse battery staple").expect("init source");
        init_vault(&target, "correct horse battery staple").expect("init target");

        let (certificate_pem, private_key_pem) = test_certificate_pair();
        let source_vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        source_vault
            .add_identity(NewIdentityRecord {
                title: "Primary Identity".to_string(),
                full_name: "Jon Bogaty".to_string(),
                email: Some("jon@example.com".to_string()),
                phone: None,
                address: None,
                notes: Some("customer profile".to_string()),
                folder: Some("Identity".to_string()),
                tags: vec!["profile".to_string()],
            })
            .expect("add identity");
        source_vault
            .export_transfer_package(
                &transfer,
                &VaultItemFilter {
                    kind: Some(VaultItemKind::Identity),
                    ..VaultItemFilter::default()
                },
                None,
                Some(certificate_pem.as_slice()),
            )
            .expect("export transfer");
        let package = read_transfer_package(&transfer).expect("read transfer package");
        let certificate_access = package
            .access
            .certificate
            .expect("certificate transfer access");
        assert_eq!(
            certificate_access.wrap_algorithm,
            CERTIFICATE_WRAP_ALGORITHM
        );
        assert!(!certificate_access.wrapped_transport_key_der_hex.is_empty());
        assert!(!certificate_access.nonce_hex.is_empty());
        assert!(!certificate_access.tag_hex.is_empty());
        assert!(!certificate_access.encrypted_transfer_key_hex.is_empty());

        let target_vault = unlock_vault(&target, "correct horse battery staple").expect("unlock");
        let summary = target_vault
            .import_transfer_package_with_certificate(
                &transfer,
                certificate_pem.as_slice(),
                private_key_pem.as_slice(),
                None,
                false,
            )
            .expect("import transfer");
        assert_eq!(summary.imported_count, 1);
        assert_eq!(summary.replaced_count, 0);
        assert_eq!(summary.remapped_count, 0);

        let items = target_vault.list_items().expect("list items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, VaultItemKind::Identity);
        assert_eq!(items[0].title, "Primary Identity");
    }

    #[test]
    fn legacy_certificate_transfer_import_remains_supported() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("source.sqlite");
        let target = dir.path().join("target.sqlite");
        let transfer = dir.path().join("vault-transfer-legacy.ppvt.json");
        init_vault(&source, "correct horse battery staple").expect("init source");
        init_vault(&target, "correct horse battery staple").expect("init target");

        let (certificate_pem, private_key_pem) = test_certificate_pair();
        let certificate = load_certificate(certificate_pem.as_slice()).expect("load certificate");
        let metadata = certificate_keyslot_metadata(&certificate).expect("certificate metadata");

        let source_vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        let exported = source_vault
            .add_identity(NewIdentityRecord {
                title: "Legacy Transfer Identity".to_string(),
                full_name: "Jon Bogaty".to_string(),
                email: Some("jon@example.com".to_string()),
                phone: None,
                address: None,
                notes: Some("legacy certificate transfer".to_string()),
                folder: Some("Identity".to_string()),
                tags: vec!["legacy".to_string()],
            })
            .expect("add identity");
        let transfer_key = Zeroizing::new(random_bytes(MASTER_KEY_LEN).expect("transfer key"));
        let payload_plaintext = serde_json::to_vec(&VaultTransferPayload {
            items: vec![exported],
        })
        .expect("serialize payload");
        let payload = encrypt_blob(
            transfer_key.as_slice(),
            TRANSFER_PAYLOAD_AAD,
            payload_plaintext.as_slice(),
        )
        .expect("encrypt payload");
        let wrapped_transport_key_der =
            cms_encrypt_with_certificate(transfer_key.as_slice(), &certificate)
                .expect("legacy certificate wrap");
        let package = summarize_transfer_items(
            VaultItemFilter {
                kind: Some(VaultItemKind::Identity),
                ..VaultItemFilter::default()
            },
            std::iter::once(VaultItemKind::Identity),
            FORMAT_VERSION,
            unix_epoch_now().expect("epoch"),
            VaultTransferAccess {
                recovery: None,
                certificate: Some(VaultTransferCertificateAccess {
                    wrap_algorithm: LEGACY_CERTIFICATE_WRAP_ALGORITHM.to_string(),
                    wrapped_transport_key_der_hex: hex_encode(wrapped_transport_key_der.as_slice()),
                    nonce_hex: String::new(),
                    tag_hex: String::new(),
                    encrypted_transfer_key_hex: String::new(),
                    certificate_fingerprint_sha256: metadata.fingerprint_sha256,
                    certificate_subject: metadata.subject,
                    certificate_not_before: metadata.not_before,
                    certificate_not_after: metadata.not_after,
                    certificate_not_before_epoch: metadata.not_before_epoch,
                    certificate_not_after_epoch: metadata.not_after_epoch,
                }),
            },
            payload,
        );
        fs::write(
            &transfer,
            serde_json::to_vec_pretty(&package).expect("serialize package"),
        )
        .expect("write transfer");

        let target_vault = unlock_vault(&target, "correct horse battery staple").expect("unlock");
        let summary = target_vault
            .import_transfer_package_with_certificate(
                &transfer,
                certificate_pem.as_slice(),
                private_key_pem.as_slice(),
                None,
                false,
            )
            .expect("import legacy transfer");
        assert_eq!(summary.imported_count, 1);
        assert_eq!(summary.replaced_count, 0);
        assert_eq!(summary.remapped_count, 0);

        let items = target_vault.list_items().expect("list items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Legacy Transfer Identity");
        assert_eq!(items[0].kind, VaultItemKind::Identity);
    }

    #[test]
    fn restore_backup_rejects_invalid_package_fail_closed() {
        let dir = tempdir().expect("tempdir");
        let backup = dir.path().join("invalid-backup.ppv.json");
        let restored = dir.path().join("restored.sqlite");
        fs::write(
            &backup,
            r#"{"backup_format_version":999,"vault_format_version":1,"header":{"format_version":1,"created_at_epoch":0,"migration_state":"clean","kdf":{"algorithm":"argon2id","memory_cost_kib":65536,"iterations":3,"parallelism":1,"derived_key_len":32},"keyslots":[]},"items":[]}"#,
        )
        .expect("write invalid backup");

        let error = restore_vault_backup(&backup, &restored, false).expect_err("restore fails");
        assert!(error.to_string().contains("unsupported") || matches!(error, VaultError::Json(_)));
        assert!(!restored.exists());
    }

    #[test]
    fn tampered_item_ciphertext_fails_closed_on_list() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let item = vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add login");
        drop(vault);

        let conn = Connection::open(&path).expect("open sqlite");
        conn.execute(
            "UPDATE items SET ciphertext = '00' WHERE id = ?1",
            params![item.id],
        )
        .expect("tamper ciphertext");
        drop(conn);

        let tampered = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        tampered
            .list_items()
            .expect_err("list should fail closed on tampered ciphertext");
    }

    #[test]
    fn wrong_password_fails_closed() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let error = unlock_vault(&path, "wrong").expect_err("unlock should fail");
        assert!(matches!(error, VaultError::UnlockFailed));
    }

    #[test]
    fn certificate_keyslot_unlock_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let (certificate_pem, private_key_pem) = test_certificate_pair();
        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let keyslot = vault
            .add_certificate_keyslot(certificate_pem.as_slice(), Some("laptop".to_string()))
            .expect("add certificate keyslot");
        assert_eq!(keyslot.kind, VaultKeyslotKind::CertificateWrapped);
        assert_eq!(keyslot.wrap_algorithm, CERTIFICATE_WRAP_ALGORITHM);
        assert!(!keyslot.salt_hex.is_empty());
        assert!(!keyslot.nonce_hex.is_empty());
        assert!(!keyslot.tag_hex.is_empty());
        assert!(!keyslot.encrypted_master_key_hex.is_empty());
        assert!(keyslot.certificate_fingerprint_sha256.is_some());
        assert_eq!(
            keyslot.certificate_subject.as_deref(),
            Some("CN=paranoid-passwd.test")
        );
        assert!(keyslot.certificate_not_before.is_some());
        assert!(keyslot.certificate_not_after.is_some());

        let header = read_vault_header(&path).expect("read header");
        assert_eq!(header.keyslots.len(), 2);
        assert!(
            header
                .keyslots
                .iter()
                .any(|slot| slot.kind == VaultKeyslotKind::CertificateWrapped)
        );

        let unlocked = unlock_vault_with_certificate(
            &path,
            certificate_pem.as_slice(),
            private_key_pem.as_slice(),
            None,
        )
        .expect("unlock with cert");
        let item = unlocked
            .add_login(NewLoginRecord {
                title: "Cert Login".to_string(),
                username: "jon@example.com".to_string(),
                password: "Sup3r$ecret!".to_string(),
                url: None,
                notes: None,
                folder: None,
                tags: vec![],
            })
            .expect("add login");
        assert_eq!(unlocked.get_item(&item.id).expect("get item").id, item.id);
    }

    #[test]
    fn legacy_certificate_keyslot_unlock_remains_supported() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let (certificate_pem, private_key_pem) = test_certificate_pair();
        let certificate = load_certificate(certificate_pem.as_slice()).expect("load certificate");
        let metadata = certificate_keyslot_metadata(&certificate).expect("certificate metadata");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let wrapped_master_key =
            cms_encrypt_with_certificate(vault.master_key.as_slice(), &certificate)
                .expect("legacy wrap");
        vault.header.keyslots.push(VaultKeyslot {
            id: "cert-legacy".to_string(),
            kind: VaultKeyslotKind::CertificateWrapped,
            label: Some("legacy".to_string()),
            wrapped_by_os_keystore: false,
            wrap_algorithm: LEGACY_CERTIFICATE_WRAP_ALGORITHM.to_string(),
            salt_hex: String::new(),
            nonce_hex: String::new(),
            tag_hex: String::new(),
            encrypted_master_key_hex: hex_encode(wrapped_master_key.as_slice()),
            certificate_fingerprint_sha256: Some(metadata.fingerprint_sha256),
            certificate_subject: Some(metadata.subject),
            certificate_not_before: Some(metadata.not_before),
            certificate_not_after: Some(metadata.not_after),
            certificate_not_before_epoch: Some(metadata.not_before_epoch),
            certificate_not_after_epoch: Some(metadata.not_after_epoch),
            mnemonic_language: None,
            mnemonic_words: None,
            device_service: None,
            device_account: None,
        });
        vault.persist_header().expect("persist legacy keyslot");
        drop(vault);

        let unlocked = unlock_vault_with_certificate(
            &path,
            certificate_pem.as_slice(),
            private_key_pem.as_slice(),
            None,
        )
        .expect("unlock with legacy certificate slot");
        let item = unlocked
            .add_secure_note(NewSecureNoteRecord {
                title: "Legacy Cert Slot".to_string(),
                content: "legacy compatibility preserved".to_string(),
                folder: None,
                tags: vec!["legacy".to_string()],
            })
            .expect("add note");
        assert_eq!(unlocked.get_item(&item.id).expect("get item").id, item.id);
    }

    #[test]
    fn inspect_certificate_preview_reports_subject_and_validity() {
        let (certificate_pem, _) = test_certificate_pair();
        let preview = inspect_certificate_pem(certificate_pem.as_slice()).expect("inspect cert");
        assert!(!preview.fingerprint_sha256.is_empty());
        assert_eq!(preview.subject, "CN=paranoid-passwd.test");
        assert!(!preview.not_before.is_empty());
        assert!(!preview.not_after.is_empty());
    }

    #[test]
    fn expired_certificate_keyslot_health_reports_warning() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let key = build_test_key();
        let expired_cert = build_self_signed_cert_with_validity(&key, 0, 86_400);
        let cert_pem = expired_cert.to_pem().expect("cert pem");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let slot = vault
            .add_certificate_keyslot(cert_pem.as_slice(), Some("expired".to_string()))
            .expect("add expired certificate keyslot");
        let health = vault
            .header()
            .assess_keyslot_health(slot.id.as_str())
            .expect("health");
        assert!(!health.healthy);
        assert!(
            health
                .warnings
                .iter()
                .any(|warning| warning.contains("expired"))
        );
    }

    #[test]
    fn certificate_keyslot_rewrap_updates_fingerprint_and_unlock_path() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let (old_certificate_pem, old_private_key_pem) = test_certificate_pair();
        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let keyslot = vault
            .add_certificate_keyslot(old_certificate_pem.as_slice(), Some("laptop".to_string()))
            .expect("add certificate keyslot");
        let old_fingerprint = keyslot
            .certificate_fingerprint_sha256
            .clone()
            .expect("old fingerprint");

        let (new_certificate_pem, new_private_key_pem) = test_certificate_pair();
        let updated = vault
            .rewrap_certificate_keyslot(&keyslot.id, new_certificate_pem.as_slice())
            .expect("rewrap certificate keyslot");
        let new_fingerprint = updated
            .certificate_fingerprint_sha256
            .clone()
            .expect("new fingerprint");

        assert_eq!(updated.id, keyslot.id);
        assert_eq!(updated.label, keyslot.label);
        assert_ne!(new_fingerprint, old_fingerprint);
        assert_eq!(
            updated.certificate_subject.as_deref(),
            Some("CN=paranoid-passwd.test")
        );
        assert!(updated.certificate_not_before.is_some());
        assert!(updated.certificate_not_after.is_some());

        let header = read_vault_header(&path).expect("read header");
        let stored = header
            .keyslots
            .iter()
            .find(|slot| slot.id == keyslot.id)
            .expect("stored certificate slot");
        assert_eq!(
            stored.certificate_fingerprint_sha256.as_deref(),
            Some(new_fingerprint.as_str())
        );
        assert_eq!(
            stored.certificate_subject.as_deref(),
            Some("CN=paranoid-passwd.test")
        );

        assert!(matches!(
            unlock_vault_with_certificate(
                &path,
                old_certificate_pem.as_slice(),
                old_private_key_pem.as_slice(),
                None,
            ),
            Err(VaultError::UnlockFailed)
        ));
        let unlocked = unlock_vault_with_certificate(
            &path,
            new_certificate_pem.as_slice(),
            new_private_key_pem.as_slice(),
            None,
        )
        .expect("unlock with rewrapped cert");
        assert_eq!(unlocked.header().keyslots.len(), 2);
    }

    #[test]
    fn encrypted_private_key_unlock_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let (certificate_pem, private_key_pem) = encrypted_test_certificate_pair("vault-pass");
        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        vault
            .add_certificate_keyslot(certificate_pem.as_slice(), Some("encrypted".to_string()))
            .expect("add certificate keyslot");

        unlock_vault_with_certificate(
            &path,
            certificate_pem.as_slice(),
            private_key_pem.as_slice(),
            Some("vault-pass"),
        )
        .expect("unlock with encrypted key");
    }

    #[test]
    fn mnemonic_keyslot_unlock_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let enrollment = vault
            .add_mnemonic_keyslot(Some("offline-recovery".to_string()))
            .expect("add mnemonic keyslot");
        assert_eq!(enrollment.keyslot.kind, VaultKeyslotKind::MnemonicRecovery);
        assert_eq!(
            enrollment.keyslot.mnemonic_language.as_deref(),
            Some(MNEMONIC_LANGUAGE)
        );
        assert_eq!(enrollment.keyslot.mnemonic_words, Some(MNEMONIC_WORD_COUNT));
        assert_eq!(
            enrollment.mnemonic.split_whitespace().count(),
            usize::from(MNEMONIC_WORD_COUNT)
        );

        let unlocked = unlock_vault_with_mnemonic(
            &path,
            enrollment.mnemonic.as_str(),
            Some(enrollment.keyslot.id.as_str()),
        )
        .expect("unlock with mnemonic");
        let item = unlocked
            .add_login(NewLoginRecord {
                title: "Mnemonic Login".to_string(),
                username: "jon@example.com".to_string(),
                password: "Sup3r$ecret!".to_string(),
                url: None,
                notes: None,
                folder: None,
                tags: vec![],
            })
            .expect("add login");
        assert_eq!(unlocked.get_item(&item.id).expect("get item").id, item.id);
    }

    #[test]
    fn mnemonic_keyslot_rotation_rewraps_selected_slot_and_invalidates_old_phrase() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let original = vault
            .add_mnemonic_keyslot(Some("paper-backup".to_string()))
            .expect("add mnemonic keyslot");
        let rotated = vault
            .rotate_mnemonic_keyslot(original.keyslot.id.as_str())
            .expect("rotate mnemonic keyslot");

        assert_eq!(rotated.keyslot.id, original.keyslot.id);
        assert_eq!(rotated.keyslot.label, original.keyslot.label);
        assert_ne!(rotated.mnemonic, original.mnemonic);
        assert_ne!(
            rotated.keyslot.encrypted_master_key_hex,
            original.keyslot.encrypted_master_key_hex
        );

        let error = unlock_vault_with_mnemonic(
            &path,
            original.mnemonic.as_str(),
            Some(original.keyslot.id.as_str()),
        )
        .expect_err("old phrase should fail after rotation");
        assert!(matches!(error, VaultError::UnlockFailed));

        unlock_vault_with_mnemonic(
            &path,
            rotated.mnemonic.as_str(),
            Some(rotated.keyslot.id.as_str()),
        )
        .expect("unlock with rotated mnemonic");
    }

    #[test]
    fn mnemonic_unlock_requires_explicit_slot_when_multiple_exist() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let first = vault
            .add_mnemonic_keyslot(Some("paper-1".to_string()))
            .expect("add first mnemonic keyslot");
        vault
            .add_mnemonic_keyslot(Some("paper-2".to_string()))
            .expect("add second mnemonic keyslot");

        let error = unlock_vault_with_mnemonic(&path, first.mnemonic.as_str(), None)
            .expect_err("unlock should require slot id");
        assert!(
            matches!(error, VaultError::InvalidArguments(message) if message.contains("multiple mnemonic recovery keyslots"))
        );
    }

    #[test]
    fn wrong_mnemonic_fails_closed() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let enrollment = vault
            .add_mnemonic_keyslot(Some("paper".to_string()))
            .expect("add mnemonic keyslot");
        let mut words = enrollment
            .mnemonic
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        words[0] = "abandon".to_string();
        let wrong_phrase = words.join(" ");

        let error = unlock_vault_with_mnemonic(
            &path,
            wrong_phrase.as_str(),
            Some(enrollment.keyslot.id.as_str()),
        )
        .expect_err("unlock should fail");
        assert!(matches!(error, VaultError::UnlockFailed));
    }

    #[test]
    fn device_keyslot_unlock_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let keyslot = vault
            .add_device_keyslot(Some("daily-device".to_string()))
            .expect("add device keyslot");
        assert_eq!(keyslot.kind, VaultKeyslotKind::DeviceBound);
        assert!(keyslot.wrapped_by_os_keystore);
        assert_eq!(keyslot.wrap_algorithm, DEVICE_WRAP_ALGORITHM);
        assert!(keyslot.device_service.is_some());
        assert!(keyslot.device_account.is_some());

        let unlocked =
            unlock_vault_with_device(&path, Some(keyslot.id.as_str())).expect("device unlock");
        let item = unlocked
            .add_login(NewLoginRecord {
                title: "Device Login".to_string(),
                username: "jon@example.com".to_string(),
                password: "Sup3r$ecret!".to_string(),
                url: None,
                notes: None,
                folder: None,
                tags: vec![],
            })
            .expect("add login");
        assert_eq!(unlocked.get_item(&item.id).expect("get item").id, item.id);
    }

    #[test]
    fn removing_non_recovery_keyslot_updates_header() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let slot = vault
            .add_device_keyslot(Some("daily-device".to_string()))
            .expect("add device keyslot");
        let removed = vault
            .remove_keyslot(&slot.id, true)
            .expect("remove keyslot");
        assert_eq!(removed.id, slot.id);

        let header = read_vault_header(&path).expect("header");
        assert!(
            header
                .keyslots
                .iter()
                .all(|candidate| candidate.id != slot.id)
        );
    }

    #[test]
    fn relabel_keyslot_persists_normalized_label_and_can_clear() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let slot = vault
            .add_device_keyslot(Some("daily-device".to_string()))
            .expect("add device keyslot");

        let relabeled = vault
            .relabel_keyslot(&slot.id, Some("  laptop daily  ".to_string()))
            .expect("relabel keyslot");
        assert_eq!(relabeled.label.as_deref(), Some("laptop daily"));

        let header = read_vault_header(&path).expect("header");
        let stored = header
            .keyslots
            .iter()
            .find(|candidate| candidate.id == slot.id)
            .expect("stored slot");
        assert_eq!(stored.label.as_deref(), Some("laptop daily"));

        let cleared = vault
            .relabel_keyslot(&slot.id, None)
            .expect("clear keyslot label");
        assert_eq!(cleared.label, None);

        let header = read_vault_header(&path).expect("header after clear");
        let stored = header
            .keyslots
            .iter()
            .find(|candidate| candidate.id == slot.id)
            .expect("stored slot after clear");
        assert_eq!(stored.label, None);
    }

    #[test]
    fn removal_impact_flags_last_certificate_slot() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let (cert, _) = test_certificate_pair();
        let slot = vault
            .add_certificate_keyslot(cert.as_slice(), Some("laptop".to_string()))
            .expect("add certificate keyslot");

        let impact = vault
            .header()
            .assess_keyslot_removal(&slot.id)
            .expect("assess removal");
        assert!(impact.requires_explicit_confirmation);
        assert!(
            impact
                .warnings
                .iter()
                .any(|warning| warning.contains("last certificate-wrapped slot"))
        );
        assert!(!impact.after.has_certificate_path);
    }

    #[test]
    fn removing_risky_keyslot_requires_force() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let slot = vault
            .add_device_keyslot(Some("daily-device".to_string()))
            .expect("add device keyslot");
        let error = vault
            .remove_keyslot(&slot.id, false)
            .expect_err("last device slot removal should require force");
        assert!(
            matches!(error, VaultError::InvalidArguments(message) if message.contains("without explicit confirmation"))
        );
    }

    #[test]
    fn password_recovery_keyslot_cannot_be_removed() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let error = vault
            .remove_keyslot("recovery", true)
            .expect_err("password recovery must stay immutable");
        assert!(
            matches!(error, VaultError::InvalidArguments(message) if message.contains("cannot be removed"))
        );
    }

    #[test]
    fn recovery_secret_rotation_rewraps_password_recovery_slot() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let original = vault
            .header()
            .keyslots
            .iter()
            .find(|slot| slot.kind == VaultKeyslotKind::PasswordRecovery)
            .cloned()
            .expect("password recovery slot");

        let rotated = vault
            .rotate_password_recovery_keyslot("new battery horse staple")
            .expect("rotate recovery secret");

        assert_eq!(rotated.id, original.id);
        assert_ne!(rotated.salt_hex, original.salt_hex);
        assert_ne!(
            rotated.encrypted_master_key_hex,
            original.encrypted_master_key_hex
        );
        assert!(matches!(
            unlock_vault(&path, "correct horse battery staple"),
            Err(VaultError::UnlockFailed)
        ));
        unlock_vault(&path, "new battery horse staple").expect("unlock with new recovery secret");
    }

    #[test]
    fn recovery_posture_counts_recovery_and_certificate_coverage() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let (cert_pem, _) = test_certificate_pair();

        vault
            .add_mnemonic_keyslot(Some("paper".to_string()))
            .expect("mnemonic slot");
        vault
            .add_device_keyslot(Some("daily".to_string()))
            .expect("device slot");
        vault
            .add_certificate_keyslot(cert_pem.as_slice(), Some("ops".to_string()))
            .expect("cert slot");

        let posture = vault.header().recovery_posture();
        assert_eq!(posture.password_recovery_slots, 1);
        assert_eq!(posture.mnemonic_recovery_slots, 1);
        assert_eq!(posture.device_bound_slots, 1);
        assert_eq!(posture.certificate_wrapped_slots, 1);
        assert!(posture.has_recovery_path);
        assert!(posture.has_certificate_path);
        assert!(posture.meets_recommended_posture);
    }

    #[test]
    fn rebind_device_keyslot_rotates_secure_storage_account() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let original = vault
            .add_device_keyslot(Some("daily-device".to_string()))
            .expect("add device keyslot");
        let rebound = vault
            .rebind_device_keyslot(&original.id)
            .expect("rebind device keyslot");

        assert_eq!(rebound.id, original.id);
        assert_ne!(rebound.device_account, original.device_account);

        let unlocked =
            unlock_vault_with_device(&path, Some(rebound.id.as_str())).expect("unlock rebound");
        assert_eq!(unlocked.header().keyslots.len(), 2);
    }

    #[test]
    fn device_unlock_requires_explicit_slot_when_multiple_exist() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        vault
            .add_device_keyslot(Some("laptop".to_string()))
            .expect("add first device slot");
        vault
            .add_device_keyslot(Some("desktop".to_string()))
            .expect("add second device slot");

        let error =
            unlock_vault_with_device(&path, None).expect_err("unlock should require slot id");
        assert!(
            matches!(error, VaultError::InvalidArguments(message) if message.contains("multiple device-bound keyslots"))
        );
    }

    #[test]
    fn generate_and_store_uses_core_generator() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let (report, item) = vault
            .generate_and_store(
                &ParanoidRequest::default(),
                GenerateStoreLoginRecord {
                    target_login_id: None,
                    title: Some("Generated".to_string()),
                    username: Some("jon@example.com".to_string()),
                    url: None,
                    notes: None,
                    folder: Some("Generated".to_string()),
                    tags: Some(vec!["generated".to_string(), "vault".to_string()]),
                },
            )
            .expect("generate+store");
        assert_eq!(report.passwords.len(), 1);
        let stored = vault.get_item(&item.id).expect("show");
        let VaultItemPayload::Login(login) = stored.payload else {
            panic!("expected login payload");
        };
        assert_eq!(login.password, report.passwords[0].value);
        assert_eq!(
            login.tags,
            vec!["generated".to_string(), "vault".to_string()]
        );
    }

    #[test]
    fn generate_and_store_can_rotate_existing_login() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let original = vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: Some("https://github.com".to_string()),
                notes: Some("primary".to_string()),
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add");

        let (report, rotated) = vault
            .generate_and_store(
                &ParanoidRequest::default(),
                GenerateStoreLoginRecord {
                    target_login_id: Some(original.id.clone()),
                    title: None,
                    username: None,
                    url: None,
                    notes: None,
                    folder: None,
                    tags: None,
                },
            )
            .expect("rotate");

        assert_eq!(report.passwords.len(), 1);
        assert_eq!(rotated.id, original.id);
        let VaultItemPayload::Login(login) = rotated.payload else {
            panic!("expected login payload");
        };
        assert_eq!(login.title, "GitHub");
        assert_eq!(login.username, "octocat");
        assert_eq!(login.folder.as_deref(), Some("Work"));
        assert_eq!(login.tags, vec!["work".to_string()]);
        assert_eq!(login.password_history.len(), 1);
        assert_eq!(login.password_history[0].password, "hunter2");
        assert_ne!(login.password, "hunter2");
    }

    fn test_certificate_pair() -> (Vec<u8>, Vec<u8>) {
        let pkey = build_test_key();
        let cert = build_self_signed_cert(&pkey);
        (
            cert.to_pem().expect("cert pem"),
            pkey.private_key_to_pem_pkcs8().expect("key pem"),
        )
    }

    fn encrypted_test_certificate_pair(passphrase: &str) -> (Vec<u8>, Vec<u8>) {
        let pkey = build_test_key();
        let cert = build_self_signed_cert(&pkey);
        (
            cert.to_pem().expect("cert pem"),
            pkey.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), passphrase.as_bytes())
                .expect("encrypted key pem"),
        )
    }

    fn build_test_key() -> PKey<Private> {
        let rsa = Rsa::generate(2048).expect("rsa");
        PKey::from_rsa(rsa).expect("pkey")
    }

    fn build_self_signed_cert(pkey: &PKey<Private>) -> X509 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix epoch")
            .as_secs() as i64;
        build_self_signed_cert_with_validity(pkey, now, now + 365 * 24 * 60 * 60)
    }

    fn build_self_signed_cert_with_validity(
        pkey: &PKey<Private>,
        not_before_unix: i64,
        not_after_unix: i64,
    ) -> X509 {
        let mut name = X509Name::builder().expect("x509 name builder");
        name.append_entry_by_nid(Nid::COMMONNAME, "paranoid-passwd.test")
            .expect("append common name");
        let name = name.build();

        let mut serial = BigNum::new().expect("serial");
        serial
            .rand(128, MsbOption::MAYBE_ZERO, false)
            .expect("rand serial");

        let mut builder = X509::builder().expect("x509 builder");
        builder.set_version(2).expect("set version");
        builder
            .set_serial_number(&serial.to_asn1_integer().expect("asn1 serial"))
            .expect("set serial");
        builder.set_subject_name(&name).expect("set subject");
        builder.set_issuer_name(&name).expect("set issuer");
        builder
            .set_not_before(&Asn1Time::from_unix(not_before_unix).expect("not before"))
            .expect("apply not before");
        builder
            .set_not_after(&Asn1Time::from_unix(not_after_unix).expect("not after"))
            .expect("apply not after");
        builder.set_pubkey(pkey).expect("set pubkey");
        builder
            .sign(pkey, MessageDigest::sha256())
            .expect("sign cert");
        builder.build()
    }
}
