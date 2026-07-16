use crate::{
    AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN, CERTIFICATE_MASTER_KEY_AAD, CERTIFICATE_WRAP_ALGORITHM,
    DEVICE_CHECK_PLAINTEXT, DEVICE_KEYRING_SERVICE, DEVICE_WRAP_ALGORITHM, EncryptedBlob,
    LEGACY_CERTIFICATE_WRAP_ALGORITHM, MASTER_KEY_AAD, MASTER_KEY_LEN, MNEMONIC_LANGUAGE,
    MNEMONIC_WORD_COUNT, MNEMONIC_WRAP_ALGORITHM, PASSWORD_WRAP_ALGORITHM, UnlockedVault,
    VaultCertificatePreview, VaultError, VaultHeader, decrypt_blob, derive_key, device_slot_aad,
    device_store_delete_secret, device_store_set_secret, encrypt_blob, hex_decode, hex_encode,
    mnemonic_slot_aad, random_bytes, random_hex_id,
};
use argon2::password_hash::SaltString;
use bip39::{Language, Mnemonic};
use openssl::{
    cms::{CMSOptions, CmsContentInfo},
    pkey::{PKey, Private},
    stack::Stack,
    symm::Cipher,
    x509::X509,
};
use paranoid_core::{
    X509Preview, certificate_fingerprint_hex as core_certificate_fingerprint_hex,
    certificate_time_to_epoch as core_certificate_time_to_epoch, format_x509_name,
    inspect_certificate_pem as core_inspect_certificate_pem,
    load_certificate as core_load_certificate,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

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

impl UnlockedVault {
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
        // Dispositioned in docs/reference/ai-review.md: device-bound slots are
        // local-device convenience unlocks, not portable recovery or federal unlock paths.
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
        // Dispositioned in docs/reference/ai-review.md: generated 24-word BIP39
        // phrases encode a 256-bit OpenSSL-generated offline recovery key.
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
}

#[derive(Debug)]
pub(crate) struct CertificateWrappedSecret {
    pub(crate) wrapped_transport_key_der: Vec<u8>,
    pub(crate) encrypted_secret: EncryptedBlob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertificateKeyslotWrapMode {
    Current,
    Legacy,
}

pub(crate) fn load_private_key(
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

/// Vault-error-mapped wrapper around `paranoid_core::load_certificate`. X.509
/// parsing itself lives in core (shared with every other certificate
/// consumer); this only translates `ParanoidError` to vault's own error type
/// so existing call sites keep using `VaultError` via `?`.
pub(crate) fn load_certificate(certificate_pem: &[u8]) -> Result<X509, VaultError> {
    core_load_certificate(certificate_pem)
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))
}

pub(crate) fn certificate_fingerprint_hex(certificate: &X509) -> Result<String, VaultError> {
    core_certificate_fingerprint_hex(certificate)
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))
}

pub(crate) fn certificate_time_to_epoch(
    time: &openssl::asn1::Asn1TimeRef,
) -> Result<i64, VaultError> {
    core_certificate_time_to_epoch(time)
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))
}

pub(crate) fn certificate_keyslot_metadata(certificate: &X509) -> Result<X509Preview, VaultError> {
    Ok(X509Preview {
        fingerprint_sha256: certificate_fingerprint_hex(certificate)?,
        subject: format_x509_name(certificate.subject_name()),
        not_before: certificate.not_before().to_string(),
        not_after: certificate.not_after().to_string(),
        not_before_epoch: certificate_time_to_epoch(certificate.not_before())?,
        not_after_epoch: certificate_time_to_epoch(certificate.not_after())?,
    })
}

pub fn inspect_certificate_pem(
    certificate_pem: &[u8],
) -> Result<VaultCertificatePreview, VaultError> {
    let preview = core_inspect_certificate_pem(certificate_pem)
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))?;
    Ok(VaultCertificatePreview {
        fingerprint_sha256: preview.fingerprint_sha256,
        subject: preview.subject,
        not_before: preview.not_before,
        not_after: preview.not_after,
    })
}

pub(crate) fn wrap_secret_with_certificate(
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

pub(crate) fn cms_encrypt_with_certificate(
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
    // Dispositioned in docs/reference/ai-review.md: CMS envelopes only a random
    // 256-bit transport key for one explicit X.509 recipient. Vault secrets are
    // then wrapped by AAD-bound AES-256-GCM under that transport key.
    envelope
        .to_der()
        .map_err(|error| VaultError::CertificateFailure(error.to_string()))
}

pub(crate) fn validate_certificate_keyslot_metadata(
    keyslot: &VaultKeyslot,
    metadata: &X509Preview,
) -> Result<CertificateKeyslotWrapMode, VaultError> {
    if keyslot.kind != VaultKeyslotKind::CertificateWrapped
        || keyslot.wrapped_by_os_keystore
        || keyslot.certificate_fingerprint_sha256.as_deref()
            != Some(metadata.fingerprint_sha256.as_str())
        || keyslot.certificate_subject.as_deref() != Some(metadata.subject.as_str())
        || keyslot.certificate_not_before.as_deref() != Some(metadata.not_before.as_str())
        || keyslot.certificate_not_after.as_deref() != Some(metadata.not_after.as_str())
        || keyslot.certificate_not_before_epoch != Some(metadata.not_before_epoch)
        || keyslot.certificate_not_after_epoch != Some(metadata.not_after_epoch)
        || keyslot.mnemonic_language.is_some()
        || keyslot.mnemonic_words.is_some()
        || keyslot.device_service.is_some()
        || keyslot.device_account.is_some()
    {
        return Err(VaultError::UnlockFailed);
    }

    match keyslot.wrap_algorithm.as_str() {
        CERTIFICATE_WRAP_ALGORITHM => {
            let wrapped_transport_key = decode_certificate_slot_hex(keyslot.salt_hex.as_str())?;
            let nonce = decode_certificate_slot_hex(keyslot.nonce_hex.as_str())?;
            let tag = decode_certificate_slot_hex(keyslot.tag_hex.as_str())?;
            let ciphertext =
                decode_certificate_slot_hex(keyslot.encrypted_master_key_hex.as_str())?;
            if wrapped_transport_key.is_empty()
                || nonce.len() != AES_GCM_NONCE_LEN
                || tag.len() != AES_GCM_TAG_LEN
                || ciphertext.len() != MASTER_KEY_LEN
            {
                return Err(VaultError::UnlockFailed);
            }
            Ok(CertificateKeyslotWrapMode::Current)
        }
        LEGACY_CERTIFICATE_WRAP_ALGORITHM => {
            let wrapped_master_key =
                decode_certificate_slot_hex(keyslot.encrypted_master_key_hex.as_str())?;
            if !keyslot.salt_hex.is_empty()
                || !keyslot.nonce_hex.is_empty()
                || !keyslot.tag_hex.is_empty()
                || wrapped_master_key.is_empty()
            {
                return Err(VaultError::UnlockFailed);
            }
            Ok(CertificateKeyslotWrapMode::Legacy)
        }
        _ => Err(VaultError::UnlockFailed),
    }
}

pub(crate) fn decode_certificate_slot_hex(input: &str) -> Result<Vec<u8>, VaultError> {
    hex_decode(input).map_err(|_| VaultError::UnlockFailed)
}

pub(crate) fn unwrap_secret_with_certificate(
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

pub(crate) fn unwrap_legacy_secret_with_certificate(
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

pub(crate) fn validate_mnemonic_keyslot_metadata(keyslot: &VaultKeyslot) -> Result<(), VaultError> {
    if keyslot.wrap_algorithm != MNEMONIC_WRAP_ALGORITHM
        || keyslot.mnemonic_language.as_deref() != Some(MNEMONIC_LANGUAGE)
        || keyslot.mnemonic_words != Some(MNEMONIC_WORD_COUNT)
        || keyslot.wrapped_by_os_keystore
        || !keyslot.salt_hex.is_empty()
    {
        return Err(VaultError::UnlockFailed);
    }
    Ok(())
}

pub(crate) fn mnemonic_entropy_from_phrase(
    mnemonic_phrase: &str,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)
        .map_err(|_| VaultError::UnlockFailed)?;
    let mnemonic_entropy = Zeroizing::new(mnemonic.to_entropy());
    if mnemonic_entropy.len() != MASTER_KEY_LEN {
        return Err(VaultError::UnlockFailed);
    }
    Ok(mnemonic_entropy)
}

fn default_password_wrap_algorithm() -> String {
    PASSWORD_WRAP_ALGORITHM.to_string()
}

pub(crate) fn select_mnemonic_keyslot<'a>(
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

pub(crate) fn select_device_keyslot<'a>(
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
