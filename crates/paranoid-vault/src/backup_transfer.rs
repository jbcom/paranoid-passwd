use crate::{
    BACKUP_FORMAT_VERSION, CERTIFICATE_TRANSFER_KEY_AAD, CERTIFICATE_WRAP_ALGORITHM,
    CertificateWrappedSecret, DEFAULT_ITERATIONS, DEFAULT_MEMORY_COST_KIB, DEFAULT_PARALLELISM,
    EncryptedBlob, FORMAT_VERSION, MASTER_KEY_LEN, PASSWORD_WRAP_ALGORITHM, SQLITE_APPLICATION_ID,
    TRANSFER_FORMAT_VERSION, TRANSFER_KEY_AAD, TRANSFER_PAYLOAD_AAD, UnlockedVault, VaultError,
    VaultHeader, VaultItem, VaultItemFilter, VaultItemKind, VaultKdfParams, VaultKeyslotKind,
    VaultRecoveryPosture, certificate_fingerprint_hex, certificate_keyslot_metadata,
    certificate_validity_warnings, configure_connection, create_schema, decrypt_blob, derive_key,
    encrypt_blob, hex_decode, hex_encode, item_matches_filter, load_certificate, load_private_key,
    next_unused_item_id, normalize_and_validate_item, random_bytes, random_hex_id, unix_epoch_now,
    unwrap_legacy_secret_with_certificate, unwrap_secret_with_certificate,
    wrap_secret_with_certificate,
};
use argon2::password_hash::SaltString;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

fn reject_export_path_collision(vault_path: &Path, output_path: &Path) -> Result<(), VaultError> {
    let canonical_vault_path = fs::canonicalize(vault_path)?;
    let canonical_output_path = match fs::canonicalize(output_path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = output_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty());
            let canonical_parent = match parent {
                Some(parent) => fs::canonicalize(parent)?,
                None => std::env::current_dir()?,
            };
            let file_name = output_path.file_name().ok_or_else(|| {
                VaultError::InvalidArguments(format!(
                    "export output path {} has no file name",
                    output_path.display()
                ))
            })?;
            canonical_parent.join(file_name)
        }
        Err(error) => return Err(error.into()),
    };

    if canonical_output_path == canonical_vault_path {
        return Err(VaultError::ExportPathCollision(
            output_path.display().to_string(),
        ));
    }
    Ok(())
}

fn write_export_atomically(output_path: &Path, contents: &[u8]) -> Result<(), VaultError> {
    let parent = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let temp_dir = match parent {
        Some(parent) => parent.to_path_buf(),
        None => PathBuf::from("."),
    };
    let file_name = output_path.file_name().ok_or_else(|| {
        VaultError::InvalidArguments(format!(
            "export output path {} has no file name",
            output_path.display()
        ))
    })?;
    let temp_name = format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        random_hex_id(8)?
    );
    let temp_path = temp_dir.join(temp_name);

    let write_result = fs::write(&temp_path, contents);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(error.into());
    }

    if let Err(error) = fs::rename(&temp_path, output_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error.into());
    }
    Ok(())
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

impl UnlockedVault {
    pub fn export_backup(&self, output_path: impl AsRef<Path>) -> Result<PathBuf, VaultError> {
        let output_path = output_path.as_ref();
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        reject_export_path_collision(self.path(), output_path)?;

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
        write_export_atomically(output_path, serde_json::to_vec_pretty(&package)?.as_slice())?;
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
        reject_export_path_collision(self.path(), output_path)?;

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
        write_export_atomically(output_path, serde_json::to_vec_pretty(&package)?.as_slice())?;
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
        self.conn.execute_batch("BEGIN;")?;
        match self.import_transfer_payload_in_transaction(payload, replace_existing) {
            Ok(summary) => {
                self.conn.execute_batch("COMMIT;")?;
                Ok(summary)
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK;");
                Err(error)
            }
        }
    }

    fn import_transfer_payload_in_transaction(
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct VaultTransferPayload {
    pub(crate) items: Vec<VaultItem>,
}

fn build_restored_vault_at(
    temp_path: &Path,
    package: &VaultBackupPackage,
) -> Result<(), VaultError> {
    let conn = Connection::open(temp_path)?;
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
    Ok(())
}

fn validate_restored_vault(temp_path: &Path, expected_item_count: usize) -> Result<(), VaultError> {
    let conn = Connection::open(temp_path)?;
    configure_connection(&conn)?;
    read_restored_header(&conn)?;
    let actual_item_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM items", [], |row| row.get(0))?;
    if actual_item_count as usize != expected_item_count {
        return Err(VaultError::InvalidArguments(format!(
            "restored vault item count mismatch: expected {expected_item_count}, found {actual_item_count}"
        )));
    }
    Ok(())
}

fn read_restored_header(conn: &Connection) -> Result<VaultHeader, VaultError> {
    let application_id: i64 = conn.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let user_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
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
    let header_json: String = conn.query_row(
        "SELECT value FROM metadata WHERE key = 'header_json'",
        [],
        |row| row.get(0),
    )?;
    Ok(serde_json::from_str(header_json.as_str())?)
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

    if output_path.exists() && !overwrite {
        return Err(VaultError::VaultExists(output_path.display().to_string()));
    }
    let parent = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let temp_dir = match parent {
        Some(parent) => {
            fs::create_dir_all(parent)?;
            parent.to_path_buf()
        }
        None => PathBuf::from("."),
    };
    let file_name = output_path.file_name().ok_or_else(|| {
        VaultError::InvalidArguments(format!(
            "restore output path {} has no file name",
            output_path.display()
        ))
    })?;
    let temp_name = format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        random_hex_id(8)?
    );
    let temp_path = temp_dir.join(temp_name);

    let build_result = build_restored_vault_at(&temp_path, &package)
        .and_then(|()| validate_restored_vault(&temp_path, package.items.len()));
    if let Err(error) = build_result {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }

    if let Err(error) = fs::rename(&temp_path, output_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error.into());
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

fn default_transfer_kdf_params() -> VaultKdfParams {
    VaultKdfParams {
        algorithm: "argon2id".to_string(),
        memory_cost_kib: DEFAULT_MEMORY_COST_KIB,
        iterations: DEFAULT_ITERATIONS,
        parallelism: DEFAULT_PARALLELISM,
        derived_key_len: MASTER_KEY_LEN,
    }
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

pub(crate) fn summarize_transfer_items<I>(
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

pub(crate) fn read_transfer_package(
    input_path: impl AsRef<Path>,
) -> Result<VaultTransferPackage, VaultError> {
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
