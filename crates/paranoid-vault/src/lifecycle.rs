use crate::{
    AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN, CERTIFICATE_MASTER_KEY_AAD, CalibrationOutcome, CardRecord,
    CertificateKeyslotWrapMode, CertificateWrappedSecret, DEFAULT_KDF_CALIBRATION_TARGET,
    DEFAULT_MEMORY_COST_KIB, DEVICE_AAD_PREFIX, DEVICE_CHECK_PLAINTEXT, FORMAT_VERSION,
    GenerateStoreLoginRecord, ITEM_AAD_PREFIX, IdentityRecord, LockedSecretBuffer, LoginRecord,
    MASTER_KEY_AAD, MASTER_KEY_LEN, MNEMONIC_AAD_PREFIX, NewCardRecord, NewIdentityRecord,
    NewLoginRecord, NewSecureNoteRecord, NormalizedVaultItemFilter, PASSWORD_WRAP_ALGORITHM,
    PasswordHistoryEntry, SQLITE_APPLICATION_ID, SecureNoteRecord, UpdateCardRecord,
    UpdateIdentityRecord, UpdateLoginRecord, UpdateSecureNoteRecord, VaultError, VaultHeader,
    VaultItem, VaultItemFilter, VaultItemKind, VaultItemPayload, VaultItemSummary, VaultKdfParams,
    VaultKeyslot, VaultKeyslotKind, calibrate_kdf_params, certificate_keyslot_metadata,
    check_lockout, clear_lockout, decode_certificate_slot_hex, load_certificate, load_private_key,
    mnemonic_entropy_from_phrase, record_failed_unlock, select_device_keyslot,
    select_mnemonic_keyslot, unwrap_legacy_secret_with_certificate, unwrap_secret_with_certificate,
    validate_certificate_keyslot_metadata, validate_mnemonic_keyslot_metadata,
};
use argon2::{Algorithm, Argon2, Params, Version, password_hash::SaltString};
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};
use paranoid_core::{GenerationReport, ParanoidRequest, execute_request};
use rusqlite::{Connection, OptionalExtension, params};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct UnlockedVault {
    pub(crate) path: PathBuf,
    pub(crate) conn: Connection,
    pub(crate) header: VaultHeader,
    pub(crate) master_key: LockedSecretBuffer,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("path", &self.path)
            .field("conn", &self.conn)
            .field("header", &self.header)
            .field(
                "master_key",
                &format_args!("<redacted> ({} bytes)", self.master_key.len()),
            )
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct StoredVaultRow {
    pub(crate) id: String,
    pub(crate) kind: String,
    pub(crate) created_at_epoch: i64,
    pub(crate) updated_at_epoch: i64,
    pub(crate) nonce: Vec<u8>,
    pub(crate) tag: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct EncryptedBlob {
    pub(crate) nonce: Vec<u8>,
    pub(crate) tag: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
}

impl UnlockedVault {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
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

    pub(crate) fn load_all_items(&self) -> Result<Vec<VaultItem>, VaultError> {
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
        if let Some(password) = update.password
            && password != login.password
        {
            login.password_history.push(PasswordHistoryEntry {
                password: login.password.clone(),
                changed_at_epoch: updated_at_epoch,
            });
            login.password = password;
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
                    password: Some(password.into()),
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
                password: password.into(),
                url: record.url,
                notes: record.notes,
                folder: record.folder,
                tags: record.tags.unwrap_or_default(),
            })?
        };
        Ok((report, item))
    }

    pub(crate) fn store_item(&self, item: &VaultItem) -> Result<(), VaultError> {
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

    pub(crate) fn load_row(&self, id: &str) -> Result<StoredVaultRow, VaultError> {
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

    pub(crate) fn decrypt_row(&self, row: &StoredVaultRow) -> Result<VaultItem, VaultError> {
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

    pub(crate) fn persist_header(&self) -> Result<(), VaultError> {
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

pub fn init_vault(
    path: impl AsRef<Path>,
    master_password: &str,
) -> Result<VaultHeader, VaultError> {
    Ok(init_vault_unlocked(path, master_password)?.header)
}

/// Creates a fresh vault at `path` and returns it already unlocked, reusing
/// the master key derived during initialization instead of making the caller
/// perform a second, separate Argon2id derivation via [`unlock_vault`] just
/// to obtain a handle. Callers that only need the header (most tests, and
/// any caller not about to operate on the vault immediately) should use
/// [`init_vault`] instead; this variant exists for callers such as the TUI's
/// init flow that unlock the vault as their very next step.
pub fn init_vault_unlocked(
    path: impl AsRef<Path>,
    master_password: &str,
) -> Result<UnlockedVault, VaultError> {
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
    // P9.5: calibrate Argon2id params to this host's wall-clock cost rather
    // than always writing the fixed DEFAULT_* constants. `calibrate_kdf_params`
    // clamps memory_cost_kib to MEMORY_COST_FLOOR_KIB (== DEFAULT_MEMORY_COST_KIB)
    // on every path, including its own fallback, so this can only ever
    // strengthen the params relative to the old fixed default, never weaken
    // them. On a constrained host where the floor-memory benchmark itself
    // fails, calibration falls back to the fixed defaults and that fallback
    // is surfaced here rather than silently swallowed.
    let calibration = calibrate_kdf_params(DEFAULT_KDF_CALIBRATION_TARGET, MASTER_KEY_LEN);
    if calibration.outcome == CalibrationOutcome::FallbackToDefaults {
        eprintln!(
            "warning: Argon2id runtime calibration failed on this host; falling back to \
             the fixed default KDF parameters (memory_cost_kib={}, iterations={})",
            calibration.params.memory_cost_kib, calibration.params.iterations
        );
    }
    let params = calibration.params;
    debug_assert!(params.memory_cost_kib >= DEFAULT_MEMORY_COST_KIB);
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

    Ok(UnlockedVault {
        path: path.to_path_buf(),
        conn,
        header,
        master_key: LockedSecretBuffer::new(master_key),
    })
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
    check_lockout(path)?;
    let result = unlock_vault_inner(path, master_password);
    record_unlock_outcome(path, &result)?;
    result
}

fn unlock_vault_inner(path: &Path, master_password: &str) -> Result<UnlockedVault, VaultError> {
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
        master_key: LockedSecretBuffer::new(master_key),
    })
}

pub fn unlock_vault_with_certificate(
    path: impl AsRef<Path>,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    private_key_passphrase: Option<&str>,
) -> Result<UnlockedVault, VaultError> {
    let path = path.as_ref();
    check_lockout(path)?;
    let result = unlock_vault_with_certificate_inner(
        path,
        certificate_pem,
        private_key_pem,
        private_key_passphrase,
    );
    record_unlock_outcome(path, &result)?;
    result
}

fn unlock_vault_with_certificate_inner(
    path: &Path,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    private_key_passphrase: Option<&str>,
) -> Result<UnlockedVault, VaultError> {
    if !path.exists() {
        return Err(VaultError::VaultNotFound(path.display().to_string()));
    }

    let conn = Connection::open(path)?;
    configure_connection(&conn)?;
    let header = read_header(&conn)?;

    let certificate = load_certificate(certificate_pem)?;
    let metadata = certificate_keyslot_metadata(&certificate)?;
    let keyslot = header
        .keyslots
        .iter()
        .find(|keyslot| {
            keyslot.kind == VaultKeyslotKind::CertificateWrapped
                && keyslot.certificate_fingerprint_sha256.as_deref()
                    == Some(metadata.fingerprint_sha256.as_str())
        })
        .ok_or(VaultError::UnlockFailed)?;
    let wrap_mode = validate_certificate_keyslot_metadata(keyslot, &metadata)?;
    let private_key = load_private_key(private_key_pem, private_key_passphrase)?;
    let master_key = match wrap_mode {
        CertificateKeyslotWrapMode::Legacy => {
            let wrapped = decode_certificate_slot_hex(keyslot.encrypted_master_key_hex.as_str())?;
            unwrap_legacy_secret_with_certificate(wrapped.as_slice(), &certificate, &private_key)
        }
        CertificateKeyslotWrapMode::Current => unwrap_secret_with_certificate(
            CertificateWrappedSecret {
                wrapped_transport_key_der: decode_certificate_slot_hex(keyslot.salt_hex.as_str())?,
                encrypted_secret: EncryptedBlob {
                    nonce: decode_certificate_slot_hex(keyslot.nonce_hex.as_str())?,
                    tag: decode_certificate_slot_hex(keyslot.tag_hex.as_str())?,
                    ciphertext: decode_certificate_slot_hex(
                        keyslot.encrypted_master_key_hex.as_str(),
                    )?,
                },
            },
            &certificate,
            &private_key,
            CERTIFICATE_MASTER_KEY_AAD,
        ),
    }
    .map_err(|_| VaultError::UnlockFailed)?;

    Ok(UnlockedVault {
        path: path.to_path_buf(),
        conn,
        header,
        master_key: LockedSecretBuffer::new(master_key),
    })
}

pub fn unlock_vault_with_mnemonic(
    path: impl AsRef<Path>,
    mnemonic_phrase: &str,
    slot_id: Option<&str>,
) -> Result<UnlockedVault, VaultError> {
    let path = path.as_ref();
    check_lockout(path)?;
    let result = unlock_vault_with_mnemonic_inner(path, mnemonic_phrase, slot_id);
    record_unlock_outcome(path, &result)?;
    result
}

fn unlock_vault_with_mnemonic_inner(
    path: &Path,
    mnemonic_phrase: &str,
    slot_id: Option<&str>,
) -> Result<UnlockedVault, VaultError> {
    if !path.exists() {
        return Err(VaultError::VaultNotFound(path.display().to_string()));
    }

    let conn = Connection::open(path)?;
    configure_connection(&conn)?;
    let header = read_header(&conn)?;
    let keyslot = select_mnemonic_keyslot(&header, slot_id)?;
    validate_mnemonic_keyslot_metadata(keyslot)?;
    let mnemonic_entropy = mnemonic_entropy_from_phrase(mnemonic_phrase)?;

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
        master_key: LockedSecretBuffer::new(master_key),
    })
}

pub fn unlock_vault_with_device(
    path: impl AsRef<Path>,
    slot_id: Option<&str>,
) -> Result<UnlockedVault, VaultError> {
    let path = path.as_ref();
    check_lockout(path)?;
    let result = unlock_vault_with_device_inner(path, slot_id);
    record_unlock_outcome(path, &result)?;
    result
}

fn unlock_vault_with_device_inner(
    path: &Path,
    slot_id: Option<&str>,
) -> Result<UnlockedVault, VaultError> {
    if !path.exists() {
        return Err(VaultError::VaultNotFound(path.display().to_string()));
    }

    let conn = Connection::open(path)?;
    configure_connection(&conn)?;
    let header = read_header(&conn)?;
    let keyslot = select_device_keyslot(&header, slot_id)?;
    let master_key = read_verified_device_keyslot_secret(keyslot)?;

    Ok(UnlockedVault {
        path: path.to_path_buf(),
        conn,
        header,
        master_key,
    })
}

/// Records the lockout outcome of one unlock attempt: a successful unlock
/// clears any durable lockout record, and a failed one records a new failed
/// attempt — EXCEPT `VaultNotFound` and a lockout error that was already
/// surfaced by the caller's own `check_lockout` above, neither of which
/// represents a wrong-credential guess against an existing vault and so
/// must not itself feed the backoff counter.
fn record_unlock_outcome(
    path: &Path,
    result: &Result<UnlockedVault, VaultError>,
) -> Result<(), VaultError> {
    match result {
        Ok(_) => clear_lockout(path),
        Err(VaultError::VaultNotFound(_) | VaultError::LockedOut { .. }) => Ok(()),
        Err(_) => record_failed_unlock(path),
    }
}

pub(crate) fn read_verified_device_keyslot_secret(
    keyslot: &VaultKeyslot,
) -> Result<LockedSecretBuffer, VaultError> {
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
    let master_key = LockedSecretBuffer::new(device_store_get_secret(service, account)?);
    if master_key.len() != MASTER_KEY_LEN {
        return Err(VaultError::UnlockFailed);
    }
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

    Ok(master_key)
}

pub(crate) fn create_schema(conn: &Connection) -> Result<(), VaultError> {
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

pub(crate) fn configure_connection(conn: &Connection) -> Result<(), VaultError> {
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

pub(crate) fn derive_key(
    master_password: &str,
    salt: &SaltString,
    params: &VaultKdfParams,
) -> Result<LockedSecretBuffer, VaultError> {
    let argon_params = Params::new(
        params.memory_cost_kib,
        params.iterations,
        params.parallelism,
        Some(params.derived_key_len),
    )
    .map_err(|error| VaultError::Argon2(error.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    // Locked from the moment it exists: the Argon2id-derived KEK is, along
    // with the master key itself, the highest-value secret buffer in the
    // process (whoever holds it can unwrap the master key and every vault
    // item). `mlock`ing it here (P9.3) means the kernel never swaps or
    // hibernates it to disk for the entire time it's resident, not just
    // after some later wrapping step.
    let mut derived = LockedSecretBuffer::new(vec![0_u8; params.derived_key_len]);
    argon
        .hash_password_into(
            master_password.as_bytes(),
            salt.as_salt().as_str().as_bytes(),
            derived.as_mut_slice(),
        )
        .map_err(|error| VaultError::Argon2(error.to_string()))?;
    Ok(derived)
}

pub(crate) fn encrypt_blob(
    key: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedBlob, VaultError> {
    let cipher = Cipher::aes_256_gcm();
    let nonce = random_bytes(AES_GCM_NONCE_LEN)?;
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
    let mut tag = vec![0_u8; AES_GCM_TAG_LEN];
    crypter
        .get_tag(tag.as_mut_slice())
        .map_err(|error| VaultError::CryptoFailure(error.to_string()))?;
    Ok(EncryptedBlob {
        nonce,
        tag,
        ciphertext,
    })
}

pub(crate) fn decrypt_blob(
    key: &[u8],
    aad: &[u8],
    blob: EncryptedBlob,
) -> Result<Vec<u8>, VaultError> {
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
    if record.content.as_str().trim().is_empty() {
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
    if record.number.as_str().trim().is_empty() {
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
    if record.security_code.as_str().trim().is_empty() {
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

pub(crate) fn item_summary(item: &VaultItem, duplicate_password_count: usize) -> VaultItemSummary {
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
            subtitle: secure_note_preview(note.content.as_str()),
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
                card_number_preview(card.number.as_str())
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

pub(crate) fn duplicate_password_counts(items: &[VaultItem]) -> HashMap<String, usize> {
    // Duplicate-password detection is inherently a plaintext comparison
    // across every login's password, so this local, function-scoped map
    // necessarily holds plaintext `String` copies of each password for the
    // duration of the count — there is no way to detect "these two secrets
    // are equal" without comparing their bytes. The map (and its copies)
    // are dropped at the end of this function; the `SecretBytes` wrapper on
    // `LoginRecord.password` still ensures the copy resident in the vault
    // item itself, and every other clone of it, zeroizes on drop.
    let mut password_totals = HashMap::<String, usize>::new();
    for item in items {
        if let VaultItemPayload::Login(login) = &item.payload {
            *password_totals
                .entry(login.password.as_str().to_string())
                .or_insert(0) += 1;
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

pub(crate) fn item_matches_filter(item: &VaultItem, filter: &NormalizedVaultItemFilter) -> bool {
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

pub(crate) fn normalize_and_validate_item(item: &mut VaultItem) -> Result<(), VaultError> {
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
                    || field_matches(note.content.as_str(), normalized_query)
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
                    || field_matches(card.number.as_str(), normalized_query)
                    || field_matches(&card.expiry_month, normalized_query)
                    || field_matches(&card.expiry_year, normalized_query)
                    || field_matches(card.security_code.as_str(), normalized_query)
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

pub(crate) fn normalize_tags(tags: &[String]) -> Vec<String> {
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

pub(crate) fn normalize_folder(folder: Option<String>) -> Option<String> {
    folder.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

pub(crate) fn random_hex_id(len: usize) -> Result<String, VaultError> {
    Ok(hex_encode(random_bytes(len)?.as_slice()))
}

pub(crate) fn next_unused_item_id(vault: &UnlockedVault) -> Result<String, VaultError> {
    loop {
        let candidate = random_hex_id(16)?;
        match vault.load_row(candidate.as_str()) {
            Ok(_) => continue,
            Err(VaultError::ItemNotFound(_)) => return Ok(candidate),
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn random_bytes(len: usize) -> Result<Vec<u8>, VaultError> {
    let mut bytes = vec![0_u8; len];
    rand_bytes(bytes.as_mut_slice())
        .map_err(|error| VaultError::RandomFailure(error.to_string()))?;
    Ok(bytes)
}

pub(crate) fn item_aad(id: &str) -> Vec<u8> {
    let mut aad = ITEM_AAD_PREFIX.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

pub(crate) fn device_slot_aad(id: &str) -> Vec<u8> {
    let mut aad = DEVICE_AAD_PREFIX.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

pub(crate) fn mnemonic_slot_aad(id: &str) -> Vec<u8> {
    let mut aad = MNEMONIC_AAD_PREFIX.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

pub(crate) fn unix_epoch_now() -> Result<i64, VaultError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| VaultError::InvalidArguments(error.to_string()))?;
    i64::try_from(duration.as_secs())
        .map_err(|error| VaultError::InvalidArguments(error.to_string()))
}

fn sqlite_format_pragmas_sql() -> String {
    format!(
        "PRAGMA application_id = {SQLITE_APPLICATION_ID};\nPRAGMA user_version = {FORMAT_VERSION};"
    )
}

#[cfg(all(
    debug_assertions,
    not(test),
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
fn debug_device_store_root() -> Option<PathBuf> {
    std::env::var_os("PARANOID_TEST_DEVICE_STORE_DIR").and_then(|value| {
        if value.is_empty() {
            None
        } else {
            Some(PathBuf::from(value))
        }
    })
}

#[cfg(all(
    debug_assertions,
    not(test),
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
fn debug_device_store_path(root: &Path, service: &str, account: &str) -> PathBuf {
    root.join(hex_encode(format!("{service}\u{0}{account}").as_bytes()).as_str())
}

#[cfg(all(
    debug_assertions,
    not(test),
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
fn debug_device_store_set_secret(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<bool, VaultError> {
    let Some(root) = debug_device_store_root() else {
        return Ok(false);
    };
    fs::create_dir_all(root.as_path())?;
    fs::write(
        debug_device_store_path(root.as_path(), service, account),
        secret,
    )?;
    Ok(true)
}

#[cfg(all(
    debug_assertions,
    not(test),
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
fn debug_device_store_get_secret(
    service: &str,
    account: &str,
) -> Result<Option<Vec<u8>>, VaultError> {
    let Some(root) = debug_device_store_root() else {
        return Ok(None);
    };
    let path = debug_device_store_path(root.as_path(), service, account);
    match fs::read(path) {
        Ok(secret) => Ok(Some(secret)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(VaultError::UnlockFailed),
        Err(error) => Err(VaultError::Io(error)),
    }
}

#[cfg(all(
    debug_assertions,
    not(test),
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
fn debug_device_store_delete_secret(service: &str, account: &str) -> Result<bool, VaultError> {
    let Some(root) = debug_device_store_root() else {
        return Ok(false);
    };
    let path = debug_device_store_path(root.as_path(), service, account);
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(VaultError::UnlockFailed),
        Err(error) => Err(VaultError::Io(error)),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
#[cfg(not(test))]
pub(crate) fn device_store_set_secret(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), VaultError> {
    #[cfg(debug_assertions)]
    if debug_device_store_set_secret(service, account, secret)? {
        return Ok(());
    }
    let entry = keyring::Entry::new(service, account)
        .map_err(|error| VaultError::DeviceStoreFailure(error.to_string()))?;
    entry
        .set_secret(secret)
        .map_err(|error| VaultError::DeviceStoreFailure(error.to_string()))
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
#[cfg(not(test))]
pub(crate) fn device_store_get_secret(service: &str, account: &str) -> Result<Vec<u8>, VaultError> {
    #[cfg(debug_assertions)]
    if let Some(secret) = debug_device_store_get_secret(service, account)? {
        return Ok(secret);
    }
    let entry = keyring::Entry::new(service, account)
        .map_err(|error| VaultError::DeviceStoreFailure(error.to_string()))?;
    entry.get_secret().map_err(|error| match error {
        keyring::Error::NoEntry => VaultError::UnlockFailed,
        other => VaultError::DeviceStoreFailure(other.to_string()),
    })
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
#[cfg(not(test))]
pub(crate) fn device_store_delete_secret(service: &str, account: &str) -> Result<(), VaultError> {
    #[cfg(debug_assertions)]
    if debug_device_store_delete_secret(service, account)? {
        return Ok(());
    }
    let entry = keyring::Entry::new(service, account)
        .map_err(|error| VaultError::DeviceStoreFailure(error.to_string()))?;
    entry.delete_credential().map_err(|error| match error {
        keyring::Error::NoEntry => VaultError::UnlockFailed,
        other => VaultError::DeviceStoreFailure(other.to_string()),
    })
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
#[cfg(not(test))]
pub(crate) fn device_store_set_secret(
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
pub(crate) fn device_store_get_secret(
    _service: &str,
    _account: &str,
) -> Result<Vec<u8>, VaultError> {
    Err(VaultError::DeviceStoreFailure(
        "device-bound secure storage is unsupported on this platform".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
#[cfg(not(test))]
pub(crate) fn device_store_delete_secret(_service: &str, _account: &str) -> Result<(), VaultError> {
    Err(VaultError::DeviceStoreFailure(
        "device-bound secure storage is unsupported on this platform".to_string(),
    ))
}

#[cfg(test)]
pub(crate) fn device_store_set_secret(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), VaultError> {
    let mut store = test_device_store().lock().map_err(|_| {
        VaultError::DeviceStoreFailure("device test store lock poisoned".to_string())
    })?;
    store.insert(device_store_key(service, account), secret.to_vec());
    Ok(())
}

#[cfg(test)]
pub(crate) fn device_store_get_secret(service: &str, account: &str) -> Result<Vec<u8>, VaultError> {
    let store = test_device_store().lock().map_err(|_| {
        VaultError::DeviceStoreFailure("device test store lock poisoned".to_string())
    })?;
    store
        .get(&device_store_key(service, account))
        .cloned()
        .ok_or(VaultError::UnlockFailed)
}

#[cfg(test)]
pub(crate) fn device_store_delete_secret(service: &str, account: &str) -> Result<(), VaultError> {
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

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn hex_decode(input: &str) -> Result<Vec<u8>, VaultError> {
    if !input.len().is_multiple_of(2) {
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
