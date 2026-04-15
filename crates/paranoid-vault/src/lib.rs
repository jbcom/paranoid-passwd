use argon2::{Algorithm, Argon2, Params, Version, password_hash::SaltString};
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};
use paranoid_core::{GenerationReport, ParanoidRequest, execute_request};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zeroize::Zeroizing;

const FORMAT_VERSION: u32 = 1;
const MASTER_KEY_LEN: usize = 32;
const MASTER_KEY_AAD: &[u8] = b"paranoid-passwd::vault::master-key";
const ITEM_AAD_PREFIX: &[u8] = b"paranoid-passwd::vault::item::";
const DEFAULT_MEMORY_COST_KIB: u32 = 65_536;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 1;

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
pub enum VaultKeyslotKind {
    Password,
    Device,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKeyslot {
    pub id: String,
    pub kind: VaultKeyslotKind,
    pub wrapped_by_os_keystore: bool,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub tag_hex: String,
    pub encrypted_master_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub format_version: u32,
    pub created_at_epoch: i64,
    pub migration_state: String,
    pub kdf: VaultKdfParams,
    pub keyslots: Vec<VaultKeyslot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VaultItemKind {
    Login,
}

impl VaultItemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
        }
    }

    fn parse(value: &str) -> Result<Self, VaultError> {
        match value {
            "login" => Ok(Self::Login),
            _ => Err(VaultError::InvalidArguments(format!(
                "unsupported vault item kind: {value}"
            ))),
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultItemPayload {
    Login(LoginRecord),
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
    pub username: String,
    pub url: Option<String>,
    pub updated_at_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewLoginRecord {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateLoginRecord {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<Option<String>>,
    pub notes: Option<Option<String>>,
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

    pub fn add_login(&self, record: NewLoginRecord) -> Result<VaultItem, VaultError> {
        validate_login_record(&record)?;
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
            }),
        };
        self.store_item(&item)?;
        Ok(item)
    }

    pub fn list_items(&self) -> Result<Vec<VaultItemSummary>, VaultError> {
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

        rows.map(|row| {
            let item = self.decrypt_row(&row?)?;
            Ok(match &item.payload {
                VaultItemPayload::Login(login) => VaultItemSummary {
                    id: item.id,
                    kind: item.kind,
                    title: login.title.clone(),
                    username: login.username.clone(),
                    url: login.url.clone(),
                    updated_at_epoch: item.updated_at_epoch,
                },
            })
        })
        .collect()
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
        let VaultItemPayload::Login(login) = &mut item.payload;
        if let Some(title) = update.title {
            login.title = title;
        }
        if let Some(username) = update.username {
            login.username = username;
        }
        if let Some(password) = update.password {
            login.password = password;
        }
        if let Some(url) = update.url {
            login.url = url;
        }
        if let Some(notes) = update.notes {
            login.notes = notes;
        }
        validate_login_record(&NewLoginRecord {
            title: login.title.clone(),
            username: login.username.clone(),
            password: login.password.clone(),
            url: login.url.clone(),
            notes: login.notes.clone(),
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
        title: String,
        username: String,
        url: Option<String>,
        notes: Option<String>,
    ) -> Result<(GenerationReport, VaultItem), VaultError> {
        let report = execute_request(request, true, |_| {})
            .map_err(|error| VaultError::Generator(error.to_string()))?;
        let password = report
            .passwords
            .first()
            .map(|generated| generated.value.clone())
            .ok_or_else(|| VaultError::Generator("generator produced no passwords".to_string()))?;
        let item = self.add_login(NewLoginRecord {
            title,
            username,
            password,
            url,
            notes,
        })?;
        Ok((report, item))
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
            id: "primary".to_string(),
            kind: VaultKeyslotKind::Password,
            wrapped_by_os_keystore: false,
            salt_hex: hex_encode(salt.as_str().as_bytes()),
            nonce_hex: hex_encode(&wrapped.nonce),
            tag_hex: hex_encode(&wrapped.tag),
            encrypted_master_key_hex: hex_encode(&wrapped.ciphertext),
        }],
    };

    conn.execute(
        "INSERT INTO metadata (key, value) VALUES (?1, ?2)",
        params!["header_json", serde_json::to_string(&header)?],
    )?;

    Ok(header)
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
    let header_json: String = conn.query_row(
        "SELECT value FROM metadata WHERE key = 'header_json'",
        [],
        |row| row.get(0),
    )?;
    let header: VaultHeader = serde_json::from_str(&header_json)?;
    let keyslot = header
        .keyslots
        .iter()
        .find(|keyslot| keyslot.kind == VaultKeyslotKind::Password)
        .ok_or_else(|| VaultError::InvalidArguments("vault has no password keyslot".to_string()))?;
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

fn create_schema(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(
        "BEGIN;
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
         COMMIT;",
    )?;
    Ok(())
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

fn random_hex_id(len: usize) -> Result<String, VaultError> {
    Ok(hex_encode(random_bytes(len)?.as_slice()))
}

fn random_bytes(len: usize) -> Result<Vec<u8>, VaultError> {
    let mut bytes = vec![0_u8; len];
    rand_bytes(bytes.as_mut_slice())
        .map_err(|error| VaultError::RandomFailure(error.to_string()))?;
    Ok(bytes)
}

fn item_aad(id: &str) -> Vec<u8> {
    let mut aad = ITEM_AAD_PREFIX.to_vec();
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
            })
            .expect("add");
        let listed = vault.list_items().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].title, "Example");

        let fetched = vault.get_item(&item.id).expect("show");
        let VaultItemPayload::Login(login) = fetched.payload;
        assert_eq!(login.username, "jon@example.com");

        let updated = vault
            .update_login(
                &item.id,
                UpdateLoginRecord {
                    title: Some("Example Updated".to_string()),
                    ..UpdateLoginRecord::default()
                },
            )
            .expect("update");
        let VaultItemPayload::Login(login) = updated.payload;
        assert_eq!(login.title, "Example Updated");

        vault.delete_item(&item.id).expect("delete");
        assert!(vault.list_items().expect("list").is_empty());
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
    fn generate_and_store_uses_core_generator() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let (report, item) = vault
            .generate_and_store(
                &ParanoidRequest::default(),
                "Generated".to_string(),
                "jon@example.com".to_string(),
                None,
                None,
            )
            .expect("generate+store");
        assert_eq!(report.passwords.len(), 1);
        let stored = vault.get_item(&item.id).expect("show");
        let VaultItemPayload::Login(login) = stored.payload;
        assert_eq!(login.password, report.passwords[0].value);
    }
}
