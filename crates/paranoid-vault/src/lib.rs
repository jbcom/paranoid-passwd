mod native_access;

mod backup_transfer;
mod keyslots;
mod lifecycle;
mod recovery_posture;

pub use backup_transfer::*;
pub use keyslots::*;
pub use lifecycle::*;
pub use recovery_posture::*;

pub use native_access::{
    NativeSessionHardening, SecretString, VaultAuth, VaultOpenOptions, default_vault_path,
    read_master_password, unlock_vault_for_options,
};

use serde::{Deserialize, Serialize};

use thiserror::Error;

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

const DEFAULT_MEMORY_COST_KIB: u32 = 262_144;

const DEFAULT_ITERATIONS: u32 = 3;

const DEFAULT_PARALLELISM: u32 = 1;

const PASSWORD_WRAP_ALGORITHM: &str = "argon2id+aes-256-gcm";

const MNEMONIC_WRAP_ALGORITHM: &str = "bip39-entropy+aes-256-gcm";

const LEGACY_CERTIFICATE_WRAP_ALGORITHM: &str = "cms-envelope+aes-256-cbc";

const CERTIFICATE_WRAP_ALGORITHM: &str = "cms-envelope+transport-key+aes-256-gcm";

const DEVICE_WRAP_ALGORITHM: &str = "os-keyring+aes-256-gcm-check";

const AES_GCM_NONCE_LEN: usize = 12;

const AES_GCM_TAG_LEN: usize = 16;

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
    #[error("export destination {0} resolves to the source vault path; refusing to overwrite it")]
    ExportPathCollision(String),
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
pub(crate) struct NormalizedVaultItemFilter {
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

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::SaltString;
    use bip39::{Language, Mnemonic};
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        rsa::Rsa,
        symm::Cipher,
        x509::{X509, X509Name},
    };
    use paranoid_core::ParanoidRequest;
    use paranoid_seal::VaultSealProviderKind;
    use rusqlite::{Connection, params};
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    #[test]
    fn argon2id_default_kdf_parameters_known_answers_hold() {
        assert_eq!(DEFAULT_MEMORY_COST_KIB, 262_144);
        assert_eq!(DEFAULT_ITERATIONS, 3);
        assert_eq!(DEFAULT_PARALLELISM, 1);
    }

    #[test]
    fn argon2id_derive_key_matches_known_answer() {
        // Deliberately small (8 MiB) cost parameters so this test stays fast;
        // production defaults are locked separately above. Fixed password,
        // fixed salt, explicit params: pins algorithm identity (argon2id),
        // version (0x13), salt handling, and output length end to end.
        let params = VaultKdfParams {
            algorithm: "argon2id".to_string(),
            memory_cost_kib: 8192,
            iterations: 3,
            parallelism: 1,
            derived_key_len: 32,
        };
        let salt = SaltString::encode_b64(&[7_u8; 16]).expect("salt");
        let derived = derive_key("correct horse battery staple", &salt, &params)
            .expect("argon2id derivation succeeds");
        assert_eq!(derived.len(), 32);
        assert_eq!(
            hex_encode(derived.as_slice()),
            "1fa5912167c7e28c5f8b3a77089ee2a64ba6a5672a142a11fb19523448d04bc3"
        );
    }

    #[test]
    #[ignore]
    fn bench_argon2id_derive_cost_by_memory() {
        for (label, memory_cost_kib) in [
            ("64MiB (previous default)", 65_536_u32),
            ("128MiB", 131_072_u32),
            (
                "256MiB (libsodium MODERATE parity, new default)",
                262_144_u32,
            ),
        ] {
            let params = VaultKdfParams {
                algorithm: "argon2id".to_string(),
                memory_cost_kib,
                iterations: DEFAULT_ITERATIONS,
                parallelism: DEFAULT_PARALLELISM,
                derived_key_len: MASTER_KEY_LEN,
            };
            let salt = SaltString::encode_b64(&[7_u8; 16]).expect("salt");
            let start = std::time::Instant::now();
            derive_key("correct horse battery staple", &salt, &params).expect("derive");
            eprintln!("{label}: {:?}", start.elapsed());
        }
    }

    #[test]
    fn vault_created_with_legacy_kdf_params_still_unlocks() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        let header = init_vault(&path, "correct horse battery staple").expect("init");
        assert_eq!(header.kdf.memory_cost_kib, DEFAULT_MEMORY_COST_KIB);

        let legacy_params = VaultKdfParams {
            algorithm: "argon2id".to_string(),
            memory_cost_kib: 65_536,
            iterations: 3,
            parallelism: 1,
            derived_key_len: MASTER_KEY_LEN,
        };
        let salt_bytes = random_bytes(16).expect("salt bytes");
        let salt = SaltString::encode_b64(salt_bytes.as_slice()).expect("salt");
        let kek = derive_key("correct horse battery staple", &salt, &legacy_params).expect("kek");
        let master_key = random_bytes(MASTER_KEY_LEN).expect("master key");
        let wrapped =
            encrypt_blob(kek.as_slice(), MASTER_KEY_AAD, master_key.as_slice()).expect("wrap");

        let mut legacy_header = header;
        legacy_header.kdf = legacy_params;
        legacy_header.keyslots[0].salt_hex = hex_encode(salt.as_str().as_bytes());
        legacy_header.keyslots[0].nonce_hex = hex_encode(&wrapped.nonce);
        legacy_header.keyslots[0].tag_hex = hex_encode(&wrapped.tag);
        legacy_header.keyslots[0].encrypted_master_key_hex = hex_encode(&wrapped.ciphertext);

        let conn = Connection::open(&path).expect("open");
        conn.execute(
            "UPDATE metadata SET value = ?1 WHERE key = 'header_json'",
            params![serde_json::to_string(&legacy_header).expect("serialize")],
        )
        .expect("rewrite header");
        drop(conn);

        let vault = unlock_vault(&path, "correct horse battery staple")
            .expect("legacy-params vault must still unlock");
        assert_eq!(vault.list_items().expect("list").len(), 0);
    }

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
    fn unlocked_vault_debug_redacts_master_key() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");

        let debug_output = format!("{vault:?}");

        assert!(debug_output.contains("<redacted>"));
        let key_hex = hex_encode(&vault.master_key);
        assert!(!debug_output.contains(&key_hex));
        assert!(
            !debug_output
                .as_bytes()
                .windows(vault.master_key.len())
                .any(|window| window == vault.master_key.as_slice())
        );
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
    fn backup_does_not_export_device_secure_storage_secret() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("vault.sqlite");
        let backup = dir.path().join("vault-backup.ppv.json");
        let restored = dir.path().join("restored.sqlite");
        init_vault(&source, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        let device_slot = vault
            .add_device_keyslot(Some("daily".to_string()))
            .expect("device slot");
        let service = device_slot.device_service.as_deref().expect("service");
        let account = device_slot.device_account.as_deref().expect("account");
        let device_secret = device_store_get_secret(service, account).expect("device secret");
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

        vault.export_backup(&backup).expect("export backup");
        let backup_json = fs::read_to_string(&backup).expect("read backup");
        assert!(
            !backup_json.contains(hex_encode(device_secret.as_slice()).as_str()),
            "backup package must not contain the raw device secure-storage secret"
        );
        let package: VaultBackupPackage =
            serde_json::from_str(backup_json.as_str()).expect("parse backup");
        let backed_up_slot = package
            .header
            .keyslots
            .iter()
            .find(|slot| slot.id == device_slot.id)
            .expect("backed-up device slot");
        assert_eq!(backed_up_slot.kind, VaultKeyslotKind::DeviceBound);
        assert_eq!(backed_up_slot.device_service.as_deref(), Some(service));
        assert_eq!(backed_up_slot.device_account.as_deref(), Some(account));

        device_store_delete_secret(service, account).expect("delete local device secret");
        restore_vault_backup(&backup, &restored, false).expect("restore backup");
        let error = unlock_vault_with_device(&restored, Some(device_slot.id.as_str()))
            .expect_err("restored backup should require the same device secure-storage secret");
        assert!(matches!(error, VaultError::UnlockFailed));
    }

    #[test]
    fn backup_does_not_export_mnemonic_phrase_or_entropy() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("vault.sqlite");
        let backup = dir.path().join("vault-backup.ppv.json");
        let restored = dir.path().join("restored.sqlite");
        init_vault(&source, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        let enrollment = vault
            .add_mnemonic_keyslot(Some("paper".to_string()))
            .expect("mnemonic slot");
        let mnemonic = Mnemonic::parse_in(Language::English, enrollment.mnemonic.as_str())
            .expect("parse mnemonic");
        let mnemonic_entropy_hex = hex_encode(mnemonic.to_entropy().as_slice());
        vault
            .add_login(NewLoginRecord {
                title: "Mnemonic Backup".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Recovery".to_string()),
                tags: vec!["recovery".to_string()],
            })
            .expect("add login");

        vault.export_backup(&backup).expect("export backup");
        let backup_json = fs::read_to_string(&backup).expect("read backup");
        assert!(
            !backup_json.contains(enrollment.mnemonic.as_str()),
            "backup package must not contain the mnemonic phrase"
        );
        assert!(
            !backup_json.contains(mnemonic_entropy_hex.as_str()),
            "backup package must not contain the raw mnemonic entropy"
        );

        restore_vault_backup(&backup, &restored, false).expect("restore backup");
        let restored_vault = unlock_vault_with_mnemonic(
            &restored,
            enrollment.mnemonic.as_str(),
            Some(enrollment.keyslot.id.as_str()),
        )
        .expect("unlock restored backup with mnemonic");
        let items = restored_vault.list_items().expect("list restored");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Mnemonic Backup");
    }

    #[test]
    fn backup_does_not_export_certificate_private_key_or_raw_transport_key() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("vault.sqlite");
        let backup = dir.path().join("vault-backup.ppv.json");
        let restored = dir.path().join("restored.sqlite");
        init_vault(&source, "correct horse battery staple").expect("init");

        let (certificate_pem, private_key_pem) = test_certificate_pair();
        let mut vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        let keyslot = vault
            .add_certificate_keyslot(certificate_pem.as_slice(), Some("ops".to_string()))
            .expect("certificate slot");
        let wrapped_transport_key_hex = keyslot.salt_hex.clone();
        let certificate = load_certificate(certificate_pem.as_slice()).expect("load certificate");
        let private_key =
            load_private_key(private_key_pem.as_slice(), None).expect("load private key");
        let raw_transport_key = Zeroizing::new(
            unwrap_legacy_secret_with_certificate(
                hex_decode(keyslot.salt_hex.as_str())
                    .expect("wrapped transport key")
                    .as_slice(),
                &certificate,
                &private_key,
            )
            .expect("unwrap transport key"),
        );
        let raw_transport_key_hex = hex_encode(raw_transport_key.as_slice());
        vault
            .add_secure_note(NewSecureNoteRecord {
                title: "Certificate Backup".to_string(),
                content: "certificate path".to_string(),
                folder: Some("Recovery".to_string()),
                tags: vec!["recovery".to_string()],
            })
            .expect("add note");

        vault.export_backup(&backup).expect("export backup");
        let backup_json = fs::read_to_string(&backup).expect("read backup");
        assert!(
            !backup_json.contains(std::str::from_utf8(private_key_pem.as_slice()).expect("pem")),
            "backup package must not contain the certificate private key"
        );
        assert!(
            !backup_json.contains(raw_transport_key_hex.as_str()),
            "backup package must not contain the raw certificate transport key"
        );
        assert!(
            backup_json.contains(wrapped_transport_key_hex.as_str()),
            "backup package preserves only the CMS-wrapped transport key"
        );
        assert!(
            !backup_json.contains("private_key"),
            "backup package must not add private-key material fields"
        );

        let package: VaultBackupPackage =
            serde_json::from_str(backup_json.as_str()).expect("parse backup");
        let backed_up_slot = package
            .header
            .keyslots
            .iter()
            .find(|slot| slot.id == keyslot.id)
            .expect("backed-up certificate slot");
        assert_eq!(backed_up_slot.kind, VaultKeyslotKind::CertificateWrapped);
        assert_eq!(backed_up_slot.wrap_algorithm, CERTIFICATE_WRAP_ALGORITHM);
        assert_eq!(
            backed_up_slot.certificate_fingerprint_sha256,
            keyslot.certificate_fingerprint_sha256
        );

        restore_vault_backup(&backup, &restored, false).expect("restore backup");
        let restored_vault = unlock_vault_with_certificate(
            &restored,
            certificate_pem.as_slice(),
            private_key_pem.as_slice(),
            None,
        )
        .expect("unlock restored backup with certificate");
        let items = restored_vault.list_items().expect("list restored");
        assert_eq!(items.len(), 1);
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
    fn export_backup_rejects_output_path_equal_to_vault_path() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("vault.sqlite");
        init_vault(&source, "correct horse battery staple").expect("init");
        let vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: None,
                tags: vec![],
            })
            .expect("add login");
        let before = fs::read(&source).expect("read vault before export");

        let error = vault
            .export_backup(&source)
            .expect_err("export to the vault's own path must fail closed");
        assert!(matches!(error, VaultError::ExportPathCollision(_)));

        let after = fs::read(&source).expect("read vault after export attempt");
        assert_eq!(
            before, after,
            "vault file must be untouched after rejection"
        );
        assert_eq!(vault.list_items().expect("list items").len(), 1);
    }

    #[test]
    fn export_backup_rejects_output_path_equal_to_vault_path_via_relative_components() {
        let dir = tempdir().expect("tempdir");
        let nested = dir.path().join("nested");
        fs::create_dir_all(&nested).expect("mkdir nested");
        let source = nested.join("vault.sqlite");
        init_vault(&source, "correct horse battery staple").expect("init");
        let vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");

        let indirect_path = nested.join("..").join("nested").join("vault.sqlite");
        let error = vault
            .export_backup(&indirect_path)
            .expect_err("canonicalized collision must be rejected");
        assert!(matches!(error, VaultError::ExportPathCollision(_)));
    }

    #[test]
    fn export_transfer_package_rejects_output_path_equal_to_vault_path() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("vault.sqlite");
        init_vault(&source, "correct horse battery staple").expect("init");
        let vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: None,
                tags: vec![],
            })
            .expect("add login");
        let before = fs::read(&source).expect("read vault before export");

        let error = vault
            .export_transfer_package(&source, &VaultItemFilter::default(), Some("secret"), None)
            .expect_err("export-transfer to the vault's own path must fail closed");
        assert!(matches!(error, VaultError::ExportPathCollision(_)));

        let after = fs::read(&source).expect("read vault after export attempt");
        assert_eq!(
            before, after,
            "vault file must be untouched after rejection"
        );
    }

    #[test]
    fn export_backup_writes_atomically_leaving_no_visible_temp_file() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("vault.sqlite");
        let backup = dir.path().join("vault-backup.ppv.json");
        init_vault(&source, "correct horse battery staple").expect("init");
        let vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");

        vault.export_backup(&backup).expect("export backup");
        assert!(backup.exists());

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| name != "vault.sqlite" && name != "vault-backup.ppv.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp files should remain after a successful export: {leftovers:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn export_backup_interrupted_temp_write_leaves_existing_backup_untouched() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("vault.sqlite");
        let export_dir = dir.path().join("export-dest");
        fs::create_dir_all(&export_dir).expect("mkdir export dest");
        let backup = export_dir.join("vault-backup.ppv.json");
        init_vault(&source, "correct horse battery staple").expect("init");
        let vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");

        fs::write(&backup, b"pre-existing backup contents").expect("seed pre-existing backup");
        let original_contents = fs::read(&backup).expect("read seeded backup");

        let mut perms = fs::metadata(&export_dir)
            .expect("dir metadata")
            .permissions();
        perms.set_mode(0o500);
        fs::set_permissions(&export_dir, perms).expect("lock down export dir");

        let result = vault.export_backup(&backup);

        let mut restore_perms = fs::metadata(&export_dir)
            .expect("dir metadata")
            .permissions();
        restore_perms.set_mode(0o700);
        fs::set_permissions(&export_dir, restore_perms).expect("restore dir permissions");

        assert!(
            result.is_err(),
            "export into an unwritable directory must fail, not silently succeed"
        );
        let after_contents = fs::read(&backup).expect("read backup after failed export");
        assert_eq!(
            original_contents, after_contents,
            "pre-existing backup file must be untouched by an interrupted export"
        );

        let leftovers: Vec<_> = fs::read_dir(&export_dir)
            .expect("read export dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| name != "vault-backup.ppv.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp file should remain in the export directory: {leftovers:?}"
        );
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

    fn tamper_transfer_payload_last_item_title(
        transfer_path: &Path,
        recovery_secret: &str,
    ) -> VaultTransferPackage {
        let mut package = read_transfer_package(transfer_path).expect("read transfer package");
        let access = package
            .access
            .recovery
            .clone()
            .expect("password recovery access");
        let salt_raw = hex_decode(access.salt_hex.as_str()).expect("decode salt");
        let salt_text = String::from_utf8(salt_raw).expect("utf8 salt");
        let salt = SaltString::from_b64(salt_text.as_str()).expect("parse salt");
        let kek = derive_key(recovery_secret, &salt, &access.kdf).expect("derive kek");
        let transfer_key = decrypt_blob(
            kek.as_slice(),
            TRANSFER_KEY_AAD,
            EncryptedBlob {
                nonce: hex_decode(access.nonce_hex.as_str()).expect("decode nonce"),
                tag: hex_decode(access.tag_hex.as_str()).expect("decode tag"),
                ciphertext: hex_decode(access.encrypted_transfer_key_hex.as_str())
                    .expect("decode ciphertext"),
            },
        )
        .expect("unwrap transfer key");
        let payload_plaintext = decrypt_blob(
            transfer_key.as_slice(),
            TRANSFER_PAYLOAD_AAD,
            EncryptedBlob {
                nonce: hex_decode(package.payload_nonce_hex.as_str()).expect("decode nonce"),
                tag: hex_decode(package.payload_tag_hex.as_str()).expect("decode tag"),
                ciphertext: hex_decode(package.payload_ciphertext_hex.as_str())
                    .expect("decode ciphertext"),
            },
        )
        .expect("decrypt payload");
        let mut payload: VaultTransferPayload =
            serde_json::from_slice(payload_plaintext.as_slice()).expect("parse payload");
        let last = payload.items.last_mut().expect("at least one item");
        let VaultItemPayload::Login(login) = &mut last.payload else {
            panic!("last item must be a login for this test");
        };
        login.title = String::new();

        let retampered_plaintext = serde_json::to_vec(&payload).expect("serialize payload");
        let retampered = encrypt_blob(
            transfer_key.as_slice(),
            TRANSFER_PAYLOAD_AAD,
            retampered_plaintext.as_slice(),
        )
        .expect("re-encrypt payload");
        package.payload_nonce_hex = hex_encode(retampered.nonce.as_slice());
        package.payload_tag_hex = hex_encode(retampered.tag.as_slice());
        package.payload_ciphertext_hex = hex_encode(retampered.ciphertext.as_slice());
        fs::write(
            transfer_path,
            serde_json::to_vec_pretty(&package).expect("serialize package"),
        )
        .expect("write tampered transfer");
        package
    }

    #[test]
    fn import_transfer_with_malformed_final_item_leaves_zero_rows_imported() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("source.sqlite");
        let target = dir.path().join("target.sqlite");
        let transfer = dir.path().join("vault-transfer.ppvt.json");
        init_vault(&source, "correct horse battery staple").expect("init source");
        init_vault(&target, "correct horse battery staple").expect("init target");

        let source_vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        source_vault
            .add_login(NewLoginRecord {
                title: "First Login".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add first login");
        source_vault
            .add_login(NewLoginRecord {
                title: "Second Login".to_string(),
                username: "octocat2".to_string(),
                password: "hunter3".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add second login");
        source_vault
            .export_transfer_package(
                &transfer,
                &VaultItemFilter::default(),
                Some("transfer secret"),
                None,
            )
            .expect("export transfer");

        tamper_transfer_payload_last_item_title(&transfer, "transfer secret");

        let target_vault = unlock_vault(&target, "correct horse battery staple").expect("unlock");
        let before = target_vault.list_items().expect("list items before").len();
        let error = target_vault
            .import_transfer_package_with_password(&transfer, "transfer secret", false)
            .expect_err("import fails closed on malformed final item");
        assert!(matches!(error, VaultError::InvalidArguments(_)));

        let after = target_vault.list_items().expect("list items after").len();
        assert_eq!(
            before, after,
            "a malformed final item must leave zero rows imported, not a partial commit"
        );
        assert_eq!(before, 0);
    }

    #[test]
    fn import_transfer_with_all_valid_items_commits_all_rows() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("source.sqlite");
        let target = dir.path().join("target.sqlite");
        let transfer = dir.path().join("vault-transfer.ppvt.json");
        init_vault(&source, "correct horse battery staple").expect("init source");
        init_vault(&target, "correct horse battery staple").expect("init target");

        let source_vault = unlock_vault(&source, "correct horse battery staple").expect("unlock");
        source_vault
            .add_login(NewLoginRecord {
                title: "First Login".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add first login");
        source_vault
            .add_login(NewLoginRecord {
                title: "Second Login".to_string(),
                username: "octocat2".to_string(),
                password: "hunter3".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add second login");
        source_vault
            .export_transfer_package(
                &transfer,
                &VaultItemFilter::default(),
                Some("transfer secret"),
                None,
            )
            .expect("export transfer");

        let target_vault = unlock_vault(&target, "correct horse battery staple").expect("unlock");
        let summary = target_vault
            .import_transfer_package_with_password(&transfer, "transfer secret", false)
            .expect("import succeeds");
        assert_eq!(summary.imported_count, 2);

        let items = target_vault.list_items().expect("list items");
        assert_eq!(items.len(), 2);
        assert!(items.iter().any(|item| item.title == "First Login"));
        assert!(items.iter().any(|item| item.title == "Second Login"));
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
    fn restore_leaves_no_temp_sibling_after_failure() {
        let dir = tempdir().expect("tempdir");
        let backup = dir.path().join("invalid-backup.ppv.json");
        let restored = dir.path().join("restored.sqlite");
        fs::write(
            &backup,
            r#"{"backup_format_version":999,"vault_format_version":1,"header":{"format_version":1,"created_at_epoch":0,"migration_state":"clean","kdf":{"algorithm":"argon2id","memory_cost_kib":65536,"iterations":3,"parallelism":1,"derived_key_len":32},"keyslots":[]},"items":[]}"#,
        )
        .expect("write invalid backup");

        restore_vault_backup(&backup, &restored, false).expect_err("restore fails");
        assert!(!restored.exists());
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| name != "invalid-backup.ppv.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "restore must not leave temp siblings behind: {leftovers:?}"
        );
    }

    #[test]
    fn mid_restore_failure_leaves_original_vault_intact_and_unlockable() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        let backup = dir.path().join("vault-backup.ppv.json");
        init_vault(&path, "correct horse battery staple").expect("init");

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        vault
            .add_login(NewLoginRecord {
                title: "Original Login One".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add login");
        vault
            .add_login(NewLoginRecord {
                title: "Original Login Two".to_string(),
                username: "octocat2".to_string(),
                password: "hunter3".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add login");
        vault.export_backup(&backup).expect("export backup");

        let mut package: VaultBackupPackage =
            serde_json::from_slice(&fs::read(&backup).expect("read backup")).expect("parse backup");
        assert_eq!(package.items.len(), 2, "sanity: two items exported");
        package.items.insert(
            1,
            VaultBackupItem {
                id: "malformed-late-item".to_string(),
                kind: "login".to_string(),
                created_at_epoch: 0,
                updated_at_epoch: 0,
                nonce_hex: "not-valid-hex".to_string(),
                tag_hex: "00".repeat(16),
                ciphertext_hex: "00".repeat(16),
            },
        );
        fs::write(
            &backup,
            serde_json::to_vec(&package).expect("serialize tampered backup"),
        )
        .expect("write tampered backup");

        drop(vault);
        let error = restore_vault_backup(&backup, &path, true).expect_err("restore fails closed");
        assert!(!matches!(error, VaultError::VaultExists(_)));

        assert!(path.exists(), "original vault must still exist");
        let siblings: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| name != "vault.sqlite" && name != "vault-backup.ppv.json")
            .collect();
        assert!(
            siblings.is_empty(),
            "no temp sibling should remain after failed restore: {siblings:?}"
        );

        let reopened = unlock_vault(&path, "correct horse battery staple")
            .expect("original vault still unlockable after failed restore");
        let items = reopened.list_items().expect("list items");
        assert_eq!(
            items.len(),
            2,
            "failed restore must not leave the destination with a partially-imported item set"
        );
        assert!(items.iter().any(|item| item.title == "Original Login One"));
        assert!(items.iter().any(|item| item.title == "Original Login Two"));
    }

    #[test]
    fn successful_restore_replaces_destination_atomically() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        let backup = dir.path().join("vault-backup.ppv.json");
        init_vault(&path, "correct horse battery staple").expect("init");

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        vault
            .add_login(NewLoginRecord {
                title: "Replacement Login".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add login");
        vault.export_backup(&backup).expect("export backup");

        drop(vault);
        fs::write(&path, b"stale vault contents that must be replaced").expect("stomp target");

        restore_vault_backup(&backup, &path, true).expect("restore succeeds");

        let siblings: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| name != "vault.sqlite" && name != "vault-backup.ppv.json")
            .collect();
        assert!(
            siblings.is_empty(),
            "no temp sibling should remain after successful restore: {siblings:?}"
        );

        let restored_vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock restored vault");
        let items = restored_vault.list_items().expect("list items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Replacement Login");
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
    fn certificate_keyslot_rejects_unsupported_wrap_algorithm() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let (certificate_pem, private_key_pem) = test_certificate_pair();
        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let keyslot = vault
            .add_certificate_keyslot(certificate_pem.as_slice(), Some("laptop".to_string()))
            .expect("add certificate keyslot");
        let index = vault
            .header
            .keyslots
            .iter()
            .position(|slot| slot.id == keyslot.id)
            .expect("certificate slot in header");
        vault.header.keyslots[index].wrap_algorithm = PASSWORD_WRAP_ALGORITHM.to_string();
        vault.persist_header().expect("persist tampered header");
        drop(vault);

        let error = unlock_vault_with_certificate(
            &path,
            certificate_pem.as_slice(),
            private_key_pem.as_slice(),
            None,
        )
        .expect_err("unsupported certificate keyslot algorithm should fail closed");
        assert!(matches!(error, VaultError::UnlockFailed));
    }

    #[test]
    fn certificate_keyslot_metadata_tampering_fails_closed() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let (certificate_pem, private_key_pem) = test_certificate_pair();
        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let keyslot = vault
            .add_certificate_keyslot(certificate_pem.as_slice(), Some("laptop".to_string()))
            .expect("add certificate keyslot");
        let index = vault
            .header
            .keyslots
            .iter()
            .position(|slot| slot.id == keyslot.id)
            .expect("certificate slot in header");
        vault.header.keyslots[index].certificate_subject = Some("CN=tampered.example".to_string());
        vault.persist_header().expect("persist tampered header");
        drop(vault);

        let error = unlock_vault_with_certificate(
            &path,
            certificate_pem.as_slice(),
            private_key_pem.as_slice(),
            None,
        )
        .expect_err("tampered certificate metadata should fail closed");
        assert!(matches!(error, VaultError::UnlockFailed));
    }

    #[test]
    fn certificate_keyslot_transport_key_shape_tampering_fails_closed() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let (certificate_pem, private_key_pem) = test_certificate_pair();
        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let keyslot = vault
            .add_certificate_keyslot(certificate_pem.as_slice(), Some("laptop".to_string()))
            .expect("add certificate keyslot");
        let index = vault
            .header
            .keyslots
            .iter()
            .position(|slot| slot.id == keyslot.id)
            .expect("certificate slot in header");
        vault.header.keyslots[index].nonce_hex = hex_encode(&[0_u8; AES_GCM_NONCE_LEN - 1]);
        vault.persist_header().expect("persist tampered header");
        drop(vault);

        let error = unlock_vault_with_certificate(
            &path,
            certificate_pem.as_slice(),
            private_key_pem.as_slice(),
            None,
        )
        .expect_err("tampered certificate transport-key shape should fail closed");
        assert!(matches!(error, VaultError::UnlockFailed));
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
        assert_eq!(enrollment.keyslot.wrap_algorithm, MNEMONIC_WRAP_ALGORITHM);
        assert_eq!(
            enrollment.mnemonic.as_str().split_whitespace().count(),
            usize::from(MNEMONIC_WORD_COUNT)
        );
        let parsed_mnemonic = Mnemonic::parse_in(Language::English, enrollment.mnemonic.as_str())
            .expect("generated mnemonic parses");
        assert_eq!(parsed_mnemonic.to_entropy().len(), MASTER_KEY_LEN);

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
    fn mnemonic_enrollment_debug_never_contains_the_phrase() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let enrollment = vault
            .add_mnemonic_keyslot(Some("paper".to_string()))
            .expect("add mnemonic keyslot");
        let phrase = enrollment.mnemonic.as_str().to_string();

        let enrollment_debug = format!("{enrollment:?}");
        let field_debug = format!("{:?}", enrollment.mnemonic);

        assert!(
            !enrollment_debug.contains(phrase.as_str()),
            "Debug output for MnemonicRecoveryEnrollment must not contain the phrase"
        );
        // Single mnemonic words can legitimately collide with other Debug
        // text (e.g. a keyslot label that is itself a dictionary word), so
        // leak detection checks consecutive word pairs instead.
        let words: Vec<&str> = phrase.split_whitespace().collect();
        for pair in words.windows(2) {
            let bigram = pair.join(" ");
            assert!(
                !enrollment_debug.contains(bigram.as_str()),
                "Debug output leaked mnemonic bigram {bigram:?}"
            );
        }
        assert!(enrollment_debug.contains("redacted"));
        assert!(!field_debug.contains(phrase.as_str()));
        assert!(field_debug.contains("redacted"));
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
    fn mnemonic_keyslot_rejects_invalid_word_count_phrase() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let enrollment = vault
            .add_mnemonic_keyslot(Some("paper".to_string()))
            .expect("add mnemonic keyslot");
        let invalid_phrase = enrollment
            .mnemonic
            .as_str()
            .split_whitespace()
            .take(usize::from(MNEMONIC_WORD_COUNT) - 1)
            .collect::<Vec<_>>()
            .join(" ");

        let error = unlock_vault_with_mnemonic(
            &path,
            invalid_phrase.as_str(),
            Some(enrollment.keyslot.id.as_str()),
        )
        .expect_err("invalid word count should fail");
        assert!(matches!(error, VaultError::UnlockFailed));
    }

    #[test]
    fn mnemonic_keyslot_metadata_tampering_fails_closed() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let enrollment = vault
            .add_mnemonic_keyslot(Some("paper".to_string()))
            .expect("add mnemonic keyslot");
        let index = vault
            .header
            .keyslots
            .iter()
            .position(|slot| slot.id == enrollment.keyslot.id)
            .expect("mnemonic keyslot in header");
        vault.header.keyslots[index].wrap_algorithm = PASSWORD_WRAP_ALGORITHM.to_string();
        vault.header.keyslots[index].mnemonic_language = Some("japanese".to_string());
        vault.header.keyslots[index].mnemonic_words = Some(12);
        vault.persist_header().expect("persist tampered metadata");

        let error = unlock_vault_with_mnemonic(
            &path,
            enrollment.mnemonic.as_str(),
            Some(enrollment.keyslot.id.as_str()),
        )
        .expect_err("tampered metadata should fail");
        assert!(matches!(error, VaultError::UnlockFailed));
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
            .as_str()
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        words[0] = if words[0] == "abandon" {
            "ability".to_string()
        } else {
            "abandon".to_string()
        };
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

        let header = read_vault_header(&path).expect("header");
        let metadata_health = header
            .assess_keyslot_health(keyslot.id.as_str())
            .expect("metadata health");
        assert_eq!(
            metadata_health.provider_availability,
            VaultKeyslotProviderAvailability::NotChecked
        );
        let probed_health = header
            .assess_keyslot_health_with_provider_probe(
                keyslot.id.as_str(),
                VaultKeyslotProviderProbe::VerifyAvailability,
            )
            .expect("probed health");
        assert!(probed_health.healthy);
        assert_eq!(
            probed_health.provider_availability,
            VaultKeyslotProviderAvailability::Available
        );
        assert_eq!(
            probed_health.provider_evidence_source.as_deref(),
            Some("device_provider_health_check")
        );

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
    fn device_keyslot_provider_probe_reports_unavailable_missing_secret() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let keyslot = vault
            .add_device_keyslot(Some("daily-device".to_string()))
            .expect("add device keyslot");
        let service = keyslot.device_service.as_deref().expect("service");
        let account = keyslot.device_account.as_deref().expect("account");
        device_store_delete_secret(service, account).expect("delete device secret");

        let header = read_vault_header(&path).expect("header");
        let health = header
            .assess_keyslot_health_with_provider_probe(
                keyslot.id.as_str(),
                VaultKeyslotProviderProbe::VerifyAvailability,
            )
            .expect("probed health");

        assert!(!health.healthy);
        assert_eq!(
            health.provider_availability,
            VaultKeyslotProviderAvailability::Unavailable
        );
        assert!(
            health.warnings.iter().any(|warning| {
                warning.starts_with("Device-bound provider health check failed:")
            })
        );
    }

    #[test]
    fn device_keyslot_rejects_tampered_secure_storage_secret() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let keyslot = vault
            .add_device_keyslot(Some("daily-device".to_string()))
            .expect("add device keyslot");
        let service = keyslot.device_service.as_deref().expect("service");
        let account = keyslot.device_account.as_deref().expect("account");
        let wrong_master_key = [0xa5; MASTER_KEY_LEN];
        device_store_set_secret(service, account, wrong_master_key.as_slice())
            .expect("overwrite device secret");

        let error = unlock_vault_with_device(&path, Some(keyslot.id.as_str()))
            .expect_err("tampered device secret should fail");
        assert!(matches!(error, VaultError::UnlockFailed));

        let header = read_vault_header(&path).expect("header");
        let health = header
            .assess_keyslot_health_with_provider_probe(
                keyslot.id.as_str(),
                VaultKeyslotProviderProbe::VerifyAvailability,
            )
            .expect("probed health");
        assert!(!health.healthy);
        assert_eq!(
            health.provider_availability,
            VaultKeyslotProviderAvailability::Unavailable
        );
    }

    #[test]
    fn device_keyslot_rejects_wrong_length_secure_storage_secret() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let keyslot = vault
            .add_device_keyslot(Some("daily-device".to_string()))
            .expect("add device keyslot");
        let service = keyslot.device_service.as_deref().expect("service");
        let account = keyslot.device_account.as_deref().expect("account");
        device_store_set_secret(service, account, b"not-a-32-byte-device-secret")
            .expect("overwrite device secret");

        let error = unlock_vault_with_device(&path, Some(keyslot.id.as_str()))
            .expect_err("wrong-length device secret should fail");
        assert!(matches!(error, VaultError::UnlockFailed));

        let header = read_vault_header(&path).expect("header");
        let health = header
            .assess_keyslot_health_with_provider_probe(
                keyslot.id.as_str(),
                VaultKeyslotProviderProbe::VerifyAvailability,
            )
            .expect("probed health");
        assert!(!health.healthy);
        assert_eq!(
            health.provider_availability,
            VaultKeyslotProviderAvailability::Unavailable
        );
    }

    #[test]
    fn device_keyslot_provider_probe_skips_check_when_metadata_is_missing() {
        let keyslot = VaultKeyslot {
            id: "device-missing-metadata".to_string(),
            kind: VaultKeyslotKind::DeviceBound,
            label: Some("daily-device".to_string()),
            wrapped_by_os_keystore: true,
            wrap_algorithm: DEVICE_WRAP_ALGORITHM.to_string(),
            salt_hex: String::new(),
            nonce_hex: "nonce".to_string(),
            tag_hex: "tag".to_string(),
            encrypted_master_key_hex: "ciphertext".to_string(),
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
        };

        let health =
            keyslot_health_for_slot(&keyslot, VaultKeyslotProviderProbe::VerifyAvailability);

        assert!(!health.healthy);
        assert_eq!(
            health.provider_availability,
            VaultKeyslotProviderAvailability::Unavailable
        );
        assert_eq!(
            health.provider_evidence_source.as_deref(),
            Some("device_provider_health_check")
        );
        assert!(
            health
                .warnings
                .iter()
                .any(|warning| { warning == "Device-bound provider service metadata is missing." })
        );
        assert!(
            health
                .warnings
                .iter()
                .any(|warning| { warning == "Device-bound provider account metadata is missing." })
        );
        assert!(
            !health
                .warnings
                .iter()
                .any(|warning| warning.starts_with("Device-bound provider health check failed:"))
        );
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
        let service = slot.device_service.as_deref().expect("service").to_string();
        let account = slot.device_account.as_deref().expect("account").to_string();
        device_store_get_secret(service.as_str(), account.as_str()).expect("device secret");
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
        let error = device_store_get_secret(service.as_str(), account.as_str())
            .expect_err("removed device keyslot should delete device secret");
        assert!(matches!(error, VaultError::UnlockFailed));
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
    fn recovery_recommendations_match_posture_gaps() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let fresh = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let recommendations = fresh.header().recovery_recommendations();
        assert_eq!(recommendations.len(), 3);
        assert!(
            recommendations
                .iter()
                .any(|recommendation| recommendation.contains("mnemonic recovery slot"))
        );
        assert!(
            recommendations
                .iter()
                .any(|recommendation| recommendation.contains("device-bound slot"))
        );
        assert!(
            recommendations
                .iter()
                .any(|recommendation| recommendation.contains("certificate-wrapped slot"))
        );

        let (cert_pem, _) = test_certificate_pair();
        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        vault
            .add_mnemonic_keyslot(Some("paper".to_string()))
            .expect("mnemonic slot");
        vault
            .add_device_keyslot(Some("daily".to_string()))
            .expect("device slot");
        vault
            .add_certificate_keyslot(cert_pem.as_slice(), Some("ops".to_string()))
            .expect("cert slot");

        let complete = vault.header().recovery_recommendations();
        assert!(
            complete.is_empty(),
            "recommendations should be empty when posture is complete, got {complete:?}"
        );
    }

    #[test]
    fn seal_posture_for_path_reports_recovery_required_for_missing_vault() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("missing.vault");

        let (vault_exists, posture) =
            seal_posture_for_path(&path, VaultKeyslotProviderProbe::MetadataOnly);

        assert!(!vault_exists);
        assert_eq!(
            posture.state,
            paranoid_seal::VaultSealState::RecoveryRequired
        );
        assert!(posture.recovery_required);
        assert_eq!(posture.provider_count, 0);
    }

    #[test]
    fn seal_posture_for_path_reports_recovery_required_for_unreadable_vault() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("corrupt.vault");
        fs::write(&path, b"not a sqlite vault").expect("write corrupt vault");

        let (vault_exists, posture) =
            seal_posture_for_path(&path, VaultKeyslotProviderProbe::MetadataOnly);

        assert!(vault_exists);
        assert_eq!(
            posture.state,
            paranoid_seal::VaultSealState::RecoveryRequired
        );
        assert!(posture.recovery_required);
        assert!(!posture.operator_recovery_configured);
        assert_eq!(posture.provider_count, 0);
    }

    #[test]
    fn seal_posture_for_path_reports_header_providers_for_initialized_vault() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        let header = init_vault(&path, "seal posture unit test password").expect("init vault");

        let (vault_exists, posture) =
            seal_posture_for_path(&path, VaultKeyslotProviderProbe::MetadataOnly);

        assert!(vault_exists);
        assert_eq!(posture.state, paranoid_seal::VaultSealState::Sealed);
        assert_eq!(posture.provider_count, header.keyslots.len());
        assert!(posture.operator_recovery_configured);
        assert!(!posture.recovery_required);
        assert!(posture.providers.iter().any(|provider| {
            provider.kind == VaultSealProviderKind::PasswordRecovery
                && provider.status == paranoid_seal::VaultSealProviderStatus::Configured
        }));
        let serialized = serde_json::to_string(&posture).expect("serialize posture");
        assert!(!serialized.contains("seal posture unit test password"));
    }

    #[test]
    fn header_seal_posture_matches_seal_posture_for_path() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init vault");
        let header = read_vault_header(&path).expect("read header");

        let direct = header.seal_posture(VaultKeyslotProviderProbe::MetadataOnly);
        let (_, via_path) = seal_posture_for_path(&path, VaultKeyslotProviderProbe::MetadataOnly);

        assert_eq!(direct.state, via_path.state);
        assert_eq!(direct.provider_count, via_path.provider_count);
    }

    #[test]
    fn seal_provider_evidence_maps_available_device_health() {
        let keyslot = VaultKeyslot {
            id: "device-test".to_string(),
            kind: VaultKeyslotKind::DeviceBound,
            label: Some("daily".to_string()),
            wrapped_by_os_keystore: true,
            wrap_algorithm: "os-keyring+aes-256-gcm-check".to_string(),
            salt_hex: String::new(),
            nonce_hex: "nonce".to_string(),
            tag_hex: "tag".to_string(),
            encrypted_master_key_hex: "ciphertext".to_string(),
            certificate_fingerprint_sha256: None,
            certificate_subject: None,
            certificate_not_before: None,
            certificate_not_after: None,
            certificate_not_before_epoch: None,
            certificate_not_after_epoch: None,
            mnemonic_language: None,
            mnemonic_words: None,
            device_service: Some("service".to_string()),
            device_account: Some("account".to_string()),
        };
        let health = VaultKeyslotHealth {
            keyslot_id: keyslot.id.clone(),
            keyslot_kind: VaultKeyslotKind::DeviceBound,
            warnings: Vec::new(),
            healthy: true,
            provider_availability: VaultKeyslotProviderAvailability::Available,
            provider_evidence_source: Some("device_provider_health_check".to_string()),
        };

        let evidence = seal_provider_evidence_for_health(&keyslot, health);

        assert_eq!(evidence.provider_id, "device-test");
        assert_eq!(evidence.kind, VaultSealProviderKind::DeviceBound);
        assert_eq!(
            evidence.status,
            paranoid_seal::VaultSealProviderStatus::Available
        );
        assert_eq!(evidence.evidence_source, "device_provider_health_check");
    }

    #[test]
    fn seal_provider_evidence_maps_unavailable_device_health() {
        let keyslot = VaultKeyslot {
            id: "device-test-unavailable".to_string(),
            kind: VaultKeyslotKind::DeviceBound,
            label: Some("daily".to_string()),
            wrapped_by_os_keystore: true,
            wrap_algorithm: "os-keyring+aes-256-gcm-check".to_string(),
            salt_hex: String::new(),
            nonce_hex: "nonce".to_string(),
            tag_hex: "tag".to_string(),
            encrypted_master_key_hex: "ciphertext".to_string(),
            certificate_fingerprint_sha256: None,
            certificate_subject: None,
            certificate_not_before: None,
            certificate_not_after: None,
            certificate_not_before_epoch: None,
            certificate_not_after_epoch: None,
            mnemonic_language: None,
            mnemonic_words: None,
            device_service: Some("service".to_string()),
            device_account: Some("account".to_string()),
        };
        let health = VaultKeyslotHealth {
            keyslot_id: keyslot.id.clone(),
            keyslot_kind: VaultKeyslotKind::DeviceBound,
            warnings: Vec::new(),
            healthy: false,
            provider_availability: VaultKeyslotProviderAvailability::Unavailable,
            provider_evidence_source: None,
        };

        let evidence = seal_provider_evidence_for_health(&keyslot, health);

        assert_eq!(evidence.provider_id, "device-test-unavailable");
        assert_eq!(evidence.kind, VaultSealProviderKind::DeviceBound);
        assert_eq!(
            evidence.status,
            paranoid_seal::VaultSealProviderStatus::Unavailable
        );
        assert_eq!(evidence.evidence_source, "vault_header");
        assert_eq!(
            evidence.warnings,
            vec!["Provider availability probe failed.".to_string()]
        );
    }

    #[test]
    fn seal_provider_kind_maps_vault_keyslot_kinds() {
        assert_eq!(
            seal_provider_kind(&VaultKeyslotKind::PasswordRecovery),
            VaultSealProviderKind::PasswordRecovery
        );
        assert_eq!(
            seal_provider_kind(&VaultKeyslotKind::MnemonicRecovery),
            VaultSealProviderKind::MnemonicRecovery
        );
        assert_eq!(
            seal_provider_kind(&VaultKeyslotKind::DeviceBound),
            VaultSealProviderKind::DeviceBound
        );
        assert_eq!(
            seal_provider_kind(&VaultKeyslotKind::CertificateWrapped),
            VaultSealProviderKind::CertificateWrapped
        );
    }

    #[test]
    fn password_history_does_not_grow_when_password_is_unchanged() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let item = vault
            .add_login(NewLoginRecord {
                title: "Example".to_string(),
                username: "jon@example.com".to_string(),
                password: "Sup3r$ecret!".to_string(),
                url: None,
                notes: None,
                folder: Some("Personal".to_string()),
                tags: vec!["personal".to_string()],
            })
            .expect("add");

        vault
            .update_login(
                &item.id,
                UpdateLoginRecord {
                    title: Some("Example Updated".to_string()),
                    password: Some("Sup3r$ecret!".to_string()),
                    ..UpdateLoginRecord::default()
                },
            )
            .expect("update with same password");

        let fetched = vault.get_item(&item.id).expect("show");
        let VaultItemPayload::Login(login) = fetched.payload else {
            panic!("expected login payload");
        };
        assert_eq!(login.title, "Example Updated");
        assert_eq!(login.password, "Sup3r$ecret!");
        assert!(
            login.password_history.is_empty(),
            "history must not grow when password is unchanged, got {} entries",
            login.password_history.len()
        );
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
