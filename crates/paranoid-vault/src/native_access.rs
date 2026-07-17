use crate::{
    UnlockedVault, VaultError, unlock_vault, unlock_vault_with_certificate,
    unlock_vault_with_device, unlock_vault_with_mnemonic,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    env, fmt, fs,
    path::PathBuf,
    time::{Duration, Instant},
};
#[cfg(test)]
use zeroize::Zeroize;
use zeroize::Zeroizing;

#[derive(Clone, Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn clear(&mut self) {
        // `String::clear` only resets the length to zero; the buffer's
        // capacity is left in place with the old secret bytes still resident
        // until the allocation itself is dropped. Swap in a fresh, empty
        // `Zeroizing<String>` so the old one drops (and zeroizes) its full
        // capacity immediately instead of leaving stale plaintext behind.
        self.0 = Zeroizing::new(String::new());
    }

    pub fn push(&mut self, ch: char) {
        // `Zeroizing<String>` only scrubs the buffer it holds at drop time.
        // If `String::push` were called directly and it needed to grow, the
        // standard library reallocates internally and abandons the old heap
        // buffer without zeroizing it, leaking prior secret bytes into
        // freed-but-unscrubbed memory. So growth is handled here explicitly:
        // whenever the push would exceed capacity, a fresh `Zeroizing<String>`
        // is allocated up front, the existing contents are copied into it,
        // and `mem::replace` swaps it in — dropping (and zeroizing) the old
        // buffer intact instead of letting `String` realloc it internally.
        let needs_growth = self.0.len() + ch.len_utf8() > self.0.capacity();
        if needs_growth {
            let new_capacity = (self.0.capacity() * 2).max(self.0.len() + 64);
            let mut replacement = Zeroizing::new(String::with_capacity(new_capacity));
            replacement.push_str(self.0.as_str());
            self.0 = replacement;
        }
        self.0.push(ch);
    }

    pub fn pop(&mut self) -> Option<char> {
        // `String::pop` only shrinks the length; the removed character's
        // bytes remain resident in the (unchanged) backing buffer beyond the
        // new length until the allocation is dropped. Build the
        // content-minus-last-char into a freshly allocated `Zeroizing<String>`
        // sized to fit, then swap it in so the old buffer drops (and
        // zeroizes) its full capacity — including the popped byte(s) — right
        // away. O(n) per keystroke is fine for interactive TUI backspace.
        let mut chars = self.0.chars();
        let removed = chars.next_back();
        if removed.is_some() {
            let remainder = chars.as_str();
            let mut replacement = Zeroizing::new(String::with_capacity(remainder.len()));
            replacement.push_str(remainder);
            self.0 = replacement;
        }
        removed
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        paranoid_core::constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl Eq for SecretString {}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A zeroize-on-drop wrapper for decrypted vault-item payload secrets
/// (login passwords, password-history entries, card numbers, and card
/// security codes).
///
/// This exists separately from [`SecretString`] because payload secrets are
/// stored in `#[derive(Clone, Serialize, Deserialize)]` record structs
/// (`LoginRecord`, `CardRecord`, `PasswordHistoryEntry`, and their
/// `New*`/`Update*` mirrors) that round-trip through `serde_json` as part of
/// the encrypted vault item blob. `SecretString` intentionally has no serde
/// impl (it only ever lives in ephemeral, never-persisted TUI form state), so
/// `SecretBytes` adds a *transparent* `Serialize`/`Deserialize` — it
/// serializes to exactly the JSON a plain `String` would produce, and
/// deserializes from exactly that shape, so the on-disk/wire format of a
/// vault item is byte-for-byte unchanged by this wrapper.
///
/// Every clone is an independent `Zeroizing<String>`: dropping any one of
/// them scrubs that copy's bytes, so `.clone()` no longer forks an
/// un-scrubbed heap copy of the secret the way a plain `String` did.
///
/// Drop is handled entirely by the inner `Zeroizing<String>` (its own `Drop`
/// impl zeroizes the buffer in place before deallocating), so `SecretBytes`
/// needs no `Drop`/`ZeroizeOnDrop` impl of its own — the workspace `zeroize`
/// dependency does not enable the `derive` feature, so this deliberately
/// leans on `Zeroizing`'s built-in guarantee rather than adding a new derive
/// macro dependency.
#[derive(Clone, Default)]
pub struct SecretBytes(Zeroizing<String>);

impl SecretBytes {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_inner(self) -> String {
        // `Zeroizing<T>` exposes no `into_inner` (extracting the value would
        // let the caller drop it without the zeroizing wrapper, defeating
        // the point), so the plaintext is cloned out and `self` is left to
        // drop normally, zeroizing its own buffer immediately afterward.
        // Callers that need to move the plaintext onward (e.g. handing it to
        // another zeroizing wrapper, or a legacy call site not yet migrated)
        // get the raw bytes; this instance's own backing buffer is still
        // scrubbed at the end of the call.
        self.0.to_string()
    }

    /// Zeroizes this instance's buffer in place without dropping it. Exposed
    /// so tests can observe the same in-place scrub that `Drop` performs,
    /// without resorting to memory-unsound pointer-after-free reads (which
    /// this crate's `unsafe_code = "forbid"` lint disallows) to prove it.
    #[cfg(test)]
    fn zeroize_in_place(&mut self) {
        self.0.zeroize();
    }
}

impl From<String> for SecretBytes {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretBytes {
    fn from(value: &str) -> Self {
        Self::new(value.to_string())
    }
}

impl From<SecretBytes> for String {
    fn from(value: SecretBytes) -> Self {
        value.into_inner()
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        paranoid_core::constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl Eq for SecretBytes {}

impl PartialEq<str> for SecretBytes {
    fn eq(&self, other: &str) -> bool {
        paranoid_core::constant_time_eq(self.0.as_bytes(), other.as_bytes())
    }
}

impl PartialEq<&str> for SecretBytes {
    fn eq(&self, other: &&str) -> bool {
        paranoid_core::constant_time_eq(self.0.as_bytes(), other.as_bytes())
    }
}

impl PartialEq<String> for SecretBytes {
    fn eq(&self, other: &String) -> bool {
        paranoid_core::constant_time_eq(self.0.as_bytes(), other.as_bytes())
    }
}

impl PartialEq<SecretBytes> for String {
    fn eq(&self, other: &SecretBytes) -> bool {
        paranoid_core::constant_time_eq(self.as_bytes(), other.0.as_bytes())
    }
}

impl PartialEq<SecretBytes> for str {
    fn eq(&self, other: &SecretBytes) -> bool {
        paranoid_core::constant_time_eq(self.as_bytes(), other.0.as_bytes())
    }
}

impl PartialEq<SecretBytes> for &str {
    fn eq(&self, other: &SecretBytes) -> bool {
        paranoid_core::constant_time_eq(self.as_bytes(), other.0.as_bytes())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for SecretBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Transparent: serializes to exactly the JSON string a plain
        // `String` field would have produced, so the on-disk vault item
        // format is unchanged by switching payload secret fields to this
        // type.
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(SecretBytes::new)
    }
}

const DEFAULT_CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
const DEFAULT_IDLE_LOCK_AFTER: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
struct PendingClipboardClear {
    contents: SecretString,
    clear_at: Instant,
}

#[derive(Clone, Debug)]
pub struct NativeSessionHardening {
    last_activity_at: Instant,
    clipboard_clear_after: Duration,
    idle_lock_after: Duration,
    pending_clipboard: Option<PendingClipboardClear>,
}

impl Default for NativeSessionHardening {
    fn default() -> Self {
        Self {
            last_activity_at: Instant::now(),
            clipboard_clear_after: DEFAULT_CLIPBOARD_CLEAR_AFTER,
            idle_lock_after: DEFAULT_IDLE_LOCK_AFTER,
            pending_clipboard: None,
        }
    }
}

impl NativeSessionHardening {
    pub fn with_timeouts(clipboard_clear_after: Duration, idle_lock_after: Duration) -> Self {
        Self {
            last_activity_at: Instant::now(),
            clipboard_clear_after,
            idle_lock_after,
            pending_clipboard: None,
        }
    }

    pub fn note_activity(&mut self) {
        self.last_activity_at = Instant::now();
    }

    pub fn arm_clipboard_clear(&mut self, contents: String) {
        self.pending_clipboard = Some(PendingClipboardClear {
            contents: SecretString::new(contents),
            clear_at: Instant::now() + self.clipboard_clear_after,
        });
        self.note_activity();
    }

    pub fn take_due_clipboard_contents(&mut self) -> Option<SecretString> {
        let is_due = self
            .pending_clipboard
            .as_ref()
            .is_some_and(|pending| Instant::now() >= pending.clear_at);
        if is_due {
            return self
                .pending_clipboard
                .take()
                .map(|pending| pending.contents);
        }
        None
    }

    pub fn take_pending_clipboard_contents(&mut self) -> Option<SecretString> {
        self.pending_clipboard
            .take()
            .map(|pending| pending.contents)
    }

    pub fn should_auto_lock(&self) -> bool {
        self.last_activity_at.elapsed() >= self.idle_lock_after
    }

    pub fn clipboard_clear_after(&self) -> Duration {
        self.clipboard_clear_after
    }

    pub fn idle_lock_after(&self) -> Duration {
        self.idle_lock_after
    }

    pub fn clear_clipboard_tracking(&mut self) {
        self.pending_clipboard = None;
    }

    #[cfg(test)]
    pub fn expire_clipboard_for_test(&mut self) {
        if let Some(pending) = &mut self.pending_clipboard {
            pending.clear_at = Instant::now() - Duration::from_secs(1);
        }
    }

    #[cfg(test)]
    pub fn expire_activity_for_test(&mut self) {
        self.last_activity_at = Instant::now() - self.idle_lock_after - Duration::from_secs(1);
    }
}

#[derive(Debug, Clone)]
pub struct VaultOpenOptions {
    pub path: PathBuf,
    pub auth: VaultAuth,
    pub mnemonic_phrase_env: Option<String>,
    pub mnemonic_phrase: Option<SecretString>,
    pub mnemonic_slot: Option<String>,
    pub device_slot: Option<String>,
    pub use_device_auto: bool,
}

#[derive(Debug, Clone)]
pub enum VaultAuth {
    PasswordEnv(String),
    Password(SecretString),
    Certificate {
        cert_path: PathBuf,
        key_path: PathBuf,
        key_passphrase_env: Option<String>,
        key_passphrase: Option<SecretString>,
    },
}

impl VaultOpenOptions {
    pub fn password_env(&self) -> &str {
        match &self.auth {
            VaultAuth::PasswordEnv(env_name) => env_name.as_str(),
            VaultAuth::Password(_) | VaultAuth::Certificate { .. } => "PARANOID_MASTER_PASSWORD",
        }
    }

    pub fn unlock_description(&self) -> String {
        if self.mnemonic_phrase.is_some() {
            if let Some(slot_id) = self.mnemonic_slot.as_deref() {
                return format!("mnemonic recovery via native input (slot {slot_id})");
            }
            return "mnemonic recovery via native input".to_string();
        }

        if let Some(env_name) = self.mnemonic_phrase_env.as_deref() {
            if let Some(slot_id) = self.mnemonic_slot.as_deref() {
                return format!("mnemonic recovery via {env_name} (slot {slot_id})");
            }
            return format!("mnemonic recovery via {env_name}");
        }

        if let Some(slot_id) = self.device_slot.as_deref() {
            return format!("device-bound unlock via slot {slot_id}");
        }
        if self.use_device_auto {
            return "device-bound unlock via automatic slot selection".to_string();
        }

        match &self.auth {
            VaultAuth::PasswordEnv(env_name) => {
                format!("recovery secret via {env_name}, with device fallback if available")
            }
            VaultAuth::Password(_) => "recovery secret via native input".to_string(),
            VaultAuth::Certificate {
                cert_path,
                key_path,
                ..
            } => format!(
                "certificate-backed unlock via {} + {}",
                cert_path.display(),
                key_path.display()
            ),
        }
    }
}

pub fn default_vault_path() -> PathBuf {
    if let Ok(xdg) = env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg)
            .join("paranoid-passwd")
            .join("vault.sqlite");
    }
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("paranoid-passwd")
            .join("vault.sqlite");
    }
    if let Ok(profile) = env::var("USERPROFILE") {
        return PathBuf::from(profile)
            .join("AppData")
            .join("Local")
            .join("paranoid-passwd")
            .join("vault.sqlite");
    }
    PathBuf::from("paranoid-passwd.vault.sqlite")
}

pub fn read_master_password(env_name: &str) -> Result<String, VaultError> {
    let value = env::var(env_name).map_err(|_| {
        VaultError::InvalidArguments(format!(
            "set {env_name} in the environment before running vault commands"
        ))
    })?;
    if value.is_empty() {
        return Err(VaultError::InvalidArguments(format!(
            "{env_name} must not be empty"
        )));
    }
    Ok(value)
}

pub fn unlock_vault_for_options(options: &VaultOpenOptions) -> Result<UnlockedVault, VaultError> {
    if let Some(mnemonic) = options.mnemonic_phrase.as_ref() {
        return unlock_vault_with_mnemonic(
            &options.path,
            mnemonic.as_str(),
            options.mnemonic_slot.as_deref(),
        );
    }

    if let Some(env_name) = options.mnemonic_phrase_env.as_deref() {
        let mnemonic = read_master_password(env_name)?;
        return unlock_vault_with_mnemonic(
            &options.path,
            mnemonic.as_str(),
            options.mnemonic_slot.as_deref(),
        );
    }

    if let Some(slot_id) = options.device_slot.as_deref() {
        return unlock_vault_with_device(&options.path, Some(slot_id));
    }
    if options.use_device_auto {
        return unlock_vault_with_device(&options.path, None);
    }

    match &options.auth {
        VaultAuth::PasswordEnv(env_name) => match read_master_password(env_name.as_str()) {
            Ok(master_password) => unlock_vault(&options.path, &master_password),
            Err(password_error) => match unlock_vault_with_device(&options.path, None) {
                Ok(vault) => Ok(vault),
                Err(device_error) => Err(VaultError::InvalidArguments(format!(
                    "{password_error}; device-bound fallback unavailable: {device_error}"
                ))),
            },
        },
        VaultAuth::Password(master_password) => {
            unlock_vault(&options.path, master_password.as_str())
        }
        VaultAuth::Certificate {
            cert_path,
            key_path,
            key_passphrase_env,
            key_passphrase,
        } => {
            let cert_pem = fs::read(cert_path)?;
            let key_pem = fs::read(key_path)?;
            let key_passphrase = match key_passphrase {
                Some(value) => Some(value.as_str().to_string()),
                None => match key_passphrase_env {
                    Some(env_name) => read_optional_env(env_name.as_str())?,
                    None => None,
                },
            };
            unlock_vault_with_certificate(
                &options.path,
                cert_pem.as_slice(),
                key_pem.as_slice(),
                key_passphrase.as_deref(),
            )
        }
    }
}

fn read_optional_env(env_name: &str) -> Result<Option<String>, VaultError> {
    match env::var(env_name) {
        Ok(value) => {
            if value.is_empty() {
                return Err(VaultError::InvalidArguments(format!(
                    "{env_name} must not be empty"
                )));
            }
            Ok(Some(value))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(VaultError::InvalidArguments(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{NativeSessionHardening, SecretBytes, SecretString};

    #[test]
    fn secret_bytes_debug_renders_redacted_not_the_secret() {
        let secret = SecretBytes::new("hunter2".to_string());
        assert_eq!(format!("{secret:?}"), "<redacted>");
    }

    #[test]
    fn secret_bytes_equality_matches_and_differs_correctly() {
        let a = SecretBytes::new("hunter2".to_string());
        let b = SecretBytes::new("hunter2".to_string());
        let c = SecretBytes::new("hunter3".to_string());

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, "hunter2");
        assert_eq!("hunter2", a);
        assert_ne!(a, "hunter3");
        assert_eq!(SecretBytes::default(), SecretBytes::default());
    }

    #[test]
    fn secret_bytes_serde_round_trips_to_the_same_json_a_plain_string_would() {
        let secret = SecretBytes::new("Sup3r$ecret!".to_string());

        let secret_json = serde_json::to_string(&secret).expect("serialize SecretBytes");
        let plain_json =
            serde_json::to_string(&"Sup3r$ecret!".to_string()).expect("serialize String");

        // The whole point of a transparent wrapper: the wire bytes for a
        // SecretBytes field are byte-identical to what a plain String field
        // would have produced, so no vault-format migration is needed.
        assert_eq!(secret_json, plain_json);

        let round_tripped: SecretBytes =
            serde_json::from_str(&secret_json).expect("deserialize SecretBytes");
        assert_eq!(round_tripped, secret);
        assert_eq!(round_tripped.as_str(), "Sup3r$ecret!");
    }

    #[test]
    fn secret_bytes_zeroizes_its_buffer_in_place_on_scrub() {
        let mut secret = SecretBytes::new("hunter2".to_string());
        assert_eq!(secret.as_str(), "hunter2");

        // Exercises the exact in-place scrub that `Drop` performs on the
        // inner `Zeroizing<String>` (delegated to `zeroize::Zeroize`, not a
        // re-allocate-and-abandon), without memory-unsound
        // pointer-after-free reads.
        secret.zeroize_in_place();

        assert!(secret.as_str().is_empty());
        assert!(secret.is_empty());
    }

    #[test]
    fn secret_bytes_clone_is_an_independent_zeroizing_copy() {
        let original = SecretBytes::new("hunter2".to_string());
        let mut cloned = original.clone();

        // Zeroizing the clone must not affect the original: each clone owns
        // its own `Zeroizing<String>` buffer, so a `.clone()` no longer
        // forks an un-scrubbed plain-String copy the way it did before this
        // wrapper existed.
        cloned.zeroize_in_place();

        assert!(cloned.is_empty());
        assert_eq!(original.as_str(), "hunter2");
    }

    #[test]
    fn secret_bytes_into_inner_recovers_the_plaintext() {
        let secret = SecretBytes::new("hunter2".to_string());
        assert_eq!(secret.into_inner(), "hunter2");
    }

    #[test]
    fn secret_string_equality_matches_and_differs_correctly() {
        let a = SecretString::new("hunter2".to_string());
        let b = SecretString::new("hunter2".to_string());
        let c = SecretString::new("hunter3".to_string());
        let short = SecretString::new("hunter".to_string());

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, short);
        assert_eq!(SecretString::default(), SecretString::default());
    }

    #[test]
    fn secret_string_push_stays_correct_across_capacity_growth() {
        let mut secret = SecretString::new(String::with_capacity(1));
        let expected: String = ('a'..='z').chain('A'..='Z').chain('0'..='9').collect();

        for ch in expected.chars() {
            secret.push(ch);
        }

        assert_eq!(secret.as_str(), expected.as_str());
        assert_eq!(secret.as_str().len(), expected.len());

        // Multi-byte characters must survive growth too.
        secret.push('é');
        secret.push('🔒');
        assert!(secret.as_str().ends_with("é🔒"));
    }

    #[test]
    fn secret_string_pop_drains_to_empty_correctly() {
        let mut secret = SecretString::new("ab".to_string());

        assert_eq!(secret.pop(), Some('b'));
        assert_eq!(secret.as_str(), "a");

        assert_eq!(secret.pop(), Some('a'));
        assert_eq!(secret.as_str(), "");
        assert!(secret.is_empty());

        assert_eq!(secret.pop(), None);
        assert_eq!(secret.as_str(), "");
    }

    #[test]
    fn secret_string_pop_removes_whole_multibyte_char() {
        let mut secret = SecretString::new("héllo🔒".to_string());

        assert_eq!(secret.pop(), Some('🔒'));
        assert_eq!(secret.as_str(), "héllo");

        assert_eq!(secret.pop(), Some('o'));
        assert_eq!(secret.as_str(), "héll");

        // Pop through the remaining multi-byte character too.
        assert_eq!(secret.pop(), Some('l'));
        assert_eq!(secret.pop(), Some('l'));
        assert_eq!(secret.pop(), Some('é'));
        assert_eq!(secret.as_str(), "h");
        assert_eq!(secret.pop(), Some('h'));
        assert_eq!(secret.as_str(), "");
    }

    #[test]
    fn secret_string_clear_then_push_reuses_instance_correctly() {
        let mut secret = SecretString::new("hunter2".to_string());
        assert!(!secret.is_empty());

        secret.clear();
        assert!(secret.is_empty());
        assert_eq!(secret.as_str(), "");

        secret.push('n');
        secret.push('e');
        secret.push('w');
        assert_eq!(secret.as_str(), "new");

        // Clearing again and reusing must still behave correctly.
        secret.clear();
        assert!(secret.is_empty());
        secret.push('🔒');
        assert_eq!(secret.as_str(), "🔒");
    }

    #[test]
    fn clipboard_entry_becomes_due_after_expiration() {
        let mut session = NativeSessionHardening::default();
        session.arm_clipboard_clear("hunter2".to_string());

        assert!(session.take_due_clipboard_contents().is_none());

        session.expire_clipboard_for_test();
        let due = session
            .take_due_clipboard_contents()
            .expect("clipboard contents should be due");
        assert_eq!(due.as_str(), "hunter2");
        assert!(session.take_due_clipboard_contents().is_none());
    }

    #[test]
    fn idle_lock_triggers_after_expiration() {
        let mut session = NativeSessionHardening::default();
        assert!(!session.should_auto_lock());

        session.expire_activity_for_test();
        assert!(session.should_auto_lock());
    }
}
