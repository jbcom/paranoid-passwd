use crate::vault_tui::{
    clear_clipboard_if_matches, default_backup_export_path, default_transfer_export_path,
    edit_form_value, footer, normalize_optional_field, normalize_optional_secret, selected_keyslot,
};
use anyhow::Context;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use paranoid_audit::{
    AuditEvent, AuditSinkHealth, AuditSurface, assess_optional_jsonl_file_audit_sink,
    write_events_jsonl,
};
use paranoid_core::ParanoidRequest;
use paranoid_ops::{
    CapabilityReport, FederalCryptoProviderEvidence, OpsCommand, OpsPolicyContext, OpsProfile,
    VaultOperationAccess, evaluate_ops_command, evaluate_vault_operation,
};
use paranoid_vault::MnemonicRecoveryEnrollment;
use paranoid_vault::{
    NativeSessionHardening, SecretString, UnlockedVault, VaultAuth, VaultBackupSummary,
    VaultHeader, VaultItem, VaultItemFilter, VaultItemKind, VaultItemPayload, VaultItemSummary,
    VaultOpenOptions, init_vault_unlocked, inspect_certificate_pem, read_vault_header,
    seal_posture_for_path, unlock_vault_for_options,
};
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Screen {
    /// S1 (ia.md §2/§3) — the trust gate. First screen on a fresh run: name
    /// the one job ("decide whether this copy can be trusted") before a
    /// single secret is requested (brand.md §2.1, journeys.md J1).
    TrustGate,
    /// S2 — the non-blocking self-check runs (ia.md §3; brand.md §5.5
    /// "nothing blocks"). `⎋` stays live per ia.md §0 rule 5.
    Verifying,
    /// S3 — the self-check finished (there is no S3f in this build: with no
    /// signed-release backend yet, the check cannot fail closed on a
    /// tampered binary, so it never claims a false pass; see `TrustState`).
    Verified,
    EnvironmentApproval,
    Vault,
    /// S7 (ia.md §5) — one selected item, masked by default. Reached from
    /// `Vault` (H, the vault list) via `⏎`; the only door to secret reveal.
    /// This is a distinct screen, not an always-visible pane on H, so a
    /// shoulder-surfer glancing at the list screen never sees a raw secret
    /// and the `⏎ open` the H footer promises actually navigates somewhere
    /// (P8.V.2).
    ItemDetail,
    Keyslots,
    UnlockBlocked,
    AddLogin,
    EditLogin,
    AddNote,
    EditNote,
    AddCard,
    EditCard,
    AddIdentity,
    EditIdentity,
    AddMnemonicSlot,
    AddDeviceSlot,
    AddCertSlot,
    RewrapCertSlot,
    EditKeyslotLabel,
    RotateMnemonicSlot,
    RotateRecoverySecret,
    MnemonicReveal,
    GenerateStore,
    ExportBackup,
    ExportTransfer,
    ImportBackup,
    ImportTransfer,
    /// Severe-tier confirm (ia.md §7): typed item name required.
    DeleteConfirm,
    /// Severe-tier confirm (ia.md §7): typed way-in label required — removing
    /// a way in can lock the owner out, so it is tiered the same as deleting
    /// an item, never a bare y/N.
    RemoveWayInConfirm,
}

impl Screen {
    /// `true` for every screen reachable only after a successful vault
    /// unlock. `TrustGate`/`Verifying`/`Verified`/`EnvironmentApproval` and
    /// `UnlockBlocked` are pre-unlock screens and must never be idle
    /// auto-locked: `EnvironmentApproval` would otherwise let an idle
    /// timeout silently accept vault initialization without the user ever
    /// confirming the suggested configuration, and `UnlockBlocked` has no
    /// unlocked state left to clear.
    pub(crate) fn is_unlocked_vault_screen(self) -> bool {
        !matches!(
            self,
            Self::TrustGate
                | Self::Verifying
                | Self::Verified
                | Self::EnvironmentApproval
                | Self::UnlockBlocked
        )
    }
}

/// The result of the first-run self-check (S1->S2->S3, ia.md §3). With no
/// signed-release verification backend yet (no attestation/signature crate
/// anywhere in this workspace), this cannot claim `✓ verified` or `✗ failed`
/// against a real cryptographic check — doing so would violate brand.md §3
/// rule 4 ("never overpromise"; the product reports accurately or not at
/// all). It instead honestly reports what *can* be confirmed today: the
/// binary's own build identity. `S3f` (ia.md §2 "not verified, HALT") is
/// reachable once real signature verification exists (tracked as follow-on
/// scope, not fabricated here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum TrustState {
    #[default]
    Unchecked,
    Checked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultFilterField {
    Query,
    Kind,
    Folder,
    Tag,
}

impl VaultFilterField {
    pub(crate) const ALL: [Self; 4] = [Self::Query, Self::Kind, Self::Folder, Self::Tag];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Kind => "kind",
            Self::Folder => "folder",
            Self::Tag => "tag",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VaultFilterState {
    pub(crate) query: String,
    pub(crate) kind: Option<VaultItemKind>,
    pub(crate) folder: String,
    pub(crate) tag: String,
    pub(crate) field: VaultFilterField,
}

impl Default for VaultFilterState {
    fn default() -> Self {
        Self {
            query: String::new(),
            kind: None,
            folder: String::new(),
            tag: String::new(),
            field: VaultFilterField::Query,
        }
    }
}

impl VaultFilterState {
    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.field {
            VaultFilterField::Query => Some(&mut self.query),
            VaultFilterField::Kind => None,
            VaultFilterField::Folder => Some(&mut self.folder),
            VaultFilterField::Tag => Some(&mut self.tag),
        }
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = VaultFilterField::ALL.len();
        let current = VaultFilterField::ALL
            .iter()
            .position(|field| *field == self.field)
            .unwrap_or(0);
        let next = (current as isize + delta).rem_euclid(len as isize) as usize;
        self.field = VaultFilterField::ALL[next];
    }

    pub(crate) fn cycle_kind(&mut self, delta: isize) {
        let all = [
            None,
            Some(VaultItemKind::Login),
            Some(VaultItemKind::SecureNote),
            Some(VaultItemKind::Card),
            Some(VaultItemKind::Identity),
        ];
        let current = all.iter().position(|kind| *kind == self.kind).unwrap_or(0);
        let next = (current as isize + delta).rem_euclid(all.len() as isize) as usize;
        self.kind = all[next].clone();
    }

    pub(crate) fn clear_selected_field(&mut self) {
        match self.field {
            VaultFilterField::Query => self.query.clear(),
            VaultFilterField::Kind => self.kind = None,
            VaultFilterField::Folder => self.folder.clear(),
            VaultFilterField::Tag => self.tag.clear(),
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        !self.query.trim().is_empty()
            || self.kind.is_some()
            || !self.folder.trim().is_empty()
            || !self.tag.trim().is_empty()
    }

    pub(crate) fn kind_label(&self) -> &'static str {
        self.kind
            .as_ref()
            .map(VaultItemKind::as_str)
            .unwrap_or("all")
    }

    pub(crate) fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.query.trim().is_empty() {
            parts.push(format!("query={}", self.query.trim()));
        }
        if let Some(kind) = &self.kind {
            parts.push(format!("kind={}", kind.as_str()));
        }
        if !self.folder.trim().is_empty() {
            parts.push(format!("folder={}", self.folder.trim()));
        }
        if !self.tag.trim().is_empty() {
            parts.push(format!("tag={}", self.tag.trim()));
        }
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join(", ")
        }
    }

    pub(crate) fn selected_field_summary(&self) -> String {
        match self.field {
            VaultFilterField::Query => self.query.clone(),
            VaultFilterField::Kind => self.kind_label().to_string(),
            VaultFilterField::Folder => self.folder.clone(),
            VaultFilterField::Tag => self.tag.clone(),
        }
    }

    pub(crate) fn as_filter(&self) -> VaultItemFilter {
        VaultItemFilter {
            query: normalize_optional_field(&self.query),
            kind: self.kind.clone(),
            folder: normalize_optional_field(&self.folder),
            tag: normalize_optional_field(&self.tag),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddLoginField {
    Title,
    Username,
    Password,
    Url,
    Notes,
    Folder,
    Tags,
    Save,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoteField {
    Title,
    Content,
    Folder,
    Tags,
    Save,
}

impl NoteField {
    pub(crate) const ALL: [Self; 5] = [
        Self::Title,
        Self::Content,
        Self::Folder,
        Self::Tags,
        Self::Save,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardField {
    Title,
    Cardholder,
    Number,
    ExpiryMonth,
    ExpiryYear,
    SecurityCode,
    BillingZip,
    Notes,
    Folder,
    Tags,
    Save,
}

impl CardField {
    pub(crate) const ALL: [Self; 11] = [
        Self::Title,
        Self::Cardholder,
        Self::Number,
        Self::ExpiryMonth,
        Self::ExpiryYear,
        Self::SecurityCode,
        Self::BillingZip,
        Self::Notes,
        Self::Folder,
        Self::Tags,
        Self::Save,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityField {
    Title,
    FullName,
    Email,
    Phone,
    Address,
    Notes,
    Folder,
    Tags,
    Save,
}

impl IdentityField {
    pub(crate) const ALL: [Self; 9] = [
        Self::Title,
        Self::FullName,
        Self::Email,
        Self::Phone,
        Self::Address,
        Self::Notes,
        Self::Folder,
        Self::Tags,
        Self::Save,
    ];
}

impl AddLoginField {
    pub(crate) const ALL: [Self; 8] = [
        Self::Title,
        Self::Username,
        Self::Password,
        Self::Url,
        Self::Notes,
        Self::Folder,
        Self::Tags,
        Self::Save,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenerateField {
    Title,
    Username,
    Url,
    Notes,
    Folder,
    Tags,
    Length,
    Frameworks,
    MinLower,
    MinUpper,
    MinDigits,
    MinSymbols,
    Save,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LabelOnlyField {
    Label,
    Save,
}

impl LabelOnlyField {
    pub(crate) const ALL: [Self; 2] = [Self::Label, Self::Save];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertificateField {
    Label,
    CertPath,
    Save,
}

impl CertificateField {
    pub(crate) const ALL: [Self; 3] = [Self::Label, Self::CertPath, Self::Save];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertificateRewrapField {
    CertPath,
    KeyPath,
    KeyPassphrase,
    Save,
}

impl CertificateRewrapField {
    pub(crate) const ALL: [Self; 4] = [
        Self::CertPath,
        Self::KeyPath,
        Self::KeyPassphrase,
        Self::Save,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoverySecretField {
    NewSecret,
    Confirm,
    Save,
}

impl RecoverySecretField {
    pub(crate) const ALL: [Self; 3] = [Self::NewSecret, Self::Confirm, Self::Save];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnlockMode {
    Password,
    Mnemonic,
    Device,
    Certificate,
}

impl UnlockMode {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Password => "Recovery Secret",
            Self::Mnemonic => "Mnemonic",
            Self::Device => "Device Slot",
            Self::Certificate => "Certificate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnlockField {
    Mode,
    Primary,
    Secondary,
    Tertiary,
    Submit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvironmentApprovalChoice {
    Accept,
    Adjust,
}

impl EnvironmentApprovalChoice {
    pub(crate) const ALL: [Self; 2] = [Self::Accept, Self::Adjust];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Accept => "Accept suggested configuration",
            Self::Adjust => "Adjust manually",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportBackupField {
    Path,
    Save,
}

impl ExportBackupField {
    pub(crate) const ALL: [Self; 2] = [Self::Path, Self::Save];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportBackupField {
    Path,
    Overwrite,
    Save,
}

impl ImportBackupField {
    pub(crate) const ALL: [Self; 3] = [Self::Path, Self::Overwrite, Self::Save];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportTransferField {
    Path,
    PackagePassword,
    CertPath,
    Save,
}

impl ExportTransferField {
    pub(crate) const ALL: [Self; 4] = [
        Self::Path,
        Self::PackagePassword,
        Self::CertPath,
        Self::Save,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportTransferField {
    Path,
    ReplaceExisting,
    PackagePassword,
    CertPath,
    KeyPath,
    KeyPassphrase,
    Save,
}

impl ImportTransferField {
    pub(crate) const ALL: [Self; 7] = [
        Self::Path,
        Self::ReplaceExisting,
        Self::PackagePassword,
        Self::CertPath,
        Self::KeyPath,
        Self::KeyPassphrase,
        Self::Save,
    ];
}

impl GenerateField {
    pub(crate) const ALL: [Self; 13] = [
        Self::Title,
        Self::Username,
        Self::Url,
        Self::Notes,
        Self::Folder,
        Self::Tags,
        Self::Length,
        Self::Frameworks,
        Self::MinLower,
        Self::MinUpper,
        Self::MinDigits,
        Self::MinSymbols,
        Self::Save,
    ];
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AddLoginForm {
    pub(crate) focus_index: usize,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) url: String,
    pub(crate) notes: String,
    pub(crate) folder: String,
    pub(crate) tags: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct NoteForm {
    pub(crate) focus_index: usize,
    pub(crate) title: String,
    pub(crate) content: String,
    pub(crate) folder: String,
    pub(crate) tags: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CardForm {
    pub(crate) focus_index: usize,
    pub(crate) title: String,
    pub(crate) cardholder_name: String,
    pub(crate) number: String,
    pub(crate) expiry_month: String,
    pub(crate) expiry_year: String,
    pub(crate) security_code: String,
    pub(crate) billing_zip: String,
    pub(crate) notes: String,
    pub(crate) folder: String,
    pub(crate) tags: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct IdentityForm {
    pub(crate) focus_index: usize,
    pub(crate) title: String,
    pub(crate) full_name: String,
    pub(crate) email: String,
    pub(crate) phone: String,
    pub(crate) address: String,
    pub(crate) notes: String,
    pub(crate) folder: String,
    pub(crate) tags: String,
}

impl NoteForm {
    pub(crate) fn selected_field(&self) -> NoteField {
        NoteField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(NoteField::Title)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = NoteField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            NoteField::Title => Some(&mut self.title),
            NoteField::Content => Some(&mut self.content),
            NoteField::Folder => Some(&mut self.folder),
            NoteField::Tags => Some(&mut self.tags),
            NoteField::Save => None,
        }
    }
}

impl CardForm {
    pub(crate) fn selected_field(&self) -> CardField {
        CardField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(CardField::Title)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = CardField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            CardField::Title => Some(&mut self.title),
            CardField::Cardholder => Some(&mut self.cardholder_name),
            CardField::Number => Some(&mut self.number),
            CardField::ExpiryMonth => Some(&mut self.expiry_month),
            CardField::ExpiryYear => Some(&mut self.expiry_year),
            CardField::SecurityCode => Some(&mut self.security_code),
            CardField::BillingZip => Some(&mut self.billing_zip),
            CardField::Notes => Some(&mut self.notes),
            CardField::Folder => Some(&mut self.folder),
            CardField::Tags => Some(&mut self.tags),
            CardField::Save => None,
        }
    }
}

impl IdentityForm {
    pub(crate) fn selected_field(&self) -> IdentityField {
        IdentityField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(IdentityField::Title)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = IdentityField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            IdentityField::Title => Some(&mut self.title),
            IdentityField::FullName => Some(&mut self.full_name),
            IdentityField::Email => Some(&mut self.email),
            IdentityField::Phone => Some(&mut self.phone),
            IdentityField::Address => Some(&mut self.address),
            IdentityField::Notes => Some(&mut self.notes),
            IdentityField::Folder => Some(&mut self.folder),
            IdentityField::Tags => Some(&mut self.tags),
            IdentityField::Save => None,
        }
    }
}

impl AddLoginForm {
    pub(crate) fn selected_field(&self) -> AddLoginField {
        AddLoginField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(AddLoginField::Title)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = AddLoginField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            AddLoginField::Title => Some(&mut self.title),
            AddLoginField::Username => Some(&mut self.username),
            AddLoginField::Password => Some(&mut self.password),
            AddLoginField::Url => Some(&mut self.url),
            AddLoginField::Notes => Some(&mut self.notes),
            AddLoginField::Folder => Some(&mut self.folder),
            AddLoginField::Tags => Some(&mut self.tags),
            AddLoginField::Save => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GenerateStoreForm {
    pub(crate) target_login_id: Option<String>,
    pub(crate) focus_index: usize,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) url: String,
    pub(crate) notes: String,
    pub(crate) folder: String,
    pub(crate) tags: String,
    pub(crate) length: String,
    pub(crate) frameworks: String,
    pub(crate) min_lower: String,
    pub(crate) min_upper: String,
    pub(crate) min_digits: String,
    pub(crate) min_symbols: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct LabelOnlyForm {
    pub(crate) focus_index: usize,
    pub(crate) label: String,
}

impl LabelOnlyForm {
    pub(crate) fn selected_field(&self) -> LabelOnlyField {
        LabelOnlyField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(LabelOnlyField::Label)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = LabelOnlyField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            LabelOnlyField::Label => Some(&mut self.label),
            LabelOnlyField::Save => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CertificateRewrapForm {
    pub(crate) focus_index: usize,
    pub(crate) cert_path: String,
    pub(crate) key_path: String,
    pub(crate) key_passphrase: SecretString,
}

impl CertificateRewrapForm {
    pub(crate) fn selected_field(&self) -> CertificateRewrapField {
        CertificateRewrapField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(CertificateRewrapField::CertPath)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = CertificateRewrapField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            CertificateRewrapField::CertPath => Some(&mut self.cert_path),
            CertificateRewrapField::KeyPath => Some(&mut self.key_path),
            CertificateRewrapField::KeyPassphrase | CertificateRewrapField::Save => None,
        }
    }

    pub(crate) fn selected_secret_mut(&mut self) -> Option<&mut SecretString> {
        match self.selected_field() {
            CertificateRewrapField::KeyPassphrase => Some(&mut self.key_passphrase),
            CertificateRewrapField::CertPath
            | CertificateRewrapField::KeyPath
            | CertificateRewrapField::Save => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CertificateSlotForm {
    pub(crate) focus_index: usize,
    pub(crate) label: String,
    pub(crate) cert_path: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RecoverySecretForm {
    pub(crate) focus_index: usize,
    pub(crate) new_secret: SecretString,
    pub(crate) confirm_secret: SecretString,
}

#[derive(Debug, Clone)]
pub(crate) struct UnlockForm {
    pub(crate) focus_index: usize,
    pub(crate) mode: UnlockMode,
    pub(crate) password: SecretString,
    pub(crate) mnemonic_phrase: SecretString,
    pub(crate) mnemonic_slot: String,
    pub(crate) device_slot: String,
    pub(crate) cert_path: String,
    pub(crate) key_path: String,
    pub(crate) key_passphrase: SecretString,
}

#[derive(Debug, Clone)]
pub(crate) struct EnvironmentApprovalState {
    pub(crate) choice: EnvironmentApprovalChoice,
    /// `true` once the user has accepted (or manually adjusted past) this
    /// screen for the current app instance, so a subsequent init failure
    /// that bounces back to `UnlockBlocked` does not re-show it.
    pub(crate) resolved: bool,
}

impl Default for EnvironmentApprovalState {
    fn default() -> Self {
        Self {
            choice: EnvironmentApprovalChoice::Accept,
            resolved: false,
        }
    }
}

impl EnvironmentApprovalState {
    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = EnvironmentApprovalChoice::ALL.len() as isize;
        let current = EnvironmentApprovalChoice::ALL
            .iter()
            .position(|choice| *choice == self.choice)
            .unwrap_or(0) as isize;
        let next = (current + delta).rem_euclid(len) as usize;
        self.choice = EnvironmentApprovalChoice::ALL[next];
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ExportBackupForm {
    pub(crate) focus_index: usize,
    pub(crate) path: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ImportBackupForm {
    pub(crate) focus_index: usize,
    pub(crate) path: String,
    pub(crate) overwrite: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ExportTransferForm {
    pub(crate) focus_index: usize,
    pub(crate) path: String,
    pub(crate) package_password: SecretString,
    pub(crate) cert_path: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ImportTransferForm {
    pub(crate) focus_index: usize,
    pub(crate) path: String,
    pub(crate) replace_existing: bool,
    pub(crate) package_password: SecretString,
    pub(crate) cert_path: String,
    pub(crate) key_path: String,
    pub(crate) key_passphrase: SecretString,
}

impl Default for UnlockForm {
    fn default() -> Self {
        Self {
            focus_index: 0,
            mode: UnlockMode::Password,
            password: SecretString::default(),
            mnemonic_phrase: SecretString::default(),
            mnemonic_slot: String::new(),
            device_slot: String::new(),
            cert_path: String::new(),
            key_path: String::new(),
            key_passphrase: SecretString::default(),
        }
    }
}

impl ExportBackupForm {
    pub(crate) fn selected_field(&self) -> ExportBackupField {
        ExportBackupField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(ExportBackupField::Path)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = ExportBackupField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            ExportBackupField::Path => Some(&mut self.path),
            ExportBackupField::Save => None,
        }
    }
}

impl ImportBackupForm {
    pub(crate) fn selected_field(&self) -> ImportBackupField {
        ImportBackupField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(ImportBackupField::Path)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = ImportBackupField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            ImportBackupField::Path => Some(&mut self.path),
            ImportBackupField::Overwrite | ImportBackupField::Save => None,
        }
    }
}

impl ExportTransferForm {
    pub(crate) fn selected_field(&self) -> ExportTransferField {
        ExportTransferField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(ExportTransferField::Path)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = ExportTransferField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            ExportTransferField::Path => Some(&mut self.path),
            ExportTransferField::CertPath => Some(&mut self.cert_path),
            ExportTransferField::PackagePassword | ExportTransferField::Save => None,
        }
    }

    pub(crate) fn selected_secret_mut(&mut self) -> Option<&mut SecretString> {
        match self.selected_field() {
            ExportTransferField::PackagePassword => Some(&mut self.package_password),
            ExportTransferField::Path
            | ExportTransferField::CertPath
            | ExportTransferField::Save => None,
        }
    }
}

impl ImportTransferForm {
    pub(crate) fn selected_field(&self) -> ImportTransferField {
        ImportTransferField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(ImportTransferField::Path)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = ImportTransferField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            ImportTransferField::Path => Some(&mut self.path),
            ImportTransferField::CertPath => Some(&mut self.cert_path),
            ImportTransferField::KeyPath => Some(&mut self.key_path),
            ImportTransferField::PackagePassword
            | ImportTransferField::KeyPassphrase
            | ImportTransferField::ReplaceExisting
            | ImportTransferField::Save => None,
        }
    }

    pub(crate) fn selected_secret_mut(&mut self) -> Option<&mut SecretString> {
        match self.selected_field() {
            ImportTransferField::PackagePassword => Some(&mut self.package_password),
            ImportTransferField::KeyPassphrase => Some(&mut self.key_passphrase),
            ImportTransferField::Path
            | ImportTransferField::CertPath
            | ImportTransferField::KeyPath
            | ImportTransferField::ReplaceExisting
            | ImportTransferField::Save => None,
        }
    }
}

impl CertificateSlotForm {
    pub(crate) fn selected_field(&self) -> CertificateField {
        CertificateField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(CertificateField::Label)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = CertificateField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            CertificateField::Label => Some(&mut self.label),
            CertificateField::CertPath => Some(&mut self.cert_path),
            CertificateField::Save => None,
        }
    }
}

impl RecoverySecretForm {
    pub(crate) fn selected_field(&self) -> RecoverySecretField {
        RecoverySecretField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(RecoverySecretField::NewSecret)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = RecoverySecretField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_secret_mut(&mut self) -> Option<&mut SecretString> {
        match self.selected_field() {
            RecoverySecretField::NewSecret => Some(&mut self.new_secret),
            RecoverySecretField::Confirm => Some(&mut self.confirm_secret),
            RecoverySecretField::Save => None,
        }
    }
}

impl UnlockForm {
    pub(crate) fn visible_fields(&self) -> &'static [UnlockField] {
        match self.mode {
            UnlockMode::Password => &[UnlockField::Mode, UnlockField::Primary, UnlockField::Submit],
            UnlockMode::Mnemonic => &[
                UnlockField::Mode,
                UnlockField::Primary,
                UnlockField::Secondary,
                UnlockField::Submit,
            ],
            UnlockMode::Device => &[UnlockField::Mode, UnlockField::Primary, UnlockField::Submit],
            UnlockMode::Certificate => &[
                UnlockField::Mode,
                UnlockField::Primary,
                UnlockField::Secondary,
                UnlockField::Tertiary,
                UnlockField::Submit,
            ],
        }
    }

    pub(crate) fn selected_field(&self) -> UnlockField {
        self.visible_fields()
            .get(self.focus_index)
            .copied()
            .unwrap_or(UnlockField::Mode)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = self.visible_fields().len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn cycle_mode(&mut self, delta: isize) {
        let modes = [
            UnlockMode::Password,
            UnlockMode::Mnemonic,
            UnlockMode::Device,
            UnlockMode::Certificate,
        ];
        let current = modes
            .iter()
            .position(|candidate| candidate == &self.mode)
            .unwrap_or(0) as isize;
        let next = (current + delta).rem_euclid(modes.len() as isize) as usize;
        self.mode = modes[next];
        self.focus_index = self
            .focus_index
            .min(self.visible_fields().len().saturating_sub(1));
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match (self.mode, self.selected_field()) {
            (UnlockMode::Mnemonic, UnlockField::Secondary) => Some(&mut self.mnemonic_slot),
            (UnlockMode::Device, UnlockField::Primary) => Some(&mut self.device_slot),
            (UnlockMode::Certificate, UnlockField::Primary) => Some(&mut self.cert_path),
            (UnlockMode::Certificate, UnlockField::Secondary) => Some(&mut self.key_path),
            _ => None,
        }
    }

    pub(crate) fn selected_secret_mut(&mut self) -> Option<&mut SecretString> {
        match (self.mode, self.selected_field()) {
            (UnlockMode::Password, UnlockField::Primary) => Some(&mut self.password),
            (UnlockMode::Mnemonic, UnlockField::Primary) => Some(&mut self.mnemonic_phrase),
            (UnlockMode::Certificate, UnlockField::Tertiary) => Some(&mut self.key_passphrase),
            _ => None,
        }
    }
}

impl Default for GenerateStoreForm {
    fn default() -> Self {
        Self {
            target_login_id: None,
            focus_index: 0,
            title: String::new(),
            username: String::new(),
            url: String::new(),
            notes: String::new(),
            folder: String::new(),
            tags: String::new(),
            length: ParanoidRequest::default().length.to_string(),
            frameworks: String::new(),
            min_lower: "0".to_string(),
            min_upper: "0".to_string(),
            min_digits: "0".to_string(),
            min_symbols: "0".to_string(),
        }
    }
}

impl GenerateStoreForm {
    pub(crate) fn selected_field(&self) -> GenerateField {
        GenerateField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(GenerateField::Title)
    }

    pub(crate) fn adjust_focus(&mut self, delta: isize) {
        let len = GenerateField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(crate) fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            GenerateField::Title => Some(&mut self.title),
            GenerateField::Username => Some(&mut self.username),
            GenerateField::Url => Some(&mut self.url),
            GenerateField::Notes => Some(&mut self.notes),
            GenerateField::Folder => Some(&mut self.folder),
            GenerateField::Tags => Some(&mut self.tags),
            GenerateField::Length => Some(&mut self.length),
            GenerateField::Frameworks => Some(&mut self.frameworks),
            GenerateField::MinLower => Some(&mut self.min_lower),
            GenerateField::MinUpper => Some(&mut self.min_upper),
            GenerateField::MinDigits => Some(&mut self.min_digits),
            GenerateField::MinSymbols => Some(&mut self.min_symbols),
            GenerateField::Save => None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum BackupSummaryPreview {
    Available(VaultBackupSummary),
    Unavailable(String),
}

impl BackupSummaryPreview {
    pub(crate) fn as_result(&self) -> Result<&VaultBackupSummary, &str> {
        match self {
            Self::Available(summary) => Ok(summary),
            Self::Unavailable(error) => Err(error.as_str()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VaultTuiConfig {
    pub open_options: VaultOpenOptions,
    pub profile: OpsProfile,
    pub audit_jsonl: Option<PathBuf>,
    pub require_audit_sink: bool,
}

impl VaultTuiConfig {
    #[cfg(test)]
    pub fn new(open_options: VaultOpenOptions) -> Self {
        Self {
            open_options,
            profile: OpsProfile::Default,
            audit_jsonl: None,
            require_audit_sink: false,
        }
    }

    pub(crate) fn audit_sink_health(&self) -> AuditSinkHealth {
        assess_optional_jsonl_file_audit_sink(self.audit_jsonl.as_deref())
    }
}

#[derive(Debug)]
pub(crate) struct App {
    pub(crate) options: VaultOpenOptions,
    pub(crate) profile: OpsProfile,
    pub(crate) audit_jsonl: Option<PathBuf>,
    pub(crate) require_audit_sink: bool,
    pub(crate) audit_sink_health: AuditSinkHealth,
    pub(crate) ops_audit_events: Vec<AuditEvent>,
    pub(crate) screen: Screen,
    /// The screen the S12 `?` overlay was opened from (ia.md §5 S12). The
    /// overlay is a transient render-time layer, not a `Screen` variant
    /// itself (ia.md §5: "it does not become a new screen, so the skeleton
    /// geometry is preserved beneath it"), so it is tracked here alongside
    /// `screen` rather than replacing it.
    pub(crate) help_overlay_open: bool,
    /// S1/S2/S3 first-run trust-gate result (ia.md §3). `None` means the
    /// spine has not run this session yet; distinguishing from
    /// `TrustState::Unchecked` lets `TrustGate`'s copy tell "verified on
    /// this machine" (ia.md §3 short-circuit) from "not yet checked".
    pub(crate) trust_state: TrustState,
    /// `true` on `Screen::UnlockBlocked` immediately after a lock event
    /// (panic-lock or idle auto-lock), distinguishing ia.md §5 S14 ("in a
    /// locked state the only valid acts are unlock or quit" — minimal
    /// footer `⏎ unlock  q quit`, no `?`) from S15 (the ordinary unlock
    /// entry, whose footer offers `? other ways in`). Cleared the moment
    /// the persona interacts with the unlock form, so a second failed
    /// attempt reverts to the normal S15 footer with recovery paths
    /// reachable again.
    pub(crate) just_locked: bool,
    /// Typed-confirmation buffer for the severe-friction tier (ia.md §7):
    /// deleting an item or removing a way in requires typing the thing's
    /// name, not `y/N`. Cleared whenever a confirm screen opens or resolves.
    pub(crate) confirm_input: String,
    /// The exact name/label `confirm_input` must match for a severe-tier
    /// confirm (`Screen::DeleteConfirm` / `Screen::RemoveWayInConfirm`) to
    /// proceed (ia.md §7: "type the item/vault name").
    pub(crate) confirm_target_name: String,
    pub(crate) status: String,
    pub(crate) header: Option<VaultHeader>,
    pub(crate) items: Vec<VaultItemSummary>,
    pub(crate) selected_index: usize,
    pub(crate) selected_keyslot_index: usize,
    pub(crate) detail: Option<VaultItem>,
    /// S7 mask/reveal state (ia.md §5, P8.V.1): `false` (masked) is the
    /// entry default on every `ItemDetail` visit and on any lock — never
    /// sticky across a re-open. Not itself a secret, but it gates whether
    /// `detail_panel` is permitted to render one, so it is reset alongside
    /// `detail` everywhere the item selection changes or the vault locks.
    pub(crate) secret_revealed: bool,
    pub(crate) filters: VaultFilterState,
    pub(crate) search_mode: bool,
    pub(crate) capability_report: Option<CapabilityReport>,
    pub(crate) environment_approval: EnvironmentApprovalState,
    pub(crate) unlock_form: UnlockForm,
    pub(crate) add_login_form: AddLoginForm,
    pub(crate) note_form: NoteForm,
    pub(crate) card_form: CardForm,
    pub(crate) identity_form: IdentityForm,
    pub(crate) mnemonic_slot_form: LabelOnlyForm,
    pub(crate) device_slot_form: LabelOnlyForm,
    pub(crate) certificate_slot_form: CertificateSlotForm,
    pub(crate) certificate_rewrap_form: CertificateRewrapForm,
    pub(crate) keyslot_label_form: LabelOnlyForm,
    pub(crate) recovery_secret_form: RecoverySecretForm,
    pub(crate) latest_mnemonic_enrollment: Option<MnemonicRecoveryEnrollment>,
    pub(crate) pending_keyslot_removal_confirmation: Option<String>,
    pub(crate) generate_store_form: GenerateStoreForm,
    pub(crate) export_backup_form: ExportBackupForm,
    pub(crate) export_backup_preview: Option<BackupSummaryPreview>,
    pub(crate) export_transfer_form: ExportTransferForm,
    pub(crate) import_backup_form: ImportBackupForm,
    pub(crate) import_transfer_form: ImportTransferForm,
    pub(crate) editing_item_id: Option<String>,
    pub(crate) session: NativeSessionHardening,
}

impl App {
    #[cfg(test)]
    pub(crate) fn new(options: VaultOpenOptions) -> Self {
        Self::with_config(VaultTuiConfig::new(options))
    }

    pub(crate) fn with_config(config: VaultTuiConfig) -> Self {
        let audit_sink_health = config.audit_sink_health();
        let mut app = Self {
            options: config.open_options,
            profile: config.profile,
            audit_jsonl: config.audit_jsonl,
            require_audit_sink: config.require_audit_sink,
            audit_sink_health,
            ops_audit_events: Vec::new(),
            screen: Screen::UnlockBlocked,
            help_overlay_open: false,
            trust_state: TrustState::default(),
            just_locked: false,
            confirm_input: String::new(),
            confirm_target_name: String::new(),
            status: String::new(),
            header: None,
            items: Vec::new(),
            selected_index: 0,
            selected_keyslot_index: 0,
            detail: None,
            secret_revealed: false,
            filters: VaultFilterState::default(),
            search_mode: false,
            capability_report: None,
            environment_approval: EnvironmentApprovalState::default(),
            unlock_form: UnlockForm::default(),
            add_login_form: AddLoginForm::default(),
            note_form: NoteForm::default(),
            card_form: CardForm::default(),
            identity_form: IdentityForm::default(),
            mnemonic_slot_form: LabelOnlyForm::default(),
            device_slot_form: LabelOnlyForm::default(),
            certificate_slot_form: CertificateSlotForm::default(),
            certificate_rewrap_form: CertificateRewrapForm::default(),
            keyslot_label_form: LabelOnlyForm::default(),
            recovery_secret_form: RecoverySecretForm::default(),
            latest_mnemonic_enrollment: None,
            pending_keyslot_removal_confirmation: None,
            generate_store_form: GenerateStoreForm::default(),
            export_backup_form: ExportBackupForm::default(),
            export_backup_preview: None,
            export_transfer_form: ExportTransferForm::default(),
            import_backup_form: ImportBackupForm::default(),
            import_transfer_form: ImportTransferForm::default(),
            editing_item_id: None,
            session: NativeSessionHardening::default(),
        };
        app.refresh();
        app
    }

    /// Overlays the S1 trust gate (ia.md §2/§3) in front of whatever screen
    /// `refresh()` already computed at construction. Called once by
    /// `run`/`run_scripted` right after `with_config` — never by `refresh()`
    /// itself, so a mid-session refresh (the `r` hotkey, a post-mutation
    /// reload) never re-shows the first-run spine. `refresh()` has already
    /// determined the correct destination (`Vault` or `UnlockBlocked`); the
    /// trust gate just fronts it and `submit_trust_gate` hands control back.
    ///
    /// ia.md §3 short-circuit: "Copy already verified on this machine ->
    /// S1 still shows, but the title-bar token reads ✓ and S1's body reads
    /// *This copy was verified on this machine.*" — detected from a small
    /// per-user marker file (`trust_marker_path()`), never assumed.
    pub(crate) fn enter_trust_gate(&mut self) {
        self.screen = Screen::TrustGate;
        if trust_marker_exists() {
            self.trust_state = TrustState::Checked;
            self.status = "This copy was verified on this machine. You may re-verify or Continue."
                .to_string();
        } else {
            self.trust_state = TrustState::Unchecked;
            self.status =
                "Confirm this copy can be trusted before it handles a single secret.".to_string();
        }
    }

    /// S1 -> S2 -> S3: runs the self-check (see `TrustState` doc for why
    /// this cannot yet claim cryptographic verification) and lands on S3
    /// Verified. Not gated behind a real async step because there is no
    /// long-running check to run yet; `Screen::Verifying` still renders on
    /// the way through so the transition is visible and the non-blocking
    /// contract (ia.md §0 rule 5) has a concrete home for the real check
    /// once one exists. Writes the trust marker so a later session's S1
    /// short-circuit (ia.md §3) can read "verified on this machine" back.
    pub(crate) fn submit_trust_gate(&mut self) {
        self.screen = Screen::Verifying;
        self.trust_state = TrustState::Checked;
        self.screen = Screen::Verified;
        write_trust_marker();
        self.status =
            "This build's identity is confirmed. Cryptographic release verification against a signed publisher record is not available in this build yet.".to_string();
    }

    /// "Skip for now" (ia.md §3 S1) and S3's "Continue" both resume the
    /// already-computed destination screen from `refresh()`.
    pub(crate) fn dismiss_trust_gate(&mut self) {
        self.refresh();
    }

    pub(crate) fn ops_policy_context(&self) -> OpsPolicyContext {
        OpsPolicyContext {
            profile: self.profile,
            audit_sink_required: self.audit_jsonl.is_some()
                || self.require_audit_sink
                || self.profile == OpsProfile::FederalReady,
            audit_sink_available: self.audit_sink_health.is_available(),
            crypto_provider: FederalCryptoProviderEvidence::collect_from_environment(),
            seal_posture: None,
        }
    }

    pub(crate) fn record_vault_operation_policy(
        &mut self,
        operation: &str,
        access: VaultOperationAccess,
    ) -> anyhow::Result<()> {
        let context = self.ops_policy_context();
        let evaluation = evaluate_vault_operation(AuditSurface::Tui, operation, access, &context);
        self.ops_audit_events
            .extend(evaluation.audit_events.iter().cloned());
        if let Some(path) = &self.audit_jsonl
            && self.audit_sink_health.is_available()
        {
            write_events_jsonl(path, evaluation.audit_events.as_slice())
                .with_context(|| format!("write TUI vault audit events to {}", path.display()))?;
        }
        if evaluation.is_allowed() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "TUI vault operation policy denied: {:?}",
                evaluation.decision
            ))
        }
    }

    pub(crate) fn record_vault_unlock_policy(&mut self) -> anyhow::Result<()> {
        if self.profile != OpsProfile::FederalReady {
            return Ok(());
        }
        let method = crate::vault_cli::vault_unlock_method(&self.options);
        let (_, seal_posture) = seal_posture_for_path(
            &self.options.path,
            crate::vault_cli::vault_unlock_provider_probe(method),
        );
        let mut context = self.ops_policy_context();
        context.seal_posture = Some(seal_posture);
        let evaluation = evaluate_ops_command(
            AuditSurface::Tui,
            OpsCommand::VaultUnlock { method },
            &context,
        );
        self.ops_audit_events
            .extend(evaluation.audit_events.iter().cloned());
        if let Some(path) = &self.audit_jsonl
            && self.audit_sink_health.is_available()
        {
            write_events_jsonl(path, evaluation.audit_events.as_slice()).with_context(|| {
                format!("write TUI vault unlock audit events to {}", path.display())
            })?;
        }
        if evaluation.is_allowed() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "TUI vault unlock policy denied: {:?}",
                evaluation.decision
            ))
        }
    }

    pub(crate) fn unlock_for_operation(
        &mut self,
        operation: &str,
        access: VaultOperationAccess,
    ) -> anyhow::Result<UnlockedVault> {
        self.record_vault_operation_policy(operation, access)?;
        self.record_vault_unlock_policy()?;
        Ok(unlock_vault_for_options(&self.options)?)
    }

    pub(crate) fn refresh(&mut self) {
        self.pending_keyslot_removal_confirmation = None;
        self.header = read_vault_header(&self.options.path).ok();
        if !self.environment_approval.resolved && !self.options.path.exists() {
            self.open_environment_approval();
            return;
        }
        match self.reload_vault_state(None) {
            Ok(()) => {
                self.screen = Screen::Vault;
                // brand.md §3 micro-example, verbatim opening clause:
                // "Vault open. 12 items." The unlock-method detail is real
                // diagnostic information (which way in was used) and stays,
                // appended rather than leading — the persona's first read is
                // the plain fact the state changed (brand.md §3 rule 1).
                self.status = format!(
                    "Vault open. {} item(s). Unlocked via {}.",
                    self.items.len(),
                    self.options.unlock_description()
                );
            }
            Err(error) => {
                self.items.clear();
                self.detail = None;
                self.screen = Screen::UnlockBlocked;
                // This is a fresh unlock attempt (S15), not a just-locked
                // transition (S14) — the minimal footer belongs only to the
                // latter (ia.md §5 S14/S15).
                self.just_locked = false;
                // brand.md §3(d): "blocked" reframes the product as the
                // obstacle; the rewrite treats a failed unlock as a calm
                // conversation. The exact "remaining attempts: {n}" wording
                // brand.md's micro-example specifies needs a per-vault
                // attempt counter that does not exist anywhere in
                // `paranoid-vault` yet (tracked as follow-on backend scope,
                // not fabricated here); this states the same fact honestly
                // without inventing a number.
                self.status = format!(
                    "That didn't open the vault. Check your passphrase and try again. ({error})"
                );
            }
        }
    }

    /// Shows the environment-approval screen: the first screen on a fresh
    /// vault path, and reachable again from the vault main screen via the
    /// `E` hotkey. Collects a fresh `CapabilityReport` each time it opens so
    /// keychain/clipboard/display-server/seal-provider evidence reflects the
    /// current process environment.
    pub(crate) fn open_environment_approval(&mut self) {
        self.environment_approval.choice = EnvironmentApprovalChoice::Accept;
        self.capability_report = Some(crate::capability_detect::collect_capability_report(
            &self.options.path,
        ));
        self.screen = Screen::EnvironmentApproval;
        self.status = "Review detected capabilities before setting up the vault.".to_string();
    }

    pub(crate) fn reload_vault_state(&mut self, preferred_id: Option<&str>) -> anyhow::Result<()> {
        let vault = self.unlock_for_operation("read_item", VaultOperationAccess::Decrypt)?;
        self.load_vault_state_from(&vault, preferred_id)
    }

    /// Loads item/header state from an already-unlocked vault handle,
    /// without deriving or re-deriving auth. Shared by `reload_vault_state`
    /// (which unlocks fresh) and `submit_vault_init` (which already holds an
    /// `UnlockedVault` from `init_vault_unlocked` and must not pay a second
    /// Argon2id derivation just to load the same, still-empty item list).
    pub(crate) fn load_vault_state_from(
        &mut self,
        vault: &UnlockedVault,
        preferred_id: Option<&str>,
    ) -> anyhow::Result<()> {
        self.header = Some(vault.header().clone());
        if self
            .pending_keyslot_removal_confirmation
            .as_ref()
            .is_some_and(|pending| {
                !self
                    .header
                    .as_ref()
                    .is_some_and(|header| header.keyslots.iter().any(|slot| &slot.id == pending))
            })
        {
            self.pending_keyslot_removal_confirmation = None;
        }
        self.items = vault.list_items_filtered(&self.filters.as_filter())?;
        if self.items.is_empty() {
            self.selected_index = 0;
            self.detail = None;
            return Ok(());
        }

        self.selected_index = preferred_id
            .and_then(|target| self.items.iter().position(|item| item.id == target))
            .unwrap_or_else(|| self.selected_index.min(self.items.len().saturating_sub(1)));
        let selected_id = self
            .items
            .get(self.selected_index)
            .map(|item| item.id.clone())
            .unwrap_or_default();
        self.detail = Some(vault.get_item(&selected_id)?);
        Ok(())
    }

    pub(crate) fn submit_native_unlock(&mut self) {
        self.options.mnemonic_phrase_env = None;
        self.options.mnemonic_phrase = None;
        self.options.mnemonic_slot = None;
        self.options.device_slot = None;
        self.options.use_device_auto = false;
        self.options.auth = VaultAuth::PasswordEnv("PARANOID_MASTER_PASSWORD".to_string());

        match self.unlock_form.mode {
            UnlockMode::Password => {
                self.options.auth = VaultAuth::Password(self.unlock_form.password.clone());
            }
            UnlockMode::Mnemonic => {
                self.options.mnemonic_phrase = Some(self.unlock_form.mnemonic_phrase.clone());
                self.options.mnemonic_slot =
                    normalize_optional_field(&self.unlock_form.mnemonic_slot);
            }
            UnlockMode::Device => {
                let slot = normalize_optional_field(&self.unlock_form.device_slot);
                if let Some(slot_id) = slot {
                    self.options.device_slot = Some(slot_id);
                } else {
                    self.options.use_device_auto = true;
                }
            }
            UnlockMode::Certificate => {
                self.options.auth = VaultAuth::Certificate {
                    cert_path: self.unlock_form.cert_path.trim().into(),
                    key_path: self.unlock_form.key_path.trim().into(),
                    key_passphrase_env: None,
                    key_passphrase: normalize_optional_secret(&self.unlock_form.key_passphrase),
                };
            }
        }

        if !self.options.path.exists() && matches!(self.unlock_form.mode, UnlockMode::Password) {
            self.submit_vault_init();
            return;
        }

        self.refresh();
    }

    /// Initializes a fresh vault at `self.options.path` using the recovery
    /// secret entered on the unlock/init form, then applies the suggested
    /// initial configuration from the environment-approval screen (a
    /// device-bound keyslot, when accepted and the OS keychain is
    /// available). Called from `submit_native_unlock` when the target path
    /// has no vault yet, covering both the accept path (suggestion
    /// prefilled) and the adjust path (manual entry, no auto-enrollment).
    ///
    /// Uses `init_vault_unlocked` and operates on the returned handle
    /// directly rather than following up with a fresh `unlock_vault` call:
    /// the Argon2id KEK derivation is deliberately expensive (paranoid
    /// posture), so re-deriving it a second (or third, for the auto-enroll
    /// path) time immediately after init would needlessly double or triple
    /// the latency of every vault creation for no security benefit — the
    /// master key from init is already in hand.
    pub(crate) fn submit_vault_init(&mut self) {
        let master_password = self.unlock_form.password.clone();
        match init_vault_unlocked(&self.options.path, master_password.as_str()) {
            Ok(mut vault) => {
                self.options.auth = VaultAuth::Password(master_password);
                self.environment_approval.resolved = true;
                let auto_enroll_device = matches!(
                    self.environment_approval.choice,
                    EnvironmentApprovalChoice::Accept
                ) && self
                    .capability_report
                    .as_ref()
                    .is_some_and(|report| report.os_keychain.status.is_available());

                if auto_enroll_device {
                    self.auto_enroll_device_keyslot(&mut vault);
                } else if let Err(error) = self.load_vault_state_from(&vault, None) {
                    self.status = format!(
                        "Vault initialized at {}, but loading vault state failed: {error}",
                        self.options.path.display()
                    );
                } else {
                    self.status = format!("Vault initialized at {}.", self.options.path.display());
                }
                self.screen = Screen::Vault;
            }
            Err(error) => {
                self.status = format!("Vault initialization failed: {error}");
            }
        }
    }

    /// Enrolls a device-bound keyslot right after init when the environment
    /// approval screen was accepted and the OS keychain probe reported
    /// available. Operates on the freshly initialized `vault` handle passed
    /// in by `submit_vault_init` rather than re-deriving auth.
    pub(crate) fn auto_enroll_device_keyslot(&mut self, vault: &mut UnlockedVault) {
        match vault.add_device_keyslot(None).map_err(anyhow::Error::from) {
            Ok(slot) => {
                let status_suffix = format!(
                    "Enrolled device-bound keyslot {} per the accepted environment suggestion.",
                    slot.id
                );
                match self.load_vault_state_from(vault, None) {
                    Ok(()) => {
                        self.status = format!(
                            "Vault initialized at {}. {status_suffix}",
                            self.options.path.display()
                        );
                    }
                    Err(error) => {
                        self.status = format!(
                            "Vault initialized at {}. {status_suffix} (loading vault state failed: {error})",
                            self.options.path.display()
                        );
                    }
                }
            }
            Err(error) => {
                self.status = format!(
                    "Vault initialized at {}, but the suggested device-bound keyslot could not be enrolled: {error}",
                    self.options.path.display()
                );
                if let Err(load_error) = self.load_vault_state_from(vault, None) {
                    self.status = format!(
                        "{}; also failed to load vault state: {load_error}",
                        self.status
                    );
                }
            }
        }
    }

    pub(crate) fn poll_hardening(&mut self) {
        if let Some(expected) = self.session.take_due_clipboard_contents() {
            match clear_clipboard_if_matches(expected.as_str()) {
                Ok(true) => {
                    self.status = format!(
                        "Clipboard auto-cleared after {} seconds.",
                        self.session.clipboard_clear_after().as_secs()
                    );
                }
                Ok(false) => {}
                Err(error) => {
                    self.status = format!("Clipboard auto-clear failed: {error}");
                }
            }
        }

        if self.screen.is_unlocked_vault_screen() && self.session.should_auto_lock() {
            let clipboard_cleared = self.clear_decrypted_state_and_lock();
            self.session.note_activity();
            self.status = if clipboard_cleared {
                format!(
                    "Vault auto-locked after {} seconds of inactivity and cleared the clipboard.",
                    self.session.idle_lock_after().as_secs()
                )
            } else {
                format!(
                    "Vault auto-locked after {} seconds of inactivity.",
                    self.session.idle_lock_after().as_secs()
                )
            };
        }
    }

    /// Immediately drives any unlocked-vault screen to `UnlockBlocked`,
    /// clearing decrypted vault state and purging every secret-bearing form
    /// (via [`Self::purge_secret_state_on_lock`]) and the armed clipboard
    /// contents. Shared by idle auto-lock (`poll_hardening`) and the panic
    /// / quick-lock hotkey (`Ctrl+L`, see `handle_key`) so both triggers run
    /// the exact same scrub path. Returns whether an armed clipboard entry
    /// was found and cleared.
    fn clear_decrypted_state_and_lock(&mut self) -> bool {
        let clipboard_cleared = match self.session.take_pending_clipboard_contents() {
            Some(expected) => clear_clipboard_if_matches(expected.as_str()).unwrap_or(false),
            None => false,
        };
        self.header = None;
        self.items.clear();
        self.selected_index = 0;
        self.selected_keyslot_index = 0;
        self.detail = None;
        self.search_mode = false;
        self.editing_item_id = None;
        self.screen = Screen::UnlockBlocked;
        // ia.md §5 S14: a just-locked screen shows the minimal footer
        // (`⏎ unlock  q quit`, no `?`) — "in a locked state the only valid
        // acts are unlock or quit." Cleared the moment the persona
        // interacts with the unlock form (`handle_unlock_blocked_key`),
        // reverting to the ordinary S15 footer with recovery paths.
        self.just_locked = true;
        self.purge_secret_state_on_lock();
        clipboard_cleared
    }

    /// Panic / quick-lock hotkey (P9.6): from any unlocked-vault screen,
    /// `Ctrl+L` immediately runs the same lock-and-purge path as idle
    /// auto-lock, then re-arms the idle timer so the freshly-shown unlock
    /// screen does not itself appear to have triggered an auto-lock. A
    /// no-op on pre-unlock screens (`EnvironmentApproval`/`UnlockBlocked`),
    /// which have no unlocked state to purge.
    ///
    /// Documented as the TUI panic key in `docs/guides/tui.md` (see
    /// "Panic / quick-lock hotkey").
    pub(crate) fn handle_panic_lock_hotkey(&mut self) -> bool {
        if !self.screen.is_unlocked_vault_screen() {
            return false;
        }
        let clipboard_cleared = self.clear_decrypted_state_and_lock();
        self.session.note_activity();
        // brand.md §3 micro-example, verbatim: "Locked. Nothing is readable
        // until you unlock again." — never "you're safe" (brand.md §3 rule
        // 4: the product reports accurately, never overpromises).
        self.status = if clipboard_cleared {
            "Locked. Nothing is readable until you unlock again. The clipboard was cleared too."
                .to_string()
        } else {
            "Locked. Nothing is readable until you unlock again.".to_string()
        };
        true
    }

    /// Purges every secret-bearing field reachable from an unlocked-vault
    /// screen once auto-lock (or an explicit lock) fires. `options.auth`
    /// is reset to a non-secret `PasswordEnv` placeholder that forces
    /// re-entry on the next unlock attempt, and every form that can hold a
    /// `SecretString` (or a plaintext secret in a plain `String` field, e.g.
    /// `add_login_form.password`, `card_form.number`/`security_code`,
    /// `note_form.content`) is reset to its default so the zeroizing drop
    /// (or, for the plain-`String` add/edit forms, simple replacement of the
    /// old heap buffer) scrubs the old plaintext immediately instead of
    /// leaving it resident until the next time that form happens to be
    /// reused. `self.detail` — the decrypted item shown on the detail
    /// screen — is cleared here too so the panic-lock hotkey scrubs it even
    /// though `clear_decrypted_state_and_lock` also clears it independently;
    /// this method must be a complete purge on its own so a caller that
    /// invokes it directly (as the P9 gate's pinned test now does) can't be
    /// fooled by a partial scrub landing green.
    pub(crate) fn purge_secret_state_on_lock(&mut self) {
        // FAIL-CLOSED EXHAUSTIVENESS (P9 re-verify): destructure `self` with an
        // explicit `..`-free field list so adding ANY new App field breaks this
        // build until it is triaged here as either a secret to scrub or an
        // acknowledged non-secret. Three prior leaks (form fields, the master
        // recovery mnemonic, its clipboard copy) all came from a purge that
        // silently omitted a field; the compiler now catches the next one.
        let Self {
            // --- secret-bearing: MUST be scrubbed ---
            options,
            detail,
            // Not itself a secret, but it gates whether `detail_panel` is
            // permitted to render an unmasked S7 secret (P8.V.1). Scrubbed
            // alongside `detail` so a panic-lock/idle-lock can never leave a
            // vault re-opened mid-reveal; re-entering S7 always re-masks.
            secret_revealed,
            latest_mnemonic_enrollment,
            unlock_form,
            add_login_form,
            note_form,
            card_form,
            identity_form,
            recovery_secret_form,
            certificate_rewrap_form,
            export_transfer_form,
            import_transfer_form,
            // `session` holds the armed clipboard buffer (a plaintext copy of the
            // last-copied secret, incl. the master recovery mnemonic). Its
            // in-memory residency is scrubbed here; the OS clipboard wipe stays
            // with the caller that owns the arboard handle (LEAK-D).
            session,
            // --- non-secret: acknowledged, intentionally not scrubbed. NO `..`:
            // adding an App field breaks this destructure until it is triaged
            // here, which is the fail-closed guarantee. If any of these gains a
            // secret field, convert it and move it above.
            profile: _,
            audit_jsonl: _,
            require_audit_sink: _,
            audit_sink_health: _,
            ops_audit_events: _, // redacted by construction (P0.4)
            screen: _,
            status: _,
            header: _,
            items: _,
            selected_index: _,
            selected_keyslot_index: _,
            filters: _,
            search_mode: _,
            capability_report: _,
            environment_approval: _,
            mnemonic_slot_form: _,
            device_slot_form: _,
            certificate_slot_form: _,
            keyslot_label_form: _,
            pending_keyslot_removal_confirmation: _,
            generate_store_form: _,
            export_backup_form: _,
            export_backup_preview: _,
            import_backup_form: _,
            editing_item_id: _,
            help_overlay_open: _,
            trust_state: _,
            just_locked: _,
            // `confirm_input`/`confirm_target_name` hold a typed item/vault
            // *name* the persona types to confirm a severe-tier action
            // (ia.md §7) — never a passphrase or recovery secret — so they
            // are not secret-bearing. Still cleared defensively on lock so
            // no in-progress typed text lingers past a panic lock.
            confirm_input,
            confirm_target_name,
        } = self;
        confirm_input.clear();
        confirm_target_name.clear();

        options.auth = VaultAuth::PasswordEnv("PARANOID_MASTER_PASSWORD".to_string());
        options.mnemonic_phrase = None;
        *detail = None;
        *secret_revealed = false;
        *latest_mnemonic_enrollment = None;
        *unlock_form = UnlockForm::default();
        *add_login_form = AddLoginForm::default();
        *note_form = NoteForm::default();
        *card_form = CardForm::default();
        *identity_form = IdentityForm::default();
        *recovery_secret_form = RecoverySecretForm::default();
        *certificate_rewrap_form = CertificateRewrapForm::default();
        *export_transfer_form = ExportTransferForm::default();
        *import_transfer_form = ImportTransferForm::default();
        session.clear_clipboard_tracking();
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> bool {
        // P9.6: the panic / quick-lock hotkey is checked before per-screen
        // dispatch so it fires from ANY unlocked screen — including mid-edit
        // in a secret-bearing text field — rather than only where a screen
        // handler happens to leave 'l' unbound. `handle_panic_lock_hotkey`
        // itself no-ops on pre-unlock screens, so this is safe to check
        // unconditionally on every keypress.
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('l')) {
            self.handle_panic_lock_hotkey();
            return false;
        }

        // S12 `?` overlay (ia.md §5): while open, every key except the ones
        // that close it is swallowed — the overlay is a transient layer over
        // the fixed skeleton (ia.md §5 "it does not become a new screen"),
        // so closing it always returns to exactly the screen/state under it.
        if self.help_overlay_open {
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')
            ) {
                self.help_overlay_open = false;
            }
            return false;
        }
        if matches!(key.code, KeyCode::Char('?'))
            && footer::help_key_active(self.screen)
            && !(matches!(self.screen, Screen::Vault) && self.search_mode)
        {
            self.help_overlay_open = true;
            return false;
        }

        match self.screen {
            Screen::TrustGate => self.handle_trust_gate_key(key),
            Screen::Verifying => self.handle_verifying_key(key),
            Screen::Verified => self.handle_verified_key(key),
            Screen::EnvironmentApproval => self.handle_environment_approval_key(key),
            Screen::Vault | Screen::Keyslots => self.handle_vault_key(key),
            Screen::ItemDetail => self.handle_item_detail_key(key),
            Screen::UnlockBlocked => self.handle_unlock_blocked_key(key),
            Screen::AddLogin | Screen::EditLogin => self.handle_add_login_key(key),
            Screen::AddNote | Screen::EditNote => self.handle_note_key(key),
            Screen::AddCard | Screen::EditCard => self.handle_card_key(key),
            Screen::AddIdentity | Screen::EditIdentity => self.handle_identity_key(key),
            Screen::AddMnemonicSlot | Screen::AddDeviceSlot | Screen::EditKeyslotLabel => {
                self.handle_label_only_key(key)
            }
            Screen::AddCertSlot => self.handle_certificate_key(key),
            Screen::RewrapCertSlot => self.handle_certificate_rewrap_key(key),
            Screen::RotateMnemonicSlot => self.handle_rotate_mnemonic_slot_key(key),
            Screen::RotateRecoverySecret => self.handle_recovery_secret_key(key),
            Screen::MnemonicReveal => self.handle_mnemonic_reveal_key(key),
            Screen::GenerateStore => self.handle_generate_store_key(key),
            Screen::ExportBackup => self.handle_export_backup_key(key),
            Screen::ExportTransfer => self.handle_export_transfer_key(key),
            Screen::ImportBackup => self.handle_import_backup_key(key),
            Screen::ImportTransfer => self.handle_import_transfer_key(key),
            Screen::DeleteConfirm => self.handle_delete_confirm_key(key),
            Screen::RemoveWayInConfirm => self.handle_remove_way_in_confirm_key(key),
        }
    }

    pub(crate) fn handle_trust_gate_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Enter => {
                self.submit_trust_gate();
                false
            }
            KeyCode::Char('s') | KeyCode::Esc => {
                self.dismiss_trust_gate();
                false
            }
            _ => false,
        }
    }

    pub(crate) fn handle_verifying_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.dismiss_trust_gate();
                false
            }
            _ => false,
        }
    }

    pub(crate) fn handle_verified_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Enter | KeyCode::Esc => {
                self.dismiss_trust_gate();
                false
            }
            _ => false,
        }
    }

    pub(crate) fn handle_environment_approval_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc if self.header.is_some() => {
                self.screen = Screen::Vault;
                self.status = "Returned to the vault item view.".to_string();
                false
            }
            KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => {
                let delta = if matches!(key.code, KeyCode::Up | KeyCode::BackTab) {
                    -1
                } else {
                    1
                };
                self.environment_approval.adjust_focus(delta);
                false
            }
            KeyCode::Enter => {
                self.submit_environment_approval();
                false
            }
            _ => false,
        }
    }

    pub(crate) fn submit_environment_approval(&mut self) {
        self.environment_approval.resolved = true;
        self.unlock_form = UnlockForm {
            mode: UnlockMode::Password,
            ..UnlockForm::default()
        };
        self.screen = Screen::UnlockBlocked;
        self.status = match self.environment_approval.choice {
            EnvironmentApprovalChoice::Accept => {
                let device_bound_suggested = self
                    .capability_report
                    .as_ref()
                    .is_some_and(|report| report.os_keychain.status.is_available());
                if device_bound_suggested {
                    "Suggested configuration accepted: enter a recovery secret to initialize the vault; a device-bound keyslot will be enrolled automatically.".to_string()
                } else {
                    "Suggested configuration accepted: enter a recovery secret to initialize the vault.".to_string()
                }
            }
            EnvironmentApprovalChoice::Adjust => {
                "Manual setup: enter a recovery secret to initialize the vault, then adjust keyslots from the Keyslots view afterward.".to_string()
            }
        };
    }

    pub(crate) fn handle_unlock_blocked_key(&mut self, key: KeyEvent) -> bool {
        // ia.md §5 S14->S15: any interaction beyond quitting reverts the
        // minimal just-locked footer to the ordinary unlock-prompt footer
        // (`? other ways in` becomes reachable again).
        if !matches!(key.code, KeyCode::Char('q')) {
            self.just_locked = false;
        }
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Char('r') if matches!(self.screen, Screen::Vault) => {
                self.refresh();
                false
            }
            KeyCode::Char('p') => {
                self.unlock_form.mode = UnlockMode::Password;
                false
            }
            KeyCode::Char('m') => {
                self.unlock_form.mode = UnlockMode::Mnemonic;
                self.unlock_form.focus_index = self
                    .unlock_form
                    .focus_index
                    .min(self.unlock_form.visible_fields().len() - 1);
                false
            }
            KeyCode::Char('b') => {
                self.unlock_form.mode = UnlockMode::Device;
                self.unlock_form.focus_index = self
                    .unlock_form
                    .focus_index
                    .min(self.unlock_form.visible_fields().len() - 1);
                false
            }
            KeyCode::Char('c') => {
                self.unlock_form.mode = UnlockMode::Certificate;
                self.unlock_form.focus_index = self
                    .unlock_form
                    .focus_index
                    .min(self.unlock_form.visible_fields().len() - 1);
                false
            }
            KeyCode::Up => {
                self.unlock_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.unlock_form.adjust_focus(1);
                false
            }
            KeyCode::Left if matches!(self.unlock_form.selected_field(), UnlockField::Mode) => {
                self.unlock_form.cycle_mode(-1);
                false
            }
            KeyCode::Right if matches!(self.unlock_form.selected_field(), UnlockField::Mode) => {
                self.unlock_form.cycle_mode(1);
                false
            }
            KeyCode::Enter => {
                if matches!(self.unlock_form.selected_field(), UnlockField::Submit) {
                    self.submit_native_unlock();
                } else if matches!(self.unlock_form.selected_field(), UnlockField::Mode) {
                    self.unlock_form.cycle_mode(1);
                } else {
                    self.unlock_form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(self.unlock_form.selected_value_mut(), key);
                edit_form_value(self.unlock_form.selected_secret_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_vault_key(&mut self, key: KeyEvent) -> bool {
        if matches!(self.screen, Screen::Vault) && self.search_mode {
            return self.handle_search_key(key);
        }
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Char('r') if matches!(self.screen, Screen::Vault) => {
                self.refresh();
                false
            }
            KeyCode::Char('E') if matches!(self.screen, Screen::Vault) => {
                self.open_environment_approval();
                false
            }
            KeyCode::Esc if matches!(self.screen, Screen::Keyslots) => {
                self.pending_keyslot_removal_confirmation = None;
                self.screen = Screen::Vault;
                self.status = "Returned to the vault item view.".to_string();
                false
            }
            KeyCode::Char('/') if matches!(self.screen, Screen::Vault) => {
                self.search_mode = true;
                self.status = format!(
                    "Vault filter edit mode. field={} value={} | Tab cycles, Left/Right/Space changes kind, Ctrl-U clears selected field.",
                    self.filters.field.label(),
                    if self.filters.selected_field_summary().is_empty() {
                        "(empty)".to_string()
                    } else {
                        self.filters.selected_field_summary()
                    }
                );
                false
            }
            KeyCode::Char('a') if matches!(self.screen, Screen::Vault) => {
                self.open_add_login();
                false
            }
            KeyCode::Char('n') if matches!(self.screen, Screen::Vault) => {
                self.open_add_note();
                false
            }
            KeyCode::Char('v') if matches!(self.screen, Screen::Vault) => {
                self.open_add_card();
                false
            }
            KeyCode::Char('i') if matches!(self.screen, Screen::Vault) => {
                self.open_add_identity();
                false
            }
            KeyCode::Char('e') if matches!(self.screen, Screen::Vault) => {
                self.open_edit_item();
                false
            }
            KeyCode::Char('d') if matches!(self.screen, Screen::Vault) => {
                self.open_delete_confirm();
                false
            }
            KeyCode::Char('g') if matches!(self.screen, Screen::Vault) => {
                self.open_generate_store();
                false
            }
            KeyCode::Char('x') if matches!(self.screen, Screen::Vault) => {
                self.open_export_backup();
                false
            }
            KeyCode::Char('t') if matches!(self.screen, Screen::Vault) => {
                self.open_export_transfer();
                false
            }
            KeyCode::Char('u') if matches!(self.screen, Screen::Vault) => {
                self.open_import_backup();
                false
            }
            KeyCode::Char('p') if matches!(self.screen, Screen::Vault) => {
                self.open_import_transfer();
                false
            }
            KeyCode::Up if matches!(self.screen, Screen::Vault) => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                    self.reload_detail();
                }
                false
            }
            KeyCode::Down if matches!(self.screen, Screen::Vault) => {
                if self.selected_index + 1 < self.items.len() {
                    self.selected_index += 1;
                    self.reload_detail();
                }
                false
            }
            KeyCode::Char('c') if matches!(self.screen, Screen::Vault) => {
                self.copy_selected_secret();
                false
            }
            // P8.V.2: `⏎` on the vault list opens the S7 item-detail screen
            // — the footer has always promised this; it now navigates.
            KeyCode::Enter if matches!(self.screen, Screen::Vault) => {
                self.open_item_detail();
                false
            }
            KeyCode::Char('k') if matches!(self.screen, Screen::Vault) => {
                self.open_keyslots();
                false
            }
            KeyCode::Char('m') if matches!(self.screen, Screen::Keyslots) => {
                self.pending_keyslot_removal_confirmation = None;
                self.open_add_mnemonic_slot();
                false
            }
            KeyCode::Char('b') if matches!(self.screen, Screen::Keyslots) => {
                self.pending_keyslot_removal_confirmation = None;
                self.open_add_device_slot();
                false
            }
            KeyCode::Char('c') if matches!(self.screen, Screen::Keyslots) => {
                self.pending_keyslot_removal_confirmation = None;
                self.open_add_certificate_slot();
                false
            }
            KeyCode::Char('w') if matches!(self.screen, Screen::Keyslots) => {
                self.pending_keyslot_removal_confirmation = None;
                self.open_rewrap_certificate_slot();
                false
            }
            KeyCode::Char('l') if matches!(self.screen, Screen::Keyslots) => {
                self.pending_keyslot_removal_confirmation = None;
                self.open_edit_keyslot_label();
                false
            }
            KeyCode::Char('o') if matches!(self.screen, Screen::Keyslots) => {
                self.pending_keyslot_removal_confirmation = None;
                self.open_rotate_mnemonic_slot();
                false
            }
            // `x` is the ia.md §5 S10-footer key ("x remove"); `d` is kept as
            // an alias for existing muscle memory. Both now route to the
            // severe-tier typed-confirmation screen (ia.md §7) instead of
            // the old immediate/press-again removal.
            KeyCode::Char('x') | KeyCode::Char('d') if matches!(self.screen, Screen::Keyslots) => {
                self.open_remove_way_in_confirm();
                false
            }
            KeyCode::Char('r') if matches!(self.screen, Screen::Keyslots) => {
                self.rebind_selected_device_keyslot();
                false
            }
            KeyCode::Char('p') if matches!(self.screen, Screen::Keyslots) => {
                self.pending_keyslot_removal_confirmation = None;
                self.open_rotate_recovery_secret();
                false
            }
            KeyCode::Up if matches!(self.screen, Screen::Keyslots) => {
                if self.selected_keyslot_index > 0 {
                    self.selected_keyslot_index -= 1;
                    self.pending_keyslot_removal_confirmation = None;
                }
                false
            }
            KeyCode::Down if matches!(self.screen, Screen::Keyslots) => {
                let len = self
                    .header
                    .as_ref()
                    .map(|header| header.keyslots.len())
                    .unwrap_or_default();
                if self.selected_keyslot_index + 1 < len {
                    self.selected_keyslot_index += 1;
                    self.pending_keyslot_removal_confirmation = None;
                }
                false
            }
            _ => false,
        }
    }

    /// S7 (ia.md §5) key handling: `⏎ copy  r reveal  e edit  ? all keys
    /// ⎋ back` — deliberately does NOT include `d` in the footer (delete is
    /// a severe-tier action that lives behind `?`, ia.md §5), but the key
    /// itself still works here for muscle-memory parity with the vault list,
    /// same as `open_delete_confirm`'s existing behavior from `Screen::Vault`.
    pub(crate) fn handle_item_detail_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.leave_item_detail();
                false
            }
            KeyCode::Enter => {
                self.copy_selected_secret();
                false
            }
            KeyCode::Char('c') => {
                self.copy_selected_secret();
                false
            }
            KeyCode::Char('r') => {
                self.toggle_secret_reveal();
                false
            }
            KeyCode::Char('e') => {
                self.open_edit_item();
                false
            }
            KeyCode::Char('d') => {
                self.open_delete_confirm();
                false
            }
            _ => false,
        }
    }

    pub(crate) fn handle_rotate_mnemonic_slot_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Keyslots;
                self.status = "Canceled mnemonic recovery rotation.".to_string();
                false
            }
            KeyCode::Enter | KeyCode::Char('y') => {
                self.submit_rotate_mnemonic_slot();
                false
            }
            _ => false,
        }
    }

    pub(crate) fn handle_search_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.search_mode = false;
                self.status = if self.filters.is_active() {
                    format!(
                        "Vault filters locked to [{}] ({} matching item(s)).",
                        self.filters.summary(),
                        self.items.len()
                    )
                } else {
                    "Vault filters cleared.".to_string()
                };
                false
            }
            KeyCode::Tab => {
                self.filters.adjust_focus(1);
                self.status = format!(
                    "Vault filter edit mode. field={} value={}",
                    self.filters.field.label(),
                    if self.filters.selected_field_summary().is_empty() {
                        "(empty)".to_string()
                    } else {
                        self.filters.selected_field_summary()
                    }
                );
                false
            }
            KeyCode::BackTab => {
                self.filters.adjust_focus(-1);
                self.status = format!(
                    "Vault filter edit mode. field={} value={}",
                    self.filters.field.label(),
                    if self.filters.selected_field_summary().is_empty() {
                        "(empty)".to_string()
                    } else {
                        self.filters.selected_field_summary()
                    }
                );
                false
            }
            KeyCode::Left if matches!(self.filters.field, VaultFilterField::Kind) => {
                self.filters.cycle_kind(-1);
                self.refresh_filter_preview();
                false
            }
            KeyCode::Right | KeyCode::Char(' ')
                if matches!(self.filters.field, VaultFilterField::Kind) =>
            {
                self.filters.cycle_kind(1);
                self.refresh_filter_preview();
                false
            }
            _ => {
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('u'))
                {
                    self.filters.clear_selected_field();
                    self.refresh_filter_preview();
                    return false;
                }
                edit_form_value(self.filters.selected_value_mut(), key);
                self.refresh_filter_preview();
                false
            }
        }
    }

    pub(crate) fn refresh_filter_preview(&mut self) {
        match self.reload_vault_state(None) {
            Ok(()) => {
                self.status = if self.filters.is_active() {
                    format!(
                        "Filtering unlocked vault items by [{}] ({} match(es)). Active field={} value={}",
                        self.filters.summary(),
                        self.items.len(),
                        self.filters.field.label(),
                        if self.filters.selected_field_summary().is_empty() {
                            "(empty)".to_string()
                        } else {
                            self.filters.selected_field_summary()
                        }
                    )
                } else {
                    "Vault filters cleared.".to_string()
                };
            }
            Err(error) => {
                self.items.clear();
                self.detail = None;
                self.status = format!("Vault filter refresh failed: {error}");
            }
        }
    }

    pub(crate) fn handle_add_login_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Vault;
                self.editing_item_id = None;
                self.status = "Canceled login form.".to_string();
                false
            }
            KeyCode::Up => {
                self.add_login_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.add_login_form.adjust_focus(1);
                false
            }
            KeyCode::Enter => {
                if matches!(self.add_login_form.selected_field(), AddLoginField::Save) {
                    self.submit_login_form();
                } else {
                    self.add_login_form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(self.add_login_form.selected_value_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_note_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Vault;
                self.editing_item_id = None;
                self.status = "Canceled secure note form.".to_string();
                false
            }
            KeyCode::Up => {
                self.note_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.note_form.adjust_focus(1);
                false
            }
            KeyCode::Enter => {
                if matches!(self.note_form.selected_field(), NoteField::Save) {
                    self.submit_note_form();
                } else {
                    self.note_form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(self.note_form.selected_value_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_card_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Vault;
                self.editing_item_id = None;
                self.status = "Canceled card form.".to_string();
                false
            }
            KeyCode::Up => {
                self.card_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.card_form.adjust_focus(1);
                false
            }
            KeyCode::Enter => {
                if matches!(self.card_form.selected_field(), CardField::Save) {
                    self.submit_card_form();
                } else {
                    self.card_form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(self.card_form.selected_value_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_identity_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Vault;
                self.editing_item_id = None;
                self.status = "Canceled identity form.".to_string();
                false
            }
            KeyCode::Up => {
                self.identity_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.identity_form.adjust_focus(1);
                false
            }
            KeyCode::Enter => {
                if matches!(self.identity_form.selected_field(), IdentityField::Save) {
                    self.submit_identity_form();
                } else {
                    self.identity_form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(self.identity_form.selected_value_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_label_only_key(&mut self, key: KeyEvent) -> bool {
        let form = match self.screen {
            Screen::AddMnemonicSlot => &mut self.mnemonic_slot_form,
            Screen::AddDeviceSlot => &mut self.device_slot_form,
            Screen::EditKeyslotLabel => &mut self.keyslot_label_form,
            _ => unreachable!("label-only handler only supports keyslot enrollment forms"),
        };
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                let was_relabel = matches!(self.screen, Screen::EditKeyslotLabel);
                self.screen = Screen::Keyslots;
                self.status = if was_relabel {
                    "Canceled keyslot relabel.".to_string()
                } else {
                    "Canceled keyslot enrollment.".to_string()
                };
                false
            }
            KeyCode::Up => {
                form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                form.adjust_focus(1);
                false
            }
            KeyCode::Enter => {
                if matches!(form.selected_field(), LabelOnlyField::Save) {
                    match self.screen {
                        Screen::AddMnemonicSlot => self.submit_mnemonic_slot(),
                        Screen::AddDeviceSlot => self.submit_device_slot(),
                        Screen::EditKeyslotLabel => self.submit_keyslot_label_edit(),
                        _ => {}
                    }
                } else {
                    form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(form.selected_value_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_certificate_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Keyslots;
                self.status = "Canceled certificate keyslot enrollment.".to_string();
                false
            }
            KeyCode::Up => {
                self.certificate_slot_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.certificate_slot_form.adjust_focus(1);
                false
            }
            KeyCode::Enter => {
                if matches!(
                    self.certificate_slot_form.selected_field(),
                    CertificateField::Save
                ) {
                    self.submit_certificate_slot();
                } else {
                    self.certificate_slot_form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(self.certificate_slot_form.selected_value_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_certificate_rewrap_key(&mut self, key: KeyEvent) -> bool {
        let form = match self.screen {
            Screen::RewrapCertSlot => &mut self.certificate_rewrap_form,
            _ => unreachable!("certificate rewrap handler only supports certificate rewrap"),
        };
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Keyslots;
                self.status = "Canceled certificate slot rewrap.".to_string();
                false
            }
            KeyCode::Up => {
                form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                form.adjust_focus(1);
                false
            }
            KeyCode::Enter => {
                if matches!(form.selected_field(), CertificateRewrapField::Save) {
                    self.submit_certificate_slot_rewrap();
                } else {
                    form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(form.selected_value_mut(), key);
                edit_form_value(form.selected_secret_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_recovery_secret_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.recovery_secret_form = RecoverySecretForm::default();
                self.screen = Screen::Keyslots;
                self.status = "Canceled recovery secret rotation.".to_string();
                false
            }
            KeyCode::Up => {
                self.recovery_secret_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.recovery_secret_form.adjust_focus(1);
                false
            }
            KeyCode::Enter => {
                if matches!(
                    self.recovery_secret_form.selected_field(),
                    RecoverySecretField::Save
                ) {
                    self.submit_rotate_recovery_secret();
                } else {
                    self.recovery_secret_form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(self.recovery_secret_form.selected_secret_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_mnemonic_reveal_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc | KeyCode::Enter => {
                self.screen = Screen::Keyslots;
                self.latest_mnemonic_enrollment = None;
                self.status =
                    "Mnemonic recovery enrollment complete. Store the phrase offline before closing."
                        .to_string();
                false
            }
            KeyCode::Char('c') => {
                self.copy_latest_mnemonic();
                false
            }
            _ => false,
        }
    }

    pub(crate) fn handle_generate_store_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Vault;
                self.status = "Canceled generate-and-store form.".to_string();
                false
            }
            KeyCode::Up => {
                self.generate_store_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.generate_store_form.adjust_focus(1);
                false
            }
            KeyCode::Enter => {
                if matches!(
                    self.generate_store_form.selected_field(),
                    GenerateField::Save
                ) {
                    self.submit_generate_store();
                } else {
                    self.generate_store_form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(self.generate_store_form.selected_value_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_export_backup_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Vault;
                self.status = "Canceled backup export.".to_string();
                false
            }
            KeyCode::Up => {
                self.export_backup_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.export_backup_form.adjust_focus(1);
                false
            }
            KeyCode::Enter => {
                if matches!(
                    self.export_backup_form.selected_field(),
                    ExportBackupField::Save
                ) {
                    self.submit_export_backup();
                } else {
                    self.export_backup_form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(self.export_backup_form.selected_value_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_import_backup_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Vault;
                self.status = "Canceled backup import.".to_string();
                false
            }
            KeyCode::Up => {
                self.import_backup_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.import_backup_form.adjust_focus(1);
                false
            }
            KeyCode::Char(' ')
                if matches!(
                    self.import_backup_form.selected_field(),
                    ImportBackupField::Overwrite
                ) =>
            {
                self.import_backup_form.overwrite = !self.import_backup_form.overwrite;
                false
            }
            KeyCode::Left | KeyCode::Right
                if matches!(
                    self.import_backup_form.selected_field(),
                    ImportBackupField::Overwrite
                ) =>
            {
                self.import_backup_form.overwrite = !self.import_backup_form.overwrite;
                false
            }
            KeyCode::Enter => {
                match self.import_backup_form.selected_field() {
                    ImportBackupField::Overwrite => {
                        self.import_backup_form.overwrite = !self.import_backup_form.overwrite;
                    }
                    ImportBackupField::Save => self.submit_import_backup(),
                    ImportBackupField::Path => self.import_backup_form.adjust_focus(1),
                }
                false
            }
            _ => {
                edit_form_value(self.import_backup_form.selected_value_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_export_transfer_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Vault;
                self.status = "Canceled transfer export.".to_string();
                false
            }
            KeyCode::Up => {
                self.export_transfer_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.export_transfer_form.adjust_focus(1);
                false
            }
            KeyCode::Enter => {
                if matches!(
                    self.export_transfer_form.selected_field(),
                    ExportTransferField::Save
                ) {
                    self.submit_export_transfer();
                } else {
                    self.export_transfer_form.adjust_focus(1);
                }
                false
            }
            _ => {
                edit_form_value(self.export_transfer_form.selected_value_mut(), key);
                edit_form_value(self.export_transfer_form.selected_secret_mut(), key);
                false
            }
        }
    }

    pub(crate) fn handle_import_transfer_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.screen = Screen::Vault;
                self.status = "Canceled transfer import.".to_string();
                false
            }
            KeyCode::Up => {
                self.import_transfer_form.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.import_transfer_form.adjust_focus(1);
                false
            }
            KeyCode::Char(' ')
                if matches!(
                    self.import_transfer_form.selected_field(),
                    ImportTransferField::ReplaceExisting
                ) =>
            {
                self.import_transfer_form.replace_existing =
                    !self.import_transfer_form.replace_existing;
                false
            }
            KeyCode::Left | KeyCode::Right
                if matches!(
                    self.import_transfer_form.selected_field(),
                    ImportTransferField::ReplaceExisting
                ) =>
            {
                self.import_transfer_form.replace_existing =
                    !self.import_transfer_form.replace_existing;
                false
            }
            KeyCode::Enter => {
                match self.import_transfer_form.selected_field() {
                    ImportTransferField::ReplaceExisting => {
                        self.import_transfer_form.replace_existing =
                            !self.import_transfer_form.replace_existing;
                    }
                    ImportTransferField::Save => self.submit_import_transfer(),
                    _ => self.import_transfer_form.adjust_focus(1),
                }
                false
            }
            _ => {
                edit_form_value(self.import_transfer_form.selected_value_mut(), key);
                edit_form_value(self.import_transfer_form.selected_secret_mut(), key);
                false
            }
        }
    }

    /// S7 (ia.md §5): `⏎` from H (the vault list) opens one selected item on
    /// its own screen, masked by default (P8.V.1/P8.V.2). No-ops with a
    /// status message when nothing is selected, mirroring the other
    /// item-scoped `open_*` guards (`open_edit_item`, `open_delete_confirm`).
    pub(crate) fn open_item_detail(&mut self) {
        if self.detail.is_none() {
            self.status = "No vault item selected to open.".to_string();
            return;
        }
        self.secret_revealed = false;
        self.screen = Screen::ItemDetail;
        self.status =
            "Item opened. The secret stays masked until you choose to reveal it.".to_string();
    }

    /// `⎋` back from S7 to H. Re-masks unconditionally (ia.md §5 "re-masks
    /// on leave") — a persona who reveals, then backs out, then re-opens the
    /// same item is shown the mask again, never a sticky reveal.
    pub(crate) fn leave_item_detail(&mut self) {
        self.secret_revealed = false;
        self.screen = Screen::Vault;
        self.status = "Returned to the vault item view.".to_string();
    }

    /// S7 `r reveal` toggle (ia.md §5, P8.V.1). Toggling back to masked is
    /// always available from the same key — the action is a toggle, not a
    /// one-way reveal.
    pub(crate) fn toggle_secret_reveal(&mut self) {
        self.secret_revealed = !self.secret_revealed;
        self.status = if self.secret_revealed {
            "Revealed. Press r again, or leave this item, to mask it.".to_string()
        } else {
            "Masked again.".to_string()
        };
    }

    pub(crate) fn open_add_login(&mut self) {
        self.add_login_form = AddLoginForm::default();
        self.editing_item_id = None;
        if let Some(VaultItemPayload::Login(login)) = self.detail.as_ref().map(|item| &item.payload)
        {
            self.add_login_form.title = login.title.clone();
            self.add_login_form.username = login.username.clone();
            self.add_login_form.url = login.url.clone().unwrap_or_default();
            self.add_login_form.notes = login.notes.clone().unwrap_or_default();
            self.add_login_form.folder = login.folder.clone().unwrap_or_default();
            self.add_login_form.tags = login.tags.join(", ");
        }
        self.screen = Screen::AddLogin;
        self.status =
            "Fill the login fields, then save the item into the encrypted vault.".to_string();
    }

    pub(crate) fn open_keyslots(&mut self) {
        self.pending_keyslot_removal_confirmation = None;
        self.screen = Screen::Keyslots;
        self.status =
            "Keyslot view active. Inspect access slots or enroll a new mnemonic, device, or certificate slot."
                .to_string();
    }

    pub(crate) fn sync_device_fallback_target(&mut self, preferred_slot_id: Option<&str>) {
        if !matches!(self.options.auth, VaultAuth::PasswordEnv(_)) {
            return;
        }
        let device_slot_ids = self
            .header
            .as_ref()
            .map(|header| {
                header
                    .keyslots
                    .iter()
                    .filter(|slot| slot.kind == paranoid_vault::VaultKeyslotKind::DeviceBound)
                    .map(|slot| slot.id.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if let Some(slot_id) = preferred_slot_id
            && device_slot_ids.iter().any(|candidate| candidate == slot_id)
        {
            self.options.device_slot = Some(slot_id.to_string());
            self.options.use_device_auto = false;
            return;
        }

        match device_slot_ids.as_slice() {
            [slot_id] => {
                self.options.device_slot = Some(slot_id.clone());
                self.options.use_device_auto = false;
            }
            _ => {
                self.options.device_slot = None;
                self.options.use_device_auto = false;
            }
        }
    }

    pub(crate) fn sync_rotated_mnemonic_unlock(&mut self, enrollment: &MnemonicRecoveryEnrollment) {
        if self.options.mnemonic_phrase.is_some() || self.options.mnemonic_phrase_env.is_some() {
            self.options.mnemonic_phrase = Some(enrollment.mnemonic.clone());
            self.options.mnemonic_phrase_env = None;
            self.options.mnemonic_slot = Some(enrollment.keyslot.id.clone());
        }
    }

    pub(crate) fn sync_rewrapped_certificate_unlock(
        &mut self,
        replaced_slot: &paranoid_vault::VaultKeyslot,
        replacement_cert_path: &str,
        replacement_key_path: Option<&str>,
        replacement_key_passphrase: Option<&SecretString>,
    ) {
        let (active_cert_path, active_key_path, active_key_passphrase_env, active_key_passphrase) =
            match &self.options.auth {
                VaultAuth::Certificate {
                    cert_path,
                    key_path,
                    key_passphrase_env,
                    key_passphrase,
                } => (
                    cert_path.clone(),
                    key_path.clone(),
                    key_passphrase_env.clone(),
                    key_passphrase.clone(),
                ),
                _ => return,
            };

        let active_matches_selected = fs::read(&active_cert_path)
            .ok()
            .and_then(|pem| inspect_certificate_pem(pem.as_slice()).ok())
            .and_then(|preview| {
                replaced_slot
                    .certificate_fingerprint_sha256
                    .as_ref()
                    .map(|fingerprint| preview.fingerprint_sha256 == *fingerprint)
            })
            .unwrap_or_else(|| {
                self.header
                    .as_ref()
                    .map(|header| {
                        header
                            .keyslots
                            .iter()
                            .filter(|slot| {
                                slot.kind == paranoid_vault::VaultKeyslotKind::CertificateWrapped
                            })
                            .count()
                            == 1
                    })
                    .unwrap_or(false)
            });
        if !active_matches_selected {
            return;
        }

        self.options.auth = VaultAuth::Certificate {
            cert_path: replacement_cert_path.trim().into(),
            key_path: replacement_key_path
                .map(|path| path.trim().into())
                .unwrap_or(active_key_path),
            key_passphrase_env: match replacement_key_passphrase {
                Some(_) => None,
                None => active_key_passphrase_env,
            },
            key_passphrase: match replacement_key_passphrase {
                Some(passphrase) => Some(passphrase.clone()),
                None => active_key_passphrase,
            },
        };
    }

    pub(crate) fn open_add_note(&mut self) {
        self.note_form = NoteForm::default();
        self.editing_item_id = None;
        if let Some(VaultItemPayload::SecureNote(note)) =
            self.detail.as_ref().map(|item| &item.payload)
        {
            self.note_form.title = note.title.clone();
            self.note_form.content = note.content.as_str().to_string();
            self.note_form.folder = note.folder.clone().unwrap_or_default();
            self.note_form.tags = note.tags.join(", ");
        }
        self.screen = Screen::AddNote;
        self.status = "Fill the secure note fields, then save the encrypted record.".to_string();
    }

    pub(crate) fn open_add_card(&mut self) {
        self.card_form = CardForm::default();
        self.editing_item_id = None;
        if let Some(VaultItemPayload::Card(card)) = self.detail.as_ref().map(|item| &item.payload) {
            self.card_form.title = card.title.clone();
            self.card_form.cardholder_name = card.cardholder_name.clone();
            self.card_form.number = card.number.as_str().to_string();
            self.card_form.expiry_month = card.expiry_month.clone();
            self.card_form.expiry_year = card.expiry_year.clone();
            self.card_form.security_code = card.security_code.as_str().to_string();
            self.card_form.billing_zip = card.billing_zip.clone().unwrap_or_default();
            self.card_form.notes = card.notes.clone().unwrap_or_default();
            self.card_form.folder = card.folder.clone().unwrap_or_default();
            self.card_form.tags = card.tags.join(", ");
        }
        self.screen = Screen::AddCard;
        self.status = "Fill the card fields, then save the encrypted record.".to_string();
    }

    pub(crate) fn open_add_identity(&mut self) {
        self.identity_form = IdentityForm::default();
        self.editing_item_id = None;
        if let Some(VaultItemPayload::Identity(identity)) =
            self.detail.as_ref().map(|item| &item.payload)
        {
            self.identity_form.title = identity.title.clone();
            self.identity_form.full_name = identity.full_name.clone();
            self.identity_form.email = identity.email.clone().unwrap_or_default();
            self.identity_form.phone = identity.phone.clone().unwrap_or_default();
            self.identity_form.address = identity.address.clone().unwrap_or_default();
            self.identity_form.notes = identity.notes.clone().unwrap_or_default();
            self.identity_form.folder = identity.folder.clone().unwrap_or_default();
            self.identity_form.tags = identity.tags.join(", ");
        }
        self.screen = Screen::AddIdentity;
        self.status = "Fill the identity fields, then save the encrypted record.".to_string();
    }

    pub(crate) fn open_add_mnemonic_slot(&mut self) {
        self.mnemonic_slot_form = LabelOnlyForm::default();
        self.screen = Screen::AddMnemonicSlot;
        self.status =
            "Enroll a new mnemonic recovery slot. The phrase will be shown once after saving."
                .to_string();
    }

    pub(crate) fn open_add_device_slot(&mut self) {
        self.device_slot_form = LabelOnlyForm::default();
        self.screen = Screen::AddDeviceSlot;
        self.status = "Enroll a new passwordless device-bound keyslot in platform secure storage."
            .to_string();
    }

    pub(crate) fn open_add_certificate_slot(&mut self) {
        self.certificate_slot_form = CertificateSlotForm::default();
        self.screen = Screen::AddCertSlot;
        self.status =
            "Enroll a certificate-wrapped keyslot using a PEM recipient certificate on disk."
                .to_string();
    }

    pub(crate) fn open_rewrap_certificate_slot(&mut self) {
        let Some(slot) = selected_keyslot(self) else {
            self.status = "No keyslot selected to rewrap.".to_string();
            return;
        };
        if slot.kind != paranoid_vault::VaultKeyslotKind::CertificateWrapped {
            self.status = "Selected keyslot is not certificate-wrapped.".to_string();
            return;
        }
        self.certificate_rewrap_form = CertificateRewrapForm::default();
        if let VaultAuth::Certificate { key_path, .. } = &self.options.auth {
            self.certificate_rewrap_form.key_path = key_path.display().to_string();
        }
        self.screen = Screen::RewrapCertSlot;
        self.status =
            "Provide the replacement recipient certificate PEM. Replacement key path and passphrase are optional and only update the active native session."
                .to_string();
    }

    pub(crate) fn open_edit_keyslot_label(&mut self) {
        let Some(slot) = selected_keyslot(self) else {
            self.status = "No keyslot selected to relabel.".to_string();
            return;
        };
        self.keyslot_label_form = LabelOnlyForm {
            focus_index: 0,
            label: slot.label.clone().unwrap_or_default(),
        };
        self.screen = Screen::EditKeyslotLabel;
        self.status =
            "Update the selected keyslot label without changing any recovery or unlock material."
                .to_string();
    }

    pub(crate) fn open_rotate_mnemonic_slot(&mut self) {
        let Some(slot) = selected_keyslot(self) else {
            self.status = "No keyslot selected to rotate.".to_string();
            return;
        };
        if slot.kind != paranoid_vault::VaultKeyslotKind::MnemonicRecovery {
            self.status = "Selected keyslot is not mnemonic recovery.".to_string();
            return;
        }
        self.screen = Screen::RotateMnemonicSlot;
        self.status = "Rotate the selected mnemonic recovery slot in place. The replacement phrase will be shown once after confirmation.".to_string();
    }

    pub(crate) fn open_rotate_recovery_secret(&mut self) {
        self.recovery_secret_form = RecoverySecretForm::default();
        self.screen = Screen::RotateRecoverySecret;
        self.status = "Rotate the password recovery secret without changing existing mnemonic, device, or certificate keyslots.".to_string();
    }

    pub(crate) fn open_edit_item(&mut self) {
        let Some(detail) = &self.detail else {
            self.status = "No vault item selected to edit.".to_string();
            return;
        };
        match &detail.payload {
            VaultItemPayload::Login(login) => {
                self.add_login_form = AddLoginForm {
                    focus_index: 0,
                    title: login.title.clone(),
                    username: login.username.clone(),
                    password: login.password.as_str().to_string(),
                    url: login.url.clone().unwrap_or_default(),
                    notes: login.notes.clone().unwrap_or_default(),
                    folder: login.folder.clone().unwrap_or_default(),
                    tags: login.tags.join(", "),
                };
                self.editing_item_id = Some(detail.id.clone());
                self.screen = Screen::EditLogin;
                self.status =
                    "Edit the selected login, then save the updated encrypted record.".to_string();
            }
            VaultItemPayload::SecureNote(note) => {
                self.note_form = NoteForm {
                    focus_index: 0,
                    title: note.title.clone(),
                    content: note.content.as_str().to_string(),
                    folder: note.folder.clone().unwrap_or_default(),
                    tags: note.tags.join(", "),
                };
                self.editing_item_id = Some(detail.id.clone());
                self.screen = Screen::EditNote;
                self.status =
                    "Edit the selected secure note, then save the updated encrypted record."
                        .to_string();
            }
            VaultItemPayload::Card(card) => {
                self.card_form = CardForm {
                    focus_index: 0,
                    title: card.title.clone(),
                    cardholder_name: card.cardholder_name.clone(),
                    number: card.number.as_str().to_string(),
                    expiry_month: card.expiry_month.clone(),
                    expiry_year: card.expiry_year.clone(),
                    security_code: card.security_code.as_str().to_string(),
                    billing_zip: card.billing_zip.clone().unwrap_or_default(),
                    notes: card.notes.clone().unwrap_or_default(),
                    folder: card.folder.clone().unwrap_or_default(),
                    tags: card.tags.join(", "),
                };
                self.editing_item_id = Some(detail.id.clone());
                self.screen = Screen::EditCard;
                self.status =
                    "Edit the selected card, then save the updated encrypted record.".to_string();
            }
            VaultItemPayload::Identity(identity) => {
                self.identity_form = IdentityForm {
                    focus_index: 0,
                    title: identity.title.clone(),
                    full_name: identity.full_name.clone(),
                    email: identity.email.clone().unwrap_or_default(),
                    phone: identity.phone.clone().unwrap_or_default(),
                    address: identity.address.clone().unwrap_or_default(),
                    notes: identity.notes.clone().unwrap_or_default(),
                    folder: identity.folder.clone().unwrap_or_default(),
                    tags: identity.tags.join(", "),
                };
                self.editing_item_id = Some(detail.id.clone());
                self.screen = Screen::EditIdentity;
                self.status = "Edit the selected identity, then save the updated encrypted record."
                    .to_string();
            }
        }
    }

    pub(crate) fn open_generate_store(&mut self) {
        self.generate_store_form = GenerateStoreForm::default();
        if let Some(VaultItemPayload::Login(login)) = self.detail.as_ref().map(|item| &item.payload)
        {
            self.generate_store_form.target_login_id =
                self.detail.as_ref().map(|item| item.id.clone());
            self.generate_store_form.title = login.title.clone();
            self.generate_store_form.username = login.username.clone();
            self.generate_store_form.url = login.url.clone().unwrap_or_default();
            self.generate_store_form.notes = login.notes.clone().unwrap_or_default();
            self.generate_store_form.folder = login.folder.clone().unwrap_or_default();
            self.generate_store_form.tags = login.tags.join(", ");
        }
        self.screen = Screen::GenerateStore;
        self.status = if self.generate_store_form.target_login_id.is_some() {
            "Configure one generated password, then rotate the selected login in place.".to_string()
        } else {
            "Configure one generated password, then store it as a vault login item.".to_string()
        };
    }

    pub(crate) fn open_export_backup(&mut self) {
        self.export_backup_form = ExportBackupForm {
            focus_index: 0,
            path: default_backup_export_path(&self.options.path),
        };
        self.screen = Screen::ExportBackup;
        self.export_backup_preview = Some(
            match self
                .unlock_for_operation("read_item", VaultOperationAccess::Decrypt)
                .and_then(|vault| vault.backup_summary().map_err(anyhow::Error::from))
            {
                Ok(summary) => {
                    self.status =
                        "Export the current encrypted vault state into a portable JSON backup package."
                            .to_string();
                    BackupSummaryPreview::Available(summary)
                }
                Err(error) => {
                    self.status = format!("Backup preview unavailable: {error}");
                    BackupSummaryPreview::Unavailable(error.to_string())
                }
            },
        );
    }

    pub(crate) fn open_export_transfer(&mut self) {
        self.export_transfer_form = ExportTransferForm {
            focus_index: 0,
            path: default_transfer_export_path(&self.options.path),
            package_password: SecretString::default(),
            cert_path: String::new(),
        };
        self.screen = Screen::ExportTransfer;
        self.status =
            "Export the currently filtered vault items into an encrypted transfer package."
                .to_string();
    }

    pub(crate) fn open_import_backup(&mut self) {
        self.import_backup_form = ImportBackupForm {
            focus_index: 0,
            path: default_backup_export_path(&self.options.path),
            overwrite: false,
        };
        self.screen = Screen::ImportBackup;
        self.status =
            "Import a JSON backup package into the current vault path. Overwrite replaces the local file."
                .to_string();
    }

    pub(crate) fn open_import_transfer(&mut self) {
        self.import_transfer_form = ImportTransferForm {
            focus_index: 0,
            path: default_transfer_export_path(&self.options.path),
            replace_existing: false,
            package_password: SecretString::default(),
            cert_path: String::new(),
            key_path: String::new(),
            key_passphrase: SecretString::default(),
        };
        self.screen = Screen::ImportTransfer;
        self.status =
            "Import an encrypted transfer package into the unlocked local vault. Choose either the package recovery secret or certificate keypair."
                .to_string();
    }

    /// Severe-tier confirm (ia.md §7): deleting an item requires typing the
    /// item's own title, not a bare `y/N` — "make it hard to confirm by
    /// accident."
    pub(crate) fn open_delete_confirm(&mut self) {
        if self.detail.is_none() {
            self.status = "No vault item selected to delete.".to_string();
            return;
        }
        let name = self
            .items
            .get(self.selected_index)
            .map(|item| item.title.clone())
            .unwrap_or_default();
        self.confirm_target_name = name.clone();
        self.confirm_input.clear();
        self.screen = Screen::DeleteConfirm;
        self.status = format!(
            "This deletes {name} for good. Type its name to confirm, or press Esc to cancel."
        );
    }

    pub(crate) fn handle_delete_confirm_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
            KeyCode::Esc => {
                self.confirm_input.clear();
                self.screen = Screen::Vault;
                self.status = "Canceled delete. Nothing was removed.".to_string();
                false
            }
            KeyCode::Enter => {
                if self.confirm_input == self.confirm_target_name {
                    self.delete_selected_item();
                } else {
                    self.status = format!(
                        "That doesn't match. Type \"{}\" exactly to confirm, or Esc to cancel.",
                        self.confirm_target_name
                    );
                }
                false
            }
            _ => {
                edit_form_value(Some(&mut self.confirm_input), key);
                false
            }
        }
    }

    /// Severe-tier confirm (ia.md §7): removing a way in requires typing its
    /// label, not a bare `y/N` — removing a way in can lock the owner out.
    pub(crate) fn open_remove_way_in_confirm(&mut self) {
        let Some(slot) = selected_keyslot(self) else {
            self.status = "No way in selected to remove.".to_string();
            return;
        };
        let name = slot.label.clone().unwrap_or_else(|| slot.id.clone());
        self.confirm_target_name = name.clone();
        self.confirm_input.clear();
        self.pending_keyslot_removal_confirmation = None;
        self.screen = Screen::RemoveWayInConfirm;
        self.status = format!(
            "Removing {name} means it can no longer open this vault. Type its name to confirm, or press Esc to cancel."
        );
    }

    pub(crate) fn handle_remove_way_in_confirm_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
            KeyCode::Esc => {
                self.confirm_input.clear();
                self.screen = Screen::Keyslots;
                self.status = "Canceled. That way in was not removed.".to_string();
                false
            }
            KeyCode::Enter => {
                if self.confirm_input == self.confirm_target_name {
                    // Typing the exact name IS the explicit confirmation
                    // `remove_selected_keyslot`'s domain-level guard asks
                    // for (its own "press d again" is the bare-keypress
                    // form of the same gate this typed-name screen already
                    // satisfies more strongly) — drive it to completion in
                    // one step rather than making the persona type the name
                    // twice.
                    self.remove_selected_keyslot();
                    self.remove_selected_keyslot();
                    self.confirm_input.clear();
                } else {
                    self.status = format!(
                        "That doesn't match. Type \"{}\" exactly to confirm, or Esc to cancel.",
                        self.confirm_target_name
                    );
                }
                false
            }
            _ => {
                edit_form_value(Some(&mut self.confirm_input), key);
                false
            }
        }
    }
}

/// Where the S1 trust-gate "verified on this machine" marker lives (ia.md
/// §3 short-circuit): `PARANOID_PASSWD_STATE_DIR` (a directory the operator
/// deliberately opts into, e.g. `~/.local/state/paranoid-passwd`) or the
/// test-only `PARANOID_TEST_TRUST_MARKER_DIR` override (matching the
/// existing `PARANOID_TEST_DEVICE_STORE_DIR` test-isolation pattern in
/// `paranoid-vault`).
///
/// SAFETY-CRITICAL: deliberately NO `$HOME`-guessing fallback in ANY build.
/// `#[cfg(test)]` only guards the lib crate's own unit tests — it does NOT
/// cover `tests/tui_scripted.rs`, which links this crate as an ordinary
/// (non-test-cfg) dependency, so a `$HOME` fallback here previously wrote a
/// real file into the invoking developer's actual home directory the moment
/// *any* integration test (or a bare `cargo test` run outside
/// `scripts/cargo_test.sh`) exercised `submit_trust_gate`. Until this reads
/// from a properly plumbed, explicitly-configured state directory (a
/// deliberate follow-on, not a guess), `None` here means the ia.md §3
/// short-circuit simply never fires — the S1 body always shows unchecked,
/// which is honest (brand.md §3 rule 4) rather than unsafe.
fn trust_marker_path() -> Option<PathBuf> {
    let dir = std::env::var_os("PARANOID_TEST_TRUST_MARKER_DIR")
        .or_else(|| std::env::var_os("PARANOID_PASSWD_STATE_DIR"))?;
    Some(PathBuf::from(dir).join("trust-verified"))
}

fn trust_marker_exists() -> bool {
    trust_marker_path().is_some_and(|path| path.is_file())
}

/// Best-effort: a marker write that fails (read-only home, sandboxed
/// filesystem) never blocks S3's "Continue" — the trust gate itself does
/// not depend on this succeeding, only next session's short-circuit does.
fn write_trust_marker() {
    if let Some(path) = trust_marker_path() {
        let _ = fs::write(&path, b"verified\n");
    }
}
