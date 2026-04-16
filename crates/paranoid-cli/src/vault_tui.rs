use anyhow::Context;
use arboard::Clipboard;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use paranoid_core::{FrameworkId, ParanoidRequest};
use paranoid_vault::{
    GenerateStoreLoginRecord, MnemonicRecoveryEnrollment, NativeSessionHardening, NewCardRecord,
    NewIdentityRecord, NewLoginRecord, NewSecureNoteRecord, SecretString, UpdateCardRecord,
    UpdateIdentityRecord, UpdateSecureNoteRecord, VaultAuth, VaultBackupSummary, VaultHeader,
    VaultItem, VaultItemFilter, VaultItemKind, VaultItemPayload, VaultItemSummary,
    VaultOpenOptions, VaultTransferSummary, inspect_certificate_pem, inspect_vault_backup,
    inspect_vault_transfer, read_vault_header, restore_vault_backup, unlock_vault_for_options,
};
#[cfg(test)]
use ratatui::backend::TestBackend;
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};
use std::{fs, io};

const BG: Color = Color::Rgb(8, 12, 20);
const PANEL: Color = Color::Rgb(13, 17, 25);
const TEXT: Color = Color::Rgb(228, 231, 242);
const GREEN: Color = Color::Rgb(52, 211, 153);
const BLUE: Color = Color::Rgb(96, 165, 250);
const AMBER: Color = Color::Rgb(251, 191, 36);
const RED: Color = Color::Rgb(248, 113, 113);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Vault,
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
    DeleteConfirm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VaultFilterField {
    Query,
    Kind,
    Folder,
    Tag,
}

impl VaultFilterField {
    const ALL: [Self; 4] = [Self::Query, Self::Kind, Self::Folder, Self::Tag];

    fn label(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Kind => "kind",
            Self::Folder => "folder",
            Self::Tag => "tag",
        }
    }
}

#[derive(Debug, Clone)]
struct VaultFilterState {
    query: String,
    kind: Option<VaultItemKind>,
    folder: String,
    tag: String,
    field: VaultFilterField,
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
    fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.field {
            VaultFilterField::Query => Some(&mut self.query),
            VaultFilterField::Kind => None,
            VaultFilterField::Folder => Some(&mut self.folder),
            VaultFilterField::Tag => Some(&mut self.tag),
        }
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = VaultFilterField::ALL.len();
        let current = VaultFilterField::ALL
            .iter()
            .position(|field| *field == self.field)
            .unwrap_or(0);
        let next = (current as isize + delta).rem_euclid(len as isize) as usize;
        self.field = VaultFilterField::ALL[next];
    }

    fn cycle_kind(&mut self, delta: isize) {
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

    fn clear_selected_field(&mut self) {
        match self.field {
            VaultFilterField::Query => self.query.clear(),
            VaultFilterField::Kind => self.kind = None,
            VaultFilterField::Folder => self.folder.clear(),
            VaultFilterField::Tag => self.tag.clear(),
        }
    }

    fn is_active(&self) -> bool {
        !self.query.trim().is_empty()
            || self.kind.is_some()
            || !self.folder.trim().is_empty()
            || !self.tag.trim().is_empty()
    }

    fn kind_label(&self) -> &'static str {
        self.kind
            .as_ref()
            .map(VaultItemKind::as_str)
            .unwrap_or("all")
    }

    fn summary(&self) -> String {
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

    fn selected_field_summary(&self) -> String {
        match self.field {
            VaultFilterField::Query => self.query.clone(),
            VaultFilterField::Kind => self.kind_label().to_string(),
            VaultFilterField::Folder => self.folder.clone(),
            VaultFilterField::Tag => self.tag.clone(),
        }
    }

    fn as_filter(&self) -> VaultItemFilter {
        VaultItemFilter {
            query: normalize_optional_field(&self.query),
            kind: self.kind.clone(),
            folder: normalize_optional_field(&self.folder),
            tag: normalize_optional_field(&self.tag),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddLoginField {
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
enum NoteField {
    Title,
    Content,
    Folder,
    Tags,
    Save,
}

impl NoteField {
    const ALL: [Self; 5] = [
        Self::Title,
        Self::Content,
        Self::Folder,
        Self::Tags,
        Self::Save,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CardField {
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
    const ALL: [Self; 11] = [
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
enum IdentityField {
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
    const ALL: [Self; 9] = [
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
    const ALL: [Self; 8] = [
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
enum GenerateField {
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
enum LabelOnlyField {
    Label,
    Save,
}

impl LabelOnlyField {
    const ALL: [Self; 2] = [Self::Label, Self::Save];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateField {
    Label,
    CertPath,
    Save,
}

impl CertificateField {
    const ALL: [Self; 3] = [Self::Label, Self::CertPath, Self::Save];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateRewrapField {
    CertPath,
    KeyPath,
    KeyPassphrase,
    Save,
}

impl CertificateRewrapField {
    const ALL: [Self; 4] = [
        Self::CertPath,
        Self::KeyPath,
        Self::KeyPassphrase,
        Self::Save,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoverySecretField {
    NewSecret,
    Confirm,
    Save,
}

impl RecoverySecretField {
    const ALL: [Self; 3] = [Self::NewSecret, Self::Confirm, Self::Save];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnlockMode {
    Password,
    Mnemonic,
    Device,
    Certificate,
}

impl UnlockMode {
    fn label(self) -> &'static str {
        match self {
            Self::Password => "Recovery Secret",
            Self::Mnemonic => "Mnemonic",
            Self::Device => "Device Slot",
            Self::Certificate => "Certificate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnlockField {
    Mode,
    Primary,
    Secondary,
    Tertiary,
    Submit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportBackupField {
    Path,
    Save,
}

impl ExportBackupField {
    const ALL: [Self; 2] = [Self::Path, Self::Save];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportBackupField {
    Path,
    Overwrite,
    Save,
}

impl ImportBackupField {
    const ALL: [Self; 3] = [Self::Path, Self::Overwrite, Self::Save];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportTransferField {
    Path,
    PackagePassword,
    CertPath,
    Save,
}

impl ExportTransferField {
    const ALL: [Self; 4] = [
        Self::Path,
        Self::PackagePassword,
        Self::CertPath,
        Self::Save,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportTransferField {
    Path,
    ReplaceExisting,
    PackagePassword,
    CertPath,
    KeyPath,
    KeyPassphrase,
    Save,
}

impl ImportTransferField {
    const ALL: [Self; 7] = [
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
    const ALL: [Self; 13] = [
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
struct AddLoginForm {
    focus_index: usize,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    folder: String,
    tags: String,
}

#[derive(Debug, Clone, Default)]
struct NoteForm {
    focus_index: usize,
    title: String,
    content: String,
    folder: String,
    tags: String,
}

#[derive(Debug, Clone, Default)]
struct CardForm {
    focus_index: usize,
    title: String,
    cardholder_name: String,
    number: String,
    expiry_month: String,
    expiry_year: String,
    security_code: String,
    billing_zip: String,
    notes: String,
    folder: String,
    tags: String,
}

#[derive(Debug, Clone, Default)]
struct IdentityForm {
    focus_index: usize,
    title: String,
    full_name: String,
    email: String,
    phone: String,
    address: String,
    notes: String,
    folder: String,
    tags: String,
}

impl NoteForm {
    fn selected_field(&self) -> NoteField {
        NoteField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(NoteField::Title)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = NoteField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
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
    fn selected_field(&self) -> CardField {
        CardField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(CardField::Title)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = CardField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
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
    fn selected_field(&self) -> IdentityField {
        IdentityField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(IdentityField::Title)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = IdentityField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
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
    fn selected_field(&self) -> AddLoginField {
        AddLoginField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(AddLoginField::Title)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = AddLoginField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
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
struct GenerateStoreForm {
    target_login_id: Option<String>,
    focus_index: usize,
    title: String,
    username: String,
    url: String,
    notes: String,
    folder: String,
    tags: String,
    length: String,
    frameworks: String,
    min_lower: String,
    min_upper: String,
    min_digits: String,
    min_symbols: String,
}

#[derive(Debug, Clone, Default)]
struct LabelOnlyForm {
    focus_index: usize,
    label: String,
}

impl LabelOnlyForm {
    fn selected_field(&self) -> LabelOnlyField {
        LabelOnlyField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(LabelOnlyField::Label)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = LabelOnlyField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            LabelOnlyField::Label => Some(&mut self.label),
            LabelOnlyField::Save => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CertificateRewrapForm {
    focus_index: usize,
    cert_path: String,
    key_path: String,
    key_passphrase: String,
}

impl CertificateRewrapForm {
    fn selected_field(&self) -> CertificateRewrapField {
        CertificateRewrapField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(CertificateRewrapField::CertPath)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = CertificateRewrapField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            CertificateRewrapField::CertPath => Some(&mut self.cert_path),
            CertificateRewrapField::KeyPath => Some(&mut self.key_path),
            CertificateRewrapField::KeyPassphrase => Some(&mut self.key_passphrase),
            CertificateRewrapField::Save => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CertificateSlotForm {
    focus_index: usize,
    label: String,
    cert_path: String,
}

#[derive(Debug, Clone, Default)]
struct RecoverySecretForm {
    focus_index: usize,
    new_secret: String,
    confirm_secret: String,
}

#[derive(Debug, Clone)]
struct UnlockForm {
    focus_index: usize,
    mode: UnlockMode,
    password: String,
    mnemonic_phrase: String,
    mnemonic_slot: String,
    device_slot: String,
    cert_path: String,
    key_path: String,
    key_passphrase: String,
}

#[derive(Debug, Clone, Default)]
struct ExportBackupForm {
    focus_index: usize,
    path: String,
}

#[derive(Debug, Clone, Default)]
struct ImportBackupForm {
    focus_index: usize,
    path: String,
    overwrite: bool,
}

#[derive(Debug, Clone, Default)]
struct ExportTransferForm {
    focus_index: usize,
    path: String,
    package_password: String,
    cert_path: String,
}

#[derive(Debug, Clone, Default)]
struct ImportTransferForm {
    focus_index: usize,
    path: String,
    replace_existing: bool,
    package_password: String,
    cert_path: String,
    key_path: String,
    key_passphrase: String,
}

impl Default for UnlockForm {
    fn default() -> Self {
        Self {
            focus_index: 0,
            mode: UnlockMode::Password,
            password: String::new(),
            mnemonic_phrase: String::new(),
            mnemonic_slot: String::new(),
            device_slot: String::new(),
            cert_path: String::new(),
            key_path: String::new(),
            key_passphrase: String::new(),
        }
    }
}

impl ExportBackupForm {
    fn selected_field(&self) -> ExportBackupField {
        ExportBackupField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(ExportBackupField::Path)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = ExportBackupField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            ExportBackupField::Path => Some(&mut self.path),
            ExportBackupField::Save => None,
        }
    }
}

impl ImportBackupForm {
    fn selected_field(&self) -> ImportBackupField {
        ImportBackupField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(ImportBackupField::Path)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = ImportBackupField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            ImportBackupField::Path => Some(&mut self.path),
            ImportBackupField::Overwrite | ImportBackupField::Save => None,
        }
    }
}

impl ExportTransferForm {
    fn selected_field(&self) -> ExportTransferField {
        ExportTransferField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(ExportTransferField::Path)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = ExportTransferField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            ExportTransferField::Path => Some(&mut self.path),
            ExportTransferField::PackagePassword => Some(&mut self.package_password),
            ExportTransferField::CertPath => Some(&mut self.cert_path),
            ExportTransferField::Save => None,
        }
    }
}

impl ImportTransferForm {
    fn selected_field(&self) -> ImportTransferField {
        ImportTransferField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(ImportTransferField::Path)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = ImportTransferField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            ImportTransferField::Path => Some(&mut self.path),
            ImportTransferField::PackagePassword => Some(&mut self.package_password),
            ImportTransferField::CertPath => Some(&mut self.cert_path),
            ImportTransferField::KeyPath => Some(&mut self.key_path),
            ImportTransferField::KeyPassphrase => Some(&mut self.key_passphrase),
            ImportTransferField::ReplaceExisting | ImportTransferField::Save => None,
        }
    }
}

impl CertificateSlotForm {
    fn selected_field(&self) -> CertificateField {
        CertificateField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(CertificateField::Label)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = CertificateField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            CertificateField::Label => Some(&mut self.label),
            CertificateField::CertPath => Some(&mut self.cert_path),
            CertificateField::Save => None,
        }
    }
}

impl RecoverySecretForm {
    fn selected_field(&self) -> RecoverySecretField {
        RecoverySecretField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(RecoverySecretField::NewSecret)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = RecoverySecretField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
        match self.selected_field() {
            RecoverySecretField::NewSecret => Some(&mut self.new_secret),
            RecoverySecretField::Confirm => Some(&mut self.confirm_secret),
            RecoverySecretField::Save => None,
        }
    }
}

impl UnlockForm {
    fn visible_fields(&self) -> &'static [UnlockField] {
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

    fn selected_field(&self) -> UnlockField {
        self.visible_fields()
            .get(self.focus_index)
            .copied()
            .unwrap_or(UnlockField::Mode)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = self.visible_fields().len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn cycle_mode(&mut self, delta: isize) {
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

    fn selected_value_mut(&mut self) -> Option<&mut String> {
        match (self.mode, self.selected_field()) {
            (UnlockMode::Password, UnlockField::Primary) => Some(&mut self.password),
            (UnlockMode::Mnemonic, UnlockField::Primary) => Some(&mut self.mnemonic_phrase),
            (UnlockMode::Mnemonic, UnlockField::Secondary) => Some(&mut self.mnemonic_slot),
            (UnlockMode::Device, UnlockField::Primary) => Some(&mut self.device_slot),
            (UnlockMode::Certificate, UnlockField::Primary) => Some(&mut self.cert_path),
            (UnlockMode::Certificate, UnlockField::Secondary) => Some(&mut self.key_path),
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
    fn selected_field(&self) -> GenerateField {
        GenerateField::ALL
            .get(self.focus_index)
            .copied()
            .unwrap_or(GenerateField::Title)
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = GenerateField::ALL.len() as isize;
        self.focus_index = (self.focus_index as isize + delta).clamp(0, len - 1) as usize;
    }

    fn selected_value_mut(&mut self) -> Option<&mut String> {
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
struct App {
    options: VaultOpenOptions,
    screen: Screen,
    status: String,
    header: Option<VaultHeader>,
    items: Vec<VaultItemSummary>,
    selected_index: usize,
    selected_keyslot_index: usize,
    detail: Option<VaultItem>,
    filters: VaultFilterState,
    search_mode: bool,
    unlock_form: UnlockForm,
    add_login_form: AddLoginForm,
    note_form: NoteForm,
    card_form: CardForm,
    identity_form: IdentityForm,
    mnemonic_slot_form: LabelOnlyForm,
    device_slot_form: LabelOnlyForm,
    certificate_slot_form: CertificateSlotForm,
    certificate_rewrap_form: CertificateRewrapForm,
    keyslot_label_form: LabelOnlyForm,
    recovery_secret_form: RecoverySecretForm,
    latest_mnemonic_enrollment: Option<MnemonicRecoveryEnrollment>,
    pending_keyslot_removal_confirmation: Option<String>,
    generate_store_form: GenerateStoreForm,
    export_backup_form: ExportBackupForm,
    export_transfer_form: ExportTransferForm,
    import_backup_form: ImportBackupForm,
    import_transfer_form: ImportTransferForm,
    editing_item_id: Option<String>,
    session: NativeSessionHardening,
}

impl App {
    fn new(options: VaultOpenOptions) -> Self {
        let mut app = Self {
            options,
            screen: Screen::UnlockBlocked,
            status: String::new(),
            header: None,
            items: Vec::new(),
            selected_index: 0,
            selected_keyslot_index: 0,
            detail: None,
            filters: VaultFilterState::default(),
            search_mode: false,
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
            export_transfer_form: ExportTransferForm::default(),
            import_backup_form: ImportBackupForm::default(),
            import_transfer_form: ImportTransferForm::default(),
            editing_item_id: None,
            session: NativeSessionHardening::default(),
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.pending_keyslot_removal_confirmation = None;
        self.header = read_vault_header(&self.options.path).ok();
        match self.reload_vault_state(None) {
            Ok(()) => {
                self.screen = Screen::Vault;
                self.status = format!(
                    "Vault unlocked. {} item(s) loaded via {}.",
                    self.items.len(),
                    self.options.unlock_description()
                );
            }
            Err(error) => {
                self.items.clear();
                self.detail = None;
                self.screen = Screen::UnlockBlocked;
                self.status = format!("Unlock blocked: {error}");
            }
        }
    }

    fn reload_vault_state(&mut self, preferred_id: Option<&str>) -> anyhow::Result<()> {
        let vault = unlock_vault_for_options(&self.options)?;
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

    fn submit_native_unlock(&mut self) {
        self.options.mnemonic_phrase_env = None;
        self.options.mnemonic_phrase = None;
        self.options.mnemonic_slot = None;
        self.options.device_slot = None;
        self.options.use_device_auto = false;
        self.options.auth = VaultAuth::PasswordEnv("PARANOID_MASTER_PASSWORD".to_string());

        match self.unlock_form.mode {
            UnlockMode::Password => {
                self.options.auth =
                    VaultAuth::Password(SecretString::new(self.unlock_form.password.clone()));
            }
            UnlockMode::Mnemonic => {
                self.options.mnemonic_phrase =
                    Some(SecretString::new(self.unlock_form.mnemonic_phrase.clone()));
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
                    key_passphrase: normalize_optional_field(&self.unlock_form.key_passphrase)
                        .map(SecretString::new),
                };
            }
        }

        self.refresh();
    }

    fn poll_hardening(&mut self) {
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

        if !matches!(self.screen, Screen::UnlockBlocked) && self.session.should_auto_lock() {
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
            self.latest_mnemonic_enrollment = None;
            self.screen = Screen::UnlockBlocked;
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

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self.screen {
            Screen::Vault | Screen::Keyslots => self.handle_vault_key(key),
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
        }
    }

    fn handle_unlock_blocked_key(&mut self, key: KeyEvent) -> bool {
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
                false
            }
        }
    }

    fn handle_vault_key(&mut self, key: KeyEvent) -> bool {
        if matches!(self.screen, Screen::Vault) && self.search_mode {
            return self.handle_search_key(key);
        }
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Char('r') if matches!(self.screen, Screen::Vault) => {
                self.refresh();
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
            KeyCode::Char('d') if matches!(self.screen, Screen::Keyslots) => {
                self.remove_selected_keyslot();
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

    fn handle_rotate_mnemonic_slot_key(&mut self, key: KeyEvent) -> bool {
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

    fn handle_search_key(&mut self, key: KeyEvent) -> bool {
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

    fn refresh_filter_preview(&mut self) {
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

    fn handle_add_login_key(&mut self, key: KeyEvent) -> bool {
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

    fn handle_note_key(&mut self, key: KeyEvent) -> bool {
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

    fn handle_card_key(&mut self, key: KeyEvent) -> bool {
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

    fn handle_identity_key(&mut self, key: KeyEvent) -> bool {
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

    fn handle_label_only_key(&mut self, key: KeyEvent) -> bool {
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

    fn handle_certificate_key(&mut self, key: KeyEvent) -> bool {
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

    fn handle_certificate_rewrap_key(&mut self, key: KeyEvent) -> bool {
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
                false
            }
        }
    }

    fn handle_recovery_secret_key(&mut self, key: KeyEvent) -> bool {
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
                edit_form_value(self.recovery_secret_form.selected_value_mut(), key);
                false
            }
        }
    }

    fn handle_mnemonic_reveal_key(&mut self, key: KeyEvent) -> bool {
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

    fn handle_delete_confirm_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc | KeyCode::Char('n') => {
                self.screen = Screen::Vault;
                self.status = "Canceled delete.".to_string();
                false
            }
            KeyCode::Enter | KeyCode::Char('y') => {
                self.delete_selected_item();
                false
            }
            _ => false,
        }
    }

    fn handle_generate_store_key(&mut self, key: KeyEvent) -> bool {
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

    fn handle_export_backup_key(&mut self, key: KeyEvent) -> bool {
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

    fn handle_import_backup_key(&mut self, key: KeyEvent) -> bool {
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

    fn handle_export_transfer_key(&mut self, key: KeyEvent) -> bool {
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
                false
            }
        }
    }

    fn handle_import_transfer_key(&mut self, key: KeyEvent) -> bool {
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
                false
            }
        }
    }

    fn open_add_login(&mut self) {
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

    fn open_keyslots(&mut self) {
        self.pending_keyslot_removal_confirmation = None;
        self.screen = Screen::Keyslots;
        self.status =
            "Keyslot view active. Inspect access slots or enroll a new mnemonic, device, or certificate slot."
                .to_string();
    }

    fn sync_device_fallback_target(&mut self, preferred_slot_id: Option<&str>) {
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

    fn sync_rotated_mnemonic_unlock(&mut self, enrollment: &MnemonicRecoveryEnrollment) {
        if self.options.mnemonic_phrase.is_some() || self.options.mnemonic_phrase_env.is_some() {
            self.options.mnemonic_phrase = Some(SecretString::new(enrollment.mnemonic.clone()));
            self.options.mnemonic_phrase_env = None;
            self.options.mnemonic_slot = Some(enrollment.keyslot.id.clone());
        }
    }

    fn sync_rewrapped_certificate_unlock(
        &mut self,
        replaced_slot: &paranoid_vault::VaultKeyslot,
        replacement_cert_path: &str,
        replacement_key_path: Option<&str>,
        replacement_key_passphrase: Option<&str>,
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
                Some(passphrase) => Some(SecretString::new(passphrase.to_string())),
                None => active_key_passphrase,
            },
        };
    }

    fn open_add_note(&mut self) {
        self.note_form = NoteForm::default();
        self.editing_item_id = None;
        if let Some(VaultItemPayload::SecureNote(note)) =
            self.detail.as_ref().map(|item| &item.payload)
        {
            self.note_form.title = note.title.clone();
            self.note_form.content = note.content.clone();
            self.note_form.folder = note.folder.clone().unwrap_or_default();
            self.note_form.tags = note.tags.join(", ");
        }
        self.screen = Screen::AddNote;
        self.status = "Fill the secure note fields, then save the encrypted record.".to_string();
    }

    fn open_add_card(&mut self) {
        self.card_form = CardForm::default();
        self.editing_item_id = None;
        if let Some(VaultItemPayload::Card(card)) = self.detail.as_ref().map(|item| &item.payload) {
            self.card_form.title = card.title.clone();
            self.card_form.cardholder_name = card.cardholder_name.clone();
            self.card_form.number = card.number.clone();
            self.card_form.expiry_month = card.expiry_month.clone();
            self.card_form.expiry_year = card.expiry_year.clone();
            self.card_form.security_code = card.security_code.clone();
            self.card_form.billing_zip = card.billing_zip.clone().unwrap_or_default();
            self.card_form.notes = card.notes.clone().unwrap_or_default();
            self.card_form.folder = card.folder.clone().unwrap_or_default();
            self.card_form.tags = card.tags.join(", ");
        }
        self.screen = Screen::AddCard;
        self.status = "Fill the card fields, then save the encrypted record.".to_string();
    }

    fn open_add_identity(&mut self) {
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

    fn open_add_mnemonic_slot(&mut self) {
        self.mnemonic_slot_form = LabelOnlyForm::default();
        self.screen = Screen::AddMnemonicSlot;
        self.status =
            "Enroll a new mnemonic recovery slot. The phrase will be shown once after saving."
                .to_string();
    }

    fn open_add_device_slot(&mut self) {
        self.device_slot_form = LabelOnlyForm::default();
        self.screen = Screen::AddDeviceSlot;
        self.status = "Enroll a new passwordless device-bound keyslot in platform secure storage."
            .to_string();
    }

    fn open_add_certificate_slot(&mut self) {
        self.certificate_slot_form = CertificateSlotForm::default();
        self.screen = Screen::AddCertSlot;
        self.status =
            "Enroll a certificate-wrapped keyslot using a PEM recipient certificate on disk."
                .to_string();
    }

    fn open_rewrap_certificate_slot(&mut self) {
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

    fn open_edit_keyslot_label(&mut self) {
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

    fn open_rotate_mnemonic_slot(&mut self) {
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

    fn open_rotate_recovery_secret(&mut self) {
        self.recovery_secret_form = RecoverySecretForm::default();
        self.screen = Screen::RotateRecoverySecret;
        self.status = "Rotate the password recovery secret without changing existing mnemonic, device, or certificate keyslots.".to_string();
    }

    fn open_edit_item(&mut self) {
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
                    password: login.password.clone(),
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
                    content: note.content.clone(),
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
                    number: card.number.clone(),
                    expiry_month: card.expiry_month.clone(),
                    expiry_year: card.expiry_year.clone(),
                    security_code: card.security_code.clone(),
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

    fn open_generate_store(&mut self) {
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

    fn open_export_backup(&mut self) {
        self.export_backup_form = ExportBackupForm {
            focus_index: 0,
            path: default_backup_export_path(&self.options.path),
        };
        self.screen = Screen::ExportBackup;
        self.status =
            "Export the current encrypted vault state into a portable JSON backup package."
                .to_string();
    }

    fn open_export_transfer(&mut self) {
        self.export_transfer_form = ExportTransferForm {
            focus_index: 0,
            path: default_transfer_export_path(&self.options.path),
            package_password: String::new(),
            cert_path: String::new(),
        };
        self.screen = Screen::ExportTransfer;
        self.status =
            "Export the currently filtered vault items into an encrypted transfer package."
                .to_string();
    }

    fn open_import_backup(&mut self) {
        self.import_backup_form = ImportBackupForm {
            focus_index: 0,
            path: default_backup_export_path(&self.options.path),
            overwrite: self.options.path.exists(),
        };
        self.screen = Screen::ImportBackup;
        self.status =
            "Import a JSON backup package into the current vault path. Overwrite replaces the local file."
                .to_string();
    }

    fn open_import_transfer(&mut self) {
        self.import_transfer_form = ImportTransferForm {
            focus_index: 0,
            path: default_transfer_export_path(&self.options.path),
            replace_existing: false,
            package_password: String::new(),
            cert_path: String::new(),
            key_path: String::new(),
            key_passphrase: String::new(),
        };
        self.screen = Screen::ImportTransfer;
        self.status =
            "Import an encrypted transfer package into the unlocked local vault. Choose either the package recovery secret or certificate keypair."
                .to_string();
    }

    fn open_delete_confirm(&mut self) {
        if self.detail.is_none() {
            self.status = "No vault item selected to delete.".to_string();
            return;
        }
        self.screen = Screen::DeleteConfirm;
        self.status =
            "Delete confirmation is active. Press y or Enter to remove the selected item."
                .to_string();
    }

    fn submit_login_form(&mut self) {
        let record = NewLoginRecord {
            title: self.add_login_form.title.trim().to_string(),
            username: self.add_login_form.username.trim().to_string(),
            password: self.add_login_form.password.clone(),
            url: normalize_optional_field(&self.add_login_form.url),
            notes: normalize_optional_field(&self.add_login_form.notes),
            folder: normalize_optional_field(&self.add_login_form.folder),
            tags: parse_tags_csv(&self.add_login_form.tags),
        };

        match self.editing_item_id.clone() {
            Some(item_id) => self.submit_login_update(item_id, record),
            None => self.submit_login_create(record),
        }
    }

    fn submit_note_form(&mut self) {
        let record = NewSecureNoteRecord {
            title: self.note_form.title.trim().to_string(),
            content: self.note_form.content.trim().to_string(),
            folder: normalize_optional_field(&self.note_form.folder),
            tags: parse_tags_csv(&self.note_form.tags),
        };

        match self.editing_item_id.clone() {
            Some(item_id) => self.submit_note_update(item_id, record),
            None => self.submit_note_create(record),
        }
    }

    fn submit_card_form(&mut self) {
        let record = NewCardRecord {
            title: self.card_form.title.trim().to_string(),
            cardholder_name: self.card_form.cardholder_name.trim().to_string(),
            number: self.card_form.number.trim().to_string(),
            expiry_month: self.card_form.expiry_month.trim().to_string(),
            expiry_year: self.card_form.expiry_year.trim().to_string(),
            security_code: self.card_form.security_code.trim().to_string(),
            billing_zip: normalize_optional_field(&self.card_form.billing_zip),
            notes: normalize_optional_field(&self.card_form.notes),
            folder: normalize_optional_field(&self.card_form.folder),
            tags: parse_tags_csv(&self.card_form.tags),
        };
        match self.editing_item_id.clone() {
            Some(item_id) => self.submit_card_update(item_id, record),
            None => self.submit_card_create(record),
        }
    }

    fn submit_identity_form(&mut self) {
        let record = NewIdentityRecord {
            title: self.identity_form.title.trim().to_string(),
            full_name: self.identity_form.full_name.trim().to_string(),
            email: normalize_optional_field(&self.identity_form.email),
            phone: normalize_optional_field(&self.identity_form.phone),
            address: normalize_optional_field(&self.identity_form.address),
            notes: normalize_optional_field(&self.identity_form.notes),
            folder: normalize_optional_field(&self.identity_form.folder),
            tags: parse_tags_csv(&self.identity_form.tags),
        };
        match self.editing_item_id.clone() {
            Some(item_id) => self.submit_identity_update(item_id, record),
            None => self.submit_identity_create(record),
        }
    }

    fn submit_login_create(&mut self, record: NewLoginRecord) {
        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault.add_login(record).map_err(anyhow::Error::from) {
                Ok(item) => {
                    let item_id = item.id.clone();
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Stored login item {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Stored login item {item_id} in the encrypted vault.");
                }
                Err(error) => {
                    self.status = format!("Store failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Store failed: {error}");
            }
        }
    }

    fn submit_login_update(&mut self, item_id: String, record: NewLoginRecord) {
        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault
                .update_login(
                    &item_id,
                    paranoid_vault::UpdateLoginRecord {
                        title: Some(record.title),
                        username: Some(record.username),
                        password: Some(record.password),
                        url: Some(record.url),
                        notes: Some(record.notes),
                        folder: Some(record.folder),
                        tags: Some(record.tags),
                    },
                )
                .map_err(anyhow::Error::from)
            {
                Ok(item) => {
                    let item_id = item.id.clone();
                    self.editing_item_id = None;
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Updated login item {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Updated login item {item_id} in the encrypted vault.");
                }
                Err(error) => {
                    self.status = format!("Update failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Update failed: {error}");
            }
        }
    }

    fn submit_note_create(&mut self, record: NewSecureNoteRecord) {
        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault.add_secure_note(record).map_err(anyhow::Error::from) {
                Ok(item) => {
                    let item_id = item.id.clone();
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Stored secure note {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Stored secure note {item_id} in the encrypted vault.");
                }
                Err(error) => {
                    self.status = format!("Store failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Store failed: {error}");
            }
        }
    }

    fn submit_note_update(&mut self, item_id: String, record: NewSecureNoteRecord) {
        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault
                .update_secure_note(
                    &item_id,
                    UpdateSecureNoteRecord {
                        title: Some(record.title),
                        content: Some(record.content),
                        folder: Some(record.folder),
                        tags: Some(record.tags),
                    },
                )
                .map_err(anyhow::Error::from)
            {
                Ok(item) => {
                    let item_id = item.id.clone();
                    self.editing_item_id = None;
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Updated secure note {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Updated secure note {item_id} in the encrypted vault.");
                }
                Err(error) => {
                    self.status = format!("Update failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Update failed: {error}");
            }
        }
    }

    fn submit_card_create(&mut self, record: NewCardRecord) {
        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault.add_card(record).map_err(anyhow::Error::from) {
                Ok(item) => {
                    let item_id = item.id.clone();
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status = format!("Stored card {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Stored card {item_id} in the encrypted vault.");
                }
                Err(error) => self.status = format!("Store failed: {error}"),
            },
            Err(error) => self.status = format!("Store failed: {error}"),
        }
    }

    fn submit_card_update(&mut self, item_id: String, record: NewCardRecord) {
        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault
                .update_card(
                    &item_id,
                    UpdateCardRecord {
                        title: Some(record.title),
                        cardholder_name: Some(record.cardholder_name),
                        number: Some(record.number),
                        expiry_month: Some(record.expiry_month),
                        expiry_year: Some(record.expiry_year),
                        security_code: Some(record.security_code),
                        billing_zip: Some(record.billing_zip),
                        notes: Some(record.notes),
                        folder: Some(record.folder),
                        tags: Some(record.tags),
                    },
                )
                .map_err(anyhow::Error::from)
            {
                Ok(item) => {
                    let item_id = item.id.clone();
                    self.editing_item_id = None;
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Updated card {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Updated card {item_id} in the encrypted vault.");
                }
                Err(error) => self.status = format!("Update failed: {error}"),
            },
            Err(error) => self.status = format!("Update failed: {error}"),
        }
    }

    fn submit_identity_create(&mut self, record: NewIdentityRecord) {
        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault.add_identity(record).map_err(anyhow::Error::from) {
                Ok(item) => {
                    let item_id = item.id.clone();
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Stored identity {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Stored identity {item_id} in the encrypted vault.");
                }
                Err(error) => self.status = format!("Store failed: {error}"),
            },
            Err(error) => self.status = format!("Store failed: {error}"),
        }
    }

    fn submit_identity_update(&mut self, item_id: String, record: NewIdentityRecord) {
        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault
                .update_identity(
                    &item_id,
                    UpdateIdentityRecord {
                        title: Some(record.title),
                        full_name: Some(record.full_name),
                        email: Some(record.email),
                        phone: Some(record.phone),
                        address: Some(record.address),
                        notes: Some(record.notes),
                        folder: Some(record.folder),
                        tags: Some(record.tags),
                    },
                )
                .map_err(anyhow::Error::from)
            {
                Ok(item) => {
                    let item_id = item.id.clone();
                    self.editing_item_id = None;
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Updated identity {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Updated identity {item_id} in the encrypted vault.");
                }
                Err(error) => self.status = format!("Update failed: {error}"),
            },
            Err(error) => self.status = format!("Update failed: {error}"),
        }
    }

    fn submit_generate_store(&mut self) {
        let request = match build_generate_request(&self.generate_store_form) {
            Ok(request) => request,
            Err(error) => {
                self.status = format!("Generation request blocked: {error}");
                return;
            }
        };
        let title = self.generate_store_form.title.trim();
        let username = self.generate_store_form.username.trim();
        if self.generate_store_form.target_login_id.is_none()
            && (title.is_empty() || username.is_empty())
        {
            self.status = "Generation store requires both a title and username.".to_string();
            return;
        }

        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault
                .generate_and_store(
                    &request,
                    GenerateStoreLoginRecord {
                        target_login_id: self.generate_store_form.target_login_id.clone(),
                        title: (!title.is_empty()).then(|| title.to_string()),
                        username: (!username.is_empty()).then(|| username.to_string()),
                        url: normalize_optional_field(&self.generate_store_form.url),
                        notes: normalize_optional_field(&self.generate_store_form.notes),
                        folder: normalize_optional_field(&self.generate_store_form.folder),
                        tags: Some(parse_tags_csv(&self.generate_store_form.tags)),
                    },
                )
                .map_err(anyhow::Error::from)
            {
                Ok((report, item)) => {
                    let verdict = report
                        .audit
                        .as_ref()
                        .map(|audit| if audit.overall_pass { "PASS" } else { "REVIEW" })
                        .unwrap_or("PASS");
                    let item_id = item.id.clone();
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status = format!(
                            "Generated and stored {item_id} ({verdict}), but refresh failed: {error}"
                        );
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!(
                        "Generated one password and {} item {item_id}. Generator verdict: {verdict}.",
                        if self.generate_store_form.target_login_id.is_some() {
                            "rotated"
                        } else {
                            "stored"
                        }
                    );
                }
                Err(error) => {
                    self.status = format!("Generate-and-store failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Generate-and-store failed: {error}");
            }
        }
    }

    fn submit_export_backup(&mut self) {
        let output = self.export_backup_form.path.trim();
        if output.is_empty() {
            self.status = "Backup export requires an output path.".to_string();
            return;
        }
        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault.export_backup(output).map_err(anyhow::Error::from) {
                Ok(path) => {
                    self.screen = Screen::Vault;
                    self.status = format!("Exported encrypted vault backup to {}.", path.display());
                }
                Err(error) => {
                    self.status = format!("Backup export failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Backup export failed: {error}");
            }
        }
    }

    fn submit_import_backup(&mut self) {
        let input = self.import_backup_form.path.trim();
        if input.is_empty() {
            self.status = "Backup import requires an input path.".to_string();
            return;
        }
        match restore_vault_backup(input, &self.options.path, self.import_backup_form.overwrite)
            .map_err(anyhow::Error::from)
        {
            Ok(_) => {
                let source = input.to_string();
                self.refresh();
                self.status = format!(
                    "Imported encrypted vault backup from {} into {}.",
                    source,
                    self.options.path.display()
                );
            }
            Err(error) => {
                self.status = format!("Backup import failed: {error}");
            }
        }
    }

    fn submit_export_transfer(&mut self) {
        let output = self.export_transfer_form.path.trim();
        if output.is_empty() {
            self.status = "Transfer export requires an output path.".to_string();
            return;
        }

        let package_password =
            normalize_optional_field(&self.export_transfer_form.package_password);
        let cert_path = normalize_optional_field(&self.export_transfer_form.cert_path);
        if package_password.is_none() && cert_path.is_none() {
            self.status =
                "Transfer export requires a package recovery secret, recipient certificate, or both."
                    .to_string();
            return;
        }

        match unlock_vault_for_options(&self.options) {
            Ok(vault) => {
                let cert_pem = match cert_path {
                    Some(ref path) => match fs::read(path) {
                        Ok(pem) => Some(pem),
                        Err(error) => {
                            self.status = format!("Transfer export failed: {error}");
                            return;
                        }
                    },
                    None => None,
                };
                match vault
                    .export_transfer_package(
                        output,
                        &self.filters.as_filter(),
                        package_password.as_deref(),
                        cert_pem.as_deref(),
                    )
                    .map_err(anyhow::Error::from)
                {
                    Ok(path) => {
                        self.screen = Screen::Vault;
                        self.status = format!(
                            "Exported encrypted transfer package for {} current item(s) to {}.",
                            self.items.len(),
                            path.display()
                        );
                    }
                    Err(error) => {
                        self.status = format!("Transfer export failed: {error}");
                    }
                }
            }
            Err(error) => {
                self.status = format!("Transfer export failed: {error}");
            }
        }
    }

    fn submit_import_transfer(&mut self) {
        let input = self.import_transfer_form.path.trim().to_string();
        if input.is_empty() {
            self.status = "Transfer import requires an input path.".to_string();
            return;
        }

        let package_password =
            normalize_optional_field(&self.import_transfer_form.package_password);
        let cert_path = normalize_optional_field(&self.import_transfer_form.cert_path);
        let key_path = normalize_optional_field(&self.import_transfer_form.key_path);
        let key_passphrase = normalize_optional_field(&self.import_transfer_form.key_passphrase);
        let use_password = package_password.is_some();
        let use_certificate = cert_path.is_some() || key_path.is_some();
        if use_password && use_certificate {
            self.status =
                "Transfer import requires either a package recovery secret or a certificate keypair, not both."
                    .to_string();
            return;
        }
        if !use_password && !use_certificate {
            self.status =
                "Transfer import requires a package recovery secret or a certificate keypair."
                    .to_string();
            return;
        }
        if use_certificate && (cert_path.is_none() || key_path.is_none()) {
            self.status =
                "Transfer import requires both a recipient certificate path and private key path."
                    .to_string();
            return;
        }

        match unlock_vault_for_options(&self.options) {
            Ok(vault) => {
                let result = if let Some(password) = package_password {
                    vault.import_transfer_package_with_password(
                        input.as_str(),
                        password.as_str(),
                        self.import_transfer_form.replace_existing,
                    )
                } else {
                    let cert_pem = match fs::read(cert_path.as_deref().unwrap_or_default()) {
                        Ok(pem) => pem,
                        Err(error) => {
                            self.status = format!("Transfer import failed: {error}");
                            return;
                        }
                    };
                    let key_pem = match fs::read(key_path.as_deref().unwrap_or_default()) {
                        Ok(pem) => pem,
                        Err(error) => {
                            self.status = format!("Transfer import failed: {error}");
                            return;
                        }
                    };
                    vault.import_transfer_package_with_certificate(
                        input.as_str(),
                        cert_pem.as_slice(),
                        key_pem.as_slice(),
                        key_passphrase.as_deref(),
                        self.import_transfer_form.replace_existing,
                    )
                };
                match result.map_err(anyhow::Error::from) {
                    Ok(summary) => {
                        self.refresh();
                        self.status = format!(
                            "Imported transfer package from {}. imported={} replaced={} remapped={}.",
                            input,
                            summary.imported_count,
                            summary.replaced_count,
                            summary.remapped_count
                        );
                    }
                    Err(error) => {
                        self.status = format!("Transfer import failed: {error}");
                    }
                }
            }
            Err(error) => {
                self.status = format!("Transfer import failed: {error}");
            }
        }
    }

    fn submit_mnemonic_slot(&mut self) {
        match unlock_vault_for_options(&self.options) {
            Ok(mut vault) => match vault
                .add_mnemonic_keyslot(normalize_optional_field(&self.mnemonic_slot_form.label))
                .map_err(anyhow::Error::from)
            {
                Ok(enrollment) => {
                    self.header = Some(vault.header().clone());
                    self.selected_keyslot_index = self
                        .header
                        .as_ref()
                        .map(|h| h.keyslots.len().saturating_sub(1))
                        .unwrap_or(0);
                    self.latest_mnemonic_enrollment = Some(enrollment);
                    self.screen = Screen::MnemonicReveal;
                    self.status = "Mnemonic recovery slot enrolled. Capture the phrase offline before leaving this screen."
                        .to_string();
                }
                Err(error) => {
                    self.status = format!("Mnemonic enrollment failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Mnemonic enrollment failed: {error}");
            }
        }
    }

    fn submit_rotate_mnemonic_slot(&mut self) {
        let Some(slot) = selected_keyslot(self).cloned() else {
            self.status = "No keyslot selected to rotate.".to_string();
            return;
        };
        match unlock_vault_for_options(&self.options) {
            Ok(mut vault) => match vault
                .rotate_mnemonic_keyslot(&slot.id)
                .map_err(anyhow::Error::from)
            {
                Ok(enrollment) => {
                    self.header = Some(vault.header().clone());
                    self.sync_rotated_mnemonic_unlock(&enrollment);
                    self.selected_keyslot_index = self
                        .header
                        .as_ref()
                        .and_then(|header| {
                            header
                                .keyslots
                                .iter()
                                .position(|candidate| candidate.id == enrollment.keyslot.id)
                        })
                        .unwrap_or(0);
                    self.latest_mnemonic_enrollment = Some(enrollment);
                    self.screen = Screen::MnemonicReveal;
                    self.status = "Mnemonic recovery slot rotated. Capture the replacement phrase offline before leaving this screen.".to_string();
                }
                Err(error) => {
                    self.status = format!("Mnemonic rotation failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Mnemonic rotation failed: {error}");
            }
        }
    }

    fn submit_device_slot(&mut self) {
        match unlock_vault_for_options(&self.options) {
            Ok(mut vault) => match vault
                .add_device_keyslot(normalize_optional_field(&self.device_slot_form.label))
                .map_err(anyhow::Error::from)
            {
                Ok(slot) => {
                    self.header = Some(vault.header().clone());
                    self.sync_device_fallback_target(Some(slot.id.as_str()));
                    self.selected_keyslot_index = self
                        .header
                        .as_ref()
                        .and_then(|header| {
                            header
                                .keyslots
                                .iter()
                                .position(|candidate| candidate.id == slot.id)
                        })
                        .unwrap_or(0);
                    self.screen = Screen::Keyslots;
                    self.status = format!(
                        "Enrolled device-bound keyslot {} in secure storage.",
                        slot.id
                    );
                }
                Err(error) => {
                    self.status = format!("Device keyslot enrollment failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Device keyslot enrollment failed: {error}");
            }
        }
    }

    fn submit_certificate_slot(&mut self) {
        let cert_path = self.certificate_slot_form.cert_path.trim();
        if cert_path.is_empty() {
            self.status = "Certificate enrollment requires a PEM path.".to_string();
            return;
        }
        match fs::read(cert_path) {
            Ok(cert_pem) => match unlock_vault_for_options(&self.options) {
                Ok(mut vault) => match vault
                    .add_certificate_keyslot(
                        cert_pem.as_slice(),
                        normalize_optional_field(&self.certificate_slot_form.label),
                    )
                    .map_err(anyhow::Error::from)
                {
                    Ok(slot) => {
                        self.header = Some(vault.header().clone());
                        self.selected_keyslot_index = self
                            .header
                            .as_ref()
                            .and_then(|header| {
                                header
                                    .keyslots
                                    .iter()
                                    .position(|candidate| candidate.id == slot.id)
                            })
                            .unwrap_or(0);
                        self.screen = Screen::Keyslots;
                        self.status = format!(
                            "Enrolled certificate keyslot {} for fingerprint {} (valid until {}).",
                            slot.id,
                            slot.certificate_fingerprint_sha256.unwrap_or_default(),
                            slot.certificate_not_after.unwrap_or_default()
                        );
                    }
                    Err(error) => {
                        self.status = format!("Certificate keyslot enrollment failed: {error}");
                    }
                },
                Err(error) => {
                    self.status = format!("Certificate keyslot enrollment failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Certificate read failed: {error}");
            }
        }
    }

    fn submit_certificate_slot_rewrap(&mut self) {
        let Some(slot) = selected_keyslot(self).cloned() else {
            self.status = "No keyslot selected to rewrap.".to_string();
            return;
        };
        let cert_path = self.certificate_rewrap_form.cert_path.trim().to_string();
        if cert_path.is_empty() {
            self.status = "Certificate rewrap requires a PEM path.".to_string();
            return;
        }
        let replacement_key_path = normalize_optional_field(&self.certificate_rewrap_form.key_path);
        let replacement_key_passphrase =
            normalize_optional_field(&self.certificate_rewrap_form.key_passphrase);
        match fs::read(&cert_path) {
            Ok(cert_pem) => match unlock_vault_for_options(&self.options) {
                Ok(mut vault) => match vault
                    .rewrap_certificate_keyslot(&slot.id, cert_pem.as_slice())
                    .map_err(anyhow::Error::from)
                {
                    Ok(updated) => {
                        self.sync_rewrapped_certificate_unlock(
                            &slot,
                            cert_path.as_str(),
                            replacement_key_path.as_deref(),
                            replacement_key_passphrase.as_deref(),
                        );
                        self.header = Some(vault.header().clone());
                        self.selected_keyslot_index = self
                            .header
                            .as_ref()
                            .and_then(|header| {
                                header
                                    .keyslots
                                    .iter()
                                    .position(|candidate| candidate.id == updated.id)
                            })
                            .unwrap_or(0);
                        self.screen = Screen::Keyslots;
                        self.status = format!(
                            "Rewrapped certificate keyslot {} to fingerprint {} (valid until {}). Active certificate session settings were preserved or updated if this was the active cert slot.",
                            updated.id,
                            updated.certificate_fingerprint_sha256.unwrap_or_default(),
                            updated.certificate_not_after.unwrap_or_default()
                        );
                    }
                    Err(error) => {
                        self.status = format!("Certificate keyslot rewrap failed: {error}");
                    }
                },
                Err(error) => {
                    self.status = format!("Certificate keyslot rewrap failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Certificate read failed: {error}");
            }
        }
    }

    fn submit_keyslot_label_edit(&mut self) {
        let Some(slot) = selected_keyslot(self).cloned() else {
            self.status = "No keyslot selected to relabel.".to_string();
            return;
        };
        match unlock_vault_for_options(&self.options) {
            Ok(mut vault) => match vault
                .relabel_keyslot(
                    &slot.id,
                    normalize_optional_field(&self.keyslot_label_form.label),
                )
                .map_err(anyhow::Error::from)
            {
                Ok(updated) => {
                    self.header = Some(vault.header().clone());
                    self.selected_keyslot_index = self
                        .header
                        .as_ref()
                        .and_then(|header| {
                            header
                                .keyslots
                                .iter()
                                .position(|candidate| candidate.id == updated.id)
                        })
                        .unwrap_or(0);
                    self.screen = Screen::Keyslots;
                    self.status = format!(
                        "Updated {} keyslot {} label to {}.",
                        updated.kind.as_str(),
                        updated.id,
                        updated.label.unwrap_or_else(|| "(cleared)".to_string())
                    );
                }
                Err(error) => {
                    self.status = format!("Keyslot relabel failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Keyslot relabel failed: {error}");
            }
        }
    }

    fn submit_rotate_recovery_secret(&mut self) {
        if self.recovery_secret_form.new_secret.is_empty() {
            self.status = "Recovery secret rotation requires a non-empty new secret.".to_string();
            return;
        }
        if self.recovery_secret_form.new_secret != self.recovery_secret_form.confirm_secret {
            self.status = "Recovery secret rotation requires matching confirmation.".to_string();
            return;
        }

        let new_secret = self.recovery_secret_form.new_secret.clone();
        match unlock_vault_for_options(&self.options) {
            Ok(mut vault) => match vault
                .rotate_password_recovery_keyslot(new_secret.as_str())
                .map_err(anyhow::Error::from)
            {
                Ok(keyslot) => {
                    self.header = Some(vault.header().clone());
                    if matches!(
                        self.options.auth,
                        VaultAuth::PasswordEnv(_) | VaultAuth::Password(_)
                    ) {
                        self.options.auth = VaultAuth::Password(SecretString::new(new_secret));
                    }
                    self.recovery_secret_form = RecoverySecretForm::default();
                    self.screen = Screen::Keyslots;
                    self.status = format!(
                        "Rotated password recovery keyslot {} with {}.",
                        keyslot.id, keyslot.wrap_algorithm
                    );
                }
                Err(error) => {
                    self.status = format!("Recovery secret rotation failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Recovery secret rotation failed: {error}");
            }
        }
    }

    fn remove_selected_keyslot(&mut self) {
        let Some(slot) = selected_keyslot(self).cloned() else {
            self.status = "No keyslot selected to remove.".to_string();
            return;
        };
        let Some(header) = self.header.as_ref() else {
            self.status = "No vault header loaded for keyslot analysis.".to_string();
            return;
        };
        let impact = match header.assess_keyslot_removal(&slot.id) {
            Ok(impact) => impact,
            Err(error) => {
                self.status = format!("Keyslot removal failed: {error}");
                return;
            }
        };
        let force = self.pending_keyslot_removal_confirmation.as_deref() == Some(slot.id.as_str());
        if impact.requires_explicit_confirmation && !force {
            self.pending_keyslot_removal_confirmation = Some(slot.id.clone());
            self.status = format!(
                "Removal of {} requires confirmation: {} Press d again to confirm.",
                slot.id,
                impact.warnings.join(" ")
            );
            return;
        }
        match unlock_vault_for_options(&self.options) {
            Ok(mut vault) => match vault
                .remove_keyslot(&slot.id, force)
                .map_err(anyhow::Error::from)
            {
                Ok(removed) => {
                    self.header = Some(vault.header().clone());
                    self.sync_device_fallback_target(None);
                    let remaining = self
                        .header
                        .as_ref()
                        .map(|header| header.keyslots.len())
                        .unwrap_or_default();
                    self.selected_keyslot_index =
                        self.selected_keyslot_index.min(remaining.saturating_sub(1));
                    self.pending_keyslot_removal_confirmation = None;
                    self.screen = Screen::Keyslots;
                    self.status =
                        format!("Removed {} keyslot {}.", removed.kind.as_str(), removed.id);
                }
                Err(error) => {
                    self.pending_keyslot_removal_confirmation = None;
                    self.status = format!("Keyslot removal failed: {error}");
                }
            },
            Err(error) => {
                self.pending_keyslot_removal_confirmation = None;
                self.status = format!("Keyslot removal failed: {error}");
            }
        }
    }

    fn rebind_selected_device_keyslot(&mut self) {
        let Some(slot) = selected_keyslot(self).cloned() else {
            self.status = "No keyslot selected to rebind.".to_string();
            return;
        };
        self.pending_keyslot_removal_confirmation = None;
        match unlock_vault_for_options(&self.options) {
            Ok(mut vault) => match vault
                .rebind_device_keyslot(&slot.id)
                .map_err(anyhow::Error::from)
            {
                Ok(updated) => {
                    self.header = Some(vault.header().clone());
                    self.sync_device_fallback_target(Some(updated.id.as_str()));
                    self.selected_keyslot_index = self
                        .header
                        .as_ref()
                        .and_then(|header| {
                            header
                                .keyslots
                                .iter()
                                .position(|candidate| candidate.id == updated.id)
                        })
                        .unwrap_or(0);
                    self.screen = Screen::Keyslots;
                    self.status = format!(
                        "Rebound device-bound keyslot {} to secure-storage account {}.",
                        updated.id,
                        updated.device_account.unwrap_or_default()
                    );
                }
                Err(error) => {
                    self.status = format!("Device keyslot rebind failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Device keyslot rebind failed: {error}");
            }
        }
    }

    fn delete_selected_item(&mut self) {
        let Some(detail) = &self.detail else {
            self.screen = Screen::Vault;
            self.status = "No vault item selected to delete.".to_string();
            return;
        };
        let item_id = detail.id.clone();
        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault.delete_item(&item_id).map_err(anyhow::Error::from) {
                Ok(()) => {
                    self.screen = Screen::Vault;
                    self.editing_item_id = None;
                    if let Err(error) = self.reload_vault_state(None) {
                        self.status =
                            format!("Deleted item {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.status = format!("Deleted vault item {item_id} from the encrypted vault.");
                }
                Err(error) => {
                    self.status = format!("Delete failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Delete failed: {error}");
            }
        }
    }

    fn reload_detail(&mut self) {
        let Some(item) = self.items.get(self.selected_index) else {
            self.detail = None;
            return;
        };

        match unlock_vault_for_options(&self.options) {
            Ok(vault) => match vault
                .get_item(&item.id)
                .map_err(anyhow::Error::from)
                .context("failed to reload selected vault item")
            {
                Ok(detail) => {
                    self.detail = Some(detail);
                }
                Err(error) => {
                    self.detail = None;
                    self.status = format!("Detail reload failed: {error}");
                }
            },
            Err(error) => {
                self.detail = None;
                self.status = format!("Detail reload failed: {error}");
            }
        }
    }

    fn copy_selected_secret(&mut self) {
        let Some(payload) = self.detail.as_ref().map(|item| &item.payload) else {
            self.status = "No vault item selected to copy.".to_string();
            return;
        };
        let content = match payload {
            VaultItemPayload::Login(login) => login.password.clone(),
            VaultItemPayload::SecureNote(note) => note.content.clone(),
            VaultItemPayload::Card(card) => card.number.clone(),
            VaultItemPayload::Identity(identity) => identity
                .email
                .clone()
                .or_else(|| identity.phone.clone())
                .unwrap_or_else(|| identity.full_name.clone()),
        };
        match Clipboard::new().and_then(|mut clipboard| clipboard.set_text(content.clone())) {
            Ok(()) => {
                self.session.arm_clipboard_clear(content);
                self.status = format!(
                    "Copied the selected vault secret to the clipboard. It will be cleared in {} seconds if unchanged.",
                    self.session.clipboard_clear_after().as_secs()
                );
            }
            Err(error) => {
                self.status = format!("Clipboard unavailable: {error}");
            }
        }
    }

    fn copy_latest_mnemonic(&mut self) {
        let Some(enrollment) = &self.latest_mnemonic_enrollment else {
            self.status = "No mnemonic phrase is available to copy.".to_string();
            return;
        };
        match Clipboard::new()
            .and_then(|mut clipboard| clipboard.set_text(enrollment.mnemonic.clone()))
        {
            Ok(()) => {
                self.session
                    .arm_clipboard_clear(enrollment.mnemonic.clone());
                self.status = format!(
                    "Copied the current mnemonic recovery phrase to the clipboard. It will be cleared in {} seconds if unchanged.",
                    self.session.clipboard_clear_after().as_secs()
                );
            }
            Err(error) => {
                self.status = format!("Clipboard unavailable: {error}");
            }
        }
    }
}

fn edit_form_value(buffer: Option<&mut String>, key: KeyEvent) {
    let Some(buffer) = buffer else {
        return;
    };
    match key.code {
        KeyCode::Backspace => {
            buffer.pop();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => buffer.clear(),
        KeyCode::Char(ch) if (32..=126).contains(&(ch as u32)) => buffer.push(ch),
        _ => {}
    }
}

pub fn run(options: VaultOpenOptions) -> anyhow::Result<()> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to initialize terminal")?;
    terminal.clear().ok();
    let result = run_app(&mut terminal, App::new(options));
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    result
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> anyhow::Result<()> {
    loop {
        app.poll_hardening();
        terminal
            .draw(|frame| render(frame, &app))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if event::poll(std::time::Duration::from_millis(80))? {
            if let Event::Key(key) = event::read()? {
                app.session.note_activity();
                if app.handle_key(key) {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    frame.render_widget(Block::default().style(Style::default().bg(BG)), area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(3),
        ])
        .split(area);
    render_header(
        frame,
        chunks[0],
        header_title(app.screen),
        header_subtitle(app.screen),
    );

    frame.render_widget(
        Paragraph::new(app.status.as_str())
            .style(
                Style::default()
                    .fg(match app.screen {
                        Screen::UnlockBlocked => RED,
                        _ => AMBER,
                    })
                    .bg(BG),
            )
            .wrap(Wrap { trim: false }),
        chunks[1],
    );

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[2]);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(8)])
        .split(body[0]);

    frame.render_widget(keyslot_panel(app), left[0]);
    frame.render_widget(item_list(app), left[1]);
    frame.render_widget(right_panel(app), body[1]);

    frame.render_widget(
        Paragraph::new(footer_text(app))
            .style(Style::default().fg(TEXT).bg(BG))
            .wrap(Wrap { trim: false }),
        chunks[3],
    );
}

fn render_header(frame: &mut Frame<'_>, area: Rect, title: &str, subtitle: &str) {
    frame.render_widget(
        Paragraph::new(Text::from(vec![
            Line::styled(
                format!("paranoid-passwd · {title}"),
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
            Line::styled(subtitle, Style::default().fg(TEXT)),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GREEN))
                .style(Style::default().bg(PANEL)),
        ),
        area,
    );
}

fn header_title(screen: Screen) -> &'static str {
    match screen {
        Screen::Vault => "Vault",
        Screen::Keyslots => "Keyslots",
        Screen::UnlockBlocked => "Vault",
        Screen::AddLogin => "Add Login",
        Screen::EditLogin => "Edit Login",
        Screen::AddNote => "Add Secure Note",
        Screen::EditNote => "Edit Secure Note",
        Screen::AddCard => "Add Card",
        Screen::EditCard => "Edit Card",
        Screen::AddIdentity => "Add Identity",
        Screen::EditIdentity => "Edit Identity",
        Screen::AddMnemonicSlot => "Add Mnemonic Slot",
        Screen::AddDeviceSlot => "Add Device Slot",
        Screen::AddCertSlot => "Add Certificate Slot",
        Screen::RewrapCertSlot => "Rewrap Certificate Slot",
        Screen::EditKeyslotLabel => "Edit Keyslot Label",
        Screen::RotateMnemonicSlot => "Rotate Mnemonic Slot",
        Screen::RotateRecoverySecret => "Rotate Recovery Secret",
        Screen::MnemonicReveal => "Mnemonic Recovery",
        Screen::GenerateStore => "Generate & Store",
        Screen::ExportBackup => "Export Backup",
        Screen::ExportTransfer => "Export Transfer",
        Screen::ImportBackup => "Import Backup",
        Screen::ImportTransfer => "Import Transfer",
        Screen::DeleteConfirm => "Delete Item",
    }
}

fn header_subtitle(screen: Screen) -> &'static str {
    match screen {
        Screen::Vault => "Native vault list/detail view with the same builder-owned trust model.",
        Screen::Keyslots => {
            "Inspect and enroll recovery or unlock keyslots without leaving the native TUI."
        }
        Screen::UnlockBlocked => {
            "Unlock uses the same password, mnemonic, device, and certificate paths as the CLI, now with direct native input."
        }
        Screen::AddLogin => "Write a login entry directly into the encrypted local vault.",
        Screen::EditLogin => {
            "Update the selected login entry without leaving the native vault TUI."
        }
        Screen::AddNote => "Write a secure note directly into the encrypted local vault.",
        Screen::EditNote => "Update the selected secure note without leaving the native vault TUI.",
        Screen::AddCard => "Write a payment card directly into the encrypted local vault.",
        Screen::EditCard => "Update the selected card without leaving the native vault TUI.",
        Screen::AddIdentity => "Write an identity profile directly into the encrypted local vault.",
        Screen::EditIdentity => {
            "Update the selected identity profile without leaving the native vault TUI."
        }
        Screen::AddMnemonicSlot => {
            "Enroll a wallet-style mnemonic recovery slot for offline recovery."
        }
        Screen::AddDeviceSlot => {
            "Enroll a passwordless device-bound slot backed by platform secure storage."
        }
        Screen::AddCertSlot => {
            "Enroll a certificate-wrapped slot using a recipient PEM certificate."
        }
        Screen::RewrapCertSlot => {
            "Replace the recipient certificate for the selected certificate-wrapped keyslot."
        }
        Screen::EditKeyslotLabel => {
            "Update the selected keyslot label without changing any recovery or unlock material."
        }
        Screen::RotateMnemonicSlot => {
            "Replace the selected mnemonic recovery phrase while preserving the same keyslot id and vault master key."
        }
        Screen::RotateRecoverySecret => {
            "Rewrap the password recovery keyslot while preserving the existing vault master key."
        }
        Screen::MnemonicReveal => {
            "Capture the phrase offline now; it will not be rederived from the UI."
        }
        Screen::GenerateStore => {
            "Run the Rust-native generator and store the result as a vault login item."
        }
        Screen::ExportBackup => {
            "Export the current encrypted vault state into a portable JSON backup package."
        }
        Screen::ExportTransfer => {
            "Export the currently filtered vault items into an encrypted transfer package."
        }
        Screen::ImportBackup => {
            "Restore a JSON backup package into the current vault path with explicit overwrite control."
        }
        Screen::ImportTransfer => {
            "Import a selective encrypted transfer package into the unlocked local vault."
        }
        Screen::DeleteConfirm => {
            "Confirm removal of the selected vault item from the encrypted vault."
        }
    }
}

fn footer_text(app: &App) -> &'static str {
    match app.screen {
        Screen::Vault => {
            if app.search_mode {
                "Controls: Type to filter the unlocked list, Backspace deletes, Ctrl+u clears, Enter or Esc exits filter mode, q quits."
            } else {
                "Controls: Up/Down select items, / filters, a adds login, n adds secure note, v adds card, i adds identity, e edits, d deletes, g generates and stores one password, x exports backup, t exports transfer, u imports backup, p imports transfer, k opens keyslots, c copies the selected value, r refreshes, q quits."
            }
        }
        Screen::Keyslots => {
            "Controls: Up/Down select keyslots, m adds mnemonic recovery, b adds device-bound, c adds certificate-wrapped, w rewraps the selected certificate slot, l relabels the selected keyslot, o rotates the selected mnemonic slot, p rotates the recovery secret, d removes the selected non-recovery slot, r rebinds the selected device slot, Esc returns to items, q quits."
        }
        Screen::UnlockBlocked => {
            "Controls: p/m/b/c pick password, mnemonic, device, or certificate mode; Up/Down or Tab move; Left/Right cycles the mode field; Enter advances or unlocks; r retries current policy; q quits."
        }
        Screen::AddLogin
        | Screen::EditLogin
        | Screen::AddNote
        | Screen::EditNote
        | Screen::AddCard
        | Screen::EditCard
        | Screen::AddIdentity
        | Screen::EditIdentity
        | Screen::AddMnemonicSlot
        | Screen::AddDeviceSlot
        | Screen::AddCertSlot
        | Screen::RewrapCertSlot
        | Screen::EditKeyslotLabel
        | Screen::RotateMnemonicSlot
        | Screen::RotateRecoverySecret
        | Screen::GenerateStore => {
            "Controls: Type into the focused field, Up/Down or Tab move, Enter advances or saves, Ctrl+u clears the field, Esc cancels, q quits."
        }
        Screen::ExportBackup
        | Screen::ExportTransfer
        | Screen::ImportBackup
        | Screen::ImportTransfer => {
            "Controls: Type into the focused path field, Up/Down or Tab move, Space/Left/Right toggle overwrite when selected, Enter advances or saves, Ctrl+u clears the field, Esc cancels, q quits."
        }
        Screen::MnemonicReveal => {
            "Controls: c copies the phrase, Enter or Esc returns to keyslots, q quits."
        }
        Screen::DeleteConfirm => {
            "Controls: y or Enter confirms deletion, n or Esc cancels, q quits."
        }
    }
}

fn keyslot_panel(app: &App) -> Paragraph<'static> {
    let mut lines = vec![
        Line::raw(format!("Vault path: {}", app.options.path.display())),
        Line::raw(format!("Unlock: {}", app.options.unlock_description())),
        Line::raw(""),
    ];
    if let Some(header) = &app.header {
        let posture = header.recovery_posture();
        lines.push(Line::styled(
            format!("Keyslots ({})", header.keyslots.len()),
            Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::raw(format!(
            "Recovery posture: recovery={} cert={} recommended={}",
            posture.has_recovery_path,
            posture.has_certificate_path,
            posture.meets_recommended_posture
        )));
        lines.push(Line::raw(format!(
            "Counts: password={} mnemonic={} device={} cert={}",
            posture.password_recovery_slots,
            posture.mnemonic_recovery_slots,
            posture.device_bound_slots,
            posture.certificate_wrapped_slots
        )));
        for recommendation in header.recovery_recommendations() {
            lines.push(Line::styled(
                format!("recommend: {recommendation}"),
                Style::default().fg(AMBER),
            ));
        }
        for slot in header.keyslots.iter().take(3) {
            let label = slot.label.as_deref().unwrap_or("unlabeled");
            lines.push(Line::raw(format!("{} · {}", slot.kind.as_str(), label)));
        }
        if header.keyslots.len() > 3 {
            lines.push(Line::raw(format!(
                "... {} more slot(s)",
                header.keyslots.len() - 3
            )));
        }
    } else {
        lines.push(Line::raw(
            "Keyslots unavailable until the vault header can be read.",
        ));
    }
    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Access")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn item_list(app: &App) -> List<'static> {
    if matches!(
        app.screen,
        Screen::Keyslots
            | Screen::AddMnemonicSlot
            | Screen::AddDeviceSlot
            | Screen::AddCertSlot
            | Screen::RewrapCertSlot
            | Screen::EditKeyslotLabel
            | Screen::RotateMnemonicSlot
            | Screen::RotateRecoverySecret
            | Screen::MnemonicReveal
    ) {
        return keyslot_list(app);
    }

    let items = if app.items.is_empty() {
        vec![ListItem::new(Line::styled(
            if !app.filters.is_active() {
                "No vault items yet. Press a to add a login, n to add a secure note, v to add a card, i to add an identity, or g to generate and store one."
            } else {
                "No vault items match the current filter. Press / to refine or clear it."
            },
            Style::default().fg(AMBER),
        ))]
    } else {
        app.items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let selected = index == app.selected_index && matches!(app.screen, Screen::Vault);
                let prefix = if selected { "› " } else { "  " };
                let style = if selected {
                    Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(TEXT)
                };
                let duplicate_marker = if item.duplicate_password_count > 0 {
                    format!(" [dup:{}]", item.duplicate_password_count)
                } else {
                    String::new()
                };
                let folder_marker = item
                    .folder
                    .as_deref()
                    .map(|folder| format!(" [{folder}]"))
                    .unwrap_or_default();
                ListItem::new(Line::from(vec![
                    Span::styled(prefix.to_string(), style),
                    Span::styled(
                        format!(
                            "{}{} · {}{}",
                            item.title, folder_marker, item.subtitle, duplicate_marker
                        ),
                        style,
                    ),
                ]))
            })
            .collect::<Vec<_>>()
    };

    List::new(items).block(
        Block::default()
            .title(if !app.filters.is_active() {
                "Items".to_string()
            } else if app.search_mode {
                format!("Items · filter: {}_", app.filters.summary())
            } else {
                format!("Items · filter: {}", app.filters.summary())
            })
            .borders(Borders::ALL)
            .border_style(Style::default().fg(GREEN))
            .style(Style::default().bg(PANEL).fg(TEXT)),
    )
}

fn keyslot_list(app: &App) -> List<'static> {
    let items = match &app.header {
        Some(header) if !header.keyslots.is_empty() => header
            .keyslots
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                let selected = index == app.selected_keyslot_index
                    && matches!(
                        app.screen,
                        Screen::Keyslots
                            | Screen::AddMnemonicSlot
                            | Screen::AddDeviceSlot
                            | Screen::AddCertSlot
                            | Screen::RewrapCertSlot
                            | Screen::EditKeyslotLabel
                            | Screen::RotateMnemonicSlot
                            | Screen::RotateRecoverySecret
                            | Screen::MnemonicReveal
                    );
                let prefix = if selected { "› " } else { "  " };
                let style = if selected {
                    Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(TEXT)
                };
                let label = slot.label.as_deref().unwrap_or("unlabeled");
                ListItem::new(Line::from(vec![
                    Span::styled(prefix.to_string(), style),
                    Span::styled(format!("{} · {}", slot.kind.as_str(), label), style),
                ]))
            })
            .collect::<Vec<_>>(),
        _ => vec![ListItem::new(Line::styled(
            "No keyslots available yet beyond the required recovery slot.",
            Style::default().fg(AMBER),
        ))],
    };

    List::new(items).block(
        Block::default()
            .title("Keyslots")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(GREEN))
            .style(Style::default().bg(PANEL).fg(TEXT)),
    )
}

fn right_panel(app: &App) -> Paragraph<'static> {
    match app.screen {
        Screen::Vault => detail_panel(app),
        Screen::UnlockBlocked => unlock_blocked_panel(app),
        Screen::AddLogin | Screen::EditLogin => add_login_panel(app),
        Screen::AddNote | Screen::EditNote => add_note_panel(app),
        Screen::AddCard | Screen::EditCard => add_card_panel(app),
        Screen::AddIdentity | Screen::EditIdentity => add_identity_panel(app),
        Screen::Keyslots => keyslot_detail_panel(app),
        Screen::AddMnemonicSlot => add_mnemonic_slot_panel(app),
        Screen::AddDeviceSlot => add_device_slot_panel(app),
        Screen::AddCertSlot => add_certificate_slot_panel(app),
        Screen::RewrapCertSlot => rewrap_certificate_slot_panel(app),
        Screen::EditKeyslotLabel => edit_keyslot_label_panel(app),
        Screen::RotateMnemonicSlot => rotate_mnemonic_slot_panel(app),
        Screen::RotateRecoverySecret => rotate_recovery_secret_panel(app),
        Screen::MnemonicReveal => mnemonic_reveal_panel(app),
        Screen::GenerateStore => generate_store_panel(app),
        Screen::ExportBackup => export_backup_panel(app),
        Screen::ExportTransfer => export_transfer_panel(app),
        Screen::ImportBackup => import_backup_panel(app),
        Screen::ImportTransfer => import_transfer_panel(app),
        Screen::DeleteConfirm => delete_confirm_panel(app),
    }
}

fn unlock_blocked_panel(app: &App) -> Paragraph<'static> {
    let form = &app.unlock_form;
    let mode_value = format!("{} (p/m/b/c or Left/Right)", form.mode.label());
    let mut lines = vec![form_line(
        matches!(form.selected_field(), UnlockField::Mode),
        "Unlock mode",
        &mode_value,
    )];

    match form.mode {
        UnlockMode::Password => {
            lines.push(form_line(
                matches!(form.selected_field(), UnlockField::Primary),
                "Recovery secret",
                &masked_value(&form.password),
            ));
        }
        UnlockMode::Mnemonic => {
            lines.push(form_line(
                matches!(form.selected_field(), UnlockField::Primary),
                "Recovery phrase",
                &masked_value(&form.mnemonic_phrase),
            ));
            lines.push(form_line(
                matches!(form.selected_field(), UnlockField::Secondary),
                "Mnemonic slot (optional)",
                &form.mnemonic_slot,
            ));
        }
        UnlockMode::Device => {
            lines.push(form_line(
                matches!(form.selected_field(), UnlockField::Primary),
                "Device slot (optional)",
                &form.device_slot,
            ));
        }
        UnlockMode::Certificate => {
            lines.push(form_line(
                matches!(form.selected_field(), UnlockField::Primary),
                "Recipient cert PEM path",
                &form.cert_path,
            ));
            lines.push(form_line(
                matches!(form.selected_field(), UnlockField::Secondary),
                "Private key PEM path",
                &form.key_path,
            ));
            lines.push(form_line(
                matches!(form.selected_field(), UnlockField::Tertiary),
                "Key passphrase (optional)",
                &masked_value(&form.key_passphrase),
            ));
        }
    }

    lines.push(form_action_line(
        matches!(form.selected_field(), UnlockField::Submit),
        "Unlock Vault",
    ));
    lines.push(Line::raw(""));
    lines.push(Line::raw(
        "Native unlock now works directly from the TUI; env-based CLI inputs remain valid too.",
    ));
    lines.push(Line::raw(format!(
        "Current path: {}",
        app.options.path.display()
    )));
    if app.header.is_some() {
        lines.push(Line::raw(
            "The vault header is readable, so the on-disk format still looks intact.",
        ));
    }

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Unlock Vault")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(RED))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn detail_panel(app: &App) -> Paragraph<'static> {
    let lines = match app.screen {
        Screen::UnlockBlocked => unreachable!("unlock blocked uses a dedicated panel"),
        Screen::Vault => match &app.detail {
            Some(item) => match &item.payload {
                VaultItemPayload::Login(login) => {
                    let duplicate_password_count = app
                        .items
                        .iter()
                        .find(|summary| summary.id == item.id)
                        .map(|summary| summary.duplicate_password_count)
                        .unwrap_or(0);
                    vec![
                        Line::styled(
                            "Selected login",
                            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
                        ),
                        Line::raw(""),
                        Line::raw(format!("id: {}", item.id)),
                        Line::raw(format!("title: {}", login.title)),
                        Line::raw(format!("username: {}", login.username)),
                        Line::raw(format!("password: {}", login.password)),
                        Line::raw(format!(
                            "duplicate passwords elsewhere: {duplicate_password_count}"
                        )),
                        Line::raw(format!("url: {}", login.url.as_deref().unwrap_or(""))),
                        Line::raw(format!("notes: {}", login.notes.as_deref().unwrap_or(""))),
                        Line::raw(format!("folder: {}", login.folder.as_deref().unwrap_or(""))),
                        Line::raw(format!(
                            "tags: {}",
                            if login.tags.is_empty() {
                                String::new()
                            } else {
                                login.tags.join(", ")
                            }
                        )),
                        Line::raw(format!(
                            "password history entries: {}",
                            login.password_history.len()
                        )),
                        Line::raw(format!(
                            "recent history: {}",
                            if login.password_history.is_empty() {
                                String::new()
                            } else {
                                login
                                    .password_history
                                    .iter()
                                    .rev()
                                    .take(3)
                                    .map(|entry| {
                                        format!("{} @ {}", entry.password, entry.changed_at_epoch)
                                    })
                                    .collect::<Vec<_>>()
                                    .join(" | ")
                            }
                        )),
                        Line::raw(""),
                        Line::raw(format!("updated_at_epoch: {}", item.updated_at_epoch)),
                        Line::raw(""),
                        Line::raw(
                            "Press a to add, e to edit, d to delete, or g to generate-and-store.",
                        ),
                        Line::raw("Press k to inspect or enroll vault keyslots natively."),
                        Line::raw("Press x to export a backup package or u to restore one."),
                    ]
                }
                VaultItemPayload::SecureNote(note) => vec![
                    Line::styled(
                        "Selected secure note",
                        Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
                    ),
                    Line::raw(""),
                    Line::raw(format!("id: {}", item.id)),
                    Line::raw(format!("title: {}", note.title)),
                    Line::raw(format!("content: {}", note.content)),
                    Line::raw(format!("folder: {}", note.folder.as_deref().unwrap_or(""))),
                    Line::raw(format!(
                        "tags: {}",
                        if note.tags.is_empty() {
                            String::new()
                        } else {
                            note.tags.join(", ")
                        }
                    )),
                    Line::raw(""),
                    Line::raw(format!("updated_at_epoch: {}", item.updated_at_epoch)),
                    Line::raw(""),
                    Line::raw(
                        "Press a to add login, n to add secure note, v to add card, e to edit, or d to delete.",
                    ),
                    Line::raw(
                        "Use c to copy the full note content into the clipboard when needed.",
                    ),
                ],
                VaultItemPayload::Card(card) => vec![
                    Line::styled(
                        "Selected card",
                        Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
                    ),
                    Line::raw(""),
                    Line::raw(format!("id: {}", item.id)),
                    Line::raw(format!("title: {}", card.title)),
                    Line::raw(format!("cardholder: {}", card.cardholder_name)),
                    Line::raw(format!("number: {}", card.number)),
                    Line::raw(format!(
                        "expiry: {}/{}",
                        card.expiry_month, card.expiry_year
                    )),
                    Line::raw(format!("security code: {}", card.security_code)),
                    Line::raw(format!(
                        "billing zip: {}",
                        card.billing_zip.as_deref().unwrap_or("")
                    )),
                    Line::raw(format!("notes: {}", card.notes.as_deref().unwrap_or(""))),
                    Line::raw(format!("folder: {}", card.folder.as_deref().unwrap_or(""))),
                    Line::raw(format!(
                        "tags: {}",
                        if card.tags.is_empty() {
                            String::new()
                        } else {
                            card.tags.join(", ")
                        }
                    )),
                    Line::raw(""),
                    Line::raw(format!("updated_at_epoch: {}", item.updated_at_epoch)),
                    Line::raw(""),
                    Line::raw(
                        "Press a to add login, n to add secure note, v to add card, i to add identity, e to edit, or d to delete.",
                    ),
                    Line::raw("Use c to copy the full card number into the clipboard when needed."),
                ],
                VaultItemPayload::Identity(identity) => vec![
                    Line::styled(
                        "Selected identity",
                        Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
                    ),
                    Line::raw(""),
                    Line::raw(format!("id: {}", item.id)),
                    Line::raw(format!("title: {}", identity.title)),
                    Line::raw(format!("full name: {}", identity.full_name)),
                    Line::raw(format!(
                        "email: {}",
                        identity.email.as_deref().unwrap_or("")
                    )),
                    Line::raw(format!(
                        "phone: {}",
                        identity.phone.as_deref().unwrap_or("")
                    )),
                    Line::raw(format!(
                        "address: {}",
                        identity.address.as_deref().unwrap_or("")
                    )),
                    Line::raw(format!(
                        "notes: {}",
                        identity.notes.as_deref().unwrap_or("")
                    )),
                    Line::raw(format!(
                        "folder: {}",
                        identity.folder.as_deref().unwrap_or("")
                    )),
                    Line::raw(format!(
                        "tags: {}",
                        if identity.tags.is_empty() {
                            String::new()
                        } else {
                            identity.tags.join(", ")
                        }
                    )),
                    Line::raw(""),
                    Line::raw(format!("updated_at_epoch: {}", item.updated_at_epoch)),
                    Line::raw(""),
                    Line::raw(
                        "Press a to add login, n to add secure note, v to add card, i to add identity, e to edit, or d to delete.",
                    ),
                    Line::raw(
                        "Use c to copy the preferred contact value (email, phone, or full name).",
                    ),
                ],
            },
            None => vec![
                Line::styled(
                    "Vault detail",
                    Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw("No item is selected yet."),
                Line::raw(
                    "Press a to add a login, n to add a secure note, v to add a card, i to add an identity, or g to generate and store one.",
                ),
                Line::raw("Use x to export the encrypted vault state or u to restore a backup."),
            ],
        },
        _ => unreachable!("detail panel only renders vault screens"),
    };

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Detail")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn keyslot_detail_panel(app: &App) -> Paragraph<'static> {
    let lines = match selected_keyslot(app) {
        Some(slot) => {
            let mut lines = vec![
                Line::styled(
                    "Selected keyslot",
                    Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw(format!("id: {}", slot.id)),
                Line::raw(format!("kind: {}", slot.kind.as_str())),
                Line::raw(format!("label: {}", slot.label.as_deref().unwrap_or(""))),
                Line::raw(format!("wrap: {}", slot.wrap_algorithm)),
                Line::raw(format!(
                    "device-bound: {}",
                    if slot.wrapped_by_os_keystore {
                        "yes"
                    } else {
                        "no"
                    }
                )),
            ];
            if let Some(fingerprint) = &slot.certificate_fingerprint_sha256 {
                lines.push(Line::raw(format!("fingerprint: {fingerprint}")));
            }
            if let Some(subject) = &slot.certificate_subject {
                lines.push(Line::raw(format!("subject: {subject}")));
            }
            if let Some(not_before) = &slot.certificate_not_before {
                lines.push(Line::raw(format!("valid from: {not_before}")));
            }
            if let Some(not_after) = &slot.certificate_not_after {
                lines.push(Line::raw(format!("valid until: {not_after}")));
            }
            if let Some(language) = &slot.mnemonic_language {
                lines.push(Line::raw(format!(
                    "mnemonic: {} words ({language})",
                    slot.mnemonic_words.unwrap_or_default()
                )));
            }
            if let Some(service) = &slot.device_service {
                lines.push(Line::raw(format!("device service: {service}")));
            }
            if let Some(account) = &slot.device_account {
                lines.push(Line::raw(format!("device account: {account}")));
            }
            if let Some(header) = &app.header
                && let Ok(health) = header.assess_keyslot_health(slot.id.as_str())
            {
                lines.push(Line::raw(format!("healthy: {}", health.healthy)));
                for warning in health.warnings {
                    lines.push(Line::styled(
                        format!("health warning: {warning}"),
                        Style::default().fg(AMBER),
                    ));
                }
            }
            if let Some(header) = &app.header
                && let Ok(impact) = header.assess_keyslot_removal(slot.id.as_str())
            {
                lines.push(Line::raw(""));
                lines.push(Line::raw(format!(
                    "removal requires confirmation: {}",
                    impact.requires_explicit_confirmation
                )));
                if impact.warnings.is_empty() {
                    lines.push(Line::raw("removal impact: no posture downgrade detected."));
                } else {
                    for warning in impact.warnings {
                        lines.push(Line::styled(
                            format!("warning: {warning}"),
                            Style::default().fg(AMBER),
                        ));
                    }
                }
            }
            lines.push(Line::raw(""));
            lines.push(Line::raw(
                "Press m to add mnemonic recovery, b to add device-bound, c to add certificate-wrapped, w to rewrap the selected certificate slot, l to relabel the selected keyslot, o to rotate the selected mnemonic slot, p to rotate the recovery secret, d to remove the selected non-recovery slot, or r to rebind the selected device slot.",
            ));
            if app.pending_keyslot_removal_confirmation.as_deref() == Some(slot.id.as_str()) {
                lines.push(Line::styled(
                    "Removal confirmation armed for this slot. Press d again to proceed.",
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                ));
            }
            lines
        }
        None => vec![
            Line::styled(
                "Keyslot detail",
                Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw("No keyslot is currently selectable."),
            Line::raw(
                "Press m, b, or c to enroll a new unlock or recovery path, or p to rotate the recovery secret.",
            ),
        ],
    };

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Keyslot Detail")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn edit_keyslot_label_panel(app: &App) -> Paragraph<'static> {
    let form = &app.keyslot_label_form;
    let current_label = selected_keyslot(app)
        .and_then(|slot| slot.label.as_deref())
        .unwrap_or("");
    let lines = vec![
        form_line(
            matches!(form.selected_field(), LabelOnlyField::Label),
            "Label (blank clears it)",
            &form.label,
        ),
        form_action_line(
            matches!(form.selected_field(), LabelOnlyField::Save),
            "Save Keyslot Label",
        ),
        Line::raw(""),
        Line::raw(format!("Current label: {current_label}")),
        Line::raw(
            "This only updates operator-visible metadata. Recovery posture and wrapped key material stay unchanged.",
        ),
    ];

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Edit Keyslot Label")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn add_login_panel(app: &App) -> Paragraph<'static> {
    let form = &app.add_login_form;
    let lines = vec![
        form_line(
            matches!(form.selected_field(), AddLoginField::Title),
            "Title",
            &form.title,
        ),
        form_line(
            matches!(form.selected_field(), AddLoginField::Username),
            "Username",
            &form.username,
        ),
        form_line(
            matches!(form.selected_field(), AddLoginField::Password),
            "Password",
            &form.password,
        ),
        form_line(
            matches!(form.selected_field(), AddLoginField::Url),
            "URL (optional)",
            &form.url,
        ),
        form_line(
            matches!(form.selected_field(), AddLoginField::Notes),
            "Notes (optional)",
            &form.notes,
        ),
        form_line(
            matches!(form.selected_field(), AddLoginField::Folder),
            "Folder (optional)",
            &form.folder,
        ),
        form_line(
            matches!(form.selected_field(), AddLoginField::Tags),
            "Tags (csv)",
            &form.tags,
        ),
        form_action_line(
            matches!(form.selected_field(), AddLoginField::Save),
            "Save Login",
        ),
        Line::raw(""),
        Line::raw("Required: title, username, password."),
        Line::raw("This writes a new encrypted Login record into the current vault."),
    ];

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title(match app.screen {
                    Screen::EditLogin => "Edit Login",
                    _ => "Add Login",
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GREEN))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn add_note_panel(app: &App) -> Paragraph<'static> {
    let form = &app.note_form;
    let lines = vec![
        form_line(
            matches!(form.selected_field(), NoteField::Title),
            "Title",
            &form.title,
        ),
        form_line(
            matches!(form.selected_field(), NoteField::Content),
            "Content",
            &form.content,
        ),
        form_line(
            matches!(form.selected_field(), NoteField::Folder),
            "Folder (optional)",
            &form.folder,
        ),
        form_line(
            matches!(form.selected_field(), NoteField::Tags),
            "Tags (csv)",
            &form.tags,
        ),
        form_action_line(
            matches!(form.selected_field(), NoteField::Save),
            "Save Secure Note",
        ),
        Line::raw(""),
        Line::raw("Required: title, content."),
        Line::raw("This writes a new encrypted SecureNote record into the current vault."),
    ];

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title(match app.screen {
                    Screen::EditNote => "Edit Secure Note",
                    _ => "Add Secure Note",
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn add_card_panel(app: &App) -> Paragraph<'static> {
    let form = &app.card_form;
    let lines = vec![
        form_line(
            matches!(form.selected_field(), CardField::Title),
            "Title",
            &form.title,
        ),
        form_line(
            matches!(form.selected_field(), CardField::Cardholder),
            "Cardholder",
            &form.cardholder_name,
        ),
        form_line(
            matches!(form.selected_field(), CardField::Number),
            "Card number",
            &form.number,
        ),
        form_line(
            matches!(form.selected_field(), CardField::ExpiryMonth),
            "Expiry month",
            &form.expiry_month,
        ),
        form_line(
            matches!(form.selected_field(), CardField::ExpiryYear),
            "Expiry year",
            &form.expiry_year,
        ),
        form_line(
            matches!(form.selected_field(), CardField::SecurityCode),
            "Security code",
            &form.security_code,
        ),
        form_line(
            matches!(form.selected_field(), CardField::BillingZip),
            "Billing zip (optional)",
            &form.billing_zip,
        ),
        form_line(
            matches!(form.selected_field(), CardField::Notes),
            "Notes (optional)",
            &form.notes,
        ),
        form_line(
            matches!(form.selected_field(), CardField::Folder),
            "Folder (optional)",
            &form.folder,
        ),
        form_line(
            matches!(form.selected_field(), CardField::Tags),
            "Tags (csv)",
            &form.tags,
        ),
        form_action_line(
            matches!(form.selected_field(), CardField::Save),
            "Save Card",
        ),
        Line::raw(""),
        Line::raw("Required: title, cardholder, card number, expiry month/year, security code."),
        Line::raw("This writes a new encrypted Card record into the current vault."),
    ];

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title(match app.screen {
                    Screen::EditCard => "Edit Card",
                    _ => "Add Card",
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn add_identity_panel(app: &App) -> Paragraph<'static> {
    let form = &app.identity_form;
    let lines = vec![
        form_line(
            matches!(form.selected_field(), IdentityField::Title),
            "Title",
            &form.title,
        ),
        form_line(
            matches!(form.selected_field(), IdentityField::FullName),
            "Full name",
            &form.full_name,
        ),
        form_line(
            matches!(form.selected_field(), IdentityField::Email),
            "Email (optional)",
            &form.email,
        ),
        form_line(
            matches!(form.selected_field(), IdentityField::Phone),
            "Phone (optional)",
            &form.phone,
        ),
        form_line(
            matches!(form.selected_field(), IdentityField::Address),
            "Address (optional)",
            &form.address,
        ),
        form_line(
            matches!(form.selected_field(), IdentityField::Notes),
            "Notes (optional)",
            &form.notes,
        ),
        form_line(
            matches!(form.selected_field(), IdentityField::Folder),
            "Folder (optional)",
            &form.folder,
        ),
        form_line(
            matches!(form.selected_field(), IdentityField::Tags),
            "Tags (csv)",
            &form.tags,
        ),
        form_action_line(
            matches!(form.selected_field(), IdentityField::Save),
            "Save Identity",
        ),
        Line::raw(""),
        Line::raw("Required: title, full name."),
        Line::raw("This writes a new encrypted Identity record into the current vault."),
    ];

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title(match app.screen {
                    Screen::EditIdentity => "Edit Identity",
                    _ => "Add Identity",
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn add_mnemonic_slot_panel(app: &App) -> Paragraph<'static> {
    let form = &app.mnemonic_slot_form;
    let lines = vec![
        form_line(
            matches!(form.selected_field(), LabelOnlyField::Label),
            "Label (optional)",
            &form.label,
        ),
        form_action_line(
            matches!(form.selected_field(), LabelOnlyField::Save),
            "Enroll Mnemonic Slot",
        ),
        Line::raw(""),
        Line::raw("A 24-word recovery phrase will be generated and shown once after saving."),
        Line::raw("Store it offline. This path is for disaster recovery, not daily use."),
    ];

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Add Mnemonic Slot")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn add_device_slot_panel(app: &App) -> Paragraph<'static> {
    let form = &app.device_slot_form;
    let lines = vec![
        form_line(
            matches!(form.selected_field(), LabelOnlyField::Label),
            "Label (optional)",
            &form.label,
        ),
        form_action_line(
            matches!(form.selected_field(), LabelOnlyField::Save),
            "Enroll Device Slot",
        ),
        Line::raw(""),
        Line::raw(
            "This stores the unwrap secret in platform secure storage for passwordless daily unlock.",
        ),
        Line::raw("Keep a separate recovery path active before relying on device-bound access."),
    ];

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Add Device Slot")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn add_certificate_slot_panel(app: &App) -> Paragraph<'static> {
    let form = &app.certificate_slot_form;
    let mut lines = vec![
        form_line(
            matches!(form.selected_field(), CertificateField::Label),
            "Label (optional)",
            &form.label,
        ),
        form_line(
            matches!(form.selected_field(), CertificateField::CertPath),
            "Recipient cert PEM path",
            &form.cert_path,
        ),
        form_action_line(
            matches!(form.selected_field(), CertificateField::Save),
            "Enroll Certificate Slot",
        ),
        Line::raw(""),
        Line::raw("The certificate file must already exist on disk in PEM format."),
        Line::raw("Only the public recipient certificate is needed to enroll this slot."),
    ];
    lines.extend(certificate_preview_lines(form.cert_path.as_str()));

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Add Certificate Slot")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn rewrap_certificate_slot_panel(app: &App) -> Paragraph<'static> {
    let form = &app.certificate_rewrap_form;
    let current = selected_keyslot(app);
    let mut lines = vec![
        form_line(
            matches!(form.selected_field(), CertificateRewrapField::CertPath),
            "Replacement cert PEM path",
            &form.cert_path,
        ),
        form_line(
            matches!(form.selected_field(), CertificateRewrapField::KeyPath),
            "Replacement key PEM path (optional)",
            &form.key_path,
        ),
        form_line(
            matches!(form.selected_field(), CertificateRewrapField::KeyPassphrase),
            "Replacement key passphrase (optional)",
            &masked_value(&form.key_passphrase),
        ),
        form_action_line(
            matches!(form.selected_field(), CertificateRewrapField::Save),
            "Rewrap Certificate Slot",
        ),
        Line::raw(""),
        Line::raw(format!(
            "Current fingerprint: {}",
            current
                .and_then(|slot| slot.certificate_fingerprint_sha256.as_deref())
                .unwrap_or("")
        )),
        Line::raw(format!(
            "Current subject: {}",
            current
                .and_then(|slot| slot.certificate_subject.as_deref())
                .unwrap_or("")
        )),
        Line::raw(format!(
            "Current valid from: {}",
            current
                .and_then(|slot| slot.certificate_not_before.as_deref())
                .unwrap_or("")
        )),
        Line::raw(format!(
            "Current valid until: {}",
            current
                .and_then(|slot| slot.certificate_not_after.as_deref())
                .unwrap_or("")
        )),
        Line::raw(
            "This replaces the recipient certificate while preserving the same keyslot id and recovery posture semantics.",
        ),
        Line::raw(
            "Leave replacement key path/passphrase blank to keep the active native session key settings unchanged.",
        ),
    ];
    lines.extend(certificate_preview_lines(form.cert_path.as_str()));

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Rewrap Certificate Slot")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn certificate_preview_lines(cert_path: &str) -> Vec<Line<'static>> {
    let cert_path = cert_path.trim();
    if cert_path.is_empty() {
        return Vec::new();
    }

    let mut lines = vec![Line::raw(""), Line::raw("Certificate preview")];
    match fs::read(cert_path) {
        Ok(cert_pem) => match inspect_certificate_pem(cert_pem.as_slice()) {
            Ok(preview) => {
                lines.push(Line::raw(format!(
                    "fingerprint: {}",
                    preview.fingerprint_sha256
                )));
                lines.push(Line::raw(format!("subject: {}", preview.subject)));
                lines.push(Line::raw(format!("valid from: {}", preview.not_before)));
                lines.push(Line::raw(format!("valid until: {}", preview.not_after)));
            }
            Err(error) => {
                lines.push(Line::styled(
                    format!("preview unavailable: {error}"),
                    Style::default().fg(RED),
                ));
            }
        },
        Err(error) => {
            lines.push(Line::styled(
                format!("preview unavailable: {error}"),
                Style::default().fg(RED),
            ));
        }
    }
    lines
}

fn rotate_recovery_secret_panel(app: &App) -> Paragraph<'static> {
    let form = &app.recovery_secret_form;
    let lines = vec![
        form_line(
            matches!(form.selected_field(), RecoverySecretField::NewSecret),
            "New recovery secret",
            &masked_value(&form.new_secret),
        ),
        form_line(
            matches!(form.selected_field(), RecoverySecretField::Confirm),
            "Confirm recovery secret",
            &masked_value(&form.confirm_secret),
        ),
        form_action_line(
            matches!(form.selected_field(), RecoverySecretField::Save),
            "Rotate Recovery Secret",
        ),
        Line::raw(""),
        Line::raw(
            "This only rewraps the password recovery keyslot. Mnemonic, device, and certificate slots stay intact.",
        ),
        Line::raw(
            "Use this after moving to passwordless daily unlock so the offline recovery secret does not stay frozen at vault-init time.",
        ),
    ];

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Rotate Recovery Secret")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn rotate_mnemonic_slot_panel(app: &App) -> Paragraph<'static> {
    let lines = match selected_keyslot(app) {
        Some(slot) => vec![
            Line::styled(
                "Rotate Mnemonic Slot",
                Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw(format!("slot id: {}", slot.id)),
            Line::raw(format!(
                "label: {}",
                slot.label.as_deref().unwrap_or("(cleared)")
            )),
            Line::raw(""),
            Line::raw(
                "This replaces the existing offline recovery phrase while preserving the same keyslot id and wrapped vault master key semantics.",
            ),
            Line::raw(
                "The old phrase will stop unlocking immediately after rotation. The replacement phrase will be shown once on the next screen.",
            ),
            Line::raw(""),
            Line::raw("Press y or Enter to rotate, or Esc to cancel."),
            Line::raw(""),
            Line::styled(app.status.clone(), Style::default().fg(TEXT)),
        ],
        None => vec![
            Line::raw("No mnemonic keyslot is currently selectable."),
            Line::raw("Return to keyslots and select a mnemonic recovery slot first."),
            Line::raw(""),
            Line::styled(app.status.clone(), Style::default().fg(TEXT)),
        ],
    };

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Rotate Mnemonic")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn mnemonic_reveal_panel(app: &App) -> Paragraph<'static> {
    let lines = match &app.latest_mnemonic_enrollment {
        Some(enrollment) => vec![
            Line::styled(
                "Mnemonic Recovery Phrase",
                Style::default().fg(RED).add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw(format!("slot id: {}", enrollment.keyslot.id)),
            Line::raw(format!(
                "label: {}",
                enrollment.keyslot.label.as_deref().unwrap_or("")
            )),
            Line::raw(""),
            Line::raw(enrollment.mnemonic.clone()),
            Line::raw(""),
            Line::raw("Write this phrase down and store it offline."),
            Line::raw("Press c to copy it temporarily, then Enter or Esc to return to keyslots."),
        ],
        None => vec![
            Line::styled(
                "Mnemonic Recovery",
                Style::default().fg(RED).add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw("No mnemonic enrollment is available to display."),
        ],
    };

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Recovery Phrase")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(RED))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn delete_confirm_panel(app: &App) -> Paragraph<'static> {
    let lines = match &app.detail {
        Some(item) => match &item.payload {
            VaultItemPayload::Login(login) => vec![
                Line::styled(
                    "Confirm delete",
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw(format!("id: {}", item.id)),
                Line::raw(format!("title: {}", login.title)),
                Line::raw(format!("username: {}", login.username)),
                Line::raw(""),
                Line::raw("This removes the encrypted vault record permanently."),
                Line::raw("Press y or Enter to delete, or n / Esc to cancel."),
            ],
            VaultItemPayload::SecureNote(note) => vec![
                Line::styled(
                    "Confirm delete",
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw(format!("id: {}", item.id)),
                Line::raw(format!("title: {}", note.title)),
                Line::raw(""),
                Line::raw("This removes the encrypted vault record permanently."),
                Line::raw("Press y or Enter to delete, or n / Esc to cancel."),
            ],
            VaultItemPayload::Card(card) => vec![
                Line::styled(
                    "Confirm delete",
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw(format!("id: {}", item.id)),
                Line::raw(format!("title: {}", card.title)),
                Line::raw(format!("cardholder: {}", card.cardholder_name)),
                Line::raw(""),
                Line::raw("This removes the encrypted vault record permanently."),
                Line::raw("Press y or Enter to delete, or n / Esc to cancel."),
            ],
            VaultItemPayload::Identity(identity) => vec![
                Line::styled(
                    "Confirm delete",
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw(format!("id: {}", item.id)),
                Line::raw(format!("title: {}", identity.title)),
                Line::raw(format!("full name: {}", identity.full_name)),
                Line::raw(""),
                Line::raw("This removes the encrypted vault record permanently."),
                Line::raw("Press y or Enter to delete, or n / Esc to cancel."),
            ],
        },
        None => vec![
            Line::styled(
                "No selection",
                Style::default().fg(RED).add_modifier(Modifier::BOLD),
            ),
            Line::raw("No vault item is currently selected for deletion."),
        ],
    };

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Delete Item")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(RED))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn generate_store_panel(app: &App) -> Paragraph<'static> {
    let form = &app.generate_store_form;
    let action_label = if form.target_login_id.is_some() {
        "Generate + Rotate Login"
    } else {
        "Generate + Store"
    };
    let form_title = if form.target_login_id.is_some() {
        "Generate + Rotate"
    } else {
        "Generate + Store"
    };
    let mut lines = vec![
        form_line(
            matches!(form.selected_field(), GenerateField::Title),
            "Title",
            &form.title,
        ),
        form_line(
            matches!(form.selected_field(), GenerateField::Username),
            "Username",
            &form.username,
        ),
        form_line(
            matches!(form.selected_field(), GenerateField::Url),
            "URL (optional)",
            &form.url,
        ),
        form_line(
            matches!(form.selected_field(), GenerateField::Notes),
            "Notes (optional)",
            &form.notes,
        ),
        form_line(
            matches!(form.selected_field(), GenerateField::Folder),
            "Folder (optional)",
            &form.folder,
        ),
        form_line(
            matches!(form.selected_field(), GenerateField::Tags),
            "Tags (csv)",
            &form.tags,
        ),
        form_line(
            matches!(form.selected_field(), GenerateField::Length),
            "Password length",
            &form.length,
        ),
        form_line(
            matches!(form.selected_field(), GenerateField::Frameworks),
            "Framework IDs (csv)",
            &form.frameworks,
        ),
        form_line(
            matches!(form.selected_field(), GenerateField::MinLower),
            "Min lowercase",
            &form.min_lower,
        ),
        form_line(
            matches!(form.selected_field(), GenerateField::MinUpper),
            "Min uppercase",
            &form.min_upper,
        ),
        form_line(
            matches!(form.selected_field(), GenerateField::MinDigits),
            "Min digits",
            &form.min_digits,
        ),
        form_line(
            matches!(form.selected_field(), GenerateField::MinSymbols),
            "Min symbols",
            &form.min_symbols,
        ),
        form_action_line(
            matches!(form.selected_field(), GenerateField::Save),
            action_label,
        ),
        Line::raw(""),
    ];
    lines.extend(generate_request_preview(form));

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title(form_title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GREEN))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn export_backup_panel(app: &App) -> Paragraph<'static> {
    let form = &app.export_backup_form;
    let mut lines = vec![
        form_line(
            matches!(form.selected_field(), ExportBackupField::Path),
            "Backup output path",
            &form.path,
        ),
        form_action_line(
            matches!(form.selected_field(), ExportBackupField::Save),
            "Export Backup",
        ),
        Line::raw(""),
        Line::raw(
            "This writes the current encrypted vault header and ciphertext rows into a portable JSON package.",
        ),
        Line::raw("The live vault file is not modified by export."),
    ];
    lines.extend(backup_preview_lines(
        current_vault_backup_summary(app).as_ref(),
    ));

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Export Backup")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn export_transfer_panel(app: &App) -> Paragraph<'static> {
    let form = &app.export_transfer_form;
    let package_password = if form.package_password.trim().is_empty() {
        "(unset)"
    } else {
        "(set)"
    };
    let cert_path = if form.cert_path.trim().is_empty() {
        "(unset)"
    } else {
        form.cert_path.as_str()
    };
    let mut lines = vec![
        form_line(
            matches!(form.selected_field(), ExportTransferField::Path),
            "Transfer output path",
            &form.path,
        ),
        form_line(
            matches!(form.selected_field(), ExportTransferField::PackagePassword),
            "Package recovery secret",
            package_password,
        ),
        form_line(
            matches!(form.selected_field(), ExportTransferField::CertPath),
            "Recipient cert path",
            cert_path,
        ),
        form_action_line(
            matches!(form.selected_field(), ExportTransferField::Save),
            "Export Transfer",
        ),
        Line::raw(""),
        Line::raw(
            "This writes the currently filtered decrypted item payloads into a separate encrypted transfer package.",
        ),
        Line::raw("Provide a package recovery secret, a recipient certificate, or both."),
    ];
    lines.extend(current_transfer_selection_lines(app, form));

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Export Transfer")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn import_backup_panel(app: &App) -> Paragraph<'static> {
    let form = &app.import_backup_form;
    let overwrite = if form.overwrite { "yes" } else { "no" };
    let mut lines = vec![
        form_line(
            matches!(form.selected_field(), ImportBackupField::Path),
            "Backup input path",
            &form.path,
        ),
        form_line(
            matches!(form.selected_field(), ImportBackupField::Overwrite),
            "Overwrite current vault",
            overwrite,
        ),
        form_action_line(
            matches!(form.selected_field(), ImportBackupField::Save),
            "Import Backup",
        ),
        Line::raw(""),
        Line::raw(format!(
            "Destination vault path: {}",
            app.options.path.display()
        )),
        Line::raw("Import replaces the current local vault file when overwrite is enabled."),
        Line::raw("Use this for restore and migration, not for ad hoc editing of the backup JSON."),
    ];
    lines.extend(backup_preview_lines(
        inspected_backup_summary(form.path.as_str()).as_ref(),
    ));

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Import Backup")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(RED))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn import_transfer_panel(app: &App) -> Paragraph<'static> {
    let form = &app.import_transfer_form;
    let replace_existing = if form.replace_existing { "yes" } else { "no" };
    let package_password = if form.package_password.trim().is_empty() {
        "(unset)"
    } else {
        "(set)"
    };
    let cert_path = if form.cert_path.trim().is_empty() {
        "(unset)"
    } else {
        form.cert_path.as_str()
    };
    let key_path = if form.key_path.trim().is_empty() {
        "(unset)"
    } else {
        form.key_path.as_str()
    };
    let key_passphrase = if form.key_passphrase.trim().is_empty() {
        "(unset)"
    } else {
        "(set)"
    };
    let mut lines = vec![
        form_line(
            matches!(form.selected_field(), ImportTransferField::Path),
            "Transfer input path",
            &form.path,
        ),
        form_line(
            matches!(form.selected_field(), ImportTransferField::ReplaceExisting),
            "Replace conflicting ids",
            replace_existing,
        ),
        form_line(
            matches!(form.selected_field(), ImportTransferField::PackagePassword),
            "Package recovery secret",
            package_password,
        ),
        form_line(
            matches!(form.selected_field(), ImportTransferField::CertPath),
            "Recipient cert path",
            cert_path,
        ),
        form_line(
            matches!(form.selected_field(), ImportTransferField::KeyPath),
            "Private key path",
            key_path,
        ),
        form_line(
            matches!(form.selected_field(), ImportTransferField::KeyPassphrase),
            "Private key passphrase",
            key_passphrase,
        ),
        form_action_line(
            matches!(form.selected_field(), ImportTransferField::Save),
            "Import Transfer",
        ),
        Line::raw(""),
        Line::raw(format!(
            "Destination vault path: {}",
            app.options.path.display()
        )),
        Line::raw(
            "Choose either the package recovery secret or the certificate keypair for unwrap.",
        ),
        Line::raw("Conflicting ids are remapped safely unless replacement is enabled."),
    ];
    lines.extend(transfer_preview_lines(
        inspected_transfer_summary(form.path.as_str()).as_ref(),
    ));

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Import Transfer")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(RED))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn current_vault_backup_summary(app: &App) -> Result<VaultBackupSummary, anyhow::Error> {
    let vault = unlock_vault_for_options(&app.options)?;
    Ok(vault.backup_summary()?)
}

fn inspected_backup_summary(path: &str) -> Result<VaultBackupSummary, anyhow::Error> {
    let path = path.trim();
    if path.is_empty() {
        anyhow::bail!("enter a backup path to inspect the package summary");
    }
    Ok(inspect_vault_backup(path)?)
}

fn inspected_transfer_summary(path: &str) -> Result<VaultTransferSummary, anyhow::Error> {
    let path = path.trim();
    if path.is_empty() {
        anyhow::bail!("enter a transfer path to inspect the package summary");
    }
    Ok(inspect_vault_transfer(path)?)
}

fn backup_preview_lines(
    summary: Result<&VaultBackupSummary, &anyhow::Error>,
) -> Vec<Line<'static>> {
    match summary {
        Ok(summary) => {
            let mut lines = vec![
                Line::raw(""),
                Line::raw("Backup summary"),
                Line::raw(format!(
                    "restorable: {} · exported_at_epoch: {}",
                    summary.restorable_by_current_build, summary.exported_at_epoch
                )),
                Line::raw(format!(
                    "items: total={} login={} note={} card={} identity={}",
                    summary.item_count,
                    summary.login_count,
                    summary.secure_note_count,
                    summary.card_count,
                    summary.identity_count
                )),
                Line::raw(format!(
                    "keyslots: total={} recovery={} cert={} recommended={}",
                    summary.keyslot_count,
                    summary.recovery_posture.has_recovery_path,
                    summary.recovery_posture.has_certificate_path,
                    summary.recovery_posture.meets_recommended_posture
                )),
                Line::raw(format!(
                    "formats: backup={} vault={} header={}",
                    summary.backup_format_version,
                    summary.vault_format_version,
                    summary.header_format_version
                )),
            ];
            for keyslot in summary.keyslots.iter().take(3) {
                lines.push(Line::raw(format!(
                    "keyslot: {} · {} · {}",
                    keyslot.id,
                    keyslot.kind.as_str(),
                    keyslot.label.as_deref().unwrap_or("")
                )));
                if let Some(subject) = &keyslot.certificate_subject {
                    lines.push(Line::raw(format!("  subject: {subject}")));
                }
                if let Some(not_after) = &keyslot.certificate_not_after {
                    lines.push(Line::raw(format!("  valid until: {not_after}")));
                }
            }
            if summary.keyslots.len() > 3 {
                lines.push(Line::raw(format!(
                    "… {} more keyslots not shown in preview",
                    summary.keyslots.len() - 3
                )));
            }
            for warning in summary.warnings.iter().take(3) {
                lines.push(Line::raw(format!("warning: {warning}")));
            }
            lines
        }
        Err(error) => vec![
            Line::raw(""),
            Line::raw(format!("Backup summary unavailable: {error}")),
        ],
    }
}

fn current_transfer_selection_lines(app: &App, form: &ExportTransferForm) -> Vec<Line<'static>> {
    let mut login_count = 0;
    let mut secure_note_count = 0;
    let mut card_count = 0;
    let mut identity_count = 0;
    for item in &app.items {
        match item.kind {
            VaultItemKind::Login => login_count += 1,
            VaultItemKind::SecureNote => secure_note_count += 1,
            VaultItemKind::Card => card_count += 1,
            VaultItemKind::Identity => identity_count += 1,
        }
    }
    let mut lines = vec![
        Line::raw(""),
        Line::raw("Transfer selection"),
        Line::raw(format!("filters: {}", app.filters.summary())),
        Line::raw(format!(
            "items: total={} login={} note={} card={} identity={}",
            app.items.len(),
            login_count,
            secure_note_count,
            card_count,
            identity_count
        )),
        Line::raw(format!(
            "unwrap paths: recovery_secret={} certificate={}",
            !form.package_password.trim().is_empty(),
            !form.cert_path.trim().is_empty()
        )),
    ];
    if app.items.is_empty() {
        lines.push(Line::raw(
            "warning: the current filter matches no vault items.",
        ));
    }
    lines
}

fn transfer_preview_lines(
    summary: Result<&VaultTransferSummary, &anyhow::Error>,
) -> Vec<Line<'static>> {
    match summary {
        Ok(summary) => {
            let mut lines = vec![
                Line::raw(""),
                Line::raw("Transfer summary"),
                Line::raw(format!(
                    "importable: {} · exported_at_epoch: {}",
                    summary.importable_by_current_build, summary.exported_at_epoch
                )),
                Line::raw(format!(
                    "items: total={} login={} note={} card={} identity={}",
                    summary.item_count,
                    summary.login_count,
                    summary.secure_note_count,
                    summary.card_count,
                    summary.identity_count
                )),
                Line::raw(format!(
                    "filters: query={} kind={} folder={} tag={}",
                    summary.filter.query.clone().unwrap_or_default(),
                    summary
                        .filter
                        .kind
                        .as_ref()
                        .map(VaultItemKind::as_str)
                        .unwrap_or_default(),
                    summary.filter.folder.clone().unwrap_or_default(),
                    summary.filter.tag.clone().unwrap_or_default()
                )),
                Line::raw(format!(
                    "unwrap paths: recovery_secret={} certificate={}",
                    summary.has_recovery_path, summary.has_certificate_path
                )),
            ];
            if let Some(subject) = &summary.certificate_subject {
                lines.push(Line::raw(format!("certificate subject: {subject}")));
            }
            if let Some(not_after) = &summary.certificate_not_after {
                lines.push(Line::raw(format!("certificate valid until: {not_after}")));
            }
            for warning in summary.warnings.iter().take(3) {
                lines.push(Line::raw(format!("warning: {warning}")));
            }
            lines
        }
        Err(error) => vec![
            Line::raw(""),
            Line::raw(format!("Transfer summary unavailable: {error}")),
        ],
    }
}

fn form_line(selected: bool, label: &str, value: &str) -> Line<'static> {
    let style = if selected {
        Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(TEXT)
    };
    let prefix = if selected { "› " } else { "  " };
    Line::from(vec![
        Span::styled(prefix.to_string(), style),
        Span::styled(format!("{label}: {value}"), style),
    ])
}

fn form_action_line(selected: bool, label: &str) -> Line<'static> {
    let style = if selected {
        Style::default().fg(BLUE).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(TEXT)
    };
    let prefix = if selected { "› " } else { "  " };
    Line::from(vec![
        Span::styled(prefix.to_string(), style),
        Span::styled(label.to_string(), style),
    ])
}

fn masked_value(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        "•".repeat(value.chars().count())
    }
}

fn default_backup_export_path(vault_path: &std::path::Path) -> String {
    let mut path = vault_path.to_path_buf();
    path.set_extension("backup.json");
    path.display().to_string()
}

fn default_transfer_export_path(vault_path: &std::path::Path) -> String {
    let mut path = vault_path.to_path_buf();
    path.set_extension("transfer.ppvt.json");
    path.display().to_string()
}

fn generate_request_preview(form: &GenerateStoreForm) -> Vec<Line<'static>> {
    match build_generate_request(form) {
        Ok(request) => {
            let resolved = request.resolve().expect("request already validated");
            let frameworks = if request.selected_frameworks.is_empty() {
                "none".to_string()
            } else {
                request
                    .selected_frameworks
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            vec![
                Line::styled(
                    "Generation preview",
                    Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
                ),
                Line::raw(format!("Frameworks: {frameworks}")),
                Line::raw(format!(
                    "Effective charset size: {}",
                    resolved.charset.len()
                )),
                Line::raw(format!("Length: {}", resolved.length)),
                Line::raw(format!(
                    "Manual minima: lower={} upper={} digits={} symbols={}",
                    resolved.requirements.min_lowercase,
                    resolved.requirements.min_uppercase,
                    resolved.requirements.min_digits,
                    resolved.requirements.min_symbols
                )),
            ]
        }
        Err(error) => vec![
            Line::styled(
                "Generation preview",
                Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
            ),
            Line::styled(format!("Blocked: {error}"), Style::default().fg(RED)),
        ],
    }
}

fn normalize_optional_field(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_tags_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn clear_clipboard_if_matches(expected: &str) -> Result<bool, arboard::Error> {
    let mut clipboard = Clipboard::new()?;
    match clipboard.get_text() {
        Ok(current) if current == expected => {
            clipboard.set_text(String::new())?;
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(_) => Ok(false),
    }
}

fn selected_keyslot(app: &App) -> Option<&paranoid_vault::VaultKeyslot> {
    app.header
        .as_ref()
        .and_then(|header| header.keyslots.get(app.selected_keyslot_index))
}

fn build_generate_request(form: &GenerateStoreForm) -> anyhow::Result<ParanoidRequest> {
    let mut request = ParanoidRequest {
        count: 1,
        ..ParanoidRequest::default()
    };
    request.length = parse_usize_field(form.length.trim(), "length")?;
    request.requirements.min_lowercase = parse_usize_field(form.min_lower.trim(), "min lowercase")?;
    request.requirements.min_uppercase = parse_usize_field(form.min_upper.trim(), "min uppercase")?;
    request.requirements.min_digits = parse_usize_field(form.min_digits.trim(), "min digits")?;
    request.requirements.min_symbols = parse_usize_field(form.min_symbols.trim(), "min symbols")?;
    request.selected_frameworks = parse_frameworks_csv(form.frameworks.trim())?;
    request.resolve()?;
    Ok(request)
}

fn parse_usize_field(raw: &str, label: &str) -> anyhow::Result<usize> {
    if raw.is_empty() {
        return Err(anyhow::anyhow!("{label} is required"));
    }
    raw.parse::<usize>()
        .map_err(|error| anyhow::anyhow!("{label} must be an integer: {error}"))
}

fn parse_frameworks_csv(raw: &str) -> anyhow::Result<Vec<FrameworkId>> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut frameworks = Vec::new();
    for value in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let framework = FrameworkId::parse(value)
            .ok_or_else(|| anyhow::anyhow!("unknown framework: {value}"))?;
        if !frameworks.contains(&framework) {
            frameworks.push(framework);
        }
    }
    Ok(frameworks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509NameBuilder},
    };
    use paranoid_vault::{
        SecretString, VaultAuth, init_vault, unlock_vault, unlock_vault_with_mnemonic,
    };
    use std::{fs, path::Path, path::PathBuf, thread, time::Duration};
    use tempfile::tempdir;

    fn render_to_string(app: &App) -> String {
        let backend = TestBackend::new(120, 42);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal.draw(|frame| render(frame, app)).expect("draw");
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    fn app_options(path: &std::path::Path) -> VaultOpenOptions {
        VaultOpenOptions {
            path: path.to_path_buf(),
            auth: VaultAuth::PasswordEnv("PARANOID_TUI_TEST_PASSWORD".to_string()),
            mnemonic_phrase_env: None,
            mnemonic_phrase: None,
            mnemonic_slot: None,
            device_slot: None,
            use_device_auto: false,
        }
    }

    fn add_device_fallback(options: &VaultOpenOptions) -> anyhow::Result<()> {
        let mut vault = unlock_vault(&options.path, "correct horse battery staple")?;
        vault.add_device_keyslot(Some("tui-test".to_string()))?;
        Ok(())
    }

    fn password_only_options(path: &std::path::Path) -> VaultOpenOptions {
        VaultOpenOptions {
            path: path.to_path_buf(),
            auth: VaultAuth::PasswordEnv("PARANOID_TUI_MISSING_PASSWORD".to_string()),
            mnemonic_phrase_env: None,
            mnemonic_phrase: None,
            mnemonic_slot: None,
            device_slot: None,
            use_device_auto: false,
        }
    }

    fn write_test_certificate_pair(dir: &Path, prefix: &str) -> (PathBuf, PathBuf) {
        let rsa = Rsa::generate(2048).expect("rsa");
        let pkey = PKey::from_rsa(rsa).expect("pkey");

        let mut name = X509NameBuilder::new().expect("name builder");
        name.append_entry_by_text("CN", &format!("{prefix}.example"))
            .expect("common name");
        let name = name.build();

        let mut builder = X509::builder().expect("x509 builder");
        builder.set_version(2).expect("version");
        let serial = BigNum::from_u32(1)
            .expect("serial bignum")
            .to_asn1_integer()
            .expect("serial integer");
        builder
            .set_serial_number(serial.as_ref())
            .expect("serial number");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&pkey).expect("pubkey");
        let not_before = Asn1Time::days_from_now(0).expect("not before");
        builder
            .set_not_before(not_before.as_ref())
            .expect("set not before");
        let not_after = Asn1Time::days_from_now(365).expect("not after");
        builder
            .set_not_after(not_after.as_ref())
            .expect("set not after");
        builder
            .sign(&pkey, MessageDigest::sha256())
            .expect("sign certificate");
        let certificate = builder.build();

        let cert_path = dir.join(format!("{prefix}-cert.pem"));
        let key_path = dir.join(format!("{prefix}-key.pem"));
        fs::write(&cert_path, certificate.to_pem().expect("cert pem")).expect("write cert");
        fs::write(&key_path, pkey.private_key_to_pem_pkcs8().expect("key pem")).expect("write key");
        (cert_path, key_path)
    }

    #[test]
    fn vault_view_renders_selected_login_details() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let item = vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: Some("https://github.com".to_string()),
                notes: Some("primary code host".to_string()),
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string(), "code".to_string()],
            })
            .expect("add login");
        let header = read_vault_header(&path).expect("header");
        let items = vault.list_items().expect("items");
        let app = App {
            options,
            screen: Screen::Vault,
            status: "test render".to_string(),
            header: Some(header),
            items,
            selected_index: 0,
            selected_keyslot_index: 0,
            detail: Some(item),
            filters: VaultFilterState::default(),
            search_mode: false,
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
            export_transfer_form: ExportTransferForm::default(),
            import_backup_form: ImportBackupForm::default(),
            import_transfer_form: ImportTransferForm::default(),
            editing_item_id: None,
            session: NativeSessionHardening::default(),
        };
        let rendered = render_to_string(&app);
        assert!(rendered.contains("Vault"));
        assert!(rendered.contains("GitHub"));
        assert!(rendered.contains("folder: Work"));
        assert!(rendered.contains("Press a to add, e to edit, d to delete"));
    }

    #[test]
    fn add_login_form_submission_persists_item() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        app.open_add_login();
        app.add_login_form.title = "GitHub".to_string();
        app.add_login_form.username = "octocat".to_string();
        app.add_login_form.password = "hunter2".to_string();
        app.add_login_form.url = "https://github.com".to_string();
        app.add_login_form.folder = "Work".to_string();
        app.add_login_form.tags = "work,code".to_string();
        app.submit_login_form();

        assert!(matches!(app.screen, Screen::Vault));
        assert_eq!(app.items.len(), 1);
        let VaultItemPayload::Login(login) = &app.detail.expect("detail").payload else {
            panic!("expected login");
        };
        assert_eq!(login.title, "GitHub");
        assert_eq!(login.username, "octocat");
        assert_eq!(login.folder.as_deref(), Some("Work"));
        assert_eq!(login.tags, vec!["work".to_string(), "code".to_string()]);
        assert!(app.status.contains("Stored login item"));
    }

    #[test]
    fn add_secure_note_form_submission_persists_item() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        app.open_add_note();
        app.note_form.title = "Recovery Plan".to_string();
        app.note_form.content = "Paper copy in the safe.".to_string();
        app.note_form.folder = "Recovery".to_string();
        app.note_form.tags = "recovery,offline".to_string();
        app.submit_note_form();

        assert!(matches!(app.screen, Screen::Vault));
        assert_eq!(app.items.len(), 1);
        let VaultItemPayload::SecureNote(note) = &app.detail.expect("detail").payload else {
            panic!("expected secure note");
        };
        assert_eq!(note.title, "Recovery Plan");
        assert_eq!(note.folder.as_deref(), Some("Recovery"));
        assert_eq!(
            note.tags,
            vec!["recovery".to_string(), "offline".to_string()]
        );
        assert!(app.status.contains("Stored secure note"));
    }

    #[test]
    fn add_card_form_submission_persists_item() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        app.open_add_card();
        app.card_form.title = "Backup Mastercard".to_string();
        app.card_form.cardholder_name = "Jon Bogaty".to_string();
        app.card_form.number = "5555444433331111".to_string();
        app.card_form.expiry_month = "11".to_string();
        app.card_form.expiry_year = "2030".to_string();
        app.card_form.security_code = "999".to_string();
        app.card_form.billing_zip = "73301".to_string();
        app.card_form.folder = "Travel".to_string();
        app.card_form.tags = "finance,travel".to_string();
        app.submit_card_form();

        assert!(matches!(app.screen, Screen::Vault));
        assert_eq!(app.items.len(), 1);
        let VaultItemPayload::Card(card) = &app.detail.expect("detail").payload else {
            panic!("expected card");
        };
        assert_eq!(card.title, "Backup Mastercard");
        assert_eq!(card.cardholder_name, "Jon Bogaty");
        assert_eq!(card.billing_zip.as_deref(), Some("73301"));
        assert_eq!(card.folder.as_deref(), Some("Travel"));
        assert_eq!(card.tags, vec!["finance".to_string(), "travel".to_string()]);
        assert!(app.status.contains("Stored card"));
    }

    #[test]
    fn add_identity_form_submission_persists_item() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        app.open_add_identity();
        app.identity_form.title = "Personal Identity".to_string();
        app.identity_form.full_name = "Jon Bogaty".to_string();
        app.identity_form.email = "jon@example.com".to_string();
        app.identity_form.phone = "+1-555-0100".to_string();
        app.identity_form.address = "123 Main St".to_string();
        app.identity_form.folder = "Identity".to_string();
        app.identity_form.tags = "identity,travel".to_string();
        app.submit_identity_form();

        assert!(matches!(app.screen, Screen::Vault));
        assert_eq!(app.items.len(), 1);
        let VaultItemPayload::Identity(identity) = &app.detail.expect("detail").payload else {
            panic!("expected identity");
        };
        assert_eq!(identity.title, "Personal Identity");
        assert_eq!(identity.full_name, "Jon Bogaty");
        assert_eq!(identity.email.as_deref(), Some("jon@example.com"));
        assert_eq!(identity.folder.as_deref(), Some("Identity"));
        assert_eq!(
            identity.tags,
            vec!["identity".to_string(), "travel".to_string()]
        );
        assert!(app.status.contains("Stored identity"));
    }

    #[test]
    fn generate_store_submission_persists_generated_item() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        app.open_generate_store();
        app.generate_store_form.title = "GitHub".to_string();
        app.generate_store_form.username = "octocat".to_string();
        app.generate_store_form.folder = "Generated".to_string();
        app.generate_store_form.tags = "generated,work".to_string();
        app.generate_store_form.length = "20".to_string();
        app.generate_store_form.frameworks = "nist".to_string();
        app.submit_generate_store();

        assert!(matches!(app.screen, Screen::Vault));
        assert_eq!(app.items.len(), 1);
        let VaultItemPayload::Login(login) = &app.detail.expect("detail").payload else {
            panic!("expected login");
        };
        assert_eq!(login.title, "GitHub");
        assert_eq!(login.username, "octocat");
        assert_eq!(login.password.len(), 20);
        assert_eq!(login.folder.as_deref(), Some("Generated"));
        assert_eq!(
            login.tags,
            vec!["generated".to_string(), "work".to_string()]
        );
        assert!(app.status.contains("Generator verdict"));
    }

    #[test]
    fn generate_store_can_rotate_selected_login_in_place() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
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
            .expect("add login");

        let mut app = App::new(options);
        app.open_generate_store();
        assert_eq!(
            app.generate_store_form.target_login_id.as_deref(),
            Some(original.id.as_str())
        );
        app.generate_store_form.length = "20".to_string();
        app.generate_store_form.frameworks = "nist".to_string();
        app.submit_generate_store();

        assert!(matches!(app.screen, Screen::Vault));
        let detail = app.detail.expect("detail");
        assert_eq!(detail.id, original.id);
        let VaultItemPayload::Login(login) = detail.payload else {
            panic!("expected login");
        };
        assert_eq!(login.password.len(), 20);
        assert_eq!(login.password_history.len(), 1);
        assert_eq!(login.password_history[0].password, "hunter2");
        assert!(app.status.contains("rotated item"));
    }

    #[test]
    fn search_mode_filters_vault_items() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string(), "octo".to_string()],
            })
            .expect("add github");
        vault
            .add_login(NewLoginRecord {
                title: "Bank".to_string(),
                username: "jon".to_string(),
                password: "hunter3".to_string(),
                url: None,
                notes: Some("monthly".to_string()),
                folder: Some("Finance".to_string()),
                tags: vec!["finance".to_string()],
            })
            .expect("add bank");

        let mut app = App::new(options);
        assert_eq!(app.items.len(), 2);
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('/'))));
        assert!(app.search_mode);
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('o'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('c'))));

        assert_eq!(app.items.len(), 1);
        let VaultItemPayload::Login(login) = &app.detail.expect("detail").payload else {
            panic!("expected login");
        };
        assert_eq!(login.title, "GitHub");
        assert!(app.status.contains("Filtering unlocked vault items by"));
    }

    #[test]
    fn search_mode_supports_structured_filters() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        vault
            .add_login(NewLoginRecord {
                title: "GitHub".to_string(),
                username: "octocat".to_string(),
                password: "hunter2".to_string(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string(), "code".to_string()],
            })
            .expect("add github");
        vault
            .add_card(NewCardRecord {
                title: "Travel Card".to_string(),
                cardholder_name: "Jon Bogaty".to_string(),
                number: "5555444433331111".to_string(),
                expiry_month: "11".to_string(),
                expiry_year: "2030".to_string(),
                security_code: "999".to_string(),
                billing_zip: None,
                notes: None,
                folder: Some("Travel".to_string()),
                tags: vec!["travel".to_string(), "finance".to_string()],
            })
            .expect("add card");

        let mut app = App::new(options);
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('/'))));
        assert!(app.search_mode);
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Tab)));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Right)));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Right)));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Right)));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Tab)));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('t'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('r'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('a'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('v'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('e'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('l'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Tab)));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('f'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('i'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('n'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('a'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('n'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('c'))));
        assert!(!app.handle_key(KeyEvent::from(KeyCode::Char('e'))));

        assert_eq!(app.items.len(), 1);
        assert_eq!(app.items[0].kind, VaultItemKind::Card);
        assert_eq!(app.items[0].title, "Travel Card");
        assert!(app.status.contains("kind=card"));
    }

    #[test]
    fn duplicate_password_counts_surface_in_vault_view() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
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
            .expect("add github");
        vault
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

        let app = App::new(options);
        assert!(
            app.items
                .iter()
                .any(|summary| summary.duplicate_password_count == 1)
        );

        let rendered = render_to_string(&app);
        assert!(rendered.contains("[dup:1]"));
        assert!(rendered.contains("duplicate passwords elsewhere: 1"));
    }

    #[test]
    fn edit_login_form_updates_selected_item() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
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

        let mut app = App::new(options);
        app.open_edit_item();
        app.add_login_form.password = "hunter3".to_string();
        app.add_login_form.notes = "rotated".to_string();
        app.add_login_form.tags = "work,rotated".to_string();
        app.submit_login_form();

        assert!(matches!(app.screen, Screen::Vault));
        let VaultItemPayload::Login(login) = &app.detail.expect("detail").payload else {
            panic!("expected login");
        };
        assert_eq!(login.password, "hunter3");
        assert_eq!(login.notes.as_deref(), Some("rotated"));
        assert_eq!(login.tags, vec!["work".to_string(), "rotated".to_string()]);
        assert_eq!(login.password_history.len(), 1);
        assert_eq!(login.password_history[0].password, "hunter2");
        assert!(app.status.contains("Updated login item"));
    }

    #[test]
    fn delete_confirmation_removes_selected_item() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
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

        let mut app = App::new(options);
        app.open_delete_confirm();
        app.delete_selected_item();

        assert!(matches!(app.screen, Screen::Vault));
        assert!(app.items.is_empty());
        assert!(app.detail.is_none());
        assert!(app.status.contains("Deleted vault item"));
    }

    #[test]
    fn mnemonic_slot_enrollment_shows_phrase_once() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        app.open_keyslots();
        app.open_add_mnemonic_slot();
        app.mnemonic_slot_form.label = "paper-backup".to_string();
        app.submit_mnemonic_slot();

        assert!(matches!(app.screen, Screen::MnemonicReveal));
        let enrollment = app
            .latest_mnemonic_enrollment
            .as_ref()
            .expect("mnemonic enrollment");
        assert_eq!(enrollment.keyslot.label.as_deref(), Some("paper-backup"));
        assert_eq!(enrollment.mnemonic.split_whitespace().count(), 24);
        assert!(
            app.header
                .as_ref()
                .is_some_and(|header| header.keyslots.len() >= 2)
        );
    }

    #[test]
    fn mnemonic_slot_rotation_reveals_replacement_phrase_and_invalidates_old_one() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        app.open_keyslots();
        app.open_add_mnemonic_slot();
        app.mnemonic_slot_form.label = "paper-backup".to_string();
        app.submit_mnemonic_slot();

        let original = app
            .latest_mnemonic_enrollment
            .clone()
            .expect("original enrollment");
        app.screen = Screen::Keyslots;
        app.open_rotate_mnemonic_slot();
        app.submit_rotate_mnemonic_slot();

        assert!(matches!(app.screen, Screen::MnemonicReveal));
        let rotated = app
            .latest_mnemonic_enrollment
            .as_ref()
            .expect("rotated enrollment");
        assert_eq!(rotated.keyslot.id, original.keyslot.id);
        assert_eq!(rotated.keyslot.label, original.keyslot.label);
        assert_ne!(rotated.mnemonic, original.mnemonic);
        assert!(app.status.contains("Mnemonic recovery slot rotated"));
        assert!(
            unlock_vault_with_mnemonic(
                &path,
                original.mnemonic.as_str(),
                Some(original.keyslot.id.as_str())
            )
            .is_err()
        );
        unlock_vault_with_mnemonic(
            &path,
            rotated.mnemonic.as_str(),
            Some(rotated.keyslot.id.as_str()),
        )
        .expect("unlock with rotated phrase");
    }

    #[test]
    fn mnemonic_slot_rotation_updates_native_unlock_options_when_session_uses_mnemonic() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let enrollment = {
            let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
            vault
                .add_mnemonic_keyslot(Some("paper-backup".to_string()))
                .expect("add mnemonic")
        };

        let options = VaultOpenOptions {
            path: path.clone(),
            auth: VaultAuth::PasswordEnv("PARANOID_TUI_TEST_PASSWORD".to_string()),
            mnemonic_phrase_env: None,
            mnemonic_phrase: Some(SecretString::new(enrollment.mnemonic.clone())),
            mnemonic_slot: Some(enrollment.keyslot.id.clone()),
            device_slot: None,
            use_device_auto: false,
        };

        let mut app = App::new(options);
        app.open_keyslots();
        app.selected_keyslot_index = 1;
        app.open_rotate_mnemonic_slot();
        app.submit_rotate_mnemonic_slot();

        let rotated = app
            .latest_mnemonic_enrollment
            .as_ref()
            .expect("rotated enrollment");
        assert_eq!(
            app.options
                .mnemonic_phrase
                .as_ref()
                .map(SecretString::as_str),
            Some(rotated.mnemonic.as_str())
        );
        assert_eq!(
            app.options.mnemonic_slot.as_deref(),
            Some(rotated.keyslot.id.as_str())
        );
        unlock_vault_for_options(&app.options).expect("refresh uses rotated mnemonic");
    }

    #[test]
    fn device_slot_enrollment_updates_header_and_returns_to_keyslots() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        app.open_keyslots();
        app.open_add_device_slot();
        app.device_slot_form.label = "daily".to_string();
        app.submit_device_slot();

        assert!(matches!(app.screen, Screen::Keyslots));
        let header = app.header.as_ref().expect("header");
        assert!(
            header
                .keyslots
                .iter()
                .any(|slot| slot.label.as_deref() == Some("daily"))
        );
        assert!(app.status.contains("Enrolled device-bound keyslot"));
    }

    #[test]
    fn keyslot_relabel_flow_updates_header() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        app.open_keyslots();
        app.open_add_device_slot();
        app.device_slot_form.label = "daily".to_string();
        app.submit_device_slot();

        app.open_edit_keyslot_label();
        app.keyslot_label_form.label = "laptop daily".to_string();
        app.submit_keyslot_label_edit();

        assert!(matches!(app.screen, Screen::Keyslots));
        let selected = selected_keyslot(&app).expect("selected keyslot");
        assert_eq!(selected.label.as_deref(), Some("laptop daily"));
        assert!(app.status.contains("Updated device_bound keyslot"));
    }

    #[test]
    fn certificate_keyslot_rewrap_screen_opens_for_selected_certificate_slot() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        let mut app = App::new(options);
        let mut header = read_vault_header(&path).expect("header");
        header.keyslots.push(paranoid_vault::VaultKeyslot {
            id: "cert-test".to_string(),
            kind: paranoid_vault::VaultKeyslotKind::CertificateWrapped,
            label: Some("ops".to_string()),
            wrapped_by_os_keystore: false,
            wrap_algorithm: "cms-envelope+transport-key+aes-256-gcm".to_string(),
            salt_hex: "00".to_string(),
            nonce_hex: "00".to_string(),
            tag_hex: "00".to_string(),
            encrypted_master_key_hex: "00".to_string(),
            certificate_fingerprint_sha256: Some("abcd".to_string()),
            certificate_subject: Some("CN=ops.example".to_string()),
            certificate_not_before: Some("Apr 16 00:00:00 2026 GMT".to_string()),
            certificate_not_after: Some("Apr 16 00:00:00 2027 GMT".to_string()),
            certificate_not_before_epoch: Some(1_776_307_200),
            certificate_not_after_epoch: Some(1_807_843_200),
            mnemonic_language: None,
            mnemonic_words: None,
            device_service: None,
            device_account: None,
        });
        app.header = Some(header);
        app.open_keyslots();
        app.selected_keyslot_index = 1;

        app.open_rewrap_certificate_slot();

        assert!(matches!(app.screen, Screen::RewrapCertSlot));
        assert!(app.status.contains("replacement recipient certificate PEM"));
    }

    #[test]
    fn certificate_keyslot_rewrap_updates_active_certificate_unlock_options() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let (old_cert_path, old_key_path) = write_test_certificate_pair(tempdir.path(), "old");
        let (new_cert_path, new_key_path) = write_test_certificate_pair(tempdir.path(), "new");

        let keyslot_id = {
            let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
            vault
                .add_certificate_keyslot(
                    fs::read(&old_cert_path).expect("old cert").as_slice(),
                    Some("ops".to_string()),
                )
                .expect("add certificate slot")
                .id
        };

        let options = VaultOpenOptions {
            path: path.clone(),
            auth: VaultAuth::Certificate {
                cert_path: old_cert_path.clone(),
                key_path: old_key_path.clone(),
                key_passphrase_env: None,
                key_passphrase: None,
            },
            mnemonic_phrase_env: None,
            mnemonic_phrase: None,
            mnemonic_slot: None,
            device_slot: None,
            use_device_auto: false,
        };

        let mut app = App::new(options);
        app.open_keyslots();
        app.selected_keyslot_index = app
            .header
            .as_ref()
            .and_then(|header| {
                header
                    .keyslots
                    .iter()
                    .position(|slot| slot.id == keyslot_id)
            })
            .expect("certificate keyslot index");
        app.open_rewrap_certificate_slot();
        app.certificate_rewrap_form.cert_path = new_cert_path.display().to_string();
        app.certificate_rewrap_form.key_path = new_key_path.display().to_string();
        app.submit_certificate_slot_rewrap();

        match &app.options.auth {
            VaultAuth::Certificate {
                cert_path,
                key_path,
                ..
            } => {
                assert_eq!(cert_path, &new_cert_path);
                assert_eq!(key_path, &new_key_path);
            }
            auth => panic!("expected certificate auth after rewrap, got {auth:?}"),
        }
        unlock_vault_for_options(&app.options).expect("refresh uses rewrapped certificate");
    }

    #[test]
    fn keyslot_remove_and_rebind_flow_updates_header() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        app.open_keyslots();
        app.selected_keyslot_index = 1;
        app.rebind_selected_device_keyslot();
        assert!(app.status.contains("Rebound device-bound keyslot"));

        let before_remove = app
            .header
            .as_ref()
            .map(|header| header.keyslots.len())
            .expect("header");
        app.remove_selected_keyslot();
        assert!(app.status.contains("requires confirmation"));
        app.remove_selected_keyslot();
        let after_remove = app
            .header
            .as_ref()
            .map(|header| header.keyslots.len())
            .expect("header");
        assert_eq!(after_remove + 1, before_remove);
        assert!(app.status.contains("Removed device_bound keyslot"));
    }

    #[test]
    fn rebind_selected_device_keyslot_preserves_active_device_unlock_options() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let device_slot = {
            let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
            vault
                .add_device_keyslot(Some("daily".to_string()))
                .expect("device slot")
        };

        let options = VaultOpenOptions {
            path: path.clone(),
            auth: VaultAuth::PasswordEnv("PARANOID_TUI_DEVICE_REBIND".to_string()),
            mnemonic_phrase_env: None,
            mnemonic_phrase: None,
            mnemonic_slot: None,
            device_slot: Some(device_slot.id.clone()),
            use_device_auto: false,
        };

        let mut app = App::new(options);
        app.open_keyslots();
        app.selected_keyslot_index = app
            .header
            .as_ref()
            .and_then(|header| {
                header
                    .keyslots
                    .iter()
                    .position(|slot| slot.id == device_slot.id)
            })
            .expect("device keyslot index");

        app.rebind_selected_device_keyslot();

        assert_eq!(
            app.options.device_slot.as_deref(),
            Some(device_slot.id.as_str())
        );
        assert!(!app.options.use_device_auto);
        unlock_vault_for_options(&app.options).expect("rebound device slot still unlocks");
    }

    #[test]
    fn recovery_secret_rotation_updates_password_auth_and_unlocks_with_new_secret() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");

        let options = VaultOpenOptions {
            path: path.clone(),
            auth: VaultAuth::Password(SecretString::new(
                "correct horse battery staple".to_string(),
            )),
            mnemonic_phrase_env: None,
            mnemonic_phrase: None,
            mnemonic_slot: None,
            device_slot: None,
            use_device_auto: false,
        };

        let mut app = App::new(options);
        app.open_keyslots();
        app.open_rotate_recovery_secret();
        app.recovery_secret_form.new_secret = "new battery horse staple".to_string();
        app.recovery_secret_form.confirm_secret = "new battery horse staple".to_string();
        app.submit_rotate_recovery_secret();

        assert!(matches!(app.screen, Screen::Keyslots));
        assert!(app.status.contains("Rotated password recovery keyslot"));
        assert!(matches!(app.options.auth, VaultAuth::Password(_)));
        assert!(unlock_vault(&path, "correct horse battery staple").is_err());
        unlock_vault(&path, "new battery horse staple").expect("unlock with rotated secret");
    }

    #[test]
    fn export_backup_writes_portable_package() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        let backup = tempdir.path().join("vault.backup.json");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
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

        let mut app = App::new(options);
        app.open_export_backup();
        app.export_backup_form.path = backup.display().to_string();
        app.submit_export_backup();

        assert!(matches!(app.screen, Screen::Vault));
        assert!(backup.exists());
        assert!(app.status.contains("Exported encrypted vault backup"));
    }

    #[test]
    fn import_backup_restores_previous_encrypted_state() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        let backup = tempdir.path().join("vault.backup.json");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
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

        let mut app = App::new(options);
        app.open_export_backup();
        app.export_backup_form.path = backup.display().to_string();
        app.submit_export_backup();

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock again");
        vault
            .add_secure_note(NewSecureNoteRecord {
                title: "Temporary".to_string(),
                content: "remove me".to_string(),
                folder: Some("Temp".to_string()),
                tags: vec!["temp".to_string()],
            })
            .expect("add note");
        app.refresh();
        assert_eq!(app.items.len(), 2);

        app.open_import_backup();
        app.import_backup_form.path = backup.display().to_string();
        app.import_backup_form.overwrite = true;
        app.submit_import_backup();

        assert!(matches!(app.screen, Screen::Vault));
        assert_eq!(app.items.len(), 1);
        let VaultItemPayload::Login(login) = &app.detail.expect("detail").payload else {
            panic!("expected login");
        };
        assert_eq!(login.title, "GitHub");
        assert!(app.status.contains("Imported encrypted vault backup"));
    }

    #[test]
    fn invalid_backup_import_fails_closed_and_preserves_current_items() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        let invalid_backup = tempdir.path().join("invalid.backup.json");
        fs::write(&invalid_backup, b"{\"broken\":true").expect("write invalid backup");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
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

        let mut app = App::new(options);
        let original_id = app.detail.as_ref().expect("detail").id.clone();
        app.open_import_backup();
        app.import_backup_form.path = invalid_backup.display().to_string();
        app.import_backup_form.overwrite = true;
        app.submit_import_backup();

        assert!(matches!(app.screen, Screen::ImportBackup));
        assert_eq!(app.items.len(), 1);
        assert_eq!(app.detail.as_ref().expect("detail").id, original_id);
        assert!(app.status.contains("Backup import failed"));
    }

    #[test]
    fn export_transfer_writes_filtered_package_and_import_restores_selection() {
        let source_dir = tempdir().expect("source tempdir");
        let source_path = source_dir.path().join("source-vault.sqlite");
        let transfer_path = source_dir.path().join("selected-items.transfer.ppvt.json");
        init_vault(&source_path, "correct horse battery staple").expect("init source");
        let source_options = app_options(&source_path);
        add_device_fallback(&source_options).expect("device fallback");
        let source_vault =
            unlock_vault(&source_path, "correct horse battery staple").expect("unlock source");
        source_vault
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
        source_vault
            .add_secure_note(NewSecureNoteRecord {
                title: "Recovery".to_string(),
                content: "paper copy in safe".to_string(),
                folder: Some("Recovery".to_string()),
                tags: vec!["recovery".to_string()],
            })
            .expect("add note");

        let mut source_app = App::new(source_options);
        source_app.filters.kind = Some(VaultItemKind::Login);
        source_app.refresh();
        assert_eq!(source_app.items.len(), 1);

        source_app.open_export_transfer();
        source_app.export_transfer_form.path = transfer_path.display().to_string();
        source_app.export_transfer_form.package_password = "transfer secret".to_string();
        source_app.submit_export_transfer();

        assert!(matches!(source_app.screen, Screen::Vault));
        assert!(transfer_path.exists());
        assert!(
            source_app
                .status
                .contains("Exported encrypted transfer package")
        );

        let dest_dir = tempdir().expect("dest tempdir");
        let dest_path = dest_dir.path().join("dest-vault.sqlite");
        init_vault(&dest_path, "correct horse battery staple").expect("init dest");
        let dest_options = app_options(&dest_path);
        add_device_fallback(&dest_options).expect("dest device fallback");

        let mut dest_app = App::new(dest_options);
        dest_app.open_import_transfer();
        dest_app.import_transfer_form.path = transfer_path.display().to_string();
        dest_app.import_transfer_form.package_password = "transfer secret".to_string();
        dest_app.submit_import_transfer();

        assert!(matches!(dest_app.screen, Screen::Vault));
        assert_eq!(dest_app.items.len(), 1);
        assert_eq!(dest_app.items[0].kind, VaultItemKind::Login);
        let VaultItemPayload::Login(login) = &dest_app.detail.expect("detail").payload else {
            panic!("expected imported login");
        };
        assert_eq!(login.title, "GitHub");
        assert!(dest_app.status.contains("Imported transfer package"));
    }

    #[test]
    fn export_transfer_with_certificate_imports_via_certificate_keypair() {
        let source_dir = tempdir().expect("source tempdir");
        let source_path = source_dir.path().join("source-vault.sqlite");
        let transfer_path = source_dir
            .path()
            .join("selected-items-cert.transfer.ppvt.json");
        let (cert_path, key_path) = write_test_certificate_pair(source_dir.path(), "transfer");
        init_vault(&source_path, "correct horse battery staple").expect("init source");
        let source_options = app_options(&source_path);
        add_device_fallback(&source_options).expect("device fallback");
        let source_vault =
            unlock_vault(&source_path, "correct horse battery staple").expect("unlock source");
        source_vault
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

        let mut source_app = App::new(source_options);
        source_app.open_export_transfer();
        source_app.export_transfer_form.path = transfer_path.display().to_string();
        source_app.export_transfer_form.cert_path = cert_path.display().to_string();
        source_app.submit_export_transfer();

        assert!(matches!(source_app.screen, Screen::Vault));
        assert!(transfer_path.exists());
        assert!(
            source_app
                .status
                .contains("Exported encrypted transfer package")
        );

        let dest_dir = tempdir().expect("dest tempdir");
        let dest_path = dest_dir.path().join("dest-vault.sqlite");
        init_vault(&dest_path, "correct horse battery staple").expect("init dest");
        let dest_options = app_options(&dest_path);
        add_device_fallback(&dest_options).expect("dest device fallback");

        let mut dest_app = App::new(dest_options);
        dest_app.open_import_transfer();
        dest_app.import_transfer_form.path = transfer_path.display().to_string();
        dest_app.import_transfer_form.cert_path = cert_path.display().to_string();
        dest_app.import_transfer_form.key_path = key_path.display().to_string();
        dest_app.submit_import_transfer();

        assert!(matches!(dest_app.screen, Screen::Vault));
        assert_eq!(dest_app.items.len(), 1);
        assert_eq!(dest_app.items[0].kind, VaultItemKind::Login);
        let VaultItemPayload::Login(login) = &dest_app.detail.expect("detail").payload else {
            panic!("expected imported login");
        };
        assert_eq!(login.title, "GitHub");
        assert!(dest_app.status.contains("Imported transfer package"));
    }

    #[test]
    fn invalid_transfer_import_fails_closed_and_preserves_current_items() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        let invalid_transfer = tempdir.path().join("invalid.transfer.ppvt.json");
        fs::write(&invalid_transfer, b"{\"broken\":true").expect("write invalid transfer");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
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

        let mut app = App::new(options);
        let original_id = app.detail.as_ref().expect("detail").id.clone();
        app.open_import_transfer();
        app.import_transfer_form.path = invalid_transfer.display().to_string();
        app.import_transfer_form.package_password = "transfer secret".to_string();
        app.submit_import_transfer();

        assert!(matches!(app.screen, Screen::ImportTransfer));
        assert_eq!(app.items.len(), 1);
        assert_eq!(app.detail.as_ref().expect("detail").id, original_id);
        assert!(app.status.contains("Transfer import failed"));
    }

    #[test]
    fn blocked_view_explains_unlock_sources() {
        let app = App {
            options: VaultOpenOptions {
                path: "missing.sqlite".into(),
                auth: VaultAuth::PasswordEnv("PARANOID_MASTER_PASSWORD".to_string()),
                mnemonic_phrase_env: None,
                mnemonic_phrase: None,
                mnemonic_slot: None,
                device_slot: None,
                use_device_auto: false,
            },
            screen: Screen::UnlockBlocked,
            status: "Unlock blocked: no secret".to_string(),
            header: None,
            items: Vec::new(),
            selected_index: 0,
            selected_keyslot_index: 0,
            detail: None,
            filters: VaultFilterState::default(),
            search_mode: false,
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
            export_transfer_form: ExportTransferForm::default(),
            import_backup_form: ImportBackupForm::default(),
            import_transfer_form: ImportTransferForm::default(),
            editing_item_id: None,
            session: NativeSessionHardening::default(),
        };

        let rendered = render_to_string(&app);
        assert!(rendered.contains("Unlock blocked"));
        assert!(rendered.contains("Recovery Secret"));
        assert!(rendered.contains("Native unlock now works directly from the TUI"));
        assert!(rendered.contains("Unlock Vault"));
    }

    #[test]
    fn native_password_unlock_updates_state() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");

        let mut app = App::new(password_only_options(&path));
        assert!(matches!(app.screen, Screen::UnlockBlocked));

        app.unlock_form.password = "correct horse battery staple".to_string();
        app.submit_native_unlock();

        assert!(matches!(app.screen, Screen::Vault));
        assert!(app.status.contains("Vault unlocked"));
    }

    #[test]
    fn native_mnemonic_unlock_updates_state() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");
        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let enrollment = vault
            .add_mnemonic_keyslot(Some("paper".to_string()))
            .expect("mnemonic");

        let mut app = App::new(password_only_options(&path));
        assert!(matches!(app.screen, Screen::UnlockBlocked));

        app.unlock_form.mode = UnlockMode::Mnemonic;
        app.unlock_form.mnemonic_phrase = enrollment.mnemonic;
        app.unlock_form.mnemonic_slot = enrollment.keyslot.id;
        app.submit_native_unlock();

        assert!(matches!(app.screen, Screen::Vault));
        assert!(app.status.contains("Vault unlocked"));
    }

    #[test]
    fn native_device_unlock_updates_state() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");
        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        vault
            .add_device_keyslot(Some("daily".to_string()))
            .expect("first device slot");
        let second = vault
            .add_device_keyslot(Some("laptop".to_string()))
            .expect("second device slot");

        let mut app = App::new(password_only_options(&path));
        assert!(matches!(app.screen, Screen::UnlockBlocked));

        app.unlock_form.mode = UnlockMode::Device;
        app.unlock_form.device_slot = second.id;
        app.submit_native_unlock();

        assert!(matches!(app.screen, Screen::Vault));
        assert!(app.status.contains("Vault unlocked"));
    }

    #[test]
    fn native_certificate_unlock_updates_state() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");
        let (cert_path, key_path) = write_test_certificate_pair(tempdir.path(), "unlock");
        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        vault
            .add_certificate_keyslot(
                fs::read(&cert_path).expect("cert").as_slice(),
                Some("ops".to_string()),
            )
            .expect("certificate slot");

        let mut app = App::new(password_only_options(&path));
        assert!(matches!(app.screen, Screen::UnlockBlocked));

        app.unlock_form.mode = UnlockMode::Certificate;
        app.unlock_form.cert_path = cert_path.display().to_string();
        app.unlock_form.key_path = key_path.display().to_string();
        app.submit_native_unlock();

        assert!(matches!(app.screen, Screen::Vault));
        assert!(app.status.contains("Vault unlocked"));
    }

    #[test]
    fn idle_timeout_auto_locks_vault_and_clears_decrypted_state() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");
        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
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

        let mut app = App::new(options);
        assert!(matches!(app.screen, Screen::Vault));
        assert!(!app.items.is_empty());
        assert!(app.detail.is_some());

        app.session = NativeSessionHardening::with_timeouts(
            Duration::from_millis(10),
            Duration::from_millis(10),
        );
        thread::sleep(Duration::from_millis(15));
        app.poll_hardening();

        assert!(matches!(app.screen, Screen::UnlockBlocked));
        assert!(app.items.is_empty());
        assert!(app.detail.is_none());
        assert!(app.header.is_none());
        assert!(app.status.contains("auto-locked"));
    }

    #[test]
    fn generate_request_preview_rejects_unknown_frameworks() {
        let preview = generate_request_preview(&GenerateStoreForm {
            frameworks: "unknown".to_string(),
            ..GenerateStoreForm::default()
        });
        let rendered = preview
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("Blocked: unknown framework"));
    }
}
