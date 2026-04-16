use arboard::Clipboard;
use iced::{
    Alignment, Element, Length, Task, Theme,
    widget::{button, checkbox, column, container, row, scrollable, text, text_input},
};
use paranoid_core::{
    AuditStage, CharsetOptions, CharsetSpec, FrameworkId, GenerationReport, ParanoidRequest,
    VERSION, combined_framework_requirements, execute_request,
};
#[cfg(test)]
use paranoid_vault::read_vault_header;
use paranoid_vault::{
    GenerateStoreLoginRecord, MnemonicRecoveryEnrollment, NativeSessionHardening, NewCardRecord,
    NewIdentityRecord, NewLoginRecord, NewSecureNoteRecord, SecretString, UpdateCardRecord,
    UpdateIdentityRecord, UpdateLoginRecord, UpdateSecureNoteRecord, VaultAuth, VaultBackupSummary,
    VaultHeader, VaultItem, VaultItemFilter, VaultItemKind, VaultItemPayload, VaultItemSummary,
    VaultKeyslot, VaultOpenOptions, VaultTransferSummary, default_vault_path,
    inspect_certificate_pem, inspect_vault_backup, inspect_vault_transfer, restore_vault_backup,
    unlock_vault_for_options,
};
use std::{
    fs,
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchAction {
    RunGui,
    PrintHelp,
    PrintVersion,
}

fn gui_usage() -> &'static str {
    "\
Usage: paranoid-passwd-gui [OPTIONS]

Launch the native paranoid-passwd desktop application.

Options:
  -V, --version            Print version info and exit
  -h, --help               Print this help and exit
"
}

fn resolve_launch_action<I>(args: I) -> Result<LaunchAction, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut action = LaunchAction::RunGui;
    for argument in args {
        match argument.to_string_lossy().as_ref() {
            "-V" | "--version" => action = LaunchAction::PrintVersion,
            "-h" | "--help" => action = LaunchAction::PrintHelp,
            "--" => break,
            value => return Err(format!("unsupported argument: {value}")),
        }
    }
    Ok(action)
}

fn print_gui_usage() {
    print!("{}", gui_usage());
}

fn print_gui_version() {
    println!("paranoid-passwd-gui {VERSION}");
    println!(
        "build:          {}",
        option_env!("PARANOID_GUI_BUILD_DATE").unwrap_or("dev")
    );
    println!(
        "commit:         {}",
        option_env!("PARANOID_GUI_BUILD_COMMIT").unwrap_or("dev")
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    Generator,
    Vault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeneratorScreen {
    Configure,
    Audit,
    Results,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VaultScreen {
    List,
    Keyslots,
    AddLogin,
    EditLogin,
    AddNote,
    EditNote,
    AddCard,
    EditCard,
    AddIdentity,
    EditIdentity,
    GenerateStore,
    AddMnemonicSlot,
    AddDeviceSlot,
    AddCertSlot,
    RewrapCertSlot,
    EditKeyslotLabel,
    RotateMnemonicSlot,
    RotateRecoverySecret,
    MnemonicReveal,
    ExportBackup,
    ExportTransfer,
    ImportBackup,
    ImportTransfer,
    DeleteConfirm,
    UnlockBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VaultUnlockMode {
    Password,
    Mnemonic,
    Device,
    Certificate,
}

impl VaultUnlockMode {
    const ALL: [Self; 4] = [
        Self::Password,
        Self::Mnemonic,
        Self::Device,
        Self::Certificate,
    ];

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
enum DetailTab {
    Summary,
    Compliance,
    Entropy,
    Stats,
    Threats,
    SelfAudit,
}

impl DetailTab {
    const ALL: [Self; 6] = [
        Self::Summary,
        Self::Compliance,
        Self::Entropy,
        Self::Stats,
        Self::Threats,
        Self::SelfAudit,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Compliance => "Compliance",
            Self::Entropy => "Entropy",
            Self::Stats => "Stats",
            Self::Threats => "Threats",
            Self::SelfAudit => "Self-Audit",
        }
    }
}

#[derive(Debug)]
enum WorkerMessage {
    Stage(AuditStage),
    Done(Box<Result<GenerationReport, String>>),
}

#[derive(Debug, Clone)]
enum Message {
    SwitchSurface(Surface),
    LengthChanged(String),
    CountChanged(String),
    BatchChanged(String),
    MinLowerChanged(String),
    MinUpperChanged(String),
    MinDigitsChanged(String),
    MinSymbolsChanged(String),
    ToggleLowercase(bool),
    ToggleUppercase(bool),
    ToggleDigits(bool),
    ToggleSymbols(bool),
    ToggleSpace(bool),
    ToggleAmbiguous(bool),
    FrameworkChanged(FrameworkId, bool),
    CustomCharsetChanged(String),
    RunAudit,
    Poll,
    SessionTick,
    SelectTab(DetailTab),
    CopyPrimary,
    GoToConfigure,
    RefreshVault,
    OpenVaultUnlockSettings,
    SelectVaultUnlockMode(VaultUnlockMode),
    VaultUnlockPasswordChanged(String),
    VaultUnlockMnemonicChanged(String),
    VaultUnlockMnemonicSlotChanged(String),
    VaultUnlockDeviceSlotChanged(String),
    VaultUnlockCertPathChanged(String),
    VaultUnlockKeyPathChanged(String),
    VaultUnlockKeyPassphraseChanged(String),
    VaultAttemptNativeUnlock,
    VaultSearchChanged(String),
    VaultFilterKindChanged(String),
    VaultFilterFolderChanged(String),
    VaultFilterTagChanged(String),
    SelectVaultItem(usize),
    OpenVaultKeyslots,
    SelectVaultKeyslot(usize),
    OpenVaultAddLogin,
    OpenVaultAddNote,
    OpenVaultAddCard,
    OpenVaultAddIdentity,
    OpenVaultEditLogin,
    OpenVaultGenerateStore,
    OpenVaultExportBackup,
    OpenVaultExportTransfer,
    OpenVaultImportBackup,
    OpenVaultImportTransfer,
    OpenVaultDelete,
    VaultCopySelected,
    VaultSaveLogin,
    VaultSaveNote,
    VaultSaveCard,
    VaultSaveIdentity,
    VaultSaveGenerated,
    VaultConfirmDelete,
    VaultCancelFlow,
    VaultTitleChanged(String),
    VaultUsernameChanged(String),
    VaultPasswordChanged(String),
    VaultContentChanged(String),
    VaultCardholderChanged(String),
    VaultCardNumberChanged(String),
    VaultExpiryMonthChanged(String),
    VaultExpiryYearChanged(String),
    VaultSecurityCodeChanged(String),
    VaultBillingZipChanged(String),
    VaultIdentityFullNameChanged(String),
    VaultIdentityEmailChanged(String),
    VaultIdentityPhoneChanged(String),
    VaultIdentityAddressChanged(String),
    VaultUrlChanged(String),
    VaultNotesChanged(String),
    VaultFolderChanged(String),
    VaultTagsChanged(String),
    VaultLengthChanged(String),
    VaultFrameworksChanged(String),
    VaultMinLowerChanged(String),
    VaultMinUpperChanged(String),
    VaultMinDigitsChanged(String),
    VaultMinSymbolsChanged(String),
    OpenVaultAddMnemonicSlot,
    OpenVaultAddDeviceSlot,
    OpenVaultAddCertSlot,
    OpenVaultRewrapCertSlot,
    OpenVaultEditKeyslotLabel,
    OpenVaultRotateMnemonicSlot,
    OpenVaultRotateRecoverySecret,
    VaultKeyslotLabelChanged(String),
    VaultKeyslotCertPathChanged(String),
    VaultRecoverySecretChanged(String),
    VaultRecoverySecretConfirmChanged(String),
    VaultBackupPathChanged(String),
    VaultBackupOverwriteChanged(bool),
    VaultTransferPathChanged(String),
    VaultTransferPasswordChanged(String),
    VaultTransferCertPathChanged(String),
    VaultTransferKeyPathChanged(String),
    VaultTransferKeyPassphraseChanged(String),
    VaultTransferReplaceExistingChanged(bool),
    VaultEnrollMnemonicSlot,
    VaultEnrollDeviceSlot,
    VaultEnrollCertSlot,
    VaultRewrapCertSlot,
    VaultSaveKeyslotLabel,
    VaultRotateMnemonicSlot,
    VaultRotateRecoverySecret,
    VaultRemoveSelectedKeyslot,
    VaultRebindSelectedDeviceSlot,
    VaultExportBackup,
    VaultExportTransfer,
    VaultImportBackup,
    VaultImportTransfer,
    VaultCopyMnemonic,
}

#[derive(Debug, Clone, Default)]
struct VaultLoginForm {
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    folder: String,
    tags: String,
}

#[derive(Debug, Clone, Default)]
struct VaultNoteForm {
    title: String,
    content: String,
    folder: String,
    tags: String,
}

#[derive(Debug, Clone, Default)]
struct VaultCardForm {
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
struct VaultIdentityForm {
    title: String,
    full_name: String,
    email: String,
    phone: String,
    address: String,
    notes: String,
    folder: String,
    tags: String,
}

#[derive(Debug, Clone)]
struct VaultGenerateForm {
    target_login_id: Option<String>,
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

impl Default for VaultGenerateForm {
    fn default() -> Self {
        Self {
            target_login_id: None,
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

#[derive(Debug, Clone, Default)]
struct VaultKeyslotLabelForm {
    label: String,
}

#[derive(Debug, Clone, Default)]
struct VaultCertificateSlotForm {
    label: String,
    cert_path: String,
}

#[derive(Debug, Clone, Default)]
struct VaultCertificateRewrapForm {
    cert_path: String,
    key_path: String,
    key_passphrase: String,
}

#[derive(Debug, Clone, Default)]
struct VaultRecoverySecretForm {
    new_secret: String,
    confirm_secret: String,
}

#[derive(Debug, Clone)]
struct VaultUnlockForm {
    mode: VaultUnlockMode,
    password: String,
    mnemonic_phrase: String,
    mnemonic_slot: String,
    device_slot: String,
    cert_path: String,
    key_path: String,
    key_passphrase: String,
}

#[derive(Debug, Clone, Default)]
struct VaultExportBackupForm {
    path: String,
}

#[derive(Debug, Clone, Default)]
struct VaultImportBackupForm {
    path: String,
    overwrite: bool,
}

#[derive(Debug, Clone, Default)]
struct VaultExportTransferForm {
    path: String,
    package_password: String,
    cert_path: String,
}

#[derive(Debug, Clone, Default)]
struct VaultImportTransferForm {
    path: String,
    replace_existing: bool,
    package_password: String,
    cert_path: String,
    key_path: String,
    key_passphrase: String,
}

impl Default for VaultUnlockForm {
    fn default() -> Self {
        Self {
            mode: VaultUnlockMode::Password,
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

#[derive(Debug, Clone)]
struct VaultState {
    options: VaultOpenOptions,
    screen: VaultScreen,
    header: Option<VaultHeader>,
    items: Vec<VaultItemSummary>,
    selected_index: usize,
    detail: Option<VaultItem>,
    search_query: String,
    filter_kind: String,
    filter_folder: String,
    filter_tag: String,
    login_form: VaultLoginForm,
    note_form: VaultNoteForm,
    card_form: VaultCardForm,
    identity_form: VaultIdentityForm,
    generate_form: VaultGenerateForm,
    editing_item_id: Option<String>,
    selected_keyslot_index: usize,
    mnemonic_slot_form: VaultKeyslotLabelForm,
    device_slot_form: VaultKeyslotLabelForm,
    certificate_slot_form: VaultCertificateSlotForm,
    certificate_rewrap_form: VaultCertificateRewrapForm,
    edit_keyslot_label_form: VaultKeyslotLabelForm,
    recovery_secret_form: VaultRecoverySecretForm,
    latest_mnemonic_enrollment: Option<MnemonicRecoveryEnrollment>,
    pending_keyslot_removal_confirmation: Option<String>,
    unlock_form: VaultUnlockForm,
    export_backup_form: VaultExportBackupForm,
    export_transfer_form: VaultExportTransferForm,
    import_backup_form: VaultImportBackupForm,
    import_transfer_form: VaultImportTransferForm,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            options: VaultOpenOptions {
                path: default_vault_path(),
                auth: VaultAuth::PasswordEnv("PARANOID_MASTER_PASSWORD".to_string()),
                mnemonic_phrase_env: None,
                mnemonic_phrase: None,
                mnemonic_slot: None,
                device_slot: None,
                use_device_auto: false,
            },
            screen: VaultScreen::UnlockBlocked,
            header: None,
            items: Vec::new(),
            selected_index: 0,
            detail: None,
            search_query: String::new(),
            filter_kind: String::new(),
            filter_folder: String::new(),
            filter_tag: String::new(),
            login_form: VaultLoginForm::default(),
            note_form: VaultNoteForm::default(),
            card_form: VaultCardForm::default(),
            identity_form: VaultIdentityForm::default(),
            generate_form: VaultGenerateForm::default(),
            editing_item_id: None,
            selected_keyslot_index: 0,
            mnemonic_slot_form: VaultKeyslotLabelForm::default(),
            device_slot_form: VaultKeyslotLabelForm::default(),
            certificate_slot_form: VaultCertificateSlotForm::default(),
            certificate_rewrap_form: VaultCertificateRewrapForm::default(),
            edit_keyslot_label_form: VaultKeyslotLabelForm::default(),
            recovery_secret_form: VaultRecoverySecretForm::default(),
            latest_mnemonic_enrollment: None,
            pending_keyslot_removal_confirmation: None,
            unlock_form: VaultUnlockForm::default(),
            export_backup_form: VaultExportBackupForm::default(),
            export_transfer_form: VaultExportTransferForm::default(),
            import_backup_form: VaultImportBackupForm::default(),
            import_transfer_form: VaultImportTransferForm::default(),
        }
    }
}

struct GuiApp {
    surface: Surface,
    request: ParanoidRequest,
    length_input: String,
    count_input: String,
    batch_input: String,
    min_lower_input: String,
    min_upper_input: String,
    min_digits_input: String,
    min_symbols_input: String,
    custom_charset_input: String,
    report: Option<GenerationReport>,
    generator_screen: GeneratorScreen,
    detail_tab: DetailTab,
    current_stage: Option<AuditStage>,
    completed_stages: Vec<AuditStage>,
    worker: Option<Receiver<WorkerMessage>>,
    vault: VaultState,
    status: String,
    session: NativeSessionHardening,
}

fn main() -> iced::Result {
    match resolve_launch_action(std::env::args_os().skip(1)) {
        Ok(LaunchAction::RunGui) => iced::application(boot, update, view)
            .title(title)
            .theme(theme)
            .run(),
        Ok(LaunchAction::PrintHelp) => {
            print_gui_usage();
            Ok(())
        }
        Ok(LaunchAction::PrintVersion) => {
            print_gui_version();
            Ok(())
        }
        Err(error) => {
            eprintln!("error: {error}\n\n{}", gui_usage());
            std::process::exit(2);
        }
    }
}

fn title(_app: &GuiApp) -> String {
    "paranoid-passwd".to_string()
}

fn theme(_app: &GuiApp) -> Theme {
    Theme::TokyoNight
}

fn boot() -> (GuiApp, Task<Message>) {
    let request = ParanoidRequest {
        charset: CharsetSpec::Options(CharsetOptions::default()),
        ..ParanoidRequest::default()
    };
    let mut app = GuiApp {
        surface: Surface::Generator,
        length_input: request.length.to_string(),
        count_input: request.count.to_string(),
        batch_input: request.batch_size.to_string(),
        min_lower_input: "0".to_string(),
        min_upper_input: "0".to_string(),
        min_digits_input: "0".to_string(),
        min_symbols_input: "0".to_string(),
        custom_charset_input: String::new(),
        request,
        report: None,
        generator_screen: GeneratorScreen::Configure,
        detail_tab: DetailTab::Summary,
        current_stage: None,
        completed_stages: Vec::new(),
        worker: None,
        vault: VaultState::default(),
        status: "Configure the generator, then run the 7-layer audit.".to_string(),
        session: NativeSessionHardening::default(),
    };
    let _ = refresh_vault_state(&mut app);
    (app, schedule_session_tick())
}

fn update(app: &mut GuiApp, message: Message) -> Task<Message> {
    if message_counts_as_activity(&message) {
        app.session.note_activity();
    }
    match message {
        Message::SwitchSurface(surface) => {
            app.surface = surface;
            if matches!(surface, Surface::Vault) {
                let _ = refresh_vault_state(app);
            }
        }
        Message::LengthChanged(value) => {
            app.length_input = value.clone();
            if let Ok(length) = value.parse() {
                app.request.length = length;
            }
        }
        Message::CountChanged(value) => {
            app.count_input = value.clone();
            if let Ok(count) = value.parse() {
                app.request.count = count;
            }
        }
        Message::BatchChanged(value) => {
            app.batch_input = value.clone();
            if let Ok(batch_size) = value.parse() {
                app.request.batch_size = batch_size;
            }
        }
        Message::MinLowerChanged(value) => {
            app.min_lower_input = value.clone();
            if let Ok(count) = value.parse() {
                app.request.requirements.min_lowercase = count;
            }
        }
        Message::MinUpperChanged(value) => {
            app.min_upper_input = value.clone();
            if let Ok(count) = value.parse() {
                app.request.requirements.min_uppercase = count;
            }
        }
        Message::MinDigitsChanged(value) => {
            app.min_digits_input = value.clone();
            if let Ok(count) = value.parse() {
                app.request.requirements.min_digits = count;
            }
        }
        Message::MinSymbolsChanged(value) => {
            app.min_symbols_input = value.clone();
            if let Ok(count) = value.parse() {
                app.request.requirements.min_symbols = count;
            }
        }
        Message::ToggleLowercase(value) => {
            charset_options_mut(&mut app.request).include_lowercase = value
        }
        Message::ToggleUppercase(value) => {
            charset_options_mut(&mut app.request).include_uppercase = value
        }
        Message::ToggleDigits(value) => {
            charset_options_mut(&mut app.request).include_digits = value
        }
        Message::ToggleSymbols(value) => {
            charset_options_mut(&mut app.request).include_symbols = value
        }
        Message::ToggleSpace(value) => charset_options_mut(&mut app.request).include_space = value,
        Message::ToggleAmbiguous(value) => {
            charset_options_mut(&mut app.request).exclude_ambiguous = value
        }
        Message::FrameworkChanged(framework, enabled) => {
            if enabled {
                if !app.request.selected_frameworks.contains(&framework) {
                    app.request.selected_frameworks.push(framework);
                }
            } else {
                app.request
                    .selected_frameworks
                    .retain(|candidate| candidate != &framework);
            }
            apply_frameworks(&mut app.request);
            sync_inputs_from_request(app);
        }
        Message::CustomCharsetChanged(value) => {
            app.custom_charset_input = value.clone();
            charset_options_mut(&mut app.request).custom_charset = if value.trim().is_empty() {
                None
            } else {
                Some(value)
            };
        }
        Message::RunAudit => {
            app.generator_screen = GeneratorScreen::Audit;
            app.current_stage = Some(AuditStage::Generate);
            app.completed_stages.clear();
            app.status = "Running native generation and batch audit...".to_string();
            let request = app.request.clone();
            let (tx, rx) = mpsc::channel::<WorkerMessage>();
            app.worker = Some(rx);
            thread::spawn(move || {
                let result = execute_request(&request, true, |stage| {
                    let _ = tx.send(WorkerMessage::Stage(stage));
                })
                .map_err(|error| error.to_string());
                let _ = tx.send(WorkerMessage::Done(Box::new(result)));
            });
            return Task::perform(
                async move {
                    thread::sleep(Duration::from_millis(80));
                },
                |_| Message::Poll,
            );
        }
        Message::Poll => {
            let messages = app
                .worker
                .as_ref()
                .map(|worker| worker.try_iter().collect::<Vec<_>>())
                .unwrap_or_default();
            let mut clear_worker = false;
            for worker_message in messages {
                match worker_message {
                    WorkerMessage::Stage(stage) => {
                        if !app.completed_stages.contains(&stage)
                            && !matches!(stage, AuditStage::Complete)
                        {
                            app.completed_stages.push(stage);
                        }
                        app.current_stage = Some(stage);
                    }
                    WorkerMessage::Done(result) => {
                        clear_worker = true;
                        match *result {
                            Ok(report) => {
                                app.report = Some(report);
                                app.generator_screen = GeneratorScreen::Results;
                                app.detail_tab = DetailTab::Summary;
                                app.status =
                                    "Audit complete. Review the results or copy the primary password."
                                        .to_string();
                            }
                            Err(error) => {
                                app.generator_screen = GeneratorScreen::Configure;
                                app.status = format!("Audit failed: {error}");
                            }
                        }
                    }
                }
            }
            if clear_worker {
                app.worker = None;
            } else if app.worker.is_some() {
                return Task::perform(
                    async move {
                        thread::sleep(Duration::from_millis(80));
                    },
                    |_| Message::Poll,
                );
            }
        }
        Message::SessionTick => {
            poll_session_hardening(app);
            return schedule_session_tick();
        }
        Message::SelectTab(tab) => app.detail_tab = tab,
        Message::CopyPrimary => {
            if let Some(password) = app
                .report
                .as_ref()
                .and_then(|report| report.passwords.first())
            {
                match Clipboard::new()
                    .and_then(|mut clipboard| clipboard.set_text(password.value.clone()))
                {
                    Ok(()) => {
                        app.session.arm_clipboard_clear(password.value.clone());
                        app.status = format!(
                            "Copied the primary password to the clipboard. It will be cleared in {} seconds if unchanged.",
                            app.session.clipboard_clear_after().as_secs()
                        );
                    }
                    Err(error) => {
                        app.status = format!("Clipboard unavailable: {error}");
                    }
                }
            }
        }
        Message::GoToConfigure => {
            app.generator_screen = GeneratorScreen::Configure;
            app.current_stage = None;
            app.completed_stages.clear();
        }
        Message::RefreshVault => {
            let _ = refresh_vault_state(app);
        }
        Message::OpenVaultUnlockSettings => {
            app.vault.screen = VaultScreen::UnlockBlocked;
            app.status =
                "Choose a native unlock method, then retry access to the encrypted local vault."
                    .to_string();
        }
        Message::SelectVaultUnlockMode(mode) => {
            app.vault.unlock_form.mode = mode;
        }
        Message::VaultUnlockPasswordChanged(value) => app.vault.unlock_form.password = value,
        Message::VaultUnlockMnemonicChanged(value) => app.vault.unlock_form.mnemonic_phrase = value,
        Message::VaultUnlockMnemonicSlotChanged(value) => {
            app.vault.unlock_form.mnemonic_slot = value
        }
        Message::VaultUnlockDeviceSlotChanged(value) => app.vault.unlock_form.device_slot = value,
        Message::VaultUnlockCertPathChanged(value) => app.vault.unlock_form.cert_path = value,
        Message::VaultUnlockKeyPathChanged(value) => match app.vault.screen {
            VaultScreen::UnlockBlocked => app.vault.unlock_form.key_path = value,
            VaultScreen::RewrapCertSlot => app.vault.certificate_rewrap_form.key_path = value,
            _ => {}
        },
        Message::VaultUnlockKeyPassphraseChanged(value) => match app.vault.screen {
            VaultScreen::UnlockBlocked => app.vault.unlock_form.key_passphrase = value,
            VaultScreen::RewrapCertSlot => app.vault.certificate_rewrap_form.key_passphrase = value,
            _ => {}
        },
        Message::VaultAttemptNativeUnlock => {
            apply_native_unlock_settings(app);
            let _ = refresh_vault_state(app);
        }
        Message::VaultSearchChanged(value) => {
            app.vault.search_query = value;
            let _ = refresh_vault_state(app);
        }
        Message::VaultFilterKindChanged(value) => {
            app.vault.filter_kind = value;
            let _ = refresh_vault_state(app);
        }
        Message::VaultFilterFolderChanged(value) => {
            app.vault.filter_folder = value;
            let _ = refresh_vault_state(app);
        }
        Message::VaultFilterTagChanged(value) => {
            app.vault.filter_tag = value;
            let _ = refresh_vault_state(app);
        }
        Message::SelectVaultItem(index) => {
            app.vault.selected_index = index.min(app.vault.items.len().saturating_sub(1));
            if let Err(error) = reload_vault_detail(app) {
                app.status = format!("Vault detail reload failed: {error}");
            }
        }
        Message::OpenVaultKeyslots => {
            app.vault.pending_keyslot_removal_confirmation = None;
            app.vault.screen = VaultScreen::Keyslots;
            app.status =
                "Inspect current keyslots or enroll mnemonic, device-bound, or certificate-based recovery."
                    .to_string();
        }
        Message::SelectVaultKeyslot(index) => {
            let keyslot_count = app
                .vault
                .header
                .as_ref()
                .map(|header| header.keyslots.len())
                .unwrap_or_default();
            app.vault.selected_keyslot_index = index.min(keyslot_count.saturating_sub(1));
            app.vault.pending_keyslot_removal_confirmation = None;
        }
        Message::OpenVaultAddLogin => {
            app.vault.login_form = VaultLoginForm::default();
            app.vault.editing_item_id = None;
            app.vault.screen = VaultScreen::AddLogin;
            app.status = "Fill the login form, then save the encrypted record.".to_string();
        }
        Message::OpenVaultAddNote => {
            app.vault.note_form = VaultNoteForm::default();
            app.vault.editing_item_id = None;
            app.vault.screen = VaultScreen::AddNote;
            app.status = "Fill the secure note form, then save the encrypted record.".to_string();
        }
        Message::OpenVaultAddCard => {
            app.vault.card_form = VaultCardForm::default();
            app.vault.editing_item_id = None;
            app.vault.screen = VaultScreen::AddCard;
            app.status = "Fill the card form, then save the encrypted record.".to_string();
        }
        Message::OpenVaultAddIdentity => {
            app.vault.identity_form = VaultIdentityForm::default();
            app.vault.editing_item_id = None;
            app.vault.screen = VaultScreen::AddIdentity;
            app.status = "Fill the identity form, then save the encrypted record.".to_string();
        }
        Message::OpenVaultEditLogin => {
            if let Some(detail) = &app.vault.detail {
                match &detail.payload {
                    VaultItemPayload::Login(login) => {
                        app.vault.login_form = VaultLoginForm {
                            title: login.title.clone(),
                            username: login.username.clone(),
                            password: login.password.clone(),
                            url: login.url.clone().unwrap_or_default(),
                            notes: login.notes.clone().unwrap_or_default(),
                            folder: login.folder.clone().unwrap_or_default(),
                            tags: login.tags.join(", "),
                        };
                        app.vault.editing_item_id = Some(detail.id.clone());
                        app.vault.screen = VaultScreen::EditLogin;
                        app.status =
                            "Edit the selected login, then save the updated encrypted record."
                                .to_string();
                    }
                    VaultItemPayload::SecureNote(note) => {
                        app.vault.note_form = VaultNoteForm {
                            title: note.title.clone(),
                            content: note.content.clone(),
                            folder: note.folder.clone().unwrap_or_default(),
                            tags: note.tags.join(", "),
                        };
                        app.vault.editing_item_id = Some(detail.id.clone());
                        app.vault.screen = VaultScreen::EditNote;
                        app.status =
                            "Edit the selected secure note, then save the updated encrypted record."
                                .to_string();
                    }
                    VaultItemPayload::Card(card) => {
                        app.vault.card_form = VaultCardForm {
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
                        app.vault.editing_item_id = Some(detail.id.clone());
                        app.vault.screen = VaultScreen::EditCard;
                        app.status =
                            "Edit the selected card, then save the updated encrypted record."
                                .to_string();
                    }
                    VaultItemPayload::Identity(identity) => {
                        app.vault.identity_form = VaultIdentityForm {
                            title: identity.title.clone(),
                            full_name: identity.full_name.clone(),
                            email: identity.email.clone().unwrap_or_default(),
                            phone: identity.phone.clone().unwrap_or_default(),
                            address: identity.address.clone().unwrap_or_default(),
                            notes: identity.notes.clone().unwrap_or_default(),
                            folder: identity.folder.clone().unwrap_or_default(),
                            tags: identity.tags.join(", "),
                        };
                        app.vault.editing_item_id = Some(detail.id.clone());
                        app.vault.screen = VaultScreen::EditIdentity;
                        app.status =
                            "Edit the selected identity, then save the updated encrypted record."
                                .to_string();
                    }
                }
            } else {
                app.status = "No vault item selected to edit.".to_string();
            }
        }
        Message::OpenVaultGenerateStore => {
            app.vault.generate_form = VaultGenerateForm::default();
            if let Some(detail) = &app.vault.detail {
                if let VaultItemPayload::Login(login) = &detail.payload {
                    app.vault.generate_form.target_login_id = Some(detail.id.clone());
                    app.vault.generate_form.title = login.title.clone();
                    app.vault.generate_form.username = login.username.clone();
                    app.vault.generate_form.url = login.url.clone().unwrap_or_default();
                    app.vault.generate_form.notes = login.notes.clone().unwrap_or_default();
                    app.vault.generate_form.folder = login.folder.clone().unwrap_or_default();
                    app.vault.generate_form.tags = login.tags.join(", ");
                }
            }
            app.vault.screen = VaultScreen::GenerateStore;
            app.status = if app.vault.generate_form.target_login_id.is_some() {
                "Configure one generated password, then rotate the selected login in place."
                    .to_string()
            } else {
                "Configure one generated password, then store it as a vault login item.".to_string()
            };
        }
        Message::OpenVaultExportBackup => {
            app.vault.export_backup_form = VaultExportBackupForm {
                path: default_backup_export_path(&app.vault.options.path),
            };
            app.vault.screen = VaultScreen::ExportBackup;
            app.status =
                "Export the current encrypted vault state into a portable JSON backup package."
                    .to_string();
        }
        Message::OpenVaultExportTransfer => {
            app.vault.export_transfer_form = VaultExportTransferForm {
                path: default_transfer_export_path(&app.vault.options.path),
                package_password: String::new(),
                cert_path: String::new(),
            };
            app.vault.screen = VaultScreen::ExportTransfer;
            app.status =
                "Export the currently filtered vault items into an encrypted transfer package."
                    .to_string();
        }
        Message::OpenVaultImportBackup => {
            app.vault.import_backup_form = VaultImportBackupForm {
                path: default_backup_export_path(&app.vault.options.path),
                overwrite: app.vault.options.path.exists(),
            };
            app.vault.screen = VaultScreen::ImportBackup;
            app.status =
                "Import a JSON backup package into the current vault path. Overwrite replaces the local file."
                    .to_string();
        }
        Message::OpenVaultImportTransfer => {
            app.vault.import_transfer_form = VaultImportTransferForm {
                path: default_transfer_export_path(&app.vault.options.path),
                replace_existing: false,
                package_password: String::new(),
                cert_path: String::new(),
                key_path: String::new(),
                key_passphrase: String::new(),
            };
            app.vault.screen = VaultScreen::ImportTransfer;
            app.status =
                "Import an encrypted transfer package into the unlocked local vault. Choose either the package recovery secret or certificate keypair."
                    .to_string();
        }
        Message::OpenVaultDelete => {
            if app.vault.detail.is_some() {
                app.vault.screen = VaultScreen::DeleteConfirm;
                app.status =
                    "Delete confirmation is active. Remove the selected encrypted record only if you mean it."
                        .to_string();
            } else {
                app.status = "No vault item selected to delete.".to_string();
            }
        }
        Message::VaultCopySelected => {
            if let Some(payload) = app.vault.detail.as_ref().map(|item| &item.payload) {
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
                match Clipboard::new().and_then(|mut clipboard| clipboard.set_text(content.clone()))
                {
                    Ok(()) => {
                        app.session.arm_clipboard_clear(content);
                        app.status = format!(
                            "Copied the selected vault secret to the clipboard. It will be cleared in {} seconds if unchanged.",
                            app.session.clipboard_clear_after().as_secs()
                        );
                    }
                    Err(error) => {
                        app.status = format!("Clipboard unavailable: {error}");
                    }
                }
            } else {
                app.status = "No vault item selected to copy.".to_string();
            }
        }
        Message::VaultSaveLogin => match submit_vault_login(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Vault write failed: {error}"),
        },
        Message::VaultSaveNote => match submit_vault_note(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Vault write failed: {error}"),
        },
        Message::VaultSaveCard => match submit_vault_card(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Vault write failed: {error}"),
        },
        Message::VaultSaveIdentity => match submit_vault_identity(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Vault write failed: {error}"),
        },
        Message::VaultSaveGenerated => match submit_vault_generate(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Generate-and-store failed: {error}"),
        },
        Message::VaultExportBackup => match submit_vault_export_backup(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Backup export failed: {error}"),
        },
        Message::VaultExportTransfer => match submit_vault_export_transfer(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Transfer export failed: {error}"),
        },
        Message::VaultImportBackup => match submit_vault_import_backup(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Backup import failed: {error}"),
        },
        Message::VaultImportTransfer => match submit_vault_import_transfer(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Transfer import failed: {error}"),
        },
        Message::VaultConfirmDelete => match delete_selected_vault_item(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Delete failed: {error}"),
        },
        Message::VaultCancelFlow => {
            if matches!(app.vault.screen, VaultScreen::MnemonicReveal) {
                app.vault.latest_mnemonic_enrollment = None;
            }
            app.vault.pending_keyslot_removal_confirmation = None;
            app.vault.screen = match app.vault.screen {
                VaultScreen::AddLogin
                | VaultScreen::EditLogin
                | VaultScreen::AddNote
                | VaultScreen::EditNote
                | VaultScreen::AddCard
                | VaultScreen::EditCard
                | VaultScreen::AddIdentity
                | VaultScreen::EditIdentity
                | VaultScreen::GenerateStore
                | VaultScreen::ExportBackup
                | VaultScreen::ExportTransfer
                | VaultScreen::ImportBackup
                | VaultScreen::ImportTransfer
                | VaultScreen::DeleteConfirm => VaultScreen::List,
                VaultScreen::AddMnemonicSlot
                | VaultScreen::AddDeviceSlot
                | VaultScreen::AddCertSlot
                | VaultScreen::RewrapCertSlot
                | VaultScreen::EditKeyslotLabel
                | VaultScreen::RotateMnemonicSlot
                | VaultScreen::RotateRecoverySecret
                | VaultScreen::MnemonicReveal => VaultScreen::Keyslots,
                current => current,
            };
            app.vault.editing_item_id = None;
            app.status = "Canceled vault form.".to_string();
        }
        Message::VaultTitleChanged(value) => match app.vault.screen {
            VaultScreen::AddLogin | VaultScreen::EditLogin => app.vault.login_form.title = value,
            VaultScreen::AddNote | VaultScreen::EditNote => app.vault.note_form.title = value,
            VaultScreen::AddCard | VaultScreen::EditCard => app.vault.card_form.title = value,
            VaultScreen::AddIdentity | VaultScreen::EditIdentity => {
                app.vault.identity_form.title = value
            }
            VaultScreen::GenerateStore => app.vault.generate_form.title = value,
            _ => {}
        },
        Message::VaultUsernameChanged(value) => match app.vault.screen {
            VaultScreen::AddLogin | VaultScreen::EditLogin => app.vault.login_form.username = value,
            VaultScreen::GenerateStore => app.vault.generate_form.username = value,
            _ => {}
        },
        Message::VaultPasswordChanged(value) => {
            app.vault.login_form.password = value;
        }
        Message::VaultContentChanged(value) => {
            app.vault.note_form.content = value;
        }
        Message::VaultCardholderChanged(value) => app.vault.card_form.cardholder_name = value,
        Message::VaultCardNumberChanged(value) => app.vault.card_form.number = value,
        Message::VaultExpiryMonthChanged(value) => app.vault.card_form.expiry_month = value,
        Message::VaultExpiryYearChanged(value) => app.vault.card_form.expiry_year = value,
        Message::VaultSecurityCodeChanged(value) => app.vault.card_form.security_code = value,
        Message::VaultBillingZipChanged(value) => app.vault.card_form.billing_zip = value,
        Message::VaultIdentityFullNameChanged(value) => app.vault.identity_form.full_name = value,
        Message::VaultIdentityEmailChanged(value) => app.vault.identity_form.email = value,
        Message::VaultIdentityPhoneChanged(value) => app.vault.identity_form.phone = value,
        Message::VaultIdentityAddressChanged(value) => app.vault.identity_form.address = value,
        Message::VaultUrlChanged(value) => match app.vault.screen {
            VaultScreen::AddLogin | VaultScreen::EditLogin => app.vault.login_form.url = value,
            VaultScreen::GenerateStore => app.vault.generate_form.url = value,
            _ => {}
        },
        Message::VaultNotesChanged(value) => match app.vault.screen {
            VaultScreen::AddLogin | VaultScreen::EditLogin => app.vault.login_form.notes = value,
            VaultScreen::AddCard | VaultScreen::EditCard => app.vault.card_form.notes = value,
            VaultScreen::AddIdentity | VaultScreen::EditIdentity => {
                app.vault.identity_form.notes = value
            }
            VaultScreen::GenerateStore => app.vault.generate_form.notes = value,
            _ => {}
        },
        Message::VaultFolderChanged(value) => match app.vault.screen {
            VaultScreen::AddLogin | VaultScreen::EditLogin => app.vault.login_form.folder = value,
            VaultScreen::AddNote | VaultScreen::EditNote => app.vault.note_form.folder = value,
            VaultScreen::AddCard | VaultScreen::EditCard => app.vault.card_form.folder = value,
            VaultScreen::AddIdentity | VaultScreen::EditIdentity => {
                app.vault.identity_form.folder = value
            }
            VaultScreen::GenerateStore => app.vault.generate_form.folder = value,
            _ => {}
        },
        Message::VaultTagsChanged(value) => match app.vault.screen {
            VaultScreen::AddLogin | VaultScreen::EditLogin => app.vault.login_form.tags = value,
            VaultScreen::AddNote | VaultScreen::EditNote => app.vault.note_form.tags = value,
            VaultScreen::AddCard | VaultScreen::EditCard => app.vault.card_form.tags = value,
            VaultScreen::AddIdentity | VaultScreen::EditIdentity => {
                app.vault.identity_form.tags = value
            }
            VaultScreen::GenerateStore => app.vault.generate_form.tags = value,
            _ => {}
        },
        Message::VaultLengthChanged(value) => app.vault.generate_form.length = value,
        Message::VaultFrameworksChanged(value) => app.vault.generate_form.frameworks = value,
        Message::VaultMinLowerChanged(value) => app.vault.generate_form.min_lower = value,
        Message::VaultMinUpperChanged(value) => app.vault.generate_form.min_upper = value,
        Message::VaultMinDigitsChanged(value) => app.vault.generate_form.min_digits = value,
        Message::VaultMinSymbolsChanged(value) => app.vault.generate_form.min_symbols = value,
        Message::OpenVaultAddMnemonicSlot => {
            app.vault.pending_keyslot_removal_confirmation = None;
            app.vault.mnemonic_slot_form = VaultKeyslotLabelForm::default();
            app.vault.screen = VaultScreen::AddMnemonicSlot;
            app.status =
                "Enroll a mnemonic recovery slot. The phrase will be shown once after saving."
                    .to_string();
        }
        Message::OpenVaultAddDeviceSlot => {
            app.vault.pending_keyslot_removal_confirmation = None;
            app.vault.device_slot_form = VaultKeyslotLabelForm::default();
            app.vault.screen = VaultScreen::AddDeviceSlot;
            app.status =
                "Enroll a device-bound slot for passwordless local unlock on this machine."
                    .to_string();
        }
        Message::OpenVaultAddCertSlot => {
            app.vault.pending_keyslot_removal_confirmation = None;
            app.vault.certificate_slot_form = VaultCertificateSlotForm::default();
            app.vault.screen = VaultScreen::AddCertSlot;
            app.status =
                "Enroll a certificate-wrapped slot using a PEM recipient certificate.".to_string();
        }
        Message::OpenVaultRewrapCertSlot => {
            let Some(keyslot) = selected_keyslot(app) else {
                app.status = "No keyslot selected to rewrap.".to_string();
                return Task::none();
            };
            if keyslot.kind != paranoid_vault::VaultKeyslotKind::CertificateWrapped {
                app.status = "Selected keyslot is not certificate-wrapped.".to_string();
                return Task::none();
            }
            app.vault.pending_keyslot_removal_confirmation = None;
            app.vault.certificate_rewrap_form = VaultCertificateRewrapForm::default();
            if let VaultAuth::Certificate { key_path, .. } = &app.vault.options.auth {
                app.vault.certificate_rewrap_form.key_path = key_path.display().to_string();
            }
            app.vault.screen = VaultScreen::RewrapCertSlot;
            app.status =
                "Provide the replacement recipient certificate PEM. Replacement key path and passphrase are optional and only update the active native session."
                    .to_string();
        }
        Message::OpenVaultEditKeyslotLabel => {
            let Some(label) =
                selected_keyslot(app).map(|keyslot| keyslot.label.clone().unwrap_or_default())
            else {
                app.status = "No keyslot selected to relabel.".to_string();
                return Task::none();
            };
            app.vault.pending_keyslot_removal_confirmation = None;
            app.vault.edit_keyslot_label_form = VaultKeyslotLabelForm { label };
            app.vault.screen = VaultScreen::EditKeyslotLabel;
            app.status =
                "Update the selected keyslot label without changing any recovery material."
                    .to_string();
        }
        Message::OpenVaultRotateMnemonicSlot => {
            let Some(keyslot) = selected_keyslot(app) else {
                app.status = "No keyslot selected to rotate.".to_string();
                return Task::none();
            };
            if keyslot.kind != paranoid_vault::VaultKeyslotKind::MnemonicRecovery {
                app.status = "Selected keyslot is not mnemonic recovery.".to_string();
                return Task::none();
            }
            app.vault.pending_keyslot_removal_confirmation = None;
            app.vault.screen = VaultScreen::RotateMnemonicSlot;
            app.status = "Rotate the selected mnemonic recovery slot in place. The replacement phrase will be shown once after confirmation.".to_string();
        }
        Message::OpenVaultRotateRecoverySecret => {
            app.vault.pending_keyslot_removal_confirmation = None;
            app.vault.recovery_secret_form = VaultRecoverySecretForm::default();
            app.vault.screen = VaultScreen::RotateRecoverySecret;
            app.status = "Rotate the password recovery secret without changing existing mnemonic, device, or certificate keyslots.".to_string();
        }
        Message::VaultKeyslotLabelChanged(value) => match app.vault.screen {
            VaultScreen::AddMnemonicSlot => app.vault.mnemonic_slot_form.label = value,
            VaultScreen::AddDeviceSlot => app.vault.device_slot_form.label = value,
            VaultScreen::AddCertSlot => app.vault.certificate_slot_form.label = value,
            VaultScreen::EditKeyslotLabel => app.vault.edit_keyslot_label_form.label = value,
            _ => {}
        },
        Message::VaultKeyslotCertPathChanged(value) => match app.vault.screen {
            VaultScreen::AddCertSlot => app.vault.certificate_slot_form.cert_path = value,
            VaultScreen::RewrapCertSlot => app.vault.certificate_rewrap_form.cert_path = value,
            _ => {}
        },
        Message::VaultRecoverySecretChanged(value) => {
            if matches!(app.vault.screen, VaultScreen::RotateRecoverySecret) {
                app.vault.recovery_secret_form.new_secret = value;
            }
        }
        Message::VaultRecoverySecretConfirmChanged(value) => {
            if matches!(app.vault.screen, VaultScreen::RotateRecoverySecret) {
                app.vault.recovery_secret_form.confirm_secret = value;
            }
        }
        Message::VaultBackupPathChanged(value) => match app.vault.screen {
            VaultScreen::ExportBackup => app.vault.export_backup_form.path = value,
            VaultScreen::ImportBackup => app.vault.import_backup_form.path = value,
            _ => {}
        },
        Message::VaultBackupOverwriteChanged(value) => {
            if matches!(app.vault.screen, VaultScreen::ImportBackup) {
                app.vault.import_backup_form.overwrite = value;
            }
        }
        Message::VaultTransferPathChanged(value) => match app.vault.screen {
            VaultScreen::ExportTransfer => app.vault.export_transfer_form.path = value,
            VaultScreen::ImportTransfer => app.vault.import_transfer_form.path = value,
            _ => {}
        },
        Message::VaultTransferPasswordChanged(value) => match app.vault.screen {
            VaultScreen::ExportTransfer => app.vault.export_transfer_form.package_password = value,
            VaultScreen::ImportTransfer => app.vault.import_transfer_form.package_password = value,
            _ => {}
        },
        Message::VaultTransferCertPathChanged(value) => match app.vault.screen {
            VaultScreen::ExportTransfer => app.vault.export_transfer_form.cert_path = value,
            VaultScreen::ImportTransfer => app.vault.import_transfer_form.cert_path = value,
            _ => {}
        },
        Message::VaultTransferKeyPathChanged(value) => {
            if matches!(app.vault.screen, VaultScreen::ImportTransfer) {
                app.vault.import_transfer_form.key_path = value;
            }
        }
        Message::VaultTransferKeyPassphraseChanged(value) => {
            if matches!(app.vault.screen, VaultScreen::ImportTransfer) {
                app.vault.import_transfer_form.key_passphrase = value;
            }
        }
        Message::VaultTransferReplaceExistingChanged(value) => {
            if matches!(app.vault.screen, VaultScreen::ImportTransfer) {
                app.vault.import_transfer_form.replace_existing = value;
            }
        }
        Message::VaultEnrollMnemonicSlot => match submit_vault_mnemonic_slot(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Mnemonic enrollment failed: {error}"),
        },
        Message::VaultEnrollDeviceSlot => match submit_vault_device_slot(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Device keyslot enrollment failed: {error}"),
        },
        Message::VaultEnrollCertSlot => match submit_vault_certificate_slot(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Certificate enrollment failed: {error}"),
        },
        Message::VaultRewrapCertSlot => match submit_vault_certificate_rewrap(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Certificate rewrap failed: {error}"),
        },
        Message::VaultSaveKeyslotLabel => match submit_vault_keyslot_label_edit(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Keyslot relabel failed: {error}"),
        },
        Message::VaultRotateMnemonicSlot => match submit_vault_rotate_mnemonic_slot(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Mnemonic rotation failed: {error}"),
        },
        Message::VaultRotateRecoverySecret => match submit_vault_rotate_recovery_secret(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Recovery secret rotation failed: {error}"),
        },
        Message::VaultRemoveSelectedKeyslot => match submit_vault_remove_keyslot(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Keyslot removal failed: {error}"),
        },
        Message::VaultRebindSelectedDeviceSlot => match submit_vault_rebind_device_slot(app) {
            Ok(()) => {}
            Err(error) => app.status = format!("Device keyslot rebind failed: {error}"),
        },
        Message::VaultCopyMnemonic => {
            if let Some(enrollment) = &app.vault.latest_mnemonic_enrollment {
                match Clipboard::new()
                    .and_then(|mut clipboard| clipboard.set_text(enrollment.mnemonic.clone()))
                {
                    Ok(()) => {
                        app.session.arm_clipboard_clear(enrollment.mnemonic.clone());
                        app.status = format!(
                            "Copied the recovery phrase to the clipboard. It will be cleared in {} seconds if unchanged.",
                            app.session.clipboard_clear_after().as_secs()
                        );
                    }
                    Err(error) => {
                        app.status = format!("Clipboard unavailable: {error}");
                    }
                }
            } else {
                app.status = "No mnemonic recovery phrase is available to copy.".to_string();
            }
        }
    }
    Task::none()
}

fn view(app: &GuiApp) -> Element<'_, Message> {
    let nav = row![
        button("Generator").on_press(Message::SwitchSurface(Surface::Generator)),
        button("Vault").on_press(Message::SwitchSurface(Surface::Vault)),
    ]
    .spacing(12);

    let content = match app.surface {
        Surface::Generator => match app.generator_screen {
            GeneratorScreen::Configure => configure_view(app),
            GeneratorScreen::Audit => audit_view(app),
            GeneratorScreen::Results => results_view(app),
        },
        Surface::Vault => vault_view(app),
    };

    container(column![nav, content].spacing(16))
        .padding(24)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn configure_view(app: &GuiApp) -> Element<'_, Message> {
    let options = charset_options(&app.request);
    let frameworks = paranoid_core::frameworks().iter().fold(
        column![text("Frameworks").size(22)].spacing(8),
        |column, framework| {
            column.push(
                checkbox(app.request.selected_frameworks.contains(&framework.id))
                    .label(framework.name)
                    .on_toggle(move |enabled| Message::FrameworkChanged(framework.id, enabled)),
            )
        },
    );
    let validation = match app.request.resolve() {
        Ok(resolved) => format!(
            "Ready: {} password(s), {} chars, {:.2} bits per password.",
            resolved.count,
            resolved.length,
            (resolved.charset.len() as f64).log2() * resolved.length as f64
        ),
        Err(error) => error.to_string(),
    };
    let body = row![
        scrollable(
            column![
                text("paranoid-passwd").size(34),
                text("Configure the native generator and audit model."),
                row![
                    text_input("Length", &app.length_input).on_input(Message::LengthChanged),
                    text_input("Count", &app.count_input).on_input(Message::CountChanged),
                    text_input("Audit batch", &app.batch_input).on_input(Message::BatchChanged),
                ]
                .spacing(12),
                row![
                    text_input("Min lower", &app.min_lower_input)
                        .on_input(Message::MinLowerChanged),
                    text_input("Min upper", &app.min_upper_input)
                        .on_input(Message::MinUpperChanged),
                    text_input("Min digits", &app.min_digits_input)
                        .on_input(Message::MinDigitsChanged),
                    text_input("Min symbols", &app.min_symbols_input)
                        .on_input(Message::MinSymbolsChanged),
                ]
                .spacing(12),
                checkbox(options.include_lowercase)
                    .label("Lowercase")
                    .on_toggle(Message::ToggleLowercase),
                checkbox(options.include_uppercase)
                    .label("Uppercase")
                    .on_toggle(Message::ToggleUppercase),
                checkbox(options.include_digits)
                    .label("Digits")
                    .on_toggle(Message::ToggleDigits),
                checkbox(options.include_symbols)
                    .label("Symbols")
                    .on_toggle(Message::ToggleSymbols),
                checkbox(options.include_space)
                    .label("Include space")
                    .on_toggle(Message::ToggleSpace),
                checkbox(options.exclude_ambiguous)
                    .label("Exclude ambiguous")
                    .on_toggle(Message::ToggleAmbiguous),
                text_input("Custom charset override", &app.custom_charset_input)
                    .on_input(Message::CustomCharsetChanged),
                button("Generate + Run 7-Layer Audit").on_press(Message::RunAudit),
            ]
            .spacing(12)
        )
        .width(Length::FillPortion(3)),
        scrollable(
            column![
                frameworks,
                text("Validation").size(22),
                text(validation),
                text("The GUI uses the same typed request/result model as the CLI and TUI."),
                text(app.status.as_str()),
            ]
            .spacing(12)
        )
        .width(Length::FillPortion(2)),
    ]
    .spacing(20);

    column![body].into()
}

fn audit_view(app: &GuiApp) -> Element<'_, Message> {
    let progress = match app.current_stage {
        None => 0.0,
        Some(AuditStage::Generate) => 1.0 / 7.0,
        Some(AuditStage::ChiSquared) => 2.0 / 7.0,
        Some(AuditStage::SerialCorrelation) => 3.0 / 7.0,
        Some(AuditStage::CollisionDetection) => 4.0 / 7.0,
        Some(AuditStage::EntropyProofs) => 5.0 / 7.0,
        Some(AuditStage::PatternDetection) => 6.0 / 7.0,
        Some(AuditStage::ThreatAssessment) | Some(AuditStage::Complete) => 1.0,
    };
    let stages = [
        AuditStage::Generate,
        AuditStage::ChiSquared,
        AuditStage::SerialCorrelation,
        AuditStage::CollisionDetection,
        AuditStage::EntropyProofs,
        AuditStage::PatternDetection,
        AuditStage::ThreatAssessment,
    ]
    .into_iter()
    .fold(
        column![text("7-Layer Audit").size(30)].spacing(8),
        |column, stage| {
            let label = if app.completed_stages.contains(&stage) {
                format!("✓ {}", stage.label())
            } else if app.current_stage == Some(stage) {
                format!("→ {}", stage.label())
            } else {
                format!("· {}", stage.label())
            };
            column.push(text(label))
        },
    );
    column![
        text("Generate & Audit").size(34),
        text(format!("Progress: {:.0}%", progress * 100.0)),
        stages,
        text(app.status.as_str()),
    ]
    .spacing(14)
    .into()
}

fn results_view(app: &GuiApp) -> Element<'_, Message> {
    let Some(report) = &app.report else {
        return text("No report available.").into();
    };
    let Some(audit) = &report.audit else {
        return text("Audit summary unavailable.").into();
    };
    let Some(primary) = report.passwords.first() else {
        return text("No generated password available.").into();
    };

    let tabs = DetailTab::ALL
        .into_iter()
        .fold(row![].spacing(8), |row, tab| {
            row.push(button(tab.label()).on_press(Message::SelectTab(tab)))
        });

    let detail = match app.detail_tab {
        DetailTab::Summary => column![
            text(if audit.overall_pass {
                "CRYPTOGRAPHICALLY SOUND"
            } else {
                "REVIEW FLAGGED ITEMS"
            })
            .size(26),
            text(format!("Primary: {}", primary.value)),
            text(format!("SHA-256: {}", primary.sha256_hex)),
            text(format!(
                "Primary verdict: {}",
                if primary.all_pass { "PASS" } else { "REVIEW" }
            )),
            text(format!(
                "Additional passwords: {}",
                report.passwords.len().saturating_sub(1)
            )),
        ]
        .spacing(8),
        DetailTab::Compliance => report.passwords.iter().enumerate().fold(
            column![text("Selected Frameworks").size(24)].spacing(8),
            |column, (index, password)| {
                let label = if index == 0 {
                    "Primary".to_string()
                } else {
                    format!("Additional {}", index + 1)
                };
                let selected = password
                    .compliance
                    .iter()
                    .filter(|status| status.selected)
                    .map(|status| {
                        format!(
                            "{} {}",
                            if status.passed { "✓" } else { "✗" },
                            status.name
                        )
                    })
                    .collect::<Vec<_>>();
                column.push(text(format!(
                    "{label}: {}",
                    if selected.is_empty() {
                        "no frameworks selected".to_string()
                    } else {
                        selected.join(", ")
                    }
                )))
            },
        ),
        DetailTab::Entropy => column![
            text("Entropy").size(24),
            text(format!("Charset size: {}", audit.charset_size)),
            text(format!("Password length: {}", audit.password_length)),
            text(format!("Bits per character: {:.4}", audit.entropy.bits_per_char)),
            text(format!("Total entropy: {:.2} bits", audit.entropy.total_entropy)),
            text(format!(
                "Brute-force @ 1T/s: {:.2e} years",
                audit.entropy.brute_force_years
            )),
        ]
        .spacing(8),
        DetailTab::Stats => column![
            text("Batch Statistics").size(24),
            text(format!(
                "Chi-squared: {:.2} (df={}, p={:.4})",
                audit.chi2_statistic, audit.chi2_df, audit.chi2_p_value
            )),
            text(format!(
                "Serial correlation: {:.6}",
                audit.serial_correlation
            )),
            text(format!("Duplicates: {} / {}", audit.duplicates, audit.batch_size)),
            text(format!(
                "Rejection boundary: {} ({:.4}% rejected)",
                audit.rejection_max_valid, audit.rejection_rate_pct
            )),
        ]
        .spacing(8),
        DetailTab::Threats => column![
            text("Threat Model").size(24),
            text("T1 Training-data leakage — mitigated by OpenSSL-backed OS entropy."),
            text("T2 Token-distribution bias — mitigated by rejection sampling."),
            text("T3 Deterministic regeneration — mitigated by hardware entropy."),
            text("T4 Prompt injection steering — residual risk in source review."),
            text("T5 Hallucinated security claims — residual risk, review the math."),
            text("T6 Screen exposure — operational risk, clear copied passwords."),
        ]
        .spacing(8),
        DetailTab::SelfAudit => column![
            text("Self-Audit").size(24),
            text("The GUI consumes the same typed report as the CLI and TUI."),
            text("Batch statistics stay separated from per-password verdicts."),
            text("Selected frameworks are enforced per emitted password."),
            text("This desktop surface remains native-only; no webview trust boundary is reintroduced."),
        ]
        .spacing(8),
    };

    column![
        text("Results").size(34),
        text(format!("Primary password: {}", primary.value)),
        row![
            button("Copy primary password").on_press(Message::CopyPrimary),
            button("Back to configuration").on_press(Message::GoToConfigure),
        ]
        .spacing(12),
        tabs,
        scrollable(detail),
        text(app.status.as_str()),
    ]
    .spacing(16)
    .align_x(Alignment::Start)
    .into()
}

fn vault_view(app: &GuiApp) -> Element<'_, Message> {
    match app.vault.screen {
        VaultScreen::UnlockBlocked => vault_unlock_blocked_view(app),
        VaultScreen::List => vault_list_view(app),
        VaultScreen::Keyslots
        | VaultScreen::AddMnemonicSlot
        | VaultScreen::AddDeviceSlot
        | VaultScreen::AddCertSlot
        | VaultScreen::RewrapCertSlot
        | VaultScreen::EditKeyslotLabel
        | VaultScreen::RotateMnemonicSlot
        | VaultScreen::RotateRecoverySecret
        | VaultScreen::MnemonicReveal => vault_keyslot_view(app),
        VaultScreen::AddLogin | VaultScreen::EditLogin => vault_login_form_view(app),
        VaultScreen::AddNote | VaultScreen::EditNote => vault_note_form_view(app),
        VaultScreen::AddCard | VaultScreen::EditCard => vault_card_form_view(app),
        VaultScreen::AddIdentity | VaultScreen::EditIdentity => vault_identity_form_view(app),
        VaultScreen::GenerateStore => vault_generate_form_view(app),
        VaultScreen::ExportBackup => vault_export_backup_view(app),
        VaultScreen::ExportTransfer => vault_export_transfer_view(app),
        VaultScreen::ImportBackup => vault_import_backup_view(app),
        VaultScreen::ImportTransfer => vault_import_transfer_view(app),
        VaultScreen::DeleteConfirm => vault_delete_confirm_view(app),
    }
}

fn vault_unlock_blocked_view(app: &GuiApp) -> Element<'_, Message> {
    let mode_buttons = VaultUnlockMode::ALL
        .into_iter()
        .fold(row![].spacing(8), |row, mode| {
            let label = if app.vault.unlock_form.mode == mode {
                format!("● {}", mode.label())
            } else {
                mode.label().to_string()
            };
            row.push(button(text(label)).on_press(Message::SelectVaultUnlockMode(mode)))
        });

    let mode_form = match app.vault.unlock_form.mode {
        VaultUnlockMode::Password => column![
            text_input("Recovery secret", &app.vault.unlock_form.password)
                .on_input(Message::VaultUnlockPasswordChanged)
                .secure(true),
            text("Use the Argon2id recovery secret directly instead of reading an environment variable."),
        ]
        .spacing(12),
        VaultUnlockMode::Mnemonic => column![
            text_input("Recovery phrase", &app.vault.unlock_form.mnemonic_phrase)
                .on_input(Message::VaultUnlockMnemonicChanged)
                .secure(true),
            text_input("Mnemonic slot id (optional)", &app.vault.unlock_form.mnemonic_slot)
                .on_input(Message::VaultUnlockMnemonicSlotChanged),
            text("Use the wallet-style recovery phrase directly and optionally force a specific mnemonic slot."),
        ]
        .spacing(12),
        VaultUnlockMode::Device => column![
            text_input(
                "Device slot id (optional)",
                &app.vault.unlock_form.device_slot
            )
            .on_input(Message::VaultUnlockDeviceSlotChanged),
            text("Leave the slot blank to let the native vault unlock path choose the sole available device-bound slot."),
        ]
        .spacing(12),
        VaultUnlockMode::Certificate => column![
            text_input("Recipient cert PEM path", &app.vault.unlock_form.cert_path)
                .on_input(Message::VaultUnlockCertPathChanged),
            text_input("Private key PEM path", &app.vault.unlock_form.key_path)
                .on_input(Message::VaultUnlockKeyPathChanged),
            text_input(
                "Key passphrase (optional)",
                &app.vault.unlock_form.key_passphrase
            )
            .on_input(Message::VaultUnlockKeyPassphraseChanged)
            .secure(true),
            text("Use the certificate-backed unwrap path without requiring shell env setup."),
        ]
        .spacing(12),
    };

    column![
        text("Vault").size(34),
        text("Unlock blocked"),
        text(app.status.as_str()),
        text("The GUI uses the same unlock policy as the CLI and TUI, but it can now supply native direct secrets instead of relying on shell env configuration."),
        text(format!("Vault path: {}", app.vault.options.path.display())),
        mode_buttons,
        mode_form,
        row![
            button("Unlock vault").on_press(Message::VaultAttemptNativeUnlock),
            button("Retry current policy").on_press(Message::RefreshVault),
        ]
        .spacing(12),
    ]
    .spacing(12)
    .into()
}

fn vault_list_view(app: &GuiApp) -> Element<'_, Message> {
    let actions = row![
        button("Refresh").on_press(Message::RefreshVault),
        button("Unlock Method").on_press(Message::OpenVaultUnlockSettings),
        button("Keyslots").on_press(Message::OpenVaultKeyslots),
        button("Add Login").on_press(Message::OpenVaultAddLogin),
        button("Add Note").on_press(Message::OpenVaultAddNote),
        button("Add Card").on_press(Message::OpenVaultAddCard),
        button("Add Identity").on_press(Message::OpenVaultAddIdentity),
        button("Export Backup").on_press(Message::OpenVaultExportBackup),
        button("Export Transfer").on_press(Message::OpenVaultExportTransfer),
        button("Import Backup").on_press(Message::OpenVaultImportBackup),
        button("Import Transfer").on_press(Message::OpenVaultImportTransfer),
        maybe_button(
            "Edit",
            app.vault.detail.is_some(),
            Message::OpenVaultEditLogin
        ),
        maybe_button(
            "Delete",
            app.vault.detail.is_some(),
            Message::OpenVaultDelete
        ),
        button("Generate + Store").on_press(Message::OpenVaultGenerateStore),
        maybe_button(
            "Copy Secret",
            app.vault.detail.is_some(),
            Message::VaultCopySelected
        ),
    ]
    .spacing(8);

    let access = vault_access_summary(app);
    let search = text_input("Filter unlocked vault items", &app.vault.search_query)
        .on_input(Message::VaultSearchChanged);
    let filter_kind = text_input(
        "Kind (login|secure_note|card|identity)",
        &app.vault.filter_kind,
    )
    .on_input(Message::VaultFilterKindChanged);
    let filter_folder =
        text_input("Folder", &app.vault.filter_folder).on_input(Message::VaultFilterFolderChanged);
    let filter_tag =
        text_input("Tag", &app.vault.filter_tag).on_input(Message::VaultFilterTagChanged);
    let item_list = app.vault.items.iter().enumerate().fold(
        column![text("Items").size(22)].spacing(8),
        |column, (index, item)| {
            let selected = index == app.vault.selected_index;
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
            let label = if selected {
                format!(
                    "› {}{} · {}{}",
                    item.title, folder_marker, item.subtitle, duplicate_marker
                )
            } else {
                format!(
                    "{}{} · {}{}",
                    item.title, folder_marker, item.subtitle, duplicate_marker
                )
            };
            column.push(button(text(label)).on_press(Message::SelectVaultItem(index)))
        },
    );

    let left = column![
        text("Vault").size(34),
        actions,
        access,
        search,
        row![filter_kind, filter_folder, filter_tag].spacing(8),
        text(format!(
            "Active filters: {}",
            vault_filter_summary(&app.vault)
        )),
        scrollable(item_list).height(Length::Fill),
    ]
    .spacing(12)
    .width(Length::FillPortion(2));

    let right = scrollable(vault_detail_panel(app)).width(Length::FillPortion(3));
    row![left, right].spacing(20).into()
}

fn vault_keyslot_view(app: &GuiApp) -> Element<'_, Message> {
    let selected_keyslot = selected_keyslot(app);
    let remove_label = if selected_keyslot
        .map(|slot| {
            app.vault.pending_keyslot_removal_confirmation.as_deref() == Some(slot.id.as_str())
        })
        .unwrap_or(false)
    {
        "Confirm Remove"
    } else {
        "Remove Selected"
    };
    let actions = row![
        button("Back to Vault").on_press(Message::VaultCancelFlow),
        button("Refresh").on_press(Message::RefreshVault),
        button("Add Mnemonic").on_press(Message::OpenVaultAddMnemonicSlot),
        button("Add Device").on_press(Message::OpenVaultAddDeviceSlot),
        button("Add Certificate").on_press(Message::OpenVaultAddCertSlot),
        maybe_button(
            "Rewrap Certificate",
            selected_keyslot
                .map(|slot| slot.kind == paranoid_vault::VaultKeyslotKind::CertificateWrapped)
                .unwrap_or(false),
            Message::OpenVaultRewrapCertSlot,
        ),
        maybe_button(
            "Edit Label",
            selected_keyslot.is_some(),
            Message::OpenVaultEditKeyslotLabel,
        ),
        maybe_button(
            "Rotate Mnemonic",
            selected_keyslot
                .map(|slot| slot.kind == paranoid_vault::VaultKeyslotKind::MnemonicRecovery)
                .unwrap_or(false),
            Message::OpenVaultRotateMnemonicSlot,
        ),
        button("Rotate Recovery").on_press(Message::OpenVaultRotateRecoverySecret),
        maybe_button(
            remove_label,
            selected_keyslot
                .map(|slot| slot.kind != paranoid_vault::VaultKeyslotKind::PasswordRecovery)
                .unwrap_or(false),
            Message::VaultRemoveSelectedKeyslot,
        ),
        maybe_button(
            "Rebind Device",
            selected_keyslot
                .map(|slot| slot.kind == paranoid_vault::VaultKeyslotKind::DeviceBound)
                .unwrap_or(false),
            Message::VaultRebindSelectedDeviceSlot,
        ),
    ]
    .spacing(8);

    let item_list = app
        .vault
        .header
        .as_ref()
        .map(|header| {
            header.keyslots.iter().enumerate().fold(
                column![text("Keyslots").size(22)].spacing(8),
                |column, (index, keyslot)| {
                    let selected = index == app.vault.selected_keyslot_index;
                    let label = keyslot.label.as_deref().unwrap_or(keyslot.kind.as_str());
                    let line = if selected {
                        format!("› {label} · {}", keyslot.kind.as_str())
                    } else {
                        format!("{label} · {}", keyslot.kind.as_str())
                    };
                    column.push(button(text(line)).on_press(Message::SelectVaultKeyslot(index)))
                },
            )
        })
        .unwrap_or_else(|| {
            column![text("Keyslots").size(22), text("No keyslots loaded.")].spacing(8)
        });

    let left = column![
        text("Vault Keyslots").size(34),
        actions,
        vault_access_summary(app),
        scrollable(item_list).height(Length::Fill),
    ]
    .spacing(12)
    .width(Length::FillPortion(2));

    let right = scrollable(vault_keyslot_panel(app)).width(Length::FillPortion(3));
    row![left, right].spacing(20).into()
}

fn vault_access_summary(app: &GuiApp) -> Element<'_, Message> {
    let keyslots = app
        .vault
        .header
        .as_ref()
        .map(|header| header.keyslots.len().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let posture = app
        .vault
        .header
        .as_ref()
        .map(|header| header.recovery_posture());
    let recommendations = app
        .vault
        .header
        .as_ref()
        .map(|header| header.recovery_recommendations())
        .unwrap_or_default();
    let mut summary = column![
        text("Access").size(22),
        text(format!("Vault path: {}", app.vault.options.path.display())),
        text(format!(
            "Unlock: {}",
            app.vault.options.unlock_description()
        )),
        text(format!("Keyslots: {keyslots}")),
        text(format!(
            "Recovery posture: recovery={} cert={} recommended={}",
            posture
                .as_ref()
                .map(|value| value.has_recovery_path)
                .unwrap_or(false),
            posture
                .as_ref()
                .map(|value| value.has_certificate_path)
                .unwrap_or(false),
            posture
                .as_ref()
                .map(|value| value.meets_recommended_posture)
                .unwrap_or(false)
        )),
        text(format!(
            "Counts: password={} mnemonic={} device={} cert={}",
            posture
                .as_ref()
                .map(|value| value.password_recovery_slots)
                .unwrap_or_default(),
            posture
                .as_ref()
                .map(|value| value.mnemonic_recovery_slots)
                .unwrap_or_default(),
            posture
                .as_ref()
                .map(|value| value.device_bound_slots)
                .unwrap_or_default(),
            posture
                .as_ref()
                .map(|value| value.certificate_wrapped_slots)
                .unwrap_or_default()
        )),
    ]
    .spacing(6);
    for recommendation in recommendations {
        summary = summary.push(text(format!("recommend: {recommendation}")));
    }
    summary.into()
}

fn vault_detail_panel(app: &GuiApp) -> Element<'_, Message> {
    match &app.vault.detail {
        Some(item) => match &item.payload {
            VaultItemPayload::Login(login) => {
                let duplicate_password_count = app
                    .vault
                    .items
                    .iter()
                    .find(|summary| summary.id == item.id)
                    .map(|summary| summary.duplicate_password_count)
                    .unwrap_or(0);
                column![
                text("Selected login").size(26),
                text(format!("id: {}", item.id)),
                text(format!("title: {}", login.title)),
                text(format!("username: {}", login.username)),
                text(format!("password: {}", login.password)),
                text(format!(
                    "duplicate passwords elsewhere: {duplicate_password_count}"
                )),
                text(format!("url: {}", login.url.as_deref().unwrap_or(""))),
                text(format!("notes: {}", login.notes.as_deref().unwrap_or(""))),
                text(format!("folder: {}", login.folder.as_deref().unwrap_or(""))),
                text(format!("tags: {}", login.tags.join(", "))),
                text(format!(
                    "password history entries: {}",
                    login.password_history.len()
                )),
                text(format!(
                    "recent history: {}",
                    if login.password_history.is_empty() {
                        String::new()
                    } else {
                        login.password_history
                            .iter()
                            .rev()
                            .take(3)
                            .map(|entry| format!("{} @ {}", entry.password, entry.changed_at_epoch))
                            .collect::<Vec<_>>()
                            .join(" | ")
                    }
                )),
                text(format!("updated_at_epoch: {}", item.updated_at_epoch)),
                text("The GUI now supports native Login CRUD, SecureNote CRUD, and generate-and-store flows."),
                text(app.status.as_str()),
            ]
            .spacing(8)
            .into()
            }
            VaultItemPayload::SecureNote(note) => column![
                text("Selected secure note").size(26),
                text(format!("id: {}", item.id)),
                text(format!("title: {}", note.title)),
                text(format!("content: {}", note.content)),
                text(format!("folder: {}", note.folder.as_deref().unwrap_or(""))),
                text(format!("tags: {}", note.tags.join(", "))),
                text(format!("updated_at_epoch: {}", item.updated_at_epoch)),
                text("The GUI now supports native SecureNote CRUD alongside Login flows."),
                text(app.status.as_str()),
            ]
            .spacing(8)
            .into(),
            VaultItemPayload::Card(card) => column![
                text("Selected card").size(26),
                text(format!("id: {}", item.id)),
                text(format!("title: {}", card.title)),
                text(format!("cardholder: {}", card.cardholder_name)),
                text(format!("number: {}", card.number)),
                text(format!(
                    "expiry: {}/{}",
                    card.expiry_month, card.expiry_year
                )),
                text(format!("security code: {}", card.security_code)),
                text(format!(
                    "billing zip: {}",
                    card.billing_zip.as_deref().unwrap_or("")
                )),
                text(format!("notes: {}", card.notes.as_deref().unwrap_or(""))),
                text(format!("folder: {}", card.folder.as_deref().unwrap_or(""))),
                text(format!("tags: {}", card.tags.join(", "))),
                text(format!("updated_at_epoch: {}", item.updated_at_epoch)),
                text("The GUI now supports native Card CRUD alongside Login and SecureNote flows."),
                text(app.status.as_str()),
            ]
            .spacing(8)
            .into(),
            VaultItemPayload::Identity(identity) => column![
                text("Selected identity").size(26),
                text(format!("id: {}", item.id)),
                text(format!("title: {}", identity.title)),
                text(format!("full name: {}", identity.full_name)),
                text(format!(
                    "email: {}",
                    identity.email.as_deref().unwrap_or("")
                )),
                text(format!(
                    "phone: {}",
                    identity.phone.as_deref().unwrap_or("")
                )),
                text(format!(
                    "address: {}",
                    identity.address.as_deref().unwrap_or("")
                )),
                text(format!(
                    "notes: {}",
                    identity.notes.as_deref().unwrap_or("")
                )),
                text(format!("folder: {}", identity.folder.as_deref().unwrap_or(""))),
                text(format!("tags: {}", identity.tags.join(", "))),
                text(format!("updated_at_epoch: {}", item.updated_at_epoch)),
                text("The GUI now supports native Identity CRUD alongside Login, SecureNote, and Card flows."),
                text(app.status.as_str()),
            ]
            .spacing(8)
            .into(),
        },
        None => column![
            text("Vault detail").size(26),
            text("No vault item selected yet."),
            text("Add a login, add a secure note, add a card, add an identity, or generate and store one to begin using the encrypted local vault."),
            text(app.status.as_str()),
        ]
        .spacing(8)
        .into(),
    }
}

fn vault_keyslot_panel(app: &GuiApp) -> Element<'_, Message> {
    match app.vault.screen {
        VaultScreen::AddMnemonicSlot => vault_mnemonic_slot_form_view(app),
        VaultScreen::AddDeviceSlot => vault_device_slot_form_view(app),
        VaultScreen::AddCertSlot => vault_certificate_slot_form_view(app),
        VaultScreen::RewrapCertSlot => vault_certificate_rewrap_form_view(app),
        VaultScreen::EditKeyslotLabel => vault_keyslot_label_form_view(app),
        VaultScreen::RotateMnemonicSlot => vault_rotate_mnemonic_slot_view(app),
        VaultScreen::RotateRecoverySecret => vault_rotate_recovery_secret_view(app),
        VaultScreen::MnemonicReveal => vault_mnemonic_reveal_view(app),
        _ => vault_keyslot_detail_panel(app),
    }
}

fn vault_keyslot_detail_panel(app: &GuiApp) -> Element<'_, Message> {
    let Some(keyslot) = selected_keyslot(app) else {
        return column![
            text("Selected keyslot").size(26),
            text("No keyslot selected yet."),
            text(
                "Enroll mnemonic, device-bound, or certificate-wrapped access from this native GUI."
            ),
            text(app.status.as_str()),
        ]
        .spacing(8)
        .into();
    };

    let posture = app
        .vault
        .header
        .as_ref()
        .map(|header| header.recovery_posture());

    let mut body = column![
        text("Selected keyslot").size(26),
        text(format!("id: {}", keyslot.id)),
        text(format!("kind: {}", keyslot.kind.as_str())),
        text(format!("label: {}", keyslot.label.as_deref().unwrap_or(""))),
        text(format!(
            "wrapped_by_os_keystore: {}",
            keyslot.wrapped_by_os_keystore
        )),
        text(format!("wrap algorithm: {}", keyslot.wrap_algorithm)),
        text(format!(
            "Recovery posture: recovery={} cert={} recommended={}",
            posture
                .as_ref()
                .map(|value| value.has_recovery_path)
                .unwrap_or(false),
            posture
                .as_ref()
                .map(|value| value.has_certificate_path)
                .unwrap_or(false),
            posture
                .as_ref()
                .map(|value| value.meets_recommended_posture)
                .unwrap_or(false)
        )),
    ]
    .spacing(8);

    if let Some(fingerprint) = &keyslot.certificate_fingerprint_sha256 {
        body = body.push(text(format!("certificate sha256: {fingerprint}")));
    }
    if let Some(subject) = &keyslot.certificate_subject {
        body = body.push(text(format!("certificate subject: {subject}")));
    }
    if let Some(not_before) = &keyslot.certificate_not_before {
        body = body.push(text(format!("certificate valid from: {not_before}")));
    }
    if let Some(not_after) = &keyslot.certificate_not_after {
        body = body.push(text(format!("certificate valid until: {not_after}")));
    }
    if let Some(language) = &keyslot.mnemonic_language {
        body = body.push(text(format!("mnemonic language: {language}")));
    }
    if let Some(words) = keyslot.mnemonic_words {
        body = body.push(text(format!("mnemonic words: {words}")));
    }
    if let Some(service) = &keyslot.device_service {
        body = body.push(text(format!("device service: {service}")));
    }
    if let Some(account) = &keyslot.device_account {
        body = body.push(text(format!("device account: {account}")));
    }
    if let Some(header) = &app.vault.header
        && let Ok(health) = header.assess_keyslot_health(keyslot.id.as_str())
    {
        body = body.push(text(format!("healthy: {}", health.healthy)));
        for warning in health.warnings {
            body = body.push(text(format!("health warning: {warning}")));
        }
    }
    if let Some(header) = &app.vault.header
        && let Ok(impact) = header.assess_keyslot_removal(keyslot.id.as_str())
    {
        body = body.push(text(format!(
            "removal requires confirmation: {}",
            impact.requires_explicit_confirmation
        )));
        if impact.warnings.is_empty() {
            body = body.push(text("removal impact: no posture downgrade detected."));
        } else {
            for warning in impact.warnings {
                body = body.push(text(format!("warning: {warning}")));
            }
        }
    }
    if app.vault.pending_keyslot_removal_confirmation.as_deref() == Some(keyslot.id.as_str()) {
        body = body.push(text(
            "Removal confirmation armed for this slot. Select Confirm Remove to proceed.",
        ));
    }

    body.push(text(app.status.as_str())).into()
}

fn vault_mnemonic_slot_form_view(app: &GuiApp) -> Element<'_, Message> {
    let form = &app.vault.mnemonic_slot_form;
    column![
        text("Add Mnemonic Slot").size(34),
        text_input("Label (optional)", &form.label).on_input(Message::VaultKeyslotLabelChanged),
        row![
            button("Enroll Mnemonic Slot").on_press(Message::VaultEnrollMnemonicSlot),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text("A 24-word recovery phrase will be generated and shown once after saving."),
        text("Store it offline. This path is for disaster recovery, not daily use."),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_device_slot_form_view(app: &GuiApp) -> Element<'_, Message> {
    let form = &app.vault.device_slot_form;
    column![
        text("Add Device Slot").size(34),
        text_input("Label (optional)", &form.label).on_input(Message::VaultKeyslotLabelChanged),
        row![
            button("Enroll Device Slot").on_press(Message::VaultEnrollDeviceSlot),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text("This stores the unwrap secret in platform secure storage for passwordless daily unlock."),
        text("Keep a separate recovery path active before relying on device-bound access."),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_certificate_slot_form_view(app: &GuiApp) -> Element<'_, Message> {
    let form = &app.vault.certificate_slot_form;
    let mut content = column![
        text("Add Certificate Slot").size(34),
        text_input("Label (optional)", &form.label).on_input(Message::VaultKeyslotLabelChanged),
        text_input("Recipient cert PEM path", &form.cert_path)
            .on_input(Message::VaultKeyslotCertPathChanged),
        row![
            button("Enroll Certificate Slot").on_press(Message::VaultEnrollCertSlot),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text("The certificate file must already exist on disk in PEM format."),
        text("Only the public recipient certificate is needed to enroll this slot."),
    ]
    .spacing(12);
    if let Some(preview) = vault_certificate_preview_view(form.cert_path.as_str()) {
        content = content.push(preview);
    }
    content.push(text(app.status.as_str())).into()
}

fn vault_certificate_rewrap_form_view(app: &GuiApp) -> Element<'_, Message> {
    let form = &app.vault.certificate_rewrap_form;
    let current = selected_keyslot(app);
    let mut content = column![
        text("Rewrap Certificate Slot").size(34),
        text_input("Replacement cert PEM path", &form.cert_path)
            .on_input(Message::VaultKeyslotCertPathChanged),
        text_input("Replacement key PEM path (optional)", &form.key_path)
            .on_input(Message::VaultUnlockKeyPathChanged),
        text_input(
            "Replacement key passphrase (optional)",
            &form.key_passphrase
        )
        .on_input(Message::VaultUnlockKeyPassphraseChanged)
        .secure(true),
        row![
            button("Rewrap Certificate Slot").on_press(Message::VaultRewrapCertSlot),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text(format!(
            "Current fingerprint: {}",
            current
                .and_then(|slot| slot.certificate_fingerprint_sha256.as_deref())
                .unwrap_or("")
        )),
        text(format!(
            "Current subject: {}",
            current
                .and_then(|slot| slot.certificate_subject.as_deref())
                .unwrap_or("")
        )),
        text(format!(
            "Current valid from: {}",
            current
                .and_then(|slot| slot.certificate_not_before.as_deref())
                .unwrap_or("")
        )),
        text(format!(
            "Current valid until: {}",
            current
                .and_then(|slot| slot.certificate_not_after.as_deref())
                .unwrap_or("")
        )),
        text(
            "This replaces the recipient certificate while preserving the same keyslot id and recovery posture semantics.",
        ),
        text(
            "Leave replacement key path/passphrase blank to keep the active native session key settings unchanged.",
        ),
    ]
    .spacing(12);
    if let Some(preview) = vault_certificate_preview_view(form.cert_path.as_str()) {
        content = content.push(preview);
    }
    content.push(text(app.status.as_str())).into()
}

fn vault_certificate_preview_view(path: &str) -> Option<Element<'static, Message>> {
    let path = normalize_optional_field(path)?;
    let content = match fs::read(path.as_str()) {
        Ok(cert_pem) => match inspect_certificate_pem(cert_pem.as_slice()) {
            Ok(preview) => column![
                text("Certificate preview").size(18),
                text(format!("fingerprint: {}", preview.fingerprint_sha256)),
                text(format!("subject: {}", preview.subject)),
                text(format!("valid from: {}", preview.not_before)),
                text(format!("valid until: {}", preview.not_after)),
            ]
            .spacing(4),
            Err(error) => column![
                text("Certificate preview").size(18),
                text(format!("unavailable: {error}")),
            ]
            .spacing(4),
        },
        Err(error) => column![
            text("Certificate preview").size(18),
            text(format!("unavailable: {error}")),
        ]
        .spacing(4),
    };
    Some(container(content).into())
}

fn vault_keyslot_label_form_view(app: &GuiApp) -> Element<'_, Message> {
    let form = &app.vault.edit_keyslot_label_form;
    let current_label = selected_keyslot(app)
        .and_then(|slot| slot.label.as_deref())
        .unwrap_or("");
    column![
        text("Edit Keyslot Label").size(34),
        text_input("Label (blank clears it)", &form.label)
            .on_input(Message::VaultKeyslotLabelChanged),
        row![
            button("Save Keyslot Label").on_press(Message::VaultSaveKeyslotLabel),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text(format!("Current label: {current_label}")),
        text(
            "This only updates operator-visible metadata. Recovery posture and wrapped key material stay unchanged.",
        ),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_rotate_mnemonic_slot_view(app: &GuiApp) -> Element<'_, Message> {
    let selected = selected_keyslot(app);
    column![
        text("Rotate Mnemonic Slot").size(34),
        text(format!(
            "slot id: {}",
            selected.map(|slot| slot.id.as_str()).unwrap_or("")
        )),
        text(format!(
            "label: {}",
            selected
                .and_then(|slot| slot.label.as_deref())
                .unwrap_or("(cleared)")
        )),
        row![
            button("Rotate Mnemonic Slot").on_press(Message::VaultRotateMnemonicSlot),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text(
            "This replaces the current offline recovery phrase while preserving the same keyslot id and vault master key.",
        ),
        text(
            "The old phrase stops unlocking immediately after rotation. The replacement phrase is shown once on the next screen.",
        ),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_rotate_recovery_secret_view(app: &GuiApp) -> Element<'_, Message> {
    let form = &app.vault.recovery_secret_form;
    column![
        text("Rotate Recovery Secret").size(34),
        text_input("New recovery secret", &form.new_secret)
            .secure(true)
            .on_input(Message::VaultRecoverySecretChanged),
        text_input("Confirm recovery secret", &form.confirm_secret)
            .secure(true)
            .on_input(Message::VaultRecoverySecretConfirmChanged),
        row![
            button("Rotate Recovery Secret").on_press(Message::VaultRotateRecoverySecret),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text(
            "This rewraps only the password recovery keyslot. Mnemonic, device, and certificate slots remain valid.",
        ),
        text(
            "Use it after moving to passwordless daily unlock so the offline recovery secret does not remain frozen at vault-init time.",
        ),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_mnemonic_reveal_view(app: &GuiApp) -> Element<'_, Message> {
    let body = match &app.vault.latest_mnemonic_enrollment {
        Some(enrollment) => column![
            text("Recovery Phrase").size(34),
            text(format!("slot id: {}", enrollment.keyslot.id)),
            text(format!(
                "label: {}",
                enrollment.keyslot.label.as_deref().unwrap_or("")
            )),
            text(enrollment.mnemonic.as_str()),
            row![
                button("Copy Phrase").on_press(Message::VaultCopyMnemonic),
                button("Back to Keyslots").on_press(Message::VaultCancelFlow),
            ]
            .spacing(12),
            text("Write this phrase down and store it offline."),
            text(app.status.as_str()),
        ]
        .spacing(12),
        None => column![
            text("Recovery Phrase").size(34),
            text("No mnemonic enrollment is available to display."),
            button("Back to Keyslots").on_press(Message::VaultCancelFlow),
            text(app.status.as_str()),
        ]
        .spacing(12),
    };
    body.into()
}

fn vault_login_form_view(app: &GuiApp) -> Element<'_, Message> {
    let title = if matches!(app.vault.screen, VaultScreen::EditLogin) {
        "Edit Login"
    } else {
        "Add Login"
    };
    let form = &app.vault.login_form;
    column![
        text(title).size(34),
        text_input("Title", &form.title).on_input(Message::VaultTitleChanged),
        text_input("Username", &form.username).on_input(Message::VaultUsernameChanged),
        text_input("Password", &form.password).on_input(Message::VaultPasswordChanged),
        text_input("URL (optional)", &form.url).on_input(Message::VaultUrlChanged),
        text_input("Notes (optional)", &form.notes).on_input(Message::VaultNotesChanged),
        text_input("Folder (optional)", &form.folder).on_input(Message::VaultFolderChanged),
        text_input("Tags (csv)", &form.tags).on_input(Message::VaultTagsChanged),
        row![
            button("Save").on_press(Message::VaultSaveLogin),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text("Required: title, username, password."),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_note_form_view(app: &GuiApp) -> Element<'_, Message> {
    let title = if matches!(app.vault.screen, VaultScreen::EditNote) {
        "Edit Secure Note"
    } else {
        "Add Secure Note"
    };
    let form = &app.vault.note_form;
    column![
        text(title).size(34),
        text_input("Title", &form.title).on_input(Message::VaultTitleChanged),
        text_input("Content", &form.content).on_input(Message::VaultContentChanged),
        text_input("Folder (optional)", &form.folder).on_input(Message::VaultFolderChanged),
        text_input("Tags (csv)", &form.tags).on_input(Message::VaultTagsChanged),
        row![
            button("Save").on_press(Message::VaultSaveNote),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text("Required: title, content."),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_card_form_view(app: &GuiApp) -> Element<'_, Message> {
    let title = if matches!(app.vault.screen, VaultScreen::EditCard) {
        "Edit Card"
    } else {
        "Add Card"
    };
    let form = &app.vault.card_form;
    column![
        text(title).size(34),
        text_input("Title", &form.title).on_input(Message::VaultTitleChanged),
        text_input("Cardholder", &form.cardholder_name).on_input(Message::VaultCardholderChanged),
        text_input("Card number", &form.number).on_input(Message::VaultCardNumberChanged),
        row![
            text_input("Expiry month", &form.expiry_month)
                .on_input(Message::VaultExpiryMonthChanged),
            text_input("Expiry year", &form.expiry_year).on_input(Message::VaultExpiryYearChanged),
            text_input("Security code", &form.security_code)
                .on_input(Message::VaultSecurityCodeChanged),
        ]
        .spacing(12),
        text_input("Billing zip (optional)", &form.billing_zip)
            .on_input(Message::VaultBillingZipChanged),
        text_input("Notes (optional)", &form.notes).on_input(Message::VaultNotesChanged),
        text_input("Folder (optional)", &form.folder).on_input(Message::VaultFolderChanged),
        text_input("Tags (csv)", &form.tags).on_input(Message::VaultTagsChanged),
        row![
            button("Save").on_press(Message::VaultSaveCard),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text("Required: title, cardholder, card number, expiry month/year, security code."),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_identity_form_view(app: &GuiApp) -> Element<'_, Message> {
    let title = if matches!(app.vault.screen, VaultScreen::EditIdentity) {
        "Edit Identity"
    } else {
        "Add Identity"
    };
    let form = &app.vault.identity_form;
    column![
        text(title).size(34),
        text_input("Title", &form.title).on_input(Message::VaultTitleChanged),
        text_input("Full name", &form.full_name).on_input(Message::VaultIdentityFullNameChanged),
        text_input("Email (optional)", &form.email).on_input(Message::VaultIdentityEmailChanged),
        text_input("Phone (optional)", &form.phone).on_input(Message::VaultIdentityPhoneChanged),
        text_input("Address (optional)", &form.address)
            .on_input(Message::VaultIdentityAddressChanged),
        text_input("Notes (optional)", &form.notes).on_input(Message::VaultNotesChanged),
        text_input("Folder (optional)", &form.folder).on_input(Message::VaultFolderChanged),
        text_input("Tags (csv)", &form.tags).on_input(Message::VaultTagsChanged),
        row![
            button("Save").on_press(Message::VaultSaveIdentity),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text("Required: title, full name."),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_generate_form_view(app: &GuiApp) -> Element<'_, Message> {
    let form = &app.vault.generate_form;
    let generate_label = if form.target_login_id.is_some() {
        "Generate + Rotate Login"
    } else {
        "Generate + Store"
    };
    let title_label = if form.target_login_id.is_some() {
        "Generate + Rotate"
    } else {
        "Generate + Store"
    };
    let preview = match build_generate_request(form) {
        Ok(request) => {
            let resolved = request.resolve().expect("validated");
            format!(
                "Ready: frameworks={}, charset={}, length={}, minima=({}, {}, {}, {})",
                if request.selected_frameworks.is_empty() {
                    "none".to_string()
                } else {
                    request
                        .selected_frameworks
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                resolved.charset.len(),
                resolved.length,
                resolved.requirements.min_lowercase,
                resolved.requirements.min_uppercase,
                resolved.requirements.min_digits,
                resolved.requirements.min_symbols
            )
        }
        Err(error) => format!("Blocked: {error}"),
    };

    column![
        text(title_label).size(34),
        text_input("Title", &form.title).on_input(Message::VaultTitleChanged),
        text_input("Username", &form.username).on_input(Message::VaultUsernameChanged),
        text_input("URL (optional)", &form.url).on_input(Message::VaultUrlChanged),
        text_input("Notes (optional)", &form.notes).on_input(Message::VaultNotesChanged),
        text_input("Folder (optional)", &form.folder).on_input(Message::VaultFolderChanged),
        text_input("Tags (csv)", &form.tags).on_input(Message::VaultTagsChanged),
        row![
            text_input("Length", &form.length).on_input(Message::VaultLengthChanged),
            text_input("Frameworks (csv)", &form.frameworks)
                .on_input(Message::VaultFrameworksChanged),
        ]
        .spacing(12),
        row![
            text_input("Min lower", &form.min_lower).on_input(Message::VaultMinLowerChanged),
            text_input("Min upper", &form.min_upper).on_input(Message::VaultMinUpperChanged),
            text_input("Min digits", &form.min_digits).on_input(Message::VaultMinDigitsChanged),
            text_input("Min symbols", &form.min_symbols).on_input(Message::VaultMinSymbolsChanged),
        ]
        .spacing(12),
        row![
            button(generate_label).on_press(Message::VaultSaveGenerated),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text(preview),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_export_backup_view(app: &GuiApp) -> Element<'_, Message> {
    let form = &app.vault.export_backup_form;
    column![
        text("Export Backup").size(34),
        text_input("Backup output path", &form.path).on_input(Message::VaultBackupPathChanged),
        row![
            button("Export Backup").on_press(Message::VaultExportBackup),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text("This writes the current encrypted vault header and ciphertext rows into a portable JSON package."),
        text("The live vault file is not modified by export."),
        vault_backup_summary_view(current_vault_backup_summary(&app.vault)),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_export_transfer_view(app: &GuiApp) -> Element<'_, Message> {
    let form = &app.vault.export_transfer_form;
    let package_password = if form.package_password.trim().is_empty() {
        "(unset)"
    } else {
        "(set)"
    };
    column![
        text("Export Transfer").size(34),
        text_input("Transfer output path", &form.path).on_input(Message::VaultTransferPathChanged),
        text_input("Package recovery secret (optional)", &form.package_password)
            .on_input(Message::VaultTransferPasswordChanged)
            .secure(true),
        text_input("Recipient cert PEM path (optional)", &form.cert_path)
            .on_input(Message::VaultTransferCertPathChanged),
        row![
            button("Export Transfer").on_press(Message::VaultExportTransfer),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text("This writes the currently filtered decrypted item payloads into a separate encrypted transfer package."),
        text("Provide a package recovery secret, a recipient certificate, or both."),
        text(format!(
            "Current selection: total={} · filters={}",
            app.vault.items.len(),
            vault_filter_summary(&app.vault)
        )),
        text(format!(
            "unwrap paths: recovery_secret={} · certificate={}",
            !form.package_password.trim().is_empty(),
            !form.cert_path.trim().is_empty()
        )),
        text(format!("package secret: {package_password}")),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_import_backup_view(app: &GuiApp) -> Element<'_, Message> {
    let form = &app.vault.import_backup_form;
    column![
        text("Import Backup").size(34),
        text_input("Backup input path", &form.path).on_input(Message::VaultBackupPathChanged),
        checkbox(form.overwrite)
            .label("Overwrite current vault path")
            .on_toggle(Message::VaultBackupOverwriteChanged),
        text(format!(
            "Destination vault path: {}",
            app.vault.options.path.display()
        )),
        row![
            button("Import Backup").on_press(Message::VaultImportBackup),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text("Import replaces the current local vault file when overwrite is enabled."),
        text("Use this for restore and migration, not for ad hoc editing of the backup JSON."),
        vault_backup_summary_view(inspected_vault_backup_summary(&form.path)),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_import_transfer_view(app: &GuiApp) -> Element<'_, Message> {
    let form = &app.vault.import_transfer_form;
    let package_password = if form.package_password.trim().is_empty() {
        "(unset)"
    } else {
        "(set)"
    };
    let key_passphrase = if form.key_passphrase.trim().is_empty() {
        "(unset)"
    } else {
        "(set)"
    };
    column![
        text("Import Transfer").size(34),
        text_input("Transfer input path", &form.path).on_input(Message::VaultTransferPathChanged),
        checkbox(form.replace_existing)
            .label("Replace conflicting ids instead of remapping")
            .on_toggle(Message::VaultTransferReplaceExistingChanged),
        text_input("Package recovery secret (optional)", &form.package_password)
            .on_input(Message::VaultTransferPasswordChanged)
            .secure(true),
        text_input("Recipient cert PEM path (optional)", &form.cert_path)
            .on_input(Message::VaultTransferCertPathChanged),
        text_input("Private key PEM path (optional)", &form.key_path)
            .on_input(Message::VaultTransferKeyPathChanged),
        text_input("Private key passphrase (optional)", &form.key_passphrase)
            .on_input(Message::VaultTransferKeyPassphraseChanged)
            .secure(true),
        row![
            button("Import Transfer").on_press(Message::VaultImportTransfer),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text(format!(
            "Destination vault path: {}",
            app.vault.options.path.display()
        )),
        text("Choose either the package recovery secret or the certificate keypair for unwrap."),
        text(format!(
            "package secret: {package_password} · key passphrase: {key_passphrase}"
        )),
        vault_transfer_summary_view(inspected_vault_transfer_summary(&form.path)),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn vault_delete_confirm_view(app: &GuiApp) -> Element<'_, Message> {
    let target = app
        .vault
        .detail
        .as_ref()
        .map(|item| match &item.payload {
            VaultItemPayload::Login(login) => format!("{} · {}", login.title, login.username),
            VaultItemPayload::SecureNote(note) => note.title.clone(),
            VaultItemPayload::Card(card) => format!("{} · {}", card.title, card.cardholder_name),
            VaultItemPayload::Identity(identity) => {
                format!("{} · {}", identity.title, identity.full_name)
            }
        })
        .unwrap_or_else(|| "No selected item".to_string());

    column![
        text("Delete Item").size(34),
        text(format!("Delete: {target}")),
        text("This removes the encrypted record permanently."),
        row![
            button("Delete").on_press(Message::VaultConfirmDelete),
            button("Cancel").on_press(Message::VaultCancelFlow),
        ]
        .spacing(12),
        text(app.status.as_str()),
    ]
    .spacing(12)
    .into()
}

fn apply_native_unlock_settings(app: &mut GuiApp) {
    app.vault.options.mnemonic_phrase_env = None;
    app.vault.options.mnemonic_phrase = None;
    app.vault.options.mnemonic_slot = None;
    app.vault.options.device_slot = None;
    app.vault.options.use_device_auto = false;
    app.vault.options.auth = VaultAuth::PasswordEnv("PARANOID_MASTER_PASSWORD".to_string());

    match app.vault.unlock_form.mode {
        VaultUnlockMode::Password => {
            app.vault.options.auth =
                VaultAuth::Password(SecretString::new(app.vault.unlock_form.password.clone()));
        }
        VaultUnlockMode::Mnemonic => {
            app.vault.options.mnemonic_phrase = Some(SecretString::new(
                app.vault.unlock_form.mnemonic_phrase.clone(),
            ));
            app.vault.options.mnemonic_slot =
                normalize_optional_field(&app.vault.unlock_form.mnemonic_slot);
        }
        VaultUnlockMode::Device => {
            let slot = normalize_optional_field(&app.vault.unlock_form.device_slot);
            if let Some(slot_id) = slot {
                app.vault.options.device_slot = Some(slot_id);
            } else {
                app.vault.options.use_device_auto = true;
            }
        }
        VaultUnlockMode::Certificate => {
            app.vault.options.auth = VaultAuth::Certificate {
                cert_path: app.vault.unlock_form.cert_path.trim().into(),
                key_path: app.vault.unlock_form.key_path.trim().into(),
                key_passphrase_env: None,
                key_passphrase: normalize_optional_field(&app.vault.unlock_form.key_passphrase)
                    .map(SecretString::new),
            };
        }
    }
}

fn sync_device_fallback_target(app: &mut GuiApp, preferred_slot_id: Option<&str>) {
    if !matches!(app.vault.options.auth, VaultAuth::PasswordEnv(_)) {
        return;
    }
    let device_slot_ids = app
        .vault
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
        app.vault.options.device_slot = Some(slot_id.to_string());
        app.vault.options.use_device_auto = false;
        return;
    }

    match device_slot_ids.as_slice() {
        [slot_id] => {
            app.vault.options.device_slot = Some(slot_id.clone());
            app.vault.options.use_device_auto = false;
        }
        _ => {
            app.vault.options.device_slot = None;
            app.vault.options.use_device_auto = false;
        }
    }
}

fn sync_rotated_mnemonic_unlock(app: &mut GuiApp, enrollment: &MnemonicRecoveryEnrollment) {
    if app.vault.options.mnemonic_phrase.is_some()
        || app.vault.options.mnemonic_phrase_env.is_some()
    {
        app.vault.options.mnemonic_phrase = Some(SecretString::new(enrollment.mnemonic.clone()));
        app.vault.options.mnemonic_phrase_env = None;
        app.vault.options.mnemonic_slot = Some(enrollment.keyslot.id.clone());
    }
}

fn sync_rewrapped_certificate_unlock(
    app: &mut GuiApp,
    replaced_slot: &VaultKeyslot,
    replacement_cert_path: &str,
    replacement_key_path: Option<&str>,
    replacement_key_passphrase: Option<&str>,
) {
    let (active_cert_path, active_key_path, active_key_passphrase_env, active_key_passphrase) =
        match &app.vault.options.auth {
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
            app.vault
                .header
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

    app.vault.options.auth = VaultAuth::Certificate {
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

fn schedule_session_tick() -> Task<Message> {
    Task::perform(
        async move {
            thread::sleep(Duration::from_secs(1));
        },
        |_| Message::SessionTick,
    )
}

fn message_counts_as_activity(message: &Message) -> bool {
    !matches!(message, Message::Poll | Message::SessionTick)
}

fn poll_session_hardening(app: &mut GuiApp) {
    if let Some(expected) = app.session.take_due_clipboard_contents() {
        match clear_clipboard_if_matches(expected.as_str()) {
            Ok(true) => {
                app.status = format!(
                    "Clipboard cleared automatically after {} seconds.",
                    app.session.clipboard_clear_after().as_secs()
                );
            }
            Ok(false) => {}
            Err(error) => {
                app.status = format!("Clipboard auto-clear failed: {error}");
            }
        }
    }

    if !matches!(app.vault.screen, VaultScreen::UnlockBlocked) && app.session.should_auto_lock() {
        if let Some(expected) = app.session.take_pending_clipboard_contents() {
            let _ = clear_clipboard_if_matches(expected.as_str());
        }
        app.session.clear_clipboard_tracking();
        app.vault.header = None;
        app.vault.items.clear();
        app.vault.selected_index = 0;
        app.vault.detail = None;
        app.vault.editing_item_id = None;
        app.vault.latest_mnemonic_enrollment = None;
        app.vault.screen = VaultScreen::UnlockBlocked;
        app.status = format!(
            "Vault auto-locked after {} seconds of inactivity.",
            app.session.idle_lock_after().as_secs()
        );
        app.session.note_activity();
    }
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

fn maybe_button(
    label: impl Into<String>,
    enabled: bool,
    message: Message,
) -> Element<'static, Message> {
    let label = label.into();
    if enabled {
        button(text(label)).on_press(message).into()
    } else {
        button(text(label)).into()
    }
}

fn build_vault_item_filter(state: &VaultState) -> Result<VaultItemFilter, String> {
    let kind = normalize_optional_field(&state.filter_kind)
        .map(|value| VaultItemKind::parse(value.as_str()).map_err(|error| error.to_string()))
        .transpose()?;
    Ok(VaultItemFilter {
        query: normalize_optional_field(&state.search_query),
        kind,
        folder: normalize_optional_field(&state.filter_folder),
        tag: normalize_optional_field(&state.filter_tag),
    })
}

fn vault_filter_summary(state: &VaultState) -> String {
    let mut parts = Vec::new();
    if let Some(query) = normalize_optional_field(&state.search_query) {
        parts.push(format!("query={query}"));
    }
    if let Some(kind) = normalize_optional_field(&state.filter_kind) {
        parts.push(format!("kind={kind}"));
    }
    if let Some(folder) = normalize_optional_field(&state.filter_folder) {
        parts.push(format!("folder={folder}"));
    }
    if let Some(tag) = normalize_optional_field(&state.filter_tag) {
        parts.push(format!("tag={tag}"));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

fn current_vault_backup_summary(state: &VaultState) -> Result<VaultBackupSummary, String> {
    let vault = unlock_vault_for_options(&state.options).map_err(|error| error.to_string())?;
    vault.backup_summary().map_err(|error| error.to_string())
}

fn inspected_vault_backup_summary(path: &str) -> Result<VaultBackupSummary, String> {
    let Some(path) = normalize_optional_field(path) else {
        return Err("enter a backup path to inspect the package summary".to_string());
    };
    inspect_vault_backup(path).map_err(|error| error.to_string())
}

fn inspected_vault_transfer_summary(path: &str) -> Result<VaultTransferSummary, String> {
    let Some(path) = normalize_optional_field(path) else {
        return Err("enter a transfer path to inspect the package summary".to_string());
    };
    inspect_vault_transfer(path).map_err(|error| error.to_string())
}

fn vault_backup_summary_view(
    summary: Result<VaultBackupSummary, String>,
) -> Element<'static, Message> {
    match summary {
        Ok(summary) => {
            let mut column = column![
                text("Backup summary").size(22),
                text(format!(
                    "restorable: {} · exported_at_epoch: {}",
                    summary.restorable_by_current_build, summary.exported_at_epoch
                )),
                text(format!(
                    "items: total={} login={} note={} card={} identity={}",
                    summary.item_count,
                    summary.login_count,
                    summary.secure_note_count,
                    summary.card_count,
                    summary.identity_count
                )),
                text(format!(
                    "keyslots: total={} recovery={} cert={} recommended={}",
                    summary.keyslot_count,
                    summary.recovery_posture.has_recovery_path,
                    summary.recovery_posture.has_certificate_path,
                    summary.recovery_posture.meets_recommended_posture
                )),
                text(format!(
                    "formats: backup={} vault={} header={}",
                    summary.backup_format_version,
                    summary.vault_format_version,
                    summary.header_format_version
                )),
            ]
            .spacing(4);
            for keyslot in summary.keyslots.iter().take(3) {
                column = column.push(text(format!(
                    "keyslot: {} · {} · {}",
                    keyslot.id,
                    keyslot.kind.as_str(),
                    keyslot.label.as_deref().unwrap_or("")
                )));
                if let Some(subject) = &keyslot.certificate_subject {
                    column = column.push(text(format!("subject: {subject}")));
                }
                if let Some(not_after) = &keyslot.certificate_not_after {
                    column = column.push(text(format!("valid until: {not_after}")));
                }
            }
            if summary.keyslots.len() > 3 {
                column = column.push(text(format!(
                    "... {} more keyslots not shown in preview",
                    summary.keyslots.len() - 3
                )));
            }
            for warning in summary.warnings.into_iter().take(3) {
                column = column.push(text(format!("warning: {warning}")));
            }
            container(column).into()
        }
        Err(error) => container(
            column![
                text("Backup summary").size(22),
                text(format!("unavailable: {error}")),
            ]
            .spacing(4),
        )
        .into(),
    }
}

fn vault_transfer_summary_view(
    summary: Result<VaultTransferSummary, String>,
) -> Element<'static, Message> {
    match summary {
        Ok(summary) => {
            let mut column = column![
                text("Transfer summary").size(22),
                text(format!(
                    "importable: {} · exported_at_epoch: {}",
                    summary.importable_by_current_build, summary.exported_at_epoch
                )),
                text(format!(
                    "items: total={} login={} note={} card={} identity={}",
                    summary.item_count,
                    summary.login_count,
                    summary.secure_note_count,
                    summary.card_count,
                    summary.identity_count
                )),
                text(format!(
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
                text(format!(
                    "unwrap paths: recovery_secret={} · certificate={}",
                    summary.has_recovery_path, summary.has_certificate_path
                )),
            ]
            .spacing(4);
            if let Some(subject) = &summary.certificate_subject {
                column = column.push(text(format!("certificate subject: {subject}")));
            }
            if let Some(not_after) = &summary.certificate_not_after {
                column = column.push(text(format!("certificate valid until: {not_after}")));
            }
            for warning in summary.warnings.into_iter().take(3) {
                column = column.push(text(format!("warning: {warning}")));
            }
            container(column).into()
        }
        Err(error) => container(
            column![
                text("Transfer summary").size(22),
                text(format!("unavailable: {error}")),
            ]
            .spacing(4),
        )
        .into(),
    }
}

fn refresh_vault_state(app: &mut GuiApp) -> Result<(), String> {
    let preserve_keyslot_view = matches!(
        app.vault.screen,
        VaultScreen::Keyslots
            | VaultScreen::AddMnemonicSlot
            | VaultScreen::AddDeviceSlot
            | VaultScreen::AddCertSlot
            | VaultScreen::RewrapCertSlot
            | VaultScreen::EditKeyslotLabel
            | VaultScreen::RotateMnemonicSlot
            | VaultScreen::RotateRecoverySecret
            | VaultScreen::MnemonicReveal
    );
    match unlock_vault_for_options(&app.vault.options) {
        Ok(vault) => {
            app.vault.header = Some(vault.header().clone());
            let filter = match build_vault_item_filter(&app.vault) {
                Ok(filter) => filter,
                Err(error) => {
                    app.status = format!("Vault filter is invalid: {error}");
                    return Err(error);
                }
            };
            app.vault.items = vault
                .list_items_filtered(&filter)
                .map_err(|error| error.to_string())?;
            if app.vault.items.is_empty() {
                app.vault.selected_index = 0;
                app.vault.detail = None;
            } else {
                app.vault.selected_index = app
                    .vault
                    .selected_index
                    .min(app.vault.items.len().saturating_sub(1));
                let selected_id = app.vault.items[app.vault.selected_index].id.clone();
                app.vault.detail = Some(
                    vault
                        .get_item(&selected_id)
                        .map_err(|error| error.to_string())?,
                );
            }
            let keyslot_count = app
                .vault
                .header
                .as_ref()
                .map(|header| header.keyslots.len())
                .unwrap_or_default();
            app.vault.selected_keyslot_index = app
                .vault
                .selected_keyslot_index
                .min(keyslot_count.saturating_sub(1));
            if app
                .vault
                .pending_keyslot_removal_confirmation
                .as_ref()
                .is_some_and(|pending| {
                    !app.vault.header.as_ref().is_some_and(|header| {
                        header.keyslots.iter().any(|slot| &slot.id == pending)
                    })
                })
            {
                app.vault.pending_keyslot_removal_confirmation = None;
            }
            app.vault.screen = if preserve_keyslot_view {
                VaultScreen::Keyslots
            } else {
                VaultScreen::List
            };
            app.status = if vault_filter_summary(&app.vault) == "none" {
                format!(
                    "Vault unlocked. {} item(s) loaded via {}.",
                    app.vault.items.len(),
                    app.vault.options.unlock_description()
                )
            } else {
                format!(
                    "Vault unlocked. {} item(s) match [{}] via {}.",
                    app.vault.items.len(),
                    vault_filter_summary(&app.vault),
                    app.vault.options.unlock_description()
                )
            };
            Ok(())
        }
        Err(error) => {
            app.vault.items.clear();
            app.vault.detail = None;
            app.vault.screen = VaultScreen::UnlockBlocked;
            app.status = format!("Unlock blocked: {error}");
            Err(error.to_string())
        }
    }
}

fn reload_vault_detail(app: &mut GuiApp) -> Result<(), String> {
    let Some(item) = app.vault.items.get(app.vault.selected_index) else {
        app.vault.detail = None;
        return Ok(());
    };
    let vault = unlock_vault_for_options(&app.vault.options).map_err(|error| error.to_string())?;
    app.vault.detail = Some(
        vault
            .get_item(&item.id)
            .map_err(|error| error.to_string())?,
    );
    Ok(())
}

fn submit_vault_login(app: &mut GuiApp) -> Result<(), String> {
    let record = NewLoginRecord {
        title: app.vault.login_form.title.trim().to_string(),
        username: app.vault.login_form.username.trim().to_string(),
        password: app.vault.login_form.password.clone(),
        url: normalize_optional_field(&app.vault.login_form.url),
        notes: normalize_optional_field(&app.vault.login_form.notes),
        folder: normalize_optional_field(&app.vault.login_form.folder),
        tags: parse_tags_csv(&app.vault.login_form.tags),
    };

    let result = if let Some(item_id) = app.vault.editing_item_id.clone() {
        unlock_vault_for_options(&app.vault.options)
            .and_then(|vault| {
                vault.update_login(
                    &item_id,
                    UpdateLoginRecord {
                        title: Some(record.title),
                        username: Some(record.username),
                        password: Some(record.password),
                        url: Some(record.url),
                        notes: Some(record.notes),
                        folder: Some(record.folder),
                        tags: Some(record.tags),
                    },
                )
            })
            .map(|item| ("Updated".to_string(), item))
    } else {
        unlock_vault_for_options(&app.vault.options)
            .and_then(|vault| vault.add_login(record))
            .map(|item| ("Stored".to_string(), item))
    };

    match result {
        Ok((verb, item)) => {
            let item_id = item.id.clone();
            app.vault.editing_item_id = None;
            refresh_vault_state(app)?;
            if let Some(index) = app
                .vault
                .items
                .iter()
                .position(|candidate| candidate.id == item_id)
            {
                app.vault.selected_index = index;
                let _ = reload_vault_detail(app);
            }
            app.status = format!("{verb} login item {item_id} in the encrypted vault.");
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn submit_vault_note(app: &mut GuiApp) -> Result<(), String> {
    let record = NewSecureNoteRecord {
        title: app.vault.note_form.title.trim().to_string(),
        content: app.vault.note_form.content.trim().to_string(),
        folder: normalize_optional_field(&app.vault.note_form.folder),
        tags: parse_tags_csv(&app.vault.note_form.tags),
    };

    let result = if let Some(item_id) = app.vault.editing_item_id.clone() {
        unlock_vault_for_options(&app.vault.options)
            .and_then(|vault| {
                vault.update_secure_note(
                    &item_id,
                    UpdateSecureNoteRecord {
                        title: Some(record.title),
                        content: Some(record.content),
                        folder: Some(record.folder),
                        tags: Some(record.tags),
                    },
                )
            })
            .map(|item| ("Updated".to_string(), item))
    } else {
        unlock_vault_for_options(&app.vault.options)
            .and_then(|vault| vault.add_secure_note(record))
            .map(|item| ("Stored".to_string(), item))
    };

    match result {
        Ok((verb, item)) => {
            let item_id = item.id.clone();
            app.vault.editing_item_id = None;
            refresh_vault_state(app)?;
            if let Some(index) = app
                .vault
                .items
                .iter()
                .position(|candidate| candidate.id == item_id)
            {
                app.vault.selected_index = index;
                let _ = reload_vault_detail(app);
            }
            app.status = format!("{verb} secure note {item_id} in the encrypted vault.");
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn submit_vault_card(app: &mut GuiApp) -> Result<(), String> {
    let record = NewCardRecord {
        title: app.vault.card_form.title.trim().to_string(),
        cardholder_name: app.vault.card_form.cardholder_name.trim().to_string(),
        number: app.vault.card_form.number.trim().to_string(),
        expiry_month: app.vault.card_form.expiry_month.trim().to_string(),
        expiry_year: app.vault.card_form.expiry_year.trim().to_string(),
        security_code: app.vault.card_form.security_code.trim().to_string(),
        billing_zip: normalize_optional_field(&app.vault.card_form.billing_zip),
        notes: normalize_optional_field(&app.vault.card_form.notes),
        folder: normalize_optional_field(&app.vault.card_form.folder),
        tags: parse_tags_csv(&app.vault.card_form.tags),
    };

    let result = if let Some(item_id) = app.vault.editing_item_id.clone() {
        unlock_vault_for_options(&app.vault.options)
            .and_then(|vault| {
                vault.update_card(
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
            })
            .map(|item| ("Updated".to_string(), item))
    } else {
        unlock_vault_for_options(&app.vault.options)
            .and_then(|vault| vault.add_card(record))
            .map(|item| ("Stored".to_string(), item))
    };

    match result {
        Ok((verb, item)) => {
            let item_id = item.id.clone();
            app.vault.editing_item_id = None;
            refresh_vault_state(app)?;
            if let Some(index) = app
                .vault
                .items
                .iter()
                .position(|candidate| candidate.id == item_id)
            {
                app.vault.selected_index = index;
                let _ = reload_vault_detail(app);
            }
            app.status = format!("{verb} card {item_id} in the encrypted vault.");
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn submit_vault_identity(app: &mut GuiApp) -> Result<(), String> {
    let record = NewIdentityRecord {
        title: app.vault.identity_form.title.trim().to_string(),
        full_name: app.vault.identity_form.full_name.trim().to_string(),
        email: normalize_optional_field(&app.vault.identity_form.email),
        phone: normalize_optional_field(&app.vault.identity_form.phone),
        address: normalize_optional_field(&app.vault.identity_form.address),
        notes: normalize_optional_field(&app.vault.identity_form.notes),
        folder: normalize_optional_field(&app.vault.identity_form.folder),
        tags: parse_tags_csv(&app.vault.identity_form.tags),
    };

    let result = if let Some(item_id) = app.vault.editing_item_id.clone() {
        unlock_vault_for_options(&app.vault.options)
            .and_then(|vault| {
                vault.update_identity(
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
            })
            .map(|item| ("Updated".to_string(), item))
    } else {
        unlock_vault_for_options(&app.vault.options)
            .and_then(|vault| vault.add_identity(record))
            .map(|item| ("Stored".to_string(), item))
    };

    match result {
        Ok((verb, item)) => {
            let item_id = item.id.clone();
            app.vault.editing_item_id = None;
            refresh_vault_state(app)?;
            if let Some(index) = app
                .vault
                .items
                .iter()
                .position(|candidate| candidate.id == item_id)
            {
                app.vault.selected_index = index;
                let _ = reload_vault_detail(app);
            }
            app.status = format!("{verb} identity {item_id} in the encrypted vault.");
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn submit_vault_generate(app: &mut GuiApp) -> Result<(), String> {
    let request =
        build_generate_request(&app.vault.generate_form).map_err(|error| error.to_string())?;
    let title = app.vault.generate_form.title.trim();
    let username = app.vault.generate_form.username.trim();
    if app.vault.generate_form.target_login_id.is_none()
        && (title.is_empty() || username.is_empty())
    {
        return Err("generate-and-store requires both a title and username".to_string());
    }

    match unlock_vault_for_options(&app.vault.options).and_then(|vault| {
        vault.generate_and_store(
            &request,
            GenerateStoreLoginRecord {
                target_login_id: app.vault.generate_form.target_login_id.clone(),
                title: (!title.is_empty()).then(|| title.to_string()),
                username: (!username.is_empty()).then(|| username.to_string()),
                url: normalize_optional_field(&app.vault.generate_form.url),
                notes: normalize_optional_field(&app.vault.generate_form.notes),
                folder: normalize_optional_field(&app.vault.generate_form.folder),
                tags: Some(parse_tags_csv(&app.vault.generate_form.tags)),
            },
        )
    }) {
        Ok((report, item)) => {
            let verdict = report
                .audit
                .as_ref()
                .map(|audit| if audit.overall_pass { "PASS" } else { "REVIEW" })
                .unwrap_or("PASS");
            let item_id = item.id.clone();
            refresh_vault_state(app)?;
            if let Some(index) = app
                .vault
                .items
                .iter()
                .position(|candidate| candidate.id == item_id)
            {
                app.vault.selected_index = index;
                let _ = reload_vault_detail(app);
            }
            app.status = format!(
                "Generated one password and {} item {item_id}. Generator verdict: {verdict}.",
                if app.vault.generate_form.target_login_id.is_some() {
                    "rotated"
                } else {
                    "stored"
                }
            );
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn submit_vault_export_backup(app: &mut GuiApp) -> Result<(), String> {
    let output = app.vault.export_backup_form.path.trim();
    if output.is_empty() {
        return Err("backup export requires an output path".to_string());
    }
    let written = unlock_vault_for_options(&app.vault.options)
        .and_then(|vault| vault.export_backup(output))
        .map_err(|error| error.to_string())?;
    app.vault.screen = VaultScreen::List;
    app.status = format!("Exported encrypted vault backup to {}.", written.display());
    Ok(())
}

fn submit_vault_export_transfer(app: &mut GuiApp) -> Result<(), String> {
    let output = app.vault.export_transfer_form.path.trim();
    if output.is_empty() {
        return Err("transfer export requires an output path".to_string());
    }
    let package_password =
        normalize_optional_field(&app.vault.export_transfer_form.package_password);
    let cert_path = normalize_optional_field(&app.vault.export_transfer_form.cert_path);
    if package_password.is_none() && cert_path.is_none() {
        return Err(
            "transfer export requires a package recovery secret, recipient certificate, or both"
                .to_string(),
        );
    }
    let filter = build_vault_item_filter(&app.vault)?;
    let cert_pem = cert_path
        .as_ref()
        .map(fs::read)
        .transpose()
        .map_err(|error| error.to_string())?;
    let written = unlock_vault_for_options(&app.vault.options)
        .and_then(|vault| {
            vault.export_transfer_package(
                output,
                &filter,
                package_password.as_deref(),
                cert_pem.as_deref(),
            )
        })
        .map_err(|error| error.to_string())?;
    app.vault.screen = VaultScreen::List;
    app.status = format!(
        "Exported encrypted transfer package for {} current item(s) to {}.",
        app.vault.items.len(),
        written.display()
    );
    Ok(())
}

fn submit_vault_import_backup(app: &mut GuiApp) -> Result<(), String> {
    let input = app.vault.import_backup_form.path.trim().to_string();
    if input.is_empty() {
        return Err("backup import requires an input path".to_string());
    }
    restore_vault_backup(
        &input,
        &app.vault.options.path,
        app.vault.import_backup_form.overwrite,
    )
    .map_err(|error| error.to_string())?;
    refresh_vault_state(app)?;
    app.status = format!(
        "Imported encrypted vault backup from {} into {}.",
        input,
        app.vault.options.path.display()
    );
    Ok(())
}

fn submit_vault_import_transfer(app: &mut GuiApp) -> Result<(), String> {
    let input = app.vault.import_transfer_form.path.trim().to_string();
    if input.is_empty() {
        return Err("transfer import requires an input path".to_string());
    }
    let package_password =
        normalize_optional_field(&app.vault.import_transfer_form.package_password);
    let cert_path = normalize_optional_field(&app.vault.import_transfer_form.cert_path);
    let key_path = normalize_optional_field(&app.vault.import_transfer_form.key_path);
    let key_passphrase = normalize_optional_field(&app.vault.import_transfer_form.key_passphrase);
    let use_password = package_password.is_some();
    let use_certificate = cert_path.is_some() || key_path.is_some();
    if use_password && use_certificate {
        return Err(
            "transfer import requires either a package recovery secret or a certificate keypair, not both"
                .to_string(),
        );
    }
    if !use_password && !use_certificate {
        return Err(
            "transfer import requires a package recovery secret or a certificate keypair"
                .to_string(),
        );
    }
    if use_certificate && (cert_path.is_none() || key_path.is_none()) {
        return Err(
            "transfer import requires both a recipient certificate path and private key path"
                .to_string(),
        );
    }

    let summary = if let Some(password) = package_password {
        unlock_vault_for_options(&app.vault.options)
            .and_then(|vault| {
                vault.import_transfer_package_with_password(
                    &input,
                    password.as_str(),
                    app.vault.import_transfer_form.replace_existing,
                )
            })
            .map_err(|error| error.to_string())?
    } else {
        let cert_pem = fs::read(cert_path.as_deref().unwrap_or_default())
            .map_err(|error| error.to_string())?;
        let key_pem =
            fs::read(key_path.as_deref().unwrap_or_default()).map_err(|error| error.to_string())?;
        unlock_vault_for_options(&app.vault.options)
            .and_then(|vault| {
                vault.import_transfer_package_with_certificate(
                    &input,
                    cert_pem.as_slice(),
                    key_pem.as_slice(),
                    key_passphrase.as_deref(),
                    app.vault.import_transfer_form.replace_existing,
                )
            })
            .map_err(|error| error.to_string())?
    };
    refresh_vault_state(app)?;
    app.status = format!(
        "Imported transfer package from {}. imported={} replaced={} remapped={}.",
        input, summary.imported_count, summary.replaced_count, summary.remapped_count
    );
    Ok(())
}

fn delete_selected_vault_item(app: &mut GuiApp) -> Result<(), String> {
    let Some(detail) = &app.vault.detail else {
        return Err("no vault item selected to delete".to_string());
    };
    let item_id = detail.id.clone();
    unlock_vault_for_options(&app.vault.options)
        .and_then(|vault| vault.delete_item(&item_id))
        .map_err(|error| error.to_string())?;
    refresh_vault_state(app)?;
    app.status = format!("Deleted vault item {item_id} from the encrypted vault.");
    Ok(())
}

fn submit_vault_mnemonic_slot(app: &mut GuiApp) -> Result<(), String> {
    let mut vault =
        unlock_vault_for_options(&app.vault.options).map_err(|error| error.to_string())?;
    let enrollment = vault
        .add_mnemonic_keyslot(normalize_optional_field(
            &app.vault.mnemonic_slot_form.label,
        ))
        .map_err(|error| error.to_string())?;
    app.vault.header = Some(vault.header().clone());
    app.vault.selected_keyslot_index = app
        .vault
        .header
        .as_ref()
        .map(|header| header.keyslots.len().saturating_sub(1))
        .unwrap_or(0);
    app.vault.latest_mnemonic_enrollment = Some(enrollment);
    app.vault.screen = VaultScreen::MnemonicReveal;
    app.status =
        "Mnemonic recovery slot enrolled. Capture the phrase offline before leaving this screen."
            .to_string();
    Ok(())
}

fn submit_vault_device_slot(app: &mut GuiApp) -> Result<(), String> {
    let mut vault =
        unlock_vault_for_options(&app.vault.options).map_err(|error| error.to_string())?;
    let slot = vault
        .add_device_keyslot(normalize_optional_field(&app.vault.device_slot_form.label))
        .map_err(|error| error.to_string())?;
    app.vault.header = Some(vault.header().clone());
    sync_device_fallback_target(app, Some(slot.id.as_str()));
    app.vault.selected_keyslot_index = app
        .vault
        .header
        .as_ref()
        .and_then(|header| {
            header
                .keyslots
                .iter()
                .position(|candidate| candidate.id == slot.id)
        })
        .unwrap_or(0);
    app.vault.screen = VaultScreen::Keyslots;
    app.status = format!(
        "Enrolled device-bound keyslot {} in secure storage.",
        slot.id
    );
    Ok(())
}

fn submit_vault_certificate_slot(app: &mut GuiApp) -> Result<(), String> {
    let cert_path = app.vault.certificate_slot_form.cert_path.trim();
    if cert_path.is_empty() {
        return Err("certificate enrollment requires a PEM path".to_string());
    }
    let cert_pem = fs::read(cert_path)
        .map_err(|error| format!("failed to read certificate PEM {cert_path}: {error}"))?;
    let mut vault =
        unlock_vault_for_options(&app.vault.options).map_err(|error| error.to_string())?;
    let slot = vault
        .add_certificate_keyslot(
            cert_pem.as_slice(),
            normalize_optional_field(&app.vault.certificate_slot_form.label),
        )
        .map_err(|error| error.to_string())?;
    let fingerprint = slot
        .certificate_fingerprint_sha256
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    app.vault.header = Some(vault.header().clone());
    app.vault.selected_keyslot_index = app
        .vault
        .header
        .as_ref()
        .and_then(|header| {
            header
                .keyslots
                .iter()
                .position(|candidate| candidate.id == slot.id)
        })
        .unwrap_or(0);
    app.vault.screen = VaultScreen::Keyslots;
    app.status = format!(
        "Enrolled certificate keyslot {} for fingerprint {} (valid until {}).",
        slot.id,
        fingerprint,
        slot.certificate_not_after.unwrap_or_default()
    );
    Ok(())
}

fn submit_vault_certificate_rewrap(app: &mut GuiApp) -> Result<(), String> {
    let keyslot = selected_keyslot(app)
        .cloned()
        .ok_or_else(|| "no keyslot selected to rewrap".to_string())?;
    let cert_path = app
        .vault
        .certificate_rewrap_form
        .cert_path
        .trim()
        .to_string();
    if cert_path.is_empty() {
        return Err("certificate rewrap requires a PEM path".to_string());
    }
    let cert_pem = fs::read(&cert_path)
        .map_err(|error| format!("failed to read certificate PEM {cert_path}: {error}"))?;
    let replacement_key_path =
        normalize_optional_field(&app.vault.certificate_rewrap_form.key_path);
    let replacement_key_passphrase =
        normalize_optional_field(&app.vault.certificate_rewrap_form.key_passphrase);
    let mut vault =
        unlock_vault_for_options(&app.vault.options).map_err(|error| error.to_string())?;
    let updated = vault
        .rewrap_certificate_keyslot(&keyslot.id, cert_pem.as_slice())
        .map_err(|error| error.to_string())?;
    sync_rewrapped_certificate_unlock(
        app,
        &keyslot,
        cert_path.as_str(),
        replacement_key_path.as_deref(),
        replacement_key_passphrase.as_deref(),
    );
    app.vault.header = Some(vault.header().clone());
    app.vault.selected_keyslot_index = app
        .vault
        .header
        .as_ref()
        .and_then(|header| {
            header
                .keyslots
                .iter()
                .position(|candidate| candidate.id == updated.id)
        })
        .unwrap_or(0);
    app.vault.screen = VaultScreen::Keyslots;
    app.status = format!(
        "Rewrapped certificate keyslot {} to fingerprint {} (valid until {}). Active certificate session settings were preserved or updated if this was the active cert slot.",
        updated.id,
        updated.certificate_fingerprint_sha256.unwrap_or_default(),
        updated.certificate_not_after.unwrap_or_default()
    );
    Ok(())
}

fn submit_vault_keyslot_label_edit(app: &mut GuiApp) -> Result<(), String> {
    let keyslot = selected_keyslot(app)
        .cloned()
        .ok_or_else(|| "no keyslot selected to relabel".to_string())?;
    let mut vault =
        unlock_vault_for_options(&app.vault.options).map_err(|error| error.to_string())?;
    let updated = vault
        .relabel_keyslot(
            &keyslot.id,
            normalize_optional_field(&app.vault.edit_keyslot_label_form.label),
        )
        .map_err(|error| error.to_string())?;
    app.vault.header = Some(vault.header().clone());
    app.vault.selected_keyslot_index = app
        .vault
        .header
        .as_ref()
        .and_then(|header| {
            header
                .keyslots
                .iter()
                .position(|candidate| candidate.id == updated.id)
        })
        .unwrap_or(0);
    app.vault.screen = VaultScreen::Keyslots;
    app.status = format!(
        "Updated {} keyslot {} label to {}.",
        updated.kind.as_str(),
        updated.id,
        updated.label.unwrap_or_else(|| "(cleared)".to_string())
    );
    Ok(())
}

fn submit_vault_rotate_mnemonic_slot(app: &mut GuiApp) -> Result<(), String> {
    let keyslot = selected_keyslot(app)
        .cloned()
        .ok_or_else(|| "no keyslot selected to rotate".to_string())?;
    let mut vault =
        unlock_vault_for_options(&app.vault.options).map_err(|error| error.to_string())?;
    let enrollment = vault
        .rotate_mnemonic_keyslot(&keyslot.id)
        .map_err(|error| error.to_string())?;

    app.vault.header = Some(vault.header().clone());
    sync_rotated_mnemonic_unlock(app, &enrollment);
    app.vault.selected_keyslot_index = app
        .vault
        .header
        .as_ref()
        .and_then(|header| {
            header
                .keyslots
                .iter()
                .position(|candidate| candidate.id == enrollment.keyslot.id)
        })
        .unwrap_or(0);
    app.vault.latest_mnemonic_enrollment = Some(enrollment);
    app.vault.screen = VaultScreen::MnemonicReveal;
    app.status =
        "Mnemonic recovery slot rotated. Capture the replacement phrase offline before leaving this screen."
            .to_string();
    Ok(())
}

fn submit_vault_rotate_recovery_secret(app: &mut GuiApp) -> Result<(), String> {
    if app.vault.recovery_secret_form.new_secret.is_empty() {
        return Err("new recovery secret must not be empty".to_string());
    }
    if app.vault.recovery_secret_form.new_secret != app.vault.recovery_secret_form.confirm_secret {
        return Err("recovery secret confirmation must match".to_string());
    }

    let new_secret = app.vault.recovery_secret_form.new_secret.clone();
    let mut vault =
        unlock_vault_for_options(&app.vault.options).map_err(|error| error.to_string())?;
    let keyslot = vault
        .rotate_password_recovery_keyslot(new_secret.as_str())
        .map_err(|error| error.to_string())?;

    app.vault.header = Some(vault.header().clone());
    if matches!(
        app.vault.options.auth,
        VaultAuth::PasswordEnv(_) | VaultAuth::Password(_)
    ) {
        app.vault.options.auth = VaultAuth::Password(SecretString::new(new_secret));
    }
    app.vault.recovery_secret_form = VaultRecoverySecretForm::default();
    app.vault.screen = VaultScreen::Keyslots;
    app.status = format!(
        "Rotated password recovery keyslot {} with {}.",
        keyslot.id, keyslot.wrap_algorithm
    );
    Ok(())
}

fn submit_vault_remove_keyslot(app: &mut GuiApp) -> Result<(), String> {
    let keyslot = selected_keyslot(app)
        .cloned()
        .ok_or_else(|| "no keyslot selected to remove".to_string())?;
    let impact = app
        .vault
        .header
        .as_ref()
        .ok_or_else(|| "no vault header loaded for keyslot analysis".to_string())?
        .assess_keyslot_removal(keyslot.id.as_str())
        .map_err(|error| error.to_string())?;
    let force =
        app.vault.pending_keyslot_removal_confirmation.as_deref() == Some(keyslot.id.as_str());
    if impact.requires_explicit_confirmation && !force {
        app.vault.pending_keyslot_removal_confirmation = Some(keyslot.id.clone());
        app.status = format!(
            "Removal of {} requires confirmation: {} Select Remove again to proceed.",
            keyslot.id,
            impact.warnings.join(" ")
        );
        return Ok(());
    }
    let mut vault =
        unlock_vault_for_options(&app.vault.options).map_err(|error| error.to_string())?;
    let removed = vault
        .remove_keyslot(&keyslot.id, force)
        .map_err(|error| error.to_string())?;
    app.vault.header = Some(vault.header().clone());
    app.vault.pending_keyslot_removal_confirmation = None;
    sync_device_fallback_target(app, None);
    let keyslot_count = app
        .vault
        .header
        .as_ref()
        .map(|header| header.keyslots.len())
        .unwrap_or_default();
    app.vault.selected_keyslot_index = app
        .vault
        .selected_keyslot_index
        .min(keyslot_count.saturating_sub(1));
    app.vault.screen = VaultScreen::Keyslots;
    app.status = format!("Removed {} keyslot {}.", removed.kind.as_str(), removed.id);
    Ok(())
}

fn submit_vault_rebind_device_slot(app: &mut GuiApp) -> Result<(), String> {
    let keyslot = selected_keyslot(app)
        .cloned()
        .ok_or_else(|| "no keyslot selected to rebind".to_string())?;
    app.vault.pending_keyslot_removal_confirmation = None;
    let mut vault =
        unlock_vault_for_options(&app.vault.options).map_err(|error| error.to_string())?;
    let updated = vault
        .rebind_device_keyslot(&keyslot.id)
        .map_err(|error| error.to_string())?;
    app.vault.header = Some(vault.header().clone());
    sync_device_fallback_target(app, Some(updated.id.as_str()));
    app.vault.selected_keyslot_index = app
        .vault
        .header
        .as_ref()
        .and_then(|header| {
            header
                .keyslots
                .iter()
                .position(|candidate| candidate.id == updated.id)
        })
        .unwrap_or(0);
    app.vault.screen = VaultScreen::Keyslots;
    app.status = format!(
        "Rebound device-bound keyslot {} to secure-storage account {}.",
        updated.id,
        updated.device_account.unwrap_or_default()
    );
    Ok(())
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

fn selected_keyslot(app: &GuiApp) -> Option<&VaultKeyslot> {
    app.vault
        .header
        .as_ref()
        .and_then(|header| header.keyslots.get(app.vault.selected_keyslot_index))
}

fn build_generate_request(form: &VaultGenerateForm) -> Result<ParanoidRequest, String> {
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
    request.resolve().map_err(|error| error.to_string())?;
    Ok(request)
}

fn parse_usize_field(raw: &str, label: &str) -> Result<usize, String> {
    if raw.is_empty() {
        return Err(format!("{label} is required"));
    }
    raw.parse::<usize>()
        .map_err(|error| format!("{label} must be an integer: {error}"))
}

fn parse_frameworks_csv(raw: &str) -> Result<Vec<FrameworkId>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut frameworks = Vec::new();
    for value in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let framework =
            FrameworkId::parse(value).ok_or_else(|| format!("unknown framework: {value}"))?;
        if !frameworks.contains(&framework) {
            frameworks.push(framework);
        }
    }
    Ok(frameworks)
}

fn charset_options(request: &ParanoidRequest) -> &CharsetOptions {
    match &request.charset {
        CharsetSpec::Options(options) => options,
        CharsetSpec::NamedOrLiteral(_) => unreachable!("GUI uses charset options"),
    }
}

fn charset_options_mut(request: &mut ParanoidRequest) -> &mut CharsetOptions {
    match &mut request.charset {
        CharsetSpec::Options(options) => options,
        CharsetSpec::NamedOrLiteral(_) => unreachable!("GUI uses charset options"),
    }
}

fn apply_frameworks(request: &mut ParanoidRequest) {
    let combined = combined_framework_requirements(&request.selected_frameworks);
    request.length = request.length.max(combined.min_length.max(8));
    charset_options_mut(request).apply_frameworks(&combined);
}

fn sync_inputs_from_request(app: &mut GuiApp) {
    app.length_input = app.request.length.to_string();
    app.count_input = app.request.count.to_string();
    app.batch_input = app.request.batch_size.to_string();
    app.min_lower_input = app.request.requirements.min_lowercase.to_string();
    app.min_upper_input = app.request.requirements.min_uppercase.to_string();
    app.min_digits_input = app.request.requirements.min_digits.to_string();
    app.min_symbols_input = app.request.requirements.min_symbols.to_string();
    app.custom_charset_input = charset_options(&app.request)
        .custom_charset
        .clone()
        .unwrap_or_default();
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
    use paranoid_vault::{SecretString, VaultAuth, unlock_vault, unlock_vault_with_mnemonic};
    use std::{fs, path::Path, path::PathBuf, thread, time::Duration};
    use tempfile::tempdir;

    fn with_test_vault() -> (std::path::PathBuf, VaultOpenOptions) {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_test_vault(&path);
        // Keep tempdir alive by leaking it for the duration of the test process.
        std::mem::forget(tempdir);
        (
            path.clone(),
            VaultOpenOptions {
                path,
                auth: VaultAuth::PasswordEnv("PARANOID_GUI_TEST_PASSWORD".to_string()),
                mnemonic_phrase_env: None,
                mnemonic_phrase: None,
                mnemonic_slot: None,
                device_slot: None,
                use_device_auto: false,
            },
        )
    }

    fn init_test_vault(path: &std::path::Path) {
        paranoid_vault::init_vault(path, "correct horse battery staple").expect("init");
        let mut vault =
            unlock_vault(path, "correct horse battery staple").expect("unlock with password");
        vault
            .add_device_keyslot(Some("gui-test".to_string()))
            .expect("device slot");
    }

    fn with_password_only_vault() -> (std::path::PathBuf, VaultOpenOptions) {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");
        std::mem::forget(tempdir);
        (
            path.clone(),
            VaultOpenOptions {
                path,
                auth: VaultAuth::PasswordEnv("PARANOID_GUI_MISSING_PASSWORD".to_string()),
                mnemonic_phrase_env: None,
                mnemonic_phrase: None,
                mnemonic_slot: None,
                device_slot: None,
                use_device_auto: false,
            },
        )
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
    fn framework_selection_updates_request_constraints() {
        let (mut app, _) = boot();
        let _ = update(
            &mut app,
            Message::FrameworkChanged(FrameworkId::PciDss, true),
        );
        assert!(
            app.request
                .selected_frameworks
                .contains(&FrameworkId::PciDss)
        );
        assert!(app.request.length >= 12);
        assert!(charset_options(&app.request).include_uppercase);
        assert!(charset_options(&app.request).include_digits);
    }

    #[test]
    fn numeric_inputs_update_request() {
        let (mut app, _) = boot();
        let _ = update(&mut app, Message::LengthChanged("40".to_string()));
        let _ = update(&mut app, Message::CountChanged("3".to_string()));
        assert_eq!(app.request.length, 40);
        assert_eq!(app.request.count, 3);
    }

    #[test]
    fn vault_refresh_loads_items_via_shared_options() {
        let (path, options) = with_test_vault();
        let vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
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

        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert_eq!(app.vault.items.len(), 1);
        assert_eq!(app.vault.items[0].folder.as_deref(), Some("Work"));
        let VaultItemPayload::Login(login) = &app.vault.detail.expect("detail").payload else {
            panic!("expected login");
        };
        assert_eq!(login.title, "GitHub");
        assert_eq!(login.tags, vec!["work".to_string()]);
    }

    #[test]
    fn vault_add_login_form_persists_item() {
        let (_path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultAddLogin);
        let _ = update(&mut app, Message::VaultTitleChanged("GitHub".to_string()));
        let _ = update(
            &mut app,
            Message::VaultUsernameChanged("octocat".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultPasswordChanged("hunter2".to_string()),
        );
        let _ = update(&mut app, Message::VaultFolderChanged("Work".to_string()));
        let _ = update(&mut app, Message::VaultTagsChanged("work,code".to_string()));
        let _ = update(&mut app, Message::VaultSaveLogin);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert_eq!(app.vault.items.len(), 1);
        let VaultItemPayload::Login(login) = &app.vault.detail.expect("detail").payload else {
            panic!("expected login");
        };
        assert_eq!(login.username, "octocat");
        assert_eq!(login.folder.as_deref(), Some("Work"));
        assert_eq!(login.tags, vec!["work".to_string(), "code".to_string()]);
    }

    #[test]
    fn vault_add_secure_note_form_persists_item() {
        let (_path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultAddNote);
        let _ = update(&mut app, Message::VaultTitleChanged("Recovery".to_string()));
        let _ = update(
            &mut app,
            Message::VaultContentChanged("Paper copy in the safe.".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultFolderChanged("Recovery".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultTagsChanged("recovery,offline".to_string()),
        );
        let _ = update(&mut app, Message::VaultSaveNote);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert_eq!(app.vault.items.len(), 1);
        let VaultItemPayload::SecureNote(note) = &app.vault.detail.expect("detail").payload else {
            panic!("expected secure note");
        };
        assert_eq!(note.title, "Recovery");
        assert_eq!(note.folder.as_deref(), Some("Recovery"));
        assert_eq!(
            note.tags,
            vec!["recovery".to_string(), "offline".to_string()]
        );
    }

    #[test]
    fn vault_add_card_form_persists_item() {
        let (_path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultAddCard);
        let _ = update(
            &mut app,
            Message::VaultTitleChanged("Primary Visa".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultCardholderChanged("Jon Bogaty".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultCardNumberChanged("4111111111111111".to_string()),
        );
        let _ = update(&mut app, Message::VaultExpiryMonthChanged("08".to_string()));
        let _ = update(
            &mut app,
            Message::VaultExpiryYearChanged("2031".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultSecurityCodeChanged("123".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultBillingZipChanged("60601".to_string()),
        );
        let _ = update(&mut app, Message::VaultFolderChanged("Travel".to_string()));
        let _ = update(
            &mut app,
            Message::VaultTagsChanged("finance,travel".to_string()),
        );
        let _ = update(&mut app, Message::VaultSaveCard);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert_eq!(app.vault.items.len(), 1);
        let VaultItemPayload::Card(card) = &app.vault.detail.expect("detail").payload else {
            panic!("expected card");
        };
        assert_eq!(card.title, "Primary Visa");
        assert_eq!(card.cardholder_name, "Jon Bogaty");
        assert_eq!(card.billing_zip.as_deref(), Some("60601"));
        assert_eq!(card.folder.as_deref(), Some("Travel"));
        assert_eq!(card.tags, vec!["finance".to_string(), "travel".to_string()]);
    }

    #[test]
    fn vault_add_identity_form_persists_item() {
        let (_path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultAddIdentity);
        let _ = update(
            &mut app,
            Message::VaultTitleChanged("Personal Identity".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultIdentityFullNameChanged("Jon Bogaty".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultIdentityEmailChanged("jon@example.com".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultIdentityPhoneChanged("+1-555-0100".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultIdentityAddressChanged("123 Main St".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultFolderChanged("Identity".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultTagsChanged("identity,travel".to_string()),
        );
        let _ = update(&mut app, Message::VaultSaveIdentity);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert_eq!(app.vault.items.len(), 1);
        let VaultItemPayload::Identity(identity) = &app.vault.detail.expect("detail").payload
        else {
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
    }

    #[test]
    fn vault_generate_store_form_persists_item() {
        let (_path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultGenerateStore);
        let _ = update(&mut app, Message::VaultTitleChanged("GitHub".to_string()));
        let _ = update(
            &mut app,
            Message::VaultUsernameChanged("octocat".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultFolderChanged("Generated".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultTagsChanged("generated,work".to_string()),
        );
        let _ = update(&mut app, Message::VaultLengthChanged("20".to_string()));
        let _ = update(
            &mut app,
            Message::VaultFrameworksChanged("nist".to_string()),
        );
        let _ = update(&mut app, Message::VaultSaveGenerated);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert_eq!(app.vault.items.len(), 1);
        let VaultItemPayload::Login(login) = &app.vault.detail.expect("detail").payload else {
            panic!("expected login");
        };
        assert_eq!(login.password.len(), 20);
        assert_eq!(login.folder.as_deref(), Some("Generated"));
        assert_eq!(
            login.tags,
            vec!["generated".to_string(), "work".to_string()]
        );
    }

    #[test]
    fn vault_generate_store_can_rotate_selected_login() {
        let (path, options) = with_test_vault();
        let vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
        vault
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

        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultGenerateStore);
        assert_eq!(
            app.vault.generate_form.target_login_id.as_deref(),
            app.vault.detail.as_ref().map(|item| item.id.as_str())
        );
        let _ = update(&mut app, Message::VaultLengthChanged("20".to_string()));
        let _ = update(
            &mut app,
            Message::VaultFrameworksChanged("nist".to_string()),
        );
        let _ = update(&mut app, Message::VaultSaveGenerated);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        let VaultItemPayload::Login(login) = &app.vault.detail.expect("detail").payload else {
            panic!("expected login");
        };
        assert_eq!(login.password.len(), 20);
        assert_eq!(login.password_history.len(), 1);
        assert_eq!(login.password_history[0].password, "hunter2");
        assert!(app.status.contains("rotated item"));
    }

    #[test]
    fn vault_search_filters_items() {
        let (path, options) = with_test_vault();
        let vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
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

        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);
        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::VaultSearchChanged("octo".to_string()));

        assert_eq!(app.vault.items.len(), 1);
        let VaultItemPayload::Login(login) = &app.vault.detail.expect("detail").payload else {
            panic!("expected login");
        };
        assert_eq!(login.title, "GitHub");
        assert!(app.status.contains("match"));
    }

    #[test]
    fn vault_structured_filters_items() {
        let (path, options) = with_test_vault();
        let vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
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
                notes: Some("backup travel wallet".to_string()),
                folder: Some("Travel".to_string()),
                tags: vec!["travel".to_string(), "finance".to_string()],
            })
            .expect("add card");

        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);
        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(
            &mut app,
            Message::VaultFilterKindChanged("card".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultFilterFolderChanged("Travel".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultFilterTagChanged("finance".to_string()),
        );

        assert_eq!(app.vault.items.len(), 1);
        assert_eq!(app.vault.items[0].kind, VaultItemKind::Card);
        assert_eq!(app.vault.items[0].title, "Travel Card");
        assert!(app.status.contains("kind=card"));
    }

    #[test]
    fn vault_duplicate_password_counts_surface_in_gui_state() {
        let (path, options) = with_test_vault();
        let vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
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

        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);
        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));

        assert!(
            app.vault
                .items
                .iter()
                .any(|summary| summary.duplicate_password_count == 1)
        );
    }

    #[test]
    fn gui_mnemonic_keyslot_enrollment_shows_phrase() {
        let (_path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultKeyslots);
        let _ = update(&mut app, Message::OpenVaultAddMnemonicSlot);
        let _ = update(
            &mut app,
            Message::VaultKeyslotLabelChanged("paper-backup".to_string()),
        );
        let _ = update(&mut app, Message::VaultEnrollMnemonicSlot);

        assert!(matches!(app.vault.screen, VaultScreen::MnemonicReveal));
        assert!(app.vault.latest_mnemonic_enrollment.is_some());
        let enrollment = app
            .vault
            .latest_mnemonic_enrollment
            .as_ref()
            .expect("mnemonic enrollment");
        assert_eq!(enrollment.keyslot.label.as_deref(), Some("paper-backup"));
        assert_eq!(enrollment.mnemonic.split_whitespace().count(), 24);
    }

    #[test]
    fn gui_mnemonic_keyslot_rotation_reveals_replacement_phrase() {
        let (path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultKeyslots);
        let _ = update(&mut app, Message::OpenVaultAddMnemonicSlot);
        let _ = update(
            &mut app,
            Message::VaultKeyslotLabelChanged("paper-backup".to_string()),
        );
        let _ = update(&mut app, Message::VaultEnrollMnemonicSlot);
        let original = app
            .vault
            .latest_mnemonic_enrollment
            .clone()
            .expect("original mnemonic");

        let _ = update(&mut app, Message::VaultCancelFlow);
        let _ = update(&mut app, Message::OpenVaultRotateMnemonicSlot);
        let _ = update(&mut app, Message::VaultRotateMnemonicSlot);

        assert!(matches!(app.vault.screen, VaultScreen::MnemonicReveal));
        let rotated = app
            .vault
            .latest_mnemonic_enrollment
            .as_ref()
            .expect("rotated mnemonic");
        assert_eq!(rotated.keyslot.id, original.keyslot.id);
        assert_eq!(rotated.keyslot.label, original.keyslot.label);
        assert_ne!(rotated.mnemonic, original.mnemonic);
        assert!(app.status.contains("Mnemonic recovery slot rotated"));
        assert!(
            unlock_vault_with_mnemonic(
                &path,
                original.mnemonic.as_str(),
                Some(original.keyslot.id.as_str()),
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
    fn gui_mnemonic_rotation_updates_native_unlock_options() {
        let (path, _options) = with_test_vault();
        let enrollment = {
            let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
            vault
                .add_mnemonic_keyslot(Some("paper-backup".to_string()))
                .expect("add mnemonic")
        };

        let (mut app, _) = boot();
        app.vault.options = VaultOpenOptions {
            path: path.clone(),
            auth: VaultAuth::PasswordEnv("PARANOID_GUI_TEST_PASSWORD".to_string()),
            mnemonic_phrase_env: None,
            mnemonic_phrase: Some(SecretString::new(enrollment.mnemonic.clone())),
            mnemonic_slot: Some(enrollment.keyslot.id.clone()),
            device_slot: None,
            use_device_auto: false,
        };
        let _ = refresh_vault_state(&mut app);
        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultKeyslots);
        let mnemonic_index = app
            .vault
            .header
            .as_ref()
            .and_then(|header| {
                header
                    .keyslots
                    .iter()
                    .position(|slot| slot.id == enrollment.keyslot.id)
            })
            .expect("mnemonic keyslot index");
        let _ = update(&mut app, Message::SelectVaultKeyslot(mnemonic_index));
        let _ = update(&mut app, Message::OpenVaultRotateMnemonicSlot);
        let _ = update(&mut app, Message::VaultRotateMnemonicSlot);

        let rotated = app
            .vault
            .latest_mnemonic_enrollment
            .as_ref()
            .expect("rotated mnemonic");
        assert_eq!(
            app.vault
                .options
                .mnemonic_phrase
                .as_ref()
                .map(SecretString::as_str),
            Some(rotated.mnemonic.as_str())
        );
        assert_eq!(
            app.vault.options.mnemonic_slot.as_deref(),
            Some(rotated.keyslot.id.as_str())
        );
        unlock_vault_for_options(&app.vault.options).expect("refresh uses rotated mnemonic");
    }

    #[test]
    fn gui_device_keyslot_enrollment_updates_keyslot_view() {
        let (_path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let original = app
            .vault
            .header
            .as_ref()
            .map(|header| header.keyslots.len())
            .expect("header");
        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultKeyslots);
        let _ = update(&mut app, Message::OpenVaultAddDeviceSlot);
        let _ = update(
            &mut app,
            Message::VaultKeyslotLabelChanged("daily-gui".to_string()),
        );
        let _ = update(&mut app, Message::VaultEnrollDeviceSlot);

        assert!(matches!(app.vault.screen, VaultScreen::Keyslots));
        let header = app.vault.header.as_ref().expect("header");
        assert_eq!(header.keyslots.len(), original + 1);
        let selected = selected_keyslot(&app).expect("selected keyslot");
        assert_eq!(selected.kind.as_str(), "device_bound");
        assert_eq!(selected.label.as_deref(), Some("daily-gui"));
    }

    #[test]
    fn gui_keyslot_relabel_updates_keyslot_view() {
        let (_path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultKeyslots);
        let _ = update(&mut app, Message::OpenVaultAddDeviceSlot);
        let _ = update(
            &mut app,
            Message::VaultKeyslotLabelChanged("daily-gui".to_string()),
        );
        let _ = update(&mut app, Message::VaultEnrollDeviceSlot);

        let _ = update(&mut app, Message::OpenVaultEditKeyslotLabel);
        let _ = update(
            &mut app,
            Message::VaultKeyslotLabelChanged("laptop daily".to_string()),
        );
        let _ = update(&mut app, Message::VaultSaveKeyslotLabel);

        assert!(matches!(app.vault.screen, VaultScreen::Keyslots));
        let selected = selected_keyslot(&app).expect("selected keyslot");
        assert_eq!(selected.label.as_deref(), Some("laptop daily"));
        assert!(app.status.contains("Updated device_bound keyslot"));
    }

    #[test]
    fn gui_certificate_rewrap_screen_opens_for_selected_certificate_slot() {
        let (path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let mut header = read_vault_header(&path).expect("header");
        header.keyslots.push(VaultKeyslot {
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
        app.vault.header = Some(header);
        app.vault.selected_keyslot_index = app
            .vault
            .header
            .as_ref()
            .map(|header| header.keyslots.len().saturating_sub(1))
            .unwrap_or(0);
        app.surface = Surface::Vault;
        app.vault.screen = VaultScreen::Keyslots;
        let _ = update(&mut app, Message::OpenVaultRewrapCertSlot);

        assert!(matches!(app.vault.screen, VaultScreen::RewrapCertSlot));
        assert!(app.status.contains("replacement recipient certificate PEM"));
    }

    #[test]
    fn gui_certificate_rewrap_updates_active_certificate_unlock_options() {
        let (path, _options) = with_test_vault();
        let (old_cert_path, old_key_path) =
            write_test_certificate_pair(path.parent().expect("vault parent"), "old");
        let (new_cert_path, new_key_path) =
            write_test_certificate_pair(path.parent().expect("vault parent"), "new");

        let keyslot_id = {
            let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
            vault
                .add_certificate_keyslot(
                    fs::read(&old_cert_path).expect("old cert").as_slice(),
                    Some("ops".to_string()),
                )
                .expect("certificate slot")
                .id
        };

        let (mut app, _) = boot();
        app.vault.options = VaultOpenOptions {
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
        let _ = refresh_vault_state(&mut app);
        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultKeyslots);
        let keyslot_index = app
            .vault
            .header
            .as_ref()
            .and_then(|header| {
                header
                    .keyslots
                    .iter()
                    .position(|slot| slot.id == keyslot_id)
            })
            .expect("certificate keyslot index");
        let _ = update(&mut app, Message::SelectVaultKeyslot(keyslot_index));
        let _ = update(&mut app, Message::OpenVaultRewrapCertSlot);
        let _ = update(
            &mut app,
            Message::VaultKeyslotCertPathChanged(new_cert_path.display().to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultUnlockKeyPathChanged(new_key_path.display().to_string()),
        );
        let _ = update(&mut app, Message::VaultRewrapCertSlot);

        match &app.vault.options.auth {
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
        unlock_vault_for_options(&app.vault.options).expect("refresh uses rewrapped certificate");
    }

    #[test]
    fn gui_keyslot_remove_and_rebind_update_state() {
        let (_path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultKeyslots);
        let _ = update(&mut app, Message::OpenVaultAddDeviceSlot);
        let _ = update(
            &mut app,
            Message::VaultKeyslotLabelChanged("daily-gui".to_string()),
        );
        let _ = update(&mut app, Message::VaultEnrollDeviceSlot);

        let before_remove = app
            .vault
            .header
            .as_ref()
            .map(|header| header.keyslots.len())
            .expect("header");

        submit_vault_rebind_device_slot(&mut app).expect("rebind device slot");
        let rebound_account = selected_keyslot(&app)
            .and_then(|slot| slot.device_account.clone())
            .expect("rebound device account");
        assert!(!rebound_account.is_empty());
        assert!(app.status.contains("Rebound device-bound keyslot"));

        submit_vault_remove_keyslot(&mut app).expect("remove keyslot");
        let after_remove = app
            .vault
            .header
            .as_ref()
            .map(|header| header.keyslots.len())
            .expect("header");
        assert_eq!(after_remove + 1, before_remove);
        assert!(app.status.contains("Removed device_bound keyslot"));
    }

    #[test]
    fn gui_rebind_device_slot_preserves_active_device_unlock_options() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");
        let device_slot = {
            let mut vault =
                unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
            vault
                .add_device_keyslot(Some("daily".to_string()))
                .expect("device slot")
        };

        let (mut app, _) = boot();
        app.vault.options = VaultOpenOptions {
            path: path.clone(),
            auth: VaultAuth::PasswordEnv("PARANOID_GUI_DEVICE_REBIND".to_string()),
            mnemonic_phrase_env: None,
            mnemonic_phrase: None,
            mnemonic_slot: None,
            device_slot: Some(device_slot.id.clone()),
            use_device_auto: false,
        };
        let _ = refresh_vault_state(&mut app);
        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultKeyslots);
        let keyslot_index = app
            .vault
            .header
            .as_ref()
            .and_then(|header| {
                header
                    .keyslots
                    .iter()
                    .position(|slot| slot.id == device_slot.id)
            })
            .expect("device keyslot index");
        let _ = update(&mut app, Message::SelectVaultKeyslot(keyslot_index));

        submit_vault_rebind_device_slot(&mut app).expect("rebind device slot");

        assert_eq!(
            app.vault.options.device_slot.as_deref(),
            Some(device_slot.id.as_str())
        );
        assert!(!app.vault.options.use_device_auto);
        unlock_vault_for_options(&app.vault.options).expect("rebound device slot still unlocks");
    }

    #[test]
    fn gui_recovery_secret_rotation_updates_password_auth() {
        let (path, mut options) = with_test_vault();
        options.auth = VaultAuth::Password(SecretString::new(
            "correct horse battery staple".to_string(),
        ));

        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultKeyslots);
        let _ = update(&mut app, Message::OpenVaultRotateRecoverySecret);
        let _ = update(
            &mut app,
            Message::VaultRecoverySecretChanged("new battery horse staple".to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultRecoverySecretConfirmChanged("new battery horse staple".to_string()),
        );
        let _ = update(&mut app, Message::VaultRotateRecoverySecret);

        assert!(matches!(app.vault.screen, VaultScreen::Keyslots));
        assert!(app.status.contains("Rotated password recovery keyslot"));
        assert!(matches!(app.vault.options.auth, VaultAuth::Password(_)));
        assert!(unlock_vault(&path, "correct horse battery staple").is_err());
        unlock_vault(&path, "new battery horse staple").expect("unlock with rotated secret");
    }

    #[test]
    fn gui_export_backup_writes_portable_package() {
        let (_path, options) = with_test_vault();
        let (mut app, _) = boot();
        let backup_dir = tempdir().expect("tempdir");
        let backup = backup_dir.path().join("vault.backup.json");
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultExportBackup);
        let _ = update(
            &mut app,
            Message::VaultBackupPathChanged(backup.display().to_string()),
        );
        let _ = update(&mut app, Message::VaultExportBackup);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert!(backup.exists());
        assert!(app.status.contains("Exported encrypted vault backup"));
    }

    #[test]
    fn gui_import_backup_restores_previous_encrypted_state() {
        let (path, options) = with_test_vault();
        let (mut app, _) = boot();
        let backup_dir = tempdir().expect("tempdir");
        let backup = backup_dir.path().join("vault.backup.json");
        app.vault.options = options;
        let vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
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
        let _ = refresh_vault_state(&mut app);

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultExportBackup);
        let _ = update(
            &mut app,
            Message::VaultBackupPathChanged(backup.display().to_string()),
        );
        let _ = update(&mut app, Message::VaultExportBackup);

        let vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
        vault
            .add_secure_note(NewSecureNoteRecord {
                title: "Temporary".to_string(),
                content: "remove me".to_string(),
                folder: Some("Temp".to_string()),
                tags: vec!["temp".to_string()],
            })
            .expect("add note");
        let _ = refresh_vault_state(&mut app);
        assert_eq!(app.vault.items.len(), 2);

        let _ = update(&mut app, Message::OpenVaultImportBackup);
        let _ = update(
            &mut app,
            Message::VaultBackupPathChanged(backup.display().to_string()),
        );
        let _ = update(&mut app, Message::VaultBackupOverwriteChanged(true));
        let _ = update(&mut app, Message::VaultImportBackup);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert_eq!(app.vault.items.len(), 1);
        let VaultItemPayload::Login(login) = &app.vault.detail.expect("detail").payload else {
            panic!("expected login");
        };
        assert_eq!(login.title, "GitHub");
        assert!(app.status.contains("Imported encrypted vault backup"));
    }

    #[test]
    fn gui_invalid_backup_import_fails_closed_and_preserves_current_items() {
        let (path, options) = with_test_vault();
        let backup_dir = tempdir().expect("backup dir");
        let invalid_backup = backup_dir.path().join("invalid.backup.json");
        fs::write(&invalid_backup, b"{\"broken\":true").expect("write invalid backup");
        let vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
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

        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);
        let original_id = app.vault.detail.as_ref().expect("detail").id.clone();
        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultImportBackup);
        let _ = update(
            &mut app,
            Message::VaultBackupPathChanged(invalid_backup.display().to_string()),
        );
        let _ = update(&mut app, Message::VaultBackupOverwriteChanged(true));
        let _ = update(&mut app, Message::VaultImportBackup);

        assert!(matches!(app.vault.screen, VaultScreen::ImportBackup));
        assert_eq!(app.vault.items.len(), 1);
        assert_eq!(app.vault.detail.as_ref().expect("detail").id, original_id);
        assert!(app.status.contains("Backup import failed"));
    }

    #[test]
    fn gui_export_transfer_writes_filtered_package_and_import_restores_selection() {
        let (source_path, source_options) = with_test_vault();
        let transfer_dir = tempdir().expect("transfer dir");
        let transfer_path = transfer_dir
            .path()
            .join("selected-items.transfer.ppvt.json");
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

        let (mut source_app, _) = boot();
        source_app.vault.options = source_options;
        let _ = refresh_vault_state(&mut source_app);
        let _ = update(&mut source_app, Message::SwitchSurface(Surface::Vault));
        let _ = update(
            &mut source_app,
            Message::VaultFilterKindChanged("login".to_string()),
        );
        assert_eq!(source_app.vault.items.len(), 1);

        let _ = update(&mut source_app, Message::OpenVaultExportTransfer);
        let _ = update(
            &mut source_app,
            Message::VaultTransferPathChanged(transfer_path.display().to_string()),
        );
        let _ = update(
            &mut source_app,
            Message::VaultTransferPasswordChanged("transfer secret".to_string()),
        );
        let _ = update(&mut source_app, Message::VaultExportTransfer);

        assert!(matches!(source_app.vault.screen, VaultScreen::List));
        assert!(transfer_path.exists());
        assert!(
            source_app
                .status
                .contains("Exported encrypted transfer package")
        );

        let (_dest_path, dest_options) = with_test_vault();
        let (mut dest_app, _) = boot();
        dest_app.vault.options = dest_options;
        let _ = refresh_vault_state(&mut dest_app);
        let _ = update(&mut dest_app, Message::SwitchSurface(Surface::Vault));

        let _ = update(&mut dest_app, Message::OpenVaultImportTransfer);
        let _ = update(
            &mut dest_app,
            Message::VaultTransferPathChanged(transfer_path.display().to_string()),
        );
        let _ = update(
            &mut dest_app,
            Message::VaultTransferPasswordChanged("transfer secret".to_string()),
        );
        let _ = update(&mut dest_app, Message::VaultImportTransfer);

        assert!(matches!(dest_app.vault.screen, VaultScreen::List));
        assert_eq!(dest_app.vault.items.len(), 1);
        assert_eq!(dest_app.vault.items[0].kind, VaultItemKind::Login);
        let VaultItemPayload::Login(login) = &dest_app.vault.detail.expect("detail").payload else {
            panic!("expected imported login");
        };
        assert_eq!(login.title, "GitHub");
        assert!(dest_app.status.contains("Imported transfer package"));
    }

    #[test]
    fn gui_export_transfer_with_certificate_imports_via_certificate_keypair() {
        let (source_path, source_options) = with_test_vault();
        let transfer_dir = tempdir().expect("transfer dir");
        let transfer_path = transfer_dir
            .path()
            .join("selected-items-cert.transfer.ppvt.json");
        let (cert_path, key_path) = write_test_certificate_pair(transfer_dir.path(), "transfer");
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

        let (mut source_app, _) = boot();
        source_app.vault.options = source_options;
        let _ = refresh_vault_state(&mut source_app);
        let _ = update(&mut source_app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut source_app, Message::OpenVaultExportTransfer);
        let _ = update(
            &mut source_app,
            Message::VaultTransferPathChanged(transfer_path.display().to_string()),
        );
        let _ = update(
            &mut source_app,
            Message::VaultTransferCertPathChanged(cert_path.display().to_string()),
        );
        let _ = update(&mut source_app, Message::VaultExportTransfer);

        assert!(matches!(source_app.vault.screen, VaultScreen::List));
        assert!(transfer_path.exists());
        assert!(
            source_app
                .status
                .contains("Exported encrypted transfer package")
        );

        let (_dest_path, dest_options) = with_test_vault();
        let (mut dest_app, _) = boot();
        dest_app.vault.options = dest_options;
        let _ = refresh_vault_state(&mut dest_app);
        let _ = update(&mut dest_app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut dest_app, Message::OpenVaultImportTransfer);
        let _ = update(
            &mut dest_app,
            Message::VaultTransferPathChanged(transfer_path.display().to_string()),
        );
        let _ = update(
            &mut dest_app,
            Message::VaultTransferCertPathChanged(cert_path.display().to_string()),
        );
        let _ = update(
            &mut dest_app,
            Message::VaultTransferKeyPathChanged(key_path.display().to_string()),
        );
        let _ = update(&mut dest_app, Message::VaultImportTransfer);

        assert!(matches!(dest_app.vault.screen, VaultScreen::List));
        assert_eq!(dest_app.vault.items.len(), 1);
        assert_eq!(dest_app.vault.items[0].kind, VaultItemKind::Login);
        let VaultItemPayload::Login(login) = &dest_app.vault.detail.expect("detail").payload else {
            panic!("expected imported login");
        };
        assert_eq!(login.title, "GitHub");
        assert!(dest_app.status.contains("Imported transfer package"));
    }

    #[test]
    fn gui_invalid_transfer_import_fails_closed_and_preserves_current_items() {
        let (path, options) = with_test_vault();
        let transfer_dir = tempdir().expect("transfer dir");
        let invalid_transfer = transfer_dir.path().join("invalid.transfer.ppvt.json");
        fs::write(&invalid_transfer, b"{\"broken\":true").expect("write invalid transfer");
        let vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
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

        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);
        let original_id = app.vault.detail.as_ref().expect("detail").id.clone();
        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(&mut app, Message::OpenVaultImportTransfer);
        let _ = update(
            &mut app,
            Message::VaultTransferPathChanged(invalid_transfer.display().to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultTransferPasswordChanged("transfer secret".to_string()),
        );
        let _ = update(&mut app, Message::VaultImportTransfer);

        assert!(matches!(app.vault.screen, VaultScreen::ImportTransfer));
        assert_eq!(app.vault.items.len(), 1);
        assert_eq!(app.vault.detail.as_ref().expect("detail").id, original_id);
        assert!(app.status.contains("Transfer import failed"));
    }

    #[test]
    fn gui_native_password_unlock_form_reaches_vault() {
        let (_path, options) = with_password_only_vault();
        let (mut app, _) = boot();
        app.vault.options = options;

        assert!(refresh_vault_state(&mut app).is_err());
        assert!(matches!(app.vault.screen, VaultScreen::UnlockBlocked));

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(
            &mut app,
            Message::VaultUnlockPasswordChanged("correct horse battery staple".to_string()),
        );
        let _ = update(&mut app, Message::VaultAttemptNativeUnlock);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert!(app.status.contains("Vault unlocked"));
    }

    #[test]
    fn gui_native_mnemonic_unlock_form_reaches_vault() {
        let (path, mut options) = with_password_only_vault();
        let mut vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
        let enrollment = vault
            .add_mnemonic_keyslot(Some("paper".to_string()))
            .expect("mnemonic slot");
        options.auth = VaultAuth::PasswordEnv("PARANOID_GUI_MISSING_PASSWORD".to_string());

        let (mut app, _) = boot();
        app.vault.options = options;

        assert!(refresh_vault_state(&mut app).is_err());
        assert!(matches!(app.vault.screen, VaultScreen::UnlockBlocked));

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(
            &mut app,
            Message::SelectVaultUnlockMode(VaultUnlockMode::Mnemonic),
        );
        let _ = update(
            &mut app,
            Message::VaultUnlockMnemonicChanged(enrollment.mnemonic),
        );
        let _ = update(
            &mut app,
            Message::VaultUnlockMnemonicSlotChanged(enrollment.keyslot.id),
        );
        let _ = update(&mut app, Message::VaultAttemptNativeUnlock);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert!(app.status.contains("Vault unlocked"));
    }

    #[test]
    fn gui_native_device_unlock_form_reaches_vault() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");
        let mut vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
        vault
            .add_device_keyslot(Some("daily".to_string()))
            .expect("first device slot");
        let second = vault
            .add_device_keyslot(Some("laptop".to_string()))
            .expect("second device slot");

        let (mut app, _) = boot();
        app.vault.options = VaultOpenOptions {
            path: path.clone(),
            auth: VaultAuth::PasswordEnv("PARANOID_GUI_MISSING_PASSWORD".to_string()),
            mnemonic_phrase_env: None,
            mnemonic_phrase: None,
            mnemonic_slot: None,
            device_slot: None,
            use_device_auto: false,
        };

        assert!(refresh_vault_state(&mut app).is_err());
        assert!(matches!(app.vault.screen, VaultScreen::UnlockBlocked));

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(
            &mut app,
            Message::SelectVaultUnlockMode(VaultUnlockMode::Device),
        );
        let _ = update(&mut app, Message::VaultUnlockDeviceSlotChanged(second.id));
        let _ = update(&mut app, Message::VaultAttemptNativeUnlock);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert!(app.status.contains("Vault unlocked"));
    }

    #[test]
    fn gui_native_certificate_unlock_form_reaches_vault() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");
        let (cert_path, key_path) = write_test_certificate_pair(tempdir.path(), "unlock");
        let mut vault =
            unlock_vault(&path, "correct horse battery staple").expect("unlock with password");
        vault
            .add_certificate_keyslot(
                fs::read(&cert_path).expect("cert").as_slice(),
                Some("ops".to_string()),
            )
            .expect("certificate slot");

        let (mut app, _) = boot();
        app.vault.options = VaultOpenOptions {
            path: path.clone(),
            auth: VaultAuth::PasswordEnv("PARANOID_GUI_MISSING_PASSWORD".to_string()),
            mnemonic_phrase_env: None,
            mnemonic_phrase: None,
            mnemonic_slot: None,
            device_slot: None,
            use_device_auto: false,
        };

        assert!(refresh_vault_state(&mut app).is_err());
        assert!(matches!(app.vault.screen, VaultScreen::UnlockBlocked));

        let _ = update(&mut app, Message::SwitchSurface(Surface::Vault));
        let _ = update(
            &mut app,
            Message::SelectVaultUnlockMode(VaultUnlockMode::Certificate),
        );
        let _ = update(
            &mut app,
            Message::VaultUnlockCertPathChanged(cert_path.display().to_string()),
        );
        let _ = update(
            &mut app,
            Message::VaultUnlockKeyPathChanged(key_path.display().to_string()),
        );
        let _ = update(&mut app, Message::VaultAttemptNativeUnlock);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert!(app.status.contains("Vault unlocked"));
    }

    #[test]
    fn gui_session_tick_auto_locks_unattended_vault() {
        let (_path, options) = with_test_vault();
        let (mut app, _) = boot();
        app.vault.options = options;
        let _ = refresh_vault_state(&mut app);

        assert!(matches!(app.vault.screen, VaultScreen::List));
        assert!(app.vault.header.is_some());

        app.session = NativeSessionHardening::with_timeouts(
            Duration::from_millis(10),
            Duration::from_millis(10),
        );
        thread::sleep(Duration::from_millis(15));
        let _ = update(&mut app, Message::SessionTick);

        assert!(matches!(app.vault.screen, VaultScreen::UnlockBlocked));
        assert!(app.vault.header.is_none());
        assert!(app.vault.items.is_empty());
        assert!(app.vault.detail.is_none());
        assert!(app.status.contains("auto-locked"));
    }

    #[test]
    fn gui_launch_action_supports_version_and_help_shortcuts() {
        assert_eq!(
            resolve_launch_action([std::ffi::OsString::from("--version")]).expect("version"),
            LaunchAction::PrintVersion
        );
        assert_eq!(
            resolve_launch_action([std::ffi::OsString::from("--help")]).expect("help"),
            LaunchAction::PrintHelp
        );
        assert_eq!(
            resolve_launch_action(std::iter::empty::<std::ffi::OsString>()).expect("default"),
            LaunchAction::RunGui
        );
    }

    #[test]
    fn gui_launch_action_rejects_unknown_arguments() {
        let error =
            resolve_launch_action([std::ffi::OsString::from("--bogus")]).expect_err("unknown arg");
        assert!(error.contains("--bogus"));
    }
}
