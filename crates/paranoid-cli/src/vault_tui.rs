use anyhow::Context;

use arboard::Clipboard;

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};

use paranoid_core::{FrameworkId, ParanoidRequest};

use paranoid_ops::VaultOperationAccess;

use paranoid_vault::{
    GenerateStoreLoginRecord, SecretString, UpdateCardRecord, UpdateIdentityRecord,
    UpdateSecureNoteRecord, VaultAuth, VaultItemPayload, inspect_certificate_pem,
    inspect_vault_backup, inspect_vault_transfer, restore_vault_backup,
};

#[cfg(test)]
use ratatui::backend::TestBackend;

use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

use std::{fs, io};

mod mutation_handlers;
mod panel_rendering;
mod screen_state;

pub(crate) use panel_rendering::*;
pub use screen_state::VaultTuiConfig;
pub(crate) use screen_state::*;

const BG: Color = Color::Rgb(8, 12, 20);

const PANEL: Color = Color::Rgb(13, 17, 25);

const TEXT: Color = Color::Rgb(228, 231, 242);

const GREEN: Color = Color::Rgb(52, 211, 153);

const BLUE: Color = Color::Rgb(96, 165, 250);

const AMBER: Color = Color::Rgb(251, 191, 36);

const RED: Color = Color::Rgb(248, 113, 113);

trait EditableText {
    fn edit_pop(&mut self);
    fn edit_clear(&mut self);
    fn edit_push(&mut self, ch: char);
}

impl EditableText for String {
    fn edit_pop(&mut self) {
        self.pop();
    }

    fn edit_clear(&mut self) {
        self.clear();
    }

    fn edit_push(&mut self, ch: char) {
        self.push(ch);
    }
}

impl EditableText for SecretString {
    fn edit_pop(&mut self) {
        self.pop();
    }

    fn edit_clear(&mut self) {
        self.clear();
    }

    fn edit_push(&mut self, ch: char) {
        self.push(ch);
    }
}

fn edit_form_value<T: EditableText>(buffer: Option<&mut T>, key: KeyEvent) {
    let Some(buffer) = buffer else {
        return;
    };
    match key.code {
        KeyCode::Backspace => {
            buffer.edit_pop();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            buffer.edit_clear();
        }
        KeyCode::Char(ch) if (32..=126).contains(&(ch as u32)) => buffer.edit_push(ch),
        _ => {}
    }
}

pub fn run(config: VaultTuiConfig) -> anyhow::Result<()> {
    if let Some(mut prepared) = crate::scripted::prepare_scripted_terminal(
        crate::scripted::DEFAULT_COLS,
        crate::scripted::DEFAULT_ROWS,
    )? {
        let final_frame =
            run_scripted(&mut prepared.terminal, config, &prepared.tokens).map_err(|error| {
                anyhow::anyhow!(
                    "scripted run of {} failed: {error}",
                    prepared.path.display()
                )
            })?;
        println!("{final_frame}");
        return Ok(());
    }

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to initialize terminal")?;
    terminal.clear().ok();
    let result = run_app(&mut terminal, App::with_config(config));
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    result
}

/// Drives the vault manager `App` through a pre-parsed key script against an
/// in-memory `TestBackend`, returning the final rendered frame as text.
///
/// The vault TUI has no background worker thread (all vault operations are
/// synchronous), so `<wait-idle>` is a no-op single poll here; it is
/// supported for script portability with the generator wizard's scripts.
pub fn run_scripted(
    terminal: &mut Terminal<ratatui::backend::TestBackend>,
    config: VaultTuiConfig,
    tokens: &[crate::scripted::ScriptToken],
) -> anyhow::Result<String> {
    let mut app = App::with_config(config);
    crate::scripted::drive(terminal, tokens, |terminal, key| {
        let quit = match key {
            Some(key) => app.handle_key(key),
            None => false,
        };
        app.poll_hardening();
        terminal
            .draw(|frame| render(frame, &app))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok(crate::scripted::StepOutcome { idle: true, quit })
    })?;
    Ok(crate::scripted::dump_buffer(terminal))
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> anyhow::Result<()> {
    loop {
        app.poll_hardening();
        terminal
            .draw(|frame| render(frame, &app))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if event::poll(std::time::Duration::from_millis(80))?
            && let Event::Key(key) = event::read()?
        {
            app.session.note_activity();
            if app.handle_key(key) {
                break;
            }
        }
    }
    Ok(())
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

fn normalize_optional_secret(value: &SecretString) -> Option<SecretString> {
    let trimmed = value.as_str().trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(SecretString::new(trimmed.to_string()))
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
    use paranoid_audit::AuditSinkHealth;
    use paranoid_ops::OpsProfile;
    use paranoid_vault::{
        NativeSessionHardening, NewCardRecord, NewLoginRecord, NewSecureNoteRecord, SecretString,
        VaultAuth, VaultItemKind, VaultOpenOptions, init_vault, read_vault_header, unlock_vault,
        unlock_vault_for_options, unlock_vault_with_mnemonic,
    };
    use std::{
        collections::HashMap,
        fs,
        path::Path,
        path::PathBuf,
        sync::{Mutex, Once, OnceLock},
        thread,
        time::Duration,
    };
    use tempfile::tempdir;

    static MOCK_KEYRING: Once = Once::new();

    fn use_mock_keyring() {
        MOCK_KEYRING.call_once(|| {
            keyring::set_default_credential_builder(Box::new(PersistentTestCredentialBuilder));
        });
    }

    #[derive(Debug)]
    struct PersistentTestCredential {
        key: String,
    }

    struct PersistentTestCredentialBuilder;

    impl keyring::credential::CredentialBuilderApi for PersistentTestCredentialBuilder {
        fn build(
            &self,
            target: Option<&str>,
            service: &str,
            user: &str,
        ) -> keyring::Result<Box<keyring::Credential>> {
            Ok(Box::new(PersistentTestCredential {
                key: format!("{}\u{0}{service}\u{0}{user}", target.unwrap_or_default()),
            }))
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn persistence(&self) -> keyring::credential::CredentialPersistence {
            keyring::credential::CredentialPersistence::ProcessOnly
        }
    }

    impl keyring::credential::CredentialApi for PersistentTestCredential {
        fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
            test_keyring_store()
                .lock()
                .expect("test keyring lock")
                .insert(self.key.clone(), secret.to_vec());
            Ok(())
        }

        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            test_keyring_store()
                .lock()
                .expect("test keyring lock")
                .get(&self.key)
                .cloned()
                .ok_or(keyring::Error::NoEntry)
        }

        fn delete_credential(&self) -> keyring::Result<()> {
            test_keyring_store()
                .lock()
                .expect("test keyring lock")
                .remove(&self.key)
                .map(|_| ())
                .ok_or(keyring::Error::NoEntry)
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn test_keyring_store() -> &'static Mutex<HashMap<String, Vec<u8>>> {
        static STORE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
        STORE.get_or_init(|| Mutex::new(HashMap::new()))
    }

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

    fn press_key(app: &mut App, code: KeyCode) {
        let should_quit = app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
        assert!(!should_quit, "unexpected quit for key {code:?}");
    }

    fn type_text(app: &mut App, value: &str) {
        for ch in value.chars() {
            press_key(app, KeyCode::Char(ch));
        }
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
        use_mock_keyring();
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
                password: "hunter2".to_string().into(),
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
            profile: OpsProfile::Default,
            audit_jsonl: None,
            require_audit_sink: false,
            audit_sink_health: AuditSinkHealth::not_configured_jsonl(),
            ops_audit_events: Vec::new(),
            screen: Screen::Vault,
            status: "test render".to_string(),
            header: Some(header),
            items,
            selected_index: 0,
            selected_keyslot_index: 0,
            detail: Some(item),
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
    fn tui_vault_operation_policy_records_non_secret_audit_metadata() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        let initial_event_count = app.ops_audit_events.len();
        app.open_add_login();
        app.add_login_form.title = "GitHub".to_string();
        app.add_login_form.username = "octocat".to_string();
        app.add_login_form.password = "hunter2".to_string();
        app.submit_login_form();

        assert!(app.ops_audit_events.len() >= initial_event_count + 4);
        assert!(app.ops_audit_events.iter().all(|event| {
            event
                .attributes
                .get("session_surface")
                .is_some_and(|surface| surface == "tui")
        }));
        assert!(
            app.ops_audit_events
                .iter()
                .any(|event| event.attributes.get("vault_access") == Some(&"mutate".to_string()))
        );
        let serialized = serde_json::to_string(&app.ops_audit_events).expect("serialize events");
        assert!(!serialized.contains("hunter2"));
    }

    #[test]
    fn tui_vault_operation_policy_persists_jsonl_when_configured() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        let audit_path = tempdir.path().join("tui-audit.jsonl");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::with_config(VaultTuiConfig {
            open_options: options,
            profile: OpsProfile::Default,
            audit_jsonl: Some(audit_path.clone()),
            require_audit_sink: false,
        });
        app.open_add_login();
        app.add_login_form.title = "GitHub".to_string();
        app.add_login_form.username = "octocat".to_string();
        app.add_login_form.password = "hunter2".to_string();
        app.submit_login_form();

        let audit_jsonl = fs::read_to_string(&audit_path).expect("audit jsonl");
        let events = audit_jsonl
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("audit event"))
            .collect::<Vec<_>>();
        assert!(events.len() >= 6);
        assert!(events.iter().all(|event| event["surface"] == "ops"));
        assert!(
            events
                .iter()
                .all(|event| event["attributes"]["session_surface"] == "tui")
        );
        assert!(
            events
                .iter()
                .any(|event| event["action"] == "vault_operation.request")
        );
        assert!(!audit_jsonl.contains("hunter2"));
    }

    #[test]
    fn tui_vault_operation_policy_keeps_memory_events_when_jsonl_write_fails() {
        let vault_tempdir = tempdir().expect("vault tempdir");
        let audit_tempdir = tempdir().expect("audit tempdir");
        let path = vault_tempdir.path().join("vault.sqlite");
        let audit_path = audit_tempdir.path().join("tui-audit.jsonl");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::with_config(VaultTuiConfig {
            open_options: options,
            profile: OpsProfile::Default,
            audit_jsonl: Some(audit_path),
            require_audit_sink: false,
        });
        let initial_event_count = app.ops_audit_events.len();
        drop(audit_tempdir);

        let result = app.record_vault_operation_policy("export", VaultOperationAccess::Export);

        assert!(result.is_err());
        assert_eq!(app.ops_audit_events.len(), initial_event_count + 2);
        assert!(
            app.ops_audit_events[initial_event_count..]
                .iter()
                .all(|event| {
                    event
                        .attributes
                        .get("session_surface")
                        .is_some_and(|surface| surface == "tui")
                })
        );
    }

    #[test]
    fn end_to_end_key_workflow_exercises_primary_vault_actions() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        let backup = path.with_extension("backup.json");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        assert!(matches!(app.screen, Screen::Vault));

        press_key(&mut app, KeyCode::Char('a'));
        assert!(matches!(app.screen, Screen::AddLogin));
        type_text(&mut app, "GitHub");
        press_key(&mut app, KeyCode::Tab);
        type_text(&mut app, "octocat");
        press_key(&mut app, KeyCode::Tab);
        type_text(&mut app, "hunter2");
        press_key(&mut app, KeyCode::Tab);
        press_key(&mut app, KeyCode::Tab);
        press_key(&mut app, KeyCode::Tab);
        type_text(&mut app, "Work");
        press_key(&mut app, KeyCode::Tab);
        type_text(&mut app, "work,code");
        press_key(&mut app, KeyCode::Tab);
        press_key(&mut app, KeyCode::Enter);

        assert!(matches!(app.screen, Screen::Vault));
        assert_eq!(app.items.len(), 1);
        assert!(app.status.contains("Stored login item"));

        press_key(&mut app, KeyCode::Char('/'));
        assert!(app.search_mode);
        type_text(&mut app, "GitHub");
        press_key(&mut app, KeyCode::Enter);
        assert!(!app.search_mode);
        assert_eq!(app.items.len(), 1);
        assert_eq!(app.items[0].title, "GitHub");
        assert!(app.status.contains("Vault filters locked"));

        press_key(&mut app, KeyCode::Char('k'));
        assert!(matches!(app.screen, Screen::Keyslots));
        press_key(&mut app, KeyCode::Char('m'));
        assert!(matches!(app.screen, Screen::AddMnemonicSlot));
        type_text(&mut app, "paper-backup");
        press_key(&mut app, KeyCode::Tab);
        press_key(&mut app, KeyCode::Enter);

        assert!(matches!(app.screen, Screen::MnemonicReveal));
        assert!(app.latest_mnemonic_enrollment.is_some());
        assert!(app.status.contains("Mnemonic recovery slot enrolled"));

        press_key(&mut app, KeyCode::Enter);
        assert!(matches!(app.screen, Screen::Keyslots));
        press_key(&mut app, KeyCode::Esc);
        assert!(matches!(app.screen, Screen::Vault));

        press_key(&mut app, KeyCode::Char('x'));
        assert!(matches!(app.screen, Screen::ExportBackup));
        press_key(&mut app, KeyCode::Tab);
        press_key(&mut app, KeyCode::Enter);

        assert!(matches!(app.screen, Screen::Vault));
        assert!(backup.exists());
        assert!(app.status.contains("Exported encrypted vault backup"));
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
        assert_eq!(login.password.as_str().len(), 20);
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
                password: "hunter2".to_string().into(),
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
        assert_eq!(login.password.as_str().len(), 20);
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
                password: "hunter2".to_string().into(),
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
                password: "hunter3".to_string().into(),
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
                password: "hunter2".to_string().into(),
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
                number: "5555444433331111".to_string().into(),
                expiry_month: "11".to_string(),
                expiry_year: "2030".to_string(),
                security_code: "999".to_string().into(),
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
                password: "hunter2".to_string().into(),
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
                password: "hunter2".to_string().into(),
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
                password: "hunter2".to_string().into(),
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
                password: "hunter2".to_string().into(),
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
        assert_eq!(enrollment.mnemonic.as_str().split_whitespace().count(), 24);
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
            mnemonic_phrase: Some(enrollment.mnemonic.clone()),
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
        use_mock_keyring();
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
        app.recovery_secret_form.new_secret =
            SecretString::new("new battery horse staple".to_string());
        app.recovery_secret_form.confirm_secret =
            SecretString::new("new battery horse staple".to_string());
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
                password: "hunter2".to_string().into(),
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
    fn open_import_backup_defaults_to_no_overwrite_when_target_exists() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        assert!(path.exists());
        app.open_import_backup();

        assert!(
            !app.import_backup_form.overwrite,
            "import backup must not preselect overwrite even when the target vault exists"
        );
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
                password: "hunter2".to_string().into(),
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
                content: "remove me".to_string().into(),
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
                password: "hunter2".to_string().into(),
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
                password: "hunter2".to_string().into(),
                url: None,
                notes: None,
                folder: Some("Work".to_string()),
                tags: vec!["work".to_string()],
            })
            .expect("add login");
        source_vault
            .add_secure_note(NewSecureNoteRecord {
                title: "Recovery".to_string(),
                content: "paper copy in safe".to_string().into(),
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
        source_app.export_transfer_form.package_password =
            SecretString::new("transfer secret".to_string());
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
        dest_app.import_transfer_form.package_password =
            SecretString::new("transfer secret".to_string());
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
                password: "hunter2".to_string().into(),
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
                password: "hunter2".to_string().into(),
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
        app.import_transfer_form.package_password =
            SecretString::new("transfer secret".to_string());
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
            profile: OpsProfile::Default,
            audit_jsonl: None,
            require_audit_sink: false,
            audit_sink_health: AuditSinkHealth::not_configured_jsonl(),
            ops_audit_events: Vec::new(),
            screen: Screen::UnlockBlocked,
            status: "Unlock blocked: no secret".to_string(),
            header: None,
            items: Vec::new(),
            selected_index: 0,
            selected_keyslot_index: 0,
            detail: None,
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

        app.unlock_form.password = SecretString::new("correct horse battery staple".to_string());
        app.submit_native_unlock();

        assert!(matches!(app.screen, Screen::Vault));
        assert!(app.status.contains("Vault unlocked"));
    }

    #[test]
    fn missing_vault_opens_environment_approval_first() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");

        let app = App::new(password_only_options(&path));

        assert!(matches!(app.screen, Screen::EnvironmentApproval));
        assert!(app.capability_report.is_some());
        assert!(!app.environment_approval.resolved);
        let rendered = render_to_string(&app);
        assert!(rendered.contains("Environment Approval"));
        assert!(rendered.contains("OS keychain"));
        assert!(rendered.contains("Clipboard"));
        assert!(rendered.contains("Display server"));
        assert!(rendered.contains("Suggested initial configuration"));
        assert!(rendered.contains("Accept suggested configuration"));
        assert!(rendered.contains("Adjust manually"));
    }

    #[test]
    fn environment_approval_focus_cycles_between_accept_and_adjust() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        let mut app = App::new(password_only_options(&path));
        assert_eq!(
            app.environment_approval.choice,
            EnvironmentApprovalChoice::Accept
        );

        press_key(&mut app, KeyCode::Down);
        assert_eq!(
            app.environment_approval.choice,
            EnvironmentApprovalChoice::Adjust
        );

        press_key(&mut app, KeyCode::Down);
        assert_eq!(
            app.environment_approval.choice,
            EnvironmentApprovalChoice::Accept
        );

        press_key(&mut app, KeyCode::Up);
        assert_eq!(
            app.environment_approval.choice,
            EnvironmentApprovalChoice::Adjust
        );
    }

    #[test]
    fn accepting_environment_approval_leads_to_init_form_prefilled_with_password_mode() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        let mut app = App::new(password_only_options(&path));

        press_key(&mut app, KeyCode::Enter);

        assert!(matches!(app.screen, Screen::UnlockBlocked));
        assert_eq!(app.unlock_form.mode, UnlockMode::Password);
        assert!(app.environment_approval.resolved);
        assert!(app.status.contains("Suggested configuration accepted"));
    }

    #[test]
    fn accepting_environment_approval_initializes_vault_and_does_not_reshow_approval() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        let mut app = App::new(password_only_options(&path));

        press_key(&mut app, KeyCode::Enter); // accept -> UnlockBlocked init form
        app.unlock_form.password = SecretString::new("correct horse battery staple".to_string());
        app.submit_native_unlock();

        assert!(matches!(app.screen, Screen::Vault));
        assert!(path.exists());
        assert!(app.status.contains("Vault initialized"));

        // A subsequent refresh (e.g. pressing `r`) must not bounce back to
        // the approval screen now that a vault exists at this path.
        app.refresh();
        assert!(matches!(app.screen, Screen::Vault));
    }

    #[test]
    fn adjusting_environment_approval_skips_device_keyslot_auto_enrollment() {
        use_mock_keyring();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        let mut app = App::new(password_only_options(&path));

        press_key(&mut app, KeyCode::Down); // focus Adjust
        press_key(&mut app, KeyCode::Enter); // select Adjust -> UnlockBlocked init form
        assert!(app.status.contains("Manual setup"));

        app.unlock_form.password = SecretString::new("correct horse battery staple".to_string());
        app.submit_native_unlock();

        assert!(matches!(app.screen, Screen::Vault));
        let header = app.header.as_ref().expect("header");
        assert!(
            header
                .keyslots
                .iter()
                .all(|slot| slot.kind != paranoid_vault::VaultKeyslotKind::DeviceBound)
        );
    }

    #[test]
    fn accepting_environment_approval_auto_enrolls_device_keyslot_when_keychain_available() {
        use_mock_keyring();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        let mut app = App::new(password_only_options(&path));
        assert!(
            app.capability_report
                .as_ref()
                .expect("report")
                .os_keychain
                .status
                .is_available(),
            "mock keyring must report the OS keychain as available for this scenario"
        );

        press_key(&mut app, KeyCode::Enter); // accept -> UnlockBlocked init form
        app.unlock_form.password = SecretString::new("correct horse battery staple".to_string());
        app.submit_native_unlock();

        assert!(matches!(app.screen, Screen::Vault));
        assert!(app.status.contains("device-bound keyslot"));
        let header = app.header.as_ref().expect("header");
        assert!(
            header
                .keyslots
                .iter()
                .any(|slot| slot.kind == paranoid_vault::VaultKeyslotKind::DeviceBound)
        );
    }

    #[test]
    fn environment_approval_reachable_from_vault_hotkey_and_esc_returns() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");

        let mut app = App::new(password_only_options(&path));
        assert!(matches!(app.screen, Screen::UnlockBlocked));
        app.unlock_form.password = SecretString::new("correct horse battery staple".to_string());
        app.submit_native_unlock();
        assert!(matches!(app.screen, Screen::Vault));

        press_key(&mut app, KeyCode::Char('E'));
        assert!(matches!(app.screen, Screen::EnvironmentApproval));
        assert!(app.capability_report.is_some());

        press_key(&mut app, KeyCode::Esc);
        assert!(matches!(app.screen, Screen::Vault));
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
    fn form_debug_output_never_leaks_secret_text() {
        let unlock_form = UnlockForm {
            password: SecretString::new("correct horse battery staple".to_string()),
            mnemonic_phrase: SecretString::new(
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong".to_string(),
            ),
            key_passphrase: SecretString::new("pkcs8-passphrase".to_string()),
            ..UnlockForm::default()
        };
        let unlock_debug = format!("{unlock_form:?}");
        assert!(unlock_debug.contains("<redacted>"));
        assert!(!unlock_debug.contains("correct horse battery staple"));
        assert!(!unlock_debug.contains("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"));
        assert!(!unlock_debug.contains("pkcs8-passphrase"));

        let certificate_rewrap_form = CertificateRewrapForm {
            key_passphrase: SecretString::new("cert-rewrap-passphrase".to_string()),
            ..CertificateRewrapForm::default()
        };
        let certificate_rewrap_debug = format!("{certificate_rewrap_form:?}");
        assert!(certificate_rewrap_debug.contains("<redacted>"));
        assert!(!certificate_rewrap_debug.contains("cert-rewrap-passphrase"));

        let recovery_secret_form = RecoverySecretForm {
            new_secret: SecretString::new("new battery horse staple".to_string()),
            confirm_secret: SecretString::new("new battery horse staple".to_string()),
            ..RecoverySecretForm::default()
        };
        let recovery_secret_debug = format!("{recovery_secret_form:?}");
        assert!(recovery_secret_debug.contains("<redacted>"));
        assert!(!recovery_secret_debug.contains("new battery horse staple"));

        let export_transfer_form = ExportTransferForm {
            package_password: SecretString::new("transfer package secret".to_string()),
            ..ExportTransferForm::default()
        };
        let export_transfer_debug = format!("{export_transfer_form:?}");
        assert!(export_transfer_debug.contains("<redacted>"));
        assert!(!export_transfer_debug.contains("transfer package secret"));

        let import_transfer_form = ImportTransferForm {
            package_password: SecretString::new("import package secret".to_string()),
            key_passphrase: SecretString::new("import key passphrase".to_string()),
            ..ImportTransferForm::default()
        };
        let import_transfer_debug = format!("{import_transfer_form:?}");
        assert!(import_transfer_debug.contains("<redacted>"));
        assert!(!import_transfer_debug.contains("import package secret"));
        assert!(!import_transfer_debug.contains("import key passphrase"));
    }

    #[test]
    fn normalize_optional_secret_trims_surrounding_whitespace() {
        let padded = SecretString::new("  hunter2  \t".to_string());
        let normalized = normalize_optional_secret(&padded).expect("non-empty secret");
        assert_eq!(normalized.as_str(), "hunter2");

        let blank = SecretString::new("   ".to_string());
        assert!(normalize_optional_secret(&blank).is_none());
    }

    #[test]
    fn native_device_unlock_updates_state() {
        use_mock_keyring();
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
                password: "hunter2".to_string().into(),
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
    fn idle_timeout_does_not_fire_on_environment_approval() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");

        let mut app = App::new(password_only_options(&path));
        assert!(matches!(app.screen, Screen::EnvironmentApproval));
        assert!(!app.environment_approval.resolved);

        app.session = NativeSessionHardening::with_timeouts(
            Duration::from_millis(10),
            Duration::from_millis(10),
        );
        thread::sleep(Duration::from_millis(15));
        app.poll_hardening();

        assert!(matches!(app.screen, Screen::EnvironmentApproval));
        assert!(!app.environment_approval.resolved);
        assert!(!app.status.contains("auto-locked"));
    }

    #[test]
    fn idle_timeout_purges_auth_and_secret_bearing_forms() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        let mut app = App::new(options);
        assert!(matches!(app.screen, Screen::Vault));

        app.options.auth = VaultAuth::Password(SecretString::new(
            "correct horse battery staple".to_string(),
        ));
        app.unlock_form.password = SecretString::new("unlock-secret".to_string());
        app.unlock_form.mnemonic_phrase = SecretString::new("mnemonic-secret".to_string());
        app.unlock_form.key_passphrase = SecretString::new("unlock-key-pass".to_string());
        app.recovery_secret_form.new_secret = SecretString::new("recovery-new".to_string());
        app.recovery_secret_form.confirm_secret = SecretString::new("recovery-confirm".to_string());
        app.certificate_rewrap_form.key_passphrase = SecretString::new("rewrap-pass".to_string());
        app.export_transfer_form.package_password =
            SecretString::new("export-package-pass".to_string());
        app.import_transfer_form.package_password =
            SecretString::new("import-package-pass".to_string());
        app.import_transfer_form.key_passphrase = SecretString::new("import-key-pass".to_string());

        app.session = NativeSessionHardening::with_timeouts(
            Duration::from_millis(10),
            Duration::from_millis(10),
        );
        thread::sleep(Duration::from_millis(15));
        app.poll_hardening();

        assert!(matches!(app.screen, Screen::UnlockBlocked));
        assert!(matches!(app.options.auth, VaultAuth::PasswordEnv(_)));
        assert!(app.unlock_form.password.is_empty());
        assert!(app.unlock_form.mnemonic_phrase.is_empty());
        assert!(app.unlock_form.key_passphrase.is_empty());
        assert!(app.recovery_secret_form.new_secret.is_empty());
        assert!(app.recovery_secret_form.confirm_secret.is_empty());
        assert!(app.certificate_rewrap_form.key_passphrase.is_empty());
        assert!(app.export_transfer_form.package_password.is_empty());
        assert!(app.import_transfer_form.package_password.is_empty());
        assert!(app.import_transfer_form.key_passphrase.is_empty());
    }

    /// P9.6: the panic/quick-lock hotkey (Ctrl+L) must immediately drive any
    /// unlocked screen to `UnlockBlocked`, purge every secret-bearing form
    /// via `purge_secret_state_on_lock`, and clear the decrypted vault state
    /// (`items`/`detail`/`header`) — from a representative unlocked screen
    /// (`Vault`) and while a secret-bearing text field is mid-entry, proving
    /// the hotkey is not swallowed by an in-progress edit.
    #[test]
    fn panic_lock_hotkey_purges_secrets_from_any_unlocked_screen() {
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
                password: "hunter2".to_string().into(),
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

        // Simulate a secret mid-entry in a form the panic key must still
        // scrub, proving the hotkey is not blocked by focus on a text field.
        app.certificate_rewrap_form.key_passphrase =
            SecretString::new("half-typed-secret".to_string());

        let should_quit = app.handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL));

        assert!(!should_quit, "panic-lock must not quit the app");
        assert!(matches!(app.screen, Screen::UnlockBlocked));
        assert!(app.items.is_empty());
        assert!(app.detail.is_none());
        assert!(app.header.is_none());
        assert!(matches!(app.options.auth, VaultAuth::PasswordEnv(_)));
        assert!(app.certificate_rewrap_form.key_passphrase.is_empty());
        assert!(app.status.to_lowercase().contains("lock"));
    }

    /// P9.6 verify fix: `purge_secret_state_on_lock` must scrub EVERY
    /// secret-bearing UI field, not just the unlock/recovery/certificate/
    /// transfer forms. Before this fix, triggering the panic-lock hotkey
    /// from mid-edit on an Add/Edit form (or with a decrypted item still
    /// shown on the detail screen) left the plaintext password, card
    /// number/CVV, and note content resident in `add_login_form`,
    /// `card_form`, `note_form`, `identity_form`, and `self.detail` even
    /// though the screen had already flipped to `UnlockBlocked`. This test
    /// must fail before the fix and pass after.
    #[test]
    fn panic_lock_hotkey_scrubs_every_secret_bearing_form_and_detail() {
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
                password: "hunter2".to_string().into(),
                url: None,
                notes: None,
                folder: None,
                tags: vec![],
            })
            .expect("add login");

        let mut app = App::new(options);
        assert!(matches!(app.screen, Screen::Vault));
        assert!(
            app.detail.is_some(),
            "a decrypted item must be resident to prove it gets scrubbed"
        );

        // Simulate mid-entry secrets in every form the panic key must scrub.
        app.screen = Screen::EditLogin;
        app.add_login_form.password = "half-typed-password".to_string();
        app.card_form.number = "4111111111111111".to_string();
        app.card_form.security_code = "123".to_string();
        app.note_form.content = "recovery codes: AAAA-BBBB-CCCC".to_string();
        app.identity_form.full_name = "Jane Doe".to_string();
        app.identity_form.address = "123 Secret St".to_string();

        let should_quit = app.handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL));

        assert!(!should_quit, "panic-lock must not quit the app");
        assert!(matches!(app.screen, Screen::UnlockBlocked));
        assert!(
            app.detail.is_none(),
            "the decrypted detail item must be scrubbed from the panic-lock path"
        );
        assert!(
            app.add_login_form.password.is_empty(),
            "add_login_form.password must be scrubbed on panic-lock"
        );
        assert!(
            app.card_form.number.is_empty(),
            "card_form.number must be scrubbed on panic-lock"
        );
        assert!(
            app.card_form.security_code.is_empty(),
            "card_form.security_code must be scrubbed on panic-lock"
        );
        assert!(
            app.note_form.content.is_empty(),
            "note_form.content must be scrubbed on panic-lock"
        );
        assert!(
            app.identity_form.full_name.is_empty(),
            "identity_form.full_name must be scrubbed on panic-lock"
        );
        assert!(
            app.identity_form.address.is_empty(),
            "identity_form.address must be scrubbed on panic-lock"
        );
    }

    /// `purge_secret_state_on_lock` must be a COMPLETE scrub on its own, called
    /// DIRECTLY — not only correct when reached through the hotkey path (which
    /// clears some fields in its wrapper). This enforces the function's contract
    /// so a partial scrub cannot land green via a hotkey-only test (P9 re-verify
    /// LEAK-C: the master recovery mnemonic was cleared by the caller, not here).
    #[test]
    fn purge_secret_state_on_lock_directly_scrubs_the_master_recovery_mnemonic() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");
        paranoid_vault::init_vault(&path, "correct horse battery staple").expect("init");
        let options = app_options(&path);
        add_device_fallback(&options).expect("device fallback");

        // Obtain a real enrollment (holds the 24-word master recovery phrase)
        // through the vault API, then plant it in App state as the enroll flow does.
        let mut vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        let enrollment = vault
            .add_mnemonic_keyslot(Some("paper-backup".to_string()))
            .expect("add mnemonic keyslot");
        let mut app = App::new(options);
        app.latest_mnemonic_enrollment = Some(enrollment);

        // Call the purge contract DIRECTLY, not through the hotkey wrapper.
        app.purge_secret_state_on_lock();

        assert!(
            app.latest_mnemonic_enrollment.is_none(),
            "purge_secret_state_on_lock must clear the master recovery mnemonic on its own"
        );
    }

    /// The panic-lock hotkey must be a no-op (not crash, not change screen)
    /// from pre-unlock screens that have no unlocked state to purge.
    #[test]
    fn panic_lock_hotkey_is_inert_before_unlock() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("vault.sqlite");

        let mut app = App::new(password_only_options(&path));
        assert!(matches!(app.screen, Screen::EnvironmentApproval));

        let should_quit = app.handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL));

        assert!(!should_quit);
        assert!(matches!(app.screen, Screen::EnvironmentApproval));
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
