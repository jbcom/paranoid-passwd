#![allow(clippy::todo)]

#[cfg(not(any(target_os = "android", target_arch = "wasm32")))]
use arboard::Clipboard;
#[cfg(not(target_arch = "wasm32"))]
use paranoid_audit::{
    AuditEvent, AuditSinkHealth, AuditSurface, assess_optional_jsonl_file_audit_sink,
    write_events_jsonl,
};
#[cfg(not(target_arch = "wasm32"))]
use paranoid_core::{
    CharsetOptions, CharsetSpec, FrameworkId, GenerationReport, ParanoidRequest, execute_request,
};
#[cfg(not(target_arch = "wasm32"))]
use paranoid_ops::{
    FederalCryptoProviderEvidence, OpsPolicyContext, OpsProfile, VaultOperationAccess,
    evaluate_vault_operation,
};
#[cfg(not(target_arch = "wasm32"))]
use paranoid_vault::{
    GenerateStoreLoginRecord, NewLoginRecord, SecretString, VaultAuth, VaultHeader,
    VaultItemFilter, VaultItemKind, VaultItemPayload, VaultItemSummary, VaultOpenOptions,
    default_vault_path, init_vault, unlock_vault_for_options,
};
use slint::ComponentHandle;
#[cfg(not(target_arch = "wasm32"))]
use slint::SharedString;
use std::{cell::RefCell, env, rc::Rc};
#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs,
    path::{Path, PathBuf},
};

const GUI_VERSION: &str = env!("CARGO_PKG_VERSION");

#[allow(clippy::all, clippy::unwrap_used, warnings)]
mod slint_shell {
    slint::include_modules!();
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct GuiLaunchOptions {
    audit_jsonl: Option<String>,
    require_audit_sink: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LaunchAction {
    RunGui(GuiLaunchOptions),
    PrintHelp,
    PrintVersion,
}

fn gui_usage() -> &'static str {
    "\
Usage: paranoid-passwd-gui [OPTIONS]

Launch the native paranoid-passwd desktop application.

Options:
      --audit-jsonl PATH      Append GUI ops policy audit events to a JSONL file
      --require-audit-sink    Fail closed when the configured audit sink is unavailable
  -V, --version            Print version info and exit
  -h, --help               Print this help and exit
"
}

fn resolve_launch_action<I>(args: I) -> Result<LaunchAction, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut options = GuiLaunchOptions::default();
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        match argument.to_string_lossy().as_ref() {
            "-V" | "--version" => return Ok(LaunchAction::PrintVersion),
            "-h" | "--help" => return Ok(LaunchAction::PrintHelp),
            "--audit-jsonl" => {
                let Some(path) = args.next() else {
                    return Err("--audit-jsonl requires a path".to_string());
                };
                options.audit_jsonl = Some(path.to_string_lossy().to_string());
            }
            "--require-audit-sink" => options.require_audit_sink = true,
            "--" => break,
            value => return Err(format!("unsupported argument: {value}")),
        }
    }
    Ok(LaunchAction::RunGui(options))
}

fn print_gui_usage() {
    print!("{}", gui_usage());
}

fn print_gui_version() {
    println!("paranoid-passwd-gui {GUI_VERSION}");
    println!(
        "build:          {}",
        option_env!("PARANOID_GUI_BUILD_DATE").unwrap_or("dev")
    );
    println!(
        "commit:         {}",
        option_env!("PARANOID_GUI_BUILD_COMMIT").unwrap_or("dev")
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuiAutomationScenario {
    OperatorWorkflow,
}

#[cfg(not(target_arch = "wasm32"))]
impl GuiAutomationScenario {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "operator" | "operator-workflow" => Some(Self::OperatorWorkflow),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::OperatorWorkflow => "operator-workflow",
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
struct GuiAutomation {
    scenario: GuiAutomationScenario,
    #[cfg(not(target_arch = "wasm32"))]
    vault_path: PathBuf,
    #[cfg(not(target_arch = "wasm32"))]
    backup_path: PathBuf,
    #[cfg(not(target_arch = "wasm32"))]
    output_path: PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
struct GuiRuntimeConfig {
    audit_jsonl: Option<PathBuf>,
    require_audit_sink: bool,
    audit_sink_health: AuditSinkHealth,
}

#[cfg(not(target_arch = "wasm32"))]
impl GuiRuntimeConfig {
    fn from_launch_options(options: &GuiLaunchOptions) -> Self {
        let audit_jsonl = options.audit_jsonl.as_ref().map(PathBuf::from);
        let audit_sink_health = assess_optional_jsonl_file_audit_sink(audit_jsonl.as_deref());
        Self {
            audit_jsonl,
            require_audit_sink: options.require_audit_sink,
            audit_sink_health,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for GuiRuntimeConfig {
    fn default() -> Self {
        Self {
            audit_jsonl: None,
            require_audit_sink: false,
            audit_sink_health: AuditSinkHealth::not_configured_jsonl(),
        }
    }
}

#[derive(Clone)]
struct GuiState {
    #[cfg(not(target_arch = "wasm32"))]
    vault_path: PathBuf,
    #[cfg(not(target_arch = "wasm32"))]
    vault_secret: String,
    #[cfg(not(target_arch = "wasm32"))]
    selected_login_id: Option<String>,
    #[cfg(not(target_arch = "wasm32"))]
    last_report: Option<GenerationReport>,
    #[cfg(not(target_arch = "wasm32"))]
    ops_audit_events: Vec<AuditEvent>,
    #[cfg(not(target_arch = "wasm32"))]
    audit_jsonl: Option<PathBuf>,
    #[cfg(not(target_arch = "wasm32"))]
    require_audit_sink: bool,
    #[cfg(not(target_arch = "wasm32"))]
    audit_sink_health: AuditSinkHealth,
    status: String,
    generated_passwords: String,
    audit_details: String,
    vault_items: String,
    vault_posture: String,
    keyslot_summary: String,
    selected_item: String,
    automation_status: String,
}

impl std::fmt::Debug for GuiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("GuiState");
        #[cfg(not(target_arch = "wasm32"))]
        debug_struct
            .field("vault_path", &self.vault_path)
            .field(
                "vault_secret",
                &format_args!("<redacted> ({} bytes)", self.vault_secret.len()),
            )
            .field("selected_login_id", &self.selected_login_id)
            .field(
                "last_report",
                &self.last_report.as_ref().map(|_| "<redacted>"),
            )
            .field("ops_audit_events", &self.ops_audit_events)
            .field("audit_jsonl", &self.audit_jsonl)
            .field("require_audit_sink", &self.require_audit_sink)
            .field("audit_sink_health", &self.audit_sink_health);
        let generated_password_count = self
            .generated_passwords
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        debug_struct
            .field("status", &self.status)
            .field(
                "generated_passwords",
                &format_args!("<redacted> ({generated_password_count} passwords)"),
            )
            .field("audit_details", &self.audit_details)
            .field("vault_items", &self.vault_items)
            .field("vault_posture", &self.vault_posture)
            .field("keyslot_summary", &self.keyslot_summary)
            .field("selected_item", &"<redacted>")
            .field("automation_status", &self.automation_status)
            .finish()
    }
}

impl Default for GuiState {
    #[cfg(not(target_arch = "wasm32"))]
    fn default() -> Self {
        Self::with_runtime_config(GuiRuntimeConfig::default())
    }

    #[cfg(target_arch = "wasm32")]
    fn default() -> Self {
        Self {
            status: "WASM target is compile-checked as a non-secret Slint surface. Native vault and generator operations stay disabled until target storage and crypto are threat-modeled.".to_string(),
            generated_passwords: "No password material is generated on this gated WASM surface.".to_string(),
            audit_details:
                "WASM release support is intentionally disabled for secret-handling flows.".to_string(),
            vault_items: "Vault storage is unavailable on the gated WASM surface.".to_string(),
            vault_posture: "WASM secret handling gated".to_string(),
            keyslot_summary: "No keyslots loaded; native vault crate is not linked for wasm32.".to_string(),
            selected_item: "No vault item selected.".to_string(),
            automation_status: "WASM compile check only".to_string(),
        }
    }
}

impl GuiState {
    #[cfg(not(target_arch = "wasm32"))]
    fn with_runtime_config(config: GuiRuntimeConfig) -> Self {
        Self {
            vault_path: default_vault_path(),
            vault_secret: String::new(),
            selected_login_id: None,
            last_report: None,
            ops_audit_events: Vec::new(),
            audit_jsonl: config.audit_jsonl,
            require_audit_sink: config.require_audit_sink,
            audit_sink_health: config.audit_sink_health,
            status: "Ready. Core owns RNG, rejection sampling, audit math, and vault crypto."
                .to_string(),
            generated_passwords: "No passwords generated yet.".to_string(),
            audit_details:
                "Run an audit to produce entropy, compliance, and rejection-sampling evidence."
                    .to_string(),
            vault_items: "Vault is locked or not loaded.".to_string(),
            vault_posture: "Vault posture unavailable.".to_string(),
            keyslot_summary: "No keyslots loaded.".to_string(),
            selected_item: "No vault item selected.".to_string(),
            automation_status: "Manual mode".to_string(),
        }
    }

    fn apply_to(&self, window: &slint_shell::ParanoidPasswdShell) {
        window.set_mode("Slint GUI".into());
        window.set_posture(self.vault_posture.clone().into());
        window.set_readiness(self.status.clone().into());
        #[cfg(not(target_arch = "wasm32"))]
        window.set_vault_path(self.vault_path.display().to_string().into());
        #[cfg(target_arch = "wasm32")]
        window.set_vault_path("WASM gated".into());
        window.set_status(self.status.clone().into());
        window.set_generated_passwords(self.generated_passwords.clone().into());
        window.set_audit_details(self.audit_details.clone().into());
        window.set_vault_items(self.vault_items.clone().into());
        window.set_keyslot_summary(self.keyslot_summary.clone().into());
        window.set_selected_item(self.selected_item.clone().into());
        window.set_automation_status(self.automation_status.clone().into());
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn set_error(&mut self, context: &str, error: impl ToString) {
        self.status = format!("{context}: {}", error.to_string());
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn record_vault_operation_policy(
        &mut self,
        operation: &str,
        access: VaultOperationAccess,
    ) -> Result<(), String> {
        let context = self.ops_policy_context();
        let evaluation = evaluate_vault_operation(AuditSurface::Gui, operation, access, &context);
        self.ops_audit_events
            .extend(evaluation.audit_events.iter().cloned());
        self.audit_details = summarize_gui_ops_audit(self.ops_audit_events.as_slice());
        if let Some(path) = &self.audit_jsonl
            && self.audit_sink_health.is_available()
        {
            write_events_jsonl(path, evaluation.audit_events.as_slice()).map_err(|error| {
                format!(
                    "write GUI vault audit events to {}: {error}",
                    path.display()
                )
            })?;
        }
        if evaluation.is_allowed() {
            Ok(())
        } else {
            Err(format!(
                "GUI vault operation policy denied: {:?}",
                evaluation.decision
            ))
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn ops_policy_context(&self) -> OpsPolicyContext {
        OpsPolicyContext {
            profile: OpsProfile::Default,
            audit_sink_required: self.audit_jsonl.is_some() || self.require_audit_sink,
            audit_sink_available: self.audit_sink_health.is_available(),
            crypto_provider: FederalCryptoProviderEvidence::collect_from_environment(),
            seal_posture: None,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn summarize_gui_ops_audit(events: &[AuditEvent]) -> String {
    let event_count = events.len();
    let operation_count = event_count / 2;
    let last_response = events
        .iter()
        .rev()
        .find(|event| event.attributes.contains_key("decision"));
    let last_operation = last_response
        .and_then(|event| event.attributes.get("vault_operation"))
        .map(String::as_str)
        .unwrap_or("unknown");
    let last_access = last_response
        .and_then(|event| event.attributes.get("vault_access"))
        .map(String::as_str)
        .unwrap_or("unknown");
    let last_decision = last_response
        .and_then(|event| event.attributes.get("decision"))
        .map(String::as_str)
        .unwrap_or("pending");

    format!(
        "GUI ops audit: {operation_count} vault operation(s), {event_count} policy event(s). Last operation={last_operation} access={last_access} decision={last_decision}."
    )
}

pub fn cli_main() -> Result<(), slint::PlatformError> {
    match resolve_launch_action(env::args_os().skip(1)) {
        Ok(LaunchAction::RunGui(options)) => run_gui(options),
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

#[cfg(not(target_arch = "wasm32"))]
fn run_gui(options: GuiLaunchOptions) -> Result<(), slint::PlatformError> {
    let window = slint_shell::ParanoidPasswdShell::new()?;
    let runtime_config = GuiRuntimeConfig::from_launch_options(&options);
    let state = Rc::new(RefCell::new(GuiState::with_runtime_config(runtime_config)));

    if let Ok(Some(automation)) = configured_gui_automation() {
        let result = run_operator_automation(&mut state.borrow_mut(), &automation);
        match result {
            Ok(message) => {
                state.borrow_mut().automation_status = "Automation passed".to_string();
                if let Err(error) = write_gui_automation_outcome(
                    &automation.output_path,
                    "pass",
                    automation.scenario,
                    &automation.vault_path,
                    &automation.backup_path,
                    message.as_str(),
                ) {
                    eprintln!("failed to write GUI automation pass marker: {error}");
                    state
                        .borrow_mut()
                        .set_error("GUI automation outcome write failed", error);
                }
            }
            Err(error) => {
                state.borrow_mut().automation_status = "Automation failed".to_string();
                state
                    .borrow_mut()
                    .set_error("GUI automation failed", &error);
                let _ = write_gui_automation_outcome(
                    &automation.output_path,
                    "fail",
                    automation.scenario,
                    &automation.vault_path,
                    &automation.backup_path,
                    error.as_str(),
                );
            }
        }
    } else if let Err(error) = configured_gui_automation() {
        state
            .borrow_mut()
            .set_error("GUI automation configuration invalid", error);
    }

    wire_callbacks(&window, Rc::clone(&state));
    state.borrow().apply_to(&window);
    window.run()
}

#[cfg(target_arch = "wasm32")]
fn run_gui(_options: GuiLaunchOptions) -> Result<(), slint::PlatformError> {
    let window = slint_shell::ParanoidPasswdShell::new()?;
    let state = Rc::new(RefCell::new(GuiState::default()));
    wire_callbacks(&window, Rc::clone(&state));
    state.borrow().apply_to(&window);
    window.run()
}

#[cfg(not(target_arch = "wasm32"))]
fn wire_callbacks(window: &slint_shell::ParanoidPasswdShell, state: Rc<RefCell<GuiState>>) {
    let weak = window.as_weak();
    let state_for_audit = Rc::clone(&state);
    window.on_run_audit(move |length, count, nist, pci, soc2| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        let mut state = state_for_audit.borrow_mut();
        let result = run_generator_audit(&mut state, &length, &count, nist, pci, soc2);
        if let Err(error) = result {
            state.set_error("Generator audit failed", error);
        }
        state.apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_init = Rc::clone(&state);
    window.on_init_vault(move |path, secret| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        let mut state = state_for_init.borrow_mut();
        match init_vault_from_ui(&mut state, &path, &secret) {
            Ok(()) => {}
            Err(error) => state.set_error("Vault initialization failed", error),
        }
        state.apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_unlock = Rc::clone(&state);
    window.on_unlock_vault(move |path, secret| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        let mut state = state_for_unlock.borrow_mut();
        match load_vault_from_ui(&mut state, &path, &secret) {
            Ok(()) => {}
            Err(error) => state.set_error("Vault unlock failed", error),
        }
        state.apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_add = Rc::clone(&state);
    window.on_add_login(
        move |path, secret, title, username, password, folder, tags| {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let mut state = state_for_add.borrow_mut();
            let input = LoginFormInput {
                title: &title,
                username: &username,
                password: &password,
                folder: &folder,
                tags: &tags,
            };
            match add_login_from_ui(&mut state, &path, &secret, input) {
                Ok(()) => {}
                Err(error) => state.set_error("Vault add login failed", error),
            }
            state.apply_to(&window);
        },
    );

    let weak = window.as_weak();
    let state_for_rotate = Rc::clone(&state);
    window.on_generate_rotate(move |path, secret, length| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        let mut state = state_for_rotate.borrow_mut();
        match rotate_selected_login_from_ui(&mut state, &path, &secret, &length) {
            Ok(()) => {}
            Err(error) => state.set_error("Generate and rotate failed", error),
        }
        state.apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_mnemonic = Rc::clone(&state);
    window.on_enroll_mnemonic(move |path, secret, label| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        let mut state = state_for_mnemonic.borrow_mut();
        match enroll_mnemonic_from_ui(&mut state, &path, &secret, &label) {
            Ok(()) => {}
            Err(error) => state.set_error("Mnemonic enrollment failed", error),
        }
        state.apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_backup = Rc::clone(&state);
    window.on_export_backup(move |path, secret, output| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        let mut state = state_for_backup.borrow_mut();
        match export_backup_from_ui(&mut state, &path, &secret, &output) {
            Ok(()) => {}
            Err(error) => state.set_error("Backup export failed", error),
        }
        state.apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_copy = Rc::clone(&state);
    window.on_copy_primary(move || {
        let Some(window) = weak.upgrade() else {
            return;
        };
        let mut state = state_for_copy.borrow_mut();
        match copy_primary_password(&state) {
            Ok(()) => state.status = "Primary generated password copied to clipboard.".to_string(),
            Err(error) => state.set_error("Clipboard copy failed", error),
        }
        state.apply_to(&window);
    });
}

#[cfg(target_arch = "wasm32")]
fn wire_callbacks(window: &slint_shell::ParanoidPasswdShell, state: Rc<RefCell<GuiState>>) {
    let gate_message = "WASM Slint surface is compile-checked only. Secret generation, vault unlock, storage, recovery, backup, and clipboard operations are disabled until target storage and crypto are threat-modeled.";

    let weak = window.as_weak();
    let state_for_audit = Rc::clone(&state);
    window.on_run_audit(move |_, _, _, _, _| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        apply_wasm_gate(&mut state_for_audit.borrow_mut(), "Generator", gate_message);
        state_for_audit.borrow().apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_init = Rc::clone(&state);
    window.on_init_vault(move |_, _| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        apply_wasm_gate(&mut state_for_init.borrow_mut(), "Vault init", gate_message);
        state_for_init.borrow().apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_unlock = Rc::clone(&state);
    window.on_unlock_vault(move |_, _| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        apply_wasm_gate(
            &mut state_for_unlock.borrow_mut(),
            "Vault unlock",
            gate_message,
        );
        state_for_unlock.borrow().apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_add = Rc::clone(&state);
    window.on_add_login(move |_, _, _, _, _, _, _| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        apply_wasm_gate(&mut state_for_add.borrow_mut(), "Add login", gate_message);
        state_for_add.borrow().apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_rotate = Rc::clone(&state);
    window.on_generate_rotate(move |_, _, _| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        apply_wasm_gate(&mut state_for_rotate.borrow_mut(), "Rotate", gate_message);
        state_for_rotate.borrow().apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_mnemonic = Rc::clone(&state);
    window.on_enroll_mnemonic(move |_, _, _| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        apply_wasm_gate(
            &mut state_for_mnemonic.borrow_mut(),
            "Mnemonic enrollment",
            gate_message,
        );
        state_for_mnemonic.borrow().apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_backup = Rc::clone(&state);
    window.on_export_backup(move |_, _, _| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        apply_wasm_gate(
            &mut state_for_backup.borrow_mut(),
            "Backup export",
            gate_message,
        );
        state_for_backup.borrow().apply_to(&window);
    });

    let weak = window.as_weak();
    let state_for_copy = Rc::clone(&state);
    window.on_copy_primary(move || {
        let Some(window) = weak.upgrade() else {
            return;
        };
        apply_wasm_gate(&mut state_for_copy.borrow_mut(), "Clipboard", gate_message);
        state_for_copy.borrow().apply_to(&window);
    });
}

#[cfg(target_arch = "wasm32")]
fn apply_wasm_gate(state: &mut GuiState, operation: &str, message: &str) {
    state.status = format!("{operation} blocked: {message}");
    state.generated_passwords = "No password material generated on WASM.".to_string();
    state.audit_details = "Native paranoid-core is not linked into the WASM target.".to_string();
    state.vault_items = "Native paranoid-vault is not linked into the WASM target.".to_string();
    state.keyslot_summary = "WASM vault keyslots are unavailable.".to_string();
    state.selected_item = "No secret material is loaded on this surface.".to_string();
    state.automation_status = "WASM gate enforced".to_string();
}

#[cfg(not(target_arch = "wasm32"))]
fn configured_gui_automation() -> Result<Option<GuiAutomation>, String> {
    let Some(raw_scenario) = env::var_os("PARANOID_GUI_AUTOMATION_SCENARIO") else {
        return Ok(None);
    };
    let raw_scenario = raw_scenario.to_string_lossy().into_owned();
    let scenario = GuiAutomationScenario::parse(raw_scenario.as_str())
        .ok_or_else(|| format!("unknown GUI automation scenario: {raw_scenario}"))?;
    let vault_path = env::var_os("PARANOID_GUI_AUTOMATION_VAULT_PATH")
        .map(PathBuf::from)
        .ok_or_else(|| {
            "PARANOID_GUI_AUTOMATION_VAULT_PATH is required when GUI automation is enabled"
                .to_string()
        })?;
    let backup_path = env::var_os("PARANOID_GUI_AUTOMATION_BACKUP_PATH")
        .map(PathBuf::from)
        .ok_or_else(|| {
            "PARANOID_GUI_AUTOMATION_BACKUP_PATH is required when GUI automation is enabled"
                .to_string()
        })?;
    let output_path = env::var_os("PARANOID_GUI_AUTOMATION_OUTPUT_PATH")
        .map(PathBuf::from)
        .ok_or_else(|| {
            "PARANOID_GUI_AUTOMATION_OUTPUT_PATH is required when GUI automation is enabled"
                .to_string()
        })?;
    Ok(Some(GuiAutomation {
        scenario,
        vault_path,
        backup_path,
        output_path,
    }))
}

#[cfg(not(target_arch = "wasm32"))]
fn write_gui_automation_outcome(
    path: &Path,
    status: &str,
    scenario: GuiAutomationScenario,
    vault_path: &Path,
    backup_path: &Path,
    message: &str,
) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let sanitized_message = message.replace('\n', " ");
    fs::write(
        path,
        format!(
            "status={status}\nscenario={}\nvault={}\nbackup={}\nmessage={sanitized_message}\n",
            scenario.as_str(),
            vault_path.display(),
            backup_path.display()
        ),
    )
    .map_err(|error| error.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn run_operator_automation(
    state: &mut GuiState,
    automation: &GuiAutomation,
) -> Result<String, String> {
    let secret = if state.vault_secret.is_empty() {
        env::var("PARANOID_MASTER_PASSWORD").map_err(|_| {
            "PARANOID_MASTER_PASSWORD is required for GUI automation vault unlock".to_string()
        })?
    } else {
        state.vault_secret.clone()
    };
    state.vault_path = automation.vault_path.clone();
    state.vault_secret = secret.clone();
    state.automation_status = format!("Running {} under xvfb-run", automation.scenario.as_str());

    run_generator_audit(state, "24", "2", true, false, false)?;
    let report = state
        .last_report
        .as_ref()
        .ok_or_else(|| "generator automation did not produce a report".to_string())?;
    if report.passwords.len() != 2 {
        return Err(format!(
            "generator automation expected 2 passwords, found {}",
            report.passwords.len()
        ));
    }

    state.record_vault_operation_policy("read_item", VaultOperationAccess::Decrypt)?;
    load_vault(state, &automation.vault_path, secret.as_str())?;
    state.record_vault_operation_policy("mutate_item", VaultOperationAccess::Mutate)?;
    let github = add_login(
        state,
        &automation.vault_path,
        secret.as_str(),
        LoginInput {
            title: "GitHub".to_string(),
            username: "octocat".to_string(),
            password: "hunter2".to_string(),
            folder: Some("Work".to_string()),
            tags: vec!["work".to_string(), "code".to_string()],
        },
    )?;
    if github.title != "GitHub" {
        return Err("vault automation did not store the GitHub login".to_string());
    }

    state.record_vault_operation_policy("read_item", VaultOperationAccess::Decrypt)?;
    let filtered = unlock_with_password(&automation.vault_path, secret.as_str())?
        .list_items_filtered(&VaultItemFilter {
            query: Some("GitHub".to_string()),
            kind: None,
            folder: None,
            tag: None,
        })
        .map_err(|error| error.to_string())?;
    if filtered.len() != 1 {
        return Err(format!(
            "vault automation expected one filtered GitHub login, found {}",
            filtered.len()
        ));
    }

    state.record_vault_operation_policy("mutate_item", VaultOperationAccess::Mutate)?;
    rotate_selected_login(state, &automation.vault_path, secret.as_str(), 28)?;
    state.record_vault_operation_policy("read_item", VaultOperationAccess::Decrypt)?;
    let rotated = unlock_with_password(&automation.vault_path, secret.as_str())?
        .get_item(
            state
                .selected_login_id
                .as_deref()
                .ok_or_else(|| "rotation lost the selected login id".to_string())?,
        )
        .map_err(|error| error.to_string())?;
    match rotated.payload {
        VaultItemPayload::Login(login) if login.password != "hunter2" => {}
        VaultItemPayload::Login(_) => {
            return Err("vault automation rotated the login but kept the original password".into());
        }
        _ => return Err("vault automation selected a non-login item after rotation".into()),
    }

    state.record_vault_operation_policy("keyslot_lifecycle", VaultOperationAccess::Keyslot)?;
    let mut vault = unlock_with_password(&automation.vault_path, secret.as_str())?;
    let enrollment = vault
        .add_mnemonic_keyslot(Some("paper-backup".to_string()))
        .map_err(|error| error.to_string())?;
    if enrollment.keyslot.label.as_deref() != Some("paper-backup") {
        return Err("mnemonic keyslot was enrolled with an unexpected label".to_string());
    }
    state.status =
        "Mnemonic recovery slot enrolled; phrase captured by automation memory only.".to_string();
    state.keyslot_summary = summarize_keyslots(vault.header());

    state.record_vault_operation_policy("export", VaultOperationAccess::Export)?;
    let written = vault
        .export_backup(&automation.backup_path)
        .map_err(|error| error.to_string())?;
    if !written.exists() {
        return Err(format!(
            "backup export did not create {}",
            automation.backup_path.display()
        ));
    }

    state.record_vault_operation_policy("read_item", VaultOperationAccess::Decrypt)?;
    load_vault(state, &automation.vault_path, secret.as_str())?;
    state.status = "GUI automation passed. Generator audit, typed ops policy events, vault CRUD, generate-and-rotate, mnemonic enrollment, and backup export all completed under xvfb-run.".to_string();
    Ok(state.status.clone())
}

#[cfg(not(target_arch = "wasm32"))]
fn run_generator_audit(
    state: &mut GuiState,
    length: impl AsRef<str>,
    count: impl AsRef<str>,
    nist: bool,
    pci: bool,
    soc2: bool,
) -> Result<(), String> {
    let request = build_request(length.as_ref(), count.as_ref(), nist, pci, soc2)?;
    let mut stages = Vec::new();
    let report = execute_request(&request, true, |stage| stages.push(stage))
        .map_err(|error| error.to_string())?;
    state.generated_passwords = report
        .passwords
        .iter()
        .enumerate()
        .map(|(index, password)| {
            format!(
                "{}. {}  sha256={}  pass={}",
                index + 1,
                password.value,
                password.sha256_hex,
                password.all_pass
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    state.audit_details = summarize_report(&report, stages.as_slice());
    state.status = "Generator audit complete through paranoid-core.".to_string();
    state.last_report = Some(report);
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn build_request(
    length: &str,
    count: &str,
    nist: bool,
    pci: bool,
    soc2: bool,
) -> Result<ParanoidRequest, String> {
    let mut selected_frameworks = Vec::new();
    if nist {
        selected_frameworks.push(FrameworkId::Nist);
    }
    if pci {
        selected_frameworks.push(FrameworkId::PciDss);
    }
    if soc2 {
        selected_frameworks.push(FrameworkId::Soc2);
    }

    Ok(ParanoidRequest {
        length: parse_usize(length, "length")?,
        count: parse_usize(count, "count")?,
        batch_size: 500,
        charset: CharsetSpec::Options(CharsetOptions::default()),
        requirements: Default::default(),
        selected_frameworks,
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn summarize_report(report: &GenerationReport, stages: &[paranoid_core::AuditStage]) -> String {
    let stage_names = stages
        .iter()
        .map(|stage| format!("{stage:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    match &report.audit {
        Some(audit) => format!(
            "verdict={} | length={} | charset={} | entropy={:.2} bits | chi2_p={:.6} | serial={:.6} | duplicates={} | rejection_max_valid={} | stages={}",
            if audit.overall_pass { "PASS" } else { "REVIEW" },
            report.request.length,
            report.request.charset.len(),
            audit.entropy.total_entropy,
            audit.chi2_p_value,
            audit.serial_correlation,
            audit.duplicates,
            audit.rejection_max_valid,
            stage_names
        ),
        None => "Audit disabled.".to_string(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn init_vault_from_ui(
    state: &mut GuiState,
    path: &SharedString,
    secret: &SharedString,
) -> Result<(), String> {
    state.record_vault_operation_policy("init", VaultOperationAccess::Keyslot)?;
    let path = PathBuf::from(path.as_str());
    let secret = secret.as_str();
    init_vault(&path, secret).map_err(|error| error.to_string())?;
    state.status = format!("Initialized encrypted vault at {}.", path.display());
    load_vault(state, &path, secret)
}

#[cfg(not(target_arch = "wasm32"))]
fn load_vault_from_ui(
    state: &mut GuiState,
    path: &SharedString,
    secret: &SharedString,
) -> Result<(), String> {
    state.record_vault_operation_policy("read_item", VaultOperationAccess::Decrypt)?;
    load_vault(state, Path::new(path.as_str()), secret.as_str())
}

#[cfg(not(target_arch = "wasm32"))]
struct LoginFormInput<'a> {
    title: &'a SharedString,
    username: &'a SharedString,
    password: &'a SharedString,
    folder: &'a SharedString,
    tags: &'a SharedString,
}

#[cfg(not(target_arch = "wasm32"))]
fn add_login_from_ui(
    state: &mut GuiState,
    path: &SharedString,
    secret: &SharedString,
    input: LoginFormInput<'_>,
) -> Result<(), String> {
    state.record_vault_operation_policy("mutate_item", VaultOperationAccess::Mutate)?;
    add_login(
        state,
        Path::new(path.as_str()),
        secret.as_str(),
        LoginInput {
            title: input.title.to_string(),
            username: input.username.to_string(),
            password: input.password.to_string(),
            folder: normalize_optional_field(input.folder.as_str()),
            tags: parse_tags_csv(input.tags.as_str()),
        },
    )?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn rotate_selected_login_from_ui(
    state: &mut GuiState,
    path: &SharedString,
    secret: &SharedString,
    length: &SharedString,
) -> Result<(), String> {
    state.record_vault_operation_policy("mutate_item", VaultOperationAccess::Mutate)?;
    let length = parse_usize(length.as_str(), "length")?;
    rotate_selected_login(state, Path::new(path.as_str()), secret.as_str(), length)
}

#[cfg(not(target_arch = "wasm32"))]
fn enroll_mnemonic_from_ui(
    state: &mut GuiState,
    path: &SharedString,
    secret: &SharedString,
    label: &SharedString,
) -> Result<(), String> {
    state.record_vault_operation_policy("keyslot_lifecycle", VaultOperationAccess::Keyslot)?;
    let mut vault = unlock_with_password(Path::new(path.as_str()), secret.as_str())?;
    let enrollment = vault
        .add_mnemonic_keyslot(normalize_optional_field(label.as_str()))
        .map_err(|error| error.to_string())?;
    state.vault_path = PathBuf::from(path.as_str());
    state.vault_secret = secret.to_string();
    state.keyslot_summary = summarize_keyslots(vault.header());
    state.status = format!(
        "Mnemonic recovery slot {} enrolled. Capture the phrase offline before closing this screen.",
        enrollment.keyslot.id
    );
    state.selected_item = format!(
        "New recovery phrase: {}\nThis GUI keeps the phrase in memory only long enough to show the operator.",
        enrollment.mnemonic
    );
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn export_backup_from_ui(
    state: &mut GuiState,
    path: &SharedString,
    secret: &SharedString,
    output: &SharedString,
) -> Result<(), String> {
    state.record_vault_operation_policy("export", VaultOperationAccess::Export)?;
    let output = output.as_str().trim();
    if output.is_empty() {
        return Err("backup output path is required".to_string());
    }
    let vault = unlock_with_password(Path::new(path.as_str()), secret.as_str())?;
    let written = vault
        .export_backup(output)
        .map_err(|error| error.to_string())?;
    state.status = format!("Exported encrypted vault backup to {}.", written.display());
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn load_vault(state: &mut GuiState, path: &Path, secret: &str) -> Result<(), String> {
    let vault = unlock_with_password(path, secret)?;
    let items = vault.list_items().map_err(|error| error.to_string())?;
    state.vault_path = path.to_path_buf();
    state.vault_secret = secret.to_string();
    state.vault_items = summarize_items(items.as_slice());
    state.vault_posture = summarize_posture(vault.header());
    state.keyslot_summary = summarize_keyslots(vault.header());
    if let Some(first_login) = items
        .iter()
        .find(|item| item.kind == VaultItemKind::Login)
        .or_else(|| items.first())
    {
        state.selected_login_id =
            (first_login.kind == VaultItemKind::Login).then(|| first_login.id.clone());
        state.selected_item = summarize_selected_item(&vault.get_item(&first_login.id).ok());
    } else {
        state.selected_login_id = None;
        state.selected_item = "Vault is unlocked and empty.".to_string();
    }
    state.status = format!(
        "Vault unlocked. {} item(s) loaded from {}.",
        items.len(),
        path.display()
    );
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn unlock_with_password(
    path: impl AsRef<Path>,
    secret: &str,
) -> Result<paranoid_vault::UnlockedVault, String> {
    if secret.is_empty() {
        return Err("vault recovery secret must not be empty".to_string());
    }
    let options = VaultOpenOptions {
        path: path.as_ref().to_path_buf(),
        auth: VaultAuth::Password(SecretString::new(secret.to_string())),
        mnemonic_phrase_env: None,
        mnemonic_phrase: None,
        mnemonic_slot: None,
        device_slot: None,
        use_device_auto: false,
    };
    unlock_vault_for_options(&options).map_err(|error| error.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
struct LoginInput {
    title: String,
    username: String,
    password: String,
    folder: Option<String>,
    tags: Vec<String>,
}

#[cfg(not(target_arch = "wasm32"))]
fn add_login(
    state: &mut GuiState,
    path: &Path,
    secret: &str,
    input: LoginInput,
) -> Result<VaultItemSummary, String> {
    let vault = unlock_with_password(path, secret)?;
    let item = vault
        .add_login(NewLoginRecord {
            title: input.title.trim().to_string(),
            username: input.username.trim().to_string(),
            password: input.password,
            url: None,
            notes: None,
            folder: input.folder,
            tags: input.tags,
        })
        .map_err(|error| error.to_string())?;
    state.selected_login_id = Some(item.id.clone());
    load_vault(state, path, secret)?;
    let summary = unlock_with_password(path, secret)?
        .list_items()
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|candidate| candidate.id == item.id)
        .ok_or_else(|| "stored login was not visible after refresh".to_string())?;
    state.selected_login_id = Some(summary.id.clone());
    state.status = format!("Stored login item {} in the encrypted vault.", summary.id);
    Ok(summary)
}

#[cfg(not(target_arch = "wasm32"))]
fn rotate_selected_login(
    state: &mut GuiState,
    path: &Path,
    secret: &str,
    length: usize,
) -> Result<(), String> {
    let target_login_id = state
        .selected_login_id
        .clone()
        .ok_or_else(|| "select or create a login before rotating its password".to_string())?;
    let request = ParanoidRequest {
        length,
        count: 1,
        batch_size: 500,
        charset: CharsetSpec::Options(CharsetOptions::default()),
        requirements: paranoid_core::CharRequirements {
            min_lowercase: 0,
            min_uppercase: 0,
            min_digits: 2,
            min_symbols: 0,
        },
        selected_frameworks: vec![FrameworkId::Nist],
    };
    let vault = unlock_with_password(path, secret)?;
    let (report, item) = vault
        .generate_and_store(
            &request,
            GenerateStoreLoginRecord {
                target_login_id: Some(target_login_id),
                title: None,
                username: None,
                url: None,
                notes: None,
                folder: None,
                tags: None,
            },
        )
        .map_err(|error| error.to_string())?;
    state.last_report = Some(report);
    state.selected_login_id = Some(item.id.clone());
    load_vault(state, path, secret)?;
    state.selected_login_id = Some(item.id.clone());
    state.status = format!(
        "Generated one password and rotated item {}. Generator verdict: PASS.",
        item.id
    );
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn copy_primary_password(state: &GuiState) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _ = state;
        return Err(
            "clipboard copy is disabled on this target until a platform clipboard adapter is added"
                .to_string(),
        );
    }

    #[cfg(not(target_os = "android"))]
    {
        let Some(password) = state
            .last_report
            .as_ref()
            .and_then(|report| report.passwords.first())
            .map(|password| password.value.clone())
        else {
            return Err("no generated password is available to copy".to_string());
        };
        Clipboard::new()
            .and_then(|mut clipboard| clipboard.set_text(password))
            .map_err(|error| error.to_string())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn summarize_items(items: &[VaultItemSummary]) -> String {
    if items.is_empty() {
        return "No records stored yet.".to_string();
    }
    items
        .iter()
        .map(|item| {
            let folder = item.folder.as_deref().unwrap_or("unfiled");
            format!(
                "{} | {} | {} | folder={} | duplicates={}",
                item.kind.as_str(),
                item.title,
                item.subtitle,
                folder,
                item.duplicate_password_count
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(not(target_arch = "wasm32"))]
fn summarize_selected_item(item: &Option<paranoid_vault::VaultItem>) -> String {
    let Some(item) = item else {
        return "No vault item selected.".to_string();
    };
    match &item.payload {
        VaultItemPayload::Login(login) => format!(
            "Login: {}\nUsername: {}\nFolder: {}\nTags: {}\nPassword history entries: {}",
            login.title,
            login.username,
            login.folder.as_deref().unwrap_or("unfiled"),
            login.tags.join(", "),
            login.password_history.len()
        ),
        VaultItemPayload::SecureNote(note) => format!(
            "Secure note: {}\nFolder: {}\nTags: {}",
            note.title,
            note.folder.as_deref().unwrap_or("unfiled"),
            note.tags.join(", ")
        ),
        VaultItemPayload::Card(card) => format!(
            "Card: {}\nCardholder: {}\nExpiry: {}/{}",
            card.title, card.cardholder_name, card.expiry_month, card.expiry_year
        ),
        VaultItemPayload::Identity(identity) => {
            format!("Identity: {}\nName: {}", identity.title, identity.full_name)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn summarize_posture(header: &VaultHeader) -> String {
    let posture = header.recovery_posture();
    format!(
        "Recovery={} Cert={} Device={} Recommended={}",
        posture.has_recovery_path,
        posture.has_certificate_path,
        posture.device_bound_slots,
        posture.meets_recommended_posture
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn summarize_keyslots(header: &VaultHeader) -> String {
    header
        .keyslots
        .iter()
        .map(|slot| {
            format!(
                "{} | {} | {}",
                slot.kind.as_str(),
                slot.id,
                slot.label.as_deref().unwrap_or("unlabeled")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_usize(raw: &str, label: &str) -> Result<usize, String> {
    raw.trim()
        .parse::<usize>()
        .map_err(|_| format!("{label} must be a positive integer"))
}

#[cfg(not(target_arch = "wasm32"))]
fn normalize_optional_field(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_tags_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(target_os = "android")]
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    slint::android::init(app).expect("failed to initialize Slint Android backend");
    if let Err(error) = run_gui(GuiLaunchOptions::default()) {
        eprintln!("paranoid-passwd-gui Android launch failed: {error}");
    }
}

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn paranoid_passwd_wasm_entrypoint() {
    if let Err(error) = run_gui(GuiLaunchOptions::default()) {
        eprintln!("paranoid-passwd-gui WASM launch failed: {error}");
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn launch_arguments_are_resolved() {
        assert_eq!(
            resolve_launch_action([std::ffi::OsString::from("--version")]),
            Ok(LaunchAction::PrintVersion)
        );
        assert_eq!(
            resolve_launch_action([std::ffi::OsString::from("--help")]),
            Ok(LaunchAction::PrintHelp)
        );
        assert!(resolve_launch_action([std::ffi::OsString::from("--bogus")]).is_err());
        assert_eq!(
            resolve_launch_action([
                std::ffi::OsString::from("--audit-jsonl"),
                std::ffi::OsString::from("gui-audit.jsonl"),
                std::ffi::OsString::from("--require-audit-sink"),
            ]),
            Ok(LaunchAction::RunGui(GuiLaunchOptions {
                audit_jsonl: Some("gui-audit.jsonl".to_string()),
                require_audit_sink: true,
            }))
        );
    }

    #[test]
    fn slint_shell_bindings_are_generated() {
        fn assert_component_handle<T: slint::ComponentHandle>() {}
        type Shell = slint_shell::ParanoidPasswdShell;
        assert_component_handle::<Shell>();

        let _set_mode: fn(&Shell, slint::SharedString) = Shell::set_mode;
        let _set_status: fn(&Shell, slint::SharedString) = Shell::set_status;
        let _set_vault_items: fn(&Shell, slint::SharedString) = Shell::set_vault_items;
    }

    #[test]
    fn request_builder_sets_frameworks() {
        let request = build_request("24", "2", true, false, true).expect("valid generator request");
        assert_eq!(request.length, 24);
        assert_eq!(request.count, 2);
        assert_eq!(
            request.selected_frameworks,
            vec![FrameworkId::Nist, FrameworkId::Soc2]
        );
    }

    #[test]
    fn tag_parser_normalizes_csv() {
        assert_eq!(
            parse_tags_csv(" work, code ,,"),
            vec!["work".to_string(), "code".to_string()]
        );
    }

    #[test]
    fn automation_contract_exercises_core_and_vault() {
        let tmpdir = tempfile::tempdir().expect("temporary GUI automation directory");
        let vault_path = tmpdir.path().join("vault.sqlite");
        let backup_path = tmpdir.path().join("vault.backup.json");
        init_vault(&vault_path, "correct horse battery staple").expect("test vault init");

        let automation = GuiAutomation {
            scenario: GuiAutomationScenario::OperatorWorkflow,
            vault_path: vault_path.clone(),
            backup_path: backup_path.clone(),
            output_path: tmpdir.path().join("outcome"),
        };
        let mut state = GuiState {
            vault_secret: "correct horse battery staple".to_string(),
            ..GuiState::default()
        };
        let result = run_operator_automation(&mut state, &automation);
        assert!(result.is_ok(), "{result:?}");
        assert!(backup_path.exists());
        assert!(state.vault_items.contains("GitHub"));
        assert!(state.keyslot_summary.contains("mnemonic"));
        assert_eq!(state.ops_audit_events.len(), 16);
        assert!(state.audit_details.contains("8 vault operation(s)"));
        assert!(state.audit_details.contains("decision=allow"));
        assert!(!state.audit_details.contains("hunter2"));
    }

    #[test]
    fn gui_state_debug_output_never_leaks_generated_password_material() {
        let mut state = GuiState::default();
        run_generator_audit(&mut state, "24", "3", true, false, false)
            .expect("valid generator audit request");

        assert!(!state.generated_passwords.trim().is_empty());
        assert!(state.last_report.is_some());

        let debug_output = format!("{state:?}");
        assert!(debug_output.contains("<redacted>"));
        assert!(debug_output.contains("3 passwords"));
        for line in state.generated_passwords.lines() {
            let Some((_, password)) = line.split_once(". ") else {
                continue;
            };
            let Some((password, _)) = password.split_once("  sha256=") else {
                continue;
            };
            assert!(!debug_output.contains(password));
        }
    }

    #[test]
    fn gui_state_debug_output_never_leaks_enrolled_mnemonic_phrase() {
        let tmpdir = tempfile::tempdir().expect("temporary GUI mnemonic directory");
        let vault_path = tmpdir.path().join("vault.sqlite");
        init_vault(&vault_path, "correct horse battery staple").expect("test vault init");

        let mut state = GuiState {
            vault_secret: "correct horse battery staple".to_string(),
            ..GuiState::default()
        };
        enroll_mnemonic_from_ui(
            &mut state,
            &SharedString::from(vault_path.to_string_lossy().to_string()),
            &SharedString::from("correct horse battery staple"),
            &SharedString::from("paper-backup"),
        )
        .expect("mnemonic enrollment succeeds");

        assert!(state.selected_item.contains("New recovery phrase:"));
        let mnemonic = state
            .selected_item
            .strip_prefix("New recovery phrase: ")
            .and_then(|rest| rest.split_once('\n'))
            .map(|(phrase, _)| phrase.to_string())
            .expect("selected_item carries the raw recovery phrase for the operator to record");
        assert!(!mnemonic.is_empty());

        let debug_output = format!("{state:?}");
        assert!(debug_output.contains("selected_item: \"<redacted>\""));
        assert!(!debug_output.contains(&mnemonic));
    }

    #[test]
    fn gui_vault_operation_policy_records_non_secret_audit_metadata() {
        let mut state = GuiState::default();

        state
            .record_vault_operation_policy("mutate_item", VaultOperationAccess::Mutate)
            .expect("default GUI policy allows local mutate operation");

        assert_eq!(state.ops_audit_events.len(), 2);
        assert!(state.audit_details.contains("mutate_item"));
        assert!(state.audit_details.contains("access=mutate"));
        assert!(state.audit_details.contains("decision=allow"));
    }

    #[test]
    fn gui_vault_operation_policy_persists_jsonl_when_configured() {
        let tmpdir = tempfile::tempdir().expect("temporary GUI audit directory");
        let audit_path = tmpdir.path().join("gui-audit.jsonl");
        let mut state = GuiState::with_runtime_config(GuiRuntimeConfig::from_launch_options(
            &GuiLaunchOptions {
                audit_jsonl: Some(audit_path.display().to_string()),
                require_audit_sink: false,
            },
        ));

        state
            .record_vault_operation_policy("export", VaultOperationAccess::Export)
            .expect("policy allow");

        let audit_jsonl = fs::read_to_string(&audit_path).expect("audit jsonl");
        assert_eq!(audit_jsonl.lines().count(), 2);
        assert!(audit_jsonl.contains(r#""surface":"ops""#));
        assert!(audit_jsonl.contains(r#""session_surface":"gui""#));
        assert!(audit_jsonl.contains(r#""vault_access":"export""#));
    }

    #[test]
    fn gui_vault_operation_policy_keeps_memory_events_when_jsonl_write_fails() {
        let tmpdir = tempfile::tempdir().expect("temporary GUI audit directory");
        let audit_path = tmpdir.path().join("gui-audit.jsonl");
        let mut state = GuiState::with_runtime_config(GuiRuntimeConfig::from_launch_options(
            &GuiLaunchOptions {
                audit_jsonl: Some(audit_path.display().to_string()),
                require_audit_sink: false,
            },
        ));
        drop(tmpdir);

        let result = state.record_vault_operation_policy("export", VaultOperationAccess::Export);

        assert!(result.is_err());
        assert_eq!(state.ops_audit_events.len(), 2);
        assert!(state.audit_details.contains("Last operation=export"));
        assert!(state.audit_details.contains("decision=allow"));
    }
}
