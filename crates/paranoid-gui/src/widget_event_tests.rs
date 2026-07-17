//! Real widget-event tests for the compiled `paranoid.slint` UI tree.
//!
//! These drive the actual generated `slint_shell::ParanoidPasswdShell` widget
//! tree through `i_slint_backend_testing`'s synthetic pointer/accessible-value
//! events (the same code paths a real mouse click or keystroke exercises: a
//! `LineEdit`'s compiled `accessible-action-set-value` handler assigns
//! `text-input.text` and fires `edited`, exactly like a real keystroke would,
//! and a `Button`'s synthetic pointer press/release exercises the same
//! `TouchArea` that a real mouse click would), then assert on window
//! property state (status text, item counts, keyslot/vault summaries)
//! rather than the `PARANOID_GUI_AUTOMATION_*` side-channel that
//! `tests/test_gui_e2e.sh` uses.
//!
//! Runs fully headless: `i_slint_backend_testing::init_no_event_loop()`
//! installs a null-rendering testing platform (no display server, no
//! `SLINT_BACKEND`/Xvfb required, unlike `test-gui-host-check`'s runtime
//! sibling `test-gui-e2e`) with real Slint layout math, so element
//! positions used by `single_click`/`mock_single_click` are geometrically
//! accurate against the compiled `.slint` tree. Building with
//! `SLINT_EMIT_DEBUG_INFO=1` (required for `ElementHandle::find_by_element_id`
//! to resolve compiled-in element ids) is wired through `make
//! test-gui-widgets`.

use super::*;
use i_slint_backend_testing::ElementHandle;
use slint::platform::PointerEventButton;

/// Builds a freshly wired, headless `ParanoidPasswdShell` with its real
/// callbacks connected to a fresh [`GuiState`], matching what `run_gui`
/// wires for the real desktop app.
fn new_wired_shell() -> (slint_shell::ParanoidPasswdShell, Rc<RefCell<GuiState>>) {
    i_slint_backend_testing::init_no_event_loop();
    let window = slint_shell::ParanoidPasswdShell::new().expect("compiled shell window");
    let state = Rc::new(RefCell::new(GuiState::default()));
    wire_callbacks(&window, Rc::clone(&state));
    state.borrow().apply_to(&window);
    (window, state)
}

fn find_one(window: &slint_shell::ParanoidPasswdShell, id: &str) -> ElementHandle {
    let full_id = format!("ParanoidPasswdShell::{id}");
    let mut matches = ElementHandle::find_by_element_id(window, full_id.as_str());
    let element = matches
        .next()
        .unwrap_or_else(|| panic!("no element with id {full_id} in the compiled widget tree"));
    assert!(
        matches.next().is_none(),
        "expected exactly one element with id {full_id}"
    );
    element
}

fn type_into(
    window: &slint_shell::ParanoidPasswdShell,
    id: &str,
    value: impl Into<slint::SharedString>,
) {
    find_one(window, id).set_accessible_value(value.into());
}

fn click(window: &slint_shell::ParanoidPasswdShell, id: &str) {
    find_one(window, id).mock_single_click(PointerEventButton::Left);
}

/// Real generator-audit widget flow: type a length/count into the real
/// `gen-length`/`gen-count` inputs and click the real "Run audit" button,
/// then assert the window's audit/status/generated-password properties.
#[test]
fn run_audit_via_real_widgets_populates_generator_state() {
    let (window, _state) = new_wired_shell();

    type_into(&window, "gen-length", "20");
    type_into(&window, "gen-count", "2");
    click(&window, "run-audit-button");

    let status = window.get_status().to_string();
    assert!(
        status.contains("Generator audit complete"),
        "status should reflect a completed audit, got: {status}"
    );
    let generated = window.get_generated_passwords().to_string();
    assert_eq!(
        generated
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count(),
        2,
        "two passwords should be listed, got: {generated}"
    );
    let audit_details = window.get_audit_details().to_string();
    assert!(
        audit_details.contains("verdict=PASS"),
        "audit details should carry a PASS verdict, got: {audit_details}"
    );
}

/// Real init-vault widget flow: type the vault path and recovery secret
/// into the real `vault-path-input`/`vault-secret` inputs and click the
/// real "Init" button, asserting the vault file exists and the window's
/// status/item-count properties reflect an unlocked, empty vault.
#[test]
fn init_vault_via_real_widgets_creates_and_unlocks_vault() {
    let tmpdir = tempfile::tempdir().expect("temp dir for init-vault test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, _state) = new_wired_shell();

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    assert!(
        vault_path.exists(),
        "clicking Init should create the vault file at the typed path"
    );
    let status = window.get_status().to_string();
    assert!(
        status.contains("Vault unlocked"),
        "status should report the vault as unlocked after Init, got: {status}"
    );
    assert!(
        status.contains("0 item(s)"),
        "a freshly initialized vault should report zero items, got: {status}"
    );
    let vault_items = window.get_vault_items().to_string();
    assert!(
        vault_items.contains("No records stored yet."),
        "a freshly initialized vault should show no records, got: {vault_items}"
    );
}

/// Real add-login widget flow: init a vault, then type a title/username/
/// password into the real Operations panel inputs and click the real
/// "Add login" button, asserting the window's vault-items property gains
/// exactly one entry reflecting the typed login.
#[test]
fn add_login_via_real_widgets_stores_one_item() {
    let tmpdir = tempfile::tempdir().expect("temp dir for add-login test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, _state) = new_wired_shell();

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    type_into(&window, "login-title", "GitHub");
    type_into(&window, "login-user", "octocat");
    type_into(&window, "login-password", "hunter2");
    type_into(&window, "login-folder", "Work");
    type_into(&window, "login-tags", "work,code");
    click(&window, "add-login-button");

    let status = window.get_status().to_string();
    assert!(
        status.contains("Stored login item"),
        "status should confirm the login was stored, got: {status}"
    );
    let vault_items = window.get_vault_items().to_string();
    assert_eq!(
        vault_items.lines().count(),
        1,
        "exactly one item should be listed after adding one login, got: {vault_items}"
    );
    assert!(
        vault_items.contains("GitHub") && vault_items.contains("octocat"),
        "the stored item should reflect the typed title/username, got: {vault_items}"
    );
    assert!(
        !vault_items.contains("hunter2"),
        "the vault item summary must never leak the stored password, got: {vault_items}"
    );
}

/// Real generate-and-rotate widget flow: init a vault, add a login, then
/// type a rotate length into the real input and click the real "Rotate"
/// button, asserting the window's status confirms rotation and the
/// selected item's history grew.
#[test]
fn generate_and_rotate_via_real_widgets_rotates_selected_login() {
    let tmpdir = tempfile::tempdir().expect("temp dir for rotate test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, _state) = new_wired_shell();

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    type_into(&window, "login-title", "GitHub");
    type_into(&window, "login-user", "octocat");
    type_into(&window, "login-password", "hunter2");
    click(&window, "add-login-button");

    type_into(&window, "rotate-length", "24");
    click(&window, "rotate-button");

    let status = window.get_status().to_string();
    assert!(
        status.contains("Generated one password and rotated item"),
        "status should confirm the rotation, got: {status}"
    );
    let selected_item = window.get_selected_item().to_string();
    assert!(
        selected_item.contains("Password history entries: 1"),
        "the rotated item should carry one password-history entry, got: {selected_item}"
    );
}

/// Real enroll-mnemonic widget flow: init a vault, type a mnemonic label
/// into the real input and click the real "Enroll mnemonic" button,
/// asserting the window's keyslot-summary property gains a mnemonic entry
/// and the status reports the enrollment.
#[test]
fn enroll_mnemonic_via_real_widgets_adds_keyslot() {
    let tmpdir = tempfile::tempdir().expect("temp dir for mnemonic test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, _state) = new_wired_shell();

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    type_into(&window, "mnemonic-label", "paper-backup");
    click(&window, "enroll-mnemonic-button");

    let status = window.get_status().to_string();
    assert!(
        status.contains("Mnemonic recovery slot") && status.contains("enrolled"),
        "status should confirm the mnemonic enrollment, got: {status}"
    );
    let keyslot_summary = window.get_keyslot_summary().to_string();
    assert!(
        keyslot_summary.contains("mnemonic") && keyslot_summary.contains("paper-backup"),
        "keyslot summary should list the enrolled mnemonic slot, got: {keyslot_summary}"
    );
    let selected_item = window.get_selected_item().to_string();
    assert!(
        selected_item.contains("New recovery phrase:"),
        "the selected-item pane should surface the recovery phrase once for the operator, got: {selected_item}"
    );
}

/// Real export-backup widget flow: init a vault, add a login, type a
/// backup output path into the real input and click the real "Export
/// backup" button, asserting the backup file was written and the
/// window's status reflects the export.
#[test]
fn export_backup_via_real_widgets_writes_backup_file() {
    let tmpdir = tempfile::tempdir().expect("temp dir for export-backup test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let backup_path = tmpdir.path().join("vault.backup.json");
    let (window, _state) = new_wired_shell();

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    type_into(&window, "login-title", "GitHub");
    type_into(&window, "login-user", "octocat");
    type_into(&window, "login-password", "hunter2");
    click(&window, "add-login-button");

    type_into(&window, "backup-path", backup_path.display().to_string());
    click(&window, "export-backup-button");

    assert!(
        backup_path.exists(),
        "clicking Export backup should write the backup file to the typed path"
    );
    let status = window.get_status().to_string();
    assert!(
        status.contains("Exported encrypted vault backup"),
        "status should confirm the export, got: {status}"
    );
}

/// P9.6: real "Lock vault" button click from an unlocked, populated screen
/// immediately scrubs every secret-bearing window property (vault items,
/// selected item, keyslot summary, generated passwords, recovery-secret
/// field text stays as typed in the widget itself — the underlying
/// `GuiState.vault_secret` copy is what gets zeroized — but the
/// vault-derived summaries must be gone) and reports the vault as locked.
#[test]
fn lock_vault_via_real_widgets_scrubs_secrets_from_unlocked_screen() {
    let tmpdir = tempfile::tempdir().expect("temp dir for lock-vault test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, state) = new_wired_shell();

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    type_into(&window, "login-title", "GitHub");
    type_into(&window, "login-user", "octocat");
    type_into(&window, "login-password", "hunter2");
    click(&window, "add-login-button");

    // Representative unlocked screen: a vault is unlocked with a decrypted
    // item summarized in the window, and the cached session handle is set.
    assert!(window.get_vault_items().to_string().contains("GitHub"));
    assert!(state.borrow().unlocked_vault.is_some());

    click(&window, "lock-vault-button");

    let status = window.get_status().to_string();
    assert!(
        status.to_lowercase().contains("lock"),
        "status should report the vault as locked, got: {status}"
    );
    assert!(
        !window.get_vault_items().to_string().contains("GitHub"),
        "vault-items property must not retain the decrypted item after lock, got: {}",
        window.get_vault_items()
    );
    let selected_item = window.get_selected_item().to_string();
    assert!(
        !selected_item.contains("GitHub") && !selected_item.contains("octocat"),
        "selected-item property must be scrubbed after lock, got: {selected_item}"
    );
    let state = state.borrow();
    assert!(
        state.unlocked_vault.is_none(),
        "the cached unlocked-vault handle must be dropped on lock"
    );
    assert!(
        state.vault_secret.is_empty(),
        "the in-memory master-password copy must be cleared on lock"
    );
}

/// P9.6: the `Control+L` keyboard accelerator (`PanicLockShortcut` in
/// paranoid.slint) drives the exact same lock path as the button, even
/// though the master-password `LineEdit` still holds simulated focus from
/// typing into it — proving the panic key is not swallowed by a
/// focused text field.
#[test]
fn ctrl_l_accelerator_locks_vault_while_a_text_field_has_focus() {
    let tmpdir = tempfile::tempdir().expect("temp dir for ctrl-l test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, state) = new_wired_shell();

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    type_into(&window, "login-title", "GitHub");
    type_into(&window, "login-user", "octocat");
    type_into(&window, "login-password", "hunter2");
    click(&window, "add-login-button");
    assert!(window.get_vault_items().to_string().contains("GitHub"));

    // Give the login-password field simulated keyboard focus, mirroring a
    // user mid-entry, then dispatch the raw Control+L key sequence at the
    // window level exactly as a real keyboard would.
    find_one(&window, "login-password").invoke_accessible_default_action();
    let slint_window = window.window();
    slint_window.dispatch_event(slint::platform::WindowEvent::KeyPressed {
        text: slint::platform::Key::Control.into(),
    });
    slint_window.dispatch_event(slint::platform::WindowEvent::KeyPressed { text: "l".into() });
    slint_window.dispatch_event(slint::platform::WindowEvent::KeyReleased { text: "l".into() });
    slint_window.dispatch_event(slint::platform::WindowEvent::KeyReleased {
        text: slint::platform::Key::Control.into(),
    });

    let status = window.get_status().to_string();
    assert!(
        status.to_lowercase().contains("lock"),
        "Ctrl+L should have locked the vault, got status: {status}"
    );
    assert!(
        !window.get_vault_items().to_string().contains("GitHub"),
        "Ctrl+L must scrub the decrypted item from the window, got: {}",
        window.get_vault_items()
    );
    assert!(
        state.borrow().unlocked_vault.is_none(),
        "Ctrl+L must drop the cached unlocked-vault handle"
    );
}
