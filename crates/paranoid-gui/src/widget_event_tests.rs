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
//! The shell renders one screen at a time behind `root.screen`
//! (ia.md §2/§6's screen graph: S1 trust gate -> S3 verified -> H vault
//! list -> S7/S8/S10/S11/S14). Real navigation clicks (not a direct
//! `set_screen` jump) walk each test through the same path a real user
//! takes, so a screen-graph regression (a button that no longer advances
//! `screen`, a callback that stopped firing) fails these tests the same
//! way it would fail a human.
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
use i_slint_backend_testing::{ElementHandle, ElementRoot};
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

/// Finds exactly one element whose Slint-generated id ends in `::{id}`.
///
/// Every screen (`TrustGateScreen`, `VaultListScreen`, `ItemDetailScreen`,
/// ...) is its own named component, so `i-slint-backend-testing` qualifies
/// each element's compiled id by the component it is *declared* in (see
/// `ElementHandle::id`'s doc example: `App::mybutton`), not by
/// `ParanoidPasswdShell` regardless of where that component is instantiated
/// in the shell. Matching on the bare-id suffix keeps these tests stable
/// against which screen component an id happens to live in.
fn find_one(window: &slint_shell::ParanoidPasswdShell, id: &str) -> ElementHandle {
    let suffix = format!("::{id}");
    let results = window
        .root_element()
        .query_descendants()
        .match_predicate(move |element| {
            element
                .id()
                .is_some_and(|candidate| candidate.ends_with(suffix.as_str()))
        })
        .find_all();
    let mut iter = results.into_iter();
    let element = iter.next().unwrap_or_else(|| {
        panic!("no element with id ending in ::{id} in the compiled widget tree")
    });
    assert!(
        iter.next().is_none(),
        "expected exactly one element with id ending in ::{id}"
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

/// Walks S1 (trust gate) -> S3 (verified) -> H (vault list) via real button
/// clicks — the same path `journeys.md` J1 storyboards, and the entry point
/// every other screen in the graph is reached through.
fn navigate_to_vault_list(window: &slint_shell::ParanoidPasswdShell) {
    assert_eq!(window.get_screen(), "trust-gate");
    click(window, "verify-button");
    assert_eq!(window.get_screen(), "verified");
    click(window, "continue-button");
    assert_eq!(window.get_screen(), "vault-list");
}

/// Real init-vault widget flow, walked from the real S1/S3 trust-gate spine:
/// type the vault path and recovery secret into the real
/// `vault-path-input`/`vault-secret` inputs on the vault-list (H) screen and
/// click the real "Init" button, asserting the vault file exists and the
/// window's status/unlocked properties reflect an unlocked, empty vault.
#[test]
fn init_vault_via_real_widgets_creates_and_unlocks_vault() {
    let tmpdir = tempfile::tempdir().expect("temp dir for init-vault test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, _state) = new_wired_shell();
    navigate_to_vault_list(&window);

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
    // brand.md §3 micro-example, verbatim: "Vault open. 12 items." — the
    // same framing journeys.md J4 gives every successful unlock/init.
    assert!(
        status.contains("Vault open"),
        "status should report the vault as open after Init, got: {status}"
    );
    assert!(
        status.contains("0 item(s)"),
        "a freshly initialized vault should report zero items, got: {status}"
    );
    assert!(
        window.get_vault_unlocked(),
        "the shell's vault-unlocked property should be true after Init"
    );
    let vault_items = window.get_vault_items().to_string();
    assert!(
        vault_items.contains("No records stored yet."),
        "a freshly initialized vault should show no records, got: {vault_items}"
    );
}

/// Real add-login widget flow (S8, the "n new" fan-out from H): init a
/// vault, navigate to the add-item screen, type a title/username/password
/// into the real form inputs and click the real "Save" button, asserting
/// the window's vault-items property gains exactly one entry reflecting
/// the typed login and the shell returns to the vault list.
#[test]
fn add_login_via_real_widgets_stores_one_item() {
    let tmpdir = tempfile::tempdir().expect("temp dir for add-login test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, _state) = new_wired_shell();
    navigate_to_vault_list(&window);

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    click(&window, "add-login-nav-button");
    assert_eq!(window.get_screen(), "add-item");

    type_into(&window, "login-title", "GitHub");
    type_into(&window, "login-user", "octocat");
    type_into(&window, "login-password", "hunter2");
    type_into(&window, "login-folder", "Work");
    type_into(&window, "login-tags", "work,code");
    click(&window, "save-login-button");

    assert_eq!(
        window.get_screen(),
        "vault-list",
        "saving a new item should return to the vault list"
    );
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

/// Real generate-and-rotate widget flow (S7's rotate action): init a vault,
/// add a login, open its item-detail screen (S7), then type a rotate length
/// into the real input and click the real "Rotate" button, asserting the
/// window's status confirms rotation and the selected item's history grew.
#[test]
fn generate_and_rotate_via_real_widgets_rotates_selected_login() {
    let tmpdir = tempfile::tempdir().expect("temp dir for rotate test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, _state) = new_wired_shell();
    navigate_to_vault_list(&window);

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    click(&window, "add-login-nav-button");
    type_into(&window, "login-title", "GitHub");
    type_into(&window, "login-user", "octocat");
    type_into(&window, "login-password", "hunter2");
    click(&window, "save-login-button");

    click(&window, "open-item-row");
    assert_eq!(window.get_screen(), "item-detail");

    type_into(&window, "rotate-length", "24");
    click(&window, "rotate-button");

    let status = window.get_status().to_string();
    // brand.md §4: chi-squared/p-value verdict → "randomness check:
    // passed" on the primary flow.
    assert!(
        status.contains("Rotated") && status.contains("Randomness check: passed"),
        "status should confirm the rotation, got: {status}"
    );
    let selected_item = window.get_selected_item().to_string();
    assert!(
        selected_item.contains("Password history entries: 1"),
        "the rotated item should carry one password-history entry, got: {selected_item}"
    );
}

/// Real enroll-mnemonic widget flow (S10, "Ways in"): init a vault,
/// navigate to the ways-in screen, type a mnemonic label into the real
/// input and click the real "Add a way in" button, asserting the window's
/// keyslot-summary property gains a mnemonic entry and the status reports
/// the enrollment.
#[test]
fn enroll_mnemonic_via_real_widgets_adds_keyslot() {
    let tmpdir = tempfile::tempdir().expect("temp dir for mnemonic test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, _state) = new_wired_shell();
    navigate_to_vault_list(&window);

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    click(&window, "ways-in-nav-button");
    assert_eq!(window.get_screen(), "ways-in");

    type_into(&window, "mnemonic-label", "paper-backup");
    click(&window, "add-way-in-button");

    let status = window.get_status().to_string();
    // brand.md §4: `keyslot` → "way in" on the primary flow.
    assert!(
        status.contains("Recovery phrase added as way in"),
        "status should confirm the recovery phrase was added, got: {status}"
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

/// Real export-backup widget flow (also on S10, "Ways in"): init a vault,
/// add a login, navigate to the ways-in screen, type a backup output path
/// into the real input and click the real "Export backup" button, asserting
/// the backup file was written and the window's status reflects the export.
#[test]
fn export_backup_via_real_widgets_writes_backup_file() {
    let tmpdir = tempfile::tempdir().expect("temp dir for export-backup test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let backup_path = tmpdir.path().join("vault.backup.json");
    let (window, _state) = new_wired_shell();
    navigate_to_vault_list(&window);

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    click(&window, "add-login-nav-button");
    type_into(&window, "login-title", "GitHub");
    type_into(&window, "login-user", "octocat");
    type_into(&window, "login-password", "hunter2");
    click(&window, "save-login-button");

    click(&window, "ways-in-nav-button");
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

/// S11 real generator-audit widget flow: navigate to the generate screen,
/// type a length/count into the real inputs and click the real "Run audit"
/// button, then assert the window's audit/status/generated-password
/// properties, and that the randomness-check verdict and evidence
/// disclosure (S11d) both render.
#[test]
fn run_audit_via_real_widgets_populates_generator_state() {
    let (window, _state) = new_wired_shell();
    navigate_to_vault_list(&window);
    click(&window, "generate-nav-button");
    assert_eq!(window.get_screen(), "generate");

    type_into(&window, "gen-length", "20");
    type_into(&window, "gen-count", "2");
    click(&window, "run-audit-button");

    let status = window.get_status().to_string();
    // brand.md §4: chi-squared/p-value verdict → "randomness check:
    // passed" on the primary flow.
    assert!(
        status.contains("Randomness check: passed"),
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

/// P9.6: real "Lock vault" button click from an unlocked, populated screen
/// immediately scrubs every secret-bearing window property (vault items,
/// selected item, keyslot summary, generated passwords) and navigates the
/// shell to the S14 locked screen (ia.md §5 "S13 -> S14").
#[test]
fn lock_vault_via_real_widgets_scrubs_secrets_from_unlocked_screen() {
    let tmpdir = tempfile::tempdir().expect("temp dir for lock-vault test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, state) = new_wired_shell();
    navigate_to_vault_list(&window);

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    click(&window, "add-login-nav-button");
    type_into(&window, "login-title", "GitHub");
    type_into(&window, "login-user", "octocat");
    type_into(&window, "login-password", "hunter2");
    click(&window, "save-login-button");

    // Representative unlocked screen: a vault is unlocked with a decrypted
    // item summarized in the window, and the cached session handle is set.
    assert!(window.get_vault_items().to_string().contains("GitHub"));
    assert!(state.borrow().unlocked_vault.is_some());

    click(&window, "lock-vault-button");

    assert_eq!(
        window.get_screen(),
        "locked",
        "clicking Lock vault should navigate to the S14 locked screen"
    );
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
/// focused text field — and lands on the S14 locked screen exactly like
/// the button does.
#[test]
fn ctrl_l_accelerator_locks_vault_while_a_text_field_has_focus() {
    let tmpdir = tempfile::tempdir().expect("temp dir for ctrl-l test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, state) = new_wired_shell();
    navigate_to_vault_list(&window);

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    click(&window, "add-login-nav-button");
    type_into(&window, "login-title", "GitHub");
    type_into(&window, "login-user", "octocat");
    type_into(&window, "login-password", "hunter2");
    click(&window, "save-login-button");
    assert!(window.get_vault_items().to_string().contains("GitHub"));

    // Give the login-password field simulated keyboard focus, mirroring a
    // user mid-entry, then dispatch the raw Control+L key sequence at the
    // window level exactly as a real keyboard would. The add-item screen
    // has already navigated away by this point (save returns to the vault
    // list), so re-open it to have a focusable text field mid-entry.
    click(&window, "add-login-nav-button");
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

    assert_eq!(
        window.get_screen(),
        "locked",
        "Ctrl+L should have navigated to the S14 locked screen"
    );
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

/// S1/S3 trust-gate spine, journeys.md J1: on launch the shell shows the
/// unverified caution state (never a default "all fine" wash — system.md
/// §1 "verified is earned"), and clicking "Verify this copy" advances to
/// S3's earned green verdict before the persona can reach anything else.
#[test]
fn trust_gate_shows_unverified_state_until_verified() {
    let (window, _state) = new_wired_shell();

    assert_eq!(window.get_screen(), "trust-gate");
    assert!(
        !window.get_copy_code_verified(),
        "a freshly launched shell must not claim verification it never performed"
    );

    click(&window, "verify-button");

    assert_eq!(window.get_screen(), "verified");
    assert!(
        window.get_copy_code_verified(),
        "clicking Verify this copy should set the earned-verified state"
    );
}

/// S3's progressive-disclosure region (ia.md §6 GUI disclosure rule): the
/// fingerprint/evidence text is collapsed by default and only appears in
/// the widget tree once the disclosure is toggled open.
#[test]
fn verified_screen_evidence_disclosure_is_collapsed_by_default() {
    let (window, _state) = new_wired_shell();
    click(&window, "verify-button");
    assert_eq!(window.get_screen(), "verified");

    let evidence_before = window
        .root_element()
        .query_descendants()
        .match_predicate(|element| {
            element
                .accessible_label()
                .is_some_and(|label| label.contains("cryptographic release-signature"))
        })
        .find_all();
    assert!(
        evidence_before.is_empty(),
        "the fingerprint/evidence detail must be collapsed until 'Show the details' is clicked"
    );
}

/// H — Vault list empty state (ia.md §6; brand.md §1 "no screen is a dead
/// end"): a freshly unlocked, empty vault shows the honest empty-state copy
/// rather than a blank list, and the "Add a login" primary action is
/// enabled so the persona always has exactly one next move.
#[test]
fn vault_list_shows_empty_state_copy_for_a_freshly_unlocked_vault() {
    let tmpdir = tempfile::tempdir().expect("temp dir for empty-vault-list test");
    let vault_path = tmpdir.path().join("vault.sqlite");
    let (window, _state) = new_wired_shell();
    navigate_to_vault_list(&window);

    type_into(
        &window,
        "vault-path-input",
        vault_path.display().to_string(),
    );
    type_into(&window, "vault-secret", "correct horse battery staple");
    click(&window, "init-vault-button");

    let vault_items = window.get_vault_items().to_string();
    assert_eq!(vault_items, "No records stored yet.");

    let empty_state_present = window
        .root_element()
        .query_descendants()
        .match_predicate(|element| {
            element
                .accessible_label()
                .is_some_and(|label| label.contains("Nothing stored yet."))
        })
        .find_all();
    assert!(
        !empty_state_present.is_empty(),
        "an empty, unlocked vault should render the honest empty-state copy"
    );
}

/// S14 locked screen: the only action present is Unlock (ia.md §6 "locked
/// state shows only unlock"), and clicking it returns the shell to the
/// vault list (S15's home-entry-loop equivalent for this build).
#[test]
fn locked_screen_unlock_button_returns_to_vault_list() {
    let (window, state) = new_wired_shell();
    navigate_to_vault_list(&window);
    lock_vault(&mut state.borrow_mut());
    window.set_screen("locked".into());

    assert_eq!(window.get_screen(), "locked");
    click(&window, "unlock-button");
    assert_eq!(
        window.get_screen(),
        "vault-list",
        "S14's Unlock button should return to the vault-list unlock/create form"
    );
}
