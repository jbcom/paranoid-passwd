//! Integration tests for the deterministic scripted TUI driving surface
//! (`paranoid_cli::scripted`, `paranoid_cli::tui::run_scripted`,
//! `paranoid_cli::vault_tui::run_scripted`).
//!
//! These exercise the real `App` types (including, for the generator wizard,
//! its background worker thread) against an in-memory `TestBackend`, proving
//! the scripted mode required by `PARANOID_TUI_SCRIPT` can drive both TUI
//! applications end to end without a PTY. `tests/test_tui_e2e.py` remains the
//! terminal-emulation-accurate PTY layer; this is a second, hermetic path.

use paranoid_cli::scripted::{self, DEFAULT_COLS, DEFAULT_ROWS};
use paranoid_cli::vault_tui::{self, VaultTuiConfig};
use paranoid_cli::{tui, vault_cli};
use paranoid_vault::{SecretString, VaultAuth, VaultOpenOptions, init_vault};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tempfile::tempdir;

fn scripted_terminal() -> Terminal<TestBackend> {
    Terminal::new(TestBackend::new(DEFAULT_COLS, DEFAULT_ROWS)).expect("test backend terminal")
}

#[test]
fn scripted_generator_wizard_completes_end_to_end() {
    // Reach the Launch field the same way the in-crate reducer test
    // (`generator_key_driven_flow_reaches_results_and_entropy_tab`) does:
    // Tab past every configure field (the focus order clamps at the last
    // field, so over-tabbing is harmless), then Enter to launch the audit,
    // then wait for the worker thread to drain before asserting on the
    // rendered Results screen.
    let tab_count = 40;
    let mut script = "# generator wizard: tab to Launch, run audit, inspect results\n".to_string();
    for _ in 0..tab_count {
        script.push_str("<tab>\n");
    }
    script.push_str("<enter>\n<wait-idle>\n");
    // Results screen defaults to the Summary detail tab; switch to Entropy
    // (index 2) the same way the in-crate reducer test does.
    script.push_str("<tab>\n<tab>\n");

    let tokens = scripted::parse_script(&script).expect("parse script");
    let mut terminal = scripted_terminal();
    let final_frame = tui::run_scripted(&mut terminal, &tokens).expect("scripted run");

    assert!(
        final_frame.contains("Total entropy"),
        "expected the Results screen entropy panel in the final frame:\n{final_frame}"
    );
    assert!(
        final_frame.contains("Brute-force"),
        "expected the Results screen brute-force panel in the final frame:\n{final_frame}"
    );
}

#[test]
fn scripted_generator_wizard_rejects_unknown_token() {
    let error = scripted::parse_script("<not-a-real-token>").expect_err("should reject");
    assert!(error.to_string().contains("unknown token"));
}

#[test]
fn scripted_vault_init_and_add_login_flow_persists_item() {
    let tempdir = tempdir().expect("tempdir");
    let vault_path = tempdir.path().join("vault.sqlite");
    let master_password = "correct horse battery staple";
    init_vault(&vault_path, master_password).expect("init vault");

    // `PasswordEnv` unlock (the pattern used elsewhere for scripted/native
    // access) requires either the env var or a mocked keyring device
    // fallback; a directly-supplied password avoids needing either for this
    // deterministic flow.
    let open_options = VaultOpenOptions {
        path: vault_path.clone(),
        auth: VaultAuth::Password(SecretString::new(master_password.to_string())),
        mnemonic_phrase_env: None,
        mnemonic_phrase: None,
        mnemonic_slot: None,
        device_slot: None,
        use_device_auto: false,
    };
    let config = VaultTuiConfig {
        open_options,
        profile: paranoid_ops::OpsProfile::Default,
        audit_jsonl: None,
        require_audit_sink: false,
    };

    // 'a' opens Add Login (starting on the Vault screen, since password auth
    // unlocks synchronously during App construction). Field order is Title,
    // Username, Password, Url, Notes, Folder, Tags, Save; focus clamps at
    // Save so extra Tabs are harmless.
    let script = "\
a
G
i
t
H
u
b
<tab>
o
c
t
o
c
a
t
<tab>
h
u
n
t
e
r
2
<tab>
<tab>
<tab>
<tab>
<tab>
<enter>
<wait-idle>
";

    let tokens = scripted::parse_script(script).expect("parse script");
    let mut terminal = scripted_terminal();
    let final_frame =
        vault_tui::run_scripted(&mut terminal, config, &tokens).expect("scripted run");

    assert!(
        final_frame.contains("GitHub") || final_frame.contains("octocat"),
        "expected the newly added login to be visible in the final frame:\n{final_frame}"
    );

    // Confirm the item was actually persisted to the vault, not just
    // reflected transiently in the in-memory `App` state.
    let unlocked = paranoid_vault::unlock_vault(&vault_path, master_password).expect("unlock");
    let items = unlocked.list_items().expect("list items");
    assert_eq!(items.len(), 1);
    let item = unlocked.get_item(&items[0].id).expect("get item");
    let paranoid_vault::VaultItemPayload::Login(login) = item.payload else {
        panic!("expected a login item, got {:?}", item.payload);
    };
    assert_eq!(login.title, "GitHub");
    assert_eq!(login.username, "octocat");
    assert_eq!(login.password, "hunter2");

    // vault_cli::run stays reachable through the library surface too (used
    // by main.rs); this is a compile-time reachability check, not a
    // behavioral one, since driving the real CLI arg parser is already
    // covered by tests/test_vault_cli.sh.
    let _ = vault_cli::run;
}

/// P9.6: driven through the real scripted event loop (not `App::handle_key`
/// directly, as the in-crate unit tests already cover), `<ctrl-l>` from an
/// unlocked screen with a login on screen immediately renders the
/// unlock-blocked screen and the previously-visible secret no longer appears
/// in any rendered frame.
#[test]
fn scripted_panic_lock_hotkey_clears_screen_from_unlocked_vault() {
    let tempdir = tempdir().expect("tempdir");
    let vault_path = tempdir.path().join("vault.sqlite");
    let master_password = "correct horse battery staple";
    init_vault(&vault_path, master_password).expect("init vault");

    let open_options = VaultOpenOptions {
        path: vault_path.clone(),
        auth: VaultAuth::Password(SecretString::new(master_password.to_string())),
        mnemonic_phrase_env: None,
        mnemonic_phrase: None,
        mnemonic_slot: None,
        device_slot: None,
        use_device_auto: false,
    };
    let config = VaultTuiConfig {
        open_options,
        profile: paranoid_ops::OpsProfile::Default,
        audit_jsonl: None,
        require_audit_sink: false,
    };

    // Add a login (same script as the flow above) so there is decrypted
    // secret material on screen, then fire the panic-lock hotkey.
    let script = "\
a
G
i
t
H
u
b
<tab>
o
c
t
o
c
a
t
<tab>
h
u
n
t
e
r
2
<tab>
<tab>
<tab>
<tab>
<tab>
<enter>
<wait-idle>
<ctrl-l>
";

    let tokens = scripted::parse_script(script).expect("parse script");
    let mut terminal = scripted_terminal();
    let final_frame =
        vault_tui::run_scripted(&mut terminal, config, &tokens).expect("scripted run");

    assert!(
        !final_frame.contains("hunter2"),
        "panic-lock must scrub the plaintext password from the rendered frame:\n{final_frame}"
    );
    assert!(
        final_frame.to_lowercase().contains("lock"),
        "expected the panic-lock status or unlock-blocked screen in the final frame:\n{final_frame}"
    );

    // The item must still be safely persisted on disk; panic-lock scrubs
    // in-memory state, not the vault itself.
    let unlocked = paranoid_vault::unlock_vault(&vault_path, master_password).expect("unlock");
    let items = unlocked.list_items().expect("list items");
    assert_eq!(items.len(), 1);
}

fn missing_vault_config(vault_path: &std::path::Path) -> VaultTuiConfig {
    // Pointing at a path that does not exist yet is what triggers the
    // first-run environment-approval screen (see `vault_tui::App::refresh`).
    // The auth mode here is irrelevant until the approval screen is resolved
    // and the init form is reached, since `App::with_config` never attempts
    // an unlock against a missing vault.
    let open_options = VaultOpenOptions {
        path: vault_path.to_path_buf(),
        auth: VaultAuth::PasswordEnv("PARANOID_TUI_SCRIPTED_MISSING".to_string()),
        mnemonic_phrase_env: None,
        mnemonic_phrase: None,
        mnemonic_slot: None,
        device_slot: None,
        use_device_auto: false,
    };
    VaultTuiConfig {
        open_options,
        profile: paranoid_ops::OpsProfile::Default,
        audit_jsonl: None,
        require_audit_sink: false,
    }
}

fn type_literal(script: &mut String, text: &str) {
    for ch in text.chars() {
        script.push(ch);
        script.push('\n');
    }
}

#[test]
fn scripted_environment_approval_accept_flows_into_vault_init_and_add_login() {
    let tempdir = tempdir().expect("tempdir");
    let vault_path = tempdir.path().join("vault.sqlite");
    // The scripted token grammar sends one literal character per line and
    // trims each line before matching, so a space-bearing secret cannot
    // round-trip through the keystream (see `scripted::parse_script`).
    // `handle_unlock_blocked_key` also treats `p`/`m`/`b`/`c` as unconditional
    // unlock-mode-switch shortcuts regardless of the focused field, so those
    // letters cannot appear in a secret typed through this scripted path
    // either (typing one would silently switch away from Password mode
    // mid-entry). Use a secret avoiding both constraints for the scripted
    // path specifically.
    let master_password = "dragonsteelfortress9";
    let config = missing_vault_config(&vault_path);

    // <enter> on the environment-approval screen accepts the default
    // (Accept) choice, landing on the reused unlock/init form pre-set to
    // Password mode. Typing the recovery secret there and submitting
    // initializes the vault (there is no vault yet at this path). From the
    // resulting Vault screen, 'a' opens Add Login the same way the
    // already-initialized-vault test above does.
    let mut script =
        String::from("# environment approval: accept -> init -> add login\n<enter>\n<tab>\n");
    type_literal(&mut script, master_password);
    script.push_str("<tab>\n<enter>\n");
    script.push_str("a\n");
    type_literal(&mut script, "GitHub");
    script.push_str("<tab>\n");
    type_literal(&mut script, "octocat");
    script.push_str("<tab>\n");
    type_literal(&mut script, "hunter2");
    script.push_str("<tab>\n<tab>\n<tab>\n<tab>\n<tab>\n<enter>\n<wait-idle>\n");

    let tokens = scripted::parse_script(&script).expect("parse script");
    let mut terminal = scripted_terminal();
    let final_frame =
        vault_tui::run_scripted(&mut terminal, config, &tokens).expect("scripted run");

    assert!(
        final_frame.contains("GitHub") || final_frame.contains("octocat"),
        "expected the newly added login to be visible in the final frame:\n{final_frame}"
    );

    assert!(
        vault_path.exists(),
        "vault should have been initialized on disk"
    );
    let unlocked = paranoid_vault::unlock_vault(&vault_path, master_password).expect("unlock");
    let items = unlocked.list_items().expect("list items");
    assert_eq!(items.len(), 1);
    let item = unlocked.get_item(&items[0].id).expect("get item");
    let paranoid_vault::VaultItemPayload::Login(login) = item.payload else {
        panic!("expected a login item, got {:?}", item.payload);
    };
    assert_eq!(login.title, "GitHub");
    assert_eq!(login.username, "octocat");
    assert_eq!(login.password, "hunter2");
}

#[test]
fn scripted_environment_approval_adjust_flows_into_manual_vault_init() {
    let tempdir = tempdir().expect("tempdir");
    let vault_path = tempdir.path().join("vault.sqlite");
    let master_password = "dragonsteelfortress9";
    let config = missing_vault_config(&vault_path);

    // <down> moves focus from Accept to Adjust before <enter> selects it,
    // reaching the same reused unlock/init form but without the
    // accept-path's automatic device-bound keyslot suggestion applied. The
    // following <tab> moves focus off Mode onto the Primary (password)
    // field before the secret is typed, matching the accept-path script.
    let mut script =
        String::from("# environment approval: adjust -> manual init\n<down>\n<enter>\n<tab>\n");
    type_literal(&mut script, master_password);
    script.push_str("<tab>\n<enter>\n");

    let tokens = scripted::parse_script(&script).expect("parse script");
    let mut terminal = scripted_terminal();
    let final_frame =
        vault_tui::run_scripted(&mut terminal, config, &tokens).expect("scripted run");

    assert!(
        final_frame.contains("Vault") && !final_frame.contains("Unlock blocked"),
        "expected the vault screen after manual init in the final frame:\n{final_frame}"
    );

    assert!(
        vault_path.exists(),
        "vault should have been initialized on disk"
    );
    let header = paranoid_vault::read_vault_header(&vault_path).expect("read header");
    assert!(
        header
            .keyslots
            .iter()
            .all(|slot| slot.kind != paranoid_vault::VaultKeyslotKind::DeviceBound),
        "manual adjust path must not auto-enroll a device-bound keyslot"
    );
}
