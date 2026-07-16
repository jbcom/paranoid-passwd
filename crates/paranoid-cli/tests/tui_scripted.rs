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
