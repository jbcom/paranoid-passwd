//! Contextual footer + `?` help overlay — ia.md §5 and §1 rule 3.
//!
//! Replaces the single 40-key `Controls:` wall (brand.md §3e) with a footer
//! that shows only the 3-5 keys valid for the *currently focused pane*, plus
//! `? all keys` as the door to the full keymap (the L2 layer, ia.md §5 "S12
//! The `?` overlay"). The overlay is a transient render-time layer, not a new
//! `Screen` variant, so the fixed skeleton (ia.md §1 rule 4) is unchanged
//! beneath it and every existing `Screen::` match stays exhaustive.

use crate::vault_tui::{App, Screen};

/// The contextual footer for the app's current screen/mode — ia.md §5,
/// verbatim per screen where the doc specifies exact text.
pub(crate) fn contextual_footer(app: &App) -> &'static str {
    match app.screen {
        Screen::TrustGate | Screen::Verified => "↑↓ move  ⏎ select  ? help  q quit",
        Screen::Verifying => "⎋ back  (verifying…)",
        Screen::EnvironmentApproval => "↑↓ move  ⏎ create vault  ? help  ⎋ back",
        Screen::Vault => {
            if app.search_mode {
                "type to filter  ⏎/⎋ done  Ctrl-u clear"
            } else {
                "↑↓ move  ⏎ open  n new  / find  ? all keys  q quit"
            }
        }
        // S7 (ia.md §5), verbatim: differs from the list footer — the
        // footer re-renders on focus change (rule 3). Destructive actions
        // (delete) are deliberately absent here; they live behind `?`.
        Screen::ItemDetail => "⏎ copy  r reveal  e edit  ? all keys  ⎋ back",
        Screen::Keyslots => "↑↓ move  k mechanics  x remove  ? all keys  ⎋ back",
        // ia.md §5 S14 vs S15: a just-locked screen (panic-lock or idle
        // auto-lock) shows the minimal footer — "in a locked state the only
        // valid acts are unlock or quit," no `?` recovery-paths door. Any
        // interaction reverts to the ordinary S15 footer
        // (`App::handle_unlock_blocked_key`).
        Screen::UnlockBlocked if app.just_locked => "⏎ unlock  q quit",
        Screen::UnlockBlocked => "⏎ unlock  ? other ways in  ⎋ back",
        // Text-entry screens never bind `?` in the footer or as a key: a
        // literal '?' must remain typeable into any field (a URL, a note, a
        // tag). The full keymap for these screens is reachable via `Esc`
        // back to a browsing pane instead.
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
        | Screen::GenerateStore => "type to fill  Tab move  ⏎ save  ⎋ cancel",
        Screen::ExportBackup
        | Screen::ExportTransfer
        | Screen::ImportBackup
        | Screen::ImportTransfer => "type path  Tab move  ⏎ save  ⎋ cancel",
        Screen::MnemonicReveal => "c copy  ⏎/⎋ back  q quit",
        Screen::DeleteConfirm => "type the name  ⏎ confirm  ⎋ cancel",
        Screen::RemoveWayInConfirm => "type the way in's name  ⏎ confirm  ⎋ cancel",
    }
}

/// `true` for screens where `?` is a safe, non-colliding overlay trigger —
/// i.e. every screen that is NOT free-text entry (ia.md §5's contextual
/// footer only offers `? all keys` where a literal `?` cannot also be
/// meaningful user input).
pub(crate) fn help_key_active(screen: Screen) -> bool {
    matches!(
        screen,
        Screen::TrustGate
            | Screen::Verified
            | Screen::EnvironmentApproval
            | Screen::Vault
            | Screen::ItemDetail
            | Screen::Keyslots
            | Screen::UnlockBlocked
    )
}

/// The context-scoped heading for the `?` overlay (ia.md §5 "S12": `Keys ·
/// Vault list` / `Keys · Item` / `Keys · Ways in`, etc — never a static
/// global wall; it names the pane it was opened from).
pub(crate) fn overlay_heading(app: &App) -> &'static str {
    match app.screen {
        Screen::TrustGate | Screen::Verifying | Screen::Verified => "Keys · Trust gate",
        Screen::EnvironmentApproval => "Keys · Create vault",
        Screen::Vault => "Keys · Vault list",
        Screen::ItemDetail => "Keys · Item",
        Screen::Keyslots => "Keys · Ways in",
        Screen::UnlockBlocked => "Keys · Unlock",
        _ => "Keys · This screen",
    }
}

/// The full keymap body for the `?` overlay, scoped to the screen it was
/// opened from. Every capability that used to live in the flat `Controls:`
/// wall is redistributed here — nothing removed (ia.md §5 S12, brand.md §3e).
pub(crate) fn overlay_lines(app: &App) -> Vec<&'static str> {
    match app.screen {
        Screen::Vault => vec![
            "Move & open    ↑↓ move    ⏎ open      / find",
            "Add            a login    n note      v card    i identity",
            "Item           e edit     c copy      d delete (typed confirm)",
            "Vault          w ways in  E approvals",
            "Backup         x export   u import    t transfer  p receive",
            "Generate       g generate one and store it",
            "System         r refresh  q quit",
        ],
        Screen::ItemDetail => vec![
            "Use            ⏎ copy     r reveal / mask   e edit",
            "Item           d delete (typed confirm)",
            "System         ⎋ back  q quit",
        ],
        Screen::Keyslots => vec![
            "Add a way in   m recovery phrase   b this device   c trusted contact",
            "Evidence       k show the mechanics for the selected way in",
            "Manage         l relabel  o rotate phrase  p rotate recovery",
            "Certificate    w replace the held key",
            "Device         r rebind to this device's secure hardware",
            "Remove         x remove (typed confirm)",
            "System         ⎋ back  q quit",
        ],
        Screen::UnlockBlocked => vec![
            "Ways in        p passphrase  m recovery phrase  b this device  c trusted contact",
            "Move           ↑↓ / Tab move   Left/Right change mode",
            "Submit         ⏎ unlock   r retry current way in",
            "System         q quit",
        ],
        Screen::TrustGate | Screen::Verifying | Screen::Verified => vec![
            "Trust          ⏎ verify this copy   s skip for now",
            "Evidence       d show the fingerprint",
            "System         ⎋ back  q quit",
        ],
        _ => vec!["No additional keys beyond the footer for this screen."],
    }
}
