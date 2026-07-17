use crate::theme::{self, ICON_ACTION, ICON_CAUTION, ICON_LOCKED, ICON_VERIFIED};
use crate::vault_tui::*;
use paranoid_ops::CapabilityProbeStatus;
use paranoid_vault::{
    VaultBackupSummary, VaultItem, VaultItemKind, VaultItemPayload, VaultTransferSummary,
};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

pub(crate) fn render(frame: &mut Frame<'_>, app: &App) {
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
        header_state_token(app),
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

    // Single-purpose first-run screens (ia.md §1 "the two panes may merge
    // into one centered column, but the title/status/footer rows never
    // move") render one full-width column instead of the list/detail split
    // — there is no list to browse before trust is established.
    if matches!(
        app.screen,
        Screen::TrustGate | Screen::Verifying | Screen::Verified | Screen::ItemDetail
    ) {
        frame.render_widget(right_panel(app), chunks[2]);
    } else {
        // ia.md §1 rule 4: fixed two-pane skeleton (primary + detail) — no
        // third panel. P8.V.9 removed the "Access" panel (raw vault path +
        // unlock method) that used to sit above the primary pane; the
        // primary pane now owns the full left column on every list-based
        // screen (Vault, Keyslots).
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(chunks[2]);

        frame.render_widget(item_list(app), body[0]);
        frame.render_widget(right_panel(app), body[1]);
    }

    frame.render_widget(
        Paragraph::new(footer_text(app))
            .style(Style::default().fg(TEXT).bg(BG))
            .wrap(Wrap { trim: false }),
        chunks[3],
    );

    // S12 `?` overlay (ia.md §5): a transient layer drawn last, over the
    // fixed skeleton — the skeleton geometry underneath is unchanged.
    if app.help_overlay_open {
        render_help_overlay(frame, area, app);
    }
}

pub(crate) fn render_help_overlay(frame: &mut Frame<'_>, area: Rect, app: &App) {
    use ratatui::widgets::Clear;
    let popup = centered_rect(70, 60, area);
    frame.render_widget(Clear, popup);
    let mut lines: Vec<Line<'static>> = footer::overlay_lines(app)
        .into_iter()
        .map(Line::raw)
        .collect();
    lines.push(Line::raw(""));
    lines.push(Line::styled("⎋ close", theme::muted()));
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(footer::overlay_heading(app))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(BLUE))
                    .style(Style::default().bg(PANEL).fg(TEXT)),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

/// A centered `Rect` covering `percent_x`% width and `percent_y`% height of
/// `area` — used to place the `?` overlay as a floating panel over the fixed
/// skeleton rather than replacing it.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

pub(crate) fn render_header(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    subtitle: &str,
    state_token: Option<(&'static str, Color)>,
) {
    let title_line = match state_token {
        // ia.md §1: "title region... state token: ✓ ! ⊘" — the fixed
        // skeleton's single global state indicator, right-aligned on the
        // title row. system.md §1.1 "the test": the glyph, not just a
        // color, is what survives a monochrome/no-color terminal.
        Some((glyph, color)) => Line::from(vec![
            Span::styled(
                format!("paranoid-passwd · {title}  "),
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                glyph,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
        ]),
        None => Line::styled(
            format!("paranoid-passwd · {title}"),
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        ),
    };
    frame.render_widget(
        Paragraph::new(Text::from(vec![
            title_line,
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

/// The single global state token ia.md §1 requires in the title region:
/// `⊘` (locked, `text.muted` per theme.rs — deliberately not danger red,
/// since locking is the safe state) for `UnlockBlocked` (S14/S15); no token
/// on every other screen (trust-gate/verified already carry their own `!`/
/// `✓` in the body per ia.md §5 S1-S3, which are single-purpose screens
/// where the body-level glyph IS the title-region token).
pub(crate) fn header_state_token(app: &App) -> Option<(&'static str, Color)> {
    match app.screen {
        Screen::UnlockBlocked => Some((ICON_LOCKED, theme::TEXT_MUTED)),
        _ => None,
    }
}

pub(crate) fn header_title(screen: Screen) -> &'static str {
    match screen {
        Screen::TrustGate => "Verify this copy",
        Screen::Verifying => "Verifying…",
        Screen::Verified => "Verified",
        Screen::EnvironmentApproval => "Create vault",
        Screen::Vault => "Vault",
        Screen::ItemDetail => "Item",
        Screen::Keyslots => "Ways in",
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
        Screen::RemoveWayInConfirm => "Remove a way in",
    }
}

pub(crate) fn header_subtitle(screen: Screen) -> &'static str {
    match screen {
        Screen::TrustGate => {
            "Before you trust this program with anything, confirm it is the genuine, unmodified release."
        }
        Screen::Verifying => "Watch the check without being trapped — Esc returns any time.",
        Screen::Verified => {
            "The self-check finished. Its fingerprint stays reachable one level down."
        }
        Screen::EnvironmentApproval => {
            "Make the container and the way to open it. Ways in and hardware protection come later."
        }
        Screen::Vault => "Native vault list/detail view with the same builder-owned trust model.",
        Screen::ItemDetail => "One item. Masked by default; use it safely.",
        Screen::Keyslots => {
            "The keys and phrases that can open this vault. Add a recovery phrase, bind a device, or remove a way in you no longer trust."
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
        Screen::DeleteConfirm => "This deletes the item for good. Type its name to confirm.",
        Screen::RemoveWayInConfirm => {
            "This way in will no longer open the vault. Type its name to confirm."
        }
    }
}

pub(crate) fn footer_text(app: &App) -> &'static str {
    footer::contextual_footer(app)
}

pub(crate) fn item_list(app: &App) -> List<'static> {
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

pub(crate) fn keyslot_list(app: &App) -> List<'static> {
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
            "No ways in available yet beyond the required recovery phrase.",
            Style::default().fg(AMBER),
        ))],
    };

    List::new(items).block(
        Block::default()
            .title("Ways in")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(GREEN))
            .style(Style::default().bg(PANEL).fg(TEXT)),
    )
}

pub(crate) fn right_panel(app: &App) -> Paragraph<'static> {
    match app.screen {
        Screen::TrustGate => trust_gate_panel(app),
        Screen::Verifying => verifying_panel(app),
        Screen::Verified => verified_panel(app),
        Screen::EnvironmentApproval => environment_approval_panel(app),
        Screen::Vault => detail_panel(app),
        Screen::ItemDetail => item_detail_panel(app),
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
        Screen::RemoveWayInConfirm => remove_way_in_confirm_panel(app),
    }
}

pub(crate) fn trust_gate_panel(app: &App) -> Paragraph<'static> {
    let already_checked = matches!(app.trust_state, TrustState::Checked);
    let mut lines = vec![Line::raw(
        "Before you trust this program with anything, confirm it is the genuine, unmodified release.",
    )];
    lines.push(Line::raw(""));
    if already_checked {
        lines.push(Line::styled(
            format!("{ICON_VERIFIED} This copy was checked on this machine."),
            theme::verified(),
        ));
    } else {
        lines.push(Line::styled(
            format!("{ICON_CAUTION} This copy has not been checked on this machine yet."),
            theme::caution(),
        ));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!("{ICON_ACTION} Verify this copy"),
        theme::accent_action(),
    ));
    lines.push(Line::raw("  Skip for now"));

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Trust")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

pub(crate) fn verifying_panel(_app: &App) -> Paragraph<'static> {
    Paragraph::new(Text::from(vec![
        Line::raw("Checking this copy's build identity…"),
        Line::raw(""),
        Line::styled(
            "Esc returns any time — nothing here blocks you.",
            theme::muted(),
        ),
    ]))
    .block(
        Block::default()
            .title("Verifying")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BLUE))
            .style(Style::default().bg(PANEL).fg(TEXT)),
    )
    .wrap(Wrap { trim: false })
}

pub(crate) fn verified_panel(app: &App) -> Paragraph<'static> {
    let mut lines = vec![Line::styled(
        format!("{ICON_VERIFIED} This build's identity is confirmed."),
        theme::verified(),
    )];
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "Cryptographic release verification against a signed publisher record is not available in this build yet — that is a real limit, stated plainly rather than papered over.",
        theme::caution(),
    ));
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!("{ICON_ACTION} Continue"),
        theme::accent_action(),
    ));
    let _ = app;
    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Verified")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GREEN))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

pub(crate) fn remove_way_in_confirm_panel(app: &App) -> Paragraph<'static> {
    let lines = vec![
        Line::styled(
            format!(
                "Removing \"{}\" means it can no longer open this vault.",
                app.confirm_target_name
            ),
            theme::caution(),
        ),
        Line::raw(""),
        Line::raw(format!("Type \"{}\" to confirm:", app.confirm_target_name)),
        Line::styled(
            format!("{}_", app.confirm_input),
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        ),
    ];
    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Remove a way in")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(RED))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

pub(crate) fn capability_status_label(status: CapabilityProbeStatus) -> &'static str {
    match status {
        CapabilityProbeStatus::Available => "available",
        CapabilityProbeStatus::Unavailable => "unavailable",
        CapabilityProbeStatus::NotChecked => "not checked",
    }
}

pub(crate) fn capability_status_color(status: CapabilityProbeStatus) -> Color {
    match status {
        CapabilityProbeStatus::Available => GREEN,
        CapabilityProbeStatus::Unavailable => RED,
        CapabilityProbeStatus::NotChecked => AMBER,
    }
}

pub(crate) fn environment_approval_panel(app: &App) -> Paragraph<'static> {
    // P8.V.9: the raw vault filesystem path and unlock method used to sit on
    // every Home/steady-state screen as a permanent third "Access" panel,
    // violating ia.md §1's fixed two-pane (primary + detail) skeleton. Both
    // facts are real and occasionally useful, so they are relocated here —
    // the one screen ia.md already treats as the disclosure surface for
    // environment/posture detail — instead of being deleted outright.
    let mut lines = vec![
        Line::raw(format!("Vault path: {}", app.options.path.display())),
        Line::raw(format!("Unlock: {}", app.options.unlock_description())),
    ];

    let Some(report) = app.capability_report.as_ref() else {
        lines.push(Line::raw("Collecting capability evidence..."));
        return Paragraph::new(Text::from(lines)).block(
            Block::default()
                .title("Environment Approval")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        );
    };

    lines.push(Line::raw(format!(
        "Platform: {} / {}",
        report.operating_system, report.architecture
    )));
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "Capabilities",
        Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
    ));

    lines.push(Line::styled(
        format!(
            "OS keychain ({}): {}",
            report.os_keychain.backend,
            capability_status_label(report.os_keychain.status)
        ),
        Style::default().fg(capability_status_color(report.os_keychain.status)),
    ));
    if let Some(detail) = &report.os_keychain.error_detail {
        lines.push(Line::raw(format!("  {detail}")));
    }

    lines.push(Line::styled(
        format!(
            "Clipboard: {}",
            capability_status_label(report.clipboard.status)
        ),
        Style::default().fg(capability_status_color(report.clipboard.status)),
    ));
    if let Some(detail) = &report.clipboard.error_detail {
        lines.push(Line::raw(format!("  {detail}")));
    }

    let display_line = match &report.display_server.session_type {
        Some(session_type) => format!(
            "Display server: {} ({session_type})",
            report.display_server.kind.as_str()
        ),
        None => format!("Display server: {}", report.display_server.kind.as_str()),
    };
    lines.push(Line::styled(display_line, Style::default().fg(TEXT)));

    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "Hardware protection",
        Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
    ));
    if report.seal_providers.is_empty() {
        // brand.md §3(b) verbatim: names the actual guarantee (can my vault
        // be opened on a machine that isn't mine) rather than "seal
        // provider" engineer vocabulary.
        lines.push(Line::raw(
            "This vault is not yet tied to this device's secure hardware. Once it is set up, an attacker who copies the vault file to another machine cannot open it there.",
        ));
    } else {
        for provider in &report.seal_providers {
            lines.push(Line::raw(format!(
                "{} ({}): {:?}",
                provider.provider_id,
                provider.kind.as_str(),
                provider.status
            )));
        }
    }

    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "Suggested initial configuration",
        Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
    ));
    lines.push(Line::raw(
        "Password recovery keyslot (required; the only vault-init path).",
    ));
    if report.os_keychain.status.is_available() {
        lines.push(Line::raw(
            "+ Device-bound keyslot via the OS keychain, enrolled automatically on accept.",
        ));
    } else {
        lines.push(Line::raw(
            "Device-bound keyslot not suggested: OS keychain is unavailable.",
        ));
    }

    lines.push(Line::raw(""));
    for choice in EnvironmentApprovalChoice::ALL {
        lines.push(form_action_line(
            app.environment_approval.choice == choice,
            choice.label(),
        ));
    }

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title("Environment Approval")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

pub(crate) fn unlock_blocked_panel(app: &App) -> Paragraph<'static> {
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
                &masked_value(form.password.as_str()),
            ));
        }
        UnlockMode::Mnemonic => {
            lines.push(form_line(
                matches!(form.selected_field(), UnlockField::Primary),
                "Recovery phrase",
                &masked_value(form.mnemonic_phrase.as_str()),
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
                &masked_value(form.key_passphrase.as_str()),
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

/// H's detail pane (ia.md §5 "detail pane: empty until sel."). This is a
/// preview only — it never shows a secret in cleartext and never dumps
/// internal fields (P8.V.1, P8.V.3). Opening the item (`⏎`) is the only way
/// to reach the full S7 `item_detail_panel`, which itself still masks by
/// default (rule 2, "progressive disclosure of evidence").
pub(crate) fn detail_panel(app: &App) -> Paragraph<'static> {
    let lines = match app.screen {
        Screen::UnlockBlocked => unreachable!("unlock blocked uses a dedicated panel"),
        Screen::Vault => match &app.detail {
            Some(item) => {
                let (kind_label, subtitle) = match &item.payload {
                    VaultItemPayload::Login(login) => ("Login", login.username.clone()),
                    VaultItemPayload::SecureNote(_) => ("Secure note", String::new()),
                    VaultItemPayload::Card(card) => {
                        ("Card", format!("{} ••••", card.cardholder_name))
                    }
                    VaultItemPayload::Identity(identity) => {
                        ("Identity", identity.full_name.clone())
                    }
                };
                let title = match &item.payload {
                    VaultItemPayload::Login(login) => login.title.clone(),
                    VaultItemPayload::SecureNote(note) => note.title.clone(),
                    VaultItemPayload::Card(card) => card.title.clone(),
                    VaultItemPayload::Identity(identity) => identity.title.clone(),
                };
                vec![
                    Line::styled(
                        title,
                        Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
                    ),
                    Line::raw(kind_label),
                    Line::raw(subtitle),
                    Line::raw(""),
                    Line::raw("⏎ open"),
                ]
            }
            None => vec![
                Line::styled(
                    "Vault detail",
                    Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw("No item is selected yet."),
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

/// S7 (ia.md §5) — one selected item, safe to use. Masked by default
/// (P8.V.1): a password/note/card-number/etc is rendered as `masked_value`
/// (the same `•`-per-character mask the unlock/export secret fields already
/// use) unless `app.secret_revealed` is `true`, toggled only by the explicit
/// `r reveal` action and re-masked on every re-entry (ia.md §5, journeys.md
/// invariant 1 — no coercion/shoulder-surfer cleartext-by-default leak).
///
/// No raw internal fields (`id:`, `updated_at_epoch:`, `duplicate passwords
/// elsewhere:`, `password history entries:`) are shown on this primary
/// surface at all (P8.V.3) — this is the "box of data with no answer to
/// what do I do next" antipattern journeys.md names as the defect PUX exists
/// to fix. There is currently no drill-down leaf for these counts; they are
/// omitted rather than fabricated a home that doesn't exist yet in ia.md.
pub(crate) fn item_detail_panel(app: &App) -> Paragraph<'static> {
    let Some(item) = &app.detail else {
        return Paragraph::new(Text::from(vec![
            Line::styled(
                "Item",
                Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw("No item is selected."),
        ]))
        .block(
            Block::default()
                .title("Detail")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false });
    };

    let reveal = app.secret_revealed;
    let mask_or = |secret: &str| -> String {
        if reveal {
            secret.to_string()
        } else {
            masked_value(secret)
        }
    };

    let mut lines = Vec::new();
    let title = match &item.payload {
        VaultItemPayload::Login(login) => login.title.clone(),
        VaultItemPayload::SecureNote(note) => note.title.clone(),
        VaultItemPayload::Card(card) => card.title.clone(),
        VaultItemPayload::Identity(identity) => identity.title.clone(),
    };
    lines.push(Line::styled(
        title,
        Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
    ));
    lines.push(Line::raw(""));

    match &item.payload {
        VaultItemPayload::Login(login) => {
            lines.push(Line::raw(format!("User    {}", login.username)));
            lines.push(Line::raw(format!(
                "Pass    {}",
                mask_or(login.password.as_str())
            )));
            if let Some(url) = login.url.as_deref().filter(|value| !value.is_empty()) {
                lines.push(Line::raw(format!("URL     {url}")));
            }
        }
        VaultItemPayload::SecureNote(note) => {
            lines.push(Line::raw(format!(
                "Note    {}",
                mask_or(note.content.as_str())
            )));
        }
        VaultItemPayload::Card(card) => {
            lines.push(Line::raw(format!("Holder  {}", card.cardholder_name)));
            lines.push(Line::raw(format!(
                "Number  {}",
                mask_or(card.number.as_str())
            )));
            lines.push(Line::raw(format!(
                "Expiry  {}/{}",
                card.expiry_month, card.expiry_year
            )));
            lines.push(Line::raw(format!(
                "CVV     {}",
                mask_or(card.security_code.as_str())
            )));
        }
        VaultItemPayload::Identity(identity) => {
            lines.push(Line::raw(format!("Name    {}", identity.full_name)));
            if let Some(email) = identity.email.as_deref().filter(|value| !value.is_empty()) {
                lines.push(Line::raw(format!("Email   {email}")));
            }
            if let Some(phone) = identity.phone.as_deref().filter(|value| !value.is_empty()) {
                lines.push(Line::raw(format!("Phone   {phone}")));
            }
        }
    }

    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "▸ Copy password",
        Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
    ));
    lines.push(Line::raw(if reveal { "Mask" } else { "Reveal" }));
    lines.push(Line::raw("Edit"));

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title(item_title_for_block(item))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false })
}

fn item_title_for_block(item: &VaultItem) -> String {
    match &item.payload {
        VaultItemPayload::Login(login) => login.title.clone(),
        VaultItemPayload::SecureNote(note) => note.title.clone(),
        VaultItemPayload::Card(card) => card.title.clone(),
        VaultItemPayload::Identity(identity) => identity.title.clone(),
    }
}

pub(crate) fn keyslot_detail_panel(app: &App) -> Paragraph<'static> {
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

pub(crate) fn edit_keyslot_label_panel(app: &App) -> Paragraph<'static> {
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

pub(crate) fn add_login_panel(app: &App) -> Paragraph<'static> {
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

pub(crate) fn add_note_panel(app: &App) -> Paragraph<'static> {
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

pub(crate) fn add_card_panel(app: &App) -> Paragraph<'static> {
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

pub(crate) fn add_identity_panel(app: &App) -> Paragraph<'static> {
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

pub(crate) fn add_mnemonic_slot_panel(app: &App) -> Paragraph<'static> {
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

pub(crate) fn add_device_slot_panel(app: &App) -> Paragraph<'static> {
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

pub(crate) fn add_certificate_slot_panel(app: &App) -> Paragraph<'static> {
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

pub(crate) fn rewrap_certificate_slot_panel(app: &App) -> Paragraph<'static> {
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
            &masked_value(form.key_passphrase.as_str()),
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

pub(crate) fn certificate_preview_lines(cert_path: &str) -> Vec<Line<'static>> {
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

pub(crate) fn rotate_recovery_secret_panel(app: &App) -> Paragraph<'static> {
    let form = &app.recovery_secret_form;
    let lines = vec![
        form_line(
            matches!(form.selected_field(), RecoverySecretField::NewSecret),
            "New recovery secret",
            &masked_value(form.new_secret.as_str()),
        ),
        form_line(
            matches!(form.selected_field(), RecoverySecretField::Confirm),
            "Confirm recovery secret",
            &masked_value(form.confirm_secret.as_str()),
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

pub(crate) fn rotate_mnemonic_slot_panel(app: &App) -> Paragraph<'static> {
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

pub(crate) fn mnemonic_reveal_panel(app: &App) -> Paragraph<'static> {
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
            Line::raw(enrollment.mnemonic.as_str().to_string()),
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

pub(crate) fn delete_confirm_panel(app: &App) -> Paragraph<'static> {
    // Severe-tier confirm (ia.md §7): the persona types the item's own name
    // rather than a bare y/N — "make it hard to confirm by accident."
    let detail_line = match &app.detail {
        Some(item) => match &item.payload {
            VaultItemPayload::Login(login) => {
                format!("{} · {}", login.title, login.username)
            }
            VaultItemPayload::SecureNote(note) => note.title.clone(),
            VaultItemPayload::Card(card) => format!("{} · {}", card.title, card.cardholder_name),
            VaultItemPayload::Identity(identity) => {
                format!("{} · {}", identity.title, identity.full_name)
            }
        },
        None => "No selection".to_string(),
    };

    let lines = vec![
        Line::styled(
            format!("This deletes \"{}\" for good.", app.confirm_target_name),
            theme::caution(),
        ),
        Line::raw(detail_line),
        Line::raw(""),
        Line::raw(format!("Type \"{}\" to confirm:", app.confirm_target_name)),
        Line::styled(
            format!("{}_", app.confirm_input),
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        ),
    ];

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

pub(crate) fn generate_store_panel(app: &App) -> Paragraph<'static> {
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

pub(crate) fn export_backup_panel(app: &App) -> Paragraph<'static> {
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
        app.export_backup_preview
            .as_ref()
            .map_or(Err("current backup summary was not prepared"), |preview| {
                preview.as_result()
            }),
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

pub(crate) fn export_transfer_panel(app: &App) -> Paragraph<'static> {
    let form = &app.export_transfer_form;
    let package_password = if form.package_password.as_str().trim().is_empty() {
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

pub(crate) fn import_backup_panel(app: &App) -> Paragraph<'static> {
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
    let inspected = inspected_backup_summary(form.path.as_str());
    lines.extend(match inspected.as_ref() {
        Ok(summary) => backup_preview_lines(Ok(summary)),
        Err(error) => {
            let error = error.to_string();
            backup_preview_lines(Err(error.as_str()))
        }
    });

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

pub(crate) fn import_transfer_panel(app: &App) -> Paragraph<'static> {
    let form = &app.import_transfer_form;
    let replace_existing = if form.replace_existing { "yes" } else { "no" };
    let package_password = if form.package_password.as_str().trim().is_empty() {
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
    let key_passphrase = if form.key_passphrase.as_str().trim().is_empty() {
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

pub(crate) fn inspected_backup_summary(path: &str) -> Result<VaultBackupSummary, anyhow::Error> {
    let path = path.trim();
    if path.is_empty() {
        anyhow::bail!("enter a backup path to inspect the package summary");
    }
    Ok(inspect_vault_backup(path)?)
}

pub(crate) fn inspected_transfer_summary(
    path: &str,
) -> Result<VaultTransferSummary, anyhow::Error> {
    let path = path.trim();
    if path.is_empty() {
        anyhow::bail!("enter a transfer path to inspect the package summary");
    }
    Ok(inspect_vault_transfer(path)?)
}

pub(crate) fn backup_preview_lines(
    summary: Result<&VaultBackupSummary, &str>,
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

pub(crate) fn current_transfer_selection_lines(
    app: &App,
    form: &ExportTransferForm,
) -> Vec<Line<'static>> {
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
            !form.package_password.as_str().trim().is_empty(),
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

pub(crate) fn transfer_preview_lines(
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
