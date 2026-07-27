//! Shared ratatui theme module — the CLI/TUI half of the cross-surface token
//! system defined in `docs/design/system.md`.
//!
//! Every color, spacing step, and status glyph the TUI renders traces back to
//! a named token in `docs/design/system.md` §1-§5. Both `tui.rs` (the
//! generator/audit TUI) and `vault_tui.rs` (the vault TUI) import from this
//! module instead of defining their own `Color` constants — consolidating
//! what were previously two duplicated (and, in `tui.rs`'s case, one
//! off-palette) const blocks per `docs/design/system.md` §7.
//!
//! Naming mirrors the token table exactly: `color.bg.base` -> [`BG_BASE`],
//! `color.status.verified` -> [`STATUS_VERIFIED`], and so on. Short aliases
//! (`BG`, `PANEL`, `TEXT`, `GREEN`, `BLUE`, `AMBER`, `RED`) are kept so the
//! existing call sites across both TUIs did not need to churn their bare
//! identifiers; new code should prefer the intent-named constants.
//!
//! `docs/design/system.md` §7 flags a `PURPLE = #a78bfa` constant in the old
//! `tui.rs` const block as off-palette — it maps to no token meaning and is
//! deliberately not carried forward here.

use ratatui::style::{Color, Modifier, Style};

// ---------------------------------------------------------------------
// Color tokens (docs/design/system.md §1)
// ---------------------------------------------------------------------

/// `color.bg.base` — the ground. Near-black, low-glare; the whole surface.
pub const BG_BASE: Color = Color::Rgb(8, 12, 20);

/// `color.bg.panel` — a raised panel or focused region.
pub const BG_PANEL: Color = Color::Rgb(13, 17, 25);

/// `color.border` — structure and separation between regions.
pub const BORDER: Color = Color::Rgb(23, 48, 75);

/// `color.text.primary` — primary reading text.
pub const TEXT_PRIMARY: Color = Color::Rgb(228, 231, 242);

/// `color.text.muted` — secondary text, labels, footer keys, hints.
pub const TEXT_MUTED: Color = Color::Rgb(149, 160, 184);

/// `color.status.verified` — verified / safe / passed. Earned only after a
/// real check; never a default "all fine" wash.
pub const STATUS_VERIFIED: Color = Color::Rgb(52, 211, 153);

/// `color.accent.action` — the one next thing to do. One per screen.
pub const ACCENT_ACTION: Color = Color::Rgb(96, 165, 250);

/// `color.status.danger` — danger / failure / irreversible. A stop, never
/// decoration.
pub const STATUS_DANGER: Color = Color::Rgb(248, 113, 113);

/// `color.status.caution` — attention / unverified / in-between.
pub const STATUS_CAUTION: Color = Color::Rgb(251, 191, 36);

// Short aliases matching the pre-existing per-file const names, so both TUIs
// keep their bare `BG` / `PANEL` / ... call sites unchanged while sourcing
// the single canonical value.
pub const BG: Color = BG_BASE;
pub const PANEL: Color = BG_PANEL;
pub const TEXT: Color = TEXT_PRIMARY;
pub const GREEN: Color = STATUS_VERIFIED;
pub const BLUE: Color = ACCENT_ACTION;
pub const AMBER: Color = STATUS_CAUTION;
pub const RED: Color = STATUS_DANGER;

// ---------------------------------------------------------------------
// 16-ANSI fallbacks (docs/design/system.md §1.1) — for terminals without
// truecolor. Not yet wired into rendering (both TUIs currently render
// truecolor unconditionally), but declared here as the single source so a
// future capability-detect branch has one place to read from.
// ---------------------------------------------------------------------

/// `color.text.muted` 16-ANSI fallback — bright-black (8).
pub const ANSI_TEXT_MUTED: Color = Color::DarkGray;

/// `color.status.verified` 16-ANSI fallback — green (2).
pub const ANSI_STATUS_VERIFIED: Color = Color::Green;

/// `color.accent.action` 16-ANSI fallback — bright-blue (12).
pub const ANSI_ACCENT_ACTION: Color = Color::LightBlue;

/// `color.status.danger` 16-ANSI fallback — red (1).
pub const ANSI_STATUS_DANGER: Color = Color::Red;

/// `color.status.caution` 16-ANSI fallback — yellow (3).
pub const ANSI_STATUS_CAUTION: Color = Color::Yellow;

// ---------------------------------------------------------------------
// Spacing scale (docs/design/system.md §2) — four steps, expressed in cells
// for ratatui `Layout`/`Margin` constraints.
// ---------------------------------------------------------------------

/// `space.tight` — between a label and its value; intra-row.
pub const SPACE_TIGHT: u16 = 1;

/// `space.snug` — between stacked lines in a group.
pub const SPACE_SNUG: u16 = 1;

/// `space.base` — between groups; default panel padding.
pub const SPACE_BASE: u16 = 2;

/// `space.loose` — between major regions; around the primary action.
pub const SPACE_LOOSE: u16 = 3;

// ---------------------------------------------------------------------
// Type scale (docs/design/system.md §3) — four steps, expressed as ratatui
// `Modifier`s. The TUI has no font sizes; hierarchy comes from weight, as
// system.md specifies ("an austere instrument does not shout").
// ---------------------------------------------------------------------

/// `type.title` — screen title, one per screen, states its one job.
pub const TYPE_TITLE: Modifier = Modifier::BOLD;

/// `type.body` — primary content and reading text (no modifier).
pub const TYPE_BODY: Modifier = Modifier::empty();

/// `type.label` — field labels, footer keys, hints.
pub const TYPE_LABEL: Modifier = Modifier::DIM;

/// `type.mono` — secrets, hashes, phrases, generated passwords. The
/// terminal's cell font is implicitly monospace; no modifier is needed, but
/// the constant documents the mapping so call sites can name the intent.
pub const TYPE_MONO: Modifier = Modifier::empty();

// ---------------------------------------------------------------------
// Iconography set (docs/design/system.md §5) — the monochrome carriers that
// pair with each status color so meaning survives with zero color.
// ---------------------------------------------------------------------

/// `✓` verified / passed.
pub const ICON_VERIFIED: &str = "\u{2713}";

/// `✗` failed / danger.
pub const ICON_DANGER: &str = "\u{2717}";

/// `!` attention / unverified.
pub const ICON_CAUTION: &str = "!";

/// `⊘` locked — pairs with `color.text.muted`, never danger red (a locked
/// vault is the safe state, not a failure).
pub const ICON_LOCKED: &str = "\u{2298}";

/// `▸` the one next action.
pub const ICON_ACTION: &str = "\u{25b8}";

/// `⋯` drill into evidence / progressive disclosure.
pub const ICON_DRILL_DOWN: &str = "\u{22ef}";

// ---------------------------------------------------------------------
// Style helpers (docs/design/system.md §4) — named by intent so call sites
// read as "the verified style" rather than "green bold".
// ---------------------------------------------------------------------

/// Style for verified/passed status text: `color.status.verified`, bold.
pub fn verified() -> Style {
    Style::default()
        .fg(STATUS_VERIFIED)
        .add_modifier(Modifier::BOLD)
}

/// Style for failed/danger status text: `color.status.danger`, bold.
pub fn danger() -> Style {
    Style::default()
        .fg(STATUS_DANGER)
        .add_modifier(Modifier::BOLD)
}

/// Style for attention/unverified status text: `color.status.caution`.
pub fn caution() -> Style {
    Style::default().fg(STATUS_CAUTION)
}

/// Style for the single primary action on a screen: `color.accent.action`,
/// bold (docs/design/system.md §4.2). Exactly one element per screen may use
/// this.
pub fn accent_action() -> Style {
    Style::default()
        .fg(ACCENT_ACTION)
        .add_modifier(Modifier::BOLD)
}

/// Style for locked state: `color.text.muted` — deliberately not danger red,
/// since locking is the safe state (docs/design/system.md §4.4).
pub fn locked() -> Style {
    Style::default().fg(TEXT_MUTED)
}

/// Style for primary reading text: `color.text.primary`.
pub fn body() -> Style {
    Style::default().fg(TEXT_PRIMARY)
}

/// Style for muted/secondary text: `color.text.muted`, dim.
pub fn muted() -> Style {
    Style::default().fg(TEXT_MUTED).add_modifier(Modifier::DIM)
}

/// Base panel style: `color.bg.panel` background, `color.text.primary`
/// foreground (docs/design/system.md §4.1).
pub fn panel() -> Style {
    Style::default().bg(BG_PANEL).fg(TEXT_PRIMARY)
}

/// Base ground style: `color.bg.base` background.
pub fn base() -> Style {
    Style::default().bg(BG_BASE)
}
