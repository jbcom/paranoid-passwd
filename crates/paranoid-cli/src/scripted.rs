//! Deterministic scripted driving surface for the TUI applications.
//!
//! Both `tui::run()` (the generator wizard) and `vault_tui::run()` (the vault
//! manager) normally read real keyboard events from a `CrosstermBackend`
//! terminal, which is why the only existing end-to-end coverage
//! (`tests/test_tui_e2e.py`) has to fork a real PTY. That PTY layer stays as
//! the sole terminal-emulation-accurate check; this module adds a second,
//! deterministic path that feeds a script of key tokens straight into the
//! same `App::handle_key` step function used by the real event loop, backed
//! by ratatui's in-memory `TestBackend` instead of a real terminal.
//!
//! A scripted run is activated by setting `PARANOID_TUI_SCRIPT=<path>` before
//! calling `tui::run()` or `vault_tui::run(config)`. The path must contain
//! newline-delimited key tokens (see [`parse_script`]). Blank lines and lines
//! starting with `#` are ignored. The run drives the real `App` — including,
//! for the generator wizard, its background worker thread — and returns a
//! final-frame text dump of the terminal buffer so callers can assert on
//! rendered content without a PTY.
//!
//! # Token grammar
//!
//! One token per line, whitespace-trimmed:
//!
//! - A single printable character is sent as its own literal
//!   `KeyCode::Char` key event. Multi-character text is scripted as one
//!   character per line (there is no inline string literal).
//! - `<enter>`, `<esc>`, `<tab>`, `<backspace>`, `<up>`, `<down>` map to the
//!   matching `KeyCode` variant.
//! - `<ctrl-u>` sends `KeyCode::Char('u')` with `KeyModifiers::CONTROL`
//!   (matches the custom-charset / form "clear field" shortcut).
//! - `<ctrl-l>` sends `KeyCode::Char('l')` with `KeyModifiers::CONTROL`
//!   (the vault TUI's panic / quick-lock hotkey, P9.6).
//! - `<wait-idle>` does not send a key event. It repeatedly polls the app
//!   (worker + hardening polling, when the app exposes it) until any
//!   background worker thread has drained, up to a bounded timeout. Use it
//!   after triggering an action that spawns a worker thread (e.g. launching
//!   the generator audit) before scripting further keys or ending the run.
//! - Blank lines and lines starting with `#` are ignored (comments).

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Default terminal size used for scripted runs, matching the PTY e2e layer.
pub const DEFAULT_COLS: u16 = 120;
pub const DEFAULT_ROWS: u16 = 40;

/// Upper bound on how long a single `<wait-idle>` token will poll before
/// giving up. Scripted runs are meant to be fast and hermetic; a worker that
/// has not drained within this window indicates a stuck test, not a slow one.
const WAIT_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const WAIT_IDLE_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// A single step to apply to the application under script control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptToken {
    /// Send this key event to `App::handle_key`.
    Key(KeyEvent),
    /// Poll until any background worker has drained, or time out.
    WaitIdle,
}

/// Reads `PARANOID_TUI_SCRIPT` from the environment and, if set, parses the
/// script file at that path. Returns `None` when the variable is unset so
/// callers can fall back to the normal interactive event loop.
pub fn script_from_env() -> Option<anyhow::Result<Vec<ScriptToken>>> {
    let path = env::var_os("PARANOID_TUI_SCRIPT")?;
    Some(load_script(Path::new(&path)))
}

/// `true` when `PARANOID_TUI_SCRIPT` is set. A scripted run is, by
/// definition, a deliberate non-interactive drive of the TUI (there is no
/// real terminal to detect), so callers should treat this the same as an
/// explicit `--tui` request when deciding whether to launch the TUI instead
/// of the scriptable CLI/ops path.
pub fn is_script_active() -> bool {
    env::var_os("PARANOID_TUI_SCRIPT").is_some()
}

/// Loads and parses a script file.
pub fn load_script(path: &Path) -> anyhow::Result<Vec<ScriptToken>> {
    let contents = fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("failed to read script {}: {error}", path.display()))?;
    parse_script(&contents)
}

/// Parses newline-delimited key tokens into [`ScriptToken`]s. See the module
/// docs for the token grammar.
pub fn parse_script(contents: &str) -> anyhow::Result<Vec<ScriptToken>> {
    let mut tokens = Vec::new();
    for (line_number, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        tokens.push(parse_token(line).map_err(|error| {
            anyhow::anyhow!("script line {}: {error} (in {raw_line:?})", line_number + 1)
        })?);
    }
    Ok(tokens)
}

fn parse_token(token: &str) -> anyhow::Result<ScriptToken> {
    if let Some(special) = token
        .strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
    {
        return Ok(ScriptToken::Key(match special {
            "enter" => key(KeyCode::Enter),
            "esc" => key(KeyCode::Esc),
            "tab" => key(KeyCode::Tab),
            "backspace" => key(KeyCode::Backspace),
            "up" => key(KeyCode::Up),
            "down" => key(KeyCode::Down),
            "ctrl-u" => KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
            "ctrl-l" => KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL),
            "wait-idle" => return Ok(ScriptToken::WaitIdle),
            other => anyhow::bail!("unknown token <{other}>"),
        }));
    }

    let mut chars = token.chars();
    let first = chars
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty literal token"))?;
    if chars.next().is_some() {
        anyhow::bail!(
            "literal tokens must be a single character; got {token:?} (send each character on its own line, or use one line per word for multi-character literal text)"
        );
    }
    Ok(ScriptToken::Key(key(KeyCode::Char(first))))
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Renders the given `TestBackend` terminal buffer to a plain-text dump, one
/// line per terminal row, trailing whitespace trimmed. This is the
/// "final-frame" text callers assert against after a scripted run.
pub fn dump_buffer(terminal: &Terminal<TestBackend>) -> String {
    let buffer = terminal.backend().buffer();
    let width = buffer.area.width as usize;
    let mut out = String::with_capacity(buffer.content.len() + buffer.area.height as usize);
    for (row_index, row) in buffer.content.chunks(width.max(1)).enumerate() {
        if row_index > 0 {
            out.push('\n');
        }
        for cell in row {
            out.push_str(cell.symbol());
        }
    }
    out
}

/// Result of a single [`drive`] step.
pub struct StepOutcome {
    /// `true` once any background work the app owns has fully drained (so
    /// `<wait-idle>` knows when to stop polling). Apps with no background
    /// work should always report `true`.
    pub idle: bool,
    /// `true` when the app requested to quit in response to a key event.
    /// Ignored for poll-only steps (`key: None`).
    pub quit: bool,
}

/// Generic scripted-run driver shared by `tui::run_scripted` and
/// `vault_tui::run_scripted`.
///
/// `step` performs one iteration of the app's own event loop body: when
/// `key` is `Some`, it should forward the event to the app's `handle_key`
/// before polling/rendering; when `None`, it should just poll (worker /
/// hardening) and render, as the real event loop does on each tick even
/// without a key event.
pub fn drive<S>(
    terminal: &mut Terminal<TestBackend>,
    tokens: &[ScriptToken],
    mut step: S,
) -> anyhow::Result<()>
where
    S: FnMut(&mut Terminal<TestBackend>, Option<KeyEvent>) -> anyhow::Result<StepOutcome>,
{
    // Drive one frame up front so the initial screen (e.g. an
    // already-unlocked vault from `PasswordEnv` auth) is reflected before any
    // keys are sent.
    step(terminal, None)?;
    for token in tokens {
        match token {
            ScriptToken::Key(key_event) => {
                let outcome = step(terminal, Some(*key_event))?;
                if outcome.quit {
                    break;
                }
            }
            ScriptToken::WaitIdle => {
                let deadline = Instant::now() + WAIT_IDLE_TIMEOUT;
                loop {
                    let outcome = step(terminal, None)?;
                    if outcome.idle {
                        break;
                    }
                    if Instant::now() >= deadline {
                        anyhow::bail!(
                            "<wait-idle> timed out after {:?} waiting for background work to drain",
                            WAIT_IDLE_TIMEOUT
                        );
                    }
                    std::thread::sleep(WAIT_IDLE_POLL_INTERVAL);
                }
            }
        }
    }
    Ok(())
}

/// A ready-to-drive scripted terminal, its parsed token script, and the
/// script file path it was loaded from (for error messages).
pub struct PreparedScript {
    pub terminal: Terminal<TestBackend>,
    pub tokens: Vec<ScriptToken>,
    pub path: PathBuf,
}

/// Convenience for `run()` implementations: reads the script path from
/// `PARANOID_TUI_SCRIPT`, builds a `TestBackend` terminal of the given size,
/// and returns both plus the parsed tokens, ready to hand to [`drive`].
pub fn prepare_scripted_terminal(cols: u16, rows: u16) -> anyhow::Result<Option<PreparedScript>> {
    let Some(path) = env::var_os("PARANOID_TUI_SCRIPT") else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    let tokens = load_script(&path)?;
    let backend = TestBackend::new(cols, rows);
    let terminal = Terminal::new(backend)
        .map_err(|error| anyhow::anyhow!("failed to initialize scripted terminal: {error}"))?;
    Ok(Some(PreparedScript {
        terminal,
        tokens,
        path,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_literal_and_special_tokens() {
        let script = "h\ne\nl\nl\no\n<enter>\n<esc>\n<tab>\n<backspace>\n<up>\n<down>\n<ctrl-u>\n<ctrl-l>\n<wait-idle>\n# a comment\n\n";
        let tokens = parse_script(script).expect("parse");
        assert_eq!(
            tokens,
            vec![
                ScriptToken::Key(key(KeyCode::Char('h'))),
                ScriptToken::Key(key(KeyCode::Char('e'))),
                ScriptToken::Key(key(KeyCode::Char('l'))),
                ScriptToken::Key(key(KeyCode::Char('l'))),
                ScriptToken::Key(key(KeyCode::Char('o'))),
                ScriptToken::Key(key(KeyCode::Enter)),
                ScriptToken::Key(key(KeyCode::Esc)),
                ScriptToken::Key(key(KeyCode::Tab)),
                ScriptToken::Key(key(KeyCode::Backspace)),
                ScriptToken::Key(key(KeyCode::Up)),
                ScriptToken::Key(key(KeyCode::Down)),
                ScriptToken::Key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)),
                ScriptToken::Key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL)),
                ScriptToken::WaitIdle,
            ]
        );
    }

    #[test]
    fn rejects_unknown_special_token() {
        let error = parse_script("<bogus>").expect_err("should reject");
        assert!(error.to_string().contains("unknown token"));
    }

    #[test]
    fn rejects_multi_character_literal_token() {
        let error = parse_script("abc").expect_err("should reject");
        assert!(error.to_string().contains("single character"));
    }

    #[test]
    fn dump_buffer_joins_rows_with_newlines() {
        let backend = TestBackend::new(3, 2);
        let terminal = Terminal::new(backend).expect("terminal");
        let dump = dump_buffer(&terminal);
        assert_eq!(dump, "   \n   ");
    }
}
