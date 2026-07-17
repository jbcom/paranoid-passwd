//! Library surface for `paranoid-cli`.
//!
//! The binary target (`src/main.rs`) is a thin wrapper around this crate. The
//! library target exists so integration tests (and, longer term, agentic
//! control surfaces) can drive the real TUI applications without spawning a
//! PTY: see the `scripted` module for the deterministic scripted-mode driver
//! used by `PARANOID_TUI_SCRIPT`.

pub mod capability_detect;
pub mod scripted;
pub mod theme;
pub mod tui;
pub mod vault_cli;
pub mod vault_tui;
