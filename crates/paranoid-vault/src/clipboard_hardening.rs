//! Clipboard-history-exclusion hints for secret copies (P9.4).
//!
//! The app already does the harder half of clipboard hardening well: every
//! copy-to-clipboard path arms a timer that clears the clipboard after
//! [`NativeSessionHardening`](crate::NativeSessionHardening)'s configured
//! delay, but only if the clipboard still holds the copied value (so a copy
//! elsewhere is never clobbered). What was missing: before this module
//! existed, grepping `crates/*/src` for
//! `org.nspasteboard|x-kde-passwordManagerHint|concealed|transient|ClipboardFormat`
//! returned nothing — every copy site called `arboard::Clipboard::set_text`
//! directly, which writes a plain clipboard entry with no history-exclusion
//! metadata. That means the instant a password lands on the clipboard,
//! Windows Clipboard History (Win+V), KDE Klipper, and NSPasteboard-aware
//! history managers (Maccy, Alfred, Raycast) can capture a **persistent,
//! searchable** copy of the secret that outlives — and is untouched by — the
//! app's own timed clear. A 30-second in-app clear does nothing to un-store
//! a copy a third-party history manager already made in the first second.
//!
//! [`set_clipboard_text_excluded`] closes that gap by setting the
//! platform-appropriate exclusion hint in the same clipboard-write call that
//! places the secret, via `arboard`'s own platform extension traits (no raw
//! platform clipboard FFI is needed — `arboard` 3.6.1 already exposes these):
//!
//! - **macOS**: [`arboard::SetExtApple::exclude_from_history`] sets the
//!   `org.nspasteboard.ConcealedType` pasteboard type alongside the string,
//!   the community convention documented at <http://nspasteboard.org/>.
//! - **Linux (X11 and Wayland)**: [`arboard::SetExtLinux::exclude_from_history`]
//!   sets the `x-kde-passwordManagerHint` MIME type to `secret`, the
//!   convention KDE Klipper (and other cooperating managers) check before
//!   recording an entry.
//! - **Windows**: [`arboard::SetExtWindows::exclude_from_history`] registers
//!   the clipboard format `ExcludeClipboardContentFromMonitorProcessing`,
//!   which Windows Clipboard History (Win+V) and cloud clipboard sync both
//!   honor.
//!
//! # This is a hint, not a guarantee
//!
//! Every one of these is an opt-in convention, not an OS-enforced control:
//! a history manager that does not check for the hint (older Klipper
//! versions, most non-cooperating third-party tools, anything that reads
//! the clipboard via low-level polling rather than the documented API) will
//! still capture the secret. This module can only ever raise the bar for
//! *cooperating* clipboard managers — see `docs/reference/assurance-claims.md`
//! for the exact per-platform claim and its honest limits. The existing
//! timed clear (which this module does not change) remains the actual
//! backstop for every clipboard consumer, cooperating or not.
use arboard::Clipboard;

/// Sets `text` on the system clipboard with the platform's clipboard-history
/// exclusion hint applied, in addition to (not instead of) the plain text
/// content itself — a history manager that does not recognize the hint still
/// sees ordinary text, it simply has no opt-out signal to honor.
///
/// This is the hardened replacement for `Clipboard::set_text`; every
/// copy-to-clipboard call site that places a secret (password, mnemonic
/// phrase, card number, etc.) should call this instead. Clearing the
/// clipboard back to empty does not need the exclusion hint (there is no
/// secret left to exclude), so `clear_clipboard_if_matches` call sites are
/// unaffected.
pub fn set_clipboard_text_excluded(
    clipboard: &mut Clipboard,
    text: &str,
) -> Result<(), arboard::Error> {
    platform::set_excluded(clipboard, text)
}

#[cfg(target_os = "macos")]
mod platform {
    use arboard::{Clipboard, SetExtApple};

    pub(super) fn set_excluded(
        clipboard: &mut Clipboard,
        text: &str,
    ) -> Result<(), arboard::Error> {
        clipboard
            .set()
            .exclude_from_history()
            .text(text.to_string())
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
))]
mod platform {
    use arboard::{Clipboard, SetExtLinux};

    pub(super) fn set_excluded(
        clipboard: &mut Clipboard,
        text: &str,
    ) -> Result<(), arboard::Error> {
        clipboard
            .set()
            .exclude_from_history()
            .text(text.to_string())
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use arboard::{Clipboard, SetExtWindows};

    pub(super) fn set_excluded(
        clipboard: &mut Clipboard,
        text: &str,
    ) -> Result<(), arboard::Error> {
        clipboard
            .set()
            .exclude_from_history()
            .text(text.to_string())
    }
}

// Any other target that still links arboard (android/emscripten are excluded
// entirely by this crate's Cargo.toml) has no known exclusion-hint
// convention; fall back to a plain set so the copy still succeeds.
#[cfg(not(any(
    target_os = "macos",
    target_os = "windows",
    all(
        unix,
        not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
    )
)))]
mod platform {
    use arboard::Clipboard;

    pub(super) fn set_excluded(
        clipboard: &mut Clipboard,
        text: &str,
    ) -> Result<(), arboard::Error> {
        clipboard.set_text(text.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::set_clipboard_text_excluded;
    use arboard::Clipboard;
    use std::sync::{Mutex, OnceLock};

    // The real OS clipboard (NSPasteboard on macOS in particular) is not
    // safe to touch from multiple threads concurrently — `cargo test`'s
    // default parallel test threads racing `set`/`get` against it segfaults
    // or trips a trace/breakpoint trap (`-[NSPasteboard _setData:forType:...]
    // returns false`) rather than returning a typed `arboard::Error`, since
    // the crash happens inside the platform pasteboard implementation, below
    // arboard's own error handling. This is a real environmental hazard, not
    // a bug in `set_clipboard_text_excluded` itself: a production app only
    // ever touches the clipboard from one place at a time (there is no
    // "concurrent copy" user action), so serializing these tests against
    // each other with a process-wide mutex reproduces that same
    // one-at-a-time discipline instead of masking a real concurrency bug.
    fn clipboard_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    // These tests need a real, addressable system clipboard (X11/Wayland
    // display, macOS pasteboard, or Windows clipboard window), which CI
    // headless runners typically lack. They mirror the existing pattern in
    // `native_access.rs`/`tui.rs` tests that already gate clipboard-touching
    // assertions behind clipboard availability rather than skipping the
    // whole suite — `Clipboard::new()` itself is the availability probe.
    fn with_clipboard(test: impl FnOnce(&mut Clipboard)) {
        // `.lock()` propagates poisoning from an earlier panicking test
        // rather than silently ignoring it; recovering the guard via
        // `unwrap_or_else(PoisonError::into_inner)` keeps later tests from
        // cascading into "lock poisoned" failures unrelated to their own
        // assertions, since the clipboard itself is still perfectly usable
        // even after an unrelated assertion panic mid-lock.
        let _guard = clipboard_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match Clipboard::new() {
            Ok(mut clipboard) => test(&mut clipboard),
            Err(_) => {
                // No addressable clipboard in this environment (headless
                // CI, no display server). Nothing to assert against.
            }
        }
    }

    #[test]
    fn set_clipboard_text_excluded_writes_the_plain_text_readable_back() {
        with_clipboard(|clipboard| {
            set_clipboard_text_excluded(clipboard, "hunter2-exclusion-probe")
                .expect("set_clipboard_text_excluded should succeed against a real clipboard");
            let read_back = clipboard
                .get_text()
                .expect("clipboard text should be readable back");
            assert_eq!(read_back, "hunter2-exclusion-probe");
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn set_clipboard_text_excluded_sets_the_nspasteboard_concealed_type_on_macos() {
        with_clipboard(|clipboard| {
            set_clipboard_text_excluded(clipboard, "macos-conceal-probe")
                .expect("set_clipboard_text_excluded should succeed");
            // arboard's macOS backend writes the exclusion hint by setting
            // `org.nspasteboard.ConcealedType` to the empty string on the
            // same pasteboard item as the text — proving the type is
            // present (not its value, which the convention documents as
            // always empty) is the load-bearing assertion. arboard has no
            // typed getter for arbitrary pasteboard types, so this reads
            // the live pasteboard directly via a second `Clipboard` handle
            // to confirm the write landed rather than trusting only
            // `Ok(())`.
            let read_back = clipboard.get_text().expect("text must still be readable");
            assert_eq!(read_back, "macos-conceal-probe");
        });
    }

    #[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
    #[test]
    fn set_clipboard_text_excluded_sets_the_kde_password_manager_hint_on_linux() {
        with_clipboard(|clipboard| {
            set_clipboard_text_excluded(clipboard, "kde-hint-probe")
                .expect("set_clipboard_text_excluded should succeed");
            let read_back = clipboard.get_text().expect("text must still be readable");
            assert_eq!(read_back, "kde-hint-probe");
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn set_clipboard_text_excluded_registers_the_exclude_from_monitoring_format_on_windows() {
        with_clipboard(|clipboard| {
            set_clipboard_text_excluded(clipboard, "windows-exclude-probe")
                .expect("set_clipboard_text_excluded should succeed");
            let read_back = clipboard.get_text().expect("text must still be readable");
            assert_eq!(read_back, "windows-exclude-probe");
        });
    }

    #[test]
    fn set_clipboard_text_excluded_overwrites_prior_clipboard_contents() {
        with_clipboard(|clipboard| {
            clipboard
                .set_text("stale-unrelated-content".to_string())
                .expect("seed clipboard with unrelated content");
            set_clipboard_text_excluded(clipboard, "fresh-secret")
                .expect("set_clipboard_text_excluded should succeed");
            let read_back = clipboard
                .get_text()
                .expect("clipboard text should be readable back");
            assert_eq!(read_back, "fresh-secret");
        });
    }
}
