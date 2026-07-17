//! First-run/install-time capability probes: OS keychain (`keyring`), clipboard
//! (`arboard`), display server, and configured seal providers. Assembled into
//! `paranoid_ops::CapabilityReport`, modeled on
//! `FederalCryptoProviderEvidence::collect_from_environment()`.
//!
//! The probes live here (not in `paranoid-core` or `paranoid-ops`) because they
//! are the only crates in the workspace with real `keyring`/`arboard`
//! dependencies; the seal-provider evidence is reused from
//! `paranoid_vault::seal_posture_for_path()` rather than re-derived.

use paranoid_ops::{CapabilityReport, ClipboardCapability, OsKeychainCapability};
use paranoid_vault::{VaultKeyslotProviderProbe, seal_posture_for_path};
use std::path::Path;

const KEYCHAIN_PROBE_SERVICE: &str = "paranoid-passwd-capability-probe";
const KEYCHAIN_PROBE_ACCOUNT: &str = "environment-detection";

/// Collects the full capability report for the given vault path, probing the
/// OS keychain and clipboard live and reusing seal-provider evidence from the
/// vault header at `vault_path` (if any).
pub fn collect_capability_report(vault_path: &Path) -> CapabilityReport {
    let (_, seal_posture) =
        seal_posture_for_path(vault_path, VaultKeyslotProviderProbe::VerifyAvailability);
    CapabilityReport::assemble(
        probe_os_keychain(),
        probe_clipboard(),
        seal_posture.providers,
    )
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn keychain_backend_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "apple-native"
    } else if cfg!(target_os = "windows") {
        "windows-native"
    } else {
        "secret-service"
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn probe_os_keychain() -> OsKeychainCapability {
    let backend = keychain_backend_label();
    match keyring::Entry::new(KEYCHAIN_PROBE_SERVICE, KEYCHAIN_PROBE_ACCOUNT) {
        Ok(entry) => match entry.get_secret() {
            Ok(_) | Err(keyring::Error::NoEntry) => {
                OsKeychainCapability::available(backend, "keyring_probe")
            }
            Err(error) => {
                OsKeychainCapability::unavailable(backend, "keyring_probe", error.to_string())
            }
        },
        Err(error) => {
            OsKeychainCapability::unavailable(backend, "keyring_probe", error.to_string())
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn probe_os_keychain() -> OsKeychainCapability {
    OsKeychainCapability::unavailable(
        "unsupported",
        "keyring_probe",
        "OS keychain secure storage is unsupported on this platform",
    )
}

fn probe_clipboard() -> ClipboardCapability {
    match arboard::Clipboard::new() {
        Ok(_) => ClipboardCapability::available("arboard_probe"),
        Err(error) => ClipboardCapability::unavailable("arboard_probe", error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paranoid_vault::{default_vault_path, init_vault};
    use tempfile::tempdir;

    #[test]
    fn collect_capability_report_for_missing_vault_has_no_seal_providers() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist.sqlite");

        let report = collect_capability_report(&path);

        assert!(report.seal_providers.is_empty());
        assert_eq!(report.operating_system, std::env::consts::OS);
        assert_eq!(report.architecture, std::env::consts::ARCH);
    }

    #[test]
    fn collect_capability_report_for_initialized_vault_reports_password_provider() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.sqlite");
        init_vault(&path, "correct horse battery staple").expect("init vault");

        let report = collect_capability_report(&path);

        assert_eq!(report.seal_providers.len(), 1);
        assert_eq!(report.seal_providers[0].provider_id, "recovery");
        assert_eq!(
            report.seal_providers[0].kind,
            paranoid_ops::VaultSealProviderKind::PasswordRecovery
        );
    }

    #[test]
    fn probe_clipboard_reports_available_or_a_typed_error_detail() {
        let clipboard = probe_clipboard();
        if !clipboard.status.is_available() {
            assert!(clipboard.error_detail.is_some());
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn probe_os_keychain_reports_available_or_a_typed_error_detail() {
        let keychain = probe_os_keychain();
        if !keychain.status.is_available() {
            assert!(keychain.error_detail.is_some());
        }
    }

    #[test]
    fn default_vault_path_is_a_usable_probe_target() {
        // Exercises the same path callers use for `--detect-environment`
        // without requiring a vault to exist there.
        let path = default_vault_path();
        let report = collect_capability_report(&path);
        assert_eq!(
            report.schema_version,
            paranoid_ops::CAPABILITY_REPORT_SCHEMA_VERSION
        );
    }
}
