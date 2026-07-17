//! Persisted, cross-restart failed-attempt lockout with exponential backoff.
//!
//! `Screen::UnlockBlocked` in the TUI (and the equivalent unlock-error path
//! in the GUI/CLI) was, before this module existed, a pure in-memory UI
//! state: a process restart, or even just re-opening the unlock form,
//! cleared it instantly. The only throttle on an offline brute-force attempt
//! against a stolen vault file was Argon2id's per-guess compute cost. This
//! module adds a durable record, bound to the vault path, that survives
//! restart and refuses unlock attempts before Argon2id runs while a lockout
//! is in force.
//!
//! The record deliberately lives in a sibling file next to the vault
//! (`<vault>.lock-state`), NOT inside the AEAD-encrypted `items` rows or the
//! vault's own `metadata` table: it must be readable — and writable — before
//! the vault is unlocked, since its entire purpose is to gate the unlock
//! attempt itself. It carries no secret material, only attempt counters and
//! timestamps, so storing it in plaintext alongside the vault reveals
//! nothing an attacker with the vault file didn't already have.

use crate::{VaultError, random_hex_id, unix_epoch_now};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Failed attempts are allowed to accumulate without any lockout up to this
/// count; the (N+1)th failure past this many free attempts starts the
/// exponential backoff. Matches the common "a few honest typos shouldn't
/// lock you out" allowance used by KeePassXC/Bitwarden-style throttles.
const FREE_ATTEMPTS: u32 = 3;

/// Base backoff duration applied to the first attempt past `FREE_ATTEMPTS`.
const BASE_BACKOFF_SECS: i64 = 5;

/// Hard cap on the computed backoff so a very high attempt count still
/// resolves to a bounded (if long) wait rather than an effectively
/// permanent lockout or an integer overflow: 24 hours.
const MAX_BACKOFF_SECS: i64 = 24 * 60 * 60;

/// Durable, path-bound record of failed unlock attempts. Stored in plaintext
/// (no secret material) as a sibling file next to the vault so it can be
/// read and updated before the vault is unlocked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockoutRecord {
    pub failed_attempt_count: u32,
    pub first_failure_epoch: i64,
    pub locked_until_epoch: i64,
}

/// Returns the sibling lockout-state path for a given vault path:
/// `<vault-file-name>.lock-state` in the same directory. Bound to the exact
/// vault path so distinct vaults (including a vault moved/renamed) never
/// share a lockout record.
pub fn lockout_state_path(vault_path: impl AsRef<Path>) -> PathBuf {
    let vault_path = vault_path.as_ref();
    let file_name = vault_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let lock_state_name = format!("{file_name}.lock-state");
    match vault_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(lock_state_name),
        _ => PathBuf::from(lock_state_name),
    }
}

/// Exponential backoff, in seconds, for the given total failed-attempt
/// count. Zero for any count at or below [`FREE_ATTEMPTS`]; otherwise
/// `BASE_BACKOFF_SECS * 2^(count - FREE_ATTEMPTS - 1)`, clamped to
/// [`MAX_BACKOFF_SECS`]. Uses checked/saturating arithmetic throughout so a
/// pathologically large attempt count saturates at the cap instead of
/// overflowing or panicking.
fn backoff_secs_for_attempt_count(failed_attempt_count: u32) -> i64 {
    if failed_attempt_count <= FREE_ATTEMPTS {
        return 0;
    }
    let exponent = failed_attempt_count - FREE_ATTEMPTS - 1;
    let multiplier = 1_i64.checked_shl(exponent).unwrap_or(i64::MAX);
    BASE_BACKOFF_SECS
        .checked_mul(multiplier)
        .unwrap_or(i64::MAX)
        .min(MAX_BACKOFF_SECS)
}

fn read_lockout_record(vault_path: impl AsRef<Path>) -> Result<Option<LockoutRecord>, VaultError> {
    let lock_state_path = lockout_state_path(vault_path);
    match fs::read_to_string(&lock_state_path) {
        Ok(contents) => {
            // A corrupt or unreadable lockout file must never itself become
            // an availability bug that permanently locks the legitimate
            // owner out: treat it as "no record" rather than propagating a
            // parse error, and let the next recorded failure or successful
            // unlock overwrite it with a fresh, well-formed record.
            Ok(serde_json::from_str::<LockoutRecord>(contents.as_str()).ok())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_lockout_record_atomically(
    vault_path: impl AsRef<Path>,
    record: &LockoutRecord,
) -> Result<(), VaultError> {
    let lock_state_path = lockout_state_path(vault_path);
    let parent = lock_state_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let temp_dir = match parent {
        Some(parent) => parent.to_path_buf(),
        None => PathBuf::from("."),
    };
    let file_name = lock_state_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp_name = format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        random_hex_id(8)?
    );
    let temp_path = temp_dir.join(temp_name);

    let contents = serde_json::to_string(record)?;
    let write_result = fs::write(&temp_path, contents.as_bytes());
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&temp_path, &lock_state_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error.into());
    }
    Ok(())
}

/// Checks whether a vault at `vault_path` is currently locked out. Returns
/// `Ok(())` when the attempt may proceed (no record, or the record's
/// `locked_until_epoch` has already passed) and
/// `Err(VaultError::LockedOut { retry_after_secs })` — with a positive
/// remaining-lockout duration — when it must be refused before Argon2id
/// runs. Called first by every `unlock_vault*` entry point, ahead of any KDF
/// work, so a locked-out attempt costs the attacker nothing extra but denies
/// the legitimate fast retry and makes the wait explicit.
pub(crate) fn check_lockout(vault_path: impl AsRef<Path>) -> Result<(), VaultError> {
    let vault_path = vault_path.as_ref();
    let Some(record) = read_lockout_record(vault_path)? else {
        return Ok(());
    };
    let now = unix_epoch_now()?;
    let retry_after_secs = record.locked_until_epoch - now;
    if retry_after_secs > 0 {
        return Err(VaultError::LockedOut { retry_after_secs });
    }
    Ok(())
}

/// Records a failed unlock attempt against `vault_path`, incrementing the
/// durable failed-attempt counter and recomputing `locked_until_epoch` with
/// exponential backoff. Called on every unlock failure (wrong password,
/// wrong mnemonic, wrong device secret, wrong certificate/key), regardless
/// of which auth method was attempted, so switching methods cannot be used
/// to reset or bypass the counter.
pub(crate) fn record_failed_unlock(vault_path: impl AsRef<Path>) -> Result<(), VaultError> {
    let vault_path = vault_path.as_ref();
    let now = unix_epoch_now()?;
    let previous = read_lockout_record(vault_path)?;
    let failed_attempt_count = previous
        .as_ref()
        .map(|record| record.failed_attempt_count)
        .unwrap_or(0)
        .saturating_add(1);
    let first_failure_epoch = previous
        .as_ref()
        .map(|record| record.first_failure_epoch)
        .unwrap_or(now);
    let locked_until_epoch = now
        .checked_add(backoff_secs_for_attempt_count(failed_attempt_count))
        .unwrap_or(i64::MAX);

    write_lockout_record_atomically(
        vault_path,
        &LockoutRecord {
            failed_attempt_count,
            first_failure_epoch,
            locked_until_epoch,
        },
    )
}

/// Clears any durable lockout record for `vault_path` after a successful
/// unlock. A missing record (nothing to clear) is not an error.
pub(crate) fn clear_lockout(vault_path: impl AsRef<Path>) -> Result<(), VaultError> {
    let lock_state_path = lockout_state_path(vault_path);
    match fs::remove_file(&lock_state_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn vault_path_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("vault.sqlite")
    }

    #[test]
    fn lockout_state_path_is_a_sibling_of_the_vault_file() {
        let dir = tempdir().expect("tempdir");
        let vault_path = vault_path_in(&dir);

        let lock_state_path = lockout_state_path(&vault_path);

        assert_eq!(lock_state_path.parent(), vault_path.parent());
        assert_eq!(
            lock_state_path.file_name().and_then(|name| name.to_str()),
            Some("vault.sqlite.lock-state")
        );
    }

    #[test]
    fn no_record_means_no_lockout() {
        let dir = tempdir().expect("tempdir");
        let vault_path = vault_path_in(&dir);

        assert!(check_lockout(&vault_path).is_ok());
    }

    #[test]
    fn free_attempts_do_not_trigger_a_lockout() {
        let dir = tempdir().expect("tempdir");
        let vault_path = vault_path_in(&dir);

        for _ in 0..FREE_ATTEMPTS {
            record_failed_unlock(&vault_path).expect("record failed unlock");
            assert!(
                check_lockout(&vault_path).is_ok(),
                "attempts within the free allowance must not lock out"
            );
        }
    }

    #[test]
    fn a_failed_unlock_past_the_free_allowance_locks_out_with_positive_retry_after() {
        let dir = tempdir().expect("tempdir");
        let vault_path = vault_path_in(&dir);

        for _ in 0..=FREE_ATTEMPTS {
            record_failed_unlock(&vault_path).expect("record failed unlock");
        }

        let error = check_lockout(&vault_path).expect_err("must be locked out");
        match error {
            VaultError::LockedOut { retry_after_secs } => {
                assert!(retry_after_secs > 0, "retry_after_secs must be positive");
            }
            other => panic!("expected LockedOut, got {other:?}"),
        }
    }

    #[test]
    fn lockout_persists_across_a_fresh_process_handle_restart() {
        let dir = tempdir().expect("tempdir");
        let vault_path = vault_path_in(&dir);

        for _ in 0..=FREE_ATTEMPTS {
            record_failed_unlock(&vault_path).expect("record failed unlock");
        }
        assert!(check_lockout(&vault_path).is_err());

        // Simulate a process restart: nothing but the on-disk sibling file
        // is shared with the calls above, so re-reading it here is exactly
        // the same code path a freshly started process would take.
        let error = check_lockout(&vault_path).expect_err("must remain locked out after restart");
        assert!(
            matches!(error, VaultError::LockedOut { retry_after_secs } if retry_after_secs > 0)
        );
    }

    #[test]
    fn backoff_grows_exponentially_with_attempt_count_and_is_capped() {
        assert_eq!(backoff_secs_for_attempt_count(0), 0);
        assert_eq!(backoff_secs_for_attempt_count(FREE_ATTEMPTS), 0);

        let first = backoff_secs_for_attempt_count(FREE_ATTEMPTS + 1);
        let second = backoff_secs_for_attempt_count(FREE_ATTEMPTS + 2);
        let third = backoff_secs_for_attempt_count(FREE_ATTEMPTS + 3);
        assert_eq!(first, BASE_BACKOFF_SECS);
        assert_eq!(second, BASE_BACKOFF_SECS * 2);
        assert_eq!(third, BASE_BACKOFF_SECS * 4);
        assert!(second > first);
        assert!(third > second);

        // A very large attempt count must saturate at the cap, not overflow
        // or panic.
        assert_eq!(backoff_secs_for_attempt_count(u32::MAX), MAX_BACKOFF_SECS);
        assert_eq!(
            backoff_secs_for_attempt_count(FREE_ATTEMPTS + 100),
            MAX_BACKOFF_SECS
        );
    }

    #[test]
    fn clear_lockout_removes_the_record_and_a_subsequent_attempt_is_allowed() {
        let dir = tempdir().expect("tempdir");
        let vault_path = vault_path_in(&dir);

        for _ in 0..=FREE_ATTEMPTS {
            record_failed_unlock(&vault_path).expect("record failed unlock");
        }
        assert!(check_lockout(&vault_path).is_err());

        clear_lockout(&vault_path).expect("clear lockout");

        assert!(check_lockout(&vault_path).is_ok());
        assert!(!lockout_state_path(&vault_path).exists());
    }

    #[test]
    fn clear_lockout_on_a_vault_with_no_record_is_not_an_error() {
        let dir = tempdir().expect("tempdir");
        let vault_path = vault_path_in(&dir);

        assert!(clear_lockout(&vault_path).is_ok());
    }

    #[test]
    fn the_lockout_record_lives_outside_the_vault_file_itself() {
        let dir = tempdir().expect("tempdir");
        let vault_path = vault_path_in(&dir);
        fs::write(
            &vault_path,
            b"not a real sqlite file, just proving the vault is untouched",
        )
        .expect("write stub vault file");
        let vault_contents_before = fs::read(&vault_path).expect("read vault file");

        record_failed_unlock(&vault_path).expect("record failed unlock");

        let lock_state_path = lockout_state_path(&vault_path);
        assert!(
            lock_state_path.exists(),
            "lockout record must be a separate, readable-pre-unlock file"
        );
        let vault_contents_after = fs::read(&vault_path).expect("read vault file");
        assert_eq!(
            vault_contents_before, vault_contents_after,
            "recording a failed unlock must never touch the vault file itself"
        );
    }

    #[test]
    fn a_corrupt_lockout_file_is_treated_as_no_record_rather_than_a_hard_failure() {
        let dir = tempdir().expect("tempdir");
        let vault_path = vault_path_in(&dir);
        let lock_state_path = lockout_state_path(&vault_path);
        fs::write(&lock_state_path, b"not valid json").expect("write corrupt lockout file");

        assert!(
            check_lockout(&vault_path).is_ok(),
            "a corrupt lockout file must never itself lock out the legitimate owner"
        );
    }

    #[test]
    fn no_lockout_file_is_created_for_the_free_attempt_check_alone() {
        // check_lockout must not have a write side effect: only recording a
        // failure or clearing after success touches the file.
        let dir = tempdir().expect("tempdir");
        let vault_path = vault_path_in(&dir);

        assert!(check_lockout(&vault_path).is_ok());
        assert!(!lockout_state_path(&vault_path).exists());
    }
}
