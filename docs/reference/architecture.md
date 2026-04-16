---
title: Architecture
---

# Architecture

`paranoid-passwd` now uses a Cargo workspace:

- `crates/paranoid-core`
- `crates/paranoid-cli`
- `crates/paranoid-gui`
- `crates/paranoid-vault`

## Core

`paranoid-core` is the single source of truth for:

- charset resolution and validation
- OpenSSL-backed CSPRNG access
- rejection sampling
- constrained generation
- SHA-256 hashing
- chi-squared distribution checks via `statrs`
- serial correlation
- collision counting
- pattern detection
- compliance evaluation

The old raw-memory WASM result struct is gone. The native application surface now passes typed Rust data structures between layers.

The shared report model is split between:

- `GeneratedPassword` for per-password counts, pattern checks, hashes, and framework verdicts
- `AuditSummary` for batch-level chi-squared, serial correlation, collision, and entropy reporting

## CLI and TUI

`paranoid-passwd` is the primary user binary.

- On an interactive TTY with no mode-forcing or operational flags, it launches the TUI.
- In automation or with `--cli`, it keeps the scriptable stdout/stderr contract.
- That launch policy is treated as the standard product contract: default TUI, explicit or implied headless CLI when operational flags are present, dedicated GUI app when the GUI surface is launched.
- The TUI uses `ratatui` plus `crossterm` to keep the current three-step product flow.
- `paranoid-passwd vault` follows the same contract: interactive TTY with no vault subcommand opens the native vault TUI, explicit subcommands stay headless.
- The `vault` namespace adds encrypted local retention without changing the generator root behavior.
- Vault filtering is standardized across modes: `vault list --query ... --kind ... --folder ... --tag ...`, the vault TUI `/` filter editor, and the GUI vault filter controls all call the same typed decrypted local summary filter in `paranoid-vault`, including kind, folder, and tag metadata stored inside encrypted payloads.
- Duplicate-password detection for `Login` items is also standardized at the vault layer and surfaced consistently in CLI, TUI, and GUI views without adding new persisted state.
- The vault TUI and GUI now both include native keyslot inspection, recovery-posture reporting, mnemonic/device-bound/certificate enrollment flows, in-place mnemonic rotation, certificate rewrap, non-destructive keyslot relabeling, password recovery-secret rotation, selected non-recovery slot removal, and device-slot rebind operations. Certificate-backed slots now persist public lifecycle metadata such as subject and validity window so CLI, TUI, and GUI can surface rotation pressure without shelling out to external tooling. Both interactive surfaces support direct native unlock input for recovery-secret, mnemonic, device-slot, and certificate-backed access when shell env setup is unavailable, and all three native surfaces expose the same encrypted backup and selective transfer export/import model. CLI remains the headless administration surface for scripting and automation, not the sole vault-exchange surface.
- Certificate lifecycle admin is now standardized before mutation as well as after: CLI can preview a PEM with `inspect-certificate`, inspect a persisted slot with `inspect-keyslot`, and the TUI/GUI certificate enrollment and rewrap forms parse the candidate PEM and show public metadata before changing vault state.
- Certificate lifecycle interpretation is also centralized now: `paranoid-vault` computes shared health warnings for not-yet-valid, expired, or near-expiry certificate slots, and the CLI/TUI/GUI consume that same assessment instead of inventing UI-local rules.
- Backup administration is standardized across surfaces as well: the engine now exposes a typed backup summary over item-kind counts, keyslot posture, and format compatibility; CLI exposes that via `vault inspect-backup`, and the TUI/GUI import-export screens render the same summary before restore. Separate item-level transfer packages use the same engine model and are now available across CLI, TUI, and GUI, while still remaining distinct from full-vault restore flows because they carry selected decrypted item payloads under fresh unwrap material instead of the source vault header and ciphertext rows.
- Keyslot removal policy is now standardized across surfaces: `VaultHeader::assess_keyslot_removal()` computes the same before/after posture and warning set for CLI, TUI, and GUI; headless removal requires `--force` for posture-downgrading removals, while TUI and GUI arm a native confirmation step before proceeding.
- Native interactive surfaces share a small session-hardening layer from `paranoid-vault`: copied secrets are cleared from the clipboard after 30 seconds if unchanged, and unlocked vault views auto-lock after 5 minutes of inactivity while clearing cached decrypted state.

## GUI

`paranoid-passwd-gui` is the dedicated desktop surface. It uses `Iced`, shares the same core request/result model, includes native vault `Login`, `SecureNote`, `Card`, and `Identity` CRUD/filter flows plus folder-plus-tag organization, login password-history visibility, duplicate-password visibility, native keyslot management, recovery-posture reporting, direct native unlock, encrypted backup export/import, clipboard auto-clear, and vault idle auto-lock, and now ships as a separate direct-download artifact with Linux `.deb` packaging and a native macOS `.dmg` path while native installer work remains later roadmap work.

## Vault Foundation

`paranoid-vault` is the first password-manager crate boundary.

- SQLite is the explicit vault file format, not a temporary backend choice.
- The vault stays local-device only and uses rollback-journal SQLite rather than a persistent WAL profile.
- A random master key encrypts vault items.
- Keyslots unwrap that master key:
  - `password_recovery` is the current recovery path
  - `mnemonic_recovery` is the current wallet-style recovery phrase path
  - `certificate_wrapped` is the current certificate-based unwrap path
  - `device_bound` is the current passwordless local-unlock path via platform secure storage
- Argon2id derives the recovery KEK.
- BIP39 encodes a 24-word recovery phrase for mnemonic recovery slots.
- OpenSSL-backed AES-256-GCM encrypts item payloads.
- OpenSSL CMS envelope encryption wraps the master key for certificate slots.
- Device-bound slots store the unwrap secret in OS secure storage and keep only verification metadata in SQLite.
- Keyslot lifecycle operations are now part of the native product surface: mnemonic recovery slots can be rotated in place to a replacement phrase without changing the slot id, certificate-wrapped slots can be rewrapped in place to a replacement recipient certificate, the native TUI/GUI rewrap flows can optionally update the active certificate key path and passphrase when the live session is using that slot, keyslot labels can be updated in place, the password recovery slot can be rewrapped in place, non-recovery slots can be removed, device-bound slots can be rebound to a fresh secure-storage account, and the unlock layer keeps explicit slot selection stable when multiple device or mnemonic slots exist.
- `VaultHeader::recovery_posture()` gives every surface the same policy view over whether the vault currently has recovery coverage, certificate coverage, and the recommended combination of both.
- `VaultHeader::recovery_recommendations()` and `VaultHeader::assess_keyslot_removal()` extend that into actionable policy: the product can now tell the operator what coverage is still missing and when a keyslot removal would weaken the vault’s access posture.
- The current item model supports `Login`, `SecureNote`, `Card`, and `Identity` entries, CRUD operations, folder-plus-tag metadata, encrypted password history for `Login` items, duplicate-password detection across unlocked `Login` items, generate-and-store flows for `Login` that can either create a new item or rotate an existing login in place, encrypted backup export/import, and native vault TUI/GUI surfaces with unlocked local filtering.
- `VaultBackupPackage` remains the portable encrypted backup format, and `VaultBackupSummary` is the read-only inspection model used to preview recovery packages before import.
- `VaultTransferPackage` is now the separate portable encrypted item-exchange format. It carries selected decrypted item payloads under a fresh AES-256-GCM data key, and that data key can be wrapped by a recovery secret, a recipient certificate, or both. Import happens into an already unlocked local vault and can remap conflicting ids safely instead of overwriting by default.

See [Vault Format](./vault-format.md) for the storage-engine decision and on-disk layout.

## Public Website

The public website is documentation only. GitHub Pages publishes the repository `docs/` tree, including:

- installation instructions
- TUI walkthrough
- architecture and testing notes
- release verification guidance
- generated Rust API docs via `sphinx-rust`

## Release Path

Release packaging is driven by checked-in scripts instead of workflow-only shell:

- `scripts/build_release_artifact.sh`
- `scripts/smoke_test_release_artifact.sh`
- `scripts/release_validate.sh`

Linux release builds run inside the repository-owned builder action. Native macOS and Windows archives use the same repo-owned packaging and smoke-test scripts on platform runners. Linux now also emits `.deb` packages through the same checked-in packaging scripts instead of a separate external packaging pipeline.

The release surface now includes both:

- `paranoid-passwd` for CLI/TUI and headless automation
- `paranoid-passwd-gui` for the dedicated desktop app surface

`install.sh` and package-manager publication remain intentionally scoped to the CLI/TUI artifact.
