---
title: Vault Format
---

# Vault Format

`paranoid-passwd` is standardizing on **SQLite as the vault file format**.

That is an intentional product decision, not a placeholder:

- the vault is device-local, not a shared network database
- the roadmap needs tags, history, migrations, search, and typed item models
- the file format needs to remain portable, inspectable, and stable across platforms
- the encryption boundary needs to stay in application code so keyslots can evolve independently of the storage engine

## Chosen Layout

- Main file: `vault.sqlite`
- SQLite profile:
  - `application_id` pinned to the vault format
  - `user_version` pinned to the vault schema version
  - rollback journal mode, not persistent WAL
  - `secure_delete=ON`
  - `temp_store=MEMORY`
- Tables:
  - `metadata`
  - `items`
- Header storage:
  - `metadata.header_json` stores `VaultHeader`
- Item storage:
  - row-level SQLite columns keep only ids, item kind, timestamps, and encrypted blobs
  - item payloads are encrypted with the random vault master key using OpenSSL-backed `AES-256-GCM`
  - item payloads currently include typed `Login`, `SecureNote`, `Card`, and `Identity` records plus local organization metadata such as tags, and `Login` items retain prior passwords as encrypted history entries when rotations occur

## Backup Package

The standardized backup format is a **portable JSON package of the existing encrypted vault state**, not a second vault implementation.

- Backup file: user-chosen path, typically `vault.backup.json`
- Contents:
  - `backup_format_version`
  - `exported_at_epoch`
  - `vault_format_version`
  - serialized `VaultHeader`
  - encrypted item rows with ids, kinds, timestamps, and hex-encoded `nonce`, `tag`, and `ciphertext`

That means backup export/import preserves the same keyslot model, encrypted item rows, unlock semantics, and recovery posture:

- recovery-secret slots
- mnemonic recovery slots
- certificate-wrapped slots
- device-bound slots

Export does not decrypt items into a new storage format. Restore recreates a normal `vault.sqlite` file from the serialized encrypted rows and header. Device-bound backup semantics are intentionally same-device only: the package preserves the device keyslot metadata and check blob, but it does not contain the device secure-storage secret. A restore can use that slot only if the same platform secure-storage account is still present and the check blob verifies the exact 256-bit master-key candidate.

Backup packages can now be inspected before restore through a read-only `VaultBackupSummary`, which reports item-kind counts, keyslot posture, keyslot detail summaries including certificate metadata, and whether the current build can restore the package directly without mutating a live vault.

Export is fail-closed against overwriting the source vault: the requested output path is canonicalized and compared against the vault's own path before any write happens, and a collision returns `VaultError::ExportPathCollision` instead of touching either file. The package bytes are then written to a same-directory temp file and moved into place with `fs::rename`, so a mid-write interruption (disk full, permission change, process kill) never leaves a partially written file at the destination path — the destination is either the previous contents or the complete new package, never a truncated one.

Restore is atomic against the destination path. `restore_vault_backup` never touches the target file directly: it builds the full restored vault (schema, header row, every item row) in a same-directory temp sibling, then validates that build by reopening it in a fresh connection — checking the SQLite application ID and schema version pragmas, deserializing the header, and confirming the imported row count matches the backup package's item count — before `fs::rename`-ing the validated temp file over the destination. If the package is malformed, an item fails to decode, or the row count check fails partway through, the temp file is removed and the destination path is never touched, so a mid-restore failure (including a malformed item late in the backup file) leaves a pre-existing vault at that path fully intact and unlockable. `--force`/`overwrite` only lifts the pre-flight `VaultError::VaultExists` check; it does not pre-emptively delete the destination.

## Transfer Package

The standardized transfer format is a **portable encrypted package of selected item payloads**, not a second full-vault backup.

- Transfer file: user-chosen path, typically `vault-transfer.ppvt.json`
- Contents:
  - `transfer_format_version`
  - `exported_at_epoch`
  - `source_vault_format_version`
  - clear item-kind counts and the selection filter used at export time
  - an encrypted payload containing the selected `VaultItem` records
  - one or more unwrap paths for the transfer data key:
    - recovery-secret unwrap via Argon2id + `AES-256-GCM`
    - recipient-certificate unwrap via OpenSSL CMS envelope encryption

That separation is intentional:

- **backup packages** preserve the current encrypted vault header, ciphertext rows, and keyslots for full restore or migration
- **transfer packages** move selected decrypted records into an already unlocked destination vault without copying the source vault’s keyslots or device-bound secure-storage assumptions

Import keeps the cryptographic boundary in application code:

- the transfer payload is decrypted only after the package unwrap path succeeds
- imported items are revalidated before storage
- conflicting ids are remapped by default instead of overwriting local records silently
- headless import can explicitly replace matching ids when the operator chooses that behavior
- the whole item list is imported inside a single SQLite transaction: if any item fails
  normalization/validation partway through the list, the transaction rolls back and the
  destination vault ends with zero newly-imported rows, never a partial commit of the
  items that happened to validate before the failing one

Transfer export shares the same fail-closed path-collision check and atomic temp-file-then-rename write as backup export: it never overwrites the source vault path, and an interrupted write never corrupts or truncates a pre-existing file at the destination.

## Key Hierarchy

- A random 256-bit vault master key encrypts records.
- Keyslots wrap that master key.
- The current keyslot model is:
  - `password_recovery`
  - `mnemonic_recovery`
  - `certificate_wrapped`
  - `device_bound`

The current shipped password recovery slot is password-derived with Argon2id and `AES-256-GCM`. Newly created vaults derive that Argon2id key with a memory cost of 262144 KiB (256 MiB), 3 iterations, and a parallelism of 1. Those defaults are recorded in the header's `VaultKdfParams` at creation time, not hard-coded at unlock: every unlock path re-derives the key using whatever `VaultKdfParams` are already stored in that vault's header, so a vault created under older or newer defaults keeps unlocking correctly and a future default change never invalidates existing vaults.

Mnemonic recovery slots use a 24-word English BIP39 phrase as a wallet-style recovery encoding for a random 256-bit recovery key generated by the OpenSSL-backed RNG path. The recovered 256-bit entropy wraps the same vault master key with OpenSSL-backed `AES-256-GCM`; the phrase is not user-authored, not imported from outside the vault workflow, and not treated as a password KDF.

Certificate slots wrap the same master key with an X.509 recipient certificate through a two-layer
construction. Current enrollment and rewrap generate a fresh 256-bit transport key, wrap only that
transport key with OpenSSL CMS EnvelopedData for one explicit recipient certificate, and wrap the
vault master key separately with OpenSSL-backed `AES-256-GCM` plus associated data. The header stores
the CMS-wrapped transport key, AES-GCM nonce/tag/ciphertext, and public certificate metadata needed
for lifecycle management, including the fingerprint, subject, validity window, and canonical epoch
values used by the shared keyslot-health layer. The certificate private key and raw transport key are
never stored in the vault header or backup package. Legacy direct-CMS master-key slots remain a
read-only unlock compatibility path; new slots use `cms-envelope+transport-key+aes-256-gcm`.

Device-bound slots store the unwrap secret in platform secure storage and keep only an AES-256-GCM verification blob plus keyring metadata in the SQLite header. Unlock rejects missing, wrong-length, deleted, or tampered secure-storage values before exposing plaintext vault state. That gives the product passwordless daily unlock without collapsing recovery or certificate support into the same path, and it remains a default-profile local convenience path rather than portable recovery or the strict federal-ready unlock path.

The lifecycle stays explicit in the application layer: interactive and headless native surfaces can inspect slots, compute a shared recovery posture, emit shared recovery recommendations, enroll new mnemonic/device/certificate slots, rotate mnemonic recovery slots in place, rotate the password recovery slot in place, remove non-recovery slots, and rebind device-bound slots to a fresh secure-storage account without changing the underlying SQLite file format. Native certificate rewrap forms can also update the active certificate key path and passphrase alongside the replacement recipient certificate so session continuity does not depend on stale unlock material after a rotation.

Keyslot removal is no longer a blind mutation. The header now supports a shared removal-impact analysis that compares the before/after posture and warns when a removal would drop certificate coverage, remove the last mnemonic recovery phrase, or disable passwordless daily unlock. The CLI requires `--force` for those posture-downgrading removals, and the TUI/GUI mirror that with a native confirmation step instead of silently weakening the vault.

Item payloads now carry folder plus tag metadata inside ciphertext, so local organization and decrypted summary search can evolve without exposing a plaintext folder index in SQLite.

Generator-driven password rotation reuses the same login item id and appends the previous password to encrypted history instead of creating a parallel shadow record format for rotated credentials.

## Why SQLite

SQLite matches the actual product constraints:

- it is designed for local application storage and file-format use
- it gives us transactions, migrations, indices, and future query flexibility without inventing a custom container
- it stays cross-platform and easy to package in the current release model

## Why Not Something Else

### SQLCipher

SQLCipher is strong technology, but it encrypts the whole database at the storage layer. For this product we want the key hierarchy, recovery model, certificate wrapping, and future device-bound slots to stay explicit in `paranoid-vault`, not hidden behind a database password interface.

### LMDB / redb / other KV stores

Those engines are attractive for simple encrypted blobs, but the roadmap is already beyond “store opaque values by key”. Password-manager features need structured queries, migrations, history, and richer local indexing. SQLite is a better long-term fit.

### Ad hoc files

Raw JSON, CBOR, or custom binary containers would force the project to reinvent indexing, migrations, integrity handling, and crash recovery. That is the wrong place to spend complexity.

## Recovery Direction

The current wallet-style recovery implementation uses a single 24-word BIP39 phrase generated from 256 bits of vault-owned entropy. Backup packages preserve the encrypted mnemonic keyslot metadata but do not export the phrase or raw entropy. The vault file format does not need to change again to support stronger future recovery.

If the project adopts split recovery later, the likely direction is **SLIP-0039 style split recovery** rather than replacing the underlying SQLite format. That would change the recovery keyslot type, not encrypted item storage.

The storage format remains:

- one SQLite vault file
- one random master key
- multiple keyslots that can unwrap that master key

That lets the project add stronger recovery later, such as mnemonic or split-secret recovery, without reworking encrypted item storage.
