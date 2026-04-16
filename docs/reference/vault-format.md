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

Export does not decrypt items into a new storage format. Restore recreates a normal `vault.sqlite` file from the serialized encrypted rows and header.

Backup packages can now be inspected before restore through a read-only `VaultBackupSummary`, which reports item-kind counts, keyslot posture, keyslot detail summaries including certificate metadata, and whether the current build can restore the package directly without mutating a live vault.

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

## Key Hierarchy

- A random 256-bit vault master key encrypts records.
- Keyslots wrap that master key.
- The current keyslot model is:
  - `password_recovery`
  - `mnemonic_recovery`
  - `certificate_wrapped`
  - `device_bound`

The current shipped password recovery slot is password-derived with Argon2id and `AES-256-GCM`.

Mnemonic recovery slots use a 24-word English BIP39 phrase as a wallet-style recovery encoding for a random 256-bit recovery key. That recovery key wraps the same vault master key with OpenSSL-backed `AES-256-GCM`.

Certificate slots wrap the same master key with an X.509 recipient certificate using OpenSSL CMS envelope encryption. The header also stores public certificate metadata needed for lifecycle management, including the fingerprint, subject, validity window, and canonical epoch values used by the shared keyslot-health layer. This preserves one vault format while allowing multiple unlock paths.

Device-bound slots store the unwrap secret in platform secure storage and keep only an AES-256-GCM verification blob plus keyring metadata in the SQLite header. That gives the product passwordless daily unlock without collapsing recovery or certificate support into the same path.

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

The current wallet-style recovery implementation uses a single 24-word BIP39 phrase. The vault file format does not need to change again to support stronger future recovery.

If the project adopts split recovery later, the likely direction is **SLIP-0039 style split recovery** rather than replacing the underlying SQLite format. That would change the recovery keyslot type, not encrypted item storage.

The storage format remains:

- one SQLite vault file
- one random master key
- multiple keyslots that can unwrap that master key

That lets the project add stronger recovery later, such as mnemonic or split-secret recovery, without reworking encrypted item storage.
