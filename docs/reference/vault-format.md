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

Certificate slots wrap the same master key with an X.509 recipient certificate using OpenSSL CMS envelope encryption. This preserves one vault format while allowing multiple unlock paths.

Device-bound slots store the unwrap secret in platform secure storage and keep only an AES-256-GCM verification blob plus keyring metadata in the SQLite header. That gives the product passwordless daily unlock without collapsing recovery or certificate support into the same path.

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
