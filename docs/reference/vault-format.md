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
  - `certificate_wrapped`
  - `device_bound` reserved for passwordless local unlock

The current shipped recovery slot is password-derived with Argon2id and `AES-256-GCM`.

Certificate slots wrap the same master key with an X.509 recipient certificate using OpenSSL CMS envelope encryption. This preserves one vault format while allowing multiple unlock paths.

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

The long-term recovery target is **wallet-style mnemonic recovery**, but not by changing the vault file format again.

If the project adopts a wallet-style recovery scheme, the likely direction is **SLIP-0039 style split recovery** rather than a plain BIP-39 phrase. The vault format does not need to change for that; only the recovery keyslot type changes.

The storage format remains:

- one SQLite vault file
- one random master key
- multiple keyslots that can unwrap that master key

That lets the project add stronger recovery later, such as mnemonic or split-secret recovery, without reworking encrypted item storage.
