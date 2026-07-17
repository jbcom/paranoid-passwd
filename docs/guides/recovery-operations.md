---
title: Recovery Operations
---

# Recovery Operations

This runbook covers normal vault recovery maintenance. It is written for the current local-first
product line: the operator owns the vault file, recovery material, certificate lifecycle, and
release evidence for the environment where the vault runs.

Run lifecycle commands with durable audit evidence when the environment requires an operation log:

```bash
VAULT="$HOME/.local/share/paranoid-passwd/vault.sqlite"
export PARANOID_MASTER_PASSWORD="current recovery secret"

paranoid-passwd vault --cli --path "$VAULT" --audit-jsonl vault-ops.jsonl keyslots
paranoid-passwd vault --cli --path "$VAULT" seal-status --probe-providers
```

`keyslots` shows recovery posture, keyslot type, labels, certificate metadata, and health warnings.
`seal-status` reports non-secret seal posture. Add `--probe-providers` only when you want the process
to perform live provider checks, such as verifying that a device-bound secure-storage value can still
unwrap the current slot.

## Recovery Paths

Keep at least two independent recovery paths. Device-bound unlock is useful for daily local use, but
it is not portable disaster recovery because backup packages do not include the platform
secure-storage secret.

| Path | Purpose | Portable | Operator action |
| --- | --- | --- | --- |
| Recovery secret | Baseline unlock and scripted administration | Yes, if stored separately | Rotate with `rotate-recovery-secret` |
| Mnemonic recovery | Offline paper or vault-safe recovery | Yes, if the 24-word phrase is stored separately | Rotate with `rotate-mnemonic-slot` |
| Certificate-wrapped | Controlled unlock with deployment-owned key custody | Yes, if the private key remains available | Rollover with `rewrap-cert-slot` |
| Device-bound | Daily passwordless unlock on one device/account | No | Rebind with `rebind-device-slot` after device or account changes |

## Add Recovery Keyslots

Add a mnemonic recovery slot before relying on passwordless or certificate-only operation:

```bash
paranoid-passwd vault --cli --path "$VAULT" add-mnemonic-slot --label paper-backup
paranoid-passwd vault --cli --path "$VAULT" keyslots
```

The command prints the 24-word phrase once. Store it outside the device and do not place it in a
backup package, transfer package, shell history, ticket, or chat transcript.

Add a device-bound slot only for the device/account that will use daily passwordless unlock:

```bash
paranoid-passwd vault --cli --path "$VAULT" add-device-slot --label daily-laptop
paranoid-passwd vault --cli --path "$VAULT" seal-status --probe-providers
```

Add a certificate-wrapped slot only after previewing the recipient certificate:

```bash
paranoid-passwd vault --cli --path "$VAULT" inspect-certificate --cert recipient.pem
paranoid-passwd vault --cli --path "$VAULT" add-cert-slot --cert recipient.pem --label ops-cert
```

Certificate slots depend on deployment-owned certificate issuance, private-key protection,
expiration monitoring, and revocation or replacement process. The vault records public certificate
metadata and health warnings, but it does not operate a PKI.

## Rotate Recovery Material

Rotate the recovery secret when the baseline unlock secret changes:

```bash
export PARANOID_NEXT_MASTER_PASSWORD="new recovery secret"
paranoid-passwd vault --cli --path "$VAULT" rotate-recovery-secret \
  --new-password-env PARANOID_NEXT_MASTER_PASSWORD
```

Verify that the old secret no longer unlocks the vault and the new secret does. Existing mnemonic,
device-bound, and certificate-wrapped slots stay in place.

Rotate a mnemonic slot when the phrase has been copied too widely, stored in the wrong place, or
replaced as part of a scheduled recovery drill:

```bash
paranoid-passwd vault --cli --path "$VAULT" keyslots
paranoid-passwd vault --cli --path "$VAULT" rotate-mnemonic-slot --id "$MNEMONIC_SLOT_ID"
```

The replacement phrase is shown once. After rotation, the old phrase must fail to unlock the vault
and the replacement phrase must succeed:

```bash
export PARANOID_RECOVERY_PHRASE="replacement 24 word phrase ..."
paranoid-passwd vault --cli --path "$VAULT" \
  --recovery-phrase-env PARANOID_RECOVERY_PHRASE \
  list
```

Rebind a device-bound slot after operating-system account migration, secure-storage reset, or device
replacement:

```bash
paranoid-passwd vault --cli --path "$VAULT" rebind-device-slot --id "$DEVICE_SLOT_ID"
paranoid-passwd vault --cli --path "$VAULT" --device-slot "$DEVICE_SLOT_ID" list
```

The rebind writes a fresh platform secure-storage value for the same keyslot id. It does not make
old backups portable to a different device-bound provider.

## Certificate Expiration And Rollover

Inspect certificate slot health during regular recovery drills:

```bash
paranoid-passwd vault --cli --path "$VAULT" keyslots
paranoid-passwd vault --cli --path "$VAULT" inspect-keyslot --id "$CERT_SLOT_ID"
```

If a recipient certificate is near expiry, expired, or being replaced, preview the new certificate
and rewrap the existing slot:

```bash
paranoid-passwd vault --cli --path "$VAULT" inspect-certificate --cert replacement.pem
paranoid-passwd vault --cli --path "$VAULT" rewrap-cert-slot \
  --id "$CERT_SLOT_ID" \
  --cert replacement.pem
```

After rollover, the previous certificate/private-key pair should no longer unlock that slot and the
replacement certificate/private-key pair should. Revocation checks, certificate authority policy,
hardware-backed key custody, and emergency access approval remain deployment responsibilities.

## Backup And Restore

Use backup packages for full encrypted vault recovery or migration. Backup export preserves the
vault header, encrypted item rows, keyslot metadata, and ciphertext. It does not decrypt records into
a new format, and it does not include mnemonic phrases, certificate private keys, raw certificate
transport keys, or device secure-storage secrets.

```bash
paranoid-passwd vault --cli --path "$VAULT" export-backup --output vault.backup.json
paranoid-passwd vault --cli --path "$VAULT" inspect-backup --input vault.backup.json
```

`--output` must not resolve to the same file as `--path`: export fails closed with a typed error rather
than overwriting the source vault, and the write itself is atomic (temp file in the destination
directory, then renamed into place), so an interrupted export never leaves a partial file behind.

Restore into a new path first when you are testing a backup:

```bash
RESTORE_VAULT="$PWD/restore.sqlite"
paranoid-passwd vault --cli --path "$RESTORE_VAULT" import-backup --input vault.backup.json
PARANOID_MASTER_PASSWORD="current recovery secret" \
  paranoid-passwd vault --cli --path "$RESTORE_VAULT" list
```

Use `import-backup --force` only when you have intentionally chosen to overwrite the target vault
path. Treat a same-device device-bound unlock after restore as a convenience check, not as proof that
the backup is portable.

## Transfer Packages

Use transfer packages to move selected decrypted records into an already unlocked destination vault.
Transfers are not full-vault backups: they do not copy the source vault keyslots, device-bound
provider assumptions, or recovery posture.

Export a selected package with either a package password, a recipient certificate, or both:

```bash
export PARANOID_TRANSFER_PASSWORD="temporary transfer package secret"

paranoid-passwd vault --cli --path "$VAULT" export-transfer \
  --output selected.transfer.ppvt.json \
  --kind login \
  --folder Work \
  --tag code \
  --package-password-env PARANOID_TRANSFER_PASSWORD \
  --package-cert recipient.pem

paranoid-passwd vault --cli --path "$VAULT" inspect-transfer \
  --input selected.transfer.ppvt.json
```

Import with the unwrap path intended for the destination operator:

```bash
paranoid-passwd vault --cli --path "$DEST_VAULT" import-transfer \
  --input selected.transfer.ppvt.json \
  --package-password-env PARANOID_TRANSFER_PASSWORD

paranoid-passwd vault --cli --path "$DEST_VAULT" import-transfer \
  --input selected.transfer.ppvt.json \
  --package-cert recipient.pem \
  --package-key recipient-key.pem
```

By default, conflicting item ids are remapped instead of silently replacing destination records. Use
`--replace-existing` only when the transfer is intended to update existing records.

## Disaster Recovery Drill

Run a recovery drill before you need it:

1. Export and inspect a backup.
2. Restore the backup into a new vault path.
3. Unlock the restored vault with the recovery secret.
4. Unlock with the current mnemonic phrase.
5. Unlock with the current certificate/private-key pair when a certificate slot exists.
6. Confirm device-bound unlock only on the same device/account after provider probing.
7. Export and import one selected transfer package into a separate destination vault.
8. Save the command transcript, `vault-ops.jsonl`, backup summary, transfer summary, and release
   version used for the drill.

That evidence distinguishes encrypted backup/restore, selected-item transfer, daily passwordless
unlock, and disaster recovery. The paths are related, but they are not interchangeable.

## Federal-Ready Boundary

Strict federal-ready policy treats password recovery, mnemonic recovery, and device-bound unlock as
default-profile methods. Certificate-wrapped unlock is the current controlled federal-ready path, and
it still requires approved-provider evidence, a writable audit sink, seal posture evidence, and fresh
operator proof.

Use the evidence commands to document the selected profile without claiming authorization:

```bash
paranoid-passwd --federal-evidence
paranoid-passwd vault --cli --path "$VAULT" federal-evidence
```

The project can support customers operating inside FedRAMP High, GovCloud, or DoD IL5-oriented
boundaries, but the local tool is not itself FedRAMP authorized, DoD IL5 authorized, or a FIPS
validated product.

