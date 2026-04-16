---
title: Getting Started
---

# Getting Started

```{toctree}
:maxdepth: 1

downloads
install-and-verify
```

## Download

The canonical binaries are published through [GitHub Releases](https://github.com/jbcom/paranoid-passwd/releases). Release assets keep the existing naming pattern:

- `paranoid-passwd-<version>-linux-amd64.tar.gz`
- `paranoid-passwd-<version>-linux-arm64.tar.gz`
- `paranoid-passwd-<version>-darwin-amd64.tar.gz`
- `paranoid-passwd-<version>-darwin-arm64.tar.gz`
- `paranoid-passwd-<version>-windows-amd64.zip`
- `paranoid-passwd_<version>_amd64.deb`
- `paranoid-passwd_<version>_arm64.deb`
- `paranoid-passwd-gui-<version>-linux-amd64.tar.gz`
- `paranoid-passwd-gui-<version>-linux-arm64.tar.gz`
- `paranoid-passwd-gui-<version>-darwin-amd64.tar.gz`
- `paranoid-passwd-gui-<version>-darwin-arm64.tar.gz`
- `paranoid-passwd-gui-<version>-darwin-amd64.dmg`
- `paranoid-passwd-gui-<version>-darwin-arm64.dmg`
- `paranoid-passwd-gui-<version>-windows-amd64.zip`
- `paranoid-passwd-gui_<version>_amd64.deb`
- `paranoid-passwd-gui_<version>_arm64.deb`

The docs site also serves [`/install.sh`](https://paranoid-passwd.com/install.sh), which downloads the `paranoid-passwd` CLI/TUI archive for the current Unix-like platform.

Today’s published release surface includes both `paranoid-passwd` and `paranoid-passwd-gui`. Linux publishes `.deb` packages for both, and macOS publishes `.dmg` images for the GUI. `install.sh` and package-manager flows remain scoped to `paranoid-passwd`.

## Install With `install.sh`

```bash
curl -sSL https://paranoid-passwd.com/install.sh | sh
```

You can pin a version or install into a custom directory:

```bash
curl -sSL https://paranoid-passwd.com/install.sh | sh -s -- --version paranoid-passwd-v3.5.1
curl -sSL https://paranoid-passwd.com/install.sh | sh -s -- --install-dir "$HOME/.local/bin"
```

## Package Managers

- `brew tap jbcom/tap && brew install paranoid-passwd`
- `scoop bucket add jbcom https://github.com/jbcom/pkgs && scoop install paranoid-passwd`
- `choco install paranoid-passwd`

## First Run

Interactive terminal:

```bash
paranoid-passwd
```

That launches the TUI wizard by default. Native interactive copy actions clear the clipboard after 30 seconds if the copied value is still present.

Non-interactive / scriptable usage:

```bash
paranoid-passwd --cli --length 20 --count 3 --framework nist,pci_dss
paranoid-passwd --cli --charset hex --length 64 --no-audit --quiet
```

Dedicated GUI surface:

```bash
paranoid-passwd-gui
paranoid-passwd-gui --version
```

Vault foundation:

```bash
export PARANOID_MASTER_PASSWORD='correct horse battery staple'
paranoid-passwd vault init
paranoid-passwd vault generate-store --title GitHub --username jon@example.com --length 24 --framework nist
paranoid-passwd vault add-note --title 'Emergency contact' --content 'Call +1-555-0100 after laptop rotation.' --folder Recovery --tags recovery,ops
paranoid-passwd vault add-card --title 'Primary Visa' --cardholder 'Jon Bogaty' --number 4111111111111111 --expiry-month 08 --expiry-year 2031 --security-code 123 --folder Travel --tags finance,travel
paranoid-passwd vault add-identity --title 'Personal Identity' --full-name 'Jon Bogaty' --email jon@example.com --phone +1-555-0100 --folder Identity --tags identity,travel
paranoid-passwd vault add --title GitHub --username jon@example.com --password 'Sup3r$ecret!' --folder Work --tags work,code
paranoid-passwd vault generate-store --id login-0123456789abcdef --length 24 --framework nist
paranoid-passwd vault inspect-keyslot --id device-0123456789abcdef
paranoid-passwd vault inspect-certificate --cert recipient-cert-next.pem
paranoid-passwd vault rotate-mnemonic-slot --id mnemonic-0123456789abcdef
paranoid-passwd vault rewrap-cert-slot --id cert-0123456789abcdef --cert recipient-cert-next.pem
paranoid-passwd vault rename-keyslot --id device-0123456789abcdef --label laptop-daily
paranoid-passwd vault rotate-recovery-secret --new-password-env PARANOID_NEXT_MASTER_PASSWORD
paranoid-passwd vault rebind-device-slot --id device-0123456789abcdef
paranoid-passwd vault remove-keyslot --id cert-0123456789abcdef --force
paranoid-passwd vault export-backup --output ./vault.backup.json
paranoid-passwd vault inspect-backup --input ./vault.backup.json
paranoid-passwd vault import-backup --input ./vault.backup.json --force
paranoid-passwd vault export-transfer --output ./work-logins.ppvt.json --kind login --folder Work --package-password-env PARANOID_TRANSFER_PASSWORD --package-cert recipient-cert.pem
paranoid-passwd vault inspect-transfer --input ./work-logins.ppvt.json
paranoid-passwd vault import-transfer --input ./work-logins.ppvt.json --package-password-env PARANOID_TRANSFER_PASSWORD
paranoid-passwd vault
paranoid-passwd vault list
paranoid-passwd vault list --query work
paranoid-passwd vault list --kind card --folder Travel --tag finance
```

On an interactive terminal, `paranoid-passwd vault` opens the native vault list/detail TUI when no explicit vault subcommand is passed. The unlocked CLI, TUI, and GUI all share the same vault filter model, so `vault list --query ... --kind ... --folder ... --tag ...` and the native vault views narrow the same decrypted local summaries rather than inventing separate search paths. The current item model supports `Login`, `SecureNote`, `Card`, and `Identity` entries, all four item kinds carry native folder plus tag metadata for local organization, rotated login passwords are retained as encrypted history instead of being overwritten blindly, duplicate current login passwords are flagged across the unlocked vault, generator-driven password rotation can update an existing login in place through `generate-store --id ...`, all three native surfaces now show the current recovery posture so it is obvious when certificate coverage or extra recovery paths are still missing, `vault keyslots` now emits explicit recommendations when the vault still lacks mnemonic, device-bound, or certificate coverage, `vault inspect-keyslot --id ...` exposes a headless detail view for a specific slot, `vault inspect-certificate --cert ...` exposes public certificate metadata headlessly, mnemonic slots can now be rotated in place through `rotate-mnemonic-slot --id ...` while preserving the same slot id, certificate slots can now be rewrapped in place to a replacement recipient certificate, and the native TUI/GUI rewrap flows can optionally update the active certificate key path and passphrase at the same time when the rotated slot is the live certificate-backed unlock path. Cert-backed keyslot inspection now exposes the current fingerprint, subject, and validity window before a rotation is required. The native add/rewrap certificate forms now preview the PEM path before mutation so the operator can confirm the replacement recipient cert, and the shared keyslot-health layer now flags not-yet-valid, expired, and near-expiry certificate slots consistently across CLI, TUI, GUI, and backup inspection. Keyslot labels can now be updated in place through `rename-keyslot` or the native keyslot views instead of forcing re-enrollment, headless keyslot removal now requires `--force` when a removal would weaken that posture, both native interactive surfaces mirror the same policy with two-step confirmation for risky removals, both native interactive surfaces can inspect, enroll, rotate mnemonic slots, rewrap certificate slots, relabel, rotate the password recovery secret, remove, and rebind keyslots directly, all three native surfaces now share encrypted backup export/import around the same vault header and ciphertext rows, and backup inspection is now available before restore so an operator can confirm item counts, keyslot posture, concrete keyslot summaries, certificate lifecycle metadata, and restorable format support before overwriting a local vault. For selective cross-vault exchange, CLI, TUI, and GUI now all support encrypted transfer packages that carry chosen item payloads under a fresh data key, with unwrap support for a recovery secret, a recipient certificate, or both. The native vault views auto-lock after 5 minutes of inactivity while clearing copied secrets from the clipboard after 30 seconds when unchanged.

## Build Locally

```bash
cargo build --workspace --locked --frozen --offline
cargo test --workspace --locked --frozen --offline
cargo build -p paranoid-cli --locked --frozen --offline
bash tests/test_cli.sh target/debug/paranoid-passwd
python3 -m tox -e docs
```

If you want to reproduce the CI environment from the repository root:

```bash
make ci-emulate
```

If you want to exercise the checked-in release packaging path locally:

```bash
make smoke-release
make release-emulate
```

If you are validating the release process itself instead of installing the tool, use the release checklist in [Reference → Release Checklist](../reference/release-checklist.md).
