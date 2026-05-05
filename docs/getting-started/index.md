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
curl -sSL https://paranoid-passwd.com/install.sh | sh -s -- --version paranoid-passwd-v3.6.2
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

Local vault:

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

On an interactive terminal, `paranoid-passwd vault` opens the native vault list/detail TUI
when no explicit vault subcommand is passed. The same vault engine backs the CLI, TUI,
and GUI, so behavior stays consistent across surfaces.

What the vault gives you:

- `Login`, `SecureNote`, `Card`, and `Identity` records
- folder and tag organization across all item kinds
- encrypted login password history and duplicate-password visibility
- generator-driven login creation and in-place password rotation
- structured filtering by query, kind, folder, and tag
- recovery posture warnings when mnemonic, device-bound, or certificate coverage is missing

Recovery and keyslot operations:

- inspect keyslots and certificate metadata before changing vault state
- enroll and rotate mnemonic recovery slots
- enroll, relabel, rebind, and remove device-bound slots
- enroll and rewrap certificate-wrapped slots
- rotate the password recovery secret without invalidating other recovery paths
- require extra confirmation when keyslot removal would weaken recovery posture

Backup and transfer:

- encrypted full-vault backup export/import over the existing vault header and ciphertext rows
- read-only backup inspection before restore
- encrypted selected-item transfer packages for cross-vault exchange
- recovery-secret and certificate unwrap options for transfer packages

Session hardening:

- copied secrets are cleared from the clipboard after 30 seconds when unchanged
- unlocked native vault views auto-lock after 5 minutes of inactivity

## Build Locally

```bash
cargo build --workspace --locked --frozen --offline
make test
cargo build -p paranoid-cli --locked --frozen --offline
bash tests/test_cli.sh target/debug/paranoid-passwd
make verify-assurance
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
