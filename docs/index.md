---
title: paranoid-passwd
---

# paranoid-passwd

## Local Secrets. Verifiable Trust.

`paranoid-passwd` is a **Rust-native password manager and generator** built around one
promise: secrets stay local, and trust is verified instead of assumed.

It ships native tools for daily use, scripting, and recovery operations:

- `paranoid-core` owns password generation, rejection sampling, OpenSSL-backed hashing and RNG, compliance policy, and the 7-layer audit.
- `paranoid-ops` and `paranoid-audit` provide the first typed operation and structured evidence boundary for automation-facing generator workflows.
- `paranoid-passwd` is the primary user binary. It defaults to the TUI on an interactive terminal and keeps the scriptable CLI for automation.
- `paranoid-passwd-gui` is the dedicated Slint-native GUI surface over the same generator and vault model.
- `paranoid-vault` stores encrypted local `Login`, `SecureNote`, `Card`, and `Identity` records with explicit recovery posture.
- the public website is docs and downloads only; the retired browser generator and JavaScript
  trust boundary are gone from the product surface.
- closed crypto/statistics, keyslot, ops, audit, and seal dispositions are tracked as assurance claims instead of scattered source comments.
- the project is licensed as `GPL-3.0-only`, which keeps the password manager open source
  under a reciprocal license and enables Slint's GPLv3 native GUI path.
- future Slint WASM or mobile targets must be explicit Rust/Slint surfaces with their own
  threat models and release gates.

```{toctree}
:maxdepth: 2
:caption: Docs

getting-started/index
guides/tui
guides/recovery-operations
reference/index
api/index
```

## Download Channels

- [GitHub Releases](https://github.com/jbcom/paranoid-passwd/releases) ship checksummed and attested native archives, macOS `.dmg` images for the GUI, Windows GUI `.msi` installers, Linux `.deb` packages, and checksums.
- `install.sh` is hosted at the docs site root and resolves the latest GitHub Release.
- Package-manager metadata is still generated from the release workflow for Homebrew, Scoop, and Chocolatey.
- The release pipeline now validates archive, `.dmg`, MSI, and Debian package payloads, manifest generation, and the installer surface before attesting assets.
- The current release line ships both the CLI/TUI binary and a separate GUI binary through direct archives, with Linux `.deb` packages for both and a Windows WiX `.msi` for the GUI.
- `install.sh` and package-manager flows remain focused on the CLI/TUI binary; the GUI uses direct-download artifacts and native desktop packages.
- Platform installer, code-signing, and notarization decisions are tracked in
  [Platform Installers and Signing](./reference/platform-installers.md).

## Why It Exists

- Local secrets should not depend on a browser runtime.
- Recovery should be visible before a vault is in trouble.
- Release trust should come from reproducible checks, payload inspection, checksums, and attestations.
- AI-assisted changes should be constrained by deterministic gates and explicit assurance claims.
