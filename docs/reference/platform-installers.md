---
title: Platform Installers and Signing
---

# Platform Installers and Signing

This document is the release-boundary decision record for native installers,
code signing, notarization, and package formats. It separates the current
checksummed and attested release surface from future platform code-signing
claims.

## Current Release Surface

GitHub Releases currently ship:

- direct CLI/TUI archives for Linux, macOS, and Windows
- direct GUI archives for Linux, macOS, and Windows
- macOS GUI `.dmg` images containing `Paranoid Passwd.app`
- Linux `.deb` packages for both binaries
- `checksums.txt`
- GitHub build provenance attestations
- generated Homebrew, Scoop, and Chocolatey package-manager metadata

The release workflow validates payload layout, installer scripts, package
metadata, checksums, and host-runnable smoke paths through repo-owned scripts.
GitHub artifact attestations are build provenance evidence. They are not a
substitute for platform code signing.

The current release line has no Developer ID app signing, no Apple
notarization, no stapled notarization ticket, no Windows Authenticode-signed
installer, no MSIX package, no Flatpak package, and no AppImage package.

## Claim Boundary

Use precise release language:

- Current releases are checksummed and attested native archives plus `.dmg` and
  `.deb` packages.
- Current releases are not platform-signed or notarized.
- Do not describe current artifacts as signed native archives.
- Do not describe GitHub artifact attestations as code signatures.

Future docs may claim platform signing only after the matching release workflow
and published-release verifier enforce it.

## macOS Decision

The selected macOS path is:

1. sign `Paranoid Passwd.app` with a Developer ID Application identity
2. create the GUI `.dmg` from the signed `.app`
3. notarize the `.app` and/or `.dmg` with `notarytool`
4. staple the ticket before publishing
5. verify the published payload with platform checks

The expected verification commands are:

```bash
codesign --verify --deep --strict "Paranoid Passwd.app"
spctl --assess --type execute -vv "Paranoid Passwd.app"
xcrun stapler validate "Paranoid Passwd.app"
hdiutil verify paranoid-passwd-gui-<version>-darwin-arm64.dmg
```

The release workflow must fail closed when signing mode is requested and the
required credentials are missing. Unsigned local release emulation may continue
to exist, but unsigned output must stay labeled as unsigned.

The CLI/TUI binary stays archive-first and Homebrew-distributed for now. A
macOS `.pkg` is deferred until there is a concrete install-management need that
justifies another package surface.

## Windows Decision

The selected Windows GUI installer path is WiX Toolset MSI. The MSI should be
the first native Windows installer surface because it is auditable, familiar to
enterprise deployment tooling, and does not require Store-style packaging.

The installer must preserve the same local vault and keyslot behavior as the
zip artifact. Installer tests should verify that vault creation, unlock, backup
restore, and recovery posture behave the same after installation as they do from
the direct archive.

The Windows signing path should use Authenticode for the installer and any
signed executable payloads. Acceptable credential backends include a certificate
made available to the release workflow or Azure Trusted Signing. The published
payload verifier should include:

```powershell
signtool verify /pa paranoid-passwd-gui-<version>-windows-amd64.msi
```

MSIX deferred unless a real Store, sandbox, or managed-update requirement
appears. The CLI/TUI binary remains zip-first plus Scoop and Chocolatey metadata.

## Linux Decision

Linux keeps `.deb` as the first-class native package format. The package must
remain verifiable through the repo-owned payload-inspection model and should
continue to be validated in the Wolfi-based builder path.

No additional Linux desktop package is required for the current release line.
If desktop distribution demand requires another format, prefer Flatpak over
AppImage because Flatpak has a clearer sandbox and repository model. AppImage
remains deferred unless portability becomes more important than managed
repository integration. Any added Linux package format must get the same
scripted payload validation, checksum coverage, and published-release
verification as the existing archives and `.deb` packages.

## Implementation Standard

Installer/signing work is not complete until:

- build scripts create the installer or signed payload in-repo
- validation scripts inspect the package layout and signature state
- published-release verification downloads and verifies the released artifact
- docs name the actual shipped path without overclaiming
- credentials are optional for local unsigned emulation but mandatory when a
  signed release mode is requested
- Linux validation continues through the Wolfi builder instead of replacing it
  with runner-local package installs

This document closes the installer technology decision. It does not claim that
macOS signing/notarization or the Windows MSI implementation has shipped yet.
