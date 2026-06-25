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
- Windows GUI `.msi` installers built with WiX Toolset
- Linux `.deb` packages for both binaries
- `checksums.txt`
- GitHub build provenance attestations
- generated Homebrew, Scoop, and Chocolatey package-manager metadata

The release workflow validates payload layout, installer scripts, package
metadata, checksums, and host-runnable smoke paths through repo-owned scripts.
GitHub artifact attestations are build provenance evidence. They are not a
substitute for platform code signing.

`scripts/verify_platform_signing.sh` is now part of release validation. Its
default `unsigned` mode records the current boundary: artifacts are checksummed
and attested, not platform-signed. `PARANOID_RELEASE_SIGNING_MODE=signed` is a
fail-closed mode for future signed releases; it requires a host that can perform
the relevant platform verification instead of silently accepting unsigned
payloads.

`scripts/macos_sign_notarize.sh` is the credential-gated macOS build helper. It
signs and notarizes only when `PARANOID_RELEASE_SIGNING_MODE=signed`; unsigned
local emulation remains an explicit no-op. Signed mode requires
`PARANOID_MACOS_CODESIGN_IDENTITY` plus either
`PARANOID_MACOS_NOTARY_KEYCHAIN_PROFILE` or the
`PARANOID_MACOS_NOTARY_KEY_PATH`, `PARANOID_MACOS_NOTARY_KEY_ID`, and
`PARANOID_MACOS_NOTARY_ISSUER` App Store Connect API key credential set. The
release workflow can import a Developer ID certificate from
`PARANOID_MACOS_CERTIFICATE_P12_BASE64` and
`PARANOID_MACOS_CERTIFICATE_PASSWORD`, then materialize
`PARANOID_MACOS_NOTARY_KEY_P8_BASE64` into a temporary `.p8` file before the
helper runs. App-specific passwords are not passed to `notarytool submit` as
command-line arguments.

`scripts/windows_sign_artifact.sh` is the credential-gated Windows signing
helper. It signs only when `PARANOID_RELEASE_SIGNING_MODE=signed`; unsigned
local emulation remains an explicit no-op. Signed mode requires a Windows host,
`signtool`, and `PARANOID_WINDOWS_SIGNTOOL_CERT_SHA1` for a certificate already
imported into the current user's certificate store. The release workflow can
import that certificate from `PARANOID_WINDOWS_CERTIFICATE_PFX_BASE64` and
`PARANOID_WINDOWS_CERTIFICATE_PASSWORD`, then pass only the imported
certificate thumbprint to the helper. PFX passwords are not accepted by the
helper and are not passed to `signtool` as command-line arguments.

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
Linux release aggregation may defer signed macOS checks only when a paired macOS
published-release verification job is responsible for running `codesign`,
`spctl`, `stapler`, and `hdiutil` against the downloaded artifacts.

The CLI/TUI binary stays archive-first and Homebrew-distributed for now. A
macOS `.pkg` is deferred until there is a concrete install-management need that
justifies another package surface.

## Windows Decision

The selected Windows GUI installer path is WiX Toolset MSI. The MSI is the
first native Windows installer surface because it is auditable, familiar to
enterprise deployment tooling, and does not require Store-style packaging.

The release workflow installs the pinned WiX .NET tool version declared by
`PARANOID_WIX_VERSION`, builds
`paranoid-passwd-gui-<version>-windows-amd64.msi`, validates the MSI payload on
a Windows host through administrative extraction, and includes the MSI in
checksums and GitHub artifact attestations. Linux release aggregation may defer
MSI payload extraction only when the paired Windows published-release
verification job is responsible for the MSI payload and smoke checks.

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

Signed Windows release builds sign the staged GUI executable before WiX binds it
into the MSI, then sign and verify the MSI after creation. Unsigned MSI output
must remain labeled as unsigned/checksummed/attested.

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
- validation scripts inspect the package layout and signature state through
  `scripts/verify_platform_signing.sh`
- macOS signed release builds run `scripts/macos_sign_notarize.sh` for the `.app`
  before archive/DMG creation and for the `.dmg` after image creation
- Windows release builds create the GUI MSI with WiX and run
  `scripts/windows_sign_artifact.sh` for the staged executable and MSI when
  signed mode is requested
- published-release verification downloads and verifies the released artifact
- docs name the actual shipped path without overclaiming
- credentials are optional for local unsigned emulation but mandatory when a
  signed release mode is requested
- Linux validation continues through the Wolfi builder instead of replacing it
  with runner-local package installs

This document closes the installer technology decision and records the current
macOS and Windows implementation boundaries. It does not claim platform-signed
or notarized artifacts unless signed release mode and the matching host
verification jobs pass for the published release.
