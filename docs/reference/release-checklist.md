---
title: Release Checklist
---

# Release Checklist

Use this checklist before and after cutting a release from `main`.

## Before Tagging

1. Confirm `main` branch protection matches the Rust-native required checks.

   ```bash
   make verify-branch-protection
   ```

2. Run the local merge-equivalent gates.

   ```bash
   make verify-assurance
   make ci
   ```

3. Exercise the checked-in release packaging path.

   ```bash
   make smoke-release
   make release-emulate
   ```

4. Confirm the docs/download surface still builds and link-checks cleanly.

   ```bash
   make docs-check
   ```

5. Confirm the security assurance report can be generated for the candidate.

   ```bash
   python3 scripts/security_assurance_gate.py \
     --json-out dist/security-assurance-report.json \
     --markdown-out dist/security-assurance-report.md
   ```

6. If you are validating an already-published tag, verify the public release surface directly.

   ```bash
   make verify-published-release TAG=paranoid-passwd-v3.7.0
   ```

## After Publishing

1. Verify that the release workflow produced every expected CLI and GUI artifact plus `checksums.txt`, including Linux `.deb` packages, macOS GUI `.dmg` images, and the Windows GUI `.msi`.
2. Verify that payload-layout validation passed for every archive, `.dmg`, Debian package, and MSI package, not just the host-runnable smoke artifacts.
3. Verify there are no stale browser-era or otherwise unexpected assets attached to the release.
4. Verify GitHub attestation for at least one downloaded artifact from each packaging family you ship.
5. Re-run installer validation against the published release surface if needed.
6. Confirm Homebrew, Scoop, and Chocolatey manifests were generated and published through their PR flow.
7. Do not describe artifacts as platform-signed unless the matching platform checks in
   [Platform Installers and Signing](./platform-installers.md) passed for the published release.
8. When validating a platform-signed release candidate, run the release validation path with
   `PARANOID_RELEASE_SIGNING_MODE=signed` on hosts that can verify the relevant platform signature.
9. For macOS signed candidates, confirm the release workflow imported the Developer ID certificate
   and that `scripts/macos_sign_notarize.sh` signed/notarized both `Paranoid Passwd.app` and the
   GUI `.dmg` before publication.
10. For Windows signed candidates, confirm the release workflow imported the signing certificate
    into the current-user certificate store, that `scripts/windows_sign_artifact.sh` signed the
    staged GUI executable before WiX packaging, and that it signed and verified the GUI `.msi`
    before publication.

## Canary Expectations

The first release after a pipeline change should be treated as a canary:

- inspect the archive matrix
- inspect the Debian package set
- inspect the macOS GUI `.dmg` set
- inspect the Windows GUI `.msi`
- verify the checksums
- verify provenance
- verify `install.sh`
- confirm the docs download links resolve
- confirm the public docs still describe unsigned artifacts as checksummed and attested, not as
  platform-signed

If any of those fail, treat the release pipeline as untrusted until the failure is fixed and the validation path passes again.
