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

5. Confirm the tracked human-review inventory still matches the source tree.

   ```bash
   make verify-human-review
   ```

6. If you are validating an already-published tag, verify the public release surface directly.

   ```bash
   make verify-published-release TAG=paranoid-passwd-v3.5.2
   ```

## After Publishing

1. Verify that the release workflow produced every expected CLI and GUI artifact plus `checksums.txt`, including Linux `.deb` packages and the macOS GUI `.dmg` images.
2. Verify that payload-layout validation passed for every archive, `.dmg`, and Debian package, not just the host-runnable smoke artifacts.
3. Verify there are no stale browser-era or otherwise unexpected assets attached to the release.
4. Verify GitHub attestation for at least one downloaded artifact from each packaging family you ship.
5. Re-run installer validation against the published release surface if needed.
6. Confirm Homebrew, Scoop, and Chocolatey manifests were generated and published through their PR flow.

## Canary Expectations

The first release after a pipeline change should be treated as a canary:

- inspect the archive matrix
- inspect the Debian package set
- inspect the macOS GUI `.dmg` set
- verify the checksums
- verify provenance
- verify `install.sh`
- confirm the docs download links resolve

If any of those fail, treat the release pipeline as untrusted until the failure is fixed and the validation path passes again.
