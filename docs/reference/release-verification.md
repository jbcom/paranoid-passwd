---
title: Release Verification
---

# Release Verification

## Local Emulation

Use the checked-in release scripts before you cut a tag:

```bash
make verify-branch-protection
make smoke-release
make release-emulate
```

`make verify-branch-protection` catches stale required-check policies before they block or silently weaken the release line.

`make smoke-release` packages and verifies the host-native CLI and GUI release artifacts. On Linux hosts that includes both the direct archives and the `.deb` packages. On macOS hosts that includes the direct archives and the GUI `.dmg` image. The smoke path includes checked-in payload-layout validation before any executable smoke assertions run.

`make release-emulate` runs the Linux amd64 release path through the repository-owned builder container, including the Debian package outputs.

## Verify a Published Release End to End

If a tag is already published, use the checked-in verifier instead of replaying the commands manually:

```bash
make verify-published-release TAG=paranoid-passwd-v3.5.2
```

That script verifies:

- the exact expected asset set
- checksum integrity for every published CLI and GUI artifact, including Linux `.deb` packages and macOS GUI `.dmg` images
- expected payload layout for every published CLI and GUI artifact, including macOS `.app` bundles inside archives and `.dmg` images, Linux GUI desktop metadata, and Debian package filesystem roots
- GitHub attestation for the host-native downloadable artifacts, including Linux `.deb` packages on Linux hosts and the GUI `.dmg` image on macOS hosts
- the host-native smoke path through `scripts/smoke_test_release_artifact.sh` for both binaries and, on Linux hosts, both `.deb` packages, and on macOS hosts, the GUI `.dmg` image

## Download a Release

```bash
TAG=$(gh release view --repo jbcom/paranoid-passwd --json tagName --jq .tagName)
VERSION="${TAG#paranoid-passwd-v}"
gh release download "$TAG" --repo jbcom/paranoid-passwd \
  -p "paranoid-passwd-${VERSION}-darwin-arm64.tar.gz" \
  -p "paranoid-passwd-gui-${VERSION}-darwin-arm64.tar.gz" \
  -p "paranoid-passwd-gui-${VERSION}-darwin-arm64.dmg" \
  -p "checksums.txt"
```

## Verify the Checksum

```bash
grep "paranoid-passwd-${VERSION}-darwin-arm64.tar.gz$" checksums.txt | shasum -a 256 -c
grep "paranoid-passwd-gui-${VERSION}-darwin-arm64.tar.gz$" checksums.txt | shasum -a 256 -c
grep "paranoid-passwd-gui-${VERSION}-darwin-arm64.dmg$" checksums.txt | shasum -a 256 -c
```

On Linux:

```bash
grep "paranoid-passwd-${VERSION}-linux-amd64.tar.gz$" checksums.txt | sha256sum -c
grep "paranoid-passwd_${VERSION}_amd64.deb$" checksums.txt | sha256sum -c
grep "paranoid-passwd-gui-${VERSION}-linux-amd64.tar.gz$" checksums.txt | sha256sum -c
grep "paranoid-passwd-gui_${VERSION}_amd64.deb$" checksums.txt | sha256sum -c
```

## Verify GitHub Attestation

```bash
gh attestation verify "paranoid-passwd-${VERSION}-darwin-arm64.tar.gz" --owner jbcom
gh attestation verify "paranoid-passwd-gui-${VERSION}-darwin-arm64.tar.gz" --owner jbcom
gh attestation verify "paranoid-passwd-gui-${VERSION}-darwin-arm64.dmg" --owner jbcom
```

This ties the archives back to the GitHub Actions workflow run that produced them.

On Linux, the same applies to the `.deb` packages:

```bash
gh attestation verify "paranoid-passwd_${VERSION}_amd64.deb" --owner jbcom
gh attestation verify "paranoid-passwd-gui_${VERSION}_amd64.deb" --owner jbcom
```

## Verify the Installer Surface

The release workflow also validates `docs/public/install.sh` against a local HTTP server backed by the built archives. If you already have a complete release dist directory locally, you can rerun that validation with:

```bash
bash scripts/release_validate.sh "$VERSION" dist/release
```
