---
title: Release Verification
---

# Release Verification

## Local Emulation

Use the checked-in release scripts before you cut a tag:

```bash
make smoke-release
make release-emulate
```

`make smoke-release` packages and verifies the host-native archive.

`make release-emulate` runs the Linux amd64 release path through the repository-owned builder container.

## Download a Release

```bash
TAG=$(gh release view --repo jbcom/paranoid-passwd --json tagName --jq .tagName)
VERSION="${TAG#paranoid-passwd-v}"
gh release download "$TAG" --repo jbcom/paranoid-passwd \
  -p "paranoid-passwd-${VERSION}-darwin-arm64.tar.gz" \
  -p "checksums.txt"
```

## Verify the Checksum

```bash
grep "paranoid-passwd-${VERSION}-darwin-arm64.tar.gz$" checksums.txt | shasum -a 256 -c
```

On Linux:

```bash
grep "paranoid-passwd-${VERSION}-linux-amd64.tar.gz$" checksums.txt | sha256sum -c
```

## Verify GitHub Attestation

```bash
gh attestation verify "paranoid-passwd-${VERSION}-darwin-arm64.tar.gz" --owner jbcom
```

This ties the archive back to the GitHub Actions workflow run that produced it.

## Verify the Installer Surface

The release workflow also validates `docs/public/install.sh` against a local HTTP server backed by the built archives. If you already have a complete release dist directory locally, you can rerun that validation with:

```bash
bash scripts/release_validate.sh "$VERSION" dist/release
```
