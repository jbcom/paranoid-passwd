---
title: Install and Verify
---

# Install and Verify

## Install with `install.sh`

Install the latest compatible release:

```bash
curl -sSL https://paranoid-passwd.com/install.sh | sh
```

Pin a specific version:

```bash
curl -sSL https://paranoid-passwd.com/install.sh | sh -s -- --version paranoid-passwd-v3.5.2
```

Install into a custom directory:

```bash
curl -sSL https://paranoid-passwd.com/install.sh | sh -s -- --install-dir "$HOME/.local/bin"
```

## Verify the Installed Binary

```bash
paranoid-passwd --version
paranoid-passwd --cli --length 20 --count 2 --no-audit --quiet
paranoid-passwd vault help
```

`install.sh` installs `paranoid-passwd` only. If you download the GUI artifact directly from GitHub Releases, verify it with:

```bash
paranoid-passwd-gui --version
paranoid-passwd-gui --help
```

On macOS, the GUI archive now unpacks to `Paranoid Passwd.app`, with the executable at `Paranoid Passwd.app/Contents/MacOS/paranoid-passwd-gui`.

On macOS, the GUI `.dmg` image is also published. Inspect and mount it with:

```bash
hdiutil verify paranoid-passwd-gui-<version>-darwin-arm64.dmg
hdiutil attach paranoid-passwd-gui-<version>-darwin-arm64.dmg
```

On Linux, the direct `.deb` packages are also published. Inspect them before install with:

```bash
dpkg-deb -c paranoid-passwd_<version>_amd64.deb
dpkg-deb -c paranoid-passwd-gui_<version>_amd64.deb
```

## Verify the Release Artifact Manually

If you download release artifacts directly from GitHub Releases:

```bash
TAG=$(gh release view --repo jbcom/paranoid-passwd --json tagName --jq .tagName)
VERSION="${TAG#paranoid-passwd-v}"
gh release download "$TAG" --repo jbcom/paranoid-passwd \
  -p "paranoid-passwd-${VERSION}-linux-amd64.tar.gz" \
  -p "paranoid-passwd_${VERSION}_amd64.deb" \
  -p "paranoid-passwd-gui-${VERSION}-linux-amd64.tar.gz" \
  -p "paranoid-passwd-gui_${VERSION}_amd64.deb" \
  -p "paranoid-passwd-gui-${VERSION}-darwin-arm64.dmg" \
  -p "checksums.txt"
grep "paranoid-passwd-${VERSION}-linux-amd64.tar.gz$" checksums.txt | sha256sum -c -
grep "paranoid-passwd_${VERSION}_amd64.deb$" checksums.txt | sha256sum -c -
grep "paranoid-passwd-gui-${VERSION}-linux-amd64.tar.gz$" checksums.txt | sha256sum -c -
grep "paranoid-passwd-gui_${VERSION}_amd64.deb$" checksums.txt | sha256sum -c -
grep "paranoid-passwd-gui-${VERSION}-darwin-arm64.dmg$" checksums.txt | shasum -a 256 -c -
gh attestation verify "paranoid-passwd-${VERSION}-linux-amd64.tar.gz" --owner jbcom
gh attestation verify "paranoid-passwd-gui-${VERSION}-linux-amd64.tar.gz" --owner jbcom
gh attestation verify "paranoid-passwd_${VERSION}_amd64.deb" --owner jbcom
gh attestation verify "paranoid-passwd-gui_${VERSION}_amd64.deb" --owner jbcom
gh attestation verify "paranoid-passwd-gui-${VERSION}-darwin-arm64.dmg" --owner jbcom
```

On macOS, replace `sha256sum -c -` with `shasum -a 256 -c -`.

## Validate the Installer Surface Locally

If you have already built a local release directory:

```bash
make release-validate
```

That replays the same installer, checksum, and package-manifest validation path used by the release workflow.
