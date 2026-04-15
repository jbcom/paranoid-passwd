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

## Verify the Release Artifact Manually

If you download an archive directly from GitHub Releases:

```bash
TAG=$(gh release view --repo jbcom/paranoid-passwd --json tagName --jq .tagName)
VERSION="${TAG#paranoid-passwd-v}"
gh release download "$TAG" --repo jbcom/paranoid-passwd \
  -p "paranoid-passwd-${VERSION}-linux-amd64.tar.gz" \
  -p "checksums.txt"
grep "paranoid-passwd-${VERSION}-linux-amd64.tar.gz$" checksums.txt | sha256sum -c -
gh attestation verify "paranoid-passwd-${VERSION}-linux-amd64.tar.gz" --owner jbcom
```

On macOS, replace `sha256sum -c -` with `shasum -a 256 -c -`.

## Validate the Installer Surface Locally

If you have already built a local release directory:

```bash
make release-validate
```

That replays the same installer, checksum, and package-manifest validation path used by the release workflow.
