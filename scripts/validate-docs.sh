#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required=(
  "$REPO_ROOT/docs/conf.py"
  "$REPO_ROOT/docs/index.md"
  "$REPO_ROOT/docs/getting-started/index.md"
  "$REPO_ROOT/docs/getting-started/downloads.md"
  "$REPO_ROOT/docs/getting-started/install-and-verify.md"
  "$REPO_ROOT/docs/guides/tui.md"
  "$REPO_ROOT/docs/guides/recovery-operations.md"
  "$REPO_ROOT/docs/reference/index.md"
  "$REPO_ROOT/docs/reference/architecture.md"
  "$REPO_ROOT/docs/reference/messaging.md"
  "$REPO_ROOT/docs/reference/security-assurance.md"
  "$REPO_ROOT/docs/reference/assurance-claims.md"
  "$REPO_ROOT/docs/reference/platform-installers.md"
  "$REPO_ROOT/docs/reference/release-checklist.md"
  "$REPO_ROOT/docs/reference/testing.md"
  "$REPO_ROOT/docs/reference/supply-chain.md"
  "$REPO_ROOT/docs/reference/release-verification.md"
  "$REPO_ROOT/docs/api/index.md"
  "$REPO_ROOT/docs/public/install.sh"
  "$REPO_ROOT/scripts/verify_published_release.sh"
  "$REPO_ROOT/scripts/verify_platform_signing.sh"
  "$REPO_ROOT/scripts/macos_sign_notarize.sh"
  "$REPO_ROOT/scripts/windows_sign_artifact.sh"
  "$REPO_ROOT/tests/test_platform_signing_verify.sh"
)

for file in "${required[@]}"; do
  test -f "$file"
done

grep -q "paranoid-passwd-<version>-linux-amd64.tar.gz" "$REPO_ROOT/docs/getting-started/index.md"
grep -q "downloads" "$REPO_ROOT/docs/getting-started/index.md"
grep -q "install-and-verify" "$REPO_ROOT/docs/getting-started/index.md"
grep -q "crates/paranoid_core/lib" "$REPO_ROOT/docs/api/index.md"
grep -q "install.sh" "$REPO_ROOT/docs/index.md"
grep -q "guides/recovery-operations" "$REPO_ROOT/docs/index.md"
grep -q "verify-assurance" "$REPO_ROOT/docs/reference/release-checklist.md"
grep -q "verify-branch-protection" "$REPO_ROOT/docs/reference/release-checklist.md"
grep -q "verify-published-release" "$REPO_ROOT/docs/reference/release-verification.md"
grep -q "quality-emulate" "$REPO_ROOT/docs/reference/testing.md"
grep -q "quality-emulate" "$REPO_ROOT/docs/reference/supply-chain.md"
grep -q "cargo-audit" "$REPO_ROOT/docs/reference/supply-chain.md"
grep -q "RustSec advisory DB" "$REPO_ROOT/docs/reference/supply-chain.md"
grep -q "platform-installers" "$REPO_ROOT/docs/reference/index.md"
grep -q "checksummed and attested native archives" "$REPO_ROOT/docs/index.md"
if grep -q "signed native archives" "$REPO_ROOT/docs/index.md"; then
  echo "docs/index.md must not claim signed native archives" >&2
  exit 1
fi
grep -q "no Developer ID app signing" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "no Apple" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "scripts/verify_platform_signing.sh" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "scripts/macos_sign_notarize.sh" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "PARANOID_RELEASE_SIGNING_MODE=signed" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "PARANOID_MACOS_CODESIGN_IDENTITY" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "PARANOID_MACOS_NOTARY_KEYCHAIN_PROFILE" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "PARANOID_MACOS_NOTARY_KEY_PATH" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "PARANOID_MACOS_NOTARY_KEY_P8_BASE64" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "App-specific passwords are not passed to" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "PARANOID_WINDOWS_SIGNTOOL_CERT_SHA1" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "PARANOID_WINDOWS_CERTIFICATE_PFX_BASE64" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "PFX passwords are not accepted" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "https://timestamp.digicert.com" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "D95336DD2022934D80E3F3A4F938DD66EC7076BBBA680F76C11F2B54B346D61D" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -Fq 'Package Id="*"' "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "PARANOID_RELEASE_SIGNING_ALLOW_HOST_DEFERRED=1" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "Developer ID Application" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "notarytool" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "stapler validate" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "WiX Toolset MSI" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "PARANOID_WIX_VERSION" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "windows_sign_artifact.sh" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "signtool verify /pa" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "MSIX deferred" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "Flatpak" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "AppImage" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "verify_platform_signing.sh" "$REPO_ROOT/scripts/release_validate.sh"
grep -q "test-platform-signing-boundary" "$REPO_ROOT/Makefile"
grep -q "add-mnemonic-slot" "$REPO_ROOT/docs/guides/recovery-operations.md"
grep -q "rotate-mnemonic-slot" "$REPO_ROOT/docs/guides/recovery-operations.md"
grep -q "rewrap-cert-slot" "$REPO_ROOT/docs/guides/recovery-operations.md"
grep -q "rebind-device-slot" "$REPO_ROOT/docs/guides/recovery-operations.md"
grep -q "export-backup" "$REPO_ROOT/docs/guides/recovery-operations.md"
grep -q "import-backup" "$REPO_ROOT/docs/guides/recovery-operations.md"
grep -q "export-transfer" "$REPO_ROOT/docs/guides/recovery-operations.md"
grep -q "import-transfer" "$REPO_ROOT/docs/guides/recovery-operations.md"
grep -q "daily passwordless unlock" "$REPO_ROOT/docs/guides/recovery-operations.md"
grep -q "disaster recovery" "$REPO_ROOT/docs/guides/recovery-operations.md"

workspace_version="$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^\s*version\s*=\s*"([^"]+)".*/\1/p}' -E "$REPO_ROOT/Cargo.toml" | head -n1)"
# Lines marked with the "docs-version-history" marker document past releases on
# purpose (e.g. "v3.7.0 did not include an MSI") and must not be flagged just
# because the workspace version has since moved on. Exclude those lines before
# checking for stale pins.
stale_pins="$(grep -rnE "paranoid-passwd-v[0-9]+\.[0-9]+\.[0-9]+" "$REPO_ROOT/docs" | grep -v -F "docs-version-history" | grep -vE "paranoid-passwd-v${workspace_version}([^0-9.]|\$)" || true)"
if [ -n "$stale_pins" ]; then
  echo "docs/ contains version pins that do not match workspace version $workspace_version:" >&2
  echo "$stale_pins" >&2
  exit 1
fi
