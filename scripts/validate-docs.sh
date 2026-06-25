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
grep -q "platform-installers" "$REPO_ROOT/docs/reference/index.md"
grep -q "checksummed and attested native archives" "$REPO_ROOT/docs/index.md"
if grep -q "signed native archives" "$REPO_ROOT/docs/index.md"; then
  echo "docs/index.md must not claim signed native archives" >&2
  exit 1
fi
grep -q "no Developer ID app signing" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "no Apple" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "Developer ID Application" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "notarytool" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "stapler validate" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "WiX Toolset MSI" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "signtool verify /pa" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "MSIX deferred" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "Flatpak" "$REPO_ROOT/docs/reference/platform-installers.md"
grep -q "AppImage" "$REPO_ROOT/docs/reference/platform-installers.md"
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
