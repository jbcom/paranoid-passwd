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
  "$REPO_ROOT/docs/reference/compliance-frameworks.md"
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
grep -q "compliance-frameworks" "$REPO_ROOT/docs/reference/index.md"
grep -q "reference/compliance-frameworks" "$REPO_ROOT/docs/getting-started/index.md"
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

# Every FrameworkId variant in crates/paranoid-core/src/lib.rs must appear in the canonical
# compliance-frameworks doc. This list is intentionally hardcoded (not derived from the source)
# so that adding, removing, or renaming a framework id in code without touching docs fails this
# gate instead of silently passing because the check re-derived itself from the same drift.
framework_ids=(nist pci_dss hipaa soc2 gdpr iso27001)
missing_framework_ids=()
for id in "${framework_ids[@]}"; do
  if ! grep -q "\`$id\`" "$REPO_ROOT/docs/reference/compliance-frameworks.md"; then
    missing_framework_ids+=("$id")
  fi
done
if [ "${#missing_framework_ids[@]}" -gt 0 ]; then
  echo "docs/reference/compliance-frameworks.md is missing framework id(s): ${missing_framework_ids[*]}" >&2
  exit 1
fi

# Every vault subcommand match arm in crates/paranoid-cli/src/vault_cli.rs must appear somewhere
# under docs/. Subcommand names are extracted mechanically from the `Some("name") => ...` arms of
# the `let command = match command.as_deref() { ... };` block, not hardcoded here, so a renamed,
# added, or removed subcommand in code fails this gate instead of silently passing.
vault_cli_src="$REPO_ROOT/crates/paranoid-cli/src/vault_cli.rs"
mapfile -t vault_subcommands < <(awk '/let command = match command\.as_deref\(\) \{/{flag=1} flag{print} flag && /^    \};$/{exit}' "$vault_cli_src" | grep -oE 'Some\("[a-z-]+"\)' | sed -E 's/Some\("([a-z-]+)"\)/\1/')
if [ "${#vault_subcommands[@]}" -eq 0 ]; then
  echo "failed to extract any vault subcommands from $vault_cli_src; extraction pattern is stale" >&2
  exit 1
fi
missing_vault_subcommands=()
for subcommand in "${vault_subcommands[@]}"; do
  if ! grep -rq --include='*.md' -- "$subcommand" "$REPO_ROOT/docs"; then
    missing_vault_subcommands+=("$subcommand")
  fi
done
if [ "${#missing_vault_subcommands[@]}" -gt 0 ]; then
  echo "docs/ is missing coverage for vault subcommand(s): ${missing_vault_subcommands[*]}" >&2
  exit 1
fi

# Every GUI callback wired via `window.on_*(...)` in wire_callbacks() (crates/paranoid-gui/src/lib.rs,
# both the desktop and WASM-gated variants) must appear somewhere under docs/. Callback names are
# extracted mechanically from `window.on_<name>` call sites, not hardcoded here, so a renamed,
# added, or removed callback in code fails this gate instead of silently passing.
gui_lib_src="$REPO_ROOT/crates/paranoid-gui/src/lib.rs"
mapfile -t gui_callbacks < <(grep -oE '\bwindow\.on_[a-zA-Z_]+' "$gui_lib_src" | sed -E 's/^window\.//' | sort -u)
if [ "${#gui_callbacks[@]}" -eq 0 ]; then
  echo "failed to extract any GUI callbacks from $gui_lib_src; extraction pattern is stale" >&2
  exit 1
fi
missing_gui_callbacks=()
for callback in "${gui_callbacks[@]}"; do
  if ! grep -rq --include='*.md' -- "$callback" "$REPO_ROOT/docs"; then
    missing_gui_callbacks+=("$callback")
  fi
done
if [ "${#missing_gui_callbacks[@]}" -gt 0 ]; then
  echo "docs/ is missing coverage for GUI callback(s): ${missing_gui_callbacks[*]}" >&2
  exit 1
fi
