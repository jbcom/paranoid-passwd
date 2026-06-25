#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/verify_platform_signing.sh"
MACOS_SCRIPT="${REPO_ROOT}/scripts/macos_sign_notarize.sh"
WINDOWS_SCRIPT="${REPO_ROOT}/scripts/windows_sign_artifact.sh"
BUILD_SCRIPT="${REPO_ROOT}/scripts/build_release_artifact.sh"
PAYLOAD_SCRIPT="${REPO_ROOT}/scripts/assert_release_payload.sh"
tmpdir="$(mktemp -d)"

cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

pass=0
fail=0

record_pass() {
  printf '  PASS  %s\n' "$1"
  pass=$((pass + 1))
}

record_fail() {
  printf '  FAIL  %s\n' "$1" >&2
  fail=$((fail + 1))
}

assert_ok() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    record_pass "${name}"
  else
    record_fail "${name}"
  fi
}

assert_fails() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    record_fail "${name}"
  else
    record_pass "${name}"
  fi
}

linux_archive="${tmpdir}/paranoid-passwd-1.2.3-linux-amd64.tar.gz"
linux_deb="${tmpdir}/paranoid-passwd_1.2.3_amd64.deb"
mac_dmg="${tmpdir}/paranoid-passwd-gui-1.2.3-darwin-arm64.dmg"
mac_app="${tmpdir}/Paranoid Passwd.app"
win_msi="${tmpdir}/paranoid-passwd-gui-1.2.3-windows-amd64.msi"

: > "${linux_archive}"
: > "${linux_deb}"
: > "${mac_dmg}"
: > "${win_msi}"
mkdir -p "${mac_app}/Contents/MacOS"
: > "${mac_app}/Contents/MacOS/paranoid-passwd-gui"

assert_ok "unsigned mode records current release boundary" \
  bash "${SCRIPT}" --mode unsigned --artifact "${linux_archive}" --product paranoid-passwd

assert_ok "signed mode permits Linux deb payload boundary" \
  bash "${SCRIPT}" --mode signed --artifact "${linux_deb}" --product paranoid-passwd

assert_fails "invalid signing mode fails closed" \
  bash "${SCRIPT}" --mode maybe --artifact "${linux_archive}"

assert_fails "missing artifact fails closed" \
  bash "${SCRIPT}" --mode unsigned --artifact "${tmpdir}/missing.tar.gz"

assert_fails "signed macOS dmg fails without verifiable signed payload" \
  bash "${SCRIPT}" --mode signed --artifact "${mac_dmg}" --product paranoid-passwd-gui

assert_fails "macOS signing helper never passes notarization password argv" \
  grep -q -- "--password" "${MACOS_SCRIPT}"

assert_fails "Windows signing helper never accepts PFX password argv" \
  grep -Eq -- '(^|[[:space:]])/p([[:space:]]|$)|CERTIFICATE_PASSWORD' "${WINDOWS_SCRIPT}"

assert_ok "unsigned macOS app helper records no-op boundary" \
  bash "${MACOS_SCRIPT}" --mode unsigned --kind app --app "${mac_app}"

assert_ok "unsigned macOS dmg helper records no-op boundary" \
  bash "${MACOS_SCRIPT}" --mode unsigned --kind dmg --dmg "${mac_dmg}"

assert_fails "signed macOS app helper requires signing identity" \
  env -u PARANOID_MACOS_CODESIGN_IDENTITY \
    -u PARANOID_MACOS_NOTARY_KEYCHAIN_PROFILE \
    -u PARANOID_MACOS_NOTARY_KEY_PATH \
    -u PARANOID_MACOS_NOTARY_KEY_ID \
    -u PARANOID_MACOS_NOTARY_ISSUER \
    bash "${MACOS_SCRIPT}" --mode signed --kind app --app "${mac_app}"

assert_fails "signed macOS app helper requires notarization credentials" \
  env PARANOID_MACOS_CODESIGN_IDENTITY="Developer ID Application: Example" \
    -u PARANOID_MACOS_NOTARY_KEYCHAIN_PROFILE \
    -u PARANOID_MACOS_NOTARY_KEY_PATH \
    -u PARANOID_MACOS_NOTARY_KEY_ID \
    -u PARANOID_MACOS_NOTARY_ISSUER \
    bash "${MACOS_SCRIPT}" --mode signed --kind app --app "${mac_app}"

assert_fails "invalid macOS signing helper kind fails closed" \
  bash "${MACOS_SCRIPT}" --mode unsigned --kind maybe --app "${mac_app}"

assert_fails "missing macOS app helper payload fails closed" \
  bash "${MACOS_SCRIPT}" --mode unsigned --kind app --app "${tmpdir}/missing.app"

assert_ok "unsigned Windows signing helper records no-op boundary" \
  bash "${WINDOWS_SCRIPT}" --mode unsigned --artifact "${win_msi}"

assert_fails "signed Windows signing helper fails without signing host and cert" \
  env -u PARANOID_WINDOWS_SIGNTOOL_CERT_SHA1 \
    bash "${WINDOWS_SCRIPT}" --mode signed --artifact "${win_msi}"

assert_fails "MSI build refuses non-Windows targets before cargo build" \
  bash "${BUILD_SCRIPT}" 1.2.3 linux amd64 "" msi "${tmpdir}" paranoid-passwd-gui paranoid-gui

assert_fails "MSI payload validation fails closed without Windows host or deferral" \
  env -u PARANOID_MSI_ALLOW_HOST_DEFERRED \
    bash "${PAYLOAD_SCRIPT}" 1.2.3 windows amd64 "${win_msi}" paranoid-passwd-gui

assert_ok "MSI payload validation can be explicitly host-deferred" \
  env PARANOID_MSI_ALLOW_HOST_DEFERRED=1 \
    bash "${PAYLOAD_SCRIPT}" 1.2.3 windows amd64 "${win_msi}" paranoid-passwd-gui

printf '\n%s passed, %s failed\n' "${pass}" "${fail}"
if [ "${fail}" -ne 0 ]; then
  exit 1
fi
