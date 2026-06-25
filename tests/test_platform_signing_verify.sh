#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/verify_platform_signing.sh"
MACOS_SCRIPT="${REPO_ROOT}/scripts/macos_sign_notarize.sh"
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

: > "${linux_archive}"
: > "${linux_deb}"
: > "${mac_dmg}"
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

printf '\n%s passed, %s failed\n' "${pass}" "${fail}"
if [ "${fail}" -ne 0 ]; then
  exit 1
fi
