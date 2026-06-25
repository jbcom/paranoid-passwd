#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/verify_platform_signing.sh"
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

: > "${linux_archive}"
: > "${linux_deb}"
: > "${mac_dmg}"

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

printf '\n%s passed, %s failed\n' "${pass}" "${fail}"
if [ "${fail}" -ne 0 ]; then
  exit 1
fi
