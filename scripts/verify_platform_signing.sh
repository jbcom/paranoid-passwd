#!/usr/bin/env bash

set -euo pipefail

mode="${PARANOID_RELEASE_SIGNING_MODE:-unsigned}"
artifact=""
product_name=""

usage() {
  cat >&2 <<'EOF'
usage: verify_platform_signing.sh [--mode unsigned|signed] --artifact <path> [--product <name>]

Verifies the platform-signing boundary for a release artifact.

unsigned mode records that the release is checksummed and attested, not platform-signed.
signed mode fails closed unless this host can verify the relevant platform signature.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --artifact)
      artifact="${2:-}"
      shift 2
      ;;
    --product)
      product_name="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 64
      ;;
  esac
done

if [ -z "${artifact}" ]; then
  echo "--artifact is required" >&2
  usage
  exit 64
fi

if [ ! -e "${artifact}" ]; then
  echo "missing artifact for platform-signing verification: ${artifact}" >&2
  exit 1
fi

case "${mode}" in
  unsigned|signed)
    ;;
  *)
    echo "unsupported platform-signing mode: ${mode}" >&2
    exit 64
    ;;
esac

artifact_name="$(basename "${artifact}")"

if [ "${mode}" = "unsigned" ]; then
  printf 'platform signing boundary verified as unsigned/checksummed+attested for %s\n' "${artifact_name}"
  exit 0
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required for signed platform verification of ${artifact_name}" >&2
    exit 1
  fi
}

verify_macos_app() {
  local app_path="$1"

  require_cmd codesign
  require_cmd spctl
  require_cmd xcrun

  codesign --verify --deep --strict "${app_path}"
  spctl --assess --type execute -vv "${app_path}"
  xcrun stapler validate "${app_path}"
}

verify_macos_dmg() {
  local mount_point
  local tmpdir
  local app_path

  if [ "$(uname -s)" != "Darwin" ]; then
    echo "signed macOS verification requires a macOS host: ${artifact_name}" >&2
    exit 1
  fi

  require_cmd hdiutil
  require_cmd codesign
  require_cmd spctl
  require_cmd xcrun
  hdiutil verify "${artifact}"

  tmpdir="$(mktemp -d)"
  mount_point="${tmpdir}/dmg"
  mkdir -p "${mount_point}"

  hdiutil attach -quiet -readonly -nobrowse -mountpoint "${mount_point}" "${artifact}" >/dev/null
  app_path="${mount_point}/Paranoid Passwd.app"
  if [ ! -d "${app_path}" ]; then
    echo "signed macOS dmg is missing Paranoid Passwd.app: ${artifact_name}" >&2
    hdiutil detach -quiet "${mount_point}" >/dev/null 2>&1 || true
    rm -rf "${tmpdir}"
    exit 1
  fi
  set +e
  verify_macos_app "${app_path}"
  local status=$?
  set -e
  hdiutil detach -quiet "${mount_point}" >/dev/null 2>&1 || true
  rm -rf "${tmpdir}"
  if [ "${status}" -ne 0 ]; then
    exit "${status}"
  fi
}

verify_macos_archive() {
  local tmpdir
  local app_path

  if [ "$(uname -s)" != "Darwin" ]; then
    echo "signed macOS archive verification requires a macOS host: ${artifact_name}" >&2
    exit 1
  fi

  require_cmd codesign
  require_cmd spctl
  require_cmd xcrun

  tmpdir="$(mktemp -d)"

  tar -xzf "${artifact}" -C "${tmpdir}"
  app_path="$(find "${tmpdir}" -maxdepth 3 -type d -name 'Paranoid Passwd.app' | head -n 1)"
  if [ -z "${app_path}" ]; then
    echo "signed macOS archive is missing Paranoid Passwd.app: ${artifact_name}" >&2
    rm -rf "${tmpdir}"
    exit 1
  fi
  set +e
  verify_macos_app "${app_path}"
  local status=$?
  set -e
  rm -rf "${tmpdir}"
  if [ "${status}" -ne 0 ]; then
    exit "${status}"
  fi
}

verify_windows_signed_artifact() {
  require_cmd signtool
  signtool verify /pa "${artifact}"
}

case "${artifact_name}" in
  paranoid-passwd-gui-*-darwin-*.dmg)
    verify_macos_dmg
    ;;
  paranoid-passwd-gui-*-darwin-*.tar.gz)
    verify_macos_archive
    ;;
  *.msi|*.exe)
    verify_windows_signed_artifact
    ;;
  *.deb)
    printf 'platform signing check not required for Linux deb payload: %s\n' "${artifact_name}"
    ;;
  *.tar.gz|*.zip)
    printf 'no platform code-signature verifier required for %s archive: %s\n' "${product_name:-unknown}" "${artifact_name}"
    ;;
  *)
    echo "unsupported artifact for platform-signing verification: ${artifact_name}" >&2
    exit 64
    ;;
esac
