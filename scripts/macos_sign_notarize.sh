#!/usr/bin/env bash

set -euo pipefail

mode="${PARANOID_RELEASE_SIGNING_MODE:-unsigned}"
kind=""
app_path=""
dmg_path=""

usage() {
  cat >&2 <<'EOF'
usage: macos_sign_notarize.sh [--mode unsigned|signed] --kind app|dmg (--app <path>|--dmg <path>)

Signs and notarizes macOS release payloads when signed release mode is requested.

unsigned mode records an explicit no-op so local release emulation remains unsigned.
signed mode fails closed unless this host, signing identity, and notarization credentials are ready.

Required signed-mode environment:
  PARANOID_MACOS_CODESIGN_IDENTITY
  and either PARANOID_MACOS_NOTARY_KEYCHAIN_PROFILE
  or PARANOID_MACOS_NOTARY_KEY_PATH + PARANOID_MACOS_NOTARY_KEY_ID + PARANOID_MACOS_NOTARY_ISSUER
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --kind)
      kind="${2:-}"
      shift 2
      ;;
    --app)
      app_path="${2:-}"
      shift 2
      ;;
    --dmg)
      dmg_path="${2:-}"
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

case "${mode}" in
  unsigned|signed) ;;
  *)
    echo "unsupported macOS signing mode: ${mode}" >&2
    exit 64
    ;;
esac

case "${kind}" in
  app)
    if [ -z "${app_path}" ]; then
      echo "--app is required for macOS app signing" >&2
      usage
      exit 64
    fi
    if [ ! -d "${app_path}" ]; then
      echo "missing macOS app bundle for signing: ${app_path}" >&2
      exit 1
    fi
    payload_name="$(basename "${app_path}")"
    ;;
  dmg)
    if [ -z "${dmg_path}" ]; then
      echo "--dmg is required for macOS dmg notarization" >&2
      usage
      exit 64
    fi
    if [ ! -f "${dmg_path}" ]; then
      echo "missing macOS dmg for notarization: ${dmg_path}" >&2
      exit 1
    fi
    payload_name="$(basename "${dmg_path}")"
    ;;
  *)
    echo "unsupported macOS signing payload kind: ${kind}" >&2
    usage
    exit 64
    ;;
esac

if [ "${mode}" = "unsigned" ]; then
  printf 'macOS signing boundary verified as unsigned/no-op for %s\n' "${payload_name}"
  exit 0
fi

if [ -z "${PARANOID_MACOS_CODESIGN_IDENTITY:-}" ]; then
  echo "PARANOID_MACOS_CODESIGN_IDENTITY is required for signed macOS release payloads" >&2
  exit 1
fi

notary_args=()
if [ -n "${PARANOID_MACOS_NOTARY_KEYCHAIN_PROFILE:-}" ]; then
  notary_args=(--keychain-profile "${PARANOID_MACOS_NOTARY_KEYCHAIN_PROFILE}")
elif [ -n "${PARANOID_MACOS_NOTARY_KEY_PATH:-}" ] \
  && [ -n "${PARANOID_MACOS_NOTARY_KEY_ID:-}" ] \
  && [ -n "${PARANOID_MACOS_NOTARY_ISSUER:-}" ]; then
  if [ ! -f "${PARANOID_MACOS_NOTARY_KEY_PATH}" ]; then
    echo "PARANOID_MACOS_NOTARY_KEY_PATH does not exist: ${PARANOID_MACOS_NOTARY_KEY_PATH}" >&2
    exit 1
  fi
  notary_args=(
    --key "${PARANOID_MACOS_NOTARY_KEY_PATH}"
    --key-id "${PARANOID_MACOS_NOTARY_KEY_ID}"
    --issuer "${PARANOID_MACOS_NOTARY_ISSUER}"
  )
else
  echo "notarization credentials are required for signed macOS release payloads" >&2
  exit 1
fi

if [ "$(uname -s)" != "Darwin" ]; then
  echo "signed macOS signing and notarization requires a macOS host: ${payload_name}" >&2
  exit 1
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required for signed macOS release payloads" >&2
    exit 1
  fi
}

require_cmd codesign
require_cmd ditto
require_cmd xcrun
if [ "${kind}" = "dmg" ]; then
  require_cmd hdiutil
fi

notarize_file() {
  local notarization_input="$1"

  xcrun notarytool submit "${notarization_input}" "${notary_args[@]}" --wait
}

sign_and_notarize_app() {
  local tmpdir
  local notary_zip

  codesign --force --timestamp --options runtime \
    --sign "${PARANOID_MACOS_CODESIGN_IDENTITY}" \
    "${app_path}"
  codesign --verify --deep --strict "${app_path}"

  tmpdir="$(mktemp -d)"
  notary_zip="${tmpdir}/paranoid-passwd-gui-app-notary.zip"
  ditto -c -k --keepParent "${app_path}" "${notary_zip}"
  set +e
  notarize_file "${notary_zip}"
  local status=$?
  set -e
  rm -rf "${tmpdir}"
  if [ "${status}" -ne 0 ]; then
    exit "${status}"
  fi

  xcrun stapler staple "${app_path}"
  xcrun stapler validate "${app_path}"
}

sign_and_notarize_dmg() {
  hdiutil verify "${dmg_path}"
  codesign --force --timestamp \
    --sign "${PARANOID_MACOS_CODESIGN_IDENTITY}" \
    "${dmg_path}"
  notarize_file "${dmg_path}"
  xcrun stapler staple "${dmg_path}"
  xcrun stapler validate "${dmg_path}"
  hdiutil verify "${dmg_path}"
}

case "${kind}" in
  app) sign_and_notarize_app ;;
  dmg) sign_and_notarize_dmg ;;
esac

printf 'macOS signed release payload verified for %s\n' "${payload_name}"
