#!/usr/bin/env bash

set -euo pipefail

mode="${PARANOID_RELEASE_SIGNING_MODE:-unsigned}"
artifact=""

usage() {
  cat >&2 <<'EOF'
usage: windows_sign_artifact.sh [--mode unsigned|signed] --artifact <path>

Signs a Windows release artifact only when signed release mode is requested.

unsigned mode records the current checksummed+attested release boundary.
signed mode requires a Windows host, signtool, and
PARANOID_WINDOWS_SIGNTOOL_CERT_SHA1 for a certificate already imported into
the current user's certificate store. PFX passwords are intentionally not
accepted here so secrets are not passed through process argv.
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
  echo "missing Windows artifact for signing: ${artifact}" >&2
  exit 1
fi

case "${mode}" in
  unsigned|signed) ;;
  *)
    echo "unsupported Windows signing mode: ${mode}" >&2
    exit 64
    ;;
esac

artifact_name="$(basename "${artifact}")"

if [ "${mode}" = "unsigned" ]; then
  printf 'Windows signing boundary verified as unsigned/checksummed+attested for %s\n' "${artifact_name}"
  exit 0
fi

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) ;;
  *)
    echo "signed Windows artifact signing requires a Windows host: ${artifact_name}" >&2
    exit 1
    ;;
esac

if ! command -v signtool >/dev/null 2>&1 && ! command -v signtool.exe >/dev/null 2>&1; then
  echo "signtool is required for signed Windows artifacts: ${artifact_name}" >&2
  exit 1
fi

signtool_cmd="$(command -v signtool || command -v signtool.exe)"
cert_sha1="${PARANOID_WINDOWS_SIGNTOOL_CERT_SHA1:-}"
timestamp_url="${PARANOID_WINDOWS_SIGNTOOL_TIMESTAMP_URL:-http://timestamp.digicert.com}"

if [ -z "${cert_sha1}" ]; then
  echo "PARANOID_WINDOWS_SIGNTOOL_CERT_SHA1 is required for signed Windows artifacts" >&2
  exit 1
fi

"${signtool_cmd}" sign \
  /fd SHA256 \
  /sha1 "${cert_sha1}" \
  /tr "${timestamp_url}" \
  /td SHA256 \
  "${artifact}"

"${signtool_cmd}" verify /pa "${artifact}"
