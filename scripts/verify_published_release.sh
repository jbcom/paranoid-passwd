#!/usr/bin/env bash

set -euo pipefail

TAG="${1:?release tag required (e.g. paranoid-passwd-v3.5.2)}"
REPO="${2:-jbcom/paranoid-passwd}"
OWNER="${3:-jbcom}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required for published release verification" >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "gh auth is required for published release verification" >&2
  exit 1
fi

VERSION="${TAG#paranoid-passwd-v}"
EXPECTED_ASSETS=(
  "checksums.txt"
  "paranoid-passwd-${VERSION}-linux-amd64.tar.gz"
  "paranoid-passwd-${VERSION}-linux-arm64.tar.gz"
  "paranoid-passwd-${VERSION}-darwin-amd64.tar.gz"
  "paranoid-passwd-${VERSION}-darwin-arm64.tar.gz"
  "paranoid-passwd-${VERSION}-windows-amd64.zip"
)

mapfile -t ACTUAL_ASSETS < <(
  gh release view "${TAG}" --repo "${REPO}" --json assets --jq '.assets[].name' | LC_ALL=C sort
)
mapfile -t EXPECTED_SORTED < <(printf '%s\n' "${EXPECTED_ASSETS[@]}" | LC_ALL=C sort)

if [ "${#ACTUAL_ASSETS[@]}" -ne "${#EXPECTED_SORTED[@]}" ]; then
  printf 'unexpected asset count for %s: expected %d, got %d\n' \
    "${TAG}" "${#EXPECTED_SORTED[@]}" "${#ACTUAL_ASSETS[@]}" >&2
  printf 'actual assets:\n%s\n' "$(printf '%s\n' "${ACTUAL_ASSETS[@]}")" >&2
  exit 1
fi

for idx in "${!EXPECTED_SORTED[@]}"; do
  if [ "${EXPECTED_SORTED[$idx]}" != "${ACTUAL_ASSETS[$idx]}" ]; then
    printf 'asset mismatch for %s: expected %s, got %s\n' \
      "${TAG}" "${EXPECTED_SORTED[$idx]}" "${ACTUAL_ASSETS[$idx]}" >&2
    exit 1
  fi
done

host_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "${host_os}" in
  linux) host_os="linux" ;;
  darwin) host_os="darwin" ;;
  msys*|mingw*|cygwin*) host_os="windows" ;;
  *)
    echo "unsupported host OS: ${host_os}" >&2
    exit 1
    ;;
esac

host_arch="$(uname -m)"
case "${host_arch}" in
  x86_64|amd64) host_arch="amd64" ;;
  arm64|aarch64) host_arch="arm64" ;;
  *)
    echo "unsupported host architecture: ${host_arch}" >&2
    exit 1
    ;;
esac

if [ "${host_os}" = "windows" ]; then
  host_artifact="paranoid-passwd-${VERSION}-${host_os}-${host_arch}.zip"
else
  host_artifact="paranoid-passwd-${VERSION}-${host_os}-${host_arch}.tar.gz"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

gh release download "${TAG}" --repo "${REPO}" \
  -p "${host_artifact}" \
  -p "checksums.txt" \
  --dir "${tmpdir}"

if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "${tmpdir}"
    grep " ${host_artifact}\$" checksums.txt | sha256sum -c -
  )
else
  (
    cd "${tmpdir}"
    grep " ${host_artifact}\$" checksums.txt | shasum -a 256 -c -
  )
fi

(
  cd "${tmpdir}"
  gh attestation verify "${host_artifact}" --owner "${OWNER}"
)

bash scripts/smoke_test_release_artifact.sh "${VERSION}" "${host_os}" "${host_arch}" "${tmpdir}/${host_artifact}"

printf 'published release verified for %s (%s)\n' "${TAG}" "${host_artifact}"
