#!/usr/bin/env bash

set -euo pipefail

VERSION="${1:?version required}"
DIST_DIR="${2:?dist dir required}"
PYTHON_BIN="${PYTHON:-$(command -v python3 || command -v python || true)}"

LINUX_AMD64="paranoid-passwd-${VERSION}-linux-amd64.tar.gz"
LINUX_ARM64="paranoid-passwd-${VERSION}-linux-arm64.tar.gz"
DARWIN_AMD64="paranoid-passwd-${VERSION}-darwin-amd64.tar.gz"
DARWIN_ARM64="paranoid-passwd-${VERSION}-darwin-arm64.tar.gz"
WIN_AMD64="paranoid-passwd-${VERSION}-windows-amd64.zip"
EXPECTED_ARCHIVES=(
  "${LINUX_AMD64}"
  "${LINUX_ARM64}"
  "${DARWIN_AMD64}"
  "${DARWIN_ARM64}"
  "${WIN_AMD64}"
)

for archive in "${EXPECTED_ARCHIVES[@]}"; do
  if [ ! -f "${DIST_DIR}/${archive}" ]; then
    echo "missing release archive: ${DIST_DIR}/${archive}" >&2
    exit 1
  fi
  if [ ! -f "${DIST_DIR}/${archive}.sha256" ]; then
    echo "missing archive checksum: ${DIST_DIR}/${archive}.sha256" >&2
    exit 1
  fi
done

cat \
  "${DIST_DIR}/${LINUX_AMD64}.sha256" \
  "${DIST_DIR}/${LINUX_ARM64}.sha256" \
  "${DIST_DIR}/${DARWIN_AMD64}.sha256" \
  "${DIST_DIR}/${DARWIN_ARM64}.sha256" \
  "${DIST_DIR}/${WIN_AMD64}.sha256" \
  > "${DIST_DIR}/checksums.txt"

verify_checksum() {
  local archive="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${DIST_DIR}" && grep " ${archive}\$" checksums.txt | sha256sum -c -)
  else
    (cd "${DIST_DIR}" && grep " ${archive}\$" checksums.txt | shasum -a 256 -c -)
  fi
}

for archive in "${EXPECTED_ARCHIVES[@]}"; do
  verify_checksum "${archive}"
done

out_dir="${DIST_DIR}/pkg"
rm -rf "${out_dir}"
bash scripts/generate_pkg_manifests.sh "${VERSION}" "${DIST_DIR}/checksums.txt" "${out_dir}"

for generated in \
  "${out_dir}/paranoid-passwd.rb" \
  "${out_dir}/paranoid-passwd.json" \
  "${out_dir}/paranoid-passwd.nuspec" \
  "${out_dir}/chocolateyInstall.ps1" \
  "${out_dir}/VERIFICATION.txt"; do
  [ -f "${generated}" ]
done

install_tmp="$(mktemp -d)"
port=38125
server_log="${DIST_DIR}/http-server.log"
cleanup() {
  rm -rf "${install_tmp}"
  kill "${server_pid:-0}" 2>/dev/null || true
}
trap cleanup EXIT
if [ -z "${PYTHON_BIN}" ]; then
  echo "python3 or python is required for release validation" >&2
  exit 1
fi
"${PYTHON_BIN}" -m http.server "${port}" --directory "${DIST_DIR}" >"${server_log}" 2>&1 &
server_pid=$!
sleep 1

PARANOID_INSTALL_DOWNLOAD_BASE_URL="http://127.0.0.1:${port}" \
PARANOID_INSTALL_CHECKSUMS_URL="http://127.0.0.1:${port}/checksums.txt" \
  sh docs/public/install.sh --version "paranoid-passwd-v${VERSION}" --install-dir "${install_tmp}"

"${install_tmp}/paranoid-passwd" --version | grep -F "${VERSION}" >/dev/null

printf 'release validation passed for %s\n' "${VERSION}"
