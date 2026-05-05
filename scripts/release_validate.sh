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
LINUX_DEB_AMD64="paranoid-passwd_${VERSION}_amd64.deb"
LINUX_DEB_ARM64="paranoid-passwd_${VERSION}_arm64.deb"
GUI_LINUX_AMD64="paranoid-passwd-gui-${VERSION}-linux-amd64.tar.gz"
GUI_LINUX_ARM64="paranoid-passwd-gui-${VERSION}-linux-arm64.tar.gz"
GUI_DARWIN_AMD64="paranoid-passwd-gui-${VERSION}-darwin-amd64.tar.gz"
GUI_DARWIN_ARM64="paranoid-passwd-gui-${VERSION}-darwin-arm64.tar.gz"
GUI_DMG_AMD64="paranoid-passwd-gui-${VERSION}-darwin-amd64.dmg"
GUI_DMG_ARM64="paranoid-passwd-gui-${VERSION}-darwin-arm64.dmg"
GUI_WIN_AMD64="paranoid-passwd-gui-${VERSION}-windows-amd64.zip"
GUI_DEB_AMD64="paranoid-passwd-gui_${VERSION}_amd64.deb"
GUI_DEB_ARM64="paranoid-passwd-gui_${VERSION}_arm64.deb"
EXPECTED_ASSETS=(
  "${LINUX_AMD64}"
  "${LINUX_ARM64}"
  "${DARWIN_AMD64}"
  "${DARWIN_ARM64}"
  "${WIN_AMD64}"
  "${LINUX_DEB_AMD64}"
  "${LINUX_DEB_ARM64}"
  "${GUI_LINUX_AMD64}"
  "${GUI_LINUX_ARM64}"
  "${GUI_DARWIN_AMD64}"
  "${GUI_DARWIN_ARM64}"
  "${GUI_DMG_AMD64}"
  "${GUI_DMG_ARM64}"
  "${GUI_WIN_AMD64}"
  "${GUI_DEB_AMD64}"
  "${GUI_DEB_ARM64}"
)

for archive in "${EXPECTED_ASSETS[@]}"; do
  if [ ! -f "${DIST_DIR}/${archive}" ]; then
    echo "missing release archive: ${DIST_DIR}/${archive}" >&2
    exit 1
  fi
  if [ ! -f "${DIST_DIR}/${archive}.sha256" ]; then
    echo "missing archive checksum: ${DIST_DIR}/${archive}.sha256" >&2
    exit 1
  fi
done

validate_archive_payload() {
  local artifact="$1"
  local base_name
  local product_name
  local parsed_version
  local target_os
  local target_arch

  case "${artifact}" in
    *.tar.gz|*.zip)
      if [[ "${artifact}" == paranoid-passwd-gui-* ]]; then
        product_name="paranoid-passwd-gui"
      else
        product_name="paranoid-passwd"
      fi
      base_name="${artifact%.tar.gz}"
      base_name="${base_name%.zip}"
      parsed_version="${base_name#${product_name}-}"
      parsed_version="${parsed_version%%-*}"
      target_os="${base_name#${product_name}-${parsed_version}-}"
      target_os="${target_os%%-*}"
      target_arch="${base_name##*-}"
      ;;
    *.dmg)
      product_name="paranoid-passwd-gui"
      base_name="${artifact%.dmg}"
      parsed_version="${base_name#${product_name}-}"
      parsed_version="${parsed_version%%-*}"
      target_os="${base_name#${product_name}-${parsed_version}-}"
      target_os="${target_os%%-*}"
      target_arch="${base_name##*-}"
      if ! command -v hdiutil >/dev/null 2>&1; then
        printf 'skipping dmg payload validation on non-mac host: %s\n' "${artifact}" >&2
        return 0
      fi
      ;;
    *.deb)
      product_name="${artifact%%_*}"
      parsed_version="${artifact#${product_name}_}"
      parsed_version="${parsed_version%%_*}"
      target_os="linux"
      target_arch="${artifact##*_}"
      target_arch="${target_arch%.deb}"
      ;;
    *)
      echo "unsupported release artifact: ${artifact}" >&2
      exit 64
      ;;
  esac

  bash scripts/assert_release_payload.sh \
    "${parsed_version}" \
    "${target_os}" \
    "${target_arch}" \
    "${DIST_DIR}/${artifact}" \
    "${product_name}"
}

for archive in "${EXPECTED_ASSETS[@]}"; do
  validate_archive_payload "${archive}"
done

cat \
  "${DIST_DIR}/${LINUX_AMD64}.sha256" \
  "${DIST_DIR}/${LINUX_ARM64}.sha256" \
  "${DIST_DIR}/${DARWIN_AMD64}.sha256" \
  "${DIST_DIR}/${DARWIN_ARM64}.sha256" \
  "${DIST_DIR}/${WIN_AMD64}.sha256" \
  "${DIST_DIR}/${LINUX_DEB_AMD64}.sha256" \
  "${DIST_DIR}/${LINUX_DEB_ARM64}.sha256" \
  "${DIST_DIR}/${GUI_LINUX_AMD64}.sha256" \
  "${DIST_DIR}/${GUI_LINUX_ARM64}.sha256" \
  "${DIST_DIR}/${GUI_DARWIN_AMD64}.sha256" \
  "${DIST_DIR}/${GUI_DARWIN_ARM64}.sha256" \
  "${DIST_DIR}/${GUI_DMG_AMD64}.sha256" \
  "${DIST_DIR}/${GUI_DMG_ARM64}.sha256" \
  "${DIST_DIR}/${GUI_WIN_AMD64}.sha256" \
  "${DIST_DIR}/${GUI_DEB_AMD64}.sha256" \
  "${DIST_DIR}/${GUI_DEB_ARM64}.sha256" \
  > "${DIST_DIR}/checksums.txt"

verify_checksum() {
  local archive="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${DIST_DIR}" && grep " ${archive}\$" checksums.txt | sha256sum -c -)
  else
    (cd "${DIST_DIR}" && grep " ${archive}\$" checksums.txt | shasum -a 256 -c -)
  fi
}

for archive in "${EXPECTED_ASSETS[@]}"; do
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

bash scripts/smoke_test_release_artifact.sh "${VERSION}" linux amd64 "${DIST_DIR}/${LINUX_AMD64}"
bash scripts/smoke_test_release_artifact.sh "${VERSION}" linux amd64 "${DIST_DIR}/${GUI_LINUX_AMD64}" paranoid-passwd-gui
if [ "$(uname -s | tr '[:upper:]' '[:lower:]')" = "linux" ]; then
  bash scripts/smoke_test_release_artifact.sh "${VERSION}" linux amd64 "${DIST_DIR}/${LINUX_DEB_AMD64}"
  bash scripts/smoke_test_release_artifact.sh "${VERSION}" linux amd64 "${DIST_DIR}/${GUI_DEB_AMD64}" paranoid-passwd-gui
fi

printf 'release validation passed for %s\n' "${VERSION}"
