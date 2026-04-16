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
  "paranoid-passwd_${VERSION}_amd64.deb"
  "paranoid-passwd_${VERSION}_arm64.deb"
  "paranoid-passwd-gui-${VERSION}-linux-amd64.tar.gz"
  "paranoid-passwd-gui-${VERSION}-linux-arm64.tar.gz"
  "paranoid-passwd-gui-${VERSION}-darwin-amd64.tar.gz"
  "paranoid-passwd-gui-${VERSION}-darwin-arm64.tar.gz"
  "paranoid-passwd-gui-${VERSION}-darwin-amd64.dmg"
  "paranoid-passwd-gui-${VERSION}-darwin-arm64.dmg"
  "paranoid-passwd-gui-${VERSION}-windows-amd64.zip"
  "paranoid-passwd-gui_${VERSION}_amd64.deb"
  "paranoid-passwd-gui_${VERSION}_arm64.deb"
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

archive_ext="tar.gz"
if [ "${host_os}" = "windows" ]; then
  archive_ext="zip"
fi

host_cli_artifact="paranoid-passwd-${VERSION}-${host_os}-${host_arch}.${archive_ext}"
host_gui_artifact="paranoid-passwd-gui-${VERSION}-${host_os}-${host_arch}.${archive_ext}"
host_gui_dmg="paranoid-passwd-gui-${VERSION}-${host_os}-${host_arch}.dmg"
host_cli_deb="paranoid-passwd_${VERSION}_${host_arch}.deb"
host_gui_deb="paranoid-passwd-gui_${VERSION}_${host_arch}.deb"
EXPECTED_ARCHIVES=("${EXPECTED_ASSETS[@]:1}")

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

download_args=("${TAG}" --repo "${REPO}" --dir "${tmpdir}")
for asset in "${EXPECTED_ASSETS[@]}"; do
  download_args+=(-p "${asset}")
done
gh release download "${download_args[@]}"

verify_checksum() {
  local artifact="$1"
  local checksum_line

  checksum_line="$(awk -v artifact="${artifact}" '$2 == artifact { print; found = 1 } END { if (!found) exit 1 }' "${tmpdir}/checksums.txt")"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' "${checksum_line}" | sha256sum -c -
  else
    printf '%s\n' "${checksum_line}" | shasum -a 256 -c -
  fi
}

for artifact in "${EXPECTED_ARCHIVES[@]}"; do
  verify_checksum "${artifact}"
done

for artifact in "${EXPECTED_ARCHIVES[@]}"; do
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
        continue
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
    "${tmpdir}/${artifact}" \
    "${product_name}"
done

host_attested_artifacts=("${host_cli_artifact}" "${host_gui_artifact}")
if [ "${host_os}" = "linux" ]; then
  host_attested_artifacts+=("${host_cli_deb}" "${host_gui_deb}")
elif [ "${host_os}" = "darwin" ]; then
  host_attested_artifacts+=("${host_gui_dmg}")
fi

for artifact in "${host_attested_artifacts[@]}"; do
  (
    cd "${tmpdir}"
    gh attestation verify "${artifact}" --owner "${OWNER}"
  )
done

bash scripts/smoke_test_release_artifact.sh "${VERSION}" "${host_os}" "${host_arch}" "${tmpdir}/${host_cli_artifact}"
bash scripts/smoke_test_release_artifact.sh "${VERSION}" "${host_os}" "${host_arch}" "${tmpdir}/${host_gui_artifact}" paranoid-passwd-gui
if [ "${host_os}" = "linux" ]; then
  bash scripts/smoke_test_release_artifact.sh "${VERSION}" "${host_os}" "${host_arch}" "${tmpdir}/${host_cli_deb}"
  bash scripts/smoke_test_release_artifact.sh "${VERSION}" "${host_os}" "${host_arch}" "${tmpdir}/${host_gui_deb}" paranoid-passwd-gui
elif [ "${host_os}" = "darwin" ]; then
  bash scripts/smoke_test_release_artifact.sh "${VERSION}" "${host_os}" "${host_arch}" "${tmpdir}/${host_gui_dmg}" paranoid-passwd-gui
fi

printf 'published release verified for %s (%s, %s)\n' \
  "${TAG}" "${host_cli_artifact}" "${host_gui_artifact}"
