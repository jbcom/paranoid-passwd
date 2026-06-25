#!/usr/bin/env bash

set -euo pipefail

VERSION="${1:?version required}"
TARGET_OS="${2:?target os required}"
TARGET_ARCH="${3:?target arch required}"
ARCHIVE_PATH="${4:?archive path required}"
PRODUCT_NAME="${5:-paranoid-passwd}"
PYTHON_BIN="${PYTHON:-$(command -v python3 || command -v python || true)}"

archive_name="$(basename "${ARCHIVE_PATH}")"
stage_name="${PRODUCT_NAME}-${VERSION}-${TARGET_OS}-${TARGET_ARCH}"
tmpdir="$(mktemp -d)"
search_root="${tmpdir}/${stage_name}"
mounted_dmg=""

path_for_windows_tool() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s\n' "$1"
  fi
}

if [[ "${archive_name}" == *.dmg ]]; then
  bash scripts/assert_release_payload.sh \
    "${VERSION}" \
    "${TARGET_OS}" \
    "${TARGET_ARCH}" \
    "${ARCHIVE_PATH}" \
    "${PRODUCT_NAME}"
fi

cleanup() {
  if [ -n "${mounted_dmg}" ]; then
    hdiutil detach -quiet "${mounted_dmg}" >/dev/null 2>&1 || true
  fi
  rm -rf "${tmpdir}"
}

trap cleanup EXIT

extract_zip() {
  if [ -z "${PYTHON_BIN}" ]; then
    echo "python3 or python is required to unpack zip archives" >&2
    exit 1
  fi
  "${PYTHON_BIN}" - "${ARCHIVE_PATH}" "${tmpdir}" <<'PY'
from pathlib import Path
from zipfile import ZipFile
import sys

archive = Path(sys.argv[1])
destination = Path(sys.argv[2])

with ZipFile(archive) as bundle:
    bundle.extractall(destination)
PY
}

extract_deb() {
  local member_dir="${tmpdir}/deb-members"
  local data_archive

  if [ -z "${PYTHON_BIN}" ]; then
    echo "python3 or python is required to inspect deb archives" >&2
    exit 1
  fi

  mkdir -p "${member_dir}"
  "${PYTHON_BIN}" - "${ARCHIVE_PATH}" "${member_dir}" <<'PY'
from pathlib import Path
import sys

archive = Path(sys.argv[1])
destination = Path(sys.argv[2])

with archive.open("rb") as fh:
    if fh.read(8) != b"!<arch>\n":
        raise SystemExit(f"not an ar archive: {archive}")
    while True:
        header = fh.read(60)
        if not header:
            break
        if len(header) != 60:
            raise SystemExit(f"truncated ar header in {archive}")
        name = header[:16].decode("utf-8").strip()
        if name.endswith("/"):
            name = name[:-1]
        size = int(header[48:58].decode("ascii").strip())
        data = fh.read(size)
        (destination / name).write_bytes(data)
        if size % 2:
            fh.read(1)
PY

  data_archive="$(find "${member_dir}" -maxdepth 1 -name 'data.tar.*' | head -n 1)"
  if [ -z "${data_archive}" ]; then
    echo "data archive not found in ${ARCHIVE_PATH}" >&2
    exit 1
  fi

  tar -xf "${data_archive}" -C "${tmpdir}"
  search_root="${tmpdir}/usr"
}

extract_dmg() {
  local mount_point="${tmpdir}/dmg-mount"

  if ! command -v hdiutil >/dev/null 2>&1; then
    echo "hdiutil is required to inspect dmg archives" >&2
    exit 1
  fi

  mkdir -p "${mount_point}"
  hdiutil attach -quiet -readonly -nobrowse -mountpoint "${mount_point}" "${ARCHIVE_PATH}" >/dev/null
  mounted_dmg="${mount_point}"
  search_root="${mount_point}"
}

extract_msi() {
  local extract_root="${tmpdir}/msi-admin"
  local log_path="${tmpdir}/msi-admin.log"

  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) ;;
    *)
      echo "MSI smoke validation requires a Windows host: ${archive_name}" >&2
      exit 1
      ;;
  esac

  if ! command -v msiexec.exe >/dev/null 2>&1; then
    echo "msiexec.exe is required to smoke-test MSI payloads: ${archive_name}" >&2
    exit 1
  fi

  mkdir -p "${extract_root}"
  msiexec.exe /a "$(path_for_windows_tool "${ARCHIVE_PATH}")" /qn \
    "TARGETDIR=$(path_for_windows_tool "${extract_root}")" \
    "/L*v" "$(path_for_windows_tool "${log_path}")"
  search_root="${extract_root}"
}

stage_dmg_app_for_execution() {
  local current_binary="$1"
  local app_source
  local staged_app

  case "${current_binary}" in
    *.app/Contents/MacOS/*) ;;
    *)
      printf 'binary in %s is not inside a macOS .app bundle: %s\n' "${archive_name}" "${current_binary}" >&2
      exit 1
      ;;
  esac

  app_source="${current_binary%%.app/Contents/MacOS/*}.app"
  staged_app="${tmpdir}/dmg-exec/$(basename "${app_source}")"
  mkdir -p "$(dirname "${staged_app}")"

  if command -v ditto >/dev/null 2>&1; then
    ditto "${app_source}" "${staged_app}"
  else
    cp -R "${app_source}" "${staged_app}"
  fi

  printf '%s/Contents/MacOS/%s\n' "${staged_app}" "${PRODUCT_NAME}"
}

case "${archive_name}" in
  *.tar.gz) tar -xzf "${ARCHIVE_PATH}" -C "${tmpdir}" ;;
  *.zip) extract_zip ;;
  *.deb) extract_deb ;;
  *.dmg) extract_dmg ;;
  *.msi) extract_msi ;;
  *)
    echo "unsupported archive path: ${ARCHIVE_PATH}" >&2
    exit 64
    ;;
esac

if [[ "${archive_name}" != *.dmg ]]; then
  bash scripts/assert_release_payload.sh \
    "${VERSION}" \
    "${TARGET_OS}" \
    "${TARGET_ARCH}" \
    "${ARCHIVE_PATH}" \
    "${PRODUCT_NAME}"
fi

binary_path="$(
  find "${search_root}" -type f \
    \( -name "${PRODUCT_NAME}" -o -name "${PRODUCT_NAME}.exe" \) | head -n 1
)"
if [ -z "${binary_path}" ]; then
  echo "binary not found in ${ARCHIVE_PATH}" >&2
  exit 1
fi

if [[ "${archive_name}" == *.dmg ]]; then
  binary_path="$(stage_dmg_app_for_execution "${binary_path}")"
fi

chmod +x "${binary_path}" 2>/dev/null || true

run_binary_output() {
  local label="$1"
  local attempts=0
  local max_retries="${SMOKE_SIGKILL_RETRIES:-2}"
  local output
  local status
  shift

  while :; do
    set +e
    output="$("$@" 2>&1)"
    status=$?
    set -e
    if [ "${status}" -eq 0 ]; then
      printf '%s\n' "${output}"
      return 0
    fi
    if [ "${status}" -eq 137 ] && [ "${attempts}" -lt "${max_retries}" ]; then
      attempts=$((attempts + 1))
      printf '%s for %s was killed with exit code 137; retrying (%s/%s)\n' \
        "${label}" "${archive_name}" "${attempts}" "${max_retries}" >&2
      sleep 1
      continue
    fi
    printf '%s failed for %s with exit code %s\n' "${label}" "${archive_name}" "${status}" >&2
    printf '%s\n' "${output}" >&2
    exit "${status}"
  done
}

version_output="$(run_binary_output "version smoke" "${binary_path}" --version)"
printf '%s\n' "${version_output}" | grep -F "${VERSION}" >/dev/null

case "${PRODUCT_NAME}" in
  paranoid-passwd)
    line_count="$("${binary_path}" --cli --length 16 --count 2 --no-audit --quiet | wc -l | tr -d ' ')"
    test "${line_count}" = "2"
    "${binary_path}" vault help >/dev/null
    ;;
  paranoid-passwd-gui)
    help_output="$(run_binary_output "GUI help smoke" "${binary_path}" --help)"
    printf '%s\n' "${help_output}" | grep -F "Usage: paranoid-passwd-gui" >/dev/null
    capture_path="${ARCHIVE_PATH}.smoke.png"
    if [ "${TARGET_OS}" = "linux" ]; then
      if command -v xvfb-run >/dev/null 2>&1; then
        bash scripts/capture_gui_screenshot.sh "${TARGET_OS}" "${binary_path}" "${capture_path}" "paranoid-passwd"
        [ -f "${capture_path}" ]
      elif [ "${SMOKE_ALLOW_NO_XVFB:-0}" != "1" ]; then
        printf 'xvfb-run not found; refusing to skip Linux GUI screenshot smoke for %s; expected %s\n' "${archive_name}" "${capture_path}" >&2
        exit 1
      fi
    fi
    ;;
  *)
    echo "unsupported product for smoke testing: ${PRODUCT_NAME}" >&2
    exit 64
    ;;
esac

printf 'smoke test passed for %s\n' "${archive_name}"
