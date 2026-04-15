#!/usr/bin/env bash

set -euo pipefail

VERSION="${1:?version required}"
TARGET_OS="${2:?target os required}"
TARGET_ARCH="${3:?target arch required}"
ARCHIVE_PATH="${4:?archive path required}"
PYTHON_BIN="${PYTHON:-$(command -v python3 || command -v python || true)}"

archive_name="$(basename "${ARCHIVE_PATH}")"
stage_name="paranoid-passwd-${VERSION}-${TARGET_OS}-${TARGET_ARCH}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

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

case "${archive_name}" in
  *.tar.gz) tar -xzf "${ARCHIVE_PATH}" -C "${tmpdir}" ;;
  *.zip) extract_zip ;;
  *)
    echo "unsupported archive path: ${ARCHIVE_PATH}" >&2
    exit 64
    ;;
esac

binary_path="$(find "${tmpdir}/${stage_name}" -type f \( -name paranoid-passwd -o -name 'paranoid-passwd.exe' \) | head -n 1)"
if [ -z "${binary_path}" ]; then
  echo "binary not found in ${ARCHIVE_PATH}" >&2
  exit 1
fi

chmod +x "${binary_path}" 2>/dev/null || true

version_output="$("${binary_path}" --version 2>&1)"
printf '%s\n' "${version_output}" | grep -F "${VERSION}" >/dev/null

line_count="$("${binary_path}" --cli --length 16 --count 2 --no-audit --quiet | wc -l | tr -d ' ')"
test "${line_count}" = "2"

"${binary_path}" vault help >/dev/null

printf 'smoke test passed for %s\n' "${archive_name}"
