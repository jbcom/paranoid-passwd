#!/usr/bin/env bash

set -euo pipefail

VERSION="${1:?version required}"
TARGET_OS="${2:?target os required}"
TARGET_ARCH="${3:?target arch required}"
EXT="${4-}"
ARCHIVE="${5:?archive format required}"
OUT_DIR="${6:?output dir required}"
PYTHON_BIN="${PYTHON:-$(command -v python3 || command -v python || true)}"

case "${ARCHIVE}" in
  tar.gz|zip) ;;
  *)
    echo "unsupported archive format: ${ARCHIVE}" >&2
    exit 64
    ;;
esac

if [ -z "${PYTHON_BIN}" ]; then
  echo "python3 or python is required to package zip archives" >&2
  exit 1
fi

stage_name="paranoid-passwd-${VERSION}-${TARGET_OS}-${TARGET_ARCH}"
stage_root="${OUT_DIR}/stage"
stage_dir="${stage_root}/${stage_name}"
artifact="${OUT_DIR}/${stage_name}.${ARCHIVE}"
binary_path="target/release/paranoid-passwd${EXT}"

mkdir -p "${stage_dir}"

cargo build -p paranoid-cli --release --locked --frozen --offline

cp "${binary_path}" "${stage_dir}/"
cp LICENSE README.md "${stage_dir}/"

if [ "${ARCHIVE}" = "zip" ]; then
  "${PYTHON_BIN}" - "${stage_root}" "${stage_name}" "${artifact}" <<'PY'
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
import sys

stage_root = Path(sys.argv[1])
stage_name = sys.argv[2]
artifact = Path(sys.argv[3])

with ZipFile(artifact, "w", compression=ZIP_DEFLATED) as archive:
    for path in sorted((stage_root / stage_name).rglob("*")):
        if path.is_file():
            archive.write(path, path.relative_to(stage_root))
PY
else
  tar -C "${stage_root}" -czf "${artifact}" "${stage_name}"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${artifact}" > "${artifact}.sha256"
else
  shasum -a 256 "${artifact}" > "${artifact}.sha256"
fi

printf '%s\n' "${artifact}"
