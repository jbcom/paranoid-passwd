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
payload_root=""
control_root=""
mounted_dmg=""

extract_zip() {
  if [ -z "${PYTHON_BIN}" ]; then
    echo "python3 or python is required to inspect zip archives" >&2
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
  local control_archive
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

  if [ ! -f "${member_dir}/debian-binary" ]; then
    echo "missing debian-binary in ${ARCHIVE_PATH}" >&2
    exit 1
  fi
  grep -Fx '2.0' "${member_dir}/debian-binary" >/dev/null

  control_archive="$(find "${member_dir}" -maxdepth 1 -name 'control.tar.*' | head -n 1)"
  data_archive="$(find "${member_dir}" -maxdepth 1 -name 'data.tar.*' | head -n 1)"

  if [ -z "${control_archive}" ] || [ -z "${data_archive}" ]; then
    echo "deb package is missing control or data members: ${ARCHIVE_PATH}" >&2
    exit 1
  fi

  control_root="${tmpdir}/control"
  payload_root="${tmpdir}/data"
  mkdir -p "${control_root}" "${payload_root}"
  tar -xf "${control_archive}" -C "${control_root}"
  tar -xf "${data_archive}" -C "${payload_root}"
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
  payload_root="${mount_point}"
}

cleanup() {
  if [ -n "${mounted_dmg}" ]; then
    hdiutil detach -quiet "${mounted_dmg}" >/dev/null 2>&1 || true
  fi
  rm -rf "${tmpdir}"
}

trap cleanup EXIT

case "${archive_name}" in
  *.tar.gz)
    tar -xzf "${ARCHIVE_PATH}" -C "${tmpdir}"
    payload_root="${tmpdir}/${stage_name}"
    ;;
  *.zip)
    extract_zip
    payload_root="${tmpdir}/${stage_name}"
    ;;
  *.deb)
    extract_deb
    ;;
  *.dmg)
    extract_dmg
    ;;
  *)
    echo "unsupported archive path: ${ARCHIVE_PATH}" >&2
    exit 64
    ;;
esac

if [[ "${archive_name}" == *.deb ]]; then
  control_file="${control_root}/control"
  if [ ! -f "${control_file}" ]; then
    echo "expected deb control file missing: ${control_file}" >&2
    exit 1
  fi
  grep -F "Package: ${PRODUCT_NAME}" "${control_file}" >/dev/null
  grep -F "Version: ${VERSION}" "${control_file}" >/dev/null
  grep -F "Architecture: ${TARGET_ARCH}" "${control_file}" >/dev/null
else
  if [ ! -d "${payload_root}" ]; then
    echo "expected release stage root missing: ${payload_root}" >&2
    exit 1
  fi
  test -f "${payload_root}/LICENSE"
  test -f "${payload_root}/README.md"
fi

case "${PRODUCT_NAME}:${TARGET_OS}:${archive_name}" in
  paranoid-passwd:linux:*.deb)
    test -f "${payload_root}/usr/bin/${PRODUCT_NAME}"
    test -f "${payload_root}/usr/share/doc/${PRODUCT_NAME}/LICENSE"
    test -f "${payload_root}/usr/share/doc/${PRODUCT_NAME}/README.md"
    ;;
  paranoid-passwd-gui:linux:*.deb)
    test -f "${payload_root}/usr/bin/${PRODUCT_NAME}"
    desktop_path="${payload_root}/usr/share/applications/paranoid-passwd-gui.desktop"
    appdata_path="${payload_root}/usr/share/metainfo/paranoid-passwd-gui.appdata.xml"
    test -f "${desktop_path}"
    test -f "${appdata_path}"
    test -f "${payload_root}/usr/share/doc/${PRODUCT_NAME}/LICENSE"
    test -f "${payload_root}/usr/share/doc/${PRODUCT_NAME}/README.md"
    grep -F "Exec=paranoid-passwd-gui" "${desktop_path}" >/dev/null
    grep -F "<id>com.jbcom.paranoid-passwd.gui</id>" "${appdata_path}" >/dev/null
    ;;
  paranoid-passwd-gui:darwin:*.dmg)
    app_bundle="${payload_root}/Paranoid Passwd.app"
    plist_path="${app_bundle}/Contents/Info.plist"
    binary_path="${app_bundle}/Contents/MacOS/${PRODUCT_NAME}"
    test -f "${payload_root}/LICENSE"
    test -f "${payload_root}/README.md"
    test -d "${app_bundle}"
    test -f "${plist_path}"
    test -f "${binary_path}"
    /usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "${plist_path}" >/dev/null 2>&1 || \
      grep -F "<key>CFBundleExecutable</key>" "${plist_path}" >/dev/null
    ;;
  paranoid-passwd:*)
    binary_path="${payload_root}/${PRODUCT_NAME}"
    if [ "${TARGET_OS}" = "windows" ]; then
      binary_path="${binary_path}.exe"
    fi
    test -f "${binary_path}"
    ;;
  paranoid-passwd-gui:darwin:*)
    app_bundle="${payload_root}/Paranoid Passwd.app"
    plist_path="${app_bundle}/Contents/Info.plist"
    binary_path="${app_bundle}/Contents/MacOS/${PRODUCT_NAME}"
    test -d "${app_bundle}"
    test -f "${plist_path}"
    test -f "${binary_path}"
    /usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "${plist_path}" >/dev/null 2>&1 || \
      grep -F "<key>CFBundleExecutable</key>" "${plist_path}" >/dev/null
    ;;
  paranoid-passwd-gui:linux:*)
    test -f "${payload_root}/${PRODUCT_NAME}"
    desktop_path="${payload_root}/share/applications/paranoid-passwd-gui.desktop"
    appdata_path="${payload_root}/share/metainfo/paranoid-passwd-gui.appdata.xml"
    test -f "${desktop_path}"
    test -f "${appdata_path}"
    grep -F "Exec=paranoid-passwd-gui" "${desktop_path}" >/dev/null
    grep -F "<id>com.jbcom.paranoid-passwd.gui</id>" "${appdata_path}" >/dev/null
    ;;
  paranoid-passwd-gui:windows:*)
    test -f "${payload_root}/${PRODUCT_NAME}.exe"
    ;;
  *)
    echo "unsupported product/target combination: ${PRODUCT_NAME}:${TARGET_OS}" >&2
    exit 64
    ;;
esac

printf 'payload layout verified for %s\n' "${archive_name}"
