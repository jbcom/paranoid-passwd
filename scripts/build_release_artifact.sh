#!/usr/bin/env bash

set -euo pipefail

VERSION="${1:?version required}"
TARGET_OS="${2:?target os required}"
TARGET_ARCH="${3:?target arch required}"
EXT="${4-}"
ARCHIVE="${5:?archive format required}"
OUT_DIR="${6:?output dir required}"
PRODUCT_NAME="${7:-paranoid-passwd}"
CARGO_PACKAGE="${8:-paranoid-cli}"
PYTHON_BIN="${PYTHON:-$(command -v python3 || command -v python || true)}"

case "${ARCHIVE}" in
  tar.gz|zip|deb|dmg) ;;
  *)
    echo "unsupported archive format: ${ARCHIVE}" >&2
    exit 64
    ;;
esac

if { [ "${ARCHIVE}" = "zip" ] || [ "${ARCHIVE}" = "deb" ]; } && [ -z "${PYTHON_BIN}" ]; then
  echo "python3 or python is required to package ${ARCHIVE} artifacts" >&2
  exit 1
fi
if [ "${ARCHIVE}" = "dmg" ] && ! command -v hdiutil >/dev/null 2>&1; then
  echo "hdiutil is required to package dmg artifacts" >&2
  exit 1
fi

stage_name="${PRODUCT_NAME}-${VERSION}-${TARGET_OS}-${TARGET_ARCH}"
stage_root="${OUT_DIR}/stage"
stage_dir="${stage_root}/${stage_name}"
if [ "${ARCHIVE}" = "deb" ]; then
  artifact="${OUT_DIR}/${PRODUCT_NAME}_${VERSION}_${TARGET_ARCH}.deb"
elif [ "${ARCHIVE}" = "dmg" ]; then
  artifact="${OUT_DIR}/${stage_name}.dmg"
else
  artifact="${OUT_DIR}/${stage_name}.${ARCHIVE}"
fi
binary_path="target/release/${PRODUCT_NAME}${EXT}"

add_linux_gui_metadata() {
  local root_dir="$1"

  mkdir -p "${root_dir}/share/applications"
  mkdir -p "${root_dir}/share/metainfo"
  cat > "${root_dir}/share/applications/paranoid-passwd-gui.desktop" <<'DESKTOP'
[Desktop Entry]
Version=1.0
Type=Application
Name=Paranoid Passwd
Comment=Local-first password manager
Exec=paranoid-passwd-gui
Terminal=false
Categories=Utility;Security;
DESKTOP
  cat > "${root_dir}/share/metainfo/paranoid-passwd-gui.appdata.xml" <<APPDATA
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>com.jbcom.paranoid-passwd.gui</id>
  <name>Paranoid Passwd</name>
  <summary>Local-first password manager</summary>
  <metadata_license>MIT</metadata_license>
  <project_license>MIT</project_license>
  <developer_name>Jon Bogaty</developer_name>
  <launchable type="desktop-id">paranoid-passwd-gui.desktop</launchable>
  <description>
    <p>Paranoid Passwd is a local-first password manager with a Rust-native vault, CLI, TUI, and desktop GUI.</p>
  </description>
  <url type="homepage">https://paranoid-passwd.com</url>
  <url type="bugtracker">https://github.com/jbcom/paranoid-passwd/issues</url>
  <releases>
    <release version="${VERSION}"/>
  </releases>
</component>
APPDATA
}

build_deb_package() {
  local package_root
  local control_root
  local doc_root
  local binary_target
  local member_root
  local package_description
  local package_summary

  if [ "${TARGET_OS}" != "linux" ]; then
    echo "deb packaging is only supported for linux targets" >&2
    exit 64
  fi

  package_root="${OUT_DIR}/deb-root/${PRODUCT_NAME}"
  control_root="${OUT_DIR}/deb-control/${PRODUCT_NAME}"
  member_root="${OUT_DIR}/deb-members/${PRODUCT_NAME}-${TARGET_ARCH}"
  doc_root="${package_root}/usr/share/doc/${PRODUCT_NAME}"
  binary_target="${package_root}/usr/bin/${PRODUCT_NAME}"

  rm -rf "${package_root}" "${control_root}" "${member_root}"
  mkdir -p "${package_root}/usr/bin" "${doc_root}" "${control_root}" "${member_root}"

  cp "${binary_path}" "${binary_target}"
  chmod 0755 "${binary_target}"
  cp LICENSE README.md "${doc_root}/"

  if [ "${PRODUCT_NAME}" = "paranoid-passwd-gui" ]; then
    mkdir -p "${package_root}/usr/share"
    add_linux_gui_metadata "${package_root}/usr"
    package_summary="Local-first password manager desktop GUI"
    package_description=" Local-first password manager desktop GUI with encrypted vault, native unlock flows, and release-verifiable packaging."
  else
    package_summary="Local-first password manager CLI and TUI"
    package_description=" Scriptable CLI and full-screen TUI for the Paranoid Passwd local-first password manager."
  fi

  cat > "${control_root}/control" <<CONTROL
Package: ${PRODUCT_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${TARGET_ARCH}
Maintainer: Jon Bogaty <noreply@jonbogaty.com>
Homepage: https://paranoid-passwd.com
Description: ${package_summary}
${package_description}
CONTROL

  printf '2.0\n' > "${member_root}/debian-binary"
  COPYFILE_DISABLE=1 COPY_EXTENDED_ATTRIBUTES_DISABLE=1 tar -C "${control_root}" -czf "${member_root}/control.tar.gz" .
  COPYFILE_DISABLE=1 COPY_EXTENDED_ATTRIBUTES_DISABLE=1 tar -C "${package_root}" -czf "${member_root}/data.tar.gz" .
  rm -f "${artifact}"
  "${PYTHON_BIN}" - "${artifact}" "${member_root}/debian-binary" "${member_root}/control.tar.gz" "${member_root}/data.tar.gz" <<'PY'
from pathlib import Path
import stat
import sys

artifact = Path(sys.argv[1])
members = [Path(path) for path in sys.argv[2:]]

with artifact.open("wb") as archive:
    archive.write(b"!<arch>\n")
    for member in members:
        data = member.read_bytes()
        info = member.stat()
        name = f"{member.name}/"
        if len(name) > 16:
            raise SystemExit(f"deb member name too long: {member.name}")
        header = (
            f"{name:<16}"
            f"{int(info.st_mtime):<12}"
            f"{0:<6}"
            f"{0:<6}"
            f"{stat.S_IMODE(info.st_mode):<8o}"
            f"{len(data):<10}"
            "`\n"
        )
        archive.write(header.encode("ascii"))
        archive.write(data)
        if len(data) % 2:
            archive.write(b"\n")
PY
}

build_dmg_package() {
  if [ "${PRODUCT_NAME}" != "paranoid-passwd-gui" ] || [ "${TARGET_OS}" != "darwin" ]; then
    echo "dmg packaging is only supported for paranoid-passwd-gui on darwin targets" >&2
    exit 64
  fi

  rm -f "${artifact}"
  hdiutil create \
    -quiet \
    -volname "Paranoid Passwd" \
    -srcfolder "${stage_dir}" \
    -ov \
    -format UDZO \
    "${artifact}"
}

rm -rf "${stage_dir}"
mkdir -p "${stage_dir}"

cargo build -p "${CARGO_PACKAGE}" --release --locked --frozen --offline

if [ "${ARCHIVE}" = "deb" ]; then
  build_deb_package
elif [ "${ARCHIVE}" = "dmg" ]; then
  if [ "${PRODUCT_NAME}" = "paranoid-passwd-gui" ] && [ "${TARGET_OS}" = "darwin" ]; then
    app_name="Paranoid Passwd.app"
    bundle_root="${stage_dir}/${app_name}/Contents"
    bundle_exec_dir="${bundle_root}/MacOS"
    mkdir -p "${bundle_exec_dir}"
    cp "${binary_path}" "${bundle_exec_dir}/${PRODUCT_NAME}"
    cat > "${bundle_root}/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>${PRODUCT_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>com.jbcom.paranoid-passwd.gui</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Paranoid Passwd</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST
  fi
elif [ "${PRODUCT_NAME}" = "paranoid-passwd-gui" ] && [ "${TARGET_OS}" = "darwin" ]; then
  app_name="Paranoid Passwd.app"
  bundle_root="${stage_dir}/${app_name}/Contents"
  bundle_exec_dir="${bundle_root}/MacOS"
  mkdir -p "${bundle_exec_dir}"
  cp "${binary_path}" "${bundle_exec_dir}/${PRODUCT_NAME}"
  cat > "${bundle_root}/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>${PRODUCT_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>com.jbcom.paranoid-passwd.gui</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Paranoid Passwd</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST
else
  cp "${binary_path}" "${stage_dir}/"
fi

if [ "${ARCHIVE}" != "deb" ] && [ "${ARCHIVE}" != "dmg" ] && [ "${PRODUCT_NAME}" = "paranoid-passwd-gui" ] && [ "${TARGET_OS}" = "linux" ]; then
  add_linux_gui_metadata "${stage_dir}/share"
fi

if [ "${ARCHIVE}" != "deb" ]; then
  cp LICENSE README.md "${stage_dir}/"
fi

if [ "${ARCHIVE}" = "deb" ]; then
  :
elif [ "${ARCHIVE}" = "dmg" ]; then
  build_dmg_package
elif [ "${ARCHIVE}" = "zip" ]; then
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
  COPYFILE_DISABLE=1 COPY_EXTENDED_ATTRIBUTES_DISABLE=1 tar -C "${stage_root}" -czf "${artifact}" "${stage_name}"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${artifact}" > "${artifact}.sha256"
else
  shasum -a 256 "${artifact}" > "${artifact}.sha256"
fi

printf '%s\n' "${artifact}"
