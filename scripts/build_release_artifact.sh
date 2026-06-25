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
  tar.gz|zip|deb|dmg|msi) ;;
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
if [ "${ARCHIVE}" = "msi" ] && [ "${TARGET_OS}" != "windows" ]; then
  echo "msi packaging is only supported for windows targets" >&2
  exit 64
fi
if [ "${ARCHIVE}" = "msi" ] && [ "${PRODUCT_NAME}" != "paranoid-passwd-gui" ]; then
  echo "msi packaging is only supported for paranoid-passwd-gui" >&2
  exit 64
fi

stage_name="${PRODUCT_NAME}-${VERSION}-${TARGET_OS}-${TARGET_ARCH}"
stage_root="${OUT_DIR}/stage"
stage_dir="${stage_root}/${stage_name}"
if [ "${ARCHIVE}" = "deb" ]; then
  artifact="${OUT_DIR}/${PRODUCT_NAME}_${VERSION}_${TARGET_ARCH}.deb"
elif [ "${ARCHIVE}" = "dmg" ]; then
  artifact="${OUT_DIR}/${stage_name}.dmg"
elif [ "${ARCHIVE}" = "msi" ]; then
  artifact="${OUT_DIR}/${stage_name}.msi"
else
  artifact="${OUT_DIR}/${stage_name}.${ARCHIVE}"
fi
artifact_name="$(basename "${artifact}")"
target_root="${CARGO_TARGET_DIR:-target}"
target_root="${target_root%/}"
binary_path="${target_root}/release/${PRODUCT_NAME}${EXT}"
release_signing_mode="${PARANOID_RELEASE_SIGNING_MODE:-unsigned}"

path_for_windows_tool() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s\n' "$1"
  fi
}

add_linux_gui_metadata() {
  local share_root="$1"

  mkdir -p "${share_root}/applications"
  mkdir -p "${share_root}/metainfo"
  cat > "${share_root}/applications/paranoid-passwd-gui.desktop" <<'DESKTOP'
[Desktop Entry]
Version=1.0
Type=Application
Name=Paranoid Passwd
Comment=Local-first password manager and generator
Exec=paranoid-passwd-gui
Terminal=false
Categories=Utility;Security;
DESKTOP
  cat > "${share_root}/metainfo/paranoid-passwd-gui.appdata.xml" <<APPDATA
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>com.jbcom.paranoid-passwd.gui</id>
  <name>Paranoid Passwd</name>
  <summary>Local-first password manager and generator</summary>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>GPL-3.0-only</project_license>
  <developer_name>Jon Bogaty</developer_name>
  <launchable type="desktop-id">paranoid-passwd-gui.desktop</launchable>
  <description>
    <p>Paranoid Passwd is a local-first password manager and generator with a Rust-native vault, CLI, TUI, and desktop GUI.</p>
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
    add_linux_gui_metadata "${package_root}/usr/share"
    package_summary="Local-first password manager and generator desktop GUI"
    package_description=" Local-first password manager and generator desktop GUI with encrypted vault, native unlock flows, and release-verifiable packaging."
  else
    package_summary="Local-first password manager and generator CLI and TUI"
    package_description=" Scriptable CLI and full-screen TUI for the Paranoid Passwd local-first password manager and generator."
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
  bash scripts/macos_sign_notarize.sh \
    --mode "${release_signing_mode}" \
    --kind dmg \
    --dmg "${artifact}"
}

build_msi_package() {
  local wix_cmd="${WIX:-}"
  local wix_arch
  local wxs_path
  local exe_source
  local license_source
  local readme_source

  if [ "${PRODUCT_NAME}" != "paranoid-passwd-gui" ] || [ "${TARGET_OS}" != "windows" ]; then
    echo "msi packaging is only supported for paranoid-passwd-gui on windows targets" >&2
    exit 64
  fi

  if [ -z "${wix_cmd}" ]; then
    wix_cmd="$(command -v wix || command -v wix.exe || true)"
  fi
  if [ -z "${wix_cmd}" ]; then
    echo "WiX Toolset wix command is required to package msi artifacts" >&2
    exit 1
  fi

  case "${TARGET_ARCH}" in
    amd64) wix_arch="x64" ;;
    arm64) wix_arch="arm64" ;;
    *)
      echo "unsupported Windows MSI architecture: ${TARGET_ARCH}" >&2
      exit 64
      ;;
  esac

  cp "${binary_path}" "${stage_dir}/${PRODUCT_NAME}${EXT}"
  cp LICENSE README.md "${stage_dir}/"

  bash scripts/windows_sign_artifact.sh \
    --mode "${release_signing_mode}" \
    --artifact "${stage_dir}/${PRODUCT_NAME}${EXT}"

  wxs_path="${stage_root}/${stage_name}.wxs"
  exe_source="$(path_for_windows_tool "${stage_dir}/${PRODUCT_NAME}${EXT}")"
  license_source="$(path_for_windows_tool "${stage_dir}/LICENSE")"
  readme_source="$(path_for_windows_tool "${stage_dir}/README.md")"

  cat > "${wxs_path}" <<WXS
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Id="com.jbcom.paranoid-passwd.gui" Name="Paranoid Passwd"
           Manufacturer="Jon Bogaty" Version="${VERSION}"
           UpgradeCode="2f79e1b5-49e4-4a8a-a6a8-1ecda82af8fe">
    <MajorUpgrade DowngradeErrorMessage="A newer version of [ProductName] is already installed." />
    <MediaTemplate EmbedCab="yes" />
    <StandardDirectory Id="ProgramFiles6432Folder">
      <Directory Id="INSTALLFOLDER" Name="Paranoid Passwd">
        <Component Id="GuiExecutable" Guid="46b87264-3476-41a7-9de4-340c50956699">
          <File Id="ParanoidPasswdGuiExe" Source="${exe_source}" KeyPath="yes" />
        </Component>
        <Component Id="LicenseFile" Guid="4f6d19fb-927e-4475-bdc9-f063191b1acf">
          <File Id="ParanoidPasswdLicense" Source="${license_source}" KeyPath="yes" />
        </Component>
        <Component Id="ReadmeFile" Guid="45661679-3365-4060-9aa9-f411f142e637">
          <File Id="ParanoidPasswdReadme" Source="${readme_source}" KeyPath="yes" />
        </Component>
      </Directory>
    </StandardDirectory>
    <Feature Id="DefaultFeature" Title="Paranoid Passwd" Level="1">
      <ComponentRef Id="GuiExecutable" />
      <ComponentRef Id="LicenseFile" />
      <ComponentRef Id="ReadmeFile" />
    </Feature>
  </Package>
</Wix>
WXS

  rm -f "${artifact}"
  "${wix_cmd}" build -arch "${wix_arch}" -pdbtype none -out "${artifact}" "${wxs_path}"
  bash scripts/windows_sign_artifact.sh \
    --mode "${release_signing_mode}" \
    --artifact "${artifact}"
}

stage_macos_gui_app() {
  local app_name="Paranoid Passwd.app"
  local bundle_root="${stage_dir}/${app_name}/Contents"
  local bundle_exec_dir="${bundle_root}/MacOS"

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
  bash scripts/macos_sign_notarize.sh \
    --mode "${release_signing_mode}" \
    --kind app \
    --app "${stage_dir}/${app_name}"
}

rm -rf "${stage_dir}"
mkdir -p "${stage_dir}"

cargo build -p "${CARGO_PACKAGE}" --release --locked --frozen --offline

if [ "${ARCHIVE}" = "deb" ]; then
  build_deb_package
elif [ "${ARCHIVE}" = "dmg" ]; then
  if [ "${PRODUCT_NAME}" = "paranoid-passwd-gui" ] && [ "${TARGET_OS}" = "darwin" ]; then
    stage_macos_gui_app
  fi
elif [ "${ARCHIVE}" = "msi" ]; then
  :
elif [ "${PRODUCT_NAME}" = "paranoid-passwd-gui" ] && [ "${TARGET_OS}" = "darwin" ]; then
  stage_macos_gui_app
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
elif [ "${ARCHIVE}" = "msi" ]; then
  build_msi_package
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
  (cd "${OUT_DIR}" && sha256sum "${artifact_name}") > "${artifact}.sha256"
else
  (cd "${OUT_DIR}" && shasum -a 256 "${artifact_name}") > "${artifact}.sha256"
fi

printf '%s\n' "${artifact}"
