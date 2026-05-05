#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$REPO_ROOT/.config"
LOCAL_MK="$CONFIG_DIR/paranoid-local.mk"
LOCAL_ENV="$CONFIG_DIR/paranoid-local.env"
SUMMARY="$CONFIG_DIR/paranoid-local.summary"

ANDROID_TARGET="${ANDROID_TARGET:-aarch64-linux-android}"
WASM_TARGET="${WASM_TARGET:-wasm32-unknown-unknown}"
quiet=0

for argument in "$@"; do
  case "$argument" in
    -q|--quiet)
      quiet=1
      ;;
    -h|--help)
      cat <<'EOF'
Usage: scripts/configure_local_toolchain.sh [--quiet]

Detect the local Rust, Android, WASM, Docker, and GUI test build chain and write:
  .config/paranoid-local.mk
  .config/paranoid-local.env
  .config/paranoid-local.summary
EOF
      exit 0
      ;;
    *)
      echo "unsupported configure option: $argument" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$CONFIG_DIR"

command_path() {
  command -v "$1" 2>/dev/null || true
}

first_existing() {
  for candidate in "$@"; do
    if [ -n "$candidate" ] && [ -e "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

make_value() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/#/\\#/g' -e 's/\$/$$/g'
}

shell_export() {
  local name="$1"
  local value="$2"
  if [ -n "$value" ]; then
    printf 'export %s=%q\n' "$name" "$value"
  else
    printf 'unset %s\n' "$name"
  fi
}

bool_from_path() {
  if [ -n "$1" ]; then
    printf '1\n'
  else
    printf '0\n'
  fi
}

rust_target_installed() {
  local target="$1"
  rustup target list --installed 2>/dev/null | grep -Fxq "$target"
}

detect_android_sdk() {
  first_existing \
    "${ANDROID_HOME:-}" \
    "${ANDROID_SDK_ROOT:-}" \
    "$HOME/Library/Android/sdk" \
    "$HOME/Android/Sdk" \
    "$HOME/android-sdk" \
    "/opt/android-sdk" \
    "/usr/local/share/android-sdk" || true
}

detect_android_ndk() {
  local sdk="$1"
  if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_NDK_HOME" ]; then
    printf '%s\n' "$ANDROID_NDK_HOME"
    return 0
  fi
  if [ -n "${ANDROID_NDK_ROOT:-}" ] && [ -d "$ANDROID_NDK_ROOT" ]; then
    printf '%s\n' "$ANDROID_NDK_ROOT"
    return 0
  fi
  if [ -n "$sdk" ] && [ -d "$sdk/ndk" ]; then
    find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1
    return 0
  fi
  return 1
}

detect_ndk_bin() {
  local ndk="$1"
  local kernel
  local machine
  local preferred=""
  kernel="$(uname -s | tr '[:upper:]' '[:lower:]')"
  machine="$(uname -m)"

  case "$kernel:$machine" in
    darwin:arm64) preferred="darwin-arm64" ;;
    darwin:*) preferred="darwin-x86_64" ;;
    linux:aarch64|linux:arm64) preferred="linux-aarch64" ;;
    linux:*) preferred="linux-x86_64" ;;
  esac

  first_existing \
    "$ndk/toolchains/llvm/prebuilt/$preferred/bin" \
    "$ndk/toolchains/llvm/prebuilt/darwin-arm64/bin" \
    "$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin" \
    "$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin" \
    "$ndk/toolchains/llvm/prebuilt/linux-aarch64/bin" || \
    find "$ndk/toolchains/llvm/prebuilt" -mindepth 2 -maxdepth 2 -type d -name bin 2>/dev/null | sort | head -n 1
}

detect_android_api() {
  local ndk_bin="$1"
  local best=0
  local clang base api
  if [ -n "${ANDROID_API:-}" ]; then
    printf '%s\n' "$ANDROID_API"
    return 0
  fi
  for clang in "$ndk_bin"/aarch64-linux-android*-clang; do
    [ -e "$clang" ] || continue
    base="${clang##*/}"
    api="${base#aarch64-linux-android}"
    api="${api%-clang}"
    case "$api" in
      ''|*[!0-9]*) continue ;;
    esac
    if [ "$api" -gt "$best" ]; then
      best="$api"
    fi
  done
  if [ "$best" -gt 0 ]; then
    printf '%s\n' "$best"
  fi
}

host_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
host_arch="$(uname -m)"
case "$host_arch" in
  x86_64) host_arch="amd64" ;;
  aarch64) host_arch="arm64" ;;
esac

cargo_bin="$(command_path cargo)"
rustc_bin="$(command_path rustc)"
rustup_bin="$(command_path rustup)"
docker_bin="$(command_path docker)"
if [ -z "$docker_bin" ]; then
  docker_bin="$(first_existing "/Applications/Docker.app/Contents/Resources/bin/docker" || true)"
fi
docker_bin_dir=""
docker_ready=0
if [ -n "$docker_bin" ]; then
  docker_bin_dir="$(dirname "$docker_bin")"
  if PATH="$docker_bin_dir:$PATH" "$docker_bin" info >/dev/null 2>&1; then
    docker_ready=1
  fi
fi
xvfb_run_bin="$(command_path xvfb-run)"
image_magick_import_bin="$(command_path import)"
image_magick_identify_bin="$(command_path identify)"
wasm_pack_bin="$(command_path wasm-pack)"

android_home="$(detect_android_sdk)"
android_ndk_home=""
android_ndk_bin=""
android_api=""
android_cc=""
android_ar=""
android_ranlib=""
android_linker=""
adb_bin=""
emulator_bin=""
maestro_bin="$(command_path maestro)"
if [ -z "$maestro_bin" ]; then
  maestro_bin="$(first_existing "$HOME/.maestro/bin/maestro" || true)"
fi

if [ -n "$android_home" ]; then
  android_ndk_home="$(detect_android_ndk "$android_home")"
  adb_bin="$(first_existing "$android_home/platform-tools/adb" "$(command_path adb)" || true)"
  emulator_bin="$(first_existing "$android_home/emulator/emulator" "$(command_path emulator)" || true)"
fi

if [ -n "$android_ndk_home" ]; then
  android_ndk_bin="$(detect_ndk_bin "$android_ndk_home")"
fi

if [ -n "$android_ndk_bin" ]; then
  android_api="$(detect_android_api "$android_ndk_bin")"
  if [ -n "$android_api" ]; then
    android_cc="$android_ndk_bin/aarch64-linux-android${android_api}-clang"
    android_linker="$android_cc"
  fi
  android_ar="$android_ndk_bin/llvm-ar"
  android_ranlib="$android_ndk_bin/llvm-ranlib"
fi

android_target_installed=0
wasm_target_installed=0
if [ -n "$rustup_bin" ]; then
  if rust_target_installed "$ANDROID_TARGET"; then
    android_target_installed=1
  fi
  if rust_target_installed "$WASM_TARGET"; then
    wasm_target_installed=1
  fi
fi

android_ready=0
if [ -n "$android_home" ] \
  && [ -n "$android_ndk_home" ] \
  && [ -x "$android_cc" ] \
  && [ -x "$android_ar" ] \
  && [ -x "$android_ranlib" ] \
  && [ "$android_target_installed" -eq 1 ]; then
  android_ready=1
fi

wasm_ready=0
if [ "$wasm_target_installed" -eq 1 ]; then
  wasm_ready=1
fi

gui_capture_ready=0
if [ -n "$xvfb_run_bin" ] && [ -n "$image_magick_import_bin" ] && [ -n "$image_magick_identify_bin" ]; then
  gui_capture_ready=1
fi

local_gui_e2e_mode="missing"
case "$host_os" in
  linux)
    if [ "$gui_capture_ready" -eq 1 ]; then
      local_gui_e2e_mode="host-xvfb"
    fi
    ;;
  darwin)
    if [ "$docker_ready" -eq 1 ]; then
      local_gui_e2e_mode="docker-builder-xvfb"
    fi
    ;;
esac

cat >"$LOCAL_MK" <<EOF
# Generated by ./configure. Do not edit by hand.
LOCAL_CONFIGURED := 1
LOCAL_CONFIG_SUMMARY := $(make_value "$SUMMARY")
LOCAL_CONFIG_ENV := $(make_value "$LOCAL_ENV")
HOST_OS := $(make_value "$host_os")
HOST_ARCH := $(make_value "$host_arch")
CARGO_BIN := $(make_value "$cargo_bin")
RUSTC_BIN := $(make_value "$rustc_bin")
RUSTUP_BIN := $(make_value "$rustup_bin")
DOCKER := $(make_value "$docker_bin")
DOCKER_BIN_DIR := $(make_value "$docker_bin_dir")
DOCKER_READY := $docker_ready
XVFB_RUN := $(make_value "$xvfb_run_bin")
IMAGE_MAGICK_IMPORT := $(make_value "$image_magick_import_bin")
IMAGE_MAGICK_IDENTIFY := $(make_value "$image_magick_identify_bin")
GUI_CAPTURE_READY := $gui_capture_ready
LOCAL_GUI_E2E_MODE := $(make_value "$local_gui_e2e_mode")
WASM_PACK := $(make_value "$wasm_pack_bin")
WASM_TARGET := $(make_value "$WASM_TARGET")
WASM_TARGET_INSTALLED := $wasm_target_installed
WASM_TOOLCHAIN_READY := $wasm_ready
WASM_READY := $wasm_ready
ANDROID_TARGET := $(make_value "$ANDROID_TARGET")
ANDROID_HOME := $(make_value "$android_home")
ANDROID_SDK_ROOT := $(make_value "$android_home")
ANDROID_NDK_HOME := $(make_value "$android_ndk_home")
ANDROID_NDK_ROOT := $(make_value "$android_ndk_home")
ANDROID_NDK_BIN := $(make_value "$android_ndk_bin")
ANDROID_API := $(make_value "$android_api")
ANDROID_CC_AARCH64 := $(make_value "$android_cc")
ANDROID_AR := $(make_value "$android_ar")
ANDROID_RANLIB := $(make_value "$android_ranlib")
ANDROID_LINKER_AARCH64 := $(make_value "$android_linker")
ANDROID_TARGET_INSTALLED := $android_target_installed
ANDROID_TOOLCHAIN_READY := $android_ready
ANDROID_READY := $android_ready
ADB := $(make_value "$adb_bin")
ANDROID_EMULATOR := $(make_value "$emulator_bin")
MAESTRO := $(make_value "$maestro_bin")
EOF

{
  printf '# Generated by ./configure. Source this for manual Android/WASM commands.\n'
  shell_export ANDROID_TARGET "$ANDROID_TARGET"
  shell_export ANDROID_HOME "$android_home"
  shell_export ANDROID_SDK_ROOT "$android_home"
  shell_export ANDROID_NDK_HOME "$android_ndk_home"
  shell_export ANDROID_NDK_ROOT "$android_ndk_home"
  shell_export CC_aarch64_linux_android "$android_cc"
  shell_export AR_aarch64_linux_android "$android_ar"
  shell_export RANLIB_aarch64_linux_android "$android_ranlib"
  shell_export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER "$android_linker"
  shell_export ADB "$adb_bin"
  shell_export MAESTRO "$maestro_bin"
  shell_export DOCKER "$docker_bin"
  shell_export DOCKER_BIN_DIR "$docker_bin_dir"
  shell_export WASM_TARGET "$WASM_TARGET"
  shell_export WASM_PACK "$wasm_pack_bin"
} >"$LOCAL_ENV"

{
  printf 'Local build chain configuration\n'
  printf 'host: %s/%s\n' "$host_os" "$host_arch"
  printf 'cargo: %s\n' "${cargo_bin:-missing}"
  printf 'rustc: %s\n' "${rustc_bin:-missing}"
  printf 'docker: %s\n' "${docker_bin:-missing}"
  printf 'docker bin dir: %s\n' "${docker_bin_dir:-missing}"
  printf 'docker ready: %s\n' "$docker_ready"
  printf 'xvfb-run: %s\n' "${xvfb_run_bin:-missing}"
  printf 'imagemagick import: %s\n' "${image_magick_import_bin:-missing}"
  printf 'imagemagick identify: %s\n' "${image_magick_identify_bin:-missing}"
  printf 'gui capture ready: %s\n' "$gui_capture_ready"
  printf 'local gui e2e mode: %s\n' "$local_gui_e2e_mode"
  printf 'android sdk: %s\n' "${android_home:-missing}"
  printf 'android ndk: %s\n' "${android_ndk_home:-missing}"
  printf 'android api: %s\n' "${android_api:-missing}"
  printf 'android cc: %s\n' "${android_cc:-missing}"
  printf 'android rust target installed: %s\n' "$android_target_installed"
  printf 'android toolchain ready: %s\n' "$android_ready"
  printf 'wasm target installed: %s\n' "$wasm_target_installed"
  printf 'wasm-pack: %s\n' "${wasm_pack_bin:-missing}"
  printf 'wasm toolchain ready: %s\n' "$wasm_ready"
  printf 'adb: %s\n' "${adb_bin:-missing}"
  printf 'emulator: %s\n' "${emulator_bin:-missing}"
  printf 'maestro: %s\n' "${maestro_bin:-missing}"
  printf 'make include: %s\n' "$LOCAL_MK"
  printf 'shell env: %s\n' "$LOCAL_ENV"
} >"$SUMMARY"

if [ "$quiet" -ne 1 ]; then
  cat "$SUMMARY"
fi
