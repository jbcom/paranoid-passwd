#!/usr/bin/env bash

set -euo pipefail

TARGET_OS="${1:?target os required}"
BINARY_PATH="${2:?binary path required}"
OUTPUT_PATH="${3:?output path required}"
WINDOW_NAME="${4:-paranoid-passwd}"

HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"

capture_linux() {
  if ! command -v xvfb-run >/dev/null 2>&1; then
    echo "xvfb-run is required for Linux GUI capture" >&2
    return 1
  fi
  if ! command -v import >/dev/null 2>&1; then
    echo "ImageMagick import is required for Linux GUI capture" >&2
    return 1
  fi
  if ! command -v identify >/dev/null 2>&1; then
    echo "ImageMagick identify is required for Linux GUI capture" >&2
    return 1
  fi

  mkdir -p "$(dirname "${OUTPUT_PATH}")"

  xvfb-run -a env WINIT_UNIX_BACKEND=x11 bash -lc '
    set -euo pipefail
    binary_path="$1"
    output_path="$2"
    log_path="${output_path}.log"
    screenshot_ready=0

    cleanup() {
      if [ -n "${gui_pid:-}" ]; then
        kill "${gui_pid}" >/dev/null 2>&1 || true
        wait "${gui_pid}" >/dev/null 2>&1 || true
      fi
    }
    trap cleanup EXIT

    "${binary_path}" >"${log_path}" 2>&1 &
    gui_pid=$!

    capture_gui_window() {
      if ! import -descend -window "'"${WINDOW_NAME}"'" "${output_path}" 2>/dev/null; then
        import -window root "${output_path}"
      fi
    }

    for _ in $(seq 1 120); do
      if ! kill -0 "${gui_pid}" >/dev/null 2>&1; then
        cat "${log_path}" >&2 || true
        echo "GUI exited before rendering under Xvfb" >&2
        exit 1
      fi

      capture_gui_window
      read -r width height colors scaled_mean < <(
        identify -format "%w %h %k %[fx:int(mean*1000000)]\n" "${output_path}"
      )

      if [ "${width}" -ge 400 ] \
        && [ "${height}" -ge 300 ] \
        && [ "${colors}" -gt 32 ] \
        && [ "${scaled_mean}" -gt 10000 ]; then
        screenshot_ready=1
        break
      fi

      sleep 0.1
    done

    if [ "${screenshot_ready}" -ne 1 ]; then
      cat "${log_path}" >&2 || true
      echo "GUI did not render a non-blank screenshot under Xvfb" >&2
      exit 1
    fi
  ' _ "${BINARY_PATH}" "${OUTPUT_PATH}"
}

case "${TARGET_OS}:${HOST_OS}" in
  linux:linux)
    capture_linux
    ;;
  *)
    echo "GUI screen capture is not implemented for target=${TARGET_OS} on host=${HOST_OS}" >&2
    exit 64
    ;;
esac

printf 'captured GUI screenshot: %s\n' "${OUTPUT_PATH}"
