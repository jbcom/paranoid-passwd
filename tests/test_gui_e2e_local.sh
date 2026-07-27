#!/usr/bin/env bash
# tests/test_gui_e2e_local.sh — real-input local GUI e2e (macOS)
#
# Drives the actual paranoid-passwd-gui window through the operator
# workflow with real OS-level mouse clicks and keyboard input (not the
# PARANOID_GUI_AUTOMATION_* side-channel that `make test-gui-e2e` /
# `tests/test_gui_e2e.sh` use). Only `make e2e-local` runs this; it is
# gated out of `make e2e-ci` / `make ci` because it requires a real,
# unlocked display session and Accessibility permission for synthetic
# input, neither of which exist on a CI runner.
#
# Requires macOS with a real (Aqua) window session — not SSH, not a
# headless CI runner — and the terminal driving this script must hold
# Accessibility permission in System Settings > Privacy & Security >
# Accessibility (and, on modern macOS, Input Monitoring) so its synthetic
# CGEvents are delivered to other applications. See the "Real-input local
# GUI e2e" section of docs/reference/testing.md for the exact grant steps
# and why this can't be faked or skipped silently.

set -euo pipefail

CLI_BINARY="${1:?path to paranoid-passwd required}"
GUI_BINARY="${2:?path to paranoid-passwd-gui required}"
OUTPUT_DIR="${3:?output directory for screenshots required}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [[ "${HOST_OS}" != "darwin" ]]; then
  echo "test_gui_e2e_local.sh only implements the macOS real-input driver; host is ${HOST_OS}" >&2
  exit 64
fi

# --- Display-feasibility gate -----------------------------------------
#
# `launchctl managername` reports "Aqua" only inside a real logged-in
# WindowServer session; a headless SSH/CI session reports something else
# (e.g. "Background" or errors outright). Fail fast with a clear,
# actionable message instead of hanging on a window that will never
# appear, or worse, silently no-op-ing.
session_name="$(launchctl managername 2>/dev/null || true)"
if [[ "${session_name}" != "Aqua" ]]; then
  cat >&2 <<EOF
test_gui_e2e_local.sh requires a real macOS GUI (Aqua) session; this
session reports managername="${session_name:-<none>}". Run this from a
real logged-in desktop session (Screen Sharing / physical console), not
over plain SSH or a CI runner. This is a display-feasibility failure, not
a test failure.
EOF
  exit 64
fi

# `System Events`'s "UI elements enabled" reflects whether this process
# (and the terminal driving it) has Accessibility permission. The Swift
# real-input helper below posts CGEvents at the HID event tap, which
# requires the same Accessibility grant (and, on current macOS, Input
# Monitoring) for the calling process; without it every synthetic
# click/keystroke is silently dropped by the OS rather than erroring, so
# this check is the only way to fail loud instead of hanging on a GUI
# that never receives any input.
accessibility_enabled="$(osascript -e 'tell application "System Events" to return UI elements enabled' 2>/dev/null || echo "false")"
if [[ "${accessibility_enabled}" != "true" ]]; then
  cat >&2 <<EOF
test_gui_e2e_local.sh requires Accessibility permission for the process
running this script (your terminal app, e.g. Terminal.app / iTerm2).
Grant it in: System Settings > Privacy & Security > Accessibility, and
also add the terminal under System Settings > Privacy & Security > Input
Monitoring if clicks/keystrokes still do not reach the GUI window after
granting Accessibility. This is a permissions blocker, not a test
failure -- do not attempt to bypass it.
EOF
  exit 64
fi

for required in swiftc osascript screencapture; do
  if ! command -v "${required}" >/dev/null 2>&1; then
    echo "${required} is required for the macOS real-input GUI e2e driver" >&2
    exit 64
  fi
done

if [[ ! -x "${CLI_BINARY}" ]]; then
  echo "FAIL: CLI binary not executable: ${CLI_BINARY}" >&2
  exit 1
fi
if [[ ! -x "${GUI_BINARY}" ]]; then
  echo "FAIL: GUI binary not executable: ${GUI_BINARY}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# TMPDIR on macOS is typically already an absolute path with a trailing
# slash (e.g. /var/folders/.../T/); trim it so the generated paths stay
# single-slash and readable in screenshots/logs instead of a cosmetically
# doubled "//".
TMP_ROOT="${TMPDIR:-/tmp}"
TMP_ROOT="${TMP_ROOT%/}"

INPUT_DRIVER_SRC="${REPO_ROOT}/scripts/gui_real_input_macos.swift"
INPUT_DRIVER_BIN="$(mktemp -d "${TMP_ROOT}/paranoid-gui-e2e-local.driver.XXXXXX")/gui_real_input_macos"
swiftc "${INPUT_DRIVER_SRC}" -o "${INPUT_DRIVER_BIN}"

TMPDIR_ROOT="$(mktemp -d "${TMP_ROOT}/paranoid-gui-e2e-local.XXXXXX")"
VAULT_PATH="${TMPDIR_ROOT}/vault.sqlite"
BACKUP_PATH="${TMPDIR_ROOT}/vault.backup.json"
GUI_LOG="${TMPDIR_ROOT}/gui.log"
MASTER_PASSWORD="correct horse battery staple"
TIMEOUT_SCALE="${PARANOID_E2E_TIMEOUT_SCALE:-1}"

GUI_PID=""

cleanup() {
  if [[ -n "${GUI_PID}" ]] && kill -0 "${GUI_PID}" >/dev/null 2>&1; then
    kill "${GUI_PID}" >/dev/null 2>&1 || true
    wait "${GUI_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "$(dirname "${INPUT_DRIVER_BIN}")"
}
trap cleanup EXIT

FAILS=0
PASSES=0

check() {
  local description="$1"
  shift
  if "$@"; then
    PASSES=$((PASSES + 1))
    printf 'PASS: %s\n' "${description}"
  else
    FAILS=$((FAILS + 1))
    printf 'FAIL: %s\n' "${description}" >&2
  fi
}

# --- Real-input primitives ----------------------------------------------
#
# Window origin/size are queried fresh (not hardcoded) because the OS may
# place the window at a different position on a different display/desktop
# layout; every element coordinate below is expressed relative to that
# origin and computed at click time, so the driver stays correct even if
# the window is not at the position measured during development.
window_origin_and_size() {
  osascript -e '
    tell application "System Events"
      tell process "paranoid-passwd-gui"
        set winPos to position of window 1
        set winSize to size of window 1
        return (item 1 of winPos as string) & "," & (item 2 of winPos as string) & "," & (item 1 of winSize as string) & "," & (item 2 of winSize as string)
      end tell
    end tell
  '
}

WIN_X=0
WIN_Y=0
WIN_W=0
WIN_H=0

resolve_window_geometry() {
  local geometry=""
  for _ in $(seq 1 "$((50 * TIMEOUT_SCALE))"); do
    geometry="$(window_origin_and_size 2>/dev/null || true)"
    if [[ -n "${geometry}" ]]; then
      break
    fi
    sleep 0.1
  done
  if [[ -z "${geometry}" ]]; then
    echo "paranoid-passwd-gui window never appeared" >&2
    return 1
  fi
  IFS=',' read -r WIN_X WIN_Y WIN_W WIN_H <<<"${geometry}"
}

# Every element coordinate below is a window-relative point measured once
# against a real running instance of this exact compiled `paranoid.slint`
# tree (see docs/reference/testing.md's "Real-input local GUI e2e"
# section for the measurement method). The layout is fully static -- every
# panel, field, and button in paranoid.slint carries a literal pixel
# width/height with no data-dependent reflow -- so these offsets are
# stable across runs on a given compiled binary. `preferred-width`/
# `preferred-height` are read at click time to compute a rescale factor,
# so the driver keeps working if a future compiler/toolchain change
# shifts the window's actual granted size.
REF_W=1234
REF_H=1040

# This machine runs other concurrent interactive/automated sessions (other
# terminal windows, browser automation, etc.) that can raise their own
# window and steal keyboard/mouse focus between two stages of this script.
# `System Events`'s frontmost-process check is cheap and catches that race:
# every click/keystroke below re-asserts paranoid-passwd-gui as frontmost
# immediately first, then verifies the assertion actually stuck. If some
# other application refuses to yield focus (e.g. it is itself capturing
# input), this fails loudly with a clear diagnosis instead of silently
# clicking whatever window happened to be on top -- which is exactly the
# failure mode that produced garbage screenshots of an unrelated Chrome tab
# during hardening of this script.
ensure_foreground() {
  local frontmost=""
  for _ in $(seq 1 20); do
    osascript -e 'tell application "System Events" to tell process "paranoid-passwd-gui" to set frontmost to true' >/dev/null 2>&1 || true
    frontmost="$(osascript -e 'tell application "System Events" to get name of first process whose frontmost is true' 2>/dev/null || true)"
    if [[ "${frontmost}" == "paranoid-passwd-gui" ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "paranoid-passwd-gui did not stay frontmost before a real-input action (another window/process on this machine has focus: \"${frontmost}\"); this is an environment focus-stealing race, not a paranoid-passwd defect" >&2
  return 1
}

click_ref() {
  local ref_x="$1" ref_y="$2"
  local scale_x scale_y abs_x abs_y
  ensure_foreground
  scale_x="$(echo "scale=6; ${WIN_W}/${REF_W}" | bc)"
  scale_y="$(echo "scale=6; ${WIN_H}/${REF_H}" | bc)"
  abs_x="$(echo "${WIN_X} + (${ref_x} * ${scale_x})" | bc)"
  abs_y="$(echo "${WIN_Y} + (${ref_y} * ${scale_y})" | bc)"
  "${INPUT_DRIVER_BIN}" click "${abs_x}" "${abs_y}" >/dev/null
}

type_text() {
  ensure_foreground
  "${INPUT_DRIVER_BIN}" type "$1" >/dev/null
}

# Moves to the end of the field's text (Right arrow x100, comfortably
# longer than any field content in this workflow) then clears it
# (Backspace x150) regardless of what was there before -- Cmd+A/Cmd+Right
# select-all/end-of-line shortcuts were tried first and are not reliably
# honored by this Slint LineEdit build, so plain repeated navigation keys
# are used instead since they were verified to work deterministically.
clear_field() {
  ensure_foreground
  "${INPUT_DRIVER_BIN}" keyrepeat 124 100 >/dev/null
  "${INPUT_DRIVER_BIN}" keyrepeat 51 150 >/dev/null
}

set_field() {
  local ref_x="$1" ref_y="$2" text="$3"
  click_ref "${ref_x}" "${ref_y}"
  sleep 0.2
  clear_field
  sleep 0.05
  type_text "${text}"
  sleep 0.1
}

screenshot_stage() {
  local name="$1"
  local path="${OUTPUT_DIR}/${name}.png"
  # Re-raise paranoid-passwd-gui first: `screencapture -R` captures whatever
  # pixels are actually on screen at that region regardless of AX frontmost
  # state, so a screenshot taken while another window is on top over that
  # region silently captures the wrong app instead of erroring.
  ensure_foreground
  sleep 0.2
  screencapture -x -R"${WIN_X},${WIN_Y},${WIN_W},${WIN_H}" "${path}"
  printf 'captured screenshot: %s\n' "${path}"
}

wait_for_file() {
  local path="$1"
  local iterations=$((100 * TIMEOUT_SCALE))
  for _ in $(seq 1 "${iterations}"); do
    if [[ -f "${path}" ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_vault_unlockable() {
  local vault="$1" password="$2"
  local iterations=$((600 * TIMEOUT_SCALE))
  for _ in $(seq 1 "${iterations}"); do
    if PARANOID_MASTER_PASSWORD="${password}" "${CLI_BINARY}" vault --cli --path "${vault}" list >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_vault_item_count() {
  local vault="$1" password="$2" expected="$3"
  local iterations=$((300 * TIMEOUT_SCALE))
  for _ in $(seq 1 "${iterations}"); do
    local actual
    actual="$(PARANOID_MASTER_PASSWORD="${password}" "${CLI_BINARY}" vault --cli --path "${vault}" list 2>/dev/null | grep -c . || true)"
    if [[ "${actual}" -ge "${expected}" ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

launch_gui() {
  "${GUI_BINARY}" >"${GUI_LOG}" 2>&1 &
  GUI_PID=$!
  local iterations=$((100 * TIMEOUT_SCALE))
  for _ in $(seq 1 "${iterations}"); do
    if osascript -e 'tell application "System Events" to (name of every process) contains "paranoid-passwd-gui"' 2>/dev/null | grep -q true; then
      # This machine runs other real, regularly-frontmost application
      # windows (editor, other terminal panes, etc.) whose default window
      # placement was observed to land on top of the same screen region
      # macOS grants a freshly-launched paranoid-passwd-gui window by
      # default -- confirmed by `screencapture -R` at that region
      # intermittently capturing unrelated window content even while
      # System Events reported paranoid-passwd-gui as AX-frontmost.
      # Explicitly pinning the window to a fixed top-left corner makes its
      # screen position deterministic and away from where other windows on
      # this desktop tend to sit, instead of trusting whatever position the
      # OS handed it.
      osascript -e 'tell application "System Events" to tell process "paranoid-passwd-gui" to set position of window 1 to {0, 50}' >/dev/null 2>&1 || true
      resolve_window_geometry
      osascript -e 'tell application "System Events" to tell process "paranoid-passwd-gui" to set frontmost to true' >/dev/null 2>&1 || true
      sleep 0.5
      return 0
    fi
    if ! kill -0 "${GUI_PID}" >/dev/null 2>&1; then
      cat "${GUI_LOG}" >&2 || true
      echo "paranoid-passwd-gui exited before its window appeared" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "paranoid-passwd-gui window never appeared" >&2
  return 1
}

quit_gui() {
  # Proxy for "lock": the GUI has no manual lock button (session
  # unlock/lock is idle-timeout-driven, see
  # paranoid_vault::native_access::NativeSessionHardening, which is not
  # practical to wait out in an e2e run). Fully quitting and relaunching
  # against the same vault path exercises the same on-disk persistence
  # and re-derivation path a real lock/unlock cycle would, and is exactly
  # the technique tests/test_tui_e2e.py already uses for its own
  # fresh-process restart/unlock coverage.
  osascript -e 'tell application "System Events" to tell process "paranoid-passwd-gui" to click button 1 of window 1' >/dev/null 2>&1 || true
  local iterations=$((50 * TIMEOUT_SCALE))
  for _ in $(seq 1 "${iterations}"); do
    if ! kill -0 "${GUI_PID}" >/dev/null 2>&1; then
      GUI_PID=""
      return 0
    fi
    sleep 0.1
  done
  kill "${GUI_PID}" >/dev/null 2>&1 || true
  wait "${GUI_PID}" >/dev/null 2>&1 || true
  GUI_PID=""
}

# Fixed window-relative points for every field/button this workflow
# drives, measured against a real running instance (see comment on
# REF_W/REF_H above).
LENGTH_FIELD=(125 416)
RUN_AUDIT_BUTTON=(120 546)
VAULT_PATH_FIELD=(616 380)
VAULT_SECRET_FIELD=(616 485)
INIT_BUTTON=(524 555)
UNLOCK_BUTTON=(697 555)
LOGIN_TITLE_FIELD=(933 263)
LOGIN_USER_FIELD=(1107 263)
LOGIN_PASSWORD_FIELD=(1020 313)
LOGIN_FOLDER_FIELD=(933 363)
LOGIN_TAGS_FIELD=(1107 363)
BACKUP_PATH_FIELD=(1020 471)
ADD_LOGIN_BUTTON=(937 521)
EXPORT_BACKUP_BUTTON=(1111 579)

echo "=== Stage 1: launch GUI ==="
launch_gui
screenshot_stage "01-launch"

echo "=== Stage 2: generate passwords (Run audit) ==="
set_field "${LENGTH_FIELD[@]}" "40"
click_ref "${RUN_AUDIT_BUTTON[@]}"
sleep 1
screenshot_stage "02-generate"

echo "=== Stage 3: init vault (real 256MiB Argon2id KDF) ==="
set_field "${VAULT_PATH_FIELD[@]}" "${VAULT_PATH}"
set_field "${VAULT_SECRET_FIELD[@]}" "${MASTER_PASSWORD}"
click_ref "${INIT_BUTTON[@]}"
check "vault becomes unlockable after Init" wait_for_vault_unlockable "${VAULT_PATH}" "${MASTER_PASSWORD}"
screenshot_stage "03-init-vault"

echo "=== Stage 4: add login ==="
set_field "${LOGIN_TITLE_FIELD[@]}" "E2E Local Login"
set_field "${LOGIN_USER_FIELD[@]}" "e2e-local-user"
set_field "${LOGIN_PASSWORD_FIELD[@]}" "existing-password-value"
set_field "${LOGIN_FOLDER_FIELD[@]}" "E2ELocal"
set_field "${LOGIN_TAGS_FIELD[@]}" "e2e,local"
click_ref "${ADD_LOGIN_BUTTON[@]}"
check "vault has 1 item after Add login" wait_for_vault_item_count "${VAULT_PATH}" "${MASTER_PASSWORD}" 1
screenshot_stage "04-add-login"

echo "=== Stage 5: lock (quit the GUI process) ==="
quit_gui
check "GUI process exited (lock proxy)" test -z "${GUI_PID}"

echo "=== Stage 6: unlock (relaunch, real 256MiB Argon2id KDF again) ==="
launch_gui
set_field "${VAULT_PATH_FIELD[@]}" "${VAULT_PATH}"
set_field "${VAULT_SECRET_FIELD[@]}" "${MASTER_PASSWORD}"
click_ref "${UNLOCK_BUTTON[@]}"
check "vault still unlockable and item survived lock/unlock" wait_for_vault_item_count "${VAULT_PATH}" "${MASTER_PASSWORD}" 1
screenshot_stage "06-unlock"

echo "=== Stage 7: export backup ==="
set_field "${BACKUP_PATH_FIELD[@]}" "${BACKUP_PATH}"
click_ref "${EXPORT_BACKUP_BUTTON[@]}"
check "backup file was written" wait_for_file "${BACKUP_PATH}"
screenshot_stage "07-export-backup"

if [[ -f "${BACKUP_PATH}" ]] && grep -q "${MASTER_PASSWORD}" "${BACKUP_PATH}"; then
  FAILS=$((FAILS + 1))
  printf 'FAIL: %s\n' "backup file did not leak the vault recovery secret" >&2
else
  PASSES=$((PASSES + 1))
  printf 'PASS: %s\n' "backup file did not leak the vault recovery secret"
fi

echo "=== Stage 8: verify the added item via the vault CLI ==="
LIST_OUTPUT="$(PARANOID_MASTER_PASSWORD="${MASTER_PASSWORD}" "${CLI_BINARY}" vault --cli --path "${VAULT_PATH}" list 2>&1 || true)"
if echo "${LIST_OUTPUT}" | grep -q "E2E Local Login"; then
  PASSES=$((PASSES + 1))
  printf 'PASS: %s\n' "vault CLI list shows the item added through the real GUI"
else
  FAILS=$((FAILS + 1))
  printf 'FAIL: %s\n' "vault CLI list does not show the item added through the real GUI" >&2
  echo "${LIST_OUTPUT}" >&2
fi

quit_gui
if [[ "${PARANOID_E2E_LOCAL_KEEP_TMPDIR:-0}" == "1" ]]; then
  printf 'kept vault/backup working directory for inspection: %s\n' "${TMPDIR_ROOT}"
else
  rm -rf "${TMPDIR_ROOT}"
fi

echo ""
echo "test_gui_e2e_local.sh: ${PASSES} passed, ${FAILS} failed"
if [[ "${FAILS}" -ne 0 ]]; then
  exit 1
fi
