#!/usr/bin/env bash

set -euo pipefail

CLI_BINARY="${1:?path to paranoid-passwd required}"
GUI_BINARY="${2:?path to paranoid-passwd-gui required}"
SCREENSHOT_PATH="${3:?output screenshot path required}"

for required in xvfb-run import identify; do
  if ! command -v "${required}" >/dev/null 2>&1; then
    echo "${required} is required for GUI e2e" >&2
    exit 64
  fi
done

mkdir -p "$(dirname "${SCREENSHOT_PATH}")"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/paranoid-gui-e2e.XXXXXX")"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

vault_path="${tmpdir}/vault.sqlite"
backup_path="${tmpdir}/vault.backup.json"
outcome_path="${tmpdir}/gui.outcome"
log_path="${tmpdir}/gui.log"
audit_path="${tmpdir}/gui-audit.jsonl"

export PARANOID_MASTER_PASSWORD="correct horse battery staple"
"${CLI_BINARY}" vault --cli --path "${vault_path}" init >/dev/null

# The inner script expands inside the Xvfb shell, not in this parent shell.
# shellcheck disable=SC2016
xvfb-run -a env WINIT_UNIX_BACKEND=x11 SLINT_BACKEND=software bash -lc '
  set -euo pipefail

  gui_binary="$1"
  screenshot_path="$2"
  backup_path="$3"
  outcome_path="$4"
  log_path="$5"
  vault_path="$6"
  audit_path="$7"

  cleanup_gui() {
    if [ -n "${gui_pid:-}" ]; then
      kill "${gui_pid}" >/dev/null 2>&1 || true
      wait "${gui_pid}" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_gui EXIT

  capture_gui_window() {
    timeout 5s import -window root "${screenshot_path}"
  }

  PARANOID_GUI_AUTOMATION_SCENARIO=operator-workflow \
  PARANOID_GUI_AUTOMATION_VAULT_PATH="${vault_path}" \
  PARANOID_GUI_AUTOMATION_BACKUP_PATH="${backup_path}" \
  PARANOID_GUI_AUTOMATION_OUTPUT_PATH="${outcome_path}" \
  "${gui_binary}" --audit-jsonl "${audit_path}" --require-audit-sink >"${log_path}" 2>&1 &
  gui_pid=$!

  for _ in $(seq 1 300); do
    if [ -f "${outcome_path}" ]; then
      break
    fi
    if ! kill -0 "${gui_pid}" >/dev/null 2>&1; then
      cat "${log_path}" >&2 || true
      echo "GUI exited before reporting the automation outcome" >&2
      exit 1
    fi
    sleep 0.1
  done

  if [ ! -f "${outcome_path}" ]; then
    cat "${log_path}" >&2 || true
    echo "GUI automation timed out without writing an outcome marker" >&2
    exit 1
  fi

  if ! grep -q "^status=pass$" "${outcome_path}"; then
    cat "${outcome_path}" >&2 || true
    cat "${log_path}" >&2 || true
    echo "GUI automation reported failure" >&2
    exit 1
  fi

  if [ ! -f "${backup_path}" ]; then
    cat "${outcome_path}" >&2 || true
    cat "${log_path}" >&2 || true
    echo "GUI automation did not write the expected backup package" >&2
    exit 1
  fi

  if [ ! -s "${audit_path}" ]; then
    cat "${outcome_path}" >&2 || true
    cat "${log_path}" >&2 || true
    echo "GUI automation did not write durable ops audit JSONL" >&2
    exit 1
  fi

  if ! AUDIT_JSONL="${audit_path}" python3 - <<PY
import json
import os
import sys

path = os.environ["AUDIT_JSONL"]
events = []
with open(path, encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, 1):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as error:
            print(f"invalid JSONL at line {line_number}: {error}", file=sys.stderr)
            sys.exit(1)

if not any(
    event.get("attributes", {}).get("session_surface") == "gui"
    and event.get("attributes", {}).get("vault_operation") == "export"
    for event in events
):
    print("missing GUI export provenance event", file=sys.stderr)
    sys.exit(1)
PY
  then
    cat "${audit_path}" >&2 || true
    echo "GUI automation audit JSONL did not preserve GUI ops provenance" >&2
    exit 1
  fi

  if grep -q "correct horse battery staple" "${audit_path}"; then
    cat "${audit_path}" >&2 || true
    echo "GUI automation audit JSONL leaked the vault recovery secret" >&2
    exit 1
  fi

  sleep 1
  screenshot_ready=0
  for _ in $(seq 1 120); do
    capture_gui_window "${screenshot_path}"
    read -r width height colors scaled_mean < <(
      identify -format "%w %h %k %[fx:int(mean*1000000)]\n" "${screenshot_path}"
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
    cat "${outcome_path}" >&2 || true
    cat "${log_path}" >&2 || true
    echo "GUI automation screenshot was blank or undersized" >&2
    exit 1
  fi
' _ "${GUI_BINARY}" "${SCREENSHOT_PATH}" "${backup_path}" "${outcome_path}" "${log_path}" "${vault_path}" "${audit_path}"

printf 'GUI e2e passed: %s\n' "${SCREENSHOT_PATH}"
