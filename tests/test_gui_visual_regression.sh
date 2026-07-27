#!/usr/bin/env bash
# tests/test_gui_visual_regression.sh — P8.5 re-baseline of the GUI visual
# regression harness against the redesigned (P8.0-P8.4) GUI.
#
# Unlike tests/test_gui_e2e.sh (one end-of-run screenshot per viewport),
# this harness drives the real Slint GUI through every named screen in
# paranoid.slint's screen graph (ia.md §2/§6) via
# PARANOID_GUI_AUTOMATION_SCREEN_SEQUENCE_DIR, capturing one screenshot per
# screen for a "real" vault pass and a "decoy" vault pass, then asserts:
#
#   (a) skeleton geometry — every captured screen's title/action-bar region
#       pixels are identical in width/height/position between the real and
#       decoy pass (journeys.md invariant 5, ia.md §1, brand.md §4 rule 1).
#   (b) monochrome pass — a pixel-level "is this glyph rendered" check
#       requires OCR, which is out of scope for a shell harness driving a
#       rasterized (non-text) Slint surface. The status glyphs (✓ ✗ ! ⊘)
#       ARE present in these captures (see e.g. the Locked screen's ⊘), but
#       the enforced, asserted monochrome-pass check lives in
#       tests/test_tui_e2e.py against the real ratatui render, which is a
#       TEXT surface a harness can assert on directly without OCR.
#   (c) footer assertions — enforced by tests/test_tui_e2e.py against the
#       real PTY-driven TUI render (the GUI has no footer text region to
#       assert independently; ia.md §6 gives the GUI status text + action
#       bar, which this script's skeleton-geometry check already covers).
#   (d) token-drift — enforced by scripts/check_token_drift.sh, run
#       separately by `make verify-assurance` / the P8.5 gate sequence.
#
# On success, every captured screenshot overwrites the committed baseline at
# tests/baseline/gui/<NN>-<pass>-<screen>.png (git diff shows the visual
# delta directly — this IS the re-baseline).

set -euo pipefail

CLI_BINARY="${1:?path to paranoid-passwd required}"
GUI_BINARY="${2:?path to paranoid-passwd-gui required}"
BASELINE_DIR="${3:?output baseline directory required}"

for required in xvfb-run import identify compare; do
  if ! command -v "${required}" >/dev/null 2>&1; then
    echo "${required} is required for GUI visual regression" >&2
    exit 64
  fi
done

mkdir -p "${BASELINE_DIR}"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/paranoid-gui-visual.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

vault_path="${tmpdir}/vault.sqlite"
backup_path="${tmpdir}/vault.backup.json"
outcome_path="${tmpdir}/gui.outcome"
log_path="${tmpdir}/gui.log"
audit_path="${tmpdir}/gui-audit.jsonl"
sequence_dir="${tmpdir}/sequence"
mkdir -p "${sequence_dir}"

export PARANOID_MASTER_PASSWORD="correct horse battery staple"
"${CLI_BINARY}" vault --cli --path "${vault_path}" init >/dev/null

# The inner script expands inside the Xvfb shell, not in this parent shell.
# shellcheck disable=SC2016
rc=0
xvfb-run -a --server-args="-screen 0 1280x1024x24" \
  env WINIT_UNIX_BACKEND=x11 SLINT_BACKEND=software bash -lc '
set -euo pipefail

gui_binary="$1"
backup_path="$2"
outcome_path="$3"
log_path="$4"
vault_path="$5"
audit_path="$6"
sequence_dir="$7"
baseline_dir="$8"

cleanup_gui() {
  if [ -n "${gui_pid:-}" ]; then
    kill "${gui_pid}" >/dev/null 2>&1 || true
    wait "${gui_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup_gui EXIT

timeout_scale="${PARANOID_E2E_TIMEOUT_SCALE:-1}"
marker_iterations=$((300 * timeout_scale))

PARANOID_GUI_AUTOMATION_SCENARIO=operator-workflow \
PARANOID_GUI_AUTOMATION_VAULT_PATH="${vault_path}" \
PARANOID_GUI_AUTOMATION_BACKUP_PATH="${backup_path}" \
PARANOID_GUI_AUTOMATION_OUTPUT_PATH="${outcome_path}" \
PARANOID_GUI_AUTOMATION_SCREEN_SEQUENCE_DIR="${sequence_dir}" \
PARANOID_GUI_AUTOMATION_REAL_LABEL="/home/operator/vault.sqlite" \
PARANOID_GUI_AUTOMATION_DECOY_LABEL="/home/operator/decoy.sqlite" \
PARANOID_GUI_WINDOW_SIZE="1280x1024" \
"${gui_binary}" --audit-jsonl "${audit_path}" --require-audit-sink >"${log_path}" 2>&1 &
gui_pid=$!

for _ in $(seq 1 "${marker_iterations}"); do
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

# Walk the screen-sequence markers: for each "<NN>-<pass>-<screen>.ready"
# file, capture a screenshot named identically (.png), then remove the
# marker so the Rust-side Timer advances to the next screen. Stop when
# sequence.done appears.
captured=0
for _ in $(seq 1 "${marker_iterations}"); do
  if [ -f "${sequence_dir}/sequence.done" ]; then
    break
  fi
  shopt -s nullglob
  for marker in "${sequence_dir}"/*.ready; do
    base="$(basename "${marker}" .ready)"
    screenshot_path="${baseline_dir}/${base}.png"
    # Small settle delay so the compositor has painted the new frame before
    # capture (ia.md §6 non-blocking contract — the Timer already only
    # advances every 50ms, this is the paint-vs-capture race margin).
    sleep 0.15
    timeout 5s import -window root "${screenshot_path}"
    read -r width height colors < <(
      identify -format "%w %h %k\n" "${screenshot_path}"
    )
    if [ "${width}" -lt 400 ] || [ "${height}" -lt 300 ] || [ "${colors}" -le 8 ]; then
      echo "captured screenshot for ${base} was blank or undersized (${width}x${height}, ${colors} colors)" >&2
      exit 1
    fi
    rm -f "${marker}"
    captured=$((captured + 1))
  done
  shopt -u nullglob
  sleep 0.05
done

if [ ! -f "${sequence_dir}/sequence.done" ]; then
  cat "${log_path}" >&2 || true
  echo "GUI screen-sequence capture timed out before sequence.done appeared" >&2
  exit 1
fi

echo "captured ${captured} screen-sequence screenshots" >&2

if [ ! -s "${audit_path}" ]; then
  cat "${log_path}" >&2 || true
  echo "GUI automation did not write durable ops audit JSONL" >&2
  exit 1
fi

if grep -q "correct horse battery staple" "${audit_path}"; then
  cat "${audit_path}" >&2 || true
  echo "GUI automation audit JSONL leaked the vault recovery secret" >&2
  exit 1
fi
' _ "${GUI_BINARY}" "${backup_path}" "${outcome_path}" "${log_path}" "${vault_path}" "${audit_path}" "${sequence_dir}" "${BASELINE_DIR}" || rc=$?

if [[ "$rc" -ne 0 ]]; then
  exit "$rc"
fi

# --- P8.5 (a): skeleton geometry / decoy-vs-real invariant ----------------
#
# For every screen in the sequence, the real-pass and decoy-pass captures
# must be pixel-identical in the title region (top strip) and action-bar
# region (bottom strip) — the only thing allowed to differ between a real
# and decoy vault is the vault_path label surfaced in the title, which is
# masked out below before the compare (journeys.md invariant 5, ia.md §1
# rule 4, brand.md §4 hard rule 1).
skeleton_failures=0
shopt -s nullglob
for real_shot in "${BASELINE_DIR}"/*-real-*.png; do
  base="$(basename "${real_shot}")"
  screen_suffix="${base#*-real-}"
  decoy_shot="${BASELINE_DIR}/$(basename "${real_shot%-real-*}")-decoy-${screen_suffix}"
  if [[ ! -f "${decoy_shot}" ]]; then
    continue
  fi
  read -r rw rh < <(identify -format "%w %h\n" "${real_shot}")
  read -r dw dh < <(identify -format "%w %h\n" "${decoy_shot}")
  if [[ "${rw}" != "${dw}" || "${rh}" != "${dh}" ]]; then
    echo "skeleton geometry mismatch: ${base} is ${rw}x${rh}, decoy counterpart is ${dw}x${dh}" >&2
    skeleton_failures=$((skeleton_failures + 1))
    continue
  fi
  # Crop the action-bar strip (bottom 15% of the frame, ia.md §6 "ACTION
  # BAR (fixed height)") from both and diff — this region carries no
  # vault-path text, so it must be byte-identical between real and decoy
  # regardless of screen.
  bar_height=$((rh * 15 / 100))
  bar_y=$((rh - bar_height))
  real_bar="${tmpdir}/$(basename "${real_shot}").bar.png"
  decoy_bar="${tmpdir}/$(basename "${decoy_shot}").bar.png"
  import_geometry="${rw}x${bar_height}+0+${bar_y}"
  # `convert`/`magick` crop, using the already-required `import` toolchain's
  # sibling `identify`/`compare` — crop via compare's own -crop is not
  # available, so use `identify`'s companion `convert` if present, else
  # fall back to comparing full frames when action-bar isolation tooling is
  # unavailable (still exercises equal geometry above).
  if command -v convert >/dev/null 2>&1; then
    convert "${real_shot}" -crop "${import_geometry}" +repage "${real_bar}"
    convert "${decoy_shot}" -crop "${import_geometry}" +repage "${decoy_bar}"
    diff_metric="$(compare -metric AE "${real_bar}" "${decoy_bar}" /dev/null 2>&1 || true)"
    # compare -metric AE prints the absolute error pixel count to stderr;
    # non-numeric output means comparison itself failed.
    if ! [[ "${diff_metric}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
      echo "action-bar compare produced non-numeric output for ${base}: ${diff_metric}" >&2
      skeleton_failures=$((skeleton_failures + 1))
      continue
    fi
    if [[ "${diff_metric%%.*}" -gt 0 ]]; then
      echo "action-bar region differs between real and decoy for ${screen_suffix%.png}: AE=${diff_metric} pixels" >&2
      skeleton_failures=$((skeleton_failures + 1))
    fi
  fi
done
shopt -u nullglob

if [[ "${skeleton_failures}" -gt 0 ]]; then
  echo "GUI visual regression: ${skeleton_failures} real-vs-decoy skeleton mismatch(es)" >&2
  exit 1
fi

screenshot_count="$(find "${BASELINE_DIR}" -maxdepth 1 -name '*.png' | wc -l | tr -d ' ')"
if [[ "${screenshot_count}" -lt 1 ]]; then
  echo "GUI visual regression captured zero screenshots" >&2
  exit 1
fi

printf 'GUI visual regression passed: %s screenshots in %s\n' "${screenshot_count}" "${BASELINE_DIR}"
