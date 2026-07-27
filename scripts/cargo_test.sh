#!/usr/bin/env bash
#
# Runs the workspace's cargo test suites.
#
# Default mode (P6.7): build every test binary once with `cargo test --no-run`
# (one lockfile-honoring compile), then run the resulting per-crate/per-suite
# test binaries CONCURRENTLY, bounded to the host's CPU count, buffering each
# suite's output and printing it atomically on completion so interleaved runs
# never garble each other's output. Aggregate exit code is nonzero if any
# suite fails.
#
# Escape hatch: PARANOID_TEST_SERIAL=1 restores the previous behavior of a
# single `cargo test` invocation running every suite serially in-process.
# This is also the fallback when the requested `cargo test` arguments are not
# safe to split (e.g. a `--` test-filter argument, which must see every suite
# in one process to apply consistently).

set -euo pipefail

DEVICE_STORE_DIR_CREATED=0
if [ -z "${PARANOID_TEST_DEVICE_STORE_DIR:-}" ]; then
  PARANOID_TEST_DEVICE_STORE_DIR="$(mktemp -d)"
  DEVICE_STORE_DIR_CREATED=1
  export PARANOID_TEST_DEVICE_STORE_DIR
fi

# NOTE on the S1 trust-gate marker (ia.md §3 short-circuit,
# `vault_tui::screen_state::trust_marker_path`): deliberately NOT wired up
# here. That function has no `$HOME` fallback in any build (see its doc
# comment) — it only reads `PARANOID_TEST_TRUST_MARKER_DIR` /
# `PARANOID_PASSWD_STATE_DIR`, both unset by default, so it is inert unless
# an operator explicitly opts in. Setting either here would give every
# concurrently-running test in the same binary process a single SHARED
# marker file (unlike the per-job device-store subdirectory below), which
# raced two trust-gate tests against each other the one time this was tried.

cleanup_device_store() {
  if [ "$DEVICE_STORE_DIR_CREATED" -eq 1 ]; then
    rm -rf "$PARANOID_TEST_DEVICE_STORE_DIR"
  fi
}
trap cleanup_device_store EXIT

# ---------------------------------------------------------------------------
# xvfb/dbus wrapper selection (unchanged behavior, now shared by both modes)
# ---------------------------------------------------------------------------
run_wrapped() {
  if [ "${PARANOID_USE_XVFB:-auto}" = "0" ] || [ "${PARANOID_USE_XVFB:-auto}" = "false" ]; then
    "$@"
    return $?
  fi

  if command -v xvfb-run >/dev/null 2>&1; then
    if command -v dbus-run-session >/dev/null 2>&1; then
      xvfb-run -a dbus-run-session -- "$@"
      return $?
    fi
    xvfb-run -a "$@"
    return $?
  fi

  "$@"
  return $?
}

# ---------------------------------------------------------------------------
# Decide whether the parallel path is applicable to this invocation.
# ---------------------------------------------------------------------------
serial_requested=0
if [ "${PARANOID_TEST_SERIAL:-0}" = "1" ] || [ "${PARANOID_TEST_SERIAL:-0}" = "true" ]; then
  serial_requested=1
fi

has_test_filter_args=0
for arg in "$@"; do
  if [ "$arg" = "--" ]; then
    has_test_filter_args=1
    break
  fi
done

if [ "$serial_requested" -eq 1 ] || [ "$has_test_filter_args" -eq 1 ]; then
  run_wrapped cargo test "$@"
  exit $?
fi

# ---------------------------------------------------------------------------
# Parallel path: one `--no-run` build, then concurrent per-suite execution.
# ---------------------------------------------------------------------------

build_message_file="$(mktemp)"
cleanup_build_message_file() {
  rm -f "$build_message_file"
}
trap 'cleanup_build_message_file; cleanup_device_store' EXIT

if ! run_wrapped cargo test "$@" --no-run --message-format=json >"$build_message_file"; then
  echo "cargo_test.sh: build failed (cargo test --no-run)" >&2
  exit 1
fi

suite_list_file="$(mktemp)"
trap 'rm -f "$suite_list_file"; cleanup_build_message_file; cleanup_device_store' EXIT

python3 - "$build_message_file" >"$suite_list_file" <<'PYEOF'
import json
import sys

path = sys.argv[1]
seen = set()
suites = []
with open(path, encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        profile = message.get("profile") or {}
        if not profile.get("test"):
            continue
        executable = message.get("executable")
        if not executable:
            continue
        target = message.get("target") or {}
        kinds = target.get("kind") or []
        name = target.get("name", "unknown")
        if "lib" in kinds:
            suite_name = f"{name} (unit)"
        else:
            suite_name = name
        if executable in seen:
            continue
        seen.add(executable)
        suites.append((suite_name, executable))

suites.sort(key=lambda item: item[0])
for suite_name, executable in suites:
    print(f"{suite_name}\t{executable}")
PYEOF

if [ ! -s "$suite_list_file" ]; then
  echo "cargo_test.sh: no test binaries found in --no-run build output" >&2
  exit 1
fi

# cargo test also always runs doc-tests, which `--no-run` cannot pre-build
# (rustdoc compiles and runs them together). Fold them into the batch as one
# more suite so `make test`/`make ci` keep parity with `cargo test`'s default
# scope; --no-doc bypasses this the same way `cargo test --no-doc` would.
run_doctests=1
for arg in "$@"; do
  if [ "$arg" = "--no-doc" ] || [ "$arg" = "--doc" ]; then
    # --doc alone is a doctest-only invocation; the normal per-binary suites
    # above will be empty in that case and doctests remain the only work.
    if [ "$arg" = "--no-doc" ]; then
      run_doctests=0
    fi
  fi
done

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"; rm -f "$suite_list_file"; cleanup_build_message_file; cleanup_device_store' EXIT

job_count=0
job_names=()
job_status_files=()
job_log_files=()

nproc_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
max_parallel="${PARANOID_TEST_MAX_PARALLEL:-$nproc_count}"
case "$max_parallel" in
  ''|*[!0-9]*) max_parallel="$nproc_count" ;;
esac
if [ "$max_parallel" -lt 1 ]; then
  max_parallel=1
fi

running_pids=()

wait_for_slot() {
  while [ "${#running_pids[@]}" -ge "$max_parallel" ]; do
    wait -n "${running_pids[@]}" 2>/dev/null || true
    next_pids=()
    for pid in "${running_pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        next_pids+=("$pid")
      fi
    done
    running_pids=("${next_pids[@]}")
  done
}

launch_suite() {
  local suite_name="$1"
  shift
  local status_file="$work_dir/status-${job_count}"
  local log_file="$work_dir/log-${job_count}"
  job_names+=("$suite_name")
  job_status_files+=("$status_file")
  job_log_files+=("$log_file")
  job_count=$((job_count + 1))

  (
    set +e
    # Give each concurrently-running suite its own device-store subdirectory.
    # The debug-only device store keys files by hex(service+account), so two
    # suites racing on the same account inside a shared root can clobber one
    # another once suites run concurrently instead of one-cargo-test-at-a-time.
    if [ "$DEVICE_STORE_DIR_CREATED" -eq 1 ]; then
      suite_store_dir="${PARANOID_TEST_DEVICE_STORE_DIR}/job-${job_count}"
      mkdir -p "$suite_store_dir"
      PARANOID_TEST_DEVICE_STORE_DIR="$suite_store_dir" run_wrapped "$@" >"$log_file" 2>&1
    else
      run_wrapped "$@" >"$log_file" 2>&1
    fi
    echo "$?" >"$status_file"
  ) &
  running_pids+=("$!")
  wait_for_slot
}

while IFS=$'\t' read -r suite_name executable; do
  # Each suite gets its own OS process running concurrently with the others
  # (bounded to $max_parallel processes at a time). Suites keep libtest's own
  # default in-process thread count (nproc) rather than stacking a second
  # layer of parallelism on top -- letting each suite fan out internally as
  # well would oversubscribe the host by suite_count * nproc threads.
  launch_suite "$suite_name" "$executable"
done <"$suite_list_file"

if [ "$run_doctests" -eq 1 ]; then
  launch_suite "doctests" cargo test "$@" --doc
fi

for pid in "${running_pids[@]}"; do
  wait "$pid" 2>/dev/null || true
done

aggregate_status=0
for i in $(seq 0 $((job_count - 1))); do
  suite_name="${job_names[$i]}"
  status_file="${job_status_files[$i]}"
  log_file="${job_log_files[$i]}"
  status="$(cat "$status_file" 2>/dev/null || echo 1)"

  echo "=== suite: ${suite_name} ==="
  cat "$log_file"
  echo

  if [ "$status" != "0" ]; then
    echo "=== suite FAILED: ${suite_name} (exit ${status}) ===" >&2
    aggregate_status=1
  fi
done

exit "$aggregate_status"
