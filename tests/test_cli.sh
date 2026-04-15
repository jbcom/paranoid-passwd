#!/usr/bin/env bash
# tests/test_cli.sh — CLI behavior tests
#
# Invoked by CTest with the CLI binary path as $1.
# Exit 0 on pass, nonzero on fail. Prints a summary line for each case.

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <path-to-paranoid-passwd>" >&2
    exit 64
fi

BIN="$1"
FAILS=0
PASSES=0

if [[ ! -x "$BIN" ]]; then
    echo "FAIL: binary not executable: $BIN" >&2
    exit 1
fi

check() {
    local name="$1"
    shift
    if "$@"; then
        printf '  PASS  %s\n' "$name"
        PASSES=$((PASSES + 1))
    else
        printf '  FAIL  %s\n' "$name" >&2
        FAILS=$((FAILS + 1))
    fi
}

# --- Test 1: --help exits 0
t_help() {
    "$BIN" --help >/dev/null 2>&1
}
check "--help exits 0" t_help

# --- Test 2: --version prints version line
t_version() {
    local out
    out="$("$BIN" --version 2>&1)"
    [[ "$out" == paranoid-passwd\ * ]]
}
check "--version prints version line" t_version

# --- Test 3: scriptable invocation produces a 32-char password on stdout
t_bare_len() {
    local pw
    pw="$("$BIN" --cli --no-audit --quiet)"
    [[ ${#pw} -eq 32 ]]
}
check "scriptable invocation -> 32 chars" t_bare_len

# --- Test 4: --length 16 --count 3 produces 3 lines of 16 chars
t_multi() {
    local out
    out="$("$BIN" --cli --length 16 --count 3 --no-audit --quiet)"
    local n
    n=$(printf '%s\n' "$out" | wc -l | tr -d ' ')
    [[ "$n" -eq 3 ]] || return 1
    while IFS= read -r line; do
        [[ ${#line} -eq 16 ]] || return 1
    done <<< "$out"
}
check "--length 16 --count 3 -> 3x16" t_multi

# --- Test 5: --charset hex --length 64 produces only [0-9a-f]
t_hex() {
    local pw
    pw="$("$BIN" --cli --charset hex --length 64 --no-audit --quiet)"
    [[ ${#pw} -eq 64 ]] || return 1
    [[ "$pw" =~ ^[0-9a-f]+$ ]]
}
check "--charset hex -> [0-9a-f]" t_hex

# --- Test 6: --length 4 --require-lower 5 exits 1 (impossible)
t_impossible() {
    local rc=0
    "$BIN" --cli --length 4 --require-lower 5 --no-audit --quiet >/dev/null 2>&1 || rc=$?
    [[ "$rc" -eq 1 ]]
}
check "impossible requirements -> exit 1" t_impossible

# --- Test 7: --length 0 exits 1
t_zero_len() {
    local rc=0
    "$BIN" --cli --length 0 --quiet >/dev/null 2>&1 || rc=$?
    [[ "$rc" -eq 1 ]]
}
check "--length 0 -> exit 1" t_zero_len

# --- Test 8: --count 11 exits 1 (over max)
t_over_count() {
    local rc=0
    "$BIN" --cli --count 11 --quiet >/dev/null 2>&1 || rc=$?
    [[ "$rc" -eq 1 ]]
}
check "--count 11 -> exit 1" t_over_count

# --- Test 9: --no-audit suppresses audit stage lines
t_no_audit() {
    local err
    err="$("$BIN" --cli --no-audit --quiet 2>&1 >/dev/null)"
    [[ -z "$err" ]]
}
check "--no-audit --quiet -> empty stderr" t_no_audit

# --- Test 10: --quiet still produces stdout
t_quiet_stdout() {
    local pw
    pw="$("$BIN" --cli --quiet 2>/dev/null)"
    [[ ${#pw} -ge 1 ]]
}
check "--quiet keeps stdout" t_quiet_stdout

# --- Test 11: audit enabled by default produces stage lines
t_default_audit() {
    local err
    err="$("$BIN" --cli --length 16 2>&1 >/dev/null)"
    [[ "$err" == *"chi-squared"* ]]
}
check "default run audits (mentions chi-squared)" t_default_audit

# --- Test 12: --require-lower 2 produces password with 2+ lowercase
t_require_lower() {
    local pw
    pw="$("$BIN" --cli --length 16 --require-lower 5 --no-audit --quiet)"
    local n
    n=$(printf '%s' "$pw" | tr -cd 'a-z' | wc -c | tr -d ' ')
    [[ "$n" -ge 5 ]]
}
check "--require-lower 5 -> >=5 lowercase" t_require_lower

# --- Test 13: audit output distinguishes primary/additional passwords and generator roll-up
t_audit_rollup() {
    local err
    err="$("$BIN" --cli --length 18 --count 2 --framework nist 2>&1 >/dev/null)"
    [[ "$err" == *"primary:"* ]] || return 1
    [[ "$err" == *"additional[2]:"* ]] || return 1
    [[ "$err" == *"generator:"* ]]
}
check "audit output includes per-password and generator roll-ups" t_audit_rollup

# --- Summary
printf '\n'
printf '%d passed, %d failed\n' "$PASSES" "$FAILS"
exit "$FAILS"
