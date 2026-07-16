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

# --- Test 14: --json emits a structured automation report
t_json_output() {
    local out err
    err="$(mktemp)" || return 1
    out="$("$BIN" --cli --json --length 12 --charset hex --no-audit 2>"$err")"
    if [[ -s "$err" ]]; then
        rm -f "$err"
        return 1
    fi
    printf '%s' "$out" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
assert data["schema_version"] == 1
assert data["operation"] == "generate_password"
assert data["operation_id"].startswith("pp.operation.v1.")
assert data["status"] == "success"
assert len(data["report"]["passwords"]) == 1
assert len(data["report"]["passwords"][0]["value"]) == 12
assert data["audit_events"][0]["operation_id"] == data["operation_id"]
assert data["audit_events"][0]["event_id"] == data["operation_id"] + ".event.1"
'
    rm -f "$err"
}
check "--json emits structured automation report" t_json_output

# --- Test 15: --json errors stay structured
t_json_error_output() {
    local out err rc
    err="$(mktemp)" || return 1
    rc=0
    out="$("$BIN" --cli --json --length 0 2>"$err")" || rc=$?
    if [[ "$rc" -ne 1 ]]; then
        rm -f "$err"
        return 1
    fi
    if [[ -s "$err" ]]; then
        rm -f "$err"
        return 1
    fi
    printf '%s' "$out" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
assert data["schema_version"] == 1
assert data["operation"] == "generate_password"
assert data["operation_id"].startswith("pp.operation.v1.")
assert data["status"] == "error"
assert data["error_kind"] == "invalid_arguments"
assert data["audit_events"][0]["operation_id"] == data["operation_id"]
'
    rm -f "$err"
}
check "--json emits structured error report" t_json_error_output

# --- Test 16: --audit-jsonl writes request/response audit evidence
t_audit_jsonl_sink() {
    local out err dir audit
    dir="$(mktemp -d)" || return 1
    err="$dir/stderr"
    audit="$dir/audit.jsonl"
    out="$("$BIN" --cli --json --length 12 --charset hex --no-audit --audit-jsonl "$audit" 2>"$err")"
    if [[ -s "$err" || ! -s "$audit" ]]; then
        rm -rf "$dir"
        return 1
    fi
    printf '%s' "$out" | AUDIT_JSONL="$audit" python3 -c '
import json
import os
import sys

report = json.load(sys.stdin)
with open(os.environ["AUDIT_JSONL"], encoding="utf-8") as handle:
    events = [json.loads(line) for line in handle]

assert report["operation_id"].startswith("pp.operation.v1.")
assert len(events) >= 4
assert events[0]["action"] == "generate_password.request"
assert events[1]["action"] == "generate_password.response"
assert all(event["operation_id"] == report["operation_id"] for event in events)
'
    rm -rf "$dir"
}
check "--audit-jsonl writes typed request/response events" t_audit_jsonl_sink

# --- Test 17: federal-ready mode fails closed without approved provider evidence
t_federal_ready_policy_denial() {
    local out err dir audit rc
    dir="$(mktemp -d)" || return 1
    err="$dir/stderr"
    audit="$dir/audit.jsonl"
    rc=0
    out="$("$BIN" --cli --json --federal-ready --length 12 --audit-jsonl "$audit" 2>"$err")" || rc=$?
    if [[ "$rc" -ne 6 || -s "$err" || ! -s "$audit" ]]; then
        rm -rf "$dir"
        return 1
    fi
    printf '%s' "$out" | AUDIT_JSONL="$audit" python3 -c '
import json
import os
import sys

report = json.load(sys.stdin)
with open(os.environ["AUDIT_JSONL"], encoding="utf-8") as handle:
    events = [json.loads(line) for line in handle]

assert report["status"] == "error"
assert report["error_kind"] == "policy_denied"
assert report["audit_sink"]["status"] == "ready"
assert "fips_approved_mode" in report["policy_decision"]["missing_controls"]
assert events[-1]["outcome"] == "blocked"
'
    rm -rf "$dir"
}
check "federal-ready profile fails closed without approved provider evidence" t_federal_ready_policy_denial

# --- Test 18: federal evidence emits startup profile report
t_federal_evidence() {
    local out
    out="$(env \
        -u PARANOID_AUDIT_DEVICE_ENDPOINT \
        -u PARANOID_AUDIT_DEVICE_ID \
        -u PARANOID_AUDIT_DEVICE_MTLS_CERT \
        -u PARANOID_AUDIT_DEVICE_MTLS_KEY \
        -u PARANOID_AUDIT_DEVICE_CA_CERT \
        -u PARANOID_AUDIT_DEVICE_PROBE \
        -u PARANOID_FEDERAL_APPROVED_MODE \
        -u PARANOID_FEDERAL_CERTIFICATE_REFERENCE \
        "$BIN" --federal-evidence)"
    printf '%s' "$out" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
assert data["schema_version"] == 3
assert data["profile"] == "federal_ready"
assert data["audit_sink"]["status"] == "not_configured"
assert data["external_audit_device"]["kind"] == "external_device"
assert data["external_audit_device"]["status"] == "not_configured"
assert data["crypto_provider"]["provider_name"] == "OpenSSL"
assert any(
    method["federal_ready_policy_control"] == "non_federal_unlock_method:mnemonic_recovery"
    for method in data["recovery_disposition"]["methods"]
)
device = next(
    method
    for method in data["recovery_disposition"]["methods"]
    if method["method"] == "device_bound"
)
assert "device_bound_provider_available" in device["required_controls"]
assert data["policy_decision"]["decision"] == "deny"
'
}
check "--federal-evidence emits startup profile report" t_federal_evidence

# --- Test 19: explicit required sink fails closed without a sink path
t_required_audit_sink_denial() {
    local out err rc
    err="$(mktemp)" || return 1
    rc=0
    out="$("$BIN" --cli --json --require-audit-sink --length 12 2>"$err")" || rc=$?
    if [[ "$rc" -ne 6 || -s "$err" ]]; then
        rm -f "$err"
        return 1
    fi
    printf '%s' "$out" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
assert data["status"] == "error"
assert data["error_kind"] == "policy_denied"
assert data["audit_sink"]["status"] == "not_configured"
assert data["policy_decision"]["missing_controls"] == ["required_audit_sink"]
'
    rm -f "$err"
}
check "--require-audit-sink fails closed without --audit-jsonl" t_required_audit_sink_denial

# --- Test 20: configured but unwritable audit sink fails at policy
t_unavailable_audit_sink_denial() {
    local out err dir audit rc
    dir="$(mktemp -d)" || return 1
    err="$dir/stderr"
    audit="$dir/missing/audit.jsonl"
    rc=0
    out="$("$BIN" --cli --json --audit-jsonl "$audit" --length 12 2>"$err")" || rc=$?
    if [[ "$rc" -ne 6 || -s "$err" ]]; then
        rm -rf "$dir"
        return 1
    fi
    printf '%s' "$out" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
assert data["status"] == "error"
assert data["error_kind"] == "policy_denied"
assert data["audit_sink"]["status"] == "unavailable"
assert data["audit_sink"]["configured"] is True
assert data["audit_sink"]["writable"] is False
assert data["audit_sink"]["failure"]
assert data["policy_decision"]["missing_controls"] == ["required_audit_sink"]
'
    rm -rf "$dir"
}
check "--audit-jsonl fails closed when configured sink is unavailable" t_unavailable_audit_sink_denial

# --- Test 21: detect-environment emits capability report
t_detect_environment() {
    local out
    out="$("$BIN" --detect-environment)"
    printf '%s' "$out" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
assert data["schema_version"] == 1
assert data["operating_system"]
assert data["architecture"]
assert data["os_keychain"]["status"] in ("available", "unavailable", "not_checked")
assert data["os_keychain"]["evidence_source"] == "keyring_probe"
assert data["clipboard"]["status"] in ("available", "unavailable", "not_checked")
assert data["clipboard"]["evidence_source"] == "arboard_probe"
assert data["display_server"]["kind"] in (
    "quartz", "wayland", "x11", "windows", "headless"
)
assert isinstance(data["seal_providers"], list)
'
}
check "--detect-environment emits capability report" t_detect_environment

# --- Summary
printf '\n'
printf '%d passed, %d failed\n' "$PASSES" "$FAILS"
exit "$FAILS"
