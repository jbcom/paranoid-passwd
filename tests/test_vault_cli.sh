#!/usr/bin/env bash
# tests/test_vault_cli.sh — headless vault workflow tests
#
# Invoked with the CLI binary path as $1. Exercises the documented headless
# vault flows against the real CLI surface, including recovery, transfer,
# backup, and release-sensitive keyslot lifecycle behavior.

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

if ! command -v openssl >/dev/null 2>&1; then
    echo "FAIL: openssl is required for vault e2e tests" >&2
    exit 1
fi

TMPDIR_ROOT="$(mktemp -d)"
SOURCE_VAULT="$TMPDIR_ROOT/source.sqlite"
RESTORE_VAULT="$TMPDIR_ROOT/restore.sqlite"
IMPORT_PASSWORD_VAULT="$TMPDIR_ROOT/import-password.sqlite"
IMPORT_CERT_VAULT="$TMPDIR_ROOT/import-cert.sqlite"
IMPORT_REPLACE_VAULT="$TMPDIR_ROOT/import-replace.sqlite"
BACKUP_PATH="$TMPDIR_ROOT/vault.backup.json"
TRANSFER_PATH="$TMPDIR_ROOT/work-login.transfer.json"
DEVICE_STORE_DIR="$TMPDIR_ROOT/device-store"

CERT1_PEM="$TMPDIR_ROOT/cert-one.pem"
CERT1_KEY="$TMPDIR_ROOT/key-one.pem"
CERT2_PEM="$TMPDIR_ROOT/cert-two.pem"
CERT2_KEY="$TMPDIR_ROOT/key-two.pem"

MASTER_PASSWORD="VaultPrimary#2026"
NEW_MASTER_PASSWORD="VaultPrimary#2026-rotated"
IMPORT_PASSWORD_MASTER="ImportPassword#2026"
IMPORT_CERT_MASTER="ImportCert#2026"
TRANSFER_PASSWORD="TransferSecret#2026"

export PARANOID_TRANSFER_PASSWORD="$TRANSFER_PASSWORD"

LOGIN1_ID=""
LOGIN2_ID=""
NOTE_ID=""
CARD_ID=""
IDENTITY_ID=""
MNEMONIC_SLOT_ID=""
MNEMONIC_OLD=""
MNEMONIC_NEW=""
DEVICE_SLOT_ID=""
DEVICE_ACCOUNT_BEFORE=""
DEVICE_ACCOUNT_AFTER=""
CERT_SLOT_ID=""
LOGIN1_ROTATED_PASSWORD=""

cleanup() {
    rm -rf "$TMPDIR_ROOT"
}
trap cleanup EXIT

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

contains() {
    local haystack="$1"
    local needle="$2"
    [[ "$haystack" == *"$needle"* ]]
}

not_contains() {
    local haystack="$1"
    local needle="$2"
    [[ "$haystack" != *"$needle"* ]]
}

extract_tsv_value() {
    local content="$1"
    local key="$2"
    printf '%s\n' "$content" | awk -F '\t' -v key="$key" '$1 == key { print $2; exit }'
}

extract_colon_value() {
    local content="$1"
    local key="$2"
    printf '%s\n' "$content" | awk -F ': ' -v key="$key" '$1 == key { print substr($0, length($1) + 3); exit }'
}

source_vault() {
    PARANOID_MASTER_PASSWORD="$MASTER_PASSWORD" \
    PARANOID_TEST_DEVICE_STORE_DIR="$DEVICE_STORE_DIR" \
    "$BIN" vault --cli --path "$SOURCE_VAULT" "$@"
}

source_vault_with_master() {
    local master="$1"
    shift
    PARANOID_MASTER_PASSWORD="$master" \
    PARANOID_TEST_DEVICE_STORE_DIR="$DEVICE_STORE_DIR" \
    "$BIN" vault --cli --path "$SOURCE_VAULT" "$@"
}

source_vault_no_master() {
    env -u PARANOID_MASTER_PASSWORD \
        PARANOID_TEST_DEVICE_STORE_DIR="$DEVICE_STORE_DIR" \
        "$BIN" vault --cli --path "$SOURCE_VAULT" "$@"
}

source_vault_with_mnemonic() {
    local mnemonic="$1"
    shift
    PARANOID_TEST_RECOVERY_PHRASE="$mnemonic" \
    PARANOID_TEST_DEVICE_STORE_DIR="$DEVICE_STORE_DIR" \
    "$BIN" vault --cli --path "$SOURCE_VAULT" --recovery-phrase-env PARANOID_TEST_RECOVERY_PHRASE "$@"
}

source_vault_with_cert() {
    local cert_path="$1"
    local key_path="$2"
    shift 2
    env -u PARANOID_MASTER_PASSWORD \
        PARANOID_TEST_DEVICE_STORE_DIR="$DEVICE_STORE_DIR" \
        "$BIN" vault --cli --path "$SOURCE_VAULT" --cert "$cert_path" --key "$key_path" "$@"
}

vault_at() {
    local path="$1"
    local master="$2"
    shift 2
    PARANOID_MASTER_PASSWORD="$master" \
    PARANOID_TEST_DEVICE_STORE_DIR="$DEVICE_STORE_DIR" \
    "$BIN" vault --cli --path "$path" "$@"
}

vault_import_with_password() {
    local path="$1"
    local master="$2"
    shift 2
    PARANOID_MASTER_PASSWORD="$master" \
    PARANOID_TRANSFER_PASSWORD="$TRANSFER_PASSWORD" \
    PARANOID_TEST_DEVICE_STORE_DIR="$DEVICE_STORE_DIR" \
    "$BIN" vault --cli --path "$path" "$@"
}

vault_import_with_cert() {
    local path="$1"
    local master="$2"
    shift 2
    PARANOID_MASTER_PASSWORD="$master" \
    PARANOID_TEST_DEVICE_STORE_DIR="$DEVICE_STORE_DIR" \
    "$BIN" vault --cli --path "$path" "$@"
}

generate_cert_pair() {
    local cert_path="$1"
    local key_path="$2"
    local common_name="$3"
    openssl req \
        -x509 \
        -newkey rsa:2048 \
        -sha256 \
        -days 365 \
        -nodes \
        -subj "/CN=${common_name}" \
        -keyout "$key_path" \
        -out "$cert_path" \
        >/dev/null 2>&1
}

prepare_workspace() {
    mkdir -p "$DEVICE_STORE_DIR"
    generate_cert_pair "$CERT1_PEM" "$CERT1_KEY" "paranoid-passwd.test.one"
    generate_cert_pair "$CERT2_PEM" "$CERT2_KEY" "paranoid-passwd.test.two"
}

t_init_and_crud() {
    local out=""
    local audit_out=""
    local audit_path=""
    local audit_missing_path=""
    local audit_denial=""
    local audit_err=""
    local audit_rc=0
    local seal_status=""
    local created_password=""
    local created_list=""
    local created_login_id=""
    local created_show=""
    local login2_show=""
    local note_show=""
    local card_show=""
    local identity_show=""
    local list_out=""
    local login1_show=""
    local temp_note_id=""

    out="$(source_vault init)"
    contains "$out" $'initialized\t'"$SOURCE_VAULT" || return 1
    contains "$out" "format=1" || return 1
    contains "$out" "keyslots=1" || return 1

    seal_status="$(source_vault seal-status)"
    MASTER_PASSWORD="$MASTER_PASSWORD" python3 -c '
import json
import os
import sys

data = json.load(sys.stdin)
seal = data["seal"]
assert data["operation"] == "vault_seal_status"
assert data["state"] == "sealed"
assert seal["state"] == "sealed"
assert seal["provider_count"] == 1
assert seal["operator_recovery_configured"] is True
assert seal["recovery_required"] is False
assert any(
    provider["kind"] == "password_recovery" and provider["status"] == "configured"
    for provider in seal["providers"]
)
assert os.environ["MASTER_PASSWORD"] not in json.dumps(data)
' <<<"$seal_status"

    audit_path="$TMPDIR_ROOT/vault-audit.jsonl"
    audit_out="$(source_vault --audit-jsonl "$audit_path" keyslots)"
    contains "$audit_out" $'posture\trecovery=true' || return 1
    [[ -s "$audit_path" ]] || return 1
    AUDIT_JSONL="$audit_path" python3 -c '
import json
import os

with open(os.environ["AUDIT_JSONL"], encoding="utf-8") as handle:
    events = [json.loads(line) for line in handle]

assert len(events) == 2
assert events[0]["surface"] == "ops"
assert events[0]["action"] == "vault_operation.request"
assert events[1]["action"] == "vault_operation.response"
assert events[0]["attributes"]["request_id"] == events[1]["attributes"]["request_id"]
assert events[0]["attributes"]["session_surface"] == "vault"
assert events[1]["attributes"]["session_surface"] == "vault"
assert events[0]["attributes"]["vault_operation"] == "keyslots"
assert events[0]["attributes"]["vault_access"] == "metadata"
assert events[1]["attributes"]["decision"] == "allow"
'

    audit_missing_path="$TMPDIR_ROOT/missing/vault-audit.jsonl"
    audit_err="$TMPDIR_ROOT/vault-audit.err"
    audit_rc=0
    audit_denial="$(source_vault --audit-jsonl "$audit_missing_path" keyslots 2>"$audit_err")" || audit_rc=$?
    if [[ "$audit_rc" -ne 6 || -s "$audit_err" ]]; then
        return 1
    fi
    printf '%s' "$audit_denial" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
assert data["operation"] == "vault"
assert data["status"] == "error"
assert data["error_kind"] == "policy_denied"
assert data["audit_sink"]["status"] == "unavailable"
assert data["policy_decision"]["missing_controls"] == ["required_audit_sink"]
assert data["audit_events"][0]["action"] == "vault_operation.request"
assert data["audit_events"][0]["attributes"]["session_surface"] == "vault"
'

    LOGIN1_ID="$(source_vault add --title GitHub --username octo@example.com --password 'ReuseMe#2026' --url https://github.com --notes 'Primary engineering login' --folder Work --tags work,code)"
    LOGIN2_ID="$(source_vault add --title GitLab --username octo@example.com --password 'ReuseMe#2026' --folder Archive --tags archive)"
    NOTE_ID="$(source_vault add-note --title 'API seed' --content 'Rotate after migration cutover.' --folder Recovery --tags recovery,ops)"
    CARD_ID="$(source_vault add-card --title 'Travel Card' --cardholder 'Octo Example' --number '4111111111111111' --expiry-month 08 --expiry-year 2031 --security-code 999 --notes 'Use for travel only' --folder Finance --tags travel)"
    IDENTITY_ID="$(source_vault add-identity --title 'Primary Identity' --full-name 'Octo Example' --email octo@example.com --phone '555-0100' --address '1 Example Way' --notes 'Main identity record' --folder Recovery --tags identity)"
    temp_note_id="$(source_vault add-note --title 'Temp note' --content 'Delete me' --folder Scratch --tags temp)"

    source_vault update --id "$LOGIN2_ID" --url https://gitlab.com --notes 'Rotates weekly' --clear-folder --clear-tags >/dev/null
    source_vault update-note --id "$NOTE_ID" --content 'Rotate after verified recovery drill.' --folder Ops --tags recovery,verified >/dev/null
    source_vault update-card --id "$CARD_ID" --billing-zip 60601 --notes 'Bring to canary release travel' >/dev/null
    source_vault update-identity --id "$IDENTITY_ID" --email octo+vault@example.com --phone '555-0101' >/dev/null
    source_vault delete --id "$temp_note_id" >/dev/null

    login2_show="$(source_vault show --id "$LOGIN2_ID")"
    contains "$login2_show" "url: https://gitlab.com" || return 1
    contains "$login2_show" "notes: Rotates weekly" || return 1
    contains "$login2_show" "folder: " || return 1
    contains "$login2_show" "tags: " || return 1

    note_show="$(source_vault show --id "$NOTE_ID")"
    contains "$note_show" "content: Rotate after verified recovery drill." || return 1
    contains "$note_show" "folder: Ops" || return 1
    contains "$note_show" "tags: recovery,verified" || return 1

    card_show="$(source_vault show --id "$CARD_ID")"
    contains "$card_show" "billing_zip: 60601" || return 1
    contains "$card_show" "notes: Bring to canary release travel" || return 1

    identity_show="$(source_vault show --id "$IDENTITY_ID")"
    contains "$identity_show" "email: octo+vault@example.com" || return 1
    contains "$identity_show" "phone: 555-0101" || return 1

    list_out="$(source_vault list --query GitHub)"
    contains "$list_out" "$LOGIN1_ID"$'\tlogin\tGitHub' || return 1
    not_contains "$list_out" "$temp_note_id" || return 1

    list_out="$(source_vault list --kind login --folder Work --tag code)"
    contains "$list_out" "$LOGIN1_ID"$'\tlogin\tGitHub' || return 1
    not_contains "$list_out" "$LOGIN2_ID" || return 1

    login1_show="$(source_vault show --id "$LOGIN1_ID")"
    contains "$login1_show" "duplicate_password_count: 1" || return 1

    created_password="$(source_vault generate-store --title 'CI Robot' --username ci@example.com --folder Automation --tags generated,ci --length 20 --framework nist --quiet 2>/dev/null)"
    [[ ${#created_password} -eq 20 ]] || return 1
    created_list="$(source_vault list --query 'CI Robot')"
    created_login_id="$(printf '%s\n' "$created_list" | awk -F '\t' '$3 == "CI Robot" { print $1; exit }')"
    [[ -n "$created_login_id" ]] || return 1
    created_show="$(source_vault show --id "$created_login_id")"
    contains "$created_show" "username: ci@example.com" || return 1
    contains "$created_show" "password: $created_password" || return 1
    contains "$created_show" "folder: Automation" || return 1
    contains "$created_show" "tags: generated,ci" || return 1
    source_vault delete --id "$created_login_id" >/dev/null

    LOGIN1_ROTATED_PASSWORD="$(source_vault generate-store --id "$LOGIN1_ID" --length 24 --framework nist --quiet 2>/dev/null)"
    [[ ${#LOGIN1_ROTATED_PASSWORD} -eq 24 ]] || return 1

    login1_show="$(source_vault show --id "$LOGIN1_ID")"
    contains "$login1_show" "password: $LOGIN1_ROTATED_PASSWORD" || return 1
    contains "$login1_show" "password_history_count: 1" || return 1
    contains "$login1_show" "duplicate_password_count: 0" || return 1
    contains "$login1_show" "folder: Work" || return 1
    contains "$login1_show" "tags: work,code" || return 1

    return 0
}

t_recovery_paths() {
    local cert_preview=""
    local mnemonic_out=""
    local device_out=""
    local cert_out=""
    local keyslots=""
    local seal_probe=""
    local inspect_out=""
    local rotate_out=""

    cert_preview="$(source_vault inspect-certificate --cert "$CERT1_PEM")"
    contains "$cert_preview" $'subject\tCN=paranoid-passwd.test.one' || return 1

    mnemonic_out="$(source_vault add-mnemonic-slot --label paper-backup)"
    MNEMONIC_SLOT_ID="$(extract_tsv_value "$mnemonic_out" "slot_id")"
    MNEMONIC_OLD="$(extract_tsv_value "$mnemonic_out" "mnemonic")"
    [[ -n "$MNEMONIC_SLOT_ID" ]] || return 1
    [[ "$(printf '%s\n' "$MNEMONIC_OLD" | wc -w | tr -d ' ')" -eq 24 ]] || return 1

    device_out="$(source_vault add-device-slot --label daily)"
    DEVICE_SLOT_ID="$(printf '%s\n' "$device_out" | cut -f1)"
    [[ -n "$DEVICE_SLOT_ID" ]] || return 1

    cert_out="$(source_vault add-cert-slot --cert "$CERT1_PEM" --label laptop)"
    CERT_SLOT_ID="$(printf '%s\n' "$cert_out" | cut -f1)"
    [[ -n "$CERT_SLOT_ID" ]] || return 1

    keyslots="$(source_vault keyslots)"
    contains "$keyslots" "$MNEMONIC_SLOT_ID"$'\tmnemonic_recovery' || return 1
    contains "$keyslots" "$DEVICE_SLOT_ID"$'\tdevice_bound' || return 1
    contains "$keyslots" "$CERT_SLOT_ID"$'\tcertificate_wrapped' || return 1

    seal_probe="$(source_vault seal-status --probe-providers)"
    DEVICE_SLOT_ID="$DEVICE_SLOT_ID" python3 -c '
import json
import os
import sys

data = json.load(sys.stdin)
seal = data["seal"]
device_id = os.environ["DEVICE_SLOT_ID"]
device = next(
    (provider for provider in seal["providers"] if provider["provider_id"] == device_id),
    None,
)
provider_ids = [provider["provider_id"] for provider in seal["providers"]]
assert device is not None, f"device provider {device_id!r} not found in {provider_ids!r}"
assert device["kind"] == "device_bound"
assert device["status"] == "available"
assert device["evidence_source"] == "device_provider_health_check"
assert seal["auto_unseal_available"] is True
' <<<"$seal_probe"

    inspect_out="$(source_vault inspect-keyslot --id "$CERT_SLOT_ID")"
    contains "$inspect_out" "label"$'\t'"laptop" || return 1
    contains "$inspect_out" "certificate_subject"$'\t'"CN=paranoid-passwd.test.one" || return 1

    source_vault_with_mnemonic "$MNEMONIC_OLD" list --query GitHub | grep -F "$LOGIN1_ID" >/dev/null
    source_vault_no_master list --query GitHub | grep -F "$LOGIN1_ID" >/dev/null
    source_vault_no_master --device-slot "$DEVICE_SLOT_ID" list --query GitHub | grep -F "$LOGIN1_ID" >/dev/null
    source_vault_with_cert "$CERT1_PEM" "$CERT1_KEY" list --query GitHub | grep -F "$LOGIN1_ID" >/dev/null

    rotate_out="$(source_vault rotate-mnemonic-slot --id "$MNEMONIC_SLOT_ID")"
    MNEMONIC_NEW="$(extract_tsv_value "$rotate_out" "mnemonic")"
    [[ "$(printf '%s\n' "$MNEMONIC_NEW" | wc -w | tr -d ' ')" -eq 24 ]] || return 1
    if source_vault_with_mnemonic "$MNEMONIC_OLD" list --query GitHub >/dev/null 2>&1; then
        return 1
    fi
    source_vault_with_mnemonic "$MNEMONIC_NEW" list --query GitHub | grep -F "$LOGIN1_ID" >/dev/null

    inspect_out="$(source_vault inspect-keyslot --id "$DEVICE_SLOT_ID")"
    DEVICE_ACCOUNT_BEFORE="$(extract_tsv_value "$inspect_out" "device_account")"
    [[ -n "$DEVICE_ACCOUNT_BEFORE" ]] || return 1
    source_vault rebind-device-slot --id "$DEVICE_SLOT_ID" >/dev/null
    inspect_out="$(source_vault inspect-keyslot --id "$DEVICE_SLOT_ID")"
    DEVICE_ACCOUNT_AFTER="$(extract_tsv_value "$inspect_out" "device_account")"
    [[ -n "$DEVICE_ACCOUNT_AFTER" ]] || return 1
    [[ "$DEVICE_ACCOUNT_AFTER" != "$DEVICE_ACCOUNT_BEFORE" ]] || return 1
    source_vault_no_master --device-slot "$DEVICE_SLOT_ID" list --query GitHub | grep -F "$LOGIN1_ID" >/dev/null

    source_vault rename-keyslot --id "$CERT_SLOT_ID" --label laptop-rotated >/dev/null
    inspect_out="$(source_vault inspect-keyslot --id "$CERT_SLOT_ID")"
    contains "$inspect_out" "label"$'\t'"laptop-rotated" || return 1

    source_vault rewrap-cert-slot --id "$CERT_SLOT_ID" --cert "$CERT2_PEM" >/dev/null
    if source_vault_with_cert "$CERT1_PEM" "$CERT1_KEY" list --query GitHub >/dev/null 2>&1; then
        return 1
    fi
    source_vault_with_cert "$CERT2_PEM" "$CERT2_KEY" list --query GitHub | grep -F "$LOGIN1_ID" >/dev/null
    inspect_out="$(source_vault inspect-keyslot --id "$CERT_SLOT_ID")"
    contains "$inspect_out" "certificate_subject"$'\t'"CN=paranoid-passwd.test.two" || return 1

    return 0
}

t_federal_recovery_disposition_policy() {
    local audit_path=""
    local cert_audit_path=""
    local err_path=""
    local out=""
    local rc=0

    audit_path="$TMPDIR_ROOT/federal-password-audit.jsonl"
    err_path="$TMPDIR_ROOT/federal-password.err"
    rc=0
    out="$(PARANOID_FEDERAL_APPROVED_MODE=confirmed \
        PARANOID_FEDERAL_CERTIFICATE_REFERENCE="CMVP fixture certificate" \
        source_vault --federal-ready --audit-jsonl "$audit_path" list --query GitHub 2>"$err_path")" || rc=$?
    if [[ "$rc" -ne 6 || -s "$err_path" || ! -s "$audit_path" ]]; then
        return 1
    fi
    printf '%s' "$out" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
assert data["operation"] == "vault"
assert data["status"] == "error"
assert data["error_kind"] == "policy_denied"
assert data["policy_decision"]["decision"] == "deny"
assert "non_federal_unlock_method:password_recovery" in data["policy_decision"]["missing_controls"]
' || return 1
    AUDIT_JSONL="$audit_path" python3 -c '
import json
import os

with open(os.environ["AUDIT_JSONL"], encoding="utf-8") as handle:
    events = [json.loads(line) for line in handle]

assert [event["action"] for event in events] == [
    "vault_operation.request",
    "vault_operation.response",
    "vault_unlock.request",
    "vault_unlock.response",
]
assert events[1]["attributes"]["decision"] == "allow"
assert events[3]["attributes"]["decision"] == "deny"
assert events[2]["attributes"]["unlock_method"] == "password_recovery"
' || return 1

    cert_audit_path="$TMPDIR_ROOT/federal-certificate-audit.jsonl"
    err_path="$TMPDIR_ROOT/federal-certificate.err"
    rc=0
    out="$(PARANOID_FEDERAL_APPROVED_MODE=confirmed \
        PARANOID_FEDERAL_CERTIFICATE_REFERENCE="CMVP fixture certificate" \
        source_vault_with_cert "$CERT2_PEM" "$CERT2_KEY" --federal-ready --audit-jsonl "$cert_audit_path" list --query GitHub 2>"$err_path")" || rc=$?
    if [[ "$rc" -ne 7 || -s "$err_path" || ! -s "$cert_audit_path" ]]; then
        return 1
    fi
    printf '%s' "$out" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
assert data["status"] == "challenge_required"
assert data["error_kind"] == "policy_challenge"
assert data["policy_decision"]["decision"] == "challenge"
assert "fresh_operator_proof" in data["policy_decision"]["required_actions"]
' || return 1
    CERT_AUDIT_JSONL="$cert_audit_path" python3 -c '
import json
import os

with open(os.environ["CERT_AUDIT_JSONL"], encoding="utf-8") as handle:
    events = [json.loads(line) for line in handle]

assert [event["action"] for event in events] == [
    "vault_operation.request",
    "vault_operation.response",
    "vault_unlock.request",
    "vault_unlock.response",
]
assert events[1]["attributes"]["decision"] == "allow"
assert events[3]["attributes"]["decision"] == "challenge"
assert events[2]["attributes"]["unlock_method"] == "certificate_wrapped"
assert "fresh_operator_proof" in json.loads(events[3]["attributes"]["required_actions"])
' || return 1

    return 0
}

t_backup_and_transfer() {
    local backup_summary=""
    local import_summary=""
    local restored_list=""
    local transfer_summary=""
    local imported_list=""
    local github_count=""

    source_vault export-backup --output "$BACKUP_PATH" >/dev/null
    backup_summary="$(source_vault inspect-backup --input "$BACKUP_PATH")"
    contains "$backup_summary" $'item_count\t5' || return 1
    contains "$backup_summary" $'keyslot_count\t4' || return 1
    contains "$backup_summary" $'restorable_by_current_build\ttrue' || return 1
    contains "$backup_summary" $'recovery_posture\trecovery=true\tcertificate=true\trecommended=true' || return 1

    "$BIN" vault --cli --path "$RESTORE_VAULT" import-backup --input "$BACKUP_PATH" >/dev/null
    restored_list="$(vault_at "$RESTORE_VAULT" "$MASTER_PASSWORD" list --query GitHub)"
    contains "$restored_list" $'\tlogin\tGitHub' || return 1
    if "$BIN" vault --cli --path "$RESTORE_VAULT" import-backup --input "$BACKUP_PATH" >/dev/null 2>&1; then
        return 1
    fi
    "$BIN" vault --cli --path "$RESTORE_VAULT" import-backup --input "$BACKUP_PATH" --force >/dev/null
    restored_list="$(vault_at "$RESTORE_VAULT" "$MASTER_PASSWORD" list --query GitHub)"
    contains "$restored_list" $'\tlogin\tGitHub' || return 1

    source_vault export-transfer --output "$TRANSFER_PATH" --kind login --folder Work --tag code --package-password-env PARANOID_TRANSFER_PASSWORD --package-cert "$CERT2_PEM" >/dev/null
    transfer_summary="$(source_vault inspect-transfer --input "$TRANSFER_PATH")"
    contains "$transfer_summary" $'item_count\t1' || return 1
    contains "$transfer_summary" $'has_recovery_path\ttrue' || return 1
    contains "$transfer_summary" $'has_certificate_path\ttrue' || return 1
    contains "$transfer_summary" $'filter\tquery=\tkind=login\tfolder=Work\ttag=code' || return 1
    contains "$transfer_summary" $'certificate_subject\tCN=paranoid-passwd.test.two' || return 1

    vault_at "$IMPORT_PASSWORD_VAULT" "$IMPORT_PASSWORD_MASTER" init >/dev/null
    vault_import_with_password "$IMPORT_PASSWORD_VAULT" "$IMPORT_PASSWORD_MASTER" import-transfer --input "$TRANSFER_PATH" --package-password-env PARANOID_TRANSFER_PASSWORD >/dev/null
    imported_list="$(vault_at "$IMPORT_PASSWORD_VAULT" "$IMPORT_PASSWORD_MASTER" list --query GitHub)"
    contains "$imported_list" $'\tlogin\tGitHub' || return 1
    import_summary="$(vault_import_with_password "$IMPORT_PASSWORD_VAULT" "$IMPORT_PASSWORD_MASTER" import-transfer --input "$TRANSFER_PATH" --package-password-env PARANOID_TRANSFER_PASSWORD)"
    contains "$import_summary" $'imported_count\t1' || return 1
    contains "$import_summary" $'replaced_count\t0' || return 1
    contains "$import_summary" $'remapped_count\t1' || return 1
    imported_list="$(vault_at "$IMPORT_PASSWORD_VAULT" "$IMPORT_PASSWORD_MASTER" list --query GitHub)"
    github_count="$(printf '%s\n' "$imported_list" | awk -F '\t' '$3 == "GitHub" { count += 1 } END { print count + 0 }')"
    [[ "$github_count" == "2" ]] || return 1

    vault_at "$IMPORT_CERT_VAULT" "$IMPORT_CERT_MASTER" init >/dev/null
    vault_import_with_cert "$IMPORT_CERT_VAULT" "$IMPORT_CERT_MASTER" import-transfer --input "$TRANSFER_PATH" --package-cert "$CERT2_PEM" --package-key "$CERT2_KEY" >/dev/null
    imported_list="$(vault_at "$IMPORT_CERT_VAULT" "$IMPORT_CERT_MASTER" list --query GitHub)"
    contains "$imported_list" $'\tlogin\tGitHub' || return 1

    vault_at "$IMPORT_REPLACE_VAULT" "$IMPORT_CERT_MASTER" init >/dev/null
    vault_import_with_password "$IMPORT_REPLACE_VAULT" "$IMPORT_CERT_MASTER" import-transfer --input "$TRANSFER_PATH" --package-password-env PARANOID_TRANSFER_PASSWORD >/dev/null
    import_summary="$(vault_import_with_password "$IMPORT_REPLACE_VAULT" "$IMPORT_CERT_MASTER" import-transfer --input "$TRANSFER_PATH" --replace-existing --package-password-env PARANOID_TRANSFER_PASSWORD)"
    contains "$import_summary" $'imported_count\t1' || return 1
    contains "$import_summary" $'replaced_count\t1' || return 1
    contains "$import_summary" $'remapped_count\t0' || return 1
    imported_list="$(vault_at "$IMPORT_REPLACE_VAULT" "$IMPORT_CERT_MASTER" list --query GitHub)"
    github_count="$(printf '%s\n' "$imported_list" | awk -F '\t' '$3 == "GitHub" { count += 1 } END { print count + 0 }')"
    [[ "$github_count" == "1" ]] || return 1

    return 0
}

t_rotation_and_removal_guards() {
    local keyslots=""

    PARANOID_MASTER_PASSWORD="$MASTER_PASSWORD" \
    PARANOID_NEXT_MASTER_PASSWORD="$NEW_MASTER_PASSWORD" \
    PARANOID_TEST_DEVICE_STORE_DIR="$DEVICE_STORE_DIR" \
    "$BIN" vault --cli --path "$SOURCE_VAULT" rotate-recovery-secret --new-password-env PARANOID_NEXT_MASTER_PASSWORD >/dev/null

    if source_vault_with_master "$MASTER_PASSWORD" list --query GitHub >/dev/null 2>&1; then
        return 1
    fi
    source_vault_with_master "$NEW_MASTER_PASSWORD" list --query GitHub | grep -F "$LOGIN1_ID" >/dev/null

    if source_vault_with_master "$NEW_MASTER_PASSWORD" remove-keyslot --id "$CERT_SLOT_ID" >/dev/null 2>&1; then
        return 1
    fi
    source_vault_with_master "$NEW_MASTER_PASSWORD" remove-keyslot --id "$CERT_SLOT_ID" --force >/dev/null
    keyslots="$(source_vault_with_master "$NEW_MASTER_PASSWORD" keyslots)"
    not_contains "$keyslots" "$CERT_SLOT_ID"$'\tcertificate_wrapped' || return 1

    return 0
}

prepare_workspace

check "headless vault init, CRUD, filters, and generate-store rotation" t_init_and_crud
check "mnemonic, device, and certificate unlock flows" t_recovery_paths
check "federal recovery disposition gates vault unlock methods" t_federal_recovery_disposition_policy
check "backup restore and transfer-package round trips" t_backup_and_transfer
check "recovery-secret rotation and keyslot removal guards" t_rotation_and_removal_guards

printf '\n'
printf '%d passed, %d failed\n' "$PASSES" "$FAILS"
exit "$FAILS"
