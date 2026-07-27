#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOC="$REPO_ROOT/docs/reference/ai-review.md"

pass() {
  printf "%bPASS%b %s\n" "$GREEN" "$NC" "$1"
}

fail() {
  printf "%bFAIL%b %s\n" "$RED" "$NC" "$1"
  exit 1
}

warn() {
  printf "%bWARN%b %s\n" "$YELLOW" "$NC" "$1"
}

normalize_inventory() {
  sed -E 's#^([^:]+):[0-9]+:#\1:#' | LC_ALL=C sort
}

expected_inventory() {
  true
}

echo
echo "AI Review Inventory Verification"
echo

if [ ! -f "$DOC" ]; then
  fail "AI review reference doc is missing at docs/reference/ai-review.md"
fi

current="$(
  { rg -n "TODO: AI_REVIEW" "$REPO_ROOT/crates" --glob '*.rs' || true; } \
    | sed "s#^$REPO_ROOT/##" \
    | normalize_inventory
)"

expected="$(expected_inventory | LC_ALL=C sort)"

if [ "$current" != "$expected" ]; then
  printf "%bCurrent inventory does not match the expected open AI review surface.%b\n" "$RED" "$NC"
  echo
  echo "Expected:"
  printf '%s\n' "$expected"
  echo
  echo "Actual:"
  printf '%s\n' "$current"
  echo
  fail "update docs/reference/ai-review.md and scripts/verify_ai_review_inventory.sh together when the review surface changes"
else
  pass "source TODO inventory matches the expected AI review surface"
fi

if rg -F "expected open AI review sites: **0**" "$DOC" >/dev/null 2>&1; then
  pass "AI review reference doc tracks the expected open-site count"
else
  fail "AI review reference doc must state the expected open-site count"
fi

for required in \
  "Chi-squared audit" \
  "Dispositioned Inventory" \
  "chi_squared_upper_tail_threshold_brackets_one_percent_critical_value" \
  "Serial correlation audit" \
  "serial_correlation_exact_lag_one_known_answers" \
  "External audit-device posture" \
  "external_audit_device_availability_requires_ready_writable_health" \
  "TCP reachability remains evidence only and must stay" \
  "Ops policy boundary" \
  "policy_envelope_cannot_downgrade_authoritative_context_profile" \
  "vault_operation_policy_boundary_preserves_adapter_surface_and_access_metadata" \
  "seal.lifecycle-boundary" \
  "Seal lifecycle posture model" \
  "Device-bound keyslot design" \
  "device_keyslot_rejects_tampered_secure_storage_secret" \
  "device_keyslot_rejects_wrong_length_secure_storage_secret" \
  "backup_does_not_export_device_secure_storage_secret" \
  "Mnemonic recovery construction" \
  "mnemonic_keyslot_metadata_tampering_fails_closed" \
  "backup_does_not_export_mnemonic_phrase_or_entropy" \
  "Certificate-wrapped keyslots" \
  "validate_certificate_keyslot_metadata" \
  "certificate_keyslot_rejects_unsupported_wrap_algorithm" \
  "certificate_keyslot_metadata_tampering_fails_closed" \
  "certificate_keyslot_transport_key_shape_tampering_fails_closed" \
  "backup_does_not_export_certificate_private_key_or_raw_transport_key"
do
  if ! rg -F "$required" "$DOC" >/dev/null 2>&1; then
    fail "AI review reference doc is missing required section: $required"
  fi
done

if rg -F "AI review status: **closed**" "$DOC" >/dev/null 2>&1; then
  pass "AI review reference doc marks the review surface as closed"
else
  fail "AI review reference doc must mark the review surface as closed"
fi

if rg -F "make test-gui-visual-regression" "$DOC" >/dev/null 2>&1 \
  && rg -F "tests/baseline/gui/00-real-trust-gate.png" "$DOC" >/dev/null 2>&1 \
  && rg -F "tests/baseline/gui/02-real-vault-list.png" "$DOC" >/dev/null 2>&1 \
  && rg -F "tests/baseline/gui/07-real-locked.png" "$DOC" >/dev/null 2>&1; then
  pass "AI review reference doc requires per-screen GUI screenshot evidence for UI-sensitive changes"
else
  fail "AI review reference doc must require per-screen GUI screenshot evidence for UI-sensitive changes"
fi

pass "AI review reference doc contains the expected dispositioned review areas"
