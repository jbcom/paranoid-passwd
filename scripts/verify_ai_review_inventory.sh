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
  cat <<'EOF'
crates/paranoid-core/src/lib.rs:    // TODO: AI_REVIEW - verify the serial-correlation coefficient matches the intended estimator.
crates/paranoid-audit/src/lib.rs:// TODO: AI_REVIEW - confirm external audit-device posture and health semantics do not overstate sink availability or federal audit coverage.
crates/paranoid-ops/src/lib.rs:// TODO: AI_REVIEW - centralized policy boundary for ops/vault authorization and audit evidence across adapters.
crates/paranoid-seal/src/lib.rs:// TODO: AI_REVIEW - confirm the seal/posture model correctly represents unlock and recovery posture without overstating provider availability.
crates/paranoid-vault/src/lib.rs:        // TODO: AI_REVIEW - confirm the device-bound keyslot design of storing the raw master key in OS secure storage plus an AES-GCM verification blob is acceptable across macOS, Windows, and Linux secret stores.
crates/paranoid-vault/src/lib.rs:        // TODO: AI_REVIEW - confirm using 24-word BIP39 entropy directly as the AES-256-GCM wrapping key for mnemonic recovery slots is the right recovery construction.
crates/paranoid-vault/src/lib.rs:    // TODO: AI_REVIEW - confirm CMS recipient selection and content-encryption policy for certificate-wrapped keyslots.
EOF
}

echo
echo "AI Review Inventory Verification"
echo

if [ ! -f "$DOC" ]; then
  fail "AI review reference doc is missing at docs/reference/ai-review.md"
fi

current="$(
  rg -n "TODO: AI_REVIEW" "$REPO_ROOT/crates" --glob '*.rs' \
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

if rg -F "expected open AI review sites: **7**" "$DOC" >/dev/null 2>&1; then
  pass "AI review reference doc tracks the expected open-site count"
else
  fail "AI review reference doc must state the expected open-site count"
fi

for required in \
  "Chi-squared audit" \
  "Dispositioned Inventory" \
  "chi_squared_upper_tail_threshold_brackets_one_percent_critical_value" \
  "Serial correlation audit" \
  "External audit-device posture" \
  "Ops policy boundary" \
  "seal.lifecycle-boundary" \
  "Seal lifecycle posture model" \
  "Device-bound keyslot design" \
  "Mnemonic recovery construction" \
  "Certificate-wrapped keyslots"
do
  if ! rg -F "$required" "$DOC" >/dev/null 2>&1; then
    fail "AI review reference doc is missing required section: $required"
  fi
done

if rg -F "AI review status: **open**" "$DOC" >/dev/null 2>&1; then
  pass "AI review reference doc still marks the review surface as open"
else
  warn "AI review doc no longer marks the review surface as open"
fi

if rg -F "make test-gui-visual-regression" "$DOC" >/dev/null 2>&1 \
  && rg -F "dist/release/gui-e2e-desktop.png" "$DOC" >/dev/null 2>&1 \
  && rg -F "dist/release/gui-e2e-tablet.png" "$DOC" >/dev/null 2>&1 \
  && rg -F "dist/release/gui-e2e-mobile.png" "$DOC" >/dev/null 2>&1; then
  pass "AI review reference doc requires multi-viewport GUI screenshot evidence for UI-sensitive changes"
else
  fail "AI review reference doc must require multi-viewport GUI screenshot evidence for UI-sensitive changes"
fi

pass "AI review reference doc contains the expected tracked review areas"
