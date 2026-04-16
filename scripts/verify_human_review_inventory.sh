#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOC="$REPO_ROOT/docs/reference/human-review.md"

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
  sed -E 's#^([^:]+):[0-9]+:#\1:#'
}

expected_inventory() {
  cat <<'EOF'
crates/paranoid-core/src/lib.rs:    // TODO: HUMAN_REVIEW - verify chi-squared upper-tail interpretation and thresholding.
crates/paranoid-core/src/lib.rs:    // TODO: HUMAN_REVIEW - verify the serial-correlation coefficient matches the intended estimator.
crates/paranoid-vault/src/lib.rs:        // TODO: HUMAN_REVIEW - confirm the device-bound keyslot design of storing the raw master key in OS secure storage plus an AES-GCM verification blob is acceptable across macOS, Windows, and Linux secret stores.
crates/paranoid-vault/src/lib.rs:        // TODO: HUMAN_REVIEW - confirm using 24-word BIP39 entropy directly as the AES-256-GCM wrapping key for mnemonic recovery slots is the right recovery construction.
crates/paranoid-vault/src/lib.rs:    // TODO: HUMAN_REVIEW - confirm CMS recipient selection and content-encryption policy for certificate-wrapped keyslots.
EOF
}

echo
echo "Human Review Inventory Verification"
echo

if [ ! -f "$DOC" ]; then
  fail "human review reference doc is missing at docs/reference/human-review.md"
fi

current="$(
  rg -n "TODO: HUMAN_REVIEW" "$REPO_ROOT/crates" --glob '*.rs' \
    | sed "s#^$REPO_ROOT/##" \
    | normalize_inventory
)"

expected="$(expected_inventory)"

if [ "$current" != "$expected" ]; then
  printf "%bCurrent inventory does not match the expected open review surface.%b\n" "$RED" "$NC"
  echo
  echo "Expected:"
  printf '%s\n' "$expected"
  echo
  echo "Actual:"
  printf '%s\n' "$current"
  echo
  fail "update docs/reference/human-review.md and scripts/verify_human_review_inventory.sh together when the review surface changes"
else
  pass "source TODO inventory matches the expected human review surface"
fi

for required in \
  "Chi-squared audit" \
  "Serial correlation audit" \
  "Device-bound keyslot design" \
  "Mnemonic recovery construction" \
  "Certificate-wrapped keyslots"
do
  if ! rg -F "$required" "$DOC" >/dev/null 2>&1; then
    fail "human review reference doc is missing required section: $required"
  fi
done

if rg -F "review status: **open**" "$DOC" >/dev/null 2>&1; then
  pass "human review reference doc still marks the review surface as open"
else
  warn "human review doc no longer marks the review surface as open"
fi

pass "human review reference doc contains the expected tracked review areas"
