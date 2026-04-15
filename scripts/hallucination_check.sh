#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE="$REPO_ROOT/crates/paranoid-core/src/lib.rs"

failed=0

pass() {
  printf "%bPASS%b %s\n" "$GREEN" "$NC" "$1"
}

fail() {
  printf "%bFAIL%b %s\n" "$RED" "$NC" "$1"
  failed=1
}

warn() {
  printf "%bWARN%b %s\n" "$YELLOW" "$NC" "$1"
}

echo
echo "Rust-Native Hallucination Checks"
echo

if rg -n -P '\b(use\s+rand::|rand::(thread_rng|rng|random|Rng|distributions|prelude)|StdRng|SmallRng|OsRng|fastrand|Math\.random|getRandomValues)\b' \
  "$REPO_ROOT/crates" "$REPO_ROOT/scripts" "$REPO_ROOT/.github" \
  --glob '!scripts/hallucination_check.sh' >/dev/null 2>&1; then
  fail "non-approved randomness source detected"
else
  pass "no ad hoc randomness helpers detected"
fi

if rg -n '\bunsafe\b' "$REPO_ROOT/crates" >/dev/null 2>&1; then
  fail "unsafe Rust detected in workspace crates"
else
  pass "workspace crates remain unsafe-free"
fi

if rg -q 'let max_valid = \(256 / charset_bytes\.len\(\)\) \* charset_bytes\.len\(\) - 1;' "$CORE" \
  && rg -q 'let rejection_max_valid = \(256 / charset_len\) \* charset_len - 1;' "$CORE"; then
  pass "rejection sampling keeps the critical -1 boundary"
else
  fail "rejection sampling boundary no longer matches the audited formula"
fi

if rg -q 'let chi2_pass = chi2_p_value > 0\.01;' "$CORE"; then
  pass "chi-squared pass logic still rejects only low p-values"
else
  fail "chi-squared pass logic no longer uses p > 0.01"
fi

if rg -q 'let df = charset_bytes\.len\(\)\.saturating_sub\(1\);' "$CORE"; then
  pass "chi-squared degrees of freedom remain N - 1"
else
  fail "chi-squared degrees of freedom changed away from N - 1"
fi

if rg -q '^use openssl::\{rand::rand_bytes, sha::sha256\};' "$CORE"; then
  pass "core still delegates RNG and SHA-256 to OpenSSL"
else
  fail "OpenSSL-backed RNG/SHA-256 delegation missing from paranoid-core"
fi

if rg -q '^use statrs::distribution::\{ChiSquared, ContinuousCDF\};' "$CORE"; then
  pass "chi-squared tail probability still uses statrs"
else
  fail "statrs chi-squared dependency path missing"
fi

legacy_paths=(
  "$REPO_ROOT/CMakeLists.txt"
  "$REPO_ROOT/www"
  "$REPO_ROOT/tests/e2e"
  "$REPO_ROOT/src/paranoid.c"
  "$REPO_ROOT/include/paranoid.h"
  "$REPO_ROOT/melange.yaml"
  "$REPO_ROOT/apko.yaml"
)

legacy_found=0
for path in "${legacy_paths[@]}"; do
  if [ -e "$path" ]; then
    printf "  legacy path still present: %s\n" "$path"
    legacy_found=1
  fi
done

if [ "$legacy_found" -eq 0 ]; then
  pass "retired browser/C surfaces are gone"
else
  fail "retired browser/C surfaces still exist"
fi

if [ "$failed" -ne 0 ]; then
  echo
  echo -e "${RED}Hallucination checks failed${NC}"
  exit 1
fi

echo
echo -e "${GREEN}All hallucination checks passed${NC}"
