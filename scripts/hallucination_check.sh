#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# hallucination_check.sh — Automated LLM Hallucination Detection
# ═══════════════════════════════════════════════════════════════════════════════
#
# This script detects common LLM hallucinations in cryptographic code:
#   1. Direct RNG usage (rand(), srand()) instead of OpenSSL RAND_bytes
#   2. Incorrect rejection sampling boundary (missing -1)
#   3. Inverted p-value logic (< instead of >)
#   4. Wrong degrees of freedom (N instead of N-1)
#   5. Unreviewed LLM code markers
#
# Exit codes:
#   0 = All checks passed
#   1 = Hallucination detected (security issue)
#
# Usage: ./scripts/hallucination_check.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$REPO_ROOT/src"
INC_DIR="$REPO_ROOT/include"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  LLM Hallucination Detection"
echo "═══════════════════════════════════════════════════════════"
echo ""

FAILED=0

# ─────────────────────────────────────────────────────────────
# Check 1: No direct RNG (must use platform abstraction)
# ─────────────────────────────────────────────────────────────
echo -n "Check 1: No direct rand()/srand() calls... "

if grep -rn '\brand\s*(' "$SRC_DIR" "$INC_DIR" 2>/dev/null | grep -v 'RAND_bytes' | grep -v 'random_get' | grep -v '// OK:'; then
    echo -e "${RED}FAIL${NC}"
    echo "  HALLUCINATION: Direct rand() found!"
    echo "  LLMs often generate rand() from training data (biased toward breach dumps)"
    echo "  FIX: Use paranoid_platform_random() (delegates to RAND_bytes or WASI random_get)"
    FAILED=1
else
    echo -e "${GREEN}PASS${NC}"
fi

if grep -rn '\bsrand\s*(' "$SRC_DIR" "$INC_DIR" 2>/dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo "  HALLUCINATION: srand() found!"
    echo "  FIX: CSPRNG doesn't need seeding; use RAND_bytes()"
    FAILED=1
fi

# ─────────────────────────────────────────────────────────────
# Check 2: Rejection sampling boundary correct (-1, not -0)
# ─────────────────────────────────────────────────────────────
echo -n "Check 2: Rejection sampling uses (256/N)*N - 1... "

# Look for the correct pattern
if grep -q 'max_valid.*=.*256.*charset_len.*-.*1' "$SRC_DIR"/*.c 2>/dev/null || \
   grep -q 'max_valid.*=.*(256.*/.*charset_len).*\*.*charset_len.*-.*1' "$SRC_DIR"/*.c 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "  HALLUCINATION: Wrong rejection sampling boundary!"
    echo "  LLMs often forget the -1, causing modulo bias"
    echo "  CORRECT: max_valid = (256 / charset_len) * charset_len - 1"
    echo "  WRONG:   max_valid = (256 / charset_len) * charset_len"
    FAILED=1
fi

# ─────────────────────────────────────────────────────────────
# Check 3: P-value interpretation correct (> 0.01 passes)
# ─────────────────────────────────────────────────────────────
echo -n "Check 3: P-value interpretation (p > 0.01 passes)... "

# Look for correct pattern: chi2_pass = (p_value > 0.01)
if grep -q 'chi2_pass.*=.*p.*>.*0\.01' "$SRC_DIR"/*.c 2>/dev/null || \
   grep -q 'chi2_p_value.*>.*0\.01' "$SRC_DIR"/*.c 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    # Check for inverted logic (common hallucination)
    if grep -q 'chi2_pass.*=.*p.*<.*0\.01' "$SRC_DIR"/*.c 2>/dev/null; then
        echo -e "${RED}FAIL${NC}"
        echo "  HALLUCINATION: Inverted p-value logic!"
        echo "  WRONG:   chi2_pass = (p_value < 0.01)  // Rejects good randomness"
        echo "  CORRECT: chi2_pass = (p_value > 0.01)  // Fails to reject H₀"
        FAILED=1
    else
        echo -e "${YELLOW}WARN${NC} (pattern not found, manual review needed)"
    fi
fi

# ─────────────────────────────────────────────────────────────
# Check 4: Degrees of freedom correct (N-1, not N)
# ─────────────────────────────────────────────────────────────
echo -n "Check 4: Degrees of freedom (df = N - 1)... "

# Look for correct pattern
if grep -q 'df.*=.*charset_len.*-.*1' "$SRC_DIR"/*.c 2>/dev/null || \
   grep -q 'chi2_df.*=.*-.*1' "$SRC_DIR"/*.c 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${YELLOW}WARN${NC} (pattern not found, manual review needed)"
fi

# ─────────────────────────────────────────────────────────────
# Check 5: No unreviewed LLM code markers in production
# ─────────────────────────────────────────────────────────────
echo -n "Check 5: No TODO:HUMAN_REVIEW markers... "

if grep -rn 'TODO.*HUMAN.*REVIEW\|FIXME.*LLM\|HALLUCINATION' "$SRC_DIR" "$INC_DIR" 2>/dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo "  Unreviewed LLM code found!"
    echo "  All TODO:HUMAN_REVIEW markers must be resolved before merge"
    FAILED=1
else
    echo -e "${GREEN}PASS${NC}"
fi

# ─────────────────────────────────────────────────────────────
# Check 6: Platform CSPRNG abstraction is used (not raw rand)
# ─────────────────────────────────────────────────────────────
echo -n "Check 6: CSPRNG via platform abstraction... "

# v3.0: paranoid.c calls paranoid_platform_random() (defined in paranoid_platform.h).
# platform_native.c implements it via OpenSSL RAND_bytes().
# platform_wasm.c implements it via WASI random_get().
if grep -q 'paranoid_platform_random' "$SRC_DIR"/paranoid.c 2>/dev/null; then
    # Also verify the native backend still delegates to RAND_bytes
    if grep -q 'RAND_bytes' "$SRC_DIR"/platform_native.c 2>/dev/null; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "  platform_native.c does not use RAND_bytes!"
        echo "  Native backend MUST delegate to OpenSSL CSPRNG"
        FAILED=1
    fi
else
    echo -e "${RED}FAIL${NC}"
    echo "  HALLUCINATION: paranoid_platform_random() not found in paranoid.c!"
    echo "  All randomness MUST go through the platform abstraction layer"
    FAILED=1
fi

# ─────────────────────────────────────────────────────────────
# Check 7: No JavaScript fallbacks
# ─────────────────────────────────────────────────────────────
echo -n "Check 7: No JavaScript RNG fallbacks... "

WWW_DIR="$REPO_ROOT/www"
if [ -d "$WWW_DIR" ]; then
    # Check for Math.random() or custom RNG in JS
    if grep -rn 'Math\.random\s*(' "$WWW_DIR"/*.js 2>/dev/null | grep -v '// test-only'; then
        echo -e "${RED}FAIL${NC}"
        echo "  HALLUCINATION: Math.random() found in production JavaScript!"
        echo "  JS layer must ONLY read from WASM, never generate"
        FAILED=1
    else
        echo -e "${GREEN}PASS${NC}"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (www/ not found)"
fi

# ─────────────────────────────────────────────────────────────
# Check 8: Struct offsets are verified at runtime
# ─────────────────────────────────────────────────────────────
echo -n "Check 8: Struct offset verification exports exist... "

if grep -q 'paranoid_offset_' "$INC_DIR"/*.h 2>/dev/null && \
   grep -q 'paranoid_offset_' "$SRC_DIR"/*.c 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${YELLOW}WARN${NC} (offset verification functions not found)"
fi

# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
if [ $FAILED -eq 0 ]; then
    echo -e "  ${GREEN}All hallucination checks passed${NC}"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    exit 0
else
    echo -e "  ${RED}Hallucination detected — DO NOT MERGE${NC}"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "LLM-generated code may contain subtle security bugs."
    echo "Review the flagged issues and fix before proceeding."
    echo ""
    exit 1
fi
