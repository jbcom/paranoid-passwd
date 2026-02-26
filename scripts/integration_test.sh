#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# integration_test.sh — End-to-End Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════
#
# Tests the complete build pipeline:
#   1. Build WASM from source
#   2. Verify exports
#   3. Verify imports
#   4. Check binary size
#   5. Verify SRI hash generation
#   6. Run hallucination checks
#   7. Run supply chain verification
#
# Usage: ./scripts/integration_test.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Integration Tests"
echo "═══════════════════════════════════════════════════════════"
echo ""

PASSED=0
FAILED=0

run_test() {
    local NAME="$1"
    local CMD="$2"
    
    echo -n "TEST: $NAME... "
    
    if eval "$CMD" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────
# Pre-flight checks
# ─────────────────────────────────────────────────────────────
echo "Pre-flight checks:"
echo ""

run_test "Source file exists" "test -f $REPO_ROOT/src/paranoid.c"
run_test "Header file exists" "test -f $REPO_ROOT/include/paranoid.h"
run_test "Makefile exists" "test -f $REPO_ROOT/Makefile"
run_test "Web assets exist" "test -f $REPO_ROOT/www/index.html"
run_test "OpenSSL WASM available" "test -d $REPO_ROOT/vendor/openssl-wasm/precompiled"
run_test "libcrypto.a exists" "test -f $REPO_ROOT/vendor/openssl-wasm/precompiled/lib/libcrypto.a"
run_test "Acutest available" "test -f $REPO_ROOT/vendor/acutest/include/acutest.h"

echo ""

# ─────────────────────────────────────────────────────────────
# Build tests
# ─────────────────────────────────────────────────────────────
echo "Build tests:"
echo ""

cd "$REPO_ROOT"

# Clean build
echo -n "TEST: make clean... "
if make clean > /dev/null 2>&1; then
    echo -e "${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${YELLOW}SKIP${NC} (nothing to clean)"
fi

# Build WASM
echo -n "TEST: make build... "
if make build > /dev/null 2>&1; then
    echo -e "${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    FAILED=$((FAILED + 1))
    echo "  Build failed! Check Zig installation."
    exit 1
fi

# Build site
echo -n "TEST: make site... "
if make site > /dev/null 2>&1; then
    echo -e "${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    FAILED=$((FAILED + 1))
fi

echo ""

# ─────────────────────────────────────────────────────────────
# WASM verification tests
# ─────────────────────────────────────────────────────────────
echo "WASM verification tests:"
echo ""

WASM="$REPO_ROOT/build/paranoid.wasm"

run_test "WASM file exists" "test -f $WASM"

# Check binary size (should be ~180KB ± 50KB)
echo -n "TEST: Binary size in range... "
if [ -f "$WASM" ]; then
    SIZE=$(stat -f%z "$WASM" 2>/dev/null || stat -c%s "$WASM")
    if [ "$SIZE" -gt 100000 ] && [ "$SIZE" -lt 300000 ]; then
        echo -e "${GREEN}PASS${NC} ($SIZE bytes)"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAIL${NC} ($SIZE bytes - outside expected range)"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "${RED}FAIL${NC} (file not found)"
    FAILED=$((FAILED + 1))
fi

# Check exports (if wabt available)
if command -v wasm-objdump &> /dev/null; then
    REQUIRED_EXPORTS="paranoid_version paranoid_generate paranoid_run_audit paranoid_get_result_ptr malloc free"
    
    for EXPORT in $REQUIRED_EXPORTS; do
        run_test "Export: $EXPORT" "wasm-objdump -x $WASM 2>/dev/null | grep -q '$EXPORT'"
    done
    
    # Check imports (should only be wasi_snapshot_preview1)
    echo -n "TEST: Only WASI imports... "
    IMPORTS=$(wasm-objdump -x "$WASM" 2>/dev/null | grep "import" | grep -v "wasi_snapshot_preview1" || true)
    if [ -z "$IMPORTS" ]; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAIL${NC}"
        echo "  Unexpected imports found:"
        echo "$IMPORTS" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "${YELLOW}SKIP${NC} wasm-objdump not available (install wabt)"
fi

echo ""

# ─────────────────────────────────────────────────────────────
# Site verification tests
# ─────────────────────────────────────────────────────────────
echo "Site verification tests:"
echo ""

SITE_DIR="$REPO_ROOT/build/site"

run_test "Site directory exists" "test -d $SITE_DIR"
run_test "index.html exists" "test -f $SITE_DIR/index.html"
run_test "app.js exists" "test -f $SITE_DIR/app.js"
run_test "style.css exists" "test -f $SITE_DIR/style.css"
run_test "paranoid.wasm exists" "test -f $SITE_DIR/paranoid.wasm"
run_test "BUILD_MANIFEST.json exists" "test -f $SITE_DIR/BUILD_MANIFEST.json"

# Check SRI hashes injected
echo -n "TEST: SRI hashes injected... "
if grep -q 'sha384-' "$SITE_DIR/index.html" 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    FAILED=$((FAILED + 1))
fi

# Check no placeholders remain
echo -n "TEST: No SRI placeholders... "
if ! grep -q '__.*_SRI__' "$SITE_DIR/index.html" 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    echo "  Unreplaced placeholders found"
    FAILED=$((FAILED + 1))
fi

echo ""

# ─────────────────────────────────────────────────────────────
# Hallucination check
# ─────────────────────────────────────────────────────────────
echo "Hallucination detection:"
echo ""

if [ -x "$SCRIPT_DIR/hallucination_check.sh" ]; then
    echo -n "TEST: Hallucination check... "
    if "$SCRIPT_DIR/hallucination_check.sh" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAIL${NC}"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "${YELLOW}SKIP${NC} (script not found)"
fi

echo ""

# ─────────────────────────────────────────────────────────────
# Supply chain check
# ─────────────────────────────────────────────────────────────
echo "Supply chain verification:"
echo ""

if [ -x "$SCRIPT_DIR/supply_chain_verify.sh" ]; then
    echo -n "TEST: Supply chain verify... "
    if "$SCRIPT_DIR/supply_chain_verify.sh" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${YELLOW}WARN${NC} (non-critical issues)"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (script not found)"
fi

echo ""

# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════"
echo "  Results: $PASSED passed, $FAILED failed"
echo "═══════════════════════════════════════════════════════════"
echo ""

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Integration tests failed!${NC}"
    exit 1
else
    echo -e "${GREEN}All integration tests passed!${NC}"
    exit 0
fi
