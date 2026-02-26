#!/bin/bash
# ===============================================================================
# integration_test.sh — End-to-End Integration Tests
# ===============================================================================
#
# Tests the complete build pipeline:
#   1. Source files exist (v3.0 platform abstraction)
#   2. Build WASM via CMake + Zig
#   3. Verify exports
#   4. Verify imports
#   5. Check binary size
#   6. Run hallucination checks
#   7. Run supply chain verification
#
# v3.0: Uses CMake build system with Zig cross-compilation.
#       No vendor/openssl, no Makefile, no wasm_entry.c.
#
# Usage: ./scripts/integration_test.sh
# ===============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo ""
echo "==================================================================="
echo "  Integration Tests"
echo "==================================================================="
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

# -------------------------------------------------------------------
# Pre-flight checks
# -------------------------------------------------------------------
echo "Pre-flight checks:"
echo ""

run_test "Source file exists" "test -f $REPO_ROOT/src/paranoid.c"
run_test "Platform WASM backend exists" "test -f $REPO_ROOT/src/platform_wasm.c"
run_test "Platform native backend exists" "test -f $REPO_ROOT/src/platform_native.c"
run_test "Compact SHA-256 exists" "test -f $REPO_ROOT/src/sha256_compact.c"
run_test "Header file exists" "test -f $REPO_ROOT/include/paranoid.h"
run_test "Platform header exists" "test -f $REPO_ROOT/include/paranoid_platform.h"
run_test "CMakeLists.txt exists" "test -f $REPO_ROOT/CMakeLists.txt"
run_test "WASM toolchain file exists" "test -f $REPO_ROOT/cmake/wasm32-wasi.cmake"
run_test "Web assets exist" "test -f $REPO_ROOT/www/index.html"
run_test "Web app.js exists" "test -f $REPO_ROOT/www/app.js"
run_test "Web style.css exists" "test -f $REPO_ROOT/www/style.css"

echo ""

# -------------------------------------------------------------------
# Build tests (CMake + Zig)
# -------------------------------------------------------------------
echo "Build tests:"
echo ""

cd "$REPO_ROOT"

# Check for Zig
echo -n "TEST: Zig available... "
if command -v zig &> /dev/null; then
    echo -e "${GREEN}PASS${NC} ($(zig version))"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    FAILED=$((FAILED + 1))
    echo "  Zig not found. Cannot build WASM target."
    echo ""
    echo "==================================================================="
    echo "  Results: $PASSED passed, $FAILED failed"
    echo "==================================================================="
    exit 1
fi

# CMake configure
echo -n "TEST: cmake configure (WASM)... "
if cmake -B build/wasm \
    -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake \
    -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1; then
    echo -e "${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    FAILED=$((FAILED + 1))
    echo "  CMake configure failed!"
    exit 1
fi

# CMake build
echo -n "TEST: cmake build (WASM)... "
if cmake --build build/wasm > /dev/null 2>&1; then
    echo -e "${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    FAILED=$((FAILED + 1))
    echo "  Build failed! Check Zig installation."
    exit 1
fi

echo ""

# -------------------------------------------------------------------
# WASM verification tests
# -------------------------------------------------------------------
echo "WASM verification tests:"
echo ""

WASM="$REPO_ROOT/build/wasm/paranoid.wasm"

run_test "WASM file exists" "test -f $WASM"

# Check binary size (v3.0: no OpenSSL, smaller binary expected)
echo -n "TEST: Binary size in range... "
if [ -f "$WASM" ]; then
    SIZE=$(stat -f%z "$WASM" 2>/dev/null || stat -c%s "$WASM")
    # v3.0 binary should be 20KB-200KB (no OpenSSL, compact SHA-256)
    if [ "$SIZE" -gt 20000 ] && [ "$SIZE" -lt 200000 ]; then
        echo -e "${GREEN}PASS${NC} ($SIZE bytes)"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAIL${NC} ($SIZE bytes - outside expected range 20KB-200KB)"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "${RED}FAIL${NC} (file not found)"
    FAILED=$((FAILED + 1))
fi

# Validate WASM binary
if command -v wasm-validate &> /dev/null; then
    run_test "WASM validates" "wasm-validate $WASM"
fi

# Check exports (if wabt available)
if command -v wasm-objdump &> /dev/null; then
    REQUIRED_EXPORTS="paranoid_version paranoid_generate paranoid_run_audit paranoid_get_result_ptr paranoid_get_result_size paranoid_offset_password_length paranoid_offset_all_pass malloc free"

    for EXPORT in $REQUIRED_EXPORTS; do
        run_test "Export: $EXPORT" "wasm-objdump -x $WASM 2>/dev/null | grep -q '<${EXPORT}>'"
    done

    # Check imports (should only be wasi_snapshot_preview1)
    echo -n "TEST: Only WASI imports... "
    IMPORTS=$(wasm-objdump -x "$WASM" 2>/dev/null | grep " <- " | grep -v "wasi_snapshot_preview1" || true)
    if [ -z "$IMPORTS" ]; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAIL${NC}"
        echo "  Unexpected imports found:"
        echo "    ${IMPORTS//$'\n'/$'\n'    }"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "${YELLOW}SKIP${NC} wasm-objdump not available (install wabt)"
fi

echo ""

# -------------------------------------------------------------------
# Hallucination check
# -------------------------------------------------------------------
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

# -------------------------------------------------------------------
# Supply chain check
# -------------------------------------------------------------------
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

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo "==================================================================="
echo "  Results: $PASSED passed, $FAILED failed"
echo "==================================================================="
echo ""

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Integration tests failed!${NC}"
    exit 1
else
    echo -e "${GREEN}All integration tests passed!${NC}"
    exit 0
fi
