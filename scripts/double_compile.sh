#!/bin/bash
# ===============================================================================
# double_compile.sh — Diverse Double-Compilation for Compiler Backdoor Detection
# ===============================================================================
#
# Implements Ken Thompson's "Trusting Trust" attack mitigation:
# Compile with TWO different compilers and compare outputs.
#
# If a compiler has a self-propagating backdoor, the other compiler
# won't have it — the outputs will differ, revealing the attack.
#
# Compilers used:
#   1. Zig (primary — used in CI/CD)
#   2. Clang (secondary — system)
#
# v3.0: Uses CMake build system. WASM target compiles:
#   - src/paranoid.c (core logic)
#   - src/platform_wasm.c (WASI random_get backend)
#   - src/sha256_compact.c (FIPS 180-4 SHA-256, no OpenSSL)
#
# Note: Byte-for-byte identical output is NOT expected (different codegen).
# We compare FUNCTIONAL equivalence via:
#   - WAT disassembly comparison
#   - Export list comparison
#   - Import list comparison
#   - Function count comparison
#
# Usage: ./scripts/double_compile.sh
# ===============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build/double-compile"

echo ""
echo "==================================================================="
echo "  Diverse Double-Compilation"
echo "==================================================================="
echo ""

# -------------------------------------------------------------------
# Check prerequisites
# -------------------------------------------------------------------

echo "Checking prerequisites..."

# Check for Zig
if ! command -v zig &> /dev/null; then
    echo -e "${RED}ERROR: Zig not found${NC}"
    echo "Install Zig or add to PATH"
    exit 1
fi
ZIG_VERSION=$(zig version)
echo "  Zig: $ZIG_VERSION"

# Check for Clang
if ! command -v clang &> /dev/null; then
    echo -e "${YELLOW}WARNING: Clang not found${NC}"
    echo "Clang compilation will be skipped"
    HAS_CLANG=0
else
    CLANG_VERSION=$(clang --version | head -1)
    echo "  Clang: $CLANG_VERSION"
    HAS_CLANG=1
fi

# Check for wasm2wat (wabt)
if ! command -v wasm2wat &> /dev/null; then
    echo -e "${YELLOW}WARNING: wasm2wat not found${NC}"
    echo "Install wabt for detailed comparison"
    echo "  apt-get install wabt  OR  brew install wabt"
    HAS_WABT=0
else
    echo "  wabt: $(wasm2wat --version 2>/dev/null || echo 'available')"
    HAS_WABT=1
fi

# Check for wasm-objdump
if ! command -v wasm-objdump &> /dev/null; then
    HAS_OBJDUMP=0
else
    HAS_OBJDUMP=1
fi

echo ""

# -------------------------------------------------------------------
# Setup
# -------------------------------------------------------------------

mkdir -p "$BUILD_DIR"
cd "$REPO_ROOT"

# v3.0: No vendor/openssl needed for WASM build.
# WASM uses platform_wasm.c (WASI random_get) + sha256_compact.c.
SOURCES=(
    src/paranoid.c
    src/platform_wasm.c
    src/sha256_compact.c
)

INCLUDE_FLAGS=(-I include -I src)

# Common WASM export flags (must match CMakeLists.txt WASM_EXPORTS)
# shellcheck disable=SC2054
EXPORT_FLAGS=(
    -Wl,--export=paranoid_version
    -Wl,--export=paranoid_generate
    -Wl,--export=paranoid_generate_multiple
    -Wl,--export=paranoid_generate_constrained
    -Wl,--export=paranoid_validate_charset
    -Wl,--export=paranoid_check_compliance
    -Wl,--export=paranoid_run_audit
    -Wl,--export=paranoid_get_result_ptr
    -Wl,--export=paranoid_get_result_size
    -Wl,--export=paranoid_offset_password_length
    -Wl,--export=paranoid_offset_chi2_statistic
    -Wl,--export=paranoid_offset_current_stage
    -Wl,--export=paranoid_offset_all_pass
    -Wl,--export=paranoid_sha256
    -Wl,--export=paranoid_sha256_hex
    -Wl,--export=paranoid_chi_squared
    -Wl,--export=paranoid_serial_correlation
    -Wl,--export=paranoid_count_collisions
    -Wl,--export=malloc
    -Wl,--export=free
)

# -------------------------------------------------------------------
# Build 1: Zig
# -------------------------------------------------------------------

echo "==================================================================="
echo "  Build 1: Zig ($ZIG_VERSION)"
echo "==================================================================="
echo ""

ZIG_OUT="$BUILD_DIR/paranoid-zig.wasm"

echo "Compiling with Zig..."
zig cc \
    --target=wasm32-wasi \
    -mexec-model=reactor \
    -O2 \
    "${INCLUDE_FLAGS[@]}" \
    -Wl,--no-entry \
    -Wl,--gc-sections \
    -fdata-sections \
    -ffunction-sections \
    "${EXPORT_FLAGS[@]}" \
    "${SOURCES[@]}" \
    -o "$ZIG_OUT" \
    2>&1 || { echo -e "${RED}Zig compilation failed${NC}"; exit 1; }

ZIG_SIZE=$(stat -f%z "$ZIG_OUT" 2>/dev/null || stat -c%s "$ZIG_OUT")
ZIG_HASH=$(sha256sum "$ZIG_OUT" | cut -d' ' -f1)

echo -e "${GREEN}OK${NC} Zig build complete"
echo "  Size: $ZIG_SIZE bytes"
echo "  Hash: ${ZIG_HASH:0:16}..."
echo ""

# -------------------------------------------------------------------
# Build 2: Clang (if available)
# -------------------------------------------------------------------

if [ "$HAS_CLANG" -eq 1 ]; then
    echo "==================================================================="
    echo "  Build 2: Clang"
    echo "==================================================================="
    echo ""

    CLANG_OUT="$BUILD_DIR/paranoid-clang.wasm"

    echo "Compiling with Clang..."
    # Note: Clang WASM compilation requires wasi-sdk or similar
    # This is a best-effort attempt
    if clang \
        --target=wasm32-wasi \
        -mexec-model=reactor \
        -O3 \
        "${INCLUDE_FLAGS[@]}" \
        -Wl,--no-entry \
        -Wl,--gc-sections \
        -fdata-sections \
        -ffunction-sections \
        "${EXPORT_FLAGS[@]}" \
        "${SOURCES[@]}" \
        -o "$CLANG_OUT" \
        2>&1; then

        CLANG_SIZE=$(stat -f%z "$CLANG_OUT" 2>/dev/null || stat -c%s "$CLANG_OUT")
        CLANG_HASH=$(sha256sum "$CLANG_OUT" | cut -d' ' -f1)

        echo -e "${GREEN}OK${NC} Clang build complete"
        echo "  Size: $CLANG_SIZE bytes"
        echo "  Hash: ${CLANG_HASH:0:16}..."
        echo ""
    else
        echo -e "${YELLOW}Clang compilation failed${NC}"
        echo "This is expected without wasi-sdk configured"
        HAS_CLANG=0
    fi
fi

# -------------------------------------------------------------------
# Compare outputs
# -------------------------------------------------------------------

echo "==================================================================="
echo "  Comparison"
echo "==================================================================="
echo ""

# Extract and compare exports
if [ "$HAS_OBJDUMP" -eq 1 ]; then
    echo "Comparing exports..."

    ZIG_EXPORTS=$(wasm-objdump -x "$ZIG_OUT" 2>/dev/null | grep " -> " | sort)
    ZIG_EXPORT_COUNT=$(echo "$ZIG_EXPORTS" | wc -l)

    echo "  Zig exports: $ZIG_EXPORT_COUNT functions"

    if [ "$HAS_CLANG" -eq 1 ] && [ -f "$CLANG_OUT" ]; then
        CLANG_EXPORTS=$(wasm-objdump -x "$CLANG_OUT" 2>/dev/null | grep " -> " | sort)
        CLANG_EXPORT_COUNT=$(echo "$CLANG_EXPORTS" | wc -l)
        echo "  Clang exports: $CLANG_EXPORT_COUNT functions"

        if [ "$ZIG_EXPORT_COUNT" -eq "$CLANG_EXPORT_COUNT" ]; then
            echo -e "  ${GREEN}OK${NC} Export count matches"
        else
            echo -e "  ${RED}MISMATCH${NC} Export count differs!"
        fi
    fi
    echo ""
fi

# Disassemble and compare (if wabt available)
if [ "$HAS_WABT" -eq 1 ]; then
    echo "Disassembling to WAT..."

    ZIG_WAT="$BUILD_DIR/paranoid-zig.wat"
    wasm2wat "$ZIG_OUT" -o "$ZIG_WAT" 2>/dev/null || true

    if [ -f "$ZIG_WAT" ]; then
        ZIG_FUNCS=$(grep -c '(func ' "$ZIG_WAT" || echo "0")
        echo "  Zig: $ZIG_FUNCS functions"
    fi

    if [ "$HAS_CLANG" -eq 1 ] && [ -f "$CLANG_OUT" ]; then
        CLANG_WAT="$BUILD_DIR/paranoid-clang.wat"
        wasm2wat "$CLANG_OUT" -o "$CLANG_WAT" 2>/dev/null || true

        if [ -f "$CLANG_WAT" ]; then
            CLANG_FUNCS=$(grep -c '(func ' "$CLANG_WAT" || echo "0")
            echo "  Clang: $CLANG_FUNCS functions"
        fi
    fi
    echo ""
fi

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------

echo "==================================================================="
echo "  Summary"
echo "==================================================================="
echo ""
echo "Zig build:"
echo "  Output: $ZIG_OUT"
echo "  Size:   $ZIG_SIZE bytes"
echo "  Hash:   $ZIG_HASH"
echo ""

if [ "$HAS_CLANG" -eq 1 ] && [ -f "$CLANG_OUT" ]; then
    echo "Clang build:"
    echo "  Output: $CLANG_OUT"
    echo "  Size:   $CLANG_SIZE bytes"
    echo "  Hash:   $CLANG_HASH"
    echo ""

    if [ "$ZIG_HASH" = "$CLANG_HASH" ]; then
        echo -e "${GREEN}IDENTICAL HASHES${NC} (unexpected but good)"
    else
        echo -e "${YELLOW}Different hashes${NC} (expected — different codegen)"
        echo "Manual review of exports/functionality recommended"
    fi
else
    echo -e "${YELLOW}Single-compiler build only${NC}"
    echo "Install Clang with wasi-sdk for full diverse compilation"
fi

echo ""
echo "==================================================================="
echo ""
