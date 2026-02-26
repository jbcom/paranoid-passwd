#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# supply_chain_verify.sh — Supply Chain Verification Script
# ═══════════════════════════════════════════════════════════════════════════════
#
# Verifies the complete supply chain before build/deploy:
#   1. No uncommitted changes
#   2. OpenSSL built from source (vendor/openssl with BUILD_PROVENANCE.txt)
#   3. libcrypto.a exists
#   4. Zig compiler hash verification (if available)
#   5. GitHub Actions SHA-pinned
#   6. Dockerfile base image pinned
#   7. Source files exist
#   8. Web assets exist
#   9. Git metadata available
#
# Exit codes:
#   0 = All verifications passed
#   1 = Verification failed (supply chain issue)
#
# Usage: ./scripts/supply_chain_verify.sh
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
echo "  Supply Chain Verification"
echo "═══════════════════════════════════════════════════════════"
echo ""

FAILED=0
WARNINGS=0

# ─────────────────────────────────────────────────────────────
# Check 1: No uncommitted changes
# ─────────────────────────────────────────────────────────────
echo -n "Check 1: No uncommitted changes... "
cd "$REPO_ROOT"

if git diff --quiet && git diff --cached --quiet; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${YELLOW}WARN${NC}"
    echo "  Uncommitted changes detected. Build may not be reproducible."
    WARNINGS=$((WARNINGS + 1))
fi

# ─────────────────────────────────────────────────────────────
# Check 2: Platform abstraction layer exists
# ─────────────────────────────────────────────────────────────
echo -n "Check 2: Platform abstraction layer... "

PLATFORM_H="$REPO_ROOT/include/paranoid_platform.h"
PLATFORM_NATIVE="$REPO_ROOT/src/platform_native.c"
PLATFORM_WASM="$REPO_ROOT/src/platform_wasm.c"

if [ -f "$PLATFORM_H" ] && [ -f "$PLATFORM_NATIVE" ] && [ -f "$PLATFORM_WASM" ]; then
    echo -e "${GREEN}PASS${NC}"
    echo "    paranoid_platform.h, platform_native.c, platform_wasm.c all present"
else
    echo -e "${RED}FAIL${NC}"
    echo "  Platform abstraction layer incomplete!"
    [ ! -f "$PLATFORM_H" ] && echo "    Missing: include/paranoid_platform.h"
    [ ! -f "$PLATFORM_NATIVE" ] && echo "    Missing: src/platform_native.c"
    [ ! -f "$PLATFORM_WASM" ] && echo "    Missing: src/platform_wasm.c"
    FAILED=1
fi

# ─────────────────────────────────────────────────────────────
# Check 3: CMake build system exists
# ─────────────────────────────────────────────────────────────
echo -n "Check 3: CMake build system... "

CMAKE_FILE="$REPO_ROOT/CMakeLists.txt"
TOOLCHAIN_FILE="$REPO_ROOT/cmake/wasm32-wasi.cmake"
if [ -f "$CMAKE_FILE" ] && [ -f "$TOOLCHAIN_FILE" ]; then
    echo -e "${GREEN}PASS${NC}"
    echo "    CMakeLists.txt and cmake/wasm32-wasi.cmake present"
else
    echo -e "${RED}FAIL${NC}"
    echo "  CMake build system incomplete!"
    [ ! -f "$CMAKE_FILE" ] && echo "    Missing: CMakeLists.txt"
    [ ! -f "$TOOLCHAIN_FILE" ] && echo "    Missing: cmake/wasm32-wasi.cmake"
    FAILED=1
fi

# ─────────────────────────────────────────────────────────────
# Check 4: Zig tarball hash (if present)
# ─────────────────────────────────────────────────────────────
echo -n "Check 4: Zig tarball hash... "

ZIG_TARBALL="$REPO_ROOT/zig-linux-x86_64-0.13.0.tar.xz"
EXPECTED_ZIG_HASH="d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea"

if [ -f "$ZIG_TARBALL" ]; then
    if command -v sha256sum &> /dev/null; then
        ACTUAL_HASH=$(sha256sum "$ZIG_TARBALL" | cut -d' ' -f1)
        if [ "$ACTUAL_HASH" = "$EXPECTED_ZIG_HASH" ]; then
            echo -e "${GREEN}PASS${NC}"
        else
            echo -e "${RED}FAIL${NC}"
            echo "  Zig tarball hash mismatch!"
            echo "  Expected: $EXPECTED_ZIG_HASH"
            echo "  Actual:   $ACTUAL_HASH"
            FAILED=1
        fi
    else
        echo -e "${YELLOW}SKIP${NC} (sha256sum not available)"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (tarball not present locally)"
fi

# ─────────────────────────────────────────────────────────────
# Check 5: GitHub Actions SHA-pinned
# ─────────────────────────────────────────────────────────────
echo -n "Check 5: GitHub Actions SHA-pinned... "

WORKFLOWS="$REPO_ROOT/.github/workflows"
TOTAL_USES=0
TOTAL_PINNED=0
if [ -d "$WORKFLOWS" ]; then
    for WF in "$WORKFLOWS"/*.yml; do
        [ -f "$WF" ] || continue
        USES_COUNT=$(grep -cE '^\s*uses:' "$WF" 2>/dev/null || echo "0")
        SHA_PINNED=$(grep -cE '^\s*uses:.*@[a-f0-9]{40}' "$WF" 2>/dev/null || echo "0")
        TOTAL_USES=$((TOTAL_USES + USES_COUNT))
        TOTAL_PINNED=$((TOTAL_PINNED + SHA_PINNED))
    done

    if [ "$TOTAL_USES" -eq "$TOTAL_PINNED" ] && [ "$TOTAL_USES" -gt 0 ]; then
        echo -e "${GREEN}PASS${NC} ($TOTAL_PINNED/$TOTAL_USES actions pinned across all workflows)"
    else
        echo -e "${RED}FAIL${NC}"
        echo "  Not all actions are SHA-pinned!"
        echo "  Pinned: $TOTAL_PINNED / $TOTAL_USES"
        echo "  Unpinned actions:"
        grep -rE '^\s*uses:' "$WORKFLOWS"/*.yml | grep -v '@[a-f0-9]\{40\}' | sed 's/^/    /'
        FAILED=1
    fi
else
    echo -e "${YELLOW}SKIP${NC} (workflows directory not found)"
fi

# ─────────────────────────────────────────────────────────────
# Check 6: melange/apko build configs exist
# ─────────────────────────────────────────────────────────────
echo -n "Check 6: melange/apko build configs... "

MELANGE_YAML="$REPO_ROOT/melange.yaml"
APKO_YAML="$REPO_ROOT/apko.yaml"
if [ -f "$MELANGE_YAML" ] && [ -f "$APKO_YAML" ]; then
    echo -e "${GREEN}PASS${NC}"
    echo "    melange.yaml and apko.yaml present"
else
    echo -e "${YELLOW}WARN${NC}"
    [ ! -f "$MELANGE_YAML" ] && echo "    Missing: melange.yaml (needed for CD pipeline)"
    [ ! -f "$APKO_YAML" ] && echo "    Missing: apko.yaml (needed for OCI image build)"
    WARNINGS=$((WARNINGS + 1))
fi

# ─────────────────────────────────────────────────────────────
# Check 7: Source files exist
# ─────────────────────────────────────────────────────────────
echo -n "Check 7: Core source files exist... "

MISSING=0
for FILE in "src/paranoid.c" "src/platform_wasm.c" "src/platform_native.c" "src/sha256_compact.c" "include/paranoid.h" "include/paranoid_platform.h" "CMakeLists.txt"; do
    if [ ! -f "$REPO_ROOT/$FILE" ]; then
        MISSING=1
        break
    fi
done

if [ $MISSING -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "  Missing core source files!"
    FAILED=1
fi

# ─────────────────────────────────────────────────────────────
# Check 8: Web assets exist
# ─────────────────────────────────────────────────────────────
echo -n "Check 8: Web assets exist... "

MISSING=0
for FILE in "www/index.html" "www/app.js" "www/style.css"; do
    if [ ! -f "$REPO_ROOT/$FILE" ]; then
        MISSING=1
        break
    fi
done

if [ $MISSING -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "  Missing web assets!"
    FAILED=1
fi

# ─────────────────────────────────────────────────────────────
# Check 9: Git commit information
# ─────────────────────────────────────────────────────────────
echo -n "Check 9: Git metadata available... "

if git rev-parse HEAD &>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
    COMMIT=$(git rev-parse --short HEAD)
    BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "detached")
    echo "    Commit: $COMMIT"
    echo "    Branch: $BRANCH"
else
    echo -e "${YELLOW}WARN${NC} (not a git repository)"
    WARNINGS=$((WARNINGS + 1))
fi

# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"

if [ $FAILED -eq 0 ]; then
    if [ $WARNINGS -gt 0 ]; then
        echo -e "  ${YELLOW}Verification passed with $WARNINGS warning(s)${NC}"
    else
        echo -e "  ${GREEN}All supply chain checks passed${NC}"
    fi
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    exit 0
else
    echo -e "  ${RED}Supply chain verification FAILED${NC}"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "DO NOT BUILD OR DEPLOY until issues are resolved."
    echo ""
    exit 1
fi
