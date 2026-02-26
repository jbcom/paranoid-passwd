#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# build_openssl_wasm.sh — Build OpenSSL from official source for WASM/WASI
# ═══════════════════════════════════════════════════════════════════════════════
#
# Implements the build approach from jedisct1/openssl-wasm but against the
# OFFICIAL OpenSSL source at a pinned tag — no precompiled binaries.
#
# Full provenance chain:
#   Official OpenSSL source → Our patches → Zig compiler → libcrypto.a (WASM)
#
# Usage:
#   ./scripts/build_openssl_wasm.sh <openssl-src-dir> <output-dir> [patches-dir]
#
# Arguments:
#   openssl-src-dir  Path to cloned OpenSSL source
#   output-dir       Where to place lib/libcrypto.a and include/openssl/
#   patches-dir      Directory containing *.patch files (default: ./patches)
#
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Resolve all paths to absolute BEFORE any cd
OPENSSL_SRC="$(cd "${1:?Usage: build_openssl_wasm.sh <openssl-src-dir> <output-dir> [patches-dir]}" && pwd)"
OUTPUT_DIR="$(mkdir -p "${2:?Usage: build_openssl_wasm.sh <openssl-src-dir> <output-dir> [patches-dir]}" && cd "$2" && pwd)"
PATCHES_DIR="$(cd "${3:-$(dirname "${BASH_SOURCE[0]}")/../patches}" && pwd)"

NPROC=$(getconf NPROCESSORS_ONLN 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Building OpenSSL for WASM/WASI from source"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Source:   $OPENSSL_SRC"
echo "  Output:   $OUTPUT_DIR"
echo "  Patches:  $PATCHES_DIR"
echo "  Jobs:     $NPROC"
echo ""

# ─────────────────────────────────────────────────────────────
# Verify prerequisites
# ─────────────────────────────────────────────────────────────

command -v zig >/dev/null 2>&1 || { echo "ERROR: zig not found in PATH"; exit 1; }
command -v perl >/dev/null 2>&1 || { echo "ERROR: perl not found (required by OpenSSL Configure)"; exit 1; }
command -v make >/dev/null 2>&1 || { echo "ERROR: make not found"; exit 1; }

echo "Zig version: $(zig version)"
echo ""

# ─────────────────────────────────────────────────────────────
# Apply patches
# ─────────────────────────────────────────────────────────────

cd "$OPENSSL_SRC"

echo "Applying WASI patches..."
for patchfile in "$PATCHES_DIR"/*.patch; do
    [ -f "$patchfile" ] || continue
    BASENAME=$(basename "$patchfile")
    echo "  Applying $BASENAME..."
    # --forward: skip already-applied patches
    # --fuzz=3: handle minor context differences across OpenSSL versions
    patch -p1 --forward --fuzz=3 < "$patchfile" || {
        # Check if already applied
        if patch -p1 --reverse --dry-run < "$patchfile" >/dev/null 2>&1; then
            echo "    (already applied, skipping)"
        else
            echo "ERROR: Failed to apply $BASENAME"
            exit 1
        fi
    }
done
echo ""

# ─────────────────────────────────────────────────────────────
# Configure OpenSSL for WASM/WASI
# ─────────────────────────────────────────────────────────────

echo "Configuring OpenSSL for wasm32-wasi..."
echo ""

env \
    CROSS_COMPILE="" \
    AR="zig ar" \
    RANLIB="zig ranlib" \
    CC="zig cc --target=wasm32-wasi" \
    CFLAGS="-O2 -Qunused-arguments -Wno-shift-count-overflow -fdata-sections -ffunction-sections" \
    CPPFLAGS="-D_BSD_SOURCE -D_WASI_EMULATED_GETPID -Dgetuid=getpagesize -Dgeteuid=getpagesize -Dgetgid=getpagesize -Dgetegid=getpagesize" \
    CXXFLAGS="-Werror -Qunused-arguments -Wno-shift-count-overflow" \
    LDFLAGS="-s -lwasi-emulated-getpid" \
    ./Configure \
    --banner="paranoid-passwd wasm32-wasi (from official OpenSSL source)" \
    no-asm \
    no-async \
    no-egd \
    no-ktls \
    no-module \
    no-posix-io \
    no-secure-memory \
    no-shared \
    no-sock \
    no-stdio \
    no-thread-pool \
    no-threads \
    no-ui-console \
    no-weak-ssl-ciphers \
    wasm32-wasi || { echo "ERROR: OpenSSL Configure failed"; exit 1; }

echo ""

# ─────────────────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────────────────

echo "Building OpenSSL (this may take several minutes)..."
make -j"$NPROC" 2>&1 || { echo "ERROR: OpenSSL make failed"; exit 1; }

echo ""

# ─────────────────────────────────────────────────────────────
# Collect outputs
# ─────────────────────────────────────────────────────────────

echo "Collecting build artifacts..."

mkdir -p "$OUTPUT_DIR/lib"
mkdir -p "$OUTPUT_DIR/include"

# Copy static libraries
cp libcrypto.a "$OUTPUT_DIR/lib/"
[ -f libssl.a ] && cp libssl.a "$OUTPUT_DIR/lib/" || true

# Copy headers (includes generated configuration headers)
cp -r include/openssl "$OUTPUT_DIR/include/"

# Record provenance
echo "Recording build provenance..."
OPENSSL_VERSION=$(./configdata.pm --dump 2>/dev/null | grep 'version =>' | head -1 || echo "unknown")
cat > "$OUTPUT_DIR/BUILD_PROVENANCE.txt" << EOF
OpenSSL WASM Build Provenance
═════════════════════════════
Source:     Official OpenSSL (https://github.com/openssl/openssl)
Commit:     $(git rev-parse HEAD 2>/dev/null || echo "unknown")
Tag:        $(git describe --tags 2>/dev/null || echo "unknown")
Compiler:   zig cc --target=wasm32-wasi ($(zig version))
Built:      $(date -u +%Y-%m-%dT%H:%M:%SZ)
Patches:    $(ls "$PATCHES_DIR"/*.patch 2>/dev/null | xargs -n1 basename | tr '\n' ' ')
Configure:  no-asm no-async no-egd no-ktls no-module no-posix-io no-secure-memory no-shared no-sock no-stdio no-thread-pool no-threads no-ui-console no-weak-ssl-ciphers wasm32-wasi
EOF

# Print summary
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  OpenSSL WASM build complete"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  libcrypto.a: $(du -h "$OUTPUT_DIR/lib/libcrypto.a" | cut -f1)"
[ -f "$OUTPUT_DIR/lib/libssl.a" ] && echo "  libssl.a:    $(du -h "$OUTPUT_DIR/lib/libssl.a" | cut -f1)"
echo "  Headers:     $OUTPUT_DIR/include/openssl/"
echo "  Provenance:  $OUTPUT_DIR/BUILD_PROVENANCE.txt"
echo ""
