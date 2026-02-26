#!/usr/bin/env bash
# ================================================================
# cleanup_legacy_build.sh -- Remove files replaced by Wolfi migration
#
# This script lists (and optionally deletes) files that have been
# superseded by the melange.yaml + apko.yaml + CMakeLists.txt
# build system.
#
# Usage:
#   ./scripts/cleanup_legacy_build.sh           # Dry run (list only)
#   ./scripts/cleanup_legacy_build.sh --delete  # Actually delete
#
# Items A5-A10 from the migration plan.
# ================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Files to remove and the reason each is obsolete
declare -A LEGACY_FILES=(
    ["Dockerfile"]="Replaced by melange.yaml + apko.yaml"
    ["Makefile"]="Replaced by CMakeLists.txt"
    ["zig-linux-x86_64-0.13.0.tar.xz"]="Replaced by 'apk add zig' in melange environment"
    ["scripts/build_openssl_wasm.sh"]="No longer needed -- WASM build uses platform_wasm.c + sha256_compact.c, not OpenSSL"
    ["src/wasm_entry.c"]="OpenSSL WASI stub, no longer needed -- platform_wasm.c provides the entry point"
    ["docker-compose.yml"]="Replaced by apko.yaml"
)

DRY_RUN=true
if [[ "${1:-}" == "--delete" ]]; then
    DRY_RUN=false
fi

echo ""
echo "================================================================"
echo "  Legacy Build File Cleanup"
echo "================================================================"
echo ""

if $DRY_RUN; then
    echo "  Mode: DRY RUN (pass --delete to actually remove files)"
else
    echo "  Mode: DELETE"
fi
echo ""

FOUND=0
MISSING=0

for file in "${!LEGACY_FILES[@]}"; do
    reason="${LEGACY_FILES[$file]}"
    filepath="${REPO_ROOT}/${file}"

    if [[ -e "$filepath" ]]; then
        FOUND=$((FOUND + 1))
        if $DRY_RUN; then
            printf "  [FOUND]   %-45s %s\n" "$file" "$reason"
        else
            rm -f "$filepath"
            printf "  [DELETED] %-45s %s\n" "$file" "$reason"
        fi
    else
        MISSING=$((MISSING + 1))
        printf "  [ABSENT]  %-45s (already removed)\n" "$file"
    fi
done

echo ""
echo "  Found: ${FOUND}  |  Already absent: ${MISSING}"
echo ""

if $DRY_RUN && [[ $FOUND -gt 0 ]]; then
    echo "  To delete these files, run:"
    echo "    ./scripts/cleanup_legacy_build.sh --delete"
    echo ""
fi

echo "================================================================"
echo ""
