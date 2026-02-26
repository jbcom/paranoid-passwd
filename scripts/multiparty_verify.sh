#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# multiparty_verify.sh — Multi-Party Build Verification
# ═══════════════════════════════════════════════════════════════════════════════
#
# Implements 3-of-5 threshold verification for reproducible builds.
# Collects and compares hashes from multiple independent builders.
#
# Usage:
#   # Builder submits their hash
#   ./scripts/multiparty_verify.sh submit <builder_name> <wasm_sha256>
#
#   # Check if threshold is met
#   ./scripts/multiparty_verify.sh check
#
#   # View all submissions
#   ./scripts/multiparty_verify.sh list
#
#   # Reset for new build
#   ./scripts/multiparty_verify.sh reset
#
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ATTESTATIONS_DIR="$REPO_ROOT/build/attestations"
THRESHOLD=3

# ─────────────────────────────────────────────────────────────
# Functions
# ─────────────────────────────────────────────────────────────

show_help() {
    echo "Multi-Party Build Verification"
    echo ""
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  submit <builder> <hash>  Submit a builder's WASM hash"
    echo "  check                    Check if threshold is met"
    echo "  list                     List all submissions"
    echo "  reset                    Clear all submissions"
    echo "  compute                  Compute local WASM hash"
    echo ""
    echo "Threshold: $THRESHOLD matching hashes required"
    echo ""
    echo "Example workflow:"
    echo "  1. Builder 1: make site && $0 compute"
    echo "  2. Builder 1: $0 submit builder1 <hash>"
    echo "  3. Builder 2: make site && $0 submit builder2 <hash>"
    echo "  4. Builder 3: make site && $0 submit builder3 <hash>"
    echo "  5. All: $0 check"
}

ensure_dir() {
    mkdir -p "$ATTESTATIONS_DIR"
}

submit_hash() {
    local BUILDER="$1"
    local HASH="$2"
    
    # Validate hash format (64 hex chars)
    if ! echo "$HASH" | grep -Eq '^[a-f0-9]{64}$'; then
        echo -e "${RED}ERROR: Invalid hash format${NC}"
        echo "Hash must be 64 lowercase hex characters"
        exit 1
    fi
    
    ensure_dir
    
    # Create attestation file
    local TIMESTAMP
    TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local ATTESTATION_FILE="$ATTESTATIONS_DIR/${BUILDER}.json"
    
    cat > "$ATTESTATION_FILE" << EOF
{
  "builder": "$BUILDER",
  "wasm_sha256": "$HASH",
  "timestamp": "$TIMESTAMP",
  "commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
}
EOF
    
    echo -e "${GREEN}✓${NC} Attestation recorded for $BUILDER"
    echo "  Hash: $HASH"
    echo "  Time: $TIMESTAMP"
    echo "  File: $ATTESTATION_FILE"
}

list_submissions() {
    ensure_dir
    
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Build Attestations"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    
    local COUNT=0
    shopt -s nullglob
    for FILE in "$ATTESTATIONS_DIR"/*.json; do
        if [ -f "$FILE" ]; then
            COUNT=$((COUNT + 1))
            BUILDER=$(jq -r '.builder' "$FILE")
            HASH=$(jq -r '.wasm_sha256' "$FILE")
            TIMESTAMP=$(jq -r '.timestamp' "$FILE")
            echo "Builder:   $BUILDER"
            echo "Hash:      ${HASH:0:16}...${HASH:48}"
            echo "Timestamp: $TIMESTAMP"
            echo ""
        fi
    done
    shopt -u nullglob

    if [ $COUNT -eq 0 ]; then
        echo "No attestations found."
        echo ""
        echo "Submit with: $0 submit <builder_name> <hash>"
    fi

    echo "═══════════════════════════════════════════════════════════"
    echo "  Total: $COUNT attestations (threshold: $THRESHOLD)"
    echo "═══════════════════════════════════════════════════════════"
}

check_threshold() {
    ensure_dir
    
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Threshold Verification ($THRESHOLD-of-5 required)"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    
    # Collect all hashes
    local -A HASH_COUNTS
    local TOTAL=0

    shopt -s nullglob
    for FILE in "$ATTESTATIONS_DIR"/*.json; do
        if [ -f "$FILE" ]; then
            HASH=$(jq -r '.wasm_sha256' "$FILE")
            BUILDER=$(jq -r '.builder' "$FILE")

            if [ -z "${HASH_COUNTS[$HASH]+x}" ]; then
                HASH_COUNTS[$HASH]="$BUILDER"
            else
                HASH_COUNTS[$HASH]="${HASH_COUNTS[$HASH]}, $BUILDER"
            fi
            TOTAL=$((TOTAL + 1))
        fi
    done
    shopt -u nullglob
    
    if [ $TOTAL -eq 0 ]; then
        echo -e "${YELLOW}No attestations found${NC}"
        echo ""
        exit 1
    fi
    
    # Check for consensus
    local MAX_MATCH=0
    local CONSENSUS_HASH=""
    local CONSENSUS_BUILDERS=""
    
    for HASH in "${!HASH_COUNTS[@]}"; do
        # Count comma-separated builders
        BUILDERS="${HASH_COUNTS[$HASH]}"
        COUNT=$(echo "$BUILDERS" | tr ',' '\n' | wc -l)
        
        echo "Hash: ${HASH:0:16}...${HASH:48}"
        echo "  Builders: $BUILDERS"
        echo "  Count: $COUNT"
        echo ""
        
        if [ "$COUNT" -gt "$MAX_MATCH" ]; then
            MAX_MATCH=$COUNT
            CONSENSUS_HASH=$HASH
            CONSENSUS_BUILDERS=$BUILDERS
        fi
    done
    
    echo "═══════════════════════════════════════════════════════════"
    
    if [ "$MAX_MATCH" -ge "$THRESHOLD" ]; then
        echo -e "  ${GREEN}✓ THRESHOLD MET ($MAX_MATCH/$THRESHOLD)${NC}"
        echo ""
        echo "  Consensus hash: $CONSENSUS_HASH"
        echo "  Verified by: $CONSENSUS_BUILDERS"
        echo ""
        echo "  BUILD IS VERIFIED — safe to deploy"
        echo "═══════════════════════════════════════════════════════════"
        exit 0
    else
        echo -e "  ${YELLOW}⚠ THRESHOLD NOT MET ($MAX_MATCH/$THRESHOLD)${NC}"
        echo ""
        echo "  Need $((THRESHOLD - MAX_MATCH)) more matching attestations"
        echo ""
        if [ "${#HASH_COUNTS[@]}" -gt 1 ]; then
            echo -e "  ${RED}WARNING: Multiple different hashes detected!${NC}"
            echo "  This could indicate:"
            echo "    - Non-reproducible build"
            echo "    - Compromised build environment"
            echo "    - Different source versions"
            echo ""
            echo "  INVESTIGATE before proceeding!"
        fi
        echo "═══════════════════════════════════════════════════════════"
        exit 1
    fi
}

reset_attestations() {
    ensure_dir
    
    rm -f "$ATTESTATIONS_DIR"/*.json 2>/dev/null || true
    echo -e "${GREEN}✓${NC} Attestations cleared"
}

compute_hash() {
    local WASM="$REPO_ROOT/build/paranoid.wasm"
    
    if [ ! -f "$WASM" ]; then
        echo -e "${RED}ERROR: WASM not found at $WASM${NC}"
        echo "Run 'make site' first"
        exit 1
    fi
    
    if command -v sha256sum &> /dev/null; then
        HASH=$(sha256sum "$WASM" | cut -d' ' -f1)
    elif command -v shasum &> /dev/null; then
        HASH=$(shasum -a 256 "$WASM" | cut -d' ' -f1)
    else
        echo -e "${RED}ERROR: No sha256sum or shasum available${NC}"
        exit 1
    fi
    
    echo ""
    echo "WASM SHA-256: $HASH"
    echo ""
    echo "Submit with:"
    echo "  $0 submit <your_builder_name> $HASH"
}

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

if [ $# -lt 1 ]; then
    show_help
    exit 1
fi

COMMAND="$1"
shift

case "$COMMAND" in
    submit)
        if [ $# -lt 2 ]; then
            echo "Usage: $0 submit <builder_name> <wasm_sha256>"
            exit 1
        fi
        submit_hash "$1" "$2"
        ;;
    check)
        check_threshold
        ;;
    list)
        list_submissions
        ;;
    reset)
        reset_attestations
        ;;
    compute)
        compute_hash
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac
