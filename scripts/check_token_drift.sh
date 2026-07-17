#!/usr/bin/env bash
# scripts/check_token_drift.sh — P8.5 (d) token-drift regression gate.
#
# docs/design/system.md's "consumption rule" (§0) says a surface never
# hard-codes a hex color, a pixel/rem size, or a font weight of its own — it
# reads the named token from one of the three canonical modules:
#
#   - crates/paranoid-cli/src/theme.rs   (ratatui CLI/TUI)
#   - crates/paranoid-gui/ui/paranoid-tokens.slint  (Slint GUI)
#   - docs/_static/custom.css            (Sphinx docs/download site)
#
# system.md §7 documents the drift this rule exists to prevent: three
# surfaces slowly diverging to three different palettes. This script fails
# the build if a raw hex color literal reappears in any Rust or Slint source
# file OUTSIDE those three canonical modules, so the drift cannot recur
# silently (P8.5 acceptance criterion (d)).
#
# Scope: Rust (`crates/**/*.rs`) and Slint (`crates/**/*.slint`) sources
# only — not docs/markdown (which cites hex values in prose tables by
# design, e.g. system.md itself) and not `vendor/` (third-party code this
# repo does not own).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Canonical token modules — the only files a raw hex color literal may
# appear in (system.md §0 "consumption rule", §7 "drift to reconcile").
ALLOWED_FILES=(
  "crates/paranoid-cli/src/theme.rs"
  "crates/paranoid-gui/ui/paranoid-tokens.slint"
)

# Hex color literal: '#' followed by 3, 4, 6, or 8 hex digits, not preceded
# by an alphanumeric (so it doesn't match inside a longer hex-like token),
# scoped to Rust and Slint source under crates/.
HEX_PATTERN='#([0-9a-fA-F]{3}\b|[0-9a-fA-F]{4}\b|[0-9a-fA-F]{6}\b|[0-9a-fA-F]{8}\b)'

failed=0

# Build the search file list: every tracked .rs/.slint file under crates/,
# minus the allowlist, using git ls-files so build artifacts and vendor
# code are never scanned.
mapfile -t candidate_files < <(git ls-files 'crates/**/*.rs' 'crates/**/*.slint')

for file in "${candidate_files[@]}"; do
  skip=0
  for allowed in "${ALLOWED_FILES[@]}"; do
    if [[ "${file}" == "${allowed}" ]]; then
      skip=1
      break
    fi
  done
  if [[ "${skip}" -eq 1 ]]; then
    continue
  fi
  if [[ ! -f "${file}" ]]; then
    continue
  fi
  if matches="$(grep -nE "${HEX_PATTERN}" "${file}" 2>/dev/null)"; then
    printf "%bFAIL%b %s: raw hex color literal outside the token modules\n" "${RED}" "${NC}" "${file}"
    printf '%s\n' "${matches}" | sed 's/^/    /'
    failed=1
  fi
done

# docs/_static/custom.css is the third canonical module (Sphinx docs site);
# it is intentionally exempt above by not being under crates/. Nothing else
# in docs/_static may define its own raw hex colors outside the :root
# custom-property block, since every rule in the file should consume
# var(--pp-*) instead (system.md's consumption rule extends to the CSS
# surface, not just Rust/Slint).
CSS_ALLOWED="docs/_static/custom.css"
mapfile -t css_candidate_files < <(git ls-files 'docs/_static/*.css')
for file in "${css_candidate_files[@]}"; do
  if [[ "${file}" == "${CSS_ALLOWED}" ]]; then
    continue
  fi
  if [[ ! -f "${file}" ]]; then
    continue
  fi
  if matches="$(grep -nE "${HEX_PATTERN}" "${file}" 2>/dev/null)"; then
    printf "%bFAIL%b %s: raw hex color literal outside custom.css's :root tokens\n" "${RED}" "${NC}" "${file}"
    printf '%s\n' "${matches}" | sed 's/^/    /'
    failed=1
  fi
done

if [[ "${failed}" -ne 0 ]]; then
  echo "" >&2
  echo "Token drift detected: a raw color value was reintroduced outside" >&2
  echo "the canonical token modules. Add the value to docs/design/system.md" >&2
  echo "as a named token, define it once in theme.rs / paranoid-tokens.slint" >&2
  echo "/ custom.css, and reference the token from the call site instead." >&2
  exit 1
fi

printf "%bPASS%b no raw hex color literals outside the canonical token modules\n" "${GREEN}" "${NC}"
