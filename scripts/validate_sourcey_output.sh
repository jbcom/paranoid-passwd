#!/usr/bin/env bash

# Validate the Sourcey artifact, not just its input Markdown. This stays local,
# deterministic, and dependency-free so the untrusted PR docs job can run it
# without credentials or a deployment-capable token.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="$repo_root/docs/dist"

required=(
  "$output/index.html"
  "$output/sourcey.css"
  "$output/sourcey.js"
  "$output/search-index.json"
  "$output/sitemap.xml"
  "$output/llms.txt"
  "$output/llms-full.txt"
  "$output/install.sh"
  "$output/assets/local-vault-hero.png"
)

for file in "${required[@]}"; do
  test -s "$file"
done

if rg -n '\{toctree\}|\{rust:' "$output" --glob '*.html'; then
  echo "Sourcey output contains unrendered legacy Sphinx directives." >&2
  exit 1
fi

if ! rg -q 'paranoid-passwd' "$output/llms.txt" \
  || ! rg -q 'Rust-native password manager' "$output/llms-full.txt"; then
  echo "Sourcey context exports are missing the project identity." >&2
  exit 1
fi

# The README hero must be reachable from the emitted home page and copied to
# the static artifact instead of remaining only in the source tree.
rg -q 'assets/local-vault-hero.png' "$output/index.html"

echo "Sourcey output validation passed."
