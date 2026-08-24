#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Sourcey consumes docs/ as its content root. Keep this published copy byte-for-byte
# aligned with the contributor source of truth; validate-docs.sh enforces the same
# invariant in CI.
cp "$repo_root/CONTRIBUTING.md" "$repo_root/docs/contributing.md"
