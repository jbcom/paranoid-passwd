#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required=(
  "$REPO_ROOT/docs/conf.py"
  "$REPO_ROOT/docs/index.md"
  "$REPO_ROOT/docs/getting-started/index.md"
  "$REPO_ROOT/docs/guides/tui.md"
  "$REPO_ROOT/docs/reference/index.md"
  "$REPO_ROOT/docs/reference/architecture.md"
  "$REPO_ROOT/docs/reference/testing.md"
  "$REPO_ROOT/docs/reference/supply-chain.md"
  "$REPO_ROOT/docs/reference/release-verification.md"
  "$REPO_ROOT/docs/api/index.md"
  "$REPO_ROOT/docs/public/install.sh"
)

for file in "${required[@]}"; do
  test -f "$file"
done

grep -q "paranoid-passwd-<version>-linux-amd64.tar.gz" "$REPO_ROOT/docs/getting-started/index.md"
grep -q "crates/paranoid_core/lib" "$REPO_ROOT/docs/api/index.md"
grep -q "install.sh" "$REPO_ROOT/docs/index.md"
