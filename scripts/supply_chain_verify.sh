#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

failed=0

pass() {
  printf "%bPASS%b %s\n" "$GREEN" "$NC" "$1"
}

fail() {
  printf "%bFAIL%b %s\n" "$RED" "$NC" "$1"
  failed=1
}

echo
echo "Rust-Native Supply Chain Verification"
echo

if [ -f "$REPO_ROOT/.cargo/config.toml" ] \
  && rg -q 'replace-with = "vendored-sources"' "$REPO_ROOT/.cargo/config.toml" \
  && rg -q 'directory = "vendor"' "$REPO_ROOT/.cargo/config.toml"; then
  pass "Cargo is pinned to vendored sources"
else
  fail "Cargo vendoring configuration is incomplete"
fi

if [ -d "$REPO_ROOT/vendor" ] && [ -f "$REPO_ROOT/Cargo.lock" ]; then
  pass "vendor tree and Cargo.lock are present"
else
  fail "vendor tree or Cargo.lock is missing"
fi

if (cd "$REPO_ROOT" && cargo metadata --locked --frozen --offline --format-version 1 >/dev/null); then
  pass "Cargo metadata resolves fully offline"
else
  fail "offline Cargo resolution failed"
fi

workflow_dir="$REPO_ROOT/.github/workflows"
if [ -d "$workflow_dir" ]; then
  external_uses=$(grep -rE '^[[:space:]]*uses:' "$workflow_dir"/*.yml | grep -v 'uses:[[:space:]]\+\./' || true)
  if [ -n "$external_uses" ] && ! printf '%s\n' "$external_uses" | grep -vE '@[a-f0-9]{40}' >/dev/null; then
    pass "external GitHub Actions are SHA-pinned"
  else
    fail "one or more external GitHub Actions are not SHA-pinned"
  fi
else
  fail "workflow directory missing"
fi

if rg -q -- '--locked --frozen --offline' "$REPO_ROOT/.github/workflows/ci.yml" \
  && rg -q -- '--locked --frozen --offline' "$REPO_ROOT/Makefile"; then
  pass "CI and make targets use locked/frozen/offline Cargo commands"
else
  fail "locked/frozen/offline Cargo flags missing from CI or Makefile"
fi

builder="$REPO_ROOT/.github/actions/builder/Dockerfile"
if [ -f "$builder" ] \
  && rg -q '^FROM .+@sha256:' "$builder" \
  && rg -q 'openssl-dev' "$builder" \
  && rg -q 'pkgconf' "$builder" \
  && rg -q 'python3' "$builder" \
  && rg -q 'RUST_APK_PACKAGE=rust-1\.88' "$builder" \
  && rg -q 'RUST_APK_VERSION=1\.88\.0-r0' "$builder" \
  && rg -q 'tox==' "$builder"; then
  pass "builder image is digest-pinned and contains the expected Rust/OpenSSL/docs toolchain"
else
  fail "builder image is not pinned or is missing required Rust/OpenSSL/docs packages"
fi

release_workflow="$REPO_ROOT/.github/workflows/release.yml"
if [ -f "$release_workflow" ] \
  && rg -q 'brew install openssl@3 pkg-config' "$release_workflow" \
  && rg -q 'vcpkg\.exe.*openssl:x64-windows-static-md' "$release_workflow"; then
  pass "release workflow installs OpenSSL prerequisites per platform"
else
  fail "release workflow is missing one or more platform OpenSSL setup steps"
fi

if [ -f "$release_workflow" ] \
  && rg -q 'scripts/build_release_artifact\.sh' "$release_workflow" \
  && rg -q 'scripts/smoke_test_release_artifact\.sh' "$release_workflow" \
  && rg -q 'scripts/release_validate\.sh' "$release_workflow" \
  && ! rg -q '\|\| true' "$release_workflow"; then
  pass "release workflow uses repo-owned packaging/validation scripts and fails loud"
else
  fail "release workflow is not fully scripted in-repo or still swallows errors"
fi

if rg -q '^release-emulate:' "$REPO_ROOT/Makefile" \
  && rg -q '^release-validate:' "$REPO_ROOT/Makefile"; then
  pass "Makefile exposes local release emulation and validation targets"
else
  fail "Makefile is missing local release emulation or validation targets"
fi

if [ -f "$REPO_ROOT/docs/public/install.sh" ] && [ -f "$REPO_ROOT/tox.ini" ]; then
  pass "docs/download surface and docs build config exist"
else
  fail "docs/download surface is incomplete"
fi

if [ "$failed" -ne 0 ]; then
  echo
  echo -e "${RED}Supply chain verification failed${NC}"
  exit 1
fi

echo
echo -e "${GREEN}All supply chain checks passed${NC}"
