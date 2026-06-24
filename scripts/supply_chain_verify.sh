#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
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

if [ -f "$REPO_ROOT/.gitattributes" ] \
  && rg -q '^vendor/\*\*[[:space:]]+-text[[:space:]]*(#.*)?$' "$REPO_ROOT/.gitattributes"; then
  pass "vendored Cargo sources are protected from checkout line-ending rewrites"
else
  fail "vendored Cargo sources are not protected from checkout line-ending rewrites"
fi

dependabot_config="$REPO_ROOT/.github/dependabot.yml"
if [ -f "$dependabot_config" ] \
  && rg -q 'package-ecosystem:[[:space:]]+github-actions' "$dependabot_config" \
  && ! rg -q 'package-ecosystem:[[:space:]]+cargo' "$dependabot_config"; then
  pass "Dependabot is scoped to updater-supported ecosystems while Cargo remains maintainer-vendored"
else
  fail "Dependabot must not claim Cargo automation until vendored Cargo updates are supported"
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

if rg -q -- '--locked --frozen --offline' "$REPO_ROOT/Makefile" \
  && { rg -q -- '--locked --frozen --offline' "$REPO_ROOT/.github/workflows/ci.yml" \
    || rg -q 'make ci' "$REPO_ROOT/.github/workflows/ci.yml"; }; then
  pass "CI reaches Makefile targets that use locked/frozen/offline Cargo commands"
else
  fail "locked/frozen/offline Cargo flags missing from Makefile, or CI no longer reaches the Makefile gate"
fi

builder="$REPO_ROOT/.github/actions/builder/Dockerfile"
if [ -f "$builder" ] \
  && rg -q '^# syntax=docker/dockerfile:1\.' "$builder" \
  && rg -q '^FROM cgr\.dev/chainguard/wolfi-base@sha256:' "$builder" \
  && rg -q 'RUST_APK_PACKAGE=rust-1\.95' "$builder" \
  && rg -q 'RUST_APK_VERSION=1\.95\.0-r0' "$builder" \
  && rg -q -- '--mount=type=cache,target=/var/cache/apk' "$builder" \
  && rg -q 'apk add' "$builder" \
  && rg -q 'build-base' "$builder" \
  && rg -q 'fontconfig-dev' "$builder" \
  && rg -q 'gh' "$builder" \
  && rg -q 'openssl-dev' "$builder" \
  && rg -q 'dbus-dev' "$builder" \
  && rg -q 'libxcursor-dev' "$builder" \
  && rg -q 'libxi-dev' "$builder" \
  && rg -q 'imagemagick-7' "$builder" \
  && rg -q 'xvfb-run' "$builder" \
  && rg -q 'ripgrep' "$builder" \
  && rg -q 'semgrep' "$builder" \
  && rg -q 'osv-scanner' "$builder" \
  && rg -q 'syft' "$builder" \
  && rg -q 'trivy' "$builder" \
  && rg -q 'py3-pip' "$builder" \
  && rg -q 'python3' "$builder" \
  && rg -q 'command -v gh' "$builder" \
  && rg -q 'cargo fmt --version' "$builder" \
  && rg -q 'cargo clippy --version' "$builder" \
  && rg -q 'rustc --version | grep -F "1\.95\.0"' "$builder" \
  && rg -q 'SPHINX_RUSTDOCGEN_VERSION=1\.1\.0' "$builder" \
  && rg -q 'cargo install --locked --root /usr/local' "$builder" \
  && rg -q 'sphinx-rustdocgen@' "$builder" \
  && rg -q 'tox==' "$builder" \
  && ! rg -q 'apt-get|DEBIAN_FRONTEND|rust:1\.95\.0-slim-bookworm' "$builder"; then
  pass "builder image is Wolfi-based, digest-pinned, and contains the expected Rust/OpenSSL/docs/scanner toolchain"
else
  fail "builder image is not Wolfi-pinned or is missing required Rust/OpenSSL/docs/scanner packages"
fi

ci_workflow="$REPO_ROOT/.github/workflows/ci.yml"
if [ -f "$ci_workflow" ] \
  && rg -q 'make ci' "$ci_workflow" \
  && rg -q 'uses: \./\.github/actions/builder' "$ci_workflow"; then
  pass "remote Rust CI invokes the full local make ci gate inside the repository builder"
else
  fail "remote Rust CI no longer invokes the full local make ci gate inside the repository builder"
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
  && rg -q 'uses: \./\.github/actions/builder' "$release_workflow" \
  && ! rg -q 'apt-get|DEBIAN_FRONTEND' "$release_workflow" \
  && ! rg -q '\|\| true' "$release_workflow"; then
  pass "release workflow uses repo-owned packaging/validation scripts inside the Wolfi builder and fails loud"
else
  fail "release workflow is not fully scripted in-repo, has drifted from the Wolfi builder, or still swallows errors"
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

if [ -f "$REPO_ROOT/scripts/verify_published_release.sh" ] \
  && rg -q '^verify-published-release:' "$REPO_ROOT/Makefile"; then
  pass "published release verification is available from the repo"
else
  fail "published release verification is missing"
fi

if rg -q 'docs-linkcheck' "$REPO_ROOT/tox.ini" \
  && rg -q 'docs-linkcheck' "$REPO_ROOT/.github/workflows/ci.yml"; then
  pass "docs link validation is wired into tox and CI"
else
  fail "docs link validation is missing from tox or CI"
fi

if [ -f "$REPO_ROOT/scripts/verify_branch_protection.sh" ] \
  && rg -q '^verify-branch-protection:' "$REPO_ROOT/Makefile"; then
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    if bash "$REPO_ROOT/scripts/verify_branch_protection.sh" >/dev/null; then
      pass "branch protection matches the Rust-native required checks"
    else
      fail "branch protection does not match the Rust-native required checks"
    fi
  else
    pass "branch protection verification script exists (live check skipped: gh auth unavailable)"
  fi
else
  fail "branch protection verification is missing"
fi

if [ "$failed" -ne 0 ]; then
  echo
  echo -e "${RED}Supply chain verification failed${NC}"
  exit 1
fi

echo
echo -e "${GREEN}All supply chain checks passed${NC}"
