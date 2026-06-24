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

contains_regex() {
  grep -qE -- "$1" "$2"
}

contains_fixed() {
  grep -qF -- "$1" "$2"
}

require_manifest_var() {
  local name="$1"
  if [ -n "${!name:-}" ]; then
    return 0
  fi
  fail "scanner toolchain manifest is missing $name"
  return 1
}

echo
echo "Rust-Native Supply Chain Verification"
echo

scanner_manifest="$REPO_ROOT/supply-chain/scanner-toolchain.env"
if [ -f "$scanner_manifest" ]; then
  # shellcheck source=/dev/null
  . "$scanner_manifest"
else
  fail "scanner toolchain manifest is missing"
fi

SCANNER_TOOLCHAIN_SCHEMA_VERSION="${SCANNER_TOOLCHAIN_SCHEMA_VERSION:-}"
BUILDER_SCANNER_TOOLS="${BUILDER_SCANNER_TOOLS:-}"
SEMGREP_APK_PACKAGE="${SEMGREP_APK_PACKAGE:-}"
SEMGREP_APK_VERSION="${SEMGREP_APK_VERSION:-}"
OSV_SCANNER_APK_PACKAGE="${OSV_SCANNER_APK_PACKAGE:-}"
OSV_SCANNER_APK_VERSION="${OSV_SCANNER_APK_VERSION:-}"
SYFT_APK_PACKAGE="${SYFT_APK_PACKAGE:-}"
SYFT_APK_VERSION="${SYFT_APK_VERSION:-}"
TRIVY_APK_PACKAGE="${TRIVY_APK_PACKAGE:-}"
TRIVY_APK_VERSION="${TRIVY_APK_VERSION:-}"
CODEQL_ACTION_VERSION="${CODEQL_ACTION_VERSION:-}"
CODEQL_ACTION_SHA="${CODEQL_ACTION_SHA:-}"
HOST_LOCAL_SCANNER_TOOLS="${HOST_LOCAL_SCANNER_TOOLS:-}"

if require_manifest_var SCANNER_TOOLCHAIN_SCHEMA_VERSION \
  && require_manifest_var BUILDER_SCANNER_TOOLS \
  && require_manifest_var SEMGREP_APK_PACKAGE \
  && require_manifest_var SEMGREP_APK_VERSION \
  && require_manifest_var OSV_SCANNER_APK_PACKAGE \
  && require_manifest_var OSV_SCANNER_APK_VERSION \
  && require_manifest_var SYFT_APK_PACKAGE \
  && require_manifest_var SYFT_APK_VERSION \
  && require_manifest_var TRIVY_APK_PACKAGE \
  && require_manifest_var TRIVY_APK_VERSION \
  && require_manifest_var CODEQL_ACTION_VERSION \
  && require_manifest_var CODEQL_ACTION_SHA \
  && require_manifest_var HOST_LOCAL_SCANNER_TOOLS; then
  pass "scanner toolchain manifest is present and complete"
else
  fail "scanner toolchain manifest is incomplete"
fi

if [ -f "$REPO_ROOT/.cargo/config.toml" ] \
  && contains_fixed 'replace-with = "vendored-sources"' "$REPO_ROOT/.cargo/config.toml" \
  && contains_fixed 'directory = "vendor"' "$REPO_ROOT/.cargo/config.toml"; then
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
  && contains_regex '^vendor/\*\*[[:space:]]+-text[[:space:]]*(#.*)?$' "$REPO_ROOT/.gitattributes"; then
  pass "vendored Cargo sources are protected from checkout line-ending rewrites"
else
  fail "vendored Cargo sources are not protected from checkout line-ending rewrites"
fi

dependabot_config="$REPO_ROOT/.github/dependabot.yml"
if [ -f "$dependabot_config" ] \
  && contains_regex 'package-ecosystem:[[:space:]]+github-actions' "$dependabot_config" \
  && ! contains_regex 'package-ecosystem:[[:space:]]+cargo' "$dependabot_config"; then
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
  external_uses=$(grep -rE '^[[:space:]]*uses:' "$workflow_dir"/*.yml | grep -vE 'uses:[[:space:]]+\./' || true)
  if [ -n "$external_uses" ] && ! printf '%s\n' "$external_uses" | grep -vE '@[a-f0-9]{40}' >/dev/null; then
    pass "external GitHub Actions are SHA-pinned"
  else
    fail "one or more external GitHub Actions are not SHA-pinned"
  fi
else
  fail "workflow directory missing"
fi

if contains_fixed '--locked --frozen --offline' "$REPO_ROOT/Makefile" \
  && { contains_fixed '--locked --frozen --offline' "$REPO_ROOT/.github/workflows/ci.yml" \
    || contains_fixed 'make ci' "$REPO_ROOT/.github/workflows/ci.yml"; }; then
  pass "CI reaches Makefile targets that use locked/frozen/offline Cargo commands"
else
  fail "locked/frozen/offline Cargo flags missing from Makefile, or CI no longer reaches the Makefile gate"
fi

builder="$REPO_ROOT/.github/actions/builder/Dockerfile"
if [ -f "$builder" ] \
  && contains_regex '^# syntax=docker/dockerfile:1\.' "$builder" \
  && contains_regex '^FROM cgr\.dev/chainguard/wolfi-base@sha256:' "$builder" \
  && contains_fixed 'RUST_APK_PACKAGE=rust-1.95' "$builder" \
  && contains_fixed 'RUST_APK_VERSION=1.95.0-r0' "$builder" \
  && contains_fixed "ARG SEMGREP_APK_VERSION=${SEMGREP_APK_VERSION}" "$builder" \
  && contains_fixed "ARG OSV_SCANNER_APK_VERSION=${OSV_SCANNER_APK_VERSION}" "$builder" \
  && contains_fixed "ARG SYFT_APK_VERSION=${SYFT_APK_VERSION}" "$builder" \
  && contains_fixed "ARG TRIVY_APK_VERSION=${TRIVY_APK_VERSION}" "$builder" \
  && contains_fixed '--mount=type=cache,target=/var/cache/apk' "$builder" \
  && contains_fixed 'apk add' "$builder" \
  && contains_fixed 'build-base' "$builder" \
  && contains_fixed 'fontconfig-dev' "$builder" \
  && contains_fixed 'gh' "$builder" \
  && contains_fixed 'openssl-dev' "$builder" \
  && contains_fixed 'dbus-dev' "$builder" \
  && contains_fixed 'libxcursor-dev' "$builder" \
  && contains_fixed 'libxi-dev' "$builder" \
  && contains_fixed 'imagemagick-7' "$builder" \
  && contains_fixed 'xvfb-run' "$builder" \
  && contains_fixed 'ripgrep' "$builder" \
  && contains_fixed "${SEMGREP_APK_PACKAGE}=\"\${SEMGREP_APK_VERSION}\"" "$builder" \
  && contains_fixed "${OSV_SCANNER_APK_PACKAGE}=\"\${OSV_SCANNER_APK_VERSION}\"" "$builder" \
  && contains_fixed "${SYFT_APK_PACKAGE}=\"\${SYFT_APK_VERSION}\"" "$builder" \
  && contains_fixed "${TRIVY_APK_PACKAGE}=\"\${TRIVY_APK_VERSION}\"" "$builder" \
  && contains_fixed 'py3-pip' "$builder" \
  && contains_fixed 'python3' "$builder" \
  && contains_fixed 'command -v gh' "$builder" \
  && contains_fixed 'cargo fmt --version' "$builder" \
  && contains_fixed 'cargo clippy --version' "$builder" \
  && contains_fixed 'rustc --version | grep -F "1.95.0"' "$builder" \
  && contains_fixed 'SPHINX_RUSTDOCGEN_VERSION=1.1.0' "$builder" \
  && contains_fixed 'cargo install --locked --root /usr/local' "$builder" \
  && contains_fixed 'sphinx-rustdocgen@' "$builder" \
  && contains_fixed 'tox==' "$builder" \
  && ! contains_regex 'apt-get|DEBIAN_FRONTEND|rust:1\.95\.0-slim-bookworm' "$builder"; then
  pass "builder image is Wolfi-based, digest-pinned, and contains the expected Rust/OpenSSL/docs/scanner toolchain"
else
  fail "builder image is not Wolfi-pinned or is missing required Rust/OpenSSL/docs/scanner packages"
fi

for builder_tool in $BUILDER_SCANNER_TOOLS; do
  if contains_fixed "command -v $builder_tool" "$builder"; then
    :
  else
    fail "builder scanner tool $builder_tool is listed in the manifest but missing from builder self-checks"
  fi
done

ci_workflow="$REPO_ROOT/.github/workflows/ci.yml"
if [ -f "$ci_workflow" ] \
  && contains_fixed 'make ci' "$ci_workflow" \
  && contains_fixed 'uses: ./.github/actions/builder' "$ci_workflow"; then
  pass "remote Rust CI invokes the full local make ci gate inside the repository builder"
else
  fail "remote Rust CI no longer invokes the full local make ci gate inside the repository builder"
fi

release_workflow="$REPO_ROOT/.github/workflows/release.yml"
if [ -f "$release_workflow" ] \
  && contains_fixed 'brew install openssl@3 pkg-config' "$release_workflow" \
  && contains_regex 'vcpkg\.exe.*openssl:x64-windows-static-md' "$release_workflow"; then
  pass "release workflow installs OpenSSL prerequisites per platform"
else
  fail "release workflow is missing one or more platform OpenSSL setup steps"
fi

if [ -f "$release_workflow" ] \
  && contains_fixed 'scripts/build_release_artifact.sh' "$release_workflow" \
  && contains_fixed 'scripts/smoke_test_release_artifact.sh' "$release_workflow" \
  && contains_fixed 'scripts/release_validate.sh' "$release_workflow" \
  && contains_fixed 'uses: ./.github/actions/builder' "$release_workflow" \
  && ! contains_regex 'apt-get|DEBIAN_FRONTEND' "$release_workflow" \
  && ! contains_fixed '|| true' "$release_workflow"; then
  pass "release workflow uses repo-owned packaging/validation scripts inside the Wolfi builder and fails loud"
else
  fail "release workflow is not fully scripted in-repo, has drifted from the Wolfi builder, or still swallows errors"
fi

codeql_refs=$(grep -rE 'github/codeql-action/(init|autobuild|analyze|upload-sarif)@' "$workflow_dir"/*.yml || true)
if [ -n "$codeql_refs" ] \
  && ! printf '%s\n' "$codeql_refs" | grep -vF "@${CODEQL_ACTION_SHA} # v${CODEQL_ACTION_VERSION}" >/dev/null; then
  pass "CodeQL action references match the scanner toolchain manifest"
else
  fail "CodeQL action references are missing or drifted from the scanner toolchain manifest"
fi

for host_tool in $HOST_LOCAL_SCANNER_TOOLS; do
  if contains_fixed "\"$host_tool\"" "$REPO_ROOT/xtask/src/main.rs"; then
    :
  else
    fail "host-local scanner tool $host_tool is listed in the manifest but missing from xtask visibility checks"
  fi
done

if contains_regex '^release-emulate:' "$REPO_ROOT/Makefile" \
  && contains_regex '^release-validate:' "$REPO_ROOT/Makefile"; then
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
  && contains_regex '^verify-published-release:' "$REPO_ROOT/Makefile"; then
  pass "published release verification is available from the repo"
else
  fail "published release verification is missing"
fi

if contains_fixed 'docs-linkcheck' "$REPO_ROOT/tox.ini" \
  && contains_fixed 'docs-linkcheck' "$REPO_ROOT/.github/workflows/ci.yml"; then
  pass "docs link validation is wired into tox and CI"
else
  fail "docs link validation is missing from tox or CI"
fi

if [ -f "$REPO_ROOT/scripts/verify_branch_protection.sh" ] \
  && contains_regex '^verify-branch-protection:' "$REPO_ROOT/Makefile"; then
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
