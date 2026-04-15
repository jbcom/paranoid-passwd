#!/usr/bin/env bash

set -euo pipefail

REPO="${1:-jbcom/paranoid-passwd}"
BRANCH="${2:-main}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required for branch protection verification" >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "gh auth is required for branch protection verification" >&2
  exit 1
fi

expected_checks=(
  "CodeQL (python)"
  "CodeQL (rust)"
  "Docs Build"
  "Rust Build + Tests"
)

mapfile -t actual_checks < <(
  gh api "repos/${REPO}/branches/${BRANCH}/protection" --jq '.required_status_checks.contexts[]' \
    | LC_ALL=C sort
)

mapfile -t expected_sorted < <(printf '%s\n' "${expected_checks[@]}" | LC_ALL=C sort)

if [ "${#actual_checks[@]}" -ne "${#expected_sorted[@]}" ]; then
  printf 'expected %d required checks, found %d\n' "${#expected_sorted[@]}" "${#actual_checks[@]}" >&2
  printf 'actual: %s\n' "${actual_checks[*]-}" >&2
  exit 1
fi

for index in "${!expected_sorted[@]}"; do
  if [ "${expected_sorted[$index]}" != "${actual_checks[$index]}" ]; then
    printf 'required checks mismatch at index %s: expected %s got %s\n' \
      "$index" "${expected_sorted[$index]}" "${actual_checks[$index]}" >&2
    exit 1
  fi
done

printf 'branch protection OK for %s:%s\n' "${REPO}" "${BRANCH}"
