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
  "Dependency Scan"
  "Docs Build"
  "Rust Build + Tests"
  "Security Assurance"
  "SonarQube Cloud"
)

mapfile -t actual_checks < <(
  gh api "repos/${REPO}/branches/${BRANCH}/protection" --jq '.required_status_checks.contexts[]' \
    | LC_ALL=C sort
)

strict="$(gh api "repos/${REPO}/branches/${BRANCH}/protection/required_status_checks" --jq '.strict')"
if [ "$strict" != "true" ]; then
  echo "required status checks must be strict/up-to-date" >&2
  exit 1
fi

protection="$(gh api "repos/${REPO}/branches/${BRANCH}/protection")"
if [ "$(jq -r '.required_pull_request_reviews // empty' <<<"$protection")" != "" ]; then
  echo "main must not require human pull-request reviews" >&2
  exit 1
fi
if [ "$(jq -r '.allow_force_pushes.enabled' <<<"$protection")" != "false" ] \
  || [ "$(jq -r '.allow_deletions.enabled' <<<"$protection")" != "false" ] \
  || [ "$(jq -r '.required_linear_history.enabled' <<<"$protection")" != "false" ]; then
  echo "main branch history protection does not match policy" >&2
  exit 1
fi

repo_settings="$(gh api "repos/${REPO}")"
if [ "$(jq -r '.allow_merge_commit' <<<"$repo_settings")" != "true" ] \
  || [ "$(jq -r '.allow_squash_merge' <<<"$repo_settings")" != "false" ] \
  || [ "$(jq -r '.allow_rebase_merge' <<<"$repo_settings")" != "false" ] \
  || [ "$(jq -r '.allow_auto_merge' <<<"$repo_settings")" != "true" ]; then
  echo "repository merge settings do not preserve merge-commit-only history" >&2
  exit 1
fi

ruleset_id="$(gh api "repos/${REPO}/rulesets" --jq '.[] | select(.name == "agentic-main") | .id')"
if [ -z "$ruleset_id" ]; then
  echo "agentic-main ruleset is missing" >&2
  exit 1
fi
ruleset="$(gh api "repos/${REPO}/rulesets/${ruleset_id}")"
if [ "$(jq -r '.name' <<<"$ruleset")" != "agentic-main" ] \
  || [ "$(jq -r '.enforcement' <<<"$ruleset")" != "active" ] \
  || [ "$(jq -r '.bypass_actors | length' <<<"$ruleset")" != "0" ]; then
  echo "agentic-main ruleset must be active with no bypass actors" >&2
  exit 1
fi
pull_request_rule="$(jq -c '.rules[] | select(.type == "pull_request")' <<<"$ruleset")"
if [ "$(jq -r '.parameters.required_approving_review_count' <<<"$pull_request_rule")" != "0" ] \
  || [ "$(jq -r '.parameters.require_code_owner_review' <<<"$pull_request_rule")" != "false" ] \
  || [ "$(jq -r '.parameters.require_last_push_approval' <<<"$pull_request_rule")" != "false" ] \
  || [ "$(jq -r '.parameters.allowed_merge_methods | join(",")' <<<"$pull_request_rule")" != "merge" ]; then
  echo "agentic-main ruleset must require PRs without human approvals and allow merge commits only" >&2
  exit 1
fi

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
