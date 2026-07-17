#!/usr/bin/env bash
#
# Bootstrap / bump the digest-pinned GHCR reference in
# .github/actions/builder/action.yml.
#
# .github/workflows/builder-image.yml publishes
# ghcr.io/jbcom/paranoid-passwd-builder:latest on push-to-main (paths
# scoped to .github/actions/builder/**), a weekly schedule, and
# workflow_dispatch. This script resolves that tag's current digest and
# rewrites action.yml to consume it by immutable @sha256 reference instead
# of rebuilding the Dockerfile per job.
#
# First run (bootstrap): action.yml is still on `image: Dockerfile` with the
# docker:// line commented out. This script uncomments it with the resolved
# digest and comments out `image: Dockerfile`.
#
# Subsequent runs (digest bump): action.yml already has an active `image:
# docker://...@sha256:` line; this script replaces the digest in place.
#
# See docs/reference/ci-design.md "Bootstrap Ordering" for the full sequence.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ACTION_FILE="$REPO_ROOT/.github/actions/builder/action.yml"
IMAGE_REF="ghcr.io/jbcom/paranoid-passwd-builder"

fail() {
  printf "%bERROR%b %s\n" "$RED" "$NC" "$1" >&2
  exit 1
}

[ -f "$ACTION_FILE" ] || fail "action.yml not found at $ACTION_FILE"

resolve_digest() {
  if command -v docker >/dev/null 2>&1; then
    docker buildx imagetools inspect "${IMAGE_REF}:latest" --format '{{json .Manifest}}' 2>/dev/null \
      | grep -oE '"digest":"sha256:[0-9a-f]{64}"' \
      | head -n1 \
      | grep -oE 'sha256:[0-9a-f]{64}'
    return
  fi
  if command -v skopeo >/dev/null 2>&1; then
    skopeo inspect "docker://${IMAGE_REF}:latest" 2>/dev/null \
      | grep -oE '"Digest": "sha256:[0-9a-f]{64}"' \
      | head -n1 \
      | grep -oE 'sha256:[0-9a-f]{64}'
    return
  fi
  fail "neither docker nor skopeo is available to resolve ${IMAGE_REF}:latest"
}

digest="$(resolve_digest || true)"
[ -n "$digest" ] || fail "could not resolve a digest for ${IMAGE_REF}:latest (has builder-image.yml published yet?)"

new_image_line="  image: docker://${IMAGE_REF}@${digest}"

if grep -qE '^\s*image: docker://ghcr\.io/jbcom/paranoid-passwd-builder@sha256:' "$ACTION_FILE"; then
  # Digest bump: replace the existing active docker:// line in place.
  sed -i.bak -E "s|^[[:space:]]*image: docker://ghcr\.io/jbcom/paranoid-passwd-builder@sha256:[0-9a-f]{64}|${new_image_line}|" "$ACTION_FILE"
  rm -f "${ACTION_FILE}.bak"
  printf "%bOK%b bumped action.yml to %s@%s\n" "$GREEN" "$NC" "$IMAGE_REF" "$digest"
elif grep -qE '^\s*image: Dockerfile\s*$' "$ACTION_FILE"; then
  # Bootstrap: flip from the Dockerfile build onto the resolved digest, and
  # comment out (not delete) the Dockerfile line so rollback is a one-line
  # uncomment per the rollback note in docs/reference/ci-design.md.
  sed -i.bak -E "s|^([[:space:]]*)image: Dockerfile[[:space:]]*\$|\1# image: Dockerfile\n\1image: docker://${IMAGE_REF}@${digest}|" "$ACTION_FILE"
  rm -f "${ACTION_FILE}.bak"
  printf "%bOK%b bootstrapped action.yml onto %s@%s\n" "$GREEN" "$NC" "$IMAGE_REF" "$digest"
else
  fail "action.yml's runs.image line is neither 'Dockerfile' nor an active ${IMAGE_REF} docker:// reference; refusing to guess"
fi

printf "Review the diff in %s before committing.\n" "$ACTION_FILE"
