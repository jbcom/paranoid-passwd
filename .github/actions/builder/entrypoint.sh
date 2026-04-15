#!/usr/bin/env bash
# entrypoint.sh — Docker container action entrypoint
#
# Receives the workflow step's `run:` content via the INPUT_RUN env var
# (GitHub Actions automatically prefixes any `with: <name>:` with INPUT_).
# Writes it to a temp script and execs it with strict bash flags.
#
# All execution happens inside the Wolfi container with $GITHUB_WORKSPACE
# bind-mounted at /github/workspace (cwd).

set -o errexit
set -o nounset
set -o pipefail

if [[ -z "${INPUT_RUN:-}" ]]; then
    echo "::error::builder action requires a 'run:' input"
    exit 64
fi

# Write the script to a tempfile so multi-line + heredoc + quoting all work.
script=$(mktemp /tmp/builder-step-XXXXXX.sh)
printf '%s\n' "${INPUT_RUN}" > "${script}"
chmod +x "${script}"

# Execute with strict flags. The caller can override locally with `set +e` etc.
exec bash -o errexit -o nounset -o pipefail "${script}"
