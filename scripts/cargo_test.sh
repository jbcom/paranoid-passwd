#!/usr/bin/env bash

set -euo pipefail

if [ "${PARANOID_USE_XVFB:-auto}" = "0" ] || [ "${PARANOID_USE_XVFB:-auto}" = "false" ]; then
  exec cargo test "$@"
fi

if command -v xvfb-run >/dev/null 2>&1; then
  if command -v dbus-run-session >/dev/null 2>&1; then
    exec xvfb-run -a dbus-run-session -- cargo test "$@"
  fi
  exec xvfb-run -a cargo test "$@"
fi

exec cargo test "$@"
