#!/usr/bin/env bash

set -euo pipefail

DEVICE_STORE_DIR_CREATED=0
if [ -z "${PARANOID_TEST_DEVICE_STORE_DIR:-}" ]; then
  PARANOID_TEST_DEVICE_STORE_DIR="$(mktemp -d)"
  DEVICE_STORE_DIR_CREATED=1
  export PARANOID_TEST_DEVICE_STORE_DIR
fi

cleanup_device_store() {
  if [ "$DEVICE_STORE_DIR_CREATED" -eq 1 ]; then
    rm -rf "$PARANOID_TEST_DEVICE_STORE_DIR"
  fi
}
trap cleanup_device_store EXIT

if [ "${PARANOID_USE_XVFB:-auto}" = "0" ] || [ "${PARANOID_USE_XVFB:-auto}" = "false" ]; then
  cargo test "$@"
  exit $?
fi

if command -v xvfb-run >/dev/null 2>&1; then
  if command -v dbus-run-session >/dev/null 2>&1; then
    xvfb-run -a dbus-run-session -- cargo test "$@"
    exit $?
  fi
  xvfb-run -a cargo test "$@"
  exit $?
fi

cargo test "$@"
