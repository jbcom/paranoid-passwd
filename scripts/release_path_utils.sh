#!/usr/bin/env bash

path_for_windows_tool() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s\n' "$1"
  fi
}

find_exactly_one_file_named() {
  local root="$1"
  local label="$2"
  shift 2
  local matches=()
  local name
  local match

  for name in "$@"; do
    while IFS= read -r -d '' match; do
      matches+=("${match}")
    done < <(find "${root}" -type f -name "${name}" -print0)
  done

  case "${#matches[@]}" in
    1)
      printf '%s\n' "${matches[0]}"
      ;;
    0)
      echo "expected exactly one ${label}; found none under ${root}" >&2
      exit 1
      ;;
    *)
      echo "expected exactly one ${label}; found ${#matches[@]} under ${root}" >&2
      printf '%s\n' "${matches[@]}" >&2
      exit 1
      ;;
  esac
}
