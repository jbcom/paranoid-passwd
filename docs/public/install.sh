#!/bin/sh
# paranoid-passwd curl-pipe installer.
#
# Usage:
#   curl -sSL https://paranoid-passwd.com/install.sh | sh
#   curl -sSL https://paranoid-passwd.com/install.sh | sh -s -- --version paranoid-passwd-v3.5.1

set -eu

REPO="jbcom/paranoid-passwd"
BIN="paranoid-passwd"
VERSION="latest"
INSTALL_DIR=""
DOWNLOAD_BASE_URL=""
CHECKSUMS_URL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="$2"; shift 2 ;;
    --install-dir)
      INSTALL_DIR="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,8p' "$0"; exit 0 ;;
    *)
      echo "install.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

uname_os() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    darwin) echo darwin ;;
    linux) echo linux ;;
    msys*|mingw*|cygwin*)
      echo "install.sh: Windows detected; use Scoop or Chocolatey instead" >&2
      exit 1 ;;
    *)
      echo "install.sh: unsupported OS: $os" >&2; exit 1 ;;
  esac
}

uname_arch() {
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *)
      echo "install.sh: unsupported arch: $arch" >&2; exit 1 ;;
  esac
}

pick_install_dir() {
  if [ -n "$INSTALL_DIR" ]; then
    echo "$INSTALL_DIR"; return
  fi
  if [ -w /usr/local/bin ] 2>/dev/null; then
    echo /usr/local/bin; return
  fi
  mkdir -p "$HOME/.local/bin"
  echo "$HOME/.local/bin"
}

checksum_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c -
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c -
    return
  fi
  echo "install.sh: no SHA-256 checksum tool found (need sha256sum or shasum)" >&2
  exit 1
}

resolve_version() {
  if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
      | head -n1)
    if [ -z "$VERSION" ]; then
      echo "install.sh: could not resolve latest version" >&2
      exit 1
    fi
  fi
}

OS=$(uname_os)
ARCH=$(uname_arch)
INSTALL_DIR=$(pick_install_dir)
resolve_version
VERSION_NO_PREFIX=${VERSION#paranoid-passwd-v}

if [ -n "${PARANOID_INSTALL_DOWNLOAD_BASE_URL:-}" ]; then
  DOWNLOAD_BASE_URL="${PARANOID_INSTALL_DOWNLOAD_BASE_URL}"
else
  DOWNLOAD_BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
fi

if [ -n "${PARANOID_INSTALL_CHECKSUMS_URL:-}" ]; then
  CHECKSUMS_URL="${PARANOID_INSTALL_CHECKSUMS_URL}"
else
  CHECKSUMS_URL="${DOWNLOAD_BASE_URL}/checksums.txt"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ "$OS" = "windows" ]; then
  EXT="zip"
else
  EXT="tar.gz"
fi

ARCHIVE="${BIN}-${VERSION_NO_PREFIX}-${OS}-${ARCH}.${EXT}"
URL="${DOWNLOAD_BASE_URL}/$ARCHIVE"

echo "Downloading $ARCHIVE..."
curl -sSL -o "$TMP/$ARCHIVE" "$URL" || {
  echo "install.sh: download failed: $URL" >&2; exit 1
}

echo "Verifying checksum..."
curl -sSL -o "$TMP/checksums.txt" "$CHECKSUMS_URL" || {
  echo "install.sh: checksum download failed: $CHECKSUMS_URL" >&2; exit 1
}

( cd "$TMP" && grep "  $ARCHIVE\$" checksums.txt | checksum_check ) || {
  echo "install.sh: checksum verification failed" >&2; exit 1
}

echo "Extracting to $INSTALL_DIR..."
mkdir -p "$TMP/unpack"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP/unpack"
INSTALL_PATH=$(find "$TMP/unpack" -type f -name paranoid-passwd | head -n1)
if [ ! -s "$INSTALL_PATH" ]; then
  echo "install.sh: binary not found in archive" >&2; exit 1
fi
install -m 0755 "$INSTALL_PATH" "$INSTALL_DIR/$BIN"

echo
echo "Installed $BIN $VERSION to $INSTALL_DIR"
echo
echo "Run it interactively:"
echo "  $INSTALL_DIR/$BIN"
echo
echo "Or force CLI mode:"
echo "  $INSTALL_DIR/$BIN --cli --length 32 --count 1"
