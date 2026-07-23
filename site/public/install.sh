#!/usr/bin/env bash
# Warden installer — downloads the latest Warden release for your platform.
#
#   curl -sL https://wardengateway.com/install | bash
#
# Override the install location with WARDEN_INSTALL_DIR (default: /usr/local/bin if
# writable, otherwise $HOME/.local/bin).
set -euo pipefail

REPO="stephnangue/warden"

info() { printf '  %s\n' "$*"; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || err "curl is required"
command -v tar  >/dev/null 2>&1 || err "tar is required"

# --- detect platform ---
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  darwin|linux) ;;
  *) err "unsupported OS '$OS' (need darwin or linux)" ;;
esac
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) err "unsupported architecture '$ARCH'" ;;
esac

# --- resolve the latest version ---
VER=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | cut -d'"' -f4)
[ -n "$VER" ] || err "could not resolve the latest version"

ASSET="warden_${VER#v}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VER}/${ASSET}"

# --- choose install dir ---
if [ -n "${WARDEN_INSTALL_DIR:-}" ]; then
  DIR="$WARDEN_INSTALL_DIR"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  DIR="/usr/local/bin"
else
  DIR="$HOME/.local/bin"
fi
mkdir -p "$DIR"

info "Installing Warden ${VER} (${OS}/${ARCH}) to ${DIR}"

# --- download + extract ---
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$URL" | tar -xz -C "$TMP" warden || err "download or extract failed: $URL"
chmod +x "$TMP/warden"
mv "$TMP/warden" "$DIR/warden"

info "Installed $("$DIR/warden" --version 2>/dev/null || echo warden) to $DIR/warden"
case ":$PATH:" in
  *":$DIR:"*) info "Verify with 'warden --version'." ;;
  *) info "Add it to your PATH:  export PATH=\"$DIR:\$PATH\"" ;;
esac
