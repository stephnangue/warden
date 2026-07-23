#!/usr/bin/env bash
# Warden installer — downloads the latest Warden release for your platform.
#
#   curl -sL https://wardengateway.com/install | bash
#
# It installs into the first writable directory already on your PATH (so `warden`
# works right away); otherwise it uses $HOME/.local/bin and adds that to your shell
# profile. Override the location with WARDEN_INSTALL_DIR.
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

# --- choose install dir: prefer a writable directory already on PATH ---
on_path() { case ":$PATH:" in *":$1:"*) return 0 ;; *) return 1 ;; esac; }

DIR=""
if [ -n "${WARDEN_INSTALL_DIR:-}" ]; then
  DIR="$WARDEN_INSTALL_DIR"
else
  for d in "$HOME/.local/bin" /opt/homebrew/bin /usr/local/bin "$HOME/bin"; do
    if on_path "$d" && [ -d "$d" ] && [ -w "$d" ]; then DIR="$d"; break; fi
  done
  [ -n "$DIR" ] || DIR="$HOME/.local/bin"   # fall back (may not be on PATH yet)
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

if on_path "$DIR"; then
  info "Verify with 'warden --version'."
else
  # Persist the PATH entry for future shells, then tell the user how to use it now.
  case "$(basename "${SHELL:-}")" in
    zsh)  profile="$HOME/.zshrc" ;;
    bash) profile="${HOME}/.bashrc" ;;
    *)    profile="$HOME/.profile" ;;
  esac
  line="export PATH=\"$DIR:\$PATH\""
  if [ -f "$profile" ] && grep -qF "$DIR" "$profile" 2>/dev/null; then :; else
    printf '\n# Added by the Warden installer\n%s\n' "$line" >> "$profile"
  fi
  info "Added $DIR to your PATH in $profile."
  info "Open a new terminal, or run:  $line"
  info "Then verify with 'warden --version'."
fi
