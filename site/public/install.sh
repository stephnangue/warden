#!/usr/bin/env bash
# Warden installer — downloads the latest Warden release for your platform.
#
#   curl -sL https://wardengateway.com/install.sh | bash
#
# It installs into the first writable directory already on your PATH (so `warden`
# works right away); otherwise it uses $HOME/.local/bin and adds that to your shell
# profile. Override the location with WARDEN_INSTALL_DIR.
#
# The archive is checked against the release's checksums.txt. When cosign v3 or
# later is installed, checksums.txt is also checked against the signature the
# release workflow made (see SECURITY.md), so a replaced release is refused.
set -euo pipefail

REPO="stephnangue/warden"
# The first release signed by the release workflow. From this minor version on,
# a release without a signature is refused when cosign is installed.
SIGNED_SINCE_MINOR=23

info() { printf '  %s\n' "$*"; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || err "curl is required"
command -v tar  >/dev/null 2>&1 || err "tar is required"
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  err "sha256sum or shasum is required"
fi

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
BASE="https://github.com/${REPO}/releases/download/${VER}"

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

# --- download ---
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET" || err "download failed: $BASE/$ASSET"
curl -fsSL -o "$TMP/checksums.txt" "$BASE/checksums.txt" || err "download failed: $BASE/checksums.txt"

# --- check the signature of checksums.txt, when cosign v3+ is installed ---
signed_release() {
  local maj min
  IFS=. read -r maj min _ <<< "${VER#v}"
  [ "${maj:-0}" -gt 0 ] || [ "${min:-0}" -ge "$SIGNED_SINCE_MINOR" ]
}
COSIGN_VER=""
if command -v cosign >/dev/null 2>&1; then
  COSIGN_VER=$(cosign version 2>/dev/null | awk '/^GitVersion:/ { print $2 }')
fi
case "$COSIGN_VER" in
  v[3-9].*|v[1-9][0-9]*.*)
    if signed_release; then
      curl -fsSL -o "$TMP/checksums.txt.sigstore.json" "$BASE/checksums.txt.sigstore.json" \
        || err "release ${VER} has no signature: $BASE/checksums.txt.sigstore.json"
      cosign verify-blob "$TMP/checksums.txt" \
          --bundle "$TMP/checksums.txt.sigstore.json" \
          --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VER}" \
          --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
          >"$TMP/cosign.log" 2>&1 \
        || { cat "$TMP/cosign.log" >&2; err "the signature of ${VER}'s checksums.txt does not verify"; }
      info "Checked the release signature with cosign ${COSIGN_VER}."
    fi
    ;;
  *)
    if signed_release; then
      info "Install cosign v3 or later to also check the release signature."
    fi
    ;;
esac

# --- check the archive against checksums.txt ---
WANT=$(awk -v f="$ASSET" '$2 == f { print $1 }' "$TMP/checksums.txt")
[ -n "$WANT" ] || err "$ASSET is not listed in checksums.txt"
GOT=$(sha256 "$TMP/$ASSET")
[ "$GOT" = "$WANT" ] || err "checksum mismatch for $ASSET: expected $WANT, got $GOT"
info "Checked the download against checksums.txt."

# --- extract ---
tar -xzf "$TMP/$ASSET" -C "$TMP" warden || err "extract failed: $ASSET"
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
