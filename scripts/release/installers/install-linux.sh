#!/usr/bin/env bash
# 3FA Linux installer. Run from inside the unzipped folder: ./install.sh
# Installs to ~/.local/bin (no root needed) and adds a desktop entry.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pinned minisign public key for release authenticity. Bake the real key in at
# GA; while empty, only checksum integrity (not authenticity) is enforced.
THREEFA_MINISIGN_PUBKEY="${THREEFA_MINISIGN_PUBKEY:-}"

# Fail closed unless the payload matches the shipped (and, when a key is pinned,
# signed) SHA-256 manifest. Defends against corrupted or tampered downloads.
verify_payload() {
  command -v shasum >/dev/null 2>&1 || command -v sha256sum >/dev/null 2>&1 \
    || { echo "no shasum/sha256sum found; cannot verify integrity" >&2; exit 1; }
  [[ -f "$HERE/SHA256SUMS" ]] || { echo "missing SHA256SUMS; refusing to install unverified files" >&2; exit 1; }
  if [[ -n "$THREEFA_MINISIGN_PUBKEY" ]]; then
    command -v minisign >/dev/null 2>&1 || { echo "minisign required to verify signature; aborting" >&2; exit 1; }
    [[ -f "$HERE/SHA256SUMS.minisig" ]] || { echo "missing signature; refusing to install" >&2; exit 1; }
    minisign -V -P "$THREEFA_MINISIGN_PUBKEY" -m "$HERE/SHA256SUMS" \
      || { echo "signature verification FAILED — do not trust this download" >&2; exit 1; }
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$HERE" && sha256sum -c SHA256SUMS >/dev/null )
  else
    ( cd "$HERE" && shasum -a 256 -c SHA256SUMS >/dev/null )
  fi || { echo "checksum verification FAILED — refusing to install" >&2; exit 1; }
  echo "Integrity verified."
}
verify_payload

BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
mkdir -p "$BIN_DIR" "$APP_DIR"

echo "Installing 3fa to $BIN_DIR ..."
install -m 0755 "$HERE/3fa" "$BIN_DIR/3fa"

if [[ -f "$HERE/3fa.desktop" ]]; then
  sed "s|@BIN@|$BIN_DIR/3fa|g" "$HERE/3fa.desktop" > "$APP_DIR/3fa.desktop"
  update-desktop-database "$APP_DIR" 2>/dev/null || true
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "Note: add $BIN_DIR to your PATH to run '3fa' directly." ;;
esac
echo "Done."
