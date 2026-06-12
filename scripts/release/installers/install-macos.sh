#!/usr/bin/env bash
# 3FA macOS installer. Run from inside the unzipped folder: ./install.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pinned minisign public key for release authenticity. Bake the real key in at
# GA; while empty, only checksum integrity (not authenticity) is enforced.
THREEFA_MINISIGN_PUBKEY="${THREEFA_MINISIGN_PUBKEY:-}"

# Fail closed unless the payload matches the shipped (and, when a key is pinned,
# signed) SHA-256 manifest. Defends against corrupted or tampered downloads.
verify_payload() {
  command -v shasum >/dev/null 2>&1 || { echo "shasum not found; cannot verify integrity" >&2; exit 1; }
  [[ -f "$HERE/SHA256SUMS" ]] || { echo "missing SHA256SUMS; refusing to install unverified files" >&2; exit 1; }
  if [[ -n "$THREEFA_MINISIGN_PUBKEY" ]]; then
    command -v minisign >/dev/null 2>&1 || { echo "minisign required to verify signature; aborting" >&2; exit 1; }
    [[ -f "$HERE/SHA256SUMS.minisig" ]] || { echo "missing signature; refusing to install" >&2; exit 1; }
    minisign -V -P "$THREEFA_MINISIGN_PUBKEY" -m "$HERE/SHA256SUMS" \
      || { echo "signature verification FAILED — do not trust this download" >&2; exit 1; }
  fi
  ( cd "$HERE" && shasum -a 256 -c SHA256SUMS >/dev/null ) \
    || { echo "checksum verification FAILED — refusing to install" >&2; exit 1; }
  echo "Integrity verified."
}
verify_payload

if [[ -d "$HERE/3FA.app" ]]; then
  echo "Installing 3FA.app to /Applications ..."
  rm -rf "/Applications/3FA.app"
  cp -R "$HERE/3FA.app" "/Applications/3FA.app"
  # NOTE: we deliberately do NOT strip com.apple.quarantine. Removing it disables
  # Gatekeeper's notarization/malware check on a just-downloaded app. The shipped
  # app must instead be code-signed + notarized so Gatekeeper validates it.
  echo "Done. Launch 3FA from /Applications or Spotlight."
else
  DEST="/usr/local/bin/3fa"
  echo "Installing 3fa to $DEST ..."
  sudo install -m 0755 "$HERE/3fa" "$DEST"
  echo "Done. Run '3fa' from your terminal."
fi
