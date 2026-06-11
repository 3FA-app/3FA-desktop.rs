#!/usr/bin/env bash
# 3FA macOS installer. Run from inside the unzipped folder: ./install.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -d "$HERE/3FA.app" ]]; then
  echo "Installing 3FA.app to /Applications ..."
  rm -rf "/Applications/3FA.app"
  cp -R "$HERE/3FA.app" "/Applications/3FA.app"
  # Clear the quarantine flag set on downloaded apps.
  xattr -dr com.apple.quarantine "/Applications/3FA.app" 2>/dev/null || true
  echo "Done. Launch 3FA from /Applications or Spotlight."
else
  DEST="/usr/local/bin/3fa"
  echo "Installing 3fa to $DEST ..."
  sudo install -m 0755 "$HERE/3fa" "$DEST"
  echo "Done. Run '3fa' from your terminal."
fi
