#!/usr/bin/env bash
# 3FA Linux installer. Run from inside the unzipped folder: ./install.sh
# Installs to ~/.local/bin (no root needed) and adds a desktop entry.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
