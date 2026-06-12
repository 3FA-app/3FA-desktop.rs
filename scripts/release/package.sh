#!/usr/bin/env bash
# Package a built 3FA binary into a per-platform distributable zip.
#
# Each zip contains the app, a platform installer, and a README — a single
# uniform format across macOS / Windows / Linux, with the right installer baked
# in so users just unzip and run it.
#
# Usage:
#   scripts/release/package.sh <platform> <binary_path> <version> [arch]
#     platform : macos | windows | linux
#     binary   : path to the compiled binary (or .app dir on macOS)
#     version  : e.g. 0.1.0
#     arch     : optional, e.g. aarch64 | x86_64 (default: host arch)
#
# Output: dist/3fa-<version>-<platform>-<arch>.zip
set -euo pipefail

PLATFORM="${1:?platform required}"
BINARY="${2:?binary path required}"
VERSION="${3:?version required}"
ARCH="${4:-$(uname -m)}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLERS="$ROOT/scripts/release/installers"
DIST="$ROOT/dist"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$DIST"

NAME="3fa-${VERSION}-${PLATFORM}-${ARCH}"
PKG="$STAGE/$NAME"
mkdir -p "$PKG"

cp "$ROOT/scripts/release/INSTALL-README.txt" "$PKG/README.txt"

case "$PLATFORM" in
  macos)
    # Accept either a raw binary or a prebuilt .app bundle.
    if [[ -d "$BINARY" ]]; then
      cp -R "$BINARY" "$PKG/3FA.app"
    else
      cp "$BINARY" "$PKG/3fa"
      chmod +x "$PKG/3fa"
    fi
    cp "$INSTALLERS/install-macos.sh" "$PKG/install.sh"
    chmod +x "$PKG/install.sh"
    ;;
  linux)
    cp "$BINARY" "$PKG/3fa"
    chmod +x "$PKG/3fa"
    cp "$INSTALLERS/install-linux.sh" "$PKG/install.sh"
    chmod +x "$PKG/install.sh"
    cp "$INSTALLERS/3fa.desktop" "$PKG/3fa.desktop"
    ;;
  windows)
    cp "$BINARY" "$PKG/3fa.exe"
    cp "$INSTALLERS/install.ps1" "$PKG/install.ps1"
    ;;
  *)
    echo "unknown platform: $PLATFORM" >&2; exit 1 ;;
esac

# Integrity manifest *inside* the package, covering the installable payload
# (everything except the installer script that verifies it and the manifest /
# signature themselves). The installer checks this before copying anything into
# place, so a corrupted or partially-tampered download fails closed.
command -v shasum >/dev/null 2>&1 || { echo "shasum required to build a verifiable package" >&2; exit 1; }
( cd "$PKG" && find . -type f \
    ! -name 'SHA256SUMS' ! -name 'SHA256SUMS.*' \
    ! -name 'install.sh' ! -name 'install.ps1' \
    -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 > SHA256SUMS )

# Authenticity (the real tamper-evidence root): if a minisign secret key is
# configured in the release environment, sign the manifest. The installers pin
# the matching public key and verify this signature when present, so a swapped
# binary *and* a swapped checksum can't both pass. Set MINISIGN_SECRET_KEY in CI.
if [[ -n "${MINISIGN_SECRET_KEY:-}" ]] && command -v minisign >/dev/null 2>&1; then
  minisign -S -s "$MINISIGN_SECRET_KEY" -m "$PKG/SHA256SUMS" -t "3FA $NAME"
  echo "signed: SHA256SUMS.minisig"
else
  echo "WARNING: MINISIGN_SECRET_KEY not set — package ships unsigned (checksums only)." >&2
fi

OUT="$DIST/$NAME.zip"
rm -f "$OUT"
( cd "$STAGE" && zip -r -q "$OUT" "$NAME" )

# Emit a sidecar checksum of the whole zip for the download page.
( cd "$DIST" && shasum -a 256 "$NAME.zip" > "$NAME.zip.sha256" )

echo "packaged: $OUT"
