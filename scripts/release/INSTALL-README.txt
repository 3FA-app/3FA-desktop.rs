3FA — Secure Desktop Authenticator
==================================

To install:

  macOS    : run ./install.sh   (or drag 3FA.app to /Applications)
  Linux    : run ./install.sh   (installs to ~/.local/bin)
  Windows  : right-click install.ps1 -> Run with PowerShell

The installer verifies the unzipped payload against the bundled SHA256SUMS
manifest (and, for signed releases, its minisign signature) before copying
anything into place, and refuses to install if verification fails.

You can also independently check the downloaded zip against the SHA-256 shown on
the download page:

  macOS / Linux : shasum -a 256 <file>.zip
  Windows       : Get-FileHash <file>.zip

3FA keeps your one-time-password seeds encrypted on-device and locked behind a
passcode, biometrics, a passkey, or your voice. It never uploads anything
unencrypted. Learn more at https://threefa.app
