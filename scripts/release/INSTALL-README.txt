3FA — Secure Desktop Authenticator
==================================

To install:

  macOS    : run ./install.sh   (or drag 3FA.app to /Applications)
  Linux    : run ./install.sh   (installs to ~/.local/bin)
  Windows  : right-click install.ps1 -> Run with PowerShell

Before installing, verify the download's integrity against the SHA-256 shown on
the download page:

  macOS / Linux : shasum -a 256 <file>.zip
  Windows       : Get-FileHash <file>.zip

3FA keeps your one-time-password seeds encrypted on-device and locked behind a
passcode, biometrics, a passkey, or your voice. It never uploads anything
unencrypted. Learn more at https://threefa.app
