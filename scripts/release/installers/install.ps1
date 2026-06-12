# 3FA Windows installer. Right-click -> "Run with PowerShell", or:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Fail closed unless every payload file matches the shipped SHA-256 manifest.
function Verify-Payload {
  $manifest = Join-Path $here 'SHA256SUMS'
  if (-not (Test-Path $manifest)) {
    Write-Error 'missing SHA256SUMS; refusing to install unverified files'; exit 1
  }
  foreach ($line in Get-Content $manifest) {
    if ($line -match '^([0-9a-fA-F]{64})\s+\*?\.?[\\/]?(.+)$') {
      $expected = $matches[1].ToUpperInvariant()
      $rel = $matches[2].Trim()
      $path = Join-Path $here $rel
      if (-not (Test-Path $path)) { Write-Error "missing file from manifest: $rel"; exit 1 }
      $actual = (Get-FileHash -Algorithm SHA256 $path).Hash
      if ($actual -ne $expected) { Write-Error "checksum FAILED for $rel — refusing to install"; exit 1 }
    }
  }
  Write-Host 'Integrity verified.'
}
Verify-Payload

$dest = Join-Path $env:LOCALAPPDATA 'Programs\3FA'
New-Item -ItemType Directory -Force -Path $dest | Out-Null

Write-Host "Installing 3FA to $dest ..."
Copy-Item -Force (Join-Path $here '3fa.exe') (Join-Path $dest '3fa.exe')

# Start Menu shortcut.
$startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$shortcut = Join-Path $startMenu '3FA.lnk'
$ws = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut($shortcut)
$lnk.TargetPath = Join-Path $dest '3fa.exe'
$lnk.WorkingDirectory = $dest
$lnk.Description = '3FA Authenticator'
$lnk.Save()

Write-Host "Done. Launch 3FA from the Start Menu."
