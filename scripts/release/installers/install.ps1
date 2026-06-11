# 3FA Windows installer. Right-click -> "Run with PowerShell", or:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

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
