# dove installer for Windows (PowerShell).
#
#   irm https://raw.githubusercontent.com/boomctl/dove/main/install.ps1 | iex
#
# Downloads the latest windows-msvc release binary, verifies its SHA-256 against
# the release's SHA256SUMS, installs it, and adds the install dir to your user PATH.
#
# Env: DOVE_BINDIR (install dir), DOVE_VERSION (release tag, default latest).
$ErrorActionPreference = 'Stop'

$Repo    = 'boomctl/dove'
$Version = if ($env:DOVE_VERSION) { $env:DOVE_VERSION } else { 'latest' }
$BinDir  = if ($env:DOVE_BINDIR)  { $env:DOVE_BINDIR }  else { "$env:LOCALAPPDATA\dove\bin" }

# Only x86_64 windows-msvc is published; it runs on ARM64 Windows via emulation.
$Asset = 'dove-x86_64-pc-windows-msvc.exe'
$Base  = if ($Version -eq 'latest') {
  "https://github.com/$Repo/releases/latest/download"
} else {
  "https://github.com/$Repo/releases/download/$Version"
}

$Tmp = Join-Path $env:TEMP ("dove-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  Write-Host "downloading $Asset ($Version)..."
  Invoke-WebRequest -Uri "$Base/$Asset"     -OutFile "$Tmp\dove.exe"
  Invoke-WebRequest -Uri "$Base/SHA256SUMS"  -OutFile "$Tmp\SHA256SUMS"

  $line = Select-String -Path "$Tmp\SHA256SUMS" -Pattern (" " + [regex]::Escape($Asset) + '$')
  if (-not $line) { throw "no checksum for $Asset in SHA256SUMS" }
  $want = ($line.Line -split '\s+')[0]
  $got  = (Get-FileHash "$Tmp\dove.exe" -Algorithm SHA256).Hash
  if ($want.ToLower() -ne $got.ToLower()) { throw "checksum mismatch (expected $want, got $got)" }

  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
  Move-Item -Force "$Tmp\dove.exe" "$BinDir\dove.exe"
  Write-Host "installed dove -> $BinDir\dove.exe"

  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split ';') -notcontains $BinDir) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$BinDir", 'User')
    Write-Host "added $BinDir to your user PATH -- restart your terminal to pick it up"
  }
  & "$BinDir\dove.exe" --version
}
finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
