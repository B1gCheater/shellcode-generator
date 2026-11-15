# Release build for shellcode-generator.
#
# Produces static release binaries for every supported generator host into
# .\release and prints their SHA-256 sums. Requires a Go toolchain; the payload
# itself always targets Windows - only the generator's host platform varies.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$out = Join-Path $PSScriptRoot "release"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$win = Join-Path $out "shellcode-generator-windows-amd64.exe"
$lin = Join-Path $out "shellcode-generator-linux-amd64"
Remove-Item $win, $lin -ErrorAction SilentlyContinue

Write-Host "[1/2] windows/amd64"
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-s -w" -o $win .

Write-Host "[2/2] linux/amd64"
$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-s -w" -o $lin .

Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "release artifacts:"
Get-ChildItem $out -File | Get-FileHash -Algorithm SHA256 |
  ForEach-Object { "{0}  {1}" -f $_.Hash.ToLower(), (Split-Path $_.Path -Leaf) }
