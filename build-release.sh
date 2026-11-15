#!/usr/bin/env bash
# Release build for shellcode-generator.
#
# Produces static release binaries for every supported generator host into
# ./release and prints their SHA-256 sums. Requires a Go toolchain; the payload
# itself always targets Windows - only the generator's host platform varies.
set -euo pipefail
cd "$(dirname "$0")"

OUT=release
mkdir -p "$OUT"
rm -f "$OUT/shellcode-generator-windows-amd64.exe" \
      "$OUT/shellcode-generator-linux-amd64"

echo "[1/2] windows/amd64"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" \
  -o "$OUT/shellcode-generator-windows-amd64.exe" .

echo "[2/2] linux/amd64"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" \
  -o "$OUT/shellcode-generator-linux-amd64" .

echo
echo "release artifacts:"
sha256sum "$OUT/shellcode-generator-windows-amd64.exe" \
          "$OUT/shellcode-generator-linux-amd64"
