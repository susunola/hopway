#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"
destination="${1:-$PWD/../HopWay.app}"
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
app="$staging/HopWay.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp ui/Info.plist "$app/Contents/Info.plist"
# sing-box protocol features: QUIC (Hysteria2, TUIC) and uTLS (REALITY, fingerprints).
# Set HOPWAY_TAGS=hopway_native for a build without the sing-box stack.
tags="${HOPWAY_TAGS:-with_quic,with_utls,badlinkname,tfogo_checklinkname0}"
go build -trimpath -tags "$tags" -ldflags "-s -w -checklinkname=0" -o "$app/Contents/Resources/mac-proxy-core" .
arch="$(uname -m)"
xcrun swiftc -O -target "$arch-apple-macosx14.0" -o "$app/Contents/MacOS/MacProxy" ui/*.swift
codesign --force --sign - "$app/Contents/Resources/mac-proxy-core"
codesign --force --sign - "$app"
codesign --verify --deep --strict "$app"
# ditto preserves the bundle structure and supports rebuilding an existing app.
ditto "$app" "$destination"
printf '%s\n' "$destination"
