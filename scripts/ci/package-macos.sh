#!/usr/bin/env bash
# Build an ad-hoc signed macOS .app bundle and wrap it in a DMG.
#
# Usage:
#   ./scripts/ci/package-macos.sh VERSION VERSION_CODE [BINARY] [OUT_DIR]
#
# Defaults:
#   BINARY  = target/desktop/hakimi-ui
#   OUT_DIR = dist
#
# The resulting app is Apple Silicon only (arm64), matching the release job.
set -euo pipefail

VERSION="${1:?usage: package-macos.sh VERSION VERSION_CODE [BINARY] [OUT_DIR]}"
VERSION_CODE="${2:?usage: package-macos.sh VERSION VERSION_CODE [BINARY] [OUT_DIR]}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${3:-$REPO_ROOT/target/desktop/hakimi-ui}"
OUT_DIR="${4:-dist}"
ICON="${HAKIMI_ICON:-$REPO_ROOT/crates/hakimi-ui/assets/hakimi.icns}"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: this script must run on macOS" >&2
    exit 1
fi
if [[ ! -x "$BIN" ]]; then
    echo "error: binary not found or not executable: $BIN" >&2
    exit 1
fi
if [[ ! -f "$ICON" ]]; then
    echo "error: app icon not found: $ICON" >&2
    exit 1
fi

ARCHS="$(lipo -archs "$BIN")"
if [[ "$ARCHS" != "arm64" ]]; then
    echo "error: expected an arm64 binary, got: $ARCHS" >&2
    exit 1
fi

APP="$OUT_DIR/hakimi.app"
STAGE="$OUT_DIR/dmg-stage"
DMG="$OUT_DIR/hakimi-${VERSION}-macos-arm64.dmg"

rm -rf "$APP" "$STAGE"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BIN" "$APP/Contents/MacOS/hakimi"
chmod +x "$APP/Contents/MacOS/hakimi"
cp "$ICON" "$APP/Contents/Resources/hakimi.icns"

cat >"$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>zh_CN</string>
    <key>CFBundleDisplayName</key>
    <string>hakimi</string>
    <key>CFBundleExecutable</key>
    <string>hakimi</string>
    <key>CFBundleIdentifier</key>
    <string>com.hakimi.app</string>
    <key>CFBundleIconFile</key>
    <string>hakimi.icns</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>hakimi</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION_CODE}</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
</dict>
</plist>
PLIST

plutil -lint "$APP/Contents/Info.plist" >/dev/null
xattr -cr "$APP" 2>/dev/null || true

# Ad-hoc signing is mandatory on Apple Silicon. Without a Developer ID this
# still keeps Gatekeeper's "damaged app" error away; users must right-click
# Open (or allow it in System Settings) the first time.
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"

mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"

hdiutil create \
    -quiet \
    -volname "hakimi ${VERSION}" \
    -srcfolder "$STAGE" \
    -ov \
    -format UDZO \
    "$DMG"

rm -rf "$STAGE"
echo "created: $DMG"
