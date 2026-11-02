#!/usr/bin/env bash
#
# Build a macOS .app bundle for the MT7601U GUI.
#
# Usage:
#   bash scripts/bundle-macos-app.sh
#
# Environment overrides:
#   PROFILE=release|debug     build profile (default: release)
#   APP_NAME=MT7601U          bundle / executable name (default: MT7601U)
#   BUNDLE_ID=...             CFBundleIdentifier (default: ai.commandcode.mt7601u-macos)
#
# Output: dist/<APP_NAME>.app
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

APP_NAME="${APP_NAME:-MT7601U}"
BIN_NAME="mt7601u-macos"
PROFILE="${PROFILE:-release}"
BUNDLE_ID="${BUNDLE_ID:-ai.commandcode.mt7601u-macos}"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
VERSION="${VERSION:-0.1.0}"

if [[ "$PROFILE" == "release" ]]; then
    CARGO_FLAGS=(--release)
else
    CARGO_FLAGS=()
fi

echo "==> Building ($PROFILE)…"
cargo build "${CARGO_FLAGS[@]}"

BIN_PATH="target/$PROFILE/$BIN_NAME"
if [[ ! -f "$BIN_PATH" ]]; then
    echo "error: expected binary at $BIN_PATH" >&2
    exit 1
fi

APP_DIR="dist/$APP_NAME.app"
echo "==> Assembling ${APP_DIR}…"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
cp "$BIN_PATH" "$APP_DIR/Contents/MacOS/$APP_NAME"
chmod +x "$APP_DIR/Contents/MacOS/$APP_NAME"

# Optional icon: drop an .icns at assets/AppIcon.icns and it is picked up.
ICON_KEYS=""
if [[ -f "assets/AppIcon.icns" ]]; then
    cp "assets/AppIcon.icns" "$APP_DIR/Contents/Resources/AppIcon.icns"
    ICON_KEYS="    <key>CFBundleIconFile</key><string>AppIcon</string>"
    echo "    (using assets/AppIcon.icns)"
fi

cat > "$APP_DIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key><string>MT7601U Bridge</string>
    <key>CFBundleExecutable</key><string>${APP_NAME}</string>
    <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
    <key>CFBundleVersion</key><string>${VERSION}</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>LSMinimumSystemVersion</key><string>12.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
${ICON_KEYS}
</dict>
</plist>
PLIST

# Optional firmware: bundled into Resources so the app can bring the radio up
# without any extra setup. The blob is not vendored in the repo; it is copied
# from the local reference clone (or $MT7601U_FIRMWARE) at bundle time.
FIRMWARE_SRC=""
for candidate in "${MT7601U_FIRMWARE:-}" \
                 "mt7601u-refs/linux-firmware/mediatek/mt7601u.bin" \
                 "mt7601u.bin"; do
    if [[ -n "$candidate" && -f "$candidate" ]]; then
        FIRMWARE_SRC="$candidate"
        break
    fi
done
if [[ -n "$FIRMWARE_SRC" ]]; then
    cp "$FIRMWARE_SRC" "$APP_DIR/Contents/Resources/mt7601u.bin"
    echo "    (bundled firmware from $FIRMWARE_SRC)"
else
    echo "    (no firmware found; set MT7601U_FIRMWARE to bundle mt7601u.bin)"
fi

if command -v codesign >/dev/null 2>&1; then
    echo "==> Ad-hoc code signing…"
    codesign --force --sign - "$APP_DIR"
else
    echo "==> codesign not found; skipping signing (install Xcode command line tools)"
fi
DMG_PATH="dist/$APP_NAME.dmg"
if command -v hdiutil >/dev/null 2>&1; then
    echo "==> Creating ${DMG_PATH}…"
    rm -f "$DMG_PATH"
    rm -rf "dist/dmg-root"
    mkdir -p "dist/dmg-root"
    cp -R "$APP_DIR" "dist/dmg-root/"
    ln -s /Applications "dist/dmg-root/Applications"
    hdiutil create -quiet -volname "$APP_NAME" -srcfolder "dist/dmg-root" \
        -ov -format UDZO "$DMG_PATH"
    rm -rf "dist/dmg-root"
else
    echo "==> hdiutil not found; skipping DMG creation"
fi

echo
echo "==> Built: $REPO_ROOT/$APP_DIR"
echo "    Launch:      open \"$APP_DIR\""
echo "    CLI inside:  \"$APP_DIR/Contents/MacOS/$APP_NAME\" --identify"
if [[ -f "$DMG_PATH" ]]; then
    echo "    Installer:   $REPO_ROOT/$DMG_PATH  (open it and drag the app to Applications)"
fi
