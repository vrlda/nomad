#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <version> <binary> <output-directory>" >&2
  exit 2
fi

version="$1"
binary="$2"
output_directory="$3"
app_name="Nomad Browser"
bundle="$output_directory/$app_name.app"
dmg="$output_directory/nomad-browser-macos-$version.dmg"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "DMG packaging requires macOS" >&2
  exit 1
fi
if [[ ! -x "$binary" ]]; then
  echo "release binary is missing or not executable: $binary" >&2
  exit 1
fi

rm -rf "$bundle"
rm -f "$dmg"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"

cp "$binary" "$bundle/Contents/MacOS/nomad-browser"
cp packaging/macos/Nomad.icns "$bundle/Contents/Resources/Nomad.icns"
sed "s/@VERSION@/$version/g" packaging/macos/Info.plist.in > "$bundle/Contents/Info.plist"
chmod 755 "$bundle/Contents/MacOS/nomad-browser"

# Ad-hoc signing seals nested code and catches malformed bundles. Public Alpha
# builds remain unnotarized until release signing credentials are configured.
codesign --force --deep --sign - "$bundle"

staging_directory="$(mktemp -d)"
trap 'rm -rf "$staging_directory"' EXIT
cp -R "$bundle" "$staging_directory/"
ln -s /Applications "$staging_directory/Applications"
hdiutil create \
  -volname "$app_name Alpha" \
  -srcfolder "$staging_directory" \
  -format UDZO \
  -ov \
  "$dmg"

codesign --verify --deep --strict "$bundle"
hdiutil verify "$dmg"
shasum -a 256 "$dmg" > "$dmg.sha256"
