#!/bin/zsh
set -euo pipefail
cd -- "${0:A:h}"
if [[ "$(uname -s)" != Darwin ]]; then
  print -u2 "Claude Network Check requires macOS."
  exit 1
fi
if ! xcrun --find swiftc >/dev/null 2>&1; then
  print -u2 "Install Apple's Command Line Tools first: xcode-select --install"
  exit 1
fi
app_path="${1:-$PWD/dist/Claude Network Check.app}"
[[ "$app_path" = /* ]] || app_path="$PWD/$app_path"
if [[ "$app_path" != *.app ]]; then
  print -u2 "The output path must end in .app."
  exit 1
fi
if [[ -e "$app_path" && ! -f "$app_path/Contents/Resources/privacy_audit.py" ]]; then
  print -u2 "Output exists and is not this app; refusing to overwrite."
  exit 1
fi
build_temp="$(mktemp -d "${TMPDIR:-/tmp}/claude-network-check.XXXXXX")"
trap 'rm -rf -- "$build_temp"' EXIT
bundle_path="$build_temp/Claude Network Check.app"
mkdir -p "$bundle_path/Contents/MacOS" "$bundle_path/Contents/Resources"
xcrun swiftc -O -target "$(uname -m)-apple-macos13.0" App.swift \
  -o "$bundle_path/Contents/MacOS/NetworkEnvironmentCheck" -framework AppKit -framework WebKit
strip -S "$bundle_path/Contents/MacOS/NetworkEnvironmentCheck"
cp index.html browser_probe.html environment.py egress.py privacy_audit.py "$bundle_path/Contents/Resources/"
cat > "$bundle_path/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>local.claude-network-check</string>
<key>CFBundleName</key><string>Claude Network Check</string>
<key>CFBundleDisplayName</key><string>Claude Network Check</string>
<key>CFBundleExecutable</key><string>NetworkEnvironmentCheck</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>2.2.1</string>
<key>CFBundleVersion</key><string>221</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$bundle_path"
codesign --verify --deep --strict "$bundle_path"
mkdir -p -- "${app_path:h}"
# ditto only replaces this app's generated bundle; user history is stored elsewhere.
ditto "$bundle_path" "$app_path"
print "Built: $app_path"
