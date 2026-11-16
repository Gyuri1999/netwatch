#!/bin/bash
# Φτιάχνει το NetWatch.app (στο dist/) — χρειάζεται μόνο τα Command Line Tools (swiftc), όχι Xcode.
#   ./macapp/build.sh            → dist/NetWatch.app
#   ./macapp/build.sh --install  → και αντιγραφή στο ~/Applications
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
OUT=dist/NetWatch.app
BUILD=build/macapp
rm -rf "$OUT" && mkdir -p "$OUT/Contents/MacOS" "$OUT/Contents/Resources/netwatch" "$BUILD"

echo "▸ μεταγλώττιση (swiftc)"
swiftc -O -swift-version 5 -target "$(uname -m)-apple-macos12.0" \
  -framework AppKit -framework WebKit macapp/NetWatch.swift -o "$OUT/Contents/MacOS/NetWatch"

echo "▸ εικονίδιο"
swiftc -swift-version 5 macapp/make_icon.swift -o "$BUILD/make_icon"
"$BUILD/make_icon" "$BUILD/icon.png"
ICONSET="$BUILD/NetWatch.iconset"
rm -rf "$ICONSET" && mkdir "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s "$BUILD/icon.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) "$BUILD/icon.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$OUT/Contents/Resources/NetWatch.icns"

echo "▸ αρχεία NetWatch"
cp macapp/Info.plist "$OUT/Contents/Info.plist"
rsync -a --exclude '__pycache__' netwatch.py pentest.py rules.py ctf.py wifiguard.py privacy.py index.html edu.js \
  config.example.yaml requirements.txt rules ctf samples "$OUT/Contents/Resources/netwatch/"
rm -f "$OUT/Contents/Resources/netwatch/rules/local.yaml"

echo "▸ υπογραφή (ad-hoc)"
codesign --force --deep --sign - "$OUT" >/dev/null

# Python περιβάλλον: φτιάχνεται εδώ, ώστε η πρώτη εκκίνηση να είναι άμεση
VENV="$HOME/Library/Application Support/NetWatch/venv"
if [ ! -x "$VENV/bin/python" ]; then
  echo "▸ Python περιβάλλον στο $VENV"
  mkdir -p "$(dirname "$VENV")"
  /usr/bin/python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r requirements.txt
fi

if [ "${1:-}" = "--install" ]; then
  mkdir -p "$HOME/Applications"
  rm -rf "$HOME/Applications/NetWatch.app"
  cp -R "$OUT" "$HOME/Applications/"
  echo "✔ εγκαταστάθηκε: ~/Applications/NetWatch.app"
else
  echo "✔ $ROOT/$OUT  (άνοιγμα: open $OUT)"
fi
