#!/bin/bash
# Φτιάχνει το NetWatch.app (στο dist/) — χρειάζεται μόνο τα Command Line Tools (swiftc), όχι Xcode.
#   ./macapp/build.sh            → dist/NetWatch.app
#   ./macapp/build.sh --install  → και αντιγραφή στο ~/Applications
#   ./macapp/build.sh --dmg      → και dist/NetWatch.dmg (για να το μοιραστείς / GitHub Releases)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
OUT=dist/NetWatch.app
BUILD=build/macapp
rm -rf "$OUT" && mkdir -p "$OUT/Contents/MacOS" "$OUT/Contents/Resources/netwatch" "$BUILD"

echo "▸ μεταγλώττιση (swiftc) — universal: Apple Silicon (arm64) + Intel (x86_64)"
# Intel από macOS 13: τα νέα Command Line Tools δεν έχουν πια τις βιβλιοθήκες συμβατότητας x86_64 για macOS 12
for T in arm64-apple-macos12.0 x86_64-apple-macos13.0; do
  A=${T%%-*}
  swiftc -O -swift-version 5 -target "$T" \
    -framework AppKit -framework WebKit -framework SwiftUI -framework ServiceManagement macapp/NetWatch.swift -o "$BUILD/NetWatch-$A"
done
lipo -create "$BUILD/NetWatch-arm64" "$BUILD/NetWatch-x86_64" -output "$OUT/Contents/MacOS/NetWatch"
lipo -info "$OUT/Contents/MacOS/NetWatch"

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
VER=$(cat VERSION 2>/dev/null || echo 1.0.0)
plutil -replace CFBundleShortVersionString -string "$VER" "$OUT/Contents/Info.plist"
rsync -a --exclude '__pycache__' --exclude '*.md' ./*.py \
  index.html edu.js wireshark.js infra.js sectools.js privtools.js protocols.js ciscolab.js uiplus.js pentestui.js socui.js worktools.js opstools.js cmdxlate.js navplus.js anontools.js topomap.js sshui.js vlsm.js updateui.js presenceui.js l2guardui.js assessui.js vulnui.js upnpui.js otui.js acceptui.js sitesui.js labelsui.js calcui.js v6ui.js nacui.js iotinvui.js radioui.js fieldui.js soakui.js remoteui.js camcheckui.js probesui.js watchui.js acl.js names.js golive.js alertwhy.js i18n.js i18n academy academy.html manifest.webmanifest sw.js config.example.yaml requirements.txt VERSION update_signers rules ctf samples "$OUT/Contents/Resources/netwatch/"
rm -f "$OUT/Contents/Resources/netwatch/rules/local.yaml"

echo "▸ υπογραφή (ad-hoc)"
codesign --force --deep --sign - "$OUT" >/dev/null

# Python περιβάλλον: φτιάχνεται εδώ, ώστε η πρώτη εκκίνηση να είναι άμεση
VENV="$HOME/Library/Application Support/NetWatch/venv"
if [ ! -x "$VENV/bin/python" ]; then
  echo "▸ Python περιβάλλον στο $VENV"
  mkdir -p "$(dirname "$VENV")"
  /usr/bin/python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install -q --disable-pip-version-check -r requirements.txt   # και για νέες εξαρτήσεις (π.χ. paho-mqtt)

case " $* " in *" --dmg "*)
  echo "▸ δίσκος εγκατάστασης (.dmg)"
  STAGE="$BUILD/dmg"
  rm -rf "$STAGE" dist/NetWatch.dmg && mkdir -p "$STAGE"
  cp -R "$OUT" "$STAGE/"
  ln -s /Applications "$STAGE/Applications"   # σύρε το NetWatch εδώ
  hdiutil create -quiet -volname NetWatch -srcfolder "$STAGE" -ov -format UDZO dist/NetWatch.dmg
  echo "✔ $ROOT/dist/NetWatch.dmg ($(du -h dist/NetWatch.dmg | cut -f1))";;
esac
if [[ " $* " == *" --install "* ]]; then
  mkdir -p "$HOME/Applications"
  rm -rf "$HOME/Applications/NetWatch.app"
  cp -R "$OUT" "$HOME/Applications/"
  echo "✔ εγκαταστάθηκε: ~/Applications/NetWatch.app"
else
  echo "✔ $ROOT/$OUT  (άνοιγμα: open $OUT)"
fi
