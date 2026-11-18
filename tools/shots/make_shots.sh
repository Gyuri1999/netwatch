#!/bin/bash
# Βγάζει τις εικόνες του README (docs/*.png, docs/demo.gif) και την εικόνα προεπισκόπησης (docs/og.png)
# από το NetWatch σε λειτουργία DEMO (προσομοίωση — κανένα πραγματικό δεδομένο του δικτύου σου).
#
#   ./tools/shots/make_shots.sh          # χρειάζεται: macOS (swiftc, WebKit) και ffmpeg (brew install ffmpeg)
#
# Αγγλικό UI για το README. Κάθε λήψη έχει καθαρή μνήμη (όχι localStorage από το δικό σου browser).
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
PY=${PY:-.venv/bin/python}
PORT=${PORT:-8797}
OUT=docs
TMP=build/shots
mkdir -p "$TMP" "$OUT"
command -v ffmpeg >/dev/null || { echo "χρειάζεται ffmpeg (brew install ffmpeg)"; exit 1; }

echo "▸ μεταγλώττιση snap"
swiftc -O -swift-version 5 tools/shots/snap.swift -o build/snap

echo "▸ demo server στη θύρα $PORT"
"$PY" netwatch.py --demo --port "$PORT" --no-open >"$TMP/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for _ in $(seq 40); do curl -sf "http://localhost:$PORT/api/status" | grep -q '"demo"' && break; sleep 0.5; done
curl -sf "http://localhost:$PORT/api/status" | grep -q '"demo"' || { echo "ο server δεν είναι σε demo — σταματάω"; exit 1; }
echo "  ζέσταμα (κίνηση, ειδοποιήσεις, sparklines)…"; sleep 45

U="http://localhost:$PORT/?lang=en&quiet=1"
# μια συσκευή του LAN με πολλούς προορισμούς (όχι εσύ, όχι ο router)
PICK="const k=[...S.out.entries()].filter(([ip])=>{const h=S.hosts.get(ip);return h&&!h.me&&!h.gw}).sort((a,b)=>b[1].size-a[1].size)[0][0];select(k);"
TOOUT="setTimeout(()=>{const h=[...document.querySelectorAll('#t-det h3')].find(x=>x.textContent.includes('🛰'));if(h)h.scrollIntoView()},300);"

shot() {  # όνομα, url, [επιπλέον ορίσματα για το snap]
  local name=$1 url=$2; shift 2
  echo "  📸 $name"
  build/snap "$url" "$TMP/$name.png" --wait 8 "$@" >/dev/null
  ffmpeg -loglevel error -y -i "$TMP/$name.png" -vf "scale=1600:-1:flags=lanczos" "$OUT/$name.png"
}

echo "▸ στιγμιότυπα"
shot dashboard    "$U&mode=tech&tab=home"
shot home-learn   "$U&mode=learn&tab=home"
shot map          "$U&mode=tech&tab=map"
shot lan          "$U&mode=tech&tab=lan"
shot destinations "$U&mode=tech&tab=det" --js "$PICK$TOOUT" --after 1.5
shot route        "$U&mode=tech&tab=det" --js "$PICK setTimeout(()=>{document.querySelector('#t-det [data-oroute]').click();setTimeout(()=>document.querySelector('#rt-trace')?.click(),300)},300)" --after 4
shot analysis     "$U&mode=tech&tab=alerts" --js "(document.querySelector('#t-alerts .al.high .act button')||document.querySelector('#t-alerts .al .act button')).click()" --after 2
shot wireshark    "$U&mode=tech&tab=ws" --js "document.querySelector('#t-ws [data-cat=tcp]').click()"
shot tools        "$U&mode=learn&tab=pentest" --js "ptSub='tools';PTIN.subnet_in='192.168.1.37/26';PTIN.dns_name='github.com';drawPentest();nkRun('subnet');nkRun('dns');setTimeout(()=>document.querySelector('#t-pentest [data-tool=subnet]').scrollIntoView({block:'end'}),2500)" --after 5
shot palette      "$U&mode=tech&tab=home" --js "cmdkOpen();\$('cmdk-in').value='dns';\$('cmdk-in').oninput()"
shot stats        "$U&mode=tech&tab=stats"
shot academy      "http://localhost:$PORT/academy.html?lang=en" --js "ACADEMY.openLesson('iot','iot-4-2')" --after 3
shot latency      "$U&mode=tech&tab=lat" --after 3
shot ipam         "$U&mode=tech&tab=ipam"
shot topology     "$U&mode=tech&tab=snmp"
shot light        "$U&mode=tech&tab=home&theme=light"
shot tor          "$U&mode=tech&tab=tor" --after 3
shot cameras      "$U&mode=tech&tab=cams" --after 2
shot trackers     "$U&mode=tech&tab=home" --js "setTimeout(()=>showTab('trk'),13000)" --after 16
shot fingerprint  "$U&mode=tech&tab=priv" --js "document.querySelector('#fp-run')&&document.querySelector('#fp-run').click();setTimeout(()=>{const e=[...document.querySelectorAll('#t-priv h3')].find(x=>x.textContent.includes('Δακτυλικό'));e&&e.scrollIntoView()},1200)" --after 3

echo "▸ GIF (ζωντανός χάρτης)"
rm -f "$TMP"/gif-*.png
build/snap "$U&mode=tech&tab=map" "$TMP/gif.png" --wait 8 --frames 48 --every 0.06 >/dev/null
ffmpeg -loglevel error -y -framerate 12 -i "$TMP/gif-%03d.png" \
  -vf "scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" \
  "$OUT/demo.gif"

echo "▸ εικόνα προεπισκόπησης (1200×630)"
mkdir -p "$TMP/og"
cp tools/shots/og.html "$TMP/og/og.html"
cp "$OUT/dashboard.png" "$TMP/og/shot.png"
build/snap "file://$ROOT/$TMP/og/og.html" "$TMP/og.png" --size 1200x630 --wait 1 >/dev/null
ffmpeg -loglevel error -y -i "$TMP/og.png" -vf "scale=1200:630:flags=lanczos" "$OUT/og.png"

ls -la "$OUT"/*.png "$OUT"/*.gif
echo "✔ έτοιμο"
