#!/usr/bin/env bash
# NetWatch field box — εγκατάσταση σε Raspberry Pi OS Lite (64-bit) / Debian.
#
#   sudo tools/fieldbox/install.sh                 # NetWatch ως υπηρεσία (agent mode) στο eth0
#   sudo tools/fieldbox/install.sh --oled          # + οθόνη SSD1306 (ανοίγει το I2C)
#   sudo tools/fieldbox/install.sh --oled --button 17 --lte --iface eth0
#   tools/fieldbox/install.sh --dry-run --oled     # δείξε μόνο τι ΘΑ έκανε (δεν θέλει sudo)
#
# Τι κάνει — και τίποτα άλλο:
#   1. apt: python3-venv, tcpdump, ethtool, iproute2, iputils-ping, network-manager, openssl
#           (--oled: i2c-tools, python3-pil, python3-gpiozero, python3-lgpio · --lte: modemmanager, usb-modeswitch)
#   2. .venv στον φάκελο του repo + pip install -r requirements.txt  (--oled: και .venv-oled με luma.oled)
#   3. --oled: ενεργοποιεί το I2C (raspi-config) και βάζει τον χρήστη στις ομάδες i2c, gpio
#   4. γράφει /etc/systemd/system/netwatch-fieldbox.service (+ -oled.service) και τις ενεργοποιεί
# Μπορείς να το ξανατρέξεις όσες φορές θες (idempotent). Δεν κατεβάζει/εκτελεί scripts από το Internet.
set -euo pipefail

DRY=0; OLED=0; LTE=0; START=1
IFACE="eth0"; PORT="8765"; BUTTON=""; RUN_USER="${SUDO_USER:-$(id -un)}"

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --oled) OLED=1 ;;
    --lte) LTE=1 ;;
    --no-start) START=0 ;;
    --iface) IFACE="${2:-}"; shift ;;
    --port) PORT="${2:-}"; shift ;;
    --button) BUTTON="${2:-}"; shift ;;
    --user) RUN_USER="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Άγνωστη επιλογή: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[[ "$IFACE" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]] || { echo "Μη έγκυρη διεπαφή: $IFACE" >&2; exit 2; }
[[ "$PORT" =~ ^[0-9]{2,5}$ ]] || { echo "Μη έγκυρη θύρα: $PORT" >&2; exit 2; }
[[ -z "$BUTTON" || "$BUTTON" =~ ^[0-9]{1,2}$ ]] || { echo "Μη έγκυρο GPIO: $BUTTON" >&2; exit 2; }
[[ "$RUN_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "Μη έγκυρος χρήστης: $RUN_USER" >&2; exit 2; }

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIT_DIR="/etc/systemd/system"

if [[ "$(uname -s)" != "Linux" ]]; then
  if [[ $DRY -eq 1 ]]; then
    echo "⚠ Αυτό δεν είναι Linux ($(uname -s)) — δείχνω μόνο τι θα έκανα σε Raspberry Pi."
  else
    echo "✖ Το install.sh είναι για Raspberry Pi OS / Debian (Linux). Εδώ: $(uname -s)." >&2
    echo "  Για να δεις τι κάνει χωρίς να τρέξει τίποτα: $0 --dry-run" >&2
    exit 1
  fi
fi
if [[ $DRY -eq 0 ]]; then
  [[ $EUID -eq 0 ]] || { echo "✖ Θέλει sudo:  sudo $0 [επιλογές]   (ή --dry-run για να δεις μόνο τι θα έκανε)" >&2; exit 1; }
  command -v apt-get >/dev/null || { echo "✖ Δεν βρέθηκε apt-get (θέλει Raspberry Pi OS / Debian / Ubuntu)." >&2; exit 1; }
  command -v systemctl >/dev/null || { echo "✖ Δεν βρέθηκε systemd." >&2; exit 1; }
  [[ "$RUN_USER" != "root" ]] || { echo "✖ Δώσε απλό χρήστη με --user (η υπηρεσία δεν τρέχει ως root)." >&2; exit 1; }
  id "$RUN_USER" >/dev/null 2>&1 || { echo "✖ Δεν υπάρχει ο χρήστης $RUN_USER." >&2; exit 1; }
fi
[[ -f "$DIR/netwatch.py" && -f "$DIR/requirements.txt" ]] || { echo "✖ Δεν βρήκα το NetWatch στο $DIR." >&2; exit 1; }

say() { printf '\n▸ %s\n' "$*"; }
run() {                       # εκτελεί ή (σε --dry-run) απλώς τυπώνει
  if [[ $DRY -eq 1 ]]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi
}
as_user() {                   # ό,τι αφορά το repo γίνεται ως ο απλός χρήστης, όχι ως root
  if [[ $DRY -eq 1 ]]; then printf '  [dry-run] (%s) %s\n' "$RUN_USER" "$*"; else sudo -u "$RUN_USER" -- "$@"; fi
}
install_unit() {              # install_unit <πηγή> <όνομα>
  local src="$1" dst="$UNIT_DIR/$2" tmp btn=""
  [[ -n "$BUTTON" ]] && btn="--button $BUTTON"
  if [[ $DRY -eq 1 ]]; then
    printf '  [dry-run] γράφω %s (DIR=%s USER=%s IFACE=%s PORT=%s%s)\n' "$dst" "$DIR" "$RUN_USER" "$IFACE" "$PORT" "${btn:+ $btn}"
    return 0
  fi
  tmp="$(mktemp)"
  sed -e "s|__DIR__|$DIR|g" -e "s|__USER__|$RUN_USER|g" -e "s|__IFACE__|$IFACE|g" \
      -e "s|__PORT__|$PORT|g" -e "s|__BUTTON__|$btn|g" "$src" > "$tmp"
  install -m 0644 -o root -g root "$tmp" "$dst"
  rm -f "$tmp"
}

echo "NetWatch field box — εγκατάσταση"
echo "  φάκελος: $DIR · χρήστης: $RUN_USER · διεπαφή: $IFACE · θύρα: $PORT · OLED: $OLED · LTE: $LTE${BUTTON:+ · κουμπί GPIO$BUTTON}"
case "$DIR" in *[\ \|\&\\]*) echo "✖ Ο φάκελος έχει κενά ή ειδικούς χαρακτήρες — μετακίνησε το repo (π.χ. ~/netwatch)." >&2; exit 1 ;; esac

PKGS=(python3-venv python3-pip tcpdump ethtool iproute2 iputils-ping network-manager openssl)
[[ $OLED -eq 1 ]] && PKGS+=(i2c-tools python3-pil python3-gpiozero python3-lgpio)
[[ $LTE -eq 1 ]] && PKGS+=(modemmanager usb-modeswitch)

say "1/4 Πακέτα συστήματος (apt): ${PKGS[*]}"
run apt-get update -qq
run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PKGS[@]}"

say "2/4 Python venv + εξαρτήσεις του NetWatch"
if [[ ! -x "$DIR/.venv/bin/python" ]]; then as_user python3 -m venv "$DIR/.venv"; fi
as_user "$DIR/.venv/bin/pip" install -q -r "$DIR/requirements.txt"
as_user mkdir -p "$DIR/data"
if [[ $OLED -eq 1 ]]; then
  # ξεχωριστό venv που «βλέπει» τα πακέτα του συστήματος (PIL, gpiozero, lgpio) — το NetWatch μένει καθαρό
  if [[ ! -x "$DIR/.venv-oled/bin/python" ]]; then as_user python3 -m venv --system-site-packages "$DIR/.venv-oled"; fi
  as_user "$DIR/.venv-oled/bin/pip" install -q luma.oled
fi

if [[ $OLED -eq 1 ]]; then
  say "3/4 I2C για την οθόνη"
  if command -v raspi-config >/dev/null; then
    run raspi-config nonint do_i2c 0
  else
    echo "  (δεν βρέθηκε raspi-config — άνοιξε το I2C με το χέρι: dtparam=i2c_arm=on στο /boot/firmware/config.txt)"
  fi
  for g in i2c gpio; do
    if getent group "$g" >/dev/null 2>&1 || [[ $DRY -eq 1 ]]; then run usermod -aG "$g" "$RUN_USER"; fi
  done
else
  say "3/4 Οθόνη OLED: παραλείπεται (ξανατρέξε με --oled όταν τη συνδέσεις)"
fi

say "4/4 Υπηρεσίες systemd"
install_unit "$DIR/tools/fieldbox/netwatch-fieldbox.service" netwatch-fieldbox.service
[[ $OLED -eq 1 ]] && install_unit "$DIR/tools/fieldbox/netwatch-fieldbox-oled.service" netwatch-fieldbox-oled.service
run systemctl daemon-reload
if [[ $START -eq 1 ]]; then
  run systemctl enable netwatch-fieldbox.service
  run systemctl restart netwatch-fieldbox.service
  if [[ $OLED -eq 1 ]]; then
    run systemctl enable netwatch-fieldbox-oled.service
    run systemctl restart netwatch-fieldbox-oled.service
  fi
else
  echo "  (--no-start: οι υπηρεσίες γράφτηκαν αλλά δεν ξεκίνησαν)"
fi

cat <<EOF

✔ Έτοιμο$(if [[ $DRY -eq 1 ]]; then echo " (dry-run: δεν άλλαξε τίποτα)"; fi).

Επόμενα βήματα:
  1. Δες το URL με το token και το αποτύπωμα του πιστοποιητικού:
       journalctl -u netwatch-fieldbox -n 30 --no-pager | grep -A1 agent
     (το token υπάρχει και στο $DIR/data/agent-token)
  2. Από το κινητό: https://<IP του Pi>:$PORT/?token=…  → σύγκρινε το SHA-256 → καρτέλα «🔌 Tester πρίζας».
     Χωρίς δίκτυο πελάτη; Κάνε το Pi hotspot:
       sudo nmcli device wifi hotspot ifname wlan0 ssid NetWatch-Box password '<δικός σου κωδικός, 12+ χαρακτήρες>'
     και άνοιξε https://10.42.0.1:$PORT/?token=…
  3. Εφεδρική γραμμή LTE (USB modem):  sudo $DIR/tools/fieldbox/lte-setup.sh <APN>
  4. Δοκιμή οθόνης χωρίς υλικό:  $DIR/.venv/bin/python $DIR/tools/fieldbox/oled.py --stdout --once \\
       --url https://127.0.0.1:$PORT
  Αν μόλις ενεργοποιήθηκε το I2C ή μπήκες σε νέες ομάδες: κάνε μία επανεκκίνηση (sudo reboot).
  Οδηγός: $DIR/tools/fieldbox/README.md
EOF
