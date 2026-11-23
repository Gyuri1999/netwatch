#!/usr/bin/env bash
# NetWatch field box — τούνελ WireGuard προς τον δικό σου server, για να βλέπεις το κουτί από μακριά.
#
#   sudo tools/fieldbox/wg-setup.sh                 # εγκατάσταση του data/remote/nw0.conf και εκκίνηση
#   sudo tools/fieldbox/wg-setup.sh --conf /path/nw0.conf
#   sudo tools/fieldbox/wg-setup.sh --remove        # σταμάτα και σβήσε το τούνελ
#   tools/fieldbox/wg-setup.sh --dry-run            # δείξε μόνο τις εντολές
#
# Το nw0.conf το φτιάχνει η καρτέλα 🛰 Απομακρυσμένη πρόσβαση του NetWatch (εκεί είναι και το κομμάτι [Peer] που
# βάζεις στον server σου). Αυτό το script: εγκαθιστά το wireguard-tools αν λείπει, αντιγράφει το αρχείο στο
# /etc/wireguard/nw0.conf (δικαιώματα 600) και ενεργοποιεί το wg-quick@nw0 ώστε να ξεκινά και μετά από reboot.
# Δεν αγγίζει τίποτα άλλο: ούτε firewall, ούτε routes πέρα από τη μία διεύθυνση του server σου μέσα στο τούνελ.
set -euo pipefail

IFACE="nw0"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONF="$HERE/data/remote/$IFACE.conf"
DRY=0; REMOVE=0

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --remove) REMOVE=1 ;;
    --conf) CONF="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Άγνωστη επιλογή: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

run() { if [[ $DRY -eq 1 ]]; then printf '+ %s\n' "$*"; else "$@"; fi; }

[[ "$(uname -s)" == "Linux" ]] || { echo "✖ Μόνο για Linux (Raspberry Pi OS / Debian)." >&2; exit 1; }
if [[ $DRY -eq 0 && $EUID -ne 0 ]]; then echo "✖ Τρέξ' το με sudo (ή με --dry-run για να δεις τι θα κάνει)." >&2; exit 1; fi

DEST="/etc/wireguard/$IFACE.conf"

if [[ $REMOVE -eq 1 ]]; then
  echo "▸ Σταματάω το τούνελ $IFACE"
  run systemctl disable --now "wg-quick@$IFACE" || true
  if [[ -e "$DEST" || $DRY -eq 1 ]]; then run rm -f -- "$DEST"; fi
  echo "✓ Το τούνελ αφαιρέθηκε. Σβήσε και το [Peer] του κουτιού από τον server σου."
  exit 0
fi

[[ -f "$CONF" ]] || { echo "✖ Δεν βρήκα το $CONF — φτιάξ' το πρώτα από την καρτέλα 🛰 Απομακρυσμένη πρόσβαση." >&2; exit 1; }
grep -q '^\[Interface\]' "$CONF" && grep -q '^PrivateKey = ' "$CONF" && grep -q '^\[Peer\]' "$CONF" \
  || { echo "✖ Το $CONF δεν μοιάζει με ρύθμιση WireGuard του NetWatch." >&2; exit 1; }
# Ασφάλεια: δεχόμαστε μόνο τούνελ που δρομολογεί ΜΙΑ διεύθυνση (/32) — ποτέ όλο το Internet ή το δίκτυο του πελάτη.
ALLOWED="$(sed -n 's/^AllowedIPs = //p' "$CONF")"
[[ "$ALLOWED" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/32$ ]] \
  || { echo "✖ AllowedIPs = «$ALLOWED». Αυτό το script εγκαθιστά μόνο τούνελ προς μία διεύθυνση (/32)." >&2; exit 1; }
if grep -Eq '^(PostUp|PostDown|PreUp|PreDown|DNS|Table)[[:space:]]*=' "$CONF"; then
  echo "✖ Το αρχείο έχει εντολές PostUp/PreUp/DNS/Table — δεν το εγκαθιστώ (τρέχουν ως root)." >&2; exit 1
fi

if ! command -v wg-quick >/dev/null 2>&1; then
  echo "▸ Εγκατάσταση wireguard-tools"
  run apt-get update -qq
  run apt-get install -y --no-install-recommends wireguard-tools
fi

echo "▸ Αντιγραφή ρύθμισης στο $DEST (600)"
run install -d -m 700 /etc/wireguard
run install -m 600 -o root -g root "$CONF" "$DEST"
echo "▸ Εκκίνηση και ενεργοποίηση στο boot"
run systemctl enable "wg-quick@$IFACE"
run systemctl restart "wg-quick@$IFACE"

BOX_IP="$(sed -n 's/^Address = \([0-9.]*\).*/\1/p' "$CONF")"
cat <<EOF
✓ Έτοιμο. Έλεγχος:
    sudo wg show $IFACE            # «latest handshake» μέσα σε ~30″ = το τούνελ δουλεύει
Αν δεν βλέπεις handshake: πρόσθεσες το [Peer] του κουτιού στον server σου; είναι ανοιχτή η θύρα UDP του server;

Το κουτί (υπηρεσία netwatch-fieldbox) τρέχει ήδη με --agent (HTTPS + token), άρα από τον υπολογιστή σου, μέσα από το
τούνελ, ανοίγεις:   https://$BOX_IP:8765/?token=…
Το URL με το token το τυπώνει το NetWatch στην εκκίνηση (journalctl -u netwatch-fieldbox) και υπάρχει στο data/agent-token.
Αν τρέχεις το NetWatch με το χέρι, ξεκίνα το με:   --agent
EOF
