#!/usr/bin/env bash
# NetWatch field box — το 4G/LTE ως ΕΦΕΔΡΙΚΗ γραμμή (μόνο όταν πέσει η ενσύρματη).
#
#   sudo tools/fieldbox/lte-setup.sh internet                 # USB modem (ModemManager), APN «internet»
#   sudo tools/fieldbox/lte-setup.sh internet --metric 700 --name netwatch-lte
#   sudo tools/fieldbox/lte-setup.sh --tether usb0            # modem HiLink / κινητό σε USB tethering (φαίνεται ως Ethernet)
#   tools/fieldbox/lte-setup.sh internet --dry-run            # δείξε μόνο τις εντολές
#
# Τι κάνει: προσθέτει (ή διορθώνει) ΜΙΑ σύνδεση στο NetworkManager με μεγάλο route metric (700), ώστε το default
# route της ενσύρματης (metric ~100) να προτιμάται πάντα και το LTE να μένει εφεδρεία. Δεν αγγίζει τίποτα άλλο.
# APN: Cosmote «internet», Vodafone GR «internet.vodafone.gr», Nova/Wind «gint.b-online.gr» — ρώτα τον πάροχό σου.
# Το PIN της SIM καλύτερα να είναι απενεργοποιημένο (βάλ' τη μία φορά σε κινητό και κλείσ' το).
set -euo pipefail

DRY=0; APN=""; NAME="netwatch-lte"; METRIC="700"; TETHER=""

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --name) NAME="${2:-}"; shift ;;
    --metric) METRIC="${2:-}"; shift ;;
    --tether) TETHER="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "Άγνωστη επιλογή: $1" >&2; usage >&2; exit 2 ;;
    *) if [[ -z "$APN" ]]; then APN="$1"; else echo "Περίσσιο όρισμα: $1" >&2; exit 2; fi ;;
  esac
  shift
done

[[ "$METRIC" =~ ^[0-9]{1,5}$ && "$METRIC" -ge 200 ]] || { echo "✖ Το metric πρέπει να είναι αριθμός ≥ 200 (η ενσύρματη έχει ~100)." >&2; exit 2; }
[[ "$NAME" =~ ^[A-Za-z0-9_.-]{1,40}$ ]] || { echo "✖ Μη έγκυρο όνομα σύνδεσης: $NAME" >&2; exit 2; }
if [[ -n "$TETHER" ]]; then
  [[ "$TETHER" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]] || { echo "✖ Μη έγκυρη διεπαφή: $TETHER" >&2; exit 2; }
  [[ -z "$APN" ]] || { echo "✖ Με --tether δεν χρειάζεται APN (το έχει το modem/κινητό)." >&2; exit 2; }
else
  [[ "$APN" =~ ^[A-Za-z0-9._-]{1,63}$ ]] || { echo "✖ Δώσε το APN του παρόχου, π.χ.: $0 internet" >&2; usage >&2; exit 2; }
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  if [[ $DRY -eq 1 ]]; then
    echo "⚠ Αυτό δεν είναι Linux ($(uname -s)) — δείχνω μόνο τις εντολές."
  else
    echo "✖ Το lte-setup.sh είναι για Linux με NetworkManager (Raspberry Pi OS). Δοκίμασε --dry-run." >&2; exit 1
  fi
fi
if [[ $DRY -eq 0 ]]; then
  [[ $EUID -eq 0 ]] || { echo "✖ Θέλει sudo." >&2; exit 1; }
  command -v nmcli >/dev/null || { echo "✖ Δεν βρέθηκε το nmcli (sudo apt install network-manager modemmanager)." >&2; exit 1; }
fi

run() { if [[ $DRY -eq 1 ]]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }
exists() { [[ $DRY -eq 0 ]] && nmcli -t -f NAME connection show 2>/dev/null | grep -Fxq -- "$1"; }

if [[ -n "$TETHER" ]]; then
  echo "▸ Διεπαφή $TETHER (HiLink / USB tethering): route metric $METRIC"
  CON=""
  if [[ $DRY -eq 0 ]]; then
    CON="$(nmcli -g GENERAL.CONNECTION device show "$TETHER" 2>/dev/null | head -n1 || true)"
    [[ -n "$CON" && "$CON" != "--" ]] || { echo "✖ Η $TETHER δεν έχει ενεργή σύνδεση στο NetworkManager. Σύνδεσε το modem/κινητό και δες: nmcli device status" >&2; exit 1; }
  else
    CON="<σύνδεση της $TETHER>"
  fi
  run nmcli connection modify "$CON" ipv4.route-metric "$METRIC" ipv6.route-metric "$METRIC" connection.autoconnect yes
  run nmcli connection up "$CON"
else
  if exists "$NAME"; then
    echo "▸ Η σύνδεση «$NAME» υπάρχει ήδη — ενημερώνω APN και metric"
    run nmcli connection modify "$NAME" gsm.apn "$APN" ipv4.route-metric "$METRIC" ipv6.route-metric "$METRIC" connection.autoconnect yes
  else
    echo "▸ Νέα σύνδεση GSM «$NAME» (APN $APN, route metric $METRIC)"
    run nmcli connection add type gsm ifname '*' con-name "$NAME" apn "$APN" connection.autoconnect yes \
      ipv4.route-metric "$METRIC" ipv6.route-metric "$METRIC"
  fi
  echo "▸ Σύνδεση (αν το modem είναι στη θέση του)"
  if [[ $DRY -eq 1 ]]; then
    run nmcli connection up "$NAME"
  elif ! nmcli connection up "$NAME"; then
    echo "  ⚠ Δεν συνδέθηκε τώρα — θα συνδεθεί μόνο του όταν βρεθεί modem. Δες: mmcli -L · nmcli device status · journalctl -u ModemManager -n 30"
  fi
fi

cat <<EOF

✔ Έτοιμο$(if [[ $DRY -eq 1 ]]; then echo " (dry-run: δεν άλλαξε τίποτα)"; fi). Έλεγχος:

  ip route show default
      default via 192.168.1.1 dev eth0  proto dhcp   metric 100      ← κύρια (μικρότερο metric = προτιμάται)
      default via 10.64.64.64 dev wwan0 proto static metric $METRIC      ← LTE, μόνο εφεδρεία
  Αν το LTE έχει ΜΙΚΡΟΤΕΡΟ metric από την ενσύρματη, όλη η κίνηση θα φεύγει από τα δεδομένα κινητής!

  mmcli -L && mmcli -m 0          σήμα, πάροχος, κατάσταση SIM
  ping -I wwan0 -c 3 1.1.1.1      βγαίνει Internet από το LTE; (βάλε τη σωστή διεπαφή)
  Δοκιμή εφεδρείας: βγάλε το καλώδιο WAN του router (όχι του Pi) → σε ~1 λεπτό το NetWatch στέλνει
  «Έπεσε η κύρια γραμμή — δουλεύω από LTE». Στο NetWatch: καρτέλα «🔌 Tester πρίζας» → κάρτα «Uplink / LTE».

  Αφαίρεση:  sudo nmcli connection delete $NAME
EOF
