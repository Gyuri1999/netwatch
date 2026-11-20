#!/bin/bash
# Φτιάχνει το κλειδί υπογραφής των ενημερώσεων του NetWatch (ed25519, μία φορά).
#   ./tools/release_key.sh
# • Το ιδιωτικό κλειδί: ~/.ssh/netwatch_release (μένει στο Mac σου — ΠΟΤΕ στο git).
# • Το δημόσιο μπαίνει στο update_signers (αυτό ΝΑΙ στο git — έτσι το app ξέρει ποιον να εμπιστευτεί).
# • Μετά το βάζεις στα GitHub Secrets για να υπογράφει το workflow:  gh secret set NETWATCH_RELEASE_KEY < ~/.ssh/netwatch_release
set -euo pipefail
cd "$(dirname "$0")/.."
KEY="$HOME/.ssh/netwatch_release"
if [ -e "$KEY" ]; then
  echo "ℹ️  Υπάρχει ήδη: $KEY (δεν το αντικαθιστώ)"
else
  mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
  ssh-keygen -q -t ed25519 -N "" -C "netwatch-release" -f "$KEY"   # χωρίς passphrase: το χρησιμοποιεί το CI
  echo "✔ Νέο κλειδί: $KEY"
fi
LINE="netwatch-release namespaces=\"netwatch-update\" $(cut -d' ' -f1,2 "$KEY.pub")"
grep -qF "$(cut -d' ' -f2 "$KEY.pub")" update_signers || echo "$LINE" >> update_signers
echo "✔ Το δημόσιο κλειδί είναι στο update_signers — κάνε commit αυτό το αρχείο."
echo "➜ Επόμενο βήμα (ανεβάζει το ιδιωτικό κλειδί ΜΟΝΟ στα κρυφά Secrets του repo σου):"
echo "   gh secret set NETWATCH_RELEASE_KEY < $KEY"
