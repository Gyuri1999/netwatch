#!/usr/bin/env bash
# Φτιάχνει δική σου CA + πιστοποιητικό για τον Mosquitto broker, ώστε να περάσεις από 1883 (ανοιχτό) σε 8883 (TLS).
#
#   ./tools/mosquitto-tls.sh 192.168.1.17 [broker.lan]
#
# Τρέχει στον υπολογιστή σου (όχι στον broker) και γράφει στο ./iot-ca/:
#   ca.key          ΤΟ ΜΥΣΤΙΚΟ ΤΗΣ CA — κράτα το offline, ΜΗΝ το αντιγράψεις στον broker
#   ca.crt          μπαίνει στον broker, στο NetWatch (ca_file) και στα ESP32 (CA_CERT)
#   broker.key/.crt μπαίνουν στον broker
#   mosquitto-tls.conf   έτοιμο κομμάτι για /etc/mosquitto/conf.d/
#   ca_cert.h       το ca.crt ως C string για το secrets.h των ESP32
# Δεν αλλάζει τίποτα στον broker μόνο του — στο τέλος τυπώνει τις εντολές για να τα αντιγράψεις εσύ.
set -euo pipefail

IP="${1:-}"
NAME="${2:-}"
if [[ -z "$IP" || ! "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Χρήση: $0 <IP του broker> [όνομα DNS]   π.χ. $0 192.168.1.17 broker.lan" >&2
  exit 1
fi
OUT="${OUT:-./iot-ca}"
DAYS_CA=3650
DAYS_SRV=825   # οι browsers/πελάτες δεν δέχονται πολύ μεγαλύτερη διάρκεια για server certs
mkdir -p "$OUT"
cd "$OUT"
umask 077

if [[ -f ca.key ]]; then
  echo "▸ Υπάρχει ήδη CA στο $OUT — την ξαναχρησιμοποιώ (τα ESP32 που την έχουν δεν χρειάζονται αλλαγή)."
else
  echo "▸ Νέα CA (EC P-256, $DAYS_CA μέρες)"
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key
  openssl req -x509 -new -key ca.key -sha256 -days "$DAYS_CA" -subj "/CN=Home IoT CA" -out ca.crt \
    -extensions v3_ca -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
fi

echo "▸ Πιστοποιητικό broker για IP:$IP${NAME:+ και DNS:$NAME}"
SAN="IP:$IP${NAME:+,DNS:$NAME}"
openssl ecparam -name prime256v1 -genkey -noout -out broker.key
openssl req -new -key broker.key -subj "/CN=${NAME:-$IP}" -out broker.csr \
  -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n')
openssl x509 -req -in broker.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days "$DAYS_SRV" -out broker.crt \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyAgreement\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n" "$SAN")
rm -f broker.csr
openssl verify -CAfile ca.crt broker.crt >/dev/null && echo "  ✔ το broker.crt επαληθεύεται από τη CA"

cat > mosquitto-tls.conf <<EOF
# NetWatch: TLS για τον Mosquitto — αντίγραψέ το στο /etc/mosquitto/conf.d/tls.conf
per_listener_settings false
allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl
log_dest topic

# Το παλιό 1883 μόνο για το ίδιο το μηχάνημα (π.χ. Home Assistant στο ίδιο VM). Σβήσ' το αν δεν το χρειάζεσαι.
listener 1883 127.0.0.1

listener 8883
cafile /etc/mosquitto/certs/ca.crt
certfile /etc/mosquitto/certs/broker.crt
keyfile /etc/mosquitto/certs/broker.key
tls_version tlsv1.2
EOF

{
  echo "// Η CA του σπιτιού σου — βάλ' το στο secrets.h (CA_CERT) των ESP32"
  echo "static const char CA_CERT[] = R\"PEM("
  cat ca.crt
  echo ")PEM\";"
} > ca_cert.h

FP=$(openssl x509 -in broker.crt -noout -fingerprint -sha256 | cut -d= -f2)
cat <<EOF

✔ Έτοιμα στο $(pwd)
  Fingerprint broker.crt (SHA-256): $FP

Επόμενα βήματα (τα τρέχεις εσύ):
  1) Αντιγραφή στον broker:
       scp ca.crt broker.crt broker.key mosquitto-tls.conf <χρήστης>@$IP:/tmp/
       ssh <χρήστης>@$IP 'sudo install -d -o root -g mosquitto -m 750 /etc/mosquitto/certs &&
         sudo install -o root -g mosquitto -m 644 /tmp/ca.crt /tmp/broker.crt /etc/mosquitto/certs/ &&
         sudo install -o root -g mosquitto -m 640 /tmp/broker.key /etc/mosquitto/certs/ &&
         sudo install -m 644 /tmp/mosquitto-tls.conf /etc/mosquitto/conf.d/tls.conf &&
         rm /tmp/broker.key && sudo systemctl restart mosquitto'
     (Αν το mosquitto.conf έχει ήδη listener 1883 χωρίς διεύθυνση, σβήσ' τον — αλλιώς θα συγκρουστεί.)
  2) Δοκιμή από εδώ:
       mosquitto_sub -h $IP -p 8883 --cafile $(pwd)/ca.crt -u <χρήστης> -P '<κωδικός>' -t '\$SYS/broker/version' -C 1
  3) ESP32: αντίγραψε το ca_cert.h στο secrets.h, άλλαξε θύρα σε 8883 και ξαναπέρασε το firmware.
  4) NetWatch config.yaml: port: 8883 και ca_file: $(pwd)/ca.crt (στα mqtt_guard / sensor / homeassistant).
  5) Στο NetWatch → 🔌 IoT μου → ▶ Έλεγχος: το «MQTT χωρίς TLS (1883)» πρέπει να γίνει «MQTT με TLS (8883)» 👍

  ⚠ Το ca.key δεν πάει ΠΟΥΘΕΝΑ. Όποιος το έχει, φτιάχνει «έγκυρους» ψεύτικους brokers για τα ESP32 σου.
EOF
