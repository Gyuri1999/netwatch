# NetWatch Sentinel (ESP32)

Μικρός, **παθητικός** ασύρματος αισθητήρας ασφαλείας. Ακούει το Wi‑Fi γύρω του
και στέλνει αναφορές στο NetWatch μέσω **MQTT over TLS** (Mosquitto στο Raspberry Pi).

Τι ανιχνεύει:

| Ανίχνευση | Πώς | Topic / `type` |
|---|---|---|
| Deauth / disassoc flood | promiscuous mode, εναλλαγή καναλιών 1–13, μέτρηση πλαισίων 0xC0/0xA0 ανά κανάλι ανά δευτερόλεπτο (όριο `DEAUTH_THRESHOLD`, προεπιλογή 10/s) | `event` / `deauth` |
| Evil twin | το `PROTECTED_SSID` εμφανίζεται με **ασθενέστερη** ασφάλεια από την `EXPECTED_SECURITY` (π.χ. open/WEP) | `event` / `evil_twin` |
| Rogue AP | το `PROTECTED_SSID` εμφανίζεται από BSSID που **δεν** είναι στο `ALLOWED_BSSIDS`, με ίδια ασφάλεια | `event` / `rogue_ap` |
| Heartbeat | κάθε ~30 s: uptime, heap, RSSI, IP, έκδοση, μετρητές | `status` (retained) |

## 1. Υλικό

- **Οποιαδήποτε ESP32 dev board** (ESP32‑DevKitC, ESP32‑WROOM‑32, NodeMCU‑32S κ.λπ.).
- Καλώδιο USB (με δεδομένα, όχι μόνο φόρτισης).
- Raspberry Pi με Mosquitto 2.x (ο broker) και NetWatch.

Δεν χρειάζεται καμία εξωτερική βιβλιοθήκη: ο κώδικας χρησιμοποιεί μόνο ό,τι
έρχεται με τον πυρήνα **arduino‑esp32 3.x** (`WiFi.h`, `esp_wifi.h`, `Preferences`
και το `mqtt_client.h` του ESP‑IDF). Το JSON φτιάχνεται με `snprintf`.

## 2. Αρχεία

| Αρχείο | Ρόλος |
|---|---|
| `esp32-sentinel.ino` | το firmware |
| `sentinel_types.h` | struct/enum (σε header για να μη σκοντάφτουν τα αυτόματα prototypes του Arduino) |
| `secrets.example.h` | πρότυπο όλων των ρυθμίσεων |
| `secrets.h` | **οι δικές σου** ρυθμίσεις, αγνοείται από το git (`.gitignore`) |
| `../common/` | κοινή βιβλιοθήκη `NetWatchSignedOta` για το (προαιρετικό) υπογεγραμμένο OTA |

```bash
cp secrets.example.h secrets.h   # και συμπλήρωσε το secrets.h
```

## 3. CA και πιστοποιητικά στο Raspberry Pi

Η πλήρης εξήγηση βρίσκεται στο **Academy, μάθημα IoT, ενότητα 4** (μαθήματα `iot-4-*`):
`iot-4-2` (χρήστες και ACL), `iot-4-3` (δική σου CA και TLS στο 8883),
`iot-4-4` (ESP32 με TLS). Σύντομα:

```bash
mkdir -p ~/iot-ca && chmod 700 ~/iot-ca && cd ~/iot-ca

# CA (το ca.key δεν φεύγει ΠΟΤΕ από εδώ)
openssl genrsa -aes256 -out ca.key 4096
openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=Home IoT Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.crt

# Πιστοποιητικό broker: το SAN πρέπει να περιέχει το MQTT_HOST του Sentinel!
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=pi-broker.local" -out server.csr
cat > server.ext <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:pi-broker.local, IP:192.168.1.50
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile server.ext
openssl verify -CAfile ca.crt server.crt      # -> server.crt: OK

sudo mkdir -p /etc/mosquitto/certs
sudo cp ca.crt server.crt server.key /etc/mosquitto/certs/
sudo chown -R mosquitto:mosquitto /etc/mosquitto/certs
sudo chmod 600 /etc/mosquitto/certs/server.key
```

Το **περιεχόμενο του `ca.crt`** (δημόσιο) επικολλάται στο `MQTT_CA_PEM` του `secrets.h`.

> Ο έλεγχος πιστοποιητικού είναι **πάντα ενεργός**. Αν στο Serial δεις
> `certificate verification FAILED`, έλεγξε ότι (α) το `MQTT_CA_PEM` είναι το σωστό
> `ca.crt` και (β) το `MQTT_HOST` υπάρχει στο SAN του `server.crt`. Μην τον απενεργοποιήσεις.

## 4. Mosquitto: listener 8883 και ACL

Χρήστες (ο καθένας με δικό του κωδικό):

```bash
sudo mosquitto_passwd /etc/mosquitto/passwd sentinel   # το ESP32 (γράφει)
sudo mosquitto_passwd /etc/mosquitto/passwd netwatch   # το NetWatch (διαβάζει)
```

`/etc/mosquitto/conf.d/10-auth.conf`:

```text
per_listener_settings false
allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl

# Τοπικά, χωρίς TLS, μόνο για εργαλεία στο ίδιο το Pi
listener 1883 127.0.0.1

# TLS για το δίκτυο
listener 8883
certfile /etc/mosquitto/certs/server.crt
keyfile  /etc/mosquitto/certs/server.key
cafile   /etc/mosquitto/certs/ca.crt
```

`/etc/mosquitto/acl`:

```text
# Ο Sentinel μόνο ΓΡΑΦΕΙ αναφορές (και το LWT του)
user sentinel
topic write netwatch/sensor/#

# Το NetWatch μόνο ΔΙΑΒΑΖΕΙ
user netwatch
topic read netwatch/sensor/#
```

```bash
sudo systemctl restart mosquitto
# Δοκιμή από το Pi:
mosquitto_sub -h pi-broker.local -p 8883 --cafile ~/iot-ca/ca.crt \
  -u netwatch -P '<κωδικός>' -t 'netwatch/sensor/#' -v
```

Με πολλούς Sentinel, ασφαλέστερο είναι ένας χρήστης ανά συσκευή και
`pattern write netwatch/sensor/%c/#` (το `%c` = client id, π.χ. `sentinel-a1b2c3`).

## 5. Flash

### arduino-cli

```bash
cd ~/netwatch/firmware/esp32-sentinel
arduino-cli compile --fqbn esp32:esp32:esp32 .
arduino-cli upload  --fqbn esp32:esp32:esp32 -p /dev/cu.usbserial-0001 .   # Linux: /dev/ttyUSB0
arduino-cli monitor -p /dev/cu.usbserial-0001 -c baudrate=115200
```

(`arduino-cli board list` δείχνει τη σωστή θύρα.)

### Υπογεγραμμένο OTA (προαιρετικό)

Με `OTA_ENABLE 1` στο `secrets.h` το Sentinel ρωτά στην εκκίνηση και κάθε 6 ώρες τον OTA
server σου για νέο firmware, και εγκαθιστά **μόνο** υπογεγραμμένη (ECDSA P-256), **αυστηρά
νεότερη** έκδοση, με rollback αν το νέο firmware δεν συνδεθεί στο MQTT σε 5 λεπτά. Κλειδιά,
server και workflow: [`../../tools/ota/README.md`](../../tools/ota/README.md).

Ο κώδικας είναι στην κοινή βιβλιοθήκη `../common` (`NetWatchSignedOta`), οπότε η
μεταγλώττιση θέλει `--library`:

```bash
arduino-cli compile --fqbn esp32:esp32:esp32 --library ../common .
# νέα έκδοση για OTA: ανέβασε το FW_VERSION στο .ino, και μετά
arduino-cli compile --fqbn esp32:esp32:esp32 --library ../common --output-dir /tmp/sentinel-build .
python3 ../../tools/ota/ota_sign.py /tmp/sentinel-build/esp32-sentinel.ino.bin --version <FW_VERSION> --device-class sentinel
```

Στο Arduino IDE: `ln -s "$(cd ../common && pwd)" ~/Documents/Arduino/libraries/NetWatchSignedOta`.
Με `OTA_ENABLE 0` (προεπιλογή) η βιβλιοθήκη δεν χρειάζεται και τίποτα δεν αλλάζει.
Partition scheme: το προεπιλεγμένο (δύο OTA partitions)· **όχι** «Huge APP».

### Arduino IDE

1. Boards Manager: εγκατάσταση **esp32 by Espressif** (3.x).
2. Άνοιξε το `esp32-sentinel.ino` (το IDE ανοίγει και τα `.h` ως καρτέλες).
3. Board: **ESP32 Dev Module**, επίλεξε θύρα, **Upload**.
4. Serial Monitor στα **115200** baud.

Στην εκκίνηση θα δεις το id, π.χ. `id=sentinel-a1b2c3`, και μετά τους κύκλους
`[sniff]` / `[scan]` / `[wifi]` / `[mqtt]`.

## 6. Topics και payloads

`<id>` = `sentinel-` + τα 3 τελευταία bytes της MAC σε πεζά hex, χωρίς `:`.

**`netwatch/sensor/<id>/status`** (retained, QoS 1):

```json
{"id":"sentinel-a1b2c3","online":true,"fw":"1.1.0","uptime":123,"heap":180000,"rssi":-55,"ip":"192.168.1.50","deauth_total":0,"twins_total":0}
```

LWT (retained) στο ίδιο topic: `{"online":false}`.
Το `twins_total` μετρά **και** τα `evil_twin` **και** τα `rogue_ap`.
Οι μετρητές διατηρούνται στη flash (Preferences) και μετά από επανεκκίνηση.

**`netwatch/sensor/<id>/event`** (όχι retained, QoS 1):

```json
{"type":"deauth","id":"sentinel-a1b2c3","channel":6,"count":42,"window_s":1,"bssid":"aa:bb:cc:dd:ee:ff","target":"ff:ff:ff:ff:ff:ff","rssi":-60,"t":5321}
{"type":"evil_twin","id":"sentinel-a1b2c3","ssid":"HomeWiFi","bssid":"11:22:33:44:55:66","security":"open","channel":11,"rssi":-48,"t":5400}
{"type":"rogue_ap","id":"sentinel-a1b2c3","ssid":"HomeWiFi","bssid":"66:55:44:33:22:11","security":"wpa2","channel":1,"rssi":-70,"t":5400}
```

- `t` = uptime (s) **τη στιγμή της ανίχνευσης** (όχι της αποστολής).
- deauth: `bssid` = διεύθυνση αποστολέα (addr2) του τελευταίου πλαισίου στο παράθυρο·
  `target` = `ff:ff:ff:ff:ff:ff` αν έστω ένα πλαίσιο ήταν broadcast, αλλιώς ο παραλήπτης.
- `security` ∈ `open, owe, wep, wpa, wpa/wpa2, wpa-ent, wpa2, wpa2-ent, wpa2/wpa3, wapi, wpa3, wpa3-ent, unknown`.
- Το ίδιο BSSID για evil twin/rogue AP αναφέρεται ξανά το πολύ κάθε 10 λεπτά.

**Υπογεγραμμένο OTA** (μόνο με `OTA_ENABLE 1`), στο ίδιο event topic:

```json
{"type":"ota","id":"sentinel-a1b2c3","result":"up_to_date","reason":"running 1.1.0","version":"1.1.0","fw":"1.1.0","t":12}
{"type":"ota","id":"sentinel-a1b2c3","result":"updated","reason":"1.1.0 -> 1.2.0","version":"1.2.0","fw":"1.2.0","t":41}
{"type":"ota","id":"sentinel-a1b2c3","result":"rejected","reason":"bad signature","version":"1.3.0","fw":"1.2.0","t":21650}
```

`result` ∈ `up_to_date`, `updated` (το στέλνει το **νέο** firmware αφού περάσει το self-test),
`rejected` (λόγος ασφαλείας: υπογραφή, sha256, rollback, κατηγορία, αποτυχημένο self-test → **ερεύνησέ το**),
`error` (δίκτυο/server/ρυθμίσεις· ξαναδοκιμάζει σε 6 ώρες). Το `fw` του heartbeat δείχνει την έκδοση που τρέχει.

## 7. Ρύθμιση στο NetWatch

Στο `config.yaml` του NetWatch, ενότητα `sensor:`:

```yaml
sensor:
  mqtt_host: pi-broker.local
  mqtt_port: 8883
  ca_file: /etc/mosquitto/certs/ca.crt   # ή ~/iot-ca/ca.crt
  username: netwatch
  password: "<κωδικός του χρήστη netwatch>"
  topic: netwatch/sensor/#               # προεπιλογή
```

## 8. Σχεδιαστικές επιλογές (trade-offs)

**Ένα ραδιόφωνο, δύο δουλειές.** Το ESP32 δεν μπορεί να ακούει όλα τα κανάλια
και ταυτόχρονα να μένει συνδεδεμένο (η σύνδεση το κλειδώνει στο κανάλι του router).
Γι' αυτό τρέχει κύκλο:

```
[SNIFF ~22 s: κανάλια 1..13, 1 s το καθένα] -> [ONLINE ~5-8 s: scan κάθε ~60 s, Wi-Fi, MQTT, publish] -> ...
```

- **Τυφλό διάστημα:** όσο είναι ONLINE δεν ακούει. Ένα σύντομο flood μπορεί να χαθεί.
- **Καθυστέρηση:** οι αναφορές φτάνουν έως ~1 κύκλο (~30 s) μετά την ανίχνευση.
- **Κάλυψη:** κάθε κανάλι ακούγεται ~1 s ανά 13 s (~8% του χρόνου). Μια επίθεση
  που κρατά λίγα δευτερόλεπτα μπορεί να μη "πέσει" πάνω στο κανάλι της.
  Οι πραγματικές deauth επιθέσεις συνήθως διαρκούν αρκετά για να εντοπιστούν.
- **Ουρά:** τα γεγονότα κρατιούνται σε ring buffer 16 θέσεων· αν γεμίσει,
  χάνεται το παλαιότερο (το Serial δείχνει πόσα χάθηκαν).
- **LWT και κύκλος:** στο τέλος κάθε ONLINE γίνεται ομαλό MQTT DISCONNECT, άρα ο broker
  **δεν** στέλνει LWT σε κάθε φάση sniff. Το LWT πιάνει μόνο απότομη απώλεια ενώ είναι
  συνδεδεμένος. Αν ο αισθητήρας "πεθάνει" ενώ ακούει, το retained status μένει
  `online:true`: το NetWatch καλό είναι να θεωρεί τον αισθητήρα offline αν δεν έρθει
  heartbeat για ~3 κύκλους (~90 s).
- Όλοι οι χρονισμοί ρυθμίζονται στο `secrets.h` (`SNIFF_SECONDS`, `CHANNEL_DWELL_MS`, …).
  Για συνεχή ακρόαση χωρίς τυφλό διάστημα, η λύση είναι **δύο** ESP32
  (ένας ακούει, ένας στέλνει μέσω UART) ή ένα Pi με κάρτα σε monitor mode.

## 9. Περιορισμοί και ηθική

- **Μόνο παθητική ανίχνευση.** Το firmware **δεν** στέλνει ποτέ deauth/disassoc ή άλλα
  πλαίσια διαχείρισης, δεν χρησιμοποιεί `esp_wifi_80211_tx()`, δεν κάνει "αντεπίθεση"
  και δεν συνδέεται σε ξένα δίκτυα. Η αποστολή deauth σε δίκτυα τρίτων είναι
  **παράνομη** (παρεμβολή σε ραδιοεπικοινωνίες) και δεν έχει θέση εδώ.
- Η ακρόαση πλαισίων διαχείρισης (που εκπέμπονται ανοιχτά) για την άμυνα του
  **δικού σου** δικτύου είναι νόμιμη. Το firmware δεν διαβάζει δεδομένα χρηστών:
  το φίλτρο κρατά μόνο πλαίσια διαχείρισης και κρατά μόνο διευθύνσεις MAC, κανάλι και RSSI.
- Μόνο 2,4 GHz (κανάλια 1–13): το ESP32 δεν βλέπει 5 GHz.
- Τα πλαίσια με **PMF/802.11w** (WPA3) προστατεύονται από πλαστά deauth· ο αισθητήρας
  θα τα μετρήσει, αλλά οι συσκευές σου δεν θα αποσυνδεθούν.
- Ένα evil twin που αντιγράφει **και** το BSSID **και** την ασφάλεια ενός νόμιμου AP
  δεν ξεχωρίζει με απλό scan.
- Το RSSI βοηθά να εκτιμήσεις απόσταση, όχι ακριβή θέση.
