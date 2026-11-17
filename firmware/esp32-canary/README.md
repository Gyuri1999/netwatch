# NetWatch Canary (ESP32)

Ένα ESP32 που **προσποιείται μια ξεχασμένη IP κάμερα** στο δίκτυο. Δεν κάνει
τίποτα χρήσιμο, και ακριβώς γι' αυτό είναι χρήσιμο: **κανείς νόμιμος δεν έχει
λόγο να του μιλήσει**. Αν κάποιος ανοίξει σύνδεση στο Telnet ή στη σελίδα admin
του, κάποιος **σκανάρει ή επιτίθεται** στο LAN σου, και το NetWatch το μαθαίνει
αμέσως μέσω **MQTT over TLS** (Mosquitto στο Raspberry Pi).

| Θύρα | Τι "δείχνει" | Τι κάνει στην πραγματικότητα |
|---|---|---|
| 23 (Telnet) | `Hikvision-DS2CD login:` → `Password:` | διαβάζει έως 2 γραμμές (10 s), απαντά `Login incorrect`, κλείνει |
| 80 (HTTP) | σελίδα admin με κωδικό | πάντα `401 Unauthorized` + `WWW-Authenticate: Basic realm="IPCamera"` |
| 8080 (HTTP) | ίδιο με το 80 | προαιρετικό (`CANARY_ENABLE_8080`) |
| mDNS | `camera-salon.local`, `_http._tcp` (80), `_telnet._tcp` (23) | για να το βρίσκουν τα εργαλεία ανακάλυψης |

Κάθε σύνδεση → ένα γεγονός στο `netwatch/sensor/<id>/event`.

## 1. Γιατί δουλεύει ένα "καναρίνι"

Τα περισσότερα συστήματα ανίχνευσης ψάχνουν "ύποπτη" συμπεριφορά μέσα σε
πολλή **κανονική** κίνηση, άρα κάνουν λάθη (ψευδείς συναγερμούς). Η παγίδα
είναι το αντίθετο: **δεν υπάρχει κανονική κίνηση προς αυτήν**. Καμία δική σου
συσκευή δεν τη χρησιμοποιεί, δεν είναι σε κανένα bookmark, καμία εφαρμογή δεν
την ξέρει. Άρα:

- **Σχεδόν μηδέν ψευδείς συναγερμοί.** Όποιος συνδεθεί, είτε σκανάρει
  (nmap, Shodan‑style scripts, malware τύπου Mirai που ψάχνει Telnet) είτε
  δοκιμάζει κωδικούς.
- **Πιάνει αυτό που τα logs του router δεν βλέπουν:** κίνηση **μέσα** στο LAN /
  VLAN (π.χ. μια "έξυπνη" πρίζα που μολύνθηκε και ψάχνει το επόμενο θύμα).
- **Μοιάζει με εύκολο στόχο:** Telnet + κάμερα Hikvision είναι από τα πρώτα
  που δοκιμάζουν τα botnet.

Οι μόνες "αθώες" συνδέσεις είναι οι **δικοί σου** έλεγχοι (π.χ. ένα port scan
του NetWatch ή ένα δικό σου `nmap`). Αυτές τις εξαιρείς με το
`CANARY_IGNORE_IPS` στο `secrets.h`.

## 2. Πού να το βάλεις

- **Στο IoT VLAN / IoT SSID**, δίπλα στις κάμερες, πρίζες, τηλεοράσεις. Εκεί
  ζουν οι συσκευές που μολύνονται πιο εύκολα, και από εκεί ξεκινά συνήθως η
  "πλευρική κίνηση" (lateral movement).
- Αν δεν έχεις VLAN, στο κύριο δίκτυο: πάλι δουλεύει.
- Δύο καναρίνια (ένα σε κάθε VLAN) δίνουν καλύτερη κάλυψη. Κάθε ESP32 παίρνει
  αυτόματα δικό του id από τη MAC.
- Firewall: από το IoT VLAN επίτρεψε **μόνο** `καναρίνι → Pi:8883`. Το
  καναρίνι δεν χρειάζεται τίποτε άλλο (ούτε internet).
- Δώσε του **σταθερή IP** (DHCP reservation) και ένα πιστευτό όνομα
  (`CANARY_HOSTNAME`, π.χ. `camera-salon`, `nvr-garage`).

## 3. Υλικό και αρχεία

Οποιαδήποτε ESP32 dev board (ESP32‑DevKitC, WROOM‑32, NodeMCU‑32S κ.λπ.) και ένα
τροφοδοτικό USB. Καμία εξωτερική βιβλιοθήκη: μόνο ό,τι έρχεται με τον πυρήνα
**arduino‑esp32 3.x** (`WiFi.h`, `ESPmDNS.h`, `Preferences` και το
`mqtt_client.h` του ESP‑IDF). Το JSON φτιάχνεται με `snprintf`.

| Αρχείο | Ρόλος |
|---|---|
| `esp32-canary.ino` | το firmware |
| `canary_types.h` | struct/enum (σε header για να μη σκοντάφτουν τα αυτόματα prototypes του Arduino) |
| `secrets.example.h` | πρότυπο όλων των ρυθμίσεων |
| `secrets.h` | **οι δικές σου** ρυθμίσεις, αγνοείται από το git (`.gitignore`) |
| `../common/` | κοινή βιβλιοθήκη `NetWatchSignedOta` για το (προαιρετικό) υπογεγραμμένο OTA |

```bash
cp secrets.example.h secrets.h   # και συμπλήρωσε το secrets.h
```

Η CA και το πιστοποιητικό του broker είναι **τα ίδια** με του Sentinel: βλ.
[`../esp32-sentinel/README.md`](../esp32-sentinel/README.md), ενότητα 3. Το
περιεχόμενο του `ca.crt` (δημόσιο) μπαίνει στο `MQTT_CA_PEM` και το `MQTT_HOST`
πρέπει να υπάρχει στο SAN του `server.crt`. Ο έλεγχος πιστοποιητικού είναι
**πάντα ενεργός**.

## 4. Mosquitto: χρήστης και ACL για το καναρίνι

Ξεχωριστός χρήστης ανά καναρίνι, με δικαίωμα **μόνο εγγραφής** και **μόνο**
στα δικά του topics:

```bash
sudo mosquitto_passwd /etc/mosquitto/passwd canary
```

Στο `/etc/mosquitto/acl` (δίπλα στους κανόνες του `sentinel` / `netwatch`):

```text
# Το καναρίνι μόνο ΓΡΑΦΕΙ, και μόνο στο δικό του δέντρο (και το LWT του)
user canary
topic write netwatch/sensor/canary-a1b2c3/#
```

Το `canary-a1b2c3` είναι το id που τυπώνει το Serial στην εκκίνηση
(`id=canary-…`). Το NetWatch εμπιστεύεται το id του **topic**, όχι του payload,
άρα το ACL εμποδίζει ένα παραβιασμένο καναρίνι να "υποδυθεί" άλλον αισθητήρα.

```bash
sudo systemctl restart mosquitto
```

## 5. Flash

### arduino-cli

```bash
cd ~/netwatch/firmware/esp32-canary
arduino-cli compile --fqbn esp32:esp32:esp32 .
arduino-cli upload  --fqbn esp32:esp32:esp32 -p /dev/cu.usbserial-0001 .   # Linux: /dev/ttyUSB0
arduino-cli monitor -p /dev/cu.usbserial-0001 -c baudrate=115200
```

(`arduino-cli board list` δείχνει τη σωστή θύρα.)

### Υπογεγραμμένο OTA (προαιρετικό)

Με `OTA_ENABLE 1` στο `secrets.h` το καναρίνι ρωτά στην εκκίνηση και κάθε 6 ώρες τον OTA
server σου για νέο firmware, και εγκαθιστά **μόνο** υπογεγραμμένη (ECDSA P-256), **αυστηρά
νεότερη** έκδοση, με rollback αν το νέο firmware δεν συνδεθεί στο MQTT σε 5 λεπτά. Κλειδιά,
server και workflow: [`../../tools/ota/README.md`](../../tools/ota/README.md).

Ο κώδικας είναι στην κοινή βιβλιοθήκη `../common` (`NetWatchSignedOta`), οπότε η
μεταγλώττιση θέλει `--library`:

```bash
arduino-cli compile --fqbn esp32:esp32:esp32 --library ../common .
# νέα έκδοση για OTA: ανέβασε το FW_VERSION στο .ino, και μετά
arduino-cli compile --fqbn esp32:esp32:esp32 --library ../common --output-dir /tmp/canary-build .
python3 ../../tools/ota/ota_sign.py /tmp/canary-build/esp32-canary.ino.bin --version <FW_VERSION> --device-class canary
```

Στο Arduino IDE: `ln -s "$(cd ../common && pwd)" ~/Documents/Arduino/libraries/NetWatchSignedOta`.
Με `OTA_ENABLE 0` (προεπιλογή) η βιβλιοθήκη δεν χρειάζεται και τίποτα δεν αλλάζει.
Partition scheme: το προεπιλεγμένο (δύο OTA partitions)· **όχι** «Huge APP».

### Arduino IDE

1. Boards Manager: εγκατάσταση **esp32 by Espressif** (3.x).
2. Άνοιξε το `esp32-canary.ino` (το IDE ανοίγει και τα `.h` ως καρτέλες).
3. Board: **ESP32 Dev Module**, επίλεξε θύρα, **Upload**.
4. Serial Monitor στα **115200** baud.

Στην εκκίνηση θα δεις κάτι σαν:

```text
 NetWatch Canary v1.1.0  id=canary-a1b2c3
[wifi] connected, ip 192.168.20.37 rssi -58 hostname camera-salon
[mdns] camera-salon.local: _http._tcp:80 _telnet._tcp:23
[trap] listening on 23 (telnet), 80 (http), 8080 (http)
[mqtt] connected (TLS verified)
[mqtt] status -> {"id":"canary-a1b2c3","online":true,...}
```

## 6. Δοκιμή

Από **άλλο** μηχάνημα του ίδιου δικτύου/VLAN (όχι από IP που είναι στο
`CANARY_IGNORE_IPS`):

```bash
nc <canary-ip> 23
#   Hikvision-DS2CD login: admin
#   Password: οτιδήποτε
#   Login incorrect

curl -i -u test:x http://<canary-ip>/
#   HTTP/1.1 401 Unauthorized
#   WWW-Authenticate: Basic realm="IPCamera"
```

Στο Serial θα δεις `[ALERT] canary …` και `[mqtt] event -> …`, και στο NetWatch
την ειδοποίηση. Το `curl` θα αναφερθεί με `"user":"test"`, **χωρίς** τον κωδικό
`x`. Ξαναδοκιμή από την ίδια IP στην ίδια θύρα μέσα σε 30 s **δεν** βγάζει νέο
γεγονός (rate limit), μετριέται όμως στο `suppressed`.

## 7. Πώς εμφανίζεται στο NetWatch

Το NetWatch χρησιμοποιεί την ίδια ρύθμιση `sensor:` του `config.yaml` με τον
Sentinel (ο χρήστης `netwatch` διαβάζει `netwatch/sensor/#`). Δεν χρειάζεται
τίποτα επιπλέον.

- Καρτέλα **📡 Αισθητήρες**: το καναρίνι εμφανίζεται ως αισθητήρας
  `canary-…` (`kind: canary`) με uptime, RSSI, IP, `canary_hits` και
  `suppressed`. Θεωρείται offline αν λείψει heartbeat για > 90 s ή αν έρθει το LWT.
- Καρτέλα **⚠ Επιθέσεις**: κάθε γεγονός γίνεται ειδοποίηση υψηλής σοβαρότητας
  **«Παγίδα (ESP32 καναρίνι)»**, με «δράστη» την IP που άγγιξε την παγίδα, π.χ.
  *«Η 192.168.20.14 άγγιξε το ψεύτικο telnet (θύρα 23) του καναρινιού
  canary-a1b2c3 — δοκίμασε χρήστη «root»…»*.

## 8. Topics και payloads

`<id>` = `canary-` + τα 3 τελευταία bytes της MAC σε πεζά hex, χωρίς `:`.

**`netwatch/sensor/<id>/status`** (retained, QoS 1, κάθε 30 s και αμέσως μετά από κάθε σύνδεση):

```json
{"id":"canary-a1b2c3","online":true,"fw":"1.1.0","uptime":123,"heap":190000,"rssi":-58,"ip":"192.168.20.37","canary_hits":3,"suppressed":1,"kind":"canary"}
```

LWT (retained) στο ίδιο topic: `{"online":false}`.
`canary_hits` = όλες οι συνδέσεις (και όσες δεν έβγαλαν γεγονός)·
`suppressed` = συνδέσεις που **δεν** έβγαλαν γεγονός λόγω rate limit ή γεμάτης ουράς.
Και οι δύο είναι σωρευτικοί και διατηρούνται στη flash μετά από επανεκκίνηση.

**`netwatch/sensor/<id>/event`** (όχι retained, QoS 1):

```json
{"type":"canary","id":"canary-a1b2c3","port":23,"src":"192.168.20.14","service":"telnet","data":"root / ***","user":"root","t":5321}
{"type":"canary","id":"canary-a1b2c3","port":80,"src":"192.168.20.14","service":"http","data":"GET /Security/users?auth=*** HTTP/1.1","user":"","t":5330}
```

- `data`: η πρώτη γραμμή, μόνο εκτυπώσιμοι ASCII (οι υπόλοιποι γίνονται `.`),
  έως 80 χαρακτήρες. Telnet: το όνομα χρήστη και ` / ***` αν στάλθηκε γραμμή
  κωδικού. HTTP: η request line, με τις τιμές παραμέτρων όπως `pass`, `pwd`,
  `auth`, `token`, `key`, `secret`, `sid` να γίνονται `***`.
- `user`: Telnet: η γραμμή `login:`· HTTP: **μόνο** το όνομα από το
  `Authorization: Basic` (αποκωδικοποιείται ως το `:` και σταματά). Αλλιώς `""`.
- `t` = uptime (s) τη στιγμή της σύνδεσης.

**Υπογεγραμμένο OTA** (μόνο με `OTA_ENABLE 1`), στο ίδιο event topic:

```json
{"type":"ota","id":"canary-a1b2c3","result":"up_to_date","reason":"running 1.1.0","version":"1.1.0","fw":"1.1.0","t":12}
{"type":"ota","id":"canary-a1b2c3","result":"updated","reason":"1.1.0 -> 1.2.0","version":"1.2.0","fw":"1.2.0","t":41}
{"type":"ota","id":"canary-a1b2c3","result":"rejected","reason":"bad signature","version":"1.3.0","fw":"1.2.0","t":21650}
```

`result` ∈ `up_to_date`, `updated` (το στέλνει το **νέο** firmware αφού περάσει το self-test),
`rejected` (λόγος ασφαλείας: υπογραφή, sha256, rollback, κατηγορία, αποτυχημένο self-test → **ερεύνησέ το**),
`error` (δίκτυο/server/ρυθμίσεις· ξαναδοκιμάζει σε 6 ώρες). Το `fw` του heartbeat δείχνει την έκδοση που τρέχει.

## 9. Όρια και σχεδιαστικές επιλογές

- **Rate limit:** το πολύ 1 γεγονός ανά IP+θύρα ανά 30 s, και το πολύ 20
  γεγονότα/λεπτό συνολικά (`RATE_PER_SOURCE_S`, `RATE_GLOBAL_PER_MIN`). Ένα
  `nmap` σε όλο το subnet δεν πλημμυρίζει ούτε το MQTT ούτε τις ειδοποιήσεις.
- **Χωρίς μπλοκαρίσματα:** οι servers είναι non‑blocking και κάθε σύνδεση έχει
  δική της μηχανή καταστάσεων με timeout (Telnet 10 s, HTTP 5 s, έως 4096 bytes).
  Έως 4 ταυτόχρονες συνδέσεις· αν είναι όλες πιασμένες, η νέα καταγράφεται
  και κλείνει αμέσως. Το MQTT (keepalive, TLS, επανασύνδεση) τρέχει στο δικό
  του task του esp‑mqtt, άρα ένας αργός επισκέπτης δεν το επηρεάζει.
- **Ουρά:** αν ο broker είναι προσωρινά κάτω, έως 8 γεγονότα περιμένουν στη
  RAM· αν γεμίσει, χάνεται το παλαιότερο (μετριέται στο `suppressed`).
- **Flash:** οι μετρητές γράφονται το πολύ μία φορά ανά heartbeat (όχι ανά
  σύνδεση), ώστε μια "πλημμύρα" να μη φθείρει τη flash.
- **SYN scan:** ένα `nmap -sS` (half‑open) δεν ολοκληρώνει τη σύνδεση, άρα δεν
  φτάνει στο firmware. Τα περισσότερα εργαλεία/botnet όμως συνδέονται κανονικά
  (`-sT`, `-sV`, scripts, brute force), και αυτά πιάνονται.
- **IPv6:** οι διευθύνσεις αναφέρονται όπως τις δίνει το lwIP· ένα IPv4‑mapped
  γίνεται κανονικό IPv4.

## 10. Ασφάλεια και ηθική

- **Μόνο ακούει.** Οι απαντήσεις είναι σταθερά, αθώα κείμενα (`login:`,
  `Login incorrect`, `401`). Καμία "αντεπίθεση", καμία σύνδεση προς τον
  επισκέπτη, καμία εκπομπή εκτός από τον broker.
- **Ποτέ κωδικοί** (ίδιος κανόνας με το NetWatch): η γραμμή κωδικού του Telnet
  δεν γράφεται ποτέ σε buffer, από το HTTP Basic αποκωδικοποιείται μόνο το
  όνομα χρήστη, οι ευαίσθητες παράμετροι URL γίνονται `***` και κάθε γραμμή
  headers σβήνεται από τη μνήμη αμέσως μετά την επεξεργασία.
- Βάλε το **μόνο στο δικό σου δίκτυο**. Δεν "ψαρεύει" ξένους: απαντά μόνο σε
  όποιον έρθει μόνος του σε μια συσκευή του δικού σου LAN.
