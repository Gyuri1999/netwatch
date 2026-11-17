# Υπογεγραμμένο OTA για τα ESP32 του NetWatch

Ενημέρωση firmware «από τον αέρα» για το **esp32-sentinel** και το **esp32-canary**,
χωρίς να ανοίγει καμία πόρτα για ξένο firmware. Είναι η πρακτική εφαρμογή του μαθήματος
**iot-5-3 «Ασφαλή OTA updates»** της Ακαδημίας: HTTPS με δική σου CA, **ψηφιακή υπογραφή**,
**rollback** και **anti-rollback**.

| Αρχείο | Πού τρέχει | Τι κάνει |
|---|---|---|
| `ota_sign.py` | στο **Mac σου** (εκεί ζει το ιδιωτικό κλειδί) | φτιάχνει κλειδιά, υπογράφει `.bin`, ελέγχει manifest |
| `ota_server.py` | στο **Raspberry Pi / VM του Proxmox** | σερβίρει τα αρχεία με HTTPS (μόνο GET) |
| `../../firmware/common/` | στο **ESP32** | `signedOtaCheck()`: κατεβάζει, ελέγχει, εγκαθιστά |

Χωρίς νέα εξάρτηση: το `ota_sign.py` καλεί το εργαλείο **`openssl`** (subprocess) αντί για
το πακέτο `cryptography`, που δεν υπάρχει στο `.venv` του NetWatch. Δουλεύει με το LibreSSL
του macOS και με το OpenSSL του Linux. Το `ota_server.py` θέλει μόνο Python 3.9+ (stdlib).

---

## 1. Μοντέλο απειλών: γιατί ΚΑΙ TLS ΚΑΙ υπογραφή

Ένα OTA χωρίς ασφάλεια είναι κερκόπορτα: όποιος το βρει, ανεβάζει δικό του firmware και η
συσκευή γίνεται δική του (κατασκοπεία στο LAN, botnet, «νεκρός» αισθητήρας που δεν ειδοποιεί).

| Επίθεση | Τι τη σταματά |
|---|---|
| Κάποιος στο LAN «σπρώχνει» firmware στη συσκευή | Η συσκευή **ρωτά** (pull). Δεν ακούει σε καμία θύρα OTA (όχι ArduinoOTA/3232). |
| Man-in-the-middle αλλάζει το `.bin` καθ' οδόν (ARP spoofing, ψεύτικο DNS) | **TLS** με τη δική σου CA (`setCACert`): μόνο ο δικός σου server γίνεται δεκτός. |
| **Παραβιάζεται ο OTA server** (Pi/VM) και ανεβαίνει κακόβουλο `.bin` | **Υπογραφή ECDSA P-256.** Το ιδιωτικό κλειδί ΔΕΝ είναι στον server, άρα ο επιτιθέμενος δεν μπορεί να φτιάξει έγκυρη υπογραφή. Το TLS εδώ δεν βοηθά: ο server είναι «γνήσιος», απλώς είναι δικός του πια. |
| Ο επιτιθέμενος (στον server) ξαναβάζει μια **παλιά, νόμιμα υπογεγραμμένη** έκδοση με γνωστή ευπάθεια | **Anti-rollback:** δεκτή μόνο **αυστηρά νεότερη** έκδοση από την τρέχουσα *και* από την υψηλότερη επιβεβαιωμένη (αποθηκευμένη στο NVS). Η έκδοση είναι **μέσα στην υπογραφή**, άρα δεν μπορεί να «μετονομάσει» το `1.0.0.bin` σε `9.9.9`. |
| Firmware του sentinel σε canary (ή ανάποδα) | Η **κατηγορία** (`class`) είναι κι αυτή μέσα στην υπογραφή. |
| Κομμένη λήψη / διακοπή ρεύματος στη μέση | Το νέο image γράφεται στο **ανενεργό** OTA partition και γίνεται bootable μόνο στο τέλος, αφού ελεγχθούν υπογραφή + SHA-256. |
| Νέο firmware που κρασάρει ή δεν συνδέεται | **Rollback:** το νέο image ξεκινά «υπό δοκιμή». Αν δεν συνδεθεί σε Wi‑Fi **και** MQTT/TLS σε 5 λεπτά (ή κάνει reset πριν), ο bootloader γυρίζει στο παλιό. Η αποτυχημένη έκδοση δεν ξαναδοκιμάζεται. |

Με απλά λόγια: **το TLS προστατεύει τη μεταφορά, η υπογραφή προστατεύει από τον ίδιο τον
server, η μονότονη έκδοση από το «γύρνα με πίσω».**

Τι **δεν** καλύπτει (για να ξέρεις τα όρια):

- Κάποιος με **φυσική πρόσβαση** στο ESP32 το ξαναπρογραμματίζει με USB. Γι' αυτό υπάρχουν
  Secure Boot v2 + Flash Encryption (μάθημα iot-5-2), που κλειδώνουν το chip μόνιμα (eFuses).
- Το anti-rollback ζει στο NVS, όχι σε eFuses: ένα `erase_flash` με USB το μηδενίζει. Για
  OTA επιθέσεις αρκεί.
- Αν **κλαπεί το ιδιωτικό κλειδί**, ο κλέφτης υπογράφει ό,τι θέλει. Δες §5.

### Τι ακριβώς υπογράφεται

```text
netwatch-ota/1\n<class>\n<version>\n<size>\n<sha256 hex του .bin>\n
```

`sig` = ECDSA P-256, SHA-256, υπογραφή **DER** σε base64. Η συσκευή ξαναφτιάχνει αυτό το
κείμενο από τα πεδία του manifest, παίρνει το SHA-256 του (32 bytes) και καλεί
`mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, sig_der, len)`. Μετά κατεβάζει το `.bin`
και ελέγχει ότι το SHA-256 του είναι ίδιο με το υπογεγραμμένο. Η υπογραφή ελέγχεται **πριν**
γραφτεί έστω και ένα byte στη flash.

```json
{
  "format": 1,
  "class": "canary",
  "version": "1.2.0",
  "size": 1128900,
  "sha256": "a752c3b1…",
  "sig": "MEUCIHarJmY0…"
}
```

---

## 2. Κλειδιά (μία φορά, στο Mac)

```bash
python3 tools/ota/ota_sign.py --genkey
#  ~/.netwatch-ota/ota_signing.pem   ΙΔΙΩΤΙΚΟ (chmod 600) - μένει ΜΟΝΟ εδώ
#  ~/.netwatch-ota/ota_public.pem    δημόσιο (για --verify)
#  ~/.netwatch-ota/ota_public.h      δημόσιο, ως C string για το secrets.h
```

Κανόνες:

- Το `ota_signing.pem` **δεν** πάει ποτέ σε: OTA server, repository, firmware, cloud sync.
  Ο φάκελος είναι εξ ορισμού το `~/.netwatch-ota` (έξω από το git). Το `ota_server.py`
  αρνείται να ξεκινήσει αν βρει `ota_signing.pem` στο `--root`.
- Κράτα **αντίγραφο offline** (π.χ. κρυπτογραφημένο USB). Αν το χάσεις, οι συσκευές
  χρειάζονται ξανά καλώδιο (§5).
- Το δημόσιο κλειδί δεν είναι μυστικό: μόνο **ελέγχει** υπογραφές.

---

## 3. Ο server (Raspberry Pi / VM στο Proxmox)

Χρειάζεται ένα πιστοποιητικό server από τη **δική σου CA**, η ίδια που ήδη εμπιστεύονται τα
ESP32 για το MQTT (`MQTT_CA_PEM`). Αν ο OTA server είναι το ίδιο μηχάνημα με τον broker,
ξαναχρησιμοποίησε το `broker.crt/broker.key` του `tools/mosquitto-tls.sh`. Αλλιώς τρέξε το
script ξανά με την IP/όνομα του VM (ξαναχρησιμοποιεί την ίδια CA). Το όνομα στο
`OTA_BASE_URL` **πρέπει** να είναι στο SAN του πιστοποιητικού.

```bash
# στο Pi / VM
sudo useradd --system --home /srv/ota --shell /usr/sbin/nologin ota
sudo mkdir -p /srv/ota /etc/ota
sudo cp ota_server.py /usr/local/bin/
sudo cp broker.crt broker.key /etc/ota/          # το TLS κλειδί, ΟΧΙ το κλειδί υπογραφής
sudo chown -R ota: /etc/ota && sudo chmod 600 /etc/ota/broker.key
sudo chown -R $USER: /srv/ota                    # γράφεις εσύ (rsync), ο ota μόνο διαβάζει

sudo -u ota python3 /usr/local/bin/ota_server.py --root /srv/ota \
     --cert /etc/ota/broker.crt --key /etc/ota/broker.key --port 8443 --log /var/log/ota.log
```

Ως υπηρεσία systemd (`/etc/systemd/system/netwatch-ota.service`):

```ini
[Unit]
Description=NetWatch signed OTA server
After=network-online.target

[Service]
User=ota
ExecStart=/usr/bin/python3 /usr/local/bin/ota_server.py --root /srv/ota --cert /etc/ota/broker.crt --key /etc/ota/broker.key --port 8443
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/srv/ota
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Firewall: η θύρα **μόνο** για το IoT υποδίκτυο, π.χ.
`sudo ufw allow from 192.168.30.0/24 to any port 8443 proto tcp`.

Τι κάνει ο server: **μόνο GET** (τα άλλα: 405), **κανένα directory listing** (φάκελος → 404),
σερβίρει **μόνο** `/<class>/manifest.json` και `/<class>/X.Y.Z.bin`, αρνείται `../`,
`%2e%2e`, `\`, NUL, κρυφά αρχεία και symlinks που βγαίνουν από το `--root`, TLS 1.2+, και
γράφει κάθε λήψη στο log (`192.168.30.41 GET /canary/1.2.0.bin 1128900/1128900 bytes`).

---

## 4. Workflow μιας νέας έκδοσης

```bash
# 1) Ανέβασε το FW_VERSION στο .ino (π.χ. "1.2.0"): ΠΡΕΠΕΙ να είναι μεγαλύτερο από το τωρινό.

# 2) Χτίσε (στο Mac). Θέλουμε το <sketch>.ino.bin, ΟΧΙ το .merged.bin.
arduino-cli compile --fqbn esp32:esp32:esp32 --library firmware/common \
    --output-dir /tmp/canary-build firmware/esp32-canary

# 3) Υπόγραψε (ίδια έκδοση με το FW_VERSION!)
python3 tools/ota/ota_sign.py /tmp/canary-build/esp32-canary.ino.bin \
    --version 1.2.0 --device-class canary
#  -> ~/.netwatch-ota/repo/canary/1.2.0.bin + manifest.json  (αυτοέλεγχος υπογραφής)

# 4) Ανέβασε ΜΟΝΟ .bin + manifest (ποτέ το κλειδί)
rsync -av ~/.netwatch-ota/repo/ <χρήστης>@<pi>:/srv/ota/

# 5) (προαιρετικά) έλεγξε ό,τι σερβίρει ο server
curl --cacert iot-ca/ca.crt https://pi-broker.local:8443/canary/manifest.json
```

Οι συσκευές ελέγχουν στην εκκίνηση και κάθε 6 ώρες. Στο NetWatch (topic
`netwatch/sensor/<id>/event`) θα δεις:

```json
{"type":"ota","id":"canary-a1b2c3","result":"updated","reason":"1.1.0 -> 1.2.0","version":"1.2.0","fw":"1.2.0","t":41}
```

| `result` | Σημασία |
|---|---|
| `up_to_date` | ο server δεν έχει αυστηρά νεότερη έκδοση |
| `updated` | το **νέο** firmware ξεκίνησε και πέρασε το self-test (στέλνεται από το νέο firmware) |
| `rejected` | απόρριψη για λόγο **ασφαλείας**: `bad signature`, `sha256 mismatch`, `rollback refused…`, `class mismatch`, `… failed self-test, rolled back…`. **Ερεύνησέ το.** |
| `error` | πρόβλημα δικτύου/server/ρυθμίσεων (π.χ. `manifest: HTTP 404`, TLS/CA/SAN). Τίποτα δεν άλλαξε· ξαναδοκιμάζει σε 6 ώρες. |

Το `ota_sign.py` αρνείται να υπογράψει έκδοση που δεν είναι μεγαλύτερη από αυτή που ήδη
έχει το `manifest.json` του φακέλου εξόδου (για να μη «χαθεί» μια έκδοση από λάθος).

---

## 5. Αλλαγή κλειδιού (rotation)

Οι συσκευές εμπιστεύονται **ένα** δημόσιο κλειδί, μέσα στο firmware τους. Για να το αλλάξεις
χωρίς καλώδιο, το νέο κλειδί πρέπει να «ταξιδέψει» με firmware υπογεγραμμένο με το **παλιό**:

```bash
# 1) Νέο ζεύγος σε ΧΩΡΙΣΤΟ φάκελο (το παλιό μένει όπως είναι)
python3 tools/ota/ota_sign.py --genkey --keydir ~/.netwatch-ota/new

# 2) Βάλε το ~/.netwatch-ota/new/ota_public.h στο OTA_PUBKEY_PEM, ανέβασε FW_VERSION, χτίσε.

# 3) Υπόγραψε αυτό το firmware με το ΠΑΛΙΟ κλειδί (αυτό εμπιστεύονται ακόμα οι συσκευές)
python3 tools/ota/ota_sign.py build/esp32-canary.ino.bin --version 1.3.0 --device-class canary \
    --key ~/.netwatch-ota/ota_signing.pem

# 4) Όταν ΟΛΕΣ οι συσκευές αναφέρουν "updated" 1.3.0, από την επόμενη έκδοση υπογράφεις
#    με --key ~/.netwatch-ota/new/ota_signing.pem. Το παλιό κλειδί: κράτα το offline λίγο
#    ακόμα (για συσκευή που ήταν εκτός ρεύματος), μετά σβήσ' το με ασφάλεια.
```

(Το `--genkey --force` στον ίδιο φάκελο μετακινεί το παλιό σε `ota_signing.pem.bak-<ημερομηνία>`
αντί να το σβήσει, ακριβώς επειδή θα το χρειαστείς στο βήμα 3.)

**Αν κλαπεί το ιδιωτικό κλειδί:** μην εμπιστευτείς το OTA για τη διόρθωση (ο κλέφτης μπορεί
να υπογράψει κι αυτός «νεότερη» έκδοση). Βάλε `OTA_ENABLE 0` ή νέο κλειδί, και ξαναπέρασε
firmware **με καλώδιο** σε κάθε συσκευή. Μετά νέο κλειδί, νέα αρχή.

---

## 6. Στο firmware

Η κοινή βιβλιοθήκη βρίσκεται στο `firmware/common/` (`NetWatchSignedOta`):

- `signed_ota.h / .cpp`: `signedOtaCheck(baseUrl, deviceClass, currentVersion, caPem, pubKeyPem)`
  και οι βοηθητικές για self-test/rollback/αναφορά.
- `signed_ota_core.h`: parser του manifest, σύγκριση εκδόσεων και το υπογεγραμμένο κείμενο,
  χωρίς Arduino. Το `tests/test_ota.py` το μεταγλωττίζει στον υπολογιστή και ελέγχει ότι
  φτιάχνει **byte-προς-byte** το ίδιο κείμενο με το `ota_sign.py`.

Το Arduino δεν κάνει `#include "../common/…"` από sketch, οπότε η βιβλιοθήκη δίνεται με
**`--library firmware/common`** (arduino-cli, και στο CI). Στο Arduino IDE: φτιάξε ένα link
`ln -s "$PWD/firmware/common" ~/Documents/Arduino/libraries/NetWatchSignedOta`. Με
`OTA_ENABLE 0` η βιβλιοθήκη δεν χρειάζεται καθόλου.

Ρύθμιση στο `secrets.h` κάθε sketch (βλ. `secrets.example.h`):

```c
#define OTA_ENABLE 1
#define OTA_BASE_URL "https://pi-broker.local:8443"
static const char OTA_PUBKEY_PEM[] = R"PEM(  ...περιεχόμενο του ota_public.h...  )PEM";
```

Σημειώσεις:

- **Μπλοκάρει** όσο κατεβαίνει το firmware (συνήθως 10-40 s, όριο 180 s). Τα sketches το
  καλούν μόνο όταν είναι αδρανή: το canary όταν καμία σύνδεση στην παγίδα δεν είναι ενεργή,
  το sentinel στο τέλος της φάσης online (το «τυφλό» διάστημα του sniff μακραίνει για λίγο).
- Θέλει partition scheme με **δύο** OTA partitions (το προεπιλεγμένο «Default 4MB with
  spiffs» έχει 2 × 1.25 MB). Το «Huge APP» δεν έχει και το OTA απαντά `error`.
- Το rollback βασίζεται στο `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`, που είναι ενεργό στον
  Arduino core 3.x. Η βιβλιοθήκη ορίζει `verifyRollbackLater()` ώστε ο core να **μην**
  επιβεβαιώνει αυτόματα το νέο image· το επιβεβαιώνει το sketch όταν συνδεθεί στο MQTT.

---

## 7. Δοκιμές

```bash
.venv/bin/python -m pytest -q tests/test_ota.py
```

Ελέγχουν: υπογραφή → επαλήθευση με `openssl` (και πάνω στο έτοιμο hash των 32 bytes, όπως
το `mbedtls_pk_verify`), πεδία manifest, αλλοίωση `.bin` / μετονομασία έκδοσης / άλλο κλειδί,
άρνηση rollback στο `ota_sign.py`, ότι ο C++ parser του firmware ξαναφτιάχνει ακριβώς το
υπογεγραμμένο κείμενο, και τον server (HTTPS, traversal, symlinks, κανένα listing, μόνο GET).
