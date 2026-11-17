# 🏠 Στήσιμο στο πραγματικό homelab: βήμα-βήμα

Ο οδηγός παίρνει ένα τυπικό homelab και το φτάνει στο «όλα μιλάνε με TLS και το NetWatch τα βλέπει όλα».
Οι διευθύνσεις είναι παραδείγματα· βάλε τις δικές σου.

| Ρόλος | Παράδειγμα |
|---|---|
| Mosquitto broker (VM στον Proxmox) | `192.168.1.17` |
| Proxmox host | `192.168.1.16` |
| Home Assistant | `192.168.1.30` |
| ESP32 Sentinel / καναρίνι | `192.168.1.20`, `192.168.1.21` |
| Mac με το NetWatch | `192.168.1.49` |

> Τις εντολές στον broker τις τρέχεις **εσύ** (θέλουν `sudo`). Κανένας κωδικός δεν γράφεται σε αρχείο του repo:
> το `config.yaml` και τα `secrets.h` είναι στο `.gitignore`.

## 1. TLS στον broker (από 1883 σε 8883)

Στο Mac:

```bash
./tools/mosquitto-tls.sh 192.168.1.17
```

Φτιάχνει το `./iot-ca/`: δική σου CA, πιστοποιητικό για τον broker, έτοιμο `mosquitto-tls.conf` και `ca_cert.h`
για τα ESP32. Στο τέλος τυπώνει τις εντολές `scp`/`ssh` για να τα περάσεις στον broker.

- Αν το `/etc/mosquitto/mosquitto.conf` έχει ήδη `listener 1883` χωρίς διεύθυνση, σβήσ' τον: το νέο conf ανοίγει το 1883 μόνο στο `127.0.0.1`.
- Το `iot-ca/ca.key` **δεν φεύγει ποτέ από το Mac** (καλύτερα σε USB/offline). Όποιος το έχει φτιάχνει «έγκυρους» ψεύτικους brokers.

## 2. Χρήστες και ACL: ένας χρήστης ανά ρόλο

Στον broker:

```bash
sudo mosquitto_passwd /etc/mosquitto/passwd netwatch      # φύλακας: μόνο ανάγνωση
sudo mosquitto_passwd /etc/mosquitto/passwd netwatch-ha   # Home Assistant discovery + playbooks
sudo mosquitto_passwd /etc/mosquitto/passwd sentinel      # ESP32 Sentinel
sudo mosquitto_passwd /etc/mosquitto/passwd canary        # ESP32 καναρίνι
```

`/etc/mosquitto/acl`:

```text
# NetWatch φύλακας (📨 MQTT): βλέπει τα πάντα, δεν γράφει τίποτα
user netwatch
topic read #
topic read $SYS/#

# NetWatch → Home Assistant
user netwatch-ha
topic readwrite homeassistant/#
topic readwrite netwatch/ha/#
topic write netwatch/alerts
topic write netwatch/playbook/#

# Οι αισθητήρες μόνο γράφουν στο δικό τους κλαδί
user sentinel
topic write netwatch/sensor/#
user canary
topic write netwatch/sensor/#
```

```bash
sudo systemctl restart mosquitto
journalctl -u mosquitto -n 20 --no-pager     # να μη δείχνει σφάλμα
```

Το `log_dest topic` (υπάρχει ήδη στο conf του βήματος 1) επιτρέπει στον φύλακα να βλέπει **ποιος** συνδέεται.

## 3. Το `config.yaml` του NetWatch

```bash
cp config.example.yaml config.yaml   # αν δεν το έχεις ήδη
```

```yaml
mqtt_guard:
  host: 192.168.1.17
  port: 8883
  username: netwatch
  password: "…"
  ca_file: ~/netwatch/iot-ca/ca.crt

sensor:
  mqtt_host: 192.168.1.17
  mqtt_port: 8883
  ca_file: ~/netwatch/iot-ca/ca.crt
  username: netwatch
  password: "…"

homeassistant:
  host: 192.168.1.17
  port: 8883
  username: netwatch-ha
  password: "…"
  ca_file: ~/netwatch/iot-ca/ca.crt

health:
  - {name: Proxmox, host: 192.168.1.16, port: 8006, tls: true}
  - {name: MQTT broker, host: 192.168.1.17, port: 8883, tls: true}
  - {name: Home Assistant, url: "http://192.168.1.30:8123/"}
  - {name: ESP32 Sentinel, host: 192.168.1.20, ping: true}

playbooks:
  - name: Καναρίνι → μπλόκαρε
    when: {type: "Καναρίνι ESP32"}
    do: [block, notify]
    block_minutes: 60
    dry_run: true          # άφησέ το true μια εβδομάδα, δες τι ΘΑ έκανε στο ⚡, μετά false
```

Μετά: επανεκκίνηση του NetWatch και έλεγχος στις καρτέλες
**📨 MQTT** (μαθαίνει 15′), **🩺 Homelab**, **📡 Αισθητήρας** και **🔌 IoT μου → ▶ Έλεγχος**.
Το «MQTT χωρίς TLS (1883)» πρέπει να γίνει «MQTT με TLS (8883)».

## 4. Flash στα ESP32 (USB)

```bash
arduino-cli board list                       # βρες τη θύρα, π.χ. /dev/cu.usbserial-0001
cd firmware/esp32-canary                     # ή esp32-sentinel
cp secrets.example.h secrets.h               # Wi‑Fi, MQTT_HOST 192.168.1.17, θύρα 8883, χρήστης/κωδικός
#   και επικόλλησε το περιεχόμενο του ../../iot-ca/ca_cert.h ως CA
arduino-cli compile --fqbn esp32:esp32:esp32 .
arduino-cli upload  --fqbn esp32:esp32:esp32 -p /dev/cu.usbserial-0001 .
arduino-cli monitor -p /dev/cu.usbserial-0001 -c baudrate=115200
```

Στο monitor πρέπει να δεις σύνδεση στο Wi‑Fi και στον broker. Στο NetWatch, ο αισθητήρας εμφανίζεται στο 📡 μέσα σε 30″.
Δοκιμή καναρινιού από άλλο μηχάνημα: `nc 192.168.1.21 23` → ειδοποίηση «Καναρίνι ESP32».

Για ενημερώσεις χωρίς καλώδιο μετά το πρώτο flash, δες το [`tools/ota/README.md`](../tools/ota/README.md) (υπογεγραμμένο OTA).

## 5. Λίστα ελέγχου

- [ ] `mosquitto_sub … -p 8883 --cafile iot-ca/ca.crt` δουλεύει, το `-p 1883` από το Mac **αποτυγχάνει**
- [ ] 📨 MQTT: ο broker φαίνεται, οι clients είναι γνωστοί μετά τα 15′ εκμάθησης
- [ ] 📡 Αισθητήρας: Sentinel και καναρίνι «online»
- [ ] 🏠 Home Assistant: συσκευή «NetWatch» στο Settings → Devices (MQTT integration)
- [ ] 🩺 Homelab: όλα πράσινα, το πιστοποιητικό του broker λήγει σε ~825 μέρες
- [ ] ⚡ Playbooks: μια δοκιμή στο καναρίνι γράφει «(δοκιμή) θα έκανα: block …»
