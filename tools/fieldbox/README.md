# 🔌 NetWatch field box — το κουτί του τεχνικού

Ένα Raspberry Pi με NetWatch που το έχεις στην τσάντα. Το βάζεις σε μια πρίζα δικτύου και σε ~30 δευτερόλεπτα
βλέπεις στη μικρή οθόνη ή στο κινητό:

```
A-03 OK                  ← ετικέτα πρίζας + αποτέλεσμα
SW-OFFICE-1              ← σε ποιο switch καταλήγει (LLDP/CDP)
Gi1/0/14 VLAN 20         ← θύρα και VLAN
1G full PoE 15.4W        ← ταχύτητα, duplex, PoE
DHCP 0.4s 10.20.0.57     ← πόσο γρήγορα απάντησε το DHCP και τι IP έδωσε
GW ok NET ok             ← router και Internet
```

Μόνο ανάγνωση: ακούει LLDP/CDP, στέλνει **ένα** DHCPDISCOVER (ποτέ REQUEST) και pings. Δεν γράφει τίποτα σε switch.

## 1. Τι να αγοράσεις (τιμές κατά προσέγγιση, 2026)

| Υλικό | Τιμή | Σχόλιο |
|---|---|---|
| Raspberry Pi Zero 2 W **ή** Pi 4 (2 GB) | ~20 € / ~55 € | Το Zero χωράει στην τσέπη. Το Pi 4 έχει πραγματικό gigabit και ενσωματωμένο Ethernet. |
| microSD 32 GB (A1) | ~8 € | |
| USB‑Ethernet gigabit (RTL8153 / AX88179) + καλώδιο micro‑USB OTG | ~15 € | Μόνο για το Zero. Διαπραγματεύεται κανονικά 1 Gbps (αυτό μας νοιάζει), αλλά το USB 2.0 περνά ~300 Mbps. |
| PoE splitter 802.3af → 5 V micro‑USB/USB‑C **ή** PoE+ HAT (Pi 4) | ~12 € / ~25 € | Προαιρετικό αλλά πολύ χρήσιμο: το κουτί ανάβει από την ίδια την πρίζα → **βλέπεις με το μάτι αν έχει PoE**. |
| Οθόνη OLED 0,96" SSD1306 **I2C** (4 ακροδέκτες) | ~5 € | Αυτή υποστηρίζει το `oled.py`. |
| Οθόνη e‑paper 2,13" (Waveshare) | ~20 € | Εναλλακτική που διαβάζεται στον ήλιο· **δεν** την οδηγεί το `oled.py` — πάρε τις γραμμές από το `--stdout` ή το `/api/kit/field/oled`. |
| Κουμπί (push button) + 2 καλώδια dupont | ~1 € | «Νέο τεστ» χωρίς κινητό. |
| USB modem 4G/LTE (π.χ. Huawei E3372h) + SIM δεδομένων | ~40 € | Εφεδρική γραμμή: οι ειδοποιήσεις φτάνουν ακόμη κι όταν πέσει η γραμμή του πελάτη. |
| Power bank 10.000 mAh | ~18 € | Όταν η πρίζα δεν έχει PoE. Το Zero 2 W τραβά ~0,3 A → μια ολόκληρη μέρα. |
| Κουτί | ~8 € | Με άνοιγμα για την οθόνη. |

Σύνολο: περίπου **90 €** (Zero, χωρίς LTE) έως **170 €** (Pi 4 με PoE HAT και LTE).

## 2. Καλωδίωση οθόνης και κουμπιού

Οθόνη SSD1306 (I2C, διεύθυνση `0x3C`):

| Οθόνη | Raspberry Pi (φυσικός ακροδέκτης) |
|---|---|
| VCC | 3V3 — pin 1 |
| GND | GND — pin 6 |
| SDA | GPIO2 (SDA) — pin 3 |
| SCL | GPIO3 (SCL) — pin 5 |

Κουμπί: ανάμεσα σε **GPIO17 — pin 11** και **GND — pin 9** (δεν θέλει αντίσταση, χρησιμοποιείται η εσωτερική pull‑up).

> Σύνδεσε την οθόνη στα **3,3 V**, όχι στα 5 V, και πάντα με το Pi σβηστό.

## 3. Εγκατάσταση (Raspberry Pi OS Lite 64‑bit)

1. Γράψε την κάρτα με το **Raspberry Pi Imager**: «Raspberry Pi OS Lite (64‑bit)». Στις ρυθμίσεις του Imager βάλε
   όνομα (π.χ. `fieldbox`), χρήστη/κωδικό, Wi‑Fi του εργαστηρίου σου και **ενεργοποίησε το SSH**.
2. Πρώτη εκκίνηση, σύνδεση και ενημέρωση:
   ```bash
   ssh <χρήστης>@fieldbox.local
   sudo apt update && sudo apt full-upgrade -y
   sudo apt install -y git
   git clone https://github.com/Gyuri1999/netwatch.git && cd netwatch
   ```
3. Δες πρώτα τι θα κάνει ο installer και μετά τρέξ' τον:
   ```bash
   tools/fieldbox/install.sh --dry-run --oled --button 17 --lte
   sudo tools/fieldbox/install.sh --oled --button 17 --lte      # άφησε έξω ό,τι δεν έχεις
   sudo reboot                                                  # για το I2C και τις ομάδες i2c/gpio
   ```
   Επιλογές: `--iface eth0` (η διεπαφή που μπαίνει στην πρίζα), `--port 8765`, `--user <χρήστης>`, `--no-start`.
   Ο installer εγκαθιστά πακέτα apt (python3‑venv, tcpdump, ethtool, network‑manager κ.λπ.), φτιάχνει το `.venv`,
   ανοίγει το I2C αν ζήτησες `--oled`, και γράφει δύο υπηρεσίες systemd. Τίποτα άλλο.
4. Έλεγχος:
   ```bash
   systemctl status netwatch-fieldbox --no-pager
   journalctl -u netwatch-fieldbox -n 30 --no-pager | grep -A1 agent     # URL με token + αποτύπωμα πιστοποιητικού
   i2cdetect -y 1                                                        # πρέπει να δείχνει 3c
   ```

Η υπηρεσία τρέχει το NetWatch **όχι ως root**, μόνο με τα δικαιώματα που θέλει η καταγραφή πακέτων
(`CAP_NET_RAW`, `CAP_NET_ADMIN`):

```
netwatch.py --agent --no-open -i eth0 --port 8765
```

Χρήσιμες επιπλέον σημαίες του NetWatch για το κουτί (πρόσθεσέ τες στο `ExecStart` του
`/etc/systemd/system/netwatch-fieldbox.service` και κάνε `sudo systemctl daemon-reload && sudo systemctl restart netwatch-fieldbox`):
`--no-geo` (χωρίς γεωεντοπισμό μέσω ip-api.com), `--no-intel` (χωρίς κατέβασμα blocklists — γλιτώνει δεδομένα στο LTE),
`--no-rdns`, `--config <αρχείο>`.

## 4. Πρόσβαση από το κινητό — και τι σημαίνει για την ασφάλεια

Το NetWatch ακούει κανονικά **μόνο στο 127.0.0.1**. Για να το ανοίξεις από κινητό θέλει τη **λειτουργία agent**
(`--agent`): HTTPS με self‑signed πιστοποιητικό **και** token σε κάθε αίτημα (δες [`docs/agent.md`](../../docs/agent.md)).

**Α. Το Pi ως Wi‑Fi hotspot** (δεν χρειάζεσαι το δίκτυο του πελάτη):

```bash
sudo nmcli device wifi hotspot ifname wlan0 ssid NetWatch-Box password '<δικός σου κωδικός, 12+ χαρακτήρες>'
sudo nmcli connection modify Hotspot connection.autoconnect yes      # να σηκώνεται μόνο του σε κάθε εκκίνηση
```

Σύνδεσε το κινητό στο `NetWatch-Box` και άνοιξε `https://10.42.0.1:8765/?token=…`.

**Β. Μέσα από το LAN του πελάτη:** `https://<IP του Pi>:8765/?token=…` (η IP του Pi: `hostname -I` — συνήθως αυτή που δείχνει η οθόνη στη γραμμή DHCP).

Και στις δύο περιπτώσεις:

1. Το token το τυπώνει το NetWatch στην εκκίνηση (`journalctl -u netwatch-fieldbox`) και υπάρχει στο `data/agent-token`.
2. Ο browser θα προειδοποιήσει για το πιστοποιητικό. **Σύγκρινε το αποτύπωμα SHA‑256** με αυτό που τύπωσε το NetWatch.
3. Μετά ο browser κρατά το token σε cookie για 30 μέρες. Στο Android μπορείς να βάλεις και την εφαρμογή NetWatch (pinning).

Τι να προσέξεις:

- Με `--agent` το NetWatch ακούει σε **όλες** τις διεπαφές (`0.0.0.0`) — δηλαδή και στο δίκτυο του πελάτη όπου κουμπώνεις.
  Το προστατεύουν το HTTPS και το token· μην το μοιράζεσαι, και μη φωτογραφίζεις την οθόνη με το URL.
- Θες να ακούει **μόνο** στο hotspot; Βάλε `--bind 10.42.0.1` στο `ExecStart` (το hotspot πρέπει να έχει σηκωθεί πριν
  ξεκινήσει η υπηρεσία) και άλλαξε στο `netwatch-fieldbox-oled.service` το `--url` σε `https://10.42.0.1:8765`.
- Το τερματικό της Ακαδημίας και το «κλείσιμο» είναι απενεργοποιημένα σε λειτουργία agent.
- **Ποτέ** port forwarding της 8765 προς το Internet. Για πρόσβαση από μακριά: VPN (WireGuard/Tailscale).
- Ο κωδικός του hotspot είναι το πρώτο κλείδωμα — βάλε μεγάλο και δικό σου, όχι του παραδείγματος.
- Αν χάσεις το κουτί: η κάρτα έχει το token, το ιστορικό των πριζών και (αν έβαλες) κωδικούς στο `config.yaml`.
  Σβήσε το `data/agent-token` για νέο token και άλλαξε ό,τι κωδικό είχε μέσα.

## 5. Η οθόνη και το κουμπί

Η υπηρεσία `netwatch-fieldbox-oled` τρέχει το [`oled.py`](oled.py): κάθε δευτερόλεπτο ρωτά το τοπικό NetWatch
(`GET /api/kit/field/oled`) και ζωγραφίζει έως 6 γραμμές. Το κουμπί ξεκινά τεστ στην **επόμενη ετικέτα**
(A‑01 → A‑02 → …) με `POST /api/kit/field/test`.

Δοκιμή χωρίς οθόνη:

```bash
.venv/bin/python tools/fieldbox/oled.py --stdout --once --url https://127.0.0.1:8765     # λειτουργία agent
.venv/bin/python tools/fieldbox/oled.py --stdout --url http://127.0.0.1:8765             # τοπικό NetWatch (./run.sh --demo)
.venv/bin/python tools/fieldbox/oled.py --test --url https://127.0.0.1:8765              # ξεκίνα ένα τεστ τώρα
```

Το script ακολουθεί τους κανόνες του server: σε λειτουργία agent στέλνει `Authorization: Bearer <token>` (από το
`data/agent-token`) και ελέγχει πρώτα το αποτύπωμα του `data/agent.crt`· τοπικά στέλνει μόνο JSON χωρίς `Origin`.
Γι' αυτό τρέχει με τον **ίδιο χρήστη** με το NetWatch (το token είναι αρχείο `0600`).

Η μικρή οθόνη δεν έχει ελληνικά: δείχνει σύντομα αγγλικά/κωδικούς (`OK`, `WARN`, `FAIL`, `! slow`, `! dhcp_none`,
`NO LINK`). Το πλήρες κείμενο με το «τι να ελέγξεις» είναι στο κινητό.

## 6. Μια μέρα στον πελάτη

1. **Πριν φύγεις:** φόρτισε το power bank, τσέκαρε ότι το κουτί ανάβει και ότι το κινητό ανοίγει το UI από το hotspot.
2. **Στον πελάτη:** καρτέλα **🔌 Tester πρίζας** → «Τι περιμένω»: βάλε το VLAN των πριζών (π.χ. 20), τσέκαρε PoE αν
   πρέπει να έχουν, ταχύτητα 1 Gbps.
3. Γράψε την ετικέτα της πρώτης πρίζας όπως στο patch panel (**A‑01**), κούμπωσε, πάτα **Τεστ**.
4. Επόμενη πρίζα: άλλαξε καλώδιο, πάτα **Επόμενη πρίζα** (ή το κουμπί του κουτιού). Η ετικέτα ανεβαίνει μόνη της.
   24 πρίζες = περίπου ένα τέταρτο.
5. Ό,τι βγει πορτοκαλί/κόκκινο το φτιάχνεις **πριν κλείσει το ψευδοτάβανο**:
   - `Μόνο 100 Mbps` → ένα ζεύγος δεν κάνει επαφή· ξανατερμάτισε (T568B και στις δύο άκρες).
   - `Λάθος VLAN` / `κανένας DHCP` → η θύρα στο switch που γράφει η οθόνη θέλει `switchport access vlan …`.
   - `Χωρίς PoE` → `power inline auto` ή θύρα χωρίς PoE.
   - `Νεκρή πρίζα` → δεν είναι πατσαρισμένη ή κομμένο καλώδιο.
6. **Στο τέλος:** κατέβασε το **CSV**, φτιάξε το **πρωτόκολλο παράδοσης** (καρτέλα παράδοσης — παίρνει τα αποτελέσματα
   ανά ετικέτα) και τύπωσε **ετικέτες** για τις πρίζες (καρτέλα ετικετών).
7. Αν αφήσεις το κουτί στον πελάτη για παρακολούθηση: βάλε το LTE (παρακάτω) και ρύθμισε ntfy/Telegram στο `config.yaml`.

## 7. Εφεδρική γραμμή LTE

```bash
sudo tools/fieldbox/lte-setup.sh internet            # APN του παρόχου σου· USB modem που το βλέπει το ModemManager
sudo tools/fieldbox/lte-setup.sh --tether usb0       # modem «HiLink» ή κινητό σε USB tethering (φαίνεται ως Ethernet)
tools/fieldbox/lte-setup.sh internet --dry-run       # δείξε μόνο τις εντολές
ip route show default                                # η ενσύρματη πρέπει να έχει ΜΙΚΡΟΤΕΡΟ metric (100) από το LTE (700)
```

Το script προσθέτει μία σύνδεση στο NetworkManager με `ipv4.route-metric 700`, ώστε το LTE να είναι **μόνο εφεδρεία**.
Το NetWatch (κάρτα «Uplink / LTE») ελέγχει κάθε ~30 s αν η κύρια γραμμή βγάζει Internet και:

- «**Έπεσε η κύρια γραμμή — δουλεύω από LTE**» (σοβαρή) → φτάνει στο κινητό σου μέσω ntfy/Telegram από το LTE.
- «**Η κύρια γραμμή επανήλθε**» (ενημερωτική), με διάρκεια και πόσα MB πέρασαν από το LTE.
- «**Η εφεδρική γραμμή LTE δεν δουλεύει**» (μέτρια) → τελείωσαν τα δεδομένα / βγήκε το modem, πριν το χρειαστείς.

Η εφεδρική ελέγχεται αραιά (κάθε 5 λεπτά, λίγα bytes) για να μην τρώει δεδομένα — περίπου 5 MB τον μήνα.
Προαιρετικά στο `config.yaml`:

```yaml
uplink:
  expect_cellular: true      # ειδοποίησε αν το modem δεν φαίνεται καθόλου
  cap_gb: 5                  # μηνιαίο πακέτο δεδομένων (για τη μπάρα)
  cellular_ifaces: [eth1]    # αν το modem σου φαίνεται ως απλό Ethernet και δεν αναγνωρίζεται μόνο του
```

## 8. Αν κάτι δεν πάει καλά

| Σύμπτωμα | Τι να δεις |
|---|---|
| Η οθόνη μένει σβηστή | `i2cdetect -y 1` (θέλει `3c`)· καλωδίωση SDA/SCL· `journalctl -u netwatch-fieldbox-oled -n 20`. Μετά το `--oled` θέλει ένα reboot. |
| Οθόνη: `waiting for NetWatch` | Το NetWatch δεν έχει ξεκινήσει: `systemctl status netwatch-fieldbox`, `journalctl -u netwatch-fieldbox -n 40`. |
| Οθόνη: `NetWatch: 401` | Το `oled.py` δεν διαβάζει το `data/agent-token` (άλλος χρήστης;). Οι δύο υπηρεσίες πρέπει να έχουν το ίδιο `User=`. |
| «Δεν έγινε ακρόαση LLDP/CDP (θέλει root/CAP_NET_RAW)» | Το NetWatch τρέχει χωρίς τα capabilities: χρησιμοποίησε την υπηρεσία ή `sudo`. Θέλει και το `tcpdump` (φίλτρα BPF). |
| Δεν βλέπει switch/θύρα | Unmanaged switch ή κλειστό LLDP (`lldp run` σε Cisco). Κάποια switch στέλνουν κάθε 30 s — περίμενε όλο το τεστ. |
| PoE «άγνωστο» ενώ η θύρα δίνει ρεύμα | Το PoE το μαθαίνουμε **μόνο** από ό,τι διαφημίζει το switch (LLDP 802.3 / LLDP‑MED / CDP). Με PoE splitter το βλέπεις και από το ότι άναψε το κουτί. |
| Ταχύτητα «?» | Λείπει το `ethtool` ή ο αντάπτορας USB δεν τη δηλώνει: `ethtool eth0`. |
| DHCP ΟΚ στο τεστ, αλλά «ο router δεν απαντά» | Το Pi δεν πρόλαβε να πάρει δική του IP: `nmcli device status`· ξαναπάτα Τεστ μετά από 10 s. |
| Το κινητό δεν ανοίγει το UI | Είσαι στο σωστό Wi‑Fi; `https://` (όχι http)· σωστή θύρα· `ss -ltnp \| grep 8765`. |
| Το LTE δεν συνδέεται | `mmcli -L`, `mmcli -m 0` (SIM, σήμα, PIN)· `nmcli connection show netwatch-lte`· σωστό APN· ορισμένα modem θέλουν `usb-modeswitch`. |
| Όλη η κίνηση φεύγει από το LTE | Το metric του LTE είναι μικρότερο από της ενσύρματης: `ip route show default` και ξανά `lte-setup.sh`. |
| Η κάρτα SD χαλάει από τα απότομα σβησίματα | Σβήνε με `sudo poweroff` πριν βγάλεις το ρεύμα. (Μην ενεργοποιήσεις overlay filesystem: θα χάνεται το ιστορικό των πριζών σε κάθε επανεκκίνηση.) |

Απεγκατάσταση:

```bash
sudo systemctl disable --now netwatch-fieldbox netwatch-fieldbox-oled
sudo rm /etc/systemd/system/netwatch-fieldbox.service /etc/systemd/system/netwatch-fieldbox-oled.service
sudo systemctl daemon-reload
```
