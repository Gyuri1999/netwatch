# NetWatch PoE Field (Olimex ESP32-POE)

**Tester πρίζας δικτύου** και **μόνιμος ενσύρματος φρουρός**, σε Olimex ESP32-POE ή
ESP32-POE-ISO. Μόνο Ethernet: το Wi-Fi δεν ξεκινά ποτέ. Βάζεις το καλώδιο και σε λίγα
δευτερόλεπτα το NetWatch (τύπος **`field`**) δείχνει:

| Τι | Πώς | Πεδίο |
|---|---|---|
| Link, ταχύτητα, duplex | PHY LAN8720 | `link.up`, `link.speed`, `link.duplex` |
| Χρόνος DHCP, μάσκα, πύλη, DNS | από «link up» μέχρι «πήρα IP» | `link.dhcp_ms`, `link.mask`, `link.gw`, `link.dns` |
| Πύλη | ICMP ping x3· αν δεν απαντά σε ping, σύνδεση TCP (80/443/53) | `metrics.gw_ms` |
| Internet | άνοιγμα/κλείσιμο σύνδεσης TCP σε `1.1.1.1:443` | `metrics.inet_ms` |
| Switch, θύρα, VLAN | παθητική ακρόαση **LLDP** και **CDP** | `link.lldp_sw`, `link.lldp_port`, `link.vlan` |
| PoE | βλ. ενότητα 5 | `link.poe` |

Γεγονότα: `link_down` (στέλνεται όταν ξαναέρθει το link), `outage` (η πύλη δεν απαντά 3 φορές
στη σειρά), `dhcp_rogue` (είδαμε **δεύτερο** DHCP server στο καλώδιο), `poe_lost`.

> **Δοκιμασμένο μόνο σε compile· δεν έχει τρέξει σε πραγματικό υλικό.** Δες την ενότητα 9.

## 1. Υλικό και τιμές (ενδεικτικά)

| Εξάρτημα | Τιμή |
|---|---|
| Olimex **ESP32-POE** (χωρίς γαλβανική απομόνωση) | ~20 € |
| Olimex **ESP32-POE-ISO** (με απομόνωση 3 kV, συνιστάται) | ~27 € |
| Μπαταρία LiPo 3,7 V με βύσμα JST 2 mm (προαιρετική, για το `poe_lost`) | ~6 € |
| Switch ή injector PoE 802.3af | – |

Καμία εξωτερική βιβλιοθήκη: `ETH.h`, lwIP και `esp_eth` του πυρήνα **arduino-esp32 3.x**, και η
κοινή βιβλιοθήκη `../common` (`nw_probe.h`).

## 2. Αρχεία

| Αρχείο | Ρόλος |
|---|---|
| `esp32-poe.ino` | το firmware |
| `secrets.example.h` | πρότυπο ρυθμίσεων |
| `secrets.h` | **οι δικές σου** ρυθμίσεις, αγνοείται από το git (`.gitignore`) |
| `../common/nw_probe.h/.cpp` | κοινός πελάτης του πρωτοκόλλου αισθητήρα |

## 3. Συνδεσμολογία

Δεν υπάρχει καλωδίωση: όλα είναι πάνω στην πλακέτα. Τα pins έρχονται από το «variant» της
πλακέτας στον πυρήνα (γι' αυτό μετράει το σωστό `--fqbn`):

| Λειτουργία | GPIO | Σημείωση |
|---|---|---|
| PHY LAN8720 (LAN8710A): MDC / MDIO | 23 / 18 | διεύθυνση PHY 0 |
| Τροφοδοσία PHY | 12 | |
| Ρολόι RMII 50 MHz | **17, έξοδος** από το ESP32 | στις εκδόσεις WROVER (PSRAM): GPIO0 |
| RMII δεδομένα | 19, 21, 22, 25, 26, 27 | μην τα χρησιμοποιείς για άλλα |
| «External power sense» | 39 | διαιρέτης από τα +5 V (βλ. ενότητα 5) |
| Μέτρηση μπαταρίας | 35 | δεν χρησιμοποιείται εδώ |
| Κουμπί BUT1 | 34 | πάτημα = ξανατρέξε τις δοκιμές τώρα |

> **ESP32-POE (όχι ISO): ΜΗΝ συνδέεις USB και PoE ταυτόχρονα.** Η πλακέτα δεν έχει γαλβανική
> απομόνωση από την τροφοδοσία του Ethernet· μπορεί να καεί η θύρα USB του υπολογιστή σου.
> Προγραμμάτισε με USB και **χωρίς** καλώδιο PoE (ή με switch χωρίς PoE). Η έκδοση -ISO δεν
> έχει αυτόν τον περιορισμό.

## 4. Ρύθμιση και σύζευξη

```bash
cd ~/netwatch/firmware/esp32-poe
cp secrets.example.h secrets.h
```

1. Στο NetWatch: **🧩 Οι συσκευές μου → κάρτα «Tester τσέπης» → Δημιουργία κωδικού → Αντιγραφή**.
2. Στο `secrets.h`: ο κωδικός στο `NW_PAIR_CODE`, και **η αλήθεια για την τροφοδοσία**
   (`USB_CONNECTED`, `HAS_BATTERY`, ενότητα 5).
3. Προαιρετικά: `INET_TEST_IP` (`""` = καμία κίνηση προς το Internet), `DHCP_ALLOWED_SERVER`.

Ο κωδικός περιέχει το token **και** το αποτύπωμα SHA-256 του πιστοποιητικού του NetWatch. Αν το
αποτύπωμα δεν ταιριάζει, το firmware **δεν στέλνει τίποτα**.

Χωρίς σύζευξη η πλακέτα δουλεύει ως αυτόνομος tester: όλα τα αποτελέσματα βγαίνουν στο Serial.

**Ως tester τσέπης:** η αναφορά φτάνει στο NetWatch μόνο αν η πρίζα που δοκιμάζεις «βλέπει» τη
διεύθυνση του NetWatch (ίδιο VLAN ή δρομολόγηση προς τη θύρα 8790). Σε απομονωμένο VLAN θα δεις
τα αποτελέσματα μόνο στο Serial, και τα γεγονότα θα σταλούν όταν ξαναβρεθεί το NetWatch.

## 5. PoE: τι μπορεί και τι δεν μπορεί να ξέρει η πλακέτα

Η πλακέτα **δεν έχει σήμα «έχω PoE»**. Έχει μόνο το GPIO39, που βλέπει τη γραμμή +5 V. Αυτή
τροφοδοτείται είτε από το PoE είτε από το USB, άρα το GPIO39 λέει «υπάρχει εξωτερική
τροφοδοσία», όχι «υπάρχει PoE». Το firmware λέει `poe` μόνο όταν είναι αλήθεια:

| `USB_CONNECTED` | `HAS_BATTERY` | Τι αναφέρεται |
|---|---|---|
| 1 | – | το πεδίο `poe` **δεν στέλνεται** (άγνωστο) |
| 0 | 0 | `poe: true` — τρέχει χωρίς USB και χωρίς μπαταρία, άρα την τροφοδοτεί το PoE |
| 0 | 1 | `poe` = GPIO39· αν πέσει (3 μετρήσεις) → γεγονός `poe_lost` |

Χωρίς μπαταρία δεν μπορεί να υπάρξει `poe_lost`: όταν κοπεί το PoE η πλακέτα σβήνει και το
NetWatch θα δείξει «αισθητήρας εκτός σύνδεσης». Ανάλογα με την αναθεώρηση της πλακέτας, η
μέτρηση στο GPIO39 μπορεί να θέλει κλειστό το jumper `PWR_SENS_E` (δες το σχηματικό της
Olimex για τη δική σου αναθεώρηση). Αν δηλώσεις ψευδώς `USB_CONNECTED 0`, θα δεις ψευδώς
`poe: true`.

## 6. Flash

### arduino-cli

```bash
cd ~/netwatch/firmware/esp32-poe
arduino-cli compile --fqbn esp32:esp32:esp32-poe --library ../common .      # ISO: esp32:esp32:esp32-poe-iso
arduino-cli upload  --fqbn esp32:esp32:esp32-poe -p /dev/cu.usbserial-0001 .
arduino-cli monitor -p /dev/cu.usbserial-0001 -c baudrate=115200
```

### Arduino IDE

1. Boards Manager: **esp32 by Espressif** (3.x).
2. Μία φορά: `ln -s "$(cd ../common && pwd)" ~/Documents/Arduino/libraries/NetWatchSignedOta`.
3. Board: **OLIMEX ESP32-POE** (ή **ESP32-POE-ISO**), θύρα, **Upload**.
4. Serial Monitor στα **115200**.

## 7. Τι θα δεις

Στο Serial, μόλις μπει το καλώδιο:

```text
[eth] link UP 100 Mbps full duplex
[dhcp] server seen: 192.168.1.1
[eth] ip=192.168.1.74 mask=255.255.255.0 gw=192.168.1.1 dns=192.168.1.1 dhcp=1840 ms
[test] gw_ms=1 (icmp) inet_ms=14
[lldp] switch="sw-rack-1" port="GigabitEthernet1/0/12" vlan=20
[nw] report ok (next in 60 s)
```

Στο NetWatch:

```json
{"status":{"fw":"1.0.0","hw":"Olimex ESP32-POE","ip":"192.168.1.74","mac":"a8:03:2a:aa:bb:cc","uptime":42,"heap":231000,"interval":60,
  "metrics":{"gw_ms":1,"inet_ms":14},
  "link":{"up":true,"speed":100,"duplex":"full","poe":true,"dhcp_ms":1840,"gw":"192.168.1.1","dns":"192.168.1.1",
          "mask":"255.255.255.0","vlan":20,"lldp_sw":"sw-rack-1","lldp_port":"GigabitEthernet1/0/12"}},
 "events":[]}
```

- `gw_ms` / `inet_ms` **λείπουν** όταν η δοκιμή απέτυχε. Το ping του lwIP μετρά σε ακέραια ms:
  σε τοπικό δίκτυο το `0` είναι φυσιολογικό.
- Το LLDP στέλνεται από το switch κάθε ~30 s (CDP ~60 s): η πρώτη αναφορά μπορεί να μην το
  έχει, και η επόμενη φεύγει μόλις ακουστεί. Τα στοιχεία CDP μπαίνουν στα ίδια πεδία `lldp_*`.
- Το `vlan` είναι το Port VLAN ID που **διαφημίζει** το switch (LLDP 802.1 PVID ή CDP native VLAN).

## 8. Αντιμετώπιση προβλημάτων

| Σύμπτωμα | Τι να κοιτάξεις |
|---|---|
| `ETH.begin() FAILED` | λάθος `--fqbn`/Board, ή έκδοση WROVER (ρολόι στο GPIO0: διάλεξε PSRAM «enabled») |
| link UP αλλά ποτέ IP | δεν υπάρχει DHCP σε αυτό το VLAN, ή θύρα με 802.1X/port security |
| δεν εμφανίζεται switch/θύρα | το LLDP/CDP είναι κλειστό στο switch, unmanaged switch, ή παρεμβάλλεται μικρό switch/IP τηλέφωνο |
| `dhcp_rogue` χωρίς λόγο | έχεις σκόπιμα δύο DHCP (failover): γράψε τον δεύτερο στο `DHCP_ALLOWED_SERVER` |
| `outage` ενώ όλα δουλεύουν | η πύλη δεν απαντά ούτε σε ping ούτε σε TCP 80/443/53 (σπάνιο): αύξησε το `GW_TEST_PERIOD_S` |
| `CERT MISMATCH … token NOT sent` | νέο πιστοποιητικό στο NetWatch ή παρεμβολή: νέα σύζευξη / έρευνα |
| `connect … failed` | από αυτή την πρίζα δεν φτάνεις τη θύρα 8790 του NetWatch |

## 9. Όρια και ασφάλεια

- **Παθητική ακρόαση L2.** Το firmware μπαίνει στον δρόμο εισόδου του οδηγού Ethernet
  (`esp_eth_update_input_path_info`), κοιτά τα πλαίσια LLDP/CDP/DHCP και τα παραδίδει ανέπαφα
  στο lwIP. **Δεν στέλνει** δικά του πλαίσια LLDP/CDP, δεν κάνει ARP scan, δεν αγγίζει άλλες συσκευές.
- Ενεργές δοκιμές: ping/TCP **μόνο** προς τη δική σου πύλη, και ένα άνοιγμα-κλείσιμο σύνδεσης
  TCP (χωρίς δεδομένα) προς το `INET_TEST_IP`. Με `INET_TEST_IP ""` δεν βγαίνει τίποτα έξω.
- `dhcp_rogue`: βλέπουμε μόνο τις απαντήσεις DHCP που φτάνουν **στη δική μας θύρα** (τις
  προσφορές προς εμάς και ό,τι είναι broadcast). Ένας δεύτερος server που απαντά μόνο σε άλλους
  με unicast δεν φαίνεται από εδώ. Χρειάζεται να έχουμε δει και το ACK του «δικού μας» server.
- Όλα τα κείμενα από το δίκτυο (όνομα switch, θύρα) κόβονται στους 47 χαρακτήρες, γίνονται
  καθαρό ASCII και περνούν από escape πριν μπουν στο JSON.
- 10/100 Mbps μόνο (LAN8720). Μια θύρα 1 Gbps θα φανεί ως 100.
- Το `secrets.h` (token) μένει εκτός git· όποιος έχει την πλακέτα στα χέρια του μπορεί να το
  διαβάσει από τη flash.

**Πιθανότερα σημεία προσαρμογής σε πραγματικό υλικό:** (α) το jumper και το κατώφλι του GPIO39
(`PWR_SENSE_MIN_MV`) όταν υπάρχει μπαταρία, (β) αν ο οδηγός EMAC περνά όντως τα multicast του
LLDP (`01:80:c2:00:00:0e`) — ζητάμε «όλα τα multicast», αλλά δεν έχει επαληθευτεί σε πλακέτα,
(γ) ο χρόνος DHCP σε switch με spanning tree χωρίς portfast (30–50 s είναι τότε φυσιολογικό),
(δ) το ICMP της πύλης (αν δεν απαντά, το `gw_ms` είναι χρόνος σύνδεσης TCP).
