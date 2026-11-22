# NetWatch BLE Scanner (ESP32)

Περιοδική **παθητική** σάρωση Bluetooth Low Energy. Στέλνει στο NetWatch (τύπος **`ble`**) τη
λίστα των συσκευών που εκπέμπουν γύρω, και ειδοποιεί όταν ένα **ιχνηλατικό** μένει κοντά για ώρα.

| Τι | Πώς | Στο NetWatch |
|---|---|---|
| Συσκευές BLE | passive scan ~20 s ανά κύκλο, οι 80 ισχυρότερες, μία γραμμή ανά διεύθυνση | `items`, `metrics.seen` |
| Ιχνηλατικά | Apple Find My / AirTag (εταιρεία `0x004C`, τύπος `0x12`), Tile (`0xFEED`), Samsung SmartTag (`0xFD5A`) που φαίνονται **συνεχώς** `TRACKER_MINUTES` λεπτά | γεγονός `ble_tracker` (`data.mac`, `data.kind`) |

> **Δοκιμασμένο μόνο σε compile· δεν έχει τρέξει σε πραγματικό υλικό.** Δες την ενότητα 8.

## 1. Υλικό και τιμές

| Εξάρτημα | Τιμή |
|---|---|
| ESP32 DevKit με **κλασικό ESP32** (ESP32-WROOM-32), flash 4 MB | ~5 € |
| Τροφοδοτικό USB | – |

Καμία εξωτερική βιβλιοθήκη και καμία καλωδίωση. Χρησιμοποιείται το **Bluedroid** του πυρήνα
arduino-esp32 3.x απευθείας (`esp_gap_ble_api.h`), όχι η βιβλιοθήκη `BLE` του Arduino (εκείνη
δεσμεύει μνήμη για κάθε διαφήμιση). Σε ESP32-C3/S3 το sketch σταματά με μήνυμα στη μεταγλώττιση.

## 2. Αρχεία

| Αρχείο | Ρόλος |
|---|---|
| `esp32-ble.ino` | το firmware |
| `secrets.example.h` | πρότυπο ρυθμίσεων |
| `secrets.h` | **οι δικές σου** ρυθμίσεις, αγνοείται από το git (`.gitignore`) |
| `../common/nw_probe.h/.cpp` | κοινός πελάτης του πρωτοκόλλου αισθητήρα |

## 3. Συνδεσμολογία

| Τι | Πού |
|---|---|
| Τροφοδοσία | USB |
| Κεραία | η ενσωματωμένη· κράτα την πλακέτα μακριά από μεταλλικά κουτιά |

Τίποτα άλλο. Βάλ' τη στο σημείο που σε ενδιαφέρει (είσοδος, γραφείο, αποθήκη).

## 4. Ρύθμιση και σύζευξη

```bash
cd ~/netwatch/firmware/esp32-ble
cp secrets.example.h secrets.h
```

1. Στο NetWatch: **🧩 Οι συσκευές μου → κάρτα «BLE» → Δημιουργία κωδικού → Αντιγραφή**.
2. Στο `secrets.h`: `WIFI_SSID`, `WIFI_PASS` (2,4 GHz) και ο κωδικός στο `NW_PAIR_CODE`.
3. `TRACKER_MINUTES` (προεπιλογή 30) και `TRACKER_MIN_RSSI` (προεπιλογή −85 dBm: πιο αδύναμα,
   δηλαδή μακρινά, ιχνηλατικά δεν μετράνε).

Ο κωδικός περιέχει το token **και** το αποτύπωμα SHA-256 του πιστοποιητικού του NetWatch. Αν το
αποτύπωμα δεν ταιριάζει, το firmware **δεν στέλνει τίποτα**.

## 5. Flash

Το Bluetooth + Wi-Fi + TLS **δεν χωρά** στο προεπιλεγμένο partition (1,2 MB). Θέλει
**Minimal SPIFFS (1.9MB APP with OTA)**:

### arduino-cli

```bash
cd ~/netwatch/firmware/esp32-ble
arduino-cli compile --fqbn esp32:esp32:esp32:PartitionScheme=min_spiffs --library ../common .
arduino-cli upload  --fqbn esp32:esp32:esp32:PartitionScheme=min_spiffs -p /dev/cu.usbserial-0001 .
arduino-cli monitor -p /dev/cu.usbserial-0001 -c baudrate=115200
```

### Arduino IDE

1. Boards Manager: **esp32 by Espressif** (3.x).
2. Μία φορά: `ln -s "$(cd ../common && pwd)" ~/Documents/Arduino/libraries/NetWatchSignedOta`.
3. Board **ESP32 Dev Module**, **Tools → Partition Scheme → Minimal SPIFFS (1.9MB APP with OTA…)**.
4. **Upload**, Serial Monitor στα **115200**.

## 6. Τι θα δεις

Στο Serial, κάθε κύκλο:

```text
[ble] scan ok: 37 devices, 2210 adverts, table-full 0, heap 148200 -> 187400
[nw] report ok: 37 devices, 37 rows (next in 60 s)
```

Στο NetWatch, μία γραμμή ανά συσκευή (φθίνον σήμα, έως 80):

```json
{"status":{"fw":"1.0.0","hw":"ESP32 BLE scanner","ip":"192.168.1.62","mac":"a4:cf:12:aa:bb:cc","uptime":912,"heap":187400,
  "rssi":-55,"interval":60,"metrics":{"seen":37}},
 "events":[{"type":"ble_tracker","detail":"Ιχνηλατικό Apple Find My / AirTag (d3:4a:…) μένει κοντά εδώ και 30 λεπτά, σήμα -61 dBm",
            "data":{"mac":"d3:4a:10:22:9c:01","kind":"findmy","rssi":-61,"minutes":30}}],
 "items":[{"mac":"d3:4a:10:22:9c:01","rssi":-61,"name":"","mfr":76,"svc":"","ad":"1219a1b2c3d4e5f60718293a","rnd":true,"conn":false},
          {"mac":"f0:99:19:aa:bb:cc","rssi":-70,"name":"Mi Band 7","mfr":343,"svc":"fee0","ad":"0102","rnd":false,"conn":true}]}
```

| Πεδίο | Σημασία |
|---|---|
| `mac` | διεύθυνση όπως εκπέμπεται (συνήθως **τυχαία** και αλλάζει) |
| `rssi` | η ισχυρότερη τιμή της σάρωσης (dBm) |
| `name` | όνομα από τη διαφήμιση, έως 20 bytes, ή `""` |
| `mfr` | Bluetooth company id (π.χ. 76 = Apple), ή `-1` |
| `svc` | το πρώτο 16-bit service UUID (4 hex)· αν δεν υπάρχει λίστα UUID, το UUID των service data· αλλιώς `""` |
| `ad` | hex των πρώτων ≤12 bytes των manufacturer data, **μετά** το company id |
| `rnd` | `true` = τυχαία διεύθυνση |
| `conn` | `true` = η συσκευή δέχεται συνδέσεις (εμείς δεν συνδεόμαστε ποτέ) |

`kind` του `ble_tracker`: `findmy`, `tile`, `smarttag`. Η ειδοποίηση βγαίνει **μία φορά** ανά
διεύθυνση, και ξανά μόνο αν το ιχνηλατικό χαθεί (πάνω από `TRACKER_MISS_CYCLES` κύκλους) και
ξαναμείνει.

## 7. Αντιμετώπιση προβλημάτων

| Σύμπτωμα | Τι να κοιτάξεις |
|---|---|
| `Sketch too big` | δεν διάλεξες partition **min_spiffs** (ενότητα 5) |
| `[ble] controller start failed` | δεν είναι κλασικό ESP32, ή η μνήμη BLE ελευθερώθηκε (άλλαξες το `bleInUse()`;) |
| `[ble] low heap … restarting` | βλ. ενότητα 8 (διαρροή στο ανέβασμα/κατέβασμα)· αν γίνεται συχνά, δοκίμασε `BLE_KEEP_STACK 1` |
| `report FAILED: connect …` μόνο μετά από σάρωση | λίγη μνήμη για το TLS: μείωσε το `BLE_SCAN_SECONDS` ή δες το heap στο Serial |
| λίγες συσκευές | το Wi-Fi μοιράζεται το ίδιο ραδιόφωνο· αύξησε το `BLE_SCAN_SECONDS` |
| `CERT MISMATCH … token NOT sent` | νέο πιστοποιητικό στο NetWatch ή παρεμβολή: νέα σύζευξη / έρευνα |

## 8. Όρια, ιδιωτικότητα, ασφάλεια

- **Μόνο ακρόαση.** Passive scan: δεν στέλνεται scan request, **δεν γίνεται ποτέ σύνδεση** σε
  καμία συσκευή, το ESP32 δεν διαφημίζει τίποτα.
- **Τίποτα δεν αποθηκεύεται.** Ο πίνακας της σάρωσης (διευθύνσεις, ονόματα, δεδομένα) σβήνεται
  από τη RAM μετά από κάθε αναφορά. Στη μνήμη μένουν μόνο οι διευθύνσεις των έως 16 ιχνηλατικών
  που χρονομετρούνται. Τίποτα δεν γράφεται στη flash.
- Η σάρωση βλέπει και συσκευές **γειτόνων και περαστικών**. Χρησιμοποίησέ τη στον δικό σου
  χώρο, για τη δική σου ασφάλεια, και ενημέρωσε όσους δουλεύουν εκεί.
- **Το `ble_tracker` είναι ένδειξη, όχι απόδειξη παρακολούθησης.** Το Find My (`0x12`) το
  εκπέμπουν και iPhone/MacBook/AirPods που είναι εκτός δικτύου, και το AirTag του συναδέλφου
  στο διπλανό γραφείο. Τα ιχνηλατικά αλλάζουν διεύθυνση (το AirTag περίπου κάθε 15 λεπτά όταν
  είναι κοντά στον ιδιοκτήτη του, μία φορά τη μέρα όταν είναι μακριά του): ένα ιχνηλατικό που
  «ταξιδεύει» με τον ιδιοκτήτη του μπορεί να μην συμπληρώσει ποτέ `TRACKER_MINUTES` με την ίδια διεύθυνση.
- **Μνήμη.** Bluetooth + Wi-Fi + TLS σε κλασικό ESP32 είναι σφιχτά. Γι' αυτό σε κάθε κύκλο το
  Bluetooth **κατεβαίνει εντελώς** πριν από το TLS. Αν η ελεύθερη μνήμη πέσει κάτω από
  `HEAP_RESTART_BELOW` (45 KB) πριν από αναφορά, η πλακέτα κάνει επανεκκίνηση (τα ιχνηλατικά
  που χρονομετρούνταν ξεκινούν από την αρχή).
- Όσο γίνεται η αναφορά (~2–4 s) δεν ακούμε. Ο πίνακας χωρά 160 διευθύνσεις ανά σάρωση· σε
  πολύ πυκνό χώρο κρατιούνται οι ισχυρότερες (`table-full` στο Serial).
- Μόνο 1M PHY / legacy advertising (το κλασικό ESP32 δεν έχει BLE 5 extended advertising).

**Πιθανότερα σημεία προσαρμογής σε πραγματικό υλικό:** (α) η ελεύθερη μνήμη μετά από πολλούς
κύκλους ανεβάσματος/κατεβάσματος του Bluedroid (παρακολούθησε το `heap … -> …` στο Serial για
μερικές ώρες), (β) το παράθυρο σάρωσης 60/100 ms σε σχέση με τη σταθερότητα του Wi-Fi,
(γ) το μέγεθος του buffer αναφοράς (14 KB για 80 γραμμές· οι γραμμές που δεν χωρούν παραλείπονται).
