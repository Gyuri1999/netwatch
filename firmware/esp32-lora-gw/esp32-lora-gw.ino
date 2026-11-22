// =============================================================================
//  NetWatch LoRa Gateway  v1.0.0   (τύπος αισθητήρα στο NetWatch: "lora")
// -----------------------------------------------------------------------------
//  Πύλη για τους κόμβους esp32-lora-node. Ακούει ΣΥΝΕΧΩΣ στο LoRa (SX1276),
//  ελέγχει κάθε πακέτο (HMAC-SHA256 + μετρητή κατά του replay), κρατά πίνακα
//  κόμβων και τον προωθεί στο NetWatch μέσω Wi-Fi (nw_probe.h) ως "items".
//
//  Γεγονότα: door_open, temp_high, batt_low, lora_node_lost (σιωπή 3x την
//  περίοδο του κόμβου).
//
//  Η πύλη ΔΕΝ εκπέμπει ποτέ στο LoRa (ούτε ACK): άρα δεν έχει θέμα duty cycle.
//
//  ΑΣΦΑΛΕΙΑ:
//    * Πακέτο χωρίς σωστό HMAC αγνοείται (μετριέται στο rx_bad).
//    * Πακέτο με μετρητή <= του τελευταίου που δεχτήκαμε από τον ίδιο κόμβο
//      αγνοείται (replay). Ο τελευταίος μετρητής κάθε κόμβου γράφεται στο NVS,
//      ώστε μια επανεκκίνηση της πύλης να ΜΗΝ ξανανοίγει την πόρτα σε παλιά πακέτα.
//    * Νέος κόμβος μπαίνει στον πίνακα μόνο ΑΦΟΥ περάσει το HMAC.
//
//  ΔΕΝ έχει δοκιμαστεί σε πραγματικό υλικό (μόνο μεταγλώττιση). Βλ. README.
//
//  Μεταγλώττιση:  arduino-cli compile --fqbn esp32:esp32:esp32 --library ../common .
// =============================================================================

#include <WiFi.h>
#include <SPI.h>
#include <Preferences.h>
#include <nw_probe.h>     // firmware/common (--library ../common)
#include <nw_lora.h>

#include "secrets.h"      // ΔΕΝ είναι στο git, βλ. secrets.example.h

#define FW_VERSION "1.0.0"

// -----------------------------------------------------------------------------
//  Προεπιλογές (αν δεν ορίζονται στο secrets.h). Pins: TTGO LoRa32 V1 / Heltec V2.
// -----------------------------------------------------------------------------
#ifndef LORA_FREQ_HZ
#define LORA_FREQ_HZ 868100000UL
#endif
#ifndef LORA_SF
#define LORA_SF 9
#endif
#ifndef LORA_BW_HZ
#define LORA_BW_HZ 125000UL
#endif
#ifndef LORA_CR
#define LORA_CR 5
#endif
#ifndef PIN_LORA_SCK
#define PIN_LORA_SCK 5
#endif
#ifndef PIN_LORA_MISO
#define PIN_LORA_MISO 19
#endif
#ifndef PIN_LORA_MOSI
#define PIN_LORA_MOSI 27
#endif
#ifndef PIN_LORA_SS
#define PIN_LORA_SS 18
#endif
#ifndef PIN_LORA_RST
#define PIN_LORA_RST 14
#endif
#ifndef PIN_BUTTON
#define PIN_BUTTON 0          // PRG/BOOT: κρατημένο 3 s στην εκκίνηση = ξέχνα τους μετρητές
#endif
#ifndef LORA_TEMP_HIGH_C
#define LORA_TEMP_HIGH_C 35.0f
#endif
#ifndef LORA_TEMP_HYST_C
#define LORA_TEMP_HYST_C 2.0f
#endif
#ifndef LORA_BATT_LOW_V
#define LORA_BATT_LOW_V 3.40f
#endif
#ifndef REPORT_INTERVAL_S
#define REPORT_INTERVAL_S 60
#endif

static const uint8_t  MAX_NODES = 24;        // ο server δέχεται έως 80 γραμμές· 24 φτάνουν για ένα κτίριο
static const uint32_t LOST_SLACK_S = 30;

// (Οι τύποι ορίζονται ΠΡΙΝ από κάθε συνάρτηση, για τα αυτόματα prototypes του Arduino.)
struct Node {
  uint16_t id;            // 0 = ελεύθερη θέση
  uint32_t seq;           // τελευταίος μετρητής που δεχτήκαμε (0 = κανένας)
  uint32_t lastMs;
  uint16_t intervalS;
  int16_t rssi;
  float snr, batt, temp, hum;
  bool heard;             // ακούστηκε από την τελευταία εκκίνηση της πύλης
  bool hasDoor, door, hasTemp, hasHum;
  bool lost, tempAlarm, battLow;
};

// -----------------------------------------------------------------------------
//  Κατάσταση
// -----------------------------------------------------------------------------
static NwProbe nw;
static NwSx1276 radio;
static Preferences g_prefs;
static uint8_t g_key[NWL_KEY_LEN];
static bool g_keyOk = false, g_radioOk = false;
static char g_mac[18] = "";
static Node g_nodes[MAX_NODES];
static uint32_t g_rxOk = 0, g_rxBad = 0, g_rxReplay = 0, g_rxCrc = 0;
static uint32_t g_lastWifiTry = 0, g_lastLostCheck = 0, g_lastRadioRetry = 0;

// =============================================================================
//  1. Πίνακας κόμβων
// =============================================================================
static void nodeKey(uint16_t id, char *out, size_t cap) { snprintf(out, cap, "s%04x", id); }
static void nodeName(uint16_t id, char *out, size_t cap) { snprintf(out, cap, "n%u", (unsigned)id); }

// Βρίσκει ή δημιουργεί. Καλείται ΜΟΝΟ για πακέτα που πέρασαν το HMAC.
static int nodeSlot(uint16_t id) {
  int freeSlot = -1;
  for (uint8_t i = 0; i < MAX_NODES; i++) {
    if (g_nodes[i].id == id) return i;
    if (g_nodes[i].id == 0 && freeSlot < 0) freeSlot = i;
  }
  if (freeSlot < 0) return -1;
  Node &n = g_nodes[freeSlot];
  memset(&n, 0, sizeof(n));
  n.id = id;
  char key[8];
  nodeKey(id, key, sizeof(key));
  n.seq = g_prefs.getUInt(key, 0);             // ο μετρητής που θυμόμαστε από πριν την επανεκκίνηση
  return freeSlot;
}

// =============================================================================
//  2. Λήψη
// =============================================================================
static void onPacket(const uint8_t *buf, int len, int rssi, float snr) {
  NwLoraPacket p;
  if (!nwLoraDecode(buf, (size_t)len, g_key, p)) {
    g_rxBad++;                                 // ξένο LoRa, άλλο κλειδί ή πλαστό πακέτο
    Serial.printf("[lora] rejected %d bytes (not ours / bad HMAC) rssi=%d\n", len, rssi);
    return;
  }
  int slot = nodeSlot(p.node);
  if (slot < 0) {
    Serial.printf("[lora] node table full, ignoring n%u\n", (unsigned)p.node);
    return;
  }
  Node &n = g_nodes[slot];
  char name[12];
  nodeName(p.node, name, sizeof(name));
  if (p.seq <= n.seq) {
    if (p.seq == n.seq && n.heard) return;     // η 2η αποστολή του ίδιου γεγονότος: φυσιολογικό
    g_rxReplay++;
    Serial.printf("[lora] %s REPLAY/old counter %lu <= %lu - ignored (αν ξανάγραψες τον κόμβο: βλ. README)\n", name,
                  (unsigned long)p.seq, (unsigned long)n.seq);
    return;
  }
  // --- έγκυρο, φρέσκο πακέτο ---
  g_rxOk++;
  n.seq = p.seq;
  char key[8];
  nodeKey(p.node, key, sizeof(key));
  g_prefs.putUInt(key, n.seq);

  bool prevDoor = n.door, prevHeard = n.heard;
  n.heard = true;
  n.lastMs = millis();
  n.intervalS = p.intervalS >= 10 ? p.intervalS : 10;
  n.rssi = (int16_t)rssi;
  n.snr = snr;
  n.batt = p.battMv / 1000.0f;
  n.hasTemp = p.tempC100 != NWL_TEMP_NONE;
  n.hasHum = p.humHalf != NWL_HUM_NONE;
  n.temp = n.hasTemp ? p.tempC100 / 100.0f : NAN;
  n.hum = n.hasHum ? p.humHalf / 2.0f : NAN;
  n.hasDoor = p.flags & NWL_F_HAS_DOOR;
  n.door = p.flags & NWL_F_DOOR_OPEN;
  n.lost = false;
  Serial.printf("[lora] %s seq=%lu rssi=%d snr=%.1f batt=%.2f temp=%.1f hum=%.0f door=%d flags=0x%02X\n", name,
                (unsigned long)p.seq, rssi, snr, n.batt, n.temp, n.hum, (int)n.door, p.flags);

  char txt[160];
  // Πόρτα: «άνοιξε» αν τώρα είναι ανοιχτή και πριν δεν ήταν, ή αν ο κόμβος λέει
  // ότι άλλαξε αλλά τη βρίσκουμε πάλι κλειστή (άνοιξε και έκλεισε ενδιάμεσα).
  if (n.hasDoor) {
    bool opened = n.door && (!prevHeard ? (p.flags & NWL_F_DOOR_EVT) : !prevDoor);
    bool pulse = !n.door && prevHeard && !prevDoor && (p.flags & NWL_F_DOOR_EVT);
    if (opened || pulse) {
      snprintf(txt, sizeof(txt), opened ? "Άνοιξε η πόρτα στον κόμβο LoRa %s" : "Η πόρτα στον κόμβο LoRa %s άνοιξε και έκλεισε", name);
      nw.event("door_open", txt);
      nw.evStr("node", name);
      nw.evBool("door", n.door);
    }
  }
  if (n.hasTemp) {
    if (!n.tempAlarm && n.temp >= LORA_TEMP_HIGH_C) {
      n.tempAlarm = true;
      snprintf(txt, sizeof(txt), "Θερμοκρασία %.1f °C στον κόμβο LoRa %s (όριο %.1f °C)", n.temp, name, (double)LORA_TEMP_HIGH_C);
      nw.event("temp_high", txt);
      nw.evStr("node", name);
      nw.evNum("temp", n.temp, 1);
    } else if (n.tempAlarm && n.temp <= LORA_TEMP_HIGH_C - LORA_TEMP_HYST_C) {
      n.tempAlarm = false;
    }
  }
  if (p.battMv > 0) {
    bool low = (p.flags & NWL_F_BATT_LOW) || n.batt < LORA_BATT_LOW_V;
    if (!n.battLow && low) {
      n.battLow = true;
      snprintf(txt, sizeof(txt), "Χαμηλή μπαταρία (%.2f V) στον κόμβο LoRa %s", n.batt, name);
      nw.event("batt_low", txt);
      nw.evStr("node", name);
      nw.evNum("batt", n.batt, 2);
    } else if (n.battLow && !low && n.batt >= LORA_BATT_LOW_V + 0.15f) {
      n.battLow = false;                       // άλλαξε/φόρτισε η μπαταρία
    }
  }
  nw.kick();                                   // φρέσκα δεδομένα: ενημέρωσε το NetWatch σύντομα
}

// Κόμβος που σώπασε για 3x την περίοδό του -> ένα γεγονός (μέχρι να ξανακουστεί).
static void lostCheck() {
  if (millis() - g_lastLostCheck < 10000) return;
  g_lastLostCheck = millis();
  for (uint8_t i = 0; i < MAX_NODES; i++) {
    Node &n = g_nodes[i];
    if (!n.id || !n.heard || n.lost) continue;
    uint32_t silentS = (millis() - n.lastMs) / 1000UL;
    if (silentS <= 3UL * n.intervalS + LOST_SLACK_S) continue;
    n.lost = true;
    char name[12], txt[160];
    nodeName(n.id, name, sizeof(name));
    snprintf(txt, sizeof(txt), "Ο κόμβος LoRa %s σώπασε (%lu λεπτά χωρίς πακέτο): μπαταρία, κεραία ή απόσταση;", name,
             (unsigned long)(silentS / 60));
    nw.event("lora_node_lost", txt);
    nw.evStr("node", name);
    nw.evInt("silent_s", (long)silentS);
    Serial.printf("[event] lora_node_lost %s\n", name);
  }
}

// =============================================================================
//  3. Αναφορά
// =============================================================================
static void report() {
  if (WiFi.status() != WL_CONNECTED) {
    if (g_lastWifiTry && millis() - g_lastWifiTry < 15000) return;
    g_lastWifiTry = millis();
    Serial.printf("[wifi] connecting to %s ...\n", WIFI_SSID);
    if (!nwWifiConnect(WIFI_SSID, WIFI_PASS, 10000)) {
      Serial.printf("[wifi] not connected (events queued: %u)\n", nw.pending());
      return;
    }
    Serial.printf("[wifi] ip=%s rssi=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
  }
  uint8_t heard = 0;
  for (uint8_t i = 0; i < MAX_NODES; i++) heard += (g_nodes[i].id && g_nodes[i].heard) ? 1 : 0;

  NwJson &j = nw.start(WiFi.localIP().toString().c_str(), g_mac, WiFi.RSSI());
  j.beginObject("metrics");
  j.integer("nodes", heard);
  j.integer("rx_ok", (long)g_rxOk);
  j.integer("rx_bad", (long)g_rxBad);         // λάθος HMAC / ξένα πακέτα
  j.integer("replay", (long)g_rxReplay);      // παλιός μετρητής
  j.boolean("radio", g_radioOk);
  j.endObject();
  nw.items();
  for (uint8_t i = 0; i < MAX_NODES; i++) {
    const Node &n = g_nodes[i];
    if (!n.id || !n.heard) continue;
    if (!nw.rowBegin()) break;
    char name[12];
    nodeName(n.id, name, sizeof(name));
    j.str("node", name);
    j.integer("rssi", n.rssi);
    j.num("snr", n.snr, 1);
    if (n.batt > 0) j.num("batt", n.batt, 2);
    if (n.hasTemp) j.num("temp", n.temp, 1);
    if (n.hasHum) j.num("hum", n.hum, 1);
    if (n.hasDoor) j.boolean("door", n.door);
    j.integer("age", (long)((millis() - n.lastMs) / 1000UL));
    j.integer("seq", (long)n.seq);
    nw.rowEnd();
  }
  NwResult r = nw.send();
  if (r == NW_OK) Serial.printf("[nw] report ok: %u nodes (next in %lu s)\n", heard, (unsigned long)nw.intervalS());
  else Serial.printf("[nw] report FAILED: %s (try %u, queued events %u)\n", nw.lastError(), nw.fails(), nw.pending());
}

// =============================================================================
//  4. setup / loop
// =============================================================================
static bool radioStart() {
  g_radioOk = radio.begin(SPI, PIN_LORA_SS, PIN_LORA_RST, LORA_FREQ_HZ, LORA_SF, LORA_BW_HZ, LORA_CR, 2);
  if (g_radioOk) radio.receive();
  return g_radioOk;
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.printf("\n[gw] NetWatch LoRa Gateway %s\n", FW_VERSION);

  g_prefs.begin("nwloragw", false);
  pinMode(PIN_BUTTON, INPUT_PULLUP);
  if (digitalRead(PIN_BUTTON) == LOW) {        // κρατημένο 3 s: σβήσε τους μετρητές των κόμβων
    uint32_t t0 = millis();
    while (digitalRead(PIN_BUTTON) == LOW && millis() - t0 < 3000) delay(20);
    if (millis() - t0 >= 3000) {
      g_prefs.clear();
      Serial.println("[gw] node counters ERASED (button held at boot)");
    }
  }

  g_keyOk = nwLoraParseKey(LORA_KEY_HEX, g_key);
  if (!g_keyOk) Serial.println("[gw] ΛΑΘΟΣ ΡΥΘΜΙΣΗ: βάλε LORA_KEY_HEX (64 hex, ίδιο με των κόμβων) στο secrets.h - κανένα πακέτο δεν γίνεται δεκτό");

  SPI.begin(PIN_LORA_SCK, PIN_LORA_MISO, PIN_LORA_MOSI, PIN_LORA_SS);
  if (radioStart()) {
    Serial.printf("[lora] SX1276 ok: %.3f MHz SF%d BW%lu CR4/%d, packet air time %lu ms\n", LORA_FREQ_HZ / 1e6, (int)LORA_SF,
                  (unsigned long)LORA_BW_HZ, (int)LORA_CR, (unsigned long)nwLoraAirtimeMs(NWL_PKT_LEN, LORA_SF, LORA_BW_HZ, LORA_CR));
  } else {
    Serial.println("[lora] SX1276 NOT FOUND (pins? SX1262 board?) - will retry every 30 s");
  }

  WiFi.mode(WIFI_STA);
  nwWifiMac(g_mac, sizeof(g_mac));
  if (!nw.begin(NW_PAIR_CODE, FW_VERSION, "ESP32 LoRa gateway (SX1276)", 4096, REPORT_INTERVAL_S)) {
    Serial.printf("[nw] NOT PAIRED: %s\n", nw.lastError());
    Serial.println("[nw] Στο NetWatch: Οι συσκευές μου -> LoRa -> Δημιουργία κωδικού, και βάλ' τον στο NW_PAIR_CODE του secrets.h");
  } else {
    Serial.printf("[nw] paired as %s (kind=%s)\n", nw.id(), nw.kind());
    if (strcmp(nw.kind(), "lora") != 0) Serial.println("[nw] WARNING: ο κωδικός δεν είναι τύπου 'lora'");
  }
  nwWatchdog(90);
}

void loop() {
  if (g_radioOk && g_keyOk) {
    uint8_t buf[64];
    int rssi = 0;
    float snr = 0;
    int n = radio.readPacket(buf, sizeof(buf), &rssi, &snr);
    if (n > 0) onPacket(buf, n, rssi, snr);
    else if (n < 0) g_rxCrc++;                 // θόρυβος / σύγκρουση
  } else if (!g_radioOk && millis() - g_lastRadioRetry > 30000) {
    g_lastRadioRetry = millis();
    radioStart();
  }
  lostCheck();
  if (nw.due()) report();
  delay(5);
}
