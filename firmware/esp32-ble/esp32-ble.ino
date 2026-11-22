// =============================================================================
//  NetWatch BLE Scanner  v1.0.0   (τύπος αισθητήρα στο NetWatch: "ble")
// -----------------------------------------------------------------------------
//  Περιοδική ΠΑΘΗΤΙΚΗ σάρωση Bluetooth Low Energy σε απλό ESP32:
//
//    * λίστα των συσκευών που εκπέμπουν γύρω (οι 80 ισχυρότερες) -> "items"
//    * ειδοποίηση ble_tracker όταν ένα «ιχνηλατικό» (Apple Find My / AirTag,
//      Tile, Samsung SmartTag) μένει κοντά ΣΥΝΕΧΩΣ για TRACKER_MINUTES λεπτά
//
//  ΑΣΦΑΛΕΙΑ / ΙΔΙΩΤΙΚΟΤΗΤΑ:
//    Μόνο ακούμε διαφημίσεις (passive scan): δεν στέλνουμε scan request, δεν
//    συνδεόμαστε ΠΟΤΕ σε καμία συσκευή, δεν διαφημίζουμε τίποτα. Ο πίνακας των
//    συσκευών (και τα ονόματα) σβήνεται μετά από κάθε αναφορά: στη μνήμη μένουν
//    μόνο οι διευθύνσεις των ιχνηλατικών που παρακολουθούμε.
//
//  Κύκλος (ένα ραδιόφωνο για Wi-Fi ΚΑΙ BLE, και η μνήμη είναι σφιχτή):
//
//      [ BLE επάνω -> σάρωση ~20 s -> BLE ΚΑΤΩ ]  ->  [ Wi-Fi + TLS: αναφορά ]  -> αναμονή
//
//    Το Bluetooth «κατεβαίνει» εντελώς πριν από το TLS, ώστε το handshake
//    (~40 KB) να έχει ελεύθερη μνήμη. Το Wi-Fi μένει συνδεδεμένο στη σάρωση.
//
//  Χρησιμοποιεί το Bluedroid του πυρήνα (esp_gap_ble_api.h), όχι τη βιβλιοθήκη
//  BLE του Arduino: εκείνη δεσμεύει μνήμη για κάθε διαφήμιση που βλέπει.
//
//  ΔΕΝ έχει δοκιμαστεί σε πραγματικό υλικό (μόνο μεταγλώττιση). Βλ. README.
//
//  Μεταγλώττιση:
//    arduino-cli compile --fqbn esp32:esp32:esp32:PartitionScheme=min_spiffs --library ../common .
// =============================================================================

#include <WiFi.h>
#include <esp32-hal-bt.h>
#include <nw_probe.h>     // firmware/common (--library ../common)

#include "secrets.h"      // ΔΕΝ είναι στο git, βλ. secrets.example.h

#if !defined(CONFIG_BLUEDROID_ENABLED)
#error "Αυτό το sketch θέλει ESP32 με Bluedroid (κλασικό ESP32, fqbn esp32:esp32:esp32)."
#endif
#include <esp_bt.h>
#include <esp_bt_main.h>
#include <esp_gap_ble_api.h>

#define FW_VERSION "1.0.0"

// -----------------------------------------------------------------------------
//  Προεπιλογές (αν δεν ορίζονται στο secrets.h)
// -----------------------------------------------------------------------------
#ifndef BLE_SCAN_SECONDS
#define BLE_SCAN_SECONDS 20
#endif
#ifndef REPORT_INTERVAL_S
#define REPORT_INTERVAL_S 60      // ένας κύκλος (σάρωση + αναφορά) κάθε τόσα s
#endif
#ifndef BLE_MIN_RSSI
#define BLE_MIN_RSSI -100         // ασθενέστερες συσκευές αγνοούνται
#endif
#ifndef TRACKER_MINUTES
#define TRACKER_MINUTES 30
#endif
#ifndef TRACKER_MIN_RSSI
#define TRACKER_MIN_RSSI -85      // πιο μακρινά ιχνηλατικά (του γείτονα) δεν μετράνε
#endif
#ifndef TRACKER_MISS_CYCLES
#define TRACKER_MISS_CYCLES 2     // τόσοι κύκλοι χωρίς να φανεί = «έφυγε», το χρονόμετρο μηδενίζει
#endif
#ifndef BLE_KEEP_STACK
#define BLE_KEEP_STACK 0          // 1 = μην κατεβάζεις το Bluetooth ανάμεσα στους κύκλους
#endif
#ifndef HEAP_RESTART_BELOW
#define HEAP_RESTART_BELOW 45000  // λιγότερη ελεύθερη μνήμη πριν από την αναφορά -> επανεκκίνηση
#endif

static const uint16_t BLE_TABLE = 160;   // διαφορετικές συσκευές ανά σάρωση (κρατάμε τις ισχυρότερες)
static const uint8_t  TRK_TABLE = 16;
static const uint8_t  BLE_NAME_MAX  = 20;

enum : uint8_t { TRK_NONE = 0, TRK_FINDMY = 1, TRK_TILE = 2, TRK_SMARTTAG = 3 };
enum : uint8_t { F_RND = 1, F_CONN = 2, F_MFR = 4, F_SVC = 8 };

// (Οι τύποι ορίζονται ΠΡΙΝ από κάθε συνάρτηση, για τα αυτόματα prototypes του Arduino.)
struct BleDev {
  uint8_t addr[6];
  int8_t rssi;            // η ισχυρότερη τιμή της σάρωσης
  uint8_t flags;
  uint16_t mfr;           // company id (αν F_MFR)
  uint16_t svc;           // πρώτο 16-bit service uuid (αν F_SVC)
  uint8_t ad[12];         // πρώτα bytes των manufacturer data (ΜΕΤΑ το company id)
  uint8_t adLen;
  uint8_t tracker;
  char name[BLE_NAME_MAX + 1];
};

struct Tracker {
  uint8_t addr[6];
  uint8_t kind;           // TRK_NONE = ελεύθερη θέση
  uint8_t missed;
  int8_t rssi;
  bool alerted;
  uint32_t firstMs;
};

// Ο πυρήνας ελευθερώνει τη μνήμη του Bluetooth στην εκκίνηση αν «κανείς δεν το
// χρησιμοποιεί». Εμείς χρησιμοποιούμε BLE (όχι Classic: εκείνη η μνήμη δίνεται πίσω).
bool bleInUse(void) { return true; }

// -----------------------------------------------------------------------------
//  Κατάσταση
// -----------------------------------------------------------------------------
static NwProbe nw;
static char g_mac[18] = "";

static BleDev g_dev[BLE_TABLE];              // γράφεται ΜΟΝΟ από το callback όσο τρέχει η σάρωση
static volatile uint16_t g_devCount = 0;
static volatile uint32_t g_advCount = 0, g_tableFull = 0;
static volatile bool g_paramSet = false, g_scanStarted = false, g_scanDone = false, g_scanFail = false;
static uint8_t g_order[BLE_TABLE];           // ταξινόμηση κατά RSSI
static Tracker g_trk[TRK_TABLE];
static bool g_bleUp = false;
static uint32_t g_cycleStart = 0;
static bool g_firstCycle = true;
static uint32_t g_lastWifiTry = 0;

// =============================================================================
//  1. Ανάλυση διαφήμισης (τρέχει στο task του Bluetooth)
// =============================================================================
static uint8_t trackerOfUuid(uint16_t u) {
  if (u == 0xFEED || u == 0xFEEC) return TRK_TILE;       // Tile, Inc.
  if (u == 0xFD5A) return TRK_SMARTTAG;                  // Samsung SmartTag
  return TRK_NONE;
}

static void onAdv(const uint8_t *addr, uint8_t addrType, uint8_t evtType, int rssi, const uint8_t *adv, size_t len) {
  g_advCount = g_advCount + 1;
  if (rssi < BLE_MIN_RSSI || rssi > 20) return;

  // Βρες τη συσκευή ή πιάσε θέση.
  uint16_t n = g_devCount;
  BleDev *d = nullptr;
  for (uint16_t i = 0; i < n; i++) {
    if (memcmp(g_dev[i].addr, addr, 6) == 0) {
      d = &g_dev[i];
      break;
    }
  }
  if (!d) {
    if (n < BLE_TABLE) {
      d = &g_dev[n];
    } else {                                              // γεμάτος: η νέα παίρνει τη θέση της ασθενέστερης
      g_tableFull = g_tableFull + 1;
      uint16_t weakest = 0;
      for (uint16_t i = 1; i < n; i++)
        if (g_dev[i].rssi < g_dev[weakest].rssi) weakest = i;
      if (g_dev[weakest].rssi >= rssi) return;
      d = &g_dev[weakest];
    }
    memset(d, 0, sizeof(*d));
    memcpy(d->addr, addr, 6);
    d->rssi = (int8_t)rssi;
    if (n < BLE_TABLE) g_devCount = (uint16_t)(n + 1);
  }
  if (rssi > d->rssi) d->rssi = (int8_t)rssi;
  if (addrType == BLE_ADDR_TYPE_RANDOM || addrType == BLE_ADDR_TYPE_RPA_RANDOM) d->flags |= F_RND;
  if (evtType == ESP_BLE_EVT_CONN_ADV || evtType == ESP_BLE_EVT_CONN_DIR_ADV) d->flags |= F_CONN;

  // Δομές AD: [μήκος][τύπος][δεδομένα…]. Όλα με έλεγχο ορίων.
  for (size_t i = 0; i + 1 < len;) {
    uint8_t l = adv[i];
    if (l == 0 || i + 1 + l > len) break;
    uint8_t type = adv[i + 1];
    const uint8_t *v = adv + i + 2;
    uint8_t vl = (uint8_t)(l - 1);
    if ((type == 0x09 || type == 0x08) && vl > 0) {       // Complete / Shortened Local Name
      if (type == 0x09 || !d->name[0]) {
        uint8_t c = vl > BLE_NAME_MAX ? BLE_NAME_MAX : vl;
        memcpy(d->name, v, c);
        d->name[c] = '\0';
      }
    } else if (type == 0xFF && vl >= 2) {                 // Manufacturer Specific Data
      uint16_t company = (uint16_t)(v[0] | (v[1] << 8));
      bool findmy = (company == 0x004C && vl >= 3 && v[2] == 0x12);   // Apple «offline finding»
      if (!(d->flags & F_MFR) || findmy) {
        d->flags |= F_MFR;
        d->mfr = company;
        d->adLen = (uint8_t)(vl - 2 > (int)sizeof(d->ad) ? sizeof(d->ad) : vl - 2);
        memcpy(d->ad, v + 2, d->adLen);
      }
      if (findmy) d->tracker = TRK_FINDMY;
    } else if ((type == 0x02 || type == 0x03) && vl >= 2) {   // λίστα 16-bit Service UUIDs
      for (uint8_t k = 0; k + 1 < vl; k += 2) {
        uint16_t u = (uint16_t)(v[k] | (v[k + 1] << 8));
        if (!(d->flags & F_SVC)) {
          d->flags |= F_SVC;
          d->svc = u;
        }
        uint8_t t = trackerOfUuid(u);
        if (t && !d->tracker) d->tracker = t;
      }
    } else if (type == 0x16 && vl >= 2) {                 // Service Data (16-bit UUID)
      uint16_t u = (uint16_t)(v[0] | (v[1] << 8));
      uint8_t t = trackerOfUuid(u);
      if (t) {
        d->tracker = d->tracker ? d->tracker : t;
        d->flags |= F_SVC;                                // το uuid του ιχνηλατικού είναι το πιο χρήσιμο
        d->svc = u;
      } else if (!(d->flags & F_SVC)) {
        d->flags |= F_SVC;
        d->svc = u;
      }
    }
    i += 1u + l;
  }
}

static void gapCallback(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *p) {
  switch (event) {
    case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT:
      if (p->scan_param_cmpl.status != ESP_BT_STATUS_SUCCESS) g_scanFail = true;
      g_paramSet = true;
      break;
    case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT:
      if (p->scan_start_cmpl.status != ESP_BT_STATUS_SUCCESS) g_scanFail = true;
      g_scanStarted = true;
      break;
    case ESP_GAP_BLE_SCAN_RESULT_EVT:
      if (p->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT) {
        size_t len = (size_t)p->scan_rst.adv_data_len + p->scan_rst.scan_rsp_len;
        if (len > sizeof(p->scan_rst.ble_adv)) len = sizeof(p->scan_rst.ble_adv);
        onAdv(p->scan_rst.bda, (uint8_t)p->scan_rst.ble_addr_type, (uint8_t)p->scan_rst.ble_evt_type, p->scan_rst.rssi,
              p->scan_rst.ble_adv, len);
      } else if (p->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_CMPL_EVT) {
        g_scanDone = true;
      }
      break;
    case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT:
      g_scanDone = true;
      break;
    default: break;
  }
}

// =============================================================================
//  2. Bluetooth επάνω / κάτω
// =============================================================================
static bool waitFlag(volatile bool &flag, uint32_t ms) {
  uint32_t t0 = millis();
  while (!flag && millis() - t0 < ms) delay(10);
  return flag;
}

static bool bleUp() {
  if (g_bleUp) return true;
  if (!btStartMode(BT_MODE_BLE)) {
    Serial.println("[ble] controller start failed");
    return false;
  }
  if (esp_bluedroid_get_status() == ESP_BLUEDROID_STATUS_UNINITIALIZED && esp_bluedroid_init() != ESP_OK) {
    Serial.println("[ble] bluedroid init failed");
    btStop();
    return false;
  }
  if (esp_bluedroid_get_status() != ESP_BLUEDROID_STATUS_ENABLED && esp_bluedroid_enable() != ESP_OK) {
    Serial.println("[ble] bluedroid enable failed");
    esp_bluedroid_deinit();
    btStop();
    return false;
  }
  esp_ble_gap_register_callback(gapCallback);
  g_bleUp = true;
  return true;
}

static void bleDown() {
  if (!g_bleUp) return;
  esp_bluedroid_disable();
  esp_bluedroid_deinit();
  btStop();
  g_bleUp = false;
}

// Μία παθητική σάρωση. Μπλοκάρει ~BLE_SCAN_SECONDS (με όριο).
static bool scanOnce() {
  g_devCount = 0;
  g_advCount = 0;
  g_tableFull = 0;
  memset(g_dev, 0, sizeof(g_dev));
  if (!bleUp()) return false;

  esp_ble_scan_params_t sp;
  memset(&sp, 0, sizeof(sp));
  sp.scan_type = BLE_SCAN_TYPE_PASSIVE;            // ΜΟΝΟ ακρόαση: κανένα scan request
  sp.own_addr_type = BLE_ADDR_TYPE_PUBLIC;
  sp.scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL;
  sp.scan_interval = 0x00A0;                       // 100 ms
  sp.scan_window = 0x0060;                         // 60 ms: το υπόλοιπο μένει για το Wi-Fi
  sp.scan_duplicate = BLE_SCAN_DUPLICATE_DISABLE;  // θέλουμε ΟΛΕΣ τις διαφημίσεις μιας συσκευής

  g_paramSet = false;
  g_scanStarted = false;
  g_scanDone = false;
  g_scanFail = false;
  bool ok = esp_ble_gap_set_scan_params(&sp) == ESP_OK && waitFlag(g_paramSet, 2000) && !g_scanFail;
  ok = ok && esp_ble_gap_start_scanning(BLE_SCAN_SECONDS) == ESP_OK && waitFlag(g_scanStarted, 2000) && !g_scanFail;
  if (ok) {
    uint32_t t0 = millis();
    while (!g_scanDone && millis() - t0 < (uint32_t)(BLE_SCAN_SECONDS + 3) * 1000UL) {
      delay(50);
      nwWatchdogFeed();
    }
    if (!g_scanDone) {
      esp_ble_gap_stop_scanning();
      waitFlag(g_scanDone, 1500);
    }
  } else {
    Serial.println("[ble] scan could not start");
  }
#if !BLE_KEEP_STACK
  bleDown();                                        // από εδώ και πέρα ο πίνακας είναι «δικός μας»
#else
  delay(50);
#endif
  return ok;
}

// =============================================================================
//  3. Ιχνηλατικά
// =============================================================================
static const char *trackerKind(uint8_t k) {
  return k == TRK_FINDMY ? "findmy" : k == TRK_TILE ? "tile" : k == TRK_SMARTTAG ? "smarttag" : "";
}

static const char *trackerLabel(uint8_t k) {
  return k == TRK_FINDMY ? "Apple Find My / AirTag" : k == TRK_TILE ? "Tile" : "Samsung SmartTag";
}

static void macText(const uint8_t *m, char *out, size_t cap) {
  snprintf(out, cap, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void trackersUpdate() {
  uint32_t now = millis();
  bool seen[TRK_TABLE] = {false};
  for (uint16_t i = 0; i < g_devCount; i++) {
    const BleDev &d = g_dev[i];
    if (!d.tracker || d.rssi < TRACKER_MIN_RSSI) continue;
    int slot = -1, freeSlot = -1;
    for (uint8_t k = 0; k < TRK_TABLE; k++) {
      if (g_trk[k].kind && memcmp(g_trk[k].addr, d.addr, 6) == 0) slot = k;
      else if (!g_trk[k].kind && freeSlot < 0) freeSlot = k;
    }
    if (slot < 0) {
      if (freeSlot < 0) continue;                    // γεμάτος: αγνόησε (σπάνιο)
      slot = freeSlot;
      memset(&g_trk[slot], 0, sizeof(Tracker));
      memcpy(g_trk[slot].addr, d.addr, 6);
      g_trk[slot].kind = d.tracker;
      g_trk[slot].firstMs = now;
    }
    Tracker &t = g_trk[slot];
    seen[slot] = true;
    t.missed = 0;
    t.rssi = d.rssi;
    if (!t.alerted && now - t.firstMs >= (uint32_t)TRACKER_MINUTES * 60000UL) {
      t.alerted = true;
      char mac[18], txt[180];
      macText(t.addr, mac, sizeof(mac));
      snprintf(txt, sizeof(txt), "Ιχνηλατικό %s (%s) μένει κοντά εδώ και %d λεπτά, σήμα %d dBm", trackerLabel(t.kind), mac,
               (int)TRACKER_MINUTES, (int)t.rssi);
      nw.event("ble_tracker", txt);
      nw.evStr("mac", mac);
      nw.evStr("kind", trackerKind(t.kind));
      nw.evInt("rssi", t.rssi);
      nw.evInt("minutes", TRACKER_MINUTES);
      Serial.printf("[event] ble_tracker %s %s\n", trackerKind(t.kind), mac);
    }
  }
  for (uint8_t k = 0; k < TRK_TABLE; k++) {
    if (g_trk[k].kind && !seen[k] && ++g_trk[k].missed > TRACKER_MISS_CYCLES) g_trk[k].kind = TRK_NONE;   // έφυγε
  }
}

// =============================================================================
//  4. Αναφορά
// =============================================================================
static void sortByRssi() {
  uint16_t n = g_devCount;
  for (uint16_t i = 0; i < n; i++) g_order[i] = (uint8_t)i;
  for (uint16_t i = 1; i < n; i++) {                 // insertion sort, φθίνον RSSI
    uint8_t v = g_order[i];
    int j = (int)i - 1;
    while (j >= 0 && g_dev[g_order[j]].rssi < g_dev[v].rssi) {
      g_order[j + 1] = g_order[j];
      j--;
    }
    g_order[j + 1] = v;
  }
}

static bool wifiReady() {
  if (WiFi.status() == WL_CONNECTED) return true;
  if (g_lastWifiTry && millis() - g_lastWifiTry < 15000) return false;
  g_lastWifiTry = millis();
  Serial.printf("[wifi] connecting to %s ...\n", WIFI_SSID);
  if (!nwWifiConnect(WIFI_SSID, WIFI_PASS, 12000)) {
    Serial.printf("[wifi] not connected (events queued: %u)\n", nw.pending());
    return false;
  }
  Serial.printf("[wifi] ip=%s rssi=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
  return true;
}

static void report() {
  if (!wifiReady()) return;
  if (ESP.getFreeHeap() < HEAP_RESTART_BELOW) {
    // Το ανέβασμα/κατέβασμα του Bluetooth μπορεί με τον καιρό να «τρώει» λίγη
    // μνήμη. Καλύτερα μια καθαρή επανεκκίνηση παρά ένα TLS που αποτυγχάνει σιωπηλά.
    Serial.printf("[ble] low heap (%u) - restarting\n", (unsigned)ESP.getFreeHeap());
    delay(100);
    ESP.restart();
  }
  sortByRssi();
  NwJson &j = nw.start(WiFi.localIP().toString().c_str(), g_mac, WiFi.RSSI());
  j.beginObject("metrics");
  j.integer("seen", g_devCount);
  j.endObject();
  nw.items();
  char mac[18], hex[2 * sizeof(g_dev[0].ad) + 1], svc[5];
  for (uint16_t i = 0; i < g_devCount; i++) {
    const BleDev &d = g_dev[g_order[i]];
    if (!nw.rowBegin()) break;                       // 80 γραμμές ή γέμισε το buffer
    macText(d.addr, mac, sizeof(mac));
    hex[0] = svc[0] = '\0';
    for (uint8_t k = 0; k < d.adLen; k++) snprintf(hex + 2 * k, 3, "%02x", d.ad[k]);
    if (d.flags & F_SVC) snprintf(svc, sizeof(svc), "%04x", d.svc);
    j.str("mac", mac);
    j.integer("rssi", d.rssi);
    j.str("name", d.name);                           // escape + έλεγχος UTF-8 μέσα στο NwJson
    j.integer("mfr", (d.flags & F_MFR) ? (long)d.mfr : -1L);
    j.str("svc", svc);
    j.str("ad", hex);
    j.boolean("rnd", d.flags & F_RND);
    j.boolean("conn", d.flags & F_CONN);
    nw.rowEnd();
  }
  uint8_t rows = nw.rows();
  NwResult r = nw.send();
  if (r == NW_OK) Serial.printf("[nw] report ok: %u devices, %u rows (next in %lu s)\n", (unsigned)g_devCount, rows, (unsigned long)nw.intervalS());
  else Serial.printf("[nw] report FAILED: %s (try %u, queued events %u)\n", nw.lastError(), nw.fails(), nw.pending());
}

// =============================================================================
//  5. setup / loop
// =============================================================================
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.printf("\n[ble] NetWatch BLE Scanner %s\n", FW_VERSION);

  WiFi.mode(WIFI_STA);
  nwWifiMac(g_mac, sizeof(g_mac));
  // 14 KB: 80 γραμμές των ~150 bytes, κάτω από το όριο των 16 KB του server.
  if (!nw.begin(NW_PAIR_CODE, FW_VERSION, "ESP32 BLE scanner", 14000, REPORT_INTERVAL_S)) {
    Serial.printf("[nw] NOT PAIRED: %s\n", nw.lastError());
    Serial.println("[nw] Στο NetWatch: Οι συσκευές μου -> BLE -> Δημιουργία κωδικού, και βάλ' τον στο NW_PAIR_CODE του secrets.h");
  } else {
    Serial.printf("[nw] paired as %s (kind=%s)\n", nw.id(), nw.kind());
    if (strcmp(nw.kind(), "ble") != 0) Serial.println("[nw] WARNING: ο κωδικός δεν είναι τύπου 'ble'");
  }
  nwWatchdog(120);
  if (nw.paired()) nwWifiConnect(WIFI_SSID, WIFI_PASS, 12000);   // πρώτα Wi-Fi, μετά BLE (συνύπαρξη)
}

void loop() {
  uint32_t period = (uint32_t)nw.intervalS() * 1000UL;
  uint32_t minPeriod = (uint32_t)(BLE_SCAN_SECONDS + 10) * 1000UL;
  if (period < minPeriod) period = minPeriod;
  if (!g_firstCycle && millis() - g_cycleStart < period) {
    if (nw.pending() && nw.due() && wifiReady()) {   // γεγονός που έμεινε από αποτυχημένη αναφορά
      nw.start(WiFi.localIP().toString().c_str(), g_mac, WiFi.RSSI());
      nw.send();                                     // χωρίς "items": ο server κρατά την παλιά λίστα
    }
    delay(50);
    return;
  }
  g_firstCycle = false;
  g_cycleStart = millis();

  uint32_t heapBefore = ESP.getFreeHeap();
  bool ok = scanOnce();
  Serial.printf("[ble] scan %s: %u devices, %lu adverts, table-full %lu, heap %u -> %u\n", ok ? "ok" : "FAILED",
                (unsigned)g_devCount, (unsigned long)g_advCount, (unsigned long)g_tableFull, (unsigned)heapBefore,
                (unsigned)ESP.getFreeHeap());
  if (ok) {
    trackersUpdate();
    if (nw.due()) report();
  }
  // Ιδιωτικότητα: τίποτα από τη σάρωση (ονόματα, δεδομένα) δεν μένει στη μνήμη.
  memset(g_dev, 0, sizeof(g_dev));
  g_devCount = 0;
}
