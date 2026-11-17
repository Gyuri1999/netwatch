// =============================================================================
//  NetWatch Sentinel  v1.1.0
// -----------------------------------------------------------------------------
//  Μικρός ΠΑΘΗΤΙΚΟΣ ασύρματος αισθητήρας ασφαλείας για ESP32.
//  Αναφέρει στο NetWatch (μέσω MQTT over TLS) τα εξής:
//
//    1. Deauth / disassoc flood  (promiscuous mode, εναλλαγή καναλιών 1-13)
//    2. Evil twin / rogue AP     (περιοδικό WiFi.scanNetworks)
//    3. Heartbeat                (uptime, heap, RSSI, IP, έκδοση, μετρητές)
//
//  ΑΣΦΑΛΕΙΑ / ΗΘΙΚΗ:
//    Ο κώδικας ΜΟΝΟ ακούει. ΔΕΝ στέλνει ποτέ deauth ή άλλα πλαίσια διαχείρισης,
//    δεν χρησιμοποιεί esp_wifi_80211_tx() και δεν κάνει καμία "αντεπίθεση".
//    Η ανίχνευση είναι αμυντική και νόμιμη στο δικό σου δίκτυο.
//
//  Γιατί κύκλος "ακρόαση <-> σύνδεση";
//    Το ESP32 έχει ΕΝΑ ραδιόφωνο. Για να ακούει όλα τα κανάλια πρέπει να
//    αλλάζει κανάλι συνέχεια, ενώ η σύνδεση Wi-Fi το "κλειδώνει" στο κανάλι
//    του router. Άρα εναλλάσσουμε:
//
//       [ SNIFF ~22 s ]  ->  [ ONLINE ~5-8 s ]  ->  [ SNIFF ... ]
//        hop 1..13           scan, Wi-Fi, MQTT,
//        μέτρηση deauth      publish ουράς, heartbeat
//
//    Trade-off: όσο είμαστε ONLINE δεν ακούμε (τυφλό διάστημα), και όσο
//    ακούμε δεν είμαστε συνδεδεμένοι (οι αναφορές καθυστερούν έως έναν κύκλο).
//    Γι' αυτό τα γεγονότα μπαίνουν σε μια μικρή ουρά (ring buffer).
// =============================================================================

#include <WiFi.h>
#include <Preferences.h>
#include <esp_wifi.h>      // promiscuous mode, αλλαγή καναλιού
#include <esp_mac.h>       // esp_read_mac()
#include <mqtt_client.h>   // esp-mqtt (ESP-IDF), ενσωματωμένο στον πυρήνα

#include "secrets.h"       // ΔΕΝ είναι στο git, βλ. secrets.example.h
#include "sentinel_types.h" // struct/enum του firmware

// Υπογεγραμμένο OTA: προαιρετικό. Ένα παλιό secrets.h χωρίς OTA_ENABLE
// συνεχίζει να μεταγλωττίζεται (OTA ανενεργό).
#ifndef OTA_ENABLE
#define OTA_ENABLE 0
#endif
#if OTA_ENABLE
// Από τη βιβλιοθήκη firmware/common (NetWatchSignedOta). Μεταγλώττιση με
//   arduino-cli compile --library ../common ...   (βλ. README)
#include <signed_ota.h>
#endif

// -----------------------------------------------------------------------------
//  Σταθερές & προεπιλογές (αν δεν ορίζονται στο secrets.h)
// -----------------------------------------------------------------------------
#define FW_VERSION "1.1.0"      // ΙΔΙΑ με το --version του tools/ota/ota_sign.py
#define OTA_DEVICE_CLASS "sentinel"

#ifndef SNIFF_SECONDS
#define SNIFF_SECONDS 22
#endif
#ifndef CHANNEL_DWELL_MS
#define CHANNEL_DWELL_MS 1000
#endif
#ifndef HEARTBEAT_INTERVAL_S
#define HEARTBEAT_INTERVAL_S 30
#endif
#ifndef SCAN_INTERVAL_S
#define SCAN_INTERVAL_S 60
#endif
#ifndef OTA_INTERVAL_H
#define OTA_INTERVAL_H 6      // έλεγχος για νέο firmware: στην εκκίνηση + κάθε τόσες ώρες
#endif
#ifndef OTA_SELFTEST_S
#define OTA_SELFTEST_S 300    // νέο firmware: αν δεν συνδεθεί στο MQTT μέσα σε τόσα s -> rollback
#endif

static const uint8_t  FIRST_CHANNEL        = 1;
static const uint8_t  LAST_CHANNEL         = 13;    // Ευρώπη: 1-13
static const uint32_t WIFI_CONNECT_TIMEOUT = 15000; // ms
static const uint32_t MQTT_CONNECT_TIMEOUT = 10000; // ms (το TLS handshake θέλει 1-3 s)
static const uint32_t MQTT_FLUSH_TIMEOUT   = 5000;  // ms αναμονή για PUBACK
static const uint32_t TWIN_COOLDOWN_S      = 600;   // ξανα-αναφορά ίδιου BSSID μετά από 10'
static const uint32_t TIMING_SLACK_MS      = 5000;  // ανοχή στους περιοδικούς χρονισμούς

// -----------------------------------------------------------------------------
//  Ταυτότητα & topics (υπολογίζονται στο setup από τη MAC)
// -----------------------------------------------------------------------------
static char g_id[20];            // "sentinel-a1b2c3"
static char g_topicStatus[64];   // netwatch/sensor/<id>/status  (retained)
static char g_topicEvent[64];    // netwatch/sensor/<id>/event   (όχι retained)
static char g_brokerUri[128];    // mqtts://<host>:8883

// Μετρητές (διατηρούνται στη flash με Preferences ανάμεσα σε επανεκκινήσεις)
static uint32_t g_deauthTotal = 0;
static uint32_t g_twinsTotal  = 0;
static uint32_t g_dropped     = 0;   // γεγονότα που χάθηκαν επειδή γέμισε η ουρά
static bool     g_countersDirty = false;
static Preferences g_prefs;

// =============================================================================
//  1. ΒΟΗΘΗΤΙΚΑ
// =============================================================================

// Χρόνος λειτουργίας σε δευτερόλεπτα (το "t" των γεγονότων).
static uint32_t uptimeS() { return (uint32_t)(millis() / 1000UL); }

// MAC -> "aa:bb:cc:dd:ee:ff" (πεζά). Το out πρέπει να έχει χώρο >= 18.
static void macToStr(const uint8_t *mac, char *out, size_t len) {
  snprintf(out, len, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static bool isBroadcast(const uint8_t *mac) {
  for (int i = 0; i < 6; i++) if (mac[i] != 0xFF) return false;
  return true;
}

// Ασφαλής εισαγωγή string σε JSON: escape για " \ και χαρακτήρες ελέγχου.
// (Ένα SSID μπορεί να περιέχει οτιδήποτε. Χωρίς escape, ένας επιτιθέμενος
//  θα μπορούσε να "σπάσει" το JSON με ένα SSID όπως  x","type":"fake  .)
static void jsonEscape(const char *in, char *out, size_t len) {
  size_t o = 0;
  for (; *in && o + 7 < len; in++) {
    unsigned char c = (unsigned char)*in;
    if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
    else if (c < 0x20)         { o += snprintf(out + o, len - o, "\\u%04x", c); }
    else                       { out[o++] = (char)c; }
  }
  out[o] = '\0';
}

// -----------------------------------------------------------------------------
//  Επίπεδα ασφάλειας Wi-Fi
// -----------------------------------------------------------------------------
// Κάθε τρόπος πιστοποίησης παίρνει ένα όνομα (για το JSON) και έναν "βαθμό"
// (rank). Μικρότερος βαθμός = ασθενέστερη ασφάλεια. (SecurityInfo: βλ. header)

static const SecurityInfo SECURITY_TABLE[] = {
  { WIFI_AUTH_OPEN,                    "open",      0 },
  { WIFI_AUTH_OWE,                     "owe",       1 },  // κρυπτογραφημένο, αλλά χωρίς κωδικό
  { WIFI_AUTH_WEP,                     "wep",       1 },  // σπάει σε λεπτά
  { WIFI_AUTH_WPA_PSK,                 "wpa",       2 },
  { WIFI_AUTH_WPA_WPA2_PSK,            "wpa/wpa2",  2 },  // δέχεται και WPA
  { WIFI_AUTH_WPA_ENTERPRISE,          "wpa-ent",   2 },
  { WIFI_AUTH_WPA2_PSK,                "wpa2",      3 },
  { WIFI_AUTH_WPA2_ENTERPRISE,         "wpa2-ent",  3 },
  { WIFI_AUTH_WPA2_WPA3_PSK,           "wpa2/wpa3", 3 },  // δέχεται και WPA2
  { WIFI_AUTH_WAPI_PSK,                "wapi",      3 },
  { WIFI_AUTH_WPA3_PSK,                "wpa3",      4 },
  { WIFI_AUTH_WPA3_EXT_PSK,            "wpa3",      4 },
  { WIFI_AUTH_WPA3_EXT_PSK_MIXED_MODE, "wpa3",      4 },
  { WIFI_AUTH_DPP,                     "wpa3",      4 },
  { WIFI_AUTH_WPA2_WPA3_ENTERPRISE,    "wpa3-ent",  4 },
  { WIFI_AUTH_WPA3_ENTERPRISE,         "wpa3-ent",  4 },
  { WIFI_AUTH_WPA3_ENT_192,            "wpa3-ent",  4 },
};
static const size_t SECURITY_COUNT = sizeof(SECURITY_TABLE) / sizeof(SECURITY_TABLE[0]);

static const SecurityInfo *securityFor(wifi_auth_mode_t mode) {
  for (size_t i = 0; i < SECURITY_COUNT; i++)
    if (SECURITY_TABLE[i].mode == mode) return &SECURITY_TABLE[i];
  return nullptr;
}

// Βαθμός από όνομα (για το EXPECTED_SECURITY). Άγνωστο όνομα -> 3 (wpa2).
static uint8_t rankForName(const char *name) {
  for (size_t i = 0; i < SECURITY_COUNT; i++)
    if (strcasecmp(SECURITY_TABLE[i].name, name) == 0) return SECURITY_TABLE[i].rank;
  return 3;
}

// =============================================================================
//  2. ΟΥΡΑ ΓΕΓΟΝΟΤΩΝ (ring buffer)
// -----------------------------------------------------------------------------
//  Τα γεγονότα εντοπίζονται όσο είμαστε ΕΚΤΟΣ δικτύου, οπότε τα κρατάμε εδώ
//  μέχρι την επόμενη φάση ONLINE. Αν γεμίσει, γράφουμε πάνω στο ΠΑΛΑΙΟΤΕΡΟ
//  (τα πρόσφατα είναι πιο χρήσιμα) και αυξάνουμε τον μετρητή g_dropped.
//  Η ουρά γεμίζει/αδειάζει ΜΟΝΟ από το loop(), άρα δεν χρειάζεται κλείδωμα.
// =============================================================================
// (Ο τύπος SentinelEvent ορίζεται στο sentinel_types.h)
static const size_t QUEUE_SIZE = 16;
static SentinelEvent g_queue[QUEUE_SIZE];
static size_t g_qHead = 0;   // θέση του παλαιότερου
static size_t g_qCount = 0;

static void queuePush(const SentinelEvent &ev) {
  if (g_qCount == QUEUE_SIZE) {               // γεμάτη: πετάμε το παλαιότερο
    g_qHead = (g_qHead + 1) % QUEUE_SIZE;
    g_qCount--;
    g_dropped++;
  }
  g_queue[(g_qHead + g_qCount) % QUEUE_SIZE] = ev;
  g_qCount++;
}

static SentinelEvent *queuePeek() { return g_qCount ? &g_queue[g_qHead] : nullptr; }

static void queuePop() {
  if (!g_qCount) return;
  g_qHead = (g_qHead + 1) % QUEUE_SIZE;
  g_qCount--;
}

// =============================================================================
//  3. ΑΝΙΧΝΕΥΣΗ DEAUTH / DISASSOC (promiscuous mode)
// -----------------------------------------------------------------------------
//  Το callback καλείται από το task του Wi-Fi driver για ΚΑΘΕ πλαίσιο
//  διαχείρισης (το φίλτρο κόβει data/control). Πρέπει να είναι ΓΡΗΓΟΡΟ:
//  μόνο μετράμε και κρατάμε λίγα στοιχεία. Η απόφαση παίρνεται στο loop().
//
//  Μορφή κεφαλίδας 802.11 (πλαίσιο διαχείρισης, 24 bytes):
//    [0]    Frame Control: 0xC0 = deauthentication, 0xA0 = disassociation
//    [4]    addr1 = παραλήπτης (target), ff:ff:ff:ff:ff:ff = "όλοι"
//    [10]   addr2 = αποστολέας (source). Σε πλαστά deauth είναι το BSSID του AP
//    [16]   addr3 = BSSID
// =============================================================================
// Το g_win γράφεται από το Wi-Fi task και διαβάζεται από το loop(). Κάθε
// πρόσβαση γίνεται μέσα σε critical section (spinlock), που εγγυάται και
// ατομικότητα και σωστή ορατότητα μνήμης, οπότε δεν χρειάζεται volatile.
static DeauthWindow g_win = {};
static portMUX_TYPE g_winMux = portMUX_INITIALIZER_UNLOCKED;

static void snifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
  const uint8_t *p = pkt->payload;
  if (pkt->rx_ctrl.sig_len < 24) return;                  // πολύ μικρό πλαίσιο

  const uint8_t fc = p[0];
  if (fc != 0xC0 && fc != 0xA0) return;                   // όχι deauth/disassoc

  portENTER_CRITICAL(&g_winMux);
  if (g_win.count < 0xFFFF) g_win.count++;
  g_win.rssi = (int8_t)pkt->rx_ctrl.rssi;
  for (int i = 0; i < 6; i++) {
    g_win.target[i] = p[4 + i];
    g_win.source[i] = p[10 + i];
  }
  if (isBroadcast(p + 4)) g_win.sawBroadcast = true;
  portEXIT_CRITICAL(&g_winMux);
}

// Ξεκινά νέο παράθυρο μέτρησης (μηδενίζει τους μετρητές).
static void resetWindow() {
  portENTER_CRITICAL(&g_winMux);
  g_win.count = 0;
  g_win.sawBroadcast = false;
  portEXIT_CRITICAL(&g_winMux);
}

// Αντιγράφει ατομικά το τρέχον παράθυρο σε τοπική μεταβλητή.
static DeauthWindow snapshotWindow() {
  DeauthWindow w;
  portENTER_CRITICAL(&g_winMux);
  w.count = g_win.count;
  w.sawBroadcast = g_win.sawBroadcast;
  w.rssi = g_win.rssi;
  for (int i = 0; i < 6; i++) { w.source[i] = g_win.source[i]; w.target[i] = g_win.target[i]; }
  portEXIT_CRITICAL(&g_winMux);
  return w;
}

// Φάση SNIFF: ακούμε για SNIFF_SECONDS, αλλάζοντας κανάλι κάθε CHANNEL_DWELL_MS.
// Κάθε κανάλι = ένα παράθυρο μέτρησης (window_s = CHANNEL_DWELL_MS / 1000).
static void sniffPhase() {
  static uint8_t channel = FIRST_CHANNEL;     // συνεχίζουμε από όπου μείναμε

  // Ενεργοποίηση promiscuous ΜΟΝΟ για πλαίσια διαχείρισης.
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_promiscuous(true);

  Serial.printf("[sniff] listening %d s on ch %d-%d (threshold %d/s)\n",
                SNIFF_SECONDS, FIRST_CHANNEL, LAST_CHANNEL, DEAUTH_THRESHOLD);

  const uint32_t windowS = (CHANNEL_DWELL_MS + 500) / 1000;  // στρογγυλοποίηση
  const uint32_t threshold = (uint32_t)DEAUTH_THRESHOLD * (windowS ? windowS : 1);
  const uint32_t start = millis();

  while (millis() - start < (uint32_t)SNIFF_SECONDS * 1000UL) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    resetWindow();
    delay(CHANNEL_DWELL_MS);                  // ακούμε σε αυτό το κανάλι
    DeauthWindow w = snapshotWindow();

    if (w.count > 0) {
      Serial.printf("[sniff] ch %2u: %u deauth/disassoc frames\n", channel, w.count);
    }
    if (w.count >= threshold) {
      SentinelEvent ev = {};
      ev.type = EV_DEAUTH;
      ev.t = uptimeS();
      ev.channel = channel;
      ev.rssi = w.rssi;
      ev.count = w.count;
      memcpy(ev.bssid, w.source, 6);
      if (w.sawBroadcast) memset(ev.target, 0xFF, 6);    // flood προς "όλους"
      else                memcpy(ev.target, w.target, 6);
      queuePush(ev);
      g_deauthTotal++;
      g_countersDirty = true;

      char src[18], dst[18];
      macToStr(ev.bssid, src, sizeof src);
      macToStr(ev.target, dst, sizeof dst);
      Serial.printf("[ALERT] DEAUTH FLOOD ch %u: %u frames/%lus src %s -> %s rssi %d\n",
                    channel, w.count, (unsigned long)windowS, src, dst, w.rssi);
    }
    channel = (channel >= LAST_CHANNEL) ? FIRST_CHANNEL : channel + 1;
  }

  esp_wifi_set_promiscuous(false);
}

// =============================================================================
//  4. ΑΝΙΧΝΕΥΣΗ EVIL TWIN / ROGUE AP (WiFi.scanNetworks)
// -----------------------------------------------------------------------------
//  Για κάθε AP που εκπέμπει το PROTECTED_SSID:
//    - ασθενέστερη ασφάλεια από την αναμενόμενη    -> "evil_twin"
//      (π.χ. "HomeWiFi" ανοιχτό: κλασικό δόλωμα για να συνδεθούν συσκευές)
//    - άγνωστο BSSID με ίδια/ισχυρότερη ασφάλεια  -> "rogue_ap"
//  Για να μην "πλημμυρίζουμε" το NetWatch, το ίδιο BSSID αναφέρεται ξανά
//  μόνο μετά από TWIN_COOLDOWN_S.
// =============================================================================
struct TwinMemory { uint8_t bssid[6]; uint32_t lastS; bool used; };
static TwinMemory g_twinSeen[8];

// true αν πρέπει να αναφερθεί (και ενημερώνει τη μνήμη).
static bool twinShouldReport(const uint8_t *bssid) {
  const uint32_t now = uptimeS();

  // 1) Το έχουμε ξαναδεί; Αναφορά μόνο αν πέρασε το cooldown.
  for (auto &m : g_twinSeen) {
    if (m.used && memcmp(m.bssid, bssid, 6) == 0) {
      if (now - m.lastS < TWIN_COOLDOWN_S) return false;
      m.lastS = now;
      return true;
    }
  }

  // 2) Νέο BSSID: πρώτη ελεύθερη θέση, αλλιώς η παλαιότερη εγγραφή.
  TwinMemory *slot = &g_twinSeen[0];
  for (auto &m : g_twinSeen) {
    if (!m.used) { slot = &m; break; }
    if (m.lastS < slot->lastS) slot = &m;
  }
  memcpy(slot->bssid, bssid, 6);
  slot->lastS = now;
  slot->used = true;
  return true;
}

static bool bssidAllowed(const char *bssidStr) {
  for (size_t i = 0; i < sizeof(ALLOWED_BSSIDS) / sizeof(ALLOWED_BSSIDS[0]); i++)
    if (strcasecmp(ALLOWED_BSSIDS[i], bssidStr) == 0) return true;
  return false;
}

static void scanForTwins() {
  Serial.println("[scan] scanning for '" PROTECTED_SSID "' ...");
  const int n = WiFi.scanNetworks(/*async=*/false, /*show_hidden=*/false);
  if (n < 0) { Serial.printf("[scan] failed (%d)\n", n); return; }

  const uint8_t expectedRank = rankForName(EXPECTED_SECURITY);
  int matches = 0;

  for (int i = 0; i < n; i++) {
    if (WiFi.SSID(i) != PROTECTED_SSID) continue;
    matches++;

    const uint8_t *bssid = WiFi.BSSID(i);
    char bssidStr[18];
    macToStr(bssid, bssidStr, sizeof bssidStr);
    const SecurityInfo *sec = securityFor(WiFi.encryptionType(i));
    const char *secName = sec ? sec->name : "unknown";
    const uint8_t rank = sec ? sec->rank : 0;
    const bool known = bssidAllowed(bssidStr);

    Serial.printf("[scan]   %s ch %2ld rssi %4ld %-9s %s\n", bssidStr,
                  (long)WiFi.channel(i), (long)WiFi.RSSI(i), secName,
                  known ? "(allowed)" : "(UNKNOWN)");

    EventType type;
    if (rank < expectedRank)  type = EV_EVIL_TWIN;   // υποβάθμιση ασφάλειας
    else if (!known)          type = EV_ROGUE_AP;    // άγνωστο AP με ίδιο όνομα
    else                      continue;              // όλα καλά

    if (!twinShouldReport(bssid)) continue;          // ήδη αναφέρθηκε πρόσφατα

    SentinelEvent ev = {};
    ev.type = type;
    ev.t = uptimeS();
    ev.channel = (uint8_t)WiFi.channel(i);
    ev.rssi = (int8_t)WiFi.RSSI(i);
    memcpy(ev.bssid, bssid, 6);
    ev.security = secName;
    queuePush(ev);
    g_twinsTotal++;
    g_countersDirty = true;
    Serial.printf("[ALERT] %s: %s (%s)\n",
                  type == EV_EVIL_TWIN ? "EVIL TWIN" : "ROGUE AP", bssidStr, secName);
  }
  Serial.printf("[scan] %d networks, %d with protected SSID\n", n, matches);
  WiFi.scanDelete();   // απελευθέρωση μνήμης των αποτελεσμάτων
}

// =============================================================================
//  5. MQTT OVER TLS (esp-mqtt)
// =============================================================================
static esp_mqtt_client_handle_t g_mqtt = nullptr;
static volatile bool g_mqttConnected = false;
static bool g_mqttStarted = false;

// Χειριστής γεγονότων: καλείται από το task του esp-mqtt.
static void mqttEventHandler(void *, esp_event_base_t, int32_t eventId, void *eventData) {
  esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)eventData;
  switch ((esp_mqtt_event_id_t)eventId) {
    case MQTT_EVENT_CONNECTED:
      g_mqttConnected = true;
      Serial.println("[mqtt] connected (TLS verified)");
      break;
    case MQTT_EVENT_DISCONNECTED:
      g_mqttConnected = false;
      Serial.println("[mqtt] disconnected");
      break;
    case MQTT_EVENT_ERROR:
      // Χρήσιμη διάγνωση: τα πιο συνηθισμένα λάθη στο TLS είναι λάθος CA
      // ή hostname που δεν υπάρχει στο SAN του πιστοποιητικού.
      if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
        Serial.printf("[mqtt] transport error: esp_err=0x%x tls_stack=0x%x cert_flags=0x%x errno=%d\n",
                      event->error_handle->esp_tls_last_esp_err,
                      event->error_handle->esp_tls_stack_err,
                      event->error_handle->esp_tls_cert_verify_flags,
                      event->error_handle->esp_transport_sock_errno);
        if (event->error_handle->esp_tls_cert_verify_flags)
          Serial.println("[mqtt]   -> certificate verification FAILED (CA or SAN mismatch?)");
      } else if (event->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
        Serial.printf("[mqtt] broker refused connection (code %d): check user/pass/ACL\n",
                      event->error_handle->connect_return_code);
      }
      break;
    default:
      break;
  }
}

static void mqttInit() {
  static const char LWT_MSG[] = "{\"online\":false}";

  esp_mqtt_client_config_t cfg = {};
  cfg.broker.address.uri = g_brokerUri;
  // Επαλήθευση του broker με τη δική μας CA. ΠΟΤΕ δεν παρακάμπτουμε τον
  // έλεγχο (δεν ορίζουμε skip_cert_common_name_check). Το hostname του
  // URI πρέπει να υπάρχει στο SAN του server.crt.
  cfg.broker.verification.certificate = MQTT_CA_PEM;
  cfg.credentials.client_id = g_id;
  cfg.credentials.username = MQTT_USER;
  cfg.credentials.authentication.password = MQTT_PASS;
  // Last Will: αν χαθεί απότομα η σύνδεση (crash, ρεύμα), ο broker
  // δημοσιεύει αυτό στο status topic ως retained.
  cfg.session.last_will.topic = g_topicStatus;
  cfg.session.last_will.msg = LWT_MSG;
  cfg.session.last_will.msg_len = sizeof(LWT_MSG) - 1;
  cfg.session.last_will.qos = 1;
  cfg.session.last_will.retain = 1;
  cfg.session.keepalive = 15;
  cfg.network.timeout_ms = 8000;

  g_mqtt = esp_mqtt_client_init(&cfg);
  if (!g_mqtt) { Serial.println("[mqtt] init FAILED"); return; }
  esp_mqtt_client_register_event(g_mqtt, MQTT_EVENT_ANY, mqttEventHandler, nullptr);
}

// Ξεκινά τον client και περιμένει μέχρι να συνδεθεί (ή timeout).
static bool mqttConnect() {
  if (!g_mqtt) return false;
  if (!g_mqttStarted) {
    if (esp_mqtt_client_start(g_mqtt) != ESP_OK) return false;
    g_mqttStarted = true;
  }
  const uint32_t start = millis();
  while (!g_mqttConnected && millis() - start < MQTT_CONNECT_TIMEOUT) delay(50);
  return g_mqttConnected;
}

// Σταματά ΟΜΑΛΑ τον client (στέλνει DISCONNECT). Έτσι ο broker ΔΕΝ στέλνει
// το LWT σε κάθε φάση sniff: το retained status μένει "online":true.
static void mqttStop() {
  if (g_mqtt && g_mqttStarted) {
    esp_mqtt_client_stop(g_mqtt);
    g_mqttStarted = false;
    g_mqttConnected = false;
  }
}

static bool mqttPublish(const char *topic, const char *payload, bool retain) {
  if (!g_mqttConnected) return false;
  const int id = esp_mqtt_client_publish(g_mqtt, topic, payload, 0, /*qos=*/1, retain ? 1 : 0);
  return id >= 0;
}

// Περιμένει να επιβεβαιωθούν (PUBACK) τα μηνύματα QoS 1 πριν κλείσουμε.
static void mqttFlush() {
  const uint32_t start = millis();
  while (g_mqttConnected && esp_mqtt_client_get_outbox_size(g_mqtt) > 0 &&
         millis() - start < MQTT_FLUSH_TIMEOUT) {
    delay(50);
  }
}

// -----------------------------------------------------------------------------
//  JSON payloads (με snprintf: καμία εξωτερική βιβλιοθήκη)
// -----------------------------------------------------------------------------
static void buildHeartbeat(char *out, size_t len) {
  snprintf(out, len,
           "{\"id\":\"%s\",\"online\":true,\"fw\":\"%s\",\"uptime\":%lu,\"heap\":%lu,"
           "\"rssi\":%d,\"ip\":\"%s\",\"deauth_total\":%lu,\"twins_total\":%lu}",
           g_id, FW_VERSION, (unsigned long)uptimeS(), (unsigned long)ESP.getFreeHeap(),
           (int)WiFi.RSSI(), WiFi.localIP().toString().c_str(),
           (unsigned long)g_deauthTotal, (unsigned long)g_twinsTotal);
}

static void buildEvent(const SentinelEvent &ev, char *out, size_t len) {
  char bssid[18];
  macToStr(ev.bssid, bssid, sizeof bssid);

  if (ev.type == EV_DEAUTH) {
    char target[18];
    macToStr(ev.target, target, sizeof target);
    snprintf(out, len,
             "{\"type\":\"deauth\",\"id\":\"%s\",\"channel\":%u,\"count\":%u,\"window_s\":%u,"
             "\"bssid\":\"%s\",\"target\":\"%s\",\"rssi\":%d,\"t\":%lu}",
             g_id, ev.channel, ev.count, (unsigned)((CHANNEL_DWELL_MS + 500) / 1000),
             bssid, target, ev.rssi, (unsigned long)ev.t);
  } else {
    char ssid[70];
    jsonEscape(PROTECTED_SSID, ssid, sizeof ssid);
    snprintf(out, len,
             "{\"type\":\"%s\",\"id\":\"%s\",\"ssid\":\"%s\",\"bssid\":\"%s\","
             "\"security\":\"%s\",\"channel\":%u,\"rssi\":%d,\"t\":%lu}",
             ev.type == EV_EVIL_TWIN ? "evil_twin" : "rogue_ap", g_id, ssid, bssid,
             ev.security ? ev.security : "unknown", ev.channel, ev.rssi, (unsigned long)ev.t);
  }
}

// =============================================================================
//  6. ΦΑΣΗ ONLINE: Wi-Fi -> MQTT -> δημοσίευση -> αποσύνδεση
// =============================================================================
static uint32_t g_lastHeartbeatMs = 0;
static uint32_t g_lastScanMs = 0;
static bool     g_firstHeartbeat = true;
static bool     g_firstScan = true;

static bool due(uint32_t lastMs, uint32_t intervalS, bool first) {
  return first || (millis() - lastMs + TIMING_SLACK_MS >= intervalS * 1000UL);
}

static bool wifiConnect() {
  Serial.printf("[wifi] connecting to '%s' ...\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  const uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < WIFI_CONNECT_TIMEOUT) delay(100);
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[wifi] connect timeout, events stay queued");
    WiFi.disconnect(false, false);   // σταματά τυχόν προσπάθεια σε εξέλιξη
    return false;
  }
  Serial.printf("[wifi] connected, ip %s rssi %d ch %ld\n",
                WiFi.localIP().toString().c_str(), (int)WiFi.RSSI(), (long)WiFi.channel());
  return true;
}

static void saveCounters() {
  if (!g_countersDirty) return;
  // Γράφουμε στη flash μόνο όταν αλλάξει κάτι (λιγότερη φθορά της flash).
  g_prefs.putULong("deauth", g_deauthTotal);
  g_prefs.putULong("twins", g_twinsTotal);
  g_countersDirty = false;
}

// -----------------------------------------------------------------------------
//  Υπογεγραμμένο OTA (μόνο με OTA_ENABLE 1, βλ. tools/ota/README.md)
// -----------------------------------------------------------------------------
//  Τρέχει ΜΕΣΑ στη φάση online, αφού σταλούν heartbeat και γεγονότα:
//    - το self-test του νέου firmware = "συνδέθηκα σε Wi-Fi ΚΑΙ σε MQTT/TLS"
//    - έλεγχος στην πρώτη φάση online και μετά κάθε OTA_INTERVAL_H ώρες.
//      ΜΠΛΟΚΑΡΕΙ όσο κατεβαίνει firmware (η φάση online μακραίνει για λίγο,
//      άρα και το "τυφλό" διάστημα του sniff). Αν εγκατασταθεί νέο: restart.
//    - αποτέλεσμα στο event topic: {"type":"ota","result":"updated|up_to_date|
//      rejected|error","reason":"..."}
// -----------------------------------------------------------------------------
#if OTA_ENABLE
static uint32_t g_lastOtaMs = 0;
static bool     g_firstOta = true;

static void publishOta(const SignedOtaStatus &st) {
  char reason[sizeof st.reason * 2];
  char ver[sizeof st.version * 2];
  jsonEscape(st.reason, reason, sizeof reason);
  jsonEscape(st.version, ver, sizeof ver);
  char buf[400];
  snprintf(buf, sizeof buf,
           "{\"type\":\"ota\",\"id\":\"%s\",\"result\":\"%s\",\"reason\":\"%s\",\"version\":\"%s\","
           "\"fw\":\"%s\",\"t\":%lu}",
           g_id, signedOtaResultName(st.result), reason, ver, FW_VERSION, (unsigned long)uptimeS());
  if (mqttPublish(g_topicEvent, buf, /*retain=*/false)) Serial.printf("[mqtt] event  -> %s\n", buf);
}

static void otaOnline() {
  signedOtaMarkHealthy();   // Wi-Fi + MQTT/TLS δουλεύουν: το self-test πέρασε
  SignedOtaStatus report;
  if (signedOtaTakeReport(report)) publishOta(report);

  if (!due(g_lastOtaMs, (uint32_t)OTA_INTERVAL_H * 3600UL, g_firstOta)) return;
  g_lastOtaMs = millis();
  g_firstOta = false;
  mqttFlush();   // πρώτα να φύγουν τα γεγονότα, μετά το (αργό) κατέβασμα
  signedOtaCheck(OTA_BASE_URL, OTA_DEVICE_CLASS, FW_VERSION, MQTT_CA_PEM, OTA_PUBKEY_PEM);
  publishOta(signedOtaLastStatus());
}
#endif

static void onlinePhase() {
  // (α) Σάρωση για evil twin: γίνεται ΠΡΙΝ τη σύνδεση, ώστε να μη διακόψει
  //     την ενεργή σύνδεση (η σάρωση αλλάζει κανάλια).
  if (due(g_lastScanMs, SCAN_INTERVAL_S, g_firstScan)) {
    scanForTwins();
    g_lastScanMs = millis();
    g_firstScan = false;
  }
  saveCounters();

  // (β) Wi-Fi + MQTT
  if (!wifiConnect()) return;
  if (!mqttConnect()) {
    Serial.println("[mqtt] connect timeout, events stay queued");
    mqttStop();
    WiFi.disconnect(false, false);
    return;
  }

  // (γ) Heartbeat (retained, για να βλέπει το NetWatch αμέσως την κατάσταση)
  static char buf[384];
  if (due(g_lastHeartbeatMs, HEARTBEAT_INTERVAL_S, g_firstHeartbeat)) {
    buildHeartbeat(buf, sizeof buf);
    if (mqttPublish(g_topicStatus, buf, /*retain=*/true)) {
      Serial.printf("[mqtt] status -> %s\n", buf);
      g_lastHeartbeatMs = millis();
      g_firstHeartbeat = false;
    }
  }

  // (δ) Άδειασμα της ουράς γεγονότων. Αφαιρούμε από την ουρά μόνο ό,τι
  //     μπήκε επιτυχώς στο outbox του esp-mqtt.
  int sent = 0;
  while (SentinelEvent *ev = queuePeek()) {
    buildEvent(*ev, buf, sizeof buf);
    if (!mqttPublish(g_topicEvent, buf, /*retain=*/false)) break;
    Serial.printf("[mqtt] event  -> %s\n", buf);
    queuePop();
    sent++;
  }
  if (g_dropped) Serial.printf("[queue] %lu events dropped so far (queue full)\n",
                               (unsigned long)g_dropped);

#if OTA_ENABLE
  otaOnline();
#endif

  // (ε) Περιμένουμε τα PUBACK και κλείνουμε ομαλά.
  mqttFlush();
  Serial.printf("[cycle] sent %d events, %u still queued, heap %lu\n",
                sent, (unsigned)g_qCount, (unsigned long)ESP.getFreeHeap());
  mqttStop();
  WiFi.disconnect(false, false);   // επιστροφή σε "ελεύθερο" ραδιόφωνο για sniff
}

// =============================================================================
//  7. SETUP & LOOP
// =============================================================================
void setup() {
  Serial.begin(115200);
  delay(300);

  // Ταυτότητα: "sentinel-" + τα 3 τελευταία bytes της MAC (πεζά, χωρίς ':').
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  snprintf(g_id, sizeof g_id, "sentinel-%02x%02x%02x", mac[3], mac[4], mac[5]);
  snprintf(g_topicStatus, sizeof g_topicStatus, "netwatch/sensor/%s/status", g_id);
  snprintf(g_topicEvent, sizeof g_topicEvent, "netwatch/sensor/%s/event", g_id);
  snprintf(g_brokerUri, sizeof g_brokerUri, "mqtts://%s:%d", MQTT_HOST, (int)MQTT_PORT);

  Serial.println();
  Serial.println("=============================================");
  Serial.printf (" NetWatch Sentinel v%s  id=%s\n", FW_VERSION, g_id);
  Serial.println(" Passive Wi-Fi monitor: listens only, never transmits attacks");
  Serial.println("=============================================");
  Serial.printf("[cfg] broker %s  protected SSID '%s' expect %s  allow-list %u BSSID(s)\n",
                g_brokerUri, PROTECTED_SSID, EXPECTED_SECURITY,
                (unsigned)(sizeof(ALLOWED_BSSIDS) / sizeof(ALLOWED_BSSIDS[0])));

#if OTA_ENABLE
  signedOtaBegin(FW_VERSION);   // διαβάζει NVS: προηγήθηκε update ή rollback;
#endif

  // Μετρητές από τη flash
  g_prefs.begin("sentinel", /*readOnly=*/false);
  g_deauthTotal = g_prefs.getULong("deauth", 0);
  g_twinsTotal  = g_prefs.getULong("twins", 0);
  const uint32_t boots = g_prefs.getULong("boots", 0) + 1;
  g_prefs.putULong("boots", boots);
  Serial.printf("[cfg] boot #%lu, deauth_total=%lu twins_total=%lu\n", (unsigned long)boots,
                (unsigned long)g_deauthTotal, (unsigned long)g_twinsTotal);

  // Wi-Fi σε λειτουργία station. Χωρίς αυτόματη επανασύνδεση: εμείς
  // αποφασίζουμε πότε συνδεόμαστε (αλλιώς θα "τραβούσε" το ραδιόφωνο
  // στο κανάλι του router την ώρα που ακούμε).
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(false);
  WiFi.persistent(false);
  WiFi.setSleep(false);

  mqttInit();

  // Πρώτα μια φάση online: heartbeat αμέσως μετά την εκκίνηση.
  onlinePhase();
}

void loop() {
#if OTA_ENABLE
  signedOtaSelfTestTick(OTA_SELFTEST_S);   // νέο firmware που δεν "υγιαίνει" -> rollback
#endif
  sniffPhase();    // ~SNIFF_SECONDS: εναλλαγή καναλιών, μέτρηση deauth
  onlinePhase();   // ~5-8 s: scan (κάθε ~60 s), σύνδεση, δημοσίευση
}
