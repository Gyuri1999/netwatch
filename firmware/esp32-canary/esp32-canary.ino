// =============================================================================
//  NetWatch Canary  v1.0.0
// -----------------------------------------------------------------------------
//  "Καναρίνι" / παγίδα (honeypot) για ESP32. Προσποιείται μια ξεχασμένη
//  IP κάμερα στο δίκτυο (συνήθως στο IoT VLAN). Κανείς νόμιμος δεν έχει λόγο
//  να συνδεθεί σε αυτή, άρα ΚΑΘΕ σύνδεση σημαίνει ότι κάποιος σκανάρει ή
//  δοκιμάζει κωδικούς στο LAN. Η αναφορά πάει στο NetWatch μέσω MQTT over TLS.
//
//    Θύρα 23    ψεύτικο Telnet:  "login:" / "Password:" -> "Login incorrect"
//    Θύρα 80    ψεύτικο HTTP admin: πάντα 401 + Basic realm="IPCamera"
//    Θύρα 8080  ίδιο με το 80 (προαιρετικό, CANARY_ENABLE_8080)
//    mDNS       <hostname>.local, _http._tcp (80), _telnet._tcp (23)
//
//  ΑΣΦΑΛΕΙΑ / ΗΘΙΚΗ:
//    Ο κώδικας ΜΟΝΟ ακούει και απαντά με σταθερά, αθώα μηνύματα. Δεν
//    "αντεπιτίθεται", δεν συνδέεται πουθενά εκτός από τον broker και ΠΟΤΕ δεν
//    κρατά/στέλνει κωδικούς: από το Telnet η γραμμή κωδικού δεν αποθηκεύεται
//    καθόλου, από το HTTP Basic αποκωδικοποιείται μόνο το όνομα χρήστη (ως
//    το ':') και οι τιμές παραμέτρων τύπου pass/pwd/auth/token στο URL
//    αντικαθίστανται με "***". Ίδιος κανόνας με το NetWatch: «ποτέ κωδικοί».
//
//  Αρχιτεκτονική (χωρίς μπλοκαρίσματα):
//    - Το esp-mqtt τρέχει στο δικό του FreeRTOS task (keepalive, επανασύνδεση,
//      TLS). Το loop() μόνο βάζει μηνύματα στο outbox (esp_mqtt_client_enqueue),
//      άρα ένας αργός επισκέπτης δεν μπορεί να "παγώσει" το MQTT.
//    - Οι WiFiServer είναι non-blocking (accept() επιστρέφει αμέσως).
//    - Κάθε σύνδεση έχει μια μικρή μηχανή καταστάσεων με timeout. Διαβάζουμε
//      μόνο ό,τι έχει ήδη φτάσει (available()), ποτέ δεν περιμένουμε.
// =============================================================================

#include <WiFi.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include <esp_mac.h>       // esp_read_mac()
#include <mqtt_client.h>   // esp-mqtt (ESP-IDF), ενσωματωμένο στον πυρήνα

#include "secrets.h"       // ΔΕΝ είναι στο git, βλ. secrets.example.h
#include "canary_types.h"  // struct/enum του firmware

// -----------------------------------------------------------------------------
//  Σταθερές & προεπιλογές (αν δεν ορίζονται στο secrets.h)
// -----------------------------------------------------------------------------
#define FW_VERSION "1.0.0"

#ifndef CANARY_HOSTNAME
#define CANARY_HOSTNAME "camera-salon"
#endif
#ifndef CANARY_ENABLE_8080
#define CANARY_ENABLE_8080 1
#endif
#ifndef CANARY_IGNORE_IPS
#define CANARY_IGNORE_IPS ""
#endif
#ifndef HEARTBEAT_INTERVAL_S
#define HEARTBEAT_INTERVAL_S 30
#endif
#ifndef RATE_PER_SOURCE_S
#define RATE_PER_SOURCE_S 30
#endif
#ifndef RATE_GLOBAL_PER_MIN
#define RATE_GLOBAL_PER_MIN 20
#endif
#ifndef TELNET_TIMEOUT_S
#define TELNET_TIMEOUT_S 10
#endif
#ifndef HTTP_TIMEOUT_S
#define HTTP_TIMEOUT_S 5
#endif

static const size_t   MAX_CLIENTS        = 4;      // ταυτόχρονες συνδέσεις
static const size_t   QUEUE_SIZE         = 8;      // γεγονότα σε αναμονή για MQTT
static const size_t   RATE_SLOTS         = 16;     // μνήμη IP+θύρας για το rate limit
static const size_t   MAX_IGNORE         = 4;
static const uint16_t MAX_BYTES_PER_CONN = 4096;   // μετά από τόσα bytes κλείνουμε
static const int      ACCEPTS_PER_LOOP   = 4;      // ανά server, ανά γύρο του loop
static const size_t   READ_CHUNK         = 128;
static const int      CHUNKS_PER_LOOP    = 4;      // ανά client, ανά γύρο του loop
static const int      OUTBOX_MAX_BYTES   = 8192;   // δεν γεμίζουμε το outbox του esp-mqtt
static const uint32_t WIFI_KICK_MS       = 60000;  // επανεκκίνηση σύνδεσης αν λείπει τόσο
static const uint32_t CLIENT_WRITE_MS    = 1000;   // όριο για write() σε αργό client

// -----------------------------------------------------------------------------
//  Ταυτότητα & topics (υπολογίζονται στο setup από τη MAC)
// -----------------------------------------------------------------------------
static char g_id[20];            // "canary-a1b2c3"
static char g_topicStatus[64];   // netwatch/sensor/<id>/status  (retained)
static char g_topicEvent[64];    // netwatch/sensor/<id>/event   (όχι retained)
static char g_brokerUri[128];    // mqtts://<host>:8883

// Μετρητές (διατηρούνται στη flash με Preferences, γράφονται το πολύ μία
// φορά ανά heartbeat ώστε μια "πλημμύρα" συνδέσεων να μη φθείρει τη flash).
static uint32_t g_hits = 0;        // όλες οι συνδέσεις (και οι σιωπηλές)
static uint32_t g_suppressed = 0;  // συνδέσεις χωρίς γεγονός (rate limit / γεμάτη ουρά)
static bool     g_countersDirty = false;
static Preferences g_prefs;

// =============================================================================
//  1. ΒΟΗΘΗΤΙΚΑ
// =============================================================================

static uint32_t uptimeS() { return (uint32_t)(millis() / 1000UL); }

// Ασφαλής αντιγραφή με όριο: πάντα τερματίζει με '\0'.
static void copyStr(char *out, size_t len, const char *in) {
  if (!len) return;
  size_t i = 0;
  for (; in && in[i] && i + 1 < len; i++) out[i] = in[i];
  out[i] = '\0';
}

// Κρατά ΜΟΝΟ εκτυπώσιμους ASCII (0x20-0x7E). Ό,τι άλλο γίνεται '.'.
// Έτσι ένας επιτιθέμενος δεν μπορεί να στείλει χαρακτήρες ελέγχου/ANSI
// escapes που θα "πείραζαν" το Serial, το JSON ή το UI του NetWatch.
static void sanitize(const char *in, char *out, size_t len) {
  if (!len) return;
  size_t o = 0;
  for (; *in && o + 1 < len; in++) {
    const unsigned char c = (unsigned char)*in;
    out[o++] = (c >= 0x20 && c <= 0x7E) ? (char)c : '.';
  }
  out[o] = '\0';
}

// Ασφαλής εισαγωγή string σε JSON: escape για " \ και χαρακτήρες ελέγχου.
static void jsonEscape(const char *in, char *out, size_t len) {
  if (!len) return;
  size_t o = 0;
  for (; *in && o + 7 < len; in++) {
    const unsigned char c = (unsigned char)*in;
    if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
    else if (c < 0x20)         { o += snprintf(out + o, len - o, "\\u%04x", c); }
    else                       { out[o++] = (char)c; }
  }
  out[o] = '\0';
}

// Περιέχει το όνομα παραμέτρου κάτι που μοιάζει με κωδικό/κλειδί;
static bool sensitiveName(const char *name, size_t n) {
  char low[32];
  if (n >= sizeof low) n = sizeof low - 1;
  for (size_t i = 0; i < n; i++) low[i] = (char)tolower((unsigned char)name[i]);
  low[n] = '\0';
  static const char *const WORDS[] = { "pass", "pwd", "auth", "token", "key", "secret", "sid" };
  for (const char *w : WORDS) if (strstr(low, w)) return true;
  return false;
}

// Request line HTTP -> καθαρό κείμενο για το γεγονός. Στο query string οι
// τιμές "ευαίσθητων" παραμέτρων γίνονται "***", π.χ.
//   GET /Security/users?auth=YWRtaW46MTEK  ->  GET /Security/users?auth=***
// (το "auth" του γνωστού backdoor της Hikvision είναι base64 user:password).
static void sanitizeRequestLine(const char *in, char *out, size_t len) {
  if (!len) return;
  size_t o = 0;
  bool inQuery = false;
  size_t nameStart = 0;   // θέση στο out όπου ξεκινά το όνομα της παραμέτρου
  while (*in && o + 1 < len) {
    const unsigned char c = (unsigned char)*in++;
    const char pc = (c >= 0x20 && c <= 0x7E) ? (char)c : '.';
    if (!inQuery) {
      out[o++] = pc;
      if (c == '?') { inQuery = true; nameStart = o; }
      continue;
    }
    if (c == ' ') { inQuery = false; out[o++] = pc; continue; }   // τέλος URL (" HTTP/1.1")
    if (c == '&') { out[o++] = pc; nameStart = o; continue; }
    out[o++] = pc;
    if (c == '=' && sensitiveName(out + nameStart, o - 1 - nameStart)) {
      for (const char *m = "***"; *m && o + 1 < len; m++) out[o++] = *m;
      while (*in && *in != '&' && *in != ' ') in++;              // πετάμε την τιμή
      nameStart = o;   // ώστε ένα δεύτερο '=' στην ίδια παράμετρο να μη μετρήσει
    }
  }
  out[o] = '\0';
}

// Τιμή ενός χαρακτήρα base64, ή -1 (τέλος / μη έγκυρος).
static int b64val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

// "Authorization: Basic <base64(user:pass)>" -> ΜΟΝΟ το user.
// Αποκωδικοποιούμε byte-byte και σταματάμε στο ':', άρα ο κωδικός δεν
// αποκωδικοποιείται ποτέ και δεν υπάρχει ούτε προσωρινά στη RAM.
static void basicAuthUser(const char *b64, char *out, size_t len) {
  char raw[USER_MAX + 1];
  size_t r = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (; *b64; b64++) {
    const int v = b64val(*b64);
    if (v < 0) break;
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      const char ch = (char)((acc >> bits) & 0xFF);
      if (ch == ':') break;          // από εδώ και πέρα είναι ο κωδικός: ΣΤΟΠ
      if (r >= USER_MAX) break;      // πολύ μεγάλο όνομα: κόβουμε
      raw[r++] = ch;
    }
  }
  raw[r] = '\0';
  sanitize(raw, out, len);
  memset(raw, 0, sizeof raw);
  acc = 0;
}

// -----------------------------------------------------------------------------
//  IP που αγνοούνται (CANARY_IGNORE_IPS)
// -----------------------------------------------------------------------------
static char   g_ignore[MAX_IGNORE][SRC_MAX + 1];
static size_t g_ignoreCount = 0;

static void parseIgnoreList() {
  char buf[MAX_IGNORE * (SRC_MAX + 2)];
  copyStr(buf, sizeof buf, CANARY_IGNORE_IPS);
  char *save = nullptr;
  for (char *tok = strtok_r(buf, ",", &save); tok && g_ignoreCount < MAX_IGNORE;
       tok = strtok_r(nullptr, ",", &save)) {
    while (*tok == ' ') tok++;
    size_t n = strlen(tok);
    while (n && tok[n - 1] == ' ') tok[--n] = '\0';
    IPAddress ip;
    if (n && ip.fromString(tok)) {
      // Κανονικοποίηση μέσω IPAddress, ώστε να ταιριάζει με το remoteIP().toString()
      copyStr(g_ignore[g_ignoreCount++], SRC_MAX + 1, ip.toString().c_str());
    } else if (n) {
      Serial.printf("[cfg] ignoring invalid CANARY_IGNORE_IPS entry '%s'\n", tok);
    }
  }
}

static bool isIgnored(const char *src) {
  for (size_t i = 0; i < g_ignoreCount; i++)
    if (strcmp(g_ignore[i], src) == 0) return true;
  return false;
}

// =============================================================================
//  2. RATE LIMIT
// -----------------------------------------------------------------------------
//  (α) το πολύ 1 γεγονός ανά IP+θύρα κάθε RATE_PER_SOURCE_S
//  (β) το πολύ RATE_GLOBAL_PER_MIN γεγονότα ανά λεπτό συνολικά
//  Ένα nmap σε όλο το subnet δεν πρέπει να πλημμυρίσει το MQTT / τις
//  ειδοποιήσεις. Ό,τι κόβεται μετριέται στο "suppressed" του heartbeat.
// =============================================================================
static RateEntry g_rate[RATE_SLOTS];
static uint32_t  g_globalWinStart = 0;
static uint32_t  g_globalCount = 0;

static bool rateAllow(const char *src, uint16_t port) {
  const uint32_t now = millis();
  if (now - g_globalWinStart >= 60000UL) { g_globalWinStart = now; g_globalCount = 0; }

  RateEntry *slot = nullptr;
  for (auto &e : g_rate) {
    if (e.used && e.port == port && strcmp(e.src, src) == 0) {
      if (now - e.lastMs < (uint32_t)RATE_PER_SOURCE_S * 1000UL) return false;
      slot = &e;
      break;
    }
  }
  if (g_globalCount >= (uint32_t)RATE_GLOBAL_PER_MIN) return false;

  if (!slot) {   // νέα πηγή: πρώτη ελεύθερη θέση, αλλιώς η παλαιότερη
    slot = &g_rate[0];
    for (auto &e : g_rate) {
      if (!e.used) { slot = &e; break; }
      if ((now - e.lastMs) > (now - slot->lastMs)) slot = &e;
    }
    copyStr(slot->src, sizeof slot->src, src);
    slot->port = port;
    slot->used = true;
  }
  slot->lastMs = now;
  g_globalCount++;
  return true;
}

// =============================================================================
//  3. ΟΥΡΑ ΓΕΓΟΝΟΤΩΝ (ring buffer)
// -----------------------------------------------------------------------------
//  Αν το MQTT είναι προσωρινά κάτω, τα γεγονότα περιμένουν εδώ. Αν γεμίσει,
//  πετάμε το ΠΑΛΑΙΟΤΕΡΟ και το μετράμε στο g_suppressed.
//  Γεμίζει/αδειάζει ΜΟΝΟ από το loop(), άρα δεν χρειάζεται κλείδωμα.
// =============================================================================
static CanaryEvent g_queue[QUEUE_SIZE];
static size_t g_qHead = 0;
static size_t g_qCount = 0;

static void queuePush(uint32_t t, const char *src, uint16_t port, ServiceKind svc,
                      const char *data, const char *user) {
  if (g_qCount == QUEUE_SIZE) {
    g_qHead = (g_qHead + 1) % QUEUE_SIZE;
    g_qCount--;
    g_suppressed++;
    g_countersDirty = true;
  }
  CanaryEvent &ev = g_queue[(g_qHead + g_qCount) % QUEUE_SIZE];
  ev.t = t;
  ev.port = port;
  ev.service = svc;
  copyStr(ev.src, sizeof ev.src, src);
  copyStr(ev.data, sizeof ev.data, data);
  copyStr(ev.user, sizeof ev.user, user);
  g_qCount++;

  Serial.printf("[ALERT] canary %s:%u from %s data='%s' user='%s'\n",
                svc == SVC_TELNET ? "telnet" : "http", port, ev.src, ev.data, ev.user);
}

// =============================================================================
//  4. ΨΕΥΤΙΚΕΣ ΥΠΗΡΕΣΙΕΣ (μηχανή καταστάσεων ανά σύνδεση)
// =============================================================================
static WiFiServer g_srvTelnet(23, MAX_CLIENTS);
static WiFiServer g_srvHttp(80, MAX_CLIENTS);
#if CANARY_ENABLE_8080
static WiFiServer g_srvHttpAlt(8080, MAX_CLIENTS);
#endif
static ClientSlot g_slots[MAX_CLIENTS];

static const char TELNET_BANNER[] = "\r\nHikvision-DS2CD login: ";
static const char TELNET_PASS[]   = "Password: ";
static const char TELNET_FAIL[]   = "\r\nLogin incorrect\r\n";
static const char HTTP_BODY[]     = "<html><head><title>401 Unauthorized</title></head>"
                                    "<body><h1>401 Unauthorized</h1></body></html>";

static void clientWrite(ClientSlot &s, const char *txt) {
  s.client.write((const uint8_t *)txt, strlen(txt));
}

static void sendHttp401(ClientSlot &s) {
  char head[256];
  const int n = snprintf(head, sizeof head,
                         "HTTP/1.1 401 Unauthorized\r\n"
                         "Server: App-webs/\r\n"
                         "WWW-Authenticate: Basic realm=\"IPCamera\"\r\n"
                         "Content-Type: text/html\r\n"
                         "Content-Length: %u\r\n"
                         "Connection: close\r\n\r\n",
                         (unsigned)(sizeof(HTTP_BODY) - 1));
  if (n > 0 && (size_t)n < sizeof head) {
    s.client.write((const uint8_t *)head, (size_t)n);
    s.client.write((const uint8_t *)HTTP_BODY, sizeof(HTTP_BODY) - 1);
  }
}

static void resetSlot(ClientSlot &s) {
  s.client = WiFiClient();   // απελευθερώνει το socket
  s.phase = PH_FREE;
  s.service = SVC_TELNET;
  s.port = 0;
  s.src[0] = '\0';
  s.startMs = 0;
  s.t = 0;
  s.report = false;
  s.skipLf = false;
  s.iac = 0;
  s.gotFirst = false;
  s.sawPass = false;
  s.total = 0;
  s.lineLen = 0;
  memset(s.line, 0, sizeof s.line);   // σβήνουμε ό,τι έστειλε ο επισκέπτης
  s.data[0] = '\0';
  s.user[0] = '\0';
}

// Κλείνει τη σύνδεση και (αν πέρασε το rate limit) βάζει το γεγονός στην ουρά.
static void finishSlot(ClientSlot &s) {
  if (s.report) {
    if (s.service == SVC_TELNET && s.sawPass) {
      // Η γραμμή κωδικού ΔΕΝ αποθηκεύτηκε ποτέ: σημειώνουμε μόνο ότι υπήρξε.
      char tmp[DATA_MAX + 1];
      snprintf(tmp, sizeof tmp, "%.*s / ***", (int)(DATA_MAX - 6), s.data);
      copyStr(s.data, sizeof s.data, tmp);
    }
    queuePush(s.t, s.src, s.port, s.service, s.data, s.user);
  }
  s.client.stop();
  resetSlot(s);
}

// Μια ολόκληρη γραμμή έφτασε (χωρίς το CR/LF).
static void onLine(ClientSlot &s) {
  s.line[s.lineLen] = '\0';

  switch (s.phase) {
    case PH_TELNET_USER:
      sanitize(s.line, s.data, sizeof s.data);
      sanitize(s.line, s.user, sizeof s.user);
      clientWrite(s, TELNET_PASS);
      s.phase = PH_TELNET_PASS;
      break;

    case PH_TELNET_PASS:   // (η γραμμή δεν γράφτηκε στο buffer, βλ. feedByte)
      s.sawPass = true;
      clientWrite(s, TELNET_FAIL);
      finishSlot(s);
      return;

    case PH_HTTP_HEAD:
      if (!s.gotFirst) {
        if (s.lineLen == 0) break;           // κενές γραμμές πριν το request: αγνοούνται
        sanitizeRequestLine(s.line, s.data, sizeof s.data);
        s.gotFirst = true;
      } else if (s.lineLen == 0) {           // τέλος headers
        sendHttp401(s);
        finishSlot(s);
        return;
      } else if (strncasecmp(s.line, "authorization:", 14) == 0) {
        const char *p = s.line + 14;
        while (*p == ' ' || *p == '\t') p++;
        if (strncasecmp(p, "basic", 5) == 0 && (p[5] == ' ' || p[5] == '\t')) {
          p += 5;
          while (*p == ' ' || *p == '\t') p++;
          basicAuthUser(p, s.user, sizeof s.user);
        }
      }
      break;

    default:
      break;
  }
  memset(s.line, 0, s.lineLen + 1);   // ΚΑΘΕ γραμμή σβήνεται (π.χ. Authorization)
  s.lineLen = 0;
}

// Ένα byte από τον επισκέπτη.
static void feedByte(ClientSlot &s, uint8_t c) {
  // Telnet: αποκοπή διαπραγμάτευσης (IAC = 0xFF). Καταστάσεις του s.iac:
  //   0 κανονικό, 1 μετά από IAC, 2 περιμένουμε option (WILL/WONT/DO/DONT),
  //   3 μέσα σε SB, 4 μέσα σε SB μετά από IAC
  if (s.service == SVC_TELNET) {
    switch (s.iac) {
      case 0: if (c == 0xFF) { s.iac = 1; return; } break;
      case 1:
        if (c == 0xFF) { s.iac = 0; break; }               // διπλό IAC = byte 0xFF
        s.iac = (c >= 251 && c <= 254) ? 2 : (c == 250 ? 3 : 0);
        return;
      case 2: s.iac = 0; return;
      case 3: if (c == 0xFF) s.iac = 4; return;
      case 4: s.iac = (c == 240) ? 0 : 3; return;          // 240 = SE
      default: s.iac = 0; return;
    }
  }

  if (s.skipLf) {   // CRLF ή CR NUL (telnet) = ένα τέλος γραμμής
    s.skipLf = false;
    if (c == '\n' || c == '\0') return;
  }
  if (c == '\r' || c == '\n') {
    s.skipLf = (c == '\r');
    onLine(s);
    return;
  }
  if (s.phase == PH_TELNET_PASS) return;   // ο κωδικός ΔΕΝ αποθηκεύεται ποτέ
  if (s.lineLen < CANARY_LINE_MAX) s.line[s.lineLen++] = (char)c;
}

static ClientSlot *freeSlot() {
  for (auto &s : g_slots) if (s.phase == PH_FREE) return &s;
  return nullptr;
}

static void acceptFrom(WiFiServer &srv, uint16_t port, ServiceKind svc) {
  for (int n = 0; n < ACCEPTS_PER_LOOP; n++) {
    WiFiClient c = srv.accept();   // non-blocking: άδειο αν δεν περιμένει κανείς
    if (!c) return;

    char src[SRC_MAX + 1];
    copyStr(src, sizeof src, c.remoteIP().toString().c_str());
    if (isIgnored(src)) { c.stop(); continue; }

    g_hits++;
    g_countersDirty = true;
    const bool report = rateAllow(src, port);
    if (!report) g_suppressed++;

    ClientSlot *s = freeSlot();
    if (!s) {   // όλες οι θέσεις πιασμένες: καταγραφή χωρίς διάλογο
      if (report) queuePush(uptimeS(), src, port, svc, "", "");
      c.stop();
      continue;
    }
    resetSlot(*s);
    s->client = c;
    s->client.setConnectionTimeout(CLIENT_WRITE_MS);   // όριο και για το write()
    s->service = svc;
    s->port = port;
    copyStr(s->src, sizeof s->src, src);
    s->startMs = millis();
    s->t = uptimeS();
    s->report = report;
    if (svc == SVC_TELNET) {
      s->phase = PH_TELNET_USER;
      clientWrite(*s, TELNET_BANNER);
    } else {
      s->phase = PH_HTTP_HEAD;
    }
  }
}

static void serviceClients() {
  uint8_t buf[READ_CHUNK];
  for (auto &s : g_slots) {
    if (s.phase == PH_FREE) continue;

    // (α) Διαβάζουμε ΜΟΝΟ ό,τι έχει ήδη φτάσει, με όριο ανά γύρο.
    for (int k = 0; k < CHUNKS_PER_LOOP && s.phase != PH_FREE; k++) {
      const int avail = s.client.available();
      if (avail <= 0) break;
      const size_t want = (size_t)avail < sizeof buf ? (size_t)avail : sizeof buf;
      const int got = s.client.read(buf, want);
      if (got <= 0) break;
      for (int i = 0; i < got && s.phase != PH_FREE; i++) {
        if (++s.total > MAX_BYTES_PER_CONN) {   // υπερβολικά πολλά δεδομένα
          if (s.service != SVC_TELNET) sendHttp401(s);
          finishSlot(s);
          break;
        }
        feedByte(s, buf[i]);
      }
    }
    memset(buf, 0, sizeof buf);   // ίχνη κωδικών Telnet δεν μένουν στη στοίβα
    if (s.phase == PH_FREE) continue;

    // (β) Timeout: ο αργός επισκέπτης δεν κρατά τη θέση για πάντα.
    const uint32_t limitMs =
        (s.service == SVC_TELNET ? TELNET_TIMEOUT_S : HTTP_TIMEOUT_S) * 1000UL;
    if (millis() - s.startMs >= limitMs) {
      if (s.service == SVC_HTTP) sendHttp401(s);   // απαντάμε ό,τι κι αν έστειλε
      finishSlot(s);
      continue;
    }

    // (γ) Ο επισκέπτης έκλεισε τη σύνδεση (και δεν έχει άλλα δεδομένα).
    if (!s.client.connected()) finishSlot(s);
  }
}

// =============================================================================
//  5. MQTT OVER TLS (esp-mqtt)
// =============================================================================
static esp_mqtt_client_handle_t g_mqtt = nullptr;
static volatile bool g_mqttConnected = false;
static volatile bool g_heartbeatNow = false;   // heartbeat αμέσως μετά από (επανα)σύνδεση
static bool g_mqttStarted = false;

// Χειριστής γεγονότων: καλείται από το task του esp-mqtt (ΟΧΙ από το loop).
// Μόνο σημαίες και Serial: καμία πρόσβαση στις δομές του loop.
static void mqttEventHandler(void *, esp_event_base_t, int32_t eventId, void *eventData) {
  esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)eventData;
  switch ((esp_mqtt_event_id_t)eventId) {
    case MQTT_EVENT_CONNECTED:
      g_mqttConnected = true;
      g_heartbeatNow = true;
      Serial.println("[mqtt] connected (TLS verified)");
      break;
    case MQTT_EVENT_DISCONNECTED:
      g_mqttConnected = false;
      Serial.println("[mqtt] disconnected (esp-mqtt will retry)");
      break;
    case MQTT_EVENT_ERROR:
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
  // έλεγχο. Το hostname του URI πρέπει να υπάρχει στο SAN του server.crt.
  cfg.broker.verification.certificate = MQTT_CA_PEM;
  cfg.credentials.client_id = g_id;
  cfg.credentials.username = MQTT_USER;
  cfg.credentials.authentication.password = MQTT_PASS;
  // Last Will: αν χαθεί απότομα η σύνδεση (ρεύμα, crash, κάποιος το βγάλει
  // από την πρίζα), ο broker δημοσιεύει αυτό στο status topic ως retained.
  cfg.session.last_will.topic = g_topicStatus;
  cfg.session.last_will.msg = LWT_MSG;
  cfg.session.last_will.msg_len = sizeof(LWT_MSG) - 1;
  cfg.session.last_will.qos = 1;
  cfg.session.last_will.retain = 1;
  cfg.session.keepalive = 15;
  cfg.network.timeout_ms = 8000;
  cfg.network.reconnect_timeout_ms = 5000;

  g_mqtt = esp_mqtt_client_init(&cfg);
  if (!g_mqtt) { Serial.println("[mqtt] init FAILED"); return; }
  esp_mqtt_client_register_event(g_mqtt, MQTT_EVENT_ANY, mqttEventHandler, nullptr);
}

// Βάζει μήνυμα στο outbox του esp-mqtt ΧΩΡΙΣ να περιμένει το δίκτυο.
// Την αποστολή (και την επανάληψη για QoS 1) την κάνει το task του esp-mqtt.
static bool mqttEnqueue(const char *topic, const char *payload, bool retain) {
  if (!g_mqtt || !g_mqttConnected) return false;
  if (esp_mqtt_client_get_outbox_size(g_mqtt) > OUTBOX_MAX_BYTES) return false;
  return esp_mqtt_client_enqueue(g_mqtt, topic, payload, 0, /*qos=*/1, retain ? 1 : 0,
                                 /*store=*/true) >= 0;
}

// -----------------------------------------------------------------------------
//  JSON payloads (με snprintf: καμία εξωτερική βιβλιοθήκη)
// -----------------------------------------------------------------------------
static void buildHeartbeat(char *out, size_t len) {
  snprintf(out, len,
           "{\"id\":\"%s\",\"online\":true,\"fw\":\"%s\",\"uptime\":%lu,\"heap\":%lu,"
           "\"rssi\":%d,\"ip\":\"%s\",\"canary_hits\":%lu,\"suppressed\":%lu,\"kind\":\"canary\"}",
           g_id, FW_VERSION, (unsigned long)uptimeS(), (unsigned long)ESP.getFreeHeap(),
           (int)WiFi.RSSI(), WiFi.localIP().toString().c_str(),
           (unsigned long)g_hits, (unsigned long)g_suppressed);
}

static void buildEvent(const CanaryEvent &ev, char *out, size_t len) {
  char data[DATA_MAX * 2 + 1];   // χειρότερη περίπτωση: κάθε χαρακτήρας γίνεται \x
  char user[USER_MAX * 2 + 1];
  char src[SRC_MAX * 2 + 1];
  jsonEscape(ev.data, data, sizeof data);
  jsonEscape(ev.user, user, sizeof user);
  jsonEscape(ev.src, src, sizeof src);
  snprintf(out, len,
           "{\"type\":\"canary\",\"id\":\"%s\",\"port\":%u,\"src\":\"%s\",\"service\":\"%s\","
           "\"data\":\"%s\",\"user\":\"%s\",\"t\":%lu}",
           g_id, (unsigned)ev.port, src, ev.service == SVC_TELNET ? "telnet" : "http",
           data, user, (unsigned long)ev.t);
}

static void saveCounters() {
  if (!g_countersDirty) return;
  g_prefs.putULong("hits", g_hits);
  g_prefs.putULong("supp", g_suppressed);
  g_countersDirty = false;
}

static uint32_t g_lastHeartbeatMs = 0;

static void heartbeatTick() {
  if (!g_mqttConnected) return;
  if (!g_heartbeatNow && millis() - g_lastHeartbeatMs < (uint32_t)HEARTBEAT_INTERVAL_S * 1000UL)
    return;
  char buf[320];
  buildHeartbeat(buf, sizeof buf);
  if (mqttEnqueue(g_topicStatus, buf, /*retain=*/true)) {
    Serial.printf("[mqtt] status -> %s\n", buf);
    g_heartbeatNow = false;
    g_lastHeartbeatMs = millis();
    saveCounters();   // το πολύ μία εγγραφή στη flash ανά heartbeat
  }
}

static void flushEvents() {
  char buf[512];   // χειρότερη περίπτωση ~425 bytes (όλα escaped)
  for (int n = 0; n < 4 && g_qCount && g_mqttConnected; n++) {
    buildEvent(g_queue[g_qHead], buf, sizeof buf);
    if (!mqttEnqueue(g_topicEvent, buf, /*retain=*/false)) break;
    Serial.printf("[mqtt] event  -> %s\n", buf);
    g_qHead = (g_qHead + 1) % QUEUE_SIZE;
    g_qCount--;
  }
}

// =============================================================================
//  6. Wi-Fi, mDNS, εκκίνηση υπηρεσιών
// =============================================================================
static bool     g_wifiUp = false;
static bool     g_servicesStarted = false;
static uint32_t g_wifiDownSince = 0;

static void startServices() {
  if (g_servicesStarted) return;
  g_servicesStarted = true;

  g_srvTelnet.begin();
  g_srvTelnet.setNoDelay(true);
  g_srvHttp.begin();
  g_srvHttp.setNoDelay(true);
#if CANARY_ENABLE_8080
  g_srvHttpAlt.begin();
  g_srvHttpAlt.setNoDelay(true);
#endif

  // mDNS: για να μας "βρίσκουν" οι scanners (και τα εργαλεία ανακάλυψης).
  if (MDNS.begin(CANARY_HOSTNAME)) {
    MDNS.setInstanceName("IP Camera");
    MDNS.addService("http", "tcp", 80);
    MDNS.addService("telnet", "tcp", 23);
    Serial.printf("[mdns] %s.local: _http._tcp:80 _telnet._tcp:23\n", CANARY_HOSTNAME);
  } else {
    Serial.println("[mdns] start FAILED (continuing without mDNS)");
  }

  if (g_mqtt && !g_mqttStarted) {
    g_mqttStarted = (esp_mqtt_client_start(g_mqtt) == ESP_OK);
    if (!g_mqttStarted) Serial.println("[mqtt] start FAILED");
  }

  Serial.printf("[trap] listening on 23 (telnet), 80 (http)%s\n",
                CANARY_ENABLE_8080 ? ", 8080 (http)" : "");
}

static void wifiTick() {
  const bool up = WiFi.status() == WL_CONNECTED;
  if (up && !g_wifiUp) {
    g_wifiUp = true;
    Serial.printf("[wifi] connected, ip %s rssi %d hostname %s\n",
                  WiFi.localIP().toString().c_str(), (int)WiFi.RSSI(), WiFi.getHostname());
    startServices();
  } else if (!up && g_wifiUp) {
    g_wifiUp = false;
    g_wifiDownSince = millis();
    Serial.println("[wifi] disconnected (auto-reconnect)");
  }
  // Δίχτυ ασφαλείας: αν το auto-reconnect δεν τα καταφέρει για πολύ, ξαναρχίζουμε.
  if (!up && millis() - g_wifiDownSince >= WIFI_KICK_MS) {
    Serial.println("[wifi] still down, restarting connection");
    WiFi.disconnect(false, false);
    WiFi.begin(WIFI_SSID, WIFI_PASS);   // ασύγχρονο: δεν περιμένει
    g_wifiDownSince = millis();
  }
}

// =============================================================================
//  7. SETUP & LOOP
// =============================================================================
void setup() {
  Serial.begin(115200);
  delay(300);   // μόνο στην εκκίνηση, για να προλάβει το Serial monitor

  for (auto &s : g_slots) resetSlot(s);

  // Ταυτότητα: "canary-" + τα 3 τελευταία bytes της MAC (πεζά, χωρίς ':').
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  snprintf(g_id, sizeof g_id, "canary-%02x%02x%02x", mac[3], mac[4], mac[5]);
  snprintf(g_topicStatus, sizeof g_topicStatus, "netwatch/sensor/%s/status", g_id);
  snprintf(g_topicEvent, sizeof g_topicEvent, "netwatch/sensor/%s/event", g_id);
  snprintf(g_brokerUri, sizeof g_brokerUri, "mqtts://%s:%d", MQTT_HOST, (int)MQTT_PORT);

  Serial.println();
  Serial.println("=============================================");
  Serial.printf (" NetWatch Canary v%s  id=%s\n", FW_VERSION, g_id);
  Serial.println(" Honeypot tripwire: listens only, never stores passwords");
  Serial.println("=============================================");

  parseIgnoreList();
  Serial.printf("[cfg] broker %s  hostname %s  ignore-list %u IP(s)\n",
                g_brokerUri, CANARY_HOSTNAME, (unsigned)g_ignoreCount);

  g_prefs.begin("canary", /*readOnly=*/false);
  g_hits       = g_prefs.getULong("hits", 0);
  g_suppressed = g_prefs.getULong("supp", 0);
  const uint32_t boots = g_prefs.getULong("boots", 0) + 1;
  g_prefs.putULong("boots", boots);
  Serial.printf("[cfg] boot #%lu, canary_hits=%lu suppressed=%lu\n", (unsigned long)boots,
                (unsigned long)g_hits, (unsigned long)g_suppressed);

  // Wi-Fi station. Το hostname ΠΡΙΝ το mode/begin, αλλιώς το DHCP στέλνει
  // το προεπιλεγμένο "esp32-xxxxxx" και η μεταμφίεση χαλάει.
  WiFi.setHostname(CANARY_HOSTNAME);
  WiFi.mode(WIFI_STA);
  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);
  WiFi.setSleep(false);   // γρήγορη απόκριση σε scanners
  WiFi.begin(WIFI_SSID, WIFI_PASS);   // ασύγχρονο: τη σύνδεση την παρακολουθεί το wifiTick()
  g_wifiDownSince = millis();
  Serial.printf("[wifi] connecting to '%s' ...\n", WIFI_SSID);

  mqttInit();
}

void loop() {
  wifiTick();
  if (g_servicesStarted) {
    acceptFrom(g_srvTelnet, 23, SVC_TELNET);
    acceptFrom(g_srvHttp, 80, SVC_HTTP);
#if CANARY_ENABLE_8080
    acceptFrom(g_srvHttpAlt, 8080, SVC_HTTP);
#endif
    serviceClients();
  }
  flushEvents();
  heartbeatTick();
  // 1 tick παραχώρηση στο RTOS (όχι αναμονή): αφήνει χρόνο στα tasks Wi-Fi/MQTT
  // και στο idle task, χωρίς να καθυστερεί αισθητά καμία σύνδεση.
  vTaskDelay(1);
}
