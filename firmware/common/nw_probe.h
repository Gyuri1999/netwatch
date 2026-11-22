// =============================================================================
//  NetWatch - nw_probe.h   (κοινός πελάτης του «πρωτοκόλλου αισθητήρα»)
// -----------------------------------------------------------------------------
//  Κοινό για τα esp32-rack, esp32-poe, esp32-ble, esp32-lora-gw. Υλοποιεί ό,τι
//  κάνει και το tools/netwatch_probe.py (ο πελάτης αναφοράς), για ESP32
//  (Arduino core 3.x), ΧΩΡΙΣ εξωτερικές βιβλιοθήκες:
//
//    POST https://<NetWatch>:8790/probe/v1/report     Authorization: Bearer <token>
//    {"status": {fw,hw,ip,mac,uptime,heap,rssi,batt,temp,hum,interval,
//                "metrics": {…}, "link": {…}},
//     "events": [{"type","detail","data":{…}}],
//     "items":  [{…}, …]}
//
//  ΑΣΦΑΛΕΙΑ
//    * Ο κωδικός σύζευξης ("NW1.<base64url JSON>") δίνει id, διευθύνσεις, token
//      και το αποτύπωμα SHA-256 του πιστοποιητικού του NetWatch.
//    * TLS προς self-signed πιστοποιητικό: ΔΕΝ υπάρχει CA να ελεγχθεί, οπότε η
//      ταυτότητα του server ελέγχεται με ΚΑΡΦΙΤΣΩΜΑ (pinning): μετά το
//      handshake συγκρίνουμε το SHA-256 ΟΛΟΥ του πιστοποιητικού με αυτό της
//      σύζευξης, και ΜΟΝΟ αν ταιριάζει στέλνουμε το token. Αν δεν ταιριάζει,
//      κλείνουμε τη σύνδεση. Δεν υπάρχει «ανασφαλές» fallback.
//    * Όλα τα buffers έχουν όριο. Ό,τι δεν χωρά (γραμμές items, πεδία) απλώς
//      παραλείπεται, το JSON μένει πάντα έγκυρο.
//    * Κάθε string περνά από escape ΚΑΙ έλεγχο UTF-8 (ένα όνομα BLE ή ένα
//      LLDP system name μπορεί να περιέχει οτιδήποτε).
//
//  ΧΡΗΣΗ (βλ. τα sketches):
//    static NwProbe nw;
//    setup():  nw.begin(NW_PAIR_CODE, FW_VERSION, "ESP32 + SHT31", 4096, 60);
//              nwWifiConnect(WIFI_SSID, WIFI_PASS, 15000);
//    loop():   if (κάτι συνέβη) { nw.event("door_open", "Άνοιξε η πόρτα"); nw.evBool("door", true); }
//              if (nw.due() && δίκτυο) {
//                NwJson &j = nw.start(ip, mac, rssi);   // ανοίγει το "status"
//                j.num("temp", 23.4, 1);
//                j.beginObject("metrics"); j.boolean("door", false); j.endObject();
//                nw.items();                             // (προαιρετικό) ανοίγει το "items"
//                if (nw.rowBegin()) { j.str("mac", "…"); nw.rowEnd(); }
//                nw.send();                              // POST + backoff + interval
//              }
//
//  Η event() ΔΕΝ είναι ασφαλής από ISR: κάλεσέ τη μόνο από το loop().
//  Μεταγλώττιση: arduino-cli compile --library ../common ...
// =============================================================================
#pragma once

#include <Arduino.h>

// Όρια (ίδια ή αυστηρότερα από του server, βλ. probes.py)
#define NW_SERVER_MAX_BODY 16384   // MAX_BODY του server
#define NW_MAX_URLS        4       // πόσες διευθύνσεις κρατάμε από τον κωδικό
#define NW_MAX_ITEMS       80      // γραμμές "items" ανά αναφορά
#define NW_MAX_EVENTS_POST 10      // γεγονότα ανά αναφορά (ο server κρατά 10)
#define NW_EVENT_QUEUE     12      // γεγονότα που κρατάμε όσο είμαστε offline
#define NW_JSON_MAX_DEPTH  6

enum NwResult : uint8_t {
  NW_OK = 0,
  NW_ERR_CONFIG,    // δεν υπάρχει (έγκυρος) κωδικός σύζευξης
  NW_ERR_CONNECT,   // καμία διεύθυνση δεν απάντησε (TCP/TLS)
  NW_ERR_PIN,       // ΑΛΛΟ πιστοποιητικό από αυτό της σύζευξης: δεν στάλθηκε τίποτα
  NW_ERR_AUTH,      // HTTP 401/403: ο αισθητήρας διαγράφηκε ή λάθος token
  NW_ERR_HTTP,      // άλλο HTTP status (413, 429, 5xx…)
  NW_ERR_REPLY,     // δεν ήρθε (έγκυρη) απάντηση
};

// -----------------------------------------------------------------------------
//  NwJson: μικρός, ασφαλής συγγραφέας JSON πάνω σε ξένο buffer.
//  Κάθε μέλος γράφεται ΑΤΟΜΙΚΑ: ή χωρά ολόκληρο ή δεν γράφεται καθόλου (και το
//  overflow() γίνεται true). Οι αγκύλες κλεισίματος έχουν πάντα κρατημένο χώρο.
// -----------------------------------------------------------------------------
class NwJson {
public:
  struct Mark { size_t len; uint8_t depth; uint8_t first; uint8_t skip; bool ovf; };

  void attach(char *buf, size_t cap);
  void reset();
  const char *c_str() const { return _buf ? _buf : ""; }
  size_t length() const { return _len; }
  bool overflow() const { return _ovf; }

  // key == nullptr: ανώνυμο (ρίζα ή στοιχείο πίνακα)
  bool beginObject(const char *key = nullptr);
  bool beginArray(const char *key = nullptr);
  void endObject();
  void endArray();

  bool str(const char *key, const char *val);               // escape + έλεγχος UTF-8
  bool num(const char *key, double v, uint8_t decimals = 1); // NaN/Inf -> παραλείπεται
  bool integer(const char *key, long v);
  bool boolean(const char *key, bool v);

  Mark mark() const;            // σημείο επιστροφής (π.χ. πριν από μια γραμμή items)
  void rewind(const Mark &m);   // πέτα ό,τι γράφτηκε μετά το mark

private:
  char *_buf = nullptr;
  size_t _cap = 0, _len = 0;
  uint8_t _depth = 0;
  uint8_t _first = 0xFF;   // bit ανά βάθος: 1 = δεν έχει γραφτεί ακόμα μέλος
  uint8_t _skip = 0;       // >0: είμαστε μέσα σε αντικείμενο/πίνακα που ΔΕΝ χώρεσε (όλα αγνοούνται)
  bool _ovf = false;

  bool _room(size_t n) const;
  bool _raw(const char *s, size_t n);
  bool _sepKey(const char *key);
  bool _escaped(const char *s);
  void _close(char c);
  bool _open(const char *key, char c);
};

// Escape για JSON string με έλεγχο UTF-8 (άκυρα bytes -> '?'). Επιστρέφει μήκος
// ή (size_t)-1 αν δεν χωρά. Δεν γράφει εισαγωγικά.
size_t nwJsonEscape(const char *in, char *out, size_t cap);

// -----------------------------------------------------------------------------
//  NwProbe
// -----------------------------------------------------------------------------
class NwProbe {
public:
  // Διαβάζει τον κωδικό σύζευξης και δεσμεύει το buffer της αναφοράς (μία φορά).
  // bodyCap: 1024..16000 bytes. intervalS: κάθε πότε στέλνουμε (10..3600 s).
  bool begin(const char *pairCode, const char *fw, const char *hw, size_t bodyCap = 4096, uint16_t intervalS = 60);

  bool paired() const { return _paired; }
  const char *id() const { return _id; }          // "p-xxxxxxxx"
  const char *kind() const { return _kind; }      // "rack", "field", "ble", "lora"…
  const char *lastError() const { return _err; }  // σύντομο, ASCII, για το Serial
  int lastHttp() const { return _http; }

  // --- Γεγονότα (ουρά NW_EVENT_QUEUE· αν γεμίσει χάνεται το ΠΑΛΑΙΟΤΕΡΟ) ---
  // type: [a-z0-9_]{1,24}. detail: σύντομο κείμενο (UTF-8). Κάνει και kick().
  bool event(const char *type, const char *detail);
  // Πεδία "data" του ΤΕΛΕΥΤΑΙΟΥ event() (έως ~10, ο server κρατά 12 μαζί με το "ago").
  void evStr(const char *key, const char *val);
  void evNum(const char *key, double v, uint8_t decimals = 1);
  void evInt(const char *key, long v);
  void evBool(const char *key, bool v);
  uint8_t pending() const { return _qCount; }
  uint32_t dropped() const { return _qDropped; }

  // --- Χρονισμός ---
  bool due() const;              // ώρα για αναφορά; (περιοδικά, ή νωρίτερα μετά από kick)
  void kick() { _kick = true; }  // «στείλε το συντομότερο» (σεβόμενο το backoff)
  uint32_t intervalS() const { return _interval; }
  uint8_t fails() const { return _fails; }

  // --- Σύνθεση αναφοράς ---
  // Ξεκινά {"status":{fw,hw,ip,mac,uptime,heap,[rssi,]interval και αφήνει το
  // "status" ΑΝΟΙΧΤΟ για batt/temp/hum/metrics/link. rssi == 0: δεν γράφεται.
  NwJson &start(const char *ip, const char *mac, int rssi = 0);
  // Κλείνει το "status", γράφει τα "events" και ανοίγει το "items".
  // (Αν δεν κληθεί, η αναφορά δεν έχει "items" και ο server κρατά την παλιά λίστα.)
  void items();
  bool rowBegin();   // false: γεμάτο (NW_MAX_ITEMS ή buffer) -> μην γράψεις γραμμή
  bool rowEnd();     // false: η γραμμή δεν χώρεσε και αφαιρέθηκε ολόκληρη
  uint8_t rows() const { return _rows; }
  // Κλείνει το JSON και το στέλνει. Σε επιτυχία αφαιρεί τα γεγονότα που έφυγαν.
  NwResult send();

private:
  struct Url { char host[48]; uint16_t port; };
  struct Ev { char type[25]; char detail[200]; char data[176]; uint32_t ms; };

  bool _paired = false;
  char _id[20] = "";
  char _kind[12] = "";
  char _token[104] = "";
  uint8_t _fp[32];
  Url _urls[NW_MAX_URLS];
  uint8_t _nUrls = 0;
  const char *_fw = "", *_hw = "";

  char *_body = nullptr;
  size_t _bodyCap = 0;
  NwJson _j;
  uint8_t _phase = 0;        // 0 τίποτα, 1 status ανοιχτό, 2 items ανοιχτό
  uint8_t _rows = 0;
  uint8_t _evInBody = 0;
  NwJson::Mark _rowMark;

  Ev _q[NW_EVENT_QUEUE];
  uint8_t _qHead = 0, _qCount = 0;
  uint32_t _qDropped = 0;

  uint16_t _interval = 60;
  uint32_t _lastTry = 0, _waitMs = 0;
  uint8_t _fails = 0;
  bool _kick = true, _never = true;
  int _http = 0;
  char _err[64] = "";

  void _evAppend(const char *key, const char *valueJson);
  void _writeEvents();
  NwResult _post(const Url &u, size_t len);
  void _setErr(const char *fmt, ...);
};

// -----------------------------------------------------------------------------
//  Βοηθητικά δικτύου / συστήματος
// -----------------------------------------------------------------------------
// Σύνδεση Wi-Fi (STA) με όριο χρόνου. true αν συνδεθήκαμε (ή ήμασταν ήδη).
bool nwWifiConnect(const char *ssid, const char *pass, uint32_t timeoutMs = 15000);
// MAC του Wi-Fi STA ως "aa:bb:cc:dd:ee:ff" (out >= 18).
void nwWifiMac(char *out, size_t len);
// Task watchdog για το loop(): αν ένα loop() κρατήσει πάνω από `seconds`, reset.
// Οι κλήσεις του NwProbe που μπλοκάρουν ταΐζουν μόνες τους τον watchdog.
void nwWatchdog(uint32_t seconds);
void nwWatchdogFeed();
