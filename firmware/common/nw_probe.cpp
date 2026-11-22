// =============================================================================
//  NetWatch - nw_probe.cpp   (βλ. nw_probe.h για την περιγραφή και τη χρήση)
// =============================================================================
#include "nw_probe.h"

#include <WiFi.h>
#include <NetworkClientSecure.h>
#include <esp_task_wdt.h>
#include <esp_random.h>
#include <mbedtls/base64.h>
#include <stdarg.h>
#include <math.h>

static const uint32_t CONNECT_TIMEOUT_MS = 6000;   // TCP + αναμονές socket
static const uint32_t HANDSHAKE_TIMEOUT_S = 10;    // TLS handshake
static const uint32_t REPLY_TIMEOUT_MS = 8000;     // αναμονή απάντησης HTTP
static const uint32_t SEND_BUDGET_MS = 30000;      // συνολικό όριο μιας send() (όλες οι διευθύνσεις)
static const uint32_t KICK_MIN_GAP_MS = 2000;      // ελάχιστη απόσταση δύο αναφορών
static const uint32_t BACKOFF_FIRST_S = 5;         // 5, 10, 20, 40 … s
static const uint32_t BACKOFF_MAX_S = 300;
static const size_t JSON_RESERVE = NW_JSON_MAX_DEPTH + 2;   // χώρος για τις αγκύλες κλεισίματος

static bool s_wdt = false;

// =============================================================================
//  1. JSON: escape + συγγραφέας
// =============================================================================

// Πόσα bytes πιάνει ο έγκυρος χαρακτήρας UTF-8 που αρχίζει στο s (0 = άκυρος).
// Αυστηρός έλεγχος (όχι overlong, όχι surrogates): ο server διαβάζει το σώμα με
// αυστηρό UTF-8 και ένα μόνο κακό byte θα απέρριπτε ΟΛΗ την αναφορά.
static uint8_t utf8Len(const unsigned char *s) {
  unsigned char c = s[0];
  if (c < 0x80) return 1;
  if (c >= 0xC2 && c <= 0xDF) return ((s[1] & 0xC0) == 0x80) ? 2 : 0;
  if (c >= 0xE0 && c <= 0xEF) {
    if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
    if (c == 0xE0 && s[1] < 0xA0) return 0;
    if (c == 0xED && s[1] > 0x9F) return 0;
    return 3;
  }
  if (c >= 0xF0 && c <= 0xF4) {
    if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) return 0;
    if (c == 0xF0 && s[1] < 0x90) return 0;
    if (c == 0xF4 && s[1] > 0x8F) return 0;
    return 4;
  }
  return 0;
}

size_t nwJsonEscape(const char *in, char *out, size_t cap) {
  size_t o = 0;
  const unsigned char *s = (const unsigned char *)(in ? in : "");
  while (*s) {
    unsigned char c = *s;
    if (o + 7 >= cap) return (size_t)-1;   // 6 = το μακρύτερο (\u00XX) + NUL
    if (c == '"' || c == '\\') {
      out[o++] = '\\';
      out[o++] = (char)c;
      s++;
    } else if (c < 0x20 || c == 0x7F) {
      o += snprintf(out + o, cap - o, "\\u%04x", c);
      s++;
    } else {
      // Το utf8Len διαβάζει μόνο όσα bytes συνέχειας χρειάζεται και σταματά στο
      // πρώτο που δεν ταιριάζει (άρα και στο NUL): δεν περνά το τέλος του string.
      uint8_t n = utf8Len(s);
      if (n == 0) {
        out[o++] = '?';
        s++;
      } else {
        for (uint8_t i = 0; i < n; i++) out[o++] = (char)s[i];
        s += n;
      }
    }
  }
  out[o] = '\0';
  return o;
}

void NwJson::attach(char *buf, size_t cap) {
  _buf = buf;
  _cap = cap;
  reset();
}

void NwJson::reset() {
  _len = 0;
  _depth = 0;
  _first = 0xFF;
  _skip = 0;
  _ovf = false;
  if (_buf && _cap) _buf[0] = '\0';
}

bool NwJson::_room(size_t n) const { return _buf && _len + n + JSON_RESERVE + 1 <= _cap; }

bool NwJson::_raw(const char *s, size_t n) {
  if (!_room(n)) return false;
  memcpy(_buf + _len, s, n);
  _len += n;
  _buf[_len] = '\0';
  return true;
}

bool NwJson::_escaped(const char *s) {
  if (!_room(8)) return false;
  size_t avail = _cap - _len - JSON_RESERVE;
  size_t n = nwJsonEscape(s, _buf + _len, avail);
  if (n == (size_t)-1) {
    _buf[_len] = '\0';
    return false;
  }
  _len += n;
  return true;
}

// Γράφει  [,]"key":  (ή μόνο το κόμμα για ανώνυμο στοιχείο).
bool NwJson::_sepKey(const char *key) {
  if (!(_first & (1 << _depth)) && !_raw(",", 1)) return false;
  if (key) return _raw("\"", 1) && _escaped(key) && _raw("\":", 2);
  return true;
}

NwJson::Mark NwJson::mark() const { return Mark{_len, _depth, _first, _skip, _ovf}; }

void NwJson::rewind(const Mark &m) {
  _len = m.len;
  _depth = m.depth;
  _first = m.first;
  _skip = m.skip;
  _ovf = m.ovf;
  if (_buf && _cap) _buf[_len] = '\0';
}

// Τα μέλη γράφονται ατομικά: αν κάτι δεν χωρά, γυρνάμε στο σημείο πριν.
#define NW_MEMBER(expr)                 \
  do {                                  \
    Mark m_ = mark();                   \
    if (_skip || !(expr)) {                      \
      rewind(m_);                       \
      _ovf = true;                      \
      return false;                     \
    }                                   \
    _first &= (uint8_t)~(1 << _depth);  \
    return true;                        \
  } while (0)

bool NwJson::str(const char *key, const char *val) {
  NW_MEMBER(_sepKey(key) && _raw("\"", 1) && _escaped(val) && _raw("\"", 1));
}

bool NwJson::num(const char *key, double v, uint8_t decimals) {
  if (isnan(v) || isinf(v) || fabs(v) > 1e12) return false;   // ο server τα πετά ούτως ή άλλως
  char t[32];
  int n = snprintf(t, sizeof(t), "%.*f", decimals > 6 ? 6 : decimals, v);
  if (n <= 0 || n >= (int)sizeof(t)) return false;
  NW_MEMBER(_sepKey(key) && _raw(t, (size_t)n));
}

bool NwJson::integer(const char *key, long v) {
  char t[16];
  int n = snprintf(t, sizeof(t), "%ld", v);
  NW_MEMBER(_sepKey(key) && _raw(t, (size_t)n));
}

bool NwJson::boolean(const char *key, bool v) {
  NW_MEMBER(_sepKey(key) && (v ? _raw("true", 4) : _raw("false", 5)));
}

bool NwJson::_open(const char *key, char c) {
  // Αν το άνοιγμα δεν χωρά, μπαίνουμε σε «παράλειψη»: ό,τι γραφτεί μέχρι το
  // αντίστοιχο end…() αγνοείται, ώστε τα begin/end του καλούντος να ισορροπούν.
  if (_skip) {
    _skip++;
    return false;
  }
  Mark m = mark();
  bool ok = _depth + 1 < NW_JSON_MAX_DEPTH && _sepKey(key) && _raw(&c, 1);
  if (!ok) {
    rewind(m);
    _ovf = true;
    _skip = 1;
    return false;
  }
  _first &= (uint8_t)~(1 << _depth);
  _depth++;
  _first |= (uint8_t)(1 << _depth);
  return true;
}

bool NwJson::beginObject(const char *key) { return _open(key, '{'); }
bool NwJson::beginArray(const char *key) { return _open(key, '['); }

void NwJson::_close(char c) {
  if (_skip) {
    _skip--;
    return;
  }
  if (_depth == 0 || !_buf) return;
  if (_len + 2 <= _cap) {   // ο χώρος είναι κρατημένος από το JSON_RESERVE
    _buf[_len++] = c;
    _buf[_len] = '\0';
  }
  _depth--;
}

void NwJson::endObject() { _close('}'); }
void NwJson::endArray() { _close(']'); }

// =============================================================================
//  2. Κωδικός σύζευξης:  "NW1." + base64url(JSON {"v":1,"id","n","k","u":[…],"fp","t"})
// =============================================================================

static const char *skipWs(const char *p) {
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
  return p;
}

// Δείκτης στην ΤΙΜΗ του κλειδιού `key` στο πρώτο επίπεδο του αντικειμένου, ή nullptr.
// Ελάχιστος, ανεκτικός σαρωτής: καταλαβαίνει strings (με escapes) και βάθος.
static const char *jsonFind(const char *js, const char *key) {
  const size_t kl = strlen(key);
  int depth = 0;
  const char *p = js;
  while (*p) {
    char c = *p;
    if (c == '"') {
      const char *s = p + 1, *e = s;
      while (*e && *e != '"') {
        if (*e == '\\' && e[1]) e++;
        e++;
      }
      if (!*e) return nullptr;   // string που δεν κλείνει
      const char *q = skipWs(e + 1);
      if (depth == 1 && *q == ':') {
        if ((size_t)(e - s) == kl && memcmp(s, key, kl) == 0) return skipWs(q + 1);
        p = q + 1;
        continue;
      }
      p = e + 1;
      continue;
    }
    if (c == '{' || c == '[') depth++;
    else if (c == '}' || c == ']') depth--;
    p++;
  }
  return nullptr;
}

// Διαβάζει JSON string από το p (που δείχνει στο πρώτο ") στο out. Επιστρέφει
// δείκτη ΜΕΤΑ το κλείσιμο, ή nullptr (όχι string / δεν χωρά / δεν κλείνει).
static const char *jsonReadStr(const char *p, char *out, size_t cap) {
  if (!p || *p != '"' || cap == 0) return nullptr;
  p++;
  size_t o = 0;
  while (*p && *p != '"') {
    char c = *p++;
    if (c == '\\') {
      char e = *p;
      if (!e) return nullptr;
      p++;
      if (e == 'u') {   // \uXXXX: κρατάμε μόνο ASCII (id/token/url/fp είναι ASCII)
        unsigned v = 0;
        for (int i = 0; i < 4; i++) {
          char h = *p;
          if (!isxdigit((unsigned char)h)) return nullptr;
          v = v * 16 + (unsigned)(isdigit((unsigned char)h) ? h - '0' : (tolower(h) - 'a' + 10));
          p++;
        }
        c = (v >= 0x20 && v < 0x7F) ? (char)v : '?';
      } else if (e == 'n' || e == 'r' || e == 't' || e == 'b' || e == 'f') {
        c = ' ';
      } else {
        c = e;   // \" \\ \/
      }
    }
    if (o + 1 >= cap) return nullptr;
    out[o++] = c;
  }
  if (*p != '"') return nullptr;
  out[o] = '\0';
  return p + 1;
}

static int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// "AA:BB:…" (32 bytes) -> out. Δέχεται και χωρίς ':'. false αν δεν είναι ΑΚΡΙΒΩΣ 32 bytes.
static bool parseFingerprint(const char *s, uint8_t out[32]) {
  int n = 0;
  while (*s) {
    if (*s == ':' || *s == ' ') {
      s++;
      continue;
    }
    int hi = hexNibble(s[0]);
    int lo = (hi >= 0) ? hexNibble(s[1]) : -1;
    if (hi < 0 || lo < 0 || n >= 32) return false;
    out[n++] = (uint8_t)((hi << 4) | lo);
    s += 2;
  }
  return n == 32;
}

// "https://host:port" -> host, port. Μόνο https, μόνο ρητή θύρα.
static bool parseUrl(const char *url, char *host, size_t hostCap, uint16_t *port) {
  if (strncmp(url, "https://", 8) != 0) return false;
  const char *h = url + 8;
  const char *colon = strrchr(h, ':');
  if (!colon || colon == h) return false;
  size_t hl = (size_t)(colon - h);
  if (hl >= hostCap) return false;
  for (size_t i = 0; i < hl; i++) {
    char c = h[i];
    if (!(isalnum((unsigned char)c) || c == '.' || c == '-')) return false;
  }
  long p = 0;
  const char *d = colon + 1;
  if (!isdigit((unsigned char)*d)) return false;
  while (isdigit((unsigned char)*d) && p < 100000) p = p * 10 + (*d++ - '0');
  if (*d == '/') d++;
  if (*d != '\0' || p < 1 || p > 65535) return false;
  memcpy(host, h, hl);
  host[hl] = '\0';
  *port = (uint16_t)p;
  return true;
}

void NwProbe::_setErr(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(_err, sizeof(_err), fmt, ap);
  va_end(ap);
}

bool NwProbe::begin(const char *pairCode, const char *fw, const char *hw, size_t bodyCap, uint16_t intervalS) {
  _fw = fw ? fw : "";
  _hw = hw ? hw : "";
  _interval = constrain(intervalS, 10, 3600);
  _paired = false;
  _nUrls = 0;

  if (!_body) {
    _bodyCap = constrain(bodyCap, (size_t)2048, (size_t)(NW_SERVER_MAX_BODY - 384));
    _body = (char *)malloc(_bodyCap);
    if (!_body) {
      _setErr("no memory for %u byte body", (unsigned)_bodyCap);
      return false;
    }
    _j.attach(_body, _bodyCap);
  }

  // --- "NW1." + base64url ---
  const char *code = pairCode ? pairCode : "";
  while (*code == ' ') code++;
  if (strncmp(code, "NW1.", 4) != 0) {
    _setErr("pairing code must start with NW1.");
    return false;
  }
  code += 4;
  const size_t MAXB64 = 1400, MAXJSON = 1056;
  char *b64 = (char *)malloc(MAXB64 + 4);
  char *js = (char *)malloc(MAXJSON);
  bool ok = false;
  do {
    if (!b64 || !js) {
      _setErr("no memory");
      break;
    }
    size_t n = 0;
    for (const char *p = code; *p; p++) {   // base64url -> base64, χωρίς κενά
      char c = *p;
      if (c == ' ' || c == '\r' || c == '\n' || c == '=') continue;
      if (c == '-') c = '+';
      else if (c == '_') c = '/';
      if (n >= MAXB64) {
        n = 0;
        break;
      }
      b64[n++] = c;
    }
    if (n == 0) {
      _setErr("pairing code empty or too long");
      break;
    }
    while (n % 4) b64[n++] = '=';
    size_t olen = 0;
    if (mbedtls_base64_decode((unsigned char *)js, MAXJSON - 1, &olen, (const unsigned char *)b64, n) != 0) {
      _setErr("pairing code is not valid base64");
      break;
    }
    js[olen] = '\0';
    if (strlen(js) != olen) {   // NUL μέσα στο JSON: όχι
      _setErr("pairing code corrupt");
      break;
    }

    const char *v = jsonFind(js, "v");
    if (v && atoi(v) != 1) {
      _setErr("unsupported pairing code version");
      break;
    }
    char fp[128];
    if (!jsonReadStr(jsonFind(js, "id"), _id, sizeof(_id)) || !jsonReadStr(jsonFind(js, "t"), _token, sizeof(_token))
        || !jsonReadStr(jsonFind(js, "fp"), fp, sizeof(fp)) || !_id[0] || !_token[0]) {
      _setErr("pairing code incomplete (id/t/fp)");
      break;
    }
    for (const char *t = _token; *t; t++) {   // το token μπαίνει σε κεφαλίδα HTTP: μόνο «ασφαλείς» χαρακτήρες
      if (!(isalnum((unsigned char)*t) || *t == '-' || *t == '_' || *t == '.' || *t == '~')) {
        _token[0] = '\0';
        break;
      }
    }
    if (!_token[0]) {
      _setErr("pairing code: bad token");
      break;
    }
    if (!parseFingerprint(fp, _fp)) {
      _setErr("pairing code: bad certificate fingerprint");
      break;
    }
    if (!jsonReadStr(jsonFind(js, "k"), _kind, sizeof(_kind))) _kind[0] = '\0';

    const char *u = jsonFind(js, "u");
    if (u && *u == '[') {
      u = skipWs(u + 1);
      char url[96];
      while (*u == '"' && _nUrls < NW_MAX_URLS) {
        const char *next = jsonReadStr(u, url, sizeof(url));
        if (!next) break;
        if (parseUrl(url, _urls[_nUrls].host, sizeof(_urls[_nUrls].host), &_urls[_nUrls].port)) _nUrls++;
        u = skipWs(next);
        if (*u == ',') u = skipWs(u + 1);
      }
    }
    if (_nUrls == 0) {
      _setErr("pairing code: no usable https://host:port");
      break;
    }
    ok = true;
  } while (0);
  if (js) memset(js, 0, MAXJSON);   // μέσα ήταν το token
  free(js);
  free(b64);
  if (!ok) {
    _token[0] = '\0';
    return false;
  }
  _paired = true;
  _err[0] = '\0';
  _never = true;
  return true;
}

// =============================================================================
//  3. Ουρά γεγονότων
// =============================================================================

bool NwProbe::event(const char *type, const char *detail) {
  if (_qCount == NW_EVENT_QUEUE) {   // γεμάτη: χάνεται το παλαιότερο
    _qHead = (uint8_t)((_qHead + 1) % NW_EVENT_QUEUE);
    _qCount--;
    _qDropped++;
    if (_evInBody) _evInBody--;
  }
  Ev &e = _q[(_qHead + _qCount) % NW_EVENT_QUEUE];
  size_t o = 0;
  for (const char *p = type ? type : ""; *p && o + 1 < sizeof(e.type); p++) {
    char c = (char)tolower((unsigned char)*p);
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') e.type[o++] = c;
  }
  e.type[o] = '\0';
  if (o == 0) return false;
  strlcpy(e.detail, detail ? detail : "", sizeof(e.detail));
  // Αν κόπηκε στη μέση χαρακτήρα UTF-8, βγάλε το μισό κομμάτι.
  size_t dl = strlen(e.detail);
  if (detail && strlen(detail) > dl) {
    while (dl > 0 && ((unsigned char)e.detail[dl - 1] & 0xC0) == 0x80) dl--;
    if (dl > 0 && ((unsigned char)e.detail[dl - 1] & 0x80)) dl--;
    e.detail[dl] = '\0';
  }
  e.data[0] = '\0';
  e.ms = millis();
  _qCount++;
  _kick = true;
  return true;
}

// Προσθέτει  "key":<valueJson>  στο data του τελευταίου γεγονότος (ατομικά).
void NwProbe::_evAppend(const char *key, const char *valueJson) {
  if (_qCount == 0 || !key || !*key) return;
  for (const char *p = key; *p; p++)
    if (!(isalnum((unsigned char)*p) || *p == '_')) return;
  Ev &e = _q[(_qHead + _qCount - 1) % NW_EVENT_QUEUE];
  size_t used = strlen(e.data);
  size_t need = strlen(key) + strlen(valueJson) + 4;   // ,"key":value
  if (used + need + 16 >= sizeof(e.data)) return;      // +16: χώρος για το "ago"
  snprintf(e.data + used, sizeof(e.data) - used, "%s\"%s\":%s", used ? "," : "", key, valueJson);
}

void NwProbe::evStr(const char *key, const char *val) {
  char t[100];
  t[0] = '"';
  size_t n = nwJsonEscape(val, t + 1, sizeof(t) - 2);
  if (n == (size_t)-1) {   // πολύ μακρύ: κόψε το (ο server κρατά 60 χαρακτήρες)
    char cut[40];
    strlcpy(cut, val ? val : "", sizeof(cut));
    n = nwJsonEscape(cut, t + 1, sizeof(t) - 2);
    if (n == (size_t)-1) return;
  }
  t[n + 1] = '"';
  t[n + 2] = '\0';
  _evAppend(key, t);
}

void NwProbe::evNum(const char *key, double v, uint8_t decimals) {
  if (isnan(v) || isinf(v) || fabs(v) > 1e12) return;
  char t[32];
  snprintf(t, sizeof(t), "%.*f", decimals > 6 ? 6 : decimals, v);
  _evAppend(key, t);
}

void NwProbe::evInt(const char *key, long v) {
  char t[16];
  snprintf(t, sizeof(t), "%ld", v);
  _evAppend(key, t);
}

void NwProbe::evBool(const char *key, bool v) { _evAppend(key, v ? "true" : "false"); }

// =============================================================================
//  4. Σύνθεση αναφοράς
// =============================================================================

bool NwProbe::due() const {
  if (!_paired) return false;
  if (_never) return true;
  uint32_t el = millis() - _lastTry;
  if (el >= _waitMs) return true;
  return _kick && _fails == 0 && el >= KICK_MIN_GAP_MS;
}

NwJson &NwProbe::start(const char *ip, const char *mac, int rssi) {
  _j.reset();
  _rows = 0;
  _evInBody = 0;
  _phase = 1;
  _j.beginObject();
  _j.beginObject("status");
  _j.str("fw", _fw);
  _j.str("hw", _hw);
  if (ip && *ip) _j.str("ip", ip);
  if (mac && *mac) _j.str("mac", mac);
  _j.integer("uptime", (long)(millis() / 1000UL));
  _j.integer("heap", (long)ESP.getFreeHeap());
  if (rssi != 0) _j.integer("rssi", rssi);
  _j.integer("interval", _interval);
  return _j;
}

// "events":[…] από την ουρά. Όσα δεν χωρούν μένουν για την επόμενη αναφορά.
void NwProbe::_writeEvents() {
  _evInBody = 0;
  _j.beginArray("events");
  uint8_t max = _qCount < NW_MAX_EVENTS_POST ? _qCount : NW_MAX_EVENTS_POST;
  uint32_t now = millis();
  for (uint8_t i = 0; i < max; i++) {
    const Ev &e = _q[(_qHead + i) % NW_EVENT_QUEUE];
    NwJson::Mark m = _j.mark();
    bool ok = _j.beginObject();
    ok = ok && _j.str("type", e.type) && _j.str("detail", e.detail);
    ok = ok && _j.beginObject("data");
    if (ok) {
      // Τα πεδία data είναι ήδη έγκυρο JSON (φτιάχτηκαν από τα ev…()).
      // "ago": πόσα s πριν έγινε (ο server βάζει ώρα ΛΗΨΗΣ, όχι συμβάντος).
      char tail[24] = "";
      uint32_t ago = (now - e.ms) / 1000UL;
      if (ago >= 5) snprintf(tail, sizeof(tail), "%s\"ago\":%lu", e.data[0] ? "," : "", (unsigned long)ago);
      size_t dl = strlen(e.data), tl = strlen(tail);
      size_t room = _bodyCap - _j.length();
      if (dl + tl + JSON_RESERVE + 4 < room) {
        // γράψιμο «ωμό», κατευθείαν στο buffer του _j
        char *w = _body + _j.length();
        memcpy(w, e.data, dl);
        memcpy(w + dl, tail, tl + 1);
        NwJson::Mark m2 = _j.mark();
        m2.len += dl + tl;
        m2.first &= (uint8_t)~(1 << m2.depth);
        _j.rewind(m2);
      } else {
        ok = false;
      }
    }
    if (!ok) {
      _j.rewind(m);
      break;
    }
    _j.endObject();   // data
    _j.endObject();   // event
    _evInBody++;
  }
  _j.endArray();
  // Ένα γεγονός που δεν χωρά ΟΥΤΕ πρώτο δεν θα χωρέσει ποτέ: πέτα το, μην κολλήσει η ουρά.
  if (_evInBody == 0 && _qCount > 0 && max > 0) {
    _qHead = (uint8_t)((_qHead + 1) % NW_EVENT_QUEUE);
    _qCount--;
    _qDropped++;
  }
}

void NwProbe::items() {
  if (_phase != 1) return;
  _j.endObject();   // status
  _writeEvents();
  _j.beginArray("items");
  _phase = 2;
}

bool NwProbe::rowBegin() {
  if (_phase != 2 || _rows >= NW_MAX_ITEMS) return false;
  _rowMark = _j.mark();
  NwJson::Mark clean = _rowMark;
  clean.ovf = false;
  _j.rewind(clean);   // καθαρό overflow για να δούμε αν χώρεσε ΑΥΤΗ η γραμμή
  if (!_j.beginObject()) {
    _j.rewind(_rowMark);
    return false;
  }
  return true;
}

bool NwProbe::rowEnd() {
  if (_phase != 2) return false;
  if (_j.overflow()) {   // κάποιο πεδίο δεν χώρεσε: πέτα ΟΛΗ τη γραμμή
    _j.rewind(_rowMark);
    return false;
  }
  _j.endObject();
  _rows++;
  return true;
}

// =============================================================================
//  5. Αποστολή (HTTPS με pinning)
// =============================================================================

NwResult NwProbe::_post(const Url &u, size_t len) {
  NetworkClientSecure c;
  // setInsecure() = «μην ψάξεις αλυσίδα CA» (δεν υπάρχει: το πιστοποιητικό είναι
  // self-signed). Η ΤΑΥΤΟΤΗΤΑ ελέγχεται αμέσως μετά, με το αποτύπωμα SHA-256
  // ολόκληρου του πιστοποιητικού, ΠΡΙΝ φύγει έστω ένα byte (άρα και το token).
  c.setInsecure();
  c.setHandshakeTimeout(HANDSHAKE_TIMEOUT_S);
  IPAddress ip;
  int ok = ip.fromString(u.host) ? c.connect(ip, u.port, (int32_t)CONNECT_TIMEOUT_MS)
                                 : c.connect(u.host, u.port, (int32_t)CONNECT_TIMEOUT_MS);
  if (!ok) {
    _setErr("connect %s:%u failed", u.host, u.port);
    return NW_ERR_CONNECT;
  }
  uint8_t fp[32];
  if (!c.getFingerprintSHA256(fp)) {
    c.stop();
    _setErr("no peer certificate from %s", u.host);
    return NW_ERR_CONNECT;
  }
  uint8_t diff = 0;   // σύγκριση σταθερού χρόνου
  for (int i = 0; i < 32; i++) diff |= (uint8_t)(fp[i] ^ _fp[i]);
  if (diff) {
    c.stop();
    _setErr("CERT MISMATCH at %s - token NOT sent", u.host);
    return NW_ERR_PIN;
  }

  char head[360];
  int hn = snprintf(head, sizeof(head),
                    "POST /probe/v1/report HTTP/1.1\r\nHost: %s:%u\r\nAuthorization: Bearer %s\r\n"
                    "Content-Type: application/json\r\nContent-Length: %u\r\nConnection: close\r\n\r\n",
                    u.host, u.port, _token, (unsigned)len);
  if (hn <= 0 || hn >= (int)sizeof(head)) {
    c.stop();
    return NW_ERR_CONFIG;
  }
  bool wrote = c.write((const uint8_t *)head, (size_t)hn) == (size_t)hn;
  for (size_t off = 0; wrote && off < len;) {
    size_t n = len - off > 1024 ? 1024 : len - off;
    wrote = c.write((const uint8_t *)_body + off, n) == n;
    off += n;
  }
  memset(head, 0, sizeof(head));   // είχε μέσα το token
  if (!wrote) {
    c.stop();
    _setErr("write to %s failed", u.host);
    return NW_ERR_REPLY;
  }

  // Απάντηση: μικρή (status + ένα επίπεδο αντικείμενο JSON). Διαβάζουμε έως 511 bytes.
  char rsp[512];
  size_t got = 0;
  uint32_t t0 = millis();
  while (millis() - t0 < REPLY_TIMEOUT_MS && got + 1 < sizeof(rsp)) {
    if (c.available() > 0) {
      int n = c.read((uint8_t *)rsp + got, sizeof(rsp) - 1 - got);
      if (n > 0) {
        got += (size_t)n;
        rsp[got] = '\0';
        const char *b = strstr(rsp, "\r\n\r\n");
        if (b && strchr(b, '}')) break;
      }
    } else if (!c.connected()) {
      break;
    } else {
      delay(10);
    }
  }
  rsp[got] = '\0';
  c.stop();

  if (got < 12 || strncmp(rsp, "HTTP/1.", 7) != 0) {
    _setErr("no HTTP reply from %s", u.host);
    return NW_ERR_REPLY;
  }
  _http = atoi(rsp + 9);
  if (_http == 401 || _http == 403) {
    _setErr("HTTP %d: sensor unknown/removed - pair again", _http);
    return NW_ERR_AUTH;
  }
  if (_http != 200) {
    _setErr("HTTP %d", _http);
    return NW_ERR_HTTP;
  }
  const char *body = strstr(rsp, "\r\n\r\n");
  const char *iv = body ? strstr(body, "\"interval\"") : nullptr;
  if (iv) {
    iv = strchr(iv, ':');
    long v = iv ? atol(iv + 1) : 0;
    if (v >= 10 && v <= 3600) _interval = (uint16_t)v;   // το διάστημα το ορίζει ο server
  }
  return NW_OK;
}

NwResult NwProbe::send() {
  _lastTry = millis();
  _never = false;
  _http = 0;
  if (!_paired || !_body || _phase == 0) {
    _phase = 0;
    _waitMs = 60000;
    return NW_ERR_CONFIG;
  }
  if (_phase == 1) {
    _j.endObject();   // status
    _writeEvents();
  } else {
    _j.endArray();    // items
  }
  _j.endObject();     // ρίζα
  _phase = 0;
  size_t len = _j.length();

  NwResult res = NW_ERR_CONNECT;
  bool pinFail = false;
  uint32_t t0 = millis();
  for (uint8_t i = 0; i < _nUrls; i++) {
    if (i > 0 && millis() - t0 > SEND_BUDGET_MS) break;
    nwWatchdogFeed();
    NwResult r = _post(_urls[i], len);
    nwWatchdogFeed();
    if (r == NW_ERR_PIN) pinFail = true;
    if (r == NW_OK || r == NW_ERR_AUTH || r == NW_ERR_HTTP) {   // μίλησε ο σωστός server
      if (i > 0) {   // θυμήσου ποια διεύθυνση δούλεψε
        Url w = _urls[i];
        for (uint8_t k = i; k > 0; k--) _urls[k] = _urls[k - 1];
        _urls[0] = w;
      }
      res = r;
      break;
    }
    res = r;
  }
  if (res != NW_OK && res != NW_ERR_AUTH && res != NW_ERR_HTTP && pinFail) res = NW_ERR_PIN;

  if (res == NW_OK) {
    for (uint8_t i = 0; i < _evInBody && _qCount > 0; i++) {   // αυτά έφυγαν
      _qHead = (uint8_t)((_qHead + 1) % NW_EVENT_QUEUE);
      _qCount--;
    }
    _fails = 0;
    _err[0] = '\0';
    _waitMs = (uint32_t)_interval * 1000UL;
    _kick = _qCount > 0;   // έμειναν κι άλλα γεγονότα: στείλ' τα σύντομα
  } else {
    if (_fails < 10) _fails++;
    uint32_t s = BACKOFF_FIRST_S << (_fails > 6 ? 6 : (_fails - 1));   // 5,10,20,40,80,160,320
    if (res == NW_ERR_AUTH && s < 60) s = 60;                          // μη σφυροκοπάς με λάθος token
    if (s > BACKOFF_MAX_S) s = BACKOFF_MAX_S;
    _waitMs = s * 1000UL + (esp_random() % 1000);                      // + λίγο τυχαίο (jitter)
  }
  _evInBody = 0;
  return res;
}

// =============================================================================
//  6. Wi-Fi / watchdog
// =============================================================================

bool nwWifiConnect(const char *ssid, const char *pass, uint32_t timeoutMs) {
  static uint32_t lastBegin = 0;
  static bool begun = false;
  if (WiFi.status() == WL_CONNECTED) return true;
  if (!begun || millis() - lastBegin > 30000) {   // μην ξαναρχίζεις τη σύνδεση πάνω σε μια που εξελίσσεται
    WiFi.persistent(false);                        // μην γράφεις τον κωδικό στη flash σε κάθε σύνδεση
    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(true);
    WiFi.begin(ssid, pass);
    begun = true;
    lastBegin = millis();
  }
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < timeoutMs) {
    delay(100);
    nwWatchdogFeed();
  }
  return WiFi.status() == WL_CONNECTED;
}

void nwWifiMac(char *out, size_t len) {
  uint8_t m[6] = {0};
  WiFi.macAddress(m);
  snprintf(out, len, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void nwWatchdog(uint32_t seconds) {
  esp_task_wdt_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.timeout_ms = (seconds < 30 ? 30 : seconds) * 1000UL;   // < 30 s δεν φτάνει για ένα TLS handshake που αργεί
  cfg.idle_core_mask = 1;                                     // όπως η προεπιλογή του πυρήνα (idle task CPU0)
  cfg.trigger_panic = true;
  esp_task_wdt_reconfigure(&cfg);
  enableLoopWDT();
  s_wdt = true;
}

void nwWatchdogFeed() {
  if (s_wdt) feedLoopWDT();
}
