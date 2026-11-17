// =============================================================================
//  NetWatch - signed_ota_core.h
// -----------------------------------------------------------------------------
//  Το "καθαρό" κομμάτι του signed OTA: έκδοση, αυστηρός parser του manifest,
//  και το κείμενο που υπογράφεται. ΚΑΜΙΑ εξάρτηση από Arduino/ESP-IDF, ώστε
//  να μεταγλωττίζεται ΚΑΙ στον υπολογιστή: το tests/test_ota.py το χτίζει με
//  τον C++ compiler του συστήματος και ελέγχει ότι παράγει byte-προς-byte το
//  ίδιο κείμενο με το tools/ota/ota_sign.py (άρα η υπογραφή που φτιάχνει το
//  Python επαληθεύεται στη συσκευή).
// =============================================================================
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

namespace signed_ota_core {

static const size_t CLASS_MAX   = 24;
static const size_t VER_MAX     = 17;    // "65535.65535.65535"
static const size_t SIG_B64_MAX = 128;   // DER ECDSA P-256 <= 72 bytes -> <= 96 base64
static const char   STATEMENT_MAGIC[] = "netwatch-ota/1";

static inline void copyStr(char *out, size_t len, const char *in) {
  if (!len) return;
  size_t i = 0;
  for (; in && in[i] && i + 1 < len; i++) out[i] = in[i];
  out[i] = '\0';
}

// "MAJOR.MINOR.PATCH", μόνο ψηφία, κάθε μέρος <= 65535, χωρίς μηδενικά μπροστά
// (το "01.2.3" απορρίπτεται, όπως και στο ota_sign.py), μήκος <= VER_MAX.
static inline bool parseVersion(const char *s, uint32_t out[3]) {
  if (!s || strlen(s) > VER_MAX) return false;
  for (int part = 0; part < 3; part++) {
    if (*s < '0' || *s > '9') return false;
    if (*s == '0' && s[1] >= '0' && s[1] <= '9') return false;   // μηδενικό μπροστά
    uint32_t v = 0;
    int digits = 0;
    while (*s >= '0' && *s <= '9') {
      v = v * 10 + (uint32_t)(*s - '0');
      if (++digits > 5 || v > 65535) return false;
      s++;
    }
    out[part] = v;
    if (part < 2) {
      if (*s != '.') return false;
      s++;
    }
  }
  return *s == '\0';
}

// <0, 0, >0 όπως το strcmp
static inline int compareVersion(const uint32_t a[3], const uint32_t b[3]) {
  for (int i = 0; i < 3; i++)
    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

static inline bool validClass(const char *s) {
  const size_t n = strlen(s);
  if (n == 0 || n > CLASS_MAX) return false;
  for (size_t i = 0; i < n; i++) {
    const char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
  }
  return true;
}

static inline bool validSha256Hex(const char *s) {
  if (strlen(s) != 64) return false;
  for (size_t i = 0; i < 64; i++) {
    const char c = s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

// =============================================================================
//  Αυστηρός parser για το (επίπεδο) manifest.json
// -----------------------------------------------------------------------------
//  Δεν εμπιστευόμαστε τον server: ο parser δέχεται ΜΟΝΟ ένα αντικείμενο
//  {"key": "string" | ακέραιος, ...}, χωρίς escapes, nested αντικείμενα ή
//  πίνακες, με όρια σε κάθε μήκος. Ό,τι άλλο -> απόρριψη. (Ακόμα κι αν
//  κάποιος "ξεγελούσε" τον parser, η υπογραφή ελέγχεται πάνω στις τιμές
//  που διαβάστηκαν, άρα δεν θα περνούσε.)
// =============================================================================
struct Manifest {
  uint32_t format;
  char     cls[CLASS_MAX + 1];
  char     version[VER_MAX + 1];
  uint32_t size;
  char     sha256[65];
  char     sig[SIG_B64_MAX + 1];
  bool     hasFormat, hasCls, hasVersion, hasSize, hasSha, hasSig;
};

static inline const char *skipWs(const char *p) {
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
  return p;
}

// Διαβάζει "..." χωρίς escapes. Επιστρέφει τη θέση μετά το κλείσιμο ή nullptr.
static inline const char *readString(const char *p, char *out, size_t len, bool *tooLong) {
  if (*p != '"') return nullptr;
  p++;
  size_t n = 0;
  *tooLong = false;
  while (*p && *p != '"') {
    const unsigned char c = (unsigned char)*p;
    if (c == '\\' || c < 0x20 || c > 0x7E) return nullptr;   // κανένα escape / μη-ASCII
    if (n + 1 < len) out[n++] = (char)c;
    else *tooLong = true;
    p++;
  }
  if (*p != '"') return nullptr;
  out[n] = '\0';
  return p + 1;
}

// Το ίδιο κλειδί δύο φορές -> απόρριψη (αλλιώς ποιο ισχύει;).
static inline bool parseManifest(const char *json, Manifest &m) {
  memset(&m, 0, sizeof m);
  const char *p = skipWs(json);
  if (*p++ != '{') return false;
  for (int fields = 0; fields < 16; fields++) {
    char key[16];
    bool tooLong = false;
    p = readString(skipWs(p), key, sizeof key, &tooLong);
    if (!p) return false;
    const bool knownKey = !tooLong;
    p = skipWs(p);
    if (*p++ != ':') return false;
    p = skipWs(p);

    if (*p == '"') {
      char val[SIG_B64_MAX + 1];
      p = readString(p, val, sizeof val, &tooLong);
      if (!p || tooLong) return false;
      if (knownKey) {
        if (!strcmp(key, "class")) {
          if (m.hasCls || strlen(val) > CLASS_MAX) return false;
          copyStr(m.cls, sizeof m.cls, val);
          m.hasCls = true;
        } else if (!strcmp(key, "version")) {
          if (m.hasVersion || strlen(val) > VER_MAX) return false;
          copyStr(m.version, sizeof m.version, val);
          m.hasVersion = true;
        } else if (!strcmp(key, "sha256")) {
          if (m.hasSha || strlen(val) != 64) return false;
          copyStr(m.sha256, sizeof m.sha256, val);
          m.hasSha = true;
        } else if (!strcmp(key, "sig")) {
          if (m.hasSig) return false;
          copyStr(m.sig, sizeof m.sig, val);
          m.hasSig = true;
        }
      }
    } else if (*p >= '0' && *p <= '9') {
      uint64_t v = 0;
      int digits = 0;
      while (*p >= '0' && *p <= '9') {
        v = v * 10 + (uint64_t)(*p++ - '0');
        if (++digits > 10) return false;
      }
      if (v > 0xFFFFFFFFULL) return false;
      if (knownKey && !strcmp(key, "size")) {
        if (m.hasSize) return false;
        m.size = (uint32_t)v;
        m.hasSize = true;
      } else if (knownKey && !strcmp(key, "format")) {
        if (m.hasFormat) return false;
        m.format = (uint32_t)v;
        m.hasFormat = true;
      }
    } else {
      return false;   // true/false/null/αρνητικοί/αντικείμενα/πίνακες: όχι στο δικό μας manifest
    }

    p = skipWs(p);
    if (*p == ',') { p++; continue; }
    if (*p == '}') {
      p = skipWs(p + 1);
      return *p == '\0' && m.hasFormat && m.hasCls && m.hasVersion && m.hasSize && m.hasSha && m.hasSig;
    }
    return false;
  }
  return false;   // υπερβολικά πολλά πεδία
}

// Το κείμενο που υπογράφεται. ΙΔΙΑ μορφή με το statement() του tools/ota/ota_sign.py:
//   "netwatch-ota/1\n<class>\n<version>\n<size>\n<sha256 hex>\n"
// Επιστρέφει το μήκος (όπως το snprintf).
static inline int buildStatement(char *out, size_t len, const Manifest &m) {
  return snprintf(out, len, "%s\n%s\n%s\n%lu\n%s\n", STATEMENT_MAGIC, m.cls, m.version,
                  (unsigned long)m.size, m.sha256);
}

}  // namespace signed_ota_core
