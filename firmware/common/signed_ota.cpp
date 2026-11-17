// =============================================================================
//  NetWatch - signed_ota.cpp  (βλ. signed_ota.h για την περιγραφή)
// -----------------------------------------------------------------------------
//  Σειρά ελέγχων (κάθε βήμα που αποτυγχάνει σταματά ΑΜΕΣΩΣ):
//
//    1. GET <base>/<class>/manifest.json  (HTTPS, μόνο η δική μας CA, χωρίς redirects)
//    2. Ανάλυση manifest (αυστηρή: μόνο strings/αριθμοί, όρια μεγέθους)
//    3. Κατηγορία == deviceClass, έκδοση ΑΥΣΤΗΡΑ μεγαλύτερη από την τρέχουσα
//       ΚΑΙ από την υψηλότερη επιβεβαιωμένη (NVS), όχι έκδοση που απέτυχε
//    4. Υπογραφή ECDSA P-256 πάνω στο "signed statement" (περιέχει size+sha256)
//       -> ελέγχεται ΠΡΙΝ γραφτεί το παραμικρό στη flash
//    5. GET <base>/<class>/<version>.bin, ροή στο ανενεργό OTA partition με
//       Update, ενώ υπολογίζεται SHA-256 (mbedtls)
//    6. sha256 == υπογεγραμμένο sha256 και bytes == υπογεγραμμένο size,
//       ΜΟΝΟ ΤΟΤΕ Update.end() (που κάνει το partition bootable) + restart
//
//  Γιατί δεν μένει ποτέ "μισό" bootable image: η Update κρατά τα πρώτα 16
//  bytes (μαζί με το magic byte 0xE9 της κεφαλίδας) στη RAM και τα γράφει
//  μόνο στο end(). Επίσης το boot partition αλλάζει ΜΟΝΟ στο end(). Σε
//  οποιοδήποτε σφάλμα καλούμε Update.abort() και η συσκευή συνεχίζει με
//  το τρέχον firmware σαν να μην έγινε τίποτα.
// =============================================================================
#include "signed_ota.h"
#include "signed_ota_core.h"

#include <memory>
#include <new>
#include <stdarg.h>
#include <string.h>

#include <HTTPClient.h>
#include <NetworkClientSecure.h>
#include <Preferences.h>
#include <Update.h>
#include <esp_ota_ops.h>

#include <mbedtls/base64.h>
#include <mbedtls/build_info.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include <psa/crypto.h>
#endif

using namespace signed_ota_core;

// -----------------------------------------------------------------------------
//  Σταθερές
// -----------------------------------------------------------------------------
static const char   NVS_NS[]          = "signedota";   // namespace στο NVS (<= 15 χαρακτήρες)
static const size_t MANIFEST_MAX      = 1024;          // το δικό μας είναι ~250 bytes
static const size_t URL_MAX           = 192;
static const size_t SIG_DER_MAX       = 80;
static const size_t CHUNK             = 2048;

// -----------------------------------------------------------------------------
//  Κατάσταση
// -----------------------------------------------------------------------------
static SignedOtaStatus g_last = {SignedOtaResult::None, "", ""};
static SignedOtaStatus g_report = {SignedOtaResult::None, "", ""};
static bool g_reportReady = false;
static bool g_pendingVerify = false;   // το τρέχον image περιμένει self-test (rollback)
static bool g_begun = false;
static char g_current[VER_MAX + 1] = "";

// -----------------------------------------------------------------------------
//  Rollback: λέμε στον Arduino core να ΜΗΝ επιβεβαιώσει αυτόματα το νέο image
//  στην εκκίνηση (η προεπιλογή του κάνει "valid" αμέσως). Το επιβεβαιώνουμε
//  εμείς στο signedOtaMarkHealthy(), όταν περάσει το self-test. Αν η συσκευή
//  κάνει reset πριν από αυτό (crash, watchdog, ρεύμα), ο bootloader γυρίζει
//  στο προηγούμενο firmware (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y στον core).
// -----------------------------------------------------------------------------
extern "C" bool verifyRollbackLater() { return true; }

// =============================================================================
//  Βοηθητικά
// =============================================================================
const char *signedOtaResultName(SignedOtaResult r) {
  switch (r) {
    case SignedOtaResult::UpToDate: return "up_to_date";
    case SignedOtaResult::Updated:  return "updated";
    case SignedOtaResult::Rejected: return "rejected";
    case SignedOtaResult::Error:    return "error";
    default:                        return "none";
  }
}

static void setStatus(SignedOtaStatus &st, SignedOtaResult r, const char *version, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static void setStatus(SignedOtaStatus &st, SignedOtaResult r, const char *version, const char *fmt, ...) {
  st.result = r;
  copyStr(st.version, sizeof st.version, version ? version : "");
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(st.reason, sizeof st.reason, fmt, ap);
  va_end(ap);
}

static void toHex(const uint8_t *in, size_t n, char *out) {
  static const char HEX_DIGITS[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i]     = HEX_DIGITS[in[i] >> 4];
    out[2 * i + 1] = HEX_DIGITS[in[i] & 0x0F];
  }
  out[2 * n] = '\0';
}

// =============================================================================
//  Κρυπτογραφία (mbedtls)
// =============================================================================

static bool sha256Of(const uint8_t *data, size_t n, uint8_t out[32]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  const bool ok = mbedtls_sha256_starts(&ctx, /*is224=*/0) == 0 &&
                  mbedtls_sha256_update(&ctx, data, n) == 0 &&
                  mbedtls_sha256_finish(&ctx, out) == 0;
  mbedtls_sha256_free(&ctx);
  return ok;
}

// ECDSA P-256: mbedtls_pk_verify(MBEDTLS_MD_SHA256, hash 32 bytes, υπογραφή DER).
// Επιστρέφει 0 = έγκυρη, αλλιώς σύντομο λόγο στο *why.
static bool verifySignature(const char *pubKeyPem, const uint8_t hash[32], const uint8_t *sig,
                            size_t sigLen, const char **why) {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
  if (psa_crypto_init() != PSA_SUCCESS) { *why = "psa init failed"; return false; }
#endif
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  bool ok = false;
  // Για PEM το μήκος πρέπει να περιλαμβάνει και το τελικό '\0'.
  if (mbedtls_pk_parse_public_key(&pk, (const unsigned char *)pubKeyPem, strlen(pubKeyPem) + 1) != 0) {
    *why = "invalid OTA public key (check OTA_PUBKEY_PEM)";
  } else if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA) || !mbedtls_pk_ec(pk) ||
             mbedtls_ecp_keypair_get_group_id(mbedtls_pk_ec(pk)) != MBEDTLS_ECP_DP_SECP256R1) {
    *why = "OTA public key is not ECDSA P-256";
  } else if (mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, sigLen) != 0) {
    *why = "bad signature";
  } else {
    ok = true;
  }
  mbedtls_pk_free(&pk);
  return ok;
}

// =============================================================================
//  NVS: υψηλότερη επιβεβαιωμένη έκδοση, εκκρεμές update, έκδοση που απέτυχε
// -----------------------------------------------------------------------------
//    max   υψηλότερη έκδοση που ΤΡΕΞΕ και πέρασε το self-test (anti-rollback)
//    pend  έκδοση που γράφτηκε με OTA και περιμένει την πρώτη εκκίνηση
//    prev  η έκδοση από την οποία έγινε το update (για την αναφορά)
//    bad   έκδοση που γράφτηκε αλλά ΔΕΝ πέρασε το self-test (δεν ξαναδοκιμάζεται)
// =============================================================================
static void nvsGet(Preferences &p, const char *key, char *out, size_t len) {
  out[0] = '\0';
  if (p.isKey(key)) p.getString(key, out, len);
}

// max = max(max, v). Ποτέ δεν μειώνεται.
static void raiseMax(Preferences &p, const char *v) {
  uint32_t nv[3], mv[3];
  if (!parseVersion(v, nv)) return;
  char cur[VER_MAX + 1];
  nvsGet(p, "max", cur, sizeof cur);
  if (!parseVersion(cur, mv) || compareVersion(nv, mv) > 0) p.putString("max", v);
}

static bool runningImagePending() {
  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_img_states_t state;
  return running && esp_ota_get_state_partition(running, &state) == ESP_OK &&
         state == ESP_OTA_IMG_PENDING_VERIFY;
}

void signedOtaBegin(const char *currentVersion) {
  if (g_begun) return;
  g_begun = true;
  copyStr(g_current, sizeof g_current, currentVersion);
  g_pendingVerify = runningImagePending();

  Preferences p;
  if (!p.begin(NVS_NS, /*readOnly=*/false)) {
    Serial.println("[ota] NVS open FAILED");
    return;
  }
  char pend[VER_MAX + 1], prev[VER_MAX + 1], maxv[VER_MAX + 1];
  nvsGet(p, "pend", pend, sizeof pend);
  nvsGet(p, "prev", prev, sizeof prev);

  if (pend[0] && strcmp(pend, g_current) != 0) {
    // Γράψαμε την pend αλλά τρέχει ΑΛΛΗ έκδοση: το νέο image δεν πέρασε το
    // self-test (ή δεν ξεκίνησε καν) και ο bootloader γύρισε πίσω.
    p.putString("bad", pend);
    p.remove("pend");
    p.remove("prev");
    setStatus(g_report, SignedOtaResult::Rejected, pend,
              "%s failed self-test, rolled back to %s", pend, g_current);
    g_reportReady = true;
    Serial.printf("[ota] ROLLBACK: %s did not pass self-test, running %s again\n", pend, g_current);
  } else if (pend[0] && !g_pendingVerify) {
    // Ίδια έκδοση με την pend, αλλά το image δεν είναι "υπό δοκιμή" (π.χ.
    // core χωρίς rollback). Το θεωρούμε επιβεβαιωμένο.
    p.remove("pend");
    p.remove("prev");
    setStatus(g_report, SignedOtaResult::Updated, g_current, "%s -> %s", prev[0] ? prev : "?", g_current);
    g_reportReady = true;
  }
  if (!g_pendingVerify) raiseMax(p, g_current);
  nvsGet(p, "max", maxv, sizeof maxv);
  p.end();

  Serial.printf("[ota] fw %s, highest confirmed %s%s\n", g_current, maxv[0] ? maxv : "-",
                g_pendingVerify ? ", NEW IMAGE PENDING SELF-TEST" : "");
}

void signedOtaMarkHealthy() {
  if (!g_pendingVerify) return;
  g_pendingVerify = false;
  if (esp_ota_mark_app_valid_cancel_rollback() != ESP_OK) {
    Serial.println("[ota] mark valid FAILED");
  }
  Preferences p;
  if (p.begin(NVS_NS, false)) {
    char prev[VER_MAX + 1];
    nvsGet(p, "prev", prev, sizeof prev);
    raiseMax(p, g_current);   // από εδώ και πέρα, τίποτα παλαιότερο από αυτή
    p.remove("pend");
    p.remove("prev");
    p.end();
    setStatus(g_report, SignedOtaResult::Updated, g_current, "%s -> %s", prev[0] ? prev : "?", g_current);
    g_reportReady = true;
  }
  Serial.printf("[ota] self-test passed, %s is now permanent\n", g_current);
}

void signedOtaSelfTestTick(uint32_t timeoutS) {
  if (!g_pendingVerify) return;
  if (millis() / 1000UL < timeoutS) return;
  Serial.printf("[ota] self-test not passed within %lus, rolling back\n", (unsigned long)timeoutS);
  Serial.flush();
  esp_ota_mark_app_invalid_rollback_and_reboot();   // δεν επιστρέφει αν υπάρχει παλιό image
  // Δεν υπάρχει έγκυρο προηγούμενο image (π.χ. πρώτο flash): δεν έχουμε πού
  // να γυρίσουμε, άρα κρατάμε αυτό.
  Serial.println("[ota] no previous image to roll back to, keeping this one");
  g_pendingVerify = false;
  esp_ota_mark_app_valid_cancel_rollback();
}

bool signedOtaTakeReport(SignedOtaStatus &out) {
  if (!g_reportReady) return false;
  out = g_report;
  g_reportReady = false;
  return true;
}

const SignedOtaStatus &signedOtaLastStatus() { return g_last; }

// =============================================================================
//  HTTPS
// =============================================================================
static void setupHttp(HTTPClient &http, NetworkClientSecure &tls, const char *caPem) {
  tls.setCACert(caPem);                       // ΜΟΝΟ server υπογεγραμμένος από τη δική μας CA
  tls.setHandshakeTimeout(15);                // δευτερόλεπτα
  http.setConnectTimeout(10000);
  http.setTimeout((uint16_t)(SIGNED_OTA_IDLE_MS > 65000UL ? 65000UL : SIGNED_OTA_IDLE_MS));
  http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);   // κανένα redirect αλλού
  http.useHTTP10(true);                       // όχι chunked: σταθερό Content-Length
  http.setReuse(false);
  http.setUserAgent("netwatch-ota/1");
}

// Διαβάζει ακριβώς n bytes (ή λιγότερα αν κλείσει η σύνδεση) με όρια χρόνου.
// Καλεί onData για κάθε κομμάτι. Επιστρέφει πόσα bytes διαβάστηκαν.
template <typename F>
static size_t readBody(HTTPClient &http, size_t n, uint8_t *buf, size_t bufLen, uint32_t deadlineMs, F onData) {
  NetworkClient *s = http.getStreamPtr();
  if (!s) return 0;
  size_t got = 0;
  uint32_t lastData = millis();
  while (got < n) {
    const int avail = s->available();
    if (avail > 0) {
      size_t want = n - got;
      if (want > bufLen) want = bufLen;
      if (want > (size_t)avail) want = (size_t)avail;
      const int r = s->read(buf, want);
      if (r <= 0) break;
      if (!onData(buf, (size_t)r)) break;
      got += (size_t)r;
      lastData = millis();
      continue;
    }
    if (!s->connected()) break;
    if (millis() - lastData > SIGNED_OTA_IDLE_MS) break;
    if ((int32_t)(millis() - deadlineMs) > 0) break;
    delay(5);   // παραχώρηση στα tasks Wi-Fi/TLS
  }
  return got;
}

// =============================================================================
//  Ο έλεγχος
// =============================================================================
#define FAIL(res, ver, ...)                          \
  do {                                               \
    setStatus(g_last, (res), (ver), __VA_ARGS__);    \
    Serial.printf("[ota] %s: %s\n", signedOtaResultName(g_last.result), g_last.reason); \
    return false;                                    \
  } while (0)

bool signedOtaCheck(const char *baseUrl, const char *deviceClass, const char *currentVersion,
                    const char *caPem, const char *pubKeyPem) {
  const uint32_t deadline = millis() + SIGNED_OTA_TOTAL_MS;
  if (!g_begun) signedOtaBegin(currentVersion);

  // --- 0. Ρυθμίσεις -----------------------------------------------------------
  uint32_t cur[3];
  if (!baseUrl || !deviceClass || !caPem || !pubKeyPem || !parseVersion(currentVersion, cur) ||
      !validClass(deviceClass) || strncmp(baseUrl, "https://", 8) != 0)
    FAIL(SignedOtaResult::Error, "", "bad configuration (https:// URL, class, x.y.z version)");
  if (g_pendingVerify)
    FAIL(SignedOtaResult::Error, "", "current image not confirmed yet, skipping check");

  size_t baseLen = strlen(baseUrl);
  while (baseLen && baseUrl[baseLen - 1] == '/') baseLen--;
  char url[URL_MAX];
  int n = snprintf(url, sizeof url, "%.*s/%s/manifest.json", (int)baseLen, baseUrl, deviceClass);
  if (n < 0 || (size_t)n >= sizeof url) FAIL(SignedOtaResult::Error, "", "URL too long");

  // --- 1. manifest.json -------------------------------------------------------
  static char manifestBuf[MANIFEST_MAX + 1];   // static: όχι 1 KB στη στοίβα του loop
  size_t mlen = 0;
  {
    NetworkClientSecure tls;
    HTTPClient http;
    setupHttp(http, tls, caPem);
    if (!http.begin(tls, url)) FAIL(SignedOtaResult::Error, "", "manifest: bad URL");
    const int code = http.GET();
    if (code != HTTP_CODE_OK) {
      http.end();
      if (code < 0) FAIL(SignedOtaResult::Error, "", "manifest: %s (TLS/CA/SAN?)", HTTPClient::errorToString(code).c_str());
      FAIL(SignedOtaResult::Error, "", "manifest: HTTP %d", code);
    }
    const int size = http.getSize();
    if (size <= 0 || (size_t)size > MANIFEST_MAX) {
      http.end();
      FAIL(SignedOtaResult::Rejected, "", "manifest: bad size %d", size);
    }
    mlen = readBody(http, (size_t)size, (uint8_t *)manifestBuf, MANIFEST_MAX, deadline,
                    [](const uint8_t *, size_t) { return true; });
    http.end();
    if (mlen != (size_t)size) FAIL(SignedOtaResult::Error, "", "manifest: short read");
  }
  manifestBuf[mlen] = '\0';
  if (strlen(manifestBuf) != mlen) FAIL(SignedOtaResult::Rejected, "", "manifest: NUL byte");

  Manifest m;
  if (!parseManifest(manifestBuf, m)) FAIL(SignedOtaResult::Rejected, "", "manifest: malformed");

  // --- 2. Κατηγορία / έκδοση (anti-rollback) -----------------------------------
  uint32_t offered[3];
  if (m.format != 1) FAIL(SignedOtaResult::Rejected, "", "manifest: unknown format %lu", (unsigned long)m.format);
  if (!parseVersion(m.version, offered)) FAIL(SignedOtaResult::Rejected, "", "manifest: bad version");
  if (strcmp(m.cls, deviceClass) != 0) FAIL(SignedOtaResult::Rejected, m.version, "class mismatch (not for %s)", deviceClass);

  const int vsCurrent = compareVersion(offered, cur);
  if (vsCurrent == 0) {
    setStatus(g_last, SignedOtaResult::UpToDate, m.version, "running %s", currentVersion);
    Serial.printf("[ota] up to date (%s)\n", currentVersion);
    return true;
  }
  if (vsCurrent < 0)
    FAIL(SignedOtaResult::Rejected, m.version, "rollback refused: %s is older than %s", m.version, currentVersion);

  char maxv[VER_MAX + 1] = "", bad[VER_MAX + 1] = "";
  {
    Preferences p;
    if (p.begin(NVS_NS, /*readOnly=*/true)) {
      nvsGet(p, "max", maxv, sizeof maxv);
      nvsGet(p, "bad", bad, sizeof bad);
      p.end();
    }
  }
  uint32_t mv[3];
  if (parseVersion(maxv, mv) && compareVersion(offered, mv) <= 0)
    FAIL(SignedOtaResult::Rejected, m.version, "rollback refused: not newer than installed %s", maxv);
  if (bad[0] && strcmp(bad, m.version) == 0)
    FAIL(SignedOtaResult::Rejected, m.version, "%s failed self-test before, waiting for a newer one", m.version);

  // --- 3. Μέγεθος / μορφή -------------------------------------------------------
  const esp_partition_t *target = esp_ota_get_next_update_partition(nullptr);
  if (!target) FAIL(SignedOtaResult::Error, m.version, "no OTA partition (partition scheme?)");
  if (m.size < 1024 || m.size > target->size)
    FAIL(SignedOtaResult::Rejected, m.version, "bad size %lu (partition %lu)", (unsigned long)m.size,
         (unsigned long)target->size);
  if (!validSha256Hex(m.sha256)) FAIL(SignedOtaResult::Rejected, m.version, "manifest: bad sha256");

  // --- 4. Υπογραφή: ΠΡΙΝ από οποιαδήποτε εγγραφή στη flash -----------------------
  uint8_t sig[SIG_DER_MAX];
  size_t sigLen = 0;
  if (mbedtls_base64_decode(sig, sizeof sig, &sigLen, (const unsigned char *)m.sig, strlen(m.sig)) != 0 || sigLen < 8)
    FAIL(SignedOtaResult::Rejected, m.version, "manifest: bad sig encoding");

  char statement[160];
  n = buildStatement(statement, sizeof statement, m);
  if (n < 0 || (size_t)n >= sizeof statement) FAIL(SignedOtaResult::Rejected, m.version, "statement too long");
  uint8_t stHash[32];
  if (!sha256Of((const uint8_t *)statement, (size_t)n, stHash)) FAIL(SignedOtaResult::Error, m.version, "sha256 failed");
  const char *why = "";
  if (!verifySignature(pubKeyPem, stHash, sig, sigLen, &why)) {
    if (strncmp(why, "bad", 3) == 0) FAIL(SignedOtaResult::Rejected, m.version, "%s", why);
    FAIL(SignedOtaResult::Error, m.version, "%s", why);
  }
  Serial.printf("[ota] manifest OK: %s %s, %lu bytes, signature valid\n", m.cls, m.version, (unsigned long)m.size);

  // --- 5. Λήψη + εγγραφή + SHA-256 -------------------------------------------------
  n = snprintf(url, sizeof url, "%.*s/%s/%s.bin", (int)baseLen, baseUrl, deviceClass, m.version);
  if (n < 0 || (size_t)n >= sizeof url) FAIL(SignedOtaResult::Error, m.version, "URL too long");

  std::unique_ptr<uint8_t[]> buf(new (std::nothrow) uint8_t[CHUNK]);
  if (!buf) FAIL(SignedOtaResult::Error, m.version, "out of memory");

  NetworkClientSecure tls;
  HTTPClient http;
  setupHttp(http, tls, caPem);
  if (!http.begin(tls, url)) FAIL(SignedOtaResult::Error, m.version, "firmware: bad URL");
  const int code = http.GET();
  if (code != HTTP_CODE_OK) {
    http.end();
    if (code < 0) FAIL(SignedOtaResult::Error, m.version, "firmware: %s", HTTPClient::errorToString(code).c_str());
    FAIL(SignedOtaResult::Error, m.version, "firmware: HTTP %d", code);
  }
  if (http.getSize() != (int)m.size) {
    http.end();
    FAIL(SignedOtaResult::Rejected, m.version, "firmware: size %d != signed %lu", http.getSize(), (unsigned long)m.size);
  }
  if (!Update.begin(m.size, U_FLASH)) {
    http.end();
    FAIL(SignedOtaResult::Error, m.version, "Update.begin: %s", Update.errorString());
  }
  Serial.printf("[ota] downloading %s ...\n", url);

  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  bool hashOk = mbedtls_sha256_starts(&sha, 0) == 0;
  bool writeOk = true;
  const size_t got = readBody(http, m.size, buf.get(), CHUNK, deadline, [&](const uint8_t *d, size_t len) {
    if (mbedtls_sha256_update(&sha, d, len) != 0) hashOk = false;
    if (Update.write(const_cast<uint8_t *>(d), len) != len) writeOk = false;
    return hashOk && writeOk;
  });
  uint8_t digest[32];
  if (mbedtls_sha256_finish(&sha, digest) != 0) hashOk = false;
  mbedtls_sha256_free(&sha);
  http.end();

  if (!writeOk) {
    Update.abort();
    FAIL(SignedOtaResult::Error, m.version, "flash write: %s", Update.errorString());
  }
  if (!hashOk) {
    Update.abort();
    FAIL(SignedOtaResult::Error, m.version, "sha256 failed");
  }
  if (got != m.size) {
    Update.abort();
    FAIL(SignedOtaResult::Error, m.version, "download incomplete (%lu/%lu)", (unsigned long)got, (unsigned long)m.size);
  }

  // --- 6. Σύγκριση με το ΥΠΟΓΕΓΡΑΜΜΕΝΟ sha256 ----------------------------------------
  char hex[65];
  toHex(digest, sizeof digest, hex);
  if (strcmp(hex, m.sha256) != 0) {
    Update.abort();
    FAIL(SignedOtaResult::Rejected, m.version, "sha256 mismatch: firmware differs from signed one");
  }
  // Όλα τα bytes γράφτηκαν (remaining == 0), άρα το end() εδώ ΔΕΝ χρειάζεται
  // "evenIfRemaining": αν για οποιονδήποτε λόγο λείπει κάτι, αποτυγχάνει.
  // Το end() ελέγχει επίσης το image (esp_ota_end) και ΜΟΝΟ τότε αλλάζει boot partition.
  if (!Update.end(/*evenIfRemaining=*/false)) {
    Update.abort();
    FAIL(SignedOtaResult::Error, m.version, "Update.end: %s", Update.errorString());
  }

  {
    Preferences p;
    if (p.begin(NVS_NS, false)) {
      p.putString("pend", m.version);
      p.putString("prev", currentVersion);
      p.end();
    }
  }
  setStatus(g_last, SignedOtaResult::Updated, m.version, "%s -> %s, rebooting", currentVersion, m.version);
  Serial.printf("[ota] installed %s (sha256 %.16s...), rebooting into it\n", m.version, hex);
  Serial.flush();
  delay(500);
  ESP.restart();
  return false;   // δεν φτάνει ποτέ εδώ
}
