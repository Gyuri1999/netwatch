// =============================================================================
//  NetWatch - nw_lora.h   (κοινό για το esp32-lora-node και το esp32-lora-gw)
// -----------------------------------------------------------------------------
//  1. Η μορφή του πακέτου LoRa (24 bytes) και η πιστοποίησή του (HMAC-SHA256).
//  2. Ελάχιστος οδηγός SX1276 / RFM95 πάνω σε ωμό SPI (χωρίς βιβλιοθήκη).
//  3. Υπολογισμός «χρόνου στον αέρα» (time-on-air) για τον κανόνα 1% (EU868).
//
//  Είναι LoRa ΣΗΜΕΙΟ-ΠΡΟΣ-ΣΗΜΕΙΟ, ΟΧΙ LoRaWAN: κανένα join, κανένας network
//  server. Ο κόμβος στέλνει, η πύλη ακούει. Δεν υπάρχει απάντηση (ACK).
//
//  ΠΑΚΕΤΟ (little-endian, 24 bytes):
//
//    θέση  μήκος  πεδίο
//    0     1      magic     0x4E ('N')
//    1     1      version   0x01
//    2     2      node      id κόμβου (1..65535)
//    4     4      seq       μετρητής που ΜΟΝΟ ανεβαίνει (προστασία από replay)
//    8     2      batt      mV (0 = δεν μετριέται)
//    10    2      temp      εκατοστά °C, προσημασμένο (0x7FFF = δεν υπάρχει)
//    12    1      hum       μισά % (0..200, 0xFF = δεν υπάρχει)
//    13    1      flags     NWL_F_…
//    14    2      interval  περίοδος του κόμβου σε s (η πύλη: «χάθηκε» μετά από 3x)
//    16    8      tag       τα πρώτα 8 bytes του HMAC-SHA256(key, bytes 0..15)
//
//  ΑΣΦΑΛΕΙΑ: το πακέτο είναι ΠΙΣΤΟΠΟΙΗΜΕΝΟ, όχι κρυπτογραφημένο. Όποιος ακούει
//  βλέπει θερμοκρασία/πόρτα· δεν μπορεί όμως να φτιάξει ή να αλλάξει πακέτο
//  χωρίς το κλειδί (tag 64 bit), ούτε να ξαναπαίξει παλιό (μετρητής seq).
// =============================================================================
#pragma once

#include <Arduino.h>
#include <SPI.h>
#include <mbedtls/md.h>

#define NWL_MAGIC    0x4E
#define NWL_VERSION  0x01
#define NWL_PKT_LEN  24
#define NWL_BODY_LEN 16
#define NWL_TAG_LEN  8
#define NWL_KEY_LEN  32

#define NWL_F_DOOR_OPEN 0x01   // η πόρτα είναι ανοιχτή ΤΩΡΑ
#define NWL_F_DOOR_EVT  0x02   // το πακέτο στάλθηκε επειδή άλλαξε η πόρτα
#define NWL_F_HAS_DOOR  0x04   // ο κόμβος έχει επαφή πόρτας
#define NWL_F_BOOT      0x08   // πρώτο πακέτο μετά από τροφοδοσία / reset
#define NWL_F_BATT_LOW  0x10   // ο κόμβος θεωρεί τη μπαταρία χαμηλή

#define NWL_TEMP_NONE 0x7FFF
#define NWL_HUM_NONE  0xFF

struct NwLoraPacket {
  uint16_t node;
  uint32_t seq;
  uint16_t battMv;
  int16_t tempC100;
  uint8_t humHalf;
  uint8_t flags;
  uint16_t intervalS;
};

// 64 δεκαεξαδικά ψηφία -> 32 bytes. false αν δεν είναι ακριβώς αυτό.
static inline bool nwLoraParseKey(const char *hex, uint8_t key[NWL_KEY_LEN]) {
  if (!hex || strlen(hex) != 2 * NWL_KEY_LEN) return false;
  for (int i = 0; i < NWL_KEY_LEN; i++) {
    int v = 0;
    for (int k = 0; k < 2; k++) {
      char c = hex[2 * i + k];
      int n = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
      if (n < 0) return false;
      v = (v << 4) | n;
    }
    key[i] = (uint8_t)v;
  }
  return true;
}

static inline bool nwLoraTag(const uint8_t key[NWL_KEY_LEN], const uint8_t *body, uint8_t tag[NWL_TAG_LEN]) {
  uint8_t mac[32];
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md || mbedtls_md_hmac(md, key, NWL_KEY_LEN, body, NWL_BODY_LEN, mac) != 0) return false;
  memcpy(tag, mac, NWL_TAG_LEN);
  return true;
}

static inline bool nwLoraEncode(const NwLoraPacket &p, const uint8_t key[NWL_KEY_LEN], uint8_t out[NWL_PKT_LEN]) {
  out[0] = NWL_MAGIC;
  out[1] = NWL_VERSION;
  out[2] = (uint8_t)(p.node & 0xFF);
  out[3] = (uint8_t)(p.node >> 8);
  out[4] = (uint8_t)(p.seq & 0xFF);
  out[5] = (uint8_t)((p.seq >> 8) & 0xFF);
  out[6] = (uint8_t)((p.seq >> 16) & 0xFF);
  out[7] = (uint8_t)((p.seq >> 24) & 0xFF);
  out[8] = (uint8_t)(p.battMv & 0xFF);
  out[9] = (uint8_t)(p.battMv >> 8);
  out[10] = (uint8_t)((uint16_t)p.tempC100 & 0xFF);
  out[11] = (uint8_t)((uint16_t)p.tempC100 >> 8);
  out[12] = p.humHalf;
  out[13] = p.flags;
  out[14] = (uint8_t)(p.intervalS & 0xFF);
  out[15] = (uint8_t)(p.intervalS >> 8);
  return nwLoraTag(key, out, out + NWL_BODY_LEN);
}

// Ελέγχει μήκος, magic, έκδοση και tag (σύγκριση σταθερού χρόνου). Ο έλεγχος του
// μετρητή seq (replay) είναι δουλειά της πύλης, που θυμάται τον τελευταίο ανά κόμβο.
static inline bool nwLoraDecode(const uint8_t *in, size_t len, const uint8_t key[NWL_KEY_LEN], NwLoraPacket &p) {
  if (len != NWL_PKT_LEN || in[0] != NWL_MAGIC || in[1] != NWL_VERSION) return false;
  uint8_t tag[NWL_TAG_LEN];
  if (!nwLoraTag(key, in, tag)) return false;
  uint8_t diff = 0;
  for (int i = 0; i < NWL_TAG_LEN; i++) diff |= (uint8_t)(tag[i] ^ in[NWL_BODY_LEN + i]);
  if (diff) return false;
  p.node = (uint16_t)(in[2] | (in[3] << 8));
  p.seq = (uint32_t)in[4] | ((uint32_t)in[5] << 8) | ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
  p.battMv = (uint16_t)(in[8] | (in[9] << 8));
  p.tempC100 = (int16_t)(in[10] | (in[11] << 8));
  p.humHalf = in[12];
  p.flags = in[13];
  p.intervalS = (uint16_t)(in[14] | (in[15] << 8));
  return p.node != 0;
}

// Χρόνος στον αέρα σε ms (τύπος του datasheet SX1276, ρητή κεφαλίδα, CRC on).
//   sf 7..12, bwHz 125000/250000/500000, crDenom 5..8 (4/5 … 4/8), preamble σύμβολα
static inline uint32_t nwLoraAirtimeMs(uint8_t payloadLen, uint8_t sf, uint32_t bwHz, uint8_t crDenom, uint16_t preamble = 8) {
  float tsym = (float)(1UL << sf) * 1000.0f / (float)bwHz;        // ms ανά σύμβολο
  bool lowDr = tsym > 16.0f;                                      // LowDataRateOptimize (SF11/12 στα 125 kHz)
  float num = 8.0f * payloadLen - 4.0f * sf + 28.0f + 16.0f;      // +16: CRC, κεφαλίδα ρητή (IH = 0)
  float den = 4.0f * (sf - (lowDr ? 2 : 0));
  float n = ceilf(num / den) * (float)crDenom;
  if (n < 0) n = 0;
  float total = (preamble + 4.25f) * tsym + (8.0f + n) * tsym;
  return (uint32_t)ceilf(total);
}

// -----------------------------------------------------------------------------
//  SX1276 / RFM95 (LoRa mode), ωμό SPI. Χωρίς interrupts: η κατάσταση
//  διαβάζεται από τον καταχωρητή IRQ (polling), άρα το DIO0 δεν χρειάζεται.
// -----------------------------------------------------------------------------
class NwSx1276 {
public:
  // false αν το τσιπ δεν απαντά (RegVersion != 0x12): λάθος pins ή άλλο τσιπ (π.χ. SX1262).
  bool begin(SPIClass &spi, int8_t ss, int8_t rst, uint32_t freqHz, uint8_t sf, uint32_t bwHz, uint8_t crDenom, int8_t txDbm,
             uint16_t preamble = 8, uint8_t syncWord = 0x12) {
    _spi = &spi;
    _ss = ss;
    pinMode(_ss, OUTPUT);
    digitalWrite(_ss, HIGH);
    if (rst >= 0) {
      pinMode(rst, OUTPUT);
      digitalWrite(rst, LOW);
      delay(10);
      digitalWrite(rst, HIGH);
      delay(10);
    }
    if (rd(0x42) != 0x12) return false;                    // RegVersion
    wr(0x01, 0x80);                                        // sleep + LoRa (το bit LoRa αλλάζει μόνο σε sleep)
    delay(10);
    uint64_t frf = ((uint64_t)freqHz << 19) / 32000000ULL; // βήμα = 32 MHz / 2^19
    wr(0x06, (uint8_t)(frf >> 16));
    wr(0x07, (uint8_t)(frf >> 8));
    wr(0x08, (uint8_t)frf);
    wr(0x0E, 0x00);                                        // FIFO TX base
    wr(0x0F, 0x00);                                        // FIFO RX base
    wr(0x0C, 0x23);                                        // LNA: μέγιστο κέρδος + boost
    uint8_t bw = bwHz >= 500000 ? 9 : bwHz >= 250000 ? 8 : 7;
    sf = constrain(sf, 7, 12);
    crDenom = constrain(crDenom, 5, 8);
    wr(0x1D, (uint8_t)((bw << 4) | ((crDenom - 4) << 1)));  // ρητή κεφαλίδα
    wr(0x1E, (uint8_t)((sf << 4) | 0x04));                  // CRC on
    bool lowDr = ((float)(1UL << sf) * 1000.0f / (float)(bw == 9 ? 500000 : bw == 8 ? 250000 : 125000)) > 16.0f;
    wr(0x26, (uint8_t)(0x04 | (lowDr ? 0x08 : 0x00)));      // AGC auto (+ LowDataRateOptimize)
    wr(0x20, (uint8_t)(preamble >> 8));
    wr(0x21, (uint8_t)(preamble & 0xFF));
    wr(0x39, syncWord);                                     // 0x12 = ιδιωτικό δίκτυο (0x34 = LoRaWAN)
    txDbm = constrain(txDbm, 2, 17);
    wr(0x09, (uint8_t)(0x80 | (txDbm - 2)));                // PA_BOOST (έτσι είναι καλωδιωμένα τα RFM95/TTGO/Heltec)
    wr(0x4D, 0x84);                                         // PA DAC κανονικό (όχι +20 dBm)
    wr(0x0B, 0x2B);                                         // προστασία υπερέντασης 100 mA
    standby();
    return true;
  }

  void standby() { wr(0x01, 0x81); }
  void sleep() { wr(0x01, 0x80); }                          // ~0,2 µA

  // Στέλνει και περιμένει το TxDone (με όριο). Επιστρέφει true αν ολοκληρώθηκε.
  bool transmit(const uint8_t *data, uint8_t len, uint32_t timeoutMs) {
    standby();
    wr(0x0D, 0x00);                                         // δείκτης FIFO στην αρχή
    burst(0x00, data, len);
    wr(0x22, len);
    wr(0x12, 0xFF);                                         // καθάρισε τα IRQ
    wr(0x01, 0x83);                                         // TX
    uint32_t t0 = millis();
    bool done = false;
    while (millis() - t0 < timeoutMs) {
      if (rd(0x12) & 0x08) {                                // TxDone
        done = true;
        break;
      }
      delay(1);
    }
    wr(0x12, 0xFF);
    standby();                                              // ποτέ «κολλημένος» πομπός
    return done;
  }

  void receive() {
    standby();
    wr(0x12, 0xFF);
    wr(0x0D, 0x00);
    wr(0x01, 0x85);                                         // συνεχής λήψη
  }

  // 0 = τίποτα, >0 = μήκος πακέτου στο buf, -1 = πακέτο με λάθος CRC ή πολύ μεγάλο.
  int readPacket(uint8_t *buf, uint8_t cap, int *rssi, float *snr) {
    uint8_t irq = rd(0x12);
    if (!(irq & 0x40)) return 0;                            // RxDone
    int res = -1;
    if (!(irq & 0x20)) {                                    // όχι PayloadCrcError
      uint8_t n = rd(0x13);
      if (n > 0 && n <= cap) {
        wr(0x0D, rd(0x10));                                 // αρχή του τελευταίου πακέτου στο FIFO
        _spi->beginTransaction(SPISettings(1000000, MSBFIRST, SPI_MODE0));
        digitalWrite(_ss, LOW);
        _spi->transfer(0x00);
        for (uint8_t i = 0; i < n; i++) buf[i] = _spi->transfer(0);
        digitalWrite(_ss, HIGH);
        _spi->endTransaction();
        float s = (int8_t)rd(0x19) * 0.25f;
        int r = (int)rd(0x1A) - 157;                        // θύρα HF (868/915 MHz)
        if (s < 0) r += (int)s;
        if (snr) *snr = s;
        if (rssi) *rssi = r;
        res = n;
      }
    }
    wr(0x12, 0xFF);
    return res;
  }

private:
  SPIClass *_spi = nullptr;
  int8_t _ss = -1;

  uint8_t rd(uint8_t reg) {
    _spi->beginTransaction(SPISettings(1000000, MSBFIRST, SPI_MODE0));
    digitalWrite(_ss, LOW);
    _spi->transfer(reg & 0x7F);
    uint8_t v = _spi->transfer(0);
    digitalWrite(_ss, HIGH);
    _spi->endTransaction();
    return v;
  }
  void wr(uint8_t reg, uint8_t v) {
    _spi->beginTransaction(SPISettings(1000000, MSBFIRST, SPI_MODE0));
    digitalWrite(_ss, LOW);
    _spi->transfer(reg | 0x80);
    _spi->transfer(v);
    digitalWrite(_ss, HIGH);
    _spi->endTransaction();
  }
  void burst(uint8_t reg, const uint8_t *d, uint8_t n) {
    _spi->beginTransaction(SPISettings(1000000, MSBFIRST, SPI_MODE0));
    digitalWrite(_ss, LOW);
    _spi->transfer(reg | 0x80);
    for (uint8_t i = 0; i < n; i++) _spi->transfer(d[i]);
    digitalWrite(_ss, HIGH);
    _spi->endTransaction();
  }
};
