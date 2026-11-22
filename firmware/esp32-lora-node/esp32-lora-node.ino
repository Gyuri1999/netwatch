// =============================================================================
//  NetWatch LoRa Node  v1.0.0   (κόμβος· η σύζευξη γίνεται στην ΠΥΛΗ, esp32-lora-gw)
// -----------------------------------------------------------------------------
//  Αισθητήρας μπαταρίας για μέρη ΧΩΡΙΣ Wi-Fi (αποθήκη, υπόγειο, αντλιοστάσιο).
//  Κοιμάται (deep sleep) και ξυπνά:
//     * όταν αλλάξει η πόρτα (μαγνητική επαφή, ext0 wake)
//     * κάθε LORA_INTERVAL_S για περιοδική αναφορά
//  Στέλνει ΕΝΑ μικρό πακέτο LoRa 24 bytes {id, seq, μπαταρία, θερμοκρασία,
//  υγρασία, σημαίες} με HMAC-SHA256 (βλ. firmware/common/nw_lora.h) και
//  ξανακοιμάται. Δεν ακούει ποτέ, δεν έχει Wi-Fi/Bluetooth.
//
//  Προστασία από replay: ο μετρητής seq μόνο ανεβαίνει. Ζει στη μνήμη RTC (αντέχει
//  το deep sleep) και «κρατιέται» στο NVS ανά μπλοκ των 64 (αντέχει διακοπή
//  τροφοδοσίας χωρίς να γράφουμε στη flash σε κάθε πακέτο).
//
//  EU868: 1% duty cycle. Ο κώδικας υπολογίζει τον χρόνο στον αέρα και ΔΕΝ εκπέμπει
//  ξανά πριν περάσει 100x αυτός ο χρόνος· ισχύς το πολύ 14 dBm.
//
//  ΔΕΝ έχει δοκιμαστεί σε πραγματικό υλικό (μόνο μεταγλώττιση). Βλ. README.
//
//  Μεταγλώττιση:  arduino-cli compile --fqbn esp32:esp32:esp32 --library ../common .
// =============================================================================

#include <SPI.h>
#include <Wire.h>
#include <Preferences.h>
#include <esp_sleep.h>
#include <driver/rtc_io.h>
#include <sys/time.h>
#include <nw_lora.h>      // firmware/common (--library ../common)

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
#define LORA_CR 5             // 4/5
#endif
#ifndef LORA_TX_DBM
#define LORA_TX_DBM 14
#endif
#if LORA_TX_DBM > 14
#error "EU868 (868.0-868.6 MHz): το πολύ 14 dBm ERP. Μείωσε το LORA_TX_DBM."
#endif
#ifndef LORA_INTERVAL_S
#define LORA_INTERVAL_S 900
#endif
#ifndef LORA_EVENT_REPEATS
#define LORA_EVENT_REPEATS 2  // ένα γεγονός πόρτας στέλνεται 2 φορές (δεν υπάρχει ACK)
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
#ifndef USE_DOOR
#define USE_DOOR 1
#endif
#ifndef PIN_DOOR
#define PIN_DOOR 13           // ΠΡΕΠΕΙ να είναι RTC GPIO (0,2,4,12-15,25-27,32-39)
#endif
#ifndef DOOR_OPEN_LEVEL
#define DOOR_OPEN_LEVEL 1     // reed προς GND + pull-up: ανοιχτή = HIGH
#endif
#ifndef DOOR_INTERNAL_PULLUP
#define DOOR_INTERNAL_PULLUP 1
#endif
#ifndef USE_SHT31
#define USE_SHT31 1           // ανιχνεύεται μόνος του
#endif
#ifndef PIN_SDA
#define PIN_SDA 21
#endif
#ifndef PIN_SCL
#define PIN_SCL 22
#endif
#ifndef USE_BATT
#define USE_BATT 1
#endif
#ifndef PIN_BATT_ADC
#define PIN_BATT_ADC 35
#endif
#ifndef BATT_DIVIDER
#define BATT_DIVIDER 2.0f
#endif
#ifndef PIN_BATT_CTRL
#define PIN_BATT_CTRL -1      // Heltec V2: 21 (LOW = ενεργός διαιρέτης)
#endif
#ifndef BATT_LOW_MV
#define BATT_LOW_MV 3400
#endif

static const uint32_t RTC_MAGIC = 0x4E574C31;   // "NWL1"
static const uint32_t SEQ_BLOCK = 64;           // κάθε πόσα πακέτα γράφουμε στο NVS
static const uint8_t  PEND_SEND = 1, PEND_DOOR = 2;

// Μνήμη RTC: επιζεί από το deep sleep, χάνεται όταν κοπεί η τροφοδοσία.
RTC_DATA_ATTR static uint32_t r_magic = 0;
RTC_DATA_ATTR static uint32_t r_seq = 0;        // ο ΕΠΟΜΕΝΟΣ μετρητής που θα χρησιμοποιηθεί
RTC_DATA_ATTR static uint32_t r_seqCeil = 0;    // ό,τι είναι < από αυτό είναι «δεσμευμένο» στο NVS
RTC_DATA_ATTR static uint32_t r_nextTxS = 0;    // πριν από αυτή τη στιγμή ΔΕΝ εκπέμπουμε (duty cycle)
RTC_DATA_ATTR static uint32_t r_nextPeriodicS = 0;
RTC_DATA_ATTR static uint8_t r_lastDoor = 0xFF; // η κατάσταση που ΣΤΑΛΘΗΚΕ τελευταία (0xFF = καμία)
RTC_DATA_ATTR static uint8_t r_pending = 0;

static NwSx1276 radio;
static uint8_t g_key[NWL_KEY_LEN];

// Ρολόι RTC σε δευτερόλεπτα: συνεχίζει να μετρά στο deep sleep.
static uint32_t rtcNowS() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint32_t)tv.tv_sec;
}

// -----------------------------------------------------------------------------
//  Αισθητήρες
// -----------------------------------------------------------------------------
static bool doorRead() {
#if USE_DOOR
  rtc_gpio_deinit((gpio_num_t)PIN_DOOR);         // από «RTC» πίσω σε κανονικό GPIO
  pinMode(PIN_DOOR, DOOR_INTERNAL_PULLUP ? INPUT_PULLUP : INPUT);
  delay(2);
  uint8_t high = 0;
  for (uint8_t i = 0; i < 5; i++) {              // debounce: πλειοψηφία 5 αναγνώσεων σε ~25 ms
    if (digitalRead(PIN_DOOR)) high++;
    delay(5);
  }
  return (high >= 3) == (DOOR_OPEN_LEVEL != 0);
#else
  return false;
#endif
}

static uint16_t battReadMv() {
#if USE_BATT
  if (PIN_BATT_CTRL >= 0) {
    pinMode(PIN_BATT_CTRL, OUTPUT);
    digitalWrite(PIN_BATT_CTRL, LOW);
    delay(10);
  }
  analogSetPinAttenuation(PIN_BATT_ADC, ADC_11db);
  uint32_t sum = 0;
  for (uint8_t i = 0; i < 8; i++) sum += analogReadMilliVolts(PIN_BATT_ADC);
  if (PIN_BATT_CTRL >= 0) pinMode(PIN_BATT_CTRL, INPUT);   // κλείσε τον διαιρέτη: δεν τραβά ρεύμα στον ύπνο
  float mv = (float)sum / 8.0f * BATT_DIVIDER;
  return mv > 65000.0f ? 65000 : (uint16_t)mv;
#else
  return 0;
#endif
}

// CRC-8 του Sensirion: πολυώνυμο 0x31, αρχική τιμή 0xFF.
static uint8_t shtCrc(const uint8_t *d, size_t n) {
  uint8_t crc = 0xFF;
  for (size_t i = 0; i < n; i++) {
    crc ^= d[i];
    for (uint8_t b = 0; b < 8; b++) crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x31) : (uint8_t)(crc << 1);
  }
  return crc;
}

// Μία μέτρηση SHT31 (0x44 ή 0x45). false αν δεν υπάρχει ή απέτυχε το CRC.
static bool shtRead(float *t, float *h) {
#if USE_SHT31
  Wire.begin(PIN_SDA, PIN_SCL, 100000);
  Wire.setTimeOut(50);
  for (uint8_t addr = 0x44; addr <= 0x45; addr++) {
    Wire.beginTransmission(addr);
    Wire.write(0x24);                            // single shot, high repeatability
    Wire.write(0x00);
    if (Wire.endTransmission() != 0) continue;
    delay(20);
    uint8_t d[6];
    if (Wire.requestFrom((int)addr, 6) != 6) continue;
    for (uint8_t i = 0; i < 6; i++) d[i] = (uint8_t)Wire.read();
    if (shtCrc(d, 2) != d[2] || shtCrc(d + 3, 2) != d[5]) continue;
    *t = -45.0f + 175.0f * (float)((d[0] << 8) | d[1]) / 65535.0f;
    *h = 100.0f * (float)((d[3] << 8) | d[4]) / 65535.0f;
    Wire.end();
    return true;
  }
  Wire.end();
#endif
  (void)t;
  (void)h;
  return false;
}

// -----------------------------------------------------------------------------
//  Ύπνος
// -----------------------------------------------------------------------------
static void goToSleep(uint32_t seconds, bool doorNow) {
  if (seconds < 1) seconds = 1;
  esp_sleep_enable_timer_wakeup((uint64_t)seconds * 1000000ULL);
#if USE_DOOR
  // Ξύπνα όταν η επαφή πάει στην ΑΝΤΙΘΕΤΗ στάθμη από τη σημερινή (άνοιγμα Ή κλείσιμο).
  int openLevel = DOOR_OPEN_LEVEL ? 1 : 0;
  int levelNow = doorNow ? openLevel : !openLevel;
  rtc_gpio_init((gpio_num_t)PIN_DOOR);
  rtc_gpio_set_direction((gpio_num_t)PIN_DOOR, RTC_GPIO_MODE_INPUT_ONLY);
#if DOOR_INTERNAL_PULLUP
  rtc_gpio_pulldown_dis((gpio_num_t)PIN_DOOR);
  rtc_gpio_pullup_en((gpio_num_t)PIN_DOOR);      // ~45 kΩ: με κλειστή επαφή τραβά ~70 µA (βλ. README)
#endif
  esp_sleep_enable_ext0_wakeup((gpio_num_t)PIN_DOOR, !levelNow);
#else
  (void)doorNow;
#endif
  Serial.printf("[node] sleep %lu s\n", (unsigned long)seconds);
  Serial.flush();
  esp_deep_sleep_start();
}

// -----------------------------------------------------------------------------
//  Όλη η δουλειά γίνεται στο setup(): ξύπνα, μέτρα, στείλε, κοιμήσου.
// -----------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  bool cold = (r_magic != RTC_MAGIC);
  esp_sleep_wakeup_cause_t cause = esp_sleep_get_wakeup_cause();
  Serial.printf("\n[node] NetWatch LoRa Node %s id=%u wake=%d%s\n", FW_VERSION, (unsigned)LORA_NODE_ID, (int)cause, cold ? " (cold boot)" : "");

  if (!nwLoraParseKey(LORA_KEY_HEX, g_key) || LORA_NODE_ID == 0) {
    // Χωρίς δικό σου κλειδί δεν εκπέμπουμε ΤΙΠΟΤΑ (ένα «γνωστό» κλειδί δεν προστατεύει).
    Serial.println("[node] ΛΑΘΟΣ ΡΥΘΜΙΣΗ: βάλε LORA_KEY_HEX (64 hex, ίδιο με της πύλης) και LORA_NODE_ID (1-65535) στο secrets.h");
    Serial.flush();
    esp_sleep_enable_timer_wakeup(3600ULL * 1000000ULL);
    esp_deep_sleep_start();
  }

  if (cold) {
    // Μετά από διακοπή τροφοδοσίας συνεχίζουμε από το «ταβάνι» του NVS: είναι
    // σίγουρα μεγαλύτερο από κάθε μετρητή που έχει ήδη εκπεμφθεί.
    Preferences prefs;
    prefs.begin("nwlora", true);
    uint32_t ceil = prefs.getUInt("ceil", 0);
    prefs.end();
    r_seq = ceil > 0 ? ceil : 1;
    r_seqCeil = ceil;
    r_nextTxS = 0;
    r_nextPeriodicS = 0;
    r_lastDoor = 0xFF;
    r_pending = 0;
    r_magic = RTC_MAGIC;
  }

  uint32_t now = rtcNowS();
  bool door = doorRead();
  bool doorChanged = USE_DOOR && r_lastDoor != 0xFF && (uint8_t)door != r_lastDoor;
  bool periodic = now >= r_nextPeriodicS;
  if (doorChanged) r_pending |= PEND_DOOR;
  bool want = cold || periodic || doorChanged || (r_pending & PEND_SEND);

  if (want && now < r_nextTxS) {
    // Κανόνας 1%: είναι νωρίς για νέα εκπομπή. Κράτα το «χρωστούμενο» και κοιμήσου.
    r_pending |= PEND_SEND;
    Serial.printf("[node] duty cycle: wait %lu s\n", (unsigned long)(r_nextTxS - now));
  } else if (want) {
    NwLoraPacket p;
    memset(&p, 0, sizeof(p));
    p.node = (uint16_t)LORA_NODE_ID;
    p.intervalS = (uint16_t)LORA_INTERVAL_S;
    p.battMv = battReadMv();
    float t = NAN, h = NAN;
    if (shtRead(&t, &h)) {
      p.tempC100 = (int16_t)lroundf(constrain(t, -100.0f, 300.0f) * 100.0f);
      p.humHalf = (uint8_t)lroundf(constrain(h, 0.0f, 100.0f) * 2.0f);
    } else {
      p.tempC100 = NWL_TEMP_NONE;
      p.humHalf = NWL_HUM_NONE;
    }
    if (USE_DOOR) p.flags |= NWL_F_HAS_DOOR;
    if (door) p.flags |= NWL_F_DOOR_OPEN;
    if (r_pending & PEND_DOOR) p.flags |= NWL_F_DOOR_EVT;
    if (cold) p.flags |= NWL_F_BOOT;
    if (USE_BATT && p.battMv > 0 && p.battMv < BATT_LOW_MV) p.flags |= NWL_F_BATT_LOW;

    // Μετρητής: πρώτα «δέσμευσε» στο NVS, μετά χρησιμοποίησε.
    if (r_seq >= r_seqCeil) {
      r_seqCeil = r_seq + SEQ_BLOCK;
      Preferences prefs;
      prefs.begin("nwlora", false);
      prefs.putUInt("ceil", r_seqCeil);
      prefs.end();
    }
    p.seq = r_seq++;

    uint8_t pkt[NWL_PKT_LEN];
    uint32_t airMs = nwLoraAirtimeMs(NWL_PKT_LEN, LORA_SF, LORA_BW_HZ, LORA_CR);
    uint32_t usedMs = 0;
    SPI.begin(PIN_LORA_SCK, PIN_LORA_MISO, PIN_LORA_MOSI, PIN_LORA_SS);
    bool ok = nwLoraEncode(p, g_key, pkt)
              && radio.begin(SPI, PIN_LORA_SS, PIN_LORA_RST, LORA_FREQ_HZ, LORA_SF, LORA_BW_HZ, LORA_CR, LORA_TX_DBM);
    if (!ok) {
      Serial.println("[node] SX1276 not found (pins?) - nothing sent");
    } else {
      // Το ίδιο πακέτο (ίδιο seq) ξαναστέλνεται για τα γεγονότα πόρτας: η πύλη
      // κρατά το πρώτο και πετά το αντίγραφο. Κάθε εκπομπή μετρά στο duty cycle.
      uint8_t sends = (p.flags & NWL_F_DOOR_EVT) ? (uint8_t)LORA_EVENT_REPEATS : 1;
      if (sends < 1) sends = 1;
      for (uint8_t i = 0; i < sends; i++) {
        if (i) delay(150 + (esp_random() % 250));
        if (radio.transmit(pkt, NWL_PKT_LEN, airMs * 2 + 200)) usedMs += airMs;
      }
      radio.sleep();
      Serial.printf("[node] sent seq=%lu batt=%u mV temp=%.2f hum=%.1f door=%d flags=0x%02X air=%lu ms\n", (unsigned long)p.seq,
                    p.battMv, t, h, (int)door, p.flags, (unsigned long)usedMs);
    }
    SPI.end();
    now = rtcNowS();
    // 1% duty cycle: μετά από T ms στον αέρα, σιωπή για 100 x T (στρογγυλεμένο προς τα πάνω).
    r_nextTxS = now + (usedMs * 100UL + 999UL) / 1000UL;
    r_lastDoor = (uint8_t)door;
    r_pending = 0;
    if (periodic || cold) r_nextPeriodicS = now + LORA_INTERVAL_S;
  }

  now = rtcNowS();
  uint32_t sleepS;
  if (r_pending & PEND_SEND) sleepS = r_nextTxS > now ? r_nextTxS - now : 1;   // χρωστάμε πακέτο: ξύπνα μόλις επιτρέπεται
  else sleepS = r_nextPeriodicS > now ? r_nextPeriodicS - now : 1;
  goToSleep(sleepS, door);
}

void loop() {}   // δεν φτάνουμε ποτέ εδώ
