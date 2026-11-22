// =============================================================================
//  NetWatch Rack  v1.0.0   (τύπος αισθητήρα στο NetWatch: "rack")
// -----------------------------------------------------------------------------
//  Αισθητήρας περιβάλλοντος για rack / ντουλάπι δικτύου, σε απλό ESP32:
//
//    1. SHT31 (I2C 0x44/0x45)     θερμοκρασία + υγρασία           -> temp_high, humid_high
//    2. Μαγνητική επαφή (reed)    πόρτα του rack                   -> door_open
//    3. Αισθητήρας νερού          δύο ακροδέκτες σε ADC ή module   -> water_leak
//    4. PZEM-004T v3 (UART2)      τάση/ρεύμα/ισχύς/ενέργεια/Hz/PF  -> power_fail, power_back
//
//  Κάθε αισθητήρας είναι ΠΡΟΑΙΡΕΤΙΚΟΣ (USE_… στο secrets.h). Ο SHT31 και το PZEM
//  ανιχνεύονται μόνοι τους στην εκκίνηση: μια πλακέτα με σκέτο SHT31 δουλεύει.
//
//  Αναφορές: HTTPS προς το NetWatch με καρφιτσωμένο πιστοποιητικό (nw_probe.h).
//  Τα γεγονότα φεύγουν ΑΜΕΣΩΣ, η κατάσταση κάθε «interval» (60 s).
//
//  ΑΣΦΑΛΕΙΑ: το firmware μόνο ΔΙΑΒΑΖΕΙ. Στο PZEM στέλνει αποκλειστικά την
//  εντολή Modbus 0x04 (read input registers): ποτέ εγγραφή, ποτέ μηδενισμό kWh.
//
//  ΔΕΝ έχει δοκιμαστεί σε πραγματικό υλικό (μόνο μεταγλώττιση). Βλ. README.
//
//  Μεταγλώττιση:  arduino-cli compile --fqbn esp32:esp32:esp32 --library ../common .
// =============================================================================

#include <WiFi.h>
#include <Wire.h>
#include <nw_probe.h>     // firmware/common (--library ../common)

#include "secrets.h"      // ΔΕΝ είναι στο git, βλ. secrets.example.h

#define FW_VERSION "1.0.0"

// -----------------------------------------------------------------------------
//  Προεπιλογές (αν δεν ορίζονται στο secrets.h)
// -----------------------------------------------------------------------------
#ifndef USE_SHT31
#define USE_SHT31 1
#endif
#ifndef USE_DOOR
#define USE_DOOR 1
#endif
#ifndef USE_LEAK
#define USE_LEAK 0            // 0 = όχι, 1 = δύο ακροδέκτες σε ADC, 2 = ψηφιακό module
#endif
#ifndef USE_PZEM
#define USE_PZEM 1
#endif

#ifndef PIN_SDA
#define PIN_SDA 21
#endif
#ifndef PIN_SCL
#define PIN_SCL 22
#endif
#ifndef PIN_DOOR
#define PIN_DOOR 27
#endif
#ifndef DOOR_OPEN_LEVEL
#define DOOR_OPEN_LEVEL HIGH  // reed προς GND + pull-up: ανοιχτή πόρτα = HIGH
#endif
#ifndef DOOR_DEBOUNCE_MS
#define DOOR_DEBOUNCE_MS 60
#endif
#ifndef PIN_LEAK
#define PIN_LEAK 34           // ADC1 (ΟΧΙ ADC2: δεν δουλεύει μαζί με το Wi-Fi)
#endif
#ifndef PIN_LEAK_DRIVE
#define PIN_LEAK_DRIVE 25     // τροφοδοτεί τον ακροδέκτη ΜΟΝΟ στη μέτρηση (-1 = μόνιμα στα 3V3)
#endif
#ifndef LEAK_WET_MV
#define LEAK_WET_MV 500
#endif
#ifndef LEAK_DIGITAL_WET_LEVEL
#define LEAK_DIGITAL_WET_LEVEL LOW
#endif
#ifndef PIN_PZEM_RX
#define PIN_PZEM_RX 16
#endif
#ifndef PIN_PZEM_TX
#define PIN_PZEM_TX 17
#endif
#ifndef PZEM_ADDR
#define PZEM_ADDR 0xF8        // «γενική» διεύθυνση: απαντά όποιο PZEM είναι στη γραμμή
#endif
#ifndef PZEM_MIN_VOLT
#define PZEM_MIN_VOLT 50.0f   // κάτω από αυτό = «δεν έχει ρεύμα»
#endif
#ifndef TEMP_HIGH_C
#define TEMP_HIGH_C 35.0f
#endif
#ifndef TEMP_HYST_C
#define TEMP_HYST_C 2.0f
#endif
#ifndef HUMID_HIGH_PCT
#define HUMID_HIGH_PCT 70.0f
#endif
#ifndef HUMID_HYST_PCT
#define HUMID_HYST_PCT 5.0f
#endif
#ifndef REPORT_INTERVAL_S
#define REPORT_INTERVAL_S 60
#endif

static const uint32_t SENSE_PERIOD_MS = 2000;   // κάθε πότε διαβάζουμε SHT31 / νερό / PZEM
static const uint8_t  CONFIRM_READS   = 2;      // τόσες συνεχόμενες μετρήσεις πριν από γεγονός
static const uint8_t  PZEM_FAIL_READS = 3;      // τόσες σιωπές του PZEM = διακοπή ρεύματος
static const uint32_t PZEM_RETRY_MS   = 60000;  // αν δεν βρέθηκε στην εκκίνηση, ξαναψάξε

// -----------------------------------------------------------------------------
//  Κατάσταση
// -----------------------------------------------------------------------------
static NwProbe nw;
static char g_hw[48] = "ESP32";
static char g_mac[18] = "";

// SHT31
static uint8_t g_shtAddr = 0;          // 0 = δεν βρέθηκε
static bool    g_shtValid = false;
static float   g_temp = NAN, g_hum = NAN;
static uint8_t g_shtFails = 0;
static bool    g_tempAlarm = false, g_humAlarm = false;
static uint8_t g_tempOver = 0, g_humOver = 0;

// Πόρτα
static volatile uint32_t g_doorEdges = 0;   // γράφεται από ISR
static bool     g_doorOpen = false;         // σταθερή (debounced) κατάσταση
static bool     g_doorRaw = false;
static uint32_t g_doorRawAt = 0;

// Νερό
static bool    g_leak = false;
static uint8_t g_leakCount = 0;
static int     g_leakMv = 0;

// PZEM
static bool    g_pzemSeen = false;     // απάντησε έστω μία φορά από την εκκίνηση
static bool    g_pzemOk = false;       // απάντησε στην τελευταία μέτρηση
static uint8_t g_pzemFails = 0;
static bool    g_powerFail = false;
static uint32_t g_pzemLastTry = 0;
static float   g_volt = 0, g_amp = 0, g_watt = 0, g_kwh = 0, g_freq = 0, g_pf = 0;

static uint32_t g_lastSense = 0;
static uint32_t g_lastWifiTry = 0;
static uint32_t g_lastPrint = 0;

// =============================================================================
//  1. SHT31 (raw I2C, χωρίς βιβλιοθήκη)
// =============================================================================

// CRC-8 του Sensirion: πολυώνυμο 0x31, αρχική τιμή 0xFF.
static uint8_t shtCrc(const uint8_t *d, size_t n) {
  uint8_t crc = 0xFF;
  for (size_t i = 0; i < n; i++) {
    crc ^= d[i];
    for (uint8_t b = 0; b < 8; b++) crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x31) : (uint8_t)(crc << 1);
  }
  return crc;
}

static bool i2cPresent(uint8_t addr) {
  Wire.beginTransmission(addr);
  return Wire.endTransmission() == 0;
}

static bool shtCommand(uint8_t addr, uint16_t cmd) {
  Wire.beginTransmission(addr);
  Wire.write((uint8_t)(cmd >> 8));
  Wire.write((uint8_t)(cmd & 0xFF));
  return Wire.endTransmission() == 0;
}

static void shtDetect() {
#if USE_SHT31
  Wire.begin(PIN_SDA, PIN_SCL, 100000);
  Wire.setTimeOut(50);                       // ποτέ μπλοκάρισμα σε κολλημένο δίαυλο
  for (uint8_t a = 0x44; a <= 0x45; a++) {
    if (i2cPresent(a)) {
      g_shtAddr = a;
      shtCommand(a, 0x30A2);                 // soft reset
      delay(5);
      Serial.printf("[sht31] found at 0x%02X\n", a);
      return;
    }
  }
  Serial.println("[sht31] not found (0x44/0x45) - temperature/humidity disabled");
#endif
}

// Μία μέτρηση (single shot, high repeatability, χωρίς clock stretching).
static bool shtRead() {
  if (!g_shtAddr) return false;
  bool ok = false;
  float t = NAN, h = NAN;
  if (shtCommand(g_shtAddr, 0x2400)) {
    delay(20);                               // η μέτρηση θέλει <= 15 ms
    uint8_t d[6];
    if (Wire.requestFrom((int)g_shtAddr, 6) == 6) {
      for (uint8_t i = 0; i < 6; i++) d[i] = (uint8_t)Wire.read();
      if (shtCrc(d, 2) == d[2] && shtCrc(d + 3, 2) == d[5]) {
        uint16_t rt = (uint16_t)((d[0] << 8) | d[1]);
        uint16_t rh = (uint16_t)((d[3] << 8) | d[4]);
        t = -45.0f + 175.0f * (float)rt / 65535.0f;
        h = 100.0f * (float)rh / 65535.0f;
        ok = true;
      }
    }
  }
  if (ok) {
    g_temp = t;
    g_hum = h;
    g_shtValid = true;
    g_shtFails = 0;
  } else if (g_shtFails < 255 && ++g_shtFails >= 5) {
    g_shtValid = false;                      // 5 αποτυχίες στη σειρά: μην δείχνεις μπαγιάτικη τιμή
  }
  return ok;
}

// Όρια με υστέρηση: γεγονός όταν ΠΕΡΑΣΕΙ το όριο, νέο γεγονός μόνο αφού πρώτα
// πέσει κάτω από (όριο - υστέρηση). Έτσι μια τιμή που «παίζει» γύρω από το όριο
// δεν γεμίζει το NetWatch ειδοποιήσεις.
static void shtEvaluate() {
  if (!g_shtValid) return;
  char txt[160];
  if (!g_tempAlarm) {
    g_tempOver = (g_temp >= TEMP_HIGH_C) ? (uint8_t)(g_tempOver + 1) : 0;
    if (g_tempOver >= CONFIRM_READS) {
      g_tempAlarm = true;
      snprintf(txt, sizeof(txt), "Θερμοκρασία rack %.1f °C (όριο %.1f °C)", g_temp, (double)TEMP_HIGH_C);
      nw.event("temp_high", txt);
      nw.evNum("temp", g_temp, 1);
      nw.evNum("limit", TEMP_HIGH_C, 1);
      Serial.printf("[event] temp_high %.1f C\n", g_temp);
    }
  } else if (g_temp <= TEMP_HIGH_C - TEMP_HYST_C) {
    g_tempAlarm = false;
    g_tempOver = 0;
    nw.kick();
  }
  if (!g_humAlarm) {
    g_humOver = (g_hum >= HUMID_HIGH_PCT) ? (uint8_t)(g_humOver + 1) : 0;
    if (g_humOver >= CONFIRM_READS) {
      g_humAlarm = true;
      snprintf(txt, sizeof(txt), "Υγρασία rack %.0f %% (όριο %.0f %%)", g_hum, (double)HUMID_HIGH_PCT);
      nw.event("humid_high", txt);
      nw.evNum("hum", g_hum, 1);
      nw.evNum("limit", HUMID_HIGH_PCT, 1);
      Serial.printf("[event] humid_high %.0f %%\n", g_hum);
    }
  } else if (g_hum <= HUMID_HIGH_PCT - HUMID_HYST_PCT) {
    g_humAlarm = false;
    g_humOver = 0;
    nw.kick();
  }
}

// =============================================================================
//  2. Πόρτα (reed): interrupt + debounce
// =============================================================================
#if USE_DOOR
static void IRAM_ATTR doorIsr() {
  g_doorEdges = g_doorEdges + 1;   // μόνο μετράμε: η δουλειά γίνεται στο loop()
}

static bool doorReadRaw() { return digitalRead(PIN_DOOR) == DOOR_OPEN_LEVEL; }

static void doorSetup() {
  pinMode(PIN_DOOR, INPUT_PULLUP);   // GPIO 34-39 ΔΕΝ έχουν pull-up: θέλουν εξωτερική αντίσταση
  delay(5);
  g_doorOpen = g_doorRaw = doorReadRaw();
  g_doorRawAt = millis();
  attachInterrupt(digitalPinToInterrupt(PIN_DOOR), doorIsr, CHANGE);
  Serial.printf("[door] GPIO%d, now %s (no event for the state at boot)\n", PIN_DOOR, g_doorOpen ? "OPEN" : "closed");
}

static void doorOpenEvent(bool stillOpen) {
  nw.event("door_open", stillOpen ? "Άνοιξε η πόρτα του rack" : "Η πόρτα του rack άνοιξε και έκλεισε");
  nw.evBool("door", stillOpen);
  Serial.printf("[event] door_open (%s)\n", stillOpen ? "open" : "open+closed");
}

static void doorPoll() {
  uint32_t now = millis();
  bool raw = doorReadRaw();
  if (raw != g_doorRaw) {
    g_doorRaw = raw;
    g_doorRawAt = now;
    return;
  }
  if (now - g_doorRawAt < DOOR_DEBOUNCE_MS) return;

  noInterrupts();
  uint32_t edges = g_doorEdges;
  g_doorEdges = 0;
  interrupts();

  if (raw != g_doorOpen) {
    g_doorOpen = raw;
    if (raw) doorOpenEvent(true);
    else nw.kick();                          // έκλεισε: απλώς ενημέρωσε την κατάσταση
  } else if (edges >= 2 && !g_doorOpen) {
    // Η πόρτα άνοιξε ΚΑΙ έκλεισε όσο το loop() ήταν απασχολημένο (π.χ. σε αποστολή).
    // Χωρίς το interrupt θα το χάναμε. (>= 2 ακμές: ένα μόνο «τρεμόπαιγμα» δεν μετρά.)
    doorOpenEvent(false);
  }
}
#endif

// =============================================================================
//  3. Νερό
// =============================================================================
#if USE_LEAK
static void leakSetup() {
#if USE_LEAK == 1
  analogSetPinAttenuation(PIN_LEAK, ADC_11db);
  if (PIN_LEAK_DRIVE >= 0) {
    pinMode(PIN_LEAK_DRIVE, OUTPUT);
    digitalWrite(PIN_LEAK_DRIVE, LOW);
  }
  Serial.printf("[leak] 2-wire probe on ADC GPIO%d (wet above %d mV)\n", PIN_LEAK, LEAK_WET_MV);
#else
  pinMode(PIN_LEAK, INPUT);
  Serial.printf("[leak] digital module on GPIO%d (wet = %s)\n", PIN_LEAK, LEAK_DIGITAL_WET_LEVEL == LOW ? "LOW" : "HIGH");
#endif
}

static void leakRead() {
  bool wet;
#if USE_LEAK == 1
  // Ο ακροδέκτης παίρνει τάση ΜΟΝΟ για λίγα ms ανά μέτρηση: με μόνιμη τάση (DC)
  // τα μέταλλα μέσα στο νερό διαβρώνονται (ηλεκτρόλυση) σε λίγες εβδομάδες.
  if (PIN_LEAK_DRIVE >= 0) {
    digitalWrite(PIN_LEAK_DRIVE, HIGH);
    delay(5);
  }
  g_leakMv = (int)analogReadMilliVolts(PIN_LEAK);
  if (PIN_LEAK_DRIVE >= 0) digitalWrite(PIN_LEAK_DRIVE, LOW);
  wet = g_leakMv >= LEAK_WET_MV;
#else
  wet = digitalRead(PIN_LEAK) == LEAK_DIGITAL_WET_LEVEL;
#endif
  if (wet == g_leak) {
    g_leakCount = 0;
    return;
  }
  if (++g_leakCount < CONFIRM_READS) return;
  g_leakCount = 0;
  g_leak = wet;
  if (wet) {
    nw.event("water_leak", "Νερό στον αισθητήρα διαρροής του rack");
    nw.evBool("leak", true);
#if USE_LEAK == 1
    nw.evInt("mv", g_leakMv);
#endif
    Serial.println("[event] water_leak");
  } else {
    nw.kick();
  }
}
#endif

// =============================================================================
//  4. PZEM-004T v3 (Modbus-RTU, 9600 8N1, ΜΟΝΟ ανάγνωση)
// =============================================================================
#if USE_PZEM
// CRC-16/MODBUS: πολυώνυμο 0xA001 (ανεστραμμένο), αρχική τιμή 0xFFFF.
static uint16_t modbusCrc(const uint8_t *d, size_t n) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < n; i++) {
    crc ^= d[i];
    for (uint8_t b = 0; b < 8; b++) crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0xA001) : (uint16_t)(crc >> 1);
  }
  return crc;
}

// Διαβάζει τους 10 input registers (0x0000-0x0009). Μπλοκάρει το πολύ ~250 ms.
static bool pzemRead() {
  uint8_t req[8] = {PZEM_ADDR, 0x04, 0x00, 0x00, 0x00, 0x0A, 0, 0};   // 0x04 = read input registers
  uint16_t crc = modbusCrc(req, 6);
  req[6] = (uint8_t)(crc & 0xFF);            // στο Modbus το CRC πάει low byte πρώτα
  req[7] = (uint8_t)(crc >> 8);
  while (Serial2.available()) Serial2.read();   // πέτα ό,τι σκουπίδι έμεινε
  Serial2.write(req, sizeof(req));
  Serial2.flush();

  uint8_t r[25];                             // addr, fn, 20, 20 bytes δεδομένα, CRC lo, CRC hi
  size_t got = 0;
  uint32_t t0 = millis();
  while (got < sizeof(r) && millis() - t0 < 250) {
    if (Serial2.available()) r[got++] = (uint8_t)Serial2.read();
    else delay(2);
  }
  if (got != sizeof(r) || r[1] != 0x04 || r[2] != 20) return false;
  if (modbusCrc(r, 23) != (uint16_t)(r[23] | (r[24] << 8))) return false;

  // Οι τιμές 32 bit έρχονται ως δύο registers με το ΧΑΜΗΛΟ word πρώτο.
  #define R16(i) ((uint16_t)((r[3 + 2 * (i)] << 8) | r[4 + 2 * (i)]))
  #define R32(i) ((uint32_t)R16(i) | ((uint32_t)R16((i) + 1) << 16))
  g_volt = R16(0) / 10.0f;                   // 0.1 V
  g_amp  = R32(1) / 1000.0f;                 // 0.001 A
  g_watt = R32(3) / 10.0f;                   // 0.1 W
  g_kwh  = R32(5) / 1000.0f;                 // 1 Wh
  g_freq = R16(7) / 10.0f;                   // 0.1 Hz
  g_pf   = R16(8) / 100.0f;                  // 0.01
  #undef R16
  #undef R32
  return true;
}

static void pzemSetup() {
  Serial2.begin(9600, SERIAL_8N1, PIN_PZEM_RX, PIN_PZEM_TX);
  delay(50);
  for (uint8_t i = 0; i < 3 && !g_pzemSeen; i++) {
    g_pzemSeen = g_pzemOk = pzemRead();
    if (!g_pzemSeen) delay(100);
  }
  g_pzemLastTry = millis();
  if (g_pzemSeen) Serial.printf("[pzem] found: %.1f V %.1f Hz\n", g_volt, g_freq);
  else Serial.println("[pzem] no reply (not fitted, or mains is off) - will retry every 60 s");
}

// Το PZEM τροφοδοτείται ΑΠΟ ΤΗΝ ΠΛΕΥΡΑ ΤΟΥ ΔΙΚΤΥΟΥ: όταν κοπεί το ρεύμα σωπαίνει.
// Άρα «διακοπή» = το PZEM που απαντούσε σταμάτησε να απαντά (ή δείχνει ~0 V),
// ενώ το ESP32 συνεχίζει να τρέχει από UPS/USB.
static void pzemPoll() {
  if (!g_pzemSeen) {                         // δεν έχει φανεί ποτέ: ψάξε αραιά
    if (millis() - g_pzemLastTry < PZEM_RETRY_MS) return;
    g_pzemLastTry = millis();
    if (pzemRead()) {
      g_pzemSeen = g_pzemOk = true;
      hwString();
      Serial.println("[pzem] found");
      nw.kick();
    }
    return;
  }
  bool ok = pzemRead();
  bool live = ok && g_volt >= PZEM_MIN_VOLT;
  g_pzemOk = ok;
  if (live) {
    g_pzemFails = 0;
    if (g_powerFail) {
      g_powerFail = false;
      char txt[120];
      snprintf(txt, sizeof(txt), "Το ρεύμα επανήλθε στο rack (%.0f V)", g_volt);
      nw.event("power_back", txt);
      nw.evNum("volt", g_volt, 1);
      Serial.println("[event] power_back");
    }
    return;
  }
  if (!ok) g_volt = g_amp = g_watt = g_freq = g_pf = 0;   // το kWh μένει (μετρητής)
  if (g_pzemFails < 255) g_pzemFails++;
  if (!g_powerFail && g_pzemFails >= PZEM_FAIL_READS) {
    g_powerFail = true;
    nw.event("power_fail", ok ? "Διακοπή ρεύματος στο rack (τάση ~0 V)" : "Διακοπή ρεύματος στο rack (ο μετρητής PZEM δεν απαντά)");
    nw.evNum("volt", g_volt, 1);
    nw.evBool("pzem_reply", ok);
    Serial.println("[event] power_fail");
  }
}
#endif

// =============================================================================
//  5. Αναφορά
// =============================================================================
static void hwString() {
  snprintf(g_hw, sizeof(g_hw), "ESP32%s%s%s%s", g_shtAddr ? " + SHT31" : "", USE_DOOR ? " + reed" : "",
           USE_LEAK ? " + leak" : "", g_pzemSeen ? " + PZEM-004T" : "");
}

static void report() {
  if (WiFi.status() != WL_CONNECTED) {
    if (g_lastWifiTry && millis() - g_lastWifiTry < 15000) return;   // όχι συνεχείς προσπάθειες
    g_lastWifiTry = millis();
    Serial.printf("[wifi] connecting to %s ...\n", WIFI_SSID);
    if (!nwWifiConnect(WIFI_SSID, WIFI_PASS, 10000)) {
      Serial.printf("[wifi] not connected (events queued: %u)\n", nw.pending());
      return;
    }
    Serial.printf("[wifi] ip=%s rssi=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
  }
  NwJson &j = nw.start(WiFi.localIP().toString().c_str(), g_mac, WiFi.RSSI());
  if (g_shtValid) {
    j.num("temp", g_temp, 1);
    j.num("hum", g_hum, 1);
  }
  j.beginObject("metrics");
#if USE_PZEM
  if (g_pzemSeen) {
    j.num("volt", g_volt, 1);
    j.num("amp", g_amp, 3);
    j.num("watt", g_watt, 1);
    j.num("kwh", g_kwh, 3);
    j.num("freq", g_freq, 1);
    j.num("pf", g_pf, 2);
  }
#endif
#if USE_DOOR
  j.boolean("door", g_doorOpen);
#endif
#if USE_LEAK
  j.boolean("leak", g_leak);
#endif
  j.endObject();

  NwResult r = nw.send();
  if (r == NW_OK) Serial.printf("[nw] report ok (next in %lu s)\n", (unsigned long)nw.intervalS());
  else Serial.printf("[nw] report FAILED: %s (try %u, queued events %u)\n", nw.lastError(), nw.fails(), nw.pending());
}

// =============================================================================
//  6. setup / loop
// =============================================================================
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.printf("\n[rack] NetWatch Rack %s\n", FW_VERSION);

  shtDetect();
#if USE_DOOR
  doorSetup();
#endif
#if USE_LEAK
  leakSetup();
#endif
#if USE_PZEM
  pzemSetup();
#endif
  hwString();

  WiFi.mode(WIFI_STA);
  nwWifiMac(g_mac, sizeof(g_mac));
  if (!nw.begin(NW_PAIR_CODE, FW_VERSION, g_hw, 3072, REPORT_INTERVAL_S)) {
    // Χωρίς σύζευξη ο αισθητήρας συνεχίζει να μετρά και να γράφει στο Serial
    // (χρήσιμο για έλεγχο της καλωδίωσης), απλώς δεν στέλνει τίποτα.
    Serial.printf("[nw] NOT PAIRED: %s\n", nw.lastError());
    Serial.println("[nw] Στο NetWatch: Οι συσκευές μου -> Rack -> Δημιουργία κωδικού, και βάλ' τον στο NW_PAIR_CODE του secrets.h");
  } else {
    Serial.printf("[nw] paired as %s (kind=%s)\n", nw.id(), nw.kind());
    if (strcmp(nw.kind(), "rack") != 0) Serial.println("[nw] WARNING: ο κωδικός δεν είναι τύπου 'rack'");
  }
  nwWatchdog(90);
}

void loop() {
#if USE_DOOR
  doorPoll();
#endif
  uint32_t now = millis();
  if (now - g_lastSense >= SENSE_PERIOD_MS) {
    g_lastSense = now;
#if USE_SHT31
    if (g_shtAddr) {
      shtRead();
      shtEvaluate();
    }
#endif
#if USE_LEAK
    leakRead();
#endif
#if USE_PZEM
    pzemPoll();
#endif
  }
  if (now - g_lastPrint >= 10000) {
    g_lastPrint = now;
    Serial.printf("[rack] temp=%.1f hum=%.1f door=%d leak=%d volt=%.1f watt=%.1f heap=%u\n", g_temp, g_hum, (int)g_doorOpen,
                  (int)g_leak, g_volt, g_watt, (unsigned)ESP.getFreeHeap());
  }
  if (nw.due()) report();
  delay(10);
}
