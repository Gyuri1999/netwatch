// =============================================================================
//  NetWatch - signed_ota.h  (βιβλιοθήκη "NetWatchSignedOta")
// -----------------------------------------------------------------------------
//  Υπογεγραμμένο HTTPS OTA για ESP32 (Arduino core 3.x), κοινό για το
//  esp32-sentinel και το esp32-canary. Υλοποιεί τα 4 επίπεδα του μαθήματος
//  iot-5-3 της Ακαδημίας:
//
//    1. Authentication  η συσκευή ΡΩΤΑΕΙ (pull). Δεν ακούει σε καμία θύρα
//                       OTA, άρα κανείς δεν μπορεί να της "σπρώξει" firmware.
//    2. Transport       HTTPS με τη δική σου CA (setCACert), TLS 1.2+.
//    3. Authenticity    υπογραφή ECDSA P-256 με κλειδί που ΔΕΝ είναι στον
//                       server. Ελέγχεται ΠΡΙΝ γραφτεί έστω ένα byte.
//    4. Recovery        rollback του bootloader (το νέο image μένει "υπό
//                       δοκιμή" μέχρι να περάσει το self-test) και
//                       anti-rollback (μόνο ΑΥΣΤΗΡΑ νεότερη έκδοση, με την
//                       υψηλότερη επιβεβαιωμένη έκδοση αποθηκευμένη στο NVS).
//
//  Τι υπογράφεται (βλ. tools/ota/ota_sign.py, ίδια ακριβώς μορφή):
//
//      "netwatch-ota/1\n<class>\n<version>\n<size>\n<sha256 hex του .bin>\n"
//
//  Η υπογραφή είναι ECDSA (DER, base64 στο manifest.json) πάνω στο SHA-256
//  αυτού του κειμένου. Επειδή μέσα είναι και το SHA-256 του .bin, η υπογραφή
//  καλύπτει το firmware. Επειδή είναι και η έκδοση και η κατηγορία, ένας
//  παραβιασμένος server ΔΕΝ μπορεί να ξαναβαφτίσει ένα παλιό υπογεγραμμένο
//  .bin σε "9.9.9" (rollback) ούτε να δώσει firmware sentinel σε canary.
//
//  ΜΠΛΟΚΑΡΕΙ: η signedOtaCheck() κρατά το loop() όσο κατεβαίνει το firmware
//  (συνήθως 10-40 s, όριο SIGNED_OTA_TOTAL_MS). Είναι αποδεκτό για έλεγχο κάθε
//  6 ώρες, αλλά κάλεσέ τη ΜΟΝΟ όταν η συσκευή είναι αδρανής (όχι μέσα σε
//  κρίσιμο κομμάτι). Το esp-mqtt τρέχει στο δικό του task και κρατά τη
//  σύνδεση ζωντανή στο μεταξύ.
//
//  Χρήση (βλ. τα δύο sketches):
//    setup():  signedOtaBegin(FW_VERSION);
//    loop():   signedOtaSelfTestTick(300);          // rollback αν δεν "υγιάνει"
//              if (mqtt συνδεδεμένο) signedOtaMarkHealthy();
//              if (ώρα για έλεγχο) signedOtaCheck(...);  // + δημοσίευση αποτελέσματος
//              if (signedOtaTakeReport(st)) ... δημοσίευση "updated"/"rejected"
// =============================================================================
#pragma once

#include <Arduino.h>

// Συνολικό όριο χρόνου για ΟΛΗ τη λήψη (manifest + firmware).
#ifndef SIGNED_OTA_TOTAL_MS
#define SIGNED_OTA_TOTAL_MS 180000UL
#endif
// Αν δεν έρθει ούτε ένα byte για τόσο χρόνο, η λήψη ακυρώνεται.
#ifndef SIGNED_OTA_IDLE_MS
#define SIGNED_OTA_IDLE_MS 20000UL
#endif

enum class SignedOtaResult : uint8_t {
  None,       // δεν έγινε ακόμα έλεγχος
  UpToDate,   // ο server δεν έχει αυστηρά νεότερη έκδοση
  Updated,    // εγκαταστάθηκε νέα έκδοση (αναφέρεται μετά το reboot, όταν περάσει το self-test)
  Rejected,   // απόρριψη για λόγο ΑΣΦΑΛΕΙΑΣ: υπογραφή, sha256, rollback, κατηγορία, έκδοση που απέτυχε
  Error,      // πρόβλημα δικτύου/server/flash: τίποτα δεν άλλαξε, ξαναδοκιμάζουμε αργότερα
};

struct SignedOtaStatus {
  SignedOtaResult result;
  char version[18];   // η έκδοση που προσφέρθηκε / εγκαταστάθηκε (ή "")
  char reason[96];    // σύντομη εξήγηση στα αγγλικά (ASCII, για JSON/logs)
};

// "updated" | "up_to_date" | "rejected" | "error" | "none"
const char *signedOtaResultName(SignedOtaResult r);

// Μία φορά στο setup(), ΠΡΙΝ από οτιδήποτε άλλο OTA. Διαβάζει το NVS,
// καταλαβαίνει αν προηγήθηκε update ή rollback και ετοιμάζει την αναφορά.
void signedOtaBegin(const char *currentVersion);

// Το self-test πέρασε (π.χ. συνδεθήκαμε σε Wi-Fi ΚΑΙ στον MQTT broker με TLS).
// Αν το τρέχον image είναι "υπό δοκιμή" μετά από OTA, γίνεται μόνιμο.
// Ασφαλές να καλείται συχνά (κάνει δουλειά μόνο την πρώτη φορά).
void signedOtaMarkHealthy();

// Αν το τρέχον image είναι "υπό δοκιμή" και δεν κλήθηκε signedOtaMarkHealthy()
// μέσα σε timeoutS δευτερόλεπτα από την εκκίνηση: rollback στο προηγούμενο
// firmware και επανεκκίνηση. Κάλεσέ τη στο loop().
void signedOtaSelfTestTick(uint32_t timeoutS);

// Ελέγχει για νέα έκδοση και, αν υπάρχει ΚΑΙ είναι έγκυρη, την εγκαθιστά
// και κάνει επανεκκίνηση (τότε η συνάρτηση δεν επιστρέφει).
//   baseUrl        π.χ. "https://pi-broker.local:8443" (χωρίς / στο τέλος)
//   deviceClass    "canary" | "sentinel"  -> <baseUrl>/<class>/manifest.json
//   currentVersion "MAJOR.MINOR.PATCH" (το FW_VERSION του sketch)
//   caPem          η CA του σπιτιού (ίδια με το MQTT_CA_PEM)
//   pubKeyPem      το δημόσιο κλειδί υπογραφής (ota_public.h)
// Επιστρέφει true αν δεν υπάρχει νεότερη έκδοση (UpToDate), false αλλιώς.
// Λεπτομέρειες: signedOtaLastStatus().
bool signedOtaCheck(const char *baseUrl, const char *deviceClass, const char *currentVersion,
                    const char *caPem, const char *pubKeyPem);

const SignedOtaStatus &signedOtaLastStatus();

// Αναφορά που αφορά ΠΡΟΗΓΟΥΜΕΝΗ εκκίνηση: "updated" (το νέο firmware πέρασε
// το self-test) ή "rejected" (το νέο firmware ΔΕΝ πέρασε το self-test και ο
// bootloader γύρισε στο παλιό). Επιστρέφει true μία φορά, όταν υπάρχει κάτι
// να δημοσιευτεί. Κάλεσέ τη όταν το MQTT είναι συνδεδεμένο.
bool signedOtaTakeReport(SignedOtaStatus &out);
