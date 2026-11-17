// =============================================================================
//  NetWatch Sentinel - sentinel_types.h
// -----------------------------------------------------------------------------
//  Οι τύποι δεδομένων (struct/enum) του firmware.
//
//  Γιατί σε ξεχωριστό header; Το Arduino IDE / arduino-cli προσθέτει αυτόματα
//  "prototypes" για τις συναρτήσεις του .ino ΣΤΗΝ ΑΡΧΗ του αρχείου, πριν από
//  τους ορισμούς των struct. Αν μια συνάρτηση δέχεται ένα struct ως όρισμα,
//  το prototype θα έβγαζε σφάλμα "does not name a type". Βάζοντας τους τύπους
//  σε header που γίνεται #include νωρίς, το πρόβλημα λύνεται καθαρά.
// =============================================================================
#pragma once

#include <stdint.h>
#include <esp_wifi_types.h>   // wifi_auth_mode_t

// Ένα επίπεδο ασφάλειας Wi-Fi: όνομα για το JSON και "βαθμός" σύγκρισης
// (μικρότερος βαθμός = ασθενέστερη ασφάλεια).
struct SecurityInfo {
  wifi_auth_mode_t mode;
  const char *name;
  uint8_t rank;
};

// Τύποι γεγονότων που στέλνονται στο topic  netwatch/sensor/<id>/event
enum EventType : uint8_t { EV_DEAUTH, EV_EVIL_TWIN, EV_ROGUE_AP };

// Ένα γεγονός στην ουρά (ring buffer), μέχρι να σταλεί.
struct SentinelEvent {
  EventType type;
  uint32_t  t;            // uptime (s) τη στιγμή της ανίχνευσης
  uint8_t   channel;
  int8_t    rssi;
  uint16_t  count;        // μόνο για deauth: πλαίσια στο παράθυρο
  uint8_t   bssid[6];     // deauth: πηγή (addr2) | twin/rogue: BSSID του AP
  uint8_t   target[6];    // μόνο για deauth: παραλήπτης (addr1)
  const char *security;   // μόνο για twin/rogue (δείχνει σε σταθερό string)
};

// Μετρητές ενός παραθύρου μέτρησης deauth/disassoc (ένα κανάλι, ~1 s).
struct DeauthWindow {
  uint16_t count;
  bool     sawBroadcast;  // στάλθηκε έστω ένα πλαίσιο σε ff:ff:ff:ff:ff:ff;
  int8_t   rssi;          // RSSI του τελευταίου πλαισίου
  uint8_t  source[6];     // πηγή (addr2) του τελευταίου πλαισίου
  uint8_t  target[6];     // παραλήπτης (addr1) του τελευταίου πλαισίου
};
