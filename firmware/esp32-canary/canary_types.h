// =============================================================================
//  NetWatch Canary - canary_types.h
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
#include <WiFi.h>   // WiFiClient

// Μέγιστα μήκη (χωρίς το '\0'). Τα ίδια όρια εφαρμόζει και το NetWatch
// (sensor.py: clean_txt(data, 80), clean_txt(user, 40)).
static const size_t DATA_MAX = 80;
static const size_t USER_MAX = 32;
static const size_t CANARY_LINE_MAX = 200;   // buffer γραμμής (μεγαλύτερες κόβονται)
static const size_t SRC_MAX  = 40;    // IPv4 ή IPv6 ως κείμενο (IPv6: έως 39)

// Ποια ψεύτικη υπηρεσία "άγγιξε" ο επισκέπτης.
enum ServiceKind : uint8_t { SVC_TELNET, SVC_HTTP };

// Ένα γεγονός στην ουρά (ring buffer), μέχρι να σταλεί στο MQTT.
struct CanaryEvent {
  uint32_t    t;                  // uptime (s) τη στιγμή της σύνδεσης
  char        src[SRC_MAX + 1];   // IP του επισκέπτη ως κείμενο
  uint16_t    port;               // 23 / 80 / 8080
  ServiceKind service;
  char        data[DATA_MAX + 1]; // καθαρισμένη πρώτη γραμμή (ΠΟΤΕ κωδικός)
  char        user[USER_MAX + 1]; // όνομα χρήστη αν φάνηκε, αλλιώς ""
};

// Φάσεις μιας σύνδεσης (μηχανή καταστάσεων ανά client).
enum ClientPhase : uint8_t {
  PH_FREE,        // ελεύθερη θέση
  PH_TELNET_USER, // περιμένουμε το "login:"
  PH_TELNET_PASS, // περιμένουμε το "Password:" (τα bytes ΔΕΝ αποθηκεύονται)
  PH_HTTP_HEAD,   // διαβάζουμε request line + headers
};

// Μία ενεργή σύνδεση. Όλα τα πεδία μηδενίζονται όταν ελευθερώνεται.
struct ClientSlot {
  WiFiClient  client;
  ClientPhase phase;
  ServiceKind service;
  uint16_t    port;
  char        src[SRC_MAX + 1];
  uint32_t    startMs;            // για το timeout
  uint32_t    t;                  // uptime (s) στην αποδοχή
  bool        report;             // πέρασε το rate limit; (αποφασίζεται στο accept)
  bool        skipLf;             // μόλις είδαμε '\r': αγνόησε επόμενο '\n' / '\0'
  uint8_t     iac;                // telnet: κατάσταση αποκοπής διαπραγμάτευσης (IAC)
  bool        gotFirst;           // http: διαβάστηκε η request line
  bool        sawPass;            // telnet: στάλθηκε γραμμή κωδικού (δεν την κρατάμε)
  uint16_t    total;              // συνολικά bytes που διαβάστηκαν
  uint16_t    lineLen;
  char        line[CANARY_LINE_MAX + 1];
  char        data[DATA_MAX + 1];
  char        user[USER_MAX + 1];
};

// Μνήμη για το rate limit: πότε αναφέραμε τελευταία φορά IP+θύρα.
struct RateEntry {
  char     src[SRC_MAX + 1];
  uint16_t port;
  bool     used;
  uint32_t lastMs;
};
