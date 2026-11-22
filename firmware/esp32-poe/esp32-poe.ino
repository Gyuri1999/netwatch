// =============================================================================
//  NetWatch PoE Field  v1.0.0   (τύπος αισθητήρα στο NetWatch: "field")
// -----------------------------------------------------------------------------
//  Tester πρίζας δικτύου / μόνιμος ενσύρματος φρουρός, σε Olimex ESP32-POE
//  (ή ESP32-POE-ISO). ΜΟΝΟ Ethernet (LAN8720): το Wi-Fi δεν ξεκινά ποτέ.
//
//  Μόλις «ανέβει» το link:
//    1. ταχύτητα / duplex, χρόνος DHCP, IP / μάσκα / πύλη / DNS
//    2. πύλη: ICMP ping (ή, αν δεν απαντά σε ping, δοκιμή TCP)        -> gw_ms
//    3. Internet: σύνδεση TCP σε δημόσια IP:443                       -> inet_ms
//    4. LLDP / CDP: όνομα switch, θύρα, VLAN (παθητική ακρόαση)
//    5. PoE: βλ. ενότητα 4 (και README) για το τι μπορεί να ξέρει η πλακέτα
//
//  Γεγονότα: link_down (στέλνεται όταν ξαναέρθει το link), poe_lost, outage
//  (η πύλη δεν απαντά), dhcp_rogue (είδαμε ΔΕΥΤΕΡΟ DHCP server στο καλώδιο).
//
//  Πώς ακούμε LLDP/CDP/DHCP: το Arduino ETH API δεν δίνει ωμά πλαίσια, αλλά ο
//  οδηγός esp_eth του ESP-IDF επιτρέπει να μπούμε «στη μέση» του δρόμου εισόδου
//  (esp_eth_update_input_path_info). Κοιτάμε το πλαίσιο και το παραδίδουμε
//  ΑΝΕΠΑΦΟ στο lwIP. Δεν στέλνουμε ποτέ δικά μας πλαίσια L2.
//
//  ΔΕΝ έχει δοκιμαστεί σε πραγματικό υλικό (μόνο μεταγλώττιση). Βλ. README.
//
//  Μεταγλώττιση:  arduino-cli compile --fqbn esp32:esp32:esp32-poe --library ../common .
// =============================================================================

#include <ETH.h>          // τα pins/ρολόι του LAN8720 έρχονται από το variant της πλακέτας
#include <esp_netif.h>
#include <ping/ping_sock.h>
#include <lwip/sockets.h>
#include <nw_probe.h>     // firmware/common (--library ../common)

#include "secrets.h"      // ΔΕΝ είναι στο git, βλ. secrets.example.h

#define FW_VERSION "1.0.0"

#if !defined(ETH_PHY_TYPE) || !defined(ETH_PHY_MDC) || !defined(ETH_CLK_MODE)
#error "Διάλεξε πλακέτα OLIMEX ESP32-POE (fqbn esp32:esp32:esp32-poe) ή ESP32-POE-ISO: από εκεί έρχονται τα pins του Ethernet."
#endif

// -----------------------------------------------------------------------------
//  Προεπιλογές (αν δεν ορίζονται στο secrets.h)
// -----------------------------------------------------------------------------
#ifndef USB_CONNECTED
#define USB_CONNECTED 0       // 1 = η πλακέτα είναι ΚΑΙ στο USB: το PoE δεν μπορεί να κριθεί
#endif
#ifndef HAS_BATTERY
#define HAS_BATTERY 0         // 1 = υπάρχει μπαταρία LiPo: τότε (μόνο) ανιχνεύεται η απώλεια PoE
#endif
#ifndef PIN_PWR_SENSE
#define PIN_PWR_SENSE 39      // Olimex: «external power sense» (διαιρέτης από τα +5V)
#endif
#ifndef PWR_SENSE_MIN_MV
#define PWR_SENSE_MIN_MV 500
#endif
#ifndef PIN_BUTTON
#define PIN_BUTTON 34         // BUT1 της πλακέτας (ενεργό LOW, έχει δικό του pull-up)
#endif
#ifndef INET_TEST_IP
#define INET_TEST_IP "1.1.1.1"   // "" = καμία δοκιμή προς το Internet
#endif
#ifndef INET_TEST_PORT
#define INET_TEST_PORT 443
#endif
#ifndef DHCP_ALLOWED_SERVER
#define DHCP_ALLOWED_SERVER ""   // νόμιμος ΔΕΥΤΕΡΟΣ DHCP server (failover), π.χ. "192.168.1.2"
#endif
#ifndef GW_TEST_PERIOD_S
#define GW_TEST_PERIOD_S 15
#endif
#ifndef REPORT_INTERVAL_S
#define REPORT_INTERVAL_S 60
#endif

static const uint8_t  OUTAGE_FAILS   = 3;      // τόσες αποτυχίες στη σειρά = outage
static const uint32_t TCP_TIMEOUT_MS = 2500;
static const size_t   NBR_FRAME_MAX  = 640;    // όσα bytes κρατάμε από ένα πλαίσιο LLDP/CDP
static const uint8_t  DHCP_MAX_SERVERS = 4;

// (Οι τύποι ορίζονται ΠΡΙΝ από κάθε συνάρτηση, για τα αυτόματα prototypes του Arduino.)
struct DhcpSeen {
  uint32_t server;   // IPv4, network byte order
  uint8_t type;      // 2 = OFFER, 5 = ACK, 6 = NAK
  bool mine;         // το chaddr ήταν η δική μας MAC
};

// -----------------------------------------------------------------------------
//  Κατάσταση
// -----------------------------------------------------------------------------
static NwProbe nw;
static char g_mac[18] = "";
static uint8_t g_macRaw[6];

// Από τον χειριστή γεγονότων δικτύου (άλλο task): μόνο σημαίες/χρόνοι.
static volatile bool g_evLinkUp = false, g_evGotIp = false;
static volatile uint32_t g_evLinkUpAt = 0, g_evGotIpAt = 0;

static bool g_linkUp = false, g_hasIp = false, g_everLink = false;
static uint32_t g_dhcpMs = 0;
static int g_gwMs = -1, g_inetMs = -1;
static bool g_gwIcmp = true;
static uint8_t g_gwFails = 0;
static bool g_outage = false;
static uint32_t g_lastGwTest = 0;

// Γείτονας (LLDP ή CDP)
static char g_nbrSw[48] = "", g_nbrPort[48] = "";
static int g_nbrVlan = -1;
static uint8_t g_nbrBuf[NBR_FRAME_MAX];
static volatile uint16_t g_nbrLen = 0;       // >0: υπάρχει πλαίσιο προς ανάλυση
static volatile bool g_nbrBusy = false;

// DHCP που είδαμε στο καλώδιο (ουρά ενός γραφέα / ενός αναγνώστη)
static DhcpSeen g_dhcpQ[8];
static volatile uint8_t g_dhcpW = 0;
static uint8_t g_dhcpR = 0;
static uint32_t g_dhcpOurs = 0;
static uint32_t g_dhcpServers[DHCP_MAX_SERVERS];
static bool g_dhcpAlerted[DHCP_MAX_SERVERS];
static uint8_t g_dhcpCount = 0;

// PoE
static bool g_poeKnown = false, g_poe = false;
static uint8_t g_poeCount = 0;
static uint32_t g_lastPoe = 0;

// =============================================================================
//  1. Ακρόαση L2 (LLDP / CDP / DHCP) μέσα στον δρόμο εισόδου του οδηγού
// =============================================================================

static inline uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

// Τρέχει στο task λήψης του EMAC, για ΚΑΘΕ πλαίσιο: πρέπει να είναι σύντομη,
// να μην δεσμεύει μνήμη και να μην αλλάζει το πλαίσιο.
static void l2Inspect(const uint8_t *f, uint32_t len) {
  if (len < 14) return;
  uint16_t et = be16(f + 12);
  uint32_t off = 14;

  // LLDP: ethertype 0x88CC. CDP: 802.3 + LLC/SNAP προς 01:00:0c:cc:cc:cc.
  bool lldp = (et == 0x88CC);
  bool cdp = (et <= 1500 && len >= 22 && f[0] == 0x01 && f[1] == 0x00 && f[2] == 0x0C && f[3] == 0xCC && f[4] == 0xCC
              && f[5] == 0xCC && f[14] == 0xAA && f[15] == 0xAA && f[20] == 0x20 && f[21] == 0x00);
  if (lldp || cdp) {
    if (g_nbrLen == 0 && !g_nbrBusy) {   // το loop() δεν έχει άλλο σε αναμονή
      uint16_t n = (uint16_t)(len > NBR_FRAME_MAX ? NBR_FRAME_MAX : len);
      memcpy(g_nbrBuf, f, n);
      g_nbrLen = n;
    }
    return;
  }

  if (et == 0x8100 && len >= 18) {       // ετικέτα 802.1Q
    et = be16(f + 16);
    off = 18;
  }
  if (et != 0x0800 || len < off + 20) return;
  const uint8_t *ip = f + off;
  uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4;
  if ((ip[0] >> 4) != 4 || ihl < 20 || ip[9] != 17 || len < off + ihl + 8) return;
  if ((be16(ip + 6) & 0x1FFF) != 0) return;                 // όχι θραύσματα
  const uint8_t *udp = ip + ihl;
  if (be16(udp) != 67 || be16(udp + 2) != 68) return;       // μόνο απαντήσεις DHCP server -> client
  const uint8_t *bp = udp + 8;
  uint32_t blen = len - (off + ihl + 8);
  if (blen < 244 || bp[0] != 2) return;                     // BOOTREPLY + χώρος για options
  if (bp[236] != 0x63 || bp[237] != 0x82 || bp[238] != 0x53 || bp[239] != 0x63) return;
  uint8_t type = 0;
  uint32_t server = 0;
  memcpy(&server, ip + 12, 4);                              // αν λείπει το option 54: η IP αποστολέα
  for (uint32_t i = 240; i + 1 < blen;) {
    uint8_t opt = bp[i];
    if (opt == 255) break;
    if (opt == 0) {
      i++;
      continue;
    }
    uint8_t ol = bp[i + 1];
    if (i + 2 + ol > blen) break;
    if (opt == 53 && ol == 1) type = bp[i + 2];
    else if (opt == 54 && ol == 4) memcpy(&server, bp + i + 2, 4);
    i += 2u + ol;
  }
  if (type != 2 && type != 5 && type != 6) return;
  uint8_t w = g_dhcpW;
  DhcpSeen &d = g_dhcpQ[w % 8];
  d.server = server;
  d.type = type;
  d.mine = memcmp(bp + 28, g_macRaw, 6) == 0;
  g_dhcpW = (uint8_t)(w + 1);
}

static esp_err_t l2Hook(esp_eth_handle_t hdl, uint8_t *buffer, uint32_t length, void *priv, void *info) {
  (void)hdl;
  (void)info;
  l2Inspect(buffer, length);
  // Ό,τι κάνει και το esp_eth_netif_glue του ESP-IDF: παράδοση στο lwIP.
  return esp_netif_receive((esp_netif_t *)priv, buffer, length, NULL);
}

// Κείμενο από το δίκτυο -> μόνο εκτυπώσιμο ASCII, με όριο.
static void cleanText(const uint8_t *s, size_t n, char *out, size_t cap) {
  size_t o = 0;
  for (size_t i = 0; i < n && o + 1 < cap; i++) {
    uint8_t c = s[i];
    if (c == 0) break;
    out[o++] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
  }
  while (o > 0 && out[o - 1] == ' ') o--;
  out[o] = '\0';
}

static void macText(const uint8_t *m, char *out, size_t cap) {
  snprintf(out, cap, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void parseLldp(const uint8_t *f, size_t len, char *sw, char *port, size_t cap, int *vlan) {
  char chassis[48] = "", portId[48] = "", portDesc[48] = "", sysName[48] = "";
  bool portIsMac = false;
  size_t i = 14;
  while (i + 2 <= len) {
    uint16_t h = be16(f + i);
    uint8_t type = (uint8_t)(h >> 9);
    size_t l = h & 0x1FF;
    i += 2;
    if (type == 0 || i + l > len) break;
    const uint8_t *v = f + i;
    if (type == 1 && l >= 2) {                       // Chassis ID: [subtype][τιμή]
      if (v[0] == 4 && l == 7) macText(v + 1, chassis, sizeof(chassis));
      else cleanText(v + 1, l - 1, chassis, sizeof(chassis));
    } else if (type == 2 && l >= 2) {                // Port ID
      if (v[0] == 3 && l == 7) {
        macText(v + 1, portId, sizeof(portId));
        portIsMac = true;
      } else {
        cleanText(v + 1, l - 1, portId, sizeof(portId));
      }
    } else if (type == 4) {
      cleanText(v, l, portDesc, sizeof(portDesc));
    } else if (type == 5) {
      cleanText(v, l, sysName, sizeof(sysName));
    } else if (type == 127 && l >= 6 && v[0] == 0x00 && v[1] == 0x80 && v[2] == 0xC2 && v[3] == 1) {
      *vlan = be16(v + 4);                           // IEEE 802.1: Port VLAN ID
    }
    i += l;
  }
  strlcpy(sw, sysName[0] ? sysName : chassis, cap);
  strlcpy(port, (portIsMac && portDesc[0]) ? portDesc : (portId[0] ? portId : portDesc), cap);
}

static void parseCdp(const uint8_t *f, size_t len, char *sw, char *port, size_t cap, int *vlan) {
  size_t i = 26;                                     // 14 (802.3) + 8 (LLC/SNAP) + 4 (ver, ttl, checksum)
  while (i + 4 <= len) {
    uint16_t type = be16(f + i);
    size_t l = be16(f + i + 2);                      // το μήκος ΜΕΤΡΑ και την κεφαλίδα των 4 bytes
    if (l < 4 || i + l > len) break;
    const uint8_t *v = f + i + 4;
    size_t vl = l - 4;
    if (type == 0x0001) cleanText(v, vl, sw, cap);
    else if (type == 0x0003) cleanText(v, vl, port, cap);
    else if (type == 0x000A && vl >= 2) *vlan = be16(v);
    i += l;
  }
}

static void nbrPoll() {
  if (g_nbrLen == 0) return;
  g_nbrBusy = true;
  size_t len = g_nbrLen;
  char sw[48] = "", port[48] = "";
  int vlan = -1;
  if (be16(g_nbrBuf + 12) == 0x88CC) parseLldp(g_nbrBuf, len, sw, port, sizeof(sw), &vlan);
  else parseCdp(g_nbrBuf, len, sw, port, sizeof(sw), &vlan);
  g_nbrLen = 0;
  g_nbrBusy = false;
  if (!sw[0] && !port[0]) return;
  if (strcmp(sw, g_nbrSw) != 0 || strcmp(port, g_nbrPort) != 0 || vlan != g_nbrVlan) {
    strlcpy(g_nbrSw, sw, sizeof(g_nbrSw));
    strlcpy(g_nbrPort, port, sizeof(g_nbrPort));
    g_nbrVlan = vlan;
    Serial.printf("[lldp] switch=\"%s\" port=\"%s\" vlan=%d\n", g_nbrSw, g_nbrPort, g_nbrVlan);
    nw.kick();
  }
}

// =============================================================================
//  2. Δεύτερος DHCP server
// =============================================================================
static void ip4Text(uint32_t nbo, char *out, size_t cap) {
  const uint8_t *b = (const uint8_t *)&nbo;
  snprintf(out, cap, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static void dhcpPoll() {
  while (g_dhcpR != g_dhcpW) {
    DhcpSeen d = g_dhcpQ[g_dhcpR % 8];
    g_dhcpR = (uint8_t)(g_dhcpR + 1);
    if (d.server == 0) continue;
    if (d.mine && d.type == 5) g_dhcpOurs = d.server;        // ο server που μας έδωσε τη διεύθυνση
    bool known = false;
    for (uint8_t i = 0; i < g_dhcpCount; i++) known = known || g_dhcpServers[i] == d.server;
    if (!known && g_dhcpCount < DHCP_MAX_SERVERS) {
      g_dhcpAlerted[g_dhcpCount] = false;
      g_dhcpServers[g_dhcpCount++] = d.server;
      char t[16];
      ip4Text(d.server, t, sizeof(t));
      Serial.printf("[dhcp] server seen: %s\n", t);
    }
  }
  if (g_dhcpOurs == 0 || g_dhcpCount < 2) return;            // χρειάζονται ΔΥΟ διαφορετικοί
  for (uint8_t i = 0; i < g_dhcpCount; i++) {
    if (g_dhcpServers[i] == g_dhcpOurs || g_dhcpAlerted[i]) continue;
    g_dhcpAlerted[i] = true;
    char other[16], ours[16];
    ip4Text(g_dhcpServers[i], other, sizeof(other));
    ip4Text(g_dhcpOurs, ours, sizeof(ours));
    if (strcmp(other, DHCP_ALLOWED_SERVER) == 0) continue;
    char txt[160];
    snprintf(txt, sizeof(txt), "Δεύτερος DHCP server στο καλώδιο: %s (ο κανονικός είναι ο %s)", other, ours);
    nw.event("dhcp_rogue", txt);
    nw.evStr("src", other);
    nw.evStr("server", ours);
    Serial.printf("[event] dhcp_rogue %s (ours %s)\n", other, ours);
  }
}

// =============================================================================
//  3. Δοκιμές προσβασιμότητας
// =============================================================================
static volatile bool s_pingDone = false;
static volatile uint32_t s_pingRecv = 0, s_pingSumMs = 0;

static void pingOnSuccess(esp_ping_handle_t h, void *) {
  uint32_t ms = 0;
  esp_ping_get_profile(h, ESP_PING_PROF_TIMEGAP, &ms, sizeof(ms));
  s_pingRecv = s_pingRecv + 1;
  s_pingSumMs = s_pingSumMs + ms;
}

static void pingOnEnd(esp_ping_handle_t, void *) { s_pingDone = true; }

// ICMP echo x3. Επιστρέφει μέσο χρόνο σε ms (το lwIP μετρά σε ακέραια ms: σε LAN
// συχνά 0), -1 αν δεν απάντησε κανένα, -2 αν δεν ξεκίνησε καν το ping.
static int pingMs(IPAddress ip) {
  esp_ping_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.count = 3;
  cfg.interval_ms = 200;
  cfg.timeout_ms = 700;
  cfg.data_size = 32;
  cfg.ttl = 64;
  cfg.task_stack_size = 3072;
  cfg.task_prio = 2;
  IP_ADDR4(&cfg.target_addr, ip[0], ip[1], ip[2], ip[3]);
  esp_ping_callbacks_t cbs;
  memset(&cbs, 0, sizeof(cbs));
  cbs.on_ping_success = pingOnSuccess;
  cbs.on_ping_end = pingOnEnd;
  esp_ping_handle_t h = nullptr;
  s_pingDone = false;
  s_pingRecv = 0;
  s_pingSumMs = 0;
  if (esp_ping_new_session(&cfg, &cbs, &h) != ESP_OK || !h) return -2;
  if (esp_ping_start(h) != ESP_OK) {
    esp_ping_delete_session(h);
    return -2;
  }
  uint32_t t0 = millis();
  while (!s_pingDone && millis() - t0 < 4000) delay(20);
  esp_ping_stop(h);
  esp_ping_delete_session(h);
  delay(20);
  uint32_t n = s_pingRecv;
  return n ? (int)(s_pingSumMs / n) : -1;
}

// Σύνδεση TCP με όριο χρόνου. 1 = συνδέθηκε, 2 = «αρνήθηκε» (RST: ο κόμβος ζει),
// 0 = καμία απάντηση. Δεν στέλνει δεδομένα: ανοίγει και κλείνει.
static int tcpProbe(IPAddress ip, uint16_t port, uint32_t timeoutMs, uint32_t *ms) {
  int s = lwip_socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return 0;
  lwip_fcntl(s, F_SETFL, lwip_fcntl(s, F_GETFL, 0) | O_NONBLOCK);
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = (uint32_t)ip;
  uint32_t t0 = micros();
  int res = 0;
  int r = lwip_connect(s, (struct sockaddr *)&a, sizeof(a));
  if (r == 0) {
    res = 1;
  } else if (errno == EINPROGRESS) {
    fd_set w;
    FD_ZERO(&w);
    FD_SET(s, &w);
    struct timeval tv;
    tv.tv_sec = (long)(timeoutMs / 1000);
    tv.tv_usec = (long)(timeoutMs % 1000) * 1000;
    if (lwip_select(s + 1, NULL, &w, NULL, &tv) > 0) {
      int e = 0;
      socklen_t el = sizeof(e);
      lwip_getsockopt(s, SOL_SOCKET, SO_ERROR, &e, &el);
      res = (e == 0) ? 1 : (e == ECONNREFUSED || e == ECONNRESET ? 2 : 0);
    }
  } else if (errno == ECONNREFUSED) {
    res = 2;
  }
  if (ms) *ms = (micros() - t0) / 1000UL;
  lwip_close(s);
  return res;
}

static void testGateway() {
  g_lastGwTest = millis();
  IPAddress gw = ETH.gatewayIP();
  if ((uint32_t)gw == 0) {
    g_gwMs = -1;
    return;
  }
  int ms = pingMs(gw);
  g_gwIcmp = ms >= 0;
  if (ms < 0) {
    // Κάποια routers δεν απαντούν σε ping: δοκίμασε TCP στις συνηθισμένες θύρες.
    // Και η «άρνηση» (RST) είναι απόδειξη ότι η πύλη είναι ζωντανή.
    static const uint16_t ports[] = {80, 443, 53};
    for (uint8_t i = 0; i < 3 && ms < 0; i++) {
      uint32_t t = 0;
      if (tcpProbe(gw, ports[i], 800, &t)) ms = (int)t;
    }
  }
  g_gwMs = ms;
  nwWatchdogFeed();
  if (ms >= 0) {
    g_gwFails = 0;
    if (g_outage) {
      g_outage = false;
      Serial.println("[gw] reachable again");
      nw.kick();
    }
    return;
  }
  if (g_gwFails < 255) g_gwFails++;
  if (!g_outage && g_gwFails >= OUTAGE_FAILS) {
    g_outage = true;
    char txt[140];
    snprintf(txt, sizeof(txt), "Η πύλη %s δεν απαντά από την ενσύρματη πρίζα", gw.toString().c_str());
    nw.event("outage", txt);
    nw.evStr("gw", gw.toString().c_str());
    Serial.println("[event] outage");
  }
}

static void testInternet() {
  g_inetMs = -1;
  IPAddress ip;
  if (!INET_TEST_IP[0] || !ip.fromString(INET_TEST_IP)) return;
  uint32_t t = 0;
  if (tcpProbe(ip, INET_TEST_PORT, TCP_TIMEOUT_MS, &t) == 1) g_inetMs = (int)t;
  nwWatchdogFeed();
}

// =============================================================================
//  4. PoE
// -----------------------------------------------------------------------------
//  Η πλακέτα ΔΕΝ έχει σήμα «έχω PoE». Έχει μόνο το GPIO39 («external power
//  sense»), που βλέπει τη γραμμή +5V: αυτή τροφοδοτείται ΕΙΤΕ από το PoE ΕΙΤΕ
//  από το USB. Άρα λέμε «poe» μόνο όταν είναι αλήθεια:
//    USB_CONNECTED 1                 -> άγνωστο, το πεδίο "poe" ΔΕΝ στέλνεται
//    USB_CONNECTED 0, HAS_BATTERY 0  -> τρέχουμε χωρίς USB και χωρίς μπαταρία:
//                                       μας τροφοδοτεί το PoE (poe = true)
//    USB_CONNECTED 0, HAS_BATTERY 1  -> poe = GPIO39· αν πέσει: poe_lost
// =============================================================================
static bool extPower() { return (int)analogReadMilliVolts(PIN_PWR_SENSE) >= PWR_SENSE_MIN_MV; }

static void poeSetup() {
#if USB_CONNECTED
  g_poeKnown = false;
  Serial.println("[poe] USB_CONNECTED=1: cannot tell PoE from USB power, not reported");
#elif HAS_BATTERY
  analogSetPinAttenuation(PIN_PWR_SENSE, ADC_11db);
  g_poeKnown = true;
  g_poe = extPower();
  Serial.printf("[poe] battery fitted, external power sense GPIO%d: %s\n", PIN_PWR_SENSE, g_poe ? "present" : "ABSENT");
#else
  g_poeKnown = true;
  g_poe = true;
  Serial.println("[poe] no USB, no battery: the board can only be running from PoE");
#endif
}

static void poePoll() {
#if !USB_CONNECTED && HAS_BATTERY
  if (millis() - g_lastPoe < 1000) return;
  g_lastPoe = millis();
  bool ext = extPower();
  if (ext == g_poe) {
    g_poeCount = 0;
    return;
  }
  if (++g_poeCount < 3) return;                  // 3 συνεχόμενες μετρήσεις
  g_poeCount = 0;
  g_poe = ext;
  if (!ext) {
    nw.event("poe_lost", "Χάθηκε η τροφοδοσία PoE (η πλακέτα τρέχει από μπαταρία)");
    nw.evBool("poe", false);
    nw.evBool("link", g_linkUp);
    Serial.println("[event] poe_lost");
  } else {
    Serial.println("[poe] back");
    nw.kick();
  }
#endif
}

// =============================================================================
//  5. Γεγονότα δικτύου / αναφορά
// =============================================================================
// ΠΡΟΣΟΧΗ: καλείται από άλλο task. Μόνο σημαίες.
static void onNetEvent(arduino_event_id_t event) {
  switch (event) {
    case ARDUINO_EVENT_ETH_START:
      ETH.setHostname("netwatch-field");
      break;
    case ARDUINO_EVENT_ETH_CONNECTED:
      g_evLinkUpAt = millis();
      g_evLinkUp = true;
      break;
    case ARDUINO_EVENT_ETH_GOT_IP:
      g_evGotIpAt = millis();
      g_evGotIp = true;
      break;
    case ARDUINO_EVENT_ETH_LOST_IP:
      g_evGotIp = false;
      break;
    case ARDUINO_EVENT_ETH_DISCONNECTED:
    case ARDUINO_EVENT_ETH_STOP:
      g_evGotIp = false;
      g_evLinkUp = false;
      break;
    default: break;
  }
}

static void linkPoll() {
  bool up = g_evLinkUp, ip = g_evGotIp;
  if (up != g_linkUp) {
    g_linkUp = up;
    if (up) {
      g_everLink = true;
      Serial.printf("[eth] link UP %u Mbps %s duplex\n", ETH.linkSpeed(), ETH.fullDuplex() ? "full" : "half");
    } else {
      Serial.println("[eth] link DOWN");
      // Νέα πρίζα = νέο δίκτυο: ξέχνα γείτονα, DHCP, μετρήσεις.
      g_nbrSw[0] = g_nbrPort[0] = '\0';
      g_nbrVlan = -1;
      g_dhcpCount = 0;
      g_dhcpOurs = 0;
      g_gwMs = g_inetMs = -1;
      g_gwFails = 0;
      g_outage = false;
      g_hasIp = false;
      if (g_everLink) {
        // Χωρίς link δεν μπορεί να φύγει: μένει στην ουρά και στέλνεται όταν
        // ξαναέρθει (το "ago" στα δεδομένα λέει πόσα s πριν έγινε).
        nw.event("link_down", "Έπεσε το link Ethernet (καλώδιο, switch ή θύρα)");
        nw.evBool("poe", g_poeKnown && g_poe);
      }
    }
  }
  if (ip != g_hasIp) {
    g_hasIp = ip;
    if (ip) {
      g_dhcpMs = g_evGotIpAt - g_evLinkUpAt;
      Serial.printf("[eth] ip=%s mask=%s gw=%s dns=%s dhcp=%lu ms\n", ETH.localIP().toString().c_str(),
                    ETH.subnetMask().toString().c_str(), ETH.gatewayIP().toString().c_str(), ETH.dnsIP(0).toString().c_str(),
                    (unsigned long)g_dhcpMs);
      testGateway();
      testInternet();
      Serial.printf("[test] gw_ms=%d (%s) inet_ms=%d\n", g_gwMs, g_gwIcmp ? "icmp" : "tcp", g_inetMs);
      nw.kick();
    }
  }
}

static void report() {
  testInternet();
  NwJson &j = nw.start(ETH.localIP().toString().c_str(), g_mac, 0);
  j.beginObject("metrics");
  if (g_gwMs >= 0) j.integer("gw_ms", g_gwMs);       // λείπει = η πύλη δεν απάντησε
  if (g_inetMs >= 0) j.integer("inet_ms", g_inetMs); // λείπει = δεν βγήκαμε στο Internet
  j.endObject();
  j.beginObject("link");
  j.boolean("up", g_linkUp);
  j.integer("speed", ETH.linkSpeed());
  j.str("duplex", ETH.fullDuplex() ? "full" : "half");
  if (g_poeKnown) j.boolean("poe", g_poe);
  j.integer("dhcp_ms", (long)g_dhcpMs);
  j.str("gw", ETH.gatewayIP().toString().c_str());
  j.str("dns", ETH.dnsIP(0).toString().c_str());
  j.str("mask", ETH.subnetMask().toString().c_str());
  if (g_nbrVlan >= 0) j.integer("vlan", g_nbrVlan);
  if (g_nbrSw[0]) j.str("lldp_sw", g_nbrSw);
  if (g_nbrPort[0]) j.str("lldp_port", g_nbrPort);
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
  Serial.printf("\n[field] NetWatch PoE Field %s\n", FW_VERSION);
  pinMode(PIN_BUTTON, INPUT);
  poeSetup();

  Network.onEvent(onNetEvent);
  if (!ETH.begin()) {                      // LAN8720: pins/ρολόι από το variant (GPIO17 clock out, power GPIO12)
    Serial.println("[eth] ETH.begin() FAILED - λάθος πλακέτα στο fqbn;");
  } else {
    ETH.macAddress(g_macRaw);
    macText(g_macRaw, g_mac, sizeof(g_mac));
    // Ο πυρήνας έχει ήδη ζητήσει «όλα τα multicast» (αλλιώς το MAC θα πετούσε τα
    // 01:80:c2:00:00:0e του LLDP)· το ξαναζητάμε ρητά, δεν βλάπτει.
    ETH.receiveAllMulticast(true);
    esp_err_t e = esp_eth_update_input_path_info(ETH.handle(), l2Hook, ETH.netif());
    Serial.printf("[eth] mac=%s, LLDP/CDP/DHCP tap: %s\n", g_mac, e == ESP_OK ? "on" : "FAILED (no LLDP)");
  }

  if (!nw.begin(NW_PAIR_CODE, FW_VERSION, "Olimex ESP32-POE", 3072, REPORT_INTERVAL_S)) {
    // Χωρίς σύζευξη δουλεύει ως αυτόνομος tester: όλα τα αποτελέσματα στο Serial.
    Serial.printf("[nw] NOT PAIRED: %s\n", nw.lastError());
    Serial.println("[nw] Στο NetWatch: Οι συσκευές μου -> Tester τσέπης -> Δημιουργία κωδικού, και βάλ' τον στο NW_PAIR_CODE του secrets.h");
  } else {
    Serial.printf("[nw] paired as %s (kind=%s)\n", nw.id(), nw.kind());
    if (strcmp(nw.kind(), "field") != 0) Serial.println("[nw] WARNING: ο κωδικός δεν είναι τύπου 'field'");
  }
  nwWatchdog(90);
}

void loop() {
  linkPoll();
  nbrPoll();
  dhcpPoll();
  poePoll();

  if (g_hasIp) {
    if (millis() - g_lastGwTest >= (uint32_t)GW_TEST_PERIOD_S * 1000UL) testGateway();
    if (digitalRead(PIN_BUTTON) == LOW) {            // κουμπί: ξανατρέξε τις δοκιμές τώρα
      delay(30);
      if (digitalRead(PIN_BUTTON) == LOW) {
        Serial.println("[btn] re-test");
        testGateway();
        Serial.printf("[test] gw_ms=%d\n", g_gwMs);
        nw.kick();
        uint32_t t0 = millis();
        while (digitalRead(PIN_BUTTON) == LOW && millis() - t0 < 3000) delay(10);
      }
    }
    if (nw.due()) report();
  }
  delay(10);
}
