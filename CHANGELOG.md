# Changelog

What changed in each NetWatch release, newest first. Every release with its downloads is on the
[Releases page](https://github.com/Gyuri1999/netwatch/releases).

## Unreleased

### Security
- The map libraries (d3, topojson) and the world map now ship with the app instead of being loaded from a CDN.
  The map works with no Internet, and the page no longer loads code or data from a third party. (#57)
- The server sends security headers on every response (no framing by other sites, no referrer on outbound
  links, no MIME sniffing) and no longer reports its Python version. (#56)

### Fixed
- NetWatch's own LAN scan no longer raises "suspicious outbound port 4444 (Metasploit)" for every device. (#58)
- When the connection to the server is lost, the page says so and shows "Offline" instead of "All good"
  over old data. It reconnects on its own. (#59)

## 1.17.0 — 2026-11-26

A calmer interface. Nothing was removed; screens were grouped and hidden behind views.

### Added
- **Menu views**: Home, Student, Technician and All. The sidebar shows 13, 24, 56 or 73 entries
  instead of 86. Hidden screens stay reachable with ⌘K. (#48)
- **Text size** (A, A+, A++) and a **reading mode** with more spacing and no italics, under
  Appearance → Accessibility. (#53)
- **Simpler Home** for learners: "Is everything OK?", up to three things to look at today, and the
  lesson card. Everything else moved under "More". (#55)

### Changed
- Similar screens are now one menu entry with tabs: Packets + Wireshark, Devices (five screens),
  Wi‑Fi, History, Cameras and Academy. Old links still open the right tab. (#49, #50, #51)
- Every screen has its own emoji, and seven screens have clearer names. Long menu labels wrap
  instead of being cut off. (#52)
- Each menu group has its own colour, and page tabs show an underline on the active tab. (#54)

### Fixed
- The Learning group was missing from the sidebar, and Packets had no menu entry at all. (#48)

## 1.16.3 — 2026-11-26

### Fixed
- **Mac app: LAN scans found no open ports.** macOS hides the network card's MAC address from the app,
  and NetWatch sent ARP requests with the placeholder `02:00:00:00:00:00`, which made the router stop
  answering for a few seconds. NetWatch now uses the real MAC, or sends nothing. (#46)
- Home and lab networks that both use `192.168.1.x` no longer mix: scans are remembered per network,
  identified by the router's MAC address. (#45)

## 1.16.2 — 2026-11-26

Fixes found while testing every tool on a real network.

### Fixed
- LAN scan finds Wi‑Fi devices that were asleep, and no longer loses open ports on routers that
  silently drop closed ones. (#41, #44)
- No false "NXDOMAIN flood" alert from reverse DNS lookups, and an unanswered ARP probe is no longer
  reported as "ARP spoofing". (#39, #40)
- Port 1723 is named PPTP and flagged as a broken VPN. (#37)
- The TLS audit accepts a bare IP address. (#38)
- The pentest report explains missed slow-attack variants as detection thresholds, not gaps. (#42)
- Secret scan: placeholders such as "app-password" are ignored, and file paths use `/` on Windows. (#36, #43)

## 1.16.1 — 2026-11-26

### Added
- **Forgotten secrets**: finds passwords, keys and tokens in your own project folder and its git
  history. Values are always masked. (#35)
- Email domain check gives a "can someone spoof you?" verdict and checks the SPF 10-lookup limit,
  dead includes, DMARC subdomain policy and reports. (#34)

### Fixed
- DNS lookups retry over TCP when the UDP answer is truncated. (#34)

## 1.16.0 — 2026-11-25

### Added
- **Mac app: Live mode without a password.** A one-time setup gives your user access to packet capture,
  with Touch ID where available. An in-app screen explains why admin rights are needed. (#29, #30, #31)

### Fixed
- A locally built app is no longer replaced by the auto-updater. (#32)

## Earlier versions

Versions 1.0 to 1.15.0 are described on the [Releases page](https://github.com/Gyuri1999/netwatch/releases).
