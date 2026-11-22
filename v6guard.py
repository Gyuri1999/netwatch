"""🌐 Έλεγχος IPv6: «έχει το δίκτυο IPv6 χωρίς να το ξέρει κανείς;» + ψεύτικα Router Advertisements / DHCPv6.

Γιατί: πολλά router παρόχων έχουν το IPv6 ανοιχτό από το εργοστάσιο. Οι συσκευές παίρνουν ΔΗΜΟΣΙΑ (global) διεύθυνση
και — αν το IPv6 firewall του router είναι κλειστό — φαίνονται από το Internet, παρακάμπτοντας το «NAT firewall» του IPv4.
Επιπλέον, όποιος στείλει ένα Router Advertisement (RA) γίνεται default gateway / DNS για όλους (SLAAC attack, mitm6).

Τι κάνει:
  • Παθητικά (observe): διαβάζει τα ICMPv6 Router Advertisements (τύπος 134, RFC 4861 §4.2 · προτίμηση RFC 4191 ·
    RDNSS/DNSSL RFC 8106) από τα πρώτα 128 bytes του πλαισίου και τις απαντήσεις DHCPv6 (UDP 547 → 546, RFC 8415).
    Κρατά πίνακα router (ανά MAC). Όσα router φανούν στο «παράθυρο εκμάθησης» (ή έχουν τη MAC του IPv4 gateway)
    θεωρούνται έμπιστα· ΝΕΟ router αργότερα → ειδοποίηση. Ο τεχνικός μπορεί να δηλώσει ένα router έμπιστο.
  • Ενεργά, με ένα κουμπί (check): στέλνει ΕΝΑ Router Solicitation στο ff02::2 και μαζεύει τα RA για ~3 δευτ.,
    δείχνει τις IPv6 διευθύνσεις αυτού του υπολογιστή, δοκιμάζει αν βγαίνει στο Internet με IPv6 (TCP 443 σε
    2 σταθερές, γνωστές διευθύνσεις) και μαζεύει τις συσκευές του LAN με global διεύθυνση.
  • ΔΕΝ μπορεί να ελέγξει από μέσα αν το router κόβει τα εισερχόμενα IPv6 — το λέει καθαρά και δίνει τη δοκιμή
    που πρέπει να γίνει από έξω (κινητό με δεδομένα).
Δεν στέλνει ποτέ Router Advertisement, δεν αλλάζει τίποτα στο δίκτυο.
"""
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

LEARN = 600               # παράθυρο εκμάθησης (δευτ.) από το πρώτο RA που βλέπουμε
COOLDOWN = 3600           # ίδια ειδοποίηση το πολύ μία φορά την ώρα
MAX_ROUTERS = 64
MAX_EVENTS = 40
MAX_DEVICES = 200
MIN_INTERVAL = 10
RA_TYPE = 134
V6_TARGETS = (("2606:4700:4700::1111", "Cloudflare"), ("2001:4860:4860::8888", "Google"))  # σταθερό σύνολο, TCP 443
AAAA_NAMES = ("one.one.one.one", "dns.google")
PRF = {0: "medium", 1: "high", 2: "medium", 3: "low"}  # RFC 4191 §2.1: 01=High, 00=Medium, 11=Low, 10=δεσμευμένο (→ Medium)
T_RA = "Ψεύτικο Router Advertisement (IPv6)"
T_DHCP6 = "Ψεύτικος DHCPv6 server"
ULA = ipaddress.ip_network("fc00::/7")
GLOBAL = ipaddress.ip_network("2000::/3")
DOC = ipaddress.ip_network("2001:db8::/32")


def _norm(m):
    m = str(m or "").lower().replace("-", ":")
    return ":".join(x.zfill(2) for x in m.split(":")) if re.match(r"^[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}$", m) else ""


def _mac(b):
    return ":".join("%02x" % x for x in b)


def _u16(b, o):
    return (b[o] << 8) | b[o + 1]


def _u32(b, o):
    return (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]


def _ip6(b):
    return str(ipaddress.IPv6Address(bytes(b)))


# ───────── ανάλυση πλαισίων (καθαρές συναρτήσεις, δεν πετάνε ποτέ) ─────────
def l3_offset(raw):
    """Ethernet II (+ έως 2 ετικέτες 802.1Q/802.1ad) → (ethertype, θέση επόμενης επικεφαλίδας, vlan ή None)."""
    if not raw or len(raw) < 14:
        return None
    off, vlan, n = 12, None, 0
    et = _u16(raw, off)
    while et in (0x8100, 0x88A8, 0x9100) and n < 2:
        if len(raw) < off + 6:
            return None
        if vlan is None:
            vlan = _u16(raw, off + 2) & 0x0FFF
        off += 4
        et = _u16(raw, off)
        n += 1
    return et, off + 2, vlan


def _ip6_header(raw):
    """→ (θέση payload, next header, hop limit, src, dst, payload length, vlan) για IPv6 ΧΩΡΙΣ extension headers."""
    l3 = l3_offset(raw)
    if not l3 or l3[0] != 0x86DD:
        return None
    ip = l3[1]
    if len(raw) < ip + 40 or raw[ip] >> 4 != 6:
        return None
    return ip + 40, raw[ip + 6], raw[ip + 7], raw[ip + 8:ip + 24], raw[ip + 24:ip + 40], _u16(raw, ip + 4), l3[2]


def _dnssl(b):
    """Ονόματα DNS σε μορφή RFC 1035 (χωρίς συμπίεση), με όρια."""
    out, cur, i = [], [], 0
    while i < len(b) and len(out) < 4:
        n = b[i]
        i += 1
        if n == 0:
            if cur:
                out.append(".".join(cur)[:80])
            cur = []
            continue
        if n > 63 or i + n > len(b):
            break
        cur.append(re.sub(r"[^A-Za-z0-9_-]", "?", bytes(b[i:i + n]).decode("ascii", "replace")))
        i += n
    return out


def parse_ra(raw):
    """Πλαίσιο Ethernet → dict του Router Advertisement ή None. Μόνο ό,τι υπάρχει ολόκληρο στα bytes που έχουμε.

    RFC 4861 §4.2: type(1)=134 code(1)=0 checksum(2) cur-hop-limit(1) flags(1: M=0x80 O=0x40, Prf=0x18 κατά RFC 4191)
    router-lifetime(2) reachable(4) retrans(4) και μετά επιλογές type(1) len(1, σε 8άδες bytes).
    """
    try:
        raw = bytes(raw)
        h = _ip6_header(raw)
        if not h or h[1] != 58:
            return None
        ic, _nh, hlim, src, dst, plen, vlan = h
        if len(raw) < ic + 16 or raw[ic] != RA_TYPE or raw[ic + 1] != 0:
            return None
        fl = raw[ic + 5]
        ra = {"mac": _mac(raw[6:12]), "src": _ip6(src), "dst": _ip6(dst), "vlan": vlan, "hlim": hlim,
              "cur_hlim": raw[ic + 4], "M": bool(fl & 0x80), "O": bool(fl & 0x40), "pref": PRF[(fl >> 3) & 3],
              "lifetime": _u16(raw, ic + 6), "reachable": _u32(raw, ic + 8), "retrans": _u32(raw, ic + 12),
              "prefixes": [], "rdnss": [], "dnssl": [], "routes": [], "mtu": None, "slla": None, "truncated": False, "bad": False}
        end = ic + plen
        if end > len(raw):
            ra["truncated"], end = True, len(raw)
        o, n = ic + 16, 0
        while o + 2 <= end and n < 24:
            typ, ln = raw[o], raw[o + 1] * 8
            if ln == 0:  # RFC 4861 §4.6: μήκος 0 = άκυρο πακέτο
                ra["bad"] = True
                break
            if o + ln > end:
                ra["truncated"] = True
                break
            if typ == 1 and ln == 8:
                ra["slla"] = _mac(raw[o + 2:o + 8])
            elif typ == 3 and ln == 32 and len(ra["prefixes"]) < 8:
                pl = raw[o + 2]
                if pl <= 128:
                    net = ipaddress.IPv6Network((bytes(raw[o + 16:o + 32]), pl), strict=False)
                    ra["prefixes"].append({"prefix": str(net), "len": pl, "L": bool(raw[o + 3] & 0x80), "A": bool(raw[o + 3] & 0x40),
                                           "valid": _u32(raw, o + 4), "preferred": _u32(raw, o + 8)})
            elif typ == 5 and ln == 8:
                ra["mtu"] = _u32(raw, o + 4)
            elif typ == 25 and ln >= 24:  # RDNSS (RFC 8106 §5.1): reserved(2) lifetime(4) διευθύνσεις(16 η καθεμία)
                ra["rdnss_lifetime"] = _u32(raw, o + 4)
                for a in range(o + 8, o + ln - 15, 16):
                    if len(ra["rdnss"]) < 8:
                        ra["rdnss"].append(_ip6(raw[a:a + 16]))
            elif typ == 31 and ln >= 16:  # DNSSL (RFC 8106 §5.2)
                ra["dnssl"] = _dnssl(raw[o + 8:o + ln])
            elif typ == 24 and ln in (8, 16, 24) and len(ra["routes"]) < 8:  # Route Information (RFC 4191 §2.3)
                pl = raw[o + 2]
                if pl <= 128:
                    pb = bytes(raw[o + 8:o + ln]).ljust(16, b"\x00")
                    ra["routes"].append({"prefix": str(ipaddress.IPv6Network((pb, pl), strict=False)),
                                         "pref": PRF[(raw[o + 3] >> 3) & 3], "lifetime": _u32(raw, o + 4)})
            o += ln
            n += 1
        return ra
    except Exception:  # noqa: BLE001 — ό,τι κι αν έστειλε το δίκτυο
        return None


def is_stub(ra):
    """RA που ΔΕΝ ζητά να γίνει default gateway ούτε DNS και μιλά μόνο για ιδιωτικά (ULA) prefixes — π.χ. Thread border
    router (HomePod, Apple TV, Nest Hub, Matter hub). Συνηθισμένο στα σπίτια· δεν είναι επίθεση."""
    if ra.get("lifetime") or ra.get("rdnss") or ra.get("pref") == "high":
        return False
    try:
        nets = [ipaddress.IPv6Network(x["prefix"]) for x in (ra.get("routes") or []) + (ra.get("prefixes") or [])]
    except (ValueError, KeyError, TypeError):
        return False
    return all(n.prefixlen >= 7 and n.subnet_of(ULA) for n in nets)


def dhcp6_type(raw):
    """Τύπος μηνύματος DHCPv6 (RFC 8415 §7.3: 2=Advertise, 7=Reply) από πλαίσιο UDP 547→546 ή None."""
    try:
        raw = bytes(raw)
        h = _ip6_header(raw)
        if not h or h[1] != 17:
            return None
        u = h[0]
        if len(raw) < u + 9 or _u16(raw, u) != 547 or _u16(raw, u + 2) != 546:
            return None
        return raw[u + 8]
    except Exception:  # noqa: BLE001
        return None


# ───────── διευθύνσεις ─────────
def classify(addr, flags=()):
    """→ {"addr","scope","eui64","mac","kind"}: scope link-local/ula/global/…, kind eui64 / temp / stable."""
    try:
        a = ipaddress.IPv6Address(str(addr).split("%")[0].split("/")[0])
    except ValueError:
        return None
    b = a.packed
    if a.is_loopback:
        scope = "loopback"
    elif a.is_multicast:
        scope = "multicast"
    elif a.is_link_local:
        scope = "link-local"
    elif a in ULA:
        scope = "ula"
    elif a in GLOBAL:
        scope = "global"
    else:
        scope = "other"
    eui = b[11] == 0xFF and b[12] == 0xFE and scope in ("link-local", "ula", "global")  # τροποποιημένο EUI-64: …ff:fe… στη μέση
    mac = _mac(bytes([b[8] ^ 0x02]) + b[9:11] + b[13:16]) if eui else None
    fl = {str(f).lower() for f in flags or ()}
    kind = "eui64" if eui else "temp" if "temporary" in fl else "stable"
    return {"addr": str(a), "scope": scope, "eui64": eui, "mac": mac, "kind": kind, "deprecated": "deprecated" in fl}


def parse_ifconfig6(text):
    """`ifconfig` (macOS/BSD) → [{"addr","iface","flags"}]."""
    out, iface = [], None
    for line in (text or "").splitlines():
        m = re.match(r"^(\S+?):\s+flags=", line)
        if m:
            iface = m.group(1)
            continue
        m = re.match(r"^\s+inet6 ([0-9a-fA-F:.]+)(?:%\S+)? prefixlen (\d+)(.*)$", line)
        if m:
            out.append({"addr": m.group(1).lower(), "iface": iface, "flags": [w for w in m.group(3).split() if w.isalpha()]})
    return out[:64]


def parse_ip6_addr(text):
    """`ip -6 addr` (Linux) → [{"addr","iface","flags"}]."""
    out, iface = [], None
    for line in (text or "").splitlines():
        m = re.match(r"^\d+:\s+([^:@\s]+)", line)
        if m:
            iface = m.group(1)
            continue
        m = re.match(r"^\s+inet6 ([0-9a-fA-F:.]+)/(\d+) scope (\S+)(.*)$", line)
        if m:
            out.append({"addr": m.group(1).lower(), "iface": iface, "flags": m.group(4).split()})
    return out[:64]


def parse_neigh(text):
    """`ip -6 neigh` ή `ndp -an` ή `netsh interface ipv6 show neighbors` → [{"ip","mac","router"}]."""
    out, seen = [], set()
    for line in (text or "").splitlines():
        m = (re.match(r"^\s*([0-9a-fA-F:]+)(?:%\S+)?\s+dev \S+ lladdr ([0-9a-fA-F:]+)(.*)$", line)          # Linux
             or re.match(r"^\s*([0-9a-fA-F:]+)(?:%\S+)?\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\s(.*)$", line)  # macOS/BSD
             or re.match(r"^\s*([0-9a-fA-F:]+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s(.*)$", line))    # Windows
        if not m or ":" not in m.group(1):
            continue
        mac = _norm(m.group(2))
        try:
            ip = str(ipaddress.IPv6Address(m.group(1)))
        except ValueError:
            continue
        if not mac or ip in seen or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or mac.startswith("33:33"):
            continue
        seen.add(ip)
        rest = m.group(3)
        out.append({"ip": ip, "mac": mac, "router": bool(re.search(r"\brouter\b|\sR\b", rest))})
        if len(out) >= 256:
            break
    return out


def _run(cmd, timeout=6):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


class Net:
    """Τα πραγματικά πακέτα / εντολές. Στα tests μπαίνει ψεύτικο αντικείμενο με τις ίδιες μεθόδους."""

    def solicit(self, iface, timeout=3.0):
        """Ένα Router Solicitation (RFC 4861 §4.1) στο ff02::2 → λίστα πλαισίων (bytes) με όσα ICMPv6 ήρθαν. Θέλει root."""
        from scapy.all import AsyncSniffer, Ether, ICMPv6ND_RS, ICMPv6NDOptSrcLLAddr, IPv6, conf, get_if_hwaddr, sendp
        iface = iface or conf.iface
        mac = get_if_hwaddr(iface)
        # (το AsyncSniffer των νεότερων scapy δεν δέχεται timeout= — σταματάμε εμείς μετά από `timeout` δευτερόλεπτα)
        sn = AsyncSniffer(iface=iface, filter="icmp6", store=True)
        sn.start()
        time.sleep(0.4)
        if not getattr(sn, "running", True):  # δεν άνοιξε η καταγραφή (συνήθως: χωρίς δικαιώματα διαχειριστή)
            raise PermissionError("η καταγραφή πακέτων θέλει δικαιώματα διαχειριστή (Live)")
        try:
            sendp(Ether(src=mac, dst="33:33:00:00:00:02") / IPv6(dst="ff02::2", hlim=255) / ICMPv6ND_RS()
                  / ICMPv6NDOptSrcLLAddr(lladdr=mac), iface=iface, verbose=0)
            time.sleep(timeout)
        finally:
            try:
                sn.stop()
            except Exception:  # noqa: BLE001
                pass
        return [bytes(getattr(p, "original", None) or bytes(p)) for p in list(sn.results or [])[:200]]

    def addresses(self):
        if sys.platform == "win32":
            out = []
            try:
                for r in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
                    out.append({"addr": r[4][0].split("%")[0], "iface": None, "flags": []})
            except OSError:
                pass
            return out
        if sys.platform.startswith("linux"):
            r = parse_ip6_addr(_run(["ip", "-6", "addr"]))
            if r:
                return r
        return parse_ifconfig6(_run(["ifconfig"]))

    def neighbors(self):
        if sys.platform == "win32":
            return parse_neigh(_run(["netsh", "interface", "ipv6", "show", "neighbors"]))
        if sys.platform.startswith("linux"):
            return parse_neigh(_run(["ip", "-6", "neigh"]))
        return parse_neigh(_run(["ndp", "-an"]))

    def connect6(self, host, port=443, timeout=3.0):
        """→ ms ή None. Μόνο προς το σταθερό σύνολο V6_TARGETS."""
        if host not in [h for h, _ in V6_TARGETS]:
            return None
        t0 = time.time()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return round((time.time() - t0) * 1000, 1)
        except OSError:
            return None

    def aaaa(self, name):
        try:
            return sorted({r[4][0] for r in socket.getaddrinfo(name, 443, socket.AF_INET6, socket.SOCK_STREAM)})[:4]
        except (OSError, UnicodeError):
            return []


CISCO = """! RA Guard: Router Advertisements μόνο από τη θύρα του πραγματικού router
ipv6 nd raguard policy HOSTS
 device-role host
ipv6 nd raguard policy ROUTER
 device-role router
!
! DHCPv6 Guard: απαντήσεις DHCPv6 μόνο από τη θύρα του server/router
ipv6 dhcp guard policy CLIENTS
 device-role client
ipv6 dhcp guard policy SERVER
 device-role server
!
interface GigabitEthernet0/1
 description Uplink προς router
 ipv6 nd raguard attach-policy ROUTER
 ipv6 dhcp guard attach-policy SERVER
!
interface range GigabitEthernet0/2 - 24
 description Θύρες χρηστών
 ipv6 nd raguard attach-policy HOSTS
 ipv6 dhcp guard attach-policy CLIENTS
!
! Έλεγχος: show ipv6 nd raguard policy · show ipv6 snooping policies
end"""
_CISCO_EN = {"! RA Guard: Router Advertisements μόνο από τη θύρα του πραγματικού router": "! RA Guard: Router Advertisements only from the real router's port",
             "! DHCPv6 Guard: απαντήσεις DHCPv6 μόνο από τη θύρα του server/router": "! DHCPv6 Guard: DHCPv6 replies only from the server/router port",
             " description Uplink προς router": " description Uplink to router", " description Θύρες χρηστών": " description User ports",
             "! Έλεγχος: show ipv6 nd raguard policy · show ipv6 snooping policies": "! Verify: show ipv6 nd raguard policy · show ipv6 snooping policies"}


def switch_config(lang="el"):
    return "\n".join(_CISCO_EN.get(x, x) for x in CISCO.split("\n")) if lang == "en" else CISCO


# ───────── demo ─────────
_DM = {"isp": "a4:2b:b0:11:22:33", "rogue": "00:0c:29:5e:7a:10"}
_DP = "2a02:587:4c1a:2b00"


def _demo(now):
    isp = {"mac": _DM["isp"], "src": "fe80::a62b:b0ff:fe11:2233", "vlan": None, "hlim": 255, "cur_hlim": 64, "M": False, "O": True,
           "pref": "medium", "lifetime": 1800, "reachable": 0, "retrans": 0, "mtu": 1492, "slla": _DM["isp"],
           "prefixes": [{"prefix": _DP + "::/64", "len": 64, "L": True, "A": True, "valid": 86400, "preferred": 14400}],
           "rdnss": ["fe80::a62b:b0ff:fe11:2233"], "dnssl": ["home"], "routes": [], "truncated": False, "bad": False,
           "first": now - 6 * 86400, "last": now - 140, "n": 2590, "trusted": True, "by": "gw", "name": "Router παρόχου (192.168.1.1)"}
    rogue = {"mac": _DM["rogue"], "src": "fe80::20c:29ff:fe5e:7a10", "vlan": None, "hlim": 255, "cur_hlim": 64, "M": False, "O": True,
             "pref": "high", "lifetime": 1800, "reachable": 0, "retrans": 0, "mtu": None, "slla": _DM["rogue"],
             "prefixes": [{"prefix": "fd00:6d69:746d::/64", "len": 64, "L": True, "A": True, "valid": 300, "preferred": 120}],
             "rdnss": ["fe80::20c:29ff:fe5e:7a10"], "dnssl": [], "routes": [], "truncated": False, "bad": False,
             "first": now - 3 * 3600, "last": now - 3 * 3600 + 420, "n": 37, "trusted": False, "by": "", "name": "Laptop-Lab (192.168.1.77)"}
    events = [{"t": now - 3 * 3600, "kind": "rogue_ra", "sev": "high", "mac": _DM["rogue"], "src": rogue["src"],
               "el": f"Νέο router IPv6 ({_DM['rogue']}) άρχισε να στέλνει Router Advertisements με προτίμηση High και δικό του DNS "
                     f"({rogue['rdnss'][0]}) — οι συσκευές το προτιμούν από τον πραγματικό router (επίθεση SLAAC / mitm6).",
               "en": f"A new IPv6 router ({_DM['rogue']}) started sending Router Advertisements with High preference and its own DNS "
                     f"({rogue['rdnss'][0]}) — devices prefer it over the real router (SLAAC attack / mitm6)."}]
    addrs = [{"addr": "fe80::1ceb:13da:ea5a:78d8", "iface": "en0", "flags": ["secured"]},
             {"addr": _DP + ":1833:ae14:a598:f043", "iface": "en0", "flags": ["autoconf", "secured"]},
             {"addr": _DP + ":14a6:998:4310:dfc0", "iface": "en0", "flags": ["autoconf", "temporary"]}]
    devices = [
        {"ip": _DP + ":be24:11ff:fe3a:9c01", "mac": "bc:24:11:3a:9c:01", "name": "Κάμερα εισόδου", "dicon": "📷"},
        {"ip": _DP + ":211:32ff:fe8d:4410", "mac": "00:11:32:8d:44:10", "name": "NAS Synology", "dicon": "🗄"},
        {"ip": _DP + ":8c1f:6a02:77d1:e3b9", "mac": "f0:18:98:22:10:aa", "name": "MacBook Μαρίας", "dicon": "💻"},
        {"ip": _DP + ":59e2:b7a1:400c:91f5", "mac": "3c:22:fb:70:01:9d", "name": "iPhone", "dicon": "📱"},
        {"ip": _DP + ":d0c5:3ff2:8a11:6e07", "mac": "d8:3a:dd:41:be:02", "name": "Smart TV", "dicon": "📺"}]
    res = {"t": now - 95, "iface": "en0",
           "ra": {"status": "ok", "n": 1, "el": "Απάντησε 1 router στο Router Solicitation.", "en": "1 router answered the Router Solicitation."},
           "addrs": addrs, "neigh": [{"ip": d["ip"], "mac": d["mac"], "router": False} for d in devices],
           "inet": {"tcp": [{"host": h, "name": n, "ms": ms} for (h, n), ms in zip(V6_TARGETS, (21.4, 24.9))], "aaaa": True, "ok": True}}
    return {isp["mac"]: isp, rogue["mac"]: rogue}, events, res, devices


class V6Guard:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time, net=None):
        self.state, self.demo, self.clock = state, demo, clock
        self.net = net or Net()
        self.path = os.path.join(data_dir, "v6guard.json") if data_dir else None
        self.on_save = None
        self.lock = threading.RLock()
        self.busy = False
        self.routers = {}      # mac → τελευταίο RA + first/last/n
        self.dhcp6 = {}        # mac → {"src","first","last","n","type"}
        self.trusted = {}      # mac → {"t","by": learn/gw/user,"src"}
        self.learn_until = 0
        self.fw_ok = None      # {"t"} όταν ο τεχνικός επιβεβαίωσε από έξω ότι το IPv6 firewall κόβει τα εισερχόμενα
        self.events = []
        self.res = None
        self._alerted = {}
        self._demo_devices = []
        if demo:
            self.routers, self.events, self.res, self._demo_devices = _demo(self.clock())
            self.trusted = {_DM["isp"]: {"t": self.clock() - 6 * 86400, "by": "gw", "src": self.routers[_DM["isp"]]["src"]}}
        else:
            self._load()

    # ── αποθήκευση ──
    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                j = json.load(f)
            self.trusted = {_norm(k): {"t": float(v.get("t") or 0), "by": str(v.get("by") or "learn")[:8], "src": str(v.get("src") or "")[:45]}
                            for k, v in (j.get("trusted") or {}).items() if _norm(k) and isinstance(v, dict)}
            self.learn_until = float(j.get("learn_until") or 0)
            self.fw_ok = {"t": float(j["fw_ok"]["t"])} if isinstance(j.get("fw_ok"), dict) else None
            self.events = [e for e in (j.get("events") or []) if isinstance(e, dict)][-MAX_EVENTS:]
        except (OSError, ValueError, TypeError, AttributeError, KeyError):
            pass

    def _save(self):
        if not self.path or self.demo:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"trusted": self.trusted, "learn_until": self.learn_until, "fw_ok": self.fw_ok, "events": self.events[-MAX_EVENTS:]}, f)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    # ── βοηθητικά ──
    def _hosts(self):
        st = self.state
        if st is None:
            return []
        lock = getattr(st, "lock", None)
        try:
            if lock:
                lock.acquire()
            return [dict(h) for h in (getattr(st, "hosts", None) or {}).values() if isinstance(h, dict)]
        except RuntimeError:
            return []
        finally:
            if lock:
                lock.release()

    def _gw_mac(self):
        st = self.state
        gw = getattr(st, "gateway", None) if st is not None else None
        if not gw:
            return ""
        h = (getattr(st, "hosts", None) or {}).get(gw) or {}
        return _norm(h.get("mac") or (getattr(st, "arp_first", None) or {}).get(gw) or "")

    def _trust_check(self, mac, src, t):
        """Έμπιστο router; (μαθαίνει στο παράθυρο εκμάθησης ή αν έχει τη MAC του IPv4 gateway)."""
        if mac in self.trusted:
            return True
        by = None
        if mac and mac == self._gw_mac():
            by = "gw"
        else:
            if not self.trusted and not self.learn_until:
                self.learn_until = t + LEARN
            if t < self.learn_until:
                by = "learn"
        if not by:
            return False
        self.trusted[mac] = {"t": t, "by": by, "src": src}
        if not self.learn_until:
            self.learn_until = t  # ξέρουμε το πραγματικό router από το IPv4 → δεν χρειάζεται εκμάθηση
        self._save()
        return True

    def _event(self, kind, sev, mac, src, el, en, t, typ=T_RA):
        """Γεγονός στην καρτέλα + ειδοποίηση (μία ανά COOLDOWN για το ίδιο router/είδος)."""
        k = (kind, mac)
        if k in self._alerted and t - self._alerted[k] < COOLDOWN:
            return False
        self._alerted[k] = t
        if len(self._alerted) > 500:
            self._alerted.pop(next(iter(self._alerted)))
        self.events.append({"t": t, "kind": kind, "sev": sev, "mac": mac, "src": src, "el": el, "en": en})
        del self.events[:-MAX_EVENTS]
        st = self.state
        if sev in ("high", "med") and st is not None and hasattr(st, "alert") and not self.demo:
            try:
                st.alert(typ, sev, src or mac, "LAN (IPv6)", el, t, key=("v6", kind, mac), cooldown=COOLDOWN, mark=False)
            except Exception:  # noqa: BLE001
                pass
        self._save()
        return True

    def _name(self, mac):
        """Όνομα συσκευής από τη MAC (αν το NetWatch την ξέρει από το IPv4)."""
        st = self.state
        try:
            for h in list((getattr(st, "hosts", None) or {}).values()) if st is not None else ():
                if isinstance(h, dict) and _norm(h.get("mac")) == mac and ":" not in str(h.get("ip")):
                    names = sorted(h.get("names") or ())
                    return ((h.get("alias") or (names[0] if names else "") or "") + f" ({h.get('ip')})").strip()
        except (AttributeError, TypeError, RuntimeError):
            pass
        return ""

    # ── παθητικά ──
    def observe(self, P, t, raw=None):
        """Για κάθε πακέτο. Φθηνό: γυρνά αμέσως αν δεν είναι ICMPv6 ή DHCPv6."""
        try:
            proto = P.get("proto")
            if proto == "ICMPv6":
                raw = raw or P.get("_raw") or self._raw(P)
                if not raw or len(raw) < 70:
                    return
                ra = parse_ra(raw)
                if ra:
                    with self.lock:
                        self._ra(ra, t)
            elif proto == "UDP" and P.get("sp") == 547 and P.get("dp") == 546:
                raw = raw or P.get("_raw") or self._raw(P)
                mt = dhcp6_type(raw) if raw else None
                if mt in (2, 7) or (mt is None and not raw):
                    with self.lock:
                        self._dhcp6(_norm(P.get("smac")), str(P.get("src") or ""), mt, t)
        except Exception:  # noqa: BLE001 — ποτέ δεν ρίχνουμε τη σύλληψη
            pass

    @staticmethod
    def _raw(P):
        """Το detect() έχει ήδη βγάλει το `_raw` από το P — το ξαναβρίσκουμε από τη μνήμη πακέτων (μόνο για υποψήφια RA/DHCPv6)."""
        src, dst = str(P.get("src") or ""), str(P.get("dst") or "")
        if not src.startswith("fe80") or P.get("_id") is None:
            return None
        if P.get("proto") == "ICMPv6" and dst.startswith("ff02") and dst != "ff02::1":
            return None  # NS/MLD κ.λπ. — τα RA πάνε στο ff02::1 ή απευθείας στον host
        try:
            import packets
            it = packets.get(src, dst, pid=P["_id"])
            return it.get("raw") if it and not it.get("approx") else None
        except Exception:  # noqa: BLE001
            return None

    def _ra(self, ra, t):
        if ra.get("bad") or ra["hlim"] != 255 or not ra["src"].startswith("fe80"):
            return  # RFC 4861 §6.1.2: οι hosts τα πετάνε (hop limit ≠ 255 = ήρθε από άλλο δίκτυο)
        mac = ra["mac"]
        prev = self.routers.get(mac)
        if prev is None and len(self.routers) >= MAX_ROUTERS:
            self.routers.pop(min(self.routers, key=lambda k: self.routers[k].get("last", 0)))
        cur = dict(ra, first=(prev or {}).get("first", t), last=t, n=(prev or {}).get("n", 0) + 1, stub=is_stub(ra))
        if ra["truncated"] and prev:  # το RDNSS συχνά δεν χωρά στα 128 bytes — κράτα ό,τι ξέραμε
            for k in ("rdnss", "dnssl", "routes"):
                if not cur[k]:
                    cur[k] = prev.get(k) or []
            if not cur["prefixes"]:
                cur["prefixes"] = prev.get("prefixes") or []
        self.routers[mac] = cur
        # kill-RA: lifetime 0 «εκ μέρους» του έμπιστου router (ίδια link-local ή SLLA) αλλά από άλλη MAC
        victim = next((m for m, tr in self.trusted.items() if m != mac and (tr.get("src") == ra["src"] or ra.get("slla") == m)), None)
        if ra["lifetime"] == 0 and victim and mac not in self.trusted:
            self._event("kill_ra", "high", mac, ra["src"],
                        f"Η συσκευή με MAC {mac} έστειλε Router Advertisement με διάρκεια 0 στο όνομα του πραγματικού router "
                        f"({victim}) — προσπαθεί να τον «σβήσει» από τις συσκευές ώστε να περάσει η κίνηση IPv6 από αλλού (kill-RA).",
                        f"The device with MAC {mac} sent a Router Advertisement with lifetime 0 on behalf of the real router "
                        f"({victim}) — it is trying to remove it from devices so IPv6 traffic goes elsewhere (kill-RA).", t)
            return
        if self._trust_check(mac, ra["src"], t):
            if prev and not ra["truncated"] and prev.get("rdnss") and ra["rdnss"] and set(prev["rdnss"]) != set(ra["rdnss"]):
                self._event("rdnss", "med", mac, ra["src"],
                            f"Το router IPv6 {ra['src']} ({mac}) άλλαξε τον DNS που μοιράζει (RDNSS): {', '.join(prev['rdnss'])} → "
                            f"{', '.join(ra['rdnss'])}. Αν δεν το άλλαξες εσύ, κάποιος στέλνει RA με τη MAC του router.",
                            f"IPv6 router {ra['src']} ({mac}) changed the DNS it hands out (RDNSS): {', '.join(prev['rdnss'])} → "
                            f"{', '.join(ra['rdnss'])}. If you did not change it, someone is sending RAs with the router's MAC.", t)
            elif prev and prev.get("lifetime") and ra["lifetime"] == 0:
                self._event("gone", "low", mac, ra["src"],
                            f"Το router IPv6 {ra['src']} ανακοίνωσε ότι σταματά (διάρκεια 0) — φυσιολογικό σε επανεκκίνηση.",
                            f"IPv6 router {ra['src']} announced it is going away (lifetime 0) — normal on reboot.", t)
            return
        who = self._name(mac)
        who_el, who_en = (f" — συσκευή: {who}" if who else ""), (f" — device: {who}" if who else "")
        dns_el = f" Μοιράζει DNS {', '.join(ra['rdnss'])}." if ra["rdnss"] else ""
        dns_en = f" It hands out DNS {', '.join(ra['rdnss'])}." if ra["rdnss"] else ""
        if cur["stub"]:
            return  # δεν ζητά να γίνει gateway ούτε DNS (π.χ. HomePod / Nest Hub: Thread border router με ULA prefix)
        if ra["pref"] == "high":
            self._event("rogue_high", "high", mac, ra["src"],
                        f"Νέο router IPv6 ({mac}, {ra['src']}) στέλνει Router Advertisements με προτίμηση High — οι συσκευές θα το "
                        f"προτιμήσουν από τον πραγματικό router (επίθεση SLAAC / mitm6).{dns_el}{who_el}",
                        f"A new IPv6 router ({mac}, {ra['src']}) is sending Router Advertisements with High preference — devices will "
                        f"prefer it over the real router (SLAAC attack / mitm6).{dns_en}{who_en}", t)
        else:
            self._event("rogue_ra", "high", mac, ra["src"],
                        f"Νέο router IPv6 ({mac}, {ra['src']}) άρχισε να στέλνει Router Advertisements. Αν δεν έβαλες εσύ δεύτερο router/"
                        f"mesh, κάποιος προσπαθεί να γίνει gateway για το IPv6.{dns_el}{who_el}",
                        f"A new IPv6 router ({mac}, {ra['src']}) started sending Router Advertisements. If you did not add a second "
                        f"router/mesh, someone is trying to become the IPv6 gateway.{dns_en}{who_en}", t)

    def _dhcp6(self, mac, src, mt, t):
        if not mac:
            return
        d = self.dhcp6.get(mac)
        if d is None:
            if len(self.dhcp6) >= MAX_ROUTERS:
                self.dhcp6.pop(next(iter(self.dhcp6)))
            d = self.dhcp6[mac] = {"mac": mac, "src": src, "first": t, "n": 0}
        d.update(last=t, n=d["n"] + 1, src=src, type={2: "Advertise", 7: "Reply"}.get(mt, ""))
        if self._trust_check(mac, src, t):
            return
        who = self._name(mac)
        self._event("dhcp6", "high", mac, src,
                    f"Η συσκευή {mac} ({src}) απαντά ως DHCPv6 server χωρίς να είναι το router — έτσι δουλεύει το mitm6: δίνει δικό της "
                    f"DNS μέσω IPv6 και υποκλέπτει συνδέσεις/κωδικούς Windows." + (f" Συσκευή: {who}" if who else ""),
                    f"Device {mac} ({src}) answers as a DHCPv6 server although it is not the router — this is how mitm6 works: it hands "
                    f"out its own DNS over IPv6 and intercepts Windows logins." + (f" Device: {who}" if who else ""), t, typ=T_DHCP6)

    # ── ενεργός έλεγχος ──
    def check(self):
        """Τρέχει τον έλεγχο (μπλοκάρει ~5 δευτ.). → view()."""
        with self.lock:
            if self.busy:
                return self.view()
            self.busy = True
        self._check()
        return self.view()

    def _check(self):
        try:
            now = self.clock()
            if self.demo:
                self.res = dict(self.res, t=now)
                return None
            iface = getattr(self.state, "iface", None) if self.state is not None else None
            r = {"t": now, "iface": iface}
            # (α) Router Solicitation
            try:
                frames = self.net.solicit(iface)
                n = 0
                for f in (frames or [])[:200]:
                    ra = parse_ra(f)
                    if ra:
                        n += 1
                        with self.lock:
                            self._ra(ra, now)
                r["ra"] = ({"status": "ok", "n": n, "el": f"Απάντησαν {n} Router Advertisement(s) στο Router Solicitation.",
                            "en": f"{n} Router Advertisement(s) answered the Router Solicitation."} if n else
                           {"status": "none", "n": 0, "el": "Κανένα router δεν απάντησε στο Router Solicitation — δεν φαίνεται να υπάρχει IPv6 router σε αυτό το δίκτυο.",
                            "en": "No router answered the Router Solicitation — there seems to be no IPv6 router on this network."})
            except Exception as e:  # noqa: BLE001
                perm = isinstance(e, PermissionError) or re.search(r"permi|not permitted|root|admin", str(e), re.I)
                r["ra"] = {"status": "err", "n": 0,
                           "el": ("Δεν επιτρέπεται η αποστολή πακέτων: το Router Solicitation θέλει δικαιώματα διαχειριστή (root). "
                                  "Τρέξε το NetWatch με sudo ή δες παρακάτω ό,τι φάνηκε παθητικά." if perm
                                  else "Δεν στάλθηκε το Router Solicitation: " + str(e)[:140]),
                           "en": ("Sending packets is not permitted: the Router Solicitation needs administrator (root) rights. "
                                  "Run NetWatch with sudo, or see below what was seen passively." if perm
                                  else "Router Solicitation was not sent: " + str(e)[:140])}
            # (β) διευθύνσεις αυτού του υπολογιστή · (δ) γείτονες
            try:
                r["addrs"] = [a for a in (self.net.addresses() or []) if isinstance(a, dict)][:64]
            except Exception:  # noqa: BLE001
                r["addrs"] = []
            try:
                r["neigh"] = [n for n in (self.net.neighbors() or []) if isinstance(n, dict)][:256]
            except Exception:  # noqa: BLE001
                r["neigh"] = []
            # (γ) Internet με IPv6
            tcp = []
            for host, name in V6_TARGETS:
                try:
                    ms = self.net.connect6(host, 443, 3.0)
                except Exception:  # noqa: BLE001
                    ms = None
                tcp.append({"host": host, "name": name, "ms": ms})
            aaaa = False
            for nm in AAAA_NAMES:
                try:
                    if self.net.aaaa(nm):
                        aaaa = True
                        break
                except Exception:  # noqa: BLE001
                    pass
            r["inet"] = {"tcp": tcp, "aaaa": aaaa, "ok": any(x["ms"] is not None for x in tcp)}
            self.res = r
            return None
        finally:
            self.busy = False

    def _bg(self):
        try:
            self.check()
        except Exception:  # noqa: BLE001
            self.busy = False

    # ── προβολή ──
    def _my_addrs(self):
        out = []
        for a in (self.res or {}).get("addrs") or []:
            c = classify(a.get("addr"), a.get("flags"))
            if c and c["scope"] in ("link-local", "ula", "global"):
                c["iface"] = a.get("iface")
                out.append(c)
        return out

    def _devices(self, mine):
        """Συσκευές του LAN με global IPv6: από την κίνηση (state.hosts) και από τον πίνακα γειτόνων."""
        if self.demo:
            rows = [dict(d, src="demo") for d in self._demo_devices]
        else:
            hosts = self._hosts()
            by_mac = {}
            for h in hosts:
                m = _norm(h.get("mac"))
                if m and ":" not in str(h.get("ip")):
                    by_mac.setdefault(m, h)
            rows, seen = [], set()

            def add(ip, mac, src, me=False):
                c = classify(ip)
                if not c or c["scope"] != "global" or c["addr"] in seen or ipaddress.IPv6Address(c["addr"]) in DOC:
                    return
                seen.add(c["addr"])
                mac = _norm(mac) or (c["mac"] or "")
                h4 = by_mac.get(mac) or {}
                names = sorted(h4.get("names") or ())
                dt = {}
                try:
                    dt = self.state._dtype(h4) if h4 and hasattr(self.state, "_dtype") else {}
                except Exception:  # noqa: BLE001
                    dt = {}
                rows.append({"ip": c["addr"], "mac": mac, "src": src, "me": me, "ip4": h4.get("ip") or "",
                             "name": dt.get("alias") or h4.get("alias") or (names[0] if names else "") or "", "dicon": dt.get("dicon") or ""})

            for h in hosts:
                ip = str(h.get("ip") or "")
                if ":" in ip and (h.get("kind") in (None, "local") or h.get("mac") or h.get("me")):
                    add(ip, h.get("mac"), "traffic", bool(h.get("me")) or ip in mine)
            for n in (self.res or {}).get("neigh") or []:
                add(n.get("ip"), n.get("mac"), "ndp", n.get("ip") in mine)
        for r in rows:
            c = classify(r["ip"]) or {}
            r["eui64"], r["me"] = bool(c.get("eui64")), bool(r.get("me"))
        rows.sort(key=lambda x: (not x["eui64"], x["ip"]))
        return rows[:MAX_DEVICES]

    def view(self):
        now = self.clock()
        with self.lock:
            routers = [dict(r, trusted=m in self.trusted, by=(self.trusted.get(m) or {}).get("by", ""),
                            name=r.get("name") or self._name(m)) for m, r in self.routers.items()]
            dhcp6 = [dict(d, trusted=m in self.trusted) for m, d in self.dhcp6.items()]
            events = [dict(e) for e in self.events[-MAX_EVENTS:]][::-1]
            trusted = {m: dict(v) for m, v in self.trusted.items()}
        routers.sort(key=lambda r: (r["trusted"], -r.get("last", 0)))
        res = self.res or {}
        addrs = self._my_addrs()
        mine = {a["addr"] for a in addrs}
        devices = self._devices(mine)
        others = [d for d in devices if not d["me"]]
        live = [r for r in routers if r.get("lifetime") and now - r.get("last", 0) < 3 * 3600]
        rogue = [r for r in routers if not r["trusted"] and not r.get("stub")]
        recent_bad = [e for e in events if e.get("sev") == "high" and now - e.get("t", 0) < 86400]
        has_global = any(a["scope"] == "global" for a in addrs)
        on = bool(live or has_global or others)
        confirmed = bool(routers) and all(r["by"] in ("user", "gw") for r in routers if r["trusted"]) and any(r["trusted"] for r in routers)
        if not on and not res and not routers:
            status = "unknown"
        elif not on:
            status = "off"
        elif self.fw_ok and confirmed and not recent_bad and not rogue:
            status = "managed"
        else:
            status = "unmanaged"
        VER = {"unknown": ("info", "Δεν ξέρω ακόμα αν το δίκτυο έχει IPv6 — πάτα «Έλεγχος».", "I don't know yet whether this network has IPv6 — press “Check”."),
               "off": ("ok", "Το IPv6 είναι κλειστό σε αυτό το δίκτυο — δεν υπάρχει κάτι να προστατέψεις (ούτε κάτι να ξεχάσεις).",
                       "IPv6 is off on this network — nothing to protect (and nothing to forget)."),
               "managed": ("ok", "Το IPv6 είναι ανοιχτό και ελεγμένο: γνωστό router, firewall επιβεβαιωμένο από έξω.",
                           "IPv6 is on and managed: known router, firewall confirmed from outside."),
               "unmanaged": ("bad" if (recent_bad or rogue) else "warn",
                             "Το IPv6 είναι ανοιχτό αλλά κανείς δεν το έχει ελέγξει — οι συσκευές μπορεί να φαίνονται από το Internet.",
                             "IPv6 is on but nobody has checked it — devices may be reachable from the Internet.")}
        lvl, vel, ven = VER[status]
        if recent_bad or rogue:
            vel, ven = ("Βρέθηκε ψεύτικο ή άγνωστο router IPv6 στο δίκτυο — δες τα γεγονότα παρακάτω.",
                        "A rogue or unknown IPv6 router was seen on the network — see the events below.")
            lvl = "bad"
        eui = [d for d in others if d["eui64"]]
        chk = []

        def add(cid, level, el, en):
            chk.append({"id": cid, "level": level, "el": el, "en": en})

        if status == "unknown":
            add("ra", "info", "Δεν έχω δει Router Advertisement ακόμα.", "No Router Advertisement seen yet.")
        elif not routers:
            add("ra", "ok", "Κανένα router δεν μοιράζει IPv6 (κανένα Router Advertisement).", "No router is handing out IPv6 (no Router Advertisement).")
        elif rogue:
            add("ra", "bad", f"{len(rogue)} άγνωστο/α router στέλνουν Router Advertisements: {', '.join(r['mac'] for r in rogue[:4])}.",
                f"{len(rogue)} unknown router(s) are sending Router Advertisements: {', '.join(r['mac'] for r in rogue[:4])}.")
        elif not confirmed:
            add("ra", "warn", "Το router IPv6 το έμαθα αυτόματα (το πρώτο που είδα). Επιβεβαίωσε ότι είναι το δικό σου και πάτα «Έμπιστο».",
                "I learned the IPv6 router automatically (the first one seen). Confirm it is yours and press “Trusted”.")
        else:
            add("ra", "ok", "Router Advertisements μόνο από γνωστό, επιβεβαιωμένο router.", "Router Advertisements only from a known, confirmed router.")
        if on:
            if self.fw_ok:
                add("fw", "ok", "Το IPv6 firewall του router επιβεβαιώθηκε από έξω (" + time.strftime("%d/%m/%Y", time.localtime(self.fw_ok["t"])) + ").",
                    "The router's IPv6 firewall was confirmed from outside (" + time.strftime("%d/%m/%Y", time.localtime(self.fw_ok["t"])) + ").")
            else:
                add("fw", "warn", "Δεν μπορώ να δω από μέσα αν το router κόβει τα εισερχόμενα IPv6. Κάνε τη δοκιμή από έξω (παρακάτω) και σημείωσέ το.",
                    "From inside I cannot tell whether the router blocks inbound IPv6. Run the outside test (below) and tick it.")
            if others:
                add("dev", "warn" if not self.fw_ok else "info", f"{len(others)} συσκευές του LAN έχουν δημόσια (global) διεύθυνση IPv6 — χωρίς IPv6 firewall φαίνονται απευθείας από το Internet.",
                    f"{len(others)} LAN devices have a public (global) IPv6 address — without an IPv6 firewall they are directly reachable from the Internet.")
            if eui:
                add("eui", "warn", f"{len(eui)} συσκευές χρησιμοποιούν διεύθυνση EUI-64 (η MAC φαίνεται μέσα στη διεύθυνση): σταθερή, εύκολη να βρεθεί και να παρακολουθηθεί.",
                    f"{len(eui)} devices use an EUI-64 address (the MAC is visible inside the address): stable, easy to find and track.")
            mine_eui = [a for a in addrs if a["scope"] == "global" and a["eui64"]]
            if mine_eui:
                add("me", "warn", "Αυτός ο υπολογιστής έχει global διεύθυνση EUI-64 — άνοιξε τις «προσωρινές διευθύνσεις» (privacy extensions).",
                    "This computer has a global EUI-64 address — enable temporary addresses (privacy extensions).")
            ms = [r for r in live if r.get("M")]
            if ms:
                add("m", "info", "Το router ζητά DHCPv6 (σημαία M) — οι διευθύνσεις δίνονται από DHCPv6 server.", "The router asks for DHCPv6 (M flag) — addresses come from a DHCPv6 server.")
            inet = res.get("inet")
            if inet:
                add("inet", "info", "Αυτός ο υπολογιστής βγαίνει στο Internet με IPv6." if inet.get("ok") else "Αυτός ο υπολογιστής ΔΕΝ βγαίνει στο Internet με IPv6 (μόνο τοπικά).",
                    "This computer reaches the Internet over IPv6." if inet.get("ok") else "This computer does NOT reach the Internet over IPv6 (local only).")
        if any(not d["trusted"] for d in dhcp6):
            add("dhcp6", "bad", "Άγνωστος DHCPv6 server απαντά στο δίκτυο (τεχνική mitm6).", "An unknown DHCPv6 server is answering on the network (mitm6 technique).")
        sample = next((d for d in others if d["eui64"]), others[0] if others else None)
        return {"demo": self.demo, "busy": self.busy, "checked": res.get("t") or 0, "iface": res.get("iface"), "status": status,
                "verdict": {"level": lvl, "el": vel, "en": ven}, "checklist": chk, "routers": routers, "dhcp6": dhcp6, "events": events,
                "trusted": trusted, "learning": bool(self.learn_until and now <= self.learn_until), "learn_until": self.learn_until,
                "fw_ok": self.fw_ok, "ra": res.get("ra"), "addrs": addrs, "inet": res.get("inet"), "devices": devices,
                "counts": {"devices": len(others), "eui64": len(eui), "rogue": len(rogue)},
                "ext_test": {"addr": sample["ip"] if sample else "", "name": (sample or {}).get("name", "")},
                "config": switch_config(), "config_en": switch_config("en")}

    # ── API ──
    def trust(self, mac, on=True):
        mac = _norm(mac)
        if not mac:
            return False
        with self.lock:
            if on:
                src = (self.routers.get(mac) or self.dhcp6.get(mac) or {}).get("src", "")
                self.trusted[mac] = {"t": self.clock(), "by": "user", "src": src}
            else:
                self.trusted.pop(mac, None)
                if not self.learn_until:
                    self.learn_until = 1  # μην ξανανοίξει το παράθυρο εκμάθησης
            self._save()
        return True

    def api(self, method, sub, q, body):
        if method == "GET":
            return (200, self.view()) if sub == "" else (404, {"error": "not found"})
        if sub == "check":
            if self.demo:
                return 200, self.check()
            with self.lock:
                if self.busy:
                    return 200, self.view()
                if self.res and self.clock() - self.res.get("t", 0) < MIN_INTERVAL:
                    return 200, self.view()
            threading.Thread(target=self._bg, daemon=True).start()
            return 200, dict(self.view(), busy=True)
        if sub in ("trust", "untrust"):
            if self.demo:
                return 200, self.view()
            if not self.trust((body or {}).get("mac"), sub == "trust"):
                return 400, {"error": "Άκυρη διεύθυνση MAC."}
            return 200, self.view()
        if sub == "confirm":  # ο τεχνικός έκανε τη δοκιμή από έξω
            if not self.demo:
                with self.lock:
                    self.fw_ok = {"t": self.clock()} if (body or {}).get("fw", True) else None
                    self._save()
            return 200, self.view()
        return 404, {"error": "not found"}
