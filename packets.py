"""🔬 «Εξήγησέ μου αυτό το πακέτο»: κρατά λίγα πρόσφατα πακέτα ανά ζεύγος συσκευών και τα «σπάει» σε επίπεδα OSI,
με εξήγηση για κάθε πεδίο και σύνδεσμο στο μάθημα CCNA.

Ιδιωτικότητα: κρατάμε μόνο τα πρώτα 128 bytes (ουσιαστικά τις κεφαλίδες) στη μνήμη, ποτέ στον δίσκο,
και από το payload δείχνουμε μόνο το μήκος του — ποτέ περιεχόμενο (θα μπορούσε να είναι κωδικός ή cookie).
"""
import re
import threading
import time

KEEP_BYTES = 128
MAX_PAIRS = 2000
PER_PAIR = 3

_lock = threading.Lock()
_pairs = {}  # (src, dst) → [{t, P, raw}]


def remember(P, raw=None):
    if not P.get("src") or not P.get("dst"):
        return
    key = (P["src"], P["dst"])
    item = {"t": P.get("t") or time.time(), "P": {k: v for k, v in P.items() if k not in ("cred", "raw")},
            "raw": bytes(raw[:KEEP_BYTES]) if raw else None, "id": P.get("_id")}
    with _lock:
        lst = _pairs.pop(key, [])  # pop+insert → τα πιο πρόσφατα στο τέλος (LRU)
        lst.append(item)
        del lst[:-PER_PAIR]
        _pairs[key] = lst
        while len(_pairs) > MAX_PAIRS:
            _pairs.pop(next(iter(_pairs)))


def clear():
    with _lock:
        _pairs.clear()


def flows(ip, limit=15):
    """Οι πιο πρόσφατες «συνομιλίες» μιας IP, για να διαλέξεις πακέτο."""
    out = []
    with _lock:
        for (s, d), lst in reversed(list(_pairs.items())):
            if ip in (s, d):
                it = lst[-1]
                P = it["P"]
                out.append({"src": s, "dst": d, "proto": P.get("proto"), "sp": P.get("sp"), "dp": P.get("dp"),
                            "flags": P.get("flags"), "len": P.get("len"), "t": it["t"], "real": it["raw"] is not None,
                            "n": len(lst)})
                if len(out) >= limit:
                    break
    return out


def get(src, dst, idx=-1, pid=None):
    """Το πακέτο με αυτό το id (από τη λίστα 📦 Πακέτα) ή, αν έχει «φύγει», το πιο πρόσφατο του ζεύγους."""
    with _lock:
        lst = _pairs.get((src, dst)) or []
        if pid is not None:
            for it in reversed(lst):
                if it.get("id") == pid:
                    return dict(it)
            return {**lst[-1], "approx": True} if lst else None
        return dict(lst[idx]) if lst and -len(lst) <= idx < len(lst) else None


def conversation(recent, a, b, proto=None, pa=None, pb=None, limit=60):
    """🔁 Τα πακέτα μιας σύνδεσης (και προς τις δύο κατευθύνσεις) για το διάγραμμα «σκάλα».
    a:pa ↔ b:pb· για ARP/ICMP χωρίς θύρες. Μόνο κεφαλίδες (σημαίες, μέγεθος, χρόνος) — ποτέ περιεχόμενο."""
    out = []
    for P in list(recent):
        s, d = P.get("src"), P.get("dst")
        if {s, d} != {a, b} or s == d:
            continue
        pr = P.get("proto")
        if proto and pr != proto:
            continue
        if pr in ("TCP", "UDP") and pa is not None and pb is not None:
            sp, dp = P.get("sp"), P.get("dp")
            if not ((s == a and sp == pa and dp == pb) or (s == b and sp == pb and dp == pa)):
                continue
        it = {"t": round(P.get("t") or 0, 4), "dir": "ab" if s == a else "ba", "p": pr, "l": P.get("len"),
              "f": P.get("flags") or {1: "who-has", 2: "is-at"}.get((P.get("arp") or {}).get("op"), "")}
        if P.get("icmp_type") is not None:
            it["ic"] = P["icmp_type"]
        if P.get("dns_q"):
            it["n"] = str(P["dns_q"][0])[:80]
        elif P.get("dns_resp"):
            it["n"] = "↩"
        elif P.get("sni"):
            it["n"] = str(P["sni"])[:80]
        out.append(it)
    return out[-limit:]


def synth(P):
    """Demo/όταν δεν έχουμε bytes: φτιάχνει ένα ρεαλιστικό πακέτο από τα πεδία που ξέρουμε."""
    from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, IPv6
    eth = Ether(src=P.get("smac") or "3c:22:fb:12:34:56", dst="08:aa:89:41:26:04")
    if P.get("proto") == "ARP":
        a = P.get("arp") or {}
        return eth / ARP(op=a.get("op", 1), psrc=a.get("psrc", P["src"]), pdst=a.get("pdst", P["dst"]), hwsrc=a.get("hwsrc", eth.src))
    l3 = IPv6(src=P["src"], dst=P["dst"]) if ":" in P["src"] else IP(src=P["src"], dst=P["dst"], ttl=64, flags="DF")
    pr = P.get("proto")
    if pr in ("TCP", "HTTP", "HTTPS", "TLS") or (P.get("flags") and pr != "UDP"):
        l4 = TCP(sport=P.get("sp") or 50000, dport=P.get("dp") or 443, flags=P.get("flags") or "PA", seq=1000, ack=1, window=65535)
    elif pr == "ICMP":
        l4 = ICMP()
    else:
        l4 = UDP(sport=P.get("sp") or 50000, dport=P.get("dp") or 53)
    return eth / l3 / l4


# (layer, field) → (εξήγηση, μάθημα). Τα επίπεδα: Ethernet=L2, ARP=L2/L3, IP/IPv6=L3, TCP/UDP/ICMP=L4, DNS κ.λπ.=L7.
OSI = {"Ethernet": 2, "802.1Q": 2, "ARP": 2, "IP": 3, "IPv6": 3, "ICMP": 3, "ICMPv6": 3, "TCP": 4, "UDP": 4}
LAYER_INFO = {
    "Ethernet": ("Ethernet II (Layer 2): πλαίσιο μέσα στο τοπικό δίκτυο. Οι MAC αλλάζουν σε κάθε «hop» (router), οι IP όχι.", "ccna-1-13"),
    "802.1Q": ("Ετικέτα VLAN 802.1Q: 4 bytes που λένε σε ποιο VLAN ανήκει το πλαίσιο σε ένα trunk.", "ccna-2-2"),
    "ARP": ("ARP: «ποιος έχει αυτή την IP; πες μου τη MAC σου». Συνδέει Layer 3 με Layer 2.", "ccna-1-6"),
    "IP": ("IPv4 (Layer 3): διευθυνσιοδότηση από άκρη σε άκρη και δρομολόγηση.", "ccna-1-6"),
    "IPv6": ("IPv6 (Layer 3): 128-bit διευθύνσεις, χωρίς checksum και χωρίς fragmentation από τους routers.", "ccna-1-10"),
    "TCP": ("TCP (Layer 4): αξιόπιστη, με σύνδεση (3-way handshake), αριθμούς σειράς και επιβεβαιώσεις.", "ccna-1-5"),
    "UDP": ("UDP (Layer 4): χωρίς σύνδεση και χωρίς επιβεβαιώσεις — γρήγορο, για DNS, DHCP, φωνή/βίντεο.", "ccna-1-5"),
    "ICMP": ("ICMP: μηνύματα ελέγχου/σφαλμάτων (ping = echo request/reply, TTL exceeded = traceroute).", "ccna-7-1"),
    "DNS": ("DNS (Layer 7): «ποια IP έχει αυτό το όνομα;» — συνήθως UDP 53.", "ccna-4-4"),
    "BOOTP": ("DHCP (πάνω από BOOTP): ο client παίρνει IP, μάσκα, gateway, DNS — Discover/Offer/Request/Ack.", "ccna-4-3"),
    "DHCP options": ("Επιλογές DHCP: τύπος μηνύματος, μάσκα, router, DNS, lease time.", "ccna-4-3"),
    "NTPHeader": ("NTP: συγχρονισμός ώρας (UDP 123).", "ccna-4-5"),
}
FIELD_INFO = {
    ("Ethernet", "dst"): ("MAC προορισμού: η κάρτα δικτύου του επόμενου βήματος (συχνά ο router). ff:ff:ff:ff:ff:ff = broadcast σε όλους.", "ccna-1-13"),
    ("Ethernet", "src"): ("MAC πηγής: τα 3 πρώτα bytes (OUI) δείχνουν τον κατασκευαστή. Ο switch τη «μαθαίνει» στη θύρα που ήρθε.", "ccna-1-13"),
    ("Ethernet", "type"): ("EtherType: τι μεταφέρει το πλαίσιο — 0x0800 IPv4, 0x86dd IPv6, 0x0806 ARP, 0x8100 VLAN tag.", "ccna-1-2"),
    ("802.1Q", "vlan"): ("VLAN ID (12 bits: 1–4094).", "ccna-2-2"),
    ("802.1Q", "prio"): ("PCP / CoS (3 bits): προτεραιότητα για QoS στο Layer 2.", "ccna-4-7"),
    ("ARP", "op"): ("1 = request («ποιος έχει;», broadcast), 2 = reply (unicast). Gratuitous ARP: απάντηση χωρίς ερώτηση — έτσι γίνεται και το ARP spoofing.", "ccna-5-9"),
    ("ARP", "hwsrc"): ("Η MAC του αποστολέα.", "ccna-1-6"),
    ("ARP", "psrc"): ("Η IP του αποστολέα.", "ccna-1-6"),
    ("ARP", "hwdst"): ("Η MAC που ψάχνουμε (00:00:00:00:00:00 σε request).", "ccna-1-6"),
    ("ARP", "pdst"): ("Η IP για την οποία ρωτάμε.", "ccna-1-6"),
    ("IP", "version"): ("4 = IPv4.", "ccna-1-6"),
    ("IP", "ihl"): ("Μήκος κεφαλίδας σε λέξεις των 4 bytes (5 = 20 bytes, χωρίς options).", "ccna-1-6"),
    ("IP", "tos"): ("DSCP (6 bits) + ECN: σήμανση QoS. Π.χ. EF (46) για φωνή.", "ccna-4-7"),
    ("IP", "len"): ("Συνολικό μήκος του IP πακέτου (κεφαλίδα + δεδομένα) σε bytes.", "ccna-1-6"),
    ("IP", "id"): ("Αναγνωριστικό για επανασυναρμολόγηση fragments.", "ccna-1-6"),
    ("IP", "flags"): ("DF = Don't Fragment (μην το τεμαχίσεις — χρησιμοποιείται για Path MTU Discovery), MF = More Fragments.", "ccna-1-6"),
    ("IP", "frag"): ("Θέση του fragment (0 = πρώτο ή καθόλου τεμαχισμός).", "ccna-1-6"),
    ("IP", "ttl"): ("Time To Live: κάθε router το μειώνει κατά 1· στο 0 το πακέτο πετιέται (και στέλνεται ICMP TTL exceeded — έτσι δουλεύει το traceroute). Αρχικό 64 = Linux/macOS, 128 = Windows, 255 = δικτυακές συσκευές.", "ccna-3-2"),
    ("IP", "proto"): ("Τι είναι μέσα: 6 = TCP, 17 = UDP, 1 = ICMP, 50 = ESP (IPsec), 89 = OSPF.", "ccna-1-5"),
    ("IP", "chksum"): ("Checksum μόνο της κεφαλίδας· ξαναϋπολογίζεται σε κάθε router (γιατί αλλάζει το TTL).", "ccna-1-6"),
    ("IP", "src"): ("IP πηγής. Αν είναι ιδιωτική (10/8, 172.16/12, 192.168/16), ο router θα την αλλάξει με NAT/PAT πριν βγει στο Internet.", "ccna-4-2"),
    ("IP", "dst"): ("IP προορισμού: ο router κάνει longest prefix match στον routing table για να αποφασίσει πού θα το στείλει.", "ccna-3-2"),
    ("IPv6", "hlim"): ("Hop Limit: το αντίστοιχο του TTL.", "ccna-1-10"),
    ("IPv6", "nh"): ("Next Header: 6 = TCP, 17 = UDP, 58 = ICMPv6.", "ccna-1-10"),
    ("IPv6", "src"): ("IPv6 πηγής (fe80:: = link-local, 2000::/3 = global unicast).", "ccna-1-10"),
    ("IPv6", "dst"): ("IPv6 προορισμού (ff02:: = multicast στο τοπικό δίκτυο).", "ccna-1-10"),
    ("IPv6", "fl"): ("Flow Label: σημαδεύει πακέτα της ίδιας ροής.", "ccna-1-10"),
    ("TCP", "sport"): ("Θύρα πηγής. Από client: «εφήμερη» (49152–65535). Από server (π.χ. 443/80): είναι η απάντηση της υπηρεσίας.", "ccna-1-5"),
    ("TCP", "dport"): ("Θύρα προορισμού: η υπηρεσία (443 HTTPS, 80 HTTP, 22 SSH, 1883 MQTT, 8883 MQTT/TLS).", "ccna-1-5"),
    ("TCP", "seq"): ("Αριθμός σειράς: ποιο byte της ροής είναι το πρώτο αυτού του segment.", "ccna-1-5"),
    ("TCP", "ack"): ("Αριθμός επιβεβαίωσης: «έλαβα τα πάντα μέχρι εδώ, στείλε το επόμενο».", "ccna-1-5"),
    ("TCP", "dataofs"): ("Μήκος κεφαλίδας TCP σε λέξεις των 4 bytes.", "ccna-1-5"),
    ("TCP", "flags"): ("S = SYN (άνοιγμα), A = ACK, F = FIN (κλείσιμο), R = RST (απότομο κλείσιμο), P = PUSH. Handshake: SYN → SYN-ACK → ACK.", "ccna-1-5"),
    ("TCP", "window"): ("Window: πόσα bytes μπορεί να δεχτεί ο παραλήπτης πριν επιβεβαιώσει (flow control).", "ccna-1-5"),
    ("TCP", "chksum"): ("Checksum κεφαλίδας + δεδομένων.", "ccna-1-5"),
    ("TCP", "urgptr"): ("Urgent pointer (σχεδόν ποτέ σε χρήση).", "ccna-1-5"),
    ("TCP", "options"): ("Επιλογές: MSS (μέγιστο segment), Window Scale, SACK, Timestamps — συμφωνούνται στο SYN.", "ccna-1-5"),
    ("UDP", "sport"): ("Θύρα πηγής.", "ccna-1-5"),
    ("UDP", "dport"): ("Θύρα προορισμού (53 DNS, 67/68 DHCP, 123 NTP, 161 SNMP, 443 QUIC).", "ccna-1-5"),
    ("UDP", "len"): ("Μήκος κεφαλίδας (8 bytes) + δεδομένων.", "ccna-1-5"),
    ("UDP", "chksum"): ("Checksum (προαιρετικό στο IPv4, υποχρεωτικό στο IPv6).", "ccna-1-5"),
    ("ICMP", "type"): ("8 = echo request (ping), 0 = echo reply, 3 = destination unreachable, 11 = TTL exceeded.", "ccna-7-1"),
    ("ICMP", "code"): ("Λεπτομέρεια του τύπου (π.χ. type 3 code 3 = port unreachable).", "ccna-7-1"),
    ("DNS", "qd"): ("Η ερώτηση: όνομα και τύπος (A = IPv4, AAAA = IPv6, MX, TXT…).", "ccna-4-4"),
    ("DNS", "an"): ("Οι απαντήσεις.", "ccna-4-4"),
    ("DNS", "qr"): ("0 = ερώτηση, 1 = απάντηση.", "ccna-4-4"),
    ("DNS", "rcode"): ("0 = OK, 3 = NXDOMAIN (δεν υπάρχει το όνομα).", "ccna-4-4"),
}
SKIP_LAYERS = ("Raw", "Padding")
# 🔒 hex μόνο για κεφαλίδες χωρίς μυστικά· πεδία που μοιάζουν με κωδικό/κλειδί δεν δείχνονται ποτέ (π.χ. SNMP community)
HEX_OK = ("Ethernet", "802.1Q", "ARP", "IP", "IPv6", "TCP", "UDP", "ICMP", "DNS", "BOOTP")
SECRET_RE = re.compile(r"community|auth|pass|secret|token|cookie|key|cred|digest|chap|psk", re.I)
SECRET_LAYERS = ("SNMP", "Radius", "TACACS", "HTTPRequest", "HTTPResponse", "HTTP")
WELL_KNOWN = {20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP server", 68: "DHCP client",
              69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 443: "HTTPS/QUIC", 445: "SMB",
              514: "Syslog", 1883: "MQTT", 5353: "mDNS", 8883: "MQTT/TLS", 3389: "RDP"}


def decode(item):
    """item = {P, raw} → {layers:[{name, osi, info, lesson, fields:[{name, value, info, lesson}]}], payload, real}."""
    from scapy.all import Ether
    from scapy.layers.dhcp import BOOTP  # noqa: F401
    from scapy.layers.dns import DNS  # noqa: F401
    real = item.get("raw") is not None
    P = item["P"]
    try:
        pkt = Ether(item["raw"]) if real else Ether(bytes(synth(P)))  # bytes() → υπολογίζονται checksum/μήκη
    except Exception:
        pkt, real = Ether(bytes(synth(P))), False
    layers, payload = [], 0
    wire = bytes(pkt)
    off = 0
    cur = pkt
    while cur is not None and cur.__class__.__name__ != "NoPayload" and len(layers) < 7:
        if cur.__class__.__name__ in SKIP_LAYERS:
            payload = len(bytes(cur))
            break
        name = cur.name
        info, lesson = LAYER_INFO.get(name, (None, None))
        fields = []
        for f in cur.fields_desc:
            if name == "DNS" and f.name not in ("id", "qr", "opcode", "rd", "ra", "rcode", "qd", "an"):
                continue
            try:
                v = cur.getfieldval(f.name)
                shown = f.i2repr(cur, v)
            except Exception:
                continue
            if name == "DNS" and f.name in ("qd", "an"):
                recs = v if isinstance(v, list) else ([] if v is None else [v])
                shown = ", ".join(f"{r.rrname.decode(errors='replace') if isinstance(getattr(r, 'rrname', None), bytes) else getattr(r, 'qname', b'').decode(errors='replace')}"
                                  f" {r.get_field('type' if hasattr(r, 'rrname') else 'qtype').i2repr(r, getattr(r, 'type', getattr(r, 'qtype', 1)))}"
                                  f"{' → ' + str(r.rdata) if hasattr(r, 'rdata') else ''}" for r in recs[:4]) or "—"
            if f.name in ("sport", "dport") and isinstance(v, int) and v in WELL_KNOWN:
                shown = f"{v} ({WELL_KNOWN[v]})"
            if SECRET_RE.search(f.name) or (name in SECRET_LAYERS and f.name not in ("version", "PDU")):
                shown = "••• (κρυμμένο)"
            fi, fl = FIELD_INFO.get((name, f.name), (None, None))
            fields.append({"name": f.name, "value": str(shown)[:120], "info": fi, "lesson": fl})
        nb = len(bytes(cur)) - len(bytes(cur.payload))
        # 🔢 hex μόνο των κεφαλίδων (μέχρι 64 B ανά επίπεδο)· τα δεδομένα εφαρμογής δεν τα δείχνουμε ποτέ
        layers.append({"name": name, "osi": OSI.get(name, 7), "info": info, "lesson": lesson, "fields": fields,
                       "bytes": nb, "off": off, "hex": wire[off:off + min(nb, 64)].hex() if name in HEX_OK else ""})
        off += nb
        cur = cur.payload
    total = P.get("len") or len(bytes(pkt))
    hdr = sum(x["bytes"] for x in layers)
    payload = max(0, total - hdr) if real else payload
    return {"layers": layers, "payload": payload, "total": total, "real": real, "t": item["t"],
            "summary": f"{P.get('src')} → {P.get('dst')} {P.get('proto') or ''} {P.get('sp') or ''}→{P.get('dp') or ''} {P.get('flags') or ''}".strip()}
