"""NetWatch — εργαλειοθήκη τεχνικού δικτύου (ping, DNS, θύρες, HTTP, Wake-on-LAN, διεπαφές, ονόματα).

Κάθε συνάρτηση που αγγίζει το δίκτυο δέχεται `sim=True` και τότε επιστρέφει ρεαλιστικά ψεύτικα
αποτελέσματα (λειτουργία demo) χωρίς να στείλει τίποτα. Λάθη εισόδου → ValueError με ελληνικό μήνυμα.
Εξωτερικές εντολές καλούνται ΜΟΝΟ με λίστα ορισμάτων (ποτέ μέσω shell).

API (Python)                                               HTTP (server.py)
-----------------------------------------------------------------------------------------------
ping(host, count=5, interval=0.3)                          POST /api/netkit {tool:"ping", host, count?, interval?}
  → {host, ip, sent, received, loss_pct, min, avg, max, jitter, rtts:[ms], ttl, hops, os_guess}
    (min/avg/max/jitter σε ms ή null· os_guess μόνο για συσκευές LAN — είναι εκτίμηση από το TTL)
dns_lookup(name, rtype="A", server=None, timeout=2)        POST /api/netkit {tool:"dns", name, type?, server?}
  → {name, type, server, ms, rcode, answers:[{type, ttl, data}], truncated}
    (type: A AAAA MX TXT NS CNAME SOA PTR SRV· για PTR δέχεται και σκέτη IP)
dns_compare(name)                                          POST /api/netkit {tool:"dnscmp", name}
  → {name, results:[{id, label, server, ms, rcode, answers:[ip], error}], mismatch, severity, explanation}
    (severity: "ok" | "low" (μάλλον CDN) | "high" (ιδιωτική/μηδενική IP ή NXDOMAIN μόνο τοπικά))
port_check(host, ports, timeout=1.5)                       POST /api/netkit {tool:"ports", host, ports:"22,80,8000-8010"}
  → {host, ip, private, ports:[{port, state:"open"|"closed"|"filtered", ms, banner, product, version}]}
    (ιδιωτικός στόχος: έως 1024 θύρες· δημόσιος: έως 10 — έλεγχος σύνδεσης, όχι σάρωση)
http_inspect(url)                                          POST /api/netkit {tool:"http", url}
  → {url, final_url, status, ms, chain:[{url, status, ms, location}], headers:{...}, server, title,
     security:[{header, present, value, note, ok}], security_score:"4/6", tls:{...}|null}
wol(mac, broadcast=None)                                   POST /api/netkit {tool:"wol", mac, broadcast?}
  → {ok, mac, broadcast, port:9, bytes:102}
discover_names(ips, timeout=2)                             POST /api/netkit {tool:"names", ips:[...] | target:"192.168.1.0/24"}
  → {ip: {names:[...], sources:{dns|router|netbios|mdns|ssdp: ...}, model}}   (HTTP: τυλιγμένο ως {hosts: {...}})
iface_info()                                               GET  /api/netkit/iface
  → {interfaces:[{name, up, mtu, mac, ipv4:[{addr, prefix, broadcast}], ipv6:[{addr, prefix}]}],
     gateway, gateway_iface, dns:[...], search:[...]}
Μέσω του API (run_tool) κάθε εργαλείο καλεί state.note_own_tool(...) όσο τρέχει: η κίνηση από τον υπολογιστή σου
μετράει ως «δική σου δοκιμή» και δεν βγάζει ψεύτικους συναγερμούς (στο demo δεν στέλνεται τίποτα).
mac_vendor(mac) → όνομα κατασκευαστή | "τυχαία MAC (...)" | None
parse_ports(spec, limit) → [θύρες]   (ValueError με ελληνικό μήνυμα)
"""
import errno
import hashlib
import html
import http.client
import ipaddress
import json
import os
import random
import re
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import pentest

UA = "NetWatch/1.0 (netkit)"
RANDOM_MAC = "τυχαία MAC (κινητό/laptop με ιδιωτικότητα)"
MAX_PRIVATE_PORTS = 1024
MAX_PUBLIC_PORTS = 10
DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}
DNS_TYPE_NAMES = {v: k for k, v in DNS_TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
PUBLIC_RESOLVERS = [("cloudflare", "Cloudflare 1.1.1.1", "1.1.1.1"), ("google", "Google 8.8.8.8", "8.8.8.8"),
                    ("quad9", "Quad9 9.9.9.9", "9.9.9.9")]
SECURITY_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
SHOW_HEADERS = ["server", "content-type", "content-length", "x-powered-by", "via", "cache-control",
                "location", "alt-svc", "date"]

_HOST_RE = re.compile(r"^(?=.{1,253}\.?$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)"
                      r"(\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*\.?$")
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?)[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$")


# =============================== βοηθητικά / έλεγχος εισόδου ===============================
def _run(cmd, timeout=5):
    """Εκτέλεση εντολής (λίστα ορισμάτων, χωρίς shell). Επιστρέφει stdout ή ''."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, "LC_ALL": "C", "LANG": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _ip(s):
    try:
        return ipaddress.ip_address(str(s).strip().split("%")[0])
    except ValueError:
        return None


def valid_host(host):
    """IP ή hostname (RFC-ish). Επιστρέφει το καθαρό όνομα, αλλιώς ValueError."""
    h = str(host or "").strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if _ip(h) is not None:
        return h.split("%")[0]
    try:
        h = h.encode("idna").decode("ascii") if any(ord(c) > 127 for c in h) else h
    except UnicodeError:
        raise ValueError("Μη έγκυρο όνομα")
    if not h or not _HOST_RE.match(h):
        raise ValueError("Μη έγκυρο όνομα ή IP — γράψε π.χ. 192.168.1.1 ή example.com")
    return h.rstrip(".") or h


def _usable(a, what="στόχος"):
    if a.is_multicast or a.is_unspecified or (a.version == 4 and int(a) == 0xFFFFFFFF):
        raise ValueError(f"Μη χρήσιμος {what}: {a} (multicast/broadcast/0.0.0.0)")
    return a


def _is_private(a):
    return (a.is_private or a.is_loopback or a.is_link_local) and not a.is_multicast


def resolve(host, sim=False):
    """Όνομα → (καθαρό όνομα, IP). Προτιμά IPv4."""
    h = valid_host(host)
    a = _ip(h)
    if a is not None:
        return h, str(a)
    if sim:
        return h, _sim_ip(h)
    try:
        infos = socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        raise ValueError(f"Δεν βρέθηκε το όνομα «{h}»")
    infos.sort(key=lambda i: i[0] != socket.AF_INET)
    return h, infos[0][4][0].split("%")[0]


def parse_mac(mac):
    m = str(mac or "").strip()
    if re.fullmatch(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}", m):  # Cisco 0011.2233.4455
        m = m.replace(".", "")
    if not _MAC_RE.match(m):
        raise ValueError("Μη έγκυρη MAC — γράψε π.χ. aa:bb:cc:dd:ee:ff")
    raw = bytes.fromhex(re.sub(r"[:-]", "", m))
    return raw, ":".join(f"{b:02x}" for b in raw)


def parse_ports(spec, limit=MAX_PRIVATE_PORTS):
    """'22,80,8000-8010' → [22, 80, 8000, ..., 8010]. Έλεγχος ορίων και πλήθους."""
    if isinstance(spec, int) and not isinstance(spec, bool):
        spec = str(spec)
    if isinstance(spec, (list, tuple)):
        spec = ",".join(str(x) for x in spec)
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("Δώσε θύρες, π.χ. 22,80,443 ή 8000-8010")
    if len(spec) > 4000:
        raise ValueError("Πολύ μεγάλη λίστα θυρών")
    out = set()
    for tok in re.split(r"[,\s]+", spec.strip()):
        if not tok:
            continue
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", tok)
        if not m:
            raise ValueError(f"Μη έγκυρη θύρα «{tok[:20]}» — π.χ. 22,80,8000-8010")
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= a <= 65535 and 1 <= b <= 65535):
            raise ValueError(f"Οι θύρες είναι από 1 έως 65535 («{tok}»)")
        if a > b:
            raise ValueError(f"Λάθος διάστημα «{tok}» — το πρώτο πρέπει να είναι μικρότερο")
        if b - a + 1 > limit:
            raise ValueError(f"Πάρα πολλές θύρες — το πολύ {limit}")
        out.update(range(a, b + 1))
    if not out:
        raise ValueError("Δώσε θύρες, π.χ. 22,80,443")
    if len(out) > limit:
        raise ValueError(f"Πάρα πολλές θύρες ({len(out)}) — το πολύ {limit}")
    return sorted(out)


def compress_ports(ports):
    """[1,2,3,5] → '1-3,5'."""
    ps, out = sorted(set(int(p) for p in ports)), []
    i = 0
    while i < len(ps):
        j = i
        while j + 1 < len(ps) and ps[j + 1] == ps[j] + 1:
            j += 1
        out.append(str(ps[i]) if i == j else f"{ps[i]}-{ps[j]}")
        i = j + 1
    return ",".join(out)


def _seed(*parts):
    return int(hashlib.md5("|".join(map(str, parts)).encode()).hexdigest()[:8], 16)


def _sim_ip(name):
    if name in SIM_DNS_LOCAL:
        return SIM_DNS_LOCAL[name]
    s = _seed(name)
    return f"{[93, 104, 151, 185][s % 4]}.{(s >> 8) % 250 + 2}.{(s >> 16) % 250 + 2}.{(s >> 24) % 250 + 2}"


# =============================== ping ===============================
def os_guess(ttl):
    """Εκτίμηση λειτουργικού από το TTL (αρχικό 64/128/255). Είναι ΜΟΝΟ εκτίμηση."""
    if not ttl:
        return None
    if ttl <= 64:
        return "Linux/macOS/IoT (εκτίμηση από TTL)"
    if ttl <= 128:
        return "Windows (εκτίμηση από TTL)"
    return "δικτυακός εξοπλισμός — router/switch/εκτυπωτής (εκτίμηση από TTL)"


def _initial_ttl(ttl):
    return next((x for x in (64, 128, 255) if ttl <= x), 255)


def parse_ping(text):
    """Ανάλυση εξόδου ping macOS/Linux → {sent, received, loss_pct, min, avg, max, jitter, rtts, ttl}."""
    rtts, ttls = [], []
    for line in text.splitlines():
        m = re.search(r"time[=<]\s*([\d.]+)\s*ms", line)
        if m and ("bytes from" in line or "icmp_seq" in line):
            rtts.append(float(m.group(1)))
            t = re.search(r"ttl=(\d+)", line, re.I)
            if t:
                ttls.append(int(t.group(1)))
    sent = received = None
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", text)
    if m:
        sent, received = int(m.group(1)), int(m.group(2))
    if sent is None:
        sent, received = len(rtts), len(rtts)
    received = min(received, sent)
    loss = round(100.0 * (sent - received) / sent, 1) if sent else 100.0
    jitter = (round(sum(abs(b - a) for a, b in zip(rtts, rtts[1:])) / (len(rtts) - 1), 3)
              if len(rtts) > 1 else (0.0 if rtts else None))
    return {"sent": sent, "received": received, "loss_pct": loss,
            "min": round(min(rtts), 3) if rtts else None, "max": round(max(rtts), 3) if rtts else None,
            "avg": round(sum(rtts) / len(rtts), 3) if rtts else None, "jitter": jitter,
            "rtts": rtts, "ttl": ttls[0] if ttls else None}


def ping_cmd(ip, count, interval, platform=None):
    platform = platform or sys.platform
    v6 = ":" in ip
    deadline = str(int(count * interval + 3))
    if platform == "darwin":
        if v6:
            return ["ping6", "-n", "-c", str(count), "-i", str(interval), ip]
        return ["ping", "-n", "-c", str(count), "-i", str(interval), "-W", "1500", "-t", deadline, ip]
    return ["ping", "-6" if v6 else "-4", "-n", "-c", str(count), "-i", str(interval), "-W", "2", "-w", deadline, ip]


def ping(host, count=5, interval=0.3, sim=False):
    try:
        count, interval = int(count), float(interval)
    except (TypeError, ValueError):
        raise ValueError("Μη έγκυρο πλήθος/διάστημα")
    if not 1 <= count <= 20:
        raise ValueError("Πλήθος πακέτων: από 1 έως 20")
    if not 0.2 <= interval <= 5:
        raise ValueError("Διάστημα: από 0,2 έως 5 δευτερόλεπτα")
    name, ip = resolve(host, sim=sim)
    a = _usable(_ip(ip))
    if sim:
        r = _sim_ping(ip, count)
    else:
        if sys.platform == "win32":  # χωρίς -i: τα Windows στέλνουν ένα πακέτο ανά ~1 δευτ.
            import winplat
            out = winplat.ping(ip, count, 1500)
        else:
            out = _run(ping_cmd(ip, count, interval), timeout=count * interval + 8)
        r = parse_ping(out)
        if r["sent"] == 0:
            r["sent"], r["loss_pct"] = count, 100.0
    ttl = r["ttl"]
    r.update(host=name, ip=ip, hops=(_initial_ttl(ttl) - ttl) if ttl else None,
             os_guess=os_guess(ttl) if _is_private(a) else None)
    return r


def _sim_ping(ip, count):
    rnd = random.Random(_seed(ip, int(time.time() // 30)))
    a = _ip(ip)
    base = 0.05 if a.is_loopback else (rnd.uniform(1.2, 6) if _is_private(a) else rnd.uniform(9, 45))
    rtts = [round(base + abs(rnd.gauss(0, base * 0.15)), 3) for _ in range(count)]
    if count >= 5 and rnd.random() < 0.15:
        rtts.pop(rnd.randrange(len(rtts)))
    ttl = SIM_HOSTS.get(ip, {}).get("ttl") or (64 if _is_private(a) else 117)
    lines = [f"64 bytes from {ip}: icmp_seq={i} ttl={ttl} time={t} ms" for i, t in enumerate(rtts)]
    lines.append(f"{count} packets transmitted, {len(rtts)} packets received")
    return parse_ping("\n".join(lines))


# =============================== DNS ===============================
def _dns_mod():
    from scapy.layers import dns as d
    return d


def reverse_name(ip):
    a = _ip(ip)
    if a is None:
        raise ValueError("Μη έγκυρη IP")
    return a.reverse_pointer


def build_query(name, rtype="A", qid=None, rd=1):
    d = _dns_mod()
    return bytes(d.DNS(id=qid if qid is not None else random.randint(1, 65535), rd=rd,
                       qd=d.DNSQR(qname=name, qtype=DNS_TYPES[rtype])))


def _txt(v):
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8", "replace")
    return str(v)


def _rr_data(rr):
    t = DNS_TYPE_NAMES.get(rr.type, str(rr.type))
    if t == "MX":
        return f"{rr.preference} {_txt(rr.exchange).rstrip('.') or '.'}"
    if t == "SOA":
        return (f"{_txt(rr.mname).rstrip('.')} {_txt(rr.rname).rstrip('.')} serial={rr.serial} "
                f"refresh={rr.refresh} retry={rr.retry} expire={rr.expire} min={rr.minimum}")
    if t == "SRV":
        return f"{rr.priority} {rr.weight} {rr.port} {_txt(rr.target).rstrip('.')}"
    data = getattr(rr, "rdata", None)
    if t == "TXT":
        parts = data if isinstance(data, list) else [data]
        return " ".join(_txt(p) for p in parts if p is not None)
    if isinstance(data, (bytes, bytearray)):
        return _txt(data).rstrip(".")
    return str(data).rstrip(".") if data is not None else ""


def parse_response(data):
    """Bytes απάντησης DNS → {id, rcode, truncated, answers:[{type, ttl, data, name}]}."""
    d = _dns_mod()
    p = d.DNS(data)
    ans = []
    for rr in (p.an or []):
        try:
            ans.append({"type": DNS_TYPE_NAMES.get(rr.type, str(rr.type)), "ttl": int(rr.ttl or 0),
                        "data": _rr_data(rr), "name": _txt(rr.rrname).rstrip(".")})
        except Exception:
            continue
    extra = []
    for rr in (p.ar or []):
        try:
            extra.append({"type": DNS_TYPE_NAMES.get(rr.type, str(rr.type)), "data": _rr_data(rr),
                          "name": _txt(rr.rrname).rstrip(".")})
        except Exception:
            continue
    return {"id": p.id, "rcode": RCODES.get(p.rcode, str(p.rcode)), "truncated": bool(p.tc),
            "answers": ans, "additional": extra, "ra": bool(p.ra)}


def _query_name(name, rtype):
    rtype = str(rtype or "A").upper()
    if rtype not in DNS_TYPES:
        raise ValueError(f"Άγνωστος τύπος — επιτρέπονται: {', '.join(DNS_TYPES)}")
    if rtype == "PTR" and _ip(name) is not None:
        return reverse_name(name), rtype
    if _ip(name) is not None and rtype != "PTR":
        return reverse_name(name), "PTR"  # δόθηκε IP → αντίστροφη αναζήτηση
    return valid_host(name), rtype


def dns_lookup(name, rtype="A", server=None, timeout=2, sim=False, port=53):
    qname, rtype = _query_name(name, rtype)
    try:
        timeout = max(0.2, min(float(timeout), 10))
    except (TypeError, ValueError):
        timeout = 2
    if server in (None, ""):
        server = (["192.168.1.1"] if sim else _system_dns()[0] or [None])[0]
        if not server:
            raise ValueError("Δεν βρέθηκε DNS server του συστήματος — δώσε server")
    a = _ip(server)
    if a is None:
        raise ValueError("Ο DNS server πρέπει να είναι IP (π.χ. 1.1.1.1)")
    _usable(a, "server")
    server = str(a)
    if sim:
        return _sim_dns(qname, rtype, server)
    qid = random.randint(1, 65535)
    pkt = build_query(qname, rtype, qid)
    s = socket.socket(socket.AF_INET6 if a.version == 6 else socket.AF_INET, socket.SOCK_DGRAM)
    t0 = time.monotonic()
    try:
        s.settimeout(timeout)
        s.sendto(pkt, (server, int(port)))
        while True:
            left = timeout - (time.monotonic() - t0)
            if left <= 0:
                raise socket.timeout()
            s.settimeout(left)
            data, src = s.recvfrom(65535)
            if len(data) < 12 or struct.unpack("!H", data[:2])[0] != qid:
                continue  # όχι δική μας απάντηση
            break
    except socket.timeout:
        raise TimeoutError(f"Ο DNS server {server} δεν απάντησε σε {timeout:g} s")
    except OSError as e:
        raise TimeoutError(f"DNS {server}: {e.strerror or e}")
    finally:
        s.close()
    ms = round((time.monotonic() - t0) * 1000, 1)
    r = parse_response(data)
    return {"name": qname, "type": rtype, "server": server, "ms": ms, "rcode": r["rcode"],
            "truncated": r["truncated"], "answers": [{k: x[k] for k in ("type", "ttl", "data")} for x in r["answers"]]}


def _sim_dns(qname, rtype, server):
    low = qname.lower()
    rnd = random.Random(_seed(qname, rtype))
    ms = round(rnd.uniform(2, 9) if _ip(server) and _ip(server).is_private else rnd.uniform(8, 35), 1)
    base = {"name": qname, "type": rtype, "server": server, "ms": ms, "rcode": "NOERROR", "truncated": False, "answers": []}
    if low.endswith((".invalid", ".example")) or "nonexistent" in low or "does-not-exist" in low:
        base["rcode"] = "NXDOMAIN"
        return base
    dom = low[4:] if low.startswith("www.") else low
    ttl = rnd.choice([60, 300, 3600])
    ans = {
        "A": [_sim_ip(qname)] + ([_sim_ip(qname + "2")] if rnd.random() < 0.5 else []),
        "AAAA": [f"2606:4700:{rnd.randint(1, 0xffff):x}::{rnd.randint(1, 0xffff):x}"],
        "MX": [f"10 mx1.{dom}", f"20 mx2.{dom}"],
        "TXT": [f"v=spf1 include:_spf.{dom} ~all", "google-site-verification=demo"],
        "NS": [f"ns1.{dom}", f"ns2.{dom}"],
        "CNAME": [f"{dom}.cdn.cloudflare.net"] if low.startswith("www.") else [],
        "SOA": [f"ns1.{dom} hostmaster.{dom} serial=2026111701 refresh=7200 retry=3600 expire=1209600 min=300"],
        "SRV": [f"10 5 5060 sip.{dom}"],
        "PTR": [],
    }[rtype]
    if rtype == "PTR":
        ip = _ptr_to_ip(qname)
        n = SIM_HOSTS.get(ip, {}).get("names")
        ans = [n[-1]] if n else ([] if ip and _ip(ip).is_private else [f"server-{_seed(qname) % 900 + 100}.{'demo-isp.example'}"])
        if not ans:
            base["rcode"] = "NXDOMAIN"
    base["answers"] = [{"type": rtype, "ttl": ttl, "data": x} for x in ans]
    return base


def _ptr_to_ip(name):
    n = name.lower().rstrip(".")
    if n.endswith(".in-addr.arpa"):
        parts = n[:-len(".in-addr.arpa")].split(".")
        return ".".join(reversed(parts)) if len(parts) == 4 else None
    if n.endswith(".ip6.arpa"):
        nib = n[:-len(".ip6.arpa")].split(".")[::-1]
        if len(nib) == 32:
            return str(ipaddress.ip_address(":".join("".join(nib[i:i + 4]) for i in range(0, 32, 4))))
    return None


# --------------------------- σύγκριση resolvers ---------------------------
def _net16(ip):
    a = _ip(ip)
    return ".".join(ip.split(".")[:2]) if a and a.version == 4 else None


def compare_verdict(results):
    """Ετυμηγορία σύγκρισης. results: [{id, label, group:'local'|'public', rcode, answers:[ip], error}].
    Επίτηδες συντηρητική: τα CDN δίνουν διαφορετικές IP ανά resolver — αυτό ΔΕΝ είναι πρόβλημα."""
    pub = [r for r in results if r["group"] == "public" and not r.get("error")]
    loc = [r for r in results if r["group"] == "local" and not r.get("error")]
    pub_ips = [ip for r in pub if r["rcode"] == "NOERROR" for ip in r["answers"]]
    pub_global = [ip for ip in pub_ips if _ip(ip) and _ip(ip).is_global]
    if not pub:
        return False, "ok", "Δεν απάντησε κανένας δημόσιος resolver — δεν γίνεται σύγκριση."
    if not pub_global:
        if any(r["answers"] for r in loc) and all(r["rcode"] == "NXDOMAIN" for r in pub):
            return False, "ok", "Το όνομα υπάρχει μόνο στο τοπικό δίκτυο (π.χ. router.home) — φυσιολογικό."
        return False, "ok", "Οι δημόσιοι resolvers δεν δίνουν δημόσια IP — δεν γίνεται σύγκριση."
    pub16 = {_net16(ip) for ip in pub_global}
    high, low = [], []
    for r in loc:
        if r["rcode"] == "NXDOMAIN":
            high.append(f"Ο {r['label']} λέει ότι το όνομα δεν υπάρχει, ενώ οι δημόσιοι το βρίσκουν — "
                        "φίλτρο (Pi-hole, γονικός έλεγχος) ή παραποίηση DNS.")
            continue
        bog = [ip for ip in r["answers"] if _ip(ip) and not _ip(ip).is_global]
        if bog:
            high.append(f"Ο {r['label']} δίνει {bog[0]} (ιδιωτική/μηδενική IP) ενώ οι δημόσιοι δίνουν δημόσια — "
                        "αποκλεισμός διαφημίσεων (Pi-hole/AdGuard) ή πιθανό DNS hijack.")
            continue
        v4 = [ip for ip in r["answers"] if _net16(ip)]
        if v4 and pub16 and not ({_net16(ip) for ip in v4} & pub16):
            low.append(f"Ο {r['label']} δίνει εντελώς διαφορετικές IP — συνήθως CDN (άλλος server ανά περιοχή), "
                       "όχι απαραίτητα πρόβλημα.")
    if high:
        return True, "high", high[0]
    if low:
        return True, "low", low[0]
    return False, "ok", "Όλοι συμφωνούν (μικρές διαφορές στις IP είναι φυσιολογικές λόγω CDN)."


def dns_compare(name, sim=False, timeout=2):
    qname = valid_host(name)
    sysdns = (["192.168.1.1"] if sim else _system_dns()[0])
    gw = "192.168.1.1" if sim else _default_gateway()[0]
    targets = []
    if sysdns:
        targets.append(("system", "Σύστημα", sysdns[0], "local"))
    if gw and gw not in sysdns[:1] and _ip(gw) and _ip(gw).version == 4:
        targets.append(("router", "Router", gw, "local"))
    targets += [(i, lab, ip, "public") for i, lab, ip in PUBLIC_RESOLVERS]

    def one(t):
        rid, label, server, group = t
        row = {"id": rid, "label": label, "server": server, "group": group, "ms": None, "rcode": None,
               "answers": [], "error": None}
        try:
            if sim:
                r = _sim_dns(qname, "A", server)
                if group == "local" and re.search(r"(^|\.)(ads?|doubleclick|tracker)\.", qname.lower() + "."):
                    r = {**r, "answers": [{"type": "A", "ttl": 60, "data": "0.0.0.0"}]}
            else:
                r = dns_lookup(qname, "A", server=server, timeout=timeout)
            row.update(ms=r["ms"], rcode=r["rcode"], answers=[a["data"] for a in r["answers"] if a["type"] == "A"])
        except (TimeoutError, OSError, ValueError) as e:
            row["error"] = str(e)[:120]
        return row
    with ThreadPoolExecutor(len(targets)) as ex:
        results = list(ex.map(one, targets))
    mismatch, sev, why = compare_verdict(results)
    return {"name": qname, "results": results, "mismatch": mismatch, "severity": sev, "explanation": why}


# =============================== θύρες ===============================
def _probe_tcp(ip, port, timeout):
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.monotonic()
    try:
        s.connect((ip, port))
    except socket.timeout:
        s.close()
        return {"port": port, "state": "filtered", "ms": None, "banner": "", "product": None, "version": None}
    except ConnectionRefusedError:
        s.close()
        return {"port": port, "state": "closed", "ms": round((time.monotonic() - t0) * 1000, 1),
                "banner": "", "product": None, "version": None}
    except OSError as e:
        s.close()
        st = "closed" if e.errno == errno.ECONNREFUSED else "filtered"
        return {"port": port, "state": st, "ms": None, "banner": "", "product": None, "version": None}
    ms = round((time.monotonic() - t0) * 1000, 1)
    banner = ""
    try:
        s.settimeout(min(1.2, timeout))
        if port in pentest.HTTP_PORTS:
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nUser-Agent: NetWatch\r\n\r\n")
        banner = s.recv(1024).decode("latin-1", "replace").strip()[:300]
    except OSError:
        pass
    finally:
        s.close()
    prod, ver = pentest.parse_banner(banner)
    return {"port": port, "state": "open", "ms": ms, "banner": banner, "product": prod, "version": ver}


def port_check(host, ports, timeout=1.5, sim=False):
    name, ip = resolve(host, sim=sim)
    a = _usable(_ip(ip))
    private = _is_private(a)
    plist = parse_ports(ports, MAX_PRIVATE_PORTS if private else MAX_PUBLIC_PORTS)
    try:
        timeout = max(0.2, min(float(timeout), 5))
    except (TypeError, ValueError):
        timeout = 1.5
    if sim:
        res = _sim_ports(ip, plist, private)
    else:
        with ThreadPoolExecutor(min(64, len(plist))) as ex:
            res = list(ex.map(lambda p: _probe_tcp(ip, p, timeout), plist))
    return {"host": name, "ip": ip, "private": private, "ports": res,
            "open": sum(1 for r in res if r["state"] == "open")}


def _sim_ports(ip, plist, private):
    try:
        from demo import DEMO_SCAN
    except Exception:
        DEMO_SCAN = {}
    known = dict(DEMO_SCAN.get(ip, (None, []))[1])
    rnd = random.Random(_seed(ip))
    out = []
    for p in plist:
        if p in known or (not private and p in (80, 443)):
            ban = known.get(p, "HTTP/1.1 301 Moved Permanently\r\nServer: nginx" if p == 80 else "")
            prod, ver = pentest.parse_banner(ban)
            out.append({"port": p, "state": "open", "ms": round(rnd.uniform(0.8, 4) if private else rnd.uniform(10, 40), 1),
                        "banner": ban, "product": prod, "version": ver})
        else:
            st = "closed" if private or ip in SIM_HOSTS else "filtered"
            out.append({"port": p, "state": st, "ms": round(rnd.uniform(0.5, 3), 1) if st == "closed" else None,
                        "banner": "", "product": None, "version": None})
    return out


# =============================== HTTP ===============================
SEC_NOTES = {
    "Strict-Transport-Security": ("Ο browser θα μπαίνει πάντα με HTTPS.",
                                  "Λείπει — ο browser μπορεί να «πέσει» σε HTTP (κίνδυνος downgrade)."),
    "Content-Security-Policy": ("Περιορίζει από πού φορτώνονται scripts — προστασία από XSS.",
                                "Λείπει — λιγότερη προστασία από XSS."),
    "X-Frame-Options": ("Η σελίδα δεν μπαίνει σε ξένο iframe.",
                        "Λείπει — η σελίδα μπορεί να μπει σε iframe (clickjacking)."),
    "X-Content-Type-Options": ("Ο browser δεν «μαντεύει» τύπο αρχείου.",
                               "Λείπει — ο browser μπορεί να «μαντέψει» λάθος τύπο αρχείου."),
    "Referrer-Policy": ("Ελέγχεται τι διεύθυνση στέλνεται σε άλλα sites.",
                        "Λείπει — ισχύει η προεπιλογή του browser (συνήθως εντάξει)."),
    "Permissions-Policy": ("Περιορίζει κάμερα/μικρόφωνο/τοποθεσία.",
                           "Λείπει — δεν περιορίζονται κάμερα/μικρόφωνο/τοποθεσία (μικρό θέμα)."),
}


def security_report(headers, https):
    """headers: dict με πεζά κλειδιά. → [{header, present, value, note, ok}]."""
    out = []
    csp = headers.get("content-security-policy", "")
    for h in SECURITY_HEADERS:
        v = headers.get(h.lower())
        good, bad = SEC_NOTES[h]
        present = v is not None
        note, ok = (good if present else bad), present
        if h == "Strict-Transport-Security" and not https:
            note, ok = "Ισχύει μόνο σε HTTPS — η σελίδα είναι σε απλό HTTP.", False
        if h == "X-Frame-Options" and not present and "frame-ancestors" in csp:
            note, ok = "Καλύπτεται από το frame-ancestors του CSP.", True
        if h == "X-Content-Type-Options" and present and v.strip().lower() != "nosniff":
            note, ok = "Πρέπει να είναι «nosniff».", False
        out.append({"header": h, "present": present, "value": (v or "")[:200] or None, "note": note, "ok": ok})
    return out


def _title(body):
    m = re.search(rb"<title[^>]*>(.*?)</title>", body[:262144], re.I | re.S)
    if not m:
        return None
    raw = m.group(1)[:600]
    cs = re.search(rb"charset=[\"']?([\w-]+)", body[:4096], re.I)
    try:
        t = raw.decode(cs.group(1).decode() if cs else "utf-8", "replace")
    except LookupError:
        t = raw.decode("utf-8", "replace")
    return re.sub(r"\s+", " ", html.unescape(t)).strip()[:200] or None


def _check_url(url):
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https"):
        raise ValueError("Μόνο διευθύνσεις http:// ή https://")
    if not p.hostname:
        raise ValueError("Λείπει το όνομα του server")
    valid_host(p.hostname)
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        raise ValueError("Μη έγκυρη θύρα στη διεύθυνση")
    return p, port


def _http_get(url, timeout, read_body):
    p, port = _check_url(url)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    if p.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        conn = http.client.HTTPSConnection(p.hostname, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(p.hostname, port, timeout=timeout)
    t0 = time.monotonic()
    try:
        host_hdr = p.netloc.rsplit("@", 1)[-1]
        conn.request("GET", path, headers={"Host": host_hdr, "User-Agent": UA, "Accept": "text/html,*/*;q=0.8",
                                           "Accept-Encoding": "identity", "Connection": "close"})
        r = conn.getresponse()
        body = r.read(256 * 1024) if read_body else b""
        ms = round((time.monotonic() - t0) * 1000, 1)
        hdrs = {}
        for k, v in r.getheaders():
            k = k.lower()
            hdrs[k] = (hdrs[k] + ", " + v) if k in hdrs and k != "set-cookie" else v
        cookies = sum(1 for k, _ in r.getheaders() if k.lower() == "set-cookie")
        return r.status, hdrs, body, ms, cookies
    except (OSError, http.client.HTTPException) as e:
        raise TimeoutError(f"{p.hostname}:{port} — {str(e)[:120] or type(e).__name__}")
    finally:
        conn.close()


def _tls_verify(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s, \
                ssl.create_default_context().wrap_socket(s, server_hostname=host):
            return True, None
    except ssl.SSLCertVerificationError as e:
        return False, (e.verify_message or str(e))[:160]
    except (OSError, ssl.SSLError) as e:
        return None, str(e)[:160]


def http_inspect(url, sim=False, timeout=6):
    url = str(url or "").strip()
    if not url or len(url) > 2000:
        raise ValueError("Δώσε διεύθυνση, π.χ. https://example.com")
    if "://" not in url:
        url = "http://" + url
    _check_url(url)
    if sim:
        return _sim_http(url)
    chain, t_end = [], time.monotonic() + 25
    for hop in range(9):
        left = t_end - time.monotonic()
        if left <= 0:
            raise TimeoutError("Πήρε πολύ ώρα — σταμάτησα")
        status, hdrs, body, ms, cookies = _http_get(url, min(timeout, left), read_body=True)
        loc = hdrs.get("location") if status in (301, 302, 303, 307, 308) else None
        chain.append({"url": url, "status": status, "ms": ms, "location": loc})
        if not loc:
            break
        if hop == 8:
            raise ValueError("Πάρα πολλές ανακατευθύνσεις (πάνω από 8) — πιθανός βρόχος")
        nxt = urllib.parse.urljoin(url, loc.strip())
        _check_url(nxt)
        url = nxt
    p, port = _check_url(url)
    https = p.scheme == "https"
    res = {"url": chain[0]["url"], "final_url": url, "status": status, "ms": ms, "chain": chain,
           "headers": {k: hdrs[k][:300] for k in SHOW_HEADERS if k in hdrs}, "cookies": cookies,
           "server": hdrs.get("server"), "title": _title(body), "bytes": len(body),
           "security": security_report(hdrs, https), "tls": None}
    res["security_score"] = f"{sum(1 for s in res['security'] if s['ok'])}/{len(SECURITY_HEADERS)}"
    res["https_redirect"] = any(c["url"].startswith("http://") for c in chain) and https
    if https:
        tls = pentest.tls_info(p.hostname, port, timeout=min(timeout, 4), sni=None if _ip(p.hostname) else p.hostname)
        tls["findings"] = [list(f) for f in tls.get("findings", [])]
        tls["trusted"], tls["trust_error"] = _tls_verify(p.hostname, port, min(timeout, 4))
        if tls["trusted"] is False:
            tls["findings"].append(["med", "Ο browser δεν εμπιστεύεται το πιστοποιητικό: " + (tls["trust_error"] or "")])
        if tls.get("days_left") is not None and 0 <= tls["days_left"] < 14:
            tls["findings"].append(["low", f"Το πιστοποιητικό λήγει σε {tls['days_left']} μέρες"])
        res["tls"] = tls
    return res


def _sim_http(url):
    p, port = _check_url(url)
    host = p.hostname
    rnd = random.Random(_seed(host))
    https_url = f"https://{host}{p.path or '/'}"
    chain = []
    if p.scheme == "http":
        chain.append({"url": url, "status": 301, "ms": round(rnd.uniform(15, 40), 1), "location": https_url})
    chain.append({"url": https_url, "status": 200, "ms": round(rnd.uniform(40, 160), 1), "location": None})
    hdrs = {"server": rnd.choice(["nginx", "cloudflare", "Apache"]), "content-type": "text/html; charset=utf-8",
            "strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff",
            "content-length": str(rnd.randint(4000, 90000))}
    sec = security_report(hdrs, True)
    return {"url": url, "final_url": https_url, "status": 200, "ms": chain[-1]["ms"], "chain": chain,
            "headers": {k: v for k, v in hdrs.items() if k in SHOW_HEADERS}, "cookies": 1, "server": hdrs["server"],
            "title": host.split(".")[0].capitalize() + " — αρχική σελίδα", "bytes": int(hdrs["content-length"]),
            "security": sec, "security_score": f"{sum(1 for s in sec if s['ok'])}/{len(SECURITY_HEADERS)}",
            "https_redirect": p.scheme == "http", "sim": True,
            "tls": {"version": "TLSv1.3", "subject": f"CN={host}", "issuer": "C=US, O=Let's Encrypt, CN=R11",
                    "not_after": "Jan 15 12:00:00 2027 GMT", "days_left": 59, "sans": [host, "www." + host],
                    "findings": [], "trusted": True, "trust_error": None}}


# =============================== Wake-on-LAN ===============================
def wol_packet(mac):
    raw, _ = parse_mac(mac)
    return b"\xff" * 6 + raw * 16


def _wol_dest(broadcast):
    a = _ip(broadcast)
    if a is None or a.version != 4:
        raise ValueError("Η διεύθυνση broadcast πρέπει να είναι IPv4 (π.χ. 192.168.1.255)")
    if int(a) == 0xFFFFFFFF:
        return str(a)
    if not a.is_private or a.is_loopback or a.is_multicast or a.is_unspecified or a.is_link_local:
        raise ValueError("Το Wake-on-LAN στέλνεται μόνο στο τοπικό δίκτυο (π.χ. 192.168.1.255)")
    return str(a)


def wol(mac, broadcast=None, sim=False):
    pkt = wol_packet(mac)
    _, norm = parse_mac(mac)
    if pkt[6:12] == b"\x00" * 6 or pkt[6:12] == b"\xff" * 6 or pkt[6] & 1:
        raise ValueError("Αυτή η MAC δεν ανήκει σε συσκευή (multicast/μηδενική)")
    if broadcast in (None, ""):
        broadcast = "192.168.1.255" if sim else _default_broadcast()
    dest = _wol_dest(broadcast)
    if not sim:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(pkt, (dest, 9))
        except OSError as e:
            raise TimeoutError(f"Δεν στάλθηκε: {e.strerror or e}")
        finally:
            s.close()
    return {"ok": True, "mac": norm, "broadcast": dest, "port": 9, "bytes": len(pkt), "sim": bool(sim)}


def _default_broadcast():
    try:
        info = iface_info()
        for i in info["interfaces"]:
            if i["name"] == info.get("gateway_iface"):
                for a in i["ipv4"]:
                    if a.get("broadcast"):
                        return a["broadcast"]
                    if a.get("prefix") is not None:
                        return str(ipaddress.ip_network(f"{a['addr']}/{a['prefix']}", strict=False).broadcast_address)
    except Exception:
        pass
    return "255.255.255.255"


# =============================== διεπαφές ===============================
def parse_ifconfig(text):
    ifs, cur = [], None
    for line in text.splitlines():
        m = re.match(r"^([\w.:@-]+):\s+flags=\w+<([^>]*)>.*?mtu (\d+)", line)
        if m:
            flags = m.group(2).split(",")
            cur = {"name": m.group(1), "up": "UP" in flags, "mtu": int(m.group(3)), "mac": None, "ipv4": [], "ipv6": []}
            ifs.append(cur)
            continue
        if cur is None:
            continue
        s = line.strip()
        m = re.match(r"ether ([0-9a-fA-F:]{17})", s)
        if m:
            cur["mac"] = m.group(1).lower()
            continue
        m = re.match(r"inet (\d+\.\d+\.\d+\.\d+)(?: --> \S+)? netmask (0x[0-9a-fA-F]+|[\d.]+)(?: broadcast (\S+))?", s)
        if m:
            mask = m.group(2)
            try:
                prefix = bin(int(mask, 16)).count("1") if mask.startswith("0x") else \
                    ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
            except ValueError:
                prefix = None
            cur["ipv4"].append({"addr": m.group(1), "prefix": prefix, "broadcast": m.group(3)})
            continue
        m = re.match(r"inet6 ([0-9a-fA-F:.%\w]+) prefixlen (\d+)", s)
        if m:
            cur["ipv6"].append({"addr": m.group(1), "prefix": int(m.group(2))})
    return ifs


def parse_ip_json(text):
    try:
        data = json.loads(text or "[]")
    except ValueError:
        return []
    out = []
    for d in data if isinstance(data, list) else []:
        if not isinstance(d, dict) or not d.get("ifname"):
            continue
        it = {"name": d["ifname"], "up": "UP" in (d.get("flags") or []), "mtu": d.get("mtu"),
              "mac": d.get("address") if d.get("link_type") == "ether" else None, "ipv4": [], "ipv6": []}
        for a in d.get("addr_info") or []:
            if a.get("family") == "inet":
                it["ipv4"].append({"addr": a.get("local"), "prefix": a.get("prefixlen"), "broadcast": a.get("broadcast")})
            elif a.get("family") == "inet6":
                it["ipv6"].append({"addr": a.get("local"), "prefix": a.get("prefixlen")})
        out.append(it)
    return out


def parse_scutil_dns(text):
    """Η πρώτη ενότητα resolver χωρίς «domain» (η προεπιλεγμένη) → (servers, search)."""
    body = text.split("DNS configuration (for scoped queries)")[0]
    for block in re.split(r"\nresolver #\d+", body)[1:]:
        if re.search(r"^\s*domain\s*:", block, re.M):
            continue
        servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", block)
        search = re.findall(r"search domain\[\d+\]\s*:\s*(\S+)", block)
        if servers:
            return servers, search
    return [], []


def parse_resolv_conf(text):
    servers, search = [], []
    for line in text.splitlines():
        p = line.split("#")[0].split()
        if len(p) >= 2 and p[0] == "nameserver" and _ip(p[1]):
            servers.append(p[1])
        elif p and p[0] in ("search", "domain"):
            search = p[1:]
    return servers, search


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(65536)
    except OSError:
        return ""


def _system_dns():
    servers, search = [], []
    if sys.platform == "win32":
        import winplat
        return sorted(winplat.net_info().get("dns") or [], key=lambda s: ":" in s), []
    if sys.platform == "darwin":
        servers, search = parse_scutil_dns(_run(["scutil", "--dns"]))
    if not servers:
        servers, search = parse_resolv_conf(_read("/etc/resolv.conf"))
        if servers == ["127.0.0.53"]:  # systemd-resolved: ο stub δουλεύει, αλλά δείχνουμε και τους πραγματικούς
            up, _ = parse_resolv_conf(_read("/run/systemd/resolve/resolv.conf"))
            servers = servers + [s for s in up if s not in servers]
    servers.sort(key=lambda s: ":" in s)  # IPv4 πρώτα
    return servers, search


def _default_gateway():
    if sys.platform == "win32":
        import winplat
        v = winplat.net_info()
        return v.get("gateway"), v.get("gateway_iface")
    out = _run(["route", "-n", "get", "default"]) if sys.platform == "darwin" else ""
    gw = re.search(r"gateway:\s*(\S+)", out)
    dev = re.search(r"interface:\s*(\S+)", out)
    if gw:
        return gw.group(1), dev.group(1) if dev else None
    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\S+)(?: dev (\S+))?", out)
    return (m.group(1), m.group(2)) if m else (None, None)


def iface_info(sim=False):
    if sim:
        return dict(SIM_IFACE)
    if sys.platform == "darwin":
        ifs = parse_ifconfig(_run(["ifconfig", "-a"]))
    elif sys.platform == "win32":
        import winplat
        ifs = winplat.net_info().get("interfaces") or []
    else:
        ifs = parse_ip_json(_run(["ip", "-j", "addr"])) or parse_ifconfig(_run(["ifconfig", "-a"]))
    gw, gif = _default_gateway()
    dns, search = _system_dns()
    return {"interfaces": ifs, "gateway": gw, "gateway_iface": gif, "dns": dns, "search": search}


# =============================== κατασκευαστής από MAC ===============================
_manuf = {}


def mac_vendor(mac):
    try:
        raw, norm = parse_mac(mac)
    except ValueError:
        return None
    if raw[0] & 0x02:
        return RANDOM_MAC
    if norm in _manuf:
        return _manuf[norm]
    name = None
    try:
        from scapy.all import conf
        db = conf.manufdb
        if db is not None:
            r = db.lookup(norm)
            long_name = r[1] if isinstance(r, tuple) else r
            if long_name and long_name.lower() != norm and not re.fullmatch(r"[0-9a-f:]+", long_name.lower()):
                name = long_name.strip()
    except Exception:
        name = None
    if len(_manuf) > 5000:
        _manuf.clear()
    _manuf[norm] = name
    return name


# =============================== ανακάλυψη ονομάτων ===============================
def _udp_exchange(sends, timeout, sock_setup=None):
    """Στέλνει [(addr, port, bytes)] από ένα socket και μαζεύει απαντήσεις → [(src_ip, data)]."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out = []
    try:
        if sock_setup:
            sock_setup(s)
        s.setblocking(False)
        for ip, port, data in sends:
            try:
                s.sendto(data, (ip, port))
            except OSError:
                pass
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                break
            r, _, _ = select.select([s], [], [], left)
            if not r:
                break
            try:
                data, src = s.recvfrom(65535)
                out.append((src[0], data))
            except OSError:
                continue
    finally:
        s.close()
    return out


def nbstat_request(qid=0x4e57):
    name = b"".join(bytes([0x41 + (b >> 4), 0x41 + (b & 0xF)]) for b in b"*" + b"\x00" * 15)
    return struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0) + b"\x20" + name + b"\x00" + struct.pack("!HH", 0x21, 1)


def parse_nbstat(data):
    """Απάντηση NetBIOS node status → {names:[{name, suffix, group}], host, workgroup, mac} ή None."""
    try:
        if len(data) < 57:
            return None
        i = 12
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while data[i] != 0:
                i += data[i] + 1
            i += 1
        rtype, _cls, _ttl, _rdlen = struct.unpack("!HHIH", data[i:i + 10])
        if rtype != 0x21:
            return None
        i += 10
        n = data[i]
        i += 1
        names = []
        for _ in range(n):
            ent = data[i:i + 18]
            if len(ent) < 18:
                break
            nm = ent[:15].decode("latin-1").rstrip(" \x00")
            flags = struct.unpack("!H", ent[16:18])[0]
            names.append({"name": nm, "suffix": ent[15], "group": bool(flags & 0x8000)})
            i += 18
        mac = data[i:i + 6]
        host = next((x["name"] for x in names if x["suffix"] == 0 and not x["group"]), None)
        wg = next((x["name"] for x in names if x["suffix"] == 0 and x["group"]), None)
        return {"names": names, "host": host, "workgroup": wg,
                "mac": ":".join(f"{b:02x}" for b in mac) if len(mac) == 6 and any(mac) else None}
    except (IndexError, struct.error):
        return None


SSDP_MSEARCH = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
                b"MX: 1\r\nST: ssdp:all\r\nUSER-AGENT: NetWatch/1.0 UPnP/1.1\r\n\r\n")


def parse_ssdp(data):
    """Απάντηση SSDP → dict κεφαλίδων με πεζά κλειδιά (ή None)."""
    try:
        text = data[:4096].decode("utf-8", "replace")
    except Exception:
        return None
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines or not re.match(r"(HTTP/1\.\d 200|NOTIFY \*)", lines[0], re.I):
        return None
    h = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            h[k.strip().lower()] = v.strip()
    return h


def parse_upnp_description(xml):
    """XML περιγραφής συσκευής UPnP → {friendlyName, manufacturer, modelName, modelNumber} (με regex — χωρίς DTD/entities)."""
    if isinstance(xml, bytes):
        xml = xml.decode("utf-8", "replace")
    out = {}
    for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber"):
        m = re.search(rf"<(?:\w+:)?{tag}>\s*([^<]{{1,200}}?)\s*</(?:\w+:)?{tag}>", xml)
        if m:
            out[tag] = html.unescape(m.group(1)).strip()
    return out


def _model(d):
    man, mod = d.get("manufacturer") or "", d.get("modelName") or ""
    if man and mod.lower().startswith(man.lower()):
        man = ""
    return " ".join(x for x in (man, mod) if x) or None


def _fetch_upnp(location, src_ip, timeout=2.0):
    """GET της περιγραφής — μόνο http, μόνο προς την ΙΔΙΑ ιδιωτική IP που απάντησε (όχι SSRF)."""
    try:
        p = urllib.parse.urlsplit(location)
        if p.scheme != "http" or p.hostname != src_ip or not _ip(src_ip) or not _ip(src_ip).is_private:
            return {}
        conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=timeout)
        try:
            conn.request("GET", (p.path or "/") + ("?" + p.query if p.query else ""), headers={"User-Agent": UA})
            r = conn.getresponse()
            if r.status != 200:
                return {}
            return parse_upnp_description(r.read(65536))
        finally:
            conn.close()
    except (OSError, http.client.HTTPException, ValueError):
        return {}


def _private_ips(ips):
    if isinstance(ips, str):
        ips = [x for x in re.split(r"[,\s]+", ips) if x]
    if not isinstance(ips, (list, tuple, set)) or not ips:
        raise ValueError("Δώσε IP του τοπικού δικτύου")
    out = []
    for x in list(ips)[:1100]:
        out += pentest.check_target(str(x))
        if len(out) > pentest.MAX_HOSTS:
            raise ValueError(f"Το πολύ {pentest.MAX_HOSTS} διευθύνσεις")
    return list(dict.fromkeys(out))


def discover_names(ips, timeout=2, sim=False, router=None, resolver=None):
    ips = _private_ips(ips)
    try:
        timeout = max(0.3, min(float(timeout), 6))
    except (TypeError, ValueError):
        timeout = 2
    if sim:
        return {ip: {"names": list(SIM_HOSTS[ip]["names"]), "sources": dict(SIM_HOSTS[ip]["sources"]),
                     "model": SIM_HOSTS[ip].get("model")} for ip in ips if ip in SIM_HOSTS}
    want = set(ips)
    found, lock = {}, threading.Lock()

    def add(ip, src, name, model=None):
        if ip not in want:
            return
        name = (name or "").strip().rstrip(".")
        if _ip(name) is not None or name.lower().endswith(".arpa") or name.isdigit():
            name = ""  # μερικοί routers «απαντούν» με την ίδια την IP — δεν είναι όνομα
        with lock:
            e = found.setdefault(ip, {"names": [], "sources": {}, "model": None})
            if name and name.lower() not in (n.lower() for n in e["names"]) and len(e["names"]) < 12:
                e["names"].append(name[:120])
            if name:
                e["sources"].setdefault(src, name[:120])
            if model and not e["model"]:
                e["model"] = model[:120]
    rev = {reverse_name(ip): ip for ip in ips}

    def rdns(server, src):
        if not server or not _ip(server):
            return
        sends = [(server, 53, build_query(reverse_name(ip), "PTR", qid=n + 1)) for n, ip in enumerate(ips)]
        for _src, data in _udp_exchange(sends, timeout):
            try:
                r = parse_response(data)
            except Exception:
                continue
            if 1 <= r["id"] <= len(ips):
                for a in r["answers"]:
                    if a["type"] == "PTR":
                        add(ips[r["id"] - 1], src, a["data"])

    def netbios():
        for src, data in _udp_exchange([(ip, 137, nbstat_request()) for ip in ips], timeout):
            nb = parse_nbstat(data)
            if nb and nb["host"]:
                add(src, "netbios", nb["host"])

    def mdns():
        sends = [(ip, 5353, build_query(reverse_name(ip), "PTR", qid=n + 1, rd=0)) for n, ip in enumerate(ips)]
        if len(ips) <= 32:
            sends += [("224.0.0.251", 5353, build_query(reverse_name(ip), "PTR", qid=0, rd=0)) for ip in ips]
        for src, data in _udp_exchange(sends, timeout):
            try:
                r = parse_response(data)
            except Exception:
                continue
            for a in r["answers"] + r["additional"]:
                if a["type"] == "PTR" and a["name"].lower() in rev:
                    add(rev[a["name"].lower()], "mdns", a["data"])
                elif a["type"] == "A" and a["data"] in want and a["name"].endswith(".local"):
                    add(a["data"], "mdns", a["name"])

    def ssdp():
        locs = {}
        for src, data in _udp_exchange([("239.255.255.250", 1900, SSDP_MSEARCH)], timeout,
                                       sock_setup=lambda s: s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)):
            h = parse_ssdp(data)
            if h and src in want and h.get("location"):
                locs.setdefault(src, h["location"])
        for src, loc in list(locs.items())[:64]:
            d = _fetch_upnp(loc, src)
            if d:
                model = _model(d)
                add(src, "ssdp", d.get("friendlyName") or model, model)
    sysdns = resolver or (_system_dns()[0] or [None])[0]
    gw = router or _default_gateway()[0]
    jobs = [lambda: rdns(sysdns, "dns"), netbios, mdns, ssdp]
    if gw and gw != sysdns:
        jobs.append(lambda: rdns(gw, "router"))
    with ThreadPoolExecutor(len(jobs)) as ex:
        for f in [ex.submit(j) for j in jobs]:
            try:
                f.result()
            except Exception:
                pass
    return {ip: found[ip] for ip in ips if ip in found and (found[ip]["names"] or found[ip]["model"])}


def merge_names(state, found):
    """Προσθέτει τα ονόματα στον πίνακα συσκευών (state.hosts[ip]['names']) ώστε να φαίνονται στον χάρτη."""
    if not found or state is None:
        return 0
    n = 0
    with state.lock:
        for ip, info in found.items():
            names = info if isinstance(info, (list, tuple, set)) else (info or {}).get("names") or []
            for nm in names:
                nm = str(nm)[:120]
                if not nm:
                    continue
                if hasattr(state, "domains"):
                    state.domains[ip].add(nm)
                h = state.hosts.get(ip)
                if h is not None and nm not in h["names"]:
                    h["names"].add(nm)
                    if hasattr(state, "dirty"):
                        state.dirty.add(ip)
                    n += 1
    return n


# =============================== UDP υπηρεσίες (για τον σαρωτή) ===============================
def ntp_request():
    return b"\x1b" + b"\x00" * 47


def snmp_get_sysdescr(community="public"):
    from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind
    from scapy.asn1.asn1 import ASN1_OID
    return bytes(SNMP(community=community, PDU=SNMPget(id=0x4e57, varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])))


def _snmp_descr(data):
    try:
        from scapy.layers.snmp import SNMP
        p = SNMP(data)
        v = p.PDU.varbindlist[0].value
        val = getattr(v, "val", v)
        return _txt(val)[:200]
    except Exception:
        m = re.search(rb"[\x20-\x7e]{6,}", data[20:])
        return m.group(0).decode()[:200] if m else ""


UDP_PORTS = [53, 123, 137, 161, 1900, 5353]


def udp_requests():
    return {53: build_query(".", "NS", qid=0x4e57, rd=0), 123: ntp_request(), 137: nbstat_request(),
            161: snmp_get_sysdescr(), 1900: SSDP_MSEARCH.replace(b"239.255.255.250:1900", b"{ip}:1900"),
            5353: build_query("_services._dns-sd._udp.local", "PTR", qid=0x4e57, rd=0)}


def describe_udp(port, data):
    """Απάντηση UDP → (banner, product, findings)."""
    if port == 53:
        try:
            r = parse_response(data)
            return f"DNS ({r['rcode']}{', αναδρομικός' if r['ra'] else ''})", "DNS", []
        except Exception:
            return "DNS", "DNS", []
    if port == 123 and len(data) >= 48:
        return f"NTP stratum {data[1]}", "NTP", []
    if port == 137:
        nb = parse_nbstat(data)
        if nb:
            return f"NetBIOS: {nb['host'] or '?'}" + (f" ({nb['workgroup']})" if nb["workgroup"] else ""), "NetBIOS", []
        return "NetBIOS", "NetBIOS", []
    if port == 161:
        d = _snmp_descr(data)
        return (f"SNMP: {d}" if d else "SNMP"), "SNMP", [["high", "SNMP με community public — όποιος είναι στο "
                                                                  "δίκτυο διαβάζει (ίσως και αλλάζει) ρυθμίσεις της συσκευής"]]
    if port == 1900:
        h = parse_ssdp(data) or {}
        return "SSDP/UPnP" + (f": {h['server']}" if h.get("server") else ""), "UPnP", []
    if port == 5353:
        try:
            r = parse_response(data)
            svcs = sorted({a["data"] for a in r["answers"] if a["type"] == "PTR"})
            return "mDNS" + (": " + ", ".join(svcs[:6]) if svcs else ""), "mDNS", []
        except Exception:
            return "mDNS", "mDNS", []
    return "", None, []


def udp_scan(ips, timeout=1.5):
    """Στέλνει τα σωστά αιτήματα UDP σε κάθε IP → {ip: [service dict με proto 'udp']}."""
    reqs = udp_requests()
    out = {}
    for port in UDP_PORTS:
        sends = [(ip, port, reqs[port].replace(b"{ip}", ip.encode())) for ip in ips]
        seen = set()
        for src, data in _udp_exchange(sends, timeout):
            if src not in ips or src in seen:
                continue
            seen.add(src)
            banner, prod, findings = describe_udp(port, data)
            out.setdefault(src, []).append({"port": port, "proto": "udp", "state": "open", "banner": banner[:200],
                                            "product": prod, "version": None, "findings": findings})
    return out


# =============================== δεδομένα demo ===============================
SIM_HOSTS = {
    "192.168.1.1": {"names": ["router.home"], "sources": {"dns": "router.home", "ssdp": "Archer C6"},
                    "model": "TP-Link Archer C6", "ttl": 64},
    "192.168.1.10": {"names": ["Samsung-TV", "smart-tv.local"], "sources": {"ssdp": "Samsung-TV", "mdns": "smart-tv.local"},
                     "model": "Samsung QE55Q60", "ttl": 64},
    "192.168.1.15": {"names": ["iPhone-tis-Marias.local"], "sources": {"mdns": "iPhone-tis-Marias.local"}, "ttl": 64},
    "192.168.1.23": {"names": ["MacBook-Pro.local"], "sources": {"mdns": "MacBook-Pro.local"}, "ttl": 64},
    "192.168.1.30": {"names": ["ipcam.local"], "sources": {"mdns": "ipcam.local", "ssdp": "IPCAM"},
                     "model": "Hikvision DS-2CD1043", "ttl": 64},
    "192.168.1.40": {"names": ["NPI4A0B2C", "printer.local"], "sources": {"netbios": "NPI4A0B2C", "mdns": "printer.local"},
                     "model": "HP LaserJet Pro M404", "ttl": 255},
    "192.168.1.77": {"names": ["DESKTOP-7K2QF1"], "sources": {"netbios": "DESKTOP-7K2QF1"}, "ttl": 128},
}
SIM_DNS_LOCAL = {"router.home": "192.168.1.1", "printer.local": "192.168.1.40", "ipcam.local": "192.168.1.30"}
SIM_UDP = {
    "192.168.1.1": [(53, "DNS (NOERROR, αναδρομικός)", "DNS", []), (123, "NTP stratum 3", "NTP", []),
                    (1900, "SSDP/UPnP: Linux/3.10 UPnP/1.0 Archer_C6/1.0", "UPnP", [])],
    "192.168.1.10": [(1900, "SSDP/UPnP: Samsung/Tizen UPnP/1.0", "UPnP", []),
                     (5353, "mDNS: _airplay._tcp.local, _googlecast._tcp.local", "mDNS", [])],
    "192.168.1.15": [(5353, "mDNS: _companion-link._tcp.local, _rdlink._tcp.local", "mDNS", [])],
    "192.168.1.40": [(161, "SNMP: HP ETHERNET MULTI-ENVIRONMENT, ROM none, JETDIRECT", "SNMP",
                      [["high", "SNMP με community public — όποιος είναι στο δίκτυο διαβάζει (ίσως και αλλάζει) "
                                "ρυθμίσεις της συσκευής"]]),
                     (5353, "mDNS: _ipp._tcp.local, _printer._tcp.local", "mDNS", [])],
    "192.168.1.77": [(137, "NetBIOS: DESKTOP-7K2QF1 (WORKGROUP)", "NetBIOS", [])],
}
SIM_IFACE = {
    "interfaces": [
        {"name": "lo0", "up": True, "mtu": 16384, "mac": None, "ipv4": [{"addr": "127.0.0.1", "prefix": 8, "broadcast": None}],
         "ipv6": [{"addr": "::1", "prefix": 128}]},
        {"name": "en0", "up": True, "mtu": 1500, "mac": "3c:22:fb:aa:bb:23",
         "ipv4": [{"addr": "192.168.1.23", "prefix": 24, "broadcast": "192.168.1.255"}],
         "ipv6": [{"addr": "fe80::1c2a:3bff:fe4d:5e6f%en0", "prefix": 64}, {"addr": "2a02:587:1234:5600::23", "prefix": 64}]},
        {"name": "utun3", "up": True, "mtu": 1380, "mac": None, "ipv4": [], "ipv6": [{"addr": "fe80::ce81:b1c:bd2c:69e%utun3", "prefix": 64}]},
    ],
    "gateway": "192.168.1.1", "gateway_iface": "en0", "dns": ["192.168.1.1"], "search": ["home"], "sim": True,
}


def sim_udp(ip):
    return [{"port": p, "proto": "udp", "state": "open", "banner": b, "product": pr, "version": None,
             "findings": [list(f) for f in fs]} for p, b, pr, fs in SIM_UDP.get(ip, [])]


# =============================== πύλη για το HTTP API ===============================
def _num(v, default, cast=float):
    if v is None or v == "":
        return default
    try:
        return cast(v)
    except (TypeError, ValueError):
        raise ValueError("Μη έγκυρος αριθμός")


TOOL_LABELS = {"ping": "ping", "dns": "ερώτημα DNS", "dnscmp": "σύγκριση DNS", "ports": "έλεγχος θυρών",
               "http": "έλεγχος HTTP", "wol": "Wake-on-LAN", "names": "ανακάλυψη ονομάτων"}


class _OwnTool:
    """Όσο τρέχει ένα εργαλείο, λέμε στη μηχανή ανίχνευσης ότι η κίνηση από εμάς είναι δική μας δοκιμή
    (state.note_own_tool) — με «παλμό» κάθε 5 s για τα εργαλεία που αργούν."""

    def __init__(self, state, why):
        self.note = getattr(state, "note_own_tool", None) if state is not None else None
        self.why, self.stop = why, threading.Event()

    def _beat(self):
        try:
            self.note(self.why)
        except Exception:
            pass

    def __enter__(self):
        if self.note:
            self._beat()
            threading.Thread(target=self._loop, daemon=True).start()
        return self

    def _loop(self):
        while not self.stop.wait(5):
            self._beat()

    def __exit__(self, *exc):
        self.stop.set()
        if self.note:
            self._beat()  # η χάρη (grace) μετράει από το τέλος
        return False


def run_tool(body, sim=False, state=None):
    """Εκτελεί ένα εργαλείο από το JSON του POST /api/netkit."""
    tool = str(body.get("tool") or "")
    if tool not in TOOL_LABELS:
        raise ValueError("Άγνωστο εργαλείο — ping, dns, dnscmp, ports, http, wol, names")
    with _OwnTool(None if sim else state, f"{TOOL_LABELS[tool]} (🔴 Pentest → Εργαλεία)"):
        return _run_tool(tool, body, sim, state)


def _run_tool(tool, body, sim, state):
    s = lambda k, n=300: str(body.get(k) or "")[:n]  # noqa: E731
    if tool == "ping":
        return ping(s("host"), _num(body.get("count"), 5, int), _num(body.get("interval"), 0.3), sim=sim)
    if tool == "dns":
        return dns_lookup(s("name"), s("type", 8) or "A", server=s("server", 64) or None, sim=sim)
    if tool == "dnscmp":
        return dns_compare(s("name"), sim=sim)
    if tool == "ports":
        return port_check(s("host"), s("ports", 4000), sim=sim)
    if tool == "http":
        return http_inspect(s("url", 2000), sim=sim)
    if tool == "wol":
        return wol(s("mac", 40), s("broadcast", 40) or None, sim=sim)
    if tool == "names":
        ips = body.get("ips") or s("target", 64)
        if isinstance(ips, list):
            ips = [str(x)[:64] for x in ips[:1100]]
        found = discover_names(ips, sim=sim)
        merge_names(state, found)
        return {"hosts": found}
    raise ValueError("Άγνωστο εργαλείο — ping, dns, dnscmp, ports, http, wol, names")
