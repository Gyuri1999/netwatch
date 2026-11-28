"""NetWatch — OSINT: γεωεντοπισμός, δημόσια IP, traceroute, whois."""
import ipaddress
import json
import os
import queue
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

from core import ip_kind, log


# ---------------- OSINT helpers ----------------
def geo_worker(state):
    """Γεωεντοπισμός των δημόσιων IP — ΤΟΠΙΚΑ (geodb: DB-IP Lite μέσα στην εφαρμογή). Καμία IP δεν φεύγει από τον
    υπολογιστή· πριν στέλνονταν όλες, χωρίς κρυπτογράφηση, στο ip-api.com."""
    import geodb
    while True:
        ip = state.geo_q.get()
        try:
            g = geodb.lookup(ip)
        except Exception as e:  # noqa: BLE001
            log("geo lookup error:", e)
            g = None
        if g:
            with state.lock:
                h = state.hosts.get(ip)
                if h is not None:
                    h["geo"] = g
                    state.dirty.add(ip)


# Η δική μας δημόσια IP δεν βρίσκεται τοπικά: ρωτάμε ΜΙΑ φορά, με HTTPS, «ποια είναι η IP μου;». Η απάντηση δεν λέει
# σε κανέναν με ποιον μιλάμε. Χώρα/πάροχος βγαίνουν μετά από την τοπική βάση.
PUBLIC_IP_URLS = ("https://1.1.1.1/cdn-cgi/trace", "https://api.ipify.org")


def public_ip(timeout=6, opener=urllib.request.urlopen):
    for url in PUBLIC_IP_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "netwatch"})
            with opener(req, timeout=timeout) as r:
                text = r.read(2048).decode("ascii", "replace")
        except Exception:  # noqa: BLE001
            continue
        m = re.search(r"^ip=(\S+)$", text, flags=re.M)
        cand = (m.group(1) if m else text).strip()
        try:
            if ipaddress.ip_address(cand).is_global:
                return cand
        except ValueError:
            continue
    return None


def fetch_home(state):
    try:
        import geodb
        ip = public_ip()
        if not ip:
            return
        g = geodb.lookup(ip) or {"status": "success", "query": ip, "country": None, "countryCode": None, "city": None, "isp": None}
        with state.lock:
            state.home = g
        state.publish({"type": "home", "home": g})
        log(f"Δημόσια IP {g['query']} — {g.get('country') or '?'} ({g.get('isp') or '?'})")
    except Exception as e:
        log("home lookup error:", e)


TRACE_RE = re.compile(r"^\s*(\d+)\s+(\S+)(?:\s+([\d.]+) ms)?")


def parse_traceroute(text):
    hops = []
    for line in text.splitlines():
        m = TRACE_RE.match(line)
        if m:
            hops.append({"n": int(m.group(1)), "ip": None if m.group(2) == "*" else m.group(2),
                         "ms": float(m.group(3)) if m.group(3) else None})
    return hops


# Windows: το `tracert` έχει άλλη μορφή (IP στο τέλος, «Request timed out», «<1 ms»)
_TRACERT_HOP = re.compile(r"^\s*(\d+)\s+(.*\S)\s*$")
_TRACERT_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")
_TRACERT_MS = re.compile(r"<?(\d+)\s*ms", re.I)


def parse_tracert(text):
    hops = []
    for line in text.splitlines():
        m = _TRACERT_HOP.match(line)
        if not m:
            continue
        rest = m.group(2)
        ip = next((t for t in reversed(rest.split()) if _TRACERT_IP.match(t)), None)
        mm = _TRACERT_MS.search(rest)
        hops.append({"n": int(m.group(1)), "ip": ip, "ms": float(mm.group(1)) if mm else None})
    return hops


def trace_cmd(target, max_hops, v6=False):
    if sys.platform == "win32":  # tracert: -d χωρίς DNS, -w σε ms, -h μέγιστα hops
        return ["tracert", "-d", "-h", str(max_hops), "-w", "1000", target]
    exe = "traceroute6" if v6 else "traceroute"
    return [exe, "-n", "-q", "1", "-w", "1", "-m", str(max_hops), target]


def sys_trace(target, max_hops=20, timeout=60, v6=False):
    """traceroute (Unix) / tracert (Windows) → λίστα hops [{n, ip, ms}]. Κενή λίστα αν αποτύχει."""
    try:
        out = subprocess.run(trace_cmd(target, max_hops, v6), capture_output=True, text=True, timeout=timeout).stdout
    except (subprocess.TimeoutExpired, OSError):
        return []
    return parse_tracert(out) if sys.platform == "win32" else parse_traceroute(out)


def geo_batch(ips):
    """{ip: γεωεντοπισμός} για δημόσιες IP — τοπικά (geodb), χωρίς αίτημα προς τα έξω."""
    import geodb
    out = {}
    for ip in [i for i in dict.fromkeys(ips) if i and ip_kind(i) == "public"][:100]:
        g = geodb.lookup(ip)
        if g:
            out[ip] = g
    return out


def traceroute(state, ip, max_hops=20):
    """Από ποιους routers περνά η κίνηση μέχρι τον server (traceroute, χωρίς root)."""
    a = ipaddress.ip_address(ip)  # ValueError αν δεν είναι IP — τίποτα δεν περνά σε shell
    if not a.is_global:
        raise ValueError("Μόνο για διευθύνσεις του Internet")
    if state.mode == "demo":
        return demo_trace(state, ip)
    hops = sys_trace(ip, max_hops, 60, v6=a.version == 6)
    reached = bool(hops) and hops[-1]["ip"] == ip
    while hops and hops[-1]["ip"] is None:  # οι τελευταίοι «σιωπηλοί» routers δεν λένε τίποτα
        hops.pop()
    if state.geo_enabled:
        try:
            geo = geo_batch([h["ip"] for h in hops])
            for h in hops:
                h["geo"] = geo.get(h["ip"])
        except Exception as e:
            log("trace geo error:", e)
    return {"ip": ip, "hops": hops, "reached": reached}


def demo_trace(state, ip):
    g = (state.hosts.get(ip) or {}).get("geo") or {"country": "Germany", "countryCode": "DE", "city": "Frankfurt"}
    gr = {"country": "Greece", "countryCode": "GR", "city": "Athens", "isp": "Demo ISP", "as": "AS64500 Demo ISP"}
    ix = {"country": "Germany", "countryCode": "DE", "city": "Frankfurt am Main", "isp": "DE-CIX",
          "as": "AS6695 DE-CIX Frankfurt"}
    hops = [{"n": 1, "ip": "192.168.1.1", "ms": 2.1}, {"n": 2, "ip": "10.106.108.100", "ms": 9.8},
            {"n": 3, "ip": "79.128.234.168", "ms": 11.4, "geo": gr}, {"n": 4, "ip": "79.128.224.186", "ms": 12.9, "geo": gr},
            {"n": 5, "ip": None, "ms": None}, {"n": 6, "ip": "80.81.192.1", "ms": 38.2, "geo": ix},
            {"n": 7, "ip": ip, "ms": 41.7, "geo": g}]
    return {"ip": ip, "hops": hops, "reached": True, "demo": True}


def whois(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "Μη έγκυρη IP"
    try:
        out = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=20).stdout
    except Exception as e:
        return f"whois απέτυχε: {e}"
    lines = [l for l in out.splitlines() if l.strip() and not l.startswith(("%", "#"))]
    return "\n".join(lines)[:12000] or "(κενό αποτέλεσμα)"


# ---------- 🧅 Tor relay; (Onionoo — το επίσημο API του Tor Metrics) ----------
_ONIONOO_CACHE = {}
ONIONOO_FIELDS = ("nickname,fingerprint,flags,running,country,country_name,as,as_name,observed_bandwidth,"
                  "first_seen,last_seen,platform,exit_policy_summary,or_addresses,exit_addresses")


def onionoo_parse(j):
    out = []
    for r in (j or {}).get("relays", [])[:5]:
        flags = r.get("flags") or []
        out.append({"nickname": r.get("nickname"), "fingerprint": r.get("fingerprint"), "running": r.get("running"),
                    "flags": flags, "exit": "Exit" in flags, "guard": "Guard" in flags,
                    "country": (r.get("country") or "").upper(), "country_name": r.get("country_name"),
                    "as": r.get("as"), "as_name": r.get("as_name"), "bandwidth": r.get("observed_bandwidth"),
                    "first_seen": r.get("first_seen"), "last_seen": r.get("last_seen"), "platform": r.get("platform"),
                    "exit_ports": ((r.get("exit_policy_summary") or {}).get("accept") or [])[:12],
                    "url": "https://metrics.torproject.org/rs.html#details/" + str(r.get("fingerprint") or "")})
    return out


def onionoo(ip, demo=False, now=None, fetch=None):
    """Είναι αυτή η IP κόμβος Tor; Αν ναι: όνομα, ρόλος (guard/exit), εύρος ζώνης, από πότε τρέχει."""
    now = now or time.time()
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "error": "Μη έγκυρη IP"}
    if not a.is_global:
        return {"ip": ip, "relays": [], "note": "Ιδιωτική IP — δεν μπορεί να είναι κόμβος Tor."}
    if demo:
        rel = [] if not str(ip).startswith(("185.220.", "45.141.", "199.249.")) else [{
            "nickname": "ForPrivacyNET", "fingerprint": "ABCD1234" * 5, "running": True,
            "flags": ["Exit", "Fast", "Running", "Stable", "Valid"], "exit": True, "guard": False, "country": "DE",
            "country_name": "Germany", "as": "AS208294", "as_name": "Foundation for Applied Privacy",
            "bandwidth": 48_000_000, "first_seen": "2019-03-02 00:00:00", "last_seen": "2026-11-18 00:00:00",
            "platform": "Tor 0.4.8.13 on Linux", "exit_ports": ["80", "443"], "url": "https://metrics.torproject.org/"}]
        return {"ip": ip, "relays": rel, "demo": True}
    c = _ONIONOO_CACHE.get(ip)
    if c and now - c[0] < 6 * 3600:
        return c[1]
    url = "https://onionoo.torproject.org/details?search=" + str(a) + "&fields=" + ONIONOO_FIELDS
    try:
        if fetch:
            j = fetch(url)
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "NetWatch"})
            with urllib.request.urlopen(req, timeout=10) as r:
                j = json.loads(r.read(4_000_000))
        res = {"ip": ip, "relays": onionoo_parse(j)}
    except Exception as e:
        return {"ip": ip, "error": f"Onionoo: {str(e)[:100]}"}
    _ONIONOO_CACHE[ip] = (now, res)
    if len(_ONIONOO_CACHE) > 500:
        _ONIONOO_CACHE.pop(next(iter(_ONIONOO_CACHE)))
    return res
