"""NetWatch — OSINT: γεωεντοπισμός, δημόσια IP, traceroute, whois."""
import ipaddress
import json
import os
import queue
import re
import subprocess
import time
import urllib.parse
import urllib.request

from core import GEO_FIELDS, ip_kind, log


# ---------------- OSINT helpers ----------------
def geo_worker(state):
    while True:
        ips = [state.geo_q.get()]
        time.sleep(1.0)
        while len(ips) < 100:
            try:
                ips.append(state.geo_q.get_nowait())
            except queue.Empty:
                break
        try:
            req = urllib.request.Request(
                f"http://ip-api.com/batch?fields={GEO_FIELDS}", data=json.dumps(ips).encode(),
                headers={"Content-Type": "application/json", "User-Agent": "netwatch/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                res = json.load(r)
                rl, ttl = r.headers.get("X-Rl"), r.headers.get("X-Ttl")
            with state.lock:
                for g in res:
                    if g.get("status") == "success":
                        h = state.hosts.get(g["query"])
                        if h is not None:
                            h["geo"] = g
                            state.dirty.add(g["query"])
            if rl == "0" and ttl:
                time.sleep(int(ttl) + 1)
        except Exception as e:
            log("geo lookup error:", e)
            for ip in ips:
                state.geo_q.put(ip)
            time.sleep(15)
        time.sleep(4.2)  # free tier: 15 batch requests / λεπτό


def fetch_home(state):
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/?fields={GEO_FIELDS}", timeout=10) as r:
            g = json.load(r)
        if g.get("status") == "success":
            with state.lock:
                state.home = g
            state.publish({"type": "home", "home": g})
            log(f"Δημόσια IP {g['query']} — {g.get('city')}, {g.get('country')} ({g.get('isp')})")
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


def geo_batch(ips):
    ips = [i for i in dict.fromkeys(ips) if i and ip_kind(i) == "public"][:100]
    if not ips:
        return {}
    req = urllib.request.Request(f"http://ip-api.com/batch?fields={GEO_FIELDS}", data=json.dumps(ips).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return {g["query"]: g for g in json.load(r) if g.get("status") == "success"}


def traceroute(state, ip, max_hops=20):
    """Από ποιους routers περνά η κίνηση μέχρι τον server (traceroute, χωρίς root)."""
    a = ipaddress.ip_address(ip)  # ValueError αν δεν είναι IP — τίποτα δεν περνά σε shell
    if not a.is_global:
        raise ValueError("Μόνο για διευθύνσεις του Internet")
    if state.mode == "demo":
        return demo_trace(state, ip)
    exe = "traceroute6" if a.version == 6 else "traceroute"
    out = subprocess.run([exe, "-n", "-q", "1", "-w", "1", "-m", str(max_hops), ip],
                         capture_output=True, text=True, timeout=60).stdout
    hops = parse_traceroute(out)
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
