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
