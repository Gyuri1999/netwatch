#!/usr/bin/env python3
"""NetWatch — ζωντανή οπτικοποίηση κίνησης δικτύου & ανίχνευση επιθέσεων.

Live:  sudo .venv/bin/python netwatch.py            (χρειάζεται root για capture)
Demo:  .venv/bin/python netwatch.py --demo           (προσομοίωση, χωρίς root)
Μετά άνοιξε  http://127.0.0.1:8765
"""
import argparse
import collections
import copy
import functools
import hashlib
import ipaddress
import json
import math
import os
import queue
import random
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
GEO_FIELDS = ("status,message,country,countryCode,regionName,city,lat,lon,"
              "isp,org,as,asname,proxy,hosting,mobile,query")

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP", 853: "DoT", 993: "IMAPS", 995: "POP3S",
    1194: "OpenVPN", 1433: "MSSQL", 1900: "SSDP", 3306: "MySQL", 3389: "RDP",
    5060: "SIP", 5222: "XMPP", 5353: "mDNS", 5355: "LLMNR", 5432: "Postgres",
    5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt", 51820: "WireGuard",
}
BRUTE_PORTS = {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900}
SUSPECT_PORTS = {1337: "backdoor", 4444: "Metasploit", 5555: "ADB/backdoor",
                 6666: "IRC/botnet", 6667: "IRC/botnet", 31337: "Back Orifice",
                 9001: "Tor relay"}
SEV = {"low": 1, "med": 2, "high": 3}

# Αντιστοίχιση ειδοποιήσεων σε MITRE ATT&CK (https://attack.mitre.org) και στο κλειδί του ανιχνευτή
MITRE = [  # (πρόθεμα τύπου, technique id, όνομα, tactic, ανιχνευτής στο config)
    ("Port scan", "T1046", "Network Service Discovery", "Discovery", "port_scan"),
    ("Stealth scan", "T1046", "Network Service Discovery", "Discovery", "stealth_scan"),
    ("Network sweep", "T1018", "Remote System Discovery", "Discovery", "network_sweep"),
    ("Brute force", "T1110.001", "Brute Force: Password Guessing", "Credential Access", "brute_force"),
    ("SYN flood", "T1498.001", "Network DoS: Direct Network Flood", "Impact", "syn_flood"),
    ("ICMP flood", "T1498.001", "Network DoS: Direct Network Flood", "Impact", "icmp_flood"),
    ("ARP spoofing", "T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning", "Credential Access", "arp_spoofing"),
    ("ARP flood", "T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning", "Credential Access", "arp_flood"),
    ("Rogue DHCP", "T1557.003", "Adversary-in-the-Middle: DHCP Spoofing", "Credential Access", "rogue_dhcp"),
    ("Ύποπτη απάντηση DNS", "T1557", "Adversary-in-the-Middle", "Credential Access", "dns_spoofing"),
    ("Εισερχόμενη σύνδεση", "T1595", "Active Scanning", "Reconnaissance", "inbound"),
    ("Ύποπτη εξερχόμενη θύρα", "T1571", "Non-Standard Port", "Command and Control", "suspicious_port"),
    ("Beaconing", "T1071", "Application Layer Protocol", "Command and Control", "beaconing"),
    ("DNS tunneling", "T1071.004", "Application Layer Protocol: DNS", "Command and Control", "dns_tunnel"),
    ("DGA", "T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "Command and Control", "dga"),
    ("Νέα συσκευή", "T1200", "Hardware Additions", "Initial Access", "new_device"),
    ("Σύνδεση σε κακόβουλη IP", "T1071", "Application Layer Protocol", "Command and Control", "threat_intel"),
    ("Κίνηση από κακόβουλη IP", "T1595", "Active Scanning", "Reconnaissance", "threat_intel"),
]


def mitre_for(typ):
    for prefix, tid, name, tactic, _ in MITRE:
        if typ.startswith(prefix):
            return {"id": tid, "name": name, "tactic": tactic,
                    "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"}
    return None


def detector_for(typ):
    for prefix, *_rest, det in MITRE:
        if typ.startswith(prefix):
            return det
    return None


# ---------------- ρυθμίσεις (config.yaml) ----------------
DEFAULT_CONFIG = {
    "thresholds": {
        "alert_cooldown": 60,
        "port_scan": {"count": 20, "window": 10},
        "syn_flood": {"count": 300, "window": 5},
        "icmp_flood": {"count": 100, "window": 5},
        "brute_force": {"count": 15, "window": 30},
        "ping_sweep": {"count": 30, "window": 10},
        "arp_sweep": {"count": 40, "window": 10},
        "arp_flood": {"count": 60, "window": 5},
        "beaconing": {"min_events": 8, "max_jitter": 0.15, "min_interval": 10, "max_interval": 3600},
        "dns_tunnel": {"unique_subdomains": 30, "window": 60, "min_length": 20, "min_entropy": 3.5},
        "dga": {"nxdomain": 8, "window": 60, "min_score": 0.6},
        "new_device": {"warmup": 60},
    },
    "detectors": {d: True for d in (
        "port_scan", "stealth_scan", "network_sweep", "brute_force", "syn_flood", "icmp_flood",
        "arp_spoofing", "arp_flood", "rogue_dhcp", "dns_spoofing", "inbound", "suspicious_port",
        "beaconing", "dns_tunnel", "dga", "new_device", "threat_intel")},
    "allowlist": {"ips": [], "macs": [], "domains": []},
    "intel": {
        "enabled": True,
        "max_age_hours": 24,
        "abuseipdb_key": "",
        "feeds": [
            {"name": "Feodo Tracker (botnet C2)", "kind": "c2",
             "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"},
            {"name": "Spamhaus DROP", "kind": "block", "url": "https://www.spamhaus.org/drop/drop_v4.json"},
            {"name": "FireHOL level1", "kind": "block",
             "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"},
        ],
    },
    "notify": {"min_severity": "high", "cooldown": 30, "macos": True,
               "telegram": {"bot_token": "", "chat_id": ""}},
    "history": {"path": "data/netwatch.db"},
}


def deep_merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(path=None):
    """Διαβάζει config.yaml (αν υπάρχει) πάνω από τις προεπιλογές."""
    if not path:
        return copy.deepcopy(DEFAULT_CONFIG)
    try:
        import yaml
    except ImportError:
        sys.exit("Για config.yaml χρειάζεται: .venv/bin/pip install pyyaml")
    with open(path, encoding="utf-8") as f:
        return deep_merge(DEFAULT_CONFIG, yaml.safe_load(f) or {})


def chown_to_user(path):
    """Αν τρέχουμε με sudo, τα αρχεία που φτιάχνουμε να ανήκουν στον κανονικό χρήστη."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid and os.path.exists(path):
        try:
            os.chown(path, int(uid), int(gid))
        except OSError:
            pass


# ---------------- βοηθητικά για DNS / DGA ----------------
SLD2 = {"co", "com", "net", "org", "gov", "edu", "ac"}


def split_domain(q):
    """'a.b.example.co.uk' → ('example.co.uk', 'a.b') — απλή προσέγγιση χωρίς public-suffix list."""
    parts = q.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return q, ""
    n = 3 if len(parts) >= 3 and parts[-2] in SLD2 and len(parts[-1]) == 2 else 2
    return ".".join(parts[-n:]), ".".join(parts[:-n])


def entropy(s):
    if not s:
        return 0.0
    c = collections.Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def dga_score(label):
    """0..1 — πόσο «τυχαίο μηχανής» μοιάζει ένα όνομα (π.χ. xk3j9qz7lp)."""
    label = label.lower()
    if len(label) < 8:
        return 0.0
    vowels = sum(c in "aeiou" for c in label) / len(label)
    digits = sum(c.isdigit() for c in label) / len(label)
    run = best = 0
    for c in label:
        run = run + 1 if c.isalpha() and c not in "aeiou" else 0
        best = max(best, run)
    score = min(1, max(0, (entropy(label) - 2.5) / 1.5)) * 0.4
    score += (1 if vowels < 0.25 else 0.5 if vowels < 0.32 else 0) * 0.25
    score += min(1, digits * 3) * 0.15
    score += min(1, best / 6) * 0.2
    return round(score, 2)


def random_mac(mac):
    """Locally-administered MAC (τυχαία MAC ιδιωτικότητας iPhone/Android)."""
    return bool(mac) and len(mac) > 1 and mac[1].lower() in "26ae"


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, flush=True)


def app_label(proto, sp, dp):
    if proto not in ("TCP", "UDP"):
        return proto
    for p in sorted((sp or 0, dp or 0)):
        if p in SERVICES:
            if p == 443 and proto == "UDP":
                return "QUIC"
            return SERVICES[p]
    return proto


def service_port(sp, dp):
    for p in sorted((sp or 0, dp or 0)):
        if p in SERVICES:
            return p
    return min(sp or 65535, dp or 65535)


@functools.lru_cache(maxsize=20000)
def ip_kind(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    if a.is_multicast or ip == "255.255.255.255" or (a.version == 4 and ip.endswith(".255")):
        return "bcast"
    if a.is_global:
        return "public"
    return "local"


def norm_mac(m):
    if not m:
        return m
    return ":".join(p.zfill(2) for p in m.lower().split(":"))


class Window:
    """Συρόμενο χρονικό παράθυρο ανά κλειδί."""

    def __init__(self, span):
        self.span = span
        self.d = collections.defaultdict(collections.deque)

    def add(self, key, item, t):
        dq = self.d[key]
        dq.append((t, item))
        while dq and dq[0][0] < t - self.span:
            dq.popleft()
        return dq

    def gc(self, t):
        for k in [k for k, dq in self.d.items() if not dq or dq[-1][0] < t - self.span]:
            del self.d[k]


# ---------------- threat intelligence ----------------
class Intel:
    """Δημόσιες blocklists (Feodo/Spamhaus/FireHOL) σε lookup O(#prefix lengths)."""

    def __init__(self, cfg=None, cache_dir=None):
        self.cfg = cfg or {}
        self.cache_dir = cache_dir
        self.nets = {}  # prefixlen -> {int network: [feed,…]}
        self.info, self.entries, self.loaded = [], 0, False

    @staticmethod
    def _add(nets, cidr, feed):
        try:
            n = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return False
        if n.version != 4 or not n.is_global:
            return False  # οι λίστες περιέχουν και bogons (10/8, 192.168/16…) — δεν μας αφορούν
        bucket = nets.setdefault(n.prefixlen, {}).setdefault(int(n.network_address), [])
        if feed not in bucket:
            bucket.append(feed)
        return True

    @classmethod
    def parse(cls, text, feed, nets):
        n = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] in "#;":
                continue
            if line.startswith("{"):
                try:
                    cidr = json.loads(line).get("cidr")
                except ValueError:
                    cidr = None
                if not cidr:
                    continue
            else:
                cidr = line.split()[0].split(";")[0]
            n += cls._add(nets, cidr, feed)
        return n

    def add(self, cidr, name, kind="block"):
        self._add(self.nets, cidr, {"name": name, "kind": kind})
        self.entries += 1

    def lookup(self, ip):
        try:
            a = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return []
        out = []
        for pl, d in list(self.nets.items()):
            mask = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF if pl else 0
            for f in d.get(a & mask, ()):
                if f not in out:
                    out.append(f)
        return out

    def load(self, on_done=None):
        nets, info, total = {}, [], 0
        for f in self.cfg.get("feeds", []):
            feed = {"name": f["name"], "kind": f.get("kind", "block")}
            slug = re.sub(r"[^a-z0-9]+", "-", f["name"].lower()).strip("-")
            path = os.path.join(self.cache_dir, slug + ".txt") if self.cache_dir else None
            text, src = None, "cache"
            try:
                fresh = path and os.path.exists(path) and \
                    time.time() - os.path.getmtime(path) < self.cfg.get("max_age_hours", 24) * 3600
                if fresh:
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                else:
                    src = "download"
                    req = urllib.request.Request(f["url"], headers={"User-Agent": "netwatch/1.0"})
                    with urllib.request.urlopen(req, timeout=20) as r:
                        text = r.read().decode("utf-8", "ignore")
                    if path:
                        os.makedirs(self.cache_dir, exist_ok=True)
                        chown_to_user(os.path.dirname(self.cache_dir))
                        chown_to_user(self.cache_dir)
                        with open(path, "w", encoding="utf-8") as fh:
                            fh.write(text)
                        chown_to_user(path)
                n = self.parse(text, feed, nets)
                info.append({**feed, "entries": n, "ok": True, "source": src})
                total += n
            except Exception as e:
                info.append({**feed, "entries": 0, "ok": False, "error": str(e)[:120]})
                log(f"intel: {f['name']} απέτυχε: {e}")
        for pl, d in self.nets.items():  # κράτα και ό,τι προστέθηκε χειροκίνητα (demo)
            for k, v in d.items():
                nets.setdefault(pl, {}).setdefault(k, []).extend(x for x in v if x not in nets[pl].get(k, []))
        self.nets, self.info, self.entries, self.loaded = nets, info, total + self.entries, True
        log(f"intel: {total} δίκτυα από {sum(i['ok'] for i in info)}/{len(info)} λίστες")
        if on_done:
            on_done()


def abuseipdb_check(key, ip):
    ipaddress.ip_address(ip)
    req = urllib.request.Request(
        "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90}),
        headers={"Key": key, "Accept": "application/json", "User-Agent": "netwatch/1.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r).get("data", {})


# ---------------- ιστορικό (SQLite) ----------------
class History:
    def __init__(self, path=":memory:"):
        self.path = path
        if path != ":memory:":
            d = os.path.dirname(os.path.abspath(path))
            os.makedirs(d, exist_ok=True)
            chown_to_user(d)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, t REAL, type TEXT, sev TEXT,
                actor TEXT, target TEXT, detail TEXT, mitre TEXT, mode TEXT);
            CREATE INDEX IF NOT EXISTS alerts_t ON alerts(t);
            CREATE TABLE IF NOT EXISTS traffic(minute INTEGER PRIMARY KEY, pkts INTEGER, bytes INTEGER);
            CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY, ip TEXT, first_seen REAL, last_seen REAL);
            """)
            self.db.commit()
        chown_to_user(path)

    def add_alert(self, a, mode):
        with self.lock:
            self.db.execute("INSERT INTO alerts(t,type,sev,actor,target,detail,mitre,mode) VALUES(?,?,?,?,?,?,?,?)",
                            (a["t"], a["type"], a["sev"], a["actor"], str(a["target"]), a["detail"],
                             (a.get("mitre") or {}).get("id"), mode))
            self.db.commit()

    def add_traffic(self, minute, pkts, nbytes):
        with self.lock:
            self.db.execute("INSERT INTO traffic VALUES(?,?,?) ON CONFLICT(minute) DO UPDATE SET "
                            "pkts=pkts+excluded.pkts, bytes=bytes+excluded.bytes", (minute, pkts, nbytes))
            self.db.commit()

    def device_seen(self, mac, ip, t):
        """Επιστρέφει True αν η MAC δεν υπήρχε ποτέ ξανά στη βάση."""
        with self.lock:
            new = self.db.execute("SELECT 1 FROM devices WHERE mac=?", (mac,)).fetchone() is None
            self.db.execute("INSERT INTO devices VALUES(?,?,?,?) ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, "
                            "last_seen=excluded.last_seen", (mac, ip, t, t))
            self.db.commit()
            return new

    def known_macs(self):
        with self.lock:
            return {r[0] for r in self.db.execute("SELECT mac FROM devices")}

    def query(self, hours=24, ref=None):
        ref = ref or time.time()
        since = ref - hours * 3600
        with self.lock:
            cols = ["t", "type", "sev", "actor", "target", "detail", "mitre", "mode"]
            alerts = [dict(zip(cols, r)) for r in self.db.execute(
                f"SELECT {','.join(cols)} FROM alerts WHERE t>=? ORDER BY t DESC LIMIT 1000", (since,))]
            by_hour = self.db.execute("SELECT CAST(t/3600 AS INTEGER)*3600 h, sev, COUNT(*) FROM alerts WHERE t>=? "
                                      "GROUP BY h, sev ORDER BY h", (since,)).fetchall()
            traffic = self.db.execute("SELECT minute*60, pkts, bytes FROM traffic WHERE minute*60>=? ORDER BY minute",
                                      (since,)).fetchall()
            devices = [dict(zip(["mac", "ip", "first_seen", "last_seen"], r)) for r in self.db.execute(
                "SELECT mac, ip, first_seen, last_seen FROM devices ORDER BY first_seen DESC")]
            total = self.db.execute("SELECT COUNT(*), MIN(t) FROM alerts").fetchone()
        return {"ref": ref, "hours": hours, "alerts": alerts, "by_hour": by_hour, "traffic": traffic,
                "devices": devices, "total_alerts": total[0], "since_ever": total[1]}


# ---------------- ειδοποιήσεις ----------------
class Notifier:
    def __init__(self, cfg):
        self.cfg = cfg
        self.last = {}

    def __call__(self, a):
        if SEV[a["sev"]] < SEV.get(self.cfg.get("min_severity", "high"), 3):
            return
        now = time.time()
        if now - self.last.get(a["type"], 0) < self.cfg.get("cooldown", 30):
            return
        self.last[a["type"]] = now
        threading.Thread(target=self._send, args=(a,), daemon=True).start()

    def _send(self, a):
        title = f"NetWatch — {a['type']}"
        body = f"{a['actor']} → {a['target']}: {a['detail']}"
        if self.cfg.get("macos") and sys.platform == "darwin":
            cmd = ["osascript", "-e", "on run argv", "-e",
                   'display notification (item 2 of argv) with title (item 1 of argv) sound name "Basso"',
                   "-e", "end run", title, body[:220]]
            uid, user = os.environ.get("SUDO_UID"), os.environ.get("SUDO_USER")
            if user and uid and os.geteuid() == 0:
                cmd = ["launchctl", "asuser", uid, "sudo", "-u", user] + cmd
            try:
                subprocess.run(cmd, timeout=10, capture_output=True)
            except Exception as e:
                log("macOS notification error:", e)
        tg = self.cfg.get("telegram") or {}
        if tg.get("bot_token") and tg.get("chat_id"):
            try:
                data = urllib.parse.urlencode({"chat_id": tg["chat_id"], "text": f"⚠ {title}\n{body}"}).encode()
                urllib.request.urlopen(f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage", data=data,
                                       timeout=10).read()
            except Exception as e:
                log("telegram error:", e)


class NetState:
    def __init__(self, mode, iface, me_ips, gateway, geo=True, rdns=True, cfg=None, history=None, intel=None):
        self.lock = threading.RLock()
        self.cfg = cfg or copy.deepcopy(DEFAULT_CONFIG)
        th = self.cfg["thresholds"]
        al = self.cfg["allowlist"]
        self.allow_ips = set(al.get("ips") or [])
        self.allow_macs = {norm_mac(m) for m in al.get("macs") or []}
        self.allow_domains = tuple(d.lower().lstrip("*.") for d in al.get("domains") or [])
        self.history = history or History(":memory:")
        self.intel = intel or Intel(self.cfg.get("intel"))
        self.notifier = None
        self.known_macs = self.history.known_macs()
        self.had_devices = bool(self.known_macs)
        self.seen_macs = set()
        self.beacons = {}
        self.first_t, self.last_t = None, 0.0
        self.min_pkts = self.min_bytes = 0
        self.cur_minute = int(time.time() // 60)
        self.mode, self.iface = mode, iface
        self.me = set(me_ips)
        self.gateway = gateway
        self.geo_enabled, self.rdns_enabled = geo, rdns
        self.hosts = {}
        self.alerts = collections.deque(maxlen=500)
        self.alert_seq = 0
        self.cooldown = {}
        self.pending = []
        self.dirty, self.new_hosts = set(), set()
        self.subs = []
        self.total_pkts = self.total_bytes = 0
        self.win_pkts = self.win_bytes = 0
        self.protos = collections.Counter()
        self.home = None
        self.arp_table = {}
        self.arp_first = {}  # η πρώτη (έμπιστη) MAC που είδαμε για κάθε IP
        self.mac_ips = collections.defaultdict(set)
        self.dhcp_servers = {gateway} if gateway else set()
        self.dns_servers = {}
        self.domains = collections.defaultdict(set)
        self.demo_geo = {}
        self.geo_q = queue.Queue()
        self.rdns_pool = ThreadPoolExecutor(8)
        self.w_scan = Window(th["port_scan"]["window"])
        self.w_sweep = Window(max(th["ping_sweep"]["window"], th["arp_sweep"]["window"]))
        self.w_syn, self.w_icmp = Window(th["syn_flood"]["window"]), Window(th["icmp_flood"]["window"])
        self.w_arpflood, self.w_brute = Window(th["arp_flood"]["window"]), Window(th["brute_force"]["window"])
        self.w_dnstun, self.w_dga = Window(th["dns_tunnel"]["window"]), Window(th["dga"]["window"])
        self.windows = (self.w_scan, self.w_sweep, self.w_syn, self.w_icmp, self.w_arpflood, self.w_brute,
                        self.w_dnstun, self.w_dga)
        self.started = time.time()

    # ---------- pub/sub ----------
    def subscribe(self):
        q = queue.Queue(maxsize=400)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)

    def publish(self, msg):
        for q in list(self.subs):
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass

    # ---------- hosts ----------
    def host(self, ip, t):
        if not ip or ip in ("0.0.0.0", "::"):
            return None
        h = self.hosts.get(ip)
        if h is None:
            kind = ip_kind(ip)
            h = dict(ip=ip, kind=kind, me=ip in self.me, gw=ip == self.gateway,
                     first=t, last=t, pkts_in=0, pkts_out=0, bytes_in=0, bytes_out=0,
                     ports=collections.Counter(), protos=collections.Counter(),
                     names=set(self.domains.get(ip, ())), mac=None, geo=None,
                     rdns=None, threat=0, alerts=[],
                     hits=collections.Counter(), victims=collections.Counter(),
                     act=collections.deque(maxlen=120), ja3=collections.Counter(), ja3_sni={},
                     intel=self.intel.lookup(ip) if kind == "public" else [])
            self.hosts[ip] = h
            self.new_hosts.add(ip)
            if ip in self.demo_geo:
                h["geo"], h["rdns"] = self.demo_geo[ip]
            else:
                if kind == "public" and self.geo_enabled:
                    self.geo_q.put(ip)
                if kind != "bcast" and self.rdns_enabled:
                    self.rdns_pool.submit(self._rdns, ip)
            if len(self.hosts) > 3000:
                old = sorted(self.hosts.values(), key=lambda x: x["last"])[:300]
                for o in old:
                    if not o["me"] and not o["gw"] and not o["threat"]:
                        self.hosts.pop(o["ip"], None)
        return h

    def _rdns(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            return
        with self.lock:
            h = self.hosts.get(ip)
            if h:
                h["rdns"] = name
                self.dirty.add(ip)

    def ser(self, h):
        return {
            "ip": h["ip"], "kind": h["kind"], "me": h["me"], "gw": h["gw"],
            "first": h["first"], "last": h["last"],
            "pkts_in": h["pkts_in"], "pkts_out": h["pkts_out"],
            "bytes_in": h["bytes_in"], "bytes_out": h["bytes_out"],
            "ports": [[p, c, SERVICES.get(p, "")] for p, c in h["ports"].most_common(12)],
            "protos": dict(h["protos"].most_common(8)),
            "names": sorted(h["names"])[:25], "mac": h["mac"], "geo": h["geo"],
            "rdns": h["rdns"], "threat": h["threat"], "alerts": h["alerts"][-30:],
            "hits": [[k, c, SERVICES.get(k, "") if isinstance(k, int) else ""] for k, c in h["hits"].most_common(25)],
            "victims": h["victims"].most_common(12),
            "act": list(h["act"]),
            "ja3": [[j, c, sorted(h["ja3_sni"].get(j, ()))[:6]] for j, c in h["ja3"].most_common(8)],
            "intel": h["intel"],
        }

    def recheck_intel(self):
        with self.lock:
            for ip, h in self.hosts.items():
                if h["kind"] == "public":
                    found = self.intel.lookup(ip)
                    if found != h["intel"]:
                        h["intel"] = found
                        self.dirty.add(ip)
        self.publish({"type": "features", "features": self.features()})

    def features(self):
        n = self.cfg.get("notify", {})
        return {
            "intel": {"enabled": self.cfg["detectors"].get("threat_intel", True), "loaded": self.intel.loaded,
                      "entries": self.intel.entries, "feeds": self.intel.info},
            "abuseipdb": bool(self.cfg.get("intel", {}).get("abuseipdb_key")),
            "history": self.history.path,
            "notify": ({"macos": bool(n.get("macos")), "telegram": bool((n.get("telegram") or {}).get("bot_token")),
                        "min_severity": n.get("min_severity")} if self.notifier else None),
            "detectors": self.cfg["detectors"], "thresholds": self.cfg["thresholds"],
            "allowlist": {"ips": len(self.allow_ips), "macs": len(self.allow_macs), "domains": len(self.allow_domains)},
            "config": self.cfg.get("_path"),
        }

    # ---------- alerts ----------
    def _allowed(self, ip):
        if ip in self.allow_ips:
            return True
        h = self.hosts.get(ip)
        if h and h.get("mac") and h["mac"] in self.allow_macs:
            return True
        return bool(h and self.allow_domains and any(
            n.lower().endswith(self.allow_domains) for n in (h["names"] | ({h["rdns"]} if h["rdns"] else set()))))

    def _allowed_name(self, name):
        return bool(self.allow_domains) and name.lower().endswith(self.allow_domains)

    def alert(self, typ, sev, actor, target, detail, t, key=None, cooldown=None):
        det = detector_for(typ)
        if det and not self.cfg["detectors"].get(det, True):
            return
        if self._allowed(actor):
            return
        k = (typ, key or actor)
        cd = self.cfg["thresholds"].get("alert_cooldown", 60) if cooldown is None else cooldown
        if k in self.cooldown and t - self.cooldown[k] < cd:
            return
        self.cooldown[k] = t
        self.alert_seq += 1
        a = dict(id=self.alert_seq, t=t, type=typ, sev=sev, actor=actor,
                 target=target, detail=detail, mitre=mitre_for(typ))
        self.alerts.appendleft(a)
        h = self.host(actor, t)
        if h:
            h["threat"] = max(h["threat"], SEV[sev])
            h["alerts"].append(a["id"])
            self.dirty.add(actor)
        self.publish({"type": "alert", "alert": a})
        try:
            self.history.add_alert(a, self.mode)
        except Exception as e:
            log("history error:", e)
        if self.notifier:
            self.notifier(a)
        log(f"⚠  [{sev.upper()}] {typ} [{(a['mitre'] or {}).get('id', '-')}]: {actor} → {target} — {detail}")

    # ---------- main pipeline ----------
    def process(self, P):
        t, L = P["t"], P["len"]
        src, dst, proto = P["src"], P["dst"], P["proto"]
        sp, dp = P.get("sp"), P.get("dp")
        label = app_label(proto, sp, dp)
        with self.lock:
            if self.first_t is None:
                self.first_t = t
            self.last_t = max(self.last_t, t)
            self.total_pkts += 1
            self.min_pkts += 1
            self.min_bytes += L
            self.total_bytes += L
            self.win_pkts += 1
            self.win_bytes += L
            self.protos[label] += 1
            for name, ip in P.get("dns") or ():
                self.domains[ip].add(name)
                hh = self.hosts.get(ip)
                if hh is not None and name not in hh["names"]:
                    hh["names"].add(name)
                    self.dirty.add(ip)
            for nm in (P.get("sni"), P.get("http_host")):
                if nm:
                    self.domains[dst].add(nm)
            hs = self.host(src, t)
            # ARP «ποιος έχει;» δεν αποδεικνύει ότι υπάρχει η συσκευή-στόχος
            hd = self.hosts.get(dst) if (proto == "ARP" and (P.get("arp") or {}).get("op") == 1) else self.host(dst, t)
            svc = service_port(sp, dp) if sp is not None else None
            if hs:
                hs["pkts_out"] += 1
                hs["bytes_out"] += L
                hs["last"] = t
                hs["protos"][label] += 1
                if svc:
                    hs["ports"][svc] += 1
                if P.get("smac") and hs["kind"] == "local" and proto != "ARP":
                    hs["mac"] = norm_mac(P["smac"])
                    self._mac_seen(src, hs["mac"], t)
                if P.get("ja3"):
                    hs["ja3"][P["ja3"]] += 1
                    if P.get("sni"):
                        sn = hs["ja3_sni"].setdefault(P["ja3"], set())
                        if len(sn) < 20:
                            sn.add(P["sni"])
                # τι «χτυπάει» / πού συνδέεται ο αποστολέας (μόνο πακέτα που ξεκινούν κάτι)
                fl = P.get("flags", "")
                key = None
                if proto == "TCP" and "S" in fl and "A" not in fl:
                    key = dp
                elif proto == "TCP" and fl in ("", "F", "FPU"):
                    key = dp
                elif proto == "UDP" and dp is not None and (sp or 0) > (dp or 0):
                    key = dp
                elif proto == "ICMP" and P.get("icmp_type") == 8:
                    key = "ICMP ping"
                elif proto == "ARP" and (P.get("arp") or {}).get("op") == 1:
                    key = "ARP who-has"
                if key is not None:
                    hs["hits"][key] += 1
                    hs["victims"][dst] += 1
                # δραστηριότητα ανά 10 δευτερόλεπτα (για γράφημα)
                b = int(t // 10) * 10
                if hs["act"] and hs["act"][-1][0] == b:
                    hs["act"][-1][1] += 1
                else:
                    hs["act"].append([b, 1])
                self.dirty.add(src)
            if hd:
                hd["pkts_in"] += 1
                hd["bytes_in"] += L
                hd["last"] = t
                hd["protos"][label] += 1
                if svc:
                    hd["ports"][svc] += 1
                for nm in (P.get("sni"), P.get("http_host")):
                    if nm and nm not in hd["names"]:
                        hd["names"].add(nm)
                self.dirty.add(dst)
            try:
                self.detect(P, t)
            except Exception as e:  # never kill capture
                log("detect error:", e)
            x = 1 if (hs and hs["threat"] >= 2 and not hs["me"]) else 0
            if len(self.pending) < 4000:
                self.pending.append({"s": src, "d": dst, "p": proto, "a": label, "l": L,
                                     "sp": sp, "dp": dp, "x": x,
                                     "f": P.get("flags") or {1: "who-has", 2: "is-at"}.get((P.get("arp") or {}).get("op"), ""),
                                     "t": round(t, 3)})

    # ---------- detection ----------
    def _th(self, name):
        return self.cfg["thresholds"][name]

    def detect(self, P, t):
        src, dst, proto = P["src"], P["dst"], P["proto"]
        sp, dp, fl = P.get("sp"), P.get("dp"), P.get("flags", "")
        from_me, to_me = src in self.me, dst in self.me
        if proto == "ARP":
            return self._arp(P, t)
        self._intel_check(src, dst, dp, t)
        if P.get("dns_q"):
            self._dns_query(src, P["dns_q"][0], t)
        if P.get("nx"):
            self._nxdomain(dst, P["nx"], t)

        if proto == "TCP" and not from_me:
            if fl in ("", "F", "FPU") or ("F" in fl and "P" in fl and "U" in fl and "A" not in fl):
                name = {"": "NULL", "F": "FIN"}.get(fl, "XMAS")
                self.alert(f"Stealth scan ({name})", "high" if to_me else "med", src, dst,
                           f"Πακέτα TCP με ασυνήθιστα flags [{fl or 'κανένα'}] — εργαλείο τύπου nmap -s{name[0]}", t)
            syn = "S" in fl and "A" not in fl
            if syn:
                th = self._th("port_scan")
                dq = self.w_scan.add(src, (dst, dp), t)
                n = len({i for _, i in dq})
                if n >= th["count"]:
                    targets = len({i[0] for _, i in dq})
                    self.alert("Port scan", "high" if to_me else "med", src, dst,
                               f"{n} απόπειρες σε {targets} στόχο(ους) μέσα σε {th['window']}s (TCP SYN scan)", t)
                if to_me:
                    if ip_kind(src) == "public":
                        self.alert("Εισερχόμενη σύνδεση", "low", src, dst,
                                   f"Μη αναμενόμενο SYN από το Internet στη θύρα {dp} ({SERVICES.get(dp, '?')})", t)
                    th = self._th("syn_flood")
                    dq = self.w_syn.add("me", src, t)
                    if len(dq) >= th["count"]:
                        top = collections.Counter(i for _, i in dq).most_common(1)[0][0]
                        self.alert("SYN flood", "high", top, dst,
                                   f"{len(dq)} SYN σε {th['window']}s προς εσένα — επίθεση άρνησης υπηρεσίας (DoS)",
                                   t, key="synflood")
                    if dp in BRUTE_PORTS:
                        th = self._th("brute_force")
                        dq = self.w_brute.add((src, dp), 1, t)
                        if len(dq) >= th["count"]:
                            self.alert("Brute force", "high", src, dst,
                                       f"{len(dq)} συνδέσεις στην υπηρεσία {SERVICES.get(dp)} ({dp}) σε "
                                       f"{th['window']}s — δοκιμή κωδικών", t)

        if proto == "TCP" and "S" in fl and "A" not in fl and ip_kind(src) == "local" and ip_kind(dst) == "public":
            self._beacon(src, dst, dp, t)

        if (proto == "UDP" and not from_me and dp is not None and dp < 1024 and (sp or 0) >= 1024
                and dp not in (53, 67, 68, 123, 137, 138)):
            th = self._th("port_scan")
            dq = self.w_scan.add(src, (dst, dp), t)
            n = len({i for _, i in dq})
            if n >= th["count"]:
                self.alert("Port scan (UDP)", "high" if to_me else "med", src, dst,
                           f"{n} διαφορετικές UDP θύρες/στόχοι σε {th['window']}s", t)

        if proto == "ICMP" and P.get("icmp_type") == 8 and not from_me:
            th = self._th("ping_sweep")
            dq = self.w_sweep.add(("icmp", src), dst, t)
            n = len({i for ti, i in dq if ti >= t - th["window"]})
            if n >= th["count"]:
                self.alert("Network sweep (ping)", "med", src, dst,
                           f"Ping σε {n} διαφορετικές IP σε {th['window']}s — χαρτογράφηση δικτύου", t)
            if to_me:
                th = self._th("icmp_flood")
                dq = self.w_icmp.add(src, 1, t)
                if len(dq) >= th["count"]:
                    self.alert("ICMP flood", "high", src, dst, f"{len(dq)} ping σε {th['window']}s προς εσένα", t)

        if proto == "UDP" and sp == 67 and dp == 68:
            if src not in self.dhcp_servers and self.dhcp_servers:
                self.alert("Rogue DHCP server", "high", src, dst,
                           f"Νέος DHCP server ({src}) εκτός από {', '.join(sorted(self.dhcp_servers))} — "
                           "μπορεί να σε στείλει σε ψεύτικο gateway/DNS", t)
            self.dhcp_servers.add(src)

        if proto == "UDP":
            if from_me and dp == 53:
                self.dns_servers[dst] = t
            elif to_me and sp == 53 and self.dns_servers and src not in self.dns_servers:
                self.alert("Ύποπτη απάντηση DNS", "med", src, dst,
                           "Απάντηση DNS από διακομιστή που δεν ρωτήθηκε — πιθανό DNS spoofing", t)

        if from_me and proto in ("TCP", "UDP") and dp in SUSPECT_PORTS and ("S" in fl or proto == "UDP"):
            self.alert("Ύποπτη εξερχόμενη θύρα", "low", dst, src,
                       f"Σύνδεση προς θύρα {dp} ({SUSPECT_PORTS[dp]})", t)

    # --- C2 beaconing: συνδέσεις με «ρολόι» ---
    def _beacon(self, src, dst, dp, t):
        if dp in (53, 123):
            return
        b = self._th("beaconing")
        key = (src, dst, dp)
        dq = self.beacons.get(key)
        if dq is None:
            if len(self.beacons) > 20000:
                return
            dq = self.beacons[key] = collections.deque(maxlen=max(30, b["min_events"]))
        if dq and t - dq[-1] < 1:  # παράλληλες συνδέσεις / retransmits
            return
        dq.append(t)
        n = b["min_events"]
        if len(dq) < n:
            return
        ts = list(dq)[-n:]
        iv = [y - x for x, y in zip(ts, ts[1:])]
        mean = sum(iv) / len(iv)
        if not b["min_interval"] <= mean <= b["max_interval"]:
            return
        cv = (sum((x - mean) ** 2 for x in iv) / len(iv)) ** 0.5 / mean
        if cv <= b["max_jitter"]:
            self.alert("Beaconing (πιθανό C2)", "med", dst, src,
                       f"Η {src} ανοίγει σύνδεση στο {dst}:{dp} κάθε ~{mean:.0f}s (απόκλιση ±{cv * 100:.0f}%), "
                       f"{len(ts)} φορές στη σειρά — τέτοιο «ρολόι» είναι τυπικό για malware που ζητάει εντολές",
                       t, key=("beacon", key), cooldown=600)

    # --- DNS tunneling: δεδομένα κρυμμένα σε subdomains ---
    def _dns_query(self, src, qname, t):
        if ip_kind(src) != "local":
            return
        q = qname.lower().rstrip(".")
        if q.endswith((".local", ".arpa", ".lan", ".home", ".localdomain")) or self._allowed_name(q):
            return
        base, sub = split_domain(q)
        if not sub:
            return
        th = self._th("dns_tunnel")
        flat = sub.replace(".", "")
        if (len(flat) >= th["min_length"] and entropy(flat) >= th["min_entropy"]) or len(q) > 120:
            dq = self.w_dnstun.add((src, base), sub, t)
            n = len({i for _, i in dq})
            if n >= th["unique_subdomains"]:
                self.alert("DNS tunneling", "high", src, base,
                           f"{n} μοναδικά, τυχαία subdomains του {base} σε {th['window']}s (π.χ. {sub[:32]}…) — "
                           "δεδομένα κρυμμένα μέσα σε ερωτήματα DNS (exfiltration / C2)", t,
                           key=("dnstun", src, base), cooldown=300)

    # --- DGA: πολλά ανύπαρκτα «τυχαία» domains ---
    def _nxdomain(self, client, qname, t):
        if ip_kind(client) != "local":
            return
        q = qname.lower().rstrip(".")
        base, _ = split_domain(q)
        th = self._th("dga")
        if self._allowed_name(q) or dga_score(base.split(".")[0]) < th["min_score"]:
            return
        dq = self.w_dga.add(client, q, t)
        names = {i for _, i in dq}
        if len(names) >= th["nxdomain"]:
            self.alert("DGA domains", "high", client, "DNS",
                       f"{len(names)} ανύπαρκτα «τυχαία» domains σε {th['window']}s (π.χ. {', '.join(sorted(names)[:3])}) "
                       "— malware που ψάχνει τον server του (Domain Generation Algorithm)", t,
                       key=("dga", client), cooldown=300)

    # --- threat intel ---
    def _intel_check(self, src, dst, dp, t):
        hs, hd = self.hosts.get(src), self.hosts.get(dst)
        if hd is not None and hd["intel"] and ip_kind(src) == "local":
            c2 = any(f["kind"] == "c2" for f in hd["intel"])
            self.alert("Σύνδεση σε κακόβουλη IP", "high" if c2 else "med", dst, src,
                       f"Η {src} επικοινωνεί με {dst}{':' + str(dp) if dp else ''} που υπάρχει στη λίστα "
                       f"{', '.join(f['name'] for f in hd['intel'])}"
                       f"{' — πιθανή μόλυνση από botnet!' if c2 else ''}", t, key=("intel", dst), cooldown=600)
        elif hs is not None and hs["intel"] and ip_kind(dst) == "local":
            self.alert("Κίνηση από κακόβουλη IP", "med", src, dst,
                       f"Πακέτα από IP που υπάρχει στη λίστα {', '.join(f['name'] for f in hs['intel'])}",
                       t, key=("intel", src), cooldown=600)

    # --- νέες συσκευές ---
    def _mac_seen(self, ip, mac, t):
        if not mac or mac in self.seen_macs or mac == "ff:ff:ff:ff:ff:ff":
            return
        self.seen_macs.add(mac)
        try:
            self.history.device_seen(mac, ip, t)
        except Exception as e:
            log("history error:", e)
        if mac in self.known_macs:
            return
        self.known_macs.add(mac)
        warm = self._th("new_device")["warmup"]
        if ip in self.me or ip == self.gateway or ip_kind(ip) != "local":
            return
        if self.had_devices or (self.first_t is not None and t - self.first_t >= warm):
            self.alert("Νέα συσκευή", "low", ip, self.gateway or "LAN",
                       f"Πρώτη φορά στο δίκτυο: {ip} με MAC {mac}"
                       f"{' (τυχαία MAC — μάλλον κινητό)' if random_mac(mac) else ''}. Την αναγνωρίζεις;",
                       t, key=("newdev", mac), cooldown=10 ** 9)

    def _arp(self, P, t):
        a = P["arp"]
        op, psrc, pdst, hw = a["op"], a["psrc"], a["pdst"], norm_mac(a["hwsrc"])
        if op == 1 and psrc not in self.me and psrc != self.gateway and psrc != pdst:
            th = self._th("arp_sweep")
            dq = self.w_sweep.add(("arp", psrc), pdst, t)
            n = len({i for ti, i in dq if ti >= t - th["window"]})
            if n >= th["count"]:
                self.alert("Network sweep (ARP)", "med", psrc, pdst,
                           f"ARP ερωτήσεις για {n} IP σε {th['window']}s — κάποιος σκανάρει το LAN", t)
        if psrc and psrc != "0.0.0.0" and hw and hw != "ff:ff:ff:ff:ff:ff":
            old = self.arp_table.get(psrc)
            trusted = self.arp_first.setdefault(psrc, old or hw)
            if old and old != hw and hw != trusted:
                gw = psrc == self.gateway
                others = [i for i in self.mac_ips.get(hw, ()) if i != psrc and self.arp_first.get(i) == hw]
                actor = others[0] if others else psrc
                self.alert("ARP spoofing" + (" (ROUTER)" if gw else ""), "high", actor, psrc,
                           f"Η IP {psrc}{' του router' if gw else ''} άλλαξε MAC {trusted} → {hw}"
                           f"{' (ανήκει στη ' + actor + ')' if others else ''}. Πιθανό Man‑in‑the‑Middle.",
                           t, key=("arp", psrc, hw))
            self.arp_table[psrc] = hw
            self.mac_ips[hw].add(psrc)
            h = self.hosts.get(psrc)
            if h is not None:
                h["mac"] = hw
            if hw == trusted:
                self._mac_seen(psrc, hw, t)
        if op == 2:
            th = self._th("arp_flood")
            dq = self.w_arpflood.add(hw, 1, t)
            if len(dq) >= th["count"]:
                self.alert("ARP flood", "med", psrc, pdst, f"{len(dq)} ARP replies σε {th['window']}s από {hw}", t)

    # ---------- periodic flush to browsers ----------
    def snapshot(self):
        with self.lock:
            return {"type": "snapshot", "mode": self.mode, "iface": self.iface,
                    "me": sorted(self.me), "gw": self.gateway, "home": self.home,
                    "hosts": [self.ser(h) for h in self.hosts.values()],
                    "alerts": list(self.alerts)[:200], "stats": self._stats(1), "features": self.features()}

    def _stats(self, dt):
        return {"pps": round(self.win_pkts / dt, 1), "bps": round(self.win_bytes / dt),
                "pkts": self.total_pkts, "bytes": self.total_bytes, "hosts": len(self.hosts),
                "alerts": self.alert_seq, "protos": dict(self.protos.most_common(10)),
                "uptime": round(time.time() - self.started)}

    def flusher(self):
        last_stats = time.time()
        tick = 0
        while True:
            time.sleep(0.2)
            tick += 1
            now = time.time()
            with self.lock:
                items, self.pending = self.pending, []
                if len(items) > 160:
                    keep = [i for i in items if i["x"]][:60]
                    items = sorted(keep + random.sample(items, 160 - len(keep)), key=lambda i: i["t"])
                newh = [self.ser(self.hosts[i]) for i in self.new_hosts if i in self.hosts]
                self.new_hosts.clear()
                msg = {"type": "pkts", "items": items}
                if newh:
                    msg["hosts"] = newh
                if now - last_stats >= 1:
                    msg["stats"] = self._stats(now - last_stats)
                    self.win_pkts = self.win_bytes = 0
                    last_stats = now
                    dirty = [self.ser(self.hosts[i]) for i in list(self.dirty)[:400] if i in self.hosts]
                    self.dirty.clear()
                    if dirty:
                        msg["hosts"] = msg.get("hosts", []) + dirty
                if tick % 150 == 0:
                    for w in self.windows:
                        w.gc(self.last_t)
                    maxi = self._th("beaconing")["max_interval"] * 2
                    for k in [k for k, dq in self.beacons.items() if dq and dq[-1] < self.last_t - maxi]:
                        del self.beacons[k]
                minute = int(now // 60)
                if minute != self.cur_minute:
                    mp, mb, self.min_pkts, self.min_bytes = self.min_pkts, self.min_bytes, 0, 0
                    self.cur_minute = minute
                    try:
                        self.history.add_traffic(minute - 1, mp, mb)
                    except Exception as e:
                        log("history error:", e)
            if items or "hosts" in msg or "stats" in msg:
                self.publish(msg)


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


# ---------------- live capture ----------------
GREASE = {0x0a0a + 0x1010 * i for i in range(16)}


def parse_client_hello(b):
    """TLS ClientHello → SNI + JA3 fingerprint (https://github.com/salesforce/ja3)."""
    try:
        if len(b) < 43 or b[0] != 0x16 or b[5] != 0x01:
            return None
        complete = len(b) >= 5 + int.from_bytes(b[3:5], "big")
        ver = int.from_bytes(b[9:11], "big")
        i = 43
        i += 1 + b[i]
        cl = int.from_bytes(b[i:i + 2], "big")
        ciphers = [int.from_bytes(b[j:j + 2], "big") for j in range(i + 2, min(len(b), i + 2 + cl) - 1, 2)]
        i += 2 + cl
        i += 1 + b[i]
        end = min(len(b), i + 2 + int.from_bytes(b[i:i + 2], "big"))
        i += 2
        exts, curves, pfs, sni = [], [], [], None
        while i + 4 <= end:
            et, el = int.from_bytes(b[i:i + 2], "big"), int.from_bytes(b[i + 2:i + 4], "big")
            i += 4
            data = b[i:i + el]
            exts.append(et)
            if et == 0 and len(data) >= 5:
                nl = int.from_bytes(data[3:5], "big")
                sni = data[5:5 + nl].decode("ascii", "ignore") or None
            elif et == 10 and len(data) >= 2:
                ll = int.from_bytes(data[0:2], "big")
                curves = [int.from_bytes(data[k:k + 2], "big") for k in range(2, min(len(data), 2 + ll) - 1, 2)]
            elif et == 11 and len(data) >= 1:
                pfs = list(data[1:1 + data[0]])
            i += el
    except Exception:
        return None
    g = lambda xs: "-".join(str(x) for x in xs if x not in GREASE)  # noqa: E731
    ja3_str = f"{ver},{g(ciphers)},{g(exts)},{g(curves)},{'-'.join(map(str, pfs))}"
    return {"sni": sni, "ja3": hashlib.md5(ja3_str.encode()).hexdigest() if complete else None, "ja3_str": ja3_str}


def parse_sni(b):
    r = parse_client_hello(b)
    return r["sni"] if r else None


HTTP_HOST = re.compile(rb"\r\nHost:\s*([^\r\n:]+)", re.I)


def make_parser():
    from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, IPv6
    from scapy.layers.dhcp import BOOTP  # noqa: F401  (registers DHCP dissector)

    def parse(pkt):
        P = {"t": time.time(), "len": len(pkt)}
        if Ether in pkt:
            P["smac"] = pkt[Ether].src
        if ARP in pkt:
            a = pkt[ARP]
            P.update(src=a.psrc, dst=a.pdst, proto="ARP",
                     arp=dict(op=int(a.op), psrc=a.psrc, pdst=a.pdst, hwsrc=a.hwsrc))
            return P
        if IP in pkt:
            P["src"], P["dst"] = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            P["src"], P["dst"] = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return None
        if TCP in pkt:
            tcp = pkt[TCP]
            P.update(proto="TCP", sp=int(tcp.sport), dp=int(tcp.dport), flags=str(tcp.flags))
            pl = bytes(tcp.payload)
            if pl:
                if pl[0] == 0x16:
                    ch = parse_client_hello(pl)
                    if ch:
                        P["sni"], P["ja3"] = ch["sni"], ch["ja3"]
                elif pl[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                    m = HTTP_HOST.search(pl[:2048])
                    if m:
                        P["http_host"] = m.group(1).decode("ascii", "ignore")
        elif UDP in pkt:
            udp = pkt[UDP]
            P.update(proto="UDP", sp=int(udp.sport), dp=int(udp.dport))
            if DNS in pkt:
                d = pkt[DNS]
                try:
                    qd = d.qd[0] if isinstance(d.qd, list) else d.qd
                    qn = qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname)
                    if d.qr == 0:
                        P["dns_q"] = (qn.rstrip("."), int(qd.qtype))
                    elif int(d.rcode) == 3:
                        P["nx"] = qn.rstrip(".")
                except Exception:
                    pass
            if DNS in pkt and pkt[DNS].qr == 1 and pkt[DNS].ancount:
                d = pkt[DNS]
                try:
                    rrs = d.an if isinstance(d.an, list) else [d.an[i] for i in range(d.ancount)]
                    ans = []
                    for rr in rrs:
                        if getattr(rr, "type", 0) in (1, 28):
                            name = rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname)
                            ans.append((name.rstrip("."), str(rr.rdata)))
                    P["dns"] = ans
                except Exception:
                    pass
        elif ICMP in pkt:
            P.update(proto="ICMP", icmp_type=int(pkt[ICMP].type))
        elif IPv6 in pkt and pkt[IPv6].nh == 58:
            P["proto"] = "ICMPv6"
        else:
            P["proto"] = "IP"
        return P
    return parse


def live_capture(state, iface, bpf):
    from scapy.all import sniff
    parse = make_parser()

    def cb(pkt):
        try:
            P = parse(pkt)
            if P:
                state.process(P)
        except Exception as e:
            log("parse error:", e)
    log(f"Καταγραφή στο {iface}{' με φίλτρο ' + bpf if bpf else ''} …")
    try:
        sniff(iface=iface, prn=cb, store=False, filter=bpf or None)
    except PermissionError:
        log("✖ Χρειάζεται sudo για καταγραφή πακέτων. Τρέξε: sudo .venv/bin/python netwatch.py  (ή --demo)")
        os._exit(1)


def detect_net(iface=None):
    gw, me, found_if = None, set(), None
    try:
        out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"gateway:\s*(\S+)", out)
        gw = m.group(1) if m else None
        m = re.search(r"interface:\s*(\S+)", out)
        found_if = m.group(1) if m else None
    except Exception:
        pass
    if not gw:  # Linux
        try:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"default via (\S+) dev (\S+)", out)
            if m:
                gw, found_if = m.group(1), m.group(2)
        except Exception:
            pass
    iface = iface or found_if
    if iface:
        for cmd in (["ifconfig", iface], ["ip", "addr", "show", iface]):
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
            except Exception:
                continue
            for ip in re.findall(r"inet6? (?:addr:)?([0-9a-fA-F:.%]+)", out):
                me.add(ip.split("%")[0].split("/")[0])
            if me:
                break
    return iface, gw, me


def seed_arp(state):
    try:
        out = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=5).stdout
        for ip, mac in re.findall(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)", out):
            state.arp_table[ip] = state.arp_first[ip] = norm_mac(mac)
            state.mac_ips[norm_mac(mac)].add(ip)
        log(f"ARP πίνακας: {len(state.arp_table)} εγγραφές (router MAC: {state.arp_table.get(state.gateway, '?')})")
    except Exception:
        pass


# ---------------- PCAP replay ----------------
def pcap_guess(path, limit=20000):
    """Μαντεύει ποιος είναι ο «δικός μας» υπολογιστής και ο router μέσα σε ένα pcap."""
    from scapy.all import ARP, IP, Ether, PcapReader
    out_cnt, gw_macs, mac_ip = collections.Counter(), collections.Counter(), {}
    with PcapReader(path) as rd:
        for i, p in enumerate(rd):
            if i >= limit:
                break
            if ARP in p and int(p[ARP].op) == 2:
                mac_ip[norm_mac(p[ARP].hwsrc)] = p[ARP].psrc
            if IP in p:
                s, d = p[IP].src, p[IP].dst
                if ip_kind(s) == "local" and ip_kind(d) == "public":
                    out_cnt[s] += 1
                    if Ether in p:
                        gw_macs[norm_mac(p[Ether].dst)] += 1
                if Ether in p and ip_kind(s) == "local":
                    mac_ip.setdefault(norm_mac(p[Ether].src), s)
    me = out_cnt.most_common(1)[0][0] if out_cnt else None
    gw = mac_ip.get(gw_macs.most_common(1)[0][0]) if gw_macs else None
    if not gw and me and "." in me:
        gw = me.rsplit(".", 1)[0] + ".1"
    return me, gw


def pcap_replay(state, path, speed=1.0, loop=False, done=None):
    """Ξαναπαίζει ένα pcap μέσα από την ίδια μηχανή ανίχνευσης.
    speed=1 πραγματικός χρόνος, 10 = 10x πιο γρήγορα, 0 = όσο πιο γρήγορα γίνεται.
    Οι ανιχνευτές βλέπουν τις αρχικές χρονοσφραγίδες της καταγραφής (forensics),
    ενώ τα μεγάλα κενά στην αναπαραγωγή «πηδιούνται»."""
    from scapy.all import PcapReader
    parse = make_parser()
    shift, rnd = 0.0, 0
    while True:
        wall0, first, last, n = time.time(), None, None, 0
        with PcapReader(path) as rd:
            for pkt in rd:
                pt = float(pkt.time)
                if first is None:
                    first = pt
                if speed > 0:
                    delay = wall0 + (pt - first) / speed - time.time()
                    if delay > 2:  # μεγάλο κενό στην καταγραφή → το πηδάμε
                        wall0 -= delay - 2
                        delay = 2
                    if delay > 0:
                        time.sleep(delay)
                elif n % 200 == 0:
                    time.sleep(0.005)
                try:
                    P = parse(pkt)
                except Exception:
                    P = None
                if P:
                    P["t"] = pt + shift
                    state.process(P)
                    n += 1
                last = pt
        log(f"PCAP: τέλος αναπαραγωγής #{rnd + 1} ({n} πακέτα, {state.alert_seq} ειδοποιήσεις)")
        if not loop:
            break
        rnd += 1
        shift += (last or 0) - (first or 0) + 3600  # κάθε επανάληψη «μετά» την προηγούμενη
        time.sleep(3)
    if done:
        done()


# ---------------- demo / simulation ----------------
DEMO_REMOTE = [
    ("142.250.184.110", "www.google.com", "United States", "US", "Mountain View", 37.42, -122.08, "Google LLC", "AS15169 Google LLC", 30),
    ("157.240.9.35", "graph.facebook.com", "Ireland", "IE", "Dublin", 53.34, -6.26, "Meta Platforms", "AS32934 Facebook, Inc.", 10),
    ("104.16.132.229", "cdnjs.cloudflare.com", "Germany", "DE", "Frankfurt", 50.11, 8.68, "Cloudflare, Inc.", "AS13335 Cloudflare, Inc.", 12),
    ("52.94.236.248", "s3.eu-central-1.amazonaws.com", "Germany", "DE", "Frankfurt", 50.11, 8.68, "Amazon.com", "AS16509 Amazon.com, Inc.", 8),
    ("13.107.42.14", "outlook.office.com", "Netherlands", "NL", "Amsterdam", 52.37, 4.89, "Microsoft Corporation", "AS8075 Microsoft Corporation", 8),
    ("45.57.90.1", "ipv4-c001-ath001.nflxvideo.net", "Greece", "GR", "Athens", 37.98, 23.73, "Netflix Streaming Services", "AS2906 Netflix", 40),
    ("151.101.1.140", "www.reddit.com", "United States", "US", "San Francisco", 37.77, -122.42, "Fastly", "AS54113 Fastly", 5),
    ("140.82.121.4", "github.com", "Germany", "DE", "Frankfurt", 50.11, 8.68, "GitHub, Inc.", "AS36459 GitHub, Inc.", 5),
    ("17.253.53.207", "swcdn.apple.com", "Sweden", "SE", "Stockholm", 59.33, 18.06, "Apple Inc.", "AS714 Apple Inc.", 6),
    ("91.198.174.192", "el.wikipedia.org", "Netherlands", "NL", "Amsterdam", 52.37, 4.89, "Wikimedia Foundation", "AS14907 Wikimedia", 3),
    ("193.92.150.3", "dns.otenet.gr", "Greece", "GR", "Athens", 37.98, 23.73, "OTEnet S.A.", "AS6799 OTEnet S.A.", 4),
    ("23.32.29.18", "a248.e.akamai.net", "Japan", "JP", "Tokyo", 35.68, 139.69, "Akamai Technologies", "AS20940 Akamai", 3),
    ("200.147.67.142", "www.uol.com.br", "Brazil", "BR", "São Paulo", -23.55, -46.63, "UOL", "AS7162 Universo Online", 1),
    ("1.1.1.1", "one.one.one.one", "Australia", "AU", "Sydney", -33.87, 151.21, "Cloudflare, Inc.", "AS13335 Cloudflare, Inc.", 2),
    ("35.186.224.25", "spclient.wg.spotify.com", "United States", "US", "Council Bluffs", 41.26, -95.86, "Google Cloud", "AS15169 Google LLC", 6),
    ("41.63.64.10", "cdn.example.za", "South Africa", "ZA", "Johannesburg", -26.2, 28.04, "Demo Telecom", "AS0000 Demo", 1),
]


def demo_attackers():
    def rip(a):
        return f"{a}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return [
        (rip(185), "Russia", "RU", "Moscow", 55.75, 37.62, "DemoBulletproof LLC (demo)", "AS64501 DEMO-BP", True, True),
        (rip(61), "China", "CN", "Nanjing", 32.06, 118.78, "DemoNet Backbone (demo)", "AS64502 DEMO-CN", False, True),
        (rip(103), "Vietnam", "VN", "Hanoi", 21.03, 105.85, "Demo VPS (demo)", "AS64503 DEMO-VPS", True, True),
        (rip(45), "Netherlands", "NL", "Amsterdam", 52.37, 4.89, "Scanner Inc (demo)", "AS64504 DEMO-SCAN", False, True),
    ]


def demo_run(state):
    me, gw = "192.168.1.23", "192.168.1.1"
    lan = {"192.168.1.10": "smart-tv.local", "192.168.1.15": "iphone.local",
           "192.168.1.40": "printer.local", "192.168.1.77": "unknown-laptop.local"}
    macs = {gw: "a4:2b:b0:11:22:01", me: "3c:22:fb:aa:bb:23", "192.168.1.10": "f0:de:f1:10:10:10",
            "192.168.1.15": "ac:1f:74:15:15:15", "192.168.1.40": "00:1e:0b:40:40:40",
            "192.168.1.77": "de:ad:be:ef:77:77"}
    state.arp_table.update(macs)
    state.arp_first.update(macs)
    for ip, m in macs.items():
        state.mac_ips[m].add(ip)
    state.home = {"status": "success", "query": "79.130.12.34", "country": "Greece", "countryCode": "GR",
                  "city": "Athens", "regionName": "Attica", "lat": 37.98, "lon": 23.73,
                  "isp": "Demo ISP", "org": "Demo ISP", "as": "AS6799 (demo)"}
    for ip, name, c, cc, city, lat, lon, isp, asn, _ in DEMO_REMOTE:
        state.demo_geo[ip] = ({"country": c, "countryCode": cc, "city": city, "regionName": "", "lat": lat,
                               "lon": lon, "isp": isp, "org": isp, "as": asn, "proxy": False,
                               "hosting": True, "mobile": False, "query": ip}, name)
        state.domains[ip].add(name)
    attackers = demo_attackers()
    for ip, c, cc, city, lat, lon, isp, asn, proxy, hosting in attackers:
        state.demo_geo[ip] = ({"country": c, "countryCode": cc, "city": city, "regionName": "", "lat": lat,
                               "lon": lon, "isp": isp, "org": isp, "as": asn, "proxy": proxy,
                               "hosting": hosting, "mobile": False, "query": ip}, None)
    for ip, n in lan.items():
        state.demo_geo[ip] = (None, n)
    state.demo_geo[gw] = (None, "router.home")
    weights = [r[-1] for r in DEMO_REMOTE]
    # threat intel (demo): ο «ρώσος» επιτιθέμενος σε blocklist + ένας C2 server που «καλεί» το laptop
    c2 = f"91.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    state.demo_geo[c2] = ({"country": "Romania", "countryCode": "RO", "city": "Bucharest", "regionName": "",
                           "lat": 44.43, "lon": 26.10, "isp": "Bulletproof C2 Hosting (demo)", "org": "(demo)",
                           "as": "AS64505 DEMO-C2", "proxy": False, "hosting": True, "mobile": False, "query": c2},
                          None)
    state.intel.add(attackers[0][0] + "/32", "Demo blocklist (demo)", "block")
    state.intel.add(c2 + "/32", "Feodo Tracker (demo)", "c2")
    state.intel.loaded = True
    ja3 = {ip: hashlib.md5(f"demo-{ip}".encode()).hexdigest() for ip in [me] + list(lan)}
    newdev, newdev_mac = "192.168.1.99", "da:7c:31:99:99:99"
    state.cfg["thresholds"]["new_device"]["warmup"] = 30

    def emit(**P):
        P.setdefault("t", time.time())
        P.setdefault("len", random.randint(60, 1500))
        state.process(P)

    def background():
        while True:
            r = random.choices(DEMO_REMOTE, weights)[0]
            port = random.choice([443, 443, 443, 80, 443]) if r[0] != "193.92.150.3" else 53
            sp = random.randint(49152, 65000)
            client = me if random.random() < 0.8 else random.choice(list(lan))
            if port == 53:
                emit(src=client, dst=r[0], proto="UDP", sp=sp, dp=53, len=80)
                pick = random.choice(DEMO_REMOTE)
                emit(src=r[0], dst=client, proto="UDP", sp=53, dp=sp, len=140, dns=[(pick[1], pick[0])])
            elif random.random() < 0.25 and port == 443:
                emit(src=client, dst=r[0], proto="UDP", sp=sp, dp=443, len=1250)
                emit(src=r[0], dst=client, proto="UDP", sp=443, dp=sp, len=1350)
            else:
                emit(src=client, dst=r[0], proto="TCP", sp=sp, dp=port, flags="PA", len=random.randint(80, 600),
                     sni=r[1] if port == 443 else None, http_host=r[1] if port == 80 else None,
                     ja3=ja3.get(client) if port == 443 else None)
                for _ in range(random.randint(1, 3)):
                    emit(src=r[0], dst=client, proto="TCP", sp=port, dp=sp, flags="A", len=random.randint(800, 1500))
            if random.random() < 0.08:
                dev = random.choice(list(lan))
                emit(src=dev, dst="224.0.0.251", proto="UDP", sp=5353, dp=5353, len=180, smac=macs[dev])
            if random.random() < 0.04:
                dev = random.choice(list(lan))
                emit(src=dev, dst="239.255.255.250", proto="UDP", sp=50000, dp=1900, len=300, smac=macs[dev])
            if random.random() < 0.03:
                a, b = random.sample(list(lan) + [me, gw], 2)
                emit(src=a, dst=b, proto="ARP", len=42, arp=dict(op=1, psrc=a, pdst=b, hwsrc=macs[a]))
                emit(src=b, dst=a, proto="ARP", len=42, arp=dict(op=2, psrc=b, pdst=a, hwsrc=macs[b]))
            if random.random() < 0.05:
                emit(src="192.168.1.10", dst="192.168.1.40", proto="TCP", sp=51000, dp=9100, flags="PA", len=900)
            time.sleep(random.uniform(0.008, 0.03))

    def beacon():
        # το «παραβιασμένο» laptop καλεί τον C2 κάθε 6 δευτερόλεπτα με ακρίβεια ρολογιού
        time.sleep(20)
        while True:
            sp = random.randint(49152, 65000)
            emit(src="192.168.1.77", dst=c2, proto="TCP", sp=sp, dp=8443, flags="S", len=60)
            emit(src=c2, dst="192.168.1.77", proto="TCP", sp=8443, dp=sp, flags="SA", len=60)
            emit(src="192.168.1.77", dst=c2, proto="TCP", sp=sp, dp=8443, flags="PA", len=220)
            time.sleep(6 + random.uniform(-0.2, 0.2))

    def rnd_label(n, alphabet="bcdfghjklmnpqrstvwxz0123456789"):
        return "".join(random.choice(alphabet) for _ in range(n))

    def scenarios():
        time.sleep(8)
        i = 0
        order = ["portscan", "dga", "arpspoof", "newdev", "brute", "dnstunnel", "xmas", "synflood",
                 "arpsweep", "dhcp", "pingsweep"]
        while True:
            kind = order[i % len(order)]
            i += 1
            log(f"(demo) σενάριο επίθεσης: {kind}")
            A = attackers[i % len(attackers)][0]
            if kind == "portscan":
                for p in random.sample(range(1, 10000), 45):
                    emit(src=A, dst=me, proto="TCP", sp=random.randint(40000, 60000), dp=p, flags="S", len=60)
                    emit(src=me, dst=A, proto="TCP", sp=p, dp=40000, flags="RA", len=54)
                    time.sleep(0.07)
            elif kind == "brute":
                for _ in range(25):
                    sp = random.randint(40000, 60000)
                    emit(src=A, dst=me, proto="TCP", sp=sp, dp=22, flags="S", len=60)
                    emit(src=me, dst=A, proto="TCP", sp=22, dp=sp, flags="SA", len=60)
                    emit(src=A, dst=me, proto="TCP", sp=sp, dp=22, flags="PA", len=300)
                    time.sleep(0.25)
            elif kind == "arpspoof":
                for _ in range(12):
                    emit(src=gw, dst=me, proto="ARP", len=42, smac=macs["192.168.1.77"],
                         arp=dict(op=2, psrc=gw, pdst=me, hwsrc=macs["192.168.1.77"]))
                    time.sleep(0.4)
                emit(src=gw, dst=me, proto="ARP", len=42, arp=dict(op=2, psrc=gw, pdst=me, hwsrc=macs[gw]))
            elif kind == "xmas":
                for p in (21, 22, 80, 443, 3389):
                    emit(src=A, dst=me, proto="TCP", sp=41000, dp=p, flags="FPU", len=60)
                    time.sleep(0.2)
            elif kind == "synflood":
                srcs = [a[0] for a in attackers]
                for _ in range(380):
                    emit(src=random.choice(srcs), dst=me, proto="TCP", sp=random.randint(1024, 65000), dp=443,
                         flags="S", len=60)
                    time.sleep(0.008)
            elif kind == "arpsweep":
                for n in range(2, 80):
                    emit(src="192.168.1.77", dst=f"192.168.1.{n}", proto="ARP", len=42,
                         arp=dict(op=1, psrc="192.168.1.77", pdst=f"192.168.1.{n}", hwsrc=macs["192.168.1.77"]))
                    time.sleep(0.04)
            elif kind == "dhcp":
                emit(src="192.168.1.77", dst="255.255.255.255", proto="UDP", sp=67, dp=68, len=342)
            elif kind == "dga":  # η «μολυσμένη» smart TV ψάχνει τον C2 της σε τυχαία domains
                for _ in range(12):
                    name = rnd_label(random.randint(10, 14)) + random.choice([".com", ".net", ".biz", ".info"])
                    sp = random.randint(40000, 60000)
                    emit(src="192.168.1.10", dst=gw, proto="UDP", sp=sp, dp=53, len=80, dns_q=(name, 1),
                         smac=macs["192.168.1.10"])
                    emit(src=gw, dst="192.168.1.10", proto="UDP", sp=53, dp=sp, len=140, nx=name)
                    time.sleep(0.3)
            elif kind == "dnstunnel":  # το laptop «βγάζει» δεδομένα μέσα σε ερωτήματα DNS
                for _ in range(36):
                    sub = rnd_label(30, "0123456789abcdef") + "." + rnd_label(8, "0123456789abcdef")
                    sp = random.randint(40000, 60000)
                    emit(src="192.168.1.77", dst=gw, proto="UDP", sp=sp, dp=53, len=160,
                         dns_q=(f"{sub}.exfil-demo.example", 16))
                    time.sleep(0.12)
            elif kind == "newdev":  # άγνωστο κινητό μπαίνει στο Wi-Fi
                for _ in range(3):
                    emit(src=newdev, dst="224.0.0.251", proto="UDP", sp=5353, dp=5353, len=180, smac=newdev_mac)
                    emit(src=newdev, dst=gw, proto="ARP", len=42,
                         arp=dict(op=1, psrc=newdev, pdst=gw, hwsrc=newdev_mac))
                    time.sleep(0.5)
            elif kind == "pingsweep":
                for n in range(1, 50):
                    emit(src=A, dst=f"192.168.1.{n}", proto="ICMP", icmp_type=8, len=98)
                    time.sleep(0.05)
            time.sleep(random.uniform(14, 22))

    threading.Thread(target=background, daemon=True).start()
    threading.Thread(target=scenarios, daemon=True).start()
    threading.Thread(target=beacon, daemon=True).start()


# ---------------- web server ----------------
def make_handler(state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path in ("/", "/index.html"):
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if u.path == "/edu.js":
                with open(os.path.join(HERE, "edu.js"), "rb") as f:
                    return self._send(200, f.read(), "text/javascript; charset=utf-8")
            if u.path == "/api/whois":
                ip = parse_qs(u.query).get("ip", [""])[0]
                return self._send(200, json.dumps({"ip": ip, "text": whois(ip)}).encode(), "application/json")
            if u.path == "/api/history":
                try:
                    hours = max(1, min(24 * 90, float(parse_qs(u.query).get("hours", ["24"])[0])))
                except ValueError:
                    hours = 24
                ref = state.last_t if state.mode == "pcap" and state.last_t else None
                return self._send(200, json.dumps(state.history.query(hours, ref)).encode(), "application/json")
            if u.path == "/api/abuseipdb":
                ip = parse_qs(u.query).get("ip", [""])[0]
                key = state.cfg.get("intel", {}).get("abuseipdb_key")
                if not key:
                    return self._send(400, b'{"error":"abuseipdb_key not set in config.yaml"}', "application/json")
                try:
                    data = {"ip": ip, "data": abuseipdb_check(key, ip)}
                except Exception as e:
                    data = {"ip": ip, "error": str(e)[:200]}
                return self._send(200, json.dumps(data).encode(), "application/json")
            if u.path == "/events":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                q = state.subscribe()
                try:
                    self.wfile.write(b"data: " + json.dumps(state.snapshot()).encode() + b"\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            data = b"data: " + json.dumps(q.get(timeout=10), separators=(",", ":")).encode() + b"\n\n"
                        except queue.Empty:
                            data = b": ping\n\n"
                        self.wfile.write(data)
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    state.unsubscribe(q)
                return
            self._send(404, b"not found", "text/plain")
    return H


def open_browser(url):
    """Ανοίγει τον browser ως ο κανονικός χρήστης, ακόμα κι αν τρέχουμε με sudo."""
    time.sleep(1.5)
    cmd = ["open", url] if sys.platform == "darwin" else ["xdg-open", url]
    user = os.environ.get("SUDO_USER")
    if user and os.geteuid() == 0:
        cmd = ["sudo", "-u", user] + cmd
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="NetWatch — live network map & attack detector")
    ap.add_argument("--demo", action="store_true", help="προσομοίωση κίνησης & επιθέσεων (χωρίς root)")
    ap.add_argument("-i", "--iface", help="interface (π.χ. en0)")
    ap.add_argument("-f", "--filter", default="", help="BPF φίλτρο (π.χ. 'not port 22')")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-open", action="store_true", help="να μην ανοίξει αυτόματα ο browser")
    ap.add_argument("--no-geo", action="store_true", help="χωρίς γεωεντοπισμό μέσω ip-api.com")
    ap.add_argument("--no-rdns", action="store_true", help="χωρίς reverse DNS")
    ap.add_argument("--pcap", help="αναπαραγωγή αρχείου .pcap/.pcapng αντί για live (χωρίς root)")
    ap.add_argument("--speed", type=float, default=1.0, help="ταχύτητα pcap (1 = πραγματική, 0 = μέγιστη)")
    ap.add_argument("--loop", action="store_true", help="επανάληψη του pcap")
    ap.add_argument("--me", help="η IP του «δικού μας» υπολογιστή στο pcap (αλλιώς μαντεύει)")
    ap.add_argument("--gw", help="η IP του router στο pcap (αλλιώς μαντεύει)")
    ap.add_argument("--config", help="αρχείο ρυθμίσεων YAML (προεπιλογή: config.yaml δίπλα στο netwatch.py)")
    ap.add_argument("--history", help="αρχείο SQLite ιστορικού (live: data/netwatch.db, αλλιώς στη μνήμη)")
    ap.add_argument("--notify", action="store_true", help="ειδοποιήσεις macOS/Telegram και σε demo/pcap")
    ap.add_argument("--no-intel", action="store_true", help="χωρίς κατέβασμα blocklists (threat intel)")
    args = ap.parse_args()

    cfg_path = args.config or (os.path.join(HERE, "config.yaml") if os.path.exists(os.path.join(HERE, "config.yaml")) else None)
    cfg = load_config(cfg_path)
    cfg["_path"] = cfg_path
    if cfg_path:
        log(f"Ρυθμίσεις: {cfg_path}")
    mode = "pcap" if args.pcap else "demo" if args.demo else "live"
    hist_path = args.history or (os.path.join(HERE, cfg["history"]["path"]) if mode == "live" else ":memory:")
    history = History(hist_path)
    intel = Intel(cfg["intel"], os.path.join(HERE, "data", "intel"))
    common = dict(cfg=cfg, history=history, intel=intel)

    if args.pcap:
        if not os.path.exists(args.pcap):
            sys.exit(f"Δεν βρέθηκε το αρχείο {args.pcap}")
        g_me, g_gw = pcap_guess(args.pcap)
        me, gw = args.me or g_me, args.gw or g_gw
        state = NetState("pcap", os.path.basename(args.pcap), [me] if me else [], gw,
                         geo=not args.no_geo, rdns=not args.no_rdns, **common)
        log(f"PCAP {args.pcap} | «εγώ» = {me} | router = {gw} | ταχύτητα {args.speed or 'max'}")
        if state.geo_enabled:
            threading.Thread(target=geo_worker, args=(state,), daemon=True).start()
            threading.Thread(target=fetch_home, args=(state,), daemon=True).start()
        start_replay = lambda: pcap_replay(state, args.pcap, args.speed, args.loop)  # noqa: E731
    elif args.demo:
        state = NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False, **common)
        demo_run(state)
    else:
        iface, gw, me = detect_net(args.iface)
        if not iface:
            sys.exit("Δεν βρέθηκε interface — δώσε -i en0")
        state = NetState("live", iface, me, gw, geo=not args.no_geo, rdns=not args.no_rdns, **common)
        log(f"Interface {iface} | οι IP μου {', '.join(sorted(me))} | router {gw} | ιστορικό {hist_path}")
        seed_arp(state)
        if state.geo_enabled:
            threading.Thread(target=geo_worker, args=(state,), daemon=True).start()
            threading.Thread(target=fetch_home, args=(state,), daemon=True).start()
        threading.Thread(target=live_capture, args=(state, iface, args.filter), daemon=True).start()

    if mode == "live" or args.notify:
        state.notifier = Notifier(cfg["notify"])
    if cfg["intel"].get("enabled", True) and cfg["detectors"].get("threat_intel", True) \
            and not args.no_intel and mode != "demo":
        intel_thread = threading.Thread(target=intel.load, args=(state.recheck_intel,), daemon=True)
        intel_thread.start()
        if mode == "pcap":  # στο pcap φόρτωσε πρώτα τις λίστες ώστε να «πιάσει» και τα πρώτα πακέτα
            intel_thread.join(timeout=30)
    if mode == "pcap":
        threading.Thread(target=start_replay, daemon=True).start()

    threading.Thread(target=state.flusher, daemon=True).start()
    srv = None
    for port in range(args.port, args.port + 20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
            break
        except OSError:
            log(f"Η θύρα {port} είναι πιασμένη (τρέχει ήδη άλλο NetWatch;) — δοκιμάζω την {port + 1}")
    if srv is None:
        log(f"✖ Καμία ελεύθερη θύρα από {args.port} έως {args.port + 19}. Δώσε --port.")
        os._exit(1)
    srv.daemon_threads = True
    url = f"http://127.0.0.1:{port}"
    log(f"NetWatch ({state.mode}) → {url}")
    if not args.no_open:
        threading.Thread(target=open_browser, args=(url,), daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("Τέλος.")


if __name__ == "__main__":
    main()
