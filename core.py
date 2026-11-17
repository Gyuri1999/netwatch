"""NetWatch — Σταθερές, ρυθμίσεις (config.yaml) και μικρά βοηθητικά που χρησιμοποιούν όλα τα modules."""
import collections
import copy
import functools
import ipaddress
import json
import math
import os
import random
import re
import subprocess
import sys
import time


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
                 9001: "Tor relay", 9030: "Tor directory"}
TOR_PORTS = {9001, 9030}


_tor_cache = [0.0, False]


def local_tor_running():
    """Τρέχει Tor στο Mac (tor daemon 9050 / Tor Browser 9150); — έλεγχος το πολύ κάθε 30″."""
    now = time.time()
    if now - _tor_cache[0] > 30:
        import privacy
        _tor_cache[:] = [now, privacy.tor_port() is not None]
    return _tor_cache[1]
SEV = {"low": 1, "med": 2, "high": 3}
# Υπηρεσίες που αν «ακούν» σε συσκευή του LAN αυξάνουν την επιφάνεια επίθεσης: (κίνδυνος, γιατί)
RISKY_SERVICES = {
    23: ("high", "Telnet: όλα χωρίς κρυπτογράφηση, ο νο1 στόχος των botnets (Mirai)"),
    21: ("high", "FTP: κωδικοί και αρχεία χωρίς κρυπτογράφηση"),
    3389: ("high", "RDP: απομακρυσμένη επιφάνεια εργασίας, κύρια πόρτα εισόδου για ransomware"),
    5900: ("high", "VNC: απομακρυσμένος έλεγχος οθόνης, συχνά με αδύναμο κωδικό"),
    7547: ("high", "TR-069: απομακρυσμένη διαχείριση router, στόχος botnets"),
    3306: ("high", "MySQL ανοιχτή στο δίκτυο"), 5432: ("high", "PostgreSQL ανοιχτή στο δίκτυο"),
    6379: ("high", "Redis: συχνά χωρίς κωδικό → εκτέλεση κώδικα"),
    27017: ("high", "MongoDB: συχνά χωρίς κωδικό"),
    445: ("med", "SMB: κοινόχρηστα αρχεία, στόχος ransomware (WannaCry)"),
    139: ("med", "NetBIOS/SMB v1: παλιό και ευάλωτο"),
    1900: ("med", "UPnP: προγράμματα μπορούν να ανοίξουν θύρες στο router χωρίς να ρωτήσουν"),
    161: ("med", "SNMP: συχνά με default κωδικό «public»"),
    554: ("med", "RTSP: ροή βίντεο κάμερας"),
    1883: ("med", "MQTT: μηνύματα IoT χωρίς κρυπτογράφηση"),
    80: ("low", "HTTP: σελίδα διαχείρισης χωρίς HTTPS"), 8080: ("low", "HTTP-alt: σελίδα διαχείρισης χωρίς HTTPS"),
    9100: ("low", "Εκτυπωτής (JetDirect): δέχεται εργασίες από οποιονδήποτε"),
    22: ("low", "SSH: ασφαλές αν έχει κλειδιά ή δυνατό κωδικό"),
}
# Πρωτόκολλα χωρίς κρυπτογράφηση (θύρα προορισμού → όνομα)
PLAIN_PORTS = {80: "HTTP", 21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 25: "SMTP",
               53: "DNS", 161: "SNMP", 69: "TFTP", 1883: "MQTT"}

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
    ("Κωδικός σε καθαρό κείμενο", "T1040", "Network Sniffing", "Credential Access", "cleartext_creds"),
    ("Evil twin Wi‑Fi", "T1557", "Adversary-in-the-Middle", "Credential Access", "wifi_guard"),
    ("DNS hijacking στο Wi‑Fi", "T1557", "Adversary-in-the-Middle", "Credential Access", "wifi_guard"),
    ("TLS interception στο Wi‑Fi", "T1557", "Adversary-in-the-Middle", "Credential Access", "wifi_guard"),
    ("Ανοιχτό Wi‑Fi", "T1040", "Network Sniffing", "Credential Access", "wifi_guard"),
    ("Παγίδα", "T1046", "Network Service Discovery", "Discovery", "honeypot"),
    ("Deauth επίθεση", "T1498", "Network Denial of Service", "Impact", "sensor"),
    ("Άγνωστο access point", "T1557", "Adversary-in-the-Middle", "Credential Access", "sensor"),
    ("Tor από συσκευή", "T1090.003", "Proxy: Multi-hop Proxy", "Command and Control", "threat_intel"),
    ("Κίνηση από κόμβο Tor", "T1090.003", "Proxy: Multi-hop Proxy", "Command and Control", "threat_intel"),
    ("Νέα χώρα για συσκευή", "T1071", "Application Layer Protocol", "Command and Control", "threat_intel"),
    ("Υπηρεσία εκτός", "T1499", "Endpoint Denial of Service", "Impact", "health"),
    ("Υπηρεσία επανήλθε", "T1499", "Endpoint Denial of Service", "Impact", "health"),
    ("Πιστοποιητικό λήγει", "T1588.004", "Obtain Capabilities: Digital Certificates", "Resource Development", "health"),
    ("Καναρίνι ESP32", "T1046", "Network Service Discovery", "Discovery", "sensor"),
    ("OTA απορρίφθηκε", "T1195.002", "Compromise Software Supply Chain", "Initial Access", "sensor"),
    ("OTA ενημέρωση", "T1195.002", "Compromise Software Supply Chain", "Initial Access", "sensor"),
    ("Άγνωστος MQTT client", "T1078", "Valid Accounts", "Initial Access", "mqtt_guard"),
    ("Εντολή MQTT", "T0855", "Unauthorized Command Message", "Impair Process Control", "mqtt_guard"),
    ("Νέο MQTT topic", "T1071", "Application Layer Protocol", "Command and Control", "mqtt_guard"),
    ("IoT συσκευή", "T1499", "Endpoint Denial of Service", "Impact", "mqtt_guard"),
]


EXTRA_MITRE = {  # τεχνικές που χρησιμοποιούν συχνά οι δικοί σου κανόνες
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1090": ("Proxy", "Command and Control"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1498": ("Network Denial of Service", "Impact"),
}


def mitre_for(typ):
    for prefix, tid, name, tactic, _ in MITRE:
        if typ.startswith(prefix):
            return {"id": tid, "name": name, "tactic": tactic,
                    "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"}
    return None


def detector_for(typ):
    if typ.startswith("Κανόνας:"):
        return "custom_rules"
    if typ.startswith("Διαρροή"):
        return "privacy_leaks"
    for prefix, *_rest, det in MITRE:
        if typ.startswith(prefix):
            return det
    return None


def quit_now(code=0):
    """Άμεσο τέλος (και από threads), αφού τρέξουν τα atexit (π.χ. αφαίρεση κανόνων τείχους)."""
    import atexit
    try:
        atexit._run_exitfuncs()
    finally:
        os._exit(code)


# ---------------- ρυθμίσεις (config.yaml) ----------------
RULES_DIR = os.path.join(HERE, "rules")

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
        "beaconing", "dns_tunnel", "dga", "new_device", "threat_intel", "cleartext_creds", "custom_rules", "wifi_guard", "privacy_leaks")},
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
            {"name": "Tor exit κόμβοι", "kind": "tor", "url": "https://check.torproject.org/torbulkexitlist"},
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


def mask_user(u):
    """Δείχνουμε μόνο τα 2 πρώτα γράμματα του ονόματος χρήστη."""
    if not u:
        return None
    return (u[:2] if len(u) > 3 else u[:1]) + "***"


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
