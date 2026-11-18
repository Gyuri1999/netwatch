"""🎥 Άμυνα: «Είναι εκτεθειμένες οι κάμερες / τα DVR μου;» — μόνο για το ΔΙΚΟ ΣΟΥ δίκτυο.

Ξαναδιαβάζει την ιδέα του εργαλείου CamXploit (σαρωτής εκτεθειμένων IP καμερών) ως **αμυντικό**
έλεγχο: ελέγχει αν οι κάμερες/καταγραφικά του σπιτιού σου φαίνονται ανοιχτά από το τοπικό δίκτυο,
ώστε να τα κλείσεις ΕΣΥ — ποτέ ως εργαλείο επίθεσης.

ΣΚΛΗΡΟΙ ΚΑΝΟΝΕΣ ΑΣΦΑΛΕΙΑΣ (επιβάλλονται στον κώδικα, όχι μόνο στα σχόλια):
- Κάθε IP-στόχος ΠΡΕΠΕΙ να περάσει έλεγχο ιδιωτικού εύρους· κάθε δημόσια/global IP απορρίπτεται και
  καταγράφεται ως «skipped». (Ίδιος κανόνας με τις ενεργές σαρώσεις του NetWatch: μόνο ιδιωτικά δίκτυα.)
- ΠΟΤΕ δεν προσπαθεί login, δεν στέλνει διαπιστευτήρια και δεν δοκιμάζει προεπιλεγμένους κωδικούς.
  Μόνο παρατηρεί: είναι ανοιχτή η θύρα; τι banner/HTTP headers/TLS πιστοποιητικό δείχνει; ζητάει auth
  (401 / WWW-Authenticate = καλό); Οι «προεπιλεγμένοι κωδικοί» ΜΟΝΟ αναφέρονται ως κίνδυνος προς
  χειροκίνητο έλεγχο — ποτέ δεν δοκιμάζονται.
- ΠΟΤΕ δεν αγγίζει περιεχόμενο RTSP/stream πέρα από μία γραμμή banner· διαβάζει το πολύ ~1 KB και κλείνει,
  με μικρά timeouts (2 s).
"""
import ipaddress
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# θύρα → ελληνική ετικέτα (οι θύρες που ελέγχουν τα CamXploit-style εργαλεία)
CAMERA_PORTS = {
    554: "RTSP (ροή βίντεο)",
    8554: "RTSP (εναλλακτική)",
    10554: "RTSP (εναλλακτική)",
    80: "Web UI κάμερας (HTTP)",
    81: "Web UI κάμερας (HTTP)",
    8000: "Web UI κάμερας (HTTP)",
    8080: "Web UI κάμερας (HTTP)",
    8081: "Web UI κάμερας (HTTP)",
    443: "Web UI κάμερας (HTTPS)",
    8443: "Web UI κάμερας (HTTPS)",
    37777: "Dahua (ιδιόκτητο πρωτόκολλο)",
    34567: "Sofia / XMeye DVR (ιδιόκτητο)",
    9000: "Υπηρεσία κάμερας / XMeye",
    88: "Hikvision (ιδιόκτητο)",
    3702: "ONVIF WS-Discovery",
    5000: "Υπηρεσία κάμερας / UPnP",
    7001: "Web UI / υπηρεσία κάμερας",
    1935: "RTMP (ροή βίντεο)",
}

HTTP_PORTS = {80, 81, 8000, 8080, 8081, 5000, 7001, 88, 9000}
HTTPS_PORTS = {443, 8443}
RTSP_PORTS = {554, 8554, 10554}
# Οι υπόλοιπες (37777, 34567, 3702, 1935) είναι δυαδικά/ιδιόκτητα: διαβάζουμε μόνο ένα banner.

OLD_TLS = {"TLSv1", "TLSv1.1", "SSLv3", "TLSv1.0"}

# ── Αναγνώριση κατασκευαστή από Server-header / realm / RTSP Server / θύρα ──
# (τύπος, regex, κατασκευαστής). Ο τύπος λέει πού ψάχνουμε: "txt" = οπουδήποτε στο banner/header.
VENDOR_HINTS = [
    ("txt", r"hikvision|app-?webs|dvrdvs|dnvrs-?webs", "Hikvision"),
    ("txt", r"dahua|uc-?httpd|webs\b.*dahua|sonia", "Dahua"),
    ("txt", r"\baxis\b|axis communications|boa/.*axis", "Axis"),
    ("txt", r"reolink", "Reolink"),
    ("txt", r"foscam|ipcam_?web", "Foscam"),
    ("txt", r"amcrest", "Amcrest"),
    ("txt", r"ubiquiti|unifi|airvision|ubnt", "Ubiquiti"),
    ("txt", r"tp-?link|tapo", "TP-Link Tapo"),
    ("txt", r"wyze", "Wyze"),
    ("txt", r"xmeye|sofia|uc-?httpd|net surveillance|netsurveillance", "XMeye / Sofia (γενικό DVR)"),
    ("txt", r"onvif", "Γενική ONVIF κάμερα"),
    ("txt", r"rtsp server|live555|gstreamer rtsp", "Γενική RTSP κάμερα"),
]
# Αποτυπώματα θύρας → πιθανός κατασκευαστής (όταν δεν μιλάει το banner).
PORT_VENDOR = {37777: "Dahua", 34567: "XMeye / Sofia (γενικό DVR)", 88: "Hikvision", 3702: "Γενική ONVIF κάμερα"}

# «CVE-ish» banners: παλιές/επικίνδυνες υπογραφές που αξίζει να ελεγχθούν χειροκίνητα (δεν τις εκμεταλλευόμαστε).
RISKY_BANNERS = [
    (r"uc-?httpd", "uc-httpd (Sofia/XMeye) — γνωστές ευπάθειες (π.χ. path traversal, CVE-2018-9995)"),
    (r"app-?webs|hikvision-?webs|dnvrs-?webs", "Παλιό firmware Hikvision — γνωστό backdoor (CVE-2017-7921)"),
    (r"boa/0\.9", "Boa webserver — εγκαταλελειμμένος, με γνωστές ευπάθειες"),
    (r"rompager", "RomPager — ευπάθεια «Misfortune Cookie» (CVE-2014-9222)"),
    (r"goahead-?webs?", "GoAhead — γνωστές ευπάθειες σε παλιές κάμερες (π.χ. CVE-2017-17562)"),
    (r"thttpd/2\.2", "thttpd 2.2x — παλιός, συχνά σε φθηνές κάμερες"),
]

# Κοινές οδηγίες θωράκισης (ελληνικά).
FIXES = {
    "vlan": "Βάλε τις κάμερες σε χωριστό VLAN/SSID ή πίσω από VPN — όχι στο ίδιο δίκτυο με τον υπολογιστή σου.",
    "upnp": "Κλείσε το UPnP στο router και σβήσε κάθε port-forward προς την κάμερα (μην τη βγάζεις στο Internet).",
    "pass": "Άλλαξε τον προεπιλεγμένο κωδικό (admin/12345) — έλεγξέ τον χειροκίνητα, δεν τον δοκιμάζει το εργαλείο.",
    "fw": "Ενημέρωσε το firmware της κάμερας/καταγραφικού στην τελευταία έκδοση.",
    "p2p": "Απενεργοποίησε το P2P cloud (XMeye, iCloud-cam κ.λπ.) — στέλνει το βίντεο σε άγνωστους διακομιστές.",
    "https": "Χρησιμοποίησε HTTPS με σύγχρονο TLS (1.2+) αντί για απλό HTTP στο web UI.",
}


# ── έλεγχος ιδιωτικού εύρους (ΣΚΛΗΡΟΣ ΚΑΝΟΝΑΣ) ──
# Μόνο πραγματικά τοπικά δίκτυα (RFC1918 + ULA). Οι χώροι τεκμηρίωσης (π.χ. 203.0.113.0/24) και
# κάθε δημόσια/global IP ΑΠΟΡΡΙΠΤΟΝΤΑΙ — δεν σαρώνουμε ποτέ δίκτυα που δεν είναι του σπιτιού σου.
_LAN_NETS = [ipaddress.ip_network(n) for n in
             ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def is_private(ip):
    """True μόνο για ιδιωτικές LAN διευθύνσεις (RFC1918 / ULA)· όχι loopback/link-local/multicast/τεκμηρίωση."""
    try:
        a = ipaddress.ip_address(str(ip).strip().strip("[]"))
    except ValueError:
        return False
    if a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified:
        return False
    return any(a in n for n in _LAN_NETS)


# ── αιτήματα (καμία αποστολή διαπιστευτηρίων — απόδειξη στο no-login invariant) ──
def http_request(ip, method="GET"):
    """Το ακριβές αίτημα που στέλνουμε σε web UI. Δεν περιέχει ΠΟΤΕ Authorization/κωδικό."""
    return (f"{method} / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetWatch-CamCheck\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n").encode("latin-1")


def rtsp_request(ip, port=554):
    """OPTIONS σε RTSP — απλώς ρωτάμε «τι υποστηρίζεις». Χωρίς Authorization/κωδικό."""
    return (f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n"
            "User-Agent: NetWatch-CamCheck\r\n\r\n").encode("latin-1")


def _cat(port):
    if port in HTTPS_PORTS:
        return "https"
    if port in HTTP_PORTS:
        return "http"
    if port in RTSP_PORTS:
        return "rtsp"
    return "binary"


# ── parsing (καθαρές συναρτήσεις, για tests) ──
_STATUS = re.compile(r"^\s*(?:HTTP|RTSP)/\d\.\d\s+(\d{3})", re.I)


def _header(raw, name):
    m = re.search(rf"^{name}\s*:\s*([^\r\n]{{0,200}})", raw, re.I | re.M)
    return m.group(1).strip() if m else None


def parse_http(raw):
    """HTTP απάντηση → {status, server, www_auth, realm, title, location, login_redirect, auth}."""
    raw = raw if isinstance(raw, str) else (raw or b"").decode("latin-1", "replace")
    m = _STATUS.search(raw)
    status = int(m.group(1)) if m else None
    server = _header(raw, "Server")
    wa = _header(raw, "WWW-Authenticate")
    loc = _header(raw, "Location")
    realm = None
    if wa:
        rm = re.search(r'realm\s*=\s*"?([^"\r\n]{0,60})', wa, re.I)
        realm = rm.group(1).strip() if rm else None
    tm = re.search(r"<title>(.*?)</title>", raw, re.I | re.S)
    title = re.sub(r"\s+", " ", tm.group(1)).strip()[:80] if tm else None
    login_redirect = bool(status and 300 <= status < 400 and loc and re.search(r"login|signin|auth", loc, re.I))
    auth = bool(status == 401 or wa)
    return {"status": status, "server": server, "www_auth": wa, "realm": realm,
            "title": title, "location": loc, "login_redirect": login_redirect, "auth": auth}


def parse_rtsp(raw):
    """RTSP OPTIONS απάντηση → {status, server, public, auth}."""
    raw = raw if isinstance(raw, str) else (raw or b"").decode("latin-1", "replace")
    m = _STATUS.search(raw)
    status = int(m.group(1)) if m else None
    return {"status": status, "server": _header(raw, "Server"), "public": _header(raw, "Public"),
            "www_auth": _header(raw, "WWW-Authenticate"),
            "auth": bool(status == 401 or _header(raw, "WWW-Authenticate"))}


# ── πραγματικό «grab» (μόνο παρατήρηση, μικρά timeouts, ≤ ~4 KB HTTP / ~1 KB αλλιώς) ──
def _grab(ip, port, cat, timeout):
    """Επιστρέφει (raw_bytes|None, tls_version|None). None = κλειστή θύρα. Κανένα credential δεν στέλνεται."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None, None
    tls_ver = None
    try:
        sock.settimeout(timeout)
        s = sock
        if cat == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                s = ctx.wrap_socket(sock, server_hostname=None)
                tls_ver = s.version()
            except (ssl.SSLError, OSError):
                return b"", None
        if cat in ("http", "https"):
            s.sendall(http_request(ip, "GET"))
            data = _recv(s, 4096)
            if not data:  # HEAD fallback
                try:
                    s.sendall(http_request(ip, "HEAD"))
                    data = _recv(s, 4096)
                except OSError:
                    data = b""
        elif cat == "rtsp":
            s.sendall(rtsp_request(ip, port))
            data = _recv(s, 1024)
        else:  # binary/ιδιόκτητο: μόνο μία γραμμή banner, ≤ 1 KB
            data = _recv(s, 1024)
        return data, tls_ver
    except OSError:
        return b"", tls_ver
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _recv(s, limit):
    buf = b""
    try:
        while len(buf) < limit:
            chunk = s.recv(min(1024, limit - len(buf)))
            if not chunk:
                break
            buf += chunk
    except OSError:
        pass
    return buf[:limit]


def _finding(port, raw, tls_ver):
    """Χτίζει το εύρημα μιας θύρας από το raw banner + TLS έκδοση."""
    cat = _cat(port)
    label = CAMERA_PORTS.get(port, f"θύρα {port}")
    f = {"port": port, "label": label, "cat": cat, "open": True, "banner": "", "server": None,
         "auth": False, "status": None, "title": None, "tls": tls_ver, "note": None, "realm": None,
         "location": None}
    if raw is None:
        f["open"] = False
        return f
    text = raw if isinstance(raw, str) else raw.decode("latin-1", "replace")
    f["banner"] = re.sub(r"\s+", " ", text.strip())[:160]
    if cat in ("http", "https"):
        p = parse_http(text)
        f.update({"status": p["status"], "server": p["server"], "auth": p["auth"],
                  "title": p["title"], "realm": p["realm"], "location": p["location"]})
        if p["login_redirect"]:
            f["auth"] = True
    elif cat == "rtsp":
        p = parse_rtsp(text)
        f.update({"status": p["status"], "server": p["server"], "auth": p["auth"]})
    # σημείωση «CVE-ish»
    for rx, why in RISKY_BANNERS:
        if re.search(rx, text, re.I):
            f["note"] = why
            break
    return f


def probe_host(ip, ports=None, timeout=2, _conn=None):
    """Παρατηρεί τις θύρες καμερών σε ΜΙΑ ιδιωτική IP. Δημόσιες IP → δεν αγγίζονται ποτέ (skipped).

    _conn(ip, port) -> raw bytes | None  (κλειστή) : εισάγεται στα tests αντί για πραγματικό socket.
    Επιστρέφει {ip, skipped, reason, ports: {port: finding}}.
    """
    ports = ports or CAMERA_PORTS
    if not is_private(ip):  # ΣΚΛΗΡΟΣ ΚΑΝΟΝΑΣ: ποτέ probe σε δημόσια IP
        return {"ip": ip, "skipped": True, "reason": "public", "ports": {}}
    out = {}
    for port in ports:
        cat = _cat(port)
        if _conn is not None:
            raw = _conn(ip, port)
            tls = None
        else:
            raw, tls = _grab(ip, port, cat, timeout)
        if raw is None:
            continue  # κλειστή θύρα: δεν την εμφανίζουμε
        out[port] = _finding(port, raw, tls)
    return {"ip": ip, "skipped": False, "reason": None, "ports": out}


# ── αναγνώριση κατασκευαστή ──
def detect_vendor(findings):
    """findings: {port: finding} → όνομα κατασκευαστή ή None."""
    blob = " ".join(filter(None, (" ".join(filter(None, (f.get("server"), f.get("realm"), f.get("banner"))))
                                   for f in findings.values())))
    for _, rx, vendor in VENDOR_HINTS:
        if re.search(rx, blob, re.I):
            return vendor
    for port, vendor in PORT_VENDOR.items():
        if port in findings:
            return vendor
    return None


# ── ετυμηγορία κινδύνου ──
def verdict(findings):
    """findings: {port: finding} → (verdict, issues, fixes, no_auth_open).

    RED: web UI κάμερας απαντά 200 ΧΩΡΙΣ auth (ανοιχτή ροή/admin) ή RTSP OPTIONS 200 χωρίς auth.
    ORANGE: προσβάσιμη αλλά πίσω από auth / απλό HTTP / παλιό TLS / «CVE-ish» banner.
    GREEN: μόνο HTTPS προστατευμένο με auth.
    """
    open_f = [f for f in findings.values() if f.get("open")]
    issues, fixes = [], []
    red = orange = no_auth_open = False
    for f in open_f:
        cat, st, auth = f["cat"], f.get("status"), f.get("auth")
        if cat in ("http", "https") and st == 200 and not auth:
            red = no_auth_open = True
            issues.append(f"Το web UI στη θύρα {f['port']} απαντά 200 OK ΧΩΡΙΣ να ζητά κωδικό — "
                          "οποιοσδήποτε στο δίκτυο βλέπει τη ροή/τις ρυθμίσεις.")
        elif cat == "rtsp" and st == 200 and not auth:
            red = no_auth_open = True
            issues.append(f"Η ροή RTSP (θύρα {f['port']}) απαντά χωρίς έλεγχο ταυτότητας — "
                          "ανοιχτή ροή βίντεο προς όλο το δίκτυο.")
        else:
            if cat == "http":
                loc = (f.get("location") or "").lower()
                redirect_https = bool(st and 300 <= st < 400 and loc.startswith("https"))
                if not redirect_https:  # ανακατεύθυνση σε HTTPS είναι καλό, δεν το χρεώνουμε
                    orange = True
                    issues.append(f"Web UI σε απλό HTTP (θύρα {f['port']}) — αν κάνεις login, ο κωδικός ταξιδεύει ανοιχτός.")
            if f.get("tls") in OLD_TLS:
                orange = True
                issues.append(f"Παλιό TLS ({f['tls']}) στη θύρα {f['port']} — σπασμένη κρυπτογράφηση.")
            if cat in ("rtsp", "https") and auth:
                issues.append(f"Θύρα {f['port']} ({f['label']}) προσβάσιμη αλλά ζητά κωδικό — καλό.")
        if f.get("note"):
            orange = True
            issues.append(f"Θύρα {f['port']}: {f['note']}")
        if f["port"] in (34567, 9000, 37777):
            orange = True
            issues.append(f"Θύρα {f['port']} ({f['label']}): ιδιόκτητο DVR με P2P cloud (XMeye/iCloud-cam) — "
                          "συχνά στέλνει βίντεο έξω χωρίς να το ξέρεις.")
    if red:
        v = "red"
        fixes = [FIXES["pass"], FIXES["vlan"], FIXES["upnp"], FIXES["fw"], FIXES["p2p"]]
    elif orange:
        v = "orange"
        fixes = [FIXES["https"], FIXES["vlan"], FIXES["pass"], FIXES["fw"], FIXES["p2p"], FIXES["upnp"]]
    else:
        v = "green"
        fixes = [FIXES["fw"], FIXES["pass"]]
    return v, issues, fixes, no_auth_open


# ── σενάριο demo (ένα εύλογο σπίτι) ──
SIM_BANNERS = {
    # 192.168.1.64 — Hikvision πίσω από HTTPS + auth → ΠΡΑΣΙΝΟ
    ("192.168.1.64", 443): b"HTTP/1.1 401 Unauthorized\r\nServer: webserver\r\n"
                           b'WWW-Authenticate: Digest realm="Hikvision", qop="auth"\r\n'
                           b"Content-Length: 0\r\n\r\n",
    ("192.168.1.64", 80): b"HTTP/1.1 301 Moved Permanently\r\nServer: webserver\r\n"
                          b"Location: https://192.168.1.64/\r\nContent-Length: 0\r\n\r\n",
    # 192.168.1.108 — Dahua/XMeye DVR στο 34567 + απλό HTTP :80 χωρίς auth (ανοιχτή ροή) → ΚΟΚΚΙΝΟ
    ("192.168.1.108", 34567): b"",  # ανοιχτή ιδιόκτητη θύρα, κενό banner
    ("192.168.1.108", 80): b"HTTP/1.1 200 OK\r\nServer: uc-httpd 1.0.0\r\nContent-Type: text/html\r\n\r\n"
                           b"<html><head><title>WEB SERVICE</title></head><body>NetSurveillance</body></html>",
    # 192.168.1.70 — γενική ONVIF: RTSP 554 ζητά auth, αλλά HTTP admin σε απλό HTTP (με auth) → ΠΟΡΤΟΚΑΛΙ
    ("192.168.1.70", 554): b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: Rtsp Server\r\n"
                           b'WWW-Authenticate: Digest realm="ONVIF", nonce="abc"\r\n\r\n',
    ("192.168.1.70", 80): b"HTTP/1.1 401 Unauthorized\r\nServer: Boa/0.94.14rc21\r\n"
                          b'WWW-Authenticate: Basic realm="ONVIF Camera"\r\nContent-Length: 0\r\n\r\n',
}
SIM_NAMES = {"192.168.1.64": "Κάμερα εισόδου", "192.168.1.108": "DVR σαλονιού", "192.168.1.70": "Κάμερα αυλής"}
SIM_PUBLIC_SKIPPED = "203.0.113.45"  # δείχνει ότι ο φραγμός δημόσιων IP δουλεύει


def _sim_conn(ip, port):
    return SIM_BANNERS.get((ip, port))  # None → κλειστή


class CamExposure:
    """Αμυντικός έλεγχος έκθεσης καμερών για το δικό σου LAN. (state, cfg, sim=False)."""

    def __init__(self, state=None, cfg=None, sim=False):
        cfg = cfg or {}
        self.state, self.sim = state, sim
        self.enabled = bool(cfg.get("enabled", sim))  # στο live: off απ' προεπιλογή (χειροκίνητο scan)
        self.subnet_cfg = cfg.get("subnet")
        self.extra_ports = [int(p) for p in (cfg.get("extra_ports") or []) if str(p).isdigit()]
        self.interval_h = float(cfg.get("interval_h") or 0)  # 0 = μόνο χειροκίνητα
        self.hint_only = bool(cfg.get("hint_only", True))
        self.ports = dict(CAMERA_PORTS)
        for p in self.extra_ports:
            self.ports.setdefault(p, f"θύρα {p} (extra)")
        self.lock = threading.Lock()
        self.scanning = False
        self.last_scan = 0
        self.error = None
        self._results = {}        # ip → {vendor, verdict, ports, issues, fixes, no_auth_open}
        self._skipped = []        # δημόσιες IP που αγνοήθηκαν
        self._subnet = None

    # ── υποκείμενα δεδομένα ──
    def _hosts(self):
        """{ip: host} από το NetWatch (αν υπάρχει state)."""
        st = self.state
        if st is None or not hasattr(st, "hosts"):
            return {}
        try:
            with getattr(st, "lock", _NullLock()):
                return dict(st.hosts)
        except Exception:
            return dict(getattr(st, "hosts", {}))

    def _auto_subnet(self):
        """Το /24 των τοπικών ιδιωτικών IP (το πιο συχνό)."""
        counts = {}
        for ip, h in self._hosts().items():
            if h.get("kind") == "local" and is_private(ip):
                try:
                    net = ipaddress.ip_network(f"{ip}/24", strict=False)
                except ValueError:
                    continue
                counts[str(net)] = counts.get(str(net), 0) + 1
        if counts:
            return max(counts, key=counts.get)
        return None

    def known_cameras(self):
        """Κάμερες που ήδη ξέρει το NetWatch — ΜΟΝΟ με ισχυρό σημάδι κάμερας, για να μη γεμίζει ο κατάλογος
        με κάθε συσκευή: είτε κατασκευαστής αμιγώς καμερών (όχι γενικοί σαν TP-Link/Ubiquiti που φτιάχνουν τα πάντα),
        είτε θύρα ειδική για κάμερα (RTSP 554/8554, Dahua 37777, XMeye 34567, ONVIF 3702)."""
        out = {}
        # αμιγώς κατασκευαστές καμερών· τα Tapo/UniFi Protect/«cam» πιάνονται χωριστά από το όνομα
        CAM_VENDOR = re.compile(r"hikvision|dahua|reolink|axis comm|foscam|amcrest|lorex|swann|vivotek|hanwha|"
                                r"\bwyze\b|\beufy\b|\barlo\b|\bannke\b|uniview|\bdahua\b", re.I)
        CAM_NAME = re.compile(r"\b(ipcam|ipcamera|camera|nvr|dvr|doorbell|tapo.?c\d|unifi.?protect|reolink|hikvision)\b", re.I)
        CAM_PORTS = {554, 8554, 37777, 34567, 3702}
        for ip, h in self._hosts().items():
            if h.get("kind") != "local" or not is_private(ip) or h.get("gw") or h.get("me"):
                continue
            names = sorted(h.get("names") or [])
            if h.get("rdns"):
                names = names + [h["rdns"]]
            text = " ".join(names).lower()
            ports = set(h.get("ports") or ())
            vendor = None
            v = ""
            try:
                import devtype
                _t, _i, _l, v = devtype.classify(h.get("mac"), names, list(ports), gw=h.get("gw"), me=h.get("me"))
            except Exception:
                v = ""
            strong = (v and CAM_VENDOR.search(v)) or CAM_NAME.search(text) or (ports & CAM_PORTS)
            if strong:
                if v and CAM_VENDOR.search(v):
                    vendor = v
                out[ip] = {"ip": ip, "name": names[0] if names else None, "vendor": vendor}
        return out

    def _targets(self):
        """Λίστα IP προς έλεγχο: όλοι οι ιδιωτικοί hosts + οι host του /24 (έως 254)."""
        subnet = self.subnet_cfg or self._auto_subnet()
        self._subnet = subnet
        targets, seen = [], set()
        for ip in self._hosts():
            if is_private(ip) and ip not in seen:
                seen.add(ip)
                targets.append(ip)
        if subnet:
            try:
                net = ipaddress.ip_network(subnet, strict=False)
                for host in net.hosts():
                    ip = str(host)
                    if ip not in seen and is_private(ip):
                        seen.add(ip)
                        targets.append(ip)
                    if len(targets) >= 254:
                        break
            except ValueError:
                self.error = f"Μη έγκυρο subnet: {subnet}"
        return targets[:254]

    # ── σάρωση ──
    def scan(self, now=None):
        """Μία σάρωση. Παρατηρεί μόνο· αποθηκεύει αποτελέσματα. Επιστρέφει τον αριθμό καμερών που βρέθηκαν."""
        now = now or time.time()
        with self.lock:
            if self.scanning:
                return 0
            self.scanning = True
        try:
            results, skipped = {}, []
            if self.sim:
                targets = list(SIM_NAMES) + [SIM_PUBLIC_SKIPPED]
                conn = _sim_conn
            else:
                targets = self._targets()
                conn = None
            # έλεγχος ιδιωτικού εύρους ΠΡΙΝ από κάθε probe
            priv = [ip for ip in targets if is_private(ip)]
            skipped = [ip for ip in targets if not is_private(ip)]

            def work(ip):
                return probe_host(ip, self.ports, timeout=2, _conn=conn)

            with ThreadPoolExecutor(max_workers=16) as ex:
                for res in ex.map(work, priv):
                    if res.get("skipped"):
                        skipped.append(res["ip"])
                        continue
                    findings = res["ports"]
                    if not findings:
                        continue  # καμία θύρα κάμερας ανοιχτή
                    v, issues, fixes, no_auth = verdict(findings)
                    results[res["ip"]] = {"vendor": detect_vendor(findings), "verdict": v, "ports": findings,
                                          "issues": issues, "fixes": fixes, "no_auth_open": no_auth}
            with self.lock:
                self._results = results
                self._skipped = sorted(set(skipped))
                self.last_scan = now
            self._maybe_alert(results, now)
            return len(results)
        except Exception as e:  # pragma: no cover
            self.error = str(e)[:160]
            return 0
        finally:
            with self.lock:
                self.scanning = False

    def _maybe_alert(self, results, now):
        """Live: κάθε εκτεθειμένη (RED) κάμερα σε ιδιωτική IP → αμυντική ειδοποίηση στον ιδιοκτήτη."""
        if self.sim or self.state is None:
            return
        for ip, r in results.items():
            if r["verdict"] != "red" or not is_private(ip):
                continue
            sev = "high" if r["no_auth_open"] else "med"
            detail = ("Η κάμερα/DVR στο δίκτυό σου φαίνεται εκτεθειμένη: "
                      + (r["issues"][0] if r["issues"] else "ανοιχτή χωρίς έλεγχο ταυτότητας.")
                      + " Κλείσ' την πίσω από VLAN/VPN και άλλαξε κωδικό.")
            self.state.alert("Κάμερα εκτεθειμένη στο δίκτυο", sev, ip,
                             r.get("vendor") or "κάμερα", detail, now,
                             key=("cam-exposed", ip), cooldown=6 * 3600, mark=False)

    # ── κατάσταση ──
    def _camera_row(self, ip, data, name, vendor):
        ports = [{"port": f["port"], "label": f["label"], "open": f["open"], "banner": f["banner"],
                  "server": f["server"], "auth": f["auth"], "note": f["note"]}
                 for f in sorted(data["ports"].values(), key=lambda x: x["port"])] if data else []
        return {"ip": ip, "name": name, "vendor": (data and data["vendor"]) or vendor,
                "verdict": data["verdict"] if data else "unknown",
                "ports": ports, "issues": data["issues"] if data else [],
                "fixes": data["fixes"] if data else ["Πάτησε «Σάρωση» για να ελεγχθεί η έκθεση αυτής της κάμερας."]}

    def status(self, now=None):
        now = now or time.time()
        with self.lock:
            results = dict(self._results)
            skipped = list(self._skipped)
            scanning, last_scan, subnet = self.scanning, self.last_scan, (self._subnet or self.subnet_cfg)
        known = self.known_cameras()
        if self.sim and not skipped:
            skipped = [SIM_PUBLIC_SKIPPED]
        if self.sim and not subnet:
            subnet = "192.168.1.0/24"
        names = dict(SIM_NAMES) if self.sim else {}
        cameras = []
        for ip, data in sorted(results.items()):
            nm = names.get(ip) or (known.get(ip) or {}).get("name")
            vd = (known.get(ip) or {}).get("vendor")
            cameras.append(self._camera_row(ip, data, nm, vd))
        # γνωστές κάμερες που δεν σαρώθηκαν ακόμη
        for ip, info in sorted(known.items()):
            if ip not in results:
                cameras.append(self._camera_row(ip, None, info.get("name"), info.get("vendor")))
        summary = {"red": sum(1 for c in cameras if c["verdict"] == "red"),
                   "orange": sum(1 for c in cameras if c["verdict"] == "orange"),
                   "green": sum(1 for c in cameras if c["verdict"] == "green")}
        return {"enabled": self.enabled, "demo": self.sim, "error": self.error,
                "scanning": scanning, "last_scan": last_scan, "subnet": subnet,
                "cameras": cameras, "skipped_public": skipped, "summary": summary}

    def run_forever(self):
        """Περιοδική σάρωση μόνο αν interval_h > 0 και enabled· αλλιώς «κοιμάται» (χειροκίνητο scan)."""
        if self.sim:
            try:
                self.scan()
            except Exception:
                pass
            return
        while True:
            try:
                if self.enabled and self.interval_h > 0:
                    self.scan()
            except Exception:
                pass
            time.sleep(max(300.0, self.interval_h * 3600) if self.interval_h > 0 else 3600)


class _NullLock:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False
