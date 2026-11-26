"""📷 Βοηθός παράδοσης καμερών — «γιατί η κάμερα 7 είναι offline;» πριν φύγεις από τον πελάτη.

Τα ίδια πράγματα φέρνουν τον εγκαταστάτη πίσω ξανά και ξανά: δύο κάμερες με την ίδια IP (συχνά την εργοστασιακή),
κάμερα σε λάθος subnet, κάμερα που δεν ενεργοποιήθηκε ποτέ, λάθος ώρα (άχρηστες καταγραφές), απώλειες στο καλώδιο/PoE,
ροή ανοιχτή χωρίς κωδικό. Εδώ ελέγχονται όλα με ένα κουμπί, ανά κάμερα, και βγαίνει φύλλο παράδοσης.

Τι στέλνουμε (όλα μόνο ανάγνωση, μόνο σε ιδιωτικές διευθύνσεις του τοπικού δικτύου):
  • ping (απώλεια/καθυστέρηση) και ARP για την ίδια IP — δύο διαφορετικές MAC = σύγκρουση
  • WS-Discovery (ONVIF, UDP 3702) και Hikvision SADP (UDP 37020): «ποιες κάμερες υπάρχουν;» — τις βρίσκει και όταν
    είναι σε ΛΑΘΟΣ subnet, γιατί απαντούν σε multicast
  • ONVIF GetSystemDateAndTime (το πρότυπο το επιτρέπει χωρίς κωδικό): η ώρα της κάμερας και αν παίρνει ώρα από NTP
  • RTSP OPTIONS / DESCRIBE ΧΩΡΙΣ διαπιστευτήρια: 401 = ζητά κωδικό (σωστό), 200 = η ροή είναι ανοιχτή

ΣΚΛΗΡΟΙ ΚΑΝΟΝΕΣ (ίδιοι με το camexposure.py): ο ΕΛΕΓΧΟΣ δεν κάνει ποτέ login, δεν δοκιμάζει ποτέ κωδικούς (ούτε τους
εργοστασιακούς), δεν γράφει καμία ρύθμιση και δεν κατεβάζει βίντεο — διαβάζει λίγα KB κεφαλίδων και κλείνει.

👁 «Δες τι βλέπει»: ξεχωριστή ενέργεια, μόνο όταν ο τεχνικός πληκτρολογήσει ο ίδιος όνομα και κωδικό της κάμερας.
  • ΜΙΑ προσπάθεια σύνδεσης ανά πάτημα (οι κάμερες κλειδώνουν μετά από λίγες αποτυχίες) — ποτέ λίστες, ποτέ επανάληψη.
  • Ο κωδικός δεν αποθηκεύεται και δεν γράφεται σε log· ζει μόνο όσο διαρκεί το αίτημα.
  • Στέλνεται μόνο με Digest ή μέσα από HTTPS. Αν η κάμερα δέχεται μόνο Basic σε απλό HTTP (ο κωδικός θα ταξίδευε
    ανοιχτά), αρνούμαστε εκτός αν ο χρήστης το επιτρέψει ρητά.
  • Μία φωτογραφία JPEG (έως 3 MB), όχι βίντεο· μόνο από ιδιωτική IP που είναι ήδη στη λίστα καμερών.
"""
import base64
import hashlib
import secrets
import calendar
import ipaddress
import re
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import sites
from sites import L, clean, esc

MAX_CAMS = 128
MAX_REPLY = 16 * 1024
TIMEOUT = 2.0
ONVIF_PORTS = (80, 8000, 8899, 2020, 8080)
RTSP_PORTS = (554, 8554)
CLOCK_WARN, CLOCK_FAIL = 30, 300          # δευτερόλεπτα απόκλισης ώρας
LOSS_WARN, LOSS_FAIL = 1.0, 10.0          # % απώλεια ping
# εργοστασιακές IP: κάθε καινούργια κάμερα της ίδιας μάρκας βγαίνει με αυτήν → σίγουρη σύγκρουση στη 2η
FACTORY_IPS = {"192.168.1.64": "Hikvision", "192.168.1.108": "Dahua", "192.168.0.90": "Axis", "192.168.1.168": "Uniview / XMeye",
               "192.168.1.10": "XMeye / γενικές", "192.168.0.123": "Reolink (παλιές)", "192.168.1.88": "Foscam / γενικές",
               "192.168.226.201": "TVT", "192.168.1.13": "Uniview"}
MAX_JPEG = 3 * 1024 * 1024
# γνωστές διευθύνσεις στιγμιότυπου (χωρίς κωδικό μέσα στο URL — όσες τον θέλουν εκεί δεν υποστηρίζονται)
SNAP_PATHS = [("hikvision", "/ISAPI/Streaming/channels/101/picture"), ("dahua", "/cgi-bin/snapshot.cgi?channel=1"),
              ("axis", "/axis-cgi/jpg/image.cgi"), ("hikvision", "/onvif-http/snapshot?Profile_1"), ("", "/snap.jpg"), ("", "/tmpfs/auto.jpg")]
SNAP_PATH_RX = re.compile(r"^/[A-Za-z0-9_./?=&%:-]{0,160}$")
WSD_ADDR, SADP_ADDR = ("239.255.255.250", 3702), ("239.255.255.250", 37020)


def is_private(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return a.version == 4 and a.is_private and not (a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)


def norm_mac(m):
    h = re.sub(r"[^0-9a-fA-F]", "", str(m or ""))
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)).lower() if len(h) == 12 else ""


# ───────────────────────── μηνύματα πρωτοκόλλων (καθαρές συναρτήσεις) ─────────────────────────
def wsd_probe(mid=None):
    """WS-Discovery Probe για συσκευές ONVIF (NetworkVideoTransmitter)."""
    mid = mid or str(uuid.uuid4())
    return ('<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
            'xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><w:MessageID>uuid:' + mid + '</w:MessageID>'
            '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
            '<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>'
            '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>').encode()


def _tag(xml, name):
    """Περιεχόμενο του πρώτου <…:name>…</…:name> (χωρίς XML parser: τίποτα από DOCTYPE/ENTITY δεν ερμηνεύεται)."""
    m = re.search(r"<(?:[A-Za-z0-9_]+:)?" + re.escape(name) + r"(?:\s[^>]*)?>([^<]{0,2000})</(?:[A-Za-z0-9_]+:)?" + re.escape(name) + r">", xml)
    return m.group(1).strip() if m else ""


def parse_wsd(data, src_ip):
    """ProbeMatch → {ip, xaddrs:[(ip, port, path)], name, hardware} ή None."""
    try:
        xml = bytes(data[:MAX_REPLY]).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    if "ProbeMatch" not in xml:
        return None
    xa = []
    for u in _tag(xml, "XAddrs").split()[:6]:
        m = re.match(r"^http://(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(/[A-Za-z0-9_./-]{0,80})?$", u)
        if m and 0 < int(m.group(2) or 80) < 65536:
            xa.append((m.group(1), int(m.group(2) or 80), m.group(3) or "/onvif/device_service"))
    scopes = _tag(xml, "Scopes")

    def scope(key):
        m = re.search(r"onvif://www\.onvif\.org/" + key + r"/(\S{1,80})", scopes)
        return clean(re.sub(r"%([0-9A-Fa-f]{2})", lambda x: chr(int(x.group(1), 16)), m.group(1)), 60) if m else ""
    ip = xa[0][0] if xa else str(src_ip)
    return {"ip": ip, "src": str(src_ip), "xaddrs": xa, "name": scope("name"), "hardware": scope("hardware")}


def sadp_probe(mid=None):
    """Hikvision SADP: ερώτημα «ποιος είναι εκεί;» (inquiry) — δεν αλλάζει τίποτα."""
    return ('<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>' + (mid or str(uuid.uuid4()).upper()) + '</Uuid><Types>inquiry</Types></Probe>').encode()


def parse_sadp(data):
    """ProbeMatch του SADP → {ip, mac, model, sn, fw, activated, dhcp, mask, gw} ή None."""
    try:
        xml = bytes(data[:MAX_REPLY]).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    if "<ProbeMatch" not in xml or not _tag(xml, "IPv4Address"):
        return None
    b = lambda v: {"true": True, "false": False}.get(v.strip().lower())  # noqa: E731
    return {"ip": _tag(xml, "IPv4Address"), "mac": norm_mac(_tag(xml, "MAC")), "model": clean(_tag(xml, "DeviceDescription"), 40),
            "sn": clean(_tag(xml, "DeviceSN"), 60), "fw": clean(_tag(xml, "SoftwareVersion"), 40), "activated": b(_tag(xml, "Activated")),
            "dhcp": b(_tag(xml, "DHCP")), "mask": _tag(xml, "IPv4SubnetMask"), "gw": _tag(xml, "IPv4Gateway")}


def onvif_time_request(ip, port, path="/onvif/device_service"):
    body = ('<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
            '<GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>')
    return (f"POST {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: NetWatch-CamCheck\r\n"
            f"Content-Type: application/soap+xml; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}").encode()


def parse_onvif_time(raw):
    """Απάντηση GetSystemDateAndTime → {"utc": epoch, "ntp": True/False/None} ή None."""
    try:
        txt = bytes(raw[:MAX_REPLY]).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    m = re.search(r"UTCDateTime\b.*?</(?:[A-Za-z0-9_]+:)?UTCDateTime>", txt, re.S)
    if not m:
        return None
    seg = m.group(0)
    try:
        v = [int(_tag(seg, k)) for k in ("Year", "Month", "Day", "Hour", "Minute", "Second")]
        utc = calendar.timegm((v[0], v[1], v[2], v[3], v[4], v[5], 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    if not (2000 <= v[0] <= 2100 and 1 <= v[1] <= 12 and 1 <= v[2] <= 31):
        return None
    kind = _tag(txt, "DateTimeType").lower()
    return {"utc": utc, "ntp": True if kind == "ntp" else False if kind == "manual" else None}


def rtsp_request(ip, port, method="OPTIONS", cseq=1):
    """Χωρίς Authorization — ποτέ δεν στέλνουμε κωδικό."""
    extra = "Accept: application/sdp\r\n" if method == "DESCRIBE" else ""
    return (f"{method} rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: {cseq}\r\nUser-Agent: NetWatch-CamCheck\r\n{extra}\r\n").encode("latin-1")


def parse_rtsp(raw):
    """→ {"code": int, "auth": bool, "codec": ""} ή None."""
    try:
        txt = bytes(raw[:MAX_REPLY]).decode("latin-1")
    except Exception:  # noqa: BLE001
        return None
    m = re.match(r"RTSP/1\.\d (\d{3})", txt)
    if not m:
        return None
    c = re.search(r"a=rtpmap:\d+ (H264|H265|HEVC|JPEG|MP4V-ES)", txt, re.I)
    return {"code": int(m.group(1)), "auth": bool(re.search(r"^WWW-Authenticate:", txt, re.I | re.M)),
            "codec": (c.group(1).upper().replace("HEVC", "H265") if c else "")}


def parse_challenge(header):
    """WWW-Authenticate → {"digest": {realm, nonce, qop, opaque, algorithm} ή None, "basic": bool}."""
    h = header if isinstance(header, str) else ", ".join(header or [])
    out = {"digest": None, "basic": bool(re.search(r"(^|,\s*)Basic\b", h, re.I))}
    m = re.search(r"Digest\s+(.*)", h, re.I | re.S)
    if m:
        kv = {k.lower(): (a if a else b) for k, a, b in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]*))', m.group(1)[:2000])}
        if kv.get("nonce"):
            out["digest"] = {k: kv.get(k, "") for k in ("realm", "nonce", "qop", "opaque", "algorithm")}
    return out


def digest_header(user, password, method, uri, ch, cnonce=None, nc=1):
    """Κεφαλίδα Authorization για HTTP Digest (RFC 2617/7616: MD5 ή SHA-256, qop=auth). None αν ο αλγόριθμος δεν υποστηρίζεται."""
    alg = (ch.get("algorithm") or "MD5").upper()
    if alg not in ("MD5", "SHA-256"):
        return None
    H = lambda x: (hashlib.md5 if alg == "MD5" else hashlib.sha256)(x.encode("utf-8")).hexdigest()  # noqa: E731
    ha1, ha2 = H(f"{user}:{ch['realm']}:{password}"), H(f"{method}:{uri}")
    q = lambda v: v.replace("\\", "").replace('"', "")  # noqa: E731
    parts = [f'username="{q(user)}"', f'realm="{q(ch["realm"])}"', f'nonce="{q(ch["nonce"])}"', f'uri="{uri}"']
    if "auth" in [x.strip() for x in (ch.get("qop") or "").split(",")]:
        cnonce = cnonce or secrets.token_hex(8)
        ncs = f"{nc:08x}"
        resp = H(f"{ha1}:{ch['nonce']}:{ncs}:{cnonce}:auth:{ha2}")
        parts += ["qop=auth", f"nc={ncs}", f'cnonce="{cnonce}"']
    else:
        resp = H(f"{ha1}:{ch['nonce']}:{ha2}")
    parts.append(f'response="{resp}"')
    if ch.get("opaque"):
        parts.append(f'opaque="{q(ch["opaque"])}"')
    if alg != "MD5":
        parts.append(f"algorithm={alg}")
    return "Digest " + ", ".join(parts)


def is_jpeg(b):
    return isinstance(b, (bytes, bytearray)) and len(b) > 100 and b[:3] == b"\xff\xd8\xff"


def same_subnet(ip, me_ip, prefix):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(f"{me_ip}/{prefix}", strict=False)
    except ValueError:
        return True


# ───────────────────────── πραγματικό δίκτυο (τα tests δίνουν ψεύτικο) ─────────────────────────
class RealNet:
    def local(self):
        import changecheck
        i = changecheck.local_info()
        return {"ip": i.get("ip"), "prefix": i.get("prefix") or 24, "gateway": i.get("gateway")}

    def ping(self, ip):
        import changecheck
        # 1 ping/δευτ.: πολλές κάμερες/NVR περιορίζουν το ICMP (rate limit) και στα γρήγορα ping δείχνουν ψεύτικη απώλεια 40–70%
        r = changecheck.ping(ip, count=5, interval=1.0, timeout=1.0)
        return {"ok": bool(r.get("ok")), "loss": r.get("loss_pct"), "ms": r.get("avg"), "err": r.get("err")}

    def arp_macs(self, ip):
        """Όλες οι MAC που απαντούν για αυτή την IP (None αν δεν επιτρέπεται — θέλει root)."""
        try:
            from core import arp_request  # noqa: PLC0415
            ans = arp_request(ip, timeout=1.5, retry=1, multi=True)
            return sorted({norm_mac(r.hwsrc) for _, r in ans if norm_mac(r.hwsrc)})
        except Exception:  # noqa: BLE001  (χωρίς δικαιώματα / χωρίς scapy)
            return None

    def _tcp(self, ip, port, payload):
        try:
            with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
                s.settimeout(TIMEOUT)
                s.sendall(payload)
                buf = b""
                while len(buf) < MAX_REPLY:
                    try:
                        d = s.recv(4096)
                    except socket.timeout:
                        break
                    if not d:
                        break
                    buf += d
                    if b"\r\n\r\n" in buf and payload[:4] != b"POST" and b"Content-Length" not in buf:
                        break
                return buf
        except OSError:
            return None

    def onvif_time(self, ip, port, path):
        return self._tcp(ip, port, onvif_time_request(ip, port, path))

    def http_get(self, ip, scheme, path, auth=None, port=None):
        """Ένα GET → (status, WWW-Authenticate, σώμα έως 3 MB) ή None. Δεν ακολουθεί ανακατευθύνσεις."""
        import http.client
        import ssl
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # κάμερα στο LAN με self-signed
                c = http.client.HTTPSConnection(ip, port or 443, timeout=4, context=ctx)
            else:
                c = http.client.HTTPConnection(ip, port or 80, timeout=4)
            hd = {"User-Agent": "NetWatch-CamCheck", "Accept": "image/jpeg", "Connection": "close"}
            if auth:
                hd["Authorization"] = auth
            c.request("GET", path, headers=hd)
            r = c.getresponse()
            body = r.read(MAX_JPEG + 1) if r.status == 200 else b""
            www = ", ".join(r.headers.get_all("WWW-Authenticate") or [])
            c.close()
            return r.status, www, body
        except Exception:  # noqa: BLE001
            return None

    def rtsp(self, ip, port, method):
        return self._tcp(ip, port, rtsp_request(ip, port, method, 2 if method == "DESCRIBE" else 1))

    def _mcast(self, addr, payload, wait=2.5):
        out = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            s.settimeout(0.4)
            for _ in range(2):
                s.sendto(payload, addr)
            end = time.monotonic() + wait
            while time.monotonic() < end and len(out) < 256:
                try:
                    d, a = s.recvfrom(MAX_REPLY)
                except socket.timeout:
                    continue
                out.append((d, a[0]))
            s.close()
        except OSError:
            pass
        return out

    def discover_onvif(self):
        return self._mcast(WSD_ADDR, wsd_probe())

    def discover_sadp(self):
        return self._mcast(SADP_ADDR, sadp_probe())


# ───────────────────────── ο έλεγχος ─────────────────────────
def _c(cid, status, el, en, fix="", fix_en="", val=""):
    return {"id": cid, "status": status, "el": el, "en": en, "fix": fix, "fix_en": fix_en, "val": val}


class CamCheck:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time, net=None, site_reg=None):
        import os
        self.state, self.demo, self.clock = state, demo, clock
        self.net = net or RealNet()
        self.sites = site_reg
        self.path = os.path.join(data_dir, "camcheck.json") if data_dir else None
        self.on_save = None
        self.lock = threading.RLock()
        self.cams = {}          # ip → {ip, name, mac, vendor, model, fw, src, added}
        self.results = {}       # ip → {t, level, checks[]}
        self.found = []         # τελευταία ανακάλυψη (και όσες είναι σε λάθος subnet)
        self.conflicts = []     # [{ip, macs[], why}]
        self.busy, self.scanned, self.error = False, None, None
        if demo:
            self._demo()
        elif self.path:
            j = sites.read_json(self.path, {})
            self.cams = {ip: c for ip, c in (j.get("cams") or {}).items() if is_private(ip) and isinstance(c, dict)}
            self.results = {ip: r for ip, r in (j.get("results") or {}).items() if ip in self.cams and isinstance(r, dict)}
            self.scanned = j.get("scanned")

    def _save(self):
        if self.path:
            sites.write_json(self.path, {"cams": self.cams, "results": self.results, "scanned": self.scanned}, self.on_save)

    # ── κατάλογος καμερών ──
    def add(self, ip, name="", src="manual", **extra):
        ip = str(ip or "").strip()
        if not is_private(ip):
            return {"error": "Μόνο ιδιωτικές διευθύνσεις του τοπικού δικτύου (π.χ. 192.168.1.64).", "error_en": "Private LAN addresses only (e.g. 192.168.1.64)."}
        with self.lock:
            if ip not in self.cams and len(self.cams) >= MAX_CAMS:
                return {"error": f"Έως {MAX_CAMS} κάμερες.", "error_en": f"Up to {MAX_CAMS} cameras."}
            c = self.cams.setdefault(ip, {"ip": ip, "name": "", "mac": "", "vendor": "", "model": "", "fw": "", "src": src, "added": self.clock()})
            if name:
                c["name"] = clean(name, 60)
            for k in ("mac", "vendor", "model", "fw"):
                if extra.get(k):
                    c[k] = clean(extra[k], 60)
            if isinstance(extra.get("web"), int) and 0 < extra["web"] < 65536:
                c["web"] = extra["web"]      # θύρα του web UI όπως τη δήλωσε η συσκευή (π.χ. 8000 σε καταγραφικά TVT)
        return {"ok": True}

    def _import_known(self):
        ce = getattr(self.state, "camexp", None)
        try:
            known = ce.known_cameras() if ce is not None else {}
        except Exception:  # noqa: BLE001
            known = {}
        for ip, k in list(known.items())[:MAX_CAMS]:
            self.add(ip, k.get("name") or "", "seen", vendor=k.get("vendor") or "")

    def discover(self):
        """WS-Discovery + SADP. Γεμίζει τον κατάλογο και βρίσκει κάμερες σε λάθος subnet και διπλές IP."""
        loc = self._local()
        found, by_ip = {}, {}
        for d, src in (self.net.discover_onvif() or [])[:256]:
            w = parse_wsd(d, src)
            if w and is_private(w["ip"]):
                f = found.setdefault(w["ip"] + "|" + w["src"], {"ip": w["ip"], "mac": "", "name": w["name"], "model": w["hardware"], "fw": "", "via": "ONVIF"})
                f["xaddrs"] = w["xaddrs"]
        for d, _src in (self.net.discover_sadp() or [])[:256]:
            s = parse_sadp(d)
            if s and is_private(s["ip"]):
                found[s["ip"] + "|" + (s["mac"] or s["sn"])] = {"ip": s["ip"], "mac": s["mac"], "name": "", "model": s["model"], "fw": s["fw"], "via": "SADP",
                                                              "activated": s["activated"], "dhcp": s["dhcp"], "mask": s["mask"], "gw": s["gw"], "sn": s["sn"]}
        out, conflicts = [], []
        for f in found.values():
            f["off_subnet"] = bool(loc.get("ip")) and not same_subnet(f["ip"], loc["ip"], loc.get("prefix") or 24)
            f["factory"] = FACTORY_IPS.get(f["ip"], "")
            if f.get("mac"):
                by_ip.setdefault(f["ip"], set()).add(f["mac"])
            out.append(f)
        for ip, macs in by_ip.items():
            if len(macs) > 1:
                conflicts.append({"ip": ip, "macs": sorted(macs), "why": "discovery"})
        with self.lock:
            self.found, self.conflicts = sorted(out, key=lambda x: (not x["off_subnet"], x["ip"]))[:256], conflicts
        for f in out:
            if not f["off_subnet"]:
                self.add(f["ip"], f.get("name") or "", "found", mac=f.get("mac"), model=f.get("model"), fw=f.get("fw"), vendor="Hikvision" if f["via"] == "SADP" else "",
                         web=next((x[1] for x in (f.get("xaddrs") or []) if x[0] == f["ip"]), None))
        return out

    def _local(self):
        try:
            loc = self.net.local() or {}
        except Exception:  # noqa: BLE001
            loc = {}
        if not loc.get("gateway"):
            loc["gateway"] = getattr(self.state, "gateway", None)
        return loc

    # ── έλεγχος μίας κάμερας ──
    def check_one(self, ip, loc=None, found=None):
        if not is_private(ip):
            return {"t": self.clock(), "level": "fail", "checks": [_c("target", "fail", "Μη επιτρεπτός στόχος.", "Target not allowed.")]}
        loc, f, n, out = loc or self._local(), found or {}, self.net, []
        # 1) απαντά; με τι απώλειες;
        p = n.ping(ip) or {}
        if p.get("err") in ("noping", "denied"):
            out.append(_c("ping", "skip", "Δεν μπόρεσα να κάνω ping από αυτό το σύστημα.", "Could not ping from this system."))
        elif not p.get("ok"):
            out.append(_c("ping", "fail", "Δεν απαντά σε ping.", "Does not answer ping.",
                          "Έλεγξε PoE (ανάβει;), καλώδιο και θύρα switch. Αν η κάμερα είναι καινούργια, ίσως έχει ακόμα την εργοστασιακή IP — πάτα «Αναζήτηση καμερών».",
                          "Check PoE (is it lit?), the cable and the switch port. A new camera may still have its factory IP — press “Find cameras”."))
        else:
            loss, ms = p.get("loss") or 0.0, p.get("ms")
            st = "fail" if loss >= LOSS_FAIL else "warn" if loss >= LOSS_WARN else "pass"
            out.append(_c("ping", st, f"Απαντά · απώλεια {loss:g}%" + (f" · {ms:.1f} ms" if ms is not None else ""),
                          f"Answers · loss {loss:g}%" + (f" · {ms:.1f} ms" if ms is not None else ""),
                          "" if st == "pass" else "Απώλειες σε καλώδιο δείχνουν κακό τερματισμό, μήκος πάνω από 90 m ή χαμηλή τάση PoE. Ξανατερμάτισε, δοκίμασε άλλη θύρα, μέτρησε με τον 🔌 Tester πρίζας.",
                          "" if st == "pass" else "Loss on a wired run points to bad termination, a run over 90 m or low PoE voltage. Re-terminate, try another port, measure with the 🔌 Socket tester.",
                          f"{loss:g}%"))
        # 2) σύγκρουση IP
        macs = n.arp_macs(ip)
        if macs is None:
            out.append(_c("conflict", "skip", "Ο έλεγχος διπλής IP θέλει δικαιώματα διαχειριστή (Live).", "The duplicate-IP check needs admin rights (Live)."))
        elif len(macs) > 1:
            out.append(_c("conflict", "fail", f"ΔΥΟ συσκευές απαντούν για την {ip}: {', '.join(macs)}.", f"TWO devices answer for {ip}: {', '.join(macs)}.",
                          "Σύγκρουση IP: η κάμερα θα «πέφτει» τυχαία. Βγάλε τη μία από το δίκτυο, δώσε της νέα IP και ξανασύνδεσέ τη. Κράτα πίνακα IP (🗂 IPAM).",
                          "IP conflict: the camera will drop at random. Unplug one, give it a new IP and reconnect it. Keep an IP table (🗂 IPAM).", ", ".join(macs)))
        elif macs:
            out.append(_c("conflict", "pass", f"Μία μόνο συσκευή έχει αυτή την IP ({macs[0]}).", f"Only one device holds this IP ({macs[0]}).", val=macs[0]))
        else:
            out.append(_c("conflict", "skip", "Καμία απάντηση ARP (άλλο subnet ή εκτός δικτύου).", "No ARP answer (different subnet or offline)."))
        # 3) διεύθυνση
        if FACTORY_IPS.get(ip):
            out.append(_c("factory", "warn", f"Έχει ακόμα την εργοστασιακή IP ({FACTORY_IPS[ip]}).", f"Still on the factory IP ({FACTORY_IPS[ip]}).",
                          "Η επόμενη κάμερα της ίδιας μάρκας θα βγει με την ίδια IP και θα συγκρουστούν. Δώσε της δική της στατική IP τώρα.",
                          "The next camera of this brand will come up on the same IP and they will collide. Give it its own static IP now."))
        if f.get("dhcp") is True:
            out.append(_c("dhcp", "warn", "Παίρνει IP από DHCP.", "It gets its IP from DHCP.",
                          "Αν αλλάξει IP, το καταγραφικό θα τη χάσει. Βάλε στατική IP ή δέσμευση (reservation) στο router.",
                          "If its IP changes the recorder loses it. Set a static IP or a DHCP reservation on the router."))
        if f.get("gw") and loc.get("gateway") and f["gw"] != loc["gateway"] and f["gw"] != "0.0.0.0":
            out.append(_c("gw", "warn", f"Η πύλη της κάμερας είναι {f['gw']}, του δικτύου {loc['gateway']}.", f"The camera’s gateway is {f['gw']}, the network’s is {loc['gateway']}.",
                          "Με λάθος πύλη η κάμερα δεν βρίσκει NTP ούτε cloud/ειδοποιήσεις. Διόρθωσέ τη στις ρυθμίσεις δικτύου της.",
                          "With the wrong gateway the camera reaches neither NTP nor cloud/notifications. Fix it in its network settings."))
        if f.get("activated") is False:
            out.append(_c("active", "fail", "Η κάμερα ΔΕΝ έχει ενεργοποιηθεί (δεν έχει οριστεί κωδικός).", "The camera is NOT activated (no password has been set).",
                          "Ενεργοποίησέ τη από το web UI της ή από το καταγραφικό και όρισε ισχυρό κωδικό — αλλιώς ο πρώτος που θα τη βρει ορίζει τον δικό του.",
                          "Activate it from its web UI or from the recorder and set a strong password — otherwise whoever finds it first sets theirs."))
        # 4) ώρα (ONVIF, χωρίς κωδικό)
        xa = [(x[1], x[2]) for x in (f.get("xaddrs") or []) if x[0] == ip] or [(pt, "/onvif/device_service") for pt in ONVIF_PORTS]
        tm = None
        for port, path in xa[:6]:
            tm = parse_onvif_time(n.onvif_time(ip, port, path) or b"")
            if tm:
                break
        if not tm:
            out.append(_c("clock", "skip", "Δεν απάντησε σε ONVIF — δεν μπορώ να δω την ώρα της.", "No ONVIF answer — cannot read its clock.",
                          "Αν το καταγραφικό τη βρίσκει με ιδιόκτητο πρωτόκολλο, είναι εντάξει. Αλλιώς άνοιξε το ONVIF στην κάμερα.",
                          "If the recorder finds it with a proprietary protocol this is fine. Otherwise enable ONVIF on the camera."))
        else:
            drift = int(round(tm["utc"] - self.clock()))
            st = "fail" if abs(drift) >= CLOCK_FAIL else "warn" if abs(drift) >= CLOCK_WARN else "pass"
            how = f"{abs(drift)} s {'μπροστά' if drift > 0 else 'πίσω'}" if abs(drift) < 7200 else f"{abs(drift) // 3600} ώρες {'μπροστά' if drift > 0 else 'πίσω'}"
            how_en = f"{abs(drift)} s {'ahead' if drift > 0 else 'behind'}" if abs(drift) < 7200 else f"{abs(drift) // 3600} h {'ahead' if drift > 0 else 'behind'}"
            out.append(_c("clock", st, "Η ώρα είναι σωστή." if st == "pass" else f"Η ώρα της κάμερας είναι {how}.", "The clock is correct." if st == "pass" else f"The camera clock is {how_en}.",
                          "" if st == "pass" else "Με λάθος ώρα δεν βρίσκεις το συμβάν στις καταγραφές (και δεν στέκει ως αποδεικτικό). Βάλε NTP: το router ή το καταγραφικό ως server.",
                          "" if st == "pass" else "With a wrong clock you cannot find the event in the recordings (and it is weak as evidence). Set NTP: the router or the recorder as server.",
                          f"{drift:+d}s"))
            if tm["ntp"] is False:
                out.append(_c("ntp", "warn", "Η ώρα έχει μπει με το χέρι, όχι από NTP.", "The clock is set manually, not from NTP.",
                              "Θα ξεφύγει σε λίγους μήνες και μετά από διακοπή ρεύματος. Όρισε NTP server.", "It will drift within months and after a power cut. Set an NTP server."))
        # 5) ροή RTSP: ζητά κωδικό;
        rt = None
        for port in RTSP_PORTS:
            o = parse_rtsp(n.rtsp(ip, port, "OPTIONS") or b"")
            if o:
                d = parse_rtsp(n.rtsp(ip, port, "DESCRIBE") or b"") or o
                rt = dict(d, port=port)
                break
        if not rt:
            out.append(_c("rtsp", "warn", "Δεν απαντά σε RTSP (554/8554).", "No RTSP answer (554/8554).",
                          "Το καταγραφικό χρειάζεται RTSP ή το ιδιόκτητο πρωτόκολλο της μάρκας. Αν δεν γράφει, άνοιξε το RTSP στην κάμερα.",
                          "The recorder needs RTSP or the brand’s own protocol. If it does not record, enable RTSP on the camera."))
        elif rt["code"] == 200:
            out.append(_c("rtsp", "fail", "Η ροή βίντεο δίνεται ΧΩΡΙΣ κωδικό.", "The video stream is served WITHOUT a password.",
                          "Όποιος είναι στο δίκτυο βλέπει την κάμερα. Ενεργοποίησε έλεγχο ταυτότητας RTSP (digest) στις ρυθμίσεις της.",
                          "Anyone on the network can watch the camera. Enable RTSP authentication (digest) in its settings.", rt.get("codec") or ""))
        elif rt["code"] == 401 or rt["auth"]:
            out.append(_c("rtsp", "pass", f"Η ροή ζητά κωδικό (RTSP :{rt['port']}).", f"The stream asks for a password (RTSP :{rt['port']})."))
        else:
            out.append(_c("rtsp", "pass", f"Το RTSP απαντά (κωδικός {rt['code']}).", f"RTSP answers (status {rt['code']})."))
        lv = "fail" if any(c["status"] == "fail" for c in out) else "warn" if any(c["status"] == "warn" for c in out) else "pass"
        return {"t": self.clock(), "level": lv, "checks": out}

    def run(self, ips=None, discover=True):
        """Ανακάλυψη + έλεγχος όλων (ή κάποιων) καμερών."""
        try:
            self.error = None
            self._import_known()
            found = {}
            if discover:
                for f in self.discover():
                    found.setdefault(f["ip"], f)
            loc = self._local()
            with self.lock:
                todo = [ip for ip in (ips or sorted(self.cams, key=lambda x: tuple(int(p) for p in x.split(".")))) if ip in self.cams][:MAX_CAMS]
            with ThreadPoolExecutor(max_workers=8) as ex:
                res = list(ex.map(lambda ip: (ip, self._safe(ip, loc, found.get(ip))), todo))
            with self.lock:
                for ip, r in res:
                    self.results[ip] = r
                    mac = next((c["val"] for c in r["checks"] if c["id"] == "conflict" and c["status"] == "pass"), "")
                    if mac and not self.cams[ip].get("mac"):
                        self.cams[ip]["mac"] = mac
                    if any(c["id"] == "conflict" and c["status"] == "fail" for c in r["checks"]) and not any(x["ip"] == ip for x in self.conflicts):
                        self.conflicts.append({"ip": ip, "macs": next(c["val"] for c in r["checks"] if c["id"] == "conflict").split(", "), "why": "arp"})
                self.scanned = self.clock()
                self._save()
        except Exception as e:  # noqa: BLE001
            self.error = str(e)[:160]
        finally:
            self.busy = False

    # ── 👁 τι βλέπει η κάμερα (με κωδικό που δίνει ο χρήστης· ΜΙΑ προσπάθεια) ──
    def snapshot(self, ip, user, password, allow_basic=False, path=""):
        E = lambda el, en: {"error": el, "error_en": en}  # noqa: E731
        ip = str(ip or "").strip()
        with self.lock:
            cam = dict(self.cams.get(ip) or {})
        if not cam or not is_private(ip):
            return E("Η κάμερα δεν είναι στη λίστα.", "The camera is not in the list.")
        if self.demo:
            return {"ok": True, "img": _demo_img(cam.get("name") or ip), "via": "demo", "open": False}
        user, password = str(user or "")[:64], str(password or "")[:128]
        if path and not SNAP_PATH_RX.match(path):
            return E("Μη έγκυρη διαδρομή.", "Invalid path.")
        hint = (cam.get("vendor") or "").lower() + " " + (cam.get("model") or "").lower()
        paths = [path] if path else [p for v, p in sorted(SNAP_PATHS, key=lambda vp: not (vp[0] and vp[0] in hint))]
        # 1) χωρίς κωδικό: ποια διεύθυνση υπάρχει; (404 → επόμενη· 401 → αυτή είναι, ζητά κωδικό)
        target = None
        web = cam.get("web") if isinstance(cam.get("web"), int) else None
        ways = [("https", None), ("http", None)] + ([("http", web)] if web and web not in (80, 443) else [])
        for scheme, port in ways:
            for p in paths:
                r = self.net.http_get(ip, scheme, p, None, port)
                if not r:
                    break                      # το scheme δεν απαντά καθόλου
                st, www, body = r
                if st == 200 and is_jpeg(body):
                    return self._img(body, scheme, True)
                if st == 401:
                    target = (scheme, p, parse_challenge(www), port)
                    break
            if target:
                break
        if not target:
            return E("Δεν βρήκα διεύθυνση στιγμιότυπου σε αυτή την κάμερα. Δώσε τη διαδρομή από το εγχειρίδιό της (π.χ. /cgi-bin/snapshot.cgi).",
                     "No snapshot address found on this camera. Enter the path from its manual (e.g. /cgi-bin/snapshot.cgi).")
        if not user or not password:
            return E("Η κάμερα ζητά όνομα χρήστη και κωδικό.", "The camera asks for a user name and password.")
        scheme, p, ch, port = target
        # 2) ΜΙΑ προσπάθεια με τα στοιχεία του χρήστη
        if ch["digest"]:
            auth = digest_header(user, password, "GET", p, ch["digest"])
            if not auth:
                return E("Η κάμερα ζητά αλγόριθμο Digest που δεν υποστηρίζω.", "The camera asks for a Digest algorithm I do not support.")
        elif ch["basic"]:
            if scheme != "https" and not allow_basic:
                return dict(E("Η κάμερα δέχεται μόνο «Basic» σε απλό HTTP: ο κωδικός θα ταξίδευε χωρίς κρυπτογράφηση στο δίκτυο. Άνοιξε HTTPS ή Digest στην κάμερα — ή τσέκαρε «το επιτρέπω» για αυτή τη φορά.",
                              "The camera only accepts “Basic” over plain HTTP: the password would travel unencrypted on the network. Enable HTTPS or Digest on the camera — or tick “allow it” for this once."), need_basic=True)
            auth = "Basic " + base64.b64encode(f"{user}:{password}".encode("utf-8")).decode()
        else:
            return E("Η κάμερα ζητά τρόπο σύνδεσης που δεν υποστηρίζω.", "The camera asks for a login method I do not support.")
        r = self.net.http_get(ip, scheme, p, auth, port)
        del auth, password
        if not r:
            return E("Η κάμερα δεν απάντησε.", "The camera did not answer.")
        st, _www, body = r
        if st == 401 or st == 403:
            return E("Λάθος όνομα ή κωδικός. Δεν ξαναδοκιμάζω μόνος μου — οι κάμερες κλειδώνουν μετά από λίγες αποτυχίες.",
                     "Wrong user name or password. I will not retry on my own — cameras lock after a few failures.")
        if st != 200 or not is_jpeg(body):
            return E(f"Η κάμερα απάντησε {st}, όχι με εικόνα.", f"The camera answered {st}, not an image.")
        return self._img(body, scheme, False)

    @staticmethod
    def _img(body, scheme, is_open):
        if len(body) > MAX_JPEG:
            return {"error": "Η εικόνα είναι πολύ μεγάλη (πάνω από 3 MB).", "error_en": "The image is too large (over 3 MB)."}
        return {"ok": True, "img": "data:image/jpeg;base64," + base64.b64encode(bytes(body)).decode(), "via": scheme, "open": is_open, "kb": len(body) // 1024}

    def _safe(self, ip, loc, found):
        try:
            return self.check_one(ip, loc, found)
        except Exception as e:  # noqa: BLE001
            return {"t": self.clock(), "level": "warn", "checks": [_c("error", "skip", "Ο έλεγχος απέτυχε: " + str(e)[:80], "Check failed: " + str(e)[:80])]}

    # ── UI ──
    def view(self):
        with self.lock:
            cams = []
            for ip in sorted(self.cams, key=lambda x: tuple(int(p) for p in x.split("."))):
                c = dict(self.cams[ip])
                c["result"] = self.results.get(ip)
                cams.append(c)
            lv = [c["result"]["level"] for c in cams if c.get("result")]
            return {"demo": self.demo, "busy": self.busy, "scanned": self.scanned, "error": self.error, "cams": cams,
                    "counts": {"total": len(cams), "pass": lv.count("pass"), "warn": lv.count("warn"), "fail": lv.count("fail"), "pending": len(cams) - len(lv)},
                    "stray": [f for f in self.found if f.get("off_subnet")], "conflicts": list(self.conflicts),
                    "factory": {k: v for k, v in FACTORY_IPS.items()}}

    def api(self, method, sub, q, body):
        if method == "GET" and sub == "":
            return 200, self.view()
        if method == "GET" and sub == "report":
            return sites.raw(self.report("en" if q.get("lang") == "en" else "el"), "netwatch-cameras.html")
        if method == "GET" and sub == "csv":
            rows = []
            for c in self.view()["cams"]:
                r = c.get("result") or {}
                rows.append([c["ip"], c.get("name"), c.get("mac"), c.get("model"), r.get("level") or "", "; ".join(x["el"] for x in (r.get("checks") or []) if x["status"] in ("fail", "warn"))])
            return sites.raw(sites.csv_text(rows, ["IP", "Όνομα", "MAC", "Μοντέλο", "Αποτέλεσμα", "Προβλήματα"]), "netwatch-cameras.csv", "text/csv; charset=utf-8")
        if method != "POST":
            return 404, {"error": "not found"}
        if sub == "run":
            if self.demo:
                return 200, self.view()
            ips = [str(x) for x in body.get("ips")][:MAX_CAMS] if isinstance(body.get("ips"), list) else None
            with self.lock:
                if self.busy:
                    return 200, self.view()
                self.busy = True
            threading.Thread(target=self.run, args=(ips, not ips), daemon=True).start()
            return 200, self.view()
        if sub == "snapshot":
            r = self.snapshot(body.get("ip"), body.get("user"), body.get("password"), bool(body.get("allow_basic")), str(body.get("path") or ""))
            return (400 if r.get("error") else 200), r
        if sub == "add":
            if self.demo:
                return 200, self.view()
            r = self.add(body.get("ip"), body.get("name") or "")
            if r.get("error"):
                return 400, r
            self._save()
            return 200, self.view()
        if sub == "remove":
            with self.lock:
                if not self.demo:
                    self.cams.pop(str(body.get("ip")), None)
                    self.results.pop(str(body.get("ip")), None)
                    self._save()
            return 200, self.view()
        return 404, {"error": "not found"}

    # ── φύλλο παράδοσης ──
    def report(self, lang="el"):
        v = self.view()
        t = lambda el, en: L(lang, el, en)  # noqa: E731
        co = self.sites.company() if self.sites is not None else {}
        site = None
        if self.sites is not None:
            try:
                site = self.sites.get(self.sites.detect())
            except Exception:  # noqa: BLE001
                site = None
        c = v["counts"]
        ok = c["fail"] == 0 and c["pending"] == 0 and c["total"] > 0
        h = [sites.doc_open(t("Φύλλο παράδοσης καμερών", "Camera commissioning sheet"), lang, self.demo), sites.doc_header(co, lang, "", self.clock()),
             f'<h1>{t("Φύλλο παράδοσης καμερών", "Camera commissioning sheet")}</h1>',
             f'<div class="sub">{t("Έλεγχος", "Checked")}: {esc(sites.ts(v["scanned"], lang))}</div>',
             (f'<div class="grid">{sites.customer_block(site, lang)}<div></div></div>' if site else ""),
             f'<div class="verdict" style="--c:{"#0a7a3d" if ok else "#c0182d" if c["fail"] else "#9a6a00"}">'
             + (t("Όλες οι κάμερες πέρασαν τον έλεγχο", "All cameras passed") if ok and not c["warn"] else t(f'{c["fail"]} με πρόβλημα · {c["warn"]} με παρατήρηση · {c["pass"]} εντάξει', f'{c["fail"]} failing · {c["warn"]} with remarks · {c["pass"]} OK')) + "</div>",
             '<div class="kpis">' + "".join(f'<div><b>{c[k]}</b><span>{lbl}</span></div>' for k, lbl in (("total", t("κάμερες", "cameras")), ("pass", t("εντάξει", "OK")), ("warn", t("παρατηρήσεις", "remarks")), ("fail", t("προβλήματα", "problems")))) + "</div>"]
        if v["conflicts"]:
            h.append(f'<h2>{t("Συγκρούσεις IP", "IP conflicts")}</h2><ul>' + "".join(f'<li class="fail">{esc(x["ip"])} — {esc(", ".join(x["macs"]))}</li>' for x in v["conflicts"]) + "</ul>")
        if v["stray"]:
            h.append(f'<h2>{t("Κάμερες σε λάθος subnet", "Cameras on the wrong subnet")}</h2><ul>' + "".join(f'<li>{esc(x["ip"])} {esc(x.get("model") or "")} <span class="mono">{esc(x.get("mac") or "")}</span></li>' for x in v["stray"]) + "</ul>")
        mark = {"pass": ("pass", "✓"), "warn": ("pend", "!"), "fail": ("fail", "✗"), "skip": ("na", "–")}
        h.append(f'<h2>{t("Ανά κάμερα", "Per camera")}</h2><table><tr><th>{t("Κάμερα", "Camera")}</th><th>{t("Έλεγχοι", "Checks")}</th></tr>')
        for cam in v["cams"]:
            r = cam.get("result")
            rows = "".join(f'<div><span class="{mark[x["status"]][0]}">{mark[x["status"]][1]}</span> {esc(x["en"] if lang == "en" else x["el"])}'
                           + (f'<div class="sub">→ {esc(x["fix_en"] if lang == "en" else x["fix"])}</div>' if x["status"] in ("fail", "warn") and x["fix"] else "") + "</div>"
                           for x in (r or {}).get("checks", [])) or f'<span class="pend">{t("δεν ελέγχθηκε", "not checked")}</span>'
            h.append(f'<tr><td><b>{esc(cam.get("name") or cam["ip"])}</b><div class="mono">{esc(cam["ip"])}</div><div class="sub mono">{esc(cam.get("mac") or "")}</div>'
                     f'<div class="sub">{esc(" ".join(x for x in (cam.get("vendor"), cam.get("model"), cam.get("fw")) if x))}</div></td><td>{rows}</td></tr>')
        h.append("</table>")
        h.append(f'<h2>{t("Με το χέρι, πριν φύγεις", "By hand, before you leave")}</h2><ul>'
                 + "".join(f"<li>☐ {x}</li>" for x in (
                     t("Άλλαξαν οι εργοστασιακοί κωδικοί σε κάθε κάμερα και στο καταγραφικό (δεν ελέγχονται αυτόματα — το NetWatch δεν δοκιμάζει ποτέ κωδικούς).", "Factory passwords changed on every camera and on the recorder (not checked automatically — NetWatch never tries passwords)."),
                     t("Το καταγραφικό γράφει από κάθε κάμερα και οι μέρες διατήρησης είναι όσες συμφωνήθηκαν.", "The recorder records from every camera and retention matches what was agreed."),
                     t("Το πεδίο θέασης κάθε κάμερας εγκρίθηκε από τον πελάτη· νυχτερινή εικόνα ελέγχθηκε.", "Each camera’s field of view was approved by the customer; night image checked."),
                     t("Απομακρυσμένη πρόσβαση με VPN ή cloud του κατασκευαστή — όχι ανοιχτές θύρες στο router.", "Remote viewing via VPN or the vendor cloud — no open ports on the router."))) + "</ul>")
        h.append(sites.signatures(lang, t("Ο τεχνικός", "Technician"), t("Ο πελάτης", "Customer")))
        h.append(sites.doc_close(lang))
        return "".join(h)

    # ── demo ──
    def _demo(self):
        now = self.clock()
        P = lambda cid, el, en, val="": _c(cid, "pass", el, en, val=val)  # noqa: E731
        base = [("10.20.0.101", "Είσοδος", "Hikvision", "DS-2CD2143G2-I", "V5.7.3"), ("10.20.0.102", "Ρεσεψιόν", "Hikvision", "DS-2CD2143G2-I", "V5.7.3"),
                ("10.20.0.103", "Πάρκινγκ Α", "Dahua", "IPC-HFW2441S", "V2.840"), ("10.20.0.104", "Πάρκινγκ Β", "Dahua", "IPC-HFW2441S", "V2.840"),
                ("10.20.0.105", "Αποθήκη", "Reolink", "RLC-810A", "v3.1.0"), ("10.20.0.106", "Πίσω αυλή", "Hikvision", "DS-2CD2043G2-I", "V5.7.1")]
        for i, (ip, name, ven, model, fw) in enumerate(base):
            mac = f"44:19:b6:20:00:{i + 1:02x}"
            self.cams[ip] = {"ip": ip, "name": name, "mac": mac, "vendor": ven, "model": model, "fw": fw, "src": "found", "added": now - 3600}
            ch = [P("ping", "Απαντά · απώλεια 0% · 1.2 ms", "Answers · loss 0% · 1.2 ms", "0%"), P("conflict", f"Μία μόνο συσκευή έχει αυτή την IP ({mac}).", f"Only one device holds this IP ({mac}).", mac),
                  P("clock", "Η ώρα είναι σωστή.", "The clock is correct.", "+1s"), P("rtsp", "Η ροή ζητά κωδικό (RTSP :554).", "The stream asks for a password (RTSP :554).")]
            self.results[ip] = {"t": now - 600, "level": "pass", "checks": ch}
        net = _DemoNet(now)
        self.net = net
        for ip in ("10.20.0.104", "10.20.0.105", "10.20.0.106"):
            self.results[ip] = self.check_one(ip, {"ip": "10.20.0.23", "prefix": 24, "gateway": "10.20.0.1"}, net.found.get(ip))
            self.results[ip]["t"] = now - 600
        self.found = [{"ip": "192.168.1.64", "mac": "44:19:b6:aa:01:07", "name": "", "model": "DS-2CD2143G2-I", "fw": "V5.7.3", "via": "SADP", "activated": False,
                       "dhcp": False, "mask": "255.255.255.0", "gw": "192.168.1.1", "off_subnet": True, "factory": "Hikvision"},
                      {"ip": "192.168.1.64", "mac": "44:19:b6:aa:01:08", "name": "", "model": "DS-2CD2143G2-I", "fw": "V5.7.3", "via": "SADP", "activated": False,
                       "dhcp": False, "mask": "255.255.255.0", "gw": "192.168.1.1", "off_subnet": True, "factory": "Hikvision"}]
        self.conflicts = [{"ip": "192.168.1.64", "macs": ["44:19:b6:aa:01:07", "44:19:b6:aa:01:08"], "why": "discovery"}]
        self.scanned = now - 600


def _demo_img(name):
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 360"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#5b7c99"/>'
           '<stop offset=".55" stop-color="#9db4c0"/><stop offset=".56" stop-color="#55606b"/><stop offset="1" stop-color="#2f363d"/></linearGradient></defs>'
           '<rect width="640" height="360" fill="url(#g)"/><path d="M0 250 260 200 640 235V360H0z" fill="#3a424a"/><rect x="410" y="120" width="150" height="110" fill="#6d7780"/>'
           '<rect x="455" y="170" width="40" height="60" fill="#2b3138"/><rect x="60" y="215" width="120" height="45" rx="10" fill="#b23b3b"/>'
           '<circle cx="88" cy="262" r="12" fill="#111"/><circle cx="152" cy="262" r="12" fill="#111"/>'
           f'<text x="14" y="26" font-family="monospace" font-size="16" fill="#fff">{esc(name)[:40]}</text>'
           '<text x="626" y="26" font-family="monospace" font-size="16" fill="#fff" text-anchor="end">DEMO</text></svg>')
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode()


class _DemoNet:
    """Τρεις «προβληματικές» κάμερες για το demo: απώλειες καλωδίου, λάθος ώρα + ανοιχτή ροή, DHCP + λάθος πύλη."""
    def __init__(self, now):
        self.now = now
        self.found = {"10.20.0.106": {"ip": "10.20.0.106", "dhcp": True, "gw": "10.20.0.254", "activated": True}}

    def local(self):
        return {"ip": "10.20.0.23", "prefix": 24, "gateway": "10.20.0.1"}

    def ping(self, ip):
        return {"ok": True, "loss": 20.0 if ip.endswith(".104") else 0.0, "ms": 38.5 if ip.endswith(".104") else 1.3, "err": None}

    def arp_macs(self, ip):
        return ["44:19:b6:20:00:%02x" % (int(ip.split(".")[-1]) - 100)]

    def onvif_time(self, ip, port, path):
        t = time.gmtime(self.now - (3 * 3600 + 120 if ip.endswith(".105") else 0))
        kind = "Manual" if ip.endswith(".105") else "NTP"
        return (f"HTTP/1.1 200 OK\r\n\r\n<tt:DateTimeType>{kind}</tt:DateTimeType><tt:UTCDateTime><tt:Time><tt:Hour>{t.tm_hour}</tt:Hour><tt:Minute>{t.tm_min}</tt:Minute>"
                f"<tt:Second>{t.tm_sec}</tt:Second></tt:Time><tt:Date><tt:Year>{t.tm_year}</tt:Year><tt:Month>{t.tm_mon}</tt:Month><tt:Day>{t.tm_mday}</tt:Day></tt:Date></tt:UTCDateTime>").encode()

    def rtsp(self, ip, port, method):
        if port != 554:
            return None
        if ip.endswith(".105") and method == "DESCRIBE":
            return b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\n\r\nv=0\r\na=rtpmap:96 H265/90000\r\n"
        if method == "DESCRIBE":
            return b'RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\nWWW-Authenticate: Digest realm="cam", nonce="x"\r\n\r\n'
        return b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n"

    def discover_onvif(self):
        return []

    def discover_sadp(self):
        return []
