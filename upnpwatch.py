"""🔓 Θύρες που άνοιξαν μόνες τους στο router σου (UPnP / IGD) — μόνο ανάγνωση.

Πολλές συσκευές (κάμερες, κονσόλες, torrent, smart TV) ζητούν από το router με UPnP να τους ανοίξει θύρα προς
το Internet, χωρίς να σε ρωτήσει κανείς. Εδώ:
  1. Βρίσκουμε το router με ένα SSDP M-SEARCH στο τοπικό multicast (239.255.255.250:1900).
     Δεχόμαστε απαντήσεις ΜΟΝΟ από ιδιωτικές IP, και το LOCATION πρέπει να δείχνει στην ίδια IP.
  2. Διαβάζουμε την περιγραφή της συσκευής (XML) και βρίσκουμε την υπηρεσία WANIPConnection / WANPPPConnection.
  3. Ρωτάμε GetGenericPortMappingEntry(0, 1, 2…) μέχρι να τελειώσει ο πίνακας.
ΠΟΤΕ δεν καλούμε AddPortMapping / DeletePortMapping ή άλλη ενέργεια που αλλάζει κάτι. Το κλείσιμο το κάνεις εσύ
στο router (ή στη συσκευή). Κάθε νέα θύρα που εμφανίζεται → ειδοποίηση· κάμερα/IoT ή «επικίνδυνη» θύρα → κόκκινο.
"""
import http.client
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET

SSDP = ("239.255.255.250", 1900)
STS = ("urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
       "urn:schemas-upnp-org:service:WANIPConnection:1")
SERVICES = ("urn:schemas-upnp-org:service:WANIPConnection:2", "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANPPPConnection:1")
MAX_XML = 256 * 1024
MAX_ENTRIES = 256
EVERY = 15 * 60

# θύρες που δεν θέλεις ποτέ ανοιχτές προς το Internet
DANGER = {21: "FTP", 23: "Telnet", 445: "SMB (κοινόχρηστοι φάκελοι)", 554: "RTSP (βίντεο κάμερας)", 1883: "MQTT χωρίς TLS",
          3389: "Απομακρυσμένη επιφάνεια εργασίας (RDP)", 5900: "VNC", 8000: "κάμερα / DVR (Hikvision)",
          34567: "DVR (XMEye)", 37777: "κάμερα / DVR (Dahua)", 2323: "Telnet (εναλλακτική)", 7547: "TR-069 (διαχείριση router)"}
# θύρες διαχείρισης — θέλουν προσοχή
ADMIN = {22: "SSH", 80: "σελίδα διαχείρισης (HTTP)", 443: "σελίδα διαχείρισης (HTTPS)", 8080: "σελίδα διαχείρισης (HTTP)",
         8443: "σελίδα διαχείρισης (HTTPS)", 5000: "NAS / UPnP", 5001: "NAS (HTTPS)", 8009: "Chromecast", 9000: "υπηρεσία web"}
HIGH_TYPES = ("camera",)
MED_TYPES = ("iot", "esp", "tv", "speaker", "nas", "printer", "pi")
EXPECTED_TYPES = ("console",)


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not a.is_loopback and not a.is_multicast and not a.is_unspecified


def _safe_xml(raw):
    """XML από συσκευή του LAN: όριο μεγέθους, όχι DOCTYPE/ENTITY (billion laughs/XXE)."""
    if len(raw) > MAX_XML:
        raise ValueError("πολύ μεγάλο XML")
    txt = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    if re.search(r"<!(DOCTYPE|ENTITY)", txt, re.I):
        raise ValueError("XML με DOCTYPE — δεν το διαβάζω")
    return ET.fromstring(txt)


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _find_all(root, name):
    return [e for e in root.iter() if _local(e.tag) == name]


def _text(el, name):
    for e in el.iter():
        if _local(e.tag) == name:
            return (e.text or "").strip()
    return ""


def parse_ssdp(data):
    """Απάντηση SSDP → dict επικεφαλίδων (πεζά)."""
    txt = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
    out = {}
    for line in txt.split("\r\n")[1:]:
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip().lower()] = v.strip()
    return out


def location_ok(loc, ip):
    """Το LOCATION πρέπει να είναι http:// στην ΙΔΙΑ ιδιωτική IP που απάντησε (όχι αλλού)."""
    try:
        u = urllib.parse.urlsplit(loc)
    except ValueError:
        return False
    return u.scheme == "http" and u.hostname == ip and is_private(ip)


def control_url(desc_xml, location):
    """Περιγραφή IGD → (serviceType, controlURL) για WANIPConnection/WANPPPConnection, στην ίδια IP."""
    root = _safe_xml(desc_xml)
    base = _text(root, "URLBase") or location
    found = {}
    for s in _find_all(root, "service"):
        st, cu = _text(s, "serviceType"), _text(s, "controlURL")
        if st in SERVICES and cu:
            found.setdefault(st, cu)
    for st in SERVICES:
        if st in found:
            url = urllib.parse.urljoin(base, found[st])
            if urllib.parse.urlsplit(url).hostname != urllib.parse.urlsplit(location).hostname:
                return None
            return st, url
    return None


def soap_body(service, action, args):
    a = "".join(f"<{k}>{v}</{k}>" for k, v in args.items())
    return ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service}">{a}</u:{action}></s:Body></s:Envelope>').encode()


FIELDS = ("NewRemoteHost", "NewExternalPort", "NewProtocol", "NewInternalPort", "NewInternalClient", "NewEnabled",
          "NewPortMappingDescription", "NewLeaseDuration")


def parse_entry(resp_xml):
    root = _safe_xml(resp_xml)
    d = {f: _text(root, f) for f in FIELDS}
    try:
        ext, inte = int(d["NewExternalPort"]), int(d["NewInternalPort"] or 0)
    except ValueError:
        return None
    return {"ext": ext, "int": inte, "proto": (d["NewProtocol"] or "").upper()[:4], "client": d["NewInternalClient"][:45],
            "remote": d["NewRemoteHost"][:45], "enabled": d["NewEnabled"] not in ("0", "false"),
            "desc": re.sub(r"[\x00-\x1f]", " ", d["NewPortMappingDescription"])[:80],
            "lease": int(d["NewLeaseDuration"]) if d["NewLeaseDuration"].isdigit() else 0}


class Net:
    """Τα πραγματικά πακέτα (μόνο τοπικό LAN)."""

    def discover(self, timeout=3.0):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(0.5)
        out = []
        try:
            for st in STS:
                msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
                       f"MX: 2\r\nST: {st}\r\n\r\n").encode()
                s.sendto(msg, SSDP)
            end = time.time() + timeout
            while time.time() < end:
                try:
                    data, (ip, _port) = s.recvfrom(4096)
                except socket.timeout:
                    continue
                out.append((ip, data))
        finally:
            s.close()
        return out

    def _req(self, url, method="GET", body=None, headers=None):
        u = urllib.parse.urlsplit(url)
        if u.scheme != "http" or not is_private(u.hostname or ""):
            raise ValueError("μόνο http σε ιδιωτική IP")
        c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=5)  # nosec — μόνο το router στο LAN
        try:
            c.request(method, (u.path or "/") + ("?" + u.query if u.query else ""), body=body, headers=headers or {})
            r = c.getresponse()  # δεν ακολουθούμε redirects
            return r.status, r.read(MAX_XML + 1)
        finally:
            c.close()

    def get(self, url):
        return self._req(url)

    def soap(self, url, service, action, args):
        return self._req(url, "POST", soap_body(service, action, args),
                         {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service}#{action}"'})


def risk(m, dev):
    """→ (επίπεδο high/med/low, γιατί)."""
    dt = (dev or {}).get("dtype") or ""
    port = m.get("int") or m.get("ext")
    if dt in HIGH_TYPES:
        return "high", "Κάμερα ανοιχτή προς το Internet — οι κάμερες είναι ο πρώτος στόχος των botnets (Mirai)."
    if port in DANGER or m.get("ext") in DANGER:
        return "high", f"Θύρα {DANGER.get(port) or DANGER.get(m.get('ext'))} — δεν πρέπει ποτέ να είναι ανοιχτή προς το Internet."
    if dt in MED_TYPES:
        return "med", "Έξυπνη συσκευή (IoT) ανοιχτή προς το Internet — σπάνια χρειάζεται· οι εφαρμογές τους δουλεύουν και χωρίς."
    if port in ADMIN or m.get("ext") in ADMIN:
        return "med", f"Θύρα διαχείρισης ({ADMIN.get(port) or ADMIN.get(m.get('ext'))}) ανοιχτή προς το Internet."
    if not dev:
        return "med", "Η IP δεν είναι συσκευή που έχω δει στο δίκτυο — έλεγξε ποια είναι."
    if dt in EXPECTED_TYPES:
        return "low", "Κονσόλα: ανοίγει θύρες για online παιχνίδι — συνήθως εντάξει."
    return "low", "Συνήθως παιχνίδια, torrent ή κλήσεις βίντεο. Εντάξει αν ξέρεις ποιο πρόγραμμα το ζήτησε."


def mkey(m):
    return f"{m['proto']}/{m['ext']}->{m['client']}:{m['int']}"


DEMO = {"router": "192.168.1.1", "server": "Linux/3.4 UPnP/1.0 MiniUPnPd/2.1", "service": "WANIPConnection:1", "mappings": [
    {"ext": 554, "int": 554, "proto": "TCP", "client": "192.168.1.30", "remote": "", "enabled": True, "desc": "IPCAM RTSP", "lease": 0},
    {"ext": 8000, "int": 80, "proto": "TCP", "client": "192.168.1.30", "remote": "", "enabled": True, "desc": "IPCAM HTTP", "lease": 0},
    {"ext": 8009, "int": 8009, "proto": "TCP", "client": "192.168.1.10", "remote": "", "enabled": True, "desc": "SmartTV cast", "lease": 3600},
    {"ext": 51413, "int": 51413, "proto": "UDP", "client": "192.168.1.23", "remote": "", "enabled": True, "desc": "qBittorrent", "lease": 0},
    {"ext": 51413, "int": 51413, "proto": "TCP", "client": "192.168.1.23", "remote": "", "enabled": True, "desc": "qBittorrent", "lease": 0}]}


class UpnpWatch:
    def __init__(self, state, data_dir=None, demo=False, net=None, clock=time.time):
        self.state, self.demo, self.clock = state, demo, clock
        self.net = net or Net()
        self.path = os.path.join(data_dir, "upnp.json") if data_dir else None
        self.lock = threading.Lock()
        self.busy = False
        self.res = None        # τελευταίο αποτέλεσμα (router, mappings, error)
        self.known = {}        # κλειδί → πρώτη φορά που το είδαμε
        self.scanned = 0
        if not demo:
            self._load()

    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                j = json.load(f)
            self.known = {str(k): float(v) for k, v in (j.get("known") or {}).items()}
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save(self):
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"known": self.known}, f)
            os.replace(tmp, self.path)
        except OSError:
            pass

    # ── σάρωση ──
    def _gateway(self):
        return getattr(self.state, "gateway", None) if self.state is not None else None

    def scan(self):
        """→ {"router", "server", "service", "mappings", "error"} — μόνο ανάγνωση."""
        if self.demo:
            return dict(DEMO, mappings=[dict(m) for m in DEMO["mappings"]], error=None)
        gw = self._gateway()
        cands = []
        for ip, data in self.net.discover():
            if not is_private(ip):
                continue
            h = parse_ssdp(data)
            loc = h.get("location", "")
            if location_ok(loc, ip) and (ip, loc) not in [(c[0], c[1]) for c in cands]:
                cands.append((ip, loc, h.get("server", "")[:120]))
        if not cands:
            return {"router": None, "mappings": [], "error": None}
        cands.sort(key=lambda c: c[0] != gw)  # πρώτα το gateway
        last_err = None
        for ip, loc, server in cands:
            try:
                st, raw = self.net.get(loc)
                if st != 200:
                    raise ValueError(f"HTTP {st}")
                cu = control_url(raw, loc)
                if not cu:
                    continue
                service, url = cu
                maps = []
                for i in range(MAX_ENTRIES):
                    st, raw = self.net.soap(url, service, "GetGenericPortMappingEntry", {"NewPortMappingIndex": i})
                    if st != 200:
                        break  # 713 SpecifiedArrayIndexInvalid = τέλος πίνακα
                    m = parse_entry(raw)
                    if m:
                        maps.append(m)
                return {"router": ip, "server": server, "service": service.rsplit(":", 2)[-2] + ":" + service.rsplit(":", 1)[-1],
                        "mappings": maps, "error": None}
            except Exception as e:  # noqa: BLE001 — συσκευή του LAN που απαντά περίεργα
                last_err = str(e)[:160]
        return {"router": cands[0][0], "server": cands[0][2], "mappings": [],
                "error": ("Βρήκα UPnP router αλλά δεν μπόρεσα να διαβάσω τον πίνακα: " + last_err) if last_err else None,
                "noread": True}

    def refresh(self):
        with self.lock:
            if self.busy:
                return self.view()
            self.busy = True
        try:
            r = self.scan()
            now = self.clock()
            first = not self.known and not self.demo
            fresh = []
            for m in r.get("mappings") or []:
                k = mkey(m)
                if k not in self.known:
                    self.known[k] = now
                    fresh.append(m)
            self.res, self.scanned = r, now
            self._alert(fresh, first, now)
            self._save()
        except Exception as e:  # noqa: BLE001
            self.res, self.scanned = {"router": None, "mappings": [], "error": "Ο έλεγχος UPnP απέτυχε: " + str(e)[:160]}, self.clock()
        finally:
            self.busy = False
        return self.view()

    def _alert(self, fresh, first, now):
        st = self.state
        if self.demo or st is None or not hasattr(st, "alert"):
            return
        devs = self._devices()
        for m in fresh:
            if not m.get("enabled"):
                continue
            lvl, why = risk(m, devs.get(m["client"]))
            if first and lvl != "high":
                continue  # πρώτη σάρωση: μόνο τα σοβαρά — τα υπόλοιπα τα βλέπεις στην καρτέλα
            name = (devs.get(m["client"]) or {}).get("name") or m["client"]
            st.alert("Άνοιξε θύρα στο router (UPnP)", lvl, m["client"], f"{m['proto']} {m['ext']}",
                     f"Η συσκευή {name} ζήτησε από το router να ανοίξει τη θύρα {m['proto']} {m['ext']} προς το Internet"
                     + (f" («{m['desc']}»)" if m.get("desc") else "") + ". " + why,
                     now, key=("upnp", mkey(m)), cooldown=24 * 3600, mark=False)

    # ── προβολή ──
    def _devices(self):
        st = self.state
        out = {}
        if st is None:
            return out
        lock = getattr(st, "lock", None)
        try:
            if lock:
                lock.acquire()
            hosts = [h for h in (getattr(st, "hosts", None) or {}).values() if h.get("kind") == "local"]
        finally:
            if lock:
                lock.release()
        for h in hosts:
            try:
                dt = st._dtype(h) if hasattr(st, "_dtype") else {}
            except Exception:  # noqa: BLE001
                dt = {}
            names = sorted(h.get("names") or ())
            out[h.get("ip")] = {"name": dt.get("alias") or (names[0] if names else h.get("rdns") or h.get("ip")),
                                "dtype": dt.get("dtype") or "", "dicon": dt.get("dicon") or "", "vendor": dt.get("vendor") or "",
                                "me": bool(h.get("me"))}
        return out

    def view(self):
        r = self.res or {}
        devs = self._devices()
        rows = []
        for m in r.get("mappings") or []:
            d = devs.get(m["client"])
            lvl, why = risk(m, d)
            rows.append({**m, "level": lvl if m.get("enabled") else "off", "why": why, "dev": d,
                         "since": self.known.get(mkey(m)), "anyone": not m.get("remote") or m.get("remote") in ("*", "0.0.0.0")})
        order = {"high": 0, "med": 1, "low": 2, "off": 3}
        rows.sort(key=lambda x: (order.get(x["level"], 4), x["client"], x["ext"]))
        return {"demo": self.demo, "busy": self.busy, "scanned": self.scanned or (self.clock() if self.demo and self.res else 0),
                "router": r.get("router"), "server": r.get("server"), "service": r.get("service"), "error": r.get("error"),
                "noread": bool(r.get("noread")), "mappings": rows,
                "counts": {k: sum(1 for x in rows if x["level"] == k) for k in ("high", "med", "low")}}

    def run_forever(self):
        time.sleep(45)
        while True:
            try:
                self.refresh()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(EVERY)
