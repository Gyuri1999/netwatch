"""🧩 Οι συσκευές μου: αισθητήρες (ESP32, Raspberry Pi, υπολογιστές) που στέλνουν αναφορές στο NetWatch.

Ένα κοινό «πρωτόκολλο αισθητήρα» για όλα:
  POST https://<NetWatch>:8790/probe/v1/report      Authorization: Bearer <token>
  {"status": {"fw", "hw", "ip", "mac", "uptime", "heap", "rssi", "batt", "temp", "hum", "interval", "metrics", "link"},
   "events": [{"type": "vlan_leak" | "outage" | "dhcp_rogue" | "temp_high" | "door_open" | …, "detail": "…", "data": {…}}]}

Ασφάλεια:
  • Ξεχωριστή θύρα μόνο για αισθητήρες (όχι το UI), HTTPS με το self-signed πιστοποιητικό του NetWatch.
    Ο αισθητήρας ελέγχει το αποτύπωμα SHA-256 (pinning) — το παίρνει στη σύζευξη.
  • Κάθε συσκευή έχει δικό της τυχαίο token· κρατάμε ΜΟΝΟ το SHA-256 του. Το token φαίνεται μία φορά (κωδικός/QR).
  • Μόνο από ιδιωτικές IP, όριο μεγέθους (16 KB) και ρυθμού, μόνο γνωστοί τύποι γεγονότων γίνονται ειδοποιήσεις.
  • Η θύρα ανοίγει μόνο όταν το ενεργοποιήσεις (ή στην πρώτη σύζευξη).
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import qr

PORT = 8790  # έξω από τις 8765–8784 που δοκιμάζει το UI
MAX_BODY = 16 * 1024
MAX_PROBES = 64
RATE = 60  # αιτήματα / λεπτό / IP
ID_RX = re.compile(r"^p-[0-9a-f]{6,12}$")

KINDS = {  # τι μπορείς να συνδέσεις — «ready» = υπάρχει έτοιμο λογισμικό
    "pc": {"icon": "💻", "title": "Υπολογιστής ή Raspberry Pi", "hw": "Οποιοδήποτε Linux/Mac/Windows με Python 3 — π.χ. Pi Zero 2 W",
           "price": "0 € (ό,τι έχεις)", "ready": True,
           "what": "Αναφέρει ότι είναι ζωντανός, IP, φόρτο, και αν «βλέπει» το router — έτσι μαθαίνεις για διακοπές σε άλλο δωμάτιο ή VLAN."},
    "vlan": {"icon": "🧱", "title": "Αισθητήρας VLAN (ESP32)", "hw": "Οποιοδήποτε ESP32", "price": "~5 €", "ready": False,
             "what": "Από το Wi-Fi επισκεπτών/IoT ελέγχει αν φτάνει στο κύριο δίκτυο — αν ναι, χάλασε ο διαχωρισμός."},
    "field": {"icon": "🔌", "title": "Tester τσέπης", "hw": "Pi Zero 2 W + USB-Ethernet ή Olimex ESP32-POE", "price": "~25 €",
              "ready": False, "what": "Βάζεις καλώδιο → switch, θύρα, VLAN, DHCP, PoE, internet σε δευτερόλεπτα."},
    "wifi": {"icon": "📶", "title": "Κάλυψη Wi-Fi (ESP32)", "hw": "ESP32 ανά δωμάτιο", "price": "~5 € / δωμάτιο", "ready": False,
             "what": "Σήμα του router και πόσο γεμάτο είναι το κανάλι, ανά δωμάτιο."},
    "rack": {"icon": "🌡", "title": "Rack: θερμοκρασία & πόρτα", "hw": "ESP32 + BME280 + μαγνητική επαφή", "price": "~10 €",
             "ready": False, "what": "Ζέστη/υγρασία στο ντουλάπι δικτύου και ποιος άνοιξε την πόρτα του."},
    "sentinel": {"icon": "📡", "title": "Sentinel: ασφάλεια Wi-Fi (ESP32)", "hw": "ESP32 + Mosquitto (MQTT/TLS)", "price": "~5 €",
                 "ready": True, "mqtt": True, "what": "Deauth flood, evil twin, ψεύτικα access points — καρτέλα 📡 Αισθητήρες."},
    "canary": {"icon": "🍯", "title": "Canary: ψεύτικη κάμερα-παγίδα (ESP32)", "hw": "ESP32 + Mosquitto (MQTT/TLS)", "price": "~5 €",
               "ready": True, "mqtt": True, "what": "Όποιος της μιλήσει σκανάρει το δίκτυό σου — καρτέλα 📡 Αισθητήρες."},
}
PAIRABLE = ("pc", "vlan", "field", "wifi", "rack")

EVENTS = {  # γεγονός αισθητήρα → (τίτλος ειδοποίησης, σοβαρότητα)· άγνωστα μένουν μόνο στο ιστορικό
    "vlan_leak": ("Διαρροή διαχωρισμού VLAN (αισθητήρας)", "high"),
    "outage": ("Διακοπή δικτύου (αισθητήρας)", "med"),
    "dhcp_rogue": ("Δεύτερος DHCP server (αισθητήρας)", "high"),
    "temp_high": ("Υψηλή θερμοκρασία στο rack (αισθητήρας)", "med"),
    "door_open": ("Άνοιξε η πόρτα του rack (αισθητήρας)", "med"),
}
STATUS_NUM = ("uptime", "heap", "rssi", "batt", "temp", "hum", "interval")
STATUS_TXT = ("fw", "hw", "ip", "mac", "os")


def _txt(x, n=60):
    return "".join(c for c in str(x if x is not None else "") if c.isprintable())[:n]


def _num(x):
    if isinstance(x, bool) or not isinstance(x, (int, float)) or x != x or abs(x) > 1e12:
        return None
    return x


def _flat(d, n=20):
    """Μικρό λεξικό από απλές τιμές (για metrics/link)."""
    if not isinstance(d, dict):
        return {}
    out = {}
    for k, v in list(d.items())[:n]:
        k = re.sub(r"[^A-Za-z0-9_]", "", str(k))[:24]
        if not k:
            continue
        if isinstance(v, bool):
            out[k] = v
        elif _num(v) is not None:
            out[k] = v
        elif isinstance(v, str):
            out[k] = _txt(v, 60)
    return out


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback) and not a.is_multicast


def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def make_code(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return "NW1." + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def read_code(code):
    """Κωδικός σύζευξης → dict (για τον πελάτη/αισθητήρα και τα tests)."""
    code = str(code or "").strip()
    if not code.startswith("NW1."):
        raise ValueError("Δεν είναι κωδικός σύζευξης NetWatch (NW1.…)")
    b = code[4:]
    return json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)))


class Probes:
    def __init__(self, state, data_dir=None, demo=False, port=PORT, clock=time.time, on_save=None, cert=None):
        self.state, self.demo, self.clock, self.on_save = state, demo, clock, on_save
        self.data_dir = data_dir
        self.path = os.path.join(data_dir, "probes.json") if data_dir else None
        self.port = port
        self.cert = cert  # (crt, key, fp) — αλλιώς φτιάχνεται στο data_dir όταν ανοίξει η θύρα
        self.lock = threading.RLock()
        self.reg = {}         # id → {name, kind, hash, created}
        self.live = {}        # id → {status, seen, from, events[], offline_alerted}
        self.enabled = False
        self.srv, self.error = None, None
        self.rate = {}
        if demo:
            self._demo_seed()
        else:
            self._load()

    # ── αποθήκευση ──
    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                j = json.load(f)
            self.enabled = bool(j.get("enabled"))
            for pid, p in (j.get("probes") or {}).items():
                if ID_RX.match(pid) and isinstance(p, dict) and re.match(r"^[0-9a-f]{64}$", str(p.get("hash", ""))):
                    self.reg[pid] = {"name": _txt(p.get("name"), 40) or pid, "kind": p.get("kind") if p.get("kind") in KINDS else "pc",
                                     "hash": p["hash"], "created": float(p.get("created") or 0)}
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save(self):
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"enabled": self.enabled, "probes": self.reg}, f)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    # ── σύζευξη ──
    def _urls(self):
        st = self.state
        ips = sorted(ip for ip in (getattr(st, "me", None) or ()) if ":" not in ip and is_private(ip) and not ip.startswith("127."))
        return [f"https://{ip}:{self.port}" for ip in ips]

    def pair(self, name, kind):
        kind = kind if kind in PAIRABLE else None
        if not kind:
            return {"error": "Άγνωστος τύπος συσκευής."}
        name = _txt(name, 40).strip() or KINDS[kind]["title"]
        with self.lock:
            if len(self.reg) >= MAX_PROBES:
                return {"error": f"Έως {MAX_PROBES} συσκευές."}
            if not self.demo and not self.enabled:
                r = self.set_enabled(True)
                if r.get("error"):
                    return r
            pid = "p-" + secrets.token_hex(4)
            token = secrets.token_urlsafe(24)
            self.reg[pid] = {"name": name, "kind": kind, "hash": _h(token), "created": self.clock()}
            self._save()
        fp = self.fingerprint()
        payload = {"v": 1, "id": pid, "n": name, "k": kind, "u": self._urls() or ["https://192.168.1.23:%d" % self.port], "fp": fp, "t": token}
        code = make_code(payload)
        return {"ok": True, "id": pid, "name": name, "kind": kind, "code": code, "qr": qr.svg(code, scale=4), "urls": payload["u"], "fp": fp}

    def remove(self, pid):
        with self.lock:
            if pid not in self.reg:
                return {"error": "Δεν υπάρχει."}
            del self.reg[pid]
            self.live.pop(pid, None)
            self._save()
        return {"ok": True}

    def rename(self, pid, name):
        name = _txt(name, 40).strip()
        with self.lock:
            if pid not in self.reg or not name:
                return {"error": "Δεν υπάρχει."}
            self.reg[pid]["name"] = name
            self._save()
        return {"ok": True}

    # ── αναφορές ──
    def _find(self, token):
        if not token or len(token) > 100:
            return None
        h = _h(token)
        found = None
        for pid, p in self.reg.items():
            if hmac.compare_digest(p["hash"], h):
                found = pid
        return found

    def _limited(self, ip, now):
        w = [t for t in self.rate.get(ip, []) if now - t < 60]
        w.append(now)
        self.rate[ip] = w[-RATE - 1:]
        if len(self.rate) > 1000:
            self.rate = {k: v for k, v in self.rate.items() if v and now - v[-1] < 60}
        return len(w) > RATE

    def report(self, token, ip, body):
        """→ (http status, απάντηση). Καλείται από τη θύρα αισθητήρων."""
        now = self.clock()
        if not is_private(ip):
            return 403, {"error": "forbidden"}
        with self.lock:
            if self._limited(ip, now):
                return 429, {"error": "slow down"}
            pid = self._find(token)
            if not pid:
                return 401, {"error": "unauthorized"}
            try:
                j = json.loads(body)
            except (ValueError, TypeError):
                return 400, {"error": "bad json"}
            if not isinstance(j, dict):
                return 400, {"error": "bad json"}
            s = j.get("status") if isinstance(j.get("status"), dict) else {}
            st = {k: _num(s.get(k)) for k in STATUS_NUM if _num(s.get(k)) is not None}
            st.update({k: _txt(s.get(k), 60) for k in STATUS_TXT if s.get(k) is not None})
            if "interval" in st:
                st["interval"] = max(10, min(3600, int(st["interval"])))
            st["metrics"], st["link"] = _flat(s.get("metrics")), _flat(s.get("link"))
            lv = self.live.setdefault(pid, {"events": []})
            back = lv.get("offline_alerted")
            lv.update(status=st, seen=now, frm=ip, offline_alerted=False)
            evs = j.get("events") if isinstance(j.get("events"), list) else []
            fresh = []
            for e in evs[:10]:
                if not isinstance(e, dict):
                    continue
                typ = re.sub(r"[^a-z0-9_]", "", str(e.get("type", "")).lower())[:24]
                if not typ:
                    continue
                ev = {"t": now, "type": typ, "detail": _txt(e.get("detail"), 200), "data": _flat(e.get("data"), 12)}
                lv["events"].append(ev)
                fresh.append(ev)
            del lv["events"][:-50]
            name, kind = self.reg[pid]["name"], self.reg[pid]["kind"]
        for ev in fresh:
            self._alert(pid, name, ip, ev)
        if back:
            self._event_note(pid, "Ο αισθητήρας επανήλθε.")
        return 200, {"ok": True, "name": name, "kind": kind, "interval": st.get("interval", 60)}

    def _event_note(self, pid, txt):
        with self.lock:
            lv = self.live.get(pid)
            if lv is not None:
                lv["events"].append({"t": self.clock(), "type": "note", "detail": txt, "data": {}})
                del lv["events"][:-50]

    def _alert(self, pid, name, ip, ev):
        st = self.state
        m = EVENTS.get(ev["type"])
        if not m or st is None or not hasattr(st, "alert"):
            return
        typ, sev = m
        actor = ev["data"].get("src") if isinstance(ev["data"].get("src"), str) and is_private(ev["data"].get("src")) else ip
        st.alert(typ, sev, actor, f"αισθητήρας {name}", ev["detail"] or typ, ev["t"],
                 key=("probe", pid, ev["type"]), cooldown=600, mark=False)

    def check_offline(self):
        """Αισθητήρας που χάθηκε (3× το διάστημά του, τουλάχιστον 3′) → μία ειδοποίηση."""
        now = self.clock()
        late = []
        with self.lock:
            for pid, lv in self.live.items():
                if pid not in self.reg or lv.get("offline_alerted"):
                    continue
                iv = (lv.get("status") or {}).get("interval", 60)
                if now - lv.get("seen", now) > max(180, 3 * iv):
                    lv["offline_alerted"] = True
                    late.append((pid, self.reg[pid]["name"], lv.get("frm") or "?"))
        for pid, name, ip in late:
            self._event_note(pid, "Ο αισθητήρας σταμάτησε να στέλνει.")
            if self.state is not None and hasattr(self.state, "alert"):
                self.state.alert("Αισθητήρας εκτός σύνδεσης", "low", ip, name,
                                 f"Ο αισθητήρας «{name}» δεν έχει στείλει αναφορά εδώ και λίγα λεπτά — ρεύμα, Wi-Fi ή καλώδιο;",
                                 now, key=("probe-off", pid), cooldown=3600, mark=False)

    # ── θύρα αισθητήρων ──
    def fingerprint(self):
        if self.demo:
            return "DE:MO:" + ":".join(["00"] * 30)
        try:
            return self._cert()[2]
        except Exception as e:  # noqa: BLE001
            self.error = "Δεν μπόρεσα να φτιάξω πιστοποιητικό: " + str(e)[:120]
            return None

    def _cert(self):
        if not self.cert:
            import agent
            self.cert = agent.ensure_cert(self.data_dir or ".", cn="netwatch-probes")
        return self.cert

    def set_enabled(self, on):
        with self.lock:
            self.enabled = bool(on)
            self._save()
        if self.demo:
            return self.view()
        if on:
            self.start()
        else:
            self.stop()
        return {"error": self.error} if on and self.error else self.view()

    def start(self):
        if self.demo or not self.enabled or self.srv:
            return
        try:
            crt, key, _fp = self._cert()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(crt, key)
            srv = _ProbeServer(("0.0.0.0", self.port), _handler(self))  # nosec — μόνο /probe/v1/report με token
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            self.srv, self.error = srv, None
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        except OSError as e:
            self.error = f"Δεν άνοιξε η θύρα {self.port}: {e.strerror or e}"
        except Exception as e:  # noqa: BLE001
            self.error = "Η θύρα αισθητήρων δεν ξεκίνησε: " + str(e)[:120]

    def stop(self):
        srv, self.srv = self.srv, None
        if srv:
            threading.Thread(target=lambda: (srv.shutdown(), srv.server_close()), daemon=True).start()

    # ── προβολή ──
    def view(self):
        now = self.clock()
        if self.demo:
            self._demo_tick(now)
        out = []
        with self.lock:
            for pid, p in self.reg.items():
                lv = self.live.get(pid) or {}
                st = lv.get("status") or {}
                iv = st.get("interval", 60)
                seen = lv.get("seen")
                state = "waiting" if not seen else "online" if now - seen <= max(90, 2.5 * iv) else "offline"
                out.append({"id": pid, "name": p["name"], "kind": p["kind"], "created": p["created"], "state": state,
                            "seen": seen, "ip": lv.get("frm"), "status": st, "events": (lv.get("events") or [])[-8:][::-1]})
        out.sort(key=lambda x: ({"offline": 0, "online": 1, "waiting": 2}[x["state"]], x["name"].lower()))
        mq = []
        sb = getattr(self.state, "sensor", None) if self.state is not None else None
        if sb:
            try:
                s = sb.status()
                mq = [{"id": x.get("id"), "kind": "canary" if x.get("kind") == "canary" else "sentinel", "online": x.get("online"),
                       "ip": x.get("ip"), "fw": x.get("fw"), "ago": x.get("ago"), "rssi": x.get("rssi")} for x in s.get("sensors") or []]
            except Exception:  # noqa: BLE001
                mq = []
        return {"demo": self.demo, "enabled": self.enabled, "listening": bool(self.srv) or (self.demo and self.enabled),
                "port": self.port, "urls": self._urls(), "fp": self.fingerprint() if (self.enabled or self.demo) else None,
                "error": self.error, "probes": out, "mqtt": mq, "kinds": KINDS, "pairable": list(PAIRABLE),
                "counts": {"total": len(out) + len(mq), "online": sum(1 for x in out if x["state"] == "online") + sum(1 for x in mq if x["online"])}}

    def run_forever(self):
        while True:
            time.sleep(30)
            try:
                self.check_offline()
            except Exception:  # noqa: BLE001
                pass

    # ── demo ──
    def _demo_seed(self):
        self.enabled = True
        t = self.clock()
        for pid, name, kind in (("p-a1b2c3", "Pi Zero · γραφείο", "pc"), ("p-d4e5f6", "ESP32 · Wi-Fi επισκεπτών", "vlan"),
                                ("p-0a0b0c", "ESP32 · rack", "rack")):
            self.reg[pid] = {"name": name, "kind": kind, "hash": _h(pid), "created": t - 86400 * 3}
        self.live["p-d4e5f6"] = {"events": [
            {"t": t - 7200, "type": "vlan_check", "detail": "Το Wi-Fi επισκεπτών ΔΕΝ φτάνει στο 192.168.1.0/24 ✔", "data": {}}]}
        self.live["p-0a0b0c"] = {"events": [
            {"t": t - 5400, "type": "door_open", "detail": "Άνοιξε η πόρτα του rack", "data": {}}]}

    def _demo_tick(self, now):
        import random
        with self.lock:
            self.live.setdefault("p-a1b2c3", {"events": []}).update(seen=now - random.randint(5, 40), frm="192.168.1.60", status={
                "fw": "1.0.0", "hw": "Raspberry Pi Zero 2 W", "os": "Raspberry Pi OS 12", "ip": "192.168.1.60", "uptime": 86400 * 2 + int(now) % 3600,
                "interval": 60, "temp": 46.2, "metrics": {"gw_ms": round(random.uniform(1.2, 3.5), 1), "load": 0.08, "mem_free_mb": 212}, "link": {}})
            self.live["p-d4e5f6"].update(seen=now - random.randint(5, 50), frm="192.168.50.12", status={
                "fw": "0.9.0", "hw": "ESP32-C3", "ip": "192.168.50.12", "uptime": 86400 + int(now) % 3600, "heap": 182000,
                "rssi": random.randint(-66, -58), "interval": 60, "metrics": {"lan_reachable": False, "gw_ms": 4.1}, "link": {}})
            self.live["p-0a0b0c"].update(seen=now - 900, frm="192.168.1.61", status={
                "fw": "0.9.0", "hw": "ESP32 + BME280", "ip": "192.168.1.61", "uptime": 3600 * 5, "heap": 190000, "rssi": -71,
                "temp": 31.5, "hum": 38, "interval": 60, "metrics": {"door": "closed"}, "link": {}})


class _ProbeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False  # macOS/BSD: με SO_REUSEADDR το 0.0.0.0 «μοιράζεται» θύρα με άλλο 127.0.0.1 — όχι


def _handler(probes):
    class H(BaseHTTPRequestHandler):
        timeout = 10
        server_version = "NetWatch-probe"
        sys_version = ""

        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path == "/probe/v1/ping":
                return self._send(200, {"ok": True, "app": "NetWatch"})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/probe/v1/report":
                return self._send(404, {"error": "not found"})
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                return self._send(413, {"error": "too large"})
            auth = self.headers.get("Authorization", "")
            tok = auth[7:].strip() if auth.startswith("Bearer ") else ""
            body = self.rfile.read(n)
            code, obj = probes.report(tok, self.client_address[0], body)
            self._send(code, obj)

    return H
