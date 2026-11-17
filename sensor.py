"""Γέφυρα για τους αισθητήρες ESP32 «NetWatch Sentinel» (firmware/esp32-sentinel).

Οι αισθητήρες στέλνουν σε ένα MQTT broker (π.χ. Mosquitto στο Raspberry Pi, με TLS):
  netwatch/sensor/<id>/status  (retained) heartbeat: {"id","online","fw","uptime","heap","rssi","ip","deauth_total","twins_total"}
  netwatch/sensor/<id>/event   {"type":"deauth"|"evil_twin"|"rogue_ap", ...}
Το NetWatch κάνει subscribe και μετατρέπει τα events σε ειδοποιήσεις.
Ο αισθητήρας κόβει το MQTT όσο «ακούει» τον αέρα, άρα θεωρείται offline μόνο αν λείπει heartbeat για > 90″.
"""
import json
import os
import random
import re
import ssl
import threading
import time

OFFLINE_AFTER = 90
TOPIC_RX = re.compile(r"^netwatch/sensor/([A-Za-z0-9_-]{1,40})/(status|event)$")
MAC_RX = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
SEC_WEAK = {"open", "owe", "wep", "wpa"}


def clean_mac(x):
    x = str(x or "").lower()
    return x if MAC_RX.match(x) else "?"


def clean_txt(x, n=40):
    return "".join(c for c in str(x or "") if c.isprintable())[:n]


def to_alert(ev):
    """Event αισθητήρα → (τύπος, σοβαρότητα, λεπτομέρειες, key) ή None. Καθαρή συνάρτηση (tests)."""
    sid = clean_txt(ev.get("id"), 40)
    t = ev.get("type")
    ch = ev.get("channel")
    ch = int(ch) if isinstance(ch, (int, float)) and 0 < ch < 200 else "?"
    rssi = ev.get("rssi") if isinstance(ev.get("rssi"), (int, float)) else None
    near = f", σήμα {int(rssi)} dBm{' (πολύ κοντά!)' if rssi is not None and rssi > -50 else ''}" if rssi is not None else ""
    if t == "deauth":
        n = int(ev.get("count") or 0)
        bc = clean_mac(ev.get("target")) == "ff:ff:ff:ff:ff:ff"
        return ("Deauth επίθεση στο Wi‑Fi", "high",
                f"Ο αισθητήρας {sid} μέτρησε {n} πακέτα αποσύνδεσης/δευτ. στο κανάλι {ch} από {clean_mac(ev.get('bssid'))}"
                f"{' προς ΟΛΟΥΣ (broadcast)' if bc else ' προς ' + clean_mac(ev.get('target'))}{near}. "
                "Κάποιος «πετάει» συσκευές από το Wi‑Fi — συχνά για να τις σπρώξει σε ψεύτικο δίκτυο ή να πιάσει το handshake.",
                f"deauth:{sid}:{ch}")
    if t == "canary":
        import ipaddress
        src = str(ev.get("src") or "?")
        try:
            ipaddress.ip_address(src)
        except ValueError:
            src = "?"
        port = ev.get("port") if isinstance(ev.get("port"), int) and 0 < ev.get("port") < 65536 else "?"
        svc, data, user = clean_txt(ev.get("service"), 12), clean_txt(ev.get("data"), 80), clean_txt(ev.get("user"), 40)
        return ("Καναρίνι ESP32", "high",
                f"Η {src} άγγιξε το ψεύτικο {svc or 'service'} (θύρα {port}) του καναρινιού {sid}"
                f"{' — δοκίμασε χρήστη «' + user + '»' if user else ''}{' — έστειλε: ' + data if data else ''}. "
                "Κανείς νόμιμος δεν έχει λόγο να συνδεθεί εκεί: η συσκευή σκανάρει ή δοκιμάζει κωδικούς.",
                f"canary:{sid}:{src}", src)
    if t == "ota":  # αποτέλεσμα υπογεγραμμένου OTA (firmware/common/signed_ota)
        res, why = clean_txt(ev.get("result"), 12), clean_txt(ev.get("reason"), 80)
        ver, fw = clean_txt(ev.get("version"), 16), clean_txt(ev.get("fw"), 16)
        if res == "rejected":  # κακή υπογραφή / sha256 / rollback: κάποιος πείραξε τον OTA server ή το δίκτυο
            return ("OTA απορρίφθηκε", "high",
                    f"Ο {sid} αρνήθηκε ενημέρωση firmware {ver or '?'} ({why or 'χωρίς λόγο'}) και μένει στην {fw or '?'}. "
                    "Αν δεν έκανες εσύ κάτι λάθος στην υπογραφή, κάποιος σερβίρει πειραγμένο firmware: έλεγξε τον OTA server.",
                    f"ota:{sid}:{ver}")
        if res == "updated":
            return ("OTA ενημέρωση", "low", f"Ο {sid} ενημερώθηκε και επιβεβαίωσε ότι δουλεύει: {why or fw}.", f"ota:{sid}:{fw}")
        return None  # up_to_date / error (δίκτυο) — φαίνονται στην κατάσταση, όχι ειδοποίηση
    if t in ("evil_twin", "rogue_ap"):
        ssid, sec, bssid = clean_txt(ev.get("ssid"), 32), clean_txt(ev.get("security"), 12), clean_mac(ev.get("bssid"))
        if t == "evil_twin":
            return ("Evil twin Wi‑Fi (αισθητήρας)", "high",
                    f"Ο αισθητήρας {sid} βλέπει δεύτερο «{ssid}» ({bssid}, κανάλι {ch}) με ΑΣΘΕΝΕΣΤΕΡΗ ασφάλεια: {sec}{near}. "
                    "Κάποιος μάλλον στήνει ψεύτικο αντίγραφο του δικτύου σου.", f"twin:{bssid}")
        return ("Άγνωστο access point", "med",
                f"Ο αισθητήρας {sid} βλέπει «{ssid}» από άγνωστο BSSID {bssid} (κανάλι {ch}, {sec}){near}. "
                "Αν πρόσθεσες repeater/mesh, πρόσθεσέ το στα ALLOWED_BSSIDS· αλλιώς ψάξ' το.", f"rogue:{bssid}")
    return None


class Bridge:
    def __init__(self, state, cfg, sim=False):
        self.state, self.cfg, self.sim = state, cfg or {}, sim
        self.lock = threading.Lock()
        self.sensors, self.events = {}, []
        self.connected, self.error = False, None
        self.client = None

    @property
    def configured(self):
        return bool(self.cfg.get("mqtt_host")) or self.sim

    def status(self):
        now = time.time()
        with self.lock:
            sens = []
            for sid, s in sorted(self.sensors.items()):
                d = dict(s)
                d["online"] = bool(s.get("online")) and now - s.get("seen", 0) < OFFLINE_AFTER
                d["ago"] = int(now - s.get("seen", now))
                sens.append(d)
            return {"configured": self.configured, "connected": self.connected or self.sim, "error": self.error,
                    "broker": f"{self.cfg.get('mqtt_host')}:{self.cfg.get('mqtt_port', 8883)}" if self.cfg.get("mqtt_host") else None,
                    "sensors": sens, "events": self.events[-50:][::-1], "demo": self.sim}

    # ---- εισερχόμενα μηνύματα ----
    def handle(self, topic, payload, t=None):
        t = t or time.time()
        m = TOPIC_RX.match(topic)
        if not m:
            return
        sid, kind = m.groups()
        try:
            data = json.loads(payload[:4096])
        except (ValueError, TypeError):
            return
        if not isinstance(data, dict):
            return
        data["id"] = sid  # εμπιστευόμαστε το topic (το ελέγχει το ACL του broker), όχι το payload
        if kind == "status":
            keep = {k: data.get(k) for k in ("online", "fw", "uptime", "heap", "rssi", "ip", "deauth_total", "twins_total",
                                             "kind", "canary_hits", "suppressed")}
            with self.lock:
                self.sensors[sid] = {"id": sid, **{k: (clean_txt(v, 40) if isinstance(v, str) else v) for k, v in keep.items()}, "seen": t}
            return
        a = to_alert(data)
        with self.lock:
            self.sensors.setdefault(sid, {"id": sid, "online": True})["seen"] = t
            self.events.append({"t": t, "sensor": sid, "type": data.get("type"), "title": a[0] if a else data.get("type"),
                                "detail": a[2] if a else ""})
            del self.events[:-200]
        if a:
            typ, sev, detail, key = a[:4]
            if len(a) > 4 and a[4] != "?":  # καναρίνι: ο «δράστης» είναι η IP που το άγγιξε
                self.state.alert(typ, sev, a[4], f"καναρίνι {sid}", detail, t, key=key, cooldown=300)
            else:
                self.state.alert(typ, sev, self.state.gateway or "wifi", f"αισθητήρας {sid}", detail, t, key=key, cooldown=300, mark=False)

    # ---- σύνδεση στο broker ----
    def start(self):
        if self.sim:
            threading.Thread(target=self._demo, daemon=True).start()
            return
        if not self.cfg.get("mqtt_host"):
            return
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.error = "Λείπει η βιβλιοθήκη paho-mqtt (pip install paho-mqtt)."
            return
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"netwatch-{os.getpid()}")
        if self.cfg.get("username"):
            c.username_pw_set(self.cfg["username"], self.cfg.get("password") or None)
        port = int(self.cfg.get("mqtt_port", 8883))
        if port != 1883 or self.cfg.get("ca_file"):
            ca = os.path.expanduser(self.cfg["ca_file"]) if self.cfg.get("ca_file") else None
            c.tls_set(ca_certs=ca, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)  # ποτέ χωρίς έλεγχο πιστοποιητικού
        topic = self.cfg.get("topic", "netwatch/sensor/#")

        def on_connect(cl, _u, _f, rc, _p=None):
            self.connected = not rc.is_failure if hasattr(rc, "is_failure") else rc == 0
            self.error = None if self.connected else f"Ο broker αρνήθηκε τη σύνδεση: {rc}"
            if self.connected:
                cl.subscribe(topic, qos=1)

        def on_disconnect(_cl, _u, _f, rc, _p=None):
            self.connected = False
            if rc and getattr(rc, "value", rc) != 0:
                self.error = f"Αποσύνδεση από τον broker ({rc}) — ξαναδοκιμάζω…"

        c.on_connect, c.on_disconnect = on_connect, on_disconnect
        c.on_message = lambda _c, _u, msg: self.handle(msg.topic, msg.payload)
        c.reconnect_delay_set(2, 60)
        try:
            c.connect_async(self.cfg["mqtt_host"], port, keepalive=60)
            c.loop_start()
            self.client = c
        except Exception as e:
            self.error = str(e)[:200]

    def _demo(self):
        sid, t0, sent, beat = "sentinel-a1b2c3", time.time(), False, 0
        while True:
            up = int(time.time() - t0)
            if time.time() - beat >= 30:
                beat = time.time()
                self.handle(f"netwatch/sensor/{sid}/status", json.dumps({"online": True, "fw": "1.0.0", "uptime": 3600 + up, "heap": 181000,
                            "rssi": random.randint(-62, -55), "ip": "192.168.1.50", "deauth_total": 1 if sent else 0, "twins_total": 0}))
            if not sent and up >= 20:
                sent = True
                self.handle(f"netwatch/sensor/{sid}/event", json.dumps({"type": "deauth", "channel": 6, "count": 87, "window_s": 1,
                            "bssid": "de:ad:be:ef:00:01", "target": "ff:ff:ff:ff:ff:ff", "rssi": -44, "t": up}))
            time.sleep(5)
