"""Φύλακας του MQTT broker σου (π.χ. Mosquitto στο Raspberry Pi / σε VM του Proxmox).

Το NetWatch συνδέεται με ΔΙΚΟ ΤΟΥ χρήστη που μόνο διαβάζει (ACL: topic read #, topic read $SYS/#) και:
- μαθαίνει ποιοι clients συνδέονται (από το $SYS/broker/log/# — χρειάζεται `log_dest topic` στο mosquitto.conf)
  → «Άγνωστος MQTT client» όταν εμφανιστεί καινούργιος μετά την περίοδο εκμάθησης·
- μαθαίνει ποια topics χρησιμοποιεί κάθε συσκευή → «Νέο MQTT topic»·
- εντολές (…/set, /cmd, relay…) μέσα στη νύχτα → «Εντολή MQTT σε ασυνήθιστη ώρα»·
- συσκευή που έστελνε τακτικά και σταμάτησε → «IoT συσκευή σιώπησε»·
- δείχνει ζωντανά τα τελευταία μηνύματα (για debugging των ESP).
Ό,τι μαθαίνει το κρατάει στο data/mqttguard.json, ώστε να μη «ξαναμαθαίνει» σε κάθε εκκίνηση.
"""
import json
import os
import random
import re
import ssl
import threading
import time

LEARN_SECONDS = 15 * 60  # πρώτα 15′: μόνο μαθαίνει, δεν ειδοποιεί για «νέα» πράγματα
SILENT_MIN = 5 * 60
NIGHT = range(0, 6)
CMD_RX = re.compile(r"(^|/)(set|cmd|command|commands|relay|switch|power|reboot|restart|ota|update|config)(/|$)", re.I)
CONNECT_RX = re.compile(r"New client connected from ([0-9a-fA-F.:]+?)(?::\d+)? as (\S+?)(?: \(.*?u'([^']*)'\))?\.?$")
SYS_INFO = {"$SYS/broker/version": "version", "$SYS/broker/clients/connected": "clients",
            "$SYS/broker/uptime": "uptime", "$SYS/broker/messages/received": "received"}


def device_of(topic):
    """«home/garden/temp» → «home/garden»: οι δύο πρώτες στάθμες χαρακτηρίζουν συνήθως μια συσκευή."""
    parts = topic.split("/")
    return "/".join(parts[:2]) if len(parts) > 2 else parts[0]


def pattern_of(topic):
    """Αριθμοί/MAC/ids μέσα στο topic → «+», ώστε «sensor/42/temp» και «sensor/43/temp» να είναι το ίδιο μοτίβο."""
    return "/".join("+" if re.fullmatch(r"[0-9a-fA-F:_-]{6,}|\d+", p) else p for p in topic.split("/"))


def preview(payload, n=120):
    try:
        s = payload.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return f"<{len(payload)} bytes>"
    return "".join(c if c.isprintable() else "·" for c in s)[:n]


class Guard:
    def __init__(self, state, cfg, sim=False, path=None):
        self.state, self.cfg, self.sim = state, cfg or {}, sim
        self.path = path
        self.lock = threading.Lock()
        self.clients, self.patterns, self.devices = {}, {}, {}  # μαθημένα
        self.msgs, self.broker = [], {}
        self.connected, self.error, self.client = False, None, None
        self.started = time.time()
        self.learn_until = self.started + LEARN_SECONDS
        self.has_log = False
        self._load()

    # ---- αποθήκευση ----
    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            self.clients, self.patterns = d.get("clients", {}), d.get("patterns", {})
            self.devices = {k: {**v, "silent": False} for k, v in d.get("devices", {}).items()}
            self.learn_until = min(self.learn_until, d.get("learned_at", self.learn_until))
        except (OSError, ValueError):
            pass

    def _save(self):
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with self.lock:
                d = {"clients": self.clients, "patterns": self.patterns, "devices": self.devices,
                     "learned_at": self.learn_until}
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f)
            os.replace(tmp, self.path)
            from core import chown_to_user
            chown_to_user(self.path)
        except OSError:
            pass

    @property
    def learning(self):
        return time.time() < self.learn_until

    @property
    def configured(self):
        return bool(self.cfg.get("host")) or self.sim

    def status(self):
        now = time.time()
        with self.lock:
            devs = sorted(({"id": k, **v, "ago": int(now - v["last"])} for k, v in self.devices.items()), key=lambda d: d["id"])
            return {"configured": self.configured, "connected": self.connected or self.sim, "error": self.error,
                    "broker": f"{self.cfg.get('host')}:{self.cfg.get('port', 1883)}" if self.cfg.get("host") else None,
                    "info": self.broker, "learning": self.learning, "learn_left": max(0, int(self.learn_until - now)),
                    "has_log": self.has_log, "clients": sorted(self.clients.values(), key=lambda c: -c["last"]),
                    "devices": devs, "patterns": len(self.patterns), "msgs": self.msgs[-80:][::-1], "demo": self.sim}

    def relearn(self):
        with self.lock:
            self.clients, self.patterns, self.devices = {}, {}, {}
            self.learn_until = time.time() + LEARN_SECONDS
        self._save()

    def _alert(self, typ, sev, actor, detail, t, key):
        self.state.alert(typ, sev, actor or self.cfg.get("host") or "mqtt", "MQTT broker", detail, t, key=key, cooldown=600, mark=False)

    # ---- εισερχόμενα ----
    def handle(self, topic, payload, retained=False, t=None):
        t = t or time.time()
        if topic.startswith("$SYS/"):
            return self._sys(topic, payload, t)
        dev, pat = device_of(topic), pattern_of(topic)
        alerts = []
        with self.lock:
            self.msgs.append({"t": t, "topic": topic[:160], "payload": preview(payload), "retained": bool(retained)})
            del self.msgs[:-300]
            if retained:  # τα retained έρχονται όλα μαζί με το subscribe: δεν λένε τίποτα για τη συμπεριφορά
                self.patterns.setdefault(pat, {"first": t, "n": 0})
                return
            d = self.devices.get(dev)
            if d is None:
                d = self.devices[dev] = {"first": t, "last": t, "n": 0, "gap": None, "silent": False}
            elif t > d["last"]:
                gap = t - d["last"]
                d["gap"] = gap if d["gap"] is None else 0.8 * d["gap"] + 0.2 * gap  # κινητός μέσος όρος
            if d["silent"]:
                d["silent"] = False
                alerts.append(("IoT συσκευή ξαναμίλησε", "low", None, f"Το «{dev}» ξαναστέλνει μηνύματα στο MQTT.", f"back:{dev}"))
            d["last"], d["n"] = t, d["n"] + 1
            p = self.patterns.get(pat)
            if p is None:
                self.patterns[pat] = {"first": t, "n": 1}
                if not self.learning:
                    alerts.append(("Νέο MQTT topic", "med" if CMD_RX.search(topic) else "low", None,
                                   f"Πρώτη φορά βλέπω το topic «{topic[:120]}» (περιεχόμενο: {preview(payload, 60)}). "
                                   "Αν δεν πρόσθεσες κάτι καινούργιο, κάποιος άλλος γράφει στον broker σου.", f"topic:{pat}"))
            else:
                p["n"] += 1
            if CMD_RX.search(topic) and time.localtime(t).tm_hour in NIGHT and not self.learning:
                alerts.append(("Εντολή MQTT σε ασυνήθιστη ώρα", "med", None,
                               f"Εντολή στο «{topic[:120]}» = {preview(payload, 40)} στις {time.strftime('%H:%M', time.localtime(t))}. "
                               "Αν δεν ήταν δικός σου αυτοματισμός, κάποιος ελέγχει τις συσκευές σου.", f"night:{pat}"))
        for a in alerts:
            self._alert(a[0], a[1], a[2], a[3], t, a[4])

    def _sys(self, topic, payload, t):
        s = preview(payload, 300)
        if topic in SYS_INFO:
            with self.lock:
                self.broker[SYS_INFO[topic]] = s
            return
        if not topic.startswith("$SYS/broker/log/"):
            return
        self.has_log = True
        m = CONNECT_RX.search(s)
        if not m:
            return
        ip, cid, user = m.group(1), m.group(2), m.group(3)
        if cid.startswith("netwatch-"):
            return
        new = False
        with self.lock:
            c = self.clients.get(cid)
            if c is None:
                new = True
                c = self.clients[cid] = {"id": cid, "ips": [], "user": user, "first": t, "n": 0}
            if ip not in c["ips"]:
                c["ips"] = (c["ips"] + [ip])[-5:]
            c["last"], c["n"], c["user"] = t, c["n"] + 1, user or c.get("user")
        if new and not self.learning:
            self._alert("Άγνωστος MQTT client", "high", ip,
                        f"Νέος client «{cid}»{' (χρήστης ' + user + ')' if user else ''} συνδέθηκε στον broker από {ip}. "
                        "Αν δεν είναι δική σου καινούργια συσκευή, άλλαξε κωδικούς και έλεγξε τα ACL.", t, f"client:{cid}")
        if new:
            self._save()

    def tick(self, now=None):
        """Κάθε λεπτό: ποιες συσκευές σταμάτησαν να στέλνουν."""
        now = now or time.time()
        out = []
        with self.lock:
            for dev, d in self.devices.items():
                if d["silent"] or d["n"] < 3 or not d["gap"]:
                    continue
                limit = max(SILENT_MIN, 5 * d["gap"])
                if now - d["last"] > limit:
                    d["silent"] = True
                    out.append((dev, int((now - d["last"]) / 60)))
        for dev, mins in out:
            self._alert("IoT συσκευή σιώπησε", "med", None,
                        f"Το «{dev}» έστελνε κάθε ~{int(self.devices[dev]['gap'])}″ και σιωπά εδώ και {mins}′. "
                        "Κόλλησε, έπεσε το Wi‑Fi του — ή κάποιος το «πετάει» από το δίκτυο (deauth).", now, f"silent:{dev}")

    # ---- σύνδεση ----
    def start(self):
        threading.Thread(target=self._ticker, daemon=True).start()
        if self.sim:
            threading.Thread(target=self._demo, daemon=True).start()
            return
        if not self.cfg.get("host"):
            return
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.error = "Λείπει η βιβλιοθήκη paho-mqtt (pip install paho-mqtt)."
            return
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"netwatch-guard-{os.getpid()}")
        if self.cfg.get("username"):
            c.username_pw_set(self.cfg["username"], self.cfg.get("password") or None)
        port = int(self.cfg.get("port", 1883))
        if port != 1883 or self.cfg.get("ca_file"):
            ca = os.path.expanduser(self.cfg["ca_file"]) if self.cfg.get("ca_file") else None
            c.tls_set(ca_certs=ca, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)

        def on_connect(cl, _u, _f, rc, _p=None):
            self.connected = not rc.is_failure if hasattr(rc, "is_failure") else rc == 0
            if self.connected:
                self.error = None
                cl.subscribe([(self.cfg.get("topic", "#"), 0), ("$SYS/broker/log/#", 0), ("$SYS/broker/version", 0),
                              ("$SYS/broker/clients/connected", 0), ("$SYS/broker/uptime", 0)])
            else:
                self.error = f"Ο broker αρνήθηκε τη σύνδεση: {rc} (σωστός χρήστης/κωδικός;)"

        def on_disconnect(_cl, _u, _f, rc, _p=None):
            self.connected = False
            if rc and getattr(rc, "value", rc) != 0:
                self.error = f"Αποσύνδεση από τον broker ({rc}) — ξαναδοκιμάζω…"

        c.on_connect, c.on_disconnect = on_connect, on_disconnect
        c.on_message = lambda _c, _u, msg: self.handle(msg.topic, msg.payload, msg.retain)
        c.reconnect_delay_set(2, 60)
        try:
            c.connect_async(self.cfg["host"], port, keepalive=60)
            c.loop_start()
            self.client = c
        except Exception as e:
            self.error = str(e)[:200]

    def _ticker(self):
        n = 0
        while True:
            time.sleep(60)
            self.tick()
            n += 1
            if n % 10 == 0:
                self._save()

    def _demo(self):
        self.learn_until = time.time() + 25
        self.handle("$SYS/broker/version", b"mosquitto version 2.0.18")
        self.handle("$SYS/broker/clients/connected", b"3")
        for cid, ip, u in (("esp32-garden", "192.168.1.20", "garden"), ("esp32-door", "192.168.1.21", "door"),
                           ("homeassistant", "192.168.1.30", "ha")):
            self.handle("$SYS/broker/log/N", f"1700000000: New client connected from {ip}:5123 as {cid} (p2, c1, k60, u'{u}').".encode())
        self.handle("garden/relay/state", b"OFF", retained=True)
        t0, sent = time.time(), set()
        while True:
            up = time.time() - t0
            self.handle("home/garden/temp", f"{21 + random.random() * 2:.1f}".encode())
            self.handle("home/garden/hum", f"{55 + random.randint(-3, 3)}".encode())
            if up < 40 or up > 120:
                self.handle("home/door/state", random.choice([b"closed", b"closed", b"open"]))
            if up > 35 and "x" not in sent:
                sent.add("x")
                self.handle("$SYS/broker/log/N", b"1700000100: New client connected from 192.168.1.66:40112 as mqttx_7f3a (p2, c1, k60, u'garden').")
                self.handle("home/garden/relay/set", b"ON")
            time.sleep(5)
