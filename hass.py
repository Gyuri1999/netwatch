"""Home Assistant μέσω MQTT discovery: οι ειδοποιήσεις του NetWatch εμφανίζονται ως οντότητες στο HA.

Οντότητες (συσκευή «NetWatch»):
  binary_sensor.netwatch_attack   ON όσο υπάρχει σοβαρή ειδοποίηση τα τελευταία 10′ (για αυτοματισμούς: κόκκινα φώτα…)
  sensor.netwatch_last_alert      τύπος της τελευταίας ειδοποίησης (+ attributes: σοβαρότητα, ποιος, λεπτομέρειες, MITRE)
  sensor.netwatch_alerts_hour     ειδοποιήσεις την τελευταία ώρα
  sensor.netwatch_devices         συσκευές στο τοπικό δίκτυο
  sensor.netwatch_score           βαθμός ασφάλειας (καρτέλα 🛡 Έλεγχος)
Κάθε ειδοποίηση πάει ΚΑΙ ως JSON στο netwatch/alerts — για MQTT trigger σε αυτοματισμούς.

Χρειάζεται ΧΩΡΙΣΤΟ χρήστη από τον φύλακα (που μόνο διαβάζει), με ACL:
  user netwatch-ha / topic write homeassistant/# / topic readwrite netwatch/ha/# / topic write netwatch/alerts
"""
import json
import os
import ssl
import threading
import time

SEVS = {"low": 1, "med": 2, "high": 3}
ATTACK_WINDOW = 600


class HomeAssistant:
    def __init__(self, state, cfg, sim=False):
        self.state, self.cfg, self.sim = state, cfg or {}, sim
        self.prefix = self.cfg.get("discovery_prefix", "homeassistant")
        self.base = self.cfg.get("base_topic", "netwatch/ha")
        self.client, self.connected, self.error = None, False, None
        self.recent, self.last, self.sent = [], None, []  # sent: τι «στάλθηκε» (για demo/tests)
        self.lock = threading.Lock()

    @property
    def configured(self):
        return bool(self.cfg.get("host")) or self.sim

    # ---- discovery ----
    def discovery(self):
        dev = {"identifiers": ["netwatch"], "name": "NetWatch", "manufacturer": "NetWatch", "model": "Network IDS",
               "sw_version": "1.0"}
        avail = {"availability_topic": f"{self.base}/status", "payload_available": "online", "payload_not_available": "offline"}
        b = self.base
        ents = [
            ("binary_sensor", "attack", {"name": "Επίθεση", "device_class": "safety", "state_topic": f"{b}/attack",
                                         "payload_on": "ON", "payload_off": "OFF", "icon": "mdi:shield-alert"}),
            ("sensor", "last_alert", {"name": "Τελευταία ειδοποίηση", "state_topic": f"{b}/last_alert",
                                      "value_template": "{{ value_json.type }}", "json_attributes_topic": f"{b}/last_alert",
                                      "icon": "mdi:alert"}),
            ("sensor", "alerts_hour", {"name": "Ειδοποιήσεις (ώρα)", "state_topic": f"{b}/alerts_hour",
                                       "state_class": "measurement", "icon": "mdi:counter"}),
            ("sensor", "devices", {"name": "Συσκευές στο δίκτυο", "state_topic": f"{b}/devices",
                                   "state_class": "measurement", "icon": "mdi:lan"}),
            ("sensor", "score", {"name": "Βαθμός ασφάλειας", "state_topic": f"{b}/score", "unit_of_measurement": "%",
                                 "state_class": "measurement", "icon": "mdi:shield-check"}),
        ]
        return [(f"{self.prefix}/{kind}/netwatch/{oid}/config",
                 {**cfg, **avail, "unique_id": f"netwatch_{oid}", "object_id": f"netwatch_{oid}", "device": dev})
                for kind, oid, cfg in ents]

    def _pub(self, topic, payload, retain=False):
        data = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
        with self.lock:
            self.sent.append((topic, data, retain))
            del self.sent[:-200]
        if self.client is not None:
            self.client.publish(topic, data, qos=1, retain=retain)

    def announce(self):
        for topic, cfg in self.discovery():
            self._pub(topic, cfg, retain=True)
        self._pub(f"{self.base}/status", "online", retain=True)
        self.publish_state()

    # ---- κατάσταση ----
    def on_alert(self, a):
        if not self.configured:
            return
        now = a.get("t") or time.time()
        with self.lock:
            self.recent.append((now, a["sev"]))
            self.recent = [x for x in self.recent if now - x[0] < 3600]
            self.last = a
        mitre = a.get("mitre") or {}
        msg = {"type": a["type"], "sev": a["sev"], "actor": a["actor"], "target": str(a["target"]),
               "detail": a["detail"][:500], "mitre": mitre.get("id"), "t": int(now)}
        self._pub("netwatch/alerts", msg)
        self._pub(f"{self.base}/last_alert", msg, retain=True)
        self.publish_state(now)

    def publish_state(self, now=None, full=False):
        now = now or time.time()
        with self.lock:
            hour = [x for x in self.recent if now - x[0] < 3600]
            attack = any(s == "high" and now - t < ATTACK_WINDOW for t, s in hour)
        self._pub(f"{self.base}/attack", "ON" if attack else "OFF", retain=True)
        self._pub(f"{self.base}/alerts_hour", str(len(hour)), retain=True)
        if full:
            try:
                with self.state.lock:
                    n = sum(1 for h in self.state.hosts.values() if h.get("kind") == "local")
                self._pub(f"{self.base}/devices", str(n), retain=True)
                self._pub(f"{self.base}/score", str(self.state.audit()["score"]), retain=True)
            except Exception:
                pass

    def status(self):
        return {"configured": self.configured, "connected": self.connected or self.sim, "error": self.error,
                "broker": f"{self.cfg.get('host')}:{self.cfg.get('port', 1883)}" if self.cfg.get("host") else None}

    # ---- σύνδεση ----
    def start(self):
        if not self.configured:
            return
        threading.Thread(target=self._loop, daemon=True).start()
        if self.sim:
            self.announce()
            return
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.error = "Λείπει η βιβλιοθήκη paho-mqtt."
            return
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"netwatch-ha-{os.getpid()}")
        if self.cfg.get("username"):
            c.username_pw_set(self.cfg["username"], self.cfg.get("password") or None)
        port = int(self.cfg.get("port", 1883))
        if port != 1883 or self.cfg.get("ca_file"):
            ca = os.path.expanduser(self.cfg["ca_file"]) if self.cfg.get("ca_file") else None
            c.tls_set(ca_certs=ca, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
        c.will_set(f"{self.base}/status", "offline", qos=1, retain=True)

        def on_connect(cl, _u, _f, rc, _p=None):
            self.connected = not rc.is_failure if hasattr(rc, "is_failure") else rc == 0
            self.error = None if self.connected else f"Ο broker αρνήθηκε τη σύνδεση: {rc}"
            if self.connected:
                cl.subscribe(f"{self.prefix}/status")  # το HA ξεκίνησε → ξαναστείλε το discovery
                threading.Thread(target=self.announce, daemon=True).start()

        def on_message(_c, _u, msg):
            if msg.topic == f"{self.prefix}/status" and msg.payload == b"online":
                threading.Thread(target=self.announce, daemon=True).start()

        def on_disconnect(_cl, _u, _f, rc, _p=None):
            self.connected = False

        c.on_connect, c.on_message, c.on_disconnect = on_connect, on_message, on_disconnect
        c.reconnect_delay_set(2, 60)
        try:
            c.connect_async(self.cfg["host"], port, keepalive=60)
            c.loop_start()
            self.client = c
        except Exception as e:
            self.error = str(e)[:200]

    def _loop(self):
        while True:
            time.sleep(60)
            self.publish_state(full=True)  # ενημερώνει και το «Επίθεση» να σβήσει μετά από 10′
