"""📦 Απογραφή έξυπνων συσκευών: ό,τι «λένε» οι συσκευές IoT στον MQTT broker σου, σε έναν πίνακα.

Δεν ρωτάμε καμία συσκευή και δεν γράφουμε ποτέ στον broker: ο φύλακας MQTT (mqttwatch, χρήστης μόνο-ανάγνωσης)
μάς δίνει κάθε μήνυμα στο `handle(topic, payload, retained, t)` και εδώ αναγνωρίζουμε τα γνωστά «οικοσυστήματα»:
  • Zigbee2MQTT  — zigbee2mqtt/bridge/devices|info|state, zigbee2mqtt/<όνομα>, …/availability
  • Tasmota      — tele/<t>/LWT|STATE|INFO1-3, stat/<t>/STATUS2|5|11, tasmota/discovery/<mac>/config
  • Shelly       — Gen1: shellies/announce, shellies/<id>/online|info· Gen2+: <id>/online, <id>/status/sys|wifi, <id>/events/rpc
  • ESPHome      — <prefix>/status, <prefix>/debug και Home-Assistant discovery (homeassistant/…/config), που καλύπτει
                   και πολλές άλλες μάρκες (γενική πηγή «ha»).
Από αυτά βγαίνει: μοντέλο, firmware, αν υπάρχει ενημέρωση, μπαταρία, σήμα (LQI/RSSI), online/offline, τελευταία φορά.
Κανόνες υγείας → λίστα προβλημάτων και (μία φορά ανά συσκευή/πρόβλημα, και μετά από επανεκκίνηση) ειδοποιήσεις.
Όλα με όρια μεγέθους· κακό JSON, τεράστια ή περίεργα μηνύματα απλώς αγνοούνται.
"""
import csv
import datetime
import io
import json
import os
import re
import threading
import time

MAX_TOPIC = 256
MAX_SMALL = 16 * 1024          # κάθε μήνυμα εκτός από τη λίστα συσκευών του Zigbee2MQTT
MAX_BRIDGE = 2 * 1024 * 1024   # zigbee2mqtt/bridge/devices (έχει ολόκληρους ορισμούς συσκευών)
MAX_DEV = 500
MAX_AVAIL = 500
BATT_LOW, BATT_OK = 15, 20     # ≤15% πρόβλημα· «λύθηκε» όταν ξαναπεράσει το 20%
BATT_SHOP = 25                 # στη λίστα αγορών μπαίνει ό,τι είναι ≤25%
SILENT_BATT = 25 * 3600        # συσκευή μπαταρίας χωρίς κανένα μήνυμα
OFF_MAINS = 15 * 60            # συσκευή που δηλώθηκε offline
LQI_WEAK, RSSI_WEAK = 40, -80

SRC = {"z2m": ("Zigbee2MQTT", "🐝"), "tasmota": ("Tasmota", "💡"), "shelly": ("Shelly", "🔌"), "esphome": ("ESPHome", "📟"),
       "ha": ("MQTT discovery", "🏠")}
RESERVED = {"zigbee2mqtt", "homeassistant", "tele", "stat", "cmnd", "shellies", "tasmota", "netwatch", "frigate", "zwave"}
SHELLY2_RX = re.compile(r"^shelly[a-z0-9]*-[0-9a-f]{6,12}$", re.I)

# μοντέλο → (τύπος μπαταρίας, τεμάχια) — μόνο όσα είναι σίγουρα
BATTERY = {
    # Aqara / Xiaomi
    "WSDCGQ11LM": ("CR2032", 1), "WSDCGQ01LM": ("CR2032", 1), "WSDCGQ12LM": ("CR2032", 1), "MCCGQ11LM": ("CR1632", 1),
    "MCCGQ01LM": ("CR1632", 1), "MCCGQ14LM": ("CR1632", 1), "RTCGQ11LM": ("CR2450", 1), "RTCGQ01LM": ("CR2450", 1),
    "RTCGQ14LM": ("CR2450", 2), "SJCGQ11LM": ("CR2032", 1), "WXKG11LM": ("CR2032", 1), "WXKG01LM": ("CR2032", 1),
    "WXKG02LM": ("CR2032", 1), "WXKG03LM": ("CR2032", 1), "DJT11LM": ("CR2032", 1), "MFKZQ01LM": ("CR2450", 1),
    # IKEA
    "E1524/E1810": ("CR2032", 1), "E1743": ("CR2032", 1), "E1525/E1745": ("CR2032", 2), "E1766": ("CR2032", 1), "E1812": ("CR2032", 1),
    "E1744": ("CR2032", 1), "E2001/E2002": ("AAA", 2), "E2013": ("AAA", 1), "E2134": ("AAA", 3), "E2202": ("AAA", 1), "E2123": ("AAA", 1),
    # Sonoff
    "SNZB-01": ("CR2450", 1), "SNZB-02": ("CR2450", 1), "SNZB-03": ("CR2450", 1), "SNZB-04": ("CR2032", 1), "SNZB-02D": ("CR2450", 1),
    "SNZB-01P": ("CR2477", 1), "SNZB-02P": ("CR2477", 1), "SNZB-03P": ("CR2477", 1), "SNZB-04P": ("CR2477", 1),
    # Philips Hue
    "324131092621": ("CR2450", 1), "929002398602": ("CR2032", 1), "9290012607": ("AAA", 2), "9290019758": ("AA", 2), "8718699693985": ("CR2032", 1),
    # Shelly (Gen1)
    "SHHT-1": ("CR123A", 1), "SHWT-1": ("CR123A", 1), "SHDW-2": ("CR123A", 2),
}


def _txt(x, n=80):
    if isinstance(x, bool) or not isinstance(x, (str, int, float)):
        return ""
    return "".join(c for c in str(x) if c.isprintable())[:n].strip()


def _num(x, lo=-1e12, hi=1e12):
    if isinstance(x, bool) or not isinstance(x, (int, float)) or x != x or not lo <= x <= hi:
        return None
    return x


def _json(payload, cap=MAX_SMALL):
    """bytes → αντικείμενο JSON ή None (πολύ μεγάλο, χαλασμένο, υπερβολικά βαθύ)."""
    if len(payload) > cap or not payload:
        return None
    try:
        return json.loads(payload.decode("utf-8"))
    except (ValueError, RecursionError, MemoryError):
        return None


def _word(payload):
    """Μικρό κείμενο κατάστασης («online», «Offline», «true»…) → πεζά· αλλιώς ''."""
    if len(payload) > 64:
        return ""
    try:
        return payload.decode("utf-8").strip().strip('"').lower()
    except UnicodeDecodeError:
        return ""


def _state_word(payload):
    """«online» ή {"state": "online"} (και τα δύο υπάρχουν στο Zigbee2MQTT)."""
    w = _word(payload)
    if w.startswith("{"):
        j = _json(payload)
        w = _txt(j.get("state"), 20).lower() if isinstance(j, dict) else ""
    return w


def norm_mac(x):
    s = re.sub(r"[^0-9a-f]", "", str(x or "").lower())
    return ":".join(s[i:i + 2] for i in range(0, 12, 2)) if len(s) == 12 else ""


def _ip(x):
    s = _txt(x, 45)
    return s if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s) and s != "0.0.0.0" else ""


def parse_time(x):
    """last_seen του Zigbee2MQTT: epoch (ms ή s) ή ISO 8601 → epoch δευτερόλεπτα ή None."""
    v = _num(x, 0, 1e14)
    if v is not None:
        return v / 1000.0 if v > 1e11 else float(v) if v > 1e8 else None
    if not isinstance(x, str) or not 10 <= len(x) <= 40:
        return None
    try:
        d = datetime.datetime.fromisoformat(x.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        return time.mktime(d.timetuple())
    return d.timestamp()


def battery_of(model):
    return BATTERY.get(str(model or "").strip())


def _csv_cell(x):
    s = "" if x is None else str(x)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") and not re.match(r"^-?\d+(\.\d+)?$", s) else s


class IotInv:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time, z2m_base="zigbee2mqtt"):
        self.state, self.demo, self.clock = state, demo, clock
        self.path = os.path.join(data_dir, "iotinv.json") if data_dir else None
        self.on_save = None
        self.z2m_base = z2m_base
        self.lock = threading.RLock()
        self.devs = {}      # "πηγή:id" → συσκευή
        self.avail = {}     # availability topic (από discovery) → (κλειδί, payload online, payload offline)
        self.alerted = {}   # κλειδί → {"batt": t, "off": t} — ώστε να μην ξαναειδοποιούμε (ούτε μετά από επανεκκίνηση)
        self.z2m = {}       # κατάσταση της γέφυρας Zigbee2MQTT
        self.msgs, self.last_msg = 0, None
        self._dirty, self._saved = False, 0
        if demo:
            self._demo_seed()
        else:
            self._load()

    # ── αποθήκευση ──
    def _blank(self, src, did, t):
        return {"src": src, "id": did, "name": did, "model": "", "vendor": "", "ip": "", "mac": "", "ieee": "", "fw": "", "update": False,
                "update_to": "", "batt": None, "lqi": None, "rssi": None, "power": "", "online": None, "off_since": None,
                "first": t, "last": None, "type": "", "interview": ""}

    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                j = json.load(f)
            for key, d in list((j.get("devs") or {}).items())[:MAX_DEV]:
                if not isinstance(d, dict) or d.get("src") not in SRC or not _txt(d.get("id")):
                    continue
                b = self._blank(d["src"], _txt(d["id"]), _num(d.get("first")) or 0)
                for k in ("name", "model", "vendor", "ieee", "fw", "update_to", "power", "type", "interview"):
                    b[k] = _txt(d.get(k))
                b["name"] = b["name"] or b["id"]
                b["ip"], b["mac"] = _ip(d.get("ip")), norm_mac(d.get("mac"))
                b["update"] = d.get("update") is True
                b["online"] = d.get("online") if isinstance(d.get("online"), bool) else None
                b["batt"], b["lqi"], b["rssi"] = _num(d.get("batt"), 0, 100), _num(d.get("lqi"), 0, 255), _num(d.get("rssi"), -130, 0)
                b["off_since"], b["last"] = _num(d.get("off_since"), 0), _num(d.get("last"), 0)
                self.devs[b["src"] + ":" + b["id"]] = b
            for key, a in (j.get("alerted") or {}).items():
                if key in self.devs and isinstance(a, dict):
                    self.alerted[key] = {k: float(v) for k, v in a.items() if k in ("batt", "off") and _num(v) is not None}
            for topic, a in list((j.get("avail") or {}).items())[:MAX_AVAIL]:
                if isinstance(a, list) and len(a) == 3 and a[0] in self.devs:
                    self.avail[_txt(topic, MAX_TOPIC)] = (a[0], _txt(a[1], 32), _txt(a[2], 32))
            if isinstance(j.get("z2m"), dict):
                self.z2m = {k: v for k, v in j["z2m"].items() if isinstance(v, (str, int, float, bool))}
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save(self):
        self._dirty, self._saved = False, self.clock()
        if not self.path:
            return
        with self.lock:
            j = {"devs": self.devs, "alerted": self.alerted, "avail": {k: list(v) for k, v in self.avail.items()}, "z2m": self.z2m}
            raw = json.dumps(j)
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(raw)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    # ── βοηθητικά ──
    def _dev(self, src, did, t):
        did = _txt(did)
        if not did:
            return None
        key = src + ":" + did
        d = self.devs.get(key)
        if d is None:
            if len(self.devs) >= MAX_DEV:
                return None
            d = self.devs[key] = self._blank(src, did, t)
            d["vendor"] = {"tasmota": "Tasmota", "shelly": "Shelly", "esphome": "ESPHome"}.get(src, "")
        self._dirty = True
        return d

    @staticmethod
    def _online(d, on, t):
        if on:
            d["online"], d["off_since"] = True, None
        elif d["online"] is not False:
            d["online"], d["off_since"] = False, t

    @staticmethod
    def _touch(d, t, retained):
        if not retained:  # τα retained έρχονται με το subscribe: δεν αποδεικνύουν ότι η συσκευή ζει τώρα
            d["last"] = max(d["last"] or 0, t)

    # ── εισερχόμενα ──
    def handle(self, topic, payload, retained=False, t=None):
        """Κάθε μήνυμα MQTT περνά από εδώ (από τον φύλακα MQTT). Δεν πετά ποτέ εξαίρεση."""
        try:
            if not isinstance(topic, str) or not topic or len(topic) > MAX_TOPIC or topic[0] == "$":
                return
            if isinstance(payload, str):
                payload = payload.encode("utf-8", "replace")
            if not isinstance(payload, (bytes, bytearray)) or len(payload) > MAX_BRIDGE:
                return
            payload = bytes(payload)
            t = t or self.clock()
            p = topic.split("/")
            with self.lock:
                self.msgs += 1
                self.last_msg = t
                head = p[0]
                if head == self.z2m_base:
                    self._z2m(p, payload, retained, t)
                elif head in ("tele", "stat"):
                    self._tasmota(p, payload, retained, t)
                elif head == "tasmota":
                    self._tasmota_disc(p, payload, t)
                elif head == "shellies":
                    self._shelly1(p, payload, retained, t)
                elif head == "homeassistant":
                    self._discovery(p, payload, t)
                elif topic in self.avail:
                    key, on, off = self.avail[topic]
                    w, d = _word(payload), self.devs.get(key)
                    if d is not None and w in (on.lower(), off.lower()):
                        self._online(d, w == on.lower(), t)
                        self._touch(d, t, retained or w != on.lower())
                        self._dirty = True
                elif len(p) >= 2 and (SHELLY2_RX.match(head) or ("shelly:" + head) in self.devs or p[1:] == ["events", "rpc"]):
                    self._shelly2(p, payload, retained, t)
                elif len(p) == 2 and p[1] in ("status", "debug"):
                    self._esphome(p, payload, retained, t)
        except Exception:  # noqa: BLE001 — ό,τι κι αν στείλει μια συσκευή, ο φύλακας MQTT δεν πρέπει να πέσει
            pass

    # Zigbee2MQTT
    def _z2m(self, p, payload, retained, t):
        if len(p) < 2:
            return
        if p[1] == "bridge":
            sub = "/".join(p[2:])
            if sub == "devices":
                j = _json(payload, MAX_BRIDGE)
                if isinstance(j, list):
                    self._z2m_devices(j, t)
            elif sub == "state":
                w = _state_word(payload)
                if w in ("online", "offline"):
                    self.z2m["state"] = w
                    self._dirty = True
            elif sub == "info":
                j = _json(payload, 256 * 1024)
                if isinstance(j, dict):
                    net = j.get("network") if isinstance(j.get("network"), dict) else {}
                    co = j.get("coordinator") if isinstance(j.get("coordinator"), dict) else {}
                    self.z2m.update(version=_txt(j.get("version"), 24), coordinator=_txt(co.get("type"), 40),
                                    channel=_num(net.get("channel"), 11, 26), pan_id=_txt(net.get("pan_id"), 12),
                                    permit_join=j.get("permit_join") is True)
                    self._dirty = True
            return
        if p[-1] in ("set", "get") or len(payload) > MAX_SMALL:
            return
        if p[-1] == "availability" and len(p) >= 3:
            w = _state_word(payload)
            if w in ("online", "offline"):
                d = self._dev("z2m", "/".join(p[1:-1]), t)
                if d is not None:
                    self._online(d, w == "online", t)
            return
        name = "/".join(p[1:])
        j = _json(payload)
        if not isinstance(j, dict):
            return
        if ("z2m:" + _txt(name)) not in self.devs and not any(k in j for k in ("linkquality", "battery", "last_seen")):
            return  # κάτι άλλο κάτω από το zigbee2mqtt/ (π.χ. απαντήσεις της γέφυρας)
        d = self._dev("z2m", name, t)
        if d is None:
            return
        b, lq = _num(j.get("battery"), 0, 100), _num(j.get("linkquality"), 0, 255)
        if b is not None:
            d["batt"] = b
            d["power"] = d["power"] or "battery"
        if lq is not None:
            d["lqi"] = lq
        ls = parse_time(j.get("last_seen"))
        if ls is not None and ls <= t + 300:
            d["last"] = max(d["last"] or 0, ls)
        self._touch(d, t, retained)
        up = j.get("update")
        if isinstance(up, dict):
            st = _txt(up.get("state"), 20).lower()
            if st:
                d["update"] = st in ("available", "updating")
            d["update_to"] = _txt(up.get("latest_version"), 24) if d["update"] else ""
            d["fw"] = d["fw"] or _txt(up.get("installed_version"), 24)
        elif isinstance(j.get("update_available"), bool):
            d["update"] = j["update_available"]

    def _z2m_devices(self, lst, t):
        names, by_ieee = set(), {d["ieee"]: k for k, d in self.devs.items() if d["src"] == "z2m" and d["ieee"]}
        for x in lst[:MAX_DEV]:
            if not isinstance(x, dict):
                continue
            ieee, name = _txt(x.get("ieee_address"), 20).lower(), _txt(x.get("friendly_name"))
            typ = _txt(x.get("type"), 16)
            name = name or ieee
            if not name:
                continue
            old = by_ieee.get(ieee)
            if old and old != "z2m:" + name and old in self.devs and ("z2m:" + name) not in self.devs:  # μετονομασία στο Zigbee2MQTT
                d = self.devs.pop(old)
                d["id"] = d["name"] = name
                self.devs["z2m:" + name] = d
                if old in self.alerted:
                    self.alerted["z2m:" + name] = self.alerted.pop(old)
            d = self._dev("z2m", name, t)
            if d is None:
                continue
            names.add("z2m:" + name)
            df = x.get("definition") if isinstance(x.get("definition"), dict) else {}
            ps = _txt(x.get("power_source"), 40).lower()
            d.update(ieee=ieee, type=typ, model=_txt(df.get("model") or x.get("model_id"), 60), vendor=_txt(df.get("vendor") or x.get("manufacturer"), 40),
                     fw=_txt(x.get("software_build_id"), 40) or d["fw"],
                     power="battery" if "battery" in ps else "mains" if ("mains" in ps or "dc" in ps or typ == "Coordinator") else d["power"])
            if typ == "Coordinator":
                d["model"] = d["model"] or self.z2m.get("coordinator") or "Coordinator"
            iv = x.get("interview_state")
            d["interview"] = ("ok" if iv == "SUCCESSFUL" else "failed" if iv == "FAILED" else "pending") if isinstance(iv, str) else \
                ("ok" if x.get("interview_completed") is True else "pending" if x.get("interview_completed") is False or x.get("interviewing") else "")
        if not names:
            return  # η πραγματική λίστα έχει πάντα τουλάχιστον τον coordinator· άδεια/άκυρη λίστα δεν σβήνει τίποτα
        for k in [k for k, d in self.devs.items() if d["src"] == "z2m" and k not in names]:  # αφαιρέθηκε από το δίκτυο Zigbee
            del self.devs[k]
            self.alerted.pop(k, None)
        self._dirty = True

    # Tasmota
    def _tasmota(self, p, payload, retained, t):
        if len(p) < 3 or len(payload) > MAX_SMALL:
            return
        leaf, name = p[-1], "/".join(p[1:-1])
        key = "tasmota:" + _txt(name)
        if p[0] == "tele" and leaf == "LWT":
            w = _word(payload)
            if w in ("online", "offline"):
                d = self._dev("tasmota", name, t)
                if d is not None:
                    self._online(d, w == "online", t)
            return
        info = re.match(r"^INFO[123]$", leaf) if p[0] == "tele" else None
        stat = re.match(r"^STATUS(2|5|11)$", leaf) if p[0] == "stat" else None
        if not (info or stat or (p[0] == "tele" and leaf == "STATE")):
            if key in self.devs:  # SENSOR, RESULT κ.λπ.: μόνο «ζει»
                self._touch(self.devs[key], t, retained)
            return
        j = _json(payload)
        if not isinstance(j, dict):
            return
        d = self._dev("tasmota", name, t)
        if d is None:
            return
        self._touch(d, t, retained)
        if info:
            inner = next((v for k, v in j.items() if isinstance(v, dict) and k.lower().startswith("info")), j)
            d["fw"] = _txt(inner.get("Version"), 40) or d["fw"]
            d["model"] = _txt(inner.get("Module"), 60) or d["model"]
            d["ip"] = _ip(inner.get("IPAddress")) or d["ip"]
            return
        if stat and stat.group(1) == "2":
            fwr = j.get("StatusFWR") if isinstance(j.get("StatusFWR"), dict) else {}
            d["fw"] = _txt(fwr.get("Version"), 40) or d["fw"]
            return
        if stat and stat.group(1) == "5":
            net = j.get("StatusNET") if isinstance(j.get("StatusNET"), dict) else {}
            d["ip"], d["mac"] = _ip(net.get("IPAddress")) or d["ip"], norm_mac(net.get("Mac")) or d["mac"]
            return
        sts = j.get("StatusSTS") if isinstance(j.get("StatusSTS"), dict) else j
        wifi = sts.get("Wifi") if isinstance(sts.get("Wifi"), dict) else {}
        sig, q = _num(wifi.get("Signal"), -130, 0), _num(wifi.get("RSSI"), 0, 100)
        if sig is not None:
            d["rssi"] = sig
        elif q is not None:
            d["rssi"] = int(q / 2 - 100)  # το «RSSI» του Tasmota είναι ποιότητα %· περίπου dBm = %/2 − 100
        if not retained and d["online"] is None:
            d["online"] = True
        d["power"] = d["power"] or "mains"

    def _tasmota_disc(self, p, payload, t):
        if len(p) != 4 or p[1] != "discovery" or p[3] != "config":
            return
        j = _json(payload)
        if not isinstance(j, dict) or not _txt(j.get("t")):
            return
        d = self._dev("tasmota", j["t"], t)
        if d is None:
            return
        d["name"] = _txt(j.get("dn")) or d["name"]
        d["model"], d["fw"] = _txt(j.get("md"), 60) or d["model"], _txt(j.get("sw"), 40) or d["fw"]
        d["ip"], d["mac"] = _ip(j.get("ip")) or d["ip"], norm_mac(j.get("mac")) or d["mac"]
        d["power"] = d["power"] or "mains"

    # Shelly
    @staticmethod
    def _shelly_fw(x):
        s = _txt(x, 60)
        m = re.search(r"/(v?\d+\.\d+[\w.\-]*?)(?:-g[0-9a-f]+|@|$)", s)
        return m.group(1) if m else s

    def _shelly1(self, p, payload, retained, t):
        if len(payload) > MAX_SMALL:
            return
        if p[-1] == "announce" and len(p) in (2, 3):
            j = _json(payload)
            if not isinstance(j, dict) or not _txt(j.get("id")):
                return
            d = self._dev("shelly", j["id"], t)
            if d is None:
                return
            d["model"], d["mac"], d["ip"] = _txt(j.get("model"), 40) or d["model"], norm_mac(j.get("mac")) or d["mac"], _ip(j.get("ip")) or d["ip"]
            d["fw"] = self._shelly_fw(j.get("fw_ver")) or d["fw"]
            if isinstance(j.get("new_fw"), bool):
                d["update"] = j["new_fw"]
            self._touch(d, t, retained)
            return
        if len(p) < 3:
            return
        sid, sub = p[1], "/".join(p[2:])
        if sub == "online":
            w = _word(payload)
            if w in ("true", "false"):
                d = self._dev("shelly", sid, t)
                if d is not None:
                    self._online(d, w == "true", t)
                    d["power"] = d["power"] or "mains"
            return
        d = self.devs.get("shelly:" + _txt(sid))
        if sub == "info":
            j = _json(payload)
            if not isinstance(j, dict):
                return
            d = d or self._dev("shelly", sid, t)
            if d is None:
                return
            ws = j.get("wifi_sta") if isinstance(j.get("wifi_sta"), dict) else {}
            up = j.get("update") if isinstance(j.get("update"), dict) else {}
            bat = j.get("bat") if isinstance(j.get("bat"), dict) else {}
            d["rssi"] = _num(ws.get("rssi"), -130, 0) if _num(ws.get("rssi"), -130, 0) is not None else d["rssi"]
            d["ip"], d["mac"] = _ip(ws.get("ip")) or d["ip"], norm_mac(j.get("mac")) or d["mac"]
            if isinstance(up.get("has_update"), bool):
                d["update"] = up["has_update"]
                d["update_to"] = self._shelly_fw(up.get("new_version")) if d["update"] else ""
            d["fw"] = self._shelly_fw(up.get("old_version")) or d["fw"]
            if _num(bat.get("value"), 0, 100) is not None:
                d["batt"], d["power"] = bat["value"], "battery"
        elif sub == "sensor/battery" and d is not None:
            try:
                v = _num(float(_word(payload)), 0, 100)
            except ValueError:
                v = None
            if v is not None:
                d["batt"], d["power"] = v, "battery"
        if d is not None:
            self._touch(d, t, retained)
            self._dirty = True

    def _shelly2(self, p, payload, retained, t):
        if len(payload) > MAX_SMALL:
            return
        sid, sub = p[0], "/".join(p[1:])
        if sub == "online":
            w = _word(payload)
            if w in ("true", "false"):
                d = self._dev("shelly", sid, t)
                if d is not None:
                    self._online(d, w == "true", t)
            return
        parts = {}
        if sub == "events/rpc":
            j = _json(payload)
            if not isinstance(j, dict):
                return
            src = _txt(j.get("src"), 60)
            if not (SHELLY2_RX.match(src) or SHELLY2_RX.match(sid) or ("shelly:" + _txt(sid)) in self.devs):
                return  # κάποιο άλλο σύστημα που χρησιμοποιεί …/events/rpc
            if j.get("method") in ("NotifyStatus", "NotifyFullStatus") and isinstance(j.get("params"), dict):
                parts = {k: v for k, v in j["params"].items() if isinstance(v, dict)}
        elif sub.startswith("status/") and len(p) == 3:
            j = _json(payload)
            if not isinstance(j, dict):
                return
            parts = {p[2]: j}
        else:
            d = self.devs.get("shelly:" + _txt(sid))
            if d is not None:
                self._touch(d, t, retained)
            return
        d = self._dev("shelly", sid, t)
        if d is None:
            return
        self._touch(d, t, retained)
        d["model"] = d["model"] or (sid.rsplit("-", 1)[0] if "-" in sid else "")
        d["power"] = d["power"] or "mains"
        sysd, wifi = parts.get("sys") or {}, parts.get("wifi") or {}
        d["mac"] = norm_mac(sysd.get("mac")) or d["mac"]
        au = sysd.get("available_updates")
        if isinstance(au, dict):
            st = au.get("stable") if isinstance(au.get("stable"), dict) else None  # οι beta δεν μετράνε ως «υπάρχει ενημέρωση»
            d["update"], d["update_to"] = bool(st), _txt((st or {}).get("version"), 24)
        if _num(wifi.get("rssi"), -130, 0) is not None:
            d["rssi"] = wifi["rssi"]
        d["ip"] = _ip(wifi.get("sta_ip")) or d["ip"]
        for k, v in parts.items():
            if k.startswith("devicepower") and isinstance(v.get("battery"), dict) and _num(v["battery"].get("percent"), 0, 100) is not None:
                d["batt"], d["power"] = v["battery"]["percent"], "battery"

    # ESPHome + Home-Assistant discovery
    def _esphome(self, p, payload, retained, t):
        prefix = p[0]
        if prefix.lower() in RESERVED or not _txt(prefix):
            return
        if p[1] == "debug":
            d = self.devs.get("esphome:" + _txt(prefix))
            if d is not None:
                self._touch(d, t, retained)
            return
        w = _word(payload)
        if w not in ("online", "offline"):
            return
        d = self._dev("esphome", prefix, t)
        if d is not None:
            self._online(d, w == "online", t)
            self._touch(d, t, retained or w != "online")
            d["power"] = d["power"] or "mains"

    def _discovery(self, p, payload, t):
        if len(p) not in (4, 5) or p[-1] != "config" or len(payload) > MAX_SMALL:
            return
        j = _json(payload)
        if not isinstance(j, dict):
            return
        dev = j.get("device") if isinstance(j.get("device"), dict) else j.get("dev") if isinstance(j.get("dev"), dict) else None
        if dev is None:
            return

        def g(full, short):
            return dev.get(full) if full in dev else dev.get(short)
        ids = g("identifiers", "ids")
        ids = [_txt(x) for x in (ids if isinstance(ids, list) else [ids])[:8] if _txt(x)]
        sw, mf = _txt(g("sw_version", "sw"), 60), _txt(g("manufacturer", "mf"), 40)
        if any(i.startswith("zigbee2mqtt_") for i in ids) or "tasmota" in sw.lower() or mf.lower() == "tasmota":
            return  # τα ξέρουμε καλύτερα από τα δικά τους topics
        avty = j.get("availability_topic") or j.get("avty_t")
        if not isinstance(avty, str):
            lst = j.get("availability") or j.get("avty")
            first = lst[0] if isinstance(lst, list) and lst and isinstance(lst[0], dict) else {}
            avty = first.get("topic") or first.get("t")
        avty = _txt(avty, MAX_TOPIC) if isinstance(avty, str) else ""
        esph = "esphome" in sw.lower() or mf.lower() in ("espressif", "esphome")
        node = p[2]
        if esph:
            d = self._dev("esphome", avty[:-7] if avty.endswith("/status") and "/" not in avty[:-7] else (ids[0] if ids else node), t)
        else:
            d = self._dev("ha", ids[0] if ids else node, t)
        if d is None:
            return
        d["name"] = _txt(g("name", "name")) or d["name"]
        d["model"], d["vendor"] = _txt(g("model", "mdl"), 60) or d["model"], mf or d["vendor"]
        m = re.search(r"v?\d+\.\d+[\w.\-]*", sw)
        d["fw"] = (m.group(0) if esph and m else sw) or d["fw"]
        cns = g("connections", "cns")
        for c in (cns if isinstance(cns, list) else [])[:4]:
            if isinstance(c, list) and len(c) == 2 and c[0] == "mac":
                d["mac"] = norm_mac(c[1]) or d["mac"]
        if avty and (avty in self.avail or len(self.avail) < MAX_AVAIL):
            self.avail[avty] = (d["src"] + ":" + d["id"], _txt(j.get("payload_available") or j.get("pl_avail") or "online", 32),
                                _txt(j.get("payload_not_available") or j.get("pl_not_avail") or "offline", 32))

    # ── κανόνες υγείας ──
    @staticmethod
    def _on_battery(d):
        return d["power"] == "battery" or (d["batt"] is not None and d["power"] != "mains")

    def problems(self, d, now):
        """→ [{"code", "sev", "el", "en"}] για μία συσκευή."""
        out = []
        bt = battery_of(d["model"])
        off = False
        if d["online"] is False and d["off_since"] and now - d["off_since"] > OFF_MAINS:
            mins = int((now - d["off_since"]) / 60)
            ago_el = f"{mins}′" if mins < 120 else f"{mins // 60} ώρες"
            ago_en = f"{mins} min" if mins < 120 else f"{mins // 60} h"
            off = True
            out.append({"code": "off", "sev": "med", "el": f"Εκτός δικτύου εδώ και {ago_el} — έλεγξε ρεύμα και σήμα", "en": f"Offline for {ago_en} — check power and signal"})
        elif self._on_battery(d) and d["last"] and now - d["last"] > SILENT_BATT:
            h = int((now - d["last"]) / 3600)
            off = True
            out.append({"code": "off", "sev": "med", "el": f"Σιωπά εδώ και {h} ώρες — άδεια μπαταρία ή εκτός εμβέλειας;", "en": f"Silent for {h} h — dead battery or out of range?"})
        if d["batt"] is not None and d["batt"] <= BATT_LOW:
            need = f" ({bt[1]}× {bt[0]})" if bt else ""
            out.append({"code": "batt", "sev": "low", "el": f"Μπαταρία {int(d['batt'])}% — άλλαξέ την{need}", "en": f"Battery {int(d['batt'])}% — replace it{need}"})
        if not off and d["lqi"] is not None and d["lqi"] < LQI_WEAK:
            out.append({"code": "weak", "sev": "info", "el": f"Αδύναμο σήμα Zigbee (LQI {int(d['lqi'])}) — βάλε router κοντά", "en": f"Weak Zigbee signal (LQI {int(d['lqi'])}) — add a router nearby"})
        if not off and d["rssi"] is not None and d["rssi"] < RSSI_WEAK:
            out.append({"code": "weak", "sev": "info", "el": f"Αδύναμο Wi-Fi ({int(d['rssi'])} dBm)", "en": f"Weak Wi-Fi ({int(d['rssi'])} dBm)"})
        if d["update"]:
            to = f" ({d['update_to']})" if d["update_to"] else ""
            out.append({"code": "update", "sev": "info", "el": f"Υπάρχει νέο firmware{to}", "en": f"Firmware update available{to}"})
        if d["interview"] == "failed":
            out.append({"code": "interview", "sev": "info", "el": "Η σύζευξη Zigbee δεν ολοκληρώθηκε — ξανακάνε pairing", "en": "Zigbee interview failed — pair it again"})
        return out

    def tick(self, now=None):
        """Έλεγχος κανόνων → ειδοποιήσεις (μία ανά συσκευή/πρόβλημα μέχρι να λυθεί)."""
        now = now or self.clock()
        fire = []
        with self.lock:
            for key, d in self.devs.items():
                codes = {p["code"] for p in self.problems(d, now)}
                al = self.alerted.get(key, {})
                for code in ("batt", "off"):
                    if code in codes and code not in al:
                        self.alerted.setdefault(key, {})[code] = now
                        self._dirty = True
                        fire.append((code, dict(d)))
                    elif code not in codes and code in al:
                        if code == "batt" and (d["batt"] is None or d["batt"] <= BATT_OK):
                            continue  # υστέρηση: 14% ↔ 16% δεν ξαναειδοποιεί
                        del al[code]
                        self._dirty = True
                        if not al:
                            self.alerted.pop(key, None)
        st = self.state
        if not self.demo and st is not None and hasattr(st, "alert"):
            for code, d in fire:
                src = SRC[d["src"]][0]
                what = f"«{d['name']}» ({src}" + (f", {d['model']}" if d["model"] else "") + ")"
                actor = d["ip"] or "mqtt"
                if code == "batt":
                    bt = battery_of(d["model"])
                    st.alert("Χαμηλή μπαταρία σε συσκευή IoT", "low", actor, d["name"],
                             f"Η συσκευή {what} έχει μπαταρία {int(d['batt'])}%." + (f" Θέλει {bt[1]}× {bt[0]}." if bt else "")
                             + " Άλλαξέ την πριν σταματήσει να στέλνει.", now, key=("iotinv", d["src"], d["id"], "batt"), cooldown=86400, mark=False)
                elif d["online"] is False:
                    st.alert("Συσκευή IoT εκτός δικτύου", "med", actor, d["name"],
                             f"Η συσκευή {what} είναι εκτός δικτύου εδώ και {int((now - (d['off_since'] or now)) / 60)}′. Έλεγξε ρεύμα και σήμα Wi-Fi/Zigbee.",
                             now, key=("iotinv", d["src"], d["id"], "off"), cooldown=86400, mark=False)
                else:
                    st.alert("Συσκευή IoT εκτός δικτύου", "med", actor, d["name"],
                             f"Η συσκευή μπαταρίας {what} δεν έχει στείλει τίποτα εδώ και {int((now - (d['last'] or now)) / 3600)} ώρες — "
                             "άδεια μπαταρία ή εκτός εμβέλειας;", now, key=("iotinv", d["src"], d["id"], "off"), cooldown=86400, mark=False)
        if self._dirty and (fire or now - self._saved > 60):
            self._save()
        return [(c, d["src"] + ":" + d["id"]) for c, d in fire]

    # ── προβολή ──
    def _hosts(self):
        st = self.state
        by_ip, by_mac = {}, {}
        hosts = getattr(st, "hosts", None) if st is not None else None
        if not isinstance(hosts, dict):
            return by_ip, by_mac
        lock = getattr(st, "lock", None)
        try:
            if lock:
                lock.acquire()
            hs = [dict(h) for h in hosts.values() if isinstance(h, dict)]
        finally:
            if lock:
                lock.release()
        for h in hs:
            names = sorted(str(n) for n in (h.get("names") or ()))
            x = {"ip": h.get("ip") or "", "name": names[0] if names else ""}
            if x["ip"]:
                by_ip[x["ip"]] = x
            m = norm_mac(h.get("mac"))
            if m:
                by_mac[m] = x
        return by_ip, by_mac

    def rows(self, now=None):
        now = now or self.clock()
        by_ip, by_mac = self._hosts()
        out = []
        with self.lock:
            for key, d in self.devs.items():
                pr = self.problems(d, now)
                h = by_ip.get(d["ip"]) or by_mac.get(d["mac"])
                bt = battery_of(d["model"]) if self._on_battery(d) else None
                off = any(p["code"] == "off" for p in pr)
                online = d["online"]
                if online is None and d["type"] == "Coordinator" and self.z2m.get("state"):
                    online = self.z2m["state"] == "online"
                out.append({"key": key, "src": d["src"], "src_label": SRC[d["src"]][0], "icon": SRC[d["src"]][1], "name": d["name"], "model": d["model"],
                            "vendor": d["vendor"], "ip": d["ip"] or (h["ip"] if h else ""), "mac": d["mac"], "ieee": d["ieee"], "fw": d["fw"],
                            "update": d["update"], "update_to": d["update_to"], "batt": d["batt"], "btype": f"{bt[1]}× {bt[0]}" if bt else "",
                            "lqi": d["lqi"], "rssi": d["rssi"], "power": "battery" if self._on_battery(d) else d["power"], "type": d["type"],
                            "online": False if off else online, "last": d["last"], "host": h, "problems": pr,
                            "rank": min([{"med": 0, "low": 1, "info": 2}[p["sev"]] for p in pr] or [3])})
        out.sort(key=lambda r: (r["rank"], r["src"], r["name"].lower()))
        return out

    def shopping(self, rows):
        """Λίστα αγορών μπαταριών: ό,τι είναι ≤25% ή σιωπά, ομαδοποιημένο ανά τύπο."""
        g = {}
        for r in rows:
            if r["power"] != "battery":
                continue
            dead = any(p["code"] == "off" for p in r["problems"])
            if not dead and (r["batt"] is None or r["batt"] > BATT_SHOP):
                continue
            bt = battery_of(r["model"])
            typ, qty = (bt[0], bt[1]) if bt else ("", 1)
            x = g.setdefault(typ, {"type": typ, "qty": 0, "devices": []})
            x["qty"] += qty
            x["devices"].append({"name": r["name"], "model": r["model"], "batt": r["batt"], "qty": qty})
        return sorted(g.values(), key=lambda x: (x["type"] == "", x["type"]))

    def view(self):
        now = self.clock()
        if self.demo and now - self._t0 > 60:  # demo που τρέχει μέρες: οι χρόνοι «κυλούν» μαζί με το ρολόι
            with self.lock:
                dt, self._t0 = now - self._t0, now
                for d in self.devs.values():
                    for k in ("first", "last", "off_since"):
                        if d[k]:
                            d[k] += dt
                self.last_msg = now - 3
        try:
            self.tick(now)
        except Exception:  # noqa: BLE001
            pass
        rows = self.rows(now)
        has = lambda r, c: any(p["code"] == c for p in r["problems"])  # noqa: E731
        mq = getattr(self.state, "mqtt", None) if self.state is not None else None
        counts = {"total": len(rows), "online": sum(1 for r in rows if r["online"] is True), "offline": sum(1 for r in rows if has(r, "off")),
                  "batt": sum(1 for r in rows if has(r, "batt")), "weak": sum(1 for r in rows if has(r, "weak")),
                  "update": sum(1 for r in rows if has(r, "update")), "battery_devices": sum(1 for r in rows if r["power"] == "battery"),
                  "by_src": {s: sum(1 for r in rows if r["src"] == s) for s in SRC if any(r["src"] == s for r in rows)}}
        with self.lock:
            z2m = dict(self.z2m)
        return {"demo": self.demo, "now": now, "devices": rows, "counts": counts, "shopping": self.shopping(rows), "z2m": z2m,
                "sources": {k: {"label": v[0], "icon": v[1]} for k, v in SRC.items()},
                "mqtt": {"configured": bool(getattr(mq, "configured", False)) or self.demo, "connected": bool(getattr(mq, "connected", False)) or self.demo,
                         "msgs": self.msgs, "last": self.last_msg},
                "thresholds": {"batt": BATT_LOW, "lqi": LQI_WEAK, "rssi": RSSI_WEAK, "silent_h": SILENT_BATT // 3600, "off_min": OFF_MAINS // 60}}

    def csv(self):
        rows = self.rows()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["source", "name", "model", "vendor", "ip", "mac", "ieee", "firmware", "update_available", "battery_pct", "battery_type",
                    "lqi", "rssi_dbm", "power", "online", "last_seen", "problems"])
        for r in rows:
            last = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["last"])) if r["last"] else ""
            w.writerow([_csv_cell(x) for x in (
                r["src_label"], r["name"], r["model"], r["vendor"], r["ip"], r["mac"], r["ieee"], r["fw"], "yes" if r["update"] else "",
                "" if r["batt"] is None else int(r["batt"]), r["btype"], "" if r["lqi"] is None else int(r["lqi"]),
                "" if r["rssi"] is None else int(r["rssi"]), r["power"], {True: "yes", False: "no"}.get(r["online"], ""), last,
                "; ".join(p["el"] for p in r["problems"]))])
        return ("﻿" + buf.getvalue()).encode("utf-8")  # BOM: το Excel ανοίγει σωστά τα ελληνικά

    def api(self, method, sub, q, body):
        if method == "GET" and sub == "":
            return 200, self.view()
        if method == "GET" and sub == "csv":
            return 200, {"_raw": self.csv(), "_type": "text/csv; charset=utf-8", "_name": "iot-inventory.csv"}
        return 404, {"error": "not found"}

    def run_forever(self):
        while True:
            time.sleep(60)
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                pass

    # ── demo ──
    def _demo_seed(self):
        t = self._t0 = self.clock()
        J = lambda o: json.dumps(o).encode()  # noqa: E731,N806
        h = self.handle

        def zd(name, ieee, typ, model, vendor, power, sw=None):
            return {"friendly_name": name, "ieee_address": ieee, "type": typ, "power_source": power, "software_build_id": sw,
                    "interview_completed": True, "definition": {"model": model, "vendor": vendor}}
        h("zigbee2mqtt/bridge/state", J({"state": "online"}), True, t)
        h("zigbee2mqtt/bridge/info", J({"version": "1.39.1", "coordinator": {"type": "zStack3x0"}, "permit_join": False,
                                        "network": {"channel": 11, "pan_id": 6754}}), True, t)
        h("zigbee2mqtt/bridge/devices", J([
            {"friendly_name": "Coordinator", "ieee_address": "0x00124b0024c1a7f3", "type": "Coordinator", "interview_completed": True},
            zd("Σαλόνι · θερμοκρασία", "0x00158d0003a1b2c3", "EndDevice", "WSDCGQ11LM", "Aqara", "Battery", "3000-0001"),
            zd("Είσοδος · πόρτα", "0x00158d0004d5e6f7", "EndDevice", "MCCGQ11LM", "Aqara", "Battery", "3000-0001"),
            zd("Κουζίνα · πρίζα", "0x000d6ffffe9a8b7c", "Router", "E1603/E1702/E1708", "IKEA", "Mains (single phase)", "2.0.024"),
            zd("Διάδρομος · κίνηση", "0x14b457fffe6c5d4e", "EndDevice", "E1525/E1745", "IKEA", "Battery", "2.0.022"),
            zd("Αποθήκη · διαρροή", "0x00158d0005a9b8c7", "EndDevice", "SJCGQ11LM", "Aqara", "Battery", "3000-0001"),
            zd("Γραφείο · λάμπα", "0x0017880108a1b2c3", "Router", "9290022166", "Philips", "Mains (single phase)", "1.104.2"),
        ]), True, t)
        h("zigbee2mqtt/Coordinator/availability", J({"state": "online"}), True, t)
        h("zigbee2mqtt/Σαλόνι · θερμοκρασία", J({"battery": 12, "linkquality": 78, "temperature": 21.4, "humidity": 52}), False, t - 1400)
        h("zigbee2mqtt/Είσοδος · πόρτα", J({"battery": 87, "linkquality": 31, "contact": True}), False, t - 5200)
        h("zigbee2mqtt/Κουζίνα · πρίζα", J({"linkquality": 142, "state": "ON", "update": {"state": "available", "installed_version": 33,
                                                                                         "latest_version": 36}}), False, t - 40)
        h("zigbee2mqtt/Κουζίνα · πρίζα/availability", J({"state": "online"}), True, t)
        h("zigbee2mqtt/Διάδρομος · κίνηση", J({"battery": 64, "linkquality": 96, "occupancy": False}), False, t - 610)
        h("zigbee2mqtt/Αποθήκη · διαρροή", J({"battery": 21, "linkquality": 47, "water_leak": False}), False, t - 31 * 3600)
        h("zigbee2mqtt/Γραφείο · λάμπα", J({"linkquality": 201, "state": "OFF", "update": {"state": "idle"}}), False, t - 95)
        h("zigbee2mqtt/Γραφείο · λάμπα/availability", J({"state": "online"}), True, t)
        # Tasmota
        for topic, mod, ver, ip, sig, lwt in (("sonoff-boiler", "Sonoff Basic", "13.4.0(tasmota)", "192.168.1.41", -58, "Online"),
                                              ("plug-washer", "BlitzWolf SHP", "12.5.0(tasmota)", "192.168.1.42", -84, "Online"),
                                              ("tasmota-garage", "Sonoff Mini", "13.1.0(tasmota)", "192.168.1.43", -71, "Offline")):
            h(f"tele/{topic}/INFO1", J({"Info1": {"Module": mod, "Version": ver, "FallbackTopic": f"cmnd/DVES_{topic}_fb/", "GroupTopic": "cmnd/tasmotas/"}}), True, t)
            h(f"tele/{topic}/INFO2", J({"Info2": {"WebServerMode": "Admin", "Hostname": topic, "IPAddress": ip}}), True, t)
            off = lwt == "Offline"
            h(f"tele/{topic}/STATE", J({"Time": "2026-01-01T10:00:00", "Uptime": "3T02:11:09", "UptimeSec": 267069, "POWER": "ON",
                                        "Wifi": {"AP": 1, "SSId": "IoT", "Channel": 6, "RSSI": 2 * (sig + 100), "Signal": sig}}), False, t - (2400 if off else 120))
            h(f"tele/{topic}/LWT", lwt.encode(), True, t - (2400 if off else 0))
        # Shelly
        h("shellies/announce", J({"id": "shelly1-98F4AB", "model": "SHSW-1", "mac": "98F4ABD01122", "ip": "192.168.1.51", "new_fw": True,
                                  "fw_ver": "20221027-091427/v1.12.1-ga9117d3"}), False, t - 300)
        h("shellies/shelly1-98F4AB/online", b"true", True, t)
        h("shellies/announce", J({"id": "shellyht-A1B2C3", "model": "SHHT-1", "mac": "E868E7A1B2C3", "ip": "192.168.1.52", "new_fw": False,
                                  "fw_ver": "20230913-112531/v1.14.0-gcb84623"}), False, t - 2 * 3600)
        h("shellies/shellyht-A1B2C3/sensor/battery", b"9", False, t - 2 * 3600)
        h("shellyplus1pm-a8032abe54dc/online", b"true", True, t)
        h("shellyplus1pm-a8032abe54dc/status/sys", J({"mac": "A8032ABE54DC", "uptime": 812345, "available_updates": {"stable": {"version": "1.4.4"}}}), False, t - 60)
        h("shellyplus1pm-a8032abe54dc/status/wifi", J({"sta_ip": "192.168.1.53", "status": "got ip", "ssid": "IoT", "rssi": -61}), False, t - 60)
        # ESPHome + γενικό discovery
        h("homeassistant/sensor/rack-fan/uptime/config", J({"name": "Uptime", "stat_t": "rack-fan/sensor/uptime/state", "avty_t": "rack-fan/status",
                                                            "uniq_id": "ESPsensoruptime", "dev": {"ids": "a0b765c1d2e3", "name": "rack-fan", "sw": "esphome v2024.6.4 Jun 30 2024",
                                                                                                  "mdl": "esp32dev", "mf": "espressif", "cns": [["mac", "a0b765c1d2e3"]]}}), True, t)
        h("rack-fan/status", b"online", True, t)
        h("rack-fan/debug", b"[D][sensor:094]: 'Uptime': Sending state 81234.0 s", False, t - 15)
        h("garden-pump/status", b"online", True, t)
        h("garden-pump/debug", b"[D][switch:012]: 'Pump' Turning OFF", False, t - 260)
        h("homeassistant/sensor/OMG_ESP32_BLE/SYSuptime/config", J({
            "name": "SYS: Uptime", "state_topic": "home/OMG_ESP32_BLE/SYStoMQTT", "availability_topic": "home/OMG_ESP32_BLE/LWT",
            "device": {"identifiers": ["OMG_ESP32_BLE"], "name": "OpenMQTTGateway BLE", "manufacturer": "OMG_community", "model": "esp32dev-ble",
                       "sw_version": "v1.7.0", "connections": [["mac", "24:6f:28:aa:bb:cc"]]}}), True, t)
        h("home/OMG_ESP32_BLE/LWT", b"online", True, t)
        self.devs["tasmota:tasmota-garage"]["off_since"] = t - 2400
        self.devs["z2m:Αποθήκη · διαρροή"]["last"] = t - 31 * 3600
        self.msgs, self.last_msg = 18342, t - 3
