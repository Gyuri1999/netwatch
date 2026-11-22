"""📻 Ασύρματα IoT: Bluetooth LE, Zigbee/Thread (802.15.4) και LoRa — ό,τι «ακούνε» οι αισθητήρες σου.

Δεν εκπέμπει τίποτα και δεν αγγίζει το δίκτυο: διαβάζει μόνο τις λίστες «items» που στέλνουν οι αισθητήρες
της καρτέλας 🧩 Οι συσκευές μου (`state.probes.items(kind)`):
  • ble    — ESP32 σαρωτής: ποιες συσκευές διαφημίζονται, τι είναι (AirTag/Find My, iBeacon, Tile, SmartTag…),
             ποιος σαρωτής τις ακούει καλύτερα (≈ πού βρίσκονται) και αν ένα ΑΓΝΩΣΤΟ tracker μένει κοντά για ώρες.
  • zigbee — nRF52840 sniffer: κίνηση ανά κανάλι 11–26, δίκτυα (PAN), αδύναμα links και — το πιο χρήσιμο για τον
             τεχνικό — αν ένα PAN κάθεται κάτω από κανάλι Wi-Fi 2.4 GHz και ποιο κανάλι είναι καθαρό.
  • lora   — ESP32 πύλη: κόμβοι με RSSI/SNR, μπαταρία, πότε μίλησαν, περιθώριο ζεύξης ως προς την ευαισθησία του SF.
Ποτέ δεν αποκρυπτογραφούμε ή κρατάμε περιεχόμενο· μόνο διευθύνσεις, σήμα και μετρητές.
"""
import json
import os
import re
import threading
import time

MAX_BLE = 600          # συσκευές BLE στη μνήμη
MAX_SAVE = 400         # … και στον δίσκο
MAX_LABELS = 200
FRESH = 300            # αναφορά σαρωτή παλαιότερη από 5′ δεν μετρά ως «τώρα»
PAIR_NEW = 30 * 60     # «σε λειτουργία pairing;» μόνο για συσκευές που εμφανίστηκαν το τελευταίο μισάωρο
CHURN_TTL = 30 * 60    # τυχαίες διευθύνσεις που δεν ξαναφάνηκαν σβήνουν σε 30′
TRACK_SECS = 2 * 3600  # tracker «μένει κοντά»: το βλέπουμε τουλάχιστον 2 ώρες …
TRACK_HITS = 20        # … σε τουλάχιστον 20 αναφορές σαρωτή
LQI_WEAK, RSSI_WEAK = 60, -85   # 802.15.4: LQI 0–255, RSSI dBm
LORA_SILENT = 3600
LORA_BATT_LOW = 3.3    # V (1 κελί Li-ion/LiPo)
LORA_MARGIN = 10       # dB περιθώριο που θέλουμε πάνω από την ευαισθησία
MAC_RX = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

# Bluetooth SIG «company identifiers» (assigned numbers) — μόνο όσα είμαι σίγουρος
COMPANY = {
    0x0000: "Ericsson", 0x0001: "Nokia", 0x0002: "Intel", 0x0003: "IBM", 0x0004: "Toshiba", 0x0006: "Microsoft",
    0x0008: "Motorola", 0x000A: "Qualcomm (CSR)", 0x000D: "Texas Instruments", 0x000F: "Broadcom", 0x001D: "Qualcomm",
    0x0025: "NXP", 0x0030: "STMicroelectronics", 0x0046: "MediaTek", 0x0047: "Bluegiga", 0x0048: "Marvell",
    0x004C: "Apple", 0x0055: "Plantronics", 0x0056: "Sony Ericsson", 0x0057: "Harman", 0x0059: "Nordic Semiconductor",
    0x005D: "Realtek", 0x0067: "GN Netcom (Jabra)", 0x0075: "Samsung", 0x0078: "Nike", 0x0087: "Garmin", 0x009E: "Bose",
    0x00C4: "LG Electronics", 0x00CD: "Microchip", 0x00D2: "Dialog Semiconductor", 0x00E0: "Google",
    0x0103: "Bang & Olufsen", 0x0118: "Radius Networks", 0x012D: "Sony", 0x0131: "Cypress", 0x0157: "Huami (Amazfit / Mi Band)",
    0x015D: "Estimote", 0x0171: "Amazon", 0x01DA: "Logitech", 0x027D: "Huawei", 0x02E5: "Espressif", 0x038F: "Xiaomi",
    0x0499: "Ruuvi", 0x07D0: "Tuya", 0x0969: "SwitchBot (Woan)",
}
UNOFFICIAL = {0xEC88: "Govee"}  # το βάζουν στα manufacturer data χωρίς να είναι επίσημα δικό τους

# κωδικός → (ελληνικά, αγγλικά, εικονίδιο, είναι tracker;)
KIND = {
    "findmy": ("Tracker Apple Find My (AirTag ή συμβατό)", "Apple Find My tracker (AirTag or compatible)", "🏷", True),
    "tile": ("Tracker Tile", "Tile tracker", "🏷", True),
    "smarttag": ("Samsung SmartTag", "Samsung SmartTag", "🏷", True),
    "ibeacon": ("iBeacon (φάρος θέσης)", "iBeacon (location beacon)", "📍", False),
    "eddystone": ("Eddystone (φάρος Google)", "Eddystone (Google beacon)", "📍", False),
    "fastpair": ("Google Fast Pair (ακουστικά/αξεσουάρ)", "Google Fast Pair (earbuds/accessory)", "🎧", False),
    "airpods": ("Ακουστικά Apple (AirPods/Beats)", "Apple earbuds (AirPods/Beats)", "🎧", False),
    "apple": ("Συσκευή Apple (iPhone/Mac/Watch)", "Apple device (iPhone/Mac/Watch)", "🍎", False),
    "microsoft": ("Υπολογιστής Windows (Swift Pair)", "Windows computer (Swift Pair)", "💻", False),
    "samsung": ("Συσκευή Samsung", "Samsung device", "📱", False),
    "mi": ("Αισθητήρας Xiaomi / Mi", "Xiaomi / Mi sensor", "🌡", False),
    "ruuvi": ("Αισθητήρας Ruuvi", "Ruuvi sensor", "🌡", False),
    "govee": ("Αισθητήρας Govee", "Govee sensor", "🌡", False),
    "switchbot": ("SwitchBot", "SwitchBot", "🤖", False),
    "bthome": ("Αισθητήρας BTHome", "BTHome sensor", "🌡", False),
    "tuya": ("Συσκευή Tuya / Smart Life", "Tuya / Smart Life device", "💡", False),
    "hue": ("Φωτισμός Philips Hue", "Philips Hue light", "💡", False),
    "band": ("Ρολόι / βραχιόλι fitness", "Watch / fitness band", "⌚", False),
    "hid": ("Πληκτρολόγιο / ποντίκι / χειριστήριο", "Keyboard / mouse / controller", "⌨", False),
    "sensor": ("Αισθητήρας BLE", "BLE sensor", "🌡", False),
    "exposure": ("Κινητό (Exposure Notification)", "Phone (Exposure Notification)", "📱", False),
    "uart": ("Μονάδα BLE-σειριακής (HM-10 κ.ά.)", "BLE serial module (HM-10 etc.)", "🔧", False),
    "esp": ("Συσκευή ESP32 (Espressif)", "ESP32 device (Espressif)", "📟", False),
    "other": ("Συσκευή Bluetooth", "Bluetooth device", "🔵", False),
}
SVC = {"feed": "tile", "feec": "tile", "fd5a": "smarttag", "fe2c": "fastpair", "feaa": "eddystone", "fe95": "mi", "fd3d": "switchbot",
       "fcd2": "bthome", "fe0f": "hue", "fee0": "band", "1812": "hid", "181a": "sensor", "fd6f": "exposure", "ffe0": "uart"}
MFR_KIND = {0x0499: "ruuvi", 0xEC88: "govee", 0x0969: "switchbot", 0x07D0: "tuya", 0x038F: "mi", 0x0157: "band", 0x0006: "microsoft",
            0x0075: "samsung", 0x02E5: "esp", 0x0087: "band"}
APPLE_TYPE = {0x07: "airpods", 0x12: "findmy"}

# LoRa (SX127x, BW 125 kHz): ευαισθησία δέκτη και ελάχιστο SNR ανά spreading factor
LORA_SENS = {7: -123, 8: -126, 9: -129, 10: -132, 11: -133, 12: -136}
LORA_SNR = {7: -7.5, 8: -10, 9: -12.5, 10: -15, 11: -17.5, 12: -20}


def _txt(x, n=40):
    return "".join(c for c in str(x if x is not None else "") if c.isprintable())[:n]


def _n(x, lo=-1e9, hi=1e9):
    if isinstance(x, bool) or not isinstance(x, (int, float)) or x != x or not lo <= x <= hi:
        return None
    return x


def norm_mac(x):
    s = str(x or "").strip().lower().replace("-", ":")
    if re.match(r"^[0-9a-f]{12}$", s):
        s = ":".join(s[i:i + 2] for i in range(0, 12, 2))
    return s if MAC_RX.match(s) else None


def vendor(mfr):
    return COMPANY.get(mfr) or UNOFFICIAL.get(mfr) or ""


def _adbytes(mfr, ad):
    """Τα manufacturer data ΧΩΡΙΣ το company id (κάποια firmware το αφήνουν μπροστά, little-endian)."""
    h = re.sub(r"[^0-9a-f]", "", str(ad or "").lower())[:48]
    if len(h) % 2:
        h = h[:-1]
    b = bytes.fromhex(h)
    if isinstance(mfr, int) and 0 <= mfr <= 0xFFFF and len(b) >= 2 and b[0] == (mfr & 0xFF) and b[1] == (mfr >> 8):
        b = b[2:]
    return b


def classify(row):
    """Γραμμή σαρωτή BLE → {"kind", "vendor", "tracker", "sep"} από company id / service uuid / αρχή των manufacturer data."""
    mfr = row.get("mfr")
    mfr = mfr if isinstance(mfr, int) and not isinstance(mfr, bool) and 0 <= mfr <= 0xFFFF else -1
    svc = re.sub(r"[^0-9a-f]", "", str(row.get("svc") or "").lower())[:4]
    ad = _adbytes(mfr, row.get("ad"))
    kind, sep = None, False
    if mfr == 0x004C:
        t, ln = (ad[0] if ad else None), (ad[1] if len(ad) > 1 else None)
        if t == 0x02 and ln == 0x15:
            kind = "ibeacon"
        elif t in APPLE_TYPE:
            kind = APPLE_TYPE[t]
            sep = t == 0x12 and ln == 0x19  # «χωρισμένο από τον ιδιοκτήτη του» — αυτό που εκπέμπει ένα AirTag που ταξιδεύει μόνο του
        else:
            kind = "apple"
    if kind is None and svc in SVC:
        kind = SVC[svc]
    if kind is None and mfr in MFR_KIND:
        kind = MFR_KIND[mfr]
    if kind is None and len(ad) >= 2 and ad[0] == 0x02 and ad[1] == 0x15:
        kind = "ibeacon"  # iBeacon από άλλους κατασκευαστές (ίδια μορφή)
    kind = kind or "other"
    v = vendor(mfr) or {"tile": "Tile", "smarttag": "Samsung", "mi": "Xiaomi", "switchbot": "SwitchBot (Woan)", "hue": "Signify (Philips Hue)",
                        "eddystone": "", "fastpair": ""}.get(kind, "")
    return {"kind": kind, "vendor": v, "tracker": KIND[kind][3], "sep": sep}


# ── 802.15.4 ↔ Wi-Fi 2.4 GHz ──
CLASSIC = (15, 20, 25, 26)  # ανάμεσα/πάνω από τα Wi-Fi 1, 6, 11


def zb_mhz(ch):
    return 2405 + 5 * (ch - 11)


def wifi_mhz(ch):
    return 2484 if ch == 14 else 2407 + 5 * ch


def overlap(zch, wifi_ch, width=20):
    """Πέφτει το κανάλι Zigbee `zch` (11–26, πλάτος 2 MHz) μέσα στο κανάλι Wi-Fi `wifi_ch` (1–14, πλάτος `width` MHz);"""
    try:
        zch, wifi_ch, width = int(zch), int(wifi_ch), float(width)
    except (TypeError, ValueError):
        return False
    if not 11 <= zch <= 26 or not 1 <= wifi_ch <= 14 or width <= 0:
        return False
    return abs(zb_mhz(zch) - wifi_mhz(wifi_ch)) < width / 2 + 1


def clean_channels(wifi, activity=None):
    """Κανάλια Zigbee που δεν τα σκεπάζει κανένα από τα Wi-Fi [(ch, width)…]. Πρώτα τα «κλασικά» 15/20/25 (μένουν καθαρά
    ακόμη κι αν εμφανιστεί γείτονας στα 1/6/11), μετά τα πιο ήσυχα· το 26 τελευταίο (πολλές συσκευές εκπέμπουν εκεί με
    μειωμένη ισχύ ή δεν το υποστηρίζουν καθόλου)."""
    activity = activity or {}
    free = [c for c in range(11, 27) if not any(overlap(c, w, wd) for w, wd in wifi)]
    return sorted(free, key=lambda c: (c == 26, c not in CLASSIC, activity.get(c, 0), c))


def parse_channels(x):
    """«1, 6, 11» ή [1, 6, 11] → ταξινομημένη λίστα έγκυρων καναλιών Wi-Fi 2.4 GHz (έως 14)."""
    if isinstance(x, str):
        x = re.findall(r"\d+", x[:200])
    if not isinstance(x, (list, tuple)):
        return []
    out = set()
    for v in list(x)[:40]:
        try:
            v = int(v)
        except (TypeError, ValueError):
            continue
        if 1 <= v <= 14:
            out.add(v)
    return sorted(out)


def lora_margin(rssi, snr=None, sf=7):
    """→ (περιθώριο dB, ελάχιστο SF που δίνει ≥10 dB ή None). Το περιθώριο είναι το μικρότερο από RSSI−ευαισθησία και SNR−όριο."""
    sf = sf if sf in LORA_SENS else 7
    if _n(rssi) is None:
        return None, None

    def m(s):
        a = rssi - LORA_SENS[s]
        return min(a, snr - LORA_SNR[s]) if _n(snr) is not None else a
    need = next((s for s in sorted(LORA_SENS) if m(s) >= LORA_MARGIN), None)
    return round(m(sf), 1), need


class Radio:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time):
        self.state, self.demo, self.clock = state, demo, clock
        self.path = os.path.join(data_dir, "radio.json") if data_dir else None
        self.on_save = None
        self.lock = threading.RLock()
        self.ble = {}       # mac → {first, last, hits, name, mfr, svc, ad, rnd, conn, alerted}
        self.labels = {}    # mac → {"label", "mode": "known" | "ignored"}
        self.wifi_manual = []
        self.cur = {"ble": {}, "zigbee": {}, "lora": {}}  # kind → probe id → {name, seen, items, metrics}
        self._seen = {}     # probe id → τελευταίο «seen» που επεξεργαστήκαμε
        self._dirty, self._saved = False, 0
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
            for mac, d in list((j.get("ble") or {}).items())[:MAX_SAVE]:
                mac = norm_mac(mac)
                if mac and isinstance(d, dict):
                    self.ble[mac] = {"first": float(d.get("first") or 0), "last": float(d.get("last") or 0), "hits": int(d.get("hits") or 0),
                                     "name": _txt(d.get("name")), "mfr": d.get("mfr") if isinstance(d.get("mfr"), int) else -1,
                                     "svc": _txt(d.get("svc"), 4), "ad": _txt(d.get("ad"), 48), "rnd": bool(d.get("rnd")),
                                     "conn": bool(d.get("conn")), "alerted": bool(d.get("alerted"))}
            for mac, d in list((j.get("labels") or {}).items())[:MAX_LABELS]:
                mac = norm_mac(mac)
                if mac and isinstance(d, dict) and d.get("mode") in ("known", "ignored"):
                    self.labels[mac] = {"label": _txt(d.get("label")), "mode": d["mode"]}
            self.wifi_manual = parse_channels(j.get("wifi"))
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save(self):
        self._dirty, self._saved = False, self.clock()
        if not self.path:
            return
        with self.lock:
            keep = sorted(((m, d) for m, d in self.ble.items() if d["hits"] >= 3 or d.get("alerted") or m in self.labels),
                          key=lambda x: -x[1]["last"])[:MAX_SAVE]
            j = {"ble": dict(keep), "labels": self.labels, "wifi": self.wifi_manual}
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(j, f)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    # ── ανάγνωση αισθητήρων ──
    def _items(self, kind):
        pr = getattr(self.state, "probes", None) if self.state is not None else None
        if pr is None or not hasattr(pr, "items"):
            return []
        try:
            out = pr.items(kind)
        except Exception:  # noqa: BLE001
            return []
        return [p for p in (out if isinstance(out, list) else []) if isinstance(p, dict) and isinstance(p.get("items"), list)][:64]

    def poll(self):
        """Διάβασε τις τελευταίες λίστες των αισθητήρων· κάθε ΝΕΑ αναφορά σαρωτή BLE μετρά μία «θέαση» ανά συσκευή."""
        if self.demo:
            return
        now = self.clock()
        alerts = []
        with self.lock:
            for kind in ("ble", "zigbee", "lora"):
                cur = {}
                for p in self._items(kind):
                    pid, seen = str(p.get("id") or "")[:20], _n(p.get("seen")) or 0
                    cur[pid] = {"name": _txt(p.get("name")) or pid, "seen": seen, "items": [r for r in p["items"][:80] if isinstance(r, dict)],
                                "metrics": p.get("metrics") if isinstance(p.get("metrics"), dict) else {}}
                    if kind == "ble" and self._seen.get(pid) != seen:
                        self._seen[pid] = seen
                        alerts += self._ingest_ble(cur[pid], seen or now)
                self.cur[kind] = cur
            self._seen = {k: v for k, v in self._seen.items() if k in self.cur["ble"]}
            self._prune(now)
        for a in alerts:
            self._alert(*a)
        if self._dirty and (alerts or now - self._saved > 120):
            self._save()

    def _ingest_ble(self, sc, t):
        alerts = []
        for r in sc["items"]:
            mac = norm_mac(r.get("mac"))
            if not mac:
                continue
            d = self.ble.get(mac)
            if d is None:
                d = self.ble[mac] = {"first": t, "last": t, "hits": 0, "name": "", "mfr": -1, "svc": "", "ad": "", "rnd": False, "conn": False,
                                     "alerted": False}
            d["last"], d["hits"] = max(d["last"], t), d["hits"] + 1
            d["name"] = _txt(r.get("name")) or d["name"]
            if isinstance(r.get("mfr"), int) and not isinstance(r.get("mfr"), bool) and r["mfr"] >= 0:
                d["mfr"] = r["mfr"] & 0xFFFF
            d["svc"] = re.sub(r"[^0-9a-f]", "", str(r.get("svc") or "").lower())[:4] or d["svc"]
            d["ad"] = re.sub(r"[^0-9a-f]", "", str(r.get("ad") or "").lower())[:48] or d["ad"]
            d["rnd"], d["conn"] = r.get("rnd") is True, r.get("conn") is True
            self._dirty = True
            c = classify(d)
            if (c["tracker"] and not d["alerted"] and mac not in self.labels
                    and d["hits"] >= TRACK_HITS and d["last"] - d["first"] >= TRACK_SECS):
                d["alerted"] = True
                alerts.append((mac, c, d, sc["name"], t))
        return alerts

    def _prune(self, now):
        if len(self.ble) > MAX_BLE // 2:  # τυχαίες διευθύνσεις που άλλαξαν: δεν έχει νόημα να τις θυμόμαστε
            for mac in [m for m, d in self.ble.items() if d["rnd"] and d["hits"] < 3 and now - d["last"] > CHURN_TTL and m not in self.labels]:
                del self.ble[mac]
        if len(self.ble) > MAX_BLE:
            for mac, _d in sorted(self.ble.items(), key=lambda x: (x[0] in self.labels, x[1].get("alerted"), x[1]["last"]))[:len(self.ble) - MAX_BLE]:
                del self.ble[mac]

    def _alert(self, mac, c, d, scanner, t):
        st = self.state
        if st is None or not hasattr(st, "alert"):
            return
        hours = max(1, int(round((d["last"] - d["first"]) / 3600)))
        st.alert("Άγνωστο Bluetooth tracker κοντά στο δίκτυο", "med", mac, f"σαρωτής {scanner}",
                 f"Ένα {KIND[c['kind']][0]} ({mac}) εκπέμπει κοντά στον σαρωτή «{scanner}» εδώ και περίπου {hours} ώρες και δεν το έχεις "
                 "δηλώσει ως δικό σου. Αν δεν ανήκει σε κάποιον του χώρου, ψάξε το (τσάντες, όχημα, rack) — ή σημείωσέ το ως γνωστό "
                 "στην καρτέλα 📻 Ασύρματα IoT.", t, key=("ble-tracker", mac), cooldown=7 * 86400, mark=False)

    # ── ενέργειες χρήστη ──
    def set_known(self, mac, label="", mode="known"):
        mac = norm_mac(mac)
        if not mac:
            return {"error": "Άκυρη διεύθυνση MAC."}
        with self.lock:
            if mode in ("known", "ignored"):
                if mac not in self.labels and len(self.labels) >= MAX_LABELS:
                    return {"error": f"Έως {MAX_LABELS} σημειωμένες συσκευές."}
                self.labels[mac] = {"label": _txt(label).strip(), "mode": mode}
            else:
                self.labels.pop(mac, None)
                if mac in self.ble:  # ξανά «άγνωστο»: να μπορεί να ειδοποιήσει ξανά
                    self.ble[mac]["alerted"] = False
        self._save()
        return self.view()

    def set_wifi(self, channels):
        with self.lock:
            self.wifi_manual = parse_channels(channels)
        self._save()
        return self.view()

    # ── Wi-Fi σε χρήση ──
    def wifi_in_use(self):
        """→ (πηγή, [{"ch", "width", "ssid", "rssi", "own"}]) — χειροκίνητα, αλλιώς από τη χαρτογράφηση Wi-Fi αν υπάρχει."""
        if self.wifi_manual:
            return "manual", [{"ch": c, "width": 20, "ssid": "", "rssi": None, "own": True} for c in self.wifi_manual]
        if self.demo:
            return "survey", [{"ch": 1, "width": 20, "ssid": "Office-WiFi", "rssi": -48, "own": True},
                              {"ch": 6, "width": 20, "ssid": "COSMOTE-81B0", "rssi": -71, "own": False}]
        out = {}
        ws = getattr(self.state, "wifisurvey", None) if self.state is not None else None
        last = getattr(ws, "last", None)  # ΟΧΙ status(): μπορεί να ξεκινήσει σάρωση
        if isinstance(last, dict):
            nets = [n for n in (last.get("networks") or []) if isinstance(n, dict)]
            cur = last.get("current") if isinstance(last.get("current"), dict) else None
            for n in ([dict(cur, current=True)] if cur else []) + nets[:200]:
                ch, rssi = n.get("channel"), _n(n.get("rssi"))
                if str(n.get("band")) != "2.4" or not isinstance(ch, int) or not 1 <= ch <= 14:
                    continue
                own = bool(n.get("current")) or bool(cur and n.get("ssid") and n.get("ssid") == cur.get("ssid"))
                if not own and (rssi is None or rssi < -80):
                    continue  # μακρινοί γείτονες δεν ενοχλούν ουσιαστικά
                w = 40 if n.get("width") == 40 else 20
                o = out.get(ch)
                if o is None or (own and not o["own"]) or (own == o["own"] and (rssi or -999) > (o["rssi"] or -999)):
                    out[ch] = {"ch": ch, "width": w, "ssid": _txt(n.get("ssid"), 32), "rssi": rssi, "own": own}
        return ("survey" if out else "none"), sorted(out.values(), key=lambda x: x["ch"])

    # ── προβολή ──
    def _ble_view(self, now):
        best = {}  # mac → (rssi, σαρωτής, πόσοι σαρωτές)
        scanners = []
        for pid, sc in self.cur["ble"].items():
            fresh = now - sc["seen"] <= FRESH
            scanners.append({"id": pid, "name": sc["name"], "seen": sc["seen"], "n": len(sc["items"]), "fresh": fresh})
            if not fresh:
                continue
            for r in sc["items"]:
                mac, rssi = norm_mac(r.get("mac")), _n(r.get("rssi"), -130, 20)
                if not mac:
                    continue
                b = best.get(mac)
                if b is None:
                    best[mac] = [rssi, sc["name"], 1]
                else:
                    b[2] += 1
                    if rssi is not None and (b[0] is None or rssi > b[0]):
                        b[0], b[1] = rssi, sc["name"]
        rows, churn = [], 0
        for mac, d in self.ble.items():
            c = classify(d)
            lab = self.labels.get(mac)
            b = best.get(mac)
            span = d["last"] - d["first"]
            if d["rnd"] and not c["tracker"] and not lab and not d["name"] and c["kind"] in ("other", "apple", "microsoft", "exposure", "samsung"):
                churn += 1  # κινητά/λάπτοπ με διεύθυνση που αλλάζει κάθε ~15′: μόνο μέτρηση, όχι χιλιάδες γραμμές
                continue
            unknown = c["tracker"] and not lab
            stays = unknown and d["hits"] >= TRACK_HITS and span >= TRACK_SECS
            flags = []
            if stays:
                flags.append({"sev": "med", "el": f"Άγνωστο tracker που μένει κοντά εδώ και {max(1, int(round(span / 3600)))} ώρες",
                              "en": f"Unknown tracker staying nearby for {max(1, int(round(span / 3600)))} hours"})
            elif unknown:
                flags.append({"sev": "low", "el": "Tracker που δεν έχεις δηλώσει — αν μείνει ώρες, θα ειδοποιηθείς",
                              "en": "Tracker you have not marked — you will be alerted if it stays for hours"})
            if c["sep"] and unknown:
                flags.append({"sev": "med", "el": "Εκπέμπει ως «μακριά από τον ιδιοκτήτη του»", "en": "Broadcasting as “separated from its owner”"})
            # δημόσια διεύθυνση + δέχεται συνδέσεις + μόλις εμφανίστηκε ≈ συσκευή που περιμένει σύζευξη (όχι ένας αισθητήρας που είναι πάντα εκεί)
            pairing = d["conn"] and not d["rnd"] and not c["tracker"] and c["kind"] not in ("ibeacon", "eddystone") and span < PAIR_NEW
            if pairing:
                flags.append({"sev": "info", "el": "Μόλις εμφανίστηκε και δέχεται συνδέσεις από οποιονδήποτε — σε λειτουργία pairing;", "en": "Just appeared and accepts connections from anyone — in pairing mode?"})
            k = KIND[c["kind"]]
            rows.append({"mac": mac, "name": d["name"], "vendor": c["vendor"], "kind": c["kind"], "kind_el": k[0], "kind_en": k[1], "icon": k[2],
                         "tracker": c["tracker"], "unknown": unknown, "stays": stays, "pairing": pairing, "rnd": d["rnd"], "conn": d["conn"],
                         "rssi": b[0] if b else None, "where": b[1] if b else "", "scanners": b[2] if b else 0, "now": bool(b),
                         "first": d["first"], "last": d["last"], "hits": d["hits"],
                         "label": lab["label"] if lab else "", "mode": lab["mode"] if lab else "", "flags": flags})
        rows.sort(key=lambda x: (not x["stays"], not x["unknown"], x["mode"] == "ignored", not x["now"],
                                 -(x["rssi"] if x["rssi"] is not None else -999), x["mac"]))
        counts = {"total": len(rows) + churn, "listed": len(rows), "now": sum(1 for x in rows if x["now"]), "churn": churn,
                  "trackers": sum(1 for x in rows if x["tracker"]), "unknown_trackers": sum(1 for x in rows if x["unknown"]),
                  "staying": sum(1 for x in rows if x["stays"]), "pairing": sum(1 for x in rows if x["pairing"])}
        return {"scanners": sorted(scanners, key=lambda s: s["name"]), "devices": rows[:150], "counts": counts,
                "thresholds": {"hours": TRACK_SECS / 3600, "hits": TRACK_HITS}}

    def _zb_view(self, now):
        act = {c: 0 for c in range(11, 27)}
        sniffers, pans = [], {}
        for pid, sn in self.cur["zigbee"].items():
            fresh = now - sn["seen"] <= FRESH
            sniffers.append({"id": pid, "name": sn["name"], "seen": sn["seen"], "n": len(sn["items"]), "fresh": fresh})
            per = {c: 0 for c in range(11, 27)}
            have_metrics = False
            for c in range(11, 27):
                v = _n(sn["metrics"].get("ch%d" % c), 0, 1e7)
                if v is not None:
                    per[c], have_metrics = int(v), True
            for r in sn["items"]:
                ch, n = _n(r.get("ch"), 11, 26), _n(r.get("n"), 0, 1e7) or 1
                pan = re.sub(r"[^0-9a-f]", "", str(r.get("pan") or "").lower())[:4]
                src = re.sub(r"[^0-9a-f]", "", str(r.get("src") or "").lower())[:16]
                if ch is None:
                    continue
                ch, n = int(ch), int(n)
                if not have_metrics:
                    per[ch] += n
                if len(pan) != 4 or pan == "ffff":
                    continue  # broadcast PAN = αναζητήσεις δικτύου (beacon request), όχι δίκτυο
                p = pans.setdefault(pan, {"pan": pan, "chs": {}, "devs": {}, "frames": 0, "lq": 0, "lqn": 0, "rs": 0, "rsn": 0, "beacon": False,
                                          "sniffer": sn["name"]})
                p["chs"][ch] = p["chs"].get(ch, 0) + n
                p["frames"] += n
                p["beacon"] = p["beacon"] or r.get("t") == "beacon"
                lqi, rssi = _n(r.get("lqi"), 0, 255), _n(r.get("rssi"), -130, 20)
                if lqi is not None:
                    p["lq"], p["lqn"] = p["lq"] + lqi * n, p["lqn"] + n
                if rssi is not None:
                    p["rs"], p["rsn"] = p["rs"] + rssi * n, p["rsn"] + n
                if src:
                    dv = p["devs"].get(src)
                    if dv is None or (rssi is not None and (dv["rssi"] is None or rssi > dv["rssi"])):
                        p["devs"][src] = {"src": src, "rssi": rssi, "lqi": lqi, "n": n + (dv["n"] if dv else 0)}
                    else:
                        dv["n"] += n
            for c in act:
                act[c] += per[c]
        src, wifi = self.wifi_in_use()
        wl = [(w["ch"], w["width"]) for w in wifi]
        clean = clean_channels(wl, act)
        channels = [{"ch": c, "mhz": zb_mhz(c), "frames": act[c], "wifi": [w["ch"] for w in wifi if overlap(c, w["ch"], w["width"])]} for c in range(11, 27)]
        plist, advice = [], []
        for p in pans.values():
            ch = max(p["chs"], key=lambda c: p["chs"][c])
            under = [w for w in wifi if overlap(ch, w["ch"], w["width"])]
            weak = sorted((d for d in p["devs"].values() if (d["lqi"] is not None and d["lqi"] < LQI_WEAK) or (d["rssi"] is not None and d["rssi"] < RSSI_WEAK)),
                          key=lambda d: (d["rssi"] if d["rssi"] is not None else 0))[:10]
            plist.append({"pan": p["pan"], "ch": ch, "devices": len(p["devs"]), "frames": p["frames"], "sniffer": p["sniffer"],
                          "lqi": round(p["lq"] / p["lqn"]) if p["lqn"] else None, "rssi": round(p["rs"] / p["rsn"]) if p["rsn"] else None,
                          "weak": weak, "under": [{"ch": w["ch"], "ssid": w["ssid"], "own": w["own"]} for w in under]})
            if under:
                w = under[0]
                to = [c for c in clean if c != ch][:3]
                to_el = (" Καθαρά κανάλια τώρα: " + ", ".join(map(str, to)) + ".") if to else " Δεν βλέπω εντελώς καθαρό κανάλι — προτίμησε να στενέψεις το Wi-Fi σε 20 MHz και κανάλια 1/6/11."
                to_en = (" Clean channels right now: " + ", ".join(map(str, to)) + ".") if to else " I see no fully clean channel — narrow the Wi-Fi to 20 MHz on channels 1/6/11 first."
                who_el = "το δικό σου Wi-Fi" if w["own"] else "γειτονικό Wi-Fi"
                who_en = "your own Wi-Fi" if w["own"] else "a neighbour’s Wi-Fi"
                advice.append({"sev": "med", "pan": p["pan"],
                               "el": f"Το PAN {p['pan']} δουλεύει στο κανάλι Zigbee {ch} ({zb_mhz(ch)} MHz), ακριβώς κάτω από {who_el} στο κανάλι {w['ch']}"
                                     + (f" («{w['ssid']}»)" if w["ssid"] else "") + ". Το Wi-Fi εκπέμπει ~100× πιο δυνατά: περίμενε καθυστερήσεις και συσκευές που «πέφτουν»."
                                     + to_el + " Η αλλαγή καναλιού στον coordinator μπορεί να θέλει επανασύζευξη κάποιων συσκευών — αλλιώς μετακίνησε το Wi-Fi.",
                               "en": f"PAN {p['pan']} runs on Zigbee channel {ch} ({zb_mhz(ch)} MHz), right under {who_en} on channel {w['ch']}"
                                     + (f" (“{w['ssid']}”)" if w["ssid"] else "") + ". Wi-Fi transmits ~100× louder: expect delays and devices dropping off."
                                     + to_en + " Changing the coordinator channel may require re-pairing some devices — otherwise move the Wi-Fi."})
            if weak:
                advice.append({"sev": "low", "pan": p["pan"],
                               "el": f"PAN {p['pan']}: {len(weak)} κόμβοι ακούγονται αδύναμα (LQI < {LQI_WEAK} ή RSSI < {RSSI_WEAK} dBm) από τον sniffer «{p['sniffer']}»: "
                                     + ", ".join(d["src"] for d in weak[:5]) + ". Βάλε έναν router Zigbee (πρίζα/λάμπα με ρεύμα) στη μέση της απόστασης· "
                                     "οι συσκευές με μπαταρία δεν αναμεταδίδουν.",
                               "en": f"PAN {p['pan']}: {len(weak)} nodes are heard weakly (LQI < {LQI_WEAK} or RSSI < {RSSI_WEAK} dBm) by sniffer “{p['sniffer']}”: "
                                     + ", ".join(d["src"] for d in weak[:5]) + ". Add a Zigbee router (mains plug/bulb) halfway; battery devices do not repeat."})
        plist.sort(key=lambda x: (-len(x["under"]), -x["frames"]))
        if plist and not wifi:
            advice.append({"sev": "info", "el": "Δεν ξέρω ποια κανάλια Wi-Fi 2.4 GHz χρησιμοποιείς — γράψ' τα παρακάτω (π.χ. 1, 6, 11) για να δω αν συγκρούονται με το Zigbee.",
                           "en": "I don’t know which 2.4 GHz Wi-Fi channels you use — enter them below (e.g. 1, 6, 11) so I can check for collisions with Zigbee."})
        return {"sniffers": sorted(sniffers, key=lambda s: s["name"]), "channels": channels, "pans": plist[:40], "clean": clean,
                "wifi": {"source": src, "channels": wifi, "manual": list(self.wifi_manual)}, "advice": advice,
                "thresholds": {"lqi": LQI_WEAK, "rssi": RSSI_WEAK}}

    def _lora_view(self, now):
        gws, nodes = [], []
        for pid, gw in self.cur["lora"].items():
            late = max(0, now - gw["seen"])
            gws.append({"id": pid, "name": gw["name"], "seen": gw["seen"], "n": len(gw["items"]), "fresh": late <= FRESH})
            gsf = _n(gw["metrics"].get("sf"), 7, 12)
            for r in gw["items"]:
                node = _txt(r.get("node"), 24)
                if not node:
                    continue
                rssi, snr, batt = _n(r.get("rssi"), -160, 20), _n(r.get("snr"), -40, 40), _n(r.get("batt"), 0, 30)
                age = _n(r.get("age"), 0, 1e9)
                age = None if age is None else int(age + late)
                sf = int(_n(r.get("sf"), 7, 12) or gsf or 7)
                margin, need = lora_margin(rssi, snr, sf)
                flags = []
                if age is not None and age > LORA_SILENT:
                    flags.append({"sev": "med", "code": "silent", "el": f"Σιωπά εδώ και {age // 60}′ — μπαταρία, κεραία ή εμπόδιο;", "en": f"Silent for {age // 60} min — battery, antenna or obstacle?"})
                if margin is not None and margin < LORA_MARGIN:
                    more = f" — ανέβασε σε SF{need}" if need and need > sf else " — ψηλότερη/καλύτερη κεραία ή πιο κοντινή πύλη"
                    more_en = f" — raise to SF{need}" if need and need > sf else " — higher/better antenna or a closer gateway"
                    flags.append({"sev": "med" if margin < 3 else "low", "code": "weak", "el": f"Αδύναμη ζεύξη: περιθώριο μόνο {margin} dB στο SF{sf}{more}",
                                  "en": f"Weak link: only {margin} dB margin at SF{sf}{more_en}"})
                if batt is not None and 0 < batt < LORA_BATT_LOW:
                    flags.append({"sev": "low", "code": "batt", "el": f"Χαμηλή μπαταρία ({batt} V)", "en": f"Low battery ({batt} V)"})
                nodes.append({"node": node, "gw": gw["name"], "rssi": rssi, "snr": snr, "batt": batt, "temp": _n(r.get("temp"), -90, 200),
                              "hum": _n(r.get("hum"), 0, 100), "door": r.get("door") if isinstance(r.get("door"), bool) else None,
                              "age": age, "last": None if age is None else now - age, "seq": _n(r.get("seq"), 0, 1e12), "sf": sf,
                              "margin": margin, "sf_need": need, "flags": flags})
        nodes.sort(key=lambda x: (not x["flags"], x["margin"] if x["margin"] is not None else 999, x["node"]))
        return {"gateways": sorted(gws, key=lambda g: g["name"]), "nodes": nodes[:200],
                "counts": {"nodes": len(nodes), "weak": sum(1 for n in nodes if any(f["code"] == "weak" for f in n["flags"])),
                           "batt": sum(1 for n in nodes if any(f["code"] == "batt" for f in n["flags"])),
                           "silent": sum(1 for n in nodes if any(f["code"] == "silent" for f in n["flags"]))},
                "thresholds": {"margin": LORA_MARGIN, "batt": LORA_BATT_LOW, "silent": LORA_SILENT}}

    def view(self):
        try:
            self.poll()
        except Exception:  # noqa: BLE001
            pass
        now = self.clock()
        with self.lock:
            if self.demo:
                self._demo_tick(now)
            return {"demo": self.demo, "now": now, "ble": self._ble_view(now), "zb": self._zb_view(now), "lora": self._lora_view(now),
                    "have": {k: len(v) for k, v in self.cur.items()}}

    def api(self, method, sub, q, body):
        body = body if isinstance(body, dict) else {}
        if method == "GET" and sub == "":
            return 200, self.view()
        if method == "POST" and sub == "known":
            r = self.set_known(body.get("mac"), body.get("label") or "", str(body.get("mode", "known")))  # mode "" = ξανά άγνωστο
            return (400 if r.get("error") else 200), r
        if method == "POST" and sub == "wifi":
            return 200, self.set_wifi(body.get("channels"))
        return 404, {"error": "not found"}

    def run_forever(self):
        while True:
            time.sleep(20)
            try:
                self.poll()
            except Exception:  # noqa: BLE001
                pass

    # ── demo ──
    def _demo_seed(self):
        t = self.clock()
        self._t0 = t
        self.labels = {"e7:1c:0b:93:5d:12": {"label": "Κλειδιά Μαρίας (Tile)", "mode": "known"}}
        dev = [  # mac, name, mfr, svc, ad, rnd, conn, πρώτη φορά πριν (s), θεάσεις
            ("d3:5a:91:0c:44:e2", "", 0x004C, "", "1219a3f1c2d4e5f60718293a", True, False, 5 * 3600, 290),
            ("e7:1c:0b:93:5d:12", "Tile", -1, "feed", "", True, True, 86400 * 12, 9800),
            ("c1:77:02:ee:19:5a", "Smart Tag2", 0x0075, "fd5a", "", True, True, 1500, 22),
            ("c8:2e:47:10:aa:31", "", 0x004C, "", "0215b9407f30f5f8466eaff9", True, False, 86400 * 30, 41000),
            ("a4:c1:38:5b:0e:9d", "LYWSD03MMC", -1, "fe95", "", False, True, 86400 * 20, 28000),
            ("5c:f3:70:8a:22:4b", "Ruuvi 224B", 0x0499, "", "0512fc5394c37c0004fffc04", True, False, 86400 * 9, 12000),
            ("a4:c1:38:9e:41:c7", "GVH5075_41C7", 0xEC88, "", "00031a9c5a00", False, True, 86400 * 6, 8100),
            ("f4:b8:5e:2a:91:07", "Galaxy Watch5", 0x0075, "", "0100020003", False, True, 86400 * 2, 2500),
            ("48:e7:29:b3:0f:66", "ESP32-setup", 0x02E5, "ffe0", "", False, True, 900, 14),
            ("d0:3f:27:5a:c2:18", "JBL Flip 6", 0x0057, "fe2c", "", False, True, 3600 * 3, 170),
            ("f0:b3:ec:11:9a:d4", "", 0x004C, "", "0719010f2075aa3001000945", True, True, 2400, 36),
            ("dc:23:4e:70:b1:0c", "Hue lightstrip", -1, "fe0f", "", False, True, 86400 * 40, 55000),
        ]
        for mac, name, mfr, svc, ad, rnd, conn, ago, hits in dev:
            self.ble[mac] = {"first": t - ago, "last": t, "hits": hits, "name": name, "mfr": mfr, "svc": svc, "ad": ad, "rnd": rnd, "conn": conn,
                             "alerted": False}
        for i in range(37):  # κινητά που περνούν: τυχαίες διευθύνσεις → μόνο μέτρηση
            self.ble["%02x:%02x:9c:11:%02x:%02x" % (0x40 + i, 0x5a ^ i, i * 7 % 256, 0xe1 ^ i)] = {
                "first": t - 600 - i * 40, "last": t - i * 20, "hits": 1 + i % 2, "name": "", "mfr": 0x004C if i % 3 else 0x0006, "svc": "",
                "ad": "1005" if i % 3 else "0109", "rnd": True, "conn": i % 3 == 0, "alerted": False}

    def _demo_tick(self, now):
        rs = {"d3:5a:91:0c:44:e2": (-61, -79), "e7:1c:0b:93:5d:12": (-83, -66), "c1:77:02:ee:19:5a": (-74, None), "c8:2e:47:10:aa:31": (-78, -58),
              "a4:c1:38:5b:0e:9d": (-72, None), "5c:f3:70:8a:22:4b": (-66, -81), "a4:c1:38:9e:41:c7": (None, -63), "f4:b8:5e:2a:91:07": (-55, -72),
              "48:e7:29:b3:0f:66": (-49, None), "d0:3f:27:5a:c2:18": (None, -60), "f0:b3:ec:11:9a:d4": (-68, None), "dc:23:4e:70:b1:0c": (None, -57)}
        wob = int(now) % 5 - 2
        for mac in rs:
            self.ble[mac]["last"] = now - 12
        self.cur["ble"] = {
            "p-b1e001": {"name": "ESP32 · BLE γραφείο", "seen": now - 12, "metrics": {},
                         "items": [{"mac": m, "rssi": a + wob} for m, (a, _b) in rs.items() if a is not None]},
            "p-b1e002": {"name": "ESP32 · BLE αποθήκη", "seen": now - 31, "metrics": {},
                         "items": [{"mac": m, "rssi": b - wob} for m, (_a, b) in rs.items() if b is not None]}}
        zb = [(11, "1a62", "0000", -48, 212, 96, "beacon"), (11, "1a62", "3f2c", -71, 148, 41, "data"), (11, "1a62", "a91e", -88, 44, 17, "data"),
              (11, "1a62", "7b05", -64, 180, 63, "data"), (11, "1a62", "c410", -91, 38, 6, "data"), (20, "d0c5", "0000", -59, 196, 38, "data"),
              (20, "d0c5", "5e11", -67, 160, 22, "data"), (20, "d0c5", "9a03", -70, 151, 12, "ack"), (25, "face", "00124b0024c1a7f3", -76, 120, 9, "data"),
              (15, "ffff", "", -80, 90, 3, "cmd")]
        self.cur["zigbee"] = {"p-2b0154": {"name": "Pi + nRF52840 · αποθήκη", "seen": now - 20,
                                           "items": [{"ch": c, "pan": p, "src": s, "rssi": r, "lqi": q, "n": n, "t": ty} for c, p, s, r, q, n, ty in zb],
                                           "metrics": dict({"ch%d" % c: 0 for c in range(11, 27)}, ch11=223 + wob, ch15=3, ch20=72 - wob, ch25=9)}}
        age = int(now - self._t0)
        lora = [("silo-01", -92, 8.5, 3.94, 17.5, 61, False, 140, 2211), ("gate-02", -104, 3.2, 3.71, 14.2, 70, True, 410, 987),
                ("pump-03", -121, -9.5, 3.21, 12.8, 82, None, 1620, 455)]
        self.cur["lora"] = {"p-10fa01": {"name": "LoRa πύλη · ταράτσα", "seen": now - 25, "metrics": {"sf": 9, "freq": 868.1, "bw": 125},
                                         "items": [{"node": n, "rssi": r, "snr": s, "batt": b, "temp": te, "hum": h, "door": d, "age": a + age % 300, "seq": q}
                                                   for n, r, s, b, te, h, d, a, q in lora]}}
