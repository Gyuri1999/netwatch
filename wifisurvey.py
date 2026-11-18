"""📶 Χαρτογράφηση Wi‑Fi γειτονιάς (macOS): ποια δίκτυα ακούγονται, σε ποια κανάλια, πόσο δυνατά — και ποιο κανάλι να διαλέξεις.

config.yaml:
wifisurvey: {interval: 600, avoid_dfs: true}

Πηγή: `system_profiler SPAirPortDataType -json` (ή, σε παλιά macOS, το εργαλείο `airport -s`).
Χωρίς άδεια «Υπηρεσίες τοποθεσίας» το macOS κρύβει τα ονόματα (SSID) — τα κανάλια και τα σήματα μετράνε κανονικά.

2,4 GHz: τα κανάλια απέχουν 5 MHz, ένα δίκτυο 20 MHz «πατάει» ±4 κανάλια γύρω του — γι' αυτό μόνο τα 1/6/11 δεν
επικαλύπτονται. Κάθε γειτονικό δίκτυο μετράει ανάλογα με το πόσο δυνατά ακούγεται.
5 GHz: μετράμε ανά μπλοκ 20/40/80/160 MHz και προτείνουμε το πιο ήσυχο (προαιρετικά χωρίς κανάλια DFS — ο router
μπορεί να τα εγκαταλείψει απότομα αν «ακούσει» ραντάρ).
"""
import json
import os
import re
import shutil
import subprocess
import threading
import time

AIRPORT = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
WEAK_DBM = -70
CH24 = list(range(1, 14))
NONOVERLAP_24 = (1, 6, 11)
CH5_ALL = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
DFS = set(range(52, 65)) | set(range(100, 145))
BLOCKS5 = {
    40: [(36, 40), (44, 48), (52, 56), (60, 64), (100, 104), (108, 112), (116, 120), (124, 128), (132, 136), (140, 144),
         (149, 153), (157, 161)],
    80: [(36, 40, 44, 48), (52, 56, 60, 64), (100, 104, 108, 112), (116, 120, 124, 128), (132, 136, 140, 144), (149, 153, 157, 161)],
    160: [tuple(range(36, 65, 4)), tuple(range(100, 129, 4))],
}
PSC6 = list(range(5, 234, 16))  # «προτιμώμενα» κανάλια 6 GHz (PSC)
REDACTED_NOTE = ("Τα ονόματα των δικτύων (SSID) είναι κρυμμένα από το macOS. Δώσε άδεια «Υπηρεσίες τοποθεσίας» στο "
                 "Terminal ή στο NetWatch (Ρυθμίσεις συστήματος → Απόρρητο και ασφάλεια → Υπηρεσίες τοποθεσίας) για να φαίνονται.")

SEC_MAP = [  # (υπο-συμβολοσειρά του macOS, κανονικό όνομα) — η σειρά μετράει
    ("wpa3_transition", "wpa2/wpa3"), ("wpa2_wpa3", "wpa2/wpa3"), ("wpa3_enterprise", "wpa3-enterprise"),
    ("wpa2_enterprise", "wpa2-enterprise"), ("wpa_enterprise", "wpa-enterprise"), ("wpa3", "wpa3"), ("owe", "owe"),
    ("wpa2", "wpa2"), ("wpa1_wpa2", "wpa/wpa2"), ("wpa_personal_mixed", "wpa/wpa2"), ("wpa", "wpa"),
    ("wep", "wep"), ("none", "open"), ("open", "open"),
]
INSECURE = {"open": "ανοιχτό (χωρίς κωδικό)", "wep": "WEP (σπάει σε λεπτά)", "wpa": "WPA (παλιό TKIP)",
            "wpa/wpa2": "WPA/WPA2 μικτό (επιτρέπει TKIP)"}


# ── ανάλυση πεδίων ──
def norm_security(raw):
    s = str(raw or "").lower().replace("spairport_security_mode_", "")
    if not s:
        return None
    if s.startswith("wpa2(") or s.startswith("wpa(") or "(" in s:  # μορφή airport -s: "WPA2(PSK/AES/AES) WPA(PSK/TKIP/TKIP)"
        has = lambda k: re.search(rf"(^|\s){k}\(", s) is not None
        if has("wpa3") and has("wpa2"):
            return "wpa2/wpa3"
        if has("wpa2") and has("wpa"):
            return "wpa/wpa2"
        for k in ("wpa3", "wpa2", "wpa"):
            if has(k):
                return k + ("-enterprise" if "802.1x" in s else "")
    if s in ("none", "open"):
        return "open"
    for k, v in SEC_MAP:
        if k in s:
            return v
    return s


def parse_channel(raw):
    """"36 (5GHz, 80MHz)" / "6" / 11 / "36,+1" / "149,80" → (κανάλι, ζώνη '2.4'|'5'|'6', πλάτος MHz)."""
    if raw is None:
        return None, None, None
    s = str(raw)
    m = re.match(r"\s*(\d+)", s)
    if not m:
        return None, None, None
    ch = int(m.group(1))
    band = None
    b = re.search(r"(\d)\s*GHz", s, re.I)
    if b:
        band = {"2": "2.4", "5": "5", "6": "6"}.get(b.group(1))
    if band is None:
        band = "2.4" if ch <= 14 else "5"
    w = re.search(r"(\d+)\s*MHz", s, re.I)
    width = int(w.group(1)) if w else None
    if width is None:
        a = re.match(r"\s*\d+\s*,\s*([+-]?\d+)", s)  # airport: "+1"/"-1" = 40 MHz, "80"/"160" = πλάτος
        if a:
            v = a.group(1)
            width = 40 if v in ("+1", "-1", "1") else int(v) if v.lstrip("+-").isdigit() and int(v) >= 20 else None
    return ch, band, width or 20


def parse_signal(raw):
    """"-60 dBm / -91 dBm" → (-60, -91)."""
    nums = [int(x) for x in re.findall(r"-?\d+", str(raw or ""))]
    return (nums[0] if nums else None), (nums[1] if len(nums) > 1 else None)


def _ssid(name):
    if name is None:
        return None, True
    s = str(name).strip()
    if not s or s.lower() in ("<redacted>", "redacted", "<hidden>") or s.startswith("<redacted"):
        return None, True
    return s, False


def _net(d, current=False):
    ssid, red = _ssid(d.get("_name"))
    ch, band, width = parse_channel(d.get("spairport_network_channel"))
    rssi, noise = parse_signal(d.get("spairport_signal_noise"))
    raw_sec = d.get("spairport_security_mode")
    return {"ssid": ssid, "redacted": red, "bssid": d.get("spairport_network_bssid"), "channel": ch, "band": band, "width": width,
            "rssi": rssi, "noise": noise, "snr": (rssi - noise) if rssi is not None and noise is not None else None,
            "security": norm_security(raw_sec), "security_raw": raw_sec,
            "phy": d.get("spairport_network_phymode"), "current": current,
            "rate": d.get("spairport_network_rate"), "mcs": d.get("spairport_network_mcs")}


def parse_system_profiler(data):
    """JSON (str ή dict) του system_profiler → {"interface", "current", "networks", "power"}."""
    if isinstance(data, (str, bytes)):
        data = json.loads(data)
    items = (data or {}).get("SPAirPortDataType") or []
    for it in items:
        for itf in it.get("spairport_airport_interfaces") or []:
            cur = itf.get("spairport_current_network_information") or {}
            others = itf.get("spairport_airport_other_local_wireless_networks") or []
            if not others and not cur.get("spairport_network_channel"):
                continue  # π.χ. awdl0
            current = _net(cur, True) if cur.get("spairport_network_channel") else None
            return {"interface": itf.get("_name"), "current": current,
                    "networks": [_net(o) for o in others if isinstance(o, dict)],
                    "power": itf.get("spairport_status_information")}
    return {"interface": None, "current": None, "networks": [], "power": None}


_AIRPORT_LINE = re.compile(r"^\s*(?P<ssid>.*?)\s+(?:(?P<bssid>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+)?(?P<rssi>-\d+)\s+"
                           r"(?P<ch>\d+(?:,[+-]?\d+)?)\s+(?P<ht>[YN])\s+(?P<cc>\S+)\s+(?P<sec>.+?)\s*$", re.I)


def parse_airport(text):
    """Έξοδος `airport -s` → λίστα δικτύων."""
    out = []
    for line in (text or "").splitlines()[1:]:
        m = _AIRPORT_LINE.match(line)
        if not m:
            continue
        ssid, red = _ssid(m.group("ssid"))
        ch, band, width = parse_channel(m.group("ch"))
        out.append({"ssid": ssid, "redacted": red, "bssid": m.group("bssid"), "channel": ch, "band": band, "width": width,
                    "rssi": int(m.group("rssi")), "noise": None, "snr": None, "security": norm_security(m.group("sec")),
                    "security_raw": m.group("sec"), "phy": None, "current": False, "rate": None, "mcs": None})
    return out


# ── κατάληψη καναλιών ──
def weight(rssi):
    """Πόσο «βαραίνει» ένα γειτονικό δίκτυο: -50 dBm → 1, -90 dBm → ~0,1."""
    if rssi is None:
        return 0.3
    return round(min(1.0, max(0.05, (rssi + 95) / 45.0)), 3)


def span24(ch, width):
    """Κανάλια 20 MHz που καλύπτει ένα δίκτυο 2,4 GHz (το macOS δεν λέει αν το δεύτερο είναι πάνω ή κάτω: μαντεύουμε)."""
    if width and width >= 40:
        sec = ch + 4 if ch <= 7 else ch - 4
        return sorted({ch, sec})
    return [ch]


def occupancy24(nets):
    score = {c: 0.0 for c in CH24}
    count = {c: 0 for c in CH24}
    for n in nets:
        if n["band"] != "2.4" or not n["channel"]:
            continue
        w = weight(n["rssi"])
        hit = set()
        for centre in span24(n["channel"], n["width"]):
            for c in CH24:
                d = abs(c - centre)
                if d <= 4:
                    score[c] += w * (5 - d) / 5.0
                    hit.add(c)
        for c in hit:
            count[c] += 1
    return [{"ch": c, "score": round(score[c], 2), "count": count[c], "nonoverlap": c in NONOVERLAP_24} for c in CH24]


def block5(ch, width):
    if width and width >= 40:
        for b in BLOCKS5.get(min(width, 160), []):
            if ch in b:
                return b
    return (ch,)


def occupancy5(nets):
    score = {c: 0.0 for c in CH5_ALL}
    count = {c: 0 for c in CH5_ALL}
    for n in nets:
        if n["band"] != "5" or not n["channel"]:
            continue
        w = weight(n["rssi"])
        for c in block5(n["channel"], n["width"]):
            if c in score:
                score[c] += w
                count[c] += 1
    return [{"ch": c, "score": round(score[c], 2), "count": count[c], "dfs": c in DFS} for c in CH5_ALL]


def occupancy6(nets):
    chans = {}
    for n in nets:
        if n["band"] == "6" and n["channel"]:
            e = chans.setdefault(n["channel"], {"ch": n["channel"], "score": 0.0, "count": 0, "psc": n["channel"] in PSC6})
            e["score"] = round(e["score"] + weight(n["rssi"]), 2)
            e["count"] += 1
    return sorted(chans.values(), key=lambda x: x["ch"])


def recommend24(occ):
    by = {o["ch"]: o for o in occ}
    order = sorted(NONOVERLAP_24, key=lambda c: (by[c]["score"], c))
    return {"channel": order[0], "ranking": [{"ch": c, "score": by[c]["score"]} for c in order], "width": 20}


def recommend5(occ, width=80, avoid_dfs=True):
    by = {o["ch"]: o for o in occ}
    width = width if width in (20, 40, 80, 160) else 80
    blocks = [tuple([c]) for c in CH5_ALL] if width == 20 else BLOCKS5[width]
    cand = []
    for b in blocks:
        dfs = any(c in DFS for c in b)
        if avoid_dfs and dfs:
            continue
        cand.append({"block": list(b), "score": round(sum(by[c]["score"] for c in b if c in by), 2), "dfs": dfs})
    if not cand:  # π.χ. 160 MHz χωρίς DFS δεν υπάρχει
        return recommend5(occ, width, avoid_dfs=False) if avoid_dfs else None
    cand.sort(key=lambda x: (x["score"], x["block"][0]))
    best = cand[0]
    primary = min(best["block"], key=lambda c: (by[c]["score"] if c in by else 0, c))
    return {"channel": primary, "block": best["block"], "width": width, "dfs": best["dfs"], "ranking": cand[:6]}


def recommend6(occ):
    by = {o["ch"]: o for o in occ}
    best = min(PSC6, key=lambda c: ((by.get(c) or {}).get("score", 0.0), c))
    return {"channel": best, "width": 80, "psc": True}


def analyze(current, networks, avoid_dfs=True):
    """Κατάληψη ανά ζώνη, προτάσεις καναλιών και προβλήματα (ελληνικά)."""
    own_ssid = current.get("ssid") if current else None
    own = [n for n in networks if own_ssid and n.get("ssid") == own_ssid]
    neigh = [n for n in networks if not (own_ssid and n.get("ssid") == own_ssid)]
    occ = {"2.4": occupancy24(neigh), "5": occupancy5(neigh), "6": occupancy6(neigh)}
    cnt = {b: sum(1 for n in neigh if n["band"] == b) for b in ("2.4", "5", "6")}
    rec = {"2.4": recommend24(occ["2.4"]),
           "5": recommend5(occ["5"], width=(current or {}).get("width") if (current or {}).get("band") == "5" else 80, avoid_dfs=avoid_dfs),
           "6": recommend6(occ["6"]) if cnt["6"] or (current or {}).get("band") == "6" else None}
    issues = []

    def add(sev, code, text):
        if not any(i["code"] == code and i["text"] == text for i in issues):  # το ίδιο δίκτυο μπορεί να φαίνεται και στους «γείτονες»
            issues.append({"sev": sev, "code": code, "text": text})

    mine = ([current] if current else []) + own
    name = f"«{own_ssid}»" if own_ssid else "σου"
    for n in mine:
        if n["band"] == "2.4" and n["channel"]:
            best = rec["2.4"]["channel"]
            if n["channel"] not in NONOVERLAP_24:
                add("med", "overlap24", f"Το δίκτυό {name} είναι στο κανάλι {n['channel']} των 2,4 GHz, που επικαλύπτεται με "
                                        f"γειτονικά κανάλια. Βάλε 1, 6 ή 11 — προτείνεται το {best}.")
            else:
                by = {o["ch"]: o["score"] for o in occ["2.4"]}
                if by[n["channel"]] - by[best] >= 1.0:
                    add("low", "busy24", f"Το κανάλι {n['channel']} των 2,4 GHz είναι φορτωμένο — το {best} είναι πιο ήσυχο.")
            crowded = sum(1 for x in neigh if x["band"] == "2.4" and (x["rssi"] or -100) > -80)
            if (n["width"] or 20) >= 40 and crowded >= 3:
                add("med", "wide24", f"Το δίκτυό {name} χρησιμοποιεί {n['width']} MHz στα 2,4 GHz ενώ ακούγονται {crowded} "
                                     "γειτονικά δίκτυα: γύρνα το σε 20 MHz — θα έχεις λιγότερες παρεμβολές και σταθερότερη σύνδεση.")
        if n["band"] == "5" and n["channel"] and rec["5"]:
            by = {o["ch"]: o["score"] for o in occ["5"]}
            here = sum(by.get(c, 0) for c in block5(n["channel"], n["width"]))
            if here - rec["5"]["ranking"][0]["score"] >= 1.0:
                add("low", "busy5", f"Το κανάλι {n['channel']} των 5 GHz μοιράζεται με γείτονες — δοκίμασε το {rec['5']['channel']} "
                                    f"({rec['5']['width']} MHz{', DFS' if rec['5']['dfs'] else ''}).")
        if n["security"] in INSECURE:
            add("high", "own_insecure", f"Το δίκτυό {name} είναι {INSECURE[n['security']]}. Βάλε WPA2‑AES ή WPA3.")
    if current and current.get("rssi") is not None and current["rssi"] < WEAK_DBM:
        add("med", "weak", f"Αδύναμο σήμα: {current['rssi']} dBm (καλό είναι πάνω από {WEAK_DBM} dBm). Πλησίασε τον router, "
                           "άλλαξε θέση ή βάλε mesh/access point.")
    if current and current.get("snr") is not None and current["snr"] < 20:
        add("low", "snr", f"Χαμηλός λόγος σήματος/θορύβου ({current['snr']} dB) — πολλές παρεμβολές στο κανάλι.")
    bad = {}
    for n in neigh:
        if n["security"] in INSECURE:
            bad.setdefault(n["security"], []).append(n)
    for sec, lst in bad.items():
        names = ", ".join(sorted({f"«{x['ssid']}»" for x in lst if x["ssid"]}))[:200]
        add("info", "nearby_" + sec.replace("/", "_"), f"{len(lst)} γειτονικά δίκτυα {INSECURE[sec]}{': ' + names if names else ''}. "
                                                       "Μην συνδέεσαι σε αυτά χωρίς VPN.")
    wide = sum(1 for n in neigh if n["band"] == "2.4" and (n["width"] or 20) >= 40)
    if wide:
        add("info", "neigh_wide24", f"{wide} γειτονικά δίκτυα πιάνουν 40 MHz στα 2,4 GHz — «τρώνε» σχεδόν όλη τη ζώνη.")
    if rec["5"] and rec["5"]["dfs"]:
        add("info", "dfs", f"Το προτεινόμενο κανάλι 5 GHz ({rec['5']['channel']}) είναι DFS: ο router μπορεί να το αλλάξει "
                           "απότομα αν ανιχνεύσει ραντάρ.")
    redacted = any(n["redacted"] for n in networks + ([current] if current else []))
    return {"counts": cnt, "occupancy": occ, "recommendation": rec, "issues": issues, "redacted": redacted,
            "own": [{k: n[k] for k in ("ssid", "channel", "band", "width", "rssi")} for n in own]}


# ── demo ──
def _sp(name, ch, band, width, rssi, noise, sec, phy):
    return {"_name": name, "spairport_network_channel": f"{ch} ({band}GHz, {width}MHz)", "spairport_network_phymode": phy,
            "spairport_network_type": "spairport_network_type_station", "spairport_security_mode": f"spairport_security_mode_{sec}",
            "spairport_signal_noise": f"{rssi} dBm / {noise} dBm"}


def demo_scan():
    """Πολυκατοικία στην Αθήνα: πολλά δίκτυα παρόχων στα 2,4 GHz, μερικά 5 GHz, ένας παλιός WEP εκτυπωτής κ.λπ."""
    others = [
        _sp("COSMOTE-4F2A91", 1, 2, 20, -67, -92, "wpa2_personal", "802.11b/g/n"),
        _sp("COSMOTE-77B0C3", 6, 2, 40, -58, -90, "wpa2_personal", "802.11b/g/n/ax"),
        _sp("VODAFONE_2G_8812", 6, 2, 20, -74, -92, "wpa2_personal", "802.11b/g/n"),
        _sp("NOVA_5A21", 11, 2, 20, -71, -92, "wpa2_personal", "802.11b/g/n"),
        _sp("NOVA_5A21_5G", 36, 5, 80, -79, -95, "wpa2_personal", "802.11a/n/ac"),
        _sp("Wind-WiFi-6D3E", 3, 2, 20, -80, -93, "wpa_personal_mixed", "802.11b/g/n"),
        _sp("INALAN_2G_Papadopoulos", 11, 2, 40, -63, -91, "wpa2_personal", "802.11b/g/n/ax"),
        _sp("INALAN_5G_Papadopoulos", 44, 5, 80, -72, -95, "wpa2_wpa3_personal", "802.11a/n/ac/ax"),
        _sp("COSMOTE-77B0C3", 48, 5, 80, -66, -95, "wpa2_personal", "802.11a/n/ac/ax"),
        _sp("DIRECT-7B-HP OfficeJet 3830", 6, 2, 20, -69, -92, "wpa2_personal", "802.11b/g/n"),
        _sp("Mamas_WiFi", 1, 2, 20, -84, -94, "wep", "802.11b/g"),
        _sp("Kafeteria Free WiFi", 11, 2, 20, -86, -94, "none", "802.11b/g/n"),
        _sp("Vodafone-5G-8812", 100, 5, 80, -83, -96, "wpa2_personal", "802.11a/n/ac"),
        _sp("TP-Link_A3F0", 8, 2, 20, -77, -93, "wpa2_personal", "802.11b/g/n"),
        _sp("TP-Link_A3F0_5G", 149, 5, 80, -81, -96, "wpa2_personal", "802.11a/n/ac"),
        _sp("FRITZ!Box 7530 KL", 1, 2, 20, -76, -93, "wpa2_personal", "802.11b/g/n/ax"),
        _sp("FRITZ!Box 7530 KL", 52, 5, 80, -78, -95, "wpa2_personal", "802.11a/n/ac/ax"),
        _sp("<redacted>", 6, 2, 20, -88, -94, "wpa2_personal", "802.11b/g/n"),
        _sp("Homelab-IoT", 9, 2, 20, -52, -91, "wpa2_personal", "802.11b/g/n"),
        _sp("Homelab", 44, 5, 80, -55, -95, "wpa2_wpa3_personal", "802.11a/n/ac/ax"),
        _sp("Plaka-6E", 37, 6, 160, -82, -96, "wpa3_personal", "802.11ax"),
    ]
    cur = _sp("Homelab", 9, 2, 40, -72, -90, "wpa2_personal", "802.11ax")
    cur.update({"spairport_network_rate": 144, "spairport_network_mcs": 7, "spairport_network_country_code": "GR"})
    return {"SPAirPortDataType": [{"spairport_airport_interfaces": [
        {"_name": "en0", "spairport_status_information": "spairport_status_connected",
         "spairport_current_network_information": cur, "spairport_airport_other_local_wireless_networks": others},
        {"_name": "awdl0", "spairport_current_network_information": {"spairport_network_type": "spairport_network_type_station"}}]}]}


class WifiSurvey:
    def __init__(self, cfg=None, sim=False):
        cfg = cfg or {}
        self.sim = sim
        self.interval = max(60, int(cfg.get("interval") or 600))
        self.avoid_dfs = bool(cfg.get("avoid_dfs", True))
        self.lock = threading.Lock()
        self.last = None

    def _collect(self):
        if self.sim:
            return "demo", parse_system_profiler(demo_scan()), None
        err = None
        if shutil.which("system_profiler"):
            try:
                out = subprocess.run(["system_profiler", "SPAirPortDataType", "-json"], capture_output=True, text=True, timeout=40)
                res = parse_system_profiler(out.stdout)
                if res["current"] or res["networks"]:
                    return "system_profiler", res, None
            except (subprocess.TimeoutExpired, OSError, ValueError) as e:
                err = str(e)[:120]
        if os.path.exists(AIRPORT):
            try:
                out = subprocess.run([AIRPORT, "-s"], capture_output=True, text=True, timeout=30)
                nets = parse_airport(out.stdout)
                if nets:
                    return "airport", {"interface": None, "current": None, "networks": nets, "power": None}, None
            except (subprocess.TimeoutExpired, OSError) as e:
                err = str(e)[:120]
        return None, {"interface": None, "current": None, "networks": [], "power": None}, err

    def scan(self, now=None):
        now = now or time.time()
        src, res, err = self._collect()
        out = {"ok": bool(src), "demo": self.sim, "source": src, "t": now, "interface": res["interface"],
               "current": res["current"], "networks": sorted(res["networks"], key=lambda n: -(n["rssi"] if n["rssi"] is not None else -999)),
               "avoid_dfs": self.avoid_dfs}
        out.update(analyze(res["current"], res["networks"], self.avoid_dfs))
        if not src:
            out["error"] = ("Δεν βρέθηκαν δεδομένα Wi‑Fi — η χαρτογράφηση δουλεύει σε macOS με ενεργό Wi‑Fi."
                            + (f" ({err})" if err else ""))
        if res.get("power") == "spairport_status_off":
            out["error"] = "Το Wi‑Fi είναι κλειστό."
        out["note"] = REDACTED_NOTE if out["redacted"] else None
        with self.lock:
            self.last = out
        return out

    def status(self):
        with self.lock:
            last = self.last
        return last if last is not None else self.scan()

    def run_forever(self):
        while True:
            try:
                self.scan()
            except Exception:
                pass
            time.sleep(self.interval)
