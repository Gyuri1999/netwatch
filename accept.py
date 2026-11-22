"""✅ Τεστ αποδοχής εγκατάστασης — λίστα ελέγχων ανά σημείο και υπογεγραμμένη αναφορά «πέρασε / δεν πέρασε».

Μετά από μια εγκατάσταση (πρίζες δικτύου, access points, κάμερες, switch, IoT, γραμμή παρόχου) ο τεχνικός ανοίγει
μια «εργασία» για τον πελάτη, προσθέτει τα σημεία και για καθένα τρέχει τη λίστα του:
  • ΑΥΤΟΜΑΤΟΙ έλεγχοι που τρέχει το NetWatch: ping (απώλειες/καθυστέρηση), θύρα TCP ανοιχτή (π.χ. RTSP 554 κάμερας),
    DNS, Internet, διεύθυνση από DHCP σε αυτή τη διεπαφή, gateway, ταχύτητα ζεύξης της κάρτας δικτύου.
  • ΧΕΙΡΟΚΙΝΗΤΟΙ έλεγχοι που τσεκάρει ο τεχνικός (πέρασε / απέτυχε / δεν αφορά + μέτρηση + σημείωση): πιστοποίηση
    καλωδίου, ετικέτα, ισχύς PoE, σήμα Wi‑Fi, πεδίο κάμερας, αλλαγή εργοστασιακού κωδικού, firmware, UPS, παράδοση εγγράφων.
Στο τέλος: σύνοψη, συνολική ετυμηγορία και αναφορά αποδοχής A4 με δύο πλαίσια υπογραφής.

🔒 Ασφάλεια: οι αυτόματοι έλεγχοι πάνε ΜΟΝΟ σε ιδιωτικές IP του LAN (και στο σταθερό 1.1.1.1 για «έχω Internet;»),
με timeouts, χωρίς καμία εγγραφή σε συσκευή. Χρησιμοποιούν τα έτοιμα ασφαλή probes του changecheck.py.
Οι εργασίες αποθηκεύονται στον φάκελο του πελάτη (sites.site_dir) ως accept.json, αλλιώς στο data_dir.
"""
import os
import re
import sys
import threading
import time
import zlib

import sites as S
from sites import L, clean, esc

JOB_RE = re.compile(r"^j[0-9a-z-]{1,30}$")
STATUSES = ("pending", "pass", "fail", "na")
MAX_JOBS = 300
MAX_POINTS = 600
MAX_CHECKS = 30
AUTO_FNS = ("ping", "tcp", "dns", "internet", "dhcp", "gateway", "link")


def _a(cid, fn, el, en, arg=""):
    return {"id": cid, "kind": "auto", "fn": fn, "arg": arg, "el": el, "en": en, "unit": ""}


def _m(cid, el, en, unit=""):
    return {"id": cid, "kind": "manual", "fn": "", "arg": "", "el": el, "en": en, "unit": unit}


_LABEL = _m("label", "Ετικέτα τοποθετημένη και ευανάγνωστη", "Label applied and readable")
_PW = _m("password", "Ο εργοστασιακός κωδικός άλλαξε", "Default password changed")
_FW = _m("firmware", "Firmware ενημερωμένο στην τελευταία έκδοση", "Firmware updated to the latest version")
TYPES = {
    "socket": ("🔌", "Πρίζα δικτύου", "Network socket", [
        _a("link", "link", "Ταχύτητα ζεύξης της κάρτας (σύνδεσε το laptop στην πρίζα)", "Link speed of the adapter (plug the laptop into the socket)", "1000"),
        _a("dhcp", "dhcp", "Πήρε διεύθυνση από DHCP", "Got an address from DHCP"),
        _a("gateway", "gateway", "Το router (gateway) απαντά", "The router (gateway) answers"),
        _a("internet", "internet", "Υπάρχει Internet", "Internet is reachable"),
        _m("wiremap", "Πιστοποίηση καλωδίου / wiremap OK", "Cable certified / wiremap OK"),
        _m("length", "Μήκος καλωδίου κάτω από 90 m", "Cable length under 90 m", "m"), _LABEL]),
    "ap": ("📶", "Access point", "Access point", [
        _a("ping", "ping", "Απαντά σε ping χωρίς απώλειες", "Answers ping with no loss"),
        _a("https", "tcp", "Σελίδα διαχείρισης (TCP 443)", "Management page (TCP 443)", "443"),
        _m("poe", "Ισχύς PoE που μετρήθηκε", "PoE power measured", "W"),
        _m("signal", "Σήμα Wi‑Fi στα συμφωνημένα σημεία", "Wi‑Fi signal at the agreed spots", "dBm"),
        _m("roam", "Περιαγωγή (roaming) μεταξύ AP χωρίς διακοπή", "Roaming between APs without drops"),
        _m("guest", "Το Wi‑Fi επισκεπτών είναι απομονωμένο από το εσωτερικό δίκτυο", "Guest Wi‑Fi is isolated from the internal network"),
        _PW, _FW, _LABEL]),
    "camera": ("📷", "Κάμερα IP", "IP camera", [
        _a("ping", "ping", "Απαντά σε ping χωρίς απώλειες", "Answers ping with no loss"),
        _a("rtsp", "tcp", "Ροή βίντεο RTSP (TCP 554)", "RTSP video stream (TCP 554)", "554"),
        _a("web", "tcp", "Σελίδα ρυθμίσεων (TCP 80)", "Settings page (TCP 80)", "80"),
        _m("fov", "Πεδίο λήψης συμφωνημένο με τον πελάτη", "Field of view agreed with the customer"),
        _m("night", "Νυχτερινή λήψη / IR ελεγμένη", "Night vision / IR checked"),
        _m("retention", "Ημέρες εγγραφής επιβεβαιώθηκαν στο NVR", "Recording retention days verified on the NVR", "ημ."),
        _m("poe", "Ισχύς PoE που μετρήθηκε", "PoE power measured", "W"),
        _m("noupnp", "UPnP / P2P cloud απενεργοποιημένο (αν δεν ζητήθηκε)", "UPnP / P2P cloud disabled (unless requested)"),
        _PW, _FW, _LABEL]),
    "switch": ("🔀", "Switch / router", "Switch / router", [
        _a("ping", "ping", "Απαντά σε ping χωρίς απώλειες", "Answers ping with no loss"),
        _a("https", "tcp", "Σελίδα διαχείρισης (TCP 443)", "Management page (TCP 443)", "443"),
        _m("backup", "Αντίγραφο ρυθμίσεων αποθηκεύτηκε", "Configuration backup saved"),
        _m("vlan", "VLAN / θύρες ρυθμισμένα όπως στο σχέδιο", "VLANs / ports configured as designed"),
        _m("ups", "Αυτονομία UPS που μετρήθηκε", "UPS runtime measured", "λεπτά"),
        _m("rack", "Τακτοποίηση rack / γείωση / αερισμός", "Rack tidy / grounding / ventilation"),
        _PW, _FW, _LABEL]),
    "iot": ("💡", "Συσκευή IoT", "IoT device", [
        _a("ping", "ping", "Απαντά σε ping χωρίς απώλειες", "Answers ping with no loss"),
        _m("function", "Λειτουργία ελεγμένη μαζί με τον πελάτη", "Function tested with the customer"),
        _m("vlan", "Συνδεδεμένη στο δίκτυο/VLAN για IoT", "Connected to the IoT network/VLAN"),
        _m("signal", "Σήμα Wi‑Fi στη θέση της συσκευής", "Wi‑Fi signal at the device", "dBm"),
        _PW, _FW, _LABEL]),
    "uplink": ("🌍", "Γραμμή παρόχου / uplink", "Uplink / ISP line", [
        _a("dhcp", "dhcp", "Πήρε διεύθυνση από DHCP", "Got an address from DHCP"),
        _a("gateway", "gateway", "Το router (gateway) απαντά", "The router (gateway) answers"),
        _a("dns", "dns", "Το DNS μεταφράζει ονόματα", "DNS resolves names", "example.com"),
        _a("internet", "internet", "Υπάρχει Internet", "Internet is reachable"),
        _m("down", "Ταχύτητα λήψης που μετρήθηκε", "Download speed measured", "Mbps"),
        _m("up", "Ταχύτητα αποστολής που μετρήθηκε", "Upload speed measured", "Mbps"),
        _m("failover", "Εφεδρική γραμμή (4G/δεύτερος πάροχος) δοκιμάστηκε", "Backup line (4G / second ISP) tested"),
        _m("docs", "Έγγραφα / κωδικοί παραδόθηκαν στον πελάτη", "Documentation / credentials handed to the customer")]),
}
# τύπος συσκευής του NetWatch → τύπος σημείου
SUGGEST = {"camera": "camera", "router": "switch", "iot": "iot", "esp": "iot", "speaker": "iot", "tv": "iot", "pi": "iot"}


# ───────────────────────── αυτόματοι έλεγχοι (πραγματικοί) ─────────────────────────
def parse_media(text):
    """`ifconfig en0` (macOS/BSD) → Mbps από «media: autoselect (1000baseT <full-duplex>)», αλλιώς None."""
    m = re.search(r"media:[^\n]*?\(?\b(\d+)(G?)base", str(text or ""), re.I)
    return int(m.group(1)) * (1000 if m.group(2) else 1) if m else None


def link_speed(iface):
    """Ταχύτητα ζεύξης της τοπικής κάρτας σε Mbps, όπου το δίνει το λειτουργικό (Linux /sys, macOS ifconfig). Αλλιώς None."""
    if not iface or not re.match(r"^[A-Za-z0-9_.:-]{1,20}$", str(iface)):
        return None
    if sys.platform.startswith("linux"):
        try:
            with open(f"/sys/class/net/{iface}/speed") as f:
                v = int(f.read().strip())
            return v if v > 0 else None
        except (OSError, ValueError):
            return None
    if sys.platform == "darwin":
        import netkit
        return parse_media(netkit._run(["ifconfig", str(iface)], timeout=3))
    return None


def real_run(fn, target, arg):
    """Ένας αυτόματος έλεγχος → {"ok": True/False/None, "value", "note"}. None = δεν μπορεί να ελεγχθεί από εδώ."""
    import changecheck as cc

    def res(ok, value="", note=""):
        return {"ok": ok, "value": value, "note": note}

    def ms(v):
        return f"{v:g} ms" if isinstance(v, (int, float)) else "—"
    if fn in ("ping", "tcp"):
        if not cc.private_ip(target):
            return res(None, "", "Δώσε ιδιωτική IP στο σημείο (έλεγχος μόνο στο τοπικό δίκτυο)")
    if fn == "ping":
        r = cc.ping(target, count=4, interval=1.0, timeout=1.0)  # 1/δευτ.: κάμερες/NVR περιορίζουν το ICMP — τα γρήγορα ping δείχνουν ψεύτικες απώλειες
        if r.get("err") == "noping":
            return res(None, "", "Δεν υπάρχει ping σε αυτό το σύστημα — τσέκαρέ το με το χέρι")
        return res(bool(r.get("ok")) and not r.get("loss_pct"), f"απώλειες {r.get('loss_pct', 100):g}% · {ms(r.get('avg'))}",
                   "" if r.get("ok") else "Δεν απαντά σε ping")
    if fn == "tcp":
        try:
            port = int(arg)
            if not 1 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            return res(None, "", "Μη έγκυρη θύρα")
        r = cc.tcp(target, port, timeout=1.5)
        return res(r["state"] == "open", f"TCP {port} {r['state']}" + (f" · {ms(r['ms'])}" if r.get("ms") else ""),
                   "" if r["state"] == "open" else "Η θύρα δεν είναι ανοιχτή")
    if fn == "dns":
        name = str(arg or "example.com")
        if not re.match(r"^[A-Za-z0-9.-]{1,120}$", name):
            return res(None, "", "Μη έγκυρο όνομα")
        r = cc.sys_resolve(name, timeout=2.0)
        return res(bool(r.get("ok")), f"{name} → {r.get('ip') or '—'}" + (f" · {ms(r['ms'])}" if r.get("ms") else ""), "" if r.get("ok") else str(r.get("err") or ""))
    if fn == "internet":
        r = cc.ping("1.1.1.1", count=3, interval=0.2, timeout=1.5)
        if r.get("ok"):
            return res(True, f"1.1.1.1 · απώλειες {r['loss_pct']:g}% · {ms(r.get('avg'))}")
        t = cc.tcp("1.1.1.1", 443, timeout=2.0)
        return res(t["state"] == "open", f"1.1.1.1:443 {t['state']}", "" if t["state"] == "open" else "Δεν φτάνω στο Internet")
    info = cc.local_info()
    if fn == "dhcp":
        ip, gw = info.get("ip"), info.get("gateway")
        if not ip or str(ip).startswith("169.254."):
            return res(False, str(ip or "—"), "Χωρίς διεύθυνση από DHCP (APIPA ή καμία IP)")
        val = f"{ip}/{info.get('prefix') or '?'} · gw {gw or '—'} · DNS {', '.join(info.get('dns') or []) or '—'}"
        return res(bool(gw), val, "" if gw else "Χωρίς gateway")
    if fn == "gateway":
        gw = info.get("gateway")
        if not gw or not cc.allowed(gw):
            return res(False if not gw else None, str(gw or "—"), "Δεν υπάρχει gateway" if not gw else "Το gateway δεν είναι ιδιωτική IP")
        r = cc.ping(gw, count=4, interval=0.2, timeout=1.0)
        if r.get("ok"):
            return res(not r.get("loss_pct"), f"{gw} · απώλειες {r['loss_pct']:g}% · {ms(r.get('avg'))}")
        for p in (80, 443, 53):
            if cc.tcp(gw, p, timeout=1.0)["state"] in ("open", "closed"):
                return res(True, f"{gw} · TCP/{p}", "Δεν απαντά σε ping αλλά απαντά σε TCP")
        return res(False, str(gw), "Το gateway δεν απαντά")
    if fn == "link":
        sp = link_speed(info.get("iface"))
        if sp is None:
            return res(None, "", "Το σύστημα δεν δίνει ταχύτητα ζεύξης (Wi‑Fi ή Windows) — γράψε τη με το χέρι")
        try:
            want = int(arg or 100)
        except (TypeError, ValueError):
            want = 100
        return res(sp >= want, f"{sp} Mbps ({info.get('iface')})", "" if sp >= want else f"Κάτω από {want} Mbps — έλεγξε καλώδιο/τερματισμό")
    return res(None, "", "Άγνωστος έλεγχος")


def demo_run(fn, target, arg):
    """Demo: σταθερά, ψεύτικα αποτελέσματα — τίποτα δεν φεύγει στο δίκτυο."""
    h = zlib.crc32(f"{fn}|{target}|{arg}".encode()) % 100
    ok = h >= 12
    val = {"ping": f"απώλειες {0 if ok else 40}% · {1 + h % 7}.{h % 10} ms", "tcp": f"TCP {arg} {'open' if ok else 'filtered'}",
           "dns": f"{arg or 'example.com'} → 93.184.215.14", "internet": "1.1.1.1 · απώλειες 0% · 14 ms", "dhcp": "10.20.0.57/24 · gw 10.20.0.1 · DNS 10.20.0.1",
           "gateway": "10.20.0.1 · απώλειες 0% · 1.2 ms", "link": "1000 Mbps (en5)"}.get(fn, "")
    if fn in ("dns", "internet", "dhcp", "gateway", "link"):
        ok = True
    return {"ok": ok, "value": val, "note": "" if ok else "Δεν απάντησε (demo)"}


# ───────────────────────── ετυμηγορία ─────────────────────────
def verdict(statuses):
    """Λίστα καταστάσεων → "fail" αν υπάρχει αποτυχία, "pending" αν μένει κάτι (ή δεν υπάρχει τίποτα), αλλιώς "pass". Το «δεν αφορά» δεν μετρά."""
    st = [s for s in statuses if s != "na"]
    if "fail" in st:
        return "fail"
    if "pending" in st or not st:
        return "pending"
    return "pass"


def point_verdict(p):
    return verdict([c.get("status") for c in p.get("checks") or []])


def summarize(job):
    cs = [c.get("status") for p in job.get("points") or [] for c in p.get("checks") or []]
    pv = [point_verdict(p) for p in job.get("points") or []]
    return {"checks": {s: cs.count(s) for s in STATUSES}, "pts": {s: pv.count(s) for s in ("pass", "fail", "pending")},
            "total_points": len(pv), "verdict": "fail" if "fail" in pv else "pass" if pv and all(v == "pass" for v in pv) else "pending"}


def _err(el, en=None, code=400):
    return code, {"error": el, "error_en": en or el}


class Accept:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time, sites=None, run=None):
        self.state, self.demo, self.clock = state, demo, clock
        self.data_dir, self.sites = data_dir, sites
        self.run = run or (demo_run if demo else real_run)
        self.on_save = None
        self.lock = threading.RLock()
        self.jobs = {}
        self.busy = set()
        self._n = 0
        if demo:
            self._seed_demo()
        else:
            self._load()

    # ── αποθήκευση ──
    def _dir(self, site):
        d = self.sites.site_dir(site) if self.sites is not None and site else None
        return d or self.data_dir

    def _load(self):
        dirs = [self.data_dir] if self.data_dir else []
        if self.sites is not None:
            dirs += [d for d in (self.sites.site_dir(sid) for sid in self.sites.ids()) if d]
        for d in dirs:
            j = S.read_json(os.path.join(d, "accept.json"))
            for jid, job in ((j or {}).get("jobs") or {}).items() if isinstance(j, dict) and isinstance(j.get("jobs"), dict) else ():
                if isinstance(jid, str) and JOB_RE.match(jid) and isinstance(job, dict) and len(self.jobs) < MAX_JOBS:
                    self.jobs[jid] = self._norm_job(job, jid)

    def _save(self, site):
        d = self._dir(site)
        if not d:
            return
        S.write_json(os.path.join(d, "accept.json"), {"jobs": {k: v for k, v in self.jobs.items() if self._dir(v.get("site")) == d}}, self.on_save)

    # ── κανονικοποίηση (και για αρχεία από τον δίσκο) ──
    @staticmethod
    def _norm_check(c, i):
        c = c if isinstance(c, dict) else {}
        kind = "auto" if c.get("kind") == "auto" and c.get("fn") in AUTO_FNS else "manual"
        st = c.get("status") if c.get("status") in STATUSES else "pending"
        return {"id": re.sub(r"[^a-z0-9_-]", "", str(c.get("id") or "").lower())[:24] or f"c{i}", "kind": kind,
                "fn": c.get("fn") if kind == "auto" else "", "arg": clean(c.get("arg"), 60), "el": clean(c.get("el"), 160),
                "en": clean(c.get("en"), 160) or clean(c.get("el"), 160), "unit": clean(c.get("unit"), 12), "status": st,
                "value": clean(c.get("value"), 80), "note": clean(c.get("note"), 300), "t": float(c.get("t") or 0) if st != "pending" or c.get("t") else 0}

    def _norm_point(self, p, i):
        p = p if isinstance(p, dict) else {}
        typ = p.get("type") if p.get("type") in TYPES else "socket"
        checks, seen = [], set()
        for k, c in enumerate((p.get("checks") if isinstance(p.get("checks"), list) else [])[:MAX_CHECKS]):
            c = self._norm_check(c, k + 1)
            while c["id"] in seen:
                c["id"] += "x"
            seen.add(c["id"])
            checks.append(c)
        return {"id": re.sub(r"[^a-z0-9]", "", str(p.get("id") or ""))[:12] or f"p{i}", "type": typ, "label": clean(p.get("label"), 60).replace("\n", " "),
                "ip": clean(p.get("ip"), 45), "location": clean(p.get("location"), 80).replace("\n", " "), "checks": checks}

    def _norm_job(self, j, jid):
        site = j.get("site") if isinstance(j.get("site"), str) and S.SLUG_RE.match(j.get("site")) else ""
        pts = [self._norm_point(p, i + 1) for i, p in enumerate((j.get("points") if isinstance(j.get("points"), list) else [])[:MAX_POINTS])]
        return {"id": jid, "site": site, "title": clean(j.get("title"), 100).replace("\n", " "), "place": clean(j.get("place"), 100).replace("\n", " "),
                "tech": clean(j.get("tech"), 80), "rep": clean(j.get("rep"), 80), "remarks": clean(j.get("remarks"), 3000),
                "created": float(j.get("created") or self.clock()), "closed": float(j["closed"]) if j.get("closed") else None, "points": pts}

    # ── εργασίες ──
    def new_job(self, title, site=None, place="", tech="", rep=""):
        with self.lock:
            if len(self.jobs) >= MAX_JOBS:
                return None, "Πάρα πολλές εργασίες — σβήσε παλιές"
            if site is None and self.sites is not None:
                site = self.sites.detect()
            if site and (self.sites is None or not self.sites.get(site)):
                return None, "Άγνωστος πελάτης"
            self._n += 1
            jid = f"j{int(self.clock()):x}-{self._n}"
            while jid in self.jobs:
                self._n += 1
                jid = f"j{int(self.clock()):x}-{self._n}"
            co = self.sites.company() if self.sites is not None else {}
            sd = (self.sites.get(site) if self.sites is not None and site else None) or {}
            self.jobs[jid] = self._norm_job({"site": site or "", "title": title or "Εγκατάσταση δικτύου", "place": place or sd.get("address", ""),
                                             "tech": tech or co.get("tech", ""), "rep": rep or sd.get("contact", ""), "created": self.clock()}, jid)
            self._save(site or "")
            return self.jobs[jid], None

    def _job(self, jid, edit=True):
        j = self.jobs.get(jid) if isinstance(jid, str) else None
        if not j:
            return None, "Άγνωστη εργασία"
        if edit and j.get("closed"):
            return None, "Η εργασία έχει κλείσει — άνοιξέ την ξανά για αλλαγές"
        return j, None

    def save_job(self, jid, d):
        with self.lock:
            j, err = self._job(jid)
            if err:
                return None, err
            for k, n in (("title", 100), ("place", 100), ("tech", 80), ("rep", 80), ("remarks", 3000)):
                if k in d:
                    j[k] = clean(d.get(k), n) if k == "remarks" else clean(d.get(k), n).replace("\n", " ")
            self._save(j["site"])
            return j, None

    def close_job(self, jid, closed=True):
        with self.lock:
            j, err = self._job(jid, edit=False)
            if err:
                return None, err
            j["closed"] = self.clock() if closed else None
            self._save(j["site"])
            return j, None

    def delete_job(self, jid):
        with self.lock:
            j = self.jobs.pop(jid, None) if isinstance(jid, str) else None
            if j:
                self._save(j["site"])
            return bool(j)

    # ── σημεία ──
    def _pid(self, j):
        have = {p["id"] for p in j["points"]}
        i = len(j["points"]) + 1
        while f"p{i}" in have:
            i += 1
        return f"p{i}"

    def _mk_point(self, j, typ, label, ip="", location=""):
        if typ not in TYPES:
            raise ValueError("Άγνωστος τύπος σημείου")
        if len(j["points"]) >= MAX_POINTS:
            raise ValueError(f"Πάρα πολλά σημεία (όριο {MAX_POINTS})")
        ip = clean(ip, 45)
        if ip:
            import ipaddress
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError("Μη έγκυρη IP")
            if not a.is_private or a.is_loopback or a.is_multicast or a.is_unspecified:
                raise ValueError("Μόνο ιδιωτικές IP του τοπικού δικτύου")
        p = self._norm_point({"id": self._pid(j), "type": typ, "label": label or TYPES[typ][1], "ip": ip, "location": location,
                              "checks": [dict(c) for c in TYPES[typ][3]]}, 0)
        j["points"].append(p)
        return p

    def add_point(self, jid, typ, label, ip="", location=""):
        with self.lock:
            j, err = self._job(jid)
            if err:
                return None, err
            try:
                p = self._mk_point(j, typ, label, ip, location)
            except ValueError as e:
                return None, str(e)
            self._save(j["site"])
            return p, None

    def bulk_add(self, jid, typ, pattern, location=""):
        """«A-01..A-24» → 24 σημεία του ίδιου τύπου. → (πόσα, σφάλμα)."""
        with self.lock:
            j, err = self._job(jid)
            if err:
                return 0, err
            try:
                labels = S.expand(pattern, MAX_POINTS)
                if len(j["points"]) + len(labels) > MAX_POINTS:
                    raise ValueError(f"Πάρα πολλά σημεία (όριο {MAX_POINTS})")
                if typ not in TYPES:
                    raise ValueError("Άγνωστος τύπος σημείου")
                for lb in labels:
                    self._mk_point(j, typ, lb, "", location)
            except ValueError as e:
                return 0, str(e)
            self._save(j["site"])
            return len(labels), None

    def devices(self):
        return [dict(d, suggest=SUGGEST.get(d["dtype"], "")) for d in S.devices(self.state, 200) if d["ip"] and ":" not in d["ip"]]

    def import_devices(self, jid, ips=None, dtypes=None):
        """Σημεία από γνωστές συσκευές: συγκεκριμένες IP ή όλες ενός τύπου (π.χ. camera). Δεν ξαναβάζει IP που υπάρχει."""
        with self.lock:
            j, err = self._job(jid)
            if err:
                return 0, err
            have, n = {p["ip"] for p in j["points"] if p["ip"]}, 0
            ips = set(str(x) for x in ips) if isinstance(ips, list) else None
            dtypes = set(str(x) for x in dtypes) if isinstance(dtypes, list) else None
            for d in self.devices():
                if d["ip"] in have or (ips is not None and d["ip"] not in ips) or (dtypes is not None and d["dtype"] not in dtypes) \
                        or (ips is None and dtypes is None):
                    continue
                try:
                    self._mk_point(j, d["suggest"] or "iot", d["name"] or d["ip"], d["ip"], "")
                    n += 1
                except ValueError:
                    continue
            if n:
                self._save(j["site"])
            return n, None

    def delete_point(self, jid, pid):
        with self.lock:
            j, err = self._job(jid)
            if err:
                return False, err
            n = len(j["points"])
            j["points"] = [p for p in j["points"] if p["id"] != pid]
            self._save(j["site"])
            return len(j["points"]) != n, None

    def _find(self, jid, pid, cid=None):
        j, err = self._job(jid)
        if err:
            return None, None, None, err
        p = next((x for x in j["points"] if x["id"] == pid), None)
        if not p:
            return j, None, None, "Άγνωστο σημείο"
        c = next((x for x in p["checks"] if x["id"] == cid), None) if cid is not None else None
        if cid is not None and not c:
            return j, p, None, "Άγνωστος έλεγχος"
        return j, p, c, None

    def set_check(self, jid, pid, cid, status=None, value=None, note=None):
        """Ο τεχνικός τσεκάρει έναν έλεγχο (και αυτόματο, αν θέλει να τον διορθώσει με το χέρι)."""
        with self.lock:
            j, p, c, err = self._find(jid, pid, cid)
            if err:
                return None, err
            if status is not None:
                if status not in STATUSES:
                    return None, "Άγνωστη κατάσταση"
                c["status"] = status
            if value is not None:
                c["value"] = clean(value, 80)
            if note is not None:
                c["note"] = clean(note, 300)
            c["t"] = self.clock()
            self._save(j["site"])
            return c, None

    def add_check(self, jid, pid, el, unit=""):
        with self.lock:
            j, p, _, err = self._find(jid, pid)
            if err:
                return None, err
            if not clean(el, 160) or len(p["checks"]) >= MAX_CHECKS:
                return None, "Γράψε τι ελέγχεις" if not clean(el, 160) else "Πάρα πολλοί έλεγχοι στο σημείο"
            c = self._norm_check({"id": f"x{len(p['checks']) + 1}{int(self.clock()) % 1000}", "el": el, "en": el, "unit": unit}, 0)
            p["checks"].append(c)
            self._save(j["site"])
            return c, None

    # ── εκτέλεση αυτόματων ελέγχων ──
    def run_checks(self, jid, pid=None, cid=None):
        """Τρέχει (σύγχρονα) τους αυτόματους ελέγχους μιας εργασίας / ενός σημείου / ενός ελέγχου. → πόσοι έτρεξαν."""
        with self.lock:
            j, err = self._job(jid)
            if err:
                return 0
            todo = [(p["id"], c["id"], c["fn"], p["ip"], c["arg"]) for p in j["points"] if pid in (None, p["id"])
                    for c in p["checks"] if c["kind"] == "auto" and cid in (None, c["id"])]
        n = 0
        for ppid, ccid, fn, ip, arg in todo:
            try:
                r = self.run(fn, ip, arg) or {}
            except Exception as e:  # noqa: BLE001 — ένας έλεγχος που σκάει δεν σταματά τους υπόλοιπους
                r = {"ok": None, "value": "", "note": "Σφάλμα ελέγχου: " + str(e)[:120]}
            with self.lock:
                j, p, c, err = self._find(jid, ppid, ccid)
                if err:
                    continue
                c.update(status="pass" if r.get("ok") is True else "fail" if r.get("ok") is False else "pending",
                         value=clean(r.get("value"), 80), note=clean(r.get("note"), 300), t=self.clock())
                n += 1
        with self.lock:
            j = self.jobs.get(jid)
            if j:
                self._save(j["site"])
        return n

    def start_run(self, jid, pid=None, cid=None):
        with self.lock:
            j, err = self._job(jid)
            if err:
                return err
            if jid in self.busy:
                return None
            self.busy.add(jid)

        def work():
            try:
                self.run_checks(jid, pid, cid)
            finally:
                self.busy.discard(jid)
        threading.Thread(target=work, daemon=True, name="nw-accept").start()
        return None

    # ── προβολή ──
    def _sum(self, j):
        s = summarize(j)
        sd = (self.sites.get(j["site"]) if self.sites is not None and j["site"] else None) or {}
        return dict({k: j[k] for k in ("id", "site", "title", "place", "created", "closed")}, site_name=sd.get("name", ""), busy=j["id"] in self.busy, **s)

    def job_view(self, jid):
        with self.lock:
            j = self.jobs.get(jid) if isinstance(jid, str) else None
            if not j:
                return None
            return dict(self._sum(j), tech=j["tech"], rep=j["rep"], remarks=j["remarks"],
                        points=[dict(p, verdict=point_verdict(p), checks=[dict(c) for c in p["checks"]]) for p in j["points"]])

    def view(self):
        with self.lock:
            jobs = sorted((self._sum(j) for j in self.jobs.values()), key=lambda x: (bool(x["closed"]), -x["created"]))
            sl = [{"id": sid, "name": (self.sites.get(sid) or {}).get("name", sid)} for sid in self.sites.ids()] if self.sites is not None else []
            return {"demo": self.demo, "busy": bool(self.busy), "jobs": jobs, "site": self.sites.detect() if self.sites is not None else None, "sites": sl,
                    "types": [{"id": k, "icon": v[0], "el": v[1], "en": v[2], "auto": sum(1 for c in v[3] if c["kind"] == "auto"), "manual": sum(1 for c in v[3] if c["kind"] == "manual")}
                              for k, v in TYPES.items()],
                    "counts": {"jobs": len(jobs), "open": sum(1 for x in jobs if not x["closed"]), "fail": sum(x["checks"]["fail"] for x in jobs if not x["closed"]),
                               "pending": sum(x["checks"]["pending"] for x in jobs if not x["closed"])},
                    "devices": self.devices()}

    # ── αναφορά αποδοχής ──
    def report_html(self, jid, lang="el"):
        lang = "en" if lang == "en" else "el"
        with self.lock:
            j = self.job_view(jid)
        if not j:
            return None
        co = self.sites.company() if self.sites is not None else {}
        site = (self.sites.get(j["site"]) if self.sites is not None and j["site"] else None) or {"name": j["rep"] or "—", "address": j["place"]}
        st_l = {"pass": L(lang, "ΠΕΡΑΣΕ", "PASS"), "fail": L(lang, "ΑΠΕΤΥΧΕ", "FAIL"), "pending": L(lang, "ΕΚΚΡΕΜΕΙ", "PENDING"), "na": L(lang, "δεν αφορά", "n/a")}
        st_c = {"pass": "pass", "fail": "fail", "pending": "pend", "na": "na"}
        v = j["verdict"]
        vtxt = {"pass": L(lang, "✔ ΑΠΟΔΕΚΤΗ — όλα τα σημεία πέρασαν τους ελέγχους", "✔ ACCEPTED — every point passed its checks"),
                "fail": L(lang, f"✘ ΜΗ ΑΠΟΔΕΚΤΗ ΑΚΟΜΗ — {j['pts']['fail']} σημεία με αποτυχία", f"✘ NOT ACCEPTED YET — {j['pts']['fail']} point(s) failed"),
                "pending": L(lang, f"… ΣΕ ΕΞΕΛΙΞΗ — {j['checks']['pending']} έλεγχοι εκκρεμούν", f"… IN PROGRESS — {j['checks']['pending']} check(s) pending")}[v]
        vcol = {"pass": "#0a7a3d", "fail": "#c0182d", "pending": "#9a6a00"}[v]
        title = L(lang, "Πρωτόκολλο ελέγχου & αποδοχής εγκατάστασης", "Installation test & acceptance report")
        h = [S.doc_open(f"{title} — {j['title']}", lang, self.demo), S.doc_header(co, lang, j["id"], j["closed"] or self.clock()),
             f"<h1>{title}</h1><div class=\"sub\">{esc(j['title'])}</div>",
             f'<div class="grid">{S.customer_block(site, lang)}<div class="boxx"><div class="k">{L(lang, "Έργο", "Job")}</div><b>{esc(j["title"])}</b>'
             f'<div>{L(lang, "Τόπος", "Place")}: {esc(j["place"] or "—")}</div><div>{L(lang, "Τεχνικός", "Technician")}: {esc(j["tech"] or "—")}</div>'
             f'<div>{L(lang, "Έναρξη", "Started")}: {esc(S.ts(j["created"], lang))}{(" · " + L(lang, "Ολοκλήρωση", "Completed") + ": " + esc(S.ts(j["closed"], lang))) if j["closed"] else ""}</div></div></div>',
             f'<div class="verdict" style="--c:{vcol}">{esc(vtxt)}</div>',
             f'<div class="kpis"><div><b>{j["total_points"]}</b><span>{L(lang, "σημεία", "points")}</span></div>'
             f'<div><b class="pass">{j["pts"]["pass"]}</b><span>{L(lang, "πέρασαν", "passed")}</span></div>'
             f'<div><b class="fail">{j["pts"]["fail"]}</b><span>{L(lang, "απέτυχαν", "failed")}</span></div>'
             f'<div><b class="pend">{j["pts"]["pending"]}</b><span>{L(lang, "εκκρεμούν", "pending")}</span></div>'
             f'<div><b>{j["checks"]["pass"]}/{j["checks"]["fail"]}/{j["checks"]["pending"]}/{j["checks"]["na"]}</b><span>{L(lang, "έλεγχοι ✔/✘/…/—", "checks ✔/✘/…/—")}</span></div></div>',
             f"<h2>1. {L(lang, 'Έλεγχοι ανά σημείο', 'Checks per point')}</h2>"]
        out = []
        for p in j["points"]:
            t = TYPES[p["type"]]
            pv = p["verdict"]
            h.append(f'<table><tr><th colspan="4">{t[0]} {esc(p["label"])} — {esc(L(lang, t[1], t[2]))}'
                     f'{(" · <span class=mono>" + esc(p["ip"]) + "</span>") if p["ip"] else ""}{(" · " + esc(p["location"])) if p["location"] else ""}'
                     f' — <span class="{st_c[pv]}">{st_l[pv]}</span></th></tr>'
                     f'<tr><th style="width:46%">{L(lang, "Έλεγχος", "Check")}</th><th style="width:13%">{L(lang, "Αποτέλεσμα", "Result")}</th>'
                     f'<th style="width:18%">{L(lang, "Τιμή", "Value")}</th><th>{L(lang, "Σημείωση", "Note")}</th></tr>')
            for c in p["checks"]:
                name = L(lang, c["el"], c["en"])
                val = (c["value"] + (" " + c["unit"] if c["unit"] and c["value"] else "")) if c["value"] else ""
                h.append(f'<tr><td>{"⚙" if c["kind"] == "auto" else "✍"} {esc(name)}</td><td class="{st_c[c["status"]]}">{st_l[c["status"]]}</td>'
                         f'<td>{esc(val)}</td><td>{esc(c["note"])}</td></tr>')
                if c["status"] in ("fail", "pending"):
                    out.append((p["label"], name, st_l[c["status"]], c["note"]))
            h.append("</table>")
        if not j["points"]:
            h.append(f"<p>{L(lang, 'Δεν έχουν προστεθεί σημεία.', 'No points have been added.')}</p>")
        h.append(f'<div class="sub">⚙ {L(lang, "αυτόματος έλεγχος από το NetWatch", "automatic check by NetWatch")} · ✍ {L(lang, "έλεγχος/μέτρηση τεχνικού", "technician check/measurement")}</div>')
        h.append(f"<h2>2. {L(lang, 'Παρατηρήσεις / εκκρεμότητες', 'Remarks / outstanding items')}</h2>")
        if out:
            h.append("<ul>" + "".join(f"<li><b>{esc(a)}</b>: {esc(b)} — {esc(c)}{(' (' + esc(d) + ')') if d else ''}</li>" for a, b, c, d in out[:120]) + "</ul>")
        h.append(f'<div class="lines">{esc(j["remarks"])}</div>')
        h.append(f'<p style="margin-top:8mm">{L(lang, "Τόπος", "Place")}: {esc(j["place"] or "________________")} &nbsp;&nbsp; '
                 f'{L(lang, "Ημερομηνία", "Date")}: {esc(S.ts(j["closed"] or self.clock(), lang, True))}</p>')
        h.append(S.signatures(lang, L(lang, "Για τον εγκαταστάτη", "For the installer") + (f": {j['tech']}" if j["tech"] else ""),
                              L(lang, "Για τον πελάτη (παραλαβή)", "For the customer (acceptance)") + (f": {j['rep']}" if j["rep"] else ""), boxes=True))
        h.append(S.doc_close(lang))
        return "".join(h)

    # ── API ──
    def api(self, method, sub, q, body):
        q, body = q or {}, body if isinstance(body, dict) else {}
        if method == "GET":
            if sub == "":
                return 200, self.view()
            if sub == "job":
                j = self.job_view(q.get("id"))
                return (200, j) if j else (404, {"error": "not found"})
            if sub == "report":
                doc = self.report_html(q.get("id"), q.get("lang"))
                return S.raw(doc, f"netwatch-acceptance-{q.get('id')}.html") if doc else (404, {"error": "not found"})
            return 404, {"error": "not found"}
        if method != "POST":
            return 404, {"error": "not found"}
        jid = body.get("job")
        err = None
        if sub == "job/new":
            j, err = self.new_job(clean(body.get("title"), 100), body.get("site") if "site" in body else None, body.get("place") or "",
                                  body.get("tech") or "", body.get("rep") or "")
            jid = j["id"] if j else None
        elif sub == "job/save":
            _, err = self.save_job(jid, body)
        elif sub == "job/close":
            _, err = self.close_job(jid, body.get("closed", True) is not False)
        elif sub == "job/delete":
            return (200, self.view()) if self.delete_job(jid) else (404, {"error": "not found"})
        elif sub == "point/add":
            _, err = self.add_point(jid, body.get("type"), body.get("label"), body.get("ip") or "", body.get("location") or "")
        elif sub == "point/bulk":
            _, err = self.bulk_add(jid, body.get("type"), body.get("pattern"), body.get("location") or "")
        elif sub == "point/import":
            n, err = self.import_devices(jid, body.get("ips"), body.get("dtypes"))
        elif sub == "point/delete":
            _, err = self.delete_point(jid, body.get("point"))
        elif sub == "check":
            _, err = self.set_check(jid, body.get("point"), body.get("check"), body.get("status"), body.get("value"), body.get("note"))
        elif sub == "check/add":
            _, err = self.add_check(jid, body.get("point"), body.get("el"), body.get("unit") or "")
        elif sub == "run":
            err = self.start_run(jid, body.get("point"), body.get("check"))
        else:
            return 404, {"error": "not found"}
        if err:
            return _err(err)
        return 200, dict(self.view(), job=self.job_view(jid))

    # ── demo ──
    def _seed_demo(self):
        now, day = self.clock(), 86400.0
        site = "hotel-aegean" if self.sites is not None and self.sites.get("hotel-aegean") else ""

        def job(jid, title, created, closed, remarks):
            self.jobs[jid] = self._norm_job({"site": site, "title": title, "place": "Νάξος", "tech": "Γιώργος Παπαδόπουλος", "rep": "Ελένη Βλάχου",
                                             "created": created, "closed": closed, "remarks": remarks}, jid)
            return self.jobs[jid]

        def fill(p, t, fails=(), pend=(), vals=None):
            for c in p["checks"]:
                c["status"], c["t"] = "fail" if c["id"] in fails else "pending" if c["id"] in pend else "pass", t
                c["value"] = (vals or {}).get(c["id"], "")
                if c["kind"] == "auto" and c["status"] != "pending":
                    r = demo_run(c["fn"], p["ip"], c["arg"])
                    c["value"] = (r["value"] if r["ok"] else "") if c["status"] == "pass" else f"TCP {c['arg']} filtered" if c["fn"] == "tcp" else ""
                if c["status"] == "fail":
                    c["note"] = {"rtsp": "Η ροή δεν ανοίγει — λάθος θύρα στο NVR", "poe": "Οριακή ισχύς στο injector", "wiremap": "Ζεύγος 3-6 ανάποδα — επανατερματισμός",
                                 "retention": "Ο δίσκος φτάνει μόνο για 12 ημέρες"}.get(c["id"], "Να ξαναγίνει")

        a = job("jdemo-1", "Επέκταση CCTV & δικτύου — πτέρυγα Β", now - 9 * day, now - 7 * day,
                "Η κάμερα πάρκινγκ (cam-12) θα ρυθμιστεί ξανά στο NVR στην επόμενη επίσκεψη.\nΟ πελάτης ζήτησε 30 ημέρες εγγραφής — χρειάζεται δίσκος 8 TB.")
        t = now - 7 * day - 3600
        for i in range(9, 13):
            p = self._mk_point(a, "camera", f"cam-{i:02d}", f"10.20.0.{100 + i}", "Πτέρυγα Β" if i < 12 else "Πάρκινγκ")
            fill(p, t, fails=("rtsp", "retention") if i == 12 else (), vals={"poe": "6.4", "retention": "12" if i == 12 else "30"})
        p = self._mk_point(a, "switch", "sw-rack-B", "10.20.0.3", "Rack πτέρυγας Β")
        fill(p, t, vals={"ups": "18"})
        for i in range(1, 5):
            p = self._mk_point(a, "socket", f"B-{i:02d}", "", "Γραφείο υποδοχής Β")
            fill(p, t, fails=("wiremap",) if i == 3 else (), vals={"length": str(22 + 6 * i)})
        b = job("jdemo-2", "Νέα access points — ισόγειο", now - 3 * 3600, None, "")
        for i, loc in enumerate(("Lobby", "Εστιατόριο", "Πισίνα"), 1):
            p = self._mk_point(b, "ap", f"ap-{i:02d}", f"10.20.0.{30 + i}", loc)
            if i == 1:
                fill(p, now - 3000, vals={"poe": "11.2", "signal": "-58"})
            elif i == 2:
                fill(p, now - 1200, pend=("roam", "guest", "label"), vals={"poe": "10.9", "signal": "-63"})
        self._mk_point(b, "uplink", "VDSL παρόχου", "", "Rack υποδοχής")
