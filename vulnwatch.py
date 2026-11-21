"""🛡 Ευπάθειες για τις συσκευές σου — από τη λίστα CISA KEV (ευπάθειες που ΗΔΗ εκμεταλλεύονται επιτιθέμενοι).

Μία φορά τη μέρα κατεβάζουμε τη δημόσια λίστα της CISA (public domain) και, για όσες βρέθηκαν, την πιθανότητα
επίθεσης από το FIRST EPSS. Η σύγκριση με τις συσκευές σου γίνεται τοπικά: δεν στέλνουμε τίποτα για το δίκτυό σου
(το EPSS ρωτιέται μόνο με αριθμούς CVE).

Τίμια όρια: συνήθως ξέρουμε μόνο τον κατασκευαστή (από τη MAC), όχι μοντέλο/firmware. Γι' αυτό λέμε
«πιθανόν σε αφορά — έλεγξε το μοντέλο σου», όχι «είσαι ευάλωτος». Αν το όνομα της συσκευής ταιριάζει με το
προϊόν (π.χ. «TL-WR841N»), το σημειώνουμε ως «ταιριάζει και το μοντέλο».
"""
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?"
DAY = 86400
MAX_KEV = 12 * 1024 * 1024
ATTRIB = ("CISA Known Exploited Vulnerabilities (public domain) · EPSS: FIRST.org (https://www.first.org/epss) · "
          "This product uses data from the NVD API but is not endorsed or certified by the NVD.")

# κατασκευαστής (όπως τον γράφει η βάση MAC/OUI, πεζά) → όνομα στη λίστα KEV
VENDORS = [
    ("d-link", "D-Link"), ("tp-link", "TP-Link"), ("netgear", "NETGEAR"), ("zyxel", "Zyxel"), ("mikrotik", "MikroTik"),
    ("routerboard", "MikroTik"), ("draytek", "DrayTek"), ("synology", "Synology"), ("qnap", "QNAP"),
    ("hikvision", "Hikvision"), ("dahua", "Dahua"), ("ubiquiti", "Ubiquiti"), ("asustek", "ASUS"), ("asus", "ASUS"),
    ("linksys", "Linksys"), ("tenda", "Tenda"), ("totolink", "TOTOLINK"), ("cisco", "Cisco"), ("fortinet", "Fortinet"),
    ("sonicwall", "SonicWall"), ("juniper", "Juniper"), ("arista", "Arista"), ("western digital", "Western Digital"),
    ("huawei", "Huawei"), ("zte", "ZTE"), ("xiaomi", "Xiaomi"), ("samsung", "Samsung"), ("apple", "Apple"),
    ("microsoft", "Microsoft"), ("google", "Google"), ("hewlett packard enterprise", "Hewlett Packard Enterprise (HPE)"),
    ("hewlett", "HP"), ("hp inc", "HP"), ("lexmark", "Lexmark"), ("xerox", "Xerox"), ("kyocera", "Kyocera"),
    ("sophos", "Sophos"), ("palo alto", "Palo Alto Networks"), ("watchguard", "WatchGuard"), ("avtech", "AVTECH"),
    ("realtek", None),  # κάρτα δικτύου σε PC — όχι router SDK· αγνοείται
]
# «συσκευές με firmware» → δείχνουμε τις ευπάθειες· υπολογιστές/κινητά → απλή σύνοψη «κράτα το λειτουργικό ενημερωμένο»
FIRMWARE = ("router", "nas", "camera", "printer", "iot", "esp", "tv", "speaker", "console", "pi", "vm", "unknown", "")
EVERYDAY = ("Apple", "Microsoft", "Google", "Android", "Samsung")
GENERIC = {"multiple", "products", "product", "router", "routers", "devices", "device", "firmware", "server", "camera",
           "cameras", "web", "security", "network", "the", "and", "for", "management", "interface", "system", "systems"}

# Demo / χωρίς δίκτυο: πραγματικές εγγραφές της CISA KEV για τις συσκευές του demo (TP-Link, Hikvision, Apple)
DEMO_KEV = [
    {"cveID": "CVE-2023-50224", "vendorProject": "TP-Link", "product": "TL-WR841N", "vulnerabilityName": "TP-Link TL-WR841N Authentication Bypass by Spoofing Vulnerability",
     "dateAdded": "2025-09-03", "shortDescription": "TP-Link TL-WR841N contains an authentication bypass by spoofing vulnerability within the httpd service, which listens on TCP port 80 by default, leading to the disclose of stored credentials.", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2025-9377", "vendorProject": "TP-Link", "product": "Multiple Routers", "vulnerabilityName": "TP-Link Archer C7(EU) and TL-WR841N/ND(MS) OS Command Injection Vulnerability",
     "dateAdded": "2025-09-03", "shortDescription": "TP-Link Archer C7(EU) and TL-WR841N/ND(MS) contain an OS command injection vulnerability that exists in the Parental Control page.", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2017-7921", "vendorProject": "Hikvision", "product": "Multiple Products", "vulnerabilityName": "Hikvision Multiple Products Improper Authentication Vulnerability",
     "dateAdded": "2026-03-05", "shortDescription": "Multiple Hikvision products contain an improper authentication vulnerability that could allow a malicious user to escalate privileges and access sensitive information.", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2021-36260", "vendorProject": "Hikvision", "product": "Security cameras web server", "vulnerabilityName": "Hikvision Improper Input Validation",
     "dateAdded": "2022-01-10", "shortDescription": "Certain Hikvision products contain a command injection vulnerability in the web server due to the insufficient checking of input parameters.", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2024-27834", "vendorProject": "Apple", "product": "Multiple Products", "vulnerabilityName": "Apple Multiple Products Vulnerability",
     "dateAdded": "2026-11-04", "shortDescription": "Apple iOS, iPadOS, macOS, and Safari contain a vulnerability that could allow an attacker with arbitrary read and write capability to bypass Pointer Authentication.", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2025-43510", "vendorProject": "Apple", "product": "Multiple Products", "vulnerabilityName": "Apple Multiple Products Improper Locking Vulnerability",
     "dateAdded": "2026-03-20", "shortDescription": "Apple watchOS, iOS, iPadOS, macOS, visionOS, and tvOS contain an improper locking vulnerability.", "knownRansomwareCampaignUse": "Unknown"},
]
DEMO_EPSS = {"CVE-2023-50224": 0.71, "CVE-2025-9377": 0.62, "CVE-2017-7921": 0.94, "CVE-2021-36260": 0.97,
             "CVE-2024-27834": 0.08, "CVE-2025-43510": 0.03}
KEEP_FIELDS = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription", "knownRansomwareCampaignUse")


def _fetch(url, limit):
    req = urllib.request.Request(url, headers={"User-Agent": "NetWatch (KEV/EPSS)", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as r:  # nosec — σταθερά URL (cisa.gov, api.first.org)
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError("πολύ μεγάλη απάντηση")
    return data


def kev_vendor(vendor):
    v = (vendor or "").lower()
    for k, name in VENDORS:
        if k in v:
            return name
    return None


def _tokens(product):
    return {t for t in re.split(r"[\s,/()]+", (product or "").lower()) if len(t) >= 4 and t not in GENERIC}


def match(devices, kev, epss=None, now=None):
    """devices: [{ip, name, names, vendor, dtype, gw}] → ομάδες ανά συσκευή + σύνοψη για υπολογιστές/κινητά."""
    epss = epss or {}
    now = now or time.time()
    by_vendor = {}
    for x in kev:
        by_vendor.setdefault(x.get("vendorProject"), []).append(x)
    hits, everyday = [], {}
    for d in devices:
        kv = kev_vendor(d.get("vendor"))
        if not kv or kv not in by_vendor:
            continue
        t = d.get("dtype") or ""
        if kv in EVERYDAY and t not in ("router", "tv", "speaker", "nas", "camera") and not d.get("gw"):
            e = everyday.setdefault(kv, {"vendor": kv, "devices": [], "recent": 0, "top": []})
            e["devices"].append(d.get("name") or d.get("ip"))
            continue
        if t not in FIRMWARE and not d.get("gw"):
            continue
        text = " ".join([d.get("name") or ""] + list(d.get("names") or ())).lower()
        vulns = []
        for x in by_vendor[kv]:
            model = any(tok in text for tok in _tokens(x.get("product")))
            vulns.append({**{k: x.get(k) for k in KEEP_FIELDS}, "model": model, "epss": epss.get(x.get("cveID"))})
        vulns.sort(key=lambda v: v["dateAdded"] or "", reverse=True)  # νεότερες πρώτα…
        vulns.sort(key=lambda v: (not v["model"], -(v["epss"] or 0)))  # …αλλά πρώτα όσες ταιριάζουν στο μοντέλο / πιο πιθανές
        hits.append({"ip": d.get("ip"), "name": d.get("name") or d.get("ip"), "vendor": kv, "dtype": t, "gw": bool(d.get("gw")),
                     "model_match": any(v["model"] for v in vulns), "count": len(vulns), "vulns": vulns[:8],
                     "ransomware": any(v.get("knownRansomwareCampaignUse") == "Known" for v in vulns)})
    for kv, e in everyday.items():
        recent = sorted(by_vendor[kv], key=lambda x: x.get("dateAdded") or "", reverse=True)
        cut = time.strftime("%Y-%m-%d", time.gmtime(now - 30 * DAY))
        e["recent"] = sum(1 for x in recent if (x.get("dateAdded") or "") >= cut)
        e["total"] = len(recent)
        e["top"] = [{k: x.get(k) for k in KEEP_FIELDS} for x in recent[:3]]
        e["devices"] = sorted(set(e["devices"]))[:12]
    hits.sort(key=lambda h: (not h["model_match"], not h["gw"], -h["count"]))
    return hits, sorted(everyday.values(), key=lambda e: -e["recent"])


class VulnWatch:
    def __init__(self, state, data_dir=None, demo=False, fetch=None, clock=time.time):
        self.state, self.demo, self.clock = state, demo, clock
        self.fetch = fetch or _fetch
        self.path = os.path.join(data_dir, "kev.json") if data_dir else None
        self.kev, self.epss, self.version, self.fetched, self.err = [], {}, None, 0, None
        self.lock = threading.Lock()
        self.busy = False
        if demo:
            self.kev, self.epss, self.version, self.fetched = DEMO_KEV, DEMO_EPSS, "demo", clock()
        else:
            self._load()

    # ── λίστα ──
    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                j = json.load(f)
            self.kev, self.epss = j.get("kev") or [], j.get("epss") or {}
            self.version, self.fetched = j.get("version"), float(j.get("fetched") or 0)
        except (OSError, ValueError, TypeError):
            pass

    def _save(self):
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"kev": self.kev, "epss": self.epss, "version": self.version, "fetched": self.fetched}, f)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def refresh(self, force=False):
        """Κατεβάζει τη λίστα KEV (μία φορά τη μέρα) και το EPSS για όσα CVE ταιριάζουν με συσκευές σου."""
        if self.demo:
            return self.view()
        with self.lock:
            if self.busy or (not force and self.fetched and self.clock() - self.fetched < DAY):
                return self.view()
            self.busy = True
        try:
            j = json.loads(self.fetch(KEV_URL, MAX_KEV))
            vs = j.get("vulnerabilities")
            if not isinstance(vs, list) or not vs:
                raise ValueError("άδεια λίστα")
            self.kev = [{k: str(x.get(k) or "")[:600] for k in KEEP_FIELDS} for x in vs if isinstance(x, dict) and x.get("cveID")]
            self.version, self.fetched, self.err = str(j.get("catalogVersion") or "")[:20], self.clock(), None
            self._epss()
            self._save()
        except Exception as e:  # noqa: BLE001 — δίκτυο/JSON: κρατάμε την παλιά λίστα
            self.err = "Δεν μπόρεσα να κατεβάσω τη λίστα της CISA: " + str(e)[:160]
        finally:
            self.busy = False
        return self.view()

    def _epss(self):
        hits, _ = match(self.devices(), self.kev)
        cves = sorted({v["cveID"] for h in hits for v in h["vulns"]})[:100]
        if not cves:
            return
        try:
            j = json.loads(self.fetch(EPSS_URL + urllib.parse.urlencode({"cve": ",".join(cves)}), 2 * 1024 * 1024))
            for r in j.get("data") or []:
                if re.match(r"^CVE-\d{4}-\d+$", str(r.get("cve") or "")):
                    self.epss[r["cve"]] = round(float(r.get("epss") or 0), 4)
        except Exception:  # noqa: BLE001 — το EPSS είναι προαιρετικό
            pass

    # ── συσκευές ──
    def devices(self):
        st = self.state
        if st is None:
            return []
        lock = getattr(st, "lock", None)
        with lock if lock else _Null():
            hosts = [h for h in (getattr(st, "hosts", None) or {}).values() if h.get("kind") == "local"]
        out = []
        for h in hosts:
            try:
                dt = st._dtype(h) if hasattr(st, "_dtype") else {}
            except Exception:  # noqa: BLE001
                dt = {}
            names = sorted(h.get("names") or ())
            out.append({"ip": h.get("ip"), "name": dt.get("alias") or (names[0] if names else h.get("rdns") or h.get("ip")),
                        "names": names + ([h["rdns"]] if h.get("rdns") else []), "vendor": dt.get("vendor") or "",
                        "dtype": dt.get("dtype") or "", "gw": bool(h.get("gw"))})
        return out

    def view(self):
        hits, everyday = match(self.devices(), self.kev, self.epss, self.clock())
        return {"version": self.version, "fetched": self.fetched, "count": len(self.kev), "error": self.err, "demo": self.demo,
                "busy": self.busy, "devices": hits, "everyday": everyday, "attribution": ATTRIB,
                "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}

    def run_forever(self):
        time.sleep(60)
        while True:
            try:
                self.refresh()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(3600)


class _Null:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False
