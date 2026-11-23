"""NetWatch — 🎯 Πάγκος κυνηγιού απειλών (threat hunting workbench).

Οι ανιχνευτές (detect.py) περιμένουν να «χτυπήσει» ένα όριο. Το κυνήγι κάνει το ανάποδο: ξεκινάς από μια
ΥΠΟΘΕΣΗ («αν κάποια συσκευή είχε μολυνθεί, θα μιλούσε σπάνια με έναν server που δεν μιλά κανείς άλλος»),
ψάχνεις στα δεδομένα που ήδη υπάρχουν και κρίνεις τα ευρήματα — ο κύκλος του Sqrrl (υπόθεση → έρευνα →
μοτίβα → εμπλουτισμός) και το PEAK framework (Prepare / Execute / Act with Knowledge).

Τεχνικές:
* stack counting / long tail (Michael Collins, «Network Security Through Data Analysis»): μέτρα πόσες
  συσκευές μιλούν με κάθε προορισμό· το ενδιαφέρον είναι στην «ουρά» — ό,τι είδε μόνο μία συσκευή, λίγες φορές.
* friendly intelligence (Chris Sanders, «Applied Network Security Monitoring»): ξέρε τι είναι «κανονικό»
  για κάθε συσκευή (ώρες, προορισμοί, θύρες, αποτυπώματα TLS) ώστε να ξεχωρίζει το ασυνήθιστο → profile().

Πηγές: state.hosts (μετρητές ανά IP), state.alerts, state.timeline (κουβάδες του λεπτού, 24 ώρες), state.baseline
(χώρες ανά συσκευή) και, αν έχει μπει το hook στο detect.py, το observe() εδώ (ερωτήματα DNS ανά πελάτη, JA4).
Τίποτα δεν φεύγει στο δίκτυο· όλα είναι ερωτήματα σε δεδομένα που ήδη κρατά το NetWatch.

Στο demo (sim=True) προστίθενται λίγα, σημαδεμένα («demo»), συνθετικά επεισόδια πάνω στο 24ωρο του timeline
ώστε κάθε υπόθεση να έχει κάτι να δείξει.
"""
import collections
import contextlib
import ipaddress
import math
import re
import threading
import time

from core import DNS_RESOLVERS, SERVICES, dga_score, entropy, split_domain

MAX_FINDINGS = 25
BAD_CC = {"CN": "Κίνα", "RU": "Ρωσία", "KP": "Βόρεια Κορέα", "IR": "Ιράν"}
NIGHT = (1, 2, 3, 4)            # 01:00–05:00 τοπική ώρα
DAY = tuple(range(8, 23))       # 08:00–23:00
COMMON_PORTS = {53, 67, 68, 80, 123, 137, 138, 443, 853, 1900, 5353, 5355, 8008, 8009, 8443, 5222, 5223, 1883, 8883, 9100, 631}
RISKY_PORTS = {23, 2323, 4444, 5555, 6667, 1080, 3389, 5900, 8291, 31337, 9001, 7547}
RARE_TLD = (".top", ".xyz", ".biz", ".info", ".click", ".gq", ".tk", ".ml", ".cf", ".ga", ".pw", ".su", ".ru", ".cn", ".zip", ".mov")
BIG_NAMES = ("google", "gstatic", "googleapis", "youtube", "apple", "icloud", "amazonaws", "cloudfront", "cloudflare",
             "akamai", "microsoft", "windows", "office", "azure", "facebook", "fbcdn", "whatsapp", "instagram",
             "netflix", "nflx", "spotify", "github", "fastly", "wikipedia", "ntp.org")
BACKUP_NAMES = ("backblaze", "icloud", "dropbox", "drive.google", "onedrive", "s3.", "amazonaws", "wasabi", "pcloud",
                "mega.nz", "synology", "tailscale")
IOT_WORDS = ("cam", "κάμερα", "tv", "tapo", "tuya", "plug", "πρίζα", "esp", "printer", "εκτυπωτ", "iot", "bulb", "λάμπα",
             "sensor", "thermostat", "speaker", "chromecast", "roku")


def _tech(tid, name):
    return {"id": tid, "name": name, "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"}


HUNTS = {
    "longtail": {
        "title": "Σπάνιοι προορισμοί (long tail)",
        "hypothesis": "Μια μολυσμένη συσκευή θα μιλούσε με έναν server που δεν μιλά καμία άλλη συσκευή του σπιτιού — και λίγες φορές μόνο.",
        "mitre": _tech("T1071", "Application Layer Protocol"),
        "source": "Michael Collins — Network Security Through Data Analysis (stack counting)",
        "method": "stack counting",
        "data": "Προορισμοί ανά συσκευή (μετρητές NetWatch) + ακμές του timeline 24 ωρών",
        "steps": ["Μέτρα για κάθε δημόσια IP πόσες συσκευές του LAN τη μίλησαν και πόσες φορές.",
                  "Κράτα την «ουρά»: προορισμούς μίας μόνο συσκευής, με λίγες συνδέσεις.",
                  "Δες ποιος είναι ο server (όνομα, χώρα, whois) και αν ταιριάζει με τη συσκευή.",
                  "Αν δεν εξηγείται (ενημέρωση, εφαρμογή), έλεγξε τα πακέτα της στιγμής στο timeline."]},
    "jitterbeacon": {
        "title": "Beaconing με jitter (ώρες)",
        "hypothesis": "Ένα implant «καλεί σπίτι» κάθε μερικά λεπτά με τυχαία απόκλιση — πολύ αργά και ακανόνιστα για τον ανιχνευτή των 60″.",
        "mitre": _tech("T1071.001", "Web Protocols") | {"also": _tech("T1573", "Encrypted Channel")},
        "source": "Sqrrl hunting loop / RITA (Active Countermeasures) — beacon analysis",
        "method": "στατιστική διαστημάτων",
        "data": "Ακμές συσκευή→προορισμός ανά λεπτό από το timeline (24 ώρες)",
        "steps": ["Για κάθε ζεύγος συσκευή→προορισμός βρες τα λεπτά που εμφανίζεται.",
                  "Υπολόγισε τα κενά ανάμεσά τους και τον συντελεστή μεταβλητότητας (CV = τυπ. απόκλιση / μέσος).",
                  "Μικρό CV με κενά πολλών λεπτών και μικρό όγκο = «ρολόι» → πιθανό C2.",
                  "Σύγκρινε με γνωστές ενημερώσεις/NTP της συσκευής και δες το όνομα του server."]},
    "rarefp": {
        "title": "Σπάνιο αποτύπωμα TLS (JA3/JA4)",
        "hypothesis": "Νέο λογισμικό (π.χ. malware με δική του βιβλιοθήκη TLS) αφήνει αποτύπωμα ClientHello που δεν έχει καμία άλλη συσκευή.",
        "mitre": _tech("T1071.001", "Web Protocols"),
        "source": "Salesforce JA3 / FoxIO JA4 — fingerprint stacking",
        "method": "stack counting αποτυπωμάτων",
        "data": "JA3 (και JA4 αν καταγράφεται) ανά συσκευή, με τα SNI που συνόδευαν",
        "steps": ["Μέτρα σε πόσες συσκευές εμφανίζεται κάθε αποτύπωμα.",
                  "Κράτα όσα έχει μόνο μία συσκευή — ειδικά αν η συσκευή έχει ήδη άλλο «κανονικό» αποτύπωμα.",
                  "IoT συσκευές έχουν συνήθως ΕΝΑ σταθερό αποτύπωμα· δεύτερο είναι πολύ ύποπτο.",
                  "Ψάξε το hash σε ja3er / ja4db και δες προς ποια SNI/IP πήγε."]},
    "exfil": {
        "title": "Ασύμμετρο ανέβασμα (exfiltration)",
        "hypothesis": "Η διαρροή δεδομένων φαίνεται ως σχέση όπου η συσκευή στέλνει πολύ περισσότερα απ' όσα λαμβάνει.",
        "mitre": _tech("T1048", "Exfiltration Over Alternative Protocol"),
        "source": "Michael Collins — Network Security Through Data Analysis (producer/consumer ratio)",
        "method": "λόγος bytes έξω/μέσα",
        "data": "Bytes προς/από κάθε δημόσια IP + bytes ανά συσκευή στο timeline",
        "steps": ["Για κάθε σχέση με δημόσια IP υπολόγισε bytes που ανέβηκαν / bytes που κατέβηκαν.",
                  "Κράτα σχέσεις με λόγο ≥ 3 και αξιόλογο όγκο.",
                  "Ξεχώρισε τα γνωστά backups (NAS → cloud) από άγνωστους προορισμούς.",
                  "Δες πότε έγινε (ώρα, διάρκεια) και αν ο χρήστης ανέβαζε κάτι εκείνη την ώρα."]},
    "offhours": {
        "title": "Δραστηριότητα εκτός ωραρίου",
        "hypothesis": "Συσκευή που χρησιμοποιείται τη μέρα αλλά ξυπνά στις 01:00–05:00 για λίγο και στέλνει δεδομένα, δουλεύει για κάποιον άλλον.",
        "mitre": _tech("T1029", "Scheduled Transfer"),
        "source": "Chris Sanders — Applied Network Security Monitoring (friendly intelligence)",
        "method": "προφίλ ωρών ανά συσκευή",
        "data": "Bytes ανά συσκευή ανά λεπτό από το timeline, σε τοπική ώρα",
        "steps": ["Φτιάξε το 24ωρο προφίλ κάθε συσκευής (ποιες ώρες είναι ενεργή).",
                  "Κράτα συσκευές «ημέρας» που ήταν σιωπηλές τη νύχτα εκτός από ένα σύντομο ξέσπασμα.",
                  "Δες με ποιον μίλησε τη νύχτα και πόσα έστειλε.",
                  "Έλεγξε αν υπάρχει προγραμματισμένη εργασία (ενημέρωση firmware, backup)."]},
    "newsvc": {
        "title": "Νέα θύρα/πρωτόκολλο για τη συσκευή",
        "hypothesis": "Μια συσκευή με σταθερό προφίλ (π.χ. κάμερα: HTTPS + NTP) που ξαφνικά μιλά σε άγνωστη θύρα έχει αλλάξει συμπεριφορά.",
        "mitre": _tech("T1571", "Non-Standard Port"),
        "source": "Chris Sanders — Applied Network Security Monitoring (friendly intelligence)",
        "method": "σύγκριση με το προφίλ της συσκευής",
        "data": "Πρωτόκολλο/θύρα των ακμών στο timeline + θύρες που «χτυπά» κάθε συσκευή",
        "steps": ["Μάθε τις συνηθισμένες θύρες κάθε συσκευής από το 24ωρο.",
                  "Βρες θύρες που εμφανίστηκαν σπάνια και αργότερα από την αρχή του προφίλ.",
                  "Δες ποιος ήταν ο προορισμός και η χώρα του.",
                  "Αν δεν εξηγείται, μπλόκαρέ το στο Τείχος IoT και κοίτα τα πακέτα."]},
    "dnslongtail": {
        "title": "Σπάνια / «τυχαία» domains",
        "hypothesis": "Malware ρωτά domains με τυχαία ονόματα (DGA) ή σπάνια TLD — λίγα και αργά, ώστε να μη χτυπήσει ο ανιχνευτής DGA.",
        "mitre": _tech("T1568.002", "Domain Generation Algorithms"),
        "source": "Michael Collins — long tail ονομάτων + core.dga_score (εντροπία/φωνήεντα)",
        "method": "stack counting domains + εντροπία",
        "data": "Ερωτήματα DNS ανά πελάτη (όσα κράτησε το NetWatch) + ονόματα που λύθηκαν σε δημόσιες IP",
        "steps": ["Μέτρα πόσοι πελάτες ρώτησαν κάθε domain.",
                  "Κράτα τα domains ενός πελάτη με «τυχαίο» όνομα, σπάνιο TLD ή NXDOMAIN.",
                  "Πέτα όσα έχουν ήδη βγάλει ειδοποίηση (DGA / DNS tunneling).",
                  "Ψάξε το domain σε VirusTotal / urlscan και δες πότε καταχωρήθηκε."]},
    "quietbad": {
        "title": "Αθόρυβη επαφή με ύποπτες χώρες/IP",
        "hypothesis": "Λίγα πακέτα προς Κίνα/Ρωσία/Β. Κορέα/Ιράν ή IP από λίστα απειλών μπορεί να μείνουν κάτω από κάθε όριο ειδοποίησης.",
        "mitre": _tech("T1090", "Proxy"),
        "source": "Sqrrl hunting loop — εμπλουτισμός με geo/threat intel",
        "method": "εμπλουτισμός + φίλτρο «χωρίς ειδοποίηση»",
        "data": "Γεωγραφία/λίστες απειλών προορισμών + ειδοποιήσεις NetWatch",
        "steps": ["Βρες προορισμούς σε CN/RU/KP/IR ή σε λίστα απειλών.",
                  "Κράτα όσους ΔΕΝ έβγαλαν ειδοποίηση και είχαν μικρό όγκο.",
                  "Δες ποια συσκευή του σπιτιού ξεκίνησε την επικοινωνία.",
                  "Κάνε whois/AbuseIPDB στην IP και αποφάσισε αν θα την μπλοκάρεις."]},
}

EXPLAIN = {
    "longtail": "Stack counting: μετράμε πόσες συσκευές μίλησαν με κάθε προορισμό· τα σπάνια (μία συσκευή, λίγες συνδέσεις) είναι η «μακριά ουρά» όπου κρύβονται συχνά τα C2.",
    "jitterbeacon": "Για κάθε ζεύγος συσκευή→προορισμός μετράμε τα κενά ανάμεσα στα λεπτά επικοινωνίας· μικρός συντελεστής μεταβλητότητας με κενά πολλών λεπτών σημαίνει «ρολόι» που ξεφεύγει από τον ανιχνευτή των 60″.",
    "rarefp": "Μετράμε σε πόσες συσκευές εμφανίζεται κάθε αποτύπωμα TLS (JA3/JA4)· αποτύπωμα μίας συσκευής, ειδικά δεύτερο σε IoT, δείχνει νέο λογισμικό.",
    "exfil": "Λόγος bytes που ανέβηκαν προς bytes που κατέβηκαν ανά σχέση· οι «παραγωγοί» δεδομένων προς άγνωστους servers είναι υποψήφια διαρροή.",
    "offhours": "Φτιάχνουμε το 24ωρο προφίλ κάθε συσκευής και ψάχνουμε σύντομα νυχτερινά ξεσπάσματα (01:00–05:00) σε συσκευές που κατά κανόνα δουλεύουν τη μέρα.",
    "newsvc": "Friendly intelligence: μαθαίνουμε τις συνηθισμένες θύρες κάθε συσκευής και ψάχνουμε σπάνιες, καινούργιες θύρες/πρωτόκολλα.",
    "dnslongtail": "Stack counting στα domains + βαθμός «τυχαιότητας» (εντροπία, φωνήεντα, ψηφία)· κρατάμε μόνο όσα ΔΕΝ έχουν ήδη βγάλει ειδοποίηση.",
    "quietbad": "Εμπλουτίζουμε κάθε προορισμό με χώρα και λίστες απειλών και κρατάμε την αθόρυβη, χαμηλού όγκου επαφή που δεν έβγαλε ειδοποίηση.",
}

# ───────── demo: συνθετικά επεισόδια (μόνο sim=True) ─────────
DEMO_BEACON = ("192.168.1.52", "194.36.189.71", "NL", "Netherlands")   # πρίζα κουζίνας → άγνωστο VPS
DEMO_NIGHT = ("192.168.1.31", "45.137.21.9", "RO", "Romania")          # Smart TV → server στις 03:12
DEMO_QUIET = ("192.168.1.40", "5.188.10.176", "RU", "Russia")           # εκτυπωτής → Ρωσία, 3 μικρές επαφές
DEMO_FP_DEV = "192.168.1.33"                                           # κάμερα: δεύτερο, σπάνιο JA3
DEMO_DOMAIN = "xj4kq9vz2mtb.top"


def _ip(s):
    try:
        return ipaddress.ip_address(str(s))
    except ValueError:
        return None


def _public(ip):
    a = _ip(ip)
    return bool(a and a.is_global and not a.is_multicast)


def _local(ip):
    a = _ip(ip)
    return bool(a and (a.is_private or a.is_link_local) and not a.is_multicast and not a.is_loopback
                and not str(ip).endswith(".255"))


def _hour(t):
    return time.localtime(t).tm_hour


def _port(proto):
    try:
        return int(str(proto).split("/", 1)[1])
    except (IndexError, ValueError, TypeError):
        return None


def _cv(xs):
    if len(xs) < 2:
        return 1.0
    m = sum(xs) / len(xs)
    if m <= 0:
        return 1.0
    return (sum((x - m) ** 2 for x in xs) / len(xs)) ** 0.5 / m


def _median(xs):
    xs = sorted(xs)
    if not xs:
        return 0
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def _mb(n):
    return f"{n / 1e6:.1f} MB" if n >= 1e5 else f"{n / 1e3:.0f} KB"


class Hunt:
    def __init__(self, state, sim=False, clock=time.time):
        self.st, self.sim, self.clock = state, sim, clock
        self.lock = threading.Lock()
        self.last = {}                         # id → {"t", "count"}
        self.dnsq = {}                         # (πελάτης, όνομα) → [φορές, πρώτη, τελευταία, nx]
        self.ja4 = collections.defaultdict(collections.Counter)   # ip → {ja4: πακέτα}
        self.ja4_sni = collections.defaultdict(dict)

    # ───────── προαιρετικό hook από το detect.py ─────────
    def observe(self, P, t):
        """Κρατά ό,τι δεν κρατά το NetState: ερωτήματα DNS ανά πελάτη και JA4 ανά συσκευή (φραγμένα σε μέγεθος)."""
        q, nx, j4 = P.get("dns_q"), P.get("nx"), P.get("ja4")
        if not (q or nx or j4):
            return
        with self.lock:
            for client, name, isnx in ((P.get("src"), (q or (None,))[0], False), (P.get("dst"), nx, True)):
                if not client or not name:
                    continue
                k = (client, str(name).lower().rstrip("."))
                r = self.dnsq.get(k)
                if r is None:
                    if len(self.dnsq) >= 20000:
                        for old in sorted(self.dnsq, key=lambda x: self.dnsq[x][2])[:5000]:
                            self.dnsq.pop(old, None)
                    r = self.dnsq[k] = [0, t, t, False]
                r[0] += 0 if isnx else 1
                r[2] = t
                r[3] = r[3] or isnx
            if j4 and P.get("src") and len(self.ja4) < 3000:
                self.ja4[P["src"]][j4] += 1
                if P.get("sni"):
                    sn = self.ja4_sni[P["src"]].setdefault(j4, set())
                    if len(sn) < 20:
                        sn.add(P["sni"])

    # ───────── συλλογή δεδομένων (αντίγραφα, για να μη μας αλλάζουν κάτω από τα πόδια) ─────────
    def _data(self):
        st = self.st
        D = {"hosts": {}, "alerts": [], "recent": [], "buckets": [], "meta": {}, "me": set(), "lab": set(),
             "gw": None, "dns": [], "fps": {}, "demo_ips": set(), "baseline": {}}
        lock = getattr(st, "lock", None) or contextlib.nullcontext()
        with lock:
            for ip, h in list((getattr(st, "hosts", None) or {}).items()):
                try:
                    D["hosts"][ip] = {
                        "ip": ip, "kind": h.get("kind"), "me": bool(h.get("me")), "gw": bool(h.get("gw")),
                        "first": h.get("first"), "last": h.get("last"),
                        "bytes_in": h.get("bytes_in", 0) or 0, "bytes_out": h.get("bytes_out", 0) or 0,
                        "pkts": (h.get("pkts_in", 0) or 0) + (h.get("pkts_out", 0) or 0) + (h.get("pkts", 0) or 0),
                        "ports": collections.Counter(h.get("ports") or {}),
                        "protos": collections.Counter(h.get("protos") or {}),
                        "hits": collections.Counter(h.get("hits") or {}),
                        "victims": collections.Counter(h.get("victims") or {}),
                        "names": sorted(h.get("names") or ()), "rdns": h.get("rdns"), "mac": h.get("mac"),
                        "geo": dict(h.get("geo") or {}), "intel": list(h.get("intel") or []),
                        "alerts": len(h.get("alerts") or ()),
                        "ja3": collections.Counter(h.get("ja3") or {}),
                        "ja3_sni": {k: sorted(v) for k, v in (h.get("ja3_sni") or {}).items()},
                        "ja4": collections.Counter(h.get("ja4") or {}),
                    }
                except (AttributeError, TypeError):
                    continue
            D["alerts"] = [a for a in list(getattr(st, "alerts", None) or []) if isinstance(a, dict)]
            D["recent"] = list(getattr(st, "recent", None) or [])[-5000:]
            D["me"] = set(getattr(st, "me", None) or ())
            D["lab"] = set(getattr(st, "lab_ips", None) or ())
            D["gw"] = getattr(st, "gateway", None)
        tl = getattr(st, "timeline", None)
        if tl is not None:
            try:
                with tl.lock:
                    D["buckets"] = list(tl.buckets)
                    c = tl.cur
                    if c:
                        D["buckets"].append({"t": c["t"], "dev": {ip: v[:] for ip, v in c["dev"].items()},
                                             "edge": [[a, b, v[0], v[1], v[2]] for (a, b), v in c["edge"].items()]})
                    D["meta"] = {k: dict(v) for k, v in tl.meta.items()}
            except Exception:
                D["buckets"], D["meta"] = [], {}
        bl = getattr(st, "baseline", None)
        if bl is not None:
            try:
                with bl.lock:
                    D["baseline"] = {k: {"ip": d.get("ip"), "countries": sorted(d.get("countries") or {})}
                                     for k, d in bl.dev.items()}
            except Exception:
                pass
        # ερωτήματα DNS: από το hook (αν υπάρχει) + τα τελευταία πακέτα που κρατά το NetState
        with self.lock:
            dns = {k: v[:] for k, v in self.dnsq.items()}
            ja4 = {ip: collections.Counter(c) for ip, c in self.ja4.items()}
            ja4s = {ip: {k: sorted(v) for k, v in d.items()} for ip, d in self.ja4_sni.items()}
        hook_keys = set(dns)  # ό,τι μέτρησε ήδη το observe(): μην το ξαναμετρήσεις από τα recent
        for P in D["recent"]:
            try:
                for client, name, isnx in ((P.get("src"), (P.get("dns_q") or (None,))[0], False),
                                           (P.get("dst"), P.get("nx"), True)):
                    if not (client and name):
                        continue
                    k = (client, str(name).lower().rstrip("."))
                    if k in hook_keys:
                        continue
                    pt = P.get("t", 0)
                    if k not in dns:
                        dns[k] = [0, pt, pt, False]
                    dns[k][0] += 0 if isnx else 1
                    dns[k][2] = max(dns[k][2], pt)
                    dns[k][3] = dns[k][3] or isnx
            except AttributeError:
                continue
        D["dns"] = dns
        for ip, h in D["hosts"].items():
            for k, n in h["ja3"].items():
                D["fps"].setdefault(("JA3", k), {})[ip] = [n, h["ja3_sni"].get(k, [])]
            for k, n in h["ja4"].items():
                D["fps"].setdefault(("JA4", k), {})[ip] = [n, []]
        for ip, c in ja4.items():
            for k, n in c.items():
                D["fps"].setdefault(("JA4", k), {})[ip] = [n, ja4s.get(ip, {}).get(k, [])]
        if self.sim:
            self._demo_overlay(D)
        return D

    def _demo_overlay(self, D):
        """Συνθετικά επεισόδια για το demo (σημαδεύονται demo στα ευρήματα) πάνω στο 24ωρο του timeline."""
        bs = [dict(b) for b in D["buckets"]]
        now = self.clock()
        if not bs:  # χωρίς timeline: ένα άδειο 24ωρο ώστε να «κάθονται» τα επεισόδια
            end = int(now // 60) * 60
            bs = [{"t": end - i * 60, "pkts": 0, "bytes": 0, "dev": {}, "edge": []} for i in range(24 * 60, 0, -1)]
        meta = D["meta"]
        dev_b, peer_b, cc_b, country_b = DEMO_BEACON
        dev_n, peer_n, cc_n, country_n = DEMO_NIGHT
        meta.setdefault(peer_b, {"name": None, "cc": cc_b, "country": country_b})
        meta.setdefault(peer_n, {"name": None, "cc": cc_n, "country": country_n})
        meta.setdefault(dev_b, {"name": "Πρίζα κουζίνας", "icon": "🔌"})
        meta.setdefault(dev_n, {"name": "Smart TV σαλονιού", "icon": "📺"})
        meta.setdefault(DEMO_FP_DEV, {"name": "Κάμερα εισόδου (Tapo)", "icon": "📷"})
        D["demo_ips"].update({peer_b, peer_n, DEMO_FP_DEV + "#fp", DEMO_DOMAIN})
        idx = {b["t"]: i for i, b in enumerate(bs)}

        def add(t, dev, peer, nbytes, proto, up):
            i = idx.get(int(t // 60) * 60)
            if i is None:
                return
            b = bs[i] = dict(bs[i])
            b["edge"] = list(b.get("edge") or []) + [[dev, peer, int(nbytes), max(1, int(nbytes // 900)), proto]]
            d = dict(b.get("dev") or {})
            v = list(d.get(dev) or [0, 0, 0])
            v[0] += int(nbytes * (1 - up)); v[1] += int(nbytes * up); v[2] += max(1, int(nbytes // 900))
            d[dev] = v
            b["dev"] = d
        # 1) πρίζα → VPS κάθε ~17′ ±20% για 15 ώρες, ~700 bytes (beaconing με jitter)
        t0, k = bs[-1]["t"] - 15 * 3600, 0
        gaps = [17, 14, 19, 16, 20, 15, 18, 17, 13, 19, 16, 18, 21, 15, 17, 14, 18, 16, 19, 17]
        t = t0
        while t < bs[-1]["t"]:
            add(t, dev_b, peer_b, 680 + (k * 37) % 120, "TCP/443", 0.6)
            t += gaps[k % len(gaps)] * 60
            k += 1
        # 2) Smart TV: 20 λεπτά στις 03:12 που ανεβάζουν ~8 MB/λεπτό σε άγνωστο server (εκτός ωραρίου + exfil)
        days = collections.defaultdict(list)
        for b in bs:
            lt = time.localtime(b["t"])
            if lt.tm_hour == 3 and 12 <= lt.tm_min < 32:
                days[(lt.tm_year, lt.tm_yday)].append(b["t"])
        if days:
            for t in max(days.values(), key=lambda ts: (len(ts), ts[-1])):
                add(t, dev_n, peer_n, 8_200_000, "TCP/443", 0.94)
        # 3α) εκτυπωτής: τρεις μικρές επαφές με IP στη Ρωσία, κάτω από κάθε όριο (καμία ειδοποίηση)
        dev_q, peer_q, cc_q, country_q = DEMO_QUIET
        meta.setdefault(peer_q, {"name": None, "cc": cc_q, "country": country_q})
        meta.setdefault(dev_q, {"name": "Εκτυπωτής", "icon": "🖨"})
        D["demo_ips"].add(peer_q)
        for back in (9 * 3600, 9 * 3600 - 240, 4 * 3600):
            add(bs[-1]["t"] - back, dev_q, peer_q, 420, "TCP/443", 0.5)
        # 3β) κάμερα: δεύτερο, σπάνιο αποτύπωμα TLS χωρίς SNI (+ το «κανονικό» της)
        D["fps"].setdefault(("JA3", "6d4b8e2f1c0a9e7d3b5a2c8f4e1d6a90"), {})[DEMO_FP_DEV] = [4210, ["n-deventry.tplinkcloud.com"]]
        D["fps"].setdefault(("JA3", "a1e5c9d07f3b2e6a8c4d1f9b0e7a3c52"), {})[DEMO_FP_DEV] = [12, []]
        D["fps"].setdefault(("JA4", "t12d0907h1_6f1c3a2b9e04_51b2d7e9a0c3"), {})[DEMO_FP_DEV] = [12, []]
        has_fp = {ip for devs in D["fps"].values() for ip in devs}
        for ip, fp, n, sni in (("192.168.1.15", "773906b0efdefa24a7f2b8eb6985bf37", 3100, ["apple.com", "instagram.com"]),
                               ("192.168.1.23", "773906b0efdefa24a7f2b8eb6985bf37", 9800, ["github.com"]),
                               ("192.168.1.31", "b32309a26951912be7dba376398abc3b", 2400, ["nflxvideo.net", "youtube.com"])):
            if ip not in has_fp:  # μόνο αν η συσκευή δεν έχει ήδη πραγματικό (demo) αποτύπωμα
                D["fps"].setdefault(("JA3", fp), {})[ip] = [n, sni]
        # 4) η TV ρώτησε δύο φορές ένα «τυχαίο» .top λίγο πριν το νυχτερινό ανέβασμα (χωρίς NXDOMAIN → ο DGA δεν χτύπησε)
        D["dns"].setdefault((dev_n, DEMO_DOMAIN), [2, now - 6 * 3600, now - 5 * 3600, False])
        D["buckets"] = bs

    # ───────── βοηθητικά ─────────
    def _name(self, D, ip):
        if ip is None:
            return None
        m = D["meta"].get(ip) or {}
        h = D["hosts"].get(ip) or {}
        nm = m.get("name") or (h.get("names") or [None])[0] or h.get("rdns")
        return None if nm == ip else nm

    def _cc(self, D, ip):
        h = D["hosts"].get(ip) or {}
        return (h.get("geo") or {}).get("countryCode") or (D["meta"].get(ip) or {}).get("cc")

    def _skip(self, D, ip, me=True):
        """Ποιες συσκευές δεν «κυνηγάμε» ως δράστες: ο υπολογιστής του NetWatch (θόρυβος), το lab, ο router."""
        return (not ip or ip in D["lab"] or (me and ip in D["me"]) or ip == D["gw"]
                or (D["hosts"].get(ip) or {}).get("gw") or (me and (D["hosts"].get(ip) or {}).get("me"))
                or (D["meta"].get(ip) or {}).get("gw") or (me and (D["meta"].get(ip) or {}).get("me")))

    def _iot(self, D, ip):
        n = " ".join(filter(None, [self._name(D, ip), (D["meta"].get(ip) or {}).get("kind")])).lower()
        return any(w in n for w in IOT_WORDS)

    def _big(self, name):
        n = (name or "").lower()
        return any(w in n for w in BIG_NAMES)

    def _alerted(self, D, *keys):
        # Ταίριασμα IP/domain με όρια, όχι substring: η "5.9.1.2" δεν πρέπει να «ταιριάζει» μέσα στην
        # "15.9.1.20", ούτε το "a.top" μέσα στο "data.top".
        keys = [str(k) for k in keys if k]
        if not keys:
            return False
        pats = [re.compile(r"(?<![\w.]){}(?![\w.])".format(re.escape(k))) for k in keys]
        for a in D["alerts"]:
            if a.get("selftest"):
                continue
            if any(str(a.get(f) or "") == k for f in ("actor", "target") for k in keys):
                return True
            detail = str(a.get("detail") or "")
            if any(p.search(detail) for p in pats):
                return True
        return False

    def _f(self, D, score, actor, target, summary, evidence, why, nxt, target_name=None):
        ev = dict(evidence)
        if target and _public(target) and self._alerted(D, target):
            ev["already_alerted"] = True   # το είχε ήδη πιάσει κάποιος ανιχνευτής
        if {actor, target, actor and actor + "#fp"} & D["demo_ips"] or evidence.get("domain") in D["demo_ips"]:
            ev["demo"] = True
        return {"score": int(max(0, min(100, round(score)))), "actor": actor, "actor_name": self._name(D, actor),
                "target": target, "target_name": target_name or self._name(D, target),
                "summary": summary, "evidence": ev, "why": why, "next": nxt}

    def _edges(self, D):
        """(dev, peer) → λίστα (t, bytes, pkts, proto) από το timeline."""
        out = collections.defaultdict(list)
        for b in D["buckets"]:
            for e in b.get("edge") or ():
                try:
                    out[(e[0], e[1])].append((b["t"], e[2], e[3], e[4]))
                except (IndexError, KeyError, TypeError):
                    continue
        return out

    # ───────── οι υποθέσεις ─────────
    def _h_longtail(self, D):
        P = collections.defaultdict(lambda: {"devs": collections.Counter(), "minutes": 0, "bytes": 0, "first": None, "last": None})
        for ip, h in D["hosts"].items():
            if h["kind"] != "local" or ip in D["lab"]:
                continue
            for peer, n in h["victims"].items():
                if _public(peer):
                    P[peer]["devs"][ip] += n
        for (dev, peer), rows in self._edges(D).items():
            if not _public(peer) or dev in D["lab"]:
                continue
            p = P[peer]
            p["devs"][dev] += 0
            p["minutes"] += len(rows)
            p["bytes"] += sum(r[1] for r in rows)
            ts = [r[0] for r in rows]
            p["first"] = min([x for x in (p["first"], min(ts)) if x is not None])
            p["last"] = max([x for x in (p["last"], max(ts)) if x is not None])
        for peer, p in P.items():
            h = D["hosts"].get(peer)
            if h and not p["bytes"]:
                p["bytes"] = h["bytes_in"] + h["bytes_out"]
        stack = collections.Counter(min(len(p["devs"]), 3) for p in P.values())
        cc_count = collections.Counter(self._cc(D, peer) for peer in P)
        out = []
        for peer, p in P.items():
            if len(p["devs"]) != 1 or peer in D["lab"] or peer in DNS_RESOLVERS:
                continue
            dev = next(iter(p["devs"]))
            if self._skip(D, dev):
                continue
            conns = p["devs"][dev]
            if conns > 30 or p["minutes"] > 15:
                continue
            nm, cc = self._name(D, peer), self._cc(D, peer)
            s = 45 + (20 if not nm else 0) + (15 if cc and cc_count[cc] <= 1 else 0) + (15 if cc in BAD_CC else 0)
            s += 5 if (p["minutes"] <= 3 and conns <= 3) else 0
            s -= 20 if self._big(nm) else 0
            out.append(self._f(D, s, dev, peer,
                               f"Μόνο μία συσκευή ({self._name(D, dev) or dev}) μίλησε με {nm or peer}{' (' + cc + ')' if cc else ''} — "
                               + (f"{conns} {'σύνδεση' if conns == 1 else 'συνδέσεις'}" if conns else f"{p['minutes']} {'λεπτό' if p['minutes'] == 1 else 'λεπτά'}"),
                               {"devices": 1, "connections": conns, "minutes": p["minutes"], "bytes": p["bytes"], "cc": cc,
                                "first": p["first"], "last": p["last"]},
                               "Καμία άλλη συσκευή του σπιτιού δεν μιλά με αυτόν τον server και η επαφή ήταν σύντομη/σπάνια — "
                               "τυπικό για C2, dropper ή ξεχασμένη εφαρμογή.",
                               "Δες whois/χώρα του προορισμού, κοίτα το timeline τη στιγμή της επαφής και ρώτα: γιατί θα μιλούσε αυτή η συσκευή εκεί;"))
        return out, {"examined": len(P), "single_device": stack.get(1, 0), "two_devices": stack.get(2, 0),
                     "three_plus": stack.get(3, 0)}

    def _h_jitterbeacon(self, D):
        out, n_pairs = [], 0
        for (dev, peer), rows in self._edges(D).items():
            n_pairs += 1
            if self._skip(D, dev, me=False) or peer in D["lab"] or peer in DNS_RESOLVERS or len(rows) < 6:
                continue
            ts = sorted({r[0] for r in rows})
            gaps = [(b - a) / 60 for a, b in zip(ts, ts[1:])]
            if len(gaps) < 5:
                continue
            mean = sum(gaps) / len(gaps)
            span_h = (ts[-1] - ts[0]) / 3600
            if not 2 <= mean <= 240 or span_h < 0.75:
                continue
            cv = _cv(gaps)
            med = _median([r[1] for r in rows])
            if cv > 0.5 or med > 200_000:
                continue
            s = 40 + 40 * (1 - cv / 0.5) + min(15, len(ts) / 3) + (5 if _public(peer) else 0)
            s -= 25 if self._big(self._name(D, peer)) else 0
            proto = collections.Counter(r[3] for r in rows).most_common(1)[0][0]
            out.append(self._f(D, s, dev, peer,
                               f"{self._name(D, dev) or dev} → {self._name(D, peer) or peer} κάθε ~{mean:.0f}′ (±{cv * 100:.0f}%) για {span_h:.1f} ώρες",
                               {"contacts": len(ts), "mean_gap_min": round(mean, 1), "cv": round(cv, 2),
                                "span_h": round(span_h, 1), "median_bytes": int(med), "proto": proto, "cc": self._cc(D, peer)},
                               "Μικρά πακέτα σε σχεδόν σταθερά διαστήματα πολλών λεπτών μοιάζουν με implant που ζητά εντολές· "
                               "το jitter (τυχαία απόκλιση) το κρύβει από τον ανιχνευτή των 60″.",
                               "Δες αν ο προορισμός είναι γνωστή υπηρεσία της συσκευής (cloud κατασκευαστή, NTP)· αν όχι, μπλόκαρέ τον "
                               "και κοίτα αν η επικοινωνία «ψάχνει» εναλλακτικό server."))
        return out, {"examined": n_pairs}

    def _h_rarefp(self, D):
        fps = D["fps"]
        devs_with = collections.defaultdict(list)
        for (kind, fp), devs in fps.items():
            for ip in devs:
                devs_with[ip].append((kind, fp))
        if len([ip for ip in devs_with if not self._skip(D, ip)]) < 2:
            return [], {"examined": len(fps), "devices": len(devs_with),
                        "note": "Χρειάζονται αποτυπώματα TLS από τουλάχιστον δύο συσκευές για σύγκριση."}
        out = []
        for (kind, fp), devs in fps.items():
            if len(devs) != 1:
                continue
            ip = next(iter(devs))
            if self._skip(D, ip):
                continue
            n, sni = devs[ip]
            same_kind = [fps[k][ip][0] for k in devs_with[ip] if k[0] == kind]
            total = sum(same_kind) or 1
            share = n / total
            multi = len(same_kind) >= 2 and share <= 0.5   # δεύτερο, «μειοψηφικό» αποτύπωμα της συσκευής
            iot = self._iot(D, ip)
            s = 30 + (30 if share <= 0.2 else 10) * multi + (15 if not sni else 0) + (15 if iot and multi else 0)
            out.append(self._f(D, s, ip, None,
                               f"Αποτύπωμα {kind} {fp[:12]}… μόνο σε μία συσκευή ({self._name(D, ip) or ip})"
                               + (f" (δεύτερο, {max(share * 100, 1):.0f}% της κίνησής της)" if multi else ""),
                               {"kind": kind, "fingerprint": fp, "packets": n, "share": round(share, 2),
                                "device_fps": len(same_kind), "sni": sni[:6]},
                               ("Η συσκευή έχει ήδη «κανονικό» αποτύπωμα· ένα δεύτερο, σπάνιο, σημαίνει ότι τρέχει άλλο πρόγραμμα με δική του βιβλιοθήκη TLS"
                                + (" — σε IoT αυτό σχεδόν ποτέ δεν είναι αθώο." if iot else ".")) if multi else
                               "Κανείς άλλος στο δίκτυο δεν έχει αυτό το αποτύπωμα — συνήθως απλώς άλλο λειτουργικό/εφαρμογή, αλλά αξίζει μια ματιά.",
                               "Ψάξε το hash σε ja3er.com / ja4db.com, δες ποια SNI/IP το συνόδευαν και αν η συσκευή πήρε πρόσφατα ενημέρωση.",
                               target_name=", ".join(sni[:2]) or "χωρίς SNI"))
        return out, {"examined": len(fps), "devices": len(devs_with),
                     "unique": sum(1 for d in fps.values() if len(d) == 1)}

    def _h_exfil(self, D):
        rel = {}
        min_up = 1_000_000
        # α) ανά δημόσια IP: ό,τι «μπήκε» σε αυτήν = ό,τι ανέβηκε από το σπίτι
        for peer, h in D["hosts"].items():
            if h["kind"] != "public" or peer in D["lab"] or peer in DNS_RESOLVERS:
                continue
            up, down = h["bytes_in"], h["bytes_out"]
            if up < min_up or up / (down + 1) < 3:
                continue
            cands = [(D["hosts"][ip]["victims"].get(peer, 0), ip) for ip in D["hosts"]
                     if D["hosts"][ip]["kind"] == "local" and D["hosts"][ip]["victims"].get(peer)]
            dev = max(cands)[1] if cands else None
            if dev and self._skip(D, dev):
                continue
            rel[(dev, peer)] = {"up": up, "down": down, "src": "hosts"}
        # β) ανά συσκευή στο timeline: bytes έξω ≫ μέσα, με τον «βαρύτερο» δημόσιο προορισμό
        tot = collections.defaultdict(lambda: [0, 0])
        for b in D["buckets"]:
            for ip, v in (b.get("dev") or {}).items():
                tot[ip][0] += v[0]; tot[ip][1] += v[1]
        peers = collections.defaultdict(collections.Counter)
        for (dev, peer), rows in self._edges(D).items():
            if _public(peer):
                peers[dev][peer] += sum(r[1] for r in rows)
        for dev, (bin_, bout) in tot.items():
            if self._skip(D, dev) or bout < 5 * min_up or bout / (bin_ + 1) < 3 or not peers[dev]:
                continue
            peer = peers[dev].most_common(1)[0][0]
            rel.setdefault((dev, peer), {"up": bout, "down": bin_, "src": "timeline"})
        out = []
        for (dev, peer), r in rel.items():
            ratio = r["up"] / (r["down"] + 1)
            nm = self._name(D, peer)
            backup = any(w in (nm or "").lower() for w in BACKUP_NAMES)
            s = 35 + 15 * math.log10(max(ratio, 1)) + 10 * math.log10(max(r["up"] / min_up, 1)) + (15 if not nm else 0)
            s += 10 if self._cc(D, peer) in BAD_CC else 0
            s -= 30 if backup else 0
            out.append(self._f(D, s, dev, peer,
                               f"{self._name(D, dev) or dev or 'Συσκευή LAN'} ανέβασε {_mb(r['up'])} στο {nm or peer} (×{ratio:.0f} από όσα κατέβασε)",
                               {"bytes_out": r["up"], "bytes_in": r["down"], "ratio": round(ratio, 1), "cc": self._cc(D, peer),
                                "source": r["src"]},
                               ("Μοιάζει με backup σε γνωστή υπηρεσία cloud — λογικό αν το έχεις ρυθμίσει εσύ." if backup else
                                "Οι συσκευές του σπιτιού κυρίως ΚΑΤΕΒΑΖΟΥΝ· σχέση όπου ανεβαίνουν πολλαπλάσια δεδομένα προς άγνωστο server ταιριάζει με διαρροή."),
                               "Δες πότε έγινε στο timeline, τι υπηρεσία είναι ο προορισμός και αν ο χρήστης ανέβαζε κάτι (backup, βίντεο, cloud sync)."))
        return out, {"examined": len([h for h in D["hosts"].values() if h["kind"] == "public"]) + len(tot)}

    def _h_offhours(self, D):
        bs = D["buckets"]
        if not bs:
            return [], {"examined": 0, "note": "Δεν υπάρχει timeline (24ωρο) για να φτιαχτεί προφίλ ωρών."}
        hours = [_hour(b["t"]) for b in bs]
        n_day = sum(1 for h in hours if h in DAY) or 1
        n_night = sum(1 for h in hours if h in NIGHT) or 1
        per = collections.defaultdict(lambda: {"day": [], "night": []})
        for b, hr in zip(bs, hours):
            for ip, v in (b.get("dev") or {}).items():
                n = v[0] + v[1]
                if n <= 0:
                    continue
                if hr in DAY:
                    per[ip]["day"].append(n)
                elif hr in NIGHT:
                    per[ip]["night"].append((b["t"], n, v[1]))
        edges = self._edges(D)
        out = []
        for ip, p in per.items():
            if self._skip(D, ip) or not p["night"] or not _local(ip):
                continue
            day_frac, night_frac = len(p["day"]) / n_day, len(p["night"]) / n_night
            if day_frac < 0.2 or night_frac > 0.3:
                continue
            med = _median(p["day"])
            burst = [x for x in p["night"] if x[1] >= max(med, 50_000)]
            if not burst:
                continue
            nb = sum(x[1] for x in burst)
            up = sum(x[2] for x in burst)
            t0, t1 = burst[0][0], burst[-1][0]
            tset = {x[0] for x in burst}
            np_ = collections.Counter()
            for (dev, peer), rows in edges.items():
                if dev == ip:
                    for r in rows:
                        if r[0] in tset:
                            np_[peer] += r[1]
            peer = np_.most_common(1)[0][0] if np_ else None
            s = 50 + min(25, len(burst) * 1.5) + (15 if up > nb * 0.6 else 0) + (10 if peer and not self._name(D, peer) else 0)
            out.append(self._f(D, s, ip, peer,
                               f"{self._name(D, ip) or ip} ξύπνησε {time.strftime('%H:%M', time.localtime(t0))}–"
                               f"{time.strftime('%H:%M', time.localtime(t1 + 60))} και μετέφερε {_mb(nb)}"
                               + (f" με {self._name(D, peer) or peer}" if peer else ""),
                               {"night_minutes": len(burst), "night_bytes": nb, "night_up": up,
                                "day_active_pct": round(day_frac * 100), "night_active_pct": round(night_frac * 100),
                                "day_median_bytes": int(med), "from": t0, "to": t1 + 60, "cc": self._cc(D, peer)},
                               "Η συσκευή δουλεύει κανονικά τη μέρα και σωπαίνει τη νύχτα — εκτός από αυτό το σύντομο, βαρύ ξέσπασμα "
                               "(συχνά προγραμματισμένη μεταφορά δεδομένων όταν κανείς δεν κοιτά).",
                               "Δες στο timeline με ποιον μίλησε εκείνη την ώρα, αν ήταν ενημέρωση firmware και αν επαναλαμβάνεται κάθε βράδυ."))
        return out, {"examined": len(per), "day_minutes": n_day, "night_minutes": n_night}

    def _h_newsvc(self, D):
        out, examined = [], 0
        prof = collections.defaultdict(lambda: {"minutes": set(), "first": None, "protos": collections.defaultdict(list)})
        for (dev, peer), rows in self._edges(D).items():
            if self._skip(D, dev) or not _local(dev):
                continue
            p = prof[dev]
            for t, nb, npk, proto in rows:
                p["minutes"].add(t)
                p["first"] = t if p["first"] is None else min(p["first"], t)
                p["protos"][proto].append((t, peer, nb))
        for dev, p in prof.items():
            examined += 1
            total = len(p["minutes"])
            if total < 60:
                continue
            for proto, rows in p["protos"].items():
                port = _port(proto)
                mins = {r[0] for r in rows}
                if port is None or port in COMMON_PORTS or len(mins) > max(3, total * 0.02):
                    continue
                first = min(mins)
                if first - p["first"] < 1800:   # εμφανίστηκε από την αρχή: μέρος του προφίλ
                    continue
                peers = collections.Counter()
                for t, peer, nb in rows:
                    peers[peer] += nb
                peer = peers.most_common(1)[0][0]
                cc = self._cc(D, peer)
                normal = sorted(k for k, v in p["protos"].items() if len({r[0] for r in v}) > max(3, total * 0.02))
                s = 45 + (15 if _public(peer) else 0) + (15 if cc in BAD_CC else 0) + (10 if port in RISKY_PORTS else 0) \
                    + (10 if self._iot(D, dev) else 0)
                out.append(self._f(D, s, dev, peer,
                                   f"{self._name(D, dev) or dev} μίλησε {proto} με {self._name(D, peer) or peer}{' (' + cc + ')' if cc else ''} — εκτός του προφίλ της",
                                   {"proto": proto, "minutes": len(mins), "profile_minutes": total, "normal": normal[:6],
                                    "first": first, "cc": cc, "bytes": sum(peers.values())},
                                   "Η συσκευή έχει σταθερές συνήθειες (" + (", ".join(normal[:4]) or "λίγες θύρες") + "). Μια καινούργια θύρα που "
                                   "εμφανίστηκε για λίγα λεπτά δείχνει αλλαγή λογισμικού ή απομακρυσμένο έλεγχο.",
                                   "Δες τι υπηρεσία τρέχει συνήθως σε αυτή τη θύρα, ποιος είναι ο προορισμός και αν η συσκευή πήρε ενημέρωση· "
                                   "αλλιώς κλείσ' το στο Τείχος IoT."))
        # θύρες που «χτύπησε» σπάνια μια συσκευή με μεγάλο ιστορικό (από τους μετρητές NetWatch)
        for ip, h in D["hosts"].items():
            if h["kind"] != "local" or self._skip(D, ip) or ip in prof:
                continue
            examined += 1
            hits = {k: v for k, v in h["hits"].items() if isinstance(k, int)}
            total = sum(hits.values())
            if total < 100:
                continue
            for port, n in hits.items():
                if port in COMMON_PORTS or port > 49151 or n > 3 or n > total * 0.02:
                    continue
                s = 40 + (15 if port in RISKY_PORTS else 0) + (10 if self._iot(D, ip) else 0)
                out.append(self._f(D, s, ip, None,
                                   f"{self._name(D, ip) or ip} άνοιξε σύνδεση στη θύρα {port} ({SERVICES.get(port, '?')}) μόλις {n} φορές",
                                   {"port": port, "count": n, "total": total, "service": SERVICES.get(port)},
                                   "Σπάνια θύρα για μια συσκευή που κατά τα άλλα χρησιμοποιεί λίγες, σταθερές θύρες.",
                                   "Άνοιξε τη συσκευή στα 🔬 Πακέτα, δες προς ποια IP ήταν και αν επαναλαμβάνεται.",
                                   target_name=f"θύρα {port}"))
        return out, {"examined": examined}

    def _h_dnslongtail(self, D):
        cand = {}
        for (client, q), (n, t0, t1, nx) in D["dns"].items():
            cand[(client, q)] = {"n": n, "first": t0, "last": t1, "nx": nx, "src": "dns"}
        # ονόματα που λύθηκαν σε δημόσιες IP που μίλησε μόνο μία συσκευή
        for peer, h in D["hosts"].items():
            if h["kind"] != "public" or not h["names"] or peer in DNS_RESOLVERS:
                continue
            devs = [ip for ip, x in D["hosts"].items() if x["kind"] == "local" and x["victims"].get(peer)]
            if len(devs) == 1:
                for q in h["names"][:5]:
                    cand.setdefault((devs[0], str(q).lower()), {"n": 1, "first": h["first"], "last": h["last"], "nx": False,
                                                                "src": "resolved", "ip": peer})
        bases = collections.defaultdict(set)
        for client, q in cand:
            bases[split_domain(q)[0]].add(client)
        allowed = getattr(self.st, "_allowed_name", None)
        out, covered = [], 0
        for (client, q), c in cand.items():
            if self._skip(D, client) or q.endswith((".local", ".arpa", ".lan", ".home", ".localdomain")):
                continue
            base, sub = split_domain(q)
            if len(bases[base]) != 1 or c["n"] > 5:
                continue
            try:
                if allowed and allowed(q):
                    continue
            except Exception:
                pass
            label = base.split(".")[0]
            ds = max(dga_score(label), dga_score(sub.replace(".", "")) if len(sub) >= 12 else 0)
            rare = q.endswith(RARE_TLD)
            s = 30 + 60 * ds + (10 if c["nx"] else 0) + (10 if rare else 0)
            if s < 50 or self._big(q):
                continue
            if self._alerted(D, q, base) or (c["nx"] and any(a.get("actor") == client and "DGA" in str(a.get("type"))
                                                              for a in D["alerts"])):
                covered += 1
                continue
            out.append(self._f(D, s, client, c.get("ip"),
                               f"{self._name(D, client) or client} ρώτησε {q}{' (NXDOMAIN)' if c['nx'] else ''} — κανείς άλλος στο δίκτυο",
                               {"domain": q, "base": base, "queries": c["n"], "dga_score": ds, "entropy": round(entropy(label), 2),
                                "nx": c["nx"], "rare_tld": rare, "source": c["src"], "first": c["first"]},
                               "Όνομα που μοιάζει παραγόμενο από μηχανή (εντροπία, λίγα φωνήεντα) ή σε TLD που προτιμούν οι επιτιθέμενοι, "
                               "από μία μόνο συσκευή και λίγες φορές — κάτω από το όριο του ανιχνευτή DGA.",
                               "Ψάξε το domain σε VirusTotal/urlscan, δες σε ποια IP έλυσε και αν η συσκευή μίλησε μετά με αυτήν.",
                               target_name=q))
        return out, {"examined": len(cand), "base_domains": len(bases), "already_alerted": covered,
                     **({"note": "Λίγα ερωτήματα DNS διαθέσιμα — βάλε το hook observe() στο detect.py για πλήρες ιστορικό."}
                        if not D["dns"] else {})}

    def _h_quietbad(self, D):
        P = collections.defaultdict(lambda: {"devs": collections.Counter(), "bytes": 0, "minutes": 0})
        for ip, h in D["hosts"].items():
            if h["kind"] != "local" or ip in D["lab"]:
                continue
            for peer, n in h["victims"].items():
                if _public(peer):
                    P[peer]["devs"][ip] += n
        for (dev, peer), rows in self._edges(D).items():
            if _public(peer) and dev not in D["lab"]:
                P[peer]["devs"][dev] += 0
                P[peer]["bytes"] += sum(r[1] for r in rows)
                P[peer]["minutes"] += len(rows)
        out, alerted = [], 0
        for peer, p in P.items():
            h = D["hosts"].get(peer) or {}
            cc, intel = self._cc(D, peer), [f.get("name") for f in h.get("intel") or [] if isinstance(f, dict)]
            if peer in D["lab"] or peer in DNS_RESOLVERS or (cc not in BAD_CC and not intel):
                continue
            nb = p["bytes"] or (h.get("bytes_in", 0) + h.get("bytes_out", 0))
            pk = h.get("pkts") or sum(p["devs"].values())
            if nb > 1_000_000 or pk > 500:
                continue
            if self._alerted(D, peer):
                alerted += 1
                continue
            devs = [d for d in p["devs"] if not self._skip(D, d, me=False)]
            if not devs:
                continue
            dev = max(devs, key=lambda d: p["devs"][d])
            s = 50 + (25 if intel else 0) + (15 if cc in BAD_CC else 0) + (10 if self._iot(D, dev) else 0)
            where = BAD_CC.get(cc, cc or "?")
            out.append(self._f(D, s, dev, peer,
                               f"{self._name(D, dev) or dev} μίλησε αθόρυβα με {peer} ({where}{', ' + ', '.join(intel) if intel else ''}) — καμία ειδοποίηση",
                               {"cc": cc, "intel": intel, "bytes": nb, "minutes": p["minutes"], "devices": len(devs)},
                               "Επαφή με χώρα/IP υψηλού κινδύνου με τόσο μικρό όγκο που δεν πέρασε κανένα όριο — έτσι μοιάζει το «low and slow» "
                               "ενός proxy/botnet ή ενός implant σε αναμονή.",
                               "Κάνε whois/AbuseIPDB στην IP, δες ποια εφαρμογή της συσκευής τη χρειάζεται και σκέψου μπλοκάρισμα."))
        return out, {"examined": len(P), "already_alerted": alerted}

    # ───────── API ─────────
    def catalog(self):
        with self.lock:
            last = dict(self.last)
        return {"hunts": [{"id": k, **v, "explain": EXPLAIN[k],
                           "last_run": (last.get(k) or {}).get("t"), "last_count": (last.get(k) or {}).get("count")}
                          for k, v in HUNTS.items()], "demo": self.sim}

    def _one(self, hid, D):
        try:
            fs, stats = getattr(self, "_h_" + hid)(D)
        except Exception as e:  # ποτέ δεν «σκάει» το κυνήγι
            fs, stats = [], {"examined": 0, "note": f"Σφάλμα κατά την ανάλυση: {type(e).__name__}"}
        for f in fs:
            f["hunt"] = hid
        fs.sort(key=lambda f: -f["score"])
        stats.setdefault("examined", 0)
        stats["found"] = len(fs)
        if not fs and "note" not in stats:
            stats["note"] = "Κανένα εύρημα — η υπόθεση δεν επιβεβαιώθηκε στα δεδομένα που υπάρχουν (κι αυτό είναι αποτέλεσμα)."
        return fs[:MAX_FINDINGS], stats

    def run(self, hid):
        hid = str(hid or "")
        if hid != "all" and hid not in HUNTS:
            return {"error": "Άγνωστη υπόθεση κυνηγιού."}
        t0 = time.time()
        now = self.clock()
        D = self._data()
        if hid == "all":
            fs, stats = [], {"examined": 0}
            for k in HUNTS:
                f, s = self._one(k, D)
                fs += f
                stats[k] = s["found"]
                stats["examined"] += s.get("examined", 0)
                with self.lock:
                    self.last[k] = {"t": now, "count": s["found"]}
            fs.sort(key=lambda f: -f["score"])
            fs = fs[:MAX_FINDINGS]
            explain = "Όλες οι υποθέσεις μαζί, ταξινομημένες κατά βαθμό· κάθε εύρημα λέει από ποια υπόθεση ήρθε (hunt)."
        else:
            fs, stats = self._one(hid, D)
            with self.lock:
                self.last[hid] = {"t": now, "count": stats["found"]}
            explain = EXPLAIN[hid]
        return {"id": hid, "ran_at": now, "took_ms": int((time.time() - t0) * 1000), "findings": fs,
                "stats": stats, "explain": explain, "demo": self.sim}

    def profile(self, ip):
        ip = str(ip or "").strip()
        if not _ip(ip):
            return {"error": "Μη έγκυρη IP."}
        D = self._data()
        h = D["hosts"].get(ip)
        hours = [0] * 24
        peers = collections.Counter()
        tl_ports = collections.Counter()
        seen_tl = False
        t_first = t_last = None
        tin = tout = 0
        for b in D["buckets"]:
            v = (b.get("dev") or {}).get(ip)
            if v and (v[0] + v[1]) > 0:
                seen_tl = True
                hours[_hour(b["t"])] += 1
                tin += v[0]; tout += v[1]
                t_first = b["t"] if t_first is None else min(t_first, b["t"])
                t_last = b["t"] if t_last is None else max(t_last, b["t"])
            for e in b.get("edge") or ():
                if e[0] == ip:
                    seen_tl = True
                    peers[e[1]] += e[2]
                    tl_ports[e[4]] += 1
                elif e[1] == ip:
                    seen_tl = True
                    peers[e[0]] += e[2]
        if not h and not seen_tl:
            return {"error": "Άγνωστη συσκευή — δεν υπάρχει κίνηση της στα δεδομένα."}
        if h:
            for peer, n in h["victims"].items():
                if peer not in peers:
                    ph = D["hosts"].get(peer) or {}
                    peers[peer] += ph.get("bytes_in", 0) + ph.get("bytes_out", 0) or n
        top = [{"peer": p, "name": self._name(D, p), "cc": self._cc(D, p), "bytes": n}
               for p, n in peers.most_common(20) if p not in D["lab"] and (_public(p) or _local(p))][:8]
        if h and h["ports"]:
            ports = [{"port": p, "count": n} for p, n in h["ports"].most_common(10)]
        else:
            ports = [{"port": _port(k), "proto": str(k).split("/")[0] if "/" in str(k) else None, "count": n}
                     for k, n in tl_ports.most_common(10) if _port(k) is not None]
        protos = dict(h["protos"].most_common(10)) if h and h["protos"] else \
            dict(collections.Counter(str(k).split("/")[0] for k in tl_ports.elements()).most_common(10))
        fps = [{"kind": kind, "fp": fp, "count": devs[ip][0], "sni": devs[ip][1][:6], "devices": len(devs)}
               for (kind, fp), devs in D["fps"].items() if ip in devs]
        fps.sort(key=lambda x: -x["count"])
        countries = []
        mac = h.get("mac") if h else None
        bl = D["baseline"].get(mac or "") or D["baseline"].get(ip) or \
            next((d for d in D["baseline"].values() if d.get("ip") == ip), None)
        if bl:
            countries = list(bl["countries"])
        if not countries:
            countries = sorted({t["cc"] for t in top if t["cc"]})
        n_alerts = sum(1 for a in D["alerts"] if (a.get("actor") == ip or a.get("target") == ip) and not a.get("selftest"))
        meta = D["meta"].get(ip) or {}
        out = {"ip": ip, "name": self._name(D, ip), "mac": mac, "kind": (h or {}).get("kind") or ("local" if _local(ip) else "public"),
               "type": meta.get("kind"), "icon": meta.get("icon"),
               "first": (h or {}).get("first") or t_first, "last": (h or {}).get("last") or t_last,
               "hours": hours, "top_peers": top, "ports": ports, "protos": protos,
               "bytes_in": (h or {}).get("bytes_in") or tin, "bytes_out": (h or {}).get("bytes_out") or tout,
               "fingerprints": fps[:8], "countries": countries, "alerts": n_alerts, "demo": self.sim}
        out["normal"], out["normal_en"] = self._normal(out)
        return out

    def _normal(self, p):
        hrs = p["hours"]
        mx = max(hrs) if hrs else 0
        if not mx and not p["top_peers"]:
            return ("Δεν υπάρχουν ακόμη αρκετά δεδομένα για προφίλ.", "Not enough data for a profile yet.")
        parts, en = ["Μιλά"], ["Talks"]
        if mx:
            act = [h for h in range(24) if hrs[h] >= 0.2 * mx]
            if len(act) >= 22:
                parts.append("όλο το 24ωρο")
                en.append("around the clock")
            else:
                # το μεγαλύτερο συνεχόμενο (κυκλικά) διάστημα ενεργών ωρών
                best, cur, start, bstart = 0, 0, 0, act[0]
                for i in range(48):
                    if hrs[i % 24] >= 0.2 * mx:
                        if cur == 0:
                            start = i
                        cur += 1
                        if cur > best:
                            best, bstart = cur, start
                    else:
                        cur = 0
                best = min(best, 24)
                parts.append(f"κυρίως {bstart % 24:02d}–{(bstart + best) % 24:02d}")
                en.append(f"mostly {bstart % 24:02d}–{(bstart + best) % 24:02d}")
        n = len(p["top_peers"])
        ccs = collections.Counter(t["cc"] for t in p["top_peers"] if t["cc"])
        where = f" ({', '.join(c for c, _ in ccs.most_common(3))})" if ccs else ""
        parts.append(f"με {n} {'προορισμό' if n == 1 else 'προορισμούς'}{where}")
        en.append(f"with {n} {'destination' if n == 1 else 'destinations'}{where}")
        port = next((x["port"] for x in p["ports"] if x["port"] in SERVICES), None)
        if port:
            parts.append(f"μέσω {SERVICES[port]}")
            en.append(f"over {SERVICES[port]}")
        nf = len(p["fingerprints"])
        if nf:
            parts.append(f"και {nf} {'αποτύπωμα' if nf == 1 else 'αποτυπώματα'} TLS")
            en.append(f"and {nf} TLS {'fingerprint' if nf == 1 else 'fingerprints'}")
        return " ".join(parts) + ".", " ".join(en) + "."
