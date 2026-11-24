"""🏢 Πελάτες / εγκαταστάσεις — ένα NetWatch (laptop ή κουτί Pi) σε πολλούς πελάτες.

  • Μητρώο πελατών: όνομα, διεύθυνση, υπεύθυνος, τηλέφωνο, email, σύμβαση, σημειώσεις και «αποτύπωμα δικτύου»
    (MAC + IP του router, subnet, προαιρετικά SSID) για να αναγνωρίζεται ο πελάτης αυτόματα μόλις συνδεθείς.
  • Φάκελος ανά πελάτη `data/sites/<id>/` — εκεί γράφουν και τα τεστ αποδοχής (accept.py) και οι ετικέτες (labels.py).
  • Ημερολόγιο επισκέψεων: έναρξη/λήξη, εργασίες, υλικά, λεπτά. Στη λήξη κρατιέται μικρό «στιγμιότυπο»
    (συσκευές, ειδοποιήσεις από την προηγούμενη επίσκεψη, μετρητές από άλλα κομμάτια του NetWatch).
  • Μηνιαία αναφορά συντήρησης (HTML για εκτύπωση/PDF, A4) με υπογραφές τεχνικού και πελάτη· CSV πελατών/επισκέψεων.
  • Στοιχεία εταιρείας/τεχνικού (και λογότυπο ως data URL) που χρησιμοποιούν όλες οι εκτυπώσεις.

Δεν στέλνει τίποτα στο δίκτυο: διαβάζει μόνο ό,τι ξέρει ήδη το NetWatch (state.hosts, state.gateway, ιστορικό).
Τα id των πελατών είναι αυστηρά «slugs» [a-z0-9-] — ποτέ μονοπάτι από τον χρήστη σε όνομα φακέλου.
"""
import base64
import csv
import html
import io
import ipaddress
import json
import os
import re
import threading
import time
import unicodedata

SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?\Z")
CONTRACTS = {"none": ("Χωρίς σύμβαση", "No contract"), "monthly": ("Μηνιαία συντήρηση", "Monthly maintenance"),
             "quarterly": ("Τριμηνιαία συντήρηση", "Quarterly maintenance"), "annual": ("Ετήσια συντήρηση", "Annual maintenance"),
             "oncall": ("Κατά κλήση", "On call")}
MAX_SITES = 500
MAX_VISITS = 2000
MAX_SNAP_DEVICES = 300
MAX_LOGO = 200 * 1024
LOGO_TYPES = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff"}
MONTHS_EL = ("Ιανουάριος", "Φεβρουάριος", "Μάρτιος", "Απρίλιος", "Μάιος", "Ιούνιος", "Ιούλιος", "Αύγουστος", "Σεπτέμβριος",
             "Οκτώβριος", "Νοέμβριος", "Δεκέμβριος")
MONTHS_EN = ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
             "December")
_GR = dict(zip("αβγδεζηθικλμνξοπρσςτυφχψω", ("a", "v", "g", "d", "e", "z", "i", "th", "i", "k", "l", "m", "n", "x", "o", "p", "r",
                                             "s", "s", "t", "y", "f", "ch", "ps", "o")))


# ───────────────────────── κοινά βοηθητικά (τα χρησιμοποιούν και accept.py / labels.py) ─────────────────────────
def L(lang, el, en):
    return en if lang == "en" else el


def esc(s):
    return html.escape("" if s is None else str(s), quote=True)


def clean(s, n=80):
    """Κείμενο από χρήστη: χωρίς χαρακτήρες ελέγχου (εκτός νέας γραμμής), με όριο μήκους."""
    s = "" if s is None else str(s)
    return "".join(c for c in s if c == "\n" or (ord(c) >= 32 and ord(c) != 127)).strip()[:n]


def norm_mac(m):
    h = re.sub(r"[^0-9a-f]", "", str(m or "").lower())
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ""


def slugify(name):
    s = unicodedata.normalize("NFD", str(name or "").lower())
    s = "".join(_GR.get(c, c) for c in s if not unicodedata.combining(c))
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")[:40].strip("-")
    return s or "site"


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, obj, on_save=None):
    """Ατομική εγγραφή (tmp + os.replace). Ποτέ εξαίρεση — ένας γεμάτος δίσκος δεν ρίχνει το NetWatch."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False)
        os.replace(tmp, path)
        if on_save:
            on_save(path)
        return True
    except Exception:  # noqa: BLE001
        return False


def expand(pattern, limit=500):
    """«A-01..A-24» → [A-01 … A-24] (κρατά τα μηδενικά)· «PP1-01..24», «A-1..A-3, B-1..B-3», σκέτα ονόματα με κόμμα.
    ValueError (με ελληνικό μήνυμα) για κενό/ανάποδο/υπερβολικό μοτίβο."""
    out = []
    for part in re.split(r"[,;\n]+", str(pattern or "")):
        part = clean(part, 90)
        if not part:
            continue
        if ".." in part:
            a, b = (x.strip() for x in part.split("..", 1))
            ma, mb = re.match(r"^(.*?)(\d{1,9})(\D*)$", a), re.match(r"^(.*?)(\d{1,9})(\D*)$", b)
            if not ma or not mb:
                raise ValueError(f"Το «{part[:40]}» δεν έχει αριθμό στην αρχή και στο τέλος (π.χ. A-01..A-24)")
            if mb.group(1) and mb.group(1) != ma.group(1):
                raise ValueError(f"Διαφορετικό πρόθεμα στην αρχή και στο τέλος: «{part[:40]}»")
            lo, hi, w = int(ma.group(2)), int(mb.group(2)), len(ma.group(2))
            if hi < lo:
                raise ValueError(f"Το τέλος είναι μικρότερο από την αρχή: «{part[:40]}»")
            if len(out) + hi - lo + 1 > limit:
                raise ValueError(f"Πάρα πολλά στοιχεία (όριο {limit})")
            suf = ma.group(3) or mb.group(3)
            out += [f"{ma.group(1)}{i:0{w}d}{suf}"[:40] for i in range(lo, hi + 1)]
        else:
            out.append(part[:40])
        if len(out) > limit:
            raise ValueError(f"Πάρα πολλά στοιχεία (όριο {limit})")
    if not out:
        raise ValueError("Κενό μοτίβο — γράψε π.χ. A-01..A-24")
    return out


def ts(t, lang="el", date_only=False):
    if not t:
        return "—"
    f = ("%d/%m/%Y" if lang != "en" else "%Y-%m-%d") + ("" if date_only else " %H:%M")
    return time.strftime(f, time.localtime(t))


def hm(minutes):
    m = max(0, int(minutes or 0))
    return f"{m // 60}:{m % 60:02d}"


def csv_text(rows, head):
    def safe(v):  # όχι τύποι στο Excel από κείμενο πελάτη
        v = "" if v is None else str(v)
        return "'" + v if v[:1] in "=+-@\t\r" else v
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(head)
    for r in rows:
        w.writerow([safe(x) for x in r])
    return "﻿" + buf.getvalue()


def raw(text, name, typ="text/html; charset=utf-8"):
    return 200, {"_raw": text.encode("utf-8"), "_type": typ, "_name": name}


def devices(state, cap=MAX_SNAP_DEVICES):
    """Τοπικές συσκευές που ξέρει το NetWatch → [{ip, mac, name, vendor, type, dtype, icon}] (ταξινομημένες κατά IP)."""
    if state is None:
        return []
    lock = getattr(state, "lock", None)
    try:
        if lock:
            lock.acquire()
        hosts = [dict(h) for h in (getattr(state, "hosts", None) or {}).values() if isinstance(h, dict) and h.get("kind") == "local"]
    finally:
        if lock:
            lock.release()
    out = []
    for h in hosts:
        try:
            dt = state._dtype(h) if hasattr(state, "_dtype") else {}
        except Exception:  # noqa: BLE001
            dt = {}
        names = sorted(str(n) for n in (h.get("names") or ()))
        out.append({"ip": str(h.get("ip") or ""), "mac": norm_mac(h.get("mac")),
                    "name": clean(dt.get("alias") or (names[0] if names else h.get("rdns") or ""), 64),
                    "vendor": clean(dt.get("vendor") or h.get("vendor") or "", 48),
                    "type": clean(dt.get("dlabel") or dt.get("dtype") or "", 32), "dtype": clean(dt.get("dtype") or "", 24),
                    "icon": clean(dt.get("dicon") or "", 8)})

    def key(d):
        try:
            return (0, int(ipaddress.ip_address(d["ip"])))
        except ValueError:
            return (1, 0)
    out.sort(key=key)
    return out[:cap]


# ───────────────────────── κοινό «χαρτί» για τις εκτυπώσεις (A4) ─────────────────────────
DOC_CSS = """
@page{size:A4;margin:14mm 13mm}
:root{color-scheme:light}*{box-sizing:border-box}
body{font:12.5px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;color:#1d2633;background:#fff;margin:0}
main{max-width:184mm;margin:0 auto;padding:18px 12px 40px}
.hint{background:#eef6ff;border:1px solid #bcd7f5;border-radius:8px;padding:7px 11px;font-size:12px;margin-bottom:14px}
.demo{background:#fff4d6;border:1px solid #f0d27a;border-radius:8px;padding:6px 10px;font-size:12px;margin-bottom:12px}
.hdr{display:flex;gap:14px;align-items:center;border-bottom:2px solid #1d2633;padding-bottom:10px}
.hdr img{max-height:22mm;max-width:50mm}.hdr .co{flex:1}.hdr .co b{font-size:16px}.hdr .co div{font-size:11.5px;color:#4a5665}
.hdr .doc{text-align:right;font-size:11.5px;color:#4a5665}
h1{font-size:19px;margin:16px 0 2px}h2{font-size:14px;margin:18px 0 6px;border-bottom:1px solid #cfd6df;padding-bottom:3px;break-after:avoid}
.sub{color:#4a5665;font-size:12px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}
.boxx{border:1px solid #cfd6df;border-radius:6px;padding:8px 10px}.boxx .k{font-size:10.5px;color:#5b6878;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;font-size:11.5px;margin-top:4px}
th,td{text-align:left;padding:4px 6px;border:1px solid #d9dfe7;vertical-align:top}th{background:#f1f4f8;font-weight:600}
tr{break-inside:avoid}.mono{font-family:ui-monospace,Menlo,Consolas,monospace}.r{text-align:right}.c{text-align:center}
.pass{color:#0a7a3d;font-weight:700}.fail{color:#c0182d;font-weight:700}.pend{color:#9a6a00;font-weight:700}.na{color:#6b7684}
.kpis{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px}.kpis div{border:1px solid #cfd6df;border-radius:6px;padding:5px 10px;min-width:80px}
.kpis b{display:block;font-size:16px}.kpis span{font-size:10.5px;color:#5b6878}
.verdict{border:2px solid var(--c,#1d2633);color:var(--c,#1d2633);border-radius:8px;padding:8px 12px;font-size:15px;font-weight:700;margin-top:8px}
.lines{min-height:22mm;border:1px solid #cfd6df;border-radius:6px;padding:8px 10px;white-space:pre-wrap}
.sign{display:grid;grid-template-columns:1fr 1fr;gap:16mm;margin-top:14mm;break-inside:avoid}
.sign div{border-top:1px solid #1d2633;padding-top:4px;font-size:11.5px;min-height:10mm}.sign .box{border:1px solid #1d2633;height:26mm;margin-bottom:4px}
.sign span{display:block;color:#5b6878;font-size:10.5px}
.foot{margin-top:10mm;font-size:10px;color:#7a8594;text-align:center}
ul{margin:4px 0 0 18px;padding:0}li{margin:2px 0}
@media print{.hint{display:none}main{padding:0;max-width:none}}
"""


def doc_open(title, lang, demo=False):
    return (f'<!doctype html><html lang="{esc(lang)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,'
            f'initial-scale=1"><title>{esc(title)}</title><style>{DOC_CSS}</style></head><body><main>'
            f'<div class="hint">🖨 {L(lang, "Για εκτύπωση ή αποθήκευση ως PDF πάτησε <b>Ctrl+P</b> (Mac: <b>⌘P</b>). Αυτό το πλαίσιο δεν τυπώνεται.", "To print or save as PDF press <b>Ctrl+P</b> (Mac: <b>⌘P</b>). This box is not printed.")}</div>'
            + (f'<div class="demo">🧪 {L(lang, "Δείγμα (demo) — φανταστικά στοιχεία.", "Sample (demo) — fictional data.")}</div>' if demo else ""))


def doc_header(co, lang, doc_no="", when=None):
    """Κεφαλίδα εταιρείας/τεχνικού. co = Sites.company() (ή {})."""
    co = co or {}
    logo = co.get("logo") or ""
    img = f'<img alt="" src="{esc(logo)}">' if logo_ok(logo)[0] and logo else ""
    bits = [x for x in (co.get("tech"), co.get("phone"), co.get("email")) if x]
    vat = f'{L(lang, "ΑΦΜ", "VAT")} {esc(co["vat"])}' if co.get("vat") else ""
    return (f'<div class="hdr">{img}<div class="co"><b>{esc(co.get("name") or co.get("tech") or "NetWatch")}</b>'
            f'<div>{" · ".join(esc(x) for x in bits)}</div><div>{" · ".join(x for x in (esc(co.get("address") or ""), vat) if x)}</div></div>'
            f'<div class="doc">{esc(doc_no)}<br>{esc(ts(when, lang, True)) if when else ""}</div></div>')


def customer_block(site, lang):
    s = site or {}
    con = " · ".join(esc(x) for x in (s.get("contact"), s.get("phone"), s.get("email")) if x)
    return (f'<div class="boxx"><div class="k">{L(lang, "Πελάτης", "Customer")}</div><b>{esc(s.get("name") or "—")}</b>'
            f'<div>{esc(s.get("address") or "")}</div><div>{con}</div></div>')


def signatures(lang, left, right, boxes=False):
    b = '<div class="box"></div>' if boxes else ""
    hint = L(lang, "ονοματεπώνυμο · υπογραφή · σφραγίδα", "name · signature · stamp")
    return (f'<div class="sign"><section>{b}<div>{esc(left)}<span>{hint}</span></div></section>'
            f'<section>{b}<div>{esc(right)}<span>{hint}</span></div></section></div>')


def doc_close(lang):
    return f'<div class="foot">{L(lang, "Δημιουργήθηκε με το NetWatch", "Generated with NetWatch")}</div></main></body></html>'


def logo_ok(data_url):
    """→ (ok, μήνυμα). Δεκτά: κενό, ή data:image/png|jpeg;base64 έως ~200 KB με σωστά «μαγικά» bytes. Όχι SVG (μπορεί να κρύβει script)."""
    if not data_url:
        return True, ""
    m = re.match(r"^data:(image/[a-z+.-]+);base64,([A-Za-z0-9+/=\s]+)$", str(data_url))
    if not m or m.group(1) not in LOGO_TYPES:
        return False, "Το λογότυπο πρέπει να είναι PNG ή JPEG (όχι SVG)."
    if len(m.group(2)) > MAX_LOGO * 4 // 3 + 16:
        return False, "Το λογότυπο είναι πολύ μεγάλο (όριο 200 KB)."
    try:
        rawb = base64.b64decode(m.group(2), validate=False)
    except Exception:  # noqa: BLE001
        return False, "Το λογότυπο δεν διαβάζεται."
    if len(rawb) > MAX_LOGO:
        return False, "Το λογότυπο είναι πολύ μεγάλο (όριο 200 KB)."
    if not rawb.startswith(LOGO_TYPES[m.group(1)]):
        return False, "Το αρχείο δεν είναι πραγματικό PNG/JPEG."
    return True, ""


def _err(el, en=None, code=400):
    return code, {"error": el, "error_en": en or el}


# ───────────────────────── το μητρώο ─────────────────────────
class Sites:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time):
        self.state, self.demo, self.clock = state, demo, clock
        self.data_dir = data_dir
        self.path = os.path.join(data_dir, "sites.json") if data_dir else None
        self.on_save = None
        self.lock = threading.RLock()
        self.sites = {}       # id → στοιχεία πελάτη
        self.visits = {}      # id → [επισκέψεις, παλαιότερη πρώτη]
        self.co = {"name": "", "tech": "", "phone": "", "email": "", "vat": "", "address": "", "logo": ""}
        self.forced = None    # (id, αποτύπωμα τη στιγμή της επιλογής) — «είμαι σε αυτόν τον πελάτη» με το χέρι
        self._demo_fp = None
        if demo:
            self._seed_demo()
        else:
            self._load()

    # ── αποθήκευση ──
    def _load(self):
        j = read_json(self.path) if self.path else None
        if not isinstance(j, dict):
            return
        co = j.get("company")
        if isinstance(co, dict):
            self._set_company(co)
        for sid, s in (j.get("sites") or {}).items() if isinstance(j.get("sites"), dict) else ():
            if not (isinstance(sid, str) and SLUG_RE.match(sid) and isinstance(s, dict)):
                continue  # πειραγμένο αρχείο: ποτέ id που δεν είναι slug
            self.sites[sid] = self._clean_site(s, sid, s.get("created"))
            vs = read_json(os.path.join(self.data_dir, "sites", sid, "visits.json"), [])
            self.visits[sid] = [v for v in (vs if isinstance(vs, list) else []) if isinstance(v, dict) and v.get("id")][-MAX_VISITS:]

    def _save(self):
        if self.path:
            write_json(self.path, {"company": self.co, "sites": self.sites}, self.on_save)

    def _save_visits(self, sid):
        d = self.site_dir(sid)
        if d:
            write_json(os.path.join(d, "visits.json"), self.visits.get(sid) or [], self.on_save)

    # ── φάκελος πελάτη ──
    def site_dir(self, site_id=None):
        """Φάκελος εγγράφων του πελάτη (τρέχων αν δεν δοθεί id). None αν άγνωστος/μη έγκυρος ή χωρίς data_dir."""
        sid = self.detect() if site_id is None else site_id
        if not self.data_dir or not isinstance(sid, str) or not SLUG_RE.match(sid) or sid not in self.sites:
            return None
        p = os.path.join(self.data_dir, "sites", sid)
        try:
            os.makedirs(p, exist_ok=True)
        except OSError:
            return None
        return p

    def ids(self):
        return sorted(self.sites)

    def get(self, sid):
        s = self.sites.get(sid) if isinstance(sid, str) else None
        return dict(s) if s else None

    # ── εταιρεία ──
    def company(self):
        return dict(self.co)

    def _set_company(self, d):
        ok, msg = logo_ok(d.get("logo")) if "logo" in d else (True, "")
        if not ok:
            return msg
        for k, n in (("name", 80), ("tech", 80), ("phone", 40), ("email", 80), ("vat", 20), ("address", 160)):
            if k in d:
                self.co[k] = clean(d.get(k), n).replace("\n", " ")
        if "logo" in d:
            self.co["logo"] = re.sub(r"\s+", "", str(d.get("logo") or ""))
        return ""

    # ── αποτύπωμα δικτύου / αναγνώριση ──
    def network(self):
        """Το δίκτυο στο οποίο είμαστε τώρα → {gw_ip, gw_mac, subnet, ssid}. Μόνο από ό,τι ξέρει ήδη το NetWatch."""
        if self._demo_fp:
            return dict(self._demo_fp)
        st = self.state
        gw = str(getattr(st, "gateway", None) or "") if st is not None else ""
        mac = subnet = ""
        if gw:
            h = (getattr(st, "hosts", None) or {}).get(gw)
            mac = norm_mac(h.get("mac")) if isinstance(h, dict) else ""
            try:
                subnet = str(ipaddress.ip_network(str(getattr(st, "subnet", None) or f"{gw}/24"), strict=False))
            except ValueError:
                gw = ""
        return {"gw_ip": gw, "gw_mac": mac, "subnet": subnet, "ssid": clean(getattr(st, "ssid", "") or "", 32) if st is not None else ""}

    def detect(self):
        """Ποιος πελάτης είναι αυτό το δίκτυο; Πρώτα MAC του router, μετά IP router + subnet (αν δεν διαφωνούν οι MAC)."""
        n = self.network()
        with self.lock:
            if self.forced and self.forced[0] in self.sites and self.forced[1] == (n["gw_ip"], n["gw_mac"]):
                return self.forced[0]
            if n["gw_mac"]:
                for sid in sorted(self.sites):
                    if self.sites[sid]["fp"].get("gw_mac") == n["gw_mac"]:
                        return sid
            if n["gw_ip"]:
                for sid in sorted(self.sites):
                    fp = self.sites[sid]["fp"]
                    # 192.168.1.1/24 υπάρχει παντού: αν ξέρουμε και τις δύο MAC και διαφέρουν, ΔΕΝ είναι ο ίδιος πελάτης
                    if fp.get("gw_ip") == n["gw_ip"] and fp.get("subnet") == n["subnet"] and not (fp.get("gw_mac") and n["gw_mac"]):
                        return sid
        return None

    # ── πελάτες ──
    def _clean_fp(self, fp):
        fp = fp if isinstance(fp, dict) else {}
        ip = subnet = ""
        try:
            ip = str(ipaddress.ip_address(str(fp.get("gw_ip") or "").strip()))
        except ValueError:
            pass
        try:
            subnet = str(ipaddress.ip_network(str(fp.get("subnet") or "").strip(), strict=False)) if fp.get("subnet") else ""
        except ValueError:
            pass
        return {"gw_mac": norm_mac(fp.get("gw_mac")), "gw_ip": ip, "subnet": subnet, "ssid": clean(fp.get("ssid"), 32)}

    def _clean_site(self, d, sid, created=None):
        c = str(d.get("contract") or "none")
        return {"id": sid, "name": clean(d.get("name"), 80).replace("\n", " "), "address": clean(d.get("address"), 160),
                "contact": clean(d.get("contact"), 80), "phone": clean(d.get("phone"), 40), "email": clean(d.get("email"), 80),
                "notes": clean(d.get("notes"), 1000), "contract": c if c in CONTRACTS else "none",
                "fp": self._clean_fp(d.get("fp")), "created": float(created or self.clock())}

    def save_site(self, d):
        """Νέος πελάτης ή ενημέρωση. d["from_current"] → πάρε το αποτύπωμα από το τρέχον δίκτυο. → (site, σφάλμα)."""
        d = d if isinstance(d, dict) else {}
        with self.lock:
            sid = d.get("id")
            old = self.sites.get(sid) if isinstance(sid, str) else None
            if sid and not old:
                return None, "Άγνωστος πελάτης"
            merged = dict(old or {}, **{k: v for k, v in d.items() if k not in ("id", "created")})
            if not clean(merged.get("name"), 80):
                return None, "Δώσε όνομα πελάτη"
            if d.get("from_current"):
                cur = self.network()
                merged["fp"] = dict(cur, ssid=cur["ssid"] or ((d.get("fp") or {}).get("ssid") if isinstance(d.get("fp"), dict) else ""))
            if not old:
                if len(self.sites) >= MAX_SITES:
                    return None, "Πάρα πολλοί πελάτες"
                base = slugify(merged["name"])
                sid, i = base, 2
                while sid in self.sites:
                    sid, i = f"{base[:36]}-{i}", i + 1
            self.sites[sid] = self._clean_site(merged, sid, (old or {}).get("created"))
            self.visits.setdefault(sid, [])
            self._save()
            self.site_dir(sid)
            return dict(self.sites[sid]), None

    def delete_site(self, sid):
        """Βγάζει τον πελάτη από το μητρώο. Ο φάκελός του με τα έγγραφα ΜΕΝΕΙ στον δίσκο (δεν σβήνουμε δουλειά πελάτη)."""
        with self.lock:
            if sid not in self.sites:
                return False
            del self.sites[sid]
            self.visits.pop(sid, None)
            if self.forced and self.forced[0] == sid:
                self.forced = None
            self._save()
            return True

    def select(self, sid):
        """«Είμαι σε αυτόν τον πελάτη» με το χέρι — ισχύει όσο δεν αλλάζει το δίκτυο. Κενό → ξανά αυτόματα."""
        with self.lock:
            if not sid:
                self.forced = None
                return True
            if sid not in self.sites:
                return False
            n = self.network()
            self.forced = (sid, (n["gw_ip"], n["gw_mac"]))
            return True

    # ── στιγμιότυπο ──
    def _alerts_since(self, since, now):
        st = self.state
        rows = None
        hist = getattr(st, "history", None) if st is not None else None
        if hist is not None and hasattr(hist, "query"):
            try:
                rows = (hist.query(hours=max(1.0, (now - since) / 3600.0), ref=now) or {}).get("alerts")
            except Exception:  # noqa: BLE001 — χωρίς ιστορικό συνεχίζουμε με ό,τι έχει η μνήμη
                rows = None
        if rows is None:
            try:
                rows = list(getattr(st, "alerts", None) or ()) if st is not None else []
            except Exception:  # noqa: BLE001
                rows = []
        sev, typ = {"high": 0, "med": 0, "low": 0}, {}
        for a in rows:
            if not isinstance(a, dict) or a.get("lab") or a.get("selftest") or not since <= float(a.get("t") or 0) <= now + 1:
                continue
            if a.get("sev") in sev:
                sev[a["sev"]] += 1
            t = clean(a.get("type"), 60)
            typ[t] = typ.get(t, 0) + 1
        top = sorted(typ.items(), key=lambda kv: (-kv[1], kv[0]))[:12]
        return {"since": since, "sev": sev, "types": [{"type": t, "n": n} for t, n in top], "total": sum(typ.values())}

    def _extras(self):
        out = {}
        for name in ("vulns", "upnp", "accept", "l2guard", "camexp"):
            obj = getattr(self.state, name, None) if self.state is not None else None
            try:
                c = (obj.view() or {}).get("counts") if obj is not None and hasattr(obj, "view") else None
            except Exception:  # noqa: BLE001
                c = None
            if isinstance(c, dict):
                nums = {str(k)[:16]: v for k, v in list(c.items())[:8] if isinstance(v, (int, float)) and not isinstance(v, bool)}
                if nums:
                    out[name] = nums
        return out

    def snapshot(self, since=None):
        """Μικρή εικόνα του δικτύου τώρα: συσκευές, ειδοποιήσεις από το `since`, μετρητές άλλων ελέγχων."""
        now = self.clock()
        since = max(float(since or 0), now - 90 * 86400)
        devs = [{k: d[k] for k in ("ip", "mac", "name", "vendor", "type")} for d in devices(self.state)]
        return {"t": now, "network": self.network(), "count": len(devs), "devices": devs,
                "alerts": self._alerts_since(since, now), "extras": self._extras()}

    # ── επισκέψεις ──
    def _open(self, sid):
        return next((v for v in self.visits.get(sid) or [] if not v.get("end")), None)

    def start_visit(self, sid, tech=""):
        with self.lock:
            if sid not in self.sites:
                return None, "Άγνωστος πελάτης"
            if self._open(sid):
                return None, "Υπάρχει ήδη ανοιχτή επίσκεψη — κλείσε πρώτα εκείνη"
            now = self.clock()
            v = {"id": self._vid(sid, now), "start": now, "end": None, "tech": clean(tech, 80) or self.co.get("tech") or "",
                 "work": "", "materials": "", "recs": "", "minutes": 0, "snapshot": None}
            self.visits.setdefault(sid, []).append(v)
            del self.visits[sid][:-MAX_VISITS]
            self._save_visits(sid)
            return v, None

    def _vid(self, sid, t):
        base, i = f"v{int(t)}", 1
        have = {v["id"] for v in self.visits.get(sid) or []}
        vid = base
        while vid in have:
            i += 1
            vid = f"{base}-{i}"
        return vid

    @staticmethod
    def _minutes(v, default=0):
        try:
            return max(0, min(int(float(v)), 24 * 60 * 14))
        except (TypeError, ValueError):
            return default

    def end_visit(self, sid, work="", materials="", minutes=None, recs=""):
        """Κλείνει την ανοιχτή επίσκεψη. Στιγμιότυπο μπαίνει ΜΟΝΟ αν είμαστε στο δίκτυο αυτού του πελάτη."""
        with self.lock:
            v = self._open(sid) if sid in self.sites else None
            if not v:
                return None, "Δεν υπάρχει ανοιχτή επίσκεψη"
            now = self.clock()
            prev = [x["end"] for x in self.visits[sid] if x.get("end")]
            v.update(end=now, work=clean(work, 2000), materials=clean(materials, 1000), recs=clean(recs, 1000),
                     minutes=self._minutes(minutes, None) if minutes not in (None, "") else max(1, int(round((now - v["start"]) / 60.0))))
            if v["minutes"] is None:
                v["minutes"] = max(1, int(round((now - v["start"]) / 60.0)))
            if self.demo:  # demo: συνεπές δείγμα — αντίγραφο του τελευταίου στιγμιότυπου του πελάτη, όχι το δίκτυο του demo
                last = [x["snapshot"] for x in self.visits[sid] if x.get("snapshot")]
                v["snapshot"] = dict(last[-1], t=now) if last else None
            else:
                v["snapshot"] = self.snapshot(max(prev) if prev else v["start"] - 30 * 86400) if self.detect() == sid else None
            self._save_visits(sid)
            return v, None

    def save_visit(self, sid, d):
        """Διόρθωση κειμένων επίσκεψης (vid) ή καταχώριση παλιάς επίσκεψης με ημερομηνία (χωρίς στιγμιότυπο)."""
        with self.lock:
            if sid not in self.sites:
                return None, "Άγνωστος πελάτης"
            vs = self.visits.setdefault(sid, [])
            v = next((x for x in vs if x["id"] == d.get("vid")), None) if d.get("vid") else None
            if d.get("vid") and not v:
                return None, "Άγνωστη επίσκεψη"
            if not v:
                try:
                    start = time.mktime(time.strptime(str(d.get("date") or "")[:16].replace("T", " "),
                                                      "%Y-%m-%d %H:%M" if len(str(d.get("date") or "")) > 10 else "%Y-%m-%d"))
                except (ValueError, OverflowError):
                    return None, "Δώσε ημερομηνία (ΕΕΕΕ-ΜΜ-ΗΗ)"
                mins = self._minutes(d.get("minutes"), 0)
                v = {"id": self._vid(sid, start), "start": start, "end": start + mins * 60 if mins else start + 60,
                     "tech": self.co.get("tech") or "", "work": "", "materials": "", "recs": "", "minutes": mins, "snapshot": None}
                vs.append(v)
                vs.sort(key=lambda x: x["start"])
                del vs[:-MAX_VISITS]
            for k, n in (("work", 2000), ("materials", 1000), ("recs", 1000), ("tech", 80)):
                if k in d:
                    v[k] = clean(d.get(k), n)
            if "minutes" in d and d.get("vid"):
                v["minutes"] = self._minutes(d.get("minutes"), v["minutes"])
            self._save_visits(sid)
            return v, None

    def delete_visit(self, sid, vid):
        with self.lock:
            vs = self.visits.get(sid) or []
            n = len(vs)
            vs[:] = [v for v in vs if v["id"] != vid]
            if len(vs) != n:
                self._save_visits(sid)
            return len(vs) != n

    # ── μηνιαία αναφορά ──
    def _month(self, month):
        m = re.match(r"^(\d{4})-(\d{2})$", str(month or ""))
        if m and 1 <= int(m.group(2)) <= 12 and 2000 <= int(m.group(1)) <= 2100:
            y, mo = int(m.group(1)), int(m.group(2))
        else:
            lt = time.localtime(self.clock())
            y, mo = lt.tm_year, lt.tm_mon
        a = time.mktime((y, mo, 1, 0, 0, 0, 0, 0, -1))
        b = time.mktime((y + (mo == 12), mo % 12 + 1, 1, 0, 0, 0, 0, 0, -1))
        return y, mo, a, b

    def monthly(self, sid, month=None, lang="el"):
        """Δεδομένα μηνιαίας αναφοράς → dict (ή None αν άγνωστος πελάτης)."""
        with self.lock:
            site = self.get(sid)
            if not site:
                return None
            y, mo, a, b = self._month(month)
            allv = sorted(self.visits.get(sid) or [], key=lambda v: v["start"])
            vs = [v for v in allv if a <= v["start"] < b]
            snaps = [v["snapshot"] for v in vs if v.get("snapshot")]
            before = [v["snapshot"] for v in allv if v["start"] < a and v.get("snapshot")]
        base = before[-1] if before else (snaps[0] if len(snaps) > 1 else None)
        last = snaps[-1] if snaps else None
        new, gone = [], []
        if base and last and base is not last:
            def key(d):
                return d.get("mac") or d.get("ip")
            kb, kl = {key(d): d for d in base.get("devices") or []}, {key(d): d for d in last.get("devices") or []}
            new = [kl[k] for k in kl if k not in kb]
            gone = [kb[k] for k in kb if k not in kl]
        sev, types = {"high": 0, "med": 0, "low": 0}, {}
        for s in snaps:
            al = s.get("alerts") or {}
            for k in sev:
                sev[k] += int((al.get("sev") or {}).get(k) or 0)
            for t in al.get("types") or []:
                types[t.get("type")] = types.get(t.get("type"), 0) + int(t.get("n") or 0)
        recs = []
        if last:
            ex = last.get("extras") or {}
            if sev["high"]:
                recs.append(L(lang, f"Να εξεταστούν οι {sev['high']} ειδοποιήσεις υψηλής σοβαρότητας του μήνα και να αποκλειστεί η αιτία τους.",
                              f"Review the {sev['high']} high-severity alerts of the month and remove their cause."))
            up = ex.get("upnp") or {}
            if (up.get("high") or 0) + (up.get("med") or 0):
                recs.append(L(lang, "Να κλείσουν οι θύρες που άνοιξαν συσκευές μόνες τους στο router (UPnP) ή να απενεργοποιηθεί το UPnP.",
                              "Close the ports devices opened on the router by themselves (UPnP), or turn UPnP off."))
            vu = ex.get("vulns") or {}
            if (vu.get("critical") or 0) + (vu.get("high") or 0):
                recs.append(L(lang, "Να ενημερωθεί το firmware των συσκευών με γνωστές ευπάθειες.", "Update the firmware of devices with known vulnerabilities."))
            if new:
                recs.append(L(lang, f"Να επιβεβαιωθούν από τον πελάτη οι {len(new)} νέες συσκευές που εμφανίστηκαν στο δίκτυο.",
                              f"Have the customer confirm the {len(new)} new devices that appeared on the network."))
        for v in vs:
            recs += [x.strip() for x in str(v.get("recs") or "").split("\n") if x.strip()]
        return {"site": site, "year": y, "month": mo, "from": a, "to": b, "visits": vs, "minutes": sum(int(v.get("minutes") or 0) for v in vs),
                "compared": bool(base and last and base is not last), "new": new, "gone": gone, "devices": last.get("count") if last else None,
                "sev": sev, "types": sorted(types.items(), key=lambda kv: (-kv[1], str(kv[0])))[:12], "recs": recs[:30]}

    def monthly_html(self, sid, month=None, lang="el"):
        lang = "en" if lang == "en" else "el"
        d = self.monthly(sid, month, lang)
        if d is None:
            return None
        s, co = d["site"], self.company()
        mname = (MONTHS_EN if lang == "en" else MONTHS_EL)[d["month"] - 1]
        title = L(lang, "Αναφορά μηνιαίας συντήρησης δικτύου", "Monthly network maintenance report")
        h = [doc_open(f"{title} — {s['name']} — {d['year']}-{d['month']:02d}", lang, self.demo),
             doc_header(co, lang, f"{s['id']} / {d['year']}-{d['month']:02d}", self.clock()),
             f"<h1>{title}</h1><div class=\"sub\">{L(lang, 'Περίοδος', 'Period')}: <b>{esc(mname)} {d['year']}</b> "
             f"({esc(ts(d['from'], lang, True))} – {esc(ts(d['to'] - 1, lang, True))})</div>",
             f'<div class="grid">{customer_block(s, lang)}<div class="boxx"><div class="k">{L(lang, "Σύμβαση / δίκτυο", "Contract / network")}</div>'
             f'<b>{esc(L(lang, *CONTRACTS[s["contract"]]))}</b><div class="mono">{esc(s["fp"].get("subnet") or "—")} · gateway {esc(s["fp"].get("gw_ip") or "—")}</div>'
             f'<div>{("SSID " + esc(s["fp"]["ssid"])) if s["fp"].get("ssid") else ""}</div></div></div>',
             f'<div class="kpis"><div><b>{len(d["visits"])}</b><span>{L(lang, "επισκέψεις", "visits")}</span></div>'
             f'<div><b>{hm(d["minutes"])}</b><span>{L(lang, "ώρες εργασίας", "hours worked")}</span></div>'
             f'<div><b>{esc(d["devices"] if d["devices"] is not None else "—")}</b><span>{L(lang, "συσκευές στο δίκτυο", "devices on the network")}</span></div>'
             f'<div><b>{d["sev"]["high"]}/{d["sev"]["med"]}/{d["sev"]["low"]}</b><span>{L(lang, "ειδοποιήσεις υψ./μέτρ./χαμ.", "alerts high/med/low")}</span></div></div>',
             f"<h2>1. {L(lang, 'Επισκέψεις', 'Visits')}</h2>"]
        if d["visits"]:
            h.append(f"<table><tr><th>{L(lang, 'Ημερομηνία', 'Date')}</th><th>{L(lang, 'Τεχνικός', 'Technician')}</th><th>{L(lang, 'Εργασίες', 'Work done')}</th>"
                     f"<th>{L(lang, 'Υλικά', 'Materials')}</th><th class=\"r\">{L(lang, 'Διάρκεια', 'Duration')}</th></tr>")
            for v in d["visits"]:
                h.append(f"<tr><td>{esc(ts(v['start'], lang))}{'' if v.get('end') else ' ⏳'}</td><td>{esc(v.get('tech'))}</td>"
                         f"<td>{esc(v.get('work')).replace(chr(10), '<br>')}</td><td>{esc(v.get('materials')).replace(chr(10), '<br>')}</td>"
                         f"<td class=\"r\">{hm(v.get('minutes'))}</td></tr>")
            h.append(f"<tr><th colspan=\"4\" class=\"r\">{L(lang, 'Σύνολο ωρών', 'Total hours')}</th><th class=\"r\">{hm(d['minutes'])}</th></tr></table>")
        else:
            h.append(f"<p>{L(lang, 'Δεν καταγράφηκαν επισκέψεις αυτόν τον μήνα.', 'No visits were recorded this month.')}</p>")
        h.append(f"<h2>2. {L(lang, 'Αλλαγές στις συσκευές του δικτύου', 'Changes in network devices')}</h2>")
        if not d["compared"]:
            h.append(f"<p>{L(lang, 'Χρειάζονται δύο στιγμιότυπα (δύο επισκέψεις που έκλεισαν μέσα στο δίκτυο του πελάτη) για σύγκριση.', 'Two snapshots (two visits ended on the customer network) are needed for a comparison.')}</p>")
        elif not d["new"] and not d["gone"]:
            h.append(f"<p>{L(lang, 'Καμία αλλαγή: οι ίδιες συσκευές στην αρχή και στο τέλος της περιόδου.', 'No change: the same devices at the start and end of the period.')}</p>")
        else:
            h.append(f"<table><tr><th></th><th>IP</th><th>MAC</th><th>{L(lang, 'Όνομα', 'Name')}</th><th>{L(lang, 'Κατασκευαστής', 'Vendor')}</th><th>{L(lang, 'Τύπος', 'Type')}</th></tr>")
            for lab, rows in ((L(lang, "➕ νέα", "➕ new"), d["new"]), (L(lang, "➖ έφυγε", "➖ gone"), d["gone"])):
                for r in rows[:100]:
                    h.append(f"<tr><td>{lab}</td><td class=\"mono\">{esc(r.get('ip'))}</td><td class=\"mono\">{esc(r.get('mac'))}</td>"
                             f"<td>{esc(r.get('name'))}</td><td>{esc(r.get('vendor'))}</td><td>{esc(r.get('type'))}</td></tr>")
            h.append("</table>")
        h.append(f"<h2>3. {L(lang, 'Ειδοποιήσεις ασφάλειας', 'Security alerts')}</h2>")
        if d["types"]:
            h.append(f"<table><tr><th>{L(lang, 'Τύπος', 'Type')}</th><th class=\"r\">{L(lang, 'Πλήθος', 'Count')}</th></tr>"
                     + "".join(f"<tr><td>{esc(t)}</td><td class=\"r\">{n}</td></tr>" for t, n in d["types"]) + "</table>")
        else:
            h.append(f"<p>{L(lang, 'Καμία ειδοποίηση στην περίοδο (ή δεν υπάρχει στιγμιότυπο).', 'No alerts in the period (or no snapshot available).')}</p>")
        h.append(f"<h2>4. {L(lang, 'Ανοιχτές συστάσεις', 'Open recommendations')}</h2>")
        h.append("<ul>" + "".join(f"<li>{esc(r)}</li>" for r in d["recs"]) + "</ul>" if d["recs"]
                 else f"<p>{L(lang, 'Καμία ανοιχτή σύσταση.', 'No open recommendations.')}</p>")
        h.append(signatures(lang, L(lang, "Ο τεχνικός", "Technician") + (f": {co['tech']}" if co.get("tech") else ""),
                            L(lang, "Ο πελάτης", "Customer") + (f": {s['contact']}" if s.get("contact") else "")))
        h.append(doc_close(lang))
        return "".join(h)

    # ── CSV ──
    def sites_csv(self):
        rows = [(s["id"], s["name"], s["address"], s["contact"], s["phone"], s["email"], CONTRACTS[s["contract"]][0],
                 s["fp"]["gw_ip"], s["fp"]["gw_mac"], s["fp"]["subnet"], s["fp"]["ssid"], len(self.visits.get(s["id"]) or []), s["notes"])
                for s in sorted(self.sites.values(), key=lambda x: x["name"].lower())]
        return csv_text(rows, ["id", "name", "address", "contact", "phone", "email", "contract", "gateway_ip", "gateway_mac",
                               "subnet", "ssid", "visits", "notes"])

    def visits_csv(self, sid):
        rows = [(time.strftime("%Y-%m-%d %H:%M", time.localtime(v["start"])),
                 time.strftime("%Y-%m-%d %H:%M", time.localtime(v["end"])) if v.get("end") else "", v.get("minutes") or 0, v.get("tech"),
                 v.get("work"), v.get("materials"), v.get("recs"), (v.get("snapshot") or {}).get("count", ""))
                for v in self.visits.get(sid) or []]
        return csv_text(rows, ["start", "end", "minutes", "technician", "work", "materials", "recommendations", "devices"])

    # ── προβολή ──
    @staticmethod
    def _visit_view(v):
        s = v.get("snapshot")
        return dict({k: v.get(k) for k in ("id", "start", "end", "tech", "work", "materials", "recs", "minutes")},
                    snapshot={"t": s.get("t"), "count": s.get("count"), "alerts": s.get("alerts"), "extras": s.get("extras")} if s else None)

    def _summary(self, s):
        vs = self.visits.get(s["id"]) or []
        _, _, a, b = self._month(None)
        done = [v for v in vs if v.get("end")]
        return dict(s, visits=len(vs), open_visit=(self._open(s["id"]) or {}).get("start"),
                    last_visit=max((v["end"] for v in done), default=None),
                    month_minutes=sum(int(v.get("minutes") or 0) for v in vs if a <= v["start"] < b))

    def detail(self, sid):
        with self.lock:
            s = self.sites.get(sid)
            if not s:
                return None
            vs = sorted(self.visits.get(sid) or [], key=lambda v: -v["start"])
            months = sorted({time.strftime("%Y-%m", time.localtime(v["start"])) for v in vs} | {time.strftime("%Y-%m", time.localtime(self.clock()))}, reverse=True)
            d = dict(self._summary(s), visit_list=[self._visit_view(v) for v in vs[:200]], months=months[:36], dir=bool(self.site_dir(sid)))
        d["baseline"] = self.drift(sid)  # 🔒 εγκεκριμένο δίκτυο + τι άλλαξε (έξω από το lock: διαβάζει state.hosts)
        return d

    # ── 🔒 baseline «εγκεκριμένου δικτύου» ανά πελάτη ──
    @staticmethod
    def _dkey(d):
        return ("mac", d["mac"]) if d.get("mac") else ("ip", d.get("ip"))

    def save_baseline(self, sid):
        """«Κλείδωσε» τις τωρινές συσκευές ως το εγκεκριμένο δίκτυο του πελάτη."""
        devs = [{"ip": x["ip"], "mac": x["mac"], "name": x["name"], "vendor": x["vendor"], "type": x["type"], "icon": x["icon"]} for x in devices(self.state)]
        with self.lock:
            if sid not in self.sites:
                return {"error": "Δεν υπάρχει πελάτης."}
            self.sites[sid]["baseline"] = {"saved": self.clock(), "devices": devs[:MAX_SNAP_DEVICES]}
            self._save()
        return {"ok": True, "count": len(devs)}

    def clear_baseline(self, sid):
        with self.lock:
            if sid in self.sites and self.sites[sid].get("baseline"):
                self.sites[sid].pop("baseline", None)
                self._save()
        return {"ok": True}

    def drift(self, sid):
        """Σύγκριση εγκεκριμένου δικτύου με το τωρινό → {saved, new:[...], gone:[...], ok}. None αν δεν υπάρχει baseline."""
        with self.lock:
            s = self.sites.get(sid)
            base = (s or {}).get("baseline")
        if not base:
            return None
        cur = devices(self.state)
        bykey_base = {self._dkey(d): d for d in base.get("devices") or ()}
        bykey_cur = {self._dkey(d): d for d in cur}
        new = [d for k, d in bykey_cur.items() if k not in bykey_base]
        gone = [d for k, d in bykey_base.items() if k not in bykey_cur]
        return {"saved": base.get("saved"), "count": len(base.get("devices") or ()),
                "new": sorted(new, key=lambda d: d.get("ip") or "")[:40],
                "gone": sorted(gone, key=lambda d: d.get("ip") or "")[:40], "ok": not new and not gone}

    def check_drift(self, now=None):
        """Ειδοποίηση όταν εμφανιστεί νέα συσκευή εκτός του εγκεκριμένου δικτύου (τρέχων πελάτης). Μία φορά ανά συσκευή."""
        now = now or self.clock()
        cur_sid = self.detect()
        if not cur_sid:
            return
        dr = self.drift(cur_sid)
        if not dr or not dr["new"]:
            return
        st, name = self.state, (self.sites.get(cur_sid) or {}).get("name") or cur_sid
        if st is None or not hasattr(st, "alert"):
            return
        for d in dr["new"]:
            who = d.get("name") or d.get("vendor") or d.get("ip")
            st.alert("Νέα συσκευή εκτός εγκεκριμένου δικτύου", "med", d.get("ip") or "?", f"πελάτης {name}",
                     f"Η συσκευή {who} ({d.get('ip')}{', ' + d['mac'] if d.get('mac') else ''}) δεν υπάρχει στο εγκεκριμένο δίκτυο του πελάτη «{name}». "
                     "Αν είναι δική σου/εγκεκριμένη, ξανακλείδωσε το baseline· αλλιώς δες ποια είναι.",
                     now, key=("site-drift", cur_sid, self._dkey(d)), cooldown=6 * 3600, mark=False)

    def run_forever(self):
        import time as _t
        _t.sleep(45)
        while True:
            try:
                self.check_drift()
            except Exception as e:  # noqa: BLE001
                from core import log
                log("sites drift:", e)
            _t.sleep(120)

    def view(self):
        with self.lock:
            net, cur = self.network(), self.detect()
            co = {k: v for k, v in self.co.items() if k != "logo"}
            return {"demo": self.demo, "current": cur, "network": net, "new_network": bool(net["gw_ip"] and not cur),
                    "manual": bool(self.forced and cur == self.forced[0]),
                    "sites": [self._summary(s) for s in sorted(self.sites.values(), key=lambda x: x["name"].lower())],
                    "company": dict(co, has_logo=bool(self.co.get("logo"))),
                    "contracts": [{"id": k, "el": v[0], "en": v[1]} for k, v in CONTRACTS.items()],
                    "persist": bool(self.data_dir)}

    # ── API ──
    def api(self, method, sub, q, body):
        q, body = q or {}, body if isinstance(body, dict) else {}
        if method == "GET":
            if sub == "":
                return 200, self.view()
            if sub == "site":
                d = self.detail(q.get("id"))
                return (200, d) if d else (404, {"error": "not found"})
            if sub == "report":
                doc = self.monthly_html(q.get("id"), q.get("month"), q.get("lang"))
                if doc is None:
                    return 404, {"error": "not found"}
                return raw(doc, f"netwatch-maintenance-{q.get('id')}-{'%04d-%02d' % self._month(q.get('month'))[:2]}.html")
            if sub == "sites.csv":
                return raw(self.sites_csv(), "netwatch-sites.csv", "text/csv; charset=utf-8")
            if sub == "visits.csv":
                if q.get("id") not in self.sites:
                    return 404, {"error": "not found"}
                return raw(self.visits_csv(q["id"]), f"netwatch-visits-{q['id']}.csv", "text/csv; charset=utf-8")
            return 404, {"error": "not found"}
        if method != "POST":
            return 404, {"error": "not found"}
        sid = body.get("id")
        if sub == "save":
            s, err = self.save_site(body)
            return _err(err) if err else (200, dict(self.view(), saved=s["id"]))
        if sub == "delete":
            return (200, self.view()) if self.delete_site(sid) else (404, {"error": "not found"})
        if sub == "select":
            return (200, self.view()) if self.select(sid) else (404, {"error": "not found"})
        if sub == "baseline":            # 🔒 κλείδωσε τις τωρινές συσκευές ως εγκεκριμένο δίκτυο
            r = self.save_baseline(sid)
            return _err(r["error"]) if r.get("error") else (200, dict(self.view(), site=self.detail(sid)))
        if sub == "baseline/clear":
            self.clear_baseline(sid)
            return 200, dict(self.view(), site=self.detail(sid))
        if sub == "bind":  # «αυτό το δίκτυο είναι αυτός ο πελάτης» → ξαναγράφει το αποτύπωμα
            if sid not in self.sites:
                return 404, {"error": "not found"}
            s, err = self.save_site({"id": sid, "from_current": True, "fp": self.sites[sid]["fp"]})
            return _err(err) if err else (200, self.view())
        if sub == "company":
            with self.lock:
                msg = self._set_company(body)
                if msg:
                    return _err(msg, "The logo must be a PNG or JPEG up to 200 KB (no SVG).")
                self._save()
            return 200, self.view()
        if sub in ("visit/start", "visit/end", "visit/save", "visit/delete"):
            if sub == "visit/start":
                v, err = self.start_visit(sid, body.get("tech"))
            elif sub == "visit/end":
                v, err = self.end_visit(sid, body.get("work"), body.get("materials"), body.get("minutes"), body.get("recs"))
            elif sub == "visit/save":
                v, err = self.save_visit(sid, body)
            else:
                v, err = (True, None) if self.delete_visit(sid, body.get("vid")) else (None, "Άγνωστη επίσκεψη")
            if err:
                return _err(err)
            return 200, dict(self.view(), site=self.detail(sid))
        return 404, {"error": "not found"}

    # ── demo ──
    def _seed_demo(self):
        now, day = self.clock(), 86400.0
        lt = time.localtime(now)
        m0 = time.mktime((lt.tm_year, lt.tm_mon, 1, 10, 0, 0, 0, 0, -1))  # 1η του μήνα, 10:00
        t1, t2 = min(m0 + day, now - 7200), min(m0 + 2 * day, now - 3600)
        self.co.update(name="Δικτυακές Λύσεις Παπαδόπουλος", tech="Γιώργος Παπαδόπουλος", phone="210 555 0142",
                       email="info@diktya-demo.example", vat="099999999", address="Αγ. Δημητρίου 12, Αθήνα")

        def dev(ip, mac, name, vendor, typ):
            return {"ip": ip, "mac": mac, "name": name, "vendor": vendor, "type": typ}

        def snap(t, fp, devs, sev, types, extras=None):
            return {"t": t, "network": fp, "count": len(devs), "devices": devs, "extras": extras or {},
                    "alerts": {"since": t - 30 * day, "sev": dict(zip(("high", "med", "low"), sev)), "total": sum(n for _, n in types),
                               "types": [{"type": a, "n": n} for a, n in types]}}

        def visit(t, mins, work, mat, recs, sn):
            return {"id": f"v{int(t)}", "start": t, "end": t + mins * 60, "tech": self.co["tech"], "work": work, "materials": mat,
                    "recs": recs, "minutes": mins, "snapshot": sn}

        cafe_fp = {"gw_ip": "192.168.1.1", "gw_mac": "d8:07:b6:11:22:33", "subnet": "192.168.1.0/24", "ssid": "Cafe-Thalassa"}
        acc_fp = {"gw_ip": "192.168.10.1", "gw_mac": "74:4d:28:aa:10:01", "subnet": "192.168.10.0/24", "ssid": ""}
        hot_fp = {"gw_ip": "10.20.0.1", "gw_mac": "b4:fb:e4:20:00:01", "subnet": "10.20.0.0/24", "ssid": "Hotel-Aegean-Staff"}
        for sid, name, addr, con, ph, em, contract, fp, notes in (
                ("cafe-thalassa", "Καφέ «Θάλασσα»", "Παραλιακή 45, Γλυφάδα", "Μαρία Ιωάννου", "210 555 0101", "maria@cafe-demo.example",
                 "oncall", cafe_fp, "Router παρόχου πίσω από το ταμείο. Wi‑Fi πελατών σε ξεχωριστό SSID."),
                ("logistiko-nikolaou", "Λογιστικό γραφείο Νικολάου", "Σόλωνος 80, Αθήνα", "Νίκος Νικολάου", "210 555 0177",
                 "nikos@logistiko-demo.example", "monthly", acc_fp, "NAS με αντίγραφα κάθε βράδυ. Εκτυπωτής δικτύου στον 1ο."),
                ("hotel-aegean", "Ξενοδοχείο Aegean View", "Λεωφ. Ποσειδώνος 3, Νάξος", "Ελένη Βλάχου", "22850 55 012",
                 "eleni@hotel-demo.example", "monthly", hot_fp, "12 κάμερες IP + NVR στο rack υποδοχής. 3 VLAN: προσωπικό, πελάτες, κάμερες.")):
            self.sites[sid] = self._clean_site({"name": name, "address": addr, "contact": con, "phone": ph, "email": em, "contract": contract,
                                                "fp": fp, "notes": notes}, sid, now - 200 * day)
        cafe = [dev("192.168.1.1", cafe_fp["gw_mac"], "router", "TP-Link", "Router"), dev("192.168.1.20", "00:11:32:ab:cd:01", "pos-tameio", "Epson", "POS"),
                dev("192.168.1.31", "f0:9f:c2:01:02:03", "ap-sala", "Ubiquiti", "Access point")]
        acc = [dev("192.168.10.1", acc_fp["gw_mac"], "mikrotik", "MikroTik", "Router"), dev("192.168.10.5", "00:11:32:10:00:05", "nas", "Synology", "NAS"),
               dev("192.168.10.21", "3c:52:82:10:00:21", "pc-nikos", "HP", "Υπολογιστής"), dev("192.168.10.22", "3c:52:82:10:00:22", "pc-grammateia", "HP", "Υπολογιστής"),
               dev("192.168.10.40", "00:1b:a9:10:00:40", "ektypotis", "Brother", "Εκτυπωτής")]
        hot = [dev("10.20.0.1", hot_fp["gw_mac"], "unifi-gw", "Ubiquiti", "Router"), dev("10.20.0.2", "b4:fb:e4:20:00:02", "sw-rack", "Ubiquiti", "Switch"),
               dev("10.20.0.10", "bc:ba:c2:20:00:10", "nvr", "Hikvision", "NVR")] \
            + [dev(f"10.20.0.{100 + i}", f"bc:ba:c2:20:01:{i:02x}", f"cam-{i:02d}", "Hikvision", "Κάμερα") for i in range(1, 13)] \
            + [dev("10.20.0.60", "a4:cf:12:20:00:60", "thermostat-lobby", "Espressif", "IoT"), dev("10.20.0.61", "a4:cf:12:20:00:61", "boiler-ctl", "Espressif", "IoT")]
        hot_prev = [d for d in hot if d["name"] not in ("cam-12", "boiler-ctl")] + [dev("10.20.0.77", "50:c7:bf:20:00:77", "tv-box-201", "TP-Link", "TV")]
        self.visits = {
            "cafe-thalassa": [visit(m0 - 40 * day, 50, "Αντικατάσταση access point στη σάλα, νέο SSID πελατών.", "1× UniFi U6 Lite, 15 m UTP Cat6", "",
                                    snap(m0 - 40 * day + 3000, cafe_fp, cafe, (0, 1, 3), [("Νέα συσκευή", 3), ("Σάρωση θυρών", 1)]))],
            "logistiko-nikolaou": [
                visit(m0 - 29 * day, 90, "Μηνιαίος έλεγχος: ενημερώσεις router/NAS, έλεγχος αντιγράφων.", "—", "",
                      snap(m0 - 29 * day + 5400, acc_fp, acc[:4], (0, 0, 2), [("Νέα συσκευή", 2)])),
                visit(t1, 75, "Μηνιαίος έλεγχος. Εγκατάσταση νέου εκτυπωτή δικτύου, δοκιμή επαναφοράς αντιγράφου.", "1× patch cord 2 m",
                      "Να αλλάξει ο κωδικός του Wi‑Fi (ίδιος από το 2022).",
                      snap(t1 + 4500, acc_fp, acc, (0, 1, 2), [("Νέα συσκευή", 2), ("DNS χωρίς κρυπτογράφηση", 1)]))],
            "hotel-aegean": [
                visit(m0 - 27 * day, 180, "Έλεγχος καμερών και NVR, καθαρισμός rack, ενημέρωση UniFi.", "2× RJ45, 1× PoE injector", "",
                      snap(m0 - 27 * day + 10000, hot_fp, hot_prev, (1, 2, 4), [("Νέα συσκευή", 4), ("Άνοιξε θύρα στο router (UPnP)", 2), ("Σάρωση θυρών", 1)])),
                visit(t2, 150, "Μηνιαία συντήρηση: firmware καμερών, έλεγχος εγγραφής 30 ημερών, προσθήκη κάμερας πάρκινγκ (cam-12).",
                      "1× κάμερα IP 4MP, 40 m UTP εξωτερικού χώρου", "Το NVR εκτίθεται με UPnP στη θύρα 8000 — να κλείσει.",
                      snap(t2 + 9000, hot_fp, hot, (1, 3, 5), [("Νέα συσκευή", 3), ("Άνοιξε θύρα στο router (UPnP)", 2), ("Κάμερα εκτεθειμένη", 1),
                                                                      ("Σάρωση θυρών", 3)], {"upnp": {"high": 1, "med": 1, "low": 0}}))],
        }
        if now - t2 > 4 * 3600:  # ανοιχτή επίσκεψη «τώρα» στο ξενοδοχείο, αν δεν πέφτει πάνω στην προηγούμενη
            self.visits["hotel-aegean"].append({"id": f"v{int(now - 2400)}", "start": now - 2400, "end": None, "tech": self.co["tech"], "work": "",
                                               "materials": "", "recs": "", "minutes": 0, "snapshot": None})
        self._demo_fp = dict(hot_fp)
