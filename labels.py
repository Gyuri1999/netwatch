"""🏷 Ετικέτες & QR — φύλλα ετικετών για συσκευές, πρίζες, patch panel και καλώδια, έτοιμα για εκτύπωση.

Πηγές για ένα σετ ετικετών:
  • οι συσκευές που ξέρει το NetWatch (state.hosts, με τα ονόματα που έδωσες),
  • το IPAM (όνομα, τοποθεσία, VLAN) αν υπάρχει,
  • τα σημεία μιας εργασίας αποδοχής (accept.py),
  • ελεύθερη αρίθμηση: «PP1-01..PP1-24» ή καλώδια με δύο άκρα «A-01 ⇄ SW1/12».
Κάθε ετικέτα έχει 1–3 σύντομες γραμμές (διαλέγεις πεδία) και προαιρετικά QR: σκέτο κείμενο, IP, ή URL από πρότυπο
(προεπιλογή `http://<IP του NetWatch>:<θύρα>/#dev=<ip>`).
Έξοδος: αυτόνομη σελίδα HTML με ΑΚΡΙΒΕΙΣ διαστάσεις σε mm και `@page`, ώστε στο 100% (χωρίς «προσαρμογή στη σελίδα»)
να πέφτει πάνω στις ετικέτες: φύλλα A4 (3×8 70×37 mm, 3×7 63,5×38,1 mm, 5×13 38,1×21,2 mm) και ταινίες εκτυπωτών
ετικετών (Brother 12/24 mm, ρολό DK 62 mm, «σημαίες» καλωδίων που γράφουν το κείμενο δύο φορές).
Το QR είναι ενσωματωμένο SVG (qr.py) — καμία εξωτερική βιβλιοθήκη, κανένα script στη σελίδα.
"""
import ipaddress
import os
import re
import threading
import time
import urllib.parse

import sites as S
from sites import L, clean, esc

SET_RE = re.compile(r"^l[0-9a-z-]{1,30}$")
MAX_ITEMS = 1000
MAX_SETS = 200
A4 = (210.0, 297.0)
# kind: sheet (φύλλο A4, πλέγμα) · tape (μία ετικέτα ανά «σελίδα» ταινίας) · flag (σημαία καλωδίου: κείμενο ×2)
PRESETS = {
    "a4-24": dict(kind="sheet", cols=3, rows=8, w=70.0, h=37.0, left=0.0, top=0.5, gx=0.0, gy=0.0,
                  el="A4 · 24 ετικέτες 70×37 mm (3×8)", en="A4 · 24 labels 70×37 mm (3×8)"),
    "a4-21": dict(kind="sheet", cols=3, rows=7, w=63.5, h=38.1, left=7.25, top=15.15, gx=2.5, gy=0.0,
                  el="A4 · 21 ετικέτες 63,5×38,1 mm (3×7)", en="A4 · 21 labels 63.5×38.1 mm (3×7)"),
    "a4-65": dict(kind="sheet", cols=5, rows=13, w=38.1, h=21.2, left=4.75, top=10.7, gx=2.5, gy=0.0,
                  el="A4 · 65 ετικέτες 38,1×21,2 mm (5×13)", en="A4 · 65 labels 38.1×21.2 mm (5×13)"),
    "tape-12": dict(kind="tape", w=45.0, h=12.0, el="Ταινία 12 mm (Brother TZe) · 45 mm", en="12 mm tape (Brother TZe) · 45 mm"),
    "tape-24": dict(kind="tape", w=60.0, h=24.0, el="Ταινία 24 mm (Brother TZe) · 60 mm", en="24 mm tape (Brother TZe) · 60 mm"),
    "dk-62": dict(kind="tape", w=62.0, h=29.0, el="Ρολό 62 mm (Brother DK) · 62×29 mm", en="62 mm roll (Brother DK) · 62×29 mm"),
    "flag-12": dict(kind="flag", w=80.0, h=12.0, el="Σημαία καλωδίου · ταινία 12 mm (κείμενο ×2)", en="Cable flag · 12 mm tape (text ×2)"),
    "flag-24": dict(kind="flag", w=90.0, h=24.0, el="Σημαία καλωδίου · ταινία 24 mm (κείμενο ×2)", en="Cable flag · 24 mm tape (text ×2)"),
}
FIELDS = {"name": ("Όνομα", "Name"), "ip": ("IP", "IP"), "mac": ("MAC", "MAC"), "location": ("Τοποθεσία", "Location"),
          "vlan": ("VLAN", "VLAN"), "vendor": ("Κατασκευαστής", "Vendor"), "type": ("Τύπος", "Type"),
          "cable": ("Καλώδιο A ⇄ B", "Cable A ⇄ B")}
QR_MODES = ("none", "id", "ip", "url")
ITEM_KEYS = (("name", 40), ("ip", 45), ("mac", 17), ("location", 40), ("vlan", 12), ("vendor", 32), ("type", 24), ("b", 40))


def clean_item(d):
    d = d if isinstance(d, dict) else {"name": d}
    it = {k: clean(d.get(k), n).replace("\n", " ") for k, n in ITEM_KEYS}
    return {k: v for k, v in it.items() if v} if any(it.values()) else None


def lines_for(item, fields):
    out = []
    for f in fields[:3]:
        v = (f"{item.get('name', '')} ⇄ {item['b']}" if item.get("b") else item.get("name", "")) if f == "cable" \
            else (f"VLAN {item['vlan']}" if f == "vlan" and item.get("vlan") else item.get(f, ""))
        if v:
            out.append(v)
    return out or ([item["name"]] if item.get("name") else [])


def qr_text(item, mode, tpl):
    """Τι γράφει το QR μιας ετικέτας ("" → χωρίς QR)."""
    ident = item.get("name") or item.get("ip") or item.get("mac") or ""
    if mode == "id":
        return (f"{ident} <> {item['b']}" if item.get("b") else ident)[:200]
    if mode == "ip":
        return (item.get("ip") or ident)[:200]
    if mode == "url":
        if not tpl or ("{ip}" in tpl and not item.get("ip")) or ("{mac}" in tpl and not item.get("mac")):
            return ident[:200]  # χωρίς IP δεν βγαίνει σύνδεσμος — τουλάχιστον το όνομα
        q = urllib.parse.quote
        return (tpl.replace("{ip}", q(item.get("ip", ""), safe=".:")).replace("{mac}", q(item.get("mac", ""), safe=""))
                .replace("{name}", q(item.get("name", ""), safe="")).replace("{id}", q(ident, safe="")))[:300]
    return ""


def tpl_ok(tpl):
    return bool(re.match(r"^https?://[^\s<>\"']{1,200}$", str(tpl or "")))


def _mm(v):
    return f"{v:.2f}".rstrip("0").rstrip(".")


def sheet_html(items, preset="a4-24", fields=("name",), qr="none", tpl="", offset=0, length=None, lang="el", title="", demo=False,
               qr_svg=None):
    """Η σελίδα εκτύπωσης. Κάθε ετικέτα είναι `<div class="lb">`· κενές θέσεις (offset) είναι `<div class="sk">`."""
    lang = "en" if lang == "en" else "el"
    P = PRESETS.get(preset) or PRESETS["a4-24"]
    kind, w, h = P["kind"], P["w"], P["h"]
    if kind != "sheet" and length:
        try:
            w = max(20.0, min(float(length), 300.0))
        except (TypeError, ValueError):
            pass
    if qr_svg is None:
        import qr as _qr
        qr_svg = lambda t: _qr.svg(t, scale=1, border=3)  # noqa: E731
    cache = {}

    def qsvg(text):
        if text not in cache:
            try:
                cache[text] = qr_svg(text)
            except Exception:  # noqa: BLE001 — κείμενο που δεν χωράει σε QR: ετικέτα χωρίς QR
                cache[text] = ""
        return cache[text]

    pad = 1.0 if h <= 14 else 1.6
    qs = max(6.0, min(h - 2 * pad, w * 0.42 if kind != "flag" else h - 2 * pad))

    def face(item, fw):
        ls = lines_for(item, list(fields)) or [""]
        qt = qr_text(item, qr, tpl) if qr != "none" else ""
        svg = qsvg(qt) if qt else ""
        aw = fw - 2 * pad - ((qs + 1) if svg else 0)
        fs = max(1.3, min((h - 2 * pad) / (len(ls) * 1.22), aw / (max(len(x) for x in ls) * 0.56 or 1), 5.5))
        txt = "".join(f'<div class="{"l1" if i == 0 else "l2"}">{esc(x)}</div>' for i, x in enumerate(ls))
        return (f'<div class="q">{svg}</div>' if svg else "") + f'<div class="t" style="font-size:{_mm(fs)}mm">{txt}</div>'

    def label(item):
        if kind == "flag":
            gap = 18.0 if h <= 14 else 24.0
            half = (w - gap) / 2
            f = face(item, half)
            return (f'<div class="lb flag"><div class="hf" style="width:{_mm(half)}mm">{f}</div><div class="wr" style="width:{_mm(gap)}mm"></div>'
                    f'<div class="hf" style="width:{_mm(half)}mm">{f}</div></div>')
        return f'<div class="lb">{face(item, w)}</div>'

    items = [it for it in (clean_item(x) for x in items[:MAX_ITEMS]) if it]
    if kind == "sheet":
        pw, ph = A4
        per = P["cols"] * P["rows"]
        try:
            offset = max(0, min(int(offset or 0), per - 1))
        except (TypeError, ValueError):
            offset = 0
        cells = ['<div class="sk"></div>'] * offset + [label(it) for it in items]
        body = "".join(f'<section class="pg">{"".join(cells[i:i + per])}</section>' for i in range(0, max(len(cells), 1), per))
        layout = (f".pg{{width:{_mm(pw)}mm;padding:{_mm(P['top'])}mm 0 0 {_mm(P['left'])}mm;display:grid;grid-template-columns:repeat({P['cols']},{_mm(w)}mm);"
                  f"grid-auto-rows:{_mm(h)}mm;column-gap:{_mm(P['gx'])}mm;row-gap:{_mm(P['gy'])}mm;break-after:page;overflow:hidden}}.pg:last-child{{break-after:auto}}")
    else:
        pw, ph, offset = w, h, 0
        body = "".join(label(it) for it in items)
        layout = ".lb{break-after:page}.lb:last-child{break-after:auto}"
    hint = L(lang, f"🖨 Ctrl+P (Mac: ⌘P) → κλίμακα <b>100%</b> / «Πραγματικό μέγεθος», περιθώρια <b>Κανένα</b>, χαρτί <b>{_mm(pw)}×{_mm(ph)} mm</b>. "
             f"Τύπωσε πρώτα μία σελίδα σε απλό χαρτί και βάλ' τη πάνω στο φύλλο ετικετών κόντρα στο φως. Αυτό το πλαίσιο δεν τυπώνεται.",
             f"🖨 Ctrl+P (Mac: ⌘P) → scale <b>100%</b> / “Actual size”, margins <b>None</b>, paper <b>{_mm(pw)}×{_mm(ph)} mm</b>. "
             f"Print one page on plain paper first and hold it against the label sheet. This box is not printed.")
    css = (f"@page{{size:{_mm(pw)}mm {_mm(ph)}mm;margin:0}}*{{box-sizing:border-box}}html,body{{margin:0;padding:0;background:#fff;color:#000;"
           f"font-family:Arial,Helvetica,'Liberation Sans',sans-serif}}"
           f".hint{{font:13px/1.45 sans-serif;background:#eef6ff;border:1px solid #bcd7f5;border-radius:8px;padding:8px 12px;margin:10px;max-width:190mm}}"
           f".demo{{font:12px sans-serif;background:#fff4d6;border:1px solid #f0d27a;border-radius:8px;padding:6px 10px;margin:10px;max-width:190mm}}"
           f"{layout}.lb,.sk{{width:{_mm(w)}mm;height:{_mm(h)}mm;overflow:hidden}}"
           f".lb{{display:flex;align-items:center;gap:1mm;padding:{_mm(pad)}mm}}.lb.flag{{padding:0;gap:0}}"
           f".hf{{height:100%;display:flex;align-items:center;gap:1mm;padding:{_mm(pad)}mm;overflow:hidden}}.wr{{height:100%;border-left:.2mm dashed #999;border-right:.2mm dashed #999}}"
           f".q{{flex:none;width:{_mm(qs)}mm;height:{_mm(qs)}mm}}.q svg{{width:100%;height:100%;display:block}}"
           f".t{{flex:1;min-width:0;line-height:1.2;white-space:nowrap;overflow:hidden}}.l1{{font-weight:700}}.l2{{font-size:.86em}}"
           f"@media screen{{body{{background:#e9edf2}}.pg{{background:#fff;margin:10px auto;min-height:{_mm(ph)}mm;box-shadow:0 1px 6px rgba(0,0,0,.25)}}"
           f".lb{{outline:.2mm dotted #9aa5b1;background:#fff}}.sk{{outline:.2mm dotted #d3d9e0}}{'.lb{margin:6px 10px}' if kind != 'sheet' else ''}}}"
           f"@media print{{.hint,.demo{{display:none}}}}")
    return (f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><title>{esc(title or L(lang, "Ετικέτες", "Labels"))}</title><style>{css}</style></head><body>'
            f'<div class="hint">{hint} · <b>{len(items)}</b> {L(lang, "ετικέτες", "labels")}</div>'
            + (f'<div class="demo">🧪 {L(lang, "Δείγμα (demo).", "Sample (demo).")}</div>' if demo else "") + body + "</body></html>")


def _err(el, en=None, code=400):
    return code, {"error": el, "error_en": en or el}


class Labels:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time, sites=None):
        self.state, self.demo, self.clock = state, demo, clock
        self.data_dir, self.sites = data_dir, sites
        self.on_save = None
        self.lock = threading.RLock()
        self.sets = {}
        self._n = 0
        if demo:
            self._seed_demo()
        else:
            self._load()

    # ── αποθήκευση (ίδιο σχήμα με accept.py: labels.json στον φάκελο του πελάτη, αλλιώς στο data_dir) ──
    def _dir(self, site):
        d = self.sites.site_dir(site) if self.sites is not None and site else None
        return d or self.data_dir

    def _load(self):
        dirs = [self.data_dir] if self.data_dir else []
        if self.sites is not None:
            dirs += [d for d in (self.sites.site_dir(sid) for sid in self.sites.ids()) if d]
        for d in dirs:
            j = S.read_json(os.path.join(d, "labels.json"))
            for lid, s in ((j or {}).get("sets") or {}).items() if isinstance(j, dict) and isinstance(j.get("sets"), dict) else ():
                if isinstance(lid, str) and SET_RE.match(lid) and isinstance(s, dict) and len(self.sets) < MAX_SETS:
                    self.sets[lid] = self._norm(s, lid)

    def _save(self, site):
        d = self._dir(site)
        if d:
            S.write_json(os.path.join(d, "labels.json"), {"sets": {k: v for k, v in self.sets.items() if self._dir(v.get("site")) == d}}, self.on_save)

    # ── προεπιλεγμένο URL για το QR ──
    def url_default(self):
        st = self.state
        host = ""
        for ip in sorted(str(x) for x in (getattr(st, "me", None) or ())) if st is not None else ():
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if a.version == 4 and a.is_private and not a.is_loopback and not a.is_link_local:
                host = ip
                break
        try:
            port = int(getattr(st, "port", None) or 8765)
        except (TypeError, ValueError):
            port = 8765
        return f"http://{host or 'netwatch.local'}:{port}/#dev={{ip}}"

    def _norm(self, d, lid):
        site = d.get("site") if isinstance(d.get("site"), str) and S.SLUG_RE.match(d.get("site")) else ""
        fields = [f for f in (d.get("fields") if isinstance(d.get("fields"), list) else []) if f in FIELDS][:3] or ["name"]
        tpl = str(d.get("url_tpl") or "").strip()
        try:
            off = max(0, min(int(d.get("offset") or 0), 64))
        except (TypeError, ValueError):
            off = 0
        try:
            ln = max(20.0, min(float(d.get("len")), 300.0)) if d.get("len") else None
        except (TypeError, ValueError):
            ln = None
        items = [it for it in (clean_item(x) for x in (d.get("items") if isinstance(d.get("items"), list) else [])[:MAX_ITEMS]) if it]
        return {"id": lid, "site": site, "name": clean(d.get("name"), 80).replace("\n", " ") or "Ετικέτες", "preset": d.get("preset") if d.get("preset") in PRESETS else "a4-24",
                "fields": fields, "qr": d.get("qr") if d.get("qr") in QR_MODES else "none", "url_tpl": tpl if tpl_ok(tpl) else "", "offset": off, "len": ln,
                "items": items, "t": float(d.get("t") or self.clock())}

    # ── πηγές ──
    def _ipam_notes(self):
        try:
            return self.state.ipam.notes.all() or {}
        except Exception:  # noqa: BLE001 — χωρίς IPAM απλώς δεν έχουμε τοποθεσίες
            return {}

    def build(self, d):
        """Φτιάχνει τις γραμμές ενός σετ από μια πηγή → (items, σφάλμα). Δεν αποθηκεύει τίποτα."""
        src = d.get("source") or "pattern"
        dtypes = d.get("dtypes")
        dtypes = set(x for x in (dtypes.split(",") if isinstance(dtypes, str) else dtypes or []) if x) or None
        try:
            if src == "pattern":
                return [{"name": x} for x in S.expand(d.get("pattern"), MAX_ITEMS)], None
            if src == "cables":
                a = S.expand(d.get("pattern"), MAX_ITEMS)
                b = S.expand(d.get("pattern_b"), MAX_ITEMS) if str(d.get("pattern_b") or "").strip() else []
                if b and len(a) != len(b):
                    return None, f"Τα δύο άκρα δεν έχουν ίδιο πλήθος ({len(a)} και {len(b)})"
                return [dict({"name": x}, **({"b": b[i]} if b else {})) for i, x in enumerate(a)], None
        except ValueError as e:
            return None, str(e)
        if src == "devices":
            notes = self._ipam_notes()
            out = []
            for dv in S.devices(self.state, MAX_ITEMS):
                if dtypes and dv["dtype"] not in dtypes:
                    continue
                n = notes.get(dv["mac"]) or notes.get(dv["ip"]) or {}
                out.append({"name": n.get("name") or dv["name"] or dv["ip"], "ip": dv["ip"], "mac": dv["mac"], "vendor": dv["vendor"], "type": dv["type"],
                            "location": n.get("location", "")})
            return [x for x in (clean_item(i) for i in out) if x], None
        if src == "ipam":
            ip_ = getattr(self.state, "ipam", None) if self.state is not None else None
            if ip_ is None:
                return None, "Το IPAM δεν είναι διαθέσιμο"
            try:
                import ipam
                hosts = [{"ip": dv["ip"], "mac": dv["mac"], "names": [dv["name"]] if dv["name"] else [], "vendor": dv["vendor"], "dlabel": dv["type"],
                          "last": self.clock()} for dv in S.devices(self.state, MAX_ITEMS) if ":" not in dv["ip"]]
                rows = ipam.inventory(getattr(ip_, "cfg", None), hosts, ip_.leases() if hasattr(ip_, "leases") else (), self._ipam_notes(), self.clock())
            except Exception as e:  # noqa: BLE001
                return None, "Το IPAM δεν απάντησε: " + str(e)[:100]
            return [x for x in (clean_item({"name": r.get("name") or r.get("ip"), "ip": r.get("ip"), "mac": r.get("mac"), "vendor": r.get("vendor"),
                                            "type": r.get("type"), "location": r.get("location"), "vlan": "" if r.get("vlan") is None else r.get("vlan")})
                                for r in rows[:MAX_ITEMS]) if x], None
        if src == "accept":
            acc = getattr(self.state, "accept", None) if self.state is not None else None
            j = acc.job_view(d.get("job")) if acc is not None and hasattr(acc, "job_view") else None
            if not j:
                return None, "Δεν βρέθηκε η εργασία αποδοχής"
            tnames = {t["id"]: t["el"] for t in (acc.view().get("types") or [])}
            return [x for x in (clean_item({"name": p.get("label"), "ip": p.get("ip"), "location": p.get("location"), "type": tnames.get(p.get("type"), "")})
                                for p in j.get("points") or []) if x], None
        return None, "Άγνωστη πηγή"

    # ── σετ ──
    def save_set(self, d):
        with self.lock:
            lid = d.get("id")
            old = self.sets.get(lid) if isinstance(lid, str) else None
            if lid and not old:
                return None, "Άγνωστο σετ ετικετών"
            if d.get("url_tpl") and not tpl_ok(d.get("url_tpl")):
                return None, "Το πρότυπο URL πρέπει να ξεκινά με http:// ή https:// και να μην έχει κενά"
            site = d.get("site") if "site" in d else (old or {}).get("site") if old else (self.sites.detect() if self.sites is not None else "")
            if site and (self.sites is None or not self.sites.get(site)):
                return None, "Άγνωστος πελάτης"
            if not old:
                if len(self.sets) >= MAX_SETS:
                    return None, "Πάρα πολλά σετ — σβήσε παλιά"
                self._n += 1
                lid = f"l{int(self.clock()):x}-{self._n}"
                while lid in self.sets:
                    self._n += 1
                    lid = f"l{int(self.clock()):x}-{self._n}"
            merged = dict(old or {})
            merged.update(d)
            merged.update(site=site or "", t=self.clock())
            new = self._norm(merged, lid)
            if not new["items"]:
                return None, "Το σετ δεν έχει καμία ετικέτα"
            self.sets[lid] = new
            self._save(new["site"])
            if old and old["site"] != new["site"]:
                self._save(old["site"])
            return new, None

    def delete_set(self, lid):
        with self.lock:
            s = self.sets.pop(lid, None) if isinstance(lid, str) else None
            if s:
                self._save(s["site"])
            return bool(s)

    def sheet(self, s, lang="el"):
        P = PRESETS[s["preset"]]
        fields = s["fields"]
        if P["kind"] == "flag" and fields == ["name"] and any(i.get("b") for i in s["items"]):
            fields = ["cable"]
        return sheet_html(s["items"], s["preset"], fields, s["qr"], s["url_tpl"] or self.url_default(), s["offset"], s["len"], lang, s["name"], self.demo)

    # ── προβολή ──
    def view(self):
        with self.lock:
            sets = [dict({k: s[k] for k in ("id", "site", "name", "preset", "fields", "qr", "offset", "t")}, count=len(s["items"]),
                         site_name=((self.sites.get(s["site"]) or {}).get("name", "") if self.sites is not None and s["site"] else ""))
                    for s in sorted(self.sets.values(), key=lambda x: -x["t"])]
        acc = getattr(self.state, "accept", None) if self.state is not None else None
        try:
            jobs = [{"id": j["id"], "title": j["title"], "points": j["total_points"]} for j in acc.view().get("jobs", [])][:50] if acc is not None else []
        except Exception:  # noqa: BLE001
            jobs = []
        devs = S.devices(self.state, MAX_ITEMS)
        dts = {}
        for dv in devs:
            if dv["dtype"]:
                dts[dv["dtype"]] = dts.get(dv["dtype"], 0) + 1
        return {"demo": self.demo, "sets": sets,
                "presets": [{"id": k, "kind": p["kind"], "w": p["w"], "h": p["h"], "per": p["cols"] * p["rows"] if p["kind"] == "sheet" else 1, "el": p["el"], "en": p["en"]}
                            for k, p in PRESETS.items()],
                "fields": [{"id": k, "el": v[0], "en": v[1]} for k, v in FIELDS.items()], "url_default": self.url_default(),
                "site": self.sites.detect() if self.sites is not None else None,
                "sites": [{"id": sid, "name": (self.sites.get(sid) or {}).get("name", sid)} for sid in self.sites.ids()] if self.sites is not None else [],
                "sources": {"devices": len(devs), "dtypes": dts, "ipam": getattr(self.state, "ipam", None) is not None if self.state is not None else False, "jobs": jobs},
                "counts": {"sets": len(sets), "labels": sum(s["count"] for s in sets)}}

    # ── API ──
    def api(self, method, sub, q, body):
        q, body = q or {}, body if isinstance(body, dict) else {}
        if method == "GET":
            if sub == "":
                return 200, self.view()
            if sub == "set":
                s = self.sets.get(q.get("id"))
                return (200, dict(s)) if s else (404, {"error": "not found"})
            if sub == "sheet":
                if q.get("id"):
                    s = self.sets.get(q["id"])
                    if not s:
                        return 404, {"error": "not found"}
                    s = dict(s)
                else:  # γρήγορη εκτύπωση χωρίς αποθήκευση: ?source=pattern&pattern=PP1-01..PP1-24&preset=a4-65&qr=id
                    items, err = self.build(q)
                    if err:
                        return _err(err)
                    s = self._norm({"name": q.get("name") or q.get("pattern") or "", "items": items, "fields": (q.get("fields") or "name").split(",")}, "ltmp")
                over = {k: q[k] for k in ("preset", "qr", "offset", "len", "url_tpl") if q.get(k) not in (None, "")}
                if "fields" in q and q.get("id"):
                    over["fields"] = q["fields"].split(",")
                if over:
                    s = self._norm(dict(s, **over), s["id"])
                return S.raw(self.sheet(s, q.get("lang")), f"netwatch-labels-{s['id']}.html")
            return 404, {"error": "not found"}
        if method != "POST":
            return 404, {"error": "not found"}
        if sub == "build":
            items, err = self.build(body)
            return _err(err) if err else (200, {"items": items, "count": len(items)})
        if sub == "save":
            s, err = self.save_set(body)
            return _err(err) if err else (200, dict(self.view(), saved=s["id"]))
        if sub == "delete":
            return (200, self.view()) if self.delete_set(body.get("id")) else (404, {"error": "not found"})
        return 404, {"error": "not found"}

    # ── demo ──
    def _seed_demo(self):
        now = self.clock()
        site = "hotel-aegean" if self.sites is not None and self.sites.get("hotel-aegean") else ""
        cams = [{"name": f"cam-{i:02d}", "ip": f"10.20.0.{100 + i}", "mac": f"bc:ba:c2:20:01:{i:02x}", "location": "Πάρκινγκ" if i == 12 else "Πτέρυγα Β" if i > 8 else "Πτέρυγα Α",
                 "vlan": "30", "type": "Κάμερα"} for i in range(1, 13)]
        for lid, name, preset, fields, qr, items, age in (
                ("ldemo-1", "Κάμερες — ετικέτες με QR", "a4-24", ["name", "ip", "location"], "url", cams, 7 * 86400),
                ("ldemo-2", "Patch panel PP1 (24 θύρες)", "a4-65", ["name"], "none", [{"name": x} for x in S.expand("PP1-01..PP1-24")], 7 * 86400),
                ("ldemo-3", "Καλώδια rack Β — σημαίες", "flag-12", ["cable"], "none",
                 [{"name": a, "b": b} for a, b in zip(S.expand("B-01..B-08"), S.expand("SW2/01..SW2/08"))], 3600)):
            self.sets[lid] = self._norm({"site": site, "name": name, "preset": preset, "fields": fields, "qr": qr, "items": items, "t": now - age}, lid)
