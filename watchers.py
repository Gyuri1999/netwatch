"""👁 Ποιος σε κοιτάζει; — παθητικός εντοπισμός γνωστών trackers / τηλεμετρίας / ACR (π.χ. έξυπνες TV).

Αμυντικό, ΜΟΝΟ ανάγνωση: παρατηρούμε παθητικά σε ποια γνωστά «σπίτια» καλούν οι συσκευές σου (από το SNI των
TLS συνδέσεων και τα ονόματα DNS) και τα συγκρίνουμε με μια λίστα γνωστών υπηρεσιών παρακολούθησης:
  • ACR  — «Automatic Content Recognition»: η TV αναγνωρίζει τι βλέπεις και το στέλνει για διαφημίσεις.
  • ads  — διαφημιστικά δίκτυα.
  • analytics — τηλεμετρία / ανάλυση συμπεριφοράς.
  • social — κοινωνικά δίκτυα που «ακούν» από άλλες εφαρμογές.
ΔΕΝ μπλοκάρουμε τίποτα — για μπλοκάρισμα παραπέμπουμε στον router / Pi-hole. Εδώ μόνο δείχνουμε και εξηγούμε.
"""
import ipaddress
import threading
import time

# (κατάληξη domain, εταιρεία, κατηγορία) — γνωστές υπηρεσίες tracking/ACR. Η σύγκριση γίνεται τοπικά.
TRACKERS = [
    # ── ACR / smart TV (τι βλέπεις στην τηλεόραση) ──
    ("samba.tv", "Samba TV", "acr"),
    ("samba-tv.com", "Samba TV", "acr"),
    ("alphonso.tv", "LG Ads / Alphonso", "acr"),
    ("ad.lgappstv.com", "LG Ads", "acr"),
    ("lgads.tv", "LG Ads", "acr"),
    ("rdx2.lgtvsdp.com", "LG (ΤV telemetry)", "acr"),
    ("yumenetworks.com", "LG Ads / Yume", "acr"),
    ("samsungacr.com", "Samsung ACR", "acr"),
    ("samsungads.com", "Samsung Ads", "acr"),
    ("samsungrm.net", "Samsung (TV telemetry)", "acr"),
    ("inscapedata.com", "Vizio Inscape", "acr"),
    ("tvinteractive.tv", "Vizio Inscape", "acr"),
    ("imrworldwide.com", "Nielsen", "acr"),
    ("uimserv.net", "Nielsen", "acr"),
    ("gracenote.com", "Gracenote (ACR)", "acr"),
    ("scribe.logs.roku.com", "Roku", "acr"),
    ("ads.roku.com", "Roku Ads", "acr"),
    ("cooper.logs.roku.com", "Roku", "acr"),
    # ── διαφημιστικά δίκτυα ──
    ("doubleclick.net", "Google Ads", "ads"),
    ("googlesyndication.com", "Google Ads", "ads"),
    ("googleadservices.com", "Google Ads", "ads"),
    ("google-analytics.com", "Google Analytics", "analytics"),
    ("googletagmanager.com", "Google Tag Manager", "analytics"),
    ("app-measurement.com", "Google (Firebase)", "analytics"),
    ("admob.com", "Google AdMob", "ads"),
    ("amazon-adsystem.com", "Amazon Ads", "ads"),
    ("adsrvr.org", "The Trade Desk", "ads"),
    ("criteo.com", "Criteo", "ads"),
    ("criteo.net", "Criteo", "ads"),
    ("taboola.com", "Taboola", "ads"),
    ("outbrain.com", "Outbrain", "ads"),
    ("pubmatic.com", "PubMatic", "ads"),
    ("rubiconproject.com", "Magnite / Rubicon", "ads"),
    ("casalemedia.com", "Index Exchange", "ads"),
    ("adnxs.com", "Xandr / AppNexus", "ads"),
    ("moatads.com", "Oracle Moat", "ads"),
    ("serving-sys.com", "Amazon / Sizmek", "ads"),
    # ── τηλεμετρία / ανάλυση ──
    ("scorecardresearch.com", "Comscore", "analytics"),
    ("comscore.com", "Comscore", "analytics"),
    ("demdex.net", "Adobe (Audience)", "analytics"),
    ("omtrdc.net", "Adobe Analytics", "analytics"),
    ("2o7.net", "Adobe Analytics", "analytics"),
    ("mixpanel.com", "Mixpanel", "analytics"),
    ("segment.com", "Segment", "analytics"),
    ("segment.io", "Segment", "analytics"),
    ("amplitude.com", "Amplitude", "analytics"),
    ("branch.io", "Branch", "analytics"),
    ("appsflyer.com", "AppsFlyer", "analytics"),
    ("adjust.com", "Adjust", "analytics"),
    ("crashlytics.com", "Google (Crashlytics)", "analytics"),
    ("bugsnag.com", "Bugsnag", "analytics"),
    ("sentry.io", "Sentry", "analytics"),
    ("flurry.com", "Yahoo Flurry", "analytics"),
    ("kochava.com", "Kochava", "analytics"),
    # ── κοινωνικά δίκτυα (tracking εκτός της εφαρμογής τους) ──
    ("graph.facebook.com", "Meta / Facebook", "social"),
    ("connect.facebook.net", "Meta / Facebook", "social"),
    ("facebook.com", "Meta / Facebook", "social"),
    ("analytics.tiktok.com", "TikTok", "social"),
    ("ads.tiktok.com", "TikTok Ads", "social"),
    ("business-api.tiktok.com", "TikTok", "social"),
]

CATS = {"acr": "ACR — τι βλέπεις στην TV", "ads": "Διαφημίσεις", "analytics": "Τηλεμετρία / ανάλυση",
        "social": "Κοινωνικά δίκτυα"}
CAT_ORDER = {"acr": 0, "ads": 1, "social": 2, "analytics": 3}
MAX_DEV = 256
MAX_PER_DEV = 40

# τι να κάνεις ανά κατασκευαστή TV για να κλείσεις το ACR
ACR_OFF = {
    "LG": "Ρυθμίσεις → Γενικά → «Live Plus» κλειστό, και Ρυθμίσεις → Υποστήριξη → «Συμφωνίες χρήστη» → απενεργοποίησε τη διαφήμιση.",
    "Samsung": "Ρυθμίσεις → Όροι & Πολιτικές → «Viewing Information Services» κλειστό.",
    "Vizio": "Settings → Admin & Privacy → «Viewing Data» off.",
    "Sony/Android": "Ρυθμίσεις → Απόρρητο → Διαφημίσεις → «Εξατομίκευση» off.",
}


def match(domain):
    """→ (εταιρεία, κατηγορία) αν το domain ανήκει σε γνωστό tracker, αλλιώς None."""
    d = str(domain or "").strip().lower().rstrip(".")
    if not d:
        return None
    for suf, comp, cat in TRACKERS:
        if d == suf or d.endswith("." + suf):
            return comp, cat
    return None


def _priv(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback


def _pub(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global


def tv_brand(host):
    """Μάντεψε κατασκευαστή TV από ονόματα/vendor, για στοχευμένη οδηγία ACR."""
    s = " ".join(str(x) for x in (list(host.get("names") or []) + [host.get("vendor") or "", host.get("type") or ""])).lower()
    if "lg" in s or "webos" in s:
        return "LG"
    if "samsung" in s or "tizen" in s:
        return "Samsung"
    if "vizio" in s:
        return "Vizio"
    if "sony" in s or "bravia" in s or "android tv" in s or "google tv" in s:
        return "Sony/Android"
    return None


class Watchers:
    def __init__(self, state, sim=False, clock=time.time):
        self.state, self.sim, self.clock = state, sim, clock
        self.lock = threading.Lock()
        self.hits = {}  # devIP → {company: {"cat","count","last","sample","dst"}}

    # ── παθητική παρατήρηση ──
    def observe(self, P, t=None):
        if self.sim:
            return
        t = t or self.clock()
        src, dst = P.get("src"), P.get("dst")
        dom = P.get("sni") or P.get("http_host")
        if dom and _priv(src) and _pub(dst):  # TLS/HTTP: η συσκευή (src) μίλησε σε δημόσιο προορισμό
            self._hit(src, dom, dst, t)
        if _priv(dst):  # απάντηση DNS προς τη συσκευή (dst): ό,τι ζήτησε
            for name, ip in P.get("dns") or ():
                self._hit(dst, name, ip if _pub(ip) else None, t)

    def _hit(self, dev, domain, dstip, t):
        m = match(domain)
        if not m:
            return
        comp, cat = m
        with self.lock:
            if dev not in self.hits and len(self.hits) >= MAX_DEV:
                return
            d = self.hits.setdefault(dev, {})
            if comp not in d and len(d) >= MAX_PER_DEV:
                return
            e = d.get(comp)
            if e:
                e["count"] += 1
                e["last"] = t
                if dstip:
                    e["dst"] = dstip
            else:
                d[comp] = {"cat": cat, "count": 1, "last": t, "sample": str(domain).lower().rstrip("."), "dst": dstip}

    # ── προβολή ──
    def _devices(self):
        st = self.state
        out = {}
        if st is None:
            return out
        lock = getattr(st, "lock", None)
        try:
            if lock:
                lock.acquire()
            hosts = {h["ip"]: h for h in (getattr(st, "hosts", None) or {}).values() if h.get("kind") == "local"}
        finally:
            if lock:
                lock.release()
        for ip, h in hosts.items():
            try:
                dt = st._dtype(h) if hasattr(st, "_dtype") else {}
            except Exception:  # noqa: BLE001
                dt = {}
            names = sorted(h.get("names") or ())
            out[ip] = {"ip": ip, "name": dt.get("alias") or (names[0] if names else h.get("rdns") or ip),
                       "names": names, "vendor": dt.get("vendor") or "", "type": dt.get("dlabel") or dt.get("dtype") or "",
                       "icon": dt.get("dicon") or "", "dtype": dt.get("dtype") or ""}
        return out

    def _score(self, comps):
        """0–100: περισσότεροι/σοβαρότεροι trackers → χειρότερο σκορ (100 = κανένας)."""
        if not comps:
            return 100
        pts = sum({"acr": 34, "ads": 16, "social": 14, "analytics": 10}.get(c["cat"], 10) for c in comps.values())
        return max(0, 100 - min(100, pts))

    def _device_row(self, ip, comps, devs):
        info = devs.get(ip) or {"ip": ip, "name": ip, "names": [], "type": "", "icon": "", "dtype": "", "vendor": ""}
        items = []
        for comp, e in comps.items():
            items.append({"company": comp, "cat": e["cat"], "cat_label": CATS.get(e["cat"], e["cat"]),
                          "count": e["count"], "last": e["last"], "sample": e["sample"], "dst": e.get("dst"),
                          "country": self._country(e.get("dst"))})
        items.sort(key=lambda x: (CAT_ORDER.get(x["cat"], 9), -x["count"]))
        cats = sorted({i["cat"] for i in items}, key=lambda c: CAT_ORDER.get(c, 9))
        acr = "acr" in cats
        brand = tv_brand(info) if (acr or info.get("dtype") == "tv") else None
        return {**info, "trackers": items, "companies": len(items), "cats": cats, "acr": acr,
                "score": self._score(comps), "brand": brand, "acr_fix": ACR_OFF.get(brand) if brand else None}

    def _country(self, ip):
        if not ip:
            return None
        st = self.state
        g = getattr(st, "demo_geo", None)
        if g and ip in g:
            geo = g[ip][0] if isinstance(g[ip], tuple) else g[ip]
            return (geo or {}).get("country") if isinstance(geo, dict) else None
        cache = getattr(st, "geo_cache", None) or getattr(st, "_geo", None)
        if isinstance(cache, dict) and ip in cache:
            v = cache[ip]
            return (v or {}).get("country") if isinstance(v, dict) else None
        return None

    def view(self):
        if self.sim:
            return self._demo_view()
        devs = self._devices()
        with self.lock:
            snap = {ip: dict((c, dict(e)) for c, e in comps.items()) for ip, comps in self.hits.items() if comps}
        rows = [self._device_row(ip, comps, devs) for ip, comps in snap.items()]
        rows.sort(key=lambda r: (not r["acr"], -r["companies"], r["name"].lower()))
        all_comps = {}
        for r in rows:
            for it in r["trackers"]:
                c = all_comps.setdefault(it["company"], {"cat": it["cat"], "count": 0, "devices": 0})
                c["count"] += it["count"]
                c["devices"] += 1
        top = sorted(({"company": k, **v} for k, v in all_comps.items()), key=lambda x: (CAT_ORDER.get(x["cat"], 9), -x["count"]))
        return {"demo": False, "devices": rows, "companies": len(all_comps), "top": top[:12],
                "acr_devices": sum(1 for r in rows if r["acr"]), "generated": self.clock(),
                "cats": CATS, "note": "Παθητική παρατήρηση SNI/DNS — δεν μπλοκάρουμε τίποτα. Για μπλοκάρισμα: Pi-hole / router."}

    # ── αναφορά HTML (print → PDF) ──
    def report_html(self, lang="el"):
        import html
        import time as _t
        v = self.view()
        en = lang == "en"
        T = (lambda el, e: e if en else el)
        esc = html.escape
        when = _t.strftime("%d/%m/%Y %H:%M", _t.localtime(v.get("generated") or _t.time()))
        badge = {"acr": "#b3261e", "ads": "#8a5a00", "social": "#6a1b9a", "analytics": "#1565c0"}
        rows = []
        for d in v["devices"]:
            trs = "".join(
                f'<tr><td><b>{esc(i["company"])}</b></td><td><span class="b" style="background:{badge.get(i["cat"], "#555")}">'
                f'{esc(i["cat_label"])}</span></td><td>{esc(i["sample"])}</td><td style="text-align:right">{i["count"]}</td>'
                f'<td>{esc(i.get("country") or "—")}</td></tr>' for i in d["trackers"])
            fix = f'<div class="fix">👉 {esc(d["acr_fix"])}</div>' if d.get("acr_fix") else ""
            acr = ' <span class="acr">ACR</span>' if d.get("acr") else ""
            dtype = " · " + esc(d["type"]) if d.get("type") else ""
            rows.append(
                f'<div class="dev"><h2>{esc(d.get("icon") or "")} {esc(d["name"])} '
                f'<span class="ip">{esc(d["ip"])}{dtype}</span>{acr}</h2>'
                f'<div class="score">{T("Ιδιωτικότητα", "Privacy")}: <b>{d["score"]}/100</b> · '
                f'{d["companies"]} {T("υπηρεσίες παρακολούθησης", "tracking services")}</div>'
                f'<table><thead><tr><th>{T("Εταιρεία", "Company")}</th><th>{T("Είδος", "Type")}</th>'
                f'<th>domain</th><th>{T("Φορές", "Count")}</th><th>{T("Χώρα", "Country")}</th></tr></thead>'
                f'<tbody>{trs}</tbody></table>{fix}</div>')
        css = ("body{font:14px -apple-system,Segoe UI,Arial,sans-serif;color:#1b1b1b;max-width:900px;margin:24px auto;padding:0 16px}"
               "h1{font-size:22px;margin:0}h2{font-size:16px;margin:18px 0 6px}.sub{color:#666;margin:2px 0 18px}"
               ".ip{color:#888;font-weight:400;font-size:13px}.acr{background:#b3261e;color:#fff;border-radius:6px;padding:1px 7px;font-size:11px}"
               "table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #e3e3e3;padding:6px 8px;text-align:left}"
               "th{color:#666;font-weight:600}.b{color:#fff;border-radius:6px;padding:1px 7px;font-size:11px;white-space:nowrap}"
               ".score{color:#444;margin-bottom:6px}.dev{break-inside:avoid;margin-bottom:14px}"
               ".fix{background:#fff6e5;border-left:3px solid #d6a000;padding:8px 10px;margin-top:6px;border-radius:0 8px 8px 0}"
               ".note{color:#777;font-size:12px;margin-top:20px;border-top:1px solid #e3e3e3;padding-top:10px}"
               "@media print{body{margin:0}}")
        head = (f'<h1>👁 {T("Ποιος σε κοιτάζει;", "Who is watching you?")}</h1>'
                f'<div class="sub">NetWatch · {when} · {v["companies"]} {T("εταιρείες", "companies")} · '
                f'{v["acr_devices"]} {T("συσκευές με ACR", "devices with ACR")}</div>')
        empty = T("Καμία γνωστή υπηρεσία παρακολούθησης δεν εντοπίστηκε.", "No known tracking service detected.")
        body = head + ("".join(rows) or f'<p>{empty}</p>')
        note_txt = T("Παθητική παρατήρηση (SNI/DNS) — τίποτα δεν μπλοκαρίστηκε. Για μπλοκάρισμα: Pi-hole ή ρυθμίσεις router. "
                     "Για να σταματήσει το ACR, κλείσ' το από τις ρυθμίσεις της τηλεόρασης.",
                     "Passive observation (SNI/DNS) — nothing was blocked. To block: Pi-hole or router settings. "
                     "To stop ACR, turn it off in the TV settings.")
        note = f'<div class="note">{note_txt}</div>'
        return (f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
                f'<meta name="viewport" content="width=device-width, initial-scale=1">'
                f'<title>NetWatch — {T("Ποιος σε κοιτάζει", "Who is watching you")}</title>'
                f'<style>{css}</style></head><body>{body}{note}</body></html>')

    # ── demo ──
    def _demo_view(self):
        now = self.clock()
        rows = [
            {"ip": "192.168.1.58", "name": "LG TV σαλόνι", "names": ["LGwebOSTV.local"], "vendor": "LG Electronics",
             "type": "Smart TV", "icon": "📺", "dtype": "tv", "acr": True, "companies": 4, "score": 8,
             "brand": "LG", "acr_fix": ACR_OFF["LG"], "cats": ["acr", "ads", "analytics"], "trackers": [
                {"company": "LG Ads / Alphonso", "cat": "acr", "cat_label": CATS["acr"], "count": 41, "last": now - 120,
                 "sample": "ad.lgappstv.com", "dst": "23.1.2.3", "country": "United States"},
                {"company": "Samba TV", "cat": "acr", "cat_label": CATS["acr"], "count": 18, "last": now - 300,
                 "sample": "free.samba.tv", "dst": None, "country": None},
                {"company": "Google Ads", "cat": "ads", "cat_label": CATS["ads"], "count": 55, "last": now - 60,
                 "sample": "doubleclick.net", "dst": None, "country": "United States"},
                {"company": "Comscore", "cat": "analytics", "cat_label": CATS["analytics"], "count": 7, "last": now - 900,
                 "sample": "scorecardresearch.com", "dst": None, "country": None}]},
            {"ip": "192.168.1.15", "name": "iPhone", "names": ["iphone.local"], "vendor": "Apple", "type": "Κινητό",
             "icon": "📱", "dtype": "phone", "acr": False, "companies": 2, "score": 74, "brand": None, "acr_fix": None,
             "cats": ["ads", "analytics"], "trackers": [
                {"company": "Google (Firebase)", "cat": "analytics", "cat_label": CATS["analytics"], "count": 23,
                 "last": now - 45, "sample": "app-measurement.com", "dst": None, "country": "United States"},
                {"company": "AppsFlyer", "cat": "analytics", "cat_label": CATS["analytics"], "count": 4, "last": now - 600,
                 "sample": "appsflyer.com", "dst": None, "country": None}]},
        ]
        top = [{"company": "Google Ads", "cat": "ads", "count": 55, "devices": 1},
               {"company": "LG Ads / Alphonso", "cat": "acr", "count": 41, "devices": 1},
               {"company": "Google (Firebase)", "cat": "analytics", "count": 23, "devices": 1},
               {"company": "Samba TV", "cat": "acr", "count": 18, "devices": 1}]
        return {"demo": True, "devices": rows, "companies": 6, "top": top, "acr_devices": 1, "generated": now,
                "cats": CATS, "note": "Demo: παράδειγμα με μια LG TV που «καλεί σπίτι» σε υπηρεσίες ACR."}
