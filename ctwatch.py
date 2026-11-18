"""🔏 Certificate Transparency: ειδοποίηση όταν εκδίδεται νέο πιστοποιητικό για τα δικά σου domains (μέσω crt.sh).

Κάθε πιστοποιητικό TLS που εκδίδεται από δημόσια αρχή γράφεται σε δημόσια logs (CT). Αν εμφανιστεί πιστοποιητικό
για το domain σου που δεν έβγαλες εσύ — ή από εκδότη που δεν χρησιμοποιείς, ή για υποτομέα που δεν ήξερες —
μπορεί να σημαίνει ότι κάποιος έχει πρόσβαση στο DNS ή στον server σου (ή απλώς ότι κάποια υπηρεσία το έβγαλε αυτόματα).

config.yaml:
ct_watch:
  domains: [example.com]
  interval_h: 6                    # κάθε πόσες ώρες ρωτάμε το crt.sh
  expect_issuers: ["Let's Encrypt"] # αν ο εκδότης δεν ταιριάζει με κανένα → σοβαρότητα med
  db: data/ctwatch.json
Ο πρώτος έλεγχος κάθε domain είναι «βάση» (καμία ειδοποίηση)· μετά, κάθε νέο πιστοποιητικό → «Νέο πιστοποιητικό για
το domain σου» (low· med αν ο εκδότης είναι απρόσμενος ή αν εμφανίζεται υποτομέας που δεν είχαμε ξαναδεί).
Στο crt.sh στέλνεται μόνο το όνομα του domain (https://crt.sh/?q=%25.<domain>&output=json).
"""
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request

urlopen = urllib.request.urlopen  # για να αντικαθίσταται στα tests
CRT_URL = "https://crt.sh/?q={q}&output=json"
CERT_LINK = "https://crt.sh/?id={id}"
TIMEOUT = 20
MAX_BODY = 32 * 1024 * 1024
DEFAULT_DB = os.path.join("data", "ctwatch.json")
KEEP_CERTS = 500        # πόσα πιστοποιητικά (τα πιο πρόσφατα) κρατάμε ανά domain για εμφάνιση
RECENT = 20
MAX_ALERTS = 20         # ανά έλεγχο domain
ALERT_TYPE = "Νέο πιστοποιητικό για το domain σου"
ALERT_COOLDOWN = 86400
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def valid_domain(d):
    """Επιστρέφει το domain σε πεζά ή None. Μόνο γράμματα/ψηφία/τελείες/παύλες, χωρίς wildcards, τουλάχιστον μία τελεία."""
    d = str(d or "").strip().lower().rstrip(".")
    if not d or len(d) > 253 or "." not in d or not re.fullmatch(r"[a-z0-9.\-]+", d):
        return None
    if not all(_LABEL.match(p) for p in d.split(".")):
        return None
    return d


def short_issuer(issuer):
    """«C=US, O=Let's Encrypt, CN=R11» → «Let's Encrypt (R11)»."""
    parts = {}
    for p in re.split(r",\s*(?=[A-Za-z]+=)", str(issuer or "")):
        if "=" in p:
            k, v = p.split("=", 1)
            parts.setdefault(k.strip().upper(), v.strip().strip('"'))
    o, cn = parts.get("O"), parts.get("CN")
    if o and cn and cn != o:
        return f"{o} ({cn})"[:120]
    return (o or cn or str(issuer or "?"))[:120]


def issuer_org(issuer):
    m = re.search(r"(?:^|,\s*)O=(\"[^\"]*\"|[^,]+)", str(issuer or ""))
    return (m.group(1).strip().strip('"') if m else short_issuer(issuer))[:120]


def split_names(name_value, common_name=None):
    out = []
    for n in [*(str(name_value or "").split("\n")), str(common_name or "")]:
        n = n.strip().lower().rstrip(".")
        if n and len(n) <= 253 and n not in out and re.fullmatch(r"[a-z0-9.*\-@_]+", n):
            out.append(n)
    return out


def in_domain(name, domain):
    n = name[2:] if name.startswith("*.") else name
    return n == domain or n.endswith("." + domain)


def parse_crtsh(data):
    """JSON του crt.sh → {id: cert} (οι γραμμές με ίδιο id συγχωνεύονται)."""
    if isinstance(data, (bytes, str)):
        data = json.loads(data)
    if not isinstance(data, list):
        raise ValueError("Απρόσμενη απάντηση από το crt.sh")
    certs = {}
    for e in data:
        if not isinstance(e, dict):
            continue
        try:
            cid = int(e.get("id"))
        except (TypeError, ValueError):
            continue
        names = split_names(e.get("name_value"), e.get("common_name"))
        c = certs.get(cid)
        if c is None:
            certs[cid] = {"id": cid, "issuer_name": str(e.get("issuer_name") or "")[:300], "common_name": str(e.get("common_name") or "")[:253],
                          "names": names, "not_before": str(e.get("not_before") or "")[:32], "not_after": str(e.get("not_after") or "")[:32],
                          "entry_timestamp": str(e.get("entry_timestamp") or "")[:32]}
        else:
            c["names"] += [n for n in names if n not in c["names"]]
    return certs


def fetch_crtsh(domain):
    q = urllib.parse.quote("%." + domain, safe="")
    req = urllib.request.Request(CRT_URL.format(q=q), headers={"User-Agent": "NetWatch", "Accept": "application/json"})
    with urlopen(req, timeout=TIMEOUT) as r:
        raw = r.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY:
        raise ValueError("Πολύ μεγάλη απάντηση από το crt.sh")
    return parse_crtsh(raw.decode("utf-8", "replace") or "[]")


# ───────────────────────────── demo ─────────────────────────────

SIM_DOMAIN = "example-homelab.gr"
_SIM_LE = ["C=US, O=Let's Encrypt, CN=R3", "C=US, O=Let's Encrypt, CN=R10", "C=US, O=Let's Encrypt, CN=R11",
           "C=US, O=Let's Encrypt, CN=E5", "C=US, O=Let's Encrypt, CN=E6"]
_SIM_NAMES = [[""], ["www"], ["nas"], ["cloud"], ["vpn"], ["grafana"], ["home"]]


def sim_entries(now=None, extra=False):
    """~12 πιστοποιητικά Let's Encrypt (ανανεώσεις ανά 60 μέρες) και, με extra=True, ένα από απρόσμενο εκδότη για νέο υποτομέα."""
    now = now or time.time()
    out, cid = [], 10_412_000_000
    D = SIM_DOMAIN
    for k in range(12):
        nb = now - (12 - k) * 60 * 86400 + 3 * 3600 * k
        grp = [D, f"www.{D}"] if k % 3 == 0 else [f"*.{D}", D] if k % 3 == 1 else [f"nas.{D}", f"cloud.{D}", f"vpn.{D}"]
        if k >= 9 and k % 3 == 2:
            grp.append(f"grafana.{D}")
        cid += 13_000_000 + 7919 * k
        out.append({"id": cid, "issuer_name": _SIM_LE[min(4, k // 3)], "common_name": grp[0], "name_value": "\n".join(grp),
                    "not_before": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(nb)),
                    "not_after": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(nb + 90 * 86400)),
                    "entry_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000", time.gmtime(nb + 60))})
    if extra:
        nb = now - 5 * 3600
        out.append({"id": cid + 4_200_017, "issuer_name": "C=GB, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA",
                    "common_name": f"mail.{D}", "name_value": f"mail.{D}\nwebmail.{D}",
                    "not_before": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(nb)),
                    "not_after": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(nb + 365 * 86400)),
                    "entry_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000", time.gmtime(nb + 60))})
    return out


# ───────────────────────────── monitor ─────────────────────────────

def normalize(cfg):
    cfg = cfg or {}
    doms, bad = [], []
    for d in cfg.get("domains") or []:
        v = valid_domain(d)
        if v and v not in doms:
            doms.append(v)
        elif not v:
            bad.append(str(d)[:80])
    iss = [str(x).strip() for x in (cfg.get("expect_issuers") or []) if str(x).strip()]
    try:
        ih = float(cfg.get("interval_h") or 6)
    except (TypeError, ValueError):
        ih = 6.0
    return {"domains": doms, "invalid": bad, "expect_issuers": iss, "interval_h": max(1.0, ih),
            "db": cfg.get("db") or DEFAULT_DB, "enabled": bool(cfg.get("enabled", bool(doms)))}


class CtWatch:
    def __init__(self, state=None, cfg=None, sim=False, fetcher=None):
        self.state, self.sim = state, sim
        self.cfg = normalize(cfg)
        if sim:
            self.cfg.update(domains=[SIM_DOMAIN], expect_issuers=["Let's Encrypt"], db=None, invalid=[])
        self.domains, self.expect = self.cfg["domains"], self.cfg["expect_issuers"]
        self.interval = self.cfg["interval_h"] * 3600
        self.path = self.cfg["db"]
        self.lock = threading.Lock()
        self.error = None
        if self.cfg["invalid"]:
            self.error = "Άκυρα domains (χωρίς wildcards, μόνο γράμματα/ψηφία/τελείες/παύλες): " + ", ".join(self.cfg["invalid"])
        self.db = self._load()
        self.derr = {}           # domain → σφάλμα τελευταίου ελέγχου
        self._pending = []       # demo: ειδοποιήσεις που στέλνονται στον πρώτο γύρο
        self._fetch = fetcher or fetch_crtsh
        if sim:
            n = [0]

            def simfetch(_domain):
                n[0] += 1
                return parse_crtsh(sim_entries(extra=n[0] > 1))
            self._fetch = simfetch
            self.check(SIM_DOMAIN, quiet=True)
            self._pending = self.check(SIM_DOMAIN, quiet=True)

    # — αποθήκευση —
    def _load(self):
        if not self.path:
            return {}
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self):
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.db, f, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, self.path)
        except OSError as e:
            self.error = f"Δεν αποθηκεύτηκε το {self.path}: {e.strerror or e}"

    def _expected(self, issuer):
        if not self.expect:
            return True
        low = issuer.lower()
        return any(x.lower() in low for x in self.expect)

    # — έλεγχος —
    def check(self, domain, now=None, quiet=False):
        """Ρωτά το crt.sh για ένα domain. Επιστρέφει λίστα ειδοποιήσεων [(sev, detail, cert)]."""
        now = now or time.time()
        try:
            certs = self._fetch(domain)
        except Exception as e:
            with self.lock:
                self.derr[domain] = (str(e) or e.__class__.__name__)[:160]
                self.db.setdefault(domain, {}).update(last_error=self.derr[domain], last_try=now)
            return []
        events = []
        with self.lock:
            self.derr.pop(domain, None)
            d = self.db.setdefault(domain, {})
            seen = set(d.get("seen") or [])
            known = set(d.get("names") or [])
            stored = {int(k): v for k, v in (d.get("certs") or {}).items()}
            baseline = not d.get("baseline")
            new_ids = sorted(set(certs) - seen)
            for cid in new_ids:
                c = certs[cid]
                mine = [n for n in c["names"] if in_domain(n, domain)]
                fresh = [n for n in mine if n not in known]
                ok_issuer = self._expected(c["issuer_name"])
                rec = {"id": cid, "issuer": c["issuer_name"], "names": c["names"], "not_before": c["not_before"],
                       "not_after": c["not_after"], "entry": c["entry_timestamp"], "new": not baseline,
                       "unexpected_issuer": not ok_issuer, "new_names": [] if baseline else fresh}
                stored[cid] = rec
                if not baseline:
                    reasons = []
                    if not ok_issuer:
                        reasons.append(f"απρόσμενος εκδότης (περίμενα: {', '.join(self.expect)})")
                    if fresh:
                        reasons.append("νέος υποτομέας: " + ", ".join(fresh[:5]))
                    sev = "med" if reasons else "low"
                    detail = (f"Εκδόθηκε νέο πιστοποιητικό για «{domain}» από «{short_issuer(c['issuer_name'])}» "
                              f"για {', '.join(c['names'][:6])}{'…' if len(c['names']) > 6 else ''} "
                              f"(ισχύει από {c['not_before'][:10]} έως {c['not_after'][:10]}). "
                              + (("Προσοχή: " + "· ".join(reasons) + ". ") if reasons else "")
                              + "Αν δεν το έβγαλες εσύ ή κάποια υπηρεσία σου, έλεγξε ποιος έχει πρόσβαση στο DNS/στον server σου. "
                              + CERT_LINK.format(id=cid))
                    events.append((sev, detail, rec))
                known.update(mine)
            seen |= set(certs)
            if len(stored) > KEEP_CERTS:
                stored = dict(sorted(stored.items())[-KEEP_CERTS:])
            iss = dict(d.get("issuers") or {})
            for cid in new_ids:
                o = issuer_org(certs[cid]["issuer_name"])
                iss[o] = iss.get(o, 0) + 1
            d.update(seen=sorted(seen), names=sorted(known), certs={str(k): v for k, v in stored.items()}, issuers=iss,
                     baseline=True, last_check=now, last_error=None)
            self._save()
        if not quiet:
            self._alert(domain, events[:MAX_ALERTS], now)
        return events

    def _alert(self, domain, events, now):
        if self.state is None:
            return
        for sev, detail, rec in events:
            try:
                self.state.alert(ALERT_TYPE, sev, domain, ", ".join(rec["names"][:3]), detail, now,
                                 key=(ALERT_TYPE, domain, rec["id"]), cooldown=ALERT_COOLDOWN, mark=False)
            except Exception:
                pass

    def round(self, now=None, force=True):
        """Ελέγχει όλα τα domains (force=False: μόνο όσα δεν ελέγχθηκαν μέσα στο τελευταίο interval, π.χ. μετά από restart)."""
        out, first = {}, True
        for dom in self.domains:
            d = self.db.get(dom) or {}
            lc, lt = d.get("last_check") or 0, d.get("last_try") or 0
            due = lc + self.interval
            if lt > lc:  # ο τελευταίος έλεγχος απέτυχε: ξανά σε 30′ (όχι νωρίτερα από το κανονικό αν υπάρχει βάση)
                due = max(due, lt + 1800) if lc else lt + 1800
            if not force and (now or time.time()) < due:
                continue
            if not first and not self.sim:
                time.sleep(2)  # ευγένεια προς το crt.sh
            first = False
            out[dom] = self.check(dom, now)
        return out

    # — για το UI —
    def status(self):
        with self.lock:
            doms = []
            for dom in self.domains:
                d = self.db.get(dom) or {}
                certs = sorted((d.get("certs") or {}).values(), key=lambda c: c["id"], reverse=True)
                recent = [{"id": c["id"], "issuer": short_issuer(c["issuer"]), "issuer_name": c["issuer"], "names": list(c["names"]),
                           "not_before": c["not_before"], "not_after": c["not_after"], "new": bool(c.get("new")),
                           "unexpected_issuer": bool(c.get("unexpected_issuer")), "new_names": list(c.get("new_names") or []),
                           "link": CERT_LINK.format(id=c["id"])} for c in certs[:RECENT]]
                subs = sorted({n[2:] if n.startswith("*.") else n for n in d.get("names") or [] if in_domain(n, dom)})
                doms.append({"domain": dom, "total": len(d.get("seen") or []), "last_check": d.get("last_check"),
                             "error": self.derr.get(dom) or d.get("last_error"), "baseline": bool(d.get("baseline")),
                             "recent": recent, "issuers": dict(d.get("issuers") or {}), "subdomains": subs,
                             "flagged": sum(1 for c in certs if c.get("new") and (c.get("unexpected_issuer") or c.get("new_names")))})
            return {"enabled": bool(self.cfg["enabled"]) or self.sim, "demo": self.sim, "error": self.error,
                    "interval_h": self.cfg["interval_h"], "expect_issuers": list(self.expect), "domains": doms}

    def run_forever(self):
        while True:
            if self.sim:
                if self._pending:
                    self._alert(SIM_DOMAIN, self._pending, time.time())
                    self._pending = []
                time.sleep(3600)
                continue
            if self.cfg["enabled"] and self.domains:
                try:
                    self.round(force=False)
                except Exception as e:
                    self.error = (str(e) or e.__class__.__name__)[:160]
            time.sleep(min(self.interval, 600))
