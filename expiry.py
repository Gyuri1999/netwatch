"""⏳ Υπενθυμίσεις λήξης: πιστοποιητικά, domains, άδειες, εγγυήσεις, συμβόλαια, firmware.

Αυτόματα (χωρίς νέες συνδέσεις): ό,τι ήδη ξέρουν
  • ο έλεγχος TLS (tlsaudit: ημερομηνία λήξης του πιστοποιητικού κάθε θύρας),
  • οι έλεγχοι διαθεσιμότητας (health: cert_days των στόχων με tls),
  • η παρακολούθηση Certificate Transparency (ctwatch: το νεότερο πιστοποιητικό κάθε domain).
Με ρητή ρύθμιση στο config.yaml:
  expiry:
    certs: ["192.168.1.17:443", "nas.home.lan:5001"]    # ελέγχεται με health.cert_days (κάθε 12 ώρες)
    domains: ["example.gr"]                              # RDAP (https://rdap.org), μία φορά τη μέρα, με cache
    items:
      - {name: "Cisco SmartNet", date: 2027-03-01, kind: contract, note: "αρ. συμβολαίου 1234"}
Και χειροκίνητα από το UI (αποθηκεύονται στο data/expiry.json).

Κατάσταση: expired (< 0 μέρες), urgent (≤ 7), soon (≤ 30), ok. Ειδοποίηση «Λήξη πλησιάζει» μία φορά σε κάθε
όριο: 30 (low), 7 (med), 1 (high) και 0 μέρες (high). Στο demo: ~9 ρεαλιστικά στοιχεία, ποτέ δίκτυο.

API
---
Expiry(state, cfg=None, sim=False, path=None, clock=time.time)
  .view()                       → {items:[{id, name, kind, source, expires, date, days_left, status, detail, host}], counts, demo}
  .add(name, kind, date, note)  → item | {error}
  .delete(id)                   → {ok} | {error}
  .refresh()                    → {ok}
"""
import calendar
import datetime
import hashlib
import json
import os
import re
import secrets
import ssl
import threading
import time
import urllib.request

KINDS = ("license", "warranty", "contract", "firmware", "domain", "cert", "other")
ALERT = "Λήξη πλησιάζει"
THRESHOLDS = ((0, "high"), (1, "high"), (7, "med"), (30, "low"))   # από το αυστηρότερο
ID_RE = re.compile(r"^[a-z0-9_-]{1,40}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
HOSTPORT_RE = re.compile(r"^([A-Za-z0-9.-]{1,253}|\[[0-9a-fA-F:]+\]):(\d{1,5})$")
RDAP = "https://rdap.org/domain/{}"
RDAP_EVERY = 86400
CERT_EVERY = 12 * 3600
MAX_MANUAL = 500
KIND_LABEL = {"license": "Άδεια", "warranty": "Εγγύηση", "contract": "Συμβόλαιο", "firmware": "Firmware",
              "domain": "Domain", "cert": "Πιστοποιητικό", "other": "Άλλο"}


def _hid(prefix, key):
    return f"{prefix}-{hashlib.sha1(key.encode('utf-8')).hexdigest()[:10]}"


def parse_date(s):
    """'YYYY-MM-DD' → ts της τοπικής μεσάνυχτας. ValueError αν δεν είναι έγκυρη."""
    if isinstance(s, datetime.date):
        s = s.isoformat()
    if not isinstance(s, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s.strip()):
        raise ValueError("Η ημερομηνία πρέπει να είναι YYYY-MM-DD.")
    d = datetime.date.fromisoformat(s.strip())
    return time.mktime((d.year, d.month, d.day, 0, 0, 0, 0, 0, -1))


def parse_iso(s):
    """'2027-01-17T12:00:00Z' (και με κλάσματα/ζώνη) → UTC ts ή None."""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?", str(s or ""))
    if not m:
        return None
    y, mo, d, h, mi, se = (int(x or 0) for x in m.groups())
    try:
        ts = calendar.timegm((y, mo, d, h, mi, se, 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    z = re.search(r"([+-])(\d{2}):?(\d{2})$", str(s)[m.end():])
    if z:
        off = (int(z.group(2)) * 3600 + int(z.group(3)) * 60) * (1 if z.group(1) == "+" else -1)
        ts -= off
    return ts


def rdap_expiry(data):
    """RDAP JSON → ts λήξης (events[eventAction=expiration]) ή None."""
    for ev in (data or {}).get("events") or []:
        if isinstance(ev, dict) and str(ev.get("eventAction", "")).lower() in ("expiration", "registration expiration"):
            return parse_iso(ev.get("eventDate"))
    return None


def rdap_lookup(domain, timeout=8):
    req = urllib.request.Request(RDAP.format(domain), headers={"Accept": "application/rdap+json", "User-Agent": "NetWatch"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(512 * 1024).decode("utf-8", "replace"))


def days_between(exp, now):
    """Ημερολογιακές μέρες (τοπική ώρα) από το now μέχρι το exp (αρνητικές = έληξε)."""
    a, b = time.localtime(now), time.localtime(exp)
    return (datetime.date(b.tm_year, b.tm_mon, b.tm_mday) - datetime.date(a.tm_year, a.tm_mon, a.tm_mday)).days


def status_of(days):
    if days is None:
        return "ok"
    if days < 0:
        return "expired"
    if days <= 7:
        return "urgent"
    if days <= 30:
        return "soon"
    return "ok"


class Expiry:
    def __init__(self, state, cfg=None, sim=False, path=None, clock=time.time):
        self.st, self.sim, self.clock = state, sim, clock
        self.cfg = dict(cfg or {})
        self.path = None if sim else path
        self.lock = threading.RLock()
        self.on_save = None
        self.manual = []        # [{id, name, kind, date, note, added}]
        self.fired = {}         # id → μικρότερο όριο για το οποίο στάλθηκε ειδοποίηση
        self.rdap = {}          # domain → {t, expires, error}
        self.certs = {}         # "host:port" → {t, expires, error}
        self.errors = []
        self._busy = threading.Lock()
        self.wake = threading.Event()
        self.cfg_items = self._cfg_items()
        self.cert_targets = self._cfg_list("certs", HOSTPORT_RE, "θέση «host:port»")
        self.domains = [d.lower() for d in self._cfg_list("domains", None, "domain")]
        if sim:
            self._seed()
        elif self.path:
            self._load()

    # ───────── ρυθμίσεις ─────────
    def _cfg_list(self, key, rx, what):
        out = []
        for x in self.cfg.get(key) or []:
            x = str(x).strip()
            ok = rx.match(x) if rx else DOMAIN_RE.match(x.lower())
            if ok and (rx is None or 0 < int(ok.group(2)) < 65536):
                out.append(x)
            else:
                self.errors.append(f"expiry.{key}: μη έγκυρο {what} «{x[:60]}»")
        return out[:100]

    def _cfg_items(self):
        out = []
        for i, it in enumerate(self.cfg.get("items") or []):
            if not isinstance(it, dict):
                continue
            try:
                exp = parse_date(str(it.get("date") or ""))
            except ValueError as e:
                self.errors.append(f"expiry.items[{i}]: {e}")
                continue
            name = str(it.get("name") or "").strip()[:80] or f"Στοιχείο {i + 1}"
            kind = it.get("kind") if it.get("kind") in KINDS else "other"
            out.append({"id": _hid("cfg", f"{name}|{it.get('date')}"), "name": name, "kind": kind, "source": "config",
                        "expires": exp, "detail": str(it.get("note") or "")[:200], "host": it.get("host")})
        return out

    # ───────── αποθήκευση ─────────
    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            return
        for m in d.get("items") or []:
            try:
                if ID_RE.match(m["id"]) and m.get("kind") in KINDS:
                    parse_date(m["date"])
                    self.manual.append({k: m.get(k) for k in ("id", "name", "kind", "date", "note", "added")})
            except (KeyError, TypeError, ValueError):
                continue
        self.fired = {k: v for k, v in (d.get("fired") or {}).items() if isinstance(v, int)}
        self.rdap = {k: v for k, v in (d.get("rdap") or {}).items() if isinstance(v, dict)}
        self.certs = {k: v for k, v in (d.get("certs") or {}).items() if isinstance(v, dict)}

    def _save(self):
        if not self.path:
            return
        data = {"v": 1, "items": self.manual, "fired": self.fired, "rdap": self.rdap, "certs": self.certs}
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    # ───────── συλλογή ─────────
    def _auto(self):
        """Πιστοποιητικά που ήδη ξέρουν άλλα modules (καμία νέα σύνδεση)."""
        out, now = [], self.clock()
        ta = getattr(self.st, "tlsaudit", None)
        try:
            res = ta.last_results() if ta else []
        except Exception:
            res = []
        for r in res or []:
            c = ((r or {}).get("tls") or {}).get("cert") or {}
            exp = None
            try:
                exp = ssl.cert_time_to_seconds(c["not_after"]) if c.get("not_after") else None
            except (ValueError, TypeError):
                exp = None
            if exp is None and isinstance(c.get("days_left"), int):
                exp = now + c["days_left"] * 86400
            if exp is None:
                continue
            ss = " · self-signed" if c.get("self_signed") else ""
            out.append({"id": _hid("tls", str(r.get("target"))), "name": f"Πιστοποιητικό TLS {r.get('target')}", "kind": "cert",
                        "source": "auto", "expires": exp, "host": r.get("ip"),
                        "detail": f"Έλεγχος TLS: {str(c.get('subject') or '')[:80]}{ss}"})
        he = getattr(self.st, "health", None)
        try:
            targets = he.status().get("targets") or [] if he else []
        except Exception:
            targets = []
        for t in targets:
            if isinstance(t.get("cert_days"), int):
                out.append({"id": _hid("hl", f"{t.get('name')}|{t.get('host')}|{t.get('port')}"),
                            "name": f"Πιστοποιητικό {t.get('name')}", "kind": "cert", "source": "auto",
                            "expires": now + t["cert_days"] * 86400, "host": t.get("host"),
                            "detail": f"Έλεγχος διαθεσιμότητας: {t.get('host')}:{t.get('port') or 443}"})
        ct = getattr(self.st, "ctwatch", None)
        try:
            doms = ct.status().get("domains") or [] if ct else []
        except Exception:
            doms = []
        for d in doms:
            best = max((parse_iso(c.get("not_after")) or 0 for c in d.get("recent") or []), default=0)
            if best:
                out.append({"id": _hid("ct", d.get("domain") or ""), "name": f"Πιστοποιητικό {d.get('domain')} (CT)",
                            "kind": "cert", "source": "auto", "expires": best, "host": None,
                            "detail": "Το νεότερο πιστοποιητικό στα logs Certificate Transparency."})
        for hp, r in self.certs.items():
            if r.get("expires"):
                out.append({"id": _hid("crt", hp), "name": f"Πιστοποιητικό {hp}", "kind": "cert", "source": "auto",
                            "expires": r["expires"], "host": hp.rsplit(":", 1)[0].strip("[]"), "detail": "expiry.certs"})
        for dom, r in self.rdap.items():
            if dom in self.domains and r.get("expires"):
                out.append({"id": _hid("dom", dom), "name": f"Domain {dom}", "kind": "domain", "source": "auto",
                            "expires": r["expires"], "host": None, "detail": "RDAP (μητρώο του domain)"})
        return out

    def _fetch(self, force=False):
        """Live: config certs (health.cert_days) κάθε 12 ώρες, domains (RDAP) μία φορά τη μέρα."""
        if self.sim:
            return
        import health
        now = self.clock()
        for hp in self.cert_targets:
            r = self.certs.get(hp) or {}
            if not force and now - (r.get("t") or 0) < CERT_EVERY:
                continue
            host, port = hp.rsplit(":", 1)
            try:
                days = health.cert_days(host.strip("[]"), int(port))
                self.certs[hp] = {"t": now, "expires": now + days * 86400, "error": None}
            except Exception as e:
                self.certs[hp] = {"t": now, "expires": r.get("expires"), "error": str(e)[:120] or e.__class__.__name__}
        for dom in self.domains:
            r = self.rdap.get(dom) or {}
            if now - (r.get("t") or 0) < (3600 if force else RDAP_EVERY):
                continue
            try:
                exp = rdap_expiry(rdap_lookup(dom))
                self.rdap[dom] = {"t": now, "expires": exp or r.get("expires"),
                                  "error": None if exp else "Το RDAP δεν δίνει ημερομηνία λήξης — βάλ' τη χειροκίνητα."}
            except Exception as e:
                msg = "ο registry δεν υποστηρίζει RDAP (π.χ. .gr) — βάλε την ημερομηνία χειροκίνητα" \
                    if "404" in str(e) else (str(e)[:120] or e.__class__.__name__)
                self.rdap[dom] = {"t": now, "expires": r.get("expires"), "error": msg}
        with self.lock:
            self._save()

    # ───────── όψη ─────────
    def _all(self):
        now = self.clock()
        with self.lock:
            man = [{"id": m["id"], "name": m["name"], "kind": m["kind"], "source": "manual", "expires": parse_date(m["date"]),
                    "detail": m.get("note") or "", "host": None} for m in self.manual]
            base = (self._demo if self.sim else []) + list(self.cfg_items) + man
        items = base + ([] if self.sim else self._auto())
        out, seen = [], set()
        for it in items:
            if it["id"] in seen:
                continue
            seen.add(it["id"])
            d = days_between(it["expires"], now)
            out.append({**it, "date": time.strftime("%Y-%m-%d", time.localtime(it["expires"])), "days_left": d,
                        "status": status_of(d)})
        out.sort(key=lambda x: (x["days_left"], x["name"]))
        return out

    def view(self):
        items = self._all()
        counts = {k: 0 for k in ("expired", "urgent", "soon", "ok")}
        for it in items:
            counts[it["status"]] += 1
        out = {"items": items, "counts": counts, "demo": self.sim}
        errs = list(self.errors) + [f"{k}: {v['error']}" for src in (self.rdap, self.certs)
                                    for k, v in src.items() if v.get("error")]
        if errs:
            out["errors"] = errs[:20]
        return out

    # ───────── ενέργειες ─────────
    def add(self, name, kind, date, note=None):
        name = name.strip() if isinstance(name, str) else ""
        if not name or len(name) > 80:
            return {"error": "Το όνομα πρέπει να είναι 1–80 χαρακτήρες."}
        if kind not in KINDS:
            return {"error": "Μη έγκυρο είδος (license, warranty, contract, firmware, domain, cert, other)."}
        if note is not None and (not isinstance(note, str) or len(note) > 200):
            return {"error": "Η σημείωση πρέπει να είναι έως 200 χαρακτήρες."}
        try:
            parse_date(date)
        except ValueError as e:
            return {"error": str(e)}
        with self.lock:
            if len(self.manual) >= MAX_MANUAL:
                return {"error": f"Έως {MAX_MANUAL} χειροκίνητα στοιχεία."}
            m = {"id": "m-" + secrets.token_hex(5), "name": name, "kind": kind, "date": date.strip(),
                 "note": (note or "").strip(), "added": self.clock()}
            self.manual.append(m)
            self._save()
        return next(i for i in self._all() if i["id"] == m["id"])

    def delete(self, iid):
        with self.lock:
            for i, m in enumerate(self.manual):
                if m["id"] == iid:
                    del self.manual[i]
                    self.fired.pop(iid, None)
                    self._save()
                    return {"ok": True}
        return {"error": "Διαγράφονται μόνο χειροκίνητα στοιχεία (αυτό δεν βρέθηκε)."}

    def refresh(self):
        if not self.sim:
            threading.Thread(target=self._cycle, kwargs={"force": True}, daemon=True).start()
        return {"ok": True}

    # ───────── ειδοποιήσεις ─────────
    def check(self):
        """Ειδοποίηση μία φορά ανά όριο (30/7/1/0 μέρες). Επιστρέφει [(id, όριο)] που στάλθηκαν."""
        sent, now = [], self.clock()
        for it in self._all():
            d = it["days_left"]
            hit = next(((th, sev) for th, sev in THRESHOLDS if d <= th), None)
            if hit is None:
                continue
            th, sev = hit
            with self.lock:
                prev = self.fired.get(it["id"])
                if prev is not None and prev <= th:
                    continue
                self.fired[it["id"]] = th
            when = f"έληξε πριν {-d} μέρες" if d < 0 else ("λήγει σήμερα" if d == 0 else f"λήγει σε {d} μέρες")
            lab = KIND_LABEL.get(it["kind"], "")
            lab = "" if it["name"].lower().startswith(lab.lower()) else lab + " "
            detail = f"{lab}«{it['name']}» {when} ({it['date']})." + \
                (f" {it['detail']}" if it.get("detail") else "")
            try:
                if self.st is not None:
                    self.st.alert(ALERT, sev, it.get("host") or "netwatch", it["name"], detail[:500], now,
                                  key=f"expiry:{it['id']}", cooldown=86400, mark=False)
            except Exception:
                pass
            sent.append((it["id"], th))
        if sent:
            with self.lock:
                self._save()
        return sent

    def _cycle(self, force=False):
        if not self._busy.acquire(blocking=False):
            return
        try:
            self._fetch(force)
            self.check()
        finally:
            self._busy.release()

    def run_forever(self):
        time.sleep(60)
        while True:
            try:
                self._cycle()
            except Exception:
                pass
            self.wake.wait(3600)
            self.wake.clear()

    # ───────── demo ─────────
    def _seed(self):
        now = self.clock()
        day = lambda n: now + n * 86400  # noqa: E731
        D = [("router-cert", "HTTPS διαχείρισης router (self-signed)", "cert", -12, "192.168.1.1",
              "CN=router.home · self-signed — φτιάξε νέο: /certificate add name=www common-name=router.home days-valid=825"),
             ("nas-cert", "Πιστοποιητικό NAS (DSM)", "cert", 5, "192.168.1.17", "192.168.1.17:5001 · Let's Encrypt δεν ανανεώθηκε"),
             ("proxmox-cert", "Πιστοποιητικό Proxmox", "cert", 9, "192.168.1.16", "Έλεγχος διαθεσιμότητας: 192.168.1.16:8006"),
             ("le-homelab", "Let's Encrypt example-homelab.gr", "cert", 24, None,
              "Το νεότερο πιστοποιητικό στα logs CT · certbot renew --dry-run"),
             ("dom-homelab", "Domain example-homelab.gr", "domain", 61, None, "Ανανέωση στον registrar (το .gr δεν έχει RDAP)"),
             ("smartnet", "Cisco SmartNet core-sw (2960)", "contract", 18, "192.168.1.2", "Συμβόλαιο υποστήριξης · CON-SNT-WS-C2960"),
             ("ups-battery", "Αλλαγή μπαταρίας UPS", "other", 9, None, "APC Back-UPS 700 · μπαταρία RBC17 (κάθε 3 χρόνια)"),
             ("nas-warranty", "Εγγύηση NAS", "warranty", 140, "192.168.1.17", "Τιμολόγιο στον φάκελο «Αγορές»"),
             ("ap-firmware", "Firmware AP σαλονιού (OpenWrt)", "firmware", -45, "192.168.1.3",
              "Τελευταία ενημέρωση πριν 410 μέρες — ο έλεγχος για νέα έκδοση έπρεπε να γίνει πριν 45 μέρες")]
        self._demo = [{"id": i, "name": n, "kind": k, "source": "config" if k in ("contract", "warranty", "other") else "auto",
                       "expires": day(d), "host": h, "detail": det} for i, n, k, d, h, det in D]
        self.manual = []

    _demo = []
