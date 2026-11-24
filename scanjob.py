"""⏰ Αυτόματος έλεγχος ασφαλείας: τρέχει μόνο του μια σάρωση κάθε λίγες μέρες και σου στέλνει σύνοψη (ntfy/Telegram).

Για τον τεχνικό που αφήνει το κουτί στον πελάτη: βάζεις «κάθε 7 μέρες στις 03:00», και παίρνεις στο κινητό τον βαθμό
A–F, πόσα ευρήματα και τι να δεις. Η πλήρης αναφορά είναι πάντα στο /pentest-report.

Μόνο ανάγνωση/σάρωση ιδιωτικού δικτύου (ό,τι κάνει και το χειροκίνητο κουμπί). Δεν στέλνει τίποτα στο Internet πέρα
από την ειδοποίηση που έχεις ρυθμίσει εσύ.
"""
import json
import os
import threading
import time

DEFAULTS = {"enabled": False, "every_days": 7, "hour": 3, "profile": "top1000", "udp": True}
PROFILES = ("quick", "top1000", "full")


def due(cfg, last_run, now):
    """Ώρα για αυτόματη σάρωση; enabled, πέρασε το διάστημα, και είμαστε στην προγραμματισμένη ώρα (όχι ξανά την ίδια μέρα)."""
    if not cfg.get("enabled"):
        return False
    days = max(1, int(cfg.get("every_days") or 7))
    hour = max(0, min(23, int(cfg.get("hour") or 0)))
    lt = time.localtime(now)
    if lt.tm_hour != hour:
        return False
    if last_run is None:
        return True
    if time.localtime(last_run)[:3] == lt[:3]:      # έτρεξε ήδη σήμερα
        return False
    return now - last_run >= days * 86400 - 3600


def next_run(cfg, last_run, now):
    """Προσεγγιστικά, πότε είναι η επόμενη αυτόματη σάρωση (epoch) ή None αν είναι κλειστή."""
    if not cfg.get("enabled"):
        return None
    days = max(1, int(cfg.get("every_days") or 7))
    hour = max(0, min(23, int(cfg.get("hour") or 0)))
    base = (last_run + days * 86400) if last_run else now
    lt = time.localtime(base)
    cand = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hour, 0, 0, 0, 0, -1))
    while cand < now:
        cand += 86400
    return cand


def summary_text(scan, assess_doc, lang="el"):
    """Σύνοψη για ειδοποίηση: βαθμός, πλήθος ευρημάτων, κορυφαία, EOL. Σύντομο κείμενο για κινητό."""
    el = lang != "en"
    hosts = (scan or {}).get("hosts") or []
    nhigh = sum(1 for h in hosts for s in h.get("services") or () if s.get("risk") == "high")
    neol = len({s["eol"]["label"] for h in hosts for s in h.get("services") or () if s.get("eol")})
    grade = (assess_doc or {}).get("grade", "?")
    fixes = [(f.get("title") or "") for f in (assess_doc or {}).get("fixes") or ()][:3]
    if el:
        parts = [f"Βαθμός {grade}. {len(hosts)} συσκευές, {nhigh} υπηρεσίες υψηλού κινδύνου"]
        if neol:
            parts.append(f"{neol} εκτός υποστήριξης")
        t = " · ".join(parts) + "."
        if fixes:
            t += " Πρώτα: " + "· ".join(fixes) + "."
        t += " Πλήρης αναφορά στο NetWatch → Pentest."
    else:
        parts = [f"Grade {grade}. {len(hosts)} devices, {nhigh} high-risk services"]
        if neol:
            parts.append(f"{neol} end-of-life")
        t = " · ".join(parts) + "."
        if fixes:
            t += " First: " + "· ".join(fixes) + "."
        t += " Full report in NetWatch → Pentest."
    return t


class ScanJob:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time):
        self.state, self.demo, self.clock = state, demo, clock
        self.path = os.path.join(data_dir, "scanjob.json") if data_dir else None
        self.on_save = None
        self.lock = threading.RLock()
        self.cfg = dict(DEFAULTS)
        self.last_run = None
        self.last_summary = ""
        self.last_grade = None
        self.pending = False        # έχουμε ξεκινήσει μια προγραμματισμένη σάρωση που περιμένει να τελειώσει
        self.error = None
        if demo:
            self.cfg.update(enabled=True, every_days=7, hour=3)
            self.last_run = self.clock() - 2 * 86400
            self.last_grade = "C"
            self.last_summary = "Βαθμός C. 12 συσκευές, 3 υπηρεσίες υψηλού κινδύνου · 1 εκτός υποστήριξης. Πρώτα: Κλείσε το Telnet· Άλλαξε κωδικό κάμερας. Πλήρης αναφορά στο NetWatch → Pentest."
        elif self.path and os.path.exists(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    j = json.load(f)
                self.cfg.update({k: j.get(k, self.cfg[k]) for k in DEFAULTS})
                self.last_run, self.last_summary, self.last_grade = j.get("last_run"), j.get("last_summary", ""), j.get("last_grade")
            except (OSError, ValueError):
                pass

    def _save(self):
        if not self.path:
            return
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({**self.cfg, "last_run": self.last_run, "last_summary": self.last_summary, "last_grade": self.last_grade}, f, ensure_ascii=False)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    def set_config(self, body):
        c = dict(self.cfg)
        c["enabled"] = bool(body.get("enabled"))
        try:
            c["every_days"] = max(1, min(90, int(body.get("every_days", c["every_days"]))))
            c["hour"] = max(0, min(23, int(body.get("hour", c["hour"]))))
        except (TypeError, ValueError):
            return {"error": "Οι μέρες και η ώρα πρέπει να είναι αριθμοί."}
        if body.get("profile") in PROFILES:
            c["profile"] = body["profile"]
        c["udp"] = bool(body.get("udp"))
        with self.lock:
            self.cfg = c
            self._save()
        return {"ok": True}

    # ── εκκίνηση σάρωσης ──
    def _trigger(self):
        sc = getattr(self.state, "scanner", None)
        if sc is None:
            return False
        try:
            target = self.state.default_scan_target() if hasattr(self.state, "default_scan_target") else None
            with (getattr(self.state, "lock", None) or threading.Lock()):
                known = {ip: h["mac"] for ip, h in (getattr(self.state, "hosts", None) or {}).items()
                         if isinstance(h, dict) and h.get("mac") and h.get("kind") == "local"}
            sc.start(target, known, profile=self.cfg.get("profile", "top1000"), udp=bool(self.cfg.get("udp")))
            self.pending = True
            self.error = None
            return True
        except Exception as e:  # noqa: BLE001
            self.error = str(e)[:160]
            return False

    def run_now(self):
        if self.demo:
            return {"ok": True, "demo": True}
        with self.lock:
            sc = getattr(self.state, "scanner", None)
            if sc and sc.status().get("status") == "running":
                return {"error": "Τρέχει ήδη σάρωση."}
            ok = self._trigger()
        return {"ok": True} if ok else {"error": self.error or "Δεν μπόρεσα να ξεκινήσω σάρωση."}

    def tick(self, now=None):
        """Καλείται περιοδικά από το run_forever. Ξεκινά σάρωση αν ήρθε η ώρα."""
        now = now or self.clock()
        with self.lock:
            if self.pending or self.demo:
                return
            sc = getattr(self.state, "scanner", None)
            if not sc or sc.status().get("status") == "running":
                return
            if due(self.cfg, self.last_run, now):
                self._trigger()

    def on_scan_done(self, hosts):
        """Το netwatch.scan_done μας ειδοποιεί όταν τελειώσει ΜΙΑ σάρωση. Αν ήταν δική μας → σύνοψη + ειδοποίηση."""
        with self.lock:
            if not self.pending:
                return
            self.pending = False
            now = self.clock()
            self.last_run = now
        try:
            scan = self.state.scan_view() if hasattr(self.state, "scan_view") else {"hosts": hosts}
            doc = None
            try:
                import assess
                doc = assess.build(self.state, self.cfg.get("lang", "el"))
            except Exception:  # noqa: BLE001
                doc = None
            lang = (getattr(self.state, "cfg", None) or {}).get("lang", "el")
            text = summary_text(scan, doc, lang)
            with self.lock:
                self.last_summary = text
                self.last_grade = (doc or {}).get("grade")
                self._save()
            self._notify(text, now)
        except Exception as e:  # noqa: BLE001
            self.error = str(e)[:160]

    def _notify(self, text, now):
        n = getattr(self.state, "notifier", None)
        if n is None:
            return
        try:  # στέλνεται ως «ειδοποίηση» υψηλής προτεραιότητας ώστε να φτάσει στο κινητό (δεν καταγράφεται ως επίθεση)
            n({"type": "Αυτόματος έλεγχος ασφαλείας", "detail": text, "sev": "high", "actor": "NetWatch", "target": "", "t": now})
        except Exception:  # noqa: BLE001
            pass

    def run_forever(self):
        time.sleep(60)
        while True:
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(600)

    # ── UI ──
    def view(self):
        now = self.clock()
        with self.lock:
            return {"demo": self.demo, **self.cfg, "last_run": self.last_run, "last_summary": self.last_summary,
                    "last_grade": self.last_grade, "next_run": next_run(self.cfg, self.last_run, now),
                    "running": bool(self.pending) or bool(getattr(self.state, "scanner", None) and getattr(self.state, "scanner").status().get("status") == "running"),
                    "error": self.error, "channels": (getattr(self.state, "notifier", None).channels() if getattr(self.state, "notifier", None) else {})}

    def api(self, method, sub, q, body):
        if method == "GET" and sub == "":
            return 200, self.view()
        if method == "POST" and sub == "config":
            r = self.set_config(body if isinstance(body, dict) else {})
            return (400, r) if r.get("error") else (200, self.view())
        if method == "POST" and sub == "run":
            r = self.run_now()
            return (400, r) if r.get("error") else (200, self.view())
        return 404, {"error": "not found"}
