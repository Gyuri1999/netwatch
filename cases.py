"""🗂 Διαλογή ειδοποιήσεων & υποθέσεις (case management, ιδέα: TheHive / SOAR).

Κάθε πραγματική ειδοποίηση (όχι lab, όχι δική σου δοκιμή, όχι «αθώα») περνά από το on_alert() και
ομαδοποιείται σε μια «υπόθεση»: ίδιος δράστης (actor) μέσα σε 30 λεπτά από την τελευταία του ειδοποίηση
→ ίδια υπόθεση, αλλιώς νέα. Η υπόθεση έχει κατάσταση (νέα → υπό διερεύνηση → επιλύθηκε / ψευδώς θετικό),
σημειώσεις και χρονοσφραγίδες, ώστε να μετράμε MTTA (χρόνος μέχρι να την «πιάσεις») και MTTR (μέχρι να κλείσει).

Το «ψευδώς θετικό» δημιουργεί καταστολή (suppression) για κάθε ζεύγος (τύπος, δράστης) της υπόθεσης:
οι επόμενες ίδιες ειδοποιήσεις φαίνονται ως αθώες (benign) — δεν χρωματίζουν συσκευές ούτε στέλνουν ειδοποιήσεις.

Στη λειτουργία demo οι υποθέσεις χτίζονται από τις ειδοποιήσεις της προσομοίωσης και παίρνουν ένα
ρεαλιστικό «μείγμα» καταστάσεων (μία λυμένη, ένα ψευδώς θετικό, μία υπό διερεύνηση).
"""
import json
import os
import threading
import time

WINDOW = 30 * 60          # δευτερόλεπτα: ίδια υπόθεση αν ο ίδιος δράστης ξαναχτυπήσει μέσα σε 30′
MAX_CASES = 1000
MAX_ALERTS = 500
MAX_TARGETS = 10
MAX_NOTES = 200
VIEW_MAX = 200
STATUSES = ("new", "investigating", "resolved", "false_positive")
OPEN = ("new", "investigating")
CLOSED = ("resolved", "false_positive")
RANK = {"low": 1, "med": 2, "high": 3}
SAVE_EVERY = 10


def _sev(s):
    return s if s in RANK else "med"


def _copy(c):
    """Αντίγραφο υπόθεσης για έξοδο (οι λίστες αλλάζουν από άλλα νήματα)."""
    return {k: (list(v) if isinstance(v, list) else dict(v) if isinstance(v, dict) else v) for k, v in c.items()}


class Cases:
    def __init__(self, state, sim=False, path=None, clock=time.time):
        self.st, self.sim, self.path, self.clock = state, sim, path, clock
        self.lock = threading.RLock()
        self.cases = []            # παλαιότερη πρώτη
        self.suppressions = []     # [{type, actor, until (None = για πάντα), case}]
        self.seq = 0
        self._seen = set()         # ids ειδοποιήσεων που έχουν ήδη μπει σε υπόθεση
        self._dirty = False
        self._last_save = 0.0
        self._mixed = False
        self.on_save = None
        if path:
            self._load()
        if sim:
            self._seed()

    # ───────── βοηθητικά ─────────
    def _name(self, ip):
        """Φιλικό όνομα για τον τίτλο: DNS/rDNS που ήδη ξέρουμε (χωρίς νέα αναζήτηση), αλλιώς η IP."""
        try:
            h = (getattr(self.st, "hosts", None) or {}).get(ip)
        except Exception:
            h = None
        if h:
            names = sorted(h.get("names") or ())
            nm = h.get("rdns") or (names[0] if names else None)
            if nm:
                return f"{nm} ({ip})"
        return str(ip)

    def _find(self, cid):
        try:
            cid = int(cid)
        except (TypeError, ValueError):
            return None
        return next((c for c in self.cases if c["id"] == cid), None)

    def _touch(self, c, now=None):
        c["updated"] = self.clock() if now is None else now
        self._dirty = True

    def _trim(self):
        """Όριο MAX_CASES: φεύγουν πρώτα οι παλαιότερες κλειστές (και, αν δεν φτάνει, οι παλαιότερες γενικά)."""
        extra = len(self.cases) - MAX_CASES
        if extra <= 0:
            return
        drop = {id(c) for c in self.cases if c["status"] in CLOSED}
        keep = []
        for c in self.cases:
            if extra > 0 and id(c) in drop:
                extra -= 1
                continue
            keep.append(c)
        if extra > 0:
            keep = keep[extra:]
        self.cases = keep

    def _new_case(self, title, actors, sev, created, source=None, status="new"):
        self.seq += 1
        c = {"id": self.seq, "title": str(title)[:200], "status": status, "sev": _sev(sev),
             "actors": list(actors)[:20], "targets": [], "alert_ids": [], "types": [], "mitre": [],
             "first": None, "last": None, "count": 0, "created": created, "updated": created,
             "acked": created if status != "new" else None, "closed": None, "notes": [], "suppress": None}
        if source:
            c["source"] = source
        self.cases.append(c)
        self._trim()
        self._dirty = True
        return c

    # ───────── ειδοποιήσεις ─────────
    def on_alert(self, a, created=None):
        """Βάζει μια ειδοποίηση σε υπόθεση → id υπόθεσης (ή None αν αγνοήθηκε)."""
        if not a or a.get("lab") or a.get("selftest") or a.get("benign"):
            return None
        aid, actor, t = a.get("id"), a.get("actor"), float(a.get("t") or self.clock())
        with self.lock:
            if aid is not None and aid in self._seen:
                return next((c["id"] for c in reversed(self.cases) if aid in c["alert_ids"]), None)
            c = next((c for c in reversed(self.cases) if c["status"] in OPEN and actor in c["actors"]
                      and c["last"] is not None and abs(t - c["last"]) <= WINDOW), None)
            if c is None:
                title = f"{a.get('type') or 'Ειδοποίηση'} από {self._name(actor)}"
                c = self._new_case(title, [actor], a.get("sev"), self.clock() if created is None else created)
            if RANK.get(a.get("sev"), 0) > RANK.get(c["sev"], 0):
                c["sev"] = a["sev"]
            tg = a.get("target")
            if tg and tg not in c["targets"] and len(c["targets"]) < MAX_TARGETS:
                c["targets"].append(tg)
            if aid is not None:
                c["alert_ids"].append(aid)
                del c["alert_ids"][:-MAX_ALERTS]
                self._seen.add(aid)
                if len(self._seen) > 50000:
                    self._seen = {i for x in self.cases for i in x["alert_ids"]}
            typ = a.get("type")
            if typ and typ not in c["types"]:
                c["types"].append(typ)
            m = a.get("mitre") or {}
            if m.get("id") and all(x["id"] != m["id"] for x in c["mitre"]):
                c["mitre"].append({"id": m["id"], "name": m.get("name") or ""})
            c["first"] = t if c["first"] is None else min(c["first"], t)
            c["last"] = t if c["last"] is None else max(c["last"], t)
            c["count"] += 1
            self._touch(c, None if created is None else max(created, t))
            return c["id"]

    # ───────── ενέργειες αναλυτή ─────────
    def _note(self, c, text, now, auto=False):
        text = str(text or "").strip()
        if not text:
            return
        n = {"t": now, "text": text[:2000]}
        if auto:
            n["auto"] = True
        c["notes"].append(n)
        del c["notes"][:-MAX_NOTES]

    def _set_status(self, c, status, now):
        if status == c["status"]:
            return
        c["status"] = status
        if status != "new" and c["acked"] is None:
            c["acked"] = now
        if status in CLOSED:
            c["closed"] = now
        else:
            c["closed"] = None
        if status != "false_positive":
            c["suppress"] = None

    def update(self, id, status=None, note=None, now=None):
        if status is not None and status not in STATUSES:
            return {"error": "Μη έγκυρη κατάσταση (new, investigating, resolved, false_positive)."}
        if note is not None and len(str(note)) > 2000:
            return {"error": "Η σημείωση είναι πολύ μεγάλη (όριο 2000 χαρακτήρες)."}
        if status is None and not str(note or "").strip():
            return {"error": "Τίποτα για αλλαγή — δώσε κατάσταση ή σημείωση."}
        now = self.clock() if now is None else now
        with self.lock:
            c = self._find(id)
            if not c:
                return {"error": "Η υπόθεση δεν βρέθηκε."}
            if status == "false_positive":
                return self._fp(c, 1440, note, now)
            if status is not None:
                if c["status"] == "false_positive" and status != "false_positive":
                    self.suppressions = [s for s in self.suppressions if s["case"] != c["id"]]
                self._set_status(c, status, now)
            self._note(c, note, now)
            self._touch(c, now)
            return _copy(c)

    def _fp(self, c, minutes, note, now, base=None):
        until = None if not minutes else (now if base is None else base) + minutes * 60
        self._set_status(c, "false_positive", now)
        pairs = [(t, a) for t in c["types"] for a in c["actors"]]
        self.suppressions = [s for s in self.suppressions if (s["type"], s["actor"]) not in pairs]
        for t, a in pairs:
            self.suppressions.append({"type": t, "actor": a, "until": until, "case": c["id"]})
        c["suppress"] = {"until": until, "pairs": len(pairs)}
        self._note(c, note, now)
        span = "για πάντα" if until is None else (f"για {minutes // 60} ώρες" if minutes % 60 == 0 and minutes >= 60
                                                 else f"για {minutes} λεπτά")
        self._note(c, f"Ψευδώς θετικό — καταστολή {len(pairs)} κανόνων (τύπος × δράστης) {span}.", now, auto=True)
        self._touch(c, now)
        return _copy(c)

    def false_positive(self, id, minutes=1440, note=None, now=None):
        try:
            minutes = int(minutes)
        except (TypeError, ValueError):
            return {"error": "Τα λεπτά πρέπει να είναι ακέραιος αριθμός."}
        if not 0 <= minutes <= 525600:
            return {"error": "Λεπτά: από 0 (για πάντα) έως 525600 (1 χρόνος)."}
        if note is not None and len(str(note)) > 2000:
            return {"error": "Η σημείωση είναι πολύ μεγάλη (όριο 2000 χαρακτήρες)."}
        now = self.clock() if now is None else now
        with self.lock:
            c = self._find(id)
            if not c:
                return {"error": "Η υπόθεση δεν βρέθηκε."}
            return self._fp(c, minutes, note, now)

    def suppressed(self, typ, actor, t=None):
        """→ αιτιολογία «αθώας» ειδοποίησης αν ο (τύπος, δράστης) έχει σημειωθεί ψευδώς θετικός, αλλιώς None."""
        if not self.suppressions:
            return None
        t = self.clock() if t is None else t
        with self.lock:
            live = [s for s in self.suppressions if s["until"] is None or s["until"] > t]
            if len(live) != len(self.suppressions):
                self.suppressions = live
                self._dirty = True
            s = next((s for s in live if s["type"] == typ and s["actor"] == actor), None)
        return f"Σημειώθηκε ψευδώς θετικό (υπόθεση #{s['case']})" if s else None

    def delete_suppression(self, typ, actor):
        with self.lock:
            n = len(self.suppressions)
            self.suppressions = [s for s in self.suppressions if not (s["type"] == typ and s["actor"] == actor)]
            if len(self.suppressions) == n:
                return {"error": "Δεν βρέθηκε τέτοια καταστολή."}
            self._dirty = True
        return {"ok": True}

    def create(self, title, actors, sev="med", note=None, source="hunt", now=None):
        """Χειροκίνητη υπόθεση (π.χ. εύρημα κυνηγιού απειλών) — ξεκινά «υπό διερεύνηση»."""
        title = str(title or "").strip()
        if not title or len(title) > 200:
            return {"error": "Δώσε τίτλο (έως 200 χαρακτήρες)."}
        if isinstance(actors, str):
            actors = [actors]
        if not isinstance(actors, (list, tuple)):
            return {"error": "Οι δράστες πρέπει να είναι λίστα."}
        actors = [str(x).strip()[:100] for x in actors if str(x).strip()][:20]
        if sev not in RANK:
            return {"error": "Σοβαρότητα: low, med ή high."}
        if note is not None and len(str(note)) > 2000:
            return {"error": "Η σημείωση είναι πολύ μεγάλη (όριο 2000 χαρακτήρες)."}
        now = self.clock() if now is None else now
        with self.lock:
            c = self._new_case(title, actors, sev, now, source=str(source or "manual")[:40], status="investigating")
            c["first"] = c["last"] = now
            self._note(c, note, now)
            return _copy(c)

    # ───────── προβολή ─────────
    def view(self):
        now = self.clock()
        with self.lock:
            self.suppressions = [s for s in self.suppressions if s["until"] is None or s["until"] > now]
            cs = sorted(self.cases, key=lambda c: (-(c["updated"] or 0), -c["id"]))[:VIEW_MAX]
            out = [_copy(c) for c in cs]
            kpi = {s: 0 for s in STATUSES}
            ack, res = [], []
            for c in self.cases:
                kpi[c["status"]] = kpi.get(c["status"], 0) + 1
                if c["acked"] is not None:
                    ack.append(max(0.0, c["acked"] - c["created"]))
                if c["closed"] is not None:
                    res.append(max(0.0, c["closed"] - c["created"]))
            kpi.update(open=kpi["new"] + kpi["investigating"], total=len(self.cases),
                       mtta=round(sum(ack) / len(ack), 1) if ack else None,
                       mttr=round(sum(res) / len(res), 1) if res else None)
            sup = [dict(s) for s in self.suppressions]
        return {"cases": out, "kpi": kpi, "suppressions": sup, "demo": bool(self.sim)}

    # ───────── αποθήκευση ─────────
    def save(self):
        if not self.path:
            return
        with self.lock:
            data = {"v": 1, "seq": self.seq, "cases": self.cases, "suppressions": self.suppressions}
            raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            self._dirty = False
        self._last_save = self.clock()
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(raw)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        self.cases = [c for c in data.get("cases") or [] if isinstance(c, dict) and "id" in c][-MAX_CASES:]
        self.suppressions = [s for s in data.get("suppressions") or [] if isinstance(s, dict) and "type" in s]
        self.seq = max([int(data.get("seq") or 0)] + [c["id"] for c in self.cases])
        # τα ids ειδοποιήσεων ξεκινούν από την αρχή σε κάθε εκκίνηση — δεν τα θεωρούμε «ήδη μέσα»

    def tick(self):
        if self.sim:
            self._seed()
        if self.path and self._dirty and self.clock() - self._last_save >= SAVE_EVERY:
            self.save()

    def run_forever(self):
        while True:
            time.sleep(5)
            try:
                self.tick()
            except Exception:
                pass

    # ───────── demo ─────────
    def _seed(self):
        """Demo: υποθέσεις από τις ειδοποιήσεις που ήδη υπάρχουν + ρεαλιστικό μείγμα καταστάσεων (μία φορά)."""
        st = self.st
        try:
            lk = getattr(st, "lock", None)
            if lk:
                with lk:
                    al = list(getattr(st, "alerts", None) or [])
            else:
                al = list(getattr(st, "alerts", None) or [])
        except Exception:
            al = []
        for a in sorted(al, key=lambda a: (a.get("t") or 0, a.get("id") or 0)):
            cid = self.on_alert(a, created=a.get("t"))
            if cid is not None and isinstance(a, dict) and "case" not in a:
                a["case"] = cid
        if not self._mixed:
            self._mix()

    def _mix(self):
        with self.lock:
            cs = [c for c in self.cases if c["status"] == "new" and c.get("source") is None]
            if len(cs) < 4:
                return
            self._mixed = True
            now = self.clock()
            r, fp, inv = cs[0], cs[1], cs[2]

            def at(c, mins):  # λίγα λεπτά μετά τη δημιουργία, όχι στο μέλλον
                return min(now, c["created"] + mins * 60)
            self._set_status(r, "investigating", at(r, 4))
            self._note(r, "Το NAS έκανε σάρωση μετά από αναβάθμιση firmware — απενεργοποιήθηκε το «network discovery».", at(r, 9))
            self._set_status(r, "resolved", at(r, 22))
            self._touch(r, at(r, 22))
            self._fp(fp, 1440, "Το Home Assistant κάνει discovery κάθε λίγα λεπτά — αναμενόμενη συμπεριφορά.", at(fp, 7),
                     base=now)  # η καταστολή ισχύει από «τώρα», ώστε να φαίνεται ενεργή στο demo
            self._set_status(inv, "investigating", at(inv, 3))
            self._note(inv, "Άγνωστη συσκευή — έλεγχος MAC στο router και στο IPAM.", at(inv, 3))
            self._note(inv, "Ο κατασκευαστής (OUI) ταιριάζει με Raspberry Pi· ρώτησα αν είναι κάποιου στο σπίτι.", at(inv, 11))
            self._touch(inv, at(inv, 11))
