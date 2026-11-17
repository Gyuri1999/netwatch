"""⚡ Αυτόματες αντιδράσεις (playbooks): «όταν συμβεί Χ → κάνε Υ».

Ρύθμιση στο config.yaml (ΚΛΕΙΣΤΟ από προεπιλογή — τίποτα δεν γίνεται αυτόματα αν δεν το γράψεις):

playbooks:
  - name: Καναρίνι → μπλόκαρε
    when: {type: "Καναρίνι ESP32"}      # πρόθεμα τύπου ειδοποίησης (ή λίστα)· προαιρετικά sev: high, local: true
    do: [block, notify]                  # block · notify · mqtt (στο netwatch/playbook/<όνομα>, π.χ. για σκηνή στο HA)
    block_minutes: 60                    # το μπλοκ λήγει μόνο του (0 = μέχρι να το βγάλεις)
    dry_run: false                       # true = μόνο γράφει τι ΘΑ έκανε

Ασφάλεια:
- ποτέ δεν μπλοκάρει τον εαυτό σου, τον router ή ό,τι είναι στο allowlist (ο Blocker το αρνείται)·
- όχι πάνω από max_per_hour ενέργειες ανά playbook (προεπιλογή 10) — ένας επιτιθέμενος δεν σε κάνει να μπλοκάρεις όλο το δίκτυο
  πλαστογραφώντας IP·
- δεν αντιδρά σε ειδοποιήσεις «αναμενόμενες» (benign) ή από το εργαστήριο·
- κάθε ενέργεια καταγράφεται με κουμπί αναίρεσης.
"""
import threading
import time

ACTIONS = ("block", "notify", "mqtt")


def matches(when, a, local_ip):
    when = when or {}
    types = when.get("type")
    if types:
        types = [types] if isinstance(types, str) else list(types)
        if not any(a["type"].startswith(t) for t in types):
            return False
    sev = when.get("sev")
    if sev:
        order = {"low": 1, "med": 2, "high": 3}
        if order.get(a["sev"], 0) < order.get(sev, 3):
            return False
    if "local" in when and bool(when["local"]) != bool(local_ip(a["actor"])):
        return False
    return bool(types or sev or "local" in when)  # ένα playbook χωρίς κανένα κριτήριο δεν τρέχει ποτέ


def clean(cfg):
    """Ελέγχει τα playbooks του config· επιστρέφει (έγκυρα, λάθη)."""
    ok, errs = [], []
    for i, p in enumerate(cfg or []):
        name = str((p or {}).get("name") or f"playbook {i + 1}")[:60]
        do = (p or {}).get("do") or []
        do = [do] if isinstance(do, str) else list(do)
        bad = [d for d in do if d not in ACTIONS]
        if bad:
            errs.append(f"{name}: άγνωστη ενέργεια {bad} (επιτρέπονται: {', '.join(ACTIONS)})")
            continue
        if not do or not (p.get("when") or {}):
            errs.append(f"{name}: χρειάζεται και «when» και «do»")
            continue
        ok.append({"name": name, "when": p["when"], "do": do, "block_minutes": int(p.get("block_minutes", 60) or 0),
                   "dry_run": bool(p.get("dry_run", False)), "max_per_hour": int(p.get("max_per_hour", 10))})
    return ok, errs


class Playbooks:
    def __init__(self, state, cfg, sync=False):
        self.state, self.sync = state, sync
        self.books, self.errors = clean(cfg)
        self.lock = threading.Lock()
        self.runs = []  # ιστορικό ενεργειών
        self.recent = {}  # name → [t,…]
        self.expiry = {}  # ip → t λήξης μπλοκ
        self.seq = 0

    def _local(self, ip):
        from core import ip_kind
        return ip_kind(ip) == "local"

    def on_alert(self, a):
        if a.get("benign") or a.get("lab") or not self.books:
            return
        for pb in self.books:
            if matches(pb["when"], a, self._local):
                if self.sync:
                    self._run(pb, a)
                else:  # το pfctl κ.λπ. να μην καθυστερεί την ανάλυση πακέτων
                    threading.Thread(target=self._run, args=(pb, dict(a)), daemon=True).start()

    def _run(self, pb, a):
        now = a.get("t") or time.time()
        with self.lock:
            rec = [t for t in self.recent.get(pb["name"], []) if now - t < 3600]
            if len(rec) >= pb["max_per_hour"]:
                self.recent[pb["name"]] = rec
                return
            rec.append(now)
            self.recent[pb["name"]] = rec
        for act in pb["do"]:
            res, ok = self._do(act, pb, a, now)
            with self.lock:
                self.seq += 1
                self.runs.append({"id": self.seq, "t": now, "playbook": pb["name"], "action": act, "actor": a["actor"],
                                  "alert": a["type"], "result": res, "ok": ok, "dry": pb["dry_run"], "undone": False})
                del self.runs[:-300]

    def _do(self, act, pb, a, now):
        ip = a["actor"]
        if pb["dry_run"]:
            return f"(δοκιμή) θα έκανα: {act} {ip}", True
        try:
            if act == "block":
                if not self.state.blocker:
                    return "δεν υπάρχει τείχος προστασίας σε αυτή τη λειτουργία", False
                if self.state._allowed(ip):
                    return "στο allowlist — δεν το μπλοκάρω", False
                st = self.state.blocker.block(ip, f"⚡ {pb['name']}: {a['type']}")
                if pb["block_minutes"]:
                    with self.lock:
                        self.expiry[ip] = now + pb["block_minutes"] * 60
                applied = st.get("can_apply") and not st.get("error")
                return (f"μπλοκαρίστηκε{' για ' + str(pb['block_minutes']) + '′' if pb['block_minutes'] else ''}"
                        if applied else f"στη λίστα, αλλά δεν εφαρμόστηκε ({st.get('error') or 'χρειάζεται root'})"), bool(applied)
            if act == "notify":
                from storage import Notifier
                n = self.state.notifier or Notifier((self.state.cfg or {}).get("notify") or {})
                n._send({**a, "type": f"⚡ {pb['name']}: {a['type']}"})  # παρακάμπτει το min_severity: το ζήτησες ρητά
                return "στάλθηκε ειδοποίηση", True
            if act == "mqtt":
                h = getattr(self.state, "hass", None)
                if not h or not h.configured:
                    return "χρειάζεται ρύθμιση homeassistant (broker)", False
                slug = "".join(c if c.isalnum() else "_" for c in pb["name"].lower()).strip("_") or "playbook"
                h._pub(f"netwatch/playbook/{slug}", {"playbook": pb["name"], "alert": a["type"], "actor": ip, "t": int(now)})
                return f"MQTT → netwatch/playbook/{slug}", True
        except ValueError as e:  # π.χ. «δεν μπλοκάρω τον router»
            return str(e), False
        except Exception as e:
            return f"σφάλμα: {str(e)[:120]}", False
        return "άγνωστη ενέργεια", False

    def undo(self, run_id):
        with self.lock:
            r = next((x for x in self.runs if x["id"] == run_id), None)
        if not r or r["undone"] or r["dry"]:
            return False
        if r["action"] == "block" and self.state.blocker:
            self.state.blocker.unblock(r["actor"])
            with self.lock:
                self.expiry.pop(r["actor"], None)
        r["undone"] = True
        return True

    def expire(self, now=None):
        now = now or time.time()
        with self.lock:
            due = [ip for ip, t in self.expiry.items() if t <= now]
            for ip in due:
                self.expiry.pop(ip)
        for ip in due:
            if self.state.blocker:
                self.state.blocker.unblock(ip)
        return due

    def status(self):
        with self.lock:
            return {"playbooks": self.books, "errors": self.errors, "runs": self.runs[-60:][::-1],
                    "expiry": dict(self.expiry)}

    def run_forever(self):
        while True:
            time.sleep(20)
            self.expire()
