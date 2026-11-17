"""📈 Οι «συνήθειες» κάθε συσκευής: σε ποιες χώρες μιλάει κανονικά.

Για κάθε συσκευή του τοπικού δικτύου (εκτός από τον υπολογιστή που τρέχει το NetWatch, που σερφάρει παντού)
το NetWatch μαθαίνει τις χώρες των προορισμών της για 24 ώρες. Μετά, αν μιλήσει για πρώτη φορά με νέα χώρα,
βγαίνει «Νέα χώρα για συσκευή» — ένα ESP32 που έστελνε μόνο στον broker και ξαφνικά μιλάει με server
σε άλλη ήπειρο είναι από τα πιο καθαρά σημάδια μόλυνσης.
Κλειδί είναι η MAC (οι IP αλλάζουν)· αποθήκευση στο data/baseline.json.
"""
import json
import os
import threading
import time

LEARN = 24 * 3600


class Baseline:
    def __init__(self, state, path=None, learn=LEARN):
        self.state, self.path, self.learn = state, path, learn
        self.lock = threading.Lock()
        self.dev = {}  # key → {first, ip, countries: {CC: first_t}}
        self._load()

    def _load(self):
        if self.path and os.path.exists(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    self.dev = json.load(f).get("devices", {})
            except (OSError, ValueError):
                pass

    def save(self):
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with self.lock:
                data = json.dumps({"devices": self.dev})
            with open(self.path + ".tmp", "w", encoding="utf-8") as f:
                f.write(data)
            os.replace(self.path + ".tmp", self.path)
            from core import chown_to_user
            chown_to_user(self.path)
        except OSError:
            pass

    def tick(self, now=None):
        """Διατρέχει τους προορισμούς κάθε τοπικής συσκευής. Επιστρέφει πόσες νέες χώρες βρήκε."""
        now = now or time.time()
        found = []
        st = self.state
        with st.lock:
            for ip, h in st.hosts.items():
                if h["kind"] != "local" or h.get("me") or h.get("gw") or not h["victims"]:
                    continue
                key = h.get("mac") or ip
                ccs = {}
                for dst in h["victims"]:
                    g = (st.hosts.get(dst) or {}).get("geo")
                    if g and g.get("countryCode"):
                        ccs.setdefault(g["countryCode"], (dst, g.get("country") or g["countryCode"], g.get("org") or g.get("isp") or ""))
                if not ccs:
                    continue
                with self.lock:
                    d = self.dev.setdefault(key, {"first": now, "ip": ip, "countries": {}})
                    d["ip"] = ip
                    learning = now - d["first"] < self.learn
                    for cc, info in ccs.items():
                        if cc not in d["countries"]:
                            d["countries"][cc] = now
                            if not learning:
                                found.append((ip, h, cc, info, sorted(d["countries"])))
        for ip, h, cc, (dst, country, org), known in found:
            import iotcheck
            iot = bool(iotcheck.kind_of(h.get("mac"), sorted(h.get("names") or ())))
            st.alert("Νέα χώρα για συσκευή", "med" if iot else "low", ip, dst,
                     f"Η {ip}{' (IoT)' if iot else ''} μίλησε για πρώτη φορά με {country} ({dst}{', ' + org if org else ''}). "
                     f"Μέχρι τώρα: {', '.join(c for c in known if c != cc) or '—'}. "
                     "Αν δεν άλλαξε κάτι (ενημέρωση, νέα εφαρμογή), δες τι είναι αυτός ο server.",
                     now, key=("newcc", ip, cc), cooldown=3600)
        if found:
            self.save()
        return len(found)

    def view(self):
        now = time.time()
        with self.lock:
            return [{"key": k, "ip": d["ip"], "countries": sorted(d["countries"]), "learning": now - d["first"] < self.learn,
                     "learn_left": max(0, int(self.learn - (now - d["first"])))} for k, d in sorted(self.dev.items())]

    def run(self):
        n = 0
        while True:
            time.sleep(60)
            try:
                self.tick()
            except Exception:
                pass
            n += 1
            if n % 15 == 0:
                self.save()
