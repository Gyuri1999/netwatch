"""📈 Καθυστέρηση σε βάθος χρόνου (σαν το SmokePing): latency, jitter και απώλειες προς router, DNS και πάροχο.

config.yaml:
latency:
  enabled: true
  interval: 60          # δευτερόλεπτα ανάμεσα στους γύρους
  db: data/latency.db   # ιστορικό σε SQLite (κρατάμε 30 μέρες)
  targets:
    - {name: Router, host: 192.168.1.1}
    - {name: Cloudflare, host: 1.1.1.1}
Αν δεν γράψεις στόχους: router (gateway), 1.1.1.1, 8.8.8.8 και — αν είναι γνωστό — το πρώτο δημόσιο hop του παρόχου.

Κάθε γύρος = 10 ping (ένα κάθε 0,2″) με το ping του συστήματος· κρατάμε ελάχιστο/διάμεσο/μέγιστο, απώλειες και jitter.
Οι «κακές ώρες» (ώρες της μέρας με τον χειρότερο διάμεσο/απώλειες τις τελευταίες 7 μέρες) δείχνουν π.χ. ότι
«ο πάροχος σέρνεται κάθε βράδυ».
Ειδοποιήσεις: «Απώλειες πακέτων» (≥ 20 % για 3 γύρους) και «Υψηλή καθυστέρηση» (διάμεσος > 3× της βάσης 24 ωρών και > 50 ms για 3 γύρους).
"""
import math
import os
import random
import re
import sqlite3
import statistics
import subprocess
import sys
import threading
import time

PINGS = 10
PING_GAP = 0.2
KEEP_DAYS = 30
STREAK = 3
LOSS_ALERT = 20.0
SLOW_FACTOR = 3.0
SLOW_MIN_MS = 50.0
ALERT_COOLDOWN = 3600
DEFAULT_DB = os.path.join("data", "latency.db")
DEFAULT_PUBLIC = [{"name": "Cloudflare DNS", "host": "1.1.1.1"}, {"name": "Google DNS", "host": "8.8.8.8"}]
ISP_NAME = "Πάροχος (1ο δημόσιο hop)"

_RTT = re.compile(r"(?:icmp_)?seq[=\s]?\d+.*?time\s*[=<]\s*([\d.]+)\s*ms", re.I)
_SUM = re.compile(r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received", re.I)


# ── ping ──
def ping_cmd(host, count=PINGS, gap=PING_GAP, platform=None):
    platform = platform or sys.platform
    deadline = str(int(math.ceil(count * gap + 3)))
    if platform == "darwin":
        exe = "ping6" if ":" in host else "ping"
        return [exe, "-c", str(count), "-i", str(gap), *(["-t", deadline] if exe == "ping" else []), "-n", host]
    return ["ping", "-n", "-c", str(count), "-i", str(gap), "-w", deadline, host]


def parse_ping(out, count=PINGS):
    """Έξοδος ping (macOS ή Linux) → (λίστα χρόνων ms, πόσα στάλθηκαν)."""
    rtts = [float(m.group(1)) for m in _RTT.finditer(out or "")]
    m = _SUM.search(out or "")
    sent = int(m.group(1)) if m else count
    return rtts, max(sent, len(rtts))


def summarize(rtts, sent):
    """Στατιστικά ενός γύρου: min/med/max (ms), loss (%), jitter (μέση |διαφορά| διαδοχικών, ms)."""
    sent = max(int(sent or 0), len(rtts), 1)
    loss = round(100.0 * (sent - len(rtts)) / sent, 1)
    if not rtts:
        return {"sent": sent, "recv": 0, "min": None, "med": None, "max": None, "loss": loss, "jitter": None}
    jit = statistics.mean(abs(a - b) for a, b in zip(rtts, rtts[1:])) if len(rtts) > 1 else 0.0
    return {"sent": sent, "recv": len(rtts), "min": round(min(rtts), 3), "med": round(statistics.median(rtts), 3),
            "max": round(max(rtts), 3), "loss": loss, "jitter": round(jit, 3)}


def ping_round(host, count=PINGS, gap=PING_GAP):
    if sys.platform == "win32":
        import winplat
        return summarize(*parse_ping(winplat.ping(host, count, 1500), count))
    cmd = ping_cmd(host, count, gap)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=count * gap + 8).stdout
    except (subprocess.TimeoutExpired, OSError):
        out = ""
    return summarize(*parse_ping(out, count))


def _resolve(v):
    try:
        return v() if callable(v) else v
    except Exception:
        return None


def _auto_gateway():
    try:
        import netkit
        return netkit._default_gateway()[0]
    except Exception:
        return None


def normalize(cfg_targets, gateway=None, isp_hop=None):
    """Λίστα στόχων [{name, host}] (χωρίς διπλότυπα). Κενή ρύθμιση → router + 1.1.1.1 + 8.8.8.8 + hop παρόχου."""
    raw = list(cfg_targets or [])
    if not raw:
        gw = _resolve(gateway)
        if gw:
            raw.append({"name": "Router", "host": gw, "role": "gateway"})
        raw += [dict(x, role="public") for x in DEFAULT_PUBLIC]
        hop = _resolve(isp_hop)
        if hop:
            raw.append({"name": ISP_NAME, "host": hop, "role": "isp"})
    out, seen = [], set()
    for c in raw:
        if not isinstance(c, dict) or not c.get("host"):
            continue
        host = str(c["host"]).strip()
        if not re.fullmatch(r"[A-Za-z0-9.:\-]+", host) or host.startswith("-") or host in seen:
            continue
        seen.add(host)
        out.append({"name": str(c.get("name") or host)[:40], "host": host, "role": c.get("role")})
    return out


# ── αποθήκευση ──
class Store:
    def __init__(self, path):
        self.path = path
        if path != ":memory:":
            d = os.path.dirname(os.path.abspath(path))
            os.makedirs(d, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock, self.db:
            self.db.execute("CREATE TABLE IF NOT EXISTS rounds (t REAL NOT NULL, target TEXT NOT NULL, host TEXT, sent INTEGER, recv INTEGER,"
                            " min REAL, med REAL, max REAL, loss REAL, jitter REAL)")
            self.db.execute("CREATE INDEX IF NOT EXISTS rounds_tt ON rounds (target, t)")

    def add(self, t, target, host, r):
        self.add_many([(t, target, host, r)])

    def add_many(self, rows):
        with self.lock, self.db:
            self.db.executemany("INSERT INTO rounds VALUES (?,?,?,?,?,?,?,?,?,?)",
                                [(t, n, h, r["sent"], r["recv"], r["min"], r["med"], r["max"], r["loss"], r["jitter"]) for t, n, h, r in rows])

    def rows(self, target, since, until=None):
        with self.lock:
            return self.db.execute("SELECT t, min, med, max, loss, jitter FROM rounds WHERE target=? AND t>=? AND t<=? ORDER BY t",
                                   (target, since, until if until is not None else 9e18)).fetchall()

    def last(self, target):
        with self.lock:
            r = self.db.execute("SELECT t, sent, recv, min, med, max, loss, jitter FROM rounds WHERE target=? ORDER BY t DESC LIMIT 1",
                                (target,)).fetchone()
        return dict(zip(("t", "sent", "recv", "min", "med", "max", "loss", "jitter"), r)) if r else None

    def count(self, target=None):
        with self.lock:
            q = "SELECT COUNT(*) FROM rounds" + (" WHERE target=?" if target else "")
            return self.db.execute(q, (target,) if target else ()).fetchone()[0]

    def prune(self, now=None, keep_days=KEEP_DAYS):
        with self.lock, self.db:
            return self.db.execute("DELETE FROM rounds WHERE t < ?", ((now or time.time()) - keep_days * 86400,)).rowcount

    def close(self):
        with self.lock:
            self.db.close()


def _bucket(rows, step):
    """Συγχωνεύει γύρους σε κουτάκια `step` δευτερολέπτων (min των min, διάμεσος των διαμέσων, max των max, μέση απώλεια)."""
    out, cur, key = [], [], None
    for r in rows:
        k = int(r[0] // step)
        if key is not None and k != key:
            out.append(cur)
            cur = []
        key = k
        cur.append(r)
    if cur:
        out.append(cur)
    res = []
    for g in out:
        meds = [r[2] for r in g if r[2] is not None]
        mins = [r[1] for r in g if r[1] is not None]
        maxs = [r[3] for r in g if r[3] is not None]
        jits = [r[5] for r in g if r[5] is not None]
        res.append((g[len(g) // 2][0], min(mins) if mins else None, statistics.median(meds) if meds else None,
                    max(maxs) if maxs else None, round(statistics.mean(r[4] for r in g), 1),
                    round(statistics.mean(jits), 3) if jits else None))
    return res


def bad_hours(rows, top=3):
    """rows: [(t, min, med, max, loss, …)] → μέσος διάμεσος/απώλεια ανά ώρα της μέρας (τοπική ώρα) + οι χειρότερες ώρες."""
    per = {h: {"med": [], "loss": []} for h in range(24)}
    for r in rows:
        h = time.localtime(r[0]).tm_hour
        per[h]["loss"].append(r[4] or 0.0)
        if r[2] is not None:
            per[h]["med"].append(r[2])
    allmed = [m for p in per.values() for m in p["med"]]
    overall = statistics.median(allmed) if allmed else None
    allloss = [x for p in per.values() for x in p["loss"]]
    overall_loss = statistics.mean(allloss) if allloss else 0.0
    hours = []
    for h in range(24):
        p = per[h]
        hours.append({"hour": h, "median": round(statistics.median(p["med"]), 2) if p["med"] else None,
                      "loss": round(statistics.mean(p["loss"]), 2) if p["loss"] else None, "n": len(p["loss"])})
    worst = []
    if overall:
        def score(x):
            return (x["median"] or overall) / overall + (x["loss"] or 0) / 5.0
        cand = [x for x in hours if x["n"] and ((x["median"] or 0) >= 1.3 * overall or (x["loss"] or 0) >= max(2.0, 2 * overall_loss))]
        worst = sorted(sorted(cand, key=score, reverse=True)[:top], key=lambda x: x["hour"])
    if not allloss:
        summary = "Δεν υπάρχει ακόμη αρκετό ιστορικό."
    elif not worst:
        summary = "Καμία ώρα της μέρας δεν ξεχωρίζει — η σύνδεση είναι σταθερή όλο το 24ωρο."
    else:
        parts = [f"{x['hour']:02d}:00 (διάμεσος {x['median']:.0f} ms, απώλειες {x['loss']:.1f} %)" if x["median"] is not None
                 else f"{x['hour']:02d}:00 (απώλειες {x['loss']:.1f} %)" for x in worst]
        summary = f"Χειρότερες ώρες: {', '.join(parts)} — έναντι διάμεσου {overall:.0f} ms συνολικά."
    return {"hours": hours, "worst": [x["hour"] for x in worst], "overall_median": round(overall, 2) if overall else None,
            "overall_loss": round(overall_loss, 2), "summary": summary}


# ── demo ──
def _sim_round(target, now, rnd):
    """Εύλογος γύρος για το demo: βραδινό «φούσκωμα», σπάνιες αιχμές, ένα μικρό outage πριν από 2 μέρες."""
    role, host = target.get("role"), target["host"]
    base = {"gateway": 1.4, "isp": 6.5}.get(role) or (11.0 if host == "1.1.1.1" else 15.5 if host == "8.8.8.8" else 20.0)
    lt = time.localtime(now)
    h = lt.tm_hour + lt.tm_min / 60.0
    bump = 0.0 if role == "gateway" else max(0.0, 1 - abs(h - 21.0) / 2.5)  # κορύφωμα γύρω στις 21:00
    med = base * (1 + 2.2 * bump) + rnd.gauss(0, base * 0.06)
    loss_p = 0.002 + 0.03 * bump
    day = int(now // 86400)
    outage_day = int((time.time() - 2 * 86400) // 86400)
    if role != "gateway" and day == outage_day and 3 * 3600 + 600 <= now % 86400 < 3 * 3600 + 1320:
        loss_p = 1.0
    if host == "8.8.8.8" and int(now / 60) % 45 < 4:  # ζωντανό επεισόδιο απωλειών για να φαίνεται η ειδοποίηση
        loss_p = max(loss_p, 0.3)
    if rnd.random() < 0.01:
        med *= rnd.uniform(3, 6)
    rtts = [max(0.2, med + rnd.gauss(0, base * (0.08 + 0.25 * bump))) for _ in range(PINGS) if rnd.random() >= loss_p]
    if rtts and rnd.random() < 0.15:
        rtts[rnd.randrange(len(rtts))] *= rnd.uniform(1.5, 3)
    return summarize([round(x, 3) for x in rtts], PINGS)


SIM_TARGETS = [{"name": "Router", "host": "192.168.1.1", "role": "gateway"},
               {"name": "Cloudflare DNS", "host": "1.1.1.1", "role": "public"},
               {"name": "Google DNS", "host": "8.8.8.8", "role": "public"},
               {"name": ISP_NAME, "host": "100.64.0.1", "role": "isp"}]


class Latency:
    def __init__(self, state=None, cfg=None, sim=False, gateway=None, isp_hop=None, db_path=None, pinger=None):
        cfg = cfg or {}
        self.state, self.sim = state, sim
        self.enabled = bool(cfg.get("enabled", True))
        self.interval = max(5, int(cfg.get("interval") or 60))
        self._cfg_targets, self._gateway, self._isp_hop = cfg.get("targets"), gateway if gateway is not None else _auto_gateway, isp_hop
        self.targets = SIM_TARGETS if sim and not cfg.get("targets") else normalize(cfg.get("targets"), self._gateway, self._isp_hop)
        path = db_path or cfg.get("db") or (":memory:" if sim else DEFAULT_DB)
        self.store = Store(path)
        self.pinger = pinger or ping_round
        self.lock = threading.Lock()
        self.streak = {}  # name → {"loss": n, "slow": n}
        self._base = {}   # name → (υπολογίστηκε, τιμή)
        self._bad = {}
        self._last_prune = 0
        self.rnd = random.Random(7)
        if sim:
            self.backfill()

    def _refresh_targets(self):
        """Αν το hop του παρόχου έγινε γνωστό αργότερα, το προσθέτουμε (μόνο για αυτόματους στόχους)."""
        if self.sim or self._cfg_targets or any(t.get("role") == "isp" for t in self.targets) or not self._isp_hop:
            return
        hop = _resolve(self._isp_hop)
        if hop and all(t["host"] != hop for t in self.targets):
            self.targets = self.targets + [{"name": ISP_NAME, "host": hop, "role": "isp"}]

    def backfill(self, days=7, step=180, now=None):
        """Demo: γεμίζει γρήγορα τις τελευταίες `days` μέρες (μόνο αν η βάση είναι άδεια)."""
        if self.store.count():
            return 0
        now = now or time.time()
        rows = []
        t = now - days * 86400
        while t < now:
            for tg in self.targets:
                rows.append((t, tg["name"], tg["host"], _sim_round(tg, t, self.rnd)))
            t += step
        self.store.add_many(rows)
        return len(rows)

    def baseline(self, name, now=None):
        """Διάμεσος των διαμέσων του τελευταίου 24ώρου (cache 10′). None αν υπάρχουν < 10 γύροι."""
        now = now or time.time()
        c = self._base.get(name)
        if c and now - c[0] < 600:
            return c[1]
        meds = [r[2] for r in self.store.rows(name, now - 86400, now) if r[2] is not None]
        v = statistics.median(meds) if len(meds) >= 10 else None
        self._base[name] = (now, v)
        return v

    def measure(self, tg, now):
        if self.sim:
            return _sim_round(tg, now, self.rnd)
        return self.pinger(tg["host"])

    def round(self, now=None):
        now = now or time.time()
        self._refresh_targets()
        res = {}
        if self.sim:
            for tg in self.targets:
                res[tg["name"]] = self.measure(tg, now)
        else:
            def one(tg):
                try:
                    res[tg["name"]] = self.measure(tg, now)
                except Exception:
                    res[tg["name"]] = summarize([], PINGS)
            th = [threading.Thread(target=one, args=(tg,), daemon=True) for tg in self.targets]
            for x in th:
                x.start()
            for x in th:
                x.join(PINGS * PING_GAP + 15)
        return self.record(res, now)

    def record(self, res, now):
        """Αποθηκεύει τα αποτελέσματα ενός γύρου ({όνομα: summarize(...)}) και ελέγχει τα κατώφλια."""
        events = []
        rows = []
        for tg in self.targets:
            r = res.get(tg["name"])
            if r is None:
                continue
            base = self.baseline(tg["name"], now)  # πριν προστεθεί ο τρέχων γύρος
            rows.append((now, tg["name"], tg["host"], r))
            with self.lock:
                s = self.streak.setdefault(tg["name"], {"loss": 0, "slow": 0})
                s["loss"] = s["loss"] + 1 if r["loss"] >= LOSS_ALERT else 0
                slow = r["med"] is not None and base is not None and r["med"] > SLOW_FACTOR * base and r["med"] > SLOW_MIN_MS
                s["slow"] = s["slow"] + 1 if slow else 0
                if s["loss"] >= STREAK:
                    events.append(("Απώλειες πακέτων", "med", tg,
                                   f"Το «{tg['name']}» ({tg['host']}) χάνει {r['loss']:.0f} % των πακέτων εδώ και {s['loss']} γύρους "
                                   f"(όριο {LOSS_ALERT:.0f} %). Έλεγξε καλώδιο/Wi‑Fi ή τον πάροχο."))
                if s["slow"] >= STREAK:
                    events.append(("Υψηλή καθυστέρηση", "low", tg,
                                   f"Ο διάμεσος χρόνος προς «{tg['name']}» ({tg['host']}) είναι {r['med']:.0f} ms — πάνω από "
                                   f"{SLOW_FACTOR:.0f}× το συνηθισμένο του 24ώρου ({base:.0f} ms) για {s['slow']} γύρους."))
        self.store.add_many(rows)
        if self.state is not None:
            for typ, sev, tg, detail in events:
                self.state.alert(typ, sev, tg["host"], tg["name"], detail, now, key=(typ, tg["name"]),
                                 cooldown=ALERT_COOLDOWN, mark=False)
        if now - self._last_prune > 3600:
            self._last_prune = now
            self.store.prune(now)
        return events

    def _find(self, target):
        for tg in self.targets:
            if target in (tg["name"], tg["host"]):
                return tg
        return {"name": target, "host": target}

    def history(self, target, hours=24, max_points=1500, now=None):
        """Πίνακες για γράφημα τύπου SmokePing: t, median, min, max, loss, jitter (null όπου δεν απάντησε)."""
        now = now or time.time()
        tg = self._find(target)
        rows = self.store.rows(tg["name"], now - hours * 3600, now)
        step = None
        if max_points and len(rows) > max_points:
            step = int(math.ceil(hours * 3600 / max_points))
            rows = _bucket(rows, step)
        return {"target": tg["name"], "host": tg["host"], "hours": hours, "step": step,
                "t": [round(r[0], 1) for r in rows], "median": [r[2] for r in rows], "min": [r[1] for r in rows],
                "max": [r[3] for r in rows], "loss": [r[4] for r in rows], "jitter": [r[5] for r in rows]}

    def bad_hours(self, target, days=7, now=None):
        now = now or time.time()
        tg = self._find(target)
        c = self._bad.get((tg["name"], days))
        if c and now - c[0] < 300:
            return c[1]
        v = bad_hours(self.store.rows(tg["name"], now - days * 86400, now))
        self._bad[(tg["name"], days)] = (now, v)
        return v

    def status(self, now=None):
        now = now or time.time()
        out = []
        for tg in self.targets:
            last = self.store.last(tg["name"])
            spark = [r[2] for r in self.store.rows(tg["name"], now - 3600, now)][-60:]
            with self.lock:
                s = dict(self.streak.get(tg["name"], {"loss": 0, "slow": 0}))
            base = self.baseline(tg["name"], now)
            out.append({"name": tg["name"], "host": tg["host"], "role": tg.get("role"), "last": last,
                        "baseline": round(base, 2) if base is not None else None, "streak": s, "spark": spark,
                        "bad_hours": self.bad_hours(tg["name"], now=now)})
        return {"enabled": self.enabled, "demo": self.sim, "interval": self.interval, "pings": PINGS,
                "keep_days": KEEP_DAYS, "targets": out}

    def run_forever(self):
        while True:
            try:
                self.round()
            except Exception:
                pass
            time.sleep(self.interval if not self.sim else 15)
