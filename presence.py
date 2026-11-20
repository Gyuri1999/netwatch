"""📈 Ιστορικό διαθεσιμότητας ανά συσκευή: πόσο % ήταν online, πόσες φορές «έπεσε», πόσο κράτησε η μεγαλύτερη διακοπή.

Κάθε 5′ σημειώνουμε ποιες συσκευές του LAN ακούστηκαν (παθητικά — ό,τι βλέπει ήδη το NetWatch: ARP, mDNS, DHCP,
κίνηση). Κρατάμε ΚΑΙ πότε έτρεχε το ίδιο το NetWatch, ώστε όταν ήταν κλειστό να μη μετράει ως «εκτός».
Μικρή SQLite (data/presence.sqlite), διατήρηση 30 ημερών. Τίποτα δεν φεύγει από τον υπολογιστή.
"""
import ipaddress
import os
import random
import sqlite3
import threading
import time

BUCKET = 300                 # 5 λεπτά
SEEN_WINDOW = 330            # «online» = ακούστηκε στα τελευταία 5,5′
KEEP_DAYS = 30
MIN_GAP = 2                  # διακοπή = ≥2 συνεχόμενα κενά δείγματα (≥10′)
ALWAYS_ON = {"router", "nas", "pi", "camera", "iot", "esp", "printer", "speaker", "vm"}


def _private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.version == 4 and a.is_private
    except ValueError:
        return False


class Presence:
    def __init__(self, state, path=None, sim=False, clock=time.time, on_save=None):
        self.state, self.sim, self.clock, self.on_save = state, sim, clock, on_save
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path or ":memory:", check_same_thread=False)
        with self.lock:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runs(b INTEGER PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS seen(b INTEGER, k TEXT, PRIMARY KEY(b, k)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, ip TEXT, name TEXT, icon TEXT, dtype TEXT);
            """)
            self.db.commit()
        if path and on_save:
            on_save(path)
        if sim:
            self._demo_fill()

    # ── καταγραφή ──
    def _online_now(self):
        now = self.clock()
        out = {}
        st = self.state
        with getattr(st, "lock", threading.RLock()):
            for ip, h in list((getattr(st, "hosts", {}) or {}).items()):
                if not isinstance(h, dict) or h.get("kind") != "local" or h.get("me") or not _private(ip):
                    continue
                k = (h.get("mac") or "").lower() or "ip:" + ip
                meta = (k, ip, h.get("alias") or next(iter(sorted(h.get("names") or [])), "") or h.get("rdns") or h.get("vendor") or "", h.get("dicon") or "", h.get("dtype") or "")
                if now - (h.get("last") or 0) <= SEEN_WINDOW:
                    out[k] = meta
                else:
                    out.setdefault(("meta", k), meta)
        return out

    def sample(self):
        b = int(self.clock() // BUCKET)
        cur = self._online_now()
        with self.lock:
            self.db.execute("INSERT OR IGNORE INTO runs VALUES(?)", (b,))
            for key, m in cur.items():
                if isinstance(key, str):
                    self.db.execute("INSERT OR IGNORE INTO seen VALUES(?,?)", (b, key))
                self.db.execute("INSERT INTO meta VALUES(?,?,?,?,?) ON CONFLICT(k) DO UPDATE SET ip=excluded.ip, "
                                "name=CASE WHEN excluded.name<>'' THEN excluded.name ELSE meta.name END, icon=excluded.icon, dtype=excluded.dtype", m)
            old = b - KEEP_DAYS * 86400 // BUCKET
            self.db.execute("DELETE FROM runs WHERE b<?", (old,))
            self.db.execute("DELETE FROM seen WHERE b<?", (old,))
            self.db.commit()
        return len([k for k in cur if isinstance(k, str)])

    def run_forever(self):
        time.sleep(30)
        while True:
            try:
                self.sample()
            except Exception:  # noqa: BLE001 — ποτέ να μη σταματήσει το νήμα
                pass
            time.sleep(BUCKET - (self.clock() % BUCKET) + 1)

    # ── ανάλυση ──
    def view(self, days=7, key=None):
        days = max(1, min(30, int(days or 7)))
        nb = int(self.clock() // BUCKET)
        b0 = nb - days * 86400 // BUCKET
        with self.lock:
            runs = [r[0] for r in self.db.execute("SELECT b FROM runs WHERE b>? ORDER BY b", (b0,))]
            seen = {}
            for b, k in self.db.execute("SELECT b, k FROM seen WHERE b>?", (b0,)):
                seen.setdefault(k, set()).add(b)
            meta = {r[0]: r[1:] for r in self.db.execute("SELECT k, ip, name, icon, dtype FROM meta")}
        if not runs:
            return {"days": days, "devices": [], "coverage": 0, "bucket": BUCKET, "since": b0 * BUCKET}
        hours = days * 24
        per_hour = BUCKET and 3600 // BUCKET
        devs = []
        for k, bs in seen.items():
            first = min(bs)
            rr = [b for b in runs if b >= first]
            if not rr:
                continue
            on = [b in bs for b in rr]
            # διακοπές: συνεχόμενα κενά δείγματα (μόνο όσο έτρεχε το NetWatch, χωρίς «τρύπες» > 30′ στα runs)
            outs, i, n = [], 0, len(rr)
            while i < n:
                if on[i]:
                    i += 1
                    continue
                j = i + 1
                while j < n and not on[j] and rr[j] - rr[j - 1] <= 6:
                    j += 1
                if j - i >= MIN_GAP:
                    if j == n:
                        end = None                      # ακόμα εκτός
                    elif on[j] and rr[j] - rr[j - 1] <= 6:
                        end = rr[j]                     # ξαναγύρισε
                    else:
                        end = rr[j - 1] + 1             # μετά έκλεισε το NetWatch — δεν ξέρουμε
                    outs.append({"start": rr[i] * BUCKET, "end": end and end * BUCKET, "min": ((end or nb + 1) - rr[i]) * BUCKET // 60})
                i = j
            hb = [None] * hours  # ανά ώρα: 0..1 ή None (NetWatch κλειστό / συσκευή άγνωστη ακόμα)
            cnt = {}
            for b, o in zip(rr, on):
                h = (b - b0) // per_hour
                if 0 <= h < hours:
                    c = cnt.setdefault(h, [0, 0])
                    c[0] += o
                    c[1] += 1
            for h, (a, n) in cnt.items():
                hb[h] = round(a / n, 2)
            ip, name, icon, dtype = meta.get(k, ("", "", "", ""))
            day = nb - 86400 // BUCKET
            d = {"key": k, "ip": ip, "name": name, "icon": icon, "dtype": dtype, "always_on": dtype in ALWAYS_ON,
                 "pct": round(100 * sum(on) / len(on), 1), "online": bool(on and on[-1] and rr[-1] >= nb - 1),
                 "outages": len(outs), "outages_24h": len([o for o in outs if o["start"] >= day * BUCKET]),
                 "longest_min": max([o["min"] for o in outs] or [0]), "last_seen": max(bs) * BUCKET, "hours": hb}
            if key and key == k:
                d["list"] = outs[-50:][::-1]
            devs.append(d)
        devs.sort(key=lambda d: (not d["always_on"], -d["outages_24h"], -d["outages"], d["pct"]))
        if key:
            devs = [d for d in devs if d["key"] == key]
        return {"days": days, "devices": devs, "coverage": round(100 * len(runs) / max(1, nb - b0), 1), "bucket": BUCKET, "since": b0 * BUCKET}

    # ── demo: 7 μέρες συνθετικά δεδομένα ──
    def _demo_fill(self):
        rnd = random.Random(7)
        nb = int(self.clock() // BUCKET)
        devs = [("aa:00:00:00:00:01", "192.168.1.1", "Router", "📶", "router", lambda h, d: True),
                ("aa:00:00:00:00:02", "192.168.1.40", "Κάμερα αυλής", "📷", "camera", lambda h, d: not (d >= 5 and 1 <= h < 4 and rnd.random() < .7) and rnd.random() > .02),
                ("aa:00:00:00:00:03", "192.168.1.17", "Raspberry Pi", "🍓", "pi", lambda h, d: True),
                ("aa:00:00:00:00:04", "192.168.1.60", "Κινητό Μαρίας", "📱", "phone", lambda h, d: not (9 <= h < 17 and d % 7 < 5)),
                ("aa:00:00:00:00:05", "192.168.1.70", "TV σαλονιού", "📺", "tv", lambda h, d: 18 <= h < 24),
                ("aa:00:00:00:00:06", "192.168.1.80", "Θερμοστάτης", "🌡", "iot", lambda h, d: rnd.random() > .06)]
        with self.lock:
            for b in range(nb - 7 * 288, nb + 1):
                if 2 * 288 < nb - b < 2 * 288 + 30:   # NetWatch κλειστό ~2,5 ώρες πριν 2 μέρες
                    continue
                self.db.execute("INSERT OR IGNORE INTO runs VALUES(?)", (b,))
                t = time.localtime(b * BUCKET)
                d = 6 - (nb - b) // 288
                for mac, ip, name, icon, dt, up in devs:
                    if up(t.tm_hour, d):
                        self.db.execute("INSERT OR IGNORE INTO seen VALUES(?,?)", (b, mac))
            for mac, ip, name, icon, dt, _ in devs:
                self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?,?,?,?)", (mac, ip, name, icon, dt))
            self.db.commit()
