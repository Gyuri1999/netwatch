"""⏱ Μηχανή του χρόνου — «γύρνα» το δίκτυο σε οποιοδήποτε λεπτό του τελευταίου 24ώρου.

Κάθε πακέτο που βλέπει ο ανιχνευτής περνά από το observe(): μετράμε bytes/πακέτα ανά συσκευή του LAN και
ανά ζεύγος «συσκευή ↔ προορισμός» μέσα σε κουβάδες του ενός λεπτού. Όταν κλείσει το λεπτό, κρατάμε μόνο τα
πιο «βαριά» ζεύγη (TOP_EDGES) — αρκετά για να ξαναζωγραφίσεις τον γράφο, χωρίς να γεμίσει η μνήμη.

Στη λειτουργία demo συμπληρώνεται ένα ρεαλιστικό 24ωρο (πρωινό, βραδινό streaming, νυχτερινά backups) ώστε
το slider να έχει κάτι να δείξει από την πρώτη στιγμή.
"""
import collections
import gzip
import ipaddress
import json
import math
import os
import random
import threading
import time

STEP = 60          # δευτερόλεπτα ανά κουβά
KEEP = 24 * 60     # 24 ώρες
TOP_EDGES = 60
TOP_DEVICES = 80


def _private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_multicast and not a.is_loopback and not a.is_link_local
    except ValueError:
        return False


def _public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global and not a.is_multicast
    except ValueError:
        return False


class Timeline:
    def __init__(self, state, sim=False, path=None, step=STEP, keep=KEEP, clock=time.time):
        self.st, self.sim, self.path, self.step, self.keep, self.clock = state, sim, path, step, keep, clock
        self.lock = threading.Lock()
        self.buckets = collections.deque(maxlen=keep)   # κλεισμένα λεπτά (dict)
        self.cur = None                                  # ανοιχτός κουβάς
        self.meta = {}                                   # ip → {name, icon, cc, country}: τελευταία γνωστά
        self._dirty = 0
        if path:
            self._load()
        if sim:
            self._backfill()

    # ───────── καταγραφή ─────────
    def _new(self, b):
        return {"t": b, "pkts": 0, "bytes": 0, "dev": collections.defaultdict(lambda: [0, 0, 0]),
                "edge": collections.defaultdict(lambda: [0, 0, None])}

    def observe(self, P, t):
        src, dst = P.get("src"), P.get("dst")
        if not src or not dst:
            return
        n = int(P.get("len") or 60)
        b = int(t // self.step) * self.step
        with self.lock:
            if self.cur is None or b != self.cur["t"]:
                if self.cur is not None and b > self.cur["t"]:
                    self._close()
                if self.cur is None or b > self.cur["t"]:
                    self.cur = self._new(b)
                elif b < self.cur["t"]:   # πακέτο από το παρελθόν (pcap): το αγνοούμε
                    return
            c = self.cur
            c["pkts"] += 1
            c["bytes"] += n
            sl, dl = _private(src), _private(dst)
            if sl:
                d = c["dev"][src]; d[1] += n; d[2] += 1
            if dl:
                d = c["dev"][dst]; d[0] += n; d[2] += 1
            if sl or dl:
                dev, other = (src, dst) if sl else (dst, src)
                if sl and dl:      # LAN ↔ LAN: κλειδί με σταθερή σειρά
                    dev, other = sorted((src, dst))
                if other.startswith(("224.", "239.", "255.", "ff")) or other.endswith(".255"):
                    return
                e = c["edge"][(dev, other)]
                e[0] += n; e[1] += 1
                if e[2] is None:
                    proto = P.get("proto")
                    port = P.get("dp") if sl else P.get("sp")
                    e[2] = f"{proto}/{port}" if port else proto

    def _close(self):
        c = self.cur
        if not c:
            return
        edges = sorted(c["edge"].items(), key=lambda kv: -kv[1][0])[:TOP_EDGES]
        devs = sorted(c["dev"].items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:TOP_DEVICES]
        out = {"t": c["t"], "pkts": c["pkts"], "bytes": c["bytes"],
               "dev": {ip: v[:] for ip, v in devs},
               "edge": [[a, b, v[0], v[1], v[2]] for (a, b), v in edges]}
        for ip in list(out["dev"]) + [e[1] for e in out["edge"]]:
            self._remember(ip)
        self.buckets.append(out)
        self._dirty += 1
        if self.path and self._dirty >= 10:
            self._dirty = 0
            threading.Thread(target=self.save, daemon=True).start()

    def _remember(self, ip):
        st = self.st
        try:
            h = st.hosts.get(ip) if st is not None else None
        except Exception:
            h = None
        if not h:
            return
        m = self.meta.get(ip) or {}
        names = sorted(h.get("names") or [])
        nm = None
        try:
            nm = st.names_for(ip) if hasattr(st, "names_for") else None
        except Exception:
            nm = None
        if isinstance(nm, (list, tuple, set)):
            nm = next(iter(sorted(nm)), None)
        m["name"] = nm or (names[0] if names else None) or h.get("rdns") or m.get("name")
        geo = h.get("geo") or {}
        if geo.get("countryCode"):
            m["cc"], m["country"] = geo.get("countryCode"), geo.get("country")
        if h.get("kind") == "local":
            try:
                dt = st._dtype(h) if hasattr(st, "_dtype") else {}
            except Exception:
                dt = {}
            if dt.get("dicon"):
                m["icon"] = dt["dicon"]
            if dt.get("dlabel"):
                m["kind"] = dt["dlabel"]
            m["gw"], m["me"] = bool(h.get("gw")), bool(h.get("me"))
        self.meta[ip] = m

    def tick(self):
        """Κλείνει τον τρέχοντα κουβά όταν περάσει το λεπτό ακόμη κι αν δεν έρθει άλλο πακέτο."""
        now = self.clock()
        with self.lock:
            if self.cur and now >= self.cur["t"] + self.step + 2:
                self._close()
                self.cur = None

    def run_forever(self):
        while True:
            time.sleep(5)
            try:
                self.tick()
            except Exception:
                pass

    # ───────── ερωτήματα ─────────
    def summary(self, hours=24):
        now = self.clock()
        since = now - hours * 3600
        with self.lock:
            bs = [b for b in self.buckets if b["t"] >= since]
            cur = self.cur
        alerts = self._alerts(since, now + 60)
        per = collections.Counter(int(a["t"] // self.step) * self.step for a in alerts)
        rank, sev = {"high": 3, "med": 2, "low": 1}, {}
        for a in alerts:
            k = int(a["t"] // self.step) * self.step
            if rank.get(a.get("sev"), 0) > rank.get(sev.get(k), 0):
                sev[k] = a.get("sev")
        out = [{"t": b["t"], "bytes": b["bytes"], "pkts": b["pkts"], "devices": len(b["dev"]),
                "alerts": per.get(b["t"], 0), "sev": sev.get(b["t"])} for b in bs]
        if cur and cur["t"] >= since:
            out.append({"t": cur["t"], "bytes": cur["bytes"], "pkts": cur["pkts"], "devices": len(cur["dev"]),
                        "alerts": per.get(cur["t"], 0), "sev": sev.get(cur["t"]), "open": True})
        return {"step": self.step, "now": now, "from": out[0]["t"] if out else now, "to": now,
                "buckets": out, "demo": self.sim}

    def _alerts(self, t0, t1):
        try:
            al = list(self.st.alerts)
        except Exception:
            return []
        return [a for a in al if t0 <= a.get("t", 0) < t1 and not a.get("selftest")]

    def at(self, t, span=1):
        """Η εικόνα του δικτύου στο λεπτό t (ή άθροισμα span λεπτών που τελειώνουν στο t)."""
        span = max(1, min(60, int(span)))
        b = int(float(t) // self.step) * self.step
        lo = b - (span - 1) * self.step
        with self.lock:
            bs = [x for x in self.buckets if lo <= x["t"] <= b]
            if self.cur and lo <= self.cur["t"] <= b:
                c = self.cur
                bs.append({"t": c["t"], "pkts": c["pkts"], "bytes": c["bytes"],
                           "dev": {ip: v[:] for ip, v in c["dev"].items()},
                           "edge": [[a, bb, v[0], v[1], v[2]] for (a, bb), v in c["edge"].items()]})
            meta = dict(self.meta)
        dev, edge, tot = collections.defaultdict(lambda: [0, 0, 0]), {}, [0, 0]
        for x in bs:
            tot[0] += x["bytes"]; tot[1] += x["pkts"]
            for ip, v in x["dev"].items():
                d = dev[ip]; d[0] += v[0]; d[1] += v[1]; d[2] += v[2]
            for a, bb, nb, np_, pp in x["edge"]:
                e = edge.setdefault((a, bb), [0, 0, pp])
                e[0] += nb; e[1] += np_
        for ip in list(dev) + [k[1] for k in edge]:
            if ip not in meta:
                self._remember(ip)
                if ip in self.meta:
                    meta[ip] = self.meta[ip]

        def m(ip, k):
            return (meta.get(ip) or {}).get(k)
        devices = [{"ip": ip, "name": m(ip, "name"), "icon": m(ip, "icon"), "kind": m(ip, "kind"),
                    "gw": bool(m(ip, "gw")), "me": bool(m(ip, "me")),
                    "bytes_in": v[0], "bytes_out": v[1], "pkts": v[2]}
                   for ip, v in sorted(dev.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))]
        edges = [{"dev": a, "peer": bb, "bytes": v[0], "pkts": v[1], "proto": v[2],
                  "lan": _private(bb), "name": m(bb, "name"), "cc": m(bb, "cc"), "country": m(bb, "country")}
                 for (a, bb), v in sorted(edge.items(), key=lambda kv: -kv[1][0])[:TOP_EDGES]]
        al = self._alerts(lo, b + self.step)
        alerts = [{k: a.get(k) for k in ("id", "t", "type", "sev", "actor", "target", "detail", "lab")} for a in al][:40]
        return {"t": b, "from": lo, "span": span, "step": self.step, "found": bool(bs),
                "bytes": tot[0], "pkts": tot[1], "devices": devices, "edges": edges, "alerts": alerts}

    # ───────── αποθήκευση ─────────
    def save(self):
        if not self.path:
            return
        with self.lock:
            data = {"v": 1, "step": self.step, "buckets": list(self.buckets), "meta": self.meta}
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with gzip.open(tmp, "wt", encoding="utf-8") as f:
                json.dump(data, f, separators=(",", ":"))
            os.replace(tmp, self.path)
        except OSError:
            pass

    def _load(self):
        try:
            with gzip.open(self.path, "rt", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        if data.get("step") != self.step:
            return
        cutoff = self.clock() - self.keep * self.step
        for b in data.get("buckets", []):
            if b.get("t", 0) >= cutoff:
                self.buckets.append(b)
        self.meta.update(data.get("meta") or {})

    # ───────── demo: ένα ρεαλιστικό 24ωρο ─────────
    def _backfill(self):
        rnd = random.Random(7)
        now = self.clock()
        end = int(now // self.step) * self.step
        D = {  # συσκευή → (όνομα, εικονίδιο, προορισμοί [(ip, όνομα, cc, χώρα, proto, kbps βάσης)], προφίλ ωρών)
            "192.168.1.23": ("MacBook (εσύ)", "💻", [("140.82.112.3", "github.com", "US", "United States", "TCP/443", 30),
                                                     ("142.250.184.142", "www.google.com", "US", "United States", "TCP/443", 40),
                                                     ("151.101.1.140", "reddit.com", "US", "United States", "TCP/443", 25),
                                                     ("104.16.132.229", "cloudflare.com", "US", "United States", "UDP/443", 20)], "work"),
            "192.168.1.31": ("Smart TV σαλονιού", "📺", [("23.246.0.135", "nflxvideo.net", "NL", "Netherlands", "TCP/443", 900),
                                                        ("142.250.180.14", "youtube.com", "US", "United States", "UDP/443", 500),
                                                        ("34.98.75.36", "lgtvsdp.com", "US", "United States", "TCP/443", 4)], "evening"),
            "192.168.1.33": ("Κάμερα εισόδου (Tapo)", "📷", [("52.57.110.21", "tplinkcloud.com", "DE", "Germany", "TCP/443", 60),
                                                             ("162.159.200.123", "ntp.org", "NL", "Netherlands", "UDP/123", 0.2)], "flat"),
            "192.168.1.15": ("iPhone", "📱", [("17.253.144.10", "apple.com", "US", "United States", "TCP/443", 15),
                                              ("157.240.27.35", "instagram.com", "IE", "Ireland", "TCP/443", 120),
                                              ("31.13.84.51", "whatsapp.net", "IE", "Ireland", "TCP/5222", 3)], "day"),
            "192.168.1.40": ("Εκτυπωτής", "🖨", [("15.72.34.70", "hpeprint.com", "US", "United States", "TCP/5222", 0.3)], "flat"),
            "192.168.1.20": ("ESP32 κήπου", "🌱", [("192.168.1.17", "mqtt broker", None, None, "TCP/1883", 0.5)], "flat"),
            "192.168.1.17": ("Raspberry Pi (NAS)", "🍓", [("185.199.108.153", "backblazeb2.com", "US", "United States", "TCP/443", 2500)], "night"),
            "192.168.1.52": ("Πρίζα κουζίνας", "🔌", [("3.120.20.11", "tuyaeu.com", "DE", "Germany", "TCP/8883", 0.4)], "flat"),
        }
        prof = {
            "work": lambda h: 1.0 if 9 <= h < 18 else 0.35 if 7 <= h < 23 else 0.03,
            "evening": lambda h: 1.0 if 19 <= h < 24 else 0.15 if 13 <= h < 19 else 0.0,
            "flat": lambda h: 1.0,
            "day": lambda h: 0.9 if 8 <= h < 24 else 0.08,
            "night": lambda h: 1.0 if 2 <= h < 4 else 0.0,
        }
        self.meta["192.168.1.1"] = {"name": "Router", "icon": "📡", "gw": True}
        for ip, (nm, ic, dests, _) in D.items():
            self.meta[ip] = {"name": nm, "icon": ic, "me": ip == "192.168.1.23"}
            for dip, dn, cc, cn, _, _ in dests:
                self.meta.setdefault(dip, {"name": dn, "cc": cc, "country": cn})
        for i in range(self.keep, 0, -1):
            b = end - i * self.step
            hr = time.localtime(b).tm_hour + time.localtime(b).tm_min / 60
            x = {"t": b, "pkts": 0, "bytes": 0, "dev": {}, "edge": []}
            for ip, (nm, ic, dests, p) in D.items():
                w = prof[p](int(hr))
                if w <= 0:
                    continue
                din = dout = pk = 0
                for dip, dn, cc, cn, pp, kbps in dests:
                    v = kbps * 1000 / 8 * self.step * w * (0.6 + 0.8 * rnd.random()) * (0.85 + 0.3 * math.sin(hr / 3))
                    if v < 200 and rnd.random() > 0.3:
                        continue
                    nb = int(v)
                    n_p = max(1, nb // 900)
                    up = 0.08 if p in ("evening", "day") else 0.9 if p == "night" else 0.4
                    din += int(nb * (1 - up)); dout += int(nb * up); pk += n_p
                    x["edge"].append([ip, dip, nb, n_p, pp])
                if pk:
                    x["dev"][ip] = [din, dout, pk]
                    x["bytes"] += din + dout
                    x["pkts"] += pk
            # ο router «βλέπει» τα πάντα: DNS κάθε λεπτό
            x["dev"]["192.168.1.1"] = [4000, 3000, 40]
            # ένα επεισόδιο: η κάμερα μιλά για λίγα λεπτά με άγνωστη IP στην Κίνα (το ίδιο με το Τείχος IoT)
            if end - 31 * 60 <= b <= end - 27 * 60:
                x["edge"].append(["192.168.1.33", "47.91.88.12", 2400, 6, "TCP/9000"])
                self.meta.setdefault("47.91.88.12", {"name": "47.91.88.12", "cc": "CN", "country": "China"})
            x["edge"].sort(key=lambda e: -e[2])
            x["edge"] = x["edge"][:TOP_EDGES]
            self.buckets.append(x)
