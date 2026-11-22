"""NetWatch — Threat intelligence (blocklists), ιστορικό SQLite και ειδοποιήσεις (macOS/Telegram)."""
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

from core import SEV, chown_to_user, log


# ---------------- threat intelligence ----------------
class Intel:
    """Δημόσιες blocklists (Feodo/Spamhaus/FireHOL) σε lookup O(#prefix lengths)."""

    def __init__(self, cfg=None, cache_dir=None):
        self.cfg = cfg or {}
        self.cache_dir = cache_dir
        self.nets = {}  # prefixlen -> {int network: [feed,…]}
        self.info, self.entries, self.loaded = [], 0, False

    @staticmethod
    def _add(nets, cidr, feed):
        try:
            n = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return False
        if n.version != 4 or not n.is_global:
            return False  # οι λίστες περιέχουν και bogons (10/8, 192.168/16…) — δεν μας αφορούν
        bucket = nets.setdefault(n.prefixlen, {}).setdefault(int(n.network_address), [])
        if feed not in bucket:
            bucket.append(feed)
        return True

    @classmethod
    def parse(cls, text, feed, nets):
        n = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] in "#;":
                continue
            if line.startswith("{"):
                try:
                    cidr = json.loads(line).get("cidr")
                except ValueError:
                    cidr = None
                if not cidr:
                    continue
            else:
                cidr = line.split()[0].split(";")[0]
            n += cls._add(nets, cidr, feed)
        return n

    def add(self, cidr, name, kind="block"):
        self._add(self.nets, cidr, {"name": name, "kind": kind})
        self.entries += 1

    def lookup(self, ip):
        try:
            a = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return []
        out = []
        for pl, d in list(self.nets.items()):
            mask = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF if pl else 0
            for f in d.get(a & mask, ()):
                if f not in out:
                    out.append(f)
        return out

    def load(self, on_done=None):
        nets, info, total = {}, [], 0
        for f in self.cfg.get("feeds", []):
            feed = {"name": f["name"], "kind": f.get("kind", "block")}
            slug = re.sub(r"[^a-z0-9]+", "-", f["name"].lower()).strip("-")
            path = os.path.join(self.cache_dir, slug + ".txt") if self.cache_dir else None
            text, src = None, "cache"
            try:
                fresh = path and os.path.exists(path) and \
                    time.time() - os.path.getmtime(path) < self.cfg.get("max_age_hours", 24) * 3600
                if fresh:
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                else:
                    src = "download"
                    req = urllib.request.Request(f["url"], headers={"User-Agent": "netwatch/1.0"})
                    with urllib.request.urlopen(req, timeout=20) as r:
                        text = r.read().decode("utf-8", "ignore")
                    if path:
                        os.makedirs(self.cache_dir, exist_ok=True)
                        chown_to_user(os.path.dirname(self.cache_dir))
                        chown_to_user(self.cache_dir)
                        with open(path, "w", encoding="utf-8") as fh:
                            fh.write(text)
                        chown_to_user(path)
                n = self.parse(text, feed, nets)
                info.append({**feed, "entries": n, "ok": True, "source": src})
                total += n
            except Exception as e:
                info.append({**feed, "entries": 0, "ok": False, "error": str(e)[:120]})
                log(f"intel: {f['name']} απέτυχε: {e}")
        for pl, d in self.nets.items():  # κράτα και ό,τι προστέθηκε χειροκίνητα (demo)
            for k, v in d.items():
                nets.setdefault(pl, {}).setdefault(k, []).extend(x for x in v if x not in nets[pl].get(k, []))
        self.nets, self.info, self.entries, self.loaded = nets, info, total + self.entries, True
        log(f"intel: {total} δίκτυα από {sum(i['ok'] for i in info)}/{len(info)} λίστες")
        if on_done:
            on_done()


def abuseipdb_check(key, ip):
    ipaddress.ip_address(ip)
    req = urllib.request.Request(
        "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90}),
        headers={"Key": key, "Accept": "application/json", "User-Agent": "netwatch/1.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r).get("data", {})


# ---------------- ιστορικό (SQLite) ----------------
class History:
    def __init__(self, path=":memory:"):
        self.path = path
        if path != ":memory:":
            d = os.path.dirname(os.path.abspath(path))
            os.makedirs(d, exist_ok=True)
            chown_to_user(d)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, t REAL, type TEXT, sev TEXT,
                actor TEXT, target TEXT, detail TEXT, mitre TEXT, mode TEXT);
            CREATE INDEX IF NOT EXISTS alerts_t ON alerts(t);
            CREATE TABLE IF NOT EXISTS traffic(minute INTEGER PRIMARY KEY, pkts INTEGER, bytes INTEGER);
            CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY, ip TEXT, first_seen REAL, last_seen REAL);
            """)
            self.db.commit()
        chown_to_user(path)

    def add_alert(self, a, mode):
        with self.lock:
            self.db.execute("INSERT INTO alerts(t,type,sev,actor,target,detail,mitre,mode) VALUES(?,?,?,?,?,?,?,?)",
                            (a["t"], a["type"], a["sev"], a["actor"], str(a["target"]), a["detail"],
                             (a.get("mitre") or {}).get("id"), mode))
            self.db.commit()

    def add_traffic(self, minute, pkts, nbytes):
        with self.lock:
            self.db.execute("INSERT INTO traffic VALUES(?,?,?) ON CONFLICT(minute) DO UPDATE SET "
                            "pkts=pkts+excluded.pkts, bytes=bytes+excluded.bytes", (minute, pkts, nbytes))
            self.db.commit()

    def device_seen(self, mac, ip, t):
        """Επιστρέφει True αν η MAC δεν υπήρχε ποτέ ξανά στη βάση."""
        with self.lock:
            new = self.db.execute("SELECT 1 FROM devices WHERE mac=?", (mac,)).fetchone() is None
            self.db.execute("INSERT INTO devices VALUES(?,?,?,?) ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, "
                            "last_seen=excluded.last_seen", (mac, ip, t, t))
            self.db.commit()
            return new

    def known_macs(self):
        with self.lock:
            return {r[0] for r in self.db.execute("SELECT mac FROM devices")}

    def query(self, hours=24, ref=None):
        ref = ref or time.time()
        since = ref - hours * 3600
        with self.lock:
            cols = ["t", "type", "sev", "actor", "target", "detail", "mitre", "mode"]
            alerts = [dict(zip(cols, r)) for r in self.db.execute(
                f"SELECT {','.join(cols)} FROM alerts WHERE t>=? ORDER BY t DESC LIMIT 1000", (since,))]
            by_hour = self.db.execute("SELECT CAST(t/3600 AS INTEGER)*3600 h, sev, COUNT(*) FROM alerts WHERE t>=? "
                                      "GROUP BY h, sev ORDER BY h", (since,)).fetchall()
            traffic = self.db.execute("SELECT minute*60, pkts, bytes FROM traffic WHERE minute*60>=? ORDER BY minute",
                                      (since,)).fetchall()
            devices = [dict(zip(["mac", "ip", "first_seen", "last_seen"], r)) for r in self.db.execute(
                "SELECT mac, ip, first_seen, last_seen FROM devices ORDER BY first_seen DESC")]
            total = self.db.execute("SELECT COUNT(*), MIN(t) FROM alerts").fetchone()
        return {"ref": ref, "hours": hours, "alerts": alerts, "by_hour": by_hour, "traffic": traffic,
                "devices": devices, "total_alerts": total[0], "since_ever": total[1]}


# ---------------- ειδοποιήσεις ----------------
class Notifier:
    def __init__(self, cfg):
        self.cfg = cfg
        self.last = {}

    def __call__(self, a):
        if SEV[a["sev"]] < SEV.get(self.cfg.get("min_severity", "high"), 3):
            return
        now = time.time()
        if now - self.last.get(a["type"], 0) < self.cfg.get("cooldown", 30):
            return
        self.last[a["type"]] = now
        threading.Thread(target=self._send, args=(a,), daemon=True).start()

    def _send(self, a):
        from i18n import tr
        lang = self.cfg.get("lang", "el")  # config.yaml → lang: en
        typ = tr(a["type"], lang)
        detail = tr(a["detail"], lang)
        sev_ic = {"high": "🔴", "med": "🟠", "low": "🟡"}.get(a["sev"], "⚠️")
        headline = f"{sev_ic} {typ}"              # τύπος με χρώμα σοβαρότητας (Windows / Telegram / ntfy)
        title = f"{sev_ic} NetWatch"              # macOS: τίτλος + υπότιτλος = ο τύπος, σώμα = η εξήγηση
        body = detail                            # η εξήγηση είναι ήδη ολοκληρωμένη πρόταση — χωρίς «IP → IP:»
        mac_only = a.get("_mac_only")
        # Όταν τρέχουμε μέσα στην εφαρμογή macOS, τις ειδοποιήσεις τις στέλνει η ίδια (δικό μας εικονίδιο + κουμπιά)
        if self.cfg.get("macos") and sys.platform == "darwin" and not os.environ.get("NETWATCH_HOST_APP"):
            cmd = ["osascript", "-e", "on run argv", "-e",
                   'display notification (item 3 of argv) with title (item 1 of argv) subtitle (item 2 of argv) sound name "Basso"',
                   "-e", "end run", title, typ[:80], body[:200]]
            uid, user = os.environ.get("SUDO_UID"), os.environ.get("SUDO_USER")
            if user and uid and os.geteuid() == 0:
                cmd = ["launchctl", "asuser", uid, "sudo", "-u", user] + cmd
            try:
                subprocess.run(cmd, timeout=10, capture_output=True)
            except Exception as e:
                log("macOS notification error:", e)
        elif self.cfg.get("macos") and sys.platform == "win32":  # ίδια ρύθμιση: «ειδοποιήσεις υπολογιστή»
            try:
                import winplat
                winplat.toast(headline, body)
            except Exception as e:
                log("Windows notification error:", e)
        for name, fn in (() if mac_only else (("telegram", self._telegram), ("ntfy", self._ntfy))):
            try:
                fn(headline, body, a["sev"])
            except Exception as e:
                log(f"{name} error:", e)
        if not mac_only:
            import ops
            for name, fn in ops.CHANNELS.items():
                try:
                    fn(self.cfg.get(name), headline, body, a["sev"], a)
                except Exception as e:
                    log(f"{name} error:", str(e)[:200])

    def channels(self):
        tg, nt = self.cfg.get("telegram") or {}, self.cfg.get("ntfy") or {}
        return {"macos": bool(self.cfg.get("macos")) and sys.platform == "darwin",
                "telegram": bool(tg.get("bot_token") and tg.get("chat_id")), "ntfy": bool(nt.get("topic")),
                **__import__("ops").configured(self.cfg)}

    def _telegram(self, title, body, sev):
        tg = self.cfg.get("telegram") or {}
        if not (tg.get("bot_token") and tg.get("chat_id")):
            return False
        data = urllib.parse.urlencode({"chat_id": tg["chat_id"], "text": f"⚠ {title}\n{body}"}).encode()
        urllib.request.urlopen(f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage", data=data, timeout=10).read()
        return True

    def _ntfy(self, title, body, sev):
        """ntfy (https://ntfy.sh ή δικός σου server, π.χ. σε LXC στο Proxmox) — push στο κινητό με την εφαρμογή ntfy."""
        nt = self.cfg.get("ntfy") or {}
        if not nt.get("topic"):
            return False
        server = (nt.get("server") or "https://ntfy.sh").rstrip("/")
        msg = {"topic": nt["topic"], "title": title, "message": body[:1000],
               "priority": {"high": 5, "med": 4}.get(sev, 3), "tags": ["rotating_light" if sev == "high" else "warning"]}
        req = urllib.request.Request(server, data=json.dumps(msg).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": "netwatch/1.0",
                                              **({"Authorization": f"Bearer {nt['token']}"} if nt.get("token") else {})})
        urllib.request.urlopen(req, timeout=10).read()
        return True

    def test(self):
        """Στέλνει δοκιμαστική ειδοποίηση σε όλα τα κανάλια· επιστρέφει τι πέτυχε."""
        out = {}
        title, body = (("NetWatch — test", "If you can see this, notifications work. 👍") if self.cfg.get("lang") == "en"
                       else ("NetWatch — δοκιμή", "Αν το βλέπεις, οι ειδοποιήσεις δουλεύουν. 👍"))
        if self.channels()["macos"]:
            self._send({"type": "δοκιμή", "sev": "low", "actor": "NetWatch", "target": "εσύ", "detail": body, "_mac_only": True})
            out["macos"] = "ok"
        import ops
        chans = [("telegram", self._telegram), ("ntfy", self._ntfy)] + \
            [(n, (lambda f, n: lambda t, b, s: f(self.cfg.get(n), t, b, s, {"type": "test", "sev": s}))(f, n)) for n, f in ops.CHANNELS.items()]
        for name, fn in chans:
            try:
                out[name] = "ok" if fn(title, body, "med") else "δεν έχει ρυθμιστεί"
            except Exception as e:
                out[name] = f"σφάλμα: {str(e)[:120]}"
        return out
