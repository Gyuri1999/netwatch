"""🚀 Ταχύτητα: μέσα στο LAN με iperf3 και προς το internet με ένα απλό download/upload από την Cloudflare.

config.yaml:
speed:
  path: data/speed.json     # ιστορικό αποτελεσμάτων (κρατάμε τα τελευταία 200)
  iperf_port: 5201
  seconds: 5                # διάρκεια μέτρησης iperf3
  down_bytes: 25000000      # μέγεθος download από speed.cloudflare.com
  up_bytes: 10000000
  interval: 0               # αυτόματο τεστ internet κάθε N δευτερόλεπτα (0 = ποτέ — καίει δεδομένα)

iperf3: μόνο προς ιδιωτικές διευθύνσεις (192.168.x, 10.x, 172.16–31.x, fd00::/8, 100.64/10 για Tailscale) — δεν
«βομβαρδίζουμε» ξένους servers. Στον άλλο υπολογιστή (π.χ. VM στον Proxmox) τρέχει `iperf3 -s`.
Τεστ internet: επικοινωνεί με την Cloudflare (speed.cloudflare.com) — χωρίς κλειδιά, χωρίς λογαριασμό.
"""
import ipaddress
import json
import os
import random
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.request

KEEP = 200
DEFAULT_PATH = os.path.join("data", "speed.json")
CF_DOWN = "https://speed.cloudflare.com/__down?bytes={n}"
CF_UP = "https://speed.cloudflare.com/__up"
UA = {"User-Agent": "netwatch-speed/1.0"}
CGNAT = ipaddress.ip_network("100.64.0.0/10")

MISSING_MSG = ("Δεν βρέθηκε το iperf3. Εγκατάσταση στο Mac: «brew install iperf3». "
               "Στον άλλο υπολογιστή (π.χ. VM ή LXC στον Proxmox): «apt install iperf3» και μετά «iperf3 -s» "
               "(ακούει στη θύρα TCP 5201 — άνοιξέ τη στο firewall του Proxmox αν χρειάζεται). "
               "Για μόνιμη λειτουργία: «systemctl enable --now iperf3» ή «iperf3 -s -D».")
CF_NOTE = "Το τεστ internet επικοινωνεί με την Cloudflare (speed.cloudflare.com)."


class SpeedError(Exception):
    pass


def iperf_path():
    return shutil.which("iperf3")


def _private_ip(a):
    return (a.is_private or a.is_link_local or a.is_loopback or (a.version == 4 and a in CGNAT)) and not a.is_multicast \
        and not a.is_unspecified


def check_private(host, resolve=True):
    """Επιστρέφει την IP αν ο στόχος είναι ιδιωτικός, αλλιώς σηκώνει SpeedError (δημόσιοι στόχοι απορρίπτονται)."""
    host = str(host or "").strip().strip("[]")
    if not host or host.startswith("-"):
        raise SpeedError("Μη έγκυρος στόχος.")
    try:
        addrs = [ipaddress.ip_address(host)]
    except ValueError:
        if not resolve:
            raise SpeedError(f"Το «{host}» δεν είναι διεύθυνση IP.")
        try:
            addrs = list({ipaddress.ip_address(x[4][0].split("%")[0]) for x in socket.getaddrinfo(host, None)})
        except (socket.gaierror, ValueError, UnicodeError):
            raise SpeedError(f"Δεν βρέθηκε το «{host}».")
    bad = [str(a) for a in addrs if not _private_ip(a)]
    if bad or not addrs:
        raise SpeedError(f"Το iperf3 επιτρέπεται μόνο προς ιδιωτικές διευθύνσεις του δικτύου σου — το «{host}» "
                         f"({', '.join(bad) or '?'}) είναι δημόσιο.")
    return str(addrs[0])


def _mbps(bps):
    return round(bps / 1e6, 2) if bps is not None else None


def parse_iperf(text):
    """Έξοδος `iperf3 -J` → λεξικό αποτελέσματος (Mbps, retransmits κ.λπ.)."""
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return {"ok": False, "error": "Μη αναγνώσιμη έξοδος του iperf3."}
    if d.get("error"):
        return {"ok": False, "error": f"iperf3: {d['error']}"}
    st, end = d.get("start") or {}, d.get("end") or {}
    test = st.get("test_start") or {}
    conn = (st.get("connected") or [{}])[0]
    proto = (test.get("protocol") or "TCP").upper()
    res = {"ok": True, "protocol": proto, "reverse": bool(test.get("reverse")), "streams": test.get("num_streams"),
           "remote": conn.get("remote_host"), "port": conn.get("remote_port"), "duration": test.get("duration"),
           "sent_mbps": None, "recv_mbps": None, "retransmits": None, "jitter_ms": None, "lost_percent": None,
           "cpu_local": (end.get("cpu_utilization_percent") or {}).get("host_total"),
           "cpu_remote": (end.get("cpu_utilization_percent") or {}).get("remote_total")}
    if proto == "UDP":
        s = end.get("sum") or {}
        res.update(sent_mbps=_mbps(s.get("bits_per_second")), recv_mbps=_mbps(s.get("bits_per_second")),
                   jitter_ms=s.get("jitter_ms"), lost_percent=s.get("lost_percent"))
    else:
        snd, rcv = end.get("sum_sent") or {}, end.get("sum_received") or {}
        res.update(sent_mbps=_mbps(snd.get("bits_per_second")), recv_mbps=_mbps(rcv.get("bits_per_second")),
                   retransmits=snd.get("retransmits"))
    if res["sent_mbps"] is None and res["recv_mbps"] is None:
        return {"ok": False, "error": "Το iperf3 δεν έδωσε αποτελέσματα."}
    return res


def run_iperf(host, port=5201, seconds=5, reverse=False, udp=False, timeout=None, exe=None):
    ip = check_private(host)
    exe = exe or iperf_path()
    if not exe:
        raise SpeedError(MISSING_MSG)
    seconds = max(1, min(int(seconds), 60))
    cmd = [exe, "-c", ip, "-p", str(int(port)), "-t", str(seconds), "-J", "--connect-timeout", "3000"]
    if reverse:
        cmd.append("-R")
    if udp:
        cmd += ["-u", "-b", "0"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout or seconds + 15)
    except subprocess.TimeoutExpired:
        raise SpeedError(f"Το iperf3 προς {ip} δεν τελείωσε εγκαίρως — τρέχει `iperf3 -s` στον στόχο;")
    res = parse_iperf(out.stdout or out.stderr)
    if not res["ok"] and "unable to connect" in res.get("error", "").lower():
        res["error"] += f" — τρέχει `iperf3 -s` στο {ip}:{port};"
    return res


# ── internet (Cloudflare) ──
def _ctx():
    return ssl.create_default_context()


def cf_latency(samples=5, timeout=5):
    """Χρόνος για ένα μικροσκοπικό αίτημα (0 bytes) σε ήδη ανοιχτή σύνδεση (χωρίς TCP/TLS handshake).
    Μετράει RTT + λίγη επεξεργασία στον server — όχι καθαρό ping. → (διάμεσος ms, εύρος ms)"""
    import http.client
    c = http.client.HTTPSConnection("speed.cloudflare.com", timeout=timeout, context=_ctx())
    times = []
    try:
        for i in range(samples + 1):
            t0 = time.time()
            c.request("GET", "/__down?bytes=0", headers=UA)
            c.getresponse().read()
            if i:  # το πρώτο ανοίγει τη σύνδεση
                times.append((time.time() - t0) * 1000)
    finally:
        c.close()
    times.sort()
    return round(times[len(times) // 2], 1), round(max(times) - min(times), 1)


def cf_download(nbytes, timeout=30):
    t0, got = time.time(), 0
    with urllib.request.urlopen(urllib.request.Request(CF_DOWN.format(n=int(nbytes)), headers=UA), timeout=timeout, context=_ctx()) as r:
        t1 = time.time()  # μετά τα headers: δεν μετράμε το TLS handshake
        while True:
            b = r.read(65536)
            if not b:
                break
            got += len(b)
            if time.time() - t0 > timeout:
                break
    dt = max(time.time() - t1, 1e-3)
    return round(got * 8 / dt / 1e6, 2), got, round(dt, 2)


def cf_upload(nbytes, timeout=30):
    data = os.urandom(int(nbytes))
    req = urllib.request.Request(CF_UP, data=data, headers={**UA, "Content-Type": "application/octet-stream"}, method="POST")
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
        r.read()
    dt = max(time.time() - t0, 1e-3)
    return round(len(data) * 8 / dt / 1e6, 2), len(data), round(dt, 2)


def internet_test(down_bytes=25_000_000, up_bytes=10_000_000, timeout=30):
    lat, jit = cf_latency()
    down, dgot, dsec = cf_download(down_bytes, timeout)
    up, ugot, usec = cf_upload(up_bytes, timeout) if up_bytes else (None, 0, None)
    return {"ok": True, "down_mbps": down, "up_mbps": up, "latency_ms": lat, "jitter_ms": jit,
            "down_bytes": dgot, "up_bytes": ugot, "down_s": dsec, "up_s": usec, "server": "speed.cloudflare.com"}


# ── ιστορικό + demo ──
class Speed:
    def __init__(self, cfg=None, sim=False, path=None):
        cfg = cfg or {}
        self.sim = sim
        self.path = path or cfg.get("path") or DEFAULT_PATH
        self.port = int(cfg.get("iperf_port") or 5201)
        self.seconds = int(cfg.get("seconds") or 5)
        self.down_bytes = int(cfg.get("down_bytes") or 25_000_000)
        self.up_bytes = int(cfg.get("up_bytes") if cfg.get("up_bytes") is not None else 10_000_000)
        self.interval = int(cfg.get("interval") or 0)
        self.lock = threading.Lock()
        self.running = None
        self.hist = [] if sim else self._load()
        if sim and not self.hist:
            self._sim_history()

    def _load(self):
        try:
            with open(self.path) as f:
                d = json.load(f)
            return [x for x in d if isinstance(x, dict)][-KEEP:] if isinstance(d, list) else []
        except (OSError, ValueError):
            return []

    def _save(self):
        if self.sim:
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.hist, f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def _push(self, res):
        with self.lock:
            self.hist = (self.hist + [res])[-KEEP:]
        self._save()
        return res

    def _begin(self, what):
        with self.lock:
            if self.running:
                raise SpeedError("Τρέχει ήδη μια μέτρηση — περίμενε να τελειώσει.")
            self.running = what

    def _end(self):
        with self.lock:
            self.running = None

    def iperf(self, host, reverse=False, udp=False, seconds=None, port=None):
        """Τεστ iperf3 προς ιδιωτικό στόχο. Πάντα επιστρέφει λεξικό (ok/error), δεν σηκώνει εξαίρεση."""
        now = time.time()
        base = {"kind": "iperf", "t": now, "target": str(host), "reverse": bool(reverse), "udp": bool(udp)}
        try:
            check_private(host, resolve=not self.sim)
            if self.sim:
                return self._push({**base, **self._sim_iperf(reverse, udp), "demo": True})
            if not iperf_path():
                return {**base, "ok": False, "error": MISSING_MSG, "missing": True}
            self._begin("iperf")
            try:
                res = run_iperf(host, port or self.port, seconds or self.seconds, reverse, udp)
            finally:
                self._end()
        except SpeedError as e:
            return {**base, "ok": False, "error": str(e)}
        res = {**base, **res}
        if res.get("ok"):
            self._push(res)
        return res

    def internet(self):
        now = time.time()
        base = {"kind": "internet", "t": now, "note": CF_NOTE}
        if self.sim:
            return self._push({**base, **self._sim_internet(), "demo": True})
        try:
            self._begin("internet")
        except SpeedError as e:
            return {**base, "ok": False, "error": str(e)}
        try:
            res = {**base, **internet_test(self.down_bytes, self.up_bytes)}
        except Exception as e:
            return {**base, "ok": False, "error": f"Αποτυχία τεστ internet: {str(e)[:160] or e.__class__.__name__}"}
        finally:
            self._end()
        self._push(res)
        return res

    def _sim_iperf(self, reverse, udp, rnd=random):
        if udp:
            bw = rnd.uniform(800, 950)
            return {"ok": True, "protocol": "UDP", "sent_mbps": round(bw, 2), "recv_mbps": round(bw, 2), "retransmits": None,
                    "jitter_ms": round(rnd.uniform(0.01, 0.2), 3), "lost_percent": round(rnd.uniform(0, 0.4), 2),
                    "duration": self.seconds, "remote": "192.168.1.16", "port": self.port}
        snd = rnd.uniform(905, 945) if not reverse else rnd.uniform(880, 935)
        return {"ok": True, "protocol": "TCP", "sent_mbps": round(snd, 2), "recv_mbps": round(snd - rnd.uniform(0.5, 3), 2),
                "retransmits": rnd.choice([0, 0, 0, 2, 7, 15]), "jitter_ms": None, "lost_percent": None,
                "duration": self.seconds, "remote": "192.168.1.16", "port": self.port}

    def _sim_internet(self, rnd=random, t=None):
        h = time.localtime(t or time.time()).tm_hour
        eve = 0.55 if 19 <= h <= 23 else 1.0
        return {"ok": True, "down_mbps": round(rnd.uniform(270, 305) * eve, 2), "up_mbps": round(rnd.uniform(40, 48) * (0.8 + 0.2 * eve), 2),
                "latency_ms": round(rnd.uniform(9, 14) / eve, 1), "jitter_ms": round(rnd.uniform(0.5, 3) / eve, 1),
                "down_bytes": self.down_bytes, "up_bytes": self.up_bytes, "server": "speed.cloudflare.com"}

    def _sim_history(self):
        rnd = random.Random(11)
        now = time.time()
        for i in range(20, 0, -1):
            t = now - i * 6 * 3600 + rnd.uniform(-1800, 1800)
            self.hist.append({"kind": "internet", "t": t, "note": CF_NOTE, **self._sim_internet(rnd, t), "demo": True})
            if i % 4 == 0:
                self.hist.append({"kind": "iperf", "t": t + 60, "target": "192.168.1.16", "reverse": False, "udp": False,
                                  **self._sim_iperf(False, False, rnd), "demo": True})

    def history(self, kind=None, limit=KEEP):
        with self.lock:
            return [x for x in self.hist if kind is None or x.get("kind") == kind][-limit:]

    def status(self):
        with self.lock:
            last_i = next((x for x in reversed(self.hist) if x.get("kind") == "iperf"), None)
            last_n = next((x for x in reversed(self.hist) if x.get("kind") == "internet"), None)
            running = self.running
        return {"demo": self.sim, "iperf_available": bool(self.sim or iperf_path()),
                "iperf_help": None if (self.sim or iperf_path()) else MISSING_MSG, "running": running,
                "last_iperf": last_i, "last_internet": last_n, "count": len(self.hist), "interval": self.interval,
                "note": CF_NOTE, "history": self.history(limit=50)}

    def run_forever(self):
        """Περιοδικό τεστ internet μόνο αν το ζήτησες (speed.interval > 0)."""
        if self.interval <= 0:
            return
        while True:
            time.sleep(max(self.interval, 600) if not self.sim else self.interval)
            try:
                self.internet()
            except Exception:
                pass
