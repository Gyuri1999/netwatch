"""🩺 Υγεία του homelab: είναι «πάνω» ο Proxmox, ο broker, το Home Assistant, τα ESP32; πόσο αργούν; πότε λήγουν τα πιστοποιητικά;

config.yaml:
health:
  - {name: Proxmox, host: 192.168.1.16, port: 8006, tls: true}
  - {name: MQTT broker, host: 192.168.1.17, port: 1883}
  - {name: Home Assistant, url: "http://192.168.1.30:8123/"}
  - {name: ESP32 κήπου, host: 192.168.1.20, ping: true}
Αν δεν γράψεις τίποτα, ελέγχει αυτόματα τον router και ό,τι έχεις ρυθμίσει ως broker (mqtt_guard / sensor).
Ειδοποιήσεις: «Υπηρεσία εκτός» μετά από 2 συνεχόμενες αποτυχίες, «Υπηρεσία επανήλθε», «Πιστοποιητικό λήγει» (< 14 μέρες).
Μόνο ελαφριοί έλεγχοι: TCP σύνδεση, ένα HTTP GET, ένα ping — κάθε 60″.
"""
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

FAILS_FOR_DOWN = 2
CERT_WARN_DAYS = 14


def tcp_check(host, port, timeout=3.0):
    t0 = time.time()
    with socket.create_connection((host, port), timeout=timeout):
        pass
    return (time.time() - t0) * 1000


def http_check(url, timeout=5.0):
    t0 = time.time()
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # homelab: self-signed — μετράμε μόνο αν απαντά
    req = urllib.request.Request(url, headers={"User-Agent": "netwatch-health/1.0"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            r.read(256)
            code = r.status
    except urllib.error.HTTPError as e:  # 401/403/404 = ο server ζει
        code = e.code
    if code >= 500:
        raise OSError(f"HTTP {code}")
    return (time.time() - t0) * 1000


def ping_check(host, timeout=2):
    if sys.platform == "win32":
        import winplat
        t0 = time.time()
        m = re.search(r"time=([\d.]+)", winplat.ping(host, 1, timeout * 1000))
        if not m:  # τα Windows δίνουν κωδικό 0 ακόμα και για «Destination host unreachable»
            raise OSError("δεν απαντά στο ping")
        return float(m.group(1)) if m else (time.time() - t0) * 1000
    w = ["-W", str(timeout * 1000)] if sys.platform == "darwin" else ["-W", str(timeout)]
    t0 = time.time()
    out = subprocess.run(["ping", "-c", "1", *w, host], capture_output=True, text=True, timeout=timeout + 2)
    if out.returncode != 0:
        raise OSError("δεν απαντά στο ping")
    m = re.search(r"time[=<]([\d.]+)", out.stdout)
    return float(m.group(1)) if m else (time.time() - t0) * 1000


def cert_days(host, port, timeout=4.0):
    """Μέρες μέχρι να λήξει το πιστοποιητικό TLS (χωρίς έλεγχο εμπιστοσύνης — θέλουμε μόνο την ημερομηνία)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        der = t.getpeercert(binary_form=True)
    pem = ssl.DER_cert_to_PEM_cert(der)
    out = subprocess.run(["openssl", "x509", "-noout", "-enddate"], input=pem, capture_output=True, text=True, timeout=5).stdout
    end = ssl.cert_time_to_seconds(out.split("=", 1)[1].strip())
    return int((end - time.time()) // 86400)


def normalize(cfg, auto=()):
    out = []
    for i, c in enumerate(list(cfg or []) + [a for a in auto if not any((a.get("host"), a.get("port")) == (c.get("host"), c.get("port")) for c in (cfg or []))]):
        c = dict(c or {})
        if c.get("url"):
            u = urllib.parse.urlparse(c["url"])
            if u.scheme not in ("http", "https") or not u.hostname:
                continue
            c.setdefault("host", u.hostname)
            c["kind"] = "http"
            if u.scheme == "https":
                c.setdefault("tls", True)
                c.setdefault("port", u.port or 443)
        elif c.get("ping"):
            c["kind"] = "ping"
        elif c.get("host") and c.get("port"):
            c["kind"] = "tcp"
        else:
            continue
        c["name"] = str(c.get("name") or c["host"])[:40]
        c["id"] = f"{c['name']}|{c['host']}|{c.get('port', '')}"
        out.append(c)
    return out


class Health:
    def __init__(self, state, cfg, auto=(), sim=False):
        self.state, self.sim = state, sim
        self.targets = normalize(cfg, auto)
        self.lock = threading.Lock()
        self.res = {t["id"]: {"up": None, "fails": 0, "ms": None, "hist": [], "since": None, "err": None, "cert_days": None}
                    for t in self.targets}

    def check_one(self, t):
        if self.sim:
            import random
            if t["name"] == "ESP32 κήπου" and int(time.time() / 90) % 3 == 1:
                raise OSError("δεν απαντά στο ping")
            return random.uniform(1, 40) if t["kind"] != "http" else random.uniform(20, 120)
        if t["kind"] == "tcp":
            return tcp_check(t["host"], int(t["port"]))
        if t["kind"] == "http":
            return http_check(t["url"])
        return ping_check(t["host"])

    def round(self, now=None):
        now = now or time.time()
        events = []
        for t in self.targets:
            try:
                ms, err = self.check_one(t), None
            except Exception as e:
                ms, err = None, str(e)[:120] or e.__class__.__name__
            days = None
            if t.get("tls") and ms is not None and not self.sim:
                try:
                    days = cert_days(t["host"], int(t.get("port") or 443))
                except Exception:
                    days = None
            elif t.get("tls") and self.sim:
                days = 9 if t["name"] == "Proxmox" else 200
            with self.lock:
                r = self.res[t["id"]]
                r["hist"] = (r["hist"] + [None if ms is None else round(ms, 1)])[-60:]
                r["ms"], r["err"], r["cert_days"] = (round(ms, 1) if ms is not None else None), err, days
                if ms is None:
                    r["fails"] += 1
                    if r["fails"] == FAILS_FOR_DOWN and r["up"] is not False:
                        r["up"], r["since"] = False, now
                        events.append(("Υπηρεσία εκτός", "med", t, f"Το «{t['name']}» ({t['host']}{':' + str(t['port']) if t.get('port') else ''}) δεν απαντά: {err}."))
                else:
                    if r["up"] is False:
                        events.append(("Υπηρεσία επανήλθε", "low", t, f"Το «{t['name']}» απαντά ξανά (ήταν εκτός {int((now - (r['since'] or now)) / 60)}′)."))
                    if r["up"] is not True:
                        r["since"] = now
                    r["up"], r["fails"] = True, 0
                if days is not None and days < CERT_WARN_DAYS:
                    events.append(("Πιστοποιητικό λήγει", "med" if days >= 0 else "high", t,
                                   f"Το πιστοποιητικό TLS του «{t['name']}» {'έληξε' if days < 0 else 'λήγει σε ' + str(days) + ' μέρες'}. "
                                   "Ανανέωσέ το (π.χ. ./tools/mosquitto-tls.sh για τον broker)."))
        for typ, sev, t, detail in events:
            self.state.alert(typ, sev, t["host"], t["name"], detail, now, key=(typ, t["id"]),
                             cooldown=86400 if typ == "Πιστοποιητικό λήγει" else 60, mark=False)
        return events

    def status(self):
        with self.lock:
            return {"targets": [{**{k: t.get(k) for k in ("name", "host", "port", "kind", "url", "tls")}, **self.res[t["id"]]}
                                for t in self.targets], "demo": self.sim}

    def run_forever(self, every=60):
        while True:
            try:
                self.round()
            except Exception:
                pass
            time.sleep(every if not self.sim else 15)
