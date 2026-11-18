"""🔐 WireGuard & Tailscale: ποιοι peers είναι συνδεδεμένοι, πότε έγινε το τελευταίο handshake, πόση κίνηση περνά.

config.yaml:
wireguard:
  enabled: true
  interval: 30          # δευτερόλεπτα ανάμεσα στους ελέγχους
  stale_min: 5          # μετά από τόσα λεπτά χωρίς handshake ο peer θεωρείται «χαμένος»
  names:                # φιλικά ονόματα ανά δημόσιο κλειδί
    "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=": "Κινητό"

WireGuard: `wg show all dump` (θέλει root — στο macOS τρέξε το NetWatch ως agent ή με sudo).
Tailscale: `tailscale status --json` (και από το /Applications/Tailscale.app).
Τα ιδιωτικά κλειδιά και τα preshared keys ΔΕΝ κρατιούνται ποτέ — πετιούνται αμέσως κατά την ανάγνωση.

Κατάσταση peer: active (handshake < 3′), idle (< stale_min), stale (παλιότερο), never (ποτέ).
Ειδοποιήσεις: «WireGuard peer χάθηκε» (med) / «WireGuard peer επανήλθε» (low),
«Tailscale συσκευή εκτός» (med) / «Tailscale συσκευή επανήλθε» (low). Όχι στον πρώτο έλεγχο· 30′ cooldown ανά peer.
"""
import calendar
import collections
import json
import math
import os
import re
import shutil
import subprocess
import threading
import time

ACTIVE_S = 180
HIST = 60
TIMEOUT = 5
ALERT_COOLDOWN = 1800
SEARCH_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin")
TAILSCALE_APP = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"

HINT_PERM = ("Το `wg show` χρειάζεται δικαιώματα διαχειριστή. Τρέξε το NetWatch ως agent "
             "(sudo ./netwatch.py --install-agent) ή με sudo για να φαίνονται οι WireGuard peers.")
HINT_TS = "Το Tailscale είναι εγκατεστημένο αλλά δεν τρέχει ή δεν έχεις συνδεθεί (tailscale up)."


def find_exe(name, extra=()):
    p = shutil.which(name)
    if p:
        return p
    for d in SEARCH_DIRS:
        c = os.path.join(d, name)
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    for c in extra:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def run_cmd(argv):
    """(returncode, stdout, stderr)· ποτέ shell, timeout 5″."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except OSError as e:
        return -1, "", str(e)


def short_key(k):
    return (k[:8] + "…") if k else None


def _int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return 0


# ───────────────────────────── WireGuard ─────────────────────────────

def parse_wg_dump(text):
    """Έξοδος `wg show all dump` → [{name, public_key, listen_port, fwmark, peers:[…]}].
    Τα ιδιωτικά/preshared κλειδιά δεν αντιγράφονται ποτέ στο αποτέλεσμα."""
    ifaces = collections.OrderedDict()
    for line in (text or "").splitlines():
        f = line.rstrip("\n").split("\t")
        if len(f) == 5:  # iface, private, public, port, fwmark
            name = f[0]
            ifaces[name] = {"name": name, "public_key": f[2] if f[2] != "(none)" else None,
                            "listen_port": _int(f[3]) or None, "fwmark": None if f[4] == "off" else f[4], "peers": []}
        elif len(f) == 9:  # iface, public, preshared, endpoint, allowed, handshake, rx, tx, keepalive
            name = f[0]
            itf = ifaces.setdefault(name, {"name": name, "public_key": None, "listen_port": None, "fwmark": None, "peers": []})
            itf["peers"].append({"public_key": f[1], "endpoint": None if f[3] == "(none)" else f[3],
                                 "allowed_ips": [x for x in f[4].split(",") if x and x != "(none)"],
                                 "handshake": _int(f[5]), "rx": _int(f[6]), "tx": _int(f[7]),
                                 "keepalive": None if f[8] == "off" else _int(f[8])})
        del f  # (τα κλειδιά δεν ζουν πέρα από αυτή τη γραμμή)
    return list(ifaces.values())


def peer_state(handshake, now, stale_min=5):
    if not handshake:
        return "never"
    ago = now - handshake
    if ago < ACTIVE_S:
        return "active"
    if ago < stale_min * 60:
        return "idle"
    return "stale"


def _endpoint_ip(ep):
    if not ep:
        return None
    m = re.match(r"^\[([^\]]+)\]:\d+$", ep) or re.match(r"^([^:]+):\d+$", ep)
    return m.group(1) if m else ep


# ───────────────────────────── Tailscale ─────────────────────────────

def parse_ts_time(s):
    """«2026-11-18T10:00:00.123456789Z» → epoch· None για κενό ή «0001-01-01…»."""
    m = re.match(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)?", s or "")
    if not m or int(m.group(1)) < 1971:
        return None
    t = calendar.timegm(tuple(int(x) for x in m.groups()[:6]) + (0, 0, 0))
    tz = m.group(7)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        t -= sign * (hh * 3600 + mm * 60)
    return t


def _ts_node(n, me=False):
    name = n.get("HostName") or (n.get("DNSName") or "").split(".")[0] or "?"
    ips = n.get("TailscaleIPs") or []
    cur = n.get("CurAddr") or ""
    return {"name": name, "dns": (n.get("DNSName") or "").rstrip(".") or None, "ip": ips[0] if ips else None,
            "ips": list(ips), "os": n.get("OS") or None, "online": True if me else bool(n.get("Online")),
            "direct": bool(cur), "cur_addr": cur or None, "relay": n.get("Relay") or None,
            "last_seen": parse_ts_time(n.get("LastSeen")), "last_handshake": parse_ts_time(n.get("LastHandshake")),
            "rx": _int(n.get("RxBytes")), "tx": _int(n.get("TxBytes")), "exit_node": bool(n.get("ExitNode")),
            "exit_node_option": bool(n.get("ExitNodeOption")), "id": n.get("PublicKey") or n.get("ID") or name}


def parse_tailscale(js):
    """JSON του `tailscale status --json` (str ή dict) → {backend, self, peers}."""
    d = json.loads(js) if isinstance(js, (str, bytes)) else (js or {})
    peers = [_ts_node(p) for p in (d.get("Peer") or {}).values() if isinstance(p, dict)]
    peers.sort(key=lambda p: (not p["online"], p["name"].lower()))
    return {"backend": d.get("BackendState"), "self": _ts_node(d["Self"], me=True) if isinstance(d.get("Self"), dict) else None,
            "peers": peers}


# ───────────────────────────── demo ─────────────────────────────

SIM_WG_PUB = "mQ3v8Yc2Zr9dKq1L0sXbT4pW7nE6aH5uJgFiOyRzC0w="
SIM_PEERS = [
    ("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", "Κινητό", "85.74.211.9:51820", ["10.8.0.2/32"]),
    ("TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=", "Laptop", "94.66.58.130:39017", ["10.8.0.3/32"]),
    ("HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=", "VPS Hetzner", "159.69.42.17:51820", ["10.8.0.10/32", "10.20.0.0/24"]),
]


def sim_wg_dump(now, t0):
    """Ψεύτικο `wg show all dump` (χωρίς ιδιωτικά κλειδιά — μόνο placeholders)."""
    ph = now % 1800  # το Laptop «χάνεται» για 5′ κάθε μισάωρο, για να φαίνονται οι ειδοποιήσεις στο demo
    hs = [now - (now % 110) * 0.9 - 4,
          now - (ph % 150) - 10 if ph < 1500 else now - (ph - 1500) - 400,
          now - 3 * 3600 - 412]
    rate = [(42_000, 9_500), (6_000, 2_200), (0, 0)]
    base = [(1_284_551_204, 233_118_960), (88_331_020, 31_002_557), (5_120_331, 1_998_004)]
    lines = ["wg0\t(hidden)\t%s\t51820\toff" % SIM_WG_PUB]
    for i, (pub, _n, ep, aips) in enumerate(SIM_PEERS):
        until = now - (ph - 1500) if i == 1 and ph >= 1500 else now  # όσο λείπει, οι μετρητές μένουν παγωμένοι
        span = max(0.0, until - t0)
        wave = 20 * math.sin(until / 47 + i)  # κυματισμός ρυθμού ±40 % — οι μετρητές μένουν μονότονοι
        rx = int(base[i][0] + (span + wave) * rate[i][0])
        tx = int(base[i][1] + (span + wave * 0.8) * rate[i][1])
        lines.append("\t".join(["wg0", pub, "(none)", ep, ",".join(aips), str(int(hs[i])), str(rx), str(tx),
                                "25" if i == 0 else "off"]))
    return "\n".join(lines) + "\n"


def _iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def sim_tailscale(now, t0):
    up = max(0.0, now - t0)

    def node(host, ip, os_, online, cur, relay, rx, tx, seen=None, exit_opt=False, key=None):
        return {"PublicKey": key or "nodekey:" + host, "HostName": host, "DNSName": f"{host}.tail3c9f1.ts.net.", "OS": os_,
                "TailscaleIPs": [ip], "Online": online, "CurAddr": cur, "Relay": relay,
                "LastSeen": _iso(seen) if seen else "0001-01-01T00:00:00Z",
                "LastHandshake": _iso(now - 47) if online else "0001-01-01T00:00:00Z",
                "RxBytes": int(rx), "TxBytes": int(tx), "ExitNode": False, "ExitNodeOption": exit_opt}

    return {"BackendState": "Running",
            "Self": node("macbook-pro", "100.101.7.12", "macOS", True, "", "fra", 0, 0, key="nodekey:self"),
            "Peer": {
                "nodekey:a": node("nas-synology", "100.88.14.3", "linux", True, "192.168.1.20:41641", "fra",
                                  2_400_000_000 + up * 180_000, 310_000_000 + up * 22_000),
                "nodekey:b": node("pixel-8", "100.72.201.44", "android", True, "", "fra",
                                  52_000_000 + up * 4_000, 9_100_000 + up * 900),
                "nodekey:c": node("rpi-exit", "100.99.3.77", "linux", True, "79.130.12.5:41641", "ams",
                                  730_000_000 + up * 12_000, 1_020_000_000 + up * 15_000, exit_opt=True),
                "nodekey:d": node("work-laptop", "100.64.88.201", "windows", False, "", "fra", 0, 0, seen=now - 2 * 86400 - 3700),
            }}


# ───────────────────────────── ο poller ─────────────────────────────

class WgStatus:
    def __init__(self, state=None, cfg=None, sim=False, runner=None):
        cfg = cfg or {}
        self.state, self.sim = state, sim
        self.enabled = bool(cfg.get("enabled", True))
        self.interval = max(5, int(cfg.get("interval") or 30))
        self.stale_min = max(1, float(cfg.get("stale_min") or 5))
        self.names = {str(k): str(v)[:40] for k, v in (cfg.get("names") or {}).items()}
        if sim and not self.names:
            self.names = {k: n for k, n, _e, _a in SIM_PEERS}
        self.runner = runner or run_cmd
        self.lock = threading.Lock()
        self._t0 = time.time() - 3600
        self.prev = {}      # pubkey → (t, rx, tx)
        self.hist = {}      # pubkey → deque[(rx_rate, tx_rate)]
        self.rates = {}     # pubkey → (rx_rate, tx_rate)
        self.wg_up = {}     # pubkey → True/False (τι είδαμε τελευταία)
        self.ts_up = {}     # node id → online
        self.polls = 0
        self.wg = {"available": False, "interfaces": [], "error": None}
        self.ts = {"available": False, "backend": None, "self": None, "peers": [], "error": None}
        self.hint = None
        self.last_poll = None

    # — συλλογή —
    def _wg_dump(self):
        """(text | None, error | None, hint | None)."""
        exe = find_exe("wg")
        if not exe:
            return None, None, None
        rc, out, err = self.runner([exe, "show", "all", "dump"])
        if rc == 0:
            return out, None, None
        low = (err or "").lower()
        if "not permitted" in low or "permission denied" in low or "access interface" in low:
            return None, "Χωρίς δικαιώματα για το wg show.", HINT_PERM
        return None, (err or "wg απέτυχε").strip()[:200], None

    def _ts_json(self):
        exe = find_exe("tailscale", (TAILSCALE_APP,))
        if not exe:
            return None, None
        rc, out, err = self.runner([exe, "status", "--json"])
        if rc == 0 and out.strip():
            return out, None
        try:  # όταν είναι σταματημένο, το tailscale επιστρέφει ≠0 αλλά καμιά φορά δίνει και JSON
            json.loads(out)
            return out, None
        except ValueError:
            return None, (err or "tailscale απέτυχε").strip()[:200]

    def poll(self, now=None):
        now = time.time() if now is None else now
        if self.sim:
            wg_text, wg_err, hint = sim_wg_dump(now, self._t0), None, None
            ts_js, ts_err = sim_tailscale(now, self._t0), None
            wg_avail = ts_avail = True
        else:
            wg_text, wg_err, hint = self._wg_dump()
            wg_avail = wg_text is not None
            ts_js, ts_err = self._ts_json()
            ts_avail = ts_js is not None
        events = []
        with self.lock:
            first = self.polls == 0
            self.polls += 1
            ifaces = []
            if wg_text is not None:
                try:
                    ifaces = self._ingest_wg(parse_wg_dump(wg_text), now, first, events)
                except Exception as e:
                    wg_err = f"άκυρη έξοδος wg: {e.__class__.__name__}"
            self.wg = {"available": wg_avail, "interfaces": ifaces, "error": wg_err}
            ts = {"available": ts_avail, "backend": None, "self": None, "peers": [], "error": ts_err}
            if ts_js is not None:
                try:
                    p = parse_tailscale(ts_js)
                    ts.update(backend=p["backend"], self=self._ts_out(p["self"], now) if p["self"] else None,
                              peers=[self._ts_out(x, now) for x in p["peers"]])
                    if p["backend"] and p["backend"] != "Running":
                        ts["error"] = f"Tailscale: {p['backend']}"
                        hint = hint or HINT_TS
                    else:
                        self._ts_events(p["peers"], now, first, events)
                except (ValueError, TypeError, KeyError, AttributeError) as e:
                    ts["error"] = f"άκυρο JSON tailscale: {e.__class__.__name__}"
            self.ts = ts
            self.hint = hint
            self.last_poll = now
        if self.state is not None:
            for typ, sev, actor, target, detail, key in events:
                self.state.alert(typ, sev, actor, target, detail, now, key=(typ, key), cooldown=ALERT_COOLDOWN, mark=False)
        return events

    def _ingest_wg(self, ifaces, now, first, events):
        out = []
        seen = set()
        for itf in ifaces:
            peers = []
            for p in itf["peers"]:
                k = p["public_key"]
                seen.add(k)
                pv = self.prev.get(k)
                rr = tr = None
                if pv and now > pv[0]:
                    dt = now - pv[0]
                    rr = max(0.0, (p["rx"] - pv[1]) / dt) if p["rx"] >= pv[1] else 0.0
                    tr = max(0.0, (p["tx"] - pv[2]) / dt) if p["tx"] >= pv[2] else 0.0
                    self.hist.setdefault(k, collections.deque(maxlen=HIST)).append((round(rr, 1), round(tr, 1)))
                    self.rates[k] = (round(rr, 1), round(tr, 1))
                self.prev[k] = (now, p["rx"], p["tx"])
                st = peer_state(p["handshake"], now, self.stale_min)
                name = self.names.get(k) or short_key(k)
                if st == "active":
                    up = True
                elif st == "stale":
                    up = False
                elif st == "idle":  # ενδιάμεσο: κρατάμε ό,τι ξέραμε (ή «πάνω» αν είναι η πρώτη φορά)
                    up = self.wg_up.get(k, True)
                else:  # never: ούτε «χάθηκε» ούτε «επανήλθε»
                    up = None
                was = self.wg_up.get(k)
                if up is not None:
                    if not first and was is True and up is False:
                        events.append(("WireGuard peer χάθηκε", "med", _endpoint_ip(p["endpoint"]) or k[:8], name,
                                       f"Ο WireGuard peer «{name}» ({itf['name']}) δεν έχει κάνει handshake εδώ και "
                                       f"{_ago(now - p['handshake'])} — η σύνδεση φαίνεται να χάθηκε.", k))
                    elif not first and was is False and up is True:
                        events.append(("WireGuard peer επανήλθε", "low", _endpoint_ip(p["endpoint"]) or k[:8], name,
                                       f"Ο WireGuard peer «{name}» ({itf['name']}) συνδέθηκε ξανά"
                                       f"{' από ' + p['endpoint'] if p['endpoint'] else ''}.", k))
                    self.wg_up[k] = up
                rate = self.rates.get(k, (None, None))
                peers.append({"name": name, "key": short_key(k), "endpoint": p["endpoint"], "allowed_ips": p["allowed_ips"],
                              "handshake_ago": int(now - p["handshake"]) if p["handshake"] else None, "state": st,
                              "rx": p["rx"], "tx": p["tx"], "rx_rate": rate[0], "tx_rate": rate[1],
                              "keepalive": p["keepalive"], "hist": [list(h) for h in self.hist.get(k, ())]})
            out.append({"name": itf["name"], "public_key": short_key(itf["public_key"]), "listen_port": itf["listen_port"],
                        "peers": peers})
        for k in list(self.prev):
            if k not in seen:
                for d in (self.prev, self.hist, self.rates, self.wg_up):
                    d.pop(k, None)
        return out

    def _ts_events(self, peers, now, first, events):
        for p in peers:
            was = self.ts_up.get(p["id"])
            if not first and was is not None and was != p["online"]:
                if p["online"]:
                    events.append(("Tailscale συσκευή επανήλθε", "low", p["ip"] or p["name"], p["name"],
                                   f"Η συσκευή «{p['name']}» ({p['ip']}) του tailnet είναι ξανά online"
                                   f"{' (απευθείας)' if p['direct'] else ' (μέσω DERP ' + (p['relay'] or '?') + ')'}.", p["id"]))
                else:
                    events.append(("Tailscale συσκευή εκτός", "med", p["ip"] or p["name"], p["name"],
                                   f"Η συσκευή «{p['name']}» ({p['ip']}, {p['os'] or '?'}) του tailnet βγήκε offline.", p["id"]))
            self.ts_up[p["id"]] = p["online"]

    @staticmethod
    def _ts_out(p, now):
        return {"name": p["name"], "dns": p["dns"], "ip": p["ip"], "os": p["os"], "online": p["online"],
                "direct": p["direct"], "cur_addr": p["cur_addr"], "relay": p["relay"],
                "last_seen_ago": int(now - p["last_seen"]) if p["last_seen"] else None,
                "handshake_ago": int(now - p["last_handshake"]) if p["last_handshake"] else None,
                "rx": p["rx"], "tx": p["tx"], "exit_node": p["exit_node"], "exit_node_option": p["exit_node_option"]}

    def status(self):
        with self.lock:
            errs = [e for e in (self.wg.get("error"), self.ts.get("error")) if e]
            return {"enabled": self.enabled or self.sim, "demo": self.sim, "interval": self.interval,
                    "stale_min": self.stale_min, "last_poll": self.last_poll,
                    "error": " · ".join(errs) if errs else None, "hint": self.hint,
                    "wireguard": json.loads(json.dumps(self.wg)), "tailscale": json.loads(json.dumps(self.ts))}

    def run_forever(self):
        while True:
            if self.enabled or self.sim:
                try:
                    self.poll()
                except Exception:
                    pass
            time.sleep(self.interval)


def _ago(s):
    s = int(max(0, s))
    if s < 90:
        return f"{s}″"
    if s < 5400:
        return f"{s // 60}′"
    if s < 172800:
        return f"{s // 3600} ώρες"
    return f"{s // 86400} μέρες"
