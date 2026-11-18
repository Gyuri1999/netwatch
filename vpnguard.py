"""🛡️ VPN: kill-switch και split tunnel — περνά πράγματι η κίνηση από το VPN;

Κάθε 5″ κοιτάμε (μόνο ανάγνωση — δεν αλλάζουμε ΤΙΠΟΤΑ στο σύστημα):
- ποια διεπαφή έχει τη διαδρομή προς το Internet (route -n get / ip route get),
- ποιες διεπαφές VPN (utun/tun/tap/wg/ppp/ipsec) είναι ενεργές με διεύθυνση (ifconfig / ip -o addr)
  — οι utun0‑3 του macOS που έχουν μόνο link-local fe80 είναι του συστήματος και αγνοούνται,
- τη φυσική διεπαφή (en0 / wlan0 / eth0) και τις IP της.
Λειτουργία: «full» (όλη η κίνηση μέσω VPN), «split» (VPN ενεργό αλλά η προεπιλεγμένη διαδρομή πάει στη
φυσική διεπαφή), «off».

Kill-switch: όταν το VPN πέσει, για 30″ κοιτάμε (lsof) τις συνδέσεις προς δημόσιες IP που ξεκινούν από
IP της φυσικής διεπαφής. Αν υπάρχουν → η κίνηση βγήκε εκτός VPN (δεν υπάρχει kill-switch).
Με `arm()` ο χρήστης ξεκινά δοκιμή: «αποσύνδεσε τώρα το VPN» και βλέπει το αποτέλεσμα.

Split tunnel: με το VPN ενεργό, κάθε σύνδεση κατατάσσεται από την τοπική της διεύθυνση: IP του VPN →
μέσα στο τούνελ, IP της φυσικής διεπαφής → εκτός. Σε full tunnel κάθε εφαρμογή εκτός τούνελ είναι διαρροή.

config.yaml:
vpnguard:
  enabled: true
  interval: 5          # δευτερόλεπτα
  window: 30           # πόσο παρακολουθούμε μετά από πτώση του VPN
"""
import collections
import ipaddress
import re
import subprocess
import sys
import threading
import time

INTERVAL = 5
WINDOW = 30
ARM_DEFAULT = 60
EVENTS_MAX = 50
APP_COOLDOWN = 3600
KS_COOLDOWN = 600

VPN_RE = re.compile(r"(utun|tun|tap|wg|ppp|ipsec)\d*$")
PHYS_RE = re.compile(r"(en|eth|wlan|wlp|wlx|enp|eno|ens|enx)\w*$")
PHYS_PREFER = ("en0", "wlan0", "eth0", "en1", "wlp2s0", "enp0s3")
# οι ίδιοι οι πελάτες VPN μιλούν (λογικά) εκτός τούνελ — με τον VPN server
VPN_CLIENTS = re.compile(r"openvpn|wireguard|wg-quick|wg-go|tunnelblick|viscosity|nordvpn|expressvpn|mullvad|protonvpn|"
                         r"surfshark|tailscale|windscribe|privateinternetaccess|pia-daemon|cyberghost|ivpn|nesessionmanager|"
                         r"neagent|racoon|charon|strongswan|vpnagentd|anyconnect|forticlient|fortitray|pangps|globalprotect|"
                         r"zscaler|cloudflare warp|warp-svc|cloudflared|openconnect|pppd|nebula|zerotier", re.I)

_CONN = re.compile(r"^(?P<l>\[?[0-9a-fA-F:.%\w]*\]?):(?P<lp>\d+|\*)->(?P<r>\[?[0-9a-fA-F:.%\w]+\]?):(?P<rp>\d+)")


def run(cmd, timeout=6):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def _ip(s):
    try:
        return ipaddress.ip_address(s.split("%")[0].strip("[]"))
    except ValueError:
        return None


def is_public(ip):
    a = _ip(ip) if isinstance(ip, str) else ip
    return bool(a) and a.is_global and not a.is_multicast


def is_vpn(name):
    return bool(name and VPN_RE.match(name))


# ---------------- διεπαφές ----------------
def parse_ifconfig(text):
    """`ifconfig` (macOS/BSD) → {iface: {"up": bool, "v4": [..], "v6": [..]}} (τα v6 χωρίς το %scope)."""
    out, cur = {}, None
    for line in (text or "").splitlines():
        m = re.match(r"^([A-Za-z][\w.\-]*):\s+flags=\w+<([^>]*)>", line)
        if m:
            cur = out.setdefault(m.group(1), {"up": False, "v4": [], "v6": []})
            flags = m.group(2).split(",")
            cur["up"] = "UP" in flags
            continue
        if cur is None:
            continue
        s = line.strip()
        m = re.match(r"inet\s+(\d+\.\d+\.\d+\.\d+)", s)
        if m:
            cur["v4"].append(m.group(1))
            continue
        m = re.match(r"inet6\s+([0-9a-fA-F:]+)", s)
        if m:
            cur["v6"].append(m.group(1))
    return out


def parse_ip_addr(text, link_text=None):
    """`ip -o addr` (Linux) → ίδια μορφή με parse_ifconfig. Με `ip -o link` παίρνουμε και το UP."""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\d+:\s+([\w.\-@]+)\s+(inet6?)\s+([0-9a-fA-F:.]+)(?:/\d+)?", line)
        if not m:
            continue
        name = m.group(1).split("@")[0]
        d = out.setdefault(name, {"up": True, "v4": [], "v6": []})
        d["v4" if m.group(2) == "inet" else "v6"].append(m.group(3))
    for line in (link_text or "").splitlines():
        m = re.match(r"^\d+:\s+([\w.\-@]+):\s+<([^>]*)>", line)
        if m:
            name = m.group(1).split("@")[0]
            if name in out:
                out[name]["up"] = "UP" in m.group(2).split(",")
    return out


def usable_ips(d):
    """Οι διευθύνσεις μιας διεπαφής που μετράνε (χωρίς link-local fe80/169.254 και loopback)."""
    res = []
    for ip in list(d.get("v4", [])) + list(d.get("v6", [])):
        a = _ip(ip)
        if a and not a.is_link_local and not a.is_loopback and not a.is_unspecified:
            res.append(str(a))
    return res


def vpn_ifaces(ifs):
    """Διεπαφές VPN ενεργές ΚΑΙ με πραγματική διεύθυνση (οι utun0‑3 του macOS με μόνο fe80 δεν μετράνε)."""
    return sorted((n for n, d in ifs.items() if is_vpn(n) and d.get("up") and usable_ips(d)),
                  key=lambda n: (re.sub(r"\d+$", "", n), int(re.search(r"(\d*)$", n).group(1) or 0)))


def physical_iface(ifs, egress=None):
    """Η φυσική διεπαφή προς το Internet: αυτή της διαδρομής αν δεν είναι VPN, αλλιώς en0/wlan0/eth0 με IPv4."""
    if egress and not is_vpn(egress) and egress in ifs:
        return egress

    def ok(n):
        d = ifs.get(n) or {}
        return d.get("up") and any(_ip(x) and not _ip(x).is_link_local for x in d.get("v4", []))
    for n in PHYS_PREFER:
        if ok(n):
            return n
    for n in sorted(ifs):
        if PHYS_RE.match(n) and ok(n):
            return n
    return egress if egress and not is_vpn(egress) else None


def detect_mode(egress, vpns):
    """full: η διαδρομή προς το Internet πάει σε VPN· split: VPN ενεργό αλλά η διαδρομή είναι φυσική· off."""
    if egress and is_vpn(egress) and (egress in vpns or not vpns):
        return "full"
    if vpns:
        return "split"
    return "off"


def route_iface(dest="1.1.1.1", platform=None):
    """Από ποια διεπαφή φεύγει η κίνηση προς `dest` (πιάνει και VPN που βάζουν 0/1 + 128/1 αντί για default)."""
    platform = platform or sys.platform
    if platform == "darwin":
        m = re.search(r"interface:\s*(\S+)", run(["route", "-n", "get", dest]))
    else:
        m = re.search(r"\bdev\s+(\S+)", run(["ip", "route", "get", dest]))
    return m.group(1) if m else None


def snapshot_live():
    """Ένα «στιγμιότυπο» του δικτύου: διεπαφές, διαδρομή προς το Internet και default route."""
    if sys.platform == "darwin":
        ifs = parse_ifconfig(run(["ifconfig"]))
    else:
        ifs = parse_ip_addr(run(["ip", "-o", "addr"]), run(["ip", "-o", "link"]))
    try:
        import wifiguard
        default = wifiguard.default_iface()
    except Exception:
        default = None
    egress = route_iface("1.1.1.1") or default
    return {"ifaces": ifs, "default": default or egress, "egress": egress}


# ---------------- συνδέσεις ----------------
def parse_lsof_local(text):
    """`lsof -nP -i` → [{app, pid, proto, lip, ip, port}] — όπως apps.parse_lsof_conns, αλλά κρατά και την ΤΟΠΙΚΗ IP."""
    out = []
    for line in (text or "").splitlines()[1:]:
        cols = line.split()
        if len(cols) < 9:
            continue
        proto = cols[7].upper()
        if proto not in ("TCP", "UDP"):
            continue
        m = _CONN.match(cols[8])
        if not m:
            continue
        state = cols[9].strip("()") if len(cols) > 9 else ""
        if proto == "TCP" and state and state not in ("ESTABLISHED", "SYN_SENT"):
            continue
        r, lo = _ip(m.group("r")), _ip(m.group("l"))
        if not r or not lo or r.is_loopback or r.is_unspecified or r.is_multicast:
            continue
        out.append({"app": cols[0].replace("\\x20", " "), "pid": int(cols[1]) if cols[1].isdigit() else 0,
                    "proto": proto, "lip": str(lo), "ip": str(r), "port": int(m.group("rp"))})
    return out


def conns_live():
    try:
        import apps
        text = apps.run_lsof()
    except Exception:
        text = run(["lsof", "-nP", "-i"], timeout=8)
    return parse_lsof_local(text)


def classify(conns, vpn_ips, phys_ips):
    """Ανά εφαρμογή: πόσοι δημόσιοι προορισμοί μέσω VPN και πόσοι εκτός (κατά την τοπική IP της σύνδεσης)."""
    vpn_ips, phys_ips = set(vpn_ips or ()), set(phys_ips or ())
    apps = {}
    for c in conns:
        if not is_public(c["ip"]):
            continue
        side = "via_vpn" if c["lip"] in vpn_ips else "outside" if c["lip"] in phys_ips else None
        if not side:
            continue
        a = apps.setdefault(c["app"], {"name": c["app"], "pid": c["pid"], "via_vpn": set(), "outside": set(),
                                       "sample": None, "vpn_client": bool(VPN_CLIENTS.search(c["app"]))})
        a[side].add((c["ip"], c["port"]))
        if side == "outside" and not a["sample"]:
            a["sample"] = f"[{c['ip']}]:{c['port']}" if ":" in c["ip"] else f"{c['ip']}:{c['port']}"
            a["pid"] = c["pid"]
    res = [dict(a, via_vpn=len(a["via_vpn"]), outside=len(a["outside"])) for a in apps.values()]
    res.sort(key=lambda a: (-a["outside"], -a["via_vpn"], a["name"].lower()))
    return res


def leaking_apps(conns, phys_ips):
    """Εφαρμογές (όχι πελάτες VPN) με σύνδεση προς δημόσια IP από IP της φυσικής διεπαφής."""
    phys_ips = set(phys_ips or ())
    out = {}
    for c in conns:
        if c["lip"] in phys_ips and is_public(c["ip"]) and not VPN_CLIENTS.search(c["app"]):
            a = out.setdefault(c["app"], {"name": c["app"], "pid": c["pid"], "remotes": set()})
            a["remotes"].add((c["ip"], c["port"]))
    return out


# ---------------- demo ----------------
SIM_PHYS = {"up": True, "v4": ["192.168.1.23"], "v6": ["fe80::1c2b:3a4f:9e10:7d21", "2a02:587:d4a1:c00::23"]}
SIM_VPN = {"up": True, "v4": ["10.64.12.7"], "v6": ["fc00:bbbb:bbbb:bb01::c:7"]}


def _sim_ifaces(vpn_up):
    ifs = {"lo0": {"up": True, "v4": ["127.0.0.1"], "v6": ["::1"]}, "en0": dict(SIM_PHYS),
           "utun0": {"up": True, "v4": [], "v6": ["fe80::d1e:4a2:1b0c:9e01"]},
           "utun1": {"up": True, "v4": [], "v6": ["fe80::8e4f:3ad:c5b0:21"]},
           "utun2": {"up": True, "v4": [], "v6": ["fe80::ce81:b1c:bd2c:69e"]},
           "utun3": {"up": True, "v4": [], "v6": ["fe80::7a1:f2e4:6e0b:4c9"]}}
    if vpn_up:
        ifs["utun4"] = dict(SIM_VPN)
    return ifs


SIM_CONNS_UP = [  # (εφαρμογή, pid, τοπική, απομακρυσμένη, θύρα)
    ("Google Chrome", 812, "10.64.12.7", "142.250.185.78", 443),
    ("Google Chrome", 812, "10.64.12.7", "151.101.1.69", 443),
    ("Google Chrome", 812, "10.64.12.7", "104.244.42.1", 443),
    ("Slack", 944, "10.64.12.7", "52.89.214.238", 443),
    ("Mail", 655, "10.64.12.7", "17.42.251.41", 993),
    ("Spotify", 1203, "192.168.1.23", "35.186.224.47", 443),
    ("Spotify", 1203, "192.168.1.23", "34.98.75.36", 443),
    ("Spotify", 1203, "10.64.12.7", "104.199.65.124", 4070),
    ("Dropbox", 1377, "192.168.1.23", "162.125.19.131", 443),
    ("Dropbox", 1377, "2a02:587:d4a1:c00::23", "2620:100:6017:14::a27d:20e", 443),
    ("WireGuard", 402, "192.168.1.23", "185.65.134.77", 51820),
]
SIM_CONNS_DOWN = [
    ("Google Chrome", 812, "192.168.1.23", "142.250.185.78", 443),
    ("Google Chrome", 812, "192.168.1.23", "157.240.0.35", 443),
    ("Spotify", 1203, "192.168.1.23", "35.186.224.47", 443),
    ("Dropbox", 1377, "192.168.1.23", "162.125.19.131", 443),
]


def _sim_conns(rows):
    return [{"app": a, "pid": p, "proto": "UDP" if port == 51820 else "TCP", "lip": lip, "ip": ip, "port": port}
            for a, p, lip, ip, port in rows]


class VpnGuard:
    def __init__(self, state=None, cfg=None, sim=False, snapshot=None, lister=None, clock=None):
        cfg = cfg or {}
        self.state, self.sim = state, sim
        self.enabled = bool(cfg.get("enabled", True))
        self.interval = max(1, int(cfg.get("interval") or INTERVAL))
        self.window_s = max(5, int(cfg.get("window") or WINDOW))
        self.clock = clock or time.time
        self.lock = threading.Lock()
        self.events = collections.deque(maxlen=EVENTS_MAX)
        self.error = None
        self.mode, self.vpn, self.phys, self.default = "off", {"iface": None, "ips": []}, {"iface": None, "ips": []}, None
        self.apps = []
        self.prev_vpn = None       # None = δεν έχουμε δει ακόμη στιγμιότυπο
        self.prev_mode = None
        self.armed_until = None
        self.window = None         # {"start", "until", "armed", "apps": {...}}
        self.last = None           # {"t", "verdict", "apps", "armed"}
        self.checked = None
        if sim:
            self._sim_drop = None  # (αρχή, τέλος) της προσομοιωμένης πτώσης
            self.snapshot = snapshot or self._sim_snapshot
            self.lister = lister or self._sim_lister
            self._seed_sim()
            self.tick()
        else:
            self.snapshot = snapshot or snapshot_live
            self.lister = lister or conns_live

    # ── demo ──
    def _sim_vpn_up(self, now):
        d = self._sim_drop
        return not (d and d[0] <= now < d[1])

    def _sim_snapshot(self):
        up = self._sim_vpn_up(self.clock())
        return {"ifaces": _sim_ifaces(up), "default": "utun4" if up else "en0", "egress": "utun4" if up else "en0"}

    def _sim_lister(self):
        return _sim_conns(SIM_CONNS_UP if self._sim_vpn_up(self.clock()) else SIM_CONNS_DOWN)

    def _seed_sim(self):
        now = self.clock()
        t0 = now - 2 * 3600 - 17 * 60
        self.events.extend([
            {"t": now - 26 * 3600, "kind": "up", "iface": "utun4", "mode": "full", "text": "VPN ενεργό (utun4) — όλη η κίνηση μέσω VPN"},
            {"t": t0, "kind": "down", "iface": "utun4", "mode": "off", "text": "Το VPN έπεσε (utun4)"},
            {"t": t0 + 30, "kind": "killswitch", "iface": None, "mode": "off",
             "text": "Χωρίς kill-switch: το Google Chrome έστειλε κίνηση εκτός VPN"},
            {"t": t0 + 41, "kind": "up", "iface": "utun4", "mode": "full", "text": "VPN ενεργό (utun4) — όλη η κίνηση μέσω VPN"},
        ])
        self.last = {"t": t0 + 30, "verdict": "fail", "armed": False,
                     "apps": [{"name": "Google Chrome", "pid": 812, "remotes": 3, "sample": "142.250.185.78:443"}]}
        self.prev_vpn, self.prev_mode = "utun4", "full"

    # ── βοηθητικά ──
    def _event(self, now, kind, text, iface=None):
        self.events.append({"t": round(now, 1), "kind": kind, "iface": iface, "mode": self.mode, "text": text})

    def _alert(self, typ, sev, actor, target, detail, now, key, cooldown):
        if self.state is not None:
            try:
                self.state.alert(typ, sev, actor, target, detail, now, key=key, cooldown=cooldown, mark=False)
            except Exception:
                pass

    def arm(self, seconds=ARM_DEFAULT):
        """Ο χρήστης ξεκινά δοκιμή: «αποσύνδεσε τώρα το VPN». Επιστρέφει {ok, until} ή {ok: False, error}."""
        now = self.clock()
        seconds = max(10, min(int(seconds or ARM_DEFAULT), 600))
        with self.lock:
            if self.mode == "off" and self.checked is not None:
                return {"ok": False, "error": "Το VPN δεν είναι ενεργό — σύνδεσέ το πρώτα και ξαναπάτα τη δοκιμή."}
            self.armed_until = now + seconds
            if self.sim:
                self._sim_drop = (now + min(8, seconds / 2), now + min(8, seconds / 2) + 14)
        return {"ok": True, "until": round(now + seconds, 1),
                "text": f"Έτοιμο: αποσύνδεσε τώρα το VPN (έχεις {seconds}″). Μην κλείσεις τις εφαρμογές."}

    # ── κύκλος ──
    def tick(self, now=None):
        now = self.clock() if now is None else now
        snap = self.snapshot() or {}
        ifs = snap.get("ifaces") or {}
        egress = snap.get("egress") or snap.get("default")
        vpns = vpn_ifaces(ifs)
        mode = detect_mode(egress, vpns)
        vpn_if = egress if egress in vpns else (vpns[0] if vpns else None)
        phys_if = physical_iface(ifs, egress)
        vpn_ips = usable_ips(ifs.get(vpn_if) or {}) if vpn_if else []
        phys_ips = usable_ips(ifs.get(phys_if) or {}) if phys_if else []
        need_conns = bool(vpn_if) or self.window is not None or (self.prev_vpn and not vpn_if)
        conns, self.error = None, None
        if need_conns:
            try:
                conns = self.lister() or []
            except Exception as e:
                conns, self.error = [], f"lsof: {e}"[:160]
        alerts = []
        with self.lock:
            self.mode, self.default, self.checked = mode, snap.get("default"), now
            self.vpn = {"iface": vpn_if, "ips": vpn_ips}
            self.phys = {"iface": phys_if, "ips": phys_ips}
            first = self.prev_vpn is None and self.prev_mode is None
            was_up = bool(self.prev_vpn)
            # γεγονότα
            if first:
                if vpn_if:
                    self._event(now, "up", f"VPN ενεργό ({vpn_if}) — {self._mode_txt(mode)}", vpn_if)
            elif vpn_if and not was_up:
                self._event(now, "up", f"VPN ενεργό ({vpn_if}) — {self._mode_txt(mode)}", vpn_if)
            elif was_up and not vpn_if:
                self._event(now, "down", f"Το VPN έπεσε ({self.prev_vpn})", self.prev_vpn)
                armed = bool(self.armed_until and now <= self.armed_until)
                self.window = {"start": now, "until": now + self.window_s, "armed": armed, "apps": {}}
                if armed:
                    self.armed_until = None
            elif vpn_if and was_up and vpn_if != self.prev_vpn:
                self._event(now, "mode", f"Το VPN άλλαξε διεπαφή: {self.prev_vpn} → {vpn_if}", vpn_if)
            elif mode != self.prev_mode and vpn_if:
                self._event(now, "mode", f"Αλλαγή λειτουργίας: {self._mode_txt(self.prev_mode)} → {self._mode_txt(mode)}", vpn_if)
            self.prev_vpn, self.prev_mode = vpn_if, mode
            # παράθυρο kill-switch
            if self.window is not None:
                if conns and not vpn_if:  # μετράμε μόνο όσο το VPN είναι κάτω
                    for name, a in leaking_apps(conns, phys_ips).items():
                        w = self.window["apps"].setdefault(name, {"name": name, "pid": a["pid"], "remotes": set()})
                        w["remotes"] |= a["remotes"]
                if now >= self.window["until"]:
                    alerts += self._close_window(now)
            elif self.armed_until and now > self.armed_until:
                self.last = {"t": round(now, 1), "verdict": "no-drop", "apps": [], "armed": True}
                self.armed_until = None
                self._event(now, "killswitch", "Η δοκιμή kill-switch έληξε χωρίς να πέσει το VPN")
            # split tunnel
            if vpn_if and conns is not None:
                self.apps = classify(conns, vpn_ips, phys_ips)
                if mode == "full":
                    for a in self.apps:
                        if a["outside"] and not a["vpn_client"]:
                            alerts.append(("Εφαρμογή εκτός VPN", "low", a["name"], a["sample"],
                                           f"Το VPN είναι σε full tunnel, αλλά η εφαρμογή «{a['name']}» (pid {a['pid']}) μιλά με "
                                           f"{a['outside']} δημόσιο(υς) προορισμό(ούς) από τη φυσική διεπαφή {phys_if} "
                                           f"(π.χ. {a['sample']}) — αυτή η κίνηση ΔΕΝ περνά από το VPN και ο πάροχος/το "
                                           "δίκτυο βλέπει την πραγματική σου IP. Έλεγξε εξαιρέσεις (split tunneling/«bypass») "
                                           "στις ρυθμίσεις του VPN ή αν η εφαρμογή «δένει» σε συγκεκριμένη διεπαφή.",
                                           ("app", a["name"]), APP_COOLDOWN))
            elif not vpn_if:
                self.apps = []
        for typ, sev, actor, target, detail, key, cd in alerts:
            self._alert(typ, sev, actor, target, detail, now, key, cd)
        return mode

    def _close_window(self, now):
        w, self.window = self.window, None
        apps = sorted(({"name": a["name"], "pid": a["pid"], "remotes": len(a["remotes"]),
                        "sample": next((f"{ip}:{p}" if ":" not in ip else f"[{ip}]:{p}" for ip, p in sorted(a["remotes"])), None)}
                       for a in w["apps"].values()), key=lambda a: (-a["remotes"], a["name"].lower()))
        verdict = "fail" if apps else "pass"
        self.last = {"t": round(now, 1), "verdict": verdict, "apps": apps, "armed": w["armed"]}
        if not apps:
            self._event(now, "killswitch", "kill-switch OK: καμία κίνηση εκτός VPN μετά την πτώση")
            return []
        names = ", ".join(a["name"] for a in apps[:5]) + (" …" if len(apps) > 5 else "")
        self._event(now, "killswitch", f"Χωρίς kill-switch: κίνηση εκτός VPN από {names}")
        detail = (f"Μέσα σε {int(now - w['start'])}″ από την πτώση του VPN, οι εφαρμογές {names} συνέχισαν να μιλούν με "
                  "δημόσιες IP απευθείας από τη φυσική διεπαφή — με την πραγματική σου IP. Ενεργοποίησε στο VPN "
                  "«Kill switch» / «Block connections without VPN» (ή «Always-on VPN»), ώστε να κόβεται όλη η κίνηση "
                  "όταν πέφτει το τούνελ.")
        return [("Χωρίς kill-switch: κίνηση εκτός VPN", "med", apps[0]["name"], names, detail, ("killswitch",), KS_COOLDOWN)]

    @staticmethod
    def _mode_txt(mode):
        return {"full": "όλη η κίνηση μέσω VPN", "split": "split tunnel (μέρος της κίνησης εκτός VPN)",
                "off": "χωρίς VPN"}.get(mode, str(mode))

    def status(self):
        now = self.clock()
        with self.lock:
            armed = bool(self.armed_until and now <= self.armed_until)
            win = self.window
            if self.mode == "full":
                note = ("Όλη η κίνηση περνά από το VPN. Εφαρμογές που βγαίνουν από τη φυσική διεπαφή είναι διαρροές."
                        if not any(a["outside"] and not a["vpn_client"] for a in self.apps)
                        else "Full tunnel — αλλά κάποιες εφαρμογές βγαίνουν εκτός VPN (διαρροή).")
            elif self.mode == "split":
                note = ("Split tunnel: το VPN είναι ενεργό, αλλά η προεπιλεγμένη διαδρομή πάει στη φυσική διεπαφή — "
                        "μόνο ό,τι έχει ρυθμιστεί περνά από το VPN. Οι εφαρμογές εκτός τούνελ είναι αναμενόμενες.")
            else:
                note = "Δεν υπάρχει ενεργό VPN."
            note += " Χωρίς root το lsof βλέπει μόνο τις διεργασίες του χρήστη." if not self.sim else ""
            return {"enabled": self.enabled, "demo": self.sim, "error": self.error, "mode": self.mode,
                    "vpn": dict(self.vpn), "physical": dict(self.phys), "default_iface": self.default,
                    "checked": self.checked, "interval": self.interval,
                    "events": list(reversed(self.events)),
                    "killswitch": {"armed": armed, "until": round(self.armed_until, 1) if armed else None,
                                   "watching": bool(win), "watch_until": round(win["until"], 1) if win else None,
                                   "window": self.window_s, "last": dict(self.last) if self.last else None},
                    "apps": [{"name": a["name"], "pid": a["pid"], "via_vpn": a["via_vpn"], "outside": a["outside"],
                              "sample": a["sample"], "vpn_client": a["vpn_client"],
                              "leak": bool(self.mode == "full" and a["outside"] and not a["vpn_client"])}
                             for a in self.apps],
                    "note": note}

    def run_forever(self):
        while True:
            try:
                self.tick()
            except Exception as e:
                self.error = str(e)[:200]
            time.sleep(self.interval)
