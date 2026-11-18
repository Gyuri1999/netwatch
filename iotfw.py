"""🧱 Μικρο-τμηματοποίηση IoT: «μαθαίνει» με ποιους μιλά κανονικά κάθε συσκευή του LAN και φτιάχνει κανόνες firewall.

Για κάθε τοπική συσκευή (κλειδί: MAC όταν την ξέρουμε, αλλιώς IP) κρατάμε ένα προφίλ με τους προορισμούς της
(όνομα SNI/DNS αν το ξέρουμε, ομαδοποιημένο στο «καταχωρημένο» domain, π.χ. *.tplinkcloud.com — αλλιώς σκέτη IP),
τα πρωτόκολλα/θύρες, τους «γείτονες» στο LAN και ποιον DNS χρησιμοποιεί.

Λειτουργίες ανά συσκευή:
  learn  — μαθαίνει (προεπιλογή για νέες συσκευές, για `learn_hours` ώρες). Μετά, οι IoT συσκευές (κάμερες,
           ESP32, πρίζες, TV, ηχεία, εκτυπωτές) περνούν αυτόματα σε watch (`auto_watch`).
  watch  — ό,τι νέο (domain/IP:θύρα εκτός προφίλ) γίνεται «παράβαση»: ειδοποίηση + λίστα «προς έγκριση».
  off    — αγνοείται.

Είναι ΚΑΘΑΡΑ παθητικό: δεν αγγίζει ποτέ τον router. Η `rules()` απλώς παράγει κείμενο (OpenWrt fw4/nftables,
pfSense/OPNsense, MikroTik RouterOS, iptables) που αντιγράφει ο χρήστης. Τα προφίλ σώζονται σε JSON (ατομικά).

config.yaml:
iot_firewall:
  enabled: true
  learn_hours: 24          # πόσες ώρες μαθαίνει μια νέα συσκευή
  alert_severity: med      # βασική σοβαρότητα παράβασης (low | med | high)
  max_destinations: 200    # όριο προορισμών ανά συσκευή (φραγμένη μνήμη)
  auto_watch: true         # μετά τη μάθηση, οι IoT συσκευές περνούν σε watch
  ignore: []               # IP ή MAC συσκευών που αγνοούμε
"""
import functools
import ipaddress
import json
import os
import random
import re
import threading
import time

ALERT_TYPE = "IoT: επικοινωνία εκτός προφίλ"
ALERT_COOLDOWN = 6 * 3600
MAX_ALERTS_HOUR = 10          # ανά συσκευή — οι υπόλοιπες παραβάσεις καταγράφονται χωρίς ειδοποίηση
MAX_DEVICES = 300
MAX_LAN = 64
MAX_PENDING = 50
MAX_VIOL = 20
MAX_IPS = 16
MAX_NAMES = 8
MAX_DNS_EXT = 16
TOP_DESTS = 40
MODES = ("learn", "watch", "off")
SEVS = ("low", "med", "high")
IOT_KINDS = ("camera", "esp", "iot", "tv", "speaker", "printer")
COMMON_PORTS = {53, 80, 123, 443, 853, 1883, 8883, 5228, 3478, 5349, 8080, 8443}
FORMATS = [{"id": "openwrt", "label": "OpenWrt (fw4 / nftables)"},
           {"id": "pfsense", "label": "pfSense / OPNsense"},
           {"id": "mikrotik", "label": "MikroTik RouterOS"},
           {"id": "iptables", "label": "iptables (γενικό Linux)"}]
FMT_IDS = tuple(f["id"] for f in FORMATS)
RFC1918 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_FQDN = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SLD2 = {"co", "com", "net", "org", "gov", "edu", "ac"}


# ── βοηθητικά ──
@functools.lru_cache(maxsize=8192)
def _addr(ip):
    try:
        return ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return None


@functools.lru_cache(maxsize=8192)
def ip_class(ip):
    """→ "local" (ιδιωτική/LAN), "public", ή None (multicast/broadcast/loopback/άκυρη)."""
    a = _addr(ip)
    if a is None or a.is_multicast or a.is_loopback or a.is_unspecified:
        return None
    if a.version == 4 and (str(a) == "255.255.255.255" or str(a).endswith(".255")):
        return None
    if a.is_global:
        return "public"
    if a.version == 6 and a.is_link_local:
        return None
    return "local"


def reg_domain(name):
    """'a.b.example.co.uk' → 'example.co.uk' (απλή προσέγγιση χωρίς public-suffix list)."""
    parts = str(name).lower().rstrip(".").split(".")
    if len(parts) < 2:
        return str(name).lower()
    n = 3 if len(parts) >= 3 and parts[-2] in SLD2 and len(parts[-1]) == 2 else 2
    return ".".join(parts[-n:])


def norm_mac(m):
    if not m:
        return None
    m = ":".join(p.zfill(2) for p in str(m).lower().replace("-", ":").split(":"))
    return m if _MAC.match(m) else None


def _bump(sev, n=1):
    return SEVS[min(len(SEVS) - 1, SEVS.index(sev) + n)]


def _slug(s, n=12):
    s = re.sub(r"[^a-z0-9]+", "_", str(s or "").lower()).strip("_")
    return (s or "dev")[:n].strip("_") or "dev"


def _ascii(s, n=60):
    return re.sub(r"[^A-Za-z0-9 .*_:/@-]", "", str(s or ""))[:n]


def _is_outbound(P):
    """Μόνο πακέτα που ΞΕΚΙΝΟΥΝ σύνδεση/ροή από τη συσκευή (όχι απαντήσεις μιας συσκευής-server)."""
    proto = P.get("proto")
    if proto == "ICMP":
        return P.get("icmp_type") == 8
    if proto not in ("TCP", "UDP"):
        return False
    sp, dp = P.get("sp"), P.get("dp")
    if dp is None:
        return False
    fl = P.get("flags") or ""
    if proto == "TCP" and "S" in fl:
        return "A" not in fl
    return sp is None or sp > dp


class IotFw:
    def __init__(self, state=None, cfg=None, sim=False, path=None):
        cfg = cfg or {}
        self.state, self.sim, self.path = state, sim, path
        self.enabled = bool(cfg.get("enabled", True))
        lh = cfg.get("learn_hours", 24)
        self.learn_s = float(cfg["learn_minutes"]) * 60 if cfg.get("learn_minutes") else float(lh) * 3600
        if sim and not cfg.get("learn_minutes"):
            self.learn_s = 180.0          # στο demo η μάθηση κρατά 3 λεπτά
        sev = str(cfg.get("alert_severity") or "med").lower()
        self.base_sev = sev if sev in SEVS else "med"
        self.max_dest = max(5, int(cfg.get("max_destinations") or 200))
        self.auto_watch = bool(cfg.get("auto_watch", True))
        self.ignore = {str(x).lower() for x in (cfg.get("ignore") or []) if x}
        self.lock = threading.Lock()
        self.devs = {}       # κλειδί → προφίλ
        self.ip_key = {}     # IP → κλειδί
        self.error = None
        self.dirty = False
        self._cd = {}        # (κλειδί, προορισμός) → t τελευταίας ειδοποίησης
        self._rate = {}      # κλειδί → [t ειδοποιήσεων της τελευταίας ώρας]
        self.sim_meta = {}   # demo: IP → {name, vendor, kind}
        self.sim_geo = {}    # demo: IP → (cc, χώρα, όνομα, intel)
        self.rnd = random.Random(7)
        self._load()
        if sim:
            self._seed_sim()

    # ── πληροφορίες από το state (χωρίς δικό μας lock) ──
    def _gw(self):
        return getattr(self.state, "gateway", None) if self.state is not None else None

    def _me(self):
        return set(getattr(self.state, "me", ()) or ()) if self.state is not None else set()

    def _remote_info(self, ip):
        """→ (ονόματα, κωδικός χώρας, χώρα, intel) για απομακρυσμένη IP."""
        if ip in self.sim_geo:
            cc, country, name, intel = self.sim_geo[ip]
            return ([name] if name else []), cc, country, intel
        st = self.state
        names, cc, country, intel = [], None, None, False
        if st is None:
            return names, cc, country, intel
        try:
            dm = getattr(st, "domains", None)
            if dm is not None and ip in dm:
                names = sorted(dm.get(ip) or ())
            h = (getattr(st, "hosts", None) or {}).get(ip)
            if h:
                if not names:
                    names = sorted(h.get("names") or ()) or ([h["rdns"]] if h.get("rdns") else [])
                g = h.get("geo") or {}
                cc, country = g.get("countryCode"), g.get("country")
                intel = bool(h.get("intel"))
        except Exception:
            pass
        return names, cc, country, intel

    def _mac_of(self, ip, P):
        m = norm_mac(P.get("smac")) if P.get("smac") else None
        if m and not (int(m[:2], 16) & 1):
            return m
        st = self.state
        if st is None:
            return None
        try:
            h = (getattr(st, "hosts", None) or {}).get(ip)
            m = norm_mac(h.get("mac")) if h else None
            return m or norm_mac((getattr(st, "arp_table", None) or {}).get(ip))
        except Exception:
            return None

    # ── κάθε πακέτο ──
    def observe(self, P, t=None):
        """Φτηνό: καλείται για κάθε πακέτο (μέσα από το detect). Μετρά μόνο συσκευή του LAN → οτιδήποτε."""
        if not self.enabled or P.get("proto") not in ("TCP", "UDP", "ICMP"):
            return None
        src, dst = P.get("src"), P.get("dst")
        if not src or not dst or ip_class(src) != "local" or src in self.ignore:
            return None
        dcls = ip_class(dst)
        if dcls is None or not _is_outbound(P):
            return None
        t = t if t is not None else (P.get("t") or time.time())
        gw, me = self._gw(), self._me()
        mac = self._mac_of(src, P)
        if mac and mac in self.ignore:
            return None
        proto, port = P["proto"], (P.get("dp") if P["proto"] != "ICMP" else None)
        info = None
        if dcls == "public":
            names, cc, country, intel = self._remote_info(dst)
            nm = P.get("sni") or P.get("http_host") or (names[0] if names else None)
            info = (str(nm).lower().rstrip(".") if nm else None, cc, country, intel)
        fire = None
        with self.lock:
            d = self._device(src, mac, t, gw, me)
            if d is None or d["mode"] == "off":
                return None
            d["last"] = max(d["last"], t)
            d["pkts"] += 1
            self._learn_tick(d, t)
            # DNS: στο gateway / στο LAN ή σε εξωτερικό resolver
            if port in (53, 853) and proto in ("TCP", "UDP"):
                if dcls == "local":
                    d["dns"]["gateway" if dst == gw else "lan"] += 1
                    return "dns"
                ext = d["dns"]["external"]
                if dst in ext or len(ext) < MAX_DNS_EXT:
                    ext[dst] = ext.get(dst, 0) + 1
            if dcls == "local":
                if dst == src:
                    return None
                self._lan(d, dst, proto, port, t, gw, me)
                self.dirty = True
                return "lan"
            fire = self._dest(d, dst, proto, port, t, info)
            self.dirty = True
        if fire and self.state is not None:
            try:
                self.state.alert(ALERT_TYPE, fire["sev"], src, dst, fire["detail"], t,
                                 key=(d["key"], fire["dest"]), cooldown=ALERT_COOLDOWN)
            except Exception:
                pass
        return fire or "dest"

    def _new_dev(self, key, ip, mac, t, mode="learn"):
        return {"key": key, "ip": ip, "ips": [ip], "mac": mac, "mode": mode, "first": t, "last": t, "pkts": 0,
                "learn_start": t, "learn_until": t + self.learn_s, "learned_auto": False,
                "dests": {}, "pending": {}, "lan": {}, "violations": [], "full": False,
                "dns": {"gateway": 0, "lan": 0, "external": {}}, "meta": {}}

    def _device(self, ip, mac, t, gw, me):
        key = self.ip_key.get(ip)
        if mac and key != mac:
            if mac in self.devs:
                key = mac
            elif key and key in self.devs and not _MAC.match(key):  # ξέραμε μόνο την IP → τώρα και MAC
                d = self.devs.pop(key)
                d["key"], d["mac"] = mac, mac
                self.devs[mac] = d
                key = mac
            else:
                key = None
        if key is None or key not in self.devs:
            key = mac or ip
            if key not in self.devs:
                if len(self.devs) >= MAX_DEVICES:
                    old = min(self.devs, key=lambda k: self.devs[k]["last"])
                    del self.devs[old]
                    self.ip_key = {i: k for i, k in self.ip_key.items() if k != old}
                mode = "off" if (ip == gw or ip in me) else "learn"
                self.devs[key] = self._new_dev(key, ip, mac, t, mode)
        self.ip_key[ip] = key
        d = self.devs[key]
        if d["ip"] != ip:
            d["ip"] = ip
        if ip not in d["ips"]:
            d["ips"] = (d["ips"] + [ip])[-6:]
        return d

    def _learn_tick(self, d, t):
        """Τέλος παραθύρου μάθησης → watch για IoT συσκευές (αν auto_watch)."""
        kind = (d.get("meta") or {}).get("kind")
        if d["mode"] == "learn" and t >= d["learn_until"] and not d["learned_auto"] and kind:
            d["learned_auto"] = True   # ο τύπος έρχεται από το status() — χωρίς αυτόν περιμένουμε
            if self.auto_watch and kind in IOT_KINDS:
                d["mode"] = "watch"

    def _lan(self, d, dst, proto, port, t, gw, me):
        k = f"{dst}|{proto}/{port}" if port is not None else f"{dst}|{proto}"
        e = d["lan"].get(k)
        if e is None:
            if len(d["lan"]) >= MAX_LAN:
                return
            e = d["lan"][k] = {"key": k, "ip": dst, "proto": proto, "port": port, "first": t, "last": t, "pkts": 0,
                               "gw": dst == gw, "me": dst in me}
        e["last"] = max(e["last"], t)
        e["pkts"] += 1

    @staticmethod
    def dest_key(name, ip, proto, port):
        grp = reg_domain(name) if name and not _addr(name) else ip
        return f"{grp}|{proto}/{port}" if port is not None else f"{grp}|{proto}"

    def _dest(self, d, ip, proto, port, t, info):
        name, cc, country, intel = info
        k = self.dest_key(name, ip, proto, port)
        known = d["dests"].get(k)
        if known is None and d["mode"] == "learn":
            if len(d["dests"]) >= self.max_dest:
                d["full"] = True
                return None
            known = d["dests"][k] = self._mk_dest(k, name, ip, proto, port, t)
        if known is not None:
            self._touch(known, name, ip, t, cc, country, intel)
            return None
        # watch: προορισμός εκτός προφίλ
        p = d["pending"].get(k)
        if p is None:
            if len(d["pending"]) >= MAX_PENDING:
                return None
            p = d["pending"][k] = self._mk_dest(k, name, ip, proto, port, t)
        self._touch(p, name, ip, t, cc, country, intel)
        ck = (d["key"], k)
        if ck in self._cd and t - self._cd[ck] < ALERT_COOLDOWN:
            return None
        sev, reasons = self.base_sev, []
        countries = {x.get("cc") for x in d["dests"].values() if x.get("cc")}
        if intel:
            sev = "high"
            reasons.append("η IP είναι σε λίστα απειλών (threat intel)")
        if cc and countries and cc not in countries:
            sev = _bump(sev)
            reasons.append(f"νέα χώρα ({country or cc})")
        if port is not None and port not in COMMON_PORTS:
            sev = _bump(sev)
            reasons.append(f"ασυνήθιστη θύρα {proto}/{port}")
        self._cd[ck] = t
        v = {"t": round(t, 1), "dest": k, "name": p["name"], "ip": ip, "proto": proto, "port": port,
             "sev": sev, "reasons": reasons, "cc": cc, "country": country, "alerted": False}
        r = [x for x in self._rate.get(d["key"], []) if t - x < 3600]
        if len(r) < MAX_ALERTS_HOUR:
            r.append(t)
            v["alerted"] = True
        self._rate[d["key"]] = r
        d["violations"] = (d["violations"] + [v])[-MAX_VIOL:]
        if not v["alerted"]:
            return None
        who = (d.get("meta") or {}).get("name") or d["ip"]
        tgt = p["name"] + (f" ({ip})" if p["name"] != ip else "")
        detail = (f"Η συσκευή {who} ({d['ip']}) είναι σε λειτουργία «παρακολούθηση» και μίλησε με προορισμό που "
                  f"ΔΕΝ υπάρχει στο προφίλ της: {tgt}, {proto}" + (f"/{port}" if port is not None else "") + ". "
                  + (("Γιατί προσέχουμε: " + "· ".join(reasons) + ". ") if reasons else "")
                  + "Αν είναι αναμενόμενο (π.χ. αναβάθμιση firmware ή νέα υπηρεσία cloud), πάτα «Αποδοχή» στο 🧱 IoT "
                  "firewall· αλλιώς έλεγξε τη συσκευή και μπλόκαρέ τη με τους κανόνες που παράγει το NetWatch.")
        return {"sev": sev, "dest": k, "detail": detail}

    @staticmethod
    def _mk_dest(k, name, ip, proto, port, t):
        grp = k.split("|", 1)[0]
        disp = (("*." + grp) if name and name != grp else grp) if name and not _addr(name) else ip
        return {"key": k, "name": disp, "domain": grp if name and not _addr(name) else None, "names": [],
                "ips": [], "proto": proto, "port": port, "first": t, "last": t, "pkts": 0, "cc": None, "country": None,
                "intel": False}

    @staticmethod
    def _touch(e, name, ip, t, cc, country, intel):
        e["last"] = max(e["last"], t)
        e["first"] = min(e["first"], t)
        e["pkts"] += 1
        if ip not in e["ips"]:
            e["ips"] = (e["ips"] + [ip])[-MAX_IPS:]
        if name and not _addr(name) and name not in e["names"] and len(e["names"]) < MAX_NAMES:
            e["names"].append(name)
        if cc:
            e["cc"], e["country"] = cc, country
        if intel:
            e["intel"] = True

    # ── ενέργειες χρήστη ──
    def _find(self, dev):
        dev = str(dev or "").strip().lower()
        if dev in self.devs:
            return self.devs[dev]
        k = self.ip_key.get(dev)
        return self.devs.get(k) if k else None

    def set_mode(self, dev, mode, now=None):
        if mode not in MODES:
            raise ValueError("Άγνωστη λειτουργία (learn | watch | off)")
        now = now or time.time()
        with self.lock:
            d = self._find(dev)
            if d is None:
                raise KeyError("Δεν βρέθηκε η συσκευή")
            if mode == "learn" and d["mode"] != "learn":
                d["learn_start"], d["learn_until"], d["learned_auto"] = now, now + self.learn_s, False
            if mode == "watch":
                d["learned_auto"] = True
                d["learn_until"] = min(d["learn_until"], now)
            d["mode"] = mode
            self.dirty = True
        self._save()
        return {"ok": True, "dev": d["key"], "mode": mode}

    def accept(self, dev, dest):
        """Βάζει έναν προορισμό «προς έγκριση» στο προφίλ (dest="*" → όλους) και σβήνει τις παραβάσεις του."""
        with self.lock:
            d = self._find(dev)
            if d is None:
                raise KeyError("Δεν βρέθηκε η συσκευή")
            keys = list(d["pending"]) if dest == "*" else [str(dest or "")]
            done = []
            for k in keys:
                p = d["pending"].pop(k, None)
                if p is None:
                    continue
                if k in d["dests"]:
                    e = d["dests"][k]
                    e["ips"] = (e["ips"] + [i for i in p["ips"] if i not in e["ips"]])[-MAX_IPS:]
                    e["pkts"] += p["pkts"]
                elif len(d["dests"]) < self.max_dest:
                    d["dests"][k] = p
                else:
                    d["full"] = True
                done.append(k)
            if dest != "*" and not done and str(dest) not in d["dests"]:
                raise KeyError("Δεν βρέθηκε αυτός ο προορισμός")
            d["violations"] = [v for v in d["violations"] if v["dest"] not in done and v["dest"] != dest]
            for k in done:
                self._cd.pop((d["key"], k), None)
            self.dirty = True
        self._save()
        return {"ok": True, "dev": d["key"], "accepted": done}

    def reset(self, dev, now=None):
        now = now or time.time()
        with self.lock:
            d = self._find(dev)
            if d is None:
                raise KeyError("Δεν βρέθηκε η συσκευή")
            n = self._new_dev(d["key"], d["ip"], d["mac"], now)
            n["ips"], n["meta"] = d["ips"], d.get("meta") or {}
            self.devs[d["key"]] = n
            self._cd = {k: v for k, v in self._cd.items() if k[0] != d["key"]}
            self.dirty = True
        self._save()
        return {"ok": True, "dev": d["key"], "mode": "learn"}

    # ── κατάσταση ──
    def _meta_for(self, ip, mac):
        """Όνομα/κατασκευαστής/τύπος: από το demo ή από τα hosts του state (μέσα στο state.lock)."""
        if ip in self.sim_meta:
            return dict(self.sim_meta[ip])
        st = self.state
        if st is None or not hasattr(st, "hosts"):
            return {}
        try:
            with st.lock:
                h = st.hosts.get(ip)
                if not h:
                    return {}
                names = sorted(h.get("names") or ()) + ([h["rdns"]] if h.get("rdns") else [])
                dt = st._dtype(h) if hasattr(st, "_dtype") else {}
            return {"name": names[0] if names else None, "vendor": dt.get("vendor"), "kind": dt.get("dtype"),
                    "kind_label": dt.get("dlabel"), "icon": dt.get("dicon")}
        except Exception:
            return {}

    def status(self, now=None):
        now = now or time.time()
        with self.lock:
            ids = [(k, d["ip"], d["mac"]) for k, d in self.devs.items()]
        metas = {k: self._meta_for(ip, mac) for k, ip, mac in ids}  # state.lock ΧΩΡΙΣ το δικό μας lock
        with self.lock:
            out = []
            for k, d in self.devs.items():
                m = metas.get(k) or {}
                if m:
                    d["meta"] = {**(d.get("meta") or {}), **{x: y for x, y in m.items() if y}}
                self._learn_tick(d, now)
                out.append(self._ser(d, now))
        out.sort(key=lambda x: (x["mode"] == "off", -len(x["pending"]), -(x["last"] or 0)))
        recent = sorted(({"dev": x["key"], "dev_name": x["name"], "dev_ip": x["ip"], **v}
                         for x in out for v in x["violations"]), key=lambda v: -v["t"])[:30]
        tot = {"devices": len(out), "learning": sum(1 for x in out if x["mode"] == "learn"),
               "watching": sum(1 for x in out if x["mode"] == "watch"),
               "pending": sum(len(x["pending"]) for x in out),
               "violations_24h": sum(1 for v in recent if now - v["t"] < 86400)}
        return {"enabled": self.enabled, "demo": self.sim, "error": self.error,
                "learn_hours": round(self.learn_s / 3600, 3), "alert_severity": self.base_sev,
                "max_destinations": self.max_dest, "auto_watch": self.auto_watch,
                "modes": list(MODES), "formats": FORMATS, "totals": tot, "devices": out,
                "recent_violations": recent,
                "note": ("Το NetWatch ΔΕΝ αλλάζει τον router: μαθαίνει με ποιους μιλά κάθε συσκευή και σου δίνει κανόνες "
                         "για να τους επικολλήσεις. Τα routers φιλτράρουν με IP, όχι με όνομα — οι IP των cloud "
                         "υπηρεσιών αλλάζουν, γι' αυτό ξαναβγάλε τους κανόνες κάθε τόσο.")}

    def _ser(self, d, now):
        m = d.get("meta") or {}
        kind = m.get("kind") or "unknown"
        dests = sorted(d["dests"].values(), key=lambda e: -e["pkts"])
        span = max(1.0, d["learn_until"] - d["learn_start"])
        active = d["mode"] == "learn" and now < d["learn_until"]
        left = max(0.0, d["learn_until"] - now) if d["mode"] == "learn" else 0.0
        pct = 100 if d["mode"] != "learn" else int(min(100, max(0, (now - d["learn_start"]) / span * 100)))
        countries = sorted({e["cc"] for e in dests if e.get("cc")})
        ext = d["dns"]["external"]
        dns_ext = [{"ip": ip, "n": n, "provider": _resolver(ip)} for ip, n in sorted(ext.items(), key=lambda x: -x[1])]
        doh = [e for e in dests if e["port"] in (443, 853) and (_doh(e) or (e["port"] == 853))]
        trackers = sorted({tr["who"] for e in dests for tr in [_tracker(e)] if tr})
        hints = []
        if len(countries) >= 5:
            hints.append({"level": "warn", "code": "countries",
                          "text": f"Μιλά με {len(countries)} διαφορετικές χώρες ({', '.join(countries[:8])})"})
        if dns_ext:
            hints.append({"level": "warn", "code": "external_dns",
                          "text": "Χρησιμοποιεί εξωτερικό DNS (" + ", ".join(x["ip"] for x in dns_ext[:3])
                                  + ") — παρακάμπτει το DNS του router / Pi-hole"})
        if doh:
            hints.append({"level": "warn", "code": "doh",
                          "text": "Χρησιμοποιεί κρυπτογραφημένο DNS (DoH/DoT) — δεν βλέπεις τι ψάχνει"})
        if trackers:
            hints.append({"level": "info", "code": "trackers",
                          "text": f"Μιλά με {len(trackers)} trackers/διαφημιστές (" + ", ".join(trackers[:5]) + ")"})
        if any(e.get("intel") for e in dests):
            hints.append({"level": "bad", "code": "intel", "text": "Κάποιος προορισμός είναι σε λίστα απειλών"})
        odd = sorted({e["port"] for e in dests if e["port"] is not None and e["port"] not in COMMON_PORTS})
        if odd:
            hints.append({"level": "info", "code": "ports",
                          "text": "Ασυνήθιστες θύρες: " + ", ".join(str(p) for p in odd[:8])})
        if not dests and d["lan"]:
            hints.append({"level": "ok", "code": "lan_only", "text": "Μιλά μόνο μέσα στο LAN — μπορεί να κοπεί τελείως από το Internet"})
        if d["full"]:
            hints.append({"level": "info", "code": "full",
                          "text": f"Έφτασε το όριο των {self.max_dest} προορισμών — δεν προστίθενται άλλοι"})
        all_ips = {i for e in dests for i in e["ips"]}
        return {
            "key": d["key"], "ip": d["ip"], "ips": list(d["ips"]), "mac": d["mac"],
            "name": m.get("name") or d["ip"], "vendor": m.get("vendor"), "kind": kind,
            "kind_label": m.get("kind_label"), "icon": m.get("icon"), "iot": kind in IOT_KINDS,
            "mode": d["mode"],
            "learning": {"active": active, "pct": pct, "left_s": int(left), "started": round(d["learn_start"], 1),
                         "until": round(d["learn_until"], 1)},
            "first": round(d["first"], 1), "last": round(d["last"], 1),
            "counts": {"dests": len(dests), "domains": len({e["domain"] for e in dests if e["domain"]}),
                       "ips": len(all_ips), "countries": len(countries), "lan_peers": len({x["ip"] for x in d["lan"].values()}),
                       "pending": len(d["pending"]), "violations": len(d["violations"]), "pkts": d["pkts"]},
            "dests": [_pub(e) for e in dests[:TOP_DESTS]],
            "pending": [_pub(e) for e in sorted(d["pending"].values(), key=lambda e: -e["last"])],
            "lan": [dict(e) for e in sorted(d["lan"].values(), key=lambda e: -e["pkts"])],
            "dns": {"gateway": d["dns"]["gateway"], "lan": d["dns"]["lan"], "external": dns_ext},
            "countries": countries,
            "violations": list(reversed(d["violations"][-10:])),
            "hints": hints,
        }

    # ── κανόνες firewall ──
    def rules(self, dev, fmt, lan=False):
        if fmt not in FMT_IDS:
            raise ValueError("Άγνωστη μορφή (" + " | ".join(FMT_IDS) + ")")
        with self.lock:
            d = self._find(dev)
            if d is None:
                raise KeyError("Δεν βρέθηκε η συσκευή")
            d = json.loads(json.dumps(d))
        gw = self._gw()
        if ip_class(d["ip"]) != "local" or ":" in d["ip"]:
            raise ValueError("Οι κανόνες χρειάζονται τοπική IPv4 για τη συσκευή")
        text = RENDER[fmt](_plan(d, gw), lan)
        return {"dev": d["key"], "fmt": fmt, "lan": bool(lan), "filename": _filename(d, fmt), "text": text}

    # ── αποθήκευση ──
    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                db = json.load(f)
        except (OSError, ValueError):
            return
        for k, d in list((db.get("devices") or {}).items())[:MAX_DEVICES]:
            if not isinstance(d, dict) or d.get("mode") not in MODES:
                continue
            base = self._new_dev(k, d.get("ip"), d.get("mac"), d.get("first") or time.time())
            base.update({x: d[x] for x in base if x in d})
            base["dests"] = dict(list((base["dests"] or {}).items())[:self.max_dest])
            base["pending"] = dict(list((base["pending"] or {}).items())[:MAX_PENDING])
            base["lan"] = dict(list((base["lan"] or {}).items())[:MAX_LAN])
            base["violations"] = list(base["violations"] or [])[-MAX_VIOL:]
            self.devs[k] = base
            for ip in base["ips"] or [base["ip"]]:
                self.ip_key[ip] = k

    def _save(self):
        if not self.path:
            return
        with self.lock:
            data = json.dumps({"v": 1, "saved": time.time(), "devices": self.devs}, ensure_ascii=False,
                              separators=(",", ":"))
            self.dirty = False
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(data)
            os.replace(tmp, self.path)
        except OSError as e:
            self.error = f"Δεν αποθηκεύτηκε το {self.path}: {e.strerror or e}"

    def run_forever(self):
        n = 0
        while True:
            time.sleep(15 if self.sim else 30)
            try:
                if self.sim:
                    self._sim_tick()
                n += 1
                if n % 4 == 0:
                    self.status()  # ανανεώνει τύπο/όνομα συσκευών και τέλος μάθησης → watch
                if self.dirty and n % 2 == 0:
                    self._save()
            except Exception as e:
                self.error = str(e)[:200]

    # ── demo ──
    SIM_DEVS = {  # IP → (MAC, όνομα, κατασκευαστής, τύπος, ετικέτα, εικονίδιο, λειτουργία)
        "192.168.1.33": ("9c:a2:f4:33:33:33", "Κάμερα εισόδου (Tapo)", "TP-Link", "camera", "Κάμερα", "📷", "watch"),
        "192.168.1.52": ("d8:1f:12:52:52:52", "Πρίζα κουζίνας", "Tuya Smart", "iot", "Έξυπνη συσκευή", "💡", "watch"),
        "192.168.1.31": ("a8:23:fe:31:31:31", "Smart TV σαλονιού", "LG Electronics", "tv", "TV / media", "📺", "learn"),
        "192.168.1.20": ("24:6f:28:20:20:20", "ESP32 κήπου", "Espressif", "esp", "ESP32 / ESP8266", "🔌", "watch"),
    }
    SIM_REMOTE = {  # IP → (cc, χώρα, όνομα, intel)
        "52.57.110.21": ("DE", "Germany", "euw1-relay.tplinkcloud.com", False),
        "3.124.90.17": ("DE", "Germany", "n-deventry-de.tplinkcloud.com", False),
        "162.159.200.123": ("NL", "Netherlands", "pool.ntp.org", False),
        "18.185.4.88": ("DE", "Germany", "a2.tuyaeu.com", False),
        "3.67.3.201": ("DE", "Germany", "m2.tuyaeu.com", False),
        "8.8.8.8": ("US", "United States", "dns.google", False),
        "45.57.90.1": ("GR", "Greece", "ipv4-c001-ath001.nflxvideo.net", False),
        "142.250.184.110": ("US", "United States", "www.youtube.com", False),
        "142.250.185.68": ("US", "United States", "doubleclick.net", False),
        "142.251.1.157": ("US", "United States", "app-measurement.com", False),
        "52.84.150.12": ("IE", "Ireland", "lgtvsdp.com", False),
        "35.156.21.4": ("DE", "Germany", "ad.lgappstv.com", False),
        "104.18.32.7": ("GB", "United Kingdom", "sb.scorecardresearch.com", False),
        "23.32.29.18": ("JP", "Japan", "a248.e.akamai.net", False),
        "13.107.42.14": ("NL", "Netherlands", "settings-win.data.microsoft.com", False),
        "54.239.28.85": ("US", "United States", "aax-eu.amazon-adsystem.com", False),
        "47.91.88.12": ("CN", "China", None, False),
        "185.220.101.42": ("RU", "Russia", None, True),
        "151.101.1.140": ("SE", "Sweden", "api.samsungcloud.example", False),
    }
    SIM_PROFILE = [  # (IP συσκευής, IP προορισμού, proto, θύρα, πόσες φορές)
        ("192.168.1.33", "52.57.110.21", "TCP", 443, 140), ("192.168.1.33", "3.124.90.17", "TCP", 443, 60),
        ("192.168.1.33", "162.159.200.123", "UDP", 123, 24), ("192.168.1.33", "192.168.1.1", "UDP", 53, 30),
        ("192.168.1.52", "18.185.4.88", "TCP", 8883, 200), ("192.168.1.52", "3.67.3.201", "TCP", 443, 40),
        ("192.168.1.52", "8.8.8.8", "UDP", 53, 90),
        ("192.168.1.20", "192.168.1.17", "TCP", 1883, 300), ("192.168.1.20", "162.159.200.123", "UDP", 123, 12),
        ("192.168.1.20", "192.168.1.1", "UDP", 53, 10),
        ("192.168.1.31", "45.57.90.1", "TCP", 443, 220), ("192.168.1.31", "142.250.184.110", "UDP", 443, 160),
        ("192.168.1.31", "142.250.185.68", "TCP", 443, 40), ("192.168.1.31", "142.251.1.157", "TCP", 443, 30),
        ("192.168.1.31", "52.84.150.12", "TCP", 443, 25), ("192.168.1.31", "35.156.21.4", "TCP", 443, 25),
        ("192.168.1.31", "104.18.32.7", "TCP", 443, 15), ("192.168.1.31", "23.32.29.18", "TCP", 443, 20),
        ("192.168.1.31", "13.107.42.14", "TCP", 443, 6), ("192.168.1.31", "8.8.8.8", "TCP", 443, 30),
        ("192.168.1.31", "192.168.1.40", "TCP", 9100, 3),
    ]
    SIM_NEW = [  # «νέοι» προορισμοί που εμφανίζονται κάπου-κάπου (παραβάσεις)
        ("192.168.1.33", "47.91.88.12", "TCP", 9000), ("192.168.1.52", "185.220.101.42", "TCP", 6667),
        ("192.168.1.31", "54.239.28.85", "TCP", 443), ("192.168.1.31", "151.101.1.140", "TCP", 443),
    ]

    def _sim_packet(self, src, dst, proto, dp):
        nm = (self.SIM_REMOTE.get(dst) or (None, None, None))[2]
        return {"src": src, "dst": dst, "proto": proto, "sp": 40000 + self.rnd.randrange(20000), "dp": dp,
                "flags": "S" if proto == "TCP" else "", "sni": nm if dp == 443 else None,
                "smac": self.SIM_DEVS[src][0]}

    def _seed_sim(self):
        now = time.time()
        self.sim_geo = dict(self.SIM_REMOTE)
        for ip, (mac, name, vendor, kind, label, icon, _) in self.SIM_DEVS.items():
            self.sim_meta[ip] = {"name": name, "vendor": vendor, "kind": kind, "kind_label": label, "icon": icon}
        gw = self._gw() or "192.168.1.1"
        for src, dst, proto, dp, n in self.SIM_PROFILE:
            mode = self.SIM_DEVS[src][6]
            start = now - (60 if mode == "learn" else 3 * 86400)
            with self.lock:
                d = self._device(src, self.SIM_DEVS[src][0], start, gw, set())
                d["meta"] = dict(self.sim_meta[src])
                d["mode"] = "learn"
                if mode == "learn":
                    d["learn_start"], d["learn_until"] = start, start + self.learn_s
                else:
                    d["learned_auto"] = True
            for i in range(n):
                t = start + (now - start) * i / n * (0.9 if mode != "learn" else 1)
                self.observe(self._sim_packet(src, dst, proto, dp), t)
        for ip, v in self.SIM_DEVS.items():
            if v[6] == "watch":
                with self.lock:
                    self.devs[v[0]]["mode"] = "watch"
        # μια παράβαση ήδη από την αρχή: η κάμερα «μιλά» με άγνωστη IP στην Κίνα, θύρα 9000
        src, dst, proto, dp = self.SIM_NEW[0]
        for i in range(3):
            self.observe(self._sim_packet(src, dst, proto, dp), now - 1800 + i * 40)

    def _sim_tick(self):
        if self.rnd.random() < 0.12:
            src, dst, proto, dp = self.rnd.choice(self.SIM_NEW)
        else:
            src, dst, proto, dp, _ = self.rnd.choice(self.SIM_PROFILE)
        self.observe(self._sim_packet(src, dst, proto, dp), time.time())


def _pub(e):
    return {k: e.get(k) for k in ("key", "name", "domain", "names", "ips", "proto", "port", "first", "last", "pkts",
                                  "cc", "country", "intel")}


def _resolver(ip):
    try:
        import encdns
        return encdns.resolver_provider(ip)
    except Exception:
        return None


def _doh(e):
    try:
        import encdns
        return any(encdns.doh_provider(n) for n in e.get("names") or ()) or \
            (not e.get("names") and any(encdns.resolver_provider(i) for i in e["ips"]))
    except Exception:
        return False


def _tracker(e):
    try:
        import apps
        for n in (e.get("names") or []) + ([e["domain"]] if e.get("domain") else []):
            tr = apps.tracker_for(n)
            if tr:
                return tr
    except Exception:
        pass
    return None


# ── παραγωγή κανόνων ──
def _plan(d, gw):
    """Κοινό «σχέδιο» για όλες τις μορφές: ομάδες (proto, θύρα) → [(IP, σχόλιο)], γείτονες LAN, DNS."""
    groups, fq = {}, {}
    v6 = []
    for e in sorted(d["dests"].values(), key=lambda e: (e["proto"], e["port"] or 0, e["name"])):
        cmt = e["name"] + (f" [{e['cc']}]" if e.get("cc") else "")
        fq.setdefault((e["proto"], e["port"]), set()).update(n for n in e.get("names") or () if _FQDN.match(n))
        for ip in e["ips"]:
            a = _addr(ip)
            if a is None or ip_class(ip) != "public":
                continue
            if a.version == 6:
                v6.append((ip, e["proto"], e["port"], cmt))
                continue
            g = groups.setdefault((e["proto"], e["port"]), [])
            if ip not in [x[0] for x in g]:
                g.append((ip, cmt))
    fqdns = sorted({n for e in d["dests"].values() for n in e.get("names") or () if _FQDN.match(n)})
    lan = []
    for e in sorted(d["lan"].values(), key=lambda e: (e["ip"], e["proto"], e["port"] or 0)):
        if ":" not in e["ip"]:
            lan.append((e["ip"], e["proto"], e["port"]))
    dns = [gw] if gw and ":" not in str(gw) else []
    m = d.get("meta") or {}
    return {"ip": d["ip"], "mac": d.get("mac"), "name": m.get("name") or d["ip"], "slug": _slug(m.get("name") or d["ip"]),
            "groups": groups, "fqdn_by": {k: sorted(v) for k, v in fq.items() if k in groups}, "v6": v6, "lan": lan, "dns": dns, "fqdns": fqdns,
            "domains": sorted({e["name"] for e in d["dests"].values()}), "n_dest": len(d["dests"])}


def _header(p, cm="#"):
    lines = [f"NetWatch — μικρο-τμηματοποίηση για «{p['name']}» ({p['ip']}" + (f", MAC {p['mac']}" if p["mac"] else "") + ")",
             f"Δημιουργήθηκε: {time.strftime('%Y-%m-%d %H:%M')} — {p['n_dest']} μαθημένοι προορισμοί.",
             "Επιτρέπει ΜΟΝΟ: τους μαθημένους προορισμούς, DNS στο gateway (και τους μαθημένους γείτονες στο LAN)·",
             "ό,τι άλλο από τη συσκευή προς το Internet κόβεται.",
             "ΠΡΟΣΟΧΗ: οι routers ταιριάζουν IP, όχι ονόματα (SNI). Οι IP των cloud υπηρεσιών ΑΛΛΑΖΟΥΝ —",
             "ξαναβγάλε τους κανόνες κάθε τόσο και κοίτα πρώτα τα «drop» στο log πριν βασιστείς σε αυτούς.",
             "Προϋπόθεση: σταθερή IP για τη συσκευή (DHCP reservation)."]
    if not p["groups"] and not p["v6"]:
        lines.append("Η συσκευή δεν έχει μαθημένους προορισμούς στο Internet → θα κοπεί εντελώς από το Internet.")
    if p["domains"]:
        lines.append("Domains: " + ", ".join(p["domains"][:30]) + (" …" if len(p["domains"]) > 30 else ""))
    return "\n".join(f"{cm} {x}" for x in lines) + "\n"


def _pp(proto, port):
    return f"{proto.lower()}/{port}" if port is not None else proto.lower()


def _r_openwrt(p, lan):
    s, ip = p["slug"], p["ip"]
    out = [_header(p), f"# Αποθήκευσε ως /etc/nftables.d/50-netwatch-{s}.nft και τρέξε: fw4 reload",
           "# (τα αρχεία του /etc/nftables.d/ μπαίνουν μέσα στον πίνακα «table inet fw4»)", ""]
    tcpudp = {k: v for k, v in p["groups"].items() if k[0] in ("TCP", "UDP") and k[1] is not None}
    icmp = [x for k, v in p["groups"].items() if k[0] == "ICMP" for x in v]
    out.append(f"set nw_{s}_allow4 {{\n\ttype ipv4_addr . inet_proto . inet_service")
    els = [f"\t\t{a} . {k[0].lower()} . {k[1]},  # {c}" for k, v in tcpudp.items() for a, c in v]
    out.append("\telements = {\n" + "\n".join(els) + "\n\t}\n}" if els else "}")
    if icmp:
        out.append(f"set nw_{s}_icmp4 {{\n\ttype ipv4_addr\n\telements = {{\n"
                   + "\n".join(f"\t\t{a},  # {c}" for a, c in icmp) + "\n\t}\n}")
    if p["v6"]:
        out.append(f"set nw_{s}_allow6 {{\n\ttype ipv6_addr . inet_proto . inet_service\n\telements = {{\n"
                   + "\n".join(f"\t\t{a} . {pr.lower()} . {po},  # {c}" for a, pr, po, c in p["v6"] if po is not None)
                   + "\n\t}\n}")
    out.append("")
    out.append(f"chain nw_{s} {{\n\ttype filter hook forward priority filter - 1; policy accept;")
    out.append(f"\tip saddr {ip} ct state established,related accept")
    for dns in p["dns"]:
        out.append(f"\tip saddr {ip} ip daddr {dns} meta l4proto {{ tcp, udp }} th dport 53 accept  # DNS στο gateway")
    if els:
        out.append(f"\tip saddr {ip} ip daddr . meta l4proto . th dport @nw_{s}_allow4 accept  # μαθημένοι προορισμοί")
    if icmp:
        out.append(f"\tip saddr {ip} ip daddr @nw_{s}_icmp4 icmp type echo-request accept")
    lanset = "{ " + ", ".join(RFC1918) + " }"
    peers = [f"ip saddr {ip} ip daddr {a} {pr.lower()} dport {po} accept  # γείτονας LAN"
             if pr in ("TCP", "UDP") and po is not None else f"ip saddr {ip} ip daddr {a} accept  # γείτονας LAN"
             for a, pr, po in p["lan"]]
    pre = "" if lan else "# "
    out.append("\t# — πλευρική κίνηση στο LAN (μόνο οι μαθημένοι γείτονες). Σημ.: κίνηση μέσα στην ίδια γέφυρα/switch "
               "δεν περνά από τον router· για πραγματική απομόνωση βάλε τη συσκευή σε δικό της VLAN / IoT δίκτυο.")
    out += ["\t" + pre + x for x in peers]
    out.append(f"\t{pre}ip saddr {ip} ip daddr {lanset} counter drop comment \"netwatch {s}: lan\"")
    out.append(f"\tip saddr {ip} ip daddr != {lanset} counter drop comment \"netwatch {s}: default drop\"")
    if p["v6"]:
        out.append(f"\tether saddr {p['mac']} ip6 daddr . meta l4proto . th dport @nw_{s}_allow6 accept"
                   if p["mac"] else f"\t# IPv6: πρόσθεσε κανόνα με «ether saddr <MAC>» για το @nw_{s}_allow6")
    out.append("}")
    return "\n".join(out) + "\n"


def _r_pfsense(p, lan):
    s, ip = p["slug"].upper(), p["ip"]
    out = [_header(p, "#"), "# pfSense / OPNsense — βήματα στο web UI (κανένας κωδικός ή μυστικό δεν χρειάζεται εδώ).", "",
           "## 1) Firewall ▸ Aliases ▸ Add  (Type: Host(s) — ένα alias ανά πρωτόκολλο/θύρα)"]
    rules = []
    for (pr, po), v in p["groups"].items():
        name = f"NW_{s}_{pr}{po or ''}"[:31]
        out.append(f"Alias: {name}   Type: Host(s)   Description: NetWatch {_ascii(p['name'])} {pr}/{po or '-'}")
        for a, c in v:
            out.append(f"    {a:<18}  {c}")
        rules.append((pr, po, name))
    out += ["", f"Alias: NW_RFC1918   Type: Network(s)   Περιεχόμενα: {', '.join(RFC1918)}", "",
            "## 2) Firewall ▸ Rules ▸ LAN — με ΑΥΤΗ τη σειρά, ΠΑΝΩ από τον κανόνα «Default allow LAN to any»"]
    i = 1
    for dns in p["dns"]:
        out.append(f"{i}. Pass   IPv4 TCP/UDP   Source: {ip}   Destination: {dns} port 53 (DNS)   "
                   f"Description: NW {s} dns")
        i += 1
    for pr, po, name in rules:
        proto = pr if pr in ("TCP", "UDP") else "ICMP (echo request)"
        out.append(f"{i}. Pass   IPv4 {proto}   Source: {ip}   Destination: alias {name}"
                   + (f" port {po}" if po is not None else "") + f"   Description: NW {s} learned")
        i += 1
    for a, pr, po in p["lan"]:
        out.append(f"{i}. Pass   IPv4 {pr}   Source: {ip}   Destination: {a}" + (f" port {po}" if po is not None else "")
                   + f"   Description: NW {s} lan peer" + ("" if lan else "   (χρειάζεται μόνο αν μπλοκάρεις το LAN)"))
        i += 1
    if lan:
        out.append(f"{i}. Block  IPv4 any   Source: {ip}   Destination: alias NW_RFC1918   Log: ✓   Description: NW {s} lan")
        i += 1
    out.append(f"{i}. Block  IPv4 any   Source: {ip}   Destination: alias NW_RFC1918 με «Invert match» (= Internet)   "
               f"Log: ✓   Description: NW {s} default drop")
    if p["v6"]:
        out += ["", "IPv6 προορισμοί (φτιάξε αντίστοιχο alias/κανόνα IPv6 αν η συσκευή έχει IPv6):"]
        out += [f"    {a}  {pr.lower()}/{po}  {c}" for a, pr, po, c in p["v6"]]
    out += ["", "Σημ.: Το pfSense δέχεται και FQDN σε alias Host(s) (ξαναλύνεται περιοδικά) — μπορείς να προσθέσεις:",
            "    " + (", ".join(p["fqdns"][:20]) or "(κανένα όνομα)")]
    return "\n".join(out) + "\n"


def _r_mikrotik(p, lan):
    s, ip = p["slug"].replace("_", "-"), p["ip"]
    out = [_header(p), "# Επικόλλησε στο Terminal του RouterOS (v6/v7). Μετά μετακίνησε τους κανόνες «netwatch» ΠΑΝΩ",
           "# από τυχόν «accept» για το LAN (π.χ. με place-before στο Winbox ή /ip firewall filter move).", "",
           "/ip firewall address-list"]
    for (pr, po), v in p["groups"].items():
        for a, c in v:
            out.append(f'add list=nw-{s}-{pr.lower()}{po or ""} address={a} comment="{_ascii(c)}"')
    if p["fqdns"]:
        out.append("# Ονόματα (το RouterOS τα ξαναλύνει δυναμικά — βοηθά όταν αλλάζουν οι IP του cloud):")
        for (pr, po), names in p["fqdn_by"].items():
            for n in names[:20]:
                out.append(f'add list=nw-{s}-{pr.lower()}{po or ""} address={n} comment="netwatch fqdn"')
    for net in RFC1918:
        out.append(f'add list=nw-rfc1918 address={net} comment="netwatch"')
    out += ["", "/ip firewall filter",
            f'add chain=forward action=accept src-address={ip} connection-state=established,related comment="netwatch {s}"']
    for dns in p["dns"]:
        for pr in ("udp", "tcp"):
            out.append(f'add chain=forward action=accept src-address={ip} dst-address={dns} protocol={pr} dst-port=53 '
                       f'comment="netwatch {s}: dns"')
    for (pr, po), v in p["groups"].items():
        lst = f"nw-{s}-{pr.lower()}{po or ''}"
        extra = f" protocol={pr.lower()} dst-port={po}" if pr in ("TCP", "UDP") and po is not None else \
            (" protocol=icmp" if pr == "ICMP" else "")
        out.append(f'add chain=forward action=accept src-address={ip} dst-address-list={lst}{extra} '
                   f'comment="netwatch {s}: learned"')
    pre = "" if lan else "# "
    for a, pr, po in p["lan"]:
        extra = f" protocol={pr.lower()} dst-port={po}" if pr in ("TCP", "UDP") and po is not None else ""
        out.append(f'{pre}add chain=forward action=accept src-address={ip} dst-address={a}{extra} comment="netwatch {s}: lan peer"')
    out.append(f'{pre}add chain=forward action=drop src-address={ip} dst-address-list=nw-rfc1918 log=yes '
               f'log-prefix="nw-{s}-lan" comment="netwatch {s}: lan"')
    out.append(f'add chain=forward action=drop src-address={ip} dst-address-list=!nw-rfc1918 log=yes '
               f'log-prefix="nw-{s}" comment="netwatch {s}: default drop"')
    if p["v6"]:
        out += ["", "/ipv6 firewall address-list"]
        out += [f'add list=nw-{s}-v6 address={a} comment="{_ascii(c)}"' for a, _, _, c in p["v6"]]
        out.append("# (πρόσθεσε αντίστοιχους κανόνες στο /ipv6 firewall filter με src-mac-address=" + (p["mac"] or "<MAC>") + ")")
    return "\n".join(out) + "\n"


def _r_iptables(p, lan):
    c, ip = ("NW_" + p["slug"].upper())[:28], p["ip"]
    out = ["#!/bin/sh", _header(p), "# Γενικό Linux router (iptables). Τρέξε ως root. Αναίρεση: iptables -D FORWARD -s "
           f"{ip} -j {c}; iptables -F {c}; iptables -X {c}", "set -e",
           f"iptables -N {c} 2>/dev/null || iptables -F {c}",
           f"iptables -C FORWARD -s {ip} -j {c} 2>/dev/null || iptables -I FORWARD 1 -s {ip} -j {c}",
           f"iptables -A {c} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"]
    for dns in p["dns"]:
        out += [f"iptables -A {c} -d {dns} -p udp --dport 53 -j RETURN  # DNS στο gateway",
                f"iptables -A {c} -d {dns} -p tcp --dport 53 -j RETURN"]
    for (pr, po), v in p["groups"].items():
        for a, cm in v:
            if pr in ("TCP", "UDP") and po is not None:
                out.append(f"iptables -A {c} -d {a} -p {pr.lower()} --dport {po} -j RETURN  # {cm}")
            elif pr == "ICMP":
                out.append(f"iptables -A {c} -d {a} -p icmp --icmp-type echo-request -j RETURN  # {cm}")
    pre = "" if lan else "# "
    for a, pr, po in p["lan"]:
        extra = f" -p {pr.lower()} --dport {po}" if pr in ("TCP", "UDP") and po is not None else ""
        out.append(f"{pre}iptables -A {c} -d {a}{extra} -j RETURN  # γείτονας LAN")
    for net in RFC1918:
        out.append((f"iptables -A {c} -d {net} -j DROP  # πλευρική κίνηση" if lan else
                    f"iptables -A {c} -d {net} -j RETURN  # το LAN μένει ανοιχτό (βάλε lan=1 για μπλοκάρισμα)"))
    out += [f"iptables -A {c} -m limit --limit 6/min -j LOG --log-prefix \"{c[:20]} drop: \"",
            f"iptables -A {c} -j DROP  # default drop: ό,τι άλλο προς το Internet"]
    if p["v6"]:
        out.append("# IPv6 προορισμοί (χρειάζεται αντίστοιχη αλυσίδα στο ip6tables με -m mac --mac-source "
                   + (p["mac"] or "<MAC>") + "):")
        out += [f"#   ip6tables ... -d {a} -p {pr.lower()} --dport {po} -j RETURN  # {cm}" for a, pr, po, cm in p["v6"]]
    return "\n".join(out) + "\n"


RENDER = {"openwrt": _r_openwrt, "pfsense": _r_pfsense, "mikrotik": _r_mikrotik, "iptables": _r_iptables}


def _filename(d, fmt):
    s = _slug((d.get("meta") or {}).get("name") or d["ip"])
    return {"openwrt": f"50-netwatch-{s}.nft", "pfsense": f"netwatch-{s}-pfsense.txt",
            "mikrotik": f"netwatch-{s}.rsc", "iptables": f"netwatch-{s}.sh"}[fmt]
