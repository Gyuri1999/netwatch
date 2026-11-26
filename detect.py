"""NetWatch — NetState: η κατάσταση του δικτύου και όλοι οι ανιχνευτές επιθέσεων."""
import collections
import copy
import ipaddress
import os
import queue
import random
import re
import socket
import threading
import time

import packets
import techkit
from concurrent.futures import ThreadPoolExecutor

from core import BRUTE_PORTS, DEFAULT_CONFIG, DNS_RESOLVERS, EXTRA_MITRE, MITRE, PLAIN_PORTS, RISKY_SERVICES, RULES_DIR, SERVICES, SEV, SUSPECT_PORTS, TOR_PORTS, DistinctWindow, Window, app_label, chown_to_user, detect_net, detector_for, dga_score, entropy, ip_kind, local_tor_running, log, mask_user, mitre_for, norm_mac, random_mac, service_port, split_domain
from storage import History, Intel


def host_info():
    """Πού τρέχει το backend — για τις οδηγίες «Πώς περνάω σε Live» όταν η εφαρμογή ανοίγει σε Demo."""
    import sys
    out = {"os": sys.platform, "docker": os.path.exists("/.dockerenv")}
    if sys.platform == "win32":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        out["npcap"] = any(os.path.exists(os.path.join(root, d, *f)) for d in ("System32", "Sysnative")
                           for f in (("Npcap", "wpcap.dll"), ("wpcap.dll",)))
    return out


SWEEPS = ("Network sweep (ARP)", "Network sweep (ping)")
SWEEP_SUSPECT = ("camera", "iot", "esp", "tv", "speaker", "console")  # αυτές δεν έχουν λόγο να σαρώνουν το LAN

class NetState:
    def __init__(self, mode, iface, me_ips, gateway, geo=True, rdns=True, cfg=None, history=None, intel=None):
        self.lock = threading.RLock()
        self.cfg = cfg or copy.deepcopy(DEFAULT_CONFIG)
        th = self.cfg["thresholds"]
        al = self.cfg["allowlist"]
        self.allow_ips = set(al.get("ips") or [])
        self.allow_macs = {norm_mac(m) for m in al.get("macs") or []}
        self.allow_domains = tuple(d.lower().lstrip("*.") for d in al.get("domains") or [])
        self.history = history or History(":memory:")
        self.intel = intel or Intel(self.cfg.get("intel"))
        self.notifier = None
        self.known_macs = self.history.known_macs()
        self.had_devices = bool(self.known_macs)
        self.seen_macs = set()
        self.beacons = {}
        self.services = collections.defaultdict(dict)  # ip → {θύρα που «ακούει": t}
        self.creds, self.cred_users = {}, {}
        self.lab_ips = set()  # «επιτιθέμενοι» του purple-team lab (δεν πάνε σε ιστορικό/ειδοποιήσεις)
        # «Αυτό το έκανα εγώ»: δοκιμές σου που δεν πρέπει να μπερδεύονται με πραγματικές επιθέσεις
        self.own_tool = {"until": 0.0, "why": None}  # σάρωση/εργαλείο του NetWatch από αυτόν τον υπολογιστή
        self.test_ips = {}  # ip → {"until": t, "why": …}: «κάνω δοκιμή από τη συσκευή Χ» (π.χ. nmap από Kali VM)
        self.scan_info = collections.defaultdict(dict)  # ip → {θύρα: banner/έκδοση/TLS από τον σαρωτή}
        self.scanner = self.lab = self.wifi = self.privacy = self.apps = self.honeypot = self.blocker = self.iot = self.sensor = self.mqtt = self.agent = self.hass = self.baseline = self.playbooks = self.health = None
        self._app_rdns = {}
        self.vpn_iface = None  # live: η διεπαφή του VPN όταν περνά όλη την κίνηση (utun…)
        self.leak_dns = collections.deque(maxlen=50)
        self.recent = collections.deque(maxlen=5000)  # τελευταία πακέτα για δοκιμή κανόνων
        import rules as _rules
        self.rules = _rules.RuleEngine(alert=self._rule_alert, ctx=self._rule_ctx)
        self.feed = mode  # ποια πηγή «τροφοδοτεί» τώρα (live/demo/pcap/ctf)
        self.feed_token = 0
        self.ctf_level = None
        self.plain = collections.Counter()  # (client, πρωτόκολλο) → πακέτα χωρίς κρυπτογράφηση
        self.first_t, self.last_t = None, 0.0
        self.min_pkts = self.min_bytes = 0
        self.cur_minute = int(time.time() // 60)
        self.mode, self.iface = mode, iface
        self.me = set(me_ips)
        self.gateway = gateway
        self.geo_enabled, self.rdns_enabled = geo, rdns
        self.hosts = {}
        self.alerts = collections.deque(maxlen=500)
        self.alert_seq = 0
        self.cooldown = {}
        self.pending = []
        self.dirty, self.new_hosts = set(), set()
        self.subs = []
        self.total_pkts = self.total_bytes = 0
        self.win_pkts = self.win_bytes = 0
        self.protos = collections.Counter()
        self.home = None
        self.arp_table = {}
        self.arp_first = {}  # η πρώτη (έμπιστη) MAC που είδαμε για κάθε IP
        self.ip_mac_seen = {}  # IP → {MAC: τελευταία φορά} (για το IPAM: συγκρούσεις IP)
        self.mac_ips = collections.defaultdict(set)
        self.dhcp_servers = {gateway} if gateway else set()
        self.dns_servers = {}
        self.domains = collections.defaultdict(set)
        self.demo_geo = {}
        self.geo_q = queue.Queue()
        self.rdns_pool = ThreadPoolExecutor(8)
        self.w_scan = DistinctWindow(th["port_scan"]["window"])
        self.w_sweep = Window(max(th["ping_sweep"]["window"], th["arp_sweep"]["window"]))
        self.w_syn, self.w_icmp = Window(th["syn_flood"]["window"]), Window(th["icmp_flood"]["window"])
        self.w_arpflood, self.w_brute = Window(th["arp_flood"]["window"]), Window(th["brute_force"]["window"])
        self.w_dnstun, self.w_dga = Window(th["dns_tunnel"]["window"]), Window(th["dga"]["window"])
        # επιθέσεις στο ίδιο το DNS: amplification, flood, NXDOMAIN flood / random subdomain, rebinding
        self.w_dnsamp = Window(th["dns_amplification"]["window"])
        self.w_dnsflood = Window(th["dns_flood"]["window"])
        self.w_nxflood = Window(th["nxdomain_flood"]["window"])
        self.dns_qids = collections.OrderedDict()  # (πελάτης, server, txid) → t: ερωτήματα που είδαμε
        self.dns_public = {}  # όνομα → (δημόσια IP, t): για DNS rebinding (δημόσιο → ιδιωτικό)
        self.windows = (self.w_scan, self.w_sweep, self.w_syn, self.w_icmp, self.w_arpflood, self.w_brute,
                        self.w_dnstun, self.w_dga, self.w_dnsamp, self.w_dnsflood, self.w_nxflood)
        self.started = time.time()

    # ---------- pub/sub ----------
    def subscribe(self):
        q = queue.Queue(maxsize=400)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)

    def publish(self, msg):
        for q in list(self.subs):
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass

    # ---------- hosts ----------
    def net_id(self):
        """Ποιο δίκτυο είναι αυτό: η MAC του router (12 hex), όχι η IP — σπίτι και εργαστήριο έχουν συχνά και τα δύο
        192.168.1.1. Πρώτα ό,τι λέει τώρα ο πίνακας ARP, μετά η πρώτη MAC που είδαμε. None αν δεν την ξέρουμε."""
        mac = (self.arp_table.get(self.gateway) or self.arp_first.get(self.gateway) or "") if self.gateway else ""
        h = mac.lower().replace(":", "").replace("-", "")
        return h if len(h) == 12 and h != "ffffffffffff" and h != "000000000000" else None

    def host(self, ip, t):
        if not ip or ip in ("0.0.0.0", "::"):
            return None
        h = self.hosts.get(ip)
        if h is None:
            kind = ip_kind(ip)
            h = dict(ip=ip, kind=kind, me=ip in self.me, gw=ip == self.gateway,
                     first=t, last=t, pkts_in=0, pkts_out=0, bytes_in=0, bytes_out=0,
                     ports=collections.Counter(), protos=collections.Counter(),
                     names=set(self.domains.get(ip, ())), mac=None, geo=None,
                     rdns=None, threat=0, alerts=[],
                     hits=collections.Counter(), victims=collections.Counter(),
                     act=collections.deque(maxlen=120), ja3=collections.Counter(), ja3_sni={},
                     intel=self.intel.lookup(ip) if kind == "public" else [])
            self.hosts[ip] = h
            self.new_hosts.add(ip)
            if ip in self.demo_geo:
                h["geo"], h["rdns"] = self.demo_geo[ip]
            else:
                if kind == "public" and self.geo_enabled:
                    self.geo_q.put(ip)
                if kind != "bcast" and self.rdns_enabled:
                    self.rdns_pool.submit(self._rdns, ip)
            if len(self.hosts) > 3000:
                old = sorted(self.hosts.values(), key=lambda x: x["last"])[:300]
                for o in old:
                    if not o["me"] and not o["gw"] and not o["threat"]:
                        self.hosts.pop(o["ip"], None)
        return h

    def _rdns(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            return
        with self.lock:
            h = self.hosts.get(ip)
            if h:
                h["rdns"] = name
                self.dirty.add(ip)

    def names_for(self, ip):
        """Ονόματα για μια IP: DNS που είδαμε στο δίκτυο, αλλιώς reverse DNS (στο παρασκήνιο)."""
        with self.lock:
            h = self.hosts.get(ip)
            names = sorted(h["names"]) + ([h["rdns"]] if h.get("rdns") else []) if h else []
            cache = self._app_rdns
        if names:
            return names
        if ip not in cache and self.rdns_enabled:
            cache[ip] = None

            def look():
                try:
                    cache[ip] = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
            self.rdns_pool.submit(look)
        return [cache[ip]] if cache.get(ip) else []

    def ser(self, h):
        return {
            "ip": h["ip"], "kind": h["kind"], "me": h["me"], "gw": h["gw"],
            "first": h["first"], "last": h["last"],
            "pkts_in": h["pkts_in"], "pkts_out": h["pkts_out"],
            "bytes_in": h["bytes_in"], "bytes_out": h["bytes_out"],
            "ports": [[p, c, SERVICES.get(p, "")] for p, c in h["ports"].most_common(12)],
            "protos": dict(h["protos"].most_common(8)),
            "names": sorted(h["names"])[:25], "mac": h["mac"], "geo": h["geo"],
            "rdns": h["rdns"], "threat": h["threat"], "alerts": h["alerts"][-30:],
            "hits": [[k, c, SERVICES.get(k, "") if isinstance(k, int) else ""] for k, c in h["hits"].most_common(25)],
            "victims": h["victims"].most_common(12),
            "act": list(h["act"]),
            "ja3": [[j, c, sorted(h["ja3_sni"].get(j, ()))[:6]] for j, c in h["ja3"].most_common(8)],
            "intel": h["intel"],
            **self._dtype(h),
        }

    def _expected_sweep(self, ip):
        """Οι εκτυπωτές (και τα προγράμματά τους, π.χ. HP Smart) και οι εφαρμογές τύπου Fing ψάχνουν συσκευές με
        σαρώσεις ARP/ping. Αν η πηγή είναι εκτυπωτής ή συσκευή που ονόμασες εσύ → αθώα εξήγηση, αλλιώς None.
        Δεν ισχύει για κάμερες/IoT: μια έξυπνη πρίζα που σαρώνει το LAN είναι ύποπτη ακόμα κι αν την ξέρεις."""
        h = self.hosts.get(ip)
        if not h or h.get("kind") != "local" or h.get("gw"):
            return None
        d = self._dtype(h)
        dn = getattr(self, "devnames", None)
        u = dn.get(h.get("mac"), ip) if dn else None
        t = d.get("dtype")
        if t in SWEEP_SUSPECT:
            return None
        if t == "printer":
            return ("🖨 Εκτυπωτής" + (f" «{d['alias']}»" if d.get("alias") else "") + ": οι εκτυπωτές και τα προγράμματά τους "
                    "(π.χ. HP Smart) ψάχνουν έτσι συσκευές στο δίκτυο. Αναμενόμενο.")
        if u and (u.get("name") or u.get("type")):
            return (f"🏷 Συσκευή που αναγνώρισες" + (f" («{u['name']}»)" if u.get("name") else "") + ": σαρώσεις από δικές σου "
                    "συσκευές (εφαρμογές τύπου Fing, εκτυπωτές, «Ανακάλυψη δικτύου» των Windows) είναι συνήθως αθώες.")
        return None

    def _dtype(self, h):
        """Τύπος/κατασκευαστής για τις τοπικές συσκευές (εικονίδιο και όνομα στον χάρτη του LAN)."""
        if h["kind"] != "local":
            return {}
        import devtype
        t, icon, label, v = devtype.classify(h["mac"], sorted(h["names"]) + ([h["rdns"]] if h.get("rdns") else []),
                                             list(h["ports"]), gw=h["gw"], me=h["me"])
        out = {"dtype": t, "dicon": icon, "dlabel": label, "vendor": v}
        dn = getattr(self, "devnames", None)
        u = dn.get(h["mac"], h["ip"]) if dn else None
        if u:  # 🏷 όνομα/τύπος που έδωσε ο χρήστης — υπερισχύει της εκτίμησης
            if u.get("type"):
                out["dtype"], (out["dicon"], out["dlabel"]) = u["type"], devtype.TYPES[u["type"]]
            if u.get("name"):
                out["alias"] = u["name"]
            if u.get("note"):
                out["note"] = u["note"]
        return out

    def recheck_intel(self):
        with self.lock:
            for ip, h in self.hosts.items():
                if h["kind"] == "public":
                    found = self.intel.lookup(ip)
                    if found != h["intel"]:
                        h["intel"] = found
                        self.dirty.add(ip)
        self.publish({"type": "features", "features": self.features()})

    def features(self):
        n = self.cfg.get("notify", {})
        return {
            "intel": {"enabled": self.cfg["detectors"].get("threat_intel", True), "loaded": self.intel.loaded,
                      "entries": self.intel.entries, "feeds": self.intel.info},
            "abuseipdb": bool(self.cfg.get("intel", {}).get("abuseipdb_key")),
            "history": self.history.path,
            "notify": ({"macos": bool(n.get("macos")), "telegram": bool((n.get("telegram") or {}).get("bot_token")),
                        "ntfy": bool((n.get("ntfy") or {}).get("topic")), **__import__("ops").configured(n),
                        "min_severity": n.get("min_severity")} if self.notifier else None),
            "detectors": self.cfg["detectors"], "thresholds": self.cfg["thresholds"],
            "allowlist": {"ips": len(self.allow_ips), "macs": len(self.allow_macs), "domains": len(self.allow_domains)},
            "config": self.cfg.get("_path"),
            "mitre": [[p, tid, nm, tac] for p, tid, nm, tac, _ in MITRE],
        }

    # ---------- alerts ----------
    def _allowed(self, ip):
        if ip in self.allow_ips:
            return True
        h = self.hosts.get(ip)
        if h and h.get("mac") and h["mac"] in self.allow_macs:
            return True
        return bool(h and self.allow_domains and any(
            n.lower().endswith(self.allow_domains) for n in (h["names"] | ({h["rdns"]} if h["rdns"] else set()))))

    def _allowed_name(self, name):
        return bool(self.allow_domains) and name.lower().endswith(self.allow_domains)

    # ---------- «δική σου δοκιμή» ή «κάποιος άλλος»; ----------
    OWN_TOOL_GRACE = 20  # δευτερόλεπτα μετά το τέλος ενός εργαλείου που αργούν να φτάσουν τα πακέτα του

    def note_own_tool(self, why, seconds=None):
        """Το καλούν ο σαρωτής / τα εργαλεία τεχνικού όσο τρέχουν: ό,τι «βγαίνει» από εσένα τώρα είναι δοκιμή σου."""
        until = time.time() + (seconds or self.OWN_TOOL_GRACE)
        if until > self.own_tool["until"]:
            self.own_tool = {"until": until, "why": why}

    def test_from(self, ip, minutes, why=None):
        """Δηλώνεις «για Ν λεπτά κάνω δοκιμή από αυτή τη συσκευή». minutes=0 → σταματά."""
        if not minutes:
            self.test_ips.pop(ip, None)
            return
        self.test_ips[ip] = {"until": time.time() + minutes * 60, "why": (why or "δοκιμή σου από αυτή τη συσκευή")[:80]}

    def selftest_status(self, now=None):
        now = now or time.time()
        self.test_ips = {ip: v for ip, v in self.test_ips.items() if v["until"] > now}
        return {"test_ips": [{"ip": ip, **v} for ip, v in self.test_ips.items()],
                "own_tool": self.own_tool if self.own_tool["until"] > now else None}

    def _selftest(self, actor, t):
        """→ γιατί αυτή η ειδοποίηση είναι δική σου δοκιμή, ή None (= την προκάλεσε κάποιος άλλος)."""
        now = max(t, time.time()) if self.mode == "live" else t
        x = self.test_ips.get(actor)
        if x and now <= x["until"]:
            return x["why"]
        if actor in self.me:
            sc = self.scanner.state if self.scanner and isinstance(getattr(self.scanner, "state", None), dict) else {}
            if sc.get("status") == "running" or (sc.get("finished") and time.time() - sc["finished"] < self.OWN_TOOL_GRACE):
                return "η σάρωση του NetWatch (🔴 Pentest) από αυτόν τον υπολογιστή"
            if time.time() <= self.own_tool["until"]:
                return self.own_tool["why"]
        return None

    def alert(self, typ, sev, actor, target, detail, t, key=None, cooldown=None, mark=True, mitre=None, benign=None):
        det = detector_for(typ)
        if det and not self.cfg["detectors"].get(det, True):
            return
        if self._allowed(actor):
            return
        k = (typ, key or actor)
        cd = self.cfg["thresholds"].get("alert_cooldown", 60) if cooldown is None else cooldown
        if k in self.cooldown and t - self.cooldown[k] < cd:
            return
        self.cooldown[k] = t
        hy = getattr(self, "hygiene", None)
        if hy and benign is None:  # 🔕 σίγαση από τον χρήστη → φαίνεται αχνά, χωρίς ειδοποίηση/υπόθεση
            try:
                benign = hy.match(typ, actor, t)
            except Exception as e:
                log("hygiene:", e)
        cs = getattr(self, "cases", None)
        if cs and benign is None:  # 🗂 σημειώθηκε «ψευδώς θετικό» σε υπόθεση → φαίνεται, αλλά ως αθώα
            try:
                benign = cs.suppressed(typ, actor, t) or None
            except Exception as e:
                log("cases:", e)
        if benign is None and typ in SWEEPS:  # 🖨 σάρωση από εκτυπωτή / συσκευή που αναγνώρισες → αναμενόμενη (γκρι)
            try:
                benign = self._expected_sweep(actor)
            except Exception as e:
                log("expected sweep:", e)
        self.alert_seq += 1
        lab = actor in self.lab_ips
        a = dict(id=self.alert_seq, t=t, type=typ, sev=sev, actor=actor,
                 target=target, detail=detail, mitre=mitre or mitre_for(typ), lab=lab)
        if benign:  # γνωστή αθώα εξήγηση (π.χ. το δικό σου Tor): φαίνεται, αλλά δεν «χρωματίζει» τίποτα
            a["benign"], mark = benign, False
        mine = None if lab else self._selftest(actor, t)
        if mine:  # η δική σου δοκιμή: φαίνεται (για να δεις τι πιάνει η άμυνα), αλλά δεν είναι συναγερμός
            a["selftest"], mark = mine, False
        self.alerts.appendleft(a)
        # Μερικοί συναγερμοί (DNS flood/amplification/NXDOMAIN) έχουν «δράστη» που δεν είναι IP
        # (π.χ. "DNS", "3 πηγές", ή πολλές IP μαζί)· μη φτιάχνεις ψεύτικη συσκευή γι' αυτόν.
        h = self.host(actor, t) if ip_kind(actor) != "other" else None
        if h:
            if mark:
                h["threat"] = max(h["threat"], SEV[sev])
            h["alerts"].append(a["id"])
            self.dirty.add(actor)
        self.publish({"type": "alert", "alert": a})
        if lab:
            log(f"🧪 LAB {typ}: {actor} → {target}")
            return
        if mine:
            log(f"🧪 ΔΟΚΙΜΗ ΣΟΥ {typ}: {actor} → {target} ({mine})")
            return  # ούτε ιστορικό, ούτε ειδοποιήσεις, ούτε playbooks/Home Assistant
        mt = getattr(self, "maint", None)
        win = mt.active(None, actor, target) if mt else None
        if win:  # παράθυρο συντήρησης: φαίνεται και καταγράφεται, αλλά χωρίς ειδοποιήσεις/playbooks/Home Assistant
            a["maint"] = win
        try:
            self.history.add_alert(a, self.mode)
        except Exception as e:
            log("history error:", e)
        if cs and not benign:  # 🗂 διαλογή: η ειδοποίηση μπαίνει σε υπόθεση (και στα παράθυρα συντήρησης)
            try:
                cid = cs.on_alert(a)
                if cid is not None:
                    a["case"] = cid
            except Exception as e:
                log("cases:", e)
        if win:
            log(f"🔧 [{sev.upper()}] {typ} (συντήρηση «{win}»): {actor} → {target}")
            return
        if self.notifier and not benign:
            self.notifier(a)
        if self.playbooks and not benign and not lab:
            try:
                self.playbooks.on_alert(a)
            except Exception as e:
                log("playbooks:", e)
        if self.hass and not benign and not lab:
            try:
                self.hass.on_alert(a)
            except Exception as e:
                log("home assistant:", e)
        log(f"⚠  [{sev.upper()}] {typ} [{(a['mitre'] or {}).get('id', '-')}]: {actor} → {target} — {detail}")

    # ---------- main pipeline ----------
    def process(self, P):
        t, L = P["t"], P["len"]
        src, dst, proto = P["src"], P["dst"], P["proto"]
        sp, dp = P.get("sp"), P.get("dp")
        label = app_label(proto, sp, dp)
        with self.lock:
            self.pkt_seq = getattr(self, "pkt_seq", 0) + 1
            P["_id"] = self.pkt_seq  # για να ανοίγει το ίδιο πακέτο από τη λίστα 📦 Πακέτα
            packets.remember(P, P.pop("_raw", None))
            if self.first_t is None:
                self.first_t = t
            self.last_t = max(self.last_t, t)
            self.total_pkts += 1
            self.min_pkts += 1
            self.min_bytes += L
            self.total_bytes += L
            self.win_pkts += 1
            self.win_bytes += L
            self.protos[label] += 1
            for name, ip in P.get("dns") or ():
                self.domains[ip].add(name)
                hh = self.hosts.get(ip)
                if hh is not None and name not in hh["names"]:
                    hh["names"].add(name)
                    self.dirty.add(ip)
            for nm in (P.get("sni"), P.get("http_host")):
                if nm:
                    self.domains[dst].add(nm)
            hs = self.host(src, t)
            # ARP «ποιος έχει;» δεν αποδεικνύει ότι υπάρχει η συσκευή-στόχος
            hd = self.hosts.get(dst) if (proto == "ARP" and (P.get("arp") or {}).get("op") == 1) else self.host(dst, t)
            svc = service_port(sp, dp) if sp is not None else None
            if hs:
                hs["pkts_out"] += 1
                hs["bytes_out"] += L
                hs["last"] = t
                hs["protos"][label] += 1
                if svc:
                    hs["ports"][svc] += 1
                if P.get("smac") and hs["kind"] == "local" and proto != "ARP":
                    hs["mac"] = norm_mac(P["smac"])
                    self._mac_seen(src, hs["mac"], t)
                if hs["kind"] == "local":
                    if (proto == "TCP" and P.get("flags") == "SA") or (proto == "UDP" and sp == 1900):
                        if len(self.services[src]) < 200:
                            self.services[src][sp] = t
                    elif dp in PLAIN_PORTS and proto in ("TCP", "UDP") and (sp or 0) > dp and len(self.plain) < 5000:
                        self.plain[(src, PLAIN_PORTS[dp])] += 1
                if P.get("ja3"):
                    hs["ja3"][P["ja3"]] += 1
                    if P.get("sni"):
                        sn = hs["ja3_sni"].setdefault(P["ja3"], set())
                        if len(sn) < 20:
                            sn.add(P["sni"])
                # τι «χτυπάει» / πού συνδέεται ο αποστολέας (μόνο πακέτα που ξεκινούν κάτι)
                fl = P.get("flags", "")
                key = None
                if proto == "TCP" and "S" in fl and "A" not in fl:
                    key = dp
                elif proto == "TCP" and fl in ("", "F", "FPU"):
                    key = dp
                elif proto == "UDP" and dp is not None and (sp or 0) > (dp or 0):
                    key = dp
                elif proto == "ICMP" and P.get("icmp_type") == 8:
                    key = "ICMP ping"
                elif proto == "ARP" and (P.get("arp") or {}).get("op") == 1:
                    key = "ARP who-has"
                if key is not None:
                    hs["hits"][key] += 1
                    hs["victims"][dst] += 1
                # δραστηριότητα ανά 10 δευτερόλεπτα (για γράφημα)
                b = int(t // 10) * 10
                if hs["act"] and hs["act"][-1][0] == b:
                    hs["act"][-1][1] += 1
                else:
                    hs["act"].append([b, 1])
                self.dirty.add(src)
            if hd:
                hd["pkts_in"] += 1
                hd["bytes_in"] += L
                hd["last"] = t
                hd["protos"][label] += 1
                if svc:
                    hd["ports"][svc] += 1
                for nm in (P.get("sni"), P.get("http_host")):
                    if nm and nm not in hd["names"]:
                        hd["names"].add(nm)
                self.dirty.add(dst)
            try:
                self.detect(P, t)
            except Exception as e:  # never kill capture
                log("detect error:", e)
            self.recent.append(P)
            if self.cfg["detectors"].get("custom_rules", True) and self.rules.rules:
                try:
                    self.rules.check(P, t)
                except Exception as e:
                    log("rule error:", e)
            x = 1 if (hs and hs["threat"] >= 2 and not hs["me"]) else 0
            if len(self.pending) < 4000:
                self.pending.append({"s": src, "d": dst, "p": proto, "a": label, "l": L,
                                     "sp": sp, "dp": dp, "x": x, "i": P["_id"],
                                     "f": P.get("flags") or {1: "who-has", 2: "is-at"}.get((P.get("arp") or {}).get("op"), ""),
                                     "t": round(t, 3)})
                if P.get("icmp_type") is not None:  # 8 echo, 0 reply, 11 time exceeded (traceroute), 3 unreachable
                    self.pending[-1]["ic"] = P["icmp_type"]
                nm = (P.get("dns_q") or (None,))[0] or P.get("sni") or P.get("http_host")
                if nm:  # για φίλτρα τύπου Wireshark: dns.qry.name, tls…server_name, http.host
                    self.pending[-1]["n"] = str(nm)[:120]
                    self.pending[-1]["nk"] = "dns" if P.get("dns_q") else "sni" if P.get("sni") else "http"


    def _vpn_leak(self, P, t):
        """Το VPN είναι ενεργό, άρα στη φυσική κάρτα (en0) θα έπρεπε να βλέπουμε ΜΟΝΟ το κρυπτογραφημένο τούνελ."""
        src, dst, dp = P["src"], P["dst"], P.get("dp")
        if dp == 53 and P["proto"] in ("UDP", "TCP"):
            self.leak_dns.append(t)
            if sum(1 for x in self.leak_dns if t - x < 60) >= 3:
                q = (P.get("dns_q") or ("",))[0]
                self.alert("Διαρροή DNS εκτός VPN", "med", src, dst,
                           f"Το VPN ({self.vpn_iface}) είναι ενεργό, αλλά ερωτήματα DNS"
                           + (f" (π.χ. {q})" if q else "") + f" βγαίνουν ανοιχτά από το {self.iface} προς {dst}: "
                           "το Wi‑Fi και ο πάροχος βλέπουν ποια sites επισκέπτεσαι.",
                           t, key="dns-leak", cooldown=600, mark=False)
        elif ":" in src and not src.lower().startswith("fe80") and ip_kind(dst) == "public":
            self.alert("Διαρροή IPv6 εκτός VPN", "med", src, dst,
                       f"Το VPN ({self.vpn_iface}) είναι ενεργό, αλλά κίνηση IPv6 προς {dst} βγαίνει απευθείας από το "
                       f"{self.iface} — το site βλέπει την πραγματική σου σύνδεση.", t, key="v6-leak", cooldown=600, mark=False)

    # ---------- detection ----------
    def _th(self, name):
        return self.cfg["thresholds"][name]

    def detect(self, P, t):
        src, dst, proto = P["src"], P["dst"], P["proto"]
        sp, dp, fl = P.get("sp"), P.get("dp"), P.get("flags", "")
        from_me, to_me = src in self.me, dst in self.me
        if proto == "ARP":
            return self._arp(P, t)
        self._intel_check(src, dst, dp, t, proto, fl)
        techkit.observe(self, P, t)  # 🧰 Modbus/BACnet εγγραφές, ψεύτικο IPv6 RA
        ed = getattr(self, "encdns", None)
        if ed is not None:
            try:
                ed.observe(P, t)
            except Exception:
                pass
        fw = getattr(self, "iotfw", None)
        if fw is not None:
            try:
                fw.observe(P, t)
            except Exception:
                pass
        tl = getattr(self, "timeline", None)
        if tl is not None:
            try:
                tl.observe(P, t)
            except Exception:
                pass
        hu = getattr(self, "hunt", None)
        if hu is not None:
            try:
                hu.observe(P, t)
            except Exception:
                pass
        wa = getattr(self, "watchers", None)  # 👁 trackers / ACR που «καλούν σπίτι» (παθητικό SNI/DNS)
        if wa is not None:
            try:
                wa.observe(P, t)
            except Exception:
                pass
        if P.get("cred"):
            self._cred(P, t)
        if P.get("dns_q"):
            self._dns_query(src, P["dns_q"][0], t)
        if P.get("nx"):
            self._nxdomain(dst, P["nx"], t)
        if proto == "UDP" and (dp == 53 or sp == 53) and "dns_id" in P:
            self._dns_attacks(P, src, dst, sp, dp, t)
        if from_me and self.vpn_iface and self.mode == "live" and self.vpn_iface != self.iface:
            self._vpn_leak(P, t)

        if proto == "TCP" and not from_me:
            if fl in ("", "F", "FPU") or ("F" in fl and "P" in fl and "U" in fl and "A" not in fl):
                name = {"": "NULL", "F": "FIN"}.get(fl, "XMAS")
                self.alert(f"Stealth scan ({name})", "high" if to_me else "med", src, dst,
                           f"Πακέτα TCP με ασυνήθιστα flags [{fl or 'κανένα'}] — εργαλείο τύπου nmap -s{name[0]}", t)
            syn = "S" in fl and "A" not in fl
            if syn:
                th = self._th("port_scan")
                self.w_scan.add(src, (dst, dp), t)
                n = self.w_scan.distinct(src)
                if n >= th["count"]:
                    targets = self.w_scan.distinct0(src)
                    self.alert("Port scan", "high" if to_me else "med", src, dst,
                               f"{n} απόπειρες σε {targets} στόχο(ους) μέσα σε {th['window']}s (TCP SYN scan)", t)
                if to_me:
                    if ip_kind(src) == "public":
                        self.alert("Εισερχόμενη σύνδεση", "low", src, dst,
                                   f"Μη αναμενόμενο SYN από το Internet στη θύρα {dp} ({SERVICES.get(dp, '?')})", t)
                    th = self._th("syn_flood")
                    dq = self.w_syn.add("me", src, t)
                    if len(dq) >= th["count"]:
                        top = collections.Counter(i for _, i in dq).most_common(1)[0][0]
                        self.alert("SYN flood", "high", top, dst,
                                   f"{len(dq)} SYN σε {th['window']}s προς εσένα — επίθεση άρνησης υπηρεσίας (DoS)",
                                   t, key="synflood")
                    if dp in BRUTE_PORTS:
                        th = self._th("brute_force")
                        dq = self.w_brute.add((src, dp), 1, t)
                        if len(dq) >= th["count"]:
                            self.alert("Brute force", "high", src, dst,
                                       f"{len(dq)} συνδέσεις στην υπηρεσία {SERVICES.get(dp)} ({dp}) σε "
                                       f"{th['window']}s — δοκιμή κωδικών", t)

        if proto == "TCP" and "S" in fl and "A" not in fl and ip_kind(src) == "local" and ip_kind(dst) == "public":
            self._beacon(src, dst, dp, t)

        if (proto == "UDP" and not from_me and dp is not None and dp < 1024 and (sp or 0) >= 1024
                and dp not in (53, 67, 68, 123, 137, 138)):
            th = self._th("port_scan")
            self.w_scan.add(src, (dst, dp), t)
            n = self.w_scan.distinct(src)
            if n >= th["count"]:
                self.alert("Port scan (UDP)", "high" if to_me else "med", src, dst,
                           f"{n} διαφορετικές UDP θύρες/στόχοι σε {th['window']}s", t)

        if proto == "ICMP" and P.get("icmp_type") == 8 and not from_me:
            th = self._th("ping_sweep")
            dq = self.w_sweep.add(("icmp", src), dst, t)
            n = len({i for ti, i in dq if ti >= t - th["window"]})
            if n >= th["count"]:
                self.alert("Network sweep (ping)", "med", src, dst,
                           f"Ping σε {n} διαφορετικές IP σε {th['window']}s — χαρτογράφηση δικτύου", t)
            if to_me:
                th = self._th("icmp_flood")
                dq = self.w_icmp.add(src, 1, t)
                if len(dq) >= th["count"]:
                    self.alert("ICMP flood", "high", src, dst, f"{len(dq)} ping σε {th['window']}s προς εσένα", t)

        if proto == "UDP" and sp == 67 and dp == 68:
            if src not in self.dhcp_servers and self.dhcp_servers:
                self.alert("Rogue DHCP server", "high", src, dst,
                           f"Νέος DHCP server ({src}) εκτός από {', '.join(sorted(self.dhcp_servers))} — "
                           "μπορεί να σε στείλει σε ψεύτικο gateway/DNS", t)
            self.dhcp_servers.add(src)

        if proto == "UDP":
            if from_me and dp == 53:
                self.dns_servers[dst] = t
            elif to_me and sp == 53 and self.dns_servers and src not in self.dns_servers:
                self.alert("Ύποπτη απάντηση DNS", "med", src, dst,
                           "Απάντηση DNS από διακομιστή που δεν ρωτήθηκε — πιθανό DNS spoofing", t)

        if not from_me and proto == "TCP" and fl == "S" and dp in TOR_PORTS and ip_kind(src) == "local" and ip_kind(dst) == "public":
            self._tor_use(src, dst, dp, t)

        if from_me and proto in ("TCP", "UDP") and dp in SUSPECT_PORTS and ("S" in fl or proto == "UDP"):
            benign = None
            if dp in TOR_PORTS and self.mode == "live" and local_tor_running():
                benign = ("Είναι το δικό σου Tor: τρέχει στο Mac σου και συνδέεται σε κόμβους (relays) του δικτύου "
                          "Tor σε αυτή τη θύρα. Αναμενόμενο — δεν χρειάζεται να κάνεις τίποτα.")
            self.alert("Ύποπτη εξερχόμενη θύρα", "low", dst, src,
                       f"Ο υπολογιστής σου συνδέθηκε στη θύρα {dp} ({SUSPECT_PORTS[dp]}) αυτής της IP", t,
                       key=f"{dst}:{dp}" if benign else None, cooldown=3600 if benign else None, benign=benign)

    # --- αλλαγή πηγής κίνησης (CTF) ---
    KEEP = ("lock", "subs", "intel", "notifier", "scanner", "lab", "wifi", "privacy", "apps", "honeypot", "blocker", "iot", "sensor", "mqtt", "agent", "hass", "baseline", "playbooks", "timeline", "hunt", "cases", "configbak", "changecheck", "triage", "handover", "whereis", "expiry", "segcheck", "sitecheck", "topomap", "ssh", "devnames", "updater", "l2guard", "presence", "app_ctl", "npcap", "hygiene", "assess", "vulns", "upnp", "ot", "accept", "sites", "labels", "v6", "nac", "iotinv", "radio", "field", "uplink", "soak", "remote", "camcheck", "probes", "watchers", "health", "vpn_iface", "_app_rdns", "geo_q", "rdns_pool", "demo_geo", "home",
            "rules", "cfg", "geo_enabled", "rdns_enabled", "feed_token", "origin", "rule_errors", "own_tool", "test_ips")

    def reset(self, mode, iface, me_ips, gateway, history, feed, notifier=None):
        """Καθαρίζει όλη την κατάσταση και ξεκινά από την αρχή με νέα πηγή (κρατά συνδέσεις/ρυθμίσεις)."""
        keep = {k: getattr(self, k) for k in self.KEEP if hasattr(self, k)}
        packets.clear()
        with keep["lock"]:
            self.__init__(mode, iface, me_ips, gateway, geo=keep["geo_enabled"], rdns=keep["rdns_enabled"],
                          cfg=keep["cfg"], history=history, intel=keep["intel"])
            for k, v in keep.items():
                setattr(self, k, v)
            self.rules.windows.clear()
            self.feed = feed
            self.feed_token += 1
            self.notifier = notifier
            snap = self.snapshot()
        self.publish(snap)

    # --- δικοί σου κανόνες (καρτέλα 🧩) ---
    def _rule_ctx(self):
        return {"me": self.me, "gw": self.gateway, "kind": ip_kind}

    def _rule_alert(self, rule, actor, target, detail, t):
        m = next(({"id": tid, "name": nm, "tactic": tac} for _, tid, nm, tac, _ in MITRE if tid == rule.mitre), None)
        if not m and rule.mitre in EXTRA_MITRE:
            m = {"id": rule.mitre, "name": EXTRA_MITRE[rule.mitre][0], "tactic": EXTRA_MITRE[rule.mitre][1]}
        if rule.mitre and not m:
            m = {"id": rule.mitre, "name": "", "tactic": rule.tactic or "Custom"}
        if m:
            m["url"] = "https://attack.mitre.org/techniques/" + m["id"].replace(".", "/") + "/"
        self.alert("Κανόνας: " + rule.title, rule.severity, actor, target, detail, t,
                   key=(rule.id, actor), cooldown=rule.cooldown, mitre=m)

    def rules_view(self):
        import rules as R
        ctx = self._rule_ctx()
        out = []
        for r in self.rules.rules:
            i = r.info()
            i.update(hits=self.rules.hits.get(r.id, 0), last_hit=self.rules.last_hit.get(r.id),
                     sigma=R.to_sigma(r), suricata=R.to_suricata(r, R.sid_for(r.id), ctx))
            out.append(i)
        return {"rules": out, "errors": getattr(self, "rule_errors", []), "help": R.FIELD_HELP,
                "template": R.TEMPLATE, "recent": len(self.recent),
                "enabled": self.cfg["detectors"].get("custom_rules", True)}

    def test_rules(self, text):
        """Δοκιμή κανόνα στα τελευταία πακέτα — χωρίς ειδοποιήσεις."""
        import rules as R
        rs = R.parse_rules(text, "δοκιμή")
        if not rs:
            raise R.RuleError("Κενός κανόνας")
        with self.lock:
            pkts = list(self.recent)
        ctx = self._rule_ctx()
        fired = {}

        def hit(r, a, tg, d, t):
            v = fired.setdefault((r.id, a), {"rule": r.id, "actor": a, "target": tg, "detail": d, "t": t, "n": 0})
            v["n"] += 1
        eng = R.RuleEngine(rs, ctx=ctx, alert=hit)
        matches, sample = collections.Counter(), []
        for P in pkts:
            for r in rs:
                if r.matches(P, ctx):
                    matches[r.id] += 1
                    if len(sample) < 10:
                        sample.append({k: P.get(k) for k in ("t", "src", "dst", "proto", "sp", "dp", "flags")} |
                                      {"q": (P.get("dns_q") or (None,))[0] or P.get("sni") or P.get("http_host")})
            eng.check(P, P["t"])
        return {"packets": len(pkts), "matches": dict(matches), "alerts": list(fired.values())[:30],
                "sample": sample, "rules": [r.id for r in rs]}

    def reload_rules(self):
        import rules as R
        rs, errs = R.load_dir(RULES_DIR)
        self.rules.set_rules(rs)
        self.rule_errors = errs
        for e in errs:
            log("⚠ κανόνας:", e)
        return rs

    def save_rule(self, text):
        import rules as R
        new = R.parse_rules(text, "local.yaml")
        if not new:
            raise R.RuleError("Κενός κανόνας")
        path = os.path.join(RULES_DIR, "local.yaml")
        cur = []
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                cur = R.parse_rules(f.read(), "local.yaml")
        others = {r.id: r.source for r in self.rules.rules if r.source != "local.yaml"}
        for r in new:
            if r.id in others:
                raise R.RuleError(f"Το id «{r.id}» υπάρχει ήδη στο {others[r.id]} — διάλεξε άλλο")
        ids = {r.id for r in new}
        data = [r.raw for r in cur if r.id not in ids] + [r.raw for r in new]
        self._write_local(data)
        return [r.id for r in new]

    def delete_rule(self, rid):
        import rules as R
        path = os.path.join(RULES_DIR, "local.yaml")
        if not os.path.exists(path):
            raise R.RuleError("Δεν υπάρχουν δικοί σου κανόνες")
        with open(path, encoding="utf-8") as f:
            cur = R.parse_rules(f.read(), "local.yaml")
        if rid not in {r.id for r in cur}:
            raise R.RuleError("Μόνο κανόνες του local.yaml σβήνονται από εδώ")
        self._write_local([r.raw for r in cur if r.id != rid])

    def _write_local(self, data):
        import yaml
        os.makedirs(RULES_DIR, exist_ok=True)
        path = os.path.join(RULES_DIR, "local.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Οι δικοί σου κανόνες (γράφονται από την καρτέλα 🧩 Κανόνες)\n")
            yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
        chown_to_user(path)
        self.reload_rules()

    # --- κωδικοί που ταξιδεύουν χωρίς κρυπτογράφηση ---
    def _cred(self, P, t):
        c, src, dst, dp = P["cred"], P["src"], P["dst"], P.get("dp")
        if c["field"] == "user":
            if len(self.cred_users) > 5000:
                self.cred_users.clear()
            self.cred_users[(src, dst, dp)] = c.get("user")
            return
        user = mask_user(c.get("user") or self.cred_users.pop((src, dst, dp), None))
        k = (src, dst, c["proto"])
        rec = self.creds.get(k)
        if rec is None:
            if len(self.creds) > 1000:
                return
            rec = self.creds[k] = {"client": src, "server": dst, "port": dp, "proto": c["proto"],
                                   "user": user, "n": 0, "first": t}
        rec["n"] += 1
        rec["last"] = t
        rec["user"] = user or rec["user"]
        if c["field"] == "session":
            what = "η συνεδρία Telnet (ό,τι πληκτρολογείς, μαζί με τον κωδικό)"
        elif c["field"] == "user_only":
            what = f"το όνομα χρήστη «{user}» (χωρίς κωδικό — άρα ο broker μάλλον δέχεται σχεδόν τους πάντες)"
        elif c["proto"] == "MQTT":
            what = f"ο κωδικός MQTT του «{user or '?'}»" + (f" (client {c['client']})" if c.get("client") else "") + \
                " — με αυτόν, όποιος τον δει στέλνει εντολές στις συσκευές σου. Βάλε TLS (8883)"
        else:
            what = "ο κωδικός" + (f" του χρήστη «{user}»" if user else "")
        self.alert("Κωδικός σε καθαρό κείμενο", "med" if c["field"] in ("session", "user_only") else "high", src, dst,
                   f"{c['proto']} προς {dst}:{dp} — {what} ταξιδεύει χωρίς κρυπτογράφηση· "
                   "όποιος «ακούει» το δίκτυο τον βλέπει", t, key=k, mark=False)

    # --- έλεγχος ασφάλειας του δικτύου (καρτέλα 🛡) ---
    def audit(self):
        with self.lock:
            now = self.last_t or time.time()
            checks, score = [], 100

            def chk(cid, status, title, detail, advice, penalty=0):
                nonlocal score
                score -= penalty
                checks.append({"id": cid, "status": status, "title": title, "detail": detail,
                               "advice": advice, "penalty": penalty})

            def name(ip):
                h = self.hosts.get(ip) or {}
                return h.get("rdns") or (sorted(h.get("names") or ()) or [None])[0]

            creds = sorted(self.creds.values(), key=lambda r: -r["last"])
            if creds:
                chk("creds", "bad", "Κωδικοί σε καθαρό κείμενο",
                    f"{len(creds)} σύνδεση(εις) έστειλαν κωδικό χωρίς κρυπτογράφηση "
                    f"({', '.join(sorted({c['proto'] for c in creds}))}).",
                    "Άλλαξε αυτούς τους κωδικούς και χρησιμοποίησε την ασφαλή εκδοχή: SFTP αντί FTP, SSH αντί Telnet, "
                    "HTTPS αντί HTTP, IMAPS/POP3S αντί IMAP/POP3.", min(30, 15 * len(creds)))
            else:
                chk("creds", "ok", "Κωδικοί σε καθαρό κείμενο", "Δεν είδα κανέναν κωδικό να ταξιδεύει ακρυπτογράφητος.",
                    "Συνέχισε να χρησιμοποιείς HTTPS και κρυπτογραφημένα πρωτόκολλα.")

            services = []
            for ip, ports in self.services.items():
                h = self.hosts.get(ip) or {}
                for p in sorted(ports):
                    risk, why = RISKY_SERVICES.get(p, ("info", SERVICES.get(p, "")))
                    si = self.scan_info.get(ip, {}).get(p, {})
                    services.append({"ip": ip, "name": name(ip), "mac": h.get("mac"), "port": p,
                                     "product": si.get("product"), "version": si.get("version"),
                                     "svc": SERVICES.get(p, ""), "risk": risk, "why": why,
                                     "gw": ip == self.gateway, "me": ip in self.me})
            services.sort(key=lambda s: (-SEV.get(s["risk"], 0), s["ip"], s["port"]))
            high = [s for s in services if s["risk"] == "high"]
            med = [s for s in services if s["risk"] == "med"]
            if high or med:
                chk("services", "bad" if high else "warn", "Επικίνδυνες υπηρεσίες στο LAN",
                    f"{len(high)} υψηλού και {len(med)} μεσαίου κινδύνου: " +
                    ", ".join(f"{s['svc'] or s['port']} στη {s['ip']}" for s in (high + med)[:5]),
                    "Κλείσε ό,τι δεν χρησιμοποιείς, άλλαξε default κωδικούς, βάλε τις IoT συσκευές σε δίκτυο επισκεπτών.",
                    min(30, 10 * len(high) + 5 * len(med)))
            else:
                chk("services", "ok", "Επικίνδυνες υπηρεσίες στο LAN",
                    f"Δεν είδα επικίνδυνες υπηρεσίες ({len(services)} υπηρεσίες συνολικά).",
                    "Το NetWatch βλέπει μόνο υπηρεσίες που χρησιμοποιήθηκαν· για πλήρη εικόνα κάνε σάρωση με nmap.")

            recent = [a for a in self.alerts if now - a["t"] < 3600 and not a.get("lab") and not a.get("selftest")]
            attacks = [a for a in recent if not a["type"].startswith(("Κωδικός σε καθαρό", "Νέα συσκευή"))]
            hi = [a for a in attacks if a["sev"] == "high"]
            if attacks:
                chk("attacks", "bad" if hi else "warn", "Επιθέσεις την τελευταία ώρα",
                    f"{len(attacks)} ειδοποιήσεις ({len(hi)} υψηλής σοβαρότητας) από "
                    f"{len({a['actor'] for a in attacks})} πηγές.",
                    "Δες την καρτέλα ⚠ Επιθέσεις και το «ℹ Τι σημαίνει;» σε κάθε μία.", 20 if hi else 8)
            else:
                chk("attacks", "ok", "Επιθέσεις την τελευταία ώρα", "Καμία.", "")

            intel = [a for a in recent if "κακόβουλη IP" in a["type"]]
            if intel:
                chk("intel", "bad", "Επικοινωνία με γνωστές κακόβουλες IP",
                    f"{len({a['actor'] for a in intel})} IP από λίστες threat intel.",
                    "Βρες ποια συσκευή του LAN μιλάει μαζί τους (🔎 Λεπτομέρειες) και έλεγξέ τη για malware.", 15)

            newdev = [a for a in recent if a["type"].startswith("Νέα συσκευή")]
            if newdev:
                chk("devices", "warn", "Άγνωστες συσκευές",
                    f"{len(newdev)} νέα(ες) συσκευή(ές) μπήκαν στο δίκτυο: " + ", ".join(a["actor"] for a in newdev[:5]),
                    "Αν δεν τις αναγνωρίζεις, άλλαξε τον κωδικό του Wi‑Fi (WPA2/WPA3).", 5)
            else:
                chk("devices", "ok", "Άγνωστες συσκευές", "Καμία νέα συσκευή την τελευταία ώρα.", "")

            http, enc = self.protos.get("HTTP", 0), self.protos.get("HTTPS", 0) + self.protos.get("QUIC", 0)
            share = http / (http + enc) if http + enc else 0
            if share > 0.05:
                chk("http", "warn", "Ιστοσελίδες χωρίς HTTPS", f"{share:.0%} της κίνησης web είναι ακρυπτογράφητο HTTP.",
                    "Ενεργοποίησε «HTTPS-Only mode» στον browser.", 5)
            else:
                chk("http", "ok", "Ιστοσελίδες χωρίς HTTPS", f"Μόνο {share:.0%} της κίνησης web είναι HTTP.", "")

            dns_plain = sum(n for (c, p), n in self.plain.items() if p == "DNS")
            if dns_plain:
                chk("dns", "warn", "DNS χωρίς κρυπτογράφηση",
                    f"{dns_plain} ερωτήματα DNS στάλθηκαν «ανοιχτά» — ο πάροχος και όποιος είναι στη μέση "
                    "βλέπουν κάθε site που επισκέπτεσαι.",
                    "Ενεργοποίησε DNS over HTTPS (DoH) στον browser ή στο σύστημα (π.χ. 1.1.1.1, Quad9).", 5)
            else:
                chk("dns", "ok", "DNS χωρίς κρυπτογράφηση", "Δεν είδα ακρυπτογράφητο DNS.", "")

            plain = [{"client": c, "proto": p, "n": n} for (c, p), n in self.plain.most_common(20) if p != "DNS"]
            score = max(0, min(100, score))
            grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
            return {"score": score, "grade": grade, "checks": checks, "services": services[:100],
                    "creds": creds[:50], "plain": plain, "t": now}

    # --- αποτελέσματα του σαρωτή (καρτέλα 🔴 Pentest) ---
    def scan_result(self, hosts):
        t = self.last_t or time.time()
        with self.lock:
            for h in hosts:
                for sv in h["services"]:
                    self.services[h["ip"]][sv["port"]] = t
                    self.scan_info[h["ip"]][sv["port"]] = {k: sv.get(k) for k in ("product", "version", "banner")}

    def scan_view(self):
        st = self.scanner.status() if self.scanner else {"status": "off"}
        with self.lock:
            for h in st.get("hosts") or ():
                hh = self.hosts.get(h["ip"]) or {}
                h["name"] = hh.get("rdns") or (sorted(hh.get("names") or ()) or [None])[0]
                h["gw"], h["me"] = h["ip"] == self.gateway, h["ip"] in self.me
                h["mac"] = h.get("mac") or hh.get("mac")
                worst = 0
                for sv in h["services"]:
                    p = sv["port"]
                    sv["svc"] = SERVICES.get(p, "")
                    if p in SUSPECT_PORTS:
                        sv["risk"], sv["why"] = "high", f"Θύρα {SUSPECT_PORTS[p]} — συχνά backdoor/κακόβουλο λογισμικό"
                    else:
                        sv["risk"], sv["why"] = RISKY_SERVICES.get(p, ("info", ""))
                    for sev, msg in (sv.get("tls") or {}).get("findings", []):
                        if SEV[sev] > SEV.get(sv["risk"], 0):
                            sv["risk"] = sev
                        sv["why"] = (sv["why"] + " · " if sv["why"] else "") + msg
                    worst = max(worst, SEV.get(sv["risk"], 0))
                h["risk"] = {3: "high", 2: "med", 1: "low"}.get(worst, "info")
        return st

    def default_scan_target(self):
        if self.mode == "demo":
            return "192.168.1.0/24"
        ips = [i for i in self.me if ":" not in i] if self.mode == "live" else []
        if not ips:
            if not hasattr(self, "_real_me"):
                self._real_me = sorted(i for i in detect_net()[2] if ":" not in i and not i.startswith("127."))
            ips = self._real_me
        return (ips[0].rsplit(".", 1)[0] + ".0/24") if ips else "192.168.1.0/24"

    # --- C2 beaconing: συνδέσεις με «ρολόι» ---
    def _beacon(self, src, dst, dp, t):
        if dp in (53, 123) or dst in DNS_RESOLVERS:  # DNS/NTP και γνωστοί resolvers (DoH/DoT) = κανονικό «ρολόι»
            return
        b = self._th("beaconing")
        key = (src, dst, dp)
        dq = self.beacons.get(key)
        if dq is None:
            if len(self.beacons) > 20000:
                return
            dq = self.beacons[key] = collections.deque(maxlen=max(30, b["min_events"]))
        if dq and t - dq[-1] < 1:  # παράλληλες συνδέσεις / retransmits
            return
        dq.append(t)
        n = b["min_events"]
        if len(dq) < n:
            return
        ts = list(dq)[-n:]
        iv = [y - x for x, y in zip(ts, ts[1:])]
        mean = sum(iv) / len(iv)
        if not b["min_interval"] <= mean <= b["max_interval"]:
            return
        cv = (sum((x - mean) ** 2 for x in iv) / len(iv)) ** 0.5 / mean
        if cv <= b["max_jitter"]:
            self.alert("Beaconing (πιθανό C2)", "med", dst, src,
                       f"Η {src} ανοίγει σύνδεση στο {dst}:{dp} κάθε ~{mean:.0f}s (απόκλιση ±{cv * 100:.0f}%), "
                       f"{len(ts)} φορές στη σειρά — τέτοιο «ρολόι» είναι τυπικό για malware που ζητάει εντολές",
                       t, key=("beacon", key), cooldown=600)

    # --- DNS tunneling: δεδομένα κρυμμένα σε subdomains ---
    def _dns_query(self, src, qname, t):
        if ip_kind(src) != "local":
            return
        q = qname.lower().rstrip(".")
        if q.endswith((".local", ".arpa", ".lan", ".home", ".localdomain")) or self._allowed_name(q):
            return
        base, sub = split_domain(q)
        if not sub:
            return
        th = self._th("dns_tunnel")
        flat = sub.replace(".", "")
        if (len(flat) >= th["min_length"] and entropy(flat) >= th["min_entropy"]) or len(q) > 120:
            dq = self.w_dnstun.add((src, base), sub, t)
            n = len({i for _, i in dq})
            if n >= th["unique_subdomains"]:
                self.alert("DNS tunneling", "high", src, base,
                           f"{n} μοναδικά, τυχαία subdomains του {base} σε {th['window']}s (π.χ. {sub[:32]}…) — "
                           "δεδομένα κρυμμένα μέσα σε ερωτήματα DNS (exfiltration / C2)", t,
                           key=("dnstun", src, base), cooldown=300)

    # --- επιθέσεις στο DNS ---
    DNS_QID_TTL = 15  # δευτ.: μια απάντηση χωρίς ερώτημα στο τελευταίο 15″ θεωρείται «δεν ζητήθηκε»
    DNS_QID_MAX = 50000
    REBIND_OK = (".plex.direct", ".nip.io", ".sslip.io", ".xip.io", ".localtest.me", ".lvh.me", ".traefik.me")

    def _dns_attacks(self, P, src, dst, sp, dp, t):
        if dp == 53 and not P.get("dns_resp"):
            q = self.dns_qids
            q[(src, dst, P["dns_id"])] = t
            while q and (len(q) > self.DNS_QID_MAX or next(iter(q.values())) < t - self.DNS_QID_TTL):
                q.popitem(last=False)
            self._dns_flood(src, dst, t)
        elif sp == 53 and P.get("dns_resp"):
            asked = self.dns_qids.pop((dst, src, P["dns_id"]), None) is not None
            self._dns_amplification(src, dst, P["len"], asked, t)
            if P.get("nx"):
                self._nxdomain_flood(src, P["nx"], t)
            if P.get("dns"):
                self._dns_rebinding(src, dst, P["dns"], t)

    def _dns_amplification(self, server, client, size, asked, t):
        """Πολλές/μεγάλες απαντήσεις DNS που ΔΕΝ ζήτησε κανείς: κάποιος έστειλε ερωτήματα με πλαστή διεύθυνση
        αποστολέα (τη δική μας), και οι resolvers «βομβαρδίζουν» το θύμα. Ή, ανάποδα, ένας DNS server του LAN
        απαντά μαζικά σε δημόσιες IP: είναι ανοιχτός resolver που τον χρησιμοποιούν ως «ενισχυτή»."""
        th = self._th("dns_amplification")
        local_server = ip_kind(server) == "local"
        if local_server and ip_kind(client) == "public":
            dq = self.w_dnsamp.add(("refl", server), (client, size), t)
            victims = {c for _, (c, _) in dq}
            total = sum(s for _, (_, s) in dq)
            if len(victims) >= th["reflector_targets"] or total >= th["bytes"]:
                self.alert("DNS amplification (ανοιχτός resolver)", "high", server, ", ".join(sorted(victims)[:3]),
                           f"Ο DNS server {server} του δικτύου σου έστειλε {len(dq)} απαντήσεις ({total // 1024} KB) σε "
                           f"{len(victims)} δημόσιες IP μέσα σε {th['window']}s — είναι ανοιχτός στο Internet και τον "
                           "χρησιμοποιούν ως «ενισχυτή» για επιθέσεις DDoS σε άλλους", t,
                           key=("dnsrefl", server), cooldown=600)
            return
        if asked or ip_kind(client) != "local":
            return
        dq = self.w_dnsamp.add(("victim", client), (server, size), t)
        total = sum(s for _, (_, s) in dq)
        servers = {sv for _, (sv, _) in dq}
        if (len(dq) >= th["count"] or total >= th["bytes"]) and len(servers) >= th["min_servers"]:
            self.alert("DNS amplification", "high", ", ".join(sorted(servers)[:3]), client,
                       f"{len(dq)} απαντήσεις DNS ({total // 1024} KB) από {len(servers)} servers προς {client} μέσα σε "
                       f"{th['window']}s, χωρίς να έχει ρωτήσει — κάποιος στέλνει ερωτήματα με πλαστή διεύθυνση "
                       "αποστολέα ώστε οι απαντήσεις να «πλημμυρίσουν» τη σύνδεση (DDoS με ενίσχυση)", t,
                       key=("dnsamp", client), cooldown=300)

    def _dns_flood(self, client, server, t):
        th = self._th("dns_flood")
        dq = self.w_dnsflood.add(server, client, t)
        if len(dq) < th["count"]:
            return
        top = collections.Counter(c for _, c in dq).most_common(3)
        who = top[0][0] if top[0][1] >= len(dq) * 0.5 else f"{len({c for _, c in dq})} πηγές"
        self.alert("DNS flood", "high", who, server,
                   f"{len(dq)} ερωτήματα DNS προς {server} σε {th['window']}s (κυρίως από "
                   f"{', '.join(f'{c} ×{n}' for c, n in top)}) — προσπάθεια να «γονατίσει» ο DNS server, "
                   "ώστε να μη λειτουργεί η επίλυση ονομάτων για κανέναν", t, key=("dnsflood", server), cooldown=300)

    def _nxdomain_flood(self, server, qname, t):
        th = self._th("nxdomain_flood")
        q = qname.lower().rstrip(".")
        if q.endswith((".in-addr.arpa", ".ip6.arpa")):
            return  # αντίστροφες αναζητήσεις (IP → όνομα): τις κάνει κάθε σάρωση/λίστα συσκευών, συνήθως «δεν υπάρχει»
        dq = self.w_nxflood.add(server, q, t)
        if len(dq) < th["count"]:
            return
        names = [n for _, n in dq]
        bases = collections.Counter(split_domain(n)[0] for n in names)
        base, n_base = bases.most_common(1)[0]
        uniq = len({n for n in names if split_domain(n)[0] == base})
        if n_base >= len(names) * th["same_domain"] and uniq >= th["count"] // 2:
            self.alert("NXDOMAIN flood (random subdomain)", "high", "DNS", base,
                       f"{n_base} ερωτήματα για ανύπαρκτα, τυχαία subdomains του {base} μέσα σε {th['window']}s "
                       f"(π.χ. {', '.join(sorted(set(names))[:2])}) — «water torture»: κάθε ερώτημα περνά την cache και "
                       f"φτάνει στον DNS server του {base}, για να τον υπερφορτώσει", t,
                       key=("nxsub", base), cooldown=300)
        else:
            self.alert("NXDOMAIN flood", "med", "DNS", server,
                       f"{len(names)} απαντήσεις «δεν υπάρχει» (NXDOMAIN) από τον {server} σε {th['window']}s, για "
                       f"{len(bases)} διαφορετικά domains — πλημμύρα ερωτημάτων για ανύπαρκτα ονόματα που "
                       "υπερφορτώνει τον resolver (ή συσκευή που «κόλλησε»)", t, key=("nxflood", server), cooldown=300)

    def _dns_rebinding(self, server, client, answers, t):
        """Το ίδιο δημόσιο όνομα έδειχνε σε δημόσια IP και ξαφνικά δείχνει σε IP του LAN / localhost: έτσι μια
        ιστοσελίδα κάνει τον browser να μιλήσει με τον router ή άλλες συσκευές του σπιτιού (DNS rebinding)."""
        win = self._th("dns_rebinding")["window"]
        for name, ip in answers:
            n = name.lower().rstrip(".")
            if n.endswith((".local", ".lan", ".home", ".arpa", ".localdomain", ".internal")) or \
                    n.endswith(self.REBIND_OK) or self._allowed_name(n) or "." not in n:
                continue
            if ip in ("0.0.0.0", "::"):  # έτσι «μπλοκάρουν» Pi-hole/AdGuard — όχι rebinding
                continue
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if a.is_global:
                self.dns_public[n] = (ip, t)
                if len(self.dns_public) > 20000:
                    self.dns_public.pop(next(iter(self.dns_public)))
                continue
            if not (a.is_private or a.is_loopback or a.is_link_local):
                continue
            prev = self.dns_public.get(n)
            if prev and t - prev[1] <= win:
                self.alert("DNS rebinding", "high", server, n,
                           f"Το {n} έδειχνε στη δημόσια IP {prev[0]} και πριν από {int(t - prev[1])}s άλλαξε στην {ip} "
                           f"του δικού σου δικτύου (απάντηση προς {client}) — μια ιστοσελίδα προσπαθεί να κάνει τον browser "
                           "να μιλήσει με τον router ή άλλη συσκευή του σπιτιού σου", t,
                           key=("rebind", n), cooldown=600)

    # --- DGA: πολλά ανύπαρκτα «τυχαία» domains ---
    def _nxdomain(self, client, qname, t):
        if ip_kind(client) != "local":
            return
        q = qname.lower().rstrip(".")
        base, _ = split_domain(q)
        th = self._th("dga")
        if self._allowed_name(q) or dga_score(base.split(".")[0]) < th["min_score"]:
            return
        dq = self.w_dga.add(client, q, t)
        names = {i for _, i in dq}
        if len(names) >= th["nxdomain"]:
            self.alert("DGA domains", "high", client, "DNS",
                       f"{len(names)} ανύπαρκτα «τυχαία» domains σε {th['window']}s (π.χ. {', '.join(sorted(names)[:3])}) "
                       "— malware που ψάχνει τον server του (Domain Generation Algorithm)", t,
                       key=("dga", client), cooldown=300)

    # --- threat intel ---
    def _intel_check(self, src, dst, dp, t, proto=None, fl=""):
        hs, hd = self.hosts.get(src), self.hosts.get(dst)
        tor_d = hd is not None and hd["intel"] and all(f["kind"] == "tor" for f in hd["intel"])
        tor_s = hs is not None and hs["intel"] and all(f["kind"] == "tor" for f in hs["intel"])
        if tor_d and ip_kind(src) == "local":
            self._tor_use(src, dst, dp, t)
        elif tor_s and ip_kind(dst) == "local":
            if proto == "TCP" and fl == "S":  # μόνο νέες εισερχόμενες συνδέσεις, όχι απαντήσεις
                self.alert("Κίνηση από κόμβο Tor", "low", src, dst,
                           f"Κάποιος που κρύβεται πίσω από Tor (κόμβος εξόδου {src}) χτυπά την {dst}{':' + str(dp) if dp else ''}. "
                           "Τα bots/σαρωτές χρησιμοποιούν συχνά Tor για να μη φαίνονται.", t, key=("tor-in", src), cooldown=1800)
        elif hd is not None and hd["intel"] and ip_kind(src) == "local":
            c2 = any(f["kind"] == "c2" for f in hd["intel"])
            self.alert("Σύνδεση σε κακόβουλη IP", "high" if c2 else "med", dst, src,
                       f"Η {src} επικοινωνεί με {dst}{':' + str(dp) if dp else ''} που υπάρχει στη λίστα "
                       f"{', '.join(f['name'] for f in hd['intel'])}"
                       f"{' — πιθανή μόλυνση από botnet!' if c2 else ''}", t, key=("intel", dst), cooldown=600)
        elif hs is not None and hs["intel"] and ip_kind(dst) == "local":
            self.alert("Κίνηση από κακόβουλη IP", "med", src, dst,
                       f"Πακέτα από IP που υπάρχει στη λίστα {', '.join(f['name'] for f in hs['intel'])}",
                       t, key=("intel", src), cooldown=600)

    def _tor_use(self, src, dst, dp, t):
        """Μια συσκευή του σπιτιού μιλάει με το δίκτυο Tor. Στο Mac σου με Tor Browser: αθώο. Σε IoT: πολύ ύποπτο."""
        mine = src in self.me
        benign = None
        if mine and (self.mode != "live" or local_tor_running()):
            benign = "Είναι το δικό σου Tor (Tor Browser / tor) στο Mac. Αναμενόμενο."
        h = self.hosts.get(src) or {}
        names = " ".join(sorted(h.get("names") or ())).lower()
        import iotcheck
        iot = bool(iotcheck.kind_of(h.get("mac"), names.split())) or any(w in names for w in ("tasmota", "shelly", "camera", "plug"))
        sev = "low" if mine else "high" if iot else "med"
        self.alert("Tor από συσκευή του δικτύου", sev, src, dst,
                   f"Η {src}{' (IoT συσκευή!)' if iot else ''} συνδέεται σε κόμβο Tor {dst}{':' + str(dp) if dp else ''}. "
                   + ("" if mine else "Αν δεν τρέχεις Tor εκεί, κάτι κρύβει την κίνησή του — έτσι μιλάει συχνά το malware με τον «αφέντη» του (C2)."),
                   t, key=("tor", src), cooldown=1800, benign=benign)

    # --- νέες συσκευές ---
    def _mac_seen(self, ip, mac, t):
        if ip in self.lab_ips:
            return
        if not mac or mac in self.seen_macs or mac == "ff:ff:ff:ff:ff:ff":
            return
        self.seen_macs.add(mac)
        try:
            self.history.device_seen(mac, ip, t)
        except Exception as e:
            log("history error:", e)
        if mac in self.known_macs:
            return
        self.known_macs.add(mac)
        warm = self._th("new_device")["warmup"]
        if ip in self.me or ip == self.gateway or ip_kind(ip) != "local":
            return
        if self.had_devices or (self.first_t is not None and t - self.first_t >= warm):
            self.alert("Νέα συσκευή", "low", ip, self.gateway or "LAN",
                       f"Πρώτη φορά στο δίκτυο: {ip} με MAC {mac}"
                       f"{' (τυχαία MAC — μάλλον κινητό)' if random_mac(mac) else ''}. Την αναγνωρίζεις;",
                       t, key=("newdev", mac), cooldown=10 ** 9)

    def _arp(self, P, t):
        a = P["arp"]
        op, psrc, pdst, hw = a["op"], a["psrc"], a["pdst"], norm_mac(a["hwsrc"])
        if op == 1 and psrc not in self.me and psrc != self.gateway and psrc != pdst:
            th = self._th("arp_sweep")
            dq = self.w_sweep.add(("arp", psrc), pdst, t)
            n = len({i for ti, i in dq if ti >= t - th["window"]})
            if n >= th["count"]:
                self.alert("Network sweep (ARP)", "med", psrc, pdst,
                           f"ARP ερωτήσεις για {n} IP σε {th['window']}s — κάποιος σκανάρει το LAN", t)
        if psrc and psrc != "0.0.0.0" and hw and hw not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            old = self.arp_table.get(psrc)
            trusted = self.arp_first.setdefault(psrc, old or hw)
            # Αγνόησε: μηδενική MAC (κάρτα που κοιμάται/ξυπνά) και τη ΔΙΚΗ σου IP (δεν είναι MITM — εσύ στέλνεις το ARP σου)
            if old and old != hw and hw != trusted and psrc not in self.me:
                gw = psrc == self.gateway
                others = [i for i in self.mac_ips.get(hw, ()) if i != psrc and self.arp_first.get(i) == hw]
                actor = others[0] if others else psrc
                self.alert("ARP spoofing" + (" (ROUTER)" if gw else ""), "high", actor, psrc,
                           f"Η IP {psrc}{' του router' if gw else ''} άλλαξε MAC {trusted} → {hw}"
                           f"{' (ανήκει στη ' + actor + ')' if others else ''}. Πιθανό Man‑in‑the‑Middle.",
                           t, key=("arp", psrc, hw))
            self.arp_table[psrc] = hw
            seen = self.ip_mac_seen.setdefault(psrc, {})
            seen[hw] = t
            if len(seen) > 8:
                del seen[min(seen, key=seen.get)]
            self.mac_ips[hw].add(psrc)
            h = self.hosts.get(psrc)
            if h is not None:
                h["mac"] = hw
            if hw == trusted:
                self._mac_seen(psrc, hw, t)
        if op == 2:
            th = self._th("arp_flood")
            dq = self.w_arpflood.add(hw, 1, t)
            if len(dq) >= th["count"]:
                self.alert("ARP flood", "med", psrc, pdst, f"{len(dq)} ARP replies σε {th['window']}s από {hw}", t)

    # ---------- periodic flush to browsers ----------
    def snapshot(self):
        with self.lock:
            return {"type": "snapshot", "mode": self.mode, "iface": self.iface,
                    "me": sorted(self.me), "gw": self.gateway, "home": self.home,
                    "hosts": [self.ser(h) for h in self.hosts.values()],
                    "alerts": list(self.alerts)[:200], "stats": self._stats(1), "features": self.features(),
                    "feed": self.feed, "ctf": self.ctf_level,
                    "host": {**host_info(), "app_switch": bool(getattr(self, "app_ctl", None)),
                             "npcap_get": bool(getattr(self, "npcap", None))}}

    def status(self):
        """Μικρή περίληψη για την εφαρμογή του Mac (εικονίδιο στη γραμμή μενού)."""
        with self.lock:
            al = [a for a in self.alerts if not a.get("lab") and not a.get("benign") and not a.get("selftest")]
            by = collections.Counter(a["sev"] for a in al)
            last = al[0] if al else None
            out = {"mode": self.mode, "feed": self.feed, "iface": self.iface, "alerts": len(al),
                   "high": by.get("high", 0), "med": by.get("med", 0), "low": by.get("low", 0),
                   "hosts": len(self.hosts), "pkts": self.total_pkts, "bytes": self.total_bytes,
                   "lan": sum(1 for h in self.hosts.values() if h.get("kind") == "local"),
                   "last": {k: last[k] for k in ("id", "t", "type", "sev", "actor", "target", "detail")} if last else None,
                   "recent": [{k: a.get(k) for k in ("id", "t", "type", "sev", "actor", "target", "maint")} for a in al[:6]]}
        try:
            hs = self.health.status()["targets"] if self.health else []
            out["homelab"] = {"up": sum(1 for x in hs if x.get("up")), "total": len(hs),
                              "down": [x["name"] for x in hs if x.get("up") is False][:4]}
        except Exception:
            out["homelab"] = None
        mt = getattr(self, "maint", None)
        try:
            ms = mt.status() if mt else None
            out["maint"] = {"active": bool(ms["active"]), "name": ms["active"],
                            "until": max([m["until"] for m in ms["mutes"]] or [0])} if ms else None
        except Exception:
            out["maint"] = None
        r = self.wifi.result if self.wifi else None
        out["wifi"] = {"level": r["level"], "verdict": r["verdict"], "score": r["score"],
                       "ssid": (r.get("wifi") or {}).get("ssid")} if r else None
        out["wifi_running"] = bool(self.wifi and self.wifi.running)
        return out

    def _stats(self, dt):
        return {"pps": round(self.win_pkts / dt, 1), "bps": round(self.win_bytes / dt),
                "pkts": self.total_pkts, "bytes": self.total_bytes, "hosts": len(self.hosts),
                "alerts": self.alert_seq, "protos": dict(self.protos.most_common(10)),
                "uptime": round(time.time() - self.started)}

    def flusher(self):
        last_stats = time.time()
        tick = 0
        while True:
            time.sleep(0.2)
            tick += 1
            now = time.time()
            with self.lock:
                items, self.pending = self.pending, []
                if len(items) > 160:
                    keep = [i for i in items if i["x"]][:60]
                    items = sorted(keep + random.sample(items, 160 - len(keep)), key=lambda i: i["t"])
                newh = [self.ser(self.hosts[i]) for i in self.new_hosts if i in self.hosts]
                self.new_hosts.clear()
                msg = {"type": "pkts", "items": items}
                if newh:
                    msg["hosts"] = newh
                if now - last_stats >= 1:
                    msg["stats"] = self._stats(now - last_stats)
                    self.win_pkts = self.win_bytes = 0
                    last_stats = now
                    dirty = [self.ser(self.hosts[i]) for i in list(self.dirty)[:400] if i in self.hosts]
                    self.dirty.clear()
                    if dirty:
                        msg["hosts"] = msg.get("hosts", []) + dirty
                if tick % 150 == 0:
                    for w in self.windows:
                        w.gc(self.last_t)
                    maxi = self._th("beaconing")["max_interval"] * 2
                    for k in [k for k, dq in self.beacons.items() if dq and dq[-1] < self.last_t - maxi]:
                        del self.beacons[k]
                minute = int(now // 60)
                if minute != self.cur_minute:
                    mp, mb, self.min_pkts, self.min_bytes = self.min_pkts, self.min_bytes, 0, 0
                    self.cur_minute = minute
                    try:
                        self.history.add_traffic(minute - 1, mp, mb)
                    except Exception as e:
                        log("history error:", e)
            if items or "hosts" in msg or "stats" in msg:
                self.publish(msg)
