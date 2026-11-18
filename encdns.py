"""🔐 Ποιος παρακάμπτει το DNS σου: κρυπτογραφημένο DNS (DoH / DoT / DoQ) ή απευθείας DNS σε εξωτερικό server.

Το Pi-hole ή το φίλτρο του router βλέπει μόνο ό,τι ρωτιέται σε ΑΥΤΟ. Μια συσκευή που μιλά DNS-over-HTTPS με
το dns.google ή DNS-over-TLS (θύρα 853) με το Cloudflare περνά δίπλα από το φίλτρο — και δεν βλέπεις τι ψάχνει.
Εδώ μετράμε, ανά συσκευή του LAN, πόσες συνδέσεις τέτοιου τύπου βλέπουμε και προς ποιον πάροχο.

Κανόνες (`classify`): TCP/853 → DoT· UDP/853 → DoQ· TLS SNI γνωστού ονόματος DoH → DoH· θύρα 443 (TCP ή UDP/HTTP3)
προς γνωστή IP δημόσιου resolver → DoH· απλό DNS (53) προς ΔΗΜΟΣΙΑ IP που δεν είναι στο `local_dns` → DNS-ext.

config.yaml:
encrypted_dns:
  enabled: true
  local_dns: []      # IP του router / Pi-hole (αν μείνει κενό, μπαίνει το gateway)
  alert: true
  allow: []          # IP συσκευών που αγνοούμε
"""
import ipaddress
import random
import threading
import time

ALERT_TYPE = "Συσκευή παρακάμπτει το DNS σου"
ALERT_COOLDOWN = 6 * 3600
MAX_DEVICES = 500
MAX_SAMPLES = 8
FLOW_IDLE = 300
MAX_FLOWS = 20000
METHODS = ("DoH", "DoT", "DoQ", "DNS-ext")
PORTS = (53, 443, 853)
CANARY = "use-application-dns.net"

# όνομα DoH → πάροχος
DOH_HOSTS = {
    "dns.google": "Google", "dns.google.com": "Google", "dns64.dns.google": "Google",
    "cloudflare-dns.com": "Cloudflare", "mozilla.cloudflare-dns.com": "Cloudflare",
    "chrome.cloudflare-dns.com": "Cloudflare", "one.one.one.one": "Cloudflare",
    "1dot1dot1dot1.cloudflare-dns.com": "Cloudflare", "security.cloudflare-dns.com": "Cloudflare",
    "family.cloudflare-dns.com": "Cloudflare", "dns.cloudflare.com": "Cloudflare",
    "dns.quad9.net": "Quad9", "dns9.quad9.net": "Quad9", "dns10.quad9.net": "Quad9", "dns11.quad9.net": "Quad9",
    "doh.opendns.com": "OpenDNS", "doh.familyshield.opendns.com": "OpenDNS", "dns.umbrella.com": "OpenDNS",
    "dns.nextdns.io": "NextDNS", "firefox.dns.nextdns.io": "NextDNS", "chromium.dns.nextdns.io": "NextDNS",
    "doh.cleanbrowsing.org": "CleanBrowsing",
    "dns.adguard-dns.com": "AdGuard", "dns.adguard.com": "AdGuard", "unfiltered.adguard-dns.com": "AdGuard",
    "family.adguard-dns.com": "AdGuard", "dns-unfiltered.adguard.com": "AdGuard", "dns-family.adguard.com": "AdGuard",
    "doh.mullvad.net": "Mullvad", "dns.mullvad.net": "Mullvad", "base.dns.mullvad.net": "Mullvad",
    "adblock.dns.mullvad.net": "Mullvad", "extended.dns.mullvad.net": "Mullvad", "all.dns.mullvad.net": "Mullvad",
    "freedns.controld.com": "Control D", "dns.controld.com": "Control D",
    "doh.dns.sb": "DNS.SB", "dns.alidns.com": "AliDNS", "doh.pub": "DNSPod", "dns.pub": "DNSPod",
    "dns.twnic.tw": "TWNIC", "doh.libredns.gr": "LibreDNS", "dns.digitale-gesellschaft.ch": "Digitale Gesellschaft",
    "doh.applied-privacy.net": "Applied Privacy", "dns.switch.ch": "SWITCH", "doh.ffmuc.net": "FFMUC",
    "dns0.eu": "dns0.eu", "zero.dns0.eu": "dns0.eu", "kids.dns0.eu": "dns0.eu",
    "doh.xfinity.com": "Comcast", "dns.comss.one": "Comss", "doh-jp.blahdns.com": "BlahDNS",
    "dns.brahma.world": "Brahma", "doh.crypto.sx": "crypto.sx", "dns.rabbitdns.org": "RabbitDNS",
}
# επίθημα → πάροχος (π.χ. abc123.dns.nextdns.io, xyz.dns.controld.com)
DOH_SUFFIX = {"dns.nextdns.io": "NextDNS", "dns.controld.com": "Control D", "cloudflare-gateway.com": "Cloudflare",
              "dns.adguard-dns.com": "AdGuard", "dns0.eu": "dns0.eu"}

# IP/δίκτυο δημόσιου resolver → πάροχος
RESOLVER_NETS = {
    "Cloudflare": ["1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
                   "2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112", "2606:4700:4700::1002",
                   "2606:4700:4700::1113", "2606:4700:4700::1003", "2606:4700:4700::64", "2606:4700:4700::6400"],
    "Google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
               "2001:4860:4860::64", "2001:4860:4860::6464"],
    "Quad9": ["9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
              "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11", "2620:fe::fe:11"],
    "OpenDNS": ["208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",
                "2620:119:35::35", "2620:119:53::53", "2620:119:35::123", "2620:119:53::123"],
    "AdGuard": ["94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16", "94.140.14.140", "94.140.14.141",
                "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff", "2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff",
                "2a10:50c0::1:ff", "2a10:50c0::2:ff"],
    "NextDNS": ["45.90.28.0/24", "45.90.30.0/24", "2a07:a8c0::/33", "2a07:a8c1::/33"],
    "Mullvad": ["194.242.2.0/24", "2a07:e340::/32"],
    "CleanBrowsing": ["185.228.168.0/24", "185.228.169.0/24", "2a0d:2a00:1::/48", "2a0d:2a00:2::/48"],
    "Control D": ["76.76.2.0/24", "76.76.10.0/24", "2606:1a40::/32"],
    "DNS.SB": ["185.222.222.222", "45.11.45.11", "2a09::", "2a11::"],
    "AliDNS": ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
    "DNSPod": ["1.12.12.12", "120.53.53.53", "119.29.29.29"],
    "Level3": ["4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6"],
    "dns0.eu": ["193.110.81.0", "185.253.5.0", "2a0f:fc80::", "2a0f:fc81::"],
}


def _build_nets():
    exact, nets = {}, []
    for prov, items in RESOLVER_NETS.items():
        for x in items:
            if "/" in x:
                nets.append((ipaddress.ip_network(x), prov))
            else:
                exact[str(ipaddress.ip_address(x))] = prov
    return exact, nets


_EXACT, _NETS = _build_nets()


def _addr(ip):
    try:
        return ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return None


def resolver_provider(ip):
    """Αν η IP είναι γνωστού δημόσιου resolver → όνομα παρόχου, αλλιώς None."""
    a = _addr(ip)
    if a is None:
        return None
    p = _EXACT.get(str(a))
    if p:
        return p
    for n, prov in _NETS:
        if a.version == n.version and a in n:
            return prov
    return None


def doh_provider(sni):
    """TLS SNI → πάροχος DoH (ακριβές όνομα ή γνωστό επίθημα), αλλιώς None."""
    if not sni:
        return None
    n = str(sni).lower().rstrip(".")
    p = DOH_HOSTS.get(n)
    if p:
        return p
    for suf, prov in DOH_SUFFIX.items():
        if n.endswith("." + suf):
            return prov
    return None


_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_private(ip):
    """Συσκευή του LAN: ιδιωτική (RFC1918/ULA/CGNAT) διεύθυνση, όχι loopback/multicast."""
    a = _addr(ip)
    if a is None or a.is_loopback or a.is_multicast or a.is_unspecified:
        return False
    return a.is_private or a.is_link_local or (a.version == 4 and a in _CGNAT)


def is_public(ip):
    a = _addr(ip)
    return bool(a) and a.is_global and not a.is_multicast


def classify(P, local_dns=()):
    """Πακέτο (src, dst, proto, sp, dp, sni, dns_q) → None ή {"method", "provider"[, "http3"]}.

    Κοιτάμε μόνο την κατεύθυνση συσκευή → resolver (θύρα προορισμού) και μόνο προορισμούς στο Internet
    (ένας DoT/DNS server μέσα στο LAN είναι δικός σου). Ό,τι είναι στο `local_dns` αγνοείται.
    """
    dst, dp, proto = P.get("dst"), P.get("dp"), (P.get("proto") or "").upper()
    if dp not in PORTS or proto not in ("TCP", "UDP") or not dst:
        return None
    if dst in local_dns or not is_public(dst):
        return None
    sni = P.get("sni")
    if dp == 853:
        prov = resolver_provider(dst) or doh_provider(sni) or "Άγνωστος"
        return {"method": "DoT" if proto == "TCP" else "DoQ", "provider": prov}
    if dp == 443:
        prov = doh_provider(sni)
        if prov:
            return {"method": "DoH", "provider": prov}
        prov = resolver_provider(dst)
        if prov and not sni:
            r = {"method": "DoH", "provider": prov}
            if proto == "UDP":
                r["http3"] = True
            return r
        return None
    # dp == 53: απλό DNS σε server στο Internet
    return {"method": "DNS-ext", "provider": resolver_provider(dst) or "Άλλος"}


def canary_note():
    return (f"Το «canary» domain {CANARY}: αν ο DNS σου (Pi-hole/router) απαντά σε αυτό με NXDOMAIN, ο Firefox "
            "καταλαβαίνει ότι το δίκτυο φιλτράρει το DNS και ΔΕΝ ενεργοποιεί αυτόματα το DNS-over-HTTPS. "
            f"Στο Pi-hole: πρόσθεσε το {CANARY} στη μαύρη λίστα (οι νεότερες εκδόσεις το κάνουν ήδη). "
            "Προσοχή: ισχύει μόνο για την αυτόματη ενεργοποίηση του Firefox — αν ο χρήστης ή μια εφαρμογή/συσκευή "
            "(Chrome «Secure DNS», Android «Ιδιωτικό DNS», smart TV) έχει ρυθμίσει DoH/DoT ρητά, το canary αγνοείται.")


def _alert_detail(ip, method, prov, sample):
    how = {"DoH": f"κρυπτογραφημένο DNS-over-HTTPS (DoH) προς {prov}",
           "DoT": f"κρυπτογραφημένο DNS-over-TLS (DoT, θύρα 853) προς {prov}",
           "DoQ": f"κρυπτογραφημένο DNS-over-QUIC (DoQ, UDP 853) προς {prov}",
           "DNS-ext": f"απλό DNS (θύρα 53) απευθείας σε εξωτερικό server ({prov})"}[method]
    block = {"DoH": "Το DoH μοιάζει με κανονικό HTTPS· μπλόκαρέ το στο firewall με λίστες IP γνωστών resolvers "
                    "(π.χ. dibdot/DoH-IP-blocklists) και στο Pi-hole με λίστες ονομάτων DoH. Για τον Firefox απάντα "
                    f"NXDOMAIN στο {CANARY}.",
             "DoT": "Μπλόκαρε στο firewall/router την έξοδο TCP 853 από το LAN — η συσκευή συνήθως γυρνά στο DNS του δικτύου.",
             "DoQ": "Μπλόκαρε στο firewall/router την έξοδο UDP 853 (και TCP 853 για DoT) από το LAN.",
             "DNS-ext": "Στον router: μπλόκαρε την έξοδο UDP/TCP 53 προς το Internet για όλους εκτός από το Pi-hole/router, "
                        "ή κάνε ανακατεύθυνση (DNAT) κάθε θύρας 53 στο Pi-hole."}[method]
    return (f"Η συσκευή {ip} χρησιμοποιεί {how}" + (f" (π.χ. {sample})" if sample else "") + ". Έτσι παρακάμπτει το "
            "Pi-hole / το φίλτρο DNS του router: οι αποκλεισμοί σου δεν ισχύουν και δεν βλέπεις ποια ονόματα ψάχνει. "
            + block)


class EncDns:
    def __init__(self, state=None, cfg=None, sim=False):
        cfg = cfg or {}
        self.state, self.sim = state, sim
        self.enabled = bool(cfg.get("enabled", True))
        self.alerts_on = bool(cfg.get("alert", True))
        self.local_dns = set(str(x) for x in (cfg.get("local_dns") or []) if x)
        self.allow = set(str(x) for x in (cfg.get("allow") or []) if x)
        self.lock = threading.Lock()
        self.devices = {}
        self.flows = {}
        self.error = None
        self._cd = {}
        self.rnd = random.Random(11)
        if sim:
            if not self.local_dns:
                self.local_dns = {"192.168.1.1"}
            self._seed_sim()

    # ── κάθε πακέτο ──
    def observe(self, P, t=None):
        """Φτηνό: καλείται για κάθε πακέτο. Μετρά μόνο συσκευή του LAN (src ιδιωτική) → Internet (dst δημόσια)."""
        if not self.enabled:
            return None
        dp = P.get("dp")
        if dp not in PORTS:
            return None
        src = P.get("src")
        if not src or src in self.allow or not is_private(src):
            return None
        r = classify(P, self.local_dns)
        if r is None:
            return None
        t = t if t is not None else (P.get("t") or time.time())
        q = P.get("dns_q")
        sample = P.get("sni") or ((q[0] if isinstance(q, (tuple, list)) and q else None)) or P.get("dst")
        fk = (src, P.get("dst"), P.get("proto"), P.get("sp"), dp)
        fire = None
        with self.lock:
            last = self.flows.get(fk)
            self.flows[fk] = t
            if len(self.flows) > MAX_FLOWS:
                self._prune_flows(t)
            new_flow = last is None or t - last > FLOW_IDLE or (dp == 53 and q)
            d = self.devices.get(src)
            if d is None:
                if len(self.devices) >= MAX_DEVICES:
                    old = min(self.devices, key=lambda k: self.devices[k]["last"])
                    del self.devices[old]
                d = self.devices[src] = {"ip": src, "methods": {}, "providers": {}, "first": t, "last": t, "samples": []}
            d["last"] = max(d["last"], t)
            d["first"] = min(d["first"], t)
            if sample and sample not in d["samples"]:
                d["samples"].append(sample)
                del d["samples"][:-MAX_SAMPLES]
            if new_flow or r["method"] not in d["methods"]:
                d["methods"][r["method"]] = d["methods"].get(r["method"], 0) + 1
                d["providers"][r["provider"]] = d["providers"].get(r["provider"], 0) + 1
            if self.alerts_on:
                k = (src, r["method"])
                if k not in self._cd or t - self._cd[k] >= ALERT_COOLDOWN:
                    self._cd[k] = t
                    fire = (src, r, sample)
        if fire and self.state is not None:
            ip, r2, smp = fire
            try:
                self.state.alert(ALERT_TYPE, "low", ip, r2["provider"], _alert_detail(ip, r2["method"], r2["provider"], smp),
                                 t, key=(ip, r2["method"]), cooldown=ALERT_COOLDOWN)
            except Exception:
                pass
        return r

    def _prune_flows(self, now):
        cut = now - FLOW_IDLE
        self.flows = {k: v for k, v in self.flows.items() if v >= cut}
        if len(self.flows) > MAX_FLOWS:
            self.flows.clear()

    def set_local_dns(self, ips):
        """Για τον integrator: π.χ. το gateway όταν γίνει γνωστό."""
        with self.lock:
            self.local_dns = set(str(x) for x in (ips or []) if x)

    # ── demo ──
    SIM = [  # (συσκευή, proto, dst, dp, sni, dns_q, πόσες φορές)
        ("192.168.1.31", "TCP", "8.8.8.8", 443, "dns.google", None, 46),                   # smart TV, DoH Google
        ("192.168.1.24", "TCP", "104.16.248.249", 443, "mozilla.cloudflare-dns.com", None, 23),  # Firefox, DoH Cloudflare
        ("192.168.1.37", "TCP", "8.8.4.4", 853, "dns.google", None, 31),                   # Android «Ιδιωτικό DNS»
        ("192.168.1.52", "UDP", "8.8.8.8", 53, None, ("a2.tuyaeu.com",), 118),             # έξυπνη πρίζα, σκληροκωδικοποιημένο DNS
        ("192.168.1.52", "UDP", "8.8.8.8", 53, None, ("m2.tuyaeu.com",), 40),
        ("192.168.1.44", "UDP", "94.140.14.14", 853, None, None, 9),                       # laptop, DoQ AdGuard
    ]

    def _sim_packet(self, row, sp):
        src, proto, dst, dp, sni, q, _ = row
        return {"src": src, "dst": dst, "proto": proto, "sp": sp, "dp": dp, "sni": sni, "dns_q": q}

    def _seed_sim(self):
        now = time.time()
        for row in self.SIM:
            n = row[6]
            for i in range(n):
                t = now - 3 * 86400 * (1 - i / n) - self.rnd.uniform(0, 600)
                self.observe(self._sim_packet(row, 40000 + self.rnd.randrange(20000)), t)

    def _sim_tick(self):
        row = self.rnd.choice(self.SIM)
        self.observe(self._sim_packet(row, 40000 + self.rnd.randrange(20000)), time.time())

    # ── κατάσταση ──
    def status(self):
        with self.lock:
            devs = sorted(({"ip": d["ip"], "methods": dict(d["methods"]), "providers": dict(d["providers"]),
                            "first": round(d["first"], 1), "last": round(d["last"], 1), "samples": list(d["samples"])}
                           for d in self.devices.values()), key=lambda d: -d["last"])
        totals = {m: 0 for m in METHODS}
        for d in devs:
            for m, n in d["methods"].items():
                totals[m] = totals.get(m, 0) + n
        return {"enabled": self.enabled, "demo": self.sim, "error": self.error, "alert": self.alerts_on,
                "local_dns": sorted(self.local_dns), "allow": sorted(self.allow), "devices": devs, "totals": totals,
                "providers_list": providers_list(), "canary": CANARY, "canary_note": canary_note()}

    def run_forever(self):
        while True:
            try:
                if self.sim:
                    self._sim_tick()
                else:
                    with self.lock:
                        self._prune_flows(time.time())
            except Exception as e:
                self.error = str(e)[:200]
            time.sleep(20 if self.sim else 60)


def providers_list():
    """Η γνωστή λίστα για το UI: [{provider, hosts, ips}] αλφαβητικά."""
    out = {}
    for h, p in DOH_HOSTS.items():
        out.setdefault(p, {"provider": p, "hosts": [], "ips": []})["hosts"].append(h)
    for s, p in DOH_SUFFIX.items():
        out.setdefault(p, {"provider": p, "hosts": [], "ips": []})["hosts"].append("*." + s)
    for p, ips in RESOLVER_NETS.items():
        out.setdefault(p, {"provider": p, "hosts": [], "ips": []})["ips"].extend(ips)
    return sorted(out.values(), key=lambda x: x["provider"].lower())
