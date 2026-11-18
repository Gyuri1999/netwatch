"""🧱 Έλεγχος διαχωρισμού (segmentation test): είναι πράγματι απομονωμένες οι ζώνες (VLAN/subnets) που πρέπει;

Από το σημείο όπου τρέχει το NetWatch δοκιμάζει, με απλές συνδέσεις TCP (connect, χωρίς δεδομένα), αν φτάνει σε
θύρες διαχείρισης/πλευρικής κίνησης άλλων ζωνών και τις συγκρίνει με την πολιτική που δήλωσες:
  segmentation:
    zones:  {lan: "192.168.1.0/24", iot: "192.168.30.0/24", guest: {cidr: "192.168.20.0/24", vlan: 20}}
    policy: [{from: guest, to: lan, allow: false}, {from: iot, to: internet, allow: true}]
    ports:  [22, 80, 443, 445]          # προαιρετικά (αλλιώς PORTS)
    targets: {lan: ["192.168.1.17"]}    # προαιρετικά: συγκεκριμένες IP ανά ζώνη
    source: guest                       # προαιρετικά: αλλιώς η ζώνη που περιέχει την IP αυτού του μηχανήματος
    interval_hours: 12                  # αυτόματος έλεγχος (0 = μόνο χειροκίνητα)

Αμυντικό και μόνο-ανάγνωση: μόνο ιδιωτικά δίκτυα (RFC1918 / IPv6 ULA fc00::/7), το πολύ 32 hosts ανά ζώνη,
timeout 0.4″, ≤ 32 νήματα, συνολικό όριο χρόνου, το πολύ ένας έλεγχος ανά 30″. Το «internet» ΔΕΝ δοκιμάζεται
(ποτέ συνδέσεις σε δημόσιες διευθύνσεις) — οι κανόνες προς internet μένουν «untested».

Ελέγχονται μόνο οι κανόνες με `from` = ζώνη πηγής. Για τις άλλες ζώνες τρέχεις NetWatch μέσα σε εκείνο το VLAN:
  python3 segcheck.py --config config.yaml --post https://<κεντρικό-netwatch>:8765 --token <agent-token> --cafile agent.crt
και το αποτέλεσμα στέλνεται στο POST /api/segcheck/report του κεντρικού (σε λειτουργία agent: token + HTTPS).

Ετυμηγορίες: ok | violation (deny αλλά κάτι απάντησε) | blocked (allow αλλά τίποτα δεν απάντησε — πληροφορία)
| untested (άλλη ζώνη πηγής, internet, χωρίς στόχους ή δεν έχει τρέξει ακόμα).
Παραβίαση → ειδοποίηση «Διαρροή διαχωρισμού VLAN» (MITRE T1021) μία φορά για κάθε κανόνα + σύνολο ανοιχτών θυρών.

Δίγλωσσα πεδία: πάντα ως ζευγάρια `*_el` / `*_en` (note_el/note_en, explain_el/explain_en). Οι εντολές του `fix`
είναι ουδέτερες (σχόλια στα αγγλικά).

API
---
SegCheck(state, cfg=None, sim=False, path=None, connect=None, clock=time.time)
  .view()            → {config_ok, errors, source_zone, source_ip, zones, rules, matrix, last_run, running, demo, …}
  .run()             → {ok, running} | {ok: False, error, retry_in}
  .report(payload)   → {ok, rules} | {error}       (αποτέλεσμα από NetWatch σε άλλη ζώνη)
  .violations()      → [{rule, from, to, source_ip, open, sensitive}]  (για το pentest_report)
"""
import hashlib
import ipaddress
import json
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ALERT = "Διαρροή διαχωρισμού VLAN"
MITRE = {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement",
         "url": "https://attack.mitre.org/techniques/T1021/"}
PORTS = (22, 23, 80, 443, 445, 1883, 3389, 5000, 5001, 5900, 8006, 8080, 8443, 9100)
SERVICE = {22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 445: "SMB", 1883: "MQTT", 3389: "RDP",
           5000: "HTTP (NAS/DSM)", 5001: "HTTPS (NAS/DSM)", 5900: "VNC", 8006: "Proxmox VE", 8080: "HTTP-alt",
           8443: "HTTPS-alt", 9100: "Printer (RAW)", 21: "FTP", 53: "DNS", 139: "NetBIOS", 554: "RTSP",
           3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8123: "Home Assistant", 161: "SNMP"}
INTERNET = "internet"
NAME_RE = re.compile(r"^[a-z0-9_-]{1,20}$")
MAX_HOSTS = 32
MAX_PORTS = 64
TIMEOUT = 0.4
THREADS = 32
BUDGET = 90.0
MIN_INTERVAL = 30
SENSITIVE_TO = {"lan", "mgmt"}
UNTRUSTED_FROM = {"guest", "iot"}
ULA = ipaddress.ip_network("fc00::/7")
VERDICTS = ("ok", "violation", "blocked", "untested")


# ───────── βοηθητικά (καθαρές συναρτήσεις) ─────────
def private_net(net):
    """True για RFC1918 / IPv6 ULA (όχι loopback, link-local, multicast, δημόσια)."""
    if net.version == 6:
        return net.subnet_of(ULA)
    return net.is_private and not (net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified) \
        and any(net.subnet_of(ipaddress.ip_network(n)) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def private_ip(ip):
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return private_net(ipaddress.ip_network(f"{a}/{a.max_prefixlen}"))


def tcp_connect(ip, port, timeout=TIMEOUT):
    """True αν ολοκληρωθεί το TCP handshake (κλείνει αμέσως, δεν στέλνει τίποτα)."""
    if not private_ip(ip):  # δεύτερη ασφάλεια: ποτέ δημόσια διεύθυνση
        return False
    try:
        with socket.create_connection((str(ip), int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def parse_config(cfg):
    """dict του config → {zones, policy, ports, targets, source, interval, errors}. Δεν σηκώνει εξαίρεση."""
    cfg = cfg if isinstance(cfg, dict) else {}
    errors, zones = [], {}
    raw = cfg.get("zones") or {}
    if not isinstance(raw, dict):
        errors.append("segmentation.zones: πρέπει να είναι λεξικό {όνομα: CIDR}.")
        raw = {}
    for name, val in list(raw.items())[:16]:
        name = str(name).strip().lower()
        cidr, vlan = (val.get("cidr"), val.get("vlan")) if isinstance(val, dict) else (val, None)
        if not NAME_RE.match(name) or name == INTERNET:
            errors.append(f"segmentation.zones: μη έγκυρο όνομα ζώνης «{name[:30]}» (a-z, 0-9, _ -· το «internet» είναι δεσμευμένο).")
            continue
        try:
            net = ipaddress.ip_network(str(cidr).strip(), strict=False)
        except ValueError:
            errors.append(f"segmentation.zones.{name}: μη έγκυρο δίκτυο «{str(cidr)[:50]}» (γράψε π.χ. 192.168.20.0/24).")
            continue
        if not private_net(net):
            errors.append(f"segmentation.zones.{name}: το «{net}» δεν είναι ιδιωτικό δίκτυο (RFC1918 / ULA fc00::/7) — "
                          "δημόσιες διευθύνσεις δεν δοκιμάζονται ποτέ.")
            continue
        if any(net.overlaps(z["net"]) for z in zones.values() if z["net"].version == net.version):
            errors.append(f"segmentation.zones.{name}: το {net} επικαλύπτεται με άλλη ζώνη.")
            continue
        vlan = int(vlan) if isinstance(vlan, int) and not isinstance(vlan, bool) and 0 < vlan < 4095 else None
        zones[name] = {"name": name, "net": net, "cidr": str(net), "vlan": vlan}
    policy, seen = [], set()
    rawp = cfg.get("policy")
    if rawp is None and len(zones) >= 2:  # προεπιλογή: lan/mgmt φτάνουν παντού, όλες οι άλλες απομονωμένες
        rawp = [{"from": a, "to": b, "allow": a in ("lan", "mgmt")} for a in zones for b in zones if a != b]
        rawp += [{"from": a, "to": INTERNET, "allow": True} for a in zones]
    for r in (rawp or [])[:100]:
        if not isinstance(r, dict):
            errors.append("segmentation.policy: κάθε κανόνας είναι {from, to, allow}.")
            continue
        a, b = str(r.get("from") or "").strip().lower(), str(r.get("to") or "").strip().lower()
        allow = r.get("allow")
        if a not in zones or (b not in zones and b != INTERNET) or a == b:
            errors.append(f"segmentation.policy: άγνωστη ζώνη στον κανόνα {a or '?'} → {b or '?'}.")
            continue
        if not isinstance(allow, bool):
            errors.append(f"segmentation.policy: {a} → {b}: το allow πρέπει να είναι true/false.")
            continue
        if (a, b) in seen:
            errors.append(f"segmentation.policy: διπλός κανόνας {a} → {b} (κρατήθηκε ο πρώτος).")
            continue
        seen.add((a, b))
        policy.append({"id": f"{a}>{b}", "from": a, "to": b, "allow": allow})
    ports = []
    for p in cfg.get("ports") or PORTS:
        if isinstance(p, int) and not isinstance(p, bool) and 0 < p < 65536:
            if p not in ports:
                ports.append(p)
        else:
            errors.append(f"segmentation.ports: μη έγκυρη θύρα «{str(p)[:12]}» (μόνο TCP 1–65535).")
    ports = ports[:MAX_PORTS] or list(PORTS)
    targets = {}
    for zname, ips in (cfg.get("targets") or {}).items() if isinstance(cfg.get("targets"), dict) else ():
        zname = str(zname).lower()
        if zname not in zones:
            errors.append(f"segmentation.targets: άγνωστη ζώνη «{zname[:20]}».")
            continue
        for ip in (ips if isinstance(ips, list) else [ips])[:MAX_HOSTS]:
            try:
                a = ipaddress.ip_address(str(ip).strip())
            except ValueError:
                errors.append(f"segmentation.targets.{zname}: μη έγκυρη IP «{str(ip)[:40]}».")
                continue
            if a not in zones[zname]["net"]:
                errors.append(f"segmentation.targets.{zname}: η {a} δεν ανήκει στο {zones[zname]['cidr']}.")
                continue
            targets.setdefault(zname, []).append(str(a))
    source = cfg.get("source")
    source = str(source).strip().lower() if source else None
    if source and source not in zones:
        errors.append(f"segmentation.source: άγνωστη ζώνη «{source[:20]}».")
        source = None
    iv = cfg.get("interval_hours", 12)
    iv = float(iv) if isinstance(iv, (int, float)) and not isinstance(iv, bool) and iv >= 0 else 12.0
    if cfg and not zones:
        errors.append("segmentation.zones: δεν δηλώθηκε καμία έγκυρη ζώνη.")
    return {"zones": zones, "policy": policy, "ports": ports, "targets": targets, "source": source,
            "interval": iv, "errors": errors}


def zone_of(ip, zones):
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    return next((z for z, d in zones.items() if d["net"].version == a.version and a in d["net"]), None)


def verdict(allow, tested, n_open):
    if not tested:
        return "untested"
    if allow:
        return "ok" if n_open else "blocked"
    return "violation" if n_open else "ok"


def gateway_of(net):
    return str(net.network_address + 1) if net.num_addresses > 2 else None


def fix_hints(src, dst, open_list=()):
    """Εντολές διόρθωσης για MikroTik / Cisco IOS / OpenWrt (src, dst: ζώνες με net/vlan)."""
    s, d = src["net"], dst["net"]
    gws = sorted({o["ip"] for o in open_list if o["ip"] == gateway_of(d)})
    mk = [f'/ip firewall filter add chain=forward src-address={s} dst-address={d} action=drop '
          f'comment="NetWatch: {src["name"]} -> {dst["name"]}" place-before=0']
    for g in gws:  # η IP του ίδιου του router σε άλλη ζώνη → chain=input
        mk.append(f'/ip firewall filter add chain=input src-address={s} dst-address={g} action=drop '
                  f'comment="NetWatch: {src["name"]} -> router {g}" place-before=0')
    if s.version == 4 and d.version == 4:
        acl = f"SEG-{src['name'].upper()}-IN"
        cs = [f"ip access-list extended {acl}",
              f" deny ip {s.network_address} {s.hostmask} {d.network_address} {d.hostmask}",
              " permit ip any any",
              f"interface Vlan{src['vlan'] or '<' + src['name'] + '-vlan-id>'}",
              f" ip access-group {acl} in"]
    else:
        acl = f"SEG-{src['name'].upper()}-IN6"
        cs = [f"ipv6 access-list {acl}", f" deny ipv6 {s} {d}", " permit ipv6 any any",
              f"interface Vlan{src['vlan'] or '<' + src['name'] + '-vlan-id>'}", f" ipv6 traffic-filter {acl} in"]
    ow = ["# /etc/config/firewall: remove any 'config forwarding' with "
          f"src '{src['name']}' dest '{dst['name']}', then:",
          "uci add firewall rule",
          f"uci set firewall.@rule[-1].name='NetWatch-block-{src['name']}-{dst['name']}'",
          f"uci set firewall.@rule[-1].src='{src['name']}'",
          f"uci set firewall.@rule[-1].dest='{dst['name']}'",
          "uci set firewall.@rule[-1].proto='all'",
          "uci set firewall.@rule[-1].target='REJECT'"]
    if gws:
        ow += [f"uci set firewall.@zone[<{src['name']}-zone-index>].input='REJECT'   "
               "# keep DHCP/DNS allow rules for this zone"]
    ow += ["uci commit firewall && /etc/init.d/firewall restart"]
    return {"mikrotik": "\n".join(mk), "cisco": "\n".join(cs), "openwrt": "\n".join(ow)}


def _svc(p):
    return SERVICE.get(p, f"tcp/{p}")


class SegCheck:
    def __init__(self, state, cfg=None, sim=False, path=None, connect=None, clock=time.time):
        self.st, self.sim, self.clock = state, sim, clock
        self.path = None if sim else path
        self.connect = connect or (self._demo_connect if sim else tcp_connect)
        self.lock = threading.RLock()
        self.on_save = None
        self.c = parse_config(DEMO_CFG if sim else cfg)
        self.errors = self.c["errors"]
        self.zones = self.c["zones"]
        self.result = None       # {t, finished, source_zone, source_ip, rules: {id: {...}}, partial}
        self.remote = {}         # ζώνη πηγής → αποτέλεσμα από NetWatch σε εκείνη τη ζώνη
        self.fired = {}          # rule id → υπογραφή του συνόλου ανοιχτών θυρών για την οποία στάλθηκε ειδοποίηση
        self.running = False
        self.last_start = 0.0
        self.wake = threading.Event()
        if self.path:
            self._load()
        if sim:  # demo: αποτέλεσμα αμέσως· η ειδοποίηση βγαίνει όταν πατηθεί «Έλεγχος» (το state ακόμα στήνεται)
            self.result = self.probe()

    # ───────── αποθήκευση ─────────
    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            return
        if isinstance(d.get("result"), dict):
            self.result = d["result"]
        self.remote = {k: v for k, v in (d.get("remote") or {}).items() if k in self.zones and isinstance(v, dict)}
        self.fired = {k: v for k, v in (d.get("fired") or {}).items() if isinstance(v, str)}

    def _save(self):
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"v": 1, "result": self.result, "remote": self.remote, "fired": self.fired}, f,
                          ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    # ───────── πηγή / στόχοι ─────────
    def _my_ips(self):
        if self.sim:
            return [DEMO_SOURCE_IP]
        return sorted(str(x) for x in (getattr(self.st, "me", None) or ()) if private_ip(x))

    def source(self):
        """(ζώνη, IP) από όπου τρέχει ο έλεγχος — ή (None, πρώτη IP)."""
        ips = self._my_ips()
        if self.c["source"]:
            z = self.c["source"]
            return z, next((ip for ip in ips if zone_of(ip, {z: self.zones[z]})), ips[0] if ips else None)
        for ip in ips:
            z = zone_of(ip, self.zones)
            if z:
                return z, ip
        return None, ips[0] if ips else None

    def _names(self):
        out = {}
        if self.sim:
            import whereis
            out.update({ip: name for ip, _m, name, *_ in whereis.DEMO_DEVICES})
            out.update(DEMO_NAMES)
        st = self.st
        if st is not None and getattr(st, "lock", None) is not None:
            try:
                with st.lock:
                    for ip, h in (getattr(st, "hosts", {}) or {}).items():
                        nm = sorted(h.get("names") or ()) or ([h["rdns"]] if h.get("rdns") else [])
                        if nm and ip not in out:
                            out[ip] = nm[0]
            except Exception:
                pass
        return out

    def targets(self, zname):
        z = self.zones[zname]
        if zname in self.c["targets"]:
            return self.c["targets"][zname][:MAX_HOSTS]
        mine = set(self._my_ips())
        found = set()
        st = self.st
        if st is not None and getattr(st, "lock", None) is not None:
            try:
                with st.lock:
                    found |= {ip for ip, h in (getattr(st, "hosts", {}) or {}).items() if h.get("kind") == "local"}
                    found |= set((getattr(st, "arp_table", {}) or {}).keys())
            except Exception:
                pass
        ips = []
        for ip in found:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if a.version == z["net"].version and a in z["net"] and a not in (z["net"].network_address,
                                                                              z["net"].broadcast_address):
                ips.append(a)
        ips = [str(a) for a in sorted(ips)]
        gw = gateway_of(z["net"])
        if gw:
            ips = [gw] + [x for x in ips if x != gw]
        return [x for x in ips if x not in mine and private_ip(x)][:MAX_HOSTS]

    # ───────── εκτέλεση ─────────
    def run(self):
        with self.lock:
            if self.running:
                return {"ok": True, "running": True}
            if not self.zones or not self.c["policy"]:
                return {"ok": False, "running": False, "error": "Δεν έχει ρυθμιστεί segmentation.zones / policy στο config.yaml."}
            now = self.clock()
            wait = MIN_INTERVAL - (now - self.last_start)
            if self.last_start and wait > 0:
                return {"ok": False, "running": False, "retry_in": int(wait) + 1,
                        "error": f"Περίμενε {int(wait) + 1}″ πριν τον επόμενο έλεγχο."}
            self.running, self.last_start = True, now
        if self.sim:
            self._execute(locked=True)
        else:
            threading.Thread(target=self._execute, kwargs={"locked": True}, daemon=True).start()
        return {"ok": True, "running": self.running}

    def wait(self, timeout=30):
        end = time.time() + timeout
        while self.running and time.time() < end:
            time.sleep(0.02)
        return not self.running

    def _execute(self, locked=False):
        try:
            res = self.probe()
            with self.lock:
                self.result = res
            self.check_alerts()
            with self.lock:
                self._save()
        finally:
            if locked:
                with self.lock:
                    self.running = False

    def probe(self):
        """Δοκιμάζει τους κανόνες της ζώνης πηγής. Επιστρέφει το «ωμό» αποτέλεσμα (χωρίς ετυμηγορίες)."""
        start = self.clock()
        src, sip = self.source()
        rules, jobs = {}, []
        for r in self.c["policy"]:
            if r["from"] != src or r["to"] == INTERNET:
                continue
            tg = self.targets(r["to"])
            rules[r["id"]] = {"hosts": tg, "open": [], "probes": 0}
            jobs += [(r["id"], ip, p) for ip in tg for p in self.c["ports"]]
        deadline = time.monotonic() + BUDGET
        partial = [False]

        def one(job):
            rid, ip, p = job
            if time.monotonic() > deadline:
                partial[0] = True
                return job, None
            if not private_ip(ip):
                return job, None
            try:
                return job, bool(self.connect(ip, p))
            except Exception:
                return job, False
        if jobs:
            with ThreadPoolExecutor(max_workers=min(THREADS, len(jobs))) as ex:
                for (rid, ip, p), ok in ex.map(one, jobs):
                    if ok is None:
                        continue
                    rules[rid]["probes"] += 1
                    if ok:
                        rules[rid]["open"].append({"ip": ip, "port": p})
        for r in rules.values():
            r["open"].sort(key=lambda o: (ipaddress.ip_address(o["ip"]), o["port"]))
        return {"t": start, "finished": self.clock(), "source_zone": src, "source_ip": sip, "rules": rules,
                "partial": partial[0]}

    def run_forever(self):
        iv = self.c["interval"]
        if self.sim or not iv or not self.zones or not self.c["policy"]:
            return
        time.sleep(300)
        while True:
            last = (self.result or {}).get("t") or 0
            if self.clock() - last >= iv * 3600:
                self.run()
            self.wake.wait(600)

    # ───────── αποτέλεσμα από άλλη ζώνη ─────────
    def report(self, payload):
        """Δέχεται αποτέλεσμα από NetWatch που τρέχει σε άλλη ζώνη (ίδιο σχήμα με το probe())."""
        if not isinstance(payload, dict):
            return {"error": "bad json"}
        src = str(payload.get("source_zone") or "").lower()
        sip = str(payload.get("source_ip") or "")
        if src not in self.zones:
            return {"error": "Άγνωστη ζώνη πηγής."}
        if zone_of(sip, {src: self.zones[src]}) != src:
            return {"error": f"Η source_ip πρέπει να ανήκει στο {self.zones[src]['cidr']}."}
        allowed = {r["id"]: r for r in self.c["policy"] if r["from"] == src and r["to"] != INTERNET}
        raw = payload.get("rules")
        if not isinstance(raw, dict) or len(raw) > 100:
            return {"error": "Το πεδίο rules πρέπει να είναι λεξικό {rule id: {hosts, open, probes}}."}
        rules = {}
        for rid, r in raw.items():
            if rid not in allowed or not isinstance(r, dict):
                continue
            net = self.zones[allowed[rid]["to"]]["net"]
            hosts = [str(h) for h in (r.get("hosts") or [])[:MAX_HOSTS] if zone_of(h, {"z": {"net": net}})]
            opn = []
            for o in (r.get("open") or [])[:MAX_HOSTS * MAX_PORTS]:
                if isinstance(o, dict) and zone_of(o.get("ip"), {"z": {"net": net}}) and isinstance(o.get("port"), int) \
                        and 0 < o["port"] < 65536 and private_ip(o["ip"]):
                    opn.append({"ip": str(ipaddress.ip_address(o["ip"])), "port": o["port"]})
            pr = r.get("probes")
            rules[rid] = {"hosts": hosts, "open": opn[:200],
                          "probes": pr if isinstance(pr, int) and 0 <= pr < 100000 else len(hosts)}
        if not rules:
            return {"error": "Κανένας κανόνας της πολιτικής δεν ταιριάζει με αυτή τη ζώνη πηγής."}
        now = self.clock()
        with self.lock:
            self.remote[src] = {"t": now, "finished": now, "source_zone": src, "source_ip": sip, "rules": rules,
                                "partial": bool(payload.get("partial")), "via": "report"}
        self.check_alerts()
        with self.lock:
            self._save()
        return {"ok": True, "rules": sorted(rules)}

    # ───────── προβολή ─────────
    def _results_for(self, rid, frm):
        res = self.result if (self.result or {}).get("source_zone") == frm else None
        rem = self.remote.get(frm)
        if rem and (not res or rem.get("t", 0) > res.get("t", 0)) and rid in rem["rules"]:
            return rem, rem["rules"][rid], "report"
        if res and rid in res["rules"]:
            return res, res["rules"][rid], "local"
        return None, None, None

    def rules_view(self):
        names = self._names()
        src_now, _ip = self.source()
        out = []
        with self.lock:
            for r in self.c["policy"]:
                rid, frm, to, allow = r["id"], r["from"], r["to"], r["allow"]
                run, rr, via = self._results_for(rid, frm)
                tested = bool(rr and rr["hosts"] and rr["probes"])
                opn = [{"ip": o["ip"], "port": o["port"], "service": _svc(o["port"]), "name": names.get(o["ip"])}
                       for o in (rr or {}).get("open") or ()]
                v = verdict(allow, tested, len(opn))
                row = {"id": rid, "from": frm, "to": to, "allow": allow, "expected": "allow" if allow else "deny",
                       "verdict": v, "open": opn, "tested": tested, "hosts": len((rr or {}).get("hosts") or ()),
                       "probes": (rr or {}).get("probes", 0), "via": via,
                       "source_ip": (run or {}).get("source_ip"), "t": (run or {}).get("finished"),
                       "sensitive": to in SENSITIVE_TO and frm in UNTRUSTED_FROM, "fix": None}
                row["note_el"], row["note_en"] = self._note(row, src_now, rr)
                if v == "violation":
                    row["fix"] = fix_hints(self.zones[frm], self.zones[to], opn)
                    row["explain_el"], row["explain_en"] = self._explain(row)
                out.append(row)
        return out

    def _note(self, row, src_now, rr):
        frm, to, v = row["from"], row["to"], row["verdict"]
        if to == INTERNET:
            return ("Το internet δεν δοκιμάζεται (ποτέ συνδέσεις σε δημόσιες διευθύνσεις). Έλεγξέ το με τη διάγνωση "
                    "«Φταίει το δίκτυο;» από συσκευή αυτής της ζώνης.",
                    "Internet is never probed (no connections to public addresses). Check it with the network "
                    "triage from a device in this zone.")
        if rr is None and frm != src_now:
            return (f"Το NetWatch δεν τρέχει στη ζώνη «{frm}». Για να δοκιμαστεί, τρέξε NetWatch (ή "
                    f"`python3 segcheck.py --post …`) σε μηχάνημα μέσα στο VLAN «{frm}».",
                    f"NetWatch is not running in zone '{frm}'. To test it, run NetWatch (or "
                    f"`python3 segcheck.py --post …`) on a machine inside the '{frm}' VLAN.")
        if rr is None:
            return ("Δεν έχει τρέξει ακόμα έλεγχος.", "Not run yet.")
        if not rr["hosts"]:
            return (f"Δεν υπάρχουν γνωστοί στόχοι στη ζώνη «{to}» — πρόσθεσε segmentation.targets.{to} στο config.yaml.",
                    f"No known targets in zone '{to}' — add segmentation.targets.{to} to config.yaml.")
        n = len(row["open"])
        if v == "violation":
            return (f"Ο κανόνας λέει «απαγορεύεται», αλλά από τη ζώνη «{frm}» απάντησαν {n} θύρες στη ζώνη «{to}».",
                    f"Policy says deny, but {n} port(s) in zone '{to}' answered from zone '{frm}'.")
        if v == "blocked":
            return (f"Ο κανόνας επιτρέπει {frm} → {to}, αλλά καμία από τις {row['probes']} δοκιμές δεν απάντησε "
                    "(ίσως απλώς δεν υπάρχουν υπηρεσίες σε αυτές τις θύρες).",
                    f"Policy allows {frm} → {to} but none of {row['probes']} probes answered "
                    "(maybe there are simply no services on those ports).")
        if row["allow"]:
            return (f"Επιτρέπεται και λειτουργεί ({n} θύρες απάντησαν).", f"Allowed and working ({n} port(s) answered).")
        return (f"Απομονωμένο σωστά: {row['probes']} δοκιμές σε {row['hosts']} hosts, καμία απάντηση.",
                f"Correctly isolated: {row['probes']} probes to {row['hosts']} hosts, none answered.")

    def _explain(self, row):
        frm, to = row["from"], row["to"]
        lst = ", ".join(f"{o['ip']}:{o['port']} ({o['service']})" for o in row["open"][:6])
        el = (f"Μια συσκευή στη ζώνη «{frm}» ({self.zones[frm]['cidr']}) μπορεί να ανοίξει σύνδεση σε {lst} στη ζώνη "
              f"«{to}» ({self.zones[to]['cidr']}), ενώ η πολιτική το απαγορεύει. Ένας επισκέπτης ή μια παραβιασμένη "
              "IoT συσκευή θα μπορούσε έτσι να δοκιμάσει κωδικούς ή ευπάθειες σε αυτές τις υπηρεσίες (πλευρική "
              "κίνηση). Πρόσθεσε κανόνα drop στο forward του router/firewall πριν από τα allow, και αν απαντά η IP του "
              "ίδιου του router, κόψε και το input από αυτή τη ζώνη (εκτός DHCP/DNS).")
        en = (f"A device in zone '{frm}' ({self.zones[frm]['cidr']}) can open connections to {lst} in zone '{to}' "
              f"({self.zones[to]['cidr']}), although policy denies it. A guest or a compromised IoT device could use "
              "this to try passwords or exploits on those services (lateral movement). Add a drop rule in the "
              "router/firewall forward chain before any accept rules; if the router's own IP answers, also block "
              "input from that zone (except DHCP/DNS).")
        return el, en

    def view(self):
        src, sip = self.source()
        rules = self.rules_view()
        names = [z for z in self.zones] + ([INTERNET] if any(r["to"] == INTERNET for r in self.c["policy"]) else [])
        counts = {v: sum(1 for r in rules if r["verdict"] == v) for v in VERDICTS}
        with self.lock:
            res = self.result
            zones = [{"name": z["name"], "cidr": z["cidr"], "vlan": z["vlan"],
                      "hosts": len(self.targets(z["name"])), "source": z["name"] == src} for z in self.zones.values()]
            remote = [{"zone": k, "source_ip": v.get("source_ip"), "t": v.get("t")} for k, v in sorted(self.remote.items())]
        return {
            "config_ok": bool(self.zones and self.c["policy"]) and not self.errors,
            "configured": bool(self.zones),
            "errors": list(self.errors)[:20],
            "source_zone": src, "source_ip": sip,
            "zones": zones,
            "rules": rules,
            "counts": counts,
            "matrix": {"zones": names, "cells": {r["id"]: r["verdict"] for r in rules}},
            "ports": list(self.c["ports"]),
            "remote": remote,
            "last_run": (res or {}).get("finished"),
            "partial": bool((res or {}).get("partial")),
            "running": self.running,
            "demo": self.sim,
            "note_el": ("Ελέγχονται μόνο οι κανόνες που ξεκινούν από τη ζώνη όπου τρέχει αυτό το NetWatch"
                        f"{' («' + src + '»)' if src else ''}. Για τις άλλες ζώνες τρέξε NetWatch μέσα σε εκείνο το VLAN "
                        "ή `python3 segcheck.py --config config.yaml --post https://<netwatch>:8765 --token <agent-token>` "
                        "ώστε να στείλει εδώ το αποτέλεσμα. Μόνο συνδέσεις TCP σε ιδιωτικές διευθύνσεις, χωρίς δεδομένα."),
            "note_en": ("Only rules starting from the zone where this NetWatch runs"
                        f"{' (' + repr(src) + ')' if src else ''} are tested. For other zones run NetWatch inside that VLAN, "
                        "or `python3 segcheck.py --config config.yaml --post https://<netwatch>:8765 --token <agent-token>` "
                        "to send the result here. TCP connects to private addresses only, no payload."),
        }

    def violations(self):
        """Για το pentest_report: [{rule, from, to, source_ip, open:[{ip,port,service,name}], sensitive, fix}]."""
        return [{"rule": r["id"], "from": r["from"], "to": r["to"], "source_ip": r["source_ip"], "open": r["open"],
                 "sensitive": r["sensitive"], "fix": r["fix"], "from_cidr": self.zones[r["from"]]["cidr"],
                 "to_cidr": self.zones[r["to"]]["cidr"]}
                for r in self.rules_view() if r["verdict"] == "violation"]

    # ───────── ειδοποιήσεις ─────────
    def check_alerts(self):
        """Μία ειδοποίηση ανά κανόνα + σύνολο ανοιχτών host:port. Επιστρέφει τα rule ids που στάλθηκαν."""
        sent = []
        for v in self.violations():
            sig = hashlib.sha1(",".join(f"{o['ip']}:{o['port']}" for o in v["open"]).encode()).hexdigest()[:12]
            with self.lock:
                if self.fired.get(v["rule"]) == sig:
                    continue
                self.fired[v["rule"]] = sig
            lst = ", ".join(f"{o['ip']}:{o['port']} ({o['service']})" for o in v["open"][:8])
            more = f" και άλλες {len(v['open']) - 8}" if len(v["open"]) > 8 else ""
            detail = (f"Η ζώνη «{v['from']}» ({v['from_cidr']}) φτάνει στη ζώνη «{v['to']}» ({v['to_cidr']}) "
                      f"ενώ η πολιτική το απαγορεύει: {lst}{more}. Πρόσθεσε κανόνα drop στο firewall "
                      "(δες τις εντολές στον έλεγχο διαχωρισμού).")
            try:
                if self.st is not None and hasattr(self.st, "alert"):
                    self.st.alert(ALERT, "high" if v["sensitive"] else "med", v["source_ip"] or "netwatch",
                                  f"{v['open'][0]['ip']}:{v['open'][0]['port']}", detail[:500], self.clock(),
                                  key=f"segcheck:{v['rule']}:{sig}", cooldown=86400, mark=False, mitre=MITRE)
            except Exception:
                pass
            sent.append(v["rule"])
        return sent

    # ───────── demo ─────────
    def _demo_connect(self, ip, port):
        return (ip, port) in DEMO_OPEN


DEMO_SOURCE_IP = "192.168.20.57"
DEMO_CFG = {
    "zones": {"lan": {"cidr": "192.168.1.0/24", "vlan": 10}, "iot": {"cidr": "192.168.30.0/24", "vlan": 30},
              "guest": {"cidr": "192.168.20.0/24", "vlan": 20}, "mgmt": {"cidr": "192.168.99.0/24", "vlan": 99}},
    "policy": [{"from": "guest", "to": "lan", "allow": False}, {"from": "guest", "to": "mgmt", "allow": False},
               {"from": "guest", "to": "iot", "allow": False}, {"from": "guest", "to": "internet", "allow": True},
               {"from": "iot", "to": "lan", "allow": False}, {"from": "iot", "to": "mgmt", "allow": False},
               {"from": "iot", "to": "internet", "allow": True}, {"from": "lan", "to": "iot", "allow": True},
               {"from": "lan", "to": "mgmt", "allow": True}, {"from": "mgmt", "to": "lan", "allow": True}],
    "targets": {"lan": ["192.168.1.1", "192.168.1.16", "192.168.1.17", "192.168.1.30", "192.168.1.40"],
                "mgmt": ["192.168.99.1", "192.168.99.2", "192.168.99.3"],
                "iot": ["192.168.30.1", "192.168.30.20", "192.168.30.33", "192.168.30.34"]},
    "source": "guest",
    "interval_hours": 0,
}
DEMO_OPEN = {("192.168.1.17", 445), ("192.168.1.17", 5001), ("192.168.1.16", 8006)}
DEMO_NAMES = {"192.168.99.1": "MikroTik (mgmt)", "192.168.99.2": "core-sw (mgmt)", "192.168.99.3": "access-sw-1 (mgmt)",
              "192.168.30.1": "Router (IoT VLAN)", "192.168.30.20": "ESP32 κήπου", "192.168.30.33": "Κάμερα εισόδου",
              "192.168.30.34": "Κάμερα γκαράζ"}


# ───────── CLI: έλεγχος από μηχάνημα σε άλλη ζώνη + αποστολή στο κεντρικό NetWatch ─────────
def _cli(argv=None):
    import argparse
    import ssl
    import urllib.request
    ap = argparse.ArgumentParser(description="NetWatch segmentation test (TCP connect, private ranges only)")
    ap.add_argument("--config", help="config.yaml (ενότητα segmentation:)")
    ap.add_argument("--source", help="ζώνη πηγής (αλλιώς από την IP αυτού του μηχανήματος)")
    ap.add_argument("--post", help="https://<netwatch-agent>:8765 — στέλνει το αποτέλεσμα στο /api/segcheck/report")
    ap.add_argument("--token", help="agent token του κεντρικού NetWatch")
    ap.add_argument("--cafile", help="agent.crt του κεντρικού (pinning του self-signed πιστοποιητικού)")
    a = ap.parse_args(argv)
    from core import detect_net, load_config
    cfg = dict((load_config(a.config) if a.config else {}).get("segmentation") or {})
    if a.source:
        cfg["source"] = a.source

    class _St:
        lock = threading.Lock()
        hosts, arp_table = {}, {}
    st = _St()
    try:
        st.me = set(detect_net()[2])
    except Exception:
        st.me = set()
    sc = SegCheck(st, cfg)
    for e in sc.errors:
        print("!", e)
    res = sc.probe()
    print(json.dumps(res, ensure_ascii=False, indent=1))
    if a.post:
        ctx = ssl.create_default_context(cafile=a.cafile) if a.cafile else ssl.create_default_context()
        if a.cafile:
            ctx.check_hostname = False  # self-signed CN=netwatch-agent· η εμπιστοσύνη έρχεται από το συγκεκριμένο crt
        req = urllib.request.Request(a.post.rstrip("/") + "/api/segcheck/report", data=json.dumps(res).encode(),
                                     headers={"Content-Type": "application/json",
                                              "Authorization": f"Bearer {a.token or ''}"}, method="POST")
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            print(r.read(4000).decode("utf-8", "replace"))


if __name__ == "__main__":
    _cli()
