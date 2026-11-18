"""🗂️ Διευθύνσεις IP & απογραφή (ένα μικρό NetBox / phpIPAM): ποια IP είναι πιασμένη, ποια ελεύθερη, ποια συσκευή
«κάθεται» μέσα στο DHCP pool με στατική IP, ποιες συγκρούονται — και σημειώσεις για κάθε συσκευή (ιδιοκτήτης, θέση, ρόλος).

config.yaml (όλα προαιρετικά):
ipam:
  subnets:
    - {cidr: 192.168.1.0/24, name: LAN, vlan: 1, gateway: 192.168.1.1, dhcp: "192.168.1.100-192.168.1.199"}
    - {cidr: 192.168.20.0/24, name: IoT, vlan: 20, gateway: 192.168.20.1, dhcp: "192.168.20.50-192.168.20.250"}
  reserved:
    - {ip: 192.168.1.16, name: Proxmox, mac: "bc:24:11:aa:bb:cc", note: "δεσμευμένη στον router"}
  leases_file: /var/lib/misc/dnsmasq.leases   # ή /var/lib/dhcp/dhcpd.leases (ISC) — αν το NetWatch τρέχει στον router
  stale_days: 7                               # «ξεχασμένη» IP: δεν φάνηκε τόσες μέρες

Αν δεν γράψεις subnets, τα βγάζει από τις συσκευές που βλέπει (/24 ανά ιδιωτικό δίκτυο) και το δίκτυο του υπολογιστή.
Οι σημειώσεις ανά συσκευή γράφονται στο data/ipam.json (δεν μπαίνει στο git).
"""
import csv
import io
import ipaddress
import json
import os
import re
import socket
import tempfile
import threading
import time

STALE_DAYS = 7
CONFLICT_WINDOW = 86400
NOTE_FIELDS = {"name": 64, "owner": 64, "location": 64, "role": 32, "note": 500}
MAX_TAGS, TAG_MAX = 10, 24
MAX_NOTES = 5000
LEASES_MAX_BYTES = 5 << 20
_MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_BAD_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


def norm_mac(m):
    m = str(m or "").strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", m):
        m = ":".join(m[i:i + 2] for i in range(0, 12, 2))
    if re.fullmatch(r"[0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5}", m):
        m = ":".join(x.zfill(2) for x in m.split(":"))
    return m if _MAC.match(m) and m not in _BAD_MACS else ""


def _ip(s):
    try:
        a = ipaddress.ip_address(str(s).strip())
        return a if a.version == 4 else None
    except ValueError:
        return None


def parse_range(r, net=None):
    """«a-b» ή [a, b] → (int, int) μέσα στο subnet, αλλιώς None."""
    if not r:
        return None
    a, b = (r[0], r[1]) if isinstance(r, (list, tuple)) and len(r) == 2 else (str(r).split("-", 1) + [""])[:2]
    a, b = _ip(a), _ip(b)
    if not a or not b or int(a) > int(b):
        return None
    if net is not None and (a not in net or b not in net):
        return None
    return int(a), int(b)


def _host(h):
    """Δέχεται dict του NetWatch {ip, mac, names, vendor, dlabel, last, first} ή tuple (ip, mac, name, vendor, last_seen)."""
    if isinstance(h, dict):
        names = h.get("names") or h.get("name") or []
        if isinstance(names, str):
            names = [names]
        return {"ip": str(h.get("ip") or ""), "mac": norm_mac(h.get("mac")), "name": str(next(iter(names), "") or "")[:64],
                "vendor": str(h.get("vendor") or "")[:64], "dlabel": str(h.get("dlabel") or "")[:40],
                "last": float(h.get("last") or 0), "first": float(h.get("first") or h.get("last") or 0)}
    ip, mac, name, vendor, last = (list(h) + [None] * 5)[:5]
    return {"ip": str(ip or ""), "mac": norm_mac(mac), "name": str(name or "")[:64], "vendor": str(vendor or "")[:64],
            "dlabel": "", "last": float(last or 0), "first": float(last or 0)}


def local_network():
    """Το /24 του υπολογιστή (μαντεψιά: ο κανόνας για τα σπίτια). Δεν στέλνει τίποτα — μόνο ρωτά τον πίνακα δρομολόγησης."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
        a = ipaddress.ip_address(ip)
        if a.is_private and not a.is_loopback:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except OSError:
        pass
    return None


def normalize_subnets(cfg_subnets, hosts=(), local_net=None):
    """Subnets από το config· αλλιώς ένα /24 για κάθε ιδιωτικό δίκτυο που βλέπουμε + το τοπικό."""
    out, seen = [], set()
    for s in cfg_subnets or []:
        try:
            net = ipaddress.ip_network(str(s["cidr"]), strict=False)
        except (KeyError, TypeError, ValueError):
            continue
        if net.version != 4 or net in seen:
            continue
        seen.add(net)
        gw = _ip(s.get("gateway")) if s.get("gateway") else None
        out.append({"cidr": str(net), "net": net, "name": str(s.get("name") or str(net))[:40], "vlan": s.get("vlan"),
                    "gateway": str(gw) if gw and gw in net else None, "pool": parse_range(s.get("dhcp"), net),
                    "derived": False})
    if out:
        return out
    nets = []
    if local_net:
        try:
            nets.append(ipaddress.ip_network(str(local_net), strict=False))
        except ValueError:
            pass
    for h in hosts:
        a = _ip(_host(h)["ip"])
        if a and a.is_private and not a.is_loopback and not a.is_link_local:
            nets.append(ipaddress.ip_network(f"{a}/24", strict=False))
    if not nets and not hosts and local_net is None:
        ln = local_network()
        if ln:
            nets.append(ipaddress.ip_network(ln))
    for net in nets:
        if net.version != 4 or net in seen or any(net.subnet_of(x["net"]) for x in out):
            continue
        seen.add(net)
        out.append({"cidr": str(net), "net": net, "name": str(net), "vlan": None, "gateway": None, "pool": None,
                    "derived": True})
    return out


# ---------- DHCP leases ----------
def parse_leases(text, now=None):
    """dnsmasq.leases («λήξη mac ip όνομα client-id» ανά γραμμή) ή ISC dhcpd.leases («lease IP { ... }»).
    Επιστρέφει [{ip, mac, name, expires, active, source}] — μία ανά IP (η τελευταία στο αρχείο κερδίζει)."""
    now = time.time() if now is None else now
    text = str(text or "")
    out = {}
    if re.search(r"^\s*lease\s+\d+\.\d+\.\d+\.\d+\s*\{", text, re.M):
        for m in re.finditer(r"lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)\}", text, re.S):
            ip, body = m.group(1), m.group(2)
            if not _ip(ip):
                continue
            mac = re.search(r"hardware\s+ethernet\s+([0-9a-fA-F:]+)\s*;", body)
            name = re.search(r'client-hostname\s+"([^"]{0,64})"', body)
            ends = re.search(r"\bends\s+(?:\d\s+(\d{4})/(\d\d)/(\d\d)\s+(\d\d):(\d\d):(\d\d)|never)", body)
            state = re.search(r"(?<!next )binding\s+state\s+(\w+)", body)
            exp = None
            if ends and ends.group(1):
                import calendar
                exp = calendar.timegm(tuple(int(x) for x in ends.groups()) + (0, 0, 0))  # το ISC γράφει σε UTC
            st = state.group(1) if state else "active"
            out[ip] = {"ip": ip, "mac": norm_mac(mac.group(1)) if mac else "", "name": name.group(1) if name else "",
                       "expires": exp, "active": st == "active" and (exp is None or exp > now), "source": "isc"}
        return list(out.values())
    for line in text.splitlines():
        p = line.split()
        if len(p) < 4 or not p[0].isdigit() or not _ip(p[2]):
            continue  # π.χ. γραμμή «duid ...» ή IPv6
        exp = int(p[0]) or None  # 0 = άπειρη μίσθωση
        out[p[2]] = {"ip": p[2], "mac": norm_mac(p[1]), "name": "" if p[3] == "*" else p[3][:64], "expires": exp,
                     "active": exp is None or exp > now, "source": "dnsmasq"}
    return list(out.values())


def load_leases(path, now=None):
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return parse_leases(f.read(LEASES_MAX_BYTES), now)
    except OSError:
        return []


# ---------- ανάλυση ----------
def _usable(net):
    return net.num_addresses - 2 if net.prefixlen <= 30 else net.num_addresses


def analyze(cfg=None, hosts=(), observations=(), leases=(), now=None, local_net=None, window=CONFLICT_WINDOW):
    """Η «εικόνα» των subnets + ευρήματα.
    hosts: συσκευές του NetWatch· observations: [(ip, mac, t)] (π.χ. από ARP) για συγκρούσεις· leases: από parse_leases."""
    cfg = cfg or {}
    now = time.time() if now is None else now
    stale_s = float(cfg.get("stale_days") or STALE_DAYS) * 86400
    hosts = [h for h in (_host(x) for x in hosts) if _ip(h["ip"])]
    subnets = normalize_subnets(cfg.get("subnets"), hosts, local_net)
    reserved = {}
    for r in cfg.get("reserved") or []:
        a = _ip((r or {}).get("ip"))
        if a:
            reserved[str(a)] = {"ip": str(a), "name": str(r.get("name") or "")[:64], "mac": norm_mac(r.get("mac")),
                                "note": str(r.get("note") or "")[:200]}
    active_leases = {l["ip"]: l for l in leases or [] if l.get("active") and _ip(l.get("ip"))}

    # ποια MAC είδαμε σε κάθε IP μέσα στο παράθυρο (για συγκρούσεις) και ποιες IP έχει κάθε MAC
    ip_macs, mac_ips = {}, {}
    for h in hosts:
        if h["mac"] and now - h["last"] <= window:
            ip_macs.setdefault(h["ip"], {})[h["mac"]] = max(h["last"], ip_macs.get(h["ip"], {}).get(h["mac"], 0))
    for o in observations or []:
        try:
            ip, mac, t = str(o[0]), norm_mac(o[1]), float(o[2])
        except (IndexError, TypeError, ValueError):
            continue
        if mac and _ip(ip) and now - t <= window:
            ip_macs.setdefault(ip, {})[mac] = max(t, ip_macs.get(ip, {}).get(mac, 0))
    for ip, macs in ip_macs.items():
        for mac in macs:
            mac_ips.setdefault(mac, set()).add(ip)
    conflicts = {ip: sorted(m) for ip, m in ip_macs.items() if len(m) >= 2}

    by_ip = {}
    for h in hosts:
        if h["ip"] not in by_ip or h["last"] > by_ip[h["ip"]]["last"]:
            by_ip[h["ip"]] = h
    findings = []

    def find(kind, sev, ip, detail, **kw):
        findings.append({"kind": kind, "sev": sev, "ip": ip, "detail": detail, **kw})

    out_subnets = []
    for s in subnets:
        net, pool = s["net"], s["pool"]
        in_pool = (lambda n: pool is not None and pool[0] <= n <= pool[1])
        gw = s["gateway"]
        stats = {"used": 0, "in_dhcp": 0, "static": 0, "stale": 0, "reserved": 0, "conflict": 0}
        cells = [] if net.num_addresses <= 256 else None
        free_ips = []
        for a in (net if net.num_addresses <= 65536 else []):
            n, ip = int(a), str(a)
            h, lease, res = by_ip.get(ip), active_leases.get(ip), reserved.get(ip)
            seen = h is not None and h["last"] > 0
            fresh = seen and now - h["last"] <= stale_s
            mac = (h["mac"] if h else "") or (lease["mac"] if lease else "") or (res["mac"] if res else "")
            name = (h["name"] if h else "") or (lease["name"] if lease else "") or (res["name"] if res else "")
            if net.prefixlen <= 30 and a == net.network_address:
                state = "network"
            elif net.prefixlen <= 30 and a == net.broadcast_address:
                state = "broadcast"
            elif ip == gw:
                state = "gateway"
            elif ip in conflicts or (res and res["mac"] and h and h["mac"] and h["mac"] != res["mac"] and fresh):
                state = "conflict"
            elif fresh or lease:
                state = "used"
            elif seen:
                state = "stale"
            elif res:
                state = "reserved"
            elif in_pool(n):
                state = "dhcp-pool"
            else:
                state = "free"
            if state in ("used", "conflict", "stale") or (state == "gateway" and (seen or lease)):
                stats["used"] += 1
                stats["in_dhcp" if in_pool(n) else "static"] += 1
            if state == "stale":
                stats["stale"] += 1
            if state == "conflict":
                stats["conflict"] += 1
            if res:
                stats["reserved"] += 1
            if state == "free" and len(free_ips) < 5:
                free_ips.append(ip)
            if cells is not None:
                c = {"i": n - int(net.network_address), "ip": ip, "state": state}
                if mac:
                    c["mac"] = mac
                if name:
                    c["name"] = name
                if res:
                    c["reserved"] = True
                if in_pool(n):
                    c["pool"] = True
                if h and h["last"]:
                    c["last"] = h["last"]
                cells.append(c)
            # ευρήματα ανά IP
            if res and res["mac"] and h and h["mac"] and h["mac"] != res["mac"] and fresh:
                find("reserved_mismatch", "med", ip, f"Η δεσμευμένη IP {ip} ({res['name'] or 'χωρίς όνομα'}) "
                     f"χρησιμοποιείται από άλλη συσκευή ({h['mac']}{', ' + h['name'] if h['name'] else ''}) "
                     f"αντί για {res['mac']}.", mac=h["mac"], expected=res["mac"], subnet=s["cidr"])
            if in_pool(n) and res:
                find("static_in_pool", "med", ip, f"Η δεσμευμένη/στατική IP {ip} ({res['name'] or res['mac'] or '—'}) "
                     "είναι μέσα στο DHCP pool: ο router μπορεί να τη δώσει και σε άλλη συσκευή. "
                     "Βάλ' τη έξω από το pool ή κάνε κράτηση (static lease) στον router.", subnet=s["cidr"])
            elif in_pool(n) and active_leases and fresh and h["mac"] and not res and \
                    (not lease or (lease["mac"] and lease["mac"] != h["mac"])):
                find("static_in_pool", "med", ip, f"Η συσκευή {h['mac']}{' (' + h['name'] + ')' if h['name'] else ''} "
                     f"έχει την {ip} μέσα στο DHCP pool χωρίς μίσθωση — μάλλον στατική ρύθμιση. "
                     "Κίνδυνος σύγκρουσης όταν ο router δώσει την ίδια IP σε άλλη συσκευή.", mac=h["mac"], subnet=s["cidr"])
        total = _usable(net)
        reserved_free = sum(1 for ip in reserved if ipaddress.ip_address(ip) in net and
                            not (by_ip.get(ip) or active_leases.get(ip)) and ip != gw)
        if gw and not (by_ip.get(gw) or active_leases.get(gw)):
            reserved_free += 1  # ο gateway δεν είναι «ελεύθερος» ακόμη κι αν δεν τον είδαμε
        free = max(0, total - stats["used"] - reserved_free)
        pool_size = (pool[1] - pool[0] + 1) if pool else 0
        out_subnets.append({
            "cidr": s["cidr"], "name": s["name"], "vlan": s["vlan"], "gateway": gw, "derived": s["derived"],
            "dhcp": f"{ipaddress.ip_address(pool[0])}-{ipaddress.ip_address(pool[1])}" if pool else None,
            "pool_size": pool_size, "total": total, "used": stats["used"], "free": free,
            "pct": round(100.0 * stats["used"] / total, 1) if total else 0.0,
            "in_dhcp": stats["in_dhcp"], "static": stats["static"], "stale": stats["stale"],
            "reserved": stats["reserved"], "conflicts": stats["conflict"],
            "pool_used_pct": round(100.0 * stats["in_dhcp"] / pool_size, 1) if pool_size else None,
            "next_free": free_ips, "map": cells})
        if pool_size and stats["in_dhcp"] >= pool_size * 0.9:
            find("pool_full", "med", None, f"Το DHCP pool του «{s['name']}» είναι γεμάτο κατά "
                 f"{round(100.0 * stats['in_dhcp'] / pool_size)}% ({stats['in_dhcp']}/{pool_size}).", subnet=s["cidr"])

    for ip, macs in sorted(conflicts.items()):
        names = [by_ip[ip]["name"]] if ip in by_ip and by_ip[ip]["name"] else []
        find("conflict", "med", ip, f"Η IP {ip} εμφανίστηκε με {len(macs)} διαφορετικές MAC ({', '.join(macs)}) μέσα σε "
             f"{int(window // 3600)} ώρες{' (' + names[0] + ')' if names else ''}. Δύο συσκευές έχουν την ίδια διεύθυνση — "
             "η μία θα «κόβεται». Δώσε στη μία άλλη IP (ή κάνε κράτηση στον router).", macs=macs,
             subnet=next((s["cidr"] for s in subnets if ipaddress.ip_address(ip) in s["net"]), None))
    for mac, ips in sorted(mac_ips.items()):
        if len(ips) >= 2:
            ips_s = sorted(ips, key=lambda x: int(ipaddress.ip_address(x)))
            find("multi_ip", "low", ips_s[0], f"Η συσκευή {mac} εμφανίστηκε με {len(ips)} διευθύνσεις ({', '.join(ips_s)}). "
                 "Συνήθως αλλαγή IP ή router με πολλά δίκτυα· αν όχι, ίσως κάποιος πλαστογραφεί (ARP spoofing).",
                 mac=mac, ips=ips_s)
    outside = []
    for ip, h in sorted(by_ip.items(), key=lambda kv: int(ipaddress.ip_address(kv[0]))):
        a = ipaddress.ip_address(ip)
        if not a.is_private or a.is_loopback or a.is_multicast or a.is_unspecified:
            continue
        if not any(a in s["net"] for s in subnets):
            outside.append(ip)
            find("outside", "low", ip, f"Η συσκευή {ip}{' (' + h['name'] + ')' if h['name'] else ''} είναι έξω από κάθε "
                 "γνωστό subnet — λάθος στατική ρύθμιση ή άγνωστο δίκτυο;", mac=h["mac"])
    order = {"high": 0, "med": 1, "low": 2}
    findings.sort(key=lambda f: order.get(f["sev"], 3))
    return {"t": now, "subnets": out_subnets, "findings": findings, "outside": outside,
            "reserved": list(reserved.values()), "leases": len(active_leases)}


def conflicts_to_alerts(state, findings, now=None, cooldown=3600):
    """«Σύγκρουση IP» (med) για κάθε σύγκρουση — μία φορά ανά ώρα ανά IP. Επιστρέφει πόσες στάλθηκαν."""
    now = time.time() if now is None else now
    n = 0
    for f in findings or []:
        if f.get("kind") != "conflict" or not f.get("ip"):
            continue
        try:
            state.alert("Σύγκρουση IP", "med", f["ip"], ", ".join(f.get("macs") or []), f["detail"], now,
                        key=("Σύγκρουση IP", f["ip"]), cooldown=cooldown, mark=False)
            n += 1
        except Exception:
            pass
    return n


# ---------- σημειώσεις απογραφής ----------
def device_key(k):
    """Κλειδί συσκευής: MAC (προτιμάται — η IP αλλάζει) ή IPv4."""
    m = norm_mac(k)
    if m:
        return m
    a = _ip(k)
    if a:
        return str(a)
    raise ValueError("Το κλειδί πρέπει να είναι MAC ή IPv4.")


def clean_note(fields):
    """Επικύρωση πεδίων· ValueError (στα ελληνικά) για ό,τι ξεπερνά τα όρια."""
    if not isinstance(fields, dict):
        raise ValueError("Τα πεδία πρέπει να είναι αντικείμενο.")
    out = {}
    for k, cap in NOTE_FIELDS.items():
        if k in fields and fields[k] is not None:
            v = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(fields[k])).strip()
            if len(v) > cap:
                raise ValueError(f"Το πεδίο «{k}» ξεπερνά τους {cap} χαρακτήρες.")
            if v:
                out[k] = v
    tags = fields.get("tags")
    if tags:
        if isinstance(tags, str):
            tags = [t for t in re.split(r"[,;]", tags)]
        tags = [re.sub(r"[\x00-\x1f\x7f]", "", str(t)).strip() for t in tags]
        tags = list(dict.fromkeys(t for t in tags if t))
        if len(tags) > MAX_TAGS or any(len(t) > TAG_MAX for t in tags):
            raise ValueError(f"Το πολύ {MAX_TAGS} ετικέτες, έως {TAG_MAX} χαρακτήρες η καθεμία.")
        if tags:
            out["tags"] = tags
    return out


class Notes:
    def __init__(self, path=os.path.join("data", "ipam.json")):
        self.path = path
        self.lock = threading.Lock()
        self.data = self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            return {}
        out = {}
        for k, v in (raw.get("devices", raw) if isinstance(raw, dict) else {}).items():
            try:
                out[device_key(k)] = {**clean_note(v), **({"updated": float(v["updated"])} if v.get("updated") else {})}
            except (ValueError, TypeError, AttributeError):
                continue
        return out

    def save(self):
        d = os.path.dirname(self.path) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".ipam-", suffix=".json", dir=d)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "devices": self.data}, f, ensure_ascii=False, indent=1, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def get(self, key):
        with self.lock:
            return dict(self.data.get(device_key(key)) or {})

    def all(self):
        with self.lock:
            return {k: dict(v) for k, v in self.data.items()}

    def set(self, key, fields):
        """Αντικαθιστά τις σημειώσεις της συσκευής (κενά πεδία = διαγραφή). Επιστρέφει ό,τι αποθηκεύτηκε."""
        k, v = device_key(key), clean_note(fields)
        with self.lock:
            if not v:
                self.data.pop(k, None)
            else:
                if k not in self.data and len(self.data) >= MAX_NOTES:
                    raise ValueError("Πάρα πολλές σημειώσεις.")
                v["updated"] = time.time()
                self.data[k] = v
            self.save()
        return v

    def delete(self, key):
        with self.lock:
            gone = self.data.pop(device_key(key), None) is not None
            if gone:
                self.save()
        return gone


# ---------- απογραφή / εξαγωγή ----------
CSV_COLUMNS = ["ip", "mac", "name", "vendor", "type", "subnet", "vlan", "status", "source", "in_pool", "reserved",
               "first", "last", "owner", "location", "role", "note", "tags"]


def inventory(cfg=None, hosts=(), leases=(), notes=None, now=None, local_net=None):
    """Μία γραμμή ανά συσκευή (ό,τι είδαμε + ενεργές μισθώσεις + δεσμεύσεις), με τις σημειώσεις της."""
    cfg = cfg or {}
    now = time.time() if now is None else now
    stale_s = float(cfg.get("stale_days") or STALE_DAYS) * 86400
    hosts = [h for h in (_host(x) for x in hosts) if _ip(h["ip"])]
    subnets = normalize_subnets(cfg.get("subnets"), hosts, local_net)
    notes = notes or {}
    rows = {}
    for h in hosts:
        rows[h["ip"]] = {"ip": h["ip"], "mac": h["mac"], "name": h["name"], "vendor": h["vendor"], "type": h["dlabel"],
                         "first": h["first"] or None, "last": h["last"] or None,
                         "status": "online" if now - h["last"] <= stale_s else "stale", "source": "seen"}
    for l in leases or []:
        if l.get("active") and _ip(l.get("ip")) and l["ip"] not in rows:
            rows[l["ip"]] = {"ip": l["ip"], "mac": l.get("mac") or "", "name": l.get("name") or "", "vendor": "", "type": "",
                             "first": None, "last": None, "status": "lease", "source": "lease"}
    res = {}
    for r in cfg.get("reserved") or []:
        a = _ip((r or {}).get("ip"))
        if a:
            res[str(a)] = r
            if str(a) not in rows:
                rows[str(a)] = {"ip": str(a), "mac": norm_mac(r.get("mac")), "name": str(r.get("name") or "")[:64],
                                "vendor": "", "type": "", "first": None, "last": None, "status": "offline",
                                "source": "reserved"}
    out = []
    for ip in sorted(rows, key=lambda x: int(ipaddress.ip_address(x))):
        row = rows[ip]
        a = ipaddress.ip_address(ip)
        s = next((s for s in subnets if a in s["net"]), None)
        row["subnet"], row["vlan"] = (s["cidr"], s["vlan"]) if s else ("", None)
        row["in_pool"] = bool(s and s["pool"] and s["pool"][0] <= int(a) <= s["pool"][1])
        row["reserved"] = ip in res
        n = (notes.get(row["mac"]) if row["mac"] else None) or notes.get(ip) or {}
        for k in ("owner", "location", "role", "note"):
            row[k] = n.get(k, "")
        row["tags"] = list(n.get("tags") or [])
        if n.get("name"):
            row["name"] = n["name"]  # το όνομα που έδωσες εσύ υπερισχύει
        out.append(row)
    return out


def _csv_safe(v):
    """Όχι formula injection στο Excel / LibreOffice: κείμενο που ξεκινά με = + - @ γίνεται κείμενο."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for r in rows:
        vals = []
        for c in CSV_COLUMNS:
            v = r.get(c)
            if c == "tags":
                v = ";".join(v or [])
            elif c in ("first", "last") and v:
                v = time.strftime("%Y-%m-%d %H:%M", time.localtime(v))
            elif isinstance(v, bool):
                v = "yes" if v else "no"
            vals.append(_csv_safe(v))
        w.writerow(vals)
    return buf.getvalue()


def to_json(rows):
    return json.dumps({"version": 1, "exported": time.time(), "devices": rows}, ensure_ascii=False, indent=1)


class Ipam:
    """Βολικό «όλα μαζί» για τον server: config + αρχείο leases + σημειώσεις."""

    def __init__(self, cfg=None, notes_path=os.path.join("data", "ipam.json")):
        self.cfg = cfg or {}
        self.notes = Notes(notes_path)

    def leases(self, now=None):
        return load_leases(self.cfg.get("leases_file"), now)

    def report(self, hosts=(), observations=(), now=None, local_net=None):
        leases = self.leases(now)
        rep = analyze(self.cfg, hosts, observations, leases, now, local_net)
        rep["inventory"] = inventory(self.cfg, hosts, leases, self.notes.all(), now, local_net)
        return rep

    def export(self, hosts=(), fmt="csv", now=None, local_net=None):
        rows = inventory(self.cfg, hosts, self.leases(now), self.notes.all(), now, local_net)
        return to_csv(rows) if fmt == "csv" else to_json(rows)
