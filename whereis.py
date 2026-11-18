"""🔌 «Πού είναι συνδεδεμένο;» — MAC → switch → θύρα → VLAN (σαν το «Find MAC» των NMS).

Από κάθε στόχο του `snmp.targets` (ίδιο community/θύρα/timeout με τον poller του snmp.py) διαβάζουμε:
  • BRIDGE-MIB  dot1dTpFdbPort   1.3.6.1.2.1.17.4.3.1.2   (index = MAC → bridge port)
                dot1dTpFdbStatus 1.3.6.1.2.1.17.4.3.1.3   (3 learned, 4 self, 5 mgmt)
                dot1dBasePortIfIndex 1.3.6.1.2.1.17.1.4.1.2 (bridge port → ifIndex)
  • Q-BRIDGE    dot1qTpFdbPort   1.3.6.1.2.1.17.7.1.2.2.1.2 (index = VLAN(FDB id).MAC → bridge port) ⇒ VLAN
  • IF-MIB      ifName .31.1.1.1.1 και ifAlias .31.1.1.1.18 (περιγραφή θύρας)
  • LLDP/CDP    οι γείτονες που ήδη μάζεψε το snmp.py (αλλιώς walk του lldpRemTable / CDP cache)

Θύρα **uplink** = θύρα με γείτονα LLDP/CDP που είναι switch/AP/router (ή άλλος στόχος SNMP), ή θύρα με > 8 MAC.
Η θέση μιας συσκευής είναι η θύρα «άκρης» (όχι uplink). Αν η MAC φαίνεται μόνο σε uplinks (π.χ. Wi‑Fi πελάτες
πίσω από AP, ή μη διαχειριζόμενο switch), δίνουμε την πιο «βαθιά» uplink με μικρότερη βεβαιότητα.

Cisco IOS: το BRIDGE-MIB είναι ανά VLAN (community string indexing). Δώσε στον στόχο `vlans: [10, 20, 30]` και
θα διαβαστεί και με community@<vlan>. MikroTik / OpenWrt / τα περισσότερα smart switch δίνουν Q-BRIDGE κατευθείαν.

Το community ΔΕΝ εμφανίζεται ποτέ σε απάντηση του API ή σε log.
Στο demo: δύο Cisco 2960 (core-sw 192.168.1.2, access-sw-1 192.168.1.4) και οι συσκευές του demo δικτύου.

API
---
WhereIs(state, sim=False, clock=time.time, client_factory=None)
  .lookup(q)              → {query, found, mac, ip, name, vendor, location|None, path, candidates, refreshed, note, demo}
  .table(all_rows=False)  → {rows, switches, refreshed, demo}
  .refresh(wait=False)    → {ok: True}
"""
import collections
import ipaddress
import re
import threading
import time

import snmp

FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"
BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
QFDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
QFDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
SKIP_STATUS = {2, 4}          # invalid, self (η MAC του ίδιου του switch)
MANY_MACS = 8                 # θύρα με περισσότερες MAC = uplink / μη διαχειριζόμενο switch
MAX_ROWS = 20000
EVERY = 300
INFRA_RE = re.compile(r"(^|[^a-z])(sw|switch|ap|wap|router|rtr|gw|gateway|core|access|dist|fw|firewall)([^a-z]|\d|$)"
                      r"|switch|router|mikrotik|routeros|cisco|catalyst|aruba|unifi|ubnt|ubiquiti|openwrt|tp-?link|netgear|"
                      r"omada|ruckus|meraki|juniper|procurve|ws-c|air-|cbs\d|crs\d|hap|hex", re.I)
NOTE_NO_SNMP = ("Δεν υπάρχουν στόχοι SNMP. Βάλε στο config.yaml «snmp: {enabled: true, targets: [{name: core-sw, "
                "host: 192.168.1.2, community: …}]}» και ενεργοποίησε SNMP v2c (μόνο ανάγνωση) στα switch: "
                "Cisco «snmp-server community <κάτι> RO», MikroTik «/snmp set enabled=yes», OpenWrt πακέτο snmpd.")

_HEX = re.compile(r"[^0-9a-f]")


def norm_mac(s):
    """aa:bb:cc:dd:ee:ff / aabb.ccdd.eeff / AA-BB-CC-DD-EE-FF / aabbccddeeff → 'aa:bb:cc:dd:ee:ff' (ή None)."""
    if not isinstance(s, str):
        return None
    s = s.strip().lower()
    if re.fullmatch(r"[0-9a-f]{1,2}([:-][0-9a-f]{1,2}){5}", s):
        return ":".join(p.zfill(2) for p in re.split(r"[:-]", s))
    if re.fullmatch(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", s) or re.fullmatch(r"[0-9a-f]{12}", s):
        h = _HEX.sub("", s)
        return ":".join(h[i:i + 2] for i in range(0, 12, 2))
    return None


def _mac_of(idx):
    """Τα 6 τελευταία στοιχεία του index (OID) → MAC."""
    if len(idx) < 6 or not all(isinstance(b, int) and 0 <= b <= 255 for b in idx[-6:]):
        return None
    return ":".join(f"{b:02x}" for b in idx[-6:])


def parse_fdb(fdb_port, fdb_status=None, base_ifindex=None, q_port=None, q_status=None):
    """Στήλες FDB ({index tuple: τιμή}) → [{mac, bport, ifindex, vlan}].

    Q-BRIDGE: index = (fdbId/VLAN, m1..m6). BRIDGE-MIB: index = (m1..m6). Αγνοούνται self/invalid, port 0 και
    multicast. Η ίδια (mac, port) από τα δύο MIB μετρά μία φορά (με το VLAN από το Q-BRIDGE)."""
    base_ifindex, fdb_status, q_status = base_ifindex or {}, fdb_status or {}, q_status or {}
    out, seen, pairs = [], set(), set()

    def add(mac, bport, vlan, status):
        if not mac or int(mac[:2], 16) & 1 or not isinstance(bport, int) or bport <= 0 or status in SKIP_STATUS:
            return
        if (mac, bport, vlan) in seen or (vlan is None and (mac, bport) in pairs):
            return
        seen.add((mac, bport, vlan))
        pairs.add((mac, bport))
        ifx = base_ifindex.get((bport,))
        out.append({"mac": mac, "bport": bport, "ifindex": ifx if isinstance(ifx, int) and ifx > 0 else bport, "vlan": vlan})
    for idx, bp in sorted((q_port or {}).items()):
        if len(idx) >= 7:
            add(_mac_of(idx), bp, idx[-7] if 0 < idx[-7] < 4095 else None, q_status.get(idx))
    for idx, bp in sorted((fdb_port or {}).items()):
        if len(idx) == 6:
            add(_mac_of(idx), bp, None, fdb_status.get(idx))
    return out


def is_infra(neigh, known=()):
    """Γείτονας LLDP/CDP που είναι switch/AP/router (όχι απλός server/PC με lldpd)."""
    if not neigh:
        return False
    nm = (neigh.get("remote_name") or "").strip().lower()
    if nm and nm in known:
        return True
    return bool(INFRA_RE.search(" ".join(str(neigh.get(k) or "") for k in ("remote_name", "platform"))))


def _clean_name(s):
    return re.sub(r"\s*\([^)]*\)\s*$", "", s or "").strip() or s


class WhereIs:
    def __init__(self, state, sim=False, clock=time.time, client_factory=None):
        self.st, self.sim, self.clock = state, sim, clock
        self.client_factory = client_factory
        self.lock = threading.Lock()
        self._busy = threading.Lock()
        self.entries = {}       # mac → [θέση σε κάθε switch]
        self.switches = []      # [{name, host, ports, macs, ok, error}]
        self.sw_names = {}      # όνομα/sysName/host (lower) → όνομα στόχου
        self.root = None        # switch προς το router
        self.history = collections.OrderedDict()  # mac → (θέση, seen): «πού ήταν την τελευταία φορά»
        self.refreshed = None
        self.wake = threading.Event()
        if sim:
            self._ingest(_demo_raw(), self.clock())

    # ───────── στόχοι / συλλογή ─────────
    def _targets(self):
        sn = getattr(self.st, "snmp", None)
        if sn is None or getattr(sn, "sim", False):
            return [], {}
        return list(sn.targets), sn.cfg

    def _client(self, t, cfg, community=None):
        args = (t["host"], community or t["community"], t["port"], t.get("timeout", cfg.get("timeout", 2.0)),
                t.get("retries", cfg.get("retries", 1)), t.get("bulk", True))
        return (self.client_factory or snmp.SnmpClient)(*args)

    def _neigh_from_snmp(self, t):
        sn = getattr(self.st, "snmp", None)
        try:
            with sn.lock:
                return [dict(n) for n in (sn.res.get(t["id"]) or {}).get("neigh") or []]
        except Exception:
            return []

    def fetch(self, t, cfg):
        """Ένα switch → «ωμά» δεδομένα {name, host, sysname, ifs:{ifindex:{name, alias}}, fdb:[…], neigh:[…]}."""
        cl, mr = self._client(t, cfg), MAX_ROWS
        col = lambda c, o: snmp._col(c, o, mr)  # noqa: E731
        ifs = {}
        names, descr, alias = col(cl, IF_NAME), col(cl, IF_DESCR), col(cl, IF_ALIAS)
        for idx in set(names) | set(descr):
            if len(idx) == 1:
                ifs[idx[0]] = {"name": snmp._txt(names.get(idx)) or snmp._txt(descr.get(idx)) or str(idx[0]),
                               "alias": snmp._txt(alias.get(idx))}
        base = col(cl, BASE_PORT_IFINDEX)
        fdb = parse_fdb(col(cl, FDB_PORT), col(cl, FDB_STATUS), base, col(cl, QFDB_PORT), col(cl, QFDB_STATUS))
        for v in [int(x) for x in t.get("vlans") or [] if str(x).isdigit()][:64]:  # Cisco: community@vlan
            cv = self._client(t, cfg, f"{t['community']}@{v}")
            for e in parse_fdb(col(cv, FDB_PORT), col(cv, FDB_STATUS), col(cv, BASE_PORT_IFINDEX)):
                e["vlan"] = v
                fdb.append(e)
        neigh = self._neigh_from_snmp(t)
        if not neigh:
            rem = {k: col(cl, f"{snmp.LLDP_REM}.{c}") for k, c in (("chassis", 5), ("port", 7), ("name", 9))}
            for idx in sorted(set(rem["name"]) | set(rem["port"])):
                if len(idx) >= 3:
                    neigh.append({"proto": "lldp", "local_ifindex": idx[1], "remote_name": snmp._txt(rem["name"].get(idx)),
                                  "remote_port": snmp._txt(rem["port"].get(idx)), "chassis": snmp._txt(rem["chassis"].get(idx))})
            cdp = {k: col(cl, f"{snmp.CDP_CACHE}.{c}") for k, c in (("name", 6), ("port", 7), ("platform", 8))}
            for idx in sorted(cdp["name"]):
                if len(idx) >= 2:
                    neigh.append({"proto": "cdp", "local_ifindex": idx[0], "remote_name": snmp._txt(cdp["name"].get(idx)),
                                  "remote_port": snmp._txt(cdp["port"].get(idx)), "platform": snmp._txt(cdp["platform"].get(idx)),
                                  "chassis": ""})
        bmap = {k[0]: v for k, v in base.items() if len(k) == 1}
        for n in neigh:  # lldpLocPortNum: συνήθως ifIndex, σε κάποια switch bridge port
            li = n.get("local_ifindex")
            if li not in ifs and li in bmap:
                n["local_ifindex"] = bmap[li]
        return {"name": t["name"], "host": t["host"], "sysname": "", "ifs": ifs, "fdb": fdb, "neigh": neigh}

    def refresh(self, wait=False):
        """Νέα ανάγνωση όλων των switch (στο παρασκήνιο, αν δεν τρέχει ήδη)."""
        if self.sim:
            return {"ok": True}
        if wait:
            self._refresh_now()
        else:
            threading.Thread(target=self._refresh_now, daemon=True).start()
        return {"ok": True}

    def _refresh_now(self):
        if not self._busy.acquire(blocking=False):
            return
        try:
            targets, cfg = self._targets()
            raws = []
            for t in targets:
                try:
                    raws.append(self.fetch(t, cfg))
                except Exception as e:  # SnmpTimeout, DNS…: το μήνυμα δεν περιέχει ποτέ το community
                    raws.append({"name": t["name"], "host": t["host"], "error": (str(e)[:120] or e.__class__.__name__)})
            self._ingest(raws, self.clock())
        finally:
            self._busy.release()

    def run_forever(self):
        if self.sim:
            return
        time.sleep(20)
        while True:
            try:
                self._refresh_now()
            except Exception:
                pass
            self.wake.wait(EVERY)
            self.wake.clear()

    # ───────── ανάλυση ─────────
    def _ingest(self, raws, now):
        known = set()
        for r in raws:
            for k in (r.get("name"), r.get("sysname"), r.get("host")):
                if k:
                    known.add(str(k).lower())
        sw_names = {}
        for r in raws:
            for k in (r.get("name"), r.get("sysname"), r.get("host")):
                if k:
                    sw_names[str(k).lower()] = r["name"]
        entries, switches, total = collections.defaultdict(list), [], 0
        for r in raws:
            if r.get("error"):
                switches.append({"name": r["name"], "host": r["host"], "ports": 0, "macs": 0, "ok": False, "error": r["error"]})
                continue
            ifs = r.get("ifs") or {}
            per_port = collections.defaultdict(set)
            for e in r.get("fdb") or []:
                per_port[e["ifindex"]].add(e["mac"])
            neigh = {}
            for n in r.get("neigh") or []:
                if n.get("local_ifindex") is not None:
                    neigh.setdefault(n["local_ifindex"], n)
            macs = set()
            for e in r.get("fdb") or []:
                if total >= MAX_ROWS:
                    break
                ifx = e["ifindex"]
                n = neigh.get(ifx)
                nmac = norm_mac(n.get("chassis") or "") if n else None
                to_sw = sw_names.get((n.get("remote_name") or "").lower()) if n else None
                up = len(per_port[ifx]) > MANY_MACS or is_infra(n, known)
                i = ifs.get(ifx) or {}
                entries[e["mac"]].append({
                    "switch": r["name"], "switch_host": r["host"], "port": i.get("name") or str(ifx), "ifindex": ifx,
                    "vlan": e.get("vlan"), "alias": i.get("alias") or "", "macs_on_port": len(per_port[ifx]), "uplink": up,
                    "neighbour": (n.get("remote_name") or None) if n else None, "neighbour_mac": nmac, "to_switch": to_sw})
                macs.add(e["mac"])
                total += 1
            switches.append({"name": r["name"], "host": r["host"], "ports": len(ifs) or len(per_port), "macs": len(macs),
                             "ok": True, "error": None})
        # switch προς το router: εκεί που η MAC του gateway φαίνεται σε θύρα που ΔΕΝ οδηγεί σε άλλο switch
        gw_mac = self._gw_mac()
        root = None
        for e in entries.get(gw_mac, []) if gw_mac else []:
            if not e["to_switch"]:
                root = e["switch"]
                break
        with self.lock:
            self.entries, self.switches, self.sw_names, self.root, self.refreshed = dict(entries), switches, sw_names, root, now
            for mac in entries:
                loc = self._locate(mac)
                if loc:
                    self.history[mac] = (loc, now)
                    self.history.move_to_end(mac)
            while len(self.history) > MAX_ROWS:
                self.history.popitem(last=False)

    def _locate(self, mac):
        """→ (location dict, path) ή None. Καλείται με self.lock."""
        ents = self.entries.get(mac) or []
        if not ents:
            return None
        edge = [e for e in ents if not e["uplink"]]
        note = None
        if edge:
            best = min(edge, key=lambda e: (e["macs_on_port"], e["switch"]))
            conf = "high" if best["macs_on_port"] == 1 else "medium"
            if best["macs_on_port"] > 1:
                note = (f"Στη θύρα φαίνονται {best['macs_on_port']} MAC — πιθανώς hypervisor με VM, τηλέφωνο IP με PC "
                        "ή μικρό μη διαχειριζόμενο switch.")
        else:  # μόνο uplinks: η πιο «βαθιά» — αυτή που δεν οδηγεί σε άλλο switch που βλέπουμε
            leaf = [e for e in ents if not e["to_switch"]]
            best = min(leaf or ents, key=lambda e: (e["macs_on_port"], e["switch"]))
            if best["neighbour_mac"] == mac:
                conf, note = "high", f"Είναι η ίδια η συσκευή «{best['neighbour']}» (γείτονας LLDP/CDP στη θύρα)."
            elif best["neighbour"] and leaf:
                conf = "medium"
                label = self._friendly(best["neighbour"], best["neighbour_mac"])
                wifi = re.search(r"(^|[^a-z])(ap|wap|wifi|wi-fi|uap)([^a-z]|\d|$)|access point|σαλον", label + " " + best["neighbour"], re.I)
                note = f"πίσω από {label} (Wi‑Fi)" if wifi else f"πίσω από «{label}» (συσκευή χωρίς SNMP)"
            else:
                conf = "low"
                note = (f"Η MAC φαίνεται μόνο σε uplink ({best['macs_on_port']} MAC στη θύρα): μάλλον μη διαχειριζόμενο "
                        "switch ή AP χωρίς LLDP σε εκείνη τη θύρα.")
        loc = {k: best[k] for k in ("switch", "switch_host", "port", "ifindex", "vlan", "alias", "macs_on_port", "uplink")}
        loc["confidence"] = conf
        if note:
            loc["note"] = note
        return loc, self._path(mac, best)

    def _path(self, mac, best):
        by_sw = {}
        for e in self.entries.get(mac) or []:
            by_sw.setdefault(e["switch"], e)
        path, cur, seen = [], self.root or best["switch"], set()
        while cur and cur not in seen and cur in by_sw:
            seen.add(cur)
            e = by_sw[cur]
            if e is best or not e["to_switch"]:
                break
            path.append({"switch": e["switch"], "port": e["port"], "kind": "uplink"})
            cur = e["to_switch"]
        path.append({"switch": best["switch"], "port": best["port"], "kind": "uplink" if best["uplink"] else "edge"})
        return path

    # ───────── ονόματα / IP ─────────
    def _gw_mac(self):
        gw = getattr(self.st, "gateway", None) or ("192.168.1.1" if self.sim else None)
        return self._hosts().get("ip2mac", {}).get(gw) if gw else None

    def _hosts(self):
        """{mac2: {mac: (ip, name)}, ip2mac: {ip: mac}} από το demo, το state.hosts και τον πίνακα ARP."""
        mac2, ip2mac = {}, {}
        if self.sim:
            for ip, mac, name, _v, *_ in DEMO_DEVICES:
                mac2[mac], ip2mac[ip] = (ip, name), mac
        st = self.st
        if st is not None:
            try:
                with st.lock:
                    arp = dict(getattr(st, "arp_table", {}) or {})
                    hosts = [(ip, h.get("mac"), sorted(h.get("names") or ()), h.get("rdns"))
                             for ip, h in (getattr(st, "hosts", {}) or {}).items() if h.get("kind") == "local"]
            except Exception:
                arp, hosts = {}, []
            for ip, m in arp.items():
                m = norm_mac(m or "")
                if m and ":" not in ip:
                    ip2mac.setdefault(ip, m)
                    mac2.setdefault(m, (ip, None))
            for ip, m, names, rdns in hosts:
                m = norm_mac(m or "")
                if not m:
                    continue
                ip2mac.setdefault(ip, m)
                nm = (names[0] if names else None) or rdns
                old = mac2.get(m)
                if old is None or (old[1] is None and nm):
                    mac2[m] = (old[0] if old and old[0] else ip, nm)
        return {"mac2": mac2, "ip2mac": ip2mac}

    def _friendly(self, neighbour, nmac):
        """Φιλικό όνομα γείτονα (π.χ. «ap-living» → «AP σαλονιού» από τα αντίγραφα ρυθμίσεων)."""
        cb = getattr(self.st, "configbak", None)
        try:
            for d in (cb.devices.values() if cb else ()):
                if neighbour and neighbour.lower() in (d.get("id", "").lower(), str(d.get("host", "")).lower()):
                    return _clean_name(d.get("name"))
        except Exception:
            pass
        if self.sim:
            for _ip, mac, name, *_ in DEMO_DEVICES:
                if mac == nmac:
                    return _clean_name(name)
        return neighbour

    @staticmethod
    def _vendor(mac, demo_vendor=None):
        if demo_vendor:
            return demo_vendor
        try:
            import devtype
            return devtype.vendor(mac)
        except Exception:
            return None

    def _demo_vendor(self, mac):
        if self.sim:
            for _ip, m, _n, v, *_ in DEMO_DEVICES:
                if m == mac:
                    return v
        return None

    # ───────── API ─────────
    def lookup(self, q):
        q = (q or "").strip()[:64]
        hx = self._hosts()
        mac2, ip2mac = hx["mac2"], hx["ip2mac"]
        out = {"query": q, "found": False, "mac": None, "ip": None, "name": None, "vendor": None, "location": None,
               "path": [], "candidates": [], "refreshed": self.refreshed, "note": None, "demo": self.sim}
        if not self.sim and not self._targets()[0]:
            out["note"] = NOTE_NO_SNMP
        if not q:
            out["note"] = out["note"] or "Δώσε MAC (οποιαδήποτε μορφή), IP ή μέρος ονόματος."
            return out
        mac = norm_mac(q)
        if mac is None:
            try:
                ipaddress.ip_address(q)
                mac = ip2mac.get(q)
                out["ip"] = q
                if mac is None:
                    out["note"] = out["note"] or f"Δεν ξέρω τη MAC της {q} — κάνε ένα ping από το ίδιο LAN ώστε να μπει στον πίνακα ARP."
                    return out
            except ValueError:
                ql = q.lower()
                with self.lock:
                    known_macs = set(self.entries) | set(self.history)
                cands = []
                for m, (ip, nm) in sorted(mac2.items(), key=lambda x: (x[1][0] is None, x[1][0] or "")):
                    if (nm and ql in nm.lower()) or (len(ql) >= 4 and ql.replace("-", ":") in m):
                        cands.append({"mac": m, "ip": ip, "name": nm})
                if len(ql) >= 4:
                    for m in sorted(known_macs):
                        if ql.replace("-", ":") in m and not any(c["mac"] == m for c in cands):
                            cands.append({"mac": m, "ip": None, "name": None})
                if len(cands) != 1:
                    out["candidates"] = cands[:10]
                    if not cands:
                        out["note"] = out["note"] or f"Δεν βρέθηκε συσκευή που να ταιριάζει με «{q}»."
                    else:
                        out["note"] = out["note"] or f"{len(cands)} συσκευές ταιριάζουν — διάλεξε μία."
                    return out
                mac = cands[0]["mac"]
        ip, nm = mac2.get(mac, (out["ip"], None))
        out.update(mac=mac, ip=ip or out["ip"], name=nm, vendor=self._vendor(mac, self._demo_vendor(mac)))
        with self.lock:
            r = self._locate(mac)
            hist = self.history.get(mac)
        if r:
            loc, path = r
            note = loc.pop("note", None)
            out.update(found=True, location=loc, path=path)
            out["note"] = note or out["note"]
        elif hist:
            loc = dict(hist[0][0])
            note = loc.pop("note", None)
            ago = int((self.clock() - hist[1]) // 60)
            loc["confidence"] = "low"
            out.update(found=True, location=loc, path=hist[0][1])
            out["note"] = f"Δεν φαίνεται τώρα· τελευταία φορά εδώ πριν {ago}′." + (f" ({note})" if note else "")
        else:
            out["note"] = out["note"] or ("Η MAC δεν φαίνεται σε κανένα switch (εκτός δικτύου, ή σε switch χωρίς SNMP)."
                                          if self.refreshed else "Δεν έχει γίνει ακόμα ανάγνωση των switch.")
        return out

    def table(self, all_rows=False):
        hx = self._hosts()["mac2"]
        rows = []
        with self.lock:
            for mac in sorted(self.entries):
                ip, nm = hx.get(mac, (None, None))
                vend = self._vendor(mac, self._demo_vendor(mac))
                if all_rows:
                    sel = self.entries[mac]
                else:
                    r = self._locate(mac)
                    if not r:
                        continue
                    sel = [r[0]]
                for e in sel:
                    rows.append({"mac": mac, "ip": ip, "name": nm, "vendor": vend, "switch": e["switch"], "port": e["port"],
                                 "vlan": e["vlan"], "uplink": e["uplink"], "seen": self.refreshed,
                                 "confidence": e.get("confidence"), "note": e.get("note")})
                if len(rows) >= MAX_ROWS:
                    break
            sw = [dict(s) for s in self.switches]
        if not all_rows:
            rows = [r for r in rows if not r["uplink"] or r.get("confidence") in ("high", "medium")]
        rows.sort(key=lambda r: (r["switch"], _port_key(r["port"]), r["mac"]))
        out = {"rows": rows, "switches": sw, "refreshed": self.refreshed, "demo": self.sim}
        if not self.sim and not self._targets()[0]:
            out["note"] = NOTE_NO_SNMP
        return out


def _port_key(p):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", str(p))]


# ───────── demo ─────────
# ip, mac, όνομα, κατασκευαστής, switch, θύρα, VLAN — ίδιες IP/MAC με το demo.py / changecheck / configbak
WIFI = ("core-sw", "Fa0/2")
DEMO_DEVICES = [
    ("192.168.1.1", "a4:2b:b0:11:22:01", "Router MikroTik hEX", "MikroTik", "core-sw", "Gi0/1", 10),
    ("192.168.1.3", "94:83:c4:03:03:03", "AP σαλονιού (OpenWrt)", "GL Technologies", "core-sw", "Fa0/2", 10),
    ("192.168.1.4", "00:1b:54:04:04:04", "access-sw-1 (όροφος)", "Cisco Systems", "core-sw", "Gi0/2", 10),
    ("192.168.1.17", "dc:a6:32:17:17:17", "Raspberry Pi (NAS)", "Raspberry Pi Trading", "core-sw", "Fa0/1", 20),
    ("192.168.1.16", "a8:a1:59:16:16:16", "Proxmox", "ASRock Incorporation", "core-sw", "Fa0/4", 20),
    ("192.168.1.30", "c0:56:e3:30:30:30", "Home Assistant (VM)", "Proxmox (VM)", "core-sw", "Fa0/4", 20),
    ("192.168.1.34", "54:af:97:34:34:34", "Κάμερα γκαράζ", "TP-Link (Tapo)", "core-sw", "Fa0/5", 30),
    ("192.168.1.10", "f0:de:f1:10:10:10", "smart-tv.local", "Samsung Electronics", *WIFI, 30),
    ("192.168.1.15", "ac:1f:74:15:15:15", "iPhone", "Apple", *WIFI, 10),
    ("192.168.1.20", "24:6f:28:20:20:20", "ESP32 κήπου", "Espressif", *WIFI, 30),
    ("192.168.1.31", "a8:23:fe:31:31:31", "Smart TV σαλονιού", "LG Electronics", *WIFI, 30),
    ("192.168.1.52", "50:02:91:52:52:52", "Πρίζα κουζίνας", "Espressif", *WIFI, 30),
    ("192.168.1.99", "da:7c:31:99:99:99", "Άγνωστη συσκευή (da:7c:31)", "τυχαία MAC", *WIFI, 10),
    ("192.168.1.23", "3c:22:fb:aa:bb:23", "MacBook (αυτός ο υπολογιστής)", "Apple", "access-sw-1", "Fa0/3", 10),
    ("192.168.1.33", "54:af:97:33:33:33", "Κάμερα εισόδου (Tapo)", "TP-Link (Tapo)", "access-sw-1", "Fa0/7", 30),
    ("192.168.1.40", "00:1e:0b:40:40:40", "Εκτυπωτής", "Hewlett Packard", "access-sw-1", "Fa0/9", 10),
    ("192.168.1.77", "de:ad:be:ef:77:77", "unknown-laptop.local", None, "access-sw-1", "Fa0/12", 10),
    ("192.168.1.101", "70:85:c2:01:01:01", "pc-logistirio", "ASRock Incorporation", "access-sw-1", "Fa0/1", 10),
    ("192.168.1.102", "70:85:c2:02:02:02", "pc-grammateia", "ASRock Incorporation", "access-sw-1", "Fa0/2", 10),
    ("192.168.1.103", "f4:4d:30:03:03:03", "pc-diefthinsi", "Elitegroup", "access-sw-1", "Fa0/4", 10),
    ("192.168.1.104", "00:0b:82:04:04:04", "Τηλέφωνο IP υποδοχής", "Grandstream", "access-sw-1", "Fa0/5", 10),
]
DEMO_ALIAS = {("core-sw", "Gi0/1"): "Uplink-MikroTik", ("core-sw", "Gi0/2"): "Uplink-access-sw-1",
              ("core-sw", "Fa0/1"): "NAS", ("core-sw", "Fa0/2"): "AP-living", ("core-sw", "Fa0/3"): "Guest-room",
              ("core-sw", "Fa0/4"): "Proxmox", ("core-sw", "Fa0/5"): "Camera-garage",
              ("access-sw-1", "Gi0/1"): "Uplink-core-sw", ("access-sw-1", "Fa0/1"): "Λογιστήριο",
              ("access-sw-1", "Fa0/2"): "Γραμματεία", ("access-sw-1", "Fa0/3"): "Γραφείο IT", ("access-sw-1", "Fa0/4"): "Διεύθυνση",
              ("access-sw-1", "Fa0/5"): "Υποδοχή (τηλέφωνο)", ("access-sw-1", "Fa0/7"): "Κάμερα εισόδου (PoE)",
              ("access-sw-1", "Fa0/9"): "Εκτυπωτής", ("access-sw-1", "Fa0/12"): "Αίθουσα συσκέψεων"}


def _c2960_ifs(name):
    """Cisco 2960-24TT: Fa0/1-24 = ifIndex 10001-10024, Gi0/1-2 = 10101-10102."""
    ifs = {10000 + i: {"name": f"Fa0/{i}", "alias": DEMO_ALIAS.get((name, f"Fa0/{i}"), "")} for i in range(1, 25)}
    ifs.update({10100 + i: {"name": f"Gi0/{i}", "alias": DEMO_ALIAS.get((name, f"Gi0/{i}"), "")} for i in (1, 2)})
    return ifs


def _demo_raw():
    sws = {"core-sw": ("192.168.1.2", _c2960_ifs("core-sw")), "access-sw-1": ("192.168.1.4", _c2960_ifs("access-sw-1"))}
    ifx = {sw: {v["name"]: k for k, v in ifs.items()} for sw, (_h, ifs) in sws.items()}
    fdb = {sw: [] for sw in sws}
    for ip, mac, _nm, _v, sw, port, vlan in DEMO_DEVICES:
        fdb[sw].append({"mac": mac, "ifindex": ifx[sw][port], "vlan": vlan})
        other = "access-sw-1" if sw == "core-sw" else "core-sw"  # το άλλο switch τη βλέπει στο uplink του
        fdb[other].append({"mac": mac, "ifindex": ifx[other]["Gi0/1" if other == "access-sw-1" else "Gi0/2"], "vlan": vlan})
    for e in fdb["access-sw-1"]:
        if e["mac"] == "00:1b:54:04:04:04":  # η δική του MAC (self) δεν εμφανίζεται στο δικό του FDB
            fdb["access-sw-1"].remove(e)
            break
    neigh = {"core-sw": [{"proto": "cdp", "local_ifindex": 10101, "remote_name": "gw", "remote_port": "ether2",
                          "platform": "MikroTik RouterOS", "chassis": "a4:2b:b0:11:22:01"},
                         {"proto": "cdp", "local_ifindex": 10102, "remote_name": "access-sw-1", "remote_port": "GigabitEthernet0/1",
                          "platform": "cisco WS-C2960-24TT-L", "chassis": "00:1b:54:04:04:04"},
                         {"proto": "lldp", "local_ifindex": 10002, "remote_name": "ap-living", "remote_port": "eth0",
                          "chassis": "94:83:c4:03:03:03"}],
             "access-sw-1": [{"proto": "cdp", "local_ifindex": 10101, "remote_name": "core-sw", "remote_port": "GigabitEthernet0/2",
                              "platform": "cisco WS-C2960-24TT-L", "chassis": ""}]}
    return [{"name": sw, "host": h, "sysname": sw, "ifs": ifs, "fdb": fdb[sw], "neigh": neigh[sw]} for sw, (h, ifs) in sws.items()]
