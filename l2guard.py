"""🛡 Έλεγχος L2 με ένα κουμπί: υπάρχει δεύτερος (rogue) DHCP server; προσποιείται κάποιος τον router (ARP spoofing);

Τι κάνει (μόνο στο τοπικό LAN, αμυντικά):
  1. DHCP: στέλνει ΕΝΑ DHCPDISCOVER (broadcast) και μαζεύει ΟΛΑ τα DHCPOFFER για λίγα δευτερόλεπτα.
     Δεν στέλνει ποτέ REQUEST → δεν παίρνει διεύθυνση, δεν αλλάζει τίποτα στο δίκτυο.
  2. ARP: ρωτά «ποιος έχει την IP του router;» → αν απαντήσουν >1 MAC, ή η MAC διαφέρει από αυτή που είχαμε
     μάθει (arp_first), ή από τον πίνακα ARP του υπολογιστή → πιθανό Man-in-the-Middle.
  3. Παθητικά: όσα DHCP servers / ειδοποιήσεις ARP έχει ήδη δει το NetWatch.
Όλα μαζί με τη θεωρία CCNA (DHCP snooping, Dynamic ARP Inspection) και έτοιμο config για Cisco switch.
"""
import ipaddress
import os
import random
import re
import subprocess
import threading
import time

MIN_INTERVAL = 20


def _norm(m):
    m = str(m or "").lower().replace("-", ":")
    return ":".join(x.zfill(2) for x in m.split(":")) if re.match(r"^[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}$", m) else ""


class ScapyProber:
    """Τα πραγματικά πακέτα (χρειάζεται root, όπως η καταγραφή)."""

    def dhcp_discover(self, iface, timeout=4.0):
        from scapy.all import BOOTP, DHCP, IP, UDP, Ether, conf, get_if_hwaddr, srp
        conf.checkIPaddr = False
        mac = get_if_hwaddr(iface)
        xid = random.randint(1, 0xFFFFFFFF)
        pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
               / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")) + b"\x00" * 10, xid=xid, flags=0x8000)
               / DHCP(options=[("message-type", "discover"), ("param_req_list", [1, 3, 6, 15, 51, 54]), "end"]))
        ans, _ = srp(pkt, iface=iface, multi=True, timeout=timeout, verbose=0)
        out = []
        for _, r in ans:
            if not r.haslayer(BOOTP) or r[BOOTP].xid != xid or not r.haslayer(DHCP):
                continue
            opts = {o[0]: o[1:] for o in r[DHCP].options if isinstance(o, tuple)}
            if (opts.get("message-type") or [0])[0] != 2:  # 2 = OFFER
                continue
            first = lambda k: (opts.get(k) or [None])[0]  # noqa: E731
            out.append({"server": str(first("server_id") or r[IP].src), "mac": r[Ether].src, "ip_src": r[IP].src,
                        "offer": r[BOOTP].yiaddr, "router": str(first("router") or ""), "dns": [str(x) for x in (opts.get("name_server") or [])][:4],
                        "lease": first("lease_time"), "domain": (first("domain") or b"").decode("latin-1", "replace") if isinstance(first("domain"), bytes) else str(first("domain") or "")})
        return out

    def arp_who_has(self, iface, ip, timeout=2.0):
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), iface=iface, multi=True, timeout=timeout, verbose=0)
        return sorted({_norm(r.hwsrc) for _, r in ans if r.psrc == ip})

    def arp_cache(self):
        try:
            out = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return {}
        res = {}
        for m in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)", out):
            res[m.group(1)] = _norm(m.group(2))
        if not res:  # Windows: «  192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic»
            for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", out):
                res[m.group(1)] = _norm(m.group(2))
        return res


DEMO_OFFERS = [
    {"server": "192.168.1.1", "mac": "a4:2b:b0:11:22:33", "ip_src": "192.168.1.1", "offer": "192.168.1.57", "router": "192.168.1.1", "dns": ["192.168.1.1"], "lease": 86400, "domain": "home"},
    {"server": "192.168.0.1", "mac": "b0:be:76:aa:bb:cc", "ip_src": "192.168.0.1", "offer": "192.168.0.100", "router": "192.168.0.1", "dns": ["192.168.0.1"], "lease": 7200, "domain": ""},
]


class DemoProber:
    def dhcp_discover(self, iface, timeout=4.0):
        time.sleep(0.6)
        return [dict(o) for o in DEMO_OFFERS]

    def arp_who_has(self, iface, ip, timeout=2.0):
        return ["a4:2b:b0:11:22:33"]

    def arp_cache(self):
        return {"192.168.1.1": "a4:2b:b0:11:22:33"}


_CFG_EN = {"! DHCP snooping: μόνο η θύρα προς τον πραγματικό router/DHCP server δέχεται απαντήσεις DHCP":
           "! DHCP snooping: only the port toward the real router/DHCP server may send DHCP replies",
           "! Dynamic ARP Inspection: ελέγχει κάθε ARP με τον πίνακα του DHCP snooping":
           "! Dynamic ARP Inspection: checks every ARP against the DHCP snooping table",
           " description Uplink προς router / DHCP server": " description Uplink to router / DHCP server",
           " description Θύρες χρηστών (untrusted)": " description User ports (untrusted)",
           "! Έλεγχος: show ip dhcp snooping binding · show ip arp inspection statistics":
           "! Verify: show ip dhcp snooping binding · show ip arp inspection statistics"}


def switch_config(vlans="1", lang="el"):
    lines = [
        "! DHCP snooping: μόνο η θύρα προς τον πραγματικό router/DHCP server δέχεται απαντήσεις DHCP",
        "ip dhcp snooping",
        f"ip dhcp snooping vlan {vlans}",
        "no ip dhcp snooping information option",
        "!",
        "! Dynamic ARP Inspection: ελέγχει κάθε ARP με τον πίνακα του DHCP snooping",
        f"ip arp inspection vlan {vlans}",
        "!",
        "interface GigabitEthernet0/1",
        " description Uplink προς router / DHCP server",
        " ip dhcp snooping trust",
        " ip arp inspection trust",
        "!",
        "interface range GigabitEthernet0/2 - 24",
        " description Θύρες χρηστών (untrusted)",
        " ip dhcp snooping limit rate 15",
        " ip arp inspection limit rate 15",
        " spanning-tree portfast",
        " spanning-tree bpduguard enable",
        "!",
        "! Έλεγχος: show ip dhcp snooping binding · show ip arp inspection statistics",
        "end",
    ]
    return "\n".join(_CFG_EN.get(x, x) for x in lines) if lang == "en" else "\n".join(lines)


class L2Guard:
    def __init__(self, state, sim=False, prober=None, clock=time.time):
        self.state, self.sim, self.clock = state, sim, clock
        self.prober = prober or (DemoProber() if sim else ScapyProber())
        self.lock = threading.Lock()
        self.last, self.result = 0, None

    def _ctx(self):
        st = self.state
        gw = getattr(st, "gateway", None) or ("192.168.1.1" if self.sim else None)
        iface = getattr(st, "iface", None)
        with getattr(st, "lock", threading.RLock()):
            first = dict(getattr(st, "arp_first", {}) or {})
            seen = set(getattr(st, "dhcp_servers", set()) or set())
            alerts = [a for a in list(getattr(st, "alerts", []) or []) if isinstance(a, dict) and a.get("type", "").startswith(("Rogue DHCP", "ARP spoofing"))][-10:]
            hosts = getattr(st, "hosts", {}) or {}
            names = {ip: (h.get("alias") or next(iter(sorted(h.get("names") or [])), "") or h.get("vendor") or "") for ip, h in hosts.items() if isinstance(h, dict)}
        return gw, iface, first, seen, alerts, names

    def run(self):
        with self.lock:
            if self.result and self.clock() - self.last < MIN_INTERVAL:
                return dict(self.result, cached=True)
            self.last = self.clock()
        gw, iface, first, seen, alerts, names = self._ctx()
        r = {"t": self.clock(), "gateway": gw, "iface": iface, "checks": [], "offers": [], "arp": {}, "alerts": alerts,
             "config": switch_config(), "config_en": switch_config(lang="en"), "demo": self.sim}
        # ── 1. DHCP ──
        try:
            offers = self.prober.dhcp_discover(iface)
            r["offers"] = offers
            servers = sorted({o["server"] for o in offers})
            for o in offers:
                o["name"] = names.get(o["server"]) or names.get(o["ip_src"]) or ""
                o["is_gw"] = o["server"] == gw or o["ip_src"] == gw
            if not offers:
                r["checks"].append({"id": "dhcp", "level": "warn", "inconclusive": True, "el": "Κανένας DHCP server δεν απάντησε (μπορεί να είναι κλειστός, σε άλλο VLAN, ή το δίκτυο να έχει στατικές IP).",
                                    "en": "No DHCP server answered (it may be off, on another VLAN, or the network uses static IPs)."})
            elif len(servers) == 1 and (servers[0] == gw or offers[0]["router"] == gw):
                r["checks"].append({"id": "dhcp", "level": "ok", "el": f"Ένας DHCP server ({servers[0]}) — αυτός που περιμένουμε.", "en": f"One DHCP server ({servers[0]}) — the expected one."})
            elif len(servers) == 1:
                r["checks"].append({"id": "dhcp", "level": "warn", "el": f"Ο DHCP server είναι ο {servers[0]}, όχι ο router σου ({gw}). Αν δεν το έχεις ρυθμίσει εσύ (π.χ. Pi-hole), έλεγξέ το.",
                                    "en": f"The DHCP server is {servers[0]}, not your router ({gw}). If you didn’t set this up (e.g. Pi-hole), check it."})
            else:
                rogue = [o for o in offers if not o["is_gw"]]
                txt = ", ".join(f"{o['server']} ({o['mac']})" for o in rogue)
                r["checks"].append({"id": "dhcp", "level": "bad", "el": f"{len(servers)} DHCP servers απάντησαν! Ύποπτος: {txt}. Συσκευές μπορεί να πάρουν λάθος gateway/DNS.",
                                    "en": f"{len(servers)} DHCP servers answered! Suspect: {txt}. Devices may get a wrong gateway/DNS."})
            r["dhcp_seen"] = sorted(seen)
        except Exception as e:  # noqa: BLE001 — π.χ. χωρίς root
            r["checks"].append({"id": "dhcp", "level": "err", "el": "Δεν έγινε ο έλεγχος DHCP: " + str(e)[:160], "en": "DHCP check failed: " + str(e)[:160]})
        # ── 2. ARP (router) ──
        ok_gw = False
        try:
            ok_gw = bool(gw) and ipaddress.ip_address(gw).is_private
        except ValueError:
            pass
        if not ok_gw:
            r["checks"].append({"id": "arp", "level": "warn", "inconclusive": True, "el": "Δεν ξέρω ιδιωτική IP router για να ελέγξω το ARP.", "en": "No private router IP known to check ARP."})
        else:
            try:
                macs = self.prober.arp_who_has(iface, gw)
                cache = self.prober.arp_cache().get(gw, "")
                trusted = _norm(first.get(gw, ""))
                r["arp"] = {"replies": macs, "cache": cache, "trusted": trusted}
                if len(macs) > 1:
                    r["checks"].append({"id": "arp", "level": "bad", "el": f"Στο «ποιος είναι ο router {gw};» απάντησαν {len(macs)} MAC: {', '.join(macs)} — κλασικό σημάδι ARP spoofing (MITM).",
                                        "en": f"{len(macs)} MACs answered “who is router {gw}?”: {', '.join(macs)} — a classic sign of ARP spoofing (MITM)."})
                elif not macs:
                    r["checks"].append({"id": "arp", "level": "warn", "inconclusive": True, "el": f"Ο router {gw} δεν απάντησε στο ARP.", "en": f"Router {gw} did not answer ARP."})
                elif trusted and macs[0] != trusted:
                    r["checks"].append({"id": "arp", "level": "bad", "el": f"Ο router {gw} απαντά τώρα με MAC {macs[0]}, ενώ στην αρχή ήταν {trusted}. Αν δεν άλλαξες router, κάποιος παριστάνει τον router.",
                                        "en": f"Router {gw} now answers with MAC {macs[0]}, but at first it was {trusted}. If you didn’t replace the router, someone is impersonating it."})
                elif cache and cache != macs[0]:
                    r["checks"].append({"id": "arp", "level": "bad", "el": f"Ο πίνακας ARP του υπολογιστή σου έχει για τον router {cache}, αλλά ο router απαντά με {macs[0]} — ο πίνακας έχει «δηλητηριαστεί».",
                                        "en": f"Your computer’s ARP table has {cache} for the router, but the router answers with {macs[0]} — the table has been poisoned."})
                else:
                    r["checks"].append({"id": "arp", "level": "ok", "el": f"Ο router {gw} έχει μία MAC ({macs[0]}), ίδια παντού.", "en": f"Router {gw} has one MAC ({macs[0]}), consistent everywhere."})
            except Exception as e:  # noqa: BLE001
                r["checks"].append({"id": "arp", "level": "err", "el": "Δεν έγινε ο έλεγχος ARP: " + str(e)[:160], "en": "ARP check failed: " + str(e)[:160]})
        # ── 3. ιστορικό ──
        if alerts:
            r["checks"].append({"id": "hist", "level": "bad", "el": f"Το NetWatch έχει ήδη δει {len(alerts)} ειδοποιήσεις rogue DHCP / ARP spoofing.",
                                "en": f"NetWatch has already seen {len(alerts)} rogue DHCP / ARP spoofing alerts."})
        lv = [c["level"] for c in r["checks"]]
        r["verdict"] = "bad" if "bad" in lv else "warn" if ("warn" in lv or "err" in lv) else "ok"
        with self.lock:
            self.result = r
        return r

    def view(self):
        return self.result or {"never": True, "config": switch_config(), "config_en": switch_config(lang="en"), "demo": self.sim}
