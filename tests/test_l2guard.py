"""Tests για τον έλεγχο rogue DHCP / ARP spoofing (l2guard.py). Ψεύτικος prober — κανένα πραγματικό πακέτο."""
import os
import sys
import threading
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import l2guard  # noqa: E402

GW, GWMAC = "192.168.1.1", "a4:2b:b0:11:22:33"


def offer(server, mac, router=None):
    return {"server": server, "mac": mac, "ip_src": server, "offer": "192.168.1.77", "router": router or server, "dns": [server], "lease": 3600, "domain": ""}


class Fake:
    def __init__(self, offers=(), arp=(GWMAC,), cache=None, boom=None):
        self.offers, self.arp, self.cache, self.boom, self.calls = list(offers), list(arp), cache, boom, []

    def dhcp_discover(self, iface, timeout=4.0):
        self.calls.append(("dhcp", iface))
        if self.boom:
            raise PermissionError(self.boom)
        return [dict(o) for o in self.offers]

    def arp_who_has(self, iface, ip, timeout=2.0):
        self.calls.append(("arp", ip))
        return self.arp

    def arp_cache(self):
        return self.cache if self.cache is not None else {GW: GWMAC}


def state(first=None, alerts=()):
    return types.SimpleNamespace(lock=threading.RLock(), gateway=GW, iface="en0", arp_first=first or {GW: GWMAC}, dhcp_servers={GW},
                                 alerts=list(alerts), hosts={"192.168.1.50": {"alias": "Παλιός router"}})


def lv(r, cid):
    return next(c["level"] for c in r["checks"] if c["id"] == cid)


def test_clean_network():
    r = l2guard.L2Guard(state(), prober=Fake([offer(GW, GWMAC)])).run()
    assert r["verdict"] == "ok" and lv(r, "dhcp") == "ok" and lv(r, "arp") == "ok" and r["offers"][0]["is_gw"]
    assert "ip dhcp snooping trust" in r["config"] and "ip arp inspection vlan" in r["config"]


def test_rogue_dhcp_named():
    f = Fake([offer(GW, GWMAC), offer("192.168.1.50", "b0:be:76:aa:bb:cc", router="192.168.1.50")])
    r = l2guard.L2Guard(state(), prober=f).run()
    assert r["verdict"] == "bad" and lv(r, "dhcp") == "bad" and "192.168.1.50" in next(c["el"] for c in r["checks"] if c["id"] == "dhcp")
    rogue = [o for o in r["offers"] if not o["is_gw"]][0]
    assert rogue["name"] == "Παλιός router"


def test_arp_spoof_variants():
    assert lv(l2guard.L2Guard(state(), prober=Fake([offer(GW, GWMAC)], arp=[GWMAC, "de:ad:be:ef:00:01"])).run(), "arp") == "bad"
    assert lv(l2guard.L2Guard(state(), prober=Fake([offer(GW, GWMAC)], arp=["de:ad:be:ef:00:01"], cache={})).run(), "arp") == "bad"   # άλλαξε από την αρχική
    r = l2guard.L2Guard(state(first={}), prober=Fake([offer(GW, GWMAC)], cache={GW: "de:ad:be:ef:00:01"})).run()
    assert lv(r, "arp") == "bad" and "δηλητηρ" in next(c["el"] for c in r["checks"] if c["id"] == "arp")


def test_errors_rate_limit_and_history():
    f = Fake(boom="Operation not permitted")
    g = l2guard.L2Guard(state(alerts=[{"type": "ARP spoofing (ROUTER)"}, {"type": "Port scan"}]), prober=f)
    r = g.run()
    assert lv(r, "dhcp") == "err" and lv(r, "hist") == "bad" and len(r["alerts"]) == 1
    assert g.run().get("cached") and len([c for c in f.calls if c[0] == "dhcp"]) == 1


def test_no_private_gateway_skips_arp():
    st = state()
    st.gateway = "8.8.8.8"
    f = Fake([offer(GW, GWMAC)])
    r = l2guard.L2Guard(st, prober=f).run()
    assert lv(r, "arp") == "warn" and not [c for c in f.calls if c[0] == "arp"]


def test_demo_finds_rogue_without_packets():
    r = l2guard.L2Guard(state(), sim=True).run()
    assert r["demo"] and r["verdict"] == "bad" and len(r["offers"]) == 2
