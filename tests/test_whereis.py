"""Tests για το «Πού είναι συνδεδεμένο;» (whereis.py) — ψεύτικοι πελάτες SNMP, καθόλου δίκτυο."""
import json
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import snmp  # noqa: E402
import whereis as wi  # noqa: E402

SECRET = "s3cr3t-c0mm"


def mac_t(m):
    return tuple(int(x, 16) for x in m.split(":"))


def oid(base, *idx):
    return snmp.parse_oid(base) + tuple(idx)


class FakeClient:
    """Απαντά σε walk() από ένα λεξικό {OID ρίζα: [(index tuple, τιμή)]}."""
    TABLES = {}
    made = []

    def __init__(self, host, community, port, timeout, retries, bulk):
        self.host, self.community = host, community
        FakeClient.made.append((host, community))

    def walk(self, root, max_rows=2000):
        root = snmp.parse_oid(root)
        rows = FakeClient.TABLES.get((self.host, self.community), {}).get(root, [])
        return [(root + idx, v) for idx, v in rows]


class FakeSnmp:
    def __init__(self, targets, neigh=None):
        self.sim = False
        self.cfg = {"timeout": 1.0, "retries": 0}
        self.targets = snmp.normalize({"targets": targets})["targets"]
        self.lock = threading.Lock()
        self.res = {t["id"]: {"neigh": (neigh or {}).get(t["name"], [])} for t in self.targets}


class FakeState:
    def __init__(self, snmp_=None, hosts=None, arp=None, gateway=None):
        self.snmp, self.lock = snmp_, threading.Lock()
        self.hosts, self.arp_table, self.gateway = hosts or {}, arp or {}, gateway


def switch_tables(fdb, ifnames, base=None, q=None, status=None):
    t = {snmp.parse_oid(wi.IF_NAME): [((i,), n.encode()) for i, n in ifnames.items()],
         snmp.parse_oid(wi.IF_ALIAS): [((i,), b"") for i in ifnames],
         snmp.parse_oid(wi.FDB_PORT): [(mac_t(m), p) for m, p in fdb.items()],
         snmp.parse_oid(wi.FDB_STATUS): [(mac_t(m), s) for m, s in (status or {}).items()],
         snmp.parse_oid(wi.BASE_PORT_IFINDEX): [((bp,), ifx) for bp, ifx in (base or {}).items()]}
    if q:
        t[snmp.parse_oid(wi.QFDB_PORT)] = [((vlan,) + mac_t(m), p) for (vlan, m), p in q.items()]
    return t


def test_norm_mac_formats():
    for s in ("aa:bb:cc:dd:ee:0f", "AA-BB-CC-DD-EE-0F", "aabb.ccdd.ee0f", "AABBCCDDEE0F", "aa:bb:cc:dd:ee:f"):
        assert wi.norm_mac(s) == "aa:bb:cc:dd:ee:0f"
    assert wi.norm_mac("aa:bb:cc") is None and wi.norm_mac("192.168.1.1") is None and wi.norm_mac(None) is None


def test_parse_fdb_qbridge_vlan_and_dedup():
    m1, m2, mc, me = "00:11:22:33:44:01", "00:11:22:33:44:02", "01:00:5e:00:00:fb", "00:11:22:33:44:ff"
    q = {(30,) + mac_t(m1): 3, (10,) + mac_t(m2): 5}
    d1 = {mac_t(m1): 3, mac_t(m2): 5, mac_t(mc): 4, mac_t(me): 1}
    st = {mac_t(me): 4}  # self
    out = wi.parse_fdb(d1, st, {(3,): 10003, (5,): 10005}, q)
    by = {e["mac"]: e for e in out}
    assert set(by) == {m1, m2}  # multicast και self έξω, χωρίς διπλά από το BRIDGE-MIB
    assert by[m1]["vlan"] == 30 and by[m1]["ifindex"] == 10003 and by[m1]["bport"] == 3
    assert by[m2]["vlan"] == 10 and by[m2]["ifindex"] == 10005
    # χωρίς Q-BRIDGE: VLAN άγνωστο, bridge port χωρίς αντιστοίχιση → ως ifIndex
    out2 = wi.parse_fdb({mac_t(m1): 7})
    assert out2 == [{"mac": m1, "bport": 7, "ifindex": 7, "vlan": None}]


def _two_switch_world(neigh_from_snmp=True):
    """core (Gi0/1 → router, Gi0/2 → access) + access (Gi0/1 → core, Fa0/3 PC, Fa0/9 printer)."""
    router, pc, printer, nas = "00:00:00:00:00:01", "3c:22:fb:aa:bb:23", "00:1e:0b:40:40:40", "dc:a6:32:17:17:17"
    core_if = {1: "Gi0/1", 2: "Gi0/2", 11: "Fa0/1"}
    acc_if = {1: "Gi0/1", 13: "Fa0/3", 19: "Fa0/9"}
    FakeClient.TABLES = {
        ("10.0.0.2", SECRET): switch_tables({router: 1, pc: 2, printer: 2, nas: 11}, core_if,
                                            q={(10, router): 1, (10, pc): 2, (10, printer): 2, (20, nas): 11}),
        ("10.0.0.4", SECRET): switch_tables({router: 1, nas: 1, pc: 13, printer: 19}, acc_if,
                                            q={(10, router): 1, (20, nas): 1, (10, pc): 13, (10, printer): 19}),
    }
    neigh = {"core": [{"local_ifindex": 1, "remote_name": "gw", "chassis": router},
                      {"local_ifindex": 2, "remote_name": "access", "chassis": ""}],
             "access": [{"local_ifindex": 1, "remote_name": "core", "chassis": ""}]}
    sn = FakeSnmp([{"name": "core", "host": "10.0.0.2", "community": SECRET},
                   {"name": "access", "host": "10.0.0.4", "community": SECRET}], neigh if neigh_from_snmp else None)
    st = FakeState(sn, hosts={"10.0.0.23": {"kind": "local", "mac": pc, "names": {"macbook.local"}, "rdns": None},
                              "10.0.0.40": {"kind": "local", "mac": printer, "names": {"printer.local"}, "rdns": None}},
                   arp={"10.0.0.1": router, "10.0.0.17": nas}, gateway="10.0.0.1")
    w = wi.WhereIs(st, client_factory=FakeClient)
    w.refresh(wait=True)
    return w, dict(router=router, pc=pc, printer=printer, nas=nas)


def test_edge_selection_and_path_lookup_by_ip_and_name():
    w, m = _two_switch_world()
    r = w.lookup("10.0.0.23")
    assert r["found"] and r["mac"] == m["pc"] and r["name"] == "macbook.local"
    loc = r["location"]
    assert (loc["switch"], loc["port"], loc["vlan"], loc["uplink"], loc["confidence"]) == ("access", "Fa0/3", 10, False, "high")
    assert r["path"] == [{"switch": "core", "port": "Gi0/2", "kind": "uplink"}, {"switch": "access", "port": "Fa0/3", "kind": "edge"}]
    r2 = w.lookup("PRINTER")
    assert r2["found"] and r2["ip"] == "10.0.0.40" and r2["location"]["port"] == "Fa0/9"
    r3 = w.lookup("10.0.0.17")  # μόνο από ARP, στο core
    assert r3["location"]["switch"] == "core" and r3["location"]["vlan"] == 20


def test_uplink_by_lldp_and_router_is_itself():
    w, m = _two_switch_world()
    rows = w.table(all_rows=True)["rows"]
    ups = {(r["switch"], r["port"]) for r in rows if r["uplink"]}
    assert ("core", "Gi0/2") in ups and ("access", "Gi0/1") in ups and ("core", "Gi0/1") in ups
    r = w.lookup(m["router"].replace(":", "-").upper())
    assert r["location"]["switch"] == "core" and r["location"]["port"] == "Gi0/1" and r["location"]["confidence"] == "high"
    assert w.root == "core"


def test_lldp_walked_when_snmp_has_no_neighbours():
    w, m = _two_switch_world(neigh_from_snmp=False)
    # χωρίς κανέναν γείτονα: το Gi0/2 του core (2 MAC) μοιάζει με άκρη, αλλά κερδίζει η θύρα με τις λιγότερες MAC
    assert w.lookup(m["pc"])["location"]["port"] == "Fa0/3"
    assert not any(r["uplink"] for r in w.table(all_rows=True)["rows"] if r["switch"] == "core" and r["port"] == "Gi0/2")
    # walk του lldpRemTable (index timeMark.localPort.remIndex) όταν το snmp.py δεν έχει γείτονες
    FakeClient.TABLES[("10.0.0.2", SECRET)][oid(snmp.LLDP_REM, 9)] = [((0, 2, 1), b"access")]
    w.refresh(wait=True)
    assert any(r["uplink"] for r in w.table(all_rows=True)["rows"] if r["switch"] == "core" and r["port"] == "Gi0/2")
    assert w.lookup(m["pc"])["path"][0] == {"switch": "core", "port": "Gi0/2", "kind": "uplink"}


def test_many_macs_port_is_uplink_and_low_confidence():
    macs = [f"00:aa:00:00:00:{i:02x}" for i in range(1, 11)]
    FakeClient.TABLES = {("10.0.0.2", SECRET): switch_tables({mm: 5 for mm in macs}, {5: "Port 5"})}
    st = FakeState(FakeSnmp([{"name": "sw", "host": "10.0.0.2", "community": SECRET}]))
    w = wi.WhereIs(st, client_factory=FakeClient)
    w.refresh(wait=True)
    r = w.lookup(macs[0])
    assert r["found"] and r["location"]["uplink"] is True and r["location"]["confidence"] == "low"
    assert r["location"]["macs_on_port"] == 10
    assert w.table()["rows"] == []  # χαμηλή βεβαιότητα: όχι στον βασικό πίνακα
    assert len(w.table(all_rows=True)["rows"]) == 10


def test_infra_heuristic():
    assert wi.is_infra({"remote_name": "ap-living"}) and wi.is_infra({"remote_name": "SW-Floor2"})
    assert wi.is_infra({"remote_name": "x", "platform": "cisco WS-C2960-24TT-L"})
    assert not wi.is_infra({"remote_name": "pve"}) and not wi.is_infra(None)
    assert wi.is_infra({"remote_name": "pve"}, known={"pve"})


def test_community_never_in_output_even_on_error():
    w, m = _two_switch_world()

    class Boom(FakeClient):
        def walk(self, root, max_rows=2000):
            raise snmp.SnmpTimeout(f"{self.host}: χωρίς απάντηση")
    w.client_factory = Boom
    w.refresh(wait=True)
    blob = json.dumps([w.table(True), w.lookup(m["pc"]), w.lookup("printer"), w.lookup("")], ensure_ascii=False)
    assert SECRET not in blob
    sw = w.table()["switches"]
    assert sw and all(s["ok"] is False and s["error"] for s in sw)
    r = w.lookup(m["pc"])  # από το ιστορικό: τελευταία γνωστή θέση
    assert r["found"] and r["location"]["confidence"] == "low" and "τελευταία" in r["note"]


def test_no_snmp_targets_note_and_ambiguous_candidates():
    w = wi.WhereIs(FakeState(None))
    r = w.lookup("aa:bb:cc:dd:ee:ff")
    assert not r["found"] and "snmp" in r["note"].lower()
    d = wi.WhereIs(None, sim=True)
    r2 = d.lookup("pc-")
    assert not r2["found"] and 2 <= len(r2["candidates"]) <= 10


def test_demo_all_devices_located():
    w = wi.WhereIs(None, sim=True)
    for ip, mac, name, _v, sw, port, vlan in wi.DEMO_DEVICES:
        r = w.lookup(ip)
        assert r["found"] and r["mac"] == mac and r["demo"], ip
        assert (r["location"]["switch"], r["location"]["port"], r["location"]["vlan"]) == (sw, port, vlan), ip
    wifi = w.lookup("192.168.1.15")
    assert wifi["location"]["confidence"] == "medium" and wifi["note"] == "πίσω από AP σαλονιού (Wi‑Fi)"
    assert len(w.table()["rows"]) == len(wi.DEMO_DEVICES)
    assert {s["name"] for s in w.table()["switches"]} == {"core-sw", "access-sw-1"}
