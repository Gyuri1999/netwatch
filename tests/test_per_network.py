"""🧭 Κάθε δίκτυο (MAC του router) κρατά δικές του σαρώσεις — σπίτι και εργαστήριο έχουν και τα δύο 192.168.1.x."""
import json
import time

import netwatch as nw
import pentest

HOME, LAB = "aabbcc000001", "001daa0414fc"


def _scan(sc, hosts):
    sc.sim = lambda set_: [dict(h, services=list(h.get("services", []))) for h in hosts]
    sc.start("192.168.1.0/24")
    for _ in range(200):
        if sc.status().get("status") == "done":
            return sc.status()
        time.sleep(0.01)
    raise AssertionError("scan did not finish")


def _h(ip, mac, ports=()):
    return {"ip": ip, "mac": mac, "services": [{"port": p, "proto": "tcp"} for p in ports]}


def test_two_networks_with_same_ips_keep_separate_scans(tmp_path):
    sc = pentest.LanScanner(scan_dir=str(tmp_path))
    sc._enrich = lambda hosts, udp, sim=False: None
    net = {"id": HOME}
    sc.net_fn = lambda: net["id"]
    _scan(sc, [_h("192.168.1.1", "aa:bb:cc:00:00:01", [80]), _h("192.168.1.248", "aa:bb:cc:00:00:f8")])
    net["id"] = LAB  # μετακίνηση στο εργαστήριο: ίδιο subnet, άλλος router
    st = _scan(sc, [_h("192.168.1.1", "00:1d:aa:04:14:fc", [23]), _h("192.168.1.13", "2c:cf:67:83:56:37")])
    assert st["net"] == LAB and st["diff"] is None  # 1η σάρωση εδώ: καμία «σύγκριση» με το σπίτι
    assert sc.last_result()["net"] == LAB
    net["id"] = HOME  # πίσω στο σπίτι: η σύγκριση γίνεται με την προηγούμενη σάρωση του σπιτιού
    st = _scan(sc, [_h("192.168.1.1", "aa:bb:cc:00:00:01", [80])])
    assert st["diff"]["gone_hosts"] == ["192.168.1.248"] and st["diff"]["new_hosts"] == []
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([f"last-{HOME}.json", f"last-{LAB}.json", f"prev-{HOME}.json"])


def test_last_result_never_returns_another_networks_scan(tmp_path):
    sc = pentest.LanScanner(scan_dir=str(tmp_path))
    sc._enrich = lambda hosts, udp, sim=False: None
    net = {"id": HOME}
    sc.net_fn = lambda: net["id"]
    _scan(sc, [_h("192.168.1.1", "aa:bb:cc:00:00:01", [80])])
    net["id"] = LAB
    assert sc.last_result() is None


def test_legacy_shared_scan_is_kept_only_for_its_own_router(tmp_path):
    legacy = {"target": "192.168.1.0/24", "finished": 1, "hosts": [_h("192.168.1.1", "00:1d:aa:04:14:fc", [21])]}
    (tmp_path / "last.json").write_text(json.dumps(legacy))
    for net_id, diff_expected in ((HOME, False), (LAB, True)):
        sc = pentest.LanScanner(scan_dir=str(tmp_path))
        sc._enrich = lambda hosts, udp, sim=False: None
        sc.net_fn = lambda n=net_id: n
        st = _scan(sc, [_h("192.168.1.1", "00:1d:aa:04:14:fc", [21, 23])])
        assert (st["diff"] is not None) == diff_expected
    assert st["diff"]["new_ports"] == [{"ip": "192.168.1.1", "port": 23, "proto": "tcp"}]


def test_net_id_from_router_mac():
    s = nw.NetState("demo", "demo0", ["192.168.1.10"], "192.168.1.1", geo=False, rdns=False)
    assert s.net_id() is None
    s.arp_first["192.168.1.1"] = "00:1d:aa:04:14:fc"
    assert s.net_id() == LAB
    s.arp_table["192.168.1.1"] = "AA-BB-CC-00-00-01"  # ό,τι λέει τώρα ο πίνακας ARP έχει προτεραιότητα
    assert s.net_id() == HOME
