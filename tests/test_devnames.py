"""Tests για τα ονόματα συσκευών (devnames.py) και το πώς φαίνονται σε detect/netdocs."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import devnames  # noqa: E402
import netdocs  # noqa: E402
import netwatch as nw  # noqa: E402

MAC = "AA-BB-CC-00-11-22"


def test_set_get_delete():
    dn = devnames.DevNames()
    r = dn.set({"mac": MAC, "ip": "192.168.68.59", "name": "Κινητό Μαρίας", "type": "phone", "note": "σαλόνι"})
    assert r["ok"] and r["key"] == "aa:bb:cc:00:11:22"
    e = dn.get("aa:bb:cc:00:11:22", "192.168.68.59")
    assert e["name"] == "Κινητό Μαρίας" and e["type"] == "phone" and e["note"] == "σαλόνι"
    assert dn.get(MAC.lower().replace("-", ":")) is e
    assert dn.set({"mac": MAC, "name": "", "type": "", "note": ""})["entry"] is None
    assert dn.get(MAC) is None and dn.all() == {}


def test_ip_key_moves_to_mac():
    dn = devnames.DevNames()
    assert dn.set({"ip": "192.168.1.50", "name": "TV"})["key"] == "ip:192.168.1.50"
    assert dn.get(None, "192.168.1.50")["name"] == "TV"
    dn.set({"mac": MAC, "ip": "192.168.1.50", "name": "TV σαλονιού"})
    assert list(dn.all()) == ["aa:bb:cc:00:11:22"]


def test_validation():
    dn = devnames.DevNames()
    assert "error" in dn.set({"ip": "8.8.8.8", "name": "x"})
    assert "error" in dn.set({"name": "χωρίς κλειδί"})
    assert "error" in dn.set({"mac": "zz:zz", "name": "x"})
    r = dn.set({"mac": MAC, "name": "a\x00b\nc" + "x" * 100, "type": "spaceship", "note": "ok\x07"})
    e = r["entry"]
    assert e["name"] == "abc" + "x" * 37 and len(e["name"]) == devnames.NAME_MAX
    assert e["type"] == "" and e["note"] == "ok"
    assert dn.set({"mac": MAC, "type": "unknown"})["entry"] is None  # «unknown» δεν είναι επιλογή


def test_persistence_and_bulk(tmp_path):
    p = tmp_path / "devnames.json"
    saved = []
    dn = devnames.DevNames(str(p), on_save=saved.append)
    r = dn.bulk([{"mac": MAC, "name": "Pi"}, {"ip": "192.168.1.9", "type": "printer"}, {"ip": "1.1.1.1", "name": "x"}, "junk"])
    assert r["saved"] == 2 and len(r["errors"]) == 2 and saved == [str(p)]
    raw = json.loads(p.read_text(encoding="utf-8"))
    assert raw["devices"]["aa:bb:cc:00:11:22"]["name"] == "Pi"
    p.write_text(json.dumps({"devices": dict(raw["devices"], **{"bad key": {"name": "x"}})}), encoding="utf-8")
    dn2 = devnames.DevNames(str(p))
    assert set(dn2.all()) == {"aa:bb:cc:00:11:22", "ip:192.168.1.9"}
    v = dn2.view()
    assert v["devices"]["ip:192.168.1.9"]["type"] == "printer"
    ids = [t["id"] for t in v["types"]]
    assert "phone" in ids and "unknown" not in ids
    devnames.DevNames(str(tmp_path / "missing.json"))  # δεν υπάρχει αρχείο → άδειο, όχι σφάλμα


def _state():
    s = nw.NetState("test", "test0", ["192.168.1.50"], "192.168.1.1", geo=False, rdns=False)
    h = s.host("192.168.1.77", 1_700_000_000.0)
    h["mac"] = "aa:bb:cc:00:11:22"
    s.arp_table["192.168.1.88"] = "aa:bb:cc:00:11:33"
    return s, h


def test_detect_and_netdocs_use_names():
    s, h = _state()
    before = s._dtype(h)
    assert "alias" not in before
    s.devnames = devnames.DevNames()
    s.devnames.set({"mac": MAC, "name": "Κάμερα αυλής", "type": "camera", "note": "έξω"})
    s.devnames.set({"mac": "aa:bb:cc:00:11:33", "name": "Εκτυπωτής"})
    d = s._dtype(h)
    assert d["alias"] == "Κάμερα αυλής" and d["dtype"] == "camera" and d["dicon"] == "📷" and d["note"] == "έξω"
    hosts = netdocs._collect_hosts(s)
    assert hosts["192.168.1.77"]["name"] == "Κάμερα αυλής" and hosts["192.168.1.77"]["icon"] == "📷"
    assert hosts["192.168.1.88"]["name"] == "Εκτυπωτής"
    assert "devnames" in nw.NetState.KEEP  # επιβιώνει του reset της κατάστασης
