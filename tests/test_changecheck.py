"""Tests για τον έλεγχο πριν/μετά από αλλαγή (changecheck.py) — χωρίς πραγματικό δίκτυο."""
import json
import os
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import changecheck  # noqa: E402

T0 = 1_700_000_000.0
GW = "192.168.1.1"


def snap(hosts=None, ports=None, gw_mac="aa:bb:cc:00:00:01", dns_ok=True, net_ok=True, ip="192.168.1.23"):
    hosts = hosts if hosts is not None else {GW: (True, 2.0), "192.168.1.40": (True, 3.0), "192.168.1.17": (True, 3.0)}
    return {"hosts": {k: {"name": None, "gw": k == GW, "up": u, "rtt": r if u else None} for k, (u, r) in hosts.items()},
            "ports": {k: {"name": None, "open": o} for k, o in (ports or {"192.168.1.33:554": True}).items()},
            "gateway": {"ip": GW, "mac": gw_mac},
            "dns": {"google.com@system": {"name": "google.com", "server": "system", "ok": dns_ok, "ip": "1.2.3.4", "ms": 4}},
            "internet": {"tcp:1.1.1.1:443": {"name": "1.1.1.1", "ok": net_ok, "ms": 12}},
            "local": {"iface": "en0", "ip": ip, "prefix": 24, "mtu": 1500, "gateway": GW, "dns": [GW]}}


def mk(a, b):
    c = changecheck.ChangeCheck(None, clock=lambda: T0)
    for i, (lab, s) in enumerate((("Πριν", a), ("Μετά", b))):
        s.update(label=lab, t=T0 + i * 600, took_ms=100)
        c._add(s)
    return c, c.compare(1, 2)


def item(r, kind, key):
    return next(i for i in r["items"] if i["kind"] == kind and i["key"] == key)


def test_identical_is_ok():
    _, r = mk(snap(), snap())
    assert r["verdict"] == "ok"
    assert r["counts"]["lost"] == r["counts"]["new"] == r["counts"]["slower"] == 0
    assert r["summary"].startswith("Καμία αλλαγή")
    assert all(i["status"] == "same" for i in r["items"])


def test_lost_host_high_and_port_closed_med():
    b = snap(hosts={GW: (True, 2.0), "192.168.1.40": (False, None), "192.168.1.17": (True, 3.0)},
             ports={"192.168.1.33:554": False})
    _, r = mk(snap(), b)
    h = item(r, "host", "192.168.1.40")
    assert (h["status"], h["sev"]) == ("lost", "high")
    p = item(r, "port", "192.168.1.33:554")
    assert (p["status"], p["sev"]) == ("lost", "med")
    assert r["verdict"] == "bad"
    assert "1 συσκευή δεν απαντά πια" in r["summary"] and "1 θύρα έκλεισε" in r["summary"]
    assert r["items"][0]["sev"] == "high"  # ταξινόμηση κατά σοβαρότητα


def test_gateway_lost_is_bad():
    b = snap(hosts={GW: (False, None), "192.168.1.40": (True, 3.0), "192.168.1.17": (True, 3.0)})
    _, r = mk(snap(), b)
    g = item(r, "host", GW)
    assert g["status"] == "lost" and g["sev"] == "high" and "router" in g["note"]
    assert r["verdict"] == "bad" and "ο router δεν απαντά" in r["summary"].lower()


def test_slower_rule():
    b = snap(hosts={GW: (True, 2.0), "192.168.1.40": (True, 3.0), "192.168.1.17": (True, 48.0)})
    _, r = mk(snap(), b)
    s = item(r, "host", "192.168.1.17")
    assert (s["status"], s["sev"]) == ("slower", "low")
    assert r["verdict"] == "warn"
    # ×2 αλλά όχι +20 ms → ίδιο
    b2 = snap(hosts={GW: (True, 2.0), "192.168.1.40": (True, 3.0), "192.168.1.17": (True, 9.0)})
    _, r2 = mk(snap(), b2)
    assert item(r2, "host", "192.168.1.17")["status"] == "same"


def test_gateway_mac_change_high():
    _, r = mk(snap(), snap(gw_mac="de:ad:be:ef:00:01"))
    g = item(r, "gateway", "mac")
    assert (g["status"], g["sev"]) == ("changed", "high") and "ARP" in g["note"]
    assert r["verdict"] == "bad"


def test_dns_and_internet_lost_high():
    _, r = mk(snap(), snap(dns_ok=False, net_ok=False))
    assert item(r, "dns", "google.com@system")["sev"] == "high"
    assert item(r, "internet", "tcp:1.1.1.1:443")["status"] == "lost"
    assert r["verdict"] == "bad"


def test_new_host_and_port_are_info():
    b = snap(hosts={GW: (True, 2.0), "192.168.1.40": (True, 3.0), "192.168.1.17": (True, 3.0), "192.168.1.99": (True, 5.0)},
             ports={"192.168.1.33:554": True, "192.168.1.17:22": True})
    _, r = mk(snap(), b)
    assert item(r, "host", "192.168.1.99")["sev"] == "info" and item(r, "host", "192.168.1.99")["status"] == "new"
    assert item(r, "port", "192.168.1.17:22")["status"] == "new"
    assert r["verdict"] == "ok" and r["counts"]["new"] == 2


def test_private_targets_enforced():
    c = changecheck.ChangeCheck(None, sim=True)
    for bad in (["8.8.8.8"], ["127.0.0.1"], ["192.168.1.255"], ["not-an-ip"], ["10.0.0.%d" % i for i in range(65)]):
        with pytest.raises(ValueError):
            c.snapshot("Πριν", bad)
    with pytest.raises(ValueError):
        c.snapshot("x" * 41)
    assert not changecheck.allowed("93.184.216.34") and changecheck.allowed("1.1.1.1") and changecheck.allowed("10.1.2.3")
    assert changecheck.tcp("93.184.216.34", 443)["state"] == "denied"
    assert changecheck.ping("93.184.216.34")["err"] == "denied"
    assert changecheck.http_probe("http://example.com/")["err"] == "denied"


def test_demo_before_after_regression_and_view_shape(monkeypatch):
    monkeypatch.setattr(changecheck, "DEMO_DELAY", 0.1)
    c = changecheck.ChangeCheck(None, sim=True)
    v = c.view()
    assert v["demo"] and v["status"] == "idle" and v["running_label"] is None
    assert [s["label"] for s in v["snapshots"]] == ["Μετά", "Πριν"]
    assert set(v["snapshots"][0]) == {"id", "label", "t", "hosts", "ports", "took_ms"}
    lc = v["last_compare"]
    assert lc and lc["a"]["label"] == "Πριν" and lc["b"]["label"] == "Μετά"
    assert item(lc, "host", "192.168.1.40")["status"] == "lost"
    assert item(lc, "port", "192.168.1.33:554")["status"] == "lost"
    assert item(lc, "host", "192.168.1.17")["status"] == "slower"
    assert any(i["status"] == "new" and i["kind"] == "host" for i in lc["items"])
    for i in lc["items"]:
        assert set(i) >= {"kind", "key", "name", "before", "after", "status", "sev", "note"}
    # νέο demo στιγμιότυπο = αντίγραφο του τελευταίου (η ιστορία μένει ίδια)
    assert c.snapshot("Μετά 2")["ok"]
    assert c.snapshot("Μετά 3").get("error")  # τρέχει ήδη
    for _ in range(100):
        if c.view()["status"] == "idle":
            break
        time.sleep(0.02)
    v = c.view()
    assert len(v["snapshots"]) == 3 and v["snapshots"][0]["label"] == "Μετά 2"
    assert item(v["last_compare"], "host", "192.168.1.40")["status"] == "lost"
    assert c.delete(v["snapshots"][0]["id"])["ok"] and c.delete(999).get("error")
    json.dumps(v)


def test_live_collect_monkeypatched(monkeypatch, tmp_path):
    """Live στιγμιότυπο με ψεύτικα probes: μόνο ιδιωτικοί στόχοι, αποθήκευση JSON."""
    calls = []
    monkeypatch.setattr(changecheck, "ping", lambda ip, **k: (calls.append(ip), {"ok": ip != "192.168.1.40", "avg": 2.5})[1])
    monkeypatch.setattr(changecheck, "tcp", lambda ip, p, timeout=1.0: (calls.append(ip), {"state": "open", "ms": 1.0})[1])
    monkeypatch.setattr(changecheck, "sys_resolve", lambda n, t=2.0: {"ok": True, "ip": "1.2.3.4", "ms": 3, "err": None})
    monkeypatch.setattr(changecheck, "dns_query", lambda n, s, t=1.5: {"ok": True, "ip": "1.2.3.4", "ms": 9, "err": None})
    monkeypatch.setattr(changecheck, "http_probe", lambda u, t=3.0: {"status": 204, "ms": 20})
    monkeypatch.setattr(changecheck, "local_info", lambda sim=False: {"iface": "en0", "ip": "192.168.1.23", "prefix": 24,
                                                                      "mtu": 1500, "gateway": GW, "dns": [GW], "kind": None})
    monkeypatch.setattr(changecheck.shutil, "which", lambda x: "/sbin/ping")

    class St:
        gateway, me = GW, {"192.168.1.23"}
        arp_table = {GW: "aa:bb:cc:00:00:01"}
        scan_info = {"192.168.1.40": {80: {}, 9100: {}}}
        hosts = {ip: {"ip": ip, "kind": k, "last": 1, "names": set(), "ports": {}, "rdns": None}
                 for ip, k in ((GW, "local"), ("192.168.1.40", "local"), ("192.168.1.23", "local"),
                               ("8.8.4.4", "public"), ("192.168.1.255", "bcast"))}
    path = str(tmp_path / "cc.json")
    c = changecheck.ChangeCheck(St(), path=path)
    s = c.collect()
    assert set(s["hosts"]) == {GW, "192.168.1.40"}
    assert s["hosts"]["192.168.1.40"]["up"] is True  # ping απέτυχε, αλλά TCP απάντησε
    assert "192.168.1.40:80" in s["ports"] and "192.168.1.40:9100" not in s["ports"]
    assert s["gateway"] == {"ip": GW, "mac": "aa:bb:cc:00:00:01"}
    assert all(changecheck.allowed(ip) for ip in calls) and "8.8.4.4" not in calls
    s.update(label="Πριν", t=T0, took_ms=5)
    c._add(s)
    assert json.load(open(path))["snaps"][0]["label"] == "Πριν"
    assert changecheck.ChangeCheck(St(), path=path).view()["snapshots"][0]["label"] == "Πριν"
