"""Tests για το διάγραμμα δικτύου (topomap.py) — χωρίς πραγματικό δίκτυο (ψεύτικα ping/traceroute/DNS)."""
import os
import sys
import threading
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import topomap  # noqa: E402

T0 = 1_795_000_000.0
DOC = {
    "devices": [{"name": "gw", "host": "192.168.1.1", "role": "router", "model": "hEX"},
                {"name": "core", "host": "192.168.1.2", "role": "switch", "model": "2960"},
                {"name": "ap-1", "host": "192.168.1.3", "role": "ap"}],
    "links": [{"a": "gw", "a_port": "ether2", "b": "core", "b_port": "Gi0/1"},
              {"a": "core", "a_port": "Gi0/5", "b": "ap-1", "b_port": "eth0"}],
    "hosts": [{"ip": "192.168.1.23", "name": "my-mac", "switch": "core", "port": "Gi0/3", "vlan": 10, "last": T0},
              {"ip": "192.168.1.40", "name": "printer", "switch": "core", "port": "Gi0/9", "vlan": 10, "last": T0 - 3600},
              {"ip": "192.168.1.50", "name": "phone", "switch": "", "port": "", "vlan": None, "last": T0}],
}
TRACE = [{"n": 1, "ip": "192.168.1.1"}, {"n": 2, "ip": "192.168.100.1"}, {"n": 3, "ip": "100.70.0.1"},
         {"n": 4, "ip": "62.1.1.1"}, {"n": 5, "ip": "1.1.1.1"}]


def ok(ms=1.0):
    return {"sent": 3, "recv": 3, "loss": 0.0, "med": ms}


DOWN = {"sent": 3, "recv": 0, "loss": 100.0, "med": None}


def make(down=(), dns_ok=True, slow=()):
    st = types.SimpleNamespace(gateway="192.168.1.1", me={"192.168.1.23"}, lock=threading.RLock(), home={"isp": "Demo ISP"})
    pinged = []

    def ping(h):
        pinged.append(h)
        if h in down:
            return DOWN
        return ok(400.0) if h in slow else ok()
    tm = topomap.TopoMap(st, pinger=ping, tracer=lambda: TRACE, clock=lambda: T0,
                         resolver=lambda: {"ok": dns_ok, "ms": 5.0} if dns_ok else {"ok": False})
    tm._doc = lambda: DOC
    return tm, pinged


def run(tm):
    r = tm.run()
    assert r["ok"]
    assert tm.wait(10)
    return tm.view()


def nodes(v):
    return {n["id"]: n for n in v["graph"]["nodes"]}


def test_graph_shape_and_all_ok():
    tm, pinged = make()
    v = run(tm)
    n = nodes(v)
    assert n["router"]["parent"] == "hop:192.168.100.1"
    assert n["hop:192.168.100.1"]["kind"] == "modem" and n["hop:100.70.0.1"]["label"] == "CGNAT"
    assert n["isp"]["ip"] == "62.1.1.1" and n["isp"]["parent"] == "internet"
    assert n["dev:192.168.1.2"]["parent"] == "router" and n["dev:192.168.1.2"]["port"] == "ether2"
    assert n["dev:192.168.1.3"]["parent"] == "dev:192.168.1.2"
    me = n["h:192.168.1.23"]
    assert me["kind"] == "me" and me["parent"] == "dev:192.168.1.2" and me["port"] == "Gi0/3"
    assert n["h:192.168.1.40"]["status"] == "idle"          # δεν φάνηκε την τελευταία ώρα
    assert n["h:192.168.1.50"]["parent"] == "router"        # άγνωστη θύρα → κάτω από το router (μαντεψιά)
    assert v["path"][:3] == ["h:192.168.1.23", "dev:192.168.1.2", "router"] and v["path"][-1] == "dns"
    assert v["diag"]["level"] == "ok"
    # ping μόνο σε ιδιωτικές IP + στη δική μας διαδρομή προς το 1.1.1.1 — όχι στις τελικές συσκευές
    assert "192.168.1.40" not in pinged and "1.1.1.1" in pinged and "62.1.1.1" in pinged


def test_quiet_hop_is_not_a_fault():
    tm, _ = make(down={"100.70.0.1"})
    v = run(tm)
    assert nodes(v)["hop:100.70.0.1"]["status"] == "quiet"
    assert v["diag"]["level"] == "ok"


def test_isp_fault_points_after_modem():
    tm, _ = make(down={"62.1.1.1", "1.1.1.1", "100.70.0.1"}, dns_ok=False)
    v = run(tm)
    d = v["diag"]
    assert d["level"] == "bad" and d["prev"] == "hop:192.168.100.1"
    assert "modem" in d["title"]["en"].lower() or "Modem" in d["title"]["en"]
    n = nodes(v)
    assert n["internet"]["status"] == "unreach" and n["dns"]["status"] == "unreach"   # πέρα από τη βλάβη = άγνωστο
    assert d["steps"]


def test_switch_fault_blames_my_switch_not_router():
    tm, _ = make(down={"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.100.1", "100.70.0.1", "62.1.1.1", "1.1.1.1"},
                 dns_ok=False)
    v = run(tm)
    assert v["diag"]["node"] == "dev:192.168.1.2" and v["diag"]["prev"] == "h:192.168.1.23"
    assert nodes(v)["router"]["status"] == "unreach"
    assert not [i for i in v["issues"] if i["level"] == "bad"]   # τα υπόλοιπα «κόκκινα» είναι συνέπεια, όχι ξεχωριστά προβλήματα


def test_dns_only_fault():
    tm, _ = make(dns_ok=False)
    v = run(tm)
    assert v["diag"]["node"] == "dns" and v["diag"]["prev"] == "internet"
    assert "1.1.1.1" in v["diag"]["steps"][0]["en"]


def test_slow_isp_is_warning_and_other_ap_down_is_issue():
    tm, _ = make(slow={"62.1.1.1"}, down={"192.168.1.3"})
    v = run(tm)
    assert v["diag"]["level"] == "warn" and v["diag"]["node"] == "isp"
    lv = {i["node"]: i["level"] for i in v["issues"]}
    assert lv.get("dev:192.168.1.3") == "bad" and lv.get("isp") == "warn"


def test_rate_limit_and_demo_faults():
    tm, _ = make()
    run(tm)
    r = tm.run()
    assert not r["ok"] and r["retry_in"] >= 1
    st = types.SimpleNamespace(gateway="192.168.1.1", me={"192.168.1.23"}, lock=threading.RLock(), home={})
    d = topomap.TopoMap(st, sim=True)
    d._doc = lambda: DOC
    assert d.run(fault="dns")["ok"] and d.view()["diag"]["node"] == "dns"
    assert d.view()["faults"]
    live = topomap.TopoMap(st, pinger=lambda h: DOWN, tracer=lambda: [], resolver=lambda: {"ok": False})
    live._doc = lambda: DOC
    assert live.run(fault="dns") and live.fault is None    # προσομοίωση βλάβης μόνο στο demo
    live.wait(1)


def test_hop_kind_and_private():
    assert topomap.hop_kind("192.168.100.1") == "modem"
    assert topomap.hop_kind("100.64.3.1") == "cgnat"
    assert topomap.hop_kind("62.1.1.1") == "isp"
    assert not topomap.private_ip("8.8.8.8") and topomap.private_ip("10.0.0.2")
    assert topomap.ping_status(DOWN, "router") == "down"
    assert topomap.ping_status(ok(100), "router") == "slow"


def test_export_files_are_checked_and_expire():
    now = [T0]
    st = types.SimpleNamespace(gateway="192.168.1.1", me=set(), lock=threading.RLock(), home={})
    tm = topomap.TopoMap(st, sim=True, clock=lambda: now[0])
    assert "error" in tm.put_file("exe", b"MZ")
    assert "error" in tm.put_file("pdf", b"<html>not a pdf")
    assert "error" in tm.put_file("pdf", b"")
    r = tm.put_file("pdf", b"%PDF-1.4\n...")
    f = tm.get_file(r["id"])
    assert f["mime"] == "application/pdf" and f["name"].endswith(".pdf") and f["data"].startswith(b"%PDF")
    # 📐 draw.io: το XML κατεβαίνει από τον ίδιο δρόμο (όχι ανοιχτό στο WebView → όχι «μαύρη οθόνη»)
    rd = tm.put_file("drawio", b'<?xml version="1.0"?><mxfile></mxfile>')
    fd = tm.get_file(rd["id"])
    assert fd["mime"].startswith("application/xml") and fd["name"].endswith(".drawio")
    assert "error" in tm.put_file("drawio", b"not xml")
    assert tm.get_file("nope") is None
    for _ in range(6):
        tm.put_file("svg", b"<svg></svg>")
    assert len(tm.files) <= topomap.EXPORT_KEEP
    now[0] += topomap.EXPORT_TTL + 1
    assert tm.get_file(r["id"]) is None
