"""Tests για τον έλεγχο διαχωρισμού (segcheck.py) — ψεύτικος connector, καθόλου δίκτυο."""
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import segcheck as sc  # noqa: E402

CFG = {"zones": {"lan": "192.168.1.0/24", "iot": "192.168.30.0/24", "guest": {"cidr": "192.168.20.0/24", "vlan": 20},
                 "mgmt": "192.168.99.0/24"},
       "policy": [{"from": "guest", "to": "lan", "allow": False}, {"from": "guest", "to": "mgmt", "allow": False},
                  {"from": "guest", "to": "iot", "allow": True}, {"from": "iot", "to": "lan", "allow": False},
                  {"from": "guest", "to": "internet", "allow": True}],
       "ports": [22, 445, 8006],
       "targets": {"lan": ["192.168.1.17", "192.168.1.16"], "mgmt": ["192.168.99.2"], "iot": ["192.168.30.20"]},
       "interval_hours": 0}


class FakeState:
    def __init__(self, me=("192.168.20.57",), hosts=None, arp=None):
        self.me, self.lock = set(me), threading.Lock()
        self.hosts, self.arp_table = hosts or {}, arp or {}
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append({"type": typ, "sev": sev, "actor": actor, "target": target, "detail": detail, **kw})


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def fake_connect(open_set, calls=None):
    def f(ip, port):
        if calls is not None:
            calls.append((ip, port))
        return (ip, port) in open_set
    return f


def make(cfg=CFG, open_set=(), st=None, calls=None, clock=None, path=None):
    return sc.SegCheck(st if st is not None else FakeState(), cfg, connect=fake_connect(set(open_set), calls),
                       clock=clock or Clock(), path=path)


def rule(view, rid):
    return next(r for r in view["rules"] if r["id"] == rid)


# ───────── ρυθμίσεις ─────────
def test_public_range_rejected():
    c = sc.parse_config({"zones": {"lan": "192.168.1.0/24", "evil": "8.8.8.0/24", "cgnat": "100.64.0.0/10",
                                   "v6": "2001:db8::/32", "ula": "fd00:1::/64"},
                         "policy": [{"from": "lan", "to": "evil", "allow": False}]})
    assert set(c["zones"]) == {"lan", "ula"}
    assert any("8.8.8.0/24" in e and "ιδιωτικό" in e for e in c["errors"])
    assert any("100.64.0.0/10" in e for e in c["errors"]) and any("2001:db8::/32" in e for e in c["errors"])
    assert any("evil" in e for e in c["errors"]) and c["policy"] == []


def test_config_validation_misc():
    c = sc.parse_config({"zones": {"lan": "192.168.1.0/24", "lan2": "192.168.1.128/25", "Bad Name": "10.0.0.0/8",
                                   "internet": "10.1.0.0/16"},
                         "policy": [{"from": "lan", "to": "internet", "allow": "yes"}, {"from": "lan", "to": "internet", "allow": True},
                                    {"from": "lan", "to": "internet", "allow": False}],
                         "ports": [22, 0, "x", 22], "targets": {"lan": ["192.168.2.5", "192.168.1.9"], "nope": ["1.1.1.1"]}})
    assert set(c["zones"]) == {"lan"}
    assert c["ports"] == [22] and c["targets"] == {"lan": ["192.168.1.9"]}
    assert [r["id"] for r in c["policy"]] == ["lan>internet"] and c["policy"][0]["allow"] is True
    assert len(c["errors"]) >= 7


def test_default_policy_when_missing():
    c = sc.parse_config({"zones": {"lan": "192.168.1.0/24", "guest": "192.168.20.0/24"}})
    pol = {r["id"]: r["allow"] for r in c["policy"]}
    assert pol == {"lan>guest": True, "guest>lan": False, "lan>internet": True, "guest>internet": True}


def test_unconfigured_view_and_run():
    s = sc.SegCheck(FakeState(), None, connect=fake_connect(set()))
    v = s.view()
    assert v["config_ok"] is False and v["configured"] is False and v["rules"] == []
    assert s.run()["ok"] is False


# ───────── πηγή / στόχοι ─────────
def test_source_zone_detection():
    s = make(st=FakeState(me=("10.9.9.9", "192.168.30.44")))
    assert s.source() == ("iot", "192.168.30.44")
    s = make(st=FakeState(me=("10.9.9.9",)))
    assert s.source() == (None, "10.9.9.9")
    s = make(dict(CFG, source="mgmt"), st=FakeState(me=("192.168.20.57",)))
    assert s.source()[0] == "mgmt"
    s = make(st=FakeState(me=("8.8.8.8", "192.168.1.23")))
    assert s.source() == ("lan", "192.168.1.23")


def test_targets_from_state_plus_gateway_and_cap():
    hosts = {f"192.168.1.{i}": {"kind": "local"} for i in range(2, 60)}
    hosts["8.8.8.8"] = {"kind": "public"}
    st = FakeState(me=("192.168.20.57", "192.168.1.5"), hosts=hosts, arp={"192.168.1.200": "aa:bb:cc:dd:ee:ff"})
    cfg = dict(CFG, targets={})
    s = make(cfg, st=st)
    t = s.targets("lan")
    assert t[0] == "192.168.1.1" and len(t) == sc.MAX_HOSTS
    assert "192.168.1.5" not in t and all(x.startswith("192.168.1.") for x in t)
    assert s.targets("mgmt") == ["192.168.99.1"]


# ───────── ετυμηγορίες ─────────
def test_verdicts_with_fake_connector():
    calls = []
    s = make(open_set={("192.168.1.17", 445), ("192.168.1.16", 8006)}, calls=calls)
    assert s.run()["ok"]
    assert s.wait(5)
    v = s.view()
    assert v["source_zone"] == "guest" and v["source_ip"] == "192.168.20.57" and v["config_ok"]
    gl = rule(v, "guest>lan")
    assert gl["verdict"] == "violation" and gl["expected"] == "deny" and gl["tested"] and gl["sensitive"]
    assert [(o["ip"], o["port"], o["service"]) for o in gl["open"]] == [("192.168.1.16", 8006, "Proxmox VE"),
                                                                        ("192.168.1.17", 445, "SMB")]
    assert "chain=forward src-address=192.168.20.0/24 dst-address=192.168.1.0/24 action=drop" in gl["fix"]["mikrotik"]
    assert "deny ip 192.168.20.0 0.0.0.255 192.168.1.0 0.0.0.255" in gl["fix"]["cisco"] and "Vlan20" in gl["fix"]["cisco"]
    assert "firewall.@rule[-1].dest='lan'" in gl["fix"]["openwrt"]
    assert gl["note_el"] and gl["note_en"] and gl["explain_el"] and gl["explain_en"]
    assert rule(v, "guest>mgmt")["verdict"] == "ok"
    assert rule(v, "guest>iot")["verdict"] == "blocked"  # allow αλλά τίποτα δεν απάντησε
    assert rule(v, "iot>lan")["verdict"] == "untested" and "iot" in rule(v, "iot>lan")["note_el"]
    assert rule(v, "guest>internet")["verdict"] == "untested"
    assert v["matrix"]["zones"] == ["lan", "iot", "guest", "mgmt", "internet"]
    assert v["matrix"]["cells"]["guest>lan"] == "violation" and "iot>lan" in v["matrix"]["cells"]
    assert v["counts"] == {"ok": 1, "violation": 1, "blocked": 1, "untested": 2}
    # μόνο ιδιωτικές IP, μόνο οι στόχοι των κανόνων της ζώνης πηγής, μόνο οι ρυθμισμένες θύρες
    assert {ip for ip, _ in calls} == {"192.168.1.17", "192.168.1.16", "192.168.99.2", "192.168.30.20"}
    assert {p for _, p in calls} == {22, 445, 8006} and len(calls) == 4 * 3
    json.dumps(v)


def test_verdict_function():
    assert sc.verdict(False, True, 2) == "violation" and sc.verdict(False, True, 0) == "ok"
    assert sc.verdict(True, True, 0) == "blocked" and sc.verdict(True, True, 1) == "ok"
    assert sc.verdict(False, False, 0) == "untested"


def test_never_probes_public_addresses():
    calls = []
    assert sc.tcp_connect("8.8.8.8", 53) is False
    s = make(open_set=set(), calls=calls)
    s.c["targets"]["lan"] = ["8.8.8.8", "192.168.1.17"]  # ακόμα κι αν «γλιστρήσει» δημόσια IP
    s.run()
    s.wait(5)
    assert all(sc.private_ip(ip) for ip, _ in calls) and calls


def test_rate_limit():
    clk = Clock()
    s = make(clock=clk)
    assert s.run()["ok"]
    s.wait(5)
    r = s.run()
    assert r["ok"] is False and 0 < r["retry_in"] <= sc.MIN_INTERVAL + 1 and r["error"]
    clk.t += sc.MIN_INTERVAL + 1
    assert s.run()["ok"]


def test_alert_raised_once_per_rule_and_set():
    st = FakeState()
    clk = Clock()
    opn = {("192.168.1.17", 445)}
    s = make(st=st, clock=clk)
    s.connect = fake_connect(opn)  # ίδιο set: αλλάζει ανάμεσα στους ελέγχους
    s.run()
    s.wait(5)
    assert len(st.alerts) == 1
    a = st.alerts[0]
    assert a["type"] == sc.ALERT == "Διαρροή διαχωρισμού VLAN" and a["sev"] == "high"
    assert a["mitre"]["id"] == "T1021" and a["target"] == "192.168.1.17:445" and a["mark"] is False
    clk.t += 100
    s.run()
    s.wait(5)
    assert len(st.alerts) == 1  # ίδιο σύνολο → καμία νέα ειδοποίηση
    opn.add(("192.168.1.16", 8006))
    clk.t += 100
    s.run()
    s.wait(5)
    assert len(st.alerts) == 2  # νέα θύρα → νέα ειδοποίηση


def test_alert_severity_med_for_non_sensitive():
    st = FakeState(me=("192.168.1.23",))
    cfg = dict(CFG, policy=[{"from": "lan", "to": "guest", "allow": False}], targets={"guest": ["192.168.20.9"]})
    s = make(cfg, open_set={("192.168.20.9", 22)}, st=st)
    s.run()
    s.wait(5)
    assert [a["sev"] for a in st.alerts] == ["med"]


def test_detector_and_mitre_mapping():
    import core
    assert core.detector_for(sc.ALERT) == "segmentation"
    assert core.detector_for("Διαρροή DNS") == "privacy_leaks"
    assert core.mitre_for(sc.ALERT)["id"] == "T1021"


def test_persistence(tmp_path):
    p = str(tmp_path / "segcheck.json")
    st = FakeState()
    s = make(open_set={("192.168.1.17", 445)}, st=st, path=p)
    s.run()
    s.wait(5)
    s2 = make(open_set=set(), st=st, path=p)
    assert rule(s2.view(), "guest>lan")["verdict"] == "violation"
    assert s2.check_alerts() == [] and len(st.alerts) == 1


# ───────── αναφορά από άλλη ζώνη ─────────
def test_remote_report():
    st = FakeState()
    s = make(st=st)
    bad = s.report({"source_zone": "iot", "source_ip": "192.168.20.5", "rules": {}})
    assert "error" in bad
    r = s.report({"source_zone": "iot", "source_ip": "192.168.30.44",
                  "rules": {"iot>lan": {"hosts": ["192.168.1.17", "8.8.8.8"], "probes": 3,
                                        "open": [{"ip": "192.168.1.17", "port": 1883}, {"ip": "8.8.8.8", "port": 53},
                                                 {"ip": "192.168.99.1", "port": 22}]},
                            "guest>lan": {"hosts": ["192.168.1.17"], "open": [{"ip": "192.168.1.17", "port": 22}]}}})
    assert r == {"ok": True, "rules": ["iot>lan"]}
    v = s.view()
    il = rule(v, "iot>lan")
    assert il["verdict"] == "violation" and il["via"] == "report" and il["source_ip"] == "192.168.30.44"
    assert [(o["ip"], o["port"]) for o in il["open"]] == [("192.168.1.17", 1883)]
    assert v["remote"][0]["zone"] == "iot" and [a["sev"] for a in st.alerts] == ["high"]
    assert rule(v, "guest>lan")["verdict"] == "untested"  # η αναφορά δεν «γράφει» κανόνες άλλης ζώνης


# ───────── demo ─────────
def test_demo_shape():
    s = sc.SegCheck(None, sim=True)
    v = s.view()
    assert v["demo"] and v["config_ok"] and v["source_zone"] == "guest" and v["source_ip"] == "192.168.20.57"
    assert {z["name"] for z in v["zones"]} == {"lan", "iot", "guest", "mgmt"}
    gl = rule(v, "guest>lan")
    assert gl["verdict"] == "violation"
    assert {(o["ip"], o["port"]) for o in gl["open"]} == {("192.168.1.17", 445), ("192.168.1.17", 5001), ("192.168.1.16", 8006)}
    assert next(o for o in gl["open"] if o["ip"] == "192.168.1.16")["name"] == "Proxmox"
    assert rule(v, "guest>mgmt")["verdict"] == "ok"
    assert rule(v, "iot>lan")["verdict"] == "untested" and rule(v, "lan>iot")["allow"] is True
    assert v["last_run"] and v["running"] is False
    for k in ("config_ok", "errors", "source_zone", "source_ip", "zones", "rules", "matrix", "last_run", "running", "demo"):
        assert k in v
    for r in v["rules"]:
        assert r["verdict"] in sc.VERDICTS and r["note_el"] and r["note_en"]
    assert s.run()["ok"] and s.run()["ok"] is False  # demo: τρέχει αμέσως, ίδιο όριο ρυθμού
    json.dumps(v)


# ───────── αναφορά pentest ─────────
def test_pentest_report_includes_violation():
    import netwatch as nw
    import pentest_report as pr
    s = nw.NetState("test", "t0", ["192.168.20.57"], "192.168.20.1", geo=False, rdns=False)
    s.segcheck = make(open_set={("192.168.1.17", 445), ("192.168.1.16", 8006)}, st=s)
    s.segcheck.run()
    s.segcheck.wait(5)
    assert any(a["type"] == sc.ALERT for a in s.alerts)
    d = pr.build_data(s, "en")
    f = next(f for f in d["findings"] if f["id"] == "segmentation_sensitive")
    assert f["title"] == "VLAN segmentation leak to a sensitive zone: guest → lan"
    assert f["cvss"]["score"] == 8.2 and f["severity"] == "high"
    assert [(a["host"], a["port"]) for a in f["affected"]] == [("192.168.1.16", 8006), ("192.168.1.17", 445)]
    assert "chain=forward" in f["remediation"]
    el = pr.build_data(s, "el")
    assert any(f["title"].startswith("Διαρροή διαχωρισμού VLAN") for f in el["findings"])
    assert "Διαρροή διαχωρισμού VLAN" in pr.render_html(el)


def test_pentest_report_demo_has_segmentation():
    import netwatch as nw
    import pentest_report as pr
    s = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    d = pr.build_data(s, "el")
    assert any(f["id"] == "segmentation_sensitive" for f in d["findings"])
    assert sum(d["summary"]["counts"].values()) == len(d["findings"])


# ───────── HTTP API ─────────
@pytest.fixture
def api():
    import netwatch as nw
    st = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    st.segcheck = sc.SegCheck(st, sim=True)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), nw.make_handler(st))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield st, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _req(url, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET",
                                 headers=headers if headers is not None else {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_api_routes(api):
    st, base = api
    code, v = _req(base + "/api/segcheck")
    assert code == 200 and v["demo"] and rule(v, "guest>lan")["verdict"] == "violation"
    code, r = _req(base + "/api/segcheck/run", {})
    assert code == 200 and r["ok"]
    code, r = _req(base + "/api/segcheck/run", {})
    assert code == 429 and r["retry_in"] > 0
    code, r = _req(base + "/api/segcheck/run", {}, headers={"Content-Type": "text/plain"})
    assert code == 403
    code, r = _req(base + "/api/segcheck/report", {"source_zone": "iot", "source_ip": "192.168.30.5",
                                                   "rules": {"iot>lan": {"hosts": ["192.168.1.17"], "open": [], "probes": 14}}})
    assert code == 200 and r["ok"]
    assert rule(_req(base + "/api/segcheck")[1], "iot>lan")["verdict"] == "ok"
    st.segcheck = None
    code, v = _req(base + "/api/segcheck")
    assert code == 200 and v["off"] and v["rules"] == []
    code, r = _req(base + "/api/segcheck/run", {})
    assert code == 400
