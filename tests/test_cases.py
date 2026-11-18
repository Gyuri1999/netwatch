"""Tests για τη διαλογή ειδοποιήσεων / υποθέσεις (cases.py) και τη σύνδεσή τους με τη μηχανή ανίχνευσης."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cases  # noqa: E402
import netwatch as nw  # noqa: E402

T0 = 1_700_000_000.0
EVIL = "192.168.1.66"


class FakeState:
    def __init__(self):
        self.hosts = {EVIL: {"ip": EVIL, "names": set(), "rdns": "evil.lan"}}
        self.alerts = []


def mk(clock=None):
    clock = clock or [T0]
    return cases.Cases(FakeState(), clock=lambda: clock[0]), clock


def al(i, t, typ="Port scan", sev="med", actor=EVIL, target="192.168.1.5", **kw):
    return dict(id=i, t=t, type=typ, sev=sev, actor=actor, target=target, detail="",
                mitre={"id": "T1046", "name": "Network Service Discovery"}, lab=False, **kw)


def test_grouping_by_actor_and_window():
    c, _ = mk()
    a = c.on_alert(al(1, T0))
    b = c.on_alert(al(2, T0 + 600, typ="SSH brute force", target="192.168.1.7"))
    other = c.on_alert(al(3, T0 + 700, actor="192.168.1.77"))
    late = c.on_alert(al(4, T0 + 600 + 31 * 60))
    assert a == b and other != a and late not in (a, other)
    v = c.view()
    case = next(x for x in v["cases"] if x["id"] == a)
    assert case["count"] == 2 and case["alert_ids"] == [1, 2]
    assert case["types"] == ["Port scan", "SSH brute force"]
    assert case["targets"] == ["192.168.1.5", "192.168.1.7"]
    assert case["mitre"] == [{"id": "T1046", "name": "Network Service Discovery"}]
    assert case["title"] == "Port scan από evil.lan (192.168.1.66)"
    assert v["kpi"]["new"] == 3 and v["kpi"]["open"] == 3 and v["kpi"]["total"] == 3


def test_skips_lab_selftest_benign_and_duplicates():
    c, _ = mk()
    assert c.on_alert(dict(al(1, T0), lab=True)) is None
    assert c.on_alert(al(2, T0, selftest="δοκιμή")) is None
    assert c.on_alert(al(3, T0, benign="Tor")) is None
    cid = c.on_alert(al(4, T0))
    assert c.on_alert(al(4, T0)) == cid
    assert c.view()["cases"][0]["count"] == 1


def test_sev_is_max():
    c, _ = mk()
    cid = c.on_alert(al(1, T0, sev="low"))
    c.on_alert(al(2, T0 + 1, sev="high"))
    c.on_alert(al(3, T0 + 2, sev="med"))
    assert c.view()["cases"][0]["sev"] == "high" and cid == 1


def test_resolved_case_is_not_reopened():
    c, _ = mk()
    cid = c.on_alert(al(1, T0))
    assert c.update(cid, status="resolved")["status"] == "resolved"
    nid = c.on_alert(al(2, T0 + 60))
    assert nid != cid
    assert {x["id"]: x["status"] for x in c.view()["cases"]} == {cid: "resolved", nid: "new"}


def test_update_timestamps_notes_and_kpis():
    c, clock = mk()
    cid = c.on_alert(al(1, T0))
    clock[0] = T0 + 120
    r = c.update(cid, status="investigating", note="κοιτάζω")
    assert r["acked"] == T0 + 120 and r["closed"] is None and r["notes"][0]["text"] == "κοιτάζω"
    clock[0] = T0 + 600
    r = c.update(cid, status="resolved", note="ok")
    assert r["acked"] == T0 + 120 and r["closed"] == T0 + 600 and len(r["notes"]) == 2
    k = c.view()["kpi"]
    assert k["mtta"] == 120 and k["mttr"] == 600 and k["resolved"] == 1 and k["open"] == 0
    assert mk()[0].view()["kpi"]["mtta"] is None


def test_validation_errors():
    c, _ = mk()
    cid = c.on_alert(al(1, T0))
    assert "error" in c.update(999, status="resolved")
    assert "error" in c.update(cid, status="bogus")
    assert "error" in c.update(cid, note="x" * 2001)
    assert "error" in c.update(cid)
    assert "error" in c.false_positive(cid, minutes=-5)
    assert "error" in c.false_positive(cid, minutes="abc")
    assert "error" in c.create("", ["1.2.3.4"])
    assert "error" in c.create("ok", ["1.2.3.4"], sev="critical")
    assert "error" in c.delete_suppression("Port scan", "1.1.1.1")
    assert c.view()["cases"][0]["status"] == "new"


def test_false_positive_suppression_and_expiry():
    c, clock = mk()
    cid = c.on_alert(al(1, T0))
    c.on_alert(al(2, T0 + 5, typ="SSH brute force"))
    r = c.false_positive(cid, minutes=60, note="είναι το NAS")
    assert r["status"] == "false_positive" and r["closed"] == T0 and r["notes"][-1].get("auto")
    v = c.view()
    assert {(s["type"], s["actor"]) for s in v["suppressions"]} == {("Port scan", EVIL), ("SSH brute force", EVIL)}
    assert c.suppressed("Port scan", EVIL, T0 + 100) == f"Σημειώθηκε ψευδώς θετικό (υπόθεση #{cid})"
    assert c.suppressed("Port scan", "10.0.0.9", T0 + 100) is None
    assert c.suppressed("Port scan", EVIL, T0 + 3601) is None   # έληξε
    assert len(c.suppressions) == 0
    cid2 = c.on_alert(al(3, T0 + 4000))
    c.false_positive(cid2, minutes=0)                             # για πάντα
    assert c.suppressed("Port scan", EVIL, T0 + 10 ** 8)
    assert c.delete_suppression("Port scan", EVIL) == {"ok": True}
    assert c.suppressed("Port scan", EVIL, T0 + 4001) is None


def test_create_manual_case():
    c, _ = mk()
    r = c.create("Ύποπτο beaconing από NAS", ["192.168.1.16"], sev="high", note="από threat hunt")
    assert r["status"] == "investigating" and r["source"] == "hunt" and r["acked"] == T0
    assert r["sev"] == "high" and r["actors"] == ["192.168.1.16"] and r["notes"][0]["text"] == "από threat hunt"
    # νέα ειδοποίηση του ίδιου δράστη μπαίνει στην ανοιχτή χειροκίνητη υπόθεση
    assert c.on_alert(al(1, T0 + 60, actor="192.168.1.16")) == r["id"]


def test_persistence_round_trip(tmp_path):
    p = str(tmp_path / "cases.json")
    clock = [T0]
    c = cases.Cases(FakeState(), path=p, clock=lambda: clock[0])
    cid = c.on_alert(al(1, T0))
    c.update(cid, status="investigating", note="σημείωση")
    c.false_positive(c.on_alert(al(2, T0, actor="10.0.0.9")), minutes=0)
    c.save()
    assert not os.path.exists(p + ".tmp")
    json.load(open(p, encoding="utf-8"))
    d = cases.Cases(FakeState(), path=p, clock=lambda: clock[0])
    v = d.view()
    assert [x["id"] for x in v["cases"]] == [x["id"] for x in c.view()["cases"]]
    assert d.suppressed("Port scan", "10.0.0.9", T0 + 999)
    assert d.create("x", [])["id"] == 3   # το seq συνεχίζει


def test_cap_drops_oldest_closed(monkeypatch):
    monkeypatch.setattr(cases, "MAX_CASES", 5)
    c, _ = mk()
    ids = [c.on_alert(al(i, T0, actor=f"10.0.0.{i}")) for i in range(1, 6)]
    c.update(ids[2], status="resolved")
    c.on_alert(al(6, T0, actor="10.0.0.6"))
    left = {x["id"] for x in c.view()["cases"]}
    assert len(left) == 5 and ids[2] not in left and ids[0] in left


def test_detect_alert_gets_case_and_fp_makes_it_benign():
    s = nw.NetState("test", "test0", ["192.168.1.50"], "192.168.1.1", geo=False, rdns=False)
    clock = [T0]
    s.cases = cases.Cases(s, clock=lambda: clock[0])
    s.alert("Port scan", "high", EVIL, "192.168.1.5", "x", T0)
    a = s.alerts[0]
    assert a.get("case") == 1 and "benign" not in a
    assert s.hosts[EVIL]["threat"] == 3
    s.cases.false_positive(1, minutes=60)
    s.hosts[EVIL]["threat"] = 0
    s.alert("Port scan", "high", EVIL, "192.168.1.5", "x", T0 + 300)
    b = s.alerts[0]
    assert b["benign"] == "Σημειώθηκε ψευδώς θετικό (υπόθεση #1)" and "case" not in b
    assert s.hosts[EVIL]["threat"] == 0
    assert len(s.cases.cases) == 1


def test_demo_seed_and_mix():
    st = FakeState()
    st.alerts = [al(i, T0 + i * 10, actor=f"192.168.1.{100 + i}") for i in range(6, 0, -1)]  # νεότερη πρώτη
    c = cases.Cases(st, sim=True, clock=lambda: T0 + 7200)
    v = c.view()
    k = v["kpi"]
    assert v["demo"] and k["total"] == 6
    assert k["resolved"] == 1 and k["false_positive"] == 1 and k["investigating"] == 1 and k["new"] == 3
    assert len(v["suppressions"]) == 1 and k["mtta"] is not None and k["mttr"] is not None
    inv = next(x for x in v["cases"] if x["status"] == "investigating")
    assert len(inv["notes"]) == 2
    assert all(a.get("case") for a in st.alerts)
    c.tick()   # ξανά seed: χωρίς διπλότυπα
    assert c.view()["kpi"]["total"] == 6
