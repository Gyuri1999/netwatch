"""Tests για τις καμπάνιες purple team (purple.py) — χωρίς δίκτυο: τα πακέτα εγχέονται στη μηχανή ανίχνευσης."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import netwatch as nw  # noqa: E402
import pentest  # noqa: E402
import purple  # noqa: E402
from core import dga_score  # noqa: E402

ME, GW = "192.168.1.50", "192.168.1.1"


@pytest.fixture
def state():
    s = nw.NetState("test", "test0", [ME], GW, geo=False, rdns=False)
    s.arp_table[GW] = s.arp_first[GW] = "a4:2b:b0:00:00:01"
    return s


def run(p, **kw):
    p.start(**kw)
    r = p.wait(60)
    assert r and r["status"] == "done"
    return r


def test_catalog_has_old_and_new_scenarios(state):
    ids = {s["id"] for s in purple.scenario_list(state.cfg)}
    assert set(pentest.LAB_SCENARIOS) <= ids
    new = [s for s in purple.scenario_list(state.cfg) if s["new"]]
    assert len(new) >= 5
    for s in purple.scenario_list(state.cfg):
        assert s["technique"]["id"].startswith("T") and s["technique"]["tactic"]
        assert s["lesson"] and s["tool"] and s["rule"] and s["expect"]
        assert s["variants"][0] == "loud"


def test_full_campaign_loud_detected_and_quiet_mostly_missed(state):
    p = purple.Purple(state, pace=0, settle=0)
    r = run(p)
    res = {(x["scenario"], x["variant"]): x for x in r["results"]}
    for k in purple.ORDER:
        loud = res[(k, "loud")]
        assert loud["detected"], (k, loud["alert_types"])
        assert loud["latency"] is not None and loud["latency"] >= 0
        assert loud["pkts"] > 0 and loud["matched"]
    # αθόρυβες εκδοχές που πρέπει να ξεφεύγουν (κάτω από τα όρια) ή να πιάνονται (δεν γίνεται αθόρυβα)
    for k in ("portscan", "udpscan", "pingsweep", "arpsweep", "brute", "beacon", "dga", "dnstunnel", "mirai"):
        assert not res[(k, "quiet")]["detected"], k
    for k in ("rogue_dhcp", "creds"):
        assert res[(k, "quiet")]["detected"], k
    # το beaconing «συμπιέζει» τον χρόνο: 8 συνδέσεις ανά ~60 s → λανθάνουσα ~7 λεπτά εικονικού χρόνου
    assert res[("beacon", "loud")]["latency"] > 300
    assert r["summary"]["runs"] == len(r["results"])


def test_lab_alerts_stay_lab_and_state_cleaned(state):
    p = purple.Purple(state, pace=0, settle=0)
    run(p, scenarios=["creds", "rogue_dhcp", "beacon", "arpspoof"])
    assert state.alerts and all(a.get("lab") for a in state.alerts)
    assert not [k for k in state.creds if k[0].startswith(purple.ATT_NET)]
    assert not [k for k in state.plain if k[0].startswith(purple.ATT_NET)]
    assert not any(ip.startswith(purple.ATT_NET) for ip in state.dhcp_servers)
    assert state.arp_table[GW] == "a4:2b:b0:00:00:01"  # η MAC του router επανήλθε
    assert state.history.query(24)["alerts"] == []  # τίποτα στο ιστορικό


def test_repeated_campaigns_not_suppressed_by_cooldown(state):
    p = purple.Purple(state, pace=0, settle=0)
    for _ in range(3):
        r = run(p, scenarios=["synflood", "xmas", "portscan"], variants=["loud"])
        assert all(x["detected"] for x in r["results"]), [x["alert_types"] for x in r["results"]]


def test_disabled_detector_is_skipped(state):
    state.cfg["detectors"]["beaconing"] = False
    p = purple.Purple(state, pace=0, settle=0)
    r = run(p, scenarios=["beacon"])
    assert all(x["skipped"] and "απενεργοποιημένος" in x["reason"] for x in r["results"])
    assert r["summary"]["runs"] == 0


def test_arpspoof_skipped_without_router_mac():
    s = nw.NetState("test", "test0", [ME], GW, geo=False, rdns=False)
    p = purple.Purple(s, pace=0, settle=0)
    r = run(p, scenarios=["arpspoof"])
    assert r["results"][0]["skipped"]


def test_plan_validation(state):
    p = purple.Purple(state, pace=0, settle=0)
    with pytest.raises(ValueError):
        p.plan(["nope"])
    with pytest.raises(ValueError):
        p.plan(["portscan"], ["medium"])
    with pytest.raises(ValueError):
        p.plan(["xmas"], ["quiet"])
    assert p.plan(["xmas", "portscan"], ["loud", "quiet"]) == [("xmas", "loud"), ("portscan", "loud"), ("portscan", "quiet")]
    assert len(p.plan()) == sum(len(s["variants"]) for s in purple.scenario_list(state.cfg))


def test_coverage_statuses():
    res = [{"scenario": "portscan", "variant": "loud", "detected": True},
           {"scenario": "portscan", "variant": "quiet", "detected": False},
           {"scenario": "xmas", "variant": "loud", "detected": True},
           {"scenario": "synflood", "variant": "loud", "detected": True},
           {"scenario": "icmpflood", "variant": "loud", "detected": True},
           {"scenario": "dga", "variant": "loud", "detected": False},
           {"scenario": "dga", "variant": "quiet", "detected": False}]
    cov = purple.coverage(res)
    st = {t["id"]: t["status"] for tac in cov["tactics"] for t in tac["techniques"]}
    assert st["T1046"] == "partial"        # port scan: μόνο το θορυβώδες
    assert st["T1498.001"] == "detected"   # floods: όλα
    assert st["T1568.002"] == "missed"     # DGA
    assert st["T1040"] == "not_tested"
    assert cov["tested"] == 3 and cov["score"] == 50
    assert [t["tactic"] for t in cov["tactics"]] == [x for x in purple.TACTICS if x in {t["tactic"] for t in cov["tactics"]}] \
        + sorted(x for x in {t["tactic"] for t in cov["tactics"]} if x not in purple.TACTICS)


def test_dga_quiet_names_look_human():
    for i in range(20):
        assert dga_score(purple._word_name(i).split(".")[0]) < 0.6
    assert dga_score(purple._dga_name().split(".")[0]) >= 0.75


def test_history_persisted_atomically(state, tmp_path):
    path = str(tmp_path / "purple.json")
    p = purple.Purple(state, path=path, pace=0, settle=0)
    for _ in range(3):
        run(p, scenarios=["xmas"])
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    assert [c["id"] for c in d["campaigns"]] == [1, 2, 3]
    assert not os.path.exists(path + ".tmp")
    p2 = purple.Purple(state, path=path, pace=0, settle=0)
    st = p2.status()
    assert st["last"]["id"] == 3 and [h["id"] for h in st["history"]] == [3, 2, 1]
    assert p2.status(campaign_id=2)["campaign"]["id"] == 2
    p2.history = [dict(c, id=i) for i, c in enumerate([d["campaigns"][0]] * 25, 1)]
    run(p2, scenarios=["xmas"])
    assert len(p2.history) == purple.HISTORY_MAX


def test_status_shape_and_stop(state):
    p = purple.Purple(state, pace=3, settle=0)
    st = p.status()
    assert st["status"] == "idle" and st["run"] is None and st["last"] is None
    assert st["coverage"]["score"] is None
    p.start(scenarios=["portscan", "brute"])
    with pytest.raises(ValueError):
        p.start()
    assert p.status()["status"] == "running"
    assert p.stop()["stopped"]
    r = p.wait(30)
    assert r["status"] == "stopped"
    assert p.status()["history"][0]["status"] == "stopped"


def test_refuses_while_lab_running(state):
    state.lab = pentest.Lab(state)
    state.lab.run = {"status": "running", "kind": "portscan", "first_alert": 0}
    p = purple.Purple(state, pace=0, settle=0)
    with pytest.raises(ValueError):
        p.start()
