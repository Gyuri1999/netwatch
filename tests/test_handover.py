"""Tests για την παράδοση βάρδιας (handover.py) — χωρίς πραγματικό δίκτυο."""
import json
import os
import sys
import threading
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import netwatch as nw  # noqa: E402
import cases  # noqa: E402
import changecheck  # noqa: E402
import configbak  # noqa: E402
import handover  # noqa: E402

NOW = 1_795_000_000.0
H = 3600


class FakeCases:
    def view(self):
        return {"cases": [
            {"id": 1, "title": "Port scan από 10.0.0.5", "status": "investigating", "sev": "high", "created": NOW - 2 * H,
             "updated": NOW - H, "closed": None},
            {"id": 2, "title": "Brute force", "status": "new", "sev": "high", "created": NOW - 3 * H, "updated": NOW - 3 * H, "closed": None},
            {"id": 3, "title": "Παλιά υπόθεση", "status": "new", "sev": "low", "created": NOW - 30 * H, "updated": NOW - 30 * H, "closed": None},
            {"id": 4, "title": "Έκλεισε σήμερα", "status": "resolved", "sev": "med", "created": NOW - 20 * H,
             "updated": NOW - H, "closed": NOW - H}], "kpi": {"open": 3}}


class FakeHealth:
    def status(self):
        return {"targets": [{"name": "NAS", "host": "192.168.1.5", "up": False, "since": NOW - 600, "err": "timeout"},
                            {"name": "HA", "host": "192.168.1.30", "up": True}]}


class FakeExpiry:
    def view(self):
        return {"items": [{"name": "VPN cert", "kind": "tls", "days_left": 5, "status": "warn"},
                          {"name": "domain.gr", "kind": "domain", "days_left": 12, "status": "warn"},
                          {"name": "far", "kind": "tls", "days_left": 90, "status": "ok"}]}


def fake_state():
    al = [{"t": NOW - 10 * 60, "type": "Port scan", "sev": "high", "actor": "10.0.0.5"},
          {"t": NOW - 20 * 60, "type": "Port scan", "sev": "high", "actor": "10.0.0.5"},
          {"t": NOW - 2 * H, "type": "Brute force", "sev": "high", "actor": "1.2.3.4"},
          {"t": NOW - H, "type": "ARP flood", "sev": "med", "actor": "10.0.0.9"},
          {"t": NOW - H, "type": "Νέα συσκευή", "sev": "low", "actor": "10.0.0.10"},
          {"t": NOW - 30 * H, "type": "SYN flood", "sev": "high", "actor": "9.9.9.9"},          # εκτός παραθύρου
          {"t": NOW - 5 * 60, "type": "Port scan", "sev": "high", "actor": "10.0.0.66", "lab": True}]  # lab: αγνοείται
    s = types.SimpleNamespace(lock=threading.RLock(), alerts=al, hosts={"10.0.0.5": {"names": {"kali.local"}}},
                              cases=FakeCases(), health=FakeHealth(), expiry=FakeExpiry())
    cb = configbak.ConfigBackup(None, {"devices": []}, clock=lambda: NOW - 10 * H)
    cb.upload("sw", "hostname sw\nline vty 0 4\n transport input ssh\n", name="Switch", vendor="cisco_ios")
    s.configbak = cb
    return s


def mk(state=None, **kw):
    return handover.Handover(state if state is not None else fake_state(), clock=lambda: NOW, **kw)


def test_sections_and_stats_from_fake_state():
    s = fake_state()
    cb = s.configbak
    cb.clock = lambda: NOW - H  # δεύτερη έκδοση μέσα στη βάρδια, με telnet (επικίνδυνο)
    v = cb._record("sw", "hostname sw\nline vty 0 4\n transport input ssh telnet\n", note="x", now=NOW - H)
    assert v is not None
    r = mk(s).summary(8, "el")
    ids = [x["id"] for x in r["sections"]]
    assert ids[-1] == "pending" and {"alerts", "cases", "configs", "health", "expiry"} <= set(ids)
    assert "change_check" not in ids and "triage" not in ids  # κενές ενότητες παραλείπονται
    st = r["stats"]
    assert (st["alerts_high"], st["alerts_med"], st["alerts_low"]) == (3, 1, 1)
    assert (st["cases_open"], st["cases_new"], st["cases_closed"]) == (3, 2, 1)
    assert st["config_changes"] == 1 and st["risky_changes"] == 1 and st["expiring"] == 2
    al = next(x for x in r["sections"] if x["id"] == "alerts")
    assert al["sev"] == "high" and any("kali.local (10.0.0.5) ×2" in i for i in al["items"])
    assert not any("10.0.0.66" in i or "9.9.9.9" in i for i in al["items"])
    assert next(x for x in r["sections"] if x["id"] == "health")["items"][0].startswith("NAS")


def test_pending_and_text_el_en():
    h = mk()
    r = h.summary(8, "el")
    pend = next(x for x in r["sections"] if x["id"] == "pending")["items"]
    assert any("#1" in p for p in pend) and any("#2" in p for p in pend)  # υπό διερεύνηση + νέα σοβαρή
    assert any("VPN cert" in p for p in pend) and not any("domain.gr" in p for p in pend)  # μόνο ≤ 7 μέρες
    assert "Εκκρεμ" in r["text"] and "Σημειώσεις βάρδιας" in r["text"] and r["text"].startswith("NetWatch — Παράδοση βάρδιας (8 ώρες)")
    en = h.summary(8, "en")
    assert "Pending" in en["text"] and "Shift notes" in en["text"] and en["lang"] == "en"
    assert next(x for x in en["sections"] if x["id"] == "pending")["title"] == "Pending"


def test_pending_always_present_on_empty_state():
    r = mk(types.SimpleNamespace()).summary(4, "en")
    assert [x["id"] for x in r["sections"]] == ["pending"]
    assert r["sections"][0]["items"] == ["Nothing pending."] and r["hours"] == 4 and r["to"] - r["from"] == 4 * H


def test_hours_validation():
    assert handover.parse_hours(None) == 8 and handover.parse_hours("12") == 12 and handover.parse_hours(72) == 72
    for bad in (0, 73, "abc", -1, 1.5, True, "8h"):
        with pytest.raises(ValueError):
            handover.parse_hours(bad)
    with pytest.raises(ValueError):
        mk().summary(hours=100)


def test_notes_add_delete_persist(tmp_path):
    p = str(tmp_path / "handover.json")
    h = mk(path=p)
    assert "error" in h.add_note("   ") and "error" in h.add_note("x" * 1001) and "error" in h.add_note(None)
    a = h.add_note("Έλεγχος UPS")
    b = h.add_note("Δεύτερη")
    assert a["ok"] and b["note"]["t"] != a["note"]["t"]  # ίδιο clock → μοναδικό t
    data = json.load(open(p, encoding="utf-8"))
    assert [n["text"] for n in data["notes"]] == ["Έλεγχος UPS", "Δεύτερη"]
    assert mk(path=p).notes == h.notes  # φορτώνεται ξανά
    assert h.delete_note(a["note"]["t"])["ok"] and "error" in h.delete_note(a["note"]["t"])
    assert [n["text"] for n in mk(path=p).notes] == ["Δεύτερη"]
    r = h.summary(8, "el")
    assert [n["text"] for n in r["notes"]] == ["Δεύτερη"] and "Δεύτερη" in r["text"]


def test_notes_keep_200(tmp_path):
    h = mk(path=str(tmp_path / "h.json"))
    for i in range(205):
        h.add_note(f"n{i}")
    assert len(h.notes) == 200 and h.notes[0]["text"] == "n5"


def test_demo_summary():
    s = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    s.cases = cases.Cases(s, sim=True)
    s.configbak = configbak.ConfigBackup(s, None, sim=True)
    s.changecheck = changecheck.ChangeCheck(s, sim=True)
    h = handover.Handover(s, sim=True)
    assert h.path is None and len(h.notes) == 2
    r = h.summary(8, "el")
    assert r["demo"] and len(r["sections"]) >= 4
    ids = {x["id"] for x in r["sections"]}
    assert {"alerts", "configs", "change_check", "pending"} <= ids
    cfg = next(x for x in r["sections"] if x["id"] == "configs")
    assert cfg["sev"] == "high" and "Core switch" in cfg["items"][0]
    assert next(x for x in r["sections"] if x["id"] == "change_check")["sev"] == "high"
    assert len(r["notes"]) == 2 and "MikroTik" in r["text"] and "Εκκρεμεί για την επόμενη βάρδια" in r["text"]
    assert r["stats"]["alerts_high"] >= 2 and r["stats"]["risky_changes"] >= 1
    assert "Pending for the next shift" in h.summary(8, "en")["text"]


def test_state_keep_has_handover():
    assert "handover" in nw.NetState.KEEP
