"""Tests για το «Φταίει το δίκτυο;» (nettriage.py) — demo σενάρια και live με ψεύτικα probes."""
import json
import os
import re
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import changecheck  # noqa: E402
import nettriage  # noqa: E402

MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", re.I)
EXPECT = {"ok": "OK", "dns": "DNS", "gateway": "Gateway", "captive": "Captive portal", "dhcp": "DHCP", "mtu": "MTU"}


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(nettriage, "_sleep", lambda s: None)


def wait(t):
    for _ in range(500):
        v = t.view()
        if v["status"] == "done":
            return v
        time.sleep(0.01)
    raise AssertionError("δεν τελείωσε")


@pytest.mark.parametrize("lang", ["el", "en"])
@pytest.mark.parametrize("sc", list(EXPECT))
def test_demo_scenarios(sc, lang):
    t = nettriage.Triage(None, sim=True)
    first = t.run(lang, sc)
    assert first["status"] in ("running", "done") and [s["id"] for s in first["steps"]] == nettriage.STEP_IDS
    v = wait(t)
    assert v["verdict"]["layer"] == EXPECT[sc]
    assert v["scenarios"] == nettriage.SCENARIOS and v["demo"] and v["lang"] == lang
    tk = v["ticket"]
    assert ("Διάγνωση δικτύου" in tk) == (lang == "el") and ("Network triage" in tk) == (lang == "en")
    assert ("Συμπέρασμα:" if lang == "el" else "Verdict:") in tk
    assert tk.count("\n[") >= len(nettriage.STEP_IDS)
    assert ("192.168.1.1" in tk or sc == "dhcp") and not MAC_RE.search(tk)
    for s in v["steps"]:
        assert s["status"] in ("ok", "warn", "fail", "skip") and set(s) == {"id", "title", "status", "detail", "ms", "fix"}
        assert f"{nettriage.TAG[s['status']]} {s['title']}" in tk
    if sc == "dns":
        assert "It's always DNS" in v["verdict"]["text"]
    json.dumps(v)


def test_demo_default_first_is_dns_and_running_twice(monkeypatch):
    t = nettriage.Triage(None, sim=True)
    monkeypatch.setattr(nettriage, "_sleep", lambda s: time.sleep(0.01))
    t.run()
    assert t.run().get("error", "").startswith("Τρέχει ήδη")
    v = wait(t)
    assert v["verdict"]["layer"] == "DNS"


def test_unknown_scenario_and_live_has_no_scenarios():
    with pytest.raises(ValueError):
        nettriage.Triage(None, sim=True).run("el", "nope")
    assert nettriage.Triage(None).view()["scenarios"] == []
    assert nettriage.Triage(None).view()["status"] == "idle"


def patch_net(monkeypatch, info=None, ping_ok=True, dns_local=True, dns_public=True, net=True, captive=204, df_ok=True):
    calls = []
    base = {"iface": "en0", "up": True, "ip": "192.168.1.23", "prefix": 24, "mtu": 1500, "gateway": "192.168.1.1",
            "dns": ["192.168.1.1"], "kind": "ethernet"}
    monkeypatch.setattr(changecheck, "local_info", lambda sim=False: dict(base, **(info or {})))

    def ping(ip, count=2, interval=0.2, timeout=1.0, size=None, df=False):
        calls.append(("ping", ip))
        ok = (df_ok if df else True) and (ping_ok if ip == "192.168.1.1" else net)
        return {"ok": ok, "sent": count, "received": count if ok else 0, "loss_pct": 0.0 if ok else 100.0,
                "avg": 2.0 if ok else None, "jitter": 0.5 if ok else None, "err": None}
    monkeypatch.setattr(changecheck, "ping", ping)
    monkeypatch.setattr(changecheck, "tcp", lambda ip, p, timeout=1.0: (calls.append(("tcp", ip)),
                                                                 {"state": "open" if (net if ip in changecheck.PUBLIC_OK else ping_ok) else "filtered", "ms": 10.0})[1])
    monkeypatch.setattr(changecheck, "dns_query", lambda n, s, t=1.5: (calls.append(("dns", s)),
                                                                      {"ok": dns_public if s in changecheck.PUBLIC_OK else dns_local,
                                                                       "ip": "142.250.184.110", "ms": 5.0, "err": None})[1])
    monkeypatch.setattr(changecheck, "sys_resolve", lambda n, t=2.0: {"ok": dns_local, "ip": "1.2.3.4", "ms": 3.0, "err": None})
    monkeypatch.setattr(changecheck, "http_probe", lambda u, t=3.0: (calls.append(("http", u)), {
        "status": (200 if "apple" in u else 204) if captive == 204 else captive, "body": "<HTML>Success</HTML>" if captive == 204 else "<html>login</html>",
        "location": "http://portal.lan/login" if captive == 302 else None, "ms": 20.0})[1])
    return calls


def test_live_ok_monkeypatched(monkeypatch):
    calls = patch_net(monkeypatch)
    v = wait_run(nettriage.Triage(None), "en")
    assert v["verdict"]["layer"] == "OK" and all(s["status"] == "ok" for s in v["steps"])
    assert v["scenarios"] == [] and not v["demo"]
    for kind, target in calls:
        if kind != "http":
            assert changecheck.allowed(target)


def wait_run(t, lang="el", scenario=None):
    t.run(lang, scenario)
    return wait(t)


def test_live_dns_its_always_dns(monkeypatch):
    patch_net(monkeypatch, dns_local=False)
    v = wait_run(nettriage.Triage(None), "el", "ok")  # το scenario αγνοείται στο live
    assert v["verdict"]["layer"] == "DNS" and "It's always DNS" in v["verdict"]["text"]
    assert "[FAIL] DNS του δικτύου" in v["ticket"]


def test_live_link_failure_skips_rest(monkeypatch):
    patch_net(monkeypatch, info={"up": False, "ip": None})
    v = wait_run(nettriage.Triage(None), "en")
    assert v["steps"][0]["status"] == "fail" and v["verdict"]["layer"] == "L1/L2"
    assert all(s["status"] == "skip" for s in v["steps"][1:])
    assert "[SKIP] Quality" in v["ticket"]


def test_live_apipa_is_dhcp_and_internet_down(monkeypatch):
    patch_net(monkeypatch, info={"ip": "169.254.3.4", "gateway": None, "dns": []})
    v = wait_run(nettriage.Triage(None), "el")
    assert v["verdict"]["layer"] == "DHCP" and "δεν πήρε IP από DHCP" in v["steps"][0]["detail"]
    patch_net(monkeypatch, net=False, dns_local=False, dns_public=False)
    v = wait_run(nettriage.Triage(None), "en")
    assert v["verdict"]["layer"] == "Internet/ISP"
    patch_net(monkeypatch, captive=302, net=False)
    v = wait_run(nettriage.Triage(None), "en")
    assert v["verdict"]["layer"] == "Captive portal"
    patch_net(monkeypatch, df_ok=False)
    assert wait_run(nettriage.Triage(None), "en")["verdict"]["layer"] == "MTU"


def test_ticket_has_no_other_device_macs():
    class St:
        arp_table = {"192.168.1.40": "00:1e:0b:40:40:40", "192.168.1.1": "a4:2b:b0:11:22:01"}
    t = nettriage.Triage(St(), sim=True)
    v = wait_run(t, "el", "gateway")
    assert not MAC_RE.search(v["ticket"]) and "00:1e:0b" not in json.dumps(v)
