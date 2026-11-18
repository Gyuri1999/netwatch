"""Tests για τις υπενθυμίσεις λήξης (expiry.py) — καθόλου δίκτυο."""
import calendar
import io
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import expiry as ex  # noqa: E402

NOW = time.mktime((2026, 11, 18, 12, 0, 0, 0, 0, -1))


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


class FakeState:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, key=None, cooldown=None, mark=True, **k):
        self.alerts.append({"type": typ, "sev": sev, "actor": actor, "target": target, "key": key, "cooldown": cooldown})


def day(n):
    return time.strftime("%Y-%m-%d", time.localtime(NOW + n * 86400))


def test_status_thresholds():
    assert [ex.status_of(d) for d in (-1, 0, 7, 8, 30, 31, None)] == ["expired", "urgent", "urgent", "soon", "soon", "ok", "ok"]


def test_config_items_sorted_and_counted():
    cfg = {"items": [{"name": "A", "date": day(40), "kind": "license"}, {"name": "B", "date": day(-2), "kind": "warranty"},
                     {"name": "Κακό", "date": "2026-13-01"}]}
    e = ex.Expiry(FakeState(), cfg, clock=Clock())
    v = e.view()
    assert [i["name"] for i in v["items"]] == ["B", "A"]
    assert v["items"][0]["days_left"] == -2 and v["items"][0]["status"] == "expired" and v["items"][0]["source"] == "config"
    assert v["counts"] == {"expired": 1, "urgent": 0, "soon": 0, "ok": 1}
    assert e.errors and v["errors"]
    assert all(ex.ID_RE.match(i["id"]) for i in v["items"])


def test_add_delete_persist(tmp_path):
    p = str(tmp_path / "expiry.json")
    e = ex.Expiry(FakeState(), {}, path=p, clock=Clock())
    it = e.add("Άδεια Windows Server", "license", day(10), "KMS")
    assert it["source"] == "manual" and it["days_left"] == 10 and it["status"] == "soon" and ex.ID_RE.match(it["id"])
    assert "error" in e.add("", "license", day(1))
    assert "error" in e.add("x" * 81, "license", day(1))
    assert "error" in e.add("x", "bogus", day(1))
    assert "error" in e.add("x", "other", "18/11/2026")
    assert "error" in e.add("x", "other", day(1), "n" * 201)
    e2 = ex.Expiry(FakeState(), {}, path=p, clock=Clock())
    assert [i["id"] for i in e2.view()["items"]] == [it["id"]]
    assert "error" in e2.delete("cfg-nothere")
    assert e2.delete(it["id"]) == {"ok": True}
    assert ex.Expiry(FakeState(), {}, path=p, clock=Clock()).view()["items"] == []
    assert not os.path.exists(p + ".tmp")


def test_alert_fires_once_per_threshold(tmp_path):
    st, clk = FakeState(), Clock()
    e = ex.Expiry(st, {"items": [{"name": "SmartNet", "date": day(31), "kind": "contract"}]}, path=str(tmp_path / "e.json"), clock=clk)
    assert e.check() == []
    seq = []
    for d, sev in ((1, "low"), (2, "low"), (24, "med"), (25, "med"), (29, "high"), (30, "high"), (31, "high"), (33, None)):
        clk.t = NOW + d * 86400
        sent = e.check()
        seq.append((d, [s[1] for s in sent]))
    assert seq == [(1, [30]), (2, []), (24, [7]), (25, []), (29, []), (30, [1]), (31, [0]), (33, [])]
    assert [a["sev"] for a in st.alerts] == ["low", "med", "high", "high"]
    a = st.alerts[0]
    assert a["type"] == "Λήξη πλησιάζει" and a["actor"] == "netwatch" and a["key"].startswith("expiry:cfg-") and a["cooldown"] == 86400
    # μετά από επανεκκίνηση δεν ξαναστέλνει
    e2 = ex.Expiry(st, {"items": [{"name": "SmartNet", "date": day(31), "kind": "contract"}]}, path=str(tmp_path / "e.json"), clock=clk)
    assert e2.check() == []


def test_already_expired_fires_only_strictest():
    st = FakeState()
    e = ex.Expiry(st, {"items": [{"name": "Old", "date": day(-5), "kind": "cert", "host": "192.168.1.1"}]}, clock=Clock())
    assert [s[1] for s in e.check()] == [0]
    assert st.alerts[0]["sev"] == "high" and st.alerts[0]["actor"] == "192.168.1.1"


SAMPLE_RDAP = {"objectClassName": "domain", "ldhName": "example.com",
               "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                          {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00.000+00:00"},
                          {"eventAction": "last update of RDAP database", "eventDate": "2026-11-18T10:00:00Z"}]}


def test_rdap_parse_and_daily_cache(monkeypatch, tmp_path):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append((req.full_url, timeout))
        return io.BytesIO(json.dumps(SAMPLE_RDAP).encode())
    monkeypatch.setattr(ex.urllib.request, "urlopen", fake_urlopen)
    exp = calendar.timegm((2027, 8, 13, 4, 0, 0, 0, 0, 0))
    assert ex.rdap_expiry(SAMPLE_RDAP) == exp
    clk = Clock()
    e = ex.Expiry(FakeState(), {"domains": ["Example.com", "not a domain"]}, path=str(tmp_path / "x.json"), clock=clk)
    e._fetch()
    e._fetch()  # ίδια μέρα: από την cache
    assert calls == [("https://rdap.org/domain/example.com", 8)]
    it = [i for i in e.view()["items"] if i["kind"] == "domain"]
    assert len(it) == 1 and it[0]["name"] == "Domain example.com" and it[0]["date"] == time.strftime("%Y-%m-%d", time.localtime(exp))
    clk.t += 86401
    e._fetch()
    assert len(calls) == 2
    assert any("not a domain" in x for x in e.errors)


def test_auto_from_other_modules_no_network():
    class TA:
        def last_results(self):
            return [{"target": "192.168.1.1:443", "ip": "192.168.1.1", "tls": {"cert": {"not_after": "Jan  1 00:00:00 2021 GMT",
                                                                                         "subject": "CN=router", "self_signed": True}}}]

    class HE:
        def status(self):
            return {"targets": [{"name": "Proxmox", "host": "192.168.1.16", "port": 8006, "cert_days": 9}, {"name": "x", "cert_days": None}]}
    st = FakeState()
    st.tlsaudit, st.health = TA(), HE()
    v = ex.Expiry(st, {}, clock=Clock()).view()
    names = {i["name"]: i for i in v["items"]}
    assert names["Πιστοποιητικό TLS 192.168.1.1:443"]["status"] == "expired"
    assert names["Πιστοποιητικό Proxmox"]["days_left"] == 9 and names["Πιστοποιητικό Proxmox"]["source"] == "auto"


def test_demo_counts():
    v = ex.Expiry(None, sim=True, clock=Clock()).view()
    assert v["demo"] and len(v["items"]) == 9
    assert v["counts"] == {"expired": 2, "urgent": 1, "soon": 4, "ok": 2}
    by = {i["id"]: i for i in v["items"]}
    assert by["router-cert"]["days_left"] == -12 and by["ap-firmware"]["status"] == "expired"
    assert by["nas-cert"]["status"] == "urgent" and by["dom-homelab"]["days_left"] == 61
    assert v["items"][0]["days_left"] <= v["items"][-1]["days_left"]
