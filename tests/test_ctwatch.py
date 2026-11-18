import io
import json

import pytest

import ctwatch
from ctwatch import CtWatch, parse_crtsh, valid_domain


class St:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, detail, kw))


BASE = [
    {"issuer_ca_id": 295815, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "example.com",
     "name_value": "example.com\nwww.example.com", "id": 1001, "entry_timestamp": "2024-05-01T10:00:00.123",
     "not_before": "2024-05-01T09:00:00", "not_after": "2024-07-30T09:00:00", "serial_number": "aa", "result_count": 2},
    # η ίδια ταυτότητα δύο φορές (crt.sh επιστρέφει μία γραμμή ανά ταίρισμα)
    {"issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "example.com", "name_value": "www.example.com",
     "id": 1001, "entry_timestamp": "2024-05-01T10:00:00.123", "not_before": "2024-05-01T09:00:00", "not_after": "2024-07-30T09:00:00"},
    {"issuer_name": "C=US, O=Let's Encrypt, CN=E6", "common_name": "*.example.com", "name_value": "*.example.com\nexample.com",
     "id": 1002, "entry_timestamp": "2024-06-01T10:00:00.000", "not_before": "2024-06-01T09:00:00", "not_after": "2024-08-30T09:00:00"},
]
RENEWAL = {"issuer_name": "C=US, O=Let's Encrypt, CN=R10", "common_name": "example.com", "name_value": "example.com\nwww.example.com",
           "id": 1003, "entry_timestamp": "2024-07-01T10:00:00.000", "not_before": "2024-07-01T09:00:00", "not_after": "2024-09-29T09:00:00"}
ROGUE = {"issuer_name": "C=GB, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA", "common_name": "mail.example.com",
         "name_value": "mail.example.com", "id": 1004, "entry_timestamp": "2024-07-02T10:00:00.000",
         "not_before": "2024-07-02T09:00:00", "not_after": "2025-07-02T09:00:00"}
NEW_SUB_LE = {"issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "vpn.example.com", "name_value": "vpn.example.com",
              "id": 1005, "entry_timestamp": "2024-07-03T10:00:00.000", "not_before": "2024-07-03T09:00:00", "not_after": "2024-10-01T09:00:00"}


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def crt(monkeypatch):
    box = {"data": list(BASE), "reqs": []}

    def fake_urlopen(req, timeout=None):
        box["reqs"].append((req.full_url, dict(req.header_items()), timeout))
        return FakeResp(json.dumps(box["data"]).encode())
    monkeypatch.setattr(ctwatch, "urlopen", fake_urlopen)
    return box


def test_valid_domain():
    assert valid_domain(" Example.COM. ") == "example.com"
    assert valid_domain("xn--hxajbheg2az3al.gr") == "xn--hxajbheg2az3al.gr"
    for bad in ["*.example.com", "%.example.com", "example", "exa mple.com", "-a.com", "a-.com", "a..com",
                "example.com/x", "example.com?q=1", "", None, "ex_ample.com"]:
        assert valid_domain(bad) is None, bad


def test_parse_merges_same_id():
    c = parse_crtsh(BASE)
    assert sorted(c) == [1001, 1002]
    assert c[1001]["names"] == ["example.com", "www.example.com"]


def test_baseline_then_alerts(tmp_path, crt):
    db = tmp_path / "ct.json"
    st = St()
    w = CtWatch(st, {"domains": ["example.com"], "expect_issuers": ["Let's Encrypt"], "db": str(db)})
    assert w.check("example.com", now=1000.0) == []
    assert st.alerts == []
    url, hdrs, timeout = crt["reqs"][0]
    assert url == "https://crt.sh/?q=%25.example.com&output=json" and timeout == 20
    assert hdrs.get("User-agent") == "NetWatch"
    s = w.status()["domains"][0]
    assert s["total"] == 2 and s["baseline"] and not any(c["new"] for c in s["recent"])
    assert s["subdomains"] == ["example.com", "www.example.com"]
    assert s["issuers"] == {"Let's Encrypt": 2}
    # ίδια απάντηση → τίποτα νέο
    assert w.check("example.com", now=2000.0) == []
    # κανονική ανανέωση από Let's Encrypt → low
    crt["data"] = BASE + [RENEWAL]
    ev = w.check("example.com", now=3000.0)
    assert [e[0] for e in ev] == ["low"] and len(st.alerts) == 1
    typ, sev, actor, target, detail, kw = st.alerts[0]
    assert typ == "Νέο πιστοποιητικό για το domain σου" and sev == "low" and actor == "example.com"
    assert "https://crt.sh/?id=1003" in detail and kw["key"][-1] == 1003
    # απρόσμενος εκδότης + νέος υποτομέας → med· νέος υποτομέας από LE → επίσης med
    crt["data"] = BASE + [RENEWAL, ROGUE, NEW_SUB_LE]
    ev = w.check("example.com", now=4000.0)
    assert [e[0] for e in ev] == ["med", "med"]
    assert "Sectigo" in st.alerts[1][4] and "mail.example.com" in st.alerts[1][4]
    s = w.status()["domains"][0]
    rog = [c for c in s["recent"] if c["id"] == 1004][0]
    assert rog["new"] and rog["unexpected_issuer"] and rog["new_names"] == ["mail.example.com"]
    assert rog["link"] == "https://crt.sh/?id=1004" and rog["issuer"].startswith("Sectigo Limited")
    assert "vpn.example.com" in s["subdomains"] and s["flagged"] == 2 and s["total"] == 5
    json.dumps(w.status())


def test_persistence_survives_restart(tmp_path, crt):
    db = tmp_path / "ct.json"
    CtWatch(None, {"domains": ["example.com"], "db": str(db)}).check("example.com")
    st = St()
    w2 = CtWatch(st, {"domains": ["example.com"], "db": str(db)})
    assert w2.check("example.com") == []  # δεν ξαναγίνεται baseline, ούτε ειδοποιήσεις για τα ίδια
    crt["data"] = BASE + [RENEWAL]
    assert len(w2.check("example.com")) == 1 and len(st.alerts) == 1
    assert 1003 in json.loads(db.read_text())["example.com"]["seen"]


def test_round_respects_interval_and_errors(tmp_path, monkeypatch):
    def boom(req, timeout=None):
        raise OSError("crt.sh down")
    monkeypatch.setattr(ctwatch, "urlopen", boom)
    w = CtWatch(None, {"domains": ["example.com", "*.bad.com"], "db": str(tmp_path / "x.json"), "interval_h": 6})
    assert "*.bad.com" in w.status()["error"]
    assert w.domains == ["example.com"]
    w.round(now=1000.0)
    d = w.status()["domains"][0]
    assert d["error"] and not d["baseline"]
    assert w.round(now=1100.0, force=False) == {}       # μέσα στο 30′ μετά από αποτυχία
    assert "example.com" in w.round(now=1000.0 + 1801, force=False)


def test_sim():
    st = St()
    w = CtWatch(st, {}, sim=True)
    s = w.status()
    assert s["demo"] and s["enabled"]
    d = s["domains"][0]
    assert d["domain"] == "example-homelab.gr" and d["total"] == 13
    assert d["issuers"]["Let's Encrypt"] == 12 and d["flagged"] == 1
    flagged = [c for c in d["recent"] if c["new"]]
    assert len(flagged) == 1 and flagged[0]["unexpected_issuer"]
    assert st.alerts == []  # στέλνεται από το run_forever
    w._alert(ctwatch.SIM_DOMAIN, w._pending, 0)
    assert st.alerts[0][1] == "med"
    json.dumps(s)
