import json
import threading
import time

import pytest

import ops


def at(y, mo, d, h, mi):
    return time.mktime((y, mo, d, h, mi, 0, 0, 0, -1))


# 2026-11-16 είναι Δευτέρα
MON_0230 = at(2026, 11, 16, 2, 30)
MON_0500 = at(2026, 11, 16, 5, 0)
TUE_0030 = at(2026, 11, 17, 0, 30)


def test_weekly_window():
    m = ops.Maintenance([{"name": "Backup", "start": "02:00", "end": "04:00"}])
    assert m.active(MON_0230) == "Backup"
    assert m.active(MON_0500) is None


def test_days_filter_and_greek_days():
    m = ops.Maintenance([{"name": "Τρίτη", "days": ["τρι"], "start": "02:00", "end": "04:00"}])
    assert m.active(MON_0230) is None
    assert m.active(MON_0230 + 86400) == "Τρίτη"


def test_overnight_window_belongs_to_previous_day():
    m = ops.Maintenance([{"name": "Νύχτα", "days": ["mon"], "start": "23:00", "end": "01:00"}])
    assert m.active(TUE_0030) == "Νύχτα"          # Τρίτη 00:30 → συνέχεια της Δευτέρας
    assert m.active(TUE_0030 + 86400) is None     # Τετάρτη 00:30 → όχι


def test_once_window_and_hosts():
    m = ops.Maintenance([{"name": "Router", "start": "2026-11-16 02:00", "end": "2026-11-16 03:00", "hosts": ["192.168.1.1"]}])
    assert m.active(MON_0230, "192.168.1.1", "x") == "Router"
    assert m.active(MON_0230, "192.168.1.50") is None
    assert m.active(MON_0500, "192.168.1.1") is None


def test_bad_config_reports_errors():
    m = ops.Maintenance([{"name": "x", "start": "25:99", "end": "nope"}, "σκουπίδι",
                         {"name": "ανάποδα", "start": "2026-11-16 03:00", "end": "2026-11-16 02:00"}])
    assert len(m.errors) == 3 and not m.windows


def test_mute_persists_and_expires(tmp_path):
    p = str(tmp_path / "maint.json")
    m = ops.Maintenance([], p)
    now = time.time()
    x = m.mute(30, "Δοκιμές", now=now)
    assert m.active(now + 60) == "Δοκιμές"
    assert m.active(now + 31 * 60) is None
    m2 = ops.Maintenance([], p)
    assert m2.active(now + 60) == "Δοκιμές"
    m2.unmute(x["id"])
    assert ops.Maintenance([], p).active(now + 60) is None


def test_mute_is_clamped():
    m = ops.Maintenance([])
    x = m.mute(10 ** 9, now=0)
    assert x["until"] == ops.MAX_MUTE_MIN * 60
    st = m.status(now=0)
    assert st["mutes"] and st["active"]


class FakeResp:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return b"ok"


def test_channels_post_json(monkeypatch):
    sent = []
    monkeypatch.setattr(ops.urllib.request, "urlopen", lambda req, timeout=0: (sent.append(req), FakeResp())[1])
    assert ops.discord({"webhook": "https://discord.example/x"}, "T", "B", "high")
    assert ops.slack({"webhook": "https://hooks.example/x"}, "T", "B", "med")
    assert ops.webhook({"url": "http://192.168.1.30/hook", "headers": {"X-Token": "abc", "Bad\nHeader": "x", "X-Evil": "a\r\nb"}},
                       "T", "B", "low", {"type": "x", "_private": 1})
    assert not ops.discord({}, "T", "B", "high")
    body = json.loads(sent[0].data)
    assert body["embeds"][0]["color"] == ops.SEV_COL["high"]
    hook = json.loads(sent[2].data)
    assert hook["alert"] == {"type": "x"}
    hdrs = {k.lower(): v for k, v in sent[2].header_items()}
    assert hdrs.get("x-token") == "abc" and "x-evil" not in hdrs


def test_webhook_rejects_non_http():
    with pytest.raises(ValueError):
        ops.webhook({"url": "file:///etc/passwd"}, "T", "B", "low")


def test_email_uses_starttls_and_login():
    calls = []

    class S:
        def __init__(self, host, port, timeout=0):
            calls.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            calls.append(("starttls",))

        def login(self, u, p):
            calls.append(("login", u))

        def send_message(self, msg):
            calls.append(("send", msg["To"], msg["Subject"]))

    ok = ops.email({"host": "smtp.example", "user": "me", "password": "pw", "to": "you@example"}, "Τίτλος\nx", "σώμα", "high", _smtp=S)
    assert ok and ("starttls",) in calls and ("login", "me") in calls
    assert calls[-1] == ("send", "you@example", "Τίτλος x")
    assert ops.configured({"email": {"host": "h", "to": ["a"]}})["email"]


class FakeState:
    def __init__(self):
        self.lock = threading.Lock()
        self.mode = "demo"
        self.total_pkts = 42
        self.hosts = {"a": {"kind": "local", "threat": 0}, "b": {"kind": "public", "threat": 2}}
        now = time.time()
        self.alerts = [{"sev": "high", "t": now}, {"sev": "low", "t": now - 7200}, {"sev": "high", "t": now, "lab": True}]
        self.maint = ops.Maintenance([])

    def _stats(self, dt):
        return {"pps": 3.5, "bps": 1000}


def test_metrics_text():
    txt = ops.metrics(FakeState())
    assert "netwatch_packets_total 42" in txt
    assert 'netwatch_hosts{kind="public"} 1' in txt
    assert 'netwatch_alerts{severity="high"} 1' in txt  # το lab δεν μετράει
    assert 'netwatch_alerts_last_hour{severity="low"} 0' in txt
    assert "netwatch_maintenance_active 0" in txt
    assert all(l.startswith("#") or l.startswith("netwatch_") for l in txt.strip().splitlines())


def test_token_role():
    toks = [{"token": "v" * 20, "role": "viewer"}, {"token": "a" * 20, "role": "admin"}, {"token": "short"}]
    assert ops.token_role({"Authorization": "Bearer " + "v" * 20}, "", toks) == "viewer"
    assert ops.token_role({}, "a" * 20, toks) == "admin"
    assert ops.token_role({}, "short", toks) is None
    assert ops.token_role({}, "", toks) is None
    assert ops.token_role({}, "x" * 20, toks) is None


def test_alert_in_maintenance_is_not_notified():
    from detect import NetState
    st = NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    got = []
    st.notifier = got.append
    st.maint = ops.Maintenance([])
    st.maint.mute(10)
    st.alert("Δοκιμή", "high", "203.0.113.5", "192.168.1.23", "x", time.time())
    assert st.alerts[0]["maint"] and not got
    st.maint.unmute()
    st.alert("Δοκιμή 2", "high", "203.0.113.6", "192.168.1.23", "x", time.time())
    assert got and got[0]["type"] == "Δοκιμή 2"
