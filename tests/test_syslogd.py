import socket
import time

import pytest

import syslogd


class St:
    def __init__(self):
        self.alerts = []
        self.cd = {}

    def alert(self, typ, sev, actor, target, detail, t, key=None, cooldown=None, **kw):
        self.alerts.append((typ, sev, actor, target, detail))


NOW = 1_700_000_000.0  # Νοέμβριος 2023


def test_rfc3164_basic_and_no_host():
    r = syslogd.parse("<34>Oct 11 22:14:15 mymachine su[123]: 'su root' failed on /dev/pts/8", "10.0.0.5", NOW)
    assert (r["fmt"], r["host"], r["app"], r["pid"], r["facility"], r["severity"]) == ("3164", "mymachine", "su", "123", 4, 2)
    assert r["sev_name"] == "crit" and r["fac_name"] == "auth" and r["ts"] is not None
    assert r["msg"] == "'su root' failed on /dev/pts/8"
    r = syslogd.parse("<13>Oct 11 22:14:15 sshd: hello", "10.0.0.5", NOW)  # χωρίς hostname
    assert r["host"] == "10.0.0.5" and r["app"] == "sshd" and r["msg"] == "hello"


def test_rfc3164_cisco_and_esp32_without_timestamp():
    r = syslogd.parse("<189>123: *Mar  1 00:00:00.000: %SYS-5-CONFIG_I: Configured from console by vty0", "10.0.0.2", NOW)
    assert r["app"] == "%SYS-5-CONFIG_I" and r["msg"].startswith("Configured from console") and r["host"] == "10.0.0.2"
    r = syslogd.parse("<14>esp32-kipos garden: soil=41%", "192.168.1.20", NOW)
    assert (r["host"], r["app"], r["msg"]) == ("esp32-kipos", "garden", "soil=41%")


def test_rfc5424_with_structured_data():
    raw = ('<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 '
           '[exampleSDID@32473 iut="3" eventSource="App" eventID="1011"][meta@1 q="a \\"b\\" \\]c"] ﻿An application event')
    r = syslogd.parse(raw.encode(), "10.0.0.9", NOW)
    assert r["fmt"] == "5424" and r["host"] == "mymachine.example.com" and r["app"] == "evntslog"
    assert r["pid"] == "" and r["msgid"] == "ID47" and r["facility"] == 20 and r["severity"] == 5
    assert r["sd"]["exampleSDID@32473"] == {"iut": "3", "eventSource": "App", "eventID": "1011"}
    assert r["sd"]["meta@1"]["q"] == 'a "b" ]c'
    assert r["msg"] == "An application event"
    assert abs(r["ts"] - 1065910455.003) < 1e-3
    r = syslogd.parse("<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% do-nuts", "x", NOW)
    assert r["pid"] == "8710" and r["sd"] == {} and r["msg"] == "%% do-nuts" and abs(r["ts"] - 1061727255.000003) < 1e-3


def test_malformed_inputs_never_raise():
    for raw in [b"", b"\xff\xfe\x00garbage", "<999>bad pri", "<", "<34>", "<165>1 ", "<165>1 - - - - - [unterminated sd",
                "<165>1 2003-13-45T99:99:99Z h a p m - x", "just text \x1b[31mred\x07", "x" * 10000]:
        r = syslogd.parse(raw, "1.2.3.4", NOW)
        assert isinstance(r["msg"], str) and len(r["msg"]) <= syslogd.MSG_MAX
        assert not any(ord(ch) < 32 or 0x7f <= ord(ch) <= 0x9f for ch in r["msg"] + r["host"])
    r = syslogd.parse("just some text", "1.2.3.4", NOW)
    assert (r["fmt"], r["facility"], r["severity"], r["host"]) == ("raw", 1, 5, "1.2.3.4")
    r = syslogd.parse("<165>1 - - - - - [unterminated sd", "1.2.3.4", NOW)
    assert r["fmt"] == "5424" and r["sd"] == {} and r["msg"] == "[unterminated sd"


def _wait(cond, timeout=3.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_udp_roundtrip_and_tcp_framing():
    d = syslogd.Syslogd(None, {"enabled": True, "bind": "127.0.0.1", "port": 0, "tcp": True})
    u, t = d.start()
    try:
        syslogd.send_test("127.0.0.1", u, "γεια από UDP")
        assert _wait(lambda: d.status()["total"] >= 1)
        rec = d.query()[0]
        assert rec["msg"] == "γεια από UDP" and rec["src_ip"] == "127.0.0.1" and rec["app"] == "netwatch-test"
        m1, m2 = "<13>1 - h1 app - - - πρώτο".encode(), b"<13>1 - h2 app - - - second with\nnewline inside"
        with socket.create_connection(("127.0.0.1", t)) as s:
            s.sendall(f"{len(m1)} ".encode() + m1 + f"{len(m2)} ".encode() + m2[:10])
            time.sleep(0.05)
            s.sendall(m2[10:] + b"<14>h3 app: line framed\n")
        assert _wait(lambda: d.status()["total"] >= 4)
        msgs = [r["msg"] for r in d.query()]
        assert "πρώτο" in msgs and "second with newline inside" in msgs and "line framed" in msgs
    finally:
        d.stop()


def test_split_frames_partial():
    frames, rest = syslogd.split_frames(b"5 hello3 abc7 par")
    assert frames == [b"hello", b"abc"] and rest == b"7 par"
    frames, rest = syslogd.split_frames(b"one\ntwo\r\nthr")
    assert frames == [b"one", b"two"] and rest == b"thr"


def test_allow_list():
    d = syslogd.Syslogd(None, {"allow": ["192.168.1.0/24", "10.0.0.7"]})
    assert d.ingest("<14>x a: ok", "192.168.1.50") is not None
    assert d.ingest("<14>x a: ok", "10.0.0.7") is not None
    assert d.ingest("<14>x a: no", "10.0.0.8") is None
    assert d.ingest("<14>x a: no", "garbage") is None
    st = d.status()
    assert st["total"] == 2 and st["denied"] == 2
    d2 = syslogd.Syslogd(None, {"allow": ["127.0.0.2"], "bind": "127.0.0.1", "port": 0, "tcp": False})
    u, _ = d2.start()
    try:
        syslogd.send_test("127.0.0.1", u, "blocked")
        assert _wait(lambda: d2.status()["denied"] == 1)
        assert d2.status()["total"] == 0
    finally:
        d2.stop()


def test_failed_login_burst_and_cooldown():
    st = St()
    d = syslogd.Syslogd(st, {})
    line = "<85>Oct 11 22:14:15 pve pvedaemon[2211]: authentication failure; rhost=::ffff:192.168.1.66 user=root@pam msg=x"
    for i in range(4):
        d.ingest(line, "192.168.1.16", NOW + i)
    assert st.alerts == []
    d.ingest(line, "192.168.1.16", NOW + 4)
    assert len(st.alerts) == 1
    typ, sev, actor, target, detail = st.alerts[0]
    assert (typ, sev, actor, target) == ("Αποτυχημένες συνδέσεις (syslog)", "high", "192.168.1.66", "pve")
    assert "192.168.1.66" in detail
    for i in range(10):  # cooldown: όχι ξανά
        d.ingest(line, "192.168.1.16", NOW + 10 + i)
    assert len(st.alerts) == 1
    for i in range(5):  # άλλος επιτιθέμενος = άλλο κλειδί
        d.ingest("<38>Oct 11 22:14:15 nas sshd[9]: Failed password for root from 10.9.9.9 port 2222 ssh2", "192.168.1.5", NOW + 20 + i)
    assert [a[2] for a in st.alerts] == ["192.168.1.66", "10.9.9.9"]
    # 4 αποτυχίες απλωμένες σε >2′ δεν φτάνουν
    st2 = St()
    d2 = syslogd.Syslogd(st2, {})
    for i in range(8):
        d2.ingest(line, "192.168.1.16", NOW + i * 60)
    assert st2.alerts == []
    # μετά το cooldown ξαναχτυπά
    for i in range(5):
        d.ingest(line, "192.168.1.16", NOW + 700 + i)
    assert len(st.alerts) == 3
    assert d.status()["rules"][0]["hits"] == 3


def test_other_builtin_and_user_rules():
    st = St()
    d = syslogd.Syslogd(st, {"rules": [{"name": "Backup απέτυχε", "match": "backup FAILED", "sev": "med"},
                                       {"name": "Deauth", "match": "re:deauth(enticated)?", "sev": "low", "min_count": 3, "window": 60},
                                       {"name": "κακός", "match": "re:(a+)+$"}, {"match": "x"}]})
    assert len(d.status()["errors"]) == 2
    d.ingest("<27>Oct 11 22:14:15 router kernel: eth0.2: Link is Down", "192.168.1.1", NOW)
    d.ingest("<27>Oct 11 22:14:15 router dnsmasq-dhcp[1]: DHCPDISCOVER(br-lan) no address available", "192.168.1.1", NOW)
    d.ingest("<11>Oct 11 22:14:15 pve kernel: python3[123]: segfault at 0 ip 0 sp 0", "192.168.1.16", NOW)
    d.ingest("<189>1: *Mar  1 00:00:00.000: %SYS-5-CONFIG_I: Configured from console by vty0", "192.168.1.2", NOW)
    d.ingest("<14>nas backup: nightly backup failed (disk full)", "192.168.1.5", NOW)
    for i in range(3):
        d.ingest("<14>router hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: deauthenticated", "192.168.1.1", NOW + i)
    types = [a[0] for a in st.alerts]
    assert types == ["Σύνδεση έπεσε (syslog)", "DHCP χωρίς διευθύνσεις", "Σφάλμα συστήματος (syslog)",
                     "Αλλαγή ρυθμίσεων συσκευής", "Backup απέτυχε", "Deauth"]
    assert st.alerts[0][2] == "192.168.1.1" and st.alerts[0][3] == "router"


def test_query_filters_and_regex_safety():
    d = syslogd.Syslogd(None, {"keep": 100})
    for i in range(150):
        d.ingest(f"<{8 + (i % 8)}>Oct 11 22:14:15 h{i % 3} app: message number {i}", "10.0.0.1", NOW + i)
    st = d.status()
    assert st["kept"] == 100 and st["total"] == 150 and sum(st["by_sev"].values()) == 150
    assert {h["host"] for h in st["hosts"]} == {"h0", "h1", "h2"} and st["hosts"][0]["host"] == "h2"
    assert d.query(q="NUMBER 149")[0]["msg"] == "message number 149"
    assert [r["msg"] for r in d.query(q="re:number 14[5-9]$")] == [f"message number {i}" for i in range(149, 144, -1)]
    assert all(r["severity"] <= 2 for r in d.query(sev_max=2)) and d.query(sev_max=2)
    assert all(r["host"] == "h1" for r in d.query(host="H1"))
    assert all(r["t"] >= NOW + 140 for r in d.query(since=NOW + 140)) and len(d.query(since=NOW + 140)) == 10
    assert len(d.query(limit=5)) == 5
    for bad in ["re:(a+)+$", "re:(x*)*", "re:" + "a" * 300, "re:(", "re:(a)\\1"]:
        with pytest.raises(ValueError):
            d.query(q=bad)
    d.ingest("<14>h app: " + "a" * 1999 + "!", "10.0.0.1", NOW)
    t0 = time.time()
    with pytest.raises(ValueError):  # περνά τον στατικό έλεγχο αλλά «κολλά»: σκοτώνεται στο όριο χρόνου
        d.query(q="re:a*a*a*a*b")
    assert time.time() - t0 < 6
    assert d.query(q="re:a{5}!$")[0]["msg"].endswith("a!")


def test_demo_generates_and_detects():
    st = St()
    d = syslogd.Syslogd(st, {}, sim=True)
    d.demo_tick(NOW, burst=True, flap=True)
    s = d.status(now=NOW)
    assert s["demo"] and s["total"] >= 9
    assert {"router", "pve"} <= {h["host"] for h in s["hosts"]}
    assert "Αποτυχημένες συνδέσεις (syslog)" in [a[0] for a in st.alerts]
    assert "Σύνδεση έπεσε (syslog)" in [a[0] for a in st.alerts]
    assert s["hits"] and s["recent"]
