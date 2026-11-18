import json
import os

import pytest

import logimport
from logimport import LogImport, parse_eve, parse_zeek, parse_ts


class St:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, detail, t, kw))


EVE = [
    json.dumps({"timestamp": "2024-03-01T10:20:30.123456+0200", "flow_id": 1, "event_type": "alert", "src_ip": "192.168.1.37",
                "src_port": 51234, "dest_ip": "192.168.1.10", "dest_port": 80, "proto": "TCP",
                "alert": {"action": "allowed", "signature_id": 2009358, "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                          "category": "Web Application Attack", "severity": 1}}),
    json.dumps({"timestamp": "2024-03-01T10:21:00.000000+0000", "event_type": "alert", "src_ip": "192.168.1.23", "src_port": 40000,
                "dest_ip": "93.184.216.34", "dest_port": 80, "proto": "TCP",
                "alert": {"signature_id": 2013028, "signature": "ET POLICY curl User-Agent Outbound",
                          "category": "Attempted Information Leak", "severity": 2}}),
    json.dumps({"timestamp": "2024-03-01T10:22:00Z", "event_type": "alert", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2",
                "proto": "UDP", "alert": {"signature": "ET INFO x", "severity": 3}}),
    json.dumps({"timestamp": "2024-03-01T10:22:01Z", "event_type": "dns", "src_ip": "192.168.1.41"}),
    json.dumps({"timestamp": "2024-03-01T10:22:02Z", "event_type": "dns"}),
    json.dumps({"timestamp": "2024-03-01T10:22:03Z", "event_type": "tls"}),
    json.dumps({"timestamp": "2024-03-01T10:22:04Z", "event_type": "flow"}),
    "not json {",
    "",
]

ZEEK_NOTICE_TSV = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tnotice
#open\t2024-03-01-10-00-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tnote\tmsg\tsub\tsrc\tdst\tp
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tenum\tstring\tstring\taddr\taddr\tport
1709287200.123456\t-\t-\t-\t-\t-\t-\tScan::Port_Scan\t192.168.1.37 scanned at least 15 unique ports of host 192.168.1.10 in 0m3s\tlocal\t192.168.1.37\t192.168.1.10\t-
1709287300.0\tCx1\t192.168.1.23\t50000\t192.168.1.20\t443\ttcp\tSSL::Invalid_Server_Cert\tSSL certificate validation failed\tCN=nas\t192.168.1.23\t192.168.1.20\t443
#close\t2024-03-01-11-00-00
"""

ZEEK_CONN_TSV = """#separator \\x09
#path\tconn
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state
1709287200.0\tC1\t192.168.1.23\t5000\t1.1.1.1\t443\ttcp\tssl\t1.0\t1000\t50000\tSF
1709287201.0\tC2\t192.168.1.23\t5001\t1.1.1.1\t443\ttcp\tssl\t1.0\t500\t-\tSF
1709287202.0\tC3\t192.168.1.41\t5002\t8.8.8.8\t53\tudp\tdns\t0.1\t40\t80\tSF
"""

ZEEK_JSON = [
    json.dumps({"_path": "weird", "ts": 1709287400.5, "uid": "C9", "id.orig_h": "192.168.1.52", "id.orig_p": 1,
                "id.resp_h": "192.168.1.1", "id.resp_p": 2, "name": "bad_TCP_checksum", "notice": False, "peer": "zeek"}),
    json.dumps({"ts": "2024-03-01T10:30:00.000000Z", "note": "SSL::Invalid_Server_Cert", "msg": "self signed",
                "id": {"orig_h": "192.168.1.23", "resp_h": "192.168.1.20", "resp_p": 443}}),
    json.dumps({"ts": 1709287401.0, "uid": "C3", "id.orig_h": "192.168.1.41", "id.resp_h": "8.8.8.8", "query": "example.com",
                "qtype_name": "A", "rcode": 0}),
    json.dumps({"ts": 1709287402.0, "uid": "C4", "id.orig_h": "192.168.1.41", "id.resp_h": "8.8.8.8", "proto": "udp",
                "orig_bytes": 10, "resp_bytes": 20, "conn_state": "SF"}),
]


def test_parse_ts():
    assert parse_ts("2024-03-01T10:20:30.5+0200") == pytest.approx(1709281230.5)
    assert parse_ts("2024-03-01T08:20:30.5Z") == pytest.approx(1709281230.5)
    assert parse_ts("2024-03-01T08:20:30+00:00") == pytest.approx(1709281230.0)
    assert parse_ts("1709287200.25") == 1709287200.25
    assert parse_ts("garbage", 7) == 7


def test_parse_eve():
    r = parse_eve(EVE)
    assert r["counts"] == {"alert": 3, "dns": 2, "tls": 1, "flow": 1}
    assert r["errors"] == 1
    a = r["alerts"]
    assert [x["sev"] for x in a] == ["high", "med", "low"]
    assert a[0]["signature"].startswith("ET SCAN Nmap")
    assert (a[0]["src"], a[0]["sp"], a[0]["dst"], a[0]["dp"], a[0]["proto"]) == ("192.168.1.37", 51234, "192.168.1.10", 80, "TCP")
    assert a[0]["category"] == "Web Application Attack" and a[0]["sid"] == 2009358
    assert a[0]["t"] == pytest.approx(1709281230.123456)


def test_parse_zeek_tsv_notice_and_conn():
    r = parse_zeek(ZEEK_NOTICE_TSV.splitlines())
    assert r["counts"] == {"notice": 2}
    n = r["alerts"]
    assert [x["signature"] for x in n] == ["Scan::Port_Scan", "SSL::Invalid_Server_Cert"]
    assert n[0]["src"] == "192.168.1.37" and n[0]["dst"] == "192.168.1.10" and n[0]["sev"] == "med"
    assert n[0]["t"] == pytest.approx(1709287200.123456)
    assert n[1]["dp"] == 443 and n[1]["sub"] == "CN=nas"
    c = parse_zeek(ZEEK_CONN_TSV.splitlines())
    assert c["alerts"] == [] and c["counts"] == {"conn": 3}
    assert c["top_talkers"][0] == {"ip": "192.168.1.23", "bytes": 51500, "conns": 2}


def test_parse_zeek_json():
    r = parse_zeek(ZEEK_JSON)
    assert r["counts"] == {"weird": 1, "notice": 1, "dns": 1, "conn": 1}
    sev = {a["signature"]: a["sev"] for a in r["alerts"]}
    assert sev == {"bad_TCP_checksum": "low", "SSL::Invalid_Server_Cert": "med"}
    nested = [a for a in r["alerts"] if a["log"] == "notice"][0]
    assert nested["src"] == "192.168.1.23" and nested["dp"] == 443  # φωλιασμένο «id»


def test_alerts_forwarded_with_prefix_key_and_cooldown():
    st = St()
    li = LogImport(st, {})
    res = li.import_text("\n".join(EVE), "auto")
    assert res["kind"] == "eve" and res["total"] == 3 and res["counts"]["dns"] == 2
    typ, sev, actor, target, detail, t, kw = st.alerts[0]
    assert typ == "Suricata: ET SCAN Nmap Scripting Engine User-Agent Detected" and sev == "high"
    assert actor == "192.168.1.37" and target == "192.168.1.10" and kw["cooldown"] == 300 and kw["key"]
    assert "Suricata" in detail
    li.import_text(ZEEK_NOTICE_TSV, "zeek")
    assert any(a[0] == "Zeek: Scan::Port_Scan" for a in st.alerts)
    s = li.status()
    assert s["counts"]["suricata:alert"] == 3 and s["counts"]["zeek:notice"] == 2
    assert len(s["recent"]) == 5 and s["recent"][0]["source"] == "zeek"
    json.dumps(s)


def test_upload_size_limit():
    li = LogImport(None, {})
    with pytest.raises(ValueError):
        li.import_text(b"x" * (logimport.MAX_UPLOAD + 1), "eve")


def _w(path, text, mode="a"):
    with open(path, mode) as f:
        f.write(text)


def test_tail_follow_rotation_and_truncation(tmp_path):
    eve = tmp_path / "eve.json"
    _w(eve, EVE[0] + "\n", "w")  # υπήρχε ήδη: με follow δεν διαβάζεται
    st = St()
    li = LogImport(st, {"enabled": True, "files": [{"path": str(eve), "type": "eve", "follow": True}]})
    assert li.poll() == []
    _w(eve, EVE[1] + "\n" + EVE[3][:20])  # μισή γραμμή στο τέλος
    new = li.poll()
    assert [a["sid"] for a in new] == [2013028]
    _w(eve, EVE[3][20:] + "\n")
    assert li.poll() == [] and li.status()["counts"]["suricata:dns"] == 1
    # περιστροφή: το παλιό μετονομάζεται, νέο αρχείο με νέο inode
    os.rename(eve, tmp_path / "eve.json.1")
    _w(eve, EVE[2] + "\n", "w")
    new = li.poll()
    assert [a["signature"] for a in new] == ["ET INFO x"]
    # truncate: μικραίνει → ξανά από την αρχή
    _w(eve, EVE[0] + "\n", "w")
    if os.stat(eve).st_size >= li.tails[0].offset:  # σιγουρευόμαστε ότι είναι μικρότερο
        _w(eve, "", "w")
        li.poll()
        _w(eve, EVE[0] + "\n", "w")
    new = li.poll()
    assert [a["sid"] for a in new] == [2009358]
    f = li.status()["files"][0]
    assert f["ok"] is True and f["alerts"] == 3 and f["lines"] >= 4 and f["last"]
    assert len(st.alerts) == 3


def test_tail_zeek_tsv_follow_keeps_header(tmp_path):
    p = tmp_path / "notice.log"
    head, rows = ZEEK_NOTICE_TSV.split("#types")[0], ZEEK_NOTICE_TSV.splitlines()
    _w(p, head, "w")
    li = LogImport(St(), {"files": [{"path": str(p), "type": "zeek"}]})
    li.poll()
    _w(p, rows[8] + "\n")
    new = li.poll()
    assert [a["signature"] for a in new] == ["Scan::Port_Scan"]


def test_follow_false_reads_whole_file_and_missing_file(tmp_path):
    p = tmp_path / "eve.json"
    _w(p, "\n".join(EVE) + "\n", "w")
    li = LogImport(None, {"files": [{"path": str(p), "type": "eve", "follow": False},
                                    {"path": str(tmp_path / "nope.json"), "type": "eve"}]})
    assert len(li.poll()) == 3
    fs = li.status()["files"]
    assert fs[1]["ok"] is False and fs[1]["error"]


def test_sim():
    st = St()
    li = LogImport(st, {}, sim=True)
    s = li.status()
    assert s["demo"] and s["enabled"] and len(s["recent"]) >= 20 and len(s["files"]) == 2
    sigs = {a["signature"] for a in s["recent"]}
    assert any(x.startswith("ET ") for x in sigs) and any("::" in x for x in sigs)
    assert all(a["src"].startswith(("192.168.1.", "185.")) for a in s["recent"])
    li.rnd.random = lambda: 0.0
    a = li.sim_tick()
    assert a and st.alerts
    json.dumps(li.status())
