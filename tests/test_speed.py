import json

import pytest

import speed

IPERF_TCP = json.dumps({
    "start": {"connected": [{"socket": 5, "local_host": "192.168.1.50", "local_port": 50000,
                             "remote_host": "192.168.1.16", "remote_port": 5201}],
              "test_start": {"protocol": "TCP", "num_streams": 1, "duration": 5, "reverse": 0}},
    "intervals": [],
    "end": {"sum_sent": {"start": 0, "end": 5.0, "seconds": 5.0, "bytes": 587202560, "bits_per_second": 939524096.0,
                         "retransmits": 12, "sender": True},
            "sum_received": {"start": 0, "end": 5.0, "seconds": 5.0, "bytes": 585000000, "bits_per_second": 936000000.0,
                             "sender": True},
            "cpu_utilization_percent": {"host_total": 12.5, "remote_total": 3.1}}})

IPERF_UDP = json.dumps({
    "start": {"connected": [{"remote_host": "10.0.0.5", "remote_port": 5201}],
              "test_start": {"protocol": "UDP", "num_streams": 1, "duration": 5, "reverse": 1}},
    "end": {"sum": {"bits_per_second": 1048576.0, "jitter_ms": 0.042, "lost_percent": 0.5}}})


def test_parse_iperf_tcp():
    r = speed.parse_iperf(IPERF_TCP)
    assert r["ok"] and r["protocol"] == "TCP" and not r["reverse"]
    assert r["sent_mbps"] == 939.52 and r["recv_mbps"] == 936.0 and r["retransmits"] == 12
    assert r["remote"] == "192.168.1.16" and r["cpu_local"] == 12.5


def test_parse_iperf_udp_and_errors():
    r = speed.parse_iperf(IPERF_UDP)
    assert r["ok"] and r["protocol"] == "UDP" and r["reverse"] and r["jitter_ms"] == 0.042 and r["lost_percent"] == 0.5
    e = speed.parse_iperf(json.dumps({"start": {}, "end": {}, "error": "error - unable to connect to server: Connection refused"}))
    assert not e["ok"] and "unable to connect" in e["error"]
    assert not speed.parse_iperf("garbage")["ok"]


@pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "224.0.0.1", "0.0.0.0", "-c", ""])
def test_refuses_public_targets(host):
    with pytest.raises(speed.SpeedError):
        speed.check_private(host, resolve=False)


@pytest.mark.parametrize("host", ["192.168.1.16", "10.0.0.5", "172.20.1.1", "fd00::5", "100.101.102.103", "127.0.0.1"])
def test_accepts_private_targets(host):
    assert speed.check_private(host, resolve=False) == host


def test_public_target_refused_before_running(monkeypatch):
    monkeypatch.setattr(speed.subprocess, "run", lambda *a, **k: pytest.fail("δεν έπρεπε να τρέξει"))
    s = speed.Speed(path="/nonexistent/x.json")
    r = s.iperf("8.8.8.8")
    assert not r["ok"] and "δημόσιο" in r["error"]


def test_missing_binary_message(monkeypatch, tmp_path):
    monkeypatch.setattr(speed.shutil, "which", lambda name: None)
    s = speed.Speed(path=str(tmp_path / "speed.json"))
    r = s.iperf("192.168.1.16")
    assert not r["ok"] and r["missing"] and "brew install iperf3" in r["error"] and "iperf3 -s" in r["error"]
    st = s.status()
    assert not st["iperf_available"] and "Proxmox" in st["iperf_help"]
    with pytest.raises(speed.SpeedError):
        speed.run_iperf("192.168.1.16")


def test_run_iperf_uses_json_and_history(monkeypatch, tmp_path):
    calls = []

    class Out:
        stdout, stderr = IPERF_TCP, ""

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return Out()
    monkeypatch.setattr(speed.shutil, "which", lambda name: "/usr/local/bin/iperf3")
    monkeypatch.setattr(speed.subprocess, "run", fake_run)
    p = tmp_path / "d" / "speed.json"
    s = speed.Speed(path=str(p))
    r = s.iperf("192.168.1.16", reverse=True)
    assert r["ok"] and r["sent_mbps"] == 939.52
    assert "-J" in calls[0] and "-R" in calls[0] and calls[0][2] == "192.168.1.16"
    assert json.loads(p.read_text())[0]["kind"] == "iperf"
    assert speed.Speed(path=str(p)).status()["last_iperf"]["sent_mbps"] == 939.52


def test_history_bounded(monkeypatch, tmp_path):
    s = speed.Speed(path=str(tmp_path / "s.json"))
    for i in range(speed.KEEP + 30):
        s._push({"kind": "internet", "t": i})
    assert len(s.history()) == speed.KEEP and s.history()[0]["t"] == 30


def test_internet_failure_is_reported(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise OSError("χωρίς δίκτυο")
    monkeypatch.setattr(speed, "internet_test", boom)
    r = speed.Speed(path=str(tmp_path / "s.json")).internet()
    assert not r["ok"] and "Cloudflare" in r["note"]


def test_demo_results():
    s = speed.Speed(sim=True)
    assert s.status()["count"] > 0
    r = s.internet()
    assert r["ok"] and r["demo"] and 100 < r["down_mbps"] < 400
    r = s.iperf("192.168.1.16")
    assert r["ok"] and r["sent_mbps"] > 800
    assert not s.iperf("8.8.8.8")["ok"]
