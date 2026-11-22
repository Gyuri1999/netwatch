import importlib.util
import json
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import probes  # noqa: E402
import qr  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


class State:
    me = {"192.168.1.23", "127.0.0.1"}
    sensor = None

    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, detail))


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def mk(tmp_path, clock=None):
    return probes.Probes(State(), str(tmp_path), port=0, clock=clock or Clock(), cert=("x", "y", "AA:BB"))


def token_of(code):
    return probes.read_code(code)["t"]


def test_pair_code_and_hash_only_on_disk(tmp_path):
    p = mk(tmp_path)
    p.enabled = True  # χωρίς πραγματική θύρα
    r = p.pair("Pi γραφείο", "pc")
    c = probes.read_code(r["code"])
    assert c["id"] == r["id"] and c["fp"] == "AA:BB" and c["u"] == ["https://192.168.1.23:0"] and c["k"] == "pc"
    assert r["qr"].startswith("<svg")
    disk = open(os.path.join(tmp_path, "probes.json")).read()
    assert c["t"] not in disk and probes._h(c["t"]) in disk
    if os.name != "nt":  # τα Windows δεν έχουν δικαιώματα τύπου Unix
        assert oct(os.stat(os.path.join(tmp_path, "probes.json")).st_mode & 0o777) == "0o600"
    assert probes.Probes(State(), str(tmp_path), port=0).reg[r["id"]]["name"] == "Pi γραφείο"


def test_report_auth_rate_and_private_only(tmp_path):
    p = mk(tmp_path)
    p.enabled = True
    tok = token_of(p.pair("a", "pc")["code"])
    body = json.dumps({"status": {"fw": "1", "uptime": 5, "interval": 1, "metrics": {"gw_ms": 2.1, "x y": {"no": 1}}}}).encode()
    assert p.report("wrong", "192.168.1.60", body)[0] == 401
    assert p.report(tok, "8.8.8.8", body)[0] == 403
    code, r = p.report(tok, "192.168.1.60", body)
    assert code == 200 and r["interval"] == 10  # όριο 10–3600
    v = p.view()["probes"][0]
    assert v["state"] == "online" and v["status"]["metrics"] == {"gw_ms": 2.1} and v["ip"] == "192.168.1.60"
    for _ in range(probes.RATE):
        p.report(tok, "192.168.1.61", body)
    assert p.report(tok, "192.168.1.61", body)[0] == 429


def test_events_known_become_alerts_unknown_only_logged(tmp_path):
    p = mk(tmp_path)
    p.enabled = True
    tok = token_of(p.pair("VLAN guest", "vlan")["code"])
    evs = [{"type": "vlan_leak", "detail": "Από το guest φτάνω στο 192.168.1.10:445", "data": {"src": "192.168.50.12"}},
           {"type": "<script>", "detail": "x"}, {"type": "weird_thing", "detail": "y"}]
    p.report(tok, "192.168.50.12", json.dumps({"status": {}, "events": evs}).encode())
    assert [a[0] for a in p.state.alerts] == ["Διαρροή διαχωρισμού VLAN (αισθητήρας)"]
    assert p.state.alerts[0][2] == "192.168.50.12"
    types = [e["type"] for e in p.view()["probes"][0]["events"]]
    assert "weird_thing" in types and "script" in types


def test_offline_alert_once_and_back(tmp_path):
    clk = Clock()
    p = mk(tmp_path, clk)
    p.enabled = True
    tok = token_of(p.pair("a", "pc")["code"])
    p.report(tok, "192.168.1.60", b'{"status":{"interval":60}}')
    clk.t += 200
    p.check_offline()
    p.check_offline()
    assert [a[0] for a in p.state.alerts] == ["Αισθητήρας εκτός σύνδεσης"]
    assert p.view()["probes"][0]["state"] == "offline"
    p.report(tok, "192.168.1.60", b'{"status":{"interval":60}}')
    assert p.view()["probes"][0]["state"] == "online"


def test_remove_revokes_and_rename(tmp_path):
    p = mk(tmp_path)
    p.enabled = True
    r = p.pair("a", "pc")
    tok = token_of(r["code"])
    assert p.rename(r["id"], "νέο")["ok"]
    assert p.remove(r["id"])["ok"]
    assert p.report(tok, "192.168.1.60", b"{}")[0] == 401


def test_pair_rejects_unknown_kind_and_mqtt_kinds(tmp_path):
    p = mk(tmp_path)
    assert p.pair("x", "sentinel").get("error") and p.pair("x", "nope").get("error")


def test_demo():
    p = probes.Probes(None, demo=True)
    v = p.view()
    assert v["demo"] and len(v["probes"]) == 3 and v["counts"]["online"] >= 2
    r = p.pair("δοκιμή", "pc")
    assert r["ok"] and len(p.view()["probes"]) == 4


def test_qr_sizes():
    assert len(qr.encode("x")) == 21 and len(qr.encode("y" * 200)) == 57
    with pytest.raises(ValueError):
        qr.encode("z" * 500)


def _client():
    spec = importlib.util.spec_from_file_location("netwatch_probe", os.path.join(ROOT, "tools", "netwatch_probe.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_end_to_end_tls_pinning(tmp_path):
    import agent
    try:
        cert = agent.ensure_cert(str(tmp_path), cn="netwatch-probes")
    except RuntimeError:
        pytest.skip("χωρίς openssl/cryptography")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    st = State()
    st.me = {"127.0.0.1"}
    p = probes.Probes(st, str(tmp_path), port=port, cert=cert)
    p.enabled = True
    p.start()
    try:
        assert p.srv, p.error
        r = p.pair("e2e", "pc")
        conf = probes.read_code(r["code"])
        conf["u"] = [f"https://127.0.0.1:{port}"]
        cl = _client()
        out = cl.post(conf, {"status": {"fw": "t", "interval": 30}, "events": [{"type": "outage", "detail": "δοκιμή"}]})
        assert out["ok"] and out["name"] == "e2e"
        assert p.view()["probes"][0]["state"] == "online"
        assert st.alerts and st.alerts[0][0] == "Διακοπή δικτύου (αισθητήρας)"
        bad = dict(conf, fp="00:" * 31 + "00")
        with pytest.raises(RuntimeError):
            cl.post(bad, {"status": {}})
    finally:
        p.stop()


def test_port_taken_is_reported_not_shared(tmp_path):
    import agent
    try:
        cert = agent.ensure_cert(str(tmp_path), cn="netwatch-probes")
    except RuntimeError:
        pytest.skip("χωρίς openssl/cryptography")
    busy = socket.socket()
    busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    busy.bind(("127.0.0.1", 0))
    busy.listen(1)
    try:
        p = probes.Probes(State(), str(tmp_path), port=busy.getsockname()[1], cert=cert)
        p.enabled = True
        p.start()
        assert p.srv is None and p.error and str(busy.getsockname()[1]) in p.error
    finally:
        busy.close()


def test_probe_port_outside_ui_fallback_range():
    assert not 8765 <= probes.PORT <= 8765 + 19
