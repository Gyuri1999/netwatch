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
    assert v["demo"] and len(v["probes"]) == 7 and v["counts"]["online"] >= 6
    kinds = {x["kind"]: x for x in v["probes"]}
    assert {"pc", "vlan", "rack", "field", "ble", "zigbee", "lora"} == set(kinds)
    rack = kinds["rack"]["status"]
    assert rack["metrics"]["volt"] > 200 and rack["metrics"]["door"] is False and rack["metrics"]["leak"] is False and rack["hum"]
    assert kinds["field"]["status"]["link"]["lldp_port"] and kinds["field"]["status"]["link"]["poe"] is True
    assert kinds["ble"]["items_n"] >= 5 and kinds["zigbee"]["items_n"] >= 5 and kinds["lora"]["items_n"] == 3
    assert "items" not in kinds["ble"]  # η προβολή δίνει μόνο το πλήθος
    assert all(len(json.dumps(x)) < 4000 for x in v["probes"])
    assert {r["mac"] for r in p.items("ble")[0]["items"]} >= {"d3:5a:91:0c:44:e2"}
    assert p.items("zigbee")[0]["metrics"]["ch11"] > 0 and len(p.items("lora")[0]["items"]) == 3
    json.dumps(v), json.dumps(p.items())
    r = p.pair("δοκιμή", "pc")
    assert r["ok"] and len(p.view()["probes"]) == 8


def _paired(tmp_path, kind, clock=None):
    p = mk(tmp_path, clock)
    p.enabled = True
    r = p.pair("x", kind)
    return p, r["id"], token_of(r["code"])


def test_new_kinds_pairable_ready_and_have_fw_hint(tmp_path):
    for k in ("rack", "field", "ble", "zigbee", "lora"):
        assert k in probes.PAIRABLE and probes.KINDS[k]["ready"] is True and probes.KINDS[k]["fw"]
        p, _pid, _tok = _paired(tmp_path / k, k)
        assert p.view()["probes"][0]["kind"] == k and p.view()["kinds"][k]["fw"] == probes.KINDS[k]["fw"]
    assert probes.KINDS["rack"]["hw"] == "ESP32 + SHT31 + μαγνητική επαφή + αισθητήρας νερού + PZEM-004T (προαιρετικά)"
    assert probes.KINDS["field"]["hw"] == "Olimex ESP32-POE ή Raspberry Pi"
    assert probes.KINDS["zigbee"]["fw"] == "tools/zigbee_sniff.py" and probes.KINDS["lora"]["fw2"] == "firmware/esp32-lora-node"
    assert probes.KINDS["field"]["fw"] == "firmware/esp32-poe" and probes.KINDS["field"]["fw2"] == "tools/fieldbox"


def test_items_stored_flattened_replaced_and_exposed(tmp_path):
    p, pid, tok = _paired(tmp_path, "ble")
    rows = [{"mac": "aa:bb:cc:dd:ee:%02x" % i, "rssi": -60 - i, "name": "dev<%d>" % i, "mfr": 76, "svc": "feaa", "ad": "0215",
             "rnd": True, "conn": False} for i in range(5)]
    assert p.report(tok, "192.168.1.60", json.dumps({"status": {"metrics": {"seen": 5}}, "items": rows}).encode())[0] == 200
    v = p.view()["probes"][0]
    assert v["items_n"] == 5 and "items" not in v
    it = p.items("ble")
    assert len(it) == 1 and it[0]["id"] == pid and it[0]["name"] == "x" and it[0]["kind"] == "ble" and it[0]["seen"] == 1000.0
    assert it[0]["items"][0] == rows[0] and it[0]["metrics"] == {"seen": 5}
    assert p.items("zigbee") == [] and len(p.items()) == 1
    # αναφορά χωρίς το κλειδί → η λίστα μένει· με το κλειδί → αντικαθίσταται
    p.report(tok, "192.168.1.60", b'{"status":{}}')
    assert p.view()["probes"][0]["items_n"] == 5
    p.report(tok, "192.168.1.60", json.dumps({"items": rows[:2]}).encode())
    assert len(p.items("ble")[0]["items"]) == 2
    p.report(tok, "192.168.1.60", b'{"items":[]}')
    assert p.items("ble")[0]["items"] == []
    it[0]["items"].append({"x": 1})  # αντίγραφο, όχι η ζωντανή λίστα
    assert p.items("ble")[0]["items"] == []


def test_items_hostile_input(tmp_path):
    p, _pid, tok = _paired(tmp_path, "zigbee")
    big = [{"ch": 11, "pan": "1a62", "src": "%04x" % i, "n": i} for i in range(300)]
    body = json.dumps({"items": big}).encode()
    assert len(body) <= probes.MAX_BODY  # χωράει στο όριο· ο server κρατά μόνο 80
    assert p.report(tok, "192.168.1.60", body)[0] == 200
    assert len(p.items()[0]["items"]) == probes.MAX_ITEMS == 80
    nested = [{"ch": 11, "deep": {"a": {"b": [1, 2]}}, "lst": [1], "nul": None, "s": "x" * 500, "bad key!": 1, "inf": 1e300},
              "string", 5, None, ["list"], {}, {"only": {"nested": 1}}, dict(("k%d" % i, i) for i in range(40))]
    assert p.report(tok, "192.168.1.60", json.dumps({"items": nested}).encode())[0] == 200
    it = p.items()[0]["items"]
    assert len(it) == 2  # μη-dict και άδειες γραμμές πετιούνται
    assert it[0] == {"ch": 11, "s": "x" * 60, "badkey": 1} and len(it[1]) == 12
    for junk in ('"text"', "5", "null", '{"a":1}', "true"):
        assert p.report(tok, "192.168.1.60", ('{"items":%s}' % junk).encode())[0] == 200
        assert p.items()[0]["items"] == []
    assert p.view()["probes"][0]["items_n"] == 0
    json.dumps(p.view())


def test_new_events_alerts_and_notes(tmp_path):
    want = {"water_leak": ("Διαρροή νερού στο rack (αισθητήρας)", "high"), "power_fail": ("Διακοπή ρεύματος στο rack (αισθητήρας)", "high"),
            "humid_high": ("Υψηλή υγρασία στο rack (αισθητήρας)", "med"), "ble_tracker": ("Bluetooth tracker κοντά (αισθητήρας)", "med"),
            "poe_lost": ("Χάθηκε το PoE (αισθητήρας)", "med"), "link_down": ("Έπεσε η σύνδεση Ethernet (αισθητήρας)", "med"),
            "lora_node_lost": ("Κόμβος LoRa σιώπησε (αισθητήρας)", "med"), "batt_low": ("Χαμηλή μπαταρία (αισθητήρας)", "low")}
    for k, v in want.items():
        assert probes.EVENTS[k] == v
    assert all(t.endswith("(αισθητήρας)") for t, _s in probes.EVENTS.values())
    assert "power_back" not in probes.EVENTS
    p, _pid, tok = _paired(tmp_path, "rack")
    evs = [{"type": k, "detail": "δοκιμή " + k} for k in want]
    p.report(tok, "192.168.1.61", json.dumps({"events": evs}).encode())
    assert [(a[0], a[1]) for a in p.state.alerts] == list(want.values())
    assert p.state.alerts[0][3] == "αισθητήρας x" and p.state.alerts[0][4] == "δοκιμή water_leak"
    n = len(p.state.alerts)
    p.report(tok, "192.168.1.61", json.dumps({"events": [{"type": "power_back", "detail": "ήρθε το ρεύμα"}]}).encode())
    assert len(p.state.alerts) == n  # μόνο σημείωση στο ιστορικό
    assert p.view()["probes"][0]["events"][0]["type"] == "power_back"


def test_per_node_events_get_their_own_alert_key(tmp_path):
    class St(State):
        def alert(self, typ, sev, actor, target, detail, t, **kw):
            self.alerts.append((typ, kw.get("key")))
    p = probes.Probes(St(), str(tmp_path), port=0, clock=Clock(), cert=("x", "y", "AA:BB"))
    p.enabled = True
    r = p.pair("gw", "lora")
    tok = token_of(r["code"])
    evs = [{"type": "lora_node_lost", "detail": "a", "data": {"node": "silo-01"}}, {"type": "lora_node_lost", "detail": "b", "data": {"node": "pump-03"}},
           {"type": "ble_tracker", "detail": "c", "data": {"mac": "aa:bb:cc:dd:ee:ff", "kind": "findmy"}},
           {"type": "batt_low", "detail": "d", "data": {"node": True}}, {"type": "door_open", "detail": "e"}]
    p.report(tok, "192.168.1.64", json.dumps({"events": evs}).encode())
    keys = [k for _t, k in p.state.alerts]
    assert keys == [("probe", r["id"], "lora_node_lost", "silo-01"), ("probe", r["id"], "lora_node_lost", "pump-03"),
                    ("probe", r["id"], "ble_tracker", "aa:bb:cc:dd:ee:ff"), ("probe", r["id"], "batt_low"), ("probe", r["id"], "door_open")]


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
