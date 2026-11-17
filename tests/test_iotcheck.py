import socket
import threading

import iotcheck


def test_kind_of():
    assert iotcheck.kind_of("24:0A:C4:12:34:56") == "esp"
    assert iotcheck.kind_of("dc:a6:32:00:00:01") == "pi"
    assert iotcheck.kind_of("26:0a:c4:12:34:56") is None  # locally administered: δεν εμπιστευόμαστε το OUI
    assert iotcheck.kind_of(None, ["esp32-garden.local"]) == "esp"
    assert iotcheck.kind_of("aa:bb:cc:00:00:00", ["raspberrypi.lan"]) == "pi"
    assert iotcheck.kind_of("aa:bb:cc:00:00:00", ["laptop"]) is None


def test_assess_rules():
    dev = {"ip": "192.168.1.70", "mac": None, "kind": "pi", "name": "pi"}
    r = iotcheck.assess(dev, {22: "SSH-2.0-OpenSSH", 23: "", 1883: ""}, mqtt_anon=True)
    titles = [f["title"] for f in r["findings"]]
    assert r["level"] == "bad" and any("ΟΛΟΥΣ" in t for t in titles) and "Telnet ανοιχτό" in titles
    assert r["score"] == 100 - 35 - 35
    mq = next(f for f in r["findings"] if f["port"] == 1883)
    assert mq["lesson"] == "iot-4-2"
    ok = iotcheck.assess(dev, {22: "", 8883: ""})
    assert ok["level"] == "ok" and ok["score"] == 100


def fake_broker(code):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        c, _ = srv.accept()
        data = c.recv(64)
        assert data[0] == 0x10 and b"MQTT" in data
        c.sendall(bytes([0x20, 2, 0, code]))
        c.close()
        srv.close()
    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


def test_mqtt_anonymous():
    assert iotcheck.mqtt_anonymous("127.0.0.1", fake_broker(0)) is True
    assert iotcheck.mqtt_anonymous("127.0.0.1", fake_broker(5)) is False  # not authorized
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert iotcheck.mqtt_anonymous("127.0.0.1", port, timeout=0.5) is None


def test_demo_flow():
    c = iotcheck.IotCheck(lambda: [], sim=True)
    c._run([])
    st = c.status()
    assert {d["kind"] for d in st["result"]} == {"esp", "pi"}


def test_norm_mac_macos_arp_format():
    assert iotcheck.norm_mac("8:aa:89:41:26:4") == "08:aa:89:41:26:04"
    assert iotcheck.norm_mac("bogus") is None
    assert iotcheck.kind_of("24:ec:4a:cb:5:d8") == "esp"  # νεότερο OUI Espressif, σε μορφή macOS


def test_sweep_targets_only_private_slash24():
    t = iotcheck.sweep_targets({"192.168.1.49", "8.8.8.8", "127.0.0.1", "fe80::1"})
    assert len(t) == 253 and "192.168.1.49" not in t and t[0] == "192.168.1.1"


def test_discover_finds_broker_on_unknown_device(monkeypatch):
    monkeypatch.setattr(iotcheck, "probe", lambda ip, p, timeout=0.8: "" if (ip, p) == ("192.168.1.17", 1883) else None)
    monkeypatch.setattr(iotcheck, "arp_table", lambda: {"192.168.1.17": "bc:24:11:2b:f6:bd"})
    c = iotcheck.IotCheck(lambda: [], my_ips=lambda: {"192.168.1.49"})
    found = c._discover(set())
    assert found == [{"ip": "192.168.1.17", "mac": "bc:24:11:2b:f6:bd", "kind": "srv", "name": "VM/container Proxmox"}]


def test_versions_and_known_vulns():
    v = iotcheck.versions({22: "SSH-2.0-OpenSSH_9.6p1\r\n", 80: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"},
                          [{"product": "Mosquitto", "version": "2.0.18", "port": 1883, "distro": None}])
    by = {x["product"]: x for x in v}
    assert [k["id"] for k in by["OpenSSH"]["known"]] == ["CVE-2024-6387"]
    assert by["nginx"]["version"] == "1.18.0" and by["nginx"]["known"] == []
    assert [k["id"] for k in by["Mosquitto"]["known"]] == ["CVE-2024-8376"]
    assert iotcheck.versions({22: "SSH-2.0-OpenSSH_9.9p1"})[0]["known"] == []


def test_assess_distro_backport_is_info_not_penalty():
    dev = {"ip": "192.168.1.70", "mac": None, "kind": "pi", "name": "pi"}
    plain = iotcheck.assess(dev, {22: "SSH-2.0-OpenSSH_9.2p1"})
    distro = iotcheck.assess(dev, {22: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"})
    f1 = [f for f in plain["findings"] if f["title"].startswith("Παλιά")][0]
    f2 = [f for f in distro["findings"] if f["title"].startswith("Παλιά")][0]
    assert f1["status"] == "warn" and f2["status"] == "info" and plain["score"] < distro["score"]
