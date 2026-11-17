import json
import time

import mqttwatch


class FakeState:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append({"type": typ, "sev": sev, "actor": actor, "detail": detail})


def guard(tmp_path=None, learned=True):
    st = FakeState()
    g = mqttwatch.Guard(st, {"host": "192.168.1.17"}, path=str(tmp_path / "g.json") if tmp_path else None)
    if learned:
        g.learn_until = 0
    return g, st


LOG = "1700000000: New client connected from {ip}:5123 as {cid} (p2, c1, k60, u'{u}')."


def test_helpers():
    assert mqttwatch.device_of("home/garden/temp") == "home/garden"
    assert mqttwatch.device_of("temp") == "temp"
    assert mqttwatch.pattern_of("sensor/240ac4123456/temp") == "sensor/+/temp"
    assert mqttwatch.preview(b"\xff\xfe") .startswith("<")


def test_learning_period_is_quiet():
    g, st = guard(learned=False)
    g.handle("$SYS/broker/log/N", LOG.format(ip="192.168.1.20", cid="esp32-garden", u="garden").encode())
    g.handle("home/garden/relay/set", b"ON", t=time.mktime((2026, 1, 1, 3, 0, 0, 0, 0, -1)))
    assert st.alerts == [] and "esp32-garden" in g.clients


def test_unknown_client_new_topic_and_night_command(tmp_path):
    g, st = guard(tmp_path)
    g.handle("home/garden/temp", b"21.5")
    g.handle("$SYS/broker/log/N", LOG.format(ip="192.168.1.66", cid="mqttx_7f3a", u="garden").encode())
    g.handle("$SYS/broker/log/N", b"1700000000: Client mqttx_7f3a disconnected.")
    night = time.mktime((2026, 1, 1, 3, 0, 0, 0, 0, -1))
    g.handle("home/garden/relay/set", b"ON", t=night)
    types = [a["type"] for a in st.alerts]
    assert "Άγνωστος MQTT client" in types and "Νέο MQTT topic" in types and "Εντολή MQTT σε ασυνήθιστη ώρα" in types
    cl = [a for a in st.alerts if a["type"] == "Άγνωστος MQTT client"][0]
    assert cl["actor"] == "192.168.1.66" and cl["sev"] == "high"
    # ό,τι έμαθε το θυμάται μετά από restart
    saved = json.load(open(tmp_path / "g.json"))
    assert "mqttx_7f3a" in saved["clients"]
    g2, st2 = guard(tmp_path, learned=False)
    assert not g2.learning
    g2.handle("$SYS/broker/log/N", LOG.format(ip="192.168.1.66", cid="mqttx_7f3a", u="garden").encode())
    assert st2.alerts == []


def test_own_client_and_retained_are_ignored():
    g, st = guard()
    g.handle("$SYS/broker/log/N", LOG.format(ip="192.168.1.49", cid="netwatch-guard-1", u="netwatch").encode())
    g.handle("old/retained/state", b"x", retained=True)
    assert st.alerts == [] and not g.clients


def test_silent_device_and_back():
    g, st = guard()
    t = 1000.0
    for i in range(5):
        g.handle("home/door/state", b"closed", t=t + 30 * i)
    st.alerts.clear()  # το «Νέο MQTT topic» της πρώτης φοράς
    g.tick(now=t + 120 + 200)
    assert not st.alerts
    g.tick(now=t + 120 + 400)
    assert [a["type"] for a in st.alerts] == ["IoT συσκευή σιώπησε"]
    g.handle("home/door/state", b"open", t=t + 600)
    assert st.alerts[-1]["type"] == "IoT συσκευή ξαναμίλησε"


def test_status_and_sys_info():
    g, _ = guard()
    g.handle("$SYS/broker/version", b"mosquitto version 2.0.18")
    g.handle("a/b/c", b"1")
    s = g.status()
    assert s["info"]["version"] == "mosquitto version 2.0.18" and s["devices"][0]["id"] == "a/b" and s["msgs"][0]["topic"] == "a/b/c"
