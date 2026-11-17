import json

import sensor


class FakeState:
    gateway = "192.168.1.1"

    def __init__(self):
        self.alerts = []

    def alert(self, *a, **k):
        self.alerts.append((a, k))


def test_to_alert_deauth_and_twins():
    a = sensor.to_alert({"type": "deauth", "id": "sentinel-1", "channel": 6, "count": 42, "bssid": "AA:BB:CC:DD:EE:FF",
                         "target": "ff:ff:ff:ff:ff:ff", "rssi": -40})
    assert a[0] == "Deauth επίθεση στο Wi‑Fi" and "ΟΛΟΥΣ" in a[2] and "πολύ κοντά" in a[2] and a[3] == "deauth:sentinel-1:6"
    t = sensor.to_alert({"type": "evil_twin", "id": "s", "ssid": "Home", "bssid": "11:22:33:44:55:66", "security": "open", "channel": 11})
    assert t[0].startswith("Evil twin Wi‑Fi") and t[1] == "high"
    r = sensor.to_alert({"type": "rogue_ap", "id": "s", "ssid": "Home", "bssid": "bad mac", "security": "wpa2"})
    assert r[0] == "Άγνωστο access point" and "?" in r[2]
    assert sensor.to_alert({"type": "nope"}) is None


def test_bridge_handle():
    st = FakeState()
    b = sensor.Bridge(st, {"mqtt_host": "x"})
    b.handle("netwatch/sensor/sentinel-abc/status", json.dumps({"online": True, "fw": "1.0.0", "rssi": -55, "id": "spoofed"}).encode(), t=1000)
    b.handle("netwatch/sensor/sentinel-abc/event", json.dumps({"type": "deauth", "count": 50, "channel": 1}).encode(), t=1001)
    b.handle("netwatch/sensor/../evil/event", b"{}")          # λάθος topic → αγνοείται
    b.handle("netwatch/sensor/x/event", b"not json")
    assert len(st.alerts) == 1 and st.alerts[0][0][0] == "Deauth επίθεση στο Wi‑Fi"
    s = b.status()
    assert s["sensors"][0]["id"] == "sentinel-abc" and s["events"][0]["sensor"] == "sentinel-abc"


def test_offline_after_silence(monkeypatch):
    b = sensor.Bridge(FakeState(), {"mqtt_host": "x"})
    b.handle("netwatch/sensor/s1/status", b'{"online": true}', t=1000)
    monkeypatch.setattr(sensor.time, "time", lambda: 1000 + sensor.OFFLINE_AFTER + 1)
    assert b.status()["sensors"][0]["online"] is False


def test_canary_event_alerts_on_the_toucher():
    import sensor
    class St:
        gateway = "192.168.1.1"
        def __init__(self):
            self.alerts = []
        def alert(self, typ, sev, actor, target, detail, t, **kw):
            self.alerts.append((typ, sev, actor, detail))
    st = St()
    b = sensor.Bridge(st, {})
    b.handle("netwatch/sensor/canary-a1b2c3/event", '{"type":"canary","port":23,"src":"192.168.30.66","service":"telnet","data":"root","user":"root"}')
    typ, sev, actor, detail = st.alerts[0]
    assert typ == "Καναρίνι ESP32" and sev == "high" and actor == "192.168.30.66" and "root" in detail
    b.handle("netwatch/sensor/canary-a1b2c3/event", '{"type":"canary","port":80,"src":"not-an-ip"}')
    assert st.alerts[1][2] == "192.168.1.1"  # χωρίς έγκυρη IP → όχι ψεύτικος δράστης
