import json

import hass


class St:
    def __init__(self):
        import threading
        self.lock = threading.Lock()
        self.hosts = {"192.168.1.20": {"kind": "local"}, "1.1.1.1": {"kind": "public"}}

    def audit(self):
        return {"score": 82}


def test_discovery_entities_have_unique_ids_and_device():
    h = hass.HomeAssistant(St(), {"host": "b"})
    d = dict(h.discovery())
    assert "homeassistant/binary_sensor/netwatch/attack/config" in d
    assert {c["unique_id"] for c in d.values()} == {"netwatch_attack", "netwatch_last_alert", "netwatch_alerts_hour",
                                                   "netwatch_devices", "netwatch_score"}
    assert all(c["device"]["identifiers"] == ["netwatch"] and c["availability_topic"] == "netwatch/ha/status" for c in d.values())


def test_alert_publishes_event_last_and_attack_window():
    h = hass.HomeAssistant(St(), {"host": "b"})
    h.on_alert({"type": "Port scan", "sev": "high", "actor": "192.168.1.66", "target": "192.168.1.20", "detail": "x", "t": 1000,
                "mitre": {"id": "T1046"}})
    sent = {t: (p, r) for t, p, r in h.sent}
    assert json.loads(sent["netwatch/alerts"][0])["mitre"] == "T1046" and sent["netwatch/ha/last_alert"][1] is True
    assert sent["netwatch/ha/attack"][0] == "ON" and sent["netwatch/ha/alerts_hour"][0] == "1"
    h.publish_state(now=1000 + 601, full=True)
    sent = {t: p for t, p, _ in h.sent}
    assert sent["netwatch/ha/attack"] == "OFF" and sent["netwatch/ha/devices"] == "1" and sent["netwatch/ha/score"] == "82"


def test_not_configured_is_silent():
    h = hass.HomeAssistant(St(), {})
    h.on_alert({"type": "x", "sev": "high", "actor": "a", "target": "b", "detail": "", "t": 1})
    assert h.sent == []
