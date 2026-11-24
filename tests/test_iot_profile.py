"""🔴 Προφίλ IoT: αναγνώριση πλατφόρμας (Home Assistant, ESPHome, Tasmota, Shelly, κάμερα, ESP) + συμβουλές."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pentest as P  # noqa: E402


def host(vendor="", names=(), model=None, ports=(), banners=None, svc=None):
    """Φτιάχνει host-dict όπως μετά το _enrich. ports: λίστα (port) ή (port, proto)."""
    svcs = []
    banners = banners or {}
    for p in ports:
        port, proto = (p if isinstance(p, tuple) else (p, "tcp"))
        svcs.append({"port": port, "proto": proto, "banner": banners.get(port, ""), "svc": (svc or {}).get(port, "")})
    return {"vendor": vendor, "names": list(names), "model": model, "services": svcs}


def test_each_platform():
    assert P.iot_profile(host(ports=[8123]))["kind"] == "homeassistant"
    assert P.iot_profile(host(names=["myhass"], banners={80: "Home Assistant"}, ports=[80]))["kind"] == "homeassistant"
    assert P.iot_profile(host(ports=[6053]))["kind"] == "esphome"
    assert P.iot_profile(host(vendor="Espressif Inc.", banners={80: "Server: Tasmota"}, ports=[80]))["kind"] == "tasmota"
    assert P.iot_profile(host(vendor="Allterco Robotics", names=["shellyplug-ABC"], ports=[80]))["kind"] == "shelly"
    assert P.iot_profile(host(ports=[554, 8000]))["kind"] == "camera"
    assert P.iot_profile(host(vendor="Espressif Inc.", names=["esp-light01"], ports=[80]))["kind"] == "esp"
    assert P.iot_profile(host(vendor="Seiko Epson", ports=[9100]))["kind"] == "printer"


def test_specific_beats_generic():
    # Tasmota/ESPHome τρέχουν σε ESP (Espressif) — κερδίζει η πλατφόρμα, όχι το γενικό «ESP»
    assert P.iot_profile(host(vendor="Espressif Inc.", banners={80: "Tasmota"}, ports=[80]))["kind"] == "tasmota"
    assert P.iot_profile(host(vendor="Espressif Inc.", ports=[6053, 80]))["kind"] == "esphome"


def test_mqtt_advice_appended_and_deduped():
    # Home Assistant + 1883 → προστίθεται συμβουλή MQTT (χωρίς κρυπτογράφηση)
    ha = P.iot_profile(host(ports=[8123, 1883]))
    assert any("MQTT χωρίς κρυπτογράφηση" in a[1] for a in ha["advice"])
    # TLS MQTT → ηπιότερη συμβουλή
    ha_tls = P.iot_profile(host(ports=[8123, 8883]))
    assert any("8883" in a[1] for a in ha_tls["advice"])
    # Shelly ήδη μιλά για MQTT → δεν διπλασιάζεται
    sh = P.iot_profile(host(vendor="Allterco", names=["shelly1"], ports=[80, 1883]))
    assert sum("mqtt" in a[1].lower() for a in sh["advice"]) == 1
    # σκέτος broker χωρίς πλατφόρμα
    br = P.iot_profile(host(ports=[1883]))
    assert br["kind"] == "mqtt" and br["advice"] and "1883" in br["advice"][0][1]


def test_no_false_positive():
    assert P.iot_profile(host(vendor="Dell Inc.", ports=[80])) is None
    assert P.iot_profile(host(vendor="Microsoft", ports=[443, 3389])) is None
    assert P.iot_profile(host()) is None


def test_enrich_attaches_iot(monkeypatch):
    s = P.LanScanner.__new__(P.LanScanner)
    monkeypatch.setattr(s, "_set", lambda **k: None, raising=False)
    import netkit
    monkeypatch.setattr(netkit, "discover_names", lambda ips, timeout=2, sim=False: {"10.0.0.5": {"names": ["tasmota-X"], "model": None, "sources": {}}})
    monkeypatch.setattr(netkit, "mac_vendor", lambda mac: "Espressif Inc.")
    monkeypatch.setattr(netkit, "ping", lambda ip, **k: {"ttl": 255, "os_guess": "IoT"})
    hosts = [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "services": [{"port": 80, "proto": "tcp", "banner": "Server: Tasmota/12.1"}]}]
    s._enrich(hosts, udp=False, sim=False)
    assert hosts[0]["iot"]["kind"] == "tasmota" and hosts[0]["iot"]["icon"] == "💡"
