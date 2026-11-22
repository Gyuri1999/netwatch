import csv
import io
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import iotinv as iv  # noqa: E402


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class State:
    def __init__(self):
        self.alerts = []
        self.hosts = {"192.168.1.41": {"ip": "192.168.1.41", "kind": "local", "names": {"boiler.lan"}, "mac": "AA:BB:CC:00:00:41"},
                      "192.168.1.77": {"ip": "192.168.1.77", "kind": "local", "names": set(), "mac": "98:f4:ab:d0:11:22"}}

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append({"type": typ, "sev": sev, "actor": actor, "target": target, "detail": detail, "key": kw.get("key"), "cooldown": kw.get("cooldown")})


def mk(tmp_path=None, clk=None, st=None):
    st = st or State()
    clk = clk or Clock()
    return iv.IotInv(st, str(tmp_path) if tmp_path else None, clock=clk), st, clk


def J(o):
    return json.dumps(o).encode()


def dev(inv, key):
    return next(r for r in inv.rows() if r["key"] == key)


Z2M_DEVICES = [
    {"friendly_name": "Coordinator", "ieee_address": "0x00124b0024c1a7f3", "type": "Coordinator", "interview_completed": True, "definition": None},
    {"friendly_name": "salon/temp", "ieee_address": "0x00158D0003A1B2C3", "type": "EndDevice", "power_source": "Battery", "software_build_id": "3000-0001",
     "interview_completed": True, "model_id": "lumi.weather", "manufacturer": "LUMI",
     "definition": {"model": "WSDCGQ11LM", "vendor": "Aqara", "description": "Temperature and humidity sensor", "exposes": [{"type": "numeric"}] * 20}},
    {"friendly_name": "kitchen plug", "ieee_address": "0x000d6ffffe9a8b7c", "type": "Router", "power_source": "Mains (single phase)", "software_build_id": "2.0.024",
     "interview_state": "SUCCESSFUL", "definition": {"model": "E1603/E1702/E1708", "vendor": "IKEA"}},
    {"friendly_name": "0x00158d0009999999", "ieee_address": "0x00158d0009999999", "type": "EndDevice", "interview_state": "FAILED", "definition": None},
    "junk", 5, None, {"no": "name"},
]


# ── Zigbee2MQTT ──
def test_z2m_bridge_devices_state_and_updates():
    inv, st, clk = mk()
    inv.handle("zigbee2mqtt/bridge/state", b'{"state":"online"}', True)
    inv.handle("zigbee2mqtt/bridge/info", J({"version": "1.39.1", "coordinator": {"type": "zStack3x0", "meta": {}}, "permit_join": True,
                                             "network": {"channel": 11, "pan_id": 6754, "extended_pan_id": "0xdd"}, "config": {"mqtt": {"password": "hunter2"}}}), True)
    inv.handle("zigbee2mqtt/bridge/devices", J(Z2M_DEVICES), True)
    assert inv.z2m == {"state": "online", "version": "1.39.1", "coordinator": "zStack3x0", "channel": 11, "pan_id": "6754", "permit_join": True}
    assert "hunter2" not in json.dumps(inv.view())
    assert {r["key"] for r in inv.rows()} == {"z2m:Coordinator", "z2m:salon/temp", "z2m:kitchen plug", "z2m:0x00158d0009999999"}
    t = dev(inv, "z2m:salon/temp")
    assert (t["model"], t["vendor"], t["ieee"], t["fw"], t["power"], t["type"]) == ("WSDCGQ11LM", "Aqara", "0x00158d0003a1b2c3", "3000-0001", "battery", "EndDevice")
    assert t["btype"] == "1× CR2032" and t["online"] is None and t["last"] is None
    assert dev(inv, "z2m:Coordinator")["online"] is True and dev(inv, "z2m:Coordinator")["model"] == "zStack3x0"
    assert [p["code"] for p in dev(inv, "z2m:0x00158d0009999999")["problems"]] == ["interview"]
    # κατάσταση συσκευής (το όνομα έχει «/»)
    inv.handle("zigbee2mqtt/salon/temp", J({"battery": 87, "linkquality": 31, "temperature": 21.4, "last_seen": "2023-11-14T22:10:00+00:00"}), True)
    t = dev(inv, "z2m:salon/temp")
    assert t["batt"] == 87 and t["lqi"] == 31 and t["last"] == 1699999800.0 and [p["code"] for p in t["problems"]] == ["weak"]
    clk.t += 50
    inv.handle("zigbee2mqtt/salon/temp", J({"battery": 86, "linkquality": 120}))
    assert dev(inv, "z2m:salon/temp")["last"] == clk.t and dev(inv, "z2m:salon/temp")["problems"] == []
    inv.handle("zigbee2mqtt/kitchen plug", J({"state": "ON", "linkquality": 142, "update": {"state": "available", "installed_version": 33, "latest_version": 36}}))
    inv.handle("zigbee2mqtt/kitchen plug/availability", b'{"state":"online"}', True)
    k = dev(inv, "z2m:kitchen plug")
    assert k["update"] and k["update_to"] == "36" and k["fw"] == "2.0.024" and k["online"] is True and k["power"] == "mains"
    assert [p["code"] for p in k["problems"]] == ["update"] and "36" in k["problems"][0]["el"]
    inv.handle("zigbee2mqtt/kitchen plug", J({"linkquality": 140, "update": {"state": "idle"}}))
    assert not dev(inv, "z2m:kitchen plug")["update"]
    inv.handle("zigbee2mqtt/kitchen plug/availability", b"offline")  # παλιά μορφή: σκέτο κείμενο
    assert dev(inv, "z2m:kitchen plug")["online"] is False
    # ό,τι δεν είναι συσκευή δεν γίνεται συσκευή
    for topic, pl in (("zigbee2mqtt/bridge/logging", J({"level": "info", "message": "x"})), ("zigbee2mqtt/bridge/response/permit_join", J({"status": "ok"})),
                      ("zigbee2mqtt/kitchen plug/set", J({"state": "OFF", "linkquality": 1})), ("zigbee2mqtt/kitchen plug/get", b"{}"),
                      ("zigbee2mqtt/unknown thing", J({"hello": 1})), ("zigbee2mqtt/unknown thing", b"not json"), ("zigbee2mqtt", b"x")):
        inv.handle(topic, pl)
    assert len(inv.rows()) == 4 and dev(inv, "z2m:kitchen plug")["lqi"] == 140


def test_z2m_rename_and_removal_follow_bridge_list():
    inv, st, clk = mk()
    inv.handle("zigbee2mqtt/bridge/devices", J(Z2M_DEVICES), True)
    inv.handle("zigbee2mqtt/salon/temp", J({"battery": 9, "linkquality": 80}))
    inv.tick()
    assert len(st.alerts) == 1
    lst = [dict(Z2M_DEVICES[1], friendly_name="Σαλόνι θερμόμετρο"), Z2M_DEVICES[2]]
    inv.handle("zigbee2mqtt/bridge/devices", J(lst), True)
    assert {r["key"] for r in inv.rows()} == {"z2m:Σαλόνι θερμόμετρο", "z2m:kitchen plug"}
    assert dev(inv, "z2m:Σαλόνι θερμόμετρο")["batt"] == 9  # η μπαταρία ακολουθεί τη μετονομασία
    inv.tick()
    assert len(st.alerts) == 1 and "z2m:Σαλόνι θερμόμετρο" in inv.alerted  # … και δεν ξαναειδοποιεί


def test_parse_time():
    assert iv.parse_time(1700000000000) == 1700000000.0 and iv.parse_time(1700000000) == 1700000000.0
    assert iv.parse_time("2023-11-14T22:13:20Z") == 1700000000.0 and iv.parse_time("2023-11-14T22:13:20.000+00:00") == 1700000000.0
    assert iv.parse_time("2023-11-15T00:13:20+02:00") == 1700000000.0
    for bad in (None, True, "", "yesterday", "x" * 500, -5, 12, {}, [], float("nan")):
        assert iv.parse_time(bad) is None


# ── Tasmota ──
def test_tasmota_lwt_state_info_status():
    inv, st, clk = mk()
    inv.handle("tele/sonoff-boiler/LWT", b"Online", True)
    inv.handle("tele/sonoff-boiler/INFO1", J({"Info1": {"Module": "Sonoff Basic", "Version": "13.4.0(tasmota)", "FallbackTopic": "cmnd/DVES_1A2B3C_fb/", "GroupTopic": "cmnd/tasmotas/"}}), True)
    inv.handle("tele/sonoff-boiler/INFO2", J({"Info2": {"WebServerMode": "Admin", "Hostname": "sonoff-boiler", "IPAddress": "192.168.1.41"}}), True)
    inv.handle("tele/sonoff-boiler/STATE", J({"Time": "2024-01-01T10:00:00", "Uptime": "3T02:11:09", "UptimeSec": 267069, "Heap": 26, "POWER": "ON",
                                              "Wifi": {"AP": 1, "SSId": "IoT", "BSSId": "AA:BB:CC:DD:EE:FF", "Channel": 6, "Mode": "11n", "RSSI": 84, "Signal": -58}}))
    d = dev(inv, "tasmota:sonoff-boiler")
    assert (d["model"], d["fw"], d["ip"], d["rssi"], d["online"], d["vendor"], d["power"]) == ("Sonoff Basic", "13.4.0(tasmota)", "192.168.1.41", -58, True, "Tasmota", "mains")
    assert d["last"] == clk.t and d["problems"] == [] and d["host"] == {"ip": "192.168.1.41", "name": "boiler.lan"}
    # παλαιότερο firmware: INFO χωρίς περιτύλιγμα, RSSI μόνο ως ποσοστό
    inv.handle("tele/old/INFO1", J({"Module": "Sonoff S20", "Version": "6.5.0"}))
    inv.handle("tele/old/STATE", J({"Wifi": {"RSSI": 30}}))
    assert dev(inv, "tasmota:old")["model"] == "Sonoff S20" and dev(inv, "tasmota:old")["rssi"] == -85 and [p["code"] for p in dev(inv, "tasmota:old")["problems"]] == ["weak"]
    inv.handle("stat/sonoff-boiler/STATUS2", J({"StatusFWR": {"Version": "14.0.0(tasmota)", "BuildDateTime": "2024-06-01T10:00:00", "Core": "2_7_6", "SDK": "2.2.2"}}))
    inv.handle("stat/sonoff-boiler/STATUS5", J({"StatusNET": {"Hostname": "sonoff-boiler", "IPAddress": "192.168.1.41", "Gateway": "192.168.1.1", "Mac": "DC:4F:22:1A:2B:3C"}}))
    inv.handle("stat/sonoff-boiler/STATUS11", J({"StatusSTS": {"Wifi": {"Signal": -83}}}))
    d = dev(inv, "tasmota:sonoff-boiler")
    assert d["fw"] == "14.0.0(tasmota)" and d["mac"] == "dc:4f:22:1a:2b:3c" and d["rssi"] == -83
    inv.handle("tele/sonoff-boiler/LWT", b"Offline")
    assert dev(inv, "tasmota:sonoff-boiler")["online"] is False
    # topic με υποφακέλους + native discovery· άσχετα tele/… δεν φτιάχνουν συσκευές
    inv.handle("tele/floor1/plug7/LWT", b"Online", True)
    inv.handle("tasmota/discovery/DC4F22AABBCC/config", J({"ip": "192.168.1.44", "dn": "Πλυντήριο", "fn": ["Πλυντήριο"], "hn": "plug-washer", "mac": "DC4F22AABBCC",
                                                           "md": "BlitzWolf SHP", "sw": "13.4.0", "t": "plug-washer", "ofln": "Offline", "onln": "Online"}), True)
    assert dev(inv, "tasmota:floor1/plug7")["online"] is True
    w = dev(inv, "tasmota:plug-washer")
    assert (w["name"], w["model"], w["ip"], w["mac"], w["fw"]) == ("Πλυντήριο", "BlitzWolf SHP", "192.168.1.44", "dc:4f:22:aa:bb:cc", "13.4.0")
    n = len(inv.rows())
    for topic, pl in (("tele/weather/SENSOR", J({"BME280": {"Temperature": 20}})), ("tele/x/LWT", b"maybe"), ("stat/x/RESULT", J({"POWER": "ON"})),
                      ("tele/LWT", b"Online"), ("stat/x/STATUS2", b"[1,2]"), ("tasmota/discovery/x/sensors", b"{}"), ("tasmota/discovery/x/config", J({"dn": "no topic"}))):
        inv.handle(topic, pl)
    assert len(inv.rows()) == n


# ── Shelly ──
def test_shelly_gen1():
    inv, st, clk = mk()
    inv.handle("shellies/announce", J({"id": "shelly1-98F4AB", "model": "SHSW-1", "mac": "98F4ABD01122", "ip": "192.168.1.51", "new_fw": True,
                                       "fw_ver": "20221027-091427/v1.12.1-ga9117d3"}))
    inv.handle("shellies/shelly1-98F4AB/online", b"true", True)
    d = dev(inv, "shelly:shelly1-98F4AB")
    assert (d["model"], d["mac"], d["ip"], d["fw"], d["update"], d["online"], d["vendor"]) == ("SHSW-1", "98:f4:ab:d0:11:22", "192.168.1.51", "v1.12.1", True, True, "Shelly")
    assert d["host"]["ip"] == "192.168.1.77"  # σύνδεση με state.hosts μέσω MAC
    inv.handle("shellies/shelly1-98F4AB/info", J({"wifi_sta": {"connected": True, "ssid": "IoT", "ip": "192.168.1.51", "rssi": -67}, "mac": "98F4ABD01122",
                                                  "update": {"status": "idle", "has_update": False, "new_version": "20230913-112003/v1.14.0-gcb84623",
                                                             "old_version": "20230913-112003/v1.14.0-gcb84623"}, "uptime": 1234}))
    d = dev(inv, "shelly:shelly1-98F4AB")
    assert d["rssi"] == -67 and d["update"] is False and d["fw"] == "v1.14.0"
    inv.handle("shellies/shelly1-98F4AB/relay/0", b"on")
    inv.handle("shellies/shelly1-98F4AB/online", b"false")
    assert dev(inv, "shelly:shelly1-98F4AB")["online"] is False
    # H&T με μπαταρία
    inv.handle("shellies/shellyht-A1B2C3/announce", J({"id": "shellyht-A1B2C3", "model": "SHHT-1", "mac": "E868E7A1B2C3", "ip": "192.168.1.52", "new_fw": False, "fw_ver": "x"}))
    inv.handle("shellies/shellyht-A1B2C3/sensor/battery", b"9")
    h = dev(inv, "shelly:shellyht-A1B2C3")
    assert h["batt"] == 9 and h["power"] == "battery" and h["btype"] == "1× CR123A" and [p["code"] for p in h["problems"]] == ["batt"]
    n = len(inv.rows())
    for topic, pl in (("shellies/announce", b"[]"), ("shellies/announce", J({"model": "x"})), ("shellies/ghost/relay/0", b"on"), ("shellies/ghost/online", b"dunno"),
                      ("shellies/command", b"announce"), ("shellies/ghost/sensor/battery", b"50"), ("shellies/shellyht-A1B2C3/sensor/battery", b"lots")):
        inv.handle(topic, pl)
    assert len(inv.rows()) == n and dev(inv, "shelly:shellyht-A1B2C3")["batt"] == 9


def test_shelly_gen2():
    inv, st, clk = mk()
    sid = "shellyplus1pm-a8032abe54dc"
    inv.handle(sid + "/online", b"true", True)
    inv.handle(sid + "/status/sys", J({"mac": "A8032ABE54DC", "restart_required": False, "uptime": 812345, "ram_free": 150000,
                                       "available_updates": {"stable": {"version": "1.4.4"}, "beta": {"version": "1.5.0-beta1"}}}))
    inv.handle(sid + "/status/wifi", J({"sta_ip": "192.168.1.53", "status": "got ip", "ssid": "IoT", "rssi": -61}))
    d = dev(inv, "shelly:" + sid)
    assert (d["mac"], d["ip"], d["rssi"], d["update"], d["update_to"], d["online"], d["model"]) == ("a8:03:2a:be:54:dc", "192.168.1.53", -61, True, "1.4.4", True, "shellyplus1pm")
    inv.handle(sid + "/events/rpc", J({"src": sid, "dst": sid + "/events", "method": "NotifyStatus",
                                       "params": {"ts": 1700000000.5, "sys": {"available_updates": {"beta": {"version": "1.5.0-beta1"}}}, "wifi": {"rssi": -84}, "switch:0": {"output": True}}}))
    d = dev(inv, "shelly:" + sid)
    assert d["update"] is False and d["rssi"] == -84 and [p["code"] for p in d["problems"]] == ["weak"]  # μόνο beta: δεν μετρά
    inv.handle("shellyhtg3-aabbccddeeff/status/devicepower:0", J({"id": 0, "battery": {"V": 5.1, "percent": 12}, "external": {"present": False}}))
    assert dev(inv, "shelly:shellyhtg3-aabbccddeeff")["batt"] == 12 and dev(inv, "shelly:shellyhtg3-aabbccddeeff")["power"] == "battery"
    # προσαρμοσμένο prefix: το αναγνωρίζουμε από το src του RPC
    inv.handle("garage-door/events/rpc", J({"src": "shellyplus1-441793aabbcc", "method": "NotifyFullStatus", "params": {"wifi": {"sta_ip": "192.168.1.54", "rssi": -50}}}))
    assert dev(inv, "shelly:garage-door")["ip"] == "192.168.1.54"
    n = len(inv.rows())
    for topic, pl in (("other/events/rpc", J({"src": "homeassistant", "method": "NotifyStatus", "params": {}})), ("other/events/rpc", b"x"),
                      (sid + "/status/sys", b"[]"), (sid + "/online", b"1"), ("nonshelly/status/wifi", J({"rssi": -1})), (sid + "/rpc", b"{}")):
        inv.handle(topic, pl)
    assert len(inv.rows()) == n


# ── ESPHome + discovery ──
def test_esphome_status_debug_and_discovery():
    inv, st, clk = mk()
    inv.handle("garden-pump/status", b"online", True)
    assert dev(inv, "esphome:garden-pump")["online"] is True and dev(inv, "esphome:garden-pump")["last"] is None  # retained: δεν ξέρουμε πότε μίλησε
    clk.t += 10
    inv.handle("garden-pump/debug", b"[D][switch:012]: 'Pump' Turning OFF")
    assert dev(inv, "esphome:garden-pump")["last"] == clk.t and dev(inv, "esphome:garden-pump")["vendor"] == "ESPHome"
    inv.handle("garden-pump/status", b"offline")
    assert dev(inv, "esphome:garden-pump")["online"] is False
    # discovery με συντομογραφίες (όπως το στέλνει το ESPHome)
    inv.handle("homeassistant/sensor/rack-fan/uptime/config", J({
        "name": "Uptime", "stat_t": "rack-fan/sensor/uptime/state", "avty_t": "rack-fan/status", "uniq_id": "ESPsensoruptime",
        "dev": {"ids": "a0b765c1d2e3", "name": "rack-fan", "sw": "esphome v2024.6.4 Jun 30 2024, 10:00:00", "mdl": "esp32dev", "mf": "espressif",
                "cns": [["mac", "a0b765c1d2e3"]]}}), True)
    inv.handle("homeassistant/switch/rack-fan/fan/config", J({"name": "Fan", "avty_t": "rack-fan/status", "dev": {"ids": "a0b765c1d2e3", "name": "rack-fan",
                                                                                                                 "sw": "esphome v2024.6.4", "mf": "espressif"}}), True)
    inv.handle("rack-fan/status", b"online", True)
    f = dev(inv, "esphome:rack-fan")
    assert (f["name"], f["model"], f["fw"], f["mac"], f["online"]) == ("rack-fan", "esp32dev", "v2024.6.4", "a0:b7:65:c1:d2:e3", True)
    assert sum(1 for r in inv.rows() if r["src"] == "esphome") == 2
    # γενική πηγή: άλλη μάρκα με πλήρη ονόματα πεδίων και δικά της payload διαθεσιμότητας
    inv.handle("homeassistant/sensor/OMG_BLE/SYSuptime/config", J({
        "name": "SYS: Uptime", "state_topic": "home/OMG_BLE/SYStoMQTT", "availability": [{"topic": "home/OMG_BLE/LWT"}], "payload_available": "up", "payload_not_available": "down",
        "device": {"identifiers": ["OMG_BLE"], "name": "OpenMQTTGateway", "manufacturer": "OMG_community", "model": "esp32dev-ble", "sw_version": "v1.7.0",
                   "connections": [["mac", "24:6f:28:aa:bb:cc"]]}}), True)
    g = dev(inv, "ha:OMG_BLE")
    assert (g["name"], g["vendor"], g["model"], g["fw"], g["mac"], g["src_label"], g["online"]) == ("OpenMQTTGateway", "OMG_community", "esp32dev-ble", "v1.7.0",
                                                                                               "24:6f:28:aa:bb:cc", "MQTT discovery", None)
    inv.handle("home/OMG_BLE/LWT", b"up")
    assert dev(inv, "ha:OMG_BLE")["online"] is True
    inv.handle("home/OMG_BLE/LWT", b"down")
    assert dev(inv, "ha:OMG_BLE")["online"] is False
    inv.handle("home/OMG_BLE/LWT", b"whatever")
    assert dev(inv, "ha:OMG_BLE")["online"] is False
    # 4-τμημάτων topic χωρίς node id
    inv.handle("homeassistant/binary_sensor/doorbell/config", J({"name": "Bell", "device": {"identifiers": "bell-1", "name": "Κουδούνι", "manufacturer": "DIY"}}))
    assert dev(inv, "ha:bell-1")["name"] == "Κουδούνι"
    n = len(inv.rows())
    # ό,τι ξέρουμε καλύτερα από αλλού, ή δεν είναι συσκευή, αγνοείται
    for topic, pl in (
            ("homeassistant/sensor/0x00158d0003a1b2c3/battery/config", J({"device": {"identifiers": ["zigbee2mqtt_0x00158d0003a1b2c3"], "name": "x", "manufacturer": "Aqara"}})),
            ("homeassistant/switch/DC4F22_RL_1/config", J({"device": {"identifiers": ["DC4F22"], "sw_version": "13.4.0(tasmota)", "manufacturer": "Tasmota"}})),
            ("homeassistant/status", b"online"), ("homeassistant/sensor/x/y/config", b""), ("homeassistant/sensor/x/y/config", J({"name": "no device"})),
            ("homeassistant/sensor/x/y/config", J({"device": "str"})), ("homeassistant/sensor/x/y/state", J({"device": {"identifiers": "a"}})),
            ("homeassistant/a/b/c/d/config", J({"device": {"identifiers": "deep"}})),
            ("zigbee2mqtt/status", b"online"), ("homeassistant/status", b"offline"), ("tele/status", b"online"), ("frigate/status", b"online"),
            ("some/deeper/status", b"online"), ("thing/status", b"running"), ("unknown/debug", b"hello")):
        inv.handle(topic, pl)
    assert len(inv.rows()) == n


# ── κανόνες υγείας / ειδοποιήσεις ──
def test_battery_alert_once_hysteresis_and_persistence(tmp_path):
    inv, st, clk = mk(tmp_path)
    inv.handle("zigbee2mqtt/bridge/devices", J(Z2M_DEVICES), True)
    inv.handle("zigbee2mqtt/salon/temp", J({"battery": 16, "linkquality": 90}))
    inv.tick()
    assert not st.alerts
    inv.handle("zigbee2mqtt/salon/temp", J({"battery": 15, "linkquality": 90}))
    assert inv.tick() == [("batt", "z2m:salon/temp")]
    a = st.alerts[0]
    assert a["type"] == "Χαμηλή μπαταρία σε συσκευή IoT" and a["sev"] == "low" and a["target"] == "salon/temp" and a["actor"] == "mqtt"
    assert "15%" in a["detail"] and "1× CR2032" in a["detail"] and "WSDCGQ11LM" in a["detail"] and a["key"] == ("iotinv", "z2m", "salon/temp", "batt")
    for b in (14, 16, 13, 19, 12):  # ταλάντωση γύρω από το όριο → καμία νέα ειδοποίηση
        clk.t += 3600
        inv.handle("zigbee2mqtt/salon/temp", J({"battery": b}))
        inv.view()
    assert len(st.alerts) == 1
    # επανεκκίνηση: θυμάται και τη συσκευή και ότι ειδοποίησε
    inv2 = iv.IotInv(st, str(tmp_path), clock=clk)
    assert dev(inv2, "z2m:salon/temp")["batt"] == 12 and dev(inv2, "z2m:salon/temp")["model"] == "WSDCGQ11LM"
    inv2.tick()
    assert len(st.alerts) == 1
    # νέα μπαταρία → καθαρίζει· όταν ξαναπέσει → νέα ειδοποίηση
    inv2.handle("zigbee2mqtt/salon/temp", J({"battery": 100}))
    inv2.tick()
    assert "z2m:salon/temp" not in inv2.alerted
    inv2.handle("zigbee2mqtt/salon/temp", J({"battery": 10}))
    inv2.tick()
    assert len(st.alerts) == 2
    j = json.load(open(tmp_path / "iotinv.json"))
    assert set(j) == {"devs", "alerted", "avail", "z2m"} and j["alerted"]["z2m:salon/temp"]["batt"] == clk.t


def test_offline_rules_mains_15min_battery_25h():
    inv, st, clk = mk()
    inv.handle("tele/boiler/LWT", b"Online", True)
    inv.handle("tele/boiler/INFO2", J({"Info2": {"IPAddress": "192.168.1.41"}}), True)
    inv.handle("zigbee2mqtt/bridge/devices", J(Z2M_DEVICES), True)
    inv.handle("zigbee2mqtt/salon/temp", J({"battery": 80, "linkquality": 90}))
    inv.handle("tele/boiler/LWT", b"Offline")
    clk.t += 14 * 60
    inv.tick()
    assert not st.alerts and dev(inv, "tasmota:boiler")["online"] is False and dev(inv, "tasmota:boiler")["problems"] == []
    clk.t += 2 * 60
    inv.tick()
    inv.tick()
    assert len(st.alerts) == 1
    a = st.alerts[0]
    assert a["type"] == "Συσκευή IoT εκτός δικτύου" and a["sev"] == "med" and a["actor"] == "192.168.1.41" and "16′" in a["detail"] and "Tasmota" in a["detail"]
    assert a["cooldown"] == 86400 and inv.view()["counts"]["offline"] == 1
    # επανήλθε → καθαρίζει· ξαναπέφτει → νέα ειδοποίηση μετά από 15′
    inv.handle("tele/boiler/LWT", b"Online")
    inv.tick()
    assert "tasmota:boiler" not in inv.alerted and dev(inv, "tasmota:boiler")["problems"] == []
    inv.handle("tele/boiler/LWT", b"Offline")
    inv.handle("tele/boiler/LWT", b"Offline")  # επανάληψη δεν μηδενίζει το χρονόμετρο
    clk.t += 16 * 60
    inv.handle("tele/boiler/LWT", b"Offline", True)
    inv.tick()
    assert len(st.alerts) == 2
    # συσκευή μπαταρίας: 24 ώρες σιωπής εντάξει, 26 όχι
    clk.t = 1_700_000_000.0 + 24 * 3600
    inv.tick()
    assert len(st.alerts) == 2
    clk.t += 2 * 3600
    inv.tick()
    assert len(st.alerts) == 3 and "δεν έχει στείλει τίποτα εδώ και 26 ώρες" in st.alerts[2]["detail"] and st.alerts[2]["target"] == "salon/temp"
    r = dev(inv, "z2m:salon/temp")
    assert r["online"] is False and r["problems"][0]["code"] == "off" and r["rank"] == 0 and inv.rows()[0]["rank"] == 0
    # ο router με ρεύμα που απλώς δεν μιλά (χωρίς availability) δεν θεωρείται εκτός
    assert dev(inv, "z2m:kitchen plug")["problems"] == []
    inv.handle("zigbee2mqtt/salon/temp", J({"battery": 79}))
    inv.tick()
    assert dev(inv, "z2m:salon/temp")["problems"] == [] and "z2m:salon/temp" not in inv.alerted


def test_weak_and_update_are_listed_without_alerts():
    inv, st, clk = mk()
    inv.handle("zigbee2mqtt/bridge/devices", J(Z2M_DEVICES), True)
    inv.handle("zigbee2mqtt/salon/temp", J({"battery": 80, "linkquality": 12}))
    inv.handle("zigbee2mqtt/kitchen plug", J({"linkquality": 200, "update_available": True}))
    inv.handle("tele/far/STATE", J({"Wifi": {"Signal": -88}}))
    v = inv.view()
    assert not st.alerts and v["counts"]["weak"] == 2 and v["counts"]["update"] == 1 and v["counts"]["batt"] == 0 and v["counts"]["offline"] == 0
    assert "LQI 12" in dev(inv, "z2m:salon/temp")["problems"][0]["el"] and "-88 dBm" in dev(inv, "tasmota:far")["problems"][0]["en"]
    assert all(r["rank"] == 2 for r in v["devices"][:3]) and v["devices"][-1]["rank"] == 3


def test_demo_never_alerts_and_shapes():
    inv = iv.IotInv(State(), demo=True)
    v = inv.view()
    json.dumps(v)
    assert v["demo"] is True and not inv.state.alerts and 14 <= v["counts"]["total"] <= 16
    assert set(v["counts"]["by_src"]) == {"z2m", "tasmota", "shelly", "esphome", "ha"}
    assert v["counts"]["batt"] >= 2 and v["counts"]["offline"] >= 2 and v["counts"]["update"] >= 2 and v["counts"]["weak"] >= 2
    assert v["devices"][0]["problems"] and v["devices"][0]["rank"] == 0 and v["mqtt"]["configured"]
    assert {g["type"] for g in v["shopping"]} == {"CR123A", "CR2032"} and next(g for g in v["shopping"] if g["type"] == "CR2032")["qty"] == 2
    assert v["z2m"]["version"] and set(v["sources"]) == set(iv.SRC)
    keys = {"key", "src", "src_label", "icon", "name", "model", "vendor", "ip", "mac", "ieee", "fw", "update", "update_to", "batt", "btype", "lqi", "rssi",
            "power", "type", "online", "last", "host", "problems", "rank"}
    assert all(set(r) == keys for r in v["devices"])
    assert all(set(p) == {"code", "sev", "el", "en"} for r in v["devices"] for p in r["problems"])
    # demo που τρέχει μέρες: οι χρόνοι κυλούν, τα προβλήματα μένουν ίδια
    t0 = inv.clock()
    inv.clock = lambda: t0 + 5 * 86400
    v2 = inv.view()
    assert v2["counts"] == v["counts"]


# ── CSV / λίστα αγορών / api ──
def test_csv_export_and_formula_injection():
    inv, st, clk = mk()
    inv.handle("zigbee2mqtt/bridge/devices", J(Z2M_DEVICES + [{"friendly_name": "=HYPERLINK(\"http://evil\")", "ieee_address": "0x01", "type": "EndDevice",
                                                              "definition": {"model": "+cmd", "vendor": "@x"}}]), True)
    inv.handle("zigbee2mqtt/salon/temp", J({"battery": 9, "linkquality": 77}))
    inv.handle("tele/far/STATE", J({"Wifi": {"Signal": -88}}))
    code, r = inv.api("GET", "csv", {}, {})
    assert code == 200 and r["_type"].startswith("text/csv") and r["_name"] == "iot-inventory.csv" and r["_raw"].startswith(b"\xef\xbb\xbf")
    rows = list(csv.reader(io.StringIO(r["_raw"].decode("utf-8-sig"))))
    assert rows[0][:5] == ["source", "name", "model", "vendor", "ip"] and len(rows) == 1 + len(inv.rows()) and all(len(x) == 17 for x in rows)
    by = {x[1]: x for x in rows[1:]}
    t = by["salon/temp"]
    assert t[0] == "Zigbee2MQTT" and t[2] == "WSDCGQ11LM" and t[9] == "9" and t[10] == "1× CR2032" and t[11] == "77" and "Μπαταρία 9%" in t[16]
    assert by["far"][12] == "-88"  # αρνητικός αριθμός μένει αριθμός
    evil = by["'=HYPERLINK(\"http://evil\")"]
    assert evil[2] == "'+cmd" and evil[3] == "'@x"


def test_shopping_list_groups_by_battery_type():
    inv, st, clk = mk()
    lst = [{"friendly_name": n, "ieee_address": "0x%016x" % i, "type": "EndDevice", "power_source": "Battery", "definition": {"model": m, "vendor": "v"}}
           for i, (n, m) in enumerate([("a", "WSDCGQ11LM"), ("b", "SJCGQ11LM"), ("c", "E1525/E1745"), ("d", "RTCGQ14LM"), ("e", "TS0201"), ("f", "MCCGQ11LM"), ("g", "SNZB-02")])]
    inv.handle("zigbee2mqtt/bridge/devices", J(lst), True)
    for n, b in (("a", 10), ("b", 25), ("c", 5), ("d", 20), ("e", 3), ("f", 26), ("g", 90)):
        inv.handle("zigbee2mqtt/" + n, J({"battery": b, "linkquality": 100}))
    sh = inv.view()["shopping"]
    assert [(g["type"], g["qty"]) for g in sh] == [("CR2032", 4), ("CR2450", 2), ("", 1)]  # c: 2× CR2032, d: 2× CR2450· άγνωστος τύπος τελευταίος
    assert [d["name"] for d in sh[0]["devices"]] == ["c", "a", "b"] or {d["name"] for d in sh[0]["devices"]} == {"a", "b", "c"}
    assert sh[2]["devices"][0]["name"] == "e"
    assert iv.battery_of("MCCGQ11LM") == ("CR1632", 1) and iv.battery_of("nope") is None and iv.battery_of(None) is None
    assert all(isinstance(t, str) and t and 1 <= q <= 4 for t, q in iv.BATTERY.values())


def test_api_and_view_basics():
    inv, st, clk = mk()
    code, v = inv.api("GET", "", {}, {})
    assert code == 200 and v["demo"] is False and v["devices"] == [] and v["counts"]["total"] == 0 and v["shopping"] == []
    assert v["mqtt"] == {"configured": False, "connected": False, "msgs": 0, "last": None}
    assert inv.api("GET", "nope", {}, {}) == (404, {"error": "not found"}) and inv.api("POST", "csv", {}, {})[0] == 404

    class Mq:
        configured, connected = True, True
    st.mqtt = Mq()
    inv.handle("garden-pump/status", b"online")
    m = inv.view()["mqtt"]
    assert m["configured"] and m["connected"] and m["msgs"] == 1 and m["last"] == clk.t
    assert iv.IotInv(None).view()["counts"]["total"] == 0


# ── εχθρικά μηνύματα ──
def test_hostile_payloads_never_raise_or_grow():
    inv, st, clk = mk()
    inv.handle("zigbee2mqtt/bridge/devices", J(Z2M_DEVICES), True)
    deep = b"[" * 100000 + b"]" * 100000
    huge = J({"battery": 50, "linkquality": 100, "pad": "x" * (iv.MAX_SMALL + 10)})
    bad = [b"", b"\xff\xfe\x00", b"{", b"null", b"[]", b"123", b'"str"', b"true", deep, b'{"a":' * 5000 + b"1" + b"}" * 5000, huge,
           J({"battery": "full", "linkquality": [1], "last_seen": {"x": 1}, "update": "yes"}), J({"battery": -5, "linkquality": 1e9, "update": {"state": 7}}),
           J({"battery": True, "linkquality": None}), J([{"battery": 1}]), J({"battery": float("1e400") if False else 1e300})]
    topics = ["zigbee2mqtt/salon/temp", "zigbee2mqtt/salon/temp/availability", "zigbee2mqtt/bridge/devices", "zigbee2mqtt/bridge/info", "zigbee2mqtt/bridge/state",
              "tele/x/STATE", "tele/x/INFO1", "tele/x/LWT", "stat/x/STATUS2", "stat/x/STATUS5", "stat/x/STATUS11", "tasmota/discovery/aa/config",
              "shellies/announce", "shellies/x/info", "shellies/x/online", "shellies/x/sensor/battery", "shellyplus1-aabbccddeeff/status/sys",
              "shellyplus1-aabbccddeeff/status/wifi", "shellyplus1-aabbccddeeff/events/rpc", "shellyplus1-aabbccddeeff/online", "x/events/rpc",
              "homeassistant/sensor/a/b/config", "homeassistant/sensor/b/config", "esp/status", "esp/debug", "$SYS/broker/version", "", "/", "//", "a" * 300, "x/status" * 40]
    for t in topics:
        for p in bad:
            inv.handle(t, p)
            inv.handle(t, p, True, 5.0)
    for junk_topic in (None, 5, b"bytes", ["l"]):
        inv.handle(junk_topic, b"x")
    for junk_payload in (None, 5, {"a": 1}, "κείμενο", bytearray(b"online")):
        inv.handle("esp2/status", junk_payload)
    inv.handle("zigbee2mqtt/bridge/devices", b"x" * (iv.MAX_BRIDGE + 1))
    v = inv.view()
    json.dumps(v)
    t = dev(inv, "z2m:salon/temp")
    assert t["batt"] is None or 0 <= t["batt"] <= 100
    assert t["lqi"] is None or 0 <= t["lqi"] <= 255
    assert len(v["devices"]) <= 12 and not st.alerts
    # λάθος τύποι μέσα σε έγκυρο JSON
    inv.handle("zigbee2mqtt/bridge/devices", J([{"friendly_name": ["x"], "ieee_address": {"a": 1}, "definition": "str", "power_source": 5, "type": None},
                                                {"friendly_name": "ok\x00\x1b[31m" + "n" * 500, "ieee_address": 5, "definition": {"model": {"x": 1}, "vendor": ["v"]}}]), True)
    names = [r["name"] for r in inv.rows() if r["src"] == "z2m"]
    assert len(names) == 1 and len(names[0]) <= 80 and "\x1b" not in names[0] and "\x00" not in names[0]
    inv.handle("homeassistant/sensor/n/o/config", J({"device": {"identifiers": [{"a": 1}, 5, "real-id"], "name": {"x": 1}, "manufacturer": 7, "model": ["m"], "sw_version": None,
                                                                "connections": "nope"}, "availability": "str", "availability_topic": 5}))
    assert dev(inv, "ha:5")["name"] == "5" or dev(inv, "ha:real-id")
    inv.handle("shellies/announce", J({"id": "shelly1-X", "mac": 12345, "ip": "999.1.1.1<script>", "fw_ver": {"a": 1}, "new_fw": "yes", "model": ["x"]}))
    s = dev(inv, "shelly:shelly1-X")
    assert s["ip"] == "" and s["mac"] == "" and s["update"] is False and s["model"] == ""


def test_device_cap_and_avail_cap():
    inv, st, clk = mk()
    for i in range(iv.MAX_DEV + 200):
        inv.handle("tele/dev%d/LWT" % i, b"Online")
        inv.handle("homeassistant/sensor/n%d/x/config" % i, J({"device": {"identifiers": "id%d" % i}, "availability_topic": "avail/%d" % i}))
    assert len(inv.devs) == iv.MAX_DEV and len(inv.avail) <= iv.MAX_AVAIL
    assert len(inv.view()["devices"]) == iv.MAX_DEV


def test_load_tolerates_garbage_file(tmp_path):
    (tmp_path / "iotinv.json").write_text(json.dumps({"devs": {"x": 5, "y": {"src": "nope", "id": "a"}, "z2m:ok": {"src": "z2m", "id": "ok", "batt": "many", "ip": "<b>",
                                                                                                              "online": "yes", "last": "soon", "name": ["n"]}},
                                                      "alerted": {"z2m:ok": {"batt": "x", "off": 5}, "ghost": {"batt": 1}}, "avail": {"t": ["ghost", "a", "b"], "u": "x"}, "z2m": [1]}))
    inv = iv.IotInv(None, str(tmp_path))
    assert list(inv.devs) == ["z2m:ok"] and inv.devs["z2m:ok"]["batt"] is None and inv.devs["z2m:ok"]["ip"] == "" and inv.devs["z2m:ok"]["name"] == "ok"
    assert inv.alerted == {"z2m:ok": {"off": 5.0}} and inv.avail == {} and inv.z2m == {}
    (tmp_path / "iotinv.json").write_text("{broken")
    assert iv.IotInv(None, str(tmp_path)).devs == {}


def test_mqttwatch_style_call_signature():
    # έτσι θα το καλεί ο φύλακας MQTT: handle(topic, payload, retained, t)
    inv, st, clk = mk()
    inv.handle("tele/x/LWT", b"Online", False, 1234.0)
    inv.handle("tele/x/STATE", b'{"Wifi":{"Signal":-60}}', False, 1300.0)
    assert inv.devs["tasmota:x"]["last"] == 1300.0 and inv.last_msg == 1300.0 and inv.msgs == 2
