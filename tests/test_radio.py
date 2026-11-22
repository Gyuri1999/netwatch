import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import radio as r  # noqa: E402


class Clock:
    def __init__(self, t=100000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeProbes:
    def __init__(self):
        self.data = {}  # kind → [{"id","name","kind","seen","items","metrics"}]

    def items(self, kind=None):
        return [dict(p) for k, v in self.data.items() if kind in (None, k) for p in v]


class State:
    def __init__(self):
        self.probes = FakeProbes()
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append({"type": typ, "sev": sev, "actor": actor, "target": target, "detail": detail, "key": kw.get("key")})


def mk(tmp_path=None, clk=None):
    st = State()
    clk = clk or Clock()
    return r.Radio(st, str(tmp_path) if tmp_path else None, clock=clk), st, clk


def scan(st, clk, rows, pid="p-b1", name="γραφείο"):
    cur = [p for p in st.probes.data.get("ble", []) if p["id"] != pid]
    st.probes.data["ble"] = cur + [{"id": pid, "name": name, "kind": "ble", "seen": clk.t, "items": rows, "metrics": {}}]


AIRTAG = {"mac": "D3:5A:91:0C:44:E2", "rssi": -60, "name": "", "mfr": 76, "svc": "", "ad": "1219a3f1c2d4e5f60718293a", "rnd": True, "conn": False}


# ── κατάταξη BLE ──
def test_classify_trackers_beacons_and_vendors():
    c = r.classify(AIRTAG)
    assert c["kind"] == "findmy" and c["tracker"] and c["sep"] and c["vendor"] == "Apple"
    assert r.classify(dict(AIRTAG, ad="1202aabb"))["sep"] is False  # κοντά στον ιδιοκτήτη του
    assert r.classify(dict(AIRTAG, ad="4c001219aabb"))["kind"] == "findmy"  # firmware που αφήνει μπροστά το company id
    assert r.classify({"mfr": 76, "ad": "0215b9407f30f5f8466eaff9"})["kind"] == "ibeacon"
    assert r.classify({"mfr": 76, "ad": "0214b9407f30"})["kind"] == "apple"  # λάθος μήκος: όχι iBeacon
    assert r.classify({"mfr": 76, "ad": "1005"})["kind"] == "apple" and not r.classify({"mfr": 76, "ad": "1005"})["tracker"]
    assert r.classify({"mfr": 76, "ad": "0719010f"})["kind"] == "airpods"
    assert r.classify({"mfr": 0x0118, "ad": "0215aabbccdd"})["kind"] == "ibeacon"  # iBeacon άλλου κατασκευαστή
    for svc, kind, trk in (("feed", "tile", True), ("FEEC", "tile", True), ("fd5a", "smarttag", True), ("fe2c", "fastpair", False),
                           ("feaa", "eddystone", False), ("fe95", "mi", False), ("fcd2", "bthome", False), ("fd3d", "switchbot", False)):
        c = r.classify({"mfr": -1, "svc": svc, "ad": ""})
        assert (c["kind"], c["tracker"]) == (kind, trk), svc
    assert r.classify({"mfr": 0x0499, "ad": "0512fc"})["kind"] == "ruuvi" and r.classify({"mfr": 0x0499})["vendor"] == "Ruuvi"
    assert r.classify({"mfr": 0xEC88, "ad": "0003"})["kind"] == "govee"
    assert r.classify({"mfr": 0x0006, "ad": "0109"})["kind"] == "microsoft"
    assert r.classify({"mfr": 0x0075, "svc": "fd5a"})["kind"] == "smarttag"  # το service κερδίζει τον κατασκευαστή
    assert r.classify({})["kind"] == "other" and r.classify({"mfr": "x", "svc": 5, "ad": None})["kind"] == "other"
    assert r.classify({"mfr": True, "ad": "zz"})["kind"] == "other" and r.classify({"mfr": 99999, "ad": "1"})["kind"] == "other"


def test_company_table_sane():
    assert 40 <= len(r.COMPANY) <= 60
    assert r.COMPANY[0x004C] == "Apple" and r.COMPANY[0x0006] == "Microsoft" and r.COMPANY[0x0075] == "Samsung"
    assert r.COMPANY[0x00E0] == "Google" and r.COMPANY[0x0059].startswith("Nordic") and r.COMPANY[0x02E5] == "Espressif"
    assert all(isinstance(k, int) and 0 <= k <= 0xFFFF and v for k, v in r.COMPANY.items())
    assert all(k in r.KIND for k in list(r.SVC.values()) + list(r.MFR_KIND.values()) + list(r.APPLE_TYPE.values()))


def test_norm_mac():
    assert r.norm_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff" and r.norm_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    assert r.norm_mac("<script>") is None and r.norm_mac(None) is None and r.norm_mac("aa:bb") is None


# ── Zigbee ↔ Wi-Fi ──
def test_overlap_maths():
    assert r.zb_mhz(11) == 2405 and r.zb_mhz(26) == 2480 and r.wifi_mhz(1) == 2412 and r.wifi_mhz(6) == 2437 and r.wifi_mhz(11) == 2462
    assert [z for z in range(11, 27) if r.overlap(z, 1)] == [11, 12, 13, 14]
    assert [z for z in range(11, 27) if r.overlap(z, 6)] == [16, 17, 18, 19]
    assert [z for z in range(11, 27) if r.overlap(z, 11)] == [21, 22, 23, 24]
    assert [z for z in range(11, 27) if not any(r.overlap(z, w) for w in (1, 6, 11))] == [15, 20, 25, 26]
    assert [z for z in range(11, 27) if r.overlap(z, 13)] == [23, 24, 25, 26]
    assert len([z for z in range(11, 27) if r.overlap(z, 3, 40)]) == 8  # 40 MHz: διπλάσια ζημιά
    assert not r.overlap(10, 1) and not r.overlap(27, 11) and not r.overlap(11, 0) and not r.overlap(11, 15)
    assert not r.overlap("x", 1) and not r.overlap(11, None) and not r.overlap(11, 1, 0)
    assert r.overlap("12", "1", "20")


def test_clean_channels_and_parse():
    assert r.clean_channels([(1, 20), (6, 20), (11, 20)]) == [15, 20, 25, 26]
    assert r.clean_channels([(1, 20), (6, 20), (11, 20)], {15: 50, 20: 0, 25: 3}) == [20, 25, 15, 26]
    assert r.clean_channels([(1, 20)])[:3] == [15, 20, 25] and 11 not in r.clean_channels([(1, 20)])
    assert r.clean_channels([]) [-1] == 26 and len(r.clean_channels([])) == 16
    assert r.parse_channels("1, 6,11") == [1, 6, 11] and r.parse_channels([11, "6", 6, 99, -1, None, "x", 1.0]) == [1, 6, 11]
    assert r.parse_channels(None) == [] and r.parse_channels({"a": 1}) == [] and r.parse_channels("κανένα") == []


def test_lora_margin():
    assert r.lora_margin(-92, 8.5, 9) == (21.0, 7)
    assert r.lora_margin(-121, -9.5, 9) == (3.0, 12)   # το SNR είναι ο περιορισμός
    assert r.lora_margin(-121, None, 9) == (8, 10)
    assert r.lora_margin(-140, -25, 12) == (-5, None)
    assert r.lora_margin(None, 3) == (None, None) and r.lora_margin(-100, 5, 99)[0] == 12.5


# ── BLE: συγχώνευση, tracker, ετικέτες ──
def test_merge_across_scanners_strongest_wins(tmp_path):
    rd, st, clk = mk(tmp_path)
    scan(st, clk, [dict(AIRTAG, rssi=-80), {"mac": "a4:c1:38:5b:0e:9d", "rssi": -70, "name": "LYWSD03MMC", "mfr": -1, "svc": "fe95", "rnd": False, "conn": True}],
         "p-b1", "γραφείο")
    scan(st, clk, [dict(AIRTAG, rssi=-55, mac="d3:5a:91:0c:44:e2")], "p-b2", "αποθήκη")
    v = rd.view()["ble"]
    tag = next(d for d in v["devices"] if d["mac"] == "d3:5a:91:0c:44:e2")
    assert tag["rssi"] == -55 and tag["where"] == "αποθήκη" and tag["scanners"] == 2 and tag["hits"] == 2 and tag["unknown"] and not tag["stays"]
    mi = next(d for d in v["devices"] if d["mac"] == "a4:c1:38:5b:0e:9d")
    assert mi["where"] == "γραφείο" and mi["kind"] == "mi" and mi["pairing"] and mi["vendor"] == "Xiaomi"
    assert v["counts"]["now"] == 2 and v["counts"]["trackers"] == 1 and len(v["scanners"]) == 2
    rd.view()  # ίδια αναφορά ξανά → δεν ξαναμετρά
    assert rd.ble["d3:5a:91:0c:44:e2"]["hits"] == 2
    clk.t += 1000  # παλιά αναφορά: όχι «τώρα»
    v = rd.view()["ble"]
    assert v["counts"]["now"] == 0 and v["devices"][0]["rssi"] is None and not v["scanners"][0]["fresh"]


def test_tracker_alert_only_after_persistence_and_once(tmp_path):
    rd, st, clk = mk(tmp_path)
    for i in range(r.TRACK_HITS + 5):  # πολλές θεάσεις αλλά μέσα σε λίγα λεπτά → όχι
        scan(st, clk, [AIRTAG])
        rd.poll()
        clk.t += 30
    assert not st.alerts and not rd.view()["ble"]["devices"][0]["stays"]
    clk.t += r.TRACK_SECS  # πέρασαν ώρες και είναι ακόμα εδώ
    scan(st, clk, [AIRTAG])
    rd.poll()
    assert len(st.alerts) == 1
    a = st.alerts[0]
    assert a["type"] == "Άγνωστο Bluetooth tracker κοντά στο δίκτυο" and a["sev"] == "med" and a["actor"] == "d3:5a:91:0c:44:e2"
    assert "γραφείο" in a["detail"] and a["key"] == ("ble-tracker", "d3:5a:91:0c:44:e2")
    row = rd.view()["ble"]["devices"][0]
    assert row["stays"] and row["flags"][0]["sev"] == "med" and rd.view()["ble"]["counts"]["staying"] == 1
    for _ in range(5):
        clk.t += 60
        scan(st, clk, [AIRTAG])
        rd.poll()
    assert len(st.alerts) == 1
    # μετά από επανεκκίνηση: θυμάται ότι ειδοποίησε
    rd2 = r.Radio(st, str(tmp_path), clock=clk)
    assert rd2.ble["d3:5a:91:0c:44:e2"]["alerted"] and rd2.ble["d3:5a:91:0c:44:e2"]["hits"] > r.TRACK_HITS
    clk.t += 60
    scan(st, clk, [AIRTAG])
    rd2.poll()
    assert len(st.alerts) == 1


def test_few_sightings_over_hours_do_not_alert_and_non_trackers_never():
    rd, st, clk = mk()
    for _ in range(5):
        scan(st, clk, [AIRTAG, {"mac": "f4:b8:5e:2a:91:07", "rssi": -50, "name": "Galaxy Watch5", "mfr": 117, "rnd": False, "conn": True}])
        rd.poll()
        clk.t += 3600
    assert not st.alerts
    for _ in range(40):
        scan(st, clk, [{"mac": "f4:b8:5e:2a:91:07", "rssi": -50, "name": "Galaxy Watch5", "mfr": 117, "rnd": False, "conn": True}])
        rd.poll()
        clk.t += 600
    assert not st.alerts


def test_known_label_suppresses_alert_and_persists(tmp_path):
    rd, st, clk = mk(tmp_path)
    scan(st, clk, [AIRTAG])
    rd.poll()
    code, v = rd.api("POST", "known", {}, {"mac": "D3:5A:91:0C:44:E2", "label": "Κλειδιά <b>", "mode": "known"})
    assert code == 200 and v["ble"]["devices"][0]["label"] == "Κλειδιά <b>" and v["ble"]["devices"][0]["mode"] == "known"
    assert not v["ble"]["devices"][0]["unknown"]
    for _ in range(r.TRACK_HITS + 2):
        clk.t += 600
        scan(st, clk, [AIRTAG])
        rd.poll()
    assert not st.alerts
    assert r.Radio(st, str(tmp_path), clock=clk).labels["d3:5a:91:0c:44:e2"]["mode"] == "known"
    assert rd.api("POST", "known", {}, {"mac": "d3:5a:91:0c:44:e2", "mode": "ignored"})[1]["ble"]["devices"][0]["mode"] == "ignored"
    # ξανά άγνωστο → μπορεί να ειδοποιήσει
    assert rd.api("POST", "known", {}, {"mac": "d3:5a:91:0c:44:e2", "mode": ""})[0] == 200
    clk.t += 60
    scan(st, clk, [AIRTAG])
    rd.poll()
    assert len(st.alerts) == 1
    assert rd.api("POST", "known", {}, {"mac": "nope"})[0] == 400 and rd.api("POST", "known", {}, {})[0] == 400


def test_random_address_churn_is_counted_not_listed():
    rd, st, clk = mk()
    rows = [{"mac": "4a:00:00:00:%02x:%02x" % (i // 256, i % 256), "rssi": -70, "name": "", "mfr": 76, "ad": "1005", "rnd": True, "conn": False} for i in range(79)]
    scan(st, clk, rows + [AIRTAG])
    v = rd.view()["ble"]
    assert v["counts"]["churn"] == 79 and v["counts"]["listed"] == 1 and len(v["devices"]) == 1 and v["counts"]["total"] == 80
    # χιλιάδες τυχαίες διευθύνσεις σε πολλές αναφορές: η μνήμη μένει φραγμένη, το tracker δεν χάνεται
    for k in range(40):
        clk.t += 120
        rows = [{"mac": "5%x:%02x:00:00:%02x:%02x" % (k % 16, k, i, k), "rssi": -70, "mfr": 76, "ad": "1005", "rnd": True} for i in range(80)]
        scan(st, clk, rows[:79] + [AIRTAG])
        rd.poll()
    assert len(rd.ble) <= r.MAX_BLE and "d3:5a:91:0c:44:e2" in rd.ble


def test_hostile_ble_rows_and_broken_probes():
    rd, st, clk = mk()
    scan(st, clk, [{"mac": "<img src=x>", "rssi": "loud"}, {"mac": None}, "x", 5, None, {"mac": "aa:bb:cc:dd:ee:ff", "rssi": 1e99, "name": "\x00\x1b[31mx" * 50,
                                                                                  "mfr": "76", "svc": ["a"], "ad": {"x": 1}, "rnd": "yes", "conn": 1}])
    v = rd.view()
    d = v["ble"]["devices"]
    assert len(d) == 1 and d[0]["mac"] == "aa:bb:cc:dd:ee:ff" and d[0]["rssi"] is None and len(d[0]["name"]) <= 40 and "\x1b" not in d[0]["name"]
    assert d[0]["kind"] == "other" and d[0]["rnd"] is False and d[0]["conn"] is False
    json.dumps(v)

    class Bad:
        def items(self, kind=None):
            raise RuntimeError("boom")
    st.probes = Bad()
    assert rd.view()["demo"] is False
    st.probes = None
    assert rd.view()["have"] == {"ble": 0, "zigbee": 0, "lora": 0}
    st.probes = FakeProbes()
    st.probes.data["ble"] = [{"id": "p", "items": "nope"}, "junk", {"name": "x"}]
    assert rd.view()["ble"]["scanners"] == []
    assert r.Radio(None).view()["ble"]["counts"]["total"] == 0


# ── 802.15.4 ──
def zrow(ch, pan, src, rssi, lqi, n, t="data"):
    return {"ch": ch, "pan": pan, "src": src, "rssi": rssi, "lqi": lqi, "n": n, "t": t}


def test_zigbee_pans_weak_links_and_wifi_collision():
    rd, st, clk = mk()
    st.probes.data["zigbee"] = [{"id": "p-z", "name": "sniffer", "kind": "zigbee", "seen": clk.t, "metrics": {"ch11": 150, "ch20": 30, "ch15": 2},
                                 "items": [zrow(11, "1A62", "0000", -48, 212, 90, "beacon"), zrow(11, "1a62", "3f2c", -71, 148, 40),
                                           zrow(11, "1a62", "a91e", -90, 44, 20), zrow(20, "d0c5", "0000", -60, 190, 30),
                                           zrow(15, "ffff", "", -80, 80, 2, "cmd"), zrow(99, "beef", "1", -1, 1, 1), "junk", {"ch": "x"}]}]
    rd.set_wifi("1, 6")
    z = rd.view()["zb"]
    assert [c["ch"] for c in z["channels"]] == list(range(11, 27))
    ch = {c["ch"]: c for c in z["channels"]}
    assert ch[11]["frames"] == 150 and ch[11]["wifi"] == [1] and ch[11]["mhz"] == 2405 and ch[15]["wifi"] == [] and ch[16]["wifi"] == [6]
    assert [p["pan"] for p in z["pans"]] == ["1a62", "d0c5"]  # το ffff (αναζητήσεις) δεν είναι δίκτυο· πρώτα όσα έχουν πρόβλημα
    p = z["pans"][0]
    assert p["ch"] == 11 and p["devices"] == 3 and p["frames"] == 150 and p["under"][0]["ch"] == 1 and [w["src"] for w in p["weak"]] == ["a91e"]
    assert p["lqi"] == round((212 * 90 + 148 * 40 + 44 * 20) / 150) and p["rssi"] == round((-48 * 90 - 71 * 40 - 90 * 20) / 150)
    assert z["pans"][1]["under"] == [] and z["pans"][1]["weak"] == []
    assert z["wifi"]["source"] == "manual" and z["wifi"]["manual"] == [1, 6]
    assert z["clean"][:3] == [25, 15, 20] and 11 not in z["clean"] and 17 not in z["clean"]
    adv = [a for a in z["advice"] if a["pan"] == "1a62"]
    assert adv[0]["sev"] == "med" and "κανάλι Zigbee 11" in adv[0]["el"] and "channel 11" in adv[0]["en"] and "15" in adv[0]["el"]
    assert adv[1]["sev"] == "low" and "a91e" in adv[1]["el"]
    # χωρίς Wi-Fi γνωστό → καμία σύγκρουση, αλλά ζητά τα κανάλια
    rd.api("POST", "wifi", {}, {"channels": []})
    z = rd.view()["zb"]
    assert z["wifi"]["source"] == "none" and not z["pans"][0]["under"] and any(a["sev"] == "info" for a in z["advice"])


def test_zigbee_channel_activity_falls_back_to_rows_and_survey_wifi():
    rd, st, clk = mk()
    st.probes.data["zigbee"] = [{"id": "p-z", "name": "s", "seen": clk.t, "items": [zrow(25, "face", "00124b0024c1a7f3", -70, 120, 9), zrow(25, "face", "1111", -60, 200, 4)]}]

    class WS:
        last = {"current": {"ssid": "Home", "channel": 11, "band": "2.4", "width": 20, "rssi": -50},
                "networks": [{"ssid": "Home", "channel": 11, "band": "2.4", "width": 20, "rssi": -55}, {"ssid": "Far", "channel": 1, "band": "2.4", "rssi": -90},
                             {"ssid": "Near", "channel": 13, "band": "2.4", "width": 20, "rssi": -60}, {"ssid": "5g", "channel": 36, "band": "5", "rssi": -40},
                             "junk", {"channel": "x", "band": "2.4"}]}

        def status(self):
            raise AssertionError("δεν πρέπει να ξεκινά σάρωση")
    st.wifisurvey = WS()
    z = rd.view()["zb"]
    assert {c["ch"]: c["frames"] for c in z["channels"]}[25] == 13
    assert z["wifi"]["source"] == "survey" and [(w["ch"], w["own"]) for w in z["wifi"]["channels"]] == [(11, True), (13, False)]
    assert z["pans"][0]["under"] == [{"ch": 13, "ssid": "Near", "own": False}] and "γειτονικό" in z["advice"][0]["el"]
    st.wifisurvey = object()
    assert rd.view()["zb"]["wifi"]["source"] == "none"


# ── LoRa ──
def test_lora_nodes_flags():
    rd, st, clk = mk()
    st.probes.data["lora"] = [{"id": "p-l", "name": "πύλη", "kind": "lora", "seen": clk.t - 100, "metrics": {"sf": 9},
                               "items": [{"node": "silo-01", "rssi": -92, "snr": 8.5, "batt": 3.94, "temp": 17.5, "hum": 61, "door": False, "age": 140, "seq": 2211},
                                         {"node": "pump-03", "rssi": -121, "snr": -9.5, "batt": 3.21, "age": 1620},
                                         {"node": "dead-04", "rssi": -100, "snr": 5, "batt": 3.8, "age": 7000, "sf": 12},
                                         {"node": "", "rssi": -50}, {"rssi": -50}, "junk", {"node": "odd", "rssi": "x", "snr": None, "batt": "full", "age": -5}]}]
    lo = rd.view()["lora"]
    n = {x["node"]: x for x in lo["nodes"]}
    assert set(n) == {"silo-01", "pump-03", "dead-04", "odd"}
    assert n["silo-01"]["flags"] == [] and n["silo-01"]["margin"] == 21.0 and n["silo-01"]["age"] == 240 and n["silo-01"]["sf"] == 9
    assert {f["code"] for f in n["pump-03"]["flags"]} == {"weak", "batt"} and "SF12" in n["pump-03"]["flags"][0]["el"]
    assert {f["code"] for f in n["dead-04"]["flags"]} == {"silent"} and n["dead-04"]["sf"] == 12
    assert n["odd"]["margin"] is None and n["odd"]["batt"] is None and n["odd"]["age"] is None and n["odd"]["flags"] == []
    assert lo["counts"] == {"nodes": 4, "weak": 1, "batt": 1, "silent": 1} and lo["nodes"][-1]["flags"] == []
    assert lo["gateways"][0]["fresh"] and not st.alerts


# ── api / demo / αποθήκευση ──
def test_api_routes(tmp_path):
    rd, st, clk = mk(tmp_path)
    assert rd.api("GET", "", {}, {})[0] == 200 and rd.api("GET", "", {}, {})[1]["demo"] is False
    assert rd.api("GET", "nope", {}, {}) == (404, {"error": "not found"}) and rd.api("POST", "", {}, {})[0] == 404
    code, v = rd.api("POST", "wifi", {}, {"channels": "6, 11, 200"})
    assert code == 200 and v["zb"]["wifi"]["manual"] == [6, 11]
    saved = []
    rd.on_save = saved.append
    rd.api("POST", "wifi", {}, {"channels": [1]})
    assert saved and json.load(open(saved[0]))["wifi"] == [1]
    assert r.Radio(st, str(tmp_path), clock=clk).wifi_manual == [1]
    assert rd.api("POST", "known", {}, None)[0] == 400


def test_load_tolerates_garbage(tmp_path):
    (tmp_path / "radio.json").write_text('{"ble": {"zz": 1, "aa:bb:cc:dd:ee:ff": "x", "11:22:33:44:55:66": {"hits": 3, "mfr": "bad"}}, "labels": [1], "wifi": "9"}')
    rd = r.Radio(None, str(tmp_path))
    assert list(rd.ble) == ["11:22:33:44:55:66"] and rd.ble["11:22:33:44:55:66"]["mfr"] == -1
    (tmp_path / "radio.json").write_text("not json")
    assert r.Radio(None, str(tmp_path)).ble == {}


def test_demo_shapes():
    rd = r.Radio(None, demo=True)
    v = rd.view()
    json.dumps(v)
    assert v["demo"] is True and v["have"] == {"ble": 2, "zigbee": 1, "lora": 1}
    b = v["ble"]
    assert b["counts"]["staying"] == 1 and b["counts"]["unknown_trackers"] >= 1 and b["counts"]["churn"] > 20
    top = b["devices"][0]
    assert top["kind"] == "findmy" and top["stays"] and top["where"] and top["scanners"] == 2
    assert any(d["mode"] == "known" and d["kind"] == "tile" for d in b["devices"])
    assert {"ibeacon", "mi", "ruuvi", "smarttag"} <= {d["kind"] for d in b["devices"]}
    z = v["zb"]
    p = z["pans"][0]
    assert p["pan"] == "1a62" and p["ch"] == 11 and p["under"][0]["ch"] == 1 and p["weak"]
    assert len(z["channels"]) == 16 and z["clean"][0] == 15 and any(a["sev"] == "med" for a in z["advice"])
    lo = v["lora"]
    assert lo["counts"]["nodes"] == 3 and lo["counts"]["weak"] == 1 and lo["nodes"][0]["node"] == "pump-03"
    # demo: οι ενέργειες δουλεύουν στη μνήμη, χωρίς ειδοποιήσεις/δίσκο
    assert rd.api("POST", "known", {}, {"mac": top["mac"], "label": "δικό μου", "mode": "known"})[1]["ble"]["counts"]["staying"] == 0
    assert rd.api("POST", "wifi", {}, {"channels": "6"})[1]["zb"]["pans"][0]["under"] == []
