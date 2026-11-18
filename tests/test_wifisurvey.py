import json

import wifisurvey as ws

FIXTURE = json.dumps({"SPAirPortDataType": [{"spairport_airport_interfaces": [
    {"_name": "en0", "spairport_status_information": "spairport_status_connected",
     "spairport_current_network_information": {
         "_name": "Home", "spairport_network_channel": "4 (2GHz, 40MHz)", "spairport_network_phymode": "802.11ax",
         "spairport_network_type": "spairport_network_type_station",
         "spairport_security_mode": "spairport_security_mode_wpa2_personal", "spairport_signal_noise": "-74 dBm / -90 dBm",
         "spairport_network_rate": 144, "spairport_network_mcs": 7},
     "spairport_airport_other_local_wireless_networks": [
         {"_name": "A", "spairport_network_channel": "1 (2GHz, 20MHz)", "spairport_security_mode": "spairport_security_mode_wpa2_personal",
          "spairport_signal_noise": "-50 dBm / -92 dBm", "spairport_network_phymode": "802.11b/g/n"},
         {"_name": "B", "spairport_network_channel": "6 (2GHz, 20MHz)", "spairport_security_mode": "spairport_security_mode_wpa2_personal",
          "spairport_signal_noise": "-55 dBm / -92 dBm"},
         {"_name": "C", "spairport_network_channel": "6 (2GHz, 40MHz)", "spairport_security_mode": "spairport_security_mode_none",
          "spairport_signal_noise": "-60 dBm / -92 dBm"},
         {"_name": "<redacted>", "spairport_network_channel": "36 (5GHz, 80MHz)",
          "spairport_security_mode": "spairport_security_mode_wpa2_wpa3_personal", "spairport_signal_noise": "-60 dBm / -95 dBm"},
         {"spairport_network_channel": "149 (5GHz, 80MHz)", "spairport_security_mode": "spairport_security_mode_wep"},
         {"_name": "Home", "spairport_network_channel": "100 (5GHz, 80MHz)", "spairport_security_mode": "spairport_security_mode_wpa2_personal",
          "spairport_signal_noise": "-40 dBm / -95 dBm"},
         {"_name": "Six", "spairport_network_channel": "37 (6GHz, 160MHz)", "spairport_security_mode": "spairport_security_mode_wpa3_personal",
          "spairport_signal_noise": "-80 dBm / -96 dBm"},
     ]},
    {"_name": "awdl0", "spairport_current_network_information": {"spairport_network_type": "spairport_network_type_station"}},
]}]})

AIRPORT = """                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
                        Neighbor aa:bb:cc:dd:ee:01 -61  11      Y  GR WPA2(PSK/AES/AES)
                    Old Printer aa:bb:cc:dd:ee:02 -80  6,+1    Y  -- WPA(PSK/TKIP/TKIP) WPA2(PSK/AES/AES)
                         Cafe aa:bb:cc:dd:ee:03 -85  36,80   Y  GR NONE
"""


def test_parse_system_profiler_fixture():
    r = ws.parse_system_profiler(FIXTURE)
    assert r["interface"] == "en0"
    cur = r["current"]
    assert (cur["ssid"], cur["channel"], cur["band"], cur["width"], cur["rssi"], cur["noise"], cur["snr"]) == ("Home", 4, "2.4", 40, -74, -90, 16)
    assert cur["security"] == "wpa2" and cur["current"]
    n = {x["channel"]: x for x in r["networks"]}
    assert n[36]["redacted"] and n[36]["ssid"] is None and n[36]["security"] == "wpa2/wpa3"
    assert n[149]["redacted"] and n[149]["rssi"] is None and n[149]["security"] == "wep"
    assert n[6]["security"] == "open" and n[37]["band"] == "6"
    assert ws.parse_system_profiler("{}")["networks"] == []


def test_parse_airport_fallback():
    nets = ws.parse_airport(AIRPORT)
    assert [(n["ssid"], n["channel"], n["band"], n["width"], n["security"]) for n in nets] == [
        ("Neighbor", 11, "2.4", 20, "wpa2"), ("Old Printer", 6, "2.4", 40, "wpa/wpa2"), ("Cafe", 36, "5", 80, "open")]


def test_channel_and_security_parsing():
    assert ws.parse_channel("44 (5GHz, 80MHz)") == (44, "5", 80)
    assert ws.parse_channel(11) == (11, "2.4", 20)
    assert ws.parse_channel(None) == (None, None, None)
    assert ws.norm_security("spairport_security_mode_wpa3_transition") == "wpa2/wpa3"
    assert ws.norm_security("spairport_security_mode_wpa2_enterprise") == "wpa2-enterprise"
    assert ws.norm_security("spairport_security_mode_wpa_personal_mixed") == "wpa/wpa2"


def test_occupancy_24_overlap():
    nets = [{"band": "2.4", "channel": 1, "width": 20, "rssi": -50}]
    occ = {o["ch"]: o for o in ws.occupancy24(nets)}
    assert occ[1]["score"] == 1.0 and occ[5]["score"] == round(0.2, 2) and occ[6]["score"] == 0 and occ[5]["count"] == 1
    occ = {o["ch"]: o for o in ws.occupancy24([{"band": "2.4", "channel": 1, "width": 40, "rssi": -50}])}
    assert occ[9]["score"] > 0 and occ[11]["score"] == 0  # 40 MHz στο 1 → δευτερεύον στο 5


def test_recommendation_24_and_5():
    nets = [{"band": "2.4", "channel": c, "width": 20, "rssi": -55} for c in (1, 1, 6, 6, 6)]
    assert ws.recommend24(ws.occupancy24(nets))["channel"] == 11
    nets5 = [{"band": "5", "channel": 36, "width": 80, "rssi": -55}, {"band": "5", "channel": 149, "width": 80, "rssi": -60},
             {"band": "5", "channel": 100, "width": 20, "rssi": -90}]
    occ = ws.occupancy5(nets5)
    r = ws.recommend5(occ, 80, avoid_dfs=True)
    assert r["block"] == [149, 153, 157, 161] and not r["dfs"]  # 36–48 είναι πιο φορτωμένο, τα DFS εξαιρούνται
    r = ws.recommend5(occ, 80, avoid_dfs=False)
    assert r["block"] == [52, 56, 60, 64] and r["dfs"]
    assert ws.recommend5(occ, 160, avoid_dfs=True)["width"] == 160  # χωρίς μη‑DFS 160 → πέφτει σε DFS


def test_analyze_flags_issues():
    r = ws.parse_system_profiler(FIXTURE)
    a = ws.analyze(r["current"], r["networks"])
    codes = {i["code"] for i in a["issues"]}
    assert {"overlap24", "wide24", "weak", "snr", "nearby_open", "nearby_wep"} <= codes
    assert a["redacted"] and a["own"][0]["channel"] == 100
    assert a["recommendation"]["2.4"]["channel"] == 11
    assert a["counts"] == {"2.4": 3, "5": 2, "6": 1}  # το «Home» στα 5 GHz δεν μετράει ως γείτονας
    assert a["recommendation"]["6"]["psc"]
    json.dumps(a)


def test_demo_survey():
    s = ws.WifiSurvey(sim=True)
    st = s.status()
    assert st["ok"] and st["demo"] and st["source"] == "demo" and len(st["networks"]) > 15
    assert st["current"]["ssid"] == "Homelab" and st["note"]
    codes = {i["code"] for i in st["issues"]}
    assert {"overlap24", "wide24", "weak", "nearby_wep", "nearby_open"} <= codes
    json.dumps(st, ensure_ascii=False)
