"""Tests για το Wi‑Fi Guard (χωρίς δίκτυο: όλα με fixtures)."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import netwatch as nw  # noqa: E402
import wifiguard as wg  # noqa: E402

SP = {"SPAirPortDataType": [{"spairport_airport_interfaces": [
    {"_name": "awdl0"},
    {"_name": "en0", "spairport_wireless_mac_address": "aa:bb:cc:dd:ee:ff",
     "spairport_current_network_information": {
         "_name": "Cafe", "spairport_network_channel": "6 (2GHz, 20MHz)", "spairport_network_phymode": "802.11n",
         "spairport_security_mode": "spairport_security_mode_none", "spairport_signal_noise": "-61 dBm / -92 dBm"},
     "spairport_airport_other_local_wireless_networks": [
         {"_name": "Cafe", "spairport_security_mode": "spairport_security_mode_wpa2_personal",
          "spairport_signal_noise": "-40 dBm / -92 dBm"},
         {"_name": "Home", "spairport_security_mode": "spairport_security_mode_wpa3_personal"}]}]}]}

LSOF = """COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
ControlCe   612 me    10u  IPv4 0x1      0t0  TCP *:7000 (LISTEN)
ControlCe   612 me    11u  IPv6 0x2      0t0  TCP *:5000 (LISTEN)
postgres    900 me     7u  IPv4 0x3      0t0  TCP 127.0.0.1:5432 (LISTEN)
python3     901 me     3u  IPv4 0x4      0t0  TCP 127.0.0.1:8765 (LISTEN)
sshd          1 root   4u  IPv6 0x5      0t0  TCP *:22 (LISTEN)
"""


def base(**kw):
    d = {"public": True, "wifi": wg.parse_system_profiler(json.dumps(SP)),
         "captive": {"ok": True}, "dns": {"hijacked": [], "nxdomain_hijack": [], "ok": True},
         "tls": [{"host": "github.com", "ok": True, "issuer": "Sectigo"}],
         "firewall": {"enabled": True, "block_all": False, "stealth": True},
         "listening": [], "vpn": True, "private_mac": True}
    d.update(kw)
    return d


def ids(res, status):
    return {c["id"] for c in res["checks"] if c["status"] == status}


def test_parse_system_profiler_and_evil_twin():
    w = wg.parse_system_profiler(json.dumps(SP))
    assert (w["iface"], w["ssid"], w["security"], w["signal"]) == ("en0", "Cafe", "none", -61)
    assert len(w["others"]) == 2
    tw = wg.evil_twins(w)
    assert [t["security"] for t in tw] == ["wpa2_personal"]
    assert wg.parse_system_profiler("not json") is None


def test_parse_lsof_ignores_localhost():
    assert wg.parse_lsof(LSOF) == [("sshd", 22), ("ControlCe", 5000), ("ControlCe", 7000)]


def test_parse_firewall_and_private_mac():
    fw = wg.parse_firewall("Firewall is enabled. (State = 1)\nFirewall stealth mode is off\n")
    assert fw == {"enabled": True, "block_all": False, "stealth": False}
    assert wg.parse_firewall("Firewall is disabled. (State = 0)\nFirewall stealth mode is on\n")["enabled"] is False
    assert wg.parse_firewall("Firewall is blocking all non-essential incoming connections. (State = 2)")["block_all"]
    assert wg.private_mac("9e:53:3b:15:41:bf") is True
    assert wg.private_mac("a4:2b:b0:00:00:01") is False


def test_dns_check_detects_hijack_and_nxdomain():
    good = {"one.one.one.one": {"1.1.1.1"}, "dns.google": {"8.8.8.8"}, "dns.quad9.net": {"9.9.9.9"}}
    assert wg.dns_check(lambda n: good.get(n, set()))["ok"]
    bad = wg.dns_check(lambda n: {"10.0.0.1"})
    assert len(bad["hijacked"]) == 3 and bad["nxdomain_hijack"] == ["10.0.0.1"] and not bad["ok"]
    nx = wg.dns_check(lambda n: good.get(n, {"10.10.0.1"}))
    assert not nx["hijacked"] and nx["nxdomain_hijack"] == ["10.10.0.1"]


def test_open_cafe_with_evil_twin_is_dangerous():
    r = wg.evaluate(base())
    assert {"encryption", "evil_twin"} <= ids(r, "bad")
    assert r["level"] == "bad" and r["score"] <= 40


def test_good_network_is_ok_and_home_skips_public_warnings():
    w = {"iface": "en0", "ssid": "Home", "security": "wpa2_personal", "others": []}
    r = wg.evaluate(base(wifi=w, vpn=False, firewall={"enabled": True, "block_all": False, "stealth": False}))
    assert {"encryption", "vpn", "firewall"} <= ids(r, "warn")
    home = wg.evaluate(base(wifi=w, vpn=False, public=False, firewall={"enabled": True, "block_all": False, "stealth": False}))
    assert not ids(home, "warn") and not ids(home, "bad") and home["level"] == "ok" and home["score"] == 100


def test_tls_failure_and_sharing_ports():
    r = wg.evaluate(base(tls=[{"host": "github.com", "ok": False, "error": "self signed"}],
                         listening=[("sshd", 22), ("ControlCe", 7000)]))
    assert "tls" in ids(r, "bad") and "sharing" in ids(r, "bad")
    r2 = wg.evaluate(base(listening=[("ControlCe", 7000)]))
    assert "sharing" in ids(r2, "warn")


def test_guard_raises_alerts_once_with_mitre():
    s = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    g = wg.Guard(s, sim=wg.demo_check)
    g._run("manual")
    assert g.result["demo"] and g.result["level"] == "bad"
    types = [a["type"] for a in s.alerts]
    assert "Evil twin Wi‑Fi" in types and "Ανοιχτό Wi‑Fi" in types
    a = next(a for a in s.alerts if a["type"] == "Evil twin Wi‑Fi")
    assert a["mitre"]["id"] == "T1557" and a["target"] == "Cafe_Free_WiFi"
    n = len(s.alerts)
    g._run("manual")  # cooldown: όχι διπλές ειδοποιήσεις
    assert len(s.alerts) == n


def test_guard_trusted_network_is_persisted(tmp_path):
    s = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    p = tmp_path / "trusted.json"
    g = wg.Guard(s, sim=wg.demo_check, trusted_path=str(p))
    g._run("manual")
    g.set_trusted("Cafe_Free_WiFi", True)
    assert json.loads(p.read_text()) == ["Cafe_Free_WiFi"] and g.result["public"] is False
    assert "vpn" not in {c["id"] for c in g.result["checks"]}
    assert wg.Guard(s, trusted_path=str(p)).trusted == {"Cafe_Free_WiFi"}


def test_wifi_detector_can_be_disabled():
    cfg = nw.load_config(None)
    cfg["detectors"]["wifi_guard"] = False
    s = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False, cfg=cfg)
    wg.Guard(s, sim=wg.demo_check)._run("manual")
    assert not [a for a in s.alerts if "Wi‑Fi" in a["type"]]
