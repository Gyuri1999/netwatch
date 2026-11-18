"""Tests για τη μικρο-τμηματοποίηση IoT (μάθηση προφίλ, παραβάσεις, εξαγωγή κανόνων, αποθήκευση)."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import iotfw  # noqa: E402

CAM, CAM_MAC, GW = "192.168.1.30", "c0:56:e3:30:30:30", "192.168.1.1"


class St:
    def __init__(self):
        self.alerts = []
        self.gateway = GW
        self.me = {"192.168.1.23"}
        self.domains = {"52.57.110.21": {"euw1-relay.tplinkcloud.com"}, "3.124.90.17": {"n-deventry-de.tplinkcloud.com"}}
        self.hosts = {}
        self.arp_table = {}

    def alert(self, typ, sev, actor, target, detail, t, key=None, cooldown=None, **kw):
        self.alerts.append({"type": typ, "sev": sev, "actor": actor, "target": target, "key": key, "detail": detail})


def pkt(dst, dp=443, proto="TCP", src=CAM, sni=None, smac=CAM_MAC, sp=50000, flags="S"):
    return {"src": src, "dst": dst, "proto": proto, "sp": sp, "dp": dp, "sni": sni, "smac": smac, "flags": flags}


def make(path=None, **cfg):
    st = St()
    fw = iotfw.IotFw(st, {"learn_hours": 1, **cfg}, path=path)
    return st, fw


def learn_camera(fw, t=1000.0):
    fw.observe(pkt("52.57.110.21"), t)
    fw.observe(pkt("3.124.90.17"), t + 1)
    fw.observe(pkt("162.159.200.123", 123, "UDP", sni=None), t + 2)
    fw.observe(pkt(GW, 53, "UDP"), t + 3)                       # DNS στο gateway
    fw.observe(pkt("192.168.1.17", 1883), t + 4)                # γείτονας LAN (MQTT)
    fw.observe(pkt("52.57.110.21", sp=443, dp=50000, flags="A"), t + 5)  # απάντηση → αγνοείται


def test_learning_builds_profile_grouped_by_domain():
    st, fw = make()
    learn_camera(fw)
    d = fw.devs[CAM_MAC]
    assert d["mode"] == "learn" and d["ip"] == CAM
    assert set(d["dests"]) == {"tplinkcloud.com|TCP/443", "162.159.200.123|UDP/123"}
    e = d["dests"]["tplinkcloud.com|TCP/443"]
    assert e["name"] == "*.tplinkcloud.com" and sorted(e["ips"]) == ["3.124.90.17", "52.57.110.21"]
    assert e["pkts"] == 2
    assert d["dns"]["gateway"] == 1 and not d["dns"]["external"]
    assert list(d["lan"]) == ["192.168.1.17|TCP/1883"]       # το LAN ξεχωριστά, όχι στους προορισμούς
    assert not st.alerts


def test_gateway_and_me_are_off_and_ip_key_migrates_to_mac():
    st, fw = make()
    fw.observe(pkt("8.8.4.4", src=GW, smac=None), 1)
    assert fw.devs[GW]["mode"] == "off"
    fw.observe(pkt("1.2.3.4", src="192.168.1.50", smac=None), 1)
    assert "192.168.1.50" in fw.devs
    fw.observe(pkt("1.2.3.5", src="192.168.1.50", smac="aa:bb:cc:00:00:50"), 2)
    assert "192.168.1.50" not in fw.devs and len(fw.devs["aa:bb:cc:00:00:50"]["dests"]) == 2


def test_watch_alerts_once_with_cooldown_and_accept_clears():
    st, fw = make()
    learn_camera(fw)
    fw.set_mode(CAM, "watch", now=2000)
    fw.observe(pkt("52.57.110.21"), 2001)                       # γνωστός → τίποτα
    assert not st.alerts
    fw.observe(pkt("47.91.88.12", 9000), 2002)                  # νέος, ασυνήθιστη θύρα
    fw.observe(pkt("47.91.88.12", 9000), 2003)                  # ίδιος → cooldown
    assert len(st.alerts) == 1
    a = st.alerts[0]
    assert a["type"] == iotfw.ALERT_TYPE and a["actor"] == CAM and a["target"] == "47.91.88.12"
    assert a["sev"] == "high" and "47.91.88.12" in a["detail"]
    s = fw.status(now=2010)
    dev = next(x for x in s["devices"] if x["key"] == CAM_MAC)
    assert dev["counts"]["pending"] == 1 and len(dev["violations"]) == 1
    assert s["recent_violations"][0]["dest"] == "47.91.88.12|TCP/9000"
    r = fw.accept(CAM_MAC, "47.91.88.12|TCP/9000")
    assert r["accepted"] == ["47.91.88.12|TCP/9000"]
    d = fw.devs[CAM_MAC]
    assert not d["pending"] and not d["violations"] and "47.91.88.12|TCP/9000" in d["dests"]
    fw.observe(pkt("47.91.88.12", 9000), 99999)                 # τώρα είναι στο προφίλ
    assert len(st.alerts) == 1
    with pytest.raises(KeyError):
        fw.accept(CAM_MAC, "nope|TCP/1")


def test_severity_bumps_for_intel_and_new_country():
    st, fw = make(alert_severity="low")
    st.hosts["52.57.110.21"] = {"geo": {"countryCode": "DE", "country": "Germany"}, "intel": []}
    learn_camera(fw)
    fw.set_mode(CAM, "watch")
    st.hosts["9.9.9.1"] = {"geo": {"countryCode": "US", "country": "United States"}, "intel": []}
    fw.observe(pkt("9.9.9.1", 443), 3000)
    assert st.alerts[-1]["sev"] == "med"                        # νέα χώρα
    st.hosts["6.6.6.6"] = {"geo": None, "intel": [{"kind": "c2"}]}
    fw.observe(pkt("6.6.6.6", 443), 3001)
    assert st.alerts[-1]["sev"] == "high"


def test_auto_watch_after_learning_for_iot_kind():
    st, fw = make()
    learn_camera(fw, t=0)
    fw.devs[CAM_MAC]["meta"] = {"kind": "camera"}
    fw.observe(pkt("52.57.110.21"), 3601)
    assert fw.devs[CAM_MAC]["mode"] == "watch"
    fw.observe(pkt("1.1.1.9", src="192.168.1.60", smac="aa:bb:cc:00:00:60"), 0)
    fw.devs["aa:bb:cc:00:00:60"]["meta"] = {"kind": "computer"}
    fw.observe(pkt("1.1.1.9", src="192.168.1.60", smac="aa:bb:cc:00:00:60"), 4000)
    assert fw.devs["aa:bb:cc:00:00:60"]["mode"] == "learn"     # δεν είναι IoT → μένει στη μάθηση


def test_off_mode_and_reset_and_bad_mode():
    st, fw = make()
    learn_camera(fw)
    fw.set_mode(CAM_MAC, "off")
    fw.observe(pkt("5.5.5.5"), 2000)
    assert "5.5.5.5|TCP/443" not in fw.devs[CAM_MAC]["dests"]
    fw.reset(CAM)
    d = fw.devs[CAM_MAC]
    assert d["mode"] == "learn" and not d["dests"] and not d["lan"]
    with pytest.raises(ValueError):
        fw.set_mode(CAM, "block")
    with pytest.raises(KeyError):
        fw.set_mode("10.9.9.9", "watch")


@pytest.mark.parametrize("fmt", ["openwrt", "pfsense", "mikrotik", "iptables"])
def test_rules_export(fmt):
    st, fw = make()
    learn_camera(fw)
    r = fw.rules(CAM_MAC, fmt)
    txt = r["text"]
    assert r["fmt"] == fmt and r["filename"]
    assert CAM in txt and "52.57.110.21" in txt and "3.124.90.17" in txt and "162.159.200.123" in txt
    assert "*.tplinkcloud.com" in txt                          # domain ως σχόλιο
    assert "ΑΛΛΑΖΟΥΝ" in txt                                     # σημείωση ότι οι IP του cloud αλλάζουν
    assert GW in txt                                             # DNS στο gateway
    low = txt.lower()
    assert "default drop" in low or "-j drop" in low
    assert "password" not in low and "token" not in low
    if fmt == "openwrt":
        assert "hook forward" in txt and "@nw_" in txt and "52.57.110.21 . tcp . 443" in txt
    if fmt == "mikrotik":
        assert "/ip firewall address-list" in txt and "action=drop" in txt and "dst-address-list=!nw-rfc1918" in txt
    if fmt == "iptables":
        assert "-d 52.57.110.21 -p tcp --dport 443 -j RETURN" in txt and "iptables -A NW_" in txt
    if fmt == "pfsense":
        assert "Alias:" in txt and "Block" in txt
    # πλευρική κίνηση: χωρίς lan=1 οι κανόνες LAN είναι σχόλια/ανοιχτοί, με lan=1 ενεργοί
    lan = fw.rules(CAM_MAC, fmt, lan=True)["text"]
    assert "192.168.1.17" in lan and lan != txt


def test_rules_errors():
    st, fw = make()
    learn_camera(fw)
    with pytest.raises(ValueError):
        fw.rules(CAM, "cisco")
    with pytest.raises(KeyError):
        fw.rules("10.0.0.99", "openwrt")


def test_persistence_round_trip(tmp_path):
    p = str(tmp_path / "iotfw.json")
    st, fw = make(path=p)
    learn_camera(fw)
    fw.set_mode(CAM, "watch")                                    # σώζει αμέσως
    fw.observe(pkt("47.91.88.12", 9000), 5000)
    fw._save()
    assert os.path.exists(p) and not os.path.exists(p + ".tmp")
    json.load(open(p, encoding="utf-8"))
    st2, fw2 = make(path=p)
    d = fw2.devs[CAM_MAC]
    assert d["mode"] == "watch" and "tplinkcloud.com|TCP/443" in d["dests"] and "47.91.88.12|TCP/9000" in d["pending"]
    assert fw2.ip_key[CAM] == CAM_MAC
    fw2.observe(pkt("52.57.110.21"), 6000)
    assert not st2.alerts


def test_caps_enforced():
    st, fw = make(max_destinations=10)
    for i in range(30):
        fw.observe(pkt(f"8.8.{i}.1", 443), 1000 + i)
    d = fw.devs[CAM_MAC]
    assert len(d["dests"]) == 10 and d["full"]
    fw.set_mode(CAM, "watch")
    for i in range(100):
        fw.observe(pkt(f"9.9.{i}.1", 443), 2000 + i * 10)
    assert len(d["pending"]) == iotfw.MAX_PENDING and len(d["violations"]) <= iotfw.MAX_VIOL
    assert len(st.alerts) <= iotfw.MAX_ALERTS_HOUR * 2          # όριο ειδοποιήσεων ανά ώρα
    for i in range(40):
        fw.observe(pkt("52.1.1.1", 443, sni=None), 1)
    for i in range(100):
        fw.observe(pkt(f"192.168.1.{100 + i}", 80), 1)
    assert len(d["lan"]) == iotfw.MAX_LAN


def test_external_dns_hint_and_status_shape():
    st, fw = make()
    fw.observe(pkt("8.8.8.8", 53, "UDP", src="192.168.1.52", smac="d8:1f:12:52:52:52"), 1)
    s = fw.status(now=10)
    assert s["enabled"] and s["demo"] is False and s["error"] is None
    dev = s["devices"][0]
    assert dev["dns"]["external"][0]["ip"] == "8.8.8.8" and dev["dns"]["external"][0]["provider"] == "Google"
    assert any(h["code"] == "external_dns" for h in dev["hints"])
    for k in ("key", "ip", "mac", "name", "vendor", "kind", "mode", "learning", "counts", "dests", "pending", "lan",
              "violations", "hints"):
        assert k in dev
    json.dumps(s)


def test_ignores_non_lan_sources_multicast_and_responses():
    st, fw = make()
    assert fw.observe(pkt("192.168.1.30", src="8.8.8.8", smac=None)) is None
    assert fw.observe(pkt("224.0.0.251", 5353, "UDP", sp=5353)) is None
    assert fw.observe(pkt("1.2.3.4", 50000, sp=443, flags="SA")) is None
    assert not fw.devs


def test_demo_seed_has_devices_and_violation():
    st = St()
    fw = iotfw.IotFw(st, {}, sim=True)
    s = fw.status()
    keys = {d["name"] for d in s["devices"]}
    assert {"Κάμερα εισόδου (Tapo)", "Πρίζα κουζίνας", "Smart TV σαλονιού", "ESP32 κήπου"} <= keys
    assert s["recent_violations"] and st.alerts
    tv = next(d for d in s["devices"] if d["kind"] == "tv")
    assert tv["mode"] == "learn" and tv["learning"]["active"] and tv["counts"]["countries"] >= 5
    esp = next(d for d in s["devices"] if d["kind"] == "esp")
    assert esp["lan"] and esp["lan"][0]["ip"] == "192.168.1.17"
    for d in s["devices"]:
        for fmt in iotfw.FMT_IDS:
            assert d["ip"] in fw.rules(d["key"], fmt)["text"]
