import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import uplink as up  # noqa: E402

IP_J = json.dumps([
    {"dst": "default", "gateway": "192.168.8.1", "dev": "wwan0", "protocol": "static", "metric": 700, "flags": []},
    {"dst": "default", "gateway": "192.168.1.1", "dev": "eth0", "protocol": "dhcp", "prefsrc": "192.168.1.50", "metric": 100, "flags": []},
    {"dst": "default", "dev": "ppp0", "scope": "link", "metric": 800, "flags": []},
    {"dst": "10.0.0.0/8", "gateway": "192.168.1.254", "dev": "eth0", "flags": []},
    "junk", {"dst": "default"}])

IP_TXT = """default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100
default via 192.168.8.1 dev usb0 proto dhcp metric 700
default dev ppp0 scope link metric 800
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50 metric 100
"""

NETSTAT = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            172.20.10.1        UGScIg                en7
default            link#24            UCSIg               utun3
127                127.0.0.1          UCS                   lo0
192.168.1          link#14            UCS                   en0      !
"""


def test_parse_ip_route_json_and_text():
    r = up.parse_ip_route_json(IP_J)
    assert [(x["dev"], x["gw"], x["metric"]) for x in r] == [("eth0", "192.168.1.1", 100), ("wwan0", "192.168.8.1", 700), ("ppp0", "", 800)]
    assert r[0]["src"] == "192.168.1.50"
    assert up.parse_ip_route_json("") == [] and up.parse_ip_route_json("{bad") == [] and up.parse_ip_route_json('{"a":1}') == []
    t = up.parse_ip_route(IP_TXT)
    assert [(x["dev"], x["gw"], x["metric"]) for x in t] == [("eth0", "192.168.1.1", 100), ("usb0", "192.168.8.1", 700), ("ppp0", "", 800)]
    assert t[0]["src"] == "192.168.1.50" and up.parse_ip_route("") == []


def test_parse_netstat_macos():
    r = up.parse_netstat(NETSTAT)
    assert [(x["dev"], x["gw"], x["metric"]) for x in r] == [("en0", "192.168.1.1", 0), ("en7", "172.20.10.1", 100), ("utun3", "", 200)]
    assert up.parse_netstat("") == []
    # μόνο scoped (π.χ. η κύρια μόλις έπεσε): καμία δεν παίρνει metric 0
    only = up.parse_netstat("default            172.20.10.1        UGScIg                en7\n")
    assert only[0]["metric"] == 100


def test_classify():
    c = up.classify
    assert c("eth0", "r8152") == "wired" and c("enp3s0", "igc") == "wired" and c("en0", hw="Ethernet") == "wired"
    assert c("wlan0", "brcmfmac", wireless=True) == "wifi" and c("en0", hw="Wi-Fi") == "wifi" and c("wlp2s0") == "wifi"
    assert c("wwan0", "qmi_wwan") == "cellular" and c("wwp0s20u4", "cdc_mbim") == "cellular" and c("ppp0") == "cellular"
    assert c("usb0", "rndis_host") == "cellular" and c("usb0") == "cellular"            # Android USB tethering / HiLink
    assert c("eth1", "ipheth") == "cellular"                                            # iPhone USB σε Linux
    assert c("eth1", "cdc_ether", gw="192.168.8.1") == "cellular"                       # Huawei HiLink ως eth1
    assert c("eth1", "cdc_ether", gw="192.168.1.1") == "wired"                          # απλός αντάπτορας USB‑Ethernet
    assert c("enx0c5b8f279a64", "cdc_ncm", gw="10.0.0.1") == "wired"
    assert c("en7", hw="iPhone USB") == "cellular" and c("en0", hw="Wi-Fi", gw="172.20.10.1") == "cellular"   # hotspot κινητού
    assert c("wlan0", wireless=True, gw="192.168.43.1") == "cellular"
    assert c("eth2", "r8152", mm=True) == "cellular"                                    # το λέει το ModemManager
    assert c("utun3") == "vpn" and c("wg0") == "vpn" and c("tun0") == "vpn" and c("tailscale0") == "vpn"
    assert c("lo") == "other" and c("docker0") == "other" and c("") == "other" and c(None) == "other"


MMCLI = """modem.dbus-path                                 : /org/freedesktop/ModemManager1/Modem/0
modem.generic.model                             : E3372
modem.generic.state                             : connected
modem.generic.access-technologies.length        : 1
modem.generic.access-technologies.value[1]      : lte
modem.generic.signal-quality.value              : 71
modem.generic.signal-quality.recent             : yes
modem.generic.ports.length                      : 3
modem.generic.ports.value[1]                    : cdc-wdm0 (qmi)
modem.generic.ports.value[2]                    : ttyUSB0 (at)
modem.generic.ports.value[3]                    : wwan0 (net)
modem.3gpp.operator-code                        : 20201
modem.3gpp.operator-name                        : COSMOTE
"""


def test_parse_mmcli():
    assert up.parse_mmcli_list("    /org/freedesktop/ModemManager1/Modem/0 [huawei] E3372\n") == [0]
    assert up.parse_mmcli_list("No modems were found") == []
    m = up.parse_mmcli_kv(MMCLI)
    assert m == {"operator": "COSMOTE", "signal": 71, "tech": "LTE", "state": "connected", "model": "E3372", "ports": ["wwan0"],
                 "source": "ModemManager"}
    e = up.parse_mmcli_kv("modem.3gpp.operator-name : --\nmodem.generic.signal-quality.value : 999\n")
    assert e["operator"] == "" and e["signal"] is None and e["ports"] == []


def test_parse_hilink():
    st = "<response><ConnectionStatus>901</ConnectionStatus><SignalIcon>4</SignalIcon><CurrentNetworkType>19</CurrentNetworkType></response>"
    pl = "<response><State>0</State><FullName>COSMOTE</FullName><ShortName>COSMOTE</ShortName><Numeric>20201</Numeric></response>"
    sg = "<response><rsrq>-9.0dB</rsrq><rsrp>-97dBm</rsrp><rssi>-69dBm</rssi><sinr>12dB</sinr></response>"
    m = up.parse_hilink(st, pl, sg)
    assert m["operator"] == "COSMOTE" and m["signal"] == 80 and m["tech"] == "LTE" and m["state"] == "connected"
    assert m["rsrp"] == "-97dBm" and m["source"] == "HiLink"
    assert up.parse_hilink("<error><code>125002</code><message></message></error>") is None
    assert up.parse_hilink("", None) is None


def test_formatters():
    assert up.fmt_bytes(0) == "0 B" and up.fmt_bytes(18.4 * 1024 * 1024) == "18.4 MB" and up.fmt_bytes(3 * 1024 ** 3) == "3.0 GB"
    assert up.fmt_dur(45) == "45 s" and up.fmt_dur(37 * 60) == "37 min" and up.fmt_dur(3 * 3600) == "3.0 h"


# ───────────── μηχανή καταστάσεων με ψεύτικο ρολόι ─────────────
class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeNet:
    def __init__(self, cell=True):
        self.r = [{"dev": "eth0", "gw": "192.168.1.1", "metric": 100, "src": "192.168.1.50"}]
        if cell:
            self.r.append({"dev": "wwan0", "gw": "10.64.64.64", "metric": 700, "src": "10.64.64.65"})
        self.ok = {"eth0": True, "wwan0": True}
        self.bytes = {"wwan0": 1000}
        self.probes = []

    def routes(self):
        return [dict(x) for x in self.r]

    def info(self, dev):
        n = self.bytes.get(dev)
        return {"driver": "qmi_wwan" if dev == "wwan0" else "r8152", "hw": "", "wireless": False, "ip": "", "mm": False,
                "rx": n, "tx": 0 if n is not None else None}

    def probe(self, dev, src="", timeout=3.0):
        self.probes.append(dev)
        return (True, 12.0) if self.ok.get(dev) else (False, None)

    def modem(self, u, hilink=True):
        return {"operator": "COSMOTE", "signal": 60, "tech": "LTE", "source": "ModemManager"}


class State:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, key=None, cooldown=None, mark=True):
        self.alerts.append({"type": typ, "sev": sev, "actor": actor, "detail": detail, "t": t, "key": key, "cooldown": cooldown, "mark": mark})


def mk(cell=True, cfg=None, tmp=None):
    st, net, ck = State(), FakeNet(cell), Clock()
    u = up.Uplink(st, cfg, clock=ck, net=net, data_dir=str(tmp) if tmp else None)
    return u, st, net, ck


def step(u, ck, n=1, dt=30):
    for _ in range(n):
        ck.t += dt
        u.tick()
    return u.status


def test_failover_and_restore_with_dedup():
    u, st, net, ck = mk()
    assert u.view()["state"] == "unknown" and not u.on_backup()
    assert step(u, ck) == "ok" and st.alerts == []                 # πρώτος έλεγχος: χωρίς ειδοποίηση
    v = u.view()
    assert [(x["dev"], x["kind"], x["role"], x["ok"]) for x in v["uplinks"]] == [("eth0", "wired", "primary", True),
                                                                                   ("wwan0", "cellular", "backup", True)]
    assert v["has_backup"] and v["modem"]["operator"] == "COSMOTE" and "rx" not in v["uplinks"][0]
    net.ok["eth0"] = False
    assert step(u, ck) == "ok" and st.alerts == []                 # ένας χαμένος έλεγχος δεν φτάνει
    assert step(u, ck) == "backup" and u.on_backup()
    net.bytes["wwan0"] += 5 * 1024 * 1024                          # κίνηση που πέρασε από LTE όσο ήταν κάτω η κύρια
    assert [(a["type"], a["sev"]) for a in st.alerts] == [("Έπεσε η κύρια γραμμή — δουλεύω από LTE", "high")]
    assert "eth0" in st.alerts[0]["detail"] and "wwan0, COSMOTE" in st.alerts[0]["detail"] and st.alerts[0]["mark"] is False
    step(u, ck, 10)
    assert len(st.alerts) == 1                                     # όσο μένει κάτω, όχι ξανά
    net.ok["eth0"] = True
    assert step(u, ck) == "backup"                                 # και η επαναφορά θέλει επιβεβαίωση
    assert step(u, ck) == "ok" and not u.on_backup()
    assert [(a["type"], a["sev"]) for a in st.alerts][1:] == [("Η κύρια γραμμή επανήλθε", "low")]
    assert "6 min" in st.alerts[1]["detail"] and "5.0 MB" in st.alerts[1]["detail"]
    ev = u.view()["events"]
    assert [(e["from"], e["to"]) for e in ev] == [("backup", "ok"), ("ok", "backup")] and ev[0]["en"].startswith("Primary line (eth0) is back")
    # αναπήδηση (flap) ενός ελέγχου δεν παράγει τίποτα
    net.ok["eth0"] = False
    step(u, ck)
    net.ok["eth0"] = True
    step(u, ck, 3)
    assert len(st.alerts) == 2 and u.status == "ok"


def test_all_down_then_backup_then_ok():
    u, st, net, ck = mk()
    step(u, ck)
    net.ok.update(eth0=False, wwan0=False)
    assert step(u, ck, 2) == "down" and not u.on_backup()
    types = [a["type"] for a in st.alerts]
    assert "Χωρίς Internet — έπεσαν όλες οι γραμμές" in types and "Η εφεδρική γραμμή LTE δεν δουλεύει" in types
    assert "Έπεσε η κύρια γραμμή — δουλεύω από LTE" not in types
    net.ok["wwan0"] = True
    assert step(u, ck, 2) == "backup"
    assert st.alerts[-1]["type"] == "Έπεσε η κύρια γραμμή — δουλεύω από LTE"
    net.ok["eth0"] = True
    assert step(u, ck, 2) == "ok" and st.alerts[-1]["type"] == "Η κύρια γραμμή επανήλθε"
    assert u.view()["down_since"] is None


def test_backup_health_alert_once_and_rearm():
    u, st, net, ck = mk()
    step(u, ck)
    net.ok["wwan0"] = False
    step(u, ck, 3)                                                 # η εφεδρική ελέγχεται αραιά όσο η κύρια είναι ΟΚ
    assert st.alerts == [] and net.probes.count("wwan0") == 1
    step(u, ck, 30)                                                # ≥ 2 αραιοί έλεγχοι (κάθε 300 s)
    assert [(a["type"], a["sev"]) for a in st.alerts] == [("Η εφεδρική γραμμή LTE δεν δουλεύει", "med")]
    assert st.alerts[0]["cooldown"] == 6 * 3600 and u.status == "ok" and u.view()["backup_ok"] is False
    step(u, ck, 60)
    assert len(st.alerts) == 1                                     # μία φορά, όχι κάθε 5 λεπτά
    net.ok["wwan0"] = True
    step(u, ck, 12)
    assert len(st.alerts) == 1 and u.view()["backup_ok"] is True
    net.ok["wwan0"] = False
    step(u, ck, 30)
    assert len(st.alerts) == 2                                     # ξανά μόνο αφού είχε επανέλθει


def test_backup_expected_but_modem_missing():
    u, st, net, ck = mk(cell=False, cfg={"expect_cellular": True})
    step(u, ck, 3)
    assert [a["type"] for a in st.alerts] == ["Η εφεδρική γραμμή LTE δεν δουλεύει"] and "default route" in st.alerts[0]["detail"]
    v = u.view()
    assert v["state"] == "ok" and v["expect_cellular"] and not v["has_backup"] and "SIM" in v["hint"]
    # χωρίς προσδοκία και χωρίς modem: καμία ειδοποίηση, μόνο πρόταση
    u2, st2, _net2, ck2 = mk(cell=False)
    step(u2, ck2, 5)
    assert st2.alerts == [] and "lte-setup.sh" in u2.view()["hint"]
    # χωρίς εφεδρική, πέφτει η κύρια → «όλες οι γραμμές»
    _net2.ok["eth0"] = False
    assert step(u2, ck2, 2) == "down" and [a["type"] for a in st2.alerts] == ["Χωρίς Internet — έπεσαν όλες οι γραμμές"]


def test_cellular_only_box_is_data_saver_without_alert():
    u, st, net, ck = mk()
    net.r = net.r[1:]                                              # μόνο LTE, ποτέ ενσύρματη
    assert step(u, ck, 3) == "cellular" and u.on_backup() and st.alerts == []
    net.r.insert(0, {"dev": "eth0", "gw": "192.168.1.1", "metric": 100, "src": ""})
    assert step(u, ck, 2) == "ok" and st.alerts == []              # εμφανίστηκε ενσύρματη: χωρίς «επανήλθε»
    # η ενσύρματη χάνει και το route της (βγήκε το καλώδιο) → τώρα είναι πραγματικό failover
    net.r.pop(0)
    assert step(u, ck, 2) == "backup" and st.alerts[-1]["type"] == "Έπεσε η κύρια γραμμή — δουλεύω από LTE"


def test_monthly_data_counter_and_persistence(tmp_path):
    u, st, net, ck = mk(cfg={"cap_gb": 1}, tmp=tmp_path)
    step(u, ck)
    assert u.view()["data"]["bytes"] == 0                          # η πρώτη ανάγνωση είναι μόνο σημείο αναφοράς
    net.bytes["wwan0"] += 100 * 1024 * 1024
    step(u, ck)
    net.bytes["wwan0"] = 7 * 1024 * 1024                           # reboot/επανασύνδεση: ο μετρητής ξεκίνησε από την αρχή
    step(u, ck)
    d = u.view()["data"]
    assert d["bytes"] == 107 * 1024 * 1024 and d["text"] == "107.0 MB" and d["pct"] == 10.4 and d["cap_gb"] == 1.0
    saved = json.load(open(tmp_path / "uplink.json"))
    assert saved["data"]["bytes"] == d["bytes"] and saved["seen_cell"] is True
    u2 = up.Uplink(State(), {"cap_gb": 1}, clock=ck, net=net, data_dir=str(tmp_path))
    assert u2.view()["data"]["bytes"] == d["bytes"] and u2.view()["expect_cellular"] is True
    ck.t += 40 * 86400                                             # νέος μήνας → μηδενίζει
    u2.tick()
    assert u2.view()["data"]["bytes"] == 0
    (tmp_path / "uplink.json").write_text("[]")
    assert up.Uplink(State(), data_dir=str(tmp_path), net=net).events == []


def test_forced_cellular_iface_and_vpn_ignored():
    u, st, net, ck = mk(cell=False, cfg={"cellular_ifaces": ["eth1"]})
    net.r += [{"dev": "eth1", "gw": "192.168.2.1", "metric": 600, "src": ""}, {"dev": "wg0", "gw": "", "metric": 50, "src": ""}]
    net.ok["eth1"] = True
    step(u, ck)
    assert [(x["dev"], x["kind"], x["role"]) for x in u.view()["uplinks"]] == [("eth0", "wired", "primary"), ("eth1", "cellular", "backup")]


def test_probe_exception_counts_as_down_and_no_state_object():
    u, st, net, ck = mk()

    def boom(dev, src="", timeout=3.0):
        raise OSError("x")

    step(u, ck)
    net.probe = boom
    assert step(u, ck, 2) == "down"
    u2 = up.Uplink(None, clock=ck, net=FakeNet())
    u2.net.ok["eth0"] = False
    u2.tick()
    ck.t += 30
    u2.tick()                                                      # state=None → απλώς δεν στέλνει ειδοποίηση
    assert u2.status == "backup"


def test_api_and_demo_shapes():
    u = up.Uplink(None, demo=True, clock=Clock())
    code, v = u.api("GET", "", {}, {})
    assert code == 200 and v["demo"] and v["state"] == "ok" and not v["on_backup"] and v["has_backup"]
    assert [x["kind"] for x in v["uplinks"]] == ["wired", "cellular"] and v["modem"]["operator"] == "COSMOTE"
    assert [(e["from"], e["to"]) for e in v["events"]] == [("backup", "ok"), ("ok", "backup")]
    assert v["data"]["cap_gb"] == 5.0 and 0 < v["data"]["pct"] < 100 and v["hint"] and v["hint_en"]
    json.dumps(v)
    assert u.tick() == "ok" and u.api("POST", "check", {}, {})[0] == 200 and not u.busy     # demo: ποτέ δίκτυο
    assert u.api("GET", "x", {}, {}) == (404, {"error": "not found"}) and u.api("POST", "x", {}, {})[0] == 404
    live, st, net, ck = mk()
    code, v = live.api("POST", "check", {}, {})
    assert code == 200 and "busy" in v
    for _ in range(200):
        if not live.busy:
            break
        import time
        time.sleep(0.01)
    assert live.status == "ok" and live.view()["busy"] is False
