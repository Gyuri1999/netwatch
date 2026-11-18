"""Tests για το VPN guard (kill-switch / split tunnel) — χωρίς subprocess: ψεύτικα στιγμιότυπα και συνδέσεις."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import vpnguard as vg  # noqa: E402

IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:22:fb:00:11:22
\tinet6 fe80::1c2b:3a4f:9e10:7d21%en0 prefixlen 64 secured scopeid 0xb
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 2a02:587:d4a1:c00::23 prefixlen 64 autoconf secured
\tstatus: active
en5: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.9.9.9 netmask 0xffffff00
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet6 fe80::d1e:4a2:1b0c:9e01%utun0 prefixlen 64 scopeid 0x10
utun1: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
\tinet6 fe80::8e4f:3ad:c5b0:21%utun1 prefixlen 64 scopeid 0x11
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420
\tinet 10.64.12.7 --> 10.64.12.7 netmask 0xffffffff
\tinet6 fc00:bbbb:bbbb:bb01::c:7 prefixlen 128
utun5: flags=8010<POINTOPOINT,MULTICAST> mtu 1420
\tinet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff
"""

IP_ADDR = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host \\       valid_lft forever preferred_lft forever
3: wlan0    inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0\\       valid_lft 85000sec
3: wlan0    inet6 fe80::a00:27ff:fe4e:66a1/64 scope link \\       valid_lft forever preferred_lft forever
5: wg0    inet 10.66.0.2/32 scope global wg0\\       valid_lft forever preferred_lft forever
6: tun0    inet 10.8.0.6/24 scope global tun0\\       valid_lft forever preferred_lft forever
"""
IP_LINK = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DORMANT
5: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT
6: tun0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT
"""

LSOF = """COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Google\\x20Chrome 812 me   21u  IPv4 0x1      0t0  TCP 10.64.12.7:50111->142.250.185.78:443 (ESTABLISHED)
Spotify   1203 me   80u  IPv4 0x2      0t0  TCP 192.168.1.23:50200->35.186.224.47:443 (ESTABLISHED)
Spotify   1203 me   81u  IPv4 0x3      0t0  TCP 192.168.1.23:50201->192.168.1.1:80 (ESTABLISHED)
Dropbox   1377 me   30u  IPv6 0x4      0t0  TCP [2a02:587:d4a1:c00::23]:50300->[2620:100:6017:14::a27d:20e]:443 (ESTABLISHED)
Slack      944 me   40u  IPv4 0x5      0t0  TCP *:5000 (LISTEN)
Mail       655 me   41u  IPv4 0x6      0t0  TCP 10.64.12.7:50400->17.42.251.41:993 (CLOSE_WAIT)
openvpn    402 me    5u  IPv4 0x7      0t0  UDP 192.168.1.23:61000->185.65.134.77:1194
"""


def test_parse_ifconfig_and_vpn_ifaces():
    ifs = vg.parse_ifconfig(IFCONFIG)
    assert ifs["en0"]["v4"] == ["192.168.1.23"] and ifs["en0"]["up"]
    assert not ifs["en5"]["up"] and not ifs["utun5"]["up"]
    assert "fe80::1c2b:3a4f:9e10:7d21" in ifs["en0"]["v6"]
    # utun0/1 έχουν μόνο fe80 (συστήματος), utun5 είναι κάτω
    assert vg.vpn_ifaces(ifs) == ["utun4"]
    assert vg.usable_ips(ifs["utun4"]) == ["10.64.12.7", "fc00:bbbb:bbbb:bb01::c:7"]
    assert vg.usable_ips(ifs["en0"]) == ["192.168.1.23", "2a02:587:d4a1:c00::23"]
    assert vg.physical_iface(ifs, "utun4") == "en0"
    assert vg.physical_iface(ifs, "en0") == "en0"


def test_parse_ip_addr_linux():
    ifs = vg.parse_ip_addr(IP_ADDR, IP_LINK)
    assert ifs["wlan0"]["v4"] == ["192.168.1.50"] and ifs["wg0"]["up"]
    assert not ifs["tun0"]["up"]
    assert vg.vpn_ifaces(ifs) == ["wg0"]
    assert vg.physical_iface(ifs, "wg0") == "wlan0"
    assert vg.parse_ip_addr(IP_ADDR)["tun0"]["up"]  # χωρίς ip link: διεύθυνση ⇒ ενεργό


def test_mode_detection():
    assert vg.detect_mode("utun4", ["utun4"]) == "full"
    assert vg.detect_mode("en0", ["utun4"]) == "split"
    assert vg.detect_mode("en0", []) == "off"
    assert vg.detect_mode(None, []) == "off"
    assert vg.detect_mode("wg0", ["wg0"]) == "full"


def test_parse_lsof_local_and_classify():
    conns = vg.parse_lsof_local(LSOF)
    apps = {c["app"] for c in conns}
    assert "Google Chrome" in apps and "Slack" not in apps and "Mail" not in apps  # LISTEN / CLOSE_WAIT έξω
    d = next(c for c in conns if c["app"] == "Dropbox")
    assert d["lip"] == "2a02:587:d4a1:c00::23" and d["ip"] == "2620:100:6017:14::a27d:20e"
    res = {a["name"]: a for a in vg.classify(conns, ["10.64.12.7"], ["192.168.1.23", "2a02:587:d4a1:c00::23"])}
    assert res["Google Chrome"]["via_vpn"] == 1 and res["Google Chrome"]["outside"] == 0
    assert res["Spotify"]["outside"] == 1 and res["Spotify"]["sample"] == "35.186.224.47:443"  # LAN 192.168.1.1 δεν μετρά
    assert res["Dropbox"]["outside"] == 1 and res["Dropbox"]["sample"].startswith("[2620:")
    assert res["openvpn"]["vpn_client"] and not res["Spotify"]["vpn_client"]
    assert set(vg.leaking_apps(conns, ["192.168.1.23", "2a02:587:d4a1:c00::23"])) == {"Spotify", "Dropbox"}


# ── μηχανή καταστάσεων με ψεύτικο ρολόι ──
class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class St:
    def __init__(self):
        self.alerts = []
        self.cd = {}

    def alert(self, typ, sev, actor, target, detail, t, key=None, cooldown=None, **kw):
        k = (typ, key or actor)
        if k in self.cd and t - self.cd[k] < (cooldown or 60):
            return
        self.cd[k] = t
        self.alerts.append((typ, sev, actor, target))


PHYS = {"up": True, "v4": ["192.168.1.23"], "v6": []}
TUN = {"up": True, "v4": ["10.64.12.7"], "v6": []}


def mk(world):
    def snap():
        ifs = {"en0": PHYS}
        if world["vpn"]:
            ifs["utun4"] = TUN
        eg = "utun4" if world["vpn"] and world["full"] else "en0"
        return {"ifaces": ifs, "default": eg, "egress": eg}
    return snap, (lambda: [dict(c) for c in world["conns"]])


def C(app, lip, ip, port=443, pid=1):
    return {"app": app, "pid": pid, "proto": "TCP", "lip": lip, "ip": ip, "port": port}


def make(conns=None, vpn=True, full=True):
    world = {"vpn": vpn, "full": full, "conns": conns or []}
    snap, lister = mk(world)
    clk, st = Clock(), St()
    g = vg.VpnGuard(st, {}, snapshot=snap, lister=lister, clock=clk)
    return g, world, clk, st


def test_killswitch_fail_on_drop():
    g, w, clk, st = make([C("Google Chrome", "10.64.12.7", "142.250.185.78")])
    g.tick()
    assert g.mode == "full" and g.events[-1]["kind"] == "up"
    clk.t += 5
    w["vpn"], w["conns"] = False, [C("Google Chrome", "192.168.1.23", "142.250.185.78"),
                                   C("openvpn", "192.168.1.23", "185.65.134.77", 1194),
                                   C("Sonos", "192.168.1.23", "192.168.1.40", 1400)]
    g.tick()
    assert g.mode == "off" and g.status()["killswitch"]["watching"]
    assert any(e["kind"] == "down" for e in g.events)
    for _ in range(6):
        clk.t += 5
        g.tick()
    ks = g.status()["killswitch"]
    assert not ks["watching"] and ks["last"]["verdict"] == "fail"
    assert [a["name"] for a in ks["last"]["apps"]] == ["Google Chrome"]  # όχι ο πελάτης VPN, όχι LAN
    assert [a[0] for a in st.alerts] == ["Χωρίς kill-switch: κίνηση εκτός VPN"] and st.alerts[0][1] == "med"


def test_killswitch_pass_when_no_traffic():
    g, w, clk, st = make()
    g.tick()
    clk.t += 5
    w["vpn"], w["conns"] = False, []
    g.tick()
    clk.t += 31
    g.tick()
    last = g.status()["killswitch"]["last"]
    assert last["verdict"] == "pass" and last["apps"] == [] and not st.alerts
    assert "kill-switch OK" in g.events[-1]["text"]


def test_arm_no_drop_and_armed_drop():
    g, w, clk, st = make()
    g.tick()
    r = g.arm(20)
    assert r["ok"] and g.status()["killswitch"]["armed"]
    clk.t += 25
    g.tick()
    s = g.status()["killswitch"]
    assert not s["armed"] and s["last"]["verdict"] == "no-drop"
    # οπλισμένη δοκιμή με πτώση
    g.arm(60)
    clk.t += 5
    w["vpn"], w["conns"] = False, [C("Safari", "192.168.1.23", "17.253.144.10", pid=7)]
    g.tick()
    assert not g.status()["killswitch"]["armed"]
    clk.t += 30
    g.tick()
    last = g.status()["killswitch"]["last"]
    assert last["verdict"] == "fail" and last["armed"] and last["apps"][0]["name"] == "Safari"
    # με VPN κάτω δεν οπλίζεται
    assert not g.arm(60)["ok"]


def test_split_vs_full_alerting():
    conns = [C("Spotify", "192.168.1.23", "35.186.224.47", pid=5), C("Chrome", "10.64.12.7", "142.250.185.78"),
             C("WireGuard", "192.168.1.23", "185.65.134.77", 51820)]
    g, w, clk, st = make(conns, full=False)
    g.tick()
    s = g.status()
    assert s["mode"] == "split" and not st.alerts
    sp = next(a for a in s["apps"] if a["name"] == "Spotify")
    assert sp["outside"] == 1 and not sp["leak"]
    # full tunnel: διαρροή, μία φορά ανά ώρα
    w["full"] = True
    clk.t += 5
    g.tick()
    clk.t += 5
    g.tick()
    assert st.alerts == [("Εφαρμογή εκτός VPN", "low", "Spotify", "35.186.224.47:443")]
    assert next(a for a in g.status()["apps"] if a["name"] == "Spotify")["leak"]
    assert any(e["kind"] == "mode" for e in g.events)
    clk.t += 3601
    g.tick()
    assert len(st.alerts) == 2


def test_sim_shape_and_demo_test():
    clk = Clock()
    st = St()
    g = vg.VpnGuard(st, {}, sim=True, clock=clk)
    g.tick()
    s = g.status()
    json.dumps(s)
    for k in ("enabled", "demo", "error", "mode", "vpn", "physical", "default_iface", "events", "killswitch", "apps", "note"):
        assert k in s
    assert s["demo"] and s["mode"] == "full" and s["vpn"]["iface"] == "utun4" and s["physical"]["iface"] == "en0"
    outside = {a["name"] for a in s["apps"] if a["leak"]}
    assert outside == {"Spotify", "Dropbox"}
    assert s["killswitch"]["last"]["verdict"] == "fail" and s["killswitch"]["last"]["apps"][0]["name"] == "Google Chrome"
    assert any(e["kind"] == "down" for e in s["events"])
    # η δοκιμή στο demo «ρίχνει» το VPN και καταλήγει σε αποτυχία
    assert g.arm(60)["ok"]
    for _ in range(12):
        clk.t += 5
        g.tick()
    last = g.status()["killswitch"]["last"]
    assert last["armed"] and last["verdict"] == "fail" and g.mode == "full"
