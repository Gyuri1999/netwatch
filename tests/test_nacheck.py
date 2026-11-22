"""Tests για 802.1X & απομόνωση guest (nacheck.py). Ψεύτικο δίκτυο — κανένα πραγματικό πακέτο, καμία σύνδεση."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import nacheck as n  # noqa: E402

ME_MAC, SW_MAC = "9e:4a:5e:6a:f5:8b", "00:1b:54:aa:10:02"
ME, GW = "192.168.50.23", "192.168.50.1"


# ───────── EAPOL / EAP ─────────
def test_eapol_start_bytes():
    f = n.eapol_start(ME_MAC)
    # dst = PAE group address, ethertype 888E, version 1, type 1 (Start), body length 0  (IEEE 802.1X §11.3)
    assert f == bytes.fromhex("0180c2000003" + "9e4a5e6af58b" + "888e" + "01" + "01" + "0000")
    e = n.parse_eapol(f)
    assert e["dst"] == n.PAE and e["src"] == ME_MAC and e["version"] == 1 and e["ptype"] == 1 and e["ptype_name"] == "EAPOL-Start" and e["eap"] is None
    assert n.eapol_start(ME_MAC, version=2)[14] == 2


def test_eap_packet_layout_rfc3748():
    # Request/Identity id 7: code 1, id 7, length 5, type 1
    assert n.eap_packet(1, 7, 1) == bytes([1, 7, 0, 5, 1])
    assert n.eap_packet(3, 9) == bytes([3, 9, 0, 4])                     # Success: χωρίς type/data
    f = n.eap_identity_response(ME_MAC, 7, "anonymous")
    eap = b"\x02\x07\x00\x0e\x01anonymous"                              # Response, id 7, length 14, Identity
    assert f[12:14] == b"\x88\x8e" and f[14:18] == bytes([1, 0, 0, len(eap)]) and f[18:] == eap
    e = n.parse_eapol(f)
    assert e["ptype_name"] == "EAP-Packet" and e["eap"]["code_name"] == "Response" and e["eap"]["type_name"] == "Identity"
    assert e["eap"]["id"] == 7 and e["eap"]["text"] == "anonymous" and e["eap"]["len"] == 14


def req(typ, ident=1, src=SW_MAC, data=b"", version=2, vlan=None):
    f = n.eapol_frame(src, 0, n.eap_packet(1, ident, typ, data), version=version, dst=ME_MAC)
    if vlan is not None:
        f = f[:12] + bytes([0x81, 0x00, vlan >> 8, vlan & 255]) + f[12:]
    return f + bytes(60 - len(f)) if len(f) < 60 else f                  # padding Ethernet


def test_parse_eapol_requests_methods_vlan_and_garbage():
    e = n.parse_eapol(req(1, 5, data=b"\x00networkid=corp,nasid=sw1,portid=3"))
    assert e["src"] == SW_MAC and e["version"] == 2 and e["eap"]["code"] == 1 and e["eap"]["type"] == 1 and e["eap"]["id"] == 5
    assert e["eap"]["text"] == ""                                        # κείμενο μετά από NUL δεν εμφανίζεται
    assert n.parse_eapol(req(25))["eap"]["type_name"] == "PEAP" and n.parse_eapol(req(13))["eap"]["type_name"] == "EAP-TLS"
    assert n.parse_eapol(req(21))["eap"]["type_name"] == "EAP-TTLS" and n.parse_eapol(req(199))["eap"]["type_name"] == "type 199"
    assert n.parse_eapol(req(1, vlan=120))["eap"]["type"] == 1
    fail = n.parse_eapol(n.eapol_frame(SW_MAC, 0, n.eap_packet(4, 3)))
    assert fail["eap"]["code_name"] == "Failure" and fail["eap"]["type"] is None
    assert n.parse_eapol(n.eapol_frame(SW_MAC, 3, b"\x02" * 95))["ptype_name"] == "EAPOL-Key"
    for bad in (b"", None, b"\x00" * 13, b"\xff" * 64, req(1)[:17], bytes(12) + b"\x08\x00" + bytes(40), "text"):
        assert n.parse_eapol(bad) is None
    for k in range(len(req(25))):
        n.parse_eapol(req(25)[:k])                                       # ποτέ εξαίρεση


def test_frames_match_scapy_dissection():
    """Ανεξάρτητος έλεγχος της διάταξης: το scapy διαβάζει τα πλαίσιά μας όπως τα εννοούμε."""
    sc = pytest.importorskip("scapy.all")
    from scapy.layers.eap import EAP, EAPOL
    p = sc.Ether(n.eapol_start(ME_MAC))
    assert p.dst == n.PAE and p.type == 0x888E and p[EAPOL].version == 1 and p[EAPOL].type == 1 and p[EAPOL].len == 0
    p = sc.Ether(n.eap_identity_response(ME_MAC, 7, "anonymous"))
    assert p[EAPOL].type == 0 and p[EAP].code == 2 and p[EAP].id == 7 and p[EAP].type == 1 and p[EAP].identity == b"anonymous"
    theirs = bytes(sc.Ether(src=SW_MAC, dst=ME_MAC) / EAPOL(version=2, type=0) / EAP(code=1, id=9, type=25))
    e = n.parse_eapol(theirs)
    assert e["version"] == 2 and e["eap"]["code"] == 1 and e["eap"]["id"] == 9 and e["eap"]["type_name"] == "PEAP"


# ───────── ψεύτικο δίκτυο ─────────
class FakeNet:
    def __init__(self, frames=(), boom=None, loc=None, arp=None, alive=(), open_ports=(), dns=True, inet=True, portal=False, wifi=None):
        self.frames, self.boom = list(frames), boom
        self.loc = loc if loc is not None else {"ip": ME, "prefix": 24, "gw": GW, "iface": "en0"}
        self.arp = arp if arp is not None else {GW: "a4:2b:b0:11:22:33"}
        self.alive, self.open_ports = set(alive), set(open_ports)
        self.dns_ok, self.inet_ok, self.portal, self.wifi_info = dns, inet, portal, wifi
        self.calls = []

    def eapol(self, iface, timeout=5.0, identity=None):
        self.calls.append(("eapol", iface, identity))
        if self.boom:
            raise self.boom
        return self.frames

    def local(self):
        return self.loc

    def arp_cache(self):
        return dict(self.arp)

    def ping(self, ip, timeout=1.0):
        self.calls.append(("ping", ip))
        return ip in self.alive

    def tcp(self, ip, port, timeout=1.0):
        self.calls.append(("tcp", ip, port))
        return (ip, port) in self.open_ports

    def dns(self, name="example.com"):
        return self.dns_ok

    def internet(self):
        return self.inet_ok

    def captive(self):
        return {"ok": not self.portal}

    def wifi(self):
        return self.wifi_info


class State:
    gateway, iface = GW, "en0"

    def __init__(self, me=(ME,), hosts=()):
        self.me = set(me)
        self.hosts = {ip: {"ip": ip, "kind": "local", "names": set(), "last": 100 + i} for i, ip in enumerate(hosts)}
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, detail, kw))


def rule(entry, rid):
    return next(r for r in entry["rules"] if r["id"] == rid)


# ───────── 802.1X ─────────
def test_dot1x_required_with_and_without_ip():
    c = n.NacCheck(State(me=()), net=FakeNet(frames=[req(1, 1)], loc={"ip": None, "gw": None}), clock=lambda: 50.0)
    r = c.run_dot1x()
    assert r["status"] == "required" and r["have_ip"] is False and SW_MAC in r["el"] and r["method"] is None and r["t"] == 50.0
    assert r["frames"] == [{"src": SW_MAC, "ptype_name": "EAP-Packet", "version": 2, "eap": "Request Identity (id 1)"}]
    assert c.net.calls == [("eapol", "en0", None)]
    c = n.NacCheck(State(), net=FakeNet(frames=[req(1, 1), req(1, 1), req(25, 2), b"junk"]))
    r = c.run_dot1x("anonymous")
    assert r["status"] == "required" and r["have_ip"] and r["method"] == "PEAP" and "MAB" in r["el"] and "PEAP" in r["en"] and r["identity_sent"]
    assert c.view()["dot1x"]["status"] == "required"


def test_dot1x_no_authenticator_bypass_failure_and_permission():
    r = n.NacCheck(State(), net=FakeNet(frames=[n.eapol_start("02:00:00:00:00:99")])).run_dot1x()      # ξένο Start δεν μετρά
    assert r["status"] == "none" and "ΔΕΝ ζητά 802.1X" in r["el"] and "MAB" in r["el"] and r["frames"] == []
    r = n.NacCheck(State(me=()), net=FakeNet(loc={"ip": "169.254.3.4"})).run_dot1x()
    assert r["status"] == "none" and not r["have_ip"] and "no IP" in r["en"]
    r = n.NacCheck(State(), net=FakeNet(frames=[n.eapol_frame(SW_MAC, 0, n.eap_packet(3, 1))])).run_dot1x()
    assert r["status"] == "bypass" and "EAP-Success" in r["el"]
    r = n.NacCheck(State(), net=FakeNet(frames=[n.eapol_frame(SW_MAC, 0, n.eap_packet(4, 1))])).run_dot1x()
    assert r["status"] == "required" and "EAP-Failure" in r["el"]
    r = n.NacCheck(State(), net=FakeNet(boom=PermissionError("Operation not permitted"))).run_dot1x()
    assert r["status"] == "err" and "root" in r["el"] and "root" in r["en"]
    assert "boom-x" in n.NacCheck(State(), net=FakeNet(boom=RuntimeError("boom-x"))).run_dot1x()["el"]


# ───────── Wi‑Fi ─────────
def test_wifi_class():
    k = lambda s: n.wifi_class(s)  # noqa: E731
    assert k("wpa2_enterprise")["kind"] == "enterprise" and k("wpa3_enterprise")["pmf"] == "required" and k("wpa2-enterprise")["level"] == "ok"
    assert k("wpa2_personal")["kind"] == "psk" and k("wpa2_personal")["pmf"] == "unknown" and not k("wpa2_personal")["wpa3"]
    w3 = k("wpa3_personal")
    assert w3["kind"] == "psk" and w3["wpa3"] and w3["pmf"] == "required" and not w3["transition"] and w3["level"] == "ok"
    tr = k("wpa3_transition")
    assert tr["wpa3"] and tr["transition"] and tr["pmf"] == "optional"
    assert k("none")["kind"] == "open" and k("none")["level"] == "bad" and k("wep")["kind"] == "wep" and k("owe")["pmf"] == "required"
    assert k("")["kind"] == "unknown" and k(None)["kind"] == "unknown" and k("wpa_personal")["level"] == "warn"


def test_run_wifi_uses_os_helper_result():
    c = n.NacCheck(State(), net=FakeNet(wifi={"ssid": "Cafe-Guest", "security": "wpa2_personal", "channel": "44 (5GHz, 80MHz)", "signal": -58}), clock=lambda: 9.0)
    w = c.run_wifi()
    assert w["ssid"] == "Cafe-Guest" and w["kind"] == "psk" and w["signal"] == -58 and w["t"] == 9.0
    assert n.NacCheck(State(), net=FakeNet(wifi=None)).run_wifi()["kind"] == "none"
    assert n.NacCheck(State(), net=FakeNet(wifi={"ssid": "<redacted>", "security": "wpa3_personal"})).run_wifi()["ssid"] == ""


# ───────── απομόνωση ─────────
def test_isolation_pass():
    st = State(hosts=["192.168.50.31", "192.168.50.44", "192.168.1.99", GW, ME])
    net = FakeNet(portal=False)
    c = n.NacCheck(st, net=net, clock=lambda: 1000.0)
    e = c.run_isolation()
    assert e["verdict"] == "ok" and e["iso"] is True and e["net"]["cidr"] == "192.168.50.0/24" and e["key"] == f"{GW}|192.168.50.0/24"
    assert [r["status"] for r in e["rules"]] == ["pass", "pass", "pass", "pass", "pass", "info"]
    assert [r["id"] for r in e["rules"]] == ["clients", "gw_mgmt", "internal", "dns", "internet", "captive"]
    probed = {c2[1] for c2 in net.calls if c2[0] in ("ping", "tcp")}
    assert {"192.168.50.31", "192.168.50.44"} <= probed and "192.168.1.99" not in probed          # άλλο subnet ≠ «άλλος πελάτης»
    assert ME not in probed and all(n.private4(ip) for ip in probed)
    assert {c2[2] for c2 in net.calls if c2[0] == "tcp" and c2[1] == GW} == set(n.GW_PORTS)
    assert "192.168.1.1" in probed and "10.0.0.1" in probed and e["probes"] <= n.MAX_PROBES and e["probes"] == len([x for x in net.calls if x[0] in ("ping", "tcp")])
    assert st.alerts == [] and c.view()["last"]["t"] == 1000.0


def test_isolation_failures_per_rule():
    st = State(hosts=["192.168.50.31"])
    net = FakeNet(alive={"192.168.50.31", "192.168.1.1"}, open_ports={("192.168.50.31", 445), (GW, 443), (GW, 8291), ("192.168.1.1", 80), ("10.0.0.5", 3389)},
                  arp={GW: "a4:2b:b0:11:22:33", "192.168.50.31": "3c:22:fb:70:01:9d"})
    c = n.NacCheck(st, net=net)
    c.api("POST", "config", {}, {"targets": "10.0.0.5:3389, 172.16.9.9"})
    e = c.run_isolation()
    assert e["verdict"] == "fail" and e["iso"] is False
    cl = rule(e, "clients")
    assert cl["status"] == "fail" and cl["found"] == [{"ip": "192.168.50.31", "ping": True, "ports": [445], "arp": "3c:22:fb:70:01:9d"}] and "445/SMB" in cl["el"]
    gm = rule(e, "gw_mgmt")
    assert gm["status"] == "fail" and gm["found"] == [{"ip": GW, "ports": [443, 8291]}] and "8291/Winbox" in gm["el"]
    it = rule(e, "internal")
    assert it["status"] == "fail" and {(f["ip"], f["user"]) for f in it["found"]} == {("192.168.1.1", False), ("10.0.0.5", True)}
    assert ("tcp", "10.0.0.5", 3389) in net.calls and ("tcp", "10.0.0.5", 80) not in net.calls and ("ping", "172.16.9.9") in net.calls
    assert st.alerts == []                                               # πρώτη φορά: δεν υπήρχε «πριν περνούσε»


def test_isolation_arp_only_untested_portal_and_no_dns():
    net = FakeNet(arp={GW: "a4:2b:b0:11:22:33", "192.168.50.60": "aa:bb:cc:00:00:60", "224.0.0.251": "01:00:5e:00:00:fb", "8.8.8.8": "aa:aa:aa:aa:aa:aa"})
    e = n.NacCheck(State(), net=net).run_isolation()
    assert rule(e, "clients")["status"] == "warn" and e["verdict"] == "warn" and e["iso"] is True
    assert "8.8.8.8" not in {c2[1] for c2 in net.calls if c2[0] in ("ping", "tcp")}
    net = FakeNet(open_ports={(GW, 80), (GW, 443)}, portal=True, inet=False)
    e = n.NacCheck(State(), net=net).run_isolation()
    assert rule(e, "clients")["status"] == "untested" and "δεύτερο" in rule(e, "clients")["el"]
    assert rule(e, "gw_mgmt")["status"] == "warn" and rule(e, "internet")["status"] == "warn" and rule(e, "captive")["el"].startswith("Υπάρχει")
    assert e["verdict"] == "warn"
    assert any(c2[0] == "ping" and c2[1] in ("192.168.50.22", "192.168.50.24") for c2 in net.calls)      # γείτονες γύρω μου
    e = n.NacCheck(State(hosts=["192.168.50.31"]), net=FakeNet(dns=False)).run_isolation()
    assert rule(e, "dns")["status"] == "fail" and e["verdict"] == "warn" and e["iso"] is True
    # χωρίς ιδιωτική IP δεν τρέχει τίποτα
    net = FakeNet(loc={"ip": "85.72.10.5", "prefix": 24, "gw": "85.72.10.1"})
    c = n.NacCheck(State(me=()), net=net)
    assert "error" in c.run_isolation() and not [x for x in net.calls if x[0] in ("ping", "tcp")] and c.view()["problem"]["en"] and "error" not in c.view()


def test_public_targets_are_refused_everywhere():
    for bad in ("8.8.8.8", "8.8.8.8:53", "1.1.1.1:443", "example.com", "127.0.0.1", "169.254.1.1", "fd00::1", "10.0.0.1:99999", "10.0.0.1:x", "172.32.0.1", ""):
        with pytest.raises(ValueError):
            n.parse_target(bad)
    assert n.parse_target("10.0.0.5:445") == ("10.0.0.5", 445) and n.parse_target(" 172.31.255.1 ") == ("172.31.255.1", None)
    assert not n.private4("172.32.0.1") and not n.private4("::1") and n.private4("192.168.0.1")
    c = n.NacCheck(State(), net=FakeNet())
    code, r = c.api("POST", "config", {}, {"targets": ["10.0.0.5:445", "8.8.8.8:53"]})
    assert code == 400 and "ιδιωτικές" in r["error"] and c.cfg["targets"] == []
    assert c.api("POST", "config", {}, {"peers": ["192.168.50.40:80"]})[0] == 400
    assert c.api("POST", "config", {}, {"targets": ["10.0.0.%d" % i for i in range(2, 30)]})[0] == 400
    # ακόμα κι αν μπει δημόσια διεύθυνση στο αρχείο με το χέρι, δεν δοκιμάζεται ποτέ
    c.cfg["targets"] = ["8.8.4.4:53", "10.0.0.5:445"]
    c.cfg["peers"] = ["9.9.9.9"]
    c.run_isolation()
    ips = {x[1] for x in c.net.calls if x[0] in ("ping", "tcp")}
    assert "8.8.4.4" not in ips and "9.9.9.9" not in ips and "10.0.0.5" in ips and all(n.private4(i) for i in ips)
    real = n.Net()
    assert real.tcp("8.8.8.8", 53) is False and real.ping("8.8.8.8") is False       # η πραγματική κλάση αρνείται πριν ανοίξει socket


def test_probe_cap_on_huge_network():
    st = State(hosts=["10.0.%d.%d" % (i // 250, i % 250 + 2) for i in range(600)], me=("10.0.0.1",))
    net = FakeNet(loc={"ip": "10.0.0.1", "prefix": 8, "gw": "10.255.255.254", "iface": "en0"})
    c = n.NacCheck(st, net=net)
    c.cfg["targets"] = ["10.9.9.%d" % i for i in range(1, 60)]
    e = c.run_isolation()
    calls = [x for x in net.calls if x[0] in ("ping", "tcp")]
    assert len(calls) <= n.MAX_PROBES and len({x[1] for x in calls if x[1].startswith("10.0.")}) <= n.MAX_PEERS + 2 and e["probes"] == len(calls)


def test_regression_alert_only_after_a_pass_and_history_cap(tmp_path):
    st = State(hosts=["192.168.50.31"])
    net = FakeNet()
    now = [1000.0]
    c = n.NacCheck(st, str(tmp_path), net=net, clock=lambda: now[0])
    assert c.run_isolation()["iso"] is True
    net.alive = {"192.168.50.31"}
    now[0] += 3600
    e = c.run_isolation()
    assert e["iso"] is False and len(st.alerts) == 1
    typ, sev, actor, target, detail, kw = st.alerts[0]
    assert typ == "Χάλασε η απομόνωση του guest Wi-Fi" and sev == "high" and actor == ME and target == GW and "192.168.50.0/24" in detail and "192.168.50.31" in detail
    assert c.view()["regressed"] is True
    now[0] += 3600
    c.run_isolation()                                                    # συνεχίζει χαλασμένο → όχι νέα ειδοποίηση
    assert len(st.alerts) == 1 and c.view()["regressed"] is False
    # άλλο δίκτυο που αποτυγχάνει χωρίς προηγούμενη επιτυχία → όχι ειδοποίηση
    net.loc = {"ip": "10.20.0.7", "prefix": 24, "gw": "10.20.0.1", "iface": "en0"}
    net.open_ports = {("10.20.0.1", 22)}
    c.run_isolation()
    assert len(st.alerts) == 1
    for i in range(30):
        now[0] += 60
        c.run_isolation()
    assert len(c.history) == n.HISTORY and c.history[0]["t"] == now[0] and c.history[0]["t"] > c.history[-1]["t"]
    # αποθηκεύτηκε και ξαναφορτώνεται
    c2 = n.NacCheck(State(), str(tmp_path), net=FakeNet())
    assert len(c2.history) == n.HISTORY and c2.history[0]["key"] == "10.20.0.1|10.20.0.0/24"
    assert not [f for f in os.listdir(str(tmp_path)) if f.endswith(".tmp")]
    assert c2.api("POST", "clear", {}, {})[1]["history"] == [] and n.NacCheck(State(), str(tmp_path), net=FakeNet()).history == []


def test_config_persist_and_api_shapes(tmp_path):
    saved = []
    c = n.NacCheck(State(), str(tmp_path), net=FakeNet())
    c.on_save = saved.append
    code, v = c.api("POST", "config", {}, {"targets": "10.0.0.5:445\n192.168.1.10", "peers": ["192.168.50.40"], "every_min": 5})
    assert code == 200 and v["config"] == {"targets": ["10.0.0.5:445", "192.168.1.10"], "peers": ["192.168.50.40"], "every_min": 15} and saved
    c2 = n.NacCheck(State(), str(tmp_path), net=FakeNet())
    assert c2.cfg == v["config"]
    assert c2.api("GET", "", {}, {}) == (200, c2.view()) and c2.api("GET", "x", {}, {})[0] == 404 and c2.api("POST", "x", {}, {})[0] == 404
    v = c2.view()
    json.dumps(v)
    assert v["demo"] is False and v["busy"] is None and v["last"] is None and "GUEST-IN" in v["fix"]["cisco"] and "rfc1918" in v["fix"]["mikrotik"]
    code, v = c2.api("POST", "isolation", {}, {})
    assert code == 200 and v["busy"] == "isolation"
    for _ in range(200):
        if not c2.busy:
            break
        __import__("time").sleep(0.01)
    assert c2.busy is None and c2.view()["last"]["verdict"] in ("ok", "warn")


def test_fix_config_uses_the_guest_subnet():
    f = n.fix_config("10.20.0.0/22", "10.20.0.1")
    assert "permit udp 10.20.0.0 0.0.3.255 host 10.20.0.1 eq domain" in f["cisco"] and "deny   ip any 192.168.0.0 0.0.255.255" in f["cisco"]
    assert "src-address=10.20.0.0/22" in f["mikrotik"] and "client-isolation=yes" in f["mikrotik"] and "switchport protected" in f["cisco"]
    assert "no internal networks" in n.fix_config("10.20.0.0/22", "10.20.0.1", "en")["cisco"]
    assert n.fix_config("garbage", "8.8.8.8")["gw"] == "192.168.50.1"


def test_demo():
    c = n.NacCheck(None, demo=True, clock=lambda: 1_700_000_000.0)
    v = c.view()
    json.dumps(v)
    assert v["demo"] and [h["verdict"] for h in v["history"]] == ["fail", "ok"] and v["regressed"] is True
    assert v["last"]["iso"] is False and [r["status"] for r in v["last"]["rules"][:3]] == ["fail", "fail", "fail"]
    assert v["dot1x"]["status"] == "required" and v["dot1x"]["method"] == "PEAP" and v["wifi"]["kind"] == "psk" and v["wifi"]["ssid"] == "Cafe-Guest"
    assert "192.168.50.0 0.0.0.255" in v["fix"]["cisco"]
    for sub in ("dot1x", "isolation", "wifi", "clear"):
        code, v2 = c.api("POST", sub, {}, {})
        assert code == 200 and v2["busy"] is None and len(v2["history"]) == 2          # το demo δεν αγγίζει το δίκτυο
    assert c.api("POST", "config", {}, {"targets": ["10.1.1.1"]})[1]["config"]["targets"] == ["192.168.1.10:445", "10.0.0.5:3389"]
