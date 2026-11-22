import importlib.util
import json
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import fieldbox as fb  # noqa: E402


# ───────────── κατασκευή πλαισίων με το χέρι (IEEE 802.1AB: 7 bit τύπος, 9 bit μήκος) ─────────────
def tlv(t, v):
    return struct.pack(">H", (t << 9) | len(v)) + v


def org(oui, sub, v):
    return tlv(127, oui + bytes([sub]) + v)


D1, D3, MED = b"\x00\x80\xc2", b"\x00\x12\x0f", b"\x00\x12\xbb"
CHASSIS = tlv(1, b"\x04" + bytes.fromhex("001b54aa1000"))
PORT = tlv(2, b"\x05Gi1/0/14")
TTL = tlv(3, b"\x00\x78")
END = tlv(0, b"")


def lldpdu(*extra, chassis=CHASSIS, port=PORT):
    return chassis + port + TTL + b"".join(extra) + END


def eth(payload, dst="0180c200000e", src="001b54aa100e", et=0x88CC, tags=()):
    h = bytes.fromhex(dst) + bytes.fromhex(src)
    for vid in tags:
        h += struct.pack(">HH", 0x8100, vid)
    return h + struct.pack(">H", et) + payload


FULL = lldpdu(
    tlv(4, b"Office socket 14"), tlv(5, b"SW-OFFICE-1"), tlv(6, b"Cisco IOS Software, C2960X"),
    tlv(7, b"\x00\x14\x00\x04"),
    tlv(8, b"\x05\x01" + bytes([10, 99, 0, 11]) + b"\x02" + struct.pack(">I", 14) + b"\x00"),
    org(D1, 1, struct.pack(">H", 20)),
    org(D1, 3, struct.pack(">H", 20) + b"\x06OFFICE"),
    org(D1, 7, b"\x03" + struct.pack(">I", 9)),
    org(D3, 1, b"\x03\x6c\x01\x00\x1e"),
    # Power via MDI: PSE + υποστήριξη + ενεργό (0x07), ζεύγη signal (1), class 3 (τιμή 4),
    # 802.3at: Type 2 PSE (00), requested 15.4 W (154), allocated 15.4 W (154)
    org(D3, 2, b"\x07\x01\x04\x03" + struct.pack(">HH", 154, 154)),
)


def test_lldp_full_frame():
    f = fb.parse_frame(eth(FULL))
    n = f["nbr"]
    assert f["vlans"] == [] and f["src"] == "00:1b:54:aa:10:0e"
    assert n["proto"] == "LLDP" and n["chassis"] == "00:1b:54:aa:10:00" and n["port"] == "Gi1/0/14" and n["ttl"] == 120
    assert n["name"] == "SW-OFFICE-1" and n["port_desc"] == "Office socket 14" and n["descr"].startswith("Cisco IOS")
    assert n["mgmt"] == "10.99.0.11" and n["pvid"] == 20 and n["vlans"] == {20: "OFFICE"}
    assert n["lag"] == {"capable": True, "enabled": True, "id": 9} and n["mau"] == 30
    assert n["poe"]["pse"] and n["poe"]["supported"] and n["poe"]["enabled"] and n["poe"]["class"] == 3
    assert n["poe"]["w"] == 15.4 and n["poe"]["src"] == "802.3at" and n["poe"]["type"] == "Type 2 PSE"
    assert "truncated" not in n


def test_lldp_matches_scapy_dissector():
    """Διασταύρωση με τον ανεξάρτητο αναλυτή του scapy (αν υπάρχει): ίδια πεδία από το ίδιο πλαίσιο."""
    if importlib.util.find_spec("scapy") is None:
        pytest.skip("χωρίς scapy")
    from scapy.contrib import lldp as sl
    from scapy.layers.l2 import Ether
    p = Ether(eth(FULL))
    assert p[sl.LLDPDUSystemName].system_name == b"SW-OFFICE-1"
    assert p[sl.LLDPDUPortID].id == b"Gi1/0/14" and p[sl.LLDPDUPortID].subtype == 5
    assert p[sl.LLDPDUManagementAddress].management_address == bytes([10, 99, 0, 11])
    assert p[sl.LLDPDUTimeToLive].ttl == 120
    orgs = [x for x in p.iterpayloads() if isinstance(x, sl.LLDPDUGenericOrganisationSpecific)]
    assert [(o.org_code, o.subtype) for o in orgs] == [(0x0080C2, 1), (0x0080C2, 3), (0x0080C2, 7), (0x00120F, 1), (0x00120F, 2)]


def test_lldp_med_power_and_mac_port_id():
    du = lldpdu(tlv(4, b"GigabitEthernet0/7"), tlv(5, b"sw2"),
                org(MED, 1, b"\x00\x3f\x04"),                        # MED capabilities, Network Connectivity
                org(MED, 4, b"\x01" + struct.pack(">H", 300)),       # PSE (00), primary source, 30.0 W
                org(MED, 2, b"\x01" + bytes([0x40, 0x50, 0x00])),    # Voice: tagged, VLAN 40
                port=tlv(2, b"\x03" + bytes.fromhex("001b54aa1007")))
    n = fb.parse_lldp(du)
    assert n["port"] == "00:1b:54:aa:10:07" and n["port_sub"] == 3 and fb._port_name(n) == "GigabitEthernet0/7"
    assert n["poe"]["w"] == 30.0 and n["poe"]["src"] == "MED" and n["med"] and n["voice_vlan"] == 40
    assert fb._poe(n) == {"on": True, "w": 30.0, "class": None, "src": "MED"}
    # MED από PD (π.χ. τηλέφωνο) δεν σημαίνει ότι το switch δίνει PoE
    n2 = fb.parse_lldp(lldpdu(org(MED, 4, b"\x51" + struct.pack(">H", 60))))
    assert n2["poe"].get("w") is None and fb._poe(n2)["on"] is False


def test_lldp_poe_without_at_extension_uses_class():
    n = fb.parse_lldp(lldpdu(org(D3, 2, b"\x07\x01\x05")))     # class 4, χωρίς πεδία 802.3at
    assert n["poe"]["class"] == 4 and "w" not in n["poe"]
    assert fb._poe(n) == {"on": True, "w": 30.0, "class": 4, "src": "class"}
    off = fb.parse_lldp(lldpdu(org(D3, 2, b"\x03\x01\x01")))   # PSE, υποστηρίζεται αλλά ΟΧΙ ενεργό
    assert fb._poe(off)["on"] is False and fb._poe(off)["w"] is None
    assert fb._poe(fb.parse_lldp(lldpdu()))["on"] is None


def test_lldp_truncated_and_malformed():
    cut = FULL[:len(CHASSIS) + len(PORT) + len(TTL) + 9]       # κόβεται στη μέση ενός TLV
    n = fb.parse_lldp(cut)
    assert n["truncated"] and n["port"] == "Gi1/0/14" and "name" not in n
    assert fb.parse_lldp(CHASSIS + END) is None                # χωρίς Port ID
    assert fb.parse_lldp(b"") is None and fb.parse_lldp(None) is None
    assert fb.parse_lldp(b"\xfe\x05\x00") is None              # org TLV που δηλώνει περισσότερα από όσα έχει
    # σκουπίδια και μη έγκυρες τιμές δεν σκάνε και δεν περνάνε
    junk = lldpdu(org(D1, 1, b"\x00"), org(D1, 1, struct.pack(">H", 4095)), org(D1, 3, b"\x00\x14\x40abc"),
                  org(D3, 2, b"\x07"), org(MED, 4, b"\x01"), tlv(8, b"\x09\x01\x0a"), org(b"\xaa\xbb\xcc", 9, b"x" * 40),
                  tlv(5, b"sw\x00\x1b[31m\xff\xfe"))
    n = fb.parse_lldp(junk)
    assert "pvid" not in n and "vlans" not in n and "poe" not in n and "mgmt" not in n
    assert "\x1b" not in n["name"] and "\x00" not in n["name"]
    for i in range(len(FULL)):                                  # κάθε δυνατό κόψιμο
        fb.parse_frame(eth(FULL)[:14 + i])
    assert fb.parse_frame(b"\x00" * 5) == {"src": "", "vlans": [], "nbr": None}


def test_lldp_tlv_count_is_capped():
    n = fb.parse_lldp(CHASSIS + PORT + tlv(5, b"a") * 500 + tlv(5, b"late"))
    assert n is not None and n["name"] == "a"


def ctlv(t, v):
    return struct.pack(">HH", t, len(v) + 4) + v


def cdp(*tlvs, ver=2):
    return bytes([ver, 180]) + b"\x00\x00" + b"".join(tlvs)


CDP_FULL = cdp(ctlv(1, b"SW-CORE.office.lan"),
               ctlv(2, struct.pack(">I", 1) + b"\x01\x01\xcc" + struct.pack(">H", 4) + bytes([10, 99, 0, 12])),
               ctlv(3, b"GigabitEthernet1/0/14"), ctlv(4, struct.pack(">I", 0x28)),
               ctlv(5, b"Cisco IOS Software, Version 15.2(7)E"), ctlv(6, b"cisco WS-C2960X-24PS-L"),
               ctlv(0x0A, struct.pack(">H", 20)), ctlv(0x0B, b"\x01"), ctlv(0x0E, b"\x01" + struct.pack(">H", 40)),
               ctlv(0x1A, struct.pack(">HHI", 1, 1, 15400) + struct.pack(">I", 0xFFFFFFFF)))


def cdp_frame(payload, tags=()):
    body = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + payload
    return eth(body, dst="01000ccccccc", et=len(body), tags=tags)


def test_cdp_full_frame():
    f = fb.parse_frame(cdp_frame(CDP_FULL))
    n = f["nbr"]
    assert n["proto"] == "CDP" and n["name"] == "SW-CORE.office.lan" and n["port"] == "GigabitEthernet1/0/14"
    assert n["platform"] == "cisco WS-C2960X-24PS-L" and n["pvid"] == 20 and n["duplex"] == "full" and n["voice_vlan"] == 40
    assert n["mgmt"] == "10.99.0.12" and n["poe"]["w"] == 15.4 and n["poe"]["src"] == "CDP" and n["ttl"] == 180


def test_cdp_matches_scapy_dissector():
    if importlib.util.find_spec("scapy") is None:
        pytest.skip("χωρίς scapy")
    from scapy.contrib import cdp as sc
    p = sc.CDPv2_HDR(CDP_FULL)
    assert p[sc.CDPMsgDeviceID].val == b"SW-CORE.office.lan" and p[sc.CDPMsgPortID].iface == b"GigabitEthernet1/0/14"
    assert p[sc.CDPMsgNativeVLAN].vlan == 20 and p[sc.CDPMsgPlatform].val == b"cisco WS-C2960X-24PS-L"
    assert p[sc.CDPMsgPowerAvailable].power_available_list[0] == 15400


def test_cdp_malformed_and_not_cdp():
    assert fb.parse_cdp(b"") is None and fb.parse_cdp(b"\x09\x00\x00\x00abcd") is None
    assert fb.parse_cdp(cdp(ctlv(1, b"x"))) is None                       # χωρίς Port ID
    bad = cdp(ctlv(1, b"sw"), ctlv(3, b"Gi0/1")) + struct.pack(">HH", 6, 2) + b"zz"   # μήκος < 4 → στοπ, όχι ατέρμονο
    n = fb.parse_cdp(bad)
    assert n["truncated"] and n["port"] == "Gi0/1"
    over = cdp(ctlv(1, b"sw"), ctlv(3, b"Gi0/1")) + struct.pack(">HH", 6, 400) + b"zz"
    assert fb.parse_cdp(over)["truncated"]
    for i in range(len(CDP_FULL)):
        fb.parse_cdp(CDP_FULL[:i])
    # VTP στην ίδια MAC (SNAP PID 0x2003) δεν είναι CDP
    body = b"\xaa\xaa\x03\x00\x00\x0c\x20\x03" + CDP_FULL
    assert fb.parse_frame(eth(body, dst="01000ccccccc", et=len(body)))["nbr"] is None


def test_vlan_tags_seen():
    f = fb.parse_frame(eth(b"\x45" + b"\x00" * 40, dst="ffffffffffff", et=0x0800, tags=(30,)))
    assert f["vlans"] == [30] and f["nbr"] is None
    assert fb.parse_frame(eth(b"\x00" * 40, et=0x0800, tags=(0,)))["vlans"] == []      # tag προτεραιότητας, όχι VLAN
    assert fb.parse_frame(eth(FULL, tags=(99,)))["nbr"]["name"] == "SW-OFFICE-1"
    assert fb.parse_frame(eth(b"\x00" * 40, et=0x0800, tags=(100, 200)))["vlans"] == [100, 200]   # QinQ


# ───────────── DHCP ─────────────
def opt(c, v):
    return bytes([c, len(v)]) + v


def bootp(options, yi=(10, 20, 0, 57), si=(0, 0, 0, 0), xid=0x1234ABCD):
    return (b"\x02\x01\x06\x00" + struct.pack(">I", xid) + b"\x00" * 8 + bytes(yi) + bytes(si) + b"\x00" * 4
            + b"\x00" * 16 + b"\x00" * 64 + b"\x00" * 128 + b"\x63\x82\x53\x63" + options)


OFFER = bootp(opt(53, b"\x02") + opt(54, bytes([10, 20, 0, 1])) + opt(51, struct.pack(">I", 28800))
              + opt(1, bytes([255, 255, 255, 0])) + opt(3, bytes([10, 20, 0, 1])) + opt(6, bytes([10, 20, 0, 1, 1, 1, 1, 1]))
              + opt(15, b"office.lan\x00") + opt(150, bytes([10, 40, 0, 5])) + opt(66, b"10.40.0.5")
              + opt(67, b"pxelinux.0") + opt(43, b"\xf1\x04\x0a\x00\x00\x02") + b"\xff")


def test_dhcp_offer_parsing():
    o = fb.parse_dhcp(OFFER)
    assert o["type"] == 2 and o["xid"] == 0x1234ABCD and o["offer"] == "10.20.0.57" and o["server"] == "10.20.0.1"
    assert o["mask"] == "255.255.255.0" and o["prefix"] == 24 and o["gw"] == "10.20.0.1" and o["dns"] == ["10.20.0.1", "1.1.1.1"]
    assert o["domain"] == "office.lan" and o["lease"] == 28800 and o["tftp150"] == ["10.40.0.5"] and o["bootfile"] == "pxelinux.0"
    assert [c for c in o["opts"] if c in (43, 66, 67, 150)] == [43, 66, 67, 150]
    hints = " ".join(h[1] for h in fb.dhcp_hints(o))
    assert "VoIP" in hints and "PXE" in hints and "Option 43" in hints
    assert fb.dhcp_hints(fb.parse_dhcp(bootp(opt(53, b"\x02") + b"\xff"))) == []


def test_dhcp_malformed():
    assert fb.parse_dhcp(b"") is None and fb.parse_dhcp(OFFER[:200]) is None
    assert fb.parse_dhcp(OFFER[:236] + b"\x00\x00\x00\x00" + OFFER[240:]) is None      # λάθος magic cookie
    o = fb.parse_dhcp(bootp(opt(53, b"\x02") + bytes([3, 200, 1, 2])))                 # option που «ξεχειλίζει»
    assert o["truncated"] and o["type"] == 2 and "gw" not in o
    o = fb.parse_dhcp(bootp(b"\x00\x00" + opt(1, bytes([255, 0, 255, 0])) + opt(6, b"\x01\x02\x03") + b"\xff"))
    assert "prefix" not in o and o["dns"] == []
    for i in range(236, len(OFFER)):
        fb.parse_dhcp(OFFER[:i])


# ───────────── link ─────────────
ETHTOOL = """Settings for eth0:
	Supported ports: [ TP MII ]
	Supported link modes:   10baseT/Half 10baseT/Full
	                        100baseT/Half 100baseT/Full
	                        1000baseT/Full
	Supported pause frame use: No
	Supports auto-negotiation: Yes
	Advertised link modes:  10baseT/Half 10baseT/Full
	                        100baseT/Half 100baseT/Full
	                        1000baseT/Full
	Advertised auto-negotiation: Yes
	Link partner advertised link modes:  10baseT/Half 10baseT/Full
	                                     100baseT/Half 100baseT/Full
	                                     1000baseT/Full
	Link partner advertised auto-negotiation: Yes
	Speed: 100Mb/s
	Duplex: Full
	Port: MII
	Link detected: yes
"""


def test_parse_ethtool_and_macos_media():
    e = fb.parse_ethtool(ETHTOOL)
    assert e == {"speed": 100, "duplex": "full", "carrier": True, "sup_max": 1000, "partner_max": 1000}
    assert fb.parse_ethtool("Speed: Unknown!\n\tDuplex: Unknown! (255)\n\tLink detected: no\n")["carrier"] is False
    assert fb.parse_ethtool("")["speed"] is None
    m = fb.parse_ifconfig_media("en5: flags=8863<UP>\n\tmedia: autoselect (1000baseT <full-duplex>)\n\tstatus: active\n")
    assert m["speed"] == 1000 and m["duplex"] == "full" and m["carrier"] is True
    m = fb.parse_ifconfig_media("\tmedia: autoselect (100baseTX <half-duplex>)\n\tstatus: active\n")
    assert m["speed"] == 100 and m["duplex"] == "half"
    m = fb.parse_ifconfig_media("\tmedia: autoselect (2500Base-T <full-duplex>)\n\tstatus: active\n")
    assert m["speed"] == 2500
    m = fb.parse_ifconfig_media("\tmedia: autoselect (none)\n\tstatus: inactive\n")
    assert m["carrier"] is False and m["speed"] is None


# ───────────── ετικέτες ─────────────
def test_next_label():
    assert fb.next_label("A-09") == "A-10" and fb.next_label("12") == "13" and fb.next_label("PP1-24") == "PP1-25"
    assert fb.next_label("A-99") == "A-100" and fb.next_label("") == "A-01" and fb.next_label("Γραφείο") == "Γραφείο-2"
    assert fb.next_label(" R2.P007 ") == "R2.P008" and len(fb.next_label("x" * 80)) <= 40


# ───────────── συμπέρασμα ─────────────
def R(**kw):
    return fb._demo_r(**kw)


def test_verdict_ok_text():
    v = fb.verdict(R(), {"vlan": 20, "poe": True, "speed": 1000})
    assert v["level"] == "ok" and v["issues"] == []
    assert v["el"] == "✅ Πρίζα ΟΚ — SW-OFFICE-1 θύρα Gi1/0/14, VLAN 20, 1 Gbps, PoE 15.4 W, DHCP σε 0.4 s"
    assert v["en"] == "✅ Socket OK — SW-OFFICE-1 port Gi1/0/14, VLAN 20, 1 Gbps, PoE 15.4 W, DHCP in 0.4 s"


def test_verdict_each_failure_mode():
    def code(r, ex=None):
        v = fb.verdict(r, ex)
        return v["level"], (v["issues"] or [{}])[0].get("code")

    assert code(R(carrier=False)) == ("fail", "nolink")
    assert "patch" in fb.verdict(R(carrier=False))["fix"]
    r = R(ms=0)
    r["l3"] = {"gateway": "fail"}
    assert code(r) == ("fail", "dhcp_none") and "SW-OFFICE-1" in fb.verdict(r)["fix"]
    assert code(R(ms=0)) == ("warn", "dhcp_none")                 # στατικές IP: gateway απαντά
    r = R()
    r["dhcp"]["offers"].append(dict(r["dhcp"]["offers"][0], server="192.168.0.1"))
    assert code(r) == ("fail", "dhcp_rogue")
    r = R()
    r["l3"]["gateway"] = "fail"
    assert code(r) == ("fail", "gateway")
    r = R()
    r["l3"]["internet"] = "fail"
    assert code(r) == ("fail", "internet")
    r = R()
    r["l3"].update(internet="fail", captive="fail")
    assert code(r) == ("warn", "captive")                          # το portal εξηγεί το κομμένο Internet
    r = R()
    r["l3"]["dns"] = "fail"
    assert code(r) == ("fail", "dns")
    assert code(R(speed=100)) == ("warn", "slow")
    assert "αντί για 1 Gbps" in fb.verdict(R(speed=100))["el"] and "T568B" in fb.verdict(R(speed=100))["fix"]
    assert code(R(speed=100, partner=100)) == ("warn", "slow")     # 100 Mbps πάντα αναφέρεται, πιο ήπια διατύπωση
    assert "αν το switch είναι gigabit" in fb.verdict(R(speed=100, partner=100))["el"]
    assert code(R(duplex="half")) == ("warn", "half")
    assert code(R(vlan=30), {"vlan": 20}) == ("warn", "vlan")
    assert code(R(vlan=30)) == ("ok", None)                        # χωρίς προσδοκία δεν είναι λάθος
    assert code(R(poe_w=0), {"poe": True}) == ("warn", "poe")
    assert code(R(poe_w=0)) == ("ok", None)
    assert code(R(tagged=(10, 30))) == ("warn", "trunk")
    r = R()
    r["l3"]["mtu"] = "fail"
    assert code(r) == ("warn", "mtu")
    # πρώτα το fail, μετά τα warn
    r = R(speed=100)
    r["l3"]["gateway"] = "fail"
    v = fb.verdict(r)
    assert v["level"] == "fail" and [x["code"] for x in v["issues"]] == ["gateway", "slow"]
    # δύο προειδοποιήσεις → (+1)
    assert "(+1)" in fb.verdict(R(speed=100, vlan=30), {"vlan": 20})["el"]
    # χωρίς LLDP: ΟΚ, αλλά με εξήγηση
    v = fb.verdict(R(sw=""))
    assert v["level"] == "ok" and "LLDP" in v["fix"] and v["el"].startswith("✅ Πρίζα ΟΚ — 1 Gbps")
    # Wi‑Fi δεν κρίνεται ως «χαλασμένο ζεύγος»
    r = R(speed=144)
    r["link"]["kind"] = "wifi"
    assert code(r) == ("warn", None)                      # … αλλά ούτε «Πρίζα ΟΚ»: δεν δοκιμάστηκε πρίζα
    assert "Wi‑Fi" in fb.verdict(r)["el"] and "Πρίζα ΟΚ" not in fb.verdict(r)["el"] and "Ethernet" in fb.verdict(r)["fix"]
    assert fb.verdict({})["level"] == "fail"


# ───────────── εκτέλεση με ψεύτικο δίκτυο ─────────────
class FakeNet:
    def __init__(self, link=None, frames=(), offers=None, ip="10.20.0.57", listen_err=None, dhcp_err=None):
        self.link_info = link if link is not None else {"iface": "eth0", "carrier": True, "speed": 1000, "duplex": "full",
                                                         "sup_max": 1000, "partner_max": 1000, "kind": "ethernet"}
        self.frames = list(frames)
        o = fb.parse_dhcp(OFFER)
        o.update(ms=412, mac="00:1b:54:aa:10:01", ip_src="10.20.0.1")
        self.offers = [o] if offers is None else offers
        self.ip, self.listen_err, self.dhcp_err = ip, listen_err, dhcp_err
        self.calls = []

    def link(self, iface):
        self.calls.append("link")
        return dict(self.link_info)

    def listen(self, iface, timeout, on_frame, should_stop):
        self.calls.append("listen")
        if self.listen_err:
            raise self.listen_err
        for f in self.frames:
            on_frame(f)

    def dhcp(self, iface, timeout=3.0):
        self.calls.append("dhcp")
        if self.dhcp_err:
            raise self.dhcp_err
        return [dict(o) for o in self.offers]

    def local(self):
        return {"iface": "eth0", "up": True, "ip": self.ip}

    def speedtest(self):
        self.calls.append("speed")
        return {"down_mbps": 93.4, "latency_ms": 11.0}


class FakeTriage:
    """Μιμείται το nettriage.Triage: run() → view() με status/steps."""

    def __init__(self, fail=(), polls=2):
        self.fail, self.polls, self.n, self.runs = set(fail), polls, 0, []

    def run(self, lang="el", scenario=None):
        self.runs.append(lang)
        self.n = 0
        return self.view()

    def view(self):
        self.n += 1
        done = self.n > self.polls
        ids = ["link", "dhcp", "gateway", "dns_local", "dns_public", "internet", "captive", "mtu", "quality"]
        steps = [{"id": i, "status": ("fail" if i in self.fail else "ok") if done or i in ("link", "dhcp") else "pending",
                  "detail": f"{i} detail", "ms": 5, "fix": None} for i in ids]
        return {"status": "done" if done else "running", "steps": steps}


class State:
    iface = "eth0"

    def __init__(self):
        self.alerts = []


def box(net=None, triage=None, tmp=None, **kw):
    b = fb.FieldBox(State(), str(tmp) if tmp else None, net=net or FakeNet(frames=[eth(FULL)]), triage=triage or FakeTriage(), **kw)
    b.sleep = lambda s: None
    b.listen_s = 0.2
    return b


def test_run_ok_end_to_end():
    net = FakeNet(frames=[eth(b"\x00" * 46, et=0x0800, tags=()), eth(FULL)])
    b = box(net)
    b._set_settings({"vlan": 20, "poe": True})
    rec = b.run_test("A-01", note="Υποδοχή")
    assert rec["level"] == "ok" and rec["label"] == "A-01" and rec["note"] == "Υποδοχή"
    assert rec["sw"] == "SW-OFFICE-1" and rec["port"] == "Gi1/0/14" and rec["vlan"] == 20 and rec["vlan_name"] == "OFFICE"
    assert rec["speed"] == 1000 and rec["duplex"] == "full" and rec["poe"] is True and rec["poe_w"] == 15.4 and rec["lag"] is True
    assert rec["dhcp_ms"] == 412 and rec["ip"] == "10.20.0.57" and rec["gw"] == "10.20.0.1" and rec["dhcp_opts"] == [43, 66, 67, 150]
    assert rec["l3"] == {"gateway": "ok", "dns": "ok", "internet": "ok", "captive": "ok", "mtu": "ok"}
    st = {s["id"]: s["status"] for s in rec["steps"]}
    assert st == {"link": "ok", "nbr": "ok", "dhcp": "ok", "gateway": "ok", "dns": "ok", "internet": "ok", "captive": "ok",
                  "mtu": "ok", "speed": "skip"}
    assert "DHCP σε 0.4 s" in rec["verdict"] and "DHCP in 0.4 s" in rec["verdict_en"]
    assert net.calls.count("dhcp") == 1 and "speed" not in net.calls
    v = b.view()
    assert v["busy"] is False and v["run"] is None and v["last"]["id"] == rec["id"] and v["next_label"] == "A-02"
    assert "steps" not in v["history"][0] and v["counts"] == {"ok": 1, "warn": 0, "fail": 0}
    json.dumps(v)


def test_run_no_link_skips_everything():
    net = FakeNet(link={"iface": "eth0", "carrier": False, "speed": None, "duplex": None, "kind": "ethernet"})
    rec = box(net).run_test("B-1")
    assert rec["level"] == "fail" and rec["issues"] == ["nolink"] and rec["carrier"] is False
    assert [s["status"] for s in rec["steps"]] == ["fail"] + ["skip"] * 8
    assert net.calls == ["link"]                                   # ούτε DISCOVER ούτε ακρόαση χωρίς link


def test_run_failures_map_to_verdict():
    rec = box(FakeNet(frames=[eth(FULL)], offers=[]), FakeTriage(fail={"gateway", "internet", "dns_local"})).run_test("C-1")
    assert rec["level"] == "fail" and rec["issues"][0] == "dhcp_none" and rec["dhcp_ms"] is None
    assert rec["l3"]["gateway"] == "fail"
    rec = box(triage=FakeTriage(fail={"internet"})).run_test("C-2")
    assert rec["issues"] == ["internet"] and "Internet" in rec["verdict"]
    # το λειτουργικό δεν πήρε IP → το nettriage κόβει στο link/dhcp → το δείχνουμε ως gateway
    rec = box(triage=FakeTriage(fail={"link"})).run_test("C-3")
    assert rec["l3"]["gateway"] == "fail" and rec["level"] == "fail"
    # rogue DHCP
    o = fb.parse_dhcp(OFFER)
    o2 = dict(o, server="192.168.0.1", ms=90)
    rec = box(FakeNet(frames=[eth(FULL)], offers=[dict(o, ms=400), o2])).run_test("C-4")
    assert rec["issues"][0] == "dhcp_rogue" and rec["dhcp_servers"] == ["10.20.0.1", "192.168.0.1"] and rec["dhcp_ms"] == 90


def test_run_without_root_degrades():
    net = FakeNet(listen_err=PermissionError("Operation not permitted"), dhcp_err=PermissionError("Operation not permitted"))
    rec = box(net).run_test("D-1")
    st = {s["id"]: s for s in rec["steps"]}
    assert st["nbr"]["status"] == "skip" and "root" in st["nbr"]["detail"] and st["dhcp"]["status"] == "skip"
    # χωρίς δικαιώματα ΔΕΝ λέμε «Πρίζα ΟΚ»: ο έλεγχος ήταν μερικός (βρέθηκε σε πραγματικό δίκτυο, χωρίς sudo)
    assert rec["level"] == "warn" and "Μερικός έλεγχος" in rec["verdict"] and "Πρίζα ΟΚ" not in rec["verdict"]
    assert rec["sw"] == "" and rec["l3"]["gateway"] == "ok" and "sudo" in rec["fix"]


def test_cdp_then_lldp_merge_and_trunk():
    cd = cdp(ctlv(1, b"SW-CORE"), ctlv(3, b"Gi1/0/14"), ctlv(0x0A, struct.pack(">H", 20)),
             ctlv(0x1A, struct.pack(">HHI", 1, 1, 15400)))
    ll = lldpdu(tlv(5, b"SW-CORE"))
    net = FakeNet(frames=[cdp_frame(cd), eth(ll), eth(b"\x00" * 46, dst="ffffffffffff", et=0x0806, tags=(30,))])
    rec = box(net).run_test("T-1")
    assert rec["proto"] == "LLDP" and rec["vlan"] == 20 and rec["poe_w"] == 15.4 and rec["tagged"] == [30]
    assert rec["level"] == "warn" and rec["issues"] == ["trunk"]


def test_speed_optional_and_data_saver():
    net = FakeNet(frames=[eth(FULL)])
    b = box(net)
    rec = b.run_test("S-1", speed=True)
    assert rec["down_mbps"] == 93.4 and net.calls.count("speed") == 1

    class Up:
        def on_backup(self):
            return True

        def view(self):
            return {"state": "backup"}

    b.state.uplink = Up()
    rec = b.run_test("S-2", speed=True)
    assert rec["down_mbps"] is None and net.calls.count("speed") == 1
    assert "LTE" in next(s for s in rec["steps"] if s["id"] == "speed")["detail"]
    assert b.view()["uplink"] == {"state": "backup"}


def test_progressive_view_via_api():
    """Το POST test γυρίζει αμέσως busy με τα βήματα· το view ενημερώνεται όσο τρέχει."""
    import threading
    gate, seen = threading.Event(), {}

    class SlowNet(FakeNet):
        def dhcp(self, iface, timeout=3.0):
            seen["mid"] = b.view()
            gate.wait(5)
            return super().dhcp(iface, timeout)

    b = box(SlowNet(frames=[eth(FULL)]))
    code, v = b.api("POST", "test", {}, {"label": "P-1", "lang": "en"})
    assert code == 200 and v["busy"] and v["run"]["label"] == "P-1" and len(v["run"]["steps"]) == 9
    code2, v2 = b.api("POST", "test", {}, {"label": "P-2"})
    assert code2 == 200 and v2["error"] and v2["run"]["label"] == "P-1"       # δεύτερο τεστ δεν ξεκινά
    gate.set()
    b._thread.join(10)
    mid = {s["id"]: s["status"] for s in seen["mid"]["run"]["steps"]}
    assert mid["link"] == "ok" and mid["dhcp"] == "running" and mid["gateway"] == "pending"
    assert seen["mid"]["run"]["link"]["speed"] == 1000
    v = b.api("GET", "", {}, {})[1]
    assert not v["busy"] and v["last"]["label"] == "P-1" and v["last"]["level"] == "ok" and b.triage.runs == ["en"]
    assert all("_" != k[0] for s in seen["mid"]["run"]["steps"] for k in s)


def test_auto_label_flow_history_cap_and_persistence(tmp_path):
    b = box(tmp=tmp_path)
    saved = []
    b.on_save = saved.append
    assert b.run_test("A-09")["label"] == "A-09"
    assert b.run_test()["label"] == "A-10" and b.run_test("")["label"] == "A-11"
    assert saved and os.path.exists(tmp_path / "field.json") and not os.path.exists(tmp_path / "field.json.tmp")
    b.api("POST", "settings", {}, {"vlan": "20", "poe": True, "speed": 1000, "iface": "eth1; rm -rf /"})
    b2 = box(tmp=tmp_path)
    assert [x["label"] for x in b2.hist] == ["A-09", "A-10", "A-11"] and b2.next_label() == "A-12"
    assert b2.settings == {"vlan": 20, "poe": True, "speed": 1000, "iface": None}
    b2.hist = [dict(b2.hist[0], id=str(i), label=f"X-{i}") for i in range(fb.MAX_HIST + 20)]
    b2.run_test("Z-1")
    assert len(b2.hist) == fb.MAX_HIST and b2.hist[-1]["label"] == "Z-1" and b2.hist[0]["label"] == "X-21"
    assert len(b2.view()["history"]) == fb.VIEW_HIST
    # διαγραφή / καθάρισμα
    rid = b2.hist[-1]["id"]
    assert b2.api("POST", "delete", {}, {"id": rid})[1]["count"] == fb.MAX_HIST - 1
    assert b2.api("POST", "clear", {}, {})[0] == 400
    assert b2.api("POST", "clear", {}, {"confirm": True})[1]["count"] == 0
    # χαλασμένο αρχείο δεν ρίχνει τίποτα
    (tmp_path / "field.json").write_text("{not json")
    assert box(tmp=tmp_path).hist == []


def test_results_latest_per_label():
    b = box(triage=FakeTriage())
    b.run_test("A-01")
    b.run_test("A-02")
    b.triage = FakeTriage(fail={"gateway"})
    b.run_test("A-01")                                              # επανάληψη: μετρά το τελευταίο
    res = b.results()
    assert [(x["label"], x["level"]) for x in res] == [("A-02", "ok"), ("A-01", "fail")]
    assert [x["label"] for x in b.results(["A-02", "nope"])] == ["A-02"] and "steps" in res[0]
    assert b.api("GET", "results", {"labels": "A-01"}, {})[1]["results"][0]["level"] == "fail"
    assert len(b.api("GET", "results", {}, {})[1]["results"]) == 2


def test_csv_export_is_safe():
    b = box()
    b.run_test("=HYPERLINK(\"http://x\")", note="+cmd")
    code, doc = b.api("GET", "csv", {}, {})
    assert code == 200 and doc["_type"].startswith("text/csv") and doc["_name"].endswith(".csv")
    txt = doc["_raw"].decode("utf-8-sig")
    lines = txt.strip().splitlines()
    assert lines[0].startswith("time,label,result,verdict,switch,port,vlan") and len(lines) == 2
    assert "'=HYPERLINK" in lines[1] and "'+cmd" in lines[1] and "SW-OFFICE-1" in lines[1] and ",1000,full,yes,15.4,412," in lines[1]


def test_oled_lines_short_ascii():
    def ok(lines):
        assert 1 <= len(lines) <= 6
        for x in lines:
            assert len(x) <= fb.OLED_W and all(32 <= ord(c) < 127 for c in x), x

    b = box()
    code, o = b.api("GET", "oled", {}, {})
    assert code == 200 and o["busy"] is False and o["next"] == "A-01"
    ok(o["lines"])
    b.run_test("Πρίζα-αίθουσας-συσκέψεων-με-πολύ-μεγάλο-όνομα-07")
    o = b.oled()
    ok(o["lines"])
    assert o["lines"][1] == "SW-OFFICE-1" and "VLAN 20" in o["lines"][2] and "PoE 15.4W" in o["lines"][3] and "DHCP 0.4s" in o["lines"][4]
    b.run_test("A-01")
    assert b.oled()["lines"][0] == "A-01 OK" and b.oled()["next"] == "A-02"
    for kw in (dict(carrier=False), dict(speed=100), dict(sw=""), dict(ms=0), dict(poe_w=0)):
        ok(fb.oled_lines(rec=fb.build_record("Ω-1", "", 1.0, fb._demo_r(**kw), {"poe": True})))
    assert fb.oled_lines(rec=fb.build_record("A-1", "", 1.0, fb._demo_r(carrier=False)))[1] == "NO LINK"
    run = {"label": "A-03", "elapsed": 12.4, "steps": [{"id": "link", "status": "ok"}, {"id": "dhcp", "status": "running"}],
           "nbr": fb.parse_lldp(FULL), "link": {"carrier": True, "speed": 1000}}
    lines = fb.oled_lines(run=run)
    ok(lines)
    assert lines[0] == "A-03 TEST 12s" and lines[1] == "step 1/2 dhcp"


def test_api_unknown():
    b = box()
    assert b.api("GET", "nope", {}, {}) == (404, {"error": "not found"})
    assert b.api("POST", "nope", {}, {}) == (404, {"error": "not found"})
    assert b.api("PUT", "", {}, {})[0] == 404


def test_demo_shapes_and_progressive_demo_run():
    b = fb.FieldBox(None, demo=True, clock=lambda: 1_800_000_000.0)
    b.sleep = lambda s: None
    v = b.view()
    assert v["demo"] and v["count"] == 8 and v["next_label"] == "A-09" and v["settings"]["vlan"] == 20
    by = {x["label"]: x for x in v["history"]}
    assert by["A-03"]["issues"] == ["slow"] and by["A-03"]["speed"] == 100
    assert by["A-05"]["issues"] == ["vlan"] and by["A-05"]["vlan"] == 30
    assert by["A-07"]["issues"] == ["poe"] and by["A-07"]["poe"] is False
    assert v["counts"] == {"ok": 5, "warn": 3, "fail": 0} and by["A-08"]["poe_w"] == 30.0
    rec = b.run_test()
    assert rec["label"] == "A-09" and rec["level"] == "ok" and rec["sw"] == "SW-OFFICE-1"
    assert [s["status"] for s in rec["steps"]] == ["ok"] * 8 + ["skip"]
    assert len(b.oled()["lines"]) <= 6
    json.dumps(b.view())
    assert b.api("GET", "csv", {}, {})[1]["_raw"].count(b"\n") == 10


def test_real_net_link_never_raises_on_odd_names():
    n = fb.Net()
    assert n.link("")["carrier"] is None and n.link("../../etc")["carrier"] is None


# ───────────── tools/fieldbox/oled.py (λειτουργία --stdout, χωρίς υλικό και χωρίς δίκτυο) ─────────────
def _oled_mod():
    path = os.path.join(os.path.dirname(__file__), "..", "tools", "fieldbox", "oled.py")
    spec = importlib.util.spec_from_file_location("fieldbox_oled", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class BoxClient:
    """Στη θέση του HTTP: μιλά κατευθείαν με το FieldBox.api, όπως θα έκανε ο server."""

    def __init__(self, b):
        self.b, self.posts = b, []

    def lines(self):
        code, j = self.b.api("GET", "oled", {}, {})
        return _oled_mod().clean(j["lines"]), j

    def start_test(self, label=None):
        self.posts.append(label)
        rec = self.b.run_test(label)
        return 200, {"label": rec["label"]}


def test_oled_script_stdout_and_button():
    import io
    o = _oled_mod()
    b = box()
    b.run_test("A-01")
    out = io.StringIO()
    cli = BoxClient(b)
    assert o.loop(cli, o.Stdout(out), once=True) == 0
    frame = out.getvalue().splitlines()
    assert len(frame) == 8 and frame[0] == "+" + "-" * 21 + "+" and frame[1] == "|A-01 OK".ljust(22) + "|"
    assert all(len(x) == 23 and all(32 <= ord(c) < 127 for c in x) for x in frame)
    # πάτημα κουμπιού → POST test με την επόμενη ετικέτα (A-02), μετά η οθόνη δείχνει το νέο αποτέλεσμα
    out = io.StringIO()
    pressed = []
    naps = []

    def nap(s):
        naps.append(s)
        if len(naps) == 1:
            pressed.append(1)

    o.loop(cli, o.Stdout(out), pressed=pressed, sleep=nap, max_iter=3)
    assert cli.posts == ["A-02"] and b.hist[-1]["label"] == "A-02" and "|A-02 OK" in out.getvalue() and pressed == []
    # το NetWatch δεν απαντά → μήνυμα αναμονής, όχι crash

    class Dead:
        def lines(self):
            raise OSError("refused")

    out = io.StringIO()
    assert o.loop(Dead(), o.Stdout(out), once=True) == 1 and "waiting for NetWatch" in out.getvalue()
    assert o.clean(["ok", "Πρίζα" * 20, 5, None] + ["x"] * 9) == ["ok", "?" * 21, "5", "None", "x", "x"] and o.clean("nope") == []


def test_oled_script_follows_server_auth_rules(tmp_path):
    o = _oled_mod()
    c = o.Client("http://127.0.0.1:8765")
    assert c.headers(post=True) == {"Accept": "application/json", "Content-Type": "application/json"}   # ποτέ Origin
    assert "Origin" not in c.headers() and "Content-Type" not in c.headers()
    for bad in ("http://192.168.1.5:8765", "ftp://127.0.0.1", "http://127.0.0.1:8765/x/y", ""):
        with pytest.raises(ValueError):
            o.Client(bad)
    with pytest.raises(ValueError):                    # https χωρίς πιστοποιητικό για pinning → δεν στέλνουμε token στα τυφλά
        o.Client("https://127.0.0.1:8765", "tok", str(tmp_path / "missing.crt"))
    pem = ("-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ0FLRUZBS0VGQUtFRkFLRUZBS0UwCgYIKoZIzj0EAwIw\n-----END CERTIFICATE-----\n")
    (tmp_path / "agent.crt").write_text(pem)
    c = o.Client("https://127.0.0.1:8765", "tok123", str(tmp_path / "agent.crt"))
    assert c.headers(post=True)["Authorization"] == "Bearer tok123" and len(c.fp) == 64 and c.tls and c.port == 8765
    assert o.read_token(str(tmp_path / "nope")) == ""
