"""Tests για τον έλεγχο IPv6 (v6guard.py): ανάλυση RA από χειροποίητα πλαίσια, εμπιστοσύνη/εκμάθηση/ψεύτικο router,
DHCPv6, ταξινόμηση διευθύνσεων, ενεργός έλεγχος με ψεύτικο δίκτυο. Κανένα πραγματικό πακέτο."""
import ipaddress
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import v6guard as v  # noqa: E402

GW_MAC, GW_LL = "a4:2b:b0:11:22:33", "fe80::a62b:b0ff:fe11:2233"
BAD_MAC, BAD_LL = "00:0c:29:5e:7a:10", "fe80::20c:29ff:fe5e:7a10"
PREFIX = "2a02:587:4c1a:2b00::"
P64 = PREFIX[:-1]


def mac_b(m):
    return bytes.fromhex(m.replace(":", ""))


def ip_b(a):
    return ipaddress.IPv6Address(a).packed


# ── επιλογές ND, byte προς byte όπως στα RFC ──
def opt_slla(mac):                       # RFC 4861 §4.6.1: type 1, len 1 (8 bytes)
    return bytes([1, 1]) + mac_b(mac)


def opt_mtu(mtu):                        # §4.6.4: type 5, len 1, reserved(2), MTU(4)
    return bytes([5, 1, 0, 0]) + struct.pack("!I", mtu)


def opt_prefix(prefix, plen=64, L=True, A=True, valid=86400, pref=14400):   # §4.6.2: type 3, len 4 (32 bytes)
    return bytes([3, 4, plen, (0x80 if L else 0) | (0x40 if A else 0)]) + struct.pack("!III", valid, pref, 0) + ip_b(prefix)


def opt_rdnss(addrs, life=1800):         # RFC 8106 §5.1: type 25, len 1+2n, reserved(2), lifetime(4), διευθύνσεις
    return bytes([25, 1 + 2 * len(addrs), 0, 0]) + struct.pack("!I", life) + b"".join(ip_b(a) for a in addrs)


def opt_route(prefix, plen, prf=0, life=1800):   # RFC 4191 §2.3: type 24, len 3, plen, flags(Prf στα bits 3-4), lifetime, prefix
    return bytes([24, 3, plen, prf << 3]) + struct.pack("!I", life) + ip_b(prefix)


def ra_frame(mac=GW_MAC, src=GW_LL, lifetime=1800, M=False, O=False, prf=0, opts=b"", hlim=255, vlan=None, dst="ff02::1",
             cur_hlim=64):
    flags = (0x80 if M else 0) | (0x40 if O else 0) | (prf << 3)
    icmp = bytes([134, 0, 0, 0, cur_hlim, flags]) + struct.pack("!HII", lifetime, 0, 0) + opts   # RFC 4861 §4.2
    ip6 = struct.pack("!IHBB", 6 << 28, len(icmp), 58, hlim) + ip_b(src) + ip_b(dst)
    eth = bytes.fromhex("333300000001") + mac_b(mac)
    if vlan is not None:
        eth += struct.pack("!HH", 0x8100, vlan)
    return eth + struct.pack("!H", 0x86DD) + ip6 + icmp


def dhcp6_frame(mac=BAD_MAC, src=BAD_LL, msg=2, sport=547, dport=546):
    udp = struct.pack("!HHHH", sport, dport, 12, 0) + bytes([msg, 1, 2, 3])
    ip6 = struct.pack("!IHBB", 6 << 28, len(udp), 17, 64) + ip_b(src) + ip_b("fe80::1")
    return bytes(6) + mac_b(mac) + struct.pack("!H", 0x86DD) + ip6 + udp


FULL = opt_slla(GW_MAC) + opt_mtu(1492) + opt_prefix(PREFIX) + opt_rdnss(["2001:4860:4860::8888", GW_LL])


class State:
    gateway = "192.168.1.1"
    iface = "en0"

    def __init__(self, gw_mac=None):
        self.hosts = {"192.168.1.1": {"ip": "192.168.1.1", "kind": "local", "names": {"router.home"}, "mac": gw_mac},
                      "192.168.1.77": {"ip": "192.168.1.77", "kind": "local", "names": {"kali.local"}, "mac": BAD_MAC}}
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, detail, kw))


def P_ra(frame):
    return {"proto": "ICMPv6", "src": "x", "dst": "ff02::1", "smac": v._mac(frame[6:12]), "_raw": frame}


# ───────── ανάλυση RA ─────────
def test_parse_ra_all_fields():
    ra = v.parse_ra(ra_frame(M=True, O=True, prf=1, opts=FULL))
    assert ra["mac"] == GW_MAC and ra["src"] == GW_LL and ra["hlim"] == 255 and ra["cur_hlim"] == 64
    assert ra["M"] and ra["O"] and ra["pref"] == "high" and ra["lifetime"] == 1800
    assert ra["slla"] == GW_MAC and ra["mtu"] == 1492
    assert ra["prefixes"] == [{"prefix": PREFIX + "/64", "len": 64, "L": True, "A": True, "valid": 86400, "preferred": 14400}]
    assert ra["rdnss"] == ["2001:4860:4860::8888", GW_LL] and ra["rdnss_lifetime"] == 1800
    assert not ra["truncated"] and not ra["bad"] and ra["vlan"] is None


def test_parse_ra_flags_and_preference_bits():
    assert [v.parse_ra(ra_frame(prf=p))["pref"] for p in (0, 1, 2, 3)] == ["medium", "high", "medium", "low"]  # RFC 4191 §2.2
    ra = v.parse_ra(ra_frame(M=False, O=True))
    assert not ra["M"] and ra["O"]
    ra = v.parse_ra(ra_frame(opts=opt_prefix(PREFIX, L=False, A=True) + opt_route("fd12:3456::", 48, prf=3)))
    assert ra["prefixes"][0]["L"] is False and ra["prefixes"][0]["A"] is True
    assert ra["routes"] == [{"prefix": "fd12:3456::/48", "pref": "low", "lifetime": 1800}]


def test_parse_ra_vlan_tag():
    ra = v.parse_ra(ra_frame(vlan=30, opts=FULL))
    assert ra["vlan"] == 30 and ra["mtu"] == 1492 and ra["rdnss"][0] == "2001:4860:4860::8888"
    qinq = ra_frame(opts=opt_mtu(1500))
    qinq = qinq[:12] + struct.pack("!HHHH", 0x88A8, 100, 0x8100, 20) + qinq[12:]
    assert v.parse_ra(qinq)["vlan"] == 100 and v.parse_ra(qinq)["mtu"] == 1500


def test_parse_ra_truncated_to_128_bytes_keeps_what_fits():
    f = ra_frame(opts=FULL)
    assert len(f) > 128
    ra = v.parse_ra(f[:128])                 # όπως το `_raw` της σύλληψης
    assert ra["truncated"] and ra["rdnss"] == [] and ra["mtu"] == 1492 and ra["prefixes"][0]["prefix"] == PREFIX + "/64"
    assert v.parse_ra(f[:69]) is None        # ούτε η σταθερή επικεφαλίδα του RA δεν χωρά
    for n in range(0, len(f)):               # κανένα μήκος δεν πετά εξαίρεση
        v.parse_ra(f[:n])


def test_parse_ra_garbage_and_not_ra():
    assert v.parse_ra(b"") is None and v.parse_ra(None) is None and v.parse_ra(b"\xff" * 200) is None
    ns = bytearray(ra_frame())
    ns[54] = 135                             # Neighbor Solicitation
    assert v.parse_ra(bytes(ns)) is None
    ext = bytearray(ra_frame())
    ext[20] = 0                              # next header = hop-by-hop (extension header) → δεν το αγγίζουμε
    assert v.parse_ra(bytes(ext)) is None
    ipv4 = bytearray(ra_frame())
    ipv4[12:14] = b"\x08\x00"
    assert v.parse_ra(bytes(ipv4)) is None
    zero = v.parse_ra(ra_frame(opts=bytes([3, 0]) + bytes(30)))   # επιλογή με μήκος 0 → άκυρο (RFC 4861 §4.6)
    assert zero["bad"] and zero["prefixes"] == []
    import random
    rnd = random.Random(7)
    base = ra_frame(opts=FULL)
    for _ in range(300):
        b = bytearray(base)
        for _ in range(6):
            b[rnd.randrange(len(b))] = rnd.randrange(256)
        v.parse_ra(bytes(b))                 # δεν πετά ποτέ


def test_parse_matches_scapy_layout():
    """Ανεξάρτητος έλεγχος: το ίδιο RA φτιαγμένο από το scapy (δεν στέλνεται τίποτα)."""
    sc = pytest.importorskip("scapy.all")
    pkt = (sc.Ether(src=GW_MAC, dst="33:33:00:00:00:01") / sc.IPv6(src=GW_LL, dst="ff02::1", hlim=255)
           / sc.ICMPv6ND_RA(M=1, O=0, prf=1, routerlifetime=900, chlim=64) / sc.ICMPv6NDOptSrcLLAddr(lladdr=GW_MAC)
           / sc.ICMPv6NDOptMTU(mtu=1480) / sc.ICMPv6NDOptPrefixInfo(prefix=PREFIX, prefixlen=64, L=1, A=1, validlifetime=7200, preferredlifetime=3600)
           / sc.ICMPv6NDOptRDNSS(dns=["2606:4700:4700::1111"], lifetime=600)
           / sc.ICMPv6NDOptRouteInfo(prefix="fd00:1::", plen=64, prf=3, rtlifetime=300))
    ra = v.parse_ra(bytes(pkt))
    assert ra["M"] and not ra["O"] and ra["pref"] == "high" and ra["lifetime"] == 900 and ra["mtu"] == 1480 and ra["slla"] == GW_MAC
    assert ra["prefixes"][0] == {"prefix": PREFIX + "/64", "len": 64, "L": True, "A": True, "valid": 7200, "preferred": 3600}
    assert ra["rdnss"] == ["2606:4700:4700::1111"] and ra["rdnss_lifetime"] == 600
    assert ra["routes"] == [{"prefix": "fd00:1::/64", "pref": "low", "lifetime": 300}]
    mine = ra_frame(M=True, prf=1, lifetime=900, opts=opt_slla(GW_MAC) + opt_mtu(1480) + opt_prefix(PREFIX, valid=7200, pref=3600)
                    + opt_rdnss(["2606:4700:4700::1111"], 600) + opt_route("fd00:1::", 64, prf=3, life=300))
    theirs = bytearray(bytes(pkt))
    theirs[56:58] = b"\x00\x00"              # checksum: ο δικός μας κατασκευαστής το αφήνει 0
    assert bytes(theirs) == mine             # ο χειροποίητος κατασκευαστής των tests συμφωνεί byte προς byte με το scapy
    d = (sc.Ether(src=BAD_MAC) / sc.IPv6(src=BAD_LL, dst="fe80::1") / sc.UDP(sport=547, dport=546) / sc.DHCP6_Advertise(trid=1))
    assert v.dhcp6_type(bytes(d)) == 2


# ───────── εμπιστοσύνη / εκμάθηση / ψεύτικο router ─────────
def test_learning_then_rogue_alert_once():
    st = State()
    g = v.V6Guard(st, clock=lambda: 2000.0)
    g.observe(P_ra(ra_frame(opts=FULL)), 1000.0)
    assert st.alerts == [] and g.trusted[GW_MAC]["by"] == "learn" and g.view()["learning"] is False
    # δεύτερο router ΜΕΣΑ στο παράθυρο → το μαθαίνει, δεν φωνάζει
    g.observe(P_ra(ra_frame(mac="aa:aa:aa:00:00:02", src="fe80::2")), 1000.0 + v.LEARN - 1)
    assert st.alerts == [] and "aa:aa:aa:00:00:02" in g.trusted
    # νέο router ΜΕΤΑ το παράθυρο → ειδοποίηση, μία φορά
    t = 1000.0 + v.LEARN + 5
    for i in range(5):
        g.observe(P_ra(ra_frame(mac=BAD_MAC, src=BAD_LL, opts=opt_rdnss([BAD_LL]))), t + i)
    assert len(st.alerts) == 1
    typ, sev, actor, _target, detail, kw = st.alerts[0]
    assert typ == "Ψεύτικο Router Advertisement (IPv6)" and sev == "high" and actor == BAD_LL
    assert BAD_MAC in detail and "kali.local" in detail and BAD_LL in detail and kw["key"] == ("v6", "rogue_ra", BAD_MAC)
    vw = g.view()
    assert vw["status"] == "unmanaged" and vw["verdict"]["level"] == "bad" and vw["counts"]["rogue"] == 1
    assert [r["trusted"] for r in vw["routers"]][0] is False       # το ύποπτο πρώτο
    # μετά το cooldown ξαναειδοποιεί
    g.observe(P_ra(ra_frame(mac=BAD_MAC, src=BAD_LL)), t + v.COOLDOWN + 10)
    assert len(st.alerts) == 2


def test_gateway_mac_is_trusted_without_learning_window():
    st = State(gw_mac=GW_MAC.upper().replace(":", "-"))
    g = v.V6Guard(st)
    g.observe(P_ra(ra_frame()), 50.0)
    assert g.trusted[GW_MAC]["by"] == "gw"
    g.observe(P_ra(ra_frame(mac=BAD_MAC, src=BAD_LL, prf=1)), 51.0)     # αμέσως μετά: δεν «μαθαίνεται»
    assert len(st.alerts) == 1 and "High" in st.alerts[0][4] and st.alerts[0][5]["key"][1] == "rogue_high"


def test_kill_ra_and_rdnss_change_details():
    st = State(gw_mac=GW_MAC)
    g = v.V6Guard(st)
    g.observe(P_ra(ra_frame(opts=opt_slla(GW_MAC) + opt_rdnss(["2001:4860:4860::8888"]))), 10.0)
    # lifetime 0 με τη link-local του πραγματικού router, από άλλη MAC
    g.observe(P_ra(ra_frame(mac=BAD_MAC, src=GW_LL, lifetime=0)), 20.0)
    assert len(st.alerts) == 1 and "kill-RA" in st.alerts[0][4] and st.alerts[0][1] == "high" and GW_MAC in st.alerts[0][4]
    # ο έμπιστος router αλλάζει RDNSS → μεσαία ειδοποίηση με παλιό → νέο
    g.observe(P_ra(ra_frame(opts=opt_slla(GW_MAC) + opt_rdnss([BAD_LL]))), 30.0)
    assert len(st.alerts) == 2 and st.alerts[1][1] == "med" and "RDNSS" in st.alerts[1][4] and "2001:4860:4860::8888" in st.alerts[1][4]
    # κομμένο πλαίσιο (χωρίς RDNSS) δεν μετρά ως αλλαγή και δεν σβήνει ό,τι ξέραμε
    g.observe(P_ra(ra_frame(opts=FULL)[:128]), 40.0)
    assert len(st.alerts) == 2 and g.routers[GW_MAC]["rdnss"] == [BAD_LL]
    # έμπιστος router με lifetime 0 από τη ΔΙΚΗ του MAC: γεγονός, όχι ειδοποίηση
    g.observe(P_ra(ra_frame(lifetime=0)), 50.0)
    assert len(st.alerts) == 2 and g.events[-1]["kind"] == "gone"


def test_invalid_and_stub_ras_do_not_alert():
    st = State(gw_mac=GW_MAC)
    g = v.V6Guard(st)
    g.observe(P_ra(ra_frame()), 1.0)
    g.observe(P_ra(ra_frame(mac=BAD_MAC, src=BAD_LL, hlim=64)), 2.0)                   # hop limit ≠ 255
    g.observe(P_ra(ra_frame(mac=BAD_MAC, src="2001:db8::1")), 3.0)                       # όχι link-local
    assert st.alerts == [] and BAD_MAC not in g.routers
    # Thread border router (HomePod): lifetime 0, μόνο ULA prefix/route
    g.observe(P_ra(ra_frame(mac="f4:34:f0:00:00:09", src="fe80::9", lifetime=0,
                            opts=opt_prefix("fd5a:1b2c:3d4e:1::") + opt_route("fd11:22:33::", 64))), 4.0)
    assert st.alerts == [] and g.routers["f4:34:f0:00:00:09"]["stub"] and g.view()["counts"]["rogue"] == 0
    # ίδιο, αλλά με route προς όλο το Internet → ψεύτικο
    g.observe(P_ra(ra_frame(mac="f4:34:f0:00:00:0a", src="fe80::a", lifetime=0, opts=opt_route("::", 0, prf=1))), 5.0)
    assert len(st.alerts) == 1


def test_user_trust_persisted_and_untrust(tmp_path):
    st = State(gw_mac=GW_MAC)
    saved = []
    g = v.V6Guard(st, str(tmp_path))
    g.on_save = saved.append
    g.observe(P_ra(ra_frame()), 1.0)
    g.observe(P_ra(ra_frame(mac=BAD_MAC, src=BAD_LL)), 2.0)
    assert len(st.alerts) == 1
    assert g.api("POST", "trust", {}, {"mac": "nope"})[0] == 400
    code, vw = g.api("POST", "trust", {}, {"mac": BAD_MAC.upper()})
    assert code == 200 and vw["trusted"][BAD_MAC]["by"] == "user" and vw["counts"]["rogue"] == 0 and saved
    st2 = State(gw_mac=GW_MAC)
    g2 = v.V6Guard(st2, str(tmp_path))
    g2.observe(P_ra(ra_frame(mac=BAD_MAC, src=BAD_LL)), 99999.0)
    assert st2.alerts == [] and g2.events and g2.events[0]["kind"] == "rogue_ra"       # το ιστορικό γεγονότων έμεινε
    g2.api("POST", "untrust", {}, {"mac": BAD_MAC})
    g2.observe(P_ra(ra_frame(mac=BAD_MAC, src=BAD_LL)), 99999.0 + 5)
    assert len(st2.alerts) == 1
    assert not [f for f in os.listdir(str(tmp_path)) if f.endswith(".tmp")]


def test_dhcpv6_rogue():
    st = State(gw_mac=GW_MAC)
    g = v.V6Guard(st)
    g.observe(P_ra(ra_frame()), 1.0)
    P = {"proto": "UDP", "sp": 547, "dp": 546, "src": GW_LL, "dst": "fe80::5", "smac": GW_MAC, "_raw": dhcp6_frame(GW_MAC, GW_LL, 7)}
    g.observe(P, 2.0)                                                   # το router απαντά DHCPv6 → εντάξει
    assert st.alerts == []
    bad = {"proto": "UDP", "sp": 547, "dp": 546, "src": BAD_LL, "dst": "fe80::5", "smac": BAD_MAC, "_raw": dhcp6_frame(msg=2)}
    g.observe(bad, 3.0)
    g.observe(bad, 4.0)
    assert len(st.alerts) == 1 and st.alerts[0][0] == "Ψεύτικος DHCPv6 server" and st.alerts[0][1] == "high" and "mitm6" in st.alerts[0][4]
    assert any(c["id"] == "dhcp6" and c["level"] == "bad" for c in g.view()["checklist"])
    # Solicit από client (546→547) και Relay-reply δεν μετράνε
    n = len(st.alerts)
    g.observe({"proto": "UDP", "sp": 546, "dp": 547, "src": "fe80::7", "smac": "02:00:00:00:00:07"}, 5.0)
    g.observe({"proto": "UDP", "sp": 547, "dp": 546, "src": "fe80::8", "smac": "02:00:00:00:00:08", "_raw": dhcp6_frame("02:00:00:00:00:08", "fe80::8", 13)}, 6.0)
    assert len(st.alerts) == n
    assert v.dhcp6_type(dhcp6_frame(msg=7)) == 7 and v.dhcp6_type(dhcp6_frame(sport=546, dport=547)) is None and v.dhcp6_type(b"x") is None


def test_observe_never_raises_and_ignores_other_traffic():
    g = v.V6Guard(None)
    for P in ({}, {"proto": "TCP"}, {"proto": "ICMPv6"}, {"proto": "ICMPv6", "_raw": b"\x00" * 90}, {"proto": "UDP", "sp": 547, "dp": 546, "smac": None},
              {"proto": "ICMPv6", "_raw": "str"}, {"proto": "ICMPv6", "src": "fe80::1", "dst": "ff02::1", "_id": 5}):
        g.observe(P, 1.0)
    assert g.routers == {} and g.view()["status"] == "unknown"
    g.observe({"proto": "ICMPv6"}, 2.0, raw=ra_frame())                 # ο συντονιστής μπορεί να δώσει τα bytes ξεχωριστά
    assert GW_MAC in g.routers


def test_router_table_is_capped():
    g = v.V6Guard(None)
    for i in range(v.MAX_ROUTERS + 30):
        g.observe(P_ra(ra_frame(mac="02:00:00:00:%02x:%02x" % (i >> 8, i & 255), src="fe80::%x" % (i + 1))), 10.0 + i)
    assert len(g.routers) == v.MAX_ROUTERS and len(g.events) <= v.MAX_EVENTS


# ───────── διευθύνσεις ─────────
def test_classify_addresses():
    c = v.classify("2a02:587:4c1a:2b00:be24:11ff:fe3a:9c01")
    assert c["scope"] == "global" and c["eui64"] and c["mac"] == "bc:24:11:3a:9c:01" and c["kind"] == "eui64"
    assert v.classify("fe80::a62b:b0ff:fe11:2233%en0")["mac"] == "a4:2b:b0:11:22:33"       # u/l bit αντιστρέφεται (RFC 4291 App. A)
    assert v.classify("fe80::1ceb:13da:ea5a:78d8")["scope"] == "link-local" and not v.classify("fe80::1ceb:13da:ea5a:78d8")["eui64"]
    assert v.classify("fd12:3456:789a::10/64")["scope"] == "ula" and v.classify("fc00::1")["scope"] == "ula"
    t = v.classify("2a02:587::14a6:998:4310:dfc0", ["autoconf", "temporary"])
    assert t["scope"] == "global" and t["kind"] == "temp" and not t["eui64"]
    assert v.classify("2a02:587::1833:ae14:a598:f043", ["autoconf", "secured"])["kind"] == "stable"
    assert v.classify("::1")["scope"] == "loopback" and v.classify("ff02::1")["scope"] == "multicast"
    assert v.classify("nonsense") is None and v.classify("192.168.1.1") is None


def test_parse_os_outputs():
    mac_out = ("lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet6 ::1 prefixlen 128 \n"
               "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 9e:4a:5e:6a:f5:8b\n"
               "\tinet6 fe80::1ceb:13da:ea5a:78d8%en0 prefixlen 64 secured scopeid 0xb \n"
               "\tinet6 2a02:587:7856:2a00:1833:ae14:a598:f043 prefixlen 64 autoconf secured \n"
               "\tinet6 2a02:587:7856:2a00:14a6:998:4310:dfc0 prefixlen 64 deprecated autoconf temporary \n\tinet 192.168.1.5 netmask 0xffffff00\n")
    a = v.parse_ifconfig6(mac_out)
    assert [x["iface"] for x in a] == ["lo0", "en0", "en0", "en0"] and "temporary" in a[3]["flags"] and "secured" in a[1]["flags"]
    assert v.classify(a[3]["addr"], a[3]["flags"])["deprecated"]
    lin = ("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000\n"
           "    inet6 2a02:587::be24:11ff:fe3a:9c01/64 scope global dynamic mngtmpaddr noprefixroute \n       valid_lft 86000sec preferred_lft 14000sec\n"
           "    inet6 2a02:587::59e2:b7a1:400c:91f5/64 scope global temporary dynamic \n    inet6 fe80::be24:11ff:fe3a:9c01/64 scope link \n")
    b = v.parse_ip6_addr(lin)
    assert len(b) == 3 and b[0]["iface"] == "eth0" and [v.classify(x["addr"], x["flags"])["kind"] for x in b] == ["eui64", "temp", "eui64"]
    ndp = ("Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs\n"
           "2a02:587:7856:2a00:14a6:998:4310:dfc0   9e:4a:5e:6a:f5:8b    en0 permanent R      \n"
           "fe80::1%lo0                             (incomplete)         lo0 permanent R      \n"
           "fe80::a62b:b0ff:fe11:2233%en0           a4:2b:b0:11:22:33    en0 23h59m58s S  R   \n"
           "2a02:587:7856:2a00::5                   0:1b:c:d:e:f         en0 5s        R      \n")
    n = v.parse_neigh(ndp)
    assert [x["mac"] for x in n] == ["9e:4a:5e:6a:f5:8b", "a4:2b:b0:11:22:33", "00:1b:0c:0d:0e:0f"]
    ipn = "2a02:587::9 dev eth0 lladdr bc:24:11:3a:9c:01 REACHABLE\nfe80::1 dev eth0 lladdr a4:2b:b0:11:22:33 router STALE\nfe80::3 dev eth0  FAILED\n"
    n = v.parse_neigh(ipn)
    assert [(x["ip"], x["router"]) for x in n] == [("2a02:587::9", False), ("fe80::1", True)]
    win = "Interface 12: Ethernet\n\nInternet Address                              Physical Address   Type\n2a02:587::77                                  bc-24-11-3a-9c-02  Reachable\nff02::1                                       33-33-00-00-00-01  Permanent\n"
    assert v.parse_neigh(win) == [{"ip": "2a02:587::77", "mac": "bc:24:11:3a:9c:02", "router": False}]
    assert v.parse_neigh("") == [] and v.parse_ifconfig6(None) == [] and v.parse_ip6_addr("garbage") == []


# ───────── ενεργός έλεγχος ─────────
class FakeNet:
    def __init__(self, frames=(), addrs=(), neigh=(), ok=True, boom=None):
        self.frames, self.addrs, self.neigh, self.ok, self.boom, self.calls = list(frames), list(addrs), list(neigh), ok, boom, []

    def solicit(self, iface, timeout=3.0):
        self.calls.append(("solicit", iface))
        if self.boom:
            raise self.boom
        return self.frames

    def addresses(self):
        return self.addrs

    def neighbors(self):
        return self.neigh

    def connect6(self, host, port=443, timeout=3.0):
        self.calls.append(("connect6", host, port))
        return 20.0 if self.ok else None

    def aaaa(self, name):
        return ["2606:4700:4700::1111"] if self.ok else []


def test_active_check_with_fake_net():
    st = State(gw_mac=GW_MAC)
    st.hosts["2a02:587:4c1a:2b00:211:32ff:fe8d:4410"] = {"ip": "2a02:587:4c1a:2b00:211:32ff:fe8d:4410", "kind": "local", "names": set(), "mac": None}
    st.hosts["2606:4700::6810:1"] = {"ip": "2606:4700::6810:1", "kind": "public", "names": {"cdn"}, "mac": None}   # server στο Internet: όχι
    st.hosts["192.168.1.30"] = {"ip": "192.168.1.30", "kind": "local", "names": {"cam.local"}, "mac": "bc:24:11:3a:9c:01"}
    net = FakeNet(frames=[ra_frame(opts=FULL), b"junk", ra_frame(opts=FULL)],
                  addrs=[{"addr": "fe80::1ceb:13da:ea5a:78d8", "iface": "en0", "flags": ["secured"]},
                         {"addr": P64 + "14a6:998:4310:dfc0", "iface": "en0", "flags": ["temporary"]},
                         {"addr": "::1", "iface": "lo0", "flags": []}],
                  neigh=[{"ip": P64 + "be24:11ff:fe3a:9c01", "mac": "bc:24:11:3a:9c:01", "router": False},
                         {"ip": P64 + "14a6:998:4310:dfc0", "mac": "9e:4a:5e:6a:f5:8b", "router": False},
                         {"ip": GW_LL, "mac": GW_MAC, "router": True}])
    g = v.V6Guard(st, net=net, clock=lambda: 5000.0)
    vw = g.check()
    assert vw["checked"] == 5000.0 and vw["ra"]["status"] == "ok" and vw["ra"]["n"] == 2 and vw["routers"][0]["mac"] == GW_MAC
    assert vw["routers"][0]["rdnss"] == ["2001:4860:4860::8888", GW_LL] and vw["routers"][0]["trusted"]
    assert [a["scope"] for a in vw["addrs"]] == ["link-local", "global"] and vw["addrs"][1]["kind"] == "temp"
    assert vw["inet"] == {"tcp": [{"host": h, "name": n, "ms": 20.0} for h, n in v.V6_TARGETS], "aaaa": True, "ok": True}
    assert {c[1] for c in net.calls if c[0] == "connect6"} == {h for h, _ in v.V6_TARGETS}
    devs = {d["ip"]: d for d in vw["devices"]}
    assert set(devs) == {P64 + "be24:11ff:fe3a:9c01", P64 + "14a6:998:4310:dfc0", "2a02:587:4c1a:2b00:211:32ff:fe8d:4410"}
    cam = devs[P64 + "be24:11ff:fe3a:9c01"]
    assert cam["eui64"] and cam["name"] == "cam.local" and cam["ip4"] == "192.168.1.30" and cam["src"] == "ndp"
    assert devs[P64 + "14a6:998:4310:dfc0"]["me"] and vw["counts"] == {"devices": 2, "eui64": 2, "rogue": 0}
    assert devs["2a02:587:4c1a:2b00:211:32ff:fe8d:4410"]["mac"] == "00:11:32:8d:44:10"      # MAC από το EUI-64
    assert vw["status"] == "unmanaged" and vw["verdict"]["level"] == "warn" and vw["ext_test"]["addr"] in devs
    ids = {c["id"]: c["level"] for c in vw["checklist"]}
    assert ids["ra"] == "ok" and ids["fw"] == "warn" and ids["eui"] == "warn" and ids["dev"] == "warn"
    # ο τεχνικός έκανε τη δοκιμή από έξω → «ελεγμένο»
    code, vw = g.api("POST", "confirm", {}, {"fw": True})
    assert code == 200 and vw["status"] == "managed" and vw["verdict"]["level"] == "ok"
    assert g.api("POST", "confirm", {}, {"fw": False})[1]["status"] == "unmanaged"
    assert "ipv6 nd raguard" in vw["config"] and "ipv6 dhcp guard" in vw["config_en"]


def test_active_check_ipv6_off_and_no_permission():
    g = v.V6Guard(State(), net=FakeNet(ok=False, addrs=[{"addr": "fe80::1", "iface": "en0", "flags": []}]))
    vw = g.check()
    assert vw["status"] == "off" and vw["ra"]["status"] == "none" and vw["inet"]["ok"] is False and vw["verdict"]["level"] == "ok"
    g = v.V6Guard(State(), net=FakeNet(boom=PermissionError("Operation not permitted")))
    vw = g.check()
    assert vw["ra"]["status"] == "err" and "root" in vw["ra"]["el"] and "root" in vw["ra"]["en"] and vw["busy"] is False
    g = v.V6Guard(State(), net=FakeNet(boom=ValueError("no such iface")))
    assert "no such iface" in g.check()["ra"]["el"]


def test_rogue_found_by_active_check_alerts():
    st = State(gw_mac=GW_MAC)
    g = v.V6Guard(st, net=FakeNet(frames=[ra_frame(), ra_frame(mac=BAD_MAC, src=BAD_LL, prf=1)]), clock=lambda: 100.0)
    vw = g.check()
    assert len(st.alerts) == 1 and vw["verdict"]["level"] == "bad" and vw["events"][0]["kind"] == "rogue_high"


def test_api_shapes():
    g = v.V6Guard(State(), net=FakeNet())
    assert g.api("GET", "", {}, {}) == (200, g.view()) and g.view()["demo"] is False
    assert g.api("GET", "nope", {}, {})[0] == 404 and g.api("POST", "nope", {}, {})[0] == 404
    code, vw = g.api("POST", "check", {}, {})
    assert code == 200 and vw["busy"] is True
    import json
    json.dumps(g.view())


def test_demo():
    import json
    g = v.V6Guard(None, demo=True, net=None, clock=lambda: 1_700_000_000.0)
    vw = g.view()
    json.dumps(vw)
    assert vw["demo"] and vw["status"] == "unmanaged" and vw["verdict"]["level"] == "bad"
    assert len(vw["devices"]) == 5 and vw["counts"]["eui64"] == 2 and vw["counts"]["devices"] == 5
    assert len(vw["routers"]) == 2 and vw["routers"][0]["mac"] == v._DM["rogue"] and not vw["routers"][0]["trusted"] and vw["routers"][1]["trusted"]
    assert len(vw["events"]) == 1 and vw["events"][0]["kind"] == "rogue_ra" and vw["inet"]["ok"]
    assert [a["kind"] for a in vw["addrs"]] == ["stable", "stable", "temp"]
    assert g.api("POST", "check", {}, {})[1]["checked"] == 1_700_000_000.0          # δεν αγγίζει το δίκτυο
    assert g.api("POST", "trust", {}, {"mac": v._DM["rogue"]})[1]["counts"]["rogue"] == 1   # το demo δεν αλλάζει
