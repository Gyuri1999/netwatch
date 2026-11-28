"""Tests για τη μηχανή ανίχνευσης του NetWatch (τρέχουν χωρίς root και χωρίς δίκτυο)."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import capture  # noqa: E402
import detect  # noqa: E402
import hunt  # noqa: E402
import netwatch as nw  # noqa: E402

ME, GW = "192.168.1.50", "192.168.1.1"
EVIL = "192.168.1.66"


@pytest.fixture
def state():
    s = nw.NetState("test", "test0", [ME], GW, geo=False, rdns=False)
    s.arp_table[GW] = s.arp_first[GW] = "a4:2b:b0:00:00:01"
    return s


class Clock:
    def __init__(self):
        self.t = 1_700_000_000.0

    def __call__(self, dt=0.01):
        self.t += dt
        return self.t


def feed(s, clock, **P):
    P.setdefault("len", 60)
    P["t"] = clock(P.pop("dt", 0.01))
    s.process(P)


def types(s):
    return {a["type"] for a in s.alerts}


# ---------------- κανονική κίνηση: χωρίς ψευδείς συναγερμούς ----------------
def test_normal_browsing_raises_no_alerts(state):
    c = Clock()
    for i in range(300):
        sp = 50000 + i
        dst = f"142.250.184.{i % 50 + 1}"
        feed(state, c, src=ME, dst=GW, proto="UDP", sp=sp, dp=53)
        feed(state, c, src=GW, dst=ME, proto="UDP", sp=53, dp=sp)
        feed(state, c, src=ME, dst=dst, proto="TCP", sp=sp, dp=443, flags="S")
        feed(state, c, src=dst, dst=ME, proto="TCP", sp=443, dp=sp, flags="SA")
        feed(state, c, src=dst, dst=ME, proto="UDP", sp=443, dp=sp, len=1300)  # QUIC
    assert list(state.alerts) == []


# ---------------- σαρώσεις ----------------
def test_tcp_port_scan(state):
    c = Clock()
    for port in range(1, 25):
        feed(state, c, src=EVIL, dst=ME, proto="TCP", sp=44444, dp=port, flags="S")
    a = next(a for a in state.alerts if a["type"] == "Port scan")
    assert a["actor"] == EVIL and a["sev"] == "high"
    assert a["mitre"]["id"] == "T1046"


def test_slow_scan_outside_window_is_ignored(state):
    c = Clock()
    for port in range(1, 25):
        feed(state, c, src=EVIL, dst=ME, proto="TCP", sp=44444, dp=port, flags="S", dt=1.0)
    assert "Port scan" not in types(state)


@pytest.mark.parametrize("flags,name", [("FPU", "XMAS"), ("", "NULL"), ("F", "FIN")])
def test_stealth_scans(state, flags, name):
    feed(state, Clock(), src=EVIL, dst=ME, proto="TCP", sp=1, dp=80, flags=flags)
    assert f"Stealth scan ({name})" in types(state)


def test_arp_sweep_does_not_create_phantom_hosts(state):
    c = Clock()
    for n in range(2, 60):
        feed(state, c, src=EVIL, dst=f"192.168.1.{n}", proto="ARP",
             arp=dict(op=1, psrc=EVIL, pdst=f"192.168.1.{n}", hwsrc="de:ad:be:ef:00:66"))
    assert "Network sweep (ARP)" in types(state)
    assert "192.168.1.30" not in state.hosts


# ---------------- επιθέσεις ----------------
def test_ssh_brute_force(state):
    c = Clock()
    for i in range(16):
        feed(state, c, src=EVIL, dst=ME, proto="TCP", sp=40000 + i, dp=22, flags="S", dt=0.5)
    a = next(a for a in state.alerts if a["type"] == "Brute force")
    assert a["mitre"]["tactic"] == "Credential Access"
    assert dict((k, v) for k, v, _ in state.ser(state.hosts[EVIL])["hits"])[22] == 16


def test_syn_flood(state):
    c = Clock()
    for i in range(310):
        feed(state, c, src=EVIL, dst=ME, proto="TCP", sp=1024 + i, dp=443, flags="S", dt=0.005)
    assert "SYN flood" in types(state)


def test_arp_spoofing_attributed_to_attacker_and_restore_is_quiet(state):
    c = Clock()
    evil_mac = "de:ad:be:ef:00:66"
    feed(state, c, src=EVIL, dst=GW, proto="ARP", arp=dict(op=2, psrc=EVIL, pdst=GW, hwsrc=evil_mac))
    feed(state, c, src=GW, dst=ME, proto="ARP", arp=dict(op=2, psrc=GW, pdst=ME, hwsrc=evil_mac))
    spoof = [a for a in state.alerts if a["type"].startswith("ARP spoofing")]
    assert len(spoof) == 1 and spoof[0]["actor"] == EVIL and spoof[0]["target"] == GW
    # ο πραγματικός router ξαναστέλνει τη σωστή MAC → όχι νέος συναγερμός, ο router δεν γίνεται «ύποπτος»
    feed(state, c, src=GW, dst=ME, proto="ARP", arp=dict(op=2, psrc=GW, pdst=ME, hwsrc="a4:2b:b0:00:00:01"), dt=120)
    assert len([a for a in state.alerts if a["type"].startswith("ARP spoofing")]) == 1
    assert state.hosts[GW]["threat"] == 0


def test_rogue_dhcp(state):
    feed(state, Clock(), src=EVIL, dst="255.255.255.255", proto="UDP", sp=67, dp=68)
    assert "Rogue DHCP server" in types(state)


def test_legit_dhcp_from_router_is_quiet(state):
    feed(state, Clock(), src=GW, dst="255.255.255.255", proto="UDP", sp=67, dp=68)
    assert list(state.alerts) == []


def test_unsolicited_dns_answer(state):
    c = Clock()
    feed(state, c, src=ME, dst=GW, proto="UDP", sp=5000, dp=53)
    feed(state, c, src=EVIL, dst=ME, proto="UDP", sp=53, dp=5000)
    assert "Ύποπτη απάντηση DNS" in types(state)


def test_alert_cooldown(state):
    c = Clock()
    for _ in range(5):
        feed(state, c, src=EVIL, dst=ME, proto="TCP", sp=1, dp=80, flags="FPU")
    assert len(state.alerts) == 1


# ---------------- MITRE ----------------
@pytest.mark.parametrize("typ,tid", [
    ("Port scan (UDP)", "T1046"), ("Network sweep (ping)", "T1018"), ("Brute force", "T1110.001"),
    ("ARP spoofing (ROUTER)", "T1557.002"), ("Rogue DHCP server", "T1557.003"), ("SYN flood", "T1498.001"),
])
def test_mitre_mapping(typ, tid):
    m = nw.mitre_for(typ)
    assert m["id"] == tid
    assert m["url"].startswith("https://attack.mitre.org/techniques/T")


# ---------------- parsers ----------------
def test_parse_sni():
    from make_sample_pcap import client_hello
    assert nw.parse_sni(client_hello("github.com")) == "github.com"
    assert nw.parse_sni(b"\x16\x03\x01garbage") is None
    assert nw.parse_sni(b"") is None


def test_scapy_parser_dns_and_flags():
    from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether
    parse = nw.make_parser()
    pkt = Ether(bytes(Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="8.8.8.8", dst=ME) / UDP(sport=53, dport=5555) /
                      DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34"))))
    P = parse(pkt)
    assert P["proto"] == "UDP" and ("example.com", "93.184.216.34") in P["dns"]
    P = parse(Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=EVIL, dst=ME) / TCP(flags="FPU"))
    assert P["flags"] == "FPU"


def test_ip_kind():
    assert nw.ip_kind("8.8.8.8") == "public"
    assert nw.ip_kind("192.168.1.5") == "local"
    assert nw.ip_kind("224.0.0.251") == "bcast"
    assert nw.ip_kind("not-an-ip") == "other"


# ---------------- end-to-end με pcap ----------------
def test_pcap_replay_end_to_end(tmp_path):
    from make_sample_pcap import build
    path = str(tmp_path / "attack.pcap")
    build(path)
    me, gw = nw.pcap_guess(path)
    assert (me, gw) == (ME, GW)
    s = nw.NetState("pcap", "attack.pcap", [me], gw, geo=False, rdns=False)
    nw.pcap_replay(s, path, speed=0)
    expected = {"Network sweep (ARP)", "Port scan", "Stealth scan (XMAS)", "Brute force",
                "ARP spoofing (ROUTER)", "Rogue DHCP server", "Ύποπτη απάντηση DNS", "SYN flood",
                "DNS tunneling", "DGA domains", "Νέα συσκευή"}
    assert expected <= types(s)
    assert {a["actor"] for a in s.alerts if a["type"] not in ("Νέα συσκευή", "Κωδικός σε καθαρό κείμενο")} == {EVIL}
    leaks = [a for a in s.alerts if a["type"] == "Κωδικός σε καθαρό κείμενο"]
    assert {a["target"] for a in leaks} == {GW, "192.168.1.20"} and all(a["actor"] == ME for a in leaks)
    assert not any("not-a-real-password" in a["detail"] for a in s.alerts)
    au = s.audit()
    assert {(x["ip"], x["port"]) for x in au["services"]} >= {(GW, 80), ("192.168.1.20", 21)}
    assert {c["proto"] for c in au["creds"]} == {"HTTP Basic", "FTP"}
    assert next(a for a in s.alerts if a["type"] == "Νέα συσκευή")["actor"] == "192.168.1.88"
    assert s.hosts[ME]["ja3"], "JA3 should be extracted from the ClientHello"
    assert "github.com" in s.hosts["140.82.121.4"]["names"]  # από DNS + TLS SNI


# ---------------- beaconing (C2) ----------------
def test_beaconing_detected(state):
    c = Clock()
    c2 = "185.100.87.1"
    for i in range(10):
        feed(state, c, src=ME, dst=c2, proto="TCP", sp=50000 + i, dp=8443, flags="S", dt=60 + (i % 3) * 0.5)
    a = next(a for a in state.alerts if a["type"].startswith("Beaconing"))
    assert a["actor"] == c2 and a["target"] == ME and a["mitre"]["id"] == "T1071"


def test_dns_resolver_is_not_beaconing(state):
    c = Clock()
    for dst, dp in (("1.1.1.1", 443), ("8.8.8.8", 853), ("9.9.9.9", 443)):  # DoH/DoT κάθε ~30s, πολύ «ρολόι»
        for i in range(12):
            feed(state, c, src=ME, dst=dst, proto="TCP", sp=50000 + i, dp=dp, flags="S", dt=30)
    assert not any(a["type"].startswith("Beaconing") for a in state.alerts)


def test_irregular_browsing_is_not_beaconing(state):
    import random
    rnd = random.Random(1)
    c = Clock()
    for i in range(30):
        feed(state, c, src=ME, dst="142.250.184.110", proto="TCP", sp=50000 + i, dp=443, flags="S",
             dt=rnd.uniform(2, 120))
    assert not any(a["type"].startswith("Beaconing") for a in state.alerts)


# ---------------- DNS tunneling / DGA ----------------
def test_dns_tunneling(state):
    c = Clock()
    for i in range(32):
        sub = f"{i:02x}" + "a9f3c1e7b2d4806f5e1c3a7b9d2f4e6a"[i % 7:] + "0b1c2d3e"
        feed(state, c, src=ME, dst=GW, proto="UDP", sp=40000 + i, dp=53, dns_q=(f"{sub}.t.evil.example", 16))
    a = next(a for a in state.alerts if a["type"] == "DNS tunneling")
    assert a["target"] == "evil.example" and a["mitre"]["id"] == "T1071.004"


def test_normal_dns_is_not_tunneling(state):
    c = Clock()
    for i in range(60):
        feed(state, c, src=ME, dst=GW, proto="UDP", sp=40000 + i, dp=53,
             dns_q=(["www.google.com", "i.ytimg.com", "graph.facebook.com", "api.github.com"][i % 4], 1))
    assert "DNS tunneling" not in types(state)


def test_dga_nxdomain_burst(state):
    c = Clock()
    for name in ["xk3j9qz7lpwe", "qz8mt2vkx9rp", "b7x2kq9zmtw4", "pl0zq8xv3nkr", "w9tqz2xk7mbv",
                 "z4kx8qv2mtpr", "k2zq9xv7nwt3", "v8xq2zk9mtb5", "r7q2xz9kvmt8"]:
        feed(state, c, src=GW, dst=ME, proto="UDP", sp=53, dp=40000, nx=name + ".com")
    a = next(a for a in state.alerts if a["type"] == "DGA domains")
    assert a["actor"] == ME and a["mitre"]["id"] == "T1568.002"


def test_typos_are_not_dga(state):
    c = Clock()
    for name in ["gooogle", "facebok", "wikipeida", "amazom", "micorsoft", "youtub", "netflx", "githbu", "redit"]:
        feed(state, c, src=GW, dst=ME, proto="UDP", sp=53, dp=40000, nx=name + ".com")
    assert "DGA domains" not in types(state)


@pytest.mark.parametrize("label,is_dga", [("xk3j9qz7lpwe", True), ("google", False), ("microsoftonline", False),
                                          ("nflxvideo", False), ("qz8mt2vkx9rp", True)])
def test_dga_score(label, is_dga):
    assert (nw.dga_score(label) >= 0.6) == is_dga


def test_split_domain():
    assert nw.split_domain("a.b.example.com") == ("example.com", "a.b")
    assert nw.split_domain("www.bbc.co.uk") == ("bbc.co.uk", "www")


# ---------------- new devices ----------------
def test_new_device_after_warmup(state):
    c = Clock()
    feed(state, c, src="192.168.1.20", dst="224.0.0.251", proto="UDP", sp=5353, dp=5353, smac="f0:de:f1:00:00:20")
    feed(state, c, src="192.168.1.88", dst="224.0.0.251", proto="UDP", sp=5353, dp=5353, smac="6a:3e:51:00:00:88",
         dt=120)
    new = [a for a in state.alerts if a["type"] == "Νέα συσκευή"]
    assert [a["actor"] for a in new] == ["192.168.1.88"]  # η πρώτη ήταν στο warm-up
    assert "τυχαία MAC" in new[0]["detail"]


def test_known_device_from_history_is_quiet(tmp_path):
    db = str(tmp_path / "h.db")
    h = nw.History(db)
    h.device_seen("6a:3e:51:00:00:88", "192.168.1.88", 1.0)
    s = nw.NetState("test", "t", [ME], GW, geo=False, rdns=False, history=nw.History(db))
    feed(s, Clock(), src="192.168.1.88", dst="224.0.0.251", proto="UDP", sp=5353, dp=5353, smac="6a:3e:51:00:00:88")
    feed(s, Clock(), src="192.168.1.99", dst="224.0.0.251", proto="UDP", sp=5353, dp=5353, smac="00:11:22:33:44:99")
    assert [a["actor"] for a in s.alerts if a["type"] == "Νέα συσκευή"] == ["192.168.1.99"]


# ---------------- threat intel ----------------
def test_intel_parsing_and_lookup():
    nets = {}
    text = "# comment\n1.2.3.0/24\n5.6.7.8\n10.0.0.0/8\n" + '{"cidr":"9.9.0.0/16","sblid":"x"}\n{"type":"metadata"}\n'
    assert nw.Intel.parse(text, {"name": "t", "kind": "block"}, nets) == 3  # 10/8 (bogon) αγνοείται
    i = nw.Intel()
    i.nets = nets
    assert i.lookup("1.2.3.200")[0]["name"] == "t"
    assert i.lookup("5.6.7.8") and i.lookup("9.9.255.1")
    assert not i.lookup("5.6.7.9") and not i.lookup("10.1.1.1")


def test_contact_with_c2_from_intel(state):
    state.intel.add("185.100.87.0/24", "Feodo Tracker", "c2")
    feed(state, Clock(), src=ME, dst="185.100.87.5", proto="TCP", sp=50000, dp=443, flags="S")
    a = next(a for a in state.alerts if a["type"] == "Σύνδεση σε κακόβουλη IP")
    assert a["sev"] == "high" and a["actor"] == "185.100.87.5"
    assert state.ser(state.hosts["185.100.87.5"])["intel"][0]["kind"] == "c2"


# ---------------- config / allowlist ----------------
def test_config_overrides_and_allowlist(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("thresholds:\n  port_scan: {count: 5}\nallowlist:\n  ips: ['192.168.1.30']\n"
                 "detectors:\n  stealth_scan: false\n")
    cfg = nw.load_config(str(p))
    assert cfg["thresholds"]["port_scan"] == {"count": 5, "window": 10}  # deep merge κρατά το window
    s = nw.NetState("test", "t", [ME], GW, geo=False, rdns=False, cfg=cfg)
    c = Clock()
    for port in range(1, 7):
        feed(s, c, src=EVIL, dst=ME, proto="TCP", sp=1, dp=port, flags="S")
        feed(s, c, src="192.168.1.30", dst=ME, proto="TCP", sp=1, dp=port, flags="S")
    feed(s, c, src=EVIL, dst=ME, proto="TCP", sp=1, dp=80, flags="FPU")
    assert {a["actor"] for a in s.alerts if a["type"] == "Port scan"} == {EVIL}
    assert not any(a["type"].startswith("Stealth") for a in s.alerts)


# ---------------- JA3 / history ----------------
def test_ja3_fingerprint_is_stable_and_ignores_sni():
    from make_sample_pcap import client_hello
    a, b = nw.parse_client_hello(client_hello("github.com")), nw.parse_client_hello(client_hello("example.org"))
    assert a["sni"] == "github.com" and len(a["ja3"]) == 32
    assert a["ja3"] == b["ja3"]  # ίδιο πρόγραμμα → ίδιο JA3, άσχετα με το site
    assert a["ja3_str"].startswith("771,4865,")


def test_history_persists_alerts(tmp_path, state):
    db = str(tmp_path / "h.db")
    s = nw.NetState("test", "t", [ME], GW, geo=False, rdns=False, history=nw.History(db))
    feed(s, Clock(), src=EVIL, dst=ME, proto="TCP", sp=1, dp=80, flags="FPU")
    q = nw.History(db).query(hours=24, ref=1_700_000_100)
    assert q["total_alerts"] == 1 and q["alerts"][0]["mitre"] == "T1046"
    assert q["by_hour"] and q["by_hour"][0][1] == "high"


# ---------------- κωδικοί σε καθαρό κείμενο / έλεγχος ασφάλειας ----------------
SECRET = "Sup3rSecret!"


@pytest.mark.parametrize("dp,payload,proto,user", [
    (21, b"USER nikos\r\n", "FTP", "nikos"),
    (110, b"USER mail@example.com\r\n", "POP3", "mail@example.com"),
    (143, b'a1 LOGIN "nikos" ' + SECRET.encode() + b"\r\n", "IMAP", "nikos"),
    (25, b"AUTH PLAIN " + __import__("base64").b64encode(b"\0nikos\0" + SECRET.encode()) + b"\r\n", "SMTP", "nikos"),
    (80, b"GET / HTTP/1.1\r\nHost: r\r\nAuthorization: Basic " +
     __import__("base64").b64encode(b"admin:" + SECRET.encode()) + b"\r\n\r\n", "HTTP Basic", "admin"),
    (8080, b"POST /login HTTP/1.1\r\nHost: r\r\n\r\nusername=nikos%40x.gr&password=" + SECRET.encode(),
     "HTTP φόρμα", "nikos@x.gr"),
])
def test_parse_cleartext_finds_login_but_never_keeps_password(dp, payload, proto, user):
    r = nw.parse_cleartext(50000, dp, payload)
    assert r["proto"] == proto and r.get("user") == user
    assert SECRET not in repr(r)


def test_parse_cleartext_ignores_normal_traffic():
    assert nw.parse_cleartext(50000, 80, b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n") is None
    assert nw.parse_cleartext(50000, 8080, b"POST /search HTTP/1.1\r\n\r\nq=passwords") is None
    assert nw.parse_cleartext(50000, 443, b"\x16\x03\x01binary") is None
    assert nw.parse_cleartext(50000, 21, b"LIST\r\n") is None


def test_ftp_login_alert_masks_user_and_does_not_mark_victim(state):
    c = Clock()
    nas = "192.168.1.40"
    feed(state, c, src=ME, dst=nas, proto="TCP", sp=50000, dp=21, flags="PA",
         cred=nw.parse_cleartext(50000, 21, b"USER nikolas\r\n"))
    feed(state, c, src=ME, dst=nas, proto="TCP", sp=50000, dp=21, flags="PA",
         cred=nw.parse_cleartext(50000, 21, b"PASS " + SECRET.encode() + b"\r\n"))
    a = next(a for a in state.alerts if a["type"] == "Κωδικός σε καθαρό κείμενο")
    assert a["actor"] == ME and a["target"] == nas and a["mitre"]["id"] == "T1040"
    assert "ni***" in a["detail"] and "nikolas" not in a["detail"] and SECRET not in a["detail"]
    assert state.hosts[ME]["threat"] == 0  # δεν «βάφουμε» κόκκινο το θύμα


def test_audit_scores_risky_services_and_leaks(state):
    c = Clock()
    assert state.audit()["score"] == 100
    cam = "192.168.1.30"
    feed(state, c, src=cam, dst=ME, proto="TCP", sp=23, dp=50000, flags="SA", smac="c0:56:e3:30:30:30")
    feed(state, c, src=GW, dst=ME, proto="TCP", sp=443, dp=50001, flags="SA")
    feed(state, c, src=ME, dst=cam, proto="TCP", sp=50000, dp=23, flags="PA", cred={"proto": "Telnet", "field": "session"})
    au = state.audit()
    by = {x["id"]: x for x in au["checks"]}
    assert by["services"]["status"] == "bad" and by["creds"]["status"] == "bad"
    tel = next(x for x in au["services"] if x["port"] == 23)
    assert tel["ip"] == cam and tel["risk"] == "high"
    assert next(x for x in au["services"] if x["port"] == 443)["risk"] == "info"
    assert au["score"] < 80 and au["grade"] in "BCDF"


# ---------------- pentest: σαρωτής, lab, endpoints ----------------
import json  # noqa: E402
import socket  # noqa: E402
import threading  # noqa: E402
import urllib.request  # noqa: E402

import pentest  # noqa: E402


@pytest.mark.parametrize("banner,expected", [
    ("SSH-2.0-OpenSSH_7.4", ("OpenSSH", "7.4")),
    ("SSH-2.0-dropbear_2017.75", ("Dropbear SSH", "2017.75")),
    ("220 (vsFTPd 2.3.4)", ("vsftpd", "2.3.4")),
    ("HTTP/1.1 200 OK\r\nServer: Apache/2.2.15 (CentOS)", ("Apache httpd", "2.2.15")),
    ("HTTP/1.1 200 OK\r\nServer: AcmeCam", ("AcmeCam", None)),
    ("", (None, None)),
])
def test_parse_banner(banner, expected):
    assert pentest.parse_banner(banner) == expected


@pytest.mark.parametrize("target", ["8.8.8.8", "1.1.1.0/24", "127.0.0.1", "10.0.0.0/8", "nonsense", "fe80::1"])
def test_scanner_refuses_public_huge_or_invalid_targets(target):
    with pytest.raises(ValueError):
        pentest.check_target(target)


def test_scanner_accepts_private_lan():
    assert len(pentest.check_target("192.168.1.0/24")) == 254
    assert pentest.check_target("10.0.0.7") == ["10.0.0.7"]


def test_grab_reads_banner_from_open_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        c, _ = srv.accept()
        c.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
        c.close()
    threading.Thread(target=serve, daemon=True).start()
    assert pentest.grab("127.0.0.1", port).startswith("SSH-2.0-OpenSSH_8.9p1")
    srv.close()
    assert pentest.grab("127.0.0.1", port, timeout=0.3) is None  # κλειστή θύρα


class FakeTime:
    def __init__(self):
        self.t = 1_700_000_000.0

    def time(self):
        return self.t

    def sleep(self, s):
        self.t += s


def run_lab(state, kind, variant, monkeypatch):
    ft = FakeTime()
    monkeypatch.setattr(pentest, "time", ft)
    lab = pentest.Lab(state)
    lab.run = {"status": "running", "kind": kind, "variant": variant, "started": ft.time(), "pkts": 0,
               "first_alert": state.alert_seq, "rule": lab.rule(kind)}
    lab._go(kind, variant)
    return lab.status()


@pytest.mark.parametrize("kind", list(pentest.LAB_SCENARIOS))
def test_lab_loud_attacks_are_detected(state, kind, monkeypatch):
    r = run_lab(state, kind, "loud", monkeypatch)
    assert r["status"] == "done" and r["pkts"] > 0
    assert r["detected"], f"{kind}: {[a['type'] for a in r['alerts']]}"
    assert all(a["lab"] for a in r["alerts"])


@pytest.mark.parametrize("kind", [k for k, s in pentest.LAB_SCENARIOS.items() if s["quiet"]])
def test_lab_quiet_attacks_slip_under_thresholds(state, kind, monkeypatch):
    r = run_lab(state, kind, "quiet", monkeypatch)
    assert r["pkts"] > 0 and not r["detected"]


def test_lab_alerts_stay_out_of_history_and_audit(state, monkeypatch):
    run_lab(state, "xmas", "loud", monkeypatch)
    assert any(a["lab"] for a in state.alerts)
    assert state.history.query(hours=24 * 365 * 10, ref=2_000_000_000)["total_alerts"] == 0
    assert next(c for c in state.audit()["checks"] if c["id"] == "attacks")["status"] == "ok"
    assert not any(a["type"] == "Νέα συσκευή" for a in state.alerts)


def test_demo_scan_feeds_audit(state, monkeypatch):
    monkeypatch.setattr(nw.time, "sleep", lambda s: None)
    state.scanner = pentest.LanScanner(sim=nw.demo_scan)
    state.scanner.on_result = state.scan_result
    state.scanner.start("192.168.1.0/24")
    for _ in range(200):
        if state.scanner.status()["status"] != "running":
            break
        threading.Event().wait(0.01)
    v = state.scan_view()
    assert v["status"] == "done"
    by = {h["ip"]: h for h in v["hosts"]}
    ftp = next(s for s in by["192.168.1.40"]["services"] if s["port"] == 21)
    assert (ftp["product"], ftp["version"], ftp["risk"]) == ("vsftpd", "2.3.4", "high")
    assert next(s for s in by["192.168.1.77"]["services"] if s["port"] == 4444)["risk"] == "high"
    tls = next(s for s in by["192.168.1.1"]["services"] if s["port"] == 443)
    assert tls["risk"] == "high" and "TLSv1" in tls["why"]
    au = state.audit()
    assert any(s["port"] == 23 and s["ip"] == "192.168.1.30" for s in au["services"])
    assert next(c for c in au["checks"] if c["id"] == "services")["status"] == "bad"


@pytest.fixture
def server(state):
    from http.server import ThreadingHTTPServer
    state.lab = pentest.Lab(state)
    state.scanner = pentest.LanScanner()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), nw.make_handler(state))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _post(url, body, headers):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_post_endpoints_block_cross_site_requests(server):
    ok = {"Content-Type": "application/json"}
    assert _post(server + "/api/lab", {"kind": "xmas", "variant": "loud"}, {"Content-Type": "text/plain"})[0] == 403
    assert _post(server + "/api/lab", {"kind": "xmas", "variant": "loud"},
                 {**ok, "Origin": "https://evil.example"})[0] == 403
    assert _post(server + "/api/scan", {"target": "8.8.8.0/24"}, ok)[0] == 400
    assert _post(server + "/api/lab", {"kind": "nope", "variant": "loud"}, ok)[0] == 400
    assert _post(server + "/api/lab", {"kind": "xmas", "variant": "loud"}, ok) == (200, {"ok": True})


# ---------------- κανόνες (detection engineering) ----------------
import rules as R  # noqa: E402
import ctf  # noqa: E402


def P_(**kw):
    kw.setdefault("t", 1.0)
    kw.setdefault("len", 60)
    return kw


CTX = {"me": {ME}, "gw": GW, "kind": nw.ip_kind}


def test_rule_matching_ip_keywords_ports_and_negation():
    r = R.parse_rules("""
id: lan-to-net-high
match:
  src: [local, "!192.168.1.1"]
  dst: public
  proto: TCP
  dport: ["4000-4500", 6667]
  flags: S
""")[0]
    ok = P_(src="192.168.1.20", dst="185.1.2.3", proto="TCP", sp=5000, dp=4444, flags="S")
    assert r.matches(ok, CTX)
    assert not r.matches({**ok, "src": GW}, CTX)            # αρνητικό
    assert not r.matches({**ok, "dst": "192.168.1.9"}, CTX)  # όχι public
    assert not r.matches({**ok, "dp": 443}, CTX)
    assert not r.matches({**ok, "flags": "SA"}, CTX)
    me = R.parse_rules("id: from-me\nmatch: {src: me, dns_query: '*.xyz'}")[0]
    assert me.matches(P_(src=ME, dst=GW, proto="UDP", dns_q=("evil.XYZ", 1)), CTX)
    assert not me.matches(P_(src=ME, dst=GW, proto="UDP", dns_q=("good.com", 1)), CTX)


@pytest.mark.parametrize("text,msg", [
    ("id: a\nmatch: {proto: TCP}", "id"),
    ("id: ok-id\nmatch: {colour: red}", "Άγνωστα πεδία στο match"),
    ("id: ok-id\nmatch: {dport: 70000}", "Θύρα"),
    ("id: ok-id\nmatch: {src: 'not-an-ip'}", "IP"),
    ("id: ok-id\nseverity: extreme\nmatch: {proto: TCP}", "severity"),
    ("id: ok-id\nmatch: {proto: TCP}\nthreshold: {by: port}", "threshold.by"),
    ("id: ok-id\nmatch: {proto: TCP}\nthreshold: {distinct: password}", "distinct"),
    ("id: ok-id\n", "match"),
    ("id: [unclosed", "YAML"),
])
def test_rule_validation_errors_are_clear(text, msg):
    with pytest.raises(R.RuleError, match=msg):
        R.parse_rules(text)


def test_rule_threshold_distinct_counts_unique_values():
    r = R.parse_rules("id: many-ports\nmatch: {proto: TCP, flags: S}\n"
                      "threshold: {count: 5, window: 60, by: src, distinct: dport}")[0]
    fired = []
    eng = R.RuleEngine([r], ctx=CTX, alert=lambda *a: fired.append(a[1]))
    for i in range(10):  # ίδια θύρα 10 φορές → τίποτα
        eng.check(P_(t=i, src=ME, dst="1.2.3.4", proto="TCP", sp=1, dp=443, flags="S"), i)
    assert not fired
    for i in range(5):
        eng.check(P_(t=20 + i, src=EVIL, dst=ME, proto="TCP", sp=1, dp=100 + i, flags="S"), 20 + i)
    assert fired == [EVIL]


def test_rule_exports_to_sigma_and_suricata():
    import yaml
    r = R.parse_rules("""
id: tv-backdoor
title: TV σε backdoor
severity: high
mitre: T1571
match: {src: 192.168.1.10, dst: public, proto: TCP, dport: [4444, 6667], flags: S}
threshold: {count: 3, window: 60, by: src}
""")[0]
    sig = yaml.safe_load(r.to_sigma())
    assert sig["level"] == "high" and sig["tags"] == ["attack.t1571"]
    sel = sig["detection"]["selection"]
    assert sel["src_ip|cidr"] == "192.168.1.10/32" and sel["dst_port"] == [4444, 6667]
    assert "count() by src_ip >= 3" in sig["detection"]["condition"]
    suri = R.to_suricata(r, 9000001)
    assert suri.startswith("alert tcp 192.168.1.10/32 any -> $EXTERNAL_NET [4444,6667] (")
    assert "flags:S;" in suri and "track by_src, count 3, seconds 60" in suri and "sid:9000001;" in suri
    dns = R.parse_rules("id: tld\nmatch: {dns_query: '*.xyz'}")[0]
    assert 'alert dns' in R.to_suricata(dns, 1) and 'dns.query; content:".xyz"; nocase; endswith;' in R.to_suricata(dns, 1)


def test_default_rules_load_and_fire_with_mitre(state):
    state.reload_rules()
    assert {r.id for r in state.rules.rules} >= {"telnet-connection", "smb-to-internet"}
    assert not state.rule_errors
    feed(state, Clock(), src=ME, dst="192.168.1.30", proto="TCP", sp=50000, dp=23, flags="S")
    a = next(a for a in state.alerts if a["type"] == "Κανόνας: Σύνδεση Telnet")
    assert a["mitre"]["id"] == "T1021" and a["mitre"]["tactic"] == "Lateral Movement"


def test_rule_test_save_and_delete(state, tmp_path, monkeypatch):
    monkeypatch.setattr(detect, "RULES_DIR", str(tmp_path))
    c = Clock()
    for p in range(1, 8):
        feed(state, c, src=EVIL, dst=ME, proto="TCP", sp=1, dp=p, flags="S")
    text = "id: my-scan\nmatch: {proto: TCP, flags: S}\nthreshold: {count: 5, window: 60, distinct: dport}"
    res = state.test_rules(text)
    assert res["matches"]["my-scan"] == 7 and res["alerts"][0]["actor"] == EVIL and res["alerts"][0]["n"] == 3
    assert not any(a["type"].startswith("Κανόνας") for a in state.alerts)  # η δοκιμή δεν βγάζει ειδοποιήσεις
    assert state.save_rule(text) == ["my-scan"]
    assert [r.id for r in state.rules.rules] == ["my-scan"]
    state.save_rule(text.replace("count: 5", "count: 6"))  # ίδιο id → αντικατάσταση
    assert len(state.rules.rules) == 1 and state.rules.rules[0].threshold["count"] == 6
    state.delete_rule("my-scan")
    assert state.rules.rules == []


# ---------------- CTF ----------------
CTF_ANSWERS = {("l1", "q1"): "192.168.1.66", ("l1", "q7"): "T1557.002 ", ("l2", "q1"): "192.168.1.20",
               ("l2", "q3"): "30s", ("l2", "q4"): "K3JD9FH2LQ.example", ("l3", "q1"): "192.168.1.77",
               ("l3", "q3"): "445, 22"}


def test_ctf_answers_are_hashed_and_checked():
    raw = open(ctf.CTF_FILE, encoding="utf-8").read()
    assert "192.168.1.66" not in raw and "k3jd9fh2lq" not in raw  # δεν «προδίδονται»
    for (lv, q), ans in CTF_ANSWERS.items():
        assert ctf.check(lv, q, ans), (lv, q)
    assert not ctf.check("l1", "q1", "192.168.1.1")
    assert all("answers" not in q for lv in ctf.public() for q in lv["questions"])


def test_ctf_generator_is_reproducible(tmp_path):
    import make_ctf
    make_ctf.build(str(tmp_path))
    for name in ("level2-silent-visitor.pcap", "level3-patient-scanner.pcap"):
        assert open(tmp_path / name, "rb").read() == open(os.path.join(ROOT, "ctf", name), "rb").read()
    assert json.load(open(tmp_path / "challenges.json")) == ctf.load()


def test_ctf_level2_alerts_tell_the_story():
    lv = ctf.level("l2")
    s = nw.NetState("pcap", "l2", [lv["me"]], lv["gw"], geo=False, rdns=False)
    nw.pcap_replay(s, os.path.join(ROOT, lv["pcap"]), speed=0)
    t = {a["type"].split(" (")[0]: a for a in s.alerts}
    assert t["DGA domains"]["actor"] == "192.168.1.20"
    assert t["Beaconing"]["target"] == "192.168.1.20" and "~30s" in t["Beaconing"]["detail"]


def test_ctf_level3_is_silent_and_rule_challenge_needs_precision():
    lv = ctf.level("l3")
    s = nw.NetState("pcap", "l3", [lv["me"]], lv["gw"], geo=False, rdns=False)
    s.reload_rules()
    nw.pcap_replay(s, os.path.join(ROOT, lv["pcap"]), speed=0)
    assert not s.alerts, [a["type"] for a in s.alerts]  # οι ανιχνευτές δεν βλέπουν τίποτα
    good = "id: slow-scan\nmatch: {proto: TCP, flags: S}\nthreshold: {count: 10, window: 120, distinct: dport}"
    assert nw.ctf_check_rule("l3", "rule", good)["correct"]
    naive = nw.ctf_check_rule("l3", "rule", "id: syn-count\nmatch: {proto: TCP, flags: S}\n"
                                            "threshold: {count: 15, window: 120}")
    assert not naive["correct"] and len(naive["actors"]) > 1  # false positives
    assert not nw.ctf_check_rule("l3", "rule", "id: nothing\nmatch: {dport: 1}")["correct"]


def test_ctf_load_and_exit_switch_the_data_source(state, monkeypatch):
    monkeypatch.setattr(capture, "pcap_replay", lambda st, path, speed=1.0, **k: None)
    seeded = []
    state.reload_rules()
    feed(state, Clock(), src=EVIL, dst=ME, proto="TCP", sp=1, dp=80, flags="FPU")
    state.origin = {"mode": "test", "iface": "test0", "me": [ME], "gw": GW, "history": state.history,
                    "notifier": None, "start": None, "seed": lambda: seeded.append(1)}
    token = state.feed_token
    nw.ctf_load(state, "l2")
    assert state.feed == "ctf" and state.ctf_level == "l2" and not state.alerts and state.feed_token == token + 1
    assert state.rules.rules  # οι κανόνες κρατιούνται
    nw.ctf_exit(state)
    assert state.feed == "test" and state.ctf_level is None and seeded == [1]
    assert state.history.query(hours=24, ref=1_700_000_100)["total_alerts"] == 1  # το ιστορικό κρατήθηκε


def _mqtt_connect(user=b"garden", pw=SECRET.encode(), level=4, will=False, cid=b"esp32-garden"):
    s = lambda x: len(x).to_bytes(2, "big") + x  # noqa: E731
    flags = (0x80 if user else 0) | (0x40 if pw else 0) | (0x04 if will else 0) | 0x02
    var = s(b"MQTT") + bytes([level, flags]) + b"\x00\x3c" + (b"\x00" if level == 5 else b"")
    pay = s(cid) + ((b"\x00" if level == 5 else b"") + s(b"lwt/topic") + s(b"offline") if will else b"")
    pay += (s(user) if user else b"") + (s(pw) if pw else b"")
    body = var + pay
    return b"\x10" + bytes([len(body)]) + body


@pytest.mark.parametrize("kw", [{}, {"level": 5}, {"will": True}, {"level": 5, "will": True}])
def test_parse_mqtt_connect_sees_user_never_keeps_password(kw):
    r = nw.parse_cleartext(50000, 1883, _mqtt_connect(**kw))
    assert r == {"proto": "MQTT", "field": "pass", "user": "garden", "client": "esp32-garden"}
    assert SECRET not in repr(r)


def test_parse_mqtt_connect_without_credentials_or_garbage():
    assert nw.parse_cleartext(50000, 1883, _mqtt_connect(user=None, pw=None)) is None
    assert nw.parse_cleartext(50000, 1883, _mqtt_connect(pw=None))["field"] == "user_only"
    assert nw.parse_cleartext(50000, 1883, b"\x30\x0a\x00\x04test{}") is None  # PUBLISH, όχι CONNECT
    assert nw.parse_cleartext(50000, 1883, b"\x10\xff\xff") is None


def test_mqtt_cleartext_alert(state):
    c = Clock()
    feed(state, c, src="192.168.1.20", dst="192.168.1.17", proto="TCP", sp=50000, dp=1883, flags="PA",
         cred=nw.parse_cleartext(50000, 1883, _mqtt_connect()))
    a = [a for a in state.alerts if a["type"] == "Κωδικός σε καθαρό κείμενο"]
    assert a and a[0]["sev"] == "high" and "MQTT" in a[0]["detail"] and "8883" in a[0]["detail"]
    assert SECRET not in a[0]["detail"]


def test_tor_exit_feed_alerts(state):
    state.intel.add("185.220.101.5/32", "Tor exit κόμβοι", kind="tor")
    c = Clock()
    feed(state, c, src="192.168.1.20", dst="185.220.101.5", proto="TCP", sp=50000, dp=443, flags="S")
    feed(state, c, src="185.220.101.5", dst=ME, proto="TCP", sp=40000, dp=22, flags="S")
    types = {a["type"]: a for a in state.alerts}
    assert "Tor από συσκευή του δικτύου" in types and types["Tor από συσκευή του δικτύου"]["sev"] == "med"
    assert "Κίνηση από κόμβο Tor" in types
    assert not any("κακόβουλη IP" in a["type"] for a in state.alerts)  # Tor ≠ κακόβουλο


def test_lan_device_on_tor_port(state):
    c = Clock()
    feed(state, c, src="192.168.1.20", dst="51.15.0.1", proto="TCP", sp=50000, dp=9001, flags="S")
    assert any(a["type"] == "Tor από συσκευή του δικτύου" and a["actor"] == "192.168.1.20" for a in state.alerts)


# ---------------- «το έκανα εγώ» ή «κάποιος άλλος»; ----------------
def _scan(s, c, src, dst):
    for port in range(1, 25):
        feed(s, c, src=src, dst=dst, proto="TCP", sp=44444, dp=port, flags="S")
    return next(a for a in s.alerts if a["type"] == "Port scan" and a["actor"] == src)


def test_own_tool_scan_is_marked_as_your_test(state):
    state.note_own_tool("έλεγχος θυρών (🔴 Pentest)", seconds=60)
    state.alert("Port scan", "high", ME, EVIL, "δοκιμή", Clock()())
    a = state.alerts[0]
    assert a["selftest"] == "έλεγχος θυρών (🔴 Pentest)"
    assert state.status()["alerts"] == 0  # δεν μετρά ως συναγερμός
    assert state.hosts[ME]["threat"] == 0


def test_declared_test_device(state):
    state.test_from(EVIL, 30, "nmap από το Kali")
    a = _scan(state, Clock(), EVIL, ME)
    assert a["selftest"] == "nmap από το Kali"
    assert state.selftest_status()["test_ips"][0]["ip"] == EVIL
    state.test_from(EVIL, 0)
    assert state.selftest_status()["test_ips"] == []


def test_own_scan_touching_a_suspect_port_is_your_test(state):
    """Βρέθηκε live: η σάρωση του NetWatch ρωτά τη θύρα 4444 κάθε συσκευής → «συνδέθηκες σε θύρα Metasploit».
    «Δράστης» της ειδοποίησης είναι η άλλη συσκευή, αλλά το πακέτο το έστειλε η δική μας σάρωση."""
    state.note_own_tool("η σάρωση του NetWatch (🔴 Pentest)", seconds=60)
    feed(state, Clock(), src=ME, dst=GW, proto="TCP", sp=50000, dp=4444, flags="S")
    a = next(x for x in state.alerts if x["type"] == "Ύποπτη εξερχόμενη θύρα")
    assert a["actor"] == GW and a["selftest"] == "η σάρωση του NetWatch (🔴 Pentest)"
    assert state.status()["alerts"] == 0 and state.hosts[GW]["threat"] == 0   # ούτε συναγερμός, ούτε «κόκκινη» συσκευή


def test_real_connection_to_a_suspect_port_still_alerts(state):
    """Χωρίς δική σου σάρωση, η ίδια κίνηση παραμένει κανονική ειδοποίηση."""
    feed(state, Clock(), src=ME, dst=GW, proto="TCP", sp=50000, dp=4444, flags="S")
    a = next(x for x in state.alerts if x["type"] == "Ύποπτη εξερχόμενη θύρα")
    assert "selftest" not in a and state.status()["alerts"] == 1


def test_someone_else_is_not_your_test(state):
    state.note_own_tool("σάρωση", seconds=60)  # εσύ σαρώνεις — αλλά η επίθεση έρχεται από άλλον
    state.test_from("192.168.1.77", 30)
    a = _scan(state, Clock(), EVIL, ME)
    assert "selftest" not in a
    assert state.status()["alerts"] == 1


def _sweep(state, src, mac):
    c = Clock()
    for n in range(2, 60):
        feed(state, c, src=src, dst=f"192.168.1.{n}", proto="ARP",
             arp=dict(op=1, psrc=src, pdst=f"192.168.1.{n}", hwsrc=mac))
    return [a for a in state.alerts if a["type"] == "Network sweep (ARP)"]


def test_sweep_from_printer_is_expected_not_red(state, tmp_path):
    """Οι εκτυπωτές (και το HP Smart) σαρώνουν το LAN· φαίνεται, αλλά γκρι, χωρίς να «κοκκινίζει» τη συσκευή."""
    import devnames
    state.devnames = devnames.DevNames(path=str(tmp_path / "n.json"))
    state.devnames.set({"mac": "de:ad:be:ef:00:66", "type": "printer"})
    al = _sweep(state, EVIL, "de:ad:be:ef:00:66")
    assert al and "Εκτυπωτής" in al[0]["benign"]
    assert state.hosts[EVIL]["threat"] < 2  # τα πακέτα του δεν βγαίνουν κόκκινα


def test_sweep_from_named_device_is_expected_but_not_from_iot(state, tmp_path):
    import devnames
    state.devnames = devnames.DevNames(path=str(tmp_path / "n.json"))
    state.devnames.set({"mac": "de:ad:be:ef:00:66", "name": "Γραφείο"})
    al = _sweep(state, EVIL, "de:ad:be:ef:00:66")
    assert al and "Γραφείο" in al[0]["benign"]
    other = "192.168.1.67"
    state.devnames.set({"mac": "de:ad:be:ef:00:67", "name": "Κάμερα αυλής", "type": "camera"})
    al = [a for a in _sweep(state, other, "de:ad:be:ef:00:67") if a["actor"] == other]
    assert al and not al[0].get("benign")  # κάμερα που σαρώνει → ύποπτο ακόμα κι αν την ξέρεις


def test_sweep_from_unknown_device_still_alerts(state):
    al = _sweep(state, EVIL, "de:ad:be:ef:00:66")
    assert al and not al[0].get("benign")


# ---------------- διορθώσεις bug (έλεγχος κώδικα) ----------------
def test_synthetic_alert_actor_makes_no_fake_host(state):
    """Bug #1: δράστης που δεν είναι IP (DNS flood/amplification) δεν φτιάχνει ψεύτικη συσκευή."""
    t = 1_700_000_000.0
    state.alert("NXDOMAIN flood", "med", "DNS", "example.com", "d", t)
    state.alert("DNS amplification", "high", "8.8.8.8, 9.9.9.9", "x", "d", t)
    state.alert("DNS flood", "high", "3 πηγές", "server", "d", t)
    assert "DNS" not in state.hosts
    assert "8.8.8.8, 9.9.9.9" not in state.hosts
    assert "3 πηγές" not in state.hosts
    # ενώ μια κανονική δημόσια IP εξακολουθεί να φτιάχνει host
    state.alert("Port scan", "high", "203.0.113.5", ME, "d", t)
    assert "203.0.113.5" in state.hosts


def test_packet_ids_are_unique(state):
    """Bug #5: κάθε πακέτο παίρνει δικό του _id (η αρίθμηση γίνεται μέσα στο κλείδωμα)."""
    c = Clock()
    feed(state, c, src=ME, dst=GW, proto="UDP", sp=5, dp=53)
    feed(state, c, src=GW, dst=ME, proto="UDP", sp=53, dp=5)
    ids = [p["_id"] for p in state.recent]
    assert len(ids) == len(set(ids)) and all(isinstance(i, int) for i in ids)


def test_hunt_alerted_matches_whole_token_not_substring(state):
    """Bug #2: το «ήδη ειδοποιήθηκε» ταιριάζει ολόκληρη IP/domain, όχι substring."""
    h = hunt.Hunt(state)
    D = {"alerts": [{"actor": "15.9.1.20", "target": "x", "detail": "κίνηση προς 15.9.1.20"}]}
    assert h._alerted(D, "15.9.1.20")        # ακριβές
    assert not h._alerted(D, "5.9.1.2")      # όχι substring μέσα στην 15.9.1.20
    D2 = {"alerts": [{"actor": "x", "target": "y", "detail": "ρώτησε data.top"}]}
    assert h._alerted(D2, "data.top")
    assert not h._alerted(D2, "a.top")       # όχι substring μέσα στο data.top


def test_hunt_counts_repeated_dns_queries(state):
    """Bug #3: το ίδιο domain ρωτημένο πολλές φορές μετριέται σωστά (όχι 1)."""
    c = Clock()
    for _ in range(4):
        feed(state, c, src=ME, dst=GW, proto="UDP", sp=50000, dp=53, dns_q=("rare.example.com",))
    D = hunt.Hunt(state)._data()
    assert D["dns"][(ME, "rare.example.com")][0] == 4


def test_hunt_longtail_skips_known_resolver(state):
    """Bug #4: ένας γνωστός DNS resolver (1.1.1.1) δεν βγαίνει ως «σπάνιος προορισμός»."""
    c = Clock()
    for _ in range(3):
        feed(state, c, src="192.168.1.77", dst="1.1.1.1", proto="TCP", sp=50000, dp=443, flags="S")
        feed(state, c, src="192.168.1.77", dst="93.184.216.34", proto="TCP", sp=50001, dp=443, flags="S")
    hu = hunt.Hunt(state)
    fs, _ = hu._h_longtail(hu._data())
    targets = {f["target"] for f in fs}
    assert "1.1.1.1" not in targets          # resolver → αγνοείται
    assert "93.184.216.34" in targets        # κανονικός άγνωστος server → βγαίνει


def test_arp_spoofing_ignores_zero_mac_and_self(state):
    # μηδενική MAC (κάρτα δικτύου που κοιμάται/ξυπνά) → κανένας συναγερμός
    c = Clock()
    feed(state, c, src=GW, dst=ME, proto="ARP", arp=dict(op=2, psrc=GW, pdst=ME, hwsrc="00:00:00:00:00:00"))
    assert [a for a in state.alerts if a["type"].startswith("ARP spoofing")] == []
    # αλλαγή MAC στη ΔΙΚΗ σου IP → όχι MITM (εσύ στέλνεις το δικό σου ARP)
    feed(state, c, src=ME, dst=GW, proto="ARP", arp=dict(op=2, psrc=ME, pdst=GW, hwsrc="aa:bb:cc:dd:ee:01"))
    feed(state, c, src=ME, dst=GW, proto="ARP", arp=dict(op=2, psrc=ME, pdst=GW, hwsrc="aa:bb:cc:dd:ee:02"), dt=5)
    assert [a for a in state.alerts if a["type"].startswith("ARP spoofing")] == []
    # ο router όμως που αλλάζει MAC χτυπά κανονικά (δεν χαλάσαμε την ανίχνευση)
    feed(state, c, src=GW, dst=ME, proto="ARP", arp=dict(op=2, psrc=GW, pdst=ME, hwsrc="de:ad:be:ef:00:66"), dt=5)
    assert len([a for a in state.alerts if a["type"].startswith("ARP spoofing")]) == 1


# ---------------- τύπος συσκευής: μόνο από θύρες που είναι όντως ανοιχτές ----------------
def test_being_scanned_does_not_turn_devices_into_printers_or_cameras(state):
    """Βρέθηκε live: η σάρωση του NetWatch στέλνει SYN στις 631/9100/515/554 κάθε συσκευής και το δίκτυο
    έβγαινε «12 εκτυπωτές, 2 κάμερες». Ένα πακέτο ΠΡΟΣ μια θύρα δεν σημαίνει ότι η θύρα είναι ανοιχτή."""
    c, plug = Clock(), "192.168.1.72"
    for port in (515, 631, 9100, 554, 62078, 8009, 1883, 8883):   # και οι θύρες MQTT: η σάρωση τις ρωτά σε όλους
        feed(state, c, src=ME, dst=plug, proto="TCP", sp=50000 + port, dp=port, flags="S")
    assert state._dtype(state.hosts[plug])["dtype"] == "unknown"


def test_a_device_that_answers_on_the_printer_port_is_a_printer(state):
    c, printer = Clock(), "192.168.1.205"
    feed(state, c, src=ME, dst=printer, proto="TCP", sp=50001, dp=9100, flags="S")
    feed(state, c, src=printer, dst=ME, proto="TCP", sp=9100, dp=50001, flags="SA")   # απάντησε: η θύρα είναι ανοιχτή
    assert state._dtype(state.hosts[printer])["dtype"] == "printer"


def test_mqtt_client_is_still_recognised_as_iot(state):
    c, esp = Clock(), "192.168.1.90"
    feed(state, c, src=esp, dst="192.168.1.17", proto="TCP", sp=51000, dp=1883, flags="S")   # μιλά σε broker
    assert state._dtype(state.hosts[esp])["dtype"] == "iot"


# ---------------- 🔁 P2P (torrent, Stremio…): εξήγηση αντί για σκέτο «κακόβουλη IP» ----------------
def _torrent(state, c, host, n):
    for i in range(n):   # νέες συνδέσεις προς n διαφορετικούς υπολογιστές, τυχαίες θύρες και από τις δύο πλευρές
        feed(state, c, src=host, dst=f"45.{10 + i // 200}.{i % 200}.7", proto="TCP", sp=50000 + i, dp=20000 + i * 7 % 40000, flags="S")


def test_p2p_is_recognised_from_many_peers_on_random_ports(state):
    c = Clock()
    _torrent(state, c, ME, 30)
    assert state.p2p_peers(ME, c()) >= 30
    assert state.p2p_peers("192.168.1.77", c()) == 0                      # άλλη συσκευή: όχι


def test_normal_browsing_is_not_p2p(state):
    c = Clock()
    for i in range(60):   # 60 διαφορετικοί web servers, αλλά σε γνωστή θύρα (443)
        feed(state, c, src=ME, dst=f"93.184.{i}.34", proto="TCP", sp=51000 + i, dp=443, flags="S")
    assert state.p2p_peers(ME, c()) == 0


def test_blocklisted_peer_during_p2p_is_explained_and_low(state):
    """Βρέθηκε live: το Stremio (torrent) έβγαζε «Σύνδεση σε κακόβουλη IP» (μέτριο) για peers που είναι σε λίστες."""
    c = Clock()
    _torrent(state, c, ME, 30)
    state.alert("Σύνδεση σε κακόβουλη IP", "med", "85.203.46.28", ME, "x", c())
    a = state.alerts[0]
    assert a["sev"] == "low" and a["p2p"]["ip"] == ME and a["p2p"]["peers"] >= 30


def test_c2_list_hit_stays_high_even_during_p2p(state):
    c = Clock()
    _torrent(state, c, ME, 30)
    state.alert("Σύνδεση σε κακόβουλη IP", "high", "185.1.2.3", ME, "πιθανή μόλυνση από botnet!", c())
    a = state.alerts[0]
    assert a["sev"] == "high" and a["p2p"]["peers"] >= 30                # εξηγείται, αλλά ΔΕΝ χαμηλώνει


def test_without_p2p_the_alert_is_unchanged(state):
    state.alert("Σύνδεση σε κακόβουλη IP", "med", "85.203.46.28", ME, "x", Clock()())
    a = state.alerts[0]
    assert a["sev"] == "med" and "p2p" not in a


def test_p2p_state_expires(state):
    c = Clock()
    _torrent(state, c, ME, 30)
    assert state.p2p_peers(ME, c() + 301) == 0                            # 5′ χωρίς νέους peers: όχι πια P2P
