"""Tests για την εργαλειοθήκη τεχνικού (netkit) και τις επεκτάσεις του σαρωτή — μόνο τοπικά, χωρίς Internet."""
import csv
import io
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import netkit  # noqa: E402
import pentest  # noqa: E402

# ---------------- ping ----------------
MAC_PING = """PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=2.000 ms
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=4.000 ms
Request timeout for icmp_seq 2
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=3.000 ms

--- 192.168.1.1 ping statistics ---
4 packets transmitted, 3 packets received, 25.0% packet loss
round-trip min/avg/max/stddev = 2.000/3.000/4.000/0.816 ms
"""
LINUX_PING = """PING 10.0.0.5 (10.0.0.5) 56(84) bytes of data.
64 bytes from 10.0.0.5: icmp_seq=1 ttl=128 time=10.5 ms
64 bytes from 10.0.0.5: icmp_seq=2 ttl=128 time=12 ms
64 bytes from 10.0.0.5: icmp_seq=3 ttl=128 time=11.5 ms
64 bytes from 10.0.0.5: icmp_seq=4 ttl=128 time=11 ms

--- 10.0.0.5 ping statistics ---
5 packets transmitted, 4 received, 20% packet loss, time 4005ms
rtt min/avg/max/mdev = 10.5/11.25/12/0.559 ms
"""


def test_parse_ping_macos_loss_and_jitter():
    r = netkit.parse_ping(MAC_PING)
    assert (r["sent"], r["received"], r["loss_pct"]) == (4, 3, 25.0)
    assert (r["min"], r["avg"], r["max"]) == (2.0, 3.0, 4.0)
    assert r["jitter"] == pytest.approx((2 + 1) / 2)  # |4-2|, |3-4|
    assert r["ttl"] == 64 and r["rtts"] == [2.0, 4.0, 3.0]


def test_parse_ping_linux():
    r = netkit.parse_ping(LINUX_PING)
    assert (r["sent"], r["received"], r["loss_pct"]) == (5, 4, 20.0)
    assert r["avg"] == pytest.approx(11.25) and r["jitter"] == pytest.approx((1.5 + 0.5 + 0.5) / 3, abs=1e-3)
    assert netkit.os_guess(r["ttl"]).startswith("Windows")


def test_parse_ping_total_loss():
    r = netkit.parse_ping("3 packets transmitted, 0 packets received, 100.0% packet loss")
    assert r["loss_pct"] == 100.0 and r["avg"] is None and r["jitter"] is None


def test_os_guess_ranges():
    assert "Linux" in netkit.os_guess(63)
    assert "Windows" in netkit.os_guess(120)
    assert "router" in netkit.os_guess(250)
    assert netkit.os_guess(None) is None


def test_ping_cmd_uses_argument_lists():
    mac = netkit.ping_cmd("192.168.1.1", 5, 0.3, platform="darwin")
    lin = netkit.ping_cmd("192.168.1.1", 5, 0.3, platform="linux")
    assert mac[0] == "ping" and mac[-1] == "192.168.1.1" and "-c" in mac
    assert lin[:2] == ["ping", "-4"] and "-w" in lin
    assert netkit.ping_cmd("fe80::1", 2, 1, platform="darwin")[0] == "ping6"


@pytest.mark.parametrize("kw", [dict(count=21), dict(count=0), dict(interval=0.1), dict(count="x")])
def test_ping_limits(kw):
    with pytest.raises(ValueError):
        netkit.ping("192.168.1.1", sim=True, **kw)


@pytest.mark.parametrize("host", ["1.1.1.1; rm -rf /", "-f", "$(reboot)", "a b", "`id`", "host|cat", "", "x" * 300,
                                  "--help", "example.com&&ls"])
def test_injection_is_rejected_everywhere(host, monkeypatch):
    called = []
    monkeypatch.setattr(netkit.subprocess, "run", lambda *a, **k: called.append(a))
    for fn in (lambda: netkit.ping(host), lambda: netkit.port_check(host, "80"),
               lambda: netkit.dns_lookup(host, server="127.0.0.1"), lambda: netkit.dns_compare(host),
               lambda: netkit.http_inspect("http://" + host if host else "")):
        with pytest.raises(ValueError):
            fn()
    assert not called


def test_ping_sim_is_realistic():
    r = netkit.ping("192.168.1.40", count=5, sim=True)
    assert r["sent"] == 5 and r["received"] >= 4 and r["ttl"] == 255 and "router" in r["os_guess"]
    pub = netkit.ping("8.8.8.8", count=3, sim=True)
    assert pub["os_guess"] is None and pub["hops"] == 128 - pub["ttl"]


def test_ping_refuses_multicast_and_broadcast():
    for h in ("224.0.0.1", "255.255.255.255", "0.0.0.0"):
        with pytest.raises(ValueError):
            netkit.ping(h, sim=True)


# ---------------- θύρες ----------------
def test_parse_ports_ranges_and_dedup():
    assert netkit.parse_ports("22,80,8000-8003,80", 100) == [22, 80, 8000, 8001, 8002, 8003]
    assert netkit.parse_ports(" 443 ", 10) == [443]
    assert netkit.parse_ports([22, "80"], 10) == [22, 80]
    assert netkit.compress_ports([1, 2, 3, 5, 7, 8]) == "1-3,5,7-8"


@pytest.mark.parametrize("spec", ["", "abc", "0", "65536", "80-70", "22;rm", "1-", "-5", "1-2000", None, "22,,x"])
def test_parse_ports_rejects_bad_input(spec):
    with pytest.raises(ValueError):
        netkit.parse_ports(spec, 1024)


def test_parse_ports_limit_message_is_greek():
    with pytest.raises(ValueError, match="το πολύ 10"):
        netkit.parse_ports("1-11", 10)


def _listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            c.close()
    threading.Thread(target=serve, daemon=True).start()
    return srv


def test_port_check_open_and_closed():
    srv = _listener()
    port = srv.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    cport = closed.getsockname()[1]
    closed.close()
    try:
        r = netkit.port_check("127.0.0.1", f"{port},{cport}", timeout=1)
    finally:
        srv.close()
    by = {p["port"]: p for p in r["ports"]}
    assert r["private"] and r["open"] == 1
    assert by[port]["state"] == "open" and by[port]["product"] == "OpenSSH" and by[port]["version"] == "9.6"
    assert by[cport]["state"] == "closed"


def test_port_check_public_target_limited_to_10(monkeypatch):
    monkeypatch.setattr(netkit, "_probe_tcp", lambda *a: pytest.fail("δεν πρέπει να σαρώσει"))
    with pytest.raises(ValueError, match="10"):
        netkit.port_check("8.8.8.8", "1-11")
    with pytest.raises(ValueError):
        netkit.port_check("8.8.8.8", "22,23,25,53,80,110,143,443,993,995,3389")


def test_port_check_private_allows_1024_but_not_more():
    with pytest.raises(ValueError):
        netkit.port_check("192.168.1.10", "1-1025", sim=True)
    r = netkit.port_check("192.168.1.10", "1-1024", sim=True)
    assert len(r["ports"]) == 1024


def test_port_check_sim_uses_demo_devices():
    r = netkit.port_check("192.168.1.40", "21,22", sim=True)
    by = {p["port"]: p for p in r["ports"]}
    assert by[21]["state"] == "open" and by[21]["product"] == "vsftpd" and by[22]["state"] == "closed"


# ---------------- DNS ----------------
class FakeDNS:
    """Μικρός DNS server σε UDP για τα tests (απαντά με scapy)."""

    def __init__(self):
        from scapy.layers import dns as d
        self.d = d
        self.seen = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        d = self.d
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            q = d.DNS(data)
            name = q.qd[0].qname.decode() if isinstance(q.qd[0].qname, bytes) else q.qd[0].qname
            qt = q.qd[0].qtype
            self.seen.append((name, qt))
            an, rcode = [], 0
            if name == "nx.test.":
                rcode = 3
            elif qt == 1:
                an = [d.DNSRR(rrname=name, type="A", ttl=300, rdata="93.184.216.34")]
            elif qt == 15:
                an = [d.DNSRRMX(rrname=name, ttl=60, preference=10, exchange="mx.test.")]
            elif qt == 16:
                an = [d.DNSRR(rrname=name, type="TXT", ttl=60, rdata=[b"v=spf1 -all"])]
            elif qt == 12:
                an = [d.DNSRR(rrname=name, type="PTR", ttl=60, rdata="host.lan.")]
            # πρώτα μια απάντηση με λάθος id (πρέπει να αγνοηθεί)
            self.sock.sendto(bytes(d.DNS(id=(q.id + 1) % 65536, qr=1, qd=q.qd)), addr)
            self.sock.sendto(bytes(d.DNS(id=q.id, qr=1, rd=1, ra=1, rcode=rcode, qd=q.qd, an=an)), addr)

    def close(self):
        self.sock.close()


@pytest.fixture
def fakedns():
    f = FakeDNS()
    yield f
    f.close()


def test_dns_a_record(fakedns):
    r = netkit.dns_lookup("example.test", "A", server="127.0.0.1", port=fakedns.port)
    assert r["rcode"] == "NOERROR" and r["answers"] == [{"type": "A", "ttl": 300, "data": "93.184.216.34"}]
    assert r["server"] == "127.0.0.1" and r["ms"] >= 0


def test_dns_mx_and_txt(fakedns):
    mx = netkit.dns_lookup("example.test", "mx", server="127.0.0.1", port=fakedns.port)
    assert mx["type"] == "MX" and mx["answers"][0]["data"] == "10 mx.test"
    txt = netkit.dns_lookup("example.test", "TXT", server="127.0.0.1", port=fakedns.port)
    assert txt["answers"][0]["data"] == "v=spf1 -all"


def test_dns_ptr_builds_reverse_name(fakedns):
    r = netkit.dns_lookup("1.2.3.4", "PTR", server="127.0.0.1", port=fakedns.port)
    assert fakedns.seen[-1] == ("4.3.2.1.in-addr.arpa.", 12)
    assert r["name"] == "4.3.2.1.in-addr.arpa" and r["answers"][0]["data"] == "host.lan"
    netkit.dns_lookup("2001:db8::1", "PTR", server="127.0.0.1", port=fakedns.port)
    assert fakedns.seen[-1][0].endswith(".8.b.d.0.1.0.0.2.ip6.arpa.")


def test_dns_nxdomain(fakedns):
    r = netkit.dns_lookup("nx.test", server="127.0.0.1", port=fakedns.port)
    assert r["rcode"] == "NXDOMAIN" and r["answers"] == []


def test_dns_timeout_and_validation():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))  # κανείς δεν απαντά
    try:
        with pytest.raises(TimeoutError):
            netkit.dns_lookup("a.test", server="127.0.0.1", port=s.getsockname()[1], timeout=0.3)
    finally:
        s.close()
    with pytest.raises(ValueError):
        netkit.dns_lookup("a.test", "ANY", server="127.0.0.1")
    with pytest.raises(ValueError):
        netkit.dns_lookup("a.test", server="dns.google")  # ο server πρέπει να είναι IP


def test_parse_scutil_and_resolv_conf():
    scutil = """DNS configuration

resolver #1
  search domain[0] : home
  nameserver[0] : 192.168.1.1
  nameserver[1] : 1.1.1.1
  reach    : 0x00000002 (Reachable)

resolver #2
  domain   : local
  options  : mdns

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 9.9.9.9
"""
    assert netkit.parse_scutil_dns(scutil) == (["192.168.1.1", "1.1.1.1"], ["home"])
    rc = "# generated\nnameserver 10.0.0.1\nnameserver bogus\nsearch lan corp.example\n"
    assert netkit.parse_resolv_conf(rc) == (["10.0.0.1"], ["lan", "corp.example"])


# ---------------- σύγκριση resolvers ----------------
def R(rid, group, answers=(), rcode="NOERROR", error=None):
    return {"id": rid, "label": rid, "group": group, "rcode": rcode, "answers": list(answers), "error": error}


PUB = [R("cf", "public", ["104.16.1.1"]), R("g", "public", ["104.16.2.2"]), R("q", "public", ["172.67.3.3"])]


def test_compare_agrees():
    m, sev, why = netkit.compare_verdict([R("system", "local", ["104.16.9.9"])] + PUB)
    assert not m and sev == "ok"


def test_compare_flags_bogon_from_local_resolver():
    m, sev, why = netkit.compare_verdict([R("router", "local", ["0.0.0.0"])] + PUB)
    assert m and sev == "high" and "0.0.0.0" in why
    m, sev, _ = netkit.compare_verdict([R("router", "local", ["192.168.1.66"])] + PUB)
    assert m and sev == "high"


def test_compare_flags_local_nxdomain():
    m, sev, why = netkit.compare_verdict([R("system", "local", rcode="NXDOMAIN")] + PUB)
    assert m and sev == "high" and "δεν υπάρχει" in why


def test_compare_cdn_difference_is_only_low():
    m, sev, why = netkit.compare_verdict([R("system", "local", ["23.45.6.7"])] + PUB)
    assert m and sev == "low" and "CDN" in why


def test_compare_does_not_cry_wolf():
    # τοπικό όνομα που δεν υπάρχει στο Internet
    m, _, _ = netkit.compare_verdict([R("router", "local", ["192.168.1.1"])] +
                                     [R(x, "public", rcode="NXDOMAIN") for x in "abc"])
    assert not m
    # οι δημόσιοι δεν απάντησαν (π.χ. μπλοκαρισμένο DNS προς τα έξω)
    m, _, _ = netkit.compare_verdict([R("system", "local", ["1.2.3.4"])] +
                                     [R(x, "public", error="timeout") for x in "abc"])
    assert not m
    # ο τοπικός δεν απάντησε → όχι συναγερμός
    m, _, _ = netkit.compare_verdict([R("system", "local", error="timeout")] + PUB)
    assert not m


def test_dns_compare_with_mocked_resolvers(monkeypatch):
    monkeypatch.setattr(netkit, "_system_dns", lambda: (["192.168.1.1"], []))
    monkeypatch.setattr(netkit, "_default_gateway", lambda: ("192.168.1.254", "en0"))
    answers = {"192.168.1.1": "10.10.10.10", "192.168.1.254": "151.101.1.1", "1.1.1.1": "151.101.1.1",
               "8.8.8.8": "151.101.65.1", "9.9.9.9": "151.101.129.1"}

    def fake(name, rtype="A", server=None, timeout=2):
        return {"ms": 1.0, "rcode": "NOERROR", "answers": [{"type": "A", "ttl": 1, "data": answers[server]}]}
    monkeypatch.setattr(netkit, "dns_lookup", fake)
    r = netkit.dns_compare("bank.example.com")
    assert [x["id"] for x in r["results"]] == ["system", "router", "cloudflare", "google", "quad9"]
    assert r["mismatch"] and r["severity"] == "high" and "10.10.10.10" in r["explanation"]


def test_dns_compare_sim_shows_adblock():
    assert not netkit.dns_compare("example.com", sim=True)["mismatch"]
    r = netkit.dns_compare("ads.example.com", sim=True)
    assert r["mismatch"] and r["severity"] == "high"


# ---------------- HTTP ----------------
class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/mid")
            self.end_headers()
        elif self.path == "/mid":
            self.send_response(301)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/final")
            self.end_headers()
        elif self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
        else:
            body = "<html><head><title>  Γεια &amp; χαρά </title></head><body>ok</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


@pytest.fixture
def web():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_http_inspect_redirect_chain_title_and_headers(web):
    r = netkit.http_inspect(web + "/start")
    assert [c["status"] for c in r["chain"]] == [302, 301, 200]
    assert r["final_url"].endswith("/final") and r["status"] == 200
    assert r["title"] == "Γεια & χαρά"
    sec = {s["header"]: s for s in r["security"]}
    assert sec["X-Content-Type-Options"]["ok"]
    assert not sec["Content-Security-Policy"]["present"] and "Λείπει" in sec["Content-Security-Policy"]["note"]
    assert not sec["Strict-Transport-Security"]["ok"]  # απλό HTTP
    assert r["tls"] is None and r["security_score"] == "1/6"


def test_http_inspect_stops_redirect_loops(web):
    with pytest.raises(ValueError, match="ανακατευθύνσεις"):
        netkit.http_inspect(web + "/loop")


@pytest.mark.parametrize("url", ["ftp://example.com/", "file:///etc/passwd", "javascript:alert(1)", "http://", "gopher://x"])
def test_http_inspect_only_http(url):
    with pytest.raises(ValueError):
        netkit.http_inspect(url)


def test_security_report_frame_ancestors_counts():
    rep = {s["header"]: s for s in netkit.security_report({"content-security-policy": "frame-ancestors 'none'"}, True)}
    assert rep["X-Frame-Options"]["ok"] and not rep["Strict-Transport-Security"]["ok"]


def test_http_inspect_sim():
    r = netkit.http_inspect("example.com", sim=True)
    assert r["chain"][0]["status"] == 301 and r["tls"]["days_left"] > 0 and r["tls"]["sans"]


# ---------------- Wake-on-LAN ----------------
def test_wol_packet_bytes():
    pkt = netkit.wol_packet("AA-BB-CC-DD-EE-FF")
    assert len(pkt) == 102 and pkt[:6] == b"\xff" * 6
    assert pkt[6:] == bytes.fromhex("aabbccddeeff") * 16
    assert netkit.wol_packet("aabb.ccdd.eeff") == pkt


@pytest.mark.parametrize("bcast", ["8.8.8.8", "127.0.0.1", "224.0.0.1", "nonsense", "::1", "169.254.1.1"])
def test_wol_destination_validation(bcast):
    with pytest.raises(ValueError):
        netkit.wol("aa:bb:cc:dd:ee:fe", bcast, sim=True)


@pytest.mark.parametrize("mac", ["zz:bb:cc:dd:ee:ff", "aa:bb:cc", "aa:bb:cc:dd:ee:ff;ls", "01:00:5e:00:00:01", "00:00:00:00:00:00"])
def test_wol_bad_mac(mac):
    with pytest.raises(ValueError):
        netkit.wol(mac, "192.168.1.255", sim=True)


def test_wol_ok_targets(monkeypatch):
    sent = []

    class S:
        def __init__(self, *a):
            pass

        def setsockopt(self, *a):
            pass

        def sendto(self, data, addr):
            sent.append((data, addr))

        def close(self):
            pass
    monkeypatch.setattr(netkit.socket, "socket", S)
    r = netkit.wol("aa:bb:cc:dd:ee:fe", "192.168.1.255")
    assert r["ok"] and sent == [(netkit.wol_packet("aa:bb:cc:dd:ee:fe"), ("192.168.1.255", 9))]
    assert netkit.wol("aa:bb:cc:dd:ee:fe", "255.255.255.255")["broadcast"] == "255.255.255.255"


# ---------------- NetBIOS / SSDP / mDNS ----------------
def nbstat_reply(names, mac=bytes.fromhex("001122334455")):
    enc = netkit.nbstat_request()[12:12 + 34]  # 0x20 + 32 χαρακτήρες + 0x00
    body = b"".join(n.ljust(15).encode() + bytes([suf]) + struct.pack("!H", 0x8400 if grp else 0x0400)
                    for n, suf, grp in names)
    rdata = bytes([len(names)]) + body + mac + b"\x00" * 40
    return (struct.pack("!HHHHHH", 0x4e57, 0x8400, 0, 1, 0, 0) + enc +
            struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata)


def test_nbstat_request_encoding():
    req = netkit.nbstat_request()
    assert req[12] == 0x20 and req[13:45] == b"CK" + b"A" * 30 and req[-4:] == b"\x00\x21\x00\x01"


def test_parse_nbstat():
    r = netkit.parse_nbstat(nbstat_reply([("DESKTOP-7K2QF1", 0, False), ("WORKGROUP", 0, True),
                                          ("DESKTOP-7K2QF1", 0x20, False)]))
    assert r["host"] == "DESKTOP-7K2QF1" and r["workgroup"] == "WORKGROUP" and r["mac"] == "00:11:22:33:44:55"
    assert len(r["names"]) == 3 and r["names"][2]["suffix"] == 0x20
    assert netkit.parse_nbstat(b"\x00" * 20) is None
    netkit.parse_nbstat(nbstat_reply([("X", 0, False)])[:-60])  # κομμένα δεδομένα: δεν σκάει


def test_parse_ssdp_and_upnp_description():
    h = netkit.parse_ssdp(b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:5431/desc.xml\r\n"
                          b"SERVER: Linux/3.10 UPnP/1.0 Archer/1.0\r\nST: upnp:rootdevice\r\n\r\n")
    assert h["location"] == "http://192.168.1.1:5431/desc.xml" and h["server"].startswith("Linux")
    assert netkit.parse_ssdp(b"garbage") is None
    xml = ('<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
           "<friendlyName>Living Room TV</friendlyName><manufacturer>Samsung &amp; Co</manufacturer>"
           "<modelName>QE55Q60</modelName></device></root>")
    d = netkit.parse_upnp_description(xml)
    assert d == {"friendlyName": "Living Room TV", "manufacturer": "Samsung & Co", "modelName": "QE55Q60"}
    assert netkit._model({"manufacturer": "ZTE", "modelName": "ZTE H1600"}) == "ZTE H1600"


def test_upnp_fetch_refuses_other_hosts():
    assert netkit._fetch_upnp("http://8.8.8.8/desc.xml", "8.8.8.8") == {}
    assert netkit._fetch_upnp("http://192.168.1.2/desc.xml", "192.168.1.1") == {}  # άλλη IP από αυτή που απάντησε
    assert netkit._fetch_upnp("file:///etc/passwd", "192.168.1.1") == {}


def test_discover_names_private_only_and_sim():
    for bad in (["8.8.8.8"], ["127.0.0.1"], "1.1.1.0/24", [], ["224.0.0.251"]):
        with pytest.raises(ValueError):
            netkit.discover_names(bad, sim=True)
    r = netkit.discover_names("192.168.1.0/24", sim=True)
    assert "NPI4A0B2C" in r["192.168.1.40"]["names"] and r["192.168.1.10"]["model"]


def test_discover_names_parses_replies(monkeypatch):
    """Ψεύτικες απαντήσεις σε κάθε πρωτόκολλο → σωστή συγκέντρωση ονομάτων."""
    from scapy.layers import dns as d

    def exchange(sends, timeout, sock_setup=None):
        ip, port, data = sends[0]
        if port == 137:
            return [("192.168.1.77", nbstat_reply([("PC-77", 0, False)]))]
        if port == 53 and ip == "192.168.1.1":
            q = d.DNS(data)
            return [("192.168.1.1", bytes(d.DNS(id=q.id, qr=1, qd=q.qd, an=d.DNSRR(
                rrname=q.qd[0].qname, type="PTR", rdata="192.168.1.10.")))),  # router που απαντά με την IP
                ("192.168.1.1", bytes(d.DNS(id=2, qr=1, an=d.DNSRR(rrname="77.1.168.192.in-addr.arpa", type="PTR",
                                                                     rdata="pc-77.home."))))]
        if port == 5353:
            return [("192.168.1.10", bytes(d.DNS(id=0, qr=1, aa=1, an=d.DNSRR(rrname="10.1.168.192.in-addr.arpa",
                                                                               type="PTR", rdata="tv.local."))))]
        return []
    monkeypatch.setattr(netkit, "_udp_exchange", exchange)
    r = netkit.discover_names(["192.168.1.10", "192.168.1.77"], router="192.168.1.1", resolver="192.168.1.1")
    assert set(r["192.168.1.77"]["names"]) == {"pc-77.home", "PC-77"}
    assert r["192.168.1.77"]["sources"] == {"dns": "pc-77.home", "netbios": "PC-77"}  # router == resolver → ένα ερώτημα
    assert r["192.168.1.10"]["names"] == ["tv.local"] and r["192.168.1.10"]["sources"] == {"mdns": "tv.local"}


def test_merge_names_into_host_table():
    class St:
        lock = threading.Lock()
        hosts = {"192.168.1.10": {"names": set()}}
        domains = __import__("collections").defaultdict(set)
        dirty = set()
    n = netkit.merge_names(St, {"192.168.1.10": {"names": ["tv.local"]}, "192.168.1.99": ["new.local"]})
    assert n == 1 and St.hosts["192.168.1.10"]["names"] == {"tv.local"} and "192.168.1.10" in St.dirty
    assert St.domains["192.168.1.99"] == {"new.local"}


# ---------------- διεπαφές / MAC ----------------
IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:22:fb:aa:bb:23
\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0xb
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
en5: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
"""
IP_JSON = json.dumps([{"ifname": "eth0", "flags": ["BROADCAST", "UP"], "mtu": 1500, "link_type": "ether",
                       "address": "52:54:00:12:34:56", "addr_info": [
                           {"family": "inet", "local": "10.0.0.5", "prefixlen": 24, "broadcast": "10.0.0.255"},
                           {"family": "inet6", "local": "fe80::5054:ff:fe12:3456", "prefixlen": 64}]}])


def test_parse_ifconfig_macos():
    ifs = {i["name"]: i for i in netkit.parse_ifconfig(IFCONFIG)}
    assert ifs["en0"]["ipv4"] == [{"addr": "192.168.1.23", "prefix": 24, "broadcast": "192.168.1.255"}]
    assert ifs["en0"]["mac"] == "3c:22:fb:aa:bb:23" and ifs["en0"]["mtu"] == 1500 and ifs["en0"]["up"]
    assert ifs["lo0"]["ipv4"][0]["prefix"] == 8 and not ifs["en5"]["up"]


def test_parse_ip_json_linux():
    i = netkit.parse_ip_json(IP_JSON)[0]
    assert i["name"] == "eth0" and i["ipv4"][0]["prefix"] == 24 and i["ipv6"][0]["prefix"] == 64
    assert netkit.parse_ip_json("not json") == []


def test_mac_vendor():
    assert netkit.mac_vendor("de:ad:be:ef:77:77") == netkit.RANDOM_MAC  # locally administered
    assert netkit.mac_vendor("garbage") is None
    v = netkit.mac_vendor("00:1e:0b:40:40:40")
    assert v is None or "Hewlett" in v


# ---------------- σαρωτής: προφίλ, διαφορές, εξαγωγή ----------------
def test_scan_profile_limits():
    sc = pentest.LanScanner(sim=lambda set_state: [])
    with pytest.raises(ValueError, match="65535|έως 4"):
        sc.start("192.168.1.0/24", profile="full")
    with pytest.raises(ValueError, match="256"):
        sc.start("10.0.0.0/22", profile="top1000")
    with pytest.raises(ValueError):
        sc.start("192.168.1.0/24", profile="custom", ports="1-2000")
    with pytest.raises(ValueError):
        sc.start("192.168.1.0/24", profile="custom", ports="22;rm -rf /")
    with pytest.raises(ValueError):
        sc.start("192.168.1.0/24", profile="evil")
    assert len(pentest.profile_ports("full", 4)) == 65535
    assert len(pentest.profile_ports("custom", 2, "1-5000")) == 5000
    top = pentest.profile_ports("top1000", 254)
    assert 950 <= len(top) <= 1100 and set(pentest.SCAN_PORTS) <= set(top)


def _wait(sc):
    for _ in range(1000):
        if sc.status()["status"] != "running":
            return sc.status()
        threading.Event().wait(0.01)  # όχι time.sleep: κάποια tests το «παγώνουν» για να τρέχει γρήγορα το demo
    raise AssertionError("η σάρωση δεν τελείωσε")


def test_scan_diff_logic():
    prev = {"target": "t", "hosts": [{"ip": "192.168.1.2", "services": [{"port": 22}, {"port": 80}]},
                                     {"ip": "192.168.1.3", "services": []}]}
    cur = {"target": "t", "scanned": "1-1000", "hosts": [
        {"ip": "192.168.1.2", "services": [{"port": 22}, {"port": 443}]},
        {"ip": "192.168.1.9", "services": [{"port": 8080}]}]}
    d = pentest.scan_diff(prev, cur)
    assert d["new_hosts"] == ["192.168.1.9"] and d["gone_hosts"] == ["192.168.1.3"]
    assert d["new_ports"] == [{"ip": "192.168.1.2", "port": 443, "proto": "tcp"}]
    assert d["closed_ports"] == [{"ip": "192.168.1.2", "port": 80, "proto": "tcp"}]
    cur["scanned"] = "22,443"  # η 80 δεν σαρώθηκε αυτή τη φορά → όχι «έκλεισε»
    assert pentest.scan_diff(prev, cur)["closed_ports"] == []


def test_scanner_saves_and_diffs(tmp_path):
    runs = [[{"ip": "192.168.1.2", "mac": None, "services": [{"port": 22, "banner": ""}]}],
            [{"ip": "192.168.1.2", "mac": None, "services": [{"port": 22, "banner": ""}, {"port": 80, "banner": ""}]},
             {"ip": "192.168.1.5", "mac": None, "services": []}]]
    sc = pentest.LanScanner(sim=lambda set_state: runs.pop(0), scan_dir=str(tmp_path))
    sc.start("192.168.1.0/24")
    assert _wait(sc)["diff"] is None
    sc.start("192.168.1.0/24")
    d = _wait(sc)["diff"]
    assert d["new_hosts"] == ["192.168.1.5"] and d["new_ports"] == [{"ip": "192.168.1.2", "port": 80, "proto": "tcp"}]
    assert {p.name for p in tmp_path.iterdir()} == {"last.json", "prev.json"}
    last = json.loads((tmp_path / "last.json").read_text())
    assert last["target"] == "192.168.1.0/24" and len(last["hosts"]) == 2
    assert pentest.LanScanner(scan_dir=str(tmp_path)).last_result()["hosts"] == last["hosts"]


@pytest.fixture
def demo_scan_result(monkeypatch):
    import demo
    monkeypatch.setattr(demo.time, "sleep", lambda s: None)
    sc = pentest.LanScanner(sim=demo.demo_scan)
    sc.start("192.168.1.0/24", udp=True)
    return sc, _wait(sc)


def test_demo_scan_has_new_fields(demo_scan_result):
    _, st = demo_scan_result
    assert st["status"] == "done", st.get("error")
    by = {h["ip"]: h for h in st["hosts"]}
    pr = by["192.168.1.40"]
    assert pr["vendor"] and pr["ttl"] == 255 and pr["os_guess"] and "printer.local" in pr["names"]
    snmp = next(s for s in pr["services"] if s["proto"] == "udp" and s["port"] == 161)
    assert "community public" in snmp["findings"][0][1]
    assert by["192.168.1.77"]["vendor"] == netkit.RANDOM_MAC
    v = pentest.apply_findings({"hosts": [dict(pr, risk="info", services=[dict(s, risk="info", why="") for s in pr["services"]])]})
    assert v["hosts"][0]["risk"] == "high"


def test_export_csv_and_md(demo_scan_result):
    _, st = demo_scan_result
    body, ctype, fname = pentest.export_scan(st, "csv")
    assert ctype.startswith("text/csv") and fname.endswith(".csv")
    rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))
    assert rows[0] == ["ip", "mac", "vendor", "names", "port", "proto", "state", "product", "version", "banner"]
    ftp = next(r for r in rows[1:] if r[0] == "192.168.1.40" and r[4] == "21")
    assert ftp[5:9] == ["tcp", "open", "vsftpd", "2.3.4"] and "printer.local" in ftp[3]
    assert any(r[4] == "161" and r[5] == "udp" for r in rows)
    md = pentest.export_scan(st, "md")[0].decode()
    assert md.startswith("# NetWatch") and "## Ευρήματα" in md and "SNMP με community public" in md
    assert "| 21 | tcp | vsftpd | 2.3.4 |" in md
    js = json.loads(pentest.export_scan(st, "json")[0])
    assert js["target"] == "192.168.1.0/24" and js["hosts"]
    with pytest.raises(ValueError):
        pentest.export_scan(st, "exe")
    with pytest.raises(ValueError):
        pentest.export_scan(None, "csv")


def test_csv_neutralises_formulas():
    st = {"status": "done", "hosts": [{"ip": "192.168.1.2", "services": [{"port": 80, "banner": "=HYPERLINK(\"x\")"}]}]}
    rows = list(csv.reader(io.StringIO(pentest.export_scan(st, "csv")[0].decode("utf-8-sig"))))
    assert rows[1][9].startswith("'=")


# ---------------- HTTP API ----------------
@pytest.fixture
def api():
    import netwatch as nw
    st = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    st.scanner = pentest.LanScanner()
    st.lab = pentest.Lab(st)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), nw.make_handler(st))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield st, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _post(url, body, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers=headers or {"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_api_netkit_tools_in_demo(api):
    st, base = api
    u = base + "/api/netkit"
    code, r = _post(u, {"tool": "ping", "host": "192.168.1.1", "count": 3})
    assert code == 200 and r["sent"] == 3 and r["ttl"] == 64
    assert _post(u, {"tool": "dns", "name": "example.com", "type": "MX"})[1]["answers"]
    assert _post(u, {"tool": "dnscmp", "name": "example.com"})[1]["results"]
    assert _post(u, {"tool": "ports", "host": "192.168.1.40", "ports": "21,80"})[1]["open"] == 2
    assert _post(u, {"tool": "http", "url": "https://example.com"})[1]["status"] == 200
    assert _post(u, {"tool": "wol", "mac": "aa:bb:cc:dd:ee:fe"})[1]["ok"]
    with st.lock:
        st.host("192.168.1.40", time.time())
    code, r = _post(u, {"tool": "names", "target": "192.168.1.0/24"})
    assert code == 200 and "192.168.1.40" in r["hosts"]
    assert "printer.local" in st.hosts["192.168.1.40"]["names"]


def test_api_netkit_validation_errors(api):
    _, base = api
    u = base + "/api/netkit"
    for body in ({"tool": "nope"}, {"tool": "ping", "host": "1.1.1.1; rm -rf /"}, {"tool": "ping", "host": "x", "count": "a"},
                 {"tool": "ports", "host": "8.8.8.8", "ports": "1-100"}, {"tool": "names", "ips": ["8.8.8.8"]},
                 {"tool": "wol", "mac": "aa:bb:cc:dd:ee:fe", "broadcast": "8.8.8.255"}):
        code, r = _post(u, body)
        assert code == 400 and r["error"], body
    assert _post(u, {"tool": "ping", "host": "192.168.1.1"}, {"Content-Type": "text/plain"})[0] == 403
    assert _post(u, {"tool": "ping", "host": "192.168.1.1"},
                 {"Content-Type": "application/json", "Origin": "https://evil.example"})[0] == 403


def test_api_iface_scan_profiles_and_export(api, monkeypatch):
    import demo
    monkeypatch.setattr(demo.time, "sleep", lambda s: None)
    st, base = api
    with urllib.request.urlopen(base + "/api/netkit/iface", timeout=5) as r:
        assert json.load(r)["gateway"] == "192.168.1.1"
    try:
        urllib.request.urlopen(base + "/api/scan/export?fmt=csv", timeout=5)
        raise AssertionError("χωρίς σάρωση πρέπει να αποτύχει")
    except urllib.error.HTTPError as e:
        assert e.code == 404
    assert _post(base + "/api/scan", {"target": "192.168.1.0/24", "profile": "full"})[0] == 400
    st.scanner = pentest.LanScanner(sim=demo.demo_scan)
    assert _post(base + "/api/scan", {"target": "192.168.1.0/24", "profile": "top1000", "udp": True}) == (200, {"ok": True})
    _wait(st.scanner)
    with urllib.request.urlopen(base + "/api/scan", timeout=5) as r:
        v = json.load(r)
    assert v["profile"] == "top1000" and v["udp"]
    with urllib.request.urlopen(base + "/api/scan/export?fmt=md", timeout=5) as r:
        assert "attachment" in r.headers["Content-Disposition"] and r.headers["Content-Type"].startswith("text/markdown")
        assert "## Ευρήματα" in r.read().decode()
    with urllib.request.urlopen(base + "/api/scan/export?fmt=csv", timeout=5) as r:
        assert r.read().decode("utf-8-sig").startswith("ip,mac,vendor")


# ---------------- «δική μου δοκιμή»: τα εργαλεία δεν βγάζουν ψεύτικους συναγερμούς ----------------
def test_run_tool_marks_own_traffic():
    calls = []

    class St:
        lock = threading.Lock()
        hosts, dirty = {}, set()

        def note_own_tool(self, why, seconds=None):
            calls.append(why)
    srv = _listener()
    try:
        r = netkit.run_tool({"tool": "ports", "host": "127.0.0.1", "ports": str(srv.getsockname()[1])}, state=St())
    finally:
        srv.close()
    assert r["open"] == 1 and len(calls) >= 2 and all("έλεγχος θυρών" in c for c in calls)
    calls.clear()
    netkit.run_tool({"tool": "ping", "host": "192.168.1.1"}, sim=True, state=St())
    assert calls == []  # demo: δεν φεύγει τίποτα στο δίκτυο
    with pytest.raises(ValueError):
        netkit.run_tool({"tool": "nope"}, state=St())


def test_own_tool_suppresses_alert_from_me(api):
    st, _ = api
    st.note_own_tool("έλεγχος θυρών (🔴 Pentest → Εργαλεία)")
    assert st.selftest_status()["own_tool"]["why"].startswith("έλεγχος θυρών")


def test_api_selftest_routes(api):
    st, base = api
    u = base + "/api/selftest"
    code, r = _post(u, {"ip": "192.168.1.77", "minutes": 15, "why": "δοκιμή nmap από το laptop"})
    assert code == 200 and r["test_ips"][0]["ip"] == "192.168.1.77" and r["test_ips"][0]["why"] == "δοκιμή nmap από το laptop"
    with urllib.request.urlopen(u, timeout=5) as resp:
        assert json.load(resp)["test_ips"][0]["ip"] == "192.168.1.77"
    for body in ({"ip": "8.8.8.8", "minutes": 5}, {"ip": "192.168.1.77", "minutes": 241}, {"ip": "192.168.1.77", "minutes": -1},
                 {"ip": "192.168.1.77; rm -rf /", "minutes": 5}, {"ip": "", "minutes": 5}, {"ip": "192.168.1.7", "minutes": "x"}):
        code, r = _post(u, body)
        assert code == 400 and r["error"], body
    assert _post(u, {"ip": "192.168.1.77", "minutes": 5}, {"Content-Type": "application/json", "Origin": "https://evil.example"})[0] == 403
    code, r = _post(u, {"ip": "192.168.1.77", "minutes": 0})
    assert code == 200 and r["test_ips"] == []
