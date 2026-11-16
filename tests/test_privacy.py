"""Tests για τον έλεγχο ανωνυμίας/διαρροών (χωρίς Internet: ψεύτικος SOCKS5 και HTTP server)."""
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import netwatch as nw  # noqa: E402
import privacy as pv  # noqa: E402

HOME = {"query": "31.217.160.211", "country": "Greece", "city": "Athens", "isp": "Ote SA", "as": "AS6799 Ote SA",
        "timezone": "Europe/Athens", "proxy": False, "hosting": False}
VPN = {"query": "185.65.134.77", "country": "Sweden", "city": "Stockholm", "isp": "M247", "as": "AS39351 31173 AB",
       "timezone": "Europe/Stockholm", "proxy": True, "hosting": True}
ISP_DNS = [{"ip": "195.170.0.1", "country": "Greece", "cc": "GR", "asn": "AS6799 Ote SA", "org": "Ote SA"}]
VPN_DNS = [{"ip": "185.65.134.1", "country": "Sweden", "cc": "SE", "asn": "AS39351 31173 AB", "org": "31173 AB"}]


def ids(r, st):
    return {c["id"] for c in r["checks"] if c["status"] == st}


def test_no_vpn_means_no_anonymity_but_no_leak():
    r = pv.evaluate({"info": HOME, "dns": ISP_DNS, "tor": {}, "vpn": False})
    assert r["level"] == 0 and not ids(r, "bad")


def test_vpn_with_dns_and_ipv6_leak():
    r = pv.evaluate({"info": VPN, "dns": ISP_DNS, "ipv6": "2a02:587::1", "info6": HOME, "tor": {}, "vpn": True})
    assert {"dns", "ipv6"} <= ids(r, "bad") and r["level"] == 1


def test_clean_vpn_is_medium_and_tor_is_high():
    r = pv.evaluate({"info": VPN, "dns": VPN_DNS, "tor": {}, "vpn": True})
    assert r["level"] == 2 and not ids(r, "bad")
    t = pv.evaluate({"info": VPN, "dns": VPN_DNS, "tor": {}, "tor_direct": {"IsTor": True}})
    assert t["level"] == 3


def test_vpn_on_but_home_ip_means_traffic_bypasses_vpn():
    r = pv.evaluate({"info": HOME, "dns": ISP_DNS, "tor": {}, "vpn": True})
    assert "vpn_route" in ids(r, "bad")


def test_full_tunnel_detection():
    assert pv.vpn_full_tunnel("utun4") and pv.vpn_full_tunnel("wg0")
    assert not pv.vpn_full_tunnel("en0") and not pv.vpn_full_tunnel(None)


def test_socks5_client_with_remote_dns():
    """Ψεύτικος Tor: δέχεται SOCKS5 CONNECT με ΟΝΟΜΑ (όχι IP) και προωθεί σε τοπικό HTTP server."""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"IsTor": true, "IP": "185.220.101.4"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    web = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    seen = {}
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)

    def socks():
        c, _ = lsock.accept()
        assert c.recv(3) == b"\x05\x01\x00"
        c.sendall(b"\x05\x00")
        head = c.recv(4)
        n = c.recv(1)[0]
        seen["atyp"], seen["host"] = head[3], c.recv(n).decode()
        seen["port"] = int.from_bytes(c.recv(2), "big")
        up = socket.create_connection(web.server_address)
        c.sendall(b"\x05\x00\x00\x01" + bytes(4) + b"\x00\x00")
        up.sendall(c.recv(4096))
        while True:
            d = up.recv(4096)
            if not d:
                break
            c.sendall(d)
        c.close()

    threading.Thread(target=socks, daemon=True).start()
    r = pv.get_json("http://check.torproject.example/api/ip", socks=lsock.getsockname()[1])
    assert r == {"IsTor": True, "IP": "185.220.101.4"}
    assert seen == {"atyp": 3, "host": "check.torproject.example", "port": 80}  # το DNS γίνεται ΜΕΣΑ στο Tor
    web.shutdown()


def test_demo_check_shows_leaks():
    r = pv.demo_check()
    assert r["demo"] and {"dns", "ipv6"} <= ids(r, "bad")


def _live_state():
    s = nw.NetState("live", "en0", ["192.168.1.50", "2a02:587::50"], "192.168.1.1", geo=False, rdns=False)
    s.vpn_iface = "utun4"
    return s


def _pkt(src, dst, proto="UDP", dp=53, t=1.0, q="bank.gr"):
    return {"t": t, "len": 80, "src": src, "dst": dst, "proto": proto, "sp": 50000, "dp": dp,
            "dns_q": (q, 1) if dp == 53 else None}


def test_passive_dns_leak_outside_vpn_tunnel():
    s = _live_state()
    for i in range(3):
        s.process(_pkt("192.168.1.50", "192.168.1.1", t=100 + i))
    a = [a for a in s.alerts if a["type"] == "Διαρροή DNS εκτός VPN"]
    assert len(a) == 1 and "bank.gr" in a[0]["detail"] and "utun4" in a[0]["detail"]


def test_passive_ipv6_leak_and_no_alert_without_vpn():
    s = _live_state()
    s.process(_pkt("2a02:587::50", "2606:4700::1111", proto="TCP", dp=443, t=5))
    assert any(a["type"] == "Διαρροή IPv6 εκτός VPN" for a in s.alerts)
    off = _live_state()
    off.vpn_iface = None
    for i in range(5):
        off.process(_pkt("192.168.1.50", "192.168.1.1", t=100 + i))
    assert not [a for a in off.alerts if a["type"].startswith("Διαρροή")]


def test_capturing_on_the_tunnel_itself_is_not_a_leak():
    s = _live_state()
    s.iface = "utun4"
    for i in range(5):
        s.process(_pkt("192.168.1.50", "100.100.100.100", t=100 + i))
    assert not [a for a in s.alerts if a["type"].startswith("Διαρροή")]


def test_own_tor_relay_connection_is_marked_expected(monkeypatch):
    monkeypatch.setattr(nw, "local_tor_running", lambda: True)
    s = nw.NetState("live", "en0", ["192.168.1.50"], "192.168.1.1", geo=False, rdns=False)
    s.process({"t": 1.0, "len": 60, "src": "192.168.1.50", "dst": "195.154.170.135", "proto": "TCP",
               "sp": 50000, "dp": 9001, "flags": "S"})
    a = next(a for a in s.alerts if a["type"] == "Ύποπτη εξερχόμενη θύρα")
    assert "δικό σου Tor" in a["benign"]
    assert s.hosts["195.154.170.135"]["threat"] == 0 and s.status()["alerts"] == 0
    monkeypatch.setattr(nw, "local_tor_running", lambda: False)
    s.process({"t": 2.0, "len": 60, "src": "192.168.1.50", "dst": "5.6.7.8", "proto": "TCP",
               "sp": 50001, "dp": 9001, "flags": "S"})
    other = next(a for a in s.alerts if a["actor"] == "5.6.7.8")
    assert not other.get("benign") and s.status()["alerts"] == 1


TRACE = """traceroute to 140.82.121.4 (140.82.121.4), 20 hops max, 40 byte packets
 1  192.168.1.1  5.301 ms
 2  10.106.108.100  8.017 ms
 3  79.128.234.168  14.697 ms
 4  *
 5  80.81.196.79  50.714 ms
"""


def test_parse_traceroute_and_input_validation():
    hops = nw.parse_traceroute(TRACE)
    assert [h["n"] for h in hops] == [1, 2, 3, 4, 5]
    assert hops[0] == {"n": 1, "ip": "192.168.1.1", "ms": 5.301} and hops[3]["ip"] is None
    s = nw.NetState("live", "en0", ["192.168.1.50"], "192.168.1.1", geo=False, rdns=False)
    import pytest
    for bad in ("192.168.1.1", "1.1.1.1; rm -rf /", "example.com", ""):
        with pytest.raises(ValueError):
            nw.traceroute(s, bad)
    demo = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    r = nw.traceroute(demo, "45.57.90.1")
    assert r["demo"] and r["hops"][-1]["ip"] == "45.57.90.1"
