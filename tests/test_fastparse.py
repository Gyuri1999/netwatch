"""⚡ Γρήγορος δρόμος ανάλυσης: ίδια πεδία με το scapy, αλλά χωρίς ανατομή για τα απλά IPv4 TCP/UDP."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Dot1Q, Ether, IPv6, Raw, rdpcap  # noqa: E402

import capture  # noqa: E402

E = dict(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:fe")


def _cmp(raw):
    parse = capture.make_parser()
    want = parse(Ether(raw))
    got = capture.fast_parse(raw)
    if got is None:
        return None
    for P in (want, got):
        P.pop("t", None)
    assert got == want, (got, want)
    return got


def test_fast_matches_scapy_on_samples():
    n = 0
    for f in ("samples/lan-attack.pcap", "ctf/level2-silent-visitor.pcap", "ctf/level3-patient-scanner.pcap"):
        for p in rdpcap(os.path.join(ROOT, f)):
            if _cmp(bytes(p)) is not None:
                n += 1
    assert n > 100


def test_fast_matches_scapy_synthetic():
    pkts = [
        Ether(**E) / IP(src="10.0.0.2", dst="1.1.1.1") / TCP(sport=50000, dport=443, flags="S"),
        Ether(**E) / IP(src="10.0.0.2", dst="1.1.1.1") / TCP(sport=50000, dport=443, flags="PA") / Raw(b"\x17\x03\x03" + b"z" * 900),
        Ether(**E) / IP(src="10.0.0.2", dst="1.1.1.1") / TCP(sport=1, dport=2, flags="FPU"),
        Ether(**E) / IP(src="10.0.0.2", dst="1.1.1.1") / TCP(sport=1, dport=2, flags=0),
        Ether(**E) / IP(src="10.0.0.2", dst="1.1.1.1") / TCP(sport=1, dport=2, flags="SEC"),
        Ether(**E) / IP(src="10.0.0.2", dst="10.0.0.9", options=[]) / TCP(sport=5, dport=21, flags="PA") / Raw(b"USER bob\r\n"),
        Ether(**E) / IP(src="10.0.0.2", dst="10.0.0.9") / TCP(sport=5, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\nHost: cam.local:8080\r\n\r\n"),
        Ether(**E) / IP(src="10.0.0.2", dst="10.0.0.9") / TCP(sport=5, dport=80, options=[("MSS", 1460), ("NOP", None)], flags="S"),
        Ether(**E) / IP(src="10.0.0.2", dst="239.255.255.250") / UDP(sport=1900, dport=1900) / Raw(b"M-SEARCH"),
        Ether(**E) / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=40000, dport=51820) / Raw(b"x" * 100),
        Ether(**E) / IP(src="10.0.0.2", dst="1.1.1.1") / TCP(sport=1, dport=2, flags="A") / Raw(b"short"),
    ]
    for p in pkts:
        raw = bytes(p)
        assert _cmp(raw) is not None, p.summary()
        assert _cmp(raw + b"\x00" * 12) is not None  # Ethernet padding δεν μπαίνει στο payload
    # TLS ClientHello με SNI (από το test του parser)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_ja4 import client_hello, sni_ext
    ch = client_hello([0x1301, 0x1302], [sni_ext("example.com")])
    got = _cmp(bytes(Ether(**E) / IP(src="10.0.0.2", dst="1.1.1.1") / TCP(sport=5, dport=443, flags="PA") / Raw(ch)))
    assert got["sni"] == "example.com" and got["ja4"]


def test_slow_path_for_everything_else():
    for p in (Ether(**E) / ARP(psrc="10.0.0.1", pdst="10.0.0.2"),
              Ether(**E) / IPv6() / TCP(),
              Ether(**E) / Dot1Q(vlan=10) / IP() / TCP(),
              Ether(**E) / IP() / ICMP(),
              Ether(**E) / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=5000, dport=53) / DNS(qd=DNSQR(qname="a.b")),
              Ether(**E) / IP(src="10.0.0.2", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="a.local")),
              Ether(**E) / IP(flags="MF") / TCP(),
              Ether(**E) / IP(frag=10) / Raw(b"x" * 30)):
        assert capture.fast_parse(bytes(p)) is None, p.summary()
    assert capture.fast_parse(b"\x00" * 10) is None


class FakeSock:
    def __init__(self, frames):
        self.frames = list(frames)

    def recv_raw(self, x=1514):
        if not self.frames:
            raise EOFError
        f = self.frames.pop(0)
        return (None, None, None) if f is None else (Ether, f, 1.0)


def test_raw_loop_feeds_state():
    seen = []

    class St:
        feed = "live"
        pcap_ring = None

        def process(self, P):
            seen.append(P)
    frames = [bytes(Ether(**E) / IP(src="10.0.0.2", dst="1.1.1.1") / TCP(sport=1, dport=443, flags="S")), None,
              bytes(Ether(**E) / ARP(psrc="10.0.0.1", pdst="10.0.0.2"))]
    try:
        capture.raw_loop(St(), FakeSock(frames), capture.make_parser())
    except EOFError:
        pass
    assert [P["proto"] for P in seen] == ["TCP", "ARP"] and seen[0]["_raw"][:6] == bytes.fromhex("aabbcc0000fe")
