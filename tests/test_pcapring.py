import io

from scapy.all import IP, TCP, UDP, Dot1Q, Ether, IPv6, rdpcap

import pcapring


def eth(src, dst, vlan=None):
    l2 = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    if vlan:
        l2 = l2 / Dot1Q(vlan=vlan)
    l3 = IPv6(src=src, dst=dst) if ":" in src else IP(src=src, dst=dst)
    return bytes(l2 / l3 / TCP(sport=1234, dport=80))


def read(data):
    return rdpcap(io.BytesIO(data))


def test_ring_drops_oldest_by_time_and_size():
    r = pcapring.PcapRing({"seconds": 10, "max_mb": 64})
    for i in range(30):
        r.add(1000 + i, eth("10.0.0.1", "10.0.0.2"))
    s = r.stats()
    assert s["packets"] == 11 and s["oldest"] == 1019 and s["newest"] == 1029 and s["dropped"] == 19
    small = pcapring.PcapRing({"seconds": 1e6, "max_mb": 0.001})  # ~1 KB
    pkt = eth("10.0.0.1", "10.0.0.2")
    for i in range(100):
        small.add(i, pkt)
    st = small.stats()
    assert st["bytes"] <= st["max_bytes"] and 0 < st["packets"] < 100
    assert small.buf[-1][0] == 99  # κρατά τα νεότερα


def test_disabled_ring_keeps_nothing():
    r = pcapring.PcapRing({"enabled": False})
    r.add(1, eth("10.0.0.1", "10.0.0.2"))
    assert r.stats()["packets"] == 0


def test_time_window_export_reads_back():
    r = pcapring.PcapRing({"seconds": 1000})
    for i in range(20):
        r.add(100 + i + 0.25, eth("10.0.0.1", "10.0.0.2"))
    data = r.export(105, 114.5)
    assert data[:4] == b"\xd4\xc3\xb2\xa1"
    pk = read(data)
    assert len(pk) == 10
    assert abs(float(pk[0].time) - 105.25) < 1e-5
    assert pk[0].haslayer(TCP)
    assert len(read(r.export(500, 600))) == 0


def test_ip_filter_vlan_and_ipv6(tmp_path):
    r = pcapring.PcapRing({"seconds": 1000})
    r.add(1, eth("192.168.1.5", "8.8.8.8"))
    r.add(2, eth("192.168.1.9", "192.168.1.5", vlan=20))
    r.add(3, eth("192.168.1.9", "1.1.1.1", vlan=30))
    r.add(4, eth("fd00::5", "2001:db8::1"))
    r.add(5, eth("2001:db8::2", "fd00::5", vlan=5))
    r.add(6, bytes(Ether() / Dot1Q(vlan=1) / Dot1Q(vlan=2) / IP(src="10.9.9.9", dst="10.0.0.1") / UDP()))  # QinQ
    assert len(read(r.export(0, 10, ips=["192.168.1.5"]))) == 2
    assert len(read(r.export(0, 10, ips=["fd00::5"]))) == 2
    assert len(read(r.export(0, 10, ips=["192.168.1.0/24"]))) == 3
    assert len(read(r.export(0, 10, ips=["10.9.9.9"]))) == 1
    p = tmp_path / "x" / "out.pcap"
    data = r.export(0, 10, ips=["1.1.1.1", "2001:db8::1"], path=str(p))
    assert p.read_bytes() == data and len(read(data)) == 2


def test_raw_ip_linktype_and_parse():
    raw = bytes(IP(src="10.0.0.1", dst="10.0.0.2") / TCP())
    assert pcapring.packet_ips(raw, 101) == (bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    assert pcapring.packet_ips(b"\x00" * 5, 1) is None
    r = pcapring.PcapRing()
    r.add(1, raw, linktype=101)
    data = r.export(0, 2, ips=["10.0.0.2"])
    assert data[20:24] == (101).to_bytes(4, "little") and len(read(data)) == 1


def test_export_for_alert_window_and_filename():
    r = pcapring.PcapRing({"seconds": 1000})
    for i in range(200):
        r.add(1000 + i, eth("192.168.1.66" if i % 2 else "192.168.1.7", "192.168.1.10"))
    res = r.export_for_alert({"t": 1100, "actor": "192.168.1.66", "target": "192.168.1.10"}, before=10, after=5)
    assert res["count"] == 16 and not res["synthetic"] and res["filename"].endswith(".pcap")
    res = r.export_for_alert({"t": 1100, "actor": "192.168.1.66", "target": "κάτι"}, before=10, after=5)
    assert res["count"] == 8 and res["ips"] == ["192.168.1.66"]
    assert r.export_for_alert({"t": 1, "actor": "x"})["note"]


def test_synth_for_alert_is_marked_and_valid():
    r = pcapring.PcapRing(sim=True)
    for typ in ("Port scan", "Brute force", "DNS tunneling", "Port scan (UDP)", "Network sweep (ping)"):
        res = r.export_for_alert({"t": 1000, "type": typ, "actor": "192.168.1.66", "target": "192.168.1.10"})
        assert res["synthetic"] and res["filename"].endswith("-demo.pcap")
        assert len(read(res["pcap"])) == res["count"] > 0
