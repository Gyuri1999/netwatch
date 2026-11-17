import packets
from scapy.all import IP, TCP, UDP, Ether, Raw
from scapy.layers.dns import DNS, DNSQR


def setup_function():
    packets.clear()


def test_real_packet_layers_and_no_payload_content():
    raw = bytes(Ether(src="24:ec:4a:cb:05:d8", dst="bc:24:11:2b:f6:bd") / IP(src="192.168.1.20", dst="192.168.1.17", ttl=64) /
                TCP(sport=51234, dport=1883, flags="PA") / Raw(b"\x10\x20" + b"TOPSECRET" * 20))
    packets.remember({"src": "192.168.1.20", "dst": "192.168.1.17", "proto": "TCP", "len": len(raw), "t": 1, "cred": {"x": 1}}, raw)
    d = packets.decode(packets.get("192.168.1.20", "192.168.1.17"))
    assert d["real"] and [l["name"] for l in d["layers"]] == ["Ethernet", "IP", "TCP"]
    assert [l["osi"] for l in d["layers"]] == [2, 3, 4]
    assert d["payload"] == len(raw) - 54
    assert "TOPSECRET" not in repr(d)
    ttl = [f for f in d["layers"][1]["fields"] if f["name"] == "ttl"][0]
    assert ttl["value"] == "64" and "Time To Live" in ttl["info"] and ttl["lesson"]
    dport = [f for f in d["layers"][2]["fields"] if f["name"] == "dport"][0]
    assert dport["value"] == "1883 (MQTT)"
    assert "cred" not in packets.get("192.168.1.20", "192.168.1.17")["P"]


def test_dns_and_synthetic_and_flows_lru():
    raw = bytes(Ether() / IP(src="192.168.1.49", dst="1.1.1.1") / UDP(sport=5555, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))
    packets.remember({"src": "192.168.1.49", "dst": "1.1.1.1", "proto": "UDP", "len": len(raw), "t": 2}, raw)
    dns = packets.decode(packets.get("192.168.1.49", "1.1.1.1"))["layers"][-1]
    assert dns["name"] == "DNS" and any(f["name"] == "qd" and "example.com" in f["value"] for f in dns["fields"])
    syn = packets.decode({"P": {"src": "192.168.1.5", "dst": "8.8.8.8", "proto": "TCP", "sp": 50000, "dp": 443, "flags": "S"}, "raw": None, "t": 0})
    assert not syn["real"] and [f["value"] for f in syn["layers"][2]["fields"] if f["name"] == "flags"] == ["S"]
    for i in range(packets.MAX_PAIRS + 5):
        packets.remember({"src": f"10.0.{i // 250}.{i % 250}", "dst": "10.9.9.9", "proto": "UDP", "t": i})
    assert len(packets._pairs) == packets.MAX_PAIRS and packets.get("192.168.1.49", "1.1.1.1") is None
    assert packets.flows("10.9.9.9", limit=3)[0]["src"] == f"10.0.{(packets.MAX_PAIRS + 4) // 250}.{(packets.MAX_PAIRS + 4) % 250}"
