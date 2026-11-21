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


def test_hex_only_for_headers_and_secrets_masked():
    from scapy.layers.snmp import SNMP
    raw = bytes(Ether(src="24:ec:4a:cb:05:d8", dst="bc:24:11:2b:f6:bd") / IP(src="192.168.1.2", dst="192.168.1.4") /
                UDP(sport=5000, dport=161) / SNMP(community="PRIVCOMM"))
    packets.remember({"src": "192.168.1.2", "dst": "192.168.1.4", "proto": "UDP", "len": len(raw), "t": 1, "_id": 7}, raw)
    d = packets.decode(packets.get("192.168.1.2", "192.168.1.4", pid=7))
    eth, ip, udp, snmp = d["layers"]
    assert eth["hex"].startswith("bc24112bf6bd24ec4acb05d8") and eth["off"] == 0 and ip["off"] == 14 and udp["off"] == 34
    assert snmp["hex"] == "" and "PRIVCOMM" not in repr(d) and "505249564" not in repr(d).upper()
    assert any(f["value"].startswith("•••") for f in snmp["fields"] if f["name"] == "community")


def test_get_by_id_falls_back_to_latest():
    for i in (1, 2, 3):
        packets.remember({"src": "10.0.0.1", "dst": "10.0.0.2", "proto": "UDP", "t": i, "_id": i})
    assert packets.get("10.0.0.1", "10.0.0.2", pid=2)["id"] == 2
    old = packets.get("10.0.0.1", "10.0.0.2", pid=99)
    assert old["id"] == 3 and old["approx"]


def test_conversation_ladder_both_directions_only_that_flow():
    A, B = "192.168.1.5", "93.184.216.34"
    rec = [
        {"src": A, "dst": B, "proto": "TCP", "sp": 50000, "dp": 443, "flags": "S", "len": 74, "t": 1.0},
        {"src": B, "dst": A, "proto": "TCP", "sp": 443, "dp": 50000, "flags": "SA", "len": 74, "t": 1.02},
        {"src": A, "dst": B, "proto": "TCP", "sp": 50001, "dp": 443, "flags": "S", "len": 74, "t": 1.03},  # άλλη σύνδεση
        {"src": A, "dst": B, "proto": "TCP", "sp": 50000, "dp": 443, "flags": "A", "len": 66, "t": 1.04},
        {"src": A, "dst": B, "proto": "TCP", "sp": 50000, "dp": 443, "flags": "PA", "len": 583, "t": 1.05, "sni": "example.com"},
        {"src": A, "dst": "8.8.8.8", "proto": "UDP", "sp": 5353, "dp": 53, "len": 70, "t": 1.06},
    ]
    c = packets.conversation(rec, A, B, "TCP", 50000, 443)
    assert [x["f"] for x in c] == ["S", "SA", "A", "PA"] and [x["dir"] for x in c] == ["ab", "ba", "ab", "ab"]
    assert c[-1]["n"] == "example.com" and "payload" not in repr(c)
    rec2 = [{"src": A, "dst": "192.168.1.1", "proto": "ARP", "arp": {"op": 1}, "len": 42, "t": 1},
            {"src": "192.168.1.1", "dst": A, "proto": "ARP", "arp": {"op": 2}, "len": 42, "t": 1.001}]
    assert [x["f"] for x in packets.conversation(rec2, A, "192.168.1.1", "ARP")] == ["who-has", "is-at"]
