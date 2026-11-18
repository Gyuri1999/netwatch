import ipaddress
import json
import random
import socket
import struct
import threading
import time

import flows


class St:
    def __init__(self):
        self.alerts = []
        self.lock = threading.RLock()

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, detail))


def ip4(s):
    return ipaddress.IPv4Address(s).packed


NOW = 1_800_000_000


def test_v5_parse():
    pkt = flows.build_v5([("192.168.1.20", "192.168.1.17", 50000, 1883, 6, 4200, 12),
                          ("192.168.1.10", "23.246.2.141", 51515, 443, 6, 120000, 90)], secs=NOW)
    ver, recs, dropped = flows.parse_datagram(pkt, "192.168.1.1", flows.Templates())
    assert ver == 5 and dropped == 0 and len(recs) == 2
    r = recs[0]
    assert (r["src"], r["dst"], r["sport"], r["dport"], r["proto"], r["bytes"], r["pkts"]) == \
        ("192.168.1.20", "192.168.1.17", 50000, 1883, 6, 4200, 12)
    assert r["exporter"] == "192.168.1.1" and r["in_if"] == 1 and r["out_if"] == 2 and r["tcp_flags"] == 0x1B
    assert abs(r["start"] - (NOW - 5)) < 0.01 and abs(r["end"] - (NOW - 0.1)) < 0.01
    assert set(r) == {"exporter", "src", "dst", "sport", "dport", "proto", "bytes", "pkts", "start", "end",
                      "tcp_flags", "in_if", "out_if"}


def test_v5_sampling_multiplies():
    pkt = flows.build_v5([("192.168.1.20", "8.8.8.8", 1, 53, 17, 100, 1)], secs=NOW, sampling=(1 << 14) | 10)
    _, recs, _ = flows.parse_datagram(pkt, "x", flows.Templates())
    assert recs[0]["bytes"] == 1000 and recs[0]["pkts"] == 10


def _v9(flowsets, src_id=7, uptime=60000):
    body = b"".join(flowsets)
    return struct.pack("!HHIIII", 9, len(flowsets), uptime, NOW, 1, src_id) + body


def _v9_template():
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (22, 4), (21, 4), (6, 1)]
    t = struct.pack("!HH", 300, len(fields)) + b"".join(struct.pack("!HH", a, b) for a, b in fields)
    return struct.pack("!HH", 0, 4 + len(t)) + t


def _v9_data():
    rec = ip4("192.168.1.30") + ip4("140.82.112.4") + struct.pack("!HHBIIIIB", 40000, 443, 6, 9000, 20,
                                                                    50000, 59000, 0x12)
    pad = b"\0" * ((4 - (4 + len(rec)) % 4) % 4)
    return struct.pack("!HH", 300, 4 + len(rec) + len(pad)) + rec + pad


def test_v9_template_then_data_and_data_before_template_dropped():
    tc = flows.Templates()
    # δεδομένα πριν από το template → απορρίπτονται
    ver, recs, dropped = flows.parse_datagram(_v9([_v9_data()]), "10.0.0.1", tc)
    assert ver == 9 and recs == [] and dropped == 1
    # template + δεδομένα στο ίδιο πακέτο
    ver, recs, dropped = flows.parse_datagram(_v9([_v9_template(), _v9_data()]), "10.0.0.1", tc)
    assert ver == 9 and dropped == 0 and len(recs) == 1
    r = recs[0]
    assert (r["src"], r["dst"], r["sport"], r["dport"], r["proto"], r["bytes"], r["pkts"], r["tcp_flags"]) == \
        ("192.168.1.30", "140.82.112.4", 40000, 443, 6, 9000, 20, 0x12)
    assert abs(r["start"] - (NOW - 10)) < 0.01 and abs(r["end"] - (NOW - 1)) < 0.01
    # μόνο δεδομένα πλέον: το template έχει μείνει στην cache
    _, recs, _ = flows.parse_datagram(_v9([_v9_data()]), "10.0.0.1", tc)
    assert len(recs) == 1
    # άλλο source_id ή άλλος exporter: δεν μοιράζονται templates
    assert flows.parse_datagram(_v9([_v9_data()], src_id=8), "10.0.0.1", tc)[1] == []
    assert flows.parse_datagram(_v9([_v9_data()]), "10.0.0.2", tc)[1] == []


def test_ipfix_varlen_and_enterprise_fields():
    tc = flows.Templates()
    pkt = flows.build_ipfix([("192.168.1.42", "93.184.215.14", 45678, 80, 6, 1500, 6)], secs=NOW)
    ver, recs, dropped = flows.parse_datagram(pkt, "192.168.1.1", tc)
    assert ver == 10 and dropped == 0 and len(recs) == 1
    r = recs[0]
    assert (r["src"], r["dst"], r["sport"], r["dport"], r["bytes"], r["pkts"]) == \
        ("192.168.1.42", "93.184.215.14", 45678, 80, 1500, 6)
    assert r["start"] == NOW - 5 and r["end"] == NOW


def test_ipfix_hand_built_long_varlen_and_unknown_enterprise():
    # template: src4, enterprise(9, len 2, PEN 9), varlen, dst4, ipv6? no — octets(8)
    t = struct.pack("!HH", 400, 4) + struct.pack("!HH", 8, 4) + struct.pack("!HHI", 0x8000 | 9, 2, 9) + \
        struct.pack("!HH", 82, 65535) + struct.pack("!HH", 12, 4)
    tset = struct.pack("!HH", 2, 4 + len(t)) + t
    name = b"x" * 300  # μήκος > 254 → κωδικοποίηση 255 + 2 bytes
    rec = ip4("10.1.1.5") + b"\xaa\xbb" + b"\xff" + struct.pack("!H", len(name)) + name + ip4("10.1.1.6")
    dset = struct.pack("!HH", 400, 4 + len(rec)) + rec
    msg = tset + dset
    pkt = struct.pack("!HHIII", 10, 16 + len(msg), NOW, 1, 3) + msg
    ver, recs, dropped = flows.parse_datagram(pkt, "e", flows.Templates())
    assert ver == 10 and len(recs) == 1 and recs[0]["src"] == "10.1.1.5" and recs[0]["dst"] == "10.1.1.6"


def _sflow(samples, agent="192.168.1.2"):
    hdr = struct.pack("!II", 5, 1) + ip4(agent) + struct.pack("!IIII", 0, 1, 1000, len(samples))
    return hdr + b"".join(samples)


def _flow_sample(frame_len=1500, rate=512):
    eth = b"\x11" * 6 + b"\x22" * 6 + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, ip4("192.168.1.20"), ip4("34.120.1.1"))
    tcp = struct.pack("!HHIIBBHHH", 51000, 443, 1, 0, 0x50, 0x18, 1000, 0, 0)
    hdr = eth + ip + tcp
    pad = b"\0" * ((4 - len(hdr) % 4) % 4)
    raw = struct.pack("!IIII", 1, frame_len, 4, len(hdr)) + hdr + pad
    frec = struct.pack("!II", 1, len(raw)) + raw
    body = struct.pack("!IIIIIIII", 1, 3, rate, 100000, 0, 3, 5, 1) + frec
    return struct.pack("!II", 1, len(body)) + body


def _counter_sample():
    body = struct.pack("!III", 1, 3, 0)
    return struct.pack("!II", 2, len(body)) + body


def test_sflow_flow_sample_ipv4_tcp():
    st = {}
    ver, recs, dropped = flows.parse_datagram(_sflow([_counter_sample(), _flow_sample()]), "192.168.1.2",
                                              flows.Templates(), now=NOW, stats=st)
    assert ver == "sflow5" and dropped == 0 and len(recs) == 1
    r = recs[0]
    assert (r["src"], r["dst"], r["sport"], r["dport"], r["proto"], r["tcp_flags"]) == \
        ("192.168.1.20", "34.120.1.1", 51000, 443, 6, 0x18)
    assert r["bytes"] == 1500 * 512 and r["pkts"] == 512 and r["in_if"] == 3 and r["out_if"] == 5
    assert r["start"] == NOW and st["counter_samples"] == 1


def test_sflow_vlan_and_ipv6_udp():
    eth = b"\x11" * 12 + struct.pack("!HHH", 0x8100, 10, 0x86DD)
    ip6 = struct.pack("!IHBB", 0x60000000, 8, 17, 64) + ipaddress.IPv6Address("fd00::5").packed + \
        ipaddress.IPv6Address("2001:db8::1").packed
    udp = struct.pack("!HHHH", 5353, 53, 8, 0)
    p = flows.parse_l3(eth + ip6 + udp, 1)
    assert p == {"src": "fd00::5", "dst": "2001:db8::1", "proto": 17, "sport": 5353, "dport": 53, "tcp_flags": 0}


def test_garbage_and_truncated_never_raise():
    rnd = random.Random(1)
    tc = flows.Templates()
    good = [flows.build_v5([("192.168.1.20", "1.2.3.4", 1, 2, 6, 3, 4)] * 3),
            flows.build_ipfix([("192.168.1.20", "1.2.3.4", 1, 2, 6, 3, 4)] * 3),
            _v9([_v9_template(), _v9_data()]), _sflow([_flow_sample(), _counter_sample()])]
    f = flows.Flows(None, {"allow": []})
    for g in good:
        for cut in range(len(g) + 1):
            flows.parse_datagram(g[:cut], "e", tc)
            f.ingest(g[:cut], ("10.0.0.1", 1))
        for _ in range(300):
            b = bytearray(g)
            for _ in range(rnd.randint(1, 8)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            flows.parse_datagram(bytes(b), "e", tc)
            f.ingest(bytes(b), ("10.0.0.1", 1))
    for _ in range(500):
        flows.parse_datagram(bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 200))), "e", tc)
    # παθολογικά templates: πάρα πολλά πεδία, πεδίο μήκους 0
    bad = struct.pack("!HH", 300, 5000) + b"\0" * 64
    flows.parse_datagram(_v9([struct.pack("!HH", 0, 4 + len(bad)) + bad]), "e", tc)
    z = struct.pack("!HHHH", 301, 1, 8, 0)
    flows.parse_datagram(_v9([struct.pack("!HH", 0, 4 + len(z)) + z]), "e", tc)
    assert tc.get(("e", 9, 7, 301)) is None
    # sFlow με τεράστιο πλήθος δειγμάτων
    flows.parse_datagram(struct.pack("!II", 5, 1) + ip4("1.1.1.1") + struct.pack("!IIII", 0, 1, 1, 0xFFFFFFFF), "e", tc)
    assert len(tc) <= flows.MAX_TEMPLATES


def test_template_cache_capped():
    tc = flows.Templates(cap=10)
    for i in range(50):
        t = struct.pack("!HHHH", 256 + i, 1, 8, 4)
        flows.parse_datagram(_v9([struct.pack("!HH", 0, 4 + len(t)) + t]), "e", tc)
    assert len(tc) == 10


def test_allow_list_drops_and_counts():
    f = flows.Flows(None, {"allow": ["192.168.1.1"]})
    pkt = flows.build_v5([("192.168.1.20", "1.2.3.4", 1000, 443, 6, 100, 1)], secs=NOW)
    assert f.ingest(pkt, ("192.168.1.66", 9999), now=NOW) == 0
    assert f.ingest(pkt, ("192.168.1.1", 9999), now=NOW) == 1
    s = f.status(now=NOW)
    assert s["counts"]["rejected"] == 1 and s["rejected_from"] == [{"ip": "192.168.1.66", "count": 1}]
    assert [e["ip"] for e in s["exporters"]] == ["192.168.1.1"]
    # κενό allow = από όλους
    assert flows.Flows(None, {"allow": []}).ingest(pkt, ("8.8.8.8", 1), now=NOW) == 1


def test_aggregation_status_and_device():
    f = flows.Flows(None, {"allow": []})
    f.ingest(flows.build_v5([("192.168.1.20", "192.168.1.17", 50000, 1883, 6, 1000, 10),
                             ("192.168.1.10", "23.246.2.141", 51515, 443, 6, 200, 2),
                             ("23.246.2.141", "192.168.1.10", 443, 51515, 6, 90000, 70)], secs=NOW),
             ("192.168.1.1", 2055), now=NOW)
    f.ingest(flows.build_ipfix([("192.168.1.10", "23.246.2.141", 51516, 443, 6, 300, 3)], secs=NOW),
             ("192.168.1.1", 2055), now=NOW + 60)
    s = f.status(now=NOW + 61)
    json.dumps(s)
    assert s["totals"]["records"] == 4 and s["totals"]["bytes"] == 91500
    assert s["top_talkers"][0]["ip"] == "192.168.1.10" and s["top_talkers"][0]["bytes"] == 90500
    assert s["top_talkers"][0]["bytes_in"] == 90000
    assert s["top_destinations"][0]["ip"] == "23.246.2.141" and s["top_destinations"][0]["ports"] == [443]
    assert s["top_conversations"][0]["device"] == "192.168.1.10"
    assert {e["ip"]: e["version"] for e in s["exporters"]} == {"192.168.1.1": 10}
    assert s["exporters"][0]["records"] == 4 and s["exporters"][0]["templates"] == 1
    d = f.device("192.168.1.10", now=NOW + 61)
    json.dumps(d)
    assert d["destinations"][0]["ip"] == "23.246.2.141" and d["destinations"][0]["bytes"] == 90500
    assert d["destinations"][0]["ports"] == [443] and d["destinations"][0]["local"] is False
    # τοπικό↔τοπικό: φαίνεται και στις δύο συσκευές
    assert f.device("192.168.1.17", now=NOW + 61)["destinations"][0]["ip"] == "192.168.1.20"
    assert f.device("192.168.1.20", now=NOW + 61)["destinations"][0]["ports"] == [1883]
    # μετά το παράθυρο (30′) όλα ξεχνιούνται
    s = f.status(now=NOW + 31 * 60 + 61)
    assert s["totals"]["records"] == 0 and s["top_talkers"] == [] and not f.buckets


def test_ports_capped():
    f = flows.Flows(None, {"allow": []})
    f.ingest_records([flows.record("e", "192.168.1.5", "1.1.1.1", 50000, p, 6, 10, 1) for p in range(100, 130)], now=NOW)
    assert len(f.device("192.168.1.5", now=NOW)["destinations"][0]["ports"]) == 8


def test_upload_alert_and_cooldown():
    st = St()
    f = flows.Flows(st, {"allow": [], "upload_mb": 10})
    mb = 1024 * 1024
    for i in range(4):  # 4 × 3 MB μέσα σε 4′
        f.ingest_records([flows.record("e", "192.168.1.42", "52.1.2.3", 40000, 443, 6, 3 * mb, 2000)], now=NOW + i * 60)
    ups = [a for a in st.alerts if a[0] == "Μεγάλη έξοδος δεδομένων"]
    assert len(ups) == 1 and ups[0][1] == "med" and ups[0][2] == "192.168.1.42" and ups[0][3] == "52.1.2.3"
    f.ingest_records([flows.record("e", "192.168.1.42", "52.1.2.3", 40000, 443, 6, 30 * mb, 2000)], now=NOW + 300)
    assert len([a for a in st.alerts if a[0] == "Μεγάλη έξοδος δεδομένων"]) == 1  # cooldown
    # λήψη (download) ή κίνηση μέσα στο LAN δεν μετράει
    st2 = St()
    g = flows.Flows(st2, {"allow": [], "upload_mb": 10})
    g.ingest_records([flows.record("e", "52.1.2.3", "192.168.1.42", 443, 40000, 6, 50 * mb, 1),
                      flows.record("e", "192.168.1.42", "192.168.1.16", 40000, 445, 6, 50 * mb, 1)], now=NOW)
    assert st2.alerts == []
    # μοιρασμένο σε > 10′ δεν πιάνεται
    st3 = St()
    h = flows.Flows(st3, {"allow": [], "upload_mb": 10})
    for i in range(6):
        h.ingest_records([flows.record("e", "192.168.1.42", "52.1.2.3", 1, 443, 6, 3 * mb, 1)], now=NOW + i * 300)
    assert st3.alerts == []


def test_suspicious_port_alert():
    st = St()
    f = flows.Flows(st, {"allow": []})
    # υπολογιστής → SMB μέσα στο LAN: φυσιολογικό
    f.ingest_records([flows.record("e", "192.168.1.42", "192.168.1.16", 50000, 445, 6, 100, 1)], now=NOW)
    assert st.alerts == []
    # οποιαδήποτε συσκευή → RDP στο Internet
    f.ingest_records([flows.record("e", "192.168.1.42", "45.1.2.3", 50000, 3389, 6, 100, 1)], now=NOW)
    assert st.alerts[-1][:4] == ("Ροή προς ύποπτη θύρα", "med", "192.168.1.42", "45.1.2.3:3389")
    # ESP32 (μιλά MQTT) → Telnet σε άλλη συσκευή του LAN
    f.ingest_records([flows.record("e", "192.168.1.20", "192.168.1.17", 50000, 1883, 6, 100, 1),
                      flows.record("e", "192.168.1.20", "192.168.1.50", 50001, 23, 6, 100, 1),
                      flows.record("e", "192.168.1.20", "192.168.1.51", 50002, 23, 6, 100, 1)], now=NOW)
    tel = [a for a in st.alerts if a[2] == "192.168.1.20"]
    assert len(tel) == 1 and tel[0][1] == "med"  # cooldown ανά (συσκευή, θύρα)


def test_demo_mode_has_data():
    f = flows.Flows(St(), {}, sim=True)
    for i in range(5):
        f.sim_tick(now=NOW + i * 3)
    s = f.status(now=NOW + 15)
    assert s["demo"] and s["enabled"] and s["totals"]["records"] > 0
    ips = {t["ip"] for t in s["top_talkers"]}
    assert {"192.168.1.10", "192.168.1.20", "192.168.1.30"} <= ips
    assert 1883 in f.device("192.168.1.20", now=NOW + 15)["destinations"][0]["ports"] or \
        any(1883 in d["ports"] for d in f.device("192.168.1.20", now=NOW + 15)["destinations"])


def test_udp_listener_end_to_end():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    f = flows.Flows(None, {"enabled": True, "bind": "127.0.0.1", "netflow_port": port, "sflow_port": None,
                           "allow": ["127.0.0.1"]})
    th = threading.Thread(target=f.run_forever, daemon=True)
    th.start()
    for _ in range(50):
        if f.listening["netflow"]:
            break
        time.sleep(0.02)
    flows.send_test("127.0.0.1", port)
    for _ in range(100):
        if f.status()["counts"]["records"] >= 4:
            break
        time.sleep(0.02)
    f.stop()
    th.join(3)
    s = f.status()
    assert s["counts"]["records"] == 4 and s["listening"]["netflow"] == port
    assert {e["version"] for e in s["exporters"]} <= {5, 10}
