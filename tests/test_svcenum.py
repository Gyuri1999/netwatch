import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import svcenum as sv  # noqa: E402


def smb1_resp(dialect_index):
    body = b"\xffSMB" + b"\x72" + b"\x00" * 27 + b"\x01" + struct.pack("<H", dialect_index) + b"\x00\x00"
    return struct.pack(">I", len(body)) + body


def smb2_resp(security_mode):
    hdr = b"\xfeSMB" + b"\x00" * 60            # 64-byte SMB2 header (τα υπόλοιπα δεν μας νοιάζουν)
    neg = struct.pack("<H", 65) + struct.pack("<H", security_mode) + b"\x00" * 60
    body = hdr + neg
    return struct.pack(">I", len(body)) + body


def rdp_resp(typ, value):
    neg = bytes([typ, 0]) + struct.pack("<H", 8) + struct.pack("<I", value)
    return b"\x03\x00" + struct.pack(">H", 11 + len(neg)) + b"\x06\xd0\x00\x00\x12\x34\x00" + neg


def test_smbv1_enabled_flagged():
    f = sv.read_smb(smb1_resp(5))
    assert f and f[0][0] == "high" and "SMBv1" in f[0][1]


def test_smbv1_no_dialect_not_flagged():
    assert sv.read_smb(smb1_resp(0xFFFF)) == []


def test_smb2_signing_required_clean():
    assert sv.read_smb(smb2_resp(0x03)) == []       # enabled|required
    assert sv.read_smb(smb2_resp(0x02)) == []       # required


def test_smb2_signing_not_required_flagged():
    f = sv.read_smb(smb2_resp(0x01))                 # enabled, not required
    assert f and f[0][0] == "med" and "relay" in f[0][1].lower()


def test_rdp_no_nla_flagged():
    f = sv.read_rdp(rdp_resp(0x02, 0x00))            # NEG_RSP, selected = standard RDP
    assert f and f[0][0] == "med" and "NLA" in f[0][1]


def test_rdp_nla_ok():
    assert sv.read_rdp(rdp_resp(0x02, 0x02)) == []   # CredSSP selected
    assert sv.read_rdp(rdp_resp(0x03, 0x05)) == []   # HYBRID_REQUIRED_BY_SERVER failure = NLA enforced


def test_rdp_ssl_not_allowed_flagged():
    f = sv.read_rdp(rdp_resp(0x03, 0x02))            # SSL_NOT_ALLOWED → μόνο παλιό RDP
    assert f and f[0][0] == "med"


def test_packets_are_well_formed():
    smb = sv.smb_negotiate_packet()
    assert struct.unpack(">I", smb[:4])[0] == len(smb) - 4 and smb[4:8] == b"\xffSMB"
    assert b"NT LM 0.12" in smb and b"SMB 2.???" in smb
    rdp = sv.rdp_negotiate_packet()
    assert rdp[:2] == b"\x03\x00" and struct.unpack(">H", rdp[2:4])[0] == len(rdp)


def test_enrich_only_private_and_right_port():
    seen = []

    def fake(ip, port, timeout, read=2048):
        seen.append((ip, port))
        return smb1_resp(5) if port == 445 else rdp_resp(0x02, 0x00)

    hosts = [
        {"ip": "192.168.1.40", "services": [{"port": 445, "proto": "tcp"}, {"port": 80, "proto": "tcp"}]},
        {"ip": "192.168.1.77", "services": [{"port": 3389, "proto": "tcp"}]},
        {"ip": "8.8.8.8", "services": [{"port": 445, "proto": "tcp"}]},        # δημόσια → αγνοείται
        {"ip": "192.168.1.5", "services": [{"port": 445, "proto": "udp"}]},    # udp → αγνοείται
    ]
    sv.enrich_hosts(hosts, exchange=fake)
    assert sorted(seen) == [("192.168.1.40", 445), ("192.168.1.77", 3389)]
    assert hosts[0]["services"][0]["findings"][0][0] == "high"
    assert hosts[1]["services"][0]["findings"][0][0] == "med"
    assert "findings" not in hosts[0]["services"][1]  # η θύρα 80 δεν έχει probe


def test_probe_swallows_errors():
    def boom(*a, **k):
        raise OSError("down")

    hosts = [{"ip": "192.168.1.9", "services": [{"port": 445, "proto": "tcp"}]}]
    sv.enrich_hosts(hosts, exchange=boom)             # δεν πρέπει να σκάσει
    assert "findings" not in hosts[0]["services"][0]


def test_demo_scan_has_enumeration_findings():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    import demo
    hosts = demo.demo_scan(lambda **k: None)
    by = {h["ip"]: h for h in hosts}
    f40 = [f for s in by["192.168.1.40"]["services"] if s["port"] == 445 for f in s.get("findings", [])]
    f77 = [f for s in by["192.168.1.77"]["services"] if s["port"] == 3389 for f in s.get("findings", [])]
    assert f40 and f40[0][0] == "high" and f77 and f77[0][0] == "med"
