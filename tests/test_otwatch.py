import json
import os
import random
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import otwatch as o  # noqa: E402


def H(s):
    return bytes.fromhex(s.replace(" ", ""))


# ── fixtures γραμμένα με το χέρι από τις προδιαγραφές ──
# Modbus Application Protocol V1.1b3 §6.21: Read Device Identification (basic, object 0), unit 255, transaction 1
MB_DEVID_REQ = H("0001 0000 0005 ff 2b 0e 01 00")
# απάντηση: conformity 01, more 00, next 00, 3 objects: 00 "Fronius", 01 "Symo", 02 "1.2"
MB_DEVID_PDU = H("2b 0e 01 01 00 00 03 00 07") + b"Fronius" + H("01 04") + b"Symo" + H("02 03") + b"1.2"
# §6.3 Read Holding Registers: addr 0x006B, 3 registers → 0x022B, 0x0000, 0x0064
MB_READ_REQ = H("0001 0000 0006 11 03 00 6b 00 03")
MB_READ_PDU = H("03 06 02 2b 00 00 00 64")
# §6.1 Read Coils: 19 coils από το 0x0013 → CD 6B 05
MB_COILS_PDU = H("01 03 cd 6b 05")
# αιτήματα εγγραφής (§6.5, 6.6, 6.11, 6.12, 6.16, 6.17) — μόνο για τον ΠΑΘΗΤΙΚΟ ανιχνευτή
W5 = H("0007 0000 0006 01 05 00 ac ff 00")
W6 = H("0008 0000 0006 01 06 00 01 00 03")
W15 = H("0009 0000 0009 01 0f 00 13 00 0a 02 cd 01")
W16 = H("000a 0000 000b 01 10 00 01 00 02 04 00 0a 01 02")
W22 = H("000b 0000 0008 01 16 00 04 00 f2 00 25")
W23 = H("000c 0000 0011 01 17 00 03 00 06 00 0e 00 03 06 00 ff 00 ff 00 ff")
R3 = H("000d 0000 0006 01 03 00 6b 00 03")

# ASHRAE 135 Annex J + κεφ. 20: Who-Is (global broadcast) και I-Am (device 120001, max APDU 1476, seg both, vendor 7)
BAC_WHOIS = H("81 0b 00 0c 01 20 ff ff 00 ff 10 08")
BAC_IAM = H("81 0b 00 18 01 20 ff ff 00 ff 10 00 c4 02 01 d4 c1 22 05 c4 91 00 21 07")
# I-Am από συσκευή MS/TP πίσω από router: SNET 5, SADR 0c · device 123, max APDU 50, seg none, vendor 364
BAC_IAM_ROUTED = H("81 0b 00 18 01 08 00 05 01 0c 10 00 c4 02 00 00 7b 21 32 91 03 22 01 6c")
# Confirmed-Request WriteProperty (15): analog-value 3, present-value (85), REAL
BAC_WP = H("81 0a 00 18 01 04 00 05 01 0f 0c 00 80 00 03 19 55 3e 44 42 2a 00 00 3f")
BAC_REINIT = H("81 0a 00 0c 01 04 00 05 02 14 09 01")       # ReinitializeDevice warmstart
BAC_DCC = H("81 0a 00 0c 01 04 00 05 03 11 19 01")          # DeviceCommunicationControl disable
BAC_RP = H("81 0a 00 11 01 04 00 05 01 0c 0c 02 00 00 01 19 4d")  # ReadProperty — όχι εγγραφή

# KNXnet/IP Core: SEARCH_REQUEST με HPAI 192.168.1.10:35389 και SEARCH_RESPONSE από 192.168.1.80
KNX_REQ = H("06 10 02 01 00 0e 08 01 c0 a8 01 0a 8a 3d")
KNX_NAME = b"KNX IP Interface 731".ljust(30, b"\x00")
KNX_RESP = (H("06 10 02 02 00 4c") + H("08 01 c0 a8 01 50 0e 57")
            + H("36 01 02 00 11 fa 00 00 00 c5 01 02 3a 7f e0 00 17 0c 00 24 6d 01 3a 7f") + KNX_NAME
            + H("08 02 02 01 03 01 04 01"))


def frame(src, dst, sp, dp, payload, udp=False, vlan=False, pad=0, cut=128):
    """Ethernet II + IPv4 + TCP/UDP, όπως φτάνει στο P["_raw"] (πρώτα 128 bytes)."""
    ip4 = lambda a: bytes(int(x) for x in a.split("."))  # noqa: E731
    if udp:
        l4 = struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload
    else:
        l4 = struct.pack(">HHIIBBHHH", sp, dp, 1, 1, 0x50, 0x18, 8192, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(l4), 0, 0x4000, 64, 17 if udp else 6, 0) + ip4(src) + ip4(dst)
    eth = b"\x02" * 6 + b"\x04" * 6 + (H("8100 000a") if vlan else b"") + H("0800")
    return (eth + ip + l4 + b"\x00" * pad)[:cut]


def pkt(src, dst, payload, dp=502, udp=False, **kw):
    return {"src": src, "dst": dst, "proto": "UDP" if udp else "TCP", "sp": 40000, "dp": dp, "t": 1000.0,
            "_raw": frame(src, dst, 40000, dp, payload, udp=udp, **kw)}


class FakeConn:
    def __init__(self, net, ip, handler):
        self.net, self.ip, self.handler = net, ip, handler

    def xfer(self, fr):
        self.net.sent.append((self.ip, fr))
        tid, unit, pdu = o.parse_mbap(fr)
        r = self.handler(unit, pdu)
        return b"" if r is None else struct.pack(">HHHB", tid, 0, len(r) + 1, unit) + r

    def close(self):
        self.net.closed += 1


class FakeNet:
    def __init__(self, modbus=None, bacnet=None, knx=None):
        self.mb, self.bac, self.knx = modbus or {}, bacnet or [], knx or []
        self.sent, self.closed, self.opened = [], 0, []

    def modbus_open(self, ip, timeout=1.0):
        self.opened.append(ip)
        if ip not in self.mb:
            raise OSError("refused")
        return FakeConn(self, ip, self.mb[ip])

    def bacnet_whois(self, timeout=2.0):
        return self.bac

    def knx_search(self, timeout=2.0):
        return self.knx


class State:
    gateway = "192.168.1.1"

    def __init__(self, ips=("192.168.1.60", "192.168.1.61", "192.168.1.5")):
        self.hosts = {ip: {"ip": ip, "kind": "local", "names": {"inv.local"} if ip.endswith(".60") else set()} for ip in ips}
        self.hosts["8.8.8.8"] = {"ip": "8.8.8.8", "kind": "public", "names": set()}
        self.hosts["192.168.1.2"] = {"ip": "192.168.1.2", "kind": "local", "names": set(), "me": True}
        self.alerts = []

    def _dtype(self, h):
        return {"dtype": "iot", "dicon": "🔌", "vendor": "ACME"}

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, detail, kw))


def fronius(unit, pdu):          # απαντά στο Read Device Identification
    return MB_DEVID_PDU if pdu == o.DEVID_REQ and unit == 255 else None


def sunspec(unit, pdu):          # devid → illegal function· SunSpec common model στο 40000
    if unit != 1:
        return None
    if pdu[0] == 0x2B:
        return H("ab 01")
    if pdu == H("03 9c 40 00 44"):
        body = b"SunS" + struct.pack(">HH", 1, 65) + b"SMA".ljust(32, b"\x00") + b"STP 10.0".ljust(32, b"\x00") \
            + b"\x00" * 16 + b"3.10".ljust(16, b"\x00") + b"SN123".ljust(32, b"\x00")
        return bytes((3, len(body))) + body
    return H("83 02")


# ═════════════ Modbus ═════════════
def test_modbus_request_frames_are_byte_exact():
    assert o.mbap(1, 255, o.DEVID_REQ) == MB_DEVID_REQ
    assert o.mbap(1, 0x11, o.read_req(3, 0x6B, 3)) == MB_READ_REQ
    assert o.parse_mbap(MB_READ_REQ) == (1, 0x11, H("03 00 6b 00 03"))
    assert o.parse_mbap(MB_READ_REQ, tid=2) is None          # λάθος transaction
    assert o.parse_mbap(H("0001 0001 0006 11 03 00 6b 00 03")) is None  # protocol id ≠ 0
    assert o.parse_mbap(MB_READ_REQ[:-1]) is None            # κομμένο


def test_never_builds_a_write():
    for fc in (5, 6, 15, 16, 22, 23, 8, 17, 43 + 1):
        for build in (lambda: o.mbap(1, 1, bytes((fc, 0, 0, 0, 1))), lambda: o.read_req(fc, 0, 1)):
            try:
                build()
            except ValueError:
                continue
            raise AssertionError("FC %d accepted" % fc)
    assert o.SAFE_FC.isdisjoint(o.WRITE_FC)


def test_modbus_responses():
    assert o.parse_devid(MB_DEVID_PDU) == {"vendor": "Fronius", "product": "Symo", "rev": "1.2"}
    assert o.parse_devid(MB_DEVID_PDU[:12]) == {}            # κομμένο object → ό,τι χωράει
    assert o.parse_read(3, MB_READ_PDU, 3) == [0x022B, 0, 100]
    assert o.parse_read(3, MB_READ_PDU, 4) is None           # το byte count δεν ταιριάζει με αυτό που ζητήσαμε
    assert o.parse_read(1, MB_COILS_PDU, 19) == [1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1]
    assert o.parse_exception(H("83 02")) == 2 and o.parse_exception(MB_READ_PDU) is None


def test_decode_registers_float_and_word_order():
    # 230.5 = 0x43668000 · -2 ως int32 = 0xFFFFFFFE
    rows = o.decode_registers(100, [0x4366, 0x8000, 0xFFFF, 0xFFFE])
    assert rows[0]["f32"] == 230.5 and rows[0]["u32"] == 0x43668000 and rows[0]["addr"] == 100
    assert rows[1]["f32_sw"] is None or isinstance(rows[1]["f32_sw"], float)
    assert rows[2]["s32"] == -2 and rows[2]["u32"] == 0xFFFFFFFE and rows[2]["s16"] == -1 and rows[2]["hex"] == "FFFF"
    assert "f32" not in rows[3]
    sw = o.decode_registers(0, [0x8000, 0x4366])
    assert sw[0]["f32_sw"] == 230.5 and sw[0]["u32_sw"] == 0x43668000
    assert o.decode_registers(0, [0x7FC0, 0])[0]["f32"] is None   # NaN → None (για το JSON)
    json.dumps(rows, allow_nan=False)


def test_mb_sniff_writes_and_reads():
    exp = {5: (0xAC, 1), 6: (1, 1), 15: (0x13, 10), 16: (1, 2), 22: (4, 1), 23: (0x0E, 3)}
    for fr in (W5, W6, W15, W16, W22, W23):
        m = o.mb_sniff(fr)
        assert m and m["write"] and m["unit"] == 1 and (m["addr"], m["qty"]) == exp[m["fc"]], fr.hex()
    assert o.mb_sniff(W6)["value"] == 3 and o.mb_sniff(W22)["and_mask"] == 0xF2
    assert o.mb_sniff(R3) == {"unit": 1, "fc": 3, "write": False, "addr": 0x6B, "qty": 3}
    assert o.mb_sniff(W16[:-1]) is None                          # λείπει ένα byte από το ADU
    assert o.mb_sniff(W16[:20], plen=len(W16)) is not None       # κομμένο πλαίσιο, αλλά το πραγματικό μήκος ταιριάζει
    assert o.mb_sniff(H("000a 0000 000b 01 10 00 01 00 02 05 00 0a 01 02")) is None  # byte count ≠ 2×πλήθος
    assert o.mb_sniff(H("0007 0000 0006 01 05 00 ac 12 34")) is None                 # coil: μόνο FF00/0000
    assert o.mb_sniff(b"GET / HTTP/1.1\r\n\r\n") is None


# ═════════════ BACnet ═════════════
def test_bacnet_whois_and_iam():
    assert o.WHOIS == BAC_WHOIS and len(o.WHOIS) == 12
    assert o.parse_iam(BAC_IAM) == {"instance": 120001, "max_apdu": 1476, "seg": "both", "vendor_id": 7, "vendor": "Siemens",
                                    "snet": None, "sadr": ""}
    r = o.parse_iam(BAC_IAM_ROUTED)
    assert (r["instance"], r["max_apdu"], r["seg"], r["vendor"], r["snet"], r["sadr"]) == (123, 50, "none", "Distech Controls", 5, "0c")
    unk = bytearray(BAC_IAM)
    unk[-1] = 0xFA
    assert o.parse_iam(bytes(unk))["vendor"] == "vendor #250"
    assert o.parse_iam(BAC_WHOIS) is None and o.parse_iam(BAC_WP) is None
    bad = bytearray(BAC_IAM)
    bad[3] = 0x19                                               # το μήκος BVLC δεν ταιριάζει
    assert o.parse_iam(bytes(bad)) is None
    notdev = bytearray(BAC_IAM)
    notdev[13] = 0x00                                           # object type ≠ device
    assert o.parse_iam(bytes(notdev)) is None


def test_bacnet_sniff():
    assert o.bac_sniff(BAC_WP) == {"svc": 15, "obj": "analog-value 3", "prop": "present-value", "arg": ""}
    assert o.bac_sniff(BAC_REINIT)["arg"] == "warmstart" and o.bac_sniff(BAC_REINIT)["svc"] == 20
    assert o.bac_sniff(BAC_DCC) == {"svc": 17, "obj": "", "prop": "", "arg": "disable"}
    assert o.bac_sniff(BAC_RP) is None and o.bac_sniff(BAC_WHOIS) is None and o.bac_sniff(BAC_IAM) is None
    assert o.bac_sniff(BAC_WP[:16], plen=len(BAC_WP))["obj"] == "analog-value 3"   # κομμένο στα 128 bytes του πλαισίου


# ═════════════ KNX ═════════════
def test_knx_search():
    assert o.knx_search_req("192.168.1.10", 35389) == KNX_REQ and len(KNX_REQ) == 14
    assert len(KNX_RESP) == 0x4C
    r = o.parse_knx_search(KNX_RESP)
    assert (r["addr"], r["name"], r["serial"], r["mac"]) == ("1.1.250", "KNX IP Interface 731", "00c501023a7f", "00:24:6d:01:3a:7f")
    assert r["medium"] == "TP1" and r["mcast"] == "224.0.23.12" and r["prog"] is False
    assert [f["name"] for f in r["families"]] == ["Core", "Device Management", "Tunnelling"]
    assert r["tunnelling"] and not r["routing"] and not r["secure"]
    assert (r["ctrl_ip"], r["ctrl_port"]) == ("192.168.1.80", 3671)
    assert o.parse_knx_search(KNX_REQ) is None                  # αίτημα, όχι απάντηση
    assert o.parse_knx_search(KNX_RESP[:-1]) is None            # συνολικό μήκος ≠ πραγματικό
    r2 = o.parse_knx_search(KNX_RESP[:-8] + H("08 02 02 01 05 01 09 01"))   # Core, Routing, Security
    assert r2["routing"] and r2["secure"] and not r2["tunnelling"]


def test_malformed_input_never_raises():
    rnd = random.Random(7)
    samples = [MB_DEVID_REQ, MB_DEVID_PDU, MB_READ_PDU, W5, W15, W16, W22, W23, BAC_IAM, BAC_IAM_ROUTED, BAC_WP, BAC_REINIT,
               BAC_DCC, KNX_RESP, frame("192.168.1.9", "192.168.1.60", 40000, 502, W16),
               frame("192.168.1.9", "192.168.1.70", 40000, 47808, BAC_WP, udp=True, vlan=True)]
    blobs = [b"", b"\x00", b"\xff" * 300]
    for s in samples:
        blobs += [s[:i] for i in range(len(s))]
        for _ in range(60):
            b = bytearray(s)
            for _ in range(rnd.randint(1, 4)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            blobs.append(bytes(b))
    blobs += [bytes(rnd.randrange(256) for _ in range(rnd.randint(1, 140))) for _ in range(300)]
    w = o.OtWatch(State(), net=FakeNet(), clock=lambda: 1.0)
    for b in blobs:
        o.parse_mbap(b), o.parse_devid(b), o.parse_exception(b), o.parse_read(3, b, 3), o.parse_read(1, b, 9)
        o.mb_sniff(b), o.mb_sniff(b, 500), o.parse_iam(b), o.parse_knx_search(b)
        o.l4_payload(b, 6, 40000, 502), o.l4_payload(b, 17, 40000, 47808)
        try:
            o.bac_sniff(b), o.bac_sniff(b, 600)
        except Exception as e:  # noqa: BLE001 — ο observe() το πιάνει, αλλά ας μην πετάει καθόλου
            raise AssertionError("bac_sniff raised %r on %s" % (e, b.hex()))
        for dp, proto in ((502, "TCP"), (47808, "UDP")):
            w.observe({"src": "192.168.1.9", "dst": "192.168.1.60", "proto": proto, "sp": 40000, "dp": dp, "_raw": b}, 5.0)
    for junk in ({}, {"dp": 502}, {"dp": 502, "proto": "TCP", "_raw": None}, {"dp": 47808, "proto": "UDP", "_raw": 5}):
        w.observe(junk, 1.0)


# ═════════════ payload μέσα στο πλαίσιο ═════════════
def test_l4_payload_variants():
    f = frame("192.168.1.9", "192.168.1.60", 40000, 502, W6)
    assert o.l4_payload(f, 6, 40000, 502) == (W6, len(W6))
    assert o.l4_payload(frame("192.168.1.9", "192.168.1.60", 40000, 502, W6, vlan=True), 6, 40000, 502) == (W6, len(W6))
    assert o.l4_payload(frame("192.168.1.9", "192.168.1.60", 40000, 502, W6, pad=6), 6, 40000, 502) == (W6, len(W6))  # padding
    assert o.l4_payload(f[14:], 6, 40000, 502) == (W6, len(W6))          # σκέτο IP (tun)
    assert o.l4_payload(f, 6, 40000, 503) is None                         # οι θύρες δεν ταιριάζουν → δεν μαντεύουμε
    big = H("000a 0000 00cf 01 10 00 01 00 64 c8") + b"\x00" * 200          # 100 registers: κόβεται στα 128
    pl, n = o.l4_payload(frame("192.168.1.9", "192.168.1.60", 40000, 502, big), 6, 40000, 502)
    assert n == len(big) and len(pl) == 128 - 54 and o.mb_sniff(pl, n)["qty"] == 100
    u = frame("192.168.1.9", "192.168.1.255", 40000, 47808, BAC_WP, udp=True)
    assert o.l4_payload(u, 17, 40000, 47808) == (BAC_WP, len(BAC_WP))


# ═════════════ σάρωση ═════════════
def mk(st=None, tmp=None, t=None, **net):
    st = st or State()
    n = FakeNet(**net)
    return o.OtWatch(st, str(tmp) if tmp else None, net=n, clock=(lambda: t[0]) if t else (lambda: 1000.0)), st, n


def test_scan_finds_all_three_and_only_reads():
    w, st, net = mk(modbus={"192.168.1.60": fronius, "192.168.1.61": sunspec, "192.168.1.5": lambda u, p: None},
                    bacnet=[("192.168.1.70", BAC_IAM), ("192.168.1.70", BAC_IAM), ("8.8.8.8", BAC_IAM),
                            ("192.168.1.71", BAC_WHOIS), ("192.168.1.72", b"junk")],
                    knx=[("192.168.1.80", KNX_RESP), ("1.2.3.4", KNX_RESP), ("192.168.1.81", KNX_REQ)])
    v = w.scan()
    d = {x["key"]: x for x in v["devices"]}
    assert set(d) == {"modbus:192.168.1.60", "modbus:192.168.1.61", "modbus:192.168.1.5", "bacnet:192.168.1.70:120001",
                      "knx:192.168.1.80"}
    assert v["counts"] == {"modbus": 3, "bacnet": 1, "knx": 1, "high": 3, "med": 2}
    a = d["modbus:192.168.1.60"]
    assert (a["vendor"], a["product"], a["unit"], a["level"], a["title"]) == ("Fronius", "Symo", 255, "high", "Fronius Symo")
    assert a["dev"]["name"] == "inv.local" and a["why"] and a["why_en"] and a["since"] == 1000.0
    b = d["modbus:192.168.1.61"]
    assert (b["vendor"], b["model"], b["rev"], b["serial"], b["unit"], b["sunspec"]) == ("SMA", "STP 10.0", "3.10", "SN123", 1, True)
    c = d["modbus:192.168.1.5"]
    assert c["confirmed"] is False and c["level"] == "med"
    assert d["knx:192.168.1.80"]["level"] == "high" and d["bacnet:192.168.1.70:120001"]["level"] == "med"
    # μόνο ιδιωτικές, όχι ο εαυτός μας, όχι δημόσιες
    assert sorted(net.opened) == ["192.168.1.5", "192.168.1.60", "192.168.1.61"]
    fcs = {o.parse_mbap(fr)[2][0] for _ip, fr in net.sent}
    assert fcs <= {0x2B, 3} and net.closed == 3
    assert v["scanned"] == 1000.0 and v["busy"] is False and v["error"] is None and v["demo"] is False
    json.dumps(v, allow_nan=False)


def test_scan_survives_broken_net():
    class Boom(FakeNet):
        def bacnet_whois(self, timeout=2.0):
            raise OSError("no route")
    w = o.OtWatch(State(), net=Boom(knx=[("192.168.1.80", KNX_RESP)]), clock=lambda: 5.0)
    v = w.scan()
    assert [x["proto"] for x in v["devices"]] == ["knx"] and "BACnet" in v["error"] and v["scanned"] == 5.0


def test_new_device_alert_only_after_first_scan(tmp_path):
    t = [1000.0]
    w, st, net = mk(tmp=tmp_path, t=t, modbus={"192.168.1.60": fronius}, knx=[("192.168.1.80", KNX_RESP)])
    w.scan()
    assert st.alerts == []                                   # πρώτη σάρωση: απογραφή, όχι συναγερμοί
    t[0] = 2000.0
    w.scan()
    assert st.alerts == []                                   # τίποτα νέο
    net.bac.append(("192.168.1.70", BAC_IAM))
    t[0] = 3000.0
    v = w.scan()
    assert len(st.alerts) == 1
    typ, sev, actor, target, detail, kw = st.alerts[0]
    assert (typ, sev, actor, target) == ("Νέα συσκευή αυτοματισμού (OT)", "med", "192.168.1.70", "BACnet/IP")
    assert "Siemens" in detail and "120001" in detail
    assert {x["key"]: x["since"] for x in v["devices"]}["bacnet:192.168.1.70:120001"] == 3000.0
    # επανεκκίνηση: τα γνωστά μένουν γνωστά, καμία νέα ειδοποίηση
    st2 = State()
    w2 = o.OtWatch(st2, str(tmp_path), net=net, clock=lambda: 4000.0)
    assert len(w2.view()["devices"]) == 3 and w2.view()["scanned"] == 3000.0
    w2.scan()
    assert st2.alerts == []
    assert json.load(open(os.path.join(str(tmp_path), "ot.json"), encoding="utf-8"))["known"]["knx:192.168.1.80"] == 1000.0


def test_device_that_stops_answering_is_kept_as_stale():
    t = [10.0]
    w, st, net = mk(t=t, modbus={"192.168.1.60": fronius})
    w.scan()
    net.mb.clear()
    t[0] = 20.0
    v = w.scan()
    assert v["devices"][0]["stale"] is True and v["devices"][0]["vendor"] == "Fronius"


# ═════════════ ποιος γράφει; ═════════════
def test_write_alert_once_per_new_writer_never_on_reads(tmp_path):
    w, st, net = mk(tmp=tmp_path)
    for fr in (R3, MB_DEVID_REQ, MB_READ_REQ):
        w.observe(pkt("192.168.1.9", "192.168.1.60", fr), 1000.0)
    assert st.alerts == [] and w.view()["writes"] == []
    for i in range(50):                                      # SCADA που γράφει συνέχεια → ΜΙΑ ειδοποίηση
        w.observe(pkt("192.168.1.9", "192.168.1.60", W16), 1000.0 + i)
    assert len(st.alerts) == 1
    typ, sev, actor, target, detail, kw = st.alerts[0]
    assert (typ, sev, actor, target) == ("Εγγραφή σε PLC (Modbus)", "high", "192.168.1.9", "192.168.1.60")
    assert "Write Multiple Registers" in detail and "FC 16" in detail and "unit 1" in detail
    assert "διεύθυνση 1" in detail and "πλήθος 2" in detail and "inv.local" in detail
    ws = w.view()["writes"]
    assert len(ws) == 1 and ws[0]["n"] == 50 and ws[0]["t"] == 1049.0 and ws[0]["first"] == 1000.0 and ws[0]["new"] is True
    w.observe(pkt("192.168.1.9", "192.168.1.60", W6), 1100.0)   # ίδιο ζεύγος, άλλη εντολή → όχι νέα ειδοποίηση
    assert len(st.alerts) == 1 and len(w.view()["writes"]) == 2
    w.observe(pkt("192.168.1.9", "192.168.1.61", W5, vlan=True), 1101.0)   # άλλος στόχος (και με VLAN tag)
    w.observe(pkt("192.168.1.77", "192.168.1.60", W22, pad=4), 1102.0)     # άλλη πηγή
    assert [(a[2], a[3]) for a in st.alerts[1:]] == [("192.168.1.9", "192.168.1.61"), ("192.168.1.77", "192.168.1.60")]
    # απαντήσεις (από τη θύρα 502) και άσχετες θύρες δεν μετράνε
    resp = {"src": "192.168.1.60", "dst": "192.168.1.9", "proto": "TCP", "sp": 502, "dp": 40000,
            "_raw": frame("192.168.1.60", "192.168.1.9", 502, 40000, W16)}
    w.observe(resp, 1103.0)
    other = pkt("192.168.1.9", "192.168.1.60", W16, dp=8502)
    w.observe(other, 1104.0)
    udp = dict(pkt("192.168.1.9", "192.168.1.60", W16), proto="UDP")
    w.observe(udp, 1105.0)
    assert len(st.alerts) == 3
    # οι γνωστοί «συγγραφείς» αποθηκεύονται: μετά από επανεκκίνηση δεν ξαναειδοποιεί
    w.flush()
    st2 = State()
    w2 = o.OtWatch(st2, str(tmp_path), net=net, clock=lambda: 9000.0)
    w2.observe(pkt("192.168.1.9", "192.168.1.60", W16), 9000.0)
    assert st2.alerts == [] and w2.view()["writers"] == 3
    w2.forget("192.168.1.9", "192.168.1.60")
    w2.observe(pkt("192.168.1.9", "192.168.1.60", W16), 9001.0)
    assert len(st2.alerts) == 1


def test_passive_modbus_device_and_raw_from_packets_module():
    import packets
    w, st, net = mk()
    p = pkt("192.168.1.9", "192.168.1.66", R3)               # ανάγνωση: καμία ειδοποίηση, αλλά μάθαμε ότι υπάρχει PLC
    raw = p.pop("_raw")                                      # όπως στο NetState.process(): το _raw έχει φύγει…
    p["_id"] = 424242
    packets.remember(p, raw)                                 # …αλλά το packets.py το θυμάται με το ίδιο id
    w.observe(p, 1000.0)
    v = w.view()
    assert [(x["key"], x.get("passive"), x["level"]) for x in v["devices"]] == [("modbus:192.168.1.66", True, "high")]
    assert st.alerts == []
    packets.clear()
    w.observe(dict(pkt("192.168.1.9", "8.8.4.4", R3)), 1001.0)   # δημόσιος «PLC» δεν μπαίνει στη λίστα
    assert len(w.view()["devices"]) == 1


def test_bacnet_write_detection():
    w, st, net = mk()
    w.observe(pkt("192.168.1.9", "192.168.1.70", BAC_RP, dp=47808, udp=True), 1.0)
    w.observe(pkt("192.168.1.9", "192.168.1.255", BAC_WHOIS, dp=47808, udp=True), 1.0)
    assert st.alerts == []
    for i in range(5):
        w.observe(pkt("192.168.1.9", "192.168.1.70", BAC_WP, dp=47808, udp=True), 2.0 + i)
    assert len(st.alerts) == 1
    typ, sev, actor, target, detail, kw = st.alerts[0]
    assert (typ, sev, actor, target) == ("Εγγραφή σε ελεγκτή κτιρίου (BACnet)", "high", "192.168.1.9", "192.168.1.70")
    assert "WriteProperty" in detail and "analog-value 3" in detail and "present-value" in detail
    w.observe(pkt("192.168.1.9", "192.168.1.70", BAC_REINIT, dp=47808, udp=True), 10.0)   # γνωστή πηγή, αλλά επανεκκίνηση
    assert len(st.alerts) == 2 and st.alerts[1][1] == "med" and "warmstart" in st.alerts[1][4]
    w.observe(pkt("192.168.1.50", "192.168.1.70", BAC_DCC, dp=47808, udp=True), 11.0)     # νέα πηγή
    assert st.alerts[2][1] == "high" and "disable" in st.alerts[2][4]


# ═════════════ διάβασε registers ═════════════
def test_read_refuses_public_and_validates():
    w, st, net = mk(modbus={"192.168.1.60": lambda u, p: None})
    for ip in ("8.8.8.8", "127.0.0.1", "224.0.23.12", "0.0.0.0", "example.com", "", None, 5, "192.168.1.60; rm"):
        code, r = w.api("POST", "read", {}, {"ip": ip, "unit": 1, "kind": "holding", "addr": 0, "count": 2})
        assert code == 400 and r["ok"] is False and r["error"] and r["error_en"], ip
    for bad in ({"count": 126}, {"count": 0}, {"unit": 256}, {"unit": -1}, {"addr": 65536}, {"addr": 65535, "count": 2},
                {"kind": "write"}, {"kind": "16"}, {"count": True}, {"count": 1.5}, {"addr": "x"}, {"unit": None}):
        body = dict({"ip": "192.168.1.60", "unit": 1, "kind": "holding", "addr": 0, "count": 2}, **bad)
        assert w.api("POST", "read", {}, body)[0] == 400, bad
    assert net.opened == [] and net.sent == []                # τίποτα δεν βγήκε στο δίκτυο


def test_read_decodes_and_reports_errors():
    def meter(unit, pdu):
        if unit != 3:
            return None
        if pdu == H("04 00 00 00 02"):
            return H("04 04 43 66 80 00")                     # 230.5 V ως float (ABCD)
        if pdu == H("01 00 13 00 13"):
            return MB_COILS_PDU
        if pdu == H("03 00 05 00 01"):
            return H("03 04 00 01 00 02")                     # λάθος μήκος
        return bytes((pdu[0] | 0x80, 2))
    w, st, net = mk(modbus={"192.168.1.61": meter})
    code, r = w.api("POST", "read", {}, {"ip": " 192.168.1.61 ", "unit": "3", "kind": "input", "addr": 0, "count": 2})
    assert code == 200 and r["ok"] and r["fc"] == 4 and r["rows"][0]["f32"] == 230.5 and r["rows"][0]["hex"] == "4366"
    assert net.sent[-1] == ("192.168.1.61", H("0001 0000 0006 03 04 00 00 00 02"))
    r = w.read("192.168.1.61", 3, "coil", 0x13, 19)
    assert r["ok"] and [b["bit"] for b in r["bits"]][:8] == [1, 0, 1, 1, 0, 0, 1, 1] and r["bits"][0]["addr"] == 0x13
    r = w.read("192.168.1.61", 3, "holding", 999, 4)
    assert r["ok"] is False and r["exception"] == 2 and "illegal data address" in r["error"]
    assert w.read("192.168.1.61", 3, "holding", 5, 1)["ok"] is False      # λάθος μήκος απάντησης
    assert w.read("192.168.1.61", 1, "holding", 0, 1)["ok"] is False      # δεν απάντησε σε αυτό το unit
    assert w.read("192.168.1.99", 1, "holding", 0, 1)["ok"] is False      # κλειστή θύρα
    assert {o.parse_mbap(fr)[2][0] for _ip, fr in net.sent} <= {1, 3, 4}


# ═════════════ demo / api ═════════════
def test_demo_view_and_api():
    w = o.OtWatch(None, demo=True, clock=lambda: 50000000.0)
    code, v = w.api("GET", "", {}, {})
    assert code == 200 and v["demo"] is True and v["scanned"] and v["busy"] is False
    assert set(v) >= {"demo", "scanned", "busy", "devices", "counts", "writes", "error"}
    assert v["counts"] == {"modbus": 3, "bacnet": 2, "knx": 1, "high": 4, "med": 2}
    assert {d["proto"] for d in v["devices"]} == {"modbus", "bacnet", "knx"}
    assert all(d["why"] and d["why_en"] and d["title"] and d["level"] in ("high", "med", "low") for d in v["devices"])
    assert len(v["writes"]) == 2 and all(x["what"] and x["what_en"] for x in v["writes"])
    code, v2 = w.api("POST", "scan", {}, {})
    assert code == 200 and v2["demo"] and len(v2["devices"]) == 6
    code, r = w.api("POST", "read", {}, {"ip": "192.168.1.61", "unit": 1, "kind": "input", "addr": 0, "count": 8})
    assert code == 200 and r["ok"] and r["rows"][0]["f32"] == 230.4 and len(r["rows"]) == 8
    assert w.api("POST", "read", {}, {"ip": "8.8.8.8"})[0] == 400
    assert w.api("POST", "read", {}, {"ip": "192.168.1.61", "kind": "coil", "count": 5})[1]["bits"][0] == {"addr": 0, "bit": 1}
    assert w.api("GET", "nope", {}, {}) == (404, {"error": "not found"})
    assert w.api("POST", "nope", {}, {}) == (404, {"error": "not found"})
    assert w.api("POST", "forget", {}, {"src": 1})[0] == 400
    json.dumps(v, allow_nan=False)
    w.observe(pkt("192.168.1.9", "192.168.1.60", W16), 1.0)   # demo: δεν σκάει, δεν χρειάζεται state


def test_api_scan_runs_in_background():
    w, st, net = mk(modbus={"192.168.1.60": fronius})
    code, v = w.api("POST", "scan", {}, {})
    assert code == 200 and v["busy"] is True
    import time
    for _ in range(200):
        if w.scanned and not w.busy:
            break
        time.sleep(0.01)
    assert [d["key"] for d in w.view()["devices"]] == ["modbus:192.168.1.60"]


def test_risk_levels():
    assert o.risk({"proto": "modbus", "confirmed": True})[0] == "high"
    assert o.risk({"proto": "bacnet"})[0] == "med"
    assert o.risk({"proto": "knx", "routing": True})[0] == "high"
    assert o.risk({"proto": "knx", "tunnelling": True, "secure": True})[0] == "med"
    assert o.risk({"proto": "knx"})[0] == "low"
    assert not o.is_private("8.8.8.8") and not o.is_private("fe80::1") and o.is_private("10.1.2.3") and o.is_private("169.254.3.4")
