import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)


def _mod():
    spec = importlib.util.spec_from_file_location("zigbee_sniff", os.path.join(ROOT, "tools", "zigbee_sniff.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


z = _mod()

# χειροποίητα πλαίσια (χωρίς FCS)
BEACON = bytes.fromhex("0080" "2a" "621a" "0000") + bytes.fromhex("ff0f0000")           # beacon από τον coordinator 0x0000 του PAN 0x1a62
DATA_SHORT = bytes.fromhex("6188" "5c" "621a" "0000" "2c3f") + b"\x08\x00secret"       # data, PAN compression, 0x3f2c → 0x0000
DATA_EXT = bytes.fromhex("61cc" "07" "c5d0" "f3a7c124004b1200" "8877665544332211") + b"\xaa" * 5  # και οι δύο διευθύνσεις 64-bit
DATA_NOCOMP = bytes.fromhex("2188" "01" "621a" "ffff" "cefa" "1e a9".replace(" ", ""))  # χωρίς compression: ξεχωριστό PAN πηγής
ACK = bytes.fromhex("0200" "5c")
BEACON_REQ = bytes.fromhex("0308" "9b" "ffff" "ffff" "07")                             # MAC command 7 = beacon request (broadcast)
ASSOC_REQ = bytes.fromhex("23c8" "11" "621a" "0000" "ffff" "8877665544332211" "01" "8e")  # src 64-bit με δικό του PAN (ffff)


def line(frame, rssi=-60, lqi=150, t=123456):
    return "received: %s1234 power: %d lqi: %d time: %d" % (frame.hex(), rssi, lqi, t)


def test_parse_beacon():
    h = z.parse_154(BEACON)
    assert h == {"type": "beacon", "ver": 0, "sec": False, "seq": 0x2A, "dst_pan": "", "dst": "", "src_pan": "1a62", "src": "0000", "pan": "1a62", "cmd": None}


def test_parse_data_short_and_extended():
    h = z.parse_154(DATA_SHORT)
    assert (h["type"], h["dst_pan"], h["dst"], h["src_pan"], h["src"], h["pan"], h["seq"]) == ("data", "1a62", "0000", "", "3f2c", "1a62", 0x5C)
    assert "secret" not in json.dumps(h)  # ποτέ περιεχόμενο
    h = z.parse_154(DATA_EXT)
    assert h["type"] == "data" and h["dst"] == "00124b0024c1a7f3" and h["src"] == "1122334455667788" and h["pan"] == "d0c5" and h["src_pan"] == ""
    h = z.parse_154(DATA_NOCOMP)
    assert h["dst_pan"] == "1a62" and h["dst"] == "ffff" and h["src_pan"] == "face" and h["src"] == "a91e" and h["pan"] == "face"


def test_parse_ack_and_commands():
    assert z.parse_154(ACK) == {"type": "ack", "ver": 0, "sec": False, "seq": 0x5C, "dst_pan": "", "dst": "", "src_pan": "", "src": "", "pan": "", "cmd": None}
    h = z.parse_154(BEACON_REQ)
    assert h["type"] == "cmd" and h["cmd"] == 7 and h["dst_pan"] == "ffff" and h["dst"] == "ffff" and h["src"] == "" and h["pan"] == "ffff"
    h = z.parse_154(ASSOC_REQ)
    assert h["type"] == "cmd" and h["cmd"] == 1 and h["src"] == "1122334455667788" and h["src_pan"] == "ffff" and h["dst_pan"] == "1a62"
    sec = bytearray(BEACON_REQ)
    sec[0] |= 0x08
    assert z.parse_154(bytes(sec))["sec"] is True and z.parse_154(bytes(sec))["cmd"] is None  # κρυπτογραφημένο: δεν κοιτάμε μέσα


def test_parse_2015_frames_thread():
    # έκδοση 2 (802.15.4-2015): dst short + src short, χωρίς compression → δύο PAN· με compression → μόνο του προορισμού
    f = bytes.fromhex("01a8" "10" "cefa" "0100" "cefa" "0200")
    h = z.parse_154(f)
    assert h["ver"] == 2 and h["dst_pan"] == "face" and h["dst"] == "0001" and h["src_pan"] == "face" and h["src"] == "0002"
    f = bytes.fromhex("41a8" "10" "cefa" "0100" "0200")
    assert z.parse_154(f)["src"] == "0002" and z.parse_154(f)["src_pan"] == "" and z.parse_154(f)["pan"] == "face"
    # και οι δύο 64-bit με compression → κανένα PAN· sequence number suppression
    f = bytes.fromhex("41ed" "f3a7c124004b1200" "8877665544332211")
    h = z.parse_154(f)
    assert h["seq"] is None and h["pan"] == "" and h["dst"] == "00124b0024c1a7f3" and h["src"] == "1122334455667788"
    # enh-ack χωρίς διευθύνσεις, με compression → μόνο PAN προορισμού
    assert z.parse_154(bytes.fromhex("4220" "07" "cefa"))["pan"] == "face"


def test_parse_truncated_and_garbage():
    for bad in (b"", b"\x61", b"\x61\x88", DATA_SHORT[:5], DATA_EXT[:12], BEACON[:4], b"\x00" * 200, None,
                bytes.fromhex("0484" "00" "621a0000"),   # dst addressing mode 1 (δεσμευμένο)
                bytes.fromhex("6130" "00" "621a0000"),   # έκδοση 3 (δεσμευμένη)
                bytes.fromhex("0700" "00"), bytes.fromhex("0600" "00")):  # τύποι που δεν μας αφορούν
        assert z.parse_154(bad) is None, bad
    import random
    rnd = random.Random(7)
    for _ in range(3000):  # ό,τι κι αν έρθει: dict ή None, ποτέ εξαίρεση
        h = z.parse_154(bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 40))))
        assert h is None or (h["type"] in ("beacon", "data", "ack", "cmd") and len(h["src"]) in (0, 4, 16) and len(h["pan"]) in (0, 4))


def test_parse_line_matches_nordic_format():
    f, rssi, lqi = z.parse_line(line(DATA_SHORT, -71, 148))
    assert f == DATA_SHORT and rssi == -71 and lqi == 148  # τα 2 τελευταία byte (FCS) κόβονται
    assert z.parse_line(line(ACK).encode())[0] == ACK
    assert z.parse_line("uart:~$ " + line(BEACON) + "\r\n")[0] == BEACON
    for bad in ("", "channel 11", "received: zz power: -1 lqi: 1 time: 1", "received: abc power: -60 lqi: 100 time: 1",
                "received: aabb power: -999 lqi: 1 time: 1", "received: aabb power: -60 lqi: 999 time: 1", "received: " + "ab" * 400 + " power: -60 lqi: 1 time: 1",
                b"\xff\xfe\x00garbage", "received: aabb power: lqi: time:"):
        assert z.parse_line(bad) is None, bad


def test_aggregate_per_channel_pan_src_and_cap():
    a = z.Agg()
    for i in range(5):
        a.add(11, DATA_SHORT, -70 - i, 140 + i)
    a.add(11, BEACON, -48, 212)
    a.add(11, bytes.fromhex("6188" "5d" "621a" "ffff" "0000"), -50, 200)  # data από τον ίδιο coordinator → ίδια γραμμή με το beacon
    a.add(20, DATA_EXT, -67, 160)
    a.add(20, ACK, -67, 160)
    a.add(15, BEACON_REQ, -80, 90)
    a.add(12, b"\xff\xff", -60, 100)  # σκουπίδι
    a.add(5, DATA_SHORT, -60, 100)    # κανάλι εκτός 11–26
    b = a.body(37)
    assert b["status"]["metrics"]["ch11"] == 7 and b["status"]["metrics"]["ch20"] == 2 and b["status"]["metrics"]["ch15"] == 1
    assert b["status"]["metrics"]["ch12"] == 0 and b["status"]["metrics"]["frames"] == 10 and b["status"]["metrics"]["bad"] == 1
    assert len(b["status"]["metrics"]) == 18 <= 20 and b["status"]["interval"] == 37 and b["events"] == []
    rows = {(r["ch"], r["pan"], r["src"]): r for r in b["items"]}
    assert rows[(11, "1a62", "3f2c")] == {"ch": 11, "pan": "1a62", "src": "3f2c", "rssi": -72, "lqi": 142, "n": 5, "t": "data"}
    assert rows[(11, "1a62", "0000")]["t"] == "beacon" and rows[(11, "1a62", "0000")]["n"] == 2 and rows[(11, "1a62", "0000")]["rssi"] == -49
    assert rows[(20, "d0c5", "1122334455667788")]["t"] == "data" and rows[(20, "", "")]["t"] == "ack" and rows[(15, "ffff", "")]["t"] == "cmd"
    assert b["items"][0]["n"] == 5  # ταξινόμηση κατά πλήθος πλαισίων
    assert all(set(r) == {"ch", "pan", "src", "rssi", "lqi", "n", "t"} for r in b["items"])
    assert "secret" not in json.dumps(b)
    big = z.Agg()
    for i in range(300):
        for _ in range(1 + (i % 3)):
            big.add(11 + i % 16, bytes.fromhex("6188" "00" "621a" "0000") + i.to_bytes(2, "little"), -60, 100)
    body = big.body()
    assert len(body["items"]) == z.MAX_ROWS == 80 and min(r["n"] for r in body["items"]) >= 2 and len(json.dumps(body)) < 16 * 1024


def test_replay_file_and_server_accepts_the_report(tmp_path, capsys):
    f = tmp_path / "cap.txt"
    f.write_text("\n".join(["shell echo off", "channel 11", line(BEACON, -48, 212), line(DATA_SHORT, -71, 148), line(DATA_SHORT, -73, 144), "random noise",
                            "received: nothex power: 1 lqi: 1 time: 1", "channel 20", line(DATA_EXT, -67, 160), "# channel 15", line(BEACON_REQ, -80, 90), ""]),
                 encoding="utf-8")
    agg = z.replay(str(f))
    body = agg.body()
    m = body["status"]["metrics"]
    assert (m["ch11"], m["ch20"], m["ch15"], m["frames"]) == (3, 1, 1, 5)
    assert {(r["ch"], r["pan"], r["src"], r["n"], r["t"]) for r in body["items"]} == {
        (11, "1a62", "0000", 1, "beacon"), (11, "1a62", "3f2c", 2, "data"), (20, "d0c5", "1122334455667788", 1, "data"), (15, "ffff", "", 1, "cmd")}
    # CLI: once --replay --dry τυπώνει την αναφορά χωρίς δίκτυο/σύζευξη
    z.main(["once", "--replay", str(f), "--dry"])
    out = json.loads(capsys.readouterr().out)
    assert out["items"] == body["items"] and out["status"]["hw"].startswith("replay")
    # … και ο server (probes.py) τη δέχεται όπως είναι, στη μορφή του συμβολαίου
    import probes

    class St:
        me = {"192.168.1.23"}
        sensor = None

    p = probes.Probes(St(), str(tmp_path), port=0, clock=lambda: 1000.0, cert=("x", "y", "AA:BB"))
    p.enabled = True
    tok = probes.read_code(p.pair("sniffer", "zigbee")["code"])["t"]
    assert p.report(tok, "192.168.1.63", json.dumps(body).encode())[0] == 200
    got = p.items("zigbee")[0]
    assert got["items"] == body["items"] and got["metrics"]["ch11"] == 3
    import radio
    St.probes = p
    zb = radio.Radio(St(), clock=lambda: 1000.0).view()["zb"]
    assert [x["pan"] for x in zb["pans"]] == ["1a62", "d0c5"] and {c["ch"]: c["frames"] for c in zb["channels"]}[11] == 3


def test_sniffer_serial_protocol_with_fake_port():
    class Port:
        def __init__(self):
            self.wrote, self.q = [], []

        def write(self, d):
            self.wrote.append(d)
            if d.startswith(b"channel 11"):
                self.q += [b"uart:~$ " + line(BEACON).encode()[:20], line(BEACON).encode()[20:] + b"\r\n" + line(DATA_SHORT).encode() + b"\r\nrecei"]
            if d.startswith(b"channel 12"):
                self.q += [b"ved: 00 power: 1 lqi: 1 time: 1\r\n", line(DATA_EXT).encode() + b"\r\n", b"x" * 9000]

        def read(self):
            t[0] += 0.05
            return self.q.pop(0) if self.q else b""

        def close(self):
            pass
    t = [0.0]
    port = Port()
    sn = z.Sniffer(port, clock=lambda: t[0])
    sn.start()
    assert port.wrote[:2] == [b"sleep\r\n", b"shell echo off\r\n"]
    agg = z.Agg()
    sn.listen(11, 1.0, agg)
    sn.listen(12, 1.0, agg)
    assert port.wrote[2:8] == [b"sleep\r\n", b"channel 11\r\n", b"receive\r\n", b"sleep\r\n", b"channel 12\r\n", b"receive\r\n"]
    assert agg.ch[11] == 2 and agg.ch[12] == 1 and agg.frames == 3 and len(sn.buf) <= 4096
    sn.stop()
    assert port.wrote[-2:] == [b"\r\n", b"sleep\r\n"]


def test_cli_help_systemd_and_errors(capsys, monkeypatch, tmp_path):
    z.main(["--help"])
    assert "zigbee_sniff.py pair" in capsys.readouterr().out
    z.main(["--systemd"])
    out = capsys.readouterr().out
    assert "ExecStart=/usr/bin/python3" in out and "zigbee_sniff.py run" in out and "netwatch-zigbee" in out
    with pytest.raises(SystemExit):
        z.main(["bogus"])
    with pytest.raises(SystemExit):
        z.main(["once", "--dwell", "abc", "--dry"])
    with pytest.raises(SystemExit):
        z.main(["once", "--replay", str(tmp_path / "missing.txt"), "--dry"])
    with pytest.raises(SystemExit) as e:
        z.read_code("hello")
    assert "NW1." in str(e.value)
    monkeypatch.setattr(z, "CONF", str(tmp_path / "none.json"))
    with pytest.raises(SystemExit) as e:  # χωρίς σύζευξη και χωρίς --dry
        z.main(["once", "--replay", str(tmp_path / "x.txt")])
    assert "pair" in str(e.value)


def test_pyserial_missing_message_on_windows(monkeypatch):
    monkeypatch.setitem(sys.modules, "serial", None)  # import serial → ImportError
    monkeypatch.setattr(z.os, "name", "nt")
    with pytest.raises(SystemExit) as e:
        z.open_port("COM5")
    assert "pip install pyserial" in str(e.value)
    with pytest.raises(SystemExit) as e:
        z.open_port(None)
    assert "nRF52840" in str(e.value)


def test_standalone_no_repo_imports():
    src = open(os.path.join(ROOT, "tools", "zigbee_sniff.py"), encoding="utf-8").read()
    assert "import probes" not in src and "import netwatch" not in src and "sys.path" not in src
    assert z.SNIFFER_PID == 0x154B and z.NORDIC_VID == 0x1915
