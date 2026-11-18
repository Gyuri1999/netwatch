import bisect
import json
import random
import socket
import threading

import pytest

import snmp
from snmp import (COUNTER32, COUNTER64, GAUGE32, INTEGER, IPADDRESS, NULL, OCTET_STRING, OID, SEQUENCE, TIMETICKS,
                  NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW)


class St:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, detail, kw))


# ───────── BER ─────────

@pytest.mark.parametrize("tag,val", [
    (INTEGER, 0), (INTEGER, 127), (INTEGER, 128), (INTEGER, -1), (INTEGER, -128), (INTEGER, -129),
    (INTEGER, 2 ** 31 - 1), (INTEGER, -2 ** 31),
    (OCTET_STRING, b""), (OCTET_STRING, b"\x00\xffhello"), (OCTET_STRING, "Ελληνικά".encode() * 40),
    (NULL, None), (IPADDRESS, "192.168.1.1"),
    (COUNTER32, 0), (COUNTER32, 2 ** 32 - 1), (GAUGE32, 2 ** 31), (TIMETICKS, 123456789),
    (COUNTER64, 0), (COUNTER64, 2 ** 63), (COUNTER64, 2 ** 64 - 1),
    (OID, (1, 3, 6, 1, 2, 1, 1, 1, 0)), (OID, (1, 3, 6, 1, 4, 1, 4294967295, 128, 16383, 16384, 2 ** 40)),
    (OID, (2, 999, 3)), (OID, (0, 39)), (OID, (1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9)),
    (NO_SUCH_OBJECT, None), (NO_SUCH_INSTANCE, None), (END_OF_MIB_VIEW, None),
    (SEQUENCE, [(INTEGER, 1), (OCTET_STRING, b"x"), (SEQUENCE, [(NULL, None), (COUNTER64, 5)])]),
])
def test_ber_roundtrip(tag, val):
    b = snmp.encode(tag, val)
    t, v, end = snmp.decode(b)
    assert (t, v, end) == (tag, val, len(b))


def test_ber_known_encodings():
    assert snmp.encode(INTEGER, 128) == b"\x02\x02\x00\x80"
    assert snmp.encode(INTEGER, -128) == b"\x02\x01\x80"
    assert snmp.encode(OID, "1.3.6.1.2.1") == b"\x06\x05\x2b\x06\x01\x02\x01"
    assert snmp.encode(COUNTER32, 2 ** 32 - 1) == b"\x41\x05\x00\xff\xff\xff\xff"
    long = snmp.encode(OCTET_STRING, b"a" * 300)
    assert long[:4] == b"\x04\x82\x01\x2c"
    # agent που στέλνει μετρητή «με πρόσημο»
    assert snmp.decode(b"\x41\x04\xff\xff\xff\xfe")[1] == 2 ** 32 - 2


def test_message_roundtrip():
    m = snmp.encode_message("public", snmp.GETBULK, 4242, [("1.3.6.1.2.1.2.2.1.2", (NULL, None))], 0, 25)
    d = snmp.decode_message(m)
    assert d["community"] == b"public" and d["pdu"] == snmp.GETBULK and d["reqid"] == 4242 and d["b"] == 25
    assert d["varbinds"] == [((1, 3, 6, 1, 2, 1, 2, 2, 1, 2), NULL, None)]


def test_malformed_never_crashes():
    good = snmp.encode_message("public", snmp.RESPONSE, 7, [("1.3.6.1.2.1.1.1.0", (OCTET_STRING, b"x" * 50)),
                                                            ("1.3.6.1.2.1.1.3.0", (TIMETICKS, 99))])
    bad = [b"", b"\x30", b"\x30\x80\x00\x00", b"\x30\x85\x01\x02\x03\x04\x05", b"\x06\x00", b"\x06\x02\x2b\x86",
           b"\x30\x03\x02\x01", snmp.encode(SEQUENCE, [(INTEGER, 1)]), b"\x30" * 40 + b"\x00",
           (b"\x30\x02" * 20) + b"\x02\x00", good[:-1], good[:20], good + b"junk"]
    rnd = random.Random(1)
    bad += [bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 80))) for _ in range(500)]
    for i in range(len(good)):  # κάθε byte αλλοιωμένο
        bad.append(good[:i] + bytes([good[i] ^ 0xFF]) + good[i + 1:])
    for b in bad:
        try:
            snmp.decode_message(b)
        except snmp.BerError:
            pass


# ───────── ψεύτικος agent ─────────

class FakeAgent:
    def __init__(self, mib, community=b"public", bulk=True, junk_first=False):
        self.mib = {snmp.parse_oid(k): v for k, v in mib.items()}
        self.keys = sorted(self.mib)
        self.community, self.bulk, self.junk_first = community, bulk, junk_first
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.seen = []
        threading.Thread(target=self.serve, daemon=True).start()

    def _next(self, oid):
        i = bisect.bisect_right(self.keys, oid)
        return (self.keys[i], self.mib[self.keys[i]]) if i < len(self.keys) else (oid, (END_OF_MIB_VIEW, None))

    def serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            try:
                m = snmp.decode_message(data)
            except snmp.BerError:
                continue
            self.seen.append(m["pdu"])
            if m["community"] != self.community:
                continue  # λάθος community: σιωπή, όπως οι πραγματικές συσκευές
            oids = [o for o, _, _ in m["varbinds"]]
            if m["pdu"] == snmp.GET:
                out = [(o, self.mib.get(o, (NO_SUCH_INSTANCE, None))) for o in oids]
            elif m["pdu"] == snmp.GETNEXT:
                out = [self._next(o) for o in oids]
            elif m["pdu"] == snmp.GETBULK:
                if not self.bulk:
                    continue  # agent που αγνοεί το GETBULK
                out, cur = [], oids[0]
                for _ in range(m["b"]):
                    o, v = self._next(cur)
                    out.append((o, v))
                    if v[0] == END_OF_MIB_VIEW:
                        break
                    cur = o
            else:
                continue
            if self.junk_first:
                self.sock.sendto(b"\x30\x05garbage", addr)
                self.sock.sendto(snmp.encode_message(self.community, snmp.RESPONSE, m["reqid"] + 1, out), addr)  # λάθος reqid
            self.sock.sendto(snmp.encode_message(self.community, snmp.RESPONSE, m["reqid"], out), addr)

    def close(self):
        self.sock.close()


IF = "1.3.6.1.2.1.2.2.1"
IFX = "1.3.6.1.2.1.31.1.1.1"


def device_mib(n_if=3, in_oct=1000, uptime=500000):
    mib = {"1.3.6.1.2.1.1.1.0": (OCTET_STRING, b"Test router OS 1.0"), "1.3.6.1.2.1.1.3.0": (TIMETICKS, uptime),
           "1.3.6.1.2.1.1.5.0": (OCTET_STRING, b"gw"), "1.3.6.1.2.1.1.6.0": (OCTET_STRING, b"lab"),
           "1.3.6.1.2.1.25.3.3.1.2.1": (INTEGER, 10), "1.3.6.1.2.1.25.3.3.1.2.2": (INTEGER, 30),
           "1.3.6.1.2.1.25.2.3.1.2.1": (OID, snmp.HR_RAM_TYPE), "1.3.6.1.2.1.25.2.3.1.4.1": (INTEGER, 1024),
           "1.3.6.1.2.1.25.2.3.1.5.1": (INTEGER, 1000), "1.3.6.1.2.1.25.2.3.1.6.1": (INTEGER, 250),
           "1.0.8802.1.1.2.1.4.1.1.7.0.2.1": (OCTET_STRING, b"Port 1"),
           "1.0.8802.1.1.2.1.4.1.1.9.0.2.1": (OCTET_STRING, b"sw-core"),
           "1.0.8802.1.1.2.1.3.7.1.3.2": (OCTET_STRING, b"ether2"),
           "1.3.6.1.6.3.1.1.4.1.0": (OID, (1, 3, 6, 1)),  # κάτι μετά, για να δοκιμαστεί το «τέλος υποδέντρου»
           }
    for i in range(1, n_if + 1):
        mib.update({f"{IF}.1.{i}": (INTEGER, i), f"{IF}.2.{i}": (OCTET_STRING, f"eth{i}".encode()), f"{IF}.3.{i}": (INTEGER, 6),
                    f"{IF}.5.{i}": (GAUGE32, 1000000000), f"{IF}.7.{i}": (INTEGER, 1), f"{IF}.8.{i}": (INTEGER, 1),
                    f"{IF}.10.{i}": (COUNTER32, in_oct), f"{IF}.16.{i}": (COUNTER32, in_oct), f"{IF}.14.{i}": (COUNTER32, 0),
                    f"{IFX}.1.{i}": (OCTET_STRING, f"ether{i}".encode()), f"{IFX}.6.{i}": (COUNTER64, 2 ** 40 + i),
                    f"{IFX}.10.{i}": (COUNTER64, 2 ** 41), f"{IFX}.15.{i}": (GAUGE32, 1000), f"{IFX}.18.{i}": (OCTET_STRING, b"")})
    return mib


def test_get_and_walk_bulk():
    ag = FakeAgent(device_mib(n_if=60))
    try:
        cl = snmp.SnmpClient("127.0.0.1", "public", ag.port, timeout=1, max_rep=7)
        r = cl.get(["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.99.0"])
        assert r[(1, 3, 6, 1, 2, 1, 1, 1, 0)] == b"Test router OS 1.0" and r[(1, 3, 6, 1, 2, 1, 1, 3, 0)] == 500000
        assert r[(1, 3, 6, 1, 2, 1, 1, 99, 0)] is None
        rows = cl.walk(f"{IF}.2")
        assert len(rows) == 60 and rows[0] == ((1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1), b"eth1") and cl.bulk_ok
        assert snmp.GETBULK in ag.seen and snmp.GETNEXT not in ag.seen
        assert len(cl.walk(f"{IF}.2", max_rows=10)) == 10
        assert cl.walk("1.3.6.1.2.1.99") == []
        # Counter64 μέσα από πραγματικό πακέτο
        assert snmp.walk("127.0.0.1", f"{IFX}.6", port=ag.port, timeout=1)[0][1] == 2 ** 40 + 1
        # walk μέχρι το τέλος της MIB (endOfMibView)
        assert snmp.walk("127.0.0.1", "1.3.6.1.6", port=ag.port, timeout=1) == [((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0), (1, 3, 6, 1))]
    finally:
        ag.close()


def test_walk_falls_back_to_getnext():
    ag = FakeAgent(device_mib(n_if=4), bulk=False)
    try:
        cl = snmp.SnmpClient("127.0.0.1", "public", ag.port, timeout=0.3, retries=0)
        rows = cl.walk(f"{IF}.8")
        assert [v for _, v in rows] == [1, 1, 1, 1] and not cl.bulk_ok and snmp.GETNEXT in ag.seen
    finally:
        ag.close()


def test_junk_and_wrong_reqid_ignored():
    ag = FakeAgent(device_mib(n_if=2), junk_first=True)
    try:
        cl = snmp.SnmpClient("127.0.0.1", "public", ag.port, timeout=1)
        assert cl.get(["1.3.6.1.2.1.1.5.0"])[(1, 3, 6, 1, 2, 1, 1, 5, 0)] == b"gw"
        assert len(cl.walk(f"{IF}.2")) == 2
    finally:
        ag.close()


def test_timeout_wrong_community():
    ag = FakeAgent(device_mib())
    try:
        cl = snmp.SnmpClient("127.0.0.1", "wrong", ag.port, timeout=0.2, retries=1)
        with pytest.raises(snmp.SnmpTimeout):
            cl.get(["1.3.6.1.2.1.1.1.0"])
        assert ag.seen.count(snmp.GET) == 2  # 1 + 1 retry
        assert "wrong" not in repr(cl)
    finally:
        ag.close()


def test_collect_and_poller_end_to_end():
    ag = FakeAgent(device_mib(n_if=3))
    try:
        st = St()
        s = snmp.Snmp(st, {"enabled": True, "timeout": 1, "targets": [{"name": "R", "host": "127.0.0.1", "port": ag.port,
                                                                        "community": "public"}]})
        s.round(now=1000)
        t = s.status()["targets"][0]
        assert t["ok"] and t["sys"]["name"] == "gw" and t["sys"]["uptime"] == 5000 and t["cpu"] == 20.0 and t["ram"] == 25.0
        assert [i["name"] for i in t["interfaces"]] == ["ether1", "ether2", "ether3"]
        i = t["interfaces"][0]
        assert i["hc"] and i["speed"] == 10 ** 9 and i["oper"] == "up" and i["admin"] == "up"
        assert t["neighbours"] == [{"proto": "lldp", "local_port": "ether2", "local_ifindex": 2, "remote_name": "sw-core",
                                    "remote_port": "Port 1", "remote_port_desc": "", "chassis": ""}]
        assert "public" not in json.dumps(s.status())
        json.dumps(s.iface_history("R", 1))
    finally:
        ag.close()


# ───────── ρυθμοί / ειδοποιήσεις ─────────

def iface(**kw):
    d = {"descr": "eth1", "name": "eth1", "alias": "", "type": 6, "speed": 100000000, "high_speed": 100, "admin": 1, "oper": 1,
         "in64": None, "out64": None, "in32": 0, "out32": 0, "in_err": 0, "out_err": 0, "in_disc": 0, "out_disc": 0}
    d.update(kw)
    return d


def raw(uptime, **kw):
    return {"sys": {"descr": "x", "name": "x", "location": "", "uptime": uptime}, "ifs": {1: iface(**kw)}, "cpu": None,
            "ram": None, "neigh": []}


def poller(st=None, **cfg):
    s = snmp.Snmp(st, {"targets": [{"name": "SW", "host": "192.168.1.2"}], **cfg})
    return s, s.targets[0]


def ingest(s, t, r, now):
    with s.lock:
        ev = s.ingest(t, r, now)
    for e in ev:
        s._alert(*e)
    return ev


def test_counter_helpers():
    assert snmp.counter_delta(100, 300, 32) == 200
    assert snmp.counter_delta(2 ** 32 - 100, 50, 32) == 150
    assert snmp.counter_delta(2 ** 40, 5, 64) is None
    assert snmp.uptime_reset(100000, 50, 60)
    assert not snmp.uptime_reset(2 ** 32 - 1000, 5000, 60)  # αναδίπλωση TimeTicks, όχι επανεκκίνηση
    assert snmp.fmt_bps(1.5e9) == "1.5 Gbps" and snmp.fmt_uptime(90061) == "1μ 1ω 1′"


def test_rates_with_32bit_wrap_and_reboot():
    st = St()
    s, t = poller(st)
    ingest(s, t, raw(100000, in32=2 ** 32 - 750000, out32=1000), 1000)
    ingest(s, t, raw(106000, in32=500000, out32=1000 + 7500000), 1060)  # 1.25 MB σε 60″ με αναδίπλωση
    i = s.status()["targets"][0]["interfaces"][0]
    assert i["in_bps"] == 1250000 * 8 // 60 and i["out_bps"] == 1000000 and i["util_out"] == 1.0 and i["util"] == 1.0
    assert not i["hc"] and i["err_s"] == 0.0
    ev = ingest(s, t, raw(500, in32=10, out32=10), 1120)  # επανεκκίνηση: οι μετρητές μηδενίστηκαν
    i = s.status()["targets"][0]["interfaces"][0]
    assert i["in_bps"] is None and [e[0] for e in ev] == ["Συσκευή επανεκκινήθηκε"]
    assert st.alerts[-1][:4] == ("Συσκευή επανεκκινήθηκε", "low", "192.168.1.2", "SW") and st.alerts[-1][5]["mark"] is False
    ingest(s, t, raw(6500, in32=10 + 750000, out32=10), 1180)
    h = s.iface_history("SW", 1)
    assert h["in"] == [None, 1250000 * 8 // 60, None, 100000] and len(h["t"]) == 4


def test_hc_counters_preferred_and_bogus_jump_dropped():
    s, t = poller()
    ingest(s, t, raw(100, in64=2 ** 33, out64=0, in32=5, out32=5), 0)
    ingest(s, t, raw(6100, in64=2 ** 33 + 125000000, out64=0, in32=7, out32=5), 10)
    i = s.status()["targets"][0]["interfaces"][0]
    assert i["hc"] and i["in_bps"] == 100000000 and i["util_in"] == 100.0
    ingest(s, t, raw(7100, in64=2 ** 33 + 125000000, out64=0, in32=7, out32=0), 20)
    ingest(s, t, raw(8100, in64=2 ** 33 + 125000000, out64=10 ** 12, in32=7, out32=0), 30)  # αδύνατο για 100 Mbps
    assert s.status()["targets"][0]["interfaces"][0]["out_bps"] is None


def test_history_bounded():
    s, t = poller(history=5)
    for k in range(12):
        ingest(s, t, raw(100 + k * 6000, in32=k * 1000, out32=0), k * 60)
    assert len(s.status()["targets"][0]["interfaces"][0]["hist"]["in"]) == 5


def test_port_down_up_alerts():
    st = St()
    s, t = poller(st)
    ingest(s, t, raw(100, oper=2), 0)  # ήταν ήδη κάτω στην αρχή: καμία ειδοποίηση
    ingest(s, t, raw(6100, oper=1), 60)
    assert st.alerts == []
    ingest(s, t, raw(12100, oper=2, alias="NAS"), 120)
    assert st.alerts[-1][:2] == ("Θύρα δικτύου έπεσε", "med") and "«eth1» (NAS)" in st.alerts[-1][4]
    assert st.alerts[-1][5]["key"] == ("Θύρα δικτύου έπεσε", "SW|192.168.1.2|161", 1)
    ingest(s, t, raw(42100, oper=1), 420)
    assert st.alerts[-1][:2] == ("Θύρα δικτύου επανήλθε", "low") and "5′" in st.alerts[-1][4]
    n = len(st.alerts)
    ingest(s, t, raw(48100, oper=2, admin=2), 480)  # admin down: σκόπιμο, όχι συναγερμός
    ingest(s, t, raw(54100, oper=1), 540)
    assert len(st.alerts) == n


def test_errors_and_utilisation_alerts():
    st = St()
    s, t = poller(st)
    ingest(s, t, raw(100, in_err=0), 0)
    ingest(s, t, raw(6100, in_err=30, out_err=60), 60)
    assert st.alerts[-1][:2] == ("Σφάλματα σε θύρα", "med") and "1.5 σφάλματα/s" in st.alerts[-1][4]
    st.alerts.clear()
    c = 0
    for k in range(1, 5):
        c += int(95e6 / 8 * 60)
        ingest(s, t, raw(6100 + k * 6000, in32=c % 2 ** 32, in_err=90, out_err=0), 60 + k * 60)
    assert [a[0] for a in st.alerts] == ["Θύρα κοντά στο όριο"] and "95%" in st.alerts[0][4]


def test_unreachable_after_three_polls():
    st = St()
    s = snmp.Snmp(st, {"timeout": 0.1, "retries": 0, "targets": [{"name": "Dead", "host": "127.0.0.1", "port": 9}]})
    s.fetch = lambda t, now: (_ for _ in ()).throw(snmp.SnmpTimeout("δεν απάντησε (timeout)"))
    for k in range(4):
        s.round(now=k * 60)
    assert [a[0] for a in st.alerts] == ["SNMP χωρίς απάντηση"]
    tg = s.status()["targets"][0]
    assert tg["ok"] is False and tg["fails"] == 4 and "timeout" in tg["error"]


def test_bad_raw_data_does_not_crash():
    s, t = poller()
    s.fetch = lambda t, now: {"sys": None, "ifs": {1: {"in32": "x"}}}
    s.round(now=1)
    s.round(now=61)
    json.dumps(s.status())


def test_demo_has_data():
    s = snmp.Snmp(St(), None, sim=True)
    st = s.status()
    assert st["demo"] and [t["name"] for t in st["targets"]] == ["Router", "Switch", "Proxmox"]
    r, sw, pve = st["targets"]
    assert len(r["interfaces"]) == 5 and len(sw["interfaces"]) == 8 and pve["cpu"] is not None and pve["ram"] is not None
    wan = r["interfaces"][0]
    assert wan["alias"] == "WAN (ISP)" and wan["in_bps"] > 0 and len(wan["hist"]["in"]) == s.cfg["history"]
    assert r["neighbours"] and sw["neighbours"]
    json.dumps(st)
