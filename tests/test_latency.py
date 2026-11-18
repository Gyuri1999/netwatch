import time

import latency

MAC = """PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.512 ms
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=10.101 ms
Request timeout for icmp_seq 2
64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=14.900 ms
64 bytes from 1.1.1.1: icmp_seq=4 ttl=57 time=11.000 ms

--- 1.1.1.1 ping statistics ---
5 packets transmitted, 4 packets received, 20.0% packet loss
round-trip min/avg/max/stddev = 10.101/12.128/14.900/1.801 ms
"""

LINUX = """PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=15.3 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=16.1 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=117 time<1 ms

--- 8.8.8.8 ping statistics ---
10 packets transmitted, 3 received, 70% packet loss, time 1810ms
rtt min/avg/max/mdev = 0.9/15.7/16.1/0.4 ms
"""


class St:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, kw.get("mark")))


def test_parse_mac_and_linux():
    rtts, sent = latency.parse_ping(MAC)
    assert rtts == [12.512, 10.101, 14.9, 11.0] and sent == 5
    s = latency.summarize(rtts, sent)
    assert s["loss"] == 20.0 and s["min"] == 10.101 and s["max"] == 14.9 and s["med"] == round((11.0 + 12.512) / 2, 3)
    assert s["jitter"] > 0
    rtts, sent = latency.parse_ping(LINUX)
    assert rtts == [15.3, 16.1, 1.0] and sent == 10
    assert latency.summarize(rtts, sent)["loss"] == 70.0
    assert latency.summarize(*latency.parse_ping("", 10)) == {"sent": 10, "recv": 0, "min": None, "med": None,
                                                              "max": None, "loss": 100.0, "jitter": None}


def test_ping_cmd_flags():
    mac = latency.ping_cmd("1.1.1.1", platform="darwin")
    assert mac[:5] == ["ping", "-c", "10", "-i", "0.2"] and "-t" in mac
    lin = latency.ping_cmd("1.1.1.1", platform="linux")
    assert "-w" in lin and lin[-1] == "1.1.1.1"


def test_default_targets_and_rejects_bad_hosts():
    t = latency.normalize(None, gateway=lambda: "192.168.1.1", isp_hop="62.1.1.1")
    assert [x["host"] for x in t] == ["192.168.1.1", "1.1.1.1", "8.8.8.8", "62.1.1.1"]
    t = latency.normalize([{"host": "-oops"}, {"name": "a", "host": "10.0.0.1"}, {"host": "10.0.0.1"}])
    assert [x["name"] for x in t] == ["a"]


def test_sqlite_persistence(tmp_path):
    db = str(tmp_path / "sub" / "latency.db")
    cfg = {"targets": [{"name": "A", "host": "10.0.0.1"}]}
    lt = latency.Latency(cfg=cfg, db_path=db, pinger=lambda h: latency.summarize([5.0, 6.0, 7.0], 3))
    now = time.time()
    lt.round(now=now - 60)
    lt.round(now=now)
    lt.store.add(now - 40 * 86400, "A", "10.0.0.1", latency.summarize([1.0], 1))
    lt.store.close()
    lt2 = latency.Latency(cfg=cfg, db_path=db)
    assert lt2.store.count("A") == 3
    assert lt2.store.prune(now) == 1
    h = lt2.history("A", hours=1, now=now)
    assert h["median"] == [6.0, 6.0] and h["loss"] == [0.0, 0.0] and len(h["t"]) == 2
    assert lt2.history("10.0.0.1", hours=1, now=now)["target"] == "A"
    assert lt2.status(now=now)["targets"][0]["last"]["med"] == 6.0


def test_alert_thresholds(tmp_path):
    st = St()
    lt = latency.Latency(state=st, cfg={"targets": [{"name": "ISP", "host": "1.1.1.1"}]}, db_path=":memory:")
    now = 1_000_000.0
    ok = latency.summarize([10.0] * 10, 10)
    for i in range(30):  # βάση 24ώρου ≈ 10 ms
        lt.record({"ISP": ok}, now - 3000 + i * 60)
    lossy = latency.summarize([10.0] * 7, 10)  # 30 %
    lt.record({"ISP": lossy}, now)
    lt.record({"ISP": lossy}, now + 60)
    assert not st.alerts
    lt.record({"ISP": lossy}, now + 120)
    assert st.alerts == [("Απώλειες πακέτων", "med", "1.1.1.1", "ISP", False)]
    lt.record({"ISP": ok}, now + 180)  # μηδενίζει το σερί
    assert lt.streak["ISP"]["loss"] == 0
    st.alerts.clear()
    slow = latency.summarize([60.0] * 10, 10)  # > 3×10 και > 50 ms
    for k in range(3):
        lt.record({"ISP": slow}, now + 240 + k * 60)
    assert [a[:2] for a in st.alerts] == [("Υψηλή καθυστέρηση", "low")]
    st.alerts.clear()
    lt2 = latency.Latency(state=st, cfg={"targets": [{"name": "LAN", "host": "10.0.0.1"}]}, db_path=":memory:")
    for i in range(30):
        lt2.record({"LAN": latency.summarize([1.0] * 10, 10)}, now - 3000 + i * 60)
    for k in range(4):  # 40 ms = 40× αλλά < 50 ms → όχι ειδοποίηση
        lt2.record({"LAN": latency.summarize([40.0] * 10, 10)}, now + k * 60)
    assert not st.alerts


def test_bad_hours_finds_evening():
    rows = []
    day0 = time.mktime((2026, 11, 1, 0, 0, 0, 0, 0, -1))
    for d in range(7):
        for m in range(0, 1440, 10):
            t = day0 + d * 86400 + m * 60
            h = time.localtime(t).tm_hour
            med = 45.0 if 20 <= h <= 22 else 12.0
            loss = 5.0 if h == 21 else 0.0
            rows.append((t, med - 1, med, med + 5, loss, 1.0))
    r = latency.bad_hours(rows)
    assert r["worst"] == [20, 21, 22]
    assert r["overall_median"] == 12.0 and len(r["hours"]) == 24
    assert "21:00" in r["summary"]
    flat = latency.bad_hours([(day0 + i * 600, 9, 10, 11, 0.0, 1) for i in range(1000)])
    assert flat["worst"] == [] and "σταθερή" in flat["summary"]
    assert latency.bad_hours([])["summary"]


def test_demo_backfill_and_status():
    lt = latency.Latency(cfg={}, sim=True)
    assert lt.store.count() > 4 * 3000
    lt.round()
    s = lt.status()
    assert s["demo"] and len(s["targets"]) == 4
    pub = [x for x in s["targets"] if x["host"] == "1.1.1.1"][0]
    assert pub["last"]["med"] and any(h in pub["bad_hours"]["worst"] for h in (20, 21, 22))
    h = lt.history("1.1.1.1", hours=24 * 7)
    assert len(h["t"]) <= 1500 and h["step"]
