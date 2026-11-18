import os

import timeline


class FakeState:
    def __init__(self):
        self.hosts = {"192.168.1.5": {"ip": "192.168.1.5", "kind": "local", "names": {"laptop.local"}, "gw": False, "me": False},
                      "8.8.8.8": {"ip": "8.8.8.8", "kind": "public", "names": {"dns.google"},
                                  "geo": {"countryCode": "US", "country": "United States"}}}
        self.alerts = [{"id": 1, "t": 1000.0, "type": "Port scan", "sev": "high", "actor": "192.168.1.9", "target": "192.168.1.5"}]


def pkt(src, dst, n=100, dp=443):
    return {"src": src, "dst": dst, "len": n, "proto": "TCP", "sp": 50000, "dp": dp}


def test_buckets_devices_and_edges():
    clock = [1000.0]
    tl = timeline.Timeline(FakeState(), clock=lambda: clock[0])
    for i in range(5):
        tl.observe(pkt("192.168.1.5", "8.8.8.8", 100), 1000 + i)
    tl.observe(pkt("8.8.8.8", "192.168.1.5", 1500, dp=50000), 1010)
    tl.observe(pkt("192.168.1.5", "8.8.8.8", 100), 1070)  # επόμενο λεπτό κλείνει το πρώτο
    assert len(tl.buckets) == 1
    b = tl.buckets[0]
    assert b["t"] == 960 and b["pkts"] == 6
    assert b["dev"]["192.168.1.5"] == [1500, 500, 6]
    snap = tl.at(1000)
    assert snap["found"] and snap["devices"][0]["ip"] == "192.168.1.5"
    e = snap["edges"][0]
    assert (e["dev"], e["peer"], e["bytes"], e["cc"]) == ("192.168.1.5", "8.8.8.8", 2000, "US")
    assert snap["edges"][0]["name"] == "dns.google"
    assert snap["alerts"][0]["type"] == "Port scan"


def test_summary_and_tick_closes_idle_bucket():
    clock = [1000.0]
    tl = timeline.Timeline(FakeState(), clock=lambda: clock[0])
    tl.observe(pkt("192.168.1.5", "8.8.8.8"), 1000)
    clock[0] = 1100
    tl.tick()
    assert len(tl.buckets) == 1 and tl.cur is None
    s = tl.summary(24)
    assert s["buckets"][0]["alerts"] == 1 and s["buckets"][0]["sev"] == "high"


def test_lan_pair_and_multicast_ignored():
    tl = timeline.Timeline(FakeState(), clock=lambda: 2000.0)
    tl.observe(pkt("192.168.1.9", "192.168.1.5"), 2000)
    tl.observe(pkt("192.168.1.5", "192.168.1.9"), 2001)
    tl.observe(pkt("192.168.1.5", "239.255.255.250", dp=1900), 2002)
    snap = tl.at(2000)
    assert len(snap["edges"]) == 1 and snap["edges"][0]["lan"]


def test_save_and_reload(tmp_path):
    p = str(tmp_path / "tl.json.gz")
    tl = timeline.Timeline(FakeState(), path=p, clock=lambda: 1100.0)
    tl.observe(pkt("192.168.1.5", "8.8.8.8"), 1000)
    tl.observe(pkt("192.168.1.5", "8.8.8.8"), 1070)
    tl.save()
    assert os.path.exists(p)
    tl2 = timeline.Timeline(FakeState(), path=p, clock=lambda: 1100.0)
    assert len(tl2.buckets) == 1 and tl2.at(1000)["found"]


def test_demo_backfill_has_a_day():
    tl = timeline.Timeline(FakeState(), sim=True, clock=lambda: 1_800_000_000.0)
    assert len(tl.buckets) == timeline.KEEP
    s = tl.summary(24)
    assert len(s["buckets"]) >= 1400 and any(b["bytes"] > 0 for b in s["buckets"])
    snap = tl.at(1_800_000_000.0 - 29 * 60)
    assert any(e["peer"] == "47.91.88.12" for e in snap["edges"])
