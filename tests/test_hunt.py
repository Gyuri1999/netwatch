import collections
import threading
import time

import hunt
import timeline

ME, GW = "192.168.1.23", "192.168.1.1"
CAM, LAPTOP, TV = "192.168.1.33", "192.168.1.40", "192.168.1.31"


def H(ip, kind="local", **kw):
    h = dict(ip=ip, kind=kind, me=ip == ME, gw=ip == GW, first=0.0, last=0.0, pkts_in=0, pkts_out=0,
             bytes_in=0, bytes_out=0, ports=collections.Counter(), protos=collections.Counter(),
             names=set(), mac=None, geo=None, rdns=None, threat=0, alerts=[], hits=collections.Counter(),
             victims=collections.Counter(), ja3=collections.Counter(), ja3_sni={}, intel=[])
    h.update(kw)
    return h


class FakeState:
    def __init__(self, hosts=(), alerts=(), clock=None):
        self.lock = threading.RLock()
        self.hosts = {h["ip"]: h for h in hosts}
        self.alerts = collections.deque(alerts)
        self.recent = collections.deque()
        self.me, self.gateway, self.lab_ips = {ME}, GW, set()
        self.timeline = None
        self.baseline = None


NOW = 2_000_000_000.0


def tl_with(state, rows):
    """rows: [(t, dev, peer, bytes, proto, out_frac)] → timeline με κλεισμένους κουβάδες."""
    tl = timeline.Timeline(state, clock=lambda: NOW)
    by = collections.defaultdict(list)
    for r in rows:
        by[int(r[0] // 60) * 60].append(r)
    for b in sorted(by):
        x = {"t": b, "pkts": 0, "bytes": 0, "dev": {}, "edge": []}
        for _, dev, peer, nb, proto, up in by[b]:
            x["edge"].append([dev, peer, nb, max(1, nb // 900), proto])
            d = x["dev"].setdefault(dev, [0, 0, 0])
            d[0] += int(nb * (1 - up)); d[1] += int(nb * up); d[2] += 1
        tl.buckets.append(x)
    state.timeline = tl
    return tl


def ids(res):
    return [(f["actor"], f["target"]) for f in res["findings"]]


def test_longtail_finds_single_device_rare_peer():
    peers = ["142.250.1.1", "17.1.1.1"]
    hosts = [H(ME, victims=collections.Counter({p: 50 for p in peers})),
             H(LAPTOP, victims=collections.Counter({peers[0]: 40, peers[1]: 30})),
             H(CAM, victims=collections.Counter({peers[1]: 20, "47.91.88.12": 2})),
             H("142.250.1.1", "public", names={"www.google.com"}), H("17.1.1.1", "public", names={"apple.com"}),
             H("47.91.88.12", "public", geo={"countryCode": "CN"})]
    r = hunt.Hunt(FakeState(hosts), clock=lambda: NOW).run("longtail")
    assert ids(r) == [(CAM, "47.91.88.12")]
    f = r["findings"][0]
    assert f["evidence"]["cc"] == "CN" and f["score"] >= 70 and f["hunt"] == "longtail"
    assert r["stats"]["examined"] == 3 and r["explain"]


def test_jitterbeacon_regular_gaps_vs_streaming():
    st = FakeState()
    rows, t = [], NOW - 10 * 3600
    gaps = [15, 13, 17, 16, 14, 18, 15, 16, 14, 17, 15, 16, 13, 17]
    for g in gaps * 2:
        rows.append((t, CAM, "194.36.189.71", 700, "TCP/443", 0.6))
        t += g * 60
    for i in range(300):  # συνεχής ροή κάθε λεπτό: όχι beacon
        rows.append((NOW - 6 * 3600 + i * 60, LAPTOP, "23.246.0.135", 5_000_000, "TCP/443", 0.1))
    for i in range(0, 600, 7):  # ακανόνιστο
        rows.append((NOW - 12 * 3600 + i * 60 + (i % 5) * 600, LAPTOP, "151.101.1.140", 3000, "TCP/443", 0.3))
    tl_with(st, rows)
    r = hunt.Hunt(st).run("jitterbeacon")
    assert ids(r)[0] == (CAM, "194.36.189.71")
    assert (LAPTOP, "23.246.0.135") not in ids(r)
    ev = r["findings"][0]["evidence"]
    assert 14 <= ev["mean_gap_min"] <= 17 and ev["cv"] < 0.2


def test_rarefp_second_fingerprint_on_device():
    common = "773906b0efdefa24a7f2b8eb6985bf37"
    hosts = [H(LAPTOP, ja3=collections.Counter({common: 500}), ja3_sni={common: {"apple.com"}}),
             H(TV, ja3=collections.Counter({common: 300})),
             H(CAM, names={"tapo-cam.local"}, ja3=collections.Counter({common: 900, "badbadbad0000": 9}))]
    r = hunt.Hunt(FakeState(hosts)).run("rarefp")
    assert len(r["findings"]) == 1
    f = r["findings"][0]
    assert f["actor"] == CAM and f["evidence"]["fingerprint"] == "badbadbad0000" and f["score"] >= 80


def test_exfil_upload_heavy_peer():
    hosts = [H(LAPTOP, victims=collections.Counter({"45.137.21.9": 300, "8.8.8.8": 10})),
             H(TV, victims=collections.Counter({"23.246.0.135": 900})),
             H("45.137.21.9", "public", bytes_in=80_000_000, bytes_out=900_000),
             H("23.246.0.135", "public", bytes_in=2_000_000, bytes_out=900_000_000),
             H("8.8.8.8", "public", bytes_in=10_000, bytes_out=20_000)]
    r = hunt.Hunt(FakeState(hosts)).run("exfil")
    assert ids(r) == [(LAPTOP, "45.137.21.9")]
    assert r["findings"][0]["evidence"]["ratio"] > 80


def _day_ts(hour, minute=0, days_back=0):
    lt = time.localtime(NOW)
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday - days_back, hour, minute, 0, 0, 0, -1))


def test_offhours_night_burst_on_day_device():
    st = FakeState()
    rows = []
    for h in range(8, 23):
        for m in range(0, 60, 2):
            rows.append((_day_ts(h, m, 1), TV, "23.246.0.135", 400_000, "TCP/443", 0.1))
            rows.append((_day_ts(h, m, 1), CAM, "52.57.110.21", 5_000, "TCP/443", 0.4))
    for h in range(0, 8):  # η κάμερα δουλεύει όλο το 24ωρο: όχι εύρημα
        for m in range(0, 60, 2):
            rows.append((_day_ts(h, m, 1), CAM, "52.57.110.21", 5_000, "TCP/443", 0.4))
    for m in range(12, 30):
        rows.append((_day_ts(3, m, 1), TV, "45.137.21.9", 8_000_000, "TCP/443", 0.95))
    tl_with(st, rows)
    r = hunt.Hunt(st, clock=lambda: NOW).run("offhours")
    assert ids(r) == [(TV, "45.137.21.9")]
    assert r["findings"][0]["evidence"]["night_minutes"] == 18


def test_newsvc_rare_new_port():
    st = FakeState()
    rows = []
    t0 = NOW - 20 * 3600
    for i in range(600):
        rows.append((t0 + i * 120, CAM, "52.57.110.21", 5000, "TCP/443", 0.4))
        rows.append((t0 + i * 120, CAM, "162.159.200.123", 90, "UDP/123", 0.5))
        rows.append((t0 + i * 120, LAPTOP, "142.250.1.1", 9000, "TCP/443", 0.2))
    for k in range(3):
        rows.append((t0 + 15 * 3600 + k * 60, CAM, "47.91.88.12", 2400, "TCP/9000", 0.5))
    tl_with(st, rows)
    r = hunt.Hunt(st).run("newsvc")
    assert ids(r) == [(CAM, "47.91.88.12")]
    assert r["findings"][0]["evidence"]["proto"] == "TCP/9000"


def test_dnslongtail_random_name_not_alerted():
    st = FakeState(alerts=[{"type": "DNS tunneling", "actor": LAPTOP, "target": "exfil-demo.example", "detail": "", "t": NOW}])
    h = hunt.Hunt(st)
    for name, client in (("xj4kq9vz2mtb.top", TV), ("www.google.com", LAPTOP), ("www.google.com", TV),
                         ("a8f3c9e1d2b7f6a0c4e9.exfil-demo.example", LAPTOP), ("mail.example.org", CAM)):
        h.observe({"src": client, "dst": GW, "dns_q": (name, 1)}, NOW)
    r = h.run("dnslongtail")
    assert [f["evidence"]["domain"] for f in r["findings"]] == ["xj4kq9vz2mtb.top"]
    assert r["findings"][0]["actor"] == TV
    assert r["stats"]["already_alerted"] == 1


def test_quietbad_low_volume_bad_country_without_alert():
    hosts = [H(CAM, victims=collections.Counter({"47.91.88.12": 3, "5.5.5.5": 40})),
             H("47.91.88.12", "public", geo={"countryCode": "CN"}, bytes_in=2000, bytes_out=1000, pkts_in=4, pkts_out=4),
             H("5.5.5.5", "public", geo={"countryCode": "RU"}, bytes_in=3000, bytes_out=3000),
             H("8.8.8.8", "public", geo={"countryCode": "US"}, bytes_in=10, bytes_out=10)]
    st = FakeState(hosts, alerts=[{"type": "Port scan", "actor": "5.5.5.5", "target": CAM, "detail": "", "t": NOW}])
    r = hunt.Hunt(st).run("quietbad")
    assert ids(r) == [(CAM, "47.91.88.12")]
    assert r["stats"]["already_alerted"] == 1


def test_empty_state_never_crashes_and_invalid_id():
    class Bare:
        pass
    for st in (FakeState(), Bare(), None):
        h = hunt.Hunt(st)
        for k in list(hunt.HUNTS) + ["all"]:
            r = h.run(k)
            assert r["findings"] == [] and "note" in r["stats"] or k == "all"
        assert "error" in h.profile("192.168.1.99")
        assert "error" in h.profile("not-an-ip")
    assert "error" in hunt.Hunt(FakeState()).run("nope")
    cat = hunt.Hunt(FakeState()).catalog()
    assert len(cat["hunts"]) == 8 and all(len(x["steps"]) >= 3 and x["mitre"]["id"] for x in cat["hunts"])


def test_profile_shape_and_lab_exclusion():
    st = FakeState([H(CAM, mac="c0:56:e3:30:30:30", names={"tapo-cam.local"}, ports=collections.Counter({443: 50, 123: 9}),
                      protos=collections.Counter({"HTTPS": 50, "NTP": 9}), bytes_in=1000, bytes_out=500,
                      ja3=collections.Counter({"abc": 5}), victims=collections.Counter({"52.57.110.21": 5}),
                      alerts=[1]),
                    H("52.57.110.21", "public", names={"tplinkcloud.com"}, geo={"countryCode": "DE"})],
                   alerts=[{"type": "x", "actor": CAM, "target": "y", "t": NOW}])
    rows = [(_day_ts(h, 5, 1), CAM, "52.57.110.21", 5000, "TCP/443", 0.4) for h in range(8, 20)]
    tl_with(st, rows)
    p = hunt.Hunt(st).profile(CAM)
    for k in ("ip", "name", "mac", "kind", "first", "last", "hours", "top_peers", "ports", "protos", "bytes_in",
              "bytes_out", "fingerprints", "countries", "alerts", "normal"):
        assert k in p
    assert len(p["hours"]) == 24 and sum(p["hours"]) == 12
    assert p["top_peers"][0] == {"peer": "52.57.110.21", "name": "tplinkcloud.com", "cc": "DE", "bytes": 60000}
    assert p["ports"][0] == {"port": 443, "count": 50} and p["countries"] == ["DE"] and p["alerts"] == 1
    assert "08–20" in p["normal"] and "HTTPS" in p["normal"]
    # οι «επιτιθέμενοι» του lab δεν γίνονται ποτέ ευρήματα
    st.lab_ips.add(CAM)
    assert hunt.Hunt(st).run("all")["findings"] == []


def test_demo_mode_every_hunt_has_findings():
    # όπως στο πραγματικό demo: το Τείχος IoT έχει ήδη ειδοποιήσει για την κάμερα → Κίνα
    st = FakeState(alerts=[{"type": "Παραβίαση Τείχους IoT", "actor": CAM, "target": "47.91.88.12", "detail": "", "t": NOW}])
    st.timeline = timeline.Timeline(st, sim=True)
    h = hunt.Hunt(st, sim=True)
    for k in hunt.HUNTS:
        r = h.run(k)
        assert r["findings"], k
        assert all(0 <= f["score"] <= 100 and f["summary"] and f["why"] and f["next"] for f in r["findings"])
    cat = h.catalog()
    assert cat["demo"] and all(x["last_count"] >= 1 for x in cat["hunts"])
    assert h.run("all")["findings"][0]["score"] >= 80
    assert h.profile("192.168.1.33")["name"]
