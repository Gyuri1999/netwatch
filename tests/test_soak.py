"""📅 Παρακολούθηση ποιότητας: διακοπές, κάλυψη, «ποιος φταίει», αναφορά — χωρίς δίκτυο."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import soak  # noqa: E402

T0 = 1_700_000_000.0  # σταθερή αφετηρία


def rows(spec, t0=T0, step=60):
    """spec: λίστα απωλειών % ανά γύρο (None = κενό, δεν μετρήθηκε)."""
    out = []
    for i, loss in enumerate(spec):
        if loss is None:
            continue
        ok = loss < 100
        out.append((t0 + i * step, 9.0 if ok else None, 10.0 if ok else None, 12.0 if ok else None, float(loss), 1.0 if ok else None))
    return out


class Store:
    def __init__(self, data):
        self.data = data

    def rows(self, name, a, b):
        return [r for r in self.data.get(name, []) if a <= r[0] <= b]


class Lat:
    enabled = True

    def __init__(self, data, targets):
        self.store, self.targets = Store(data), targets


class State:
    def __init__(self, data=None, targets=None):
        self.latency = Lat(data or {}, targets or [])


TG = [{"name": "Router", "host": "192.168.1.1", "role": "gateway"}, {"name": "CF", "host": "1.1.1.1", "role": "public"},
      {"name": "G", "host": "8.8.8.8", "role": "public"}]


def test_outages_and_gaps():
    r = rows([0, 0, 100, 100, 100, 0, 0, 100, 0])
    o = soak.outages(r)
    assert [(a - T0, b - T0, n) for a, b, n in o] == [(120, 300, 3), (420, 480, 1)]
    # η διακοπή δεν «τεντώνει» πάνω από κενό μετρήσεων: τελειώνει στον τελευταίο χαμένο γύρο
    r = rows([0, 100, 100] + [None] * 20 + [0])
    assert [(a - T0, b - T0) for a, b, _ in soak.outages(r)] == [(60, 120)]
    # ακόμα κάτω στο τέλος
    assert [(a - T0, b - T0) for a, b, _ in soak.outages(rows([0, 100, 100]))] == [(60, 120)]
    assert soak.outages([]) == [] and soak.outages(rows([0, 20, 50])) == []
    cov, gaps = soak.coverage(rows([0] * 10 + [None] * 10 + [0] * 10), T0, T0 + 29 * 60)
    assert 60 < cov < 66 and len(gaps) == 1
    assert soak.coverage([], T0, T0 + 100) == (0.0, [(T0, T0 + 100)])


def test_blame_isp_vs_local():
    good = [0] * 30
    down = [0] * 10 + [100] * 5 + [0] * 15
    # Internet κάτω, router όρθιο → πάροχος
    st = State({"Router": rows(good), "CF": rows(down), "G": rows(down)}, TG)
    s = soak.Soak(st, clock=lambda: T0 + 3600)
    r = s.summary(T0, T0 + 1800)
    assert r["internet"]["outages"] == 1 and r["internet"]["isp"] == 1 and r["internet"]["local"] == 0
    assert r["outages"][0]["cause"] == "isp" and r["outages"][0]["min"] == 5 and r["level"] in ("warn", "bad")
    assert any("πάροχο" in f["el"] for f in r["findings"])
    # και το router κάτω → τοπικό
    st = State({"Router": rows(down), "CF": rows(down), "G": rows(down)}, TG)
    r = soak.Soak(st, clock=lambda: T0 + 3600).summary(T0, T0 + 1800)
    assert r["internet"]["local"] == 1 and r["outages"][0]["cause"] == "local"
    # μόνο ο ένας δημόσιος στόχος κάτω → ΔΕΝ είναι διακοπή Internet
    st = State({"Router": rows(good), "CF": rows(down), "G": rows(good)}, TG)
    r = soak.Soak(st, clock=lambda: T0 + 3600).summary(T0, T0 + 1800)
    assert r["internet"]["outages"] == 0 and r["internet"]["uptime"] == 100.0
    # χωρίς μέτρηση router → «άγνωστο»
    st = State({"CF": rows(down), "G": rows(down)}, TG)
    r = soak.Soak(st, clock=lambda: T0 + 3600).summary(T0, T0 + 1800)
    assert r["outages"][0]["cause"] == "unknown"


def test_no_data_and_missing_sources():
    s = soak.Soak(object(), clock=lambda: T0)
    r = s.summary(T0 - 3600, T0)
    assert r["has_data"] is False and r["coverage"] == 0.0 and r["findings"][0]["sev"] == "warn"
    assert s.view()["summary"] is None and s.view()["sources"]["latency"] is False


def test_worst_window_wraps_midnight():
    hours = [{"h": h, "n": 10, "loss": 8.0 if h in (22, 23, 0, 1) else 0.2, "jitter": 1.0} for h in range(24)]
    assert soak.worst_window(hours) == (22, 2)
    assert soak.worst_window([{"h": h, "n": 10, "loss": 0.1} for h in range(24)]) is None
    assert soak.worst_window([{"h": h, "n": 1, "loss": 50.0} for h in range(24)]) is None  # πολύ λίγα δείγματα


def test_watch_lifecycle_and_persistence(tmp_path):
    now = [T0]
    st = State({"Router": rows([0] * 60), "CF": rows([0] * 60), "G": rows([0] * 60)}, TG)
    s = soak.Soak(st, str(tmp_path), clock=lambda: now[0])
    code, v = s.api("POST", "start", {}, {"name": "Καφέ <b>x</b>\x07", "days": 999, "back_days": 2, "note": "σημ."})
    w = v["watches"][0]
    assert code == 200 and w["running"] and w["days"] == soak.MAX_DAYS + 2 and "\x07" not in w["name"]
    assert w["start"] == T0 - 2 * 86400
    assert s.api("POST", "start", {}, {"days": "abc"})[0] == 400
    s2 = soak.Soak(st, str(tmp_path), clock=lambda: now[0])
    assert [x["id"] for x in s2.watches] == [w["id"]]
    now[0] += 3600
    code, v = s2.api("POST", "stop", {}, {"id": w["id"]})
    assert code == 200 and not v["watches"][0]["running"] and v["watches"][0]["end"] == now[0]
    assert s2.api("GET", "summary", {"id": w["id"]}, {})[1]["internet"]["outages"] == 0
    assert s2.api("POST", "delete", {}, {"id": w["id"]})[1]["watches"] == []
    assert s2.api("POST", "stop", {}, {"id": "nope"})[0] == 404
    assert s2.api("GET", "report", {"id": "nope"}, {})[0] == 404 and s2.api("GET", "x", {}, {})[0] == 404


def test_report_is_escaped_and_scriptless(tmp_path):
    down = [0] * 10 + [100] * 5 + [0] * 15
    tg = [dict(TG[0]), {"name": "<script>alert(1)</script>", "host": "1.1.1.1", "role": "public"}]
    st = State({"Router": rows([0] * 30), tg[1]["name"]: rows(down)}, tg)
    s = soak.Soak(st, str(tmp_path), clock=lambda: T0 + 1800)
    s.api("POST", "start", {}, {"name": "<img src=x onerror=1>", "days": 1, "back_days": 1})
    code, doc = s.api("GET", "report", {"id": s.watches[0]["id"], "lang": "en"}, {})
    html = doc["_raw"].decode()
    assert code == 200 and doc["_type"].startswith("text/html") and "<script" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html and "Network quality report" in html and "line / ISP" in html and "<svg" in html
    assert "Αναφορά ποιότητας δικτύου" in s.report(s.watches[0], "el")


def test_demo_view_and_readonly():
    s = soak.Soak(State(), demo=True)
    v = s.view()
    assert v["demo"] is True and len(v["watches"]) == 1 and v["watches"][0]["running"]
    assert s.api("POST", "delete", {}, {"id": v["watches"][0]["id"]})[1]["note"] == "demo" and len(s.watches) == 1
