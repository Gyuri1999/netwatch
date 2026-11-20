"""Tests για το ιστορικό διαθεσιμότητας (presence.py)."""
import os
import sys
import threading
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import presence  # noqa: E402

B = presence.BUCKET


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def make(tmp_path=None):
    clk = Clock(1_800_000_000.0)
    st = types.SimpleNamespace(lock=threading.RLock(), hosts={})
    p = presence.Presence(st, path=str(tmp_path / "p.sqlite") if tmp_path else None, clock=clk)
    return p, st, clk


def host(st, ip, mac, last, dtype="camera", name="Κάμερα"):
    st.hosts[ip] = {"kind": "local", "mac": mac, "last": last, "dtype": dtype, "dicon": "📷", "alias": name}


def test_outage_counting_and_netwatch_off_not_counted(tmp_path):
    p, st, clk = make(tmp_path)
    host(st, "192.168.1.40", "AA:00:00:00:00:02", 0)
    st.hosts["192.168.1.9"] = {"kind": "local", "me": True, "last": clk.t}               # εγώ → αγνοείται
    st.hosts["8.8.8.8"] = {"kind": "remote", "last": clk.t}                             # όχι LAN → αγνοείται
    pattern = [1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1]          # μία διακοπή 15′, ένα κενό 5′ (δεν μετράει)
    for on in pattern:
        st.hosts["192.168.1.40"]["last"] = clk.t if on else clk.t - 3600
        p.sample()
        clk.t += B
    clk.t += 10 * 3600                                     # NetWatch κλειστό 10 ώρες
    for _ in range(3):
        st.hosts["192.168.1.40"]["last"] = clk.t
        p.sample()
        clk.t += B
    clk.t -= B
    v = p.view(7)
    assert len(v["devices"]) == 1
    d = v["devices"][0]
    assert d["key"] == "aa:00:00:00:00:02" and d["name"] == "Κάμερα" and d["always_on"]
    assert d["outages"] == 1 and d["longest_min"] == 15 and d["online"]
    assert d["pct"] == round(100 * 10 / 14, 1)            # τα 10 ώρες «κλειστό» δεν μετράνε ως εκτός
    det = p.view(7, key="aa:00:00:00:00:02")["devices"][0]["list"]
    assert len(det) == 1 and det[0]["min"] == 15
    # επιμονή στον δίσκο
    p2 = presence.Presence(types.SimpleNamespace(lock=threading.RLock(), hosts={}), path=str(tmp_path / "p.sqlite"), clock=clk)
    assert p2.view(7)["devices"][0]["outages"] == 1


def test_ongoing_outage_and_retention():
    p, st, clk = make()
    host(st, "192.168.1.60", "", clk.t, dtype="phone", name="Κινητό")
    p.sample()
    clk.t += B
    st.hosts["192.168.1.60"]["last"] = 0
    for _ in range(3):
        p.sample()
        clk.t += B
    clk.t -= B
    d = p.view(1)["devices"][0]
    assert d["key"] == "ip:192.168.1.60" and not d["online"] and not d["always_on"] and d["outages"] == 1
    assert p.view(1, key=d["key"])["devices"][0]["list"][0]["end"] is None
    clk.t += 31 * 86400
    p.sample()
    assert p.db.execute("SELECT COUNT(*) FROM seen WHERE b<?", (int(clk.t // B) - 30 * 288,)).fetchone()[0] == 0


def test_demo_has_week_of_data():
    p = presence.Presence(types.SimpleNamespace(lock=threading.RLock(), hosts={}), sim=True)
    v = p.view(7)
    names = {d["name"]: d for d in v["devices"]}
    assert names["Router"]["pct"] == 100 and names["Κάμερα αυλής"]["outages"] > 0 and v["coverage"] < 100
    assert v["devices"][0]["always_on"] and len(v["devices"][0]["hours"]) == 168
