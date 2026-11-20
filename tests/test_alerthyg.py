"""🔕 σίγαση με λήξη, θόρυβος, 🧐 «γιατί χτύπησε;» — μονάδα + πραγματικός HTTP server."""
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import alerthyg  # noqa: E402
import netwatch as nw  # noqa: E402


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def _state():
    st = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    st.cfg["thresholds"]["alert_cooldown"] = 0
    return st


def test_mute_hides_from_notifications_but_keeps_alert(tmp_path):
    st = _state()
    clk = Clock()
    st.hygiene = alerthyg.AlertHygiene(st, path=str(tmp_path / "mutes.json"), clock=clk)
    sent = []
    st.notifier = sent.append
    st.alert("Port scan", "med", "192.168.1.50", "192.168.1.23", "20 θύρες", clk())
    assert len(sent) == 1
    r = st.hygiene.mute("Port scan", "192.168.1.50", minutes=60, note="Fing στο κινητό")
    assert r["ok"]
    st.alert("Port scan", "med", "192.168.1.50", "192.168.1.23", "20 θύρες", clk() + 1)
    assert len(sent) == 1                         # δεν ξαναστάλθηκε
    a = st.alerts[0]
    assert a["benign"].startswith("🔕") and "Fing" in a["benign"]
    st.alert("Port scan", "med", "192.168.1.51", "192.168.1.23", "x", clk() + 2)
    assert len(sent) == 2                         # άλλη συσκευή → κανονικά
    # λήξη
    clk.t += 3601
    st.alert("Port scan", "med", "192.168.1.50", "192.168.1.23", "x", clk())
    assert len(sent) == 3 and not st.hygiene.mutes
    # επιμένει στον δίσκο
    st.hygiene.mute(None, "192.168.1.60", minutes=0)
    again = alerthyg.AlertHygiene(st, path=str(tmp_path / "mutes.json"), clock=clk)
    assert again.match("Οτιδήποτε", "192.168.1.60") and again.mutes[0]["until"] is None


def test_mute_validation():
    h = alerthyg.AlertHygiene(_state())
    assert h.mute(None, None)["error"]
    assert h.mute("X", "not-an-ip")["error"]
    assert h.mute("X", None, minutes=-5)["error"]
    assert h.mute("X", None, minutes="abc")["error"]
    m = h.mute("X", None, minutes=10)["mute"]
    assert h.mute("X", None, minutes=20)["mute"]["id"] == m["id"] and len(h.mutes) == 1  # ανανέωση, όχι διπλή
    assert h.unmute(m["id"])["ok"] and h.unmute(m["id"])["error"]


def test_why_and_noise():
    st = _state()
    st.hygiene = alerthyg.AlertHygiene(st)
    import time
    t = time.time()
    for i in range(5):
        st.alert("Port scan", "med", "192.168.1.50", "192.168.1.23", "θύρες", t + i)
    st.alert("Νέα συσκευή", "low", "192.168.1.77", "192.168.1.1", "νέα MAC", t + 6)
    aid = st.alerts[1]["id"]  # το τελευταίο Port scan
    w = st.hygiene.why(aid)
    assert w["detector"] == "port_scan" and w["thresholds"]["port_scan"]["count"] > 0
    assert w["how"]["el"] and w["fp"]["en"] and w["mitre"]["id"] == "T1046"
    assert w["freq"]["same_7d"] == 5 and w["pattern"] == "repeat"
    assert w["target"]["ip"] == "192.168.1.23"
    assert any(r["type"] == "Port scan" for r in w["related"])
    assert st.hygiene.why(999999)["error"]
    n = st.hygiene.noise(24)
    assert n["total"] == 6 and n["types"][0]["type"] == "Port scan" and n["types"][0]["count"] == 5
    assert n["types"][0]["top"][0]["actor"] == "192.168.1.50"


def _req(url, body=None, ctype="application/json"):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET", headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_routes():
    st = _state()
    st.hygiene = alerthyg.AlertHygiene(st)
    import time
    st.alert("Port scan", "med", "192.168.1.50", "192.168.1.23", "θύρες", time.time())
    srv = ThreadingHTTPServer(("127.0.0.1", 0), nw.make_handler(st))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        aid = st.alerts[0]["id"]
        code, w = _req(base + f"/api/alerts/why?id={aid}")
        assert code == 200 and w["detector"] == "port_scan"
        assert _req(base + "/api/alerts/why?id=abc")[0] == 400
        assert _req(base + "/api/alerts/why?id=424242")[0] == 404
        code, r = _req(base + "/api/alerts/mute", {"type": "Port scan", "actor": "192.168.1.50", "minutes": 60})
        assert code == 200 and r["ok"]
        assert _req(base + "/api/alerts/mute", {"type": "Port scan"}, ctype="text/plain")[0] == 403
        assert _req(base + "/api/alerts/mute", {"actor": "1.2.3"})[0] == 400
        code, v = _req(base + "/api/alerts/hygiene")
        assert code == 200 and len(v["mutes"]) == 1 and v["noise"]["types"][0]["type"] == "Port scan"
        code, r = _req(base + "/api/alerts/unmute", {"id": v["mutes"][0]["id"]})
        assert code == 200 and r["ok"]
    finally:
        srv.shutdown()


def test_every_known_alert_type_has_a_specific_explanation():
    """Κάθε τύπος που παράγει το NetWatch (core.MITRE + τα άλλα modules) έχει δική του εξήγηση, όχι τη γενική."""
    from core import MITRE
    types = [m[0] for m in MITRE] + [p[0] for p in alerthyg.PREFIX_INFO] + ["Κανόνας: Telnet", "Port scan (UDP)",
                                                                           "Network sweep (ARP)", "Beaconing (πιθανό C2)"]
    st = _state()
    st.hygiene = alerthyg.AlertHygiene(st)
    import time
    missing = []
    for i, ty in enumerate(types):
        st.alert(ty, "low", f"192.168.1.{100 + i % 100}", "192.168.1.1", "x", time.time() + i)
        w = st.hygiene.why(st.alerts[0]["id"])
        if w["how"]["el"] == alerthyg.GENERIC[0]:
            missing.append(ty)
    assert not missing, missing
