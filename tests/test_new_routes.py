"""HTTP routes για ενημερώσεις, L2 guard και διαθεσιμότητα — πραγματικός server, demo δεδομένα, χωρίς δίκτυο."""
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


@pytest.fixture
def api():
    import l2guard
    import netwatch as nw
    import presence
    import updater
    st = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    st.updater = updater.Updater(st, sim=True)
    st.l2guard = l2guard.L2Guard(st, sim=True)
    st.presence = presence.Presence(st, sim=True)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), nw.make_handler(st))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield st, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _req(url, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET",
                                 headers=headers if headers is not None else {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_presence_routes(api):
    _, base = api
    code, v = _req(base + "/api/presence?days=7")
    assert code == 200 and v["days"] == 7 and v["devices"]
    k = v["devices"][0]["key"]
    code, v = _req(base + f"/api/presence?days=abc&key={k}")
    assert code == 200 and v["days"] == 7 and len(v["devices"]) == 1 and "list" in v["devices"][0]


def test_l2guard_routes(api):
    _, base = api
    code, v = _req(base + "/api/l2guard")
    assert code == 200 and v.get("never")
    code, r = _req(base + "/api/l2guard/run", {})
    assert code == 200 and r["verdict"] == "bad" and len(r["offers"]) == 2
    code, r = _req(base + "/api/l2guard/run", {}, headers={"Content-Type": "text/plain"})
    assert code == 403


def test_update_routes(api):
    _, base = api
    code, v = _req(base + "/api/update")
    assert code == 200 and v["kind"] == "app"
    code, v = _req(base + "/api/update/check", {})
    assert code == 200 and v["available"]
    code, r = _req(base + "/api/update/install", {}, headers={"Content-Type": "text/plain"})
    assert code == 403


def test_snapshot_reports_host_for_golive_hint():
    import detect
    h = detect.host_info()
    assert h["os"] and isinstance(h["docker"], bool)
    assert ("npcap" in h) == (h["os"] == "win32")


def test_app_mode_route_only_with_windows_launcher(api, tmp_path):
    st, base = api
    st.app_ctl = None
    code, r = _req(base + "/api/app/mode", {"mode": "live"})
    assert code == 400
    st.app_ctl = str(tmp_path)
    code, r = _req(base + "/api/app/mode", {"mode": "rm -rf"})
    assert code == 400
    code, r = _req(base + "/api/app/mode", {"mode": "live"}, headers={"Content-Type": "text/plain"})
    assert code == 403
    code, r = _req(base + "/api/app/mode", {"mode": "live-admin"})
    assert code == 200 and r["ok"]
    with open(tmp_path / "mode-request.json", encoding="utf-8") as f:
        assert json.load(f)["mode"] == "live-admin"
