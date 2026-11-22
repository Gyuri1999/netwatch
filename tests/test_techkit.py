"""🧰 Δρομολογητής /api/kit/* — πραγματικός server, demo δεδομένα, χωρίς δίκτυο."""
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
import techkit  # noqa: E402


class Fake:
    def __init__(self):
        self.seen = []

    def api(self, method, sub, q, body):
        self.seen.append((method, sub, q, body))
        if sub == "boom":
            raise RuntimeError("x" * 500)
        if sub == "doc":
            return 200, {"_raw": "<h1>γεια</h1>", "_type": "text/html; charset=utf-8", "_name": "αναφορά 1.html"}
        if sub == "csv":
            return 200, {"_raw": b"a,b\n", "_type": "text/csv; charset=utf-8", "_name": "x.csv"}
        if sub == "bad":
            return "nope"
        return 200, {"ok": True, "sub": sub}

    def observe(self, P, t):
        self.seen.append(("obs", P["dp"]))
        raise ValueError("δεν πρέπει να φτάσει στο detect()")


class S:
    pass


def test_handle_routes_and_never_raises():
    st = S()
    st.ot = Fake()
    assert techkit.handle(st, "GET", "/api/kit/ot")[1] == {"ok": True, "sub": ""}
    assert techkit.handle(st, "POST", "/api/kit/ot/scan/", "a=1&a=2&b=x", {"k": 1}) == (200, {"ok": True, "sub": "scan"})
    assert st.ot.seen[-1] == ("POST", "scan", {"a": "1", "b": "x"}, {"k": 1})
    assert techkit.handle(st, "POST", "/api/kit/ot/x", "", ["όχι dict"])[0] == 200 and st.ot.seen[-1][3] == {}
    code, obj = techkit.handle(st, "GET", "/api/kit/ot/boom")
    assert code == 500 and len(obj["error"]) <= 200
    assert techkit.handle(st, "GET", "/api/kit/ot/bad")[0] == 500
    assert techkit.handle(st, "GET", "/api/kit/nope")[0] == 404
    assert techkit.handle(st, "GET", "/api/kit/../server")[0] == 404
    # module που δεν τρέχει (π.χ. pcap): το GET λέει «off» για να το δείξει το UI, το POST αρνείται
    assert techkit.handle(st, "GET", "/api/kit/v6") == (200, {"error": "off"})
    assert techkit.handle(st, "POST", "/api/kit/v6/check", "", {}) == (400, {"error": "off"})


def test_observe_swallows_module_errors():
    st = S()
    st.ot = Fake()
    techkit.observe(st, {"dp": 502}, 1.0)
    assert st.ot.seen == [("obs", 502)]


def test_setup_pcap_mode_disables_everything():
    st = S()
    techkit.setup(st, {}, "pcap", None)
    assert all(getattr(st, a) is None for a in techkit.NAMES.values())


@pytest.fixture
def api():
    import netwatch as nw
    st = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    techkit.setup(st, {}, "demo", None)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), nw.make_handler(st))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield st, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def test_every_module_has_a_demo_view(api):
    st, base = api
    for name, attr in techkit.NAMES.items():
        assert getattr(st, attr) is not None, name
        code, _, body = _get(f"{base}/api/kit/{name}")
        v = json.loads(body)
        assert code == 200 and v.get("demo") is True and not v.get("error"), (name, v.get("error"))
        code, _, _ = _get(f"{base}/api/kit/{name}/no-such-thing")
        assert code == 404, name


def test_documents_are_served_without_scripts(api):
    st, base = api
    st.ot = Fake()
    code, hd, body = _get(base + "/api/kit/ot/doc")
    assert code == 200 and body.decode() == "<h1>γεια</h1>" and hd["Content-Type"].startswith("text/html")
    assert "default-src 'none'" in hd["Content-Security-Policy"] and "script" not in hd["Content-Security-Policy"]
    assert hd["X-Content-Type-Options"] == "nosniff" and hd["Content-Disposition"].startswith("inline")
    assert '"' not in hd["Content-Disposition"].split('filename="')[1][:-1]  # καθαρό όνομα αρχείου
    code, hd, body = _get(base + "/api/kit/ot/csv")
    assert hd["Content-Disposition"] == 'attachment; filename="x.csv"' and body == b"a,b\n"


def test_post_needs_same_origin_json(api):
    st, base = api
    st.ot = Fake()
    req = urllib.request.Request(base + "/api/kit/ot/scan", data=b"{}", method="POST",
                                 headers={"Content-Type": "application/json", "Origin": "http://evil.example"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, timeout=10)
    assert e.value.code == 403
    req = urllib.request.Request(base + "/api/kit/ot/scan", data=b'{"a":1}', method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        assert json.load(r) == {"ok": True, "sub": "scan"}
