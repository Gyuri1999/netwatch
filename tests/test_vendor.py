"""📦 Βιβλιοθήκες & χάρτης μαζί με την εφαρμογή: τίποτα από CDN, ο χάρτης δουλεύει χωρίς Internet."""
import base64
import glob
import hashlib
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

# Τα αποτυπώματα που δημοσιεύονται για αυτές ακριβώς τις εκδόσεις (d3 7.9.0 · topojson-client 3.1.0 · world-atlas 2.0.2)
PINNED = {"d3.min.js": "8glLv2FBs1lyLE/kVOtsSw8OQswQzHr5IfwVj864ZTk=",
          "topojson-client.min.js": "Jc0CrkhsxQY+AhWk5M+xXeg3AMh6xIusTVfcaq8+u4k=",
          "countries-110m.json": "JRbJFYZ8e68Y3exyeuxGwxVUGgfPs9eaZVmwXV6U7ug=",
          "countries-50m.json": "BDQs3B4wFrzX2xYw3pVoTWe3n+PIxGAyHoeu9GlQI5Q="}


def _read(*p):
    return open(os.path.join(ROOT, *p), encoding="utf-8").read()


def test_vendor_files_are_exactly_the_published_ones():
    for name, want in PINNED.items():
        data = open(os.path.join(ROOT, "vendor", name), "rb").read()
        assert base64.b64encode(hashlib.sha256(data).digest()).decode() == want, f"το vendor/{name} άλλαξε"
    assert set(PINNED) == {f for f in os.listdir(os.path.join(ROOT, "vendor")) if not f.endswith((".md", ".txt"))}
    assert "ISC License" in _read("vendor", "LICENSES.txt")


def test_nothing_is_loaded_from_a_cdn():
    """Η εφαρμογή λέει «τίποτα δεν φεύγει από τον υπολογιστή σου»: καμία σελίδα/script δεν ζητά κώδικα ή χάρτη από έξω."""
    pages = ["index.html", "academy.html", "sw.js"] + [os.path.basename(p) for p in glob.glob(os.path.join(ROOT, "*.js"))]
    for name in pages:
        s = _read(name)
        assert "cdn.jsdelivr.net" not in s and "unpkg.com" not in s and "cdnjs.cloudflare.com" not in s, name
    html = _read("index.html")
    assert '<script src="vendor/d3.min.js"></script>' in html and '<script src="vendor/topojson-client.min.js"></script>' in html
    assert "fetch('vendor/countries-110m.json')" in html and "fetch('vendor/countries-50m.json')" in html


def test_every_package_ships_the_vendor_folder():
    assert " vendor " in _read("macapp", "build.sh")                       # εφαρμογή Mac
    assert "COPY vendor ./vendor" in _read("Dockerfile")                   # Docker
    assert "(i18n|vendor|academy" in _read("winapp", "build.ps1")          # εφαρμογή Windows
    assert '"vendor"' in _read("tools", "build_static_demo.py")            # online demo


@pytest.fixture
def base():
    import netwatch as nw
    st = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), nw.make_handler(st))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_server_serves_only_the_known_vendor_files(base):
    for name, want in PINNED.items():
        with urllib.request.urlopen(f"{base}/vendor/{name}", timeout=10) as r:
            body = r.read()
            assert r.status == 200 and base64.b64encode(hashlib.sha256(body).digest()).decode() == want
            assert ("javascript" if name.endswith(".js") else "json") in r.headers["Content-Type"]
    assert len(json.loads(urllib.request.urlopen(f"{base}/vendor/countries-110m.json", timeout=10).read())["objects"]["countries"]["geometries"]) == 177
    for bad in ("README.md", "LICENSES.txt", "../server.py", "..%2Fserver.py", "d3.min.js/../../config.yaml", "nope.js"):
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(f"{base}/vendor/{bad}", timeout=10)
        assert e.value.code == 404, bad
