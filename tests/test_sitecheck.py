"""Tests για τον έλεγχο site (sitecheck.py) — fixtures, ψεύτικο Tor σε localhost, καθόλου πραγματικό δίκτυο."""
import gzip
import json
import os
import socket
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import sitecheck as sc  # noqa: E402

ONION = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"


def page(html, headers=(), status=200, url="https://www.example.com/", redirects=(), cookies=None):
    hs = [("content-type", "text/html; charset=utf-8")] + list(headers)
    return {"final_url": url, "status": status, "headers": hs, "body": html.encode(), "truncated": False,
            "redirects": list(redirects), "set_cookies": cookies if cookies is not None else [v for k, v in hs if k == "set-cookie"]}


def run(html="<p>hi</p>", via="tor:9150", **kw):
    checks, third, extra = sc.analyze(kw.get("url", "https://www.example.com/"), page(html, **kw), via, now=1_700_000_000)
    return {c["id"]: c for c in checks}, third, extra


TEXT = "<p>" + "Plenty of readable article text here. " * 20 + "</p>"


# ───────── URL ─────────
@pytest.mark.parametrize("bad", ["file:///etc/passwd", "ftp://example.com/", "javascript:alert(1)", "http://localhost/",
                                 "http://foo.localhost/", "http://192.168.1.1/", "https://10.0.0.5/", "http://127.0.0.1:8080/",
                                 "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://2130706433/",
                                 "http://0x7f.1/", "https://user:pw@example.com/", "https://user@example.com/",
                                 "http://printer.local/", "http://intranet/", "https://example.com:22/", "",
                                 "http://abc.onion/", "localhost:8080"])
def test_url_rejected(bad):
    with pytest.raises(sc.UrlError) as e:
        sc.normalize_url(bad)
    assert e.value.el and e.value.en


def test_url_normalized():
    assert sc.normalize_url("example.com") == ("https://example.com/", "example.com", False)
    assert sc.normalize_url("HTTP://Example.COM/a?b=1#frag") == ("http://example.com/a?b=1", "example.com", False)
    assert sc.normalize_url(ONION) == (f"http://{ONION}/", ONION, True)
    assert sc.normalize_url("https://example.com:8443/x")[0] == "https://example.com:8443/x"
    assert sc.normalize_url("http://93.184.216.34/")[1] == "93.184.216.34"


def test_registrable_domain():
    assert sc.registrable("a.b.example.com") == "example.com"
    assert sc.registrable("www.bbc.co.uk") == "bbc.co.uk"
    assert sc.registrable("www.gov.gr") == "www.gov.gr"
    assert sc.registrable("eody.gov.gr") == "eody.gov.gr"
    assert sc.registrable("news.in.gr") == "in.gr"
    assert sc.registrable("x.y.kathimerini.com.gr") == "kathimerini.com.gr"
    assert sc.registrable("alice.github.io") == "alice.github.io"
    assert sc.registrable("1.2.3.4") == "1.2.3.4"


# ───────── HTML / τρίτοι / trackers ─────────
def test_third_parties_parsed_and_classified():
    html = ("<html><head><script src='https://www.googletagmanager.com/gtag/js?id=G-1'></script>"
            "<script src='/static/app.js'></script><script src='https://cdn.example.com/x.js'></script>"
            "<link rel='stylesheet' href='https://fonts.googleapis.com/css'><link rel='dns-prefetch' href='//tracker.criteo.com'>"
            "<link rel='canonical' href='https://other.org/'>"
            "<script>var u='https://api.mixpanel.com/track';</script></head><body>" + TEXT +
            "<img src='https://pixel.quantserve.com/p.gif'><iframe src='https://www.youtube.com/embed/x'></iframe></body></html>")
    c, third, extra = run(html)
    kinds = {t["host"]: t["kind"] for t in third}
    assert kinds["www.googletagmanager.com"] == "tracker"
    assert kinds["tracker.criteo.com"] == "tracker" and kinds["pixel.quantserve.com"] == "tracker"
    assert kinds["api.mixpanel.com"] == "tracker"          # από inline script
    assert kinds["fonts.googleapis.com"] == "cdn"
    assert kinds["www.youtube.com"] == "embed"
    assert "cdn.example.com" not in kinds                  # ίδιος registrable domain
    assert "other.org" not in kinds                        # rel=canonical δεν φορτώνεται
    assert c["trackers"]["status"] == "bad" and len(c["trackers"]["who"]) == 4
    assert c["social"]["status"] == "warn"
    assert c["third_party"]["count"] == len(third)
    assert extra["trackers_count"] == 4


def test_session_replay_and_fingerprinting():
    html = ("<script src='https://static.hotjar.com/c/hotjar-1.js'></script>"
            "<script src='https://fpcdn.io/v3/key/loader.js'></script>" + TEXT)
    c, third, _ = run(html)
    assert c["session_replay"]["status"] == "bad" and c["session_replay"]["who"] == ["Hotjar"]
    assert c["fingerprinting"]["status"] == "bad" and "FingerprintJS" in c["fingerprinting"]["libs"]
    assert [t["kind"] for t in third] == ["replay", "fingerprint"]
    c, _, _ = run("<script>window.clarity=function(){};(function(){var s='https://www.clarity.ms/tag/abc'})()</script>" + TEXT)
    assert c["session_replay"]["who"] == ["Microsoft Clarity"]
    c, _, _ = run("<script>import('@fingerprintjs/fingerprintjs')</script>" + TEXT)
    assert c["fingerprinting"]["status"] == "bad"


def test_fingerprint_inline_heuristics_and_captcha():
    js = ("<script>var c=document.createElement('canvas');c.getContext('2d');c.toDataURL();"
          "var a=new AudioContext();a.createOscillator();gl.getExtension('WEBGL_debug_renderer_info')</script>")
    c, _, _ = run(js + TEXT)
    f = c["fingerprinting"]
    assert f["status"] == "warn" and "AudioContext" in f["heuristics"] and "canvas" in f["heuristics"]
    c, _, _ = run("<script src='https://www.google.com/recaptcha/api.js'></script><div class='g-recaptcha'></div>" + TEXT)
    assert c["fingerprinting"]["captcha"] == ["Google reCAPTCHA"] and c["fingerprinting"]["status"] == "warn"
    assert "Google" in c["fingerprinting"]["detail_en"]
    c, _, _ = run("<script>c.getContext('2d');var x=c.toDataURL()</script>" + TEXT)  # ένα ασθενές σήμα μόνο
    assert c["fingerprinting"]["status"] == "info" and c["fingerprinting"]["weight"] == 0


def test_akamai_cookie_counts_as_bot_manager():
    c, _, _ = run(TEXT, cookies=["_abck=ABCDEF0123456789~0~xyz; Path=/; Max-Age=31536000"])
    assert "Akamai Bot Manager" in c["fingerprinting"]["libs"]


def test_telemetry_is_info_not_tracker():
    c, third, _ = run("<script src='https://browser.sentry-cdn.com/7.0/bundle.min.js'></script>" + TEXT)
    assert c["telemetry"]["status"] == "info" and c["trackers"]["status"] == "ok"
    assert third[0]["kind"] == "telemetry"


# ───────── Tor blocking ─────────
def test_cloudflare_challenge_detected():
    html = "<html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={}</script></body></html>"
    c, _, extra = run(html, status=403, headers=[("server", "cloudflare"), ("cf-mitigated", "challenge")])
    assert c["tor_blocking"]["status"] == "warn" and c["tor_blocking"]["provider"] == "Cloudflare"
    assert extra["challenge"] == "Cloudflare" and "js_required" not in c
    c, _, _ = run(html, status=503, headers=[("server", "cloudflare"), ("cf-ray", "x")])
    assert c["tor_blocking"]["status"] == "warn"
    c, _, _ = run(TEXT, headers=[("server", "cloudflare"), ("cf-ray", "x")])
    assert c["tor_blocking"]["status"] == "ok" and "Cloudflare" in c["tor_blocking"]["detail_en"]


@pytest.mark.parametrize("status,headers,body,who", [
    (403, [("server", "AkamaiGHost")], "<h1>Access Denied</h1>Reference #18.abc", "Akamai"),
    (200, [], "<script src='/_Incapsula_Resource?x'></script>", "Imperva (Incapsula)"),
    (403, [("x-datadome", "protected")], "<script src='https://ct.captcha-delivery.com/c.js'></script>", "DataDome"),
    (403, [], "<div id='px-captcha'></div>", "PerimeterX (HUMAN)"),
    (403, [("x-sucuri-id", "1")], "Access Denied - Sucuri Website Firewall", "Sucuri"),
    (429, [], "Please complete the CAPTCHA", "captcha"),
])
def test_other_block_pages(status, headers, body, who):
    assert sc.detect_challenge(status, headers, body) == who


def test_no_false_challenge_on_normal_403():
    assert sc.detect_challenge(403, [("server", "nginx")], "<h1>Forbidden</h1>") is None


def test_direct_marks_tor_untested():
    c, _, _ = run(TEXT, via="direct")
    assert c["tor_blocking"]["status"] == "info"


# ───────── transport / onion-location / headers ─────────
def test_hsts_and_transport():
    c, _, _ = run(TEXT, headers=[("strict-transport-security", "max-age=63072000; includeSubDomains; preload")])
    assert c["transport"]["status"] == "ok" and c["transport"]["hsts"]["preload"]
    c, _, _ = run(TEXT, headers=[("strict-transport-security", "max-age=300")])
    assert c["transport"]["status"] == "warn"
    c, _, _ = run(TEXT)
    assert c["transport"]["status"] == "warn" and c["transport"]["hsts"]["max_age"] == 0
    c, _, _ = run(TEXT, url="http://www.example.com/")
    assert c["transport"]["status"] == "bad" and c["transport"]["weight"] == 25
    c, _, _ = run(TEXT, url="http://www.example.com/", redirects=[{"url": "https://www.example.com/", "status": 301}])
    assert c["transport"]["weight"] == 30 and "downgrade" in c["transport"]["title_en"]
    c, _, _ = run(TEXT, url=f"http://{ONION}/")
    assert c["transport"]["status"] == "ok" and "onion_location" not in c


def test_onion_location_header_and_meta():
    c, _, extra = run(TEXT, headers=[("onion-location", f"http://{ONION}/path")])
    assert c["onion_location"]["status"] == "ok" and extra["onion_location"] == f"http://{ONION}/path"
    c, _, extra = run(f"<meta http-equiv='onion-location' content='http://{ONION}/'>" + TEXT)
    assert extra["onion_location"] == f"http://{ONION}/"
    c, _, extra = run(TEXT, headers=[("onion-location", "https://not-an-onion.com/")])
    assert extra["onion_location"] is None and c["onion_location"]["status"] == "info"


def test_privacy_headers():
    c, _, _ = run(TEXT, headers=[("referrer-policy", "unsafe-url")])
    assert c["headers"]["status"] == "warn" and "FULL URL" in c["headers"]["detail_en"]
    c, _, _ = run(TEXT, headers=[("referrer-policy", "no-referrer"), ("content-security-policy", "default-src 'self'"),
                                 ("permissions-policy", "camera=()")])
    assert c["headers"]["status"] == "ok" and c["headers"]["permissions_policy"]


def test_mixed_content():
    c, _, _ = run("<script src='http://cdn.other.net/x.js'></script>" + TEXT)
    assert c["mixed_content"]["status"] == "warn" and c["mixed_content"]["weight"] == 10
    c, _, _ = run("<img src='http://img.other.net/x.png'>" + TEXT)
    assert c["mixed_content"]["weight"] == 4
    c, _, _ = run("<img src='http://img.other.net/x.png'>" + TEXT, url="http://www.example.com/")
    assert "mixed_content" not in c


# ───────── cookies / JS / WebRTC ─────────
def test_cookie_analysis():
    cookies = ["_ga=GA1.2.1873462910.1731990000; Max-Age=63072000; Path=/; SameSite=None; Secure",
               "sess=1; Path=/; HttpOnly", "uid=8a7f6e5d4c3b2a190807; Expires=Wed, 01 Jan 2099 00:00:00 GMT"]
    c, _, _ = run(TEXT, cookies=cookies)
    ck = c["cookies"]
    assert ck["status"] == "warn" and ck["weight"] == 8
    by = {x["name"]: x for x in ck["cookies"]}
    assert by["_ga"]["tracking"] and by["_ga"]["samesite_none"] and by["_ga"]["days"] == 730
    assert not by["sess"]["tracking"] and by["uid"]["tracking"]
    c, _, _ = run(TEXT, cookies=["sess=1; Path=/; HttpOnly"])
    assert c["cookies"]["status"] == "info" and c["cookies"]["weight"] == 2
    c, _, _ = run(TEXT, cookies=[])
    assert c["cookies"]["status"] == "ok"


def test_js_required_and_webrtc():
    c, _, _ = run("<div id='root'></div><script src='/app.js'></script>")
    assert c["js_required"]["status"] == "info" and "Safest" in c["js_required"]["detail_en"]
    c, _, _ = run(TEXT + "<noscript>Please enable JavaScript to use this site</noscript><script></script>")
    assert c["js_required"]["status"] == "info"
    c, _, _ = run(TEXT)
    assert c["js_required"]["status"] == "ok" and "webrtc" not in c
    c, _, _ = run(TEXT + "<script>new RTCPeerConnection({iceServers:[]})</script>")
    assert c["webrtc"]["status"] == "warn"


def test_social_login():
    c, _, _ = run("<script src='https://accounts.google.com/gsi/client'></script>"
                  "<script src='https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js'></script>" + TEXT)
    assert set(c["social"]["who"]) == {"Google Sign-In", "Sign in with Apple"}


# ───────── βαθμός ─────────
def test_scoring_and_grades():
    assert [sc.grade_for(s) for s in (100, 90, 89, 75, 74, 60, 59, 40, 39, 0)] == list("AABBCCDDFF")
    assert sc.score_result([{"weight": 30}, {"weight": 90}]) == (0, "F")
    clean = [c for c in run(TEXT, headers=[("strict-transport-security", "max-age=31536000"), ("referrer-policy", "no-referrer"),
                                           ("content-security-policy", "x")])[0].values()]
    assert sc.score_result(clean) == (100, "A")


def test_advice_bilingual():
    checks, _, extra = sc.analyze("https://x.com/", page("<script src='https://static.hotjar.com/h.js'></script>" + TEXT,
                                                         headers=[("onion-location", f"http://{ONION}/")]), "direct")
    el, en = sc.advice(checks, extra, False, "direct")
    assert len(el) == len(en) >= 4
    assert any(ONION in a for a in en) and any("uBlock" in a for a in en) and any("without Tor" in a for a in en)
    assert any("log in" in a for a in en)


# ───────── HTTP parsing ─────────
def test_parse_response_chunked_gzip_and_cap():
    body = gzip.compress(b"<p>hello</p>")
    chunked = b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
    raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n"
           b"Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n" + chunked)
    st, hs, b, trunc = sc.parse_response(raw)
    assert st == 200 and b == b"<p>hello</p>" and not trunc
    assert [v for k, v in hs if k == "set-cookie"] == ["a=1", "b=2"]
    st, _, b, trunc = sc.parse_response(b"HTTP/1.0 200 OK\r\n\r\n" + b"x" * 100, cap=10)
    assert b == b"x" * 10 and trunc
    with pytest.raises(sc.FetchError):
        sc.parse_response(b"garbage")


# ───────── ψεύτικο Tor: SOCKS5 → τοπικός HTTP server (ανακατεύθυνση + αίτημα χωρίς cookies) ─────────
def test_fetch_through_fake_tor_follows_redirect():
    seen = []

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            seen.append({"path": self.path, "host": self.headers.get("Host"), "ua": self.headers.get("User-Agent"),
                         "cookie": self.headers.get("Cookie"), "lang": self.headers.get("Accept-Language")})
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/final")
                self.send_header("Set-Cookie", "first=1; Max-Age=60")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"<html><body>" + b"<p>content</p>" * 30 + b"</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n")

        def log_message(self, *a):
            pass

    web = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(4)
    targets = []

    def socks():
        while True:
            try:
                c, _ = lsock.accept()
            except OSError:
                return
            c.recv(3)
            c.sendall(b"\x05\x00")
            head = c.recv(4)
            n = c.recv(1)[0]
            targets.append((head[3], c.recv(n).decode(), int.from_bytes(c.recv(2), "big")))
            up = socket.create_connection(web.server_address)
            c.sendall(b"\x05\x00\x00\x01" + bytes(4) + b"\x00\x00")

            def pump(a, b):
                try:
                    while True:
                        d = a.recv(65536)
                        if not d:
                            break
                        b.sendall(d)
                except OSError:
                    pass
                finally:
                    try:
                        b.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
            threading.Thread(target=pump, args=(c, up), daemon=True).start()
            threading.Thread(target=pump, args=(up, c), daemon=True).start()

    threading.Thread(target=socks, daemon=True).start()
    conn = sc.tor_connector(lsock.getsockname()[1])
    try:
        f = sc.fetch("http://site.example/start", "tor:9150", conn, timeout=10)
    finally:
        web.shutdown()
        lsock.close()
    assert f["status"] == 200 and f["final_url"] == "http://site.example/final"
    assert f["redirects"] == [{"url": "http://site.example/start", "status": 302}]
    assert f["set_cookies"] == ["first=1; Max-Age=60"] and b"content" in f["body"]
    assert targets[0] == (3, "site.example", 80)          # το όνομα επιλύεται ΜΕΣΑ στο Tor
    assert all(s["cookie"] is None for s in seen)          # ποτέ cookies (ούτε αυτό που μόλις πήραμε)
    assert seen[0]["ua"] == sc.UA and seen[0]["lang"].startswith("en-US")


def test_redirect_to_private_rejected():
    def fake_get(url, connect, timeout=None, cap=None):
        return 302, [("location", "http://192.168.1.1/admin")], b"", False
    orig = sc.http_get
    sc.http_get = fake_get
    try:
        with pytest.raises(sc.UrlError):
            sc.fetch("https://evil.example/", "tor:9150", None)
    finally:
        sc.http_get = orig


def test_too_many_redirects():
    def fake_get(url, connect, timeout=None, cap=None):
        return 301, [("location", "/again")], b"", False
    orig = sc.http_get
    sc.http_get = fake_get
    try:
        with pytest.raises(sc.FetchError):
            sc.fetch("https://loop.example/", "tor:9150", None)
    finally:
        sc.http_get = orig


def test_direct_connector_refuses_private_resolution(monkeypatch):
    monkeypatch.setattr(sc.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.7", 443))])
    with pytest.raises(sc.UrlError):
        sc.direct_connector()("rebind.example", 443, 5)


# ───────── runner: Tor/direct, rate limit, cache ─────────
class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def make(**kw):
    calls = []

    def fetcher(url, via):
        calls.append((url, via))
        return page(TEXT, url=url, headers=[("strict-transport-security", "max-age=31536000")])
    clock = Clock()
    args = dict(clock=clock, fetcher=fetcher, tor_probe=lambda: 9150, background=False)
    args.update(kw)
    return sc.SiteCheck(**args), clock, calls


def test_needs_tor_and_direct():
    s, clock, calls = make(tor_probe=lambda: None)
    r = s.start("https://example.com/")
    assert r["needs_tor"] and r["note_el"] and r["note_en"] and not calls
    r = s.start(ONION, direct=True)
    assert r["needs_tor"] and r["onion"] and not calls      # .onion ποτέ απευθείας
    r = s.start("https://example.com/", direct=True)
    assert r["ok"] and calls == [("https://example.com/", "direct")]
    res = s.get(r["id"])
    assert res["via"] == "direct" and res["grade"] and any("without Tor" in a for a in res["advice_en"])


def test_via_tor_port_and_result_shape():
    s, clock, calls = make(tor_probe=lambda: 9050)
    r = s.start("example.com", lang="en")
    res = s.get(r["id"])
    for k in ("id", "url", "final_url", "host", "onion", "via", "status", "fetched_at", "ms", "grade", "score", "verdict_el",
              "verdict_en", "checks", "third_party", "trackers_count", "onion_location", "advice_el", "advice_en"):
        assert k in res, k
    assert res["via"] == "tor:9050" and not res["running"]
    for c in res["checks"]:
        assert set(c) >= {"id", "status", "title_el", "title_en", "detail_el", "detail_en", "weight"}
        assert c["status"] in ("ok", "warn", "bad", "info")


def test_rate_limit_and_cache():
    s, clock, calls = make()
    assert s.start("https://a.example/")["ok"]
    r = s.start("https://b.example/")
    assert r["code"] == 429 and r["retry_in"] > 0
    clock.t += 1
    r = s.start("https://a.example/")                      # cache: χωρίς νέα λήψη, χωρίς rate limit
    assert r["cached"] and r["result"]["url"] == "https://a.example/" and len(calls) == 1
    clock.t += 5
    assert s.start("https://b.example/")["ok"] and len(calls) == 2
    clock.t += 601
    assert s.start("https://a.example/")["ok"] and len(calls) == 3   # έληξε η cache


def test_errors_not_cached_and_bad_url():
    def boom(url, via):
        raise sc.FetchError("λάθος", "boom")
    s, clock, _ = make(fetcher=boom)
    rid = s.start("https://x.example/")["id"]
    assert s.get(rid)["error_en"] == "boom" and "grade" not in s.get(rid)
    clock.t += 6
    assert not s.start("https://x.example/").get("cached")
    r = s.start("file:///etc/passwd", lang="en")
    assert r["code"] == 400 and "http" in r["error"]


def test_history_capped_and_view():
    s, clock, _ = make()
    ids = []
    for i in range(13):
        clock.t += 6
        ids.append(s.start(f"https://s{i}.example/")["id"])
    v = s.view()
    assert len(v["history"]) == 10 and v["history"][0]["id"] == ids[-1] and v["latest"]["id"] == ids[-1]
    assert "checks" not in v["history"][0] and s.get(ids[0]) is None
    assert v["tor"] == 9150 and not v["running"]


def test_background_running_state():
    gate = threading.Event()

    def slow(url, via):
        gate.wait(5)
        return page(TEXT, url=url)
    s, clock, _ = make(fetcher=slow, background=True)
    r = s.start("https://slow.example/")
    assert r["running"] and s.get(r["id"])["running"] and s.view()["running"]
    clock.t += 10
    assert s.start("https://other.example/")["code"] == 429  # ένας έλεγχος τη φορά
    gate.set()
    for _ in range(100):
        if not s.get(r["id"])["running"]:
            break
        threading.Event().wait(0.02)
    assert s.get(r["id"])["grade"]


# ───────── demo ─────────
def test_demo_shapes_and_grades():
    s = sc.SiteCheck(sim=True, sim_delay=0, background=False, min_interval=0)
    want = {"https://dailynews.example.com/": "D", "duckduckgo.com": "A", ONION: "A", "shop.example.gr": "C",
            "example.org": "B"}
    for url, g in want.items():
        res = s.get(s.start(url)["id"])
        assert res["grade"] == g, (url, res["score"])
        assert res["demo"] and res["via"] == "tor:9150"
    news = s.get(s.start("https://times.example/")["id"])
    kinds = {t["kind"] for t in news["third_party"]}
    assert {"tracker", "replay", "fingerprint", "cdn"} <= kinds
    ddg = s.get(s.start("https://duckduckgo.com/x")["id"])
    assert ddg["onion_location"].startswith("https://duckduckgogg42") and ddg["advice_en"][0].startswith("Use the onion")
    shop = s.get(s.start("https://myshop.example/")["id"])
    assert shop["challenge"] == "Cloudflare" and shop["partial"]


def test_demo_never_touches_network(monkeypatch):
    def nope(*a, **k):
        raise AssertionError("network!")
    monkeypatch.setattr(sc.socket, "create_connection", nope)
    monkeypatch.setattr(sc.socket, "getaddrinfo", nope)
    s = sc.SiteCheck(sim=True, sim_delay=0, background=False)
    assert s.get(s.start("http://news.example/")["id"])["grade"]
    assert s.view()["tor"] == 9150


# ───────── HTTP API ─────────
@pytest.fixture
def api():
    import netwatch as nw
    st = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    st.sitecheck = sc.SiteCheck(sim=True, sim_delay=0)
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


def test_api_routes(api):
    st, base = api
    code, v = _req(base + "/api/sitecheck")
    assert code == 200 and v["history"] == [] and v["demo"]
    code, r = _req(base + "/api/sitecheck", {"url": "https://dailynews.example.com/"})
    assert code == 200 and r["ok"] and r["id"]
    for _ in range(100):
        code, res = _req(base + "/api/sitecheck?id=" + r["id"])
        if not res.get("running"):
            break
        threading.Event().wait(0.02)
    assert code == 200 and res["grade"] == "D"
    code, r2 = _req(base + "/api/sitecheck", {"url": "https://other.example/"})
    assert code == 429 and r2["retry_in"] > 0
    code, r3 = _req(base + "/api/sitecheck", {"url": "https://dailynews.example.com/"})
    assert code == 200 and r3["cached"]
    code, r4 = _req(base + "/api/sitecheck", {"url": "http://192.168.1.1/"})
    assert code == 400 and r4["error_en"]
    code, _ = _req(base + "/api/sitecheck", {"url": "https://a.example/"}, headers={"Content-Type": "text/plain"})
    assert code == 403
    code, v = _req(base + "/api/sitecheck")
    assert v["latest"]["grade"] == "D" and len(v["history"]) == 1
    code, _ = _req(base + "/api/sitecheck?id=nope")
    assert code == 404
    st.sitecheck = None
    code, v = _req(base + "/api/sitecheck")
    assert code == 200 and v["off"]
    code, _ = _req(base + "/api/sitecheck", {"url": "https://a.example/"})
    assert code == 400
