import json

import pytest

import dnsfilter
from dnsfilter import DnsFilter, check_url, parse_adguard, parse_pihole5, parse_pihole6

SECRET = "s3cr3t-P@ss"


class St:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, detail, kw))


V6_SUMMARY = {"queries": {"total": 18234, "blocked": 4012, "percent_blocked": 22.0028, "unique_domains": 2100,
                          "forwarded": 9000, "cached": 5000},
              "clients": {"active": 9, "total": 14}, "gravity": {"domains_being_blocked": 187342, "last_update": 1700000000}}
V6_TOP_BLOCKED = {"domains": [{"domain": "doubleclick.net", "count": 912}, {"domain": "app-measurement.com", "count": 744}],
                  "total_queries": 18234, "blocked_queries": 4012}
V6_TOP_CLIENTS = {"clients": [{"ip": "192.168.1.23", "name": "laptop.lan", "count": 4210},
                              {"ip": "192.168.1.41", "name": "", "count": 3388}]}
V6_CLIENTS_BLOCKED = {"clients": [{"ip": "192.168.1.41", "name": "", "count": 1460}]}
V6_BLOCKING = {"blocking": "enabled", "timer": None}
V6_UPSTREAMS = {"upstreams": [{"ip": "1.1.1.1", "name": "one.one.one.one", "port": 53, "count": 7200},
                              {"ip": "127.0.0.1", "name": "localhost", "port": 5335, "count": 100}]}

V5 = {"domains_being_blocked": 120000, "dns_queries_today": 15000, "ads_blocked_today": 3000, "ads_percentage_today": 20.0,
      "unique_clients": 7, "status": "disabled",
      "top_queries": {"example.com": 50}, "top_ads": {"graph.facebook.com": 503, "doubleclick.net": 912},
      "top_sources": {"laptop.lan|192.168.1.23": 4210, "192.168.1.30": 2874},
      "forward_destinations": {"blocked|blocked": 20.0, "one.one.one.one#53|1.1.1.1#53": 55.5}}

AG_STATS = {"time_units": "hours", "num_dns_queries": 20000, "num_blocked_filtering": 4000, "num_replaced_safebrowsing": 10,
            "num_replaced_parental": 0, "avg_processing_time": 0.0123,
            "top_queried_domains": [{"example.com": 99}],
            "top_blocked_domains": [{"doubleclick.net": 900}, {"app-measurement.com": 700}],
            "top_clients": [{"192.168.1.23": 5000}, {"192.168.1.41": 3000}],
            "top_upstreams_responses": [{"https://dns.quad9.net:443/dns-query": 8000}],
            "top_upstreams_avg_time": [{"https://dns.quad9.net:443/dns-query": 0.02}]}
AG_STATUS = {"protection_enabled": True, "running": True, "version": "v0.107.52", "dns_port": 53}


def test_parse_v6():
    r = parse_pihole6(V6_SUMMARY, V6_TOP_BLOCKED, V6_TOP_CLIENTS, V6_BLOCKING, V6_UPSTREAMS, V6_CLIENTS_BLOCKED)
    assert (r["queries_today"], r["blocked_today"], r["blocked_pct"]) == (18234, 4012, 22.0)
    assert r["top_blocked"][0] == {"domain": "doubleclick.net", "count": 912}
    assert r["top_clients"][1] == {"client": "192.168.1.41", "name": None, "count": 3388, "blocked": 1460}
    assert r["status"] == "enabled" and r["domains_blocked"] == 187342
    assert [u["upstream"] for u in r["upstreams"]] == ["one.one.one.one", "localhost#5335"]


def test_parse_v5():
    r = parse_pihole5(V5)
    assert (r["queries_today"], r["blocked_today"], r["blocked_pct"], r["status"]) == (15000, 3000, 20.0, "disabled")
    assert [d["domain"] for d in r["top_blocked"]] == ["doubleclick.net", "graph.facebook.com"]
    assert r["top_clients"][0] == {"client": "192.168.1.23", "name": "laptop.lan", "count": 4210, "blocked": None}
    assert r["top_clients"][1]["client"] == "192.168.1.30"
    assert r["upstreams"][0]["pct"] == 55.5


def test_parse_adguard():
    r = parse_adguard(AG_STATS, AG_STATUS)
    assert (r["queries_today"], r["blocked_today"], r["blocked_pct"], r["status"]) == (20000, 4010, 20.1, "enabled")
    assert r["top_blocked"][1] == {"domain": "app-measurement.com", "count": 700}
    assert r["top_clients"][0]["client"] == "192.168.1.23" and r["upstreams"][0]["avg_ms"] == 20.0
    assert r["avg_ms"] == 12.3 and r["version"] == "v0.107.52"
    assert parse_adguard(AG_STATS, dict(AG_STATUS, protection_enabled=False))["status"] == "disabled"


@pytest.mark.parametrize("url", ["http://8.8.8.8", "https://1.1.1.1:8443/admin", "ftp://192.168.1.2", "file:///etc/passwd",
                                 "http://user:pw@192.168.1.2", "192.168.1.2", "http://[2001:4860:4860::8888]/"])
def test_refuses_bad_urls(url):
    with pytest.raises(ValueError):
        check_url(url)
    d = DnsFilter(None, {"type": "pihole", "url": url, "password": SECRET}, fetch=lambda *a: pytest.fail("no request"))
    d.poll()
    s = d.status()
    assert s["error"] and SECRET not in json.dumps(s)


@pytest.mark.parametrize("url,base", [("http://192.168.1.2/", "http://192.168.1.2"), ("https://pi.hole:8443", "https://pi.hole:8443"),
                                      ("http://10.0.0.5/adguard/", "http://10.0.0.5/adguard"), ("http://[fd00::2]", "http://[fd00::2]")])
def test_accepts_private_urls(url, base):
    assert check_url(url)[0] == base


class Fake:
    """Ψεύτικος server: path → (status, json). Καταγράφει τα αιτήματα."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, method, url, data, headers, verify):
        self.calls.append((method, url, data, dict(headers)))
        path = url.split("192.168.1.2", 1)[1]
        r = self.routes.get((method, path.split("&count")[0])) or self.routes.get((method, path))
        if r is None:
            return 404, b""
        st, body = r(headers) if callable(r) else r
        return st, json.dumps(body).encode() if body is not None else b""


def v6_routes(blocking="enabled"):
    def auth_needed(body):
        return lambda h: (200, body) if h.get("X-FTL-SID") == "SID1" else (401, {"error": {"key": "unauthorized"}})
    return {("POST", "/api/auth"): (200, {"session": {"valid": True, "sid": "SID1", "validity": 1800}}),
            ("GET", "/api/stats/summary"): auth_needed(V6_SUMMARY),
            ("GET", "/api/stats/top_domains?blocked=true"): auth_needed(V6_TOP_BLOCKED),
            ("GET", "/api/stats/top_clients?count=10"): auth_needed(V6_TOP_CLIENTS),
            ("GET", "/api/stats/top_clients?blocked=true"): auth_needed(V6_CLIENTS_BLOCKED),
            ("GET", "/api/dns/blocking"): auth_needed({"blocking": blocking, "timer": None}),
            ("GET", "/api/stats/upstreams"): auth_needed(V6_UPSTREAMS)}


def test_pihole6_poll_auth_and_password_never_in_status():
    f = Fake(v6_routes())
    st = St()
    d = DnsFilter(st, {"type": "pihole", "url": "http://192.168.1.2", "password": SECRET}, fetch=f)
    d.poll(1000.0)
    s = d.status()
    assert s["version"] == 6 and s["queries_today"] == 18234 and s["status"] == "enabled" and s["error"] is None
    assert s["top_clients"][1]["blocked"] == 1460 and len(s["history"]) == 1
    assert SECRET not in json.dumps(s)
    # ο κωδικός πάει μόνο στο POST /api/auth, και μόνο εκεί
    sent = [c for c in f.calls if SECRET in json.dumps([c[1], c[2].decode() if c[2] else "", c[3]])]
    assert [(c[0], c[1]) for c in sent] == [("POST", "http://192.168.1.2/api/auth")]
    n_auth = len(sent)
    d.poll(1060.0)  # το sid ξαναχρησιμοποιείται
    assert sum(1 for c in f.calls if c[1].endswith("/api/auth")) == n_auth
    assert st.alerts == []


def test_pihole_disabled_alert_once_and_down_after_3():
    f = Fake(v6_routes("disabled"))
    st = St()
    d = DnsFilter(st, {"type": "pihole", "url": "http://192.168.1.2", "password": SECRET}, fetch=f)
    d.poll(1000.0)
    d.poll(1060.0)
    assert [a[0] for a in st.alerts] == [dnsfilter.T_DISABLED] and st.alerts[0][1] == "med"
    f.routes = {}
    for k in range(3):
        d.poll(2000.0 + k)
    assert [a[0] for a in st.alerts] == [dnsfilter.T_DISABLED, dnsfilter.T_DOWN]
    assert d.status()["fails"] == 3 and d.status()["error"]
    assert all(SECRET not in a[4] for a in st.alerts)


def test_pihole5_fallback_and_token_not_leaked_in_error():
    calls = []

    def fetch(method, url, data, headers, verify):
        calls.append(url)
        if "/admin/api.php" in url:
            return 200, json.dumps(V5).encode()
        return 404, b""
    d = DnsFilter(St(), {"type": "pihole", "url": "http://192.168.1.2", "password": SECRET}, fetch=fetch)
    d.poll()
    s = d.status()
    assert s["version"] == 5 and s["queries_today"] == 15000 and s["status"] == "disabled"
    assert SECRET not in json.dumps(s)

    def boom(method, url, data, headers, verify):
        raise OSError(f"connection failed for {url}")
    d2 = DnsFilter(None, {"type": "pihole", "url": "http://192.168.1.2", "password": SECRET}, fetch=boom)
    d2.version = 5
    d2.poll()
    assert d2.status()["error"] and SECRET not in json.dumps(d2.status())


def test_adguard_basic_auth():
    seen = []

    def fetch(method, url, data, headers, verify):
        seen.append(headers.get("Authorization"))
        if url.endswith("/control/status"):
            return 200, json.dumps(AG_STATUS).encode()
        if url.endswith("/control/stats"):
            return 200, json.dumps(AG_STATS).encode()
        return 404, b""
    d = DnsFilter(None, {"type": "adguard", "url": "http://192.168.1.3:3000", "user": "admin", "password": SECRET}, fetch=fetch)
    d.poll()
    s = d.status()
    assert s["type"] == "adguard" and s["blocked_today"] == 4010 and s["status"] == "enabled"
    assert all(h and h.startswith("Basic ") for h in seen)
    assert SECRET not in json.dumps(s)


def test_history_one_point_per_hour_max_24():
    f = Fake(v6_routes())
    d = DnsFilter(None, {"type": "pihole", "url": "http://192.168.1.2", "password": SECRET}, fetch=f)
    for k in range(30):
        d.poll(3600.0 * k + 10)
        d.poll(3600.0 * k + 70)
    assert len(d.status()["history"]) == 24


def test_sim():
    d = DnsFilter(St(), {}, sim=True)
    s = d.status()
    assert s["demo"] and s["enabled"] and s["status"] == "enabled"
    assert 5000 < s["queries_today"] < 20000
    assert 19 < s["blocked_pct"] < 25 and s["top_blocked"][0]["domain"] == "doubleclick.net"
    assert all(c["client"].startswith("192.168.1.") for c in s["top_clients"])
    assert len(s["history"]) == 24
    json.dumps(s)
