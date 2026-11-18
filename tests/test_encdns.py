"""Tests για τον εντοπισμό κρυπτογραφημένου / παρακαμπτικού DNS (DoH, DoT, DoQ, εξωτερικό DNS)."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import encdns as ed  # noqa: E402


def P(src="192.168.1.20", dst="1.2.3.4", proto="TCP", sp=50000, dp=443, sni=None, dns_q=None):
    return {"src": src, "dst": dst, "proto": proto, "sp": sp, "dp": dp, "sni": sni, "dns_q": dns_q}


def test_classify_dot_doq():
    assert ed.classify(P(dst="8.8.8.8", dp=853)) == {"method": "DoT", "provider": "Google"}
    assert ed.classify(P(dst="94.140.14.14", dp=853, proto="UDP")) == {"method": "DoQ", "provider": "AdGuard"}
    assert ed.classify(P(dst="5.6.7.8", dp=853))["provider"] == "Άγνωστος"
    assert ed.classify(P(dst="45.90.28.17", dp=853))["provider"] == "NextDNS"  # δίκτυο /24


def test_classify_doh_by_sni_and_ip():
    assert ed.classify(P(dst="104.16.248.249", sni="mozilla.cloudflare-dns.com")) == {"method": "DoH", "provider": "Cloudflare"}
    assert ed.classify(P(dst="34.1.2.3", sni="abc123.dns.nextdns.io"))["provider"] == "NextDNS"
    assert ed.classify(P(dst="9.9.9.9", sni="DNS.Quad9.net."))["provider"] == "Quad9"
    assert ed.classify(P(dst="1.1.1.1")) == {"method": "DoH", "provider": "Cloudflare"}
    r = ed.classify(P(dst="2606:4700:4700::1111", proto="UDP"))
    assert r["method"] == "DoH" and r["http3"] and r["provider"] == "Cloudflare"
    assert ed.classify(P(dst="194.242.2.4"))["provider"] == "Mullvad"


def test_classify_external_plain_dns():
    r = ed.classify(P(dst="8.8.8.8", dp=53, proto="UDP", dns_q=("a2.tuyaeu.com",)))
    assert r == {"method": "DNS-ext", "provider": "Google"}
    assert ed.classify(P(dst="77.88.8.8", dp=53, proto="UDP"))["provider"] == "Άλλος"


def test_classify_negatives():
    assert ed.classify(P(dst="140.82.112.3", sni="github.com")) is None          # κανονικό HTTPS
    assert ed.classify(P(dst="1.1.1.1", sni="www.cloudflare.com")) is None        # site, όχι DoH
    assert ed.classify(P(dst="192.168.1.1", dp=53, proto="UDP")) is None         # DNS στον router
    assert ed.classify(P(dst="192.168.1.2", dp=853)) is None                      # DoT σε δικό σου server
    assert ed.classify(P(dst="8.8.8.8", dp=53, proto="UDP"), local_dns={"8.8.8.8"}) is None
    assert ed.classify(P(dst="8.8.8.8", dp=80)) is None
    assert ed.classify(P(dst="8.8.8.8", dp=853, proto="ICMP")) is None


class St:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, key=None, cooldown=None, **kw):
        self.alerts.append((typ, sev, actor, target, key, cooldown, detail))


def test_observe_direction_aggregation_and_cooldown():
    st = St()
    e = ed.EncDns(st, {"local_dns": ["192.168.1.1"], "allow": ["192.168.1.99"]})
    t = 1000.0
    # ίδια ροή DoH (πολλά πακέτα) = 1 σύνδεση
    e.observe(P(dst="8.8.8.8", sni="dns.google"), t)
    e.observe(P(dst="8.8.8.8"), t + 1)
    e.observe(P(dst="8.8.8.8", sp=50001), t + 2)
    # απάντηση (src δημόσια) — δεν μετρά
    assert e.observe({"src": "8.8.8.8", "dst": "192.168.1.20", "proto": "TCP", "sp": 443, "dp": 50000}, t) is None
    # allow-list και DNS προς τον router
    assert e.observe(P(src="192.168.1.99", dst="8.8.8.8", dp=853), t) is None
    assert e.observe(P(dst="192.168.1.1", dp=53, proto="UDP", dns_q=("x.com",)), t) is None
    e.observe(P(dst="8.8.8.8", dp=53, proto="UDP", dns_q=("a.example",), sp=1), t + 3)
    e.observe(P(dst="8.8.8.8", dp=53, proto="UDP", dns_q=("b.example",), sp=1), t + 4)
    s = e.status()
    json.dumps(s)
    d = s["devices"][0]
    assert d["ip"] == "192.168.1.20" and d["methods"] == {"DoH": 2, "DNS-ext": 2}
    assert d["providers"] == {"Google": 4} and "dns.google" in d["samples"] and "a.example" in d["samples"]
    assert s["totals"] == {"DoH": 2, "DoT": 0, "DoQ": 0, "DNS-ext": 2}
    assert d["first"] == t and d["last"] == t + 4
    # μία ειδοποίηση ανά συσκευή+μέθοδο, και πάλι μετά από 6 ώρες
    assert [(a[0], a[1], a[2], a[4]) for a in st.alerts] == [
        (ed.ALERT_TYPE, "low", "192.168.1.20", ("192.168.1.20", "DoH")),
        (ed.ALERT_TYPE, "low", "192.168.1.20", ("192.168.1.20", "DNS-ext"))]
    assert "Pi-hole" in st.alerts[0][6] and ed.CANARY in st.alerts[0][6] and "853" in ed._alert_detail("x", "DoT", "Google", None)
    e.observe(P(dst="8.8.8.8", sni="dns.google", sp=60000), t + 3600)
    assert len(st.alerts) == 2
    e.observe(P(dst="8.8.8.8", sni="dns.google", sp=60001), t + ed.ALERT_COOLDOWN + 1)
    assert len(st.alerts) == 3


def test_alerts_off_disabled_and_cap():
    st = St()
    e = ed.EncDns(st, {"alert": False})
    e.observe(P(dst="8.8.8.8", dp=853), 1.0)
    assert not st.alerts and e.status()["devices"]
    e2 = ed.EncDns(st, {"enabled": False})
    assert e2.observe(P(dst="8.8.8.8", dp=853), 1.0) is None and not e2.status()["devices"]
    e3 = ed.EncDns(None, {})
    for i in range(ed.MAX_DEVICES + 20):
        e3.observe(P(src=f"10.0.{i // 250}.{i % 250 + 1}", dst="8.8.8.8", dp=853), float(i))
    assert len(e3.devices) == ed.MAX_DEVICES and "10.0.0.1" not in e3.devices


def test_sim_shape():
    st = St()
    e = ed.EncDns(st, {}, sim=True)
    s = e.status()
    json.dumps(s)
    for k in ("enabled", "demo", "local_dns", "devices", "totals", "providers_list"):
        assert k in s
    assert s["demo"] and len(s["devices"]) >= 4
    by = {d["ip"]: d for d in s["devices"]}
    assert by["192.168.1.31"]["methods"].get("DoH") and "Google" in by["192.168.1.31"]["providers"]
    assert "Cloudflare" in by["192.168.1.24"]["providers"]
    assert by["192.168.1.37"]["methods"].get("DoT")
    assert by["192.168.1.52"]["methods"].get("DNS-ext") and "a2.tuyaeu.com" in by["192.168.1.52"]["samples"]
    assert all(s["totals"][m] > 0 for m in ed.METHODS)
    assert any(p["provider"] == "Cloudflare" and "1.1.1.1" in p["ips"] for p in s["providers_list"])
    assert ed.CANARY in ed.canary_note() and st.alerts
