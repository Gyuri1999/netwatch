import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import watchers as w  # noqa: E402


class Host(dict):
    pass


class State:
    def __init__(self, hosts):
        self.hosts = hosts
        self.demo_geo = {"23.1.2.3": ({"country": "United States"}, None)}

    def _dtype(self, h):
        return h.get("_dt", {})


def tv_state():
    return State({"192.168.1.58": {"ip": "192.168.1.58", "kind": "local", "names": {"LGwebOSTV.local"},
                                   "_dt": {"dtype": "tv", "dlabel": "Smart TV", "vendor": "LG Electronics", "dicon": "📺"}},
                  "192.168.1.15": {"ip": "192.168.1.15", "kind": "local", "names": {"iphone.local"},
                                   "_dt": {"dtype": "phone", "dlabel": "Κινητό", "vendor": "Apple", "dicon": "📱"}}})


def sni(src, dst, host):
    return {"src": src, "dst": dst, "sni": host}


def dnsp(dst, names):
    return {"src": "192.168.1.1", "dst": dst, "dns": [(n, "8.8.8.8") for n in names]}


def test_match():
    assert w.match("ad.lgappstv.com") == ("LG Ads", "acr")
    assert w.match("x.y.free.samba.tv") == ("Samba TV", "acr")
    assert w.match("DOUBLECLICK.NET") == ("Google Ads", "ads")
    assert w.match("example.com") is None and w.match("") is None


def test_observe_sni_attributes_to_device():
    st = tv_state()
    wa = w.Watchers(st, clock=lambda: 1000.0)
    wa.observe(sni("192.168.1.58", "23.1.2.3", "ad.lgappstv.com"))
    wa.observe(sni("192.168.1.58", "23.1.2.3", "ad.lgappstv.com"))
    wa.observe(sni("192.168.1.58", "9.9.9.9", "free.samba.tv"))
    wa.observe(sni("192.168.1.58", "9.9.9.9", "cdn.example.com"))  # αγνοείται (όχι tracker)
    v = wa.view()
    tv = next(d for d in v["devices"] if d["ip"] == "192.168.1.58")
    comps = {t["company"]: t for t in tv["trackers"]}
    assert comps["LG Ads"]["count"] == 2 and comps["LG Ads"]["country"] == "United States"
    assert "Samba TV" in comps and tv["acr"] is True
    assert tv["brand"] == "LG" and tv["acr_fix"]
    assert tv["score"] < 40  # ACR → χαμηλό σκορ ιδιωτικότητας


def test_dns_attributes_to_receiver():
    st = tv_state()
    wa = w.Watchers(st, clock=lambda: 1000.0)
    wa.observe(dnsp("192.168.1.15", ["app-measurement.com", "apple.com"]))
    v = wa.view()
    ph = next(d for d in v["devices"] if d["ip"] == "192.168.1.15")
    assert [t["company"] for t in ph["trackers"]] == ["Google (Firebase)"]
    assert ph["acr"] is False


def test_public_private_filter():
    st = tv_state()
    wa = w.Watchers(st)
    wa.observe(sni("8.8.8.8", "1.2.3.4", "doubleclick.net"))   # src δημόσιο → αγνοείται
    wa.observe(sni("192.168.1.58", "192.168.1.9", "doubleclick.net"))  # dst ιδιωτικό → αγνοείται
    assert wa.view()["devices"] == [] or all(not d["trackers"] for d in wa.view()["devices"])


def test_score_and_summary():
    st = tv_state()
    wa = w.Watchers(st, clock=lambda: 1000.0)
    wa.observe(sni("192.168.1.58", "23.1.2.3", "samba.tv"))
    wa.observe(sni("192.168.1.15", "5.6.7.8", "doubleclick.net"))
    v = wa.view()
    assert v["companies"] == 2 and v["acr_devices"] == 1
    assert v["devices"][0]["acr"] is True  # η TV με ACR μπαίνει πρώτη
    assert any(t["company"] == "Samba TV" for t in v["top"])


def test_caps_do_not_grow_unbounded():
    st = tv_state()
    wa = w.Watchers(st, clock=lambda: 1.0)
    for i in range(w.MAX_DEV + 50):
        wa.observe(sni(f"10.0.0.{i % 255}", "23.1.2.3", "doubleclick.net"))
    assert len(wa.hits) <= w.MAX_DEV


def test_report_html_el_and_en():
    wa = w.Watchers(None, sim=True)
    h = wa.report_html("el")
    assert h.startswith("<!doctype html>") and "LG TV" in h and "ACR" in h and "scorecardresearch.com" in h
    he = wa.report_html("en")
    assert "Who is watching you" in he and "nothing was blocked" in he


def test_demo_view():
    v = w.Watchers(None, sim=True).view()
    assert v["demo"] and v["acr_devices"] == 1 and v["devices"][0]["acr"]
    assert v["devices"][0]["acr_fix"]


def test_tv_brand():
    assert w.tv_brand({"names": ["LGwebOSTV.local"], "vendor": "LG Electronics", "type": "Smart TV"}) == "LG"
    assert w.tv_brand({"names": [], "vendor": "Samsung", "type": "Tizen TV"}) == "Samsung"
    assert w.tv_brand({"names": [], "vendor": "Apple", "type": "phone"}) is None
