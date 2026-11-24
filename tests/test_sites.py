import base64
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sites as s  # noqa: E402

NOW = time.mktime((2026, 3, 15, 12, 0, 0, 0, 0, -1))
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
XSS = '<script>alert(1)</script>'


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


class Hist:
    def __init__(self, rows):
        self.rows = rows

    def query(self, hours=24, ref=None):
        return {"alerts": [a for a in self.rows if a["t"] >= ref - hours * 3600]}


class State:
    def __init__(self, gw="192.168.1.1", mac="aa:bb:cc:00:00:01"):
        self.gateway = gw
        self.hosts = {gw: {"ip": gw, "kind": "local", "names": {"router.lan"}, "mac": mac},
                      "192.168.1.30": {"ip": "192.168.1.30", "kind": "local", "names": {"cam" + XSS}, "mac": "AA-BB-CC-00-00-30"},
                      "8.8.8.8": {"ip": "8.8.8.8", "kind": "public", "names": set(), "mac": None}}
        self.alerts = []

    def _dtype(self, h):
        return {"dtype": "camera", "dlabel": "Κάμερα", "vendor": "Hikvision"} if h["ip"].endswith(".30") else {"dtype": "router"}


def data_url(raw=PNG, mime="image/png"):
    return f"data:{mime};base64," + base64.b64encode(raw).decode()


def test_slugify_and_expand():
    assert s.slugify("Καφέ «Θάλασσα»") == "kafe-thalassa"
    assert s.slugify("../../etc/passwd") == "etc-passwd"
    assert s.slugify("   ") == "site" and s.SLUG_RE.match(s.slugify("x" * 200))
    assert s.expand("A-01..A-03") == ["A-01", "A-02", "A-03"]
    assert s.expand("PP1-9..11, X") == ["PP1-9", "PP1-10", "PP1-11", "X"]
    assert s.expand("SW1/08..SW1/10")[-1] == "SW1/10"
    for bad in ("", "A-05..A-01", "A-01..B-03", "A..B", "A-1..A-9999"):
        with pytest.raises(ValueError):
            s.expand(bad, 500)


def test_site_ids_are_safe_slugs_no_path_traversal(tmp_path):
    S = s.Sites(State(), str(tmp_path), clock=Clock())
    site, err = S.save_site({"name": "../../evil", "from_current": True})
    assert not err and s.SLUG_RE.match(site["id"]) and "/" not in site["id"] and ".." not in site["id"]
    d = S.site_dir(site["id"])
    assert d and os.path.realpath(d).startswith(os.path.realpath(str(tmp_path / "sites")))
    for bad in ("../x", "..", "a/b", "", "A", "/etc", 5, "nosuch", "evil\n", "evil/../evil"):
        assert S.site_dir(bad) is None
    assert S.save_site({"id": "../x", "name": "y"})[1]  # άγνωστο id → σφάλμα, όχι νέος φάκελος
    assert sorted(os.listdir(str(tmp_path / "sites"))) == [site["id"]]
    # πειραγμένο αρχείο με id-μονοπάτι αγνοείται στη φόρτωση
    j = s.read_json(str(tmp_path / "sites.json"))
    j["sites"]["../../pwn"] = dict(j["sites"][site["id"]])
    s.write_json(str(tmp_path / "sites.json"), j)
    assert s.Sites(State(), str(tmp_path)).ids() == [site["id"]]
    assert S.save_site({"name": ""})[1]
    assert S.save_site({"name": "../../evil"})[0]["id"] != site["id"]  # μοναδικό id


def test_detect_by_mac_then_ip_subnet():
    st = State()
    S = s.Sites(st, clock=Clock())
    assert S.detect() is None and S.view()["new_network"] is True and S.site_dir() is None
    a, _ = S.save_site({"name": "Alpha", "from_current": True})
    assert a["fp"] == {"gw_mac": "aa:bb:cc:00:00:01", "gw_ip": "192.168.1.1", "subnet": "192.168.1.0/24", "ssid": ""}
    assert S.detect() == a["id"] and S.view()["current"] == a["id"] and S.view()["new_network"] is False
    # άλλος πελάτης με ίδιο 192.168.1.1/24 αλλά άλλη MAC → ΔΕΝ ταιριάζει
    st.hosts["192.168.1.1"]["mac"] = "aa:bb:cc:99:99:99"
    assert S.detect() is None
    # πελάτης χωρίς MAC στο αποτύπωμα → ταίριασμα με IP + subnet
    b, _ = S.save_site({"name": "Beta", "fp": {"gw_ip": "192.168.1.1", "subnet": "192.168.1.0/24"}})
    assert S.detect() == b["id"]
    # η MAC υπερισχύει του IP+subnet
    st.hosts["192.168.1.1"]["mac"] = "aa:bb:cc:00:00:01"
    assert S.detect() == a["id"]
    # επιλογή με το χέρι ισχύει μέχρι να αλλάξει το δίκτυο
    assert S.select(b["id"]) and S.detect() == b["id"] and S.view()["manual"]
    st.gateway = "10.0.0.1"
    st.hosts["10.0.0.1"] = {"ip": "10.0.0.1", "kind": "local", "names": set(), "mac": "aa:bb:cc:00:00:02"}
    assert S.detect() is None and not S.select("nosuch")
    code, v = S.api("POST", "bind", {}, {"id": b["id"]})
    assert code == 200 and v["current"] == b["id"] and S.get(b["id"])["fp"]["gw_mac"] == "aa:bb:cc:00:00:02"
    assert s.Sites(None).detect() is None and s.Sites(None).view()["demo"] is False


def test_visit_snapshot_and_persistence(tmp_path):
    st, ck = State(), Clock()
    st.history = Hist([{"t": NOW - 3600, "type": "Σάρωση θυρών", "sev": "high"}, {"t": NOW - 7200, "type": "Νέα συσκευή", "sev": "low"},
                       {"t": NOW - 100 * 86400, "type": "παλιό", "sev": "high"}, {"t": NOW - 60, "type": "lab", "sev": "high", "lab": True}])

    class Up:
        def view(self):
            return {"counts": {"high": 1, "med": 0, "x": "no"}}

    class Boom:
        def view(self):
            raise RuntimeError("x")
    st.upnp, st.vulns = Up(), Boom()
    S = s.Sites(st, str(tmp_path), clock=ck)
    saved = []
    S.on_save = saved.append
    sid = S.save_site({"name": "Alpha", "from_current": True})[0]["id"]
    assert S.end_visit(sid)[1] and S.start_visit("nosuch")[1]
    v, err = S.start_visit(sid, "Γιώργος")
    assert not err and S.start_visit(sid)[1] and S.view()["sites"][0]["open_visit"] == NOW
    ck.t += 45 * 60
    v, err = S.end_visit(sid, "Αλλαγή switch", "1× switch 8p", None, "Να μπει UPS")
    sn = v["snapshot"]
    assert not err and v["minutes"] == 45 and sn["count"] == 2 and sn["extras"] == {"upnp": {"high": 1, "med": 0}}
    assert sn["devices"][1] == {"ip": "192.168.1.30", "mac": "aa:bb:cc:00:00:30", "name": "cam" + XSS, "vendor": "Hikvision", "type": "Κάμερα"}
    assert sn["alerts"]["sev"] == {"high": 1, "med": 0, "low": 1} and sn["alerts"]["total"] == 2
    assert any(p.endswith("visits.json") for p in saved) and any(p.endswith("sites.json") for p in saved)
    # χωρίς ιστορικό → από state.alerts· εκτός δικτύου πελάτη → χωρίς στιγμιότυπο
    del st.history
    st.alerts = [{"t": ck.t + 10, "type": "ARP spoofing", "sev": "med"}]
    S.start_visit(sid)
    ck.t += 600
    v2, _ = S.end_visit(sid, minutes="30")
    assert v2["minutes"] == 30 and v2["snapshot"]["alerts"]["sev"]["med"] == 1 and v2["snapshot"]["alerts"]["total"] == 1
    st.gateway = None
    S.start_visit(sid)
    assert S.end_visit(sid)[0]["snapshot"] is None
    # παλιά επίσκεψη με ημερομηνία + διόρθωση + διαγραφή
    p, err = S.save_visit(sid, {"date": "2026-02-10", "minutes": 120, "work": "Εγκατάσταση"})
    assert not err and p["minutes"] == 120 and S.save_visit(sid, {"date": "χθες"})[1]
    assert S.save_visit(sid, {"vid": p["id"], "work": "Νέο κείμενο", "minutes": 90})[0]["minutes"] == 90
    # round-trip από τον δίσκο
    S2 = s.Sites(State(), str(tmp_path), clock=ck)
    d = S2.detail(sid)
    assert d["visits"] == 4 and d["visit_list"][-1]["work"] == "Νέο κείμενο" and "devices" not in d["visit_list"][2]["snapshot"]
    assert S2.visits[sid][1]["snapshot"]["count"] == 2 and "2026-02" in d["months"]
    assert S2.delete_visit(sid, p["id"]) and not S2.delete_visit(sid, p["id"])
    assert len(s.Sites(State(), str(tmp_path)).visits[sid]) == 3
    assert S2.delete_site(sid) and os.path.isdir(str(tmp_path / "sites" / sid))  # ο φάκελος μένει
    assert s.Sites(State(), str(tmp_path)).ids() == []


def test_monthly_report_content_and_escaping():
    st, ck = State(), Clock()
    S = s.Sites(st, clock=ck)
    assert S._set_company({"name": "Net " + XSS, "tech": "Tech " + XSS, "vat": "123", "logo": data_url()}) == ""
    sid = S.save_site({"name": "Πελάτης " + XSS, "address": XSS, "contact": XSS, "contract": "monthly", "from_current": True})[0]["id"]
    ck.t = NOW - 10 * 86400
    S.start_visit(sid)
    ck.t += 3600
    S.end_visit(sid, "Πρώτη " + XSS, XSS, 60)
    st.hosts["192.168.1.77"] = {"ip": "192.168.1.77", "kind": "local", "names": {"new-tv"}, "mac": "aa:bb:cc:00:00:77"}
    del st.hosts["192.168.1.30"]
    st.alerts = [{"t": ck.t + 60, "type": "Σάρωση " + XSS, "sev": "high"}]
    ck.t = NOW
    S.start_visit(sid)
    ck.t += 1800
    S.end_visit(sid, "Δεύτερη", "", 90, "Αλλαγή κωδικού " + XSS)
    d = S.monthly(sid, "2026-03")
    assert len(d["visits"]) == 2 and d["minutes"] == 150 and d["compared"]
    assert [x["ip"] for x in d["new"]] == ["192.168.1.77"] and [x["ip"] for x in d["gone"]] == ["192.168.1.30"]
    assert d["sev"]["high"] == 1 and any("Αλλαγή κωδικού" in r for r in d["recs"]) and any("1 ειδοποιήσεις" in r for r in d["recs"])
    code, doc = S.api("GET", "report", {"id": sid, "month": "2026-03"}, {})
    h = doc["_raw"].decode()
    assert code == 200 and doc["_type"].startswith("text/html") and doc["_name"].endswith("2026-03.html")
    assert "<script" not in h.lower() and "&lt;script&gt;alert(1)&lt;/script&gt;" in h
    assert "Αναφορά μηνιαίας συντήρησης" in h and "Μάρτιος 2026" in h and "2:30" in h and "size:A4" in h
    assert "192.168.1.77" in h and "192.168.1.30" in h and "Ο τεχνικός" in h and "Ο πελάτης" in h and 'src="data:image/png;base64,' in h
    en = S.monthly_html(sid, "2026-03", "en")
    assert "Monthly network maintenance report" in en and "March 2026" in en and "Total hours" in en and "<script" not in en.lower()
    assert "No visits were recorded" in S.monthly_html(sid, "2025-01", "en") and S.monthly_html("nosuch") is None
    assert S.api("GET", "report", {"id": "../x"}, {})[0] == 404
    assert S.monthly(sid, "bogus")["month"] == time.localtime(ck.t).tm_mon


def test_logo_validation_and_company():
    S = s.Sites(None)
    assert s.logo_ok("")[0] and s.logo_ok(data_url())[0] and s.logo_ok(data_url(b"\xff\xd8\xff\xe0" + b"0" * 20, "image/jpeg"))[0]
    for bad in (data_url(b"<svg onload=alert(1)>", "image/svg+xml"), data_url(b"GIF89a", "image/gif"), data_url(b"not a png"),
                data_url(PNG + b"0" * (s.MAX_LOGO + 1)), "http://example.com/logo.png", "data:image/png;base64,***", "javascript:alert(1)"):
        assert not s.logo_ok(bad)[0]
        code, r = S.api("POST", "company", {}, {"name": "X", "logo": bad})
        assert code == 400 and r["error"] and r["error_en"]
    assert S.company()["logo"] == "" and S.company()["name"] == ""
    code, v = S.api("POST", "company", {}, {"name": "ACME", "tech": "Γ.Π.", "logo": data_url()})
    assert code == 200 and v["company"]["has_logo"] and "logo" not in v["company"] and S.company()["logo"].startswith("data:image/png")
    assert S.api("POST", "company", {}, {"phone": "210"})[1]["company"]["has_logo"]  # το λογότυπο μένει αν δεν σταλεί
    assert not S.api("POST", "company", {}, {"logo": ""})[1]["company"]["has_logo"]
    # πειραγμένο λογότυπο στο αρχείο δεν φτάνει ποτέ στο HTML
    S.co["logo"] = 'x" onerror="alert(1)'
    assert "onerror" not in s.doc_header(S.company(), "el")


def test_csv_and_api(tmp_path):
    S = s.Sites(State(), str(tmp_path), clock=Clock())
    code, v = S.api("POST", "save", {}, {"name": "=cmd|' /C calc'!A0", "address": "Οδός 1", "from_current": True})
    sid = v["saved"]
    assert code == 200 and S.api("GET", "", {}, {}) == (200, S.view())
    S.api("POST", "visit/start", {}, {"id": sid})
    code, r = S.api("POST", "visit/end", {}, {"id": sid, "work": "+SUM(A1)", "minutes": 20})
    assert code == 200 and r["site"]["visit_list"][0]["minutes"] == 20
    c = S.api("GET", "sites.csv", {}, {})[1]
    assert c["_type"].startswith("text/csv") and "'=cmd" in c["_raw"].decode() and "192.168.1.0/24" in c["_raw"].decode()
    assert "'+SUM(A1)" in S.api("GET", "visits.csv", {"id": sid}, {})[1]["_raw"].decode()
    assert S.api("GET", "visits.csv", {"id": "x"}, {})[0] == 404 and S.api("GET", "site", {"id": "x"}, {})[0] == 404
    assert S.api("GET", "nope", {}, {}) == (404, {"error": "not found"}) and S.api("POST", "nope", {}, {})[0] == 404
    assert S.api("POST", "save", {}, {"name": ""})[0] == 400 and S.api("POST", "visit/end", {}, {"id": sid})[0] == 400
    assert S.api("POST", "delete", {}, {"id": sid})[0] == 200 and S.api("POST", "delete", {}, {"id": sid})[0] == 404


def test_demo_view_shape():
    S = s.Sites(None, demo=True, clock=Clock())
    v = S.view()
    assert v["demo"] is True and len(v["sites"]) == 3 and v["current"] == "hotel-aegean" and v["company"]["name"]
    assert all(s.SLUG_RE.match(x["id"]) and x["visits"] >= 1 for x in v["sites"]) and S.site_dir() is None
    d = S.detail("hotel-aegean")
    assert d["visit_list"] and d["visit_list"][-1]["snapshot"]["count"] >= 10
    m = S.monthly("hotel-aegean")
    assert m["compared"] and any(x["name"] == "cam-12" for x in m["new"]) and any(x["name"] == "tv-box-201" for x in m["gone"])
    h = S.monthly_html("hotel-aegean")
    assert "Aegean View" in h and "UPnP" in h and "<script" not in h
    import json
    json.dumps(v), json.dumps(d)


def test_baseline_and_drift():
    import sites

    class St:
        def __init__(self):
            self.hosts = {"192.168.1.1": {"ip": "192.168.1.1", "kind": "local", "mac": "aa:bb:cc:00:00:01", "names": {"router"}},
                          "192.168.1.50": {"ip": "192.168.1.50", "kind": "local", "mac": "aa:bb:cc:00:00:02", "names": {"pc"}}}
            self.gateway = "192.168.1.1"
            self.me = {"192.168.1.50"}
            self.alerts = []

        def _dtype(self, h):
            return {}

        def alert(self, typ, sev, actor, target, detail, t, **kw):
            self.alerts.append({"typ": typ, "key": kw.get("key"), "cooldown": kw.get("cooldown")})

    st = St()
    s = sites.Sites(st, None)
    s.sites["kafe"] = {"id": "kafe", "name": "Καφέ", "fp": {}}
    assert s.drift("kafe") is None                      # χωρίς baseline
    assert s.save_baseline("kafe")["count"] == 2
    assert s.drift("kafe")["ok"] is True                # ίδιο δίκτυο
    assert s.detail("kafe")["baseline"]["ok"] is True
    # νέα + χαμένη συσκευή
    st.hosts["192.168.1.77"] = {"ip": "192.168.1.77", "kind": "local", "mac": "aa:bb:cc:00:00:03", "names": {"kseno"}}
    del st.hosts["192.168.1.50"]
    dr = s.drift("kafe")
    assert [d["ip"] for d in dr["new"]] == ["192.168.1.77"] and [d["ip"] for d in dr["gone"]] == ["192.168.1.50"] and dr["ok"] is False
    # ειδοποίηση για νέα συσκευή, με κλειδί για dedup + cooldown
    s.detect = lambda: "kafe"
    s.check_drift()
    assert st.alerts and st.alerts[0]["key"] == ("site-drift", "kafe", ("mac", "aa:bb:cc:00:00:03")) and st.alerts[0]["cooldown"] >= 3600
    assert s.clear_baseline("kafe")["ok"] and s.drift("kafe") is None
