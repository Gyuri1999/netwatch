import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import accept as a  # noqa: E402
import labels as lb  # noqa: E402
import sites as s  # noqa: E402

NOW = time.mktime((2026, 3, 15, 12, 0, 0, 0, 0, -1))
XSS = '<script>alert(1)</script>'


class Notes:
    def all(self):
        return {"aa:bb:cc:00:00:30": {"name": "Κάμερα εισόδου", "location": "Είσοδος"}}


class Ipam:
    cfg = {"subnets": [{"cidr": "192.168.1.0/24", "vlan": 30}], "reserved": [{"ip": "192.168.1.200", "name": "nvr"}]}
    notes = Notes()

    def leases(self, now=None):
        return []


class State:
    gateway = "192.168.1.1"
    port = 9000

    def __init__(self):
        self.me = {"192.168.1.10", "fe80::1", "127.0.0.1"}
        self.hosts = {"192.168.1.1": {"ip": "192.168.1.1", "kind": "local", "names": {"router"}, "mac": "aa:bb:cc:00:00:01"},
                      "192.168.1.30": {"ip": "192.168.1.30", "kind": "local", "names": {"cam-1"}, "mac": "aa:bb:cc:00:00:30"},
                      "192.168.1.50": {"ip": "192.168.1.50", "kind": "local", "names": {"pc" + XSS}, "mac": "aa:bb:cc:00:00:50"}}

    def _dtype(self, h):
        return {"dtype": "camera" if h["ip"].endswith(".30") else "computer", "vendor": "Hikvision" if h["ip"].endswith(".30") else ""}


def mk(tmp=None, st=None):
    st = st or State()
    S = s.Sites(st, tmp, clock=lambda: NOW)
    return st, S, lb.Labels(st, tmp, clock=lambda: NOW, sites=S)


def n_labels(h):
    return len(re.findall(r'<div class="lb(?: flag)?">', h))


def test_sheet_a4_counts_qr_and_page_size():
    items = [{"name": f"PP1-{i:02d}", "ip": f"192.168.1.{i}"} for i in range(1, 31)]
    h = lb.sheet_html(items, "a4-24", ["name", "ip"], "id")
    assert n_labels(h) == 30 and h.count("<svg") == 30 and h.count('<section class="pg">') == 2
    assert "@page{size:210mm 297mm;margin:0}" in h and "repeat(3,70mm)" in h and "grid-auto-rows:37mm" in h and "width:70mm;height:37mm" in h
    assert "<script" not in h and "PP1-30" in h and "192.168.1.30" in h
    h = lb.sheet_html(items[:5], "a4-65", ["name"], "none", offset=3)
    assert n_labels(h) == 5 and h.count("<svg") == 0 and h.count('<div class="sk">') == 3 and "repeat(5,38.1mm)" in h and "width:38.1mm;height:21.2mm" in h
    assert h.count('<section class="pg">') == 1 and "padding:10.7mm 0 0 4.75mm" in h and "column-gap:2.5mm" in h
    # 65 θέσεις: 63 + offset 5 → δεύτερο φύλλο· offset εκτός ορίων κόβεται
    assert lb.sheet_html([{"name": str(i)} for i in range(63)], "a4-65", offset=5).count('<section class="pg">') == 2
    assert lb.sheet_html(items[:1], "a4-24", offset=999).count('<div class="sk">') == 23
    assert lb.sheet_html(items[:1], "a4-24", offset="x").count('<div class="sk">') == 0
    assert n_labels(lb.sheet_html([], "a4-24")) == 0 and n_labels(lb.sheet_html(items, "nosuch")) == 30
    # κάθε φύλλο χωράει στο A4
    for p in lb.PRESETS.values():
        if p["kind"] == "sheet":
            assert p["left"] + p["cols"] * p["w"] + (p["cols"] - 1) * p["gx"] <= 210.001 and p["top"] + p["rows"] * p["h"] + (p["rows"] - 1) * p["gy"] <= 297.001


def test_tapes_and_cable_flags():
    items = [{"name": "A-01", "b": "SW1/12"}, {"name": "A-02", "b": "SW1/13"}]
    h = lb.sheet_html(items, "tape-12", ["name"], "ip")
    assert "@page{size:45mm 12mm;margin:0}" in h and n_labels(h) == 2 and ".lb{break-after:page}" in h and h.count("<svg") == 2
    assert "@page{size:62mm 29mm;margin:0}" in lb.sheet_html(items, "dk-62") and "@page{size:60mm 24mm;margin:0}" in lb.sheet_html(items, "tape-24")
    assert "@page{size:70mm 12mm;margin:0}" in lb.sheet_html(items, "tape-12", length="70")
    assert "@page{size:300mm 12mm;margin:0}" in lb.sheet_html(items, "tape-12", length=5000) and "size:45mm 12mm" in lb.sheet_html(items, "tape-12", length="x")
    assert "size:210mm 297mm" in lb.sheet_html(items, "a4-24", length=80)  # το μήκος δεν αγγίζει τα φύλλα
    f = lb.sheet_html(items, "flag-12", ["cable"], "none")
    assert "@page{size:80mm 12mm;margin:0}" in f and n_labels(f) == 2 and f.count('class="hf"') == 4 and f.count('class="wr"') == 2
    assert f.count("A-01 ⇄ SW1/12") == 2 and f.count("A-02 ⇄ SW1/13") == 2  # το κείμενο δύο φορές ανά σημαία
    assert lb.sheet_html(items, "flag-24", ["cable"], "id").count("<svg") == 4


def test_lines_qr_text_and_escaping():
    it = {"name": "cam-1", "ip": "192.168.1.30", "mac": "aa:bb:cc:00:00:30", "location": "Είσοδος", "vlan": "30"}
    assert lb.lines_for(it, ["name", "ip", "location", "mac"]) == ["cam-1", "192.168.1.30", "Είσοδος"]
    assert lb.lines_for(it, ["vlan", "vendor"]) == ["VLAN 30"] and lb.lines_for({"name": "x"}, ["ip"]) == ["x"]
    tpl = "http://192.168.1.10:9000/#dev={ip}"
    assert lb.qr_text(it, "url", tpl) == "http://192.168.1.10:9000/#dev=192.168.1.30"
    assert lb.qr_text(it, "id", tpl) == "cam-1" and lb.qr_text(it, "ip", tpl) == "192.168.1.30" and lb.qr_text(it, "none", tpl) == ""
    assert lb.qr_text({"name": "PP1-01"}, "url", tpl) == "PP1-01"  # χωρίς IP → σκέτο όνομα, όχι σπασμένος σύνδεσμος
    assert lb.qr_text({"name": "a b&c", "ip": "10.0.0.1"}, "url", "https://x.test/d?n={name}&m={mac}") == "a b&c"
    assert lb.qr_text({"name": "a b&c", "ip": "10.0.0.1"}, "url", "https://x.test/d?n={name}") == "https://x.test/d?n=a%20b%26c"
    assert lb.tpl_ok(tpl) and not lb.tpl_ok("javascript:alert(1)") and not lb.tpl_ok('http://x/"><script>') and not lb.tpl_ok("http://a b")
    seen = []
    h = lb.sheet_html([{"name": XSS, "location": '"><img src=x onerror=1>', "ip": "10.0.0.1"}], "a4-24", ["name", "location"], "url", tpl,
                      title=XSS, qr_svg=lambda t: seen.append(t) or "<svg></svg>")
    assert "<script" not in h and "<img" not in h and "&lt;script&gt;" in h and seen == ["http://192.168.1.10:9000/#dev=10.0.0.1"]
    # κείμενο που δεν χωράει σε QR → ετικέτα χωρίς QR, όχι σφάλμα

    def boom(t):
        raise ValueError("πολύ μεγάλο")
    assert n_labels(lb.sheet_html([{"name": "x"}], "a4-24", ["name"], "id", qr_svg=boom)) == 1
    assert lb.clean_item({}) is None and lb.clean_item("A-1") == {"name": "A-1"} and lb.clean_item({"name": "x" * 99, "zz": 1}) == {"name": "x" * 40}


def test_build_sources():
    st, S, L = mk()
    st.ipam = Ipam()
    assert L.build({"source": "pattern", "pattern": "PP1-01..PP1-24"})[0][23] == {"name": "PP1-24"}
    assert L.build({"source": "pattern", "pattern": "PP1-08..PP1-11"})[0][2] == {"name": "PP1-10"}  # κρατά τα μηδενικά
    for bad in ("", "A-5..A-1", "A-1..A-99999", "..", "A-1..B-2"):
        items, err = L.build({"source": "pattern", "pattern": bad})
        assert items is None and err
    c, err = L.build({"source": "cables", "pattern": "A-01..A-03", "pattern_b": "SW1/12..SW1/14"})
    assert not err and c[0] == {"name": "A-01", "b": "SW1/12"} and c[2] == {"name": "A-03", "b": "SW1/14"}
    assert L.build({"source": "cables", "pattern": "A-01..A-03", "pattern_b": "B-1..B-2"})[1] and L.build({"source": "cables", "pattern": "A-1..A-2"})[0] == [{"name": "A-1"}, {"name": "A-2"}]
    d, err = L.build({"source": "devices"})
    assert not err and [x["ip"] for x in d] == ["192.168.1.1", "192.168.1.30", "192.168.1.50"]
    assert d[1] == {"name": "Κάμερα εισόδου", "ip": "192.168.1.30", "mac": "aa:bb:cc:00:00:30", "vendor": "Hikvision", "type": "camera", "location": "Είσοδος"}
    assert [x["ip"] for x in L.build({"source": "devices", "dtypes": "camera"})[0]] == ["192.168.1.30"]
    i, err = L.build({"source": "ipam"})
    by = {x["ip"]: x for x in i}
    assert not err and by["192.168.1.30"]["vlan"] == "30" and by["192.168.1.30"]["location"] == "Είσοδος" and by["192.168.1.200"]["name"] == "nvr"
    assert L.build({"source": "accept", "job": "x"})[1] and L.build({"source": "nosuch"})[1]
    st.accept = a.Accept(st, clock=lambda: NOW, sites=S, run=lambda *x: {"ok": True})
    jid = st.accept.new_job("J", site="")[0]["id"]
    st.accept.bulk_add(jid, "socket", "A-01..A-04", "Γραφείο")
    st.accept.add_point(jid, "camera", "cam-9", "192.168.1.39")
    p, err = L.build({"source": "accept", "job": jid})
    assert not err and len(p) == 5 and p[0] == {"name": "A-01", "location": "Γραφείο", "type": "Πρίζα δικτύου"} and p[4]["ip"] == "192.168.1.39"
    assert L.view()["sources"] == {"devices": 3, "dtypes": {"camera": 1, "computer": 2}, "ipam": True, "jobs": [{"id": jid, "title": "J", "points": 5}]}
    del st.ipam
    assert L.build({"source": "ipam"})[1] and L.build({"source": "devices"})[0][1]["name"] == "cam-1" and lb.Labels(None).build({"source": "devices"}) == ([], None)


def test_url_default_and_api():
    st, S, L = mk()
    assert L.url_default() == "http://192.168.1.10:9000/#dev={ip}" and lb.Labels(None).url_default() == "http://netwatch.local:8765/#dev={ip}"
    assert L.api("GET", "", {}, {}) == (200, L.view()) and L.api("GET", "x", {}, {}) == (404, {"error": "not found"}) and L.api("POST", "x", {}, {})[0] == 404
    code, r = L.api("POST", "build", {}, {"source": "pattern", "pattern": "X1..X4"})
    assert code == 200 and r["count"] == 4
    r = L.api("POST", "build", {}, {"source": "pattern", "pattern": "X4..X1"})
    assert r[0] == 400 and r[1]["error"] and r[1]["error_en"]
    assert L.api("POST", "save", {}, {"name": "κενό", "items": []})[0] == 400 and L.api("POST", "save", {}, {"id": "lnope", "items": [{"name": "a"}]})[0] == 400
    assert L.api("POST", "save", {}, {"items": [{"name": "a"}], "url_tpl": "javascript:alert(1)"})[0] == 400
    assert L.api("POST", "save", {}, {"items": [{"name": "a"}], "site": "nosuch"})[0] == 400
    items = [{"name": "cam-1", "ip": "192.168.1.30"}, {"name": "cam-2", "ip": "192.168.1.31"}, {"name": "", "ip": ""}, "bad" * 30]
    code, v = L.api("POST", "save", {}, {"name": "Κάμερες", "preset": "a4-21", "fields": ["name", "ip", "bogus", "mac", "vlan"], "qr": "url", "offset": 2, "items": items})
    lid = v["saved"]
    assert code == 200 and lb.SET_RE.match(lid) and v["sets"][0]["count"] == 3 and v["sets"][0]["fields"] == ["name", "ip", "mac"] and v["counts"] == {"sets": 1, "labels": 3}
    assert L.api("GET", "set", {"id": lid}, {})[1]["items"][1] == {"name": "cam-2", "ip": "192.168.1.31"} and L.api("GET", "set", {"id": "x"}, {})[0] == 404
    code, doc = L.api("GET", "sheet", {"id": lid, "lang": "en"}, {})
    h = doc["_raw"].decode()
    assert code == 200 and doc["_type"].startswith("text/html") and n_labels(h) == 3 and h.count('<div class="sk">') == 2 and h.count("<svg") == 3
    assert "repeat(3,63.5mm)" in h and "@page{size:210mm 297mm;margin:0}" in h and "Actual size" in h and "<script" not in h
    # παράκαμψη από το query (άλλο χαρτί, χωρίς QR) χωρίς να αλλάξει το αποθηκευμένο σετ
    h = L.api("GET", "sheet", {"id": lid, "preset": "tape-24", "qr": "none"}, {})[1]["_raw"].decode()
    assert "@page{size:60mm 24mm;margin:0}" in h and "<svg" not in h and L.sets[lid]["preset"] == "a4-21"
    # γρήγορη εκτύπωση χωρίς αποθήκευση
    h = L.api("GET", "sheet", {"source": "pattern", "pattern": "PP1-01..PP1-24", "preset": "a4-65", "qr": "id"}, {})[1]["_raw"].decode()
    assert n_labels(h) == 24 and h.count("<svg") == 24 and len(L.sets) == 1
    assert L.api("GET", "sheet", {"source": "pattern", "pattern": "Z9..Z1"}, {})[0] == 400 and L.api("GET", "sheet", {"id": "x"}, {})[0] == 404
    assert L.api("POST", "save", {}, {"id": lid, "name": "Νέο όνομα"})[1]["sets"][0]["name"] == "Νέο όνομα" and len(L.sets[lid]["items"]) == 3
    assert L.api("POST", "delete", {}, {"id": lid})[1]["sets"] == [] and L.api("POST", "delete", {}, {"id": lid})[0] == 404


def test_real_qr_svg_is_inline():
    h = lb.sheet_html([{"name": "PP1-01"}], "a4-65", ["name"], "id")
    assert h.count('<svg xmlns="http://www.w3.org/2000/svg"') == 1 and "<path d=" in h and "http://" not in h.replace("http://www.w3.org", "")


def test_persistence_per_site(tmp_path):
    st, S, L = mk(str(tmp_path))
    saved = []
    L.on_save = saved.append
    sid = S.save_site({"name": "Alpha", "from_current": True})[0]["id"]
    a1 = L.save_set({"name": "PP1", "items": [{"name": x} for x in s.expand("PP1-01..PP1-12")], "preset": "a4-65", "len": 55})[0]
    b1 = L.save_set({"name": "Γενικό", "site": "", "items": [{"name": "X", "b": "Y"}], "preset": "flag-12", "fields": ["cable"]})[0]
    f1, f2 = tmp_path / "sites" / sid / "labels.json", tmp_path / "labels.json"
    assert a1["site"] == sid and f1.exists() and f2.exists() and str(f1) in saved and not list(tmp_path.glob("**/*.tmp"))
    assert list(json.loads(f1.read_text())["sets"]) == [a1["id"]] and list(json.loads(f2.read_text())["sets"]) == [b1["id"]]
    st2, S2, M = mk(str(tmp_path))
    assert M.sets == L.sets and M.view()["sets"][0]["site_name"] in ("Alpha", "") and len(M.sets[a1["id"]]["items"]) == 12
    assert "A-" not in M.sheet(M.sets[b1["id"]]) and "X ⇄ Y" in M.sheet(M.sets[b1["id"]])
    # μετακίνηση σε άλλον φάκελο καθαρίζει τον παλιό
    M.save_set({"id": a1["id"], "site": ""})
    assert json.loads(f1.read_text())["sets"] == {} and set(json.loads(f2.read_text())["sets"]) == {a1["id"], b1["id"]}
    f2.write_text(json.dumps({"sets": {"../x": {}, "lok": {"name": XSS, "site": "../..", "preset": "zz", "qr": "zz", "url_tpl": "javascript:x", "offset": "q",
                                                         "items": [{"name": "ok"}, 7, {}]}, "lbad": "x"}}))
    st3, S3, N = mk(str(tmp_path))
    assert set(N.sets) == {"lok"} and N.sets["lok"]["site"] == "" and N.sets["lok"]["preset"] == "a4-24" and N.sets["lok"]["url_tpl"] == ""
    assert N.sets["lok"]["items"] == [{"name": "ok"}, {"name": "7"}] and "<script" not in N.sheet(N.sets["lok"])


def test_demo_view_shape():
    st = State()
    S = s.Sites(st, demo=True, clock=lambda: NOW)
    L = lb.Labels(st, demo=True, clock=lambda: NOW, sites=S)
    v = L.view()
    assert v["demo"] is True and len(v["sets"]) == 3 and {p["id"] for p in v["presets"]} == set(lb.PRESETS) and v["site"] == "hotel-aegean"
    assert {p["id"]: p["per"] for p in v["presets"]}["a4-24"] == 24 and {p["id"]: p["per"] for p in v["presets"]}["a4-65"] == 65
    assert [f["id"] for f in v["fields"]][:3] == ["name", "ip", "mac"] and v["url_default"].endswith("/#dev={ip}")
    h = L.api("GET", "sheet", {"id": "ldemo-1"}, {})[1]["_raw"].decode()
    assert n_labels(h) == 12 and h.count("<svg") == 12 and "cam-12" in h and "Δείγμα" in h
    assert n_labels(L.api("GET", "sheet", {"id": "ldemo-3"}, {})[1]["_raw"].decode()) == 8
    json.dumps(v)
