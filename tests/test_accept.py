import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import accept as a  # noqa: E402
import sites as s  # noqa: E402

NOW = time.mktime((2026, 3, 15, 12, 0, 0, 0, 0, -1))
XSS = '<script>alert(1)</script>'


class State:
    gateway = "192.168.1.1"

    def __init__(self):
        self.hosts = {"192.168.1.1": {"ip": "192.168.1.1", "kind": "local", "names": {"router"}, "mac": "aa:bb:cc:00:00:01"},
                      "192.168.1.30": {"ip": "192.168.1.30", "kind": "local", "names": {"cam-1"}, "mac": "aa:bb:cc:00:00:30"},
                      "192.168.1.31": {"ip": "192.168.1.31", "kind": "local", "names": {"cam-2"}, "mac": "aa:bb:cc:00:00:31"},
                      "192.168.1.50": {"ip": "192.168.1.50", "kind": "local", "names": {"pc"}, "mac": "aa:bb:cc:00:00:50"},
                      "1.2.3.4": {"ip": "1.2.3.4", "kind": "public", "names": set(), "mac": None}}

    def _dtype(self, h):
        return {"dtype": "camera" if h["ip"][-2:] in ("30", "31") else "router" if h["ip"].endswith(".1") else "computer"}


class Run:
    """Ψεύτικοι αυτόματοι έλεγχοι: ό,τι δεν είναι στο `bad` περνά."""
    def __init__(self, bad=(), none=()):
        self.bad, self.none, self.calls = set(bad), set(none), []

    def __call__(self, fn, target, arg):
        self.calls.append((fn, target, arg))
        if fn == "boom":
            raise RuntimeError("x")
        k = (fn, target, arg)
        return {"ok": None if k in self.none else k not in self.bad, "value": f"{fn}:{target}:{arg}", "note": "n" + XSS}


def mk(tmp=None, run=None, st=None):
    st = st or State()
    S = s.Sites(st, tmp, clock=lambda: NOW)
    return S, a.Accept(st, tmp, clock=lambda: NOW, sites=S, run=run or Run())


def test_verdict_logic():
    assert a.verdict([]) == "pending" and a.verdict(["na", "na"]) == "pending"
    assert a.verdict(["pass", "na"]) == "pass" and a.verdict(["pass", "pending"]) == "pending"
    assert a.verdict(["pass", "pending", "fail"]) == "fail"
    job = {"points": [{"checks": [{"status": "pass"}]}, {"checks": [{"status": "pending"}]}]}
    assert a.summarize(job)["verdict"] == "pending" and a.summarize({"points": []})["verdict"] == "pending"
    job["points"][1]["checks"][0]["status"] = "na"
    assert a.summarize(job)["verdict"] == "pending"  # σημείο μόνο με «δεν αφορά» δεν έχει ελεγχθεί
    job["points"][1]["checks"].append({"status": "pass"})
    assert a.summarize(job) == {"checks": {"pending": 0, "pass": 2, "fail": 0, "na": 1}, "pts": {"pass": 2, "fail": 0, "pending": 0},
                                "total_points": 2, "verdict": "pass"}
    job["points"][0]["checks"][0]["status"] = "fail"
    assert a.summarize(job)["verdict"] == "fail"


def test_types_have_auto_and_manual_checks():
    assert set(a.TYPES) == {"socket", "ap", "camera", "switch", "iot", "uplink"}
    for k, t in a.TYPES.items():
        ids = [c["id"] for c in t[3]]
        assert len(ids) == len(set(ids)) and any(c["kind"] == "manual" for c in t[3]) and any(c["kind"] == "auto" for c in t[3])
        assert all(c["fn"] in a.AUTO_FNS for c in t[3] if c["kind"] == "auto") and all(c["el"] and c["en"] for c in t[3])
    assert a.parse_media("\tmedia: autoselect (1000baseT <full-duplex>)\n") == 1000
    assert a.parse_media("media: 10Gbase-T <full-duplex>") == 10000 and a.parse_media("media: autoselect\nstatus: active") is None
    assert a.link_speed("en0; rm -rf /") is None and a.link_speed("") is None


def test_job_lifecycle_with_fake_run():
    run = Run(bad={("tcp", "192.168.1.30", "554")}, none={("link", "", "1000")})
    S, A = mk(run=run)
    j, err = A.new_job("Κάμερες " + XSS)
    assert not err and a.JOB_RE.match(j["id"]) and j["site"] == "" and A.new_job("x", site="nosuch")[1]
    jid = j["id"]
    cam, err = A.add_point(jid, "camera", "cam-1", "192.168.1.30", "Είσοδος")
    assert not err and [c["id"] for c in cam["checks"]][:3] == ["ping", "rtsp", "web"]
    assert A.add_point(jid, "camera", "x", "8.8.8.8")[1] and A.add_point(jid, "camera", "x", "999.1.1.1")[1]
    assert A.add_point(jid, "toaster", "x")[1] and A.add_point("nosuch", "socket", "x")[1]
    sock, _ = A.add_point(jid, "socket", "A-01")
    assert A.job_view(jid)["verdict"] == "pending" and A.view()["counts"] == {"jobs": 1, "open": 1, "fail": 0, "pending": 18}
    assert A.run_checks(jid) == 7 and ("tcp", "192.168.1.30", "554") in run.calls and ("dhcp", "", "") in run.calls
    v = A.job_view(jid)
    st = {(p["label"], c["id"]): c for p in v["points"] for c in p["checks"]}
    assert st[("cam-1", "ping")]["status"] == "pass" and st[("cam-1", "rtsp")]["status"] == "fail" and st[("cam-1", "rtsp")]["value"] == "tcp:192.168.1.30:554"
    assert st[("A-01", "link")]["status"] == "pending" and st[("A-01", "link")]["note"].startswith("n")  # ok=None → μένει εκκρεμές
    assert v["verdict"] == "fail" and v["pts"] == {"pass": 0, "fail": 1, "pending": 1}
    # χειροκίνητα: ο τεχνικός τσεκάρει, διορθώνει και αυτόματο με το χέρι
    assert A.set_check(jid, cam["id"], "rtsp", "bogus")[1] and A.set_check(jid, cam["id"], "nosuch", "pass")[1]
    for p in v["points"]:
        for c in p["checks"]:
            if c["status"] != "pass":
                assert not A.set_check(jid, p["id"], c["id"], "na" if c["id"] == "night" else "pass", "6.5" if c["id"] == "poe" else None, "ok")[1]
    v = A.job_view(jid)
    assert v["verdict"] == "pass" and v["checks"]["na"] == 1 and v["checks"]["pending"] == 0
    # δικός του έλεγχος → ξανά εκκρεμές· ένας μόνο έλεγχος τρέχει μόνος του
    c, err = A.add_check(jid, sock["id"], "Καπάκι πρίζας", "")
    assert not err and c["kind"] == "manual" and A.job_view(jid)["verdict"] == "pending" and A.add_check(jid, sock["id"], "")[1]
    A.set_check(jid, sock["id"], c["id"], "pass")
    n = len(run.calls)
    assert A.run_checks(jid, cam["id"], "ping") == 1 and len(run.calls) == n + 1
    # κλειστή εργασία δεν αλλάζει· ξανανοίγει
    assert A.close_job(jid)[0]["closed"] == NOW and A.add_point(jid, "socket", "A-02")[1] and A.run_checks(jid) == 0
    assert A.set_check(jid, sock["id"], "label", "fail")[1] and A.start_run(jid)
    assert A.close_job(jid, False)[0]["closed"] is None and not A.delete_point(jid, sock["id"])[1]
    assert A.job_view(jid)["total_points"] == 1 and A.delete_job(jid) and not A.delete_job(jid) and A.job_view(jid) is None


def test_runner_exception_does_not_stop_others():
    S, A = mk()
    jid = A.new_job("x")[0]["id"]
    p = A.add_point(jid, "iot", "plug", "192.168.1.60")[0]
    A.jobs[jid]["points"][0]["checks"].insert(0, {"id": "b", "kind": "auto", "fn": "boom", "arg": "", "el": "b", "en": "b", "unit": "",
                                                  "status": "pending", "value": "", "note": "", "t": 0})
    assert A.run_checks(jid) == 2
    cs = A.job_view(jid)["points"][0]["checks"]
    assert cs[0]["status"] == "pending" and "Σφάλμα" in cs[0]["note"] and cs[1]["status"] == "pass" and p["id"] == "p1"


def test_bulk_numbering_and_import():
    S, A = mk()
    jid = A.new_job("Πρίζες")[0]["id"]
    assert A.bulk_add(jid, "socket", "A-01..A-24", "1ος") == (24, None)
    pts = A.job_view(jid)["points"]
    assert [p["label"] for p in pts][:2] == ["A-01", "A-02"] and pts[-1]["label"] == "A-24" and len({p["id"] for p in pts}) == 24
    assert pts[0]["location"] == "1ος" and pts[0]["type"] == "socket"
    for bad in ("", "A-09..A-01", "A-01..B-05", "x..y", "A-1..A-5000"):
        n, err = A.bulk_add(jid, "socket", bad)
        assert n == 0 and err
    assert A.bulk_add(jid, "nosuch", "B-1..B-2")[1] and len(A.job_view(jid)["points"]) == 24  # τίποτα μισό
    assert A.bulk_add(jid, "ap", "AP-8..AP-10")[0] == 3 and A.job_view(jid)["points"][-1]["label"] == "AP-10"
    # από γνωστές συσκευές: ανά τύπο, χωρίς διπλές, μόνο τοπικές
    assert {d["ip"]: d["suggest"] for d in A.devices()} == {"192.168.1.1": "switch", "192.168.1.30": "camera", "192.168.1.31": "camera", "192.168.1.50": ""}
    assert A.import_devices(jid, dtypes=["camera"]) == (2, None) and A.import_devices(jid, dtypes=["camera"]) == (0, None)
    assert A.import_devices(jid) == (0, None) and A.import_devices(jid, ips=["192.168.1.1", "1.2.3.4"]) == (1, None)
    got = {p["ip"]: p["type"] for p in A.job_view(jid)["points"] if p["ip"]}
    assert got == {"192.168.1.30": "camera", "192.168.1.31": "camera", "192.168.1.1": "switch"}


def test_report_html_and_escaping():
    S, A = mk(run=Run(bad={("ping", "192.168.1.30", "")}))
    S._set_company({"name": "ACME " + XSS, "tech": "Τεχνικός"})
    sid = S.save_site({"name": "Πελάτης " + XSS, "address": "Οδός " + XSS, "from_current": True})[0]["id"]
    j = A.new_job("Έργο " + XSS)[0]
    assert j["site"] == sid and j["tech"] == "Τεχνικός"  # τρέχων πελάτης + τεχνικός από τα στοιχεία εταιρείας
    jid = j["id"]
    p = A.add_point(jid, "camera", "cam " + XSS, "192.168.1.30", "loc " + XSS)[0]
    A.run_checks(jid)
    A.set_check(jid, p["id"], "poe", "pass", "6.4", "σημ " + XSS)
    A.save_job(jid, {"remarks": "Εκκρεμεί " + XSS, "rep": "κα " + XSS, "place": "Αθήνα"})
    code, doc = A.api("GET", "report", {"id": jid}, {})
    h = doc["_raw"].decode()
    assert code == 200 and doc["_type"].startswith("text/html") and doc["_name"].endswith(".html")
    assert "<script" not in h.lower() and h.count("&lt;script&gt;") >= 8
    assert "Πρωτόκολλο ελέγχου" in h and "ΜΗ ΑΠΟΔΕΚΤΗ" in h and "ΑΠΕΤΥΧΕ" in h and "ΕΚΚΡΕΜΕΙ" in h and "6.4 W" in h and "size:A4" in h
    assert "Παρατηρήσεις / εκκρεμότητες" in h and h.count('class="box"') == 2 and "Για τον πελάτη" in h and "Αθήνα" in h and "ACME" in h
    en = A.report_html(jid, "en")
    assert "Installation test &amp; acceptance report" in en and "NOT ACCEPTED YET" in en and "RTSP video stream" in en and "For the customer" in en
    assert A.api("GET", "report", {"id": "nosuch"}, {})[0] == 404 and A.report_html(None) is None


def test_api_routes():
    S, A = mk()
    assert A.api("GET", "", {}, {}) == (200, A.view()) and A.api("GET", "x", {}, {}) == (404, {"error": "not found"})
    assert A.api("POST", "x", {}, {})[0] == 404 and A.api("GET", "job", {"id": "x"}, {})[0] == 404
    code, v = A.api("POST", "job/new", {}, {"title": "T", "site": ""})
    jid = v["job"]["id"]
    assert code == 200 and v["jobs"][0]["id"] == jid and A.api("GET", "job", {"id": jid}, {})[1]["title"] == "T"
    code, v = A.api("POST", "point/add", {}, {"job": jid, "type": "ap", "label": "ap-1", "ip": "192.168.1.9"})
    pid = v["job"]["points"][0]["id"]
    assert code == 200 and A.api("POST", "point/add", {}, {"job": jid, "type": "ap", "ip": "8.8.8.8"})[0] == 400
    assert A.api("POST", "point/bulk", {}, {"job": jid, "type": "socket", "pattern": "S1..S3"})[1]["job"]["total_points"] == 4
    r = A.api("POST", "point/bulk", {}, {"job": jid, "type": "socket", "pattern": "S9..S1"})
    assert r[0] == 400 and r[1]["error"] and r[1]["error_en"]
    assert A.api("POST", "check", {}, {"job": jid, "point": pid, "check": "poe", "status": "pass", "value": "11"})[1]["job"]["points"][0]["checks"][2]["value"] == "11"
    assert A.api("POST", "check/add", {}, {"job": jid, "point": pid, "el": "Βάση στήριξης"})[0] == 200
    assert A.api("POST", "run", {}, {"job": jid, "point": pid})[0] == 200
    for _ in range(200):
        if not A.busy:
            break
        time.sleep(0.01)
    assert A.job_view(jid)["points"][0]["checks"][0]["status"] == "pass"
    assert A.api("POST", "job/save", {}, {"job": jid, "title": "Νέος"})[1]["job"]["title"] == "Νέος"
    assert A.api("POST", "job/close", {}, {"job": jid})[1]["job"]["closed"] and A.api("POST", "point/delete", {}, {"job": jid, "point": pid})[0] == 400
    assert A.api("POST", "job/close", {}, {"job": jid, "closed": False})[1]["job"]["closed"] is None
    assert A.api("POST", "point/delete", {}, {"job": jid, "point": pid})[1]["job"]["total_points"] == 3
    assert A.api("POST", "job/delete", {}, {"job": jid})[1]["jobs"] == [] and A.api("POST", "job/delete", {}, {"job": jid})[0] == 404


def test_persistence_per_site_folder(tmp_path):
    S, A = mk(str(tmp_path))
    saved = []
    A.on_save = saved.append
    sid = S.save_site({"name": "Alpha", "from_current": True})[0]["id"]
    j1 = A.new_job("Στον πελάτη")[0]["id"]
    j2 = A.new_job("Χωρίς πελάτη", site="")[0]["id"]
    p = A.add_point(j1, "camera", "cam", "192.168.1.30")[0]
    A.run_checks(j1)
    A.set_check(j1, p["id"], "fov", "fail", None, "να γυρίσει δεξιά")
    f1, f2 = tmp_path / "sites" / sid / "accept.json", tmp_path / "accept.json"
    assert f1.exists() and f2.exists() and str(f1) in saved and list(json.loads(f1.read_text())["jobs"]) == [j1]
    assert list(json.loads(f2.read_text())["jobs"]) == [j2] and not list(tmp_path.glob("**/*.tmp"))
    S2, B = mk(str(tmp_path))
    assert set(B.jobs) == {j1, j2} and B.job_view(j1) == A.job_view(j1) and B.job_view(j1)["site_name"] == "Alpha"
    assert B.job_view(j1)["points"][0]["checks"][3]["note"] == "να γυρίσει δεξιά"
    # πειραγμένο/χαλασμένο αρχείο δεν ρίχνει τίποτα
    f2.write_text(json.dumps({"jobs": {"../x": {}, "jok-1": {"title": XSS, "site": "../../etc", "points": [{"type": "nope", "checks": [{"kind": "auto", "fn": "rm"}, 5]}, "x"]}}}))
    f1.write_text("{not json")
    S3, C = mk(str(tmp_path))
    v = C.job_view("jok-1")
    assert set(C.jobs) == {"jok-1"} and v["site"] == "" and v["points"][0]["type"] == "socket" and v["points"][0]["checks"][0]["kind"] == "manual"


def test_demo_view_shape():
    st = State()
    S = s.Sites(st, demo=True, clock=lambda: NOW)
    A = a.Accept(st, demo=True, clock=lambda: NOW, sites=S)
    v = A.view()
    assert v["demo"] is True and len(v["jobs"]) == 2 and len(v["types"]) == 6 and v["site"] == "hotel-aegean"
    done = next(j for j in v["jobs"] if j["closed"])
    prog = next(j for j in v["jobs"] if not j["closed"])
    assert done["verdict"] == "fail" and 1 <= done["checks"]["fail"] <= 5 and done["checks"]["pending"] == 0 and done["site_name"]
    assert prog["verdict"] == "pending" and prog["checks"]["pass"] and prog["checks"]["pending"]
    assert A.run is a.demo_run and A.run_checks(prog["id"]) > 0  # demo: ψεύτικα αποτελέσματα, καθόλου δίκτυο
    assert "cam-12" in A.report_html(done["id"]) and "<script" not in A.report_html(done["id"], "en")
    json.dumps(v), json.dumps(A.job_view(done["id"]))
