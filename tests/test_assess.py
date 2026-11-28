"""📋 Αναφορά «νέο δίκτυο»: συλλογή ευρημάτων από τα υπάρχοντα modules, βαθμός, εξαγωγές, routes."""
import csv
import io
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import assess  # noqa: E402
import netwatch as nw  # noqa: E402


class L2:
    def view(self):
        return {"checks": [{"id": "dhcp", "level": "bad", "el": "2 DHCP servers", "en": "2 DHCP servers"},
                           {"id": "arp", "level": "ok", "el": "ok", "en": "ok"}]}

    def run(self):
        self.ran = True


class Seg:
    def view(self):
        return {"rules": [{"from": "guest", "to": "lan", "verdict": "violation", "open": [{"ip": "192.168.1.17", "port": 445, "service": "SMB"}]},
                          {"from": "iot", "to": "lan", "verdict": "ok"}]}


class Lat:
    def status(self):
        return {"targets": [{"name": "Router", "host": "192.168.1.1", "role": "gateway", "last": {"loss": 0.2, "jitter": 3, "med": 2}},
                            {"name": "Cloudflare", "host": "1.1.1.1", "last": {"loss": 0.0, "jitter": 2, "med": 12}}]}


def _state():
    st = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    st.cfg["thresholds"]["alert_cooldown"] = 0
    t = time.time()
    for ip, mac in (("192.168.1.1", "a4:2b:b0:11:22:01"), ("192.168.1.40", "da:11:22:33:44:55"), ("192.168.1.23", "00:11:22:33:44:55")):
        h = st.host(ip, t)
        h["mac"] = mac
    st.alert("Port scan", "high", "192.168.1.50", "192.168.1.23", "x", t)
    st.l2guard, st.segcheck, st.latency = L2(), Seg(), Lat()
    st.camexp = st.encdns = st.health = st.presence = None
    return st


def test_build_collects_findings_and_scores():
    st = _state()
    d = assess.build(st, "el")
    areas = {f["area"] for f in d["findings"]}
    assert {"L2", "Κατάτμηση", "WAN", "Επιθέσεις"} <= areas
    high = [f for f in d["findings"] if f["sev"] == "high"]
    assert any("Rogue DHCP" in f["title"] for f in high) and any("guest" in f["title"] for f in high)
    assert any(f["area"] == "WAN" and f["sev"] == "high" for f in d["findings"])  # απώλεια 20% ήδη στο router
    assert d["findings"] == sorted(d["findings"], key=lambda f: -assess.SEV[f["sev"]])
    assert 0 <= d["score"] < 100 and d["grade"] in "ABCDF" and d["fixes"]
    inv = {r["ip"]: r for r in d["inventory"]}
    assert inv["192.168.1.1"]["role"] == "router" and inv["192.168.1.40"]["random_mac"] and not inv["192.168.1.1"]["random_mac"]
    en = assess.build(st, "en")
    assert any(f["area"] == "Segmentation" for f in en["findings"]) and en["title"] == "Network assessment report"


def test_missing_modules_do_not_break_and_area_cap():
    st = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    st.l2guard = st.segcheck = st.latency = st.camexp = st.encdns = st.health = st.presence = None
    d = assess.build(st)
    assert d["score"] == 100 and d["grade"] == "A" and d["findings"] == []
    st.cfg["thresholds"]["alert_cooldown"] = 0
    for i in range(10):  # 10 διαφορετικοί τύποι επιθέσεων → όριο ανά περιοχή
        st.alert(f"Τύπος {i}", "high", f"192.168.1.{60 + i}", "192.168.1.23", "x", time.time())
    d = assess.build(st)
    assert d["score"] == round(100 * __import__("math").exp(-assess.AREA_CAP / assess.DECAY))  # μία περιοχή, με όριο


def test_exports():
    d = assess.build(_state(), "el")
    html = assess.to_html(d)
    assert "<table" in html and "Rogue DHCP" in html and "<script" not in html.lower()
    rows = list(csv.reader(io.StringIO(assess.to_inventory_csv(d).lstrip("﻿"))))
    assert rows[0][:3] == ["ip", "mac", "name"] and len(rows) == len(d["inventory"]) + 1
    nb = list(csv.reader(io.StringIO(assess.to_netbox_ips_csv(d))))
    assert nb[0] == ["address", "status", "dns_name", "description"] and nb[1][0].endswith("/24") and nb[1][1] == "active"
    fr = list(csv.reader(io.StringIO(assess.to_findings_csv(d).lstrip("﻿"))))
    assert fr[0][0] == "severity" and len(fr) == len(d["findings"]) + 1
    # χωρίς HTML injection από ονόματα συσκευών
    st = _state()
    st.hosts["192.168.1.40"]["names"] = {"<img src=x onerror=alert(1)>"}
    assert "<img src=x" not in assess.to_html(assess.build(st))


def test_run_triggers_existing_checks():
    st = _state()
    a = assess.Assess(st)
    assert a.run()["ok"]
    for _ in range(100):
        if a.view()["state"] == "done":
            break
        time.sleep(0.02)
    v = a.view()
    assert v["state"] == "done" and {s["id"]: s["status"] for s in v["steps"]}["l2guard"] == "ok" and st.l2guard.ran


def _get(url, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 method="POST" if body is not None else "GET", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def test_routes():
    st = _state()
    st.assess = assess.Assess(st)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), nw.make_handler(st))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        c, _, b = _get(base + "/api/assess?lang=en")
        d = json.loads(b)
        assert c == 200 and d["lang"] == "en" and "job" in d
        assert _get(base + "/api/assess?lang=xx")[0] == 400
        c, h, b = _get(base + "/assess/report.html")
        assert c == 200 and h["Content-Type"].startswith("text/html") and b"<table" in b
        for p in ("inventory.csv", "findings.csv", "netbox-ip-addresses.csv", "report.json"):
            c, h, b = _get(base + "/assess/" + p)
            assert c == 200 and "attachment" in h["Content-Disposition"], p
        c, _, b = _get(base + "/api/assess/run", {"lang": "el"})
        assert c in (200, 409)
    finally:
        srv.shutdown()


def test_scan_findings_feed_the_score():
    """EOL και ευπαθείς υπηρεσίες από τη σάρωση γίνονται ευρήματα και ρίχνουν τον βαθμό."""
    import assess

    class S:
        mode = "live"
        me = ["192.168.1.23"]
        gateway = "192.168.1.1"
        iface = "en0"

        def scan_view(self):
            return {"status": "done", "hosts": [
                {"ip": "192.168.1.61", "services": [
                    {"port": 3306, "product": "MySQL", "version": "5.1.32", "risk": "high",
                     "eol": {"sev": "high", "date": "2013-12-31", "label": "MySQL 5.1"}},
                    {"port": 21, "svc": "FTP", "risk": "high", "why": "FTP χωρίς κρυπτογράφηση"}]},
                {"ip": "192.168.1.10", "services": [{"port": 445, "svc": "SMB", "risk": "high", "why": "SMBv1"}]}]}

        def __getattr__(self, n):
            return None

    fs = assess._scan_findings(S(), "el")
    assert any(f["area"] == "software" and "εκτός υποστήριξης" in f["title"] and f["sev"] == "high" for f in fs)
    assert any("ευπαθείς υπηρεσίες" in f["title"] and set(f["ips"]) == {"192.168.1.10", "192.168.1.61"} for f in fs)

    class Empty:
        def scan_view(self):
            return {"status": "idle"}

        def __getattr__(self, n):
            return None
    assert assess._scan_findings(Empty(), "el") == []
    assert assess._scan_findings(object(), "el") == []


def test_grade_history_one_per_day_and_persists(tmp_path):
    import assess
    p = str(tmp_path / "h.json")
    t = [1_700_000_000.0]
    a = assess.Assess(object(), clock=lambda: t[0], path=p)
    a.record(70, "C")
    a.record(74, "C")                      # ίδια μέρα → αντικαθιστά
    assert len(a.history()) == 1 and a.history()[-1]["score"] == 74
    t[0] += 86400
    a.record(82, "B")                      # νέα μέρα → νέο σημείο
    assert [x["grade"] for x in a.history()] == ["C", "B"]
    # επανεκκίνηση: διαβάζει το ιστορικό από τον δίσκο
    a2 = assess.Assess(object(), clock=lambda: t[0], path=p)
    assert [x["score"] for x in a2.history()] == [74, 82]
    assert a2.record("oops", "B") == a2.history()      # μη αριθμός αγνοείται
    # όριο 180 δειγμάτων
    for i in range(200):
        t[0] += 86400
        a2.record(50 + i % 40, "D")
    assert len(a2.history()) == 180


def test_assess_history_in_memory_without_path():
    import assess
    a = assess.Assess(object(), clock=lambda: 1_700_000_000.0)
    assert a.record(90, "A") and a.history()[-1]["grade"] == "A" and a.path is None


def test_inconclusive_arp_is_not_called_spoofing():
    class L2Quiet:
        def view(self):
            return {"checks": [{"id": "arp", "level": "warn", "inconclusive": True, "el": "Ο router 192.168.1.1 δεν απάντησε στο ARP."}]}
    st = _state()
    st.l2guard = L2Quiet()
    l2 = [f for f in assess.build(st, "el")["findings"] if f["area"] == "L2"]
    assert len(l2) == 1 and l2[0]["sev"] == "low" and "spoofing" not in l2[0]["title"] and "δεν ολοκληρώθηκε" in l2[0]["title"]


def test_your_own_tests_do_not_count_as_attacks():
    """Βρέθηκε live: μετά από σάρωση LAN η αναφορά έγραφε «Συσκευή του LAN σε θύρα backdoor» και «Σύνδεση Telnet»
    από τον ίδιο τον υπολογιστή του χρήστη. Ό,τι είναι σημαδεμένο «δική σου δοκιμή» ή «lab» δεν είναι επίθεση."""
    st = _state()
    st.l2guard = st.segcheck = st.latency = None
    st.alerts.clear()
    t = time.time()
    st.alerts.appendleft(dict(id=901, t=t, type="Κανόνας: Σύνδεση Telnet", sev="med", actor="192.168.1.23", target="192.168.1.1",
                              detail="x", selftest="η σάρωση του NetWatch (🔴 Pentest)"))
    st.alerts.appendleft(dict(id=902, t=t, type="Port scan", sev="high", actor="10.66.66.11", target="192.168.1.23", detail="x", lab=True))
    assert [f for f in assess.build(st, "el")["findings"] if f["area"] == "Επιθέσεις"] == []
    st.alerts.appendleft(dict(id=903, t=t, type="Brute force", sev="high", actor="192.168.1.66", target="192.168.1.23", detail="x"))
    att = [f for f in assess.build(st, "el")["findings"] if f["area"] == "Επιθέσεις"]
    assert len(att) == 1 and "Brute force" in att[0]["title"]       # μια πραγματική επίθεση μετρά κανονικά
