"""⏰ Αυτόματος έλεγχος: χρονισμός, σύνοψη, ρύθμιση, ειδοποίηση — χωρίς δίκτυο."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import scanjob  # noqa: E402

AT3 = time.mktime((2026, 11, 24, 3, 30, 0, 0, 0, -1))   # 03:30 τοπική
CFG = {"enabled": True, "every_days": 7, "hour": 3}


def test_due():
    assert scanjob.due(CFG, None, AT3) is True                       # ποτέ, σωστή ώρα
    assert scanjob.due(CFG, None, AT3 + 2 * 3600) is False           # λάθος ώρα
    assert scanjob.due(CFG, AT3 - 600, AT3) is False                 # έτρεξε ήδη σήμερα
    assert scanjob.due(CFG, AT3 - 8 * 86400, AT3) is True            # πέρασαν 8 μέρες
    assert scanjob.due(CFG, AT3 - 3 * 86400, AT3) is False           # μόνο 3 μέρες
    assert scanjob.due({"enabled": False}, None, AT3) is False


def test_next_run():
    assert scanjob.next_run({"enabled": False}, None, AT3) is None
    nr = scanjob.next_run(CFG, AT3 - 8 * 86400, AT3)
    assert nr >= AT3 and time.localtime(nr).tm_hour == 3


def test_summary_text():
    scan = {"hosts": [{"services": [{"risk": "high"}, {"eol": {"label": "MySQL 5.1"}}]}, {"services": [{"risk": "high"}]}]}
    doc = {"grade": "D", "fixes": [{"title": "Κλείσε το Telnet"}]}
    t = scanjob.summary_text(scan, doc, "el")
    assert "Βαθμός D" in t and "2 υπηρεσίες υψηλού κινδύνου" in t and "1 εκτός υποστήριξης" in t and "Κλείσε το Telnet" in t
    assert "Grade D" in scanjob.summary_text(scan, doc, "en")


class Scanner:
    def __init__(self):
        self.started = []
        self._status = "idle"

    def status(self):
        return {"status": self._status}

    def start(self, target, known=None, profile="quick", ports=None, udp=False):
        self.started.append({"target": target, "profile": profile, "udp": udp})
        self._status = "running"


class State:
    def __init__(self):
        self.scanner = Scanner()
        self.hosts = {"192.168.1.1": {"ip": "192.168.1.1", "mac": "aa:bb", "kind": "local"}}
        self.notifs = []
        self.cfg = {"lang": "el"}

    def default_scan_target(self):
        return "192.168.1.0/24"

    def scan_view(self):
        return {"status": "done", "hosts": [{"services": [{"risk": "high"}]}]}

    @property
    def notifier(self):
        st = self
        return lambda a: st.notifs.append(a)


def test_tick_triggers_scan_when_due_then_notifies(tmp_path, monkeypatch):
    st = State()
    t = [AT3]
    j = scanjob.ScanJob(st, str(tmp_path), clock=lambda: t[0])
    j.set_config({"enabled": True, "every_days": 7, "hour": 3, "profile": "top1000", "udp": True})
    monkeypatch.setattr("assess.build", lambda state, lang="el": {"grade": "C", "fixes": [{"title": "x"}]})
    j.tick()
    assert st.scanner.started and st.scanner.started[0]["profile"] == "top1000" and j.pending
    # σάρωση τελείωσε → σύνοψη + ειδοποίηση + last_run
    j.on_scan_done([{"ip": "192.168.1.1"}])
    assert not j.pending and j.last_run == AT3 and j.last_grade == "C"
    assert st.notifs and st.notifs[0]["type"] == "Αυτόματος έλεγχος ασφαλείας" and st.notifs[0]["sev"] == "high"
    # δεν ξανατρέχει την ίδια μέρα
    st.scanner._status = "idle"
    st.scanner.started.clear()
    j.tick()
    assert not st.scanner.started
    # επανεκκίνηση: διαβάζει τη ρύθμιση και το last_run
    j2 = scanjob.ScanJob(st, str(tmp_path), clock=lambda: t[0])
    assert j2.cfg["enabled"] and j2.cfg["every_days"] == 7 and j2.last_run == AT3


def test_on_scan_done_ignored_if_not_pending():
    st = State()
    j = scanjob.ScanJob(st, None, clock=lambda: AT3)
    j.on_scan_done([{"ip": "1.2.3.4"}])
    assert st.notifs == []


def test_run_now_blocked_while_running_and_bad_config():
    st = State()
    j = scanjob.ScanJob(st, None, clock=lambda: AT3)
    assert j.set_config({"enabled": True, "every_days": "x"})["error"]
    st.scanner._status = "running"
    assert j.run_now()["error"]


def test_demo_view_shape():
    j = scanjob.ScanJob(object(), demo=True)
    v = j.view()
    assert v["demo"] and v["enabled"] and v["last_grade"] == "C" and v["last_summary"]
    assert j.api("GET", "", {}, {})[0] == 200 and j.api("POST", "run", {}, {})[1]["demo"]
