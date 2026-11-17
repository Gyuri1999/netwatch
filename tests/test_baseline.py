import collections
import threading

import baseline


class St:
    def __init__(self):
        self.lock = threading.Lock()
        self.alerts = []
        self.hosts = {
            "192.168.1.20": {"kind": "local", "mac": "24:ec:4a:cb:05:d8", "names": set(), "victims": collections.Counter({"3.1.1.1": 5})},
            "192.168.1.49": {"kind": "local", "me": True, "mac": "aa:aa:aa:aa:aa:aa", "names": set(), "victims": collections.Counter({"9.9.9.9": 1})},
            "3.1.1.1": {"kind": "public", "geo": {"countryCode": "DE", "country": "Germany", "org": "AWS"}},
            "9.9.9.9": {"kind": "public", "geo": {"countryCode": "US", "country": "USA"}},
            "5.5.5.5": {"kind": "public", "geo": {"countryCode": "RU", "country": "Russia", "org": "Evil LLC"}},
        }

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, detail))


def test_learns_then_alerts_on_new_country_for_iot(tmp_path):
    st = St()
    b = baseline.Baseline(st, str(tmp_path / "b.json"), learn=100)
    assert b.tick(now=1000) == 0  # μαθαίνει DE
    st.hosts["192.168.1.20"]["victims"]["5.5.5.5"] += 1
    assert b.tick(now=1050) == 0  # ακόμα μαθαίνει → RU μπαίνει στα γνωστά
    st.hosts["192.168.1.20"]["victims"]["9.9.9.9"] += 1
    assert b.tick(now=1200) == 1
    typ, sev, actor, target, detail = st.alerts[0]
    assert typ == "Νέα χώρα για συσκευή" and sev == "med" and actor == "192.168.1.20" and target == "9.9.9.9"
    assert "DE" in detail and "RU" in detail
    assert b.tick(now=1300) == 0  # όχι ξανά
    b2 = baseline.Baseline(st, str(tmp_path / "b.json"), learn=100)  # θυμάται μετά από restart
    assert b2.view()[0]["countries"] == ["DE", "RU", "US"] and not b2.view()[0]["learning"]


def test_ignores_this_computer():
    st = St()
    b = baseline.Baseline(st, None, learn=0)
    b.tick(now=10)
    assert all(v["ip"] != "192.168.1.49" for v in b.view())
