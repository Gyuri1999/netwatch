"""🔴 Ανίχνευση λογισμικού εκτός υποστήριξης (EOL) στη σάρωση — χωρίς δίκτυο."""
import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pentest  # noqa: E402

TODAY = datetime.date(2026, 11, 24)


def test_flags_end_of_life_versions():
    r = pentest.eol_check("MySQL", "5.1.32", today=TODAY)
    assert r["sev"] == "high" and r["date"] == "2013-12-31" and r["years"] == 12 and "5.1" in r["label"]
    # IIS δείχνει τον κύκλο ζωής του Windows Server
    assert pentest.eol_check("Microsoft IIS", "7.0", today=TODAY)["label"].startswith("Windows Server 2008")
    assert pentest.eol_check("Apache httpd", "2.2.15", today=TODAY)["sev"] == "high"


def test_longest_matching_prefix_wins():
    # 5.7 δεν πρέπει να ταιριάξει με το «5.» ή «5.1» — πιάνει το ακριβές 5.7
    r = pentest.eol_check("MySQL", "5.7.44", today=TODAY)
    assert r["date"] == "2023-10-31" and "5.7" in r["label"]


def test_severity_by_age():
    just_eol = pentest.eol_check("MySQL", "5.7.0", today=datetime.date(2024, 1, 1))     # ~2 μήνες μετά
    assert just_eol["sev"] == "med" and just_eol["years"] == 0
    old = pentest.eol_check("MySQL", "5.7.0", today=datetime.date(2027, 1, 1))           # >3 χρόνια
    assert old["sev"] == "high"


def test_supported_and_unknown_return_none():
    assert pentest.eol_check("MySQL", "8.0.35", today=TODAY) is None          # ακόμη υποστηρίζεται
    assert pentest.eol_check("Microsoft IIS", "10.0", today=TODAY) is None
    assert pentest.eol_check("OpenSSH", "9.1", today=TODAY) is None           # δεν είναι στον πίνακα
    assert pentest.eol_check("MySQL", "community", today=TODAY) is None       # χωρίς αριθμό έκδοσης
    assert pentest.eol_check("MySQL", None, today=TODAY) is None
    # ακριβώς την ημέρα του EOL δεν είναι ακόμη «ληγμένο», την επομένη ναι
    assert pentest.eol_check("MySQL", "5.1.0", today=datetime.date(2013, 12, 31)) is None   # η ημέρα EOL = ακόμη υποστήριξη
    assert pentest.eol_check("MySQL", "5.1.0", today=datetime.date(2014, 1, 1))["years"] == 0


def test_enrich_attaches_eol_finding(monkeypatch):
    """Το _enrich (τρέχει σε demo ΚΑΙ σε πραγματική σάρωση) βάζει εύρημα EOL· το apply_findings ανεβάζει το ρίσκο."""
    s = pentest.LanScanner.__new__(pentest.LanScanner)
    monkeypatch.setattr(s, "_set", lambda **k: None, raising=False)
    import netkit
    monkeypatch.setattr(netkit, "discover_names", lambda ips, timeout=2, sim=False: {})
    monkeypatch.setattr(netkit, "mac_vendor", lambda mac: None)
    monkeypatch.setattr(netkit, "ping", lambda ip, **k: {})
    hosts = [{"ip": "192.168.1.9", "mac": "aa:bb:cc:dd:ee:ff",
              "services": [{"port": 3306, "proto": "tcp", "product": "MySQL", "version": "5.1.32", "banner": "5.1.32-community"}]}]
    s._enrich(hosts, udp=False, sim=False)
    sv = hosts[0]["services"][0]
    assert sv.get("eol") and sv["eol"]["label"].startswith("MySQL 5.1")
    assert any(sev in ("high", "med") and "Εκτός υποστήριξης" in msg for sev, msg in sv["findings"])
    view = pentest.apply_findings({"hosts": hosts})
    assert view["hosts"][0]["risk"] == "high" and "Εκτός υποστήριξης" in view["hosts"][0]["services"][0]["why"]
