"""🗺 Τοπικός γεωεντοπισμός: καμία IP δεν φεύγει από τον υπολογιστή (πριν: όλες στο ip-api.com, χωρίς κρυπτογράφηση)."""
import glob
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import geodb  # noqa: E402
import osint  # noqa: E402


def test_database_ships_with_the_app_and_loads():
    info = geodb.info()
    assert info["ok"] and info["month"] and "DB-IP" in info["attribution"]
    with zipfile.ZipFile(geodb.DB_PATH) as z:
        assert {"meta.json", "countries.json", "asnames.json", "country4.start", "country4.cc", "asn4.start", "asn4.num",
                "country6.start", "country6.cc", "asn6.start", "asn6.num"} <= set(z.namelist())
    assert os.path.getsize(geodb.DB_PATH) < 8 * 1024 * 1024      # μένει μικρή: μπαίνει σε κάθε εγκατάσταση


def test_well_known_addresses():
    cf, goo = geodb.lookup("1.1.1.1"), geodb.lookup("8.8.8.8")
    assert cf["as"].startswith("AS13335") and "Cloudflare" in cf["isp"] and cf["status"] == "success" and cf["query"] == "1.1.1.1"
    assert goo["countryCode"] == "US" and goo["country"] == "United States" and goo["as"].startswith("AS15169")
    v6 = geodb.lookup("2606:4700:4700::1111")
    assert v6["as"].startswith("AS13335") and v6["countryCode"]


def test_private_and_bad_addresses_give_nothing():
    for ip in ("192.168.1.1", "10.0.0.5", "127.0.0.1", "169.254.1.1", "fe80::1", "224.0.0.251", "not-an-ip", "", None):
        assert geodb.lookup(ip) is None, ip


def test_position_is_country_level_stable_and_spread():
    a, b = geodb.lookup("8.8.8.8"), geodb.lookup("8.8.8.8")
    assert a == b and a["approx"] is True and a["city"] is None          # ίδια IP → ίδιο σημείο· δεν παριστάνουμε πόλη
    us = [geodb.lookup(ip) for ip in ("8.8.8.8", "8.8.4.4", "17.253.144.10", "140.82.112.3")]
    us = [g for g in us if g and g["countryCode"] == "US"]
    assert len({(g["lat"], g["lon"]) for g in us}) == len(us) >= 2       # οι κουκκίδες δεν πέφτουν η μία πάνω στην άλλη
    base = geodb.DB.countries["US"]
    assert all(abs(g["lat"] - base[1]) <= geodb.SPREAD and abs(g["lon"] - base[2]) <= geodb.SPREAD * 1.5 for g in us)


def test_country_positions_are_on_the_mainland():
    """Η πρώτη ζώνη ώρας της Αυστραλίας είναι το νησί Lord Howe (159°E), της Ρωσίας το Καλίνινγκραντ: παίρνουμε τη μεσαία."""
    c = geodb.DB.countries
    assert 113 < c["AU"][2] < 154 and -39 < c["AU"][1] < -11
    assert 30 < c["RU"][2] < 140 and c["GR"][:1] == ["Greece"] and c["GB"][0] == "United Kingdom"
    assert len(c) >= 240


def test_osint_no_longer_sends_addresses_to_a_lookup_service():
    src = open(os.path.join(ROOT, "osint.py"), encoding="utf-8").read()
    assert "ip-api.com/batch" not in src and "ip-api.com/json" not in src
    assert osint.geo_batch(["1.1.1.1", "192.168.1.1"]).keys() == {"1.1.1.1"}
    assert all(u.startswith("https://") for u in osint.PUBLIC_IP_URLS)   # η μόνη ερώτηση προς τα έξω: κρυπτογραφημένη


def test_public_ip_parser_accepts_only_real_public_addresses():
    class R:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return self.body

    assert osint.public_ip(opener=lambda req, timeout: R(b"fl=1\nip=150.140.159.190\nts=1\n")) == "150.140.159.190"
    assert osint.public_ip(opener=lambda req, timeout: R(b"203.0.113.9\n")) is None        # δεσμευμένη (documentation) διεύθυνση
    assert osint.public_ip(opener=lambda req, timeout: R(b"ip=192.168.1.5\n")) is None      # ιδιωτική: ποτέ ως «δημόσια IP»
    assert osint.public_ip(opener=lambda req, timeout: R(b"<html>login</html>")) is None    # captive portal


def test_geo_worker_fills_hosts_locally():
    import queue
    import threading

    class St:
        geo_q, lock, hosts, dirty = queue.Queue(), threading.Lock(), {"1.1.1.1": {}, "8.8.8.8": {}}, set()
    st = St()
    threading.Thread(target=osint.geo_worker, args=(st,), daemon=True).start()
    for ip in ("1.1.1.1", "8.8.8.8", "5.5.5.5"):       # η τρίτη δεν είναι γνωστός host: αγνοείται
        st.geo_q.put(ip)
    for _ in range(200):
        if len(st.dirty) == 2:
            break
        __import__("time").sleep(0.01)
    assert st.hosts["1.1.1.1"]["geo"]["as"].startswith("AS13335") and st.dirty == {"1.1.1.1", "8.8.8.8"}


def test_every_package_ships_the_geo_database():
    assert "vendor/** -text" in open(os.path.join(ROOT, ".gitattributes"), encoding="utf-8").read()   # δυαδικό: ανέγγιχτο από το git
    assert " vendor " in open(os.path.join(ROOT, "macapp", "build.sh"), encoding="utf-8").read()
    assert "COPY vendor ./vendor" in open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8").read()
    assert "geodb.py" in [os.path.basename(p) for p in glob.glob(os.path.join(ROOT, "*.py"))]
