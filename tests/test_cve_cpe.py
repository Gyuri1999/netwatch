"""🔴 CVE lookup: ταίριασμα με CPE (ακριβές) και επιστροφή σε αναζήτηση με λέξεις — χωρίς δίκτυο."""
import json
import urllib.parse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pentest  # noqa: E402


def nvd(*cves, total=None):
    """Φτιάχνει μια απάντηση NVD με τα δοσμένα (id, score, severity)."""
    vulns = []
    for cid, score, sev in cves:
        vulns.append({"cve": {"id": cid, "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": sev}}]},
                              "descriptions": [{"lang": "en", "value": f"desc {cid}"}, {"lang": "es", "value": "no"}],
                              "published": "2020-01-02T00:00:00"}})
    return json.dumps({"totalResults": total if total is not None else len(vulns), "vulnerabilities": vulns}).encode()


class FakeURL:
    """Καταγράφει κάθε URL που ζητήθηκε και απαντά από ένα λεξικό {substring: bytes} ή σηκώνει εξαίρεση."""
    def __init__(self, routes):
        self.routes, self.urls = routes, []

    def __call__(self, req, timeout=0):
        url = urllib.parse.unquote(req.full_url)    # συγκρίνουμε με το αποκωδικοποιημένο URL (τα ':' του CPE γίνονται %3A)
        self.urls.append(url)
        for key, val in self.routes.items():
            if key in url:
                if isinstance(val, Exception):
                    raise val
                return _Resp(val)
        raise AssertionError("unexpected URL: " + url)


class _Resp:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.data


def setup_function(_):
    pentest._cve_cache.clear()


def test_clean_version():
    assert pentest._clean_version("V5.7.3build 220112") == "5.7.3"
    assert pentest._clean_version("2019.78") == "2019.78"
    assert pentest._clean_version("7.0") == "7.0"
    assert pentest._clean_version("community") is None and pentest._clean_version(None) is None


def test_cpe_match_merges_vendors_and_dedupes(monkeypatch):
    # MySQL → δύο υποψήφια vendor (oracle:mysql, mysql:mysql). Ενώνει, αφαιρεί διπλά, ταξινομεί κατά CVSS.
    fake = FakeURL({
        "cpe:2.3:a:oracle:mysql:5.1.32": nvd(("CVE-2009-4484", 7.5, "HIGH"), ("CVE-SHARED", 5.0, "MEDIUM"), total=230),
        "cpe:2.3:a:mysql:mysql:5.1.32": nvd(("CVE-SHARED", 5.0, "MEDIUM"), ("CVE-2008-7247", 6.0, "MEDIUM"), total=53),
    })
    monkeypatch.setattr(pentest.urllib.request, "urlopen", fake)
    r = pentest.cve_lookup("MySQL", "5.1.32")
    assert r["matched"] == "cpe" and r["total"] == 283                     # αθροίζει τα totalResults των δύο
    ids = [c["id"] for c in r["cves"]]
    assert ids == ["CVE-2009-4484", "CVE-2008-7247", "CVE-SHARED"]          # ταξινομημένα, χωρίς διπλό CVE-SHARED
    assert all("keywordSearch" not in u for u in fake.urls)                 # δεν χρειάστηκε fallback
    assert pentest.cve_lookup("MySQL", "5.1.32") is r                       # cache


def test_falls_back_to_keyword_when_cpe_empty(monkeypatch):
    fake = FakeURL({"virtualMatchString": nvd(total=0), "keywordSearch": nvd(("CVE-KW", 9.1, "CRITICAL"))})
    monkeypatch.setattr(pentest.urllib.request, "urlopen", fake)
    r = pentest.cve_lookup("Dropbear SSH", "2019.78")
    assert r["matched"] == "keyword" and [c["id"] for c in r["cves"]] == ["CVE-KW"]
    assert any("keywordSearch" in u for u in fake.urls)


def test_unknown_product_uses_keyword_only(monkeypatch):
    fake = FakeURL({"keywordSearch": nvd(("CVE-X", 4.0, "MEDIUM"))})
    monkeypatch.setattr(pentest.urllib.request, "urlopen", fake)
    r = pentest.cve_lookup("SomeRandomDaemon", "1.2.3")
    assert r["matched"] == "keyword" and [c["id"] for c in r["cves"]] == ["CVE-X"]
    assert all("virtualMatchString" not in u for u in fake.urls)            # χωρίς CPE map → δεν δοκιμάζει CPE


def test_one_vendor_failing_does_not_break_the_other(monkeypatch):
    fake = FakeURL({"cpe:2.3:a:oracle:mysql": OSError("boom"),
                    "cpe:2.3:a:mysql:mysql": nvd(("CVE-OK", 7.0, "HIGH"), total=5)})
    monkeypatch.setattr(pentest.urllib.request, "urlopen", fake)
    r = pentest.cve_lookup("MySQL", "5.1.32")
    assert r["matched"] == "cpe" and [c["id"] for c in r["cves"]] == ["CVE-OK"]


def test_no_version_uses_keyword(monkeypatch):
    fake = FakeURL({"keywordSearch": nvd(("CVE-NV", 5.0, "MEDIUM"))})
    monkeypatch.setattr(pentest.urllib.request, "urlopen", fake)
    r = pentest.cve_lookup("MySQL", "community")                            # καμία καθαρή έκδοση → λέξεις
    assert r["matched"] == "keyword" and all("virtualMatchString" not in u for u in fake.urls)
