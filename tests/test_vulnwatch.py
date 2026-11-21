"""🛡 Ευπάθειες συσκευών: CISA KEV ↔ κατασκευαστής, τίμια «πιθανόν», τίποτα για το δίκτυο δεν φεύγει."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vulnwatch  # noqa: E402

KEV = [
    {"cveID": "CVE-2023-50224", "vendorProject": "TP-Link", "product": "TL-WR841N", "vulnerabilityName": "x", "dateAdded": "2025-09-03",
     "shortDescription": "d", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2025-9377", "vendorProject": "TP-Link", "product": "Multiple Routers", "vulnerabilityName": "y", "dateAdded": "2025-09-03",
     "shortDescription": "d", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2026-1", "vendorProject": "Apple", "product": "Multiple Products", "vulnerabilityName": "z", "dateAdded": "2026-11-10",
     "shortDescription": "d", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2017-7921", "vendorProject": "Hikvision", "product": "Multiple Products", "vulnerabilityName": "h", "dateAdded": "2026-03-05",
     "shortDescription": "d", "knownRansomwareCampaignUse": "Unknown"},
]
DEVS = [
    {"ip": "192.168.1.1", "name": "TL-WR841N", "names": [], "vendor": "Tp-Link Technologies Co.,Ltd.", "dtype": "router", "gw": True},
    {"ip": "192.168.1.5", "name": "iphone", "names": [], "vendor": "Apple, Inc.", "dtype": "phone", "gw": False},
    {"ip": "192.168.1.30", "name": "ipcam", "names": [], "vendor": "Hangzhou Hikvision Digital Technology Co.,Ltd.", "dtype": "camera", "gw": False},
    {"ip": "192.168.1.50", "name": "pc", "names": [], "vendor": "Realtek Semiconductor", "dtype": "computer", "gw": False},
]


def test_match_vendor_model_and_everyday():
    hits, every = vulnwatch.match(DEVS, KEV, {"CVE-2025-9377": 0.6}, now=1795000000)
    by = {h["ip"]: h for h in hits}
    r = by["192.168.1.1"]
    assert r["vendor"] == "TP-Link" and r["count"] == 2 and r["model_match"] and r["ransomware"]
    assert r["vulns"][0]["cveID"] == "CVE-2023-50224" and r["vulns"][0]["model"]  # ταιριάζει το μοντέλο → πρώτο
    assert not by["192.168.1.30"]["model_match"]  # μόνο κατασκευαστής → «πιθανόν»
    assert "192.168.1.5" not in by and "192.168.1.50" not in by
    assert every[0]["vendor"] == "Apple" and every[0]["recent"] == 1 and every[0]["devices"] == ["iphone"]
    assert hits[0]["ip"] == "192.168.1.1"  # ο router με μοντέλο πρώτος


def test_refresh_fetches_kev_then_epss_only_cve_ids(tmp_path):
    asked = []

    def fetch(url, limit):
        asked.append(url)
        if url == vulnwatch.KEV_URL:
            return json.dumps({"catalogVersion": "2026.11.20", "vulnerabilities": KEV}).encode()
        return json.dumps({"data": [{"cve": "CVE-2023-50224", "epss": "0.7123"}]}).encode()

    class St:
        hosts = {}
    w = vulnwatch.VulnWatch(St(), str(tmp_path), fetch=fetch, clock=lambda: 1795000000)
    w.devices = lambda: DEVS
    v = w.refresh(force=True)
    assert v["count"] == 4 and v["version"] == "2026.11.20" and not v["error"]
    assert asked[0] == vulnwatch.KEV_URL and "192.168" not in asked[1] and "CVE-2023-50224" in asked[1]
    assert w.epss["CVE-2023-50224"] == 0.7123
    w2 = vulnwatch.VulnWatch(St(), str(tmp_path), fetch=lambda *a: 1 / 0)
    assert len(w2.kev) == 4  # φορτώθηκε από το data/kev.json
    assert w2.refresh()["count"] == 4  # < 1 μέρα: δεν ξανακατεβάζει


def test_network_error_keeps_old_list(tmp_path):
    class St:
        hosts = {}
    w = vulnwatch.VulnWatch(St(), str(tmp_path), fetch=lambda *a: (_ for _ in ()).throw(OSError("offline")))
    v = w.refresh(force=True)
    assert "CISA" in v["error"] and v["count"] == 0


def test_demo_has_real_entries_and_no_network():
    w = vulnwatch.VulnWatch(None, None, demo=True, fetch=lambda *a: 1 / 0)
    assert w.refresh(force=True)["demo"] and len(w.kev) == len(vulnwatch.DEMO_KEV)
