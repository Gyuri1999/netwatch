"""📄 Έγγραφα έργου: CHANGELOG και SECURITY υπάρχουν, λένε τα βασικά και συνδέονται από τα README."""
import os
import re

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _read(name):
    return open(os.path.join(ROOT, name), encoding="utf-8").read()


def test_changelog_lists_releases_newest_first():
    log = _read("CHANGELOG.md")
    vers = re.findall(r"^## (\d+\.\d+\.\d+) — \d{4}-\d{2}-\d{2}$", log, flags=re.M)
    assert vers[:4] == ["1.17.1", "1.17.0", "1.16.3", "1.16.2"]
    assert vers == sorted(vers, key=lambda v: tuple(map(int, v.split("."))), reverse=True)
    assert log.index("## Unreleased") < log.index("## 1.17.1") < log.index("## 1.17.0") and "Releases page" in log


def test_security_policy_says_how_to_report_and_what_leaves_the_computer():
    sec = _read("SECURITY.md")
    assert "Report a vulnerability" in sec and "security/advisories/new" in sec
    assert "not** open a public issue" in sec                  # όχι λεπτομέρειες δημόσια
    assert "## What NetWatch sends out" in sec and "ip-api.com" in sec   # ειλικρινής λίστα, όχι «τίποτα δεν φεύγει»
    assert "@" not in sec.replace("@Gyuri1999", "")            # καμία προσωπική διεύθυνση email στο δημόσιο αρχείο


def test_readmes_link_to_both():
    for name in ("README.md", "README.el.md"):
        s = _read(name)
        assert "(SECURITY.md)" in s and "(CHANGELOG.md)" in s, name


def test_app_does_not_claim_that_nothing_leaves_the_computer():
    """Η εφαρμογή στέλνει δημόσιες IP για γεωεντοπισμό και ελέγχει για ενημέρωση: το λέμε, δεν γράφουμε «τίποτα δεν φεύγει»."""
    s = _read("golive.js")
    assert "Τίποτα δεν φεύγει από τον υπολογιστή σου" not in s and "Nothing leaves your computer" not in s
    assert "γεωεντοπισμός" in s and "geolocation" in s and "ούτε κωδικούς" in s
