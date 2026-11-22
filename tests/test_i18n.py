"""Μετάφραση στο backend (ειδοποιήσεις) με τα ίδια λεξικά με τον browser."""
import json
import os

import i18n

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _write(tmp_path, name, d):
    (tmp_path / name).write_text("// σχόλιο\nI18N.add(" + json.dumps(d, ensure_ascii=False) + ");\n", encoding="utf-8")


def test_exact_and_patterns(tmp_path, monkeypatch):
    _write(tmp_path, "en-backend.js", {"exact": {"Σάρωση θυρών": "Port scan"},
                                       "patterns": [["^Ο (\\S+) σκάναρε (\\d+) θύρες$", "$1 scanned $2 ports"]]})
    monkeypatch.setattr(i18n, "_cache", i18n.load(str(tmp_path)))
    assert i18n.tr("Σάρωση  θυρών ", "en") == "Port scan"
    assert i18n.tr("Ο 10.0.0.5 σκάναρε 44 θύρες", "en") == "10.0.0.5 scanned 44 ports"
    assert i18n.tr("Ο 10.0.0.5 σκάναρε 44 θύρες", "el") == "Ο 10.0.0.5 σκάναρε 44 θύρες"
    assert i18n.tr("άγνωστο κείμενο", "en") == "άγνωστο κείμενο"  # χωρίς μετάφραση → ίδιο
    assert i18n.tr("already english", "en") == "already english"


def test_repo_dictionaries_are_valid():
    """Τα i18n/*.js πρέπει να διαβάζονται ως JSON και όλα τα patterns να είναι έγκυρα regex Python."""
    import re
    d = os.path.join(HERE, "i18n")
    for f in os.listdir(d):
        if not f.endswith(".js") or f == "edu-en.js":
            continue
        s = open(os.path.join(d, f), encoding="utf-8").read()
        data = json.loads(s[s.index("{"): s.rindex("}") + 1])
        for pat, _ in data.get("patterns", []):
            assert pat.startswith("^") and pat.endswith("$"), (f, pat)
            re.compile(pat)


def test_notifier_translates(monkeypatch):
    from storage import Notifier
    sent = []
    n = Notifier({"lang": "en", "macos": False})
    monkeypatch.setattr(i18n, "_cache", ({"Δοκιμή": "Test"}, []))
    monkeypatch.setattr(n, "_telegram", lambda title, body, sev: sent.append((title, body)) or True, raising=False)
    monkeypatch.setattr(n, "_ntfy", lambda *a: False, raising=False)
    n.cfg["telegram"] = {"token": "x", "chat_id": "y"}
    n._send({"type": "Δοκιμή", "sev": "high", "actor": "1.2.3.4", "target": "5.6.7.8", "detail": "Δοκιμή"})
    # headline = εικονίδιο σοβαρότητας + μεταφρασμένος τύπος· σώμα = μεταφρασμένη εξήγηση (χωρίς «IP → IP:»)
    assert sent and sent[0][0] == "🔴 Test" and sent[0][1] == "Test"
