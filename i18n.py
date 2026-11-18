"""Μετάφραση κειμένων του backend (ειδοποιήσεις macOS / Telegram / ntfy) με τα ίδια λεξικά που χρησιμοποιεί ο browser.

Τα i18n/*.js έχουν τη μορφή  I18N.add({ "exact": {...}, "patterns": [[regex, replacement], ...] });
— το JSON ανάμεσα στο πρώτο «{» και το τελευταίο «}» διαβάζεται κι από εδώ. Στα patterns το $1 γίνεται \\g<1>.
config.yaml:  lang: en   (προεπιλογή el)
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
GREEK = re.compile(r"[\u0370-\u03ff\u1f00-\u1fff]")
_cache = None


def _norm(s):
    return re.sub(r"\s+", " ", s).strip()


def load(folder=None):
    exact, pats = {}, []
    folder = folder or os.path.join(HERE, "i18n")
    for f in ("en-backend.js", "en-ui.js"):
        p = os.path.join(folder, f)
        if not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8") as fh:
            s = fh.read()
        try:
            d = json.loads(s[s.index("{"): s.rindex("}") + 1])
        except ValueError:
            continue
        for k, v in (d.get("exact") or {}).items():
            exact.setdefault(_norm(k), v)
        for re_s, to in d.get("patterns") or []:
            try:
                pats.append((re.compile(re_s), to))
            except re.error:
                pass
    return exact, pats


def tr(text, lang="en"):
    global _cache
    if lang != "en" or not text or not GREEK.search(str(text)):
        return text
    if _cache is None:
        _cache = load()
    exact, pats = _cache
    k = _norm(str(text))
    if k in exact:
        return exact[k]
    for rx, to in pats:
        m = rx.search(k)
        if m:
            def grp(g, m=m):  # ό,τι «πιάνει» το pattern μεταφράζεται κι αυτό αν είναι ελληνικό
                v = m.group(int(g.group(1)))
                return "" if v is None else (tr(v, lang) if v != k and GREEK.search(v) else v)
            return k[:m.start()] + re.sub(r"\$(\d)", grp, to) + k[m.end():]
    return text
