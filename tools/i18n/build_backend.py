# Φτιάχνει το i18n/en-backend.js από τους πίνακες του tables.py:  .venv/bin/python tools/i18n/build_backend.py
# Template syntax (Greek side): {} -> (.+?)  {s} -> (\S+)  {d} -> (-?\d+)  {n} -> ([\d.,]+)  {*} -> (.*?)
# English side refers to groups as {1}..{9}  (written to the file as $1..$9).
import json
import re
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "i18n", "en-backend.js")
NBH = "‑"

EXACT = {}
PATS = []  # list of (regex, repl)

GROUP = {"": "(.+?)", "s": r"(\S+)", "d": r"(-?\d+)", "n": r"([\d.,]+)", "*": "(.*?)"}
PH = re.compile(r"\{(|s|d|n|\*)\}")


def fix(s):
    return s.replace("Wi-Fi", "Wi" + NBH + "Fi").replace("Man-in-the-Middle", "Man" + NBH + "in" + NBH + "the" + NBH + "Middle")


def esc(s):
    return re.sub(r"([\\.^$*+?()\[\]{}|])", r"\\\1", s)


def norm(s):
    return re.sub(r"\s+", " ", s).strip()


def X(gr, en):
    gr, en = norm(fix(gr)), fix(en)
    if gr in EXACT and EXACT[gr] != en:
        print("WARN duplicate exact with different value:", gr, file=sys.stderr)
    EXACT[gr] = en


class T:
    """A template pair (Greek pattern, English replacement)."""

    def __init__(self, gr, en):
        self.gr, self.en = re.sub(r"\s+", " ", fix(gr)), fix(en)

    @property
    def ngroups(self):
        return len(PH.findall(self.gr))

    def __add__(self, other):
        if isinstance(other, str):
            other = T(other, other)
        n = self.ngroups
        en2 = re.sub(r"\{(\d)\}", lambda m: "{%d}" % (int(m.group(1)) + n), other.en)
        return T(self.gr + other.gr, self.en + en2)

    def regex(self):
        out, pos = [], 0
        for m in PH.finditer(self.gr):
            out.append(esc(self.gr[pos:m.start()]))
            out.append(GROUP[m.group(1)])
            pos = m.end()
        out.append(esc(self.gr[pos:]))
        return "^" + "".join(out) + "$"

    def repl(self):
        return re.sub(r"\{(\d)\}", r"$\1", self.en)


def P(gr, en=None):
    t = gr if isinstance(gr, T) else T(gr, en)
    t = T(t.gr.strip(), t.en.strip())
    if t.ngroups == 0:
        X(t.gr, t.en)
        return t
    if t.ngroups > 9:
        raise SystemExit("too many groups: " + t.gr)
    PATS.append((t.regex(), t.repl()))
    return t


def R(rx, repl):
    PATS.append((fix(rx), fix(repl)))


def XP(gr, en):
    """Exact entry + its use as a building block."""
    X(gr, en)
    return T(gr.replace("{", "{{").replace("}", "}}") if False else gr, en)


exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "tables.py"), encoding="utf-8").read())

# sanity: every pattern must compile in Python and be anchored
for rx, to in PATS:
    re.compile(rx)
    assert rx.startswith("^") and rx.endswith("$"), rx

data = {"exact": EXACT, "patterns": [list(p) for p in PATS]}
body = json.dumps(data, ensure_ascii=False, indent=1)
with open(OUT, "w", encoding="utf-8") as f:
    f.write("// en-backend — English for text produced by the Python backend (alerts, audit, IoT, Wi‑Fi Guard, privacy,\n"
            "// health, playbooks, API errors, weekly report, CTF). Generated; see i18n/README.md for the format.\n")
    f.write("I18N.add(" + body + ");\n")
print(len(EXACT), "exact,", len(PATS), "patterns")
