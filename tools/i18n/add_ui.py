"""Προσθέτει μεταφράσεις στο i18n/en-ui.js: python tools/i18n/add_ui.py new.json  (new.json = {"exact":{…},"patterns":[…]})"""
import json, pathlib, sys

P = pathlib.Path(__file__).resolve().parents[2] / "i18n" / "en-ui.js"


def add(new):
    s = P.read_text()
    a, b = s.index("{"), s.rindex("}") + 1
    d = json.loads(s[a:b])
    d["exact"].update(new.get("exact", {}))
    have = {p[0] for p in d["patterns"]}
    d["patterns"] += [p for p in new.get("patterns", []) if p[0] not in have]
    P.write_text(s[:a] + json.dumps(d, ensure_ascii=False, indent=1) + s[b:])
    return len(d["exact"]), len(d["patterns"])


if __name__ == "__main__":
    print(add(json.load(open(sys.argv[1]))))
