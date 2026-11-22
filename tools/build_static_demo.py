#!/usr/bin/env python3
"""Χτίζει το στατικό online demo του NetWatch (για GitHub Pages) στο dist-pages/.

    .venv/bin/python tools/record_static_demo.py      # 1. καταγραφή demo → build/static-demo/
    python3 tools/build_static_demo.py                # 2. dist-pages/
    python3 -m http.server 8791 -d dist-pages         # 3. δοκιμή: http://127.0.0.1:8791/

Δεν αλλάζει κανένα αρχείο της εφαρμογής: αντιγράφει index.html / edu.js / academy/*.js και
βάζει στο αντίγραφο του index.html το demo-data.js + demo-shim.js πριν από τα άλλα scripts.
"""
import argparse
import glob
import json
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rec", default=os.path.join(ROOT, "build", "static-demo"), help="φάκελος καταγραφής")
    ap.add_argument("--out", default=os.path.join(ROOT, "dist-pages"))
    ap.add_argument("--repo-url", default="", help="σύνδεσμος του banner (αλλιώς μαντεύεται από το *.github.io URL)")
    args = ap.parse_args()

    rec_path = os.path.join(args.rec, "recording.json")
    if not os.path.isfile(rec_path):
        sys.exit(f"Δεν βρέθηκε {rec_path} — τρέξε πρώτα tools/record_static_demo.py")
    with open(rec_path, encoding="utf-8") as f:
        rec = json.load(f)
    if rec.get("mode") != "demo" or (rec.get("api", {}).get("/api/status") or {}).get("mode") != "demo":
        sys.exit("ΑΡΝΗΣΗ: η καταγραφή δεν προέρχεται από λειτουργία demo.")
    rec["repo_url"] = args.repo_url

    out = os.path.abspath(args.out)
    if os.path.basename(out) != "dist-pages" and os.path.exists(out) and os.listdir(out):
        sys.exit(f"Το {out} δεν είναι άδειο και δεν λέγεται dist-pages — δεν το σβήνω.")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(os.path.join(out, "academy"))

    # index.html: shim πριν από τα scripts, τοπικά src="/x" → src="x" (το Pages σερβίρει κάτω από /<repo>/).
    with open(os.path.join(ROOT, "index.html"), encoding="utf-8") as f:
        html = f.read()
    html = re.sub(r'(<script\b[^>]*\bsrc=")/(?!/)', r"\1", html)
    inject = '<script src="demo-data.js"></script>\n<script src="demo-shim.js"></script>\n'
    # προεπισκόπηση link (LinkedIn, Viber, Slack…): θέλει απόλυτο URL — στο GitHub Actions το ξέρουμε από το repo
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo and os.path.isfile(os.path.join(ROOT, "docs", "og.png")):
        owner, name = repo.split("/", 1)
        site = f"https://{owner.lower()}.github.io/{name}/"
        inject += (f'<meta property="og:title" content="NetWatch — network monitor & IDS for the home lab">\n'
                   f'<meta property="og:description" content="Live online demo (simulated traffic): live map, technician toolkit, Wireshark notes, IoT/MQTT security, CCNA academy.">\n'
                   f'<meta property="og:type" content="website">\n<meta property="og:url" content="{site}">\n'
                   f'<meta property="og:image" content="{site}og.png">\n<meta property="og:image:width" content="1200">\n'
                   f'<meta property="og:image:height" content="630">\n<meta name="twitter:card" content="summary_large_image">\n')
    i = html.find("<script")
    if i < 0:
        sys.exit("Δεν βρέθηκε <script> στο index.html")
    html = html[:i] + inject + html[i:]
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)

    shutil.copy2(os.path.join(ROOT, "edu.js"), out)
    shutil.copy2(os.path.join(ROOT, "wireshark.js"), out)
    shutil.copy2(os.path.join(ROOT, "infra.js"), out)
    shutil.copy2(os.path.join(ROOT, "sectools.js"), out)
    shutil.copy2(os.path.join(ROOT, "privtools.js"), out)
    shutil.copy2(os.path.join(ROOT, "protocols.js"), out)
    shutil.copy2(os.path.join(ROOT, "ciscolab.js"), out)
    shutil.copy2(os.path.join(ROOT, "uiplus.js"), out)
    shutil.copy2(os.path.join(ROOT, "pentestui.js"), out)
    shutil.copy2(os.path.join(ROOT, "socui.js"), out)
    shutil.copy2(os.path.join(ROOT, "worktools.js"), out)
    shutil.copy2(os.path.join(ROOT, "opstools.js"), out)
    shutil.copy2(os.path.join(ROOT, "cmdxlate.js"), out)
    shutil.copy2(os.path.join(ROOT, "navplus.js"), out)
    shutil.copy2(os.path.join(ROOT, "anontools.js"), out)
    shutil.copy2(os.path.join(ROOT, "topomap.js"), out)
    shutil.copy2(os.path.join(ROOT, "sshui.js"), out)
    shutil.copy2(os.path.join(ROOT, "vlsm.js"), out)
    shutil.copy2(os.path.join(ROOT, "updateui.js"), out)
    shutil.copy2(os.path.join(ROOT, "golive.js"), out)
    shutil.copy2(os.path.join(ROOT, "alertwhy.js"), out)
    shutil.copy2(os.path.join(ROOT, "presenceui.js"), out)
    shutil.copy2(os.path.join(ROOT, "l2guardui.js"), out)
    shutil.copy2(os.path.join(ROOT, "assessui.js"), out)
    shutil.copy2(os.path.join(ROOT, "vulnui.js"), out)
    shutil.copy2(os.path.join(ROOT, "upnpui.js"), out)
    shutil.copy2(os.path.join(ROOT, "probesui.js"), out)
    for f in ("otui.js", "acceptui.js", "sitesui.js", "labelsui.js", "calcui.js", "v6ui.js", "nacui.js", "iotinvui.js", "radioui.js", "fieldui.js"):  # 🧰 εργαλειοθήκη τεχνικού
        shutil.copy2(os.path.join(ROOT, f), out)
    shutil.copy2(os.path.join(ROOT, "acl.js"), out)
    shutil.copy2(os.path.join(ROOT, "names.js"), out)
    # Ακαδημία: scripts + εικονίδια του PWA (ό,τι δεν είναι .md).
    for fp in glob.glob(os.path.join(ROOT, "academy", "*")):
        if os.path.isfile(fp) and not fp.endswith(".md"):
            shutil.copy2(fp, os.path.join(out, "academy"))
    # Το PWA «Ακαδημία στο κινητό» (academy.html) διαβάζει τη λίστα μαθημάτων από αρχείο,
    # αφού στο Pages δεν υπάρχει /api/academy.
    lessons = sorted(os.path.basename(p) for p in glob.glob(os.path.join(ROOT, "academy", "*.js"))
                     if os.path.basename(p) != "engine.js")
    with open(os.path.join(out, "academy", "files.json"), "w", encoding="utf-8") as f:
        json.dump({"files": lessons}, f)
    # Αγγλικά: μαθήματα academy/en/ (+ files.json) και τα λεξικά της διεπαφής (i18n.js, i18n/)
    en_src = os.path.join(ROOT, "academy", "en")
    if os.path.isdir(en_src):
        shutil.copytree(en_src, os.path.join(out, "academy", "en"))
        with open(os.path.join(out, "academy", "en", "files.json"), "w", encoding="utf-8") as f:
            json.dump({"files": sorted(x for x in os.listdir(en_src) if x.endswith(".js"))}, f)
    shutil.copy2(os.path.join(ROOT, "i18n.js"), out)
    shutil.copytree(os.path.join(ROOT, "i18n"), os.path.join(out, "i18n"))
    for name in ("academy.html", "manifest.webmanifest", "sw.js"):
        if os.path.isfile(os.path.join(ROOT, name)):
            shutil.copy2(os.path.join(ROOT, name), out)
        else:
            print(f"  (λείπει το {name} — το PWA της Ακαδημίας δεν θα δουλεύει)")
    shutil.copy2(os.path.join(HERE, "static", "demo-shim.js"), out)
    with open(os.path.join(out, "demo-data.js"), "w", encoding="utf-8") as f:
        f.write("/* Καταγραφή από `netwatch.py --demo` (προσομοίωση) — tools/record_static_demo.py */\n")
        f.write("window.NETWATCH_DEMO=")
        json.dump(rec, f, ensure_ascii=False, separators=(",", ":"))
        f.write(";\n")

    for name in ("report.html", "pentest-report.html"):
        rep = os.path.join(args.rec, name)
        if os.path.isfile(rep):
            shutil.copy2(rep, os.path.join(out, name))
    for ext in ("md", "html", "drawio"):  # 📘 τεκμηρίωση δικτύου (Markdown / HTML / draw.io)
        src = os.path.join(args.rec, "docs", "network." + ext)
        if os.path.isfile(src):
            os.makedirs(os.path.join(out, "docs"), exist_ok=True)
            shutil.copy2(src, os.path.join(out, "docs", "network." + ext))
    if os.path.isfile(os.path.join(ROOT, "docs", "og.png")):
        shutil.copy2(os.path.join(ROOT, "docs", "og.png"), out)
    open(os.path.join(out, ".nojekyll"), "w").close()

    total = sum(os.path.getsize(p) for p in glob.glob(os.path.join(out, "**"), recursive=True) if os.path.isfile(p))
    print(f"OK: {out} ({total / 1e6:.1f} MB, {len(rec['sse'])} μηνύματα SSE, {len(rec['api'])} endpoints)")


if __name__ == "__main__":
    main()
