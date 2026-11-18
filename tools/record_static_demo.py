#!/usr/bin/env python3
"""Καταγραφή του NetWatch σε λειτουργία DEMO για το στατικό online demo (GitHub Pages).

Ξεκινά `netwatch.py --demo` (προσομοίωση — καμία πραγματική κίνηση, δεν χρειάζεται root),
γράφει το SSE stream (/events) για λίγα λεπτά, πατά μερικά κουμπιά (έλεγχος IoT, Wi‑Fi,
privacy, σάρωση LAN) και κρατά snapshots από όλα τα GET endpoints που καλεί το frontend.

    .venv/bin/python tools/record_static_demo.py            # ~150″, γράφει build/static-demo/
    .venv/bin/python tools/record_static_demo.py --seconds 60

Μετά: tools/build_static_demo.py → dist-pages/.
Ασφάλεια: αρνείται να καταγράψει αν το /api/status δεν λέει mode == "demo".
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import quote

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# GET endpoints που καλεί το index.html / academy/engine.js (χωρίς αυτά που βγαίνουν στο internet:
# /api/whois, /api/cve, /api/abuseipdb — το shim απαντά «μη διαθέσιμο στο online demo»).
GETS = ["/api/status", "/api/iot", "/api/mqtt", "/api/sensor", "/api/honeypot", "/api/block",
        "/api/apps", "/api/wifi", "/api/privacy", "/api/audit", "/api/rules", "/api/ctf",
        "/api/academy", "/api/hass", "/api/scan", "/api/lab", "/api/packet",
        # 🏗 Υποδομή (infra.js)
        "/api/infra", "/api/flows", "/api/snmp", "/api/ipam", "/api/latency", "/api/speed",
        "/api/wifisurvey", "/api/pcap", "/api/maint",
        # 🔒 ασφάλεια & ιδιωτικότητα
        "/api/tor", "/api/vpn", "/api/vpnguard", "/api/encdns", "/api/dnsfilter", "/api/logimport", "/api/ctwatch", "/api/camexp",
        "/api/iotfw", "/api/vulnlab",
        # 🟣 purple team, 🔐 TLS/SSH, 📑 αναφορά pentest (JSON· το HTML γράφεται ως pentest-report.html)
        "/api/purple", "/api/tlsaudit", "/api/pentest-report",
        # 🗂 υποθέσεις (διαλογή ειδοποιήσεων), 🎯 κυνήγι απειλών
        "/api/cases", "/api/hunt"]
LAT_HOURS = [3, 24, 168]
HISTORY_HOURS = [1, 24, 168, 720]
# Βγαίνουν στο internet ή χρειάζονται παράμετρο που δεν ξέρουμε — δεν καταγράφονται.
SKIP = {"/api/whois", "/api/cve", "/api/abuseipdb", "/api/history", "/api/packet", "/api/shell",
        "/api/flows/device", "/api/iotfw/rules", "/api/hunt/profile", "/api/pcap/alert", "/api/ipam/export", "/api/syslog"}
MAX_DECODES = 60  # αποκωδικοποιημένα πακέτα (🔬) — ~10 KB το καθένα


def discover_gets():
    """Όλα τα fetch('/api/…') του frontend, ώστε νέα endpoints να καταγράφονται χωρίς αλλαγή εδώ."""
    found = set()
    for rel in ("index.html", "edu.js", "infra.js", "sectools.js", os.path.join("academy", "engine.js")):
        try:
            src = open(os.path.join(ROOT, rel), encoding="utf-8").read()
        except OSError:
            continue
        found.update(re.findall(r"fetch\(\s*['\"`](/api/[A-Za-z0-9_/-]+)['\"`?]", src))
    return sorted((set(GETS) | found) - SKIP) + ["/api/packet"]


class Client:
    def __init__(self, port):
        self.base = f"http://127.0.0.1:{port}"

    def get(self, path, raw=False, timeout=15):
        with urllib.request.urlopen(self.base + path, timeout=timeout) as r:
            body = r.read()
        return body.decode("utf-8") if raw else json.loads(body)

    def post(self, path, obj, timeout=15):
        req = urllib.request.Request(self.base + path, data=json.dumps(obj).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return json.loads(e.read() or b"{}")


class SSERecorder(threading.Thread):
    def __init__(self, url):
        super().__init__(daemon=True)
        self.url, self.msgs, self.stop_flag, self.t0 = url, [], False, None
        self.resp = None

    def run(self):
        self.resp = urllib.request.urlopen(self.url, timeout=30)
        self.t0 = time.time()
        buf = []
        for raw in self.resp:
            if self.stop_flag:
                break
            line = raw.decode("utf-8").rstrip("\r\n")
            if line.startswith("data:"):
                buf.append(line[5:].lstrip())
            elif line == "" and buf:
                try:
                    msg = json.loads("\n".join(buf))
                    self.msgs.append({"dt": round(time.time() - self.t0, 3), "at": time.time(), "msg": msg})
                except json.JSONDecodeError:
                    pass
                buf = []


def wait_ready(c, proc, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            sys.exit(f"Ο demo server τερμάτισε (κωδικός {proc.returncode}).")
        try:
            return c.get("/api/status", timeout=2)
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.5)
    sys.exit("Ο demo server δεν απάντησε εγκαίρως.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8790)
    ap.add_argument("--seconds", type=float, default=150)
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "static-demo"))
    ap.add_argument("--python", default=sys.executable, help="python με τα requirements (scapy κ.λπ.)")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    cmd = [args.python, "netwatch.py", "--demo", "--no-open", "--no-geo", "--no-rdns", "--no-intel",
           "--port", str(args.port), "--bind", "127.0.0.1"]
    log = open(os.path.join(args.out, "server.log"), "w")
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        c = Client(args.port)
        st = wait_ready(c, proc)
        # 🔒 Ποτέ δεδομένα από live/pcap: μόνο η προσομοίωση.
        if st.get("mode") != "demo":
            sys.exit(f"ΑΡΝΗΣΗ: /api/status λέει mode={st.get('mode')!r}, όχι 'demo'.")
        print(f"demo server έτοιμος στη θύρα {args.port} — καταγραφή {args.seconds:.0f}″ …")

        sse = SSERecorder(c.base + "/events")
        sse.start()
        t_start = time.time()
        while sse.t0 is None and time.time() - t_start < 10:
            time.sleep(0.1)

        posts = {}
        # Honeypot ανοιχτό από την αρχή, για να μαζέψει (ψεύτικα) χτυπήματα.
        hp = c.get("/api/honeypot")
        posts["/api/honeypot"] = c.post("/api/honeypot", {"enable": True, "ports": sorted(int(p) for p in hp.get("services", {}))})
        # Στο 1/4 του χρόνου πατάμε τα κουμπιά, για να έχουν αποτελέσματα τα tabs.
        time.sleep(args.seconds * 0.25)
        for path, body in [("/api/iot", {"ips": []}), ("/api/wifi", {}), ("/api/privacy", {}),
                           ("/api/scan", {}), ("/api/exposure", {}),
                           ("/api/purple/run", {}), ("/api/tlsaudit/run", {})]:  # καμπάνια ~35″: τελειώνει πριν το τέλος
            posts[path] = c.post(path, body)
            print(f"  POST {path} → {'error' if 'error' in posts[path] else 'ok'}")

        while time.time() - t_start < args.seconds:
            time.sleep(1)
            el = time.time() - t_start
            if int(el) % 15 == 0:
                print(f"  {el:5.0f}″  {len(sse.msgs)} μηνύματα SSE", flush=True)

        st = c.get("/api/status")
        if st.get("mode") != "demo":
            sys.exit("ΑΡΝΗΣΗ: η λειτουργία άλλαξε κατά την καταγραφή.")

        api = {}
        for p in discover_gets():
            try:
                api[p] = c.get(p)
            except urllib.error.HTTPError as e:
                print(f"  (παράλειψη {p}: HTTP {e.code})")
        for h in HISTORY_HOURS:
            api[f"/api/history?hours={h}"] = c.get(f"/api/history?hours={h}")
        # 🏗 Υποδομή: syslog (το shim φιλτράρει τοπικά), latency ανά στόχο/εύρος, ροές ανά συσκευή
        api["/api/syslog"] = c.get("/api/syslog?limit=300")
        for t in (api.get("/api/latency") or {}).get("targets", []):
            for h in LAT_HOURS:
                api[f"/api/latency?target={t['name']}&hours={h}"] = c.get(f"/api/latency?target={quote(t['name'])}&hours={h}")
        # 🧱 IoT firewall: κανόνες ανά συσκευή και μορφή (το shim τους σερβίρει από εδώ)
        for d in (api.get("/api/iotfw") or {}).get("devices", [])[:12]:
            for fmt in ("openwrt", "pfsense", "mikrotik", "iptables"):
                api[f"/api/iotfw/rules?dev={d['key']}&fmt={fmt}"] = c.get(f"/api/iotfw/rules?dev={quote(d['key'])}&fmt={fmt}")
        for d in (api.get("/api/flows") or {}).get("top_talkers", [])[:15]:
            api["/api/flows/device?ip=" + d["ip"]] = c.get("/api/flows/device?ip=" + quote(d["ip"]))
        # 🎯 κυνήγι απειλών: ένα αποτέλεσμα ανά υπόθεση (+ "all") και προφίλ για τις συσκευές των ευρημάτων
        prof_ips = []
        for h in (api.get("/api/hunt") or {}).get("hunts", []) + [{"id": "all"}]:
            r = c.post("/api/hunt/run", {"id": h["id"]})
            api["/api/hunt/run?id=" + h["id"]] = r
            for f in r.get("findings") or []:
                if f.get("actor") and f["actor"] not in prof_ips and len(prof_ips) < 10:
                    prof_ips.append(f["actor"])
        for ip in prof_ips:
            try:
                api["/api/hunt/profile?ip=" + ip] = c.get("/api/hunt/profile?ip=" + quote(ip))
            except urllib.error.HTTPError:
                pass
        # 🔬 Πακέτα: λίστα ροών ανά host και αποκωδικοποίηση της πρώτης ροής του καθενός.
        snap = next((m["msg"] for m in sse.msgs if m["msg"].get("type") == "snapshot"), {})
        hosts = sorted(snap.get("hosts", []), key=lambda h: -(h.get("pkts") or 0))
        ips = [h["ip"] for h in hosts[:60]]
        for m in sse.msgs:
            for h in m["msg"].get("hosts") or []:
                if h["ip"] not in ips and len(ips) < 120:
                    ips.append(h["ip"])
        decodes = 0
        for ip in ips:
            fl = c.get("/api/packet?ip=" + quote(ip))
            if not fl.get("flows"):
                continue
            api["/api/packet?ip=" + ip] = fl
            for f in fl["flows"][:3]:
                src, dst = f.get("src"), f.get("dst")
                key = f"/api/packet?src={src}&dst={dst}"
                if src and dst and key not in api and decodes < MAX_DECODES:
                    api[key] = c.get(f"/api/packet?src={quote(src)}&dst={quote(dst)}")
                    decodes += 1
        # 📷 NetCam Lab: στο online demo δεν υπάρχει server για να «τρέξει» η κάμερα — μόνο η περιγραφή των προκλήσεων.
        vl = api.get("/api/vulnlab") or {}
        if not vl.get("off"):
            vl.update({"running": False, "listening": {}, "events": [], "verify": None, "idle_left_s": None,
                       "uptime_s": 0, "static": True,
                       "note": "Στο online demo η κάμερα δεν μπορεί να ξεκινήσει — κατέβασε το NetWatch για να τη "
                               "«χακάρεις» στον υπολογιστή σου (ακούει μόνο στο 127.0.0.1)."})
            api["/api/vulnlab"] = vl
        report = c.get("/report?days=7", raw=True)
        pt_report = c.get("/pentest-report?lang=el", raw=True)

        sse.stop_flag = True
        msgs = sse.msgs
        rec = {"recorded_at": time.time(), "t0": sse.t0, "duration": round(time.time() - sse.t0, 3),
               "mode": "demo", "sse": [{"dt": m["dt"], "msg": m["msg"]} for m in msgs],
               "api": api, "post": posts}
        with open(os.path.join(args.out, "recording.json"), "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, separators=(",", ":"))
        with open(os.path.join(args.out, "report.html"), "w", encoding="utf-8") as f:
            f.write(report)
        with open(os.path.join(args.out, "pentest-report.html"), "w", encoding="utf-8") as f:
            f.write(pt_report)
        types = {}
        for m in msgs:
            types[m["msg"].get("type")] = types.get(m["msg"].get("type"), 0) + 1
        print(f"OK: {len(msgs)} μηνύματα SSE {types}, {len(api)} endpoints → {args.out}")
    finally:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
        log.close()


if __name__ == "__main__":
    main()
