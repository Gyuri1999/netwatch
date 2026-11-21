"""NetWatch — Ο web server (HTTP API + SSE) του dashboard."""
import ipaddress
import json
import os
import queue
import re
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs
from urllib.parse import urlparse

from core import HERE, log, quit_now
from storage import abuseipdb_check
from osint import traceroute, whois
from capture import ctf_check_rule, ctf_exit, ctf_load
from demo import DEMO_SHODAN


# ---------------- web server ----------------
def make_handler(state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            return self._send(code, json.dumps(obj).encode(), "application/json")

        def _agent_ok(self):
            import agent
            return agent.authorized(self.headers, state.agent["token"])

        def _local_request(self):
            """Προστασία από CSRF / DNS rebinding: μόνο JSON από την ίδια τη σελίδα του NetWatch."""
            if getattr(state, "agent", None):
                import agent
                return self._agent_ok() and agent.same_origin(self.headers) and \
                    self.headers.get("Content-Type", "").startswith("application/json")
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            origin = self.headers.get("Origin")
            ok_host = host in ("127.0.0.1", "localhost", "[::1]")
            ok_origin = origin is None or urlparse(origin).hostname in ("127.0.0.1", "localhost", "::1")
            return ok_host and ok_origin and self.headers.get("Content-Type", "").startswith("application/json")

        def do_POST(self):
            import pentest
            u = urlparse(self.path)
            if not self._local_request():
                return self._json({"error": "forbidden"}, 403)
            if getattr(state, "agent", None) and u.path in __import__("agent").DENY:
                return self._json({"error": "Απενεργοποιημένο σε λειτουργία agent (θα έτρεχε στον server)."}, 403)
            if u.path == "/api/logimport/upload":  # ακατέργαστο σώμα (eve.json / Zeek), έως 20 MB
                li = getattr(state, "logimport", None)
                if not li:
                    return self._json({"error": "off"}, 400)
                n = int(self.headers.get("Content-Length") or 0)
                if n > 20 * 1024 * 1024:
                    return self._json({"error": "Πολύ μεγάλο αρχείο (όριο 20 MB)."}, 413)
                raw = self.rfile.read(n)
                try:
                    return self._json(li.import_text(raw, kind=parse_qs(u.query).get("kind", ["auto"])[0]))
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
            if u.path == "/api/topomap/export":  # 🗺 PDF/PNG/SVG του διαγράμματος (ακατέργαστο σώμα, έως 15 MB)
                tm = getattr(state, "topomap", None)
                if not tm:
                    return self._json({"error": "off"}, 400)
                n = int(self.headers.get("Content-Length") or 0)
                if n > 15 * 1024 * 1024:
                    return self._json({"error": "Πολύ μεγάλο αρχείο (όριο 15 MB)."}, 413)
                r = tm.put_file(parse_qs(u.query).get("fmt", [""])[0], self.rfile.read(n))
                return self._json(r, 400 if "error" in r else 200)
            try:
                n = int(self.headers.get("Content-Length") or 0)
                lim = 2 * 1024 * 1024 if u.path == "/api/configs/upload" else 10000  # 💾 επικόλληση ρυθμίσεων έως 512 KB
                if u.path == "/api/segcheck/report":  # 🧱 αποτέλεσμα ελέγχου διαχωρισμού από άλλο VLAN
                    lim = 256 * 1024
                if u.path == "/api/names":  # 🏷 πολλά ονόματα μαζί (οδηγός / μεταφορά από τον browser)
                    lim = 256 * 1024
                if u.path == "/api/configs/upload" and n > lim:
                    return self._json({"error": "Πολύ μεγάλο κείμενο (όριο 512 KB)."}, 413)
                body = json.loads(self.rfile.read(min(n, lim)) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._json({"error": "bad json"}, 400)
            try:
                if u.path == "/api/ipam/note":
                    ip_ = getattr(state, "ipam", None)
                    if not ip_:
                        return self._json({"error": "off"}, 400)
                    try:
                        ip_.notes.set(str(body.get("key") or ""), body.get("fields") or {})
                    except ValueError as e:
                        return self._json({"error": str(e)}, 400)
                    return self._json({"ok": True})
                if u.path in ("/api/speed/iperf", "/api/speed/internet"):
                    sp = getattr(state, "speed", None)
                    if not sp:
                        return self._json({"error": "off"}, 400)
                    try:
                        if u.path.endswith("iperf"):
                            r = sp.iperf(str(body.get("host") or ""), reverse=bool(body.get("reverse")), udp=bool(body.get("udp")))
                        else:
                            r = sp.internet()
                    except Exception as e:
                        return self._json({"error": str(e)[:300]}, 400)
                    return self._json(r if isinstance(r, dict) else {"result": r})
                if u.path == "/api/wifisurvey/scan":
                    ws = getattr(state, "wifisurvey", None)
                    if not ws:
                        return self._json({"error": "off"}, 400)
                    ws.scan()
                    return self._json(ws.status())
                if u.path == "/api/snmp/poll":
                    sn = getattr(state, "snmp", None)
                    if not sn:
                        return self._json({"error": "off"}, 400)
                    threading.Thread(target=sn.round, daemon=True).start()
                    return self._json({"ok": True})
                if u.path == "/api/tor/newnym":
                    tr = getattr(state, "tor", None)
                    return self._json(tr.newnym() if tr else {"error": "off"})
                if u.path == "/api/vpnguard/arm":
                    vg = getattr(state, "vpnguard", None)
                    if not vg:
                        return self._json({"error": "off"}, 400)
                    try:
                        return self._json(vg.arm(int(body.get("seconds") or 60)))
                    except Exception as e:
                        return self._json({"error": str(e)[:200]}, 400)
                if u.path == "/api/camexp/scan":
                    ce = getattr(state, "camexp", None)
                    if not ce:
                        return self._json({"error": "off"}, 400)
                    threading.Thread(target=ce.scan, daemon=True).start()
                    return self._json({"ok": True, "scanning": True})
                if u.path in ("/api/iotfw/mode", "/api/iotfw/accept", "/api/iotfw/reset"):
                    fw = getattr(state, "iotfw", None)
                    if not fw:
                        return self._json({"error": "off"}, 400)
                    dev = str(body.get("dev") or "")
                    try:
                        if u.path.endswith("/mode"):
                            return self._json(fw.set_mode(dev, str(body.get("mode") or "")))
                        if u.path.endswith("/accept"):
                            return self._json(fw.accept(dev, str(body.get("dest") or "")))
                        return self._json(fw.reset(dev))
                    except KeyError as e:
                        return self._json({"error": str(e.args[0] if e.args else e)}, 404)
                if u.path == "/api/ctwatch/check":
                    cw = getattr(state, "ctwatch", None)
                    if not cw:
                        return self._json({"error": "off"}, 400)
                    threading.Thread(target=lambda: cw.round(force=True), daemon=True).start()
                    return self._json({"ok": True})
                if u.path == "/api/dnsfilter/poll":
                    df = getattr(state, "dnsfilter", None)
                    if not df:
                        return self._json({"error": "off"}, 400)
                    threading.Thread(target=df.fetch, daemon=True).start()
                    return self._json({"ok": True})
                if u.path in ("/api/maint/mute", "/api/maint/unmute"):
                    mt = getattr(state, "maint", None)
                    if not mt:
                        return self._json({"error": "δεν υπάρχει σε αυτή τη λειτουργία"}, 400)
                    if u.path.endswith("/unmute"):
                        mt.unmute(int(body["id"]) if str(body.get("id", "")).isdigit() else None)
                    else:
                        hosts = [h for h in (body.get("hosts") or []) if isinstance(h, str)]
                        mt.mute(int(body.get("minutes") or 30), body.get("name"), hosts)
                    return self._json(mt.status())
                if u.path == "/api/scan":
                    target = str(body.get("target") or state.default_scan_target())
                    with state.lock:
                        known = {ip: h["mac"] for ip, h in state.hosts.items() if h.get("mac") and h["kind"] == "local"}
                    profile = str(body.get("profile") or "quick")
                    ports = str(body.get("ports") or "")[:4000] or None
                    state.scanner.start(target, known, profile=profile, ports=ports, udp=bool(body.get("udp")))
                    log(f"🔴 σάρωση LAN: {target} ({profile}{' + UDP' if body.get('udp') else ''})")
                    return self._json({"ok": True})
                if u.path == "/api/selftest":  # «για Ν λεπτά κάνω δοκιμή από αυτή τη συσκευή»
                    from core import ip_kind
                    ip = str(body.get("ip") or "").strip()[:64]
                    try:
                        minutes = float(body.get("minutes") if body.get("minutes") is not None else 30)
                    except (TypeError, ValueError):
                        raise ValueError("Μη έγκυρα λεπτά")
                    if not re.fullmatch(r"[0-9a-fA-F:.]+", ip or "-") or ip_kind(ip) != "local" or ip in ("0.0.0.0", "::"):
                        raise ValueError("Μόνο IP του τοπικού δικτύου (π.χ. 192.168.1.20)")
                    if not 0 <= minutes <= 240:
                        raise ValueError("Λεπτά: από 0 έως 240")
                    why = str(body.get("why") or "").strip()[:80] or None
                    state.test_from(ip, minutes, why)
                    log(f"🧪 δοκιμή από {ip} για {minutes:g}′" if minutes else f"🧪 τέλος δοκιμής από {ip}")
                    return self._json(state.selftest_status())
                if u.path == "/api/netkit":  # 🧰 εργαλεία τεχνικού (ping, DNS, θύρες, HTTP, WoL, ονόματα)
                    import netkit
                    return self._json(netkit.run_tool(body, sim=state.mode == "demo", state=state))
                if u.path == "/api/lab":
                    if (getattr(state, "purple", None) and state.purple.status_brief() == "running"):
                        raise ValueError("Τρέχει καμπάνια purple team — περίμενε να τελειώσει")
                    state.lab.start(str(body.get("kind")), str(body.get("variant")))
                    return self._json({"ok": True})
                if u.path.startswith("/api/cases/"):  # 🗂 διαλογή ειδοποιήσεων & υποθέσεις
                    cs = getattr(state, "cases", None)
                    if not cs:
                        return self._json({"error": "Οι υποθέσεις δεν είναι διαθέσιμες σε αυτή τη λειτουργία."}, 400)
                    act = u.path.rsplit("/", 1)[1]
                    note = body.get("note")
                    if note is not None and (not isinstance(note, str) or len(note) > 2000):
                        raise ValueError("Η σημείωση πρέπει να είναι κείμενο έως 2000 χαρακτήρες.")
                    if act in ("update", "fp"):
                        cid = body.get("id")
                        if isinstance(cid, bool) or not isinstance(cid, (int, str)) or not str(cid).isdigit():
                            raise ValueError("Μη έγκυρο id υπόθεσης.")
                        if act == "update":
                            st_ = body.get("status")
                            if st_ is not None and st_ not in ("new", "investigating", "resolved", "false_positive"):
                                raise ValueError("Μη έγκυρη κατάσταση.")
                            r = cs.update(int(cid), status=st_, note=note)
                        else:
                            mins = body.get("minutes", 1440)
                            if isinstance(mins, bool) or not isinstance(mins, (int, str)) or not str(mins).isdigit():
                                raise ValueError("Τα λεπτά πρέπει να είναι μη αρνητικός ακέραιος.")
                            r = cs.false_positive(int(cid), int(mins), note=note)
                    elif act == "new":
                        r = cs.create(str(body.get("title") or "")[:300], body.get("actors") or [],
                                      sev=str(body.get("sev") or "med"), note=note, source="hunt")
                    elif act == "delete-suppression":
                        r = cs.delete_suppression(str(body.get("type") or "")[:200], str(body.get("actor") or "")[:200])
                    else:
                        return self._json({"error": "not found"}, 404)
                    return self._json(r, 400 if "error" in r else 200)
                if u.path in ("/api/configs/backup", "/api/configs/upload"):  # 💾 αντίγραφα ρυθμίσεων συσκευών
                    cb = getattr(state, "configbak", None)
                    if not cb:
                        return self._json({"error": "Τα αντίγραφα ρυθμίσεων δεν είναι διαθέσιμα σε αυτή τη λειτουργία."}, 400)
                    if not isinstance(body, dict):
                        return self._json({"error": "bad json"}, 400)
                    did = body.get("id")
                    if not isinstance(did, str) or not (did == "all" and u.path.endswith("/backup") or re.fullmatch(r"[a-z0-9_.-]{1,40}", did)):
                        return self._json({"error": "Μη έγκυρο id συσκευής."}, 400)
                    if u.path.endswith("/backup"):
                        r = cb.backup(did)
                    else:
                        for k in ("note", "name", "vendor"):
                            if body.get(k) is not None and (not isinstance(body[k], str) or len(body[k]) > 300):
                                return self._json({"error": f"Μη έγκυρο πεδίο «{k}»."}, 400)
                        r = cb.upload(did, body.get("text"), note=body.get("note"), name=body.get("name"), vendor=body.get("vendor"))
                    return self._json(r, 400 if "error" in r else 200)
                if u.path == "/api/whereis/refresh":  # 🔌 «Πού είναι συνδεδεμένο;»
                    wi = getattr(state, "whereis", None)
                    if not wi:
                        return self._json({"error": "Η αναζήτηση θύρας δεν είναι διαθέσιμη σε αυτή τη λειτουργία."}, 400)
                    return self._json(wi.refresh())
                if u.path in ("/api/alerts/mute", "/api/alerts/unmute"):  # 🔕 σίγαση με λήξη
                    hy = getattr(state, "hygiene", None)
                    if not hy:
                        return self._json({"error": "off"}, 400)
                    if u.path == "/api/alerts/unmute":
                        r = hy.unmute(body.get("id"))
                    else:
                        r = hy.mute(body.get("type"), body.get("actor"), body.get("minutes", 1440), body.get("note"))
                    return self._json(r, 400 if r.get("error") else 200)
                if u.path == "/api/vulns/refresh":
                    vw = getattr(state, "vulns", None)
                    if not vw:
                        return self._json({"error": "off"}, 400)
                    threading.Thread(target=vw.refresh, args=(True,), daemon=True).start()
                    return self._json({**vw.view(), "busy": True})
                if u.path == "/api/npcap/install":  # ⬇ Npcap (Windows): κατέβασμα από npcap.com + έλεγχος υπογραφής + installer
                    ng = getattr(state, "npcap", None)
                    if not ng:
                        return self._json({"error": "Διαθέσιμο μόνο στην εφαρμογή των Windows."}, 400)
                    r = ng.start()
                    return self._json(r, 400 if "error" in r else 200)
                if u.path == "/api/app/mode":  # 🟢 αλλαγή Live/Demo από τον πίνακα (εφαρμογή Windows ή Mac)
                    d = getattr(state, "app_ctl", None)
                    m = str(body.get("mode") or "")
                    if not d:
                        return self._json({"error": "Η αλλαγή λειτουργίας από εδώ γίνεται μόνο στην εφαρμογή (Windows ή Mac)."}, 400)
                    if m not in ("live", "live-admin", "demo"):
                        return self._json({"error": "Άγνωστη λειτουργία."}, 400)
                    rq = os.path.join(d, "mode-request.json")
                    with open(rq, "w", encoding="utf-8") as f:
                        json.dump({"mode": m, "t": time.time()}, f)
                    try:  # Mac σε Live τρέχει ως root· το app (χρήστης) πρέπει να μπορεί να το διαβάσει/σβήσει
                        os.chmod(rq, 0o644)
                    except OSError:
                        pass
                    return self._json({"ok": True, "mode": m})
                if u.path == "/api/l2guard/run":  # 🛡 rogue DHCP / ARP spoofing με ένα κουμπί (μόνο τοπικό LAN)
                    lg = getattr(state, "l2guard", None)
                    if not lg:
                        return self._json({"error": "Ο έλεγχος L2 δεν είναι διαθέσιμος σε αυτή τη λειτουργία (χρειάζεται live ή demo)."}, 400)
                    return self._json(lg.run())
                if u.path == "/api/update/auto":  # 🔄 αυτόματη εγκατάσταση on/off
                    up = getattr(state, "updater", None)
                    if not up:
                        return self._json({"error": "Οι ενημερώσεις δεν είναι διαθέσιμες σε αυτή τη λειτουργία."}, 400)
                    r = up.set_auto(body.get("on") is True)
                    return self._json(r, 400 if "error" in r else 200)
                if u.path in ("/api/update/check", "/api/update/install", "/api/update/restart"):  # 🔄 ενημερώσεις από GitHub
                    up = getattr(state, "updater", None)
                    if not up:
                        return self._json({"error": "Οι ενημερώσεις δεν είναι διαθέσιμες σε αυτή τη λειτουργία."}, 400)
                    act = u.path.rsplit("/", 1)[1]
                    r = up.check(force=True) if act == "check" else up.install() if act == "install" else up.restart()
                    return self._json(r, 400 if "error" in r and act != "check" else 200)
                if u.path == "/api/names":  # 🏷 όνομα/τύπος συσκευής (ένα ή πολλά: {"items": [...]})
                    dn = getattr(state, "devnames", None)
                    if not dn:
                        return self._json({"error": "off"}, 400)
                    r = dn.bulk(body["items"]) if isinstance(body.get("items"), list) else dn.set(body)
                    return self._json(r, 400 if "error" in r else 200)
                if u.path.startswith("/api/ssh/"):  # 🖥 SSH Explorer (μόνο κλειδιά, μόνο ανάγνωση)
                    sb = getattr(state, "ssh", None)
                    if not sb:
                        return self._json({"error": "Το SSH Explorer δεν είναι διαθέσιμο σε αυτή τη λειτουργία."}, 400)
                    act, hid, pth = u.path[9:], str(body.get("id") or ""), body.get("path")
                    if act == "host":
                        r = sb.delete_host(hid) if body.get("delete") else sb.add_host(body)
                    elif act == "hostkey":
                        r = sb.hostkey(hid)
                    elif act == "trust":
                        r = sb.trust(hid, str(body.get("fp") or ""))
                    elif act == "ls":
                        r = sb.ls(hid, pth or "~")
                    elif act == "cat":
                        r = sb.cat(hid, pth or "")
                    elif act == "fetch":
                        r = sb.fetch(hid, pth or "")
                    elif act == "info":
                        r = sb.info(hid)
                    else:
                        return self._json({"error": "not found"}, 404)
                    return self._json(r, 400 if "error" in r and act in ("host", "trust") else 200)
                if u.path == "/api/topomap/run":  # 🗺 διάγραμμα δικτύου
                    tm = getattr(state, "topomap", None)
                    if not tm:
                        return self._json({"error": "Το διάγραμμα δικτύου δεν είναι διαθέσιμο σε αυτή τη λειτουργία."}, 400)
                    r = tm.run(fault=str(body.get("fault") or "") or None)
                    return self._json(r, 429 if r.get("retry_in") else 400 if "error" in r else 200)
                if u.path in ("/api/segcheck/run", "/api/segcheck/report"):  # 🧱 έλεγχος διαχωρισμού (VLAN)
                    sc = getattr(state, "segcheck", None)
                    if not sc:
                        return self._json({"error": "Ο έλεγχος διαχωρισμού δεν είναι διαθέσιμος σε αυτή τη λειτουργία."}, 400)
                    if u.path.endswith("/report"):  # από NetWatch/segcheck.py σε άλλο VLAN (σε agent: Bearer token)
                        r = sc.report(body)
                        return self._json(r, 400 if "error" in r else 200)
                    r = sc.run()
                    return self._json(r, 429 if r.get("retry_in") else 400 if "error" in r else 200)
                if u.path in ("/api/expiry/add", "/api/expiry/delete", "/api/expiry/refresh"):  # ⏳ υπενθυμίσεις λήξης
                    ex = getattr(state, "expiry", None)
                    if not ex:
                        return self._json({"error": "Οι υπενθυμίσεις λήξης δεν είναι διαθέσιμες σε αυτή τη λειτουργία."}, 400)
                    if not isinstance(body, dict):
                        return self._json({"error": "bad json"}, 400)
                    if u.path.endswith("/refresh"):
                        r = ex.refresh()
                    elif u.path.endswith("/delete"):
                        iid = body.get("id")
                        if not isinstance(iid, str) or not re.fullmatch(r"[a-z0-9_-]{1,40}", iid):
                            return self._json({"error": "Μη έγκυρο id."}, 400)
                        r = ex.delete(iid)
                    else:
                        for k, lim in (("name", 80), ("kind", 20), ("date", 10), ("note", 200)):
                            if body.get(k) is not None and (not isinstance(body[k], str) or len(body[k]) > lim):
                                return self._json({"error": f"Μη έγκυρο πεδίο «{k}»."}, 400)
                        r = ex.add(body.get("name"), body.get("kind"), body.get("date"), body.get("note"))
                    return self._json(r, 400 if "error" in r else 200)
                if u.path in ("/api/change/snapshot", "/api/change/delete"):  # 🔁 έλεγχος πριν/μετά από αλλαγή
                    ch = getattr(state, "changecheck", None)
                    if not ch:
                        return self._json({"error": "Ο έλεγχος πριν/μετά δεν είναι διαθέσιμος σε αυτή τη λειτουργία."}, 400)
                    if u.path.endswith("/delete"):
                        sid = body.get("id")
                        if isinstance(sid, bool) or not isinstance(sid, (int, str)) or not str(sid).isdigit():
                            raise ValueError("Μη έγκυρο id στιγμιότυπου.")
                        r = ch.delete(int(sid))
                    else:
                        label, targets = body.get("label"), body.get("targets")
                        if not isinstance(label, str) or not label.strip() or len(label.strip()) > 40:
                            raise ValueError("Η ετικέτα πρέπει να είναι κείμενο 1–40 χαρακτήρων.")
                        if targets is not None and (not isinstance(targets, list) or len(targets) > 64
                                                    or not all(isinstance(x, str) for x in targets)):
                            raise ValueError("Οι στόχοι πρέπει να είναι λίστα έως 64 ιδιωτικών IP.")
                        r = ch.snapshot(label, targets or None)
                    return self._json(r, 400 if "error" in r else 200)
                if u.path in ("/api/handover/note", "/api/handover/note/delete"):  # 🔄 σημειώσεις βάρδιας
                    ho = getattr(state, "handover", None)
                    if not ho:
                        return self._json({"error": "Η παράδοση βάρδιας δεν είναι διαθέσιμη σε αυτή τη λειτουργία."}, 400)
                    if u.path.endswith("/delete"):
                        r = ho.delete_note(body.get("t"))
                    else:
                        txt = body.get("text")
                        if not isinstance(txt, str) or len(txt) > 1000:
                            raise ValueError("Η σημείωση πρέπει να είναι κείμενο έως 1000 χαρακτήρες.")
                        r = ho.add_note(txt)
                    return self._json(r, 400 if "error" in r else 200)
                if u.path == "/api/assess/run":  # 📋 τρέξε τους ελέγχους της αναφοράς (l2guard, triage, κάμερες)
                    asr = getattr(state, "assess", None)
                    if not asr:
                        return self._json({"error": "off"}, 400)
                    lang = body.get("lang") if body.get("lang") in ("el", "en") else "el"
                    r = asr.run(lang)
                    return self._json(r, 409 if r.get("error") else 200)
                if u.path == "/api/triage/run":  # 🩺 «Φταίει το δίκτυο;»
                    tr = getattr(state, "triage", None)
                    if not tr:
                        return self._json({"error": "Η διάγνωση δεν είναι διαθέσιμη σε αυτή τη λειτουργία."}, 400)
                    import nettriage
                    lang, sc = body.get("lang") or "el", body.get("scenario")
                    if lang not in nettriage.LANGS:
                        raise ValueError("Γλώσσα: el ή en.")
                    if sc is not None and sc not in nettriage.SCENARIOS:
                        raise ValueError("Άγνωστο σενάριο.")
                    r = tr.run(lang=lang, scenario=sc)
                    return self._json(r, 400 if "error" in r else 200)
                if u.path == "/api/hunt/run":  # 🎯 κυνήγι απειλών: εκτέλεση υπόθεσης (ή "all")
                    hu = getattr(state, "hunt", None)
                    if not hu:
                        return self._json({"error": "Το κυνήγι απειλών δεν είναι διαθέσιμο σε αυτή τη λειτουργία."}, 400)
                    import hunt
                    hid = str(body.get("id") or "")
                    if hid != "all" and hid not in hunt.HUNTS:
                        return self._json({"error": "Άγνωστη υπόθεση κυνηγιού."}, 400)
                    return self._json(hu.run(hid))
                if u.path in ("/api/purple/run", "/api/purple/stop"):  # 🟣 καμπάνια purple team (εγχυμένα πακέτα)
                    pu = getattr(state, "purple", None)
                    if not pu:
                        return self._json({"error": "Δεν είναι διαθέσιμο σε αυτή τη λειτουργία."}, 400)
                    if u.path.endswith("/stop"):
                        return self._json(pu.stop())
                    return self._json(pu.start(body.get("scenarios"), body.get("variants")))
                if u.path == "/api/tlsaudit/run":  # 🔐 έλεγχος TLS/SSH (μόνο ιδιωτικές IP)
                    ta = getattr(state, "tlsaudit", None)
                    if not ta:
                        return self._json({"error": "Δεν είναι διαθέσιμο σε αυτή τη λειτουργία."}, 400)
                    res = ta.start(body.get("targets"))
                    log(f"🔐 έλεγχος TLS/SSH: {res['total']} υπηρεσίες")
                    return self._json(res)
                if u.path.startswith("/api/vulnlab/"):  # 📷 NetCam Lab (μόνο 127.0.0.1)
                    vl = getattr(state, "vulnlab", None)
                    if not vl:
                        return self._json({"error": "Το NetCam Lab δεν είναι διαθέσιμο σε αυτή τη λειτουργία."}, 400)
                    act = u.path.rsplit("/", 1)[1]
                    if act == "start":
                        return self._json(vl.start())
                    if act == "stop":
                        return self._json(vl.stop())
                    if act == "flag":
                        return self._json(vl.submit(body.get("flag")))
                    if act == "fix":
                        return self._json(vl.set_fix(str(body.get("id") or ""), body.get("on", True)))
                    if act == "verify":
                        return self._json(vl.verify())
                    if act == "reset":
                        return self._json(vl.reset())
                if u.path == "/api/ctf/load":
                    ctf_load(state, str(body.get("level")))
                    return self._json({"ok": True})
                if u.path == "/api/ctf/exit":
                    ctf_exit(state)
                    return self._json({"ok": True})
                if u.path == "/api/ctf/answer":
                    import ctf
                    return self._json({"correct": ctf.check(str(body.get("level")), str(body.get("q")),
                                                            str(body.get("answer") or "")[:200])})
                if u.path == "/api/ctf/rule":
                    return self._json(ctf_check_rule(str(body.get("level")), str(body.get("q")),
                                                     str(body.get("yaml") or "")))
                if u.path == "/api/rules/test":
                    return self._json(state.test_rules(str(body.get("yaml") or "")))
                if u.path == "/api/rules/save":
                    ids = state.save_rule(str(body.get("yaml") or ""))
                    log(f"🧩 αποθηκεύτηκε κανόνας: {', '.join(ids)}")
                    return self._json({"ok": True, "ids": ids})
                if u.path == "/api/rules/delete":
                    state.delete_rule(str(body.get("id")))
                    return self._json({"ok": True})
                if u.path == "/api/rules/toggle":
                    r = next((r for r in state.rules.rules if r.id == body.get("id")), None)
                    if not r:
                        return self._json({"error": "δεν βρέθηκε"}, 404)
                    r.enabled = bool(body.get("enabled"))
                    return self._json({"ok": True})
                if u.path == "/api/shutdown":  # η εφαρμογή Mac κλείνει / αλλάζει λειτουργία
                    self._json({"ok": True})
                    log("Τερματισμός από την εφαρμογή.")
                    threading.Timer(0.2, quit_now).start()
                    return
                if u.path == "/api/wifi":
                    if not state.wifi:
                        return self._json({"error": "Wi‑Fi Guard off"}, 400)
                    if "trusted" in body:
                        state.wifi.set_trusted(str(body.get("ssid") or ""), bool(body["trusted"]))
                    elif body.get("vpn_only"):
                        state.wifi.recheck_vpn()
                    else:
                        state.wifi.start("manual")
                    return self._json(state.wifi.status())
                if u.path == "/api/trace":
                    return self._json(traceroute(state, str(body.get("ip") or "")))
                if u.path == "/api/shell":  # τερματικό Ακαδημίας: μόνο ασφαλείς εντολές, ποτέ ως root (δες shellrun.py)
                    if not state.cfg.get("academy_terminal", True):
                        return self._json({"ok": False, "blocked": True, "out": "Το τερματικό είναι κλειστό (academy_terminal: false στο config)."})
                    import shellrun
                    return self._json(shellrun.run(str(body.get("cmd", ""))[:500]))
                if u.path == "/api/playbooks":  # αναίρεση μιας αυτόματης ενέργειας
                    if not state.playbooks:
                        return self._json({"error": "Διαθέσιμο μόνο σε Live/Demo."}, 400)
                    if body.get("undo"):
                        state.playbooks.undo(int(body["undo"]))
                    return self._json(state.playbooks.status())
                if u.path == "/api/notify":  # δοκιμαστική ειδοποίηση σε macOS / Telegram / ntfy
                    from storage import Notifier
                    n = state.notifier or Notifier(state.cfg.get("notify") or {})
                    return self._json({"channels": n.channels(), "result": n.test()})
                if u.path == "/api/mqtt":
                    if not state.mqtt:
                        return self._json({"error": "Διαθέσιμο μόνο σε Live/Demo."}, 400)
                    if body.get("relearn"):
                        state.mqtt.relearn()
                    return self._json(state.mqtt.status())
                if u.path == "/api/iot":
                    if not state.iot:
                        return self._json({"error": "Διαθέσιμο μόνο σε Live/Demo."}, 400)
                    ips = [str(x) for x in (body.get("ips") or [])][:16]
                    for ip in ips:
                        if not ipaddress.ip_address(ip).is_private:
                            raise ValueError("Μόνο IP του τοπικού δικτύου")
                    state.iot.start(ips)
                    return self._json(state.iot.status())
                if u.path == "/api/block":
                    if not state.blocker:
                        return self._json({"error": "Διαθέσιμο μόνο σε Live/Demo."}, 400)
                    if body.get("unblock"):
                        return self._json(state.blocker.unblock(body["unblock"]))
                    return self._json(state.blocker.block(body.get("ip"), body.get("why", "")))
                if u.path == "/api/honeypot":
                    if not state.honeypot:
                        return self._json({"error": "Διαθέσιμο μόνο σε Live/Demo."}, 400)
                    if body.get("enable"):
                        return self._json(state.honeypot.start(body.get("ports")))
                    return self._json(state.honeypot.stop())
                if u.path == "/api/sitecheck":  # 🧅 «Πόσο ασφαλές είναι αυτό το site για την ανωνυμία μου;» (μία σελίδα, μέσω Tor)
                    sk = getattr(state, "sitecheck", None)
                    if not sk:
                        return self._json({"error": "Ο έλεγχος site δεν είναι διαθέσιμος σε αυτή τη λειτουργία."}, 400)
                    if not isinstance(body, dict):
                        return self._json({"error": "bad json"}, 400)
                    r = sk.start(body.get("url"), direct=body.get("direct") is True, lang=body.get("lang"))
                    return self._json(r, r.pop("code", 200))
                if u.path == "/api/privacy":
                    state.privacy.start(on_done=lambda r: state.publish({"type": "privacy", "result": r}))
                    return self._json(state.privacy.status())
                if u.path == "/api/exposure":
                    if state.mode == "demo":
                        return self._json(DEMO_SHODAN)
                    ip = (state.home or {}).get("query")
                    if not ip:
                        return self._json({"error": "Δεν ξέρω ακόμα τη δημόσια IP σου"}, 400)
                    return self._json(pentest.internetdb(ip))
            except ValueError as e:
                return self._json({"error": str(e)}, 400)
            except Exception as e:
                return self._json({"error": str(e)[:200]}, 502)
            return self._json({"error": "not found"}, 404)

        def _infra_get(self, u):
            """Υποδομή: NetFlow/sFlow, SNMP, syslog, IPAM, latency, ταχύτητα, Wi‑Fi survey, pcap ανά ειδοποίηση."""
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            off = {"enabled": False, "off": True}
            p = u.path
            if p == "/api/infra":  # τι είναι διαθέσιμο (για τις καρτέλες του UI)
                return self._json({k: bool(getattr(state, k, None)) for k in
                                   ("flows", "snmp", "syslog", "ipam", "latency", "speed", "wifisurvey", "pcap_ring", "maint",
                                    "tor", "wg", "vpnguard", "encdns", "dnsfilter", "logimport", "ctwatch", "camexp", "iotfw")})
            if p == "/api/flows":
                f = getattr(state, "flows", None)
                return self._json(f.status() if f else off)
            if p == "/api/flows/device":
                f = getattr(state, "flows", None)
                return self._json(f.device(q.get("ip", "")) if f else off)
            if p == "/api/snmp":
                sn = getattr(state, "snmp", None)
                return self._json(sn.status() if sn else off)
            if p == "/api/snmp/iface":
                sn = getattr(state, "snmp", None)
                try:
                    return self._json(sn.iface_history(q.get("target", ""), int(q.get("ifindex", 0))) if sn else off)
                except ValueError:
                    return self._json({"error": "bad ifindex"}, 400)
            if p == "/api/syslog":
                sy = getattr(state, "syslog", None)
                if not sy:
                    return self._json(off)
                st = sy.status(recent=0)
                try:
                    sev = int(q["sev"]) if q.get("sev", "").isdigit() else None
                    since = float(q["since"]) if q.get("since") else None
                    st["results"] = sy.query(q.get("q") or None, q.get("host") or None, sev, since, min(int(q.get("limit") or 300), 2000))
                except ValueError as e:
                    st["results"], st["query_error"] = [], str(e)[:200]
                return self._json(st)
            if p in ("/api/ipam", "/api/ipam/export"):
                ip_ = getattr(state, "ipam", None)
                if not ip_:
                    return self._json(off)
                with state.lock:
                    hosts = [{"ip": h["ip"], "mac": h.get("mac"), "names": sorted(h.get("names") or ())[:5], "vendor": h.get("vendor"),
                              "dlabel": h.get("dlabel") or h.get("dtype"), "first": h.get("first"), "last": h.get("last")}
                             for h in state.hosts.values() if h.get("kind") == "local" and ":" not in h["ip"]]
                    obs = [(ip, mac, t) for ip, d in getattr(state, "ip_mac_seen", {}).items() for mac, t in d.items()]
                    me = sorted(state.me)[0] if state.me else None
                local_net = (me.rsplit(".", 1)[0] + ".0/24") if me and ":" not in me else None
                if p.endswith("/export"):
                    fmt = "json" if q.get("fmt") == "json" else "csv"
                    body = ip_.export(hosts, fmt=fmt)
                    body = body if isinstance(body, (bytes, bytearray)) else (body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json" if fmt == "json" else "text/csv; charset=utf-8")
                    self.send_header("Content-Disposition", f'attachment; filename="netwatch-inventory.{fmt}"')
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                rep = ip_.report(hosts, obs, time.time(), local_net)
                try:
                    import ipam
                    ipam.conflicts_to_alerts(state, rep.get("findings") or [])
                except Exception as e:
                    log("ipam:", e)
                return self._json(rep)
            if p == "/api/latency":
                la = getattr(state, "latency", None)
                if not la:
                    return self._json(off)
                st = la.status()
                if q.get("target"):
                    try:
                        st["history"] = la.history(q["target"], hours=min(float(q.get("hours") or 24), 24 * 30))
                        st["bad_hours"] = la.bad_hours(q["target"])
                    except ValueError:
                        return self._json({"error": "bad hours"}, 400)
                return self._json(st)
            if p == "/api/speed":
                sp = getattr(state, "speed", None)
                return self._json(sp.status() if sp else off)
            if p == "/api/wifisurvey":
                ws = getattr(state, "wifisurvey", None)
                if not ws:
                    return self._json(off)
                st = ws.status()
                if not st or not st.get("t"):
                    try:
                        ws.scan()
                        st = ws.status()
                    except Exception as e:
                        st = {"error": str(e)[:200]}
                return self._json(st)
            if p == "/api/pcap":
                r = getattr(state, "pcap_ring", None)
                return self._json(r.stats() if r else off)
            if p == "/api/pcap/alert":
                r = getattr(state, "pcap_ring", None)
                if not r:
                    return self._json({"error": "ο δακτύλιος pcap είναι κλειστός (pcap_ring.enabled: false)"}, 400)
                try:
                    aid = int(q.get("id", ""))
                except ValueError:
                    return self._json({"error": "bad id"}, 400)
                with state.lock:
                    a = next((x for x in state.alerts if x.get("id") == aid), None)
                if not a:
                    return self._json({"error": "δεν βρέθηκε η ειδοποίηση"}, 404)
                res = r.export_for_alert(a)
                data = res["pcap"]
                fn = re.sub(r"[^\w.-]", "_", res.get("filename") or "netwatch.pcap")
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
                self.send_header("Content-Disposition", f'attachment; filename="{fn}"')
                self.send_header("X-Packets", str(res.get("count", 0)))
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            simple = {"/api/tor": "tor", "/api/vpn": "wg", "/api/vpnguard": "vpnguard", "/api/encdns": "encdns",
                      "/api/dnsfilter": "dnsfilter", "/api/logimport": "logimport", "/api/ctwatch": "ctwatch",
                      "/api/camexp": "camexp", "/api/iotfw": "iotfw"}
            if p == "/api/iotfw/rules":
                fw = getattr(state, "iotfw", None)
                if not fw:
                    return self._json(off)
                try:
                    return self._json(fw.rules(q.get("dev", ""), q.get("fmt", "openwrt"), lan=q.get("lan") in ("1", "true")))
                except KeyError as e:
                    return self._json({"error": str(e.args[0] if e.args else e)}, 404)
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
            if p in simple:
                m = getattr(state, simple[p], None)
                return self._json(m.status() if m else off)
            return self._json({"error": "not found"}, 404)

        def do_GET(self):
            u = urlparse(self.path)
            if getattr(state, "agent", None) and not self._agent_ok() and \
                    __import__("ops").token_role(self.headers, parse_qs(u.query).get("token", [""])[0],
                                                 (state.cfg or {}).get("api_tokens")) is None:
                import hmac
                import agent
                tok = parse_qs(u.query).get("token", [""])[0]
                if u.path == "/" and tok and hmac.compare_digest(tok.encode(), state.agent["token"].encode()):
                    self.send_response(302)
                    self.send_header("Set-Cookie", f"{agent.COOKIE}={tok}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000")
                    self.send_header("Location", "/")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if u.path == "/":
                    return self._send(401, agent.LOGIN_PAGE.encode(), "text/html; charset=utf-8")
                return self._json({"error": "unauthorized"}, 401)
            if u.path == "/metrics":  # Prometheus / Grafana
                import ops
                return self._send(200, ops.metrics(state).encode(), "text/plain; version=0.0.4; charset=utf-8")
            if u.path == "/api/maint":
                mt = getattr(state, "maint", None)
                return self._json(mt.status() if mt else {"active": None, "mutes": [], "windows": [], "errors": []})
            if u.path.startswith(("/api/flows", "/api/snmp", "/api/syslog", "/api/ipam", "/api/latency", "/api/speed",
                                  "/api/wifisurvey", "/api/pcap", "/api/infra", "/api/tor", "/api/vpn", "/api/encdns",
                                  "/api/dnsfilter", "/api/logimport", "/api/ctwatch", "/api/camexp", "/api/iotfw")):
                return self._infra_get(u)
            if u.path in ("/", "/index.html"):
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if u.path in ("/edu.js", "/wireshark.js", "/infra.js", "/sectools.js", "/privtools.js", "/protocols.js", "/ciscolab.js", "/uiplus.js", "/pentestui.js", "/socui.js", "/worktools.js", "/opstools.js", "/cmdxlate.js", "/navplus.js", "/anontools.js", "/topomap.js", "/sshui.js", "/vlsm.js", "/updateui.js", "/presenceui.js", "/l2guardui.js", "/assessui.js", "/vulnui.js", "/acl.js", "/names.js", "/golive.js", "/alertwhy.js"):
                with open(os.path.join(HERE, u.path[1:]), "rb") as f:
                    return self._send(200, f.read(), "text/javascript; charset=utf-8")
            if u.path == "/i18n.js" or (u.path.startswith("/i18n/") and u.path.endswith(".js")):
                name = os.path.basename(u.path)
                fp = os.path.join(HERE, "i18n.js") if u.path == "/i18n.js" else os.path.join(HERE, "i18n", name)
                if re.fullmatch(r"[\w.-]+\.js", name) and os.path.isfile(fp):
                    with open(fp, "rb") as f:
                        return self._send(200, f.read(), "text/javascript; charset=utf-8")
                return self._send(404, b"not found", "text/plain")
            if u.path.startswith("/academy/") and u.path.endswith(".js"):
                name = os.path.basename(u.path)  # μόνο αρχεία του academy/ ή academy/en/, χωρίς ../
                sub = "en" if u.path == "/academy/en/" + name else ""
                fp = os.path.join(HERE, "academy", sub, name)
                if re.fullmatch(r"[\w.-]+\.js", name) and os.path.isfile(fp):
                    with open(fp, "rb") as f:
                        return self._send(200, f.read(), "text/javascript; charset=utf-8")
                return self._send(404, b"not found", "text/plain")
            if u.path in ("/api/academy", "/academy/files.json", "/academy/en/files.json"):
                en = u.path.startswith("/academy/en/") or parse_qs(u.query).get("lang", [""])[0] == "en"
                d = os.path.join(HERE, "academy", "en") if en else os.path.join(HERE, "academy")
                files = sorted(f for f in os.listdir(d) if f.endswith(".js") and f != "engine.js") if os.path.isdir(d) else []
                return self._json({"files": files})
            if u.path in ("/academy.html", "/manifest.webmanifest", "/sw.js"):  # η Ακαδημία ως εφαρμογή κινητού (PWA)
                ct = {".html": "text/html; charset=utf-8", ".webmanifest": "application/manifest+json",
                      ".js": "text/javascript; charset=utf-8"}[os.path.splitext(u.path)[1]]
                with open(os.path.join(HERE, u.path[1:]), "rb") as f:
                    return self._send(200, f.read(), ct)
            if re.fullmatch(r"/academy/icon(-\d+)?\.(png|svg)", u.path) and os.path.isfile(os.path.join(HERE, "academy", os.path.basename(u.path))):
                with open(os.path.join(HERE, "academy", os.path.basename(u.path)), "rb") as f:
                    return self._send(200, f.read(), "image/svg+xml" if u.path.endswith(".svg") else "image/png")
            if u.path == "/api/onionoo":
                from osint import onionoo
                ip = parse_qs(u.query).get("ip", [""])[0]
                return self._send(200, json.dumps(onionoo(ip, demo=state.mode == "demo")).encode(), "application/json")
            if u.path in ("/api/whereis", "/api/whereis/table"):  # 🔌 «Πού είναι συνδεδεμένο;» MAC → switch → θύρα → VLAN
                wi = getattr(state, "whereis", None)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                if u.path.endswith("/table"):
                    return self._json(wi.table(all_rows=q.get("all") == "1") if wi else {"rows": [], "switches": [], "off": True})
                qq = q.get("q", "")
                if len(qq) > 64:
                    return self._json({"error": "Πολύ μεγάλο ερώτημα (έως 64 χαρακτήρες)."}, 400)
                return self._json(wi.lookup(qq) if wi else {"query": qq, "found": False, "location": None, "off": True})
            if u.path in ("/api/alerts/why", "/api/alerts/noise", "/api/alerts/hygiene"):  # 🔕 υγιεινή + 🧐 γιατί
                hy = getattr(state, "hygiene", None)
                if not hy:
                    return self._json({"error": "off"}, 400)
                pq = parse_qs(u.query)
                if u.path == "/api/alerts/why":
                    try:
                        aid = int(pq.get("id", ["0"])[0])
                    except ValueError:
                        return self._json({"error": "Λάθος id."}, 400)
                    r = hy.why(aid)
                    return self._json(r, 404 if r.get("error") else 200)
                if u.path == "/api/alerts/noise":
                    try:
                        hours = int(pq.get("hours", ["24"])[0])
                    except ValueError:
                        hours = 24
                    return self._json(hy.noise(hours))
                return self._json(hy.view())
            if u.path == "/api/presence":  # 📈 διαθεσιμότητα ανά συσκευή
                pr = getattr(state, "presence", None)
                if not pr:
                    return self._json({"devices": [], "off": True})
                pq = parse_qs(u.query)
                try:
                    days = int(pq.get("days", ["7"])[0])
                except ValueError:
                    days = 7
                return self._json(pr.view(days, key=pq.get("key", [""])[0][:64] or None))
            if u.path == "/api/l2guard":  # 🛡 τελευταίος έλεγχος rogue DHCP / ARP
                lg = getattr(state, "l2guard", None)
                return self._json(lg.view() if lg else {"never": True, "off": True})
            if u.path == "/api/vulns":  # 🛡 ευπάθειες για τις συσκευές σου (CISA KEV)
                vw = getattr(state, "vulns", None)
                return self._json(vw.view() if vw else {"error": "off"})
            if u.path == "/api/npcap":
                ng = getattr(state, "npcap", None)
                return self._json(ng.view() if ng else {"available": False})
            if u.path == "/api/update":  # 🔄 κατάσταση ενημέρωσης
                up = getattr(state, "updater", None)
                return self._json(up.view() if up else {"off": True})
            if u.path == "/api/names":  # 🏷 ονόματα συσκευών
                dn = getattr(state, "devnames", None)
                return self._json(dn.view() if dn else {"devices": {}, "types": [], "off": True})
            if u.path == "/api/ssh":  # 🖥 SSH Explorer
                sb = getattr(state, "ssh", None)
                return self._json(sb.view() if sb else {"hosts": [], "keys": {"keys": []}, "suggestions": [], "off": True})
            if u.path == "/api/ssh/file":  # 🖥 κατέβασμα αρχείου από SSH (μία φορά, 5′)
                sb = getattr(state, "ssh", None)
                f = sb.get_file(parse_qs(u.query).get("id", [""])[0]) if sb else None
                if not f:
                    return self._json({"error": "Το αρχείο έληξε — πάτα ξανά κατέβασμα."}, 404)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(f["data"])))
                self.send_header("Content-Disposition", f'attachment; filename="{f["name"]}"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
                self.end_headers()
                self.wfile.write(f["data"])
                return
            if u.path == "/api/topomap/file":  # 🗺 κατέβασμα PDF/PNG/SVG που μόλις φτιάχτηκε
                tm = getattr(state, "topomap", None)
                f = tm.get_file(parse_qs(u.query).get("id", [""])[0]) if tm else None
                if not f:
                    return self._json({"error": "Το αρχείο έληξε — πάτα ξανά εξαγωγή."}, 404)
                self.send_response(200)
                self.send_header("Content-Type", f["mime"])
                self.send_header("Content-Length", str(len(f["data"])))
                self.send_header("Content-Disposition", f'attachment; filename="{f["name"]}"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
                self.end_headers()
                self.wfile.write(f["data"])
                return
            if u.path == "/api/topomap":  # 🗺 διάγραμμα δικτύου
                tm = getattr(state, "topomap", None)
                return self._json(tm.view() if tm else {"running": False, "graph": None, "diag": None, "issues": [], "off": True})
            if u.path == "/api/segcheck":  # 🧱 έλεγχος διαχωρισμού (VLAN)
                sc = getattr(state, "segcheck", None)
                return self._json(sc.view() if sc else {"config_ok": False, "configured": False, "rules": [], "zones": [],
                                                        "matrix": {"zones": [], "cells": {}}, "off": True})
            if u.path == "/api/expiry":  # ⏳ υπενθυμίσεις λήξης
                ex = getattr(state, "expiry", None)
                return self._json(ex.view() if ex else {"items": [], "counts": {}, "off": True})
            if u.path in ("/api/change", "/api/change/compare"):  # 🔁 έλεγχος πριν/μετά από αλλαγή
                ch = getattr(state, "changecheck", None)
                if u.path == "/api/change":
                    return self._json(ch.view() if ch else {"status": "idle", "snapshots": [], "last_compare": None, "off": True})
                if not ch:
                    return self._json({"off": True, "error": "Ο έλεγχος πριν/μετά δεν είναι διαθέσιμος σε αυτή τη λειτουργία."})
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                if not str(q.get("a", "")).isdigit() or not str(q.get("b", "")).isdigit():
                    return self._json({"error": "Δώσε a και b (id στιγμιότυπων)."}, 400)
                r = ch.compare(int(q["a"]), int(q["b"]))
                return self._json(r, 404 if "error" in r else 200)
            if u.path == "/api/handover":  # 🔄 παράδοση βάρδιας (SOC/NOC)
                ho = getattr(state, "handover", None)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                import handover
                try:
                    hours = handover.parse_hours(q.get("hours"))
                except ValueError:
                    return self._json({"error": "Οι ώρες πρέπει να είναι ακέραιος 1–72. / hours must be an integer 1–72."}, 400)
                lang = q.get("lang") or "el"
                if lang not in handover.LANGS:
                    return self._json({"error": "Γλώσσα: el ή en."}, 400)
                if not ho:
                    return self._json({"off": True, "sections": [], "stats": {}, "notes": [], "text": "",
                                       "error": "Η παράδοση βάρδιας δεν είναι διαθέσιμη σε αυτή τη λειτουργία."})
                return self._json(ho.summary(hours, lang))
            if u.path in ("/api/assess", "/assess/report.html", "/assess/inventory.csv", "/assess/findings.csv",
                          "/assess/netbox-ip-addresses.csv", "/assess/report.json"):  # 📋 αναφορά «νέο δίκτυο»
                import assess
                lang = parse_qs(u.query).get("lang", ["el"])[0]
                if lang not in assess.LANGS:
                    return self._json({"error": "Γλώσσα: el ή en."}, 400)
                doc = assess.build(state, lang)
                if u.path == "/api/assess":
                    asr = getattr(state, "assess", None)
                    return self._json({**doc, "job": asr.view() if asr else {"state": "off"}})
                if u.path == "/assess/report.html":
                    return self._send(200, assess.to_html(doc).encode(), "text/html; charset=utf-8")
                kind = {"inventory.csv": "inventory", "findings.csv": "findings", "netbox-ip-addresses.csv": "netbox", "report.json": "json"}[u.path.rsplit("/", 1)[1]]
                body = (assess.to_inventory_csv(doc) if kind == "inventory" else assess.to_findings_csv(doc) if kind == "findings"
                        else assess.to_netbox_ips_csv(doc) if kind == "netbox" else json.dumps(doc, ensure_ascii=False, indent=1)).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8" if kind == "json" else "text/csv; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Disposition", f'attachment; filename="{assess.filename(kind, doc["generated"])}"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
                return
            if u.path in ("/api/docs", "/docs/network.md", "/docs/network.html", "/docs/network.drawio"):  # 📘 τεκμηρίωση δικτύου
                import netdocs
                lang = parse_qs(u.query).get("lang", ["el"])[0]
                if lang not in netdocs.LANGS:
                    return self._json({"error": "Γλώσσα: el ή en."}, 400)
                doc = netdocs.build(state, lang)
                if u.path == "/api/docs":
                    md = netdocs.to_markdown(doc)
                    return self._json({"generated": doc["generated"], "counts": doc["counts"], "demo": doc["demo"],
                                       "formats": [{"id": f, "url": f"/docs/network.{f}?lang={lang}"} for f in ("md", "html", "drawio")],
                                       "preview_md": "\n".join(md.split("\n")[:80])})
                if u.path.endswith(".html"):
                    return self._send(200, netdocs.to_html(doc, lang).encode(), "text/html; charset=utf-8")
                fmt = u.path.rsplit(".", 1)[1]
                body = (netdocs.to_markdown(doc) if fmt == "md" else netdocs.to_drawio(doc)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8" if fmt == "md" else "application/xml; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Disposition", f'attachment; filename="{netdocs.filename(fmt, doc["generated"])}"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
                return
            if u.path == "/api/triage":  # 🩺 «Φταίει το δίκτυο;»
                tr = getattr(state, "triage", None)
                return self._json(tr.view() if tr else {"status": "idle", "steps": [], "verdict": None, "ticket": "",
                                                        "scenarios": [], "off": True})
            if u.path == "/api/cases":  # 🗂 διαλογή ειδοποιήσεων & υποθέσεις
                cs = getattr(state, "cases", None)
                return self._json(cs.view() if cs else {"cases": [], "kpi": {}, "off": True})
            if u.path in ("/api/configs", "/api/configs/versions", "/api/configs/show", "/api/configs/diff"):  # 💾 αντίγραφα ρυθμίσεων
                cb = getattr(state, "configbak", None)
                if not cb:
                    return self._json({"devices": [], "off": True})
                if u.path == "/api/configs":
                    return self._json(cb.view())
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                did = q.get("id", "")
                if not re.fullmatch(r"[a-z0-9_.-]{1,40}", did):
                    return self._json({"error": "Μη έγκυρο id συσκευής."}, 400)
                ts = {}
                for k in ("ts", "a", "b"):
                    if q.get(k):
                        if not re.fullmatch(r"\d{1,12}", q[k]):
                            return self._json({"error": f"Μη έγκυρο «{k}»."}, 400)
                        ts[k] = int(q[k])
                if u.path.endswith("/versions"):
                    r = cb.versions(did)
                elif u.path.endswith("/show"):
                    r = cb.show(did, ts.get("ts"))
                else:
                    r = cb.diff(did, ts.get("a"), ts.get("b"))
                return self._json(r, 404 if "error" in r else 200)
            if u.path in ("/api/hunt", "/api/hunt/profile"):  # 🎯 κυνήγι απειλών: κατάλογος υποθέσεων / προφίλ συσκευής
                hu = getattr(state, "hunt", None)
                if u.path == "/api/hunt":
                    return self._json(hu.catalog() if hu else {"hunts": [], "off": True})
                if not hu:
                    return self._json({"error": "Το κυνήγι απειλών δεν είναι διαθέσιμο σε αυτή τη λειτουργία."}, 400)
                ip = parse_qs(u.query).get("ip", [""])[0].strip()
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    return self._json({"error": "Μη έγκυρη IP."}, 400)
                r = hu.profile(ip)
                return self._json(r, 404 if "error" in r else 200)
            if u.path in ("/api/timeline", "/api/timeline/at"):
                tl = getattr(state, "timeline", None)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                if not tl:
                    return self._json({"enabled": False, "off": True})
                try:
                    if u.path == "/api/timeline":
                        return self._json(tl.summary(max(1, min(24, float(q.get("hours", 24))))))
                    return self._json(tl.at(float(q.get("t", time.time())), int(q.get("span", 1))))
                except ValueError:
                    return self._json({"error": "bad t/span"}, 400)
            if u.path == "/api/whois":
                ip = parse_qs(u.query).get("ip", [""])[0]
                return self._send(200, json.dumps({"ip": ip, "text": whois(ip)}).encode(), "application/json")
            if u.path == "/api/history":
                try:
                    hours = max(1, min(24 * 90, float(parse_qs(u.query).get("hours", ["24"])[0])))
                except ValueError:
                    hours = 24
                ref = state.last_t if state.mode == "pcap" and state.last_t else None
                return self._send(200, json.dumps(state.history.query(hours, ref)).encode(), "application/json")
            if u.path == "/api/scan":
                import pentest
                st = pentest.apply_findings(state.scan_view())
                st["default_target"] = state.default_scan_target()
                return self._json(st)
            if u.path == "/api/scan/export":  # ⬇️ η τελευταία σάρωση σε CSV / JSON / Markdown
                import pentest
                fmt = parse_qs(u.query).get("fmt", ["csv"])[0]
                scan = None
                if state.scanner and state.scanner.status().get("status") == "done":
                    scan = pentest.apply_findings(state.scan_view())
                elif state.scanner:
                    scan = state.scanner.last_result()
                try:
                    body, ctype, fname = pentest.export_scan(scan, fmt)
                except ValueError as e:
                    return self._json({"error": str(e)}, 400 if scan else 404)
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
                return
            if u.path == "/api/selftest":
                return self._json(state.selftest_status())
            if u.path == "/api/netkit/iface":
                import netkit
                try:
                    return self._json(netkit.iface_info(sim=state.mode == "demo"))
                except Exception as e:
                    return self._json({"error": str(e)[:200]}, 502)
            if u.path == "/api/lab":
                return self._json(state.lab.status() if state.lab else {"status": "off"})
            if u.path == "/api/purple":
                pu = getattr(state, "purple", None)
                cid = parse_qs(u.query).get("id", [""])[0]
                return self._json(pu.status(int(cid) if cid.isdigit() else None) if pu else {"status": "off"})
            if u.path == "/api/tlsaudit":
                ta = getattr(state, "tlsaudit", None)
                return self._json(ta.status() if ta else {"status": "off", "results": []})
            if u.path in ("/pentest-report", "/api/pentest-report"):  # 📑 αναφορά pentest (HTML → PDF) / ίδια δεδομένα σε JSON
                import pentest_report
                lang = parse_qs(u.query).get("lang", ["el"])[0]
                data = pentest_report.build_data(state, lang)
                if u.path.startswith("/api/"):
                    return self._json(data)
                return self._send(200, pentest_report.render_html(data).encode(), "text/html; charset=utf-8")
            if u.path == "/api/vulnlab":
                vl = getattr(state, "vulnlab", None)
                if vl:
                    vl.tick()
                return self._json(vl.status() if vl else {"running": False, "off": True,
                                                          "error": "Το NetCam Lab δεν είναι διαθέσιμο σε αυτή τη λειτουργία."})
            if u.path == "/api/rules":
                return self._json(state.rules_view())
            if u.path == "/api/wifi":
                return self._json(state.wifi.status() if state.wifi else {"error": "off"})
            if u.path == "/api/sitecheck":  # 🧅 έλεγχος site: ?id= για ένα αποτέλεσμα, αλλιώς τελευταίο + ιστορικό
                sk = getattr(state, "sitecheck", None)
                rid = parse_qs(u.query).get("id", [""])[0]
                if not sk:
                    return self._json({"off": True, "running": False, "latest": None, "history": [], "tor": None}
                                      if not rid else {"error": "off"}, 200 if not rid else 404)
                if rid:
                    r = sk.get(rid)
                    return self._json(r if r else {"error": "Άγνωστο id (τα αποτελέσματα κρατιούνται μόνο στη μνήμη)."},
                                      200 if r else 404)
                return self._json(sk.view())
            if u.path == "/api/privacy":
                return self._json(state.privacy.status() if state.privacy else {"error": "off"})
            if u.path == "/api/status":
                return self._json(state.status())
            if u.path == "/api/packet":  # 🔬 ανάλυση πακέτου σε επίπεδα OSI
                import packets
                q = parse_qs(u.query)
                ip, src, dst = q.get("ip", [""])[0], q.get("src", [""])[0], q.get("dst", [""])[0]
                if src and dst:
                    pid = q.get("id", [""])[0]
                    it = packets.get(src, dst, pid=int(pid) if pid.isdigit() else None)
                    if not it:
                        return self._json({"error": "Δεν έχω πακέτο για αυτή τη σύνδεση."})
                    return self._json({**packets.decode(it), "approx": bool(it.get("approx"))})
                return self._json({"flows": packets.flows(ip)})
            if u.path == "/api/conv":  # 🔁 διάγραμμα σύνδεσης (σκάλα SYN → SYN-ACK → ACK …) από τα πρόσφατα πακέτα
                import packets
                q = parse_qs(u.query)
                g = lambda k: q.get(k, [""])[0][:64]  # noqa: E731
                port = lambda k: int(g(k)) if g(k).isdigit() else None  # noqa: E731
                if not (g("a") and g("b")):
                    return self._json({"error": "a/b"}, 400)
                return self._json({"items": packets.conversation(state.recent, g("a"), g("b"), g("p") or None, port("pa"), port("pb"))})
            if u.path == "/report":  # 📄 εβδομαδιαία αναφορά (HTML → εκτύπωση σε PDF)
                import report
                try:
                    days = max(1, min(31, int(parse_qs(u.query).get("days", ["7"])[0])))
                except ValueError:
                    days = 7
                return self._send(200, report.build(state, days).encode(), "text/html; charset=utf-8")
            if u.path == "/api/health":
                return self._json(state.health.status() if state.health else {"targets": []})
            if u.path == "/api/playbooks":
                return self._json(state.playbooks.status() if state.playbooks else {"playbooks": [], "errors": [], "runs": []})
            if u.path == "/api/hass":
                return self._json(state.hass.status() if state.hass else {"configured": False})
            if u.path == "/api/mqtt":
                return self._json(state.mqtt.status() if state.mqtt else {"error": "Διαθέσιμο μόνο σε Live/Demo."})
            if u.path == "/api/sensor":
                return self._json(state.sensor.status() if state.sensor else {"error": "Διαθέσιμο μόνο σε Live/Demo."})
            if u.path == "/api/iot":
                return self._json(state.iot.status() if state.iot else {"error": "Διαθέσιμο μόνο σε Live/Demo."})
            if u.path == "/api/block":
                return self._json(state.blocker.status() if state.blocker else {"error": "Διαθέσιμο μόνο σε Live/Demo."})
            if u.path == "/api/honeypot":
                return self._json(state.honeypot.status() if state.honeypot else {"error": "Διαθέσιμο μόνο σε Live/Demo."})
            if u.path == "/api/apps":
                if not getattr(state, "apps", None):
                    return self._json({"error": "Διαθέσιμο μόνο σε Live/Demo (σε pcap δεν υπάρχουν εφαρμογές να δούμε)."})
                return self._json(state.apps.view())
            if u.path == "/api/ctf":
                import ctf
                try:
                    levels = ctf.public()
                except OSError:
                    levels = []
                return self._json({"levels": levels, "active": state.ctf_level, "feed": state.feed,
                                   "origin": (state.origin or {}).get("mode") if hasattr(state, "origin") else None})
            if u.path == "/api/cve":
                import pentest
                q = parse_qs(u.query)
                prod, ver = q.get("product", [""])[0][:60], q.get("version", [""])[0][:30]
                if not prod:
                    return self._json({"error": "product required"}, 400)
                try:
                    return self._json(pentest.cve_lookup(prod, ver))
                except Exception as e:
                    return self._json({"error": f"NVD: {str(e)[:150]}"}, 502)
            if u.path == "/api/audit":
                return self._send(200, json.dumps(state.audit()).encode(), "application/json")
            if u.path == "/api/abuseipdb":
                ip = parse_qs(u.query).get("ip", [""])[0]
                key = state.cfg.get("intel", {}).get("abuseipdb_key")
                if not key:
                    return self._send(400, b'{"error":"abuseipdb_key not set in config.yaml"}', "application/json")
                try:
                    data = {"ip": ip, "data": abuseipdb_check(key, ip)}
                except Exception as e:
                    data = {"ip": ip, "error": str(e)[:200]}
                return self._send(200, json.dumps(data).encode(), "application/json")
            if u.path == "/events":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                q = state.subscribe()
                try:
                    self.wfile.write(b"data: " + json.dumps(state.snapshot()).encode() + b"\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            data = b"data: " + json.dumps(q.get(timeout=10), separators=(",", ":")).encode() + b"\n\n"
                        except queue.Empty:
                            data = b": ping\n\n"
                        self.wfile.write(data)
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    state.unsubscribe(q)
                return
            self._send(404, b"not found", "text/plain")
    return H
