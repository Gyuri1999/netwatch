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
            try:
                n = min(int(self.headers.get("Content-Length") or 0), 10000)
                body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._json({"error": "bad json"}, 400)
            try:
                if u.path == "/api/scan":
                    target = str(body.get("target") or state.default_scan_target())
                    with state.lock:
                        known = {ip: h["mac"] for ip, h in state.hosts.items() if h.get("mac") and h["kind"] == "local"}
                    state.scanner.start(target, known)
                    log(f"🔴 σάρωση LAN: {target}")
                    return self._json({"ok": True})
                if u.path == "/api/lab":
                    state.lab.start(str(body.get("kind")), str(body.get("variant")))
                    return self._json({"ok": True})
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

        def do_GET(self):
            u = urlparse(self.path)
            if getattr(state, "agent", None) and not self._agent_ok():
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
            if u.path in ("/", "/index.html"):
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if u.path == "/edu.js":
                with open(os.path.join(HERE, "edu.js"), "rb") as f:
                    return self._send(200, f.read(), "text/javascript; charset=utf-8")
            if u.path.startswith("/academy/") and u.path.endswith(".js"):
                name = os.path.basename(u.path)  # μόνο αρχεία του φακέλου academy/, χωρίς ../
                fp = os.path.join(HERE, "academy", name)
                if re.fullmatch(r"[\w.-]+\.js", name) and os.path.isfile(fp):
                    with open(fp, "rb") as f:
                        return self._send(200, f.read(), "text/javascript; charset=utf-8")
                return self._send(404, b"not found", "text/plain")
            if u.path == "/api/academy":
                d = os.path.join(HERE, "academy")
                files = sorted(f for f in os.listdir(d) if f.endswith(".js") and f != "engine.js") if os.path.isdir(d) else []
                return self._json({"files": files})
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
                st = state.scan_view()
                st["default_target"] = state.default_scan_target()
                return self._json(st)
            if u.path == "/api/lab":
                return self._json(state.lab.status() if state.lab else {"status": "off"})
            if u.path == "/api/rules":
                return self._json(state.rules_view())
            if u.path == "/api/wifi":
                return self._json(state.wifi.status() if state.wifi else {"error": "off"})
            if u.path == "/api/privacy":
                return self._json(state.privacy.status() if state.privacy else {"error": "off"})
            if u.path == "/api/status":
                return self._json(state.status())
            if u.path == "/api/packet":  # 🔬 ανάλυση πακέτου σε επίπεδα OSI
                import packets
                q = parse_qs(u.query)
                ip, src, dst = q.get("ip", [""])[0], q.get("src", [""])[0], q.get("dst", [""])[0]
                if src and dst:
                    it = packets.get(src, dst)
                    return self._json(packets.decode(it) if it else {"error": "Δεν έχω πακέτο για αυτή τη σύνδεση."})
                return self._json({"flows": packets.flows(ip)})
            if u.path == "/report":  # 📄 εβδομαδιαία αναφορά (HTML → εκτύπωση σε PDF)
                import report
                try:
                    days = max(1, min(31, int(parse_qs(u.query).get("days", ["7"])[0])))
                except ValueError:
                    days = 7
                return self._send(200, report.build(state, days).encode(), "text/html; charset=utf-8")
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
