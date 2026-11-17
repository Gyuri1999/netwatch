import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from storage import Notifier


def test_ntfy_json_publish_and_test_report():
    got = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append((self.headers.get("Authorization"), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    n = Notifier({"macos": False, "ntfy": {"topic": "nw-test-123", "server": f"http://127.0.0.1:{srv.server_port}", "token": "tk"}})
    assert n.channels() == {"macos": False, "telegram": False, "ntfy": True}
    r = n.test()
    srv.shutdown()
    assert r == {"telegram": "δεν έχει ρυθμιστεί", "ntfy": "ok"}
    auth, msg = got[0]
    assert auth == "Bearer tk" and msg["topic"] == "nw-test-123" and msg["title"] == "NetWatch — δοκιμή" and msg["priority"] == 4


def test_ntfy_error_is_reported():
    n = Notifier({"ntfy": {"topic": "x", "server": "http://127.0.0.1:9"}})
    assert n.test()["ntfy"].startswith("σφάλμα")
