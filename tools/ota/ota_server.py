#!/usr/bin/env python3
"""Μικρός HTTPS server για το υπογεγραμμένο OTA του NetWatch (μόνο Python stdlib).

Τρέχει στο Raspberry Pi / στο VM του Proxmox και σερβίρει τον φάκελο που έφτιαξε
το ota_sign.py (π.χ. /srv/ota):

    /srv/ota/canary/manifest.json      /srv/ota/canary/1.2.0.bin
    /srv/ota/sentinel/manifest.json    /srv/ota/sentinel/1.1.0.bin

    python3 ota_server.py --root /srv/ota --cert broker.crt --key broker.key [--port 8443]

Το --cert/--key είναι ένα πιστοποιητικό server της δικής σου CA, π.χ. αυτό που
φτιάχνει το tools/mosquitto-tls.sh (iot-ca/broker.crt, iot-ca/broker.key). Οι
συσκευές το ελέγχουν με το MQTT_CA_PEM τους, άρα το όνομα στο OTA_BASE_URL πρέπει
να υπάρχει στο SAN του πιστοποιητικού (όπως και στο MQTT).

Σκληρύνσεις:
  - μόνο GET (όλα τα άλλα: 405), TLS 1.2+
  - κανένα directory listing (φάκελος -> 404)
  - ασφαλές απέναντι σε path traversal (../, %2e%2e, απόλυτα paths, symlinks
    που βγαίνουν έξω από το --root)
  - σερβίρει μόνο *.bin και manifest.json, κανένα κρυφό αρχείο (.ssh, .git…)
  - καταγράφει κάθε λήψη (IP, αρχείο, bytes, κατάσταση)

ΔΕΝ χρειάζεται (και ΔΕΝ πρέπει) να έχει το ιδιωτικό κλειδί υπογραφής: ο server
είναι "αναξιόπιστος" by design. Αν παραβιαστεί, ο επιτιθέμενος δεν μπορεί να
φτιάξει έγκυρη υπογραφή.
"""
import argparse
import http.server
import logging
import os
import re
import socket
import ssl
import sys
import threading
import urllib.parse

ALLOWED_NAME = re.compile(r"^(manifest\.json|[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\.bin)$")
ALLOWED_DIR = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")
CHUNK = 64 * 1024

log = logging.getLogger("ota")


def resolve(root, url_path):
    """URL path -> απόλυτο path αρχείου μέσα στο root, ή None (=404).

    Δέχεται ΜΟΝΟ τη μορφή /<class>/<αρχείο>, όπου class = [a-z0-9-] και
    αρχείο = manifest.json ή X.Y.Z.bin. Ό,τι άλλο (.., %2e%2e, //, \\, NUL,
    κρυφά αρχεία, φάκελοι, symlinks έξω από το root) επιστρέφει None.
    """
    path = url_path.split("?", 1)[0].split("#", 1)[0]
    try:
        path = urllib.parse.unquote(path, errors="strict")
    except UnicodeDecodeError:
        return None
    if "\x00" in path or "\\" in path or not path.startswith("/"):
        return None
    parts = path.split("/")[1:]
    if len(parts) != 2 or any(p in ("", ".", "..") for p in parts):
        return None
    cls, name = parts
    if not ALLOWED_DIR.match(cls) or not ALLOWED_NAME.match(name):
        return None
    root_real = os.path.realpath(root)
    full = os.path.realpath(os.path.join(root_real, cls, name))
    # Και μετά το realpath (symlinks) πρέπει να είμαστε μέσα στο root.
    if os.path.commonpath([root_real, full]) != root_real:
        return None
    if os.path.basename(full) != name or not os.path.isfile(full):  # το full είναι path του ΤΟΠΙΚΟΥ συστήματος (\\ στα Windows)
        return None
    return full


class OtaHandler(http.server.BaseHTTPRequestHandler):
    server_version = "netwatch-ota"
    sys_version = ""
    protocol_version = "HTTP/1.0"   # μία αίτηση ανά σύνδεση, πάντα Content-Length
    root = "."

    def setup(self):
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(self.timeout)
            self.request.do_handshake()
        super().setup()

    # Όλες οι μέθοδοι εκτός από GET: 405
    def _not_allowed(self):
        self._error(405, extra={"Allow": "GET"})

    do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_TRACE = do_CONNECT = _not_allowed

    def _error(self, code, extra=None):
        body = f"{code}\n".encode()
        self.send_response(code)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        log.warning("%s %s %s -> %d", self.client_address[0], self.command, self.path[:200], code)

    def do_GET(self):
        full = resolve(self.root, self.path)
        if full is None:
            self._error(404)
            return
        try:
            f = open(full, "rb")
        except OSError:
            self._error(404)
            return
        with f:
            size = os.fstat(f.fileno()).st_size
            self.send_response(200)
            ctype = "application/json" if full.endswith(".json") else "application/octet-stream"
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            sent = 0
            try:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    sent += len(chunk)
            except (BrokenPipeError, ConnectionResetError, socket.timeout, ssl.SSLError):
                pass
        rel = os.path.relpath(full, os.path.realpath(self.root))
        level = logging.INFO if sent == size else logging.WARNING
        log.log(level, "%s GET /%s %d/%d bytes%s", self.client_address[0], rel, sent, size,
                "" if sent == size else " (ΔΙΑΚΟΠΗΚΕ)")

    def log_message(self, fmt, *args):   # τα logs τα γράφουμε εμείς (πιο σύντομα, χωρίς headers)
        pass


class OtaServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, addr, root, ssl_ctx=None, timeout=30):
        handler = type("BoundOtaHandler", (OtaHandler,), {"root": os.path.realpath(root), "timeout": timeout})
        super().__init__(addr, handler)
        self.ssl_ctx = ssl_ctx

    def get_request(self):
        sock, addr = super().get_request()
        if self.ssl_ctx is not None:
            # Το handshake ΔΕΝ γίνεται εδώ (στο κύριο thread) αλλά στο setup() του
            # handler, στο δικό του thread και με timeout: ένας αργός ή κακόβουλος
            # client δεν μπορεί να "παγώσει" τον server.
            sock = self.ssl_ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        log.warning("%s σφάλμα σύνδεσης: %s", client_address[0], exc.__class__.__name__)


def make_ssl_context(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def make_server(root, host="0.0.0.0", port=8443, cert=None, key=None):
    if not os.path.isdir(root):
        raise SystemExit(f"✘ δεν υπάρχει ο φάκελος {root}")
    if not (cert and key):
        raise SystemExit("✘ χρειάζονται --cert και --key (μόνο HTTPS: οι συσκευές δεν μιλούν απλό HTTP)")
    return OtaServer((host, port), root, make_ssl_context(cert, key))


def serve_in_thread(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def main(argv=None):
    ap = argparse.ArgumentParser(description="HTTPS server για το υπογεγραμμένο OTA του NetWatch")
    ap.add_argument("--root", default="/srv/ota", help="φάκελος με <class>/manifest.json και <class>/X.Y.Z.bin")
    ap.add_argument("--cert", required=True, help="πιστοποιητικό server (PEM), π.χ. iot-ca/broker.crt")
    ap.add_argument("--key", required=True, help="ιδιωτικό κλειδί του πιστοποιητικού TLS (ΟΧΙ το κλειδί υπογραφής!)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--log", help="και σε αρχείο (εκτός από stderr)")
    a = ap.parse_args(argv)

    handlers = [logging.StreamHandler()]
    if a.log:
        handlers.append(logging.FileHandler(a.log))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)

    if os.path.exists(os.path.join(a.root, "ota_signing.pem")) or any(
            f == "ota_signing.pem" for _, _, files in os.walk(a.root) for f in files):
        log.error("Βρέθηκε ota_signing.pem μέσα στο %s! Το κλειδί υπογραφής ΔΕΝ πρέπει να είναι στον server. "
                  "Σβήσ' το από εδώ (κράτα το μόνο στον υπολογιστή όπου υπογράφεις).", a.root)
        return 2

    srv = make_server(a.root, a.host, a.port, a.cert, a.key)
    log.info("OTA server στο https://%s:%d/ από %s (μόνο GET, χωρίς listing)", a.host, a.port, os.path.realpath(a.root))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
