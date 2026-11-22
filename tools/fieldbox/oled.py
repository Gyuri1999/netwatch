#!/usr/bin/env python3
"""NetWatch field box — μικρή οθόνη OLED (SSD1306 128x64, I2C) + προαιρετικό κουμπί «νέο τεστ».

Ρωτά το τοπικό NetWatch (GET /api/kit/field/oled → {"lines": [έως 6 γραμμές ASCII]}) και τις ζωγραφίζει.
Το κουμπί (GPIO, προαιρετικό) ξεκινά τεστ στην επόμενη ετικέτα: POST /api/kit/field/test.

  python3 oled.py --stdout                 # χωρίς οθόνη: τυπώνει τις γραμμές στο τερματικό (για δοκιμή)
  python3 oled.py --stdout --once          # μία φορά και τέλος
  python3 oled.py                          # SSD1306 στο I2C 0x3C (θέλει luma.oled)
  python3 oled.py --button 17              # + κουμπί ανάμεσα σε GPIO17 (pin 11) και GND (pin 9)

Πώς περνάει τον έλεγχο του NetWatch (server.py):
  • τοπικά (http://127.0.0.1): τα POST θέλουν Content-Type: application/json, Host 127.0.0.1 και ΚΑΘΟΛΟΥ Origin.
  • λειτουργία agent (https + token): κάθε αίτημα θέλει «Authorization: Bearer <token>» (data/agent-token).
    Το πιστοποιητικό είναι self-signed → το «καρφώνουμε» με το SHA-256 του data/agent.crt ΠΡΙΝ σταλεί το token.
Το script μιλά μόνο με το NetWatch του ίδιου κουτιού. Χωρίς εξαρτήσεις για το --stdout.
"""
import argparse
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
LOOPBACK = ("127.0.0.1", "localhost", "::1")
MAX_LINES, MAX_COLS = 6, 21
OFFLINE = ["NetWatch field box", "waiting for NetWatch", "is the service up?"]


def clean(lines):
    """Ό,τι κι αν στείλει ο server: έως 6 γραμμές, 21 χαρακτήρες, μόνο εκτυπώσιμο ASCII."""
    out = []
    for x in (lines if isinstance(lines, list) else [])[:MAX_LINES]:
        out.append(re.sub(r"[^\x20-\x7e]", "?", str(x))[:MAX_COLS])
    return out


def cert_fingerprint(path):
    with open(path) as f:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()


def read_token(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


class Client:
    """GET/POST προς το τοπικό NetWatch με τους κανόνες του server (βλ. docstring)."""

    def __init__(self, url, token="", cert=None, timeout=4):
        m = re.match(r"^(https?)://(\[[0-9a-fA-F:]+\]|[^/:]+)(?::(\d+))?/?$", url or "")
        if not m:
            raise ValueError("Μη έγκυρο --url (π.χ. http://127.0.0.1:8765 ή https://127.0.0.1:8765)")
        self.tls, self.host = m.group(1) == "https", m.group(2).strip("[]")
        self.port = int(m.group(3) or (443 if self.tls else 80))
        self.token, self.timeout = token, timeout
        self.fp = None
        if self.tls:
            if not cert or not os.path.exists(cert):
                raise ValueError("Για https χρειάζεται το πιστοποιητικό του NetWatch (--cert data/agent.crt) για έλεγχο αποτυπώματος.")
            self.fp = cert_fingerprint(cert)
        elif self.host not in LOOPBACK:
            raise ValueError("Σκέτο http επιτρέπεται μόνο προς 127.0.0.1 — για άλλη διεύθυνση χρησιμοποίησε https (λειτουργία agent).")

    def headers(self, post=False):
        h = {"Accept": "application/json"}          # ποτέ Origin: ο server το δέχεται μόνο από την ίδια του τη σελίδα
        if post:
            h["Content-Type"] = "application/json"
        if self.token and (self.tls or self.host in LOOPBACK):
            h["Authorization"] = "Bearer " + self.token
        return h

    def _conn(self):
        if not self.tls:
            return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE             # ο έλεγχος γίνεται με το αποτύπωμα, πριν σταλεί οτιδήποτε
        c = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=ctx)
        c.connect()
        got = hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest()
        if got != self.fp:
            c.close()
            raise ssl.SSLError("άλλο πιστοποιητικό από το data/agent.crt — δεν στέλνω το token")
        return c

    def call(self, method, path, body=None):
        c = self._conn()
        try:
            c.request(method, path, json.dumps(body).encode() if method == "POST" else None, self.headers(method == "POST"))
            r = c.getresponse()
            raw = r.read(65536)
            try:
                return r.status, json.loads(raw or b"{}")
            except ValueError:
                return r.status, {}
        finally:
            c.close()

    def lines(self):
        st, j = self.call("GET", "/api/kit/field/oled")
        if st == 401:
            return ["NetWatch: 401", "token missing/wrong", "see data/agent-token"], {}
        if st != 200 or not isinstance(j, dict):
            return ["NetWatch: HTTP %d" % st, "socket tester is off?"], {}
        return clean(j.get("lines")) or OFFLINE, j

    def start_test(self, label=None):
        return self.call("POST", "/api/kit/field/test", {"label": label} if label else {})


# ───────────── έξοδοι ─────────────
class Stdout:
    def __init__(self, out=None):
        self.out = out or sys.stdout

    def show(self, lines):
        self.out.write("+" + "-" * MAX_COLS + "+\n")
        for x in (lines + [""] * MAX_LINES)[:MAX_LINES]:
            self.out.write("|" + x.ljust(MAX_COLS) + "|\n")
        self.out.write("+" + "-" * MAX_COLS + "+\n")
        self.out.flush()


class Oled:
    def __init__(self, bus=1, address=0x3C, rotate=0):
        try:
            from luma.core.interface.serial import i2c
            from luma.core.render import canvas
            from luma.oled.device import ssd1306
        except ImportError:
            sys.exit("Λείπει η βιβλιοθήκη της οθόνης (luma.oled).\n"
                     "  Εγκατάσταση:  sudo tools/fieldbox/install.sh --oled\n"
                     "  ή με το χέρι: sudo apt install python3-pil && .venv-oled/bin/pip install luma.oled\n"
                     "Για δοκιμή χωρίς οθόνη:  python3 tools/fieldbox/oled.py --stdout")
        self.canvas = canvas
        try:
            self.dev = ssd1306(i2c(port=bus, address=address), width=128, height=64, rotate=rotate)
        except Exception as e:  # noqa: BLE001 — δεν βρέθηκε η οθόνη στο I2C
            sys.exit(f"Δεν βρήκα οθόνη SSD1306 στο I2C bus {bus}, διεύθυνση 0x{address:02X}: {e}\n"
                     "  Έλεγξε την καλωδίωση (VCC→3V3, GND, SDA→GPIO2, SCL→GPIO3) και τρέξε: i2cdetect -y 1\n"
                     "  Το I2C ανοίγει με: sudo raspi-config nonint do_i2c 0")

    def show(self, lines):
        with self.canvas(self.dev) as draw:
            for i, x in enumerate(lines[:MAX_LINES]):
                draw.text((0, i * 10), x, fill="white")


def make_button(pin, on_press):
    try:
        from gpiozero import Button
    except ImportError:
        print("Το κουμπί θέλει τη βιβλιοθήκη gpiozero (sudo apt install python3-gpiozero) — συνεχίζω χωρίς κουμπί.", file=sys.stderr)
        return None
    try:
        b = Button(pin, pull_up=True, bounce_time=0.08)
    except Exception as e:  # noqa: BLE001
        print(f"Δεν άνοιξε το GPIO{pin}: {e} — συνεχίζω χωρίς κουμπί.", file=sys.stderr)
        return None
    b.when_pressed = on_press
    return b


def loop(client, screen, once=False, interval=1.0, sleep=time.sleep, pressed=None, max_iter=None):
    """Κύριος βρόχος. pressed: λίστα‑σημαία που γεμίζει το κουμπί (ή τα tests)."""
    last, state, n = None, {}, 0
    while True:
        n += 1
        if pressed:
            pressed.clear()
            try:
                if not state.get("busy"):
                    client.start_test(state.get("next") or None)
            except Exception:  # noqa: BLE001
                pass
        try:
            lines, state = client.lines()
        except Exception:  # noqa: BLE001 — το NetWatch δεν έχει σηκωθεί ακόμη / επανεκκινεί
            lines, state = list(OFFLINE), {}
        if lines != last:
            screen.show(lines)
            last = lines
        if once or (max_iter and n >= max_iter):
            return 0 if state else 1
        sleep(0.5 if state.get("busy") else interval)


def main(argv=None):
    ap = argparse.ArgumentParser(description="NetWatch field box — οθόνη OLED / κουμπί")
    ap.add_argument("--url", default=os.environ.get("NETWATCH_URL", "http://127.0.0.1:8765"),
                    help="το τοπικό NetWatch (agent: https://127.0.0.1:8765)")
    ap.add_argument("--token-file", default=os.path.join(REPO, "data", "agent-token"), help="token του agent (αν το NetWatch τρέχει με --agent)")
    ap.add_argument("--cert", default=os.path.join(REPO, "data", "agent.crt"), help="πιστοποιητικό του agent για έλεγχο αποτυπώματος (https)")
    ap.add_argument("--stdout", action="store_true", help="τύπωσε τις γραμμές στο τερματικό αντί για οθόνη")
    ap.add_argument("--once", action="store_true", help="μία ανάγνωση και τέλος")
    ap.add_argument("--test", action="store_true", help="ξεκίνα τώρα ένα τεστ στην επόμενη ετικέτα και τέλος")
    ap.add_argument("--button", type=int, metavar="GPIO", help="αριθμός GPIO (BCM) του κουμπιού, π.χ. 17")
    ap.add_argument("--bus", type=int, default=1)
    ap.add_argument("--address", type=lambda s: int(s, 0), default=0x3C)
    ap.add_argument("--rotate", type=int, default=0, choices=(0, 1, 2, 3), help="2 = ανάποδα")
    ap.add_argument("--interval", type=float, default=1.0)
    a = ap.parse_args(argv)
    try:
        client = Client(a.url, read_token(a.token_file) if a.url.startswith("https") else "", a.cert)
    except ValueError as e:
        sys.exit(str(e))
    if a.test:
        try:
            _lines, st = client.lines()
            code, j = client.start_test(st.get("next"))
        except Exception as e:  # noqa: BLE001
            sys.exit(f"Δεν μπόρεσα να ξεκινήσω τεστ: {e}")
        print("OK" if code == 200 and not j.get("error") else f"HTTP {code}: {j.get('error') or ''}")
        return 0 if code == 200 else 1
    screen = Stdout() if a.stdout else Oled(a.bus, a.address, a.rotate)
    pressed = []
    keep = make_button(a.button, lambda: pressed.append(1)) if a.button is not None else None  # noqa: F841 — να μη σβηστεί
    try:
        return loop(client, screen, once=a.once, interval=max(0.3, a.interval), pressed=pressed)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
