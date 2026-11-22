#!/usr/bin/env python3
"""NetWatch Zigbee/Thread sniffer — αισθητήρας 802.15.4 για Raspberry Pi ή υπολογιστή με nRF52840 USB dongle.

Το dongle πρέπει να έχει το firmware «nRF Sniffer for 802.15.4» της Nordic (nRF Connect → Programmer).
Το script του μιλά από τη σειριακή του (εντολές `sleep`, `channel <n>`, `receive`), γυρίζει τα κανάλια 11→26,
διαβάζει ΜΟΝΟ την επικεφαλίδα MAC κάθε πλαισίου (τύπος, PAN, διευθύνσεις) μαζί με RSSI/LQI και στέλνει στο NetWatch
μια σύνοψη ανά (κανάλι, PAN, πηγή). Δεν αποκρυπτογραφεί και δεν κρατά ποτέ περιεχόμενο πλαισίων. Δεν εκπέμπει τίποτα.

  python3 zigbee_sniff.py pair                  # πάτα 📋 Αντιγραφή στο 🧩 Οι συσκευές μου (τύπος «Sniffer Zigbee / Thread»)
  python3 zigbee_sniff.py run                   # τρέχει για πάντα (βάλ' το σε systemd — δες --systemd)
  python3 zigbee_sniff.py once                  # ένα πέρασμα 11→26 και μία αναφορά, για δοκιμή
  python3 zigbee_sniff.py --systemd             # τυπώνει έτοιμο αρχείο υπηρεσίας
Επιλογές:  --port /dev/ttyACM0   --dwell 2.0 (δευτερόλεπτα ανά κανάλι)   --replay αρχείο.txt (γραμμές sniffer από αρχείο,
           χωρίς hardware)   --dry (τύπωσε την αναφορά αντί να τη στείλεις)

Σειριακή: με pyserial αν υπάρχει (`pip install pyserial`)· σε Linux/macOS δουλεύει και χωρίς (termios).
Ασφάλεια: HTTPS με έλεγχο αποτυπώματος SHA-256 (pinning)· το token στο ~/.netwatch-zigbee.json με δικαιώματα 600.
"""
import base64
import glob
import hashlib
import http.client
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time

CONF = os.path.expanduser(os.environ.get("NETWATCH_ZIGBEE_CONF", "~/.netwatch-zigbee.json"))
FW = "1.0.0"
CHANNELS = range(11, 27)
MAX_ROWS = 80
MAX_KEYS = 2000  # διαφορετικά (κανάλι, PAN, πηγή) που κρατάμε σε ένα πέρασμα
NORDIC_VID, SNIFFER_PID = 0x1915, 0x154B  # όπως στο nrf802154_sniffer.py της Nordic
# γραμμή του firmware: «received: <hex> power: <dBm> lqi: <n> time: <us>» (ίδιο regex με το extcap της Nordic)
RCV_RX = re.compile(r"received:\s+([0-9a-fA-F]+)\s+power:\s+(-?\d+)\s+lqi:\s+(\d+)\s+time:\s+(-?\d+)")
CHAN_RX = re.compile(r"^\s*(?:#\s*)?channel[:\s]+(\d+)\s*$", re.I)
TYPES = {0: "beacon", 1: "data", 2: "ack", 3: "cmd"}


# ───────── 802.15.4: μόνο η επικεφαλίδα MAC ─────────
def parse_154(frame_bytes):
    """Πλαίσιο 802.15.4 (χωρίς FCS) → {"type", "ver", "sec", "seq", "dst_pan", "dst", "src_pan", "src", "pan", "cmd"} ή None.

    Διαβάζει το Frame Control, τον αριθμό σειράς και τα πεδία διευθύνσεων (με PAN ID compression, και τους κανόνες
    της έκδοσης 2015 που χρησιμοποιεί το Thread). Το ωφέλιμο φορτίο ΔΕΝ επιστρέφεται ούτε αποθηκεύεται· μόνο για
    μη κρυπτογραφημένες εντολές MAC κρατάμε τον κωδικό εντολής (1 byte, π.χ. 7 = beacon request)."""
    b = bytes(frame_bytes or b"")
    if len(b) < 3 or len(b) > 127:
        return None
    fcf = b[0] | (b[1] << 8)
    ftype, sec, comp = fcf & 7, bool(fcf & 0x08), bool(fcf & 0x40)
    dmode, ver, smode = (fcf >> 10) & 3, (fcf >> 12) & 3, (fcf >> 14) & 3
    if ftype not in TYPES or dmode == 1 or smode == 1 or ver == 3:
        return None  # δεσμευμένες τιμές: σκουπίδια ή πλαίσιο που δεν μας αφορά
    i, seq = 2, None
    if not (ver == 2 and fcf & 0x0100):  # sequence number suppression (μόνο 2015)
        seq = b[i]
        i += 1
    if ver < 2:
        dpan, span = dmode != 0, smode != 0 and not comp
    elif dmode == 0 and smode == 0:
        dpan, span = comp, False
    elif smode == 0:
        dpan, span = not comp, False
    elif dmode == 0:
        dpan, span = False, not comp
    elif dmode == 3 and smode == 3:
        dpan, span = not comp, False
    else:
        dpan, span = True, not comp

    def take(n):
        nonlocal i
        if i + n > len(b):
            raise IndexError
        v = b[i:i + n][::-1].hex()  # little-endian στο καλώδιο → το γράφουμε «κανονικά»
        i += n
        return v
    try:
        dst_pan = take(2) if dpan else ""
        dst = take(2 if dmode == 2 else 8) if dmode else ""
        src_pan = take(2) if span else ""
        src = take(2 if smode == 2 else 8) if smode else ""
    except IndexError:
        return None
    cmd = b[i] if ftype == 3 and not sec and ver < 2 and i < len(b) else None
    return {"type": TYPES[ftype], "ver": ver, "sec": sec, "seq": seq, "dst_pan": dst_pan, "dst": dst, "src_pan": src_pan, "src": src,
            "pan": src_pan or dst_pan, "cmd": cmd}


def parse_line(line):
    """Γραμμή του sniffer → (πλαίσιο χωρίς FCS, rssi, lqi) ή None. Τα 2 τελευταία byte είναι το FCS (όπως τα κόβει και η Nordic)."""
    if isinstance(line, bytes):
        line = line.decode("ascii", "replace")
    if len(line) > 600:
        return None
    m = RCV_RX.search(line)
    if not m or len(m.group(1)) % 2 or len(m.group(1)) > 254:
        return None
    try:
        raw = bytes.fromhex(m.group(1))
        rssi, lqi = int(m.group(2)), int(m.group(3))
    except ValueError:
        return None
    if not -130 <= rssi <= 20 or not 0 <= lqi <= 255:
        return None
    return raw[:-2], rssi, lqi


class Agg:
    """Σύνοψη ενός περάσματος: μετρητές ανά κανάλι και ανά (κανάλι, PAN, πηγή). Κανένα περιεχόμενο πλαισίου."""

    def __init__(self):
        self.ch = {c: 0 for c in CHANNELS}
        self.rows = {}
        self.frames = self.bad = 0

    def add(self, ch, frame, rssi, lqi):
        if ch not in self.ch:
            return
        h = parse_154(frame)
        if h is None:
            self.bad += 1
            return
        self.frames += 1
        self.ch[ch] += 1
        key = (ch, h["pan"], h["src"])
        r = self.rows.get(key)
        if r is None:
            if len(self.rows) >= MAX_KEYS:
                return
            r = self.rows[key] = {"n": 0, "rssi": 0, "lqi": 0, "t": {}}
        r["n"] += 1
        r["rssi"] += rssi
        r["lqi"] += lqi
        r["t"][h["type"]] = r["t"].get(h["type"], 0) + 1

    def feed(self, ch, line):
        p = parse_line(line)
        if p:
            self.add(ch, *p)

    def items(self):
        out = []
        for (ch, pan, src), r in sorted(self.rows.items(), key=lambda kv: (-kv[1]["n"], kv[0]))[:MAX_ROWS]:
            typ = "beacon" if "beacon" in r["t"] else max(sorted(r["t"]), key=lambda k: r["t"][k])  # ένα beacon αρκεί: είναι router/coordinator
            out.append({"ch": ch, "pan": pan, "src": src, "rssi": int(round(r["rssi"] / r["n"])), "lqi": int(round(r["lqi"] / r["n"])),
                        "n": r["n"], "t": typ})
        return out

    def body(self, interval=60, hw="nRF52840 802.15.4 sniffer", uptime=None):
        st = {"fw": FW, "hw": hw[:60], "os": f"{platform.system()} {platform.release()}"[:60], "interval": int(interval),
              "metrics": dict({"ch%d" % c: n for c, n in self.ch.items()}, frames=self.frames, bad=self.bad)}
        if uptime is not None:
            st["uptime"] = int(uptime)
        return {"status": st, "events": [], "items": self.items()}


def replay(path):
    """Αρχείο με γραμμές sniffer (και προαιρετικά «channel 15» πριν από κάθε ομάδα) → Agg. Για δοκιμές χωρίς hardware."""
    agg, ch = Agg(), 11
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f):
            if n > 200000:
                break
            m = CHAN_RX.match(line)
            if m:
                ch = int(m.group(1))
                continue
            agg.feed(ch, line)
    return agg


# ───────── σειριακή ─────────
class PySerialPort:
    def __init__(self, path, serial):
        self.s = serial.Serial(path, exclusive=True, timeout=0.1)

    def write(self, data):
        self.s.write(data)

    def read(self):
        return self.s.read(self.s.in_waiting or 1)

    def close(self):
        self.s.close()


class RawPort:
    """Χωρίς pyserial (Linux/macOS): ανοίγουμε τη συσκευή σε raw mode με termios. Το dongle είναι USB CDC, το baud δεν παίζει ρόλο."""

    def __init__(self, path):
        import fcntl
        import termios
        import tty
        self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # μόνο ένας τη φορά, όπως το exclusive=True του pyserial
            tty.setraw(self.fd)
            a = termios.tcgetattr(self.fd)
            a[2] |= termios.CLOCAL | termios.CREAD
            a[4] = a[5] = termios.B115200
            termios.tcsetattr(self.fd, termios.TCSANOW, a)
            termios.tcflush(self.fd, termios.TCIOFLUSH)
        except Exception:
            os.close(self.fd)
            raise

    def write(self, data):
        import select
        end = time.time() + 2
        while data and time.time() < end:
            select.select([], [self.fd], [], 0.5)
            try:
                data = data[os.write(self.fd, data):]
            except BlockingIOError:
                pass

    def read(self):
        import select
        if not select.select([self.fd], [], [], 0.1)[0]:
            return b""
        try:
            d = os.read(self.fd, 4096)
        except BlockingIOError:
            return b""
        if not d:
            raise OSError("η σειριακή έκλεισε (βγήκε το dongle;)")
        return d

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass


def find_port():
    """Το dongle: πρώτα με USB VID/PID της Nordic (αν υπάρχει pyserial), αλλιώς η πρώτη ttyACM / usbmodem."""
    try:
        from serial.tools.list_ports import comports
        for p in comports():
            if p.vid == NORDIC_VID and p.pid == SNIFFER_PID:
                return p.device
    except ImportError:
        pass
    for pat in ("/dev/serial/by-id/*nRF52*", "/dev/serial/by-id/*Nordic*", "/dev/ttyACM*", "/dev/cu.usbmodem*"):
        found = sorted(glob.glob(pat))
        if found:
            return found[0]
    return None


def open_port(path):
    if not path:
        sys.exit("Δεν βρήκα nRF52840 dongle. Σύνδεσέ το (με firmware «nRF Sniffer for 802.15.4») ή δώσε --port /dev/ttyACM0 (Windows: --port COM5).")
    try:
        import serial
    except ImportError:
        serial = None
    try:
        if serial is not None:
            return PySerialPort(path, serial)
        if os.name != "posix":
            sys.exit("Στα Windows χρειάζεται η βιβλιοθήκη pyserial για τη σειριακή του dongle. Τρέξε:  pip install pyserial")
        return RawPort(path)
    except (OSError, ValueError) as e:  # το SerialException του pyserial είναι OSError
        sys.exit(f"Δεν άνοιξε η σειριακή {path}: {e}\n(Linux: πρόσθεσε τον χρήστη στην ομάδα dialout· ή εγκατάστησε pyserial: pip install pyserial)")
    except Exception as e:  # noqa: BLE001
        sys.exit(f"Δεν άνοιξε η σειριακή {path}: {e}")


class Sniffer:
    """Το κέλυφος (shell) του firmware της Nordic: `sleep` · `shell echo off` · `channel <n>` · `receive`."""

    def __init__(self, port, clock=time.time):
        self.p, self.clock, self.buf = port, clock, b""

    def cmd(self, text):
        self.p.write(text.encode("ascii") + b"\r\n")

    def drain(self, secs=0.3):
        end = self.clock() + secs
        while self.clock() < end:
            self.p.read()
        self.buf = b""

    def start(self):
        self.cmd("sleep")
        self.cmd("shell echo off")
        self.drain()

    def lines(self, secs):
        end = self.clock() + secs
        while self.clock() < end:
            self.buf += self.p.read()
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                yield line
            if len(self.buf) > 4096:  # θόρυβος χωρίς αλλαγή γραμμής
                self.buf = b""

    def listen(self, ch, dwell, agg):
        self.cmd("sleep")  # η Nordic ορίζει κανάλι μόνο πριν το receive — άρα: σταμάτα, άλλαξε, ξανάρχισε
        self.cmd(f"channel {int(ch)}")
        self.cmd("receive")
        for line in self.lines(dwell):
            agg.feed(ch, line)

    def stop(self):
        try:
            self.p.write(b"\r\n")
            self.cmd("sleep")
            self.drain(0.2)
        except OSError:
            pass


def sweep(sn, dwell):
    agg = Agg()
    for ch in CHANNELS:
        sn.listen(ch, dwell, agg)
    return agg


# ───────── σύζευξη / αποστολή (ίδια με το netwatch_probe.py) ─────────
def read_code(code):
    code = code.strip()
    if not code.startswith("NW1."):
        sys.exit("Δεν είναι κωδικός σύζευξης NetWatch (ξεκινά με NW1.)")
    b = code[4:]
    return json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)))


def clipboard():
    """Ο κωδικός από το clipboard (macOS pbpaste, Linux wl-paste/xclip, Windows PowerShell)."""
    for cmd in (["pbpaste"], ["wl-paste", "-n"], ["xclip", "-o", "-selection", "clipboard"],
                ["powershell", "-NoProfile", "-Command", "Get-Clipboard"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            continue
        if out:
            return out
    return ""


def save(conf):
    fd = os.open(CONF, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(conf, f)


def load():
    try:
        with open(CONF) as f:
            return json.load(f)
    except (OSError, ValueError):
        sys.exit(f"Δεν βρέθηκε σύζευξη ({CONF}). Τρέξε πρώτα: python3 zigbee_sniff.py pair")


def post(conf, body):
    """HTTPS με pinning: συνδεόμαστε, ελέγχουμε το αποτύπωμα, ΜΕΤΑ στέλνουμε το token."""
    last = None
    for url in conf["u"]:
        m = re.match(r"^https://([^/:]+):(\d+)$", url)
        if not m:
            continue
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # ο έλεγχος γίνεται με το αποτύπωμα παρακάτω
        c = http.client.HTTPSConnection(m.group(1), int(m.group(2)), timeout=8, context=ctx)
        try:
            c.connect()
            fp = hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest().upper()
            if ":".join(fp[i:i + 2] for i in range(0, 64, 2)) != conf["fp"].upper():
                raise ssl.SSLError("άλλο πιστοποιητικό από αυτό της σύζευξης — δεν στέλνω το token")
            c.request("POST", "/probe/v1/report", json.dumps(body),
                      {"Content-Type": "application/json", "Authorization": "Bearer " + conf["t"]})
            r = c.getresponse()
            data = json.loads(r.read(4096) or b"{}")
            if r.status != 200:
                raise RuntimeError(f"HTTP {r.status}: {data.get('error')}")
            if conf["u"][0] != url:  # θυμήσου ποια διεύθυνση δούλεψε
                conf["u"].remove(url)
                conf["u"].insert(0, url)
            return data
        except (OSError, ssl.SSLError, RuntimeError, ValueError) as e:
            last = e
        finally:
            c.close()
    raise RuntimeError(f"Δεν βρήκα το NetWatch: {last}")


def my_ip(conf):
    m = re.match(r"^https://([^/:]+):", (conf.get("u") or [""])[0])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((m.group(1) if m else "192.168.1.1", 9))  # UDP: δεν στέλνει τίποτα, μόνο διαλέγει interface
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _opt(a, name, default=None):
    if name in a:
        i = a.index(name)
        if i + 1 >= len(a):
            sys.exit(f"Λείπει η τιμή μετά το {name}")
        v = a[i + 1]
        del a[i:i + 2]
        return v
    return default


def main(argv=None):
    a = list(sys.argv[1:] if argv is None else argv)
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return
    if a[0] == "--systemd":
        print(f"""[Unit]
Description=NetWatch Zigbee/Thread sniffer
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 {os.path.abspath(__file__)} run
Restart=always
RestartSec=15
User={os.environ.get('USER', 'pi')}
SupplementaryGroups=dialout

[Install]
WantedBy=multi-user.target
# sudo tee /etc/systemd/system/netwatch-zigbee.service < αυτό && sudo systemctl enable --now netwatch-zigbee""")
        return
    port, rep, dry = _opt(a, "--port"), _opt(a, "--replay"), "--dry" in a
    try:
        dwell = max(0.2, min(30.0, float(_opt(a, "--dwell", "2"))))
    except ValueError:
        sys.exit("Το --dwell θέλει αριθμό δευτερολέπτων (π.χ. 2).")
    a = [x for x in a if x != "--dry"]
    mode = a[0] if a else ""
    if mode not in ("pair", "run", "once"):
        sys.exit("Άγνωστη εντολή. Δες: python3 zigbee_sniff.py --help")
    if mode == "pair":
        code = a[1].strip() if len(a) > 1 else ""
        if not code.startswith("NW1."):
            clip = clipboard()
            if clip.startswith("NW1."):
                print("📋 Πήρα τον κωδικό από το clipboard.")
                code = clip
            elif sys.stdin.isatty():
                print("Στο NetWatch: 🧩 Οι συσκευές μου → «Sniffer Zigbee / Thread» → 🔑 Δημιουργία κωδικού → 📋 Αντιγραφή.")
                code = input("Επικόλλησε εδώ τον κωδικό (ξεκινά με NW1.) και πάτα Enter: ").strip()
        conf = read_code(code)
        if conf.get("v") != 1 or not conf.get("t") or not conf.get("fp"):
            sys.exit("Ελλιπής κωδικός σύζευξης.")
        save(conf)
        r = post(conf, {"status": {"fw": FW, "hw": "nRF52840 802.15.4 sniffer", "interval": 60, "ip": my_ip(conf)}, "events": []})
        print(f"✔ Συνδέθηκε στο NetWatch ως «{r.get('name')}».  Τώρα: zigbee_sniff.py run")
        return
    conf = None if dry else load()
    interval = int(round(len(CHANNELS) * dwell)) + 5
    t0 = time.time()

    def send(agg, hw):
        body = agg.body(interval, hw, time.time() - t0)
        if dry:
            print(json.dumps(body, ensure_ascii=False))
            return
        body["status"]["ip"] = my_ip(conf)
        try:
            post(conf, body)
            save(conf)
        except RuntimeError as e:
            print(e, file=sys.stderr)

    if rep:
        try:
            agg = replay(rep)
        except OSError as e:
            sys.exit(f"Δεν διαβάζεται το αρχείο {rep}: {e}")
        send(agg, "replay " + os.path.basename(rep))
        return
    while True:
        path = port or find_port()
        sn = Sniffer(open_port(path))
        try:
            sn.start()
            while True:
                send(sweep(sn, dwell), "nRF52840 sniffer " + os.path.basename(str(path)))
                if mode == "once":
                    return
        except OSError as e:  # βγήκε το dongle: περίμενε και ξαναδοκίμασε
            print(f"Σειριακή: {e} — ξαναδοκιμάζω σε 10″", file=sys.stderr)
            if mode == "once":
                sys.exit(1)
            time.sleep(10)
        except KeyboardInterrupt:
            return
        finally:
            sn.stop()
            sn.p.close()


if __name__ == "__main__":
    main()
