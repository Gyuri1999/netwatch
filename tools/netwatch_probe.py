#!/usr/bin/env python3
"""NetWatch probe — αισθητήρας για Raspberry Pi (π.χ. Zero 2 W) ή οποιονδήποτε υπολογιστή με Python 3.

Χωρίς εξαρτήσεις. Στέλνει κάθε λίγο στο NetWatch: ότι είναι ζωντανός, IP, φόρτο, θερμοκρασία (Pi),
και αν «βλέπει» το router. Αν το router χαθεί → γεγονός «outage».

  python3 netwatch_probe.py pair                # πάτα 📋 Αντιγραφή στο 🧩 Οι συσκευές μου — παίρνει τον κωδικό από το clipboard
  python3 netwatch_probe.py run                 # τρέχει για πάντα (βάλ' το σε systemd — δες --systemd)
  python3 netwatch_probe.py once                # μία αναφορά, για δοκιμή
  python3 netwatch_probe.py --systemd           # τυπώνει έτοιμο αρχείο υπηρεσίας

Ασφάλεια: η σύνδεση είναι HTTPS και ελέγχεται το αποτύπωμα SHA-256 του πιστοποιητικού του NetWatch (pinning).
Το token φυλάσσεται στο ~/.netwatch-probe.json με δικαιώματα 600. Μόνο ping στο δικό σου router — τίποτα άλλο.
"""
import base64
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

CONF = os.path.expanduser(os.environ.get("NETWATCH_PROBE_CONF", "~/.netwatch-probe.json"))
FW = "1.0.0"


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
        sys.exit(f"Δεν βρέθηκε σύζευξη ({CONF}). Τρέξε πρώτα: python3 netwatch_probe.py pair")


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


def gateway():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if p[1] == "00000000" and int(p[3], 16) & 2:
                    return socket.inet_ntoa(bytes.fromhex(p[2])[::-1])
    except OSError:
        pass
    try:
        out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"gateway:\s*([\d.]+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


def ping_ms(ip):
    if not ip:
        return None
    flag = ["-n", "1", "-w", "1500"] if os.name == "nt" else ["-c", "1", "-W", "2" if sys.platform.startswith("linux") else "2000"]
    try:
        out = subprocess.run(["ping", *flag, ip], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"time[=<]([\d.]+)", out)
    return round(float(m.group(1)), 1) if m else None


def my_ip(gw):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((gw or "192.168.1.1", 9))  # UDP: δεν στέλνει τίποτα, μόνο διαλέγει interface
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def status(interval, gw, gw_ms):
    st = {"fw": FW, "os": f"{platform.system()} {platform.release()}"[:60], "interval": interval,
          "ip": my_ip(gw), "metrics": {"gw_ms": gw_ms, "gw_ok": gw_ms is not None}}
    try:
        with open("/proc/device-tree/model") as f:
            st["hw"] = f.read().strip("\x00\n")[:60]
    except OSError:
        st["hw"] = platform.machine()
    try:
        with open("/proc/uptime") as f:
            st["uptime"] = int(float(f.read().split()[0]))
    except OSError:
        pass
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            st["temp"] = round(int(f.read()) / 1000, 1)
    except (OSError, ValueError):
        pass
    try:
        st["metrics"]["load"] = round(os.getloadavg()[0], 2)
    except (OSError, AttributeError):
        pass
    return st


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return
    if a[0] == "--systemd":
        print(f"""[Unit]
Description=NetWatch probe
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 {os.path.abspath(__file__)} run
Restart=always
RestartSec=15
User={os.environ.get('USER', 'pi')}

[Install]
WantedBy=multi-user.target
# sudo tee /etc/systemd/system/netwatch-probe.service < αυτό && sudo systemctl enable --now netwatch-probe""")
        return
    if a[0] == "pair":
        code = a[1].strip() if len(a) > 1 else ""
        if not code.startswith("NW1."):
            clip = clipboard()
            if clip.startswith("NW1."):
                print("📋 Πήρα τον κωδικό από το clipboard.")
                code = clip
            elif sys.stdin.isatty():
                print("Στο NetWatch: 🧩 Οι συσκευές μου → πάτα μια κάρτα → 🔑 Δημιουργία κωδικού → 📋 Αντιγραφή.")
                code = input("Επικόλλησε εδώ τον κωδικό (ξεκινά με NW1.) και πάτα Enter: ").strip()
        conf = read_code(code)
        if conf.get("v") != 1 or not conf.get("t") or not conf.get("fp"):
            sys.exit("Ελλιπής κωδικός σύζευξης.")
        save(conf)
        r = post(conf, {"status": status(60, gateway(), None), "events": []})
        print(f"✔ Συνδέθηκε στο NetWatch ως «{r.get('name')}».  Τώρα: netwatch_probe.py run")
        return
    conf = load()
    interval, down = 60, False
    while True:
        gw = gateway()
        ms = ping_ms(gw)
        evs = []
        if ms is None and not down:
            down = True
            evs.append({"type": "outage", "detail": f"Δεν απαντά το router {gw or '?'} από το {socket.gethostname()}",
                        "data": {"gw": gw or ""}})
        elif ms is not None and down:
            down = False
            evs.append({"type": "restored", "detail": "Το router απαντά ξανά", "data": {"gw": gw or ""}})
        try:
            r = post(conf, {"status": status(interval, gw, ms), "events": evs})
            interval = int(r.get("interval") or interval)
            save(conf)
        except RuntimeError as e:
            print(e, file=sys.stderr)
            if evs:  # θα ξαναστείλουμε την επόμενη φορά
                down = evs[0]["type"] != "outage"
        if a[0] == "once":
            return
        time.sleep(interval)


if __name__ == "__main__":
    main()
