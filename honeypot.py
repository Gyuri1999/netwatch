"""Παγίδα (honeypot): ψεύτικες υπηρεσίες σε θύρες που κανείς δεν έχει λόγο να αγγίξει.

Κανείς νόμιμος δεν συνδέεται σε μια υπηρεσία που δεν υπάρχει, οπότε όποιος συνδεθεί είναι
σχεδόν σίγουρα κάποιος που σκανάρει ή δοκιμάζει κωδικούς (ή κακόβουλο λογισμικό σε συσκευή του δικτύου).

Ασφάλεια:
- ΚΛΕΙΣΤΟ από προεπιλογή — ανοίγει μόνο όταν το ζητήσεις.
- Δεν εκτελεί τίποτα: στέλνει ένα ψεύτικο banner, διαβάζει έως 1 KB για 5″ και κλείνει.
- Θύρες > 1024, άρα δεν χρειάζεται root.
"""
import socket
import threading
import time

# θύρα → (υπηρεσία που προσποιείται, banner, εξήγηση)
SERVICES = {
    2222: ("SSH", b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n", "ψεύτικο SSH: εδώ πέφτουν bots που δοκιμάζουν κωδικούς"),
    2323: ("Telnet", b"\r\nUbuntu 22.04 LTS\r\nlogin: ", "ψεύτικο Telnet: το αγαπημένο των IoT botnets (π.χ. Mirai)"),
    8080: ("HTTP admin", b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Router admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
           "ψεύτικη σελίδα διαχείρισης router"),
    9100: ("Printer", b"", "ψεύτικος εκτυπωτής (JetDirect): τον σκανάρουν πολλά εργαλεία"),
    3389: ("RDP", b"", "ψεύτικο Remote Desktop"),
    5900: ("VNC", b"RFB 003.008\n", "ψεύτικο VNC (απομακρυσμένη οθόνη)"),
}
DEFAULT_PORTS = [2222, 2323, 8080, 9100]


def clean(data, limit=160):
    """Ασφαλής, εκτυπώσιμη μορφή των bytes που έστειλε ο επισκέπτης."""
    t = data.decode("latin-1").replace("\r\n", "\n").strip("\r\n")
    s = "".join(" ⏎ " if c in "\r\n" else c if 32 <= ord(c) < 127 else "·" for c in t)
    return s[:limit]


class Honeypot:
    def __init__(self, on_hit, sim=False, bind="0.0.0.0"):
        self.on_hit, self.sim, self.bind = on_hit, sim, bind
        self.lock = threading.Lock()
        self.socks, self.hits, self.errors, self.ports = {}, [], {}, []

    @property
    def running(self):
        return bool(self.socks) or (self.sim and bool(self.ports))

    def status(self):
        with self.lock:
            return {"running": self.running, "ports": self.ports, "listening": sorted(self.socks), "errors": self.errors,
                    "hits": self.hits[-50:][::-1], "services": {p: [s[0], s[2]] for p, s in SERVICES.items()},
                    "default": DEFAULT_PORTS, "demo": self.sim}

    def start(self, ports=None):
        self.stop()
        ports = sorted({int(p) for p in (ports or DEFAULT_PORTS) if int(p) in SERVICES})
        with self.lock:
            self.ports, self.errors = ports, {}
        if self.sim:
            t = threading.Timer(4, self._demo_hit)
            t.daemon = True
            t.start()
            return self.status()
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.bind, p))
                s.listen(16)
            except OSError as e:
                self.errors[p] = "η θύρα είναι πιασμένη" if e.errno in (48, 98) else str(e)[:80]
                continue
            with self.lock:
                self.socks[p] = s
            threading.Thread(target=self._serve, args=(p, s), daemon=True).start()
        return self.status()

    def stop(self):
        with self.lock:
            socks, self.socks, self.ports = self.socks, {}, []
        for s in socks.values():
            try:
                s.close()
            except OSError:
                pass
        return self.status()

    def _serve(self, port, srv):
        while True:
            try:
                c, (ip, rport) = srv.accept()
            except OSError:
                return  # έκλεισε
            threading.Thread(target=self._talk, args=(port, c, ip), daemon=True).start()

    def _talk(self, port, c, ip):
        name, banner, _ = SERVICES[port]
        data = b""
        try:
            c.settimeout(5)
            if banner:
                c.sendall(banner)
            while len(data) < 1024:
                chunk = c.recv(1024 - len(data))
                if not chunk:
                    break
                data += chunk
                if port == 2323 and data.count(b"\n") == 1:
                    c.sendall(b"Password: ")  # συνέχισε το θέατρο για να δεις και τον κωδικό που δοκιμάζει
                elif port != 2323 and b"\n" in data:
                    break
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass
        self._record(port, name, ip, data)

    def _record(self, port, name, ip, data):
        hit = {"t": time.time(), "ip": ip, "port": port, "service": name, "data": clean(data),
               "self": ip.startswith("127.") or ip == "::1"}
        with self.lock:
            self.hits.append(hit)
            del self.hits[:-200]
        try:
            self.on_hit(hit)
        except Exception:
            pass

    def _demo_hit(self):
        if self.ports:
            p = 2323 if 2323 in self.ports else self.ports[0]
            self._record(p, SERVICES[p][0], "192.168.1.66", b"root\r\nxc3511\r\n" if p == 2323 else b"GET / HTTP/1.1\r\n")
