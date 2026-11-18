"""🧅 Tor: τα κυκλώματά σου ζωντανά, μέσω του control port του δικού σου Tor (χωρίς stem — γραμμένο από την αρχή).

config.yaml:
tor:
  enabled: true
  control_port: 9051        # αν λείπει: δοκιμάζουμε 9051 (tor daemon) και μετά 9151 (Tor Browser)
  cookie_file: /usr/local/var/lib/tor/control_auth_cookie   # προαιρετικό — αλλιώς ό,τι λέει το PROTOCOLINFO
  interval: 10

Συνδεόμαστε ΜΟΝΟ στο loopback (127.0.0.1 / ::1) — ποτέ σε άλλο μηχάνημα.
Ταυτοποίηση: NULL, SAFECOOKIE (προτιμάται) ή COOKIE. Κωδικό (HashedControlPassword) σκόπιμα δεν υποστηρίζουμε.
Μόνο εντολές ανάγνωσης (GETINFO). Η μόνη «εγγραφή» είναι το SIGNAL NEWNYM (νέα κυκλώματα), το πολύ μία φορά / 10″.

Ειδοποίηση: «Άλλαξε ο Tor guard» (low) όταν αλλάζει ο κύριος entry guard — κανονικά αλλάζει μόνο κάθε λίγους μήνες.
"""
import binascii
import calendar
import hashlib
import hmac
import io
import ipaddress
import os
import random
import re
import socket
import threading
import time

DEFAULT_PORTS = (9051, 9151)
CONNECT_TIMEOUT = 3.0
NEWNYM_GAP = 10.0
MAX_CIRCUITS = 8
GUARD_COOLDOWN = 86400
RELAY_CACHE = 500
SIM_ROTATE = 600

SERVER_KEY = b"Tor safe cookie authentication server-to-controller hash"
CLIENT_KEY = b"Tor safe cookie authentication controller-to-server hash"

HINT = ("Δεν βρέθηκε προσβάσιμο control port του Tor. Πρόσθεσε στο torrc (macOS/Homebrew: "
        "/opt/homebrew/etc/tor/torrc, Linux: /etc/tor/torrc) τις γραμμές «ControlPort 9051» και "
        "«CookieAuthentication 1» και κάνε επανεκκίνηση του Tor (π.χ. brew services restart tor ή "
        "sudo systemctl restart tor). Το Tor Browser ανοίγει μόνο του το 9151 όσο τρέχει. "
        "Στο Linux ο χρήστης του NetWatch πρέπει να διαβάζει το control_auth_cookie (ομάδα debian-tor).")
HINT_PASSWORD = ("Το Tor ζητά κωδικό (HashedControlPassword), που το NetWatch σκόπιμα δεν υποστηρίζει. "
                 "Βάλε «CookieAuthentication 1» στο torrc και κάνε επανεκκίνηση του Tor.")
HINT_COOKIE = ("Το Tor ζητά cookie αλλά το αρχείο δεν διαβάζεται ({path}). Δώσε δικαίωμα ανάγνωσης στον χρήστη "
               "του NetWatch (Linux: sudo usermod -aG debian-tor $USER) ή όρισε tor.cookie_file στο config.")

# Κέντρα χωρών (περίπου) — για να ζωγραφίζει το UI τόξα χωρίς geo lookups.
CENTROIDS = {
    "AD": (42.5, 1.5), "AE": (24.0, 54.0), "AL": (41.0, 20.0), "AM": (40.0, 45.0), "AR": (-34.0, -64.0),
    "AT": (47.5, 14.5), "AU": (-25.0, 134.0), "BA": (44.0, 18.0), "BD": (24.0, 90.0), "BE": (50.8, 4.5),
    "BG": (42.7, 25.5), "BR": (-10.0, -52.0), "BY": (53.5, 28.0), "CA": (56.0, -96.0), "CH": (46.8, 8.2),
    "CL": (-33.0, -71.0), "CN": (35.0, 103.0), "CO": (4.0, -73.0), "CR": (10.0, -84.0), "CY": (35.0, 33.0),
    "CZ": (49.8, 15.5), "DE": (51.0, 10.0), "DK": (56.0, 10.0), "DZ": (28.0, 2.6), "EC": (-1.5, -78.0),
    "EE": (58.7, 25.0), "EG": (26.5, 30.0), "ES": (40.0, -4.0), "FI": (64.0, 26.0), "FR": (46.5, 2.5),
    "GB": (54.0, -2.5), "GE": (42.0, 43.5), "GR": (39.0, 22.0), "HK": (22.3, 114.2), "HR": (45.2, 15.5),
    "HU": (47.0, 19.5), "ID": (-2.5, 118.0), "IE": (53.2, -8.0), "IL": (31.5, 35.0), "IN": (22.0, 79.0),
    "IR": (32.0, 53.0), "IS": (65.0, -18.5), "IT": (42.8, 12.5), "JP": (36.5, 138.0), "KE": (0.5, 38.0),
    "KR": (36.5, 128.0), "KZ": (48.0, 67.0), "LI": (47.15, 9.55), "LT": (55.3, 24.0), "LU": (49.8, 6.1),
    "LV": (57.0, 25.0), "MA": (32.0, -6.0), "MD": (47.2, 28.5), "MK": (41.6, 21.7), "MT": (35.9, 14.4),
    "MX": (23.5, -102.0), "MY": (4.0, 102.0), "NG": (9.5, 8.0), "NL": (52.2, 5.5), "NO": (61.0, 9.0),
    "NZ": (-41.5, 172.5), "PA": (8.5, -80.0), "PE": (-9.5, -75.0), "PH": (12.5, 122.0), "PK": (30.0, 70.0),
    "PL": (52.0, 19.5), "PT": (39.6, -8.0), "RO": (45.9, 25.0), "RS": (44.0, 20.8), "RU": (60.0, 90.0),
    "SA": (24.0, 45.0), "SC": (-4.6, 55.5), "SE": (62.0, 15.0), "SG": (1.35, 103.8), "SI": (46.1, 14.8),
    "SK": (48.7, 19.5), "TH": (15.0, 101.0), "TR": (39.0, 35.0), "TW": (23.7, 121.0), "UA": (49.0, 32.0),
    "US": (39.5, -98.5), "UY": (-33.0, -56.0), "VN": (16.0, 107.0), "ZA": (-29.0, 25.0),
}


class TorCtlError(Exception):
    """Σφάλμα του control protocol (κωδικός 4xx/5xx ή χαλασμένη απάντηση)."""

    def __init__(self, msg, code=None):
        super().__init__(msg)
        self.code = code


# ───────────────────────────── πρωτόκολλο ─────────────────────────────

def check_host(host):
    """Επιστρέφει τη διεύθυνση αν είναι loopback· αλλιώς ValueError (δεν μιλάμε ποτέ με Tor άλλου μηχανήματος)."""
    h = str(host or "").strip().strip("[]")
    if h.lower() == "localhost":
        return "127.0.0.1"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        raise ValueError(f"Μόνο loopback (127.0.0.1 / ::1) επιτρέπεται για το Tor control port, όχι «{host}».")
    if not ip.is_loopback:
        raise ValueError(f"Μόνο loopback (127.0.0.1 / ::1) επιτρέπεται για το Tor control port, όχι «{host}».")
    return str(ip)


def read_reply(readline):
    """Διαβάζει μία πλήρη απάντηση. Επιστρέφει [(code, text, data|None)]· data = λίστα γραμμών για «250+…» μπλοκ."""
    out = []
    while True:
        raw = readline()
        if not raw:
            raise TorCtlError("Το Tor έκλεισε τη σύνδεση.")
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if len(line) < 4 or not line[:3].isdigit() or line[3] not in " -+":
            raise TorCtlError(f"Χαλασμένη απάντηση: {line[:60]!r}")
        code, sep, text = line[:3], line[3], line[4:]
        data = None
        if sep == "+":
            data = []
            while True:
                d = readline()
                if not d:
                    raise TorCtlError("Το Tor έκλεισε τη σύνδεση μέσα σε μπλοκ δεδομένων.")
                d = d.decode("utf-8", "replace").rstrip("\r\n")
                if d == ".":
                    break
                if d.startswith(".."):
                    d = d[1:]
                data.append(d)
        out.append((code, text, data))
        if sep == " ":
            return out


def parse_reply(blob):
    """Βοηθός (για τεστ): bytes μιας απάντησης → ίδιο αποτέλεσμα με read_reply."""
    return read_reply(io.BytesIO(blob).readline)


def _kv(text):
    """«A=1 B="x y" C» → {A: '1', B: 'x y'} (μόνο τα ζεύγη κλειδί=τιμή, με quoted strings)."""
    out = {}
    for m in re.finditer(r'([A-Za-z_]+)=("(?:[^"\\]|\\.)*"|\S*)', text):
        v = m.group(2)
        if v.startswith('"'):
            v = re.sub(r"\\(.)", r"\1", v[1:-1])
        out[m.group(1)] = v
    return out


def parse_protocolinfo(lines):
    """Απάντηση PROTOCOLINFO → {methods: set, cookiefile, version}."""
    info = {"methods": set(), "cookiefile": None, "version": None}
    for _code, text, _data in lines:
        if text.startswith("AUTH "):
            kv = _kv(text[5:])
            info["methods"] = {x.strip().upper() for x in kv.get("METHODS", "").split(",") if x.strip()}
            info["cookiefile"] = kv.get("COOKIEFILE") or None
        elif text.startswith("VERSION "):
            info["version"] = _kv(text[8:]).get("Tor")
    return info


def safecookie_hashes(cookie, client_nonce, server_nonce):
    """(server_hash, client_hash) του SAFECOOKIE — HMAC-SHA256(κλειδί, cookie ‖ client nonce ‖ server nonce)."""
    msg = cookie + client_nonce + server_nonce
    return (hmac.new(SERVER_KEY, msg, hashlib.sha256).digest(), hmac.new(CLIENT_KEY, msg, hashlib.sha256).digest())


def parse_path_entry(s):
    """«$FP~nick» / «$FP=nick» / «$FP» / «nick» → (fp σε κεφαλαία ή None, nick ή None)."""
    s = s.strip()
    if not s.startswith("$"):
        return None, s or None
    s = s[1:]
    for sep in ("~", "="):
        if sep in s:
            fp, nick = s.split(sep, 1)
            return fp.upper(), nick or None
    return s.upper(), None


def parse_iso_utc(s):
    """«2026-11-18T10:00:00.123456» (UTC) → epoch, ή None."""
    m = re.match(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?", s or "")
    if not m:
        return None
    t = calendar.timegm(tuple(int(x) for x in m.groups()[:6]) + (0, 0, 0))
    return t + (float("0." + m.group(7)) if m.group(7) else 0.0)


def parse_circuit_status(text):
    """Κείμενο του GETINFO circuit-status → [{id, status, path:[(fp, nick)], purpose, flags, created}]."""
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        cid, st, rest = parts[0], parts[1].upper(), parts[2:]
        path = []
        if rest and (rest[0].startswith("$") or "=" not in rest[0]):
            path = [parse_path_entry(x) for x in rest[0].split(",") if x]
            rest = rest[1:]
        kv = _kv(" ".join(rest))
        out.append({"id": cid, "status": st, "path": path, "purpose": kv.get("PURPOSE", "GENERAL").upper(),
                    "flags": [f for f in kv.get("BUILD_FLAGS", "").split(",") if f],
                    "created": parse_iso_utc(kv.get("TIME_CREATED", ""))})
    return out


def parse_ns_r(text):
    """Network status entry → {nick, ip, orport} από τη γραμμή «r» (ή None)."""
    for line in (text or "").splitlines():
        p = line.split()
        if p and p[0] == "r" and len(p) >= 8:
            return {"nick": p[1], "ip": p[6], "orport": int(p[7]) if p[7].isdigit() else None}
    return None


def parse_entry_guards(text):
    """GETINFO entry-guards → [(fp, nick, status)] με τη σειρά προτίμησης του Tor."""
    out = []
    for line in (text or "").splitlines():
        p = line.split()
        if not p:
            continue
        fp, nick = parse_path_entry(p[0])
        out.append((fp, nick, p[1].lower() if len(p) > 1 else ""))
    return out


def primary_guard(guards):
    """Ο πρώτος guard σε κατάσταση «up» (αλλιώς ο πρώτος της λίστας)."""
    for g in guards:
        if g[2] == "up":
            return g
    return guards[0] if guards else None


def short_fp(fp):
    return (fp or "")[:8]


class ControlConn:
    """Μία ταυτοποιημένη σύνδεση στο control port (μόνο loopback)."""

    def __init__(self, port, host="127.0.0.1", cookie_file=None, timeout=CONNECT_TIMEOUT):
        self.host, self.port = check_host(host), int(port)
        self.cookie_file, self.timeout = cookie_file, timeout
        self.sock = self.rfile = None
        self.info = None
        self.auth_method = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def open(self):
        fam = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((self.host, self.port))
        except OSError:
            s.close()
            raise
        self.sock, self.rfile = s, s.makefile("rb")
        return self

    def close(self):
        for x in (self.rfile, self.sock):
            try:
                if x is not None:
                    x.close()
            except OSError:
                pass
        self.sock = self.rfile = None

    def command(self, line):
        if "\r" in line or "\n" in line:
            raise TorCtlError("Μη έγκυρη εντολή.")
        self.sock.sendall(line.encode() + b"\r\n")
        rep = read_reply(self.rfile.readline)
        code = rep[-1][0]
        if code[0] in "45":
            raise TorCtlError(f"{code} {rep[-1][1]}", code=code)
        return rep

    def _read_cookie(self, path):
        try:
            with open(path, "rb") as f:
                c = f.read(64)
        except OSError:
            raise TorCtlError(HINT_COOKIE.format(path=path), code="cookie")
        if len(c) != 32:
            raise TorCtlError(f"Το cookie ({path}) δεν έχει 32 bytes.", code="cookie")
        return c

    def authenticate(self):
        self.info = info = parse_protocolinfo(self.command("PROTOCOLINFO 1"))
        m = info["methods"]
        path = self.cookie_file or info["cookiefile"]
        if "NULL" in m:
            self.command("AUTHENTICATE")
            self.auth_method = "NULL"
        elif "SAFECOOKIE" in m and path:
            cookie = self._read_cookie(path)
            cnonce = os.urandom(32)
            rep = self.command("AUTHCHALLENGE SAFECOOKIE " + binascii.hexlify(cnonce).decode())
            kv = _kv(rep[-1][1])
            try:
                shash = binascii.unhexlify(kv["SERVERHASH"])
                snonce = binascii.unhexlify(kv["SERVERNONCE"])
            except (KeyError, binascii.Error):
                raise TorCtlError("Χαλασμένη απάντηση AUTHCHALLENGE.")
            want, mine = safecookie_hashes(cookie, cnonce, snonce)
            if not hmac.compare_digest(want, shash):
                raise TorCtlError("Το Tor δεν απέδειξε ότι ξέρει το cookie (SAFECOOKIE) — άρνηση σύνδεσης.")
            self.command("AUTHENTICATE " + binascii.hexlify(mine).decode())
            self.auth_method = "SAFECOOKIE"
        elif "COOKIE" in m and path:
            self.command("AUTHENTICATE " + binascii.hexlify(self._read_cookie(path)).decode())
            self.auth_method = "COOKIE"
        elif "HASHEDPASSWORD" in m:
            raise TorCtlError(HINT_PASSWORD, code="password")
        else:
            raise TorCtlError("Καμία υποστηριζόμενη μέθοδος ταυτοποίησης (" + ",".join(sorted(m)) + ").")
        return self.auth_method

    def getinfo(self, key):
        """Μία τιμή GETINFO (κείμενο· τα μπλοκ δεδομένων ενώνονται με \\n)."""
        if not re.fullmatch(r"[A-Za-z0-9/_\-.:$~]+", key):
            raise TorCtlError("Μη έγκυρο κλειδί GETINFO.")
        for _code, text, data in self.command("GETINFO " + key):
            if text.startswith(key + "="):
                v = text[len(key) + 1:]
                return "\n".join(data) if data is not None else v
        return ""

    def signal_newnym(self):
        self.command("SIGNAL NEWNYM")


# ───────────────────────────── demo ─────────────────────────────

_SIM_GUARDS = [("A1C3E7F09B2D4458A6E1C0D93F7B2E5A8C4D1F06", "ForPrivacyNET", "185.220.101.34", "DE")]
_SIM_MIDDLES = [
    ("3F9A12C4D5E6F708192A3B4C5D6E7F8091A2B3C4", "Quintex41", "199.249.230.81", "US"),
    ("7B2C9D0E1F2A3B4C5D6E7F8091A2B3C4D5E6F708", "nothingtohide", "37.187.17.67", "FR"),
    ("9E8D7C6B5A4F3E2D1C0B9A8F7E6D5C4B3A2F1E0D", "digineo3", "93.95.230.165", "SE"),
    ("C0FFEE12345678900987654321ABCDEFFEDCBA98", "relayon0129", "45.66.33.45", "NL"),
    ("5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F80", "Unnamed", "81.17.16.150", "CH"),
    ("2468ACE013579BDF2468ACE013579BDF2468ACE0", "TheGreenDragon", "89.58.26.216", "DE"),
]
_SIM_EXITS = [
    ("E1D2C3B4A5968778695A4B3C2D1E0F1A2B3C4D5E", "artikel5ev4", "185.220.100.252", "DE"),
    ("F00DBABE1234567890ABCDEF1234567890ABCDEF", "prsv", "109.70.100.21", "AT"),
    ("8A9B0C1D2E3F405162738495A6B7C8D9E0F1A2B3", "Ichotolot60", "192.42.116.16", "NL"),
    ("6C5B4A3928170F1E2D3C4B5A69788796A5B4C3D2", "bauruine", "185.195.71.244", "CH"),
    ("1357924680ACEBDF1357924680ACEBDF13579246", "emeraldonion", "23.129.64.130", "US"),
    ("ABCDEF0123456789ABCDEF0123456789ABCDEF01", "Rodos", "193.26.115.43", "RO"),
]


def _hop(fp, nick, ip, cc, role):
    lat, lon = CENTROIDS.get(cc, (None, None))
    return {"fp": short_fp(fp), "nick": nick, "ip": ip, "cc": cc, "lat": lat, "lon": lon, "role": role}


def sim_circuits(now, epoch=0, since=0.0):
    """3–4 εύλογα κυκλώματα· αλλάζουν κάθε ~10′ (ή με NEWNYM → epoch+1, since = πότε). Ο guard μένει ίδιος."""
    slot = int(now // SIM_ROTATE) + epoch * 7919
    rnd = random.Random(slot)
    n = 3 + (slot % 2)
    g = _SIM_GUARDS[0]
    out = []
    start = max(int(now // SIM_ROTATE) * SIM_ROTATE, since or 0)
    for i in range(n):
        m = rnd.choice(_SIM_MIDDLES)
        e = rnd.choice([x for x in _SIM_EXITS if x[3] != m[3]] or _SIM_EXITS)
        age = max(1, int(now - start) + i * 37)
        out.append({"id": str(40 + slot % 50 * 5 + i), "status": "BUILT", "purpose": "GENERAL", "age_s": age,
                    "hops": [_hop(*g, "guard"), _hop(*m, "middle"), _hop(*e, "exit")]})
    return out


# ───────────────────────────── ο poller ─────────────────────────────

class TorCtl:
    def __init__(self, state=None, cfg=None, sim=False):
        cfg = cfg or {}
        self.state, self.sim = state, sim
        self.enabled = bool(cfg.get("enabled", True))
        self.interval = max(3, int(cfg.get("interval") or 10))
        p = cfg.get("control_port")
        self.ports = (int(p),) if p else DEFAULT_PORTS
        self.host = check_host(cfg.get("host") or "127.0.0.1")
        self.cookie_file = cfg.get("cookie_file") or None
        self.lock = threading.Lock()
        self.relays = {}  # fp → {nick, ip, cc}
        self.guard_fp = None
        self._last_newnym = 0.0
        self._epoch = 0
        self._t0 = time.time()
        self.res = {"connected": False, "port": None, "version": None, "error": None, "hint": None,
                    "circuits": [], "traffic": {"read": None, "written": None}, "guard": None, "auth": None,
                    "last_poll": None}

    # — ζωντανά —
    def _connect(self):
        last = None
        for port in self.ports:
            c = ControlConn(port, self.host, self.cookie_file)
            try:
                c.open()
            except OSError as e:
                last = e
                continue
            try:
                c.authenticate()
            except Exception:
                c.close()
                raise
            return c
        raise ConnectionRefusedError(str(last) if last else "καμία θύρα")

    def _relay(self, c, fp, nick):
        r = self.relays.get(fp)
        if r is None:
            r = {"nick": nick, "ip": None, "cc": None}
            try:
                ns = parse_ns_r(c.getinfo("ns/id/" + fp))
                if ns:
                    r["nick"], r["ip"] = ns["nick"], ns["ip"]
            except TorCtlError:
                pass
            if r["ip"]:
                try:
                    cc = c.getinfo("ip-to-country/" + r["ip"]).strip().upper()
                    r["cc"] = cc if re.fullmatch(r"[A-Z]{2}", cc) and cc != "??" else None
                except TorCtlError:
                    pass
            if len(self.relays) >= RELAY_CACHE:
                self.relays.pop(next(iter(self.relays)))
            self.relays[fp] = r
        return r

    def _circuits(self, c, now):
        rows = parse_circuit_status(c.getinfo("circuit-status"))
        rows.sort(key=lambda x: (not (x["status"] == "BUILT" and x["purpose"] == "GENERAL"), -(x["created"] or 0)))
        out = []
        for r in rows[:MAX_CIRCUITS]:
            hops, n = [], len(r["path"])
            for i, (fp, nick) in enumerate(r["path"]):
                info = self._relay(c, fp, nick) if fp else {"nick": nick, "ip": None, "cc": None}
                role = "guard" if i == 0 else ("exit" if i == n - 1 and r["purpose"] == "GENERAL" and n > 1 else "middle")
                hops.append(_hop(fp, info["nick"], info["ip"], info["cc"], role))
            out.append({"id": r["id"], "status": r["status"], "purpose": r["purpose"],
                        "age_s": int(now - r["created"]) if r["created"] else None, "hops": hops})
        return out

    def poll(self, now=None):
        now = time.time() if now is None else now
        if self.sim:
            return self._poll_sim(now)
        try:
            c = self._connect()
        except ConnectionRefusedError:
            return self._fail("Το control port του Tor δεν απαντά (" + "/".join(map(str, self.ports)) + ").", HINT, now)
        except TorCtlError as e:
            hint = str(e) if e.code in ("password", "cookie") else HINT
            return self._fail(str(e)[:200], hint, now)
        except OSError as e:
            return self._fail(str(e)[:200], HINT, now)
        try:
            with c:
                version = (c.getinfo("version").split() or [None])[0]
                circs = self._circuits(c, now)
                traffic = {}
                for k in ("read", "written"):
                    try:
                        traffic[k] = int(c.getinfo("traffic/" + k))
                    except (TorCtlError, ValueError):
                        traffic[k] = None
                guard = None
                try:
                    g = primary_guard(parse_entry_guards(c.getinfo("entry-guards")))
                    if g and g[0]:
                        info = self._relay(c, g[0], g[1])
                        guard = {"fp": g[0], "nick": info["nick"], "ip": info["ip"], "cc": info["cc"]}
                except TorCtlError:
                    pass
                port, auth = c.port, c.auth_method
        except (TorCtlError, OSError) as e:
            return self._fail(str(e)[:200], None, now)
        with self.lock:
            self.res.update(connected=True, port=port, version=version, error=None, hint=None, circuits=circs,
                            traffic=traffic, auth=auth, last_poll=now,
                            guard={k: guard[k] for k in ("nick", "ip", "cc")} if guard else None)
        self._check_guard(guard, now)
        return self.res

    def _fail(self, err, hint, now):
        with self.lock:
            self.res.update(connected=False, error=err, hint=hint, circuits=[], last_poll=now)
        return self.res

    def _check_guard(self, guard, now):
        if not guard:
            return
        prev, self.guard_fp = self.guard_fp, guard["fp"]
        if prev and prev != guard["fp"] and self.state is not None:
            old = self.relays.get(prev, {}).get("nick") or short_fp(prev)
            self.state.alert("Άλλαξε ο Tor guard", "low", guard.get("ip") or "tor", guard.get("nick") or short_fp(guard["fp"]),
                             f"Ο κύριος entry guard του Tor άλλαξε από «{old}» σε «{guard.get('nick')}» "
                             f"({guard.get('ip') or '?'}, {guard.get('cc') or '?'}). Οι guards κανονικά αλλάζουν μόνο κάθε "
                             f"λίγους μήνες — αν δεν καθάρισες το state του Tor, ίσως αξίζει μια ματιά.",
                             now, key=("tor-guard",), cooldown=GUARD_COOLDOWN, mark=False)

    # — demo —
    def _poll_sim(self, now):
        g = _SIM_GUARDS[0]
        up = now - self._t0
        with self.lock:
            self.res.update(connected=True, port=9051, version="0.4.8.13", error=None, hint=None, auth="SAFECOOKIE",
                            circuits=sim_circuits(now, self._epoch, self._last_newnym), last_poll=now,
                            traffic={"read": int(48_000_000 + up * 21_500), "written": int(6_200_000 + up * 3_100)},
                            guard={"nick": g[1], "ip": g[2], "cc": g[3]})
        self.guard_fp = g[0]
        return self.res

    def newnym(self, now=None):
        """SIGNAL NEWNYM — η ΜΟΝΗ εντολή εγγραφής. Το πολύ μία φορά ανά 10″."""
        now = time.time() if now is None else now
        wait = NEWNYM_GAP - (now - self._last_newnym)
        if wait > 0:
            return {"ok": False, "error": f"Περίμενε {wait:.0f}″ πριν ζητήσεις ξανά νέα κυκλώματα.", "wait": round(wait, 1)}
        self._last_newnym = now
        if self.sim:
            self._epoch += 1
            self._poll_sim(now)
            return {"ok": True, "error": None}
        try:
            with self._connect() as c:
                c.signal_newnym()
        except (TorCtlError, OSError) as e:
            return {"ok": False, "error": str(e)[:200] or e.__class__.__name__}
        return {"ok": True, "error": None}

    def status(self):
        with self.lock:
            r = self.res
            return {"enabled": self.enabled or self.sim, "demo": self.sim, "interval": self.interval,
                    "connected": r["connected"], "port": r["port"], "version": r["version"], "auth": r["auth"],
                    "error": r["error"], "hint": r["hint"], "last_poll": r["last_poll"],
                    "circuits": [dict(c, hops=[dict(h) for h in c["hops"]]) for c in r["circuits"]],
                    "traffic": dict(r["traffic"]), "guard": dict(r["guard"]) if r["guard"] else None,
                    "newnym_wait": max(0.0, round(NEWNYM_GAP - (time.time() - self._last_newnym), 1))}

    def run_forever(self):
        while True:
            if self.enabled or self.sim:
                try:
                    self.poll()
                except Exception:
                    pass
            time.sleep(self.interval)
