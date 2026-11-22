"""🛰 Απομακρυσμένη πρόσβαση στο κουτί με WireGuard — χωρίς port forwarding στο router του πελάτη.

Το κουτί (Raspberry Pi με NetWatch) μένει στον πελάτη και ανοίγει ΑΥΤΟ ένα τούνελ WireGuard προς τον δικό σου
WireGuard server (router στο γραφείο, VPS, MikroTik). Επειδή η σύνδεση ξεκινά από μέσα, δεν χρειάζεται καμία
αλλαγή στο router του πελάτη, και δουλεύει και πάνω από την εφεδρική γραμμή LTE.

Τι κάνει αυτό το module:
  • φτιάχνει το ζεύγος κλειδιών του κουτιού (X25519, καθαρή Python — RFC 7748) και το αρχείο ρυθμίσεων nw0.conf
  • σου δίνει έτοιμο το κομμάτι [Peer] για τον server σου (wg-quick και MikroTik)
  • δείχνει αν το τούνελ είναι όρθιο (τελευταίο handshake) και ειδοποιεί αν πέσει

Ασφάλεια:
  • Το ιδιωτικό κλειδί γράφεται ΜΟΝΟ στο data/remote/nw0.conf (δικαιώματα 600). Δεν επιστρέφεται ποτέ από το API.
  • AllowedIPs = μόνο η διεύθυνση του server σου μέσα στο τούνελ (/32): το κουτί ΔΕΝ δρομολογεί το δίκτυο του
    πελάτη προς τα έξω και δεν στέλνει την κίνησή του μέσα από εσένα. Βλέπεις μόνο το NetWatch.
  • Το NetWatch μέσα από το τούνελ ανοίγει με --agent (HTTPS + token), όπως περιγράφει το docs/agent.md.
  • Το module δεν αγγίζει το δίκτυο του συστήματος: η εγκατάσταση γίνεται με το tools/fieldbox/wg-setup.sh (sudo).
"""
import base64
import ipaddress
import os
import re
import secrets
import threading
import time

IFACE = "nw0"
STALE_S = 300          # χωρίς handshake > 5′ (με keepalive 25″) = το τούνελ δεν δουλεύει
HOST_RX = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
ALERT = "Έπεσε το τούνελ απομακρυσμένης πρόσβασης"

# ───────────────────────── X25519 (RFC 7748) ─────────────────────────
_P = 2 ** 255 - 19
_A24 = 121665


def _clamp(k):
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def x25519(k, u=b"\x09" + b"\x00" * 31):
    """Βαθμωτός πολλαπλασιασμός στην Curve25519 (σκάλα Montgomery). k, u: 32 bytes → 32 bytes."""
    if len(k) != 32 or len(u) != 32:
        raise ValueError("32 bytes")
    kn = int.from_bytes(_clamp(k), "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (kn >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def keypair(rand=secrets.token_bytes):
    """→ (ιδιωτικό, δημόσιο) σε base64, όπως τα θέλει το WireGuard (`wg genkey` / `wg pubkey`)."""
    priv = _clamp(rand(32))
    return base64.b64encode(priv).decode(), base64.b64encode(x25519(priv)).decode()


def pubkey_of(priv_b64):
    return base64.b64encode(x25519(base64.b64decode(priv_b64))).decode()


def valid_key(s):
    try:
        return isinstance(s, str) and len(s) == 44 and len(base64.b64decode(s, validate=True)) == 32
    except Exception:  # noqa: BLE001
        return False


# ───────────────────────── έλεγχος ρυθμίσεων ─────────────────────────
def check(cfg):
    """Καθαρίζει και ελέγχει τις ρυθμίσεις του χρήστη → (dict, None) ή (None, μήνυμα λάθους)."""
    c = cfg if isinstance(cfg, dict) else {}
    host = str(c.get("host") or "").strip().strip("[]")
    try:
        ipaddress.ip_address(host)
        ok_host = True
    except ValueError:
        ok_host = bool(HOST_RX.match(host)) and "." in host
    if not ok_host:
        return None, "Δώσε τη δημόσια διεύθυνση του WireGuard server σου (όνομα ή IP), π.χ. vpn.example.gr"
    try:
        port = int(c.get("port") or 51820)
    except (TypeError, ValueError):
        port = 0
    if not 1 <= port <= 65535:
        return None, "Η θύρα πρέπει να είναι 1–65535 (συνήθως 51820)."
    hub_key = str(c.get("hub_key") or "").strip()
    if not valid_key(hub_key):
        return None, "Το δημόσιο κλειδί του server δεν είναι έγκυρο (44 χαρακτήρες base64, τελειώνει σε «=»)."
    try:
        net = ipaddress.ip_network(str(c.get("subnet") or "10.99.0.0/24").strip(), strict=True)
        hub_ip = ipaddress.ip_address(str(c.get("hub_ip") or "").strip() or str(net.network_address + 1))
        box_ip = ipaddress.ip_address(str(c.get("box_ip") or "").strip() or str(net.network_address + 10))
    except ValueError:
        return None, "Το δίκτυο του τούνελ δεν είναι έγκυρο (π.χ. 10.99.0.0/24, server 10.99.0.1, κουτί 10.99.0.10)."
    if net.version != 4 or not net.is_private or net.prefixlen > 30 or net.prefixlen < 16:
        return None, "Το δίκτυο του τούνελ πρέπει να είναι ιδιωτικό IPv4, από /16 έως /30."
    if hub_ip not in net or box_ip not in net or hub_ip == box_ip or box_ip in (net.network_address, net.broadcast_address) \
            or hub_ip in (net.network_address, net.broadcast_address):
        return None, "Οι διευθύνσεις server και κουτιού πρέπει να είναι διαφορετικές και μέσα στο δίκτυο του τούνελ."
    return {"host": host, "port": port, "hub_key": hub_key, "subnet": str(net), "hub_ip": str(hub_ip), "box_ip": str(box_ip),
            "name": "".join(ch for ch in str(c.get("name") or "netwatch-box") if ch.isascii() and (ch.isalnum() or ch in "-_"))[:32] or "netwatch-box"}, None


def box_conf(c, priv):
    ep = f"[{c['host']}]" if ":" in c["host"] else c["host"]
    return (f"# NetWatch — τούνελ απομακρυσμένης πρόσβασης ({c['name']}). Φτιάχτηκε από την καρτέλα 🛰.\n"
            f"[Interface]\nPrivateKey = {priv}\nAddress = {c['box_ip']}/32\n\n"
            f"[Peer]\nPublicKey = {c['hub_key']}\nEndpoint = {ep}:{c['port']}\n"
            f"AllowedIPs = {c['hub_ip']}/32\nPersistentKeepalive = 25\n")


def hub_snippets(c, pub):
    """Τι προσθέτεις στον δικό σου server για να δεχτεί το κουτί."""
    return {"wg": f"# {c['name']}\n[Peer]\nPublicKey = {pub}\nAllowedIPs = {c['box_ip']}/32\n",
            "wg_live": f"sudo wg set wg0 peer {pub} allowed-ips {c['box_ip']}/32",
            "mikrotik": f"/interface wireguard peers add interface=wireguard1 public-key=\"{pub}\" allowed-address={c['box_ip']}/32 comment=\"{c['name']}\""}


def _private_write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


class Remote:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time, runner=None):
        self.state, self.demo, self.clock = state, demo, clock
        self.dir = os.path.join(data_dir, "remote") if data_dir else None
        self.on_save = None
        self.runner = runner            # (argv) → (rc, stdout, stderr)· tests δίνουν ψεύτικο
        self.lock = threading.RLock()
        self.cfg, self.pub, self.created = None, None, None
        self._mem_conf = None           # χωρίς data_dir (tests): το conf μένει στη μνήμη
        self.link = {"state": "none"}
        self.was_up = False
        self.error = None
        if demo:
            self.cfg, _ = check({"host": "vpn.techniki-ae.example", "hub_key": base64.b64encode(bytes(range(32))).decode(), "name": "box-kafe-steki"})
            self.pub = pubkey_of(base64.b64encode(_clamp(bytes(range(1, 33)))).decode())
            self.created = clock() - 6 * 86400
        elif self.dir:
            self._load()

    # ── αποθήκευση (το meta δεν έχει μυστικά· το ιδιωτικό κλειδί ζει μόνο στο nw0.conf) ──
    def _meta(self):
        return os.path.join(self.dir, "remote.json")

    def conf_path(self):
        return os.path.join(self.dir, IFACE + ".conf") if self.dir else None

    def _load(self):
        import json
        try:
            with open(self._meta(), encoding="utf-8") as f:
                j = json.load(f)
            c, err = check(j.get("cfg"))
            if c and valid_key(j.get("pub")) and os.path.isfile(self.conf_path()):
                self.cfg, self.pub, self.created = c, j["pub"], j.get("created")
        except (OSError, ValueError):
            pass

    def _save(self, conf_text):
        import json
        if not self.dir:
            self._mem_conf = conf_text
            return
        _private_write(self.conf_path(), conf_text)
        _private_write(self._meta(), json.dumps({"cfg": self.cfg, "pub": self.pub, "created": self.created}, ensure_ascii=False))
        for p in (self.conf_path(), self._meta(), self.dir):
            if self.on_save:
                try:
                    self.on_save(p)
                except Exception:  # noqa: BLE001
                    pass

    # ── ρύθμιση ──
    def setup(self, body):
        if self.demo:
            return {"error": "Στο demo δεν φτιάχνονται κλειδιά.", "error_en": "No keys are generated in demo mode."}
        c, err = check(body)
        if err:
            return {"error": err}
        with self.lock:
            keep = self.cfg is not None and not body.get("new_key")
            priv = None
            if keep:  # ίδια κλειδιά, νέες διευθύνσεις: ξαναδιάβασε το ιδιωτικό από το δικό μας αρχείο
                priv = self._read_priv()
            if not priv:
                priv, self.pub = keypair()
                self.created = self.clock()
            self.cfg = c
            self._save(box_conf(c, priv))
            del priv
            self.was_up = False
        return {"ok": True}

    def _read_priv(self):
        try:
            text = self._mem_conf if not self.dir else open(self.conf_path(), encoding="utf-8").read()
        except OSError:
            return None
        m = re.search(r"^PrivateKey\s*=\s*(\S+)\s*$", text or "", re.M)
        return m.group(1) if m and valid_key(m.group(1)) and pubkey_of(m.group(1)) == self.pub else None

    def forget(self):
        with self.lock:
            self.cfg = self.pub = self.created = self._mem_conf = None
            self.link, self.was_up = {"state": "none"}, False
            if self.dir:
                for p in (self.conf_path(), self._meta()):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
        return {"ok": True}

    # ── κατάσταση τούνελ ──
    def _run(self, argv):
        if self.runner:
            return self.runner(argv)
        import wgstatus
        exe = wgstatus.find_exe("wg")
        if not exe:
            return -2, "", "no wg"
        return wgstatus.run_cmd([exe] + argv[1:])

    def poll(self):
        """Διαβάζει `wg show nw0 dump` (μόνο ανάγνωση) → {"state": none|ready|down|never|stale|up, …}."""
        now = self.clock()
        if self.demo:
            self.link = {"state": "up", "handshake": now - 41, "ago": 41, "rx": 18_400_000, "tx": 73_900_000, "endpoint": "203.0.113.7:51820"}
            return self.link
        with self.lock:
            cfg = self.cfg
        if not cfg:
            self.link = {"state": "none"}
            return self.link
        rc, out, err = self._run(["wg", "show", IFACE, "dump"])
        if rc == -2:
            self.link = {"state": "ready", "why": "nowg"}       # δεν είναι εγκατεστημένο το wireguard-tools
        elif rc != 0:
            self.link = {"state": "ready", "why": "perm" if "ermission" in (err or "") or "perat" in (err or "") else "noiface"}
        else:
            import wgstatus
            peers = [p for i in wgstatus.parse_wg_dump("\n".join(IFACE + "\t" + ln for ln in (out or "").splitlines())) for p in i["peers"]]
            p = next((x for x in peers if x["public_key"] == cfg["hub_key"]), None)
            if not p:
                self.link = {"state": "down", "why": "nopeer"}
            else:
                hs = p.get("handshake") or 0
                st = "never" if not hs else "up" if now - hs < STALE_S else "stale"
                self.link = {"state": st, "handshake": hs or None, "ago": int(now - hs) if hs else None, "rx": p.get("rx") or 0, "tx": p.get("tx") or 0,
                             "endpoint": p.get("endpoint")}
        self._alerts(now)
        return self.link

    def _alerts(self, now):
        st = self.link.get("state")
        if st == "up":
            self.was_up = True
        elif self.was_up and st in ("stale", "down", "ready"):
            self.was_up = False
            s = self.state
            if s is not None and hasattr(s, "alert"):
                ago = self.link.get("ago")
                s.alert(ALERT, "med", self.cfg["box_ip"], self.cfg["host"],
                        f"Το τούνελ WireGuard προς {self.cfg['host']}:{self.cfg['port']} δεν έχει handshake"
                        + (f" εδώ και {ago // 60}′" if ago else "") + ". Δεν μπορείς να δεις το κουτί από μακριά μέχρι να επανέλθει — "
                        "έλεγξε αν ο server σου είναι όρθιος και αν το κουτί έχει Internet (ή εφεδρική γραμμή).",
                        now, key=("remote", "down"), cooldown=3600, mark=False)

    def run_forever(self):
        time.sleep(30)
        while True:
            try:
                self.poll()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(60)

    # ── UI ──
    def view(self):
        with self.lock:
            c = dict(self.cfg) if self.cfg else None
            pub, created = self.pub, self.created
        port = getattr(self.state, "port", None) or 8765
        v = {"demo": self.demo, "configured": bool(c), "iface": IFACE, "link": dict(self.link) if not self.demo else self.poll(),
             "agent": bool(getattr(self.state, "agent", None)), "on_backup": False}
        up = getattr(self.state, "uplink", None)
        try:
            v["on_backup"] = bool(up.on_backup()) if up is not None else False
        except Exception:  # noqa: BLE001
            pass
        if c:
            v.update(cfg={k: c[k] for k in ("host", "port", "hub_key", "subnet", "hub_ip", "box_ip", "name")}, pub=pub, created=created,
                     hub=hub_snippets(c, pub), url=f"https://{c['box_ip']}:{port}/",
                     conf=("data/remote/" + IFACE + ".conf") if self.dir else None,
                     install="sudo tools/fieldbox/wg-setup.sh", run="sudo .venv/bin/python netwatch.py --agent")
        return v

    def api(self, method, sub, q, body):
        if method == "GET" and sub == "":
            if not self.demo:
                try:
                    self.poll()
                except Exception:  # noqa: BLE001
                    pass
            return 200, self.view()
        if method == "POST" and sub == "setup":
            r = self.setup(body)
            if r.get("error"):
                return 400, r
            try:
                self.poll()
            except Exception:  # noqa: BLE001
                pass
            return 200, self.view()
        if method == "POST" and sub == "forget":
            if not body.get("confirm"):
                return 400, {"error": "Χρειάζεται επιβεβαίωση."}
            if self.demo:
                return 200, self.view()
            self.forget()
            return 200, self.view()
        return 404, {"error": "not found"}
