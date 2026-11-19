"""🖥 SSH Explorer: δες τα αρχεία και την κατάσταση του Raspberry Pi / server σου — με το OpenSSH του συστήματος.

Ασφάλεια (σκόπιμα αυστηρό):
  • 🔑 Μόνο κλειδιά SSH, ΠΟΤΕ κωδικοί: το ssh τρέχει με BatchMode=yes, άρα δεν ρωτά ποτέ password. Δεν δεχόμαστε
    ούτε αποθηκεύουμε κωδικούς. Αν δεν έχεις κλειδί, η καρτέλα δείχνει τις 2 εντολές (ssh-keygen, ssh-copy-id) για
    να τις τρέξεις εσύ στο Terminal.
  • 👀 Μόνο ανάγνωση: λίστα φακέλου, προεπισκόπηση αρχείου (έως 256 KB), κατέβασμα (έως 50 MB), κατάσταση συστήματος.
    Καμία εντολή που γράφει/σβήνει. Τα ονόματα αρχείων περνούν πάντα με shlex.quote.
  • 🏠 Μόνο ιδιωτικές/τοπικές διευθύνσεις (192.168.x, 10.x, 172.16–31.x, .local που λύνεται σε τέτοια).
  • 🔐 Κλειδί του host: StrictHostKeyChecking=yes. Την πρώτη φορά βλέπεις το fingerprint (ssh-keyscan) και πατάς
    «Εμπιστεύομαι» — τότε γράφεται στο δικό μας known_hosts (data/ssh_known_hosts). Αν αλλάξει αργότερα, το ssh αρνείται.
  • Χωρίς agent/X11/port forwarding (ForwardAgent=no, ClearAllForwardings=yes), χωρίς TTY.
  • Ιδιωτικά κλειδιά (-----BEGIN … PRIVATE KEY-----) δεν εμφανίζονται ούτε κατεβαίνουν.
  • Με sudo (Mac app): το ssh τρέχει ως ο κανονικός χρήστης (SUDO_USER), με τα δικά του ~/.ssh κλειδιά.
Οι αποθηκευμένοι hosts (όνομα, IP, χρήστης, θύρα — τίποτα μυστικό) γράφονται στο data/ssh_hosts.json.

API
---
SshBrowse(state, sim=False, path=None, known=None, runner=None)
  .view()                         → {hosts, keys, suggestions, demo}
  .add_host(d) / .delete_host(id) → {ok} | {error}
  .hostkey(id) / .trust(id, fp)   → fingerprints / εμπιστοσύνη
  .ls(id, path) / .cat(id, path) / .info(id) / .fetch(id, path) → {…} | {error, hint}
"""
import base64
import ipaddress
import json
import os
import posixpath
import re
import secrets
import shlex
import subprocess
import threading
import time

import configbak

ID_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
USER_RE = configbak.USER_RE
MAX_HOSTS = 30
MAX_ENTRIES = 1500
MAX_VIEW = 256 * 1024
MAX_DL = 50 * 1024 * 1024
TIMEOUT = 15
FILE_TTL = 300
PRIV_RE = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=6", "-o", "StrictHostKeyChecking=yes",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes",
            "-o", "RequestTTY=no", "-o", "PermitLocalCommand=no", "-o", "LogLevel=ERROR",
            "-o", "ControlMaster=auto", "-o", "ControlPath=~/.ssh/cm-nw-%C", "-o", "ControlPersist=90"]

# Λίστα φακέλου: python3 αν υπάρχει (JSON), αλλιώς GNU find. Το $P είναι ήδη quoted.
LS_SCRIPT = r"""P=%s
if command -v python3 >/dev/null 2>&1; then python3 - "$P" <<'NWEOF'
import json, os, stat, sys
p = os.path.expanduser(sys.argv[1]); out = []
for e in sorted(os.scandir(p), key=lambda e: e.name)[:%d]:
    try:
        st = e.stat(follow_symlinks=False); t = "l" if e.is_symlink() else "d" if e.is_dir() else "f"
        out.append([e.name, t, st.st_size, int(st.st_mtime), stat.filemode(st.st_mode)])
    except OSError:
        out.append([e.name, "?", 0, 0, "?"])
print(json.dumps({"path": os.path.abspath(p), "entries": out}))
NWEOF
else cd -- "$P" 2>/dev/null && echo "#PWD $(pwd)" && find . -mindepth 1 -maxdepth 1 -printf '%%y\t%%s\t%%T@\t%%M\t%%f\n' | head -n %d; fi"""

INFO_SCRIPT = r"""echo "#host"; hostname
echo "#os"; (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -s
echo "#kernel"; uname -rm
echo "#model"; tr -d '\0' </proc/device-tree/model 2>/dev/null || sysctl -n hw.model 2>/dev/null
echo "#uptime"; cat /proc/uptime 2>/dev/null
echo "#load"; cat /proc/loadavg 2>/dev/null
echo "#cpus"; nproc 2>/dev/null
echo "#mem"; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null
echo "#disk"; df -P -k 2>/dev/null | awk 'NR>1 && $1 !~ /^(tmpfs|devtmpfs|udev|overlay|none)$/'
echo "#temp"; cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null
echo "#throttled"; vcgencmd get_throttled 2>/dev/null
echo "#ips"; hostname -I 2>/dev/null
echo "#ports"; (ss -Htln 2>/dev/null || netstat -tln 2>/dev/null | tail -n +3) | awk '{print $4}' | sort -u | head -40
echo "#procs"; ps -eo pcpu,pmem,comm --sort=-pcpu 2>/dev/null | sed -n '2,7p'
echo "#failed"; systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | head -10
echo "#sshd"; grep -hiE '^[[:space:]]*(PasswordAuthentication|PermitRootLogin|Port)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -10
echo "#updates"; (timeout 6 apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst ') || true
echo "#users"; awk -F: '$3>=1000 && $3<65000 {print $1}' /etc/passwd 2>/dev/null | head -10
echo "#end"
"""


def _user_home():
    u = os.environ.get("SUDO_USER")
    if u and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            import pwd  # μόνο Unix (στα Windows δεν υπάρχει sudo/geteuid, άρα δεν φτάνουμε εδώ)
            return pwd.getpwnam(u).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")


def clean_path(p):
    p = str(p if p is not None else "~").strip() or "~"
    if "\x00" in p or "\n" in p or len(p) > 1024:
        raise ValueError("Μη έγκυρη διαδρομή")
    return p


def explain(err, host=None):
    """stderr του ssh → απλά λόγια + τι να κάνεις."""
    e = (err or "").lower()
    h = host or {}
    tgt = f"{h.get('user', 'pi')}@{h.get('host', '192.168.1.x')}"
    if "permission denied" in e:
        return ("Ο host δεν δέχτηκε το κλειδί σου (ζητά κωδικό — εμείς δεν στέλνουμε ποτέ κωδικούς).",
                f"Βάλε το δημόσιο κλειδί σου μία φορά, στο Terminal: ssh-copy-id -p {h.get('port', 22)} {tgt}")
    if "host key verification failed" in e or "no matching host key" in e:
        return ("Δεν έχεις εγκρίνει ακόμα το κλειδί του host.", "Πάτα «🔐 Έλεγχος κλειδιού host» και, αν το fingerprint είναι σωστό, «Εμπιστεύομαι».")
    if "remote host identification has changed" in e:
        return ("⚠ Το κλειδί του host ΑΛΛΑΞΕ από την προηγούμενη φορά.",
                "Αν ξαναέστησες το Pi είναι λογικό· αλλιώς μπορεί να είναι επίθεση MITM. Μην συνεχίσεις αν δεν ξέρεις γιατί.")
    if "connection refused" in e:
        return ("Το SSH δεν είναι ενεργό σε αυτή τη συσκευή.", "Στο Raspberry Pi: sudo raspi-config → Interface Options → SSH → Enable.")
    if "timed out" in e or "no route" in e or "host is down" in e:
        return ("Η συσκευή δεν απαντά.", "Είναι αναμμένη και στο ίδιο δίκτυο; Δοκίμασε ping ή «🔌 Πού είναι συνδεδεμένο».")
    if "could not resolve" in e:
        return ("Δεν βρέθηκε το όνομα.", "Δοκίμασε με IP (π.χ. 192.168.1.50).")
    if "no such file" in e or "not a directory" in e:
        return ("Ο φάκελος/αρχείο δεν υπάρχει.", "")
    if "permission" in e:
        return ("Ο χρήστης δεν έχει δικαίωμα ανάγνωσης εδώ.", "")
    return ((err or "Σφάλμα SSH").strip().splitlines()[-1][:200] if (err or "").strip() else "Σφάλμα SSH", "")


class SshBrowse:
    def __init__(self, state, sim=False, path=None, known=None, runner=None, clock=time.time):
        self.st, self.sim, self.clock = state, sim, clock
        self.path = None if sim else path
        self.known = known
        self.run = runner or self._run
        self.lock = threading.RLock()
        self.sem = threading.BoundedSemaphore(4)
        self.on_save = None
        self.hosts = {}
        self.files = {}
        self.scans = {}  # id → (t, keyscan lines, fingerprints) για το «Εμπιστεύομαι»
        if self.path:
            self._load()
        if sim:
            self.hosts = {"pi": {"id": "pi", "name": "Raspberry Pi (NAS)", "host": "192.168.1.17", "user": "pi", "port": 22},
                          "pve": {"id": "pve", "name": "Proxmox", "host": "192.168.1.16", "user": "root", "port": 22}}
            self.demo_trusted = {"pi"}

    # ── αποθήκευση ──
    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                for h in json.load(f).get("hosts") or []:
                    d, err = self._clean(h)
                    if not err:
                        self.hosts[d["id"]] = d
        except (OSError, ValueError):
            pass

    def _save(self):
        if not self.path:
            return
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"hosts": list(self.hosts.values())}, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)
        if self.on_save:
            self.on_save(self.path)

    @staticmethod
    def _clean(d):
        d = d if isinstance(d, dict) else {}
        if d.get("password") or d.get("pass") or d.get("secret"):
            return None, "Δεν δεχόμαστε κωδικούς — μόνο κλειδί SSH."
        host = str(d.get("host") or "").strip()[:255]
        user = str(d.get("user") or "").strip()
        name = str(d.get("name") or host).strip()[:60]
        hid = str(d.get("id") or re.sub(r"[^a-z0-9_-]+", "-", (name or host).lower()).strip("-")[:32] or "host")
        try:
            port = int(d.get("port") or 22)
            if not 0 < port < 65536:
                raise ValueError
        except (TypeError, ValueError):
            return None, "Μη έγκυρη θύρα."
        if not ID_RE.match(hid):
            return None, "Μη έγκυρο όνομα."
        if not USER_RE.match(user):
            return None, "Μη έγκυρος χρήστης (π.χ. pi)."
        if not host or host.startswith("-"):
            return None, "Λείπει η διεύθυνση."
        try:
            configbak.check_host(host, resolve=False)
        except ValueError as e:
            return None, str(e)
        return {"id": hid, "name": name or host, "host": host, "user": user, "port": port}, None

    def add_host(self, d):
        h, err = self._clean(d)
        if err:
            return {"error": err}
        with self.lock:
            if h["id"] not in self.hosts and len(self.hosts) >= MAX_HOSTS:
                return {"error": f"Έως {MAX_HOSTS} hosts."}
            base, n = h["id"], 2
            while h["id"] in self.hosts and not d.get("id"):
                h["id"] = f"{base[:29]}-{n}"
                n += 1
            self.hosts[h["id"]] = h
            self._save()
        return {"ok": True, "host": h}

    def delete_host(self, hid):
        with self.lock:
            if self.hosts.pop(str(hid), None) is None:
                return {"error": "Δεν υπάρχει."}
            self._save()
        return {"ok": True}

    # ── εκτέλεση ──
    def _known_opt(self):
        files = [os.path.join(_user_home(), ".ssh", "known_hosts")]
        if self.known:
            files.append(self.known)
        return ["-o", "UserKnownHostsFile=" + " ".join('"%s"' % f for f in files)]

    def _argv(self, h, remote):
        try:
            configbak.check_host(h["host"], resolve=True)  # το όνομα πρέπει να λύνεται μόνο σε ιδιωτική IP
        except ValueError as e:
            raise PermissionError(str(e))
        return configbak._as_user(["ssh", *SSH_OPTS, *self._known_opt(), "-p", str(h["port"]), f"{h['user']}@{h['host']}", remote])

    def _run(self, argv, timeout=TIMEOUT, stdin=None):
        try:
            p = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            return 255, b"", "Connection timed out"
        except OSError as e:
            return 255, b"", str(e)

    def _host(self, hid):
        with self.lock:
            h = self.hosts.get(str(hid or ""))
        if not h:
            raise KeyError("Άγνωστος host.")
        return h

    def _exec(self, hid, remote, timeout=TIMEOUT):
        h = self._host(hid)
        if not self.sem.acquire(timeout=20):
            return None, {"error": "Πολλές ταυτόχρονες συνδέσεις — δοκίμασε ξανά."}
        try:
            rc, out, err = self.run(self._argv(h, remote), timeout)
        except PermissionError as e:
            return None, {"error": str(e)}
        finally:
            self.sem.release()
        if rc != 0 and (rc == 255 or not out):
            msg, hint = explain(err, h)
            return None, {"error": msg, "hint": hint, "code": rc}
        return out, None

    def _guard(fn):  # noqa: N805
        def w(self, *a, **k):
            try:
                if self.sim:
                    return getattr(self, "_demo_" + fn.__name__)(*a, **k)
                return fn(self, *a, **k)
            except KeyError as e:
                return {"error": str(e).strip("'")}
            except ValueError as e:
                return {"error": str(e)}
        w.__name__ = fn.__name__
        return w

    # ── κλειδιά ──
    def keys(self):
        if self.sim:
            return {"keys": [{"file": "id_ed25519.pub", "type": "ED25519", "fp": "SHA256:demo3Xk9…Qe0", "comment": "you@mac"}], "home": "~"}
        d = os.path.join(_user_home(), ".ssh")
        out = []
        try:
            names = sorted(n for n in os.listdir(d) if n.endswith(".pub"))[:10]
        except OSError:
            names = []
        for n in names:
            try:
                r = subprocess.run(["ssh-keygen", "-l", "-f", os.path.join(d, n)], capture_output=True, text=True, timeout=5)
                parts = r.stdout.split()
                out.append({"file": n, "bits": parts[0] if parts else "", "fp": parts[1] if len(parts) > 1 else "",
                            "type": parts[-1].strip("()") if parts else "", "comment": " ".join(parts[2:-1])[:60]})
            except (OSError, subprocess.TimeoutExpired):
                out.append({"file": n, "fp": "", "type": "", "comment": ""})
        return {"keys": out, "home": "~/.ssh"}

    @_guard
    def hostkey(self, hid):
        h = self._host(hid)
        configbak.check_host(h["host"], resolve=True)
        try:
            r = subprocess.run(["ssh-keyscan", "-T", "4", "-p", str(h["port"]), h["host"]], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return {"error": "Η συσκευή δεν απάντησε στη θύρα SSH."}
        lines = [ln for ln in r.stdout.splitlines() if ln and not ln.startswith("#")][:6]
        if not lines:
            return {"error": "Δεν βρέθηκε SSH σε αυτή τη θύρα.", "hint": "Στο Raspberry Pi: sudo raspi-config → Interface Options → SSH."}
        fps = []
        for ln in lines:
            try:
                k = subprocess.run(["ssh-keygen", "-l", "-f", "-"], input=ln, capture_output=True, text=True, timeout=5).stdout.split()
                fps.append({"type": k[-1].strip("()") if k else "", "fp": k[1] if len(k) > 1 else ""})
            except (OSError, subprocess.TimeoutExpired):
                pass
        known = self._is_known(h)
        with self.lock:
            self.scans[h["id"]] = (self.clock(), lines, [f["fp"] for f in fps])
        return {"fingerprints": fps, "known": known}

    def _is_known(self, h):
        name = h["host"] if h["port"] == 22 else f"[{h['host']}]:{h['port']}"
        for f in [os.path.join(_user_home(), ".ssh", "known_hosts"), self.known]:
            if f and os.path.exists(f):
                try:
                    if subprocess.run(["ssh-keygen", "-F", name, "-f", f], capture_output=True, timeout=5).returncode == 0:
                        return True
                except (OSError, subprocess.TimeoutExpired):
                    pass
        return False

    @_guard
    def trust(self, hid, fp):
        h = self._host(hid)
        with self.lock:
            sc = self.scans.get(h["id"])
        if not sc or self.clock() - sc[0] > 300 or str(fp or "") not in sc[2]:
            return {"error": "Κάνε πρώτα «Έλεγχος κλειδιού host» (το fingerprint πρέπει να είναι αυτό που είδες)."}
        if not self.known:
            return {"error": "Δεν υπάρχει φάκελος δεδομένων."}
        os.makedirs(os.path.dirname(self.known) or ".", exist_ok=True)
        with open(self.known, "a", encoding="utf-8") as f:
            for ln in sc[1]:
                f.write(ln.strip() + "\n")
        if self.on_save:
            self.on_save(self.known)
        return {"ok": True}

    # ── ανάγνωση ──
    @_guard
    def ls(self, hid, path="~"):
        p = clean_path(path)
        qp = shlex.quote(p) if p != "~" and not p.startswith("~/") else ('"$HOME"' + shlex.quote(p[1:]) if p != "~" else '"$HOME"')
        out, err = self._exec(hid, LS_SCRIPT % (qp, MAX_ENTRIES, MAX_ENTRIES))
        if err:
            return err
        txt = out.decode("utf-8", "replace").strip()
        if txt.startswith("{"):
            j = json.loads(txt.splitlines()[-1])
            ents = [{"name": e[0], "type": e[1], "size": e[2], "mtime": e[3], "mode": e[4]} for e in j["entries"]]
            cwd = j["path"]
        else:
            lines = txt.splitlines()
            if not lines or not lines[0].startswith("#PWD "):
                return {"error": "Ο φάκελος δεν υπάρχει ή δεν διαβάζεται."}
            cwd, ents = lines[0][5:], []
            for ln in lines[1:]:
                parts = ln.split("\t", 4)
                if len(parts) == 5:
                    t = {"d": "d", "l": "l", "f": "f"}.get(parts[0], "?")
                    ents.append({"name": parts[4], "type": t, "size": int(parts[1] or 0), "mtime": int(float(parts[2] or 0)), "mode": parts[3]})
        ents.sort(key=lambda e: (e["type"] != "d", e["name"].startswith("."), e["name"].lower()))
        return {"path": cwd, "entries": ents, "truncated": len(ents) >= MAX_ENTRIES}

    @_guard
    def cat(self, hid, path):
        p = clean_path(path)
        out, err = self._exec(hid, f"head -c {MAX_VIEW + 1} -- {shlex.quote(p)} && echo && wc -c < {shlex.quote(p)}")
        if err:
            return err
        body, _, size = out.rstrip(b"\n").rpartition(b"\n")
        try:
            total = int(size.strip())
        except ValueError:
            body, total = out, len(out)
        body = body[:MAX_VIEW + 1]
        if PRIV_RE.search(body):
            return {"error": "🔑 Αυτό είναι ιδιωτικό κλειδί — δεν το εμφανίζουμε.", "private": True}
        binary = b"\x00" in body[:8192]
        if binary:
            return {"path": p, "binary": True, "size": total}
        return {"path": p, "text": body[:MAX_VIEW].decode("utf-8", "replace"), "size": total, "truncated": total > MAX_VIEW}

    @_guard
    def fetch(self, hid, path):
        p = clean_path(path)
        out, err = self._exec(hid, f"S=$(wc -c < {shlex.quote(p)}) && [ \"$S\" -le {MAX_DL} ] && cat -- {shlex.quote(p)}", timeout=120)
        if err:
            return err
        if not out and out is not None:
            return {"error": f"Άδειο ή πολύ μεγάλο αρχείο (όριο {MAX_DL // 1048576} MB)."}
        return self._put(os.path.basename(p.rstrip("/")) or "file", out)

    def _put(self, name, data):
        if PRIV_RE.search(data[:65536]):
            return {"error": "🔑 Αυτό είναι ιδιωτικό κλειδί — δεν το κατεβάζουμε."}
        now = self.clock()
        with self.lock:
            for k in [k for k, v in self.files.items() if now - v[0] > FILE_TTL]:
                del self.files[k]
            while len(self.files) >= 3:
                del self.files[min(self.files, key=lambda k: self.files[k][0])]
            fid = secrets.token_hex(8)
            self.files[fid] = (now, re.sub(r"[^\w.\-]+", "_", name)[:120] or "file", data)
        return {"ok": True, "url": f"/api/ssh/file?id={fid}", "size": len(data)}

    def get_file(self, fid):
        with self.lock:
            v = self.files.pop(str(fid or ""), None)  # μία φορά
        if not v or self.clock() - v[0] > FILE_TTL:
            return None
        return {"name": v[1], "data": v[2]}

    @_guard
    def info(self, hid):
        out, err = self._exec(hid, INFO_SCRIPT, timeout=25)
        if err:
            return err
        return parse_info(out.decode("utf-8", "replace"))

    def view(self):
        with self.lock:
            hosts = [dict(h, trusted=(h["id"] in getattr(self, "demo_trusted", ())) if self.sim else None) for h in self.hosts.values()]
        return {"hosts": hosts, "keys": self.keys(), "suggestions": self.suggestions(), "demo": self.sim}

    def suggestions(self):
        """Συσκευές του LAN που μοιάζουν με Raspberry Pi / Linux server (από όσα ήδη ξέρει το NetWatch)."""
        st, out = self.st, []
        lock = getattr(st, "lock", None)
        try:
            if lock:
                lock.acquire()
            hosts = list((getattr(st, "hosts", None) or {}).values())
        finally:
            if lock:
                lock.release()
        have = {h["host"] for h in self.hosts.values()}
        for h in hosts:
            ip = h.get("ip")
            if h.get("kind") not in (None, "local") or not ip or ip in have or h.get("me") or h.get("gw"):
                continue
            try:
                if not ipaddress.ip_address(ip).is_private:
                    continue
            except ValueError:
                continue
            dt = {}
            if hasattr(st, "_dtype"):
                try:
                    dt = st._dtype(h) or {}
                except Exception:
                    dt = {}
            txt = f"{dt.get('vendor') or ''} {dt.get('dlabel') or ''} {' '.join(h.get('names') or ())}".lower()
            ports = h.get("ports") or {}
            if 22 in ports or "22" in ports or any(k in txt for k in ("raspberry", "proxmox", "nas", "linux", "ubuntu", "debian", "synology")):
                names = sorted(h.get("names") or ())
                out.append({"host": ip, "name": (names[0] if names else (dt.get("vendor") or ip))[:40],
                            "user": "pi" if "raspberry" in txt else ""})
        return out[:8]

    # ── demo (ποτέ ssh) ──
    DEMO_FS = {
        "/home/pi": [("Documents", "d", 4096), ("docker-compose.yml", "f", 812), ("mosquitto", "d", 4096), ("nas", "d", 4096),
                     ("scripts", "d", 4096), (".bashrc", "f", 3523), (".ssh", "d", 4096), ("notes.txt", "f", 214)],
        "/home/pi/scripts": [("backup.sh", "f", 640), ("temp_log.py", "f", 1210)],
        "/home/pi/.ssh": [("authorized_keys", "f", 98), ("id_ed25519", "f", 411), ("id_ed25519.pub", "f", 98)],
        "/home/pi/mosquitto": [("mosquitto.conf", "f", 188), ("log", "d", 4096)],
        "/home/pi/nas": [("photos", "d", 4096), ("backups", "d", 4096), ("README.md", "f", 77)],
        "/home/pi/Documents": [("router-notes.md", "f", 402)],
        "/": [("bin", "l", 7), ("boot", "d", 4096), ("etc", "d", 4096), ("home", "d", 4096), ("var", "d", 4096)],
        "/etc": [("hostname", "f", 5), ("os-release", "f", 267), ("ssh", "d", 4096), ("fstab", "f", 312)],
        "/var": [("log", "d", 4096)], "/var/log": [("syslog", "f", 482211), ("auth.log", "f", 22104)],
        "/home": [("pi", "d", 4096)],
    }
    DEMO_TXT = {
        "/home/pi/docker-compose.yml": "services:\n  homeassistant:\n    image: ghcr.io/home-assistant/home-assistant:stable\n    network_mode: host\n    volumes: [./ha:/config]\n  mosquitto:\n    image: eclipse-mosquitto:2\n    ports: [\"1883:1883\"]\n    volumes: [./mosquitto:/mosquitto/config]\n",
        "/home/pi/notes.txt": "Raspberry Pi 4 — NAS + MQTT\n- δίσκος 1TB στο /home/pi/nas\n- backup κάθε βράδυ 03:00 (scripts/backup.sh)\n",
        "/home/pi/scripts/backup.sh": "#!/bin/sh\n# νυχτερινό backup στον εξωτερικό δίσκο\nrsync -a --delete /home/pi/nas/photos /mnt/usb/backup/\n",
        "/home/pi/mosquitto/mosquitto.conf": "listener 1883\nallow_anonymous true   # ⚠ οποιος είναι στο LAN μπορεί να γράψει\n",
        "/etc/hostname": "nas\n", "/etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\n',
        "/var/log/auth.log": "Nov 19 03:00:01 nas CRON[812]: pam_unix(cron:session): session opened for user pi\n"
                             "Nov 19 09:12:44 nas sshd[1902]: Accepted publickey for pi from 192.168.1.23 port 51234 ssh2: ED25519\n",
        "/home/pi/.ssh/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\n(demo)\n-----END OPENSSH PRIVATE KEY-----\n",
    }

    def _demo_host(self, hid):
        h = self._host(hid)
        if h["id"] not in self.demo_trusted:
            return h, {"error": "Δεν έχεις εγκρίνει ακόμα το κλειδί του host.",
                       "hint": "Πάτα «🔐 Έλεγχος κλειδιού host» και, αν το fingerprint είναι σωστό, «Εμπιστεύομαι»."}
        if h["id"] == "pve":
            return h, {"error": "Ο host δεν δέχτηκε το κλειδί σου (ζητά κωδικό — εμείς δεν στέλνουμε ποτέ κωδικούς).",
                       "hint": "Βάλε το δημόσιο κλειδί σου μία φορά, στο Terminal: ssh-copy-id -p 22 root@192.168.1.16"}
        return h, None

    def _demo_norm(self, p):
        p = clean_path(p)
        p = "/home/pi" + p[1:] if p.startswith("~") else p
        p = posixpath.normpath(p) if p != "/" else "/"  # διαδρομή του (Linux) host, όχι του δικού μας λειτουργικού
        return p

    def _demo_hostkey(self, hid):
        self._host(hid)
        fp = "SHA256:Zt4nW0x9C1demoQpL8vY2rE6uKk3jHf5sNmA7bD0cXo"
        with self.lock:
            self.scans[hid] = (self.clock(), [], [fp])
        return {"fingerprints": [{"type": "ED25519", "fp": fp}], "known": hid in self.demo_trusted}

    def _demo_trust(self, hid, fp):
        self._host(hid)
        sc = self.scans.get(hid)
        if not sc or fp not in sc[2]:
            return {"error": "Κάνε πρώτα «Έλεγχος κλειδιού host»."}
        self.demo_trusted.add(hid)
        return {"ok": True}

    def _demo_ls(self, hid, path="~"):
        _h, err = self._demo_host(hid)
        if err:
            return err
        p = self._demo_norm(path)
        if p not in self.DEMO_FS:
            return {"error": "Ο φάκελος/αρχείο δεν υπάρχει."}
        t0 = int(self.clock())
        ents = [{"name": n, "type": t, "size": s, "mtime": t0 - 3600 * (i * 7 + 2), "mode": ("drwxr-xr-x" if t == "d" else "lrwxrwxrwx" if t == "l" else "-rw-r--r--")}
                for i, (n, t, s) in enumerate(self.DEMO_FS[p])]
        ents.sort(key=lambda e: (e["type"] != "d", e["name"].startswith("."), e["name"].lower()))
        return {"path": p, "entries": ents, "truncated": False}

    def _demo_cat(self, hid, path):
        _h, err = self._demo_host(hid)
        if err:
            return err
        p = self._demo_norm(path)
        txt = self.DEMO_TXT.get(p)
        if txt is None:
            if p.endswith((".jpg", ".png", ".db")):
                return {"path": p, "binary": True, "size": 20480}
            txt = f"(demo) περιεχόμενο του {p}\n"
        if PRIV_RE.search(txt.encode()):
            return {"error": "🔑 Αυτό είναι ιδιωτικό κλειδί — δεν το εμφανίζουμε.", "private": True}
        return {"path": p, "text": txt, "size": len(txt.encode()), "truncated": False}

    def _demo_fetch(self, hid, path):
        r = self._demo_cat(hid, path)
        if r.get("error"):
            return r
        return self._put(os.path.basename(r["path"]), (r.get("text") or "").encode())

    def _demo_info(self, hid):
        _h, err = self._demo_host(hid)
        if err:
            return err
        return parse_info(DEMO_INFO)


DEMO_INFO = """#host
nas
#os
Debian GNU/Linux 12 (bookworm)
#kernel
6.6.51+rpt-rpi-v8 aarch64
#model
Raspberry Pi 4 Model B Rev 1.5
#uptime
1296000.12 5000000.00
#load
0.42 0.37 0.31 1/312 9812
#cpus
4
#mem
MemTotal:        3884332 kB
MemAvailable:    2101220 kB
SwapTotal:        204796 kB
SwapFree:         204796 kB
#disk
/dev/mmcblk0p2 29787756 9811232 18731524 35% /
/dev/sda1 960302804 712113000 199323700 79% /home/pi/nas
#temp
58400
#throttled
throttled=0x0
#ips
192.168.1.17 fd00::17
#ports
0.0.0.0:22
0.0.0.0:445
0.0.0.0:1883
0.0.0.0:5001
0.0.0.0:8123
#procs
12.0  4.1 python3
 3.2  1.2 mosquitto
 1.1  0.8 smbd
 0.5  0.3 sshd
#failed
#sshd
PasswordAuthentication yes
PermitRootLogin prohibit-password
#updates
14
#users
pi
#end
"""


def parse_info(txt):
    sec, cur = {}, None
    for ln in (txt or "").splitlines():
        if ln.startswith("#") and re.fullmatch(r"#[a-z]+", ln.strip()):
            cur = ln.strip()[1:]
            sec[cur] = []
        elif cur:
            sec[cur].append(ln.rstrip())
    one = lambda k: next((x.strip() for x in sec.get(k, []) if x.strip()), "")  # noqa: E731
    r = {"hostname": one("host"), "os": one("os"), "kernel": one("kernel"), "model": one("model")}
    try:
        r["uptime_s"] = int(float(one("uptime").split()[0]))
    except (ValueError, IndexError):
        r["uptime_s"] = None
    try:
        r["load"] = [float(x) for x in one("load").split()[:3]]
    except ValueError:
        r["load"] = []
    try:
        r["cpus"] = int(one("cpus"))
    except ValueError:
        r["cpus"] = None
    mem = {}
    for ln in sec.get("mem", []):
        m = re.match(r"(\w+):\s+(\d+)", ln)
        if m:
            mem[m.group(1)] = int(m.group(2)) * 1024
    r["mem"] = {"total": mem.get("MemTotal"), "avail": mem.get("MemAvailable"), "swap_total": mem.get("SwapTotal"), "swap_free": mem.get("SwapFree")}
    disks = []
    for ln in sec.get("disk", []):
        p = ln.split()
        if len(p) >= 6 and p[1].isdigit():
            disks.append({"dev": p[0], "size": int(p[1]) * 1024, "used": int(p[2]) * 1024, "pct": int(p[4].rstrip("%") or 0), "mount": " ".join(p[5:])})
    r["disks"] = disks[:8]
    try:
        r["temp_c"] = round(int(one("temp")) / 1000, 1)
    except ValueError:
        r["temp_c"] = None
    thr = one("throttled")
    r["throttled"] = None if not thr else thr.split("=")[-1] != "0x0"
    r["ips"] = one("ips").split()[:6]
    ports = set()
    for ln in sec.get("ports", []):
        m = re.search(r":(\d+)$", ln.strip())
        if m:
            ports.add(int(m.group(1)))
    r["ports"] = sorted(ports)[:40]
    procs = []
    for ln in sec.get("procs", []):
        p = ln.split(None, 2)
        if len(p) == 3:
            try:
                procs.append({"cpu": float(p[0]), "mem": float(p[1]), "cmd": p[2][:40]})
            except ValueError:
                pass
    r["procs"] = procs
    r["failed"] = [x.strip() for x in sec.get("failed", []) if x.strip()][:10]
    sshd = {}
    for ln in sec.get("sshd", []):
        p = ln.split()
        if len(p) >= 2 and p[0].lower() not in sshd:
            sshd[p[0].lower()] = p[1].lower()
    r["sshd"] = sshd
    try:
        r["updates"] = int(one("updates"))
    except ValueError:
        r["updates"] = None
    r["users"] = [x.strip() for x in sec.get("users", []) if x.strip()]
    r["checks"] = checks(r)
    return r


def checks(r):
    """Γρήγορος έλεγχος ασφάλειας/υγείας (μόνο από όσα διαβάσαμε)."""
    c = []
    add = lambda lv, el, en, fix="": c.append({"level": lv, "el": el, "en": en, "fix": fix})  # noqa: E731
    sd = r.get("sshd") or {}
    if sd.get("passwordauthentication") == "yes":
        add("warn", "Το SSH δέχεται κωδικούς — ευάλωτο σε μαντεψιές.", "SSH accepts passwords — open to guessing.",
            "Αφού δουλέψει το κλειδί: sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload ssh")
    if sd.get("permitrootlogin") == "yes":
        add("bad", "Επιτρέπεται σύνδεση ως root με κωδικό.", "Root login with password is allowed.", "PermitRootLogin prohibit-password (ή no) στο /etc/ssh/sshd_config")
    t = r.get("temp_c")
    if t is not None and t >= 80:
        add("bad", f"Πολύ ζεστό: {t}°C — κινδυνεύει να «κόβει» ταχύτητα.", f"Very hot: {t}°C — will throttle.", "Βάλε ψύκτρα/ανεμιστήρα.")
    elif t is not None and t >= 70:
        add("warn", f"Ζεστό: {t}°C.", f"Warm: {t}°C.", "Καλός αερισμός ή ψύκτρα.")
    if r.get("throttled"):
        add("warn", "Έχει γίνει throttling/πτώση τάσης (vcgencmd).", "Throttling/under-voltage happened (vcgencmd).", "Δοκίμασε επίσημο τροφοδοτικό 5V/3A.")
    for d in r.get("disks") or []:
        if d["pct"] >= 90:
            add("bad", f"Ο δίσκος {d['mount']} είναι {d['pct']}% γεμάτος.", f"Disk {d['mount']} is {d['pct']}% full.", "Σβήσε παλιά logs/backups (π.χ. sudo journalctl --vacuum-size=200M).")
        elif d["pct"] >= 80:
            add("warn", f"Ο δίσκος {d['mount']} είναι {d['pct']}% γεμάτος.", f"Disk {d['mount']} is {d['pct']}% full.", "")
    if r.get("updates"):
        add("warn", f"{r['updates']} ενημερώσεις εκκρεμούν.", f"{r['updates']} updates pending.", "sudo apt update && sudo apt full-upgrade")
    if r.get("failed"):
        add("warn", "Υπηρεσίες που απέτυχαν: " + ", ".join(r["failed"][:5]), "Failed services: " + ", ".join(r["failed"][:5]), "systemctl status <όνομα>")
    if 23 in (r.get("ports") or []):
        add("bad", "Ανοιχτό Telnet (23) — χωρίς κρυπτογράφηση.", "Telnet (23) open — unencrypted.", "sudo systemctl disable --now telnet.socket")
    if 1883 in (r.get("ports") or []):
        add("info", "MQTT (1883) ανοιχτό — δες αν θέλει κωδικό (καρτέλα MQTT).", "MQTT (1883) open — check it requires auth (MQTT tab).", "")
    m = r.get("mem") or {}
    if m.get("total") and m.get("avail") is not None and m["avail"] / m["total"] < 0.1:
        add("warn", "Λίγη ελεύθερη μνήμη (<10%).", "Low free memory (<10%).", "")
    if not c:
        add("ok", "Δεν βρέθηκε κάτι ανησυχητικό.", "Nothing worrying found.")
    return c


def _b64(b):
    return base64.b64encode(b).decode()
