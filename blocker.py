"""Μπλοκάρισμα IP με ένα κλικ — με τείχος προστασίας του λειτουργικού, αναστρέψιμα.

macOS: pf. Οι κανόνες μπαίνουν στο anchor `com.apple/netwatch`. Το /etc/pf.conf του macOS έχει ήδη
`anchor "com.apple/*"`, οπότε το anchor αξιολογείται χωρίς να αλλάξουμε κανένα αρχείο συστήματος.
Το pf ενεργοποιείται με `pfctl -E` (με «token» αναφοράς), και απενεργοποιείται με `pfctl -X token`
όταν ξεμπλοκάρεις τα πάντα — έτσι δεν πειράζουμε ό,τι άλλο χρησιμοποιεί το pf.
Linux: iptables (INPUT + OUTPUT DROP).

Χρειάζεται root (στο Live mode το NetWatch τρέχει ήδη ως root). Αλλιώς δείχνει τις εντολές για να τις τρέξεις μόνος σου.
Οι κανόνες ζουν στη μνήμη του πυρήνα: μετά από επανεκκίνηση φεύγουν.
"""
import ipaddress
import os
import subprocess
import sys
import tempfile
import threading
import time

ANCHOR = "com.apple/netwatch"
TABLE = "netwatch_block"


def validate(ip, protect=()):
    """Επιστρέφει την κανονική μορφή της IP ή σηκώνει ValueError με ελληνικό μήνυμα."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise ValueError("Μη έγκυρη IP")
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local and a.version == 4:
        raise ValueError("Αυτή η διεύθυνση δεν μπλοκάρεται (loopback/multicast/link-local)")
    if str(a) in {str(p) for p in protect if p}:
        raise ValueError("Δεν μπλοκάρω τον εαυτό σου ή τον router — θα έχανες το Internet")
    return str(a)


def pf_rules(ips):
    """Το περιεχόμενο του anchor για το pf."""
    if not ips:
        return "# NetWatch: τίποτα μπλοκαρισμένο\n"
    lst = " ".join(sorted(ips))
    return (f"# NetWatch — μπλοκαρισμένες IP\n"
            f"table <{TABLE}> persist {{ {lst} }}\n"
            f"block drop in quick from <{TABLE}> to any\n"
            f"block drop out quick from any to <{TABLE}>\n")


def commands(ips, platform=None):
    """Οι εντολές που θα έτρεχε (για να τις δείξουμε στον χρήστη)."""
    platform = platform or sys.platform
    if platform == "darwin":
        if not ips:
            return [f"sudo pfctl -a {ANCHOR} -F all"]
        return [f"cat > /tmp/netwatch.pf <<'EOF'\n{pf_rules(ips)}EOF",
                f"sudo pfctl -a {ANCHOR} -f /tmp/netwatch.pf", "sudo pfctl -E"]
    out = []
    for ip in sorted(ips):
        ipt = "ip6tables" if ":" in ip else "iptables"
        out += [f"sudo {ipt} -I INPUT -s {ip} -j DROP -m comment --comment netwatch",
                f"sudo {ipt} -I OUTPUT -d {ip} -j DROP -m comment --comment netwatch"]
    return out


def _run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return p.returncode, (p.stdout + p.stderr).strip()


class Blocker:
    def __init__(self, protect=lambda: (), sim=False, platform=None):
        self.protect, self.sim, self.platform = protect, sim, platform or sys.platform
        self.lock = threading.Lock()
        self.blocked = {}  # ip → {"t","why"}
        self.token = None
        self.last_error = None

    @property
    def can_apply(self):
        return self.sim or (hasattr(os, "geteuid") and os.geteuid() == 0)

    def status(self):
        with self.lock:
            ips = set(self.blocked)
            return {"blocked": [{"ip": ip, **v} for ip, v in sorted(self.blocked.items(), key=lambda x: -x[1]["t"])],
                    "can_apply": self.can_apply, "demo": self.sim, "platform": self.platform,
                    "rules": pf_rules(ips) if self.platform == "darwin" else "\n".join(commands(ips, self.platform)),
                    "commands": commands(ips, self.platform), "error": self.last_error}

    def block(self, ip, why=""):
        ip = validate(ip, self.protect())
        with self.lock:
            self.blocked[ip] = {"t": time.time(), "why": str(why)[:200]}
        self._apply(added=ip)
        return self.status()

    def unblock(self, ip):
        with self.lock:
            self.blocked.pop(str(ip), None)
        self._apply(removed=str(ip))
        return self.status()

    def _apply(self, added=None, removed=None):
        self.last_error = None
        if self.sim or not self.can_apply:
            return
        with self.lock:
            ips = set(self.blocked)
        try:
            if self.platform == "darwin":
                self._apply_pf(ips)
            else:
                self._apply_iptables(added, removed)
        except Exception as e:  # δεν ρίχνουμε τον server για ένα τείχος προστασίας
            self.last_error = str(e)[:200]

    def _apply_pf(self, ips):
        if not ips:
            _run(["pfctl", "-a", ANCHOR, "-F", "all"])
            if self.token:
                _run(["pfctl", "-X", self.token])
                self.token = None
            return
        with tempfile.NamedTemporaryFile("w", suffix=".pf", delete=False) as f:
            f.write(pf_rules(ips))
        try:
            rc, out = _run(["pfctl", "-a", ANCHOR, "-f", f.name])
            if rc:
                raise RuntimeError("pfctl: " + out[-160:])
        finally:
            os.unlink(f.name)
        if not self.token:
            rc, out = _run(["pfctl", "-E"])
            for line in out.splitlines():
                if line.lower().startswith("token"):
                    self.token = line.split(":", 1)[1].strip()

    def _apply_iptables(self, added, removed):
        for ip, op in ((added, "-I"), (removed, "-D")):
            if not ip:
                continue
            ipt = "ip6tables" if ":" in ip else "iptables"
            for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
                _run([ipt, op, chain, flag, ip, "-j", "DROP", "-m", "comment", "--comment", "netwatch"])

    def clear(self):
        with self.lock:
            ips = list(self.blocked)
        for ip in ips:
            self.unblock(ip)
