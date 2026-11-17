"""Τερματικό της Ακαδημίας: τρέχει ΑΣΦΑΛΕΙΣ εντολές δικτύου στο Mac σου, από τα μαθήματα.

Κανόνες:
- Μόνο εντολές από λίστα (ping, nmap, dig, traceroute, curl, openssl, ifconfig, grep…). Τίποτα που αλλάζει το σύστημα.
- Χωρίς shell: επιτρέπεται μόνο `|` (pipe). Όχι ; && > < ` $( — άρα ούτε ανακατευθύνσεις ούτε αλυσίδες.
- Ποτέ ως root: αν το NetWatch τρέχει ως root (Live), οι εντολές τρέχουν ως ο κανονικός χρήστης.
- nmap μόνο προς ιδιωτικές διευθύνσεις (το δικό σου δίκτυο) ή το scanme.nmap.org.
- Όριο χρόνου 30″ και 64 KB έξοδο.
Για εντολές που υπάρχουν μόνο σε Linux/Raspberry Pi (apt, systemctl, ip…) εξηγεί και προτείνει την αντίστοιχη του Mac.
"""
import ipaddress
import os
import shlex
import shutil
import subprocess
import sys
import time

ALLOW = {
    "ping", "ping6", "nmap", "dig", "nslookup", "host", "traceroute", "traceroute6", "curl", "ifconfig", "arp",
    "netstat", "route", "openssl", "nc", "whois", "grep", "egrep", "head", "tail", "wc", "sort", "uniq", "cut",
    "echo", "cat", "ls", "pwd", "whoami", "id", "date", "uname", "hostname", "scutil", "ipconfig", "lsof",
    "mosquitto_sub", "mosquitto_pub", "ssh-keyscan", "networksetup", "tr", "base64", "shasum",
    "sha256sum", "md5", "xxd", "hexdump", "file", "which", "python3",
}
# εντολές που επιτρέπονται μόνο με συγκεκριμένα «ασφαλή» πρώτα ορίσματα
ONLY = {
    "scutil": {"--dns", "--proxy", "--nc"},
    "networksetup": {"-listallhardwareports", "-getinfo", "-getdnsservers", "-getairportnetwork", "-listallnetworkservices"},
    "route": {"-n", "get"},
    "python3": {"--version", "-V"},
}
NOT_MAC = {
    "ip": "Το `ip` είναι του Linux (Raspberry Pi). Στο Mac: `ifconfig` (διευθύνσεις), `netstat -rn` (routes), `arp -a` (γείτονες).",
    "ss": "Το `ss` είναι του Linux. Στο Mac: `netstat -an` ή `lsof -i -nP`.",
    "apt": "Το `apt` εγκαθιστά πακέτα στο Raspberry Pi/Debian. Στο Mac το αντίστοιχο είναι το `brew install …` (από δικό σου Terminal).",
    "apt-get": "Το `apt-get` είναι του Raspberry Pi/Debian. Στο Mac: `brew`.",
    "systemctl": "Το `systemctl` διαχειρίζεται υπηρεσίες στο Linux (Pi). Στο Mac το αντίστοιχο είναι το `launchctl` / `brew services`.",
    "journalctl": "Το `journalctl` δείχνει logs στο Linux. Στο Mac: `log show --last 5m`.",
    "ufw": "Το `ufw` είναι firewall του Linux. Στο Mac το firewall είναι το pf (και το Application Firewall στις Ρυθμίσεις).",
    "iptables": "Το `iptables` είναι firewall του Linux. Στο Mac: pf (`pfctl`).",
    "nft": "Το `nft` (nftables) είναι firewall του Linux. Στο Mac: pf.",
    "raspi-config": "Το `raspi-config` υπάρχει μόνο στο Raspberry Pi OS.",
    "tcpdump": "Το `tcpdump` θέλει δικαιώματα διαχειριστή — εδώ δεν τρέχω τίποτα ως root. Δες τα πακέτα ζωντανά στην καρτέλα 📦 Πακέτα του NetWatch!",
    "esptool.py": "Το `esptool` μιλάει με το ESP32 πάνω από USB — τρέξ' το από δικό σου Terminal με την πλακέτα συνδεδεμένη.",
    "esptool": "Το `esptool` μιλάει με το ESP32 πάνω από USB — τρέξ' το από δικό σου Terminal.",
    "idf.py": "Το `idf.py` είναι του ESP-IDF — τρέξ' το από δικό σου Terminal μέσα στο project.",
    "espefuse.py": "⚠️ Το `espefuse` γράφει eFuses (ΜΗ αναστρέψιμα). Ποτέ από εδώ — μόνο συνειδητά, από δικό σου Terminal.",
    "arduino-cli": "Το `arduino-cli` τρέξ' το από δικό σου Terminal μέσα στον φάκελο του sketch.",
    "mosquitto": "Ο broker `mosquitto` τρέχει στο Pi (ή `brew services start mosquitto` στο Mac).",
    "mosquitto_passwd": "Το `mosquitto_passwd` αλλάζει αρχεία κωδικών — τρέξ' το στο Pi.",
    "fail2ban-client": "Το fail2ban τρέχει στο Pi (Linux).",
    "ssh": "Το `ssh` είναι διαδραστικό — άνοιξέ το σε δικό σου Terminal.",
    "ssh-keygen": "Το `ssh-keygen` φτιάχνει αρχεία κλειδιών — τρέξ' το σε δικό σου Terminal.",
    "nano": "Το `nano` είναι διαδραστικός editor — άνοιξέ το σε δικό σου Terminal.",
    "vim": "Διαδραστικός editor — άνοιξέ το σε δικό σου Terminal.",
}
BAD_CHARS = (";", "&", ">", "<", "`", "$(", "\n")
LIMIT = 64 * 1024


def _user_ids():
    """(uid, gid) του κανονικού χρήστη όταν τρέχουμε ως root, αλλιώς None."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        return int(uid), int(gid)
    st = os.stat(os.path.dirname(os.path.abspath(__file__)))  # ο φάκελος της εφαρμογής ανήκει στον χρήστη
    return (st.st_uid, st.st_gid) if st.st_uid else (-2, -2)  # αλλιώς «nobody»


def _nmap_targets_ok(args):
    skip_next = {"-p", "-oN", "-oX", "-oG", "-oA", "--top-ports", "-e", "--script", "-iL", "--exclude", "-T"}
    targets, i = [], 0
    while i < len(args):
        a = args[i]
        if a.startswith(("-iL", "-o", "--script", "--resume", "--datadir", "--stylesheet")):
            return False, f"Το `{a}` δεν επιτρέπεται εδώ (διαβάζει/γράφει αρχεία ή τρέχει scripts)."
        if a in skip_next:
            i += 2
            continue
        if not a.startswith("-"):
            targets.append(a)
        i += 1
    if not targets:
        return False, "Δώσε στόχο, π.χ. `nmap -sT -p 22,80,1883 192.168.1.0/24`."
    for t in targets:
        if t == "scanme.nmap.org":
            continue
        try:
            net = ipaddress.ip_network(t.split("-")[0] if "/" not in t else t, strict=False)
        except ValueError:
            return False, f"Το nmap εδώ σκανάρει μόνο το δικό σου δίκτυο (ιδιωτικές IP) ή το scanme.nmap.org — όχι το `{t}`."
        if not (net.is_private or net.is_loopback):
            return False, f"Το `{t}` δεν είναι ιδιωτική διεύθυνση. Σκανάρουμε μόνο ό,τι σου ανήκει."
    return True, ""


def check(cmdline):
    """→ (λίστα από argv για κάθε κομμάτι του pipe, None) ή (None, μήνυμα γιατί όχι)."""
    line = cmdline.strip()
    if not line:
        return None, ""
    if line.startswith("#"):
        return None, "(σχόλιο — δεν τρέχει τίποτα)"
    if any(c in line for c in BAD_CHARS):
        return None, "Εδώ επιτρέπεται μόνο `|` (pipe): όχι `;`, `&&`, `>`, `<`, `` ` `` ή `$(…)`. Τρέξε μία εντολή τη φορά."
    try:
        parts = [shlex.split(p) for p in line.split("|")]
    except ValueError as e:
        return None, f"Δεν καταλαβαίνω την εντολή ({e})."
    if any(not p for p in parts):
        return None, "Άδειο κομμάτι στο pipe."
    for argv in parts:
        cmd = os.path.basename(argv[0])
        if cmd == "sudo":
            rest = os.path.basename(argv[1]) if len(argv) > 1 else ""
            extra = (" " + NOT_MAC[rest]) if rest in NOT_MAC else (
                " Δοκίμασε χωρίς sudo (π.χ. στο nmap βάλε `-sT` αντί για `-sS`)." if rest == "nmap" else "")
            return None, "Εδώ δεν τρέχει τίποτα με `sudo` (ως διαχειριστής) — για ασφάλεια." + extra
        if cmd in NOT_MAC:
            return None, NOT_MAC[cmd]
        if cmd not in ALLOW:
            return None, f"Το `{cmd}` δεν είναι στη λίστα ασφαλών εντολών αυτού του τερματικού. Τρέξ' το σε δικό σου Terminal αν το εμπιστεύεσαι."
        if cmd in ONLY and (len(argv) < 2 or argv[1] not in ONLY[cmd]):
            return None, f"Το `{cmd}` επιτρέπεται εδώ μόνο ως: " + ", ".join(f"`{cmd} {a}`" for a in sorted(ONLY[cmd]))
        if cmd == "nmap":
            ok, why = _nmap_targets_ok(argv[1:])
            if not ok:
                return None, why
            if any(a in ("-sS", "-sU", "-O", "-sN", "-sF", "-sX", "-sA") for a in argv):
                return None, "Αυτό το είδος σάρωσης θέλει root. Εδώ χρησιμοποίησε `-sT` (TCP connect) — κάνει την ίδια δουλειά, απλώς πιο «θορυβώδικα»."
        bad = {"curl": ("-o", "-O", "--output", "-T", "--upload-file", "-K", "--config", "-D", "--dump-header", "-c", "--cookie-jar"),
               "openssl": ("-out", "-keyout", "-writerand"), "uniq": (), "sort": ("-o",)}.get(cmd)
        if bad and any(a.startswith(bad) for a in argv[1:] if a.startswith("-")):
            return None, f"Εδώ το `{cmd}` μόνο διαβάζει: όχι επιλογές που γράφουν αρχεία ({', '.join(b for b in bad)})."
        if cmd in ("uniq", "xxd") and len([a for a in argv[1:] if not a.startswith("-")]) > 1:
            return None, f"Το `{cmd}` με δεύτερο αρχείο γράφει έξοδο σε αρχείο — όχι εδώ."
        if cmd in ("ping", "ping6") and not any(a.startswith("-c") for a in argv):
            argv[1:1] = ["-c", "4"]  # αλλιώς τρέχει για πάντα
        if cmd == "mosquitto_sub" and "-W" not in argv:
            argv += ["-W", "15"]
        if cmd in ("cat", "head", "tail", "grep") and any(os.path.expanduser(a).startswith(
                tuple(os.path.expanduser(p) for p in ("~/.ssh", "~/Library/Keychains", "/etc/master.passwd"))) for a in argv[1:]):
            return None, "Αυτό το αρχείο έχει κλειδιά/κωδικούς — δεν το εμφανίζω εδώ."
        if not shutil.which(argv[0]):
            hint = " (`brew install nmap`)" if cmd == "nmap" else " (`brew install mosquitto`)" if cmd.startswith("mosquitto") else ""
            return None, f"Το `{cmd}` δεν είναι εγκατεστημένο σε αυτόν τον υπολογιστή{hint}."
    return parts, None


MAC_EQUIV = [  # (regex πάνω στην εντολή χωρίς sudo, αντικατάσταση για το Mac)
    (r"^ip (-4 )?a(ddr)?( show)?\b.*", "ifconfig | grep 'inet '"),
    (r"^ip -6 a(ddr)?.*", "ifconfig | grep inet6"),
    (r"^ip r(oute)?\b.*", "netstat -rn"),
    (r"^ip n(eigh)?\b.*", "arp -a"),
    (r"^ss\b.*", "netstat -an -p tcp"),
]


def suggest(cmdline):
    """Μια εκδοχή της εντολής που ΤΡΕΧΕΙ εδώ (χωρίς sudo, -sT αντί για -sS, εντολές Mac αντί για Linux), αλλιώς None."""
    import re
    c = re.sub(r"^\s*sudo\s+", "", cmdline.strip())
    for rx, rep in MAC_EQUIV:
        if re.match(rx, c):
            c = rep
            break
    if c.startswith("nmap"):
        c = re.sub(r"\s-s[SUNFXA]\b", " -sT", c)
        c = re.sub(r"\s-O\b", "", c)
    if c == cmdline.strip():
        return None
    parts, why = check(c)
    return c if parts is not None else None


def run(cmdline, timeout=30):
    parts, why = check(cmdline)
    if parts is None:
        return {"ok": False, "out": why, "code": None, "ms": 0, "blocked": True, "suggest": suggest(cmdline) if why else None}
    ids = _user_ids()

    def drop():
        if ids:
            os.setgid(ids[1])
            os.setuid(ids[0])
    env = {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "HOME": os.path.expanduser("~")}
    t0, procs, prev = time.time(), [], None
    try:
        for argv in parts:
            p = subprocess.Popen(argv, stdin=prev.stdout if prev else subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, env=env, preexec_fn=drop if ids else None, cwd=env["HOME"] if not ids else "/tmp")
            if prev:
                prev.stdout.close()
            procs.append(p)
            prev = p
        out, _ = procs[-1].communicate(timeout=timeout)
        for p in procs[:-1]:
            p.wait(timeout=2)
        code, timed = procs[-1].returncode, False
    except subprocess.TimeoutExpired:
        for p in procs:
            p.kill()
        out, code, timed = procs[-1].stdout.read() if procs[-1].stdout else b"", None, True
    except OSError as e:
        return {"ok": False, "out": str(e), "code": None, "ms": 0}
    text = out[:LIMIT].decode("utf-8", "replace")
    if len(out) > LIMIT:
        text += "\n… (κόπηκε: πολύ μεγάλη έξοδος)"
    if timed:
        text += f"\n⏱ σταμάτησε μετά από {timeout}″"
    return {"ok": code == 0, "out": text, "code": code, "ms": int((time.time() - t0) * 1000)}


if __name__ == "__main__":
    print(run(" ".join(sys.argv[1:]))["out"])
