"""NetWatch — 📷 NetCam Lab: σκόπιμα ευάλωτη *εικονική* IP κάμερα για εξάσκηση σε ηθικό IoT pentesting.

Εμπνευσμένο από τα OWASP IoTGoat / DVRF / Damn Vulnerable IoT labs. Επιτίθεσαι (nmap, nc, curl, strings,
mosquitto_sub) στη «κάμερα» που τρέχει ΜΟΝΟ στον υπολογιστή σου, βρίσκεις τις σημαίες NW{…}, μετά «διορθώνεις»
κάθε ευπάθεια και ξαναδοκιμάζεις για να δεις την επίθεση να αποτυγχάνει.

Ασφάλεια (σκληροί περιορισμοί):
  • ακούει ΜΟΝΟ στο 127.0.0.1 (ποτέ 0.0.0.0), σε υψηλές θύρες, και μόνο όταν το ζητήσεις (start)·
  • σβήνει μόνο του μετά από αδράνεια (προεπιλογή 30′) και όταν κλείνει το NetWatch·
  • κανένα πραγματικό shell: ο «υπολογιστής» της κάμερας είναι ένα λεξικό Python με ψεύτικα αρχεία· το command
    injection είναι *προσομοίωση* (αναγνώριση μοτίβου → έτοιμη απάντηση). Αυτό το module δεν εισάγει καν subprocess·
  • φραγμένοι πόροι: μέγιστες συνδέσεις, όρια μεγέθους ανάγνωσης, timeouts.
"""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
from collections import deque
from urllib.parse import parse_qs, quote, urlparse

HOST = "127.0.0.1"  # ΠΟΤΕ άλλη διεύθυνση — δεν είναι ρυθμίσιμο
DEFAULT_PORTS = {"telnet": 2323, "http": 8089, "mqtt": 18830}
IDLE_MIN = 30
MAX_CONNS = 20          # ταυτόχρονες συνδέσεις σε όλες τις υπηρεσίες μαζί
IO_TIMEOUT = 30         # s χωρίς δεδομένα → κλείνει η σύνδεση
SESSION_MAX = 600       # s μέγιστη διάρκεια μιας σύνδεσης
LINE_MAX = 512          # bytes ανά γραμμή (telnet / κείμενο)
HTTP_HEAD_MAX = 8192
HTTP_BODY_MAX = 4096
MQTT_PKT_MAX = 4096
TELNET_CMDS_MAX = 300
EVENTS_MAX = 300
BRUTE_COUNT, BRUTE_WINDOW = 5, 60

MODEL, FW_OLD, FW_NEW = "NC-200", "1.0.3", "1.0.4"
DEF_CREDS = {"admin": "admin", "root": "12345"}  # σαν τη λίστα του Mirai
WIFI_SSID, WIFI_PSK = "Spiti_2.4G", "Kalimera2017!"

_OWASP = {
    "I1": "Weak, Guessable, or Hardcoded Passwords", "I2": "Insecure Network Services",
    "I3": "Insecure Ecosystem Interfaces", "I4": "Lack of Secure Update Mechanism",
    "I5": "Use of Insecure or Outdated Components", "I7": "Insecure Data Transfer and Storage",
    "I9": "Insecure Default Settings",
}
_CWE = {
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-1392": "Use of Default Credentials", "CWE-798": "Use of Hard-coded Credentials",
    "CWE-306": "Missing Authentication for Critical Function", "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-78": "OS Command Injection", "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
}


def _owasp(*ids):
    return [{"id": i, "name": _OWASP[i], "url": "https://owasp.org/www-project-internet-of-things/"} for i in ids]


def _cwe(*ids):
    return [{"id": i, "name": _CWE[i], "url": f"https://cwe.mitre.org/data/definitions/{i.split('-')[1]}.html"} for i in ids]


def _mitre(tid, name):
    return {"id": tid, "name": name, "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"}


# Οι 7 προκλήσεις. Οι εντολές «try» παίρνουν τις πραγματικές θύρες με .format(**ports).
CHALLENGES = [
    {"id": "recon", "n": 1, "points": 50,
     "title": "Αναγνώριση: ποιες υπηρεσίες ακούν;",
     "desc": "Η κάμερα «τρέχει» στο 127.0.0.1. Βρες ποιες θύρες είναι ανοιχτές και τι λογισμικό/έκδοση δηλώνουν. "
             "Τα παλιά firmware «φωνάζουν» την έκδοσή τους — και κάτι ακόμα.",
     "hints": ["Σάρωσε εύρος θυρών με ανίχνευση εκδόσεων: nmap -sV.",
               "Συνδέσου «γυμνά» με nc στη θύρα telnet και διάβασε το banner πριν το login, ή δες τα headers του HTTP με curl -I."],
     "technique": "Banner grabbing / service version detection",
     "mitre": _mitre("T1046", "Network Service Discovery"),
     "cwe": _cwe("CWE-200"), "owasp": _owasp("I2", "I5"),
     "fix_title": "Κρύψε τα banners",
     "fix_desc": "Τα banners δεν δείχνουν πια έκδοση/build (Server: httpd, σκέτο «login:»). Δεν διορθώνει την ευπάθεια, "
                 "αλλά δυσκολεύει την αυτόματη στόχευση (π.χ. Shodan + λίστες CVE ανά έκδοση).",
     "try": ["nmap -sV -p 2300-20000 127.0.0.1", "nc 127.0.0.1 {telnet}", "curl -sI http://127.0.0.1:{http}/"]},
    {"id": "telnet", "n": 2, "points": 100,
     "title": "Telnet με εργοστασιακό κωδικό",
     "desc": "Η θύρα telnet ζητά όνομα χρήστη και κωδικό. Πολλές κάμερες βγαίνουν με τους ίδιους κωδικούς — "
             "το botnet Mirai μόλυνε εκατομμύρια συσκευές δοκιμάζοντας μια λίστα ~60 τέτοιων ζευγαριών.",
     "hints": ["Δοκίμασε τα κλασικά ζευγάρια της λίστας του Mirai (admin/admin, root/12345, root/xc3511 …).",
               "Μέσα στο shell: ls, cat, id, uname -a, ps. Κοίτα στο home του root."],
     "technique": "Default credentials / password guessing (Mirai-style)",
     "mitre": _mitre("T1078.001", "Valid Accounts: Default Accounts"),
     "cwe": _cwe("CWE-1392", "CWE-798"), "owasp": _owasp("I1", "I2", "I9"),
     "fix_title": "Κλείσε το telnet",
     "fix_desc": "Το telnetd σταματά — η θύρα κλείνει τελείως (connection refused). Στην πράξη: απενεργοποίηση "
                 "telnet/debug υπηρεσιών, SSH μόνο με κλειδί, μοναδικός κωδικός ανά συσκευή.",
     "try": ["nc 127.0.0.1 {telnet}", "(μετά: admin ↵ admin ↵ ls / ↵ cat /root/flag.txt)"]},
    {"id": "webcreds", "n": 3, "points": 100,
     "title": "Πίνακας διαχείρισης με admin/admin",
     "desc": "Η κάμερα έχει web σελίδα διαχείρισης. Μπες στο /admin χωρίς να «ξέρεις» τον κωδικό.",
     "hints": ["Η σελίδα δέχεται HTTP Basic auth ή τη φόρμα στο /login.",
               "curl -u χρήστης:κωδικός … — δοκίμασε τα πιο προφανή."],
     "technique": "Default credentials on web interface",
     "mitre": _mitre("T1078.001", "Valid Accounts: Default Accounts"),
     "cwe": _cwe("CWE-1392"), "owasp": _owasp("I1", "I3", "I9"),
     "fix_title": "Άλλαξε τον κωδικό admin",
     "fix_desc": "Ο κωδικός γίνεται τυχαίος και ισχυρός (φαίνεται παρακάτω) — το admin/admin απορρίπτεται. Στην πράξη: "
                 "υποχρεωτική αλλαγή κωδικού στην πρώτη χρήση, όριο προσπαθειών, χωρίς Basic auth σε καθαρό HTTP.",
     "try": ["curl -s -u admin:admin http://127.0.0.1:{http}/admin",
             "curl -si -d 'user=admin&pass=admin' http://127.0.0.1:{http}/login"]},
    {"id": "backup", "n": 4, "points": 150,
     "title": "Εκτεθειμένο αντίγραφο ρυθμίσεων",
     "desc": "Κάπου στον web server υπάρχει αρχείο backup των ρυθμίσεων που κατεβαίνει ΧΩΡΙΣ σύνδεση — "
             "με κωδικούς Wi‑Fi και διαχειριστή σε καθαρό κείμενο.",
     "hints": ["Τι λέει το /robots.txt; Οι διαχειριστές «κρύβουν» εκεί ό,τι δεν θέλουν να βρεθεί.",
               "Δοκίμασε /backup/config.bin ή /cgi-bin/backup."],
     "technique": "Forced browsing / unauthenticated sensitive file download",
     "mitre": _mitre("T1552.001", "Unsecured Credentials: Credentials In Files"),
     "cwe": _cwe("CWE-306", "CWE-312"), "owasp": _owasp("I3", "I7"),
     "fix_title": "Backup μόνο με σύνδεση",
     "fix_desc": "Το backup απαιτεί πλέον σύνδεση διαχειριστή (401 χωρίς στοιχεία). Στην πράξη: έλεγχος πρόσβασης σε "
                 "ΚΑΘΕ endpoint και κρυπτογραφημένα backups χωρίς μυστικά σε καθαρό κείμενο.",
     "try": ["curl -s http://127.0.0.1:{http}/robots.txt", "curl -s http://127.0.0.1:{http}/backup/config.bin"]},
    {"id": "cmdi", "n": 5, "points": 200,
     "title": "Command injection στο «Ping test»",
     "desc": "Η σελίδα διάγνωσης κάνει ping σε μια IP που δίνεις. Το firmware περνά την είσοδο αυτούσια σε shell… "
             "(Εδώ είναι ΠΡΟΣΟΜΟΙΩΣΗ: καμία εντολή δεν τρέχει στον υπολογιστή σου.)",
     "hints": ["Στο shell το ; χωρίζει εντολές. Τι γίνεται με «127.0.0.1; id»;",
               "Τα CGI scripts τρέχουν με δικές τους μεταβλητές περιβάλλοντος — δοκίμασε «; env»."],
     "technique": "OS command injection via unsanitised CGI parameter",
     "mitre": _mitre("T1190", "Exploit Public-Facing Application"),
     "cwe": _cwe("CWE-78"), "owasp": _owasp("I3"),
     "fix_title": "Επικύρωση εισόδου",
     "fix_desc": "Η είσοδος γίνεται δεκτή μόνο αν είναι έγκυρη διεύθυνση IP (allowlist) — αλλιώς 400. Στην πράξη: "
                 "ποτέ system()/popen με είσοδο χρήστη· κλήση του προγράμματος με λίστα ορισμάτων (execve).",
     "try": ["curl -s --get --data-urlencode 'ip=127.0.0.1; id' http://127.0.0.1:{http}/cgi-bin/ping.cgi",
             "curl -s --get --data-urlencode 'ip=127.0.0.1; env' http://127.0.0.1:{http}/cgi-bin/ping.cgi"]},
    {"id": "mqtt", "n": 6, "points": 150,
     "title": "MQTT χωρίς κωδικό: η ροή της κάμερας",
     "desc": "Η κάμερα στέλνει την κατάστασή της σε έναν MQTT broker χωρίς έλεγχο ταυτότητας. Όποιος εγγραφεί σε "
             "όλα τα topics βλέπει και το token της ζωντανής εικόνας.",
     "hints": ["Ο broker ακούει σε μη συνηθισμένη θύρα — η αναγνώριση τη βρήκε. Εγγραφή σε όλα: topic '#'.",
               "Χωρίς mosquitto; Η θύρα δέχεται και απλό κείμενο: nc και μετά SUB #."],
     "technique": "Unauthenticated MQTT subscription / wildcard topic sniffing",
     "mitre": _mitre("T1040", "Network Sniffing"),
     "cwe": _cwe("CWE-306", "CWE-319"), "owasp": _owasp("I2", "I7"),
     "fix_title": "MQTT με κωδικό",
     "fix_desc": "Ο broker δέχεται μόνο χρήστη με κωδικό (CONNACK 5 «not authorized» στους ανώνυμους). Στην πράξη: "
                 "allow_anonymous false, ACL ανά συσκευή, TLS στη θύρα 8883.",
     "try": ["mosquitto_sub -h 127.0.0.1 -p {mqtt} -t '#' -v -C 3 -W 5",
             "printf 'SUB #\\n' | nc 127.0.0.1 {mqtt}"]},
    {"id": "firmware", "n": 7, "points": 150,
     "title": "Ανάλυση firmware: κλειδί μέσα στο image",
     "desc": "Ο κατασκευαστής αφήνει το firmware για κατέβασμα. Μέσα στο image ξεχάστηκαν μυστικά (hardcoded).",
     "hints": ["Το /admin και το /robots.txt δείχνουν πού είναι το firmware (/firmware/).",
               "Κατέβασέ το και τρέξε strings πάνω του — ψάξε για KEY, secret, NW{."],
     "technique": "Firmware static analysis (strings / binwalk)",
     "mitre": _mitre("T1552.004", "Unsecured Credentials: Private Keys"),
     "cwe": _cwe("CWE-321", "CWE-798"), "owasp": _owasp("I1", "I4"),
     "fix_title": "Αφαίρεσε το κλειδί από το firmware",
     "fix_desc": f"Νέο image v{FW_NEW} χωρίς μυστικά — το κλειδί φορτώνεται από secure element/ανά συσκευή. Στην πράξη: "
                 "υπογεγραμμένα & κρυπτογραφημένα updates, κανένα κοινό κλειδί σε όλες τις συσκευές.",
     "try": ["curl -s -o /tmp/nc200.bin http://127.0.0.1:{http}/firmware/nc200.bin",
             "strings /tmp/nc200.bin | grep -iE 'key|secret|NW'"]},
]
IDS = [c["id"] for c in CHALLENGES]
BY_ID = {c["id"]: c for c in CHALLENGES}
TOTAL = sum(c["points"] for c in CHALLENGES)


class LabError(ValueError):
    pass


# ---------------------------------------------------------------- εικονικό σύστημα αρχείων / shell
class FakeShell:
    """BusyBox «shell» που ΔΕΝ εκτελεί τίποτα: κάθε εντολή είναι μια συνάρτηση Python πάνω σε λεξικό αρχείων."""

    def __init__(self, lab, ctx="telnet", user="root"):
        self.lab, self.ctx, self.user, self.cwd = lab, ctx, user, "/root" if user == "root" else "/"

    def files(self):
        lab = self.lab
        fs = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/sh\nadmin:x:0:0:admin:/:/bin/sh\n"
                           "daemon:x:1:1:daemon:/usr/sbin:/bin/false\nnobody:x:65534:65534:nobody:/:/bin/false\n",
            "/etc/shadow": "root:$1$nc200$3cR4mbL3dH4sHxX0zQ1Y/:17228:0:99999:7:::\n"
                           "admin:$1$nc200$Adm1nAdm1nAdm1nAdm1n.:17228:0:99999:7:::\n",
            "/etc/hostname": "nc200\n",
            "/etc/banner": f"{MODEL} IP Camera — firmware v{FW_OLD}\n",
            "/etc/init.d/rcS": "#!/bin/sh\nmount -a\n/usr/sbin/telnetd -p 23 -l /bin/login &\n/usr/sbin/goahead &\n"
                               "/usr/bin/mqtt_client -h 127.0.0.1 &\n/usr/bin/streamd --rtsp 554 &\n",
            "/etc/config/wireless": f"config wifi-iface\n\toption ssid '{WIFI_SSID}'\n\toption encryption 'psk2'\n"
                                    f"\toption key '{WIFI_PSK}'\n",
            "/mnt/mtd/Config/Account": "admin:admin:0\nroot:12345:0\n",
            "/proc/version": "Linux version 3.10.14 (builder@nc200) (gcc version 4.8.5) #1 PREEMPT Thu Mar 2 11:09:44 CST 2017\n",
            "/proc/cpuinfo": "system type\t: Ingenic T31\ncpu model\t: XBurst V0.0 FPU V0.0\nBogoMIPS\t: 1001.88\n",
            "/var/www/index.asp": "<% websGetVar(wp, \"page\", \"\"); %>\n",
            "/var/www/cgi-bin/ping.cgi": "#!/bin/sh\n# TODO: validate input\nIP=$(echo \"$QUERY_STRING\" | sed 's/.*ip=//')\n"
                                         "ping -c 3 $IP\n",
            "/usr/bin/mqtt_client": "(ELF 32-bit LSB executable, MIPS)\n",
            "/usr/sbin/goahead": "(ELF 32-bit LSB executable, MIPS)\n",
            "/tmp/.keep": "",
        }
        if self.ctx == "telnet":
            fs["/root/flag.txt"] = f"Συγχαρητήρια! Μπήκες με εργοστασιακό κωδικό.\n{lab.flag('telnet')}\n"
            fs["/root/README"] = "Σημείωση τεχνικού: άλλαξε τον κωδικό root πριν την παράδοση!!\n"
        return fs

    def env(self):
        if self.ctx == "cgi":
            return {"GATEWAY_INTERFACE": "CGI/1.1", "SERVER_SOFTWARE": "GoAhead-Webs/2.5.0",
                    "SCRIPT_NAME": "/cgi-bin/ping.cgi", "REQUEST_METHOD": "GET", "PATH": "/bin:/sbin:/usr/bin",
                    "PWD": "/var/www/cgi-bin", "USER": "root", "NC_CGI_DEBUG_TOKEN": self.lab.flag("cmdi")}
        return {"USER": self.user, "HOME": "/root", "SHELL": "/bin/sh", "PATH": "/bin:/sbin:/usr/bin:/usr/sbin",
                "PWD": self.cwd, "TERM": "vt100"}

    def _abs(self, p):
        if not p:
            return self.cwd
        p = p if p.startswith("/") else (self.cwd.rstrip("/") + "/" + p)
        out = []
        for part in p.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if out:
                    out.pop()
            else:
                out.append(part)
        return "/" + "/".join(out)

    def _children(self, d, fs):
        d = d.rstrip("/") + "/"
        kids = set()
        for f in fs:
            if f.startswith(d) and f != d:
                kids.add(f[len(d):].split("/")[0] + ("/" if "/" in f[len(d):] else ""))
        return sorted(kids)

    def run(self, line):
        """→ (έξοδος, exit). Εντολές μόνο από το λεξικό· ό,τι άλλο → «not found»."""
        line = line.strip()
        if not line:
            return "", False
        if len(line) > LINE_MAX:
            return "-sh: γραμμή πολύ μεγάλη\n", False
        argv = line.split()
        cmd, args = argv[0], argv[1:]
        if cmd.endswith("busybox") and args:
            if args[0].isupper():  # το «/bin/busybox MIRAI» με το οποίο το Mirai ελέγχει ότι μπήκε
                return f"{args[0]}: applet not found\n", False
            cmd, args = args[0], args[1:]
        fs = self.files()
        if cmd in ("exit", "logout", "quit"):
            return "", True
        if cmd == "help":
            return ("Built-in commands (εικονικό BusyBox — τίποτα δεν τρέχει στον υπολογιστή σου):\n"
                    "  help ls cd pwd cat id whoami uname ps ifconfig env echo busybox exit\n"), False
        if cmd == "pwd":
            return self.cwd + "\n", False
        if cmd == "cd":
            d = self._abs(args[0] if args else "/root")
            if d != "/" and not self._children(d, fs):
                return f"-sh: cd: can't cd to {args[0] if args else d}\n", False
            self.cwd = d
            return "", False
        if cmd == "ls":
            paths = [a for a in args if not a.startswith("-")] or [self.cwd]
            out = []
            for a in paths[:5]:
                p = self._abs(a)
                if p in fs:
                    out.append(a)
                    continue
                kids = self._children(p, fs) if p != "/" else self._children("/", fs)
                if not kids:
                    out.append(f"ls: {a}: No such file or directory")
                    continue
                if len(paths) > 1:
                    out.append(f"{a}:")
                out.append("  ".join(k for k in kids if "-a" in "".join(args) or not k.startswith(".")))
            return "\n".join(out) + "\n", False
        if cmd == "cat":
            out = []
            for a in args[:5]:
                p = self._abs(a)
                if p in fs:
                    out.append(fs[p])
                elif self._children(p, fs):
                    out.append(f"cat: read error: Is a directory\n")
                elif p == "/proc/self/environ":
                    out.append("\0".join(f"{k}={v}" for k, v in self.env().items()) + "\n")
                else:
                    out.append(f"cat: can't open '{a}': No such file or directory\n")
            return "".join(out), False
        if cmd == "id":
            return "uid=0(root) gid=0(root)\n", False
        if cmd == "whoami":
            return "root\n", False
        if cmd == "uname":
            if "-a" in args:
                return "Linux nc200 3.10.14 #1 PREEMPT Thu Mar 2 11:09:44 CST 2017 mips GNU/Linux\n", False
            return "Linux\n", False
        if cmd == "ps":
            return ("  PID USER       VSZ STAT COMMAND\n    1 root      1520 S    init\n"
                    "  402 root      1520 S    /usr/sbin/telnetd -p 23 -l /bin/login\n"
                    "  410 root      3804 S    /usr/sbin/goahead\n  433 root      2112 S    /usr/bin/mqtt_client -h 127.0.0.1\n"
                    "  451 root     18220 S    /usr/bin/streamd --rtsp 554\n"
                    f"  {700 + len(self.lab.events) % 200} root      1524 R    ps\n"), False
        if cmd == "ifconfig":
            return ("eth0      Link encap:Ethernet  HWaddr 00:12:34:AB:CD:EF\n"
                    "          inet addr:192.168.1.64  Bcast:192.168.1.255  Mask:255.255.255.0\n"), False
        if cmd in ("env", "printenv", "set"):
            return "".join(f"{k}={v}\n" for k, v in self.env().items()), False
        if cmd == "echo":
            return " ".join(args)[:200] + "\n", False
        if cmd in ("rm", "mv", "cp", "dd", "mkdir", "chmod", "reboot", "kill", "mtd", "flash_eraseall"):
            return f"{cmd}: Read-only file system (εικονικό lab)\n", False
        if cmd in ("wget", "curl", "tftp", "nc", "ftpget", "ping", "telnet", "ssh"):
            return f"{cmd}: bad address (το lab δεν έχει πρόσβαση σε δίκτυο)\n", False
        if cmd in ("sh", "bash", "ash"):
            return "", False
        return f"-sh: {cmd[:40]}: not found\n", False


# Χαρακτήρες/ακολουθίες που ένα πραγματικό /bin/sh θα ερμήνευε ως «νέα εντολή».
_INJ_SPLIT = re.compile(r"\|\||&&|;|\||&|\n|\r")
_INJ_SUB = re.compile(r"`([^`]*)`|\$\(([^)]*)\)")


def simulate_injection(value, shell):
    """Προσομοίωση του «ping -c 3 $IP» μέσα σε /bin/sh: χωρίζει την είσοδο όπως θα έκανε το shell και τρέχει τις
    υπόλοιπες «εντολές» στο FakeShell. → (κείμενο εξόδου, λίστα εντολών που «εκτελέστηκαν»)."""
    value = value[:LINE_MAX]
    subs = [a or b for a, b in _INJ_SUB.findall(value)]
    value = _INJ_SUB.sub(" ", value)
    parts = _INJ_SPLIT.split(value)
    target = parts[0].strip().split(" ")[0] if parts else ""
    cmds = [p.strip() for p in subs + parts[1:] if p.strip()][:5]
    out = []
    try:
        ipaddress.ip_address(target)
        out.append(f"PING {target} ({target}): 56 data bytes\n" +
                   "".join(f"64 bytes from {target}: seq={i} ttl=64 time={0.04 + i * 0.01:.3f} ms\n" for i in range(3)) +
                   f"\n--- {target} ping statistics ---\n3 packets transmitted, 3 packets received, 0% packet loss\n")
    except ValueError:
        out.append(f"ping: bad address '{target[:60]}'\n")
    for c in cmds:
        o, _ = shell.run(c)
        out.append(o)
    return "".join(out)[:8192], cmds


# ---------------------------------------------------------------- MQTT (ελάχιστο 3.1.1)
def topic_match(flt, topic):
    f, t = flt.split("/"), topic.split("/")
    for i, part in enumerate(f):
        if part == "#":
            return True
        if i >= len(t) or (part != "+" and part != t[i]):
            return False
    return len(f) == len(t)


def _mqtt_str(b, i):
    if i + 2 > len(b):
        raise ValueError("short")
    n = int.from_bytes(b[i:i + 2], "big")
    if i + 2 + n > len(b):
        raise ValueError("short")
    return b[i + 2:i + 2 + n], i + 2 + n


def _mqtt_len(n):
    out = bytearray()
    while True:
        d, n = n % 128, n // 128
        out.append(d | (0x80 if n else 0))
        if not n:
            return bytes(out)


def mqtt_publish_pkt(topic, payload, retain=True):
    t = topic.encode()
    body = len(t).to_bytes(2, "big") + t + payload
    return bytes([0x30 | (1 if retain else 0)]) + _mqtt_len(len(body)) + body


def parse_connect(body):
    """CONNECT → dict(client_id, username, password)."""
    proto, i = _mqtt_str(body, 0)
    if i + 4 > len(body):
        raise ValueError("short")
    flags = body[i + 1]
    i += 4
    cid, i = _mqtt_str(body, i)
    if flags & 0x04:
        _, i = _mqtt_str(body, i)
        _, i = _mqtt_str(body, i)
    user = pw = None
    if flags & 0x80:
        user, i = _mqtt_str(body, i)
    if flags & 0x40:
        pw, i = _mqtt_str(body, i)
    dec = lambda x: x.decode("utf-8", "replace") if x is not None else None  # noqa: E731
    return {"proto": dec(proto), "client_id": dec(cid), "username": dec(user), "password": dec(pw)}


# ---------------------------------------------------------------- το lab
class VulnLab:
    def __init__(self, state=None, cfg=None, path=None, clock=time.time, sim=False):
        cfg = dict(cfg or {})
        self.st, self.path, self.clock, self.sim = state, path, clock, sim
        ports = dict(DEFAULT_PORTS)
        for k in DEFAULT_PORTS:
            v = cfg.get(f"{k}_port", (cfg.get("ports") or {}).get(k))
            if v is not None:
                v = int(v)
                if v != 0 and not 1024 <= v <= 65535:
                    raise ValueError(f"vulnlab: η θύρα {k} πρέπει να είναι 1024–65535")
                ports[k] = v
        self.cfg_ports = ports
        self.idle_s = int(min(24 * 3600, max(60, float(cfg.get("idle_minutes") or IDLE_MIN) * 60)))
        self.max_conns = max(1, min(100, int(cfg.get("max_conns", MAX_CONNS))))
        self.lock = threading.RLock()
        self.events = deque(maxlen=EVENTS_MAX)
        self.ev_seq = 0
        self.running = False
        self.started = self.last_activity = None
        self.stopped_reason = None
        self.listeners = {}   # svc → socket
        self.threads = {}
        self.ports = {}       # svc → πραγματική θύρα (όταν τρέχει)
        self.conns = set()
        self.stop_evt = threading.Event()
        self.fails = deque(maxlen=50)
        self.verifying = False
        self.last_verify = None
        self.added_lab_ip = False
        self.on_save = None
        self.secret = secrets.token_hex(16)
        self.solved, self.fixed = {}, {i: False for i in IDS}
        self.sessions = {}  # SID cookie → t
        self._load()

    # ---------- σημαίες & μυστικά (παράγονται από ένα τυχαίο μυστικό ανά εγκατάσταση — όχι μέσα στον κώδικα) ----------
    def _h(self, what, n=8):
        return hmac.new(self.secret.encode(), what.encode(), hashlib.sha256).hexdigest()[:n]

    def flag(self, cid):
        return "NW{%s_%s}" % ({"recon": "banner_grab", "telnet": "mirai_was_here", "webcreds": "admin_admin",
                               "backup": "backup_leak", "cmdi": "semicolon_rce", "mqtt": "mqtt_eavesdrop",
                               "firmware": "strings_in_firmware"}[cid], self._h("flag:" + cid))

    def strong_pw(self, what):
        return "Nc!" + self._h("pw:" + what, 13)

    # ---------- αποθήκευση ----------
    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            return
        if isinstance(d.get("secret"), str) and re.fullmatch(r"[0-9a-f]{16,64}", d["secret"]):
            self.secret = d["secret"]
        self.solved = {k: float(v) for k, v in (d.get("solved") or {}).items() if k in BY_ID}
        for k, v in (d.get("fixed") or {}).items():
            if k in BY_ID:
                self.fixed[k] = bool(v)

    def _save(self):
        if not self.path:
            return
        with self.lock:
            data = json.dumps({"v": 1, "secret": self.secret, "solved": self.solved, "fixed": self.fixed}, ensure_ascii=False)
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    # ---------- συμβάντα («τι βλέπει ο αμυνόμενος») ----------
    def event(self, svc, kind, detail, sev="info", alert=None):
        with self.lock:
            self.ev_seq += 1
            e = {"id": self.ev_seq, "t": self.clock(), "svc": svc, "kind": kind, "detail": str(detail)[:300], "sev": sev}
            if self.verifying:
                e["verify"] = True
            self.events.append(e)
        if alert and not self.verifying:
            self._alert(*alert, detail=e["detail"])
        return e

    def _alert(self, typ, sev, key, mitre=None, detail=""):
        st = self.st
        if st is None or not hasattr(st, "alert"):
            return
        try:
            st.alert(f"{typ} (NetCam Lab)", sev, HOST, f"NetCam Lab {MODEL}", detail, time.time(),
                     key=f"vulnlab:{key}", cooldown=30, mitre=mitre)
        except Exception:
            pass

    def _touch(self):
        self.last_activity = self.clock()

    def _login_failed(self, svc, user):
        now = self.clock()
        with self.lock:
            self.fails.append(now)
            n = sum(1 for t in self.fails if now - t <= BRUTE_WINDOW)
        brute = n >= BRUTE_COUNT
        self.event(svc, "login_fail", f"αποτυχημένη σύνδεση ως «{user[:40]}» ({n} σε {BRUTE_WINDOW}″)",
                   "high" if brute else "low",
                   alert=("Brute force", "high", f"brute:{svc}") if brute else None)

    # ---------- έναρξη / τερματισμός ----------
    def start(self):
        with self.lock:
            if self.running:
                return self.status()
            self.stop_evt = threading.Event()
            self.ports, self.listeners = {}, {}
            try:
                for svc in ("telnet", "http", "mqtt"):
                    if svc == "telnet" and self.fixed["telnet"]:
                        continue
                    self._listen(svc)
            except OSError as e:
                for s in self.listeners.values():
                    s.close()
                self.listeners = {}
                raise LabError(f"Δεν άνοιξε η θύρα {self.cfg_ports[svc]} ({svc}) στο {HOST}: {e.strerror or e}. "
                               f"Άλλαξέ τη στο config.yaml (vulnlab:).")
            self.running = True
            self.started = self.last_activity = self.clock()
            self.stopped_reason = None
            if self.st is not None and hasattr(self.st, "lab_ips") and HOST not in self.st.lab_ips:
                self.st.lab_ips.add(HOST)  # ειδοποιήσεις από το lab → σημαδεμένες «lab», χωρίς ιστορικό/ειδοποιήσεις
                self.added_lab_ip = True
        threading.Thread(target=self._watchdog, args=(self.stop_evt,), daemon=True, name="vulnlab-idle").start()
        self.event("lab", "start", f"Η κάμερα {MODEL} ξεκίνησε στο {HOST} — θύρες " +
                   ", ".join(f"{k} {v}" for k, v in self.ports.items()))
        return self.status()

    def _listen(self, svc):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, self.cfg_ports[svc]))
            s.listen(16)
        except OSError:
            s.close()
            raise
        s.settimeout(0.5)
        self.listeners[svc] = s
        self.ports[svc] = s.getsockname()[1]
        t = threading.Thread(target=self._accept_loop, args=(svc, s, self.stop_evt), daemon=True, name=f"vulnlab-{svc}")
        self.threads[svc] = t
        t.start()

    def _close_listener(self, svc):
        s = self.listeners.pop(svc, None)
        if s:
            # Στο Linux ένα σκέτο close() ΔΕΝ ξυπνά το thread που περιμένει στο accept(): ο πυρήνας κρατά τη θύρα
            # σε LISTEN μέχρι να λήξει το timeout του και στο μεταξύ δέχεται συνδέσεις. Το shutdown() την κλείνει αμέσως
            # (στο macOS/Windows σηκώνει OSError για socket που δεν είναι συνδεδεμένο — δεν πειράζει).
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def stop(self, reason="manual"):
        with self.lock:
            if not self.running:
                return self.status()
            self.running = False
            self.stopped_reason = reason
            self.stop_evt.set()
            for svc in list(self.listeners):
                self._close_listener(svc)
            for c in list(self.conns):
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    c.close()
                except OSError:
                    pass
            self.conns.clear()
            self.ports = {}
            self.sessions.clear()
            if self.added_lab_ip and self.st is not None:
                self.st.lab_ips.discard(HOST)
                self.added_lab_ip = False
        for t in list(self.threads.values()):
            if t is not threading.current_thread():
                t.join(timeout=2)
        self.threads = {}
        self.event("lab", "stop", {"manual": "Σταμάτησε από εσένα.", "idle": "Σταμάτησε λόγω αδράνειας.",
                                   "shutdown": "Σταμάτησε (κλείσιμο NetWatch)."}.get(reason, reason))
        return self.status()

    def tick(self):
        """Έλεγχος αδράνειας (καλείται από το watchdog και από τα tests με ψεύτικο ρολόι)."""
        if self.running and self.last_activity is not None and self.clock() - self.last_activity >= self.idle_s:
            self.stop("idle")
            return True
        return False

    def _watchdog(self, evt):
        while not evt.wait(2):
            self.tick()

    def idle_left(self):
        if not self.running:
            return None
        return max(0, round(self.idle_s - (self.clock() - self.last_activity)))

    # ---------- εξυπηρέτηση συνδέσεων ----------
    def _accept_loop(self, svc, lsock, evt):
        handler = {"telnet": self._telnet, "http": self._http, "mqtt": self._mqtt}[svc]
        while not evt.is_set():
            try:
                conn, addr = lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                full = len(self.conns) >= self.max_conns or evt.is_set()
                if not full:
                    self.conns.add(conn)
            if full:
                try:
                    conn.close()
                finally:
                    self.event(svc, "limit", f"απορρίφθηκε σύνδεση: όριο {self.max_conns} ταυτόχρονων συνδέσεων", "low")
                continue
            self._touch()
            threading.Thread(target=self._serve, args=(handler, conn), daemon=True).start()

    def _serve(self, handler, conn):
        try:
            conn.settimeout(IO_TIMEOUT)
            handler(conn, time.monotonic() + SESSION_MAX)
        except (OSError, ValueError):
            pass
        finally:
            with self.lock:
                self.conns.discard(conn)
            self._linger_close(conn)

    @staticmethod
    def _linger_close(conn, max_bytes=256 * 1024, max_s=0.5):
        """Κλείσιμο χωρίς RST: αν ο πελάτης έστειλε περισσότερα απ' όσα διαβάσαμε (π.χ. τεράστια γραμμή → 431),
        ένα close() με αδιάβαστα δεδομένα στέλνει RST, και τα Windows τότε πετούν και την απάντηση που ήδη στείλαμε.
        Γι' αυτό: shutdown για εγγραφή (FIN), «άδειασμα» της εισόδου για λίγο, και μετά close."""
        try:
            conn.shutdown(socket.SHUT_WR)
            conn.settimeout(0.1)
            end, n = time.monotonic() + max_s, 0
            while n < max_bytes and time.monotonic() < end:
                d = conn.recv(65536)
                if not d:
                    break
                n += len(d)
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass

    @staticmethod
    def _readline(conn, buf, deadline):
        """Γραμμή κειμένου (χωρίς τις εντολές telnet IAC), έως LINE_MAX bytes. → (γραμμή|None, υπόλοιπο buffer)."""
        while b"\n" not in buf:
            if len(buf) > LINE_MAX or time.monotonic() > deadline:
                return None, b""
            d = conn.recv(256)
            if not d:
                return None, b""
            buf += d
        line, _, rest = buf.partition(b"\n")
        line = re.sub(rb"\xff[\xfb-\xfe].|\xff[\xf0-\xfa]", b"", line)
        return line.rstrip(b"\r\x00").decode("utf-8", "replace")[:LINE_MAX], rest

    # ----- telnet -----
    def telnet_banner(self):
        if self.fixed["recon"]:
            return "\r\nlogin: "
        return (f"\r\nBusyBox v1.19.4 (2017-03-02 11:09:44 CST) built-in shell\r\n"
                f"{MODEL} IP Camera - firmware v{FW_OLD} (build {self.flag('recon')})\r\n\r\nnc200 login: ")

    def _telnet(self, conn, deadline):
        self.event("telnet", "connect", "νέα σύνδεση telnet")
        conn.sendall(self.telnet_banner().encode())
        buf = b""
        for attempt in range(3):
            user, buf = self._readline(conn, buf, deadline)
            if user is None:
                return
            conn.sendall(b"Password: ")
            pw, buf = self._readline(conn, buf, deadline)
            if pw is None:
                return
            self._touch()
            if DEF_CREDS.get(user.strip()) == pw.strip() and not self.fixed["telnet"]:
                break
            self._login_failed("telnet", user.strip())
            time.sleep(0 if self.verifying else 0.3)
            conn.sendall(b"\r\nLogin incorrect\r\n" + (b"login: " if attempt < 2 else b""))
        else:
            return
        user = user.strip()
        self.event("telnet", "login_ok", f"ΕΠΙΤΥΧΗΣ σύνδεση ως «{user}» με εργοστασιακό κωδικό", "high",
                   alert=("Επιτυχής σύνδεση με προεπιλεγμένο κωδικό", "high", "telnet_login",
                          _mitre("T1078.001", "Valid Accounts: Default Accounts")))
        sh = FakeShell(self, "telnet", "root")
        conn.sendall(f"\r\n\r\nBusyBox v1.19.4 built-in shell (ash)\r\nΓράψε 'help' για εντολές.\r\n\r\n# ".encode())
        for _ in range(TELNET_CMDS_MAX):
            line, buf = self._readline(conn, buf, deadline)
            if line is None:
                return
            self._touch()
            if line.strip():
                self.event("telnet", "cmd", f"# {line.strip()[:120]}", "med")
            out, bye = sh.run(line)
            conn.sendall(out.replace("\n", "\r\n").encode())
            if bye:
                return
            conn.sendall(b"# ")

    # ----- HTTP -----
    def _http(self, conn, deadline):
        buf = b""
        while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
            if len(buf) > HTTP_HEAD_MAX or time.monotonic() > deadline:
                return self._http_send(conn, 431, "text/plain; charset=utf-8", "Request header too large\n")
            d = conn.recv(2048)
            if not d:
                return
            buf += d
        sep = b"\r\n\r\n" if b"\r\n\r\n" in buf else b"\n\n"
        head, _, body = buf.partition(sep)
        lines = head.decode("latin-1").splitlines()
        try:
            method, target, _ = lines[0].split(" ", 2)
        except ValueError:
            return self._http_send(conn, 400, "text/plain; charset=utf-8", "Bad request\n")
        hdr = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            hdr[k.strip().lower()] = v.strip()
        try:
            n = int(hdr.get("content-length") or 0)
        except ValueError:
            n = 0
        if n > HTTP_BODY_MAX:
            return self._http_send(conn, 413, "text/plain; charset=utf-8", "Payload too large\n")
        while len(body) < n and time.monotonic() < deadline:
            d = conn.recv(2048)
            if not d:
                break
            body += d
        self._touch()
        code, ctype, payload, extra = self.http_route(method.upper(), target, hdr, body[:n])
        self._http_send(conn, code, ctype, payload, extra, head_only=method.upper() == "HEAD")

    def _http_send(self, conn, code, ctype, payload, extra=None, head_only=False):
        reason = {200: "OK", 302: "Found", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
                  405: "Method Not Allowed", 413: "Payload Too Large", 431: "Request Header Fields Too Large"}.get(code, "OK")
        if isinstance(payload, str):
            payload = payload.encode()
        h = [f"HTTP/1.0 {code} {reason}"]
        if self.fixed["recon"]:
            h.append("Server: httpd")
        else:
            h += ["Server: GoAhead-Webs/2.5.0", f"X-Firmware: {MODEL} v{FW_OLD} build {self.flag('recon')}"]
        h += [f"Content-Type: {ctype}", f"Content-Length: {len(payload)}", "Connection: close", "Cache-Control: no-store"]
        h += [f"{k}: {v}" for k, v in (extra or {}).items()]
        conn.sendall(("\r\n".join(h) + "\r\n\r\n").encode("latin-1", "replace") + (b"" if head_only else payload))

    def _http_user(self, hdr):
        """→ (όνομα χρήστη αν συνδεδεμένος, δοκίμασε_basic_χωρίς_επιτυχία)."""
        import base64
        auth = hdr.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                u, _, p = base64.b64decode(auth[6:].strip()).decode("utf-8", "replace").partition(":")
            except ValueError:
                u, p = "?", ""
            if self._web_ok(u, p):
                return u, False
            return None, u or "?"
        m = re.search(r"(?:^|;\s*)SID=([0-9a-f]{32})", hdr.get("cookie", ""))
        if m and m.group(1) in self.sessions:
            return "admin", False
        return None, False

    def _web_ok(self, u, p):
        return u == "admin" and p == (self.strong_pw("web") if self.fixed["webcreds"] else "admin")

    def http_route(self, method, target, hdr, body):
        u = urlparse(target)
        path = re.sub(r"/{2,}", "/", u.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        if method == "POST" and "urlencoded" in hdr.get("content-type", "application/x-www-form-urlencoded"):
            q.update({k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True).items()})
        html = "text/html; charset=utf-8"
        self.event("http", "request", f"{method} {target[:160]}")
        if method not in ("GET", "POST", "HEAD"):
            return 405, "text/plain", "Method not allowed\n", None
        user, bad_basic = self._http_user(hdr)
        if bad_basic:
            self._login_failed("http", bad_basic)
        if path in ("/", "/index.asp", "/index.html"):
            if user:
                return 302, html, "", {"Location": "/admin"}
            return 200, html, self._page_login(), None
        if path == "/robots.txt":
            return 200, "text/plain", "User-agent: *\nDisallow: /admin\nDisallow: /backup/\nDisallow: /cgi-bin/\nDisallow: /firmware/\n", None
        if path == "/login":
            if method != "POST":
                return 200, html, self._page_login(), None
            un, pw = q.get("user", q.get("username", "")), q.get("pass", q.get("password", ""))
            if self._web_ok(un, pw):
                sid = secrets.token_hex(16)
                with self.lock:
                    if len(self.sessions) > 50:
                        self.sessions.clear()
                    self.sessions[sid] = self.clock()
                self._web_login_ok(un)
                return 302, html, "", {"Location": "/admin", "Set-Cookie": f"SID={sid}; Path=/; HttpOnly"}
            self._login_failed("http", un or "?")
            return 401, html, self._page_login("Λάθος όνομα χρήστη ή κωδικός."), None
        if path == "/logout":
            return 302, html, "", {"Location": "/", "Set-Cookie": "SID=; Path=/; Max-Age=0"}
        if path in ("/admin", "/admin/", "/admin.asp"):
            if not user:
                return 401, html, "<h1>401 Unauthorized</h1>", {"WWW-Authenticate": f'Basic realm="{MODEL}"'}
            if hdr.get("authorization"):
                self._web_login_ok(user)
            return 200, html, self._page_admin(), None
        if path in ("/backup/config.bin", "/cgi-bin/backup", "/cgi-bin/backup.cgi", "/backup/"):
            if self.fixed["backup"] and not user:
                self.event("http", "blocked", "άρνηση backup χωρίς σύνδεση (διορθωμένο)", "low")
                return 401, "text/plain", "401 Unauthorized\n", {"WWW-Authenticate": f'Basic realm="{MODEL}"'}
            self.event("http", "backup", "ΚΑΤΕΒΗΚΕ το αρχείο ρυθμίσεων" + ("" if user else " ΧΩΡΙΣ σύνδεση"), "high",
                       alert=None if user else ("Έκθεση αρχείου ρυθμίσεων", "med", "backup",
                                                _mitre("T1552.001", "Unsecured Credentials: Credentials In Files")))
            return 200, "application/octet-stream", self.backup_blob(), {"Content-Disposition": 'attachment; filename="config.bin"'}
        if path in ("/cgi-bin/ping.cgi", "/ping.cgi", "/cgi-bin/ping"):
            if "ip" not in q:
                return 200, html, self._page_ping(), None
            return self._ping(q["ip"])
        if path in ("/firmware", "/firmware/"):
            v = FW_NEW if self.fixed["firmware"] else FW_OLD
            return 200, html, (f"<html><body><h1>Index of /firmware/</h1><a href='/firmware/nc200.bin'>nc200.bin</a> "
                               f"({MODEL} v{v})</body></html>"), None
        if path in ("/firmware/nc200.bin", f"/firmware/NC200_v{FW_OLD}.bin", f"/firmware/NC200_v{FW_NEW}.bin"):
            v = FW_NEW if self.fixed["firmware"] else FW_OLD
            self.event("http", "firmware", f"κατέβασμα firmware v{v}", "med")
            return 200, "application/octet-stream", self.firmware_blob(), {"Content-Disposition": f'attachment; filename="NC200_v{v}.bin"'}
        if path in ("/snapshot.jpg", "/snapshot.svg"):
            if q.get("token") != self._stream_token():
                return 403, "text/plain", "403 invalid token\n", None
            self.event("http", "snapshot", "λήψη στιγμιότυπου με κλεμμένο token", "high")
            return 200, "image/svg+xml", ("<svg xmlns='http://www.w3.org/2000/svg' width='320' height='180'>"
                                          "<rect width='320' height='180' fill='#222'/><text x='20' y='95' fill='#0f0' "
                                          "font-family='monospace'>NC-200 CAM1 — εικονικό στιγμιότυπο</text></svg>"), None
        return 404, html, "<h1>404 Not Found</h1>", None

    def _web_login_ok(self, user):
        self.event("http", "login_ok", f"ΕΠΙΤΥΧΗΣ σύνδεση στο web ως «{user}»" +
                   ("" if self.fixed["webcreds"] else " με εργοστασιακό κωδικό"), "high",
                   alert=None if self.fixed["webcreds"] else
                   ("Επιτυχής σύνδεση με προεπιλεγμένο κωδικό", "high", "web_login",
                    _mitre("T1078.001", "Valid Accounts: Default Accounts")))

    def _ping(self, value):
        self.event("http", "ping", f"ping test: «{value[:120]}»")
        if self.fixed["cmdi"]:
            try:
                ipaddress.ip_address(value.strip())
            except ValueError:
                self.event("http", "blocked", f"απορρίφθηκε μη έγκυρη είσοδος: «{value[:120]}»", "med")
                return 400, "text/plain; charset=utf-8", "400 Μη έγκυρη διεύθυνση IP (επιτρέπονται μόνο IPv4/IPv6).\n", None
            out, _ = simulate_injection(value.strip(), FakeShell(self, "cgi"))
        else:
            out, cmds = simulate_injection(value, FakeShell(self, "cgi"))
            if cmds:
                self.event("http", "injection", "COMMAND INJECTION: " + " ; ".join(c[:60] for c in cmds), "high",
                           alert=("Command injection", "high", "cmdi", _mitre("T1190", "Exploit Public-Facing Application")))
        esc = out.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return 200, "text/html; charset=utf-8", f"<html><body><h2>Ping test</h2><pre>{esc}</pre></body></html>\n", None

    def _page_login(self, err=""):
        return (f"<!doctype html><html><head><meta charset='utf-8'><title>{MODEL} Web</title></head><body>"
                f"<h1>{MODEL} IP Camera</h1><p>Firmware v{'?' if self.fixed['recon'] else FW_OLD}</p>"
                + (f"<p style='color:red'>{err}</p>" if err else "") +
                "<form method='post' action='/login'>User <input name='user'> Pass <input name='pass' type='password'> "
                "<button>Login</button></form><!-- TODO: αφαίρεσε τη σελίδα /cgi-bin/ping.cgi πριν την παραγωγή --></body></html>")

    def _page_admin(self):
        flag = self.flag("webcreds")
        return (f"<!doctype html><html><head><meta charset='utf-8'><title>{MODEL} Admin</title></head><body>"
                f"<h1>{MODEL} — Πίνακας διαχείρισης</h1><p>Καλώς ήρθες, admin. Σημαία: <b>{flag}</b></p>"
                "<ul><li><a href='/cgi-bin/ping.cgi'>Διάγνωση: Ping test</a></li>"
                "<li><a href='/backup/config.bin'>Λήψη backup ρυθμίσεων</a></li>"
                "<li><a href='/firmware/'>Firmware</a></li><li><a href='/logout'>Αποσύνδεση</a></li></ul></body></html>")

    def _page_ping(self):
        return ("<!doctype html><html><head><meta charset='utf-8'><title>Ping test</title></head><body><h2>Ping test</h2>"
                "<form method='get' action='/cgi-bin/ping.cgi'>IP <input name='ip' value='192.168.1.1'> "
                "<button>Ping</button></form></body></html>")

    def backup_blob(self):
        return (f"# {MODEL} configuration backup — v{FW_OLD}\n[system]\nhostname=nc200\nadmin_user=admin\n"
                f"admin_pass={self.strong_pw('web') if self.fixed['webcreds'] else 'admin'}\n"
                f"[wifi]\nssid={WIFI_SSID}\nencryption=WPA2-PSK\npsk={WIFI_PSK}\n"
                f"[cloud]\np2p_uid=NC200-A1B2C3\nbackup_id={self.flag('backup')}\n"
                f"[mqtt]\nhost=127.0.0.1\nuser=\npass=\n").encode()

    def _stream_token(self):
        return self.flag("mqtt")

    def firmware_blob(self):
        """Ντετερμινιστικό «firmware»: θόρυβος + συμβολοσειρές που βγάζει το strings."""
        fixed = self.fixed["firmware"]
        v = FW_NEW if fixed else FW_OLD
        strs = ["NC200FW", f"{MODEL} firmware v{v}", "Linux version 3.10.14", "BusyBox v1.19.4 (2017-03-02 11:09:44 CST)",
                "GoAhead-Webs/2.5.0", "/etc/init.d/rcS", "/usr/sbin/goahead", "/usr/bin/streamd --rtsp 554",
                "/bin/login", "squashfs-root", "u-boot 2013.07 (Ingenic T31)"]
        if fixed:
            strs += ["crypto: key from secure element (ATECC608A)", "telnetd disabled at build time",
                     "update: RSA-2048 signature required"]
        else:
            strs += ["/usr/sbin/telnetd -p 23 -l /bin/login", "default_user=admin", "default_pass=admin",
                     f"AES_KEY={self._h('aes', 32)}", f"cloud_api_secret={self.flag('firmware')}",
                     "update: no signature check (TODO)"]
        seed = hashlib.sha256((self.secret + v).encode()).digest()
        out = bytearray(b"NC200FW\x00" + v.encode() + b"\x00" * 8)
        i = 0
        for s in strs:
            for _ in range(3):  # ~1.5 KB θορύβου πριν από κάθε συμβολοσειρά
                i += 1
                chunk = hashlib.sha256(seed + i.to_bytes(4, "big")).digest() * 16
                out += bytes(b if b < 0x20 or b > 0x7e else b & 0x1f for b in chunk[:500])  # χωρίς τυχαίο «κείμενο»
            out += b"\x00" + s.encode() + b"\x00"
        return bytes(out)

    # ----- MQTT -----
    def retained(self):
        return [("netcam/nc200/status", json.dumps({"online": True, "model": MODEL, "fw": FW_OLD, "uptime": 86400})),
                ("netcam/nc200/motion", json.dumps({"motion": False, "zone": "σαλόνι"}, ensure_ascii=False)),
                ("netcam/nc200/stream", json.dumps({"rtsp": "rtsp://127.0.0.1:554/live/ch0",
                                                    "snapshot": f"http://{HOST}:{self.ports.get('http', DEFAULT_PORTS['http'])}"
                                                                f"/snapshot.svg?token={quote(self._stream_token())}",
                                                    "token": self._stream_token()}))]

    def _mqtt_auth_ok(self, user, pw):
        if not self.fixed["mqtt"]:
            return True
        return user == "nc200" and pw == self.strong_pw("mqtt")

    def _recv_exact(self, conn, n, deadline):
        b = b""
        while len(b) < n:
            if time.monotonic() > deadline:
                raise ValueError("deadline")
            d = conn.recv(min(4096, n - len(b)))
            if not d:
                raise ValueError("eof")
            b += d
        return b

    def _mqtt(self, conn, deadline):
        first = conn.recv(1)
        if not first:
            return
        if first[0] != 0x10:
            return self._mqtt_text(conn, first, deadline)
        authed = False
        hdr = first[0]
        while True:
            n, mult = 0, 1
            for _ in range(4):
                b = self._recv_exact(conn, 1, deadline)[0]
                n += (b & 0x7f) * mult
                mult *= 128
                if not b & 0x80:
                    break
            else:
                return
            if n > MQTT_PKT_MAX:
                self.event("mqtt", "limit", f"πακέτο MQTT {n} bytes > όριο {MQTT_PKT_MAX}", "low")
                return
            body = self._recv_exact(conn, n, deadline)
            self._touch()
            typ = hdr >> 4
            if typ == 1:
                if authed:
                    return
                c = parse_connect(body)
                ok = self._mqtt_auth_ok(c["username"], c["password"])
                who = f"client «{(c['client_id'] or '')[:40]}»" + (f" χρήστης «{c['username'][:40]}»" if c["username"] else " ανώνυμα")
                if not ok:
                    self.event("mqtt", "auth_fail", f"MQTT CONNECT απορρίφθηκε ({who})", "low")
                    conn.sendall(b"\x20\x02\x00\x05")
                    return
                authed = True
                self.event("mqtt", "connect", f"MQTT CONNECT {who}", "low" if self.fixed["mqtt"] else "med")
                conn.sendall(b"\x20\x02\x00\x00")
            elif not authed:
                return
            elif typ == 8:  # SUBSCRIBE
                pid, i, flts = body[:2], 2, []
                while i < len(body) and len(flts) < 10:
                    f, i = _mqtt_str(body, i)
                    i += 1
                    flts.append(f.decode("utf-8", "replace"))
                conn.sendall(bytes([0x90]) + _mqtt_len(2 + len(flts)) + pid + b"\x00" * len(flts))
                self._mqtt_subscribed(flts)
                for topic, payload in self.retained():
                    if any(topic_match(f, topic) for f in flts):
                        conn.sendall(mqtt_publish_pkt(topic, payload.encode()))
            elif typ == 3:  # PUBLISH
                t, i = _mqtt_str(body, 0)
                qos = (hdr >> 1) & 3
                pid = body[i:i + 2] if qos else b""
                payload = body[i + (2 if qos else 0):]
                self.event("mqtt", "publish", f"PUBLISH {t.decode('utf-8', 'replace')[:80]} → «{payload[:80].decode('utf-8', 'replace')}»", "med")
                if qos == 1:
                    conn.sendall(b"\x40\x02" + pid)
            elif typ == 12:
                conn.sendall(b"\xd0\x00")
            elif typ == 14:
                return
            else:
                return
            hdr = self._recv_exact(conn, 1, deadline)[0]

    def _mqtt_subscribed(self, flts):
        wild = any("#" in f or "+" in f for f in flts)
        self.event("mqtt", "subscribe", "SUBSCRIBE " + ", ".join(f[:60] for f in flts),
                   "high" if wild and not self.fixed["mqtt"] else "med",
                   alert=("Άγνωστος MQTT client", "med", "mqtt_sub") if wild and not self.fixed["mqtt"] else None)

    def _mqtt_text(self, conn, first, deadline):
        """Απλό πρωτόκολλο κειμένου στην ίδια θύρα (για όσους δεν έχουν mosquitto): HELP, AUTH, SUB, QUIT."""
        buf = first
        authed = not self.fixed["mqtt"]
        for _ in range(50):
            line, buf = self._readline(conn, buf, deadline)
            if line is None:
                return
            self._touch()
            parts = line.strip().split()
            if not parts:
                continue
            cmd = parts[0].upper()
            if cmd == "HELP":
                conn.sendall(b"NC-200 event bus (MQTT 3.1.1 / text). Commands: AUTH <user> <pass> | SUB <filter> | QUIT\n")
            elif cmd == "AUTH" and len(parts) == 3:
                if self._mqtt_auth_ok(parts[1], parts[2]):
                    authed = True
                    conn.sendall(b"OK\n")
                else:
                    self.event("mqtt", "auth_fail", f"AUTH απορρίφθηκε για «{parts[1][:40]}»", "low")
                    conn.sendall(b"ERR not authorized\n")
            elif cmd == "SUB" and len(parts) == 2:
                if not authed:
                    self.event("mqtt", "auth_fail", "SUB χωρίς AUTH απορρίφθηκε", "low")
                    conn.sendall(b"ERR not authorized (AUTH first)\n")
                    continue
                self._mqtt_subscribed([parts[1]])
                for topic, payload in self.retained():
                    if topic_match(parts[1], topic):
                        conn.sendall(f"{topic} {payload}\n".encode())
                conn.sendall(b"END\n")
            elif cmd in ("QUIT", "EXIT"):
                return
            else:
                conn.sendall(b"ERR unknown command (try HELP)\n")

    # ---------- API ----------
    def submit(self, flag):
        flag = str(flag or "").strip()[:120]
        if not flag:
            raise LabError("Γράψε μια σημαία της μορφής NW{…}.")
        if self.running:
            self._touch()
        for cid in IDS:
            if hmac.compare_digest(flag.encode(), self.flag(cid).encode()):
                c = BY_ID[cid]
                with self.lock:
                    already = cid in self.solved
                    if not already:
                        self.solved[cid] = time.time()
                self._save()
                if not already:
                    self.event("lab", "solved", f"✔ Λύθηκε: {c['title']} (+{c['points']})")
                return {"correct": True, "id": cid, "title": c["title"], "points": c["points"], "already": already,
                        "score": self.score(), "total": TOTAL}
        return {"correct": False, "message": "Λάθος σημαία — δεν αντιστοιχεί σε καμία πρόκληση.", "score": self.score(), "total": TOTAL}

    def score(self):
        return sum(BY_ID[c]["points"] for c in self.solved)

    def set_fix(self, cid, on):
        if cid not in BY_ID:
            raise LabError("Άγνωστη πρόκληση.")
        on = bool(on)
        with self.lock:
            self.fixed[cid] = on
            if cid == "telnet" and self.running:
                if on:
                    self._close_listener("telnet")
                    self.ports.pop("telnet", None)
                elif "telnet" not in self.listeners:
                    try:
                        self._listen("telnet")
                    except OSError as e:
                        raise LabError(f"Δεν ξανάνοιξε το telnet: {e.strerror or e}")
            if cid in ("webcreds",) and on:
                self.sessions.clear()
            if self.running:
                self._touch()
        self._save()
        self.event("lab", "fix", f"{'🔧 Διόρθωση' if on else '↩ Αναίρεση διόρθωσης'}: {BY_ID[cid]['fix_title']}")
        return self.status()

    def reset(self):
        with self.lock:
            self.solved = {}
            self.events.clear()
            self.last_verify = None
        for cid in IDS:
            if self.fixed[cid]:
                self.set_fix(cid, False)
        self._save()
        self.event("lab", "reset", "Μηδενισμός προόδου και διορθώσεων.")
        return self.status()

    # ---------- self-test: ξαναδοκιμάζει κάθε επίθεση στις δικές του θύρες ----------
    def verify(self):
        if not self.running:
            raise LabError("Το lab δεν τρέχει — πάτησε «Έναρξη» πρώτα.")
        self._touch()
        res = []
        self.verifying = True
        try:
            for cid in IDS:
                try:
                    secure, detail = getattr(self, "_v_" + cid)()
                except Exception as e:
                    secure, detail = False, f"σφάλμα ελέγχου: {e}"
                res.append({"id": cid, "fixed": self.fixed[cid], "secure": secure, "detail": detail})
        finally:
            self.verifying = False
        self.last_verify = {"t": time.time(), "results": res, "secure": sum(r["secure"] for r in res), "of": len(res)}
        self.event("lab", "verify", f"Έλεγχος διορθώσεων: {self.last_verify['secure']}/{len(res)} ασφαλή")
        return self.last_verify

    def _port(self, svc):
        return self.ports.get(svc) or self.cfg_ports[svc]

    def _conn(self, svc):
        return socket.create_connection((HOST, self._port(svc)), timeout=3)

    def _http_get(self, path, auth=None):
        import base64
        with self._conn("http") as s:
            h = f"GET {path} HTTP/1.0\r\nHost: {HOST}\r\n"
            if auth:
                h += "Authorization: Basic " + base64.b64encode(auth.encode()).decode() + "\r\n"
            s.sendall((h + "\r\n").encode())
            data = b""
            while len(data) < 200000:
                d = s.recv(65536)
                if not d:
                    break
                data += d
        head, _, body = data.partition(b"\r\n\r\n")
        return int(head.split(b" ", 2)[1]), head.decode("latin-1"), body

    def _telnet_banner_read(self):
        with self._conn("telnet") as s:
            data = b""
            while b"login: " not in data and len(data) < 4096:
                d = s.recv(1024)
                if not d:
                    break
                data += d
            return s, data.decode("utf-8", "replace")

    def _v_recon(self):
        flag = self.flag("recon")
        _, head, _ = self._http_get("/")
        leaks = []
        if flag in head or "GoAhead" in head:
            leaks.append("HTTP headers")
        if "telnet" in self.ports:
            _, banner = self._telnet_banner_read()
            if flag in banner or FW_OLD in banner:
                leaks.append("banner telnet")
        return (not leaks, "Τα banners δεν δείχνουν έκδοση/σημαία." if not leaks else "Διαρροή έκδοσης σε: " + ", ".join(leaks))

    def _v_telnet(self):
        try:
            s = self._conn("telnet")
        except OSError:
            return True, "Η θύρα telnet είναι κλειστή (connection refused)."
        with s:
            data = b""
            s.settimeout(3)
            try:
                while b"login: " not in data and len(data) < 4096:
                    d = s.recv(1024)
                    if not d:
                        break
                    data += d
                s.sendall(b"admin\r\n")
                time.sleep(0.05)
                s.sendall(b"admin\r\n")
                out = b""
                while b"# " not in out and b"incorrect" not in out and len(out) < 4096:
                    d = s.recv(1024)
                    if not d:
                        break
                    out += d
            except OSError:
                out = b""
            if b"# " in out:
                s.sendall(b"exit\r\n")
                return False, "Το telnet είναι ανοιχτό και δέχεται admin/admin."
        return False, "Το telnet είναι ακόμα ανοιχτό (καλύτερα κλειστό εντελώς)."

    def _v_webcreds(self):
        code, _, _ = self._http_get("/admin", auth="admin:admin")
        return (code != 200, "Το admin/admin απορρίπτεται (401)." if code != 200 else "Το /admin δέχεται admin/admin.")

    def _v_backup(self):
        code, _, body = self._http_get("/backup/config.bin")
        leak = code == 200 and self.flag("backup").encode() in body
        return (not leak, f"Χωρίς σύνδεση → {code}." if not leak else "Το backup κατεβαίνει χωρίς σύνδεση (200).")

    def _v_cmdi(self):
        code, _, body = self._http_get("/cgi-bin/ping.cgi?ip=" + quote("127.0.0.1; env"))
        leak = self.flag("cmdi").encode() in body
        return (not leak, f"Η είσοδος «127.0.0.1; env» απορρίφθηκε ({code})." if not leak else
                "Το «; env» εκτελέστηκε (προσομοίωση) — η είσοδος δεν ελέγχεται.")

    def _v_mqtt(self):
        cid = b"nw-verify"
        body = b"\x00\x04MQTT\x04\x02\x00\x1e" + len(cid).to_bytes(2, "big") + cid
        with self._conn("mqtt") as s:
            s.sendall(b"\x10" + _mqtt_len(len(body)) + body)
            ack = b""
            while len(ack) < 4:
                d = s.recv(4 - len(ack))
                if not d:
                    break
                ack += d
        ok = len(ack) == 4 and ack[3] == 0
        return (not ok, "Ανώνυμο CONNECT → απορρίφθηκε (CONNACK 5)." if not ok else "Ο broker δέχεται ανώνυμους (CONNACK 0).")

    def _v_firmware(self):
        _, _, body = self._http_get("/firmware/nc200.bin")
        leak = self.flag("firmware").encode() in body or b"AES_KEY=" in body
        return (not leak, "Το image δεν περιέχει κλειδιά/σημαία." if not leak else "Το strings βρίσκει AES_KEY και σημαία.")

    # ---------- κατάσταση για το UI ----------
    def status(self):
        with self.lock:
            ports = dict(self.ports) if self.running else {}
            show = {k: ports.get(k) or self.cfg_ports[k] or DEFAULT_PORTS[k] for k in DEFAULT_PORTS}
            ch = []
            for c in CHALLENGES:
                d = {k: c[k] for k in ("id", "n", "title", "desc", "points", "hints", "technique", "mitre", "cwe", "owasp",
                                       "fix_title", "fix_desc")}
                d["solved"] = c["id"] in self.solved
                d["solved_t"] = self.solved.get(c["id"])
                d["fixed"] = self.fixed[c["id"]]
                d["try"] = [t.format(**show) for t in c["try"]]
                d["fix_info"] = None
                if self.fixed[c["id"]] and c["id"] == "webcreds":
                    d["fix_info"] = f"Νέος κωδικός admin: {self.strong_pw('web')}"
                if self.fixed[c["id"]] and c["id"] == "mqtt":
                    d["fix_info"] = f"Χρήστης MQTT: nc200 / κωδικός: {self.strong_pw('mqtt')}"
                v = next((r for r in (self.last_verify or {}).get("results", []) if r["id"] == c["id"]), None)
                d["verify"] = v
                ch.append(d)
            ev = list(self.events)[-100:][::-1]
            return {
                "running": self.running, "host": HOST, "ports": show, "listening": ports,
                "config_ports": dict(self.cfg_ports),
                "started": self.started if self.running else None,
                "uptime_s": round(self.clock() - self.started) if self.running else 0,
                "idle_timeout_s": self.idle_s, "idle_left_s": self.idle_left(),
                "stopped_reason": self.stopped_reason, "connections": len(self.conns), "max_conns": self.max_conns,
                "device": {"model": MODEL, "firmware": FW_OLD, "year": 2017, "server": "GoAhead-Webs/2.5.0",
                           "busybox": "1.19.4"},
                "persist": bool(self.path), "challenges": ch, "score": self.score(), "total": TOTAL,
                "solved": len(self.solved), "count": len(CHALLENGES), "events": ev, "verify": self.last_verify,
            }
