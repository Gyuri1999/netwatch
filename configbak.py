"""💾 Αντίγραφα ρυθμίσεων δικτυακών συσκευών & διαφορές (ιδέα: Oxidized / RANCID).

Κάθε `every_hours` ώρες (ή όταν πατήσεις «Αντίγραφο τώρα») παίρνουμε τις ρυθμίσεις κάθε συσκευής με το
**ssh του συστήματος** και τις κρατάμε ως εκδόσεις: data/configs/<id>/<unix_ts>.txt + index.json.
Νέα έκδοση γράφεται μόνο αν άλλαξε κάτι πραγματικό — οι «πτητικές» γραμμές (π.χ. στο Cisco
`! Last configuration change at …`, `ntp clock-period`, `Current configuration : N bytes`, στο MikroTik η
κεφαλίδα `# <ημερομηνία> by RouterOS`) αφαιρούνται πριν τη σύγκριση.

🔑 Μόνο κλειδιά SSH — ΠΟΤΕ κωδικοί: δεν δεχόμαστε ούτε αποθηκεύουμε password. Το ssh τρέχει με
`-o BatchMode=yes`, άρα αν δεν υπάρχει κλειδί απλώς αποτυγχάνει (δεν ρωτά κωδικό). Βάλε το δημόσιο κλειδί σου:
  • Linux / OpenWrt:  ssh-copy-id user@192.168.1.3  (στο OpenWrt/dropbear: /etc/dropbear/authorized_keys)
  • Cisco IOS:        ip ssh pubkey-chain → username backup → key-string → (επικόλληση) → exit
                      (καλύτερα χρήστης privilege 15 μόνο για ανάγνωση, π.χ. με «privilege exec level 15 show running-config»)
  • MikroTik:         /user ssh-keys import public-key-file=id_ed25519.pub user=backup  (ομάδα read)
Αν το NetWatch τρέχει με sudo, το ssh τρέχει ως ο κανονικός χρήστης (SUDO_USER) ώστε να βρει τα δικά σου
~/.ssh κλειδιά και το known_hosts (StrictHostKeyChecking=accept-new: δέχεται μόνο την πρώτη φορά).

Cisco: το `show running-config` μέσω SSH exec δεν «σελιδοποιεί» (δεν υπάρχει τερματικό), οπότε δεν χρειάζεται
`terminal length 0`· αν η συσκευή σου διαφέρει, δώσε δικό σου `command`.

Επιτρέπονται μόνο ιδιωτικές / loopback διευθύνσεις (και τα ονόματα πρέπει να λύνονται μόνο σε τέτοιες).

🙈 Μυστικά: ό,τι επιστρέφει το API (κείμενο, διαφορές) έχει τα μυστικά κρυμμένα (`<κρυφό>`) — enable secret,
κωδικοί χρηστών, SNMP communities, κλειδιά/pre-shared keys, wpa-psk, MikroTik password=, OpenWrt option key…
Τα αρχεία στον δίσκο κρατούν το πρωτότυπο. Και η διαφορά υπολογίζεται πάνω στο «κρυμμένο» κείμενο.

⚠ Ανάλυση κινδύνου κάθε αλλαγής: νέος τοπικός χρήστης, telnet, SNMP community, απενεργοποίηση κρυπτογράφησης
κωδικών, αφαίρεση ACL, web server διαχείρισης, NAT / port forward, shutdown διεπαφών, VLAN. Σε κάθε νέα
έκδοση (εκτός από την πρώτη της συσκευής) βγαίνει ειδοποίηση «Αλλαγή ρυθμίσεων».

Στη λειτουργία demo όλα μένουν στη μνήμη: 3 συσκευές με ρεαλιστικό ιστορικό ~10 ημερών, ποτέ ssh.
"""
import difflib
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time

import netkit

DEFAULTS = {"enabled": True, "every_hours": 24, "keep": 200, "devices": []}
VENDORS = ("cisco_ios", "mikrotik", "openwrt", "linux", "generic")
COMMANDS = {
    "cisco_ios": "show running-config",
    "mikrotik": "/export hide-sensitive",
    "openwrt": "uci export",
    "linux": "cat /etc/network/interfaces /etc/netplan/*.yaml 2>/dev/null",
}
ID_RE = re.compile(r"^[a-z0-9_.-]{1,40}$")
USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,31}$")
MAX_TEXT = 512 * 1024
TIMEOUT = 30
MASK = "<κρυφό>"
MAX_DIFF_LINES = 5000
DEMO_BACKUP_SECONDS = 2.0

# ───────── πτητικές γραμμές (δεν μετράνε ως αλλαγή) ─────────
VOLATILE = [re.compile(p) for p in (
    r"^!\s*Last configuration change at\b",
    r"^!\s*NVRAM config last updated at\b",
    r"^!\s*No configuration change since last restart",
    r"^ntp clock-period\s+\d+",
    r"^Current configuration\s*:\s*\d+\s*bytes",
    r"^Building configuration\.\.\.",
    r"^#\s.*\bby RouterOS\b",
)]

# ───────── μυστικά ─────────
_OWRT = re.compile(r"^(\s*option\s+(?:key|password|psk|sae_password|secret|auth_secret|acct_secret|private_key|preshared_key)\s+)(\S.*)$")
_YAML = re.compile(r"^(\s*(?:password|psk|secret|private-key|preshared-key)\s*:\s*)(\S.*)$")
_EQ = re.compile(r"\b((?:password|secret|passphrase|wpa2?-pre-shared-key|pre-shared-key|authentication-key|private-key|"
                 r"preshared-key|auth-key|psk)=)(\"(?:[^\"\\]|\\.)*\"|\S+)")
_PW = re.compile(r"\b(secret|password)(\s+)(?:[0-9]\s+)?(?!" + re.escape(MASK) + r")(\S+)")
_SNMP = re.compile(r"\b(snmp-server community\s+)(\S+)")
_KEY = re.compile(r"\b(key-string|pre-shared-key|key)(\s+)(?!generate\b|chain\b|config-key\b|zeroize\b|pubkey|storage\b|"
                  r"import\b|export\b|rsa\b|ec\b|label\b|" + re.escape(MASK) + r")(?:[0-9]\s+)?(\S+)")
_WPA = re.compile(r"\b(wpa-psk)(\s+)(?:(?:ascii|hex)\s+)?(?:[0-9]\s+)?(?!" + re.escape(MASK) + r")(\S+)")
_XML = re.compile(r"(<(password|bcrypt-hash|sha512-hash|secret|pre-shared-key|psk|key|passwd|community)>)([^<]*)(</\2>)", re.I)
_MT_NAME = re.compile(r"\b(name=)(\"(?:[^\"\\]|\\.)*\"|\S+)")


def mask(text):
    """Κρύβει τα μυστικά (κωδικούς, κλειδιά, communities) — γραμμή-γραμμή, με γνώση της ενότητας MikroTik."""
    out, sec = [], ""
    for ln in (text or "").split("\n"):
        s = ln.strip()
        if s.startswith("/"):
            sec = s.split(" add ")[0].split(" set ")[0]
        if s.startswith("#") or s.startswith("!"):  # σχόλια (κεφαλίδες RouterOS, διαχωριστικά Cisco)
            out.append(ln)
            continue
        m = _OWRT.match(ln) or _YAML.match(ln)
        if m:
            out.append(m.group(1) + MASK)
            continue
        ln = _XML.sub(lambda m: m.group(1) + MASK + m.group(4), ln)
        ln = _EQ.sub(lambda m: m.group(1) + MASK, ln)
        ln = _SNMP.sub(lambda m: m.group(1) + MASK, ln)
        ln = _WPA.sub(lambda m: m.group(1) + m.group(2) + MASK, ln)
        ln = _PW.sub(lambda m: m.group(1) + m.group(2) + MASK, ln)
        ln = _KEY.sub(lambda m: m.group(1) + m.group(2) + MASK, ln)
        if sec.startswith("/snmp community") and not s.startswith("/"):
            ln = _MT_NAME.sub(lambda m: m.group(1) + MASK, ln)
        out.append(ln)
    return "\n".join(out)


def normalize(text):
    """Καθαρό κείμενο για σύγκριση: χωρίς \\r, κενά στο τέλος, πτητικές γραμμές, κενές αρχής/τέλους."""
    lines = [ln.rstrip() for ln in (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    lines = [ln for ln in lines if not any(p.match(ln) for p in VOLATILE)]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def sha12(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]


# ───────── ανάλυση κινδύνου ─────────
def _logical(lines):
    """Ενώνει τις γραμμές συνέχειας του MikroTik (τελειώνουν σε «\\»)."""
    out, buf = [], ""
    for ln in lines:
        if ln.endswith("\\"):
            buf += ln[:-1].rstrip() + " "
            continue
        out.append((buf + ln.strip()) if buf else ln)
        buf = ""
    if buf:
        out.append(buf.rstrip())
    return out


def _ctx(lines):
    """Για κάθε γραμμή: (μπλοκ = η τελευταία γραμμή χωρίς εσοχή — η ίδια, αν δεν έχει εσοχή —, ενότητα MikroTik = «/…»)."""
    res, blk, sec = [], "", ""
    for ln in lines:
        if ln and not ln[0].isspace() and not ln.startswith("!"):
            if ln.startswith("/"):
                sec = ln.strip()
            blk = ln.strip()
            res.append((blk, sec))
        else:
            res.append((blk, sec))
    return res


def _kv(line, key):
    m = re.search(r"(?:^|\s)" + re.escape(key) + r"=(\"[^\"]*\"|\S+)", line)
    return m.group(1).strip('"') if m else None


def _changes(old, new):
    a, b = _logical(old.split("\n") if old else []), _logical(new.split("\n") if new else [])
    ca, cb = _ctx(a), _ctx(b)
    added, removed = [], []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op in ("delete", "replace"):
            removed += [(a[i].strip(), ca[i][0], ca[i][1]) for i in range(i1, i2) if a[i].strip()]
        if op in ("insert", "replace"):
            added += [(b[j].strip(), cb[j][0], cb[j][1]) for j in range(j1, j2) if b[j].strip()]
    return a, b, added, removed


def analyze(old, new):
    """Λίστα [(επίπεδο, κείμενο)] για μια αλλαγή — επίπεδο "risk" (ασφάλεια) ή "info" (δομή: VLAN, shutdown).

    Τα κείμενα δεν περιέχουν ποτέ μυστικές τιμές (μόνο ονόματα χρηστών/διεπαφών, θύρες, γνωστές προεπιλογές)."""
    a, b, added, removed = _changes(old or "", new or "")
    out = []

    def put(level, text):
        if (level, text) not in out:
            out.append((level, text))
    added_set = {x[0] for x in added}
    old_users = set(re.findall(r"^username\s+(\S+)", "\n".join(a), re.M))
    ctx_a = _ctx(a)
    old_users |= {_kv(ln, "name") for ln, (_b, sec) in zip(a, ctx_a) if sec == "/user" and ln.startswith("add ")}
    old_comms = set(re.findall(r"^snmp-server community\s+(\S+)", "\n".join(a), re.M))
    new_acls = set(re.findall(r"^(?:ipv6 |ip )?access-list\s+(?:(?:standard|extended)\s+)?(\S+)", "\n".join(b), re.M))
    old_acls = set(re.findall(r"^(?:ipv6 |ip )?access-list\s+(?:(?:standard|extended)\s+)?(\S+)", "\n".join(a), re.M))
    old_ssids = set(re.findall(r"^\s*option ssid\s+'?([^'\n]*)'?", "\n".join(a), re.M))
    new_ifaces = set(re.findall(r"^interface\s+(\S+)", "\n".join(b), re.M))
    old_trunk = {}
    for ln, (blk, _sec) in zip(a, ctx_a):
        m = re.match(r"\s*switchport trunk allowed vlan\s+(.+)", ln)
        if m and blk.startswith("interface"):
            old_trunk[blk.split(None, 1)[1]] = m.group(1).strip()

    for ln, blk, sec in added:
        # νέος τοπικός χρήστης
        m = re.match(r"username\s+(\S+)", ln)
        if m and m.group(1) not in old_users:
            put("risk", f"Νέος τοπικός χρήστης «{m.group(1)}»" + (" με privilege 15 (πλήρη δικαιώματα)" if re.search(r"\bprivilege 15\b", ln) else ""))
        if sec == "/user" and ln.startswith("add ") and _kv(ln, "name") and _kv(ln, "name") not in old_users:
            put("risk", f"Νέος τοπικός χρήστης «{_kv(ln, 'name')}»" + (f" (ομάδα {_kv(ln, 'group')})" if _kv(ln, "group") else ""))
        # telnet
        m = re.match(r"transport input\b(.*)", ln)
        if m and re.search(r"\b(telnet|all)\b", m.group(1)):
            put("risk", f"Ενεργοποιήθηκε telnet ({blk or 'line'}: «{ln}») — κωδικοί σε απλό κείμενο")
        if re.search(r"(?:^|\s)enable telnet\b", ln) or (sec == "/ip service" and re.match(r"set telnet\b", ln) and "disabled=yes" not in ln):
            put("risk", "Ενεργοποιήθηκε η υπηρεσία telnet (/ip service) — κωδικοί σε απλό κείμενο")
        # SNMP community
        m = re.match(r"snmp-server community\s+(\S+)(.*)", ln)
        if m and m.group(1) not in old_comms:
            rw = " με δικαίωμα εγγραφής (RW)" if re.search(r"\bRW\b", m.group(2)) else ""
            if m.group(1).lower() in ("public", "private"):
                put("risk", f"Προστέθηκε SNMP community προεπιλογής «{m.group(1).lower()}»{rw} — μαντεύεται αμέσως")
            else:
                put("risk", f"Προστέθηκε SNMP community{rw}")
        if sec.startswith("/snmp community") and re.match(r"(add|set)\b", ln) and _kv(ln, "name"):
            nm = _kv(ln, "name")
            put("risk", f"Προστέθηκε SNMP community προεπιλογής «{nm.lower()}» (MikroTik)" if nm.lower() in ("public", "private")
                else "Προστέθηκε / άλλαξε SNMP community (MikroTik)")
        # κρυπτογράφηση κωδικών
        if ln == "no service password-encryption":
            put("risk", "Απενεργοποιήθηκε η κρυπτογράφηση κωδικών (no service password-encryption)")
        # web server διαχείρισης
        if ln == "ip http server":
            put("risk", "Ενεργοποιήθηκε ο web server διαχείρισης χωρίς HTTPS (ip http server)")
        # NAT / port forward
        if re.match(r"ip nat (?:inside|outside) source static\b", ln):
            put("risk", f"Νέο static NAT / port forward: «{ln}»")
        if sec.startswith("/ip firewall nat") and "action=dst-nat" in ln:
            dp, to, tp, pr = _kv(ln, "dst-port"), _kv(ln, "to-addresses"), _kv(ln, "to-ports"), _kv(ln, "protocol")
            put("risk", "Νέο port forward (dst-nat): " + (f"{pr}/" if pr else "") + (dp or "όλες οι θύρες") +
                f" → {to or '?'}" + (f":{tp}" if tp else "") + (f" «{_kv(ln, 'comment')}»" if _kv(ln, "comment") else ""))
        if re.match(r"config redirect\b", ln):
            put("risk", "Νέο port forward (OpenWrt redirect)")
        # ACL / firewall (πληροφοριακά: αλλαγή κανόνων)
        m = re.match(r"(?:ipv6 |ip )?access-list\s+(?:(?:standard|extended)\s+)?(\S+)", blk)
        if m and not ln.startswith("!"):
            put("info", f"Άλλαξε η ACL «{m.group(1)}»" if m.group(1) in old_acls else f"Νέα ACL «{m.group(1)}»")
        m = re.match(r"(?:ip access-group|access-class)\s+(\S+)", ln)
        if m and blk:
            put("info", f"Εφαρμόστηκε η ACL «{m.group(1)}» στο {blk}")
        if sec.startswith("/ip firewall filter") and ln.startswith("add ") and re.search(r"action=(drop|reject)", ln):
            put("info", "Νέος κανόνας firewall (" + _kv(ln, "action") + ")" + (f" «{_kv(ln, 'comment')}»" if _kv(ln, "comment") else ""))
        # Wi‑Fi (OpenWrt)
        m = re.match(r"option ssid\s+'?([^']*)'?", ln)
        if m and blk.startswith("config wifi-iface") and m.group(1) not in old_ssids:
            put("info", f"Νέο SSID «{m.group(1)}»")
        if re.match(r"option encryption\s+'?none'?", ln) and blk.startswith("config wifi-iface"):
            put("risk", "Ανοιχτό Wi‑Fi χωρίς κρυπτογράφηση (option encryption 'none')")
        # διεπαφές
        if blk.startswith("interface") and ln == "shutdown":
            put("info", f"Απενεργοποιήθηκε η διεπαφή {blk.split(None, 1)[1]} (shutdown)")
        if blk.startswith("interface") and ln == "no shutdown":
            put("info", f"Ενεργοποιήθηκε η διεπαφή {blk.split(None, 1)[1]} (no shutdown)")
        # VLAN
        m = re.match(r"vlan\s+(\d+(?:[,-]\d+)*)$", ln)
        if m and not blk.startswith("interface"):
            put("info", f"Προστέθηκε VLAN {m.group(1)}")
        if sec.startswith("/interface vlan") and ln.startswith("add ") and _kv(ln, "vlan-id"):
            put("info", f"Προστέθηκε VLAN {_kv(ln, 'vlan-id')}" + (f" ({_kv(ln, 'name')})" if _kv(ln, "name") else ""))
        m = re.match(r"switchport trunk allowed vlan\s+(.+)", ln)
        if m and blk.startswith("interface"):
            ifn = blk.split(None, 1)[1]
            put("info", f"Άλλαξαν τα επιτρεπόμενα VLAN στο trunk {ifn}: {old_trunk.get(ifn, '—')} → {m.group(1).strip()}")

    for ln, blk, sec in removed:
        if ln == "service password-encryption":
            put("risk", "Απενεργοποιήθηκε η κρυπτογράφηση κωδικών (no service password-encryption)")
        if sec == "/ip service" and re.match(r"set telnet\b.*disabled=yes", ln) and \
                not any(re.match(r"set telnet\b.*disabled=yes", x) for x in added_set):
            put("risk", "Ενεργοποιήθηκε η υπηρεσία telnet (/ip service) — κωδικοί σε απλό κείμενο")
        m = re.match(r"(?:ipv6 |ip )?access-list\s+(?:(?:standard|extended)\s+)?(\S+)", ln)
        if m and not blk.startswith("interface") and m.group(1) not in new_acls:
            put("risk", f"Αφαιρέθηκε η ACL «{m.group(1)}»")
        m = re.match(r"(?:ip access-group|access-class|ipv6 traffic-filter)\s+(\S+)", ln)
        if m and ln not in added_set:
            put("risk", f"Αφαιρέθηκε η εφαρμογή της ACL «{m.group(1)}» από {blk or '?'}")
        if sec.startswith("/ip firewall filter") and ln.startswith("add ") and re.search(r"action=(drop|reject)", ln) and ln not in added_set:
            put("risk", "Αφαιρέθηκε κανόνας firewall που μπλόκαρε κίνηση" + (f" «{_kv(ln, 'comment')}»" if _kv(ln, "comment") else ""))
        if blk.startswith("interface") and ln == "shutdown" and blk.split(None, 1)[1] in new_ifaces and "shutdown" not in added_set:
            put("info", f"Ενεργοποιήθηκε η διεπαφή {blk.split(None, 1)[1]} (no shutdown)")
        m = re.match(r"vlan\s+(\d+(?:[,-]\d+)*)$", ln)
        if m and not blk.startswith("interface") and ln not in added_set:
            put("info", f"Αφαιρέθηκε VLAN {m.group(1)}")
        if sec.startswith("/interface vlan") and ln.startswith("add ") and _kv(ln, "vlan-id") and \
                not any(_kv(x, "vlan-id") == _kv(ln, "vlan-id") for x in added_set if x.startswith("add ")):
            put("info", f"Αφαιρέθηκε VLAN {_kv(ln, 'vlan-id')}")
    return out


# ───────── ssh ─────────
def check_host(host, resolve=True):
    """Μόνο ιδιωτικές / loopback διευθύνσεις. Ονόματα: όλες οι IP τους πρέπει να είναι ιδιωτικές."""
    h = netkit.valid_host(host)
    try:
        addrs = [ipaddress.ip_address(h)]
    except ValueError:
        if not resolve:
            return h
        try:
            addrs = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)}
        except (socket.gaierror, UnicodeError, OSError, ValueError):
            raise ValueError(f"Δεν βρέθηκε το όνομα «{h}»")
    for a in addrs:
        if not netkit._is_private(a) or a.is_unspecified:
            raise ValueError(f"Επιτρέπονται μόνο ιδιωτικές/τοπικές διευθύνσεις (όχι {a})")
    return h


def ssh_argv(dev):
    """Η εντολή ssh (λίστα, χωρίς shell). Μόνο κλειδιά: BatchMode=yes → ποτέ ερώτηση κωδικού."""
    cmd = dev.get("command") or COMMANDS.get(dev.get("vendor"))
    if not cmd:
        raise ValueError("Για vendor «generic» χρειάζεται «command» στο config.yaml")
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new"]
    if dev.get("identity_file"):
        argv += ["-i", os.path.expanduser(str(dev["identity_file"]))]
    argv += ["-p", str(int(dev.get("port") or 22)), f"{dev['user']}@{dev['host']}", cmd]
    return argv


def _as_user(argv):
    """Με sudo: τρέξε το ssh ως ο κανονικός χρήστης (τα κλειδιά και το known_hosts του)."""
    user = os.environ.get("SUDO_USER")
    if user and hasattr(os, "geteuid") and os.geteuid() == 0 and USER_RE.match(user):
        return ["sudo", "-n", "-u", user, "--"] + argv
    return argv


def _clean_dev(d, manual=False):
    """Ελέγχει μια συσκευή από το config. Επιστρέφει (συσκευή, σφάλμα ή None)."""
    did = str(d.get("id") or "").strip()
    if not ID_RE.match(did):
        return None, f"Μη έγκυρο id «{did[:40]}» (a-z, 0-9, _ . -, έως 40)"
    vendor = str(d.get("vendor") or "generic").strip().lower()
    if vendor not in VENDORS:
        vendor = "generic"
    dev = {"id": did, "name": str(d.get("name") or did)[:80], "host": str(d.get("host") or "").strip()[:255],
           "vendor": vendor, "user": str(d.get("user") or "").strip(), "manual": bool(manual),
           "command": (str(d["command"]).strip()[:500] if d.get("command") else None),
           "identity_file": (str(d["identity_file"])[:500] if d.get("identity_file") else None)}
    try:
        dev["port"] = int(d.get("port") or 22)
        if not 0 < dev["port"] < 65536:
            raise ValueError
    except (TypeError, ValueError):
        dev["port"] = 22
        return dev, "Μη έγκυρη θύρα SSH"
    if manual:
        return dev, None
    if d.get("password") or d.get("secret"):
        return dev, "Δεν δεχόμαστε κωδικούς — χρησιμοποίησε κλειδί SSH (identity_file)"
    if not dev["host"]:
        return dev, "Λείπει το host"
    try:
        check_host(dev["host"], resolve=False)
    except ValueError as e:
        return dev, str(e)
    if not USER_RE.match(dev["user"]):
        return dev, "Λείπει ή είναι μη έγκυρο το user"
    if vendor == "generic" and not dev["command"]:
        return dev, "Για vendor «generic» χρειάζεται «command»"
    return dev, None


class ConfigBackup:
    def __init__(self, state, cfg=None, sim=False, path=None, clock=time.time):
        self.st, self.sim, self.clock = state, sim, clock
        self.cfg = {**DEFAULTS, **(cfg or {})}
        self.path = None if sim else path
        self.lock = threading.RLock()
        self.on_save = None
        self.devices = {}      # id → συσκευή (σειρά εισαγωγής)
        self.vers = {}         # id → [έκδοση] (παλαιότερη πρώτη)
        self.info = {}         # id → {status, error, last_backup}
        self._mem = {}         # demo: id → {ts: κείμενο}
        try:
            self.every = max(1.0, float(self.cfg.get("every_hours") or 24))
        except (TypeError, ValueError):
            self.every = 24.0
        try:
            self.keep = max(2, int(self.cfg.get("keep") or 200))
        except (TypeError, ValueError):
            self.keep = 200
        if sim:
            self._seed()
            return
        for d in self.cfg.get("devices") or []:
            if not isinstance(d, dict):
                continue
            dev, err = _clean_dev(d)
            if dev is None or dev["id"] in self.devices:
                continue
            self.devices[dev["id"]] = dev
            self.vers[dev["id"]] = []
            self.info[dev["id"]] = {"status": "error" if err else "never", "error": err, "last_backup": None, "config_error": bool(err)}
        if self.path:
            self._load()

    # ───────── αποθήκευση ─────────
    def _dir(self, did):
        return os.path.join(self.path, did)

    def _write(self, fn, data):
        tmp = fn + ".tmp"
        os.makedirs(os.path.dirname(fn), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, fn)
        if self.on_save:
            for p in (self.path, os.path.dirname(fn), fn):
                try:
                    self.on_save(p)
                except Exception:
                    pass

    def _save_index(self, did):
        if not self.path:
            return
        dev = self.devices[did]
        data = {"v": 1, "device": dev if dev.get("manual") else None,
                "last_backup": self.info[did].get("last_backup"), "versions": self.vers[did]}
        try:
            self._write(os.path.join(self._dir(did), "index.json"), json.dumps(data, ensure_ascii=False, indent=1))
        except OSError:
            pass

    def _load(self):
        try:
            names = sorted(os.listdir(self.path))
        except OSError:
            return
        for did in names:
            if not ID_RE.match(did):
                continue
            try:
                with open(os.path.join(self._dir(did), "index.json"), encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, ValueError):
                continue
            if did not in self.devices:
                if not isinstance(data.get("device"), dict):
                    continue  # συσκευή που αφαιρέθηκε από το config: κρατάμε τα αρχεία, δεν τη δείχνουμε
                dev, _ = _clean_dev({**data["device"], "id": did}, manual=True)
                if not dev:
                    continue
                self.devices[did] = dev
                self.info[did] = {"status": "never", "error": None, "last_backup": None}
            vs = [v for v in data.get("versions") or [] if isinstance(v, dict) and isinstance(v.get("ts"), int)]
            self.vers[did] = sorted(vs, key=lambda v: v["ts"])
            lb = data.get("last_backup")
            self.info[did]["last_backup"] = lb if isinstance(lb, (int, float)) else (vs[-1]["ts"] if vs else None)
            if not self.info[did].get("config_error"):
                self.info[did]["status"] = "ok" if self.vers[did] else "never"

    def _text(self, did, ts):
        if self.path is None:
            return self._mem.get(did, {}).get(ts)
        try:
            with open(os.path.join(self._dir(did), f"{int(ts)}.txt"), encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    # ───────── πυρήνας: νέα έκδοση ─────────
    def _record(self, did, raw, note=None, now=None, alert=True):
        """Καταγράφει ένα αντίγραφο. Νέα έκδοση μόνο αν άλλαξε κάτι πραγματικό. → (έκδοση ή None)."""
        now = self.clock() if now is None else now
        with self.lock:
            dev = self.devices[did]
            info = self.info[did]
            vs = self.vers.setdefault(did, [])
            norm = normalize(raw)
            sha = sha12(norm)
            info.update(last_backup=now, error=None, status="ok")
            if vs and vs[-1]["sha"] == sha:
                self._save_index(did)
                return None
            prev_raw = self._text(did, vs[-1]["ts"]) if vs else None
            prev = normalize(prev_raw) if prev_raw is not None else ""
            ts = int(now)
            if vs and ts <= vs[-1]["ts"]:
                ts = vs[-1]["ts"] + 1
            ma, mb = mask(prev).split("\n") if prev else [], mask(norm).split("\n") if norm else []
            added = removed = 0
            for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, ma, mb, autojunk=False).get_opcodes():
                if op != "equal":
                    removed += i2 - i1
                    added += j2 - j1
            found = analyze(prev, norm) if vs else []
            if not note:
                note = "Πρώτο αντίγραφο" if not vs else ("Άλλαξε μόνο κρυφή τιμή (κωδικός / κλειδί)" if not added and not removed else None)
            v = {"ts": ts, "size": len(raw.encode("utf-8", "replace")), "sha": sha, "added": added, "removed": removed,
                 "risky": [t for _, t in found], "level": "risk" if any(lv == "risk" for lv, _ in found) else ("info" if found else None),
                 "note": (str(note)[:300] if note else None)}
            if self.path is None:
                self._mem.setdefault(did, {})[ts] = raw
            else:
                try:
                    self._write(os.path.join(self._dir(did), f"{ts}.txt"), raw)
                except OSError as e:
                    info.update(status="error", error=f"Αποτυχία εγγραφής: {e}")
                    return None
            first = not vs
            vs.append(v)
            while len(vs) > self.keep:
                old = vs.pop(0)
                if self.path is None:
                    self._mem.get(did, {}).pop(old["ts"], None)
                else:
                    try:
                        os.remove(os.path.join(self._dir(did), f"{old['ts']}.txt"))
                    except OSError:
                        pass
            self._save_index(did)
        if alert and not first:
            self._alert(dev, v, found, now)
        return v

    def _alert(self, dev, v, found, now):
        try:
            sev = "med" if any(lv == "risk" for lv, _ in found) else "low"
            detail = f"+{v['added']} / −{v['removed']} γραμμές" + (" · " + "; ".join(t for _, t in found[:4]) if found else "")
            mitre = None
            if any(t.startswith("Νέος τοπικός χρήστης") for _, t in found):
                mitre = {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence",
                         "url": "https://attack.mitre.org/techniques/T1098/"}
            self.st.alert("Αλλαγή ρυθμίσεων", sev, actor=dev.get("host") or dev["id"], target=dev["name"],
                          detail=detail[:500], t=now, key="configbak:" + dev["id"], cooldown=0, mitre=mitre)
        except Exception:
            pass

    # ───────── λήψη μέσω ssh ─────────
    def _fetch(self, dev):
        check_host(dev["host"])
        argv = _as_user(ssh_argv(dev))
        try:
            r = subprocess.run(argv, capture_output=True, timeout=TIMEOUT, stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            raise RuntimeError("Δεν βρέθηκε το πρόγραμμα ssh")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Λήξη χρόνου ({TIMEOUT} s)")
        out = (r.stdout or b"")[:MAX_TEXT * 4].decode("utf-8", "replace")
        if r.returncode != 0 and not out.strip():
            err = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
            msg = err[-1] if err else f"κωδικός εξόδου {r.returncode}"
            if "Permission denied" in msg:
                msg += " — λείπει το κλειδί SSH στη συσκευή (δες ssh-copy-id / ip ssh pubkey-chain / /user ssh-keys import)"
            raise RuntimeError(msg[:300])
        if not out.strip():
            raise RuntimeError("Κενή απάντηση από τη συσκευή")
        if len(out.encode("utf-8")) > MAX_TEXT * 4:
            raise RuntimeError("Πολύ μεγάλη απάντηση")
        return out

    def _run_one(self, did):
        with self.lock:
            dev = dict(self.devices[did])
        try:
            if self.sim:
                time.sleep(DEMO_BACKUP_SECONDS)
                with self.lock:
                    self.info[did].update(status="ok", error=None, last_backup=self.clock())
                return
            if dev.get("manual"):
                raise RuntimeError("Χειροκίνητη συσκευή — επικόλλησε τις ρυθμίσεις")
            text = self._fetch(dev)
            self._record(did, text, note="Αυτόματο αντίγραφο (SSH)")
        except Exception as e:
            with self.lock:
                self.info[did].update(status="error", error=str(e)[:300] or e.__class__.__name__)

    def _runnable(self, did):
        i = self.info[did]
        return not i.get("config_error") and not self.devices[did].get("manual") and i["status"] != "running"

    # ───────── API ─────────
    def backup(self, did):
        """Αντίγραφο τώρα (μιας συσκευής ή "all") — σε νήμα· επιστρέφει αμέσως."""
        with self.lock:
            if did == "all":
                ids = [d for d in self.devices if self._runnable(d)]
            elif did in self.devices:
                i = self.info[did]
                if i.get("config_error"):
                    return {"error": i.get("error") or "Λάθος ρύθμιση συσκευής"}
                if self.devices[did].get("manual"):
                    return {"error": "Χειροκίνητη συσκευή — επικόλλησε τις ρυθμίσεις"}
                if i["status"] == "running":
                    return {"ok": True, "running": True}
                ids = [did]
            else:
                return {"error": "Άγνωστη συσκευή"}
            if not ids:
                return {"error": "Καμία συσκευή για αντίγραφο μέσω SSH"}
            for d in ids:
                self.info[d]["status"] = "running"

        def work():
            for d in ids:
                self._run_one(d)
        threading.Thread(target=work, daemon=True).start()
        return {"ok": True}

    def upload(self, did, text, note=None, name=None, vendor=None):
        """Χειροκίνητη επικόλληση (για συσκευές χωρίς SSH). Άγνωστο id + name → νέα χειροκίνητη συσκευή."""
        did = str(did or "").strip()
        if not ID_RE.match(did):
            return {"error": "Μη έγκυρο id (a-z, 0-9, _ . -, έως 40)"}
        if not isinstance(text, str) or not text.strip():
            return {"error": "Κενό κείμενο ρυθμίσεων"}
        if len(text.encode("utf-8")) > MAX_TEXT:
            return {"error": "Πολύ μεγάλο κείμενο (όριο 512 KB)"}
        if note is not None and not isinstance(note, str):
            return {"error": "Μη έγκυρη σημείωση"}
        text = text.replace("\x00", "")
        with self.lock:
            if did not in self.devices:
                if not name or not isinstance(name, str):
                    return {"error": "Άγνωστη συσκευή — δώσε και «name» για νέα χειροκίνητη συσκευή"}
                dev, _ = _clean_dev({"id": did, "name": name.strip(), "vendor": vendor}, manual=True)
                self.devices[did] = dev
                self.vers[did] = []
                self.info[did] = {"status": "never", "error": None, "last_backup": None}
        v = self._record(did, text, note=(note or "Χειροκίνητη επικόλληση").strip()[:300])
        return {"ok": True, "changed": v is not None, "ts": v["ts"] if v else None, "risky": v["risky"] if v else []}

    def view(self):
        with self.lock:
            out = []
            for did, dev in self.devices.items():
                vs, i = self.vers.get(did) or [], self.info[did]
                last = vs[-1] if vs else None
                st = i["status"]
                if st == "ok" and not vs and not i.get("last_backup"):
                    st = "never"
                out.append({"id": did, "name": dev["name"], "host": dev["host"] or None, "vendor": dev["vendor"],
                            "manual": bool(dev.get("manual")), "last_backup": i.get("last_backup"),
                            "last_change": last["ts"] if last else None, "versions": len(vs), "status": st,
                            "error": i.get("error"), "last_added": last["added"] if last else 0,
                            "last_removed": last["removed"] if last else 0,
                            "risky": list(last["risky"]) if last and len(vs) > 1 else []})
        return {"devices": out, "every_hours": self.every, "enabled": bool(self.cfg.get("enabled", True)),
                "ssh_available": shutil.which("ssh") is not None, "demo": bool(self.sim)}

    def versions(self, did):
        with self.lock:
            if did not in self.devices:
                return {"error": "Άγνωστη συσκευή"}
            vs = [{k: (list(v[k]) if k == "risky" else v.get(k)) for k in ("ts", "size", "sha", "added", "removed", "risky", "level", "note")}
                  for v in reversed(self.vers.get(did) or [])]
            return {"id": did, "name": self.devices[did]["name"], "versions": vs}

    def _pick(self, did, ts):
        vs = self.vers.get(did) or []
        if not vs:
            return None
        if ts is None:
            return len(vs) - 1
        return next((k for k, v in enumerate(vs) if v["ts"] == int(ts)), None)

    def show(self, did, ts=None):
        with self.lock:
            if did not in self.devices:
                return {"error": "Άγνωστη συσκευή"}
            k = self._pick(did, ts)
            if k is None:
                return {"error": "Δεν υπάρχει αυτή η έκδοση" if ts is not None else "Δεν υπάρχει ακόμα αντίγραφο"}
            v = self.vers[did][k]
            raw = self._text(did, v["ts"])
        if raw is None:
            return {"error": "Το αρχείο της έκδοσης λείπει"}
        return {"id": did, "ts": v["ts"], "text": mask(raw)}

    def diff(self, did, a=None, b=None):
        with self.lock:
            if did not in self.devices:
                return {"error": "Άγνωστη συσκευή"}
            kb = self._pick(did, b)
            if kb is None:
                return {"error": "Δεν υπάρχει αυτή η έκδοση" if b is not None else "Δεν υπάρχει ακόμα αντίγραφο"}
            vs = self.vers[did]
            if a is None:
                ka = kb - 1 if kb > 0 else None
            else:
                ka = self._pick(did, a)
                if ka is None:
                    return {"error": "Δεν υπάρχει αυτή η έκδοση"}
            ta, tb = (vs[ka]["ts"] if ka is not None else None), vs[kb]["ts"]
            ra = self._text(did, ta) if ta is not None else ""
            rb = self._text(did, tb)
        if ra is None or rb is None:
            return {"error": "Το αρχείο της έκδοσης λείπει"}
        na, nb = normalize(ra), normalize(rb)
        ma, mb = (mask(na).split("\n") if na else []), (mask(nb).split("\n") if nb else [])
        lines, added, removed = [], 0, 0
        for ln in list(difflib.unified_diff(ma, mb, lineterm="", n=3))[2:]:
            op = ln[:1]
            if op == "@":
                lines.append({"op": "@", "text": ln})
                continue
            if op == "+":
                added += 1
            elif op == "-":
                removed += 1
            if len(lines) < MAX_DIFF_LINES:
                lines.append({"op": op if op in "+- " else " ", "text": ln[1:]})
        found = analyze(na, nb) if ta is not None else []
        return {"id": did, "a": ta, "b": tb, "added": added, "removed": removed,
                "risky": [t for _, t in found], "truncated": len(lines) >= MAX_DIFF_LINES, "lines": lines}

    def run_forever(self):
        """Live: αντίγραφα κάθε every_hours ώρες (ελέγχει ανά λεπτό). Demo: τίποτα."""
        if self.sim or not self.cfg.get("enabled", True):
            return
        time.sleep(30)
        while True:
            now = self.clock()
            with self.lock:
                due = [d for d in self.devices if self._runnable(d) and
                       (not self.info[d].get("last_backup") or now - self.info[d]["last_backup"] >= self.every * 3600)]
                for d in due:
                    self.info[d]["status"] = "running"
            for d in due:
                self._run_one(d)
            time.sleep(60)

    # ───────── demo ─────────
    def _seed(self):
        now = self.clock()
        for dev, hist in _demo_devices(now):
            did = dev["id"]
            self.devices[did] = {**dev, "user": "backup", "port": 22, "manual": False, "command": None, "identity_file": None}
            self.vers[did] = []
            self.info[did] = {"status": "never", "error": None, "last_backup": None}
            for ago, note, text in hist:
                self._record(did, text, note=note, now=now - ago, alert=False)
            self.info[did]["last_backup"] = now - 40 * 60  # το τελευταίο (προγραμματισμένο) αντίγραφο: χωρίς αλλαγή


# ───────── demo: ρεαλιστικό ιστορικό (CCNA) ─────────
def _cisco(v, when):
    """Cisco 2960: v1 βάση, v2 VLAN 30 IoT + trunk, v3 αυστηρότερη ACL, v4 shutdown αχρησιμοποίητης θύρας,
    v5 (ύποπτο) νέος χρήστης privilege 15 + telnet στις vty."""
    trunk = "10,20" if v < 2 else "10,20,30"
    mgmt = ([" permit 192.168.1.0 0.0.0.255"] if v < 3 else [" permit host 192.168.1.10", " permit host 192.168.1.11", " deny   any log"])
    users = ["username admin privilege 15 secret 9 $9$hQx2Lm7Zp0aB3k$Yb8dV1sKq4uR0nW2eT6yZcF9gHjLmNpQrStUvWxYz.A"]
    if v >= 5:
        users.append("username backup privilege 15 secret 9 $9$Zr4T8wqP1xJm2c$Aq3sD5fG7hJ9kL1zX3cV5bN7mQ9wE1rT3yU5iO7pA.B")
    vty = "ssh" if v < 5 else "ssh telnet"
    vlans = ["vlan 10", " name LAN", "!", "vlan 20", " name GUEST", "!"]
    if v >= 2:
        vlans += ["vlan 30", " name IOT", "!"]
    fa5 = ["interface FastEthernet0/5", " description Camera-garage", " switchport access vlan " + ("30" if v >= 2 else "10"),
           " switchport mode access", " spanning-tree portfast", "!"]
    fa8 = ["interface FastEthernet0/8"] + ([" description UNUSED", " switchport access vlan 999", " shutdown"] if v >= 4 else
                                          [" switchport mode access"]) + ["!"]
    iot_acl = (["ip access-list extended IOT-IN", " permit udp any any eq domain", " permit udp any any eq ntp",
                " deny   ip any 192.168.1.0 0.0.0.255 log", " permit ip any any", "!"] if v >= 3 else [])
    lines = [
        "Building configuration...", "", f"Current configuration : {5800 + v * 310} bytes", "!",
        f"! Last configuration change at {time.strftime('%H:%M:%S UTC %a %b %d %Y', time.gmtime(when))} by admin",
        f"! NVRAM config last updated at {time.strftime('%H:%M:%S UTC %a %b %d %Y', time.gmtime(when))} by admin",
        "!", "version 15.2", "no service pad", "service timestamps debug datetime msec", "service timestamps log datetime msec",
        "service password-encryption", "!", "hostname core-sw", "!", "boot-start-marker", "boot-end-marker", "!",
        "enable secret 9 $9$nW3e5R7t9Y1u3I$5oP7aS9dF1gH3jK5lZ7xC9vB1nM3qW5eR7tY9uI1oP.C", "!"] + users + [
        "no aaa new-model", "system mtu routing 1500", "!", "ip domain-name home.lan", "ip ssh version 2", "!",
        "spanning-tree mode rapid-pvst", "spanning-tree extend system-id", "!"] + vlans + [
        "interface GigabitEthernet0/1", " description Uplink-MikroTik", " switchport trunk native vlan 10",
        " switchport trunk allowed vlan " + trunk, " switchport mode trunk", "!",
        "interface FastEthernet0/1", " description NAS", " switchport access vlan 10", " switchport mode access", " spanning-tree portfast", "!",
        "interface FastEthernet0/2", " description AP-living", " switchport trunk allowed vlan " + trunk, " switchport mode trunk", "!",
        "interface FastEthernet0/3", " description Guest-room", " switchport access vlan 20", " switchport mode access", "!"] + fa5 + fa8 + [
        "interface Vlan1", " no ip address", " shutdown", "!",
        "interface Vlan10", " ip address 192.168.1.2 255.255.255.0", " ip access-group MGMT in" if v >= 3 else " no ip route-cache", "!",
        "ip default-gateway 192.168.1.1", "no ip http server", "no ip http secure-server", "!",
        "ip access-list standard MGMT"] + mgmt + ["!"] + iot_acl + [
        "logging host 192.168.1.10", "snmp-server community N3tW4tch-R0 RO MGMT", "snmp-server location Ntoulapa-diadromou", "!",
        "line con 0", " logging synchronous", "line vty 0 4", " access-class MGMT in", " login local", " transport input " + vty,
        "line vty 5 15", " login local", " transport input ssh", "!",
        "ntp clock-period 36028797", "ntp server 192.168.1.1", "end"]
    return "\n".join(lines) + "\n"


def _mikrotik(v, when):
    """MikroTik hEX: v1 βάση, v2 VLAN 30 IoT, v3 κανόνας IoT → LAN drop, v4 (ύποπτο) dst-nat 8080 → κάμερα."""
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(when))
    L = [f"# {stamp} by RouterOS 7.16.1", "# software id = 7KQZ-H3MN", "#", "# model = RB750Gr3", "# serial number = HE20A8F3K1M",
         "/interface bridge", "add name=bridge-lan vlan-filtering=no",
         "/interface ethernet", "set [ find default-name=ether1 ] comment=WAN-ISP"]
    if v >= 2:
        L += ["/interface vlan", "add interface=bridge-lan name=vlan30-iot vlan-id=30"]
    L += ["/interface list", "add name=WAN", "add name=LAN",
          "/ip pool", "add name=dhcp-lan ranges=192.168.1.100-192.168.1.199"]
    if v >= 2:
        L += ["add name=dhcp-iot ranges=192.168.30.100-192.168.30.199"]
    L += ["/ip dhcp-server", "add address-pool=dhcp-lan interface=bridge-lan name=dhcp-lan"]
    if v >= 2:
        L += ["add address-pool=dhcp-iot interface=vlan30-iot name=dhcp-iot"]
    L += ["/interface bridge port", "add bridge=bridge-lan interface=ether2", "add bridge=bridge-lan interface=ether3",
          "add bridge=bridge-lan interface=ether4", "add bridge=bridge-lan interface=ether5",
          "/interface list member", "add interface=ether1 list=WAN", "add interface=bridge-lan list=LAN"]
    if v >= 2:
        L += ["add interface=vlan30-iot list=LAN"]
    L += ["/ip address", "add address=192.168.1.1/24 interface=bridge-lan network=192.168.1.0"]
    if v >= 2:
        L += ["add address=192.168.30.1/24 interface=vlan30-iot network=192.168.30.0"]
    L += ["/ip dhcp-client", "add interface=ether1",
          "/ip dhcp-server network", "add address=192.168.1.0/24 dns-server=192.168.1.1 gateway=192.168.1.1"]
    if v >= 2:
        L += ["add address=192.168.30.0/24 dns-server=192.168.30.1 gateway=192.168.30.1"]
    L += ["/ip dns", "set allow-remote-requests=yes servers=1.1.1.1,9.9.9.9",
          "/ip firewall filter",
          "add action=accept chain=input comment=\"established,related\" connection-state=established,related",
          "add action=drop chain=input comment=\"drop invalid\" connection-state=invalid",
          "add action=drop chain=input comment=\"drop all not from LAN\" in-interface-list=!LAN",
          "add action=fasttrack-connection chain=forward connection-state=established,related hw-offload=yes",
          "add action=accept chain=forward connection-state=established,related"]
    if v >= 3:
        L += ["add action=drop chain=forward comment=\"IoT -> LAN block\" dst-address=192.168.1.0/24 in-interface=vlan30-iot"]
    L += ["add action=drop chain=forward comment=\"drop WAN not DSTNATed\" connection-nat-state=!dstnat connection-state=new in-interface-list=WAN",
          "/ip firewall nat", "add action=masquerade chain=srcnat out-interface-list=WAN"]
    if v >= 4:
        L += ["add action=dst-nat chain=dstnat comment=camera-remote dst-port=8080 in-interface-list=WAN protocol=tcp to-addresses=192.168.30.20 to-ports=80"]
    L += ["/ip service", "set telnet disabled=yes", "set ftp disabled=yes", "set www disabled=yes", "set api disabled=yes",
          "set api-ssl disabled=yes", "set winbox address=192.168.1.0/24",
          "/snmp community", "set [ find default=yes ] addresses=192.168.1.0/24 name=hEx-m0n1t0r",
          "/snmp", "set enabled=yes trap-version=2",
          "/system clock", "set time-zone-name=Europe/Athens", "/system identity", "set name=hEX-router",
          "/system ntp client", "set enabled=yes", "/system ntp client servers", "add address=gr.pool.ntp.org"]
    return "\n".join(L) + "\n"


def _openwrt(v, when):
    """OpenWrt AP: v1 βάση, v2 κανάλι/ισχύς, v3 νέο SSID «Home-IoT» στο VLAN 30."""
    L = ["package system", "", "config system", "\toption hostname 'ap-living'", "\toption timezone 'EET-2EEST,M3.5.0/3,M10.5.0/4'",
         "\toption zonename 'Europe/Athens'", "", "package network", "", "config interface 'loopback'", "\toption device 'lo'",
         "\toption proto 'static'", "\toption ipaddr '127.0.0.1'", "\toption netmask '255.0.0.0'", "",
         "config device", "\toption name 'br-lan'", "\toption type 'bridge'", "\tlist ports 'lan1'", "",
         "config interface 'lan'", "\toption device 'br-lan'", "\toption proto 'static'", "\toption ipaddr '192.168.1.3'",
         "\toption netmask '255.255.255.0'", "\toption gateway '192.168.1.1'", "\tlist dns '192.168.1.1'", ""]
    if v >= 3:
        L += ["config interface 'iot'", "\toption device 'br-lan.30'", "\toption proto 'none'", ""]
    L += ["package wireless", "", "config wifi-device 'radio0'", "\toption type 'mac80211'", "\toption path 'platform/soc/18000000.wifi'",
          "\toption band '2g'", "\toption channel '" + ("6" if v < 2 else "11") + "'", "\toption htmode 'HE20'",
          "\toption txpower '" + ("20" if v < 2 else "17") + "'", "\toption country 'GR'", "",
          "config wifi-device 'radio1'", "\toption type 'mac80211'", "\toption band '5g'", "\toption channel '36'", "\toption htmode 'HE80'",
          "\toption country 'GR'", "",
          "config wifi-iface 'default_radio0'", "\toption device 'radio0'", "\toption network 'lan'", "\toption mode 'ap'",
          "\toption ssid 'Spiti'", "\toption encryption 'sae-mixed'", "\toption key 'Kalokairi-2024!'", "\toption ieee80211w '1'", "",
          "config wifi-iface 'default_radio1'", "\toption device 'radio1'", "\toption network 'lan'", "\toption mode 'ap'",
          "\toption ssid 'Spiti-5G'", "\toption encryption 'sae'", "\toption key 'Kalokairi-2024!'", ""]
    if v >= 3:
        L += ["config wifi-iface 'iot_radio0'", "\toption device 'radio0'", "\toption network 'iot'", "\toption mode 'ap'",
              "\toption ssid 'Home-IoT'", "\toption encryption 'psk2'", "\toption key 'iot-Th3rm0stat#7'", "\toption isolate '1'", ""]
    L += ["package dropbear", "", "config dropbear", "\toption PasswordAuth 'off'", "\toption RootPasswordAuth 'off'", "\toption Port '22'"]
    return "\n".join(L) + "\n"


def _demo_devices(now):
    D = 86400
    out = []
    for dev, fn, hist in (
        ({"id": "core-sw", "name": "Core switch (Cisco 2960)", "host": "192.168.1.2", "vendor": "cisco_ios"}, _cisco,
         [(10 * D, 1, None), (8 * D + 5 * 3600, 2, "Νέο VLAN 30 για IoT, trunk 10,20,30"),
          (5 * D + 2 * 3600, 3, "ACL MGMT μόνο για 2 υπολογιστές διαχείρισης + ACL IoT-IN"),
          (2 * D + 7 * 3600, 4, None), (3 * 3600, 5, None)]),
        ({"id": "mikrotik", "name": "Router MikroTik hEX", "host": "192.168.1.1", "vendor": "mikrotik"}, _mikrotik,
         [(10 * D - 3600, 1, None), (8 * D + 4 * 3600, 2, "VLAN 30 IoT + DHCP"), (5 * D + 3600, 3, None), (26 * 3600, 4, None)]),
        ({"id": "ap-living", "name": "AP σαλονιού (OpenWrt)", "host": "192.168.1.3", "vendor": "openwrt"}, _openwrt,
         [(9 * D + 6 * 3600, 1, None), (6 * D, 2, "Κανάλι 11 λόγω παρεμβολών από τον γείτονα"), (4 * D + 3 * 3600, 3, None)]),
    ):
        out.append((dev, [(ago, note or "Αυτόματο αντίγραφο (SSH)", fn(v, now - ago)) for ago, v, note in hist]))
    return out
