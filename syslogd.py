"""📜 Δέκτης syslog (ένα μικρό Graylog): ο router, ο Proxmox, τα ESP32 και ο broker στέλνουν εδώ τα logs τους,
το NetWatch τα κρατά στη μνήμη, τα ψάχνει και βγάζει ειδοποιήσεις από ύποπτα μηνύματα.

config.yaml (ΚΛΕΙΣΤΟ από προεπιλογή):
syslog:
  enabled: true
  bind: 0.0.0.0
  port: 5514            # όχι 514: εκείνη θέλει root. Η ίδια θύρα ακούει σε UDP και (αν tcp: true) σε TCP
  tcp: true
  allow: []             # αν δεν είναι κενό, δέχεται μόνο από αυτές τις IP / δίκτυα (π.χ. [192.168.1.1, 192.168.1.0/24])
  keep: 5000            # πόσα μηνύματα κρατά στη μνήμη (τα παλιότερα φεύγουν)
  rules:                # δικοί σου κανόνες (εκτός από τους ενσωματωμένους)
    - {name: "Backup απέτυχε", match: "backup failed", sev: med}
    - {name: "Πολλά WiFi deauth", match: 're:deauth(enticated)?', sev: low, min_count: 10, window: 300}

Πώς στέλνεις logs εδώ (NETWATCH = η IP του μηχανήματος που τρέχει το NetWatch):
- OpenWrt:   uci set system.@system[0].log_ip=NETWATCH; uci set system.@system[0].log_port=5514;
             uci set system.@system[0].log_proto=udp; uci commit system; /etc/init.d/log restart
- Proxmox / Linux (rsyslog): γράψε στο /etc/rsyslog.d/netwatch.conf
             *.* @NETWATCH:5514          (UDP — ή @@NETWATCH:5514 για TCP)
             και systemctl restart rsyslog
- Linux (systemd-journal-remote δεν χρειάζεται): ή με syslog-ng: destination d_nw { network("NETWATCH" port(5514) transport("udp")); };
- MikroTik:  /system logging action set remote remote=NETWATCH remote-port=5514; /system logging add topics=info action=remote
- Cisco:     logging host NETWATCH transport udp port 5514
- ESP32 (ESPHome): το component «syslog» με ip_address: NETWATCH και port: 5514·
             ή από δικό σου κώδικα: ένα UDP πακέτο «<14>esp32-kipos garden: μήνυμα» αρκεί.
- Δοκιμή:    python syslogd.py --send-test 127.0.0.1 5514 "γεια από το laptop"

Μορφές: RFC 3164 (BSD) και RFC 5424 (με structured data)· ό,τι δεν έχει <PRI> κρατιέται κι αυτό (user.notice).
Το TCP δέχεται και «octet counting» (RFC 6587: «123 <34>1 ...») και ένα μήνυμα ανά γραμμή.
"""
import collections
import datetime
import ipaddress
import json
import random
import re
import socket
import subprocess
import sys
import threading
import time

DEFAULTS = {"enabled": False, "bind": "0.0.0.0", "port": 5514, "tcp": True, "allow": [], "keep": 5000, "rules": []}
MSG_MAX = 2000
FRAME_MAX = 65536
MAX_HOSTS = 500
MAX_TCP_CLIENTS = 64
TCP_IDLE = 600
QUERY_BUDGET = 0.5  # × 4 = σκληρό όριο (″) για ένα ψάξιμο με regex
REGEX_MAX = 200

SEV_NAMES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
FAC_NAMES = ("kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp",
             "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7")
MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}

_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_PRI = re.compile(r"^<(\d{1,3})>")
_ISO = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,](\d{1,9}))?(Z|[+-]\d\d:?\d\d)?$")
_BSD_TS = re.compile(r"^(?:\d+:\s+)?[*.]?([A-Z][a-z]{2})\s+(\d{1,2})\s+(?:(\d{4})\s+)?(\d\d):(\d\d):(\d\d)(?:\.\d+)?(:?)(?:\s+[A-Z]{3,4}:)?\s+")
_ISO_HEAD = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)?)\s+")
_TAG = re.compile(r"^([^\s:\[\]]{1,48})(?:\[([^\]\s]{0,16})\])?:(?:\s|$)(.*)$", re.S)
_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


def clean(s, cap=MSG_MAX):
    """Χωρίς χαρακτήρες ελέγχου (escape sequences στο τερματικό / στο UI) και με όριο μήκους."""
    s = _CTRL.sub(" ", str(s or "")).strip()
    return s[:cap]


def _iso_ts(s):
    m = _ISO.match(s or "")
    if not m:
        return None
    y, mo, d, h, mi, se, frac, tz = m.groups()
    try:
        tzinfo = None
        if tz:
            if tz == "Z":
                tzinfo = datetime.timezone.utc
            else:
                tz = tz.replace(":", "")
                off = (int(tz[1:3]) * 60 + int(tz[3:5])) * (1 if tz[0] == "+" else -1)
                tzinfo = datetime.timezone(datetime.timedelta(minutes=off))
        dt = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), int((frac or "0")[:6].ljust(6, "0")), tzinfo)
        return dt.timestamp()  # χωρίς ζώνη = τοπική ώρα
    except (ValueError, OverflowError):
        return None


def _bsd_ts(mon, day, year, h, mi, se, now):
    try:
        if year:
            return datetime.datetime(int(year), MONTHS[mon], int(day), int(h), int(mi), int(se)).timestamp()
        y = datetime.datetime.fromtimestamp(now).year
        t = datetime.datetime(y, MONTHS[mon], int(day), int(h), int(mi), int(se)).timestamp()
        if t > now + 86400:  # «Dec 31» που έφτασε την 1η Ιανουαρίου
            t = datetime.datetime(y - 1, MONTHS[mon], int(day), int(h), int(mi), int(se)).timestamp()
        return t
    except (KeyError, ValueError, OverflowError):
        return None


def parse_sd(rest):
    """RFC 5424 STRUCTURED-DATA → ({sd_id: {param: τιμή}}, υπόλοιπο μήνυμα). Αν είναι χαλασμένο: ({}, όλο ως μήνυμα)."""
    if rest == "-" or rest.startswith("- "):
        return {}, rest[2:]
    if not rest.startswith("["):
        return {}, rest
    sd, i, n = {}, 0, len(rest)
    try:
        while i < n and rest[i] == "[":
            j = i + 1
            while j < n and rest[j] not in " ]":
                j += 1
            sid = rest[i + 1:j]
            if not sid or j >= n:
                raise ValueError
            params = {}
            i = j
            while rest[i] == " ":
                i += 1
                j = rest.index("=", i)
                name = rest[i:j]
                if not name or " " in name or rest[j + 1] != '"':
                    raise ValueError
                k, val = j + 2, []
                while rest[k] != '"':
                    if rest[k] == "\\" and rest[k + 1] in '"\\]':
                        k += 1
                    val.append(rest[k])
                    k += 1
                if len(params) < 32:
                    params[clean(name, 32)] = clean("".join(val), 256)
                i = k + 1
            if rest[i] != "]":
                raise ValueError
            if len(sd) < 16:
                sd[clean(sid, 64)] = params
            i += 1
    except (ValueError, IndexError):
        return {}, rest
    return sd, rest[i + 1:] if rest[i:i + 1] == " " else rest[i:]


def _tag(rec, s):
    m = _TAG.match(s)
    if m:
        rec["app"], rec["pid"], s = m.group(1), m.group(2) or "", m.group(3)
    return s


def parse(raw, src_ip="", now=None):
    """Ένα μήνυμα syslog (bytes ή str) → dict. Δεν πετά ποτέ εξαίρεση: ό,τι δεν καταλαβαίνει μπαίνει στο msg."""
    now = time.time() if now is None else now
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", "replace")
    s = str(raw).replace("\ufeff", "").strip("\r\n\x00 \t")
    rec = {"t": now, "ts": None, "host": src_ip, "src_ip": src_ip, "facility": 1, "fac_name": "user", "severity": 5,
           "sev_name": "notice", "app": "", "pid": "", "msgid": "", "msg": "", "sd": {}, "fmt": "raw"}
    m = _PRI.match(s)
    if m and int(m.group(1)) <= 191:
        pri = int(m.group(1))
        rec["facility"], rec["severity"] = pri >> 3, pri & 7
        s = s[m.end():]
        rec["fmt"] = "3164"
        if s[:2] == "1 ":
            parts = s.split(" ", 6)
            if len(parts) >= 6:
                _, ts, host, app, pid, msgid = parts[:6]
                rec.update(fmt="5424", ts=None if ts == "-" else _iso_ts(ts))
                if host != "-":
                    rec["host"] = host
                rec["app"], rec["pid"], rec["msgid"] = ("" if x == "-" else x for x in (app, pid, msgid))
                rec["sd"], s = parse_sd(parts[6] if len(parts) > 6 else "")
                s = s.replace("\ufeff", "")
                return _finish(rec, s)
    # RFC 3164 / ό,τι μοιάζει: [TIMESTAMP] [HOST] [TAG[pid]:] MSG
    has_ts = False
    m = _BSD_TS.match(s)
    if m:
        mon, day, year, h, mi, se, colon = m.groups()
        rec["ts"], has_ts, s = _bsd_ts(mon, day, year, h, mi, se, now), not colon, s[m.end():]
        if colon:  # Cisco: «*Mar  1 00:00:00.000: %SYS-5-CONFIG_I: ...» — χωρίς hostname
            return _finish(rec, _tag(rec, s))
    else:
        m = _ISO_HEAD.match(s)
        if m:
            rec["ts"], has_ts, s = _iso_ts(m.group(1)), True, s[m.end():]
    tok, _, after = s.partition(" ")
    if tok and not tok.startswith("%") and _HOSTNAME.match(tok) and not _TAG.match(s) and (has_ts or _TAG.match(after)):
        rec["host"], s = tok, after
    return _finish(rec, _tag(rec, s))


def _finish(rec, msg):
    rec["msg"] = clean(msg)
    rec["host"] = clean(rec["host"], 64) or rec["src_ip"]
    rec["app"], rec["pid"], rec["msgid"] = clean(rec["app"], 48), clean(rec["pid"], 16), clean(rec["msgid"], 32)
    rec["fac_name"] = FAC_NAMES[rec["facility"]] if rec["facility"] < len(FAC_NAMES) else str(rec["facility"])
    rec["sev_name"] = SEV_NAMES[rec["severity"]]
    return rec


# ---------- ασφαλές regex (το re της Python δεν έχει timeout) ----------
_NESTED = re.compile(r"\((?:[^()\\]|\\.)*[+*}]\)\??[+*{]")


def safe_regex(pat):
    """Μεταγλωττίζει regex χρήστη με όρια: μήκος, όχι εμφωλευμένους ποσοδείκτες «(a+)+» (catastrophic backtracking),
    όχι backreferences. ValueError με ελληνικό μήνυμα αν δεν περνά."""
    pat = str(pat or "")
    if not pat or len(pat) > REGEX_MAX:
        raise ValueError(f"Το regex πρέπει να έχει 1–{REGEX_MAX} χαρακτήρες.")
    if _NESTED.search(pat) or re.search(r"\\\d|\(\?P=", pat):
        raise ValueError("Το regex έχει εμφωλευμένους ποσοδείκτες ή backreferences — απλοποίησέ το.")
    try:
        return re.compile(pat, re.I)
    except re.error as e:
        raise ValueError(f"Μη έγκυρο regex: {e}")


def matcher(spec):
    """«κείμενο» → αναζήτηση υποσυμβολοσειράς (χωρίς πεζά/κεφαλαία)· «re:...» → regex. Επιστρέφει f(text)->bool."""
    spec = str(spec or "")
    if spec.startswith("re:"):
        rx = safe_regex(spec[3:])
        return lambda text: rx.search(text) is not None
    if not spec:
        raise ValueError("Κενό κριτήριο.")
    low = spec.lower()[:REGEX_MAX]
    return lambda text: low in text.lower()


_RX_WORKER = (
    "import sys,json,re\n"
    "d=json.load(sys.stdin)\n"
    "rx=re.compile(d['p'],re.I)\n"
    "o=[]\n"
    "for i,t in enumerate(d['t']):\n"
    "    if rx.search(t):\n"
    "        o.append(i)\n"
    "        if len(o)>=d['n']: break\n"
    "json.dump(o,sys.stdout)\n")


def regex_filter(pattern, texts, limit=200, timeout=QUERY_BUDGET * 4):
    """Ποια κείμενα ταιριάζουν (δείκτες, με τη σειρά τους), με σκληρό όριο χρόνου: το regex τρέχει σε παιδί-διεργασία
    που σκοτώνεται αν αργήσει — έτσι ένα «κακό» regex (π.χ. a*a*a*b) δεν παγώνει το NetWatch."""
    try:
        p = subprocess.run([sys.executable, "-I", "-S", "-c", _RX_WORKER], capture_output=True, timeout=timeout,
                           input=json.dumps({"p": pattern, "t": texts, "n": int(limit)}).encode())
    except subprocess.TimeoutExpired:
        raise ValueError(f"Το regex άργησε πάνω από {timeout:g}″ — απλοποίησέ το.")
    if p.returncode != 0:
        raise ValueError("Μη έγκυρο regex.")
    try:
        return [i for i in json.loads(p.stdout or b"[]") if isinstance(i, int) and 0 <= i < len(texts)]
    except ValueError:
        raise ValueError("Μη έγκυρο regex.")


# ---------- ενσωματωμένοι κανόνες ----------
_RHOST = re.compile(r"(?:rhost=|\bfrom\s+|rip=|\bsrc=)(?:::ffff:)?([0-9a-fA-F.:]{3,45}[0-9a-fA-F])")

BUILTIN = [
    {"id": "failed_login", "type": "Αποτυχημένες συνδέσεις (syslog)", "sev": "high", "min_count": 5, "window": 120,
     "cooldown": 600, "group": "rhost", "mark": True,
     "rx": re.compile(r"failed password|authentication failure|invalid user|failed login|login failed", re.I)},
    {"id": "link_down", "type": "Σύνδεση έπεσε (syslog)", "sev": "med", "min_count": 1, "window": 60, "cooldown": 300,
     "group": "host", "rx": re.compile(r"\blink (?:is )?down\b|carrier lost|\bcarrier: ?off\b|\bno carrier\b", re.I)},
    {"id": "dhcp_exhausted", "type": "DHCP χωρίς διευθύνσεις", "sev": "med", "min_count": 1, "window": 60, "cooldown": 1800,
     "group": "host", "rx": re.compile(r"no free leases|pool exhausted|no address available", re.I)},
    {"id": "system_error", "type": "Σφάλμα συστήματος (syslog)", "sev": "low", "min_count": 1, "window": 60, "cooldown": 1800,
     "group": "host", "rx": re.compile(r"out of memory|oom-killer|oom_reaper|invoked oom|segfault|kernel panic", re.I)},
    {"id": "config_change", "type": "Αλλαγή ρυθμίσεων συσκευής", "sev": "low", "min_count": 1, "window": 60, "cooldown": 600,
     "group": "host", "rx": re.compile(r"configured from console|config(?:uration)? changed|%SYS-5-CONFIG_I", re.I)},
]


def _detail(rule, rec, key, n):
    host, sample = rec["host"], rec["msg"][:160]
    rid = rule["id"]
    if rid == "failed_login":
        return (f"{n} αποτυχημένες προσπάθειες σύνδεσης από {key} προς «{host}» μέσα σε {rule['window'] // 60}′ "
                f"(π.χ. «{sample}»). Αν δεν είσαι εσύ, κάποιος δοκιμάζει κωδικούς: μπλόκαρέ τον και έλεγξε ποιος έχει πρόσβαση.")
    if rid == "link_down":
        return f"Η συσκευή «{host}» ανέφερε πτώση σύνδεσης: «{sample}»."
    if rid == "dhcp_exhausted":
        return (f"Ο DHCP server στο «{host}» δεν έχει ελεύθερες διευθύνσεις: «{sample}». Νέες συσκευές δεν θα πάρουν IP — "
                "μεγάλωσε το pool ή μίκρυνε τον χρόνο μίσθωσης.")
    if rid == "system_error":
        return f"Σφάλμα συστήματος στο «{host}»{' (' + rec['app'] + ')' if rec['app'] else ''}: «{sample}»."
    if rid == "config_change":
        return f"Άλλαξαν οι ρυθμίσεις της συσκευής «{host}»: «{sample}». Αν δεν το έκανες εσύ, έλεγξε ποιος έχει πρόσβαση."
    return f"Κανόνας «{rule['type']}»: {n} μήνυμα(τα) από «{host}» μέσα σε {rule['window']}″ (π.χ. «{sample}»)."


def _capped(fn, cap=512):
    # οι κανόνες τρέχουν σε κάθε μήνυμα (που το στέλνει οποιοσδήποτε): το regex βλέπει μόνο τους πρώτους 512 χαρακτήρες
    return lambda text: fn(text[:cap])


def user_rules(cfg_rules):
    """Κανόνες από το config: {name, match, sev, min_count, window, cooldown}. Οι άκυροι αγνοούνται (με λόγο)."""
    out, errors = [], []
    for i, r in enumerate(cfg_rules or []):
        try:
            if not isinstance(r, dict) or not r.get("name") or not r.get("match"):
                raise ValueError("θέλει name και match")
            sev = str(r.get("sev") or "med")
            if sev not in ("low", "med", "high"):
                raise ValueError("sev: low / med / high")
            out.append({"id": f"user{i}", "type": clean(r["name"], 60), "sev": sev, "fn": _capped(matcher(r["match"])),
                        "min_count": max(1, min(int(r.get("min_count") or 1), 10000)),
                        "window": max(1, min(int(r.get("window") or 60), 86400)),
                        "cooldown": max(0, min(int(r.get("cooldown") if r.get("cooldown") is not None else 300), 86400)),
                        "group": "host", "match": str(r["match"])[:REGEX_MAX]})
        except (ValueError, TypeError) as e:
            errors.append(f"Κανόνας syslog #{i + 1}: {e}")
    return out, errors


def normalize_cfg(cfg):
    c = dict(DEFAULTS)
    c.update({k: v for k, v in (cfg or {}).items() if v is not None})
    c["port"] = int(c["port"])
    c["keep"] = max(100, min(int(c["keep"]), 200000))
    nets = []
    for a in c.get("allow") or []:
        try:
            nets.append(ipaddress.ip_network(str(a), strict=False))
        except ValueError:
            pass
    c["_allow"] = nets
    return c


class Syslogd:
    def __init__(self, state=None, cfg=None, sim=False):
        self.state, self.sim = state, sim
        self.cfg = normalize_cfg(cfg)
        self.lock = threading.Lock()
        self.ring = collections.deque(maxlen=self.cfg["keep"])
        self.hosts = collections.OrderedDict()
        self.by_sev = [0] * 8
        self.total = self.dropped = self.denied = self.seq = 0
        self.rules = [dict(r) for r in BUILTIN]
        urules, self.errors = user_rules(self.cfg.get("rules"))
        self.rules += urules
        for r in self.rules:
            r["hits"], r["last"] = 0, None
        self.windows = {}       # (rule id, key) → deque χρόνων
        self.fired = {}         # (rule id, key) → τελευταία ειδοποίηση (cooldown)
        self.hits = collections.deque(maxlen=100)
        self.socks, self.udp_port, self.tcp_port = [], None, None
        self.clients = 0
        self._stop = threading.Event()

    # ---------- είσοδος ----------
    def allowed(self, ip):
        nets = self.cfg["_allow"]
        if not nets:
            return True
        try:
            a = ipaddress.ip_address(ip)
            if getattr(a, "ipv4_mapped", None):
                a = a.ipv4_mapped
        except ValueError:
            return False
        return any(a in n for n in nets if n.version == a.version)

    def ingest(self, raw, src_ip="", now=None):
        """Ένα μήνυμα → ring + μετρητές + κανόνες. Επιστρέφει το record (ή None αν απορρίφθηκε από το allow-list)."""
        now = time.time() if now is None else now
        if not self.allowed(src_ip):
            with self.lock:
                self.denied += 1
            return None
        rec = parse(raw, src_ip, now)
        with self.lock:
            self.seq += 1
            self.total += 1
            rec["id"] = self.seq
            self.ring.append(rec)
            self.by_sev[rec["severity"]] += 1
            h = self.hosts.pop(rec["host"], None) or {"host": rec["host"], "src_ip": src_ip, "count": 0, "first": now,
                                                     "worst": 7, "by_sev": [0] * 8}
            h["count"] += 1
            h["last"], h["src_ip"] = now, src_ip or h["src_ip"]
            h["worst"] = min(h["worst"], rec["severity"])
            h["by_sev"][rec["severity"]] += 1
            self.hosts[rec["host"]] = h  # στο τέλος = πιο πρόσφατο
            while len(self.hosts) > MAX_HOSTS:
                self.hosts.popitem(last=False)
            fire = self._rules(rec, now)
        for rule, key, n in fire:
            self._alert(rule, rec, key, n, now)
        return rec

    def _rules(self, rec, now):
        text = f"{rec['app']}: {rec['msg']}" if rec["app"] else rec["msg"]
        out = []
        for r in self.rules:
            hit = r["rx"].search(text) is not None if "rx" in r else r["fn"](text)
            if not hit:
                continue
            key = rec["host"]
            if r["group"] == "rhost":
                m = _RHOST.search(rec["msg"])
                key = m.group(1) if m else rec["host"]
            wk = (r["id"], key)
            dq = self.windows.get(wk)
            if dq is None:
                if len(self.windows) > 5000:
                    self._gc(now)
                dq = self.windows[wk] = collections.deque(maxlen=max(r["min_count"], 1) * 4)
            dq.append(now)
            while dq and now - dq[0] > r["window"]:
                dq.popleft()
            if len(dq) < r["min_count"]:
                continue
            last = self.fired.get(wk)
            if last is not None and now - last < r["cooldown"]:
                continue
            self.fired[wk] = now
            r["hits"] += 1
            r["last"] = now
            self.hits.appendleft({"t": now, "rule": r["id"], "type": r["type"], "sev": r["sev"], "key": key,
                                  "host": rec["host"], "src_ip": rec["src_ip"], "count": len(dq), "msg": rec["msg"][:200]})
            out.append((r, key, len(dq)))
        return out

    def _gc(self, now):
        for wk in [k for k, dq in self.windows.items() if not dq or now - dq[-1] > 86400]:
            self.windows.pop(wk, None)
        for wk in [k for k, t in self.fired.items() if now - t > 86400]:
            self.fired.pop(wk, None)

    def _alert(self, rule, rec, key, n, now):
        if not self.state:
            return
        actor = key if rule["group"] == "rhost" else (rec["src_ip"] or rec["host"])
        try:
            self.state.alert(rule["type"], rule["sev"], actor, rec["host"], _detail(rule, rec, key, n), now,
                             key=(rule["type"], key), cooldown=rule["cooldown"], mark=bool(rule.get("mark")))
        except Exception:
            pass

    # ---------- αναζήτηση / κατάσταση ----------
    def query(self, q=None, host=None, sev_max=None, since=None, limit=200):
        """Νεότερα πρώτα. q: υποσυμβολοσειρά (χωρίς πεζά/κεφαλαία) ή «re:regex».
        Το regex τρέχει σε ξεχωριστή διεργασία με όριο χρόνου (το re της Python δεν σταματά μόνο του)·
        ValueError (ελληνικό μήνυμα) αν δεν είναι ασφαλές/έγκυρο ή αν άργησε."""
        rx = None
        if q and str(q).startswith("re:"):
            rx = safe_regex(str(q)[3:]).pattern
            fn = None
        else:
            fn = matcher(q) if q else None
        host = str(host).lower() if host else None
        limit = max(1, min(int(limit or 200), 2000))
        with self.lock:
            items = list(self.ring)
        out = []
        for r in reversed(items):
            if since is not None and r["t"] < since:
                break  # το ring είναι σε σειρά άφιξης
            if host and host not in (r["host"].lower(), r["src_ip"].lower()):
                continue
            if sev_max is not None and r["severity"] > int(sev_max):
                continue
            if fn and not fn(f"{r['host']} {r['app']} {r['msg']}"):
                continue
            out.append(r)
            if not rx and len(out) >= limit:
                break
        if rx and out:
            idx = regex_filter(rx, [f"{r['host']} {r['app']} {r['msg']}" for r in out], limit)
            out = [out[i] for i in idx]
        return out

    def status(self, recent=50, now=None):
        now = time.time() if now is None else now
        with self.lock:
            items = list(self.ring)
            hosts = sorted(({**h, "worst_name": SEV_NAMES[h["worst"]],
                             "by_sev": dict(zip(SEV_NAMES, h["by_sev"]))} for h in self.hosts.values()),
                           key=lambda h: -h["last"])
            st = {"enabled": bool(self.cfg["enabled"]) or self.sim, "demo": self.sim,
                  "listen": {"bind": self.cfg["bind"], "udp": self.udp_port, "tcp": self.tcp_port},
                  "total": self.total, "kept": len(items), "keep": self.cfg["keep"], "denied": self.denied,
                  "dropped": self.dropped, "by_sev": dict(zip(SEV_NAMES, self.by_sev)),
                  "rate_1m": sum(1 for r in items[-5000:] if now - r["t"] <= 60),
                  "hosts": hosts,
                  "recent": list(reversed(items[-recent:])) if recent else [],
                  "rules": [{"id": r["id"], "type": r["type"], "sev": r["sev"], "min_count": r["min_count"],
                             "window": r["window"], "hits": r["hits"], "last": r["last"], "builtin": "rx" in r}
                            for r in self.rules],
                  "hits": list(self.hits)[:50], "errors": list(self.errors)}
        return st

    # ---------- δίκτυο ----------
    def start(self):
        """Ανοίγει UDP (+TCP) sockets και νήματα. Επιστρέφει (udp_port, tcp_port)."""
        b, p = self.cfg["bind"], self.cfg["port"]
        fam = socket.AF_INET6 if ":" in b else socket.AF_INET
        u = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            u.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        except OSError:
            pass
        u.bind((b, p))
        self.udp_port = u.getsockname()[1]
        self.socks.append(u)
        threading.Thread(target=self._udp_loop, args=(u,), daemon=True, name="syslog-udp").start()
        if self.cfg["tcp"]:
            t = socket.socket(fam, socket.SOCK_STREAM)
            t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            t.bind((b, p if p else 0))
            t.listen(16)
            self.tcp_port = t.getsockname()[1]
            self.socks.append(t)
            threading.Thread(target=self._tcp_accept, args=(t,), daemon=True, name="syslog-tcp").start()
        return self.udp_port, self.tcp_port

    def stop(self):
        self._stop.set()
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass
        self.socks = []

    def _udp_loop(self, u):
        while not self._stop.is_set():
            try:
                data, addr = u.recvfrom(FRAME_MAX)
            except OSError:
                return
            try:
                self.ingest(data, addr[0])
            except Exception:
                self.dropped += 1

    def _tcp_accept(self, t):
        while not self._stop.is_set():
            try:
                c, addr = t.accept()
            except OSError:
                return
            if not self.allowed(addr[0]) or self.clients >= MAX_TCP_CLIENTS:
                with self.lock:
                    self.denied += 1
                c.close()
                continue
            with self.lock:
                self.clients += 1
            threading.Thread(target=self._tcp_client, args=(c, addr[0]), daemon=True).start()

    def _tcp_client(self, c, ip):
        buf = b""
        try:
            c.settimeout(TCP_IDLE)
            while not self._stop.is_set():
                data = c.recv(65536)
                if not data:
                    break
                buf += data
                frames, buf = split_frames(buf)
                for f in frames:
                    self.ingest(f, ip)
                if len(buf) > FRAME_MAX:  # τεράστια «γραμμή» χωρίς τέλος — την κόβουμε
                    self.ingest(buf[:FRAME_MAX], ip)
                    buf = b""
            if buf.strip():
                self.ingest(buf, ip)
        except (OSError, socket.timeout):
            pass
        finally:
            with self.lock:
                self.clients -= 1
            c.close()

    # ---------- demo ----------
    def demo_tick(self, now=None, burst=False, flap=False):
        now = time.time() if now is None else now
        for raw, ip in demo_messages(now, burst=burst, flap=flap):
            self.ingest(raw, ip, now)

    def run_forever(self, every=2):
        if self.sim:
            t0 = time.time()
            for k in range(60, 0, -1):  # λίγο «ιστορικό» για να μην είναι άδεια η οθόνη
                self.demo_tick(t0 - k * 30, burst=(k == 20), flap=(k == 40))
            n = 0
            while not self._stop.is_set():
                n += 1
                try:
                    self.demo_tick(burst=(n % 450 == 0), flap=(n % 300 == 150))
                except Exception:
                    pass
                time.sleep(every)
            return
        try:
            self.start()
        except OSError as e:
            self.errors.append(f"Δεν άνοιξε η θύρα syslog {self.cfg['bind']}:{self.cfg['port']}: {e}")
            return
        self._stop.wait()


def split_frames(buf):
    """TCP syslog (RFC 6587): «ΜΗΚΟΣ SP μήνυμα» (octet counting) ή ένα μήνυμα ανά γραμμή (\\n ή \\0).
    Επιστρέφει (πλήρη μηνύματα, ό,τι περίσσεψε)."""
    out = []
    while buf:
        m = re.match(rb"(\d{1,6}) ", buf)
        if m:
            n = int(m.group(1))
            if n > FRAME_MAX:  # παράλογο μήκος: σαν γραμμή
                m = None
            elif len(buf) < m.end() + n:
                break
            else:
                out.append(buf[m.end():m.end() + n])
                buf = buf[m.end() + n:].lstrip(b"\r\n")
                continue
        i = min((x for x in (buf.find(b"\n"), buf.find(b"\0")) if x >= 0), default=-1)
        if i < 0:
            break
        line = buf[:i].rstrip(b"\r")
        if line.strip():
            out.append(line)
        buf = buf[i + 1:]
    return out, buf


def _bsd(now):
    d = datetime.datetime.fromtimestamp(now)
    return f"{d.strftime('%b')} {d.day:>2} {d.strftime('%H:%M:%S')}"


def _iso(now):
    return datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def demo_messages(now, burst=False, flap=False):
    """Ρεαλιστικά μηνύματα από router (OpenWrt), Proxmox, ESP32 και Mosquitto — ως ακατέργαστο syslog, για να
    περνούν από τον ίδιο parser."""
    r = random.Random(int(now * 1000))
    ts, iso = _bsd(now), _iso(now)
    out = []
    macs = ["a4:cf:12:8e:31:07", "3c:22:fb:91:aa:10", "dc:a6:32:4b:1e:9f", "b8:27:eb:12:7c:44"]
    names = ["esp32-kipos", "iphone-maria", "raspberrypi", "tv-saloni"]
    k = r.randrange(len(macs))
    pool = [
        (f"<30>{ts} router dnsmasq-dhcp[1873]: DHCPREQUEST(br-lan) 192.168.1.{120 + k} {macs[k]}", "192.168.1.1"),
        (f"<30>{ts} router dnsmasq-dhcp[1873]: DHCPACK(br-lan) 192.168.1.{120 + k} {macs[k]} {names[k]}", "192.168.1.1"),
        (f"<30>{ts} router hostapd: wlan0: STA {macs[k]} IEEE 802.11: associated (aid {r.randint(1, 9)})", "192.168.1.1"),
        (f"<30>{ts} router hostapd: wlan0: STA {macs[k]} WPA: pairwise key handshake completed (RSN)", "192.168.1.1"),
        (f"<29>{ts} router dnsmasq[1873]: query[A] time.google.com from 192.168.1.{120 + k}", "192.168.1.1"),
        (f"<86>{ts} pve pvedaemon[2211]: <root@pam> successful auth for user 'root@pam'", "192.168.1.16"),
        (f"<78>{ts} pve CRON[{r.randint(30000, 39999)}]: (root) CMD (/usr/sbin/pve-daily-update)", "192.168.1.16"),
        (f"<30>{ts} pve pveproxy[{r.randint(1000, 9999)}]: worker {r.randint(1000, 9999)} started", "192.168.1.16"),
        (f'<134>1 {iso} esp32-kipos garden - telemetry [meta@32473 fw="1.4.2" rssi="-{r.randint(55, 78)}"] '
         f"soil={r.randint(30, 60)}% temp={r.uniform(14, 24):.1f}C", "192.168.1.20"),
        (f"<30>{ts} mqtt mosquitto[811]: New client connected from 192.168.1.30:{r.randint(40000, 60000)} "
         f"as homeassistant (p2, c1, k60, u'ha').", "192.168.1.17"),
        (f"<30>{ts} mqtt mosquitto[811]: New connection from 192.168.1.20:{r.randint(40000, 60000)} on port 1883.", "192.168.1.17"),
    ]
    out += r.sample(pool, r.randint(1, 3))
    if r.random() < 0.04:
        out.append((f'<132>1 {iso} esp32-kipos garden - wifi [meta@32473 fw="1.4.2"] WiFi reconnect (reason 201)',
                    "192.168.1.20"))
    if flap:
        out.append((f"<27>{ts} router kernel: [{r.randint(100000, 999999)}.123456] eth0.2: Link is Down", "192.168.1.1"))
        out.append((f"<30>{ts} router netifd: Interface 'wan' has link connectivity loss", "192.168.1.1"))
        out.append((f"<30>{ts} router kernel: [{r.randint(100000, 999999)}.654321] eth0.2: Link is Up - 1Gbps/Full", "192.168.1.1"))
    if burst:
        for _ in range(6):
            out.append((f"<85>{ts} pve pvedaemon[2211]: authentication failure; rhost=::ffff:192.168.1.66 "
                        f"user={r.choice(['root@pam', 'admin@pve', 'test@pam'])} msg=Authentication failure", "192.168.1.16"))
    return out


def send_test(host, port, msg, tcp=False):
    """Στέλνει ένα μήνυμα RFC 5424 (UDP ή TCP με octet counting) — για να δοκιμάσεις ότι φτάνουν τα logs."""
    data = f"<13>1 {_iso(time.time())} {socket.gethostname()[:63] or '-'} netwatch-test {__import__('os').getpid()} - - {msg}".encode()
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    if tcp:
        with socket.create_connection((host, int(port)), timeout=5) as s:
            s.sendall(f"{len(data)} ".encode() + data)
    else:
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.sendto(data, (host, int(port)))
    return data


def main(argv):
    if len(argv) >= 4 and argv[0] == "--send-test":
        tcp = "--tcp" in argv
        args = [a for a in argv[1:] if a != "--tcp"]
        send_test(args[0], int(args[1]), " ".join(args[2:]), tcp=tcp)
        print(f"Στάλθηκε στο {args[0]}:{args[1]} ({'TCP' if tcp else 'UDP'}).")
        return 0
    if argv and argv[0] == "--listen":
        port = int(argv[1]) if len(argv) > 1 else DEFAULTS["port"]
        d = Syslogd(None, {"enabled": True, "port": port})
        u, t = d.start()
        print(f"Ακούω syslog σε UDP {u} και TCP {t} (Ctrl+C για έξοδο)…")
        last = 0
        try:
            while True:
                time.sleep(0.5)
                for r in [x for x in list(d.ring) if x["id"] > last]:
                    last = r["id"]
                    print(f"{r['src_ip']:<15} {r['host']:<16} {r['sev_name']:<7} {r['app'] or '-':<14} {r['msg']}")
        except KeyboardInterrupt:
            return 0
    print("Χρήση: python syslogd.py --send-test ΔΙΕΥΘΥΝΣΗ ΘΥΡΑ \"μήνυμα\" [--tcp]\n"
          "       python syslogd.py --listen [ΘΥΡΑ]")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
