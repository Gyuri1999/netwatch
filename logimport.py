"""📥 Εισαγωγή logs από Suricata (eve.json) και Zeek: οι ειδοποιήσεις τους εμφανίζονται μαζί με του NetWatch.

config.yaml:
log_import:
  enabled: true
  interval: 10              # δευτερόλεπτα ανάμεσα στους ελέγχους των αρχείων
  files:
    - {path: /var/log/suricata/eve.json, type: eve}
    - {path: /opt/zeek/logs/current/notice.log, type: zeek}
    - {path: /opt/zeek/logs/current/conn.log, type: zeek, follow: true}
follow: true (προεπιλογή) = σαν το «tail -f»: ξεκινάμε από το τέλος του αρχείου και διαβάζουμε ό,τι γράφεται μετά.
follow: false = διαβάζουμε όλο το αρχείο μία φορά από την αρχή (και μετά ό,τι προστεθεί).
Θυμόμαστε inode + θέση· αν το αρχείο περιστραφεί (logrotate: νέο inode) διαβάζουμε το νέο από την αρχή,
αν κοπεί (truncate: μικρότερο μέγεθος) ξαναρχίζουμε από το 0.

Suricata: event_type "alert" → ειδοποίηση «Suricata: <signature>» (severity 1 → high, 2 → med, 3+ → low)·
τα υπόλοιπα event types (dns, http, tls, flow, …) μόνο μετρώνται.
Zeek: TSV (με κεφαλίδα #fields) ή JSON (ένα αντικείμενο ανά γραμμή)· notice.log → «Zeek: <note>» (med),
weird.log → «Zeek: <name>» (low), conn.log → top talkers.
Εφάπαξ ανέβασμα αρχείου (έως 20 MB): import_text(text, kind).
"""
import collections
import datetime
import json
import os
import random
import re
import threading
import time

MAX_UPLOAD = 20 * 1024 * 1024
MAX_READ = 4 * 1024 * 1024       # το πολύ τόσα bytes ανά αρχείο σε κάθε έλεγχο (τα υπόλοιπα στον επόμενο)
MAX_LINE = 256 * 1024
MAX_FORWARD = 500                # το πολύ τόσες ειδοποιήσεις προωθούνται στο NetWatch από ένα ανέβασμα
RECENT = 100
COOLDOWN = 300
TYPES = ("eve", "zeek")
ZEEK_ALERT_LOGS = {"notice": "med", "weird": "low"}


def _s(v, n=200):
    if v is None:
        return None
    return str(v).replace("\n", " ").replace("\r", " ")[:n]


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")


def parse_ts(v, default=None):
    """ISO8601 της Suricata («2024-03-01T10:20:30.123456+0200») ή epoch του Zeek → epoch (float)."""
    if v is None or v == "":
        return default
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    try:
        return float(s)
    except ValueError:
        pass
    m = _ISO.match(s)
    if not m:
        return default
    frac = float(m.group(3)) if m.group(3) else 0.0
    tz = m.group(4)
    try:
        dt = datetime.datetime.strptime(f"{m.group(1)}T{m.group(2)}", "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return default
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        off = datetime.timezone(sign * datetime.timedelta(hours=hh, minutes=mm))
    elif tz == "Z":
        off = datetime.timezone.utc
    else:
        off = None  # χωρίς ζώνη: τοπική ώρα
    dt = dt.replace(tzinfo=off) if off else dt
    return dt.timestamp() + frac


def eve_sev(v):
    n = _int(v)
    if n == 1:
        return "high"
    if n == 2:
        return "med"
    return "low"


# ───────────────────────────── Suricata ─────────────────────────────

def eve_alert(ev):
    """Ένα event της Suricata με event_type=alert → ειδοποίηση (dict)."""
    a = ev.get("alert") if isinstance(ev.get("alert"), dict) else {}
    sig = _s(a.get("signature"), 160) or "(χωρίς υπογραφή)"
    return {"source": "suricata", "t": parse_ts(ev.get("timestamp"), time.time()), "src": _s(ev.get("src_ip"), 64),
            "dst": _s(ev.get("dest_ip"), 64), "sp": _int(ev.get("src_port")), "dp": _int(ev.get("dest_port")),
            "proto": _s(ev.get("proto"), 16), "signature": sig, "category": _s(a.get("category"), 120) or "",
            "severity": _int(a.get("severity")), "sev": eve_sev(a.get("severity")), "sid": _int(a.get("signature_id")),
            "action": _s(a.get("action"), 16), "app_proto": _s(ev.get("app_proto"), 32)}


def parse_eve(lines):
    """Γραμμές eve.json → {"alerts": [...], "counts": {event_type: πλήθος}, "errors": άκυρες γραμμές}."""
    alerts, counts, errors = [], collections.Counter(), 0
    for line in lines:
        if isinstance(line, bytes):
            line = line.decode("utf-8", "replace")
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            errors += 1
            continue
        if not isinstance(ev, dict):
            errors += 1
            continue
        et = _s(ev.get("event_type"), 32) or "unknown"
        counts[et] += 1
        if et == "alert":
            alerts.append(eve_alert(ev))
    return {"alerts": alerts, "counts": dict(counts), "errors": errors}


# ───────────────────────────── Zeek ─────────────────────────────

def _zeek_path_guess(rec):
    """Zeek JSON χωρίς «_path»: μαντεύουμε το log από τα πεδία."""
    if "note" in rec:
        return "notice"
    if "conn_state" in rec or ("orig_bytes" in rec and "resp_bytes" in rec):
        return "conn"
    if "query" in rec and ("qtype_name" in rec or "rcode" in rec or "answers" in rec):
        return "dns"
    if "name" in rec and "uid" in rec and ("notice" in rec or "addl" in rec or "peer" in rec):
        return "weird"
    if "server_name" in rec or "cipher" in rec:
        return "ssl"
    if "name" in rec and "addl" in rec:
        return "weird"
    return "unknown"


class ZeekParser:
    """Κρατά την κατάσταση της κεφαλίδας (#separator, #fields, #path) — χρήσιμο στο tail ενός TSV log."""

    def __init__(self, path_hint=None):
        self.sep, self.fields, self.path = "\t", None, None
        self.unset, self.empty = "-", "(empty)"
        self.hint = path_hint

    def feed(self, line):
        """Μία γραμμή → (log, εγγραφή dict) ή None (κεφαλίδα/σχόλιο/άκυρη)."""
        if isinstance(line, bytes):
            line = line.decode("utf-8", "replace")
        line = line.rstrip("\r\n")
        if not line.strip():
            return None
        if line.lstrip().startswith("{"):
            try:
                rec = json.loads(line)
            except ValueError:
                return ("error", None)
            if not isinstance(rec, dict):
                return ("error", None)
            path = _s(rec.get("_path"), 32) or self.hint or _zeek_path_guess(rec)
            return (path, rec)
        if line.startswith("#"):
            if line.startswith("#separator"):
                v = line[len("#separator"):].strip()
                try:
                    self.sep = v.encode().decode("unicode_escape") if v else "\t"
                except Exception:
                    self.sep = "\t"
            else:
                parts = line.split(self.sep)
                k = parts[0]
                if k == "#fields":
                    self.fields = parts[1:]
                elif k == "#path" and len(parts) > 1:
                    self.path = parts[1].strip()
                elif k == "#unset_field" and len(parts) > 1:
                    self.unset = parts[1]
                elif k == "#empty_field" and len(parts) > 1:
                    self.empty = parts[1]
            return None
        if not self.fields:
            return ("error", None)
        vals = line.split(self.sep)
        rec = {}
        for k, v in zip(self.fields, vals):
            if v == self.unset:
                v = None
            elif v == self.empty:
                v = ""
            rec[k] = v
        return (self.path or self.hint or _zeek_path_guess(rec), rec)


def _zf(rec, *keys):
    """Πεδίο Zeek είτε σε επίπεδη μορφή («id.orig_h») είτε φωλιασμένο ({"id": {"orig_h": …}})."""
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
        if "." in k:
            a, b = k.split(".", 1)
            d = rec.get(a)
            if isinstance(d, dict) and d.get(b) not in (None, ""):
                return d[b]
    return None


def zeek_alert(path, rec):
    sev = ZEEK_ALERT_LOGS[path]
    if path == "notice":
        name = _s(rec.get("note"), 120) or "Notice"
        msg = _s(rec.get("msg"), 300) or ""
        sub = _s(rec.get("sub"), 200)
    else:
        name = _s(rec.get("name"), 120) or "weird"
        msg = _s(rec.get("addl"), 300) or ""
        sub = None
    src = _zf(rec, "src", "id.orig_h")
    dst = _zf(rec, "dst", "id.resp_h")
    return {"source": "zeek", "log": path, "t": parse_ts(rec.get("ts"), time.time()), "src": _s(src, 64), "dst": _s(dst, 64),
            "sp": _int(_zf(rec, "id.orig_p")), "dp": _int(_zf(rec, "p", "id.resp_p")), "proto": _s(_zf(rec, "proto"), 16),
            "signature": name, "category": path, "msg": msg, "sub": sub, "sev": sev, "uid": _s(rec.get("uid"), 40)}


class _Talkers:
    def __init__(self):
        self.d = {}

    def add(self, rec):
        ip = _zf(rec, "id.orig_h")
        if not ip:
            return
        b = (_int(_zf(rec, "orig_bytes")) or 0) + (_int(_zf(rec, "resp_bytes")) or 0)
        x = self.d.setdefault(str(ip)[:64], [0, 0])
        x[0] += b
        x[1] += 1
        if len(self.d) > 50000:  # όριο μνήμης: πετάμε τους μικρότερους
            for k, _v in sorted(self.d.items(), key=lambda kv: kv[1][0])[:10000]:
                del self.d[k]

    def top(self, n=10):
        return [{"ip": k, "bytes": v[0], "conns": v[1]} for k, v in sorted(self.d.items(), key=lambda kv: -kv[1][0])[:n]]


def parse_zeek(lines, path_hint=None):
    """Γραμμές Zeek (TSV ή JSON) → {"alerts", "counts": {log: πλήθος}, "top_talkers", "errors"}."""
    p = ZeekParser(path_hint)
    alerts, counts, errors, talk = [], collections.Counter(), 0, _Talkers()
    for line in lines:
        r = p.feed(line)
        if r is None:
            continue
        path, rec = r
        if rec is None:
            errors += 1
            continue
        counts[path] += 1
        if path in ZEEK_ALERT_LOGS:
            alerts.append(zeek_alert(path, rec))
        elif path == "conn":
            talk.add(rec)
    return {"alerts": alerts, "counts": dict(counts), "top_talkers": talk.top(), "errors": errors}


def guess_kind(text):
    for line in text.splitlines()[:50]:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            return "zeek"
        if line.startswith("{"):
            try:
                o = json.loads(line)
            except ValueError:
                continue
            return "eve" if isinstance(o, dict) and "event_type" in o else "zeek"
    return "eve"


def alert_args(a):
    """Ειδοποίηση εισαγωγής → ορίσματα για state.alert (typ, sev, actor, target, detail, t, key)."""
    if a["source"] == "suricata":
        typ = f"Suricata: {a['signature']}"
        ep = lambda ip, p: f"{ip}:{p}" if p is not None else f"{ip}"  # noqa: E731
        detail = (f"Ο Suricata ανέφερε «{a['signature']}»" + (f" ({a['category']})" if a.get("category") else "")
                  + f" από {ep(a['src'] or '?', a['sp'])} προς {ep(a['dst'] or '?', a['dp'])}"
                  + (f" ({a['proto']})" if a.get("proto") else "") + (f", SID {a['sid']}" if a.get("sid") else "") + ".")
        key = (a.get("sid") or a["signature"], a.get("src"), a.get("dst"))
    else:
        typ = f"Zeek: {a['signature']}"
        what = "notice" if a.get("log") == "notice" else "weird"
        detail = f"Το Zeek ({what}.log) ανέφερε {a['signature']}" + (f": {a['msg']}" if a.get("msg") else "") + "."
        if a.get("sub"):
            detail += f" ({a['sub']})"
        key = (a["signature"], a.get("src"), a.get("dst"))
    actor = a.get("src") or a.get("dst") or "?"
    return typ, a["sev"], actor, a.get("dst") or "", detail, a["t"], key


# ───────────────────────────── demo ─────────────────────────────

SIM_EVE = [
    ("ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)", "Web Application Attack", 1, 2009358,
     "192.168.1.37", "192.168.1.10", 80, "TCP"),
    ("ET POLICY curl User-Agent Outbound", "Attempted Information Leak", 2, 2013028, "192.168.1.23", "93.184.216.34", 80, "TCP"),
    ("ET INFO Observed DNS Query to .cloud TLD", "Potentially Bad Traffic", 2, 2027865, "192.168.1.41", "192.168.1.1", 53, "UDP"),
    ("ET POLICY SSH session in progress on Unusual Port", "Misc activity", 3, 2001984, "192.168.1.37", "192.168.1.15", 2222, "TCP"),
    ("ET SCAN Suspicious inbound to mySQL port 3306", "Potentially Bad Traffic", 2, 2010937, "185.220.101.4", "192.168.1.15", 3306, "TCP"),
    ("ET INFO Possible Kali Linux hostname in DHCP Request Packet", "Potential Corporate Privacy Violation", 1, 2022973,
     "192.168.1.37", "255.255.255.255", 67, "UDP"),
]
SIM_ZEEK = [
    ("notice", "Scan::Port_Scan", "192.168.1.37 scanned at least 15 unique ports of host 192.168.1.10 in 0m3s",
     "192.168.1.37", "192.168.1.10"),
    ("notice", "SSL::Invalid_Server_Cert", "SSL certificate validation failed with (self signed certificate)",
     "192.168.1.23", "192.168.1.20"),
    ("weird", "bad_TCP_checksum", "", "192.168.1.52", "192.168.1.1"),
    ("weird", "dns_unmatched_reply", "", "192.168.1.1", "192.168.1.41"),
]


def sim_alert(rnd, t):
    if rnd.random() < 0.6:
        sig, cat, sv, sid, src, dst, dp, proto = rnd.choice(SIM_EVE)
        ev = {"timestamp": datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat(), "event_type": "alert",
              "src_ip": src, "src_port": rnd.randint(32768, 60999), "dest_ip": dst, "dest_port": dp, "proto": proto,
              "alert": {"action": "allowed", "signature_id": sid, "rev": rnd.randint(2, 9), "signature": sig,
                        "category": cat, "severity": sv}}
        return eve_alert(ev)
    path, note, msg, src, dst = rnd.choice(SIM_ZEEK)
    rec = {"ts": t, "uid": "C" + "".join(rnd.choice("abcdefghijkLMNOPQ0123456789") for _ in range(17)),
           "id.orig_h": src, "id.resp_h": dst}
    if path == "notice":
        rec.update(note=note, msg=msg, src=src, dst=dst)
    else:
        rec.update(name=note, addl=msg or None)
    return zeek_alert(path, rec)


# ───────────────────────────── tail ─────────────────────────────

class _Tail:
    """Ένα αρχείο που παρακολουθούμε: inode + θέση + μισή γραμμή που περιμένει να ολοκληρωθεί."""

    def __init__(self, spec):
        self.path, self.type, self.follow = spec["path"], spec["type"], spec["follow"]
        self.inode, self.offset, self.buf = None, 0, b""
        self.ok, self.error, self.lines, self.alerts, self.last = None, None, 0, 0, None
        self.zeek = ZeekParser(os.path.basename(self.path).split(".")[0] or None)

    def read(self):
        """Νέες πλήρεις γραμμές από την τελευταία φορά (λίστα bytes)."""
        st = os.stat(self.path)
        out = []
        if self.inode is None:  # πρώτη φορά
            self.inode = st.st_ino
            self.offset = st.st_size if self.follow else 0
            if self.follow and self.type == "zeek":
                self._read_header()
        elif st.st_ino != self.inode:  # περιστροφή (logrotate)
            self.inode, self.offset, self.buf = st.st_ino, 0, b""
            self.zeek = ZeekParser(self.zeek.hint)
        elif st.st_size < self.offset:  # truncate
            self.offset, self.buf = 0, b""
        if st.st_size > self.offset:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                data = f.read(min(MAX_READ, st.st_size - self.offset))
            self.offset += len(data)
            data = self.buf + data
            parts = data.split(b"\n")
            self.buf = parts.pop()
            if len(self.buf) > MAX_LINE:  # τεράστια «γραμμή» χωρίς \n: την πετάμε
                self.buf = b""
            out = parts
        return out

    def _read_header(self):
        """Σε follow ενός Zeek TSV ξεκινάμε από το τέλος· χρειαζόμαστε όμως την κεφαλίδα (#fields) από την αρχή."""
        try:
            with open(self.path, "rb") as f:
                head = f.read(65536)
        except OSError:
            return
        for line in head.split(b"\n"):
            if not line.startswith(b"#"):
                break
            self.zeek.feed(line)


def normalize(cfg):
    cfg = cfg or {}
    files = []
    for f in cfg.get("files") or []:
        if not isinstance(f, dict) or not f.get("path"):
            continue
        typ = str(f.get("type") or "").lower()
        if typ not in TYPES:
            typ = "eve" if str(f["path"]).endswith(".json") and "eve" in os.path.basename(str(f["path"])) else "zeek"
        files.append({"path": os.path.expanduser(str(f["path"])), "type": typ, "follow": f.get("follow", True) is not False})
    return {"enabled": bool(cfg.get("enabled", bool(files))), "interval": max(1, int(cfg.get("interval") or 10)), "files": files}


class LogImport:
    def __init__(self, state=None, cfg=None, sim=False):
        self.state, self.sim = state, sim
        self.cfg = normalize(cfg)
        self.enabled = self.cfg["enabled"]
        self.lock = threading.Lock()
        self.recent = collections.deque(maxlen=RECENT)
        self.counts = collections.Counter()
        self.talkers = _Talkers()
        self.error = None
        self.rnd = random.Random(11)
        if sim:
            self.cfg["files"] = [{"path": "/var/log/suricata/eve.json", "type": "eve", "follow": True},
                                 {"path": "/opt/zeek/logs/current/notice.log", "type": "zeek", "follow": True}]
        self.tails = [_Tail(f) for f in self.cfg["files"]]
        if sim:
            self._sim_backfill()

    # — demo —
    def _sim_backfill(self, now=None):
        now = now or time.time()
        ts = sorted(now - self.rnd.uniform(60, 6 * 3600) for _ in range(24))
        for t in ts:
            a = sim_alert(self.rnd, t)
            self.recent.appendleft(a)
            self._sim_count(a, t)
        self.counts.update({"suricata:dns": 9412, "suricata:flow": 15873, "suricata:tls": 3120, "suricata:http": 806,
                            "suricata:fileinfo": 214, "zeek:conn": 18240, "zeek:dns": 9311, "zeek:ssl": 2970})
        for ip, b, n in (("192.168.1.23", 4_812_000_000, 2210), ("192.168.1.41", 1_904_000_000, 5120),
                         ("192.168.1.15", 655_000_000, 811), ("192.168.1.37", 120_000_000, 3900)):
            self.talkers.d[ip] = [b, n]

    def _sim_count(self, a, t):
        tl = self.tails[0 if a["source"] == "suricata" else 1]
        tl.ok, tl.alerts, tl.last = True, tl.alerts + 1, t
        tl.lines += self.rnd.randint(20, 400)
        self.counts[("suricata:alert" if a["source"] == "suricata" else f"zeek:{a['log']}")] += 1

    def sim_tick(self, now=None):
        now = now or time.time()
        if self.rnd.random() < 0.04:
            a = sim_alert(self.rnd, now)
            with self.lock:
                self.recent.appendleft(a)
                self._sim_count(a, now)
            self._forward([a])
            return a
        return None

    # — εισαγωγή —
    def _ingest(self, kind, lines, tail=None):
        """Γραμμές → ειδοποιήσεις/μετρήσεις (καλείται χωρίς lock). Επιστρέφει (alerts, counts, talkers, errors)."""
        if kind == "eve":
            r = parse_eve(lines)
            counts = {f"suricata:{k}": v for k, v in r["counts"].items()}
            talk = []
        else:
            p = tail.zeek if tail else ZeekParser()
            alerts, cnt, errors, tk = [], collections.Counter(), 0, _Talkers()
            for line in lines:
                x = p.feed(line)
                if x is None:
                    continue
                path, rec = x
                if rec is None:
                    errors += 1
                    continue
                cnt[path] += 1
                if path in ZEEK_ALERT_LOGS:
                    alerts.append(zeek_alert(path, rec))
                elif path == "conn":
                    tk.add(rec)
            r = {"alerts": alerts, "errors": errors}
            counts = {f"zeek:{k}": v for k, v in cnt.items()}
            talk = list(tk.d.items())
        with self.lock:
            self.counts.update(counts)
            for ip, (b, n) in talk:
                x = self.talkers.d.setdefault(ip, [0, 0])
                x[0] += b
                x[1] += n
            for a in r["alerts"]:
                self.recent.appendleft(a)
        return r["alerts"], counts, r["errors"]

    def _forward(self, alerts):
        if self.state is None:
            return
        for a in alerts[:MAX_FORWARD]:
            typ, sev, actor, target, detail, t, key = alert_args(a)
            try:
                self.state.alert(typ, sev, actor, target, detail, t, key=key, cooldown=COOLDOWN)
            except Exception:
                pass

    def poll(self):
        """Ένας γύρος: διαβάζει ό,τι νέο γράφτηκε σε κάθε αρχείο. Επιστρέφει τις νέες ειδοποιήσεις."""
        new = []
        for tl in self.tails:
            try:
                lines = tl.read()
            except FileNotFoundError:
                tl.ok, tl.error = False, "Το αρχείο δεν βρέθηκε"
                continue
            except OSError as e:
                tl.ok, tl.error = False, (e.strerror or e.__class__.__name__)[:120]
                continue
            tl.ok, tl.error = True, None
            if not lines:
                continue
            alerts, _c, _e = self._ingest(tl.type, lines, tl)
            tl.lines += len(lines)
            tl.alerts += len(alerts)
            tl.last = time.time()
            new += alerts
        self._forward(new)
        return new

    def import_text(self, text, kind="auto", forward=True):
        """Εφάπαξ ανέβασμα (έως 20 MB) → {"alerts": [...], "counts": {...}, "total", "errors", "top_talkers", "kind"}."""
        if isinstance(text, (bytes, bytearray)):
            if len(text) > MAX_UPLOAD:
                raise ValueError("Το αρχείο είναι πολύ μεγάλο (όριο 20 MB).")
            text = bytes(text).decode("utf-8", "replace")
        if len(text) > MAX_UPLOAD or len(text.encode("utf-8", "replace")) > MAX_UPLOAD:
            raise ValueError("Το αρχείο είναι πολύ μεγάλο (όριο 20 MB).")
        kind = (kind or "auto").lower()
        if kind not in TYPES:
            kind = guess_kind(text)
        lines = text.splitlines()
        if kind == "eve":
            r = parse_eve(lines)
            counts, talk = r["counts"], []
        else:
            r = parse_zeek(lines)
            counts, talk = r["counts"], r["top_talkers"]
        pre = "suricata" if kind == "eve" else "zeek"
        with self.lock:
            self.counts.update({f"{pre}:{k}": v for k, v in counts.items()})
            for a in r["alerts"][-RECENT:]:
                self.recent.appendleft(a)
        if forward:
            self._forward(r["alerts"])
        return {"kind": kind, "alerts": r["alerts"][:1000], "total": len(r["alerts"]), "counts": counts,
                "errors": r["errors"], "top_talkers": talk}

    def status(self):
        with self.lock:
            files = [{"path": t.path, "type": t.type, "follow": t.follow, "ok": t.ok, "error": t.error, "lines": t.lines,
                      "alerts": t.alerts, "last": t.last} for t in self.tails]
            return {"enabled": bool(self.enabled) or self.sim, "demo": self.sim, "error": self.error,
                    "interval": self.cfg["interval"], "files": files, "recent": [dict(a) for a in self.recent],
                    "counts": dict(self.counts), "top_talkers": self.talkers.top()}

    def run_forever(self):
        while True:
            try:
                if self.sim:
                    self.sim_tick()
                else:
                    self.poll()
                self.error = None
            except Exception as e:
                self.error = str(e)[:160] or e.__class__.__name__
            time.sleep(self.cfg["interval"])
