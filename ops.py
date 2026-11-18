"""🛠 Εργαλεία «λειτουργίας» (όπως στα επαγγελματικά NMS — Uptime Kuma, Zabbix, PRTG):

- Παράθυρα συντήρησης: σε προγραμματισμένες ώρες (π.χ. backup κάθε βράδυ 02:00–04:00) ή «σίγαση για 30′»
  οι ειδοποιήσεις φαίνονται στην οθόνη αλλά ΔΕΝ στέλνονται στο κινητό και δεν τρέχουν playbooks.
- Περισσότερα κανάλια ειδοποιήσεων: Discord, Slack, γενικό webhook (JSON), email (SMTP + STARTTLS).
- Prometheus /metrics: για Grafana / Prometheus στο homelab.
- Tokens μόνο-ανάγνωσης (ρόλος viewer) για οθόνη τοίχου / Prometheus σε λειτουργία agent.

config.yaml:
  maintenance:
    - {name: "Backup NAS", days: [mon, tue, wed, thu, fri, sat, sun], start: "02:00", end: "04:00"}
    - {name: "Αναβάθμιση router", start: "2026-12-01 22:00", end: "2026-12-01 23:30", hosts: ["192.168.1.1"]}
  notify:
    discord: {webhook: "https://discord.com/api/webhooks/…"}
    slack:   {webhook: "https://hooks.slack.com/services/…"}
    webhook: {url: "http://192.168.1.30:8123/api/webhook/netwatch", headers: {X-Token: "…"}}
    email:   {host: smtp.gmail.com, port: 587, user: "…", password: "…", to: ["…"], from: "…"}
  api_tokens:
    - {name: "Οθόνη σαλονιού", token: "μακρύ-τυχαίο", role: viewer}
"""
import hmac
import json
import os
import re
import smtplib
import ssl
import threading
import time
import urllib.request
from email.message import EmailMessage

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DAYS_GR = {"δευ": 0, "τρι": 1, "τετ": 2, "πεμ": 3, "παρ": 4, "σαβ": 5, "κυρ": 6}
MAX_MUTE_MIN = 24 * 60


def _hm(s):
    m = re.fullmatch(r"\s*(\d{1,2}):(\d{2})\s*", str(s or ""))
    if not m or int(m.group(1)) > 24 or int(m.group(2)) > 59:
        return None
    return int(m.group(1)) * 60 + int(m.group(2))


def _abs(s):
    try:
        return time.mktime(time.strptime(str(s).strip(), "%Y-%m-%d %H:%M"))
    except (ValueError, OverflowError):
        return None


def _day(d):
    d = str(d).strip().lower()[:3]
    if d in DAYS:
        return DAYS.index(d)
    return DAYS_GR.get(d)


class Maintenance:
    """Προγραμματισμένα παράθυρα (από το config) + προσωρινές σιγάσεις (από το UI, σώζονται στο data/maint.json)."""

    def __init__(self, windows=None, path=None):
        self.path = path
        self.lock = threading.Lock()
        self.windows, self.errors = [], []
        for i, w in enumerate(windows or []):
            self._add_cfg(i, w)
        self.mutes = []  # {id, name, until, hosts}
        self._seq = 0
        self._load()

    def _add_cfg(self, i, w):
        if not isinstance(w, dict):
            self.errors.append(f"maintenance[{i}]: πρέπει να είναι λεξικό")
            return
        name = str(w.get("name") or f"Συντήρηση {i + 1}")[:80]
        hosts = [str(h) for h in (w.get("hosts") or [])][:50]
        a, b = _abs(w.get("start")), _abs(w.get("end"))
        if a is not None and b is not None:
            if b <= a:
                self.errors.append(f"«{name}»: το τέλος είναι πριν από την αρχή")
                return
            self.windows.append({"name": name, "kind": "once", "start": a, "end": b, "hosts": hosts})
            return
        s, e = _hm(w.get("start")), _hm(w.get("end"))
        if s is None or e is None:
            self.errors.append(f"«{name}»: start/end σε μορφή ΩΩ:ΛΛ ή «ΕΕΕΕ-ΜΜ-ΗΗ ΩΩ:ΛΛ»")
            return
        days = [x for x in (_day(d) for d in (w.get("days") or DAYS)) if x is not None] or list(range(7))
        self.windows.append({"name": name, "kind": "weekly", "start": s, "end": e, "days": sorted(set(days)), "hosts": hosts})

    # ---------- αποθήκευση των σιγάσεων ----------
    def _load(self):
        if not self.path or not os.path.isfile(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            now = time.time()
            self.mutes = [m for m in d.get("mutes", []) if isinstance(m, dict) and float(m.get("until", 0)) > now][:50]
            self._seq = max([int(m.get("id", 0)) for m in self.mutes] + [0])
        except (OSError, ValueError, TypeError):
            self.mutes = []

    def _save(self):
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"mutes": self.mutes}, f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def mute(self, minutes, name=None, hosts=None, now=None):
        now = time.time() if now is None else now
        minutes = max(1, min(MAX_MUTE_MIN, int(minutes)))
        with self.lock:
            self._seq += 1
            m = {"id": self._seq, "name": str(name or f"Σίγαση {minutes}′")[:80], "until": now + minutes * 60,
                 "hosts": [str(h)[:64] for h in (hosts or [])][:20], "since": now}
            self.mutes.append(m)
            self.mutes = self.mutes[-50:]
            self._save()
        return m

    def unmute(self, mid=None):
        with self.lock:
            self.mutes = [m for m in self.mutes if mid is not None and m["id"] != mid]
            self._save()

    # ---------- έλεγχος ----------
    @staticmethod
    def _weekly_hit(w, now):
        lt = time.localtime(now)
        m, d = lt.tm_hour * 60 + lt.tm_min, lt.tm_wday
        s, e = w["start"], w["end"]
        if s <= e:
            return d in w["days"] and s <= m < e
        # πάνω από τα μεσάνυχτα (π.χ. 23:00–01:00): το κομμάτι μετά τις 00:00 ανήκει στην προηγούμενη μέρα
        return (d in w["days"] and m >= s) or (((d - 1) % 7) in w["days"] and m < e)

    def active(self, now=None, *ips):
        """Το όνομα του παραθύρου που καλύπτει αυτή τη στιγμή (και αυτές τις IP), αλλιώς None."""
        now = time.time() if now is None else now
        ips = {i for i in ips if i}
        hit = lambda hosts: not hosts or bool(ips & set(hosts))  # noqa: E731
        with self.lock:
            for m in self.mutes:
                if m["until"] > now and hit(m["hosts"]):
                    return m["name"]
        for w in self.windows:
            if not hit(w["hosts"]):
                continue
            if w["kind"] == "once" and w["start"] <= now < w["end"]:
                return w["name"]
            if w["kind"] == "weekly" and self._weekly_hit(w, now):
                return w["name"]
        return None

    def status(self, now=None):
        now = time.time() if now is None else now
        with self.lock:
            self.mutes = [m for m in self.mutes if m["until"] > now]
            mutes = [dict(m, left=round(m["until"] - now)) for m in self.mutes]
        wins = []
        for w in self.windows:
            x = dict(w)
            if w["kind"] == "weekly":
                x["start"] = "%02d:%02d" % divmod(w["start"], 60)
                x["end"] = "%02d:%02d" % divmod(w["end"], 60)
                x["days"] = [DAYS[d] for d in w["days"]]
            x["active"] = bool((w["kind"] == "once" and w["start"] <= now < w["end"]) or
                               (w["kind"] == "weekly" and self._weekly_hit(w, now)))
            wins.append(x)
        return {"active": self.active(now), "mutes": mutes, "windows": wins, "errors": self.errors}


# ---------------- επιπλέον κανάλια ειδοποιήσεων ----------------
SEV_COL = {"high": 0xFF3B5C, "med": 0xFF9F43, "low": 0xFFD23F}


def _post_json(url, obj, headers=None, timeout=10):
    if not re.match(r"^https?://", str(url or "")):
        raise ValueError("το URL πρέπει να ξεκινά με http:// ή https://")
    h = {"Content-Type": "application/json", "User-Agent": "netwatch/1.0"}
    for k, v in (headers or {}).items():
        if re.fullmatch(r"[A-Za-z0-9-]{1,64}", str(k)) and "\n" not in str(v) and "\r" not in str(v):
            h[str(k)] = str(v)
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST", headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        r.read(2048)
    return True


def discord(cfg, title, body, sev, alert=None):
    url = (cfg or {}).get("webhook")
    if not url:
        return False
    return _post_json(url, {"username": "NetWatch", "embeds": [{"title": title[:250], "description": body[:3900],
                                                               "color": SEV_COL.get(sev, 0x3EC5FF)}]})


def slack(cfg, title, body, sev, alert=None):
    url = (cfg or {}).get("webhook")
    if not url:
        return False
    icon = {"high": ":rotating_light:", "med": ":warning:"}.get(sev, ":information_source:")
    return _post_json(url, {"text": f"{icon} *{title}*\n{body}"[:3900]})


def webhook(cfg, title, body, sev, alert=None):
    url = (cfg or {}).get("url")
    if not url:
        return False
    a = {k: v for k, v in (alert or {}).items() if not str(k).startswith("_")}
    return _post_json(url, {"source": "netwatch", "title": title, "message": body, "severity": sev, "alert": a},
                      headers=(cfg or {}).get("headers"))


def email(cfg, title, body, sev, alert=None, _smtp=smtplib.SMTP):
    cfg = cfg or {}
    to = cfg.get("to")
    to = [to] if isinstance(to, str) else list(to or [])
    if not (cfg.get("host") and to):
        return False
    msg = EmailMessage()
    msg["Subject"] = title.replace("\n", " ")[:200]
    msg["From"] = cfg.get("from") or cfg.get("user") or "netwatch@localhost"
    msg["To"] = ", ".join(to[:10])
    msg.set_content(body)
    port = int(cfg.get("port") or 587)
    with _smtp(cfg["host"], port, timeout=15) as s:
        if cfg.get("starttls", True) and port != 25:
            s.starttls(context=ssl.create_default_context())
        if cfg.get("user") and cfg.get("password"):
            s.login(cfg["user"], cfg["password"])
        s.send_message(msg)
    return True


CHANNELS = {"discord": discord, "slack": slack, "webhook": webhook, "email": email}


def configured(ncfg):
    n = ncfg or {}
    return {"discord": bool((n.get("discord") or {}).get("webhook")), "slack": bool((n.get("slack") or {}).get("webhook")),
            "webhook": bool((n.get("webhook") or {}).get("url")),
            "email": bool((n.get("email") or {}).get("host") and (n.get("email") or {}).get("to"))}


# ---------------- Prometheus ----------------
def _esc(v):
    return str(v).replace("\\", "\\\\").replace("\n", " ").replace('"', '\\"')


def metrics(state):
    """Κείμενο σε μορφή Prometheus (text exposition 0.0.4)."""
    out = []

    def m(name, help_, typ, rows):
        out.append(f"# HELP netwatch_{name} {help_}")
        out.append(f"# TYPE netwatch_{name} {typ}")
        for labels, v in rows:
            lab = ",".join(f'{k}="{_esc(x)}"' for k, x in labels.items())
            out.append(f"netwatch_{name}{{{lab}}} {v}" if lab else f"netwatch_{name} {v}")

    with state.lock:
        st = state._stats(1) if hasattr(state, "_stats") else {}
        hosts = list(state.hosts.values())
        al = [a for a in state.alerts if not a.get("lab") and not a.get("benign") and not a.get("selftest")]
        total = getattr(state, "total_pkts", 0)
    now = time.time()
    m("up", "1 αν τρέχει το NetWatch", "gauge", [({"mode": getattr(state, "mode", "")}, 1)])
    m("packets_total", "πακέτα που είδε από την αρχή", "counter", [({}, total)])
    m("packets_per_second", "πακέτα/s τώρα", "gauge", [({}, st.get("pps", 0))])
    m("bytes_per_second", "bytes/s τώρα", "gauge", [({}, st.get("bps", 0))])
    kinds = {}
    for h in hosts:
        kinds[h.get("kind", "?")] = kinds.get(h.get("kind", "?"), 0) + 1
    m("hosts", "hosts ανά είδος", "gauge", [({"kind": k}, v) for k, v in sorted(kinds.items())])
    m("hosts_threat", "hosts με ένδειξη απειλής", "gauge", [({}, sum(1 for h in hosts if h.get("threat", 0) >= 2))])
    rows = {}
    for a in al:
        rows[a["sev"]] = rows.get(a["sev"], 0) + 1
    m("alerts", "ειδοποιήσεις στη μνήμη ανά σοβαρότητα", "gauge", [({"severity": k}, rows.get(k, 0)) for k in ("high", "med", "low")])
    m("alerts_last_hour", "ειδοποιήσεις την τελευταία ώρα", "gauge",
      [({"severity": k}, sum(1 for a in al if a["sev"] == k and now - a["t"] < 3600)) for k in ("high", "med", "low")])
    hl = getattr(state, "health", None)
    if hl:
        try:
            T = hl.status().get("targets", [])
            m("target_up", "homelab: 1 = απαντά", "gauge", [({"name": t.get("name"), "host": t.get("host")}, 1 if t.get("up") else 0) for t in T])
            m("target_latency_ms", "homelab: καθυστέρηση", "gauge",
              [({"name": t.get("name"), "host": t.get("host")}, t["ms"]) for t in T if t.get("ms") is not None])
        except Exception:
            pass
    lat = getattr(state, "latency", None)
    if lat:
        try:
            for t in lat.status().get("targets", []):
                cur = t.get("current") or t
                if cur.get("median") is not None:
                    m("ping_median_ms", "SmokePing-style: διάμεσος χρόνος", "gauge", [({"target": t.get("name")}, cur["median"])])
                if cur.get("loss") is not None:
                    m("ping_loss_ratio", "SmokePing-style: απώλειες (0–1)", "gauge", [({"target": t.get("name")}, round(cur["loss"] / 100, 4) if cur["loss"] > 1 else cur["loss"])])
        except Exception:
            pass
    mt = getattr(state, "maint", None)
    m("maintenance_active", "1 όταν τρέχει παράθυρο συντήρησης", "gauge", [({}, 1 if mt and mt.active() else 0)])
    return "\n".join(out) + "\n"


# ---------------- tokens μόνο-ανάγνωσης ----------------
def token_role(headers, query_token, tokens):
    """Ρόλος ("viewer"/"admin") για το token του αιτήματος (Authorization: Bearer … ή ?token=), αλλιώς None."""
    got = ""
    auth = headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        got = auth[7:].strip()
    got = got or (query_token or "")
    if not got or len(got) > 256:
        return None
    for t in tokens or []:
        tok = str((t or {}).get("token") or "")
        if len(tok) >= 16 and hmac.compare_digest(tok.encode(), got.encode()):
            return "admin" if t.get("role") == "admin" else "viewer"
    return None
