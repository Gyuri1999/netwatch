"""🛡️ Στατιστικά από Pi-hole ή AdGuard Home (μόνο ανάγνωση): ερωτήματα, μπλοκαρισμένα, top domains/πελάτες.

config.yaml:
dns_filter:
  type: pihole            # pihole | adguard
  url: http://192.168.1.2 # μόνο http(s) και μόνο ιδιωτική IP ή όνομα στο τοπικό δίκτυο
  password: ""            # Pi-hole v6: κωδικός ή «app password»· Pi-hole v5: το API token· AdGuard: ο κωδικός
  user: ""                # μόνο για AdGuard Home (HTTP basic auth)
  interval: 60
  verify_tls: true        # false για το αυτο-υπογεγραμμένο πιστοποιητικό του Pi-hole v6 σε https
Pi-hole v6: POST /api/auth → sid (κρατιέται και ξαναχρησιμοποιείται), /api/stats/summary, /api/stats/top_domains?blocked=true,
/api/stats/top_clients, /api/stats/upstreams, /api/dns/blocking. Αν το /api/auth δεν υπάρχει (404) → Pi-hole v5:
/admin/api.php?summaryRaw&topItems&getQuerySources&getForwardDestinations&auth=TOKEN.
AdGuard Home: /control/status και /control/stats με HTTP basic auth.

Ο κωδικός μένει μόνο στο config.yaml: δεν γράφεται ποτέ σε log, σε status ή σε μήνυμα σφάλματος και στέλνεται μόνο
στο url που όρισες (χωρίς να ακολουθούνται ανακατευθύνσεις).
Ειδοποιήσεις: «Το φιλτράρισμα DNS είναι απενεργοποιημένο» (med) και «Ο DNS filter δεν απαντά» (med, μετά από 3 αποτυχίες).
"""
import base64
import collections
import ipaddress
import json
import random
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 5
FAILS_FOR_DOWN = 3
HISTORY = 24            # σημεία (ένα ανά ώρα) για το ποσοστό μπλοκαρισμένων
TOP = 10
MAX_BODY = 4 * 1024 * 1024
ALERT_COOLDOWN = 3600
TYPES = ("pihole", "adguard")
T_DISABLED = "Το φιλτράρισμα DNS είναι απενεργοποιημένο"
T_DOWN = "Ο DNS filter δεν απαντά"


class DnsFilterError(Exception):
    pass


class AuthError(DnsFilterError):
    pass


# ───────────────────────────── URL ─────────────────────────────

def _private_ip(s):
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    return not a.is_global


def check_url(url):
    """Ελέγχει το url → (scheme://host[:port][/path] χωρίς τελικό «/», host). Πετά ValueError με ελληνικό μήνυμα."""
    u = urllib.parse.urlsplit(str(url or "").strip())
    if u.scheme not in ("http", "https"):
        raise ValueError("Το url πρέπει να ξεκινά με http:// ή https://")
    if u.username or u.password:
        raise ValueError("Μην βάζεις όνομα/κωδικό μέσα στο url· χρησιμοποίησε τα user/password")
    host = u.hostname or ""
    if not host or not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", host):
        raise ValueError("Άκυρο όνομα συσκευής στο url")
    priv = _private_ip(host)
    if priv is False:
        raise ValueError("Επιτρέπεται μόνο ιδιωτική διεύθυνση (π.χ. 192.168.x.x) ή όνομα του τοπικού δικτύου")
    try:
        port = u.port
    except ValueError:
        raise ValueError("Άκυρη θύρα στο url")
    netloc = (f"[{host}]" if ":" in host else host) + (f":{port}" if port else "")
    path = u.path.rstrip("/")
    return f"{u.scheme}://{netloc}{path}", host


def resolves_private(host):
    """Όνομα → True αν όλες οι διευθύνσεις του είναι ιδιωτικές (δεν στέλνουμε κωδικό σε δημόσιο server)."""
    if _private_ip(host) is not None:
        return _private_ip(host)
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        raise DnsFilterError(f"Δεν βρέθηκε η συσκευή «{host}»")
    addrs = {i[4][0].split("%")[0] for i in infos}
    return bool(addrs) and all(_private_ip(a) for a in addrs)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def http_fetch(method, url, data=None, headers=None, verify_tls=True):
    """Ένα αίτημα HTTP → (status, bytes). Χωρίς ανακατευθύνσεις, timeout 5″."""
    req = urllib.request.Request(url, data=data, method=method, headers=dict(headers or {}, **{"User-Agent": "NetWatch"}))
    handlers = [_NoRedirect()]
    if url.startswith("https:"):
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            return r.status, r.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        return e.code, b""


# ───────────────────────────── parsers ─────────────────────────────

def _n(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _pct(blocked, total):
    return round(100.0 * blocked / total, 1) if total else 0.0


def _status(v):
    if v is True:
        return "enabled"
    if v is False:
        return "disabled"
    s = str(v or "").lower()
    return s if s in ("enabled", "disabled") else ("unknown" if not s else s[:20])


def parse_pihole6(summary, top_blocked=None, top_clients=None, blocking=None, upstreams=None, clients_blocked=None):
    q = (summary or {}).get("queries") or {}
    total, blocked = _n(q.get("total")) or 0, _n(q.get("blocked")) or 0
    pct = q.get("percent_blocked")
    bl = {}
    for c in (clients_blocked or {}).get("clients") or []:
        bl[c.get("ip")] = _n(c.get("count"))
    clients = []
    for c in ((top_clients or {}).get("clients") or [])[:TOP]:
        ip = str(c.get("ip") or "")[:64]
        name = c.get("name")
        clients.append({"client": ip, "name": str(name)[:80] if name else None, "count": _n(c.get("count")) or 0,
                        "blocked": bl.get(ip)})
    ups = []
    for u in ((upstreams or {}).get("upstreams") or [])[:TOP]:
        name = u.get("name") or u.get("ip")
        ups.append({"upstream": str(name)[:80] + (f"#{u['port']}" if u.get("port") not in (None, 53, -1) else ""),
                    "count": _n(u.get("count")) or 0})
    return {"queries_today": total, "blocked_today": blocked,
            "blocked_pct": round(float(pct), 1) if isinstance(pct, (int, float)) else _pct(blocked, total),
            "top_blocked": [{"domain": str(d.get("domain"))[:253], "count": _n(d.get("count")) or 0}
                            for d in ((top_blocked or {}).get("domains") or [])[:TOP]],
            "top_clients": clients, "upstreams": ups,
            "status": _status((blocking or {}).get("blocking")) if blocking else "unknown",
            "domains_blocked": _n(((summary or {}).get("gravity") or {}).get("domains_being_blocked")),
            "clients_active": _n(((summary or {}).get("clients") or {}).get("active"))}


def _split_src(k):
    """Pi-hole v5: «όνομα|ip» ή σκέτο «ip»."""
    if "|" in k:
        name, ip = k.split("|", 1)
        return ip[:64], name[:80] or None
    return k[:64], None


def parse_pihole5(d):
    d = d or {}
    total, blocked = _n(d.get("dns_queries_today")) or 0, _n(d.get("ads_blocked_today")) or 0
    pct = d.get("ads_percentage_today")
    ads = d.get("top_ads") if isinstance(d.get("top_ads"), dict) else {}
    src = d.get("top_sources") if isinstance(d.get("top_sources"), dict) else {}
    fwd = d.get("forward_destinations") if isinstance(d.get("forward_destinations"), dict) else {}
    clients = []
    for k, v in sorted(src.items(), key=lambda kv: -(_n(kv[1]) or 0))[:TOP]:
        ip, name = _split_src(str(k))
        clients.append({"client": ip, "name": name, "count": _n(v) or 0, "blocked": None})
    ups = []
    for k, v in sorted(fwd.items(), key=lambda kv: -(float(kv[1]) if isinstance(kv[1], (int, float)) else 0))[:TOP]:
        ip, name = _split_src(str(k))
        ups.append({"upstream": name or ip, "count": None, "pct": round(float(v), 1) if isinstance(v, (int, float)) else None})
    try:
        pct = round(float(pct), 1)
    except (TypeError, ValueError):
        pct = _pct(blocked, total)
    return {"queries_today": total, "blocked_today": blocked, "blocked_pct": pct,
            "top_blocked": [{"domain": str(k)[:253], "count": _n(v) or 0}
                            for k, v in sorted(ads.items(), key=lambda kv: -(_n(kv[1]) or 0))[:TOP]],
            "top_clients": clients, "upstreams": ups, "status": _status(d.get("status")),
            "domains_blocked": _n(d.get("domains_being_blocked")), "clients_active": _n(d.get("unique_clients"))}


def _pairs(lst):
    """AdGuard: [{"όνομα": πλήθος}, …] → [(όνομα, πλήθος)]."""
    out = []
    for x in lst or []:
        if isinstance(x, dict):
            for k, v in x.items():
                out.append((str(k), v))
    return out


def parse_adguard(stats, status=None):
    s = stats or {}
    total = _n(s.get("num_dns_queries")) or 0
    blocked = sum(_n(s.get(k)) or 0 for k in ("num_blocked_filtering", "num_replaced_safebrowsing", "num_replaced_parental"))
    ups = [{"upstream": k[:80], "count": _n(v) or 0} for k, v in _pairs(s.get("top_upstreams_responses"))[:TOP]]
    avg = dict(_pairs(s.get("top_upstreams_avg_time")))
    for u in ups:
        t = avg.get(u["upstream"])
        if isinstance(t, (int, float)):
            u["avg_ms"] = round(t * 1000, 1)
    st = status or {}
    if "protection_enabled" in st:
        state = "enabled" if st.get("protection_enabled") else "disabled"
    else:
        state = "unknown"
    if st and st.get("running") is False:
        state = "disabled"
    return {"queries_today": total, "blocked_today": blocked, "blocked_pct": _pct(blocked, total),
            "top_blocked": [{"domain": k[:253], "count": _n(v) or 0} for k, v in _pairs(s.get("top_blocked_domains"))[:TOP]],
            "top_clients": [{"client": k[:64], "name": None, "count": _n(v) or 0, "blocked": None}
                            for k, v in _pairs(s.get("top_clients"))[:TOP]],
            "upstreams": ups, "status": state, "domains_blocked": None, "clients_active": None,
            "avg_ms": round(float(s["avg_processing_time"]) * 1000, 1) if isinstance(s.get("avg_processing_time"), (int, float)) else None,
            "version": str(st.get("version"))[:20] if st.get("version") else None}


# ───────────────────────────── demo ─────────────────────────────

SIM_BLOCKED = [("doubleclick.net", 912), ("app-measurement.com", 744), ("graph.facebook.com", 503),
               ("googleads.g.doubleclick.net", 468), ("telemetry.microsoft.com", 377), ("ads.tiktok.com", 289),
               ("scorecardresearch.com", 241), ("sb.scorecardresearch.com", 198), ("device-metrics-us.amazon.com", 171),
               ("analytics.samsungcloud.com", 133)]
SIM_CLIENTS = [("192.168.1.23", "laptop.lan", 4210, 702), ("192.168.1.41", "tv-saloni.lan", 3388, 1460),
               ("192.168.1.30", "pixel-8.lan", 2874, 812), ("192.168.1.52", "echo-kouzina.lan", 2105, 590),
               ("192.168.1.15", "nas.lan", 1650, 31), ("192.168.1.60", "ps5.lan", 1209, 288),
               ("192.168.1.71", "ipad.lan", 977, 121), ("192.168.1.1", "router.lan", 402, 0)]


def sim_data(now, rnd):
    h = time.localtime(now).tm_hour + time.localtime(now).tm_min / 60
    total = int(18000 * (0.35 + 0.65 * min(1.0, h / 22.0)) + rnd.randint(-120, 120))
    pct = round(22.0 + 3 * rnd.random() - 1.5, 1)
    blocked = int(total * pct / 100)
    f = total / 18000
    return {"queries_today": total, "blocked_today": blocked, "blocked_pct": pct,
            "top_blocked": [{"domain": d, "count": int(c * f)} for d, c in SIM_BLOCKED],
            "top_clients": [{"client": ip, "name": n, "count": int(c * f), "blocked": int(b * f)} for ip, n, c, b in SIM_CLIENTS],
            "upstreams": [{"upstream": "one.one.one.one", "count": int(7200 * f)},
                          {"upstream": "dns.quad9.net", "count": int(4100 * f)}],
            "status": "enabled", "domains_blocked": 187342, "clients_active": len(SIM_CLIENTS)}


# ───────────────────────────── poller ─────────────────────────────

def normalize(cfg):
    cfg = cfg or {}
    typ = str(cfg.get("type") or "pihole").lower()
    return {"type": typ if typ in TYPES else "pihole", "url": str(cfg.get("url") or "").strip(),
            "password": str(cfg.get("password") or cfg.get("token") or ""), "user": str(cfg.get("user") or ""),
            "interval": max(10, int(cfg.get("interval") or 60)), "verify_tls": cfg.get("verify_tls", True) is not False,
            "enabled": bool(cfg.get("enabled", bool(cfg.get("url"))))}


class DnsFilter:
    def __init__(self, state=None, cfg=None, sim=False, fetch=None):
        self.state, self.sim = state, sim
        c = normalize(cfg)
        self.type, self.interval, self.enabled = c["type"], c["interval"], c["enabled"]
        self._pw, self._user, self._verify = c["password"], c["user"], c["verify_tls"]
        self._fetch = fetch or http_fetch
        self._sid = None
        self.version = None      # Pi-hole: 6 ή 5
        self.lock = threading.Lock()
        self.data, self.error, self.fails, self.last_poll = {}, None, 0, None
        self.history = collections.deque(maxlen=HISTORY)
        self._prev_status = None
        self.rnd = random.Random(5)
        self.url, self.host, self.url_error = "", "", None
        if sim:
            self.type, self.url, self.host, self.version = "pihole", "http://192.168.1.2", "192.168.1.2", 6
            now = time.time()
            for k in range(HISTORY - 1, 0, -1):
                t = now - k * 3600
                self._hist(t, round(19.5 + 5 * self.rnd.random() + (2.5 if time.localtime(t).tm_hour in (20, 21, 22) else 0), 1))
            self.poll(now)
        else:
            try:
                self.url, self.host = check_url(c["url"])
            except ValueError as e:
                self.url_error = str(e)
                self.url = self._safe_url(c["url"])

    @staticmethod
    def _safe_url(url):
        """Για εμφάνιση: χωρίς userinfo/query (εκεί μπορεί να κρύβεται κωδικός)."""
        try:
            u = urllib.parse.urlsplit(str(url or ""))
            host = u.hostname or ""
            port = f":{u.port}" if u.port else ""
            return f"{u.scheme}://{host}{port}{u.path}"[:200] if u.scheme else ""
        except ValueError:
            return ""

    def _clean(self, msg):
        msg = str(msg or "")[:200]
        if self._pw:
            msg = msg.replace(self._pw, "***").replace(urllib.parse.quote(self._pw, safe=""), "***")
        return msg

    # — HTTP —
    def _req(self, method, path, body=None, headers=None):
        st, raw = self._fetch(method, self.url + path, body, headers or {}, self._verify)
        data = None
        if raw:
            try:
                data = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                data = None
        return st, data

    def _get_json(self, path, headers=None):
        st, d = self._req("GET", path, headers=headers)
        if st in (401, 403):
            raise AuthError("Απορρίφθηκε ο κωδικός")
        if st != 200 or d is None:
            raise DnsFilterError(f"HTTP {st} στο {path.split('?')[0]}")
        return d

    def _pihole6_auth(self):
        body = json.dumps({"password": self._pw}).encode()
        st, d = self._req("POST", "/api/auth", body, {"Content-Type": "application/json"})
        if st == 404:
            return False  # όχι v6
        if st in (401, 403) or not d or not (d.get("session") or {}).get("valid"):
            raise AuthError("Ο Pi-hole απέρριψε τον κωδικό (δοκίμασε app password)")
        self._sid = (d.get("session") or {}).get("sid")
        return True

    def _pihole6(self, retry=True):
        h = {"X-FTL-SID": self._sid} if self._sid else {}
        try:
            summ = self._get_json("/api/stats/summary", h)
        except AuthError:
            if not retry or not self._pw:
                raise
            if self._pihole6_auth() is False:
                raise DnsFilterError("Ο Pi-hole δεν έχει API v6")
            return self._pihole6(retry=False)
        opt = {}
        for k, p in (("top_blocked", "/api/stats/top_domains?blocked=true&count=10"), ("top_clients", "/api/stats/top_clients?count=10"),
                     ("clients_blocked", "/api/stats/top_clients?blocked=true&count=50"), ("blocking", "/api/dns/blocking"),
                     ("upstreams", "/api/stats/upstreams")):
            try:
                opt[k] = self._get_json(p, h)
            except DnsFilterError:
                opt[k] = None
        return parse_pihole6(summ, **opt)

    def _pihole5(self):
        q = "summaryRaw&topItems=10&getQuerySources=10&getForwardDestinations"
        if self._pw:
            q += "&auth=" + urllib.parse.quote(self._pw, safe="")
        d = self._get_json("/admin/api.php?" + q)
        if isinstance(d, list) or not isinstance(d, dict) or "dns_queries_today" not in d:
            raise AuthError("Ο Pi-hole v5 δεν έδωσε στατιστικά (λάθος API token;)")
        return parse_pihole5(d)

    def _adguard(self):
        h = {}
        if self._user or self._pw:
            h["Authorization"] = "Basic " + base64.b64encode(f"{self._user}:{self._pw}".encode()).decode()
        status = self._get_json("/control/status", h)
        stats = self._get_json("/control/stats", h)
        return parse_adguard(stats, status)

    def fetch(self, now=None):
        """Ένας γύρος συλλογής → κοινή μορφή (βλ. parse_*)."""
        if self.sim:
            return sim_data(now or time.time(), self.rnd)
        if self.url_error:
            raise DnsFilterError(self.url_error)
        if self._fetch is http_fetch and not resolves_private(self.host):
            raise DnsFilterError("Το όνομα δείχνει σε δημόσια διεύθυνση — δεν στέλνουμε εκεί τον κωδικό")
        if self.type == "adguard":
            return self._adguard()
        if self.version != 5:
            if self.version is None and self._pw and not self._sid:
                ok = self._pihole6_auth()
                if ok is False:
                    self.version = 5
                    return self._pihole5()
            try:
                r = self._pihole6()
                self.version = 6
                return r
            except DnsFilterError as e:
                if self.version is None and "HTTP 404" in str(e):
                    self.version = 5
                else:
                    raise
        return self._pihole5()

    # — γύρος —
    def _hist(self, now, pct):
        hr = int(now // 3600) * 3600
        if self.history and self.history[-1]["t"] == hr:
            self.history[-1]["pct"] = pct
        else:
            self.history.append({"t": hr, "pct": pct})

    def poll(self, now=None):
        now = now or time.time()
        events = []
        try:
            d = self.fetch(now)
        except Exception as e:
            err = self._clean(str(e) or e.__class__.__name__)
            if isinstance(e, (urllib.error.URLError, OSError)) and not isinstance(e, DnsFilterError):
                err = self._clean(f"Δεν απαντά: {getattr(e, 'reason', None) or e.__class__.__name__}")
            with self.lock:
                self.error, self.fails = err, self.fails + 1
                if self.fails == FAILS_FOR_DOWN:
                    events.append((T_DOWN, f"Ο {self._name()} ({self.url}) δεν απαντά εδώ και {FAILS_FOR_DOWN} ελέγχους: {err}."))
        else:
            with self.lock:
                self.data, self.error, self.fails, self.last_poll = d, None, 0, now
                self._hist(now, d.get("blocked_pct") or 0.0)
                cur = d.get("status")
                if cur == "disabled" and self._prev_status != "disabled":
                    events.append((T_DISABLED, f"Ο {self._name()} ({self.url}) δεν μπλοκάρει πια διαφημίσεις/trackers: "
                                               "η προστασία είναι απενεργοποιημένη. Αν δεν το έκανες εσύ, ενεργοποίησέ την ξανά."))
                self._prev_status = cur
        if self.state is not None:
            for typ, detail in events:
                try:
                    self.state.alert(typ, "med", self.host or "dns-filter", self._name(), detail, now, key=(typ, self.url),
                                     cooldown=ALERT_COOLDOWN, mark=False)
                except Exception:
                    pass
        return events

    def _name(self):
        return "AdGuard Home" if self.type == "adguard" else "Pi-hole"

    def status(self):
        with self.lock:
            d = self.data or {}
            out = {"enabled": bool(self.enabled) or self.sim, "demo": self.sim, "error": self.error or self.url_error,
                   "type": self.type, "url": self.url, "version": self.version if self.type == "pihole" else d.get("version"),
                   "interval": self.interval, "last_poll": self.last_poll, "fails": self.fails,
                   "queries_today": d.get("queries_today"), "blocked_today": d.get("blocked_today"),
                   "blocked_pct": d.get("blocked_pct"), "top_blocked": [dict(x) for x in d.get("top_blocked") or []],
                   "top_clients": [dict(x) for x in d.get("top_clients") or []],
                   "upstreams": [dict(x) for x in d.get("upstreams") or []], "status": d.get("status"),
                   "domains_blocked": d.get("domains_blocked"), "clients_active": d.get("clients_active"),
                   "avg_ms": d.get("avg_ms"), "history": [dict(h) for h in self.history]}
        return out

    def run_forever(self):
        while True:
            if self.enabled or self.sim:
                try:
                    self.poll()
                except Exception:
                    pass
            time.sleep(self.interval)
