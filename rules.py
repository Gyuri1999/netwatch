"""NetWatch — δικοί σου κανόνες ανίχνευσης (detection engineering).

Ένας κανόνας είναι YAML:

    id: telnet-anywhere
    title: Σύνδεση Telnet
    severity: med                 # low | med | high
    mitre: T1021                  # προαιρετικό
    description: Κάποιος ανοίγει Telnet — όλα ταξιδεύουν χωρίς κρυπτογράφηση
    match:                        # όλα πρέπει να ισχύουν (AND)
      proto: TCP
      dport: 23
      flags: S
      src: local                  # me | gw | local | public | bcast | IP | CIDR, «!» = άρνηση
    threshold:                    # προαιρετικό: «τουλάχιστον N μέσα σε W δευτερόλεπτα»
      count: 3
      window: 60
      by: src                     # src | dst | src,dst
      distinct: dport             # μέτρα ΔΙΑΦΟΡΕΤΙΚΕΣ τιμές (π.χ. θύρες)

Οι κανόνες μετατρέπονται και σε Sigma και Suricata για χρήση σε SIEM/IDS.
"""
import collections
import fnmatch
import hashlib
import ipaddress
import os
import re
import uuid

import yaml

IP_FIELDS = ("src", "dst", "ip")
PORT_FIELDS = ("sport", "dport", "port")
GLOB_FIELDS = ("dns_query", "sni", "http_host", "domain", "smac")
OTHER_FIELDS = ("proto", "flags", "len_gt", "len_lt")
MATCH_FIELDS = IP_FIELDS + PORT_FIELDS + GLOB_FIELDS + OTHER_FIELDS
DISTINCT_FIELDS = ("src", "dst", "sport", "dport", "dns_query", "sni", "http_host")
SEVERITIES = {"low": "low", "med": "med", "medium": "med", "high": "high", "critical": "high"}
PROTOS = {"TCP", "UDP", "ICMP", "ARP", "IP", "ICMPV6"}
FIELD_HELP = {
    "src / dst / ip": "IP, CIDR ή λέξη: me, gw, local, public, bcast — λίστα = «οποιοδήποτε», «!» = άρνηση",
    "sport / dport / port": "θύρα, λίστα [22, 23] ή εύρος \"1000-2000\"",
    "proto": "TCP, UDP, ICMP, ARP",
    "flags": "σημαίες TCP ακριβώς, π.χ. S (SYN), SA, FPU",
    "dns_query / sni / http_host / domain": "glob, π.χ. \"*.xyz\" ή \"*exfil*\" (domain = οποιοδήποτε από τα 3)",
    "smac": "MAC συσκευής (glob), π.χ. \"de:ad:*\"",
    "len_gt / len_lt": "μέγεθος πακέτου σε bytes",
}
TEMPLATE = """id: my-rule
title: Η TV μιλάει σε ύποπτη θύρα
severity: high
mitre: T1571
description: Μια συσκευή του LAN συνδέεται σε θύρα που χρησιμοποιούν backdoors
match:
  src: local
  dst: public
  proto: TCP
  flags: S
  dport: [4444, 6666, 6667, 31337]
"""


class RuleError(ValueError):
    pass


def _list(v):
    return v if isinstance(v, list) else [v]


def _ip_matcher(spec):
    pos, neg = [], []
    for item in _list(spec):
        s = str(item).strip()
        target = neg if s.startswith("!") else pos
        s = s.lstrip("!").strip()
        if s.lower() in ("me", "gw", "local", "private", "public", "bcast", "any"):
            target.append(s.lower().replace("private", "local"))
            continue
        try:
            target.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            raise RuleError(f"Μη έγκυρη IP/CIDR: {s!r}")
    return pos, neg


def _ports(spec):
    out = []
    for item in _list(spec):
        s = str(item).strip()
        m = re.fullmatch(r"(\d+)\s*[-:]\s*(\d+)", s)
        try:
            lo, hi = (int(m.group(1)), int(m.group(2))) if m else (int(s), int(s))
        except ValueError:
            raise RuleError(f"Μη έγκυρη θύρα: {s!r}")
        if not (0 <= lo <= hi <= 65535):
            raise RuleError(f"Θύρα εκτός ορίων: {s!r}")
        out.append((lo, hi))
    return out


class Rule:
    def __init__(self, d, source="local"):
        if not isinstance(d, dict):
            raise RuleError("Ο κανόνας πρέπει να είναι αντικείμενο YAML (key: value)")
        unknown = set(d) - {"id", "title", "severity", "mitre", "tactic", "description", "match", "threshold",
                            "enabled", "cooldown"}
        if unknown:
            raise RuleError(f"Άγνωστα πεδία: {', '.join(sorted(unknown))}")
        self.id = str(d.get("id") or "").strip()
        if not re.fullmatch(r"[a-zA-Z0-9][\w.-]{1,63}", self.id):
            raise RuleError("Το id πρέπει να είναι 2–64 χαρακτήρες: γράμματα, αριθμοί, - _ .")
        self.title = str(d.get("title") or self.id)[:120]
        sev = str(d.get("severity", "med")).lower()
        if sev not in SEVERITIES:
            raise RuleError("severity: low, med ή high")
        self.severity = SEVERITIES[sev]
        self.mitre = str(d["mitre"]).upper() if d.get("mitre") else None
        if self.mitre and not re.fullmatch(r"T\d{4}(\.\d{3})?", self.mitre):
            raise RuleError("mitre: π.χ. T1046 ή T1110.001")
        self.tactic = str(d.get("tactic") or "")[:40] or None
        self.description = str(d.get("description") or "")[:400]
        self.enabled = bool(d.get("enabled", True))
        self.cooldown = int(d.get("cooldown", 60))
        self.source = source
        self.raw = d
        m = d.get("match")
        if not isinstance(m, dict) or not m:
            raise RuleError("Χρειάζεται «match:» με τουλάχιστον ένα πεδίο")
        bad = set(m) - set(MATCH_FIELDS)
        if bad:
            raise RuleError(f"Άγνωστα πεδία στο match: {', '.join(sorted(bad))} — επιτρέπονται: "
                            f"{', '.join(MATCH_FIELDS)}")
        self.match = m
        self.ips = {f: _ip_matcher(m[f]) for f in IP_FIELDS if f in m}
        self.ports = {f: _ports(m[f]) for f in PORT_FIELDS if f in m}
        self.globs = {f: [str(x).lower() for x in _list(m[f])] for f in GLOB_FIELDS if f in m}
        self.protos = {str(x).upper() for x in _list(m["proto"])} if "proto" in m else None
        if self.protos and not self.protos <= PROTOS:
            raise RuleError(f"proto: {', '.join(sorted(PROTOS))}")
        self.flags = {str(x).upper() for x in _list(m["flags"])} if "flags" in m else None
        self.len_gt, self.len_lt = m.get("len_gt"), m.get("len_lt")
        th = d.get("threshold")
        self.threshold = None
        if th is not None:
            if not isinstance(th, dict):
                raise RuleError("threshold: {count, window, by, distinct}")
            try:
                count, window = int(th.get("count", 1)), float(th.get("window", 60))
            except (TypeError, ValueError):
                raise RuleError("threshold.count/window πρέπει να είναι αριθμοί")
            if count < 1 or not (0 < window <= 86400):
                raise RuleError("threshold: count ≥ 1 και 0 < window ≤ 86400")
            by = [b.strip() for b in str(th.get("by", "src")).split(",")]
            if not set(by) <= {"src", "dst"}:
                raise RuleError("threshold.by: src, dst ή src,dst")
            distinct = th.get("distinct")
            if distinct and distinct not in DISTINCT_FIELDS:
                raise RuleError(f"threshold.distinct: {', '.join(DISTINCT_FIELDS)}")
            self.threshold = {"count": count, "window": window, "by": by, "distinct": distinct}

    # ---------- matching ----------
    def _ip_ok(self, ip, spec, ctx):
        if ip is None:
            return False
        pos, neg = spec
        def hit(x):
            if isinstance(x, str):
                if x == "any":
                    return True
                if x == "me":
                    return ip in ctx["me"]
                if x == "gw":
                    return ip == ctx["gw"]
                return ctx["kind"](ip) == x
            try:
                return ipaddress.ip_address(ip) in x
            except ValueError:
                return False
        return (not pos or any(hit(x) for x in pos)) and not any(hit(x) for x in neg)

    @staticmethod
    def _port_ok(p, ranges):
        return p is not None and any(lo <= p <= hi for lo, hi in ranges)

    def matches(self, P, ctx):
        if self.protos and str(P.get("proto", "")).upper() not in self.protos:
            return False
        for f, spec in self.ips.items():
            if f == "ip":
                if not (self._ip_ok(P.get("src"), spec, ctx) or self._ip_ok(P.get("dst"), spec, ctx)):
                    return False
            elif not self._ip_ok(P.get(f), spec, ctx):
                return False
        for f, r in self.ports.items():
            if f == "port":
                if not (self._port_ok(P.get("sp"), r) or self._port_ok(P.get("dp"), r)):
                    return False
            elif not self._port_ok(P.get("sp" if f == "sport" else "dp"), r):
                return False
        if self.flags is not None and str(P.get("flags", "")).upper() not in self.flags:
            return False
        if self.len_gt is not None and not P.get("len", 0) > self.len_gt:
            return False
        if self.len_lt is not None and not P.get("len", 0) < self.len_lt:
            return False
        for f, pats in self.globs.items():
            vals = _field_values(P, f)
            if not any(fnmatch.fnmatchcase(v, p) for v in vals for p in pats):
                return False
        return True

    # ---------- export ----------
    def to_sigma(self):
        return to_sigma(self)

    def to_suricata(self, sid):
        return to_suricata(self, sid)

    def info(self):
        return {"id": self.id, "title": self.title, "severity": self.severity, "mitre": self.mitre,
                "description": self.description, "enabled": self.enabled, "source": self.source,
                "match": self.match, "threshold": self.threshold,
                "yaml": yaml.safe_dump(self.raw, allow_unicode=True, sort_keys=False)}


def _field_values(P, f):
    if f == "dns_query":
        q = P.get("dns_q")
        return [q[0].lower()] if q else []
    if f == "sni":
        return [P["sni"].lower()] if P.get("sni") else []
    if f == "http_host":
        return [P["http_host"].lower()] if P.get("http_host") else []
    if f == "domain":
        return _field_values(P, "dns_query") + _field_values(P, "sni") + _field_values(P, "http_host")
    if f == "smac":
        return [str(P["smac"]).lower()] if P.get("smac") else []
    return []


def _distinct_value(P, f):
    return {"src": P.get("src"), "dst": P.get("dst"), "sport": P.get("sp"), "dport": P.get("dp"),
            "dns_query": (P.get("dns_q") or (None,))[0], "sni": P.get("sni"), "http_host": P.get("http_host")}[f]


def parse_rules(text, source="local"):
    """YAML (ένας κανόνας ή λίστα) → [Rule]."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise RuleError(f"Λάθος YAML: {str(e).splitlines()[0]}")
    if data is None:
        return []
    if isinstance(data, dict) and "rules" in data and isinstance(data["rules"], list):
        data = data["rules"]
    rules = [Rule(d, source) for d in _list(data)]
    ids = [r.id for r in rules]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise RuleError(f"Διπλό id: {', '.join(sorted(dup))}")
    return rules


class RuleEngine:
    """Τρέχει τους κανόνες σε κάθε πακέτο. ctx: {me, gw, kind(ip)}; alert(...) καλείται όταν «χτυπήσει»."""

    def __init__(self, rules=(), alert=None, ctx=None):
        self.rules = list(rules)
        self.alert = alert
        self.ctx = ctx
        self.windows = collections.defaultdict(collections.deque)
        self.hits = collections.Counter()
        self.last_hit = {}

    def set_rules(self, rules):
        self.rules = list(rules)
        self.windows.clear()

    def check(self, P, t):
        ctx = self.ctx() if callable(self.ctx) else self.ctx
        fired = []
        for r in self.rules:
            if not r.enabled or not r.matches(P, ctx):
                continue
            th = r.threshold
            actor = P.get("src") if not th or "src" in th["by"] else P.get("dst")
            target = P.get("dst") if actor == P.get("src") else P.get("src")
            if th:
                key = (r.id,) + tuple(P.get(b) for b in th["by"])
                dq = self.windows[key]
                dq.append((t, _distinct_value(P, th["distinct"]) if th["distinct"] else None))
                while dq and dq[0][0] < t - th["window"]:
                    dq.popleft()
                n = len({v for _, v in dq}) if th["distinct"] else len(dq)
                if len(self.windows) > 50000:
                    self.windows.clear()
                if n < th["count"]:
                    continue
                what = f"{n} {'διαφορετικά ' + th['distinct'] if th['distinct'] else 'πακέτα'} σε {th['window']:g}s"
            else:
                what = "ταίριαξε πακέτο"
            self.hits[r.id] += 1
            self.last_hit[r.id] = t
            fired.append(r.id)
            if self.alert:
                detail = f"Κανόνας «{r.id}»: {what}" + (f" — {r.description}" if r.description else "")
                self.alert(r, actor, target, detail, t)
        return fired


# ---------------- Sigma ----------------
def _sigma_ip(spec):
    pos, neg = spec
    word = {"me": "<my-ip>/32", "gw": "<gateway-ip>/32", "local": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "public": None, "bcast": ["224.0.0.0/4", "255.255.255.255/32"], "any": None}

    def conv(items):
        out = []
        for x in items:
            if isinstance(x, str):
                w = word[x]
                out += w if isinstance(w, list) else ([w] if w else [])
            else:
                out.append(str(x))
        return out
    p, n = conv(pos), conv(neg)
    if "public" in pos:  # «δημόσια» = όχι ιδιωτική
        n += word["local"]
    return p, n


def to_sigma(rule):
    sel, flt = {}, {}
    m = rule.match
    dns = any(f in m for f in ("dns_query", "domain"))
    names = {"src": "src_ip", "dst": "dst_ip", "sport": "src_port", "dport": "dst_port"}
    for f, spec in rule.ips.items():
        p, n = _sigma_ip(spec)
        key = names.get(f, "dst_ip")
        if p:
            sel[key + "|cidr"] = p if len(p) > 1 else p[0]
        if n:
            flt[key + "|cidr"] = n if len(n) > 1 else n[0]
    for f, r in rule.ports.items():
        vals = [lo if lo == hi else f"{lo}-{hi}" for lo, hi in r]
        sel[names.get(f, "dst_port")] = vals if len(vals) > 1 else vals[0]
    if rule.protos:
        sel["protocol"] = sorted(p.lower() for p in rule.protos)
        if len(sel["protocol"]) == 1:
            sel["protocol"] = sel["protocol"][0]
    if rule.flags:
        sel["tcp_flags"] = sorted(rule.flags) if len(rule.flags) > 1 else next(iter(rule.flags))
    for f, pats in rule.globs.items():
        key = {"dns_query": "query", "domain": "query", "sni": "tls.server_name", "http_host": "cs-host",
               "smac": "src_mac"}[f]
        sel[key] = pats if len(pats) > 1 else pats[0]
    cond = "selection and not filter" if flt else "selection"
    th = rule.threshold
    if th:
        dn = {**names, "dns_query": "query", "sni": "tls.server_name", "http_host": "cs-host"}
        agg = f"count({dn.get(th['distinct'], th['distinct'])})" if th["distinct"] else "count()"
        cond += f" | {agg} by {','.join(names.get(b, b) for b in th['by'])} >= {th['count']}"
    doc = {
        "title": rule.title,
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "netwatch:" + rule.id)),
        "status": "experimental",
        "description": rule.description or rule.title,
        "author": "NetWatch",
        "tags": [f"attack.{rule.mitre.lower()}"] if rule.mitre else [],
        "logsource": {"category": "dns"} if dns else {"category": "firewall"},
        "detection": {"selection": sel, **({"filter": flt} if flt else {}), "condition": cond},
        **({"timeframe": f"{int(th['window'])}s"} if th else {}),
        "level": {"low": "low", "med": "medium", "high": "high"}[rule.severity],
    }
    if not doc["tags"]:
        del doc["tags"]
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)


# ---------------- Suricata ----------------
def _suri_addr(spec, ctx):
    if spec is None:
        return "any"
    pos, neg = spec

    def one(x):
        if isinstance(x, str):
            return {"me": (sorted(i for i in ctx.get("me", ()) if ":" not in i) or ["$HOME_NET"])[0],
                    "gw": ctx.get("gw") or "$HOME_NET", "local": "$HOME_NET", "public": "$EXTERNAL_NET",
                    "bcast": "[224.0.0.0/4,255.255.255.255]", "any": "any"}[x]
        return str(x)
    p = [one(x) for x in pos] or ["any"]
    out = p[0] if len(p) == 1 else "[" + ",".join(p) + "]"
    if neg:
        n = ",".join("!" + one(x) for x in neg)
        out = n if out == "any" else "[" + out + "," + n + "]"
    return out


def _suri_ports(ranges):
    if not ranges:
        return "any"
    v = [str(lo) if lo == hi else f"{lo}:{hi}" for lo, hi in ranges]
    return v[0] if len(v) == 1 else "[" + ",".join(v) + "]"


def _glob_contents(pat, buf):
    parts = [p for p in re.split(r"[*?]", pat) if p]
    out = [f'{buf}; content:"{p}"; nocase;' for p in parts]
    if out and not pat.endswith(("*", "?")):
        out[-1] += " endswith;"
    return out


def to_suricata(rule, sid, ctx=None):
    ctx = ctx or {}
    notes = []
    app = None
    if "dns_query" in rule.globs or "domain" in rule.globs:
        app = "dns"
    elif "sni" in rule.globs:
        app = "tls"
    elif "http_host" in rule.globs:
        app = "http"
    proto = app or (next(iter(rule.protos)).lower() if rule.protos and len(rule.protos) == 1 else "ip")
    if proto == "arp":
        notes.append("# Το Suricata δεν ελέγχει ARP — χρησιμοποίησε arpwatch / Zeek")
        proto = "ip"
    ips = rule.ips
    src, dst = ips.get("src"), ips.get("dst")
    if "ip" in ips:
        src = ips["ip"]
        notes.append("# «ip» → μετατράπηκε σε src με κατεύθυνση <> (και τις δύο)")
    ports = rule.ports
    sp = _suri_ports(ports.get("sport") or ports.get("port"))
    dp = _suri_ports(ports.get("dport") or ports.get("port"))
    arrow = "<>" if ("ip" in ips or "port" in ports) else "->"
    opts = [f'msg:"NetWatch: {rule.title}"']
    if rule.flags and proto == "tcp":
        if len(rule.flags) > 1:
            notes.append("# πολλαπλές τιμές flags — κρατήθηκε η πρώτη")
        opts.append(f"flags:{sorted(rule.flags)[0] or '0'}")
    for f, pats in rule.globs.items():
        buf = {"dns_query": "dns.query", "domain": "dns.query", "sni": "tls.sni", "http_host": "http.host"}.get(f)
        if not buf:
            notes.append(f"# το πεδίο {f} δεν έχει αντίστοιχο στο Suricata")
            continue
        if len(pats) > 1:
            notes.append(f"# {f}: πολλαπλά patterns — ο κανόνας χρησιμοποιεί το πρώτο ({pats[0]})")
        opts += _glob_contents(pats[0], buf)
    if rule.len_gt is not None:
        opts.append(f"dsize:>{rule.len_gt}")
    th = rule.threshold
    if th:
        track = "by_both" if len(th["by"]) == 2 else ("by_src" if th["by"] == ["src"] else "by_dst")
        opts.append(f"threshold: type threshold, track {track}, count {th['count']}, seconds {int(th['window'])}")
        if th["distinct"]:
            notes.append(f"# το Suricata δεν μετρά διαφορετικά {th['distinct']} — ο κανόνας μετρά όλα τα πακέτα")
    if rule.mitre:
        opts.append(f"metadata: mitre_technique_id {rule.mitre}")
    opts += [f"classtype:{'attempted-recon' if rule.severity != 'high' else 'trojan-activity'}",
             f"sid:{sid}", "rev:1"]
    line = f"alert {proto} {_suri_addr(src, ctx)} {sp} {arrow} {_suri_addr(dst, ctx)} {dp} ({'; '.join(o.rstrip(';') for o in opts)};)"
    return "\n".join(notes + [line])


def sid_for(rule_id):
    return 9000000 + int(hashlib.md5(rule_id.encode()).hexdigest()[:5], 16) % 999999


def load_dir(path):
    """Φορτώνει όλα τα rules/*.yaml. Επιστρέφει (κανόνες, λάθη)."""
    rules, errors, seen = [], [], set()
    if not os.path.isdir(path):
        return rules, errors
    for fn in sorted(os.listdir(path)):
        if not fn.endswith((".yaml", ".yml")):
            continue
        try:
            with open(os.path.join(path, fn), encoding="utf-8") as f:
                for r in parse_rules(f.read(), source=fn):
                    if r.id in seen:
                        errors.append(f"{fn}: διπλό id {r.id}")
                        continue
                    seen.add(r.id)
                    rules.append(r)
        except (RuleError, OSError) as e:
            errors.append(f"{fn}: {e}")
    return rules, errors
