"""📋 Αναφορά «νέο δίκτυο» (walk-in assessment) — μια εικόνα του δικτύου με ένα κλικ, για τεχνικό/MSP/πελάτη.

Δεν κάνει δικούς της ελέγχους: μαζεύει ό,τι ήδη ξέρουν τα άλλα κομμάτια του NetWatch και το βάζει σε σειρά:
  • απογραφή συσκευών (IP, MAC, όνομα, κατασκευαστής, τύπος, πρώτη/τελευταία φορά)
  • ευρήματα με σοβαρότητα: κωδικοί/υπηρεσίες χωρίς κρυπτογράφηση (audit), rogue DHCP / ARP spoofing (l2guard),
    παραβιάσεις κατάτμησης (segcheck), εκτεθειμένες κάμερες (camexp), παράκαμψη DNS (encdns),
    απώλειες/jitter WAN (latency), υπηρεσίες που έπεσαν / πιστοποιητικά που λήγουν (health),
    συσκευές «πάντα αναμμένες» που χάνονται (presence), επιθέσεις 24ώρου (alerts)
  • βαθμός A–F και λίστα «διόρθωσε πρώτα αυτά»
Εξαγωγές: HTML για εκτύπωση/PDF, CSV απογραφής, CSV ευρημάτων, CSV διευθύνσεων για import στο NetBox, JSON.

«Τρέξε τους ελέγχους» (run): ξεκινά στο παρασκήνιο τους υπάρχοντες ελέγχους που χρειάζονται ενεργοποίηση —
rogue DHCP/ARP (μόνο τοπικό LAN), «Φταίει το δίκτυο;» (router/DNS/1.1.1.1) και σάρωση καμερών (μόνο ιδιωτικό
subnet, αν είναι ενεργή). Τίποτα άλλο: όλοι οι ενεργοί έλεγχοι μένουν σε ιδιωτικές διευθύνσεις, όπως πριν.

🙈 Χωρίς μυστικά: δεν μπαίνουν κωδικοί, ονόματα χρηστών, payloads ή pcap. Μόνο IP/MAC/ονόματα του LAN.
"""
import csv
import html
import io
import ipaddress
import math
import threading
import time

LANGS = ("el", "en")
SEV = {"high": 3, "med": 2, "low": 1, "info": 0}
PENALTY = {"high": 15, "med": 6, "low": 2, "info": 0}
AREA_CAP = 25  # ανά περιοχή: 10 port scans δεν «κοστίζουν» όσο 10 διαφορετικά προβλήματα
DECAY = 120    # βαθμός = 100·e^(−ποινή/120): 1 υψηλό ≈ 88 (B), 3 υψηλά ≈ 69 (C), πολλά → F αλλά όχι 0
MAX_FINDINGS = 80


def _L(lang, el, en):
    return en if lang == "en" else el


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:  # noqa: BLE001 — ένα κομμάτι που λείπει/σπάει δεν ρίχνει την αναφορά
        return default


def _ts(t, lang="el"):
    if not t:
        return "—"
    return time.strftime("%d/%m/%Y %H:%M" if lang == "el" else "%Y-%m-%d %H:%M", time.localtime(t))


def _ipkey(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, str(ip))


def grade(score):
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


# ---------------- ευρήματα ανά πηγή ----------------
AUDIT_TITLES = {
    "creds": ("Κωδικοί σε καθαρό κείμενο", "Cleartext passwords"),
    "services": ("Επικίνδυνες υπηρεσίες στο LAN", "Risky services on the LAN"),
    "attacks": ("Επιθέσεις την τελευταία ώρα", "Attacks in the last hour"),
    "intel": ("Επικοινωνία με γνωστές κακόβουλες IP", "Traffic to known malicious IPs"),
    "devices": ("Άγνωστες συσκευές", "Unknown devices"),
    "http": ("Ιστοσελίδες χωρίς HTTPS", "Websites without HTTPS"),
    "dns": ("DNS χωρίς κρυπτογράφηση", "Unencrypted DNS"),
}
AUDIT_EN = {
    "creds": ("Passwords were sent without encryption (FTP/Telnet/HTTP/POP3/IMAP…).",
              "Change those passwords and use the secure version: SFTP, SSH, HTTPS, IMAPS/POP3S."),
    "attacks": ("NetWatch saw attacks on the network in the last hour.", "Open the Alerts tab and handle the high-severity ones first."),
    "intel": ("A device talked to an IP on a threat-intelligence blocklist.", "Check that device for malware; block the IP."),
    "devices": ("New, unidentified devices appeared in the last hour.", "Confirm each one is yours; name it in NetWatch."),
    "http": ("A large share of web traffic is plain HTTP.", "Prefer HTTPS; check IoT devices that use HTTP."),
    "dns": ("DNS queries travel unencrypted.", "Consider DoH/DoT on the router or a local resolver."),
}


def _f(sev, area, title, detail, fix="", source="", ips=()):
    return {"sev": sev, "area": area, "title": title, "detail": detail, "fix": fix, "source": source, "ips": list(ips)[:20]}


def _audit_findings(state, lg):
    a = _safe(state.audit, None) if hasattr(state, "audit") else None
    if not a:
        return [], None
    out = []
    for c in a.get("checks") or []:
        if c.get("status") not in ("bad", "warn") or c.get("id") in ("services", "attacks"):  # επιθέσεις: από τα alerts 24ώρου
            continue
        cid = c.get("id")
        t = AUDIT_TITLES.get(cid, (c.get("title"), c.get("title")))
        det, fix = (c.get("detail"), c.get("advice")) if lg == "el" else AUDIT_EN.get(cid, (c.get("detail"), c.get("advice")))
        out.append(_f("high" if c.get("status") == "bad" else "med", _L(lg, "Ασφάλεια", "Security"), _L(lg, *t), det, fix, "audit"))
    from core import SERVICES
    by = {}
    for s in a.get("services") or []:
        svc = s.get("svc") or SERVICES.get(s.get("port")) or (s.get("why") or "").split(":")[0].strip() or f"TCP {s.get('port')}"
        by.setdefault((svc[:40], s.get("port"), s.get("risk") or "med"), []).append(s)
    for (svc, port, risk), rows in sorted(by.items(), key=lambda kv: -SEV.get(kv[0][2], 1)):
        ips = sorted({r.get("ip") for r in rows if r.get("ip")}, key=_ipkey)
        why = rows[0].get("why") or ""
        out.append(_f("high" if risk == "high" else "med" if risk == "med" else "low", _L(lg, "Υπηρεσίες", "Services"),
                      _L(lg, f"{svc} (θύρα {port}) σε {len(ips)} συσκευή(ές)", f"{svc} (port {port}) on {len(ips)} device(s)"),
                      why if lg == "el" else f"{svc} on port {port} is reachable on the LAN — a common way in for attackers.",
                      _L(lg, f"Κλείσε το {svc} ή αντικατέστησέ το με ασφαλή εκδοχή· αν χρειάζεται, περιόρισέ το σε συγκεκριμένες IP.",
                         f"Disable {svc} or replace it with a secure version; if needed, restrict it to specific IPs."), "audit", ips))
    return out, a


def _l2_findings(state, lg):
    lg2 = getattr(state, "l2guard", None)
    if not lg2:
        return []
    v = _safe(lg2.view, {}) or {}
    if v.get("never") or not v.get("checks"):
        return [_f("info", "L2", _L(lg, "Δεν έγινε έλεγχος rogue DHCP / ARP", "Rogue DHCP / ARP check not run"),
                   _L(lg, "Πάτα «Τρέξε τους ελέγχους» για να ελεγχθεί αν απαντά δεύτερος DHCP server ή αν κάποιος παριστάνει τον router.",
                      "Press “Run checks” to test for a second DHCP server or someone impersonating the router."), "", "l2guard")]
    out = []
    for c in v.get("checks") or []:
        lvl = c.get("level")
        if lvl not in ("bad", "warn"):
            continue
        title = {"dhcp": ("Rogue DHCP server", "Rogue DHCP server"), "arp": ("ARP spoofing / αλλαγή MAC router", "ARP spoofing / router MAC change")}
        out.append(_f("high" if lvl == "bad" else "med", "L2", _L(lg, *title.get(c.get("id"), ("Έλεγχος L2", "L2 check"))),
                      c.get(lg) or c.get("el") or "",
                      _L(lg, "Βρες τη συσκευή από τη MAC (πίνακας MAC του switch) και αποσύνδεσέ τη· ενεργοποίησε DHCP snooping / DAI αν το υποστηρίζει το switch.",
                         "Find the device by MAC (switch MAC table) and unplug it; enable DHCP snooping / DAI if the switch supports it."), "l2guard"))
    return out


def _seg_findings(state, lg):
    sc = getattr(state, "segcheck", None)
    if not sc:
        return []
    v = _safe(sc.view, {}) or {}
    out = []
    for r in v.get("rules") or []:
        if r.get("verdict") != "violation":
            continue
        opn = r.get("open") or []
        svc = ", ".join(sorted({f"{o.get('service') or o.get('port')}" for o in opn}))[:160]
        out.append(_f("high", _L(lg, "Κατάτμηση", "Segmentation"),
                      _L(lg, f"Το δίκτυο «{r.get('from')}» φτάνει στο «{r.get('to')}» ενώ δεν πρέπει",
                         f"Zone “{r.get('from')}” can reach “{r.get('to')}” but should not"),
                      _L(lg, f"Ανοιχτές υπηρεσίες: {svc}", f"Open services: {svc}"),
                      _L(lg, "Πρόσθεσε κανόνα deny στο firewall/router ανάμεσα στα δύο VLAN και ξανατρέξε τον έλεγχο.",
                         "Add a deny rule between the two VLANs on the firewall/router and re-run the check."),
                      "segcheck", [o.get("ip") for o in opn if o.get("ip")]))
    return out


def _cam_findings(state, lg):
    ce = getattr(state, "camexp", None)
    if not ce:
        return []
    v = _safe(ce.status, {}) or {}
    out = []
    for c in v.get("cameras") or []:
        verdict = c.get("verdict")
        if verdict not in ("red", "yellow"):
            continue
        name = c.get("name") or c.get("ip")
        issues = c.get("issues") or []
        out.append(_f("high" if verdict == "red" else "med", _L(lg, "Κάμερες", "Cameras"),
                      _L(lg, f"Εκτεθειμένη κάμερα: {name} ({c.get('vendor') or '?'})", f"Exposed camera: {name} ({c.get('vendor') or '?'})"),
                      (issues[0] if issues and lg == "el" else _L(lg, "", f"{len(issues)} issue(s) found on the camera's open ports.")),
                      ((c.get("fixes") or [""])[0] if lg == "el" else "Change the default password, update firmware, move cameras to their own VLAN, disable P2P cloud and UPnP."),
                      "camexp", [c.get("ip")]))
    return out


def _dns_findings(state, lg):
    ed = getattr(state, "encdns", None)
    if not ed:
        return []
    v = _safe(ed.status, {}) or {}
    devs = v.get("devices") or []
    if not devs:
        return []
    ips = sorted({d.get("ip") for d in devs if d.get("ip")}, key=_ipkey)
    meth = sorted({m for d in devs for m in (d.get("methods") or {})})
    return [_f("low", "DNS", _L(lg, f"{len(ips)} συσκευή(ές) παρακάμπτουν τον DNS του δικτύου", f"{len(ips)} device(s) bypass the network's DNS"),
               _L(lg, f"Μέθοδοι: {', '.join(meth)}. Τα φίλτρα (Pi-hole, γονικός έλεγχος) δεν τις καλύπτουν.",
                  f"Methods: {', '.join(meth)}. Filters (Pi-hole, parental control) don't cover them."),
               _L(lg, "Αν θες να ισχύει το φίλτρο παντού: μπλόκαρε στο router την έξοδο σε θύρα 53/853 εκτός από τον δικό σου DNS.",
                  "To enforce filtering: block outbound 53/853 on the router except for your own DNS."), "encdns", ips)]


def _wan_findings(state, lg):
    la = getattr(state, "latency", None)
    if not la:
        return [], []
    v = _safe(la.status, {}) or {}
    out, rows = [], []
    for t in v.get("targets") or []:
        last = t.get("last") or {}
        loss, jit, med = last.get("loss"), last.get("jitter"), last.get("med")
        rows.append({"name": t.get("name"), "host": t.get("host"), "role": t.get("role"), "med": med, "jitter": jit, "loss": loss})
        if loss is None:
            continue
        gw = t.get("role") == "gateway"
        if loss >= 0.05 or (jit or 0) > 30:
            out.append(_f("high" if gw and loss >= 0.05 else "med", "WAN",
                          _L(lg, f"Απώλειες/αστάθεια προς {t.get('name')} ({t.get('host')})", f"Loss/instability to {t.get('name')} ({t.get('host')})"),
                          _L(lg, f"Απώλεια {loss:.0%}, jitter {jit or 0:.0f} ms, διάμεσος {med or 0:.0f} ms.",
                             f"Loss {loss:.0%}, jitter {jit or 0:.0f} ms, median {med or 0:.0f} ms."),
                          _L(lg, "Αν χάνονται πακέτα ήδη προς τον router: καλώδιο/Wi-Fi. Αν μόνο έξω: πάροχος — δείξε του το γράφημα 📈 Latency.",
                             "If packets are lost already to the router: cable/Wi-Fi. If only beyond it: the ISP — show them the 📈 Latency graph."),
                          "latency", [t.get("host")]))
    return out, rows


def _health_findings(state, lg):
    he = getattr(state, "health", None)
    if not he:
        return []
    v = _safe(he.status, {}) or {}
    out = []
    for t in v.get("targets") or []:
        if t.get("up") is False:
            out.append(_f("med", _L(lg, "Υπηρεσίες", "Services"), _L(lg, f"Η υπηρεσία «{t.get('name')}» δεν απαντά", f"Service “{t.get('name')}” is down"),
                          str(t.get("err") or "")[:160], _L(lg, "Έλεγξε τη συσκευή/υπηρεσία.", "Check the device/service."), "health", [t.get("host")]))
        cd = t.get("cert_days")
        if isinstance(cd, (int, float)) and cd < 14:
            out.append(_f("med" if cd >= 0 else "high", "TLS",
                          _L(lg, f"Το πιστοποιητικό του «{t.get('name')}» λήγει σε {int(cd)} μέρες", f"Certificate of “{t.get('name')}” expires in {int(cd)} days"),
                          "", _L(lg, "Ανανέωσέ το (π.χ. Let's Encrypt).", "Renew it (e.g. Let's Encrypt)."), "health", [t.get("host")]))
    return out


def _presence_findings(state, lg):
    pr = getattr(state, "presence", None)
    if not pr:
        return []
    v = _safe(lambda: pr.view(days=7), {}) or {}
    flaky = [d for d in v.get("devices") or [] if d.get("always_on") and (d.get("pct") or 100) < 97]
    return [_f("low", _L(lg, "Διαθεσιμότητα", "Availability"),
               _L(lg, f"Η «{d.get('name') or d.get('ip')}» χάνεται από το δίκτυο", f"“{d.get('name') or d.get('ip')}” keeps dropping off"),
               _L(lg, f"Online {d.get('pct')}% της εβδομάδας, {d.get('outages')} διακοπές (μεγαλύτερη {d.get('longest_min')}′).",
                  f"Online {d.get('pct')}% of the week, {d.get('outages')} outages (longest {d.get('longest_min')} min)."),
               _L(lg, "Έλεγξε σήμα Wi-Fi/τροφοδοσία· δώσε σταθερή IP (DHCP reservation).",
                  "Check Wi-Fi signal/power; give it a fixed IP (DHCP reservation)."), "presence", [d.get("ip")]) for d in flaky[:10]]


def _alert_findings(state, lg, now):
    alerts = list(getattr(state, "alerts", None) or [])
    recent = [a for a in alerts if (a.get("t") or 0) >= now - 86400 and a.get("sev") in ("high", "med") and not a.get("benign")]
    if not recent:
        return []
    by = {}
    for a in recent:
        by.setdefault(a.get("type"), []).append(a)
    out = []
    for typ, rows in sorted(by.items(), key=lambda kv: (-max(SEV.get(a.get("sev"), 0) for a in kv[1]), -len(kv[1])))[:8]:
        sev = "high" if any(a.get("sev") == "high" for a in rows) else "med"
        actors = sorted({a.get("actor") for a in rows if a.get("actor")}, key=_ipkey)
        out.append(_f(sev, _L(lg, "Επιθέσεις", "Attacks"), _L(lg, f"{typ} ×{len(rows)} (24ώ)", f"{typ} ×{len(rows)} (24h)"),
                      _L(lg, f"Από: {', '.join(actors[:5])}", f"From: {', '.join(actors[:5])}"),
                      _L(lg, "Άνοιξε το alert → «🧐 Γιατί;» για το τι σημαίνει και τι να κάνεις.",
                         "Open the alert → “🧐 Why?” for what it means and what to do."), "alerts", actors))
    return out


# ---------------- απογραφή ----------------
def random_mac(mac):
    """«Locally administered» bit (2ο bit του 1ου byte): έτσι είναι οι ιδιωτικές MAC των κινητών."""
    try:
        return bool(int(str(mac)[:2], 16) & 2)
    except ValueError:
        return False

def inventory(state):
    import netdocs
    hosts = _safe(lambda: netdocs._collect_hosts(state), {}) or {}
    rows = []
    for h in sorted(hosts.values(), key=lambda h: _ipkey(h["ip"])):
        mac = (h.get("mac") or "").lower()
        rnd = random_mac(mac)
        rows.append({"ip": h["ip"], "mac": mac, "name": h.get("name") or "", "vendor": h.get("vendor") or "",
                     "type": h.get("type") or "", "icon": h.get("icon") or "", "first": h.get("first"), "last": h.get("last"),
                     "role": "router" if h.get("gw") else "this" if h.get("me") else "", "random_mac": rnd})
    return rows


def build(state, lang="el", now=None):
    lg = lang if lang in LANGS else "el"
    now = now or time.time()
    findings, audit = _audit_findings(state, lg)
    findings += _l2_findings(state, lg) + _seg_findings(state, lg) + _cam_findings(state, lg)
    wan, wan_rows = _wan_findings(state, lg)
    findings += wan + _health_findings(state, lg) + _dns_findings(state, lg) + _presence_findings(state, lg)
    findings += _alert_findings(state, lg, now)
    findings.sort(key=lambda f: -SEV.get(f["sev"], 0))
    findings = findings[:MAX_FINDINGS]
    inv = inventory(state)
    per_area = {}
    for f in findings:
        per_area[f["area"]] = per_area.get(f["area"], 0) + PENALTY.get(f["sev"], 0)
    score = int(round(100 * math.exp(-sum(min(AREA_CAP, p) for p in per_area.values()) / DECAY)))
    counts = {s: sum(1 for f in findings if f["sev"] == s) for s in SEV}
    fixes, seen = [], set()
    for f in findings:
        if f["sev"] in ("high", "med") and f["fix"] and f["fix"] not in seen:
            seen.add(f["fix"])
            fixes.append({"sev": f["sev"], "title": f["title"], "fix": f["fix"]})
    me = sorted(getattr(state, "me", None) or [])
    me4 = [i for i in me if ":" not in i]
    types = {}
    for r in inv:
        types[r["type"] or _L(lg, "άγνωστο", "unknown")] = types.get(r["type"] or _L(lg, "άγνωστο", "unknown"), 0) + 1
    return {
        "title": _L(lg, "Αναφορά αξιολόγησης δικτύου", "Network assessment report"),
        "lang": lg, "generated": now, "demo": getattr(state, "mode", "") == "demo",
        "network": {"gateway": getattr(state, "gateway", None), "iface": getattr(state, "iface", None),
                    "me": me4[0] if me4 else (me[0] if me else None),
                    "subnet": (me4[0].rsplit(".", 1)[0] + ".0/24") if me4 else None},
        "score": score, "grade": grade(score), "counts": counts,
        "summary": {"devices": len(inv), "new_24h": sum(1 for r in inv if (r["first"] or 0) >= now - 86400),
                    "random_mac": sum(1 for r in inv if r["random_mac"]), "unknown_vendor": sum(1 for r in inv if not r["vendor"]),
                    "types": dict(sorted(types.items(), key=lambda kv: -kv[1])[:12]),
                    "audit_score": (audit or {}).get("score")},
        "visibility": _L(lg, "Παθητική εικόνα: το NetWatch βλέπει την κίνηση αυτού του υπολογιστή, broadcast/multicast και ό,τι περνά από "
                             "εδώ. Για όλη την κίνηση χρειάζεται θύρα SPAN/mirror στο switch ή εγκατάσταση στο gateway.",
                         "Passive view: NetWatch sees this computer's traffic, broadcast/multicast and whatever passes through here. "
                         "For all traffic you need a SPAN/mirror port on the switch or an install on the gateway."),
        "findings": findings, "fixes": fixes[:10], "inventory": inv, "wan": wan_rows,
    }


# ---------------- «Τρέξε τους ελέγχους» ----------------
class Assess:
    def __init__(self, state, clock=time.time):
        self.state, self.clock = state, clock
        self.lock = threading.Lock()
        self.job = {"state": "idle"}

    def run(self, lang="el"):
        with self.lock:
            if self.job.get("state") == "running":
                return {"error": "already running"}
            self.job = {"state": "running", "started": self.clock(), "steps": []}
        threading.Thread(target=self._bg, args=(lang,), daemon=True).start()
        return {"ok": True, "job": dict(self.job)}

    def _bg(self, lang):
        st, steps = self.state, []

        def step(name, fn):
            obj = fn()
            if obj is None:
                steps.append({"id": name, "status": "skip"})
                return
            try:
                obj()
                steps.append({"id": name, "status": "ok"})
            except Exception as e:  # noqa: BLE001
                steps.append({"id": name, "status": "error", "error": str(e)[:160]})
            self.job["steps"] = list(steps)

        step("l2guard", lambda: getattr(st, "l2guard", None) and st.l2guard.run)
        step("triage", lambda: getattr(st, "triage", None) and (lambda: st.triage.run(lang=lang)))
        step("camexp", lambda: getattr(st, "camexp", None) and st.camexp.scan)
        self.job = {"state": "done", "started": self.job.get("started"), "finished": self.clock(), "steps": steps}

    def view(self):
        return dict(self.job)


# ---------------- εξαγωγές ----------------
def _csv(rows, head):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(head)
    for r in rows:
        w.writerow(["" if v is None else str(v).replace("\n", " ") for v in r])
    return "﻿" + buf.getvalue()  # BOM → το Excel ανοίγει σωστά τα ελληνικά


def to_inventory_csv(doc):
    lg = doc["lang"]
    return _csv([(r["ip"], r["mac"], r["name"], r["vendor"], r["type"], r["role"], "yes" if r["random_mac"] else "",
                  _ts(r["first"], lg), _ts(r["last"], lg)) for r in doc["inventory"]],
                ["ip", "mac", "name", "vendor", "type", "role", "random_mac", "first_seen", "last_seen"])


def to_findings_csv(doc):
    return _csv([(f["sev"], f["area"], f["title"], f["detail"], f["fix"], " ".join(i for i in f["ips"] if i), f["source"])
                 for f in doc["findings"]], ["severity", "area", "title", "detail", "fix", "ips", "source"])


def to_netbox_ips_csv(doc):
    """NetBox → IPAM → IP Addresses → Import (CSV): δεν χρειάζεται να υπάρχουν πρώτα devices/sites."""
    plen = 24
    try:
        plen = ipaddress.ip_network(doc["network"]["subnet"]).prefixlen if doc["network"].get("subnet") else 24
    except ValueError:
        pass
    rows = []
    for r in doc["inventory"]:
        if ":" in r["ip"]:
            continue
        desc = " · ".join(x for x in (r["type"], r["vendor"], r["mac"]) if x)
        dns = r["name"] if r["name"] and all(c.isalnum() or c in "-." for c in r["name"]) else ""
        rows.append((f"{r['ip']}/{plen}", "active", dns, desc[:200]))
    return _csv(rows, ["address", "status", "dns_name", "description"]).lstrip("﻿")


CSS = """
:root{color-scheme:light}body{font:14px/1.45 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;color:#1d2633;background:#fff;margin:0}
main{max-width:1000px;margin:0 auto;padding:28px 22px 60px}h1{margin:0 0 4px;font-size:24px}h2{margin:28px 0 8px;font-size:18px;border-bottom:2px solid #e4e9f0;padding-bottom:4px}
.meta{color:#5b6878;font-size:13px}.demo{background:#fff4d6;border:1px solid #f0d27a;padding:6px 10px;border-radius:8px;margin:12px 0;font-size:13px}
.top{display:flex;gap:18px;align-items:center;margin:18px 0;flex-wrap:wrap}.grade{width:84px;height:84px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;border:6px solid var(--c);color:var(--c);font-weight:700}
.grade b{font-size:30px;line-height:1}.grade span{font-size:11px}.cards{display:flex;gap:10px;flex-wrap:wrap}.card{border:1px solid #e4e9f0;border-radius:10px;padding:8px 12px;min-width:96px}
.card b{display:block;font-size:20px}.card span{color:#5b6878;font-size:12px}table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:6px}
th,td{text-align:left;padding:5px 7px;border-bottom:1px solid #edf1f5;vertical-align:top}th{background:#f5f7fa;font-weight:600}.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
.sev{display:inline-block;padding:1px 7px;border-radius:9px;font-size:11px;font-weight:700;color:#fff}.s-high{background:#d6334c}.s-med{background:#e08a1e}.s-low{background:#5b8def}.s-info{background:#8a97a8}
ol.fix li{margin:4px 0}.note{color:#5b6878;font-size:12.5px;margin-top:8px}.print{float:right;border:1px solid #c9d3df;background:#f5f7fa;border-radius:8px;padding:6px 12px;cursor:pointer}
@media print{.print{display:none}main{padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def to_html(doc):
    lg = doc["lang"]
    e = lambda v: html.escape("—" if v is None or v == "" else str(v))  # noqa: E731
    sevl = {"high": _L(lg, "Υψηλό", "High"), "med": _L(lg, "Μέτριο", "Medium"), "low": _L(lg, "Χαμηλό", "Low"), "info": "Info"}
    col = {"A": "#1f9d55", "B": "#5aa02c", "C": "#c99a06", "D": "#e07b1e", "F": "#d6334c"}[doc["grade"]]
    n, s = doc["network"], doc["summary"]
    h = ["<!doctype html>", f'<html lang="{lg}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
         f"<title>{e(doc['title'])} — NetWatch</title><style>{CSS}</style></head><body><main>",
         f'<button class="print" onclick="window.print()">{e(_L(lg, "Εκτύπωση / PDF", "Print / PDF"))}</button>',
         f"<h1>{e(doc['title'])}</h1>",
         f'<div class="meta">{e(_ts(doc["generated"], lg))} · {e(_L(lg, "δίκτυο", "network"))} {e(n.get("subnet"))} · gateway {e(n.get("gateway"))} · '
         f'{e(_L(lg, "από", "from"))} {e(n.get("me"))} ({e(n.get("iface"))})</div>']
    if doc.get("demo"):
        h.append(f'<div class="demo">{e(_L(lg, "Δεδομένα προσομοίωσης (demo)", "Simulated (demo) data"))}</div>')
    c = doc["counts"]
    cards = [(s["devices"], _L(lg, "συσκευές", "devices")), (s["new_24h"], _L(lg, "νέες 24ώ", "new 24h")), (c["high"], sevl["high"]),
             (c["med"], sevl["med"]), (c["low"], sevl["low"]), (s["random_mac"], _L(lg, "τυχαίες MAC", "random MACs"))]
    h.append(f'<div class="top"><div class="grade" style="--c:{col}"><b>{doc["grade"]}</b><span>{doc["score"]}/100</span></div>'
             '<div class="cards">' + "".join(f'<div class="card"><b>{e(v)}</b><span>{e(t)}</span></div>' for v, t in cards) + "</div></div>")
    h.append(f'<h2>{e(_L(lg, "Διόρθωσε πρώτα αυτά", "Fix these first"))}</h2>')
    if doc["fixes"]:
        h.append('<ol class="fix">' + "".join(f'<li><span class="sev s-{x["sev"]}">{e(sevl[x["sev"]])}</span> <b>{e(x["title"])}</b> — {e(x["fix"])}</li>'
                                              for x in doc["fixes"]) + "</ol>")
    else:
        h.append(f'<p>{e(_L(lg, "Τίποτα επείγον. 👍", "Nothing urgent. 👍"))}</p>')
    h.append(f'<h2>{e(_L(lg, "Ευρήματα", "Findings"))} ({len(doc["findings"])})</h2>')
    if doc["findings"]:
        h.append(f'<table><thead><tr><th>{e(_L(lg, "Σοβαρότητα", "Severity"))}</th><th>{e(_L(lg, "Περιοχή", "Area"))}</th>'
                 f'<th>{e(_L(lg, "Εύρημα", "Finding"))}</th><th>{e(_L(lg, "Τι να κάνεις", "What to do"))}</th><th>IP</th></tr></thead><tbody>')
        for f in doc["findings"]:
            h.append(f'<tr><td><span class="sev s-{f["sev"]}">{e(sevl[f["sev"]])}</span></td><td>{e(f["area"])}</td>'
                     f'<td><b>{e(f["title"])}</b><br>{e(f["detail"])}</td><td>{e(f["fix"])}</td><td class="mono">{e(", ".join(i for i in f["ips"][:6] if i))}</td></tr>')
        h.append("</tbody></table>")
    if doc["wan"]:
        h.append(f'<h2>{e(_L(lg, "Υγεία σύνδεσης (WAN/DNS)", "Connection health (WAN/DNS)"))}</h2><table><thead><tr><th>{e(_L(lg, "Στόχος", "Target"))}</th>'
                 f'<th>Host</th><th>{e(_L(lg, "Διάμεσος", "Median"))} ms</th><th>Jitter ms</th><th>{e(_L(lg, "Απώλεια", "Loss"))}</th></tr></thead><tbody>')
        for w in doc["wan"]:
            loss = "" if w["loss"] is None else f"{w['loss']:.0%}"
            h.append(f'<tr><td>{e(w["name"])}</td><td class="mono">{e(w["host"])}</td><td>{e(w["med"])}</td><td>{e(w["jitter"])}</td>'
                     f'<td>{e(loss)}</td></tr>')
        h.append("</tbody></table>")
    h.append(f'<h2>{e(_L(lg, "Απογραφή συσκευών", "Device inventory"))} ({len(doc["inventory"])})</h2>')
    h.append(f'<table><thead><tr><th>IP</th><th>MAC</th><th>{e(_L(lg, "Όνομα", "Name"))}</th><th>{e(_L(lg, "Κατασκευαστής", "Vendor"))}</th>'
             f'<th>{e(_L(lg, "Τύπος", "Type"))}</th><th>{e(_L(lg, "Πρώτη φορά", "First seen"))}</th></tr></thead><tbody>')
    for r in doc["inventory"]:
        role = {"router": " (router)", "this": _L(lg, " (αυτός ο υπολογιστής)", " (this computer)")}.get(r["role"], "")
        h.append(f'<tr><td class="mono">{e(r["ip"])}</td><td class="mono">{e(r["mac"])}{" ⚂" if r["random_mac"] else ""}</td>'
                 f'<td>{e((r["icon"] + " " if r["icon"] else "") + (r["name"] or "") + role)}</td><td>{e(r["vendor"])}</td><td>{e(r["type"])}</td><td>{e(_ts(r["first"], lg))}</td></tr>')
    h.append("</tbody></table>")
    h.append(f'<p class="note">⚂ = {e(_L(lg, "τυχαία (ιδιωτική) MAC — συνήθως κινητό με «Private Wi-Fi address».", "randomized (private) MAC — usually a phone with “Private Wi-Fi address”."))}</p>')
    h.append(f'<p class="note">👁 {e(doc["visibility"])}</p>')
    h.append(f'<p class="note">NetWatch · {e(_L(lg, "παθητική ανάλυση· ενεργοί έλεγχοι μόνο σε ιδιωτικές διευθύνσεις· χωρίς κωδικούς ή περιεχόμενο κίνησης.", "passive analysis; active checks only on private addresses; no passwords or traffic content."))}</p>')
    h.append("</main></body></html>")
    return "\n".join(h)


def filename(kind, now=None):
    d = time.strftime("%Y%m%d-%H%M", time.localtime(now or time.time()))
    return {"html": f"netwatch-assessment-{d}.html", "inventory": f"netwatch-inventory-{d}.csv",
            "findings": f"netwatch-findings-{d}.csv", "netbox": f"netbox-ip-addresses-{d}.csv",
            "json": f"netwatch-assessment-{d}.json"}[kind]
