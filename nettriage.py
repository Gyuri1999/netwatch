"""🩺 «Φταίει το δίκτυο;» — διάγνωση με ένα κλικ και κείμενο έτοιμο για ticket.

Τρέχει με τη σειρά τους κλασικούς ελέγχους ενός τεχνικού helpdesk, από κάτω προς τα πάνω (OSI):
  1 link       ενεργή διεπαφή με IPv4 (169.254.x = APIPA → δεν πήρε IP από DHCP)
  2 dhcp       υπάρχουν gateway και DNS servers
  3 gateway    ping/TCP στο router, απώλειες
  4 dns_local  επίλυση μέσω των DNS που έδωσε το DHCP
  5 dns_public επίλυση μέσω 1.1.1.1 (αν το τοπικό αποτυγχάνει και το δημόσιο δουλεύει → «It's always DNS»)
  6 internet   TCP 443 προς 1.1.1.1 / 8.8.8.8
  7 captive    captive portal (ξενοδοχείο/καφετέρια): ανακατεύθυνση ή HTML αντί για 204/«Success»
  8 mtu        ping με DF και 1472 bytes (MTU 1500)· αποτυχία → PPPoE/VPN
  9 quality    10 ping σε gateway και 1.1.1.1: απώλειες, μέση καθυστέρηση, jitter

Ενεργοί έλεγχοι ΜΟΝΟ προς ιδιωτικές διευθύνσεις και το σταθερό σύνολο 1.1.1.1 / 8.8.8.8 / 9.9.9.9 / captive URL
(βλ. changecheck.allowed). Στο demo δεν αγγίζουμε καθόλου το δίκτυο: το `scenario` διαλέγει την «ιστορία».
Το ticket δεν περιέχει μυστικά ούτε MAC άλλων συσκευών.

API
---
Triage(state, sim=False, clock=time.time)
  .run(lang="el", scenario=None) → view() (ξεκινά στο παρασκήνιο) | {error}
  .view() → {status:"idle"|"running"|"done", started, finished, lang, steps:[{id,title,status,detail,ms,fix}],
             verdict:{layer,text,fix}|None, ticket, scenarios, demo}
"""
import random
import socket
import threading
import time

import changecheck as cc

LANGS = ("el", "en")
SCENARIOS = ["ok", "dns", "gateway", "captive", "dhcp", "mtu"]
STEP_IDS = ["link", "dhcp", "gateway", "dns_local", "dns_public", "internet", "captive", "mtu", "quality"]
LAYER = {"link": "L1/L2", "dhcp": "DHCP", "gateway": "Gateway", "dns_local": "DNS", "dns_public": "DNS",
         "internet": "Internet/ISP", "captive": "Captive portal", "mtu": "MTU", "quality": "Quality"}
# σειρά προτεραιότητας για το συμπέρασμα: το captive portal εξηγεί το «κομμένο» internet, το κομμένο internet
# εξηγεί το DNS που δεν απαντά (ο router προωθεί σε DNS του ISP)
PRIORITY = ["link", "dhcp", "gateway", "captive", "internet", "dns_local", "dns_public", "mtu", "quality"]
TITLES = {
    "link": ("Σύνδεση (διεπαφή)", "Link (interface)"),
    "dhcp": ("DHCP (IP, gateway, DNS)", "DHCP (IP, gateway, DNS)"),
    "gateway": ("Router (gateway)", "Router (gateway)"),
    "dns_local": ("DNS του δικτύου", "Local DNS"),
    "dns_public": ("Δημόσιο DNS (1.1.1.1)", "Public DNS (1.1.1.1)"),
    "internet": ("Internet (TCP 443)", "Internet (TCP 443)"),
    "captive": ("Captive portal", "Captive portal"),
    "mtu": ("MTU (1500)", "MTU (1500)"),
    "quality": ("Ποιότητα (απώλειες/jitter)", "Quality (loss/jitter)"),
}
TAG = {"ok": "[OK]  ", "warn": "[WARN]", "fail": "[FAIL]", "skip": "[SKIP]", "pending": "[....]", "running": "[....]"}
LOSS_WARN = 2.0
JITTER_WARN = 30.0
DNS_TEST = "google.com"
_sleep = time.sleep  # τα tests το αντικαθιστούν


def _L(lang, el, en):
    return en if lang == "en" else el


def _ms(v):
    return "—" if v is None else f"{v:.1f} ms" if v < 100 else f"{v:.0f} ms"


class Triage:
    def __init__(self, state, sim=False, clock=time.time):
        self.st, self.sim, self.clock = state, sim, clock
        self.lock = threading.RLock()
        self.status = "idle"
        self.started = self.finished = None
        self.lang = "el"
        self.steps = []
        self.verdict = None
        self.ticket = ""
        self.info = {}
        self.scenario = None
        self.runs = 0

    # ───────── δημόσιο API ─────────
    def run(self, lang="el", scenario=None):
        lang = lang if lang in LANGS else "el"
        if scenario is not None and scenario not in SCENARIOS:
            raise ValueError(_L(lang, "Άγνωστο σενάριο", "Unknown scenario"))
        with self.lock:
            if self.status == "running":
                return {"error": _L(lang, "Τρέχει ήδη… περίμενε να τελειώσει.", "Already running… please wait.")}
            self.status, self.lang = "running", lang
            self.started, self.finished = self.clock(), None
            self.steps = [self._step(i, "pending") for i in STEP_IDS]
            self.verdict, self.ticket, self.info = None, "", {}
            self.scenario = (scenario or ("dns" if self.runs == 0 else "ok")) if self.sim else None
            self.runs += 1
        threading.Thread(target=self._worker, daemon=True, name="nw-triage").start()
        return self.view()

    def view(self):
        with self.lock:
            return {"status": self.status, "started": self.started, "finished": self.finished, "lang": self.lang,
                    "steps": [dict(s) for s in self.steps], "verdict": dict(self.verdict) if self.verdict else None,
                    "ticket": self.ticket, "scenarios": list(SCENARIOS) if self.sim else [],
                    "scenario": self.scenario, "demo": bool(self.sim)}

    # ───────── εσωτερικά ─────────
    def _step(self, sid, status, detail="", ms=None, fix=None):
        return {"id": sid, "title": TITLES[sid][1 if self.lang == "en" else 0], "status": status,
                "detail": detail, "ms": ms, "fix": fix}

    def _set(self, sid, **kw):
        with self.lock:
            s = next(x for x in self.steps if x["id"] == sid)
            s.update(kw)

    def _res(self, sid):
        return next(x for x in self.steps if x["id"] == sid)

    def _worker(self):
        try:
            if self.sim:
                self._demo()
            else:
                self._live()
        except Exception as e:  # δεν αφήνουμε ποτέ το «running» να κολλήσει
            with self.lock:
                for s in self.steps:
                    if s["status"] in ("pending", "running"):
                        s.update(status="skip", detail=_L(self.lang, "διακόπηκε: ", "aborted: ") + str(e)[:100])
        with self.lock:
            self.verdict = self._verdict()
            self.ticket = self._ticket()
            self.finished = self.clock()
            self.status = "done"

    def _do(self, sid, fn):
        """Τρέχει έναν έλεγχο: running → (status, detail, fix) με μέτρηση χρόνου. Ποτέ εξαίρεση."""
        self._set(sid, status="running")
        t0 = time.monotonic()
        try:
            status, detail, fix = fn()
        except Exception as e:
            status, detail, fix = "warn", _L(self.lang, "ο έλεγχος απέτυχε: ", "check failed: ") + str(e)[:100], None
        self._set(sid, status=status, detail=detail, fix=fix, ms=int((time.monotonic() - t0) * 1000))
        return status

    def _skip_rest(self, after, why):
        i = STEP_IDS.index(after)
        for sid in STEP_IDS[i + 1:]:
            if self._res(sid)["status"] == "pending":
                self._set(sid, status="skip", detail=why)

    # ───────── live ─────────
    def _live(self):
        L = lambda el, en: _L(self.lang, el, en)  # noqa: E731
        info = cc.local_info()
        self.info = info
        res = {}

        def link():
            name, ip = info.get("iface"), info.get("ip")
            kind = {"wifi": "Wi‑Fi", "ethernet": "Ethernet", "vpn": "VPN"}.get(info.get("kind"))
            nm = f"{name} ({kind})" if name and kind else (name or "?")
            if not name or not info.get("up"):
                return "fail", L("Καμία ενεργή διεπαφή δικτύου", "No active network interface"), \
                    L("Έλεγξε καλώδιο/Wi‑Fi (είσαι συνδεδεμένος στο σωστό δίκτυο;) και αν η κάρτα δικτύου είναι ενεργή.",
                      "Check the cable/Wi‑Fi (are you on the right network?) and that the adapter is enabled.")
            if not ip:
                return "fail", L(f"{nm}: χωρίς διεύθυνση IPv4", f"{nm}: no IPv4 address"), \
                    L("Αποσύνδεση/επανασύνδεση στο δίκτυο ή «Ανανέωση DHCP lease».", "Disconnect/reconnect or renew the DHCP lease.")
            if ip.startswith("169.254."):
                res["apipa"] = True
                return "fail", L(f"{nm}: {ip} (APIPA) — δεν πήρε IP από DHCP", f"{nm}: {ip} (APIPA) — no address from DHCP"), \
                    L("Ο DHCP server (router) δεν απαντά: επανεκκίνηση router, έλεγξε καλώδιο/VLAN της θύρας ή το DHCP pool.",
                      "The DHCP server (router) is not answering: restart the router, check the cable/port VLAN or the DHCP pool.")
            pre = f"/{info['prefix']}" if info.get("prefix") else ""
            return "ok", L(f"{nm} ενεργή · IPv4 {ip}{pre}", f"{nm} up · IPv4 {ip}{pre}"), None

        if self._do("link", link) == "fail":
            if res.get("apipa"):
                self._do("dhcp", lambda: ("fail", L("Δεν πήρε διεύθυνση από DHCP (ούτε gateway/DNS)",
                                                    "No DHCP lease (no gateway/DNS either)"), None))
            self._skip_rest("dhcp" if res.get("apipa") else "link", L("παραλείφθηκε — δεν υπάρχει σύνδεση", "skipped — no link"))
            return
        gw, dns = info.get("gateway"), info.get("dns") or []

        def dhcp():
            if not gw and not dns:
                return "fail", L("Ούτε gateway ούτε DNS servers", "Neither gateway nor DNS servers"), \
                    L("Ανανέωσε το DHCP lease ή έλεγξε τις στατικές ρυθμίσεις IP.", "Renew the DHCP lease or check the static IP settings.")
            if not gw:
                return "fail", L(f"Χωρίς default gateway · DNS {', '.join(dns)}", f"No default gateway · DNS {', '.join(dns)}"), \
                    L("Λείπει η «Πύλη» (router) — ανανέωσε το DHCP lease ή διόρθωσε τη στατική ρύθμιση.",
                      "The default gateway (router) is missing — renew the DHCP lease or fix the static config.")
            if not dns:
                return "fail", L(f"Gateway {gw} · κανένας DNS server", f"Gateway {gw} · no DNS servers"), \
                    L("Βάλε DNS (π.χ. το router ή 1.1.1.1) ή διόρθωσε το DHCP του router.",
                      "Set a DNS server (e.g. the router or 1.1.1.1) or fix the router's DHCP.")
            return "ok", f"Gateway {gw} · DNS {', '.join(dns)}", None

        self._do("dhcp", dhcp)

        def gateway():
            if not gw:
                return "skip", L("δεν υπάρχει gateway", "no gateway"), None
            if not cc.allowed(gw):
                return "skip", L(f"το gateway {gw} δεν είναι ιδιωτική IP — δεν ελέγχεται", f"gateway {gw} is not private — not probed"), None
            r = cc.ping(gw, count=4, interval=0.2, timeout=1.0)
            res["gw_ping"] = r
            if r.get("ok"):
                st = "warn" if r["loss_pct"] > 0 else "ok"
                return st, L(f"{gw} απαντά · απώλειες {r['loss_pct']:g}% · μέσο {_ms(r['avg'])}",
                             f"{gw} replies · loss {r['loss_pct']:g}% · avg {_ms(r['avg'])}"), \
                    (L("Απώλειες ήδη μέχρι το router: έλεγξε σήμα Wi‑Fi/καλώδιο.", "Loss already to the router: check Wi‑Fi signal/cable.")
                     if st == "warn" else None)
            for p in (80, 443, 53):
                t = cc.tcp(gw, p, timeout=1.0)
                if t["state"] in ("open", "closed"):
                    res["gw_tcp"] = True
                    return "ok", L(f"{gw}: δεν απαντά σε ping αλλά απαντά σε TCP/{p} ({_ms(t['ms'])})",
                                   f"{gw}: no ping reply but answers TCP/{p} ({_ms(t['ms'])})"), None
            return "fail", L(f"{gw} δεν απαντά (ping 100% απώλειες, ούτε TCP)", f"{gw} does not answer (100% ping loss, no TCP)"), \
                L("Επανεκκίνηση router· έλεγξε καλώδιο/Wi‑Fi και ότι είσαι στο σωστό VLAN/SSID.",
                  "Restart the router; check cable/Wi‑Fi and that you are on the right VLAN/SSID.")

        gst = self._do("gateway", gateway)

        def dns_local():
            if not dns:
                return "skip", L("δεν υπάρχουν DNS servers", "no DNS servers"), None
            rows, ok = [], False
            for srv in dns[:2]:
                r = cc.dns_query(DNS_TEST, srv, 1.5) if cc.allowed(srv) else cc.sys_resolve(DNS_TEST, 2.0)
                via = srv if cc.allowed(srv) else L(f"{srv} (μέσω συστήματος)", f"{srv} (via system)")
                rows.append(f"{via}: " + (f"{r['ip']} ({_ms(r['ms'])})" if r["ok"] else L("αποτυχία", "failed")))
                ok = ok or r["ok"]
            res["dns_local_ok"] = ok
            if ok:
                return "ok", f"{DNS_TEST} → " + " · ".join(rows), None
            return "fail", f"{DNS_TEST} → " + " · ".join(rows), \
                L("Ο DNS του δικτύου (router/Pi-hole) δεν απαντά: restart router/Pi-hole ή βάλε προσωρινά DNS 1.1.1.1.",
                  "The network's DNS (router/Pi-hole) is not answering: restart it or temporarily use DNS 1.1.1.1.")

        self._do("dns_local", dns_local)

        def dns_public():
            r = cc.dns_query(DNS_TEST, "1.1.1.1", 1.5)
            if not r["ok"]:
                r2 = cc.dns_query(DNS_TEST, "9.9.9.9", 1.5)
                if r2["ok"]:
                    return "warn", L(f"1.1.1.1 δεν απάντησε· 9.9.9.9: {r2['ip']} ({_ms(r2['ms'])})",
                                     f"1.1.1.1 did not answer; 9.9.9.9: {r2['ip']} ({_ms(r2['ms'])})"), None
                res["dns_public_ok"] = False
                return "fail", L("1.1.1.1 και 9.9.9.9 δεν απαντούν (UDP 53)", "1.1.1.1 and 9.9.9.9 do not answer (UDP 53)"), \
                    L("Ίσως μπλοκάρεται η θύρα 53 προς τα έξω ή δεν υπάρχει internet.", "Outbound port 53 may be blocked, or there is no internet.")
            res["dns_public_ok"] = True
            return "ok", f"{DNS_TEST} → {r['ip']} ({_ms(r['ms'])})", None

        self._do("dns_public", dns_public)

        def internet():
            a, b = cc.tcp("1.1.1.1", 443, 2.0), cc.tcp("8.8.8.8", 443, 2.0)
            oa, ob = a["state"] == "open", b["state"] == "open"
            res["internet_ok"] = oa or ob
            d = f"1.1.1.1:443 {('OK ' + _ms(a['ms'])) if oa else L('αποτυχία', 'failed')} · " \
                f"8.8.8.8:443 {('OK ' + _ms(b['ms'])) if ob else L('αποτυχία', 'failed')}"
            if oa and ob:
                return "ok", d, None
            if oa or ob:
                return "warn", d, None
            return "fail", d, L("Δεν υπάρχει έξοδος στο internet: έλεγξε τα λαμπάκια WAN/DSL του router ή κάλεσε τον πάροχο (ISP).",
                                "No route to the internet: check the router's WAN/DSL lights or call the ISP.")

        ist = self._do("internet", internet)

        def captive():
            r = cc.http_probe(cc.CAPTIVE_URLS[0], 3.0)
            g = cc.http_probe(cc.CAPTIVE_URLS[1], 3.0)
            apple_ok = r.get("status") == 200 and "success" in (r.get("body") or "").lower()
            g_ok = g.get("status") == 204
            if apple_ok or g_ok:
                return "ok", L("Κανένα captive portal (204 / «Success»)", "No captive portal (204 / \"Success\")"), None
            for x in (r, g):
                if x.get("status") in (301, 302, 303, 307, 308):
                    return "fail", L(f"Ανακατεύθυνση HTTP {x['status']} → {str(x.get('location') or '')[:80]}",
                                     f"HTTP {x['status']} redirect → {str(x.get('location') or '')[:80]}"), \
                        L("Άνοιξε έναν browser σε μια http:// σελίδα και κάνε login/αποδοχή όρων στο portal.",
                          "Open a browser on any http:// page and log in / accept the terms on the portal.")
                if x.get("status") == 200:
                    return "fail", L("Επιστράφηκε σελίδα HTML αντί για 204/«Success»", "Got an HTML page instead of 204/\"Success\""), \
                        L("Άνοιξε έναν browser και κάνε login στο captive portal.", "Open a browser and log in to the captive portal.")
            if not res.get("internet_ok"):
                return "skip", L("παραλείφθηκε — δεν υπάρχει internet", "skipped — no internet"), None
            return "warn", L("Ο έλεγχος HTTP δεν ολοκληρώθηκε (μπλοκάρεται το HTTP ή το DNS;)",
                             "HTTP check did not complete (HTTP or DNS blocked?)"), None

        self._do("captive", captive)

        def mtu():
            if gst == "fail" or not gw or not cc.allowed(gw):
                return "skip", L("παραλείφθηκε — το gateway δεν απαντά", "skipped — gateway not reachable"), None
            if res.get("gw_tcp") and not (res.get("gw_ping") or {}).get("ok"):
                return "skip", L("παραλείφθηκε — το gateway δεν απαντά σε ping", "skipped — gateway ignores ping"), None
            r = cc.ping(gw, count=2, interval=0.2, timeout=1.0, size=1472, df=True)
            if r.get("err") in ("noflag", "noping"):
                return "skip", L("το ping αυτής της πλατφόρμας δεν υποστηρίζει DF", "this platform's ping lacks the DF flag"), None
            if not r.get("ok"):
                return "fail", L(f"1472 bytes με DF προς {gw} δεν περνούν — MTU < 1500 στο LAN",
                                 f"1472 bytes with DF to {gw} do not pass — MTU < 1500 on the LAN"), \
                    L("Έλεγξε MTU διεπαφής/switch (jumbo/VLAN tagging) ή VPN· βάλε MTU 1500 ή MSS clamping.",
                      "Check interface/switch MTU (VLAN tagging) or VPN; set MTU 1500 or enable MSS clamping.")
            if ist != "fail":
                small = cc.ping("1.1.1.1", count=1, timeout=1.5)
                big = cc.ping("1.1.1.1", count=2, interval=0.2, timeout=1.5, size=1472, df=True) if small.get("ok") else None
                if big is not None and not big.get("ok"):
                    return "warn", L("Το LAN περνά 1500, αλλά προς το internet όχι (1472+DF → 1.1.1.1) — πιθανό PPPoE/VPN (MTU 1492)",
                                     "LAN passes 1500 but the internet path does not (1472+DF → 1.1.1.1) — likely PPPoE/VPN (MTU 1492)"), \
                        L("Σε PPPoE βάλε MTU 1492 στο router ή ενεργοποίησε MSS clamping· στο VPN μείωσε το MTU του tunnel.",
                          "On PPPoE set MTU 1492 on the router or enable MSS clamping; on a VPN lower the tunnel MTU.")
            return "ok", L(f"1472 bytes με DF περνούν (MTU 1500) · {_ms(r['avg'])}", f"1472 bytes with DF pass (MTU 1500) · {_ms(r['avg'])}"), None

        self._do("mtu", mtu)

        def quality():
            targets = ([gw] if gw and gst != "fail" and cc.allowed(gw) else []) + (["1.1.1.1"] if ist != "fail" else [])
            if not targets:
                return "skip", L("παραλείφθηκε — κανένας στόχος δεν απαντά", "skipped — no reachable target"), None
            out = {}
            ths = [threading.Thread(target=lambda t=t: out.__setitem__(t, cc.ping(t, count=10, interval=0.2, timeout=1.0)))
                   for t in targets]
            for t in ths:
                t.start()
            for t in ths:
                t.join(10)
            parts, bad = [], False
            for t in targets:
                r = out.get(t) or {}
                if r.get("err") == "noping":
                    continue
                parts.append(f"{t}: {L('απώλειες', 'loss')} {r.get('loss_pct', 100):g}% · {L('μέσο', 'avg')} {_ms(r.get('avg'))} · "
                             f"jitter {_ms(r.get('jitter'))}")
                bad = bad or (r.get("loss_pct") or 0) > LOSS_WARN or (r.get("jitter") or 0) > JITTER_WARN
            if not parts:
                return "skip", L("δεν υπάρχει εντολή ping", "ping is not available"), None
            if bad:
                return "warn", " | ".join(parts), L("Απώλειες/jitter: μετακινήσου πιο κοντά στο Wi‑Fi ή δοκίμασε καλώδιο· αν είναι μόνο προς 1.1.1.1, πρόβλημα γραμμής/ISP.",
                                                    "Loss/jitter: move closer to the Wi‑Fi or try a cable; if only towards 1.1.1.1, it's the line/ISP.")
            return "ok", " | ".join(parts), None

        self._do("quality", quality)

    # ───────── demo ─────────
    def _demo(self):
        L = lambda el, en: _L(self.lang, el, en)  # noqa: E731
        sc = self.scenario or "dns"
        rnd = random.Random()
        self.info = {"iface": "en0", "up": True, "ip": "192.168.1.23", "prefix": 24, "mtu": 1500, "gateway": "192.168.1.1",
                     "dns": ["192.168.1.1"], "kind": "wifi", "host": "MacBook-Pro"}
        F = {  # βήμα → (status, detail, fix) ανά σενάριο· None = προεπιλογή (OK)
            "link": ("ok", L("en0 (Wi‑Fi) ενεργή · IPv4 192.168.1.23/24", "en0 (Wi‑Fi) up · IPv4 192.168.1.23/24"), None),
            "dhcp": ("ok", "Gateway 192.168.1.1 · DNS 192.168.1.1", None),
            "gateway": ("ok", L(f"192.168.1.1 απαντά · απώλειες 0% · μέσο {rnd.uniform(1.8, 3.2):.1f} ms",
                                f"192.168.1.1 replies · loss 0% · avg {rnd.uniform(1.8, 3.2):.1f} ms"), None),
            "dns_local": ("ok", f"google.com → 192.168.1.1: 142.250.184.110 ({rnd.uniform(3, 9):.1f} ms)", None),
            "dns_public": ("ok", f"google.com → 142.250.184.110 ({rnd.uniform(12, 20):.1f} ms)", None),
            "internet": ("ok", f"1.1.1.1:443 OK {rnd.uniform(11, 16):.1f} ms · 8.8.8.8:443 OK {rnd.uniform(14, 22):.1f} ms", None),
            "captive": ("ok", L("Κανένα captive portal (204 / «Success»)", "No captive portal (204 / \"Success\")"), None),
            "mtu": ("ok", L(f"1472 bytes με DF περνούν (MTU 1500) · {rnd.uniform(2, 3.5):.1f} ms",
                            f"1472 bytes with DF pass (MTU 1500) · {rnd.uniform(2, 3.5):.1f} ms"), None),
            "quality": ("ok", L(f"192.168.1.1: απώλειες 0% · μέσο {rnd.uniform(2, 3.5):.1f} ms · jitter {rnd.uniform(0.3, 1.2):.1f} ms | "
                                f"1.1.1.1: απώλειες 0% · μέσο {rnd.uniform(12, 16):.1f} ms · jitter {rnd.uniform(0.8, 3):.1f} ms",
                                f"192.168.1.1: loss 0% · avg {rnd.uniform(2, 3.5):.1f} ms · jitter {rnd.uniform(0.3, 1.2):.1f} ms | "
                                f"1.1.1.1: loss 0% · avg {rnd.uniform(12, 16):.1f} ms · jitter {rnd.uniform(0.8, 3):.1f} ms"), None),
        }
        if sc == "dns":
            F["dns_local"] = ("fail", L("google.com → 192.168.1.1: αποτυχία (timeout 1.5 s)", "google.com → 192.168.1.1: failed (timeout 1.5 s)"),
                              L("Ο DNS του δικτύου (router/Pi-hole) δεν απαντά: restart router/Pi-hole ή βάλε προσωρινά DNS 1.1.1.1.",
                                "The network's DNS (router/Pi-hole) is not answering: restart it or temporarily use DNS 1.1.1.1."))
            F["captive"] = ("warn", L("Ο έλεγχος HTTP δεν ολοκληρώθηκε (δεν λύνονται ονόματα)", "HTTP check did not complete (names do not resolve)"), None)
        elif sc == "gateway":
            F["gateway"] = ("fail", L("192.168.1.1 δεν απαντά (ping 100% απώλειες, ούτε TCP)", "192.168.1.1 does not answer (100% ping loss, no TCP)"),
                            L("Επανεκκίνηση router· έλεγξε καλώδιο/Wi‑Fi και ότι είσαι στο σωστό VLAN/SSID.",
                              "Restart the router; check cable/Wi‑Fi and that you are on the right VLAN/SSID."))
            F["dns_local"] = ("fail", L("google.com → 192.168.1.1: αποτυχία", "google.com → 192.168.1.1: failed"), None)
            F["dns_public"] = ("fail", L("1.1.1.1 και 9.9.9.9 δεν απαντούν (UDP 53)", "1.1.1.1 and 9.9.9.9 do not answer (UDP 53)"), None)
            F["internet"] = ("fail", L("1.1.1.1:443 αποτυχία · 8.8.8.8:443 αποτυχία", "1.1.1.1:443 failed · 8.8.8.8:443 failed"), None)
            for s in ("captive", "mtu", "quality"):
                F[s] = ("skip", L("παραλείφθηκε — το gateway δεν απαντά", "skipped — gateway not reachable"), None)
        elif sc == "captive":
            F["internet"] = ("fail", L("1.1.1.1:443 αποτυχία · 8.8.8.8:443 αποτυχία", "1.1.1.1:443 failed · 8.8.8.8:443 failed"), None)
            F["dns_public"] = ("fail", L("1.1.1.1 και 9.9.9.9 δεν απαντούν (UDP 53)", "1.1.1.1 and 9.9.9.9 do not answer (UDP 53)"), None)
            F["captive"] = ("fail", L("Ανακατεύθυνση HTTP 302 → http://192.168.1.1:8002/index.php?zone=guest",
                                      "HTTP 302 redirect → http://192.168.1.1:8002/index.php?zone=guest"),
                            L("Άνοιξε έναν browser σε μια http:// σελίδα και κάνε login/αποδοχή όρων στο portal.",
                              "Open a browser on any http:// page and log in / accept the terms on the portal."))
            F["quality"] = ("ok", L(f"192.168.1.1: απώλειες 0% · μέσο {rnd.uniform(2, 3.5):.1f} ms · jitter 0.6 ms",
                                    f"192.168.1.1: loss 0% · avg {rnd.uniform(2, 3.5):.1f} ms · jitter 0.6 ms"), None)
        elif sc == "dhcp":
            self.info.update(ip="169.254.83.17", prefix=16, gateway=None, dns=[])
            F["link"] = ("fail", L("en0 (Wi‑Fi): 169.254.83.17 (APIPA) — δεν πήρε IP από DHCP",
                                   "en0 (Wi‑Fi): 169.254.83.17 (APIPA) — no address from DHCP"),
                         L("Ο DHCP server (router) δεν απαντά: επανεκκίνηση router, έλεγξε καλώδιο/VLAN της θύρας ή το DHCP pool.",
                           "The DHCP server (router) is not answering: restart the router, check the cable/port VLAN or the DHCP pool."))
            F["dhcp"] = ("fail", L("Δεν πήρε διεύθυνση από DHCP (ούτε gateway/DNS)", "No DHCP lease (no gateway/DNS either)"), None)
            for s in STEP_IDS[2:]:
                F[s] = ("skip", L("παραλείφθηκε — δεν υπάρχει σύνδεση", "skipped — no link"), None)
        elif sc == "mtu":
            F["mtu"] = ("fail", L("1472 bytes με DF δεν περνούν — περνούν έως 1464 (MTU 1492, PPPoE/VPN)",
                                  "1472 bytes with DF do not pass — up to 1464 do (MTU 1492, PPPoE/VPN)"),
                        L("Σε PPPoE βάλε MTU 1492 στο router ή ενεργοποίησε MSS clamping· στο VPN μείωσε το MTU του tunnel.",
                          "On PPPoE set MTU 1492 on the router or enable MSS clamping; on a VPN lower the tunnel MTU."))
        for sid in STEP_IDS:
            st, detail, fix = F[sid]
            if st == "skip":
                self._set(sid, status="skip", detail=detail, ms=0)
                continue
            self._set(sid, status="running")
            d = rnd.uniform(0.4, 0.8) if sid not in ("quality",) else rnd.uniform(0.7, 0.8)
            _sleep(d)
            ms = int(d * 1000) if st != "fail" or sid not in ("dns_local", "gateway") else int(rnd.uniform(1500, 2100))
            self._set(sid, status=st, detail=detail, fix=fix, ms=ms)

    # ───────── συμπέρασμα & ticket ─────────
    def _verdict(self):
        L = lambda el, en: _L(self.lang, el, en)  # noqa: E731
        by = {s["id"]: s for s in self.steps}
        pick = next((sid for sid in PRIORITY if by[sid]["status"] == "fail"), None) or \
            next((sid for sid in PRIORITY if by[sid]["status"] == "warn" and sid != "captive"), None)
        if pick is None:
            return {"layer": "OK", "text": L("Το δίκτυο είναι εντάξει — το πρόβλημα είναι μάλλον στην εφαρμογή/server",
                                             "The network looks fine — the problem is probably the application/server"),
                    "fix": L("Έλεγξε την εφαρμογή/την υπηρεσία (status page, λογαριασμός, firewall του server).",
                             "Check the application/service (status page, account, server-side firewall).")}
        layer = LAYER[pick]
        apipa = pick == "link" and "169.254." in (by["link"]["detail"] or "")
        if apipa:
            layer = "DHCP"
        local_fail = by["dns_local"]["status"] == "fail"
        public_ok = by["dns_public"]["status"] in ("ok", "warn")
        texts = {
            "L1/L2": L("Δεν υπάρχει σύνδεση στο δίκτυο (διεπαφή/καλώδιο/Wi‑Fi)", "No network link (interface/cable/Wi‑Fi)"),
            "DHCP": L("Ο υπολογιστής δεν πήρε σωστές ρυθμίσεις από το DHCP", "The computer did not get proper settings from DHCP"),
            "Gateway": L("Ο router (gateway) δεν απαντά", "The router (gateway) is not answering"),
            "Captive portal": L("Captive portal: χρειάζεται login/αποδοχή όρων πριν ανοίξει το internet",
                                "Captive portal: a login / terms acceptance is needed before internet access"),
            "Internet/ISP": L("Το τοπικό δίκτυο δουλεύει, αλλά δεν υπάρχει έξοδος στο internet (router WAN / πάροχος)",
                              "The local network works, but there is no internet uplink (router WAN / ISP)"),
            "DNS": L("It's always DNS: ο DNS του δικτύου (router/Pi-hole) δεν απαντά, ενώ το internet δουλεύει",
                     "It's always DNS: the network's DNS (router/Pi-hole) is not answering, while the internet works")
            if local_fail and public_ok else L("Πρόβλημα DNS — δεν λύνονται ονόματα", "DNS problem — names do not resolve"),
            "MTU": L("Πρόβλημα MTU: τα μεγάλα πακέτα δεν περνούν (PPPoE/VPN) — «ανοίγουν μόνο κάποια sites»",
                     "MTU problem: large packets do not pass (PPPoE/VPN) — \"only some sites load\""),
            "Quality": L("Το δίκτυο δουλεύει, αλλά με απώλειες/jitter — αργό ή «κολλάει»",
                         "The network works but with loss/jitter — slow or choppy"),
        }
        fix = by[pick].get("fix") or next((by[s].get("fix") for s in PRIORITY if by[s].get("fix")), None)
        if layer == "DNS" and local_fail and public_ok:
            fix = L("Restart στο router/Pi-hole ή βάλε προσωρινά DNS 1.1.1.1 / 9.9.9.9 στη συσκευή.",
                    "Restart the router/Pi-hole, or temporarily set DNS 1.1.1.1 / 9.9.9.9 on the device.")
        return {"layer": layer, "text": texts.get(layer, layer), "fix": fix}

    def _ticket(self):
        L = lambda el, en: _L(self.lang, el, en)  # noqa: E731
        i = self.info or {}
        t = self.started or self.clock()
        stamp = time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(t))
        host = i.get("host") or (socket.gethostname() or "?").split(".")[0][:40]
        kind = {"wifi": "Wi‑Fi", "ethernet": "Ethernet", "vpn": "VPN"}.get(i.get("kind"))
        ifc = f"{i.get('iface') or '?'}" + (f" ({kind})" if kind else "")
        ip = (i.get("ip") or "—") + (f"/{i['prefix']}" if i.get("ip") and i.get("prefix") else "")
        lines = [L("NetWatch — Διάγνωση δικτύου («Φταίει το δίκτυο;»)", "NetWatch — Network triage (\"Is it the network?\")"),
                 f"{L('Ώρα', 'Time')}: {stamp}",
                 f"{L('Υπολογιστής', 'Host')}: {host} · IP {ip} · {L('διεπαφή', 'interface')} {ifc}",
                 f"Gateway: {i.get('gateway') or '—'} · DNS: {', '.join(i.get('dns') or []) or '—'}",
                 "-" * 60]
        for s in self.steps:
            lines.append(f"{TAG.get(s['status'], '[?]')} {s['title']} — {s['detail'] or '—'}")
        lines.append("-" * 60)
        v = self.verdict or {}
        lines.append(f"{L('Συμπέρασμα', 'Verdict')}: [{v.get('layer', '?')}] {v.get('text', '')}")
        if v.get("fix"):
            lines.append(f"{L('Προτεινόμενη λύση', 'Suggested fix')}: {v['fix']}")
        return "\n".join(lines)
