"""🗺 Διάγραμμα δικτύου με ένα κουμπί: σχέδιο σαν τα τεχνικά διαγράμματα + «πού είναι η βλάβη».

Ένα πάτημα «▶ Χαρτογράφησε» κάνει:
  1. traceroute (μέχρι 6 hops, -n, 1 δοκιμή/hop) προς 1.1.1.1 → router → (modem/ONT, CGNAT) → πρώτο hop παρόχου
  2. ping (3 πακέτα) στο router, στα ενδιάμεσα hops, στον πάροχο, στο 1.1.1.1 και στα switch/AP του LAN
  3. ένα DNS lookup (example.com)
  4. διαβάζει την τοπολογία που ήδη ξέρει το NetWatch (netdocs: LLDP/CDP από SNMP, whereis: switch/θύρα/VLAN, IPAM)
και βγάζει γράφο {nodes, edges} με χρώμα ανά κόμβο (ok/slow/down/quiet/idle) και μια διάγνωση: ποιος είναι ο
πρώτος κόμβος που «σπάει» στη διαδρομή από εσένα προς το Internet → εκεί κοιτάς.

Ασφάλεια: μόνο ping/traceroute (καμία σάρωση θυρών). Ping στο LAN μόνο σε ιδιωτικές IP· δημόσια μόνο το 1.1.1.1 και
τα hops της δικής σου διαδρομής. Τίποτα δεν γράφεται στον δίσκο.

API
---
TopoMap(state, sim=False, pinger=None, tracer=None, resolver=None, clock=time.time)
  .run(fault=None) → {"ok", "running"} | {"ok": False, "retry_in", "error"}  (fault: μόνο στο demo, για εξάσκηση)
  .view()          → {"running", "last_run", "graph": {nodes, edges}, "diag", "issues", "demo", "faults"}
"""
import ipaddress
import secrets
import socket
import subprocess
import threading
import time

PUBLIC_TARGET = "1.1.1.1"
DNS_NAME = "example.com"
MAX_HOPS = 6
MAX_INFRA_PINGS = 16
HOSTS_PER_PARENT = 60
MIN_INTERVAL = 8
SEEN_OK = 600            # συσκευή που φάνηκε τα τελευταία 10′ = «online»
SLOW = {"router": 20.0, "switch": 20.0, "ap": 30.0, "modem": 30.0, "isp": 60.0, "internet": 150.0}
CGNAT = ipaddress.ip_network("100.64.0.0/10")
FAULTS = ("isp", "modem", "switch", "dns", "slow")
EXPORT_MAX = 15 * 1024 * 1024   # PDF/PNG/SVG που φτιάχνει ο browser — κρατάμε μόνο στη μνήμη, για λίγα λεπτά
EXPORT_TTL = 300
EXPORT_KEEP = 4
EXPORT_TYPES = {"pdf": (b"%PDF-", "application/pdf"), "png": (b"\x89PNG", "image/png"), "svg": (b"<svg", "image/svg+xml"),
                "drawio": (b"<?xml", "application/xml; charset=utf-8")}  # draw.io: το XML το φτιάχνει ο server (netdocs)


def _L(el, en):
    return {"el": el, "en": en}


def private_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return a.is_private and not a.is_loopback and not a.is_link_local and not a.is_multicast


def hop_kind(ip):
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None
    if a in CGNAT:
        return "cgnat"
    if a.is_private:
        return "modem"
    return "isp" if a.is_global else None


def ping_status(r, kind):
    """Αποτέλεσμα ping (latency.summarize) → ok / slow / down."""
    if not r or not r.get("recv"):
        return "down"
    if (r.get("loss") or 0) > 0 or (r.get("med") or 0) > SLOW.get(kind, 50.0):
        return "slow"
    return "ok"


def _sys_ping(host):
    import latency
    return latency.ping_round(host, count=3, gap=0.2)


def _sys_trace(target=PUBLIC_TARGET):
    from osint import sys_trace  # traceroute (Unix) / tracert (Windows)
    return sys_trace(target, MAX_HOPS, 25)


def _sys_resolve(name=DNS_NAME, timeout=3.0):
    box = {}

    def go():
        t0 = time.time()
        try:
            socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
            box["ms"] = round((time.time() - t0) * 1000, 1)
        except OSError as e:
            box["err"] = str(e)[:80]
    th = threading.Thread(target=go, daemon=True)
    th.start()
    th.join(timeout)
    if "ms" in box:
        return {"ok": True, "ms": box["ms"]}
    return {"ok": False, "err": box.get("err") or "timeout"}


def _norm(s):
    return " ".join(str(s or "").lower().replace("(", " ").replace(")", " ").split())


class TopoMap:
    def __init__(self, state, sim=False, pinger=None, tracer=None, resolver=None, clock=time.time):
        self.st, self.sim, self.clock = state, sim, clock
        self.ping = pinger or (self._demo_ping if sim else _sys_ping)
        self.trace = tracer or (self._demo_trace if sim else _sys_trace)
        self.resolve = resolver or (self._demo_resolve if sim else _sys_resolve)
        self.lock = threading.RLock()
        self.running, self.last_start, self.result = False, 0.0, None
        self.fault = None
        self.files = {}  # id → (t, fmt, bytes)

    # ── εκτέλεση ──
    def run(self, fault=None):
        with self.lock:
            if self.running:
                return {"ok": True, "running": True}
            now = self.clock()
            wait = MIN_INTERVAL - (now - self.last_start)
            if self.last_start and wait > 0:
                return {"ok": False, "running": False, "retry_in": int(wait) + 1,
                        "error": f"Περίμενε {int(wait) + 1}″ πριν την επόμενη χαρτογράφηση."}
            self.running, self.last_start = True, now
            self.fault = fault if self.sim and fault in FAULTS else None
        if self.sim:
            self._execute()
        else:
            threading.Thread(target=self._execute, daemon=True).start()
        return {"ok": True, "running": self.running}

    def wait(self, timeout=60):
        end = time.time() + timeout
        while self.running and time.time() < end:
            time.sleep(0.02)
        return not self.running

    def _execute(self):
        try:
            res = self.build()
            with self.lock:
                self.result = res
        finally:
            with self.lock:
                self.running = False

    def _pings(self, hosts):
        out, ths = {}, []

        def one(h):
            try:
                out[h] = self.ping(h)
            except Exception:
                out[h] = None
        for h in dict.fromkeys(hosts):
            th = threading.Thread(target=one, args=(h,), daemon=True)
            th.start()
            ths.append(th)
        for th in ths:
            th.join(15)
        return out

    # ── τοπολογία ──
    def _doc(self):
        import netdocs
        try:
            return netdocs.build(self.st, "el")
        except Exception:
            return {"devices": [], "links": [], "hosts": [], "subnets": []}

    def build(self):
        st = self.st
        gw = getattr(st, "gateway", None)
        me = set(getattr(st, "me", None) or ())
        doc = self._doc()
        nodes, edges = {}, []

        def node(nid, kind, label, ip="", **kw):
            n = nodes.get(nid)
            if n is None:
                lab = label if isinstance(label, dict) else str(label or ip or nid)[:48]
                n = nodes[nid] = {"id": nid, "kind": kind, "label": lab, "ip": ip or "",
                                  "status": "unknown", "ms": None, "loss": None, "parent": None, "port": "", "vlan": None}
            n.update({k: v for k, v in kw.items() if v is not None})
            return n

        def edge(a, b, label="", guess=False):
            edges.append({"a": a, "b": b, "label": str(label or "")[:24], "guess": bool(guess)})
            nodes[b]["parent"] = a
            if label and not nodes[b]["port"]:
                nodes[b]["port"] = str(label)[:24]

        # — πάνω μέρος: Internet ← πάροχος ← modem ← router —
        home = getattr(st, "home", None) or {}
        node("internet", "internet", "Internet", PUBLIC_TARGET, sub="1.1.1.1 (Cloudflare)")
        node("dns", "dns", "DNS", "", sub=DNS_NAME)
        hops = [h for h in (self.trace() or []) if isinstance(h, dict)]
        chain = []  # (id) από το router προς τα πάνω
        isp_ip = None
        seen = set()
        for h in hops:
            ip = h.get("ip")
            if not ip or ip == gw or ip in seen:
                continue
            seen.add(ip)
            k = hop_kind(ip)
            if k == "modem":
                nid = f"hop:{ip}"
                node(nid, "modem", "Modem / ONT", ip, hop=h.get("n"))
                chain.append(nid)
            elif k == "cgnat":
                nid = f"hop:{ip}"
                node(nid, "isp", "CGNAT", ip, hop=h.get("n"), sub=_L("δίκτυο παρόχου (100.64/10)", "ISP network (100.64/10)"))
                chain.append(nid)
            elif k == "isp" and ip != PUBLIC_TARGET:
                isp_ip = ip
                node("isp", "isp", home.get("isp") or home.get("org") or _L("Πάροχος", "ISP"), ip, hop=h.get("n"),
                     sub=_L("1ο δημόσιο hop", "1st public hop"))
                chain.append("isp")
                break
        if "isp" not in nodes:
            node("isp", "isp", home.get("isp") or _L("Πάροχος", "ISP"), "", sub=_L("δεν απάντησε στο traceroute", "no traceroute reply"))
            chain.append("isp")
        node("router", "router", "Router", gw or "", sub="gateway")
        up = ["router"] + chain + ["internet"]
        # ακμές από πάνω προς τα κάτω (ο γονιός είναι ο κόμβος πιο κοντά στο Internet)
        for a, b in zip(up[1:], up[:-1]):
            edge(a, b)
        edges.append({"a": "internet", "b": "dns", "label": "", "guess": False, "side": True})

        # — δικτυακές συσκευές του LAN —
        alias = {}

        def add_alias(nid, *names):
            for x in names:
                if x:
                    alias[_norm(x)] = nid
        add_alias("router", gw)
        for d in doc.get("devices") or []:
            role = d.get("role")
            if role == "router" or (gw and d.get("host") == gw):
                nodes["router"]["label"] = str(d.get("name") or "Router")[:48]
                nodes["router"]["sub"] = d.get("model") or d.get("vendor") or "gateway"
                add_alias("router", d.get("name"), d.get("sysname"), d.get("host"))
                continue
            if role not in ("switch", "ap"):
                continue
            nid = f"dev:{d.get('host') or d.get('name')}"
            node(nid, role, d.get("name"), d.get("host") or "", sub=d.get("model") or d.get("vendor") or "")
            add_alias(nid, d.get("name"), d.get("sysname"), d.get("host"))

        def find(name):
            n = _norm(name)
            if not n:
                return None
            if n in alias:
                return alias[n]
            if private_ip(n):
                return None
            for k, v in alias.items():  # «Core switch (Cisco 2960) (sw-core)» ↔ «Core switch (Cisco 2960)» (ολόκληρες λέξεις)
                if len(n) >= 4 and len(k) >= 4 and not private_ip(k) and (k.startswith(n + " ") or n.startswith(k + " ")):
                    return v
            return None

        hosts = [h for h in doc.get("hosts") or [] if isinstance(h, dict) and h.get("ip")]
        # switch που φαίνονται μόνο στο whereis (π.χ. access-sw-1) → κόμβοι
        for h in hosts:
            sw = h.get("switch")
            if sw and not find(sw):
                nid = f"sw:{_norm(sw)}"
                node(nid, "switch", sw, "")
                add_alias(nid, sw)
        # τελική «συσκευή» που είναι στην πραγματικότητα switch/AP (ίδια IP ή όνομα) → υποδοχή του κόμβου
        infra_of_host = {}
        for h in hosts:
            nid = find(h.get("ip")) or find(h.get("name")) or find((h.get("name") or "").split(" ")[0])
            if nid and nid != "router":
                infra_of_host[h["ip"]] = nid
                if not nodes[nid]["ip"]:
                    nodes[nid]["ip"] = h["ip"]
                    add_alias(nid, h["ip"])

        adj = {}
        for l in doc.get("links") or []:
            a = find(l.get("a")) or find(l.get("a_key"))
            b = find(l.get("b")) or find(l.get("b_key"))
            if a and not b:
                nm = str(l.get("b") or "?")
                low = _norm(nm)
                kind = "ap" if ("ap" in low.split("-") or low.startswith("ap") or "access point" in low) else "server"
                if kind == "server":
                    continue  # π.χ. Proxmox: τελική συσκευή, μένει στη λίστα συσκευών
                b = f"lnk:{low}"
                node(b, "ap", nm, "")
                add_alias(b, nm)
            if a and b and a != b:
                adj.setdefault(a, []).append((b, l.get("a_port") or ""))
                adj.setdefault(b, []).append((a, l.get("b_port") or ""))
        for hip, nid in infra_of_host.items():  # infra που «κάθεται» σε θύρα άλλου switch (whereis)
            h = next(x for x in hosts if x["ip"] == hip)
            par = find(h.get("switch"))
            if par and par != nid:
                adj.setdefault(par, []).append((nid, h.get("port") or ""))
                adj.setdefault(nid, []).append((par, ""))
        # BFS από το router → γονιός κάθε switch/AP
        q, done = ["router"], {"router"}
        while q:
            cur = q.pop(0)
            for nb, port in adj.get(cur, []):
                if nb in done or nb not in nodes or nodes[nb]["kind"] not in ("switch", "ap"):
                    continue
                done.add(nb)
                edge(cur, nb, port)
                q.append(nb)
        for nid, n in nodes.items():
            if n["kind"] in ("switch", "ap") and nid not in done:
                edge("router", nid, "", guess=True)

        # — τελικές συσκευές —
        now = self.clock()
        per = {}
        extra = {}
        for h in sorted(hosts, key=lambda x: (x["ip"] not in me, x.get("switch") or "~", str(x.get("port") or ""))):
            ip = h["ip"]
            if ip == gw or ip in infra_of_host:
                continue
            par = find(h.get("switch")) or "router"
            guess = not h.get("switch")
            if per.get(par, 0) >= HOSTS_PER_PARENT and ip not in me:
                extra[par] = extra.get(par, 0) + 1
                continue
            per[par] = per.get(par, 0) + 1
            last = h.get("last")
            stt = "ok" if last and now - float(last) < SEEN_OK else "idle"
            nid = f"h:{ip}"
            node(nid, "me" if ip in me else "host", h.get("name") or ip, ip, status=stt, vlan=h.get("vlan"),
                 sub=(h.get("type") or h.get("vendor") or "")[:40], last=last, icon=h.get("icon") or None, mac=h.get("mac") or None)
            edge(par, nid, h.get("port") or "", guess=guess)
        for par, n in extra.items():
            nid = f"more:{par}"
            node(nid, "more", f"+{n}", "", status="idle")
            edge(par, nid, "")

        # — μετρήσεις —
        targets = [n["ip"] for nid, n in nodes.items()
                   if n["kind"] in ("router", "modem", "isp", "internet") and n["ip"]]
        lan = [n["ip"] for n in nodes.values() if n["kind"] in ("switch", "ap") and private_ip(n["ip"])][:MAX_INFRA_PINGS]
        res = self._pings(targets + lan)
        for n in nodes.values():
            if n["kind"] in ("router", "modem", "isp", "internet", "switch", "ap") and n["ip"] in res:
                r = res[n["ip"]] or {}
                n["status"] = ping_status(r, n["kind"])
                n["ms"], n["loss"] = r.get("med"), r.get("loss")
        dns = self.resolve() or {}
        nodes["dns"]["status"] = "ok" if dns.get("ok") else "down"
        nodes["dns"]["ms"] = dns.get("ms")
        # σιωπηλός κόμβος: δεν απαντά σε ping, αλλά κάτι πιο ψηλά απαντά → η κίνηση περνά (απλά μπλοκάρει το ICMP)
        for i, nid in enumerate(up[:-1]):
            if nodes[nid]["status"] == "down" and any(nodes[x]["status"] in ("ok", "slow") for x in up[i + 1:]):
                nodes[nid]["status"] = "quiet"
            elif nodes[nid]["status"] == "unknown" and not nodes[nid]["ip"]:
                nodes[nid]["status"] = "quiet" if nodes["internet"]["status"] in ("ok", "slow") else "unknown"
        for n in nodes.values():
            if n["kind"] in ("switch", "ap") and n["status"] == "unknown":
                n["status"] = "quiet" if not n["ip"] else n["status"]
        diag, issues, path = self._diagnose(nodes, up, me)
        for nid in path:
            nodes[nid]["path"] = True
        if diag.get("level") == "bad":  # μετά τη βλάβη δεν ξέρουμε τίποτα (δεν φτάνουμε) → γκρι, όχι κόκκινο
            bi = path.index(diag["node"])
            local = nodes[diag["node"]]["kind"] in ("switch", "ap", "router")
            for nid, n in nodes.items():
                if n["status"] == "down" and nid != diag["node"] and (nid in path[bi + 1:] or (local and n["kind"] != "host")):
                    n["status"] = "unreach"
            if local:
                issues = [i for i in issues if i["level"] != "bad"]
        for e in edges:
            a, b = nodes.get(e["a"]), nodes.get(e["b"])
            sts = (a["status"], b["status"])
            e["status"] = "down" if "down" in sts else "unreach" if "unreach" in sts else "slow" if "slow" in sts else "ok"
        return {"t": now, "nodes": list(nodes.values()), "edges": edges, "diag": diag, "issues": issues,
                "path": path, "hops": len(hops), "isp_ip": isp_ip, "fault": self.fault}

    # ── διάγνωση ──
    def _diagnose(self, nodes, up, me):
        mine = next((n for n in nodes.values() if n["kind"] == "me"), None)
        path = []
        cur = mine["id"] if mine else None
        while cur and cur != "router" and cur in nodes and len(path) < 12:
            path.append(cur)
            cur = nodes[cur]["parent"]
        path += up + ["dns"]
        name = lambda n: n["label"]["el"] if isinstance(n["label"], dict) else n["label"]  # noqa: E731
        nm_en = lambda n: n["label"]["en"] if isinstance(n["label"], dict) else n["label"]  # noqa: E731
        issues = []
        for n in nodes.values():
            if n["kind"] in ("switch", "ap") and n["status"] == "down" and n["id"] not in path:
                par = nodes.get(n["parent"]) or {}
                port = f" (θύρα {n['port']} στο {name(par)})" if n["port"] and par else ""
                port_en = f" (port {n['port']} on {nm_en(par)})" if n["port"] and par else ""
                issues.append({"level": "bad", "node": n["id"], "el": f"Το {name(n)} δεν απαντά{port} — οι συσκευές από κάτω του μάλλον δεν έχουν δίκτυο.",
                               "en": f"{nm_en(n)} does not answer{port_en} — devices behind it probably have no network."})
            elif n["status"] == "slow" and n["kind"] != "host":
                ms = f"{n['ms']:.0f} ms" if n.get("ms") is not None else "—"
                loss = f", απώλειες {n['loss']:.0f}%" if n.get("loss") else ""
                loss_en = f", {n['loss']:.0f}% loss" if n.get("loss") else ""
                issues.append({"level": "warn", "node": n["id"], "el": f"Αργό: {name(n)} ({ms}{loss}).",
                               "en": f"Slow: {nm_en(n)} ({ms}{loss_en})."})
        # πρώτος κόμβος που «σπάει» από εσένα προς τα πάνω
        broken = None
        for i, nid in enumerate(path):
            if nodes[nid]["status"] == "down":
                broken = i
                break
        if broken is None:
            slow = [nodes[x] for x in path if nodes[x]["status"] == "slow"]
            if slow:
                s = slow[0]
                return ({"level": "warn", "node": s["id"],
                         "title": _L(f"Δουλεύει, αλλά αργεί στο «{name(s)}»", f"Works, but slow at “{nm_en(s)}”"),
                         "text": _L("Η διαδρομή μέχρι το Internet είναι ανοιχτή. Η καθυστέρηση/απώλεια ξεκινά σε αυτόν τον κόμβο — "
                                    "αν είναι ο πάροχος, μέτρησε ξανά σε άλλη ώρα (καρτέλα 📈 Καθυστέρηση) πριν τον πάρεις τηλέφωνο.",
                                    "The path to the Internet is up. Delay/loss starts at this node — if it is the ISP, measure again "
                                    "at another time (📈 Latency tab) before you call them."),
                         "steps": self._steps(s)}, issues, path)
            return ({"level": "ok", "node": None,
                     "title": _L("Όλα καλά: η διαδρομή μέχρι το Internet και το DNS δουλεύει", "All good: the path to the Internet and DNS works"),
                     "text": _L("Κάθε κόμβος από τη συσκευή σου μέχρι το 1.1.1.1 απαντά. Κράτα αυτό το διάγραμμα (PNG/draw.io) — "
                                "όταν κάτι χαλάσει, ξαναπάτα «Χαρτογράφησε» και σύγκρινε.",
                                "Every node from your device to 1.1.1.1 answers. Keep this diagram (PNG/draw.io) — when something "
                                "breaks, press “Map it” again and compare."),
                     "steps": []}, issues, path)
        b = nodes[path[broken]]
        prev = nodes[path[broken - 1]] if broken else None
        between = _L(f"ανάμεσα σε «{name(prev)}» και «{name(b)}»" if prev else f"στο «{name(b)}»",
                     f"between “{nm_en(prev)}” and “{nm_en(b)}”" if prev else f"at “{nm_en(b)}”")
        return ({"level": "bad", "node": b["id"], "prev": prev["id"] if prev else None,
                 "title": _L(f"Η βλάβη είναι {between['el']}", f"The fault is {between['en']}"),
                 "text": self._why(b), "steps": self._steps(b)}, issues, path)

    @staticmethod
    def _why(n):
        k = n["kind"]
        return {
            "dns": _L("Το Internet φτάνει (το ping στο 1.1.1.1 περνά), αλλά τα ονόματα δεν μεταφράζονται σε IP. Γι' αυτό «δεν ανοίγει τίποτα».",
                      "The Internet is reachable (ping to 1.1.1.1 works) but names don't resolve to IPs. That's why “nothing opens”."),
            "internet": _L("Ο πάροχος απαντά αλλά πιο πέρα δεν πάει τίποτα: πρόβλημα στο δίκτυο του παρόχου ή στη διασύνδεσή του.",
                           "The ISP answers but nothing beyond it: a problem inside the ISP network or its upstream."),
            "isp": _L("Το σπίτι σου είναι εντάξει μέχρι το router/modem· μετά δεν απαντά τίποτα. Η βλάβη είναι στη γραμμή ή στον πάροχο.",
                      "Your home network is fine up to the router/modem; nothing answers after that. The fault is the line or the ISP."),
            "modem": _L("Το router απαντά αλλά το modem/ONT όχι: το καλώδιο router↔modem ή το ίδιο το modem.",
                        "The router answers but the modem/ONT doesn't: the router↔modem cable or the modem itself."),
            "router": _L("Δεν φτάνεις ούτε το router: το πρόβλημα είναι στο τοπικό δίκτυο (Wi-Fi, καλώδιο, switch) ή στο ίδιο το router.",
                         "You can't even reach the router: the problem is the local network (Wi-Fi, cable, switch) or the router itself."),
        }.get(k, _L(f"Το «{n['label']}» δεν απαντά, άρα ό,τι είναι πίσω του (και εσύ) χάνει το δίκτυο.",
                    f"“{n['label']}” does not answer, so everything behind it (you too) loses the network."))

    @staticmethod
    def _steps(n):
        k = n["kind"]
        port = n.get("port") or ""
        S = {
            "dns": [_L("Δοκίμασε: dig example.com @1.1.1.1 — αν δουλεύει, φταίει ο DNS του router/παρόχου.", "Try: dig example.com @1.1.1.1 — if it works, the router/ISP DNS is at fault."),
                    _L("Βάλε προσωρινά DNS 1.1.1.1 ή 9.9.9.9 στο router (ή στη συσκευή).", "Temporarily set DNS 1.1.1.1 or 9.9.9.9 on the router (or the device)."),
                    _L("Αν έχεις Pi-hole/AdGuard: είναι αναμμένο; (καρτέλα 🧹 DNS)", "If you run Pi-hole/AdGuard: is it up? (🧹 DNS tab)")],
            "internet": [_L("Κοίτα σελίδα βλαβών του παρόχου / downdetector.", "Check the ISP outage page / downdetector."),
                         _L("Κράτα αυτό το διάγραμμα ως απόδειξη όταν τους πάρεις τηλέφωνο.", "Keep this diagram as evidence when you call them.")],
            "isp": [_L("Δες τα λαμπάκια στο modem (DSL/Fiber/Internet). Κόκκινο ή σβηστό = γραμμή.", "Check the modem LEDs (DSL/Fiber/Internet). Red or off = the line."),
                    _L("Επανεκκίνηση modem (περίμενε 2′), ξαναπάτα «Χαρτογράφησε».", "Restart the modem (wait 2′), press “Map it” again."),
                    _L("Αν μένει κόκκινο: τηλέφωνο στον πάροχο — πες «το router μου απαντά, το πρώτο hop σας όχι».", "If it stays red: call the ISP — say “my router answers, your first hop doesn't”.")],
            "modem": [_L("Έλεγξε το καλώδιο WAN router↔modem (και τα λαμπάκια της θύρας).", "Check the WAN cable router↔modem (and the port LEDs)."),
                      _L("Επανεκκίνηση modem/ONT.", "Restart the modem/ONT.")],
            "router": [_L("Είσαι συνδεδεμένος στο σωστό Wi-Fi/καλώδιο; (καρτέλα 📶 Wi-Fi)", "Are you on the right Wi-Fi/cable? (📶 Wi-Fi tab)"),
                       _L("Έχει ρεύμα το router; Επανεκκίνηση.", "Is the router powered? Restart it."),
                       _L("Η IP σου είναι 169.254.x.x; Τότε δεν πήρες DHCP.", "Is your IP 169.254.x.x? Then DHCP failed.")],
        }
        if k in S:
            return S[k]
        st = [_L("Έχει ρεύμα; Ανάβουν τα λαμπάκια των θυρών;", "Is it powered? Are the port LEDs on?")]
        if port:
            st.append(_L(f"Κοίτα το καλώδιο στη θύρα {port} (uplink).", f"Check the cable on port {port} (uplink)."))
        st.append(_L("Δες στο 🔌 Πού είναι συνδεδεμένο ποιες συσκευές κάθονται από κάτω του.", "See 🔌 Where is it plugged in for the devices behind it."))
        return st

    # ── εξαγωγή (ο browser φτιάχνει το αρχείο, ο server το δίνει ως κανονικό «κατέβασμα» — δουλεύει και στο Mac app) ──
    def put_file(self, fmt, data):
        if fmt not in EXPORT_TYPES:
            return {"error": "Μορφή: pdf, png ή svg."}
        if not data or len(data) > EXPORT_MAX:
            return {"error": "Άδειο ή πολύ μεγάλο αρχείο (όριο 15 MB)."}
        if not data.lstrip()[:8].startswith(EXPORT_TYPES[fmt][0]):
            return {"error": "Το αρχείο δεν είναι " + fmt.upper() + "."}
        now = self.clock()
        with self.lock:
            for k in [k for k, v in self.files.items() if now - v[0] > EXPORT_TTL]:
                del self.files[k]
            while len(self.files) >= EXPORT_KEEP:
                del self.files[min(self.files, key=lambda k: self.files[k][0])]
            fid = secrets.token_hex(8)
            self.files[fid] = (now, fmt, bytes(data))
        return {"ok": True, "id": fid, "url": f"/api/topomap/file?id={fid}"}

    def get_file(self, fid):
        with self.lock:
            v = self.files.get(str(fid or ""))
        if not v or self.clock() - v[0] > EXPORT_TTL:
            return None
        t, fmt, data = v
        name = "netwatch-diagram-" + time.strftime("%Y%m%d-%H%M", time.localtime(t)) + "." + fmt
        return {"name": name, "mime": EXPORT_TYPES[fmt][1], "data": data}

    def view(self):
        with self.lock:
            r = self.result
            return {"running": self.running, "last_run": r["t"] if r else None, "demo": self.sim,
                    "graph": {"nodes": r["nodes"], "edges": r["edges"]} if r else None,
                    "diag": r["diag"] if r else None, "issues": r["issues"] if r else [],
                    "path": r["path"] if r else [], "fault": self.fault, "faults": list(FAULTS) if self.sim else []}

    # ── demo ──
    def _demo_trace(self):
        base = [{"n": 1, "ip": getattr(self.st, "gateway", None) or "192.168.1.1", "ms": 1.2},
                {"n": 2, "ip": "192.168.100.1", "ms": 2.0},
                {"n": 3, "ip": "100.70.0.1", "ms": 8.4},
                {"n": 4, "ip": "62.1.1.1", "ms": 11.9}]
        return base

    def _demo_ping(self, host):
        f = self.fault
        ms = {"192.168.1.1": 0.9, "192.168.100.1": 1.8, "100.70.0.1": 7.9, "62.1.1.1": 11.2, PUBLIC_TARGET: 14.6}.get(host, 1.4)
        down = (f == "isp" and host in ("62.1.1.1", "100.70.0.1", PUBLIC_TARGET)) or \
               (f == "modem" and host in ("192.168.100.1", "100.70.0.1", "62.1.1.1", PUBLIC_TARGET)) or \
               f == "switch"  # το switch σου έπεσε → από εσένα δεν απαντά τίποτα πιο πάνω
        if host == "100.70.0.1" and not down:
            return {"sent": 3, "recv": 0, "loss": 100.0, "med": None}  # CGNAT hop που δεν απαντά σε ping (σιωπηλός)
        if down:
            return {"sent": 3, "recv": 0, "loss": 100.0, "med": None}
        if f == "slow" and host in ("62.1.1.1", PUBLIC_TARGET):
            return {"sent": 3, "recv": 2, "loss": 33.3, "med": ms * 9}
        return {"sent": 3, "recv": 3, "loss": 0.0, "med": ms}

    def _demo_resolve(self):
        if self.fault in ("dns",):
            return {"ok": False, "err": "timeout"}
        if self.fault in ("isp", "modem", "switch"):
            return {"ok": False, "err": "timeout"}
        return {"ok": True, "ms": 18.0}
