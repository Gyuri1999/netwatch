"""📘 Αυτόματη τεκμηρίωση δικτύου (ιδέα: NetBox export / «as-built» docs) — Markdown, HTML για εκτύπωση, draw.io.

Μαζεύει ό,τι ήδη ξέρει το NetWatch και το βάζει σε ένα έγγραφο που μπορείς να δώσεις σε συνάδελφο ή πελάτη:
  • Subnets & VLAN (IPAM + VLAN που βρέθηκαν στις αποθηκευμένες ρυθμίσεις: Cisco `vlan N`/` name X`,
    MikroTik `/interface vlan … vlan-id=N`)
  • Δικτυακές συσκευές (SNMP + αντίγραφα ρυθμίσεων: όνομα, IP, κατασκευαστής, μοντέλο/sysDescr, uptime, τελευταία αλλαγή)
  • Συνδέσεις τοπολογίας (γείτονες LLDP/CDP από SNMP + uplinks από το whereis, αν υπάρχει)
  • Τελικές συσκευές του LAN (ip, mac, όνομα, τύπος, switch/θύρα/VLAN αν τα ξέρει το whereis)
  • Υπηρεσίες (health), πρόσφατες αλλαγές ρυθμίσεων, τελευταίος έλεγχος πριν/μετά, ανοιχτές υποθέσεις, λήξεις ≤ 30 μέρες

🙈 Ποτέ μυστικά: δεν διαβάζουμε SNMP communities (το snmp.status() δεν τις δίνει), από τις ρυθμίσεις
χρησιμοποιούμε ΜΟΝΟ το «κρυμμένο» κείμενο του configbak (show() → mask) και κρατάμε μόνο VLAN/μοντέλο,
και δεν αγγίζουμε pcap.

API
---
build(state, lang="el", now=None) → dict (δομημένο έγγραφο)
to_markdown(doc) → str (GitHub-flavoured πίνακες)
to_html(doc, lang=None) → str (αυτόνομο HTML, ανοιχτό θέμα, φιλικό στην εκτύπωση)
to_drawio(doc) → str (draw.io / diagrams.net XML χωρίς συμπίεση)
counts(doc) → {devices, subnets, vlans, switches, links, configs, cases_open, expiring}
"""
import html
import ipaddress
import re
import time
import xml.etree.ElementTree as ET

LANGS = ("el", "en")
MAX_HOSTS = 500          # γραμμές στον πίνακα τελικών συσκευών
DRAWIO_MAX = 60          # τελικές συσκευές στο διάγραμμα (οι υπόλοιπες ως «+N»)
EXPIRY_DAYS = 30
RANK = {"high": 3, "med": 2, "low": 1}


def _L(lang, el, en):
    return en if lang == "en" else el


def _ts(t):
    if not t:
        return "—"
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(t)))
    except (TypeError, ValueError, OverflowError):
        return "—"


def _uptime(sec, lang):
    if sec is None:
        return "—"
    try:
        sec = int(sec)
    except (TypeError, ValueError):
        return "—"
    d, h = sec // 86400, (sec % 86400) // 3600
    if d:
        return f"{d}{_L(lang, 'μ', 'd')} {h}{_L(lang, 'ω', 'h')}"
    return f"{h}{_L(lang, 'ω', 'h')} {(sec % 3600) // 60}′"


def _ipkey(ip):
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except ValueError:
        return (9, 0)


def _lan_ip(ip):
    """Μόνο ιδιωτικές IPv4 του LAN (όχι broadcast/multicast/loopback/APIPA)."""
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return (a.version == 4 and a.is_private and not a.is_loopback and not a.is_multicast and not a.is_link_local
            and not a.is_unspecified and not str(a).endswith(".255") and not str(a).endswith(".0"))


def _safe(fn, default=None):
    try:
        r = fn()
        return default if r is None else r
    except Exception:
        return default


# ───────── ανάλυση ρυθμίσεων (μόνο από το κρυμμένο κείμενο) ─────────
_CISCO_VLAN = re.compile(r"^vlan\s+(\d{1,4})\s*$")
_CISCO_NAME = re.compile(r"^\s+name\s+(\S.*)$")
_MT_VLAN_ID = re.compile(r"\bvlan-id=(\d{1,4})\b")
_MT_NAME = re.compile(r"\bname=(\"[^\"]*\"|\S+)")
_MT_ADDR = re.compile(r"\baddress=(\d+\.\d+\.\d+\.\d+/\d+)\b.*\binterface=(\S+)")
_MT_MODEL = re.compile(r"^#\s*model\s*=\s*(\S.*)$", re.M)
_CISCO_MODEL = re.compile(r"^(?:!\s*)?(?:Model number|Model)\s*:\s*(\S.*)$", re.M | re.I)


def parse_vlans(text, vendor):
    """VLAN από κείμενο ρυθμίσεων → [{id, name}] (Cisco IOS & MikroTik)· για άλλα vendors κενό."""
    out = {}
    lines = (text or "").split("\n")
    if vendor == "cisco_ios" or any(_CISCO_VLAN.match(ln) for ln in lines):
        cur = None
        for ln in lines:
            m = _CISCO_VLAN.match(ln)
            if m:
                cur = int(m.group(1))
                out.setdefault(cur, "")
                continue
            m = _CISCO_NAME.match(ln)
            if cur is not None and m:
                out[cur] = m.group(1).strip()[:40]
                continue
            if not ln.startswith(" "):
                cur = None
    if vendor == "mikrotik" or "/interface vlan" in (text or ""):
        sec = ""
        for ln in lines:
            s = ln.strip()
            if s.startswith("/"):
                sec = s.split(" add ")[0]
            if sec.startswith("/interface vlan") or "vlan-id=" in s:
                m = _MT_VLAN_ID.search(s)
                if m:
                    n = _MT_NAME.search(s)
                    out.setdefault(int(m.group(1)), (n.group(1).strip('"')[:40] if n else ""))
    return [{"id": k, "name": v} for k, v in sorted(out.items()) if 1 <= k <= 4094]


def parse_subnets(text, vendor):
    """MikroTik `/ip address add address=192.168.30.1/24 interface=vlan30-iot` → [{cidr, gateway, iface}]."""
    if vendor != "mikrotik":
        return []
    out, sec = [], ""
    for ln in (text or "").split("\n"):
        s = ln.strip()
        if s.startswith("/"):
            sec = s
            continue
        if sec.startswith("/ip address"):
            m = _MT_ADDR.search(s)
            if m:
                try:
                    itf = ipaddress.ip_interface(m.group(1))
                except ValueError:
                    continue
                out.append({"cidr": str(itf.network), "gateway": str(itf.ip), "iface": m.group(2)})
    return out


def parse_model(text, vendor):
    m = _MT_MODEL.search(text or "") or _CISCO_MODEL.search(text or "")
    return m.group(1).strip()[:60] if m else None


def _role(name, host, vendor, descr, gw):
    s = f" {name or ''} {descr or ''} {vendor or ''} ".lower()
    if (host and gw and host == gw) or "router" in s or "routeros" in s or vendor == "mikrotik":
        return "router"
    if "switch" in s or vendor == "cisco_ios" or re.search(r"[\s(]sw[-\s]", s):
        return "switch"
    if re.search(r"[\s(]ap[-\s]", s) or "openwrt" in s or "access point" in s or "unifi" in s:
        return "ap"
    return "server"


# ───────── συλλογή ─────────
def _collect_hosts(state):
    out = {}
    lock = getattr(state, "lock", None)
    hosts = getattr(state, "hosts", None) or {}
    try:
        if lock:
            lock.acquire()
        items = list(hosts.values())
        arp = dict(getattr(state, "arp_table", None) or {})
    finally:
        if lock:
            lock.release()
    for h in items:
        ip = h.get("ip")
        if h.get("kind") not in (None, "local") or not _lan_ip(ip):
            continue
        dt = {}
        if hasattr(state, "_dtype"):
            dt = _safe(lambda h=h: state._dtype(h), {}) or {}
        names = sorted(h.get("names") or ())
        out[ip] = {"ip": ip, "mac": h.get("mac") or arp.get(ip) or "", "icon": dt.get("dicon") or "",
                   "name": (dt.get("alias") or (names[0] if names else (h.get("rdns") or "")))[:64],
                   "vendor": (dt.get("vendor") or "")[:40], "type": (dt.get("dlabel") or dt.get("dtype") or "")[:40],
                   "first": h.get("first"), "last": h.get("last"), "gw": bool(h.get("gw")), "me": bool(h.get("me")),
                   "switch": "", "port": "", "vlan": None}
    dn = getattr(state, "devnames", None)
    for ip, mac in arp.items():
        if ip not in out and _lan_ip(ip):
            u = (dn.get(mac, ip) if dn else None) or {}
            out[ip] = {"ip": ip, "mac": mac or "", "name": u.get("name") or "", "vendor": "", "type": "", "first": None, "last": None, "icon": "",
                       "gw": ip == getattr(state, "gateway", None), "me": ip in (getattr(state, "me", None) or ()),
                       "switch": "", "port": "", "vlan": None}
    return out


def _ipam(state, hosts):
    ip_ = getattr(state, "ipam", None)
    if not ip_:
        return None
    hl = [{"ip": h["ip"], "mac": h["mac"] or None, "names": [h["name"]] if h["name"] else [], "vendor": h["vendor"],
           "dlabel": h["type"], "first": h["first"] or 0, "last": h["last"] or 0} for h in hosts.values()]
    me = sorted(getattr(state, "me", None) or [])
    me = me[0] if me else None
    local_net = (me.rsplit(".", 1)[0] + ".0/24") if me and ":" not in me else None
    return _safe(lambda: ip_.report(hl, (), time.time(), local_net))


def build(state, lang="el", now=None):
    """Δομημένο έγγραφο τεκμηρίωσης από την τρέχουσα κατάσταση (χωρίς μυστικά)."""
    lang = lang if lang in LANGS else "el"
    now = time.time() if now is None else now
    gw = getattr(state, "gateway", None)
    mode = getattr(state, "mode", None) or "?"
    hosts = _collect_hosts(state)

    # — whereis: switch/θύρα/VLAN ανά τελική συσκευή —
    wi = getattr(state, "whereis", None)
    wrows = _safe(lambda: wi.table(), []) if wi else []
    if isinstance(wrows, dict):
        wrows = wrows.get("rows") or wrows.get("table") or []
    for r in wrows if isinstance(wrows, list) else []:
        if not isinstance(r, dict):
            continue
        ip, mac = r.get("ip"), (r.get("mac") or "").lower()
        h = hosts.get(ip) if ip else None
        if h is None and mac:
            h = next((x for x in hosts.values() if (x["mac"] or "").lower() == mac), None)
        if h is None and ip and _lan_ip(ip):
            h = hosts[ip] = {"ip": ip, "mac": mac, "name": "", "vendor": "", "type": "", "first": None, "last": None,
                             "gw": ip == gw, "me": False, "switch": "", "port": "", "vlan": None}
        if h is None:
            continue
        h["switch"] = str(r.get("switch") or h["switch"] or "")[:40]
        h["port"] = str(r.get("port") or h["port"] or "")[:40]
        h["vlan"] = r.get("vlan") if r.get("vlan") not in (None, "") else h["vlan"]
        if r.get("name") and not h["name"]:
            h["name"] = str(r["name"])[:64]
        if r.get("vendor") and not h["vendor"]:
            h["vendor"] = str(r["vendor"])[:40]

    # — IPAM —
    rep = _ipam(state, hosts)
    inv = {r.get("ip"): r for r in (rep or {}).get("inventory") or [] if isinstance(r, dict)}
    for ip, r in inv.items():
        if ip in hosts and r.get("name") and not hosts[ip]["name"]:
            hosts[ip]["name"] = str(r["name"])[:64]
    subnets = []
    for s in (rep or {}).get("subnets") or []:
        subnets.append({"cidr": s.get("cidr"), "name": s.get("name") or "", "vlan": s.get("vlan"), "gateway": s.get("gateway"),
                        "dhcp": s.get("dhcp"), "used": s.get("used"), "total": s.get("total"), "pct": s.get("pct"),
                        "source": "ipam"})

    # — αντίγραφα ρυθμίσεων (μόνο κρυμμένο κείμενο) —
    cb = getattr(state, "configbak", None)
    cbv = _safe(lambda: cb.view(), {}) if cb else {}
    cdevs = [d for d in cbv.get("devices") or [] if isinstance(d, dict)]
    vlans, changes = {}, []
    devices = {}
    for d in cdevs:
        txt = ""
        sh = _safe(lambda d=d: cb.show(d["id"]), {}) or {}
        if isinstance(sh, dict) and not sh.get("error"):
            txt = sh.get("text") or ""
        for v in parse_vlans(txt, d.get("vendor")):
            e = vlans.setdefault(v["id"], {"id": v["id"], "name": v["name"], "devices": []})
            if v["name"] and not e["name"]:
                e["name"] = v["name"]
            e["devices"].append(d.get("name") or d["id"])
        for sn in parse_subnets(txt, d.get("vendor")):
            if not any(x["cidr"] == sn["cidr"] for x in subnets):
                m = re.search(r"vlan(\d{1,4})", sn["iface"])
                subnets.append({"cidr": sn["cidr"], "name": sn["iface"], "vlan": int(m.group(1)) if m else None,
                                "gateway": sn["gateway"], "dhcp": None, "used": None, "total": None, "pct": None,
                                "source": "config"})
        key = d.get("host") or d["id"]
        devices[key] = {"name": d.get("name") or d["id"], "host": d.get("host") or "", "vendor": d.get("vendor") or "",
                        "model": parse_model(txt, d.get("vendor")), "descr": "", "sysname": "", "location": "",
                        "uptime": None, "last_change": d.get("last_change"), "last_backup": d.get("last_backup"),
                        "config_versions": d.get("versions") or 0, "snmp": False, "ok": None, "aliases": {d["id"], d.get("name") or ""}}
        vs = _safe(lambda d=d: cb.versions(d["id"]), {}) or {}
        allv = vs.get("versions") or []
        for k, v in enumerate(allv):  # νεότερη πρώτη· η αρχική (η τελευταία στη λίστα) δεν είναι «αλλαγή»
            if k == len(allv) - 1:
                continue
            changes.append({"device": d.get("name") or d["id"], "ts": v.get("ts"), "added": v.get("added") or 0,
                            "removed": v.get("removed") or 0, "risky": list(v.get("risky") or [])[:6],
                            "level": v.get("level"), "note": (v.get("note") or "")[:120]})
    changes.sort(key=lambda c: -(c["ts"] or 0))
    changes = changes[:10]

    # — SNMP (sysDescr, uptime, LLDP) — χωρίς community —
    sn = getattr(state, "snmp", None)
    snv = _safe(lambda: sn.status(), {}) if sn else {}
    neigh = []
    for t in snv.get("targets") or []:
        if not isinstance(t, dict):
            continue
        sysd = t.get("sys") or {}
        key = t.get("host") or t.get("name")
        d = devices.get(key)
        if d is None:
            d = devices[key] = {"name": t.get("name") or key, "host": t.get("host") or "", "vendor": "", "model": None,
                                "descr": "", "sysname": "", "location": "", "uptime": None, "last_change": None,
                                "last_backup": None, "config_versions": 0, "snmp": True, "ok": None, "aliases": set()}
        d.update(descr=(sysd.get("descr") or "")[:120], sysname=(sysd.get("name") or "")[:40],
                 location=(sysd.get("location") or "")[:60], uptime=sysd.get("uptime"), snmp=True, ok=t.get("ok"))
        d["aliases"] |= {t.get("name") or "", sysd.get("name") or "", t.get("id") or ""}
        for n in t.get("neighbours") or []:
            neigh.append((key, n))
    for k, d in devices.items():
        d["role"] = _role(d["name"], d["host"], d["vendor"], d["descr"], gw)
        d["aliases"] = {a.lower() for a in d["aliases"] | {d["name"], d["host"], d["sysname"]} if a}

    def resolve(name):
        n = (name or "").lower()
        return next((k for k, d in devices.items() if n and n in d["aliases"]), None)

    links, seen = [], set()
    for key, n in neigh:
        rk = resolve(n.get("remote_name"))
        a = (key, str(n.get("local_port") or ""))
        b = (rk or "?" + str(n.get("remote_name") or "?"), str(n.get("remote_port_desc") or n.get("remote_port") or ""))
        sig = frozenset([a, b]) if rk else frozenset([a, b, ("raw", "")])
        alt = frozenset([(a[0], ""), (b[0], "")])
        if sig in seen or (rk and alt in seen):
            continue
        seen.update([sig, alt] if rk else [sig])
        links.append({"a": devices[key]["name"], "a_key": key, "a_port": a[1],
                      "b": devices[rk]["name"] if rk else str(n.get("remote_name") or "?")[:40], "b_key": rk,
                      "b_port": b[1], "proto": (n.get("proto") or "lldp").upper(), "source": "snmp"})
    up = _safe(lambda: wi.uplinks(), []) if wi and hasattr(wi, "uplinks") else []
    up = list(up) if isinstance(up, list) else []
    # whereis: μια γνωστή δικτυακή συσκευή (π.χ. AP/switch) «κάθεται» σε θύρα άλλου switch → σύνδεση τοπολογίας
    by_host = {d["host"]: k for k, d in devices.items() if d["host"]}
    for r in wrows if isinstance(wrows, list) else []:
        if isinstance(r, dict) and r.get("ip") in by_host and resolve(r.get("switch")) not in (None, by_host[r["ip"]]):
            up.append({"switch": r.get("switch"), "port": r.get("port"), "remote": devices[by_host[r["ip"]]]["name"]})
    for u in up:
        if not isinstance(u, dict):
            continue
        ak, bk = resolve(u.get("switch")), resolve(u.get("remote") or u.get("to"))
        an = devices[ak]["name"] if ak else str(u.get("switch") or "?")[:40]
        bn = devices[bk]["name"] if bk else str(u.get("remote") or u.get("to") or "?")[:40]
        if any({l["a"], l["b"]} == {an, bn} for l in links):
            continue
        links.append({"a": an, "a_key": ak, "a_port": str(u.get("port") or "")[:40], "b": bn, "b_key": bk,
                      "b_port": str(u.get("remote_port") or "")[:40], "proto": "MAC", "source": "whereis"})

    netdevs = []
    for k, d in devices.items():
        netdevs.append({x: d[x] for x in ("name", "host", "vendor", "model", "descr", "sysname", "location", "uptime",
                                          "last_change", "last_backup", "config_versions", "snmp", "ok", "role")})
    order = {"router": 0, "switch": 1, "ap": 2, "server": 3}
    netdevs.sort(key=lambda d: (order.get(d["role"], 9), _ipkey(d["host"])))

    # — VLAN από IPAM —
    for s in subnets:
        if isinstance(s.get("vlan"), int) and 1 <= s["vlan"] <= 4094:
            e = vlans.setdefault(s["vlan"], {"id": s["vlan"], "name": "", "devices": []})
            e.setdefault("subnets", []).append(s["cidr"])
    for v in vlans.values():
        v.setdefault("subnets", [])
        v["devices"] = sorted(set(v["devices"]))

    # — τελικές συσκευές —
    nd_hosts = {d["host"] for d in netdevs if d["host"]}
    end = sorted(hosts.values(), key=lambda h: _ipkey(h["ip"]))
    for h in end:
        h["netdev"] = h["ip"] in nd_hosts or h["gw"]
        sk = resolve(h["switch"]) if h["switch"] else None
        if sk:  # id του configbak/sysName → το όνομα της συσκευής στο έγγραφο (και κόμβος στο draw.io)
            h["switch"] = devices[sk]["name"]
        if h["vlan"] is None:
            for s in subnets:
                try:
                    if ipaddress.ip_address(h["ip"]) in ipaddress.ip_network(s["cidr"], strict=False):
                        h["subnet"] = s["cidr"]
                        h["vlan"] = s.get("vlan")
                        break
                except ValueError:
                    continue
        h.setdefault("subnet", None)

    # — υπηρεσίες —
    he = getattr(state, "health", None)
    hv = _safe(lambda: he.status(), {}) if he else {}
    services = [{"name": t.get("name") or "", "target": t.get("url") or (f"{t.get('host')}:{t['port']}" if t.get("port") else t.get("host") or ""),
                 "kind": t.get("kind") or "", "up": t.get("up"), "ms": t.get("ms"), "cert_days": t.get("cert_days"),
                 "err": (t.get("err") or "")[:100]} for t in hv.get("targets") or [] if isinstance(t, dict)]

    # — έλεγχος πριν/μετά —
    ch = getattr(state, "changecheck", None)
    lc = (_safe(lambda: ch.view(), {}) or {}).get("last_compare") if ch else None
    check = None
    if isinstance(lc, dict) and not lc.get("error"):
        check = {"a": (lc.get("a") or {}).get("label"), "b": (lc.get("b") or {}).get("label"),
                 "t": (lc.get("b") or {}).get("t"), "verdict": lc.get("verdict"), "summary": lc.get("summary") or ""}

    # — υποθέσεις —
    cs = getattr(state, "cases", None)
    cv = _safe(lambda: cs.view(), {}) if cs else {}
    opn = [c for c in cv.get("cases") or [] if c.get("status") in ("new", "investigating")]
    opn.sort(key=lambda c: (-RANK.get(c.get("sev"), 0), -(c.get("updated") or 0)))
    cases = {"open": (cv.get("kpi") or {}).get("open", len(opn)) if cv else 0,
             "top": [{"id": c.get("id"), "title": c.get("title") or "", "sev": c.get("sev"), "status": c.get("status"),
                      "updated": c.get("updated")} for c in opn[:10]]}

    # — λήξεις —
    ex = getattr(state, "expiry", None)
    xv = _safe(lambda: ex.view(), {}) if ex else {}
    expiring = []
    for it in (xv.get("items") if isinstance(xv, dict) else None) or []:
        try:
            dl = int(it.get("days_left"))
        except (TypeError, ValueError, AttributeError):
            continue
        if dl <= EXPIRY_DAYS:
            expiring.append({"name": str(it.get("name") or "")[:80], "kind": str(it.get("kind") or "")[:30], "days_left": dl,
                             "status": it.get("status")})
    expiring.sort(key=lambda x: x["days_left"])

    end_rows = [{k: h.get(k) for k in ("ip", "mac", "name", "vendor", "type", "switch", "port", "vlan", "subnet", "first",
                                        "last", "netdev", "icon")} for h in end[:MAX_HOSTS]]
    doc = {"lang": lang, "generated": now, "mode": mode, "demo": mode == "demo",
           "title": _L(lang, "Τεκμηρίωση δικτύου", "Network documentation"),
           "gateway": gw, "subnets": subnets, "vlans": [vlans[k] for k in sorted(vlans)], "devices": netdevs,
           "links": links, "hosts": end_rows, "hosts_total": len(end), "services": services, "changes": changes,
           "change_check": check, "cases": cases, "expiring": expiring, "configs": len(cdevs)}
    doc["counts"] = counts(doc)
    return doc


def counts(doc):
    return {"devices": doc.get("hosts_total", len(doc.get("hosts") or [])), "subnets": len(doc.get("subnets") or []),
            "vlans": len(doc.get("vlans") or []),
            "switches": sum(1 for d in doc.get("devices") or [] if d.get("role") in ("switch", "ap")),
            "links": len(doc.get("links") or []), "configs": doc.get("configs", 0),
            "cases_open": (doc.get("cases") or {}).get("open", 0), "expiring": len(doc.get("expiring") or [])}


# ───────── κοινή «σελιδοποίηση»: ενότητες ως πίνακες ─────────
def _yn(v, lang):
    return "—" if v is None else (_L(lang, "πάνω", "up") if v else _L(lang, "κάτω", "down"))


def _sections(doc):
    """Ενότητες ως (id, τίτλος, κεφαλίδες, γραμμές | None, κείμενο αν κενό, σημείωση) — κοινές για MD και HTML."""
    lg = doc.get("lang", "el")
    L = lambda el, en: _L(lg, el, en)  # noqa: E731
    roles = {"router": "Router", "switch": "Switch", "ap": "AP", "server": L("Διακομιστής", "Server")}
    S = []
    c = doc["counts"]
    S.append(("summary", L("Σύνοψη", "Summary"), [L("Στοιχείο", "Item"), L("Πλήθος", "Count")],
              [[L("Τελικές συσκευές", "End devices"), c["devices"]], [L("Subnets", "Subnets"), c["subnets"]],
               ["VLAN", c["vlans"]], [L("Switches / AP", "Switches / APs"), c["switches"]],
               [L("Συνδέσεις", "Links"), c["links"]], [L("Συσκευές με αντίγραφο ρυθμίσεων", "Devices with config backup"), c["configs"]],
               [L("Ανοιχτές υποθέσεις", "Open cases"), c["cases_open"]],
               [L(f"Λήξεις ≤ {EXPIRY_DAYS} μέρες", f"Expiring ≤ {EXPIRY_DAYS} days"), c["expiring"]]], "", None))
    S.append(("subnets", L("Subnets & VLAN", "Subnets & VLANs"),
              ["CIDR", L("Όνομα", "Name"), "VLAN", "Gateway", "DHCP", L("Χρήση", "Usage"), L("Πηγή", "Source")],
              [[s["cidr"], s["name"], s["vlan"] if s["vlan"] is not None else "—", s["gateway"] or "—", s["dhcp"] or "—",
                f"{s['used']}/{s['total']} ({s['pct']}%)" if s.get("total") else "—",
                "IPAM" if s["source"] == "ipam" else L("ρυθμίσεις", "config")] for s in doc["subnets"]],
              L("Δεν υπάρχουν subnets (ρύθμισε το IPAM).", "No subnets (configure IPAM)."), None))
    S.append(("vlans", "VLAN", ["ID", L("Όνομα", "Name"), "Subnets", L("Ορίζεται σε", "Defined on")],
              [[v["id"], v["name"] or "—", ", ".join(v.get("subnets") or []) or "—", ", ".join(v["devices"]) or "—"]
               for v in doc["vlans"]], L("Δεν βρέθηκαν VLAN στις ρυθμίσεις.", "No VLANs found in configs."), None))
    S.append(("devices", L("Δικτυακές συσκευές", "Network devices"),
              [L("Ρόλος", "Role"), L("Όνομα", "Name"), "IP", L("Κατασκευαστής", "Vendor"), L("Μοντέλο / sysDescr", "Model / sysDescr"),
               "Uptime", L("Τελευταία αλλαγή ρυθμίσεων", "Last config change")],
              [[roles.get(d["role"], d["role"]), d["name"] + (f" ({d['sysname']})" if d["sysname"] and d["sysname"] != d["name"] else ""),
                d["host"] or "—", d["vendor"] or "—", d["model"] or d["descr"] or "—", _uptime(d["uptime"], lg),
                _ts(d["last_change"])] for d in doc["devices"]],
              L("Καμία δικτυακή συσκευή (πρόσθεσε στόχους SNMP ή αντίγραφα ρυθμίσεων).",
                "No network devices (add SNMP targets or config backups)."), None))
    S.append(("links", L("Συνδέσεις τοπολογίας", "Topology links"),
              [L("Συσκευή", "Device"), L("Θύρα", "Port"), "→", L("Γείτονας", "Neighbour"), L("Θύρα", "Port"), L("Πηγή", "Source")],
              [[l["a"], l["a_port"] or "—", "↔", l["b"], l["b_port"] or "—", l["proto"]] for l in doc["links"]],
              L("Δεν υπάρχουν γείτονες LLDP/CDP.", "No LLDP/CDP neighbours."), None))
    more = doc["hosts_total"] - len(doc["hosts"])
    S.append(("hosts", L("Τελικές συσκευές", "End devices"),
              ["IP", "MAC", L("Όνομα", "Name"), L("Τύπος / κατασκευαστής", "Type / vendor"), "Switch", L("Θύρα", "Port"), "VLAN",
               L("Πρώτη φορά", "First seen"), L("Τελευταία", "Last seen")],
              [[h["ip"], h["mac"] or "—", h["name"] or "—", " · ".join(x for x in (h["type"], h["vendor"]) if x) or "—",
                h["switch"] or "—", h["port"] or "—", h["vlan"] if h["vlan"] not in (None, "") else "—", _ts(h["first"]), _ts(h["last"])]
               for h in doc["hosts"]],
              L("Δεν έχουν φανεί συσκευές ακόμα.", "No devices seen yet."),
              L(f"…και {more} ακόμα.", f"…and {more} more.") if more > 0 else None))
    S.append(("services", L("Υπηρεσίες / διαθεσιμότητα", "Services / health"),
              [L("Υπηρεσία", "Service"), L("Στόχος", "Target"), L("Κατάσταση", "Status"), "ms", L("Πιστοποιητικό (μέρες)", "Certificate (days)")],
              [[s["name"], s["target"], _yn(s["up"], lg), s["ms"] if s["ms"] is not None else "—",
                s["cert_days"] if s["cert_days"] is not None else "—"] for s in doc["services"]],
              L("Δεν παρακολουθούνται υπηρεσίες.", "No services monitored."), None))
    cc = doc.get("change_check")
    S.append(("changes", L("Πρόσφατες αλλαγές", "Recent changes"),
              [L("Πότε", "When"), L("Συσκευή", "Device"), "+/−", L("Επικίνδυνα", "Risky items"), L("Σημείωση", "Note")],
              [[_ts(c["ts"]), c["device"], f"+{c['added']} / −{c['removed']}", "; ".join(c["risky"]) or "—", c["note"] or "—"]
               for c in doc["changes"]],
              L("Καμία αλλαγή ρυθμίσεων.", "No config changes."),
              (L("Τελευταίος έλεγχος πριν/μετά", "Last before/after check") +
               f" ({cc['a']} → {cc['b']}, {_ts(cc['t'])}): [{cc['verdict']}] {cc['summary']}") if cc else None))
    S.append(("cases", L("Ανοιχτές υποθέσεις", "Open cases"), ["#", L("Σοβαρότητα", "Severity"), L("Κατάσταση", "Status"), L("Τίτλος", "Title")],
              [[c["id"], c["sev"], c["status"], c["title"]] for c in doc["cases"]["top"]],
              L("Καμία ανοιχτή υπόθεση.", "No open cases."),
              L(f"Σύνολο ανοιχτών: {doc['cases']['open']}", f"Total open: {doc['cases']['open']}")))
    S.append(("expiring", L(f"Λήγουν σύντομα (≤ {EXPIRY_DAYS} μέρες)", f"Expiring soon (≤ {EXPIRY_DAYS} days)"),
              [L("Όνομα", "Name"), L("Είδος", "Kind"), L("Μέρες", "Days left")],
              [[x["name"], x["kind"], x["days_left"]] for x in doc["expiring"]],
              L("Τίποτα δεν λήγει σύντομα.", "Nothing expires soon."), None))
    return S


def _header_lines(doc):
    lg = doc.get("lang", "el")
    L = lambda el, en: _L(lg, el, en)  # noqa: E731
    mode = {"demo": "demo", "live": L("ζωντανά", "live"), "pcap": "pcap"}.get(doc["mode"], doc["mode"])
    return [f"{L('Δημιουργήθηκε', 'Generated')}: {_ts(doc['generated'])}",
            f"{L('Λειτουργία NetWatch', 'NetWatch mode')}: {mode}" + (f" · Gateway: {doc['gateway']}" if doc.get("gateway") else "")]


# ───────── Markdown ─────────
def _md(v):
    s = "—" if v is None or v == "" else str(v)
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


def to_markdown(doc):
    out = [f"# {doc['title']}", ""]
    out += [ln + "  " for ln in _header_lines(doc)]
    if doc.get("demo"):
        out += ["", "> " + _L(doc["lang"], "Δεδομένα προσομοίωσης (demo).", "Simulated (demo) data.")]
    out.append("")
    for sid, title, head, rows, empty, note in _sections(doc):
        out += [f"## {title}", ""]
        if rows:
            out.append("| " + " | ".join(_md(h) for h in head) + " |")
            out.append("|" + "|".join("---" for _ in head) + "|")
            out += ["| " + " | ".join(_md(c) for c in r) + " |" for r in rows]
        else:
            out.append("_" + empty + "_")
        if note:
            out += ["", _md(note)]
        out.append("")
    out.append("---")
    out.append("_NetWatch — " + _L(doc["lang"], "αυτόματη τεκμηρίωση· χωρίς κωδικούς/communities.",
                                   "auto-generated documentation; no passwords/communities.") + "_")
    return "\n".join(out) + "\n"


# ───────── HTML (για εκτύπωση) ─────────
CSS = """
:root{--ink:#1d2330;--mute:#5b6577;--line:#d9dee7;--head:#f2f4f8;--acc:#2456c7;--bad:#b42318;--ok:#067647}
*{box-sizing:border-box}
body{margin:0;background:#fff;color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 28px 48px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:17px;margin:28px 0 8px;padding-bottom:4px;border-bottom:2px solid var(--acc);color:var(--acc)}
.meta{color:var(--mute);font-size:13px}
.demo{display:inline-block;margin-top:8px;padding:2px 10px;border-radius:10px;background:#fff4e5;color:#8a4b00;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin:4px 0}
th,td{border:1px solid var(--line);padding:5px 7px;text-align:left;vertical-align:top}
th{background:var(--head);font-weight:600}
td.mono,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
tr:nth-child(even) td{background:#fafbfc}
.empty{color:var(--mute);font-style:italic}
.note{color:var(--mute);font-size:12.5px;margin:6px 0 0}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0 0}
.card{flex:1 1 120px;border:1px solid var(--line);border-radius:8px;padding:8px 12px}
.card b{display:block;font-size:20px}
.card span{color:var(--mute);font-size:12px}
footer{margin-top:32px;color:var(--mute);font-size:12px;border-top:1px solid var(--line);padding-top:8px}
.print{float:right;border:1px solid var(--line);background:#fff;border-radius:6px;padding:4px 12px;cursor:pointer;font:inherit}
@media print{main{padding:0;max-width:none}.print{display:none}h2{break-after:avoid}tr{break-inside:avoid}
 body{font-size:11px}table{font-size:10.5px}@page{size:A4;margin:14mm}}
"""
MONO = {0, 1}  # στήλες IP/MAC/CIDR σε monospace (στους πίνακες subnets/hosts)


def to_html(doc, lang=None):
    lg = lang if lang in LANGS else doc.get("lang", "el")
    if lg != doc.get("lang"):
        doc = dict(doc, lang=lg, title=_L(lg, "Τεκμηρίωση δικτύου", "Network documentation"))
    e = lambda v: html.escape("—" if v is None or v == "" else str(v))  # noqa: E731
    c = doc["counts"]
    cards = [(c["devices"], _L(lg, "συσκευές", "devices")), (c["subnets"], "subnets"), (c["vlans"], "VLAN"),
             (c["switches"], "switches/AP"), (c["links"], _L(lg, "συνδέσεις", "links")),
             (c["cases_open"], _L(lg, "ανοιχτές υποθέσεις", "open cases")), (c["expiring"], _L(lg, "λήξεις", "expiring"))]
    h = ["<!doctype html>", f'<html lang="{lg}"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         f"<title>{e(doc['title'])} — NetWatch</title><style>{CSS}</style></head><body><main>",
         f'<button class="print" onclick="window.print()">{e(_L(lg, "Εκτύπωση / PDF", "Print / PDF"))}</button>',
         f"<h1>{e(doc['title'])}</h1>", '<div class="meta">' + "<br>".join(e(x) for x in _header_lines(doc)) + "</div>"]
    if doc.get("demo"):
        h.append(f'<div class="demo">{e(_L(lg, "Δεδομένα προσομοίωσης (demo)", "Simulated (demo) data"))}</div>')
    h.append('<div class="cards">' + "".join(f"<div class=\"card\"><b>{e(n)}</b><span>{e(t)}</span></div>" for n, t in cards) + "</div>")
    for sid, title, head, rows, empty, note in _sections(doc):
        if sid == "summary":
            continue
        h.append(f'<section id="{sid}"><h2>{e(title)}</h2>')
        if rows:
            mono = MONO if sid in ("subnets", "hosts") else set()
            h.append("<table><thead><tr>" + "".join(f"<th>{e(x)}</th>" for x in head) + "</tr></thead><tbody>")
            for r in rows:
                h.append("<tr>" + "".join(("<td class=\"mono\">" if i in mono else "<td>") + e(v) + "</td>"
                                          for i, v in enumerate(r)) + "</tr>")
            h.append("</tbody></table>")
        else:
            h.append(f'<p class="empty">{e(empty)}</p>')
        if note:
            h.append(f'<p class="note">{e(note)}</p>')
        h.append("</section>")
    h.append("<footer>NetWatch — " + e(_L(lg, "αυτόματη τεκμηρίωση· δεν περιέχει κωδικούς, SNMP communities ή πακέτα.",
                                          "auto-generated documentation; contains no passwords, SNMP communities or packets.")) +
             "</footer></main></body></html>")
    return "\n".join(h)


# ───────── draw.io / diagrams.net ─────────
# Επαγγελματικά σύμβολα δικτύου: η έτοιμη βιβλιοθήκη «Networks» του draw.io/diagrams.net (shape=mxgraph.networks.*),
# με την ετικέτα κάτω από το εικονίδιο — ανοίγει παντού, χωρίς να χρειάζεται να εγκαταστήσει κανείς stencils.
_NET = "sketch=0;outlineConnect=0;whiteSpace=wrap;fontSize=11;verticalLabelPosition=bottom;verticalAlign=top;align=center;"
STY = {
    "cloud": _NET + "shape=mxgraph.networks.cloud;fillColor=#dae8fc;strokeColor=#6c8ebf;",
    "router": _NET + "shape=mxgraph.networks.router;fillColor=#f8cecc;strokeColor=#b85450;",
    "switch": _NET + "shape=mxgraph.networks.switch;fillColor=#d5e8d4;strokeColor=#82b366;",
    "ap": _NET + "shape=mxgraph.networks.wireless_access_point;fillColor=#fff2cc;strokeColor=#d6b656;",
    "server": _NET + "shape=mxgraph.networks.server;fillColor=#e1d5e7;strokeColor=#9673a6;",
    "other": _NET + "shape=mxgraph.networks.pc;fillColor=#f5f5f5;strokeColor=#999999;",
    "group": "swimlane;whiteSpace=wrap;startSize=26;fillColor=#f5f5f5;strokeColor=#666666;fontStyle=1;collapsible=0;",
    "host": "rounded=1;whiteSpace=wrap;fillColor=#ffffff;strokeColor=#6c8ebf;fontSize=10;align=left;spacingLeft=6;",
    "more": "text;whiteSpace=wrap;align=center;verticalAlign=middle;fontStyle=2;fontColor=#666666;",
    "title": "rounded=0;whiteSpace=wrap;fillColor=#ffffff;strokeColor=#666666;align=left;verticalAlign=top;"
             "spacingLeft=10;spacingTop=8;fontSize=11;",
    "edge": "endArrow=none;html=0;rounded=0;fontSize=10;labelBackgroundColor=#ffffff;",
    "edge_guess": "endArrow=none;html=0;dashed=1;rounded=0;strokeColor=#999999;",
}


def to_drawio(doc, max_hosts=DRAWIO_MAX):
    """draw.io XML (χωρίς συμπίεση): Internet → router → switches/AP (ακμές από LLDP/whereis) → συσκευές ανά VLAN/subnet."""
    lg = doc.get("lang", "el")
    mx = ET.Element("mxfile", host="NetWatch", type="device")
    dg = ET.SubElement(mx, "diagram", id="netwatch", name=_L(lg, "Δίκτυο", "Network"))
    model = ET.SubElement(dg, "mxGraphModel", dx="1200", dy="800", grid="1", gridSize="10", guides="1", tooltips="1",
                          connect="1", arrows="1", fold="1", page="1", pageScale="1", pageWidth="1654", pageHeight="1169",
                          math="0", shadow="0")
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", id="0")
    ET.SubElement(root, "mxCell", id="1", parent="0")
    seq = [1]

    def vid():
        seq[0] += 1
        return f"n{seq[0]}"

    def vertex(label, style, x, y, w, h, parent="1"):
        i = vid()
        c = ET.SubElement(root, "mxCell", id=i, value=str(label), style=style, vertex="1", parent=parent)
        ET.SubElement(c, "mxGeometry", {"x": str(int(x)), "y": str(int(y)), "width": str(int(w)), "height": str(int(h)), "as": "geometry"})
        return i

    def edge(a, b, label="", style=STY["edge"]):
        i = vid()
        c = ET.SubElement(root, "mxCell", id=i, value=str(label), style=style, edge="1", parent="1", source=a, target=b)
        ET.SubElement(c, "mxGeometry", {"relative": "1", "as": "geometry"})
        return i

    W, H, GAP = 110, 78, 70  # εικονίδιο + ετικέτα από κάτω
    devs = doc.get("devices") or []
    routers = [d for d in devs if d["role"] == "router"]
    switches = [d for d in devs if d["role"] in ("switch", "ap")]
    others = [d for d in devs if d["role"] not in ("router", "switch", "ap")]
    if not routers:  # πάντα ένας router: ο gateway (ή γενικός)
        routers = [{"name": "Router", "host": doc.get("gateway") or "", "role": "router"}]
    ids = {}

    def lbl(d):
        parts = [d["name"]]
        if d.get("host"):
            parts.append(d["host"])
        extra = d.get("model") or d.get("vendor")  # μοντέλο/κατασκευαστής, αν τα ξέρουμε
        if extra and extra not in parts:
            parts.append(extra)
        return "\n".join(str(p) for p in parts if p)

    def row(items, y, style_of):
        tot = len(items) * W + max(0, len(items) - 1) * GAP
        x0 = max(20, (1654 - tot) // 2)
        for k, d in enumerate(items):
            ids[d["name"]] = vertex(lbl(d), STY.get(style_of(d), STY["other"]), x0 + k * (W + GAP), y, W, H)

    # — title block (όπως στα επαγγελματικά «as-built» σχέδια) —
    c = doc.get("counts") or {}
    gen = time.strftime("%d/%m/%Y %H:%M", time.localtime(doc.get("generated") or time.time()))
    tb = "\n".join([
        _L(lg, "NetWatch — Διάγραμμα δικτύου", "NetWatch — Network diagram"),
        _L(lg, "Πύλη (gateway): ", "Gateway: ") + (doc.get("gateway") or "—"),
        _L(lg, "Ημερομηνία: ", "Date: ") + gen,
        _L(lg, "Συσκευές: ", "Devices: ") + str(c.get("devices") or len(doc.get("hosts") or []))
        + " · VLAN: " + str(c.get("vlans") or len(doc.get("vlans") or [])),
    ])
    vertex(tb, STY["title"], 20, 20, 360, 110)

    cloud = vertex("Internet", STY["cloud"], 1654 // 2 - 55, 30, 110, 78)
    row(routers, 170, lambda d: "router")
    for r in routers:
        edge(cloud, ids[r["name"]], "WAN")
    row(switches, 300, lambda d: d["role"])
    # γείτονες LLDP που δεν είναι γνωστές συσκευές (π.χ. AP χωρίς SNMP) → επίσης στη γραμμή 3
    unknown = []
    for l in doc.get("links") or []:
        for side in ("a", "b"):
            if l[side] not in ids and l[side] not in [u["name"] for u in unknown] and l[side] not in [o["name"] for o in others]:
                unknown.append({"name": l[side], "host": "", "role": "other"})
    row(others + unknown, 430, lambda d: d.get("role") if d.get("role") in STY else "other")
    linked = set()
    for l in doc.get("links") or []:
        a, b = ids.get(l["a"]), ids.get(l["b"])
        if a and b and a != b:
            ports = " ↔ ".join(p for p in (l.get("a_port"), l.get("b_port")) if p)
            edge(a, b, ports)
            linked.update([l["a"], l["b"]])
    r0 = ids[routers[0]["name"]]
    for d in switches + others:
        if d["name"] not in linked:
            edge(r0, ids[d["name"]], "", STY["edge_guess"])

    # — τελικές συσκευές σε ομάδες ανά VLAN/subnet —
    hosts = [h for h in doc.get("hosts") or [] if not h.get("netdev")]
    shown, rest = hosts[:max_hosts], hosts[max_hosts:]
    groups = {}
    for h in shown:
        if h.get("vlan") not in (None, ""):
            key = f"VLAN {h['vlan']}" + (f" · {h['subnet']}" if h.get("subnet") else "")
        else:
            key = h.get("subnet") or "LAN"
        groups.setdefault(key, []).append(h)
    vname = {v["id"]: v.get("name") for v in doc.get("vlans") or []}
    COLS, HW, HH, PAD = 4, 140, 46, 12
    gx, gy, rowh = 20, 590, 0
    for key, members in groups.items():
        m = re.match(r"VLAN (\d+)", key)
        title = key + (f" ({vname[int(m.group(1))]})" if m and vname.get(int(m.group(1))) else "")
        cols = min(COLS, max(1, len(members)))
        rows_n = (len(members) + cols - 1) // cols
        gw_, gh = cols * (HW + PAD) + PAD, 26 + rows_n * (HH + PAD) + PAD
        if gx + gw_ > 1620 and gx > 20:
            gx, gy, rowh = 20, gy + rowh + 30, 0
        g = vertex(title, STY["group"], gx, gy, gw_, gh)
        for k, h in enumerate(members):
            ic = h.get("icon") or ""
            nm = (ic + " " if ic else "") + (h.get("name") or h.get("type") or h.get("mac") or "?")
            l2 = h["ip"] + (f" · {h['type']}" if h.get("type") and h.get("name") else "")
            vertex(nm + "\n" + l2, STY["host"],
                   PAD + (k % cols) * (HW + PAD), 26 + PAD + (k // cols) * (HH + PAD), HW, HH, parent=g)
        sws = [h.get("switch") for h in members if h.get("switch")]
        up = ids.get(max(set(sws), key=sws.count)) if sws else None
        if up is None:
            up = ids[switches[0]["name"]] if switches else r0
            edge(up, g, "", STY["edge_guess"])
        else:
            edge(up, g, "")
        gx, rowh = gx + gw_ + 30, max(rowh, gh)
    if rest:
        vertex(_L(lg, f"+{len(rest)} ακόμα συσκευές", f"+{len(rest)} more devices"), STY["more"], gx, gy, 160, 40)
    ET.indent(mx) if hasattr(ET, "indent") else None
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(mx, encoding="unicode") + "\n"


def filename(fmt, now=None):
    return "netwatch-network-" + time.strftime("%Y%m%d", time.localtime(now or time.time())) + "." + fmt
