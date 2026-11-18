"""🔁 Έλεγχος πριν/μετά από αλλαγή (pre/post change check).

Πριν από μια αλλαγή στο δίκτυο (νέο VLAN, firmware router, αλλαγή DHCP/DNS, νέο switch) πατάς «Στιγμιότυπο
Πριν», κάνεις την αλλαγή, πατάς «Στιγμιότυπο Μετά» και το compare() δείχνει τι χάλασε: συσκευές που δεν
απαντούν πια, θύρες που έκλεισαν, πιο αργές συσκευές, άλλη MAC στο router (πιθανό ARP spoofing ή νέο
router), DNS που δεν λύνει, internet που χάθηκε.

Ενεργοί έλεγχοι ΜΟΝΟ προς ιδιωτικές/loopback διευθύνσεις και προς ένα μικρό σταθερό σύνολο γνωστών δημόσιων
anycast (1.1.1.1, 8.8.8.8, 9.9.9.9 και τα captive-portal URL της Apple/Google). Κάθε έλεγχος έχει μικρό
timeout και καμία συνάρτηση probe δεν σηκώνει εξαίρεση. Στο demo δεν αγγίζουμε καθόλου το δίκτυο.

Οι βοηθητικές συναρτήσεις ping/tcp/dns_query/sys_resolve/http_probe/local_info χρησιμοποιούνται και από
το nettriage.py («Φταίει το δίκτυο;»).

API
---
ChangeCheck(state, sim=False, path=None, clock=time.time)
  .snapshot(label, targets=None) → {ok, status:"running", label} | {error}     (τρέχει σε νήμα)
  .compare(a, b)  → {a:{id,label,t}, b:{…}, verdict:"ok"|"warn"|"bad", summary, counts:{lost,new,changed,same,slower},
                     items:[{kind, key, name, before, after, status, sev, note}]}
  .view()         → {status, running_label, snapshots:[{id,label,t,hosts,ports,took_ms}], last_compare, demo}
  .delete(id)     → {ok} | {error}
"""
import http.client
import ipaddress
import json
import math
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout

import netkit

MAX_SNAPS = 20
MAX_HOSTS = 64
MAX_PORT_HOSTS = 16
MAX_TARGETS = 64
MAX_LABEL = 40
DEMO_DELAY = 1.2   # δευτερόλεπτα «συλλογής» στο demo (για να φανεί το running στο UI)
COMMON_PORTS = (22, 23, 53, 80, 443, 445, 554, 1883, 8080, 8443, 3389)   # 161 είναι UDP — παραλείπεται
GW_DEFAULT_PORTS = (53, 80, 443)
PUBLIC_OK = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
CAPTIVE_URLS = ("http://captive.apple.com/hotspot-detect.html", "http://connectivitycheck.gstatic.com/generate_204")
DNS_NAMES = ("google.com", "cloudflare.com")
RANK = {"high": 3, "med": 2, "low": 1, "info": 0}
BEFORE_WORDS = ("πριν", "before", "pre")
AFTER_WORDS = ("μετά", "μετα", "after", "post")
UA = "NetWatch/1.0 (changecheck)"
_MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})")


# =============================== ασφαλή probes (ποτέ δεν σηκώνουν εξαίρεση) ===============================
def allowed(ip):
    """Επιτρέπεται ενεργός έλεγχος; Μόνο ιδιωτικές/loopback IPv4/IPv6 και οι σταθερές δημόσιες anycast."""
    if str(ip) in PUBLIC_OK:
        return True
    try:
        a = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return False
    if a.is_multicast or a.is_unspecified or (a.version == 4 and str(a).endswith(".255")):
        return False
    return a.is_private or a.is_loopback or a.is_link_local


def private_ip(ip):
    """Μόνο ιδιωτική IP του LAN (για targets από τον χρήστη) — όχι loopback/δημόσια/multicast/broadcast."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return a.is_private and not (a.is_loopback or a.is_multicast or a.is_unspecified or a.is_link_local) \
        and not (a.version == 4 and str(a).endswith(".255"))


def _empty_ping(count, err=None):
    return {"sent": count, "received": 0, "loss_pct": 100.0, "min": None, "avg": None, "max": None,
            "jitter": None, "rtts": [], "ttl": None, "ok": False, "err": err}


def ping(ip, count=2, interval=0.2, timeout=1.0, size=None, df=False):
    """ICMP ping με μικρό timeout → {sent, received, loss_pct, avg, jitter, rtts, ok, err}.
    err: "noping" (δεν υπάρχει ping), "noflag" (η πλατφόρμα δεν ξέρει DF), "denied" (μη επιτρεπτός στόχος)."""
    if not allowed(ip):
        return _empty_ping(count, "denied")
    exe = shutil.which("ping")
    if not exe or sys.platform not in ("darwin",) and not sys.platform.startswith("linux"):
        return _empty_ping(count, "noping")
    deadline = int(math.ceil(count * interval + timeout + 1))
    if sys.platform == "darwin":
        cmd = [exe, "-n", "-c", str(count), "-i", str(interval), "-W", str(int(timeout * 1000)), "-t", str(deadline)]
        cmd += ["-D"] if df else []
    else:
        cmd = [exe, "-4", "-n", "-c", str(count), "-i", str(interval), "-W", str(max(1, int(math.ceil(timeout)))),
               "-w", str(deadline)]
        cmd += ["-M", "do"] if df else []
    if size:
        cmd += ["-s", str(int(size))]
    cmd.append(str(ip))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=deadline + 2,
                           env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except (OSError, subprocess.SubprocessError):
        return _empty_ping(count, "noping")
    err_txt = (p.stderr or "").lower()
    if df and re.search(r"illegal option|invalid option|unrecognized|invalid argument|usage:", err_txt) \
            and "bytes from" not in p.stdout:
        return _empty_ping(count, "noflag")
    r = netkit.parse_ping(p.stdout or "")
    if not r["sent"]:
        r.update(sent=count, received=0, loss_pct=100.0)
    r["ok"] = bool(r["received"])
    r["err"] = None
    if df and not r["ok"] and re.search(r"message too long|frag needed|local error", (p.stdout + err_txt).lower()):
        r["err"] = "toolong"
    return r


def tcp(ip, port, timeout=1.0):
    """Σύνδεση TCP → {state: "open"|"closed"|"filtered"|"denied", ms}. «closed» = η συσκευή απάντησε (RST)."""
    if not allowed(ip):
        return {"state": "denied", "ms": None}
    t0 = time.monotonic()
    try:
        s = socket.socket(socket.AF_INET6 if ":" in str(ip) else socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return {"state": "filtered", "ms": None}
    s.settimeout(timeout)
    try:
        s.connect((str(ip), int(port)))
        return {"state": "open", "ms": round((time.monotonic() - t0) * 1000, 1)}
    except ConnectionRefusedError:
        return {"state": "closed", "ms": round((time.monotonic() - t0) * 1000, 1)}
    except (OSError, ValueError):
        return {"state": "filtered", "ms": None}
    finally:
        try:
            s.close()
        except OSError:
            pass


def dns_query(name, server, timeout=1.5):
    """Ερώτημα A σε συγκεκριμένο DNS server (μόνο επιτρεπτοί) → {ok, ip, ms, rcode, err}."""
    if not allowed(server):
        return {"ok": False, "ip": None, "ms": None, "rcode": None, "err": "denied"}
    try:
        r = netkit.dns_lookup(name, "A", server=str(server), timeout=timeout)
    except Exception as e:  # TimeoutError / OSError / ValueError
        return {"ok": False, "ip": None, "ms": None, "rcode": None, "err": str(e)[:120]}
    ips = [a["data"] for a in r.get("answers") or [] if a.get("type") == "A"]
    return {"ok": r.get("rcode") == "NOERROR" and bool(ips), "ip": ips[0] if ips else None, "ms": r.get("ms"),
            "rcode": r.get("rcode"), "err": None if ips else (r.get("rcode") or "χωρίς απάντηση")}


_RES_POOL = ThreadPoolExecutor(4, thread_name_prefix="nw-resolve")


def sys_resolve(name, timeout=2.0):
    """Επίλυση μέσω του resolver του συστήματος (ό,τι κάνουν και οι εφαρμογές) με όριο χρόνου."""
    t0 = time.monotonic()
    fut = _RES_POOL.submit(socket.getaddrinfo, name, None, socket.AF_INET, socket.SOCK_STREAM)
    try:
        infos = fut.result(timeout=timeout)
    except FutTimeout:
        return {"ok": False, "ip": None, "ms": None, "err": f"timeout {timeout:g} s"}
    except Exception as e:  # gaierror κ.λπ.
        return {"ok": False, "ip": None, "ms": None, "err": str(e)[:120]}
    ip = infos[0][4][0] if infos else None
    return {"ok": bool(ip), "ip": ip, "ms": round((time.monotonic() - t0) * 1000, 1), "err": None if ip else "κενό"}


def http_probe(url, timeout=3.0):
    """GET σε ένα από τα σταθερά captive-portal URL (χωρίς ανακατευθύνσεις) → {status, location, body, ms, err}."""
    if url not in CAPTIVE_URLS:
        return {"status": None, "location": None, "body": "", "ms": None, "err": "denied"}
    u = urllib.parse.urlparse(url)
    t0 = time.monotonic()
    c = http.client.HTTPConnection(u.hostname, 80, timeout=timeout)
    try:
        c.request("GET", u.path or "/", headers={"User-Agent": UA, "Connection": "close"})
        r = c.getresponse()
        body = r.read(2048).decode("latin-1", "replace")
        return {"status": r.status, "location": r.getheader("Location"), "body": body,
                "ms": round((time.monotonic() - t0) * 1000, 1), "err": None}
    except Exception as e:
        return {"status": None, "location": None, "body": "", "ms": None, "err": str(e)[:120] or type(e).__name__}
    finally:
        c.close()


def iface_kind(name):
    """"wifi" | "ethernet" | "vpn" | None — φτηνή ανίχνευση τύπου διεπαφής."""
    if not name:
        return None
    if re.match(r"^(utun|tun|tap|wg|ppp|ipsec)", name):
        return "vpn"
    try:
        if sys.platform == "darwin":
            out = netkit._run(["networksetup", "-listallhardwareports"], timeout=3)
            for block in out.split("\n\n"):
                if re.search(rf"^Device:\s*{re.escape(name)}\s*$", block, re.M):
                    return "wifi" if re.search(r"Wi-?Fi|AirPort", block, re.I) else "ethernet"
        elif os.path.isdir(f"/sys/class/net/{name}"):
            return "wifi" if os.path.exists(f"/sys/class/net/{name}/wireless") else "ethernet"
    except Exception:
        pass
    if re.match(r"^(wl|wlan|ath)", name):
        return "wifi"
    if re.match(r"^(eth|eno|enp|ens)", name):
        return "ethernet"
    return None


def local_info(sim=False):
    """Η δική σου σύνδεση → {iface, up, ip, prefix, mtu, gateway, dns:[...], kind}. Ποτέ εξαίρεση."""
    try:
        info = netkit.iface_info(sim=sim)
    except Exception:
        info = {"interfaces": [], "gateway": None, "gateway_iface": None, "dns": []}
    ifs = info.get("interfaces") or []
    name = info.get("gateway_iface")
    cur = next((i for i in ifs if i.get("name") == name), None)
    if cur is None:  # χωρίς default route: η πρώτη ενεργή μη-loopback διεπαφή με IPv4
        cur = next((i for i in ifs if i.get("up") and i.get("ipv4") and not str(i.get("name")).startswith("lo")
                    and not any(str(a.get("addr", "")).startswith("127.") for a in i["ipv4"])), None)
    if cur is None:
        cur = next((i for i in ifs if not str(i.get("name")).startswith(("lo", "utun", "awdl", "llw", "bridge", "gif", "stf",
                                                                           "anpi", "ap"))), None)
    v4 = (cur or {}).get("ipv4") or []
    return {"iface": (cur or {}).get("name"), "up": bool((cur or {}).get("up")),
            "ip": v4[0].get("addr") if v4 else None, "prefix": v4[0].get("prefix") if v4 else None,
            "mtu": (cur or {}).get("mtu"), "gateway": info.get("gateway"),
            "dns": [d for d in info.get("dns") or [] if ":" not in d][:4],
            "kind": None if sim else iface_kind((cur or {}).get("name"))}


def arp_mac(ip):
    """MAC μιας IP από τον πίνακα ARP του συστήματος (μόνο για το gateway)."""
    out = netkit._run(["arp", "-n", str(ip)], timeout=2) if shutil.which("arp") else ""
    if not out:
        out = netkit._run(["ip", "neigh", "show", str(ip)], timeout=2)
    m = _MAC_RE.search(out or "")
    if not m:
        return None
    from core import norm_mac
    return norm_mac(m.group(1).lower())


# =============================== βοηθητικά σύγκρισης ===============================
def _ms(v):
    return f"{v:g} ms" if isinstance(v, (int, float)) else "—"


def _plural(n, one, many):
    return one.format(n=n) if n == 1 else many.format(n=n)


def _host_txt(h):
    if not h:
        return None
    return f"απαντά · {_ms(round(h['rtt'], 1))}" if h.get("up") and h.get("rtt") is not None else \
        ("απαντά" if h.get("up") else "δεν απαντά")


def _is(label, words):
    low = str(label or "").lower()
    return any(w in low for w in words)


class ChangeCheck:
    def __init__(self, state, sim=False, path=None, clock=time.time):
        self.st, self.sim, self.path, self.clock = state, sim, path, clock
        self.lock = threading.RLock()
        self.snaps = []           # παλαιότερο πρώτο
        self.seq = 0
        self.running = None       # ετικέτα του στιγμιότυπου που τρέχει
        self.on_save = None
        if path and not sim:
            self._load()
        if sim:
            self._seed()

    # ───────── δημόσιο API ─────────
    def snapshot(self, label, targets=None):
        label = str(label or "").strip()
        if not label:
            raise ValueError("Δώσε ετικέτα (π.χ. «Πριν» ή «Μετά»).")
        if len(label) > MAX_LABEL:
            raise ValueError(f"Η ετικέτα πρέπει να έχει έως {MAX_LABEL} χαρακτήρες.")
        tg = None
        if targets:
            if not isinstance(targets, (list, tuple)) or len(targets) > MAX_TARGETS:
                raise ValueError(f"Οι στόχοι πρέπει να είναι λίστα έως {MAX_TARGETS} IP.")
            tg = []
            for x in targets:
                x = str(x).strip()
                if not private_ip(x):
                    raise ValueError(f"Μόνο ιδιωτικές IP του LAN (π.χ. 192.168.1.40) — όχι «{x[:40]}».")
                if x not in tg:
                    tg.append(str(ipaddress.ip_address(x)))
        with self.lock:
            if self.running:
                return {"error": "Τρέχει ήδη στιγμιότυπο — περίμενε να τελειώσει."}
            self.running = label
        threading.Thread(target=self._run, args=(label, tg), daemon=True, name="nw-changecheck").start()
        return {"ok": True, "status": "running", "label": label}

    def delete(self, sid):
        with self.lock:
            s = self._find(sid)
            if not s:
                return {"error": "Δεν βρέθηκε το στιγμιότυπο."}
            self.snaps.remove(s)
        self.save()
        return {"ok": True, "id": s["id"]}

    def view(self):
        with self.lock:
            snaps = [{"id": s["id"], "label": s["label"], "t": s["t"], "hosts": len(s.get("hosts") or {}),
                      "ports": sum(1 for p in (s.get("ports") or {}).values() if p.get("open")),
                      "took_ms": s.get("took_ms")} for s in reversed(self.snaps)]
            pair = self._pair()
            running = self.running
        return {"status": "running" if running else "idle", "running_label": running, "snapshots": snaps,
                "last_compare": self.compare(pair[0]["id"], pair[1]["id"]) if pair else None, "demo": bool(self.sim)}

    def compare(self, a, b):
        with self.lock:
            A, B = self._find(a), self._find(b)
        if not A or not B:
            return {"error": "Δεν βρέθηκε το στιγμιότυπο."}
        if A["t"] > B["t"]:
            A, B = B, A
        items = []
        items += self._cmp_hosts(A, B)
        lost_hosts = {i["key"] for i in items if i["status"] == "lost"}
        items += self._cmp_ports(A, B, lost_hosts)
        items += self._cmp_gateway(A, B)
        items += self._cmp_dns(A, B)
        items += self._cmp_internet(A, B)
        items += self._cmp_local(A, B)
        order = {"lost": 0, "changed": 1, "slower": 2, "new": 3, "same": 4}
        items.sort(key=lambda i: (-RANK[i["sev"]], order[i["status"]], i["kind"], _sort_key(i["key"])))
        counts = {k: sum(1 for i in items if i["status"] == k) for k in ("lost", "new", "changed", "same", "slower")}
        sevs = [i["sev"] for i in items if i["status"] != "same"]
        verdict = "bad" if "high" in sevs else "warn" if ("med" in sevs or "low" in sevs) else "ok"
        return {"a": {"id": A["id"], "label": A["label"], "t": A["t"]},
                "b": {"id": B["id"], "label": B["label"], "t": B["t"]},
                "verdict": verdict, "summary": self._summary(items), "counts": counts, "items": items}

    # ───────── σύγκριση ανά είδος ─────────
    def _cmp_hosts(self, A, B):
        out = []
        ha, hb = A.get("hosts") or {}, B.get("hosts") or {}
        for ip in sorted(set(ha) | set(hb), key=_sort_key):
            x, y = ha.get(ip), hb.get(ip)
            name = (y or x or {}).get("name") or ip
            gw = bool((x or {}).get("gw") or (y or {}).get("gw"))
            it = {"kind": "host", "key": ip, "name": name, "before": _host_txt(x), "after": _host_txt(y), "gw": gw}
            if x and y is None:
                continue  # δεν ελέγχθηκε στο «μετά» (άλλοι στόχοι) — δεν βγάζουμε συμπέρασμα
            if x is None:
                if not y.get("up"):
                    continue
                it.update(status="new", sev="info", note="Νέα συσκευή — δεν υπήρχε στο πρώτο στιγμιότυπο.")
            elif x.get("up") and not y.get("up"):
                it.update(status="lost", sev="high",
                          note="Ο router (gateway) δεν απαντά πια — όλο το δίκτυο επηρεάζεται." if gw else
                          "Απαντούσε πριν, τώρα δεν απαντά — έλεγξε VLAN/καλώδιο/firewall ή αν απλώς κοιμάται.")
            elif not x.get("up") and y.get("up"):
                it.update(status="changed", sev="info", note="Δεν απαντούσε πριν, τώρα απαντά.")
            elif not x.get("up"):
                continue  # δεν απαντούσε ούτε πριν ούτε μετά
            else:
                ra, rb = x.get("rtt"), y.get("rtt")
                if ra is not None and rb is not None and rb >= 2 * ra and rb - ra >= 20:
                    it.update(status="slower", sev="low",
                              note=f"Πιο αργή: {_ms(round(ra, 1))} → {_ms(round(rb, 1))} — πιθανή διαδρομή μέσω router/άλλου VLAN ή φορτωμένο link.")
                else:
                    it.update(status="same", sev="info", note="Ίδια συμπεριφορά.")
            out.append(it)
        return out

    def _cmp_ports(self, A, B, lost_hosts):
        out = []
        pa, pb = A.get("ports") or {}, B.get("ports") or {}
        hb = B.get("hosts") or {}
        for key in sorted(set(pa) | set(pb), key=_sort_key):
            x, y = pa.get(key), pb.get(key)
            ip = key.rsplit(":", 1)[0]
            if ip in lost_hosts or y is None or not ((x or {}).get("open") or y.get("open")):
                continue  # ο host χάθηκε (φαίνεται ήδη) / δεν ελέγχθηκε / κλειστή και πριν και μετά
            name = y.get("name") or (x or {}).get("name") or (hb.get(ip) or {}).get("name") or ip
            st = lambda p: None if p is None else ("ανοιχτή" if p.get("open") else "κλειστή")  # noqa: E731
            it = {"kind": "port", "key": key, "name": name, "before": st(x), "after": st(y)}
            if x and x.get("open") and not y.get("open"):
                it.update(status="lost", sev="med",
                          note=f"Η θύρα {key.rsplit(':', 1)[1]} έκλεισε — η υπηρεσία δεν είναι πια προσβάσιμη (firewall/ACL ή έπεσε).")
            elif y.get("open") and not (x or {}).get("open"):
                it.update(status="new", sev="info", note=f"Νέα ανοιχτή θύρα {key.rsplit(':', 1)[1]}.")
            else:
                it.update(status="same", sev="info", note="Ανοιχτή και πριν και μετά.")
            out.append(it)
        return out

    def _cmp_gateway(self, A, B):
        x, y = A.get("gateway") or {}, B.get("gateway") or {}
        out = []
        if not x.get("ip") and not y.get("ip"):
            return out
        if x.get("ip") != y.get("ip"):
            out.append({"kind": "gateway", "key": "ip", "name": "Gateway (router)", "before": x.get("ip"), "after": y.get("ip"),
                        "status": "changed" if x.get("ip") and y.get("ip") else ("lost" if x.get("ip") else "new"),
                        "sev": "high" if x.get("ip") else "info",
                        "note": "Άλλαξε η διεύθυνση του router — έλεγξε DHCP/στατικές ρυθμίσεις." if y.get("ip")
                        else "Δεν υπάρχει πια default gateway."})
        elif x.get("mac") and y.get("mac") and x["mac"] != y["mac"]:
            out.append({"kind": "gateway", "key": "mac", "name": f"Gateway {y['ip']}", "before": x["mac"], "after": y["mac"],
                        "status": "changed", "sev": "high",
                        "note": "Άλλαξε η MAC του router — αν δεν άλλαξες router, πιθανό ARP spoofing!"})
        else:
            out.append({"kind": "gateway", "key": "mac", "name": f"Gateway {y.get('ip')}", "before": x.get("mac"),
                        "after": y.get("mac"), "status": "same", "sev": "info", "note": "Ίδιο router (ίδια IP και MAC)."})
        return out

    def _cmp_dns(self, A, B):
        out = []
        da, db = A.get("dns") or {}, B.get("dns") or {}
        for key in sorted(set(da) | set(db)):
            x, y = da.get(key), db.get(key)
            if y is None or x is None and not y.get("ok"):
                continue
            r = lambda d: None if d is None else (f"{d.get('ip')} · {_ms(d.get('ms'))}" if d.get("ok") else "αποτυχία")  # noqa: E731
            srv = "resolver συστήματος" if y.get("server") == "system" else y.get("server")
            it = {"kind": "dns", "key": key, "name": f"{y.get('name')} μέσω {srv}", "before": r(x), "after": r(y)}
            if x and x.get("ok") and not y.get("ok"):
                it.update(status="lost", sev="high", note="Το DNS δεν λύνει πια αυτό το όνομα — οι εφαρμογές «δεν έχουν internet».")
            elif x is None:
                it.update(status="new", sev="info", note="Νέος έλεγχος DNS.")
            elif not x.get("ok") and y.get("ok"):
                it.update(status="changed", sev="info", note="Το DNS λύνει ξανά.")
            else:
                it.update(status="same", sev="info", note="Λύνεται κανονικά." if y.get("ok") else "Αποτύγχανε και πριν.")
            out.append(it)
        return out

    def _cmp_internet(self, A, B):
        out = []
        ia, ib = A.get("internet") or {}, B.get("internet") or {}
        for key in sorted(set(ia) | set(ib)):
            x, y = ia.get(key), ib.get(key)
            if y is None:
                continue
            r = lambda d: None if d is None else (f"OK · {_ms(d.get('ms'))}" if d.get("ok") else "αποτυχία")  # noqa: E731
            it = {"kind": "internet", "key": key, "name": y.get("name") or key, "before": r(x), "after": r(y)}
            if x and x.get("ok") and not y.get("ok"):
                it.update(status="lost", sev="high", note="Χάθηκε η πρόσβαση στο internet από αυτόν τον υπολογιστή.")
            elif x is None:
                if not y.get("ok"):
                    continue
                it.update(status="new", sev="info", note="Νέος έλεγχος internet.")
            elif not x.get("ok") and y.get("ok"):
                it.update(status="changed", sev="info", note="Το internet δουλεύει ξανά.")
            else:
                it.update(status="same", sev="info", note="Ίδιο με πριν.")
            out.append(it)
        return out

    def _cmp_local(self, A, B):
        out = []
        x, y = A.get("local") or {}, B.get("local") or {}
        fields = [("iface", "Διεπαφή", "low", "Άλλαξε η ενεργή διεπαφή (π.χ. Wi‑Fi ↔ Ethernet)."),
                  ("ip", "Η IP σου", "med", "Άλλαξε η IP του υπολογιστή σου (νέο DHCP lease ή άλλο VLAN/υποδίκτυο)."),
                  ("dns", "DNS servers", "med", "Άλλαξαν οι DNS servers που δίνει το DHCP."),
                  ("mtu", "MTU", "low", "Άλλαξε το MTU της διεπαφής.")]
        for f, nm, sev, note in fields:
            va, vb = x.get(f), y.get(f)
            if va is None and vb is None:
                continue
            show = lambda v: ", ".join(v) if isinstance(v, list) else (None if v is None else str(v))  # noqa: E731
            if f == "ip":
                va = f"{va}/{x.get('prefix')}" if va and x.get("prefix") else va
                vb = f"{vb}/{y.get('prefix')}" if vb and y.get("prefix") else vb
            same = va == vb
            out.append({"kind": "local", "key": f, "name": nm, "before": show(va), "after": show(vb),
                        "status": "same" if same else "changed", "sev": "info" if same else sev,
                        "note": "Ίδιο με πριν." if same else note})
        return out

    def _summary(self, items):
        def n(kind, status):
            return sum(1 for i in items if i["kind"] == kind and i["status"] == status)
        gw_lost = any(i["kind"] == "host" and i["status"] == "lost" and i.get("gw") for i in items)
        parts = []
        if gw_lost:
            parts.append("ο router δεν απαντά")
        if any(i["kind"] == "gateway" and i["status"] == "changed" and i["key"] == "mac" for i in items):
            parts.append("άλλαξε η MAC του router")
        if n("internet", "lost"):
            parts.append("χάθηκε το internet")
        if n("dns", "lost"):
            parts.append("το DNS αποτυγχάνει")
        h = n("host", "lost") - (1 if gw_lost else 0)
        if h:
            parts.append(_plural(h, "{n} συσκευή δεν απαντά πια", "{n} συσκευές δεν απαντούν πια"))
        p = n("port", "lost")
        if p:
            parts.append(_plural(p, "{n} θύρα έκλεισε", "{n} θύρες έκλεισαν"))
        s = n("host", "slower")
        if s:
            parts.append(_plural(s, "{n} συσκευή πιο αργή", "{n} συσκευές πιο αργές"))
        lc = sum(1 for i in items if i["kind"] in ("local", "gateway") and i["status"] == "changed" and i["key"] != "mac")
        if lc:
            parts.append(_plural(lc, "{n} αλλαγή στη σύνδεσή σου", "{n} αλλαγές στη σύνδεσή σου"))
        nh = n("host", "new")
        if nh:
            parts.append(_plural(nh, "{n} νέα συσκευή", "{n} νέες συσκευές"))
        if not parts:
            return "Καμία αλλαγή — όλα όπως πριν."
        s = ", ".join(parts)
        return s[0].upper() + s[1:]

    # ───────── εσωτερικά ─────────
    def _find(self, sid):
        try:
            sid = int(sid)
        except (TypeError, ValueError):
            return None
        return next((s for s in self.snaps if s["id"] == sid), None)

    def _pair(self):
        """Το νεότερο «Μετά» και το νεότερο «Πριν» που είναι παλαιότερο από αυτό (ή None)."""
        after = next((s for s in reversed(self.snaps) if _is(s["label"], AFTER_WORDS)), None)
        if not after:
            return None
        before = next((s for s in reversed(self.snaps) if s["t"] < after["t"] and _is(s["label"], BEFORE_WORDS)
                       and not _is(s["label"], AFTER_WORDS)), None)
        return (before, after) if before else None

    def _add(self, snap):
        with self.lock:
            self.seq += 1
            snap["id"] = self.seq
            self.snaps.append(snap)
            self.snaps = self.snaps[-MAX_SNAPS:]
        self.save()
        return snap

    def _run(self, label, targets):
        t0 = time.monotonic()
        try:
            if self.sim:
                time.sleep(DEMO_DELAY)
                snap = self._demo_copy(label, targets)
            else:
                snap = self.collect(targets)
                snap.update(label=label, t=self.clock(), took_ms=int((time.monotonic() - t0) * 1000))
            self._add(snap)
        except Exception as e:  # ποτέ να μην «κολλήσει» σε running
            try:
                from core import log
                log("changecheck:", e)
            except Exception:
                pass
        finally:
            with self.lock:
                self.running = None

    # ───────── συλλογή (live) ─────────
    def _lan_hosts(self, targets):
        st = self.st
        gw = getattr(st, "gateway", None)
        me = set(getattr(st, "me", None) or ())
        hosts = getattr(st, "hosts", None) or {}
        lock = getattr(st, "lock", None)
        try:
            if lock:
                with lock:
                    vals = [dict(ip=h.get("ip"), kind=h.get("kind"), last=h.get("last") or 0, rdns=h.get("rdns"),
                                 names=sorted(h.get("names") or ()), ports=list(h.get("ports") or ()), gw=h.get("gw"))
                            for h in list(hosts.values())]
            else:
                vals = [dict(ip=h.get("ip"), kind=h.get("kind"), last=h.get("last") or 0, rdns=h.get("rdns"),
                             names=sorted(h.get("names") or ()), ports=list(h.get("ports") or ()), gw=h.get("gw"))
                        for h in list(hosts.values())]
        except Exception:
            vals = []
        by = {v["ip"]: v for v in vals if v.get("ip")}
        if targets:
            ips = list(targets)
        else:
            cand = [v for v in vals if v.get("kind") in ("local", "lan") and private_ip(v.get("ip"))
                    and v["ip"] not in me and v["ip"] != gw and ":" not in v["ip"]]
            cand.sort(key=lambda v: -v["last"])
            ips = ([gw] if gw and private_ip(gw) else []) + [v["ip"] for v in cand[:MAX_HOSTS]]
        out = []
        for ip in ips[:MAX_HOSTS + 1]:
            v = by.get(ip) or {}
            out.append({"ip": ip, "name": v.get("rdns") or (v.get("names") or [None])[0], "gw": ip == gw,
                        "ports": v.get("ports") or []})
        return out

    def _known_ports(self, ip, seen, gw):
        known = set(int(p) for p in seen if isinstance(p, int) or str(p).isdigit())
        for attr in ("scan_info", "services"):
            try:
                known |= set(int(p) for p in ((getattr(self.st, attr, None) or {}).get(ip) or {}))
            except Exception:
                pass
        ports = sorted(p for p in known if p in COMMON_PORTS)
        if not ports and ip == gw:
            ports = list(GW_DEFAULT_PORTS)
        return ports

    def collect(self, targets=None):
        """Ένα πλήρες στιγμιότυπο (live). Κάθε έλεγχος έχει μικρό timeout· τίποτα δεν σηκώνει εξαίρεση."""
        hosts = self._lan_hosts(targets)
        gw = getattr(self.st, "gateway", None)
        have_ping = bool(shutil.which("ping"))

        def reach(h):
            ip = h["ip"]
            if have_ping:
                r = ping(ip, count=2, interval=0.2, timeout=1.0)
                if r["ok"]:
                    return ip, {"up": True, "rtt": r["avg"], "via": "icmp"}
            for p in (h["ports"] and [x for x in h["ports"] if x in COMMON_PORTS][:2]) or [80, 443]:
                t = tcp(ip, p, timeout=0.8)
                if t["state"] in ("open", "closed"):
                    return ip, {"up": True, "rtt": t["ms"], "via": "tcp"}
            return ip, {"up": False, "rtt": None, "via": "icmp" if have_ping else "tcp"}

        port_jobs = []
        for h in [x for x in hosts if x["gw"]] + [x for x in hosts if not x["gw"]]:
            ps = self._known_ports(h["ip"], h["ports"], gw)
            if ps and len({j[0] for j in port_jobs}) < MAX_PORT_HOSTS:
                port_jobs += [(h["ip"], p) for p in ps]
        names = list(DNS_NAMES)
        gwh = next((h for h in hosts if h["gw"]), None)
        rname = (gwh or {}).get("name")
        if rname and not rname.endswith(".local") and "." in rname:
            names.append(rname)
        with ThreadPoolExecutor(32, thread_name_prefix="nw-cc") as ex:
            f_reach = [ex.submit(reach, h) for h in hosts]
            f_ports = [(ip, p, ex.submit(tcp, ip, p, 1.0)) for ip, p in port_jobs]
            f_dns = [(n, "system", ex.submit(sys_resolve, n, 2.0)) for n in names]
            f_dns += [(n, "1.1.1.1", ex.submit(dns_query, n, "1.1.1.1", 1.5)) for n in DNS_NAMES]
            f_net = [("tcp:1.1.1.1:443", "Cloudflare 1.1.1.1 (TCP 443)", ex.submit(tcp, "1.1.1.1", 443, 2.0)),
                     ("tcp:8.8.8.8:443", "Google 8.8.8.8 (TCP 443)", ex.submit(tcp, "8.8.8.8", 443, 2.0)),
                     ("http:generate_204", "Έλεγχος HTTP 204 (Google)", ex.submit(http_probe, CAPTIVE_URLS[1], 3.0))]
            f_local = ex.submit(local_info)
            f_mac = ex.submit(self._gw_mac, gw)
            res_hosts = {}
            for h, f in zip(hosts, f_reach):
                ip, r = f.result()
                res_hosts[ip] = {"name": h["name"], "gw": h["gw"], **r}
            names_by = {h["ip"]: h["name"] for h in hosts}
            ports = {f"{ip}:{p}": {"name": names_by.get(ip), "open": f.result()["state"] == "open", "ms": f.result()["ms"]}
                     for ip, p, f in f_ports}
            dns = {}
            for n, srv, f in f_dns:
                r = f.result()
                dns[f"{n}@{srv}"] = {"name": n, "server": srv, "ok": r["ok"], "ip": r["ip"], "ms": r["ms"], "err": r["err"]}
            internet = {}
            for key, nm, f in f_net:
                r = f.result()
                ok = r.get("state") == "open" if key.startswith("tcp:") else r.get("status") == 204
                internet[key] = {"name": nm, "ok": ok, "ms": r.get("ms")}
            local = f_local.result()
            mac = f_mac.result()
        local.pop("kind", None)
        return {"hosts": res_hosts, "ports": ports, "gateway": {"ip": gw, "mac": mac}, "dns": dns,
                "internet": internet, "local": local}

    def _gw_mac(self, gw):
        if not gw:
            return None
        try:
            m = (getattr(self.st, "arp_table", None) or {}).get(gw)
        except Exception:
            m = None
        return m or arp_mac(gw)

    # ───────── demo ─────────
    DEMO_HOSTS = [  # ip, όνομα, rtt (ms), θύρες
        ("192.168.1.1", "Router", 2.1, [22, 53, 80, 443]),
        ("192.168.1.15", "iPhone", 6.8, []),
        ("192.168.1.16", "Proxmox", 1.2, [22, 8443]),
        ("192.168.1.17", "Raspberry Pi (NAS)", 3.0, [22, 445, 1883]),
        ("192.168.1.20", "ESP32 κήπου", 9.5, [80]),
        ("192.168.1.30", "Home Assistant", 1.6, [22, 8080]),
        ("192.168.1.31", "Smart TV σαλονιού", 4.2, [8080]),
        ("192.168.1.33", "Κάμερα εισόδου (Tapo)", 5.3, [443, 554]),
        ("192.168.1.40", "Εκτυπωτής", 3.9, [80, 443]),
        ("192.168.1.52", "Πρίζα κουζίνας", 12.4, []),
    ]

    def _demo_base(self, regressed, rnd):
        j = lambda v: round(v * rnd.uniform(0.9, 1.1), 1)  # noqa: E731
        hosts, ports = {}, {}
        for ip, nm, rtt, ps in self.DEMO_HOSTS:
            up = not (regressed and ip == "192.168.1.40")
            r = 48.0 if regressed and ip == "192.168.1.17" else rtt
            hosts[ip] = {"name": nm, "gw": ip == "192.168.1.1", "up": up, "rtt": j(r) if up else None, "via": "icmp"}
            for p in ps:
                op = up and not (regressed and ip == "192.168.1.33" and p == 554)
                ports[f"{ip}:{p}"] = {"name": nm, "open": op, "ms": j(rtt + 0.4) if op else None}
        if regressed:
            hosts["192.168.1.99"] = {"name": "Άγνωστη συσκευή (da:7c:31)", "gw": False, "up": True, "rtt": j(7.7), "via": "icmp"}
        dns = {"google.com@system": {"name": "google.com", "server": "system", "ok": True, "ip": "142.250.184.110", "ms": j(4.2)},
               "google.com@1.1.1.1": {"name": "google.com", "server": "1.1.1.1", "ok": True, "ip": "142.250.184.110", "ms": j(17.5)},
               "cloudflare.com@system": {"name": "cloudflare.com", "server": "system", "ok": True, "ip": "104.16.132.229", "ms": j(3.8)},
               "cloudflare.com@1.1.1.1": {"name": "cloudflare.com", "server": "1.1.1.1", "ok": True, "ip": "104.16.132.229", "ms": j(15.9)},
               "router.home@system": {"name": "router.home", "server": "system", "ok": True, "ip": "192.168.1.1", "ms": j(1.9)}}
        internet = {"tcp:1.1.1.1:443": {"name": "Cloudflare 1.1.1.1 (TCP 443)", "ok": True, "ms": j(14.2)},
                    "tcp:8.8.8.8:443": {"name": "Google 8.8.8.8 (TCP 443)", "ok": True, "ms": j(17.1)},
                    "http:generate_204": {"name": "Έλεγχος HTTP 204 (Google)", "ok": True, "ms": j(22.6)}}
        return {"hosts": hosts, "ports": ports, "gateway": {"ip": "192.168.1.1", "mac": "a4:2b:b0:11:22:01"},
                "dns": dns, "internet": internet,
                "local": {"iface": "en0", "up": True, "ip": "192.168.1.23", "prefix": 24, "mtu": 1500,
                          "gateway": "192.168.1.1", "dns": ["192.168.1.1"]}}

    def _seed(self):
        now = self.clock()
        rnd = random.Random(11)
        a = self._demo_base(False, rnd)
        a.update(label="Πριν", t=now - 25 * 60, took_ms=3480, note="πριν την αλλαγή VLAN")
        b = self._demo_base(True, rnd)
        b.update(label="Μετά", t=now - 3 * 60, took_ms=4120, note="μετά την αλλαγή VLAN")
        with self.lock:
            for s in (a, b):
                self.seq += 1
                s["id"] = self.seq
                self.snaps.append(s)

    def _demo_copy(self, label, targets):
        """Νέο demo στιγμιότυπο: αντίγραφο του τελευταίου με μικρό «θόρυβο» (η ιστορία μένει ίδια)."""
        with self.lock:
            last = json.loads(json.dumps(self.snaps[-1])) if self.snaps else self._demo_base(True, random.Random(3))
        rnd = random.Random()
        for h in last.get("hosts", {}).values():
            if h.get("rtt") is not None:
                h["rtt"] = round(h["rtt"] * rnd.uniform(0.9, 1.1), 1)
        for d in list(last.get("dns", {}).values()) + list(last.get("internet", {}).values()) + list(last.get("ports", {}).values()):
            if d.get("ms") is not None:
                d["ms"] = round(d["ms"] * rnd.uniform(0.9, 1.1), 1)
        if targets:
            keep = set(targets)
            last["hosts"] = {k: v for k, v in last["hosts"].items() if k in keep}
            last["ports"] = {k: v for k, v in last["ports"].items() if k.rsplit(":", 1)[0] in keep}
        last.pop("id", None)
        last.pop("note", None)
        last.update(label=label, t=self.clock(), took_ms=int(rnd.uniform(3200, 4500)))
        return last

    # ───────── αποθήκευση ─────────
    def save(self):
        if not self.path or self.sim:
            return
        with self.lock:
            raw = json.dumps({"v": 1, "seq": self.seq, "snaps": self.snaps}, ensure_ascii=False, separators=(",", ":"))
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(raw)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            snaps = [s for s in d.get("snaps") or [] if isinstance(s, dict) and isinstance(s.get("id"), int)]
            self.snaps = snaps[-MAX_SNAPS:]
            self.seq = max([int(d.get("seq") or 0)] + [s["id"] for s in self.snaps])
        except (OSError, ValueError, TypeError, AttributeError):
            pass


def _sort_key(k):
    """Ταξινόμηση IP/IP:θύρα αριθμητικά (192.168.1.9 πριν από 192.168.1.10)."""
    s = str(k)
    ip, _, port = s.rpartition(":") if s.count(":") == 1 else (s, "", "")
    try:
        return (0, int(ipaddress.ip_address(ip or s)), int(port or 0), s)
    except ValueError:
        return (1, 0, 0, s)
