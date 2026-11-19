"""NetWatch — Ανωνυμία & διαρροές: τι βλέπει ένα site για σένα, και αν «διαρρέει» κάτι από το VPN/Tor.

Ελέγχει: δημόσια IP (IPv4/IPv6) και τι δείχνει για σένα, αν η κίνηση βγαίνει από Tor, DNS leak
(ποιοι DNS servers βλέπουν τα ονόματα που ψάχνεις), IPv6 leak, αν τρέχει Tor στο Mac.
Οι έλεγχοι WebRTC και ζώνης ώρας/γλώσσας γίνονται στον browser (index.html).
Επικοινωνεί ΜΟΝΟ όταν πατήσεις «Έλεγχος»: api.ipify.org, api64.ipify.org, check.torproject.org,
ip-api.com, bash.ws (DNS leak test).
"""
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from urllib.parse import urlparse

UA = "NetWatch-Privacy/1.0"
TOR_PORTS = (9050, 9150)  # tor daemon, Tor Browser
IPAPI_FIELDS = "status,message,country,countryCode,city,isp,org,as,timezone,proxy,hosting,mobile,query"


# ---------------- HTTP (απευθείας ή μέσω Tor SOCKS5) ----------------
def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("SOCKS: η σύνδεση έκλεισε")
        buf += chunk
    return buf


SOCKS_ERRORS = {1: "γενική αποτυχία", 2: "δεν επιτρέπεται", 3: "μη προσβάσιμο δίκτυο", 4: "μη προσβάσιμος host",
                5: "άρνηση σύνδεσης", 6: "λήξη TTL", 7: "μη υποστηριζόμενη εντολή", 8: "μη υποστηριζόμενη διεύθυνση"}


class SocksError(OSError):
    def __init__(self, code):
        super().__init__(f"SOCKS: αποτυχία σύνδεσης ({code} — {SOCKS_ERRORS.get(code, '?')})")
        self.code = code


def socks_connect(host, dport, port, timeout=20):
    """SOCKS5 CONNECT με απομακρυσμένο DNS (όπως socks5h): το όνομα επιλύεται ΜΕΣΑ στο Tor.
    Επιστρέφει συνδεδεμένο socket προς host:dport (χωρίς TLS)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if _recv_exact(s, 2) != b"\x05\x00":
            raise OSError("SOCKS: άρνηση")
        hb = host.encode("idna") if not host.isascii() else host.encode()
        if len(hb) > 255:
            raise OSError("SOCKS: πολύ μεγάλο όνομα")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + dport.to_bytes(2, "big"))
        rep = _recv_exact(s, 4)
        if rep[1] != 0:
            raise SocksError(rep[1])
        skip = {1: 4, 4: 16}.get(rep[3])
        _recv_exact(s, (skip if skip else _recv_exact(s, 1)[0]) + 2)
        return s
    except BaseException:
        s.close()
        raise


def socks_get(url, port, timeout=20):
    """GET μέσω SOCKS5 με απομακρυσμένο DNS (όπως socks5h): ούτε το όνομα δεν φεύγει εκτός Tor."""
    u = urlparse(url)
    host, tls = u.hostname, u.scheme == "https"
    dport = u.port or (443 if tls else 80)
    s = socks_connect(host, dport, port, timeout)
    try:
        if tls:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        s.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {UA}\r\nAccept: */*\r\n\r\n".encode())
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        if b" 200 " not in head.split(b"\r\n", 1)[0]:
            raise OSError("HTTP " + head.split(b"\r\n", 1)[0].decode("latin-1"))
        return body
    finally:
        s.close()


def get(url, socks=None, timeout=10):
    if socks:
        return socks_get(url, socks, timeout=max(timeout, 20))
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def get_json(url, socks=None, timeout=10):
    return json.loads(get(url, socks, timeout))


# ---------------- επιμέρους έλεγχοι ----------------
def tor_port():
    """Τρέχει Tor στο Mac; (9050 = tor daemon, 9150 = Tor Browser)."""
    for p in TOR_PORTS:
        try:
            with socket.create_connection(("127.0.0.1", p), timeout=0.5):
                return p
        except OSError:
            pass
    return None


def tor_browser_installed():
    return any(os.path.exists(p) for p in ("/Applications/Tor Browser.app",
                                           os.path.expanduser("~/Applications/Tor Browser.app")))


def public_ip(v6=False):
    try:
        ip = get_json("https://api64.ipify.org?format=json" if v6 else "https://api.ipify.org?format=json", timeout=6)["ip"]
        return ip if (":" in ip) == v6 else None
    except Exception:
        return None


def ip_info(ip):
    try:
        d = get_json(f"http://ip-api.com/json/{ip}?fields={IPAPI_FIELDS}", timeout=6)
        return d if d.get("status") == "success" else None
    except Exception:
        return None


def asn(info_or_str):
    s = info_or_str.get("as", "") if isinstance(info_or_str, dict) else (info_or_str or "")
    return s.split(" ", 1)[0] if s.startswith("AS") else ""


def dns_leak_test(n=6, resolve=None):
    """bash.ws: ψάχνουμε μοναδικά ονόματα και ο server μας λέει ΠΟΙΟΙ DNS resolvers τα ρώτησαν."""
    tid = get("https://bash.ws/id", timeout=8).decode().strip()
    if not tid.isalnum():
        raise ValueError("bash.ws: μη αναμενόμενη απάντηση")
    resolve = resolve or (lambda name: socket.gethostbyname(name))
    for i in range(1, n + 1):
        try:
            resolve(f"{i}.{tid}.bash.ws")
        except OSError:
            pass
    time.sleep(1)
    rows = get_json(f"https://bash.ws/dnsleak/test/{tid}?json", timeout=10)
    return [{"ip": r["ip"], "country": r.get("country_name", ""), "cc": (r.get("country") or "").upper(),
             "asn": r.get("asn", ""), "org": r.get("org", "")} for r in rows if r.get("type") == "dns"]


def akamai_resolver(resolve=None):
    """DNS leak test ΧΩΡΙΣ τρίτο site: το whoami.akamai.net απαντά με την IP του resolver που το ρώτησε.
    Δείχνει ποιος DNS server βγαίνει τελικά στο Internet για σένα (μόνο ο πρώτος — το bash.ws βλέπει όλους)."""
    resolve = resolve or (lambda name: socket.gethostbyname(name))
    ip = resolve("whoami.akamai.net")
    return ip if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip or "") else None


def _run(cmd, timeout=4):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def parse_inet6(ifconfig_text):
    """Από το `ifconfig en0`: πόσες global IPv6 έχει η κάρτα και τι είδους (temporary / secured / σταθερή EUI-64)."""
    out = {"global": 0, "temporary": 0, "secured": 0, "eui64": 0}
    for line in ifconfig_text.splitlines():
        m = re.search(r"\binet6 ([0-9a-f:]+)", line.strip(), re.I)
        if not m or m.group(1).lower().startswith(("fe80", "::1", "fd", "fc")):
            continue
        out["global"] += 1
        if "temporary" in line:
            out["temporary"] += 1
        elif "secured" in line:
            out["secured"] += 1
        elif "ff:fe" in m.group(1).lower():
            out["eui64"] += 1
    return out


def ipv6_privacy(iface="en0"):
    """Προσωρινές IPv6 (RFC 8981): χωρίς αυτές, το τέλος της IPv6 μένει ίδιο σε κάθε δίκτυο και σε «ακολουθεί»."""
    if sys.platform == "darwin":
        temp = _run(["sysctl", "-n", "net.inet6.ip6.use_tempaddr"]).strip()
        d = parse_inet6(_run(["ifconfig", iface]))
        d["tempaddr"] = temp == "1" if temp else None
    else:
        try:
            temp = open("/proc/sys/net/ipv6/conf/all/use_tempaddr").read().strip()
        except OSError:
            temp = ""
        d = parse_inet6(_run(["ip", "-6", "addr", "show", "dev", iface]))
        d["tempaddr"] = temp in ("1", "2") if temp else None
    d["iface"] = iface
    return d


# ---------------- αξιολόγηση ----------------
def evaluate(d):
    """Ποιο επίπεδο ανωνυμίας έχεις και τι διαρρέει."""
    checks = []

    def chk(cid, status, title, detail, fix=""):
        checks.append({"id": cid, "status": status, "title": title, "detail": detail, "fix": fix})

    v4 = d.get("info") or {}
    exit_asn = asn(v4)
    via_tor = bool((d.get("tor_direct") or {}).get("IsTor"))
    vpn = bool(d.get("vpn"))
    anon_ip = vpn or via_tor or v4.get("proxy") or v4.get("hosting")

    if v4:
        where = ", ".join(x for x in (v4.get("city"), v4.get("country")) if x)
        chk("ip", "info" if not anon_ip else "ok", "Τι βλέπει κάθε site",
            f"IP {v4.get('query')} · {where} · {v4.get('isp') or v4.get('org')} ({exit_asn})."
            + (" Μοιάζει με VPN/proxy/datacenter." if v4.get("proxy") or v4.get("hosting") else
               " Είναι η πραγματική σύνδεσή σου — τα sites ξέρουν περίπου πού είσαι και ποιος πάροχος σε εξυπηρετεί."))
    if vpn and v4 and not (v4.get("proxy") or v4.get("hosting")) and not via_tor:
        chk("vpn_route", "bad", "Το VPN δεν «κρύβει» την IP",
            f"Το VPN φαίνεται ενεργό, αλλά τα sites βλέπουν IP οικιακής σύνδεσης ({v4.get('isp')}). "
            "Ίσως η κίνηση δεν περνά από το VPN (split tunnel / λάθος ρύθμιση).",
            "Έλεγξε στο VPN ότι στέλνει ΟΛΗ την κίνηση (full tunnel / exit node) και ότι έχει kill switch.")

    tor = d.get("tor") or {}
    if via_tor:
        chk("tor", "ok", "Tor", "Η κίνηση αυτής της σύνδεσης βγαίνει από Tor.")
    elif tor.get("port"):
        ex = tor.get("exit") or {}
        chk("tor", "ok" if tor.get("is_tor") else "warn", "Tor",
            f"Το Tor τρέχει (θύρα {tor['port']}). Μέσω Tor τα sites βλέπουν "
            + (f"IP {ex.get('query')} ({ex.get('country', '?')}) αντί για τη δική σου." if ex else "άλλη IP.")
            + " Προσοχή: περνούν από Tor ΜΟΝΟ οι εφαρμογές που το χρησιμοποιούν (π.χ. Tor Browser), όχι όλο το Mac."
            + (f" Σφάλμα: {tor['error']}" if tor.get("error") else ""))
    else:
        chk("tor", "info", "Tor", "Δεν τρέχει Tor." + (" Το Tor Browser είναι εγκατεστημένο — άνοιξέ το και ξαναπάτα έλεγχο."
                                                       if d.get("tor_browser") else ""),
            "Για ανωνυμία στο web: Tor Browser (torproject.org). Για όλο το Mac: brew install tor (SOCKS στη θύρα 9050).")

    resolvers = d.get("dns")
    if isinstance(resolvers, list) and resolvers:
        orgs = sorted({r["org"] or r["asn"] for r in resolvers})
        foreign = [r for r in resolvers if exit_asn and asn(r["asn"]) != exit_asn]
        seen = list(dict.fromkeys(f"{r['org'] or r['asn']} ({r['country']})" for r in resolvers))
        txt = "Τα ονόματα που ψάχνεις τα βλέπουν: " + ", ".join(seen[:4]) + (" …" if len(seen) > 4 else "")
        if (vpn or via_tor) and foreign:
            chk("dns", "bad", "DNS leak", txt + ". Είσαι σε VPN/Tor, αλλά τα DNS ερωτήματα πάνε σε άλλον "
                f"πάροχο ({', '.join(orgs)}) — όποιος τον ελέγχει βλέπει ΠΟΙΑ sites επισκέπτεσαι.",
                "Ενεργοποίησε στο VPN «DNS leak protection» / χρήση του DNS του VPN· στον browser βάλε DoH.")
        else:
            chk("dns", "info" if not (vpn or via_tor) else "ok", "DNS", txt + ".")
    elif d.get("dns_error"):
        chk("dns", "info", "DNS", "Το τεστ DNS (bash.ws) δεν ολοκληρώθηκε: " + d["dns_error"])

    ak = d.get("dns_akamai") or {}
    if ak.get("ip"):
        org = ak.get("org") or ak.get("isp") or "?"
        foreign = (vpn or via_tor) and exit_asn and asn(ak) and asn(ak) != exit_asn
        chk("dns_akamai", "bad" if foreign else "ok" if (vpn or via_tor) else "info", "DNS χωρίς τρίτους (whoami.akamai.net)",
            f"Ο resolver που βγαίνει στο Internet για σένα: {ak['ip']} ({org}, {ak.get('country', '?')})."
            + (" Δεν ανήκει στο VPN — DNS leak." if foreign else ""),
            "Βάλε το VPN να χρησιμοποιεί το δικό του DNS, ή DoH στον browser.")

    p6 = d.get("v6priv") or {}
    if p6.get("global"):
        if p6.get("temporary"):
            chk("v6priv", "ok", "IPv6 privacy", f"Η {p6.get('iface', 'κάρτα')} χρησιμοποιεί προσωρινές IPv6 "
                f"({p6['temporary']}) για τις εξερχόμενες συνδέσεις — αλλάζουν συχνά, δεν σε «ακολουθούν».")
        else:
            chk("v6priv", "warn", "IPv6 privacy", "Δεν βρέθηκε προσωρινή IPv6: το ίδιο αναγνωριστικό συσκευής φαίνεται "
                "σε κάθε site" + (" και περιέχει τη MAC σου (EUI-64)." if p6.get("eui64") else "."),
                "macOS: sudo sysctl -w net.inet6.ip6.use_tempaddr=1 · Linux: net.ipv6.conf.all.use_tempaddr=2")

    v6 = d.get("ipv6")
    v6i = d.get("info6") or {}
    if v6:
        if (vpn or via_tor) and v6i and asn(v6i) != exit_asn:
            chk("ipv6", "bad", "IPv6 leak", f"Η IPv6 σου ({v6}, {v6i.get('isp')}) βγαίνει ΕΚΤΟΣ VPN — τα sites "
                "με IPv6 βλέπουν την πραγματική σου σύνδεση.",
                "Ενεργοποίησε στο VPN το IPv6 (ή «block IPv6»), ή κλείσε το IPv6: Ρυθμίσεις → Δίκτυο → Wi‑Fi → "
                "Λεπτομέρειες → TCP/IP → Ρύθμιση IPv6: Μόνο link-local.")
        else:
            chk("ipv6", "info", "IPv6", f"Έχεις και IPv6 ({v6}" + (f", {v6i.get('isp')}" if v6i else "") + ").")
    else:
        chk("ipv6", "ok", "IPv6", "Χωρίς δημόσια IPv6 — δεν μπορεί να διαρρεύσει από εκεί.")

    bad = [c for c in checks if c["status"] == "bad"]
    if via_tor and not bad:
        level, label = 3, "Υψηλή (Tor)"
    elif anon_ip and not bad:
        level, label = 2, "Μέτρια (VPN/proxy) — ο πάροχος του VPN σε βλέπει"
    elif anon_ip:
        level, label = 1, "Χαμηλή — το VPN/Tor «στάζει»"
    else:
        level, label = 0, "Καμία — τα sites βλέπουν την πραγματική σου σύνδεση"
    return {"level": level, "label": label, "checks": checks}


def full_check(vpn=None):
    d = {"t": time.time(), "vpn": vpn}
    d["ipv4"] = public_ip()
    d["ipv6"] = public_ip(v6=True)
    d["info"] = ip_info(d["ipv4"]) if d["ipv4"] else None
    d["info6"] = ip_info(d["ipv6"]) if d["ipv6"] else None
    try:
        d["tor_direct"] = get_json("https://check.torproject.org/api/ip", timeout=8)
    except Exception:
        d["tor_direct"] = None
    port = tor_port()
    d["tor_browser"] = tor_browser_installed()
    tor = {"port": port}
    if port:
        try:
            r = get_json("https://check.torproject.org/api/ip", socks=port)
            tor["is_tor"], tor["ip"] = r.get("IsTor"), r.get("IP")
            tor["exit"] = ip_info(r.get("IP")) if r.get("IP") else None
        except Exception as e:
            tor["error"] = str(e)[:120]
    d["tor"] = tor
    try:
        d["dns"] = dns_leak_test()
    except Exception as e:
        d["dns"], d["dns_error"] = None, str(e)[:120]
    try:
        aip = akamai_resolver()
        if aip:
            i = ip_info(aip) or {}
            d["dns_akamai"] = {"ip": aip, "org": i.get("org") or i.get("isp"), "isp": i.get("isp"),
                               "country": i.get("country"), "as": i.get("as", "")}
    except Exception:
        d["dns_akamai"] = None
    try:
        import wifiguard
        d["v6priv"] = ipv6_privacy(wifiguard.default_iface() or "en0")
    except Exception:
        d["v6priv"] = None
    d.update(evaluate(d))
    return d


def demo_check(vpn=True):
    """Σενάριο: VPN ενεργό αλλά με DNS leak και IPv6 leak, και Tor Browser ανοιχτό."""
    d = {"t": time.time(), "vpn": True, "demo": True, "ipv4": "185.65.134.77", "ipv6": "2a02:587:d4a1::17",
         "info": {"query": "185.65.134.77", "country": "Sweden", "countryCode": "SE", "city": "Stockholm",
                  "isp": "M247 Europe", "org": "Mullvad VPN", "as": "AS39351 31173 Services AB",
                  "timezone": "Europe/Stockholm", "proxy": True, "hosting": True, "mobile": False},
         "info6": {"query": "2a02:587:d4a1::17", "country": "Greece", "countryCode": "GR", "city": "Athens",
                   "isp": "Ote SA", "as": "AS6799 Ote SA", "timezone": "Europe/Athens"},
         "tor_direct": {"IsTor": False, "IP": "185.65.134.77"}, "tor_browser": True,
         "tor": {"port": 9150, "is_tor": True, "ip": "185.220.101.4",
                 "exit": {"query": "185.220.101.4", "country": "Germany", "city": "Berlin", "isp": "Tor exit"}},
         "dns_akamai": {"ip": "195.170.0.1", "org": "Ote SA", "isp": "Ote SA", "country": "Greece", "as": "AS6799 Ote SA"},
         "v6priv": {"iface": "en0", "global": 2, "temporary": 1, "secured": 1, "eui64": 0, "tempaddr": True},
         "dns": [{"ip": "195.170.0.1", "country": "Greece", "cc": "GR", "asn": "AS6799 Ote SA", "org": "Ote SA"},
                 {"ip": "172.68.61.52", "country": "Greece", "cc": "GR", "asn": "AS13335 CloudFlare Inc",
                  "org": "CloudFlare Inc"}]}
    d.update(evaluate(d))
    return d


def vpn_full_tunnel(default_iface):
    """VPN που περνά ΟΛΗ την κίνηση: η προεπιλεγμένη διαδρομή πάει σε utun/tun/wg/ppp/ipsec."""
    import re
    return bool(default_iface and re.match(r"(utun|tun|tap|wg|ppp|ipsec)\d*$", default_iface))


class Runner:
    """Τρέχει τον έλεγχο στο παρασκήνιο (διαρκεί ~10 δευτ.)."""

    def __init__(self, sim=None, vpn=None):
        self.sim, self.vpn = sim, vpn or (lambda: None)
        self.result, self.running, self.error = None, False, None
        self._lock = threading.Lock()

    def status(self):
        return {"running": self.running, "result": self.result, "error": self.error, "demo": bool(self.sim),
                "tor_port": None if self.sim else tor_port()}

    def start(self, on_done=None):
        with self._lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._run, args=(on_done,), daemon=True).start()
        return True

    def _run(self, on_done):
        self.error = None
        try:
            if self.sim:
                time.sleep(1.5 + random.random())
            self.result = (self.sim or full_check)(vpn=self.vpn())
            if on_done:
                on_done(self.result)
        except Exception as e:
            self.error = str(e)[:200]
        finally:
            self.running = False
