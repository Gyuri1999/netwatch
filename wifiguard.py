"""NetWatch — Wi‑Fi Guard: έλεγχος ασφάλειας όταν συνδέεσαι σε δημόσιο Wi‑Fi (καφετέριες, ξενοδοχεία…).

Ελέγχει ΤΟ ΔΙΚΤΥΟ (κρυπτογράφηση, evil twin, captive portal, DNS hijacking, TLS interception)
και ΤΟ MAC ΣΟΥ (firewall, stealth, VPN, ιδιωτική MAC, υπηρεσίες που «ακούν»).
Μόνο διαβάζει — δεν αλλάζει καμία ρύθμιση. Για κάθε πρόβλημα δείχνει πώς το διορθώνεις.
"""
import json
import random
import re
import socket
import ssl
import string
import subprocess
import sys
import time
import urllib.request

SEC_LABEL = {
    "none": "Ανοιχτό (χωρίς κωδικό)", "wep": "WEP", "wpa_personal": "WPA", "wpa2_personal": "WPA2",
    "wpa2_personal_mixed": "WPA/WPA2", "wpa3_personal": "WPA3", "wpa3_transition": "WPA2/WPA3",
    "wpa2_enterprise": "WPA2 Enterprise", "wpa3_enterprise": "WPA3 Enterprise", "owe": "Enhanced Open (OWE)",
}
# Υπηρεσίες του Mac που δεν πρέπει να «ακούν» σε δημόσιο δίκτυο: θύρα → (κίνδυνος, όνομα, πώς κλείνει)
MAC_SHARING = {
    22: ("high", "Απομακρυσμένη σύνδεση (SSH)", "Ρυθμίσεις → Γενικά → Κοινή χρήση → Απομακρυσμένη σύνδεση: off"),
    445: ("high", "Κοινή χρήση αρχείων (SMB)", "Ρυθμίσεις → Γενικά → Κοινή χρήση → Κοινή χρήση αρχείων: off"),
    548: ("high", "Κοινή χρήση αρχείων (AFP)", "Ρυθμίσεις → Γενικά → Κοινή χρήση → Κοινή χρήση αρχείων: off"),
    5900: ("high", "Κοινή χρήση οθόνης (VNC)", "Ρυθμίσεις → Γενικά → Κοινή χρήση → Κοινή χρήση οθόνης: off"),
    3283: ("high", "Απομακρυσμένη διαχείριση (ARD)", "Ρυθμίσεις → Γενικά → Κοινή χρήση → Απομακρυσμένη διαχείριση: off"),
    88: ("med", "Kerberos (Back to My Mac / κοινή χρήση)", "Κλείσε τις υπηρεσίες Κοινής χρήσης που δεν χρειάζεσαι"),
    5000: ("med", "Δέκτης AirPlay", "Ρυθμίσεις → Γενικά → AirDrop και Handoff → Δέκτης AirPlay: off"),
    7000: ("med", "Δέκτης AirPlay", "Ρυθμίσεις → Γενικά → AirDrop και Handoff → Δέκτης AirPlay: off"),
    631: ("med", "Κοινή χρήση εκτυπωτή", "Ρυθμίσεις → Γενικά → Κοινή χρήση → Κοινή χρήση εκτυπωτή: off"),
    3306: ("high", "MySQL", "Ρύθμισε τη βάση να ακούει μόνο στο 127.0.0.1"),
    5432: ("high", "PostgreSQL", "Ρύθμισε τη βάση να ακούει μόνο στο 127.0.0.1"),
    6379: ("high", "Redis", "Ρύθμισε το Redis να ακούει μόνο στο 127.0.0.1"),
    27017: ("high", "MongoDB", "Ρύθμισε τη βάση να ακούει μόνο στο 127.0.0.1"),
}
# διευθύνσεις που δεν αλλάζουν ποτέ — αν το DNS επιστρέψει κάτι άλλο, κάποιος το «πειράζει»
DNS_CANARIES = {"one.one.one.one": {"1.1.1.1", "1.0.0.1"}, "dns.google": {"8.8.8.8", "8.8.4.4"},
                "dns.quad9.net": {"9.9.9.9", "149.112.112.112"}}
TLS_SITES = ["www.google.com", "github.com", "www.cloudflare.com"]
UA = "NetWatch-WiFiGuard/1.0"


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


# ---------------- Wi‑Fi ----------------
def _sec(mode):
    s = (mode or "").replace("spairport_security_mode_", "").lower()
    return s or "unknown"


def parse_system_profiler(text):
    """system_profiler SPAirPortDataType -json → {iface, ssid, security, channel, phy, signal, others[]}."""
    try:
        d = json.loads(text)["SPAirPortDataType"][0]
    except (ValueError, KeyError, IndexError, TypeError):
        return None
    for i in d.get("spairport_airport_interfaces", []):
        cur = i.get("spairport_current_network_information") or {}
        if "spairport_security_mode" not in cur:
            continue
        sig = re.match(r"(-?\d+) dBm", cur.get("spairport_signal_noise") or "")
        return {
            "iface": i.get("_name"), "ssid": cur.get("_name"), "security": _sec(cur.get("spairport_security_mode")),
            "channel": cur.get("spairport_network_channel"), "phy": cur.get("spairport_network_phymode"),
            "signal": int(sig.group(1)) if sig else None,
            "others": [{"ssid": o.get("_name"), "security": _sec(o.get("spairport_security_mode")),
                        "channel": o.get("spairport_network_channel"),
                        "signal": (lambda m: int(m.group(1)) if m else None)(
                            re.match(r"(-?\d+) dBm", o.get("spairport_signal_noise") or ""))}
                       for o in i.get("spairport_airport_other_local_wireless_networks") or []],
        }
    return None


def parse_nmcli(text):
    """Linux: nmcli -t -f ACTIVE,SSID,SECURITY,CHAN,SIGNAL dev wifi."""
    cur, others = None, []
    for line in text.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) < 5:
            continue
        active, ssid, sec, chan, sigq = parts[:5]
        s = sec.lower()
        sec = ("none" if not s or s == "--" else "wpa3_personal" if "sae" in s or "wpa3" in s
               else "wpa2_personal" if "wpa2" in s else "wep" if "wep" in s else "wpa_personal")
        n = {"ssid": ssid.replace("\\:", ":"), "security": sec, "channel": chan,
             "signal": int(sigq) // 2 - 100 if sigq.isdigit() else None}
        if active == "yes" and cur is None:
            cur = dict(n, iface="wlan", phy=None, others=others)
        else:
            others.append(n)
    return cur


def wifi_info():
    if sys.platform == "win32":
        import winplat
        return winplat.wifi_info()
    if sys.platform == "darwin":
        return parse_system_profiler(run(["system_profiler", "SPAirPortDataType", "-json"], 20))
    return parse_nmcli(run(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY,CHAN,SIGNAL", "dev", "wifi"]))


def evil_twins(wifi):
    """Δίκτυα με το ΙΔΙΟ όνομα αλλά διαφορετική ασφάλεια — κλασικό σημάδι evil twin."""
    if not wifi or not wifi.get("ssid") or wifi["ssid"].startswith("<"):
        return []
    return [o for o in wifi.get("others", []) if o.get("ssid") == wifi["ssid"] and o["security"] != wifi["security"]]


def private_mac(mac):
    """«Ιδιωτική διεύθυνση Wi‑Fi»: locally administered bit (0x02) στο πρώτο byte."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, AttributeError, IndexError):
        return None


def iface_mac(iface):
    if sys.platform == "win32":
        import winplat
        return next((i["mac"] for i in winplat.net_info().get("interfaces", []) if i["name"] == iface), None)
    m = re.search(r"ether ([0-9a-f:]{17})", run(["ifconfig", iface or "en0"]))
    return m.group(1) if m else None


# ---------------- το Mac σου ----------------
def parse_firewall(text):
    t = text.lower()
    block_all = "state = 2" in t
    enabled = block_all or "state = 1" in t or ("firewall is enabled" in t)
    return {"enabled": enabled, "block_all": block_all,
            "stealth": "stealth mode is on" in t or "stealth mode enabled" in t}


def firewall():
    if sys.platform != "darwin":
        return None
    exe = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    return parse_firewall(run([exe, "--getglobalstate"]) + run([exe, "--getstealthmode"]))


def parse_lsof(text):
    """lsof -nP -iTCP -sTCP:LISTEN → [(process, port)] που ακούν ΕΚΤΟΣ localhost."""
    out = set()
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 9:
            continue
        addr = cols[8]
        host, _, port = addr.rpartition(":")
        if not port.isdigit() or host in ("127.0.0.1", "[::1]", "localhost") or host.startswith("127."):
            continue
        out.add((cols[0].replace("\\x20", " "), int(port)))
    return sorted(out, key=lambda x: (x[1], x[0]))


def listening():
    return parse_lsof(run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]))


TUN_RE = re.compile(r"(utun|tun|tap|wg|ppp|ipsec)\d*$")


def egress_iface(dst="1.1.1.1"):
    """Από ποια διεπαφή βγαίνει πραγματικά η κίνηση προς το Internet. Ένα VPN «όλης της κίνησης»
    (π.χ. Tailscale exit node, WireGuard 0.0.0.0/0) συχνά βάζει 0/1 + 128/1 και αφήνει το «default» στο Wi‑Fi,
    οπότε ρωτάμε για μια δημόσια διεύθυνση, όχι για το default."""
    m = re.search(r"interface:\s*(\S+)", run(["route", "-n", "get", dst]))
    if m:
        return m.group(1)
    m = re.search(r"\sdev (\S+)", run(["ip", "route", "get", dst]))
    return m.group(1) if m else None


def vpn_active(default_iface=None, egress=None, nc=None):
    """True = όλη η κίνηση προς το Internet περνά από VPN· "split:<όνομα>" = συνδεδεμένο VPN που καλύπτει μόνο
    ιδιωτικά δίκτυα (π.χ. Tailscale χωρίς exit node)· False = κανένα VPN."""
    eg = egress if egress is not None else egress_iface()
    if any(x and TUN_RE.match(x) for x in (eg, default_iface)):
        return True
    if nc is None:
        nc = run(["scutil", "--nc", "list"]) if sys.platform == "darwin" else ""
    m = re.search(r'\(Connected\)[^\n]*?"([^"]+)"', nc or "")
    if m:
        return "split:" + m.group(1)
    return False


TOR_SOCKS = ((9150, "Tor Browser"), (9050, "tor"))


def tor_running(ports=TOR_SOCKS):
    """Ποιο Tor ακούει τοπικά (SOCKS στο 127.0.0.1): [(θύρα, όνομα)]. Μόνο σύνδεση σε localhost — τίποτα δεν φεύγει."""
    import socket
    out = []
    for port, name in ports:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                out.append([port, name])
        except OSError:
            pass
    return out


def default_iface():
    if sys.platform == "win32":
        import winplat
        return winplat.net_info().get("gateway_iface")
    m = re.search(r"interface:\s*(\S+)", run(["route", "-n", "get", "default"]))
    if m:
        return m.group(1)
    m = re.search(r"default via \S+ dev (\S+)", run(["ip", "route"]))
    return m.group(1) if m else None


# ---------------- το δίκτυο ----------------
def captive_portal(timeout=5):
    """Η Apple σερβίρει «Success». Αν δούμε κάτι άλλο, κάποιος (portal/proxy) παρεμβαίνει στο HTTP."""
    try:
        req = urllib.request.Request("http://captive.apple.com/hotspot-detect.html", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(4096).decode("utf-8", "ignore")
            final = r.geturl()
        return {"ok": "Success" in body, "redirect": final if "captive.apple.com" not in final else None,
                "snippet": re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body))[:120]}
    except Exception as e:
        return {"ok": None, "error": str(e)[:100]}


def dns_check(resolve=None):
    """Ελέγχει (1) γνωστά ονόματα με σταθερές IP και (2) ανύπαρκτο domain (NXDOMAIN hijacking)."""
    def sysres(name):
        try:
            return {a[4][0] for a in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)}
        except OSError:
            return set()
    resolve = resolve or sysres
    bad = []
    for name, expected in DNS_CANARIES.items():
        got = resolve(name)
        if got and not got & expected:
            bad.append({"name": name, "got": sorted(got), "expected": sorted(expected)})
    fake = "nw-" + "".join(random.choice(string.ascii_lowercase) for _ in range(12)) + ".example"
    nx = sorted(resolve(fake))
    return {"hijacked": bad, "nxdomain_hijack": nx, "ok": not bad and not nx}


# ---------------- DNSSEC: επικυρώνει ο DNS του δικτύου τις υπογραφές; ----------------
# Ζώνες-δοκιμής που συντηρούνται γι' αυτόν ακριβώς τον σκοπό: το «sigok» είναι σωστά υπογεγραμμένο, τα «sigfail»,
# «badsig», «fail01» έχουν σκόπιμα χαλασμένη υπογραφή. Ένας resolver που επικυρώνει τα απορρίπτει (SERVFAIL)·
# ένας που δεν επικυρώνει δίνει κανονικά διεύθυνση.
DNSSEC_SIGNED = ("sigok.verteiltesysteme.net", "cloudflare.com", "isc.org")
DNSSEC_BOGUS = ("sigfail.verteiltesysteme.net", "badsig.go.dnscheck.tools", "fail01.dnssec.works")


def dns_query(server, name, qtype=1, timeout=2.0, txid=None, port=53):
    """Ένα ερώτημα DNS με σκέτο UDP socket (δουλεύει ίδια σε macOS, Linux, Windows — χωρίς dig).
    Ζητά DNSSEC (EDNS0 με DO=1, και AD=1 στην κεφαλίδα). → {rcode, ad, answers} ή None αν δεν απάντησε."""
    import struct
    txid = random.randrange(65536) if txid is None else txid
    q = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.rstrip(".").split(".")) + b"\0"
    pkt = struct.pack(">HHHHHH", txid, 0x0120, 1, 0, 0, 1) + q + struct.pack(">HH", qtype, 1) \
        + b"\0" + struct.pack(">HHIH", 41, 1232, 0x8000, 0)  # OPT: UDP 1232, DO bit
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (server, port))
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                data, _ = s.recvfrom(4096)
                if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == txid:
                    return parse_dns_flags(data)
        except OSError:
            return None
    return None


def parse_dns_flags(data):
    import struct
    _, flags, _, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    return {"rcode": flags & 0xF, "ad": bool(flags & 0x20), "answers": an}


def system_dns_server():
    try:
        import netkit
        servers = netkit._system_dns()[0]  # macOS: scutil, Linux: resolv.conf, Windows: PowerShell (winplat)
    except Exception:
        servers = []
    return next((s for s in servers if "." in s), None) or (servers[0] if servers else None)


def dnssec_check(server=None, query=None):
    """Αποτέλεσμα:
    validating  True: απορρίπτει τις χαλασμένες υπογραφές · False: τις δέχεται · None: άγνωστο (δεν απάντησε)
    bypass      δηλώνει «επικυρωμένο» (AD) αλλά δέχεται και χαλασμένη υπογραφή → κάποιος στη μέση απαντά
    ad_stripped επικυρώνεται κάπου ανάντη, αλλά ο router δεν περνά τη σημαία AD (συνηθισμένο, όχι πρόβλημα)"""
    server = server or system_dns_server()
    out = {"server": server, "validating": None, "bypass": False, "ad_stripped": False}
    if not server:
        return out
    query = query or dns_query
    signed = [query(server, n) for n in DNSSEC_SIGNED]
    good = [r for r in signed if r and r["rcode"] == 0 and r["answers"]]
    if not good:  # ούτε τα σωστά ονόματα δεν επιλύονται: δεν μπορούμε να πούμε τίποτα
        return out
    bogus = [r for r in (query(server, n) for n in DNSSEC_BOGUS) if r]
    if not bogus:
        return out
    ad = any(r["ad"] for r in good)
    accepted = [r for r in bogus if r["rcode"] == 0 and r["answers"]]
    rejected = [r for r in bogus if r["rcode"] == 2]
    if accepted:
        out.update(validating=False, bypass=ad)
    elif rejected:
        out.update(validating=True, ad_stripped=not ad)
    out.update(ad=ad, bogus_accepted=len(accepted), bogus_rejected=len(rejected))
    return out


def tls_check(sites=TLS_SITES, timeout=5):
    """Συνδέεται με κανονικό έλεγχο πιστοποιητικού. Αποτυχία = πιθανό TLS interception (ή captive portal)."""
    res = []
    ctx = ssl.create_default_context()
    for host in sites:
        r = {"host": host}
        try:
            with socket.create_connection((host, 443), timeout=timeout) as s, \
                    ctx.wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
                r["ok"] = True
                r["issuer"] = next((kv[1] for rdn in c.get("issuer", ()) for kv in rdn
                                    if kv[0] == "organizationName"), "")
        except ssl.SSLCertVerificationError as e:
            r["ok"], r["error"] = False, (e.verify_message or str(e))[:120]
        except Exception as e:
            r["ok"], r["error"] = None, str(e)[:120]
        res.append(r)
    return res


# ---------------- αξιολόγηση ----------------
def evaluate(d):
    """Παίρνει τα ακατέργαστα στοιχεία και βγάζει ετυμηγορία + checks με οδηγίες."""
    checks = []

    def chk(cid, status, title, detail, fix="", weight=0):
        checks.append({"id": cid, "status": status, "title": title, "detail": detail, "fix": fix, "weight": weight})

    w = d.get("wifi")
    public = d.get("public", True)
    if w:
        sec = w["security"]
        label = SEC_LABEL.get(sec, sec)
        name = w.get("ssid") or "?"
        if sec in ("none",):
            chk("encryption", "bad", "Κρυπτογράφηση Wi‑Fi", f"Το «{name}» είναι ανοιχτό: ό,τι δεν είναι HTTPS/VPN "
                "το βλέπουν όλοι γύρω σου.", "Χρησιμοποίησε VPN ή το hotspot του κινητού σου.", 30)
        elif sec == "wep":
            chk("encryption", "bad", "Κρυπτογράφηση Wi‑Fi", f"Το «{name}» έχει WEP — σπάει σε λίγα λεπτά.",
                "Θεώρησέ το ανοιχτό δίκτυο: VPN ή hotspot κινητού.", 30)
        elif sec in ("wpa_personal", "wpa2_personal", "wpa2_personal_mixed", "wpa3_transition") and public:
            chk("encryption", "warn", "Κρυπτογράφηση Wi‑Fi", f"{label}: προστατεύει από τους «έξω», αλλά σε "
                "καφετέρια ο κωδικός είναι κοινός — όποιος τον ξέρει μπορεί να «ακούει» τους άλλους πελάτες.",
                "Σε δημόσιο δίκτυο με κοινό κωδικό, άνοιξε VPN.", 8)
        elif sec == "owe":
            chk("encryption", "ok", "Κρυπτογράφηση Wi‑Fi", "Enhanced Open: ανοιχτό αλλά κρυπτογραφημένο ανά συσκευή.")
        else:
            chk("encryption", "ok", "Κρυπτογράφηση Wi‑Fi", f"{label} — καλή κρυπτογράφηση.")
        tw = evil_twins(w)
        if tw:
            chk("evil_twin", "bad", "Evil twin", f"Υπάρχει και δεύτερο δίκτυο «{name}» με διαφορετική ασφάλεια "
                f"({', '.join(SEC_LABEL.get(t['security'], t['security']) for t in tw)}). Κάποιος μπορεί να έστησε "
                "ψεύτικο σημείο πρόσβασης με το ίδιο όνομα.",
                "Ρώτα το προσωπικό ποιο είναι το σωστό δίκτυο, «Ξέχασε» το ύποπτο, άνοιξε VPN.", 30)
        else:
            chk("evil_twin", "ok", "Evil twin", f"Δεν βρέθηκε δεύτερο δίκτυο «{name}» με διαφορετική ασφάλεια "
                f"({len(w.get('others', []))} δίκτυα γύρω σου).")
    else:
        chk("encryption", "info", "Κρυπτογράφηση Wi‑Fi", "Δεν είσαι σε Wi‑Fi ή δεν ήταν δυνατή η ανάγνωση.")

    cp = d.get("captive") or {}
    if cp.get("ok") is False:
        chk("captive", "warn", "Captive portal / proxy", "Το δίκτυο παρεμβαίνει στο HTTP (σελίδα σύνδεσης ή proxy)"
            + (f": {cp['redirect']}" if cp.get("redirect") else "") + ".",
            "Στη σελίδα σύνδεσης δώσε μόνο τα απαραίτητα — ποτέ κωδικούς άλλων λογαριασμών.", 5)
    elif cp.get("ok"):
        chk("captive", "ok", "Captive portal / proxy", "Το HTTP φτάνει ανέγγιχτο.")

    dn = d.get("dns") or {}
    if dn.get("hijacked"):
        chk("dns", "bad", "DNS hijacking", "Ο DNS του δικτύου δίνει λάθος διευθύνσεις για γνωστά ονόματα ("
            + ", ".join(f"{b['name']} → {', '.join(b['got'])}" for b in dn["hijacked"]) + "). Μπορεί να σε στείλει "
            "σε ψεύτικα sites.", "Αποσυνδέσου ή άνοιξε VPN· βάλε κρυπτογραφημένο DNS (DoH).", 30)
    elif dn.get("nxdomain_hijack"):
        chk("dns", "warn", "DNS hijacking", "Ο DNS απαντά ακόμα και για domains που δεν υπάρχουν "
            f"({', '.join(dn['nxdomain_hijack'])}) — το δίκτυο αλλοιώνει απαντήσεις (συνήθως για διαφημίσεις).",
            "Βάλε κρυπτογραφημένο DNS (DoH) στον browser ή VPN.", 8)
    elif "ok" in dn:
        chk("dns", "ok", "DNS hijacking", "Ο DNS δίνει σωστές απαντήσεις.")

    ds = d.get("dnssec") or {}
    if ds.get("bypass"):
        chk("dnssec", "bad", "DNSSEC", f"Ο DNS ({ds.get('server')}) δηλώνει ότι ελέγχει τις υπογραφές DNSSEC, αλλά "
            "δέχτηκε και domain με σκόπιμα χαλασμένη υπογραφή — κάτι στη μέση απαντά αντί για τον πραγματικό "
            "resolver και παρακάμπτει την προστασία.", "Αποσυνδέσου ή άνοιξε VPN· βάλε κρυπτογραφημένο DNS (DoH).", 20)
    elif ds.get("validating") is False:
        chk("dnssec", "warn", "DNSSEC", f"Ο DNS του δικτύου ({ds.get('server')}) δεν ελέγχει τις υπογραφές DNSSEC: "
            "μια πλαστή απάντηση (cache poisoning) δεν θα απορριφθεί.",
            "Βάλε DNS που επικυρώνει DNSSEC (π.χ. 1.1.1.1, 9.9.9.9) στο router, ή κρυπτογραφημένο DNS (DoH).", 3)
    elif ds.get("validating"):
        chk("dnssec", "ok", "DNSSEC", f"Ο DNS ({ds.get('server')}) απορρίπτει απαντήσεις με χαλασμένη υπογραφή DNSSEC"
            + (" (η επικύρωση γίνεται ανάντη· ο router απλώς δεν περνά τη σημαία AD)." if ds.get("ad_stripped") else "."))

    tl = d.get("tls") or []
    failed = [t for t in tl if t.get("ok") is False]
    if failed:
        chk("tls", "bad", "TLS interception (MITM)", "Τα πιστοποιητικά για " + ", ".join(t["host"] for t in failed)
            + " ΔΕΝ επαληθεύονται — κάποιος «στη μέση» αποκρυπτογραφεί την κίνηση (ή portal πριν το login).",
            "Μην κάνεις login πουθενά. Αν δεν είναι captive portal, αποσυνδέσου αμέσως.", 40)
    elif tl and all(t.get("ok") for t in tl):
        chk("tls", "ok", "TLS interception (MITM)", "Τα πιστοποιητικά επαληθεύονται κανονικά ("
            + ", ".join(sorted({t.get('issuer', '').split(', ')[0] for t in tl if t.get('issuer')})) + ").")

    if d.get("arp_spoof"):
        chk("arp", "bad", "ARP spoofing", "Κάποιος στο δίκτυο παριστάνει τον router (δες ⚠ Επιθέσεις).",
            "Αποσυνδέσου ή άνοιξε VPN αμέσως.", 40)

    fw = d.get("firewall")
    if fw is not None:
        if not fw["enabled"]:
            chk("firewall", "bad", "Firewall του Mac", "Το firewall είναι κλειστό.",
                "Ρυθμίσεις → Δίκτυο → Firewall: Ενεργό.", 15)
        elif not fw["stealth"] and public:
            chk("firewall", "warn", "Firewall του Mac", "Ενεργό, αλλά χωρίς stealth mode: το Mac απαντά σε ping και "
                "σαρώσεις — φαίνεται στους άλλους.", "Ρυθμίσεις → Δίκτυο → Firewall → Επιλογές → «Λειτουργία "
                "απόκρυψης» (stealth).", 5)
        else:
            chk("firewall", "ok", "Firewall του Mac", "Ενεργό" + (" με stealth mode." if fw["stealth"] else "."))

    lis = d.get("listening")
    if lis is not None:
        risky = [(p, port, MAC_SHARING[port]) for p, port in lis if port in MAC_SHARING]
        if risky:
            worst = "bad" if any(r[2][0] == "high" for r in risky) else "warn"
            chk("sharing", worst, "Υπηρεσίες ανοιχτές στο δίκτυο", "Το Mac δέχεται συνδέσεις από όλο το Wi‑Fi: "
                + ", ".join(f"{r[2][1]} ({r[1]})" for r in risky) + ".",
                " · ".join(sorted({r[2][2] for r in risky})), 15 if worst == "bad" else 6)
        else:
            chk("sharing", "ok", "Υπηρεσίες ανοιχτές στο δίκτυο", f"Καμία επικίνδυνη ({len(lis)} ακούν συνολικά).")

    v = d.get("vpn")
    if isinstance(v, str) and v.startswith("split:"):
        chk("vpn", "warn", "VPN", f"Το «{v[6:]}» είναι συνδεδεμένο, αλλά μόνο για το ιδιωτικό σου δίκτυο — η κίνηση "
            "προς το Internet βγαίνει από το Wi‑Fi χωρίς VPN.",
            "Για να περνά όλη η κίνηση από VPN: στο Tailscale διάλεξε Exit Node (μια συσκευή σου στο σπίτι), "
            "ή άνοιξε ένα VPN όλης της κίνησης (Mullvad, ProtonVPN, WireGuard με 0.0.0.0/0).", 10 if public else 0)
    elif v:
        chk("vpn", "ok", "VPN", "Ενεργό — η κίνηση πάει κρυπτογραφημένη μέχρι τον server του VPN.")
    elif public:
        chk("vpn", "warn", "VPN", "Δεν είναι ενεργό VPN.", "Σε δημόσιο Wi‑Fi άνοιξε VPN (π.χ. Tailscale exit node, "
            "Mullvad, ProtonVPN) ή χρησιμοποίησε το hotspot του κινητού.", 10)
    else:
        chk("vpn", "info", "VPN", "Δεν είναι ενεργό VPN — στο δικό σου δίκτυο συνήθως δεν χρειάζεται.")
    tor = d.get("tor")
    if tor:
        names = " + ".join(f"{n} ({p})" for p, n in tor)
        chk("tor", "ok", "Tor", f"Τρέχει: {names}. Ανώνυμο είναι μόνο ό,τι ανοίγεις μέσα στο Tor Browser — οι άλλες "
            "εφαρμογές και browsers βγαίνουν κανονικά (ή από το VPN).",
            "Για να δεις το κύκλωμα των 3 κόμβων άνοιξε την καρτέλα 🧅 Tor.")

    pm = d.get("private_mac")
    if pm is False:
        chk("private_mac", "warn", "Ιδιωτική διεύθυνση Wi‑Fi", "Χρησιμοποιείς την πραγματική MAC — τα δίκτυα "
            "μπορούν να σε αναγνωρίζουν και να σε παρακολουθούν από μέρος σε μέρος.",
            "Ρυθμίσεις → Wi‑Fi → (i) δίπλα στο δίκτυο → Ιδιωτική διεύθυνση Wi‑Fi: Εναλλασσόμενη.", 3)
    elif pm:
        chk("private_mac", "ok", "Ιδιωτική διεύθυνση Wi‑Fi", "Ενεργή — δεν σε αναγνωρίζουν από τη συσκευή σου.")

    score = max(0, 100 - sum(c["weight"] for c in checks if c["status"] in ("bad", "warn")))
    bad = [c for c in checks if c["status"] == "bad"]
    if any(c["id"] in ("tls", "dns", "evil_twin", "arp") for c in bad):
        verdict, level = "Επικίνδυνο — μην το χρησιμοποιείς χωρίς VPN", "bad"
    elif bad or score < 70:
        verdict, level = "Προσοχή — διόρθωσε τα κόκκινα πριν κάνεις κάτι σημαντικό", "warn"
    else:
        verdict, level = "Εντάξει για καθημερινή χρήση", "ok"
    return {"score": score, "verdict": verdict, "level": level, "checks": checks}


def full_check(public=True, arp_spoof=False):
    di = default_iface()
    w = wifi_info()
    d = {"public": public, "wifi": w, "captive": captive_portal(), "dns": dns_check(), "dnssec": dnssec_check(),
         "tls": tls_check(),
         "firewall": firewall(), "listening": listening(), "vpn": vpn_active(di), "tor": tor_running(),
         "private_mac": private_mac(iface_mac((w or {}).get("iface") or di)) if w else None,
         "arp_spoof": arp_spoof, "t": time.time(), "default_iface": di}
    d.update(evaluate(d))
    return d


def demo_check(public=True, arp_spoof=False):
    """Ρεαλιστικό σενάριο καφετέριας για το demo."""
    wifi = {"iface": "en0", "ssid": "Cafe_Free_WiFi", "security": "none", "channel": "6 (2GHz, 20MHz)",
            "phy": "802.11n", "signal": -61,
            "others": [{"ssid": "Cafe_Free_WiFi", "security": "wpa2_personal", "channel": "11 (2GHz, 20MHz)", "signal": -48},
                       {"ssid": "Vodafone-A4F2", "security": "wpa2_personal", "channel": "36 (5GHz, 80MHz)", "signal": -77},
                       {"ssid": "COSMOTE-81B0", "security": "wpa3_transition", "channel": "1 (2GHz, 20MHz)", "signal": -80}]}
    d = {"public": public, "wifi": wifi, "demo": True,
         "captive": {"ok": False, "redirect": "http://login.cafe-wifi.example/portal", "snippet": "Welcome! Accept terms"},
         "dns": {"hijacked": [], "nxdomain_hijack": ["10.10.0.1"], "ok": False},
         "dnssec": {"server": "10.10.0.1", "validating": False, "bypass": False},
         "tls": [{"host": h, "ok": True, "issuer": "Google Trust Services" if "google" in h else "Sectigo"}
                 for h in TLS_SITES],
         "firewall": {"enabled": True, "block_all": False, "stealth": False},
         "listening": [("ControlCenter", 5000), ("ControlCenter", 7000), ("sshd", 22)],
         "vpn": False, "private_mac": True, "arp_spoof": arp_spoof, "t": time.time()}
    d.update(evaluate(d))
    return d


# ---------------- φύλακας: τρέχει τους ελέγχους και «βλέπει» αλλαγές δικτύου ----------------
ALERT_FOR = {  # check id → (τύπος ειδοποίησης, σοβαρότητα)
    "evil_twin": ("Evil twin Wi‑Fi", "high"),
    "dns": ("DNS hijacking στο Wi‑Fi", "high"),
    "dnssec": ("DNSSEC bypass στο Wi‑Fi", "high"),
    "tls": ("TLS interception στο Wi‑Fi", "high"),
    "encryption": ("Ανοιχτό Wi‑Fi", "med"),
}


def network_fingerprint():
    """(interface, gateway, MAC του gateway): αλλάζει όταν πας σε άλλο δίκτυο."""
    if sys.platform == "win32":
        import winplat
        v = winplat.net_info(max_age=5)
        gw = v.get("gateway")
        mac = dict(winplat.arp_table()).get(gw) if gw else None
        return (v.get("gateway_iface"), gw, mac)
    out = run(["route", "-n", "get", "default"], 5)
    gw = re.search(r"gateway:\s*(\S+)", out)
    ifc = re.search(r"interface:\s*(\S+)", out)
    gw = gw.group(1) if gw else None
    mac = None
    if gw:
        m = re.search(r" at ([0-9a-f:]+) ", run(["arp", "-n", gw], 5))
        mac = m.group(1) if m else None
    return (ifc.group(1) if ifc else None, gw, mac)


class Guard:
    def __init__(self, state, sim=None, trusted_path=None):
        self.state, self.sim, self.trusted_path = state, sim, trusted_path
        self.result, self.running, self.error = None, False, None
        self.watching = False
        self.trusted = set()
        if trusted_path:
            try:
                with open(trusted_path, encoding="utf-8") as f:
                    self.trusted = set(json.load(f))
            except (OSError, ValueError):
                pass
        self._lock = __import__("threading").Lock()

    def status(self):
        r = self.result
        return {"running": self.running, "result": r, "error": self.error, "watching": self.watching,
                "trusted": sorted(self.trusted), "demo": bool(self.sim)}

    def set_trusted(self, ssid, trusted):
        if not ssid:
            raise ValueError("Δεν υπάρχει δίκτυο")
        (self.trusted.add if trusted else self.trusted.discard)(ssid)
        if self.trusted_path:
            import os
            os.makedirs(os.path.dirname(self.trusted_path), exist_ok=True)
            with open(self.trusted_path, "w", encoding="utf-8") as f:
                json.dump(sorted(self.trusted), f, ensure_ascii=False)
            if getattr(self, "on_save", None):
                self.on_save(self.trusted_path)
        if self.result:  # ξανα-αξιολόγηση χωρίς νέες συνδέσεις
            d = dict(self.result, public=ssid not in self.trusted)
            d.update(evaluate(d))
            self.result = d
            self.state.publish({"type": "wifi", "result": d})

    def recheck_vpn(self):
        """Γρήγορος έλεγχος μόνο του VPN (≈1 s): άνοιξες/έκλεισες VPN → ξανα-αξιολόγηση χωρίς τους υπόλοιπους ελέγχους."""
        if self.sim:
            v = (self.result or {}).get("vpn", False)
        else:
            v = vpn_active(default_iface())
        tor = (self.result or {}).get("tor") if self.sim else tor_running()
        if self.result:
            d = dict(self.result, vpn=v, tor=tor, vpn_t=time.time())
            d.update(evaluate(d))
            self.result = d
            self.state.publish({"type": "wifi", "result": d})
        return v

    def start(self, reason="manual"):
        with self._lock:
            if self.running:
                return False
            self.running = True
        __import__("threading").Thread(target=self._run, args=(reason,), daemon=True).start()
        return True

    def _arp_spoof(self):
        now = time.time()
        with self.state.lock:
            return any(a["type"].startswith("ARP spoofing") and not a.get("lab") and
                       (self.state.mode != "live" or now - a["t"] < 600) for a in self.state.alerts)

    def _run(self, reason):
        self.error = None
        try:
            ssid = None
            if not self.sim:
                w = wifi_info()
                ssid = (w or {}).get("ssid")
            public = ssid not in self.trusted if ssid else True
            d = (self.sim or full_check)(public=public, arp_spoof=self._arp_spoof())
            if d.get("wifi") and d["wifi"].get("ssid") in self.trusted:
                d["public"] = False
                d.update(evaluate(d))
            d["reason"] = reason
            self.result = d
            self._alerts(d)
            self.state.publish({"type": "wifi", "result": d})
        except Exception as e:
            self.error = str(e)[:200]
        finally:
            self.running = False

    def _alerts(self, d):
        st = self.state
        ssid = (d.get("wifi") or {}).get("ssid") or "?"
        actor = st.gateway or "wifi"
        t = st.last_t if st.mode == "pcap" and getattr(st, "last_t", None) else time.time()
        for c in d["checks"]:
            if c["status"] != "bad" or c["id"] not in ALERT_FOR:
                continue
            typ, sev = ALERT_FOR[c["id"]]
            st.alert(typ, sev, actor, ssid, c["detail"] + (" → " + c["fix"] if c["fix"] else ""), t,
                     key=f"{ssid}:{c['id']}", cooldown=3600, mark=False)

    def watch(self, interval=15):
        """Live: σε κάθε αλλαγή δικτύου (νέο router/MAC) τρέχει αυτόματα έλεγχο."""
        self.watching = True
        last = None
        while True:
            try:
                fp = network_fingerprint()
                if fp[1] and fp != last:
                    if last is not None:
                        print(f"[netwatch] ☕ νέο δίκτυο ({fp[1]}) — έλεγχος Wi‑Fi Guard", flush=True)
                    self.start("network-change" if last else "startup")
                    last = fp
            except Exception:
                pass
            time.sleep(interval)
