"""🔐 802.1X & απομόνωση guest — οι έλεγχοι που κάνει ο τεχνικός ΑΠΟ ΤΗ ΜΕΡΙΑ ΤΟΥ ΠΕΛΑΤΗ, αφού ρυθμίσει NAC ή δίκτυο επισκεπτών.

  1. 802.1X στη θύρα (ενσύρματα): στέλνει ΕΝΑ EAPOL-Start (ethertype 0x888E → 01:80:C2:00:00:03, IEEE 802.1X §11) και
     ακούει ~5 δευτ. για EAP-Request/Identity (RFC 3748 §4.1). Απάντησε authenticator → η θύρα ζητά 802.1X.
     Δεν απάντησε → ανοιχτή θύρα ή μόνο MAB. Προαιρετικά στέλνει Response/Identity με ανώνυμο όνομα για να δει
     ποια μέθοδο EAP προσφέρει ο server (PEAP, EAP-TLS…) — ποτέ κωδικούς.
  2. Ασφάλεια του τρέχοντος Wi‑Fi (ό,τι δίνει το λειτουργικό, μέσω wifiguard.wifi_info): Enterprise / PSK / ανοιχτό, WPA3/PMF.
  3. Τεστ απομόνωσης (τρέξ' το ΣΥΝΔΕΔΕΜΕΝΟΣ στο guest): φτάνω άλλους πελάτες του ίδιου δικτύου; τις θύρες διαχείρισης
     του router; άλλα ιδιωτικά δίκτυα (συνηθισμένα gateways + «εσωτερικοί στόχοι» που δίνεις); δουλεύουν DNS/Internet;
     υπάρχει captive portal;
Ενεργές δοκιμές ΜΟΝΟ προς ιδιωτικές IPv4 (RFC1918), με μικρά timeouts, λίγες παράλληλες συνδέσεις και όριο στο πλήθος.
Για πλήρη πίνακα VLAN → VLAN υπάρχει το 🧱 segcheck.py· εδώ είναι το γρήγορο τεστ «από έναν πελάτη».
"""
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

PAE = "01:80:c2:00:00:03"           # PAE group address (IEEE 802.1X): δεν προωθείται από γέφυρες
ETH_EAPOL = 0x888E
EAPOL_TYPES = {0: "EAP-Packet", 1: "EAPOL-Start", 2: "EAPOL-Logoff", 3: "EAPOL-Key", 4: "EAPOL-ASF-Alert", 5: "EAPOL-MKA"}
EAP_CODES = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}       # RFC 3748 §4
EAP_TYPES = {1: "Identity", 2: "Notification", 3: "Nak", 4: "MD5-Challenge", 5: "OTP", 6: "GTC", 13: "EAP-TLS", 17: "LEAP",
             18: "EAP-SIM", 21: "EAP-TTLS", 23: "EAP-AKA", 25: "PEAP", 26: "EAP-MSCHAPv2", 43: "EAP-FAST", 50: "EAP-AKA'",
             52: "EAP-PWD", 55: "TEAP", 254: "Expanded"}
GW_PORTS = (22, 23, 80, 443, 8080, 8443, 8291)
PORT_NAMES = {22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 445: "SMB", 8080: "HTTP", 8443: "HTTPS", 8291: "Winbox"}
PEER_PORTS = (80, 443, 445, 22)
COMMON_GW = ("192.168.0.1", "192.168.1.1", "192.168.2.1", "192.168.10.1", "192.168.88.1", "192.168.100.1", "192.168.178.1",
             "10.0.0.1", "10.0.0.138", "10.0.1.1", "10.1.1.1", "10.10.10.1", "172.16.0.1", "172.16.1.1")
INTERNAL_PORTS = (80, 443)
MAX_PEERS = 16
MAX_TCP_PEERS = 8
MAX_TARGETS = 20
MAX_PROBES = 200
HISTORY = 20
TIMEOUT = 1.0
WORKERS = 8
MIN_INTERVAL = 10
T_ISO = "Χάλασε η απομόνωση του guest Wi-Fi"
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _norm(m):
    m = str(m or "").lower().replace("-", ":")
    return ":".join(x.zfill(2) for x in m.split(":")) if re.match(r"^[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}$", m) else ""


def private4(ip):
    """True μόνο για ιδιωτική IPv4 (RFC1918). Όλα τα άλλα (δημόσια, loopback, link-local, multicast, IPv6) → False."""
    try:
        a = ipaddress.IPv4Address(str(ip))
    except ValueError:
        return False
    return any(a in n for n in RFC1918)


def parse_target(s):
    """«10.0.0.5» ή «10.0.0.5:445» → (ip, port ή None). Δημόσια/άκυρη διεύθυνση → ValueError (ελληνικό μήνυμα)."""
    s = str(s or "").strip()
    host, _, port = s.partition(":")
    if not private4(host):
        raise ValueError(f"«{s[:40]}»: μόνο ιδιωτικές διευθύνσεις IPv4 (10.x, 172.16–31.x, 192.168.x).")
    if port:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError(f"«{s[:40]}»: άκυρη θύρα.")
        return host, int(port)
    return host, None


# ───────── EAPOL / EAP (καθαρές συναρτήσεις) ─────────
def _mac_b(m):
    return bytes.fromhex(_norm(m).replace(":", ""))


def eapol_frame(src_mac, ptype, body=b"", version=1, dst=PAE):
    """Πλαίσιο EAPOL (IEEE 802.1X §11.3): version(1) type(1) body-length(2) body."""
    return _mac_b(dst) + _mac_b(src_mac) + bytes([ETH_EAPOL >> 8, ETH_EAPOL & 255, version & 255, ptype & 255,
                                                   len(body) >> 8, len(body) & 255]) + bytes(body)


def eapol_start(src_mac, version=1):
    return eapol_frame(src_mac, 1, b"", version)


def eap_packet(code, ident, typ=None, data=b""):
    """Πακέτο EAP (RFC 3748 §4): code(1) identifier(1) length(2, όλο το πακέτο) [type(1) data]."""
    body = (bytes([typ & 255]) + bytes(data)) if typ is not None else b""
    n = 4 + len(body)
    return bytes([code & 255, ident & 255, n >> 8, n & 255]) + body


def eap_identity_response(src_mac, ident, identity="anonymous", dst=PAE):
    return eapol_frame(src_mac, 0, eap_packet(2, ident, 1, str(identity).encode("utf-8")[:64]), dst=dst)


def parse_eapol(raw):
    """Πλαίσιο Ethernet (και με ετικέτα 802.1Q) → {"src","dst","version","ptype","ptype_name","eap"} ή None."""
    try:
        raw = bytes(raw)
        if len(raw) < 18:
            return None
        off = 12
        if raw[off:off + 2] == b"\x81\x00":
            off += 4
        if len(raw) < off + 6 or raw[off:off + 2] != b"\x88\x8e":
            return None
        ver, ptype, blen = raw[off + 2], raw[off + 3], (raw[off + 4] << 8) | raw[off + 5]
        body = raw[off + 6:off + 6 + min(blen, 1500)]
        out = {"dst": ":".join("%02x" % x for x in raw[0:6]), "src": ":".join("%02x" % x for x in raw[6:12]),
               "version": ver, "ptype": ptype, "ptype_name": EAPOL_TYPES.get(ptype, f"type {ptype}"), "eap": None}
        if ptype == 0 and len(body) >= 4:
            code, ident, ln = body[0], body[1], (body[2] << 8) | body[3]
            eap = {"code": code, "code_name": EAP_CODES.get(code, f"code {code}"), "id": ident, "len": ln, "type": None, "type_name": "", "text": ""}
            if code in (1, 2) and ln >= 5 and len(body) >= 5:
                eap["type"] = body[4]
                eap["type_name"] = EAP_TYPES.get(body[4], f"type {body[4]}")
                if body[4] in (1, 2):  # Identity / Notification: προαιρετικό κείμενο
                    txt = body[5:min(ln, len(body))].split(b"\x00")[0]
                    eap["text"] = re.sub(r"[^\x20-\x7e]", "?", txt.decode("latin-1"))[:80]
            out["eap"] = eap
        return out
    except Exception:  # noqa: BLE001
        return None


def wifi_class(sec):
    """Συμβολοσειρά ασφάλειας (wifiguard.wifi_info()["security"]) → είδος, WPA3, PMF, επίπεδο και εξήγηση."""
    s = str(sec or "").lower().replace("-", "_")
    wpa3 = "wpa3" in s or "sae" in s
    trans = "transition" in s or ("wpa2" in s and wpa3) or "mixed" in s
    if not s or s == "unknown":
        kind = "unknown"
    elif "enterprise" in s or "802.1x" in s or "eap" in s:
        kind = "enterprise"
    elif "owe" in s:
        kind = "owe"
    elif s in ("none", "open") or "open" in s:
        kind = "open"
    elif "wep" in s:
        kind = "wep"
    else:
        kind = "psk"
    pmf = "required" if (kind == "owe" or (wpa3 and not trans)) else "optional" if wpa3 else "unknown"
    TXT = {
        "enterprise": ("ok", "Enterprise (802.1X): κάθε χρήστης/συσκευή μπαίνει με δικό του λογαριασμό ή πιστοποιητικό.",
                       "Enterprise (802.1X): each user/device joins with its own account or certificate."),
        "psk": ("ok" if wpa3 else "warn" if s.startswith("wpa_") or "tkip" in s else "info",
                "Κοινός κωδικός (PSK): όλοι μοιράζονται το ίδιο κλειδί — όποιος το ξέρει μπαίνει. Για επισκέπτες είναι αναμενόμενο.",
                "Shared password (PSK): everyone shares one key — whoever knows it gets in. Expected for guests."),
        "open": ("bad", "Ανοιχτό δίκτυο χωρίς κρυπτογράφηση: ό,τι δεν είναι HTTPS φαίνεται σε όποιον ακούει.",
                 "Open network without encryption: anything that is not HTTPS is visible to anyone listening."),
        "owe": ("ok", "Ανοιχτό αλλά κρυπτογραφημένο (OWE / Enhanced Open): χωρίς κωδικό, με κρυπτογράφηση ανά πελάτη.",
                "Open but encrypted (OWE / Enhanced Open): no password, per-client encryption."),
        "wep": ("bad", "WEP: σπάει σε λεπτά — άλλαξέ το σε WPA2/WPA3.", "WEP: breaks in minutes — change it to WPA2/WPA3."),
        "unknown": ("info", "Το λειτουργικό δεν μου λέει την ασφάλεια αυτού του δικτύου.", "The OS does not tell me this network's security."),
    }
    lvl, el, en = TXT[kind]
    return {"kind": kind, "wpa3": wpa3, "transition": bool(wpa3 and trans), "pmf": pmf, "level": lvl, "el": el, "en": en, "raw": str(sec or "")[:40]}


class Net:
    """Τα πραγματικά πακέτα / εντολές. Στα tests μπαίνει ψεύτικο αντικείμενο με τις ίδιες μεθόδους."""

    def eapol(self, iface, timeout=5.0, identity=None):
        """EAPOL-Start και ό,τι EAPOL απαντηθεί (λίστα πλαισίων bytes). Θέλει root, όπως η σύλληψη."""
        from scapy.all import AsyncSniffer, Ether, conf, sendp

        from core import require_real_mac
        iface = iface or conf.iface
        mac = _norm(require_real_mac(iface))
        got, answered = [], []

        def cb(p):
            raw = bytes(getattr(p, "original", None) or bytes(p))
            e = parse_eapol(raw)
            if not e or e["src"] == mac or len(got) >= 40:
                return
            got.append(raw)
            eap = e["eap"]
            if identity and not answered and eap and eap["code"] == 1 and eap["type"] == 1:
                answered.append(1)
                sendp(Ether(eap_identity_response(mac, eap["id"], identity)), iface=iface, verbose=0)

        sn = AsyncSniffer(iface=iface, filter="ether proto 0x888e", prn=cb, store=False, timeout=timeout)
        sn.start()
        time.sleep(0.4)
        sendp(Ether(eapol_start(mac)), iface=iface, verbose=0)
        sn.join(timeout + 2)
        return got

    def local(self):
        """→ {"ip","prefix","gw","iface"} της διεπαφής με το default gateway (μέσω netkit.iface_info)."""
        import netkit
        info = netkit.iface_info()
        gw, gif = info.get("gateway"), info.get("gateway_iface")
        best = None
        for it in info.get("interfaces") or []:
            for a in it.get("ipv4") or []:
                ip, pfx = a.get("addr"), a.get("prefix") or 24
                if not private4(ip):
                    continue
                cand = {"ip": ip, "prefix": int(pfx), "gw": gw, "iface": it.get("name")}
                try:
                    hit = bool(gw) and ipaddress.ip_address(gw) in ipaddress.ip_network(f"{ip}/{pfx}", strict=False)
                except ValueError:
                    hit = False
                if hit or it.get("name") == gif:
                    return cand
                best = best or cand
        return best or {"ip": None, "prefix": None, "gw": gw, "iface": gif}

    def arp_cache(self):
        import l2guard
        return l2guard.ScapyProber().arp_cache()

    def ping(self, ip, timeout=TIMEOUT):
        if not private4(ip):
            return False
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        elif sys.platform == "darwin":
            cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
        try:
            return subprocess.run(cmd, capture_output=True, timeout=timeout + 2).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def tcp(self, ip, port, timeout=TIMEOUT):
        if not private4(ip):  # δεύτερη ασφάλεια: ποτέ δημόσια διεύθυνση
            return False
        try:
            with socket.create_connection((ip, int(port)), timeout=timeout):
                return True
        except OSError:
            return False

    def dns(self, name="example.com"):
        try:
            return bool(socket.getaddrinfo(name, 80, socket.AF_INET))
        except (OSError, UnicodeError):
            return False

    def internet(self):
        for ip in ("1.1.1.1", "8.8.8.8"):  # σταθερό σύνολο, όπως το nettriage
            try:
                with socket.create_connection((ip, 443), timeout=3):
                    return True
            except OSError:
                continue
        return False

    def captive(self):
        import wifiguard
        return wifiguard.captive_portal(4)

    def wifi(self):
        import wifiguard
        return wifiguard.wifi_info()


def fix_config(cidr="192.168.50.0/24", gw="192.168.50.1", lang="el"):
    """Έτοιμο παράδειγμα ACL (Cisco IOS) και firewall filter (MikroTik) για το δίκτυο επισκεπτών."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.version != 4:
            raise ValueError
    except ValueError:
        net = ipaddress.ip_network("192.168.50.0/24")
    gw = gw if private4(gw) else str(net.network_address + 1)
    n, w = net.network_address, net.hostmask
    L = (lambda el, en: en) if lang == "en" else (lambda el, en: el)
    cisco = "\n".join([
        "ip access-list extended GUEST-IN",
        " remark " + L("DHCP και DNS προς το router επιτρέπονται", "DHCP and DNS to the router are allowed"),
        " permit udp any eq bootpc any eq bootps",
        f" permit udp {n} {w} host {gw} eq domain",
        f" permit tcp {n} {w} host {gw} eq domain",
        " remark " + L("όχι διαχείριση του router (αν έχει captive portal: permit tcp … eq 80/443 πριν)", "no router management (with a captive portal: permit tcp … eq 80/443 first)"),
        f" deny   ip {n} {w} host {gw}",
        " remark " + L("όχι εσωτερικά δίκτυα", "no internal networks"),
        " deny   ip any 10.0.0.0 0.255.255.255",
        " deny   ip any 172.16.0.0 0.15.255.255",
        " deny   ip any 192.168.0.0 0.0.255.255",
        " remark " + L("όλα τα άλλα = Internet", "everything else = Internet"),
        f" permit ip {n} {w} any",
        "!",
        "interface Vlan50",
        " ip access-group GUEST-IN in",
        "!",
        "! " + L("Πελάτης ↔ πελάτης στο ίδιο VLAN ΔΕΝ περνά από ACL: θέλει «client isolation» στο AP", "Client ↔ client inside one VLAN does NOT cross the ACL: use AP “client isolation”"),
        "! " + L("και στις θύρες του switch:", "and on the switch ports:"),
        "interface range GigabitEthernet0/2 - 24",
        " switchport protected",
    ])
    mikrotik = "\n".join([
        "/ip firewall address-list",
        "add list=rfc1918 address=10.0.0.0/8",
        "add list=rfc1918 address=172.16.0.0/12",
        "add list=rfc1918 address=192.168.0.0/16",
        "/ip firewall filter",
        "# " + L("βάλ' τους ΠΑΝΩ από τους γενικούς κανόνες accept (place-before)", "put these ABOVE the generic accept rules (place-before)"),
        f"add chain=input src-address={net} protocol=udp dst-port=53,67 action=accept comment=\"guest: DNS+DHCP\"",
        f"add chain=input src-address={net} protocol=tcp dst-port=53 action=accept comment=\"guest: DNS\"",
        f"add chain=input src-address={net} action=drop comment=\"guest: " + L("όχι διαχείριση router", "no router management") + "\"",
        f"add chain=forward src-address={net} dst-address-list=rfc1918 action=drop comment=\"guest: " + L("όχι εσωτερικά δίκτυα", "no internal networks") + "\"",
        "# " + L("απομόνωση πελατών Wi-Fi:", "Wi-Fi client isolation:"),
        "/interface wifi set [find where configuration.ssid~\"guest\"] datapath.client-isolation=yes",
        "# " + L("(παλιό πακέτο wireless: default-forwarding=no) · ενσύρματα: ίδιο horizon στις θύρες του bridge", "(legacy wireless package: default-forwarding=no) · wired: same horizon on the bridge ports"),
        "/interface bridge port set [find where bridge=bridge-guest] horizon=1",
    ])
    return {"cidr": str(net), "gw": gw, "cisco": cisco, "mikrotik": mikrotik}


# ───────── demo ─────────
def _rule(rid, status, el, en, found=None):
    return {"id": rid, "status": status, "el": el, "en": en, "found": found or []}


def _demo(now):
    netd = {"ip": "192.168.50.23", "prefix": 24, "gw": "192.168.50.1", "cidr": "192.168.50.0/24", "iface": "en0", "ssid": "Cafe-Guest"}
    ok = {"t": now - 26 * 3600, "net": netd, "key": "192.168.50.1|192.168.50.0/24", "verdict": "ok", "iso": True, "probes": 71, "trigger": "manual", "rules": [
        _rule("clients", "pass", "Δοκίμασα 6 συσκευές του ίδιου δικτύου — καμία δεν απάντησε (ούτε ARP, ούτε ping, ούτε θύρες).", "Tried 6 devices on the same network — none answered (no ARP, ping or ports)."),
        _rule("gw_mgmt", "pass", "Καμία θύρα διαχείρισης του router 192.168.50.1 δεν είναι ανοιχτή προς τους επισκέπτες.", "No management port of router 192.168.50.1 is open to guests."),
        _rule("internal", "pass", "Κανένα εσωτερικό δίκτυο δεν απαντά (14 συνηθισμένα gateways + 2 δικοί σου στόχοι).", "No internal network answers (14 common gateways + 2 of your targets)."),
        _rule("dns", "pass", "Το DNS δουλεύει.", "DNS works."), _rule("internet", "pass", "Το Internet δουλεύει.", "Internet works."),
        _rule("captive", "info", "Υπάρχει captive portal (σελίδα σύνδεσης).", "A captive portal (login page) is present.")]}
    bad = {"t": now - 40 * 60, "net": netd, "key": ok["key"], "verdict": "fail", "iso": False, "probes": 74, "trigger": "manual", "rules": [
        _rule("clients", "fail", "Έφτασα 2 άλλες συσκευές του ίδιου δικτύου: 192.168.50.31 (ping, 445/SMB), 192.168.50.44 (ping, 80/HTTP). Η απομόνωση πελατών ΔΕΝ δουλεύει.",
              "Reached 2 other devices on the same network: 192.168.50.31 (ping, 445/SMB), 192.168.50.44 (ping, 80/HTTP). Client isolation is NOT working.",
              [{"ip": "192.168.50.31", "ping": True, "ports": [445], "arp": "3c:22:fb:70:01:9d"}, {"ip": "192.168.50.44", "ping": True, "ports": [80], "arp": "d8:3a:dd:41:be:02"}]),
        _rule("gw_mgmt", "fail", "Το router 192.168.50.1 δέχεται επισκέπτες στις θύρες διαχείρισης: 443/HTTPS, 8291/Winbox.",
              "Router 192.168.50.1 accepts guests on management ports: 443/HTTPS, 8291/Winbox.", [{"ip": "192.168.50.1", "ports": [443, 8291]}]),
        _rule("internal", "fail", "Από το guest φτάνω εσωτερικά δίκτυα: 192.168.1.1 (ping, 80, 443), 192.168.1.10:445.",
              "From guest I can reach internal networks: 192.168.1.1 (ping, 80, 443), 192.168.1.10:445.",
              [{"ip": "192.168.1.1", "ping": True, "ports": [80, 443]}, {"ip": "192.168.1.10", "ping": False, "ports": [445], "user": True}]),
        _rule("dns", "pass", "Το DNS δουλεύει.", "DNS works."), _rule("internet", "pass", "Το Internet δουλεύει.", "Internet works."),
        _rule("captive", "info", "Υπάρχει captive portal (σελίδα σύνδεσης).", "A captive portal (login page) is present.")]}
    dot1x = {"t": now - 2 * 3600, "iface": "en5", "status": "required", "have_ip": False, "method": "PEAP", "identity_sent": True,
             "frames": [{"src": "00:1b:54:aa:10:02", "ptype_name": "EAP-Packet", "version": 2, "eap": "Request Identity (id 1)"},
                        {"src": "00:1b:54:aa:10:02", "ptype_name": "EAP-Packet", "version": 2, "eap": "Request PEAP (id 2)"}],
             "el": "Η θύρα ζητά 802.1X: ο authenticator (00:1b:54:aa:10:02) απάντησε με EAP-Request/Identity και ο server προσφέρει PEAP. Χωρίς σωστά στοιχεία η συσκευή δεν παίρνει δίκτυο.",
             "en": "The port requires 802.1X: the authenticator (00:1b:54:aa:10:02) answered with EAP-Request/Identity and the server offers PEAP. Without valid credentials a device gets no network."}
    wifi = dict(wifi_class("wpa2_personal"), t=now - 40 * 60, ssid="Cafe-Guest", channel="44", signal=-58)
    return [bad, ok], dot1x, wifi


class NacCheck:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time, net=None):
        self.state, self.demo, self.clock = state, demo, clock
        self.net = net or Net()
        self.path = os.path.join(data_dir, "nacheck.json") if data_dir else None
        self.on_save = None
        self.lock = threading.RLock()
        self.busy = None          # None / "dot1x" / "isolation" / "wifi"
        self.history = []         # νεότερο πρώτο, έως HISTORY
        self.dot1x = None
        self.wifi = None
        self.cfg = {"targets": [], "peers": [], "every_min": 0}
        self.error = None
        if demo:
            self.history, self.dot1x, self.wifi = _demo(self.clock())
            self.cfg = {"targets": ["192.168.1.10:445", "10.0.0.5:3389"], "peers": [], "every_min": 0}
        else:
            self._load()

    # ── αποθήκευση ──
    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                j = json.load(f)
            self.history = [h for h in (j.get("history") or []) if isinstance(h, dict) and isinstance(h.get("rules"), list)][:HISTORY]
            self.dot1x = j.get("dot1x") if isinstance(j.get("dot1x"), dict) else None
            self._set_cfg(j.get("config") or {}, strict=False)
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save(self):
        if not self.path or self.demo:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"history": self.history[:HISTORY], "dot1x": self.dot1x, "config": self.cfg}, f)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    def _set_cfg(self, c, strict=True):
        """Ρυθμίσεις από τον χρήστη. strict → ValueError στο πρώτο λάθος· αλλιώς τα άκυρα απλώς αγνοούνται."""
        out = dict(self.cfg)
        for key in ("targets", "peers"):
            if key not in c:
                continue
            raw = c.get(key)
            raw = re.split(r"[\s,;]+", raw) if isinstance(raw, str) else list(raw or [])
            ok = []
            for s in raw:
                s = str(s).strip()
                if not s:
                    continue
                try:
                    ip, port = parse_target(s)
                    if key == "peers" and port:
                        raise ValueError(f"«{s[:40]}»: για άλλο πελάτη δώσε μόνο την IP.")
                except ValueError:
                    if strict:
                        raise
                    continue
                v = ip if port is None else f"{ip}:{port}"
                if v not in ok:
                    ok.append(v)
            if strict and len(ok) > MAX_TARGETS:
                raise ValueError(f"Το πολύ {MAX_TARGETS} διευθύνσεις.")
            out[key] = ok[:MAX_TARGETS]
        if "every_min" in c:
            try:
                n = int(c.get("every_min") or 0)
            except (TypeError, ValueError):
                n = 0
            out["every_min"] = 0 if n <= 0 else max(15, min(n, 1440))
        self.cfg = out

    # ── 1. 802.1X ──
    def _have_ip(self):
        me = getattr(self.state, "me", None) if self.state is not None else None
        ips = [i for i in (me or ()) if private4(i)]
        if ips:
            return True
        try:
            return bool(private4((self.net.local() or {}).get("ip")))
        except Exception:  # noqa: BLE001
            return False

    def run_dot1x(self, identity=None):
        """Στέλνει EAPOL-Start και ερμηνεύει ό,τι απαντηθεί. → dict αποτελέσματος (και στο self.dot1x)."""
        now = self.clock()
        iface = getattr(self.state, "iface", None) if self.state is not None else None
        r = {"t": now, "iface": iface, "status": "none", "have_ip": False, "method": None, "identity_sent": bool(identity), "frames": []}
        try:
            frames = self.net.eapol(iface, 5.0, identity)
        except Exception as e:  # noqa: BLE001 — π.χ. χωρίς root
            perm = isinstance(e, PermissionError) or re.search(r"permi|not permitted|root|admin", str(e), re.I)
            r.update(status="err",
                     el=("Δεν επιτρέπεται η αποστολή πλαισίων: ο έλεγχος 802.1X θέλει δικαιώματα διαχειριστή (root), όπως η σύλληψη πακέτων."
                         if perm else "Δεν έγινε ο έλεγχος 802.1X: " + str(e)[:140]),
                     en=("Sending frames is not permitted: the 802.1X check needs administrator (root) rights, like packet capture."
                         if perm else "802.1X check failed: " + str(e)[:140]))
            self.dot1x = r
            return r
        r["have_ip"] = self._have_ip()
        auth, ident_req, method, success, failure = None, False, None, False, False
        for f in (frames or [])[:40]:
            e = parse_eapol(f)
            if not e or e["ptype"] != 0 or not e["eap"]:
                continue
            eap = e["eap"]
            if eap["code"] == 1:
                auth = auth or e["src"]
                if eap["type"] == 1:
                    ident_req = True
                elif eap["type"] not in (None, 2):
                    method = method or eap["type_name"]
            elif eap["code"] == 3:
                auth, success = auth or e["src"], True
            elif eap["code"] == 4:
                auth, failure = auth or e["src"], True
            else:
                continue
            desc = eap["code_name"] + (" " + eap["type_name"] if eap["type_name"] else "") + f" (id {eap['id']})"
            if len(r["frames"]) < 8:
                r["frames"].append({"src": e["src"], "ptype_name": e["ptype_name"], "version": e["version"], "eap": desc})
        r["method"] = method
        ip_el = (" Παρ' όλα αυτά αυτός ο υπολογιστής ΕΧΕΙ ήδη διεύθυνση IP: η θύρα σε άφησε να μπεις χωρίς 802.1X — με MAB "
                 "(αναγνώριση από τη MAC), guest VLAN ή λειτουργία «open/monitor». Έλεγξε σε ποιο VLAN βρέθηκες.") if r["have_ip"] else \
                " Χωρίς σωστά στοιχεία η συσκευή δεν παίρνει δίκτυο."
        ip_en = (" Yet this computer already HAS an IP address: the port let you in without 802.1X — via MAB (MAC-based), a guest "
                 "VLAN or “open/monitor” mode. Check which VLAN you landed in.") if r["have_ip"] else " Without valid credentials a device gets no network."
        m_el, m_en = (f" Ο server προσφέρει {method}.", f" The server offers {method}.") if method else ("", "")
        if ident_req or (auth and not success):
            r.update(status="required",
                     el=f"Η θύρα ζητά 802.1X: ο authenticator ({auth}) απάντησε με EAP-Request/Identity.{m_el}{ip_el}",
                     en=f"The port requires 802.1X: the authenticator ({auth}) answered with EAP-Request/Identity.{m_en}{ip_en}")
            if failure and not ident_req:
                r["el"] = f"Ο authenticator ({auth}) απάντησε EAP-Failure: η θύρα μιλά 802.1X και απορρίπτει.{ip_el}"
                r["en"] = f"The authenticator ({auth}) answered EAP-Failure: the port speaks 802.1X and rejects.{ip_en}"
        elif success:
            r.update(status="bypass",
                     el=f"Ο authenticator ({auth}) έστειλε EAP-Success χωρίς να δώσουμε στοιχεία: η θύρα μιλά 802.1X αλλά σε αφήνει να μπεις (guest VLAN / λειτουργία open).",
                     en=f"The authenticator ({auth}) sent EAP-Success although we gave no credentials: the port speaks 802.1X but lets you in (guest VLAN / open mode).")
        else:
            r.update(status="none",
                     el="Κανείς δεν απάντησε στο EAPOL-Start: η θύρα ΔΕΝ ζητά 802.1X. " + (
                         "Έχεις ήδη IP, άρα είναι ανοιχτή θύρα — ή το switch σε αναγνώρισε μόνο από τη MAC (MAB)." if r["have_ip"] else
                         "Δεν έχεις IP: μπορεί η θύρα να είναι κλειστή/σε άλλο VLAN χωρίς DHCP, ή να περιμένει μόνο MAB."),
                     en="Nobody answered the EAPOL-Start: the port does NOT require 802.1X. " + (
                         "You already have an IP, so it is an open port — or the switch recognised you by MAC only (MAB)." if r["have_ip"] else
                         "You have no IP: the port may be shut / in a VLAN without DHCP, or it expects MAB only."))
        self.dot1x = r
        return r

    # ── 2. Wi‑Fi ──
    def run_wifi(self):
        now = self.clock()
        try:
            w = self.net.wifi()
        except Exception:  # noqa: BLE001
            w = None
        if not isinstance(w, dict) or not (w.get("security") or w.get("ssid")):
            self.wifi = {"t": now, "kind": "none", "level": "info", "el": "Δεν είσαι συνδεδεμένος σε Wi‑Fi (ή το λειτουργικό δεν δίνει τα στοιχεία).",
                         "en": "Not connected to Wi‑Fi (or the OS does not expose the details).", "pmf": "unknown", "wpa3": False}
        else:
            ssid = str(w.get("ssid") or "")[:64]
            self.wifi = dict(wifi_class(w.get("security")), t=now, ssid="" if ssid.startswith("<") else ssid,
                             channel=str(w.get("channel") or "")[:24], signal=w.get("signal") if isinstance(w.get("signal"), int) else None)
        return self.wifi

    # ── 3. απομόνωση ──
    def _hosts_in(self, net4, skip):
        st = self.state
        if st is None:
            return []
        lock = getattr(st, "lock", None)
        try:
            if lock:
                lock.acquire()
            hs = [(h.get("last") or 0, str(h.get("ip"))) for h in (getattr(st, "hosts", None) or {}).values()
                  if isinstance(h, dict) and h.get("kind") in (None, "local")]
        except RuntimeError:
            hs = []
        finally:
            if lock:
                lock.release()
        out = []
        for _last, ip in sorted(hs, reverse=True):
            try:
                if private4(ip) and ip not in skip and ipaddress.ip_address(ip) in net4:
                    out.append(ip)
            except ValueError:
                continue
        return out

    def run_isolation(self, trigger="manual"):
        """Τρέχει το τεστ απομόνωσης (μπλοκάρει ~10–20 δευτ.). → η εγγραφή ιστορικού ή {"error": …}."""
        now = self.clock()
        try:
            loc = dict(self.net.local() or {})
        except Exception as e:  # noqa: BLE001
            loc = {"error": str(e)[:120]}
        ip, gw = loc.get("ip"), loc.get("gw")
        if not private4(ip):
            self.error = {"el": "Δεν βρήκα ιδιωτική διεύθυνση IPv4 σε αυτόν τον υπολογιστή — σύνδεσέ τον στο δίκτυο επισκεπτών και ξαναδοκίμασε.",
                          "en": "No private IPv4 address found on this computer — connect it to the guest network and try again."}
            return {"error": self.error["el"]}
        self.error = None
        try:
            pfx = int(loc.get("prefix") or 24)
        except (TypeError, ValueError):
            pfx = 24
        net4 = ipaddress.ip_network(f"{ip}/{min(max(pfx, 8), 30)}", strict=False)
        gw = gw if private4(gw) else None
        me_set = set(getattr(self.state, "me", None) or ()) | {ip}
        skip = me_set | ({gw} if gw else set()) | {str(net4.network_address), str(net4.broadcast_address)}
        budget = [MAX_PROBES]

        def spend(n=1):
            if budget[0] < n:
                return False
            budget[0] -= n
            return True

        def safe(fn, *a):
            try:
                return bool(fn(*a))
            except Exception:  # noqa: BLE001
                return False

        try:
            arp0 = {k: _norm(v) for k, v in (self.net.arp_cache() or {}).items()}
        except Exception:  # noqa: BLE001
            arp0 = {}
        # — υποψήφιοι «άλλοι πελάτες» —
        peers, known = [], 0
        for p in self.cfg.get("peers") or []:
            if private4(p) and p not in skip and p not in peers:
                peers.append(p)
        for p in self._hosts_in(net4, skip):
            if p not in peers:
                peers.append(p)
        for p, mac in arp0.items():
            try:
                inside = private4(p) and ipaddress.ip_address(p) in net4
            except ValueError:
                inside = False
            if inside and mac and mac != "ff:ff:ff:ff:ff:ff" and p not in skip and p not in peers:
                peers.append(p)
        peers = peers[:MAX_PEERS]
        known = len(peers)
        base = int(ipaddress.ip_address(ip))
        for d in (1, -1, 2, -2, 3, -3, 4, -4, 5, -5, 6, -6):  # λίγοι «γείτονες» γύρω από τη δική μου IP
            if len(peers) >= MAX_PEERS:
                break
            cand = str(ipaddress.ip_address(base + d)) if 0 < base + d < 2 ** 32 else ""
            try:
                if cand and private4(cand) and ipaddress.ip_address(cand) in net4 and cand not in skip and cand not in peers:
                    peers.append(cand)
            except ValueError:
                continue
        # — στόχοι «εσωτερικά δίκτυα» —
        internal = []
        for g in COMMON_GW:
            if g != gw and g not in me_set and ipaddress.ip_address(g) not in net4:
                internal.append((g, None, False))
        for s in (self.cfg.get("targets") or [])[:MAX_TARGETS]:
            try:
                tip, tport = parse_target(s)
            except ValueError:
                continue  # ποτέ δημόσια διεύθυνση, ό,τι κι αν γράφει το αρχείο ρυθμίσεων
            if tip not in me_set:
                internal.append((tip, tport, True))
        jobs = []   # (ομάδα, ip, "ping" ή θύρα)
        for i, p in enumerate(peers):
            jobs.append(("peer", p, "ping"))
            if i < MAX_TCP_PEERS:
                jobs += [("peer", p, port) for port in PEER_PORTS]
        if gw:
            jobs += [("gw", gw, port) for port in GW_PORTS]
        for tip, tport, _user in internal:
            if tport:
                jobs.append(("int", tip, tport))
            else:
                jobs += [("int", tip, "ping")] + [("int", tip, port) for port in INTERNAL_PORTS]
        jobs = [j for j in jobs if private4(j[1]) and spend()]

        def probe(j):
            _grp, tip, what = j
            return j, (safe(self.net.ping, tip, TIMEOUT) if what == "ping" else safe(self.net.tcp, tip, what, TIMEOUT))

        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            results = list(ex.map(probe, jobs))
        hit = {}
        for (grp, tip, what), ok in results:
            d = hit.setdefault((grp, tip), {"ip": tip, "ping": False, "ports": []})
            if ok and what == "ping":
                d["ping"] = True
            elif ok:
                d["ports"].append(what)
        try:
            arp1 = {k: _norm(v) for k, v in (self.net.arp_cache() or {}).items()}
        except Exception:  # noqa: BLE001
            arp1 = {}
        dns_ok, inet_ok = safe(self.net.dns), safe(self.net.internet)
        try:
            cap = self.net.captive() or {}
        except Exception:  # noqa: BLE001
            cap = {}
        portal = cap.get("ok") is False

        def show(d):
            bits = (["ping"] if d.get("ping") else []) + [f"{p}/{PORT_NAMES[p]}" if p in PORT_NAMES else str(p) for p in d.get("ports") or []]
            return f"{d['ip']} ({', '.join(bits)})" if bits else d["ip"]

        rules = []
        # (i) άλλοι πελάτες
        reached, arp_only = [], []
        for p in peers:
            d = dict(hit.get(("peer", p)) or {"ip": p, "ping": False, "ports": []})
            mac = arp1.get(p) or ""
            d["arp"] = mac if mac and mac != "ff:ff:ff:ff:ff:ff" else ""
            if d["ping"] or d["ports"]:
                reached.append(d)
            elif d["arp"]:
                arp_only.append(d)
        if reached:
            rules.append(_rule("clients", "fail", f"Έφτασα {len(reached)} άλλες συσκευές του ίδιου δικτύου: {', '.join(show(d) for d in reached[:6])}. Η απομόνωση πελατών ΔΕΝ δουλεύει.",
                               f"Reached {len(reached)} other devices on the same network: {', '.join(show(d) for d in reached[:6])}. Client isolation is NOT working.", reached[:MAX_PEERS]))
        elif arp_only:
            rules.append(_rule("clients", "warn", f"Βλέπω τη MAC {len(arp_only)} συσκευών (ARP) αλλά δεν απαντούν σε ping/θύρες: {', '.join(d['ip'] for d in arp_only[:6])}. "
                               "Μάλλον τις προστατεύει το δικό τους firewall — το AP δεν φαίνεται να απομονώνει στο επίπεδο 2.",
                               f"I can see the MAC of {len(arp_only)} devices (ARP) but they do not answer ping/ports: {', '.join(d['ip'] for d in arp_only[:6])}. "
                               "Their own firewall is probably protecting them — the AP does not seem to isolate at layer 2.", arp_only[:MAX_PEERS]))
        elif not known:
            rules.append(_rule("clients", "untested", "Δεν ξέρω άλλη συσκευή σε αυτό το δίκτυο, οπότε δεν μπορώ να πω αν η απομόνωση δουλεύει. Σύνδεσε ένα δεύτερο κινητό/laptop "
                               "στο guest, γράψε την IP του στο «Άλλος πελάτης» και ξανατρέξε.",
                               "I know no other device on this network, so I cannot tell whether isolation works. Connect a second phone/laptop to guest, "
                               "enter its IP under “Other client” and run again."))
        else:
            rules.append(_rule("clients", "pass", f"Δοκίμασα {len(peers)} συσκευές του ίδιου δικτύου — καμία δεν απάντησε (ούτε ARP, ούτε ping, ούτε θύρες).",
                               f"Tried {len(peers)} devices on the same network — none answered (no ARP, ping or ports)."))
        # (ii) διαχείριση router
        if not gw:
            rules.append(_rule("gw_mgmt", "untested", "Δεν βρήκα ιδιωτική διεύθυνση router (gateway).", "No private router (gateway) address found."))
        else:
            g = hit.get(("gw", gw)) or {"ip": gw, "ports": []}
            op = sorted(g["ports"])
            names = ", ".join(f"{p}/{PORT_NAMES.get(p, '')}" for p in op)
            if not op:
                rules.append(_rule("gw_mgmt", "pass", f"Καμία θύρα διαχείρισης του router {gw} δεν είναι ανοιχτή προς τους επισκέπτες.", f"No management port of router {gw} is open to guests."))
            elif portal and set(op) <= {80, 443}:
                rules.append(_rule("gw_mgmt", "warn", f"Το router {gw} απαντά στις {names} — μάλλον είναι η σελίδα του captive portal. Βεβαιώσου ότι από εκεί ΔΕΝ ανοίγει η σελίδα διαχείρισης.",
                                   f"Router {gw} answers on {names} — probably the captive portal page. Make sure the admin page is NOT reachable there.", [{"ip": gw, "ports": op}]))
            else:
                rules.append(_rule("gw_mgmt", "fail", f"Το router {gw} δέχεται επισκέπτες στις θύρες διαχείρισης: {names}.",
                                   f"Router {gw} accepts guests on management ports: {names}.", [{"ip": gw, "ports": op}]))
        # (iii) εσωτερικά δίκτυα
        found = []
        for tip, tport, user in internal:
            d = hit.get(("int", tip))
            if d and (d["ping"] or d["ports"]) and not any(x["ip"] == tip for x in found):
                found.append(dict(d, user=user))
        n_user = sum(1 for x in internal if x[2])
        if found:
            rules.append(_rule("internal", "fail", f"Από εδώ φτάνω άλλα ιδιωτικά δίκτυα: {', '.join(show(d) for d in found[:8])}.",
                               f"From here I can reach other private networks: {', '.join(show(d) for d in found[:8])}.", found[:MAX_TARGETS]))
        else:
            rules.append(_rule("internal", "pass", f"Κανένα εσωτερικό δίκτυο δεν απαντά ({len(internal) - n_user} συνηθισμένα gateways + {n_user} δικοί σου στόχοι).",
                               f"No internal network answers ({len(internal) - n_user} common gateways + {n_user} of your targets)."))
        rules.append(_rule("dns", "pass" if dns_ok else "fail", "Το DNS δουλεύει." if dns_ok else "Το DNS ΔΕΝ δουλεύει — οι επισκέπτες δεν θα ανοίγουν σελίδες.",
                           "DNS works." if dns_ok else "DNS does NOT work — guests will not be able to open pages."))
        rules.append(_rule("internet", "pass" if inet_ok else ("warn" if portal else "fail"),
                           "Το Internet δουλεύει." if inet_ok else "Δεν βγαίνω στο Internet" + (" — πρώτα κάνε είσοδο στο captive portal." if portal else "."),
                           "Internet works." if inet_ok else "No Internet access" + (" — log in to the captive portal first." if portal else ".")))
        rules.append(_rule("captive", "info", "Υπάρχει captive portal (σελίδα σύνδεσης)." if portal else
                           "Δεν υπάρχει captive portal." if cap.get("ok") else "Δεν μπόρεσα να ελέγξω για captive portal.",
                           "A captive portal (login page) is present." if portal else "No captive portal." if cap.get("ok") else "Could not check for a captive portal."))
        st3 = [r["status"] for r in rules[:3]]
        iso = False if "fail" in st3 else True
        verdict = "fail" if not iso else "warn" if (set(st3) & {"warn", "untested"} or not dns_ok or (not inet_ok and not portal)) else "ok"
        ssid = (self.wifi or {}).get("ssid") or ""
        entry = {"t": now, "net": {"ip": ip, "prefix": net4.prefixlen, "gw": gw, "cidr": str(net4), "iface": loc.get("iface"), "ssid": ssid},
                 "key": f"{gw}|{net4}", "verdict": verdict, "iso": iso, "probes": MAX_PROBES - budget[0], "trigger": trigger, "rules": rules}
        with self.lock:
            prev = next((h for h in self.history if h.get("key") == entry["key"]), None)
            self.history.insert(0, entry)
            del self.history[HISTORY:]
            self._save()
        if prev and prev.get("iso") is True and not iso:
            self._alert(entry, prev)
        return entry

    def _alert(self, entry, prev):
        st = self.state
        if self.demo or st is None or not hasattr(st, "alert"):
            return
        bad = [r["el"] for r in entry["rules"][:3] if r["status"] == "fail"]
        when = time.strftime("%d/%m %H:%M", time.localtime(prev.get("t") or 0))
        try:
            st.alert(T_ISO, "high", entry["net"]["ip"], entry["net"].get("gw") or "LAN",
                     f"Το δίκτυο επισκεπτών {entry['net']['cidr']} περνούσε τον έλεγχο απομόνωσης ({when}) αλλά τώρα όχι: " + " ".join(bad)[:600],
                     entry["t"], key=("nac", entry["key"]), cooldown=3600, mark=False)
        except Exception:  # noqa: BLE001
            pass

    # ── προβολή / API ──
    def view(self):
        with self.lock:
            hist = [dict(h) for h in self.history[:HISTORY]]
        last = hist[0] if hist else None
        netd = (last or {}).get("net") or {}
        fix = fix_config(netd.get("cidr") or "192.168.50.0/24", netd.get("gw") or "")
        fix_en = fix_config(netd.get("cidr") or "192.168.50.0/24", netd.get("gw") or "", "en")
        prev = next((h for h in hist[1:] if last and h.get("key") == last.get("key")), None)
        return {"demo": self.demo, "busy": self.busy, "dot1x": self.dot1x, "wifi": self.wifi, "last": last, "history": hist,
                "regressed": bool(last and prev and prev.get("iso") is True and last.get("iso") is False),
                "config": dict(self.cfg), "problem": self.error, "common": list(COMMON_GW), "gw_ports": list(GW_PORTS),
                "limits": {"peers": MAX_PEERS, "targets": MAX_TARGETS, "probes": MAX_PROBES, "history": HISTORY},
                "fix": dict(fix, cisco_en=fix_en["cisco"], mikrotik_en=fix_en["mikrotik"])}

    def _bg(self, what, fn, *a):
        try:
            fn(*a)
        except Exception as e:  # noqa: BLE001
            self.error = {"el": "Ο έλεγχος απέτυχε: " + str(e)[:140], "en": "The check failed: " + str(e)[:140]}
        finally:
            self.busy = None

    def _start(self, what, fn, *a):
        with self.lock:
            if self.busy:
                return self.view()
            self.busy = what
        threading.Thread(target=self._bg, args=(what, fn) + a, daemon=True).start()
        return dict(self.view(), busy=what)

    def api(self, method, sub, q, body):
        body = body or {}
        if method == "GET":
            return (200, self.view()) if sub == "" else (404, {"error": "not found"})
        if sub in ("dot1x", "isolation", "wifi", "config", "clear") and self.demo:
            return 200, self.view()  # το demo δεν αγγίζει το δίκτυο και δεν αλλάζει
        if sub == "dot1x":
            ident = "anonymous" if body.get("method") else None
            return 200, self._start("dot1x", lambda: (self.run_dot1x(ident), self._save()))
        if sub == "wifi":
            return 200, self._start("wifi", self.run_wifi)
        if sub == "isolation":
            return 200, self._start("isolation", lambda: (self.run_wifi(), self.run_isolation("manual")))
        if sub == "config":
            try:
                with self.lock:
                    self._set_cfg(body)
                    self._save()
            except ValueError as e:
                return 400, {"error": str(e)}
            return 200, self.view()
        if sub == "clear":
            with self.lock:
                self.history = []
                self._save()
            return 200, self.view()
        return 404, {"error": "not found"}

    def run_forever(self):
        """Προγραμματισμένο τεστ (μόνο αν ο τεχνικός όρισε «κάθε Ν λεπτά»· έχει νόημα όταν το NetWatch κάθεται ΣΤΟ guest)."""
        time.sleep(90)
        while True:
            try:
                n = int(self.cfg.get("every_min") or 0)
                last = self.history[0]["t"] if self.history else 0
                if n and not self.busy and self.clock() - last >= n * 60:
                    with self.lock:
                        self.busy = "isolation"
                    self._bg("isolation", self.run_isolation, "auto")
            except Exception:  # noqa: BLE001
                pass
            time.sleep(60)
