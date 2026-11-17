"""Οι δικές σου IoT συσκευές: βρίσκει ESP32 / ESP8266 / Raspberry Pi στο δίκτυο και τις ελέγχει.

Αναγνώριση: από το OUI της MAC (Espressif, Raspberry Pi), το όνομα (DNS/mDNS: esp32-…, raspberrypi…)
και τα banners (π.χ. SSH «Raspbian»).
Έλεγχοι (ελαφριοί, μόνο σε συσκευές του τοπικού δικτύου):
- Telnet ανοιχτό → κόκκινο (Mirai)
- MQTT 1883: στέλνουμε ένα MQTT CONNECT χωρίς κωδικό και διαβάζουμε το CONNACK → αν δεχτεί, ο broker είναι ανοιχτός σε όλους
- MQTT χωρίς TLS / HTTP χωρίς TLS / SSH / VNC / SMB / ArduinoOTA → προειδοποιήσεις με οδηγίες
Κάθε εύρημα δείχνει το μάθημα της Ακαδημίας που εξηγεί τη διόρθωση.
Δεν δοκιμάζει κωδικούς και δεν στέλνει τίποτα επιθετικό.
"""
import ipaddress
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ESPRESSIF = """
08:3a:f2 08:b6:1f 0c:b8:15 10:52:1c 10:91:a8 18:fe:34 24:0a:c4 24:4c:ab 24:62:ab 24:6f:28 24:a1:60 24:b2:de
24:d7:eb 24:dc:c3 2c:3a:e8 2c:f4:32 30:83:98 30:ae:a4 30:c6:f7 34:85:18 34:86:5d 34:94:54 34:ab:95 34:b4:72
3c:61:05 3c:71:bf 3c:84:27 3c:e9:0e 40:22:d8 40:4c:ca 40:91:51 44:17:93 48:27:e2 48:3f:da 48:55:19 48:e7:29
4c:11:ae 4c:75:25 4c:eb:d6 50:02:91 54:32:04 54:43:b2 54:5a:a6 58:bf:25 58:cf:79 5c:cf:7f 60:01:94 60:55:f9
64:b7:08 64:e8:33 68:67:25 68:c6:3a 70:03:9f 70:04:1d 70:b8:f6 74:4d:bd 78:21:84 78:e3:6d 7c:87:ce 7c:9e:bd
7c:df:a1 80:64:6f 80:7d:3a 84:0d:8e 84:cc:a8 84:f3:eb 84:f7:03 84:fc:e6 88:13:bf 8c:4b:14 8c:aa:b5 8c:ce:4e
90:15:06 90:38:0c 94:3c:c6 94:b5:55 94:b9:7e 94:e6:86 98:cd:ac 98:f4:ab a0:20:a6 a0:76:4e a0:b7:65 a4:7b:9d
a4:cf:12 a4:e5:7c a8:03:2a a8:42:e3 a8:48:fa ac:0b:fb ac:67:b2 b0:a7:32 b4:8a:0a b4:e6:2d b8:d6:1a b8:f0:09
bc:dd:c2 bc:ff:4d c0:49:ef c4:4f:33 c4:5b:be c4:dd:57 c8:2b:96 c8:c9:a3 c8:f0:9e cc:50:e3 cc:7b:5c cc:8d:a2
cc:db:a7 d0:ef:76 d4:8a:fc d4:d4:da d8:a0:1d d8:bf:c0 d8:f1:5b dc:4f:22 dc:54:75 dc:da:0c e0:5a:1b e0:98:06
e0:e2:e6 e4:65:b8 e8:06:90 e8:31:cd e8:68:e7 e8:9f:6d e8:db:84 ec:62:60 ec:94:cb ec:da:3b ec:fa:bc f0:08:d1
f0:9e:9e f4:12:fa f4:cf:a2 fc:b4:67 fc:e8:c0 fc:f5:c4
24:ec:4a e4:b3:23 48:ca:43 7c:2c:67 a0:85:e3 dc:06:75 30:30:f9 34:cd:b0 58:8c:81 10:20:ba ec:64:c9 e8:6b:ea
f0:f5:bd 64:e8:33 98:3d:ae cc:ba:97 b4:3a:45 68:b6:b3 1c:69:20 80:65:99 9c:9e:6e 24:58:7c 28:37:2f 94:a9:90
d8:3b:da e0:72:a1 fc:01:2c 3c:dc:75 48:31:b7 d0:cf:13 30:ed:a0 88:56:a6 5c:01:3b 44:1d:64 4c:c3:82 78:42:1c
""".split()
RASPBERRY = "b8:27:eb dc:a6:32 e4:5f:01 d8:3a:dd 28:cd:c1 2c:cf:67 3a:35:41".split()
OUI = {**{p: "esp" for p in ESPRESSIF}, **{p: "pi" for p in RASPBERRY}}
KIND = {"esp": ("ESP32 / ESP8266", "📟"), "pi": ("Raspberry Pi", "🍓"), "srv": ("Server με υπηρεσία IoT (π.χ. MQTT broker)", "🖥")}
VIRT = {"bc:24:11": "VM/container Proxmox", "52:54:00": "VM (QEMU/KVM)", "00:16:3e": "VM (Xen)", "08:00:27": "VM (VirtualBox)",
        "00:0c:29": "VM (VMware)", "00:50:56": "VM (VMware)", "00:15:5d": "VM (Hyper-V)", "02:42:ac": "Docker container"}
IOT_PORTS = (1883, 8883, 23)  # αν μια συσκευή ακούει σε αυτές, μάς ενδιαφέρει ό,τι κι αν είναι (π.χ. Mosquitto σε VM)

# θύρα → (όνομα, επίπεδο, τίτλος, εξήγηση, διόρθωση, μάθημα)
PORT_CHECKS = {
    23: ("Telnet", "bad", "Telnet ανοιχτό", "Ό,τι πληκτρολογείς (και ο κωδικός) ταξιδεύει ανοιχτό. Είναι η πόρτα από την οποία μπήκε το Mirai σε εκατομμύρια συσκευές.",
         "Κλείσ' το (sudo systemctl disable --now telnet.socket / βγάλ' το από το firmware) και χρησιμοποίησε SSH με κλειδιά.", "iot-1-2"),
    1883: ("MQTT", "warn", "MQTT χωρίς TLS (1883)", "Μετρήσεις, εντολές ΚΑΙ ο κωδικός του MQTT περνάνε ανοιχτά: όποιος είναι στο Wi‑Fi τα διαβάζει.",
           "Βάλε listener 8883 με TLS και κλείσε το 1883 (ή άφησέ το μόνο στο localhost). Έτοιμα πιστοποιητικά + ρύθμιση: ./tools/mosquitto-tls.sh <IP του broker>", "iot-4-3"),
    80: ("HTTP", "warn", "Σελίδα χωρίς HTTPS (80)", "Η σελίδα ρυθμίσεων/δεδομένων δεν είναι κρυπτογραφημένη· αν έχει login, ο κωδικός φαίνεται.",
         "Βάλε κωδικό και, αν γίνεται, HTTPS — ή κράτα τη σελίδα μόνο σε χωριστό IoT δίκτυο.", "iot-4-6"),
    8080: ("HTTP", "warn", "Σελίδα χωρίς HTTPS (8080)", "Δεύτερη web υπηρεσία χωρίς κρυπτογράφηση.", "Κλείσ' τη αν δεν τη χρειάζεσαι.", "iot-2-5"),
    22: ("SSH", "info", "SSH ανοιχτό", "Είναι κρυπτογραφημένο — αρκεί να μπαίνεις μόνο με κλειδί και να υπάρχει fail2ban.",
         "Στο /etc/ssh/sshd_config: PasswordAuthentication no, PermitRootLogin no.", "iot-2-2"),
    5900: ("VNC", "warn", "VNC (απομακρυσμένη οθόνη)", "Το VNC συχνά έχει αδύναμο ή κανέναν κωδικό και δεν κρυπτογραφεί.",
           "Κλείσ' το ή πέρνα το μέσα από SSH tunnel.", "iot-2-5"),
    445: ("SMB", "warn", "Κοινόχρηστοι φάκελοι (SMB)", "Το Samba ανοιχτό σε όλο το δίκτυο δίνει πρόσβαση σε αρχεία.", "Περιόρισέ το με ufw στις IP που το χρειάζονται.", "iot-2-4"),
    8883: ("MQTTS", "ok", "MQTT με TLS (8883)", "Ο broker δέχεται κρυπτογραφημένες συνδέσεις. 👍", "", "iot-4-3"),
    443: ("HTTPS", "ok", "HTTPS", "Κρυπτογραφημένη web υπηρεσία.", "", "iot-4-6"),
}
PROBE_PORTS = sorted(PORT_CHECKS)


def norm_mac(mac):
    """«8:aa:89:41:26:4» (macOS arp) → «08:aa:89:41:26:04»."""
    parts = str(mac or "").lower().replace("-", ":").split(":")
    if len(parts) != 6 or not all(1 <= len(x) <= 2 for x in parts):
        return None
    try:
        return ":".join(f"{int(x, 16):02x}" for x in parts)
    except ValueError:
        return None


# Γνωστές σοβαρές ευπάθειες ανά έκδοση (ενδεικτικά, offline). Για πλήρη λίστα: κουμπί 🔎 CVE (NVD).
KNOWN_VULNS = {
    "OpenSSH": [((8, 5, 1), (9, 8, 1), "CVE-2024-6387", "regreSSHion: απομακρυσμένη εκτέλεση κώδικα ως root σε Linux/glibc"),
                ((0, 0, 0), (9, 3, 2), "CVE-2023-38408", "εκτέλεση κώδικα μέσω προωθημένου ssh-agent")],
    "Mosquitto": [((0, 0, 0), (2, 0, 16), "CVE-2023-28366", "διαρροή μνήμης → ο broker πέφτει (DoS)"),
                  ((0, 0, 0), (2, 0, 19), "CVE-2024-8376", "κακόβουλος client ρίχνει τον broker (DoS)")],
}


def ver_tuple(v):
    """«8.9p1» → (8, 9, 1) · «2.0.18» → (2, 0, 18)."""
    nums = [int(x) for x in re.findall(r"\d+", v)[:3]]
    return tuple(nums + [0] * (3 - len(nums)))


def versions(open_ports, extra=()):
    """Λογισμικό + έκδοση από τα banners (SSH, HTTP Server) και ό,τι άλλο ξέρουμε (π.χ. έκδοση Mosquitto από το $SYS)."""
    out = []
    for p, b in sorted(open_ports.items()):
        b = b or ""
        m = re.match(r"SSH-[\d.]+-OpenSSH_([\w.]+)(?:\s+(\S+))?", b)
        if m:
            out.append({"product": "OpenSSH", "version": m.group(1), "port": p, "distro": m.group(2)})
            continue
        m = re.search(r"^Server:\s*([A-Za-z][\w.-]*)/(\d[\w.]*)", b, re.M | re.I)
        if m:
            out.append({"product": m.group(1), "version": m.group(2), "port": p, "distro": None})
    out += [dict(x) for x in extra]
    for v in out:
        t = ver_tuple(v["version"])
        v["known"] = [{"id": cve, "why": why} for lo, hi, cve, why in KNOWN_VULNS.get(v["product"], ()) if lo <= t < hi]
    return out


def kind_of(mac=None, names=(), banners=()):
    m = norm_mac(mac)
    if m:
        if int(m[:2], 16) & 2 == 0:  # όχι «τυχαία» (locally administered) MAC
            k = OUI.get(m[:8])
            if k:
                return k
    text = " ".join([*(names or ()), *(banners or ())]).lower()
    if any(w in text for w in ("esp32", "esp8266", "espressif", "esphome", "tasmota", "wled")):
        return "esp"
    if any(w in text for w in ("raspberrypi", "raspbian", "raspberry")):
        return "pi"
    return None


def mqtt_anonymous(ip, port=1883, timeout=2.0):
    """MQTT 3.1.1 CONNECT χωρίς username/password → True αν ο broker δέχεται (CONNACK 0), False αν αρνείται, None αν δεν ξέρουμε."""
    cid = b"netwatch-check"
    var = b"\x00\x04MQTT\x04\x02\x00\x0a"  # protocol name, level 4, clean session, keepalive 10s
    payload = len(cid).to_bytes(2, "big") + cid
    body = var + payload
    pkt = b"\x10" + bytes([len(body)]) + body
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(pkt)
            r = s.recv(4)
            if len(r) >= 4 and r[0] == 0x20:
                ok = r[3] == 0
                if ok:
                    s.sendall(b"\xe0\x00")  # DISCONNECT, ευγενικά
                return ok
    except OSError:
        pass
    return None


def probe(ip, port, timeout=0.8):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                if port in (80, 8080):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                b = s.recv(256)
            except OSError:
                b = b""
            return b.decode("latin-1", "replace")
    except OSError:
        return None


def assess(dev, open_ports, mqtt_anon=None, extra_versions=()):
    """Κανόνες → ευρήματα και βαθμός. Καθαρή συνάρτηση (για tests)."""
    findings, score = [], 100
    vers = versions(open_ports, extra_versions)
    for v in vers:
        if not v["known"]:
            continue
        backport = bool(v.get("distro"))  # π.χ. «Ubuntu-3ubuntu0.10»: οι διανομές μπαλώνουν χωρίς να αλλάζουν τον αριθμό
        lvl = "info" if backport else "warn"
        score -= 0 if backport else 12
        findings.append({"port": v["port"], "service": v["product"], "status": lvl,
                         "title": f"Παλιά έκδοση {v['product']} {v['version']}",
                         "detail": "Γνωστές ευπάθειες: " + "; ".join(f"{k['id']} ({k['why']})" for k in v["known"]) + "." +
                                   (f" Το «{v['distro']}» δείχνει πακέτο διανομής, που συχνά έχει ήδη τη διόρθωση — αν κάνεις τακτικά ενημερώσεις, μάλλον είσαι εντάξει."
                                    if backport else ""),
                         "fix": "sudo apt update && sudo apt full-upgrade (ή νεότερο firmware/image).", "lesson": "iot-2-3", "banner": ""})
    pen = {"bad": 35, "warn": 12, "info": 0, "ok": 0}
    for p in sorted(open_ports):
        if p not in PORT_CHECKS:
            continue
        name, lvl, title, why, fix, lesson = PORT_CHECKS[p]
        banner = open_ports[p] or ""
        if p == 1883 and mqtt_anon:
            lvl, title = "bad", "MQTT ανοιχτό σε ΟΛΟΥΣ (χωρίς κωδικό, χωρίς TLS)"
            why = "Ο broker δέχτηκε σύνδεση χωρίς username/password. Οποιοσδήποτε στο δίκτυο διαβάζει τις μετρήσεις σου και στέλνει εντολές (π.χ. ανοίγει το relay)."
            fix, lesson = "mosquitto.conf: allow_anonymous false + password_file + acl_file, και listener 8883 με TLS.", "iot-4-2"
        elif p == 1883 and mqtt_anon is False:
            why += " (Ζητάει κωδικό — καλό, αλλά ο κωδικός περνάει ανοιχτός.)"
        if p in (80, 8080) and " 401 " in banner[:20]:
            why += " Ζητάει κωδικό (HTTP Basic) — που όμως ταξιδεύει χωρίς κρυπτογράφηση."
        score -= pen[lvl]
        findings.append({"port": p, "service": name, "status": lvl, "title": title, "detail": why, "fix": fix,
                         "lesson": lesson, "banner": banner.strip()[:80]})
    if not any(f["status"] in ("bad", "warn") for f in findings):
        findings.append({"port": None, "service": "", "status": "ok", "title": "Καμία ανοιχτή «επικίνδυνη» πόρτα",
                         "detail": "Από το δίκτυο δεν φαίνεται κάτι εύκολο για επιτιθέμενο.",
                         "fix": "", "lesson": "iot-7-1" if dev["kind"] == "esp" else "iot-2-4", "banner": ""})
    # γενικές συμβουλές που δεν φαίνονται από το δίκτυο
    tips = (["Secure Boot & Flash Encryption: όποιος πιάσει την πλακέτα διαβάζει τον Wi‑Fi κωδικό από τη flash αν δεν είναι κρυπτογραφημένη (iot-5-2).",
             "Βάλ' το σε χωριστό IoT δίκτυο/SSID, ώστε αν πέσει να μη βλέπει τον υπολογιστή σου (iot-7-1).",
             "OTA: αν χρησιμοποιείς ArduinoOTA, βάλε κωδικό — ή καλύτερα υπογεγραμμένο HTTPS OTA (iot-5-3). (Το ArduinoOTA ακούει σε UDP, δεν φαίνεται σε αυτόν τον έλεγχο.)"] if dev["kind"] == "esp" else
            ["Αυτόματες ενημερώσεις (unattended-upgrades) και fail2ban (iot-2-3, iot-2-5).",
             "Firewall ufw: άφησε ανοιχτό μόνο ό,τι χρειάζεσαι (iot-2-4)."] +
            (["Broker: κάθε συσκευή με δικό της χρήστη και ACL μόνο στα δικά της topics (iot-4-2)."] if dev["kind"] == "srv" else []))
    lvl = "bad" if any(f["status"] == "bad" for f in findings) else "warn" if any(f["status"] == "warn" for f in findings) else "ok"
    return {**dev, "findings": findings, "score": max(0, score), "level": lvl, "tips": tips, "versions": vers}


def arp_table():
    """ip → mac από τον πίνακα ARP του συστήματος (macOS/Linux)."""
    import re
    import subprocess
    try:
        out = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return {}
    return {ip: norm_mac(mac) for ip, mac in re.findall(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)", out) if norm_mac(mac)}


def sweep_targets(my_ips):
    """Οι διευθύνσεις του δικού σου /24 (μόνο ιδιωτικά δίκτυα), για να βρούμε brokers/Telnet που δεν έχουν «μιλήσει» ακόμα."""
    out = []
    for ip in sorted(my_ips or ()):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.version == 4 and a.is_private and not a.is_loopback and not a.is_link_local:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            out += [str(h) for h in net.hosts() if str(h) != ip]
    return list(dict.fromkeys(out))


def _same_host(host, ip):
    if host == ip:
        return True
    try:
        return socket.gethostbyname(host) == ip
    except OSError:
        return False


class IotCheck:
    def __init__(self, devices, sim=False, my_ips=None, broker=None):
        self.devices, self.sim = devices, sim  # devices() → [{ip, mac, names}]
        self.broker = broker or (lambda: (None, None))  # → (host, «mosquitto version 2.0.18») από τον φύλακα MQTT
        self.my_ips = my_ips or (lambda: ())
        self.lock = threading.Lock()
        self.running, self.result, self.t = False, None, 0

    def status(self):
        with self.lock:
            known = [{"ip": d["ip"], "mac": d.get("mac"), "kind": d["kind"], "name": d.get("name")} for d in self.find()]
            return {"running": self.running, "result": self.result, "t": self.t, "found": known, "demo": self.sim,
                    "kinds": {k: list(v) for k, v in KIND.items()}}

    def find(self):
        out, seen = [], set()
        for d in self.devices():
            k = kind_of(d.get("mac"), d.get("names") or ())
            if k:
                seen.add(d["ip"])
                out.append({"ip": d["ip"], "mac": norm_mac(d.get("mac")), "kind": k, "name": (d.get("names") or [None])[0]})
        for d in (self.result or []):  # ό,τι βρήκε η προηγούμενη σάρωση (π.χ. broker σε VM)
            if d["ip"] not in seen:
                seen.add(d["ip"])
                out.append({k: d.get(k) for k in ("ip", "mac", "kind", "name")})
        return out

    def start(self, extra_ips=()):
        with self.lock:
            if self.running:
                return
            self.running = True
        threading.Thread(target=self._run, args=(list(extra_ips),), daemon=True).start()

    def _run(self, extra):
        try:
            devs = self.find()
            if not self.sim:
                devs += self._discover({d["ip"] for d in devs} | set(extra))
            for ip in extra:  # συσκευές που ο χρήστης δηλώνει «δικές μου» αν δεν αναγνωρίστηκαν
                ipaddress.ip_address(ip)
                if not any(d["ip"] == ip for d in devs):
                    mac = arp_table().get(ip)
                    devs.append({"ip": ip, "mac": mac, "kind": kind_of(mac) or "srv", "name": "(χειροκίνητα)"})
            res = self._demo(devs) if self.sim else self._real(devs)
            with self.lock:
                self.result, self.t = res, time.time()
        finally:
            with self.lock:
                self.running = False

    def _discover(self, skip):
        """Σαρώνει ελαφριά (μόνο TCP connect) το δικό σου /24 στις θύρες MQTT/Telnet. Ό,τι απαντήσει μπαίνει στον έλεγχο."""
        known = {d["ip"]: d for d in self.devices()}
        targets = [ip for ip in list(dict.fromkeys([*known, *sweep_targets(self.my_ips())])) if ip not in skip]
        with ThreadPoolExecutor(64) as ex:
            hits = [ip for ip, ok in zip(targets, ex.map(lambda ip: any(probe(ip, p, 0.6) is not None for p in IOT_PORTS), targets)) if ok]
        arp = arp_table()
        hits += [ip for ip, mac in arp.items() if ip not in skip and ip not in hits and kind_of(mac)  # ESP/Pi που ξέρει το ARP
                 and ipaddress.ip_address(ip).is_private]
        out = []
        for ip in hits:
            d = known.get(ip, {})
            mac = norm_mac(d.get("mac")) or arp.get(ip)
            names = d.get("names") or []
            k = kind_of(mac, names) or "srv"
            name = names[0] if names else (VIRT.get(mac[:8]) if mac else None)
            out.append({"ip": ip, "mac": mac, "kind": k, "name": name})
        return out

    def _real(self, devs):
        res = []
        with ThreadPoolExecutor(32) as ex:
            for d in devs:
                if not ipaddress.ip_address(d["ip"]).is_private:
                    continue
                banners = dict(zip(PROBE_PORTS, ex.map(lambda p: probe(d["ip"], p), PROBE_PORTS)))
                open_ = {p: b for p, b in banners.items() if b is not None}
                anon = mqtt_anonymous(d["ip"]) if 1883 in open_ else None
                host, bver = self.broker()
                m = re.search(r"mosquitto version ([\d.]+)", bver or "")
                extra = [{"product": "Mosquitto", "version": m.group(1), "port": 8883 if 8883 in open_ else 1883, "distro": None}] \
                    if m and host and _same_host(host, d["ip"]) else []
                res.append(assess(d, open_, anon, extra))
        return res

    def _demo(self, devs):
        if not devs:
            devs = [{"ip": "192.168.1.60", "mac": "24:0a:c4:12:34:56", "kind": "esp", "name": "esp32-garden"},
                    {"ip": "192.168.1.70", "mac": "dc:a6:32:ab:cd:ef", "kind": "pi", "name": "raspberrypi.local"}]
        out = []
        for d in devs:
            if d["kind"] == "pi":
                out.append(assess(d, {22: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", 1883: "", 8883: "", 23: ""}, True,
                                  [{"product": "Mosquitto", "version": "2.0.11", "port": 1883, "distro": None}]))
            else:
                out.append(assess(d, {80: "HTTP/1.1 200 OK\r\nServer: arduino-esp32"}))
        return out
