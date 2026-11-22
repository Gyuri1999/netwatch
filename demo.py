"""NetWatch — Demo: προσομοίωση κίνησης και επιθέσεων (χωρίς root)."""
import hashlib
import ipaddress
import os
import random
import re
import threading
import time

from core import log


# ---------------- demo / simulation ----------------
DEMO_REMOTE = [
    ("142.250.184.110", "www.google.com", "United States", "US", "Mountain View", 37.42, -122.08, "Google LLC", "AS15169 Google LLC", 30),
    ("157.240.9.35", "graph.facebook.com", "Ireland", "IE", "Dublin", 53.34, -6.26, "Meta Platforms", "AS32934 Facebook, Inc.", 10),
    ("104.16.132.229", "cdnjs.cloudflare.com", "Germany", "DE", "Frankfurt", 50.11, 8.68, "Cloudflare, Inc.", "AS13335 Cloudflare, Inc.", 12),
    ("52.94.236.248", "s3.eu-central-1.amazonaws.com", "Germany", "DE", "Frankfurt", 50.11, 8.68, "Amazon.com", "AS16509 Amazon.com, Inc.", 8),
    ("13.107.42.14", "outlook.office.com", "Netherlands", "NL", "Amsterdam", 52.37, 4.89, "Microsoft Corporation", "AS8075 Microsoft Corporation", 8),
    ("45.57.90.1", "ipv4-c001-ath001.nflxvideo.net", "Greece", "GR", "Athens", 37.98, 23.73, "Netflix Streaming Services", "AS2906 Netflix", 40),
    ("151.101.1.140", "www.reddit.com", "United States", "US", "San Francisco", 37.77, -122.42, "Fastly", "AS54113 Fastly", 5),
    ("140.82.121.4", "github.com", "Germany", "DE", "Frankfurt", 50.11, 8.68, "GitHub, Inc.", "AS36459 GitHub, Inc.", 5),
    ("17.253.53.207", "swcdn.apple.com", "Sweden", "SE", "Stockholm", 59.33, 18.06, "Apple Inc.", "AS714 Apple Inc.", 6),
    ("91.198.174.192", "el.wikipedia.org", "Netherlands", "NL", "Amsterdam", 52.37, 4.89, "Wikimedia Foundation", "AS14907 Wikimedia", 3),
    ("193.92.150.3", "dns.otenet.gr", "Greece", "GR", "Athens", 37.98, 23.73, "OTEnet S.A.", "AS6799 OTEnet S.A.", 4),
    ("23.32.29.18", "a248.e.akamai.net", "Japan", "JP", "Tokyo", 35.68, 139.69, "Akamai Technologies", "AS20940 Akamai", 3),
    ("200.147.67.142", "www.uol.com.br", "Brazil", "BR", "São Paulo", -23.55, -46.63, "UOL", "AS7162 Universo Online", 1),
    ("1.1.1.1", "one.one.one.one", "Australia", "AU", "Sydney", -33.87, 151.21, "Cloudflare, Inc.", "AS13335 Cloudflare, Inc.", 2),
    ("35.186.224.25", "spclient.wg.spotify.com", "United States", "US", "Council Bluffs", 41.26, -95.86, "Google Cloud", "AS15169 Google LLC", 6),
    ("41.63.64.10", "cdn.example.za", "South Africa", "ZA", "Johannesburg", -26.2, 28.04, "Demo Telecom", "AS0000 Demo", 1),
    # trackers (για την καρτέλα 📡 Trackers): διαφημίσεις / analytics / τηλεμετρία
    ("142.250.185.68", "doubleclick.net", "United States", "US", "Mountain View", 37.42, -122.08, "Google LLC", "AS15169 Google LLC", 14),
    ("142.251.1.157", "app-measurement.com", "United States", "US", "Mountain View", 37.42, -122.08, "Google LLC", "AS15169 Google LLC", 9),
    ("34.120.195.249", "crashlytics.com", "United States", "US", "Council Bluffs", 41.26, -95.86, "Google Cloud", "AS15169 Google LLC", 5),
    ("35.201.97.85", "app.adjust.com", "United States", "US", "Ashburn", 39.04, -77.49, "Google Cloud", "AS15169 Google LLC", 4),
]


def demo_attackers():
    def rip(a):
        return f"{a}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return [
        (rip(185), "Russia", "RU", "Moscow", 55.75, 37.62, "DemoBulletproof LLC (demo)", "AS64501 DEMO-BP", True, True),
        (rip(61), "China", "CN", "Nanjing", 32.06, 118.78, "DemoNet Backbone (demo)", "AS64502 DEMO-CN", False, True),
        (rip(103), "Vietnam", "VN", "Hanoi", 21.03, 105.85, "Demo VPS (demo)", "AS64503 DEMO-VPS", True, True),
        (rip(45), "Netherlands", "NL", "Amsterdam", 52.37, 4.89, "Scanner Inc (demo)", "AS64504 DEMO-SCAN", False, True),
    ]


DEMO_SCAN = {  # «αποτελέσματα» σάρωσης για το demo (ρεαλιστικά banners γνωστών συσκευών)
    "192.168.1.1": ("a4:2b:b0:11:22:01", [
        (22, "SSH-2.0-dropbear_2017.75"), (53, ""), (80, "HTTP/1.0 200 OK\r\nServer: mini_httpd/1.19 19dec2003"),
        (443, ""), (7547, "HTTP/1.1 401 Unauthorized\r\nServer: RomPager/4.07 UPnP/1.0")]),
    "192.168.1.23": ("3c:22:fb:aa:bb:23", [(22, "SSH-2.0-OpenSSH_9.6"), (5000, "HTTP/1.1 403 Forbidden\r\nServer: AirTunes/775.3.1")]),
    "192.168.1.10": ("f0:de:f1:10:10:10", [(8008, "HTTP/1.1 404 Not Found"), (8009, ""), (9000, "")]),
    "192.168.1.15": ("ac:1f:74:15:15:15", [(62078, "")]),
    "192.168.1.30": ("c0:56:e3:30:30:30", [(23, "\xff\xfd\x01BusyBox v1.19.4 built-in shell\r\nipcam login:"),
                                           (80, "HTTP/1.0 200 OK\r\nServer: GoAhead-Webs"), (554, "RTSP/1.0 200 OK")]),
    "192.168.1.40": ("00:1e:0b:40:40:40", [(21, "220 (vsFTPd 2.3.4)"), (80, "HTTP/1.1 200 OK\r\nServer: Apache/2.2.15"),
                                           (445, ""), (631, ""), (9100, "")]),
    "192.168.1.77": ("de:ad:be:ef:77:77", [(22, "SSH-2.0-OpenSSH_7.4"), (3389, ""), (4444, "")]),
}

DEMO_SVCFIND = {  # 🔎 demo: ευρήματα ασφαλούς απαρίθμησης (SMB/RDP)
    ("192.168.1.40", 445): [("high", "SMBv1 ενεργό — το παλιό πρωτόκολλο του WannaCry/EternalBlue. Κλείσ' το "
                                     "(Windows: «SMB 1.0/CIFS» · NAS: ρυθμίσεις SMB → ελάχιστο SMBv2).")],
    ("192.168.1.77", 3389): [("med", "Το RDP δέχεται «standard RDP security» χωρίς NLA — ευάλωτο σε BlueKeep και σε δοκιμές "
                                     "κωδικών. Ενεργοποίησε το «Network Level Authentication» στις ρυθμίσεις απομακρυσμένης επιφάνειας.")],
}
DEMO_TLS = {("192.168.1.1", 443): {"version": "TLSv1", "subject": "CN=router.home", "issuer": "CN=router.home",
                                   "not_after": "Jan  1 00:00:00 2021 GMT", "days_left": -2100,
                                   "findings": [("high", "Παλιό πρωτόκολλο TLSv1 — σπασμένο, πρέπει TLS 1.2+"),
                                                ("med", "Το πιστοποιητικό έληξε πριν 2100 μέρες"),
                                                ("low", "Self-signed πιστοποιητικό — ο browser δεν μπορεί να ελέγξει "
                                                        "ότι μιλάς με τη σωστή συσκευή (κίνδυνος MITM)")]}}
DEMO_SHODAN = {"ip": "79.130.12.34", "ports": [80, 443, 7547], "hostnames": ["ppp079130012034.access.demo-isp.example"],
               "tags": ["router"], "cpes": ["cpe:/a:allegrosoft:rompager:4.07"],
               "vulns": ["CVE-2014-9222", "CVE-2014-9223"], "demo": True}


def demo_scan(set_state):
    import pentest
    hosts = []
    ips = sorted(DEMO_SCAN, key=ipaddress.ip_address)
    for i, ip in enumerate(ips):
        set_state(phase=f"σάρωση {ip}", progress=int(100 * i / len(ips)))
        time.sleep(0.6)
        mac, ports = DEMO_SCAN[ip]
        svcs = []
        for p, banner in ports:
            prod, ver = pentest.parse_banner(banner)
            sv = {"port": p, "banner": banner, "product": prod, "version": ver}
            if (ip, p) in DEMO_TLS:
                sv["tls"] = DEMO_TLS[(ip, p)]
            if (ip, p) in DEMO_SVCFIND:
                sv["findings"] = list(DEMO_SVCFIND[(ip, p)])
            svcs.append(sv)
        hosts.append({"ip": ip, "mac": mac, "services": svcs})
    return hosts


def demo_run(state):
    me, gw = "192.168.1.23", "192.168.1.1"
    lan = {"192.168.1.10": "smart-tv.local", "192.168.1.15": "iphone.local",
           "192.168.1.40": "printer.local", "192.168.1.77": "unknown-laptop.local", "192.168.1.30": "ipcam.local"}
    macs = {gw: "a4:2b:b0:11:22:01", me: "3c:22:fb:aa:bb:23", "192.168.1.10": "f0:de:f1:10:10:10",
            "192.168.1.15": "ac:1f:74:15:15:15", "192.168.1.40": "00:1e:0b:40:40:40",
            "192.168.1.77": "de:ad:be:ef:77:77", "192.168.1.30": "c0:56:e3:30:30:30"}
    def seed():
        state.arp_table.update(macs)
        state.arp_first.update(macs)
        for ip, m in macs.items():
            state.mac_ips[m].add(ip)
    seed()
    state.demo_seed = seed
    state.home = {"status": "success", "query": "79.130.12.34", "country": "Greece", "countryCode": "GR",
                  "city": "Athens", "regionName": "Attica", "lat": 37.98, "lon": 23.73,
                  "isp": "Demo ISP", "org": "Demo ISP", "as": "AS6799 (demo)"}
    for ip, name, c, cc, city, lat, lon, isp, asn, _ in DEMO_REMOTE:
        state.demo_geo[ip] = ({"country": c, "countryCode": cc, "city": city, "regionName": "", "lat": lat,
                               "lon": lon, "isp": isp, "org": isp, "as": asn, "proxy": False,
                               "hosting": True, "mobile": False, "query": ip}, name)
        state.domains[ip].add(name)
    attackers = demo_attackers()
    for ip, c, cc, city, lat, lon, isp, asn, proxy, hosting in attackers:
        state.demo_geo[ip] = ({"country": c, "countryCode": cc, "city": city, "regionName": "", "lat": lat,
                               "lon": lon, "isp": isp, "org": isp, "as": asn, "proxy": proxy,
                               "hosting": hosting, "mobile": False, "query": ip}, None)
    for ip, n in lan.items():
        state.demo_geo[ip] = (None, n)
    state.demo_geo[gw] = (None, "router.home")
    weights = [r[-1] for r in DEMO_REMOTE]
    # threat intel (demo): ο «ρώσος» επιτιθέμενος σε blocklist + ένας C2 server που «καλεί» το laptop
    c2 = f"91.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    state.demo_geo[c2] = ({"country": "Romania", "countryCode": "RO", "city": "Bucharest", "regionName": "",
                           "lat": 44.43, "lon": 26.10, "isp": "Bulletproof C2 Hosting (demo)", "org": "(demo)",
                           "as": "AS64505 DEMO-C2", "proxy": False, "hosting": True, "mobile": False, "query": c2},
                          None)
    state.intel.add(attackers[0][0] + "/32", "Demo blocklist (demo)", "block")
    state.intel.add(c2 + "/32", "Feodo Tracker (demo)", "c2")
    state.intel.loaded = True
    ja3 = {ip: hashlib.md5(f"demo-{ip}".encode()).hexdigest() for ip in [me] + list(lan)}
    newdev, newdev_mac = "192.168.1.99", "da:7c:31:99:99:99"
    state.cfg["thresholds"]["new_device"]["warmup"] = 30

    def emit(**P):
        if state.feed != "demo":
            return
        P.setdefault("t", time.time())
        P.setdefault("len", random.randint(60, 1500))
        state.process(P)

    def background():
        while True:
            r = random.choices(DEMO_REMOTE, weights)[0]
            port = random.choice([443, 443, 443, 80, 443]) if r[0] != "193.92.150.3" else 53
            sp = random.randint(49152, 65000)
            client = me if random.random() < 0.8 else random.choice(list(lan))
            if port == 53:
                emit(src=client, dst=r[0], proto="UDP", sp=sp, dp=53, len=80)
                pick = random.choice(DEMO_REMOTE)
                emit(src=r[0], dst=client, proto="UDP", sp=53, dp=sp, len=140, dns=[(pick[1], pick[0])])
            elif random.random() < 0.25 and port == 443:
                emit(src=client, dst=r[0], proto="UDP", sp=sp, dp=443, len=1250)
                emit(src=r[0], dst=client, proto="UDP", sp=443, dp=sp, len=1350)
            else:
                emit(src=client, dst=r[0], proto="TCP", sp=sp, dp=port, flags="PA", len=random.randint(80, 600),
                     sni=r[1] if port == 443 else None, http_host=r[1] if port == 80 else None,
                     ja3=ja3.get(client) if port == 443 else None)
                for _ in range(random.randint(1, 3)):
                    emit(src=r[0], dst=client, proto="TCP", sp=port, dp=sp, flags="A", len=random.randint(800, 1500))
            if random.random() < 0.08:
                dev = random.choice(list(lan))
                emit(src=dev, dst="224.0.0.251", proto="UDP", sp=5353, dp=5353, len=180, smac=macs[dev])
            if random.random() < 0.04:
                dev = random.choice(list(lan))
                emit(src=dev, dst="239.255.255.250", proto="UDP", sp=50000, dp=1900, len=300, smac=macs[dev])
            if random.random() < 0.03:
                a, b = random.sample(list(lan) + [me, gw], 2)
                emit(src=a, dst=b, proto="ARP", len=42, arp=dict(op=1, psrc=a, pdst=b, hwsrc=macs[a]))
                emit(src=b, dst=a, proto="ARP", len=42, arp=dict(op=2, psrc=b, pdst=a, hwsrc=macs[b]))
            if random.random() < 0.05:
                emit(src="192.168.1.10", dst="192.168.1.40", proto="TCP", sp=51000, dp=9100, flags="PA", len=900)
            if random.random() < 0.02:  # υπηρεσίες που «ακούν» στις συσκευές του LAN (για τον έλεγχο 🛡)
                dev, port = random.choice([(gw, 80), (gw, 53), ("192.168.1.40", 9100), ("192.168.1.40", 21),
                                           ("192.168.1.30", 23), ("192.168.1.30", 554), ("192.168.1.10", 8008)])
                csp = random.randint(49152, 65000)
                emit(src=me, dst=dev, proto="TCP", sp=csp, dp=port, flags="S", len=60)
                emit(src=dev, dst=me, proto="TCP", sp=port, dp=csp, flags="SA", len=60, smac=macs[dev])
            if random.random() < 0.01:
                emit(src=gw, dst="239.255.255.250", proto="UDP", sp=1900, dp=1900, len=320, smac=macs[gw])
            time.sleep(random.uniform(0.008, 0.03))

    def beacon():
        # το «παραβιασμένο» laptop καλεί τον C2 κάθε 6 δευτερόλεπτα με ακρίβεια ρολογιού
        time.sleep(20)
        while True:
            sp = random.randint(49152, 65000)
            emit(src="192.168.1.77", dst=c2, proto="TCP", sp=sp, dp=8443, flags="S", len=60)
            emit(src=c2, dst="192.168.1.77", proto="TCP", sp=8443, dp=sp, flags="SA", len=60)
            emit(src="192.168.1.77", dst=c2, proto="TCP", sp=sp, dp=8443, flags="PA", len=220)
            time.sleep(6 + random.uniform(-0.2, 0.2))

    def rnd_label(n, alphabet="bcdfghjklmnpqrstvwxz0123456789"):
        return "".join(random.choice(alphabet) for _ in range(n))

    def scenarios():
        time.sleep(8)
        i = 0
        order = ["portscan", "cleartext", "dga", "arpspoof", "newdev", "brute", "dnstunnel", "xmas", "synflood",
                 "arpsweep", "dhcp", "pingsweep"]
        while True:
            kind = order[i % len(order)]
            i += 1
            log(f"(demo) σενάριο επίθεσης: {kind}")
            A = attackers[i % len(attackers)][0]
            if kind == "portscan":
                for p in random.sample(range(1, 10000), 45):
                    emit(src=A, dst=me, proto="TCP", sp=random.randint(40000, 60000), dp=p, flags="S", len=60)
                    emit(src=me, dst=A, proto="TCP", sp=p, dp=40000, flags="RA", len=54)
                    time.sleep(0.07)
            elif kind == "brute":
                for _ in range(25):
                    sp = random.randint(40000, 60000)
                    emit(src=A, dst=me, proto="TCP", sp=sp, dp=22, flags="S", len=60)
                    emit(src=me, dst=A, proto="TCP", sp=22, dp=sp, flags="SA", len=60)
                    emit(src=A, dst=me, proto="TCP", sp=sp, dp=22, flags="PA", len=300)
                    time.sleep(0.25)
            elif kind == "arpspoof":
                for _ in range(12):
                    emit(src=gw, dst=me, proto="ARP", len=42, smac=macs["192.168.1.77"],
                         arp=dict(op=2, psrc=gw, pdst=me, hwsrc=macs["192.168.1.77"]))
                    time.sleep(0.4)
                emit(src=gw, dst=me, proto="ARP", len=42, arp=dict(op=2, psrc=gw, pdst=me, hwsrc=macs[gw]))
            elif kind == "xmas":
                for p in (21, 22, 80, 443, 3389):
                    emit(src=A, dst=me, proto="TCP", sp=41000, dp=p, flags="FPU", len=60)
                    time.sleep(0.2)
            elif kind == "synflood":
                srcs = [a[0] for a in attackers]
                for _ in range(380):
                    emit(src=random.choice(srcs), dst=me, proto="TCP", sp=random.randint(1024, 65000), dp=443,
                         flags="S", len=60)
                    time.sleep(0.008)
            elif kind == "arpsweep":
                for n in range(2, 80):
                    emit(src="192.168.1.77", dst=f"192.168.1.{n}", proto="ARP", len=42,
                         arp=dict(op=1, psrc="192.168.1.77", pdst=f"192.168.1.{n}", hwsrc=macs["192.168.1.77"]))
                    time.sleep(0.04)
            elif kind == "dhcp":
                emit(src="192.168.1.77", dst="255.255.255.255", proto="UDP", sp=67, dp=68, len=342)
            elif kind == "dga":  # η «μολυσμένη» smart TV ψάχνει τον C2 της σε τυχαία domains
                for _ in range(12):
                    name = rnd_label(random.randint(10, 14)) + random.choice([".com", ".net", ".biz", ".info"])
                    sp = random.randint(40000, 60000)
                    emit(src="192.168.1.10", dst=gw, proto="UDP", sp=sp, dp=53, len=80, dns_q=(name, 1),
                         smac=macs["192.168.1.10"])
                    emit(src=gw, dst="192.168.1.10", proto="UDP", sp=53, dp=sp, len=140, nx=name)
                    time.sleep(0.3)
            elif kind == "dnstunnel":  # το laptop «βγάζει» δεδομένα μέσα σε ερωτήματα DNS
                for _ in range(36):
                    sub = rnd_label(30, "0123456789abcdef") + "." + rnd_label(8, "0123456789abcdef")
                    sp = random.randint(40000, 60000)
                    emit(src="192.168.1.77", dst=gw, proto="UDP", sp=sp, dp=53, len=160,
                         dns_q=(f"{sub}.exfil-demo.example", 16))
                    time.sleep(0.12)
            elif kind == "newdev":  # άγνωστο κινητό μπαίνει στο Wi-Fi
                for _ in range(3):
                    emit(src=newdev, dst="224.0.0.251", proto="UDP", sp=5353, dp=5353, len=180, smac=newdev_mac)
                    emit(src=newdev, dst=gw, proto="ARP", len=42,
                         arp=dict(op=1, psrc=newdev, pdst=gw, hwsrc=newdev_mac))
                    time.sleep(0.5)
            elif kind == "cleartext":  # login χωρίς κρυπτογράφηση: FTP στον εκτυπωτή, φόρμα HTTP στον router
                sp = random.randint(49152, 65000)
                emit(src=me, dst="192.168.1.40", proto="TCP", sp=sp, dp=21, flags="PA", len=70,
                     cred={"proto": "FTP", "field": "user", "user": "scanner"})
                time.sleep(0.3)
                emit(src=me, dst="192.168.1.40", proto="TCP", sp=sp, dp=21, flags="PA", len=70,
                     cred={"proto": "FTP", "field": "pass"})
                time.sleep(1)
                emit(src="192.168.1.15", dst=gw, proto="TCP", sp=random.randint(49152, 65000), dp=80, flags="PA",
                     len=520, http_host="router.home", cred={"proto": "HTTP φόρμα", "field": "pass", "user": "admin"})
            elif kind == "pingsweep":
                for n in range(1, 50):
                    emit(src=A, dst=f"192.168.1.{n}", proto="ICMP", icmp_type=8, len=98)
                    time.sleep(0.05)
            time.sleep(random.uniform(14, 22))

    threading.Thread(target=background, daemon=True).start()
    threading.Thread(target=scenarios, daemon=True).start()
    threading.Thread(target=beacon, daemon=True).start()
