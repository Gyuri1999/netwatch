#!/usr/bin/env python3
"""Φτιάχνει ένα συνθετικό pcap με κανονική κίνηση + ένα σενάριο επίθεσης μέσα στο LAN.

Σενάριο: ένα «παραβιασμένο» laptop (192.168.1.66) στο ίδιο Wi-Fi
  1. χαρτογραφεί το δίκτυο (ARP sweep)
  2. σκανάρει τις θύρες του θύματος (SYN scan + XMAS scan)
  3. δοκιμάζει κωδικούς στο SSH (brute force)
  4. κάνει ARP spoofing στον router (Man-in-the-Middle)
  5. στήνει ψεύτικο DHCP server και ψεύτικες απαντήσεις DNS
  6. κάνει SYN flood
  7. «βγάζει» δεδομένα μέσω DNS tunneling και ψάχνει C2 με DGA domains
  8. λίγο αργότερα συνδέεται και μια άγνωστη συσκευή στο Wi-Fi

Χρήση:  python tools/make_sample_pcap.py samples/lan-attack.pcap
"""
import random
import struct
import sys

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, BOOTP, Ether, Raw, wrpcap

ME, ME_MAC = "192.168.1.50", "3c:22:fb:00:00:50"
GW, GW_MAC = "192.168.1.1", "a4:2b:b0:00:00:01"
EVIL, EVIL_MAC = "192.168.1.66", "de:ad:be:ef:00:66"
TV, TV_MAC = "192.168.1.20", "f0:de:f1:00:00:20"
NEW, NEW_MAC = "192.168.1.88", "6a:3e:51:00:00:88"
SITES = [  # (ip, domain) — δημόσιοι προορισμοί για «κανονική» κίνηση
    ("142.250.184.110", "www.google.com"), ("157.240.9.35", "www.facebook.com"),
    ("140.82.121.4", "github.com"), ("104.16.132.229", "cdnjs.cloudflare.com"),
    ("13.107.42.14", "outlook.office.com"), ("91.198.174.192", "el.wikipedia.org"),
]


def client_hello(sni):
    """Ελάχιστο TLS ClientHello με επέκταση SNI (αρκετό για τον parser)."""
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(sni_ext)) + sni_ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def build(path, seed=7):
    rnd = random.Random(seed)
    pkts, t = [], 1_700_000_000.0

    def add(p, dt=0.01):
        nonlocal t
        t += dt
        p.time = t
        pkts.append(p)

    def e(src_mac, dst_mac="ff:ff:ff:ff:ff:ff"):
        return Ether(src=src_mac, dst=dst_mac)

    # --- κανονική κίνηση: ARP, DNS, HTTPS ---
    add(e(ME_MAC) / ARP(op=1, psrc=ME, pdst=GW, hwsrc=ME_MAC))
    add(e(GW_MAC, ME_MAC) / ARP(op=2, psrc=GW, pdst=ME, hwsrc=GW_MAC, hwdst=ME_MAC))
    add(e(EVIL_MAC, GW_MAC) / ARP(op=2, psrc=EVIL, pdst=GW, hwsrc=EVIL_MAC))
    add(e(TV_MAC) / IP(src=TV, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / Raw(b"\x00" * 40))
    for rnd_i in range(3):
        for ip, dom in SITES:
            sp = rnd.randint(49152, 65000)
            add(e(ME_MAC, GW_MAC) / IP(src=ME, dst=GW) / UDP(sport=sp, dport=53) / DNS(rd=1, qd=DNSQR(qname=dom)))
            add(e(GW_MAC, ME_MAC) / IP(src=GW, dst=ME) / UDP(sport=53, dport=sp) /
                DNS(qr=1, qd=DNSQR(qname=dom), an=DNSRR(rrname=dom, rdata=ip)), 0.02)
            cp = rnd.randint(49152, 65000)
            add(e(ME_MAC, GW_MAC) / IP(src=ME, dst=ip) / TCP(sport=cp, dport=443, flags="S"))
            add(e(GW_MAC, ME_MAC) / IP(src=ip, dst=ME) / TCP(sport=443, dport=cp, flags="SA"), 0.03)
            add(e(ME_MAC, GW_MAC) / IP(src=ME, dst=ip) / TCP(sport=cp, dport=443, flags="A"))
            add(e(ME_MAC, GW_MAC) / IP(src=ME, dst=ip) / TCP(sport=cp, dport=443, flags="PA") / Raw(client_hello(dom)))
            for _ in range(rnd.randint(3, 8)):
                add(e(GW_MAC, ME_MAC) / IP(src=ip, dst=ME) / TCP(sport=443, dport=cp, flags="A") / Raw(bytes(1200)), 0.005)
        t += 2

    # --- 1. ARP sweep ---
    for n in range(2, 60):
        add(e(EVIL_MAC) / ARP(op=1, psrc=EVIL, pdst=f"192.168.1.{n}", hwsrc=EVIL_MAC), 0.02)
    # --- 2. SYN scan + XMAS scan προς το θύμα ---
    for port in rnd.sample(range(1, 1024), 40):
        add(e(EVIL_MAC, ME_MAC) / IP(src=EVIL, dst=ME) / TCP(sport=44444, dport=port, flags="S"), 0.01)
        add(e(ME_MAC, EVIL_MAC) / IP(src=ME, dst=EVIL) / TCP(sport=port, dport=44444, flags="RA"), 0.001)
    for port in (22, 80, 443):
        add(e(EVIL_MAC, ME_MAC) / IP(src=EVIL, dst=ME) / TCP(sport=44445, dport=port, flags="FPU"), 0.05)
    # --- 3. SSH brute force ---
    for _ in range(20):
        sp = rnd.randint(40000, 60000)
        add(e(EVIL_MAC, ME_MAC) / IP(src=EVIL, dst=ME) / TCP(sport=sp, dport=22, flags="S"), 0.3)
        add(e(ME_MAC, EVIL_MAC) / IP(src=ME, dst=EVIL) / TCP(sport=22, dport=sp, flags="SA"), 0.01)
        add(e(EVIL_MAC, ME_MAC) / IP(src=EVIL, dst=ME) / TCP(sport=sp, dport=22, flags="PA") / Raw(b"SSH-2.0-libssh\r\n"), 0.01)
    # --- 4. ARP spoofing: «εγώ είμαι ο router» ---
    for _ in range(8):
        add(e(EVIL_MAC, ME_MAC) / ARP(op=2, psrc=GW, pdst=ME, hwsrc=EVIL_MAC, hwdst=ME_MAC), 0.5)
    # --- 5. ψεύτικος DHCP + ψεύτικη απάντηση DNS ---
    add(e(EVIL_MAC) / IP(src=EVIL, dst="255.255.255.255") / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr="192.168.1.120"), 0.2)
    add(e(ME_MAC, GW_MAC) / IP(src=ME, dst=GW) / UDP(sport=50123, dport=53) / DNS(rd=1, qd=DNSQR(qname="mybank.example")), 0.1)
    add(e(EVIL_MAC, ME_MAC) / IP(src=EVIL, dst=ME) / UDP(sport=53, dport=50123) /
        DNS(qr=1, qd=DNSQR(qname="mybank.example"), an=DNSRR(rrname="mybank.example", rdata=EVIL)), 0.001)
    # --- 6. SYN flood ---
    for _ in range(350):
        add(e(EVIL_MAC, ME_MAC) / IP(src=EVIL, dst=ME) / TCP(sport=rnd.randint(1024, 65000), dport=443, flags="S"), 0.005)
    # --- και ping sweep ---
    for n in range(1, 40):
        add(e(EVIL_MAC) / IP(src=EVIL, dst=f"192.168.1.{n}") / ICMP(type=8), 0.02)
    # --- 7a. DNS tunneling: hex δεδομένα σε subdomains ---
    for i in range(35):
        chunk = "".join(rnd.choice("0123456789abcdef") for _ in range(32))
        q = f"{chunk}.{i:04x}.t.exfil.example"
        add(e(EVIL_MAC, GW_MAC) / IP(src=EVIL, dst=GW) / UDP(sport=rnd.randint(40000, 60000), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=q, qtype="TXT")), 0.1)
    # --- 7b. DGA: τυχαία domains που δεν υπάρχουν (NXDOMAIN) ---
    for _ in range(10):
        name = "".join(rnd.choice("bcdfghjklmnpqrstvwxz0123456789") for _ in range(12)) + ".example"
        sp = rnd.randint(40000, 60000)
        add(e(EVIL_MAC, GW_MAC) / IP(src=EVIL, dst=GW) / UDP(sport=sp, dport=53) / DNS(rd=1, qd=DNSQR(qname=name)), 0.2)
        add(e(GW_MAC, EVIL_MAC) / IP(src=GW, dst=EVIL) / UDP(sport=53, dport=sp) /
            DNS(qr=1, rcode=3, qd=DNSQR(qname=name)), 0.01)
    # --- 8. νέα συσκευή, 90 δευτερόλεπτα αργότερα ---
    t += 90
    for _ in range(2):
        add(e(NEW_MAC) / IP(src=NEW, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / Raw(b"\x00" * 40), 0.5)

    wrpcap(path, pkts)
    return len(pkts)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "samples/lan-attack.pcap"
    print(f"{build(out)} πακέτα → {out}")
