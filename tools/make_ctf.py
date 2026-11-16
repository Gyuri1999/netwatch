#!/usr/bin/env python3
"""Φτιάχνει τα επίπεδα του CTF (pcap + ερωτήσεις).

⚠ SPOILERS: αυτό το αρχείο περιέχει τις απαντήσεις. Αν θέλεις να παίξεις, μην το διαβάσεις!

Χρήση:  python tools/make_ctf.py        → ctf/*.pcap + ctf/challenges.json
"""
import json
import os
import random
import sys

from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import ctf  # noqa: E402
from make_sample_pcap import client_hello  # noqa: E402

ME, ME_MAC = "192.168.1.50", "3c:22:fb:00:00:50"
GW, GW_MAC = "192.168.1.1", "a4:2b:b0:00:00:01"
TV, TV_MAC = "192.168.1.20", "f0:de:f1:00:00:20"
NAS, NAS_MAC = "192.168.1.40", "00:11:32:00:00:40"
LAP, LAP_MAC = "192.168.1.77", "8c:85:90:00:00:77"
C2 = "185.243.115.84"
SITES = [("142.250.184.110", "www.google.com"), ("140.82.121.4", "github.com"),
         ("91.198.174.192", "el.wikipedia.org"), ("13.107.42.14", "outlook.office.com"),
         ("151.101.1.140", "www.reddit.com"), ("104.16.132.229", "cdnjs.cloudflare.com")]
STREAM = ("45.57.90.1", "api.streaming.example")


class Cap:
    def __init__(self, seed):
        self.rnd, self.pkts, self.t = random.Random(seed), [], 1_710_000_000.0

    def add(self, p, at=None, dt=0.01):
        self.t = at if at is not None else self.t + dt
        p.time = self.t
        self.pkts.append(p)

    def e(self, s, d="ff:ff:ff:ff:ff:ff"):
        return Ether(src=s, dst=d)

    def arp_hello(self, ip, mac, at):
        self.add(self.e(mac) / ARP(op=2, psrc=ip, pdst=GW, hwsrc=mac), at=at)

    def dns(self, cli, cmac, name, ip=None, nx=False, qtype="A"):
        sp = self.rnd.randint(49152, 65000)
        self.add(self.e(cmac, GW_MAC) / IP(src=cli, dst=GW) / UDP(sport=sp, dport=53) /
                 DNS(rd=1, qd=DNSQR(qname=name, qtype=qtype)))
        if nx:
            ans = DNS(qr=1, rcode=3, qd=DNSQR(qname=name))
        else:
            ans = DNS(qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=ip))
        self.add(self.e(GW_MAC, cmac) / IP(src=GW, dst=cli) / UDP(sport=53, dport=sp) / ans, dt=0.02)

    def https(self, cli, cmac, ip, name, chunks=4):
        self.dns(cli, cmac, name, ip)
        cp = self.rnd.randint(49152, 65000)
        self.add(self.e(cmac, GW_MAC) / IP(src=cli, dst=ip) / TCP(sport=cp, dport=443, flags="S"))
        self.add(self.e(GW_MAC, cmac) / IP(src=ip, dst=cli) / TCP(sport=443, dport=cp, flags="SA"), dt=0.03)
        self.add(self.e(cmac, GW_MAC) / IP(src=cli, dst=ip) / TCP(sport=cp, dport=443, flags="A"))
        self.add(self.e(cmac, GW_MAC) / IP(src=cli, dst=ip) / TCP(sport=cp, dport=443, flags="PA") /
                 Raw(client_hello(name)))
        for _ in range(chunks):
            self.add(self.e(GW_MAC, cmac) / IP(src=ip, dst=cli) / TCP(sport=443, dport=cp, flags="A") /
                     Raw(bytes(1200)), dt=0.005)

    def browsing(self, start, end, every=15):
        """Κανονική κίνηση: εσύ σερφάρεις, η TV βλέπει σειρές."""
        t = start
        while t < end:
            ip, name = self.rnd.choice(SITES)
            self.t = t
            self.https(ME, ME_MAC, ip, name, self.rnd.randint(2, 6))
            if self.rnd.random() < 0.5:
                self.https(TV, TV_MAC, *STREAM, chunks=self.rnd.randint(4, 8))
            t += self.rnd.uniform(every * 0.4, every * 1.6)

    def save(self, path):
        self.pkts.sort(key=lambda p: p.time)
        wrpcap(path, self.pkts)
        return len(self.pkts)


def level2(path):
    """Ο σιωπηλός επισκέπτης: η TV έχει μολυνθεί, ψάχνει τον C2 με DGA και τον «καλεί» κάθε 30 s."""
    c = Cap(22)
    t0 = c.t
    for ip, mac, dt in ((GW, GW_MAC, 0), (ME, ME_MAC, 0.5), (TV, TV_MAC, 1)):
        c.arp_hello(ip, mac, t0 + dt)
    c.browsing(t0 + 2, t0 + 560)
    # DGA: 12 ανύπαρκτα domains και μετά ένα που υπάρχει
    c.t = t0 + 70
    alphabet = "bcdfghjklmnpqrstvwxz0123456789"
    for _ in range(12):
        c.t += c.rnd.uniform(0.8, 2.0)
        c.dns(TV, TV_MAC, "".join(c.rnd.choice(alphabet) for _ in range(10)) + ".example", nx=True)
    dom = "k3jd9fh2lq.example"
    c.t += 1.3
    c.dns(TV, TV_MAC, dom, C2)
    # beaconing κάθε 30 s
    beat = t0 + 100
    for i in range(14):
        c.t = beat + i * 30 + c.rnd.uniform(-0.3, 0.3)
        sp = c.rnd.randint(49152, 65000)
        body = f"id=TV-7731&cmd=poll&seq={i}".encode()
        req = (b"POST /gate.php HTTP/1.1\r\nHost: " + dom.encode() +
               b"\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\nContent-Length: " +
               str(len(body)).encode() + b"\r\n\r\n" + body)
        c.add(c.e(TV_MAC, GW_MAC) / IP(src=TV, dst=C2) / TCP(sport=sp, dport=8080, flags="S"), dt=0)
        c.add(c.e(GW_MAC, TV_MAC) / IP(src=C2, dst=TV) / TCP(sport=8080, dport=sp, flags="SA"), dt=0.08)
        c.add(c.e(TV_MAC, GW_MAC) / IP(src=TV, dst=C2) / TCP(sport=sp, dport=8080, flags="A"), dt=0.001)
        c.add(c.e(TV_MAC, GW_MAC) / IP(src=TV, dst=C2) / TCP(sport=sp, dport=8080, flags="PA") / Raw(req), dt=0.001)
        c.add(c.e(GW_MAC, TV_MAC) / IP(src=C2, dst=TV) / TCP(sport=8080, dport=sp, flags="PA") /
              Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nwait"), dt=0.09)
    return c.save(path), {"dga_domain": dom}


def level3(path):
    """Ο υπομονετικός: το laptop .77 σκανάρει αργά (κάτω από τα όρια) και μετά συνδέεται στο SMB."""
    c = Cap(33)
    t0 = c.t
    for ip, mac, dt in ((GW, GW_MAC, 0), (ME, ME_MAC, 0.4), (TV, TV_MAC, 0.8), (NAS, NAS_MAC, 1.2),
                        (LAP, LAP_MAC, 1.6)):
        c.arp_hello(ip, mac, t0 + dt)
    c.browsing(t0 + 2, t0 + 600, every=5)
    for i in range(30):  # το NAS κάνει backup στο Internet — πολλές συνδέσεις σε λίγο χρόνο, ΙΔΙΑ θύρα (443)
        c.t = t0 + 200 + i * 2 + c.rnd.uniform(0, 1)
        c.https(NAS, NAS_MAC, c.rnd.choice(SITES)[0], "backup.nas.example", chunks=2)
    ports = sorted(c.rnd.sample([21, 25, 53, 80, 110, 135, 139, 143, 443, 993, 1433, 3306, 3389, 5432, 5900,
                                 6379, 8080, 8443], 18) + [22, 445])
    order = ports[:]
    c.rnd.shuffle(order)
    open_ports = {22, 445}
    for i, p in enumerate(order):
        c.t = t0 + 120 + i * 4 + c.rnd.uniform(-0.5, 0.5)
        sp = c.rnd.randint(40000, 60000)
        c.add(c.e(LAP_MAC, ME_MAC) / IP(src=LAP, dst=ME) / TCP(sport=sp, dport=p, flags="S"), dt=0)
        if p in open_ports:
            c.add(c.e(ME_MAC, LAP_MAC) / IP(src=ME, dst=LAP) / TCP(sport=p, dport=sp, flags="SA"), dt=0.002)
            c.add(c.e(LAP_MAC, ME_MAC) / IP(src=LAP, dst=ME) / TCP(sport=sp, dport=p, flags="R"), dt=0.001)
        else:
            c.add(c.e(ME_MAC, LAP_MAC) / IP(src=ME, dst=LAP) / TCP(sport=p, dport=sp, flags="RA"), dt=0.002)
    # μετά τη σάρωση: σύνδεση στο SMB
    c.t = t0 + 120 + len(order) * 4 + 40
    sp = 51515
    c.add(c.e(LAP_MAC, ME_MAC) / IP(src=LAP, dst=ME) / TCP(sport=sp, dport=445, flags="S"), dt=0)
    c.add(c.e(ME_MAC, LAP_MAC) / IP(src=ME, dst=LAP) / TCP(sport=445, dport=sp, flags="SA"), dt=0.002)
    c.add(c.e(LAP_MAC, ME_MAC) / IP(src=LAP, dst=ME) / TCP(sport=sp, dport=445, flags="A"), dt=0.001)
    for _ in range(6):
        c.add(c.e(LAP_MAC, ME_MAC) / IP(src=LAP, dst=ME) / TCP(sport=sp, dport=445, flags="PA") /
              Raw(b"\x00\x00\x00\x90\xfeSMB" + bytes(140)), dt=0.05)
        c.add(c.e(ME_MAC, LAP_MAC) / IP(src=ME, dst=LAP) / TCP(sport=445, dport=sp, flags="PA") /
              Raw(b"\x00\x00\x00\x80\xfeSMB" + bytes(124)), dt=0.01)
    return c.save(path), {"ports": ports}


def build(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    n2, _ = level2(os.path.join(out_dir, "level2-silent-visitor.pcap"))
    n3, info3 = level3(os.path.join(out_dir, "level3-patient-scanner.pcap"))
    H = ctf.answer_hash
    levels = [
        {"id": "l1", "title": "Εισβολέας στο LAN", "difficulty": "Εύκολο", "pcap": "samples/lan-attack.pcap",
         "me": "192.168.1.50", "gw": "192.168.1.1",
         "story": "Το laptop κάποιου στο Wi‑Fi σου έχει παραβιαστεί και επιτίθεται στους πάντες. "
                  "Οι ανιχνευτές το έχουν πιάσει — διάβασε τις ειδοποιήσεις και τις λεπτομέρειες.",
         "questions": [
             {"id": "q1", "points": 10, "q": "Ποια είναι η IP του επιτιθέμενου;",
              "hint": "Καρτέλα ⚠ Επιθέσεις — ποια IP εμφανίζεται ξανά και ξανά;", "answers": ["192.168.1.66"]},
             {"id": "q2", "points": 10, "q": "Ποια υπηρεσία δέχτηκε brute force;",
              "hint": "Η ειδοποίηση Brute force γράφει υπηρεσία και θύρα.", "answers": ["ssh", "22"]},
             {"id": "q3", "points": 10, "q": "Ποια MAC διεύθυνση χρησιμοποίησε για να «γίνει» ο router;",
              "hint": "Δες την ειδοποίηση ARP spoofing.", "answers": ["de:ad:be:ef:00:66", "de-ad-be-ef-00-66"]},
             {"id": "q4", "points": 10, "q": "Σε ποιο domain έβγαλε δεδομένα μέσω DNS;",
              "hint": "Ειδοποίηση DNS tunneling — ο στόχος της.", "answers": ["exfil.example"]},
             {"id": "q5", "points": 10, "q": "Σε ποια IP του LAN στάλθηκε κωδικός μέσω FTP;",
              "hint": "Καρτέλα 🛡 Έλεγχος → Κωδικοί χωρίς κρυπτογράφηση.", "answers": ["192.168.1.20"]},
             {"id": "q6", "points": 10, "q": "Ποια είναι η IP της συσκευής που μπήκε τελευταία στο δίκτυο;",
              "hint": "Ειδοποίηση «Νέα συσκευή».", "answers": ["192.168.1.88"]},
             {"id": "q7", "points": 10, "q": "Ποιος είναι ο κωδικός MITRE ATT&CK του ARP spoofing;",
              "hint": "Το μωβ σήμα σε κάθε ειδοποίηση, π.χ. T1046.", "answers": ["t1557.002"]},
         ]},
        {"id": "l2", "title": "Ο σιωπηλός επισκέπτης", "difficulty": "Μέτριο",
         "pcap": "ctf/level2-silent-visitor.pcap", "me": ME, "gw": GW,
         "story": "Δεν σε επιτέθηκε κανείς — κι όμως κάτι δεν πάει καλά. Μια συσκευή στο σπίτι κάνει "
                  "περίεργες ερωτήσεις DNS και μετά «μιλάει» τακτικά με έναν server στο εξωτερικό. Βρες τη.",
         "questions": [
             {"id": "q1", "points": 20, "q": "Ποια συσκευή του LAN έχει μολυνθεί (IP);",
              "hint": "Ποια συσκευή κάνει ερωτήσεις για domains που δεν υπάρχουν;", "answers": [TV]},
             {"id": "q2", "points": 20, "q": "Ποια είναι η IP του C2 server;",
              "hint": "Ειδοποίηση Beaconing — ποιον «καλεί»;", "answers": [C2]},
             {"id": "q3", "points": 20, "q": "Κάθε πόσα δευτερόλεπτα «καλεί» το malware τον C2;",
              "hint": "Η ειδοποίηση Beaconing γράφει το διάστημα.", "answers": ["30", "30s", "30sec", "30δευτερόλεπτα"]},
             {"id": "q4", "points": 20, "q": "Ποιο domain βρήκε τελικά το DGA (αυτό που υπάρχει);",
              "hint": "Κάνε κλικ στην IP του C2 → Λεπτομέρειες → domains.", "answers": ["k3jd9fh2lq.example"]},
             {"id": "q5", "points": 20, "q": "Σε ποια θύρα μιλάει με τον C2;",
              "hint": "Λεπτομέρειες του C2 → θύρες.", "answers": ["8080"]},
             {"id": "q6", "points": 20, "q": "Ποια τεχνική MITRE ATT&CK αντιστοιχεί στο beaconing;",
              "hint": "Το μωβ σήμα στην ειδοποίηση.", "answers": ["t1071"]},
         ]},
        {"id": "l3", "title": "Ο υπομονετικός", "difficulty": "Δύσκολο",
         "pcap": "ctf/level3-patient-scanner.pcap", "me": ME, "gw": GW,
         "story": "Αυτή τη φορά οι ανιχνευτές δεν λένε τίποτα. Κάποιος όμως σκάναρε τον υπολογιστή σου τόσο "
                  "αργά που πέρασε κάτω από τα όρια — και μετά μπήκε. Ψάξε στα δεδομένα σαν αναλυτής SOC "
                  "και μετά γράψε κανόνα που να τον πιάνει.",
         "questions": [
             {"id": "q1", "points": 30, "q": "Ποια IP σάρωσε αθόρυβα τον υπολογιστή σου (192.168.1.50);",
              "hint": "Καρτέλα 📟 Συσκευές → ποια συσκευή «χτυπάει» πολλές διαφορετικές θύρες; (Λεπτομέρειες → Τι χτυπάει)",
              "answers": [LAP]},
             {"id": "q2", "points": 30, "q": "Πόσες διαφορετικές θύρες δοκίμασε;",
              "hint": "Λεπτομέρειες του scanner → Τι χτυπάει: μέτρα τις θύρες.", "answers": [str(len(info3["ports"]))]},
             {"id": "q3", "points": 30, "q": "Ποιες θύρες βρήκε ανοιχτές; (π.χ. 80,443)",
              "hint": "Ανοιχτή θύρα = ο στόχος απάντησε SYN‑ACK (SA). Καρτέλα 📦 Πακέτα, ή Λεπτομέρειες του 192.168.1.50 → θύρες.",
              "answers": ["22,445", "445,22"]},
             {"id": "q4", "points": 30, "q": "Σε ποια υπηρεσία συνδέθηκε μετά τη σάρωση;",
              "hint": "Μετά τη σάρωση υπάρχει μία κανονική σύνδεση με δεδομένα.", "answers": ["smb", "445"]},
             {"id": "rule", "type": "rule", "points": 50,
              "q": "Γράψε κανόνα (YAML) που ανιχνεύει τον αργό scanner — και ΜΟΝΟ αυτόν (όχι false positives).",
              "hint": "Ο scanner στέλνει SYN σε πολλές ΔΙΑΦΟΡΕΤΙΚΕΣ θύρες. Οι κανονικές συσκευές συνδέονται σε πολλές IP, "
                      "αλλά σχεδόν πάντα στην ίδια θύρα. Δες το threshold με distinct: dport και ένα μεγάλο window.",
              "answers": [LAP]},
         ]},
    ]
    for lv in levels:
        for q in lv["questions"]:
            q["answers"] = sorted({H(lv["id"], q["id"], a) for a in q["answers"]})
    with open(os.path.join(out_dir, "challenges.json"), "w", encoding="utf-8") as f:
        json.dump({"version": 1, "levels": levels}, f, ensure_ascii=False, indent=1)
    return n2, n3


if __name__ == "__main__":
    out = os.path.join(ROOT, "ctf")
    n2, n3 = build(out)
    print(f"ctf/level2: {n2} πακέτα, ctf/level3: {n3} πακέτα, ctf/challenges.json")
