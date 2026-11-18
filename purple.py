"""NetWatch — 🟣 Purple-team καμπάνιες και κάλυψη MITRE ATT&CK (ιδέα: Atomic Red Team / MITRE Caldera).

Κάθε σενάριο είναι μια ΠΡΟΣΟΜΟΙΩΜΕΝΗ επίθεση: φτιάχνουμε πακέτα (dict) και τα «εγχέουμε» στην ίδια μηχανή
ανίχνευσης που βλέπει την πραγματική κίνηση (state.process). ΤΙΠΟΤΑ δεν φεύγει στο δίκτυο.

* Ο χρόνος «συμπιέζεται»: τα πακέτα παίρνουν εικονικές χρονοσφραγίδες (π.χ. 10 beacons ανά 60 s τελειώνουν
  σε ~1 s πραγματικού χρόνου) που καταλήγουν στο «τώρα» — οι ανιχνευτές κοιτάνε μόνο το P["t"].
* Κάθε εκτέλεση (σενάριο × παραλλαγή) έχει δική της IP «επιτιθέμενου» (10.66.66.x), ώστε τα χρονικά
  παράθυρα και τα cooldowns να μη μπερδεύονται μεταξύ θορυβώδους και αθόρυβης εκδοχής.
* Οι ειδοποιήσεις σημαδεύονται lab (state.lab_ips) — δεν πάνε σε ιστορικό, ειδοποιήσεις, playbooks.
"""
import json
import os
import random
import threading
import time

from core import MITRE, detector_for, log

ATT_NET = "10.66.66."  # «επιτιθέμενοι» του εργαστηρίου (ιδιωτικό δίκτυο που δεν υπάρχει στο σπίτι)
C2_NET = "11.66.66."   # εικονικός C2 στο Internet — ΠΟΤΕ δεν επικοινωνούμε μαζί του (μόνο εγχυμένα πακέτα)
HISTORY_MAX = 20
VARIANTS = ("loud", "quiet")
TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
           "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
           "Collection", "Command and Control", "Exfiltration", "Impact"]


def _hex(n):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _tech(tid, name, tactic):
    return {"id": tid, "name": name, "tactic": tactic,
            "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"}


# ---------------- κατάλογος σεναρίων ----------------
# expect: προθέματα τύπου ειδοποίησης που σημαίνουν «το έπιασε»· new: νέο σενάριο (όχι από το παλιό Lab)
SCENARIOS = {
    "portscan": dict(
        title="Port scan", tool="nmap -sS", expect=("Port scan",),
        technique=_tech("T1046", "Network Service Discovery", "Discovery"),
        loud="40 θύρες σε ~2 δευτερόλεπτα (nmap -T4)",
        quiet="15 θύρες, μία κάθε 0,8 s (nmap -T1 «sneaky»)",
        lesson="Τα IDS μετράνε γεγονότα μέσα σε ένα χρονικό παράθυρο. Ένας υπομονετικός επιτιθέμενος μένει κάτω "
               "από το όριο. Γι' αυτό τα SOC κοιτάνε και μακροπρόθεσμα μοτίβα (π.χ. ανά ώρα)."),
    "brute": dict(
        title="SSH brute force", tool="hydra -t 4 ssh://…", expect=("Brute force",),
        technique=_tech("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
        loud="20 προσπάθειες σύνδεσης στο SSH σε ~4 s",
        quiet="8 προσπάθειες, μία κάθε 3 s (password spraying)",
        lesson="Το «password spraying» δοκιμάζει λίγους κωδικούς αργά για να μην ενεργοποιήσει όρια ή κλείδωμα "
               "λογαριασμού. Άμυνα: κλειδιά SSH αντί κωδικών, fail2ban, 2FA."),
    "pingsweep": dict(
        title="Ping sweep", tool="nmap -sn 192.168.1.0/24", expect=("Network sweep",),
        technique=_tech("T1018", "Remote System Discovery", "Discovery"),
        loud="ping σε 40 διευθύνσεις σε 2 s", quiet="ping σε 25 διευθύνσεις, μία κάθε 0,5 s",
        lesson="Η χαρτογράφηση του δικτύου είναι το πρώτο βήμα. Αργή σάρωση ή ARP αντί για ping την κάνει πολύ "
               "πιο δύσκολη να φανεί."),
    "dnstunnel": dict(
        title="DNS tunneling", tool="iodine / dnscat2", expect=("DNS tunneling",),
        technique=_tech("T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
        loud="35 ερωτήματα με τυχαία hex subdomains (δεδομένα κωδικοποιημένα)",
        quiet="35 ερωτήματα με «κανονικές» λέξεις (photo-1.cdn…, photo-2.cdn…)",
        lesson="Η ανίχνευση βασίζεται στην εντροπία (πόσο «τυχαίο» είναι ένα όνομα). Αν τα δεδομένα κρυφτούν σε "
               "λέξεις από λεξικό, η εντροπία πέφτει και η ανίχνευση αποτυγχάνει."),
    "xmas": dict(
        title="XMAS scan", tool="nmap -sX", expect=("Stealth scan",),
        technique=_tech("T1046", "Network Service Discovery", "Discovery"),
        loud="5 πακέτα TCP με σημαίες FIN+PSH+URG", quiet=None,
        lesson="Παράξενα πακέτα που δεν στέλνει ποτέ κανονικό πρόγραμμα — πιάνονται με την πρώτη. Γι' αυτό οι "
               "έμπειροι επιτιθέμενοι προτιμούν τις «κανονικές» συνδέσεις."),
    "arpspoof": dict(
        title="ARP spoofing (MITM)", tool="arpspoof / bettercap", expect=("ARP spoofing",),
        technique=_tech("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning", "Credential Access"),
        loud="5 ψεύτικες απαντήσεις ARP «εγώ είμαι ο router»", quiet=None,
        lesson="Το ARP δεν έχει πιστοποίηση, αλλά η αλλαγή MAC του router είναι εύκολο να φανεί. Άμυνα: Dynamic "
               "ARP Inspection σε managed switch, VPN, HTTPS παντού."),
    "synflood": dict(
        title="SYN flood (DoS)", tool="hping3 -S --flood", expect=("SYN flood",),
        technique=_tech("T1498.001", "Network DoS: Direct Network Flood", "Impact"),
        loud="320 SYN σε ~1,5 s", quiet=None,
        lesson="Οι επιθέσεις DoS είναι από τη φύση τους θορυβώδεις — ο στόχος τους είναι ο όγκος."),
    # ---- νέα σενάρια ----
    "beacon": dict(
        new=True, title="C2 beaconing", tool="Cobalt Strike / Sliver beacon", expect=("Beaconing",),
        technique=_tech("T1071", "Application Layer Protocol", "Command and Control"),
        loud="10 συνδέσεις HTTPS στον C2 ακριβώς κάθε 60 s (jitter 1%)",
        quiet="10 συνδέσεις κάθε ~60 s με jitter 50% (sleep 60 / jitter 50)",
        lesson="Το malware «ρωτάει» τον αφέντη του για εντολές σε τακτά διαστήματα· το σταθερό «ρολόι» το "
               "προδίδει. Τα σύγχρονα C2 προσθέτουν τυχαίο jitter ώστε τα διαστήματα να μη μοιάζουν μηχανικά — "
               "τότε χρειάζεται στατιστική ανάλυση σε ώρες/μέρες (π.χ. RITA) και όχι σε λίγα λεπτά."),
    "dga": dict(
        new=True, title="DGA domains", tool="Conficker / Necurs DGA", expect=("DGA domains",),
        technique=_tech("T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "Command and Control"),
        loud="20 ερωτήματα για «τυχαία» domains (π.χ. xk3j9qz7lpwt.com) που δεν υπάρχουν (NXDOMAIN)",
        quiet="20 ανύπαρκτα domains από λέξεις λεξικού (π.χ. lightriverhouse.net — τύπου Suppobox)",
        lesson="Το malware δοκιμάζει εκατοντάδες ονόματα μέχρι να βρει αυτό που έχει καταχωρίσει ο επιτιθέμενος. "
               "Τα «τυχαία» ονόματα φαίνονται από τη στατιστική των γραμμάτων· τα DGA από λέξεις λεξικού "
               "μοιάζουν ανθρώπινα και ξεφεύγουν — εκεί βοηθά η φήμη/ηλικία του domain."),
    "udpscan": dict(
        new=True, title="UDP port scan", tool="nmap -sU", expect=("Port scan (UDP)",),
        technique=_tech("T1046", "Network Service Discovery", "Discovery"),
        loud="30 θύρες UDP σε ~1,5 s", quiet="12 θύρες UDP, μία κάθε 1,5 s",
        lesson="Η σάρωση UDP είναι αργή και αναξιόπιστη για τον επιτιθέμενο (δεν υπάρχει χειραψία), αλλά βρίσκει "
               "υπηρεσίες που ξεχνάμε: SNMP, TFTP, UPnP. Ίδιο μάθημα με το TCP: κάτω από το όριο δεν φαίνεται."),
    "arpsweep": dict(
        new=True, title="ARP sweep", tool="arp-scan -l / netdiscover", expect=("Network sweep (ARP)",),
        technique=_tech("T1018", "Remote System Discovery", "Discovery"),
        loud="ARP «ποιος έχει;» για 60 διευθύνσεις σε ~2,5 s",
        quiet="ARP για 40 διευθύνσεις, μία κάθε 0,6 s (netdiscover -p με καθυστέρηση)",
        lesson="Το ARP δεν φιλτράρεται από firewall και κάθε συσκευή πρέπει να απαντήσει — γι' αυτό είναι ο "
               "πιο αξιόπιστος τρόπος ανακάλυψης στο LAN. Αργή σάρωση μοιάζει με κανονική κίνηση."),
    "icmpflood": dict(
        new=True, title="ICMP flood (DoS)", tool="hping3 --icmp --flood", expect=("ICMP flood",),
        technique=_tech("T1498.001", "Network DoS: Direct Network Flood", "Impact"),
        loud="150 ping προς εσένα σε 1,5 s", quiet=None,
        lesson="Όπως κάθε DoS, ο όγκος είναι ο σκοπός και άρα φαίνεται αμέσως. Άμυνα: όριο ICMP στο router."),
    "rogue_dhcp": dict(
        new=True, title="Rogue DHCP server", tool="yersinia / dhcpstarv + dnsmasq", expect=("Rogue DHCP",),
        technique=_tech("T1557.003", "Adversary-in-the-Middle: DHCP Spoofing", "Credential Access"),
        loud="DHCP starvation (30 DISCOVER με τυχαίες MAC) και 3 ψεύτικες προσφορές",
        quiet="μία μόνο ψεύτικη προσφορά DHCP που «προλαβαίνει» τον router",
        lesson="Όποιος απαντήσει πρώτος στο DHCP ορίζει gateway και DNS της συσκευής — τέλειο MITM. Δεν υπάρχει "
               "αθόρυβος τρόπος: η ψεύτικη απάντηση πρέπει να σταλεί. Άμυνα: DHCP snooping στο switch."),
    "creds": dict(
        new=True, title="Κωδικοί σε καθαρό κείμενο", tool="Wireshark / dsniff / PCredz", expect=("Κωδικός σε καθαρό κείμενο",),
        technique=_tech("T1040", "Network Sniffing", "Credential Access"),
        loud="σύνδεση FTP (USER/PASS) και συνεδρία Telnet που «ακούει» ο επιτιθέμενος",
        quiet="ένα μόνο αίτημα HTTP με Basic Auth (admin) προς τη σελίδα ενός router",
        lesson="Ο επιτιθέμενος που «ακούει» είναι παθητικός — δεν τον βλέπεις. Αυτό που ΜΠΟΡΕΙΣ να δεις είναι ότι "
               "ένας κωδικός ταξίδεψε ανοιχτά. Η μόνη πραγματική άμυνα είναι η κρυπτογράφηση (SFTP, SSH, HTTPS)."),
    "mirai": dict(
        new=True, title="Mirai telnet scan", tool="Mirai / Gafgyt botnet", expect=("Port scan", "Brute force"),
        technique=_tech("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
        loud="μολυσμένη κάμερα σαρώνει 23/2323 σε 30 συσκευές και δοκιμάζει 16 κωδικούς Telnet σε εσένα",
        quiet="σάρωση 23/2323 μία συσκευή κάθε 2,5 s και 6 αργές δοκιμές κωδικού",
        lesson="Το Mirai μολύνει κάμερες/routers με εργοστασιακούς κωδικούς Telnet (admin/admin, root/xc3511) και "
               "μετά σαρώνει για νέα θύματα. Άμυνα: κλείσε το Telnet, άλλαξε κωδικούς, απομόνωσε τα IoT σε VLAN."),
}
ORDER = ["portscan", "udpscan", "xmas", "pingsweep", "arpsweep", "brute", "mirai", "creds", "arpspoof",
         "rogue_dhcp", "dnstunnel", "beacon", "dga", "synflood", "icmpflood"]

_WORDS = ["light", "river", "house", "garden", "window", "blue", "sunset", "market", "place", "silver", "forest",
          "paper", "travel", "winter", "orange", "golden", "mountain", "coffee", "people", "summer"]
_UDP_SKIP = {53, 67, 68, 123, 137, 138}


def _dga_name():
    from core import dga_score
    while True:
        s = "".join(random.choice("bcdfghjklmnpqrstvwxz0123456789") for _ in range(random.randint(11, 15)))
        if dga_score(s) >= 0.75:
            return s + random.choice((".com", ".net", ".info", ".biz"))


def _word_name(i):
    a, b, c = _WORDS[i % len(_WORDS)], _WORDS[(i * 7 + 3) % len(_WORDS)], _WORDS[(i * 3 + 11) % len(_WORDS)]
    return a + b + c + (".net" if i % 2 else ".com")


def schedule(kind, loud, ctx):
    """Λίστα (dt, P): dt = εικονικά δευτερόλεπτα πριν από το πακέτο. ctx: A, A2, mac, c2, me, gw, net, gw_mac, dhcp."""
    A, me, gw, net = ctx["A"], ctx["me"], ctx["gw"], ctx["net"]
    rp = lambda: random.randint(40000, 60000)  # noqa: E731
    S = []

    def add(dt, **P):
        S.append((dt, P))
    if kind == "portscan":
        for p in random.sample(range(1, 10000), 40 if loud else 15):
            add(0.05 if loud else 0.8, src=A, dst=me, proto="TCP", sp=rp(), dp=p, flags="S")
    elif kind == "brute":
        for _ in range(20 if loud else 8):
            add(0.2 if loud else 3, src=A, dst=me, proto="TCP", sp=rp(), dp=22, flags="S")
    elif kind == "pingsweep":
        for n in random.sample(range(2, 254), 40 if loud else 25):
            add(0.05 if loud else 0.5, src=A, dst=f"{net}.{n}", proto="ICMP", icmp_type=8, len=98)
    elif kind == "dnstunnel":
        for i in range(35):
            q = f"{_hex(30)}.{_hex(8)}.t.exfil-lab.example" if loud else f"photo-{i}.images.cdn-lab.example"
            add(0.1, src=A, dst=gw, proto="UDP", sp=rp(), dp=53, dns_q=(q, 16 if loud else 1), len=120)
    elif kind == "xmas":
        for p in (21, 22, 80, 443, 3389):
            add(0.2, src=A, dst=me, proto="TCP", sp=41000, dp=p, flags="FPU")
    elif kind == "arpspoof":
        add(0, src=A, dst=gw, proto="ARP", len=42, arp=dict(op=2, psrc=A, pdst=gw, hwsrc=ctx["mac"]))
        for _ in range(5):
            add(0.3, src=gw, dst=me, proto="ARP", len=42, arp=dict(op=2, psrc=gw, pdst=me, hwsrc=ctx["mac"]))
        if ctx.get("gw_mac"):  # επαναφορά της σωστής MAC (όπως κάνει και το arpspoof όταν σταματά)
            add(0.3, src=gw, dst=me, proto="ARP", len=42, smac=ctx["gw_mac"],
                arp=dict(op=2, psrc=gw, pdst=me, hwsrc=ctx["gw_mac"]))
    elif kind == "synflood":
        for _ in range(320):
            add(1.5 / 320, src=A, dst=me, proto="TCP", sp=random.randint(1024, 65000), dp=443, flags="S")
    elif kind == "beacon":
        mult = ([1.0, 1.01, 0.99, 1.0, 1.02, 0.98, 1.0, 1.01, 0.99, 1.0] if loud else
                [1.0, 1.45, 0.55, 1.3, 0.6, 1.5, 0.7, 1.35, 0.5, 1.2])
        for i, m in enumerate(mult):
            add(0 if i == 0 else 60 * m, src=A, dst=ctx["c2"], proto="TCP", sp=rp(), dp=443, flags="S", len=74)
    elif kind == "dga":
        names = [_dga_name() for _ in range(20)] if loud else [_word_name(i) for i in range(20)]
        for q in names:
            sp = rp()
            add(0.3 if loud else 2.5, src=A, dst=gw, proto="UDP", sp=sp, dp=53, dns_q=(q, 1), len=80)
            add(0.02, src=gw, dst=A, proto="UDP", sp=53, dp=sp, nx=q, len=140)
    elif kind == "udpscan":
        ports = random.sample([p for p in range(1, 1024) if p not in _UDP_SKIP], 30 if loud else 12)
        for p in ports:
            add(0.05 if loud else 1.5, src=A, dst=me, proto="UDP", sp=rp(), dp=p, len=42)
    elif kind == "arpsweep":
        skip = {me, gw}
        targets = [f"{net}.{n}" for n in range(1, 255) if f"{net}.{n}" not in skip]
        for ip in random.sample(targets, 60 if loud else 40):
            add(0.04 if loud else 0.6, src=A, dst=ip, proto="ARP", len=42,
                arp=dict(op=1, psrc=A, pdst=ip, hwsrc=ctx["mac"]))
    elif kind == "icmpflood":
        for _ in range(150):
            add(0.01, src=A, dst=me, proto="ICMP", icmp_type=8, len=98)
    elif kind == "rogue_dhcp":
        if not ctx.get("dhcp"):  # χωρίς γνωστό DHCP server δεν υπάρχει «σωστός» για σύγκριση: πρώτα ο router
            add(0, src=gw, dst="255.255.255.255", proto="UDP", sp=67, dp=68, len=342)
        if loud:
            for _ in range(30):
                add(0.02, src="0.0.0.0", dst="255.255.255.255", proto="UDP", sp=68, dp=67, len=342)
        for _ in range(3 if loud else 1):
            add(0.05, src=A, dst="255.255.255.255", proto="UDP", sp=67, dp=68, len=342)
    elif kind == "creds":
        srv = ctx["A2"]
        if loud:
            sp = rp()
            add(0, src=A, dst=srv, proto="TCP", sp=sp, dp=21, flags="PA", len=80,
                cred={"proto": "FTP", "field": "user", "user": "admin"})
            add(0.4, src=A, dst=srv, proto="TCP", sp=sp, dp=21, flags="PA", len=80, cred={"proto": "FTP", "field": "pass"})
            add(1.0, src=A, dst=srv, proto="TCP", sp=rp(), dp=23, flags="PA", len=70,
                cred={"proto": "Telnet", "field": "session"})
        else:
            add(0, src=A, dst=srv, proto="TCP", sp=rp(), dp=80, flags="PA", len=420, http_host="router.lab",
                cred={"proto": "HTTP Basic", "field": "pass", "user": "admin"})
    elif kind == "mirai":
        hosts = random.sample([n for n in range(2, 254) if f"{net}.{n}" not in (me, gw)], 30 if loud else 10)
        for n in hosts:
            for p in (23, 2323):
                add(0.03 if loud else 1.25, src=A, dst=f"{net}.{n}", proto="TCP", sp=rp(), dp=p, flags="S")
        for _ in range(16 if loud else 6):
            add(0.15 if loud else 4, src=A, dst=me, proto="TCP", sp=rp(), dp=23, flags="S")
    else:
        raise ValueError("Άγνωστο σενάριο")
    return S


def rule_text(kind, cfg):
    th = cfg["thresholds"]
    ps, b = th["port_scan"], th["beaconing"]
    return {
        "portscan": f"≥ {ps['count']} διαφορετικές θύρες/στόχοι από την ίδια IP σε {ps['window']} s",
        "udpscan": f"≥ {ps['count']} διαφορετικές θύρες/στόχοι UDP από την ίδια IP σε {ps['window']} s",
        "brute": f"≥ {th['brute_force']['count']} συνδέσεις στην ίδια υπηρεσία σύνδεσης σε {th['brute_force']['window']} s",
        "pingsweep": f"ping σε ≥ {th['ping_sweep']['count']} διαφορετικές IP σε {th['ping_sweep']['window']} s",
        "arpsweep": f"ARP ερωτήσεις για ≥ {th['arp_sweep']['count']} διαφορετικές IP σε {th['arp_sweep']['window']} s",
        "dnstunnel": f"≥ {th['dns_tunnel']['unique_subdomains']} μοναδικά subdomains με μήκος ≥ {th['dns_tunnel']['min_length']} "
                     f"και εντροπία ≥ {th['dns_tunnel']['min_entropy']} σε {th['dns_tunnel']['window']} s",
        "xmas": "οποιοδήποτε πακέτο TCP με σημαίες NULL, FIN ή FIN+PSH+URG",
        "arpspoof": "η MAC του router αλλάζει σε MAC άλλης συσκευής",
        "synflood": f"≥ {th['syn_flood']['count']} SYN προς εσένα σε {th['syn_flood']['window']} s",
        "icmpflood": f"≥ {th['icmp_flood']['count']} ping προς εσένα σε {th['icmp_flood']['window']} s",
        "beacon": f"≥ {b['min_events']} συνδέσεις στον ίδιο προορισμό με μέσο διάστημα {b['min_interval']}–{b['max_interval']} s "
                  f"και απόκλιση ≤ {b['max_jitter'] * 100:.0f}%",
        "dga": f"≥ {th['dga']['nxdomain']} ανύπαρκτα domains (NXDOMAIN) με σκορ DGA ≥ {th['dga']['min_score']} σε {th['dga']['window']} s",
        "rogue_dhcp": "απάντηση DHCP (θύρα 67 → 68) από διακομιστή διαφορετικό από τον γνωστό",
        "creds": "όνομα χρήστη/κωδικός σε πρωτόκολλο χωρίς κρυπτογράφηση (FTP, Telnet, HTTP Basic/φόρμα, POP3, IMAP, MQTT)",
        "mirai": f"Port scan (≥ {ps['count']} θύρες/στόχοι σε {ps['window']} s) ή Brute force "
                 f"(≥ {th['brute_force']['count']} συνδέσεις σε {th['brute_force']['window']} s)",
    }[kind]


def scenario_list(cfg):
    out = []
    for k in ORDER:
        s = SCENARIOS[k]
        dets = sorted({detector_for(e) for e in s["expect"] if detector_for(e)})
        out.append({"id": k, "title": s["title"], "tool": s["tool"], "technique": s["technique"],
                    "loud": s["loud"], "quiet": s.get("quiet"), "lesson": s["lesson"], "expect": list(s["expect"]),
                    "rule": rule_text(k, cfg), "new": bool(s.get("new")),
                    "variants": [v for v in VARIANTS if s.get(v)], "detectors": dets,
                    "detector_enabled": all(cfg["detectors"].get(d, True) for d in dets)})
    return out


# ---------------- κάλυψη ATT&CK ----------------
def coverage(results):
    """results: λίστα αποτελεσμάτων μιας καμπάνιας. Επιστρέφει tactic → techniques → status + σκορ.
    status: detected (όλες οι παραλλαγές που δοκιμάστηκαν πιάστηκαν) · partial (π.χ. μόνο η θορυβώδης) ·
    missed (καμία) · not_tested."""
    techs = {}
    for k in ORDER:
        t = SCENARIOS[k]["technique"]
        techs.setdefault(t["id"], {"id": t["id"], "name": t["name"], "tactic": t["tactic"], "url": t["url"],
                                   "scenarios": []})
    for _prefix, tid, name, tactic, _det in MITRE:  # ό,τι ΜΠΟΡΕΙ να ανιχνεύσει το NetWatch αλλά δεν έχει σενάριο
        techs.setdefault(tid, {"id": tid, "name": name, "tactic": tactic,
                               "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/",
                               "scenarios": []})
    by = {}
    for r in results or ():
        if r.get("skipped"):
            continue
        by.setdefault(r["scenario"], {})[r["variant"]] = bool(r.get("detected"))
    for k in ORDER:
        t = techs[SCENARIOS[k]["technique"]["id"]]
        v = by.get(k, {})
        t["scenarios"].append({"id": k, "title": SCENARIOS[k]["title"], "loud": v.get("loud"), "quiet": v.get("quiet"),
                               "has_quiet": bool(SCENARIOS[k].get("quiet"))})
    tactics = {}
    pts = tested = 0
    counts = {"detected": 0, "partial": 0, "missed": 0, "not_tested": 0}
    for t in techs.values():
        runs = [x for s in t["scenarios"] for x in (s["loud"], s["quiet"]) if x is not None]
        if not runs:
            st = "not_tested"
        elif all(runs):
            st = "detected"
        elif any(runs):
            st = "partial"
        else:
            st = "missed"
        t["status"] = st
        counts[st] += 1
        if st != "not_tested":
            tested += 1
            pts += {"detected": 1, "partial": 0.5}.get(st, 0)
        tactics.setdefault(t["tactic"], []).append(t)
    order = [x for x in TACTICS if x in tactics] + sorted(x for x in tactics if x not in TACTICS)
    return {"tactics": [{"tactic": x, "techniques": sorted(tactics[x], key=lambda t: t["id"])} for x in order],
            "counts": counts, "tested": tested, "total": len(techs),
            "score": round(100 * pts / tested) if tested else None}


def _summary(c):
    rs = [r for r in c["results"] if not r.get("skipped")]
    det = sum(1 for r in rs if r["detected"])
    return {"id": c["id"], "started": c["started"], "finished": c.get("finished"), "status": c["status"],
            "runs": len(rs), "detected": det, "missed": len(rs) - det,
            "skipped": sum(1 for r in c["results"] if r.get("skipped")),
            "rate": round(100 * det / len(rs)) if rs else None,
            "score": (c.get("coverage") or {}).get("score")}


class Purple:
    """Εκτελεί καμπάνιες (όλα ή επιλεγμένα σενάρια × παραλλαγές) και κρατά ιστορικό των τελευταίων 20.
    path: data/purple.json (live) ή None (demo/tests: μόνο στη μνήμη). pace: πραγματικά δευτερόλεπτα ανά εκτέλεση."""

    def __init__(self, state, path=None, pace=1.0, settle=0.2):
        self.st = state
        self.path = path
        self.pace, self.settle = pace, settle
        self.lock = threading.Lock()
        self.run = None
        self.on_save = None
        self._stop = threading.Event()
        self._seq = 0
        self.history = self._load()

    # --- αποθήκευση ---
    def _load(self):
        if not self.path:
            return []
        try:
            with open(self.path, encoding="utf-8") as f:
                return list(json.load(f).get("campaigns") or [])[-HISTORY_MAX:]
        except (OSError, ValueError, AttributeError):
            return []

    def _save(self):
        if not self.path:
            return
        try:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"campaigns": self.history[-HISTORY_MAX:]}, f, ensure_ascii=False)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError as e:
            log("purple: αποθήκευση απέτυχε:", e)

    # --- API ---
    def status(self, campaign_id=None):
        cfg = self.st.cfg
        with self.lock:
            run = json.loads(json.dumps(self.run)) if self.run else None
            hist = list(self.history)
        last = hist[-1] if hist else None
        out = {"status": "running" if run and run["status"] == "running" else "idle",
               "mode": self.st.mode, "scenarios": scenario_list(cfg), "tactics_order": TACTICS,
               "run": run, "last": last,
               "coverage": (last or {}).get("coverage") or coverage([]),
               "history": [_summary(c) for c in reversed(hist)]}
        if campaign_id is not None:
            out["campaign"] = next((c for c in hist if c["id"] == campaign_id), None)
        return out

    def status_brief(self):
        with self.lock:
            return "running" if self.run and self.run["status"] == "running" else "idle"

    def plan(self, scenarios=None, variants=None):
        if scenarios in (None, [], ()):
            scenarios = list(ORDER)
        if not isinstance(scenarios, (list, tuple)) or len(scenarios) > 50:
            raise ValueError("scenarios: λίστα από ids")
        for s in scenarios:
            if s not in SCENARIOS:
                raise ValueError(f"Άγνωστο σενάριο: {str(s)[:40]}")
        variants = list(VARIANTS) if variants in (None, [], ()) else variants
        if not isinstance(variants, (list, tuple)) or any(v not in VARIANTS for v in variants):
            raise ValueError("variants: «loud» και/ή «quiet»")
        seen, runs = set(), []
        for s in scenarios:
            if s in seen:
                continue
            seen.add(s)
            for v in VARIANTS:
                if v in variants and SCENARIOS[s].get(v):
                    runs.append((s, v))
        if not runs:
            raise ValueError("Κανένα σενάριο δεν έχει αυτή την παραλλαγή")
        return runs

    def start(self, scenarios=None, variants=None):
        runs = self.plan(scenarios, variants)
        lab = getattr(self.st, "lab", None)
        if lab is not None and (lab.status() or {}).get("status") == "running":
            raise ValueError("Τρέχει μια άσκηση του Lab — περίμενε να τελειώσει")
        with self.lock:
            if self.run and self.run["status"] == "running":
                raise ValueError("Τρέχει ήδη καμπάνια")
            cid = max([c["id"] for c in self.history] + [0]) + 1
            self._stop.clear()
            self.run = {"status": "running", "id": cid, "started": time.time(), "total": len(runs), "done": 0,
                        "progress": 0, "current": None, "results": [],
                        "scenarios": sorted({s for s, _ in runs}, key=ORDER.index), "variants": sorted({v for _, v in runs})}
        threading.Thread(target=self._campaign, args=(runs,), daemon=True).start()
        return {"ok": True, "id": cid, "total": len(runs)}

    def stop(self):
        with self.lock:
            running = bool(self.run and self.run["status"] == "running")
        if running:
            self._stop.set()
        return {"ok": True, "stopped": running}

    def wait(self, timeout=120):
        """Για tests: περιμένει να τελειώσει η καμπάνια."""
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                if not self.run or self.run["status"] != "running":
                    return self.run
            time.sleep(0.02)
        return None

    # --- εκτέλεση ---
    def _next_ip(self):
        self._seq = self._seq % 230 + 1
        if self._seq + 10 == 66:  # 10.66.66.66 = ο «επιτιθέμενος» του απλού Lab
            self._seq += 1
        return ATT_NET + str(self._seq + 10)

    def _campaign(self, runs):
        status = "done"
        try:
            for i, (kind, variant) in enumerate(runs):
                if self._stop.is_set():
                    status = "stopped"
                    break
                with self.lock:
                    self.run["current"] = {"scenario": kind, "variant": variant, "title": SCENARIOS[kind]["title"],
                                           "pkts": 0, "total_pkts": 0, "started": time.time(), "index": i}
                try:
                    r = self._one(kind, variant)
                except Exception as e:  # ένα σενάριο που σκάει δεν σταματά την καμπάνια
                    r = self._result(kind, variant, skipped=True, reason=f"σφάλμα: {str(e)[:120]}")
                with self.lock:
                    self.run["results"].append(r)
                    self.run["done"] = i + 1
                    self.run["progress"] = int(100 * (i + 1) / len(runs))
                if self._stop.is_set() and i + 1 < len(runs):
                    status = "stopped"
                    break
        except Exception as e:
            status = "error"
            log("purple:", e)
        with self.lock:
            run = self.run
            run["status"], run["finished"], run["current"] = status, time.time(), None
            camp = {k: run[k] for k in ("id", "started", "finished", "status", "scenarios", "variants", "results")}
            camp["coverage"] = coverage(camp["results"])
            s = _summary(camp)
            camp["summary"] = {k: s[k] for k in ("runs", "detected", "missed", "skipped", "rate")}
            run["summary"], run["coverage"] = camp["summary"], camp["coverage"]
            self.history.append(camp)
            self.history = self.history[-HISTORY_MAX:]
            self._save()  # μέσα στο lock: όταν φανεί «done», το αρχείο έχει ήδη γραφτεί
        log(f"🟣 καμπάνια #{camp['id']}: {camp['summary']['detected']}/{camp['summary']['runs']} εντοπίστηκαν, "
            f"κάλυψη {camp['coverage']['score']}%")

    def _result(self, kind, variant, **kw):
        s = SCENARIOS[kind]
        r = {"scenario": kind, "variant": variant, "title": s["title"], "technique": s["technique"],
             "tool": s["tool"], "desc": s.get(variant), "expect": list(s["expect"]),
             "rule": rule_text(kind, self.st.cfg), "detected": False, "alerts": [], "alert_types": [],
             "matched": [], "latency": None, "pkts": 0, "sim_seconds": 0, "skipped": False, "reason": None}
        r.update(kw)
        return r

    def _one(self, kind, variant):
        st = self.st
        dets = {detector_for(e) for e in SCENARIOS[kind]["expect"]} - {None}
        if dets and not any(st.cfg["detectors"].get(d, True) for d in dets):
            return self._result(kind, variant, skipped=True,
                                reason="ο ανιχνευτής είναι απενεργοποιημένος στις ρυθμίσεις (detectors)")
        me = next((i for i in sorted(st.me) if ":" not in i), None) or "192.168.1.50"
        gw = st.gateway or "192.168.1.1"
        A, A2 = self._next_ip(), self._next_ip()
        n = int(A.rsplit(".", 1)[1])
        ctx = {"A": A, "A2": A2, "me": me, "gw": gw, "net": me.rsplit(".", 1)[0],
               "mac": "02:1a:b0:66:66:%02x" % n, "c2": C2_NET + str(n),
               "gw_mac": st.arp_first.get(gw), "dhcp": bool(st.dhcp_servers)}
        if kind == "arpspoof" and not ctx["gw_mac"]:
            return self._result(kind, variant, skipped=True,
                                reason="δεν ξέρω ακόμα τη MAC του router — χωρίς αυτήν δεν φαίνεται η αλλαγή")
        sched = schedule(kind, variant == "loud", ctx)
        ips = {A, A2, ctx["c2"]}
        added_gw_dhcp = kind == "rogue_dhcp" and not ctx["dhcp"]
        if kind == "synflood":
            self._clear_lab_cooldown("SYN flood", "synflood")
        with st.lock:
            st.lab_ips.update(ips)
            st.demo_geo[ctx["c2"]] = (None, "c2.lab.invalid")  # ώστε να μη γίνει geo/reverse-DNS lookup
            first_id = st.alert_seq
        ign = self._quiet_side_modules(ips, add=True)
        with self.lock:
            self.run["current"]["total_pkts"] = len(sched)
        total = sum(dt for dt, _ in sched)
        end = st.last_t if st.mode == "pcap" and st.last_t else time.time()
        t = end - total
        t0 = None
        per = (self.pace / len(sched)) if sched and self.pace else 0
        owed = 0.0
        sent = 0
        try:
            for dt, P in sched:
                if self._stop.is_set():
                    break
                t += dt
                P["t"] = t
                P.setdefault("len", 60)
                if t0 is None:
                    t0 = t
                st.process(P)
                sent += 1
                with self.lock:
                    self.run["current"]["pkts"] = sent
                owed += min(dt, per) if per else 0
                if owed >= 0.02:
                    time.sleep(owed)
                    owed = 0.0
            if self.settle:
                time.sleep(self.settle)
        finally:
            self._quiet_side_modules(ign, add=False)
            with st.lock:
                st.dhcp_servers.discard(A)
                if added_gw_dhcp:
                    st.dhcp_servers.discard(gw)
                for k in [k for k in st.creds if k[0] in ips]:
                    del st.creds[k]
                for k in [k for k in st.plain if k[0] in ips]:
                    del st.plain[k]
        al = [a for a in list(st.alerts) if a["id"] > first_id and a.get("lab") and a.get("actor") in ips]
        al.sort(key=lambda a: a["id"])
        exp = SCENARIOS[kind]["expect"]
        hit = [a for a in al if a["type"].startswith(exp)]
        lat = round(max(0.0, hit[0]["t"] - t0), 2) if hit and t0 is not None else None
        stopped = sent < len(sched)
        return self._result(
            kind, variant, detected=bool(hit), latency=lat, pkts=sent, sim_seconds=round(total, 1),
            alerts=[{"id": a["id"], "type": a["type"], "sev": a["sev"], "t": a["t"], "actor": a["actor"],
                     "target": a["target"], "detail": str(a.get("detail") or "")[:200],
                     "mitre": (a.get("mitre") or {}).get("id")} for a in al[:5]],
            alert_types=sorted({a["type"] for a in al}), matched=sorted({a["type"] for a in hit}),
            attacker=A, reason="σταμάτησε από τον χρήστη" if stopped else None, stopped=stopped)

    def _clear_lab_cooldown(self, typ, key):
        """Το cooldown του SYN flood είναι κοινό για όλους: αν το «έκαψε» προηγούμενη άσκηση του lab, το ξεκλειδώνουμε."""
        st = self.st
        with st.lock:
            last = next((a for a in st.alerts if a["type"] == typ), None)
            if last is not None and last.get("lab"):
                st.cooldown.pop((typ, key), None)
            w = getattr(st, "w_syn", None)  # SYN προηγούμενων ασκήσεων στο κοινό παράθυρο → λάθος «δράστης»
            dq = w.d.get("me") if w is not None else None
            if dq:
                keep = [x for x in dq if x[1] not in st.lab_ips]
                dq.clear()
                dq.extend(keep)

    def _quiet_side_modules(self, ips, add):
        """Οι εικονικές IP να μη «μαθαίνονται» ως συσκευές από το IoT firewall / encrypted-DNS."""
        done = []
        for name, attr in (("iotfw", "ignore"), ("encdns", "allow")):
            mod = getattr(self.st, name, None)
            s = getattr(mod, attr, None) if mod is not None else None
            if not isinstance(s, set):
                continue
            if add:
                new = set(ips) - s
                s.update(new)
                done.append((s, new))
        if not add:
            for s, new in ips:
                s.difference_update(new)
        return done
