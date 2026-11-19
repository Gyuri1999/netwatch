# -*- coding: utf-8 -*-
# Translation tables (executed by build_backend.py: X = exact, P = pattern template, T = template, R = raw regex)

# =====================================================================================================
# Alert types (exact) — identifiers in code, translated only as displayed text
# =====================================================================================================
TYPES = {
    "Διαρροή DNS εκτός VPN": "DNS leak outside the VPN",
    "Διαρροή IPv6 εκτός VPN": "IPv6 leak outside the VPN",
    "Εισερχόμενη σύνδεση": "Inbound connection",
    "Ύποπτη απάντηση DNS": "Suspicious DNS answer",
    "Ύποπτη εξερχόμενη θύρα": "Suspicious outbound port",
    "Κωδικός σε καθαρό κείμενο": "Password in clear text",
    "Beaconing (πιθανό C2)": "Beaconing (possible C2)",
    "Κίνηση από κόμβο Tor": "Traffic from a Tor node",
    "Σύνδεση σε κακόβουλη IP": "Connection to a malicious IP",
    "Κίνηση από κακόβουλη IP": "Traffic from a malicious IP",
    "Tor από συσκευή του δικτύου": "Tor from a device on your network",
    "Tor από συσκευή": "Tor from a device",
    "Νέα συσκευή": "New device",
    "Νέα χώρα για συσκευή": "New country for a device",
    "IoT συσκευή ξαναμίλησε": "IoT device is talking again",
    "Νέο MQTT topic": "New MQTT topic",
    "Εντολή MQTT σε ασυνήθιστη ώρα": "MQTT command at an unusual hour",
    "Εντολή MQTT": "MQTT command",
    "Άγνωστος MQTT client": "Unknown MQTT client",
    "IoT συσκευή σιώπησε": "IoT device went silent",
    "IoT συσκευή": "IoT device",
    "Υπηρεσία εκτός": "Service down",
    "Υπηρεσία επανήλθε": "Service back up",
    "Πιστοποιητικό λήγει": "Certificate expiring",
    "Deauth επίθεση στο Wi-Fi": "Deauth attack on Wi-Fi",
    "Deauth επίθεση": "Deauth attack",
    "Καναρίνι ESP32": "ESP32 canary",
    "OTA απορρίφθηκε": "OTA rejected",
    "OTA ενημέρωση": "OTA update",
    "Evil twin Wi-Fi (αισθητήρας)": "Evil twin Wi-Fi (sensor)",
    "Άγνωστο access point": "Unknown access point",
    "DNS hijacking στο Wi-Fi": "DNS hijacking on Wi-Fi",
    "TLS interception στο Wi-Fi": "TLS interception on Wi-Fi",
    "Ανοιχτό Wi-Fi": "Open Wi-Fi",
    "Παγίδα": "Honeypot",
    "Διαρροή": "Leak",
    "Κανόνας:": "Rule:",
    "Κανόνας": "Rule",
    "δοκιμή": "test",
}
for k, v in TYPES.items():
    X(k, v)

# Built-in rules (rules/default.yaml): titles become "Κανόνας: <title>"
RULE_TITLES = {
    "Σύνδεση Telnet": "Telnet connection",
    "SMB προς το Internet": "SMB to the Internet",
    "RDP/VNC από το Internet": "RDP/VNC from the Internet",
    "Συσκευή του LAN σε θύρα backdoor": "LAN device on a backdoor port",
    "Ύποπτο domain (TLD)": "Suspicious domain (TLD)",
}
RULE_DESCS = {
    "Κάποιος ανοίγει Telnet — ό,τι πληκτρολογεί, μαζί με τον κωδικό, ταξιδεύει χωρίς κρυπτογράφηση":
        "Someone is opening Telnet — everything they type, password included, travels unencrypted",
    "Κοινή χρήση αρχείων Windows (SMB) προς δημόσια IP — δεν πρέπει να συμβαίνει ποτέ, πιθανή διαρροή":
        "Windows file sharing (SMB) to a public IP — this should never happen, possible leak",
    "Σύνδεση απομακρυσμένης επιφάνειας εργασίας από το Internet — έλεγξε το port forwarding του router":
        "Remote desktop connection from the Internet — check the port forwarding on your router",
    "Μια συσκευή του σπιτιού (όχι μόνο εσύ) συνδέεται σε θύρα που χρησιμοποιούν backdoors/botnets":
        "A device in your home (not just you) is connecting to a port used by backdoors/botnets",
    "Ερώτημα DNS για κατάληξη που χρησιμοποιείται δυσανάλογα συχνά σε phishing/malware":
        "DNS query for a domain ending that is used disproportionately often for phishing/malware",
}
for k, v in RULE_TITLES.items():
    X(k, v)
    X("Κανόνας: " + k, "Rule: " + v)
for k, v in RULE_DESCS.items():
    X(k, v)
P("Κανόνας: {}", "Rule: {1}")
P("Παγίδα: σύνδεση σε ψεύτικο {}", "Honeypot: connection to a fake {1}")

# rule alert detail: Κανόνας «id»: <what>[ — <description>]
WHAT = [T("{d} διαφορετικά {s} σε {n}s", "{1} different {2} in {3}s"),
        T("{d} πακέτα σε {n}s", "{1} packets in {2}s"),
        T("ταίριαξε πακέτο", "packet matched")]
X("ταίριαξε πακέτο", "packet matched")
for w in WHAT:
    for gd, ed in RULE_DESCS.items():
        P(T("Κανόνας «{}»: ", "Rule “{1}”: ") + w + T(" — " + gd, " — " + ed))
    P(T("Κανόνας «{}»: ", "Rule “{1}”: ") + w + T(" — {}", " — {1}"))
    P(T("Κανόνας «{}»: ", "Rule “{1}”: ") + w)

# =====================================================================================================
# detect.py — alert details
# =====================================================================================================
P("Το VPN ({}) είναι ενεργό, αλλά ερωτήματα DNS (π.χ. {}) βγαίνουν ανοιχτά από το {} προς {}: το Wi-Fi και ο πάροχος βλέπουν ποια sites επισκέπτεσαι.",
  "Your VPN ({1}) is on, but DNS queries (e.g. {2}) are leaving unencrypted through {3} to {4}: the Wi-Fi and your provider can see which sites you visit.")
P("Το VPN ({}) είναι ενεργό, αλλά ερωτήματα DNS βγαίνουν ανοιχτά από το {} προς {}: το Wi-Fi και ο πάροχος βλέπουν ποια sites επισκέπτεσαι.",
  "Your VPN ({1}) is on, but DNS queries are leaving unencrypted through {2} to {3}: the Wi-Fi and your provider can see which sites you visit.")
P("Το VPN ({}) είναι ενεργό, αλλά κίνηση IPv6 προς {} βγαίνει απευθείας από το {} — το site βλέπει την πραγματική σου σύνδεση.",
  "Your VPN ({1}) is on, but IPv6 traffic to {2} goes out directly through {3} — the site sees your real connection.")
X("κανένα", "none")
P("Πακέτα TCP με ασυνήθιστα flags [κανένα] — εργαλείο τύπου nmap -s{s}",
  "TCP packets with unusual flags [none] — a tool like nmap -s{1}")
P("Πακέτα TCP με ασυνήθιστα flags [{*}] — εργαλείο τύπου nmap -s{s}",
  "TCP packets with unusual flags [{1}] — a tool like nmap -s{2}")
P("{d} απόπειρες σε {d} στόχο(ους) μέσα σε {n}s (TCP SYN scan)", "{1} attempts on {2} target(s) within {3}s (TCP SYN scan)")
P("Μη αναμενόμενο SYN από το Internet στη θύρα {d} ({})", "Unexpected SYN from the Internet to port {1} ({2})")
P("{d} SYN σε {n}s προς εσένα — επίθεση άρνησης υπηρεσίας (DoS)", "{1} SYNs in {2}s aimed at you — a denial-of-service (DoS) attack")
P("{d} συνδέσεις στην υπηρεσία {} ({d}) σε {n}s — δοκιμή κωδικών", "{1} connections to the {2} service ({3}) in {4}s — someone is guessing passwords")
P("{d} διαφορετικές UDP θύρες/στόχοι σε {n}s", "{1} different UDP ports/targets in {2}s")
P("Ping σε {d} διαφορετικές IP σε {n}s — χαρτογράφηση δικτύου", "Pings to {1} different IPs in {2}s — someone is mapping the network")
P("{d} ping σε {n}s προς εσένα", "{1} pings in {2}s aimed at you")
P("Νέος DHCP server ({}) εκτός από {} — μπορεί να σε στείλει σε ψεύτικο gateway/DNS",
  "New DHCP server ({1}) besides {2} — it could send you to a fake gateway/DNS")
X("Απάντηση DNS από διακομιστή που δεν ρωτήθηκε — πιθανό DNS spoofing",
  "DNS answer from a server that wasn't asked — possible DNS spoofing")
X("Είναι το δικό σου Tor: τρέχει στο Mac σου και συνδέεται σε κόμβους (relays) του δικτύου Tor σε αυτή τη θύρα. Αναμενόμενο — δεν χρειάζεται να κάνεις τίποτα.",
  "It's your own Tor: it runs on your Mac and connects to Tor network nodes (relays) on this port. Expected — you don't need to do anything.")
P("Ο υπολογιστής σου συνδέθηκε στη θύρα {d} ({}) αυτής της IP", "Your computer connected to port {1} ({2}) of this IP")
# cleartext credentials
CRED_WHAT = [
    T("η συνεδρία Telnet (ό,τι πληκτρολογείς, μαζί με τον κωδικό)", "the Telnet session (everything you type, password included)"),
    T("το όνομα χρήστη «{}» (χωρίς κωδικό — άρα ο broker μάλλον δέχεται σχεδόν τους πάντες)",
      "the username “{1}” (no password — so the broker probably lets almost anyone in)"),
    T("ο κωδικός MQTT του «{}» (client {}) — με αυτόν, όποιος τον δει στέλνει εντολές στις συσκευές σου. Βάλε TLS (8883)",
      "the MQTT password of “{1}” (client {2}) — with it, anyone who sees it can send commands to your devices. Use TLS (8883)"),
    T("ο κωδικός MQTT του «{}» — με αυτόν, όποιος τον δει στέλνει εντολές στις συσκευές σου. Βάλε TLS (8883)",
      "the MQTT password of “{1}” — with it, anyone who sees it can send commands to your devices. Use TLS (8883)"),
    T("ο κωδικός του χρήστη «{}»", "the password of user “{1}”"),
    T("ο κωδικός", "the password"),
]
for w in CRED_WHAT:
    P(T("{} προς {}:{d} — ", "{1} to {2}:{3} — ") + w + T(" ταξιδεύει χωρίς κρυπτογράφηση· όποιος «ακούει» το δίκτυο τον βλέπει",
                                                       " travels unencrypted; anyone “listening” on the network can see it"))
X("HTTP φόρμα", "HTTP form")
# HTTP form + each "what" (the proto label itself is Greek) — must come before the generic ones above
_n = len(PATS)
for w in CRED_WHAT:
    P(T("HTTP φόρμα προς {}:{d} — ", "HTTP form to {1}:{2} — ") + w + T(" ταξιδεύει χωρίς κρυπτογράφηση· όποιος «ακούει» το δίκτυο τον βλέπει",
                                                                    " travels unencrypted; anyone “listening” on the network can see it"))
PATS[_n - len(CRED_WHAT):_n - len(CRED_WHAT)] = PATS[_n:]
del PATS[_n + len(CRED_WHAT):]

P("Η {} ανοίγει σύνδεση στο {} κάθε ~{d}s (απόκλιση ±{d}%), {d} φορές στη σειρά — τέτοιο «ρολόι» είναι τυπικό για malware που ζητάει εντολές",
  "{1} opens a connection to {2} every ~{3}s (jitter ±{4}%), {5} times in a row — this kind of “clockwork” is typical of malware asking for commands")
P("{d} μοναδικά, τυχαία subdomains του {} σε {n}s (π.χ. {}…) — δεδομένα κρυμμένα μέσα σε ερωτήματα DNS (exfiltration / C2)",
  "{1} unique, random subdomains of {2} in {3}s (e.g. {4}…) — data hidden inside DNS queries (exfiltration / C2)")
P("{d} ανύπαρκτα «τυχαία» domains σε {n}s (π.χ. {}) — malware που ψάχνει τον server του (Domain Generation Algorithm)",
  "{1} non-existent “random” domains in {2}s (e.g. {3}) — malware looking for its server (Domain Generation Algorithm)")
P("Κάποιος που κρύβεται πίσω από Tor (κόμβος εξόδου {}) χτυπά την {}. Τα bots/σαρωτές χρησιμοποιούν συχνά Tor για να μη φαίνονται.",
  "Someone hiding behind Tor (exit node {1}) is hitting {2}. Bots and scanners often use Tor to stay hidden.")
P("Η {} επικοινωνεί με {} που υπάρχει στη λίστα {} — πιθανή μόλυνση από botnet!",
  "{1} is talking to {2}, which is on the list {3} — possible botnet infection!")
P("Η {} επικοινωνεί με {} που υπάρχει στη λίστα {}", "{1} is talking to {2}, which is on the list {3}")
P("Πακέτα από IP που υπάρχει στη λίστα {}", "Packets from an IP that is on the list {1}")
X("Είναι το δικό σου Tor (Tor Browser / tor) στο Mac. Αναμενόμενο.", "It's your own Tor (Tor Browser / tor) on your Mac. Expected.")
TOR_TAIL = (" Αν δεν τρέχεις Tor εκεί, κάτι κρύβει την κίνησή του — έτσι μιλάει συχνά το malware με τον «αφέντη» του (C2).",
            " If you don't run Tor there, something is hiding its traffic — this is often how malware talks to its “master” (C2).")
P("Η {} (IoT συσκευή!) συνδέεται σε κόμβο Tor {}." + TOR_TAIL[0], "{1} (an IoT device!) is connecting to Tor node {2}." + TOR_TAIL[1])
P("Η {} συνδέεται σε κόμβο Tor {}." + TOR_TAIL[0], "{1} is connecting to Tor node {2}." + TOR_TAIL[1])
P("Η {} (IoT συσκευή!) συνδέεται σε κόμβο Tor {}.", "{1} (an IoT device!) is connecting to Tor node {2}.")
P("Η {} συνδέεται σε κόμβο Tor {}.", "{1} is connecting to Tor node {2}.")
X(TOR_TAIL[0], TOR_TAIL[1])
P("Πρώτη φορά στο δίκτυο: {} με MAC {} (τυχαία MAC — μάλλον κινητό). Την αναγνωρίζεις;",
  "First time on the network: {1} with MAC {2} (random MAC — probably a phone). Do you recognise it?")
P("Πρώτη φορά στο δίκτυο: {} με MAC {}. Την αναγνωρίζεις;", "First time on the network: {1} with MAC {2}. Do you recognise it?")
P("ARP ερωτήσεις για {d} IP σε {n}s — κάποιος σκανάρει το LAN", "ARP requests for {1} IPs in {2}s — someone is scanning the LAN")
P("Η IP {} του router άλλαξε MAC {} → {} (ανήκει στη {}). Πιθανό Man-in-the-Middle.",
  "The router's IP {1} changed MAC {2} → {3} (it belongs to {4}). Possible Man-in-the-Middle.")
P("Η IP {} του router άλλαξε MAC {} → {}. Πιθανό Man-in-the-Middle.",
  "The router's IP {1} changed MAC {2} → {3}. Possible Man-in-the-Middle.")
P("Η IP {} άλλαξε MAC {} → {} (ανήκει στη {}). Πιθανό Man-in-the-Middle.",
  "IP {1} changed MAC {2} → {3} (it belongs to {4}). Possible Man-in-the-Middle.")
P("Η IP {} άλλαξε MAC {} → {}. Πιθανό Man-in-the-Middle.", "IP {1} changed MAC {2} → {3}. Possible Man-in-the-Middle.")
P("{d} ARP replies σε {n}s από {}", "{1} ARP replies in {2}s from {3}")
P("Θύρα {} — συχνά backdoor/κακόβουλο λογισμικό", "Port {1} — often a backdoor/malware")

# =====================================================================================================
# detect.py — Audit (🛡) checks
# =====================================================================================================
AUDIT_TITLES = {
    "Κωδικοί σε καθαρό κείμενο": "Passwords in clear text",
    "Επικίνδυνες υπηρεσίες στο LAN": "Risky services on the LAN",
    "Επιθέσεις την τελευταία ώρα": "Attacks in the last hour",
    "Επικοινωνία με γνωστές κακόβουλες IP": "Talking to known malicious IPs",
    "Άγνωστες συσκευές": "Unknown devices",
    "Ιστοσελίδες χωρίς HTTPS": "Websites without HTTPS",
    "DNS χωρίς κρυπτογράφηση": "Unencrypted DNS",
}
AUDIT_ADVICE = {
    "Άλλαξε αυτούς τους κωδικούς και χρησιμοποίησε την ασφαλή εκδοχή: SFTP αντί FTP, SSH αντί Telnet, HTTPS αντί HTTP, IMAPS/POP3S αντί IMAP/POP3.":
        "Change these passwords and use the secure version: SFTP instead of FTP, SSH instead of Telnet, HTTPS instead of HTTP, IMAPS/POP3S instead of IMAP/POP3.",
    "Συνέχισε να χρησιμοποιείς HTTPS και κρυπτογραφημένα πρωτόκολλα.": "Keep using HTTPS and encrypted protocols.",
    "Κλείσε ό,τι δεν χρησιμοποιείς, άλλαξε default κωδικούς, βάλε τις IoT συσκευές σε δίκτυο επισκεπτών.":
        "Turn off what you don't use, change default passwords, put IoT devices on a guest network.",
    "Το NetWatch βλέπει μόνο υπηρεσίες που χρησιμοποιήθηκαν· για πλήρη εικόνα κάνε σάρωση με nmap.":
        "NetWatch only sees services that were used; for the full picture, scan with nmap.",
    "Δες την καρτέλα ⚠ Επιθέσεις και το «ℹ Τι σημαίνει;» σε κάθε μία.":
        "Check the ⚠ Attacks tab and the “ℹ What does it mean?” on each one.",
    "Βρες ποια συσκευή του LAN μιλάει μαζί τους (🔎 Λεπτομέρειες) και έλεγξέ τη για malware.":
        "Find which LAN device is talking to them (🔎 Details) and check it for malware.",
    "Αν δεν τις αναγνωρίζεις, άλλαξε τον κωδικό του Wi-Fi (WPA2/WPA3).": "If you don't recognise them, change your Wi-Fi password (WPA2/WPA3).",
    "Ενεργοποίησε «HTTPS-Only mode» στον browser.": "Turn on “HTTPS-Only mode” in your browser.",
    "Ενεργοποίησε DNS over HTTPS (DoH) στον browser ή στο σύστημα (π.χ. 1.1.1.1, Quad9).":
        "Turn on DNS over HTTPS (DoH) in your browser or system (e.g. 1.1.1.1, Quad9).",
}
for k, v in AUDIT_TITLES.items():
    X(k, v)
for k, v in AUDIT_ADVICE.items():
    X(k, v)
    X("— " + k, "— " + v)  # weekly report: "<b>title</b> — advice"
P("{d} σύνδεση(εις) έστειλαν κωδικό χωρίς κρυπτογράφηση ({}).", "{1} connection(s) sent a password without encryption ({2}).")
X("Δεν είδα κανέναν κωδικό να ταξιδεύει ακρυπτογράφητος.", "I didn't see any password travelling unencrypted.")
P("Δεν είδα επικίνδυνες υπηρεσίες ({d} υπηρεσίες συνολικά).", "I didn't see any risky services ({1} services in total).")
P("{d} ειδοποιήσεις ({d} υψηλής σοβαρότητας) από {d} πηγές.", "{1} alerts ({2} high severity) from {3} sources.")
X("Καμία.", "None.")
P("{d} IP από λίστες threat intel.", "{1} IPs from threat-intel lists.")
P("{d} νέα(ες) συσκευή(ές) μπήκαν στο δίκτυο: {}", "{1} new device(s) joined the network: {2}")
X("Καμία νέα συσκευή την τελευταία ώρα.", "No new devices in the last hour.")
P("{n}% της κίνησης web είναι ακρυπτογράφητο HTTP.", "{1}% of web traffic is unencrypted HTTP.")
P("Μόνο {n}% της κίνησης web είναι HTTP.", "Only {1}% of web traffic is HTTP.")
P("{d} ερωτήματα DNS στάλθηκαν «ανοιχτά» — ο πάροχος και όποιος είναι στη μέση βλέπουν κάθε site που επισκέπτεσαι.",
  "{1} DNS queries were sent “in the open” — your provider and anyone in the middle can see every site you visit.")
X("Δεν είδα ακρυπτογράφητο DNS.", "I didn't see any unencrypted DNS.")
# services detail "<n> υψηλού και <m> μεσαίου κινδύνου: <svc> στη <ip>, <svc> στη <ip>, ..." (up to 5 items).
# Each group spans the text between two "στη", so n items need only n+1 groups.
for nitems in (5, 4, 3, 2, 1):
    P(T("{d} υψηλού και {d} μεσαίου κινδύνου: " + " στη ".join(["{}"] * (nitems + 1)),
        "{1} high-risk and {2} medium-risk: " + " on ".join("{%d}" % (i + 3) for i in range(nitems + 1))))
P("Δεν είδα επικίνδυνες υπηρεσίες ({d} υπηρεσίες συνολικά).", "I didn't see any risky services ({1} services in total).")
P("{d} ειδοποιήσεις ({d} υψηλής σοβαρότητας) από {d} πηγές.", "{1} alerts ({2} high severity) from {3} sources.")
X("Καμία.", "None.")
P("{d} IP από λίστες threat intel.", "{1} IPs from threat-intel lists.")
P("{d} νέα(ες) συσκευή(ές) μπήκαν στο δίκτυο: {}", "{1} new device(s) joined the network: {2}")
X("Καμία νέα συσκευή την τελευταία ώρα.", "No new devices in the last hour.")
P("{n}% της κίνησης web είναι ακρυπτογράφητο HTTP.", "{1}% of web traffic is unencrypted HTTP.")
P("Μόνο {n}% της κίνησης web είναι HTTP.", "Only {1}% of web traffic is HTTP.")
P("{d} ερωτήματα DNS στάλθηκαν «ανοιχτά» — ο πάροχος και όποιος είναι στη μέση βλέπουν κάθε site που επισκέπτεσαι.",
  "{1} DNS queries were sent “in the open” — your provider and anyone in the middle can see every site you visit.")
X("Δεν είδα ακρυπτογράφητο DNS.", "I didn't see any unencrypted DNS.")
# services detail with its list of "<svc> στη <ip>" items (up to 3 items fully translated)
_svc = T("{s} στη {s}", "{1} on {2}")
for nitems in (3, 2, 1):
    t = T("{d} υψηλού και {d} μεσαίου κινδύνου: ", "{1} high-risk and {2} medium-risk: ") + _svc
    for _ in range(nitems - 1):
        t = t + T(", ", ", ") + _svc
    P(t)

# RISKY_SERVICES (why) — shown in Audit / device details
RISKY = {
    "Telnet: όλα χωρίς κρυπτογράφηση, ο νο1 στόχος των botnets (Mirai)": "Telnet: everything unencrypted, the #1 target of botnets (Mirai)",
    "FTP: κωδικοί και αρχεία χωρίς κρυπτογράφηση": "FTP: passwords and files unencrypted",
    "RDP: απομακρυσμένη επιφάνεια εργασίας, κύρια πόρτα εισόδου για ransomware": "RDP: remote desktop, a main way in for ransomware",
    "VNC: απομακρυσμένος έλεγχος οθόνης, συχνά με αδύναμο κωδικό": "VNC: remote screen control, often with a weak password",
    "TR-069: απομακρυσμένη διαχείριση router, στόχος botnets": "TR-069: remote router management, a botnet target",
    "MySQL ανοιχτή στο δίκτυο": "MySQL open to the network",
    "PostgreSQL ανοιχτή στο δίκτυο": "PostgreSQL open to the network",
    "Redis: συχνά χωρίς κωδικό → εκτέλεση κώδικα": "Redis: often no password → code execution",
    "MongoDB: συχνά χωρίς κωδικό": "MongoDB: often no password",
    "SMB: κοινόχρηστα αρχεία, στόχος ransomware (WannaCry)": "SMB: shared files, a ransomware target (WannaCry)",
    "NetBIOS/SMB v1: παλιό και ευάλωτο": "NetBIOS/SMB v1: old and vulnerable",
    "UPnP: προγράμματα μπορούν να ανοίξουν θύρες στο router χωρίς να ρωτήσουν": "UPnP: programs can open ports on the router without asking",
    "SNMP: συχνά με default κωδικό «public»": "SNMP: often with the default password “public”",
    "RTSP: ροή βίντεο κάμερας": "RTSP: camera video stream",
    "MQTT: μηνύματα IoT χωρίς κρυπτογράφηση": "MQTT: IoT messages unencrypted",
    "HTTP: σελίδα διαχείρισης χωρίς HTTPS": "HTTP: admin page without HTTPS",
    "HTTP-alt: σελίδα διαχείρισης χωρίς HTTPS": "HTTP-alt: admin page without HTTPS",
    "Εκτυπωτής (JetDirect): δέχεται εργασίες από οποιονδήποτε": "Printer (JetDirect): accepts jobs from anyone",
    "SSH: ασφαλές αν έχει κλειδιά ή δυνατό κωδικό": "SSH: safe with keys or a strong password",
}
for k, v in RISKY.items():
    X(k, v)
X("Tor exit κόμβοι", "Tor exit nodes")

# TLS findings (pentest.py / demo.py)
P("Παλιό πρωτόκολλο {} — σπασμένο, πρέπει TLS 1.2+", "Old protocol {1} — broken, needs TLS 1.2+")
P("Το πιστοποιητικό έληξε πριν {d} μέρες", "The certificate expired {1} days ago")
X("Self-signed πιστοποιητικό — ο browser δεν μπορεί να ελέγξει ότι μιλάς με τη σωστή συσκευή (κίνδυνος MITM)",
  "Self-signed certificate — the browser can't check that you're talking to the right device (MITM risk)")

# =====================================================================================================
# baseline.py
# =====================================================================================================
BL_TAIL = (" Μέχρι τώρα: {}. Αν δεν άλλαξε κάτι (ενημέρωση, νέα εφαρμογή), δες τι είναι αυτός ο server.",
           " Until now: {}. If nothing changed (an update, a new app), check what this server is.")
P(T("Η {} (IoT) μίλησε για πρώτη φορά με {} ({}).", "{1} (IoT) talked to {2} ({3}) for the first time.") + T(BL_TAIL[0], BL_TAIL[1].replace("{}", "{1}")))
P(T("Η {} μίλησε για πρώτη φορά με {} ({}).", "{1} talked to {2} ({3}) for the first time.") + T(BL_TAIL[0], BL_TAIL[1].replace("{}", "{1}")))

# =====================================================================================================
# mqttwatch.py
# =====================================================================================================
P("Το «{}» ξαναστέλνει μηνύματα στο MQTT.", "“{1}” is sending MQTT messages again.")
P("Πρώτη φορά βλέπω το topic «{}» (περιεχόμενο: {}). Αν δεν πρόσθεσες κάτι καινούργιο, κάποιος άλλος γράφει στον broker σου.",
  "First time I see the topic “{1}” (content: {2}). If you didn't add something new, someone else is writing to your broker.")
P("Εντολή στο «{}» = {} στις {}. Αν δεν ήταν δικός σου αυτοματισμός, κάποιος ελέγχει τις συσκευές σου.",
  "Command on “{1}” = {2} at {3}. If it wasn't one of your automations, someone is controlling your devices.")
P("Νέος client «{}» (χρήστης {}) συνδέθηκε στον broker από {}. Αν δεν είναι δική σου καινούργια συσκευή, άλλαξε κωδικούς και έλεγξε τα ACL.",
  "New client “{1}” (user {2}) connected to the broker from {3}. If it isn't a new device of yours, change passwords and check the ACLs.")
P("Νέος client «{}» συνδέθηκε στον broker από {}. Αν δεν είναι δική σου καινούργια συσκευή, άλλαξε κωδικούς και έλεγξε τα ACL.",
  "New client “{1}” connected to the broker from {2}. If it isn't a new device of yours, change passwords and check the ACLs.")
P("Το «{}» έστελνε κάθε ~{d}″ και σιωπά εδώ και {d}′. Κόλλησε, έπεσε το Wi-Fi του — ή κάποιος το «πετάει» από το δίκτυο (deauth).",
  "“{1}” was sending every ~{2}″ and has been silent for {3}′. It froze, its Wi-Fi dropped — or someone is kicking it off the network (deauth).")
X("Λείπει η βιβλιοθήκη paho-mqtt (pip install paho-mqtt).", "The paho-mqtt library is missing (pip install paho-mqtt).")
X("Λείπει η βιβλιοθήκη paho-mqtt.", "The paho-mqtt library is missing.")
P("Ο broker αρνήθηκε τη σύνδεση: {} (σωστός χρήστης/κωδικός;)", "The broker refused the connection: {1} (right username/password?)")
P("Ο broker αρνήθηκε τη σύνδεση: {}", "The broker refused the connection: {1}")
P("Αποσύνδεση από τον broker ({}) — ξαναδοκιμάζω…", "Disconnected from the broker ({1}) — retrying…")

# =====================================================================================================
# health.py
# =====================================================================================================
X("δεν απαντά στο ping", "doesn't answer ping")
X("ESP32 κήπου", "Garden ESP32")
P("Το «ESP32 κήπου» ({}) δεν απαντά: δεν απαντά στο ping.", "“Garden ESP32” ({1}) isn't responding: doesn't answer ping.")
P("Το «{}» ({}) δεν απαντά: δεν απαντά στο ping.", "“{1}” ({2}) isn't responding: doesn't answer ping.")
P("Το «{}» ({}) δεν απαντά: {}.", "“{1}” ({2}) isn't responding: {3}.")
P("Το «ESP32 κήπου» απαντά ξανά (ήταν εκτός {d}′).", "“Garden ESP32” is responding again (it was down for {1}′).")
P("Το «{}» απαντά ξανά (ήταν εκτός {d}′).", "“{1}” is responding again (it was down for {2}′).")
CERT_TAIL = (" Ανανέωσέ το (π.χ. ./tools/mosquitto-tls.sh για τον broker).", " Renew it (e.g. ./tools/mosquitto-tls.sh for the broker).")
P("Το πιστοποιητικό TLS του «{}» έληξε." + CERT_TAIL[0], "The TLS certificate of “{1}” has expired." + CERT_TAIL[1])
P("Το πιστοποιητικό TLS του «{}» λήγει σε {d} μέρες." + CERT_TAIL[0], "The TLS certificate of “{1}” expires in {2} days." + CERT_TAIL[1])

# =====================================================================================================
# sensor.py (ESP32 sensor / canary / OTA)
# =====================================================================================================
NEAR = [T(", σήμα {d} dBm (πολύ κοντά!)", ", signal {1} dBm (very close!)"), T(", σήμα {d} dBm", ", signal {1} dBm"), T("", "")]
DEAUTH_TAIL = T(". Κάποιος «πετάει» συσκευές από το Wi-Fi — συχνά για να τις σπρώξει σε ψεύτικο δίκτυο ή να πιάσει το handshake.",
                ". Someone is kicking devices off the Wi-Fi — often to push them onto a fake network or to capture the handshake.")
for nr in NEAR:
    P(T("Ο αισθητήρας {} μέτρησε {d} πακέτα αποσύνδεσης/δευτ. στο κανάλι {} από {} προς ΟΛΟΥΣ (broadcast)",
        "Sensor {1} counted {2} deauthentication packets/sec on channel {3} from {4} to EVERYONE (broadcast)") + nr + DEAUTH_TAIL)
    P(T("Ο αισθητήρας {} μέτρησε {d} πακέτα αποσύνδεσης/δευτ. στο κανάλι {} από {} προς {}",
        "Sensor {1} counted {2} deauthentication packets/sec on channel {3} from {4} to {5}") + nr + DEAUTH_TAIL)
CANARY_TAIL = T(". Κανείς νόμιμος δεν έχει λόγο να συνδεθεί εκεί: η συσκευή σκανάρει ή δοκιμάζει κωδικούς.",
                ". Nobody legitimate has a reason to connect there: the device is scanning or trying passwords.")
CAN_HEAD = T("Η {} άγγιξε το ψεύτικο {} (θύρα {}) του καναρινιού {}", "{1} touched the fake {2} (port {3}) of canary {4}")
P(CAN_HEAD + T(" — δοκίμασε χρήστη «{}» — έστειλε: {}", " — tried user “{1}” — sent: {2}") + CANARY_TAIL)
P(CAN_HEAD + T(" — δοκίμασε χρήστη «{}»", " — tried user “{1}”") + CANARY_TAIL)
P(CAN_HEAD + T(" — έστειλε: {}", " — sent: {1}") + CANARY_TAIL)
P(CAN_HEAD + CANARY_TAIL)
X("χωρίς λόγο", "no reason given")
P("Ο {} αρνήθηκε ενημέρωση firmware {} (χωρίς λόγο) και μένει στην {}. Αν δεν έκανες εσύ κάτι λάθος στην υπογραφή, κάποιος σερβίρει πειραγμένο firmware: έλεγξε τον OTA server.",
  "{1} refused firmware update {2} (no reason given) and stays on {3}. If you didn't get the signing wrong yourself, someone is serving tampered firmware: check the OTA server.")
P("Ο {} αρνήθηκε ενημέρωση firmware {} ({}) και μένει στην {}. Αν δεν έκανες εσύ κάτι λάθος στην υπογραφή, κάποιος σερβίρει πειραγμένο firmware: έλεγξε τον OTA server.",
  "{1} refused firmware update {2} ({3}) and stays on {4}. If you didn't get the signing wrong yourself, someone is serving tampered firmware: check the OTA server.")
P("Ο {} ενημερώθηκε και επιβεβαίωσε ότι δουλεύει: {}.", "{1} updated and confirmed it works: {2}.")
for nr in NEAR:
    P(T("Ο αισθητήρας {} βλέπει δεύτερο «{}» ({}, κανάλι {}) με ΑΣΘΕΝΕΣΤΕΡΗ ασφάλεια: {}",
        "Sensor {1} sees a second “{2}” ({3}, channel {4}) with WEAKER security: {5}") + nr +
      T(". Κάποιος μάλλον στήνει ψεύτικο αντίγραφο του δικτύου σου.", ". Someone is probably setting up a fake copy of your network."))
    P(T("Ο αισθητήρας {} βλέπει «{}» από άγνωστο BSSID {} (κανάλι {}, {})", "Sensor {1} sees “{2}” from unknown BSSID {3} (channel {4}, {5})") + nr +
      T(". Αν πρόσθεσες repeater/mesh, πρόσθεσέ το στα ALLOWED_BSSIDS· αλλιώς ψάξ' το.",
        ". If you added a repeater/mesh, add it to ALLOWED_BSSIDS; otherwise track it down."))
P("καναρίνι {}", "canary {1}")
P("αισθητήρας {}", "sensor {1}")

# =====================================================================================================
# netwatch.py — honeypot alert, demo playbooks; capture.py
# =====================================================================================================
X("εσύ", "you")
P("θύρα {d} ({}) — έστειλε: «{}»", "port {1} ({2}) — sent: “{3}”")
P("θύρα {d} ({})", "port {1} ({2})")
X("Ήταν δοκιμή από τον ίδιο σου τον υπολογιστή.", "It was a test from your own computer.")
PB_NAMES = {"Παγίδα/καναρίνι → μπλόκαρε 30′": "Honeypot/canary → block 30′",
            "Σοβαρή επίθεση από το LAN → κινητό": "Serious attack from the LAN → phone"}
for k, v in PB_NAMES.items():
    X(k, v)
P("CTF · {}", "CTF · {1}")

# =====================================================================================================
# wifiguard.py (☕ Wi‑Fi Guard)
# =====================================================================================================
SEC = {"Ανοιχτό (χωρίς κωδικό)": "Open (no password)"}
for k, v in SEC.items():
    X(k, v)
MAC_SHARING = {
    "Απομακρυσμένη σύνδεση (SSH)": "Remote Login (SSH)",
    "Κοινή χρήση αρχείων (SMB)": "File Sharing (SMB)",
    "Κοινή χρήση αρχείων (AFP)": "File Sharing (AFP)",
    "Κοινή χρήση οθόνης (VNC)": "Screen Sharing (VNC)",
    "Απομακρυσμένη διαχείριση (ARD)": "Remote Management (ARD)",
    "Kerberos (Back to My Mac / κοινή χρήση)": "Kerberos (Back to My Mac / sharing)",
    "Δέκτης AirPlay": "AirPlay Receiver",
    "Κοινή χρήση εκτυπωτή": "Printer Sharing",
}
MAC_FIX = {
    "Ρυθμίσεις → Γενικά → Κοινή χρήση → Απομακρυσμένη σύνδεση: off": "Settings → General → Sharing → Remote Login: off",
    "Ρυθμίσεις → Γενικά → Κοινή χρήση → Κοινή χρήση αρχείων: off": "Settings → General → Sharing → File Sharing: off",
    "Ρυθμίσεις → Γενικά → Κοινή χρήση → Κοινή χρήση οθόνης: off": "Settings → General → Sharing → Screen Sharing: off",
    "Ρυθμίσεις → Γενικά → Κοινή χρήση → Απομακρυσμένη διαχείριση: off": "Settings → General → Sharing → Remote Management: off",
    "Κλείσε τις υπηρεσίες Κοινής χρήσης που δεν χρειάζεσαι": "Turn off the Sharing services you don't need",
    "Ρυθμίσεις → Γενικά → AirDrop και Handoff → Δέκτης AirPlay: off": "Settings → General → AirDrop & Handoff → AirPlay Receiver: off",
    "Ρυθμίσεις → Γενικά → Κοινή χρήση → Κοινή χρήση εκτυπωτή: off": "Settings → General → Sharing → Printer Sharing: off",
    "Ρύθμισε τη βάση να ακούει μόνο στο 127.0.0.1": "Set the database to listen only on 127.0.0.1",
    "Ρύθμισε το Redis να ακούει μόνο στο 127.0.0.1": "Set Redis to listen only on 127.0.0.1",
}
for k, v in MAC_SHARING.items():
    X(k, v)
for k, v in MAC_FIX.items():
    X(k, v)

WIFI_TITLES = {"Κρυπτογράφηση Wi-Fi": "Wi-Fi encryption", "Firewall του Mac": "Mac firewall",
               "Υπηρεσίες ανοιχτές στο δίκτυο": "Services open to the network", "Ιδιωτική διεύθυνση Wi-Fi": "Private Wi-Fi address"}
for k, v in WIFI_TITLES.items():
    X(k, v)

# check (detail, fix) pairs; the alert detail is detail + " → " + fix
WIFI_CHECKS = [
    (T("Το «{}» είναι ανοιχτό: ό,τι δεν είναι HTTPS/VPN το βλέπουν όλοι γύρω σου.", "“{1}” is open: anything that isn't HTTPS/VPN can be seen by everyone around you."),
     T("Χρησιμοποίησε VPN ή το hotspot του κινητού σου.", "Use a VPN or your phone's hotspot.")),
    (T("Το «{}» έχει WEP — σπάει σε λίγα λεπτά.", "“{1}” uses WEP — it can be cracked in minutes."),
     T("Θεώρησέ το ανοιχτό δίκτυο: VPN ή hotspot κινητού.", "Treat it as an open network: VPN or phone hotspot.")),
    (T("{}: προστατεύει από τους «έξω», αλλά σε καφετέρια ο κωδικός είναι κοινός — όποιος τον ξέρει μπορεί να «ακούει» τους άλλους πελάτες.",
       "{1}: protects you from “outsiders”, but in a café the password is shared — anyone who knows it can “listen” to the other customers."),
     T("Σε δημόσιο δίκτυο με κοινό κωδικό, άνοιξε VPN.", "On a public network with a shared password, turn on a VPN.")),
    (T("Υπάρχει και δεύτερο δίκτυο «{}» με διαφορετική ασφάλεια ({}). Κάποιος μπορεί να έστησε ψεύτικο σημείο πρόσβασης με το ίδιο όνομα.",
       "There is a second network “{1}” with different security ({2}). Someone may have set up a fake access point with the same name."),
     T("Ρώτα το προσωπικό ποιο είναι το σωστό δίκτυο, «Ξέχασε» το ύποπτο, άνοιξε VPN.",
       "Ask the staff which network is the right one, “Forget” the suspicious one, turn on a VPN.")),
    (T("Το δίκτυο παρεμβαίνει στο HTTP (σελίδα σύνδεσης ή proxy): {}.", "The network is tampering with HTTP (login page or proxy): {1}."),
     T("Στη σελίδα σύνδεσης δώσε μόνο τα απαραίτητα — ποτέ κωδικούς άλλων λογαριασμών.", "On the login page give only what's needed — never passwords of other accounts.")),
    (T("Το δίκτυο παρεμβαίνει στο HTTP (σελίδα σύνδεσης ή proxy).", "The network is tampering with HTTP (login page or proxy)."), None),
    (T("Ο DNS του δικτύου δίνει λάθος διευθύνσεις για γνωστά ονόματα ({}). Μπορεί να σε στείλει σε ψεύτικα sites.",
       "The network's DNS gives wrong addresses for well-known names ({1}). It could send you to fake sites."),
     T("Αποσυνδέσου ή άνοιξε VPN· βάλε κρυπτογραφημένο DNS (DoH).", "Disconnect or turn on a VPN; use encrypted DNS (DoH).")),
    (T("Ο DNS απαντά ακόμα και για domains που δεν υπάρχουν ({}) — το δίκτυο αλλοιώνει απαντήσεις (συνήθως για διαφημίσεις).",
       "The DNS answers even for domains that don't exist ({1}) — the network is altering answers (usually for ads)."),
     T("Βάλε κρυπτογραφημένο DNS (DoH) στον browser ή VPN.", "Use encrypted DNS (DoH) in your browser, or a VPN.")),
    (T("Τα πιστοποιητικά για {} ΔΕΝ επαληθεύονται — κάποιος «στη μέση» αποκρυπτογραφεί την κίνηση (ή portal πριν το login).",
       "The certificates for {1} can NOT be verified — someone “in the middle” is decrypting the traffic (or it's a portal before login)."),
     T("Μην κάνεις login πουθενά. Αν δεν είναι captive portal, αποσυνδέσου αμέσως.", "Don't log in anywhere. If it isn't a captive portal, disconnect right away.")),
    (T("Κάποιος στο δίκτυο παριστάνει τον router (δες ⚠ Επιθέσεις).", "Someone on the network is pretending to be the router (see ⚠ Attacks)."),
     T("Αποσυνδέσου ή άνοιξε VPN αμέσως.", "Disconnect or turn on a VPN right away.")),
    (T("Το firewall είναι κλειστό.", "The firewall is off."), T("Ρυθμίσεις → Δίκτυο → Firewall: Ενεργό.", "Settings → Network → Firewall: On.")),
    (T("Ενεργό, αλλά χωρίς stealth mode: το Mac απαντά σε ping και σαρώσεις — φαίνεται στους άλλους.",
       "On, but without stealth mode: the Mac answers pings and scans — others can see it."),
     T("Ρυθμίσεις → Δίκτυο → Firewall → Επιλογές → «Λειτουργία απόκρυψης» (stealth).", "Settings → Network → Firewall → Options → “Stealth mode”.")),
    (T("Δεν είναι ενεργό VPN.", "No VPN is on."),
     T("Σε δημόσιο Wi-Fi άνοιξε VPN (π.χ. Tailscale exit node, Mullvad, ProtonVPN) ή χρησιμοποίησε το hotspot του κινητού.",
       "On public Wi-Fi turn on a VPN (e.g. Tailscale exit node, Mullvad, ProtonVPN) or use your phone's hotspot.")),
    (T("Χρησιμοποιείς την πραγματική MAC — τα δίκτυα μπορούν να σε αναγνωρίζουν και να σε παρακολουθούν από μέρος σε μέρος.",
       "You're using your real MAC — networks can recognise you and track you from place to place."),
     T("Ρυθμίσεις → Wi-Fi → (i) δίπλα στο δίκτυο → Ιδιωτική διεύθυνση Wi-Fi: Εναλλασσόμενη.",
       "Settings → Wi-Fi → (i) next to the network → Private Wi-Fi address: Rotating.")),
]
for d, f in WIFI_CHECKS:
    P(d)
    if f:
        P(f)
        P(d + T(" → ", " → ") + f)  # Wi-Fi Guard alert detail
# OK / info details
P("Enhanced Open: ανοιχτό αλλά κρυπτογραφημένο ανά συσκευή.", "Enhanced Open: open but encrypted per device.")
P("{} — καλή κρυπτογράφηση.", "{1} — good encryption.")
P("Δεν βρέθηκε δεύτερο δίκτυο «{}» με διαφορετική ασφάλεια ({d} δίκτυα γύρω σου).",
  "No second “{1}” network with different security found ({2} networks around you).")
X("Δεν είσαι σε Wi-Fi ή δεν ήταν δυνατή η ανάγνωση.", "You're not on Wi-Fi, or it couldn't be read.")
X("Το HTTP φτάνει ανέγγιχτο.", "HTTP arrives untouched.")
X("Ο DNS δίνει σωστές απαντήσεις.", "The DNS gives correct answers.")
P("Τα πιστοποιητικά επαληθεύονται κανονικά ({*}).", "Certificates verify normally ({1}).")
X("Ενεργό με stealth mode.", "On, with stealth mode.")
X("Ενεργό.", "On.")
X("Ενεργό", "On")
P("Καμία επικίνδυνη ({d} ακούν συνολικά).", "None risky ({1} listening in total).")
X("Ενεργό — η κίνηση πάει κρυπτογραφημένη μέχρι τον server του VPN.", "On — traffic travels encrypted up to the VPN server.")
X("Δεν είναι ενεργό VPN — στο δικό σου δίκτυο συνήθως δεν χρειάζεται.", "No VPN on — on your own network you usually don't need one.")
P("Τρέχει: {}. Ανώνυμο είναι μόνο ό,τι ανοίγεις μέσα στο Tor Browser — οι άλλες εφαρμογές και browsers βγαίνουν κανονικά (ή από το VPN).", "Running: {1}. Only what you open inside Tor Browser is anonymous — other apps and browsers go out normally (or through the VPN).")
X("Για να δεις το κύκλωμα των 3 κόμβων άνοιξε την καρτέλα 🧅 Tor.", "To see the 3-relay circuit, open the 🧅 Tor tab.")
P("Το «{}» είναι συνδεδεμένο, αλλά μόνο για το ιδιωτικό σου δίκτυο — η κίνηση προς το Internet βγαίνει από το Wi‑Fi χωρίς VPN.", "“{1}” is connected, but only for your private network — traffic to the Internet leaves through the Wi‑Fi without a VPN.")
X("Για να περνά όλη η κίνηση από VPN: στο Tailscale διάλεξε Exit Node (μια συσκευή σου στο σπίτι), ή άνοιξε ένα VPN όλης της κίνησης (Mullvad, ProtonVPN, WireGuard με 0.0.0.0/0).", "To send all traffic through a VPN: in Tailscale pick an Exit Node (one of your devices at home), or turn on a full-tunnel VPN (Mullvad, ProtonVPN, WireGuard with 0.0.0.0/0).")
X("Ενεργή — δεν σε αναγνωρίζουν από τη συσκευή σου.", "On — networks can't recognise you by your device.")
# sharing: "Το Mac δέχεται συνδέσεις από όλο το Wi-Fi: <name> (<port>), ..."  (one pattern per item count, names kept)
SHARE_HEAD = ("Το Mac δέχεται συνδέσεις από όλο το Wi-Fi: ", "Your Mac accepts connections from the whole Wi-Fi: ")
# a single item → translated name
for gk, ek in MAC_SHARING.items():
    P(T(SHARE_HEAD[0] + gk + " ({d}).", SHARE_HEAD[1] + ek + " ({1})."))
# common demo combination (AirPlay 5000 + 7000 + SSH 22)
X(SHARE_HEAD[0] + "Δέκτης AirPlay (5000), Δέκτης AirPlay (7000), Απομακρυσμένη σύνδεση (SSH) (22).",
  SHARE_HEAD[1] + "AirPlay Receiver (5000), AirPlay Receiver (7000), Remote Login (SSH) (22).")
X(SHARE_HEAD[0] + "Δέκτης AirPlay (5000), Δέκτης AirPlay (7000).", SHARE_HEAD[1] + "AirPlay Receiver (5000), AirPlay Receiver (7000).")
P(SHARE_HEAD[0] + "{}.", SHARE_HEAD[1] + "{1}.")
# sharing fixes joined with " · "
X("Ρυθμίσεις → Γενικά → AirDrop και Handoff → Δέκτης AirPlay: off · Ρυθμίσεις → Γενικά → Κοινή χρήση → Απομακρυσμένη σύνδεση: off",
  "Settings → General → AirDrop & Handoff → AirPlay Receiver: off · Settings → General → Sharing → Remote Login: off")
# verdicts
X("Επικίνδυνο — μην το χρησιμοποιείς χωρίς VPN", "Dangerous — don't use it without a VPN")
X("Προσοχή — διόρθωσε τα κόκκινα πριν κάνεις κάτι σημαντικό", "Careful — fix the red items before doing anything important")
X("Εντάξει για καθημερινή χρήση", "OK for everyday use")
X("Δεν υπάρχει δίκτυο", "There is no network")

# =====================================================================================================
# privacy.py (🕶 anonymity / leaks)
# =====================================================================================================
X("Τι βλέπει κάθε site", "What every site sees")
P("IP {} · {*} · {} ({}). Μοιάζει με VPN/proxy/datacenter.", "IP {1} · {2} · {3} ({4}). Looks like a VPN/proxy/datacenter.")
P("IP {} · {*} · {} ({}). Είναι η πραγματική σύνδεσή σου — τα sites ξέρουν περίπου πού είσαι και ποιος πάροχος σε εξυπηρετεί.",
  "IP {1} · {2} · {3} ({4}). This is your real connection — sites know roughly where you are and which provider serves you.")
X("Το VPN δεν «κρύβει» την IP", "The VPN isn't “hiding” your IP")
P("Το VPN φαίνεται ενεργό, αλλά τα sites βλέπουν IP οικιακής σύνδεσης ({}). Ίσως η κίνηση δεν περνά από το VPN (split tunnel / λάθος ρύθμιση).",
  "The VPN looks active, but sites see a home-connection IP ({1}). Maybe the traffic isn't going through the VPN (split tunnel / wrong setting).")
X("Έλεγξε στο VPN ότι στέλνει ΟΛΗ την κίνηση (full tunnel / exit node) και ότι έχει kill switch.",
  "Check that the VPN sends ALL traffic (full tunnel / exit node) and has a kill switch.")
X("Η κίνηση αυτής της σύνδεσης βγαίνει από Tor.", "This connection's traffic exits through Tor.")
TOR_WARN = (" Προσοχή: περνούν από Tor ΜΟΝΟ οι εφαρμογές που το χρησιμοποιούν (π.χ. Tor Browser), όχι όλο το Mac.",
            " Note: ONLY the apps that use it (e.g. Tor Browser) go through Tor, not the whole Mac.")
for err in (T(" Σφάλμα: {}", " Error: {1}"), T("", "")):
    P(T("Το Tor τρέχει (θύρα {d}). Μέσω Tor τα sites βλέπουν IP {} ({}) αντί για τη δική σου.",
        "Tor is running (port {1}). Through Tor, sites see IP {2} ({3}) instead of yours.") + T(TOR_WARN[0], TOR_WARN[1]) + err)
    P(T("Το Tor τρέχει (θύρα {d}). Μέσω Tor τα sites βλέπουν άλλη IP.", "Tor is running (port {1}). Through Tor, sites see a different IP.")
      + T(TOR_WARN[0], TOR_WARN[1]) + err)
X("Δεν τρέχει Tor.", "Tor isn't running.")
X("Δεν τρέχει Tor. Το Tor Browser είναι εγκατεστημένο — άνοιξέ το και ξαναπάτα έλεγχο.",
  "Tor isn't running. Tor Browser is installed — open it and run the check again.")
X("Για ανωνυμία στο web: Tor Browser (torproject.org). Για όλο το Mac: brew install tor (SOCKS στη θύρα 9050).",
  "For anonymity on the web: Tor Browser (torproject.org). For the whole Mac: brew install tor (SOCKS on port 9050).")
DNS_SEEN = ("Τα ονόματα που ψάχνεις τα βλέπουν: ", "The names you look up are seen by: ")
P(DNS_SEEN[0] + "{}. Είσαι σε VPN/Tor, αλλά τα DNS ερωτήματα πάνε σε άλλον πάροχο ({}) — όποιος τον ελέγχει βλέπει ΠΟΙΑ sites επισκέπτεσαι.",
  DNS_SEEN[1] + "{1}. You're on VPN/Tor, but DNS queries go to a different provider ({2}) — whoever controls it sees WHICH sites you visit.")
P(DNS_SEEN[0] + "{}.", DNS_SEEN[1] + "{1}.")
X("Ενεργοποίησε στο VPN «DNS leak protection» / χρήση του DNS του VPN· στον browser βάλε DoH.",
  "Turn on “DNS leak protection” / use the VPN's DNS in your VPN app; in the browser use DoH.")
P("Το τεστ DNS δεν ολοκληρώθηκε: {}", "The DNS test didn't finish: {1}")
P("Η IPv6 σου ({}) βγαίνει ΕΚΤΟΣ VPN — τα sites με IPv6 βλέπουν την πραγματική σου σύνδεση.",
  "Your IPv6 ({1}) goes OUTSIDE the VPN — sites with IPv6 see your real connection.")
X("Ενεργοποίησε στο VPN το IPv6 (ή «block IPv6»), ή κλείσε το IPv6: Ρυθμίσεις → Δίκτυο → Wi-Fi → Λεπτομέρειες → TCP/IP → Ρύθμιση IPv6: Μόνο link-local.",
  "Enable IPv6 in your VPN (or “block IPv6”), or turn IPv6 off: Settings → Network → Wi-Fi → Details → TCP/IP → Configure IPv6: Link-local only.")
P("Έχεις και IPv6 ({}).", "You also have IPv6 ({1}).")
X("Χωρίς δημόσια IPv6 — δεν μπορεί να διαρρεύσει από εκεί.", "No public IPv6 — nothing can leak that way.")
X("Υψηλή (Tor)", "High (Tor)")
X("Μέτρια (VPN/proxy) — ο πάροχος του VPN σε βλέπει", "Medium (VPN/proxy) — your VPN provider can see you")
X("Χαμηλή — το VPN/Tor «στάζει»", "Low — the VPN/Tor is “leaking”")
X("Καμία — τα sites βλέπουν την πραγματική σου σύνδεση", "None — sites see your real connection")
X("SOCKS: άρνηση", "SOCKS: refused")
P("SOCKS: αποτυχία σύνδεσης ({})", "SOCKS: connection failed ({1})")
X("bash.ws: μη αναμενόμενη απάντηση", "bash.ws: unexpected answer")

# =====================================================================================================
# iotcheck.py (🔌 IoT check)
# =====================================================================================================
X("Server με υπηρεσία IoT (π.χ. MQTT broker)", "Server with an IoT service (e.g. MQTT broker)")
X("(χειροκίνητα)", "(manual)")
IOT_TITLES = {
    "Telnet ανοιχτό": "Telnet open",
    "MQTT χωρίς TLS (1883)": "MQTT without TLS (1883)",
    "Σελίδα χωρίς HTTPS (80)": "Page without HTTPS (80)",
    "Σελίδα χωρίς HTTPS (8080)": "Page without HTTPS (8080)",
    "SSH ανοιχτό": "SSH open",
    "VNC (απομακρυσμένη οθόνη)": "VNC (remote screen)",
    "Κοινόχρηστοι φάκελοι (SMB)": "Shared folders (SMB)",
    "MQTT με TLS (8883)": "MQTT with TLS (8883)",
    "MQTT ανοιχτό σε ΟΛΟΥΣ (χωρίς κωδικό, χωρίς TLS)": "MQTT open to EVERYONE (no password, no TLS)",
    "Καμία ανοιχτή «επικίνδυνη» πόρτα": "No open “dangerous” ports",
}
IOT_WHY = {
    "Ό,τι πληκτρολογείς (και ο κωδικός) ταξιδεύει ανοιχτό. Είναι η πόρτα από την οποία μπήκε το Mirai σε εκατομμύρια συσκευές.":
        "Everything you type (and the password) travels in the open. It's the door Mirai used to get into millions of devices.",
    "Μετρήσεις, εντολές ΚΑΙ ο κωδικός του MQTT περνάνε ανοιχτά: όποιος είναι στο Wi-Fi τα διαβάζει.":
        "Readings, commands AND the MQTT password travel in the open: anyone on the Wi-Fi can read them.",
    "Η σελίδα ρυθμίσεων/δεδομένων δεν είναι κρυπτογραφημένη· αν έχει login, ο κωδικός φαίνεται.":
        "The settings/data page isn't encrypted; if it has a login, the password can be seen.",
    "Δεύτερη web υπηρεσία χωρίς κρυπτογράφηση.": "A second web service without encryption.",
    "Είναι κρυπτογραφημένο — αρκεί να μπαίνεις μόνο με κλειδί και να υπάρχει fail2ban.":
        "It's encrypted — as long as you log in only with a key and fail2ban is in place.",
    "Το VNC συχνά έχει αδύναμο ή κανέναν κωδικό και δεν κρυπτογραφεί.": "VNC often has a weak password or none, and doesn't encrypt.",
    "Το Samba ανοιχτό σε όλο το δίκτυο δίνει πρόσβαση σε αρχεία.": "Samba open to the whole network gives access to files.",
    "Ο broker δέχεται κρυπτογραφημένες συνδέσεις. 👍": "The broker accepts encrypted connections. 👍",
    "Κρυπτογραφημένη web υπηρεσία.": "Encrypted web service.",
    "Ο broker δέχτηκε σύνδεση χωρίς username/password. Οποιοσδήποτε στο δίκτυο διαβάζει τις μετρήσεις σου και στέλνει εντολές (π.χ. ανοίγει το relay).":
        "The broker accepted a connection without username/password. Anyone on the network can read your readings and send commands (e.g. switch the relay on).",
    "Από το δίκτυο δεν φαίνεται κάτι εύκολο για επιτιθέμενο.": "From the network, nothing looks easy for an attacker.",
}
IOT_FIX = {
    "Κλείσ' το (sudo systemctl disable --now telnet.socket / βγάλ' το από το firmware) και χρησιμοποίησε SSH με κλειδιά.":
        "Turn it off (sudo systemctl disable --now telnet.socket / remove it from the firmware) and use SSH with keys.",
    "Βάλε listener 8883 με TLS και κλείσε το 1883 (ή άφησέ το μόνο στο localhost). Έτοιμα πιστοποιητικά + ρύθμιση: ./tools/mosquitto-tls.sh <IP του broker>":
        "Add an 8883 listener with TLS and close 1883 (or keep it on localhost only). Ready-made certificates + config: ./tools/mosquitto-tls.sh <broker IP>",
    "Βάλε κωδικό και, αν γίνεται, HTTPS — ή κράτα τη σελίδα μόνο σε χωριστό IoT δίκτυο.":
        "Add a password and, if possible, HTTPS — or keep the page only on a separate IoT network.",
    "Κλείσ' τη αν δεν τη χρειάζεσαι.": "Turn it off if you don't need it.",
    "Στο /etc/ssh/sshd_config: PasswordAuthentication no, PermitRootLogin no.": "In /etc/ssh/sshd_config: PasswordAuthentication no, PermitRootLogin no.",
    "Κλείσ' το ή πέρνα το μέσα από SSH tunnel.": "Turn it off or run it through an SSH tunnel.",
    "Περιόρισέ το με ufw στις IP που το χρειάζονται.": "Restrict it with ufw to the IPs that need it.",
    "sudo apt update && sudo apt full-upgrade (ή νεότερο firmware/image).": "sudo apt update && sudo apt full-upgrade (or a newer firmware/image).",
    "mosquitto.conf: allow_anonymous false + password_file + acl_file, και listener 8883 με TLS.":
        "mosquitto.conf: allow_anonymous false + password_file + acl_file, and an 8883 listener with TLS.",
}
IOT_TIPS = {
    "Secure Boot & Flash Encryption: όποιος πιάσει την πλακέτα διαβάζει τον Wi-Fi κωδικό από τη flash αν δεν είναι κρυπτογραφημένη (iot-5-2).":
        "Secure Boot & Flash Encryption: anyone who gets hold of the board can read the Wi-Fi password from flash if it isn't encrypted (iot-5-2).",
    "Βάλ' το σε χωριστό IoT δίκτυο/SSID, ώστε αν πέσει να μη βλέπει τον υπολογιστή σου (iot-7-1).":
        "Put it on a separate IoT network/SSID, so if it gets hacked it can't see your computer (iot-7-1).",
    "OTA: αν χρησιμοποιείς ArduinoOTA, βάλε κωδικό — ή καλύτερα υπογεγραμμένο HTTPS OTA (iot-5-3). (Το ArduinoOTA ακούει σε UDP, δεν φαίνεται σε αυτόν τον έλεγχο.)":
        "OTA: if you use ArduinoOTA, set a password — or better, signed HTTPS OTA (iot-5-3). (ArduinoOTA listens on UDP, so it doesn't show up in this check.)",
    "Αυτόματες ενημερώσεις (unattended-upgrades) και fail2ban (iot-2-3, iot-2-5).": "Automatic updates (unattended-upgrades) and fail2ban (iot-2-3, iot-2-5).",
    "Firewall ufw: άφησε ανοιχτό μόνο ό,τι χρειάζεσαι (iot-2-4).": "ufw firewall: leave open only what you need (iot-2-4).",
    "Broker: κάθε συσκευή με δικό της χρήστη και ACL μόνο στα δικά της topics (iot-4-2).":
        "Broker: each device with its own user and an ACL only for its own topics (iot-4-2).",
}
for k, v in IOT_TITLES.items():
    X(k, v)
    P(T("{}: " + k, "{1}: " + v))  # weekly report: "<device>: <title>"
for k, v in IOT_WHY.items():
    X(k, v)
for k, v in IOT_FIX.items():
    X(k, v)
    X("— " + k, "— " + v)
for k, v in IOT_TIPS.items():
    X(k, v)
X(list(IOT_WHY)[1] + " (Ζητάει κωδικό — καλό, αλλά ο κωδικός περνάει ανοιχτός.)",
  IOT_WHY[list(IOT_WHY)[1]] + " (It asks for a password — good, but the password travels in the open.)")
for k in list(IOT_WHY)[2:4]:
    X(k + " Ζητάει κωδικό (HTTP Basic) — που όμως ταξιδεύει χωρίς κρυπτογράφηση.",
      IOT_WHY[k] + " It asks for a password (HTTP Basic) — which, however, travels unencrypted.")
P("Παλιά έκδοση {} {}", "Old version of {1} {2}")
P("{}: Παλιά έκδοση {} {}", "{1}: Old version of {2} {3}")
VULNS = [
    ("CVE-2024-6387", "regreSSHion: απομακρυσμένη εκτέλεση κώδικα ως root σε Linux/glibc", "regreSSHion: remote code execution as root on Linux/glibc"),
    ("CVE-2023-38408", "εκτέλεση κώδικα μέσω προωθημένου ssh-agent", "code execution via a forwarded ssh-agent"),
    ("CVE-2023-28366", "διαρροή μνήμης → ο broker πέφτει (DoS)", "memory leak → the broker crashes (DoS)"),
    ("CVE-2024-8376", "κακόβουλος client ρίχνει τον broker (DoS)", "a malicious client crashes the broker (DoS)"),
]
for _, g, e in VULNS:
    X(g, e)
DISTRO = T(" Το «{}» δείχνει πακέτο διανομής, που συχνά έχει ήδη τη διόρθωση — αν κάνεις τακτικά ενημερώσεις, μάλλον είσαι εντάξει.",
           " “{1}” points to a distribution package, which often already has the fix — if you update regularly, you're probably fine.")
VCOMBOS = [[VULNS[0]], [VULNS[1]], [VULNS[0], VULNS[1]], [VULNS[2]], [VULNS[3]], [VULNS[2], VULNS[3]]]
for combo in VCOMBOS:
    g = "Γνωστές ευπάθειες: " + "; ".join(f"{c} ({w})" for c, w, _ in combo) + "."
    e = "Known vulnerabilities: " + "; ".join(f"{c} ({w})" for c, _, w in combo) + "."
    P(T(g, e) + DISTRO)
    X(g, e)
P(T("Γνωστές ευπάθειες: {}.", "Known vulnerabilities: {1}.") + DISTRO)
P("Γνωστές ευπάθειες: {}", "Known vulnerabilities: {1}")

# =====================================================================================================
# honeypot.py
# =====================================================================================================
HONEY = {
    "ψεύτικο SSH: εδώ πέφτουν bots που δοκιμάζουν κωδικούς": "fake SSH: bots that try passwords land here",
    "ψεύτικο Telnet: το αγαπημένο των IoT botnets (π.χ. Mirai)": "fake Telnet: the favourite of IoT botnets (e.g. Mirai)",
    "ψεύτικη σελίδα διαχείρισης router": "fake router admin page",
    "ψεύτικος εκτυπωτής (JetDirect): τον σκανάρουν πολλά εργαλεία": "fake printer (JetDirect): many tools scan for it",
    "ψεύτικο Remote Desktop": "fake Remote Desktop",
    "ψεύτικο VNC (απομακρυσμένη οθόνη)": "fake VNC (remote screen)",
    "η θύρα είναι πιασμένη": "the port is already in use",
}
for k, v in HONEY.items():
    X(k, v)

# =====================================================================================================
# apps.py
# =====================================================================================================
X("διαφημίσεις", "ads")
X("παρακολούθηση", "tracking")
X("τηλεμετρία", "telemetry")

# =====================================================================================================
# playbooks.py (⚡)
# =====================================================================================================
P("{}: άγνωστη ενέργεια {} (επιτρέπονται: {})", "{1}: unknown action {2} (allowed: {3})")
P("{}: χρειάζεται και «when» και «do»", "{1}: needs both “when” and “do”")
P("(δοκιμή) θα έκανα: {}", "(dry run) I would do: {1}")
X("δεν υπάρχει τείχος προστασίας σε αυτή τη λειτουργία", "there is no firewall in this mode")
X("στο allowlist — δεν το μπλοκάρω", "on the allowlist — not blocking it")
P("μπλοκαρίστηκε για {d}′", "blocked for {1}′")
X("μπλοκαρίστηκε", "blocked")
X("χρειάζεται root", "needs root")
P("στη λίστα, αλλά δεν εφαρμόστηκε (χρειάζεται root)", "on the list, but not applied (needs root)")
P("στη λίστα, αλλά δεν εφαρμόστηκε ({})", "on the list, but not applied ({1})")
X("στάλθηκε ειδοποίηση", "alert sent")
X("χρειάζεται ρύθμιση homeassistant (broker)", "needs the homeassistant (broker) setting")
P("σφάλμα: {}", "error: {1}")
X("άγνωστη ενέργεια", "unknown action")
# "⚡ <playbook>: <alert type>" (blocker reason, notification title)
for gk, ek in PB_NAMES.items():
    for tg, te in TYPES.items():
        if tg in ("Κανόνας:", "Κανόνας", "Διαρροή", "δοκιμή"):
            continue
        X("⚡ " + gk + ": " + tg, "⚡ " + ek + ": " + te)
    P(T("⚡ " + gk + ": Παγίδα: σύνδεση σε ψεύτικο {}", "⚡ " + ek + ": Honeypot: connection to a fake {1}"))
for tg, te in TYPES.items():
    if tg in ("Κανόνας:", "Κανόνας", "Διαρροή", "δοκιμή"):
        continue
    P(T("⚡ {}: " + tg, "⚡ {1}: " + te))
P("⚡ {}: Παγίδα: σύνδεση σε ψεύτικο {}", "⚡ {1}: Honeypot: connection to a fake {2}")
P("⚡ {}: Κανόνας: {}", "⚡ {1}: Rule: {2}")

# =====================================================================================================
# blocker.py, storage.py (notifications test), osint.py, hass errors
# =====================================================================================================
X("Μη έγκυρη IP", "Invalid IP")
X("Αυτή η διεύθυνση δεν μπλοκάρεται (loopback/multicast/link-local)", "This address can't be blocked (loopback/multicast/link-local)")
X("Δεν μπλοκάρω τον εαυτό σου ή τον router — θα έχανες το Internet", "I won't block yourself or the router — you'd lose the Internet")
X("NetWatch — δοκιμή", "NetWatch — test")
X("Αν το βλέπεις, οι ειδοποιήσεις δουλεύουν. 👍", "If you can see this, notifications work. 👍")
X("δεν έχει ρυθμιστεί", "not configured")
P("intel: {} απέτυχε: {}", "intel: {1} failed: {2}")
P("intel: {d} δίκτυα από {d}/{d} λίστες", "intel: {1} networks from {2}/{3} lists")
X("Μόνο για διευθύνσεις του Internet", "Only for Internet addresses")
P("whois απέτυχε: {}", "whois failed: {1}")
X("(κενό αποτέλεσμα)", "(empty result)")

# =====================================================================================================
# server.py — API errors
# =====================================================================================================
X("Απενεργοποιημένο σε λειτουργία agent (θα έτρεχε στον server).", "Disabled in agent mode (it would run on the server).")
X("δεν βρέθηκε", "not found")
X("Το τερματικό είναι κλειστό (academy_terminal: false στο config).", "The terminal is turned off (academy_terminal: false in the config).")
X("Διαθέσιμο μόνο σε Live/Demo.", "Only available in Live/Demo.")
X("Διαθέσιμο μόνο σε Live/Demo (σε pcap δεν υπάρχουν εφαρμογές να δούμε).", "Only available in Live/Demo (in a pcap there are no apps to look at).")
X("Μόνο IP του τοπικού δικτύου", "Only IPs on the local network")
X("Δεν ξέρω ακόμα τη δημόσια IP σου", "I don't know your public IP yet")
X("Δεν έχω πακέτο για αυτή τη σύνδεση.", "I don't have a packet for this connection.")
X("Τερματισμός από την εφαρμογή.", "Shut down by the app.")

# =====================================================================================================
# ctf.py / capture.py / ctf/challenges.json
# =====================================================================================================
X("Άγνωστο επίπεδο", "Unknown level")
X("Άγνωστη ερώτηση", "Unknown question")
X("Αυτή η ερώτηση θέλει κανόνα, όχι κείμενο", "This question needs a rule, not text")
P("Λείπει το {} — τρέξε: python tools/make_ctf.py", "{1} is missing — run: python tools/make_ctf.py")
X("Κενός κανόνας", "Empty rule")
CTF = {
    "Εισβολέας στο LAN": "Intruder on the LAN",
    "Εύκολο": "Easy",
    "Το laptop κάποιου στο Wi-Fi σου έχει παραβιαστεί και επιτίθεται στους πάντες. Οι ανιχνευτές το έχουν πιάσει — διάβασε τις ειδοποιήσεις και τις λεπτομέρειες.":
        "Someone's laptop on your Wi-Fi has been hacked and is attacking everyone. The detectors have caught it — read the alerts and the details.",
    "Ποια είναι η IP του επιτιθέμενου;": "What is the attacker's IP?",
    "Καρτέλα ⚠ Επιθέσεις — ποια IP εμφανίζεται ξανά και ξανά;": "⚠ Attacks tab — which IP shows up again and again?",
    "Ποια υπηρεσία δέχτηκε brute force;": "Which service was brute-forced?",
    "Η ειδοποίηση Brute force γράφει υπηρεσία και θύρα.": "The Brute force alert names the service and port.",
    "Ποια MAC διεύθυνση χρησιμοποίησε για να «γίνει» ο router;": "Which MAC address did it use to “become” the router?",
    "Δες την ειδοποίηση ARP spoofing.": "Look at the ARP spoofing alert.",
    "Σε ποιο domain έβγαλε δεδομένα μέσω DNS;": "To which domain did it send data out over DNS?",
    "Ειδοποίηση DNS tunneling — ο στόχος της.": "The DNS tunneling alert — its target.",
    "Σε ποια IP του LAN στάλθηκε κωδικός μέσω FTP;": "To which LAN IP was a password sent over FTP?",
    "Καρτέλα 🛡 Έλεγχος → Κωδικοί χωρίς κρυπτογράφηση.": "🛡 Audit tab → Passwords without encryption.",
    "Ποια είναι η IP της συσκευής που μπήκε τελευταία στο δίκτυο;": "What is the IP of the device that joined the network last?",
    "Ειδοποίηση «Νέα συσκευή».": "The “New device” alert.",
    "Ποιος είναι ο κωδικός MITRE ATT&CK του ARP spoofing;": "What is the MITRE ATT&CK id of ARP spoofing?",
    "Το μωβ σήμα σε κάθε ειδοποίηση, π.χ. T1046.": "The purple badge on each alert, e.g. T1046.",
    "Ο σιωπηλός επισκέπτης": "The silent visitor",
    "Μέτριο": "Medium",
    "Δεν σε επιτέθηκε κανείς — κι όμως κάτι δεν πάει καλά. Μια συσκευή στο σπίτι κάνει περίεργες ερωτήσεις DNS και μετά «μιλάει» τακτικά με έναν server στο εξωτερικό. Βρες τη.":
        "Nobody attacked you — and yet something is wrong. A device in the house makes strange DNS queries and then “talks” regularly to a server abroad. Find it.",
    "Ποια συσκευή του LAN έχει μολυνθεί (IP);": "Which LAN device is infected (IP)?",
    "Ποια συσκευή κάνει ερωτήσεις για domains που δεν υπάρχουν;": "Which device asks about domains that don't exist?",
    "Ποια είναι η IP του C2 server;": "What is the IP of the C2 server?",
    "Ειδοποίηση Beaconing — ποιον «καλεί»;": "The Beaconing alert — who is it “calling”?",
    "Κάθε πόσα δευτερόλεπτα «καλεί» το malware τον C2;": "Every how many seconds does the malware “call” the C2?",
    "Η ειδοποίηση Beaconing γράφει το διάστημα.": "The Beaconing alert shows the interval.",
    "Ποιο domain βρήκε τελικά το DGA (αυτό που υπάρχει);": "Which domain did the DGA finally find (the one that exists)?",
    "Κάνε κλικ στην IP του C2 → Λεπτομέρειες → domains.": "Click the C2's IP → Details → domains.",
    "Σε ποια θύρα μιλάει με τον C2;": "On which port does it talk to the C2?",
    "Λεπτομέρειες του C2 → θύρες.": "C2 details → ports.",
    "Ποια τεχνική MITRE ATT&CK αντιστοιχεί στο beaconing;": "Which MITRE ATT&CK technique matches beaconing?",
    "Το μωβ σήμα στην ειδοποίηση.": "The purple badge on the alert.",
    "Ο υπομονετικός": "The patient one",
    "Δύσκολο": "Hard",
    "Αυτή τη φορά οι ανιχνευτές δεν λένε τίποτα. Κάποιος όμως σκάναρε τον υπολογιστή σου τόσο αργά που πέρασε κάτω από τα όρια — και μετά μπήκε. Ψάξε στα δεδομένα σαν αναλυτής SOC και μετά γράψε κανόνα που να τον πιάνει.":
        "This time the detectors say nothing. But someone scanned your computer so slowly that they stayed under the thresholds — and then got in. Dig through the data like a SOC analyst, then write a rule that catches them.",
    "Ποια IP σάρωσε αθόρυβα τον υπολογιστή σου (192.168.1.50);": "Which IP quietly scanned your computer (192.168.1.50)?",
    "Καρτέλα 📟 Συσκευές → ποια συσκευή «χτυπάει» πολλές διαφορετικές θύρες; (Λεπτομέρειες → Τι χτυπάει)":
        "📟 Devices tab → which device “hits” many different ports? (Details → What it hits)",
    "Πόσες διαφορετικές θύρες δοκίμασε;": "How many different ports did it try?",
    "Λεπτομέρειες του scanner → Τι χτυπάει: μέτρα τις θύρες.": "Scanner details → What it hits: count the ports.",
    "Ποιες θύρες βρήκε ανοιχτές; (π.χ. 80,443)": "Which ports did it find open? (e.g. 80,443)",
    "Ανοιχτή θύρα = ο στόχος απάντησε SYN-ACK (SA). Καρτέλα 📦 Πακέτα, ή Λεπτομέρειες του 192.168.1.50 → θύρες.":
        "Open port = the target answered SYN-ACK (SA). 📦 Packets tab, or Details of 192.168.1.50 → ports.",
    "Σε ποια υπηρεσία συνδέθηκε μετά τη σάρωση;": "Which service did it connect to after the scan?",
    "Μετά τη σάρωση υπάρχει μία κανονική σύνδεση με δεδομένα.": "After the scan there is one normal connection with data.",
    "Γράψε κανόνα (YAML) που ανιχνεύει τον αργό scanner — και ΜΟΝΟ αυτόν (όχι false positives).":
        "Write a rule (YAML) that detects the slow scanner — and ONLY it (no false positives).",
    "Ο scanner στέλνει SYN σε πολλές ΔΙΑΦΟΡΕΤΙΚΕΣ θύρες. Οι κανονικές συσκευές συνδέονται σε πολλές IP, αλλά σχεδόν πάντα στην ίδια θύρα. Δες το threshold με distinct: dport και ένα μεγάλο window.":
        "The scanner sends SYNs to many DIFFERENT ports. Normal devices connect to many IPs, but almost always on the same port. Look at a threshold with distinct: dport and a large window.",
}
for k, v in CTF.items():
    X(k.replace("SYN-ACK", "SYN" + NBH + "ACK"), v.replace("SYN-ACK", "SYN" + NBH + "ACK"))
for k in ("Εισβολέας στο LAN", "Ο σιωπηλός επισκέπτης", "Ο υπομονετικός"):
    X("CTF · " + k, "CTF · " + CTF[k])

# =====================================================================================================
# rules.py — validation errors and field help (🧩 Rules tab)
# =====================================================================================================
RULE_HELP = {
    "IP, CIDR ή λέξη: me, gw, local, public, bcast — λίστα = «οποιοδήποτε», «!» = άρνηση":
        "IP, CIDR or a word: me, gw, local, public, bcast — list = “any of”, “!” = not",
    "θύρα, λίστα [22, 23] ή εύρος \"1000-2000\"": "port, list [22, 23] or range \"1000-2000\"",
    "σημαίες TCP ακριβώς, π.χ. S (SYN), SA, FPU": "exact TCP flags, e.g. S (SYN), SA, FPU",
    "glob, π.χ. \"*.xyz\" ή \"*exfil*\" (domain = οποιοδήποτε από τα 3)": "glob, e.g. \"*.xyz\" or \"*exfil*\" (domain = any of the 3)",
    "MAC συσκευής (glob), π.χ. \"de:ad:*\"": "device MAC (glob), e.g. \"de:ad:*\"",
    "μέγεθος πακέτου σε bytes": "packet size in bytes",
}
for k, v in RULE_HELP.items():
    X(k, v)
RULE_ERRS = [
    T("Μη έγκυρη IP/CIDR: {}", "Invalid IP/CIDR: {1}"),
    T("Μη έγκυρη θύρα: {}", "Invalid port: {1}"),
    T("Θύρα εκτός ορίων: {}", "Port out of range: {1}"),
    T("Ο κανόνας πρέπει να είναι αντικείμενο YAML (key: value)", "The rule must be a YAML object (key: value)"),
    T("Άγνωστα πεδία στο match: {} — επιτρέπονται: {}", "Unknown fields in match: {1} — allowed: {2}"),
    T("Άγνωστα πεδία: {}", "Unknown fields: {1}"),
    T("Το id πρέπει να είναι 2–64 χαρακτήρες: γράμματα, αριθμοί, - _ .", "The id must be 2–64 characters: letters, digits, - _ ."),
    T("severity: low, med ή high", "severity: low, med or high"),
    T("mitre: π.χ. T1046 ή T1110.001", "mitre: e.g. T1046 or T1110.001"),
    T("Χρειάζεται «match:» με τουλάχιστον ένα πεδίο", "It needs “match:” with at least one field"),
    T("threshold.count/window πρέπει να είναι αριθμοί", "threshold.count/window must be numbers"),
    T("threshold: count ≥ 1 και 0 < window ≤ 86400", "threshold: count ≥ 1 and 0 < window ≤ 86400"),
    T("threshold.by: src, dst ή src,dst", "threshold.by: src, dst or src,dst"),
    T("Λάθος YAML: {}", "YAML error: {1}"),
    T("Διπλό id: {}", "Duplicate id: {1}"),
    T("διπλό id {}", "duplicate id {1}"),
]
for t in RULE_ERRS:
    P(t)
for t in RULE_ERRS:
    P(T("{s}: ", "{1}: ") + t)  # rules/*.yaml load errors: "<file>: <error>"
P("Το id «{}» υπάρχει ήδη στο {} — διάλεξε άλλο", "The id “{1}” already exists in {2} — choose another one")
X("Δεν υπάρχουν δικοί σου κανόνες", "You don't have any rules of your own")
X("Μόνο κανόνες του local.yaml σβήνονται από εδώ", "Only rules from local.yaml can be deleted here")
X("⚠ κανόνας:", "⚠ rule:")

# =====================================================================================================
# pentest.py — 🔴 LAN scan + 🧪 purple-team lab
# =====================================================================================================
X("Μη έγκυρος στόχος — γράψε π.χ. 192.168.1.0/24 ή 192.168.1.10", "Invalid target — write e.g. 192.168.1.0/24 or 192.168.1.10")
X("Μόνο IPv4", "IPv4 only")
X("Επιτρέπονται μόνο ιδιωτικά δίκτυα (192.168.x.x, 10.x.x.x, 172.16–31.x.x) — σάρωση ξένων δικτύων χωρίς άδεια είναι παράνομη",
  "Only private networks are allowed (192.168.x.x, 10.x.x.x, 172.16–31.x.x) — scanning other people's networks without permission is illegal")
P("Πολύ μεγάλο δίκτυο — το πολύ {d} διευθύνσεις (π.χ. /24)", "Network too large — at most {1} addresses (e.g. /24)")
X("Τρέχει ήδη σάρωση", "A scan is already running")
X("ανακάλυψη συσκευών", "discovering devices")
X("τέλος", "done")
P("σάρωση θυρών σε {d} διευθύνσεις", "scanning ports on {1} addresses")
X("έλεγχος TLS", "checking TLS")
P("σάρωση {s}", "scanning {1}")
X("Χρειάζεται δημόσια IP", "A public IP is needed")
LAB = {
    "40 θύρες σε ~2 δευτερόλεπτα (nmap -T4)": "40 ports in ~2 seconds (nmap -T4)",
    "15 θύρες, μία κάθε 0,8 s (nmap -T1 «sneaky»)": "15 ports, one every 0.8 s (nmap -T1 “sneaky”)",
    "Τα IDS μετράνε γεγονότα μέσα σε ένα χρονικό παράθυρο. Ένας υπομονετικός επιτιθέμενος μένει κάτω από το όριο. Γι' αυτό τα SOC κοιτάνε και μακροπρόθεσμα μοτίβα (π.χ. ανά ώρα).":
        "An IDS counts events within a time window. A patient attacker stays under the threshold. That's why SOCs also look at long-term patterns (e.g. per hour).",
    "20 προσπάθειες σύνδεσης στο SSH σε ~4 s": "20 SSH login attempts in ~4 s",
    "8 προσπάθειες, μία κάθε 3 s (password spraying)": "8 attempts, one every 3 s (password spraying)",
    "Το «password spraying» δοκιμάζει λίγους κωδικούς αργά για να μην ενεργοποιήσει όρια ή κλείδωμα λογαριασμού. Άμυνα: κλειδιά SSH αντί κωδικών, fail2ban, 2FA.":
        "“Password spraying” tries a few passwords slowly so it doesn't trip thresholds or account lockout. Defence: SSH keys instead of passwords, fail2ban, 2FA.",
    "ping σε 40 διευθύνσεις σε 2 s": "ping to 40 addresses in 2 s",
    "ping σε 25 διευθύνσεις, μία κάθε 0,5 s": "ping to 25 addresses, one every 0.5 s",
    "Η χαρτογράφηση του δικτύου είναι το πρώτο βήμα. Αργή σάρωση ή ARP αντί για ping την κάνει πολύ πιο δύσκολη να φανεί.":
        "Mapping the network is the first step. A slow scan, or ARP instead of ping, makes it much harder to spot.",
    "35 ερωτήματα με τυχαία hex subdomains (δεδομένα κωδικοποιημένα)": "35 queries with random hex subdomains (encoded data)",
    "35 ερωτήματα με «κανονικές» λέξεις (photo-1.cdn…, photo-2.cdn…)": "35 queries with “normal” words (photo-1.cdn…, photo-2.cdn…)",
    "Η ανίχνευση βασίζεται στην εντροπία (πόσο «τυχαίο» είναι ένα όνομα). Αν τα δεδομένα κρυφτούν σε λέξεις από λεξικό, η εντροπία πέφτει και η ανίχνευση αποτυγχάνει.":
        "Detection relies on entropy (how “random” a name is). If the data is hidden in dictionary words, entropy drops and detection fails.",
    "5 πακέτα TCP με σημαίες FIN+PSH+URG": "5 TCP packets with FIN+PSH+URG flags",
    "Παράξενα πακέτα που δεν στέλνει ποτέ κανονικό πρόγραμμα — πιάνονται με την πρώτη. Γι' αυτό οι έμπειροι επιτιθέμενοι προτιμούν τις «κανονικές» συνδέσεις.":
        "Weird packets that no normal program ever sends — caught on the first try. That's why experienced attackers prefer “normal” connections.",
    "5 ψεύτικες απαντήσεις ARP «εγώ είμαι ο router»": "5 fake ARP replies “I am the router”",
    "Το ARP δεν έχει πιστοποίηση, αλλά η αλλαγή MAC του router είναι εύκολο να φανεί. Άμυνα: Dynamic ARP Inspection σε managed switch, VPN, HTTPS παντού.":
        "ARP has no authentication, but a change of the router's MAC is easy to spot. Defence: Dynamic ARP Inspection on a managed switch, VPN, HTTPS everywhere.",
    "320 SYN σε ~1,5 s": "320 SYNs in ~1.5 s",
    "Οι επιθέσεις DoS είναι από τη φύση τους θορυβώδεις — ο στόχος τους είναι ο όγκος.": "DoS attacks are noisy by nature — their goal is volume.",
    "Άγνωστο σενάριο": "Unknown scenario",
    "Τρέχει ήδη μια άσκηση": "An exercise is already running",
    "οποιοδήποτε πακέτο TCP με σημαίες NULL, FIN ή FIN+PSH+URG": "any TCP packet with NULL, FIN or FIN+PSH+URG flags",
    "η MAC του router αλλάζει σε MAC άλλης συσκευής": "the router's MAC changes to another device's MAC",
}
for k, v in LAB.items():
    X(k, v)
P("≥ {d} διαφορετικές θύρες/στόχοι από την ίδια IP σε {n} s", "≥ {1} different ports/targets from the same IP in {2} s")
P("≥ {d} συνδέσεις στην ίδια υπηρεσία σύνδεσης σε {n} s", "≥ {1} connections to the same login service in {2} s")
P("ping σε ≥ {d} διαφορετικές IP σε {n} s", "ping to ≥ {1} different IPs in {2} s")
P("≥ {d} μοναδικά subdomains με μήκος ≥ {n} και εντροπία ≥ {n} σε {n} s", "≥ {1} unique subdomains with length ≥ {2} and entropy ≥ {3} in {4} s")
P("≥ {d} SYN προς εσένα σε {n} s", "≥ {1} SYNs aimed at you in {2} s")

# =====================================================================================================
# packets.py — 🔬 packet analysis (layer and field explanations)
# =====================================================================================================
PKT = {
    "Ethernet II (Layer 2): πλαίσιο μέσα στο τοπικό δίκτυο. Οι MAC αλλάζουν σε κάθε «hop» (router), οι IP όχι.":
        "Ethernet II (Layer 2): a frame inside the local network. MACs change at every “hop” (router), IPs don't.",
    "Ετικέτα VLAN 802.1Q: 4 bytes που λένε σε ποιο VLAN ανήκει το πλαίσιο σε ένα trunk.":
        "802.1Q VLAN tag: 4 bytes that say which VLAN the frame belongs to on a trunk.",
    "ARP: «ποιος έχει αυτή την IP; πες μου τη MAC σου». Συνδέει Layer 3 με Layer 2.":
        "ARP: “who has this IP? tell me your MAC”. It links Layer 3 to Layer 2.",
    "IPv4 (Layer 3): διευθυνσιοδότηση από άκρη σε άκρη και δρομολόγηση.": "IPv4 (Layer 3): end-to-end addressing and routing.",
    "IPv6 (Layer 3): 128-bit διευθύνσεις, χωρίς checksum και χωρίς fragmentation από τους routers.":
        "IPv6 (Layer 3): 128-bit addresses, no checksum and no fragmentation by routers.",
    "TCP (Layer 4): αξιόπιστη, με σύνδεση (3-way handshake), αριθμούς σειράς και επιβεβαιώσεις.":
        "TCP (Layer 4): reliable, connection-based (3-way handshake), with sequence numbers and acknowledgements.",
    "UDP (Layer 4): χωρίς σύνδεση και χωρίς επιβεβαιώσεις — γρήγορο, για DNS, DHCP, φωνή/βίντεο.":
        "UDP (Layer 4): connectionless and without acknowledgements — fast, for DNS, DHCP, voice/video.",
    "ICMP: μηνύματα ελέγχου/σφαλμάτων (ping = echo request/reply, TTL exceeded = traceroute).":
        "ICMP: control/error messages (ping = echo request/reply, TTL exceeded = traceroute).",
    "DNS (Layer 7): «ποια IP έχει αυτό το όνομα;» — συνήθως UDP 53.": "DNS (Layer 7): “which IP has this name?” — usually UDP 53.",
    "DHCP (πάνω από BOOTP): ο client παίρνει IP, μάσκα, gateway, DNS — Discover/Offer/Request/Ack.":
        "DHCP (on top of BOOTP): the client gets an IP, mask, gateway, DNS — Discover/Offer/Request/Ack.",
    "Επιλογές DHCP: τύπος μηνύματος, μάσκα, router, DNS, lease time.": "DHCP options: message type, mask, router, DNS, lease time.",
    "NTP: συγχρονισμός ώρας (UDP 123).": "NTP: time synchronisation (UDP 123).",
    "MAC προορισμού: η κάρτα δικτύου του επόμενου βήματος (συχνά ο router). ff:ff:ff:ff:ff:ff = broadcast σε όλους.":
        "Destination MAC: the network card of the next hop (often the router). ff:ff:ff:ff:ff:ff = broadcast to everyone.",
    "MAC πηγής: τα 3 πρώτα bytes (OUI) δείχνουν τον κατασκευαστή. Ο switch τη «μαθαίνει» στη θύρα που ήρθε.":
        "Source MAC: the first 3 bytes (OUI) show the manufacturer. The switch “learns” it on the port it arrived on.",
    "EtherType: τι μεταφέρει το πλαίσιο — 0x0800 IPv4, 0x86dd IPv6, 0x0806 ARP, 0x8100 VLAN tag.":
        "EtherType: what the frame carries — 0x0800 IPv4, 0x86dd IPv6, 0x0806 ARP, 0x8100 VLAN tag.",
    "PCP / CoS (3 bits): προτεραιότητα για QoS στο Layer 2.": "PCP / CoS (3 bits): priority for QoS at Layer 2.",
    "1 = request («ποιος έχει;», broadcast), 2 = reply (unicast). Gratuitous ARP: απάντηση χωρίς ερώτηση — έτσι γίνεται και το ARP spoofing.":
        "1 = request (“who has?”, broadcast), 2 = reply (unicast). Gratuitous ARP: an answer without a question — that's also how ARP spoofing works.",
    "Η MAC του αποστολέα.": "The sender's MAC.",
    "Η IP του αποστολέα.": "The sender's IP.",
    "Η MAC που ψάχνουμε (00:00:00:00:00:00 σε request).": "The MAC we're looking for (00:00:00:00:00:00 in a request).",
    "Η IP για την οποία ρωτάμε.": "The IP we're asking about.",
    "Μήκος κεφαλίδας σε λέξεις των 4 bytes (5 = 20 bytes, χωρίς options).": "Header length in 4-byte words (5 = 20 bytes, no options).",
    "DSCP (6 bits) + ECN: σήμανση QoS. Π.χ. EF (46) για φωνή.": "DSCP (6 bits) + ECN: QoS marking. E.g. EF (46) for voice.",
    "Συνολικό μήκος του IP πακέτου (κεφαλίδα + δεδομένα) σε bytes.": "Total length of the IP packet (header + data) in bytes.",
    "Αναγνωριστικό για επανασυναρμολόγηση fragments.": "Identifier for reassembling fragments.",
    "DF = Don't Fragment (μην το τεμαχίσεις — χρησιμοποιείται για Path MTU Discovery), MF = More Fragments.":
        "DF = Don't Fragment (don't split it — used for Path MTU Discovery), MF = More Fragments.",
    "Θέση του fragment (0 = πρώτο ή καθόλου τεμαχισμός).": "Fragment position (0 = first, or no fragmentation).",
    "Time To Live: κάθε router το μειώνει κατά 1· στο 0 το πακέτο πετιέται (και στέλνεται ICMP TTL exceeded — έτσι δουλεύει το traceroute). Αρχικό 64 = Linux/macOS, 128 = Windows, 255 = δικτυακές συσκευές.":
        "Time To Live: every router lowers it by 1; at 0 the packet is dropped (and an ICMP TTL exceeded is sent — that's how traceroute works). Starting value 64 = Linux/macOS, 128 = Windows, 255 = network devices.",
    "Τι είναι μέσα: 6 = TCP, 17 = UDP, 1 = ICMP, 50 = ESP (IPsec), 89 = OSPF.": "What's inside: 6 = TCP, 17 = UDP, 1 = ICMP, 50 = ESP (IPsec), 89 = OSPF.",
    "Checksum μόνο της κεφαλίδας· ξαναϋπολογίζεται σε κάθε router (γιατί αλλάζει το TTL).":
        "Checksum of the header only; recalculated at every router (because the TTL changes).",
    "IP πηγής. Αν είναι ιδιωτική (10/8, 172.16/12, 192.168/16), ο router θα την αλλάξει με NAT/PAT πριν βγει στο Internet.":
        "Source IP. If it's private (10/8, 172.16/12, 192.168/16), the router will swap it with NAT/PAT before it goes out to the Internet.",
    "IP προορισμού: ο router κάνει longest prefix match στον routing table για να αποφασίσει πού θα το στείλει.":
        "Destination IP: the router does a longest prefix match in its routing table to decide where to send it.",
    "Hop Limit: το αντίστοιχο του TTL.": "Hop Limit: the equivalent of TTL.",
    "IPv6 πηγής (fe80:: = link-local, 2000::/3 = global unicast).": "Source IPv6 (fe80:: = link-local, 2000::/3 = global unicast).",
    "IPv6 προορισμού (ff02:: = multicast στο τοπικό δίκτυο).": "Destination IPv6 (ff02:: = multicast on the local network).",
    "Flow Label: σημαδεύει πακέτα της ίδιας ροής.": "Flow Label: marks packets of the same flow.",
    "Θύρα πηγής. Από client: «εφήμερη» (49152–65535). Από server (π.χ. 443/80): είναι η απάντηση της υπηρεσίας.":
        "Source port. From a client: “ephemeral” (49152–65535). From a server (e.g. 443/80): it's the service's reply.",
    "Θύρα προορισμού: η υπηρεσία (443 HTTPS, 80 HTTP, 22 SSH, 1883 MQTT, 8883 MQTT/TLS).":
        "Destination port: the service (443 HTTPS, 80 HTTP, 22 SSH, 1883 MQTT, 8883 MQTT/TLS).",
    "Αριθμός σειράς: ποιο byte της ροής είναι το πρώτο αυτού του segment.": "Sequence number: which byte of the stream is the first of this segment.",
    "Αριθμός επιβεβαίωσης: «έλαβα τα πάντα μέχρι εδώ, στείλε το επόμενο».": "Acknowledgement number: “I got everything up to here, send the next one”.",
    "Μήκος κεφαλίδας TCP σε λέξεις των 4 bytes.": "TCP header length in 4-byte words.",
    "S = SYN (άνοιγμα), A = ACK, F = FIN (κλείσιμο), R = RST (απότομο κλείσιμο), P = PUSH. Handshake: SYN → SYN-ACK → ACK.":
        "S = SYN (open), A = ACK, F = FIN (close), R = RST (abrupt close), P = PUSH. Handshake: SYN → SYN-ACK → ACK.",
    "Window: πόσα bytes μπορεί να δεχτεί ο παραλήπτης πριν επιβεβαιώσει (flow control).":
        "Window: how many bytes the receiver can accept before acknowledging (flow control).",
    "Checksum κεφαλίδας + δεδομένων.": "Checksum of header + data.",
    "Urgent pointer (σχεδόν ποτέ σε χρήση).": "Urgent pointer (almost never used).",
    "Επιλογές: MSS (μέγιστο segment), Window Scale, SACK, Timestamps — συμφωνούνται στο SYN.":
        "Options: MSS (maximum segment), Window Scale, SACK, Timestamps — agreed in the SYN.",
    "Θύρα πηγής.": "Source port.",
    "Θύρα προορισμού (53 DNS, 67/68 DHCP, 123 NTP, 161 SNMP, 443 QUIC).": "Destination port (53 DNS, 67/68 DHCP, 123 NTP, 161 SNMP, 443 QUIC).",
    "Μήκος κεφαλίδας (8 bytes) + δεδομένων.": "Length of header (8 bytes) + data.",
    "Checksum (προαιρετικό στο IPv4, υποχρεωτικό στο IPv6).": "Checksum (optional in IPv4, mandatory in IPv6).",
    "Λεπτομέρεια του τύπου (π.χ. type 3 code 3 = port unreachable).": "Detail of the type (e.g. type 3 code 3 = port unreachable).",
    "Η ερώτηση: όνομα και τύπος (A = IPv4, AAAA = IPv6, MX, TXT…).": "The question: name and type (A = IPv4, AAAA = IPv6, MX, TXT…).",
    "Οι απαντήσεις.": "The answers.",
    "0 = ερώτηση, 1 = απάντηση.": "0 = query, 1 = response.",
    "0 = OK, 3 = NXDOMAIN (δεν υπάρχει το όνομα).": "0 = OK, 3 = NXDOMAIN (the name doesn't exist).",
}
for k, v in PKT.items():
    X(k, v)

# =====================================================================================================
# report.py — 📄 weekly report (/report)
# =====================================================================================================
REPORT = {
    "NetWatch — αναφορά": "NetWatch — report",
    "🖨 Εκτύπωση / PDF": "🖨 Print / PDF",
    "Βαθμός ασφάλειας": "Security score",
    "Ειδοποιήσεις": "Alerts",
    "Νέες συσκευές": "New devices",
    "πρώτη φορά στο δίκτυο": "first time on the network",
    "IoT που ελέγχθηκαν": "IoT devices checked",
    "καμία": "none",
    "σοβαρές": "high",
    "μέτριες": "medium",
    "χαμηλές": "low",
    "✅ Τι να κάνεις αυτή την εβδομάδα": "✅ What to do this week",
    "Τίποτα επείγον. 👌 Κράτα τις ενημερώσεις και ξανακοίτα την επόμενη εβδομάδα.": "Nothing urgent. 👌 Keep up with updates and check again next week.",
    "📊 Ειδοποιήσεις ανά μέρα": "📊 Alerts per day",
    "🔎 Τι είδους": "🔎 What kind",
    "Τύπος": "Type",
    "Πλήθος": "Count",
    "Σοβαρότερη": "Most severe",
    "👤 Ποιοι προκάλεσαν τις περισσότερες (μέτριες/σοβαρές)": "👤 Who caused the most (medium/high)",
    "📟 Νέες συσκευές": "📟 New devices",
    "Πρώτη φορά": "First seen",
    "Αν κάποια δεν την αναγνωρίζεις, άλλαξε τον κωδικό του Wi-Fi.": "If you don't recognise one, change your Wi-Fi password.",
    "🔌 IoT συσκευές": "🔌 IoT devices",
    "Συσκευή": "Device",
    "Βαθμός": "Score",
    "Προβλήματα": "Problems",
    "🌍 Με ποιες χώρες μιλάει κάθε συσκευή": "🌍 Which countries each device talks to",
    "Χώρες": "Countries",
    "(μαθαίνω ακόμα)": "(still learning)",
}
for k, v in REPORT.items():
    X(k, v)
P("🛡 NetWatch — αναφορά {d} ημερών", "🛡 NetWatch — {1}-day report")
P("{} · λειτουργία {}", "{1} · {2} mode")
P("βαθμίδα {}", "grade {1}")
P("{d} με σοβαρό πρόβλημα", "{1} with a serious problem")
SEVS = [("σοβαρές", "high"), ("μέτριες", "medium"), ("χαμηλές", "low")]
import itertools as _it
for r in (3, 2, 1):
    for combo in _it.combinations(SEVS, r):
        P(T(" · ".join("{d} " + g for g, _ in combo), " · ".join("{%d} %s" % (i + 1, e) for i, (_, e) in enumerate(combo))))
MQ = T("{*} · {d} γνωστοί clients · {d} συσκευές από τα topics", "{1} · {2} known clients · {3} devices from the topics")
P(MQ + T(" · σιωπούν: {}", " · silent: {1}"))
P(MQ)
P("Φτιάχτηκε από το NetWatch στις {}. Περιέχει IP και MAC του δικτύου σου — μην τη μοιραστείς δημόσια.",
  "Made by NetWatch on {1}. It contains IPs and MACs of your network — don't share it publicly.")

# =====================================================================================================
# shellrun.py — 🖥 Academy terminal (blocked-command explanations; the page renders `code` as <code>, so
# the text fragments between code spans are added too, see SHELL_FRAGMENTS in build step below)
# =====================================================================================================
NOT_MAC = {
    "Το `ip` είναι του Linux (Raspberry Pi). Στο Mac: `ifconfig` (διευθύνσεις), `netstat -rn` (routes), `arp -a` (γείτονες).":
        "`ip` is a Linux command (Raspberry Pi). On a Mac: `ifconfig` (addresses), `netstat -rn` (routes), `arp -a` (neighbours).",
    "Το `ss` είναι του Linux. Στο Mac: `netstat -an` ή `lsof -i -nP`.": "`ss` is a Linux command. On a Mac: `netstat -an` or `lsof -i -nP`.",
    "Το `apt` εγκαθιστά πακέτα στο Raspberry Pi/Debian. Στο Mac το αντίστοιχο είναι το `brew install …` (από δικό σου Terminal).":
        "`apt` installs packages on Raspberry Pi/Debian. On a Mac the equivalent is `brew install …` (from your own Terminal).",
    "Το `apt-get` είναι του Raspberry Pi/Debian. Στο Mac: `brew`.": "`apt-get` is for Raspberry Pi/Debian. On a Mac: `brew`.",
    "Το `systemctl` διαχειρίζεται υπηρεσίες στο Linux (Pi). Στο Mac το αντίστοιχο είναι το `launchctl` / `brew services`.":
        "`systemctl` manages services on Linux (Pi). On a Mac the equivalent is `launchctl` / `brew services`.",
    "Το `journalctl` δείχνει logs στο Linux. Στο Mac: `log show --last 5m`.": "`journalctl` shows logs on Linux. On a Mac: `log show --last 5m`.",
    "Το `ufw` είναι firewall του Linux. Στο Mac το firewall είναι το pf (και το Application Firewall στις Ρυθμίσεις).":
        "`ufw` is a Linux firewall. On a Mac the firewall is pf (plus the Application Firewall in Settings).",
    "Το `iptables` είναι firewall του Linux. Στο Mac: pf (`pfctl`).": "`iptables` is a Linux firewall. On a Mac: pf (`pfctl`).",
    "Το `nft` (nftables) είναι firewall του Linux. Στο Mac: pf.": "`nft` (nftables) is a Linux firewall. On a Mac: pf.",
    "Το `raspi-config` υπάρχει μόνο στο Raspberry Pi OS.": "`raspi-config` only exists on Raspberry Pi OS.",
    "Το `tcpdump` θέλει δικαιώματα διαχειριστή — εδώ δεν τρέχω τίποτα ως root. Δες τα πακέτα ζωντανά στην καρτέλα 📦 Πακέτα του NetWatch!":
        "`tcpdump` needs admin rights — I don't run anything as root here. Watch the packets live in NetWatch's 📦 Packets tab!",
    "Το `esptool` μιλάει με το ESP32 πάνω από USB — τρέξ' το από δικό σου Terminal με την πλακέτα συνδεδεμένη.":
        "`esptool` talks to the ESP32 over USB — run it from your own Terminal with the board plugged in.",
    "Το `esptool` μιλάει με το ESP32 πάνω από USB — τρέξ' το από δικό σου Terminal.":
        "`esptool` talks to the ESP32 over USB — run it from your own Terminal.",
    "Το `idf.py` είναι του ESP-IDF — τρέξ' το από δικό σου Terminal μέσα στο project.": "`idf.py` is part of ESP-IDF — run it from your own Terminal inside the project.",
    "⚠️ Το `espefuse` γράφει eFuses (ΜΗ αναστρέψιμα). Ποτέ από εδώ — μόνο συνειδητά, από δικό σου Terminal.":
        "⚠️ `espefuse` writes eFuses (NOT reversible). Never from here — only deliberately, from your own Terminal.",
    "Το `arduino-cli` τρέξ' το από δικό σου Terminal μέσα στον φάκελο του sketch.": "`arduino-cli`: run it from your own Terminal inside the sketch folder.",
    "Ο broker `mosquitto` τρέχει στο Pi (ή `brew services start mosquitto` στο Mac).": "The `mosquitto` broker runs on the Pi (or `brew services start mosquitto` on a Mac).",
    "Το `mosquitto_passwd` αλλάζει αρχεία κωδικών — τρέξ' το στο Pi.": "`mosquitto_passwd` changes password files — run it on the Pi.",
    "Το fail2ban τρέχει στο Pi (Linux).": "fail2ban runs on the Pi (Linux).",
    "Το `ssh` είναι διαδραστικό — άνοιξέ το σε δικό σου Terminal.": "`ssh` is interactive — open it in your own Terminal.",
    "Το `ssh-keygen` φτιάχνει αρχεία κλειδιών — τρέξ' το σε δικό σου Terminal.": "`ssh-keygen` creates key files — run it in your own Terminal.",
    "Το `nano` είναι διαδραστικός editor — άνοιξέ το σε δικό σου Terminal.": "`nano` is an interactive editor — open it in your own Terminal.",
    "Διαδραστικός editor — άνοιξέ το σε δικό σου Terminal.": "An interactive editor — open it in your own Terminal.",
}
SHELL_STATIC = {
    "Δώσε στόχο, π.χ. `nmap -sT -p 22,80,1883 192.168.1.0/24`.": "Give a target, e.g. `nmap -sT -p 22,80,1883 192.168.1.0/24`.",
    "(σχόλιο — δεν τρέχει τίποτα)": "(comment — nothing runs)",
    "Εδώ επιτρέπεται μόνο `|` (pipe): όχι `;`, `&&`, `>`, `<`, `` ` `` ή `$(…)`. Τρέξε μία εντολή τη φορά.":
        "Only `|` (pipe) is allowed here: no `;`, `&&`, `>`, `<`, `` ` `` or `$(…)`. Run one command at a time.",
    "Άδειο κομμάτι στο pipe.": "Empty part in the pipe.",
    "Εδώ δεν τρέχει τίποτα με `sudo` (ως διαχειριστής) — για ασφάλεια.": "Nothing runs with `sudo` (as admin) here — for safety.",
    "Εδώ δεν τρέχει τίποτα με `sudo` (ως διαχειριστής) — για ασφάλεια. Δοκίμασε χωρίς sudo (π.χ. στο nmap βάλε `-sT` αντί για `-sS`).":
        "Nothing runs with `sudo` (as admin) here — for safety. Try without sudo (e.g. in nmap use `-sT` instead of `-sS`).",
    "Αυτό το είδος σάρωσης θέλει root. Εδώ χρησιμοποίησε `-sT` (TCP connect) — κάνει την ίδια δουλειά, απλώς πιο «θορυβώδικα».":
        "This kind of scan needs root. Here use `-sT` (TCP connect) — it does the same job, just more “noisily”.",
    "Αυτό το αρχείο έχει κλειδιά/κωδικούς — δεν το εμφανίζω εδώ.": "This file contains keys/passwords — I won't show it here.",
}
for k, v in NOT_MAC.items():
    SHELL_STATIC["Εδώ δεν τρέχει τίποτα με `sudo` (ως διαχειριστής) — για ασφάλεια. " + k] = "Nothing runs with `sudo` (as admin) here — for safety. " + v
SHELL_STATIC.update(NOT_MAC)
# dynamic messages: (Greek template, English template) with {c} = the command in backticks
SHELL_DYN = [
    ("Το `{c}` δεν επιτρέπεται εδώ (διαβάζει/γράφει αρχεία ή τρέχει scripts).", "`{c}` isn't allowed here (it reads/writes files or runs scripts)."),
    ("Το nmap εδώ σκανάρει μόνο το δικό σου δίκτυο (ιδιωτικές IP) ή το scanme.nmap.org — όχι το `{c}`.",
     "Here nmap only scans your own network (private IPs) or scanme.nmap.org — not `{c}`."),
    ("Το `{c}` δεν είναι ιδιωτική διεύθυνση. Σκανάρουμε μόνο ό,τι σου ανήκει.", "`{c}` isn't a private address. We only scan what belongs to you."),
    ("Το `{c}` δεν είναι στη λίστα ασφαλών εντολών αυτού του τερματικού. Τρέξ' το σε δικό σου Terminal αν το εμπιστεύεσαι.",
     "`{c}` isn't on this terminal's list of safe commands. Run it in your own Terminal if you trust it."),
    ("Το `{c}` επιτρέπεται εδώ μόνο ως: `{c}`", "`{c}` is only allowed here as: `{c}`"),
    ("Εδώ το `{c}` μόνο διαβάζει: όχι επιλογές που γράφουν αρχεία ({c}).", "Here `{c}` only reads: no options that write files ({c})."),
    ("Το `{c}` με δεύτερο αρχείο γράφει έξοδο σε αρχείο — όχι εδώ.", "`{c}` with a second file writes output to a file — not here."),
    ("Το `{c}` δεν είναι εγκατεστημένο σε αυτόν τον υπολογιστή.", "`{c}` isn't installed on this computer."),
    ("Το `{c}` δεν είναι εγκατεστημένο σε αυτόν τον υπολογιστή (`{c}`).", "`{c}` isn't installed on this computer (`{c}`)."),
]
for k, v in SHELL_STATIC.items():
    X(k, v)
for g, e in SHELL_DYN:
    t = T(g.replace("{c}", "{}"), re.sub(r"\{c\}", lambda m, c=iter(range(1, 10)): "{%d}" % next(c), e))
    P(t)
P("Το `{}` επιτρέπεται εδώ μόνο ως: {}", "`{1}` is only allowed here as: {2}")
P("Δεν καταλαβαίνω την εντολή ({}).", "I don't understand the command ({1}).")
X("… (κόπηκε: πολύ μεγάλη έξοδος)", "… (cut: output too long)")
P("⏱ σταμάτησε μετά από {d}″", "⏱ stopped after {1}″")

# text fragments between <code> spans, as the Academy terminal shows them ("💡 " + inline(message))
def _frags(s):
    return re.split(r"`([^`]+)`", s)[0::2]


def _add_frags(g, e, first_prefix="💡 "):
    gf, ef = _frags(g), _frags(e)
    if len(gf) != len(ef):
        print("WARN fragment mismatch:", g, file=sys.stderr)
        return
    for i, (a, b) in enumerate(zip(gf, ef)):
        if i == 0:
            a, b = first_prefix + a, first_prefix + b
        a2 = norm(a)
        if not a2 or not re.search(r"[Ͱ-Ͽἀ-῿]", a2):
            continue
        b2 = norm(b) if norm(b) else ""
        if a2 in EXACT and EXACT[a2] != b2 and not (a2.startswith("💡") and EXACT[a2] == "💡" and not b2.strip("💡 ")):
            print("FRAG conflict:", repr(a2), repr(EXACT[a2]), repr(b2), file=sys.stderr)
            continue
        EXACT[a2] = b2 if b2 else ("💡" if a2.startswith("💡") else b2)


for k, v in SHELL_STATIC.items():
    _add_frags(k, v)
for g, e in SHELL_DYN:
    _add_frags(g.replace("{c}", "x"), e.replace("{c}", "x"))

# =====================================================================================================
# combinations that are joined at runtime
# =====================================================================================================
# audit: protocol list containing the Greek label "HTTP φόρμα"
P("{d} σύνδεση(εις) έστειλαν κωδικό χωρίς κρυπτογράφηση ({*}HTTP φόρμα{*}).",
  "{1} connection(s) sent a password without encryption ({2}HTTP form{3}).")
PATS.insert([r for r, _ in PATS].index(T("{d} σύνδεση(εις) έστειλαν κωδικό χωρίς κρυπτογράφηση ({}).", "").regex()), PATS.pop())

# device services: "<why> · <TLS finding> · <TLS finding>"
TLS_F = [T("Παλιό πρωτόκολλο {} — σπασμένο, πρέπει TLS 1.2+", "Old protocol {1} — broken, needs TLS 1.2+"),
         T("Το πιστοποιητικό έληξε πριν {d} μέρες", "The certificate expired {1} days ago"),
         T("Self-signed πιστοποιητικό — ο browser δεν μπορεί να ελέγξει ότι μιλάς με τη σωστή συσκευή (κίνδυνος MITM)",
           "Self-signed certificate — the browser can't check that you're talking to the right device (MITM risk)")]
SEP = T(" · ", " · ")
for r in (3, 2, 1):
    for combo in _it.combinations(TLS_F, r):
        body = combo[0]
        for c in combo[1:]:
            body = body + SEP + c
        for pre in (None, T("RDP: απομακρυσμένη επιφάνεια εργασίας, κύρια πόρτα εισόδου για ransomware",
                            "RDP: remote desktop, a main way in for ransomware"),
                    T("Θύρα {} — συχνά backdoor/κακόβουλο λογισμικό", "Port {1} — often a backdoor/malware")):
            if pre is None and r == 1:
                continue
            P((pre + SEP + body) if pre else body)

# Wi-Fi Guard sharing: 2 items (any order) and AirPlay pair + one more
ALL_SHARE = dict(MAC_SHARING, MySQL="MySQL", PostgreSQL="PostgreSQL", Redis="Redis", MongoDB="MongoDB")
ITEM = lambda g, e: T(g + " ({d})", e + " ({1})")  # noqa: E731
for g1, e1 in ALL_SHARE.items():
    for g2, e2 in ALL_SHARE.items():
        if not (any(c > "ͯ" for c in g1 + g2)):
            continue
        P(T(SHARE_HEAD[0], SHARE_HEAD[1]) + ITEM(g1, e1) + T(", ", ", ") + ITEM(g2, e2) + T(".", "."))
        if g1 == g2 == "Δέκτης AirPlay":
            for g3, e3 in ALL_SHARE.items():
                P(T(SHARE_HEAD[0], SHARE_HEAD[1]) + ITEM(g1, e1) + T(", ", ", ") + ITEM(g2, e2) + T(", ", ", ") + ITEM(g3, e3) + T(".", "."))
                P(T(SHARE_HEAD[0], SHARE_HEAD[1]) + ITEM(g3, e3) + T(", ", ", ") + ITEM(g1, e1) + T(", ", ", ") + ITEM(g2, e2) + T(".", "."))
# the generic fallback must stay last among the sharing patterns
_gen = T(SHARE_HEAD[0] + "{}.", SHARE_HEAD[1] + "{1}.").regex()
_i = [r for r, _ in PATS].index(_gen)
PATS.append(PATS.pop(_i))
# fixes joined with " · " (sorted, unique): all pairs and triples
_fx = sorted(MAC_FIX)
for r in (2, 3):
    for combo in _it.combinations(_fx, r):
        X(" · ".join(combo), " · ".join(MAC_FIX[c] for c in combo))

# misc
X("Δεν μπλοκάρω τον router", "I won't block the router")
X("Γράψε το token που τύπωσε ο agent στην εκκίνηση (ή", "Enter the token the agent printed when it started (or")
X("στον server).", "on the server).")
X("Είσοδος", "Sign in")
X("# NetWatch: τίποτα μπλοκαρισμένο", "# NetWatch: nothing blocked")


# devtype.py (device kind labels on the LAN map)
for k, v in {"Υπολογιστής": "Computer", "Κινητό / tablet": "Phone / tablet", "Εκτυπωτής": "Printer", "Κάμερα": "Camera",
             "Κονσόλα": "Console", "Ηχείο / assistant": "Speaker / assistant", "Έξυπνη συσκευή": "Smart device",
             "Άγνωστη": "Unknown", "τυχαία MAC": "random MAC"}.items():
    X(k, v)


# =====================================================================================================
# netkit.py / pentest.py (technician toolkit)
# =====================================================================================================
# vendor / OS guess / tool labels
X("τυχαία MAC (κινητό/laptop με ιδιωτικότητα)", "random MAC (phone/laptop with privacy on)")
X("Linux/macOS/IoT (εκτίμηση από TTL)", "Linux/macOS/IoT (guessed from TTL)")
X("Windows (εκτίμηση από TTL)", "Windows (guessed from TTL)")
X("δικτυακός εξοπλισμός — router/switch/εκτυπωτής (εκτίμηση από TTL)", "network gear — router/switch/printer (guessed from TTL)")
NK_TOOLS = {"ping": "ping", "ερώτημα DNS": "DNS lookup", "σύγκριση DNS": "DNS comparison", "έλεγχος θυρών": "port check",
            "έλεγχος HTTP": "HTTP check", "Wake-on-LAN": "Wake-on-LAN", "ανακάλυψη ονομάτων": "name discovery"}
for g, e in NK_TOOLS.items():
    if g != e:
        X(g, e)
    X(g + " (🔴 Pentest → Εργαλεία)", e + " (🔴 Pentest → Tools)")
P("{} (🔴 Pentest → Εργαλεία)", "{1} (🔴 Pentest → Tools)")

# validation / errors (returned as {"error": …})
X("Μη έγκυρο όνομα", "Invalid name")
X("Μη έγκυρο όνομα ή IP — γράψε π.χ. 192.168.1.1 ή example.com", "Invalid name or IP — write e.g. 192.168.1.1 or example.com")
P("Μη χρήσιμος στόχος: {} (multicast/broadcast/0.0.0.0)", "Unusable target: {1} (multicast/broadcast/0.0.0.0)")
P("Μη χρήσιμος server: {} (multicast/broadcast/0.0.0.0)", "Unusable server: {1} (multicast/broadcast/0.0.0.0)")
P("Μη χρήσιμος {}: {} (multicast/broadcast/0.0.0.0)", "Unusable {1}: {2} (multicast/broadcast/0.0.0.0)")
P("Δεν βρέθηκε το όνομα «{}»", "Name “{1}” not found")
X("Μη έγκυρη MAC — γράψε π.χ. aa:bb:cc:dd:ee:ff", "Invalid MAC — write e.g. aa:bb:cc:dd:ee:ff")
X("Δώσε θύρες, π.χ. 22,80,443 ή 8000-8010", "Enter ports, e.g. 22,80,443 or 8000-8010")
X("Πολύ μεγάλη λίστα θυρών", "Port list too long")
P("Μη έγκυρη θύρα «{}» — π.χ. 22,80,8000-8010", "Invalid port “{1}” — e.g. 22,80,8000-8010")
P("Οι θύρες είναι από 1 έως 65535 («{}»)", "Ports go from 1 to 65535 (“{1}”)")
P("Λάθος διάστημα «{}» — το πρώτο πρέπει να είναι μικρότερο", "Wrong range “{1}” — the first number must be smaller")
P("Πάρα πολλές θύρες — το πολύ {d}", "Too many ports — at most {1}")
X("Δώσε θύρες, π.χ. 22,80,443", "Enter ports, e.g. 22,80,443")
P("Πάρα πολλές θύρες ({d}) — το πολύ {d}", "Too many ports ({1}) — at most {2}")
X("Μη έγκυρο πλήθος/διάστημα", "Invalid count/interval")
X("Πλήθος πακέτων: από 1 έως 20", "Packet count: 1 to 20")
X("Διάστημα: από 0,2 έως 5 δευτερόλεπτα", "Interval: 0.2 to 5 seconds")
X("Μη έγκυρη IP", "Invalid IP")
P("Άγνωστος τύπος — επιτρέπονται: {}", "Unknown type — allowed: {1}")
X("Δεν βρέθηκε DNS server του συστήματος — δώσε server", "No system DNS server found — enter a server")
X("Ο DNS server πρέπει να είναι IP (π.χ. 1.1.1.1)", "The DNS server must be an IP (e.g. 1.1.1.1)")
P("Ο DNS server {} δεν απάντησε σε {n} s", "DNS server {1} didn't answer within {2} s")
X("Μόνο διευθύνσεις http:// ή https://", "Only http:// or https:// addresses")
X("Λείπει το όνομα του server", "The server name is missing")
X("Μη έγκυρη θύρα στη διεύθυνση", "Invalid port in the address")
X("Δώσε διεύθυνση, π.χ. https://example.com", "Enter an address, e.g. https://example.com")
X("Πήρε πολύ ώρα — σταμάτησα", "It took too long — I stopped")
X("Πάρα πολλές ανακατευθύνσεις (πάνω από 8) — πιθανός βρόχος", "Too many redirects (more than 8) — probably a loop")
X("Η διεύθυνση broadcast πρέπει να είναι IPv4 (π.χ. 192.168.1.255)", "The broadcast address must be IPv4 (e.g. 192.168.1.255)")
X("Το Wake-on-LAN στέλνεται μόνο στο τοπικό δίκτυο (π.χ. 192.168.1.255)", "Wake-on-LAN is only sent on the local network (e.g. 192.168.1.255)")
X("Αυτή η MAC δεν ανήκει σε συσκευή (multicast/μηδενική)", "This MAC doesn't belong to a device (multicast/zero)")
P("Δεν στάλθηκε: {}", "Not sent: {1}")
X("Δώσε IP του τοπικού δικτύου", "Enter an IP on the local network")
P("Το πολύ {d} διευθύνσεις", "At most {1} addresses")
X("Μη έγκυρος αριθμός", "Invalid number")
X("Άγνωστο εργαλείο — ping, dns, dnscmp, ports, http, wol, names", "Unknown tool — ping, dns, dnscmp, ports, http, wol, names")

# DNS comparison
X("Σύστημα", "System")
X("Όλοι συμφωνούν (μικρές διαφορές στις IP είναι φυσιολογικές λόγω CDN).",
  "All agree (small differences in the IPs are normal because of CDNs).")
X("Δεν απάντησε κανένας δημόσιος resolver — δεν γίνεται σύγκριση.", "No public resolver answered — can't compare.")
X("Οι δημόσιοι resolvers δεν δίνουν δημόσια IP — δεν γίνεται σύγκριση.", "The public resolvers don't return a public IP — can't compare.")
X("Το όνομα υπάρχει μόνο στο τοπικό δίκτυο (π.χ. router.home) — φυσιολογικό.",
  "The name only exists on the local network (e.g. router.home) — that's normal.")
# the local resolver label "Σύστημα" is Greek itself: "Ο Σύστημα …" → "The system resolver …"
DNSCMP = [("Ο {} λέει ότι το όνομα δεν υπάρχει, ενώ οι δημόσιοι το βρίσκουν — φίλτρο (Pi-hole, γονικός έλεγχος) ή παραποίηση DNS.",
           "{1} says the name doesn't exist, while the public resolvers find it — a filter (Pi-hole, parental control) or DNS tampering."),
          ("Ο {} δίνει {} (ιδιωτική/μηδενική IP) ενώ οι δημόσιοι δίνουν δημόσια — αποκλεισμός διαφημίσεων (Pi-hole/AdGuard) ή πιθανό DNS hijack.",
           "{1} returns {2} (private/zero IP) while the public resolvers return a public one — ad blocking (Pi-hole/AdGuard) or possible DNS hijacking."),
          ("Ο {} δίνει εντελώς διαφορετικές IP — συνήθως CDN (άλλος server ανά περιοχή), όχι απαραίτητα πρόβλημα.",
           "{1} returns completely different IPs — usually a CDN (a different server per region), not necessarily a problem.")]
for lab_g, lab_e in (("Σύστημα", "The system resolver"), ("Router", "The router")):
    for g, e in DNSCMP:
        P(g.replace("Ο {}", "Ο " + lab_g, 1), e.replace("{1}", lab_e, 1).replace("{2}", "{1}"))
for g, e in DNSCMP:
    P(g, e)

# HTTP security headers
for g, e in {
    "Ο browser θα μπαίνει πάντα με HTTPS.": "The browser will always connect with HTTPS.",
    "Λείπει — ο browser μπορεί να «πέσει» σε HTTP (κίνδυνος downgrade).": "Missing — the browser may “fall back” to HTTP (downgrade risk).",
    "Περιορίζει από πού φορτώνονται scripts — προστασία από XSS.": "Limits where scripts load from — protection against XSS.",
    "Λείπει — λιγότερη προστασία από XSS.": "Missing — less protection against XSS.",
    "Η σελίδα δεν μπαίνει σε ξένο iframe.": "The page can't be put inside someone else's iframe.",
    "Λείπει — η σελίδα μπορεί να μπει σε iframe (clickjacking).": "Missing — the page can be put inside an iframe (clickjacking).",
    "Ο browser δεν «μαντεύει» τύπο αρχείου.": "The browser doesn't “guess” the file type.",
    "Λείπει — ο browser μπορεί να «μαντέψει» λάθος τύπο αρχείου.": "Missing — the browser may “guess” the wrong file type.",
    "Ελέγχεται τι διεύθυνση στέλνεται σε άλλα sites.": "Controls which address is sent to other sites.",
    "Λείπει — ισχύει η προεπιλογή του browser (συνήθως εντάξει).": "Missing — the browser default applies (usually fine).",
    "Περιορίζει κάμερα/μικρόφωνο/τοποθεσία.": "Limits camera/microphone/location.",
    "Λείπει — δεν περιορίζονται κάμερα/μικρόφωνο/τοποθεσία (μικρό θέμα).": "Missing — camera/microphone/location aren't limited (minor issue).",
    "Ισχύει μόνο σε HTTPS — η σελίδα είναι σε απλό HTTP.": "Only works over HTTPS — the page is on plain HTTP.",
    "Καλύπτεται από το frame-ancestors του CSP.": "Covered by the CSP frame-ancestors.",
    "Πρέπει να είναι «nosniff».": "It must be “nosniff”.",
}.items():
    X(g, e)
P("{} — αρχική σελίδα", "{1} — home page")

# TLS
P("Ο browser δεν εμπιστεύεται το πιστοποιητικό: {*}", "The browser doesn't trust the certificate: {1}")
P("Το πιστοποιητικό λήγει σε {d} μέρες", "The certificate expires in {1} days")
P("{} ({d} μέρες)", "{1} ({2} days)")

# UDP findings / banners
X("SNMP με community public — όποιος είναι στο δίκτυο διαβάζει (ίσως και αλλάζει) ρυθμίσεις της συσκευής",
  "SNMP with community “public” — anyone on the network can read (maybe even change) the device's settings")
P("DNS ({s}, αναδρομικός)", "DNS ({1}, recursive)")

# pentest.py — scan profiles and phases
X("Άγνωστο προφίλ — quick, top1000, full ή custom", "Unknown profile — quick, top1000, full or custom")
P("Το top1000 επιτρέπεται για έως {d} διευθύνσεις (π.χ. /24)", "top1000 is allowed for up to {1} addresses (e.g. /24)")
P("Πλήρης σάρωση (1–65535) μόνο για έως {d} διευθύνσεις — διάλεξε μία συσκευή (π.χ. 192.168.1.10)",
  "A full scan (1–65535) only for up to {1} addresses — pick one device (e.g. 192.168.1.10)")
X("Δεν υπάρχει ολοκληρωμένη σάρωση", "There's no finished scan")
X("Μορφή: csv, json ή md", "Format: csv, json or md")
X("σάρωση UDP (DNS, NTP, SNMP, SSDP, mDNS, NetBIOS)", "UDP scan (DNS, NTP, SNMP, SSDP, mDNS, NetBIOS)")
X("ονόματα, κατασκευαστές, TTL", "names, vendors, TTL")
P("σάρωση {d} θυρών σε {d} διευθύνσεις", "scanning {1} ports on {2} addresses")
# progress line in the UI: "<phase> — 14%"
for g, e in (("ανακάλυψη συσκευών", "discovering devices"), ("τέλος", "done"), ("έλεγχος TLS", "checking TLS"),
             ("σάρωση UDP (DNS, NTP, SNMP, SSDP, mDNS, NetBIOS)", "UDP scan (DNS, NTP, SNMP, SSDP, mDNS, NetBIOS)"),
             ("ονόματα, κατασκευαστές, TTL", "names, vendors, TTL")):
    P(T(g, e) + T(" — {d}%", " — {1}%"))
P("σάρωση θυρών σε {d} διευθύνσεις — {d}%", "scanning ports on {1} addresses — {2}%")
P("σάρωση {d} θυρών σε {d} διευθύνσεις — {d}%", "scanning {1} ports on {2} addresses — {3}%")
P("σάρωση {s} — {d}%", "scanning {1} — {2}%")

# pentest.py — Markdown export
P("# NetWatch — σάρωση δικτύου {*}", "# NetWatch — network scan {1}")
P("- Ημερομηνία: {}", "- Date: {1}")
P("- Προφίλ: {}", "- Profile: {1}")
P("- Συσκευές: {d} · ανοιχτές θύρες: {d}", "- Devices: {1} · open ports: {2}")
X("## Ευρήματα", "## Findings")
X("- Δεν βρέθηκε κάτι ανησυχητικό.", "- Nothing worrying was found.")
X("## Αλλαγές από την προηγούμενη σάρωση", "## Changes since the previous scan")
P("- Νέες συσκευές: {}", "- New devices: {1}")
P("- Συσκευές που λείπουν: {}", "- Missing devices: {1}")
P("- Νέες θύρες: {}", "- New ports: {1}")
P("- Θύρες που έκλεισαν: {}", "- Closed ports: {1}")
X("## Συσκευές", "## Devices")
P("- Κατασκευαστής: {}", "- Vendor: {1}")
P("- Μοντέλο: {}", "- Model: {1}")
P("- Λειτουργικό: {}", "- OS: {1}")
X("| Θύρα | Πρωτ. | Υπηρεσία | Έκδοση | Banner |", "| Port | Proto | Service | Version | Banner |")
X("- Καμία ανοιχτή θύρα από όσες ελέγχθηκαν.", "- None of the checked ports are open.")
MD_FINDINGS = TLS_F + [T("SNMP με community public — όποιος είναι στο δίκτυο διαβάζει (ίσως και αλλάζει) ρυθμίσεις της συσκευής",
                        "SNMP with community “public” — anyone on the network can read (maybe even change) the device's settings"),
                      T("Ο browser δεν εμπιστεύεται το πιστοποιητικό: {*}", "The browser doesn't trust the certificate: {1}"),
                      T("Το πιστοποιητικό λήγει σε {d} μέρες", "The certificate expires in {1} days")]
for g, e in (("Υψηλό", "High"), ("Μεσαίο", "Medium"), ("Χαμηλό", "Low")):
    X(g, e)
    for f in MD_FINDINGS:
        P(T("- **" + g + "** — `{}` — ", "- **" + e + "** — `{1}` — ") + f)
    P("- **" + g + "** — `{}` — {}", "- **" + e + "** — `{1}` — {2}")
for g, e in (("Linux/macOS/IoT (εκτίμηση από TTL)", "Linux/macOS/IoT (guessed from TTL)"), ("Windows (εκτίμηση από TTL)", "Windows (guessed from TTL)"),
             ("δικτυακός εξοπλισμός — router/switch/εκτυπωτής (εκτίμηση από TTL)", "network gear — router/switch/printer (guessed from TTL)")):
    X("- Λειτουργικό: " + g, "- OS: " + e)
X("- Κατασκευαστής: τυχαία MAC (κινητό/laptop με ιδιωτικότητα)", "- Vendor: random MAC (phone/laptop with privacy on)")
