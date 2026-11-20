"""🔕 Υγιεινή ειδοποιήσεων + 🧐 «Γιατί χτύπησε;»

Το πιο συχνό παράπονο για κάθε IDS/monitor (Zabbix, Auvik, Firewalla, Suricata με ET Open) δεν είναι ότι λείπουν
ανιχνεύσεις — είναι ότι υπάρχουν πολλές, επαναλαμβανόμενες και ανεξήγητες. Εδώ:

* Σίγαση με λήξη, από την ίδια την ειδοποίηση: «αυτός ο τύπος από αυτή τη συσκευή», «αυτός ο τύπος παντού»,
  «οτιδήποτε από αυτή τη συσκευή». Η σιγασμένη ειδοποίηση ΔΕΝ χάνεται: φαίνεται αχνή ως «αναμενόμενη»,
  μένει στο ιστορικό, αλλά δεν στέλνει ειδοποίηση, δεν ανοίγει υπόθεση, δεν «κοκκινίζει» τη συσκευή.
* «Θόρυβος»: ποιοι τύποι χτυπούν πιο συχνά (24ώ / 7 μέρες), από πόσες συσκευές — για να ξέρεις τι να ρυθμίσεις.
* «Γιατί χτύπησε;»: η λογική του ανιχνευτή, τα ΠΡΑΓΜΑΤΙΚΑ όρια από το config, πόσες φορές έχει ξαναγίνει,
  ποια είναι η συσκευή, τι άλλο έγινε γύρω στην ίδια ώρα, και συνηθισμένες αθώες εξηγήσεις.

Τίποτα δεν στέλνεται έξω· οι σιγάσεις μένουν στο data/mutes.json.
"""
import ipaddress
import json
import os
import threading
import time

from core import detector_for, mitre_for

MAX_MUTES = 500

# ανιχνευτής → κλειδιά στο thresholds του config που καθορίζουν πότε χτυπά
TH_KEYS = {
    "port_scan": ["port_scan"], "network_sweep": ["ping_sweep", "arp_sweep"], "brute_force": ["brute_force"],
    "syn_flood": ["syn_flood"], "icmp_flood": ["icmp_flood"], "arp_flood": ["arp_flood"], "beaconing": ["beaconing"],
    "dns_tunnel": ["dns_tunnel"], "dga": ["dga"], "dns_amplification": ["dns_amplification"],
    "dns_flood": ["dns_flood"], "nxdomain_flood": ["nxdomain_flood"], "new_device": ["new_device"],
}

# ανιχνευτής → (πώς δουλεύει, συνηθισμένες αθώες αιτίες) σε el / en
INFO = {
    "port_scan": ("Μία συσκευή δοκίμασε πολλές διαφορετικές θύρες (ή συνδυασμούς στόχου/θύρας) μέσα σε λίγα δευτερόλεπτα. "
                  "Μετράω μοναδικά ζεύγη (στόχος, θύρα) σε κυλιόμενο παράθυρο.",
                  "One device tried many different ports (or target/port pairs) within a few seconds. "
                  "I count unique (target, port) pairs in a sliding window.",
                  "Εφαρμογές σάρωσης (Fing, nmap), NAS ή εκτυπωτές που ψάχνουν υπηρεσίες, παιχνιδοκονσόλες, P2P.",
                  "Scanner apps (Fing, nmap), NAS or printers discovering services, game consoles, P2P."),
    "stealth_scan": ("Πακέτα TCP με «περίεργο» συνδυασμό σημαιών (NULL, FIN, Xmas) που δεν στέλνει μια κανονική εφαρμογή — "
                     "τα χρησιμοποιούν εργαλεία σάρωσης για να περάσουν απαρατήρητα.",
                     "TCP packets with an unusual flag combination (NULL, FIN, Xmas) that normal apps never send — "
                     "scanners use them to stay unnoticed.",
                     "Σπάνια αθώο· ίσως εργαλείο ελέγχου ασφαλείας που τρέχεις εσύ.",
                     "Rarely benign; maybe a security tool you run yourself."),
    "network_sweep": ("Μία συσκευή ρώτησε (ping ή ARP) πολλές διαφορετικές διευθύνσεις του δικτύου σε λίγα δευτερόλεπτα — "
                      "ψάχνει ποιοι υπάρχουν.",
                      "One device probed (ping or ARP) many different addresses within seconds — looking for who exists.",
                      "Ο router, εφαρμογές τύπου Fing, Home Assistant/NAS που ανακαλύπτουν συσκευές, έξυπνες TV.",
                      "The router, Fing-like apps, Home Assistant/NAS discovering devices, smart TVs."),
    "brute_force": ("Πολλές συνδέσεις στην ίδια υπηρεσία σύνδεσης (SSH, RDP, SMB, Telnet…) σε λίγα δευτερόλεπτα — "
                    "μοιάζει με δοκιμές κωδικών.",
                    "Many connections to the same login service (SSH, RDP, SMB, Telnet…) within seconds — looks like password guessing.",
                    "Εφαρμογές backup/συγχρονισμού σε NAS (SMB), scripts με SSH, monitoring που ελέγχει την υπηρεσία συχνά.",
                    "Backup/sync apps to a NAS (SMB), SSH scripts, monitoring that checks the service often."),
    "syn_flood": ("Πάρα πολλά αιτήματα έναρξης σύνδεσης (SYN) σε λίγα δευτερόλεπτα προς τον ίδιο στόχο.",
                  "Too many connection-start requests (SYN) to the same target within seconds.",
                  "Load tests, πολύ «φλύαρες» εφαρμογές, speed tests.", "Load tests, very chatty apps, speed tests."),
    "icmp_flood": ("Πάρα πολλά ping σε λίγα δευτερόλεπτα.", "Too many pings within seconds.",
                   "Εργαλεία monitoring/ping με μικρό διάστημα, speed tests.", "Monitoring/ping tools with short intervals, speed tests."),
    "arp_spoofing": ("Η ίδια IP εμφανίστηκε με ΔΙΑΦΟΡΕΤΙΚΗ MAC από αυτή που ξέραμε — κάποιος ίσως προσποιείται άλλη συσκευή "
                     "(συχνά τον router) για να περνά η κίνηση από εκείνον.",
                     "The same IP appeared with a DIFFERENT MAC than the one we knew — someone may be impersonating "
                     "another device (often the router) so traffic passes through it.",
                     "Αλλαγή router/κάρτας δικτύου, mesh/extender, VM με bridge, failover δύο router.",
                     "Replaced router/network card, mesh/extender, bridged VM, two-router failover."),
    "arp_flood": ("Πάρα πολλά πακέτα ARP από μία συσκευή σε λίγα δευτερόλεπτα.", "Too many ARP packets from one device within seconds.",
                  "Συσκευές με προβληματικό driver, IoT που κολλάει, σαρώσεις δικτύου.",
                  "Devices with buggy drivers, a hung IoT device, network scans."),
    "rogue_dhcp": ("Απάντηση DHCP από συσκευή που ΔΕΝ είναι ο router σου — μπορεί να δίνει ψεύτικο gateway/DNS.",
                   "A DHCP reply from a device that is NOT your router — it may hand out a fake gateway/DNS.",
                   "Δεύτερος router ή mesh σε λειτουργία router αντί για access point, Pi-hole/NAS με ενεργό DHCP.",
                   "A second router or mesh in router mode instead of access point, Pi-hole/NAS with DHCP enabled."),
    "dns_spoofing": ("Απάντηση DNS που δεν ταιριάζει με αυτό που περιμέναμε (π.χ. ιδιωτική IP για δημόσιο όνομα, ή απάντηση "
                     "από άλλον server από αυτόν που ρωτήθηκε).",
                     "A DNS answer that doesn't match what we expected (e.g. a private IP for a public name, or an answer "
                     "from a different server than the one asked).",
                     "Pi-hole/AdGuard που μπλοκάρει (απαντά 0.0.0.0), split DNS στη δουλειά, captive portal.",
                     "Pi-hole/AdGuard blocking (answers 0.0.0.0), split DNS at work, captive portals."),
    "inbound": ("Σύνδεση ΠΡΟΣ συσκευή του δικτύου σου από έξω (internet).",
                "A connection TO a device on your network from outside (internet).",
                "Port forwarding που έχεις βάλει εσύ (π.χ. για κάμερα/παιχνίδι), UPnP, P2P.",
                "Port forwarding you set up (e.g. camera/game), UPnP, P2P."),
    "suspicious_port": ("Συσκευή σου μίλησε προς θύρα που χρησιμοποιείται συχνά από κακόβουλα προγράμματα ή backdoors.",
                        "Your device talked to a port commonly used by malware or backdoors.",
                        "Παιχνίδια, VPN, εφαρμογές με δικές τους θύρες.", "Games, VPNs, apps with their own ports."),
    "beaconing": ("Μία συσκευή επικοινωνεί με τον ίδιο προορισμό σε ΠΟΛΥ τακτά διαστήματα (μικρή διακύμανση/jitter) — "
                  "έτσι «χτυπούν την πόρτα» τα κακόβουλα προγράμματα στον server τους (C2).",
                  "One device contacts the same destination at VERY regular intervals (low jitter) — that is how malware "
                  "checks in with its server (C2).",
                  "Ενημερώσεις, push notifications, NTP, έξυπνες συσκευές που στέλνουν τηλεμετρία, monitoring.",
                  "Updates, push notifications, NTP, smart devices sending telemetry, monitoring."),
    "dns_tunnel": ("Πολλά μακριά, «τυχαία» υπο-ονόματα στο ίδιο domain σε λίγο χρόνο — έτσι κρύβονται δεδομένα μέσα σε DNS.",
                   "Many long, random-looking subdomains of the same domain in a short time — a way to hide data inside DNS.",
                   "Antivirus/CDN που κωδικοποιούν στοιχεία στο DNS (π.χ. ESET, Sophos, Akamai), Apple/Google υπηρεσίες.",
                   "Antivirus/CDNs that encode data in DNS (e.g. ESET, Sophos, Akamai), Apple/Google services."),
    "dga": ("Πολλά ονόματα που ΔΕΝ υπάρχουν (NXDOMAIN) και μοιάζουν τυχαία — έτσι ψάχνει κακόβουλο πρόγραμμα τον server του.",
            "Many names that DO NOT exist (NXDOMAIN) and look random — how malware searches for its server.",
            "Browsers που ελέγχουν το DNS με τυχαία ονόματα (Chrome), λάθος ρυθμίσεις DNS.",
            "Browsers probing DNS with random names (Chrome), DNS misconfiguration."),
    "new_device": ("Εμφανίστηκε MAC που δεν είχαμε ξαναδεί στο δίκτυο.", "A MAC we had never seen before appeared on the network.",
                   "Κινητά με «τυχαία MAC» (αλλάζει ανά δίκτυο/μέρα), επισκέπτες, νέα συσκευή σου.",
                   "Phones with private/random MAC (changes per network/day), guests, your new device."),
    "threat_intel": ("Η IP/το όνομα υπάρχει σε λίστα γνωστών κακόβουλων (threat intel) ή σε λίστα κόμβων Tor.",
                     "The IP/name is on a list of known-bad addresses (threat intel) or Tor nodes.",
                     "Οι λίστες έχουν και λάθη: κοινόχρηστα cloud/CDN IP που κάποτε χρησιμοποιήθηκαν κακόβουλα.",
                     "Lists have mistakes: shared cloud/CDN IPs that were once used maliciously."),
    "cleartext_creds": ("Είδα κωδικό/στοιχεία σύνδεσης να περνούν ΧΩΡΙΣ κρυπτογράφηση (HTTP, FTP, Telnet…).",
                        "I saw a password/login details sent WITHOUT encryption (HTTP, FTP, Telnet…).",
                        "Παλιές συσκευές (εκτυπωτές, κάμερες, router) με διαχείριση σε HTTP.",
                        "Old devices (printers, cameras, routers) managed over HTTP."),
    "honeypot": ("Κάποιος συνδέθηκε σε ψεύτικη υπηρεσία-παγίδα που κανείς δεν έχει λόγο να αγγίξει.",
                 "Someone connected to a fake trap service that nobody has a reason to touch.",
                 "Δικές σου σαρώσεις, εφαρμογές που ψάχνουν εκτυπωτές/υπηρεσίες.", "Your own scans, apps looking for printers/services."),
    "segmentation": ("Συσκευή από ένα τμήμα του δικτύου (π.χ. IoT) έφτασε σε τμήμα που θα έπρεπε να είναι αποκλεισμένο.",
                     "A device from one network segment (e.g. IoT) reached a segment that should be blocked.",
                     "Κανόνας firewall που επιτρέπει σκόπιμα (π.χ. Home Assistant → IoT).",
                     "A firewall rule that deliberately allows it (e.g. Home Assistant → IoT)."),
    "wifi_guard": ("Ο έλεγχος Wi‑Fi (κάθε φορά που συνδέεσαι σε νέο δίκτυο) βρήκε κάτι ύποπτο: απαντήσεις DNS που δεν ταιριάζουν "
                   "με δημόσιους resolvers (DNS hijacking), DNSSEC που «σβήνει», ή πιστοποιητικό HTTPS που δεν είναι το αναμενόμενο "
                   "(κάποιος ανοίγει την κρυπτογράφηση στη μέση — TLS interception).",
                   "The Wi‑Fi check (each time you join a new network) found something suspicious: DNS answers that don't match public "
                   "resolvers (DNS hijacking), DNSSEC being stripped, or an HTTPS certificate that isn't the expected one "
                   "(someone opening the encryption in the middle — TLS interception).",
                   "Captive portals ξενοδοχείων/αεροδρομίων, εταιρικά δίκτυα με proxy/antivirus που ελέγχει το HTTPS, γονικός έλεγχος.",
                   "Hotel/airport captive portals, corporate networks with a proxy/antivirus inspecting HTTPS, parental controls."),
    "config_backup": ("Το αντίγραφο ρυθμίσεων (SSH, μόνο ανάγνωση) μιας συσκευής δικτύου διαφέρει από το προηγούμενο — κάποιος άλλαξε το config.",
                      "The configuration backup (SSH, read-only) of a network device differs from the previous one — someone changed the config.",
                      "Δική σου αλλαγή, αυτόματη ενημέρωση firmware, μετρητές/χρονοσφραγίδες μέσα στο config.",
                      "Your own change, an automatic firmware update, counters/timestamps inside the config."),
    "mqtt_guard": ("Το MQTT guard μαθαίνει τι κάνει κανονικά κάθε IoT συσκευή στον broker και ειδοποιεί για ό,τι ξεφεύγει.",
                   "The MQTT guard learns what each IoT device normally does on the broker and alerts on anything unusual.",
                   "Νέες συσκευές/αυτοματοποιήσεις, ενημερώσεις firmware.", "New devices/automations, firmware updates."),
    "custom_rules": ("Ταίριαξε ένας από τους ΔΙΚΟΥΣ σου κανόνες (καρτέλα 🧩 Κανόνες).", "One of YOUR rules matched (🧩 Rules tab).",
                     "Δες αν ο κανόνας είναι πολύ γενικός.", "Check whether the rule is too broad."),
}
# τύποι χωρίς ανιχνευτή στο core.MITRE (άλλα modules) → εξήγηση με βάση την αρχή του ονόματος
PREFIX_INFO = [
    ("Συσκευή παρακάμπτει το DNS", "encdns",
     "Η συσκευή ρωτά DNS ΑΠΕΥΘΕΙΑΣ σε εξωτερικό server (π.χ. 8.8.8.8) ή μέσω κρυπτογραφημένου DNS (DoH/DoT/DoQ), "
     "αντί για τον router/Pi-hole σου — άρα δεν περνά από τα φίλτρα σου και δεν βλέπεις τι ονόματα ψάχνει.",
     "The device asks DNS DIRECTLY from an outside server (e.g. 8.8.8.8) or over encrypted DNS (DoH/DoT/DoQ) instead "
     "of your router/Pi-hole — so it skips your filters and you can't see which names it looks up.",
     "Browsers με «Secure DNS» (Chrome, Firefox, Edge), Android «Ιδιωτικό DNS», smart TV/Chromecast με σταθερό 8.8.8.8, VPN.",
     "Browsers with “Secure DNS” (Chrome, Firefox, Edge), Android “Private DNS”, smart TVs/Chromecast with hard-coded 8.8.8.8, VPNs."),
    ("IoT: επικοινωνία εκτός προφίλ", "iot_firewall",
     "Το NetWatch έμαθε με ποιους μιλά κανονικά αυτή η IoT συσκευή (περίοδος εκμάθησης). Τώρα μίλησε σε προορισμό ή θύρα "
     "που ΔΕΝ υπήρχε στο προφίλ της.",
     "NetWatch learned who this IoT device normally talks to (learning period). It has now talked to a destination or "
     "port that was NOT in its profile.",
     "Ενημέρωση firmware, νέος cloud server του κατασκευαστή, νέα λειτουργία της εφαρμογής. Αν το αναγνωρίζεις, έγκρινέ το "
     "στο προφίλ (🧱 IoT firewall).",
     "Firmware update, a new vendor cloud server, a new app feature. If you recognise it, approve it in the profile (🧱 IoT firewall)."),
    ("Νέο πιστοποιητικό για το domain", "ct_watch",
     "Στα δημόσια logs Certificate Transparency (crt.sh) εμφανίστηκε νέο πιστοποιητικό TLS για domain σου.",
     "A new TLS certificate for your domain appeared in the public Certificate Transparency logs (crt.sh).",
     "Αυτόματη ανανέωση Let’s Encrypt, Cloudflare, hosting που βγάζει δικά του πιστοποιητικά.",
     "Automatic Let’s Encrypt renewal, Cloudflare, hosting that issues its own certificates."),
    ("Εφαρμογή εκτός VPN", "vpn",
     "Ενώ το VPN είναι ενεργό, κίνηση εφαρμογής βγήκε από τη φυσική κάρτα (Wi‑Fi/Ethernet) αντί από το τούνελ (split tunnel/διαρροή).",
     "While the VPN is on, an app's traffic left through the physical card (Wi‑Fi/Ethernet) instead of the tunnel (split tunnel/leak).",
     "Split tunneling που έχεις ρυθμίσει εσύ, τοπικές υπηρεσίες (AirPlay, εκτυπωτής), εφαρμογές που εξαιρεί το ίδιο το VPN.",
     "Split tunneling you configured, local services (AirPlay, printer), apps the VPN itself excludes."),
    ("Αποτυχημένες συνδέσεις (syslog)", "syslog",
     "Ο router/switch/server σου έστειλε στο NetWatch (syslog) πολλά μηνύματα αποτυχημένης σύνδεσης σε λίγο χρόνο.",
     "Your router/switch/server sent NetWatch (syslog) many failed-login messages in a short time.",
     "Λάθος αποθηκευμένος κωδικός σε εφαρμογή/script που ξαναπροσπαθεί, monitoring με παλιά στοιχεία.",
     "A wrong saved password in an app/script that keeps retrying, monitoring with old credentials."),
    ("Σύνδεση έπεσε (syslog)", "syslog",
     "Συσκευή δικτύου ανέφερε μέσω syslog ότι μια θύρα/σύνδεση έπεσε (link down).",
     "A network device reported via syslog that a port/link went down.",
     "Κάποιος έβγαλε καλώδιο, συσκευή μπήκε σε sleep, επανεκκίνηση.", "Someone unplugged a cable, a device went to sleep, a reboot."),
    ("Νέο MQTT topic", "mqtt_guard",
     "Το NetWatch έμαθε ποια MQTT topics χρησιμοποιεί κάθε συσκευή. Μία συσκευή δημοσίευσε/εγγράφηκε σε topic που δεν είχε ξαναχρησιμοποιήσει "
     "(πιο σοβαρό αν μοιάζει με εντολή: cmd, set, ota…).",
     "NetWatch learned which MQTT topics each device uses. A device published/subscribed to a topic it had never used "
     "(more serious if it looks like a command: cmd, set, ota…).",
     "Νέα λειτουργία ή ενημέρωση ESPHome/Tasmota, νέα αυτοματοποίηση στο Home Assistant.",
     "A new ESPHome/Tasmota feature or update, a new Home Assistant automation."),
    ("Άγνωστος MQTT client", "mqtt_guard",
     "Συνδέθηκε στον MQTT broker σου client που δεν είχε εμφανιστεί στην περίοδο εκμάθησης.",
     "A client that never appeared during the learning period connected to your MQTT broker.",
     "Νέα συσκευή IoT που πρόσθεσες, επανεγκατάσταση Home Assistant/Node-RED με νέο client id.",
     "A new IoT device you added, a Home Assistant/Node-RED reinstall with a new client id."),
    ("Deauth επίθεση", "sensor",
     "Ο αισθητήρας Wi‑Fi (ESP32) μέτρησε πολλά πακέτα «αποσύνδεσης» (deauthentication) ανά δευτερόλεπτο — έτσι πετάνε "
     "συσκευές έξω από το Wi‑Fi (για να τις σπρώξουν σε ψεύτικο δίκτυο ή να «πιάσουν» το handshake).",
     "The Wi‑Fi sensor (ESP32) counted many deauthentication packets per second — the way devices are kicked off Wi‑Fi "
     "(to push them to a fake network or capture the handshake).",
     "Λίγα deauth είναι φυσιολογικά (roaming σε mesh, router που αλλάζει κανάλι). Πολλά/δευτ. συνεχώς δεν είναι.",
     "A few deauths are normal (mesh roaming, router changing channel). Many per second continuously are not."),
    ("Evil twin", "wifi_guard",
     "Υπάρχει και δεύτερο Wi‑Fi με το ΙΔΙΟ όνομα αλλά διαφορετική ασφάλεια/κατασκευαστή — μπορεί να είναι ψεύτικο access point "
     "που μιμείται το δικό σου.",
     "There is a second Wi‑Fi with the SAME name but different security/vendor — it may be a fake access point imitating yours.",
     "Mesh/extender με λίγο διαφορετικές ρυθμίσεις, το ίδιο όνομα σε 2.4 και 5 GHz με διαφορετικό WPA, γείτονας με ίδιο όνομα.",
     "A mesh/extender with slightly different settings, the same name on 2.4 and 5 GHz with different WPA, a neighbour with the same name."),
    ("Ανοιχτό Wi", "wifi_guard",
     "Το Wi‑Fi στο οποίο είσαι συνδεδεμένος δεν έχει κρυπτογράφηση — όποιος είναι κοντά μπορεί να δει ό,τι δεν είναι HTTPS.",
     "The Wi‑Fi you are on has no encryption — anyone nearby can see whatever isn't HTTPS.",
     "Δίκτυα επισκεπτών, καφετέριες, ξενοδοχεία (εκεί είναι αναμενόμενο — χρησιμοποίησε VPN).",
     "Guest networks, cafés, hotels (expected there — use a VPN)."),
    ("Πιστοποιητικό λήγει", "health",
     "Ο έλεγχος υγείας είδε ότι το πιστοποιητικό TLS μιας υπηρεσίας σου λήγει σε λιγότερο από 14 μέρες (ή έληξε).",
     "The health check saw that a service's TLS certificate expires in under 14 days (or has expired).",
     "Αν χρησιμοποιείς Let’s Encrypt, η ανανέωση γίνεται συνήθως 30 μέρες πριν — αν το βλέπεις, η αυτόματη ανανέωση ίσως χάλασε.",
     "With Let’s Encrypt, renewal usually happens 30 days before — if you see this, auto-renewal may be broken."),
    ("Νέα χώρα για συσκευή", "threat_intel",
     "Συσκευή του δικτύου σου μίλησε για ΠΡΩΤΗ φορά με server σε χώρα που δεν είχε ξαναμιλήσει.",
     "A device on your network talked for the FIRST time to a server in a country it had never talked to.",
     "CDN/cloud που άλλαξε περιοχή, ταξίδι (laptop/κινητό), VPN, νέα εφαρμογή.",
     "A CDN/cloud changing region, travel (laptop/phone), a VPN, a new app."),
    ("Άλλαξε ο Tor guard", "threat_intel",
     "Ο πρώτος κόμβος (guard) που χρησιμοποιεί το Tor σου άλλαξε.", "The first node (guard) your Tor uses changed.",
     "Ο guard αλλάζει κανονικά κάθε λίγους μήνες ή όταν πέφτει.", "The guard normally changes every few months or when it goes down."),
    ("Διαρροή", "privacy_leaks",
     "Ενώ είσαι σε VPN, ερώτημα DNS ή κίνηση IPv6 βγήκε ΕΞΩ από το τούνελ — το site/ο πάροχος βλέπει την πραγματική σου σύνδεση.",
     "While on a VPN, a DNS query or IPv6 traffic left OUTSIDE the tunnel — the site/ISP sees your real connection.",
     "VPN χωρίς υποστήριξη IPv6, «έξυπνο» DNS του λειτουργικού, split tunnel.", "A VPN without IPv6 support, the OS's “smart” DNS, split tunnel."),
    ("DNS amplification", "dns_amplification",
     "Πολλές μεγάλες απαντήσεις DNS προς λίγους στόχους — ή ο DNS server σου απαντά σε όλο το internet (ανοιχτός resolver) και "
     "μπορεί να χρησιμοποιηθεί σε επιθέσεις DDoS.",
     "Many large DNS answers toward few targets — or your DNS server answers the whole internet (open resolver) and can be used in DDoS attacks.",
     "Pi-hole/DNS server με port forwarding 53 προς τα έξω κατά λάθος.", "A Pi-hole/DNS server with port 53 forwarded to the outside by mistake."),
    ("DNS flood", "dns_flood", "Πάρα πολλά ερωτήματα DNS σε λίγα δευτερόλεπτα.", "Too many DNS queries within seconds.",
     "Εφαρμογή που κόλλησε σε βρόχο, monitoring με μικρό διάστημα.", "An app stuck in a loop, monitoring with a short interval."),
    ("NXDOMAIN flood", "nxdomain_flood",
     "Πάρα πολλά ερωτήματα για ονόματα που δεν υπάρχουν (συχνά τυχαία υπο-ονόματα) — επίθεση που εξαντλεί τον DNS server.",
     "Too many queries for names that don't exist (often random subdomains) — an attack that exhausts the DNS server.",
     "Λάθος ρύθμιση domain αναζήτησης, συσκευή που ψάχνει συνέχεια έναν server που δεν υπάρχει.",
     "A wrong search-domain setting, a device constantly looking for a server that doesn't exist."),
    ("DNS rebinding", "dns_rebinding",
     "Δημόσιο όνομα απάντησε με ΙΔΙΩΤΙΚΗ IP του LAN σου — τρόπος να «μπει» ιστοσελίδα στις συσκευές του δικτύου σου μέσω του browser.",
     "A public name answered with a PRIVATE IP of your LAN — a way for a web page to reach devices on your network through the browser.",
     "Υπηρεσίες τύπου nip.io/sslip.io, Plex, δικό σου split DNS.", "Services like nip.io/sslip.io, Plex, your own split DNS."),
    ("IoT συσκευή σιώπησε", "mqtt_guard",
     "IoT συσκευή που στέλνει κανονικά τακτικά (MQTT/heartbeat) σταμάτησε να ακούγεται.",
     "An IoT device that normally reports regularly (MQTT/heartbeat) stopped being heard.",
     "Ρεύμα, κακό Wi‑Fi, επανεκκίνηση router, ενημέρωση.", "Power, bad Wi‑Fi, router reboot, an update."),
    ("IoT συσκευή ξαναμίλησε", "mqtt_guard", "Η IoT συσκευή που είχε σιωπήσει ξανακούγεται.", "The IoT device that had gone silent is heard again.",
     "Συνήθως απλώς επανήλθε.", "Usually it simply came back."),
    ("Εντολή MQTT", "mqtt_guard",
     "Στάλθηκε εντολή (π.χ. set/cmd) σε IoT συσκευή σε ώρα που ΔΕΝ συνηθίζεται για αυτή τη συσκευή.",
     "A command (e.g. set/cmd) was sent to an IoT device at an hour that is NOT usual for it.",
     "Νέα αυτοματοποίηση, αλλαγή ώρας (θερινή), διακοπές.", "A new automation, daylight-saving change, holidays."),
    ("Καναρίνι ESP32", "sensor",
     "Κάποιος άγγιξε το «καναρίνι» ESP32: ψεύτικη υπηρεσία που κανείς δεν έχει λόγο να επισκεφτεί.",
     "Someone touched the ESP32 “canary”: a fake service nobody has a reason to visit.",
     "Δικές σου σαρώσεις, εφαρμογές που ψάχνουν συσκευές.", "Your own scans, apps discovering devices."),
    ("OTA", "sensor",
     "Αίτημα ενημέρωσης firmware (OTA) σε συσκευή ESP32· «απορρίφθηκε» = υπογραφή/κωδικός λάθος, άρα κάποιος δοκίμασε μη εξουσιοδοτημένο firmware.",
     "A firmware update (OTA) request to an ESP32 device; “rejected” = wrong signature/password, so someone tried unauthorised firmware.",
     "Δική σου ενημέρωση από ESPHome/Arduino με λάθος κλειδί.", "Your own update from ESPHome/Arduino with the wrong key."),
    ("Άγνωστο access point", "sensor", "Ο αισθητήρας Wi‑Fi είδε access point που δεν ανήκει στη λίστα των γνωστών.",
     "The Wi‑Fi sensor saw an access point that is not on the known list.",
     "Νέο router γείτονα, hotspot κινητού.", "A neighbour's new router, a phone hotspot."),
    ("Θύρα δικτύου", "snmp",
     "Το switch/router σου ανέφερε μέσω SNMP ότι μια θύρα έπεσε (ή επανήλθε).", "Your switch/router reported via SNMP that a port went down (or came back).",
     "Κάποιος έβγαλε καλώδιο, συσκευή σε sleep/επανεκκίνηση.", "Someone unplugged a cable, a device asleep/rebooting."),
    ("Σφάλματα σε θύρα", "snmp", "Οι μετρητές σφαλμάτων (CRC/errors/discards) μιας θύρας ανεβαίνουν μέσω SNMP.",
     "A port's error counters (CRC/errors/discards) are rising via SNMP.",
     "Χαλασμένο/μακρύ καλώδιο, duplex mismatch, κακό patch panel.", "A bad/too-long cable, duplex mismatch, a bad patch panel."),
    ("Θύρα κοντά στο όριο", "snmp", "Η κίνηση μιας θύρας πλησιάζει τη μέγιστη ταχύτητά της (SNMP).",
     "A port's traffic is approaching its maximum speed (SNMP).", "Backup, μεγάλο download, streaming.", "Backups, a big download, streaming."),
    ("SNMP χωρίς απάντηση", "snmp", "Συσκευή που παρακολουθείς με SNMP σταμάτησε να απαντά.", "A device you monitor with SNMP stopped answering.",
     "Επανεκκίνηση, αλλαγή community/κωδικού SNMP, firewall.", "A reboot, a changed SNMP community/password, a firewall."),
    ("Συσκευή επανεκκινήθηκε", "snmp", "Ο χρόνος λειτουργίας (uptime) της συσκευής μηδενίστηκε — επανεκκινήθηκε.",
     "The device's uptime reset — it rebooted.", "Ενημέρωση firmware, διακοπή ρεύματος.", "A firmware update, a power cut."),
    ("WireGuard peer", "vpn", "Peer του WireGuard σταμάτησε (ή ξανάρχισε) να κάνει handshake.", "A WireGuard peer stopped (or resumed) handshaking.",
     "Κινητό εκτός δικτύου, laptop κλειστό.", "A phone out of coverage, a closed laptop."),
    ("Tailscale συσκευή", "vpn", "Συσκευή του Tailscale έγινε offline (ή επανήλθε).", "A Tailscale device went offline (or came back).",
     "Κλειστή συσκευή, χωρίς internet.", "A device turned off, no internet."),
    ("Σύγκρουση IP", "ipam", "Δύο διαφορετικές MAC χρησιμοποιούν την ίδια IP.", "Two different MACs are using the same IP.",
     "Στατική IP μέσα στο εύρος του DHCP, VM, συσκευή με δύο κάρτες.", "A static IP inside the DHCP range, a VM, a device with two cards."),
    ("Απώλειες πακέτων", "latency", "Οι μετρήσεις latency βρήκαν απώλειες πακέτων προς τον στόχο.", "Latency measurements found packet loss toward the target.",
     "Κακό Wi‑Fi, συμφόρηση, πρόβλημα του παρόχου.", "Bad Wi‑Fi, congestion, an ISP problem."),
    ("Υπηρεσία", "health",
     "Ο έλεγχος υγείας (homelab) απέτυχε 2 συνεχόμενες φορές να φτάσει την υπηρεσία (ή ξαναπέτυχε).",
     "The (homelab) health check failed to reach the service 2 times in a row (or succeeded again).",
     "Επανεκκίνηση, ενημέρωση, ο server σε sleep.", "A reboot, an update, the server asleep."),
]

GENERIC = ("Ο ανιχνευτής βρήκε συμπεριφορά που ταιριάζει με το μοτίβο αυτού του τύπου ειδοποίησης.",
           "The detector saw behaviour matching this alert type's pattern.",
           "Δες τη συσκευή και αν το έκανες εσύ.", "Check the device and whether you did it yourself.")


def _valid_ip(s):
    try:
        ipaddress.ip_address(str(s))
        return True
    except ValueError:
        return False


class AlertHygiene:
    def __init__(self, state, path=None, clock=time.time, on_save=None):
        self.state, self.path, self.clock, self.on_save = state, path, clock, on_save
        self.lock = threading.Lock()
        self.mutes = []
        self.seq = 0
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    d = json.load(f)
                self.mutes = [m for m in d.get("mutes", []) if isinstance(m, dict)][:MAX_MUTES]
                self.seq = max([int(m.get("id") or 0) for m in self.mutes] or [0])
            except (OSError, ValueError):
                pass

    # ── αποθήκευση ──
    def _save(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"mutes": self.mutes}, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)
        if self.on_save:
            self.on_save(self.path)

    def _live(self, now):
        live = [m for m in self.mutes if not m.get("until") or m["until"] > now]
        if len(live) != len(self.mutes):
            self.mutes = live
            try:
                self._save()
            except OSError:
                pass
        return live

    # ── σίγαση ──
    def match(self, typ, actor, t=None):
        """→ αιτιολογία αν η ειδοποίηση είναι σιγασμένη, αλλιώς None. Καλείται από το NetState.alert."""
        if not self.mutes:
            return None
        now = self.clock() if t is None else t
        with self.lock:
            for m in self._live(now):
                if (m.get("type") in (None, typ)) and (m.get("actor") in (None, actor)):
                    return "🔕 " + ("Σίγαση" + (f": {m['note']}" if m.get("note") else ""))
        return None

    def mute(self, typ=None, actor=None, minutes=1440, note=None, now=None):
        typ = str(typ).strip()[:200] if typ else None
        actor = str(actor).strip()[:64] if actor else None
        if not typ and not actor:
            return {"error": "Διάλεξε τύπο ειδοποίησης ή συσκευή για σίγαση."}
        if actor and not _valid_ip(actor):
            return {"error": "Μη έγκυρη διεύθυνση IP."}
        try:
            minutes = int(minutes)
        except (TypeError, ValueError):
            return {"error": "Λάθος διάρκεια."}
        if not 0 <= minutes <= 525600:
            return {"error": "Διάρκεια: 0 (για πάντα) έως 525600 λεπτά (1 χρόνος)."}
        note = (str(note).strip()[:200] or None) if note else None
        now = self.clock() if now is None else now
        with self.lock:
            live = self._live(now)
            old = next((m for m in live if m.get("type") == typ and m.get("actor") == actor), None)
            if old:  # ίδια σίγαση → απλώς ανανέωση
                old.update(until=now + minutes * 60 if minutes else None, note=note or old.get("note"))
                m = old
            else:
                if len(live) >= MAX_MUTES:
                    return {"error": f"Υπάρχουν ήδη {MAX_MUTES} σιγάσεις — άρε κάποιες πρώτα."}
                self.seq += 1
                m = {"id": self.seq, "type": typ, "actor": actor, "until": now + minutes * 60 if minutes else None,
                     "note": note, "created": now}
                self.mutes.append(m)
            self._save()
        return {"ok": True, "mute": dict(m)}

    def unmute(self, mid):
        with self.lock:
            n = len(self.mutes)
            self.mutes = [m for m in self.mutes if m.get("id") != mid]
            if len(self.mutes) == n:
                return {"error": "Η σίγαση δεν βρέθηκε."}
            self._save()
        return {"ok": True}

    # ── θόρυβος ──
    def _hist(self, sql, args):
        h = getattr(self.state, "history", None)
        if not h:
            return []
        with h.lock:
            return h.db.execute(sql, args).fetchall()

    def noise(self, hours=24):
        hours = max(1, min(24 * 30, int(hours or 24)))
        now = self.clock()
        since = now - hours * 3600
        rows = self._hist("SELECT type, COUNT(*), COUNT(DISTINCT actor), MAX(t) FROM alerts WHERE t>=? "
                          "GROUP BY type ORDER BY COUNT(*) DESC LIMIT 15", (since,))
        total = (self._hist("SELECT COUNT(*) FROM alerts WHERE t>=?", (since,)) or [(0,)])[0][0]
        out = []
        with self.lock:
            live = self._live(now)
        for typ, n, actors, last in rows:
            top = self._hist("SELECT actor, COUNT(*) FROM alerts WHERE t>=? AND type=? GROUP BY actor "
                             "ORDER BY COUNT(*) DESC LIMIT 3", (since, typ))
            det = detector_for(typ)
            out.append({"type": typ, "count": n, "actors": actors, "last": last,
                        "share": round(100 * n / total, 1) if total else 0,
                        "top": [{"actor": a, "count": c, "name": self._name(a)} for a, c in top],
                        "detector": det, "muted": any(m.get("type") == typ and not m.get("actor") for m in live)})
        return {"hours": hours, "total": total, "types": out}

    def view(self):
        now = self.clock()
        with self.lock:
            live = [dict(m) for m in self._live(now)]
        for m in live:
            m["name"] = self._name(m["actor"]) if m.get("actor") else ""
        live.sort(key=lambda m: -(m.get("created") or 0))
        return {"mutes": live, "noise": self.noise(24)}

    # ── γιατί χτύπησε ──
    def _name(self, ip):
        st = self.state
        h = (getattr(st, "hosts", {}) or {}).get(ip)
        if not isinstance(h, dict):
            return ""
        return (h.get("alias") or next(iter(sorted(h.get("names") or [])), "") or h.get("rdns") or h.get("vendor") or "")

    def _device(self, ip):
        st = self.state
        h = (getattr(st, "hosts", {}) or {}).get(ip)
        if not isinstance(h, dict):
            return {"ip": ip, "known": False}
        d = {"ip": ip, "known": True, "kind": h.get("kind"), "name": self._name(ip), "mac": h.get("mac") or "",
             "vendor": h.get("vendor") or "", "dtype": h.get("dtype") or "", "icon": h.get("dicon") or "",
             "me": bool(h.get("me")) or ip in (getattr(st, "me", None) or ()), "gw": ip == getattr(st, "gateway", None),
             "first": h.get("first"), "last": h.get("last")}
        mac = d["mac"]
        if mac and len(mac) >= 2:
            try:
                d["random_mac"] = bool(int(mac[1], 16) & 2)  # «locally administered» bit → τυχαία MAC (κινητά)
            except ValueError:
                pass
        g = h.get("geo") or {}
        if g:
            d["geo"] = {"country": g.get("country"), "cc": g.get("countryCode"), "isp": g.get("isp"), "as": g.get("as")}
        intel = getattr(st, "intel", None)
        if d["kind"] == "public" and intel:
            try:
                d["intel"] = intel.lookup(ip) or []
            except Exception:  # noqa: BLE001
                d["intel"] = []
        return d

    def why(self, alert_id):
        st = self.state
        with getattr(st, "lock", threading.RLock()):
            a = next((dict(x) for x in getattr(st, "alerts", []) if x.get("id") == alert_id), None)
        if not a:
            return {"error": "Η ειδοποίηση δεν είναι πια στη μνήμη (κρατιούνται οι πιο πρόσφατες)."}
        typ, actor, t = a["type"], a["actor"], a["t"]
        det = detector_for(typ)
        if typ.startswith("Διαρροή διαχωρισμού"):
            det = "segmentation"
        px = next((x for x in PREFIX_INFO if typ.startswith(x[0])), None)
        if px:
            det, info = det or px[1], px[2:]
        else:
            info = INFO.get(det) or GENERIC
        cfg = getattr(st, "cfg", {}) or {}
        th = cfg.get("thresholds", {}) or {}
        out = {"id": alert_id, "type": typ, "sev": a["sev"], "detector": det,
               "how": {"el": info[0], "en": info[1]}, "fp": {"el": info[2], "en": info[3]},
               "thresholds": {k: th[k] for k in TH_KEYS.get(det, []) if k in th},
               "cooldown": th.get("alert_cooldown", 60), "detail": a.get("detail"), "mitre": a.get("mitre") or mitre_for(typ),
               "detector_on": (cfg.get("detectors", {}) or {}).get(det, True) if det else True}
        # δικός σου κανόνας → ο ορισμός του
        if typ.startswith("Κανόνας: ") and getattr(st, "rules", None):
            title = typ[len("Κανόνας: "):]
            r = next((r for r in st.rules.rules if r.title == title), None)
            if r:
                out["rule"] = {"id": r.id, "title": r.title, "description": r.description, "match": r.raw.get("match"),
                               "threshold": r.threshold, "source": getattr(r, "source", "")}
        # πόσο συχνά: ίδιος τύπος από ίδια συσκευή, και ο τύπος γενικά
        day, week = t - 86400, t - 7 * 86400
        same = self._hist("SELECT COUNT(*), MIN(t) FROM alerts WHERE type=? AND actor=? AND t>=?", (typ, actor, week))
        same24 = self._hist("SELECT COUNT(*) FROM alerts WHERE type=? AND actor=? AND t>=?", (typ, actor, day))
        first = self._hist("SELECT MIN(t) FROM alerts WHERE type=? AND actor=?", (typ, actor))
        typ7 = self._hist("SELECT COUNT(*), COUNT(DISTINCT actor) FROM alerts WHERE type=? AND t>=?", (typ, week))
        n7 = same[0][0] if same else 0
        out["freq"] = {"same_24h": same24[0][0] if same24 else 0, "same_7d": n7,
                       "first_ever": first[0][0] if first else None,
                       "type_7d": typ7[0][0] if typ7 else 0, "type_actors_7d": typ7[0][1] if typ7 else 0}
        out["pattern"] = "first" if n7 <= 1 else "repeat" if n7 < 20 else "constant"
        # συσκευές
        out["actor"] = self._device(actor)
        tgt = str(a.get("target") or "")
        out["target"] = self._device(tgt) if _valid_ip(tgt) else {"label": tgt}
        # τι άλλο έγινε γύρω στην ίδια ώρα από την ίδια συσκευή (±15′)
        with getattr(st, "lock", threading.RLock()):
            rel = [{"id": x["id"], "t": x["t"], "type": x["type"], "sev": x["sev"]} for x in getattr(st, "alerts", [])
                   if x.get("id") != alert_id and (x.get("actor") == actor or x.get("target") == actor)
                   and abs(x["t"] - t) <= 900][:10]
        out["related"] = rel
        # κατάσταση: σιγασμένο / αθώο / συντήρηση
        out["benign"] = a.get("benign")
        out["maint"] = a.get("maint")
        out["selftest"] = a.get("selftest")
        now = self.clock()
        with self.lock:
            out["mutes"] = [dict(m) for m in self._live(now)
                            if m.get("type") in (None, typ) and m.get("actor") in (None, actor)]
        return out
