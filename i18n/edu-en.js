// English texts for edu.js (alert explanations, verdicts, ports, glossary, tips).
// Same keys as edu.js — see the end of edu.js for how they are applied.
window.NW_EDU_EN = {
  EDU: {
    'Port scan': {
      t: "Port scan", lvl: "Reconnaissance",
      what: "Someone “knocks” on many ports of a device, one by one, to find out which services are open (e.g. SSH, file sharing, cameras).",
      how: "It sends a TCP SYN packet (“I want to connect”) to every port. If the device answers SYN‑ACK the port is open; if it answers RST it is closed. Tools: nmap, masscan.",
      risk: "It is usually the first step before a real attack: the attacker builds a list of what they can hit.",
      todo: ["In the Details tab, see which ports were scanned", "Turn off services you don't need (Settings → General → Sharing on the Mac)", "Turn on the macOS Firewall with “Stealth mode”", "If the scanner is inside your LAN, find out which device it is from its MAC"]
    },
    'Stealth scan': {
      t: "Stealth scan (NULL / FIN / XMAS)", lvl: "Reconnaissance",
      what: "A port scan using “odd” TCP packets that a normal program would never send.",
      how: "NULL = a packet with no flags at all, FIN = only “close”, XMAS = FIN+PSH+URG (“lit up like a Christmas tree”). Some firewalls let these through, so the attacker stays hidden.",
      risk: "It shows that someone is deliberately using a hacking tool (e.g. nmap -sX). It is never an accident.",
      todo: ["Treat the IP as hostile", "Check it on AbuseIPDB / GreyNoise", "Block it on the router if it keeps going"]
    },
    'Brute force': {
      t: "Brute force attack", lvl: "Attack",
      what: "Someone tries thousands of usernames and passwords on a login service (SSH, RDP, FTP, VNC, SMB) until they find the right one.",
      how: "It opens a connection, tries one password, closes, and repeats again and again — that is why you see many connections to the same port in a short time.",
      risk: "If it finds the password, it gets full control of the device.",
      todo: ["Turn the service off if you don't need it (e.g. “Remote Login” on the Mac)", "Use long, unique passwords or SSH keys", "Don't set up port forwarding on the router for SSH/RDP", "Install fail2ban or something similar on servers"]
    },
    'SYN flood': {
      t: "SYN flood (DoS)", lvl: "Attack",
      what: "A denial-of-service attack: bombarding a device with connection requests that are never completed.",
      how: "Every SYN makes the device keep memory for a “half-open” connection. Thousands of them fill the memory and real users can't be served. The sending IPs are often fake (spoofed).",
      risk: "Slow or dead Internet / service. It doesn't steal data, but it “knocks you down”.",
      todo: ["Restart the router if it gets stuck", "If the attack from the Internet keeps going: contact your provider (ISP)", "The IPs may be forged — don't “chase” them"]
    },
    'ICMP flood': {
      t: "Ping flood (ICMP flood)", lvl: "Attack",
      what: "Bombarding with pings to fill up the line or overload the device.",
      how: "Thousands of ICMP Echo Requests per second.", risk: "Slow network.",
      todo: ["Turn on “Stealth mode” in the Mac firewall so it doesn't answer pings", "If it comes from the LAN, find the device"]
    },
    'Network sweep': {
      t: "Network sweep", lvl: "Reconnaissance",
      what: "Someone looks for the devices on the network by asking about every IP address in turn.",
      how: "With ping or with ARP “who has 192.168.1.x?” for all addresses. Tools: nmap -sn, netdiscover, arp-scan.",
      risk: "If it happens inside the LAN, a device on your network (or someone connected to your Wi‑Fi) is exploring. Some apps (Fing, some printers/smart TVs) do it legitimately.",
      todo: ["Find out which device it is from the MAC (📟 Devices tab)", "If you don't recognise it: change the Wi‑Fi password", "Use a guest network for devices that aren't yours"]
    },
    'ARP spoofing': {
      t: "ARP spoofing — Man‑in‑the‑Middle", lvl: "Serious attack",
      what: "A device on the network lies that it is the router, so that all your traffic goes through it first.",
      how: "On the local network, devices find each other with ARP (“which MAC has IP 192.168.1.1?”). The attacker keeps sending fake “it's me!” replies and becomes the “middleman”. Tools: bettercap, arpspoof, Ettercap.",
      risk: "HIGH. It can see which pages you visit, steal unencrypted data, send you to fake pages or change DNS answers.",
      todo: ["Disconnect from the Wi‑Fi right away if you don't trust the network", "Don't log in to your bank or enter passwords until it is solved", "Use a VPN", "Find the device from its MAC and kick it off the router", "Change the Wi‑Fi password"]
    },
    'ARP flood': {
      t: "ARP flood", lvl: "Attack",
      what: "Far too many ARP replies from one device.", how: "It often comes with ARP spoofing (the attacker keeps “repeating” the lie) or with attacks on a switch.",
      risk: "Possible Man‑in‑the‑Middle.", todo: ["Check whether there is also an ARP spoofing alert", "Find the MAC"]
    },
    'Rogue DHCP': {
      t: "Rogue DHCP server", lvl: "Serious attack",
      what: "A second device hands out IP addresses on the network, besides the router.",
      how: "When a device connects it asks “give me an IP”. The rogue server answers faster and hands out its own gateway and DNS — so it controls all the traffic of new devices.",
      risk: "HIGH: Man‑in‑the‑Middle and fake DNS (phishing).",
      todo: ["Find the device and disconnect it", "If you have a second router/mesh in the wrong mode, this may be a false positive", "Turn on DHCP snooping if your equipment supports it"]
    },
    'Ύποπτη απάντηση DNS': {
      t: "Suspicious DNS answer (DNS spoofing)", lvl: "Attack",
      what: "A DNS answer arrived from a server your computer didn't ask.",
      how: "DNS translates names (google.com) into IPs. If someone sends a fake answer first, it sends you to their own IP — e.g. to a fake bank page.",
      risk: "Phishing / redirection.",
      todo: ["Watch for certificate warnings in the browser", "Use encrypted DNS (DNS over HTTPS, e.g. 1.1.1.1)", "It may be a false positive if you recently changed DNS server"]
    },
    'Εισερχόμενη σύνδεση': {
      t: "Incoming connection from the Internet", lvl: "Information",
      what: "Someone from the Internet tried to start a connection to your device.",
      how: "Normally the router (NAT) blocks such connections. If they get through, there is port forwarding, UPnP or a public IP.",
      risk: "Low on its own — but it shows that the device is visible from the Internet.",
      todo: ["Check the router for port forwarding / UPnP", "Look up your IP on Shodan to see what is visible"]
    },
    'Ύποπτη εξερχόμενη θύρα': {
      t: "Suspicious outgoing connection", lvl: "Information",
      what: "Your computer connected to a port that is often used by backdoors, botnets or Tor.",
      how: "E.g. 4444 (Metasploit), 6667 (IRC botnets), 31337 (Back Orifice).",
      risk: "It may be harmless, but it could also be malware “phoning home”.",
      todo: ["Find which program is doing it: in Terminal run “lsof -i :PORT”", "Scan the computer for malware"]
    },
    'Beaconing': {
      t: "Beaconing — malware “phoning home” (C2)", lvl: "Serious sign of infection",
      what: "A device connects to the same server again and again, at almost exactly the same intervals (e.g. every 60 seconds).",
      how: "Malware periodically asks its control server (Command & Control) “do you have orders for me?”. People don't browse by the clock — programs do. We measure the intervals and if the variation is small (<15%) we raise an alert.",
      risk: "If the server is malicious, the computer is being controlled remotely. Careful: legitimate programs (updaters, messengers) also poll — check the IP.",
      todo: ["Look up the IP on AbuseIPDB / VirusTotal (Details → OSINT)", "Find which program: “lsof -i -P | grep IP” in Terminal", "If it is legitimate, add the domain to the allowlist in config.yaml", "If not: disconnect from the network and scan for malware"]
    },
    'DNS tunneling': {
      t: "DNS tunneling — data hidden in DNS", lvl: "Serious attack",
      what: "Data (files, passwords, commands) is encoded inside long, random subdomain names, e.g. 4a6f686e2053.attacker.com.",
      how: "Almost every network lets DNS through. The attacker controls the domain and reads the queries on their DNS server. Tools: iodine, dnscat2. We detect many unique, high-entropy subdomains going to the same domain.",
      risk: "HIGH: data theft or a hidden control channel that bypasses the firewall.",
      todo: ["Isolate the device", "Block the domain on the router / DNS (e.g. Pi-hole)", "Check the device for malware"]
    },
    'DNS amplification': {
      t: "DNS amplification (amplified DDoS)", lvl: "Attack",
      what: "Someone sends small DNS queries to many resolvers with a forged source address — yours. The resolvers send huge answers (ANY, TXT, DNSSEC) to you.",
      how: "A 60-byte query → an answer of up to 4000 bytes: ×50 amplification. With thousands of open resolvers the victim's line fills up. NetWatch singles out answers that nobody asked for (the query ID doesn't match). If the DNS server on your network answers public IPs en masse, it is the “amplifier” itself (an open resolver).",
      risk: "No Internet for as long as the attack lasts. If you are the amplifier: your connection is used to attack others and your provider may cut it off.",
      todo: ["As the victim: contact your provider (ISP) — only they can filter before your line", "As the amplifier: close port 53 to the Internet (port forwarding on the router)", "Pi-hole/AdGuard/Unbound: answer only the LAN"]
    },
    'DNS flood': {
      t: "DNS flood", lvl: "Attack",
      what: "Thousands of DNS queries per second to one DNS server so that it can't keep up answering anyone.",
      how: "Every query costs the server memory and CPU. When it is overwhelmed, name resolution goes down: sites won't open even though the Internet works.",
      risk: "No site opens for the whole network. If the source is a device in your home, it may be infected (botnet) or broken.",
      todo: ["Find the source device and disconnect it", "Rate-limit queries on the Pi-hole/router", "If it comes from the Internet: your provider (ISP)"]
    },
    'NXDOMAIN flood': {
      t: "NXDOMAIN flood / random subdomain (“water torture”)", lvl: "Attack",
      what: "A flood of queries for names that don't exist, often random subdomains of one target (e.g. a8f3k.bank.com, q91zz.bank.com).",
      how: "A non-existent name doesn't get cached, so every query travels all the way to the target's DNS server and overloads it. Your own resolver is overwhelmed along the way.",
      risk: "Slow or dead DNS for the whole network; if one of your devices is doing it, it is taking part in an attack (botnet).",
      todo: ["Find which device is asking (Flows / DNS) and isolate it", "Rate-limit the resolver", "If the names look like DGA across many domains, also look at the DGA alert"]
    },
    'DNS rebinding': {
      t: "DNS rebinding", lvl: "Attack",
      what: "An Internet name pointed to a public IP and suddenly points to an IP on your own network (e.g. 192.168.1.1) or to 127.0.0.1.",
      how: "You open a malicious page. A little later the attacker's DNS changes the answer to a LAN IP. The browser thinks it is still talking to the same site, so the page can send requests to your router, camera or NAS.",
      risk: "Router settings changed, access to devices without a password, data stolen from services in your home.",
      todo: ["Close the tab/page that was open at that moment", "Turn on “DNS rebind protection” on the router or Pi-hole", "Put a password on everything with a web admin page on the LAN"]
    },
    'DNSSEC bypass': {
      t: "DNSSEC bypass on the Wi‑Fi", lvl: "Attack (MITM)",
      what: "The network's DNS claims it checks DNSSEC signatures, but it also accepts answers with a deliberately broken signature.",
      how: "Wi‑Fi Guard asks for a correctly signed domain and one with a broken signature. A normal resolver rejects the second one (SERVFAIL). If it accepts it while also saying “validated” (the AD flag), something in the middle is answering in its place.",
      risk: "Forged DNS answers (cache poisoning): you can be sent to fake pages without noticing.",
      todo: ["Disconnect from this Wi‑Fi or turn on a VPN", "Use encrypted DNS (DoH/DoT)", "If it merely “doesn't check” DNSSEC (no bypass), set 1.1.1.1 or 9.9.9.9 on the router"]
    },
    'DGA': {
      t: "DGA — Domain Generation Algorithm", lvl: "Serious sign of infection",
      what: "A device asks about lots of “random” domains (e.g. xk3j9qz7lp.com) that don't exist.",
      how: "Botnets (Conficker, Mirai variants, ransomware) generate thousands of random names every day; the attacker registers only one. The malware tries them all until it finds its server — so we see many NXDOMAIN (“doesn't exist”) answers.",
      risk: "HIGH: the device is most likely part of a botnet.",
      todo: ["Find which device it is (often IoT: camera, TV, router)", "Factory reset + update the firmware", "Change default passwords"]
    },
    'Νέα συσκευή': {
      t: "New device on the network", lvl: "Information",
      what: "A MAC address appeared that has never been seen on the network before (NetWatch remembers devices in its history).",
      how: "Every network card has a MAC. When a new one sends its first packet, it is recorded. Phones with “private Wi‑Fi address” may look like a new device when they change MAC.",
      risk: "Low — unless you don't know who it is. A neighbour with your password or a “planted” device (Raspberry Pi) is a classic first step of an attack.",
      todo: ["If you recognise it: add the MAC to the allowlist", "If not: change the Wi‑Fi password and check the device list on the router"]
    },
    'Σύνδεση σε κακόβουλη IP': {
      t: "Connection to a known malicious IP", lvl: "Serious sign",
      what: "One of your devices is talking to an IP that is on a public list of malicious addresses (threat intelligence).",
      how: "NetWatch downloads lists every day: Feodo Tracker (botnet control servers such as Emotet, QakBot), Spamhaus DROP (criminal networks), FireHOL level1. Every IP is checked immediately.",
      risk: "If the list is C2 (Feodo): infection is very likely. General blocklists also have false positives.",
      todo: ["Find the program: “lsof -i -P | grep IP”", "Scan for malware", "Block the IP on the router"]
    },
    'Κίνηση από κακόβουλη IP': {
      t: "Traffic from a known malicious IP", lvl: "Reconnaissance",
      what: "Packets arrived from an IP that is on a public blocklist — usually scanners or attackers.",
      how: "Known malicious servers scan the whole Internet looking for vulnerable devices.",
      risk: "Low to medium — it depends on whether they found an open service.",
      todo: ["Make sure you have no open ports on the router (port forwarding / UPnP)"]
    },
    'Κανόνας:': {
      t: "Rule alert", lvl: "Your own rule",
      what: "A rule from the rules/ folder (or one you wrote yourself in the 🧩 Rules tab) matched the traffic.",
      how: "Rules check every packet: IP, ports, protocol, TCP flags, domains — and optionally count how many times something happens within a time window.",
      risk: "It depends on the rule — see its description in the 🧩 Rules tab.",
      todo: ["See which rule fired and why (🧩 Rules tab)", "If it is a false positive, make the rule more specific or turn it off", "Export the rule to Sigma/Suricata to use it in a SIEM/IDS"]
    },
    'Κωδικός σε καθαρό κείμενο': {
      t: "Password sent unencrypted (cleartext)", lvl: "Password theft",
      what: "One of your devices sent a username and password over a protocol without encryption (FTP, Telnet, HTTP, POP3, IMAP, SMTP).",
      how: "It isn't an attack by itself — it is an opportunity. Anyone “listening” to the network (e.g. with ARP spoofing or on public Wi‑Fi) reads the password with Wireshark in seconds. MITRE technique: Network Sniffing.",
      risk: "The password may already have leaked. If you use it elsewhere too, those accounts are at risk as well.",
      todo: ["Change the password that was sent, especially if you use it elsewhere", "Use the secure version: SFTP/FTPS instead of FTP, SSH instead of Telnet, HTTPS instead of HTTP", "On the router/NAS/camera turn on HTTPS and turn off Telnet/FTP", "Turn on “HTTPS-Only mode” in the browser"]
    },
    'Evil twin Wi‑Fi': {
      t: "Evil twin (fake Wi‑Fi)", lvl: "Man‑in‑the‑Middle",
      what: "Two networks with the same name but different security. Someone probably set up a fake access point with the name of the café.",
      how: "The attacker (e.g. with a WiFi Pineapple) broadcasts the same SSID, often stronger. Devices connect automatically and all traffic goes through their computer: they see DNS, HTTP, and show fake login pages.",
      risk: "Password theft, fake sites, malware installed through fake “updates”.",
      todo: ["Disconnect and ask the staff which network is the right one", "“Forget” the network so it doesn't connect automatically", "Turn on a VPN or use your phone's hotspot"]
    },
    'DNS hijacking στο Wi‑Fi': {
      t: "DNS hijacking", lvl: "Man‑in‑the‑Middle",
      what: "The network's DNS answers with wrong addresses for names we know for sure (e.g. dns.google = 8.8.8.8).",
      how: "The router or an attacker sends fake DNS answers, so bank.gr takes you to their own server. HTTPS usually catches it (wrong certificate), but not on HTTP sites.",
      risk: "Phishing that looks like the real site, malware downloads.",
      todo: ["Don't continue if the browser shows a certificate warning", "Turn on a VPN or encrypted DNS (DoH) in the browser", "Disconnect from the network"]
    },
    'TLS interception στο Wi‑Fi': {
      t: "TLS interception (SSL stripping/MITM)", lvl: "Man‑in‑the‑Middle",
      what: "The certificates of well-known sites can't be verified: someone in the middle decrypts and re-encrypts the traffic.",
      how: "The attacker (or a company/hotel proxy) presents their own certificate. If you click “Continue”, they see everything you send, even inside HTTPS. It may also be a captive portal before you log in.",
      risk: "Full access to passwords, cookies and messages.",
      todo: ["Don't log in anywhere", "If it isn't the Wi‑Fi's own login page, disconnect right away", "Use mobile data"]
    },
    'Ανοιχτό Wi‑Fi': {
      t: "Open Wi‑Fi (no encryption)", lvl: "Vulnerability",
      what: "You are on a Wi‑Fi with no password or with WEP: traffic travels through the air unencrypted.",
      how: "Anyone nearby puts their card in monitor mode and records everything with Wireshark — without even connecting. With HTTPS they only see which sites you visit; with HTTP they see everything.",
      risk: "Eavesdropping, password theft from unencrypted protocols, session hijacking.",
      todo: ["Turn on a VPN", "Or use your phone's hotspot", "Turn on “HTTPS-Only mode” in the browser"]
    },
    'Παγίδα': {
      t: "Someone fell into the trap (honeypot)", lvl: "Reconnaissance / attack",
      what: "NetWatch opened fake services (SSH, Telnet, a router page…) that no legitimate person has any reason to touch. A device connected to them.",
      how: "Scanning tools (nmap, masscan) or malware (Mirai-type botnets) look for open ports and try known passwords. If you see what it sent (e.g. root / xc3511), it is an automatic login attempt.",
      risk: "A device inside your network is looking for targets, so it may be infected or belong to someone who shouldn't be there.",
      todo: ["Find which device it is (📟 Devices → MAC/vendor)", "If you don't recognise it: change the Wi‑Fi password", "If it is IoT (camera, smart plug): reset + new firmware + change the default password", "If it was you (testing), ignore it"]
    },
    'Deauth επίθεση': {
      t: "Deauthentication attack (Wi‑Fi)", lvl: "Wi‑Fi attack",
      what: "The ESP32 sensor saw many “disconnect” (deauth) packets in the air. These are Wi‑Fi management messages that, on WPA2, are not protected — so anyone can send them.",
      how: "The attacker (e.g. with an ESP8266 “deauther” or aircrack-ng) forges the router's MAC and tells everyone “disconnect”. Devices reconnect — and then: the attacker captures the WPA2 handshake to crack the password offline, or pushes them onto a fake network (evil twin).",
      risk: "Wi‑Fi outage (cameras and alarms go down), Wi‑Fi password theft if it is weak, being trapped on an evil twin.",
      todo: ["Turn on WPA3 or at least “Protected Management Frames (802.11w)” on the router", "Use a long Wi‑Fi password (16+ characters) so the handshake can't be cracked", "Put critical devices (cameras) on a cable if possible", "If you also see “Evil twin”: don't connect to anything with the same name"]
    },
    'Άγνωστο access point': {
      t: "Unknown access point with your network's name", lvl: "Suspicious",
      what: "The sensor sees your network's name (SSID) from an access point that isn't on the list of your own.",
      how: "It may be a repeater/mesh you added, or someone imitating your network with the same security to “pull in” your devices.",
      risk: "If it is fake, everything that connects goes through the attacker (man-in-the-middle).",
      todo: ["Check whether it is your own repeater/mesh → add the BSSID to the sensor's ALLOWED_BSSIDS", "Otherwise track it down by signal strength (RSSI): the closer to 0, the closer it is", "Change the Wi‑Fi password if you suspect they know it"]
    },
    'Άγνωστος MQTT client': {
      t: "Unknown client on the MQTT broker", lvl: "Suspicious",
      what: "A program/device with a name (client id) that has never been seen before connected to your broker.",
      how: "Someone who learned an MQTT password (e.g. “overheard” it on 1883 without TLS, or read it from an ESP's flash) connects with tools like MQTT Explorer/mqttx to read or send commands.",
      risk: "They read your measurements and may switch relays, locks, sprinklers — whatever the user's ACL allows.",
      todo: ["If it is a new device or app of yours, ignore it (NetWatch has now learned it)", "Otherwise change the password of the user that was used (mosquitto_passwd)", "ACL: each device writes only to its own topics", "Use TLS on 8883 so passwords can't be seen on the network"]
    },
    'Εντολή MQTT σε ασυνήθιστη ώρα': {
      t: "MQTT command at an unusual time", lvl: "Suspicious",
      what: "Someone sent a command (topic …/set, /cmd, relay…) in the middle of the night.",
      how: "It may be a scheduled automation (Home Assistant) — or someone who has a password and controls your devices while you sleep.",
      risk: "Physical consequences: a door opens, an alarm is switched off, a heater turns on.",
      todo: ["Check whether there is an automation at that time", "If not: change the MQTT passwords and see which client was connected (📨 MQTT tab)", "Allow command topics only for the Home Assistant user (ACL)"]
    },
    'Νέο MQTT topic': {
      t: "New MQTT topic", lvl: "Information",
      what: "After the learning period, a topic appeared that had never been used before.",
      how: "Usually: you added a device or changed firmware. It is suspicious when it looks like a command or when an unknown client sends it.",
      risk: "Low on its own; together with “Unknown MQTT client” it points to an intruder.",
      todo: ["If you added it, nothing needs to be done", "Otherwise look at the latest messages in the 📨 MQTT tab"]
    },
    'IoT συσκευή σιώπησε': {
      t: "IoT device stopped sending", lvl: "Availability",
      what: "A device that regularly sent to MQTT has been silent much longer than usual.",
      how: "The firmware hung, the power/Wi‑Fi went down — or someone is kicking it off the Wi‑Fi with deauth so it can't send (e.g. a door sensor).",
      risk: "A security sensor that goes silent doesn't warn you.",
      todo: ["Check that the device has power and Wi‑Fi", "If you have an ESP32 Sentinel, look for deauth at the same time (📡 Sensor)", "Add a watchdog/LWT (Last Will) in the firmware so the broker announces when it “died”"]
    },
    'Νέα χώρα για συσκευή': {
      t: "Device talked to a new country", lvl: "Anomaly",
      what: "A device at home contacted a server in a country it had never talked to before, after 24 hours during which NetWatch was learning its habits.",
      how: "Usually: a firmware/app update, a new CDN. It is suspicious when it is an IoT device (ESP32, camera) that normally only talks to the broker or to one cloud server.",
      risk: "An infected device “phoning” its control server or sending data out.",
      todo: ["Click the destination IP: who is it (WHOIS, AbuseIPDB)?", "If it is IoT and you didn't expect this: isolate it (🚫 Block) and re-flash the firmware", "IoT devices should reach the Internet only where needed (VLAN + ACL)"]
    },
    'Καναρίνι ESP32': {
      t: "Someone touched the ESP32 “canary”", lvl: "Attack",
      what: "An ESP32 pretending to be a forgotten camera/IoT device (Telnet, admin page) received a connection. No legitimate person has any reason to touch it.",
      how: "Scanners (nmap, masscan) and Mirai-type botnets look for IoT devices with open Telnet/web and try default passwords. The canary lures them in and alerts you.",
      risk: "The device that touched it is scanning your network: either someone is using it, or it is infected.",
      todo: ["Find which device the IP is (📟 Devices)", "If it wasn't your own test: block it (🚫 Block) and change the Wi‑Fi password", "If it is IoT: reset, new firmware, new passwords", "Keep IoT on its own VLAN (CCNA lesson)"]
    },
    'OTA απορρίφθηκε': {
      t: "An ESP32 refused a firmware update", lvl: "Attack",
      what: "The ESP32 downloaded an update manifest, but the signature, sha256 or version was not correct. It wrote nothing to flash and carries on with the old version.",
      how: "ESP32s accept only firmware signed with your own key (ECDSA P-256) and never an older version (anti-rollback). If someone takes over the OTA server or does a MITM, they can't produce a valid signature.",
      risk: "Either a mistake of your own (you signed with another key/wrong version) or someone is trying to push their own firmware onto your devices.",
      todo: ["See the reason (bad signature / sha256 / rollback)", "If you made no change: check the OTA server files (python3 tools/ota/ota_sign.py --verify)", "Keep the signing key offline — if it leaked, see “if the key is stolen” in tools/ota/README.md"]
    },
    'OTA ενημέρωση': {
      t: "An ESP32 was updated", lvl: "Information",
      what: "New signed firmware was written, started, connected to Wi‑Fi and MQTT and confirmed that it works.",
      how: "If the new version doesn't connect within 5′, the bootloader automatically goes back to the previous one (rollback).",
      risk: "None, if you did the update yourself.",
      todo: ["If you weren't expecting an update, check who has access to the OTA server"]
    },
    'Tor από συσκευή του δικτύου': {
      t: "A home device is talking Tor", lvl: "Suspicious",
      what: "A device on your network connected to a node of the Tor network (from the node list or on port 9001/9030).",
      how: "Tor hides who you are talking to. Tor Browser and privacy apps use it — but so do malware/botnets to hide their control server (C2).",
      risk: "On your own Mac with Tor Browser: none. On an ESP32, camera, smart plug or Pi that you didn't set up for Tor: infection is very likely.",
      todo: ["Find which device it is (📟 Devices)", "If it is IoT: isolate it (🚫 Block), reset and flash new firmware", "If it is a Pi/server: ps aux | grep tor — who started it?", "Block IoT from the Internet with VLAN/firewall (VLAN for IoT lesson)"]
    },
    'Κίνηση από κόμβο Tor': {
      t: "Incoming traffic from a Tor exit node", lvl: "Information",
      what: "Someone connected to you from a Tor exit node — meaning their real IP is hidden.",
      how: "Scanners, bots and attackers often use Tor so you can't see where they come from.",
      risk: "A problem only if the port they hit is open to the Internet.",
      todo: ["Check what you have open to the outside (🛡 Audit → Shodan)", "Don't port-forward IoT; prefer a VPN or an onion service (lesson in the Academy)"]
    },
    'Διαρροή DNS εκτός VPN': {
      t: "DNS leak", lvl: "Privacy",
      what: "The VPN is on, but DNS queries (“which IP does site X have?”) leave outside the tunnel, unencrypted.",
      how: "Usually the operating system keeps asking the DNS of the router/provider. The traffic to the sites is hidden, but their names are not.",
      risk: "The Wi‑Fi, your Internet provider or an attacker on the same network can see which sites you visit — exactly what you wanted to hide.",
      todo: ["Turn on “DNS leak protection” or “Use VPN DNS” in the VPN", "Use encrypted DNS (DoH) in the browser", "Run the check again in the 🕵 Anonymity tab"]
    },
    'Διαρροή IPv6 εκτός VPN': {
      t: "IPv6 leak", lvl: "Privacy",
      what: "The VPN carries only IPv4 traffic; IPv6 goes out directly with your real address.",
      how: "Many VPNs don't support IPv6. When a site also has IPv6, the Mac prefers it — and bypasses the tunnel.",
      risk: "The site sees your real connection (provider, region) despite the VPN.",
      todo: ["Turn on IPv6 or “block IPv6” in the VPN", "Or: Settings → Network → Wi‑Fi → Details → TCP/IP → IPv6: Link-local only"]
    },
  },

  VERDICT: {
    'Port scan': ['bad', "Someone is “knocking on doors” to find which services you have open — usually the first step before an attack. From the Internet it is an everyday thing (bots); from inside your home it is NOT normal."],
    'Stealth scan': ['bad', "A scan with “weird” packets made on purpose so that it isn't noticed. No normal program does this — it is a nmap-style tool."],
    'Brute force': ['bad', "Someone is trying many passwords, one after the other, to get in. Unless it is you who forgot the password, it is an attack."],
    'SYN flood': ['bad', "An attempt to “drown” a device with thousands of connection requests so that it stops working."],
    'ICMP flood': ['check', "Far too many pings. It may be a denial-of-service attack, or just a monitoring program that “asks” very often."],
    'Network sweep': ['check', "A device is asking “who is here?” across the whole network. Apps like Fing or printers do this normally — but so do attackers looking for targets."],
    'Deauth επίθεση': ['bad', "Someone is kicking devices off your Wi‑Fi — usually to steal the password or push them onto a fake network."],
    'Άγνωστο access point': ['check', "Your Wi‑Fi's name is being broadcast from an unknown spot. If it isn't your own repeater, look into it."],
    'Άγνωστος MQTT client': ['check', "A new program/device joined your MQTT broker. If you didn't add anything, someone has a password."],
    'Εντολή MQTT σε ασυνήθιστη ώρα': ['check', "A command to a device in the middle of the night. Harmless if it is your own automation."],
    'Νέο MQTT topic': ['ok', "A new “channel” on the broker — usually a new device or firmware."],
    'IoT συσκευή σιώπησε': ['check', "A device stopped sending. Usually power/Wi‑Fi — but it could also be deauth."],
    'IoT συσκευή ξαναμίλησε': ['ok', "The device is back."],
    'Νέα χώρα για συσκευή': ['check', "A device talked to a country it never talked to before. Often an update; on IoT, look into it."],
    'Υπηρεσία εκτός': ['check', "A homelab service stopped answering. Usually a restart/power issue; if it coincides with an attack, look at that too."],
    'Υπηρεσία επανήλθε': ['ok', "It answers again."],
    'Πιστοποιητικό λήγει': ['check', "When it expires, devices (e.g. the ESP32s) will refuse to connect. Renew it in time."],
    'OTA απορρίφθηκε': ['bad', "An ESP32 refused firmware without a valid signature — the protection worked. Find out whether it was your mistake or someone tampered with the OTA server."],
    'OTA ενημέρωση': ['ok', "A firmware update that you did yourself, and it works."],
    'Καναρίνι ESP32': ['bad', "Someone touched the fake trap device. There are no false alarms here: they are either scanning or trying passwords (unless it was you)."],
    'Tor από συσκευή του δικτύου': ['check', "A device is talking to Tor. On your Mac with Tor Browser it is harmless; on an IoT device it is very suspicious."],
    'Κίνηση από κόμβο Tor': ['ok', "Someone “hidden” behind Tor knocked on your door. Common on the Internet; a problem only if the door is open."],
    'Παγίδα': ['bad', "No legitimate person touches a fake service. This device is scanning or trying passwords. Exception: if you ran nmap/a test yourself."],
    'ARP spoofing': ['bad', "Someone is pretending to be the router so your traffic goes through them (man‑in‑the‑middle). One of the most serious — especially on public Wi‑Fi."],
    'ARP flood': ['check', "Far too many ARP messages. It often comes with ARP spoofing, but it can also be a device that “hung”."],
    'Rogue DHCP': ['bad', "A second device is handing out addresses on the network. It can send everyone to a fake router/DNS. Exception: if you have a mesh or a second router."],
    'Ύποπτη απάντηση DNS': ['check', "An answer to “which IP does a site have” came from the wrong place. It may be an attempt to send you to a fake site."],
    'Εισερχόμενη σύνδεση': ['ok', "Someone from the Internet “knocked” on your door. It happens all the time (automatic bots scan the whole Internet). A problem only if the door is open."],
    'Ύποπτη εξερχόμενη θύρα': ['check', "Your computer connected to a port that Tor, backdoors or botnets often use. If you run Tor, Tor Browser or a well-known program, it is harmless; if not, find which program did it."],
    'Beaconing': ['check', "A device “phones” a server at very regular intervals, like a clock. That is how botnets communicate — but so do many harmless programs (updates, smart devices)."],
    'DNS tunneling': ['bad', "Data is hidden inside DNS names to sneak out of the network. Normal programs almost never do this."],
    'DNS amplification': ['bad', "DNS answers nobody asked for are “flooding” a device — or your DNS server is being used as an amplifier to attack others."],
    'DNS flood': ['bad', "Thousands of DNS queries to make the DNS server stop working. If the source is your own device, something is wrong with it."],
    'NXDOMAIN flood': ['bad', "A flood of queries for names that don't exist — to overload the resolver or a target's DNS server."],
    'DNS rebinding': ['bad', "A site suddenly changed its address to an IP in your home — a way for a page to “talk” to your router or devices."],
    'DNSSEC bypass': ['bad', "The Wi‑Fi accepts forged DNS answers while claiming it checks them. Don't log in on this network without a VPN."],
    'DGA': ['bad', "A device is looking up many “random” names (e.g. k3jd9fh2lq.com) that don't exist — a classic sign of malware looking for its server."],
    'Νέα συσκευή': ['ok', "A device connected to the network for the first time. Most of the time it is a phone, a tablet or something of yours/a guest's. Ask: do I recognise it? If yes, all good."],
    'Σύνδεση σε κακόβουλη IP': ['bad', "A device of yours talked to an IP that is on a public list of botnets/malicious servers. There may be an infection."],
    'Κίνηση από κακόβουλη IP': ['check', "A known malicious IP “knocked” on your network. Usually it is an Internet scanner; serious only if one of your devices answered it."],
    'Κανόνας:': ['check', "A rule that you wrote (or one of the ready-made ones) fired. See what it checks in 🧩 Rules."],
    'Κωδικός σε καθαρό κείμενο': ['bad', "A password travelled without encryption — anyone “listening” to the network can read it. It isn't an attack, it is an opportunity for one."],
    'Evil twin Wi‑Fi': ['bad', "There is a second Wi‑Fi with the same name — it may be a fake meant to “catch” your traffic."],
    'DNS hijacking στο Wi‑Fi': ['bad', "The Wi‑Fi gives wrong addresses for well-known sites. It may send you to fake pages."],
    'TLS interception στο Wi‑Fi': ['bad', "Someone “in the middle” is decrypting HTTPS traffic. Don't log in anywhere on this network."],
    'Ανοιχτό Wi‑Fi': ['check', "The Wi‑Fi has no password — anyone nearby sees whatever isn't encrypted. With HTTPS and a VPN you are fine."],
    'Διαρροή DNS εκτός VPN': ['check', "The VPN hides the traffic, but the names of the sites you visit are visible. It isn't an attack — it is a gap in your privacy."],
    'Διαρροή IPv6 εκτός VPN': ['check', "Part of the traffic (IPv6) bypasses the VPN and shows your real connection."],
  },

  TACTIC_INFO: {
    'Reconnaissance': "gathering information about the target before the attack (scans from the Internet).",
    'Initial Access': "the first way someone gets in (e.g. an unknown device on the Wi‑Fi).",
    'Discovery': "once inside, they map the network: which devices and services exist.",
    'Credential Access': "password theft: brute force, Man‑in‑the‑Middle, “listening” to the network.",
    'Command and Control': "the malware's communication with the attacker's server (C2).",
    'Impact': "the damage: service disruption (DoS), destruction or encryption of data.",
    'Lateral Movement': "moving from one device to another inside the network (SMB, RDP, SSH).",
    'Exfiltration': "stealing data out of the network.",
  },

  PORT_INFO: {
    20: ['FTP-data', "FTP file transfer", "File theft"],
    21: ['FTP', "Old file transfer protocol, passwords without encryption", "Tries passwords or anonymous access to download/upload files"],
    22: ['SSH', "Remote terminal login", "Wants to get in remotely with a password — full control of the machine"],
    23: ['Telnet', "Ancient, unencrypted remote terminal", "Target of botnets (Mirai) — routers/cameras with default passwords"],
    25: ['SMTP', "Sending email", "Looks for an open relay to send spam"],
    53: ['DNS', "Translating names into IPs", "Amplification attacks or DNS spoofing"],
    67: ['DHCP', "Hands out IP addresses", "Rogue DHCP server"],
    80: ['HTTP', "Web pages without encryption", "Looks for vulnerabilities in web servers, router admin pages, cameras"],
    110: ['POP3', "Receiving email", "Brute force on email passwords"],
    123: ['NTP', "Time synchronisation", "DDoS amplification attacks"],
    135: ['MS-RPC', "Windows services", "Windows vulnerabilities"],
    137: ['NetBIOS', "Windows computer names", "Gathering information about the network"],
    139: ['NetBIOS', "Windows file sharing (old)", "Access to shared folders"],
    143: ['IMAP', "Email", "Brute force on email passwords"],
    161: ['SNMP', "Network device management", "Default community “public” → reads router settings"],
    443: ['HTTPS', "Encrypted web pages", "Looks for vulnerabilities in web apps/VPNs"],
    445: ['SMB', "Windows/Mac file sharing", "Classic ransomware target (WannaCry/EternalBlue)"],
    548: ['AFP', "Apple file sharing", "Access to files"],
    554: ['RTSP', "Video streaming from IP cameras", "Wants to see your cameras"],
    631: ['IPP', "Printers", "CUPS / printer vulnerabilities"],
    1433: ['MSSQL', "Microsoft database", "Data theft"],
    1883: ['MQTT', "IoT messages (smart home)", "Control of IoT devices"],
    1900: ['SSDP/UPnP', "Device discovery (TV, Chromecast)", "DDoS amplification, opening ports via UPnP"],
    3306: ['MySQL', "Database", "Data theft"],
    3389: ['RDP', "Windows remote desktop", "No. 1 way in for ransomware"],
    5000: ['UPnP/Dev', "AirPlay / dev servers", "Access to development services"],
    5353: ['mDNS', "Bonjour — devices announce themselves", "Gathering device names"],
    5432: ['Postgres', "Database", "Data theft"],
    5900: ['VNC', "Remote screen (and Mac Screen Sharing)", "Wants to see/control your screen"],
    6379: ['Redis', "Database", "Often has no password → code execution"],
    7547: ['TR-069', "Remote router management by the provider", "Botnets that take over routers"],
    8080: ['HTTP-alt', "Alternative web server / proxy", "Admin panels, proxies"],
    8443: ['HTTPS-alt', "Alternative HTTPS", "Admin panels"],
    9100: ['JetDirect', "Direct printing", "Printing junk, printer vulnerabilities"],
    27017: ['MongoDB', "Database", "Often open with no password"],
    'ICMP ping': ['ICMP', "Ping — “are you there?”", "Checks whether the device is alive"],
    'ARP who-has': ['ARP', "The question “who has this IP?”", "Mapping the devices on the LAN"],
  },

  PROTO_INFO: {
    HTTPS: "Encrypted web traffic (TLS). The content isn't visible, only which server you go to (from the SNI).",
    HTTP: "Web pages without encryption — anyone in the middle sees everything.",
    QUIC: "Google's new, fast protocol over UDP 443 (HTTP/3). YouTube, Google and Instagram use it.",
    DNS: "The Internet's “phone book”: it turns names (google.com) into IP addresses.",
    ARP: "Only inside the LAN: it finds which MAC (network card) has an IP. It has no security at all — that's why ARP spoofing happens.",
    ICMP: "Control messages: ping, “destination unreachable”, traceroute.",
    ICMPv6: "ICMP for IPv6 — it also includes neighbour discovery (instead of ARP).",
    mDNS: "Bonjour/AirPlay: devices announce “I'm the living room TV”.",
    SSDP: "UPnP: smart TVs, Chromecasts and consoles looking for each other.",
    DHCP: "The router gives an IP to every device that connects.",
    NTP: "Clock synchronisation.",
    NetBIOS: "Old Windows naming system.", LLMNR: "Names on the LAN (Windows) — a target of Responder attacks.",
    SSH: "Encrypted remote login.", TCP: "Reliable connection with a “handshake” (SYN → SYN‑ACK → ACK).", UDP: "Fast packets without a connection (games, video, DNS).",
  },

  FLAGS: {
    'S': "starts a connection (SYN — “hi, I want to talk”)", 'SA': "accepts the connection (SYN‑ACK — “OK!”)", 'A': "confirms / carries data (ACK)",
    'PA': "sends data (PUSH‑ACK)", 'FA': "politely closes the connection (FIN)", 'F': "FIN only — suspicious (FIN scan)", 'R': "abruptly cuts the connection (RESET)",
    'RA': "rejects — the port is closed (RST)", 'FPU': "XMAS scan — a packet no normal program ever sends", '': "NULL — no flags, suspicious (NULL scan)",
  },

  TERMS: [
    ['IP address', "The “home address” of a device on the network. 192.168.x.x / 10.x.x.x are private (inside your home only), the rest are public (Internet)."],
    ['MAC address', "The serial number of the network card (e.g. a4:2b:b0:…). The first 3 bytes show the manufacturer. iPhones/Android use a random MAC for privacy."],
    ['Port', "A number 0‑65535 that says which service the packet goes to: 443 = web, 22 = SSH, 53 = DNS. Like the apartments in a block of flats (the IP)."],
    ['Router / Gateway', "The home's “door” to the Internet. All traffic going out passes through it."],
    ['NAT', "The router hides all your devices behind one public IP. That's why people on the Internet can't easily “hit” you."],
    ['ISP', "The Internet provider (e.g. Cosmote, Vodafone, Nova) or the company that owns the IP."],
    ['ASN', "The “autonomous system” number — the identity of a company's network on the Internet (e.g. AS15169 = Google)."],
    ['Datacenter / Hosting', "The IP belongs to a server in a data center — not a home. Attacks often come from cheap VPSs."],
    ['Proxy / VPN / Tor', "The attacker hides behind an intermediary. The country you see is probably not their real one."],
    ['TLS SNI', "Even in encrypted HTTPS, the browser says “in the open” which domain it is going to. That's how NetWatch knows you are going to, say, youtube.com."],
    ['Broadcast / Multicast', "Packets to everyone (255.255.255.255) or to a group (224.x.x.x). Every device on the LAN sees them."],
    ['OSINT', "Open Source Intelligence: information from public sources. AbuseIPDB, Shodan, VirusTotal and GreyNoise tell you whether an IP has been reported for attacks."],
    ['C2 (Command & Control)', "The server the attacker sends orders to infected machines from. Communication with it (beaconing) is often the only trace of an infection."],
    ['JA3 fingerprint', "A hash of the parameters a program sends when it opens a TLS connection (ciphers, extensions). Every browser/app/malware has a characteristic JA3 — so it can be recognised without decrypting the traffic."],
    ['Threat intelligence', "Public or commercial lists of IPs/domains that have been used in attacks (Feodo Tracker, Spamhaus, FireHOL, AbuseIPDB)."],
    ['NXDOMAIN', "The DNS answer “this domain doesn't exist”. Many NXDOMAINs for random names = likely DGA malware."],
    ['Entropy', "A measure of how “random” a text is. “google” has low entropy, “x7k2q9zv” high. It is used to spot machine-made names."],
    ['Cleartext', "Data that travels without encryption. Anyone on the path reads it as it is — passwords included."],
    ['Sniffing', "“Listening” to a network's traffic (e.g. with Wireshark). A legitimate tool for administrators, dangerous when an attacker does it."],
    ['OSI model', "The network is split into layers: Physical (1), Link/MAC (2), Network/IP (3), Transport/TCP‑UDP (4), Application (7). Each layer “wraps” the data from the layer above."],
    ['TCP handshake', "Before talking, two devices exchange SYN → SYN‑ACK → ACK. A port scanner sends only the SYN to see who answers."],
    ['Attack surface', "All the “entry points” of a network: open ports, services, devices, passwords. The smaller, the better."],
    ['Banner grabbing', "You connect to a port and read what the service “says” (e.g. “SSH-2.0-OpenSSH_7.4”). That's how you learn the software and version — and so the known vulnerabilities."],
    ['CVE / CVSS', "CVE = a unique code for a known vulnerability (e.g. CVE-2011-2523). CVSS = a severity score 0–10; above 9 is critical."],
    ['Shodan', "A search engine that scans the whole Internet and records which services each IP exposes. Whatever Shodan sees, attackers see too."],
    ['Pentest', "Penetration test: an authorised, controlled attack to find gaps before someone malicious does. Without written permission it is illegal."],
    ['Red / Blue / Purple team', "Red = attacks, Blue = defends and detects, Purple = they work together: each attack is checked to see whether it is caught, and detection is improved."],
    ['Sigma', "An open format for detection rules in SIEMs. You write the rule once and convert it for Splunk, Elastic, Microsoft Sentinel and others."],
    ['Suricata', "A free, open-source IDS/IPS that checks traffic against rules such as “alert tcp any any -> any 23 (...)”."],
    ['False positive', "An alert about something harmless. A good rule catches the attack without “shouting” about normal traffic."],
    ['Evil twin', "A fake Wi‑Fi access point with the same name as a real one, so victims connect to it."],
    ['Captive portal', "The “accept the terms” or login page that public Wi‑Fi shows before letting you onto the Internet."],
    ['VPN', "An encrypted “tunnel” from your device to a server; the local network sees only that you are talking to it."],
    ['DoH (DNS over HTTPS)', "Encrypted DNS: the network can't see or change the names you look up."],
    ['Stealth mode', "A Mac firewall setting that doesn't answer pings and scans, so you aren't visible on the network."],
    ['Tor', "An anonymity network: traffic passes through 3 volunteer nodes with layered encryption, so nobody knows both who you are and where you are going."],
    ['DNS leak', "When DNS queries go out outside the VPN/Tor and reveal which sites you visit."],
    ['WebRTC leak', "For video calls, the browser can give a site your real IP, even behind a VPN."],
    ['Kill switch', "A VPN setting that cuts the Internet if the tunnel drops, so nothing leaves unprotected."],
    ['CTF', "Capture The Flag: exercises where you find “flags” (answers) by solving security problems — the best way to practise."],
    ['WHOIS', "A public registry: which organisation an IP belongs to, where, and an email for abuse reports."],
  ],

  TIPS: [
    "Change the router's default admin password (not just the Wi‑Fi one).",
    "Use WPA2/WPA3 with a long Wi‑Fi password (12+ characters).",
    "Turn off WPS and UPnP on the router if you don't need them.",
    "Update the firmware on the router and on smart devices.",
    "Put IoT devices (cameras, bulbs, TV) on a guest network.",
    "On the Mac: Settings → Network → Firewall → On + “Stealth mode”.",
    "Turn off Sharing (files, screen, remote login) if you don't need it.",
    "On public Wi‑Fi (café, airport) use a VPN — ARP spoofing is easy there.",
    "Never ignore a certificate warning in the browser.",
    "Turn on encrypted DNS (DNS over HTTPS) in the browser.",
    "If you see an unknown device in the 📟 Devices tab, change the Wi‑Fi password.",
    "Use two-factor authentication (2FA) everywhere.",
    "Turn on “HTTPS-Only mode” in the browser so you never send a password to a page without encryption.",
    "Turn off Telnet and FTP on the router, NAS and cameras; use SSH/SFTP and HTTPS.",
    "Do the 🎓 quiz every day — the better you understand the traffic, the faster you spot something suspicious.",
  ],
};
