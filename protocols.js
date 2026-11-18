// 🎬 Πρωτόκολλα σε κίνηση — 14 πρωτόκολλα ως κινούμενα διαγράμματα ακολουθίας (βήμα-βήμα, με τα πεδία κάθε πακέτου)
// και δίπλα τους το ΑΛΗΘΙΝΟ αντίστοιχο από το δικό σου δίκτυο (από τη ζωντανή καταγραφή του NetWatch).
// Φορτώνεται ως κλασικό <script>: μοιράζεται τα S, tab, $, esc, who, showTab με το index.html.
(() => {
  // ---------------- ορισμοί πρωτοκόλλων ----------------
  // lanes: οι «συμμετέχοντες»· steps: {f:από, t:προς, l:ετικέτα, c:χρώμα, fl:{πεδία}, x:εξήγηση, lost, note}
  const P = [
    { id: 'tcp', n: 'TCP', i: '🤝', L: 'L4 · Μεταφορά', k: 'TCP θύρα: οποιαδήποτε',
      d: 'Αξιόπιστη σύνδεση: πρώτα «χειραψία» 3 βημάτων, μετά αριθμημένα δεδομένα με επιβεβαιώσεις, και στο τέλος κλείσιμο.',
      lanes: ['💻 Εσύ', '🖥 Server'],
      s: [
        { f: 0, t: 1, l: 'SYN', fl: { Flags: 'SYN', Seq: '1000 (τυχαίο ISN)', 'Θύρα πηγής': '54650 (τυχαία)', 'Θύρα προορισμού': '443' }, x: 'Ζητάς σύνδεση. Διαλέγεις έναν τυχαίο αρχικό αριθμό ακολουθίας (ISN), ώστε κανείς να μην μπορεί να «μαντέψει» και να μπει στη μέση.' },
        { f: 1, t: 0, l: 'SYN-ACK', c: 'p', fl: { Flags: 'SYN, ACK', Seq: '5000 (ISN του server)', Ack: '1001 (= 1000 + 1)' }, x: 'Ο server δέχεται: στέλνει το δικό του ISN και επιβεβαιώνει το δικό σου +1. Αν η θύρα ήταν κλειστή, θα έστελνε RST.' },
        { f: 0, t: 1, l: 'ACK', fl: { Flags: 'ACK', Seq: '1001', Ack: '5001' }, x: 'Η σύνδεση είναι ESTABLISHED. Κόστος: 1 πήγαινε-έλα (RTT) πριν σταλεί οποιοδήποτε δεδομένο.' },
        { f: 0, t: 1, l: 'Δεδομένα (PSH, ACK)', c: 'g', fl: { Flags: 'PSH, ACK', Seq: '1001', 'Μήκος': '120 bytes' }, x: 'Κάθε byte έχει αριθμό. Ο server ξέρει τη σειρά, ακόμα κι αν τα πακέτα φτάσουν ανακατεμένα.' },
        { f: 1, t: 0, l: 'ACK 1121', c: 'p', fl: { Flags: 'ACK', Ack: '1121 (= 1001 + 120)' }, x: 'Επιβεβαίωση: «πήρα μέχρι και το byte 1120». Αν δεν έρθει ACK, ο αποστολέας ξαναστέλνει (retransmission).' },
        { f: 0, t: 1, l: 'FIN', c: 'o', fl: { Flags: 'FIN, ACK' }, x: 'Τελείωσες: κλείνεις τη δική σου κατεύθυνση.' },
        { f: 1, t: 0, l: 'FIN-ACK', c: 'o', fl: { Flags: 'FIN, ACK' }, x: 'Ο server επιβεβαιώνει και κλείνει κι εκείνος.' },
        { f: 0, t: 1, l: 'ACK', fl: { Flags: 'ACK' }, x: 'Τέλος. Εσύ μένεις λίγο σε TIME_WAIT, για να μη μπερδευτούν καθυστερημένα πακέτα με μια νέα σύνδεση.' },
      ],
      q: { q: 'Ποια flags έχει το 2ο πακέτο του handshake;', o: ['ACK', 'SYN, ACK', 'SYN', 'PSH, ACK'], a: 1, w: 'SYN (το δικό του ISN) + ACK (επιβεβαίωση του δικού σου).' } },

    { id: 'udp', n: 'UDP', i: '📨', L: 'L4 · Μεταφορά', k: 'UDP',
      d: 'Χωρίς σύνδεση και χωρίς επιβεβαιώσεις: στέλνεις και ελπίζεις. Γρήγορο, γι’ αυτό το χρησιμοποιούν DNS, παιχνίδια, κλήσεις, QUIC.',
      lanes: ['💻 Εσύ', '🖥 Server'],
      s: [
        { f: 0, t: 1, l: 'Datagram #1', fl: { 'Θύρα πηγής': '51000', 'Θύρα προορισμού': '3478', 'Μήκος': '8 + 100 bytes', Checksum: '0x1c46' }, x: 'Ολόκληρη η κεφαλίδα UDP είναι μόλις 8 bytes: θύρες, μήκος, checksum. Καμία χειραψία πριν.' },
        { f: 1, t: 0, l: 'Datagram (απάντηση)', c: 'p', fl: { 'Θύρα πηγής': '3478', 'Θύρα προορισμού': '51000' }, x: 'Η «απάντηση» είναι απλώς ένα άλλο datagram με ανάποδες θύρες. Το UDP δεν ξέρει ότι είναι απάντηση.' },
        { f: 0, t: 1, l: 'Datagram #2', lost: 1, c: 'r', fl: { 'Αποτέλεσμα': 'χάθηκε στο δρόμο' }, x: 'Χάθηκε, και κανείς δεν το ξαναστέλνει. Το αν θα ξαναζητηθεί το αποφασίζει η εφαρμογή (π.χ. το DNS ξαναρωτά μετά από 1–2″).' },
        { f: 0, t: 1, l: 'Datagram #3', fl: { 'Σειρά': 'καμία εγγύηση' }, x: 'Τα datagrams μπορεί να φτάσουν με άλλη σειρά. Σε μια βιντεοκλήση, ένα χαμένο καρέ είναι καλύτερο από μια καθυστέρηση.' },
      ],
      q: { q: 'Τι κάνει το UDP όταν χαθεί ένα πακέτο;', o: ['Το ξαναστέλνει αυτόματα', 'Κλείνει τη σύνδεση', 'Τίποτα — αποφασίζει η εφαρμογή', 'Στέλνει RST'], a: 2, w: 'Το UDP δεν έχει επιβεβαιώσεις ούτε επαναποστολές.' } },

    { id: 'dns', n: 'DNS', i: '📖', L: 'L7 · Εφαρμογή', k: 'UDP 53',
      d: 'Ο «τηλεφωνικός κατάλογος» του internet: μετατρέπει ονόματα (example.com) σε διευθύνσεις IP, ρωτώντας μια ιεραρχία από servers.',
      lanes: ['💻 Εσύ', '📚 Resolver', '🌳 Root', '🏷 .com', '🏢 example.com'],
      s: [
        { f: 0, t: 1, l: 'A example.com ?', fl: { 'Τύπος': 'A (IPv4)', 'ID': '0x2b7f', 'Θύρα': 'UDP 53', RD: '1 (κάνε εσύ τη δουλειά)' }, x: 'Ρωτάς τον resolver σου (router, ISP, 1.1.1.1). Αυτός θα κάνει όλη την αναζήτηση για σένα (αναδρομικά).' },
        { f: 1, t: 2, l: 'example.com ?', fl: { 'Προς': 'έναν από τους 13 root servers' }, x: 'Ο resolver δεν ξέρει την απάντηση (δεν την έχει στην cache), οπότε ξεκινά από την κορυφή.' },
        { f: 2, t: 1, l: 'ρώτα τον .com', c: 'p', fl: { 'Απάντηση': 'NS a.gtld-servers.net (referral)' }, x: 'Ο root δεν ξέρει το example.com. Ξέρει όμως ποιος είναι υπεύθυνος για το .com.' },
        { f: 1, t: 3, l: 'example.com ?', x: 'Επόμενο σκαλί: ο server του .com (TLD).' },
        { f: 3, t: 1, l: 'ρώτα τον ns1', c: 'p', fl: { 'Απάντηση': 'NS ns1.example.com' }, x: 'Ο .com δείχνει τον authoritative server του ίδιου του domain.' },
        { f: 1, t: 4, l: 'A example.com ?', x: 'Τελευταία ερώτηση, στον server που «κατέχει» το domain.' },
        { f: 4, t: 1, l: 'A 93.184.215.14', c: 'g', fl: { 'Απάντηση': '93.184.215.14', TTL: '3600 s', AA: '1 (authoritative)' }, x: 'Η πραγματική απάντηση. Το TTL λέει για πόσο μπορεί να μείνει στην cache.' },
        { f: 1, t: 0, l: '93.184.215.14', c: 'g', fl: { 'Απάντηση': '93.184.215.14', 'Cache': 'για 1 ώρα' }, x: 'Ο resolver σού απαντά και το κρατά στην cache: την επόμενη φορά απαντά αμέσως, σε 1–2 ms. ⚠ Το απλό DNS ταξιδεύει χωρίς κρυπτογράφηση — ο πάροχος βλέπει κάθε όνομα (γι’ αυτό υπάρχουν DoH/DoT).' },
      ],
      q: { q: 'Ποιος server δίνει την τελική απάντηση για το example.com;', o: ['Ο root', 'Ο .com (TLD)', 'Ο authoritative του example.com', 'Ο router'], a: 2, w: 'Root και TLD δίνουν μόνο παραπομπές (referrals).' } },

    { id: 'dhcp', n: 'DHCP', i: '🎟', L: 'L7 · Εφαρμογή', k: 'UDP 67/68',
      d: 'Πώς παίρνει IP μια συσκευή μόλις μπει στο Wi-Fi: 4 μηνύματα, D-O-R-A.',
      lanes: ['📱 Νέα συσκευή', '📡 Router (DHCP)'],
      s: [
        { f: 0, t: 1, l: 'Discover', fl: { 'Από': '0.0.0.0:68 (δεν έχει IP ακόμα)', 'Προς': '255.255.255.255:67 (broadcast)', 'MAC': 'a4:cf:12:…' }, x: 'Η συσκευή δεν έχει IP, οπότε φωνάζει σε όλο το LAN: «υπάρχει DHCP server;»' },
        { f: 1, t: 0, l: 'Offer 192.168.1.50', c: 'p', fl: { 'Προσφορά': '192.168.1.50', 'Μάσκα': '255.255.255.0', 'Gateway': '192.168.1.1', DNS: '192.168.1.1', 'Lease': '24 ώρες' }, x: 'Ο router προτείνει μια ελεύθερη IP μαζί με όλες τις ρυθμίσεις: μάσκα, πύλη, DNS.' },
        { f: 0, t: 1, l: 'Request', fl: { 'Ζητά': '192.168.1.50', 'Προς': 'broadcast' }, x: 'Η συσκευή απαντά «τη θέλω». Είναι πάλι broadcast, ώστε αν υπήρχαν κι άλλοι DHCP servers να καταλάβουν ότι δεν επιλέχθηκαν.' },
        { f: 1, t: 0, l: 'Ack', c: 'g', fl: { 'Τελική': '192.168.1.50 για 24 ώρες' }, x: 'Επιβεβαίωση: η IP είναι δική της. Στη μέση της μίσθωσης θα ζητήσει ανανέωση. ⚠ Ένας ψεύτικος («rogue») DHCP server μπορεί να δώσει δικό του gateway/DNS — γι’ αυτό υπάρχει το DHCP snooping στα switches.' },
      ],
      q: { q: 'Με ποια σειρά γίνονται τα μηνύματα DHCP;', o: ['Request, Offer, Discover, Ack', 'Discover, Offer, Request, Ack', 'Offer, Discover, Ack, Request', 'Discover, Ack'], a: 1, w: 'D-O-R-A: Discover, Offer, Request, Ack.' } },

    { id: 'arp', n: 'ARP', i: '📣', L: 'L2/L3', k: 'Ethernet (χωρίς IP)',
      d: 'Στο τοπικό δίκτυο τα πακέτα πάνε σε MAC, όχι σε IP. Το ARP βρίσκει «ποια MAC έχει αυτή την IP».',
      lanes: ['💻 Εσύ .23', '📢 Όλο το LAN', '📡 Router .1', '😈 Επιτιθέμενος'],
      s: [
        { f: 0, t: 1, l: 'Ποιος έχει το .1;', fl: { 'Op': '1 (who-has)', 'Προς MAC': 'ff:ff:ff:ff:ff:ff (όλοι)', 'Ψάχνει': '192.168.1.1', 'Πες στο': '192.168.1.23' }, x: 'Θέλεις να βγεις στο internet μέσω του router, αλλά χρειάζεσαι τη MAC του. Ρωτάς όλο το LAN.' },
        { f: 1, t: 2, l: '(το ακούνε όλοι)', c: 'd', x: 'Το broadcast φτάνει σε κάθε συσκευή. Μόνο αυτή που έχει την IP πρέπει να απαντήσει.' },
        { f: 2, t: 0, l: 'Το .1 είναι στο 3c:84:6a:…', c: 'g', fl: { 'Op': '2 (is-at)', 'MAC': '3c:84:6a:12:34:56' }, x: 'Ο router απαντά μόνο σε σένα. Εσύ το κρατάς στον πίνακα ARP (δες τον με `arp -a`).' },
        { f: 3, t: 0, l: 'Το .1 είναι στο de:ad:be:ef…', c: 'r', fl: { 'Op': '2 (is-at, χωρίς να ρωτηθεί)', 'MAC': 'de:ad:be:ef:00:01 ⚠' }, x: '⚠ ARP spoofing: το ARP δεν έχει έλεγχο ταυτότητας. Ένας επιτιθέμενος απαντά ψέματα και η κίνησή σου περνά από αυτόν (man-in-the-middle). Το NetWatch το ανιχνεύει όταν αλλάξει η MAC του router.' },
      ],
      q: { q: 'Γιατί το ARP spoofing είναι εύκολο;', o: ['Το ARP είναι κρυπτογραφημένο', 'Το ARP δεν ελέγχει ποιος απαντά', 'Χρειάζεται κωδικό router', 'Δουλεύει μόνο σε IPv6'], a: 1, w: 'Όποιος απαντήσει πρώτος (ή τελευταίος) «κερδίζει» — δεν υπάρχει έλεγχος ταυτότητας.' } },

    { id: 'icmp', n: 'ICMP / ping', i: '🏓', L: 'L3 · Δίκτυο', k: 'ICMP (χωρίς θύρες)',
      d: 'Τα «μηνύματα ελέγχου» του IP. Το ping στέλνει Echo Request και περιμένει Echo Reply, για να μετρήσει αν απαντά κάποιος και πόσο γρήγορα.',
      lanes: ['💻 Εσύ', '🌍 1.1.1.1'],
      s: [
        { f: 0, t: 1, l: 'Echo Request', fl: { Type: '8', Code: '0', ID: '0x1a2b', Seq: '1', TTL: '64' }, x: 'Το ping δεν έχει θύρες: το ICMP μπαίνει κατευθείαν μέσα στο IP.' },
        { f: 1, t: 0, l: 'Echo Reply', c: 'g', fl: { Type: '0', Seq: '1', 'Χρόνος': '14 ms' }, x: 'Η απάντηση γυρίζει με τα ίδια ID/Seq, ώστε να ξέρεις σε ποιο αίτημα απαντά. Ο χρόνος πήγαινε-έλα είναι το RTT.' },
        { f: 0, t: 1, l: 'Echo Request #2', fl: { Seq: '2' }, x: 'Ένα κάθε δευτερόλεπτο. Αν κάποια δεν γυρίσουν, έχεις απώλειες πακέτων (packet loss).' },
        { f: 1, t: 0, l: 'Echo Reply #2', c: 'g', fl: { Type: '0', Seq: '2', 'Χρόνος': '15 ms' }, x: 'Η διαφορά ανάμεσα στους χρόνους είναι το jitter. ℹ Άλλοι τύποι ICMP: 3 = Destination Unreachable, 11 = Time Exceeded (traceroute).' },
      ],
      q: { q: 'Τι τύπο ICMP έχει το Echo Request;', o: ['0', '3', '8', '11'], a: 2, w: '8 = Request, 0 = Reply.' } },

    { id: 'trace', n: 'Traceroute', i: '🧭', L: 'L3 · Δίκτυο', k: 'ICMP / UDP με μικρό TTL',
      d: 'Ποιοι routers είναι ανάμεσα σε σένα και τον προορισμό; Ένα έξυπνο κόλπο με το TTL.',
      lanes: ['💻 Εσύ', '📡 Router σου', '🏢 Πάροχος', '🌍 Προορισμός'],
      s: [
        { f: 0, t: 1, l: 'TTL=1', fl: { TTL: '1' }, x: 'Κάθε router αφαιρεί 1 από το TTL. Στέλνεις με TTL=1, άρα «πεθαίνει» στον πρώτο router.' },
        { f: 1, t: 0, l: 'Time Exceeded', c: 'o', fl: { Type: '11 (Time Exceeded)', 'Από': '192.168.1.1' }, x: 'Ο πρώτος router πετά το πακέτο και σου στέλνει ICMP 11, φανερώνοντας έτσι την IP του. Hop 1 ✓' },
        { f: 0, t: 2, l: 'TTL=2', fl: { TTL: '2' }, x: 'Τώρα με TTL=2: περνά τον πρώτο και πεθαίνει στον δεύτερο.' },
        { f: 2, t: 0, l: 'Time Exceeded', c: 'o', fl: { Type: '11', 'Από': '79.128.x.x (πάροχος)' }, x: 'Hop 2 ✓ Ο χρόνος κάθε απάντησης δείχνει πού «βαραίνει» η διαδρομή.' },
        { f: 0, t: 3, l: 'TTL=3', fl: { TTL: '3' }, x: 'Συνεχίζεις μέχρι να φτάσεις στον προορισμό.' },
        { f: 3, t: 0, l: 'Echo Reply', c: 'g', fl: { Type: '0 (ή 3 = Port Unreachable για UDP)' }, x: 'Έφτασες: ο προορισμός απαντά κανονικά. Τα «* * *» στο traceroute είναι routers που δεν στέλνουν ICMP.' },
      ],
      q: { q: 'Τι κάνει ένας router όταν το TTL φτάσει στο 0;', o: ['Το προωθεί κανονικά', 'Το πετά και στέλνει ICMP Time Exceeded', 'Το στέλνει πίσω', 'Αυξάνει το TTL'], a: 1, w: 'Αυτή η απάντηση (type 11) είναι που αποκαλύπτει κάθε hop.' } },

    { id: 'tls', n: 'TLS 1.3', i: '🔐', L: 'L5–6 · Ασφάλεια', k: 'TCP 443',
      d: 'Η κρυπτογράφηση πίσω από το λουκέτο του HTTPS. Στην έκδοση 1.3 χρειάζεται μόλις 1 πήγαινε-έλα, πάνω από μια ήδη ανοιχτή σύνδεση TCP.',
      lanes: ['💻 Εσύ', '🖥 Server'],
      s: [
        { f: 0, t: 1, l: 'ClientHello', fl: { SNI: 'github.com (ορατό!)', 'Ciphers': 'TLS_AES_128_GCM_SHA256, …', 'key_share': 'X25519 (δημόσιο κλειδί)', ALPN: 'h2, http/1.1' }, x: 'Στέλνεις ήδη το δικό σου κομμάτι για την ανταλλαγή κλειδιών (key_share). ⚠ Το SNI, δηλαδή το όνομα του site, ταξιδεύει ακρυπτογράφητο. Έτσι το NetWatch (και ο πάροχος) βλέπει πού συνδέεσαι.' },
        { f: 1, t: 0, l: 'ServerHello + 🔒Certificate + Finished', c: 'p', fl: { 'key_share': 'X25519 του server', 'Certificate': '🔒 κρυπτογραφημένο', 'CertificateVerify': 'υπογραφή με το ιδιωτικό κλειδί', 'Finished': 'έλεγχος ακεραιότητας' }, x: 'Και οι δύο έχετε πλέον το κοινό μυστικό (ECDHE). Ό,τι ακολουθεί, ακόμα και το πιστοποιητικό, είναι κρυπτογραφημένο.' },
        { f: 0, t: 1, l: 'Finished', fl: { 'Έλεγχος': 'το πιστοποιητικό είναι για το github.com και υπογράφεται από αξιόπιστη CA' }, x: 'Ο browser ελέγχει την αλυσίδα πιστοποιητικών. Αν κάτι δεν ταιριάζει, βλέπεις την κόκκινη προειδοποίηση.' },
        { f: 0, t: 1, l: '🔒 GET / (HTTP/2)', c: 'g', fl: { 'Περιεχόμενο': 'κρυπτογραφημένο (AES-GCM)' }, x: 'Από εδώ και πέρα, όποιος παρακολουθεί βλέπει μόνο μεγέθη και χρόνους, όχι το περιεχόμενο.' },
        { f: 1, t: 0, l: '🔒 200 OK', c: 'g', x: 'Forward secrecy: τα κλειδιά της συνεδρίας σβήνονται στο τέλος. Ακόμα κι αν κλαπεί αργότερα το κλειδί του server, η παλιά κίνηση δεν ανοίγει.' },
      ],
      q: { q: 'Ποιο κομμάτι του TLS 1.3 φαίνεται ακρυπτογράφητο;', o: ['Το πιστοποιητικό', 'Το SNI (όνομα του site)', 'Τα cookies', 'Το URL'], a: 1, w: 'Το SNI στο ClientHello (εκτός αν χρησιμοποιηθεί ECH).' } },

    { id: 'http', n: 'HTTP', i: '🌐', L: 'L7 · Εφαρμογή', k: 'TCP 80',
      d: 'Αίτημα και απάντηση, σε απλό κείμενο. Χωρίς το «S» όλα ταξιδεύουν ορατά — και αυτό ακριβώς βλέπεις εδώ.',
      lanes: ['🧭 Browser', '🖥 Server'],
      s: [
        { f: 0, t: 1, l: 'GET /index.html', fl: { 'Γραμμή': 'GET /index.html HTTP/1.1', Host: 'neverssl.com', 'User-Agent': 'Mozilla/5.0 …', Cookie: 'session=abc123 ⚠' }, x: 'Όλα είναι κείμενο. Σε HTTP χωρίς S, όποιος είναι στο ίδιο Wi-Fi βλέπει το URL, τα cookies, ακόμα και κωδικούς φόρμας.' },
        { f: 1, t: 0, l: '200 OK + HTML', c: 'g', fl: { 'Κατάσταση': '200 OK', 'Content-Type': 'text/html', 'Cache-Control': 'max-age=600' }, x: 'Η απάντηση: κωδικός κατάστασης, κεφαλίδες, και το ίδιο το περιεχόμενο.' },
        { f: 0, t: 1, l: 'GET /style.css', fl: { 'If-None-Match': '"5e1f…"' }, x: 'Ο browser ζητά και τα υπόλοιπα αρχεία. Αν έχει ήδη ένα αντίγραφο, ρωτά «άλλαξε;»' },
        { f: 1, t: 0, l: '304 Not Modified', c: 'p', fl: { 'Κατάσταση': '304' }, x: 'Δεν άλλαξε: χρησιμοποίησε την cache. ℹ Κωδικοί: 2xx εντάξει · 3xx ανακατεύθυνση · 4xx λάθος σου (404) · 5xx λάθος του server.' },
      ],
      q: { q: 'Τι σημαίνει 404;', o: ['Εντάξει', 'Ανακατεύθυνση', 'Δεν βρέθηκε (λάθος του client)', 'Ο server κατέρρευσε'], a: 2, w: '4xx = σφάλμα του αιτήματος· το 404 = δεν υπάρχει αυτό το αρχείο.' } },

    { id: 'nat', n: 'NAT', i: '🔀', L: 'L3/L4 · Router', k: 'ο router σου',
      d: 'Όλες οι συσκευές του σπιτιού βγαίνουν στο internet με ΜΙΑ δημόσια IP. Ο router σημειώνει ποιος ρώτησε τι.',
      lanes: ['💻 Laptop 192.168.1.23', '📡 Router (NAT)', '🌍 Server 93.184.215.14'],
      s: [
        { f: 0, t: 1, l: '192.168.1.23:54650 →', fl: { 'Πηγή': '192.168.1.23:54650', 'Προορισμός': '93.184.215.14:443' }, x: 'Η ιδιωτική IP (192.168.x.x) δεν «περπατά» στο internet. Το πακέτο πάει πρώτα στον router.' },
        { f: 1, t: 2, l: '85.75.98.180:40001 →', c: 'o', fl: { 'Πηγή (νέα)': '85.75.98.180:40001', 'Πίνακας NAT': '40001 ↔ 192.168.1.23:54650' }, x: 'Ο router αλλάζει την πηγή στη δημόσια IP του και σε μια δική του θύρα, και σημειώνει την αντιστοίχιση.' },
        { f: 2, t: 1, l: '→ 85.75.98.180:40001', c: 'p', fl: { 'Προορισμός': '85.75.98.180:40001' }, x: 'Ο server βλέπει μόνο τη δημόσια IP. Δεν ξέρει καν ότι υπάρχει laptop.' },
        { f: 1, t: 0, l: '→ 192.168.1.23:54650', c: 'g', fl: { 'Προορισμός (πίσω)': '192.168.1.23:54650' }, x: 'Ο router κοιτά τον πίνακα και το στέλνει στη σωστή συσκευή. ℹ Γι’ αυτό κανείς απ’ έξω δεν μπορεί να ξεκινήσει σύνδεση προς τα μέσα — εκτός αν ανοίξεις port forwarding ή UPnP (δες την καρτέλα Έλεγχος).' },
      ],
      q: { q: 'Τι κρατά ο router στον πίνακα NAT;', o: ['Τους κωδικούς Wi-Fi', 'Αντιστοίχιση δημόσιας θύρας ↔ ιδιωτικής IP:θύρας', 'Τα ονόματα DNS', 'Τις MAC όλων των servers'], a: 1, w: 'Έτσι ξέρει σε ποια συσκευή να στείλει κάθε απάντηση.' } },

    { id: 'quic', n: 'QUIC / HTTP/3', i: '⚡', L: 'L4+ · Μεταφορά', k: 'UDP 443',
      d: 'Το νέο «TCP + TLS σε ένα», πάνω από UDP. Το χρησιμοποιούν Google, YouTube, Cloudflare. Ξεκινά σε 1 πήγαινε-έλα αντί για 2.',
      lanes: ['💻 Εσύ', '🖥 Server'],
      s: [
        { f: 0, t: 1, l: 'Initial (ClientHello)', fl: { 'Μεταφορά': 'UDP 443', 'Connection ID': '8f3a…', 'Μέσα': 'TLS 1.3 ClientHello' }, x: 'Χωρίς χειραψία TCP: το TLS ClientHello πάει κατευθείαν μέσα στο πρώτο πακέτο QUIC.' },
        { f: 1, t: 0, l: 'Initial + Handshake', c: 'p', fl: { 'Μέσα': 'ServerHello, 🔒 Certificate, Finished' }, x: 'Σε ένα RTT έχεις ταυτόχρονα σύνδεση ΚΑΙ κρυπτογράφηση. Με TCP + TLS θα ήθελες 2.' },
        { f: 0, t: 1, l: '🔒 HTTP/3 GET', c: 'g', fl: { 'Streams': 'πολλά, ανεξάρτητα' }, x: 'Αν χαθεί ένα πακέτο, καθυστερεί μόνο το δικό του stream και όχι όλα (τέλος στο head-of-line blocking).' },
        { f: 1, t: 0, l: '🔒 απαντήσεις', c: 'g', x: 'ℹ Το Connection ID επιτρέπει να αλλάξεις δίκτυο (Wi-Fi → 4G) χωρίς να κοπεί η σύνδεση. ⚠ Σχεδόν όλα είναι κρυπτογραφημένα, ακόμα και οι αριθμοί πακέτων — γι’ αυτό τα firewalls το βλέπουν δύσκολα.' },
      ],
      q: { q: 'Πάνω από ποιο πρωτόκολλο τρέχει το QUIC;', o: ['TCP', 'UDP', 'ICMP', 'ARP'], a: 1, w: 'UDP 443 — υλοποιεί μόνο του αξιοπιστία και κρυπτογράφηση.' } },

    { id: 'ssh', n: 'SSH', i: '🖥', L: 'L7 · Εφαρμογή', k: 'TCP 22',
      d: 'Ασφαλές τερματικό σε απομακρυσμένο μηχάνημα (Raspberry Pi, Proxmox, server). Πρώτα κλειδιά, μετά ταυτότητα, μετά shell.',
      lanes: ['💻 Εσύ', '🖥 Server'],
      s: [
        { f: 0, t: 1, l: 'SSH-2.0-OpenSSH_9.6', fl: { 'Banner': 'έκδοση λογισμικού (ορατή)' }, x: 'Μετά τη χειραψία TCP, και οι δύο λένε την έκδοσή τους. Αυτό είναι το μόνο που φαίνεται σε απλό κείμενο.' },
        { f: 1, t: 0, l: 'KEXINIT', c: 'p', fl: { 'Αλγόριθμοι': 'curve25519, chacha20-poly1305, ed25519' }, x: 'Συμφωνούν ποιους αλγορίθμους θα χρησιμοποιήσουν.' },
        { f: 0, t: 1, l: 'ECDH (κλειδί)', fl: { 'Ανταλλαγή': 'curve25519' }, x: 'Ανταλλαγή κλειδιών, όπως στο TLS: προκύπτει ένα κοινό μυστικό που δεν πέρασε ποτέ από το δίκτυο.' },
        { f: 1, t: 0, l: 'Host key + υπογραφή', c: 'o', fl: { 'Fingerprint': 'SHA256:9kq…', 'Έλεγχος': '~/.ssh/known_hosts' }, x: '⚠ Το «The authenticity of host… can’t be established» την πρώτη φορά αφορά ΑΥΤΟ. Αν αλλάξει χωρίς λόγο, ίσως κάποιος είναι στη μέση.' },
        { f: 0, t: 1, l: '🔒 publickey', c: 'g', fl: { 'Ταυτότητα': 'ed25519 κλειδί (καλύτερο από κωδικό)' }, x: 'Αποδεικνύεις ποιος είσαι με το ιδιωτικό σου κλειδί, χωρίς να το στείλεις. Οι κωδικοί δέχονται brute force — το NetWatch τις βλέπει.' },
        { f: 1, t: 0, l: '🔒 shell', c: 'g', x: 'Από εδώ και πέρα, κάθε πλήκτρο ταξιδεύει κρυπτογραφημένο.' },
      ],
      q: { q: 'Τι ελέγχει το αρχείο known_hosts;', o: ['Τον κωδικό σου', 'Ότι ο server είναι ο ίδιος με την προηγούμενη φορά', 'Ποιοι χρήστες υπάρχουν', 'Τη θύρα'], a: 1, w: 'Κρατά το fingerprint του host key κάθε server.' } },

    { id: 'mqtt', n: 'MQTT', i: '🌡', L: 'L7 · IoT', k: 'TCP 1883 / 8883 (TLS)',
      d: 'Το πρωτόκολλο των έξυπνων συσκευών: οι αισθητήρες «δημοσιεύουν» σε θέματα (topics), ο broker τα μοιράζει σε όποιον έχει «εγγραφεί».',
      lanes: ['🌡 ESP32 κήπου', '📮 Broker (Mosquitto)', '🏠 Home Assistant'],
      s: [
        { f: 2, t: 1, l: 'SUBSCRIBE home/garden/#', c: 'p', fl: { 'Topic': 'home/garden/# (# = όλα από κάτω)', QoS: '1' }, x: 'Το Home Assistant λέει στον broker: «στείλε μου ό,τι αφορά τον κήπο».' },
        { f: 0, t: 1, l: 'CONNECT', fl: { 'Client ID': 'esp32-garden', 'Keepalive': '60 s', 'User/Pass': 'esp / ••• ⚠' }, x: '⚠ Στη θύρα 1883 όλα πάνε ακρυπτογράφητα, ακόμα και ο κωδικός. Χρησιμοποίησε 8883 (TLS) — η καρτέλα MQTT του NetWatch το ελέγχει.' },
        { f: 1, t: 0, l: 'CONNACK', c: 'g', fl: { 'Κωδικός': '0 (αποδεκτό)' }, x: 'Ο broker δέχτηκε τη σύνδεση.' },
        { f: 0, t: 1, l: 'PUBLISH temp = 21.5', fl: { 'Topic': 'home/garden/temp', 'Payload': '21.5', QoS: '1 (τουλάχιστον μία φορά)' }, x: 'Ο αισθητήρας δεν ξέρει ποιος θα το διαβάσει. Απλώς δημοσιεύει.' },
        { f: 1, t: 0, l: 'PUBACK', c: 'g', x: 'Με QoS 1 ο broker επιβεβαιώνει. (QoS 0 = στείλε και ξέχνα, QoS 2 = ακριβώς μία φορά.)' },
        { f: 1, t: 2, l: 'PUBLISH temp = 21.5', c: 'g', fl: { 'Προς': 'όλους τους εγγεγραμμένους' }, x: 'Ο broker το προωθεί σε όποιον έχει εγγραφεί, εδώ στο Home Assistant.' },
      ],
      q: { q: 'Τι σημαίνει το # σε ένα topic MQTT;', o: ['Σχόλιο', 'Όλα τα θέματα από αυτό το επίπεδο και κάτω', 'Κρυπτογράφηση', 'Αριθμός θύρας'], a: 1, w: 'Το # είναι multi-level wildcard· το + ταιριάζει ένα επίπεδο.' } },

    { id: 'wg', n: 'WireGuard', i: '🛡', L: 'L3 · VPN', k: 'UDP 51820',
      d: 'Σύγχρονο, μικρό και γρήγορο VPN. Χειραψία σε 1 RTT, και μετά όλη η κίνηση πάει κρυπτογραφημένη σε ένα «τούνελ».',
      lanes: ['💻 Laptop (έξω)', '🏠 WireGuard στο σπίτι'],
      s: [
        { f: 0, t: 1, l: 'Handshake Initiation', fl: { Type: '1', 'Ephemeral': 'νέο δημόσιο κλειδί', 'Static': '🔒 το κλειδί σου (κρυπτογραφημένο)', 'Timestamp': '🔒 (κατά των replay)' }, x: 'Ξεκινάς με προσωρινό κλειδί. Ακόμα και η ταυτότητά σου πάει κρυπτογραφημένη.' },
        { f: 1, t: 0, l: 'Handshake Response', c: 'p', fl: { Type: '2', 'Ephemeral': 'του server' }, x: 'Ο server σε αναγνωρίζει από τη λίστα peers. Τώρα έχετε κλειδιά συνεδρίας (Noise protocol).' },
        { f: 0, t: 1, l: '🔒 Transport data', c: 'g', fl: { Type: '4', 'Counter': '0, 1, 2, …', 'Μέσα': 'ολόκληρο πακέτο IP (π.χ. προς 192.168.1.10)' }, x: 'Κάθε πακέτο σου «τυλίγεται» και φτάνει στο σπίτι σαν να ήσουν εκεί.' },
        { f: 1, t: 0, l: '🔒 Transport data', c: 'g', fl: { Type: '4' }, x: 'Τα κλειδιά αλλάζουν αυτόματα κάθε 2 λεπτά.' },
        { f: 0, t: 1, l: 'Keepalive', c: 'd', fl: { 'Κάθε': '25 s (αν το ρυθμίσεις)' }, x: 'Κρατά ανοιχτή την αντιστοίχιση NAT του router. ℹ Σε άγνωστους ο WireGuard δεν απαντά καθόλου: για έναν scanner η θύρα μοιάζει κλειστή.' },
      ],
      q: { q: 'Τι κάνει ο WireGuard όταν λάβει πακέτο από άγνωστο κλειδί;', o: ['Στέλνει σφάλμα', 'Δεν απαντά καθόλου', 'Ζητά κωδικό', 'Κλείνει τη θύρα'], a: 1, w: 'Σιωπή — έτσι δεν φαίνεται σε σαρώσεις.' } },
  ];
  const BY = Object.fromEntries(P.map(p => [p.id, p]));

  // ---------------- ζωντανό buffer πακέτων ----------------
  const BUF = [];
  const push = items => { for (const it of items) BUF.push(it); if (BUF.length > 4000) BUF.splice(0, BUF.length - 4000); };
  function hook() {
    if (typeof window.handle !== 'function' || window.handle.__pr) return;
    const h = window.handle;
    window.handle = function (m) { try { if (m && m.type === 'pkts' && m.items) push(m.items); } catch (e) { } return h.apply(this, arguments); };
    window.handle.__pr = 1;
    try { if (typeof S !== 'undefined' && S.feed) push(S.feed.slice().reverse()); } catch (e) { }
  }
  document.addEventListener('DOMContentLoaded', hook);

  // ---------------- κατάσταση ----------------
  const ST = { id: 'tcp', i: -1, play: false, sp: 1, tm: null, raf: null, ans: {} };
  try { const v = JSON.parse(localStorage.getItem('nw-proto') || '{}'); if (BY[v.id]) ST.id = v.id; ST.ans = v.ans || {}; } catch (e) { }
  const save = () => { try { localStorage.setItem('nw-proto', JSON.stringify({ id: ST.id, ans: ST.ans })); } catch (e) { } };
  const E = s => (typeof esc === 'function' ? esc(String(s)) : String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])));
  const nomo = () => document.documentElement.classList.contains('nomo');
  const COL = { p: 'var(--purple)', g: 'var(--green)', o: 'var(--orange)', r: 'var(--red)', d: 'var(--dim)' };

  // ---------------- διάγραμμα ακολουθίας (SVG) ----------------
  const W = 760, TOP = 58, ROW = 46;
  const laneX = (p, k) => { const n = p.lanes.length; return n === 1 ? W / 2 : 70 + k * (W - 140) / (n - 1); };
  function svg(p) {
    const H = TOP + p.s.length * ROW + 16;
    let g = `<svg class="pr-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMin meet"><defs>${Object.entries({ c: 'var(--cyan)', ...COL }).map(([k, c]) => `<marker id="pa-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="${c}"/></marker>`).join('')}</defs>`;
    p.lanes.forEach((l, k) => { const x = laneX(p, k);
      g += `<line x1="${x}" y1="40" x2="${x}" y2="${H - 6}" class="pr-life"/><rect x="${x - 62}" y="6" width="124" height="30" rx="8" class="pr-lane"/><text x="${x}" y="25" text-anchor="middle" class="pr-lt">${E(l)}</text>`; });
    p.s.forEach((s, j) => {
      const y = TOP + j * ROW + 14, x1 = laneX(p, s.f), x2 = laneX(p, s.t), c = s.c || 'c', col = c === 'c' ? 'var(--cyan)' : COL[c];
      const xe = s.lost ? (x1 + x2) / 2 : x2 - Math.sign(x2 - x1) * 3;
      g += `<g class="pr-st" data-st="${j}" style="--pc:${col}"><rect x="40" y="${y - 30}" width="${W - 80}" height="${ROW - 2}" rx="6" class="pr-hit"/>
        <line x1="${x1}" y1="${y}" x2="${xe}" y2="${y}" stroke="${col}" class="pr-ar${s.lost ? ' lost' : ''}" ${s.lost ? '' : `marker-end="url(#pa-${c})"`}/>
        ${s.lost ? `<text x="${xe + 6}" y="${y + 5}" class="pr-x">✕</text>` : ''}
        <text x="${(x1 + (s.lost ? xe : x2)) / 2}" y="${y - 8}" text-anchor="middle" class="pr-al">${E(s.l)}</text>
        <text x="${Math.min(x1, x2) - 10 < 30 ? 30 : Math.min(x1, x2) - 10}" y="${y + 4}" text-anchor="end" class="pr-n">${j + 1}</text></g>`;
    });
    return g + `<circle r="7" class="pr-dot" cx="-20" cy="-20"/></svg>`;
  }

  function stepTo(i, anim = true) {
    const p = BY[ST.id], el = document.getElementById('t-proto'); if (!el) return;
    ST.i = Math.max(-1, Math.min(i, p.s.length - 1));
    el.querySelectorAll('.pr-st').forEach(g => { const j = +g.dataset.st; g.classList.toggle('done', j < ST.i); g.classList.toggle('cur', j === ST.i); g.classList.toggle('fut', j > ST.i); });
    const dot = el.querySelector('.pr-dot'); cancelAnimationFrame(ST.raf);
    const s = p.s[ST.i], det = el.querySelector('.pr-det');
    if (!s) { dot.setAttribute('cx', -20); det.innerHTML = `<div class="pr-dh">${p.i} ${E(p.n)}</div><div class="sm" style="white-space:normal">${E(p.d)}</div><div class="pr-hint">▶ Πάτα «Αναπαραγωγή» ή κάνε κλικ σε ένα βέλος.</div>`; ctrl(); return; }
    det.innerHTML = `<div class="pr-dh"><span class="pr-num">${ST.i + 1}/${p.s.length}</span> ${E(s.l)}</div>
      <div class="pr-way"><span>${E(p.lanes[s.f])}</span> → <span>${E(p.lanes[s.t])}</span>${s.lost ? ' <b style="color:var(--red)">✕ χάθηκε</b>' : ''}</div>
      ${s.fl ? `<table class="pr-fl">${Object.entries(s.fl).map(([k, v]) => `<tr><td>${E(k)}</td><td><span class="pr-v">${E(v)}</span></td></tr>`).join('')}</table>` : ''}
      <div class="pr-x2">${E(s.x)}</div>`;
    const y = TOP + ST.i * ROW + 14, x1 = laneX(p, s.f), x2 = s.lost ? (laneX(p, s.f) + laneX(p, s.t)) / 2 : laneX(p, s.t);
    dot.style.fill = s.c && s.c !== 'c' ? COL[s.c] : 'var(--cyan)';
    if (!anim || nomo()) { dot.setAttribute('cx', x2); dot.setAttribute('cy', y); ctrl(); return; }
    const t0 = performance.now(), dur = 750 / ST.sp;
    const fr = now => { const k = Math.min(1, (now - t0) / dur), e = k < .5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2;
      dot.setAttribute('cx', x1 + (x2 - x1) * e); dot.setAttribute('cy', y); if (k < 1) ST.raf = requestAnimationFrame(fr); };
    ST.raf = requestAnimationFrame(fr); ctrl();
  }
  function ctrl() {
    const el = document.getElementById('t-proto'); if (!el) return;
    const b = el.querySelector('[data-pc="play"]'); if (b) b.textContent = ST.play ? '⏸ Παύση' : (ST.i >= BY[ST.id].s.length - 1 ? '↺ Ξανά' : '▶ Αναπαραγωγή');
  }
  function tick() {
    clearTimeout(ST.tm); if (!ST.play) return;
    if (typeof tab !== 'undefined' && tab !== 'proto') { ST.play = false; return; }
    const p = BY[ST.id];
    if (ST.i >= p.s.length - 1) { ST.play = false; ctrl(); return; }
    stepTo(ST.i + 1);
    ST.tm = setTimeout(tick, 2600 / ST.sp);
  }
  function toggle() {
    const p = BY[ST.id];
    if (ST.play) { ST.play = false; clearTimeout(ST.tm); ctrl(); return; }
    if (ST.i >= p.s.length - 1) stepTo(-1, false);
    ST.play = true; tick();
  }

  // ---------------- «Στο δικό σου δίκτυο» ----------------
  const nm = ip => { try { return typeof who === 'function' ? who(ip) : ip; } catch (e) { return ip; } };
  const tago = t => { const s = Date.now() / 1000 - t; return s < 60 ? Math.max(0, Math.round(s)) + '″' : s < 3600 ? Math.round(s / 60) + '′' : Math.round(s / 3600) + (window.I18N && I18N.lang === 'en' ? 'h' : 'ω'); };
  const ms = v => v < 1 ? (v).toFixed(2) + ' ms' : v < 10 ? v.toFixed(1) + ' ms' : Math.round(v) + ' ms';
  const port = (it, ...ps) => ps.includes(it.dp) || ps.includes(it.sp);
  const row = (t, body) => `<div class="pr-lr"><span class="pr-ago">${tago(t)}</span>${body}</div>`;
  const pair = (a, b) => `<span data-noi18n>${E(nm(a))}</span> <b class="pr-arr">→</b> <span data-noi18n>${E(nm(b))}</span>`;
  const last = (f, n = 6) => { const r = []; for (let k = BUF.length - 1; k >= 0 && r.length < n; k--) if (f(BUF[k])) r.push(BUF[k]); return r; };

  function tcpHS() {
    const m = new Map(), out = [];
    let rst = 0, fin = 0;
    for (const it of BUF) {
      if (it.p !== 'TCP') continue;
      const f = it.f || '', k = `${it.s}:${it.sp}>${it.d}:${it.dp}`, rk = `${it.d}:${it.dp}>${it.s}:${it.sp}`;
      if (f.includes('R')) rst++;
      if (f.includes('F')) fin++;
      if (f === 'S') m.set(k, { syn: it.t, it });
      else if (f === 'SA' && m.has(rk)) { const r = m.get(rk); if (!r.sa) { r.sa = it.t; out.push(r); } }
      else if (f === 'A' && m.has(k)) { const r = m.get(k); if (r.sa && !r.ack) r.ack = it.t; }
    }
    return { hs: out.slice(-5).reverse(), rst, fin, open: [...m.values()].filter(r => !r.sa).length };
  }
  function dnsPairs() {
    const q = new Map(), out = [];
    for (const it of BUF) {
      if (it.p !== 'UDP' || !port(it, 53, 5353)) continue;
      if ((it.dp === 53 || it.dp === 5353) && it.n) q.set(`${it.s}:${it.sp}>${it.d}`, it);
      else if (it.sp === 53) { const r = q.get(`${it.d}:${it.dp}>${it.s}`); if (r) { out.push({ q: r, a: it, ms: (it.t - r.t) * 1000 }); q.delete(`${it.d}:${it.dp}>${it.s}`); } }
    }
    return { pairs: out.slice(-6).reverse(), qs: last(it => it.n && it.nk === 'dns', 6) };
  }

  const LIVE = {
    tcp() { const r = tcpHS();
      if (!r.hs.length) return null;
      return r.hs.map(h => row(h.ack || h.sa, `${pair(h.it.s, h.it.d)} <span class="sm">:${h.it.dp} ${E(h.it.a || '')}</span>
        <span class="pr-hs"><i>SYN</i>→<i class="p">SYN-ACK</i> <b>${ms((h.sa - h.syn) * 1000)}</b>${h.ack ? ` →<i>ACK</i> <b>${ms((h.ack - h.sa) * 1000)}</b>` : ''}</span>`)).join('')
        + `<div class="sm pr-sum"><span>Ο χρόνος SYN → SYN-ACK είναι το RTT προς τον server.</span> <span>Στη μνήμη:</span> <span data-noi18n>${r.fin} FIN · ${r.rst} RST</span>${r.open ? ` · <span>${r.open} SYN χωρίς απάντηση</span>` : ''}</div>`; },
    udp() { const it = last(x => x.p === 'UDP', 400); if (!it.length) return null;
      const c = {}; it.forEach(x => { const k = x.a || ('θύρα ' + Math.min(x.sp, x.dp)); c[k] = (c[k] || 0) + 1; });
      return `<div class="pr-chips">${Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => `<span class="pr-chip">${E(k)} <b>${v}</b></span>`).join('')}</div>`
        + it.slice(0, 4).map(x => row(x.t, `${pair(x.s, x.d)} <span class="sm">UDP ${x.sp} → ${x.dp} · ${x.l} B</span>`)).join('') + `<div class="sm pr-sum">Κανένα handshake: κάθε γραμμή είναι ένα μεμονωμένο datagram.</div>`; },
    dns() { const r = dnsPairs(); if (!r.pairs.length && !r.qs.length) return null;
      return (r.pairs.length ? r.pairs : r.qs.map(q => ({ q }))).map(x => row(x.q.t, `<b data-noi18n>${E(x.q.n)}</b> <span class="sm">→ <span data-noi18n>${E(nm(x.q.d))}</span></span>${x.ms != null ? ` <span class="pr-hs"><span>απάντηση σε</span> <b>${ms(x.ms)}</b>${x.ms < 3 ? ' <i class="g">cache</i>' : ''}</span>` : ''}`)).join('')
        + `<div class="sm pr-sum">Κάτω από 3 ms = ήταν στην cache του resolver· δεκάδες ms = έγινε ολόκληρη η αναζήτηση.</div>`; },
    dhcp() { const it = last(x => x.p === 'UDP' && port(x, 67, 68)); if (!it.length) return null;
      return it.map(x => row(x.t, `${pair(x.s, x.d)} <span class="pr-hs">${x.sp === 68 ? '<i>Discover / Request</i>' : '<i class="g">Offer / Ack</i>'}</span>`)).join(''); },
    arp() { const it = last(x => x.p === 'ARP', 8); if (!it.length) return null;
      return it.map(x => row(x.t, x.f === 'is-at' ? `<span data-noi18n>${E(nm(x.s))}</span> <span class="pr-hs"><i class="g">is-at</i></span> <span class="sm">«εγώ έχω αυτή την IP»</span>` : `<span data-noi18n>${E(nm(x.s))}</span> <span class="pr-hs"><i>who-has</i></span> <span data-noi18n>${E(x.d)}</span>?`)).join(''); },
    icmp() { const it = last(x => x.p === 'ICMP' || x.p === 'ICMPv6', 8); if (!it.length) return null;
      const T = { 8: 'Echo Request', 0: 'Echo Reply', 11: 'Time Exceeded', 3: 'Unreachable' };
      return it.map(x => row(x.t, `${pair(x.s, x.d)} <span class="pr-hs"><i class="${x.ic === 0 ? 'g' : x.ic === 11 || x.ic === 3 ? 'o' : ''}">${E(T[x.ic] || (x.p === 'ICMPv6' ? 'ICMPv6' : 'type ' + (x.ic ?? '?')))}</i></span>`)).join(''); },
    trace() { const it = last(x => x.p === 'ICMP' && x.ic === 11, 10); if (!it.length) return null;
      const seen = new Set(), hops = it.reverse().filter(x => !seen.has(x.s) && seen.add(x.s));
      return `<div class="pr-hops">${hops.map((x, k) => `<span class="pr-chip">hop ${k + 1} · <span data-noi18n>${E(nm(x.s))}</span></span>`).join('<b class="pr-arr">→</b>')}</div><div class="sm pr-sum">Κάθε «Time Exceeded» που είδα είναι ένας router στη διαδρομή.</div>`; },
    tls() { const it = last(x => x.nk === 'sni', 8); if (!it.length) return null;
      return it.map(x => row(x.t, `<span class="pr-hs"><i>ClientHello</i></span> SNI <b data-noi18n>${E(x.n)}</b> <span class="sm">→ <span data-noi18n>${E(x.d)}</span>:${x.dp}</span>`)).join('')
        + `<div class="sm pr-sum">Αυτά είναι τα ονόματα που φαίνονται ακρυπτογράφητα μέσα στο ClientHello. Ό,τι ακολουθεί, όχι.</div>`; },
    http() { const it = last(x => x.nk === 'http' || (x.p === 'TCP' && port(x, 80) && x.l > 80), 8); if (!it.length) return null;
      return it.map(x => row(x.t, `${pair(x.s, x.d)} ${x.n ? `<b data-noi18n>${E(x.n)}</b>` : ''} <span class="pr-hs"><i class="o">ακρυπτογράφητο</i></span>`)).join(''); },
    nat() { const me = (typeof S !== 'undefined' && S.me) ? [...S.me].find(i => !i.includes(':')) : null;
      const it = last(x => x.p === 'TCP' && x.f === 'S' && me && x.s === me, 400); if (!me) return null;
      const t = Date.now() / 1000, ports = new Set(it.filter(x => t - x.t < 120).map(x => x.sp));
      const ex = it[0];
      return `<div class="pr-lr"><span>Η IP σου εδώ μέσα:</span> <b data-noi18n>${E(me)}</b> <span>ιδιωτική, δεν φαίνεται στο internet.</span></div>`
        + (ex ? `<div class="pr-lr"><span data-noi18n>${E(me)}:${ex.sp}</span> <b class="pr-arr">→</b> 📡 NAT <b class="pr-arr">→</b> <span>(δημόσια IP)</span>:? <b class="pr-arr">→</b> <span data-noi18n>${E(nm(ex.d))}:${ex.dp}</span></div>` : '')
        + `<div class="sm pr-sum">Τα τελευταία 2 λεπτά άνοιξες ${ports.size} νέες συνδέσεις TCP — άρα ο router κρατά τουλάχιστον τόσες εγγραφές NAT μόνο για σένα. Τη δημόσια IP σου τη βλέπεις στην καρτέλα Ανωνυμία.</div>`; },
    quic() { const it = last(x => x.a === 'QUIC' || (x.p === 'UDP' && port(x, 443)), 300); if (!it.length) return null;
      const d = {}; it.forEach(x => { const k = x.dp === 443 ? x.d : x.s; d[k] = (d[k] || 0) + 1; });
      return Object.entries(d).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([ip, n]) => `<div class="pr-lr"><span data-noi18n>${E(nm(ip))}</span> <span class="pr-hs"><i>UDP 443</i> <b>${n}</b> <span>πακέτα</span></span></div>`).join('')
        + `<div class="sm pr-sum">Αυτοί οι servers σού μιλούν με HTTP/3 πάνω από QUIC (συνήθως Google/YouTube/Cloudflare).</div>`; },
    ssh() { const it = last(x => x.p === 'TCP' && port(x, 22)); if (!it.length) return null;
      return it.map(x => row(x.t, `${pair(x.s, x.d)} <span class="pr-hs"><i>${E(x.f || '')}</i></span>`)).join(''); },
    mqtt() { const it = last(x => x.p === 'TCP' && port(x, 1883, 8883)); if (!it.length) return null;
      return it.map(x => row(x.t, `${pair(x.s, x.d)} <span class="pr-hs"><i class="${port(x, 8883) ? 'g' : 'o'}">${port(x, 8883) ? '8883 TLS' : '1883 ακρυπτογράφητο'}</i></span>`)).join(''); },
    wg() { const it = last(x => x.a === 'WireGuard' || (x.p === 'UDP' && port(x, 51820))); if (!it.length) return null;
      return it.map(x => row(x.t, `${pair(x.s, x.d)} <span class="sm">UDP ${x.sp} → ${x.dp} · ${x.l} B</span>`)).join('') + `<div class="sm pr-sum">Βλέπεις μόνο μεγέθη: το περιεχόμενο είναι κρυπτογραφημένο.</div>`; },
  };
  const HINT = {
    tcp: 'Άνοιξε οποιοδήποτε site — κάθε νέα σύνδεση ξεκινά με handshake.',
    udp: 'Το DNS και το QUIC (YouTube) είναι UDP — άνοιξε ένα βίντεο.',
    dns: 'Άνοιξε ένα site που δεν έχεις επισκεφτεί σήμερα.',
    dhcp: 'Κλείσε και άνοιξε το Wi-Fi σε ένα κινητό: θα δεις το DORA.',
    arp: 'Γράψε <code>arp -d -a</code> (με sudo) στο Terminal, ή περίμενε — γίνεται κάθε λίγα λεπτά.',
    icmp: 'Γράψε στο Terminal: <code>ping -c 4 1.1.1.1</code>',
    trace: 'Γράψε στο Terminal: <code>traceroute -I 1.1.1.1</code>',
    tls: 'Άνοιξε ένα site με https.',
    http: 'Άνοιξε το <code>http://neverssl.com</code> — ένα site που επίτηδες δεν έχει HTTPS.',
    nat: 'Χρειάζεται ζωντανή καταγραφή (Live).',
    quic: 'Άνοιξε ένα βίντεο στο YouTube από Chrome.',
    ssh: 'Συνδέσου με <code>ssh</code> σε ένα Raspberry Pi ή στον Proxmox σου.',
    mqtt: 'Θα εμφανιστεί όταν μιλήσει μια συσκευή IoT με τον broker σου.',
    wg: 'Ενεργοποίησε το WireGuard στο κινητό ή στο laptop σου.',
  };
  function liveHTML() {
    const p = BY[ST.id];
    let body = null; try { body = LIVE[p.id](); } catch (e) { body = null; }
    const demo = typeof S !== 'undefined' && S.mode === 'demo';
    return `<div class="brow"><b class="ctitle">🔴 Στο δικό σου δίκτυο — ${E(p.n)}${demo ? ' <span class="tag">προσομοίωση</span>' : ''}</b><span class="sm">${BUF.length} πακέτα στη μνήμη</span></div>`
      + (body ? `<div class="pr-live">${body}</div>` : `<div class="pr-empty">Δεν έχω δει ακόμα ${E(p.n)} στο δίκτυό σου. <br>💡 ${HINT[p.id]}</div>`);
  }

  function quizHTML() {
    const p = BY[ST.id], q = p.q, a = ST.ans[p.id];
    return `<div class="brow"><b class="ctitle">❓ Γρήγορη ερώτηση</b><span class="sm">${Object.keys(ST.ans).filter(k => BY[k] && ST.ans[k] === BY[k].q.a).length}/${P.length} σωστές</span></div>
      <div style="margin:6px 0 8px;white-space:normal">${E(q.q)}</div><div class="pr-qo">${q.o.map((o, k) => `<button class="b${a != null ? (k === q.a ? ' ok' : k === a ? ' bad' : '') : ''}" data-qa="${k}"${a != null ? ' disabled' : ''}>${E(o)}</button>`).join('')}</div>
      ${a != null ? `<div class="sm" style="margin-top:8px;white-space:normal"><span>${a === q.a ? '✅ Σωστά!' : '❌ Όχι ακριβώς.'}</span> <span>${E(q.w)}</span></div>` : ''}`;
  }

  // ---------------- καρτέλα ----------------
  let liveT = null;
  window.renderProto = () => {
    hook();
    const el = document.getElementById('t-proto'), p = BY[ST.id];
    ST.play = false; clearTimeout(ST.tm);
    el.innerHTML = `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">🎬 Πρωτόκολλα σε κίνηση</b><span class="sm">${P.length} πρωτόκολλα</span></div>
        <div class="sm" style="margin-top:4px">Δες βήμα-βήμα τι ανταλλάσσουν οι συσκευές — και ακριβώς από κάτω, το αληθινό αντίστοιχο από το δικό σου δίκτυο.</div>
        <div class="pr-pills">${P.map(x => `<button class="pr-pill${x.id === ST.id ? ' on' : ''}" data-pp="${x.id}"><span>${x.i}</span>${E(x.n)}${ST.ans[x.id] === x.q.a ? '<i>✓</i>' : ''}</button>`).join('')}</div></div>
      <div class="pr-main"><div class="card pr-diag"><div class="brow"><b class="ctitle">${p.i} ${E(p.n)} <span class="tag">${E(p.L)}</span> <span class="sm">${E(p.k)}</span></b>
          <span class="pr-ctl"><button class="b" data-pc="prev" title="Προηγούμενο">⏮</button><button class="b pr-play" data-pc="play">▶ Αναπαραγωγή</button><button class="b" data-pc="next" title="Επόμενο">⏭</button>
          <select class="f" data-pc="sp" title="Ταχύτητα">${[[.5, '0.5×'], [1, '1×'], [2, '2×']].map(([v, l]) => `<option value="${v}"${v === ST.sp ? ' selected' : ''}>${l}</option>`).join('')}</select></span></div>
          <div class="pr-wrap">${svg(p)}</div></div>
        <div class="card pr-det"></div></div>
      <div class="card" id="pr-live">${liveHTML()}</div>
      <div class="card" id="pr-quiz">${quizHTML()}</div>`;
    el.querySelectorAll('[data-pp]').forEach(b => b.onclick = () => { ST.id = b.dataset.pp; ST.i = -1; save(); renderProto(); });
    el.querySelectorAll('.pr-st').forEach(g => g.onclick = () => { ST.play = false; clearTimeout(ST.tm); stepTo(+g.dataset.st); });
    el.querySelector('[data-pc="play"]').onclick = toggle;
    el.querySelector('[data-pc="prev"]').onclick = () => { ST.play = false; clearTimeout(ST.tm); stepTo(ST.i - 1); };
    el.querySelector('[data-pc="next"]').onclick = () => { ST.play = false; clearTimeout(ST.tm); stepTo(ST.i + 1); };
    el.querySelector('[data-pc="sp"]').onchange = e => { ST.sp = +e.target.value; };
    bindQuiz(el);
    stepTo(ST.i, false);
    clearInterval(liveT);
    liveT = setInterval(() => {
      if (typeof tab !== 'undefined' && tab !== 'proto') { clearInterval(liveT); return; }
      const l = document.getElementById('pr-live'); if (l && !l.matches(':hover')) { l.innerHTML = liveHTML(); if (window.I18N && I18N.apply) try { I18N.apply(l); } catch (e) { } }
    }, 1500);
  };
  function bindQuiz(el) {
    el.querySelectorAll('[data-qa]').forEach(b => b.onclick = () => { ST.ans[ST.id] = +b.dataset.qa; save();
      const q = document.getElementById('pr-quiz'); q.innerHTML = quizHTML(); bindQuiz(q);
      if (ST.ans[ST.id] === BY[ST.id].q.a) { const pill = document.querySelector(`[data-pp="${ST.id}"]`); if (pill && !pill.querySelector('i')) pill.insertAdjacentHTML('beforeend', '<i>✓</i>'); } });
  }
  document.addEventListener('keydown', e => {
    if (typeof tab === 'undefined' || tab !== 'proto' || /INPUT|TEXTAREA|SELECT/.test((document.activeElement || {}).tagName || '')) return;
    if (e.key === 'ArrowRight') { ST.play = false; stepTo(ST.i + 1); e.preventDefault(); }
    else if (e.key === 'ArrowLeft') { ST.play = false; stepTo(ST.i - 1); e.preventDefault(); }
    else if (e.key === ' ' && !e.metaKey) { toggle(); e.preventDefault(); }
  });

  // ---------------- στυλ ----------------
  const css = `
  .pr-pills{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
  .pr-pill{display:inline-flex;align-items:center;gap:6px;padding:6px 11px;border-radius:999px;border:1px solid rgb(var(--w) / 12%);background:rgb(var(--w) / 4%);color:inherit;font:inherit;font-size:13px;cursor:pointer;transition:background .15s,border-color .15s}
  .pr-pill:hover{background:rgb(var(--w) / 9%)}
  .pr-pill.on{border-color:var(--cyan);background:color-mix(in srgb,var(--cyan) 16%,transparent);color:var(--cyan)}
  .pr-pill i{font-style:normal;color:var(--green);font-size:11px}
  .pr-main{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:12px;align-items:start}
  @media (max-width:1100px){.pr-main{grid-template-columns:1fr}}
  .pr-ctl{display:flex;gap:6px;align-items:center}.pr-ctl .f{width:auto}
  .pr-play{min-width:128px}
  .pr-wrap{margin-top:8px;overflow-x:auto}
  .pr-svg{width:100%;min-width:560px;height:auto;display:block}
  .pr-life{stroke:rgb(var(--w) / 14%);stroke-dasharray:3 5}
  .pr-lane{fill:rgb(var(--w) / 6%);stroke:rgb(var(--w) / 14%)}
  .pr-lt{fill:currentColor;font-size:12.5px;font-weight:600}
  .pr-st{cursor:pointer;transition:opacity .25s}
  .pr-st.fut{opacity:.26}.pr-st.done{opacity:.6}
  .pr-hit{fill:transparent}.pr-st:hover .pr-hit{fill:rgb(var(--w) / 4%)}
  .pr-st.cur .pr-hit{fill:color-mix(in srgb,var(--pc) 10%,transparent)}
  .pr-ar{stroke-width:2}.pr-st.cur .pr-ar{stroke-width:2.8}
  .pr-ar.lost{stroke-dasharray:6 5}
  .pr-x{fill:var(--red);font-size:16px;font-weight:700}
  .pr-al{fill:currentColor;font-size:12.5px;font-family:var(--mono,ui-monospace,monospace)}
  .pr-st.cur .pr-al{fill:var(--pc);font-weight:700}
  .pr-n{fill:var(--dim);font-size:10.5px}
  .pr-dot{filter:drop-shadow(0 0 6px currentColor);fill:var(--cyan)}
  .pr-det{position:sticky;top:8px;white-space:normal;min-height:240px}
  .pr-dh{font-weight:700;font-size:15px;margin-bottom:4px}
  .pr-num{font-size:11px;color:var(--dim);font-weight:500;margin-right:4px}
  .pr-way{font-size:12px;color:var(--dim);margin-bottom:10px}
  .pr-fl{width:100%;border-collapse:collapse;margin-bottom:10px;font-size:12.5px}
  .pr-fl td{padding:5px 6px;border-top:1px solid rgb(var(--w) / 8%);vertical-align:top}
  .pr-fl td:first-child{color:var(--dim);white-space:nowrap;width:1%}
  .pr-v{font-family:var(--mono,ui-monospace,monospace);font-size:12px;word-break:break-word;background:rgb(var(--w) / 6%);padding:1px 6px;border-radius:4px}
  .pr-x2{line-height:1.55;font-size:13.5px}
  .pr-hint{margin-top:14px;color:var(--cyan);font-size:13px}
  .pr-live{margin-top:6px}
  .pr-lr{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:6px 0;border-top:1px solid rgb(var(--w) / 6%);font-size:13px;animation:prIn .4s ease}
  html.nomo .pr-lr{animation:none}
  @keyframes prIn{from{opacity:0;transform:translateY(-3px)}to{opacity:1;transform:none}}
  .pr-ago{color:var(--dim);font-size:11px;min-width:30px}
  .pr-arr{color:var(--dim);font-weight:400}
  .pr-hs{display:inline-flex;gap:5px;align-items:center;font-size:12px}
  .pr-hs i{font-style:normal;padding:1px 7px;border-radius:5px;background:color-mix(in srgb,var(--cyan) 16%,transparent);color:var(--cyan);font-family:var(--mono,ui-monospace,monospace);font-size:11.5px}
  .pr-hs i.p{background:color-mix(in srgb,var(--purple) 16%,transparent);color:var(--purple)}
  .pr-hs i.g{background:color-mix(in srgb,var(--green) 16%,transparent);color:var(--green)}
  .pr-hs i.o{background:color-mix(in srgb,var(--orange) 18%,transparent);color:var(--orange)}
  .pr-chips,.pr-hops{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:8px 0}
  .pr-chip{padding:3px 9px;border-radius:999px;background:rgb(var(--w) / 6%);font-size:12px}
  .pr-sum{margin-top:8px;white-space:normal}
  .pr-empty{padding:14px 2px 4px;color:var(--dim);white-space:normal;line-height:1.6}
  .pr-qo{display:flex;flex-wrap:wrap;gap:6px}
  .pr-qo .b.ok{border-color:var(--green);color:var(--green);opacity:1}
  .pr-qo .b.bad{border-color:var(--red);color:var(--red);opacity:1}`;
  const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);
})();
