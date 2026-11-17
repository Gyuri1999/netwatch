// NetWatch Academy — 🔌 IoT Security: ESP32 & Raspberry Pi (English)
// A path from beginner to practical level: hardening, TLS/MQTT, firmware, hardware, segmentation, monitoring.
// Defensive use only, and testing only on YOUR OWN devices. Format: academy/FORMAT.md
(function () {
  'use strict';
  const fx = s => s;  // (the engine now protects the * inside `code`)
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
    intro: 'An IoT device is not just "the little box". See how many places someone can attack from: **hardware, firmware, network, cloud, app**.',
    nodes: [
      { id: 'esp', x: 90, y: 150, icon: '📟', label: 'ESP32\nhardware+firmware' },
      { id: 'ap', x: 250, y: 150, icon: '📶', label: 'Router\nWi‑Fi' },
      { id: 'cloud', x: 420, y: 150, icon: '☁️', label: 'Cloud / Broker' },
      { id: 'app', x: 570, y: 150, icon: '📱', label: 'App' },
      { id: 'att', x: 335, y: 45, icon: '🕵️', label: 'Attacker' },
    ],
    links: [['esp', 'ap', 'wifi'], ['ap', 'cloud'], ['cloud', 'app']],
    steps: [
      { from: 'att', to: 'esp', pkt: 'UART / JTAG', color: RED, mark: { esp: 'hl' }, say: '**Hardware:** exposed UART/JTAG pins, reading the SPI flash with a single USB cable.' },
      { from: 'att', to: 'esp', pkt: 'bad firmware', color: RED, mark: { esp: 'bad' }, say: '**Firmware:** OTA without a signature → the attacker uploads their own code.' },
      { from: 'esp', to: 'ap', pkt: 'MQTT plaintext', color: YEL, mark: { ap: 'hl' }, say: '**Network:** traffic without TLS can be read by anyone on the same Wi‑Fi.' },
      { from: 'att', to: 'cloud', pkt: 'API without auth', color: RED, mark: { cloud: 'bad' }, say: '**Cloud/Broker:** a broker with `allow_anonymous true` or a weak API key.' },
      { from: 'att', to: 'app', pkt: 'token in the APK', color: RED, mark: { app: 'bad' }, say: '**App:** keys "hidden" inside the phone app.' },
      { from: 'esp', via: ['ap'], to: 'cloud', pkt: 'TLS 🔒', color: GREEN, mark: { esp: 'ok', ap: 'ok', cloud: 'ok', app: 'ok' }, say: 'In this track you learn to close **every** layer, not just one.' },
    ],
  });

  ACADEMY.scene('iot-mirai', {
    w: 640, h: 290, speed: 2800,
    intro: '**Mirai (2016):** a botnet that scanned the Internet for Telnet with factory passwords and "recruited" hundreds of thousands of cameras and DVRs.',
    nodes: [
      { id: 'bot', x: 80, y: 60, icon: '🤖', label: 'Bot\nscanner' },
      { id: 'cnc', x: 80, y: 220, icon: '🧠', label: 'C&C server' },
      { id: 'net', x: 260, y: 140, icon: '🌐', label: 'Internet' },
      { id: 'cam1', x: 440, y: 45, icon: '📷', label: 'Camera A\nroot/xc3511' },
      { id: 'cam2', x: 440, y: 140, icon: '📼', label: 'DVR B\nadmin/admin' },
      { id: 'cam3', x: 440, y: 235, icon: '📷', label: 'Camera C\ncustom password' },
      { id: 'vic', x: 585, y: 140, icon: '🏢', label: 'DDoS victim' },
    ],
    links: [['bot', 'net'], ['cnc', 'net'], ['net', 'cam1'], ['net', 'cam2'], ['net', 'cam3'], ['cam1', 'vic'], ['cam2', 'vic'], ['cam3', 'vic']],
    tables: [{ id: 'bots', title: 'Infected devices', head: ['Device', 'Status'], rows: [] }],
    steps: [
      { from: 'bot', via: ['net'], to: ['cam1', 'cam2', 'cam3'], pkt: 'SYN :23', color: YEL, say: 'The bot sends SYN to random IPs on port **23 (Telnet)** and **2323**.' },
      { from: 'bot', via: ['net'], to: 'cam1', pkt: 'root/xc3511', color: RED, mark: { cam1: 'bad' }, table: { bots: [['Camera A', '🦠 infected']] }, say: 'It tries a list of ~60 factory passwords. Camera A accepts the first one.' },
      { from: 'bot', via: ['net'], to: 'cam2', pkt: 'admin/admin', color: RED, mark: { cam2: 'bad' }, table: { bots: [['Camera A', '🦠 infected'], ['DVR B', '🦠 infected']] }, say: 'DVR B still has `admin/admin`. It downloads the malware and becomes a scanner too.' },
      { from: 'bot', via: ['net'], to: 'cam3', pkt: 'admin/admin', color: RED, drop: true, mark: { cam3: 'ok' }, say: 'Camera C has a **unique password** and Telnet closed → the attack fails.' },
      { from: 'cam1', via: ['net'], to: 'cnc', pkt: 'report', color: PURP, say: 'The infected devices "report in" to the C&C (command & control).' },
      { from: 'cnc', via: ['net'], to: ['cam1', 'cam2'], pkt: 'ATTACK!', color: RED, say: 'The operator orders an attack from the whole botnet.' },
      { from: 'cam1', to: 'vic', pkt: 'flood', color: RED, mark: { vic: 'bad' }, say: 'Each camera sends a little traffic…' },
      { from: 'cam2', to: 'vic', pkt: 'flood', color: RED, say: '…but 600,000 cameras together took down Dyn DNS, and with it Twitter, Netflix and GitHub (Oct. 2016).' },
    ],
  });

  ACADEMY.scene('iot-ssh-bruteforce', {
    w: 640, h: 280, speed: 2600,
    intro: 'A Raspberry Pi with SSH open to the Internet receives **thousands** of login attempts a day. See how **fail2ban** cuts them off.',
    nodes: [
      { id: 'att', x: 80, y: 110, icon: '🕵️', label: 'Bot\n203.0.113.66' },
      { id: 'rt', x: 260, y: 110, icon: '📶', label: 'Router' },
      { id: 'pi', x: 470, y: 110, icon: '🍓', label: 'Raspberry Pi\nsshd + fail2ban' },
      { id: 'me', x: 260, y: 225, icon: '💻', label: 'You\ned25519 key' },
    ],
    links: [['att', 'rt'], ['rt', 'pi'], ['me', 'rt']],
    tables: [
      { id: 'log', title: 'journal (sshd)', head: ['IP', 'Result'], rows: [] },
      { id: 'ban', title: 'fail2ban: jail sshd', head: ['Banned IP', 'For'], rows: [] },
    ],
    steps: [
      { from: 'att', via: ['rt'], to: 'pi', pkt: 'pi / raspberry', color: RED, table: { log: [['203.0.113.66', 'Failed password']] }, say: 'First try: the old default user `pi` with password `raspberry`.' },
      { from: 'att', via: ['rt'], to: 'pi', pkt: 'admin / 123456', color: RED, table: { log: [['203.0.113.66', 'Failed password'], ['203.0.113.66', 'Invalid user admin']] }, say: 'Second: `admin/123456`. Failure.' },
      { from: 'att', via: ['rt'], to: 'pi', pkt: 'root / toor', color: RED, mark: { pi: 'hl' }, table: { log: [['203.0.113.66', 'Failed password'], ['203.0.113.66', 'Invalid user admin'], ['203.0.113.66', 'Failed password']] }, say: 'Third failure within 10 minutes → we have reached `maxretry = 3`.' },
      { from: 'pi', to: 'pi', pkt: '', mark: { att: 'bad' }, table: { ban: [['203.0.113.66', '1 hour']] }, say: 'fail2ban reads the log, sees 3 failures and adds a firewall rule: **ban for 1 hour**.' },
      { from: 'att', via: ['rt'], to: 'pi', pkt: 'SYN :22', color: RED, drop: true, say: 'Every new attempt from this IP is cut at the firewall, before it reaches sshd.' },
      { from: 'me', via: ['rt'], to: 'pi', pkt: 'ssh key ✓', color: GREEN, mark: { me: 'ok', pi: 'ok' }, say: 'You get in with a **key**. With `PasswordAuthentication no`, the bot\'s passwords would never work.' },
    ],
  });

  ACADEMY.scene('iot-evil-twin', {
    w: 640, h: 280, speed: 2800,
    intro: '**Evil twin:** a fake access point with the same SSID. What happens when your ESP32 connects to it?',
    nodes: [
      { id: 'esp', x: 80, y: 140, icon: '📟', label: 'ESP32' },
      { id: 'ap', x: 300, y: 55, icon: '📶', label: 'HomeWiFi\nthe real one' },
      { id: 'evil', x: 300, y: 225, icon: '😈', label: 'HomeWiFi\nthe fake one' },
      { id: 'pi', x: 530, y: 55, icon: '🍓', label: 'Broker\n:8883' },
      { id: 'att', x: 530, y: 225, icon: '🕵️', label: 'Attacker\'s\nlaptop' },
    ],
    links: [['esp', 'ap', 'wifi'], ['esp', 'evil', 'wifi'], ['ap', 'pi'], ['evil', 'att']],
    steps: [
      { from: 'esp', to: 'ap', pkt: 'WPA2 ✓', color: GREEN, mark: { esp: 'ok' }, say: 'The ESP32 is connected normally to the real network.' },
      { from: 'att', via: ['evil'], to: 'esp', pkt: 'deauth ×100', color: RED, mark: { esp: 'hl' }, say: 'The attacker sends **deauthentication** frames. Without PMF (802.11w) the device disconnects.' },
      { from: 'esp', to: 'evil', pkt: 'probe HomeWiFi', color: YEL, say: 'The ESP32 looks for "HomeWiFi" again and sees a stronger signal from the fake AP.' },
      { from: 'evil', to: 'esp', pkt: '4-way handshake', color: RED, drop: true, mark: { evil: 'hl' }, say: 'With **WPA2/WPA3 and a strong PSK** the fake AP does not know the password → the handshake fails.' },
      { from: 'evil', to: 'esp', pkt: 'handshake ✓', color: RED, mark: { evil: 'bad', esp: 'bad' }, say: 'But if the password **leaked** (e.g. hardcoded on GitHub), the fake AP knows it and the ESP32 connects.' },
      { from: 'esp', via: ['evil'], to: 'att', pkt: 'TLS ClientHello', color: BLUE, say: 'Now all the traffic passes through the attacker\'s laptop. But the ESP32 speaks **TLS** with CA verification.' },
      { from: 'att', via: ['evil'], to: 'esp', pkt: 'fake cert', color: RED, drop: true, mark: { esp: 'ok' }, say: 'The attacker has no certificate signed by your own CA → the ESP32 **closes the connection**. Defense in depth!' },
    ],
  });

  ACADEMY.scene('iot-mqtt-pubsub', {
    w: 640, h: 280, speed: 2500,
    intro: '**MQTT = publish/subscribe.** Devices do not talk to each other directly; everything goes through the **broker** (e.g. Mosquitto on the Pi).',
    nodes: [
      { id: 'e1', x: 85, y: 60, icon: '🌡️', label: 'ESP32 #1\nDHT22' },
      { id: 'e2', x: 85, y: 215, icon: '💡', label: 'ESP32 #2\nrelay' },
      { id: 'br', x: 320, y: 140, icon: '🍓', label: 'Mosquitto\nRaspberry Pi' },
      { id: 'dash', x: 555, y: 60, icon: '📊', label: 'Dashboard' },
      { id: 'ph', x: 555, y: 215, icon: '📱', label: 'Phone' },
    ],
    links: [['e1', 'br', 'wifi'], ['e2', 'br', 'wifi'], ['br', 'dash'], ['br', 'ph', 'wifi']],
    tables: [{ id: 'subs', title: 'Subscriptions on the broker', head: ['Client', 'Topic'], rows: [] }],
    steps: [
      { from: 'dash', to: 'br', pkt: 'SUB home/+/temp', color: BLUE, table: { subs: [['dashboard', 'home/+/temp']] }, say: 'The dashboard **subscribes** to `home/+/temp`. The `+` matches exactly one level.' },
      { from: 'e2', to: 'br', pkt: 'SUB home/relay/set', color: BLUE, table: { subs: [['dashboard', 'home/+/temp'], ['esp32-2', 'home/relay/set']] }, say: 'ESP32 #2 listens for commands on `home/relay/set`.' },
      { from: 'e1', to: 'br', pkt: 'PUB 22.5°C', color: GREEN, say: 'ESP32 #1 **publishes** to `home/esp1/temp`. It does not know who is listening.' },
      { from: 'br', to: 'dash', pkt: '22.5°C', color: GREEN, mark: { dash: 'ok' }, say: 'The broker forwards it to everyone with a matching subscription.' },
      { from: 'ph', to: 'br', pkt: 'PUB relay/set ON', color: YEL, say: 'The phone sends `ON` to `home/relay/set`.' },
      { from: 'br', to: 'e2', pkt: 'ON', color: YEL, mark: { e2: 'hl' }, say: 'The relay switches on. A security question: **who** is allowed to write to this topic? We will solve it with an ACL.' },
    ],
  });

  ACADEMY.scene('iot-mqtt-sniff', {
    w: 640, h: 280, speed: 2700,
    intro: 'The same MQTT message, first **without** TLS (port 1883) and then **with** TLS (port 8883). What does someone on the same network see?',
    nodes: [
      { id: 'esp', x: 80, y: 110, icon: '📟', label: 'ESP32' },
      { id: 'ap', x: 250, y: 110, icon: '📶', label: 'Wi‑Fi' },
      { id: 'br', x: 560, y: 110, icon: '🍓', label: 'Mosquitto' },
      { id: 'att', x: 405, y: 225, icon: '🕵️', label: 'Attacker\non the same LAN' },
    ],
    links: [['esp', 'ap', 'wifi'], ['ap', 'br'], ['ap', 'att', 'wifi']],
    tables: [{ id: 'cap', title: 'What the attacker "catches" (tcpdump)', head: ['Port', 'Content'], rows: [] }],
    steps: [
      { from: 'esp', via: ['ap'], to: 'br', pkt: 'CONNECT :1883', color: YEL, say: 'The ESP32 connects **without TLS** using a username/password.' },
      { from: 'ap', to: 'att', pkt: 'copy', color: RED, mark: { att: 'bad' }, table: { cap: [['1883', 'user=sensor01 pass=Kalimera2024']] }, say: 'The attacker sees the password **in the clear** inside the CONNECT packet.' },
      { from: 'esp', via: ['ap'], to: 'br', pkt: 'temp=22.5', color: YEL, table: { cap: [['1883', 'user=sensor01 pass=Kalimera2024'], ['1883', 'home/esp1/temp 22.5']] }, say: 'And every reading, and every command.' },
      { from: 'att', via: ['ap'], to: 'br', pkt: 'PUB relay ON', color: RED, mark: { br: 'bad' }, say: 'With the stolen credentials they connect as `sensor01` and send commands. 💥' },
      { from: 'esp', via: ['ap'], to: 'br', pkt: 'TLS :8883 🔒', color: GREEN, mark: { br: 'ok', esp: 'ok' }, say: 'Now with **TLS** on port 8883 and your own CA.' },
      { from: 'ap', to: 'att', pkt: '17 03 03 9f e2…', color: PURP, table: { cap: [['8883', '17 03 03 00 4a 9f e2 1c 7b … (encrypted)']] }, say: 'The attacker sees only **encrypted bytes** (TLS records). No password, no data.' },
      { from: 'att', via: ['ap'], to: 'br', pkt: 'CONNECT :1883', color: RED, drop: true, say: 'Port 1883 is closed to the LAN (localhost only) → the connection is cut.' },
    ],
  });

  ACADEMY.scene('iot-tls-handshake', {
    w: 640, h: 270, speed: 2700,
    intro: 'The **TLS 1.2/1.3 handshake**, simplified: how the ESP32 makes sure it is talking to **your own** broker.',
    nodes: [
      { id: 'esp', x: 100, y: 100, icon: '📟', label: 'ESP32\nhas ca.crt' },
      { id: 'br', x: 540, y: 100, icon: '🍓', label: 'Mosquitto\nserver.crt+key' },
      { id: 'att', x: 320, y: 215, icon: '🕵️', label: 'MITM' },
    ],
    links: [['esp', 'br'], ['esp', 'att'], ['att', 'br']],
    tables: [{ id: 'chk', title: 'ESP32 checks', head: ['Check', 'Result'], rows: [] }],
    steps: [
      { from: 'esp', to: 'br', pkt: 'ClientHello', color: BLUE, say: '**ClientHello:** TLS versions, cipher suites, SNI (the server name) and a random nonce.' },
      { from: 'br', to: 'esp', pkt: 'ServerHello + cert', color: YEL, say: 'The broker replies and sends its **certificate** (`server.crt`).' },
      { from: 'esp', to: 'esp', pkt: '', mark: { esp: 'hl' }, table: { chk: [['Signed by my CA?', '✅'], ['Name/SAN matches?', '✅'], ['Dates (if checked)', '✅']] }, say: 'The ESP32 checks the **signature** with the `ca.crt` it carries, and that the server **name** is in the SAN.' },
      { from: 'esp', to: 'br', pkt: 'ECDHE key share', color: PURP, say: '**Key exchange (ECDHE):** the two sides create a shared secret without ever sending it over the network.' },
      { from: 'br', to: 'esp', pkt: 'Finished 🔒', color: GREEN, mark: { esp: 'ok', br: 'ok' }, say: 'From here on everything is encrypted (AES-GCM or ChaCha20).' },
      { from: 'esp', to: 'br', pkt: 'MQTT CONNECT 🔒', color: GREEN, say: 'The MQTT username/password now travels **inside** the tunnel.' },
      { from: 'att', to: 'esp', pkt: 'self-signed cert', color: RED, drop: true, mark: { att: 'bad' }, table: { chk: [['Signed by my CA?', '❌ unknown CA'], ['Result', 'connection cut']] }, say: 'A MITM with their own certificate **fails**, unless you used `setInsecure()`… which you never will.' },
    ],
  });

  ACADEMY.scene('iot-secure-boot', {
    w: 640, h: 270, speed: 2800,
    intro: '**Secure Boot v2:** each boot stage checks the **digital signature** of the next one. The root of trust is a hash in the **eFuses**.',
    nodes: [
      { id: 'ef', x: 90, y: 50, icon: '🔥', label: 'eFuse\npublic key hash' },
      { id: 'rom', x: 90, y: 185, icon: '🧱', label: 'ROM bootloader\n(immutable)' },
      { id: 'bl', x: 270, y: 185, icon: '🥾', label: '2nd stage\nbootloader' },
      { id: 'app', x: 440, y: 185, icon: '📦', label: 'App\nfirmware' },
      { id: 'run', x: 580, y: 185, icon: '✅', label: 'Runs' },
      { id: 'att', x: 440, y: 50, icon: '🕵️', label: 'evil.bin\nunsigned' },
    ],
    links: [['ef', 'rom'], ['rom', 'bl'], ['bl', 'app'], ['app', 'run'], ['att', 'app']],
    steps: [
      { from: 'ef', to: 'rom', pkt: 'SHA-256(pubkey)', color: PURP, mark: { ef: 'info' }, say: 'The hash of your public key is burned **permanently** into the eFuse. It never changes.' },
      { from: 'rom', to: 'bl', pkt: 'verify RSA-PSS', color: BLUE, mark: { rom: 'ok', bl: 'ok' }, say: 'The ROM loads the bootloader, checks that the key in the signature block matches the hash and that the **signature** is correct.' },
      { from: 'bl', to: 'app', pkt: 'verify ✓', color: BLUE, mark: { app: 'ok' }, say: 'The bootloader does the same for the app image.' },
      { from: 'app', to: 'run', pkt: 'boot', color: GREEN, mark: { run: 'ok' }, say: 'The whole chain is signed by **you** → the firmware runs.' },
      { from: 'att', to: 'app', pkt: 'flash evil.bin', color: RED, mark: { app: 'bad', att: 'bad' }, say: 'Someone writes different firmware to the flash (via UART or OTA).' },
      { from: 'bl', to: 'app', pkt: 'verify ✗', color: RED, drop: true, mark: { run: 'bad' }, say: 'The signature does not match → the bootloader **refuses** to start it. The attacker cannot run their own code.' },
    ],
  });

  ACADEMY.scene('iot-ota-signed', {
    w: 640, h: 280, speed: 2700,
    intro: '**OTA (Over-The-Air) updates:** convenient, but also the easiest door for malicious firmware if you do not check **who** made the update.',
    nodes: [
      { id: 'dev', x: 85, y: 60, icon: '👩‍💻', label: 'You\nsigning key' },
      { id: 'srv', x: 320, y: 60, icon: '🗄️', label: 'OTA server\nHTTPS' },
      { id: 'esp', x: 550, y: 140, icon: '📟', label: 'ESP32' },
      { id: 'att', x: 320, y: 225, icon: '🕵️', label: 'Attacker\non the LAN' },
    ],
    links: [['dev', 'srv'], ['srv', 'esp'], ['att', 'esp', 'wifi']],
    steps: [
      { from: 'att', to: 'esp', pkt: 'ArduinoOTA :3232', color: RED, mark: { esp: 'bad' }, say: '❌ **No OTA password:** anyone on the same LAN uploads firmware to port 3232. The device is now theirs.' },
      { from: 'dev', to: 'srv', pkt: 'app.bin + signature', color: PURP, mark: { esp: '' }, say: '✅ You sign `app.bin` with the **private** key (which never leaves your computer).' },
      { from: 'esp', to: 'srv', pkt: 'HTTPS GET', color: BLUE, say: 'The ESP32 downloads the update over **HTTPS**, checking the server\'s certificate.' },
      { from: 'srv', to: 'esp', pkt: 'signed app.bin', color: GREEN, mark: { esp: 'ok' }, say: 'Before marking the new partition as "active", it checks the **signature** with the public key → ✓ → reboot.' },
      { from: 'att', to: 'esp', pkt: 'evil.bin', color: RED, drop: true, mark: { att: 'bad' }, say: 'The attacker sends firmware without a valid signature → **rejected**. The ESP32 stays on the old, good version.' },
      { from: 'srv', to: 'esp', pkt: 'old v1.0', color: YEL, drop: true, say: 'With **anti-rollback**, even an old (signed but vulnerable) version is rejected.' },
    ],
  });

  ACADEMY.scene('iot-uart-dump', {
    w: 640, h: 260, speed: 2800,
    intro: 'A defensive look: what someone who **holds** your device can do with a USB cable and `esptool`. (Try it only on your own ESP32.)',
    nodes: [
      { id: 'pc', x: 80, y: 110, icon: '💻', label: 'Laptop\nesptool' },
      { id: 'usb', x: 230, y: 110, icon: '🔌', label: 'USB‑UART' },
      { id: 'esp', x: 390, y: 110, icon: '📟', label: 'ESP32' },
      { id: 'fl', x: 555, y: 110, icon: '💾', label: 'SPI flash\n4MB' },
    ],
    links: [['pc', 'usb'], ['usb', 'esp', 'TX/RX'], ['esp', 'fl', 'SPI']],
    tables: [{ id: 'str', title: 'strings dump.bin | grep …', head: ['Found', 'Value'], rows: [] }],
    steps: [
      { from: 'pc', via: ['usb'], to: 'esp', pkt: 'GPIO0=LOW + RST', color: YEL, mark: { esp: 'hl' }, say: 'With GPIO0 held LOW at boot, the ESP32 enters **UART download mode** (the ROM).' },
      { from: 'esp', to: 'fl', pkt: 'read_flash', color: BLUE, say: '`esptool read_flash 0 0x400000 dump.bin` → the ROM reads the whole flash.' },
      { from: 'fl', via: ['esp', 'usb'], to: 'pc', pkt: 'dump.bin', color: RED, mark: { pc: 'bad' }, table: { str: [['SSID', 'HomeWiFi'], ['Wi‑Fi pass', 'MyS3cretPass!'], ['MQTT pass', 'sensor01:Kalimera2024']] }, say: 'Without flash encryption, a simple search finds **Wi‑Fi and MQTT passwords and keys** in plain text.' },
      { from: 'fl', via: ['esp', 'usb'], to: 'pc', pkt: 'dump.bin 🔒', color: PURP, mark: { pc: '', fl: 'ok' }, table: { str: [['SSID', '—'], ['Wi‑Fi pass', '—'], ['content', '9f e2 1c 7b 03 a8 … (noise)']] }, say: 'With **Flash Encryption** the dump is encrypted with a key that lives only in the chip\'s eFuses.' },
      { from: 'pc', via: ['usb'], to: 'esp', pkt: 'read_flash', color: RED, drop: true, mark: { esp: 'ok' }, say: 'With **Secure Download Mode** or UART download disabled, the ROM does not even accept a read command.' },
    ],
  });

  ACADEMY.scene('iot-vlan-segmentation', {
    w: 640, h: 290, speed: 2700,
    intro: 'The home split into **two networks**: VLAN 10 (laptops, NAS) and VLAN 30 (IoT). The router/firewall decides what gets through.',
    nodes: [
      { id: 'lap', x: 80, y: 60, icon: '💻', label: 'Laptop\nVLAN 10' },
      { id: 'nas', x: 80, y: 205, icon: '🗄️', label: 'NAS\nVLAN 10' },
      { id: 'fw', x: 310, y: 130, icon: '🧱', label: 'Router\nfirewall' },
      { id: 'pi', x: 310, y: 235, icon: '🍓', label: 'Pi broker\nVLAN 30' },
      { id: 'cam', x: 545, y: 60, icon: '📷', label: 'Camera\nVLAN 30' },
      { id: 'esp', x: 545, y: 205, icon: '📟', label: 'ESP32\nVLAN 30' },
    ],
    links: [['lap', 'fw', 'VLAN 10'], ['nas', 'fw'], ['fw', 'cam', 'VLAN 30'], ['fw', 'esp', 'wifi'], ['fw', 'pi']],
    tables: [{ id: 'fw', title: 'Firewall rules', head: ['From → To', 'Action'], rows: [['IoT → LAN', 'DROP'], ['IoT → broker:8883', 'ACCEPT'], ['LAN → IoT', 'ACCEPT'], ['IoT → Internet', 'only what is needed']] }],
    steps: [
      { from: 'cam', to: 'cam', pkt: '', mark: { cam: 'bad' }, say: 'The cheap camera has a vulnerability and is now controlled by an attacker.' },
      { from: 'cam', via: ['fw'], to: 'lap', pkt: 'scan :445', color: RED, drop: true, mark: { fw: 'ok' }, say: 'It tries to scan the laptop (SMB). The firewall: **IoT → LAN = DROP**.' },
      { from: 'cam', via: ['fw'], to: 'nas', pkt: 'brute :22', color: RED, drop: true, mark: { nas: 'ok', lap: 'ok' }, say: 'Same for the NAS. The damage stays **contained** in VLAN 30.' },
      { from: 'esp', via: ['fw'], to: 'pi', pkt: 'MQTT TLS :8883', color: GREEN, mark: { esp: 'ok', pi: 'ok' }, say: 'The ESP32 reaches the broker normally: an explicit ACCEPT rule for port 8883 only.' },
      { from: 'lap', via: ['fw'], to: 'cam', pkt: 'RTSP :554', color: BLUE, say: 'The laptop **can** open the camera stream (LAN → IoT), and the replies come back as *established*.' },
      { from: 'cam', via: ['fw'], to: 'lap', pkt: 'RTSP reply', color: BLUE, say: 'Stateful firewall: it allows the reply because the connection **started** from the LAN, not from the camera.' },
    ],
  });

  ACADEMY.scene('iot-arp-spoof', {
    w: 640, h: 280, speed: 2700,
    intro: '**ARP spoofing:** the attacker lies "the router\'s IP is at my MAC". Your Pi, listening to ARP with scapy, catches it.',
    nodes: [
      { id: 'rt', x: 320, y: 50, icon: '📶', label: 'Router\n192.168.1.1' },
      { id: 'esp', x: 110, y: 215, icon: '📟', label: 'ESP32\n.42' },
      { id: 'pi', x: 320, y: 215, icon: '🍓', label: 'Pi IDS\nscapy' },
      { id: 'att', x: 530, y: 215, icon: '🕵️', label: 'Attacker\n.66' },
    ],
    links: [['rt', 'esp', 'wifi'], ['rt', 'pi'], ['rt', 'att', 'wifi']],
    tables: [{ id: 'arp', title: 'What the Pi has learned (IP → MAC)', head: ['IP', 'MAC', 'Status'], rows: [['192.168.1.1', 'a4:2b:b0:11:22:33', 'baseline']] }],
    steps: [
      { from: 'rt', to: ['esp', 'pi', 'att'], pkt: 'ARP .1 is-at a4:2b…', color: BLUE, say: 'Normally: the router announces its MAC. The Pi keeps it as the **baseline**.' },
      { from: 'att', to: ['esp', 'pi'], pkt: '.1 is-at de:ad:be:ef…', color: RED, mark: { att: 'hl' }, say: 'The attacker sends **gratuitous ARP replies**: "I am .1".' },
      { from: 'pi', to: 'pi', pkt: '', mark: { pi: 'hl' }, table: { arp: [['192.168.1.1', 'a4:2b:b0:11:22:33', 'baseline'], ['192.168.1.1', 'de:ad:be:ef:00:66', '⚠️ CHANGED!']] }, say: 'The script sees that the gateway IP changed MAC → **suspicious**.' },
      { from: 'att', to: 'esp', pkt: '.1 is-at de:ad… (×50)', color: RED, mark: { att: 'bad', esp: 'hl' }, say: 'Repeats every 1–2 seconds are the classic "fingerprint" of tools like arpspoof.' },
      { from: 'pi', via: ['rt'], to: 'esp', pkt: '🚨 alert', color: YEL, say: 'The Pi sends an alert (MQTT/Telegram) and logs the event. The ESP32\'s traffic is already **TLS**, so the MITM reads nothing.' },
    ],
  });

  ACADEMY.scene('iot-heartbeat', {
    w: 640, h: 250, speed: 2500,
    intro: 'How do you know a sensor is **alive** and **behaving normally**? Heartbeat + Last Will + a small monitoring service on the Pi.',
    nodes: [
      { id: 'esp', x: 90, y: 110, icon: '📟', label: 'ESP32\nsensor01' },
      { id: 'br', x: 320, y: 110, icon: '🍓', label: 'Mosquitto' },
      { id: 'mon', x: 550, y: 110, icon: '🩺', label: 'monitor.py' },
    ],
    links: [['esp', 'br', 'wifi'], ['br', 'mon']],
    tables: [{ id: 'st', title: 'monitor.py', head: ['Device', 'Last seen', 'Status'], rows: [] }],
    steps: [
      { from: 'esp', to: 'br', pkt: 'CONNECT + LWT', color: PURP, say: 'In CONNECT the ESP32 declares a **Last Will**: "if I disappear, publish `offline` to `home/sensor01/status`".' },
      { from: 'esp', via: ['br'], to: 'mon', pkt: '♥ uptime=60 rssi=-61', color: GREEN, table: { st: [['sensor01', '1s ago', '🟢 online']] }, say: 'Every 60s: a heartbeat with uptime, RSSI, free memory and reset reason.' },
      { from: 'esp', via: ['br'], to: 'mon', pkt: '♥ heap 31k↓ rssi=-88', color: YEL, mark: { esp: 'hl' }, table: { st: [['sensor01', '1s ago', '🟡 anomaly: RSSI −27dB']] }, say: 'RSSI dropped sharply and memory is shrinking → a possible problem (or evil twin / jamming). The monitor flags it.' },
      { from: 'esp', to: 'br', pkt: '✂ power', color: RED, drop: true, mark: { esp: 'bad' }, say: 'Someone unplugged the device. It no longer sends anything.' },
      { from: 'br', to: 'mon', pkt: 'LWT: offline', color: RED, mark: { mon: 'hl' }, table: { st: [['sensor01', '95s ago', '🔴 offline (LWT)']] }, say: 'After the keepalive timeout the broker publishes the **Last Will** → the monitor raises an alert.' },
    ],
  });

  ACADEMY.scene('iot-final-flow', {
    w: 640, h: 280, speed: 2600,
    intro: 'The final project: **DHT22 → ESP32 → MQTT over TLS → Mosquitto on the Pi → dashboard**, with security at every step.',
    nodes: [
      { id: 'dht', x: 60, y: 140, icon: '🌡️', label: 'DHT22' },
      { id: 'esp', x: 170, y: 140, icon: '📟', label: 'ESP32\nsecrets+CA' },
      { id: 'ap', x: 290, y: 140, icon: '📶', label: 'IoT SSID\nWPA2/3' },
      { id: 'br', x: 420, y: 140, icon: '🍓', label: 'Pi :8883\nACL' },
      { id: 'db', x: 570, y: 55, icon: '📊', label: 'Dashboard\n127.0.0.1' },
      { id: 'me', x: 570, y: 225, icon: '💻', label: 'You\nSSH tunnel' },
    ],
    links: [['dht', 'esp', '1‑wire'], ['esp', 'ap', 'wifi'], ['ap', 'br'], ['br', 'db'], ['db', 'me'], ['br', 'me']],
    steps: [
      { from: 'dht', to: 'esp', pkt: '22.4°C 48%', color: BLUE, say: 'The ESP32 reads the DHT22 and **validates** the values (NaN, limits).' },
      { from: 'esp', via: ['ap'], to: 'br', pkt: 'TLS + user/pass', color: GREEN, mark: { esp: 'ok', ap: 'ok' }, say: 'Connecting through a separate IoT network, TLS with your own CA, a unique user per device.' },
      { from: 'esp', via: ['ap'], to: 'br', pkt: 'PUB home/sensor01/state', color: GREEN, mark: { br: 'ok' }, say: 'The ACL lets `sensor01` write **only** under `home/sensor01/`.' },
      { from: 'br', to: 'db', pkt: '{"t":22.4,"h":48}', color: BLUE, mark: { db: 'ok' }, say: 'The dashboard (a read-only user) stores to SQLite and serves a page with autoescape.' },
      { from: 'me', to: 'db', pkt: 'ssh -L 8080', color: PURP, mark: { me: 'ok' }, say: 'You see the dashboard through an **SSH tunnel**: it is not open to anyone else.' },
    ],
  });

  const M = [];

  // ====================================================================
  // MODULE 1 — What IoT is and why it gets hacked
  // ====================================================================
  M.push({
    id: 'iot-1', order: 1, title: 'What IoT is and why it gets hacked',
    desc: 'Attack surface, the OWASP IoT Top 10 and Mirai: why a "simple" ESP32 is a target.',
    lessons: [
      {
        id: 'iot-1-1', title: 'IoT, attack surface and the OWASP IoT Top 10', minutes: 14,
        goal: 'Understand **how many places** someone can attack an IoT device from, and learn the 10 most common mistakes (OWASP IoT Top 10).',
        blocks: [
          text(
            '**IoT (Internet of Things)** means any device that is not a "computer" but has a processor and a network connection: the temperature sensor with an ESP32, the camera, the smart plug, the Raspberry Pi that controls the watering.',
            '',
            'The reason they get hacked so often is simple:',
            '- They are **cheap** and built quickly, so security is left "for later".',
            '- They run **24/7** and nobody looks at them (there is no screen to show you that something is going wrong).',
            '- They rarely get **updates**.',
            '- They sit on the **same network** as your laptop, so they are a perfect stepping stone for an attack further in.',
            '',
            '### Attack surface: the 5 "doors"',
            'The **attack surface** is the sum of all the points where someone could get in. In IoT it is much bigger than you think:'
          ),
          table(['Layer', 'Example attack', 'Defense (in which module)'], [
            ['**Hardware**', 'UART/JTAG pins, reading the SPI flash with `esptool`', 'Flash encryption, disable JTAG (Mod. 5–6)'],
            ['**Firmware**', 'OTA without a signature, hardcoded passwords', 'Secure Boot, signed OTA, secrets kept out of the code (Mod. 3, 5)'],
            ['**Network**', 'MQTT/HTTP without TLS, Telnet, UPnP', 'TLS, firewall, segmentation (Mod. 4, 7)'],
            ['**Cloud/Backend**', 'Broker with anonymous access, weak APIs', 'Auth, ACL, least privilege (Mod. 4)'],
            ['**App/User**', 'Keys inside the app, default passwords', 'Unique credentials, provisioning (Mod. 2–3)'],
          ]),
          anim('iot-attack-surface', 'Press ▶: the attacker tries every layer. **One** open layer is enough to lose the device.'),
          text(
            '### OWASP IoT Top 10 (2018)',
            'The **OWASP** organization collected the most common mistakes in IoT devices. It works like a checklist: if you avoid all 10, you are already better off than most commercial devices.'
          ),
          table(['#', 'Risk', 'What it means in practice for ESP32/Pi'], [
            ['I1', 'Weak, guessable or hardcoded passwords', '`pi/raspberry`, the Wi‑Fi password inside the `.ino` on GitHub'],
            ['I2', 'Insecure network services', 'Telnet, SSH with a password, MQTT 1883 open to everyone'],
            ['I3', 'Insecure ecosystem interfaces', 'Web panel/API/cloud without auth or without TLS'],
            ['I4', 'Lack of secure update mechanism', 'OTA without a password or signature, no updates on the Pi'],
            ['I5', 'Use of insecure or outdated components', 'Old Arduino core / ESP-IDF, old libraries'],
            ['I6', 'Insufficient privacy protection', 'A sensor that sends data to third parties for no reason'],
            ['I7', 'Insecure data transfer and storage', 'Plaintext MQTT, passwords in flash without encryption'],
            ['I8', 'Lack of device management', 'You do not know which devices you have or which version they run'],
            ['I9', 'Insecure default settings', '`allow_anonymous true`, `setInsecure()`, debug left on'],
            ['I10', 'Lack of physical hardening', 'Open UART, JTAG, no flash encryption'],
          ]),
          tip('Keep this table. In the **final project** (Mod. 9) we will build a checklist where each line maps to one of these.'),
          warn(
            '**Rule of this track:** everything you will see (scanning, sniffing, reading flash) you do **only on your own devices and your own network**. On other people\'s systems it is illegal, even if you are "just looking".'
          ),
          quiz('The Wi‑Fi password is written inside `main.ino`, which was uploaded to a public GitHub repo. Which OWASP IoT Top 10 category does it mainly belong to?',
            ['I1: Weak, guessable or hardcoded passwords', 'I6: Insufficient privacy protection', 'I10: Lack of physical hardening', 'I5: Outdated components'], 0,
            'It is a **hardcoded credential**. Anyone who finds the repo (and there are bots that scan GitHub for passwords within minutes) knows your network password.'),
          quiz('Which of the following belongs to the **hardware** attack surface?',
            ['MQTT without TLS', 'The exposed UART/JTAG pins on the board', 'The cloud API', 'The SSH password'], 1,
            'UART/JTAG are physical interfaces: someone needs to have the device in their hands, but then they can read or write the firmware.'),
        ],
      },
      {
        id: 'iot-1-2', title: 'Mirai: how default passwords took down half the Internet', minutes: 15,
        goal: 'Understand step by step how **Mirai** worked, and check **your own** network for the same mistakes (Telnet, default passwords) with `nmap` and Python.',
        blocks: [
          text(
            'In September–October 2016 **Mirai** appeared. It did not use any clever vulnerability. It did something very simple:',
            '1. It scanned random Internet IPs on ports **23 and 2323 (Telnet)**.',
            '1. It tried a list of **~60 factory passwords** (`root/xc3511`, `admin/admin`, `root/vizxv`…).',
            '1. Wherever it got in, it downloaded the malware, and the device became **a scanner too**.',
            '1. The whole botnet waited for commands from a **C&C server** to launch DDoS attacks.',
            '',
            'On October 21, 2016 an attack on the DNS provider **Dyn** made sites like Twitter, Netflix, Reddit and GitHub unreachable for hours. Behind it were hundreds of thousands of cameras and DVRs.'
          ),
          anim('iot-mirai', 'Press ▶ and see why camera C, with a **unique password and Telnet closed**, got away.'),
          text(
            '### The lessons of Mirai',
            '- **No default passwords.** A unique, strong password for every device (or better: keys).',
            '- **No unnecessary services.** Telnet has no place on a 2026 device.',
            '- **Nothing exposed to the Internet** without a reason (port forwarding, UPnP).',
            '- After a reboot Mirai disappeared (it lived only in RAM), but the device was reinfected within minutes, because the mistake was still there.',
            '',
            '### Check your own network',
            'Let\'s search **your own** LAN for devices with ports that IoT usually uses: Telnet, HTTP panels, MQTT without TLS, RTSP (cameras).'
          ),
          code('bash', 'Scanning your OWN LAN with nmap (from a Pi or laptop)', R`
# Find your own subnet (e.g. 192.168.1.0/24)
ip -4 addr show | grep inet

# Install nmap (Raspberry Pi OS / Debian)
sudo apt update && sudo apt install -y nmap

# Which devices are alive?
sudo nmap -sn 192.168.1.0/24

# Which have "dangerous" IoT ports open?
sudo nmap -sS -p 23,2323,80,8080,1883,554,3232,8266 --open 192.168.1.0/24
`, L(
            '- `ip -4 addr show`: shows your IP and the /24 or /16 of the network.',
            '- `nmap -sn`: only **host discovery** (ping/ARP), no port scan.',
            '- `-sS`: SYN scan (fast, needs `sudo`).',
            '- `23,2323`: Telnet (Mirai\'s target). `80,8080`: web panels. `1883`: MQTT **without** TLS. `554`: RTSP cameras. `3232`: ESP32 ArduinoOTA. `8266`: ESP8266 OTA.',
            '- `--open`: shows only open ports, so you do not get lost in the output.'
          )),
          text('If you do not have nmap, you can do the same with a little **Python** (runs on a Pi, Mac, Linux). It is also a good exercise to understand what a scanner does:'),
          code('python', 'iot_port_check.py: a simple TCP scanner for YOUR OWN LAN', R`
#!/usr/bin/env python3
"""Checks your own subnet for ports that are usually dangerous on IoT devices."""
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

SUBNET = "192.168.1.0/24"          # change this to your own
PORTS = {23: "Telnet", 2323: "Telnet-alt", 1883: "MQTT without TLS",
         80: "HTTP panel", 554: "RTSP", 3232: "ArduinoOTA"}

def check(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        if s.connect_ex((str(ip), port)) == 0:   # 0 = the connection succeeded
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
print("Scan finished.")
`, L(
            '- `ipaddress.ip_network(SUBNET).hosts()`: all the IPs of the network except the network and broadcast addresses.',
            '- `connect_ex()`: tries a TCP connection and returns `0` if the port is open (instead of raising an exception).',
            '- `settimeout(0.5)`: we do not wait forever on closed/filtered ports.',
            '- `ThreadPoolExecutor(max_workers=100)`: 100 checks in parallel, otherwise it would take many minutes.',
            '- Red 🔴 for Telnet and OTA without protection: fix these **immediately**.'
          )),
          nw('pentest', 'The **🔴 Pentest** tab in NetWatch does the same check automatically (ports, software versions, known CVEs) for your own LAN.'),
          tip('Found Telnet open on a camera? Look in its settings for "Telnet" or "debug". If it cannot be turned off, put it on a **separate network** (Mod. 7) and block its access to the Internet.'),
          warn('Do not scan networks that do not belong to you (work, university, neighbors, cafés). Even an "innocent" port scan can be treated as an attempt at illegal access.'),
          quiz('Why did Mirai "reinfect" devices a few minutes after a reboot?',
            ['Because it wrote itself into the firmware', 'Because the default password and Telnet were still there, so another bot got in again', 'Because it had a rootkit in the bootloader', 'Because the router was infected'], 1,
            'Mirai lived in RAM and disappeared on reboot. But the **cause** (default password + Telnet) had not been fixed, and other bots were scanning constantly.'),
          quiz('Port 3232 is open on one of your ESP32s. What does it most likely mean?',
            ['It is running a web server', 'It is running ArduinoOTA: without a password, anyone on the LAN can upload firmware', 'It is MQTT with TLS', 'It is Telnet'], 1,
            '**ArduinoOTA** listens on 3232 on the ESP32. Without `setPassword`/`setPasswordHash` it is an open door for foreign firmware. We will see this in Mod. 5.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 2 — Secure setup on the Raspberry Pi
  // ====================================================================
  M.push({
    id: 'iot-2', order: 2, title: 'Secure setup on the Raspberry Pi',
    desc: 'Users, SSH with keys only, fail2ban, ufw, automatic updates and fewer services.',
    lessons: [
      {
        id: 'iot-2-1', title: 'Users and passwords: goodbye pi/raspberry', minutes: 12,
        goal: 'Create your own administrator, remove the default user and understand why `sudo` without a password is a risk.',
        blocks: [
          text(
            'Until April 2022, every Raspberry Pi OS shipped with the user **`pi`** and the password **`raspberry`**. Bots know this and try it first (you will see it in the fail2ban animation).',
            '',
            'Newer versions (Bookworm and later) force you to set a user in the **Raspberry Pi Imager** or at first boot. But many Pis still run old images, or you set them up in a hurry with `pi` and the password `1234`.',
            '',
            '### The right way in Raspberry Pi Imager',
            '- Click **Edit settings** (⚙️ or Ctrl+Shift+X).',
            '- Set **your own username** (not `pi`, `admin`, `root`) and a **strong password**.',
            '- In the **Services** tab: Enable SSH → **Allow public-key authentication only** and paste your public key (we will create it in the next lesson).',
            '- Set the Wi‑Fi country correctly (GR) for legal channels.'
          ),
          text('### If you already have a Pi with the pi user'),
          code('bash', 'A new administrator and removing pi', R`
# 1) Create a new user (it will ask for a password)
sudo adduser maria

# 2) Give them the same groups as pi (sudo, gpio, i2c, spi, video…)
groups pi
sudo usermod -aG sudo,adm,dialout,gpio,i2c,spi,video,plugdev,netdev maria

# 3) LOG OUT and log back in as maria. Check that sudo works:
sudo whoami          # must print: root

# 4) Lock (or delete) the old user
sudo passwd -l pi                 # lock the password
sudo usermod -s /usr/sbin/nologin pi   # no shell
# or, if you do not need it at all:
# sudo deluser --remove-home pi
`, L(
            '- `adduser`: Debian\'s friendly script. It creates a home directory and asks for a password.',
            '- `groups pi`: see which groups pi was in, so you do not lose access to GPIO/I2C/camera.',
            '- `usermod -aG`: the `-a` (append) is **critical**. Without it you wipe the user\'s other groups.',
            '- Step 3: **never** delete the old user before confirming that the new one has `sudo`. Otherwise you lock yourself out.',
            '- `passwd -l`: locks the password. With `nologin` the user cannot get a shell even with a key.'
          )),
          text(
            '### The sudo-without-a-password trap',
            'On old Pis there is the file `/etc/sudoers.d/010_pi-nopasswd`, which allows `sudo` **without** a password. If someone steals your session (or one of your scripts has a bug), they become root immediately.'
          ),
          code('bash', 'Checking for and removing NOPASSWD', R`
# Which files grant sudo without a password?
sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/

# Remove it (ONLY after you know your user's password!)
sudo rm /etc/sudoers.d/010_pi-nopasswd

# Check the sudoers syntax (never edit them directly with nano)
sudo visudo -c
`, L(
            '- `grep -r NOPASSWD`: searches all sudo rules without a password.',
            '- `visudo -c`: checks that the sudoers files are valid. A mistake there can cut you off from **all** of sudo.',
            '- For changes use `sudo visudo -f /etc/sudoers.d/filename`, which checks the syntax before saving.'
          )),
          cli('Lab: a new administrator on the Pi', 'pi@raspberrypi:~ $', 'Raspberry Pi OS (simulation). You are logged in as pi.', [
            { task: 'Create a new user named `maria` (with `sudo adduser`).', expect: '^sudo\\s+adduser\\s+maria$', ans: 'sudo adduser maria', out: 'Adding user `maria\' ...\nCreating home directory `/home/maria\' ...\nNew password: ********\nRetype new password: ********\npasswd: password updated successfully' },
            { task: 'Add maria to the `sudo` group (do not forget the `-a`).', expect: '^sudo\\s+usermod\\s+-(aG|Ga)\\s+\\S*sudo\\S*\\s+maria$', ans: 'sudo usermod -aG sudo maria', out: '', err: 'Use: sudo usermod -aG sudo maria' },
            { task: 'Lock the password of the `pi` user.', expect: '^sudo\\s+passwd\\s+-l\\s+pi$', ans: 'sudo passwd -l pi', out: 'passwd: password changed.' },
            { task: 'Find out whether there is a sudo rule without a password in `/etc/sudoers.d/`.', expect: '^sudo\\s+grep\\s+(-r\\s+)?NOPASSWD\\s+/etc/sudoers', ans: 'sudo grep -r NOPASSWD /etc/sudoers.d/', out: '/etc/sudoers.d/010_pi-nopasswd:pi ALL=(ALL) NOPASSWD: ALL' },
            { task: 'Delete that file.', expect: '^sudo\\s+rm\\s+(-f\\s+)?/etc/sudoers\\.d/010_pi-nopasswd$', ans: 'sudo rm /etc/sudoers.d/010_pi-nopasswd', out: '' },
            { task: 'Check the syntax of the sudoers files.', expect: '^sudo\\s+visudo\\s+-c$', ans: 'sudo visudo -c', out: '/etc/sudoers: parsed OK\n/etc/sudoers.d/README: parsed OK' },
          ], 'The default user is no longer a way in.'),
          tip('Use a **password manager** (Bitwarden, KeePassXC) for the Pi passwords. A random 20-character password per device is practically impossible to "guess".'),
          quiz('Why is the `-a` in `usermod -aG sudo maria` important?',
            ['It makes the user an admin', 'Without it, the user is removed from all their other groups', 'It enables SSH', 'It makes no difference'], 1,
            '`-G` on its own **replaces** the list of groups. With `-a` (append) you add to the existing ones.'),
        ],
      },
      {
        id: 'iot-2-2', title: 'SSH with keys only (sshd_config)', minutes: 16,
        goal: 'Create an **ed25519** key pair, put it on the Pi and completely disable passwords and root login in SSH, without locking yourself out.',
        blocks: [
          text(
            'With a password, a bot can try millions of combinations. With a **key**, it has to guess a 256-bit number. That will never happen.',
            '',
            'The **key pair** has two parts:',
            '- **Private** (`~/.ssh/id_ed25519`): stays **only** on your laptop, protected with a passphrase.',
            '- **Public** (`~/.ssh/id_ed25519.pub`): you put it on as many Pis as you like. It is not secret.'
          ),
          code('bash', 'On your laptop (Mac/Linux/Windows PowerShell)', R`
# 1) Create an ed25519 key (modern, small, fast)
ssh-keygen -t ed25519 -a 100 -C "maria@laptop"

# 2) Copy the public key to the Pi (once, with the password)
ssh-copy-id -i ~/.ssh/id_ed25519.pub maria@raspberrypi.local

# 3) Test: you must get in WITHOUT the Pi password (it may ask for the key's passphrase)
ssh maria@raspberrypi.local
`, L(
            '- `-t ed25519`: the key type. Prefer it over RSA: secure and very short.',
            '- `-a 100`: 100 KDF rounds for the passphrase. If the file is stolen, brute-forcing the passphrase becomes slow.',
            '- `-C`: a comment so you know which key is which inside `authorized_keys`.',
            '- `ssh-copy-id`: adds the public key to the Pi\'s `~/.ssh/authorized_keys` with the right permissions.',
            '- On Windows without `ssh-copy-id`: `type $env:USERPROFILE\\.ssh\\id_ed25519.pub | ssh maria@raspberrypi.local "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"`.'
          )),
          text(
            '### Turning off passwords on the Pi',
            'Instead of changing the big `/etc/ssh/sshd_config`, we create a **drop-in** file in `/etc/ssh/sshd_config.d/`. The main file loads it with an `Include` at its start.',
            '',
            'Mind the order: in OpenSSH **the first value found wins**. Files are read alphabetically, which is why the name starts with `01-`: so it beats a possible `50-cloud-init.conf` that enables passwords.'
          ),
          code('text', '/etc/ssh/sshd_config.d/01-hardening.conf', R`
# --- Authentication ---
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
PermitEmptyPasswords no
AuthenticationMethods publickey

# --- Who is allowed ---
AllowUsers maria

# --- Limiting brute force / idle connections ---
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Less attack surface ---
X11Forwarding no
AllowAgentForwarding no
`, L(
            '- `PasswordAuthentication no` + `KbdInteractiveAuthentication no`: close **both** ways of logging in with a password.',
            '- `PermitRootLogin no`: root never logs in directly. You log in as maria and use `sudo`.',
            '- `AuthenticationMethods publickey`: explicitly, key only.',
            '- `AllowUsers maria`: a whitelist. Even if someone creates another user, they cannot log in over SSH.',
            '- `MaxAuthTries 3`, `LoginGraceTime 20`: quickly cut off anyone who is "fishing".',
            '- `ClientAlive…`: closes sessions left open after ~10 minutes of inactivity.',
            '- `X11Forwarding`, `AllowAgentForwarding`: you do not need them on a headless Pi.'
          )),
          code('bash', 'Applying it safely', R`
# 1) Syntax check. If it prints anything, FIX it before the restart
sudo sshd -t

# 2) See the final, "effective" setting
sudo sshd -T | grep -Ei 'passwordauth|kbdinteractive|permitroot|allowusers'

# 3) Restart (on Raspberry Pi OS the service is called ssh)
sudo systemctl restart ssh

# 4) IN A NEW TERMINAL (keep the old one open!) test:
ssh maria@raspberrypi.local                              # must get in
ssh -o PubkeyAuthentication=no maria@raspberrypi.local   # must give: Permission denied (publickey)
`, L(
            '- `sshd -t`: test mode. It restarts nothing, it only checks.',
            '- `sshd -T`: prints all the values as sshd "sees" them after all the Includes. Here you confirm that your file won.',
            '- Step 4 is the most important: **do not close** the old session until you confirm that the new one works.',
            '- The second command forces the client not to use a key, so you can confirm that the password is **not** accepted.'
          )),
          warn('If something goes wrong and you get locked out: put the SD card in another computer, open the rootfs and delete `/etc/ssh/sshd_config.d/01-hardening.conf`. Or connect a monitor and keyboard to the Pi.'),
          cli('Lab: locking down SSH', 'maria@raspberrypi:~ $', 'Raspberry Pi OS (simulation). Your key has already been installed with ssh-copy-id.', [
            { task: 'Open the drop-in `/etc/ssh/sshd_config.d/01-hardening.conf` for editing with `nano`.', expect: '^sudo\\s+nano\\s+/etc/ssh/sshd_config\\.d/01-hardening\\.conf$', ans: 'sudo nano /etc/ssh/sshd_config.d/01-hardening.conf', out: '[ you type PasswordAuthentication no, PermitRootLogin no, AllowUsers maria … and save with Ctrl+O, Ctrl+X ]' },
            { task: 'Check the syntax of the sshd configuration.', expect: '^sudo\\s+sshd\\s+-t$', ans: 'sudo sshd -t', out: '' },
            { task: 'See the effective value of `passwordauthentication` (with `sshd -T` and `grep`).', expect: '^sudo\\s+sshd\\s+-T\\s*\\|\\s*grep\\s+(-i\\s+)?passwordauth', ans: 'sudo sshd -T | grep -i passwordauthentication', out: 'passwordauthentication no' },
            { task: 'Restart the `ssh` service.', expect: '^sudo\\s+systemctl\\s+restart\\s+ssh(d)?(\\.service)?$', ans: 'sudo systemctl restart ssh', out: '' },
            { task: 'Check that it is running correctly (status).', expect: '^(sudo\\s+)?systemctl\\s+status\\s+ssh', ans: 'systemctl status ssh', out: '● ssh.service - OpenBSD Secure Shell server\n     Active: active (running)\n     sshd[1234]: Server listening on 0.0.0.0 port 22.' },
          ], 'Now you only get in with a key. Keep the old session open until you have tested from a new terminal!'),
          tip('On the laptop, create `~/.ssh/config` with `Host pi` / `HostName raspberrypi.local` / `User maria` / `IdentityFile ~/.ssh/id_ed25519`. Then you simply connect with `ssh pi`.'),
          quiz('You put `PasswordAuthentication no` in `/etc/ssh/sshd_config`, but `sshd -T` says `passwordauthentication yes`. What is the most likely cause?',
            ['sshd ignores that option', 'A file in `sshd_config.d/` (e.g. `50-cloud-init.conf`) sets it first, and in OpenSSH the first value wins', 'You need to reboot', 'The option is called PasswordLogin'], 1,
            'The `Include /etc/ssh/sshd_config.d/*.conf` is at the **start** of the main file, and the **first** value wins. That is why we put our settings in a drop-in named `01-…`.'),
          quiz('Which file must **never** leave your laptop?',
            ['`~/.ssh/id_ed25519.pub`', '`~/.ssh/id_ed25519`', '`~/.ssh/known_hosts`', '`~/.ssh/config`'], 1,
            'The file without `.pub` is the **private** key. The `.pub` can be seen by the whole world.'),
        ],
      },
      {
        id: 'iot-2-3', title: 'fail2ban: block those who guess passwords', minutes: 13,
        goal: 'Install and configure **fail2ban** correctly on Raspberry Pi OS Bookworm (with `backend = systemd`) and check which IPs have been blocked.',
        blocks: [
          text(
            'Even with SSH using keys only, bots will keep "knocking". **fail2ban** reads the logs, sees which IPs keep failing and **blocks them in the firewall** for a while. This gives you:',
            '- Less noise in the logs (you can see the real problems).',
            '- Less CPU use on the small Pi.',
            '- Protection for other services with a login (Mosquitto, web panels) too.'
          ),
          anim('iot-ssh-bruteforce', 'Three failures, a 1-hour ban. You, with your key, get in normally.'),
          code('bash', 'Installation', R`
sudo apt update
sudo apt install -y fail2ban python3-systemd
`, L(
            '- `python3-systemd`: needed so fail2ban can read the systemd **journal** directly.',
            '- On Bookworm there is no `/var/log/auth.log` by default any more (rsyslog is not installed). If you do not set `backend = systemd`, the sshd jail does not start.'
          )),
          code('text', '/etc/fail2ban/jail.local', R`
[DEFAULT]
# Never block yourself / your LAN
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24
bantime  = 1h
findtime = 10m
maxretry = 3
# Repeat offenders get longer and longer bans (1h, 2h, 4h…)
bantime.increment = true
bantime.maxtime   = 1w
backend = systemd
# If you use ufw (next lesson), block through ufw:
banaction = ufw

[sshd]
enabled = true
port    = ssh
`, L(
            '- **Never** edit `jail.conf`: it will be replaced in some update. Your settings go in `jail.local`.',
            '- `ignoreip`: the addresses that are never blocked. Put your own subnet here, so you do not lock yourself out if you mix up your key.',
            '- `findtime = 10m` + `maxretry = 3`: 3 failures within 10 minutes → ban.',
            '- `bantime.increment`: each next ban of the same IP doubles, up to 1 week.',
            '- `backend = systemd`: reads from the journal (required on Bookworm).',
            '- `banaction = ufw`: bans become ufw rules. Without ufw, leave it at the default (iptables/nftables).'
          )),
          code('bash', 'Enabling and checking', R`
sudo systemctl enable --now fail2ban
sudo fail2ban-client status            # which jails are running
sudo fail2ban-client status sshd       # how many failures, which IPs are banned

# Unblock an IP (e.g. if you made a mistake yourself from 4G)
sudo fail2ban-client set sshd unbanip 203.0.113.66

# See what fail2ban "sees" in the sshd logs
sudo journalctl -u ssh --since "1 hour ago" | grep -Ei 'failed|invalid'
`, L(
            '- `enable --now`: starts now **and** on every boot.',
            '- `status sshd`: shows `Currently failed`, `Total banned` and the `Banned IP list`.',
            '- `unbanip`: manual unblocking.',
            '- `journalctl -u ssh`: the SSH logs from the journal, the same ones fail2ban reads.'
          )),
          code('text', 'Bonus: a jail for Mosquitto (/etc/fail2ban/jail.d/mosquitto.local)', R`
# It also needs a filter: /etc/fail2ban/filter.d/mosquitto-auth.conf
# In Mosquitto 2.x the failure is written like this, on TWO lines:
#   New connection from 192.168.1.66:50612 on port 8883.
#   Client attacker disconnected, not authorised.
# The IP and the failure are not on the same line, so the filter needs a
# multi-line regex (prefregex/maxlines). Simpler & surer: allow access to 8883
# only from the IoT subnet with a firewall (Mod. 7).
[mosquitto]
enabled  = false
port     = 8883
filter   = mosquitto-auth
logpath  = /var/log/mosquitto/mosquitto.log
backend  = auto
maxretry = 5
`, L(
            '- This is deliberately `enabled = false`: it shows how to build a jail for **another** service.',
            '- Every jail needs a **filter** (a regex that finds the attacker\'s IP in the log) and an **action** (e.g. a ban in the firewall).',
            '- You test a filter with: `fail2ban-regex /var/log/mosquitto/mosquitto.log /etc/fail2ban/filter.d/mosquitto-auth.conf`.'
          )),
          tip('Opening SSH to the Internet? Better **not**. Use **WireGuard** or **Tailscale** and leave SSH visible only inside the VPN. Then fail2ban is an extra layer, not your only defense.'),
          nw('alerts', 'In the **⚠ Alerts** tab NetWatch shows brute force against SSH/Telnet when it runs on the same network, with a MITRE code (T1110).'),
          quiz('On Raspberry Pi OS Bookworm the `sshd` jail does not start and the log says it cannot find `/var/log/auth.log`. What do you fix?',
            ['Change the SSH port', 'Set `backend = systemd` (and install `python3-systemd`)', 'Set `maxretry = 0`', 'Disable the journal'], 1,
            'Bookworm writes logs to the **systemd journal**, not to text files. With `backend = systemd` fail2ban reads them from there.'),
          quiz('Why do we put our LAN in `ignoreip`?',
            ['To make it faster', 'So we do not accidentally block ourselves', 'Because the LAN is always safe', 'Because otherwise ufw does not work'], 1,
            'If you mix up keys or users 3 times, you would get banned by your own Pi. But careful: if a device on the LAN gets infected, fail2ban will not stop it. That is why segmentation exists too (Mod. 7).'),
        ],
      },
      {
        id: 'iot-2-4', title: 'Firewall with ufw', minutes: 14,
        goal: 'Set up **ufw** with a "everything closed except what I need" policy, restrict services per subnet and avoid locking yourself out.',
        blocks: [
          text(
            '**ufw** (Uncomplicated Firewall) is a friendly tool on top of Linux netfilter (iptables/nftables). The basic idea:',
            '- **Default deny incoming**: nothing gets in unless you explicitly allow it.',
            '- **Default allow outgoing**: the Pi can reach out (for updates, NTP etc.).',
            '- You open **only** what you need and, where possible, **only from a specific subnet**.'
          ),
          code('bash', 'A basic, safe setup', R`
sudo apt install -y ufw

# 1) Policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 2) SSH FIRST (otherwise you lock yourself out!), only from the LAN, with rate limit
sudo ufw limit from 192.168.1.0/24 to any port 22 proto tcp comment 'SSH from LAN'

# 3) MQTT over TLS only from the LAN/IoT network
sudo ufw allow from 192.168.1.0/24 to any port 8883 proto tcp comment 'MQTT TLS'

# 4) Enable
sudo ufw enable

# 5) Check with rule numbering
sudo ufw status numbered
sudo ufw status verbose
`, L(
            '- `default deny incoming`: all incoming traffic is cut, except replies to connections the Pi started (stateful).',
            '- `limit`: like `allow`, but blocks an IP that opens **6+ connections in 30 seconds**. A mini fail2ban.',
            '- `from 192.168.1.0/24`: the rule applies only to your LAN. From the Internet, 22 is closed.',
            '- `comment`: you will thank yourself in 6 months.',
            '- `status numbered`: shows the rules with a number, so you can delete e.g. with `sudo ufw delete 3`.'
          )),
          code('bash', 'More useful commands', R`
# See what is LISTENING on the Pi (which ports need a rule)
sudo ss -tulpn

# Logging of blocked packets (at a low level so the card does not fill up)
sudo ufw logging low
sudo journalctl -k | grep -i 'UFW BLOCK' | tail

# Delete a rule by number
sudo ufw delete 3

# Disable (if something went wrong and you have a monitor/keyboard)
sudo ufw disable
`, L(
            '- `ss -tulpn`: TCP/UDP, listening, with process. Each line is a service you may not need.',
            '- The ufw logs go to the kernel log, hence to the journal (`journalctl -k`).',
            '- `UFW BLOCK` lines with a SRC from the Internet are normal "noise". From your LAN, though, they deserve attention.'
          )),
          cli('Lab: ufw from scratch', 'maria@raspberrypi:~ $', 'The Pi has IP 192.168.1.50. We want SSH and MQTT/TLS only from 192.168.1.0/24.', [
            { task: 'Set the default policy: deny incoming.', expect: '^sudo\\s+ufw\\s+default\\s+deny\\s+(incoming|in)$', ans: 'sudo ufw default deny incoming', out: "Default incoming policy changed to 'deny'\n(be sure to update your rules accordingly)" },
            { task: 'Set the default policy: allow outgoing.', expect: '^sudo\\s+ufw\\s+default\\s+allow\\s+(outgoing|out)$', ans: 'sudo ufw default allow outgoing', out: "Default outgoing policy changed to 'allow'" },
            { task: 'Allow SSH (22/tcp) with **limit**, only from 192.168.1.0/24.', expect: '^sudo\\s+ufw\\s+limit\\s+from\\s+192\\.168\\.1\\.0/24\\s+to\\s+any\\s+port\\s+22(\\s+proto\\s+tcp)?', ans: 'sudo ufw limit from 192.168.1.0/24 to any port 22 proto tcp', out: 'Rule added' },
            { task: 'Allow 8883/tcp only from 192.168.1.0/24.', expect: '^sudo\\s+ufw\\s+allow\\s+from\\s+192\\.168\\.1\\.0/24\\s+to\\s+any\\s+port\\s+8883(\\s+proto\\s+tcp)?', ans: 'sudo ufw allow from 192.168.1.0/24 to any port 8883 proto tcp', out: 'Rule added' },
            { task: 'Enable the firewall.', expect: '^sudo\\s+ufw\\s+(--force\\s+)?enable$', ans: 'sudo ufw enable', out: 'Command may disrupt existing ssh connections. Proceed with operation (y|n)? y\nFirewall is active and enabled on system startup' },
            { task: 'See the rules with numbering.', expect: '^sudo\\s+ufw\\s+status\\s+numbered$', ans: 'sudo ufw status numbered', out: 'Status: active\n\n     To                         Action      From\n     --                         ------      ----\n[ 1] 22/tcp                     LIMIT IN    192.168.1.0/24\n[ 2] 8883/tcp                   ALLOW IN    192.168.1.0/24' },
          ], 'The Pi accepts only SSH and MQTT/TLS, and only from the LAN.'),
          warn('**Docker + ufw:** Docker writes its own iptables rules and **bypasses** ufw for ports you publish (`-p 1883:1883`). If you run Mosquitto in a container, bind to a specific IP (`-p 127.0.0.1:1883:1883`) or look at the `ufw-docker` solution.'),
          nw('devs', 'The **📟 Devices** tab in NetWatch shows which devices talk to your Pi. If after ufw you still see connections to ports you did not open, something is bypassing the firewall (e.g. Docker).'),
          quiz('Which order of commands is **dangerous** on a Pi you manage over SSH?',
            ['`ufw allow 22` → `ufw enable`', '`ufw default deny incoming` → `ufw enable` → `ufw allow 22`', '`ufw limit from 192.168.1.0/24 to any port 22` → `ufw enable`', '`ufw status` → `ufw enable`'], 1,
            'If you enable the firewall with deny **before** allowing 22, the next SSH connection will be cut (and maybe the current one too). Always: allow SSH first, then enable.'),
          quiz('What does `ufw limit` do compared to `ufw allow`?',
            ['It allows only 1 user', 'It allows, but blocks an IP with many new connections in a short time', 'It limits the bandwidth', 'It allows only IPv4'], 1,
            '`limit` cuts off an IP that makes 6 or more new connections within 30 seconds. Ideal for SSH.'),
        ],
      },
      {
        id: 'iot-2-5', title: 'Automatic updates and fewer services', minutes: 14,
        goal: 'Set up **unattended-upgrades** for security updates and disable services and hardware (Bluetooth, avahi, CUPS) that you do not use.',
        blocks: [
          text(
            'Most attacks use **known** vulnerabilities, for which a patch already exists. A Pi that goes years without `apt upgrade` is an easy target.',
            '',
            '**unattended-upgrades** installs the security updates automatically (every day). For a device that runs on its own 24/7, it is almost mandatory.'
          ),
          code('bash', 'Installing and enabling', R`
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y unattended-upgrades apt-listchanges

# Enable (creates /etc/apt/apt.conf.d/20auto-upgrades)
sudo dpkg-reconfigure -plow unattended-upgrades

# See which sources (origin/label) your system has
apt-cache policy | grep -E 'o=|release' | sort -u
`, L(
            '- `full-upgrade`: first bring the system up to date.',
            '- `dpkg-reconfigure -plow`: asks "Automatically download and install stable updates?" → Yes.',
            '- `apt-cache policy`: shows the `o=` (origin) and `l=` (label) of each repository. You need them to tell unattended-upgrades **which** repos to update.'
          )),
          code('text', '/etc/apt/apt.conf.d/52unattended-upgrades-local', R`
// Which repos get updated automatically.
// Raspberry Pi OS 64-bit: Debian (security + updates) + archive.raspberrypi.com
// Change "bookworm" if /etc/os-release says another codename (e.g. trixie).
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=bookworm,label=Debian-Security";
        "origin=Debian,codename=bookworm-security,label=Debian-Security";
        "origin=Debian,codename=bookworm-updates";
        "origin=Raspberry Pi Foundation,codename=bookworm";
};

// Clean up packages that are no longer needed
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatic reboot if an update needs it (e.g. kernel), at 04:00
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
`, L(
            '- The files in `apt.conf.d` are read alphabetically, so `52-…` is applied **after** the default `50unattended-upgrades` and you do not touch it.',
            '- `Origins-Pattern`: each line describes a repo with the `origin`, `codename`, `label` you saw in `apt-cache policy`.',
            '- The `Raspberry Pi Foundation` line covers the Pi\'s kernel/firmware/tools from `archive.raspberrypi.com`.',
            '- `Automatic-Reboot`: kernel updates need a reboot to take effect. For a sensor at 04:00 that is usually OK.'
          )),
          code('bash', 'Testing without installing anything', R`
sudo unattended-upgrade --dry-run --debug 2>&1 | grep -Ei 'allowed origins|packages that will be upgraded|no packages'
# History: what was installed and when
less /var/log/unattended-upgrades/unattended-upgrades.log
`, L(
            '- `--dry-run --debug`: shows which origins are allowed and what it **would** upgrade.',
            '- If the `Allowed origins` list does not contain your repos, something does not match the pattern.'
          )),
          text(
            '### Fewer services = a smaller attack surface',
            'Every running service is code that can have a bug. On a headless Pi that only acts as a broker/sensor, you usually **do not** need:'
          ),
          table(['Service', 'What it does', 'When to remove it'], [
            ['`avahi-daemon`', 'mDNS (`raspberrypi.local`)', 'If you have a fixed IP or DNS on the router (you will lose `.local`)'],
            ['`bluetooth`, `hciuart`', 'Bluetooth', 'If you do not use BLE'],
            ['`cups`, `cups-browsed`', 'Printers', 'Almost always on a headless Pi'],
            ['`ModemManager`', '3G/4G modems', 'If you have no USB modem'],
            ['`triggerhappy`', 'Hotkeys', 'On a headless Pi'],
            ['`rpcbind`, `nfs-…`', 'NFS', 'If you do not mount NFS'],
          ]),
          code('bash', 'Find and remove what you do not need', R`
# What is running and what is listening on the network?
systemctl list-units --type=service --state=running
sudo ss -tulpn

# Disable (stop now + not at boot)
sudo systemctl disable --now cups.service cups-browsed.service
sudo systemctl disable --now bluetooth.service hciuart.service
sudo systemctl disable --now ModemManager.service

# Bluetooth completely off at the hardware level (Pi 3/4/5)
echo 'dtoverlay=disable-bt' | sudo tee -a /boot/firmware/config.txt

# Wi‑Fi off if the Pi is wired only (useful for a broker)
echo 'dtoverlay=disable-wifi' | sudo tee -a /boot/firmware/config.txt
sudo reboot
`, L(
            '- `list-units … running`: all the services running right now.',
            '- `disable --now`: stops it and removes it from boot. If you need it again: `enable --now`.',
            '- `dtoverlay=disable-bt`: Bluetooth does not even appear in the system (and cannot be enabled from software).',
            '- On Bookworm the file is `/boot/firmware/config.txt` (on older ones: `/boot/config.txt`).',
            '- `disable-wifi`: **do not** do this if the Pi is connected over Wi‑Fi only!'
          )),
          tip('Run `sudo ss -tulpn` again afterwards. Ideally you see only `sshd` (22), `mosquitto` (8883, and 1883 only on `127.0.0.1`) and whatever else **you** installed.'),
          quiz('Why do we create our own `52unattended-upgrades-local` file instead of changing `50unattended-upgrades`?',
            ['Because 50 is read-only', 'So our changes are not lost/conflicting when the package updates its own file', 'Because 52 runs faster', 'There is no reason'], 1,
            'Package files can be replaced in an update. Your own drop-in files stay. Same logic as `jail.local` and `sshd_config.d/`.'),
          quiz('The command `sudo ss -tulpn` shows `0.0.0.0:631 cupsd`. What does it mean?',
            ['The Pi is printing something', 'The CUPS print service is listening on all interfaces: if you do not need it, disable it', 'It is SSH', 'It is normal and necessary'], 1,
            '`0.0.0.0` means "on all interfaces". A service you do not need = unnecessary attack surface.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 3 — ESP32 basics and secure Wi‑Fi
  // ====================================================================
  M.push({
    id: 'iot-3', order: 3, title: 'ESP32: secrets, secure Wi‑Fi and provisioning',
    desc: 'Passwords out of the code (secrets.h, .gitignore), WPA2/WPA3, provisioning with Preferences, Arduino C++ and MicroPython.',
    lessons: [
      {
        id: 'iot-3-1', title: 'Never put passwords in the code: secrets.h and .gitignore', minutes: 15,
        goal: 'Take passwords and keys out of the code (Arduino and MicroPython), never push them to Git, and write callbacks that do not "crash" on bad data.',
        blocks: [
          text(
            'The most common mistake in ESP32 projects: the Wi‑Fi and MQTT passwords inside the `.ino`. Then the project goes up to GitHub "so a friend can look at it", and within minutes bots that scan GitHub have found your password.',
            '',
            'The rule: **the code is public, the secrets are not.** We split the two into different files.'
          ),
          code('cpp', '❌ WRONG: main.ino with passwords inside', R`
#include <WiFi.h>

const char* ssid     = "HomeWiFi";
const char* password = "MyS3cretPass!";        // ❌ will end up on GitHub
const char* mqttPass = "Kalimera2024";         // ❌ and this one too

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  Serial.printf("Connecting with password %s\n", password);   // ❌ and in the Serial log too!
}
void loop() {}
`, L(
            '- The passwords are **in every copy** of the code: GitHub, Discord, screenshots, backups.',
            '- The `Serial.printf` with the password means anyone who plugs USB into the device sees it.',
            '- If you change the Wi‑Fi password, you have to change the code.'
          )),
          code('cpp', '✅ secrets.h (NEVER pushed to Git)', R`
#pragma once
// Copy secrets.example.h to secrets.h and fill it in.
#define WIFI_SSID  "HomeWiFi"
#define WIFI_PASS  "MyS3cretPass!"
#define MQTT_HOST  "pi-broker.local"
#define MQTT_USER  "sensor01"
#define MQTT_PASS  "8f2K-vQ9x-Lm3p-Tz7w"
`, L(
            '- `#pragma once`: the file is included only once, even if many .cpp files ask for it.',
            '- Every device gets **its own** `MQTT_USER`/`MQTT_PASS`. If one is stolen, you revoke only that one.',
            '- In the repo you push a `secrets.example.h` with the same `#define`s and `"CHANGE_ME"` values, so someone knows what to fill in.'
          )),
          code('cpp', '✅ main.ino', R`
#include <WiFi.h>
#include "secrets.h"          // the secrets come from here

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.printf("Connecting to %s...\n", WIFI_SSID);   // SSID yes, password NO
  while (WiFi.status() != WL_CONNECTED) {
    delay(250);
    Serial.print('.');
  }
  Serial.printf("\nOK, IP=%s\n", WiFi.localIP().toString().c_str());
}

void loop() {}
`, L(
            '- `#include "secrets.h"` with quotes: it looks first in the sketch folder.',
            '- In the Arduino IDE, `secrets.h` must be **in the same folder** as the `.ino` (it shows up as a tab).',
            '- We print only the SSID. Never passwords, tokens or keys in logs.'
          )),
          code('text', '.gitignore (at the root of the repo)', R`
# Secrets: NEVER in Git
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
            '- `secrets.h` / `secrets.py`: the files with passwords for Arduino and MicroPython.',
            '- `*.pem`, `*.key`: private keys (CA, server, signing key for Secure Boot). These are **even more** valuable than the Wi‑Fi password.',
            '- `.pio/`, `build/`, `*.bin`: the compiled binaries **contain** the passwords in plain text!',
            '- `ca.crt` (the CA\'s public certificate) is **not** secret. It can be pushed.'
          )),
          code('bash', 'Check before you push', R`
# Is it really ignored?
git check-ignore -v secrets.h

# Was it already committed earlier?
git log --all --oneline -- secrets.h
git grep -n -I -E 'WIFI_PASS|password|MQTT_PASS' $(git rev-list --all) | head

# If it was already added: stop tracking it (the file stays local)
git rm --cached secrets.h
git commit -m "Remove secrets from repo"
`, L(
            '- `check-ignore -v`: tells you which line of `.gitignore` catches the file.',
            '- `git log --all -- secrets.h`: if it shows commits, the file exists in the **history**.',
            '- `git grep … $(git rev-list --all)`: searches every version of every commit.',
            '- `git rm --cached`: stops tracking it without deleting the local file.',
            '- **Important:** if the password was ever pushed to a public repo, treat it as **burned** and change it. Rewriting the history is not enough (there are forks, caches, bots).'
          )),
          text('In **PlatformIO** you can pass the secrets through environment variables, with no file at all:'),
          code('text', 'platformio.ini', '[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\nlib_deps = knolleary/PubSubClient@^2.8\n; The values come from the environment: export WIFI_PASS=\'...\'\nbuild_flags =\n  -DWIFI_SSID=\\"${sysenv.WIFI_SSID}\\"\n  -DWIFI_PASS=\\"${sysenv.WIFI_PASS}\\"', L(
            '- `${sysenv.X}`: PlatformIO reads the environment variable `X` at build time.',
            '- The `\\"` are needed so the value becomes a string literal in C++.',
            '- Useful in CI (GitHub Actions secrets).'
          )),
          text('### The same in MicroPython'),
          code('micropython', 'secrets.py (on the device, not in Git)', R`
WIFI_SSID = "HomeWiFi"
WIFI_PASS = "MyS3cretPass!"
MQTT_HOST = "pi-broker.local"
MQTT_USER = "sensor02"
MQTT_PASS = "Q7r2-Wd9k-Pz4n-Yx1m"
`, L(
            '- A simple module with constants. In `main.py` you write `import secrets`.',
            '- You upload it to the device with `mpremote cp secrets.py :secrets.py`.',
            '- Remember: on the ESP32 filesystem it is **plain text**. It protects the repo, not the device (flash encryption solves that, Mod. 5).'
          )),
          text(
            '### Safe code: data from the network is hostile',
            'Anything that comes from MQTT, HTTP or Serial may have been sent by an attacker. A classic bug with PubSubClient: the `payload` **does not end in `\\0`**.'
          ),
          code('cpp', '❌ vs ✅ the MQTT callback', R`
const int RELAY_PIN = 26;

// ❌ WRONG: reads past the buffer, strcpy without a limit
void onMessageBad(char* topic, byte* payload, unsigned int length) {
  char cmd[8];
  strcpy(cmd, (char*)payload);      // ❌ buffer overflow if length >= 8
  if (strcmp(cmd, "ON") == 0) digitalWrite(RELAY_PIN, HIGH);
}

// ✅ RIGHT: length check, null-termination, command whitelist
void onMessage(char* topic, byte* payload, unsigned int length) {
  char cmd[8];
  if (length == 0 || length >= sizeof(cmd)) {   // reject empty/huge
    Serial.println("[MQTT] rejected: wrong length");
    return;
  }
  memcpy(cmd, payload, length);
  cmd[length] = '\0';                            // now it is a proper C string

  if (strcmp(cmd, "ON") == 0)       digitalWrite(RELAY_PIN, HIGH);
  else if (strcmp(cmd, "OFF") == 0) digitalWrite(RELAY_PIN, LOW);
  else Serial.println("[MQTT] unknown command, ignored");
}
`, L(
            '- The `payload` is just bytes with a length `length`. There is no `\\0` at the end.',
            '- `strcpy` copies until it finds `\\0`, however far away that is → it writes over other stack variables (**stack overflow**). In the worst case: code execution.',
            '- `length >= sizeof(cmd)`: we keep one slot for the `\\0`.',
            '- **Whitelist:** we accept only known commands (`ON`, `OFF`). Anything else is ignored.'
          )),
          tip('Using ArduinoJson? Always check the result of `deserializeJson()` and the limits of every number (e.g. an interval from 10 to 3600). Never trust that "the field will be there".'),
          quiz('Why is it not enough to delete `secrets.h` with a new commit if it was already pushed to a public repo?',
            ['Because Git does not delete files', 'Because the password exists in the history, in forks and maybe in bots that found it: you must change the password', 'Because GitHub keeps a 1-year backup', 'It is enough, there is no problem'], 1,
            'A secret that was published, even briefly, is considered **compromised**. The only real fix is changing it (rotation).'),
          quiz('In the PubSubClient callback, why is `strcpy(cmd, (char*)payload)` dangerous?',
            ['It is slow', 'The payload does not end in `\\0` and may be larger than the buffer → buffer overflow', 'strcpy does not exist on the ESP32', 'It changes the topic'], 1,
            'Always use `length`: check the limit, do a `memcpy` and add the `\\0` yourself.'),
        ],
      },
      {
        id: 'iot-3-2', title: 'Secure Wi‑Fi connection: WPA2/WPA3, events, evil twin', minutes: 16,
        goal: 'Connect the ESP32 only to **WPA2/WPA3** networks, handle disconnections correctly (Arduino & MicroPython) and understand how this protects you from an evil twin.',
        blocks: [
          text(
            '### Which Wi‑Fi encryption?',
            'The ESP32 supports every mode, from **open** to **WPA3-SAE**. You have to tell it to **refuse** the weak ones.'
          ),
          table(['Mode', 'Security', 'Comment'], [
            ['Open', '❌ none', 'Everyone sees everything. Never for IoT.'],
            ['WEP', '❌ cracked in minutes', 'Obsolete.'],
            ['WPA (TKIP)', '❌ weak', 'Obsolete.'],
            ['WPA2-PSK (AES/CCMP)', '✅ good', 'Enough with a **long random** password (16+ characters). With a weak password it gets cracked offline from the handshake.'],
            ['WPA3-SAE', '✅✅ better', 'Resists offline brute force, PMF mandatory. The ESP32 supports it as a station.'],
            ['WPA2/WPA3 transition', '✅ practical', 'Old devices join with WPA2, new ones with WPA3.'],
          ]),
          code('cpp', 'wifi_secure.ino: connecting with minimum WPA2, events and a timeout', R`
#include <WiFi.h>
#include "secrets.h"

static void onWiFiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  switch (event) {
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      Serial.printf("[WiFi] IP=%s RSSI=%d dBm\n",
                    WiFi.localIP().toString().c_str(), WiFi.RSSI());
      break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      // The reason code helps diagnosis (e.g. 15 = 4-way handshake timeout = wrong password)
      Serial.printf("[WiFi] disconnected, reason=%d\n", info.wifi_sta_disconnected.reason);
      break;
    default:
      break;
  }
}

bool connectWiFi(uint32_t timeoutMs = 20000) {
  WiFi.persistent(false);                   // do not store credentials in the driver's NVS
  WiFi.setHostname("sensor01");             // before mode/begin
  WiFi.mode(WIFI_STA);                      // station only, not an AP too
  WiFi.setMinSecurity(WIFI_AUTH_WPA2_PSK);  // refuses open/WEP/WPA
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
    Serial.println("[WiFi] failed, restarting in 10s");
    delay(10000);
    ESP.restart();
  }
}

void loop() {
  // Your application here. autoReconnect takes care of short outages.
  delay(1000);
}
`, L(
            '- `WiFi.persistent(false)`: by default the Wi‑Fi driver writes the SSID/password to its NVS. We do not need that, since we already have them.',
            '- `setHostname`: a friendly name in the router\'s DHCP list (and in NetWatch). It must be set **before** `mode`/`begin`.',
            '- `WIFI_STA`: so it does not accidentally open its own access point too.',
            '- `setMinSecurity(WIFI_AUTH_WPA2_PSK)`: if someone sets up an **open** network with the same SSID, the ESP32 **refuses** to connect. For strict WPA3: `WIFI_AUTH_WPA3_PSK`.',
            '- `onEvent`: you learn when and **why** a disconnection happened. Many disconnections in a row = a possible deauth attack or a bad signal.',
            '- Timeout + `ESP.restart()`: the device does not "hang" forever in an infinite loop.'
          )),
          tip('ESP-IDF 5 (and so Arduino core 3.x) always has **PMF capable** (802.11w) enabled. Set your router to PMF **optional** or **required** and the attacker\'s deauth packets are rejected.'),
          text('### The same in MicroPython, checking the network\'s security before connecting'),
          code('micropython', 'wifi.py', R`
import network
import time
import machine
import secrets

# authmode values from wlan.scan() on the ESP32 (ESP-IDF wifi_auth_mode_t)
AUTH_NAMES = {0: "OPEN", 1: "WEP", 2: "WPA-PSK", 3: "WPA2-PSK",
              4: "WPA/WPA2-PSK", 5: "WPA2-ENT", 6: "WPA3-PSK", 7: "WPA2/WPA3-PSK"}
MIN_OK = (3, 6, 7)   # we accept only WPA2, WPA3 or WPA2/WPA3


def connect(timeout_s=20):
    network.hostname("sensor02")
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if wlan.isconnected():
        return wlan

    # Find our network in the scan and check its encryption
    found = [n for n in wlan.scan() if n[0].decode() == secrets.WIFI_SSID]
    if not found:
        raise OSError("SSID not found")
    best = max(found, key=lambda n: n[3])          # the strongest signal
    auth = best[4]
    print("Found:", secrets.WIFI_SSID, "RSSI", best[3], "auth", AUTH_NAMES.get(auth, auth))
    if auth not in MIN_OK:
        raise OSError("Weak encryption, NOT connecting")
    if len(found) > 1:
        print("⚠️ The same SSID from", len(found), "APs (mesh or evil twin?)")

    wlan.connect(secrets.WIFI_SSID, secrets.WIFI_PASS)
    t0 = time.ticks_ms()
    while not wlan.isconnected():
        if time.ticks_diff(time.ticks_ms(), t0) > timeout_s * 1000:
            raise OSError("Connection timeout")
        time.sleep_ms(250)
    print("IP:", wlan.ifconfig()[0])
    return wlan


try:
    wlan = connect()
except OSError as e:
    print("Wi-Fi error:", e)
    time.sleep(10)
    machine.reset()
`, L(
            '- `network.hostname()`: sets the device name (MicroPython 1.20+).',
            '- `wlan.scan()` returns tuples: `(ssid, bssid, channel, RSSI, authmode, hidden)`.',
            '- We check the `authmode` **before** sending the password. If someone sets up an open network with the same name, we do not connect.',
            '- If we see the same SSID from several BSSIDs: on a mesh that is normal; otherwise it deserves attention.',
            '- `time.ticks_diff()`: the correct way to compare times in MicroPython (it handles overflow).',
            '- On any error: we wait and call `machine.reset()`, instead of getting stuck.'
          )),
          anim('iot-evil-twin', 'Press ▶: a strong PSK stops the fake AP. And if the password leaks, TLS with your own CA is the second wall.'),
          text(
            '### Defense in depth',
            'The evil twin shows why one measure is not enough:',
            '1. **A strong, unique PSK** (or WPA3): the fake AP cannot complete the handshake.',
            '1. **A password that does not leak** (secrets out of Git, flash encryption).',
            '1. **TLS with certificate verification** (Mod. 4): even if the Wi‑Fi falls, the data cannot be read or altered.',
            '1. Optionally: **BSSID pinning** with `WiFi.begin(ssid, pass, 0, bssid)`, if you have a single AP (breaks on a mesh/router change).'
          ),
          nw('wifi', 'NetWatch\'s **Wi‑Fi Guard** checks the network you are on for encryption, **evil twin** and ARP spoofing. Try it on your home network.'),
          quiz('What does `WiFi.setMinSecurity(WIFI_AUTH_WPA2_PSK)` do?',
            ['It changes the password to WPA2', 'The ESP32 refuses to connect to networks weaker than WPA2-PSK (open, WEP, WPA)', 'It enables WPA3', 'It encrypts the flash'], 1,
            'If an attacker sets up an **open** network with the same name, the device simply does not connect.'),
          quiz('The attacker set up an evil twin and **knows** the Wi‑Fi password. What still protects the MQTT data?',
            ['The SSID', 'TLS with verification of the broker\'s certificate through your own CA', 'The RSSI', 'Nothing'], 1,
            'TLS encrypts the data and, with CA verification, stops the attacker from impersonating the broker.'),
        ],
      },
      {
        id: 'iot-3-3', title: 'Provisioning: configuring without passwords in the firmware', minutes: 15,
        goal: 'Store the credentials in **NVS** with `Preferences` instead of in the firmware, pass them in a safe way (provisioning) and know the risks of each method.',
        blocks: [
          text(
            'With `secrets.h` the password is not in Git, but it **is** inside the binary. If you build 10 sensors, you have to compile 10 times with a different `secrets.h`. And every `.bin` contains passwords.',
            '',
            '**Provisioning** is the process by which a device receives its credentials (Wi‑Fi, MQTT user) **after** flashing. The firmware stays the same for all of them, and each device holds its own secrets in **NVS** (non-volatile storage, a flash partition).'
          ),
          table(['Method', 'How', 'Security'], [
            ['Serial (USB)', 'You type the credentials from the computer over a cable', '✅ Needs physical access. Simple.'],
            ['Captive portal (WiFiManager)', 'The device opens its own AP with a settings page', '⚠️ Put a **password on the AP** and a timeout; otherwise anyone nearby configures it.'],
            ['BLE / SoftAP with ESP-IDF provisioning', 'ESP BLE Prov app, **Security 1/2** with proof-of-possession', '✅✅ Encrypted channel + a per-device code.'],
            ['Hardcoded', 'In the firmware', '❌ Every device has the same passwords.'],
          ]),
          code('cpp', 'provisioning.ino: Serial provisioning + Preferences (NVS)', R`
#include <WiFi.h>
#include <Preferences.h>

Preferences prefs;
const int PROV_BUTTON = 0;     // the BOOT button on most boards

String readLine(uint32_t timeoutMs) {
  Serial.setTimeout(timeoutMs);
  String s = Serial.readStringUntil('\n');
  s.trim();                    // removes \r and spaces
  return s;
}

void provisionOverSerial() {
  Serial.println("\n== PROVISIONING (60s per field) ==");
  Serial.print("SSID: ");
  String ssid = readLine(60000);
  Serial.print("\nWi-Fi password: ");
  String pass = readLine(60000);
  Serial.print("\nMQTT password: ");
  String mqttPass = readLine(60000);

  // Input check: 802.11 limits and a minimum length
  if (ssid.length() < 1 || ssid.length() > 32 ||
      pass.length() < 8 || pass.length() > 63 || mqttPass.length() < 12) {
    Serial.println("\n❌ Invalid credentials, nothing was saved.");
    return;
  }
  prefs.begin("creds", false);           // false = read/write
  prefs.putString("ssid", ssid);
  prefs.putString("pass", pass);
  prefs.putString("mqtt", mqttPass);
  prefs.end();
  Serial.println("\n✅ Saved to NVS. Restarting...");
  delay(500);
  ESP.restart();
}

void setup() {
  Serial.begin(115200);
  pinMode(PROV_BUTTON, INPUT_PULLUP);
  Serial.println("Press BOOT within 3s for provisioning...");
  uint32_t t0 = millis();
  while (millis() - t0 < 3000) {
    if (digitalRead(PROV_BUTTON) == LOW) { provisionOverSerial(); break; }
    delay(20);
  }

  prefs.begin("creds", true);            // true = read-only
  String ssid = prefs.getString("ssid", "");
  String pass = prefs.getString("pass", "");
  prefs.end();

  if (ssid.isEmpty()) {
    Serial.println("No credentials. Reset and press BOOT.");
    return;
  }
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setMinSecurity(WIFI_AUTH_WPA2_PSK);
  WiFi.begin(ssid.c_str(), pass.c_str());
  Serial.printf("Connecting to %s...\n", ssid.c_str());
}

void loop() {}
`, L(
            '- `Preferences`: a simple key-value store on top of NVS. The data survives a reboot and **a new flashing** of the app (as long as you do not erase the whole flash).',
            '- **Why "within 3s" and not "hold BOOT at reset"?** If GPIO0 is LOW at the moment of reset, the ESP32 enters the ROM **download mode** and does not run your program at all.',
            '- `readStringUntil(\'\\n\')` with a timeout: it does not hang forever if you type nothing.',
            '- Length check: the SSID is 1–32 bytes, the WPA2 passphrase 8–63 characters. Anything outside the limits is rejected.',
            '- `prefs.begin("creds", true)`: we open **read-only** when we are just reading.',
            '- The passwords are **never** printed to Serial.'
          )),
          warn(
            'NVS is **not** encrypted by default. Anyone with the device and a USB cable runs `esptool read_flash` and sees the passwords (Mod. 6). The fix is **Flash Encryption + NVS Encryption** (Mod. 5). Until then: a separate IoT Wi‑Fi (Mod. 7) and a unique MQTT password per device, so you do not lose "the whole house" if one sensor is stolen.'
          ),
          code('micropython', 'provision.py: the same in MicroPython (JSON file)', R`
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
        print("Invalid credentials")
        return
    with open(CFG, "w") as f:
        json.dump({"ssid": ssid, "pass": pw}, f)
    print("Saved. Reset...")
    time.sleep(1)
    machine.reset()


print("Press BOOT within 3s for provisioning")
t0 = time.ticks_ms()
while time.ticks_diff(time.ticks_ms(), t0) < 3000:
    if btn.value() == 0:
        provision()
        break
    time.sleep_ms(20)

cfg = load()
if cfg is None:
    print("No configuration")
else:
    print("Configuration for SSID:", cfg["ssid"])    # never the password
`, L(
            '- `input()` in MicroPython reads from the REPL (USB serial). You run it with `mpremote run provision.py` or through Thonny.',
            '- `json.load` inside a `try`: a corrupted file does not "take down" the device.',
            '- The same limit checks as in Arduino.',
            '- Here too the file is **plain text** in the flash.'
          )),
          tip('For many devices, the safest ready-made tool is ESP-IDF provisioning (`wifi_provisioning`, in newer versions also as `network_provisioning`) with **Security 2** (SRP6a + AES-GCM): each device has its own proof-of-possession, printed as a QR code on the box.'),
          quiz('Why do we not make the user hold BOOT (GPIO0) pressed **at the moment** of reset to enter provisioning?',
            ['Because the button burns out', 'Because with GPIO0 LOW at reset the ESP32 enters ROM download mode and does not run our program', 'Because it erases NVS', 'Because it disables Wi‑Fi'], 1,
            'GPIO0 is a **strapping pin**: its state at reset selects the boot mode. That is why we check the button shortly **after** startup.'),
          quiz('For a captive portal (WiFiManager), what is the most important measure?',
            ['A nice design', 'A password on the setup AP and a timeout, so that anyone passing by cannot configure it', 'Being on channel 1', 'Having the SSID "Setup"'], 1,
            'Without a password, anyone nearby can connect to the device\'s AP and give it **their own** Wi‑Fi, so all the traffic goes through them.'),
        ],
      },
    ],
  });

  ACADEMY.track({ id: 'iot', order: 2, title: '🔌 IoT Security: ESP32 & Raspberry Pi', level: 'Beginner → Advanced', desc: 'Secure your own ESP32 and Raspberry Pi projects step by step, with code that runs: hardening, MQTT with TLS, Secure Boot, segmentation, monitoring and a final project.', modules: M });
})();
