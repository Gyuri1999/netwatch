// 🦈 Wireshark: σημειώσεις (φίλτρα, εντολές tshark/tcpdump, συντομεύσεις) + ένα μικρό «Wireshark display filter»
// που τρέχει πάνω στα ζωντανά πακέτα του NetWatch (καρτέλα 📦 Πακέτα).
//
// Τα πακέτα της ροής έχουν: s/d (IP), p (TCP/UDP/ICMP/ARP…), a (εφαρμογή: HTTPS, DNS…), l (μήκος), sp/dp (θύρες),
// f (TCP flags «SA» ή ARP who-has/is-at), n (όνομα: DNS query / TLS SNI / HTTP host), nk (dns|sni|http), x (επιτιθέμενος).
// Ό,τι δεν υπάρχει εδώ (π.χ. tcp.analysis.*, eth.addr) το φίλτρο το λέει καθαρά: «δοκίμασέ το στο Wireshark».
(function () {
  'use strict';

  // ---------------- φίλτρο ----------------
  const APP = {  // λέξη πρωτοκόλλου → θύρες (και ετικέτα της ροής)
    dns: [53], mdns: [5353], llmnr: [5355], nbns: [137], http: [80, 8080, 8000, 8008, 8123, 8888], tls: [443, 8443, 993, 995, 465, 853, 8883, 5223],
    ssl: [443, 8443, 993, 995, 465, 853, 8883], quic: [443], ssh: [22], telnet: [23], ftp: [20, 21], smb: [445, 139], smb2: [445], rdp: [3389],
    mqtt: [1883, 8883], dhcp: [67, 68], bootp: [67, 68], ntp: [123], ssdp: [1900], snmp: [161, 162], smtp: [25, 587], imap: [143, 993],
    pop: [110, 995], vnc: [5900], sip: [5060], rtsp: [554], modbus: [502], coap: [5683], kerberos: [88], ldap: [389, 636], mysql: [3306],
    syslog: [514], tftp: [69], netbios: [137, 138, 139], irc: [6667], socks: [1080, 9050, 9150],
  };
  const UDP_ONLY = new Set(['quic', 'dhcp', 'bootp', 'ntp', 'ssdp', 'snmp', 'mdns', 'llmnr', 'nbns', 'coap', 'tftp', 'syslog']);
  const TCP_ONLY = new Set(['http', 'tls', 'ssl', 'ssh', 'telnet', 'ftp', 'smb', 'smb2', 'rdp', 'mqtt', 'smtp', 'imap', 'pop', 'vnc', 'rtsp', 'modbus', 'mysql', 'irc', 'ldap', 'socks']);
  const FLAG = { fin: 'F', syn: 'S', reset: 'R', rst: 'R', push: 'P', ack: 'A', urg: 'U', ece: 'E', cwr: 'C' };
  const FBIT = { F: 1, S: 2, R: 4, P: 8, A: 16, U: 32, E: 64, C: 128 };
  const isTCP = p => p.p === 'TCP' || (!!p.f && /^[FSRPAUEC]+$/.test(p.f) && p.p !== 'UDP');
  const isUDP = p => p.p === 'UDP' || p.a === 'QUIC';
  const ports = p => [p.sp, p.dp].filter(x => x != null);
  function proto(word, p) {
    if (word === 'ip') return !!p.s && !/:/.test(p.s) && p.p !== 'ARP';
    if (word === 'ipv6') return /:/.test(p.s || '');
    if (word === 'tcp') return isTCP(p);
    if (word === 'udp') return isUDP(p);
    if (word === 'icmp') return /^ICMP$/.test(p.p);
    if (word === 'icmpv6') return /ICMPv6/.test(p.p);
    if (word === 'arp') return p.p === 'ARP';
    if (word === 'eth' || word === 'frame') return true;
    if (word === 'dns' && p.nk === 'dns') return true;
    if ((word === 'tls' || word === 'ssl') && p.nk === 'sni') return true;
    if (word === 'http' && p.nk === 'http') return true;
    if (word === 'quic') return p.a === 'QUIC';
    const ps = APP[word];
    if (!ps) return undefined;
    if (UDP_ONLY.has(word) && !isUDP(p)) return false;
    if (TCP_ONLY.has(word) && !isTCP(p)) return false;
    return ports(p).some(x => ps.includes(x)) || (p.a || '').toLowerCase() === word;
  }
  // πεδίο → τιμές του πακέτου (λίστα· «ταιριάζει αν ταιριάζει έστω μία», όπως στο Wireshark)
  const FIELDS = {
    'ip.addr': p => [p.s, p.d], 'ip.src': p => [p.s], 'ip.dst': p => [p.d], 'ip.src_host': p => [p.s], 'ip.dst_host': p => [p.d],
    'ipv6.addr': p => [p.s, p.d].filter(x => /:/.test(x || '')), 'ipv6.src': p => /:/.test(p.s || '') ? [p.s] : [], 'ipv6.dst': p => /:/.test(p.d || '') ? [p.d] : [],
    'tcp.port': p => isTCP(p) ? ports(p) : [], 'udp.port': p => isUDP(p) ? ports(p) : [],
    'tcp.srcport': p => isTCP(p) ? [p.sp] : [], 'tcp.dstport': p => isTCP(p) ? [p.dp] : [],
    'udp.srcport': p => isUDP(p) ? [p.sp] : [], 'udp.dstport': p => isUDP(p) ? [p.dp] : [],
    'frame.len': p => [p.l], 'frame.cap_len': p => [p.l], 'ip.len': p => [p.l],
    'tcp.flags': p => isTCP(p) ? [[...(p.f || '')].reduce((n, c) => n | (FBIT[c] || 0), 0)] : [],
    'tcp.flags.str': p => isTCP(p) ? [p.f || ''] : [],
    'dns.qry.name': p => p.nk === 'dns' ? [p.n] : [],
    'tls.handshake.extensions_server_name': p => p.nk === 'sni' ? [p.n] : [],
    'ssl.handshake.extensions_server_name': p => p.nk === 'sni' ? [p.n] : [],
    'http.host': p => p.nk === 'http' ? [p.n] : [],
    'http.request': p => p.nk === 'http' ? [1] : [],  // το NetWatch κρατά το Host των αιτημάτων
    'tls.handshake.type': p => p.nk === 'sni' ? [1] : [],  // το SNI έρχεται μόνο στο Client Hello (type 1)
    'arp.opcode': p => p.p === 'ARP' ? [p.f === 'who-has' ? 1 : p.f === 'is-at' ? 2 : 0] : [],
  };
  for (const [k, c] of Object.entries(FLAG)) FIELDS['tcp.flags.' + k] = p => isTCP(p) ? [(p.f || '').includes(c) ? 1 : 0] : [];
  const KNOWN_WS = /^(eth|wlan|wlan_radio|radiotap|eapol|tcp\.analysis|tcp\.stream|tcp\.window_size|tcp\.len|tcp\.time|frame\.time|ip\.ttl|ip\.flags|icmp\.|dns\.|http\.|tls\.|ssl\.|dhcp\.|bootp\.|arp\.|vlan|stp|cdp|lldp|ospf|eigrp|hsrp|vrrp|mqtt\.|smb|ntlmssp|kerberos|ftp|telnet|x509|quic\.|udp\.length|len$)/;

  // IP / CIDR
  const ip4 = s => { const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s || ''); return m ? ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | +m[4]) >>> 0 : null; };
  function ipMatch(v, want) {
    const c = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(want);
    if (c) { const a = ip4(v), n = ip4(c[1]), b = +c[2]; if (a == null || n == null) return false; const m = b ? (0xffffffff << (32 - b)) >>> 0 : 0; return ((a & m) >>> 0) === ((n & m) >>> 0); }
    return String(v).toLowerCase() === String(want).toLowerCase();
  }

  function tokenize(s) {
    const out = [], re = /\s*(\(|\)|\{|\}|&&|\|\||!=|==|>=|<=|>|<|!|~|"(?:[^"\\]|\\.)*"|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){2,}|[A-Za-z_][\w.\-]*(?:\[[^\]]*\])?(?:\(\))?|[\w.:\/\-]+|\.\.)/y;
    let m, i = 0;
    s = s.trim();
    while (i < s.length) {
      re.lastIndex = i; m = re.exec(s);
      if (!m || m[0].trim() === '') { if (/^\s+$/.test(s.slice(i))) break; throw new Error(`Δεν καταλαβαίνω το «${s.slice(i, i + 12)}»`); }
      out.push(m[1]); i = re.lastIndex;
    }
    return out;
  }
  const OPS = { '==': 'eq', eq: 'eq', '!=': 'ne', ne: 'ne', '>': 'gt', gt: 'gt', '<': 'lt', lt: 'lt', '>=': 'ge', ge: 'ge', '<=': 'le', le: 'le', contains: 'contains', matches: 'matches', '~': 'matches', in: 'in' };
  function parse(src) {
    const T = tokenize(src); let k = 0;
    const peek = () => T[k], next = () => T[k++], low = () => (T[k] || '').toLowerCase();
    function orE() { let a = andE(); while (low() === 'or' || peek() === '||' || low() === 'xor' || peek() === '^^') { const x = next().toLowerCase(), b = andE(), A = a; a = x === 'xor' || x === '^^' ? (p => A(p) !== b(p)) : (p => A(p) || b(p)); } return a; }
    function andE() { let a = notE(); while (low() === 'and' || peek() === '&&') { next(); const b = notE(), A = a; a = p => A(p) && b(p); } return a; }
    function notE() { if (low() === 'not' || peek() === '!') { next(); const a = notE(); return p => !a(p); } return prim(); }
    function value() {
      let v = next(); if (v == null) throw new Error('Λείπει τιμή στο τέλος');
      if (v[0] === '"') v = v.slice(1, -1).replace(/\\(.)/g, '$1');
      return v;
    }
    function prim() {
      const t = next();
      if (t == null) throw new Error('Το φίλτρο τελειώνει απότομα');
      if (t === '(') { const a = orE(); if (next() !== ')') throw new Error('Λείπει μια «)»'); return a; }
      const f = t.toLowerCase();
      const opTok = low(), op = OPS[opTok];
      const get = FIELDS[f];
      if (!op) {  // σκέτο πρωτόκολλο ή «υπάρχει το πεδίο»
        if (get) return p => get(p).some(x => x != null && x !== '');
        const pr = probe(f);
        if (pr) return pr;
        throw unsupported(f);
      }
      next();
      if (!get) throw unsupported(f);
      if (op === 'in') {
        if (next() !== '{') throw new Error('Μετά το «in» θέλει { … }');
        const set = []; while (peek() && peek() !== '}') { const a = value(), r = /^(\d+)\.\.(\d+)$/.exec(a); if (r) set.push([r[1], r[2]]); else if (peek() === '..') { next(); set.push([a, value()]); } else set.push([a]); if (peek() === ',') next(); }
        if (next() !== '}') throw new Error('Λείπει η «}»');
        return p => get(p).some(v => set.some(([a, b]) => b == null ? cmp(v, 'eq', a) : (+v >= +a && +v <= +b)));
      }
      const want = value();
      if (op === 'matches') { let rx; try { rx = new RegExp(want, 'i'); } catch (e) { throw new Error('Κακό regex: ' + want); } return p => get(p).some(v => v != null && rx.test(String(v))); }
      if (op === 'ne') return p => !get(p).some(v => cmp(v, 'eq', want));  // Wireshark ≥ 3.6: a != b ≡ !(a == b)
      return p => get(p).some(v => cmp(v, op, want));
    }
    function probe(word) { const test = { s: '1.1.1.1', d: '1.1.1.1', p: 'TCP', a: '', sp: 1, dp: 1 }; if (proto(word, test) === undefined) return null; return p => !!proto(word, p); }
    function unsupported(f) { const e = new Error(KNOWN_WS.test(f) ? `Το «${f}» είναι σωστό φίλτρο Wireshark, αλλά το NetWatch δεν κρατά αυτό το πεδίο — δοκίμασέ το στο Wireshark.` : `Άγνωστο πεδίο ή πρωτόκολλο: «${f}»`); e.ws = KNOWN_WS.test(f); return e; }
    const fn = orE();
    if (k < T.length) throw new Error(`Περίσσευμα στο τέλος: «${T.slice(k).join(' ')}»`);
    return fn;
  }
  function cmp(v, op, want) {
    if (v == null) return false;
    if (op === 'contains') return String(v).toLowerCase().includes(String(want).toLowerCase());
    if (ip4(String(v)) != null || /:/.test(String(v)) && /[:\/]/.test(String(want))) { if (op === 'eq') return ipMatch(v, want); }
    const nv = Number(v), nw = /^0x[0-9a-f]+$/i.test(want) ? parseInt(want, 16) : Number(want);
    if (!isNaN(nv) && !isNaN(nw) && String(want).trim() !== '') return { eq: nv === nw, gt: nv > nw, lt: nv < nw, ge: nv >= nw, le: nv <= nw }[op];
    if (op === 'eq') return String(v).toLowerCase() === String(want).toLowerCase();
    return false;
  }
  const cache = new Map();
  function compile(src) {
    src = (src || '').trim(); if (!src) return { ok: true, fn: null };
    if (cache.has(src)) return cache.get(src);
    let r; try { r = { ok: true, fn: parse(src) }; } catch (e) { r = { ok: false, err: e.message, ws: !!e.ws }; }
    if (cache.size > 300) cache.clear(); cache.set(src, r); return r;
  }

  // ---------------- σημειώσεις ----------------
  // [κείμενο, ελληνικά, english]
  const SHEET = [
    { id: 'basic', icon: '🔰', el: 'Βασικά φίλτρα (display filters)', en: 'Basic display filters', kind: 'display', items: [
      ['tcp', 'Μόνο TCP.', 'TCP only.'], ['udp', 'Μόνο UDP.', 'UDP only.'], ['icmp', 'Ping, «host unreachable», traceroute.', 'Ping, “host unreachable”, traceroute.'],
      ['arp', 'Ποιος έχει ποια IP στο LAN (ARP).', 'Who has which IP on the LAN (ARP).'], ['dns', 'Ερωτήματα και απαντήσεις DNS.', 'DNS queries and answers.'],
      ['http', 'Απλό HTTP (χωρίς κρυπτογράφηση).', 'Plain HTTP (unencrypted).'], ['tls', 'HTTPS και ό,τι άλλο κρυπτογραφείται με TLS.', 'HTTPS and anything else using TLS.'], ['quic', 'HTTP/3 πάνω από UDP 443.', 'HTTP/3 over UDP 443.'],
      ['ip.addr == 192.168.1.17', 'Ό,τι πάει ή έρχεται από αυτή την IP.', 'Anything to or from this IP.'],
      ['ip.src == 192.168.1.49', 'Μόνο ό,τι στέλνει αυτή η IP.', 'Only what this IP sends.'], ['ip.dst == 192.168.1.1', 'Μόνο ό,τι πάει προς αυτή την IP.', 'Only what goes to this IP.'],
      ['ip.addr == 192.168.1.0/24', 'Όλο το subnet (CIDR).', 'The whole subnet (CIDR).'],
      ['ip.src == 192.168.1.0/24 && !(ip.dst == 192.168.1.0/24)', 'Ό,τι βγαίνει από το LAN προς το Internet.', 'Everything leaving the LAN for the Internet.'],
      ['!(arp or dns or mdns or ssdp)', 'Κρύψε τον «θόρυβο» του LAN για να δεις τα ουσιώδη.', 'Hide LAN chatter to see what matters.'],
      ['tcp.port == 22', 'SSH (και στις δύο κατευθύνσεις).', 'SSH (both directions).'], ['udp.port == 53', 'DNS μέσω UDP.', 'DNS over UDP.'],
      ['tcp.port in {80 443 8080}', 'Πολλές θύρες μαζί.', 'Several ports at once.'], ['tcp.dstport in {8000..8100}', 'Εύρος θυρών.', 'A range of ports.'],
      ['frame.len > 1000', 'Μεγάλα πακέτα (μεταφορά δεδομένων).', 'Large packets (data transfer).'],
      ['ip.addr == 192.168.1.17 && tcp.port == 1883', 'Συνδυασμός: ο broker MQTT και μόνο MQTT.', 'Combined: the MQTT broker, MQTT only.'],
      ['not tcp.port == 22', 'Όλα εκτός από SSH (χρήσιμο όταν καταγράφεις μέσω SSH).', 'Everything except SSH (handy when capturing over SSH).'],
    ] },
    { id: 'tcp', icon: '🤝', el: 'TCP: συνδέσεις και προβλήματα', en: 'TCP: connections and problems', kind: 'display', items: [
      ['tcp.flags.syn == 1 && tcp.flags.ack == 0', 'Απόπειρες σύνδεσης (το πρώτο SYN). Πολλές σε λίγο χρόνο = σάρωση.', 'Connection attempts (first SYN). Many in a short time = a scan.'],
      ['tcp.flags.syn == 1 && tcp.flags.ack == 1', 'SYN-ACK: η θύρα είναι ανοιχτή και απαντά.', 'SYN-ACK: the port is open and answering.'],
      ['tcp.flags.reset == 1', 'RST: κλειστή θύρα ή απότομο κλείσιμο.', 'RST: closed port or abrupt close.'], ['tcp.flags.fin == 1', 'FIN: κανονικό κλείσιμο σύνδεσης.', 'FIN: normal connection close.'],
      ['tcp.flags == 0x002', 'Μόνο SYN (όλα τα άλλα flags 0).', 'SYN only (all other flags 0).'], ['tcp.flags == 0x012', 'Ακριβώς SYN+ACK.', 'Exactly SYN+ACK.'],
      ['tcp.analysis.retransmission', 'Αναμεταδόσεις: χαμένα πακέτα, κακό Wi‑Fi/καλώδιο.', 'Retransmissions: lost packets, bad Wi‑Fi/cable.'],
      ['tcp.analysis.flags && !tcp.analysis.window_update', 'Όλα τα «προβλήματα» TCP που βρίσκει το Wireshark.', 'Every TCP “problem” Wireshark detects.'],
      ['tcp.analysis.duplicate_ack', 'Διπλά ACK: ο παραλήπτης περιμένει κάτι που χάθηκε.', 'Duplicate ACKs: the receiver is waiting for something lost.'],
      ['tcp.analysis.zero_window', 'Ο παραλήπτης «γέμισε» — αργή εφαρμογή/δίσκος.', 'The receiver is full — slow app or disk.'],
      ['tcp.time_delta > 1', 'Παύσεις πάνω από 1″ μέσα σε μια σύνδεση (θέλει «Calculate conversation timestamps»).', 'Gaps over 1 s inside a connection (needs “Calculate conversation timestamps”).'],
      ['tcp.stream eq 5', 'Μία ολόκληρη σύνδεση (αριθμός από Follow TCP Stream).', 'One whole connection (number from Follow TCP Stream).'],
      ['tcp.len > 0', 'Μόνο πακέτα με δεδομένα (όχι σκέτα ACK).', 'Only packets carrying data (no bare ACKs).'],
      ['tcp.window_size == 0 && tcp.flags.reset != 1', 'Μηδενικό παράθυρο χωρίς RST.', 'Zero window without RST.'],
    ] },
    { id: 'dns', icon: '🔤', el: 'DNS', en: 'DNS', kind: 'display', items: [
      ['dns.flags.response == 0', 'Μόνο ερωτήματα.', 'Queries only.'], ['dns.flags.response == 1', 'Μόνο απαντήσεις.', 'Answers only.'],
      ['dns.qry.name contains "google"', 'Ερωτήματα που περιέχουν μια λέξη.', 'Queries containing a word.'],
      ['dns.qry.name matches "\\\\.(xyz|top|tk|zip)$"', 'Ύποπτα TLD (regex).', 'Suspicious TLDs (regex).'],
      ['dns.flags.rcode == 3', 'NXDOMAIN: το όνομα δεν υπάρχει. Πολλά = malware με DGA.', 'NXDOMAIN: name doesn\'t exist. Many = DGA malware.'],
      ['dns.qry.type == 28', 'Ερωτήματα AAAA (IPv6).', 'AAAA queries (IPv6).'], ['dns.qry.type == 16', 'TXT: χρησιμοποιείται και για DNS tunneling.', 'TXT: also used for DNS tunnelling.'],
      ['len(dns.qry.name) > 50', 'Πολύ μακριά ονόματα: tunneling ή DGA.', 'Very long names: tunnelling or DGA.'],
      ['dns.a == 93.184.216.34', 'Ποιο όνομα έδωσε αυτή την IP.', 'Which name resolved to this IP.'],
      ['dns && !(ip.addr == 192.168.1.1)', 'DNS που δεν περνά από τον router (π.χ. συσκευή με «δικό της» DNS).', 'DNS that bypasses the router (e.g. a device with its own DNS).'],
      ['dns.time > 0.2', 'Αργές απαντήσεις DNS (> 200 ms).', 'Slow DNS answers (> 200 ms).'],
      ['mdns', 'Bonjour/AirPlay/εκτυπωτές που ανακοινώνονται στο LAN.', 'Bonjour/AirPlay/printers announcing themselves.'], ['llmnr or nbns', 'Παλιά ονόματα Windows — στόχος του Responder.', 'Legacy Windows naming — a Responder target.'],
    ] },
    { id: 'web', icon: '🌐', el: 'HTTP & TLS', en: 'HTTP & TLS', kind: 'display', items: [
      ['http.request', 'Μόνο αιτήματα HTTP.', 'HTTP requests only.'], ['http.request.method == "POST"', 'POST: εδώ πάνε φόρμες και κωδικοί.', 'POST: forms and passwords go here.'],
      ['http.response.code >= 400', 'Σφάλματα (404, 500…).', 'Errors (404, 500…).'], ['http.host contains "192.168"', 'Αιτήματα σε τοπικές συσκευές.', 'Requests to local devices.'],
      ['http.authorization', 'Basic auth: ο κωδικός φαίνεται (base64)!', 'Basic auth: the password is visible (base64)!'],
      ['http.cookie', 'Cookies σε απλό HTTP — κλέβονται εύκολα.', 'Cookies over plain HTTP — easy to steal.'],
      ['http.user_agent contains "curl"', 'Ποιο πρόγραμμα κάνει τα αιτήματα.', 'Which program is making requests.'],
      ['http.request.uri contains "login"', 'Σελίδες σύνδεσης.', 'Login pages.'],
      ['tls.handshake.type == 1', 'Client Hello: η αρχή κάθε HTTPS σύνδεσης.', 'Client Hello: the start of every HTTPS connection.'],
      ['tls.handshake.extensions_server_name contains "github"', 'Σε ποιο site πας, ακόμα και με HTTPS (SNI).', 'Which site you visit, even over HTTPS (SNI).'],
      ['tls.handshake.version < 0x0303', 'Παλιό TLS 1.0/1.1 — ευάλωτο.', 'Old TLS 1.0/1.1 — vulnerable.'],
      ['tls.alert_message', 'Αποτυχίες TLS (λάθος πιστοποιητικό κ.λπ.).', 'TLS failures (bad certificate etc.).'],
      ['x509ce.dNSName contains "local"', 'Ονόματα μέσα στα πιστοποιητικά.', 'Names inside certificates.'],
      ['quic', 'HTTP/3 (UDP 443) — το Wireshark βλέπει μόνο το SNI.', 'HTTP/3 (UDP 443) — Wireshark only sees the SNI.'],
    ] },
    { id: 'lan', icon: '🏠', el: 'LAN, CCNA & υποδομή', en: 'LAN, CCNA & infrastructure', kind: 'display', items: [
      ['arp.opcode == 1', 'ARP request: «ποιος έχει την 192.168.1.1;»', 'ARP request: “who has 192.168.1.1?”'], ['arp.opcode == 2', 'ARP reply: «εγώ, με αυτή τη MAC».', 'ARP reply: “me, with this MAC”.'],
      ['arp.duplicate-address-detected', 'Δύο MAC για την ίδια IP — πιθανό ARP spoofing!', 'Two MACs for one IP — possible ARP spoofing!'],
      ['eth.dst == ff:ff:ff:ff:ff:ff', 'Broadcast (σε όλους).', 'Broadcast (to everyone).'], ['eth.addr == aa:bb:cc:dd:ee:ff', 'Μια συσκευή με βάση τη MAC.', 'One device by MAC.'],
      ['eth.src[0:3] == 24:0a:c4', 'Κατασκευαστής από το OUI (εδώ Espressif/ESP32).', 'Manufacturer by OUI (here Espressif/ESP32).'],
      ['dhcp', 'DHCP: DORA (Discover, Offer, Request, Ack).', 'DHCP: DORA (Discover, Offer, Request, Ack).'],
      ['dhcp.option.dhcp == 1', 'DHCP Discover: μια συσκευή μόλις μπήκε.', 'DHCP Discover: a device just joined.'], ['dhcp.option.hostname', 'Το όνομα που δηλώνει κάθε συσκευή.', 'The name each device announces.'],
      ['icmp.type == 8', 'Echo request (ping).', 'Echo request (ping).'], ['icmp.type == 3', 'Destination unreachable.', 'Destination unreachable.'],
      ['icmp.type == 11', 'TTL exceeded: έτσι δουλεύει το traceroute.', 'TTL exceeded: how traceroute works.'], ['ip.ttl < 5', 'Πακέτα κοντά στη «λήξη» τους (loops/traceroute).', 'Packets about to expire (loops/traceroute).'],
      ['vlan.id == 10', '802.1Q: κίνηση στο VLAN 10 (trunk).', '802.1Q: traffic in VLAN 10 (trunk).'], ['stp', 'Spanning Tree (BPDU).', 'Spanning Tree (BPDU).'],
      ['cdp or lldp', 'Γείτονες: switch/τηλέφωνα αυτοσυστήνονται.', 'Neighbours: switches/phones introduce themselves.'],
      ['ospf', 'OSPF: Hello, LSA, γειτονίες.', 'OSPF: Hellos, LSAs, adjacencies.'], ['eigrp', 'EIGRP (Cisco).', 'EIGRP (Cisco).'], ['hsrp or vrrp', 'Εφεδρικό gateway (FHRP).', 'Backup gateway (FHRP).'],
      ['ipv6 && icmpv6.type == 134', 'IPv6 Router Advertisement.', 'IPv6 Router Advertisement.'], ['ntp', 'Συγχρονισμός ώρας.', 'Time sync.'], ['snmp', 'SNMP: διαχείριση συσκευών (ψάξε «public»).', 'SNMP: device management (look for “public”).'],
    ] },
    { id: 'wifi', icon: '📡', el: 'Wi‑Fi (802.11, monitor mode)', en: 'Wi‑Fi (802.11, monitor mode)', kind: 'display', items: [
      ['wlan.fc.type_subtype == 0x0c', 'Deauthentication: πολλά = επίθεση deauth.', 'Deauthentication: many = deauth attack.'],
      ['wlan.fc.type_subtype == 0x0a', 'Disassociation.', 'Disassociation.'], ['wlan.fc.type_subtype == 0x08', 'Beacons: τα δίκτυα που ανακοινώνονται.', 'Beacons: networks announcing themselves.'],
      ['wlan.fc.type_subtype == 0x04', 'Probe requests: δίκτυα που «θυμάται» ένα κινητό.', 'Probe requests: networks a phone “remembers”.'],
      ['eapol', 'WPA 4-way handshake.', 'WPA 4-way handshake.'], ['wlan.ssid == "MyWiFi"', 'Ένα δίκτυο με το όνομά του.', 'One network by name.'],
      ['wlan.bssid == aa:bb:cc:dd:ee:ff', 'Ένα access point.', 'One access point.'], ['wlan_radio.signal_dbm > -50', 'Πολύ δυνατό σήμα (πολύ κοντά).', 'Very strong signal (very close).'],
      ['wlan.fc.retry == 1', 'Αναμεταδόσεις στον αέρα: παρεμβολές.', 'Over-the-air retries: interference.'],
    ] },
    { id: 'atk', icon: '🚨', el: 'Επιθέσεις & κυνήγι (threat hunting)', en: 'Attacks & threat hunting', kind: 'display', items: [
      ['tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size <= 1024', 'Υπογραφή του nmap -sS.', 'The nmap -sS signature.'],
      ['tcp.flags == 0x029', 'Xmas scan (FIN+PSH+URG).', 'Xmas scan (FIN+PSH+URG).'], ['tcp.flags == 0x000', 'NULL scan.', 'NULL scan.'],
      ['tcp.flags.fin == 1 && tcp.flags.ack == 0', 'FIN scan.', 'FIN scan.'], ['icmp.type == 3 && icmp.code == 3', 'Port unreachable: απαντήσεις σε UDP scan.', 'Port unreachable: replies to a UDP scan.'],
      ['tcp.dstport == 22 && tcp.flags.syn == 1 && tcp.flags.ack == 0', 'Brute force SSH: πολλές νέες συνδέσεις.', 'SSH brute force: many new connections.'],
      ['ftp.request.command == "PASS"', 'Κωδικοί FTP σε καθαρό κείμενο.', 'FTP passwords in clear text.'], ['telnet', 'Telnet: όλα σε καθαρό κείμενο.', 'Telnet: everything in clear text.'],
      ['ntlmssp', 'Πιστοποίηση Windows (NTLM) — hashes.', 'Windows authentication (NTLM) — hashes.'], ['kerberos', 'Kerberos (Active Directory).', 'Kerberos (Active Directory).'],
      ['icmp && frame.len > 500', 'Μεγάλα ping: πιθανό ICMP tunnel.', 'Large pings: possible ICMP tunnel.'],
      ['tcp.port in {4444 1337 31337 6667}', 'Θύρες κλασικών backdoor/IRC bots.', 'Classic backdoor/IRC bot ports.'], ['tcp.port in {9001 9030 9050 9150}', 'Tor.', 'Tor.'],
      ['mqtt.msgtype == 3', 'MQTT PUBLISH: ποιος στέλνει εντολές.', 'MQTT PUBLISH: who sends commands.'], ['mqtt.topic contains "cmd"', 'Εντολές σε συσκευές IoT.', 'Commands to IoT devices.'],
      ['mqtt.msgtype == 1', 'MQTT CONNECT (δες username/password αν δεν έχει TLS).', 'MQTT CONNECT (see username/password without TLS).'],
      ['modbus or coap', 'Βιομηχανικά / IoT πρωτόκολλα.', 'Industrial / IoT protocols.'],
      ['http.request && !(http.user_agent)', 'HTTP χωρίς User-Agent: συχνά scripts/malware.', 'HTTP without a User-Agent: often scripts/malware.'],
      ['dns.flags.rcode == 3 && dns.flags.response == 1', 'Κύμα NXDOMAIN: DGA.', 'A wave of NXDOMAIN: DGA.'],
    ] },
    { id: 'bpf', icon: '🎯', el: 'Capture filters (BPF — πριν την καταγραφή)', en: 'Capture filters (BPF — before capturing)', kind: 'capture', items: [
      ['host 192.168.1.17', 'Μόνο μία συσκευή.', 'One device only.'], ['net 192.168.1.0/24', 'Ένα subnet.', 'One subnet.'], ['port 1883', 'Μία θύρα (TCP ή UDP).', 'One port (TCP or UDP).'],
      ['not port 22', 'Όχι SSH — απαραίτητο όταν καταγράφεις μέσω SSH.', 'No SSH — essential when capturing over SSH.'], ['tcp portrange 1-1024', 'Εύρος θυρών.', 'A port range.'],
      ['src host 192.168.1.20 and dst port 53', 'Τα DNS ενός ESP32.', 'An ESP32\'s DNS queries.'], ['ether host aa:bb:cc:dd:ee:ff', 'Με βάση τη MAC.', 'By MAC.'],
      ['arp or icmp', 'Μόνο ARP και ping.', 'ARP and ping only.'], ['udp port 67 or udp port 68', 'Μόνο DHCP.', 'DHCP only.'],
      ['tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0', 'Μόνο νέες συνδέσεις (SYN).', 'New connections only (SYN).'],
      ['not broadcast and not multicast', 'Χωρίς θόρυβο του LAN.', 'Without LAN chatter.'], ['greater 1000', 'Πακέτα πάνω από 1000 bytes.', 'Packets over 1000 bytes.'],
      ['vlan and host 10.0.10.5', 'Μέσα σε trunk 802.1Q.', 'Inside an 802.1Q trunk.'], ['host 192.168.1.17 and not port 22', 'Ο broker, χωρίς τη δική σου SSH.', 'The broker, without your own SSH.'],
    ] },
    { id: 'cli', icon: '⌨️', el: 'Εντολές: tshark, tcpdump, dumpcap', en: 'Commands: tshark, tcpdump, dumpcap', kind: 'cmd', items: [
      ['tshark -D', 'Λίστα με τις κάρτες δικτύου.', 'List network interfaces.'],
      ['tshark -i en0 -f "port 53"', 'Ζωντανά DNS (capture filter).', 'Live DNS (capture filter).'],
      ['tshark -i en0 -Y "dns.flags.response == 0" -T fields -e ip.src -e dns.qry.name', 'Ποιος ρωτά ποιο όνομα — ως στήλες.', 'Who asks for which name — as columns.'],
      ['tshark -r capture.pcapng -Y "http.request" -T fields -e http.host -e http.request.uri', 'Όλα τα URL από ένα pcap.', 'Every URL from a pcap.'],
      ['tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name | sort | uniq -c | sort -rn', 'Top sites (SNI) με πλήθος.', 'Top sites (SNI) with counts.'],
      ['tshark -r capture.pcapng -q -z io,phs', 'Ιεραρχία πρωτοκόλλων (τι υπάρχει στο pcap).', 'Protocol hierarchy (what is in the pcap).'],
      ['tshark -r capture.pcapng -q -z conv,tcp', 'Συνομιλίες TCP: ποιος με ποιον, πόσα bytes.', 'TCP conversations: who with whom, how many bytes.'],
      ['tshark -r capture.pcapng -q -z endpoints,ip', 'Όλες οι IP με κίνηση.', 'Every IP with traffic.'], ['tshark -r capture.pcapng -q -z dns,tree', 'Στατιστικά DNS.', 'DNS statistics.'],
      ['tshark -r capture.pcapng -q -z http,tree', 'Στατιστικά HTTP (κωδικοί, μέθοδοι).', 'HTTP statistics (codes, methods).'],
      ['tshark -r capture.pcapng --export-objects http,./files', 'Βγάλε τα αρχεία που κατέβηκαν μέσω HTTP.', 'Extract files downloaded over HTTP.'],
      ['tshark -r capture.pcapng -q -z follow,tcp,ascii,0', 'Follow TCP stream 0 στο τερματικό.', 'Follow TCP stream 0 in the terminal.'],
      ['tshark -i en0 -b filesize:10000 -b files:5 -w ring.pcapng', 'Ring buffer: 5 αρχεία × 10 MB, γράφει για πάντα.', 'Ring buffer: 5 files × 10 MB, records forever.'],
      ['dumpcap -i en0 -a duration:60 -w minute.pcapng', 'Καταγραφή για 60″ και σταμάτα.', 'Capture for 60 s then stop.'],
      ['sudo tcpdump -i en0 -nn -c 100 port 1883', '100 πακέτα MQTT, χωρίς ονόματα (-nn).', '100 MQTT packets, no name lookups (-nn).'],
      ['sudo tcpdump -i en0 -w capture.pcap not port 22', 'Γράψε σε αρχείο για το Wireshark.', 'Write to a file for Wireshark.'],
      ['sudo tcpdump -i en0 -A -s0 port 80', 'Δες το περιεχόμενο HTTP ως κείμενο.', 'See HTTP content as text.'],
      ['ssh pi@192.168.1.30 "sudo tcpdump -U -s0 -w - not port 22" | wireshark -k -i -', 'Ζωντανή καταγραφή από άλλη συσκευή στο Wireshark σου.', 'Live capture from another box into your Wireshark.'],
      ['capinfos capture.pcapng', 'Πληροφορίες αρχείου: διάρκεια, πακέτα, μέγεθος.', 'File info: duration, packets, size.'],
      ['editcap -A "2026-11-17 14:00:00" -B "2026-11-17 14:10:00" in.pcapng out.pcapng', 'Κόψε ένα χρονικό διάστημα.', 'Cut a time window.'],
      ['mergecap -w all.pcapng a.pcapng b.pcapng', 'Ένωσε pcap.', 'Merge pcaps.'],
      ['export SSLKEYLOGFILE=~/sslkeys.log', 'Ο browser γράφει τα κλειδιά TLS → το Wireshark αποκρυπτογραφεί το δικό σου HTTPS.', 'The browser logs TLS keys → Wireshark decrypts your own HTTPS.'],
      ['tshark -r capture.pcapng -o tls.keylog_file:sslkeys.log -Y http2', 'Αποκρυπτογράφηση με το keylog.', 'Decrypt using the keylog.'],
    ] },
    { id: 'ui', icon: '🖱', el: 'Wireshark: μενού & συντομεύσεις', en: 'Wireshark: menus & shortcuts', kind: 'ui', items: [
      ['Ctrl+/  (⌘/)', 'Πήγαινε στη γραμμή φίλτρου.', 'Jump to the filter bar.'], ['Ctrl+F  (⌘F)', 'Βρες πακέτο (κείμενο, hex, φίλτρο).', 'Find a packet (string, hex, filter).'],
      ['Ctrl+G  (⌘G)', 'Πήγαινε στο πακέτο Ν.', 'Go to packet N.'], ['Ctrl+M  (⌘M)', 'Σημάδεψε πακέτο.', 'Mark a packet.'],
      ['Δεξί κλικ → Apply as Filter → Selected', 'Φτιάξε φίλτρο από οποιοδήποτε πεδίο — ο πιο γρήγορος τρόπος να μάθεις τα ονόματα πεδίων.', 'Build a filter from any field — the fastest way to learn field names.'],
      ['Δεξί κλικ → Follow → TCP Stream', 'Όλη η «συζήτηση» ως κείμενο.', 'The whole “conversation” as text.'],
      ['Statistics → Conversations', 'Ποιος μίλησε με ποιον και πόσο.', 'Who talked to whom and how much.'], ['Statistics → Protocol Hierarchy', 'Τι πρωτόκολλα υπάρχουν.', 'Which protocols are present.'],
      ['Statistics → I/O Graphs', 'Γράφημα κίνησης στον χρόνο.', 'Traffic graph over time.'], ['Statistics → Flow Graph', 'Διάγραμμα ροής (handshake, DORA…).', 'Flow diagram (handshakes, DORA…).'],
      ['Analyze → Expert Information', 'Λίστα με ό,τι «ύποπτο» βρήκε το Wireshark.', 'Everything “odd” Wireshark found.'],
      ['Analyze → Decode As…', 'Πες του ότι η θύρα 8883 είναι MQTT/TLS κ.λπ.', 'Tell it port 8883 is MQTT/TLS etc.'],
      ['View → Time Display Format → Since Previous Displayed', 'Χρόνος από το προηγούμενο πακέτο — για καθυστερήσεις.', 'Time since the previous packet — for delays.'],
      ['View → Name Resolution', 'Ονόματα αντί για IP/MAC (κατασκευαστής από το OUI).', 'Names instead of IP/MAC (vendor from OUI).'],
      ['File → Export Objects → HTTP', 'Αποθήκευσε αρχεία από την καταγραφή.', 'Save files from the capture.'],
      ['Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log', 'Το SSLKEYLOGFILE για αποκρυπτογράφηση.', 'The SSLKEYLOGFILE for decryption.'],
      ['Edit → Configuration Profiles', 'Ξεχωριστές στήλες/χρώματα για Wi‑Fi, IoT, CCNA.', 'Separate columns/colours for Wi‑Fi, IoT, CCNA.'],
      ['View → Coloring Rules', 'Βάψε κόκκινα τα RST, κίτρινα τα DNS…', 'Colour RSTs red, DNS yellow…'],
    ] },
  ];
  const OPS_HELP = [['== / eq', 'ίσο', 'equal'], ['!= / ne', 'διάφορο', 'not equal'], ['> < >= <=', 'μεγαλύτερο / μικρότερο', 'greater / less'], ['contains', 'περιέχει κείμενο', 'contains text'],
    ['matches / ~', 'regex', 'regex'], ['in {80 443}', 'ένα από', 'one of'], ['&& / and', 'και', 'and'], ['|| / or', 'ή', 'or'], ['! / not', 'όχι', 'not'], ['( … )', 'ομαδοποίηση', 'grouping']];

  window.WS = { compile, SHEET, OPS_HELP, live: s => { const r = compile(s); return r.ok && !!r.fn; } };
})();
