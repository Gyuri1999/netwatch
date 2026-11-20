// ───────────────────────── 🧾 ACL tester (Cisco IOS) — ποια γραμμή ταιριάζει, γιατί, και ποιες δεν θα ταιριάξουν ποτέ ─────────────────────────
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(typeof window !== 'undefined' && window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;

  // ═════════════ βοηθητικά ═════════════
  const ip2n = s => { const p = String(s).split('.'); if (p.length !== 4) return null; let n = 0;
    for (const x of p) { if (!/^\d{1,3}$/.test(x) || +x > 255) return null; n = n * 256 + +x; } return n; };
  const n2ip = n => [24, 16, 8, 0].map(s => Math.floor(n / 2 ** s) % 256).join('.');
  const and = (a, b) => (a & b) >>> 0, not = a => (~a) >>> 0;
  const PORTS = { ftp: 21, 'ftp-data': 20, ssh: 22, telnet: 23, smtp: 25, domain: 53, www: 80, http: 80, pop3: 110, ntp: 123, bgp: 179, https: 443, bootps: 67, bootpc: 68, tftp: 69, snmp: 161, snmptrap: 162, syslog: 514, isakmp: 500, rip: 520, mqtt: 1883, 'secure-mqtt': 8883 };
  const PROTOS = { ip: 0, icmp: 1, tcp: 6, udp: 17, gre: 47, esp: 50, ahp: 51, ospf: 89, eigrp: 88 };
  const ALL = [[0, 65535]];
  const port = s => /^\d+$/.test(s) && +s <= 65535 ? +s : PORTS[String(s).toLowerCase()] ?? null;

  // «192.168.1.0 0.0.0.255» | «host 10.1.1.1» | «any» → {addr, wild, text}, πόσα tokens έφαγε
  function addrSpec(t, i, warn) {
    const w = (t[i] || '').toLowerCase();
    if (w === 'any') return [{ addr: 0, wild: 0xFFFFFFFF, text: 'any' }, 1];
    if (w === 'host') { const a = ip2n(t[i + 1]); if (a == null) throw T('μετά το «host» θέλει IP', '“host” needs an IP'); return [{ addr: a, wild: 0, text: 'host ' + t[i + 1] }, 2]; }
    const a = ip2n(t[i]); if (a == null) throw T(`περίμενα IP, «host» ή «any» αντί για «${t[i] || '…'}»`, `expected an IP, “host” or “any” instead of “${t[i] || '…'}”`);
    const wl = ip2n(t[i + 1]);
    if (wl == null) return [{ addr: a, wild: 0, text: t[i] }, 1];  // σκέτη IP = host (standard ACL)
    const maskLike = /^(255|254|252|248|240|224|192|128)\./.test(t[i + 1]) && t[i + 1] !== '255.255.255.255';
    if (maskLike)
      warn.push(T(`Το «${t[i + 1]}» μοιάζει με μάσκα subnet — τα ACL θέλουν <b>wildcard</b> (ανάποδα: π.χ. 255.255.255.0 → 0.0.0.255).`, `“${t[i + 1]}” looks like a subnet mask — ACLs need a <b>wildcard</b> (inverted: e.g. 255.255.255.0 → 0.0.0.255).`));
    else if (and(a, wl)) warn.push(T(`Η ${t[i]} έχει bits μέσα στο wildcard ${t[i + 1]} — το IOS θα τη γράψει ως ${n2ip(and(a, not(wl)))}.`, `${t[i]} has bits inside wildcard ${t[i + 1]} — IOS will store it as ${n2ip(and(a, not(wl)))}.`));
    return [{ addr: and(a, not(wl)), wild: wl, text: t[i] + ' ' + t[i + 1] }, 2];
  }
  function portSpec(t, i) {
    const op = (t[i] || '').toLowerCase();
    if (op === 'eq') { const p = port(t[i + 1]); if (p == null) throw T('λάθος θύρα: ', 'bad port: ') + t[i + 1]; return [[[p, p]], 2, 'eq ' + t[i + 1]]; }
    if (op === 'neq') { const p = port(t[i + 1]); if (p == null) throw T('λάθος θύρα: ', 'bad port: ') + t[i + 1]; return [[[0, p - 1], [p + 1, 65535]].filter(r => r[0] <= r[1]), 2, 'neq ' + t[i + 1]]; }
    if (op === 'lt') { const p = port(t[i + 1]); if (p == null) throw T('λάθος θύρα: ', 'bad port: ') + t[i + 1]; return [[[0, p - 1]], 2, 'lt ' + t[i + 1]]; }
    if (op === 'gt') { const p = port(t[i + 1]); if (p == null) throw T('λάθος θύρα: ', 'bad port: ') + t[i + 1]; return [[[p + 1, 65535]], 2, 'gt ' + t[i + 1]]; }
    if (op === 'range') { const a = port(t[i + 1]), b = port(t[i + 2]); if (a == null || b == null || a > b) throw T('λάθος range θυρών', 'bad port range'); return [[[a, b]], 3, `range ${t[i + 1]} ${t[i + 2]}`]; }
    return [ALL, 0, ''];
  }

  // ═════════════ parser ═════════════
  // Δέχεται «access-list N ...» και «ip access-list standard|extended NAME» + γραμμές από κάτω.
  function parse(text) {
    const acls = new Map(), errors = [];
    let cur = null;
    const get = (name, type) => { if (!acls.has(name)) acls.set(name, { name, type, aces: [] }); return acls.get(name); };
    const typeOfNum = n => (n >= 1 && n <= 99) || (n >= 1300 && n <= 1999) ? 'standard' : (n >= 100 && n <= 199) || (n >= 2000 && n <= 2699) ? 'extended' : null;
    String(text || '').split('\n').forEach((raw, li) => {
      const line = raw.replace(/!.*$/, '').trim(); if (!line) return;
      let t = line.split(/\s+/);
      try {
        if (/^ip$/i.test(t[0]) && /^access-list$/i.test(t[1])) {
          const ty = (t[2] || '').toLowerCase(); if (!/^(standard|extended)$/.test(ty) || !t[3]) throw T('γράψε: ip access-list standard|extended ΟΝΟΜΑ', 'write: ip access-list standard|extended NAME');
          cur = get(t[3], ty); return;
        }
        if (/^access-list$/i.test(t[0])) {
          const n = +t[1], ty = typeOfNum(n); if (!ty) throw T(`το ${t[1]} δεν είναι αριθμός ACL (1–99 standard, 100–199 extended)`, `${t[1]} is not an ACL number (1–99 standard, 100–199 extended)`);
          cur = null; const a = get(String(n), ty); t = t.slice(2); add(a, t, li + 1, raw.trim(), errors); return;
        }
        if (/^(interface|router|line|end|exit)$/i.test(t[0]) || /^ip$/i.test(t[0])) { cur = null; return; }
        if (cur) { if (/^\d+$/.test(t[0])) t = t.slice(1); add(cur, t, li + 1, raw.trim(), errors); return; }
        throw T('δεν καταλαβαίνω αυτή τη γραμμή', 'I don’t understand this line');
      } catch (e) { errors.push({ line: li + 1, text: raw.trim(), msg: String(e.message || e) }); }
    });
    return { acls: [...acls.values()], errors };
  }
  function add(acl, t, line, text, errors) {
    const act = (t[0] || '').toLowerCase();
    if (act === 'remark') return;
    if (act !== 'permit' && act !== 'deny') throw T('κάθε γραμμή ξεκινά με permit ή deny', 'each line starts with permit or deny');
    const warn = [], a = { action: act, line, text, warn };
    let i = 1;
    if (acl.type === 'standard') {
      a.proto = 'ip'; let n; [a.src, n] = addrSpec(t, i, warn); i += n;
      a.dst = { addr: 0, wild: 0xFFFFFFFF, text: 'any' }; a.sp = a.dp = ALL;
    } else {
      const p = (t[i] || '').toLowerCase();
      if (!(p in PROTOS) && !/^\d+$/.test(p)) throw T(`άγνωστο πρωτόκολλο «${t[i] || ''}» (ip, tcp, udp, icmp…)`, `unknown protocol “${t[i] || ''}” (ip, tcp, udp, icmp…)`);
      a.proto = p; i++;
      let n, ps;
      [a.src, n] = addrSpec(t, i, warn); i += n;
      if (p === 'tcp' || p === 'udp') { [a.sp, n, ps] = portSpec(t, i); i += n; a.spText = ps; } else a.sp = ALL;
      [a.dst, n] = addrSpec(t, i, warn); i += n;
      if (p === 'tcp' || p === 'udp') { [a.dp, n, ps] = portSpec(t, i); i += n; a.dpText = ps; } else a.dp = ALL;
      if (p === 'icmp' && t[i] && /^(echo|echo-reply|unreachable|time-exceeded)$/i.test(t[i])) { a.icmp = t[i].toLowerCase(); i++; }
      if ((t[i] || '').toLowerCase() === 'established') { if (p !== 'tcp') throw T('το established ισχύει μόνο για tcp', 'established only applies to tcp'); a.est = true; i++; }
    }
    if ((t[i] || '').toLowerCase() === 'log') i++;
    if (t[i]) throw T(`περίσσιο κείμενο: «${t.slice(i).join(' ')}»`, `extra text: “${t.slice(i).join(' ')}”`);
    acl.aces.push(a);
  }

  // ═════════════ αξιολόγηση ═════════════
  const inAddr = (s, ip) => and(ip, not(s.wild)) === s.addr;
  const inPorts = (r, p) => r.some(([a, b]) => p >= a && p <= b);
  const protoNum = p => PROTOS[p] ?? +p;
  // πακέτο: {proto:'tcp'|'udp'|'icmp'|'ip'|N, src, dst, sport, dport, est, icmp}
  function why(a, pk) {
    const pp = protoNum(pk.proto), ap = protoNum(a.proto);
    if (ap !== 0 && ap !== pp) return T(`πρωτόκολλο: ο κανόνας θέλει ${a.proto}, το πακέτο είναι ${pk.proto}`, `protocol: rule wants ${a.proto}, packet is ${pk.proto}`);
    if (!inAddr(a.src, pk.src)) return T(`αποστολέας: η ${n2ip(pk.src)} δεν είναι μέσα στο «${a.src.text}»`, `source: ${n2ip(pk.src)} is not in “${a.src.text}”`);
    if (!inAddr(a.dst, pk.dst)) return T(`παραλήπτης: η ${n2ip(pk.dst)} δεν είναι μέσα στο «${a.dst.text}»`, `destination: ${n2ip(pk.dst)} is not in “${a.dst.text}”`);
    if ((ap === 6 || ap === 17) && !inPorts(a.sp, pk.sport)) return T(`θύρα αποστολέα ${pk.sport} ≠ «${a.spText}»`, `source port ${pk.sport} ≠ “${a.spText}”`);
    if ((ap === 6 || ap === 17) && !inPorts(a.dp, pk.dport)) return T(`θύρα προορισμού ${pk.dport} ≠ «${a.dpText}»`, `destination port ${pk.dport} ≠ “${a.dpText}”`);
    if (a.est && !pk.est) return T('established: ταιριάζει μόνο σε απαντήσεις (ACK/RST), όχι σε νέα σύνδεση (SYN)', 'established: matches only replies (ACK/RST), not a new connection (SYN)');
    if (a.icmp && pk.icmp && a.icmp !== pk.icmp) return T(`τύπος ICMP: ${pk.icmp} ≠ ${a.icmp}`, `ICMP type: ${pk.icmp} ≠ ${a.icmp}`);
    return null;
  }
  function evaluate(acl, pk) {
    const steps = [];
    for (let i = 0; i < acl.aces.length; i++) {
      const r = why(acl.aces[i], pk);
      steps.push({ i, match: !r, why: r });
      if (!r) return { steps, hit: i, action: acl.aces[i].action };
    }
    return { steps, hit: -1, action: 'deny', implicit: true };
  }

  // ═════════════ ανάλυση: σκιασμένες/περιττές γραμμές ═════════════
  const addrCovers = (A, B) => and(B.wild, not(A.wild)) === 0 && and(A.addr, not(A.wild)) === and(B.addr, not(A.wild));
  const portsCover = (A, B) => B.every(([a, b]) => { let x = a; while (x <= b) { const r = A.find(([c, d]) => x >= c && x <= d); if (!r) return false; x = r[1] + 1; } return true; });
  const covers = (A, B) => {
    const pa = protoNum(A.proto), pb = protoNum(B.proto);
    if (pa !== 0 && pa !== pb) return false;
    if (!addrCovers(A.src, B.src) || !addrCovers(A.dst, B.dst)) return false;
    const tu = pa === 6 || pa === 17;
    if (tu && (!portsCover(A.sp, B.sp) || !portsCover(A.dp, B.dp))) return false;
    if (A.est && !B.est) return false;
    if (A.icmp && A.icmp !== B.icmp) return false;
    return true;
  };
  function analyze(acl) {
    const out = [];
    acl.aces.forEach((b, j) => {
      for (let i = 0; i < j; i++) if (covers(acl.aces[i], b)) {
        const a = acl.aces[i];
        out.push({ j, i, kind: a.action === b.action ? 'redundant' : 'shadowed',
          msg: a.action === b.action
            ? T(`Η γραμμή ${j + 1} είναι <b>περιττή</b>: η γραμμή ${i + 1} (${E(a.text)}) την καλύπτει ήδη με το ίδιο αποτέλεσμα.`, `Line ${j + 1} is <b>redundant</b>: line ${i + 1} (${E(a.text)}) already covers it with the same result.`)
            : T(`Η γραμμή ${j + 1} <b>δεν θα ταιριάξει ποτέ</b>: η γραμμή ${i + 1} (${E(a.text)}) πιάνει πρώτα όλα της τα πακέτα και κάνει ${a.action}. Βάλ’ την πιο πάνω!`, `Line ${j + 1} will <b>never match</b>: line ${i + 1} (${E(a.text)}) catches all its packets first and does ${a.action}. Move it up!`) });
        break;
      }
    });
    const tips = [];
    if (acl.aces.length && acl.aces.every(a => a.action === 'deny')) tips.push(T('Έχει μόνο <b>deny</b> — λόγω του κρυφού <code>deny any</code> στο τέλος, αυτό το ACL κόβει <b>τα πάντα</b>. Μάλλον θέλεις στο τέλος <code>permit ip any any</code> (ή <code>permit any</code> σε standard).', 'It has only <b>deny</b> lines — because of the hidden <code>deny any</code> at the end, this ACL blocks <b>everything</b>. You probably want <code>permit ip any any</code> (or <code>permit any</code> for standard) at the end.'));
    const last = acl.aces[acl.aces.length - 1];
    if (last && last.action === 'deny' && covers(last, { proto: 'ip', src: { addr: 0, wild: 0xFFFFFFFF }, dst: { addr: 0, wild: 0xFFFFFFFF }, sp: ALL, dp: ALL }))
      tips.push(T('Η τελευταία γραμμή είναι ρητό <code>deny any</code> — δεν αλλάζει κάτι (υπάρχει ήδη κρυφά), αλλά με <code>log</code> βλέπεις τι κόβεται.', 'The last line is an explicit <code>deny any</code> — it changes nothing (it is implicit), but with <code>log</code> you can see what gets dropped.'));
    tips.push(acl.type === 'standard'
      ? T('📍 <b>Standard ACL</b> (ελέγχει μόνο τον αποστολέα): βάλ’ το <b>κοντά στον προορισμό</b>, αλλιώς κόβεις τον αποστολέα και από άλλα δίκτυα.', '📍 <b>Standard ACL</b> (checks only the source): place it <b>close to the destination</b>, otherwise you also cut the source off from other networks.')
      : T('📍 <b>Extended ACL</b>: βάλ’ το <b>κοντά στην πηγή</b>, ώστε η ανεπιθύμητη κίνηση να κόβεται πριν διασχίσει το δίκτυο.', '📍 <b>Extended ACL</b>: place it <b>close to the source</b>, so unwanted traffic is dropped before it crosses the network.'));
    return { issues: out, tips };
  }

  const API = { parse, evaluate, analyze, ip2n, n2ip, covers };
  if (typeof window === 'undefined') { if (typeof module !== 'undefined') module.exports = API; return; }
  window.ACLT = API;

  // ═════════════ UI ═════════════
  const EX = {
    iot: { t: () => T('🏠 IoT να μη βλέπει το LAN', '🏠 IoT must not reach the LAN'), acl:
`! IoT (192.168.30.0/24) → μόνο Internet, όχι στο σπίτι
ip access-list extended IOT-IN
 remark επιτρέπεται DNS προς τον router
 permit udp 192.168.30.0 0.0.0.255 host 192.168.30.1 eq domain
 deny   ip 192.168.30.0 0.0.0.255 192.168.1.0 0.0.0.255
 deny   ip 192.168.30.0 0.0.0.255 192.168.99.0 0.0.0.255
 permit ip 192.168.30.0 0.0.0.255 any
!
interface GigabitEthernet0/0.30
 ip access-group IOT-IN in`,
      pk: { proto: 'tcp', src: '192.168.30.12', sport: '50123', dst: '192.168.1.10', dport: '445' } },
    bug: { t: () => T('🐞 Λάθος σειρά (κλασικό λάθος)', '🐞 Wrong order (classic mistake)'), acl:
`access-list 110 permit ip 10.0.0.0 0.0.0.255 any
access-list 110 deny   tcp host 10.0.0.66 any eq telnet
access-list 110 deny   tcp 10.0.0.0 0.0.0.255 any eq 23
access-list 110 permit tcp 10.0.0.0 0.0.0.255 any eq www`,
      pk: { proto: 'tcp', src: '10.0.0.66', sport: '40000', dst: '8.8.8.8', dport: '23' } },
    web: { t: () => T('🌐 Μόνο web προς τον server', '🌐 Web only to the server'), acl:
`ip access-list extended WEB-ONLY
 permit tcp any host 172.16.10.5 eq 80
 permit tcp any host 172.16.10.5 eq 443
 permit icmp any host 172.16.10.5 echo
 deny   ip any host 172.16.10.5 log
 permit ip any any`,
      pk: { proto: 'tcp', src: '203.0.113.7', sport: '51515', dst: '172.16.10.5', dport: '22' } },
    std: { t: () => T('📋 Standard ACL', '📋 Standard ACL'), acl:
`access-list 10 deny   host 192.168.1.66
access-list 10 permit 192.168.1.0 0.0.0.255
access-list 10 deny   any`,
      pk: { proto: 'ip', src: '192.168.2.20', sport: '', dst: '10.1.1.1', dport: '' } },
  };
  let st = { acl: EX.iot.acl, which: '', pk: { ...EX.iot.pk, est: false } };
  try { const s = JSON.parse(localStorage.getItem('nw-aclt') || 'null'); if (s && s.acl != null) st = { ...st, ...s }; } catch (e) {}
  const save = () => { try { localStorage.setItem('nw-aclt', JSON.stringify(st)); } catch (e) {} };
  const box = () => document.getElementById('t-acl');

  const css = document.createElement('style');
  css.textContent = `
#t-acl .at-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;align-items:start}
@media(max-width:1000px){#t-acl .at-grid{grid-template-columns:minmax(0,1fr)}}
#t-acl textarea{width:100%;box-sizing:border-box;min-height:250px;background:#05080f;color:#d6e2f0;border:1px solid var(--line);border-radius:10px;padding:10px 12px;font:12.5px/1.55 ui-monospace,Menlo,Consolas,monospace;resize:vertical}
#t-acl input,#t-acl select{background:var(--bg);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:7px 9px;font:13px ui-monospace,Menlo,Consolas,monospace;min-width:0;width:100%;box-sizing:border-box}
#t-acl .at-pk{display:grid;grid-template-columns:repeat(auto-fit,minmax(105px,1fr));gap:6px;align-items:end}
#t-acl .at-pk label{font-size:11px;color:var(--dim);display:block;margin-bottom:3px;font-weight:600}
#t-acl .at-lbl{font-size:12px;color:var(--dim);font-weight:600;margin:10px 0 4px}
#t-acl .at-ace{display:grid;grid-template-columns:26px 22px minmax(0,1fr);gap:6px;align-items:start;padding:7px 8px;border-radius:9px;margin-top:4px;border:1px solid transparent;font-size:12.5px}
#t-acl .at-ace code{font:12.5px ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
#t-acl .at-ace .n{color:var(--dim);font:11px ui-monospace,Menlo,Consolas,monospace;padding-top:2px}
#t-acl .at-ace .w{color:var(--dim);font-size:11.5px;margin-top:2px}
#t-acl .at-ace.hit.permit{border-color:var(--green);background:color-mix(in srgb,var(--green) 12%,transparent)}
#t-acl .at-ace.hit.deny{border-color:var(--red);background:color-mix(in srgb,var(--red) 12%,transparent)}
#t-acl .at-ace.skip{opacity:.38}
#t-acl .at-ace.bad{outline:1px dashed var(--orange)}
#t-acl .at-verdict{font-size:18px;font-weight:700;margin:4px 0 2px}
#t-acl .at-note{font-size:12.5px;line-height:1.55;background:rgb(var(--w,255 255 255) / 4%);border-radius:10px;padding:9px 12px;margin-top:8px}
#t-acl .at-note code{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px}
#t-acl .at-err{color:var(--red);font-size:12.5px;margin-top:6px}
#t-acl .at-chk{display:flex;gap:6px;align-items:center;font-size:12.5px;cursor:pointer;margin-top:8px}
#t-acl .at-chk input{width:auto}
`;
  document.head.appendChild(css);

  function results() {
    const o = box() && box().querySelector('#at-out'); if (!o) return;
    const P = parse(st.acl);
    let h = P.errors.map(e => `<div class="at-err">✖ ${T('Γραμμή', 'Line')} ${e.line}: <code>${E(e.text)}</code> — ${E(e.msg)}</div>`).join('');
    if (!P.acls.length) { o.innerHTML = h + `<div class="at-note">${T('Γράψε ένα ACL αριστερά (ή διάλεξε παράδειγμα).', 'Write an ACL on the left (or pick an example).')}</div>`; return; }
    const acl = P.acls.find(a => a.name === st.which) || P.acls[0];
    const sel = box().querySelector('#at-which');
    if (sel) sel.innerHTML = P.acls.map(a => `<option value="${E(a.name)}"${a === acl ? ' selected' : ''}>${E(a.name)} (${a.type}, ${a.aces.length})</option>`).join('');
    const pk = { proto: st.pk.proto, src: ip2n(st.pk.src), dst: ip2n(st.pk.dst), sport: +st.pk.sport || 0, dport: +st.pk.dport || 0, est: !!st.pk.est };
    const bad = [];
    if (pk.src == null) bad.push(T('αποστολέας', 'source')); if (pk.dst == null) bad.push(T('παραλήπτης', 'destination'));
    if ((pk.proto === 'tcp' || pk.proto === 'udp') && !(pk.dport >= 0 && pk.dport <= 65535)) bad.push(T('θύρα', 'port'));
    const A = analyze(acl), badSet = new Set(A.issues.map(x => x.j));
    if (bad.length) { o.innerHTML = h + `<div class="at-err">✖ ${T('Λάθος πεδία πακέτου:', 'Invalid packet fields:')} ${bad.join(', ')}</div>`; return; }
    const R = evaluate(acl, pk);
    const ok = R.action === 'permit';
    h += `<div class="card"><div class="at-verdict" style="color:var(--${ok ? 'green' : 'red'})">${ok ? '✅ PERMIT' : '⛔ DENY'}</div>
      <div class="dim" style="font-size:12.5px">${R.implicit ? T('Καμία γραμμή δεν ταίριαξε → το <b>κρυφό <code>deny any</code></b> στο τέλος κάθε ACL κόβει το πακέτο.', 'No line matched → the <b>hidden <code>deny any</code></b> at the end of every ACL drops the packet.') : T(`Ταίριαξε η <b>γραμμή ${R.hit + 1}</b> — εκεί σταματά ο έλεγχος (first match). Οι από κάτω δεν διαβάζονται καν.`, `<b>Line ${R.hit + 1}</b> matched — checking stops there (first match). The lines below are not even read.`)}</div>
      ${acl.aces.map((a, i) => { const s = R.steps[i];
        const cls = s ? (s.match ? 'hit ' + a.action : '') : 'skip';
        return `<div class="at-ace ${cls}${badSet.has(i) ? ' bad' : ''}"><span class="n">${i + 1}</span><span>${!s ? '·' : s.match ? (a.action === 'permit' ? '✅' : '⛔') : '✗'}</span><div><code>${E(a.text.replace(/^\d+\s+/, ''))}</code>${s && !s.match ? `<div class="w">${E(s.why)}</div>` : ''}${a.warn.length ? a.warn.map(w => `<div class="w" style="color:var(--orange)">⚠ ${w}</div>`).join('') : ''}</div></div>`; }).join('')}
      <div class="at-ace ${R.implicit ? 'hit deny' : 'skip'}"><span class="n">∞</span><span>${R.implicit ? '⛔' : '·'}</span><div><code>deny any</code> <span class="dim">${T('(κρυφό — υπάρχει πάντα)', '(implicit — always there)')}</span></div></div></div>`;
    h += A.issues.map(x => `<div class="at-note" style="border-left:3px solid var(--${x.kind === 'shadowed' ? 'red' : 'orange'})">${x.kind === 'shadowed' ? '🐞' : '♻️'} ${x.msg}</div>`).join('');
    h += A.tips.map(x => `<div class="at-note">${x}</div>`).join('');
    o.innerHTML = h;
  }
  function draw() {
    const b = box(); if (!b) return;
    b.setAttribute('data-noi18n', '');
    const pk = st.pk;
    b.innerHTML = `<div class="dim" style="font-size:12.5px;margin-bottom:8px">🔒 ${T('Γράψε ή επικόλλησε ένα Cisco ACL και «στείλε» ένα φανταστικό πακέτο: βλέπεις γραμμή-γραμμή τι ταιριάζει και γιατί. Όλα υπολογίζονται εδώ — δεν αγγίζει router.', 'Write or paste a Cisco ACL and “send” an imaginary packet: see line by line what matches and why. Everything is computed here — no router is touched.')}</div>
      <div class="at-grid"><div class="card"><div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">${Object.entries(EX).map(([k, x]) => `<button class="b" data-ex="${k}">${x.t()}</button>`).join('')}</div>
        <textarea id="at-acl" spellcheck="false">${E(st.acl)}</textarea>
        <div class="at-lbl">📦 ${T('Πακέτο για δοκιμή', 'Packet to test')}</div>
        <div class="at-pk"><div><label>${T('Πρωτόκολλο', 'Protocol')}</label><select data-p="proto">${['tcp', 'udp', 'icmp', 'ip'].map(p => `<option${p === pk.proto ? ' selected' : ''}>${p}</option>`).join('')}</select></div>
          <div><label>${T('Από IP', 'Source IP')}</label><input data-p="src" value="${E(pk.src)}"></div><div><label>${T('θύρα', 'port')}</label><input data-p="sport" value="${E(pk.sport)}"></div>
          <div><label>${T('Προς IP', 'Destination IP')}</label><input data-p="dst" value="${E(pk.dst)}"></div><div><label>${T('θύρα', 'port')}</label><input data-p="dport" value="${E(pk.dport)}"></div></div>
        <label class="at-chk"><input type="checkbox" data-p="est"${pk.est ? ' checked' : ''}> ${T('Απάντηση σε υπάρχουσα σύνδεση (TCP ACK — για το «established»)', 'Reply to an existing connection (TCP ACK — for “established”)')}</label>
        <div class="at-lbl">${T('Ποιο ACL να ελέγξω', 'Which ACL to test')}</div><select id="at-which"></select></div>
        <div id="at-out"></div></div>`;
    results();
  }
  let tm = null;
  function bind() {
    const b = box(); if (!b || b._at) return; b._at = 1;
    const upd = e => { const t = e.target;
      if (t.id === 'at-acl') st.acl = t.value;
      else if (t.id === 'at-which') st.which = t.value;
      else if (t.dataset.p) st.pk[t.dataset.p] = t.type === 'checkbox' ? t.checked : t.value;
      else return;
      save(); clearTimeout(tm); tm = setTimeout(results, 120); };
    b.addEventListener('input', upd); b.addEventListener('change', upd);
    b.addEventListener('click', e => { const x = e.target.closest('[data-ex]'); if (!x) return; const ex = EX[x.dataset.ex]; st.acl = ex.acl; st.which = ''; st.pk = { ...ex.pk, est: false }; save(); draw(); });
  }
  window.renderAcl = () => { bind(); draw(); };
})();
