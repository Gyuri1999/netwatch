// 🖧 Cisco Lab — προσομοιωτής Cisco IOS για εξάσκηση CCNA, μέσα στο NetWatch.
// Μηχανή εντολών (συντομεύσεις «conf t», «sh ip int br», «?», Tab, ιστορικό) + μοντέλο δικτύου
// (VLAN, trunk, router-on-a-stick, στατικές διαδρομές, OSPF, ACL) που υπολογίζει ΑΝ περνά πραγματικά ένα ping.
// Η έξοδος του τερματικού μένει στα αγγλικά, όπως σε έναν πραγματικό Cisco.
(() => {
  // ───────────── IP βοηθήματα ─────────────
  const isIP = s => /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(s) && s.split('.').every(x => +x <= 255);
  const n = s => s.split('.').reduce((a, x) => (a * 256) + +x, 0);
  const ip = v => [24, 16, 8, 0].map(k => Math.floor(v / 2 ** k) % 256).join('.');
  const mlen = m => n(m).toString(2).replace(/0+$/, '').length;
  const isMask = m => isIP(m) && /^1*0*$/.test(n(m).toString(2).padStart(32, '0'));
  const netOf = (a, m) => ip((n(a) & n(m)) >>> 0);
  const same = (a, b, m) => ((n(a) & n(m)) >>> 0) === ((n(b) & n(m)) >>> 0);
  const wmatch = (a, base, w) => ((n(a) & ~n(w)) >>> 0) === ((n(base) & ~n(w)) >>> 0);
  const pad = (s, k) => String(s).padEnd(k);

  // ───────────── ονόματα διεπαφών ─────────────
  const IFT = [['GigabitEthernet', 'Gi'], ['FastEthernet', 'Fa'], ['Vlan', 'Vlan'], ['Loopback', 'Lo']];
  function normIf(s) {
    const m = String(s).replace(/\s+/g, '').match(/^([a-z]+)([\d/.]+)$/i); if (!m) return null;
    const t = IFT.find(([full]) => full.toLowerCase().startsWith(m[1].toLowerCase())); return t ? t[0] + m[2] : null;
  }
  const shortIf = s => { for (const [f, sh] of IFT) if (s.startsWith(f)) return sh + s.slice(f.length); return s; };
  const parentIf = s => s.split('.')[0];

  // ───────────── συσκευές ─────────────
  const rIf = () => ({ ip: null, mask: null, shut: true, desc: '', acl: {}, enc: null });
  function mkRouter(name) {
    const ints = {}; ['GigabitEthernet0/0', 'GigabitEthernet0/1', 'GigabitEthernet0/2'].forEach(i => ints[i] = rIf());
    return { kind: 'router', name, host: name, ints, routes: [], ospf: null, acls: {}, users: {}, secret: null, enpw: null, spe: false, banner: '', dom: '', ssh: false, rsa: false, lines: { con: {}, vty: {} }, saved: null, flags: {} };
  }
  function mkSwitch(name) {
    const ints = {};
    for (let k = 1; k <= 24; k++) ints['FastEthernet0/' + k] = { mode: 'access', vlan: 1, allowed: null, native: 1, shut: false, desc: '', ps: null };
    ['GigabitEthernet0/1', 'GigabitEthernet0/2'].forEach(i => ints[i] = { mode: 'access', vlan: 1, allowed: null, native: 1, shut: false, desc: '', ps: null });
    return { kind: 'switch', name, host: name, ints, vlans: { 1: 'default' }, svi: {}, users: {}, secret: null, enpw: null, spe: false, banner: '', dom: '', ssh: false, rsa: false, lines: { con: {}, vty: {} }, gw: null, saved: null, flags: {} };
  }
  const mkPC = (name, a, m, g) => ({ kind: 'pc', name, host: name, ip: a, mask: m, gw: g, mac: '0050.7966.68' + (10 + name.charCodeAt(name.length - 1) % 80) });
  const mkCloud = name => ({ kind: 'cloud', name, host: name, ip: '203.0.113.1', mask: '255.255.255.252', hosts: ['8.8.8.8', '1.1.1.1'] });

  const TOPO = {
    A: { // router-on-a-stick + internet
      make: () => ({ R1: mkRouter('R1'), SW1: mkSwitch('SW1'), PC1: mkPC('PC1', '192.168.1.10', '255.255.255.0', '192.168.1.1'), PC2: mkPC('PC2', '192.168.1.12', '255.255.255.0', '192.168.1.1'), PC3: mkPC('PC3', '192.168.1.11', '255.255.255.0', '192.168.1.1'), ISP: mkCloud('ISP') }),
      links: [['R1', 'GigabitEthernet0/0', 'SW1', 'GigabitEthernet0/1'], ['PC1', 'eth0', 'SW1', 'FastEthernet0/1'], ['PC2', 'eth0', 'SW1', 'FastEthernet0/2'], ['PC3', 'eth0', 'SW1', 'FastEthernet0/3'], ['R1', 'GigabitEthernet0/1', 'ISP', 'eth0']],
      pos: { ISP: [380, 34], R1: [380, 112], SW1: [380, 196], PC1: [180, 286], PC3: [380, 286], PC2: [580, 286] },
    },
    B: { // δύο routers, δύο LAN
      make: () => ({ PC1: mkPC('PC1', '192.168.1.10', '255.255.255.0', '192.168.1.1'), R1: mkRouter('R1'), R2: mkRouter('R2'), PC2: mkPC('PC2', '192.168.2.10', '255.255.255.0', '192.168.2.1') }),
      links: [['PC1', 'eth0', 'R1', 'GigabitEthernet0/0'], ['R1', 'GigabitEthernet0/1', 'R2', 'GigabitEthernet0/1'], ['R2', 'GigabitEthernet0/0', 'PC2', 'eth0']],
      pos: { PC1: [90, 170], R1: [290, 170], R2: [470, 170], PC2: [670, 170] },
    },
  };

  // ───────────── κατάσταση εργαστηρίου ─────────────
  let L = null; // { ex, topo, D:{name:dev}, con:{name:console}, cur }
  const linksOf = () => TOPO[L.topo].links;
  const peer = (dev, ifn) => { for (const [a, ai, b, bi] of linksOf()) { if (a === dev && ai === ifn) return [b, bi]; if (b === dev && bi === ifn) return [a, ai]; } return null; };

  // κατάσταση γραμμής διεπαφής router (up/down/admin down)
  function rStatus(R, ifn) {
    const I = R.ints[ifn]; if (!I) return 'down';
    const p = parentIf(ifn), P = R.ints[p];
    if (I.shut || (P && P.shut)) return 'admin';
    const pe = peer(R.name, p); if (!pe) return 'down';
    const O = L.D[pe[0]];
    if (O.kind === 'switch') return O.ints[pe[1]].shut ? 'down' : 'up';
    if (O.kind === 'router') return O.ints[pe[1]].shut ? 'down' : 'up';
    return 'up';
  }
  function swPortUp(S, ifn) {
    const P = S.ints[ifn]; if (!P || P.shut) return false;
    const pe = peer(S.name, ifn); if (!pe) return false;
    const O = L.D[pe[0]]; if (O.kind === 'router') return !O.ints[pe[1]].shut; return true;
  }
  const trunkVlans = (S, P) => Object.keys(S.vlans).map(Number).filter(v => !P.allowed || P.allowed.includes(v));

  // L2 τμήματα (union-find): ποιες διευθύνσεις L3 «βλέπουν» η μία την άλλη
  function segments() {
    const par = {}, f = k => { par[k] = par[k] || k; return par[k] === k ? k : (par[k] = f(par[k])); }, u = (a, b) => { par[f(a)] = f(b); };
    const att = [];
    for (const d of Object.values(L.D)) {
      if (d.kind === 'pc' && d.ip) att.push({ dev: d.name, ifn: 'eth0', ip: d.ip, mask: d.mask });
      if (d.kind === 'cloud') att.push({ dev: d.name, ifn: 'eth0', ip: d.ip, mask: d.mask });
      if (d.kind === 'router') for (const [k, I] of Object.entries(d.ints)) if (I.ip && rStatus(d, k) === 'up') att.push({ dev: d.name, ifn: k, ip: I.ip, mask: I.mask });
      if (d.kind === 'switch') for (const [k, I] of Object.entries(d.svi)) if (I.ip && !I.shut && d.vlans[+k.slice(4)]) { att.push({ dev: d.name, ifn: k, ip: I.ip, mask: I.mask }); u('A:' + d.name + ':' + k, 'S:' + d.name + ':' + k.slice(4)); }
    }
    for (const [a, ai, b, bi] of linksOf()) {
      let [x, xi, y, yi] = [a, ai, b, bi];
      if (L.D[y].kind === 'switch') [x, xi, y, yi] = [b, bi, a, ai];
      const X = L.D[x], Y = L.D[y];
      if (X.kind === 'switch') {
        const P = X.ints[xi]; if (!swPortUp(X, xi)) continue;
        const vl = P.mode === 'trunk' ? trunkVlans(X, P) : (X.vlans[P.vlan] ? [P.vlan] : []);
        if (Y.kind === 'pc' || Y.kind === 'cloud') { if (P.mode === 'access' && vl.length) u('A:' + y + ':eth0', 'S:' + x + ':' + vl[0]); continue; }
        if (Y.kind === 'router') {
          if (rStatus(Y, yi) === 'up') { if (P.mode === 'access' && vl.length) u('A:' + y + ':' + yi, 'S:' + x + ':' + vl[0]); if (P.mode === 'trunk' && vl.includes(P.native)) u('A:' + y + ':' + yi, 'S:' + x + ':' + P.native); }
          for (const [k, I] of Object.entries(Y.ints)) if (k.startsWith(yi + '.') && I.enc && rStatus(Y, k) === 'up' && P.mode === 'trunk' && vl.includes(I.enc)) u('A:' + y + ':' + k, 'S:' + x + ':' + I.enc);
        }
      } else {
        const up = (D, i) => D.kind === 'router' ? rStatus(D, i) === 'up' : true;
        if (up(X, xi) && up(Y, yi)) u('A:' + x + ':' + xi, 'A:' + y + ':' + yi);
      }
    }
    att.forEach(t => t.seg = f('A:' + t.dev + ':' + t.ifn));
    return att;
  }

  // ───────────── δρομολόγηση ─────────────
  function ospfRid(R) { if (R.ospf && R.ospf.rid) return R.ospf.rid; const ips = Object.values(R.ints).filter(I => I.ip).map(I => I.ip); return ips.sort((a, b) => n(b) - n(a))[0] || '0.0.0.0'; }
  function ospfIfs(R, att) { if (!R.ospf) return []; return att.filter(t => t.dev === R.name && R.ospf.nets.some(x => wmatch(t.ip, x.ip, x.w))).map(t => ({ ...t, area: R.ospf.nets.find(x => wmatch(t.ip, x.ip, x.w)).area, passive: (R.ospf.passive || []).includes(t.ifn) })); }
  function ospfNbrs(R, att) {
    const out = [], mine = ospfIfs(R, att);
    for (const Q of Object.values(L.D)) if (Q.kind === 'router' && Q !== R && Q.ospf) for (const q of ospfIfs(Q, att)) for (const m of mine) if (m.seg === q.seg && m.area === q.area && !m.passive && !q.passive && same(m.ip, q.ip, m.mask)) out.push({ R: Q, rid: ospfRid(Q), ip: q.ip, ifn: m.ifn });
    return out;
  }
  function rtable(R, att) {
    att = att || segments();
    const t = [];
    for (const a of att) if (a.dev === R.name) { t.push({ c: 'C', net: netOf(a.ip, a.mask), mask: a.mask, ifn: a.ifn, ad: 0 }); t.push({ c: 'L', net: a.ip, mask: '255.255.255.255', ifn: a.ifn, ad: 0 }); }
    const conn = ipx => t.find(e => e.c === 'C' && same(ipx, e.net, e.mask));
    for (const r of R.routes) {
      if (r.ifn) { if (rStatus(R, r.ifn) === 'up') t.push({ c: 'S', net: r.net, mask: r.mask, ifn: r.ifn, ad: 1, dir: 1 }); continue; }
      const c = conn(r.nh); if (c) t.push({ c: 'S', net: r.net, mask: r.mask, nh: r.nh, ifn: c.ifn, ad: 1 });
    }
    if (R.ospf) { // BFS πάνω στις γειτνιάσεις OSPF
      const seen = new Set([R.name]), q = ospfNbrs(R, att).map(x => ({ Q: x.R, nh: x.ip, ifn: x.ifn, d: 1 }));
      while (q.length) {
        const x = q.shift(); if (seen.has(x.Q.name)) continue; seen.add(x.Q.name);
        for (const o of ospfIfs(x.Q, att)) { const net = netOf(o.ip, o.mask); if (!t.some(e => (e.c === 'C') && e.net === net && e.mask === o.mask) && !t.some(e => e.c === 'O' && e.net === net)) t.push({ c: 'O', net, mask: o.mask, nh: x.nh, ifn: x.ifn, ad: 110, cost: 1 + x.d }); }
        for (const y of ospfNbrs(x.Q, att)) if (!seen.has(y.R.name)) q.push({ Q: y.R, nh: x.nh, ifn: x.ifn, d: x.d + 1 });
      }
    }
    return t;
  }
  function lookup(R, dst, att) {
    let best = null;
    for (const e of rtable(R, att)) if (e.c !== 'L' && same(dst, e.net, e.mask)) { const l = mlen(e.mask); if (!best || l > best.l || (l === best.l && e.ad < best.e.ad)) best = { e, l }; }
    return best && best.e;
  }
  function aclOK(R, ifn, dir, src, dst) {
    const num = (R.ints[ifn] || {}).acl ? R.ints[ifn].acl[dir] : null; if (!num) return true;
    const A = R.acls[num]; if (!A || !A.length) return true; // ACL που δεν υπάρχει = επιτρέπει
    const ok = (spec, a) => spec.any || (spec.host ? a === spec.host : wmatch(a, spec.ip, spec.w));
    for (const r of A) {
      if (r.std) { if (ok(r.src, src)) return r.act === 'permit'; continue; }
      if (r.proto !== 'ip' && r.proto !== 'icmp') continue;
      if (ok(r.src, src) && ok(r.dst, dst)) return r.act === 'permit';
    }
    return false;
  }
  // στέλνει ένα πακέτο ICMP βήμα-βήμα· επιστρέφει {ok, at, why}
  function forward(fromDev, src, dst, att) {
    let dev = L.D[fromDev], ingress = null, hops = 0;
    const onSeg = (seg, a, not) => att.find(t => t.seg === seg && t.ip === a && t.dev !== not);
    while (hops++ < 16) {
      if (dev.kind === 'cloud') {
        if (dst === dev.ip || dev.hosts.includes(dst)) return { ok: true, at: dev.name };
        const me = att.find(t => t.dev === dev.name); const nx = me && onSeg(me.seg, '203.0.113.2', dev.name);
        if (!nx) return { ok: false, why: 'timeout' }; dev = L.D[nx.dev]; ingress = nx.ifn; continue;
      }
      if (dev.kind === 'pc') {
        const me = att.find(t => t.dev === dev.name); if (!me) return { ok: false, why: 'noip' };
        if (dst === dev.ip) return { ok: true, at: dev.name };
        let target = same(dst, dev.ip, dev.mask) ? dst : dev.gw;
        if (!target || !isIP(target)) return { ok: false, why: 'unreach' };
        const nx = onSeg(me.seg, target, dev.name); if (!nx) return { ok: false, why: same(dst, dev.ip, dev.mask) ? 'unreach' : 'timeout' };
        if (target === dst) return { ok: true, at: nx.dev, ingress: nx.ifn, dev: L.D[nx.dev] };
        dev = L.D[nx.dev]; ingress = nx.ifn; continue;
      }
      if (dev.kind === 'switch') { const me = att.find(t => t.dev === dev.name && t.ip === src); if (!me) return { ok: false, why: 'timeout' };
        if (Object.values(dev.svi).some(I => I.ip === dst)) return { ok: true, at: dev.name };
        const target = same(dst, me.ip, me.mask) ? dst : dev.gw; const nx = target && onSeg(me.seg, target, dev.name); if (!nx) return { ok: false, why: 'timeout' };
        if (target === dst) return { ok: true, at: nx.dev }; dev = L.D[nx.dev]; ingress = nx.ifn; continue; }
      // router
      const R = dev;
      if (ingress && !aclOK(R, ingress, 'in', src, dst)) return { ok: false, why: 'acl', at: R.name, ifn: ingress };
      if (att.some(t => t.dev === R.name && t.ip === dst)) return { ok: true, at: R.name };
      const rt = lookup(R, dst, att); if (!rt) return { ok: false, why: 'noroute', at: R.name };
      if (ingress && !aclOK(R, rt.ifn, 'out', src, dst)) return { ok: false, why: 'acl', at: R.name, ifn: rt.ifn };
      const me = att.find(t => t.dev === R.name && t.ifn === rt.ifn); if (!me) return { ok: false, why: 'timeout' };
      const nh = rt.nh && !rt.dir ? rt.nh : dst;
      const nx = onSeg(me.seg, nh, R.name);
      if (!nx) { const cl = att.find(t => t.seg === me.seg && L.D[t.dev].kind === 'cloud'); if (cl && L.D[cl.dev].hosts.includes(dst)) return { ok: true, at: cl.dev }; return { ok: false, why: 'timeout' }; }
      if (nh === dst && L.D[nx.dev].kind !== 'router') return { ok: true, at: nx.dev };
      dev = L.D[nx.dev]; ingress = nx.ifn;
    }
    return { ok: false, why: 'ttl' };
  }
  function srcIP(D, dst, att) {
    if (D.kind === 'pc' || D.kind === 'cloud') return D.ip;
    if (D.kind === 'switch') { const s = Object.values(D.svi).find(I => I.ip && !I.shut); return s ? s.ip : null; }
    const rt = lookup(D, dst, att); if (!rt) return null; return (D.ints[rt.ifn] || {}).ip;
  }
  function ping(from, dst) {
    const att = segments(), D = L.D[from], s = srcIP(D, dst, att);
    if (!s) return { ok: false, why: D.kind === 'router' ? 'noroute' : 'noip' };
    const go = forward(from, s, dst, att); if (!go.ok) return go;
    const back = forward(go.at, dst, s, att); return back.ok ? { ok: true } : { ok: false, why: 'timeout', back: 1 };
  }

  // ───────────── running-config / show ─────────────
  const h7 = s => [...s].map((c, i) => (c.charCodeAt(0) ^ (0x42 + i * 7) % 255).toString(16).padStart(2, '0')).join('').toUpperCase();
  const pw = (D, s) => D.spe ? '7 0' + h7(s).slice(0, 18) : s;
  const sec5 = s => '5 $1$mERr$' + btoa(s + 'nw').replace(/[^a-zA-Z0-9]/g, '').slice(0, 22);
  const aclLine = r => r.std ? `${r.act} ${r.src.any ? 'any' : r.src.host ? 'host ' + r.src.host : r.src.ip + (r.src.w && r.src.w !== '0.0.0.0' ? ', wildcard bits ' + r.src.w : '')}` : `${r.act} ${r.proto} ${spec(r.src)} ${spec(r.dst)}${r.port ? ' eq ' + r.port : ''}`;
  const spec = s => s.any ? 'any' : s.host ? 'host ' + s.host : s.ip + ' ' + s.w;
  function runCfg(D) {
    const o = ['Building configuration...', '', `Current configuration : ${1100 + Object.keys(D.ints).length * 31} bytes`, '!', 'version 15.7', (D.spe ? '' : 'no ') + 'service password-encryption', '!', 'hostname ' + D.host, '!'];
    if (D.secret) o.push('enable secret ' + sec5(D.secret)); if (D.enpw) o.push('enable password ' + pw(D, D.enpw)); if (D.secret || D.enpw) o.push('!');
    for (const [u, x] of Object.entries(D.users)) o.push(`username ${u} ${x.s ? 'secret ' + sec5(x.p) : 'password ' + pw(D, x.p)}`);
    if (D.dom) o.push('ip domain-name ' + D.dom); if (D.ssh) o.push('ip ssh version 2'); o.push('!');
    if (D.kind === 'router') {
      for (const [k, I] of Object.entries(D.ints)) {
        o.push('interface ' + k); if (I.desc) o.push(' description ' + I.desc); if (I.enc) o.push(' encapsulation dot1Q ' + I.enc);
        o.push(I.ip ? ` ip address ${I.ip} ${I.mask}` : ' no ip address'); if (I.acl.in) o.push(` ip access-group ${I.acl.in} in`); if (I.acl.out) o.push(` ip access-group ${I.acl.out} out`);
        if (I.shut) o.push(' shutdown'); if (!k.includes('.')) o.push(' duplex auto', ' speed auto'); o.push('!');
      }
      if (D.ospf) { o.push('router ospf ' + D.ospf.pid); if (D.ospf.rid) o.push(' router-id ' + D.ospf.rid); (D.ospf.passive || []).forEach(p => o.push(' passive-interface ' + p)); D.ospf.nets.forEach(x => o.push(` network ${x.ip} ${x.w} area ${x.area}`)); o.push('!'); }
      o.push('ip forward-protocol nd', '!'); D.routes.forEach(r => o.push(`ip route ${r.net} ${r.mask} ${r.nh || r.ifn}`)); o.push('!');
      for (const [num, A] of Object.entries(D.acls)) A.forEach(r => o.push(`access-list ${num} ${aclLine(r).replace(', wildcard bits ', ' ')}`)); if (Object.keys(D.acls).length) o.push('!');
    } else {
      for (const [k, P] of Object.entries(D.ints)) {
        o.push('interface ' + k); if (P.desc) o.push(' description ' + P.desc);
        if (P.mode === 'trunk') { if (P.native !== 1) o.push(' switchport trunk native vlan ' + P.native); if (P.allowed) o.push(' switchport trunk allowed vlan ' + P.allowed.join(',')); o.push(' switchport mode trunk'); }
        else { if (P.vlan !== 1) o.push(' switchport access vlan ' + P.vlan); if (P.modeSet) o.push(' switchport mode access'); }
        if (P.ps) { o.push(' switchport port-security'); if (P.ps.max !== 1) o.push(' switchport port-security maximum ' + P.ps.max); if (P.ps.viol !== 'shutdown') o.push(' switchport port-security violation ' + P.ps.viol); if (P.ps.sticky) o.push(' switchport port-security mac-address sticky'); }
        if (P.shut) o.push(' shutdown'); o.push('!');
      }
      o.push('interface Vlan1'); const v1 = D.svi.Vlan1; o.push(v1 && v1.ip ? ` ip address ${v1.ip} ${v1.mask}` : ' no ip address'); if (!v1 || v1.shut) o.push(' shutdown'); o.push('!');
      for (const [k, I] of Object.entries(D.svi)) if (k !== 'Vlan1') { o.push('interface ' + k, I.ip ? ` ip address ${I.ip} ${I.mask}` : ' no ip address'); if (I.shut) o.push(' shutdown'); o.push('!'); }
      if (D.gw) o.push('ip default-gateway ' + D.gw, '!');
    }
    if (D.banner) o.push('banner motd ^C' + D.banner + '^C', '!');
    o.push('line con 0'); if (D.lines.con.pw) o.push(' password ' + pw(D, D.lines.con.pw)); if (D.lines.con.login) o.push(' ' + D.lines.con.login); if (D.lines.con.sync) o.push(' logging synchronous');
    o.push('line vty 0 4'); if (D.lines.vty.pw) o.push(' password ' + pw(D, D.lines.vty.pw)); o.push(' ' + (D.lines.vty.login || 'login')); if (D.lines.vty.tin) o.push(' transport input ' + D.lines.vty.tin);
    o.push('!', 'end'); return o;
  }
  function ipIntBr(D) {
    const o = [pad('Interface', 27) + pad('IP-Address', 16) + 'OK? Method ' + pad('Status', 22) + 'Protocol'];
    if (D.kind === 'router') for (const [k, I] of Object.entries(D.ints)) { const s = rStatus(D, k); o.push(pad(k, 27) + pad(I.ip || 'unassigned', 16) + 'YES ' + pad(I.ip ? 'manual' : 'unset', 7) + pad(s === 'admin' ? 'administratively down' : s, 22) + (s === 'up' ? 'up' : 'down')); }
    else { for (const k of Object.keys(D.ints)) { const up = swPortUp(D, k); o.push(pad(k, 27) + pad('unassigned', 16) + 'YES unset  ' + pad(D.ints[k].shut ? 'administratively down' : up ? 'up' : 'down', 22) + (up ? 'up' : 'down')); }
      const sv = Object.keys(D.svi).length ? D.svi : { Vlan1: { shut: true } }; for (const [k, I] of Object.entries(sv)) o.push(pad(k, 27) + pad(I.ip || 'unassigned', 16) + 'YES ' + pad(I.ip ? 'manual' : 'unset', 7) + pad(I.shut ? 'administratively down' : 'up', 22) + (I.shut ? 'down' : 'up')); }
    return o;
  }
  function showVlan(D) {
    const o = [pad('VLAN', 5) + pad('Name', 33) + pad('Status', 10) + 'Ports', '---- -------------------------------- --------- -------------------------------'];
    for (const [v, nm] of Object.entries(D.vlans).sort((a, b) => a[0] - b[0])) {
      const ports = Object.entries(D.ints).filter(([, P]) => P.mode === 'access' && P.vlan === +v).map(([k]) => shortIf(k));
      const rows = []; for (let i = 0; i < Math.max(1, ports.length); i += 4) rows.push(ports.slice(i, i + 4).join(', '));
      o.push(pad(v, 5) + pad(nm, 33) + pad('active', 10) + rows[0]); rows.slice(1).forEach(r => o.push(' '.repeat(48) + r));
    }
    Object.entries(D.ints).filter(([, P]) => P.mode === 'access' && !D.vlans[P.vlan]).forEach(([k, P]) => o.push(`% Fa port ${shortIf(k)} is in VLAN ${P.vlan}, which does not exist (inactive)`));
    o.push(pad('1002', 5) + pad('fddi-default', 33) + 'act/unsup', pad('1003', 5) + pad('token-ring-default', 33) + 'act/unsup', pad('1004', 5) + pad('fddinet-default', 33) + 'act/unsup', pad('1005', 5) + pad('trnet-default', 33) + 'act/unsup');
    return o;
  }
  function showTrunk(D) {
    const T = Object.entries(D.ints).filter(([k, P]) => P.mode === 'trunk' && swPortUp(D, k)); if (!T.length) return [''];
    const o = ['', pad('Port', 12) + pad('Mode', 13) + pad('Encapsulation', 15) + pad('Status', 14) + 'Native vlan'];
    T.forEach(([k, P]) => o.push(pad(shortIf(k), 12) + pad('on', 13) + pad('802.1q', 15) + pad('trunking', 14) + P.native));
    o.push('', pad('Port', 12) + 'Vlans allowed on trunk'); T.forEach(([k, P]) => o.push(pad(shortIf(k), 12) + (P.allowed ? P.allowed.join(',') : '1-4094')));
    o.push('', pad('Port', 12) + 'Vlans allowed and active in management domain'); T.forEach(([k, P]) => o.push(pad(shortIf(k), 12) + trunkVlans(D, P).join(',')));
    return o;
  }
  function showRoute(D) {
    const t = rtable(D), def = t.find(e => e.net === '0.0.0.0' && e.mask === '0.0.0.0');
    const o = ['Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP', '       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area', '       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2', '       E1 - OSPF external type 1, E2 - OSPF external type 2', '       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2', '       * - candidate default, U - per-user static route, o - ODR', '',
      def ? `Gateway of last resort is ${def.nh || def.ifn} to network 0.0.0.0` : 'Gateway of last resort is not set', ''];
    t.sort((a, b) => n(a.net) - n(b.net) || mlen(a.mask) - mlen(b.mask)).forEach(e => {
      const p = e.net + '/' + mlen(e.mask);
      if (e.c === 'C' || e.c === 'L') o.push(pad(e.c, 9) + p + ' is directly connected, ' + e.ifn);
      else if (e.c === 'S') o.push(pad(e.net === '0.0.0.0' ? 'S*' : 'S', 6) + p + (e.dir ? ' is directly connected, ' + e.ifn : ` [1/0] via ${e.nh}`));
      else o.push(pad('O', 9) + p + ` [110/${e.cost}] via ${e.nh}, 00:0${Math.min(9, 1 + (L.tick || 0) % 9)}:1${(L.tick || 0) % 10}, ${e.ifn}`);
    });
    return o;
  }
  function showAcl(D) {
    const o = [];
    for (const [num, A] of Object.entries(D.acls)) { o.push(`${+num < 100 ? 'Standard' : 'Extended'} IP access list ${num}`); A.forEach((r, i) => o.push(`    ${(i + 1) * 10} ${aclLine(r)}${r.hits ? ` (${r.hits} matches)` : ''}`)); }
    return o.length ? o : [''];
  }
  function showOspfNbr(D) {
    if (!D.ospf) return ['%OSPF: Router process not running'];
    const att = segments(), o = [pad('Neighbor ID', 16) + pad('Pri', 6) + pad('State', 16) + pad('Dead Time', 12) + pad('Address', 16) + 'Interface'];
    ospfNbrs(D, att).forEach(x => o.push(pad(x.rid, 16) + pad('1', 6) + pad(n(x.rid) > n(ospfRid(D)) ? 'FULL/DR' : 'FULL/BDR', 16) + pad('00:00:3' + (L.tick % 10), 12) + pad(x.ip, 16) + x.ifn));
    return o;
  }
  function showMac(D) {
    const o = ['          Mac Address Table', '-------------------------------------------', '', 'Vlan    Mac Address       Type        Ports', '----    -----------       --------    -----'];
    for (const [a, ai, b, bi] of linksOf()) for (const [x, xi, y] of [[a, ai, b], [b, bi, a]]) if (x === D.name && swPortUp(D, xi)) { const P = D.ints[xi], Y = L.D[y]; const mac = Y.mac || '00d0.ba' + (y.charCodeAt(1) % 90 + 10) + '.1' + (y.length) + '01'; o.push(pad('  ' + (P.mode === 'trunk' ? P.native : P.vlan), 8) + pad(mac, 18) + pad('DYNAMIC', 12) + shortIf(xi)); }
    return o;
  }
  function showPS(D) {
    const o = ['Secure Port  MaxSecureAddr  CurrentAddr  SecurityViolation  Security Action', '                (Count)       (Count)          (Count)', '---------------------------------------------------------------------------'];
    for (const [k, P] of Object.entries(D.ints)) if (P.ps) o.push(pad('   ' + shortIf(k), 18) + pad(P.ps.max, 15) + pad(peer(D.name, k) ? 1 : 0, 17) + pad(0, 19) + (P.ps.viol[0].toUpperCase() + P.ps.viol.slice(1)));
    return o.concat(['---------------------------------------------------------------------------']);
  }

  // ───────────── εντολές ─────────────
  const CFG = ['config', 'if', 'subif', 'vlan', 'line', 'router', 'range', 'svi'];
  const IFM = ['if', 'subif', 'range', 'svi'];
  const err = (txt, at, col) => [(' '.repeat(Math.max(0, col)) + '^'), "% Invalid input detected at '^' marker.", ''];
  const ifsOf = c => c.range || [c.ifn];
  const C = [];
  const cmd = (modes, pat, help, fn, kind) => C.push({ modes, pat: pat.split(' '), help, fn, kind });
  const out = (...l) => l;

  // --- user / privileged ---
  cmd(['user'], 'enable', 'Turn on privileged commands', (D, a, c) => { if (D.secret || D.enpw) { c.pw = 'enable'; return ['Password: ']; } c.mode = 'priv'; D.flags.enabled = 1; return []; });
  cmd(['user', 'priv'], 'exit', 'Exit from the EXEC', (D, a, c) => { c.mode = 'user'; return ['', D.host + ' con0 is now available', '', '', '', 'Press RETURN to get started.', '']; });
  cmd(['user', 'priv'], 'logout', 'Exit from the EXEC', (D, a, c) => { c.mode = 'user'; return ['']; });
  cmd(['priv'], 'disable', 'Turn off privileged commands', (D, a, c) => { c.mode = 'user'; return []; });
  cmd(['priv'], 'configure terminal', 'Enter configuration mode', (D, a, c) => { c.mode = 'config'; return ['Enter configuration commands, one per line.  End with CNTL/Z.']; });
  cmd(['priv'], 'show running-config', 'Current operating configuration', D => runCfg(D));
  cmd(['priv'], 'show startup-config', 'Contents of startup configuration', D => D.saved ? ['Using 1211 out of 262136 bytes'].concat(D.saved) : ['startup-config is not present']);
  cmd(['user', 'priv'], 'show ip interface brief', 'Brief summary of IP status and configuration', D => ipIntBr(D));
  cmd(['user', 'priv'], 'show ip route', 'IP routing table', D => showRoute(D), 'r');
  cmd(['user', 'priv'], 'show ip ospf neighbor', 'Neighbor list', D => showOspfNbr(D), 'r');
  cmd(['user', 'priv'], 'show access-lists', 'List access lists', D => showAcl(D), 'r');
  cmd(['user', 'priv'], 'show vlan brief', 'VTP all VLAN status in brief', D => showVlan(D), 's');
  cmd(['user', 'priv'], 'show vlan', 'VTP VLAN status', D => showVlan(D), 's');
  cmd(['user', 'priv'], 'show interfaces trunk', 'Show interface trunk information', D => showTrunk(D), 's');
  cmd(['user', 'priv'], 'show mac address-table', 'MAC forwarding table', D => showMac(D), 's');
  cmd(['user', 'priv'], 'show port-security', 'Show secure port information', D => showPS(D), 's');
  cmd(['user', 'priv'], 'show version', 'System hardware and software status', D => [`Cisco IOS Software, ${D.kind === 'router' ? 'C2900 Software (C2900-UNIVERSALK9-M)' : 'C2960 Software (C2960-LANBASEK9-M)'}, Version 15.7(3)M, RELEASE SOFTWARE (fc2)`, 'Technical Support: http://www.cisco.com/techsupport', '', `${D.host} uptime is ${1 + (L.tick || 0) % 50} minutes`, 'System image file is "flash:/ios.bin"', '', `cisco ${D.kind === 'router' ? 'C2911' : 'WS-C2960-24TT-L'} (NetWatch lab) processor with 491520K bytes of memory.`, 'Configuration register is 0x2102']);
  const save = D => { D.saved = runCfg(D).slice(3); D.flags.saved = 1; return ['Building configuration...', '[OK]']; };
  cmd(['priv'], 'copy running-config startup-config', 'Copy running config to startup config', D => ['Destination filename [startup-config]? ', ...save(D)]);
  cmd(['priv'], 'write memory', 'Write to NV memory', save);
  cmd(['priv'], 'write', 'Write running configuration to memory', save);
  cmd(['user', 'priv'], 'ping <ip>', 'Send echo messages', (D, a, c) => {
    const r = ping(D.name, a[0]), key = a[0], first = !c.arp.has(key);
    const o = ['Type escape sequence to abort.', `Sending 5, 100-byte ICMP Echos to ${a[0]}, timeout is 2 seconds:`];
    if (r.ok) { c.arp.add(key); o.push(first && D.kind === 'router' ? '.!!!!' : '!!!!!', `Success rate is ${first && D.kind === 'router' ? '80 percent (4/5)' : '100 percent (5/5)'}, round-trip min/avg/max = 1/${2 + key.length % 4}/${5 + key.length % 6} ms`); }
    else o.push(r.why === 'noroute' ? 'U.U.U' : r.why === 'acl' ? 'U.U.U' : '.....', 'Success rate is 0 percent (0/5)');
    return o;
  });
  cmd(['priv'], 'traceroute <ip>', 'Trace route to destination', (D, a) => {
    const o = ['Type escape sequence to abort.', 'Tracing the route to ' + a[0], 'VRF info: (vrf in name/id, vrf out name/id)'];
    const r = ping(D.name, a[0]); o.push(r.ok ? `  1 ${a[0]} ${2 + a[0].length % 5} msec ${3 + a[0].length % 4} msec 2 msec` : '  1  *  *  *'); return o;
  }, 'r');
  cmd(['priv'], 'clear', 'Reset functions', (D, a, c) => { c.out = []; return []; });
  cmd(['priv'], 'reload', 'Halt and perform a cold restart', () => ['% Reload is disabled in the NetWatch lab (use the Reset button).']);

  // --- global config ---
  cmd(CFG, 'end', 'Exit from configure mode', (D, a, c) => { c.mode = 'priv'; delete c.ifn; delete c.range; return ['%SYS-5-CONFIG_I: Configured from console by console']; });
  cmd(CFG, 'exit', 'Exit from current mode', (D, a, c) => { c.mode = c.mode === 'config' ? 'priv' : 'config'; delete c.range; return []; });
  cmd(CFG, 'do <rest>', 'To run exec commands in config mode', (D, a, c) => exec(D, c, a[0], 'priv'));
  cmd(['config'], 'hostname <word>', 'Set system\'s network name', (D, a) => { D.host = a[0]; return []; });
  cmd(['config'], 'enable secret <word>', 'Assign the privileged level secret', (D, a) => { D.secret = a[0]; return []; });
  cmd(['config'], 'enable password <word>', 'Assign the privileged level password', (D, a) => { D.enpw = a[0]; return []; });
  cmd(['config'], 'no enable secret', 'Negate a command', D => { D.secret = null; return []; });
  cmd(['config'], 'service password-encryption', 'Encrypt system passwords', D => { D.spe = true; return []; });
  cmd(['config'], 'no service password-encryption', 'Negate a command', D => { D.spe = false; return []; });
  cmd(['config'], 'banner motd <rest>', 'Set Message of the Day banner', (D, a) => { const s = a[0], d = s[0], e = s.indexOf(d, 1); D.banner = e > 0 ? s.slice(1, e) : s.slice(1); return []; });
  cmd(['config'], 'no banner motd', 'Negate a command', D => { D.banner = ''; return []; });
  cmd(['config'], 'username <word> secret <word>', 'Establish User Name Authentication', (D, a) => { D.users[a[0]] = { p: a[1], s: 1 }; return []; });
  cmd(['config'], 'username <word> password <word>', 'Establish User Name Authentication', (D, a) => { D.users[a[0]] = { p: a[1] }; return []; });
  cmd(['config'], 'ip domain-name <word>', 'Define the default domain name', (D, a) => { D.dom = a[0]; return []; });
  cmd(['config'], 'ip ssh version <num>', 'Specify protocol version', D => { D.ssh = true; return D.rsa ? [] : ['Please create RSA keys to enable SSH (and of atleast 768 bits for SSH v2).']; });
  cmd(['config'], 'crypto key generate rsa', 'Generate RSA keys', D => { if (!D.dom) return ['% Please define a domain-name first.']; D.rsa = true; return [`The name for the keys will be: ${D.host}.${D.dom}`, 'How many bits in the modulus [512]: 2048', '% Generating 2048 bit RSA keys, keys will be non-exportable...[OK]', '', '%SSH-5-ENABLED: SSH 1.99 has been enabled']; });
  cmd(['config'], 'crypto key generate rsa modulus <num>', 'Generate RSA keys', (D, a) => { if (!D.dom) return ['% Please define a domain-name first.']; D.rsa = true; return [`% Generating ${a[0]} bit RSA keys, keys will be non-exportable...[OK]`, '%SSH-5-ENABLED: SSH 1.99 has been enabled']; });
  const goIf = (D, c, name) => {
    if (D.kind === 'router') { if (!D.ints[name]) { const p = parentIf(name); if (name.includes('.') && D.ints[p]) D.ints[name] = { ...rIf(), shut: false }; else return null; } c.mode = name.includes('.') ? 'subif' : 'if'; c.ifn = name; return []; }
    if (/^Vlan\d+$/.test(name)) { D.svi[name] = D.svi[name] || { ip: null, mask: null, shut: true }; c.mode = 'svi'; c.ifn = name; return name === 'Vlan1' || D.vlans[+name.slice(4)] ? [] : ['%LINK-5-CHANGED: Interface ' + name + ', changed state to down']; }
    if (!D.ints[name]) return null; c.mode = 'if'; c.ifn = name; return [];
  };
  cmd(['config', ...IFM], 'interface <if>', 'Select an interface to configure', (D, a, c) => { delete c.range; return goIf(D, c, a[0]); });
  cmd(['config', ...IFM], 'interface range <rest>', 'interface range command', (D, a, c) => {
    const list = []; for (const part of a[0].split(',')) {
      const m = part.replace(/\s+/g, '').match(/^([a-z]+)(\d+\/)(\d+)-(?:[a-z]+\d+\/)?(\d+)$/i) || part.replace(/\s+/g, '').match(/^([a-z]+)(\d+\/)(\d+)()$/i); if (!m) return null;
      for (let k = +m[3]; k <= +(m[4] || m[3]); k++) { const nm = normIf(m[1] + m[2] + k); if (!nm || !D.ints[nm]) return null; list.push(nm); }
    }
    c.mode = 'range'; c.range = list; c.ifn = list[0]; return [];
  });
  cmd(['config'], 'vlan <num>', 'VLAN commands', (D, a, c) => { const v = +a[0]; if (v < 1 || v > 4094) return null; if (!D.vlans[v]) D.vlans[v] = 'VLAN' + String(v).padStart(4, '0'); c.mode = 'vlan'; c.vlan = v; return []; }, 's');
  cmd(['config'], 'no vlan <num>', 'Negate a command', (D, a) => { if (+a[0] !== 1) delete D.vlans[+a[0]]; return +a[0] === 1 ? ['%Default VLAN 1 may not be deleted.'] : []; }, 's');
  cmd(['vlan'], 'name <word>', 'Ascii name of the VLAN', (D, a, c) => { D.vlans[c.vlan] = a[0]; return []; }, 's');
  cmd(['config'], 'ip default-gateway <ip>', 'Specify default gateway (if not routing IP)', (D, a) => { D.gw = a[0]; return []; }, 's');
  cmd(['config'], 'ip route <ip> <mask> <ip>', 'Establish static routes', (D, a) => { if (D.routes.some(r => r.net === a[0] && r.mask === a[1] && r.nh === a[2])) return []; if (netOf(a[0], a[1]) !== a[0]) return ['%Inconsistent address and mask']; D.routes.push({ net: a[0], mask: a[1], nh: a[2] }); return []; }, 'r');
  cmd(['config'], 'ip route <ip> <mask> <if>', 'Establish static routes', (D, a) => { if (!D.ints[a[2]]) return null; D.routes.push({ net: a[0], mask: a[1], ifn: a[2] }); return []; }, 'r');
  cmd(['config'], 'no ip route <ip> <mask> <ip>', 'Negate a command', (D, a) => { D.routes = D.routes.filter(r => !(r.net === a[0] && r.mask === a[1] && r.nh === a[2])); return []; }, 'r');
  cmd(['config'], 'no ip route <ip> <mask>', 'Negate a command', (D, a) => { D.routes = D.routes.filter(r => !(r.net === a[0] && r.mask === a[1])); return []; }, 'r');
  cmd(['config'], 'router ospf <num>', 'Open Shortest Path First (OSPF)', (D, a, c) => { if (!D.ospf) D.ospf = { pid: +a[0], nets: [], passive: [] }; c.mode = 'router'; return []; }, 'r');
  cmd(['config'], 'no router ospf <num>', 'Negate a command', D => { D.ospf = null; return []; }, 'r');
  cmd(['router'], 'network <ip> <ip> area <num>', 'Enable routing on an IP network', (D, a) => { if (!D.ospf.nets.some(x => x.ip === a[0] && x.w === a[1])) D.ospf.nets.push({ ip: a[0], w: a[1], area: +a[2] }); setTimeout(() => ospfLog(D), 900); return []; }, 'r');
  cmd(['router'], 'no network <ip> <ip> area <num>', 'Negate a command', (D, a) => { D.ospf.nets = D.ospf.nets.filter(x => !(x.ip === a[0] && x.w === a[1])); return []; }, 'r');
  cmd(['router'], 'router-id <ip>', 'router-id for this OSPF process', (D, a) => { D.ospf.rid = a[0]; return ['% OSPF: Reload or use "clear ip ospf process" command, for this to take effect']; }, 'r');
  cmd(['router'], 'passive-interface <if>', 'Suppress routing updates on an interface', (D, a) => { D.ospf.passive.push(a[0]); return []; }, 'r');
  cmd(['config'], 'access-list <num> <rest>', 'Add an access list entry', (D, a) => { const r = parseAcl(+a[0], a[1]); if (!r) return null; (D.acls[a[0]] = D.acls[a[0]] || []).push(r); return []; }, 'r');
  cmd(['config'], 'no access-list <num>', 'Negate a command', (D, a) => { delete D.acls[a[0]]; return []; }, 'r');
  cmd(['config'], 'line con <num>', 'Primary terminal line', (D, a, c) => { c.mode = 'line'; c.line = 'con'; return []; });
  cmd(['config'], 'line vty <num> <num>', 'Virtual terminal', (D, a, c) => { c.mode = 'line'; c.line = 'vty'; return []; });
  cmd(['line'], 'password <word>', 'Set a password', (D, a, c) => { D.lines[c.line].pw = a[0]; return []; });
  cmd(['line'], 'login', 'Enable password checking', (D, a, c) => { D.lines[c.line].login = 'login'; return D.lines[c.line].pw ? [] : ['% Login disabled on line, until \'password\' is set']; });
  cmd(['line'], 'login local', 'Local password checking', (D, a, c) => { D.lines[c.line].login = 'login local'; return []; });
  cmd(['line'], 'no login', 'Negate a command', (D, a, c) => { D.lines[c.line].login = ''; return []; });
  cmd(['line'], 'transport input <word>', 'Define which protocols to use when connecting to the terminal server', (D, a, c) => { if (!['ssh', 'telnet', 'all', 'none'].includes(a[0])) return null; D.lines[c.line].tin = a[0]; return []; });
  cmd(['line'], 'logging synchronous', 'Synchronized message output', (D, a, c) => { D.lines[c.line].sync = 1; return []; });
  cmd(['line'], 'exec-timeout <num> <num>', 'Set the EXEC timeout', () => []);

  // --- interface ---
  const each = (D, c, f) => { const o = []; for (const k of ifsOf(c)) { const r = f(c.mode === 'svi' ? D.svi[k] : D.ints[k], k); if (r) o.push(...r); } return o; };
  cmd(IFM, 'ip address <ip> <mask>', 'Set the IP address of an interface', (D, a, c) => {
    if (D.kind === 'switch' && c.mode !== 'svi') return null; if (!isMask(a[1])) return ['% Bad mask /' + a[1] + ' for address ' + a[0]];
    if (netOf(a[0], a[1]) === a[0]) return ['% ' + a[0] + ' is a network address — use a host address'];
    for (const [k, I] of Object.entries(D.kind === 'router' ? D.ints : D.svi)) if (k !== c.ifn && I.ip && same(I.ip, a[0], I.mask)) return [`% ${netOf(a[0], a[1])} overlaps with ${k}`];
    const I = c.mode === 'svi' ? D.svi[c.ifn] : D.ints[c.ifn]; I.ip = a[0]; I.mask = a[1]; return [];
  });
  cmd(IFM, 'no ip address', 'Negate a command', (D, a, c) => { const I = c.mode === 'svi' ? D.svi[c.ifn] : D.ints[c.ifn]; I.ip = I.mask = null; return []; });
  cmd(IFM, 'shutdown', 'Shutdown the selected interface', (D, a, c) => each(D, c, (I, k) => { I.shut = true; return [`%LINK-5-CHANGED: Interface ${k}, changed state to administratively down`, `%LINEPROTO-5-UPDOWN: Line protocol on Interface ${k}, changed state to down`]; }));
  cmd(IFM, 'no shutdown', 'Negate a command', (D, a, c) => each(D, c, (I, k) => {
    const was = I.shut; I.shut = false; if (!was) return [];
    const up = D.kind === 'router' ? rStatus(D, k) === 'up' : c.mode === 'svi' ? true : swPortUp(D, k);
    return [`%LINK-5-CHANGED: Interface ${k}, changed state to ${up ? 'up' : 'down'}`].concat(up ? [`%LINEPROTO-5-UPDOWN: Line protocol on Interface ${k}, changed state to up`] : []);
  }));
  cmd(IFM, 'description <rest>', 'Interface specific description', (D, a, c) => each(D, c, I => { I.desc = a[0]; }));
  cmd(IFM, 'no description', 'Negate a command', (D, a, c) => each(D, c, I => { I.desc = ''; }));
  cmd(['if', 'range'], 'switchport mode access', 'Set trunking mode to ACCESS unconditionally', (D, a, c) => each(D, c, I => { I.mode = 'access'; I.modeSet = 1; }), 's');
  cmd(['if', 'range'], 'switchport mode trunk', 'Set trunking mode to TRUNK unconditionally', (D, a, c) => each(D, c, (I, k) => { I.mode = 'trunk'; return [`%LINEPROTO-5-UPDOWN: Line protocol on Interface ${k}, changed state to down`, `%LINEPROTO-5-UPDOWN: Line protocol on Interface ${k}, changed state to up`]; }), 's');
  cmd(['if', 'range'], 'switchport access vlan <num>', 'Set VLAN when interface is in access mode', (D, a, c) => { const v = +a[0]; const o = D.vlans[v] ? [] : ['% Access VLAN does not exist. Creating vlan ' + v]; if (!D.vlans[v]) D.vlans[v] = 'VLAN' + String(v).padStart(4, '0'); each(D, c, I => { I.vlan = v; }); return o; }, 's');
  cmd(['if', 'range'], 'switchport trunk allowed vlan <rest>', 'Set allowed VLAN characteristics when interface is in trunking mode', (D, a, c) => {
    const s = a[0].trim(); let set = null;
    if (/^all$/i.test(s)) set = null; else { const m = s.match(/^(add|remove)\s+(.+)$/i); const parse = x => x.split(',').flatMap(p => { const r = p.split('-').map(Number); return r.length === 2 ? Array.from({ length: r[1] - r[0] + 1 }, (_, i) => r[0] + i) : [r[0]]; }).filter(v => v > 0);
      return each(D, c, I => { if (m) { const cur = I.allowed || Array.from({ length: 4094 }, (_, i) => i + 1); I.allowed = m[1].toLowerCase() === 'add' ? [...new Set(cur.concat(parse(m[2])))].sort((x, y) => x - y) : cur.filter(v => !parse(m[2]).includes(v)); } else I.allowed = parse(s); }); }
    return each(D, c, I => { I.allowed = set; });
  }, 's');
  cmd(['if', 'range'], 'switchport trunk native vlan <num>', 'Set native VLAN when interface is in trunking mode', (D, a, c) => each(D, c, I => { I.native = +a[0]; }), 's');
  cmd(['if', 'range'], 'switchport nonegotiate', 'Device will not engage in negotiation protocol on this interface', () => [], 's');
  cmd(['if', 'range'], 'switchport port-security', 'Security related command', (D, a, c) => each(D, c, I => { if (I.mode !== 'access' || !I.modeSet) return ['Command rejected: ' + 'FastEthernet is a dynamic port.']; I.ps = I.ps || { max: 1, viol: 'shutdown' }; }), 's');
  cmd(['if', 'range'], 'switchport port-security maximum <num>', 'Max secure addresses', (D, a, c) => each(D, c, I => { I.ps = I.ps || { max: 1, viol: 'shutdown' }; I.ps.max = +a[0]; }), 's');
  cmd(['if', 'range'], 'switchport port-security violation <word>', 'Security violation mode', (D, a, c) => { if (!['shutdown', 'restrict', 'protect'].includes(a[0])) return null; return each(D, c, I => { I.ps = I.ps || { max: 1, viol: 'shutdown' }; I.ps.viol = a[0]; }); }, 's');
  cmd(['if', 'range'], 'switchport port-security mac-address sticky', 'Configure dynamic secure addresses as sticky', (D, a, c) => each(D, c, I => { I.ps = I.ps || { max: 1, viol: 'shutdown' }; I.ps.sticky = 1; }), 's');
  cmd(['if', 'range'], 'no switchport port-security', 'Negate a command', (D, a, c) => each(D, c, I => { I.ps = null; }), 's');
  cmd(['subif'], 'encapsulation dot1Q <num>', 'IEEE 802.1Q Virtual LAN', (D, a, c) => { D.ints[c.ifn].enc = +a[0]; return []; }, 'r');
  cmd(['if', 'subif'], 'ip access-group <num> <word>', 'Specify access control for packets', (D, a, c) => { if (!['in', 'out'].includes(a[1])) return null; D.ints[c.ifn].acl[a[1]] = +a[0]; return []; }, 'r');
  cmd(['if', 'subif'], 'no ip access-group <num> <word>', 'Negate a command', (D, a, c) => { delete D.ints[c.ifn].acl[a[1]]; return []; }, 'r');

  function parseAcl(num, rest) {
    const t = rest.trim().split(/\s+/); let i = 0; const act = t[i++]; if (!['permit', 'deny'].includes(act)) return null;
    const addr = () => { if (t[i] === 'any') { i++; return { any: 1 }; } if (t[i] === 'host') { i++; return isIP(t[i]) ? { host: t[i++] } : null; } if (!isIP(t[i])) return null; const a = t[i++]; const w = isIP(t[i]) ? t[i++] : '0.0.0.0'; return { ip: a, w }; };
    if (num < 100) { const s = addr(); return s && i === t.length ? { act, std: 1, src: s } : null; }
    const proto = (t[i++] || '').toLowerCase(); if (!['ip', 'icmp', 'tcp', 'udp'].includes(proto)) return null;
    const src = addr(); if (!src) return null; const dst = addr(); if (!dst) return null; let port = null;
    if (t[i] === 'eq') { i++; port = t[i++]; } if (i !== t.length) return null;
    return { act, proto, src, dst, port };
  }
  function ospfLog(D) {
    const c = L && L.con[D.name]; if (!c) return;
    const nb = ospfNbrs(D, segments()); c.ospfSeen = c.ospfSeen || new Set();
    nb.forEach(x => { if (!c.ospfSeen.has(x.rid)) { c.ospfSeen.add(x.rid); c.out.push(`%OSPF-5-ADJCHG: Process ${D.ospf.pid}, Nbr ${x.rid} on ${x.ifn} from LOADING to FULL, Loading Done`); const o = L.con[x.R.name]; if (o) { o.ospfSeen = o.ospfSeen || new Set(); if (!o.ospfSeen.has(ospfRid(D))) { o.ospfSeen.add(ospfRid(D)); o.out.push(`%OSPF-5-ADJCHG: Process ${x.R.ospf.pid}, Nbr ${ospfRid(D)} on ${x.ifn} from LOADING to FULL, Loading Done`); } } } });
    paintTerm(); paintSide();
  }

  // ── αναλυτής: ταιριάζει τις λέξεις με τα πρότυπα (συντομεύσεις, παράμετροι) ──
  const PARAM = { '<ip>': isIP, '<mask>': isMask, '<num>': s => /^\d+$/.test(s), '<word>': s => !!s };
  const PHELP = { '<ip>': 'A.B.C.D', '<mask>': 'A.B.C.D', '<num>': '<0-4294967295>', '<word>': 'WORD', '<if>': 'Interface (e.g. g0/0, fa0/1, g0/0.10)', '<rest>': 'LINE' };
  function tryMatch(spec, toks) {
    const args = []; let i = 0, p = 0;
    for (; p < spec.pat.length; p++) {
      const pt = spec.pat[p];
      if (i >= toks.length) return { spec, args, inc: true, depth: i, at: p };
      if (pt === '<rest>') { args.push(toks.slice(i).join(' ')); i = toks.length; continue; }
      if (pt === '<if>') { let nm = normIf(toks[i]); if (nm) { args.push(nm); i++; continue; } if (i + 1 < toks.length && (nm = normIf(toks[i] + toks[i + 1]))) { args.push(nm); i += 2; continue; } return { spec, fail: true, depth: i }; }
      if (PARAM[pt]) { if (!PARAM[pt](toks[i])) return { spec, fail: true, depth: i }; args.push(toks[i++]); continue; }
      if (!pt.toLowerCase().startsWith(toks[i].toLowerCase())) return { spec, fail: true, depth: i };
      i++;
    }
    if (i < toks.length) return { spec, fail: true, depth: i };
    return { spec, args, ok: true, exact: spec.pat.every((pt, k) => pt.startsWith('<') || (toks[k] || '').toLowerCase() === pt.toLowerCase()) };
  }
  const avail = (D, mode) => C.filter(s => s.modes.includes(mode) && (!s.kind || (s.kind === 'r') === (D.kind === 'router')));
  function exec(D, c, line, asMode) {
    const toks = line.trim().split(/\s+/).filter(Boolean); if (!toks.length) return [];
    const mode = asMode || c.mode, specs = avail(D, mode), R = specs.map(s => tryMatch(s, toks));
    let ok = R.filter(r => r.ok);
    if (ok.length > 1) { const ex = ok.filter(r => r.exact); if (ex.length) ok = ex; }
    if (ok.length > 1) { // ίδια λέξη; αν οι υποψήφιες λέξεις διαφέρουν → ambiguous
      const words = new Set(ok.map(r => r.spec.pat.slice(0, toks.length).filter(x => !x.startsWith('<')).join(' ')));
      if (words.size > 1) return ['% Ambiguous command:  "' + line.trim() + '"'];
    }
    if (ok.length) { const r = ok[0], o = r.spec.fn(D, r.args, c, mode); if (o === null) return err(line, 0, (c.promptLen || 0) + line.length - (toks[toks.length - 1] || '').length); return o; }
    if (R.some(r => r.inc)) return ['% Incomplete command.', ''];
    if (!asMode && CFG.includes(mode) && mode !== 'config') { // όπως στο IOS: εντολή global από υπο-mode → πάει πίσω στο (config)
      const r2 = avail(D, 'config').map(s => tryMatch(s, toks)).filter(r => r.ok);
      if (r2.length) { const keep = c.mode; c.mode = 'config'; delete c.range; const o = r2[0].spec.fn(D, r2[0].args, c, 'config'); if (o !== null) return o; c.mode = keep; }
    }
    const depth = Math.max(0, ...R.map(r => r.depth || 0)); let col = 0, k = 0; const raw = line.replace(/^\s+/, '');
    for (; k < depth && k < toks.length; k++) col = raw.indexOf(toks[k], col) + toks[k].length; if (depth > 0) col = raw.indexOf(toks[Math.min(depth, toks.length - 1)], col);
    return err(line, depth, (c.promptLen || 0) + Math.max(0, col));
  }
  const WD = { description: 'Interface specific description', do: 'To run exec commands in config mode', interface: 'Select an interface to configure', ip: 'Interface Internet Protocol config commands', no: 'Negate a command or set its defaults', show: 'Show running system information', switchport: 'Set switching mode characteristics', 'access-group': 'Specify access control for packets', address: 'Set the IP address of an interface', interface: 'Select an interface to configure', ospf: 'OSPF information', route: 'IP routing table', vlan: 'VTP VLAN status / VLAN commands', mode: 'Set trunking mode of the interface', access: 'Set access mode characteristics of the interface', trunk: 'Set trunking characteristics of the interface', 'port-security': 'Security related command', router: 'Enable a routing process', 'access-list': 'Add an access list entry', line: 'Configure a terminal line', username: 'Establish User Name Authentication', enable: 'Modify enable password parameters', service: 'Modify use of network based services', banner: 'Define a login banner', hostname: "Set system's network name", crypto: 'Encryption module', 'ip': 'Global IP configuration subcommands', copy: 'Copy from one file to another', write: 'Write running configuration to memory', ping: 'Send echo messages', configure: 'Enter configuration mode', brief: 'Brief summary', 'running-config': 'Current operating configuration', 'startup-config': 'Contents of startup configuration', neighbor: 'Neighbor list', 'access-lists': 'List access lists', interfaces: 'Interface status and configuration', mac: 'MAC configuration', version: 'System hardware and software status', range: 'interface range command', network: 'Enable routing on an IP network', 'router-id': 'router-id for this OSPF process', 'passive-interface': 'Suppress routing updates on an interface', password: 'Set a password', login: 'Enable password checking', transport: 'Define transport protocols for line', secret: 'Assign the privileged level secret', encapsulation: 'Set encapsulation type for an interface', shutdown: 'Shutdown the selected interface', exit: 'Exit from current mode', end: 'Exit from configure mode', terminal: 'Configure from the terminal', 'default-gateway': 'Specify default gateway (if not routing IP)', 'domain-name': 'Define the default domain name', ssh: 'Configure ssh options' };
  function helpFor(D, c, line) {
    const sp = /\s$/.test(line), toks = line.trim().split(/\s+/).filter(Boolean), specs = avail(D, c.mode), m = new Map();
    if (sp || !toks.length) { for (const s of specs) { const r = tryMatch(s, toks); if (r.inc) { const pt = s.pat[r.at]; { const k = pt.startsWith('<') ? PHELP[pt] : pt, h = pt.startsWith('<') ? '' : s.pat.length === r.at + 1 ? s.help : (WD[pt] || ''); if (!m.get(k)) m.set(k, h); } } else if (r.ok && toks.length) m.set('<cr>', ''); } }
    else { const head = toks.slice(0, -1), last = toks[toks.length - 1].toLowerCase(); for (const s of specs) { const r = tryMatch(s, head); if (r.inc) { const pt = s.pat[r.at]; if (!pt.startsWith('<') && pt.toLowerCase().startsWith(last)) m.set(pt, WD[pt] || (s.pat.length === r.at + 1 ? s.help : '')); } } }
    if (!m.size) return ['% Unrecognized command'];
    return [...m.entries()].sort().map(([k, h]) => '  ' + pad(k, 22) + h);
  }
  function complete(D, c, line) {
    if (/\s$/.test(line)) return line; const toks = line.trim().split(/\s+/), head = toks.slice(0, -1), last = toks[toks.length - 1].toLowerCase(), cand = new Set();
    for (const s of avail(D, c.mode)) { const r = tryMatch(s, head); if (r.inc) { const pt = s.pat[r.at]; if (!pt.startsWith('<') && pt.toLowerCase().startsWith(last)) cand.add(pt); } }
    return cand.size === 1 ? line.replace(/\S+$/, [...cand][0] + ' ') : line;
  }

  // ── PC (Windows-like) ──
  function pcExec(D, line) {
    const t = line.trim().split(/\s+/), c0 = (t[0] || '').toLowerCase();
    if (!c0) return [];
    if (c0 === 'ipconfig') return ['', 'Ethernet adapter Ethernet0:', '', '   Connection-specific DNS Suffix  . :', '   IPv4 Address. . . . . . . . . . . : ' + (D.ip || '0.0.0.0'), '   Subnet Mask . . . . . . . . . . . : ' + (D.mask || '0.0.0.0'), '   Default Gateway . . . . . . . . . : ' + (D.gw || ''), ''];
    if (c0 === 'ping' && isIP(t[1] || '')) {
      const r = ping(D.name, t[1]), o = ['', `Pinging ${t[1]} with 32 bytes of data:`, ''];
      for (let k = 0; k < 4; k++) o.push(r.ok ? `Reply from ${t[1]}: bytes=32 time${k ? '=' + (1 + t[1].length % 3) + 'ms' : '<1ms'} TTL=${t[1] === '8.8.8.8' || t[1] === '1.1.1.1' ? 117 : 255 - (L.D[D.name].gw === t[1] ? 0 : 1)}` : r.why === 'unreach' || r.why === 'noip' ? `Reply from ${D.ip}: Destination host unreachable.` : 'Request timed out.');
      const rx = r.ok ? 4 : r.why === 'unreach' ? 4 : 0;
      o.push('', `Ping statistics for ${t[1]}:`, `    Packets: Sent = 4, Received = ${rx}, Lost = ${4 - rx} (${(4 - rx) * 25}% loss),`, ''); return o;
    }
    if (c0 === 'tracert' && isIP(t[1] || '')) { const r = ping(D.name, t[1]); return ['', 'Tracing route to ' + t[1] + ' over a maximum of 30 hops:', '', r.ok ? `  1    <1 ms    <1 ms    <1 ms  ${t[1]}` : '  1     *        *        *     Request timed out.', '', 'Trace complete.']; }
    if (c0 === 'help' || c0 === '?') return ['Available commands: ipconfig, ping <ip>, tracert <ip>, cls'];
    if (c0 === 'cls') { L.con[D.name].out = []; return []; }
    return [`'${t[0]}' is not recognized as an internal or external command,`, 'operable program or batch file.'];
  }

  // ───────────── ασκήσεις ─────────────
  const P = (from, to) => ping(from, to).ok;
  const RIF = (d, i) => L.D[d].ints[i] || {};
  const pre = { // έτοιμα κομμάτια ρυθμίσεων για ασκήσεις που χτίζουν πάνω σε προηγούμενες
    vlans(D) { const S = D.SW1; S.vlans[10] = 'STAFF'; S.vlans[20] = 'GUEST'; S.ints['FastEthernet0/1'].vlan = 10; S.ints['FastEthernet0/3'].vlan = 10; S.ints['FastEthernet0/2'].vlan = 20; ['FastEthernet0/1', 'FastEthernet0/2', 'FastEthernet0/3'].forEach(k => S.ints[k].modeSet = 1); Object.assign(D.PC1, { ip: '192.168.10.10', gw: '192.168.10.1' }); Object.assign(D.PC3, { ip: '192.168.10.11', gw: '192.168.10.1' }); Object.assign(D.PC2, { ip: '192.168.20.10', gw: '192.168.20.1' }); },
    roas(D) { pre.vlans(D); D.SW1.ints['GigabitEthernet0/1'].mode = 'trunk'; const R = D.R1; R.ints['GigabitEthernet0/0'].shut = false; R.ints['GigabitEthernet0/0.10'] = { ...rIf(), shut: false, enc: 10, ip: '192.168.10.1', mask: '255.255.255.0' }; R.ints['GigabitEthernet0/0.20'] = { ...rIf(), shut: false, enc: 20, ip: '192.168.20.1', mask: '255.255.255.0' }; },
    wan(D) { Object.assign(D.R1.ints['GigabitEthernet0/1'], { ip: '203.0.113.2', mask: '255.255.255.252', shut: false }); D.R1.routes.push({ net: '0.0.0.0', mask: '0.0.0.0', nh: '203.0.113.1' }); },
    lan1(D) { Object.assign(D.R1.ints['GigabitEthernet0/0'], { ip: '192.168.1.1', mask: '255.255.255.0', shut: false }); },
    bIfs(D) { Object.assign(D.R1.ints['GigabitEthernet0/0'], { ip: '192.168.1.1', mask: '255.255.255.0', shut: false }); Object.assign(D.R1.ints['GigabitEthernet0/1'], { ip: '10.0.0.1', mask: '255.255.255.252', shut: false }); Object.assign(D.R2.ints['GigabitEthernet0/0'], { ip: '192.168.2.1', mask: '255.255.255.0', shut: false }); Object.assign(D.R2.ints['GigabitEthernet0/1'], { ip: '10.0.0.2', mask: '255.255.255.252', shut: false }); },
  };
  const EX = [
    { id: 'basics', t: 'Πρώτα βήματα στο IOS', topo: 'A', dev: 'R1',
      d: 'Γνωριμία με τα modes του Cisco: από το «R1>» (user) στο «R1#» (privileged) και μετά στο «R1(config)#». Δώσε όνομα στον router, βάλε κωδικό και αποθήκευσε.',
      g: [['Μπες σε privileged mode (enable)', () => L.D.R1.flags.enabled], ['Άλλαξε το hostname σε HQ-R1', () => L.D.R1.host === 'HQ-R1'], ['Βάλε enable secret', () => !!L.D.R1.secret], ['Βάλε μήνυμα banner motd', () => !!L.D.R1.banner], ['Αποθήκευσε τις ρυθμίσεις (copy run start)', () => L.D.R1.saved && L.D.R1.saved.join('\n') === runCfg(L.D.R1).slice(3).join('\n')]],
      hints: ['Γράψε «?» σε οποιοδήποτε σημείο για να δεις τι εντολές υπάρχουν.', 'Οι εντολές συντομεύονται: «conf t» = configure terminal.', 'Banner: banner motd #Μόνο για εξουσιοδοτημένους#'],
      sol: { R1: ['enable', 'configure terminal', 'hostname HQ-R1', 'enable secret cisco123', 'banner motd #Authorized access only#', 'end', 'copy running-config startup-config'] } },
    { id: 'iface', t: 'Διεύθυνση IP σε διεπαφή', topo: 'A', dev: 'R1',
      d: 'Οι διεπαφές των routers είναι κλειστές (shutdown) από προεπιλογή. Δώσε στη Gi0/0 τη διεύθυνση της πύλης του LAN (192.168.1.1/24), άνοιξέ την και δες αν σε «βλέπουν» τα PC.',
      g: [['Gi0/0: 192.168.1.1 255.255.255.0', () => RIF('R1', 'GigabitEthernet0/0').ip === '192.168.1.1' && RIF('R1', 'GigabitEthernet0/0').mask === '255.255.255.0'], ['Η Gi0/0 είναι up (no shutdown)', () => rStatus(L.D.R1, 'GigabitEthernet0/0') === 'up'], ['Το PC1 κάνει ping την πύλη 192.168.1.1', () => P('PC1', '192.168.1.1')], ['Βάλε description στη Gi0/0', () => !!RIF('R1', 'GigabitEthernet0/0').desc]],
      hints: ['interface g0/0 → ip address … → no shutdown', 'Έλεγξε με «show ip interface brief» (sh ip int br).', 'Για το ping: διάλεξε το PC1 πάνω από το τερματικό και γράψε «ping 192.168.1.1».'],
      sol: { R1: ['enable', 'conf t', 'interface g0/0', 'description LAN', 'ip address 192.168.1.1 255.255.255.0', 'no shutdown', 'end', 'show ip interface brief'], PC1: ['ping 192.168.1.1'] } },
    { id: 'default', t: 'Έξοδος στο internet (default route)', topo: 'A', dev: 'R1', setup: D => pre.lan1(D),
      d: 'Το LAN δουλεύει. Τώρα σύνδεσε τη Gi0/1 με τον πάροχο (203.0.113.2/30, πύλη ISP 203.0.113.1) και πρόσθεσε default route, ώστε όλα τα «άγνωστα» δίκτυα να πηγαίνουν στον ISP.',
      g: [['Gi0/1: 203.0.113.2 255.255.255.252, up', () => RIF('R1', 'GigabitEthernet0/1').ip === '203.0.113.2' && rStatus(L.D.R1, 'GigabitEthernet0/1') === 'up'], ['Default route 0.0.0.0/0 προς 203.0.113.1', () => L.D.R1.routes.some(r => r.net === '0.0.0.0' && r.mask === '0.0.0.0')], ['Το PC1 κάνει ping το 8.8.8.8', () => P('PC1', '8.8.8.8')]],
      hints: ['Ένα /30 έχει μάσκα 255.255.255.252: μόνο 2 χρήσιμες διευθύνσεις.', 'ip route 0.0.0.0 0.0.0.0 203.0.113.1', 'Δες τον πίνακα με «show ip route»: θα εμφανιστεί «S*» και «Gateway of last resort».'],
      sol: { R1: ['enable', 'conf t', 'int g0/1', 'ip address 203.0.113.2 255.255.255.252', 'no shut', 'exit', 'ip route 0.0.0.0 0.0.0.0 203.0.113.1', 'end', 'show ip route'], PC1: ['ping 8.8.8.8'] } },
    { id: 'vlans', t: 'VLAN: χώρισε το δίκτυο', topo: 'A', dev: 'SW1', setup: D => { Object.assign(D.PC1, { ip: '192.168.10.10', gw: '192.168.10.1' }); Object.assign(D.PC3, { ip: '192.168.10.11', gw: '192.168.10.1' }); Object.assign(D.PC2, { ip: '192.168.20.10', gw: '192.168.20.1' }); },
      d: 'Στο switch φτιάξε VLAN 10 (STAFF) για τα PC1/PC3 και VLAN 20 (GUEST) για το PC2. Οι επισκέπτες πρέπει να μη «βλέπουν» τους υπαλλήλους — ούτε καν στο ίδιο switch.',
      g: [['VLAN 10 με όνομα STAFF', () => L.D.SW1.vlans[10] === 'STAFF'], ['VLAN 20 με όνομα GUEST', () => L.D.SW1.vlans[20] === 'GUEST'], ['Fa0/1 και Fa0/3 στο VLAN 10 (access)', () => ['FastEthernet0/1', 'FastEthernet0/3'].every(k => L.D.SW1.ints[k].vlan === 10 && L.D.SW1.ints[k].mode === 'access')], ['Fa0/2 στο VLAN 20 (access)', () => L.D.SW1.ints['FastEthernet0/2'].vlan === 20], ['PC1 → PC3 ping δουλεύει', () => P('PC1', '192.168.10.11')], ['PC1 → PC2 ΔΕΝ περνά (απομόνωση)', () => !P('PC1', '192.168.20.10') && L.D.SW1.vlans[20]]],
      hints: ['vlan 10 → name STAFF → exit', 'interface range fa0/1 , fa0/3 → switchport mode access → switchport access vlan 10', 'Έλεγξε με «show vlan brief».'],
      sol: { SW1: ['enable', 'conf t', 'vlan 10', 'name STAFF', 'vlan 20', 'name GUEST', 'exit', 'interface range fa0/1 , fa0/3', 'switchport mode access', 'switchport access vlan 10', 'interface fa0/2', 'switchport mode access', 'switchport access vlan 20', 'end', 'show vlan brief'], PC1: ['ping 192.168.10.11', 'ping 192.168.20.10'] } },
    { id: 'roas', t: 'Router-on-a-stick (inter-VLAN routing)', topo: 'A', dev: 'R1', setup: D => pre.vlans(D),
      d: 'Τα VLAN είναι έτοιμα. Τώρα θέλουμε τα δύο VLAN να επικοινωνούν ΜΕΣΩ του router: trunk από το switch, και υποδιεπαφές (Gi0/0.10, Gi0/0.20) με 802.1Q στον router — μία πύλη ανά VLAN, πάνω σε ένα καλώδιο.',
      g: [['SW1 Gi0/1 σε trunk', () => L.D.SW1.ints['GigabitEthernet0/1'].mode === 'trunk'], ['R1 Gi0/0 up', () => !RIF('R1', 'GigabitEthernet0/0').shut], ['Gi0/0.10: dot1Q 10, 192.168.10.1/24', () => RIF('R1', 'GigabitEthernet0/0.10').enc === 10 && RIF('R1', 'GigabitEthernet0/0.10').ip === '192.168.10.1'], ['Gi0/0.20: dot1Q 20, 192.168.20.1/24', () => RIF('R1', 'GigabitEthernet0/0.20').enc === 20 && RIF('R1', 'GigabitEthernet0/0.20').ip === '192.168.20.1'], ['PC1 (VLAN 10) → PC2 (VLAN 20) ping δουλεύει', () => P('PC1', '192.168.20.10')]],
      hints: ['Στο SW1: interface g0/1 → switchport mode trunk', 'Στο R1: interface g0/0 → no shutdown, μετά interface g0/0.10 → encapsulation dot1Q 10 → ip address …', 'Έλεγξε: «show interfaces trunk» στο switch, «show ip route» στον router.'],
      sol: { SW1: ['enable', 'conf t', 'interface g0/1', 'switchport mode trunk', 'end'], R1: ['enable', 'conf t', 'interface g0/0', 'no shutdown', 'interface g0/0.10', 'encapsulation dot1Q 10', 'ip address 192.168.10.1 255.255.255.0', 'interface g0/0.20', 'encapsulation dot1Q 20', 'ip address 192.168.20.1 255.255.255.0', 'end', 'show ip route'], PC1: ['ping 192.168.20.10'] } },
    { id: 'acl', t: 'ACL: κόψε τους επισκέπτες', topo: 'A', dev: 'R1', setup: D => { pre.roas(D); pre.wan(D); },
      d: 'Όλα επικοινωνούν — και αυτό είναι πρόβλημα: το Wi-Fi επισκεπτών (VLAN 20) φτάνει στους υπολογιστές του γραφείου. Γράψε extended ACL ώστε το GUEST να ΜΗΝ φτάνει στο STAFF, αλλά να έχει internet.',
      g: [['Το PC2 (GUEST) ΔΕΝ φτάνει το PC1', () => !P('PC2', '192.168.10.10')], ['Το PC2 (GUEST) έχει internet (8.8.8.8)', () => P('PC2', '8.8.8.8')], ['Το PC1 (STAFF) έχει internet', () => P('PC1', '8.8.8.8')], ['Η ACL είναι εφαρμοσμένη «in» στη Gi0/0.20', () => !!RIF('R1', 'GigabitEthernet0/0.20').acl.in]],
      hints: ['Οι extended ACL (100–199) εφαρμόζονται όσο πιο κοντά στην ΠΗΓΗ.', 'access-list 110 deny ip 192.168.20.0 0.0.0.255 192.168.10.0 0.0.0.255', 'Μην ξεχάσεις «access-list 110 permit ip any any» — στο τέλος κάθε ACL υπάρχει κρυφό «deny all».'],
      sol: { R1: ['enable', 'conf t', 'access-list 110 deny ip 192.168.20.0 0.0.0.255 192.168.10.0 0.0.0.255', 'access-list 110 permit ip any any', 'interface g0/0.20', 'ip access-group 110 in', 'end', 'show access-lists'], PC2: ['ping 192.168.10.10', 'ping 8.8.8.8'] } },
    { id: 'harden', t: 'Θωράκιση switch', topo: 'A', dev: 'SW1',
      d: 'Ασφάλισε το switch όπως ζητά το CCNA: κρυπτογραφημένοι κωδικοί, μόνο SSH για απομακρυσμένη πρόσβαση, κλειστές οι αχρησιμοποίητες θύρες και port-security στη θύρα του PC1.',
      g: [['service password-encryption', () => L.D.SW1.spe], ['enable secret', () => !!L.D.SW1.secret], ['Χρήστης με secret (username … secret …)', () => Object.values(L.D.SW1.users).some(u => u.s)], ['VTY: login local + transport input ssh', () => L.D.SW1.lines.vty.login === 'login local' && L.D.SW1.lines.vty.tin === 'ssh'], ['Κλειδιά RSA για SSH (domain + crypto key)', () => L.D.SW1.rsa], ['Fa0/4–24 κλειστές (shutdown)', () => Array.from({ length: 21 }, (_, i) => 'FastEthernet0/' + (i + 4)).every(k => L.D.SW1.ints[k].shut)], ['Port-security στη Fa0/1 (max 1)', () => (L.D.SW1.ints['FastEthernet0/1'].ps || {}).max === 1]],
      hints: ['interface range fa0/4 - 24 → shutdown', 'Για SSH: ip domain-name lab.local → crypto key generate rsa → line vty 0 4 → login local → transport input ssh', 'Το port-security θέλει πρώτα «switchport mode access».'],
      sol: { SW1: ['enable', 'conf t', 'service password-encryption', 'enable secret Str0ng!', 'username admin secret Adm1n!', 'ip domain-name lab.local', 'crypto key generate rsa', 'line vty 0 4', 'login local', 'transport input ssh', 'exit', 'interface range fa0/4 - 24', 'shutdown', 'interface fa0/1', 'switchport mode access', 'switchport port-security', 'switchport port-security maximum 1', 'switchport port-security violation shutdown', 'end', 'show port-security'] } },
    { id: 'static', t: 'Στατική δρομολόγηση με 2 routers', topo: 'B', dev: 'R1',
      d: 'Δύο LAN (192.168.1.0/24 και 192.168.2.0/24) ενώνονται με ένα point-to-point link 10.0.0.0/30. Ρύθμισε τις διεπαφές και πες σε κάθε router πώς να φτάσει στο LAN του άλλου.',
      g: [['R1: Gi0/0 192.168.1.1/24 και Gi0/1 10.0.0.1/30, up', () => RIF('R1', 'GigabitEthernet0/0').ip === '192.168.1.1' && RIF('R1', 'GigabitEthernet0/1').ip === '10.0.0.1' && rStatus(L.D.R1, 'GigabitEthernet0/1') !== 'admin'], ['R2: Gi0/0 192.168.2.1/24 και Gi0/1 10.0.0.2/30, up', () => RIF('R2', 'GigabitEthernet0/0').ip === '192.168.2.1' && RIF('R2', 'GigabitEthernet0/1').ip === '10.0.0.2' && rStatus(L.D.R2, 'GigabitEthernet0/1') === 'up'], ['R1 → R2 ping 10.0.0.2', () => P('R1', '10.0.0.2')], ['Στατική διαδρομή και στους δύο', () => L.D.R1.routes.length && L.D.R2.routes.length], ['PC1 → PC2 ping δουλεύει', () => P('PC1', '192.168.2.10')]],
      hints: ['Η διαδρομή χρειάζεται ΚΑΙ προς τα πίσω: αν ο R2 δεν ξέρει το 192.168.1.0, η απάντηση χάνεται.', 'R1: ip route 192.168.2.0 255.255.255.0 10.0.0.2', 'Άλλαξε συσκευή (R1/R2) από τα κουμπιά πάνω από το τερματικό.'],
      sol: { R1: ['enable', 'conf t', 'int g0/0', 'ip address 192.168.1.1 255.255.255.0', 'no shut', 'int g0/1', 'ip address 10.0.0.1 255.255.255.252', 'no shut', 'exit', 'ip route 192.168.2.0 255.255.255.0 10.0.0.2', 'end'], R2: ['enable', 'conf t', 'int g0/0', 'ip address 192.168.2.1 255.255.255.0', 'no shut', 'int g0/1', 'ip address 10.0.0.2 255.255.255.252', 'no shut', 'exit', 'ip route 192.168.1.0 255.255.255.0 10.0.0.1', 'end', 'ping 192.168.1.10'], PC1: ['ping 192.168.2.10'] } },
    { id: 'ospf', t: 'OSPF: δυναμική δρομολόγηση', topo: 'B', dev: 'R1', setup: D => pre.bIfs(D),
      d: 'Αντί για στατικές διαδρομές, άφησε τους routers να τις μάθουν μόνοι τους με OSPF (area 0). Θα δεις τη γειτνίαση να ανεβαίνει «FULL» και διαδρομές «O» στον πίνακα.',
      g: [['OSPF process στον R1 και στον R2', () => L.D.R1.ospf && L.D.R2.ospf], ['Γειτνίαση OSPF (FULL)', () => ospfNbrs(L.D.R1, segments()).length > 0], ['Ο R1 έμαθε το 192.168.2.0/24 μέσω OSPF', () => rtable(L.D.R1).some(e => e.c === 'O' && e.net === '192.168.2.0')], ['PC1 → PC2 ping χωρίς στατικές διαδρομές', () => P('PC1', '192.168.2.10') && !L.D.R1.routes.length && !L.D.R2.routes.length]],
      hints: ['router ospf 1 → network 10.0.0.0 0.0.0.3 area 0', 'Η μάσκα στο OSPF γράφεται ως wildcard: /24 → 0.0.0.255, /30 → 0.0.0.3.', 'Έλεγξε: «show ip ospf neighbor» και «show ip route».'],
      sol: { R1: ['enable', 'conf t', 'router ospf 1', 'network 192.168.1.0 0.0.0.255 area 0', 'network 10.0.0.0 0.0.0.3 area 0', 'end'], R2: ['enable', 'conf t', 'router ospf 1', 'network 192.168.2.0 0.0.0.255 area 0', 'network 10.0.0.0 0.0.0.3 area 0', 'end', 'show ip ospf neighbor', 'show ip route'], PC1: ['ping 192.168.2.10'] } },
  ];
  const BYX = Object.fromEntries(EX.map(e => [e.id, e]));

  let PR = { done: {}, cur: 'basics' };
  try { PR = Object.assign(PR, JSON.parse(localStorage.getItem('nw-ccna') || '{}')); } catch (e) { }
  const saveP = () => { try { localStorage.setItem('nw-ccna', JSON.stringify(PR)); } catch (e) { } };

  function start(id) {
    const ex = BYX[id] || EX[0]; PR.cur = ex.id; saveP();
    const D = TOPO[ex.topo].make(); if (ex.setup) ex.setup(D);
    L = { ex, topo: ex.topo, D, con: {}, cur: ex.dev, tick: 0, busy: false };
    for (const d of Object.values(D)) if (d.kind !== 'cloud') L.con[d.name] = { mode: d.kind === 'pc' ? 'pc' : 'user', out: d.kind === 'pc' ? ['NetWatch PC — ' + d.name, 'Commands: ipconfig, ping <ip>, tracert <ip>', ''] : ['', 'Press RETURN to get started.', '', ''], hist: [], hi: 0, arp: new Set() };
  }
  const MODEP = { user: '>', priv: '#', config: '(config)#', if: '(config-if)#', subif: '(config-subif)#', vlan: '(config-vlan)#', line: '(config-line)#', router: '(config-router)#', range: '(config-if-range)#', svi: '(config-if)#' };
  const prompt = name => { const D = L.D[name], c = L.con[name]; return D.kind === 'pc' ? 'C:\\>' : D.host + MODEP[c.mode]; };
  function run(name, line) {
    const D = L.D[name], c = L.con[name]; L.tick++;
    if (c.pw) { const ok = line === (D.secret || D.enpw); c.out.push(''); if (ok) { c.mode = 'priv'; D.flags.enabled = 1; } else c.out.push('% Bad secrets', ''); c.pw = null; return; }
    c.out.push(prompt(name) + ' ' + line);
    if (line.trim()) { c.hist.push(line); if (c.hist.length > 60) c.hist.shift(); } c.hi = c.hist.length;
    c.promptLen = prompt(name).length + 1;
    const o = D.kind === 'pc' ? pcExec(D, line) : /\?\s*$/.test(line) ? helpFor(D, c, line.replace(/\?\s*$/, '')) : exec(D, c, line);
    if (o) c.out.push(...o);
    if (c.out.length > 600) c.out.splice(0, c.out.length - 600);
  }

  // ───────────── UI ─────────────
  const E = s => String(s).replace(/[&<>"]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
  const $c = sel => document.querySelector('#t-cli ' + sel);
  function topoSVG() {
    const T = TOPO[L.topo], att = segments(), W = 760, H = L.topo === 'A' ? 330 : 250;
    let g = `<svg viewBox="0 0 ${W} ${H}" class="cl-svg">`;
    for (const [a, ai, b, bi] of T.links) {
      const [x1, y1] = T.pos[a], [x2, y2] = T.pos[b], A = L.D[a], B = L.D[b];
      const upA = A.kind === 'router' ? rStatus(A, ai) === 'up' : A.kind === 'switch' ? swPortUp(A, ai) : true;
      const upB = B.kind === 'router' ? rStatus(B, bi) === 'up' : B.kind === 'switch' ? swPortUp(B, bi) : true;
      const sw = A.kind === 'switch' ? [A, ai] : B.kind === 'switch' ? [B, bi] : null, trunk = sw && sw[0].ints[sw[1]].mode === 'trunk';
      const col = upA && upB ? 'var(--green)' : 'var(--red)';
      g += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${col}" stroke-width="${trunk ? 4 : 2}" ${trunk ? 'stroke-dasharray="10 4"' : ''} opacity=".85"/>`;
      const lab = (x, y, xo, yo, s) => `<text x="${x + (xo - x) * .22}" y="${y + (yo - y) * .22 + (Math.abs(yo - y) < 5 ? -8 : 4)}" class="cl-il" text-anchor="middle">${E(s)}</text>`;
      if (A.kind !== 'pc' && A.kind !== 'cloud') g += lab(x1, y1, x2, y2, shortIf(ai)); if (B.kind !== 'pc' && B.kind !== 'cloud') g += lab(x2, y2, x1, y1, shortIf(bi));
      if (trunk) g += `<text x="${(x1 + x2) / 2 + 8}" y="${(y1 + y2) / 2}" class="cl-tr">trunk</text>`;
    }
    const VC = { 1: 'var(--dim)', 10: 'var(--cyan)', 20: 'var(--orange)', 30: 'var(--purple)' };
    for (const [nm, [x, y]] of Object.entries(T.pos)) {
      const D = L.D[nm], on = L.cur === nm, cls = 'cl-node' + (on ? ' on' : '') + (D.kind === 'cloud' ? ' cloud' : '');
      let shape = '', sub = '';
      if (D.kind === 'router') shape = `<circle r="24" class="cl-shape"/><path d="M-11 -4h22M7 -8l4 4-4 4M11 4h-22M-7 0l-4 4 4 4" class="cl-glyph"/>`;
      if (D.kind === 'switch') shape = `<rect x="-34" y="-16" width="68" height="32" rx="6" class="cl-shape"/><path d="M-20 -5h40M-20 5h40M14 -9l6 4-6 4M-14 1l-6 4 6 4" class="cl-glyph"/>`;
      if (D.kind === 'pc') { shape = `<rect x="-20" y="-16" width="40" height="27" rx="3" class="cl-shape"/><path d="M-8 17h16M0 11v6" class="cl-glyph"/>`;
        const pe = peer(nm, 'eth0'), S = pe && L.D[pe[0]], v = S && S.kind === 'switch' ? S.ints[pe[1]].vlan : null;
        sub = `<text y="34" class="cl-ip" text-anchor="middle">${E(D.ip || '—')}</text>` + (v && S.ints[pe[1]].mode === 'access' ? `<text y="48" class="cl-vl" text-anchor="middle" style="fill:${VC[v] || 'var(--green)'}">VLAN ${v}</text>` : ''); }
      if (D.kind === 'cloud') { shape = `<path d="M-30 10a14 14 0 0 1 4-27a18 18 0 0 1 33-4a14 14 0 0 1 23 13a11 11 0 0 1-2 18z" class="cl-shape"/>`; sub = `<text y="-26" class="cl-ip" text-anchor="middle">8.8.8.8 · 1.1.1.1</text>`; }
      g += `<g class="${cls}" data-dev="${nm}" transform="translate(${x},${y})">${shape}<text y="${D.kind === 'pc' ? 4 : D.kind === 'cloud' ? 4 : 5}" class="cl-dn" text-anchor="middle">${E(D.kind === 'cloud' ? 'ISP' : D.host)}</text>${sub}</g>`;
    }
    return g + '</svg>';
  }
  function paintTerm() {
    if (!L) return; const el = $c('.cl-out'); if (!el) return;
    const c = L.con[L.cur]; el.textContent = c.out.join('\n'); const p = $c('.cl-pr'); if (p) p.textContent = c.pw ? 'Password:' : prompt(L.cur);
    const inp = $c('.cl-in'); if (inp) inp.type = c.pw ? 'password' : 'text';
    const sc = $c('.cl-scr'); if (sc) sc.scrollTop = sc.scrollHeight;
    document.querySelectorAll('#t-cli [data-dt]').forEach(b => b.classList.toggle('on', b.dataset.dt === L.cur));
  }
  function paintSide() {
    if (!L) return; const ex = L.ex, el = $c('.cl-goals'); if (!el) return;
    const res = ex.g.map(([t, f]) => { let ok = false; try { ok = !!f(); } catch (e) { } return [t, ok]; }), all = res.every(r => r[1]);
    if (all && !PR.done[ex.id]) { PR.done[ex.id] = 1; saveP(); setTimeout(paintList, 0); }
    el.innerHTML = res.map(([t, ok]) => `<div class="cl-g${ok ? ' ok' : ''}"><span>${ok ? '✅' : '⬜'}</span><span>${E(t)}</span></div>`).join('') + (all ? `<div class="cl-win">🎉 <span>Ολοκληρώθηκε! Πάμε στην επόμενη άσκηση.</span>${nextEx() ? ` <button class="b" data-next>→ ${E(nextEx().t)}</button>` : ''}</div>` : '');
    const tp = $c('.cl-topo'); if (tp) { tp.innerHTML = topoSVG(); bindTopo(); }
    const nx = el.querySelector('[data-next]'); if (nx) nx.onclick = () => { start(nextEx().id); renderCli(); };
  }
  const nextEx = () => EX[EX.findIndex(e => e.id === L.ex.id) + 1];
  function paintList() { const el = $c('.cl-list'); if (!el) return; el.innerHTML = EX.map((e, i) => `<button class="cl-li${e.id === L.ex.id ? ' on' : ''}" data-ex="${e.id}"><span class="cl-num">${PR.done[e.id] ? '✓' : i + 1}</span><span>${E(e.t)}</span></button>`).join(''); el.querySelectorAll('[data-ex]').forEach(b => b.onclick = () => { start(b.dataset.ex); renderCli(); }); }
  function bindTopo() { document.querySelectorAll('#t-cli .cl-node[data-dev]').forEach(g => g.onclick = () => { if (L.con[g.dataset.dev]) { L.cur = g.dataset.dev; paintTerm(); paintSide(); focusIn(); } }); }
  const focusIn = () => { const i = $c('.cl-in'); if (i) i.focus({ preventScroll: true }); };
  async function typeSol(dev, lines) {
    if (L.busy) return; L.busy = true; const ex = L.ex;
    for (const [d, ls] of Object.entries(lines)) {
      if (L.ex !== ex) break; L.cur = d; paintTerm();
      for (const line of ls) { if (L.ex !== ex) break; const c = L.con[d]; if (c.mode === 'user' && line !== 'enable' && L.D[d].kind !== 'pc') run(d, 'enable'); if (c.pw) run(d, L.D[d].secret || L.D[d].enpw); run(d, line); paintTerm(); paintSide(); await new Promise(r => setTimeout(r, 260)); }
    }
    L.busy = false;
  }

  window.renderCli = () => {
    if (!L || L.ex.id !== PR.cur) start(PR.cur);
    const el = document.getElementById('t-cli'), ex = L.ex;
    const devs = Object.values(L.D).filter(d => d.kind !== 'cloud');
    el.innerHTML = `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">🖧 Cisco Lab <span class="tag">CCNA</span></b><span class="sm">${Object.keys(PR.done).filter(k => BYX[k]).length}/${EX.length} ασκήσεις</span></div>
      <div class="sm" style="margin-top:4px">Ένας προσομοιωτής Cisco IOS: γράφεις τις ίδιες εντολές με έναν πραγματικό router/switch, και το NetWatch υπολογίζει αν περνά το ping. «?» για βοήθεια, Tab για συμπλήρωση, ↑↓ για ιστορικό.</div></div>
      <div class="cl-grid"><div class="card cl-list"></div>
        <div class="cl-mid"><div class="card cl-topo"></div>
          <div class="card cl-term" data-noi18n><div class="cl-tabs">${devs.map(d => `<button class="cl-dt" data-dt="${d.name}">${d.kind === 'router' ? '⬤' : d.kind === 'switch' ? '▦' : '▭'} ${E(d.name)}</button>`).join('')}<span class="cl-sp"></span><button class="cl-dt" data-clr title="clear">⌫</button></div>
            <div class="cl-scr"><pre class="cl-out"></pre><div class="cl-line"><span class="cl-pr"></span><input class="cl-in" spellcheck="false" autocomplete="off" autocapitalize="off"></div></div></div></div>
        <div class="card cl-side"><div class="cl-h">${E(ex.t)}</div><div class="cl-d">${E(ex.d)}</div><div class="cl-goals"></div>
          <details class="cl-det"><summary>💡 Βοήθειες</summary>${ex.hints.map(h => `<div class="cl-hint">${E(h)}</div>`).join('')}</details>
          <details class="cl-det"><summary>🔑 Λύση</summary>${Object.entries(ex.sol).map(([d, ls]) => `<div class="cl-sd">${E(d)}</div><pre class="cl-sol" data-noi18n>${E(ls.join('\n'))}</pre>`).join('')}<button class="b" data-runsol>▶ Γράψε τη λύση για μένα</button></details>
          <div class="cl-acts"><button class="b" data-reset>↺ Επαναφορά άσκησης</button></div></div></div>`;
    paintList(); paintTerm(); paintSide();
    el.querySelectorAll('[data-dt]').forEach(b => b.onclick = () => { L.cur = b.dataset.dt; paintTerm(); focusIn(); });
    el.querySelector('[data-clr]').onclick = () => { L.con[L.cur].out = []; paintTerm(); focusIn(); };
    el.querySelector('[data-reset]').onclick = () => { start(ex.id); renderCli(); };
    el.querySelector('[data-runsol]').onclick = () => typeSol(null, ex.sol);
    el.querySelector('.cl-scr').onclick = () => { if (!getSelection().toString()) focusIn(); };
    const inp = el.querySelector('.cl-in');
    inp.onkeydown = e => {
      const c = L.con[L.cur], D = L.D[L.cur];
      if (e.key === 'Enter') { e.preventDefault(); const v = inp.value; inp.value = ''; run(L.cur, v); paintTerm(); paintSide(); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); if (c.hi > 0) inp.value = c.hist[--c.hi] || ''; return; }
      if (e.key === 'ArrowDown') { e.preventDefault(); c.hi = Math.min(c.hist.length, c.hi + 1); inp.value = c.hist[c.hi] || ''; return; }
      if (e.key === 'Tab') { e.preventDefault(); if (D.kind !== 'pc' && !c.pw) inp.value = complete(D, c, inp.value); return; }
      if (e.key === '?' && D.kind !== 'pc' && !c.pw) { e.preventDefault(); c.out.push(prompt(L.cur) + ' ' + inp.value + '?', ...helpFor(D, c, inp.value)); paintTerm(); return; }
      if ((e.key === 'z' || e.key === 'c') && e.ctrlKey && D.kind !== 'pc') { e.preventDefault(); c.out.push(prompt(L.cur) + ' ' + inp.value + '^' + e.key.toUpperCase()); if (c.mode !== 'user' && c.mode !== 'priv') c.mode = 'priv'; inp.value = ''; paintTerm(); }
    };
    setTimeout(focusIn, 50);
  };
  window.CISCOLAB = { start, run, ping: (a, b) => ping(a, b), state: () => L, exercises: EX };

  const css = `
  .cl-grid{display:grid;grid-template-columns:210px minmax(0,1fr) 300px;gap:12px;align-items:start}
  @media (max-width:1250px){.cl-grid{grid-template-columns:1fr}.cl-list{flex-direction:row!important;flex-wrap:wrap}}
  .cl-list{display:flex;flex-direction:column;gap:4px;padding:8px}
  .cl-li{display:flex;gap:8px;align-items:center;text-align:left;background:none;border:1px solid transparent;color:inherit;font:inherit;font-size:13px;padding:7px 8px;border-radius:8px;cursor:pointer}
  .cl-li:hover{background:rgb(var(--w) / 5%)}.cl-li.on{background:color-mix(in srgb,var(--cyan) 13%,transparent);border-color:color-mix(in srgb,var(--cyan) 40%,transparent)}
  .cl-num{flex:none;width:20px;height:20px;border-radius:50%;display:grid;place-items:center;font-size:11px;background:rgb(var(--w) / 8%)}
  .cl-li .cl-num:not(:empty){font-weight:600}.cl-li.on .cl-num{background:var(--cyan);color:#001}
  .cl-mid{display:flex;flex-direction:column;gap:12px;min-width:0}
  .cl-topo{padding:6px}.cl-svg{width:100%;height:auto;display:block;max-height:330px}
  .cl-shape{fill:rgb(var(--w) / 6%);stroke:rgb(var(--w) / 35%);stroke-width:1.5}.cl-glyph{fill:none;stroke:rgb(var(--w) / 55%);stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
  .cl-node{cursor:pointer}.cl-node.cloud{cursor:default}.cl-node:hover .cl-shape{stroke:var(--cyan)}
  .cl-node.on .cl-shape{stroke:var(--cyan);stroke-width:2.5;fill:color-mix(in srgb,var(--cyan) 14%,transparent)}
  .cl-dn{fill:currentColor;font-size:13px;font-weight:700;pointer-events:none}.cl-node:not(.cloud) .cl-dn{transform:translateY(${0}px)}
  .cl-node .cl-dn{dominant-baseline:middle}.cl-node[data-dev^="PC"] .cl-dn,.cl-node[data-dev^="R"] .cl-dn,.cl-node[data-dev^="SW"] .cl-dn{transform:translateY(-1px)}
  .cl-node[data-dev^="R"] .cl-glyph,.cl-node[data-dev^="SW"] .cl-glyph,.cl-node[data-dev^="PC"] .cl-glyph{opacity:.0}
  .cl-ip{fill:var(--dim);font-size:12.5px;font-family:var(--mono,ui-monospace,monospace)}.cl-vl{font-size:12px;font-weight:700}
  .cl-il{fill:var(--dim);font-size:12px;font-family:var(--mono,ui-monospace,monospace)}.cl-tr{fill:var(--yellow,#ffd23f);font-size:12px;font-weight:700}
  .cl-term{padding:0;overflow:hidden;background:#05080f;border-color:rgb(var(--w) / 12%)}
  .cl-tabs{display:flex;gap:2px;padding:6px 6px 0;background:rgb(var(--w) / 4%);border-bottom:1px solid rgb(var(--w) / 10%)}
  .cl-dt{background:none;border:none;color:var(--dim);font:12px var(--mono,ui-monospace,monospace);padding:6px 11px;border-radius:7px 7px 0 0;cursor:pointer}
  .cl-dt:hover{color:#cfe0f5}.cl-dt.on{background:#05080f;color:#7ee787;box-shadow:inset 0 2px 0 #7ee787}.cl-sp{flex:1}
  .cl-scr{height:360px;overflow:auto;padding:10px 12px;font:12.5px/1.45 var(--mono,ui-monospace,SFMono-Regular,Menlo,monospace);color:#d6e2f0;cursor:text}
  .cl-out{margin:0;white-space:pre-wrap;word-break:break-word;font:inherit;color:inherit;background:none;border:0;padding:0}
  .cl-line{display:flex;align-items:baseline;gap:6px}.cl-pr{color:#7ee787;white-space:pre}
  .cl-in{flex:1;background:none;border:0;outline:none;color:#fff;font:inherit;padding:0;caret-color:#7ee787;min-width:0}
  .cl-side{white-space:normal}.cl-h{font-weight:700;font-size:15px;margin-bottom:6px}.cl-d{font-size:13px;line-height:1.55;color:var(--dim);margin-bottom:12px}
  .cl-g{display:flex;gap:8px;align-items:flex-start;font-size:13px;padding:5px 0;border-top:1px solid rgb(var(--w) / 6%);transition:color .2s}
  .cl-g.ok{color:var(--green)}
  .cl-win{margin-top:10px;padding:10px;border-radius:8px;background:color-mix(in srgb,var(--green) 14%,transparent);color:var(--green);font-weight:600;display:flex;flex-wrap:wrap;gap:8px;align-items:center;animation:clPop .4s ease}
  html.nomo .cl-win{animation:none}
  @keyframes clPop{from{transform:scale(.96);opacity:0}to{transform:none;opacity:1}}
  .cl-det{margin-top:10px}.cl-det summary{cursor:pointer;font-size:13px;color:var(--cyan)}
  .cl-hint{font-size:12.5px;padding:6px 0 0;line-height:1.5}
  .cl-sd{font-size:11px;color:var(--dim);margin-top:8px;font-weight:700}
  .cl-sol{margin:4px 0;padding:8px;border-radius:6px;background:#05080f;color:#d6e2f0;font:11.5px/1.45 var(--mono,ui-monospace,monospace);white-space:pre-wrap}
  .cl-acts{margin-top:12px}`;
  const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);
})();
