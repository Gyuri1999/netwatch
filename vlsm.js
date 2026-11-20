// ───────────────────────── 🧮 Subnet / VLSM planner (CCNA) — καθαρά υπολογισμοί στον browser ─────────────────────────
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(typeof window !== 'undefined' && window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;

  // ═════════════ IPv4 ═════════════
  const ip2n = s => { const p = String(s).trim().split('.'); if (p.length !== 4) return null;
    let n = 0; for (const x of p) { if (!/^\d{1,3}$/.test(x) || +x > 255) return null; n = n * 256 + +x; } return n; };
  const n2ip = n => [24, 16, 8, 0].map(s => Math.floor(n / 2 ** s) % 256).join('.');
  const maskN = p => p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0;
  const m2p = s => { const n = ip2n(s); if (n == null) return null; for (let p = 0; p <= 32; p++) if (maskN(p) === n) return p; return null; };
  const bin = n => n.toString(2).padStart(32, '0');
  // «10.1.1.5/26», «10.1.1.5 255.255.255.192», «10.1.1.5/255.255.255.192»
  function parse(str) {
    const m = String(str || '').trim().match(/^(\d+\.\d+\.\d+\.\d+)\s*(?:\/\s*|\s+)(\S+)$/);
    if (!m) return { error: T('Γράψε π.χ. 192.168.10.0/24 ή 192.168.10.0 255.255.255.0', 'Type e.g. 192.168.10.0/24 or 192.168.10.0 255.255.255.0') };
    const ip = ip2n(m[1]); if (ip == null) return { error: T('Λάθος διεύθυνση IP.', 'Invalid IP address.') };
    const p = /^\d{1,2}$/.test(m[2]) && +m[2] <= 32 ? +m[2] : m2p(m[2]);
    if (p == null) return { error: T('Λάθος μάσκα — πρέπει να είναι /0–/32 ή συνεχόμενοι άσσοι (π.χ. 255.255.255.192).', 'Invalid mask — use /0–/32 or contiguous ones (e.g. 255.255.255.192).') };
    return { ip, p };
  }
  function calc(ip, p) {
    const mk = maskN(p), size = 2 ** (32 - p), net = Math.floor(ip / size) * size, bc = net + size - 1;
    const usable = p === 32 ? 1 : p === 31 ? 2 : size - 2;
    const first = p >= 31 ? net : net + 1, last = p >= 31 ? bc : bc - 1;
    const oct = p >= 32 ? 3 : Math.floor(p / 8), mo = Math.floor(mk / 2 ** (24 - 8 * Math.min(oct, 3))) % 256;
    const a = Math.floor(ip / 2 ** 24), cls = a < 128 ? 'A' : a < 192 ? 'B' : a < 224 ? 'C' : a < 240 ? 'D (multicast)' : 'E';
    const priv = (a === 10) || (a === 172 && Math.floor(ip / 2 ** 16) % 256 >= 16 && Math.floor(ip / 2 ** 16) % 256 <= 31) || (a === 192 && Math.floor(ip / 2 ** 16) % 256 === 168);
    const kind = a === 127 ? 'loopback' : a === 169 && Math.floor(ip / 65536) % 256 === 254 ? 'APIPA / link-local' : a === 100 && Math.floor(ip / 65536) % 256 >= 64 && Math.floor(ip / 65536) % 256 <= 127 ? 'CGNAT (100.64/10)' : priv ? T('ιδιωτική (RFC 1918)', 'private (RFC 1918)') : a >= 224 ? 'multicast/reserved' : T('δημόσια', 'public');
    return { ip, p, mask: n2ip(mk), wild: n2ip((~mk) >>> 0), net, bc, first, last, size, usable, cls, kind,
      magic: p % 8 === 0 || p === 32 ? null : { octet: oct + 1, block: 256 - mo }, isNet: ip === net };
  }
  const prefixFor = (hosts, p31) => { if (p31 && hosts <= 2) return hosts <= 1 ? 32 : 31; let b = 2; while (2 ** b - 2 < hosts) b++; return 32 - b; };
  // VLSM: τα μεγαλύτερα πρώτα, το καθένα στο επόμενο ελεύθερο ευθυγραμμισμένο block
  function vlsm(baseStr, reqs, opt = {}) {
    const b = parse(baseStr); if (b.error) return b;
    const bsize = 2 ** (32 - b.p), bnet = Math.floor(b.ip / bsize) * bsize, end = bnet + bsize;
    const list = reqs.map((r, i) => ({ ...r, i, hosts: Math.max(1, Math.floor(+r.hosts || 0)) })).filter(r => +r.hosts > 0)
      .map(r => ({ ...r, p: prefixFor(r.hosts, opt.p31) })).sort((x, y) => x.p - y.p || x.i - y.i);
    let cur = bnet; const out = [], fail = [];
    for (const r of list) {
      const size = 2 ** (32 - r.p); let at = Math.ceil(cur / size) * size;
      if (r.p < b.p || at + size > end) { fail.push(r); continue; }
      out.push({ ...r, ...calc(at, r.p), waste: (r.p >= 31 ? size : size - 2) - r.hosts }); cur = at + size;
    }
    const free = []; let f = cur;
    while (f < end) { let p = 32; while (p > b.p && f % 2 ** (33 - p) === 0 && f + 2 ** (33 - p) <= end) p--; free.push({ net: f, p }); f += 2 ** (32 - p); }
    const used = out.reduce((s, x) => s + x.size, 0);
    return { base: { net: bnet, p: b.p, size: bsize, fixed: bnet !== b.ip }, rows: out, fail, free, used };
  }

  // ═════════════ IPv6 (BigInt) ═════════════
  function v6parse(s) {
    s = String(s || '').trim().toLowerCase().replace(/%.*$/, '');
    let p = null; const m = s.match(/^(.*)\/(\d{1,3})$/); if (m) { s = m[1]; p = +m[2]; if (p > 128) return null; }
    if ((s.match(/::/g) || []).length > 1 || !/^[0-9a-f:.]+$/.test(s)) return null;
    let tail = [];
    const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
    if (v4) { const n = ip2n(v4[1]); if (n == null) return null; tail = [Math.floor(n / 65536), n % 65536]; s = s.slice(0, -v4[1].length); if (s.endsWith(':') && !s.endsWith('::')) s = s.slice(0, -1); }
    const [L, R] = s.includes('::') ? s.split('::') : [s, null];
    const g = x => x ? x.split(':') : [];
    const lg = g(L), rg = R == null ? [] : g(R);
    if ([...lg, ...rg].some(x => !/^[0-9a-f]{1,4}$/.test(x))) return null;
    const miss = 8 - lg.length - rg.length - tail.length;
    if (R == null ? miss !== 0 : miss < 1) return null;
    const groups = [...lg.map(x => parseInt(x, 16)), ...Array(R == null ? 0 : miss).fill(0), ...rg.map(x => parseInt(x, 16)), ...tail];
    let n = 0n; for (const x of groups) n = (n << 16n) | BigInt(x);
    return { n, p };
  }
  const v6groups = n => Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(112 - 16 * i)) & 0xffffn));
  const v6full = n => v6groups(n).map(x => x.toString(16).padStart(4, '0')).join(':');
  function v6short(n) {  // RFC 5952
    const g = v6groups(n); let bs = -1, bl = 0;
    for (let i = 0; i < 8;) { if (g[i]) { i++; continue; } let j = i; while (j < 8 && !g[j]) j++; if (j - i > bl && j - i >= 2) { bs = i; bl = j - i; } i = j; }
    const h = g.map(x => x.toString(16));
    return bs < 0 ? h.join(':') : h.slice(0, bs).join(':') + '::' + h.slice(bs + bl).join(':');
  }
  const v6mask = p => p === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - p)) - 1n);
  function v6type(n) {
    const t = (pfx, p) => (n & v6mask(p)) === v6parse(pfx).n;
    if (n === 0n) return T('μη καθορισμένη (::)', 'unspecified (::)');
    if (n === 1n) return 'loopback (::1)';
    if (t('2001:db8::', 32)) return T('τεκμηρίωσης (2001:db8::/32 — για παραδείγματα)', 'documentation (2001:db8::/32 — for examples)');
    if (t('fe80::', 10)) return 'link-local (fe80::/10)';
    if (t('fc00::', 7)) return 'unique local — ULA (fc00::/7)';
    if (t('ff00::', 8)) return 'multicast (ff00::/8)';
    if (t('2000::', 3)) return 'global unicast (2000::/3)';
    if (t('::ffff:0:0', 96)) return 'IPv4-mapped (::ffff:0:0/96)';
    return T('άλλη/δεσμευμένη', 'other/reserved');
  }
  function v6subnets(n, p, np, count = 8) {
    if (np < p || np > 128) return [];
    const step = 1n << BigInt(128 - np), base = n & v6mask(p), total = 1n << BigInt(np - p), out = [];
    for (let i = 0n; i < total && i < BigInt(count); i++) out.push({ id: i, net: v6short(base + i * step) + '/' + np });
    return { list: out, total };
  }
  function eui64(mac) {
    const h = String(mac || '').toLowerCase().replace(/[^0-9a-f]/g, '');
    if (h.length !== 12) return null;
    const b = h.match(/../g).map(x => parseInt(x, 16)), f = b[0] ^ 0x02;
    const id = [f, b[1], b[2], 0xff, 0xfe, b[3], b[4], b[5]].map(x => x.toString(16).padStart(2, '0'));
    const iid = [0, 2, 4, 6].map(i => id[i] + id[i + 1]);
    return { split: h.slice(0, 6) + ' | ' + h.slice(6), withFffe: h.slice(0, 6) + 'fffe' + h.slice(6), first: b[0].toString(16).padStart(2, '0'), flipped: f.toString(16).padStart(2, '0'),
      bitBefore: b[0].toString(2).padStart(8, '0'), bitAfter: f.toString(2).padStart(8, '0'), iid: iid.join(':'),
      ll: v6short(v6parse('fe80::' + iid.join(':')).n) };
  }

  // ═════════════ IOS config ═════════════
  function iosConfig(r, o = {}) {
    const L = ['! ' + T('Δημιουργήθηκε από το NetWatch VLSM planner — έλεγξε τα ονόματα των interfaces πριν το βάλεις σε router', 'Generated by NetWatch VLSM planner — check the interface names before applying')];
    r.rows.forEach((x, k) => {
      const ifn = x.ifn || (x.p >= 30 ? 'Serial0/0/' + k : 'GigabitEthernet0/' + k);
      L.push('!', `interface ${ifn}`, ` description ${x.name || 'NET' + (k + 1)} (${x.hosts} hosts)`, ` ip address ${n2ip(x.first)} ${x.mask}`, ' no shutdown');
    });
    if (o.ospf) { L.push('!', 'router ospf 1'); r.rows.forEach(x => L.push(` network ${n2ip(x.net)} ${x.wild} area 0`)); }
    if (o.dhcp) r.rows.filter(x => x.p < 30).forEach(x => {
      const nm = String(x.name || 'NET').replace(/\s+/g, '-');
      L.push('!', `ip dhcp excluded-address ${n2ip(x.first)}`, `ip dhcp pool ${nm}`, ` network ${n2ip(x.net)} ${x.mask}`, ` default-router ${n2ip(x.first)}`, ' dns-server 1.1.1.1');
    });
    L.push('!', 'end');
    return L.join('\n');
  }

  const API = { ip2n, n2ip, parse, calc, vlsm, prefixFor, v6parse, v6full, v6short, v6type, v6subnets, eui64, iosConfig };
  if (typeof window === 'undefined') { if (typeof module !== 'undefined') module.exports = API; return; }
  window.VLSM = API;

  // ═════════════ UI ═════════════
  const PRESETS = {
    ccna: { base: '192.168.10.0/24', reqs: [['LAN-A', 50], ['LAN-B', 20], ['LAN-C', 10], ['WAN-1', 2], ['WAN-2', 2]] },
    home: { base: '192.168.0.0/23', reqs: [['LAN', 100], ['IoT', 50], ['Guest', 30], ['Cameras', 10], ['Management', 5]] },
    office: { base: '10.10.0.0/22', reqs: [['Staff', 300], ['Voice', 120], ['Servers', 25], ['Printers', 12], ['WAN-ISP', 2]] },
  };
  let st = { mode: 'vlsm', base: PRESETS.ccna.base, reqs: PRESETS.ccna.reqs.map(([name, hosts]) => ({ name, hosts })), p31: false, ospf: true, dhcp: true, calc: '192.168.10.77/27', v6: '2001:db8:acad::/48', v6new: 64, mac: '00:1a:2b:3c:4d:5e' };
  try { const s = JSON.parse(localStorage.getItem('nw-vlsm') || 'null'); if (s && s.reqs) st = { ...st, ...s }; } catch (e) {}
  const save = () => { try { localStorage.setItem('nw-vlsm', JSON.stringify(st)); } catch (e) {} };
  const box = () => document.getElementById('t-vlsm');
  const COLS = ['#3ec5ff', '#3ddc97', '#ffd23f', '#ff9f43', '#b388ff', '#ff6b9a', '#4dd0e1', '#a3e635', '#f472b6', '#60a5fa'];

  const css = document.createElement('style');
  css.textContent = `
#t-vlsm .vl-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
#t-vlsm .vl-tabs button.on{border-color:var(--cyan);color:var(--cyan);background:color-mix(in srgb,var(--cyan) 10%,transparent)}
#t-vlsm .vl-grid{display:grid;grid-template-columns:minmax(260px,340px) minmax(0,1fr);gap:12px;align-items:start}
@media(max-width:900px){#t-vlsm .vl-grid{grid-template-columns:minmax(0,1fr)}}
#t-vlsm .vl-grid>div{min-width:0}
#t-vlsm input[type=text],#t-vlsm input[type=number]{background:var(--bg);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:7px 9px;font:13px ui-monospace,Menlo,monospace;min-width:0;width:100%;box-sizing:border-box}
#t-vlsm .vl-req{display:grid;grid-template-columns:14px minmax(0,1fr) 84px 28px;gap:6px;align-items:center;margin-top:6px}
#t-vlsm .vl-dot{width:12px;height:12px;border-radius:3px}
#t-vlsm .vl-lbl{font-size:12px;color:var(--dim);font-weight:600;margin:10px 0 4px}
#t-vlsm .vl-chk{display:flex;gap:6px;align-items:center;font-size:12.5px;margin-top:6px;cursor:pointer}
#t-vlsm table.vl-t{width:100%;border-collapse:collapse;font-size:12.5px}
#t-vlsm table.vl-t th{text-align:left;color:var(--dim);font-weight:600;font-size:11px;padding:6px;border-bottom:1px solid var(--line);white-space:nowrap}
#t-vlsm table.vl-t td{padding:6px;border-bottom:1px solid rgb(var(--w,255 255 255) / 6%);font-family:ui-monospace,Menlo,monospace;white-space:nowrap}
#t-vlsm table.vl-t td.nm{font-family:inherit;font-weight:600}
#t-vlsm table.vl-t tr{cursor:pointer}#t-vlsm table.vl-t tr.sel td{background:color-mix(in srgb,var(--cyan) 9%,transparent)}
#t-vlsm .vl-wrap{overflow:auto}
#t-vlsm .vl-why{font-size:13px;line-height:1.6;background:rgb(var(--w,255 255 255) / 4%);border-radius:10px;padding:10px 12px;margin-top:10px}
#t-vlsm .vl-why code,#t-vlsm .vl-note code{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px}
#t-vlsm pre.vl-cfg{background:#05080f;color:#d6e2f0;border-radius:10px;padding:10px 12px;font:12px/1.5 ui-monospace,Menlo,monospace;max-height:340px;overflow:auto;margin:8px 0 0;white-space:pre}
#t-vlsm .vl-kv{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px}
#t-vlsm .vl-kv div{background:rgb(var(--w,255 255 255) / 4%);border-radius:10px;padding:8px 10px}
#t-vlsm .vl-kv b{display:block;font-size:11px;color:var(--dim);font-weight:600}#t-vlsm .vl-kv span{font:600 14px ui-monospace,Menlo,monospace;word-break:break-all}
#t-vlsm .vl-bin{font:13px/1.9 ui-monospace,Menlo,monospace;overflow:auto;white-space:nowrap}
#t-vlsm .vl-bin .n{color:var(--cyan)}#t-vlsm .vl-bin .h{color:var(--orange)}
#t-vlsm .vl-err{color:var(--red);font-size:13px;margin-top:6px}
#t-vlsm .vl-note{font-size:12.5px;color:var(--dim);margin-top:6px;line-height:1.55}
`;
  document.head.appendChild(css);

  let sel = 0, timer = null;
  const tabs = () => `<div class="vl-tabs">${[['vlsm', '🧮 VLSM'], ['calc', T('🔢 Υπολογιστής subnet', '🔢 Subnet calculator')], ['v6', '6️⃣ IPv6']].map(([k, n]) => `<button class="b${st.mode === k ? ' on' : ''}" data-vm="${k}">${n}</button>`).join('')}</div>`;

  // ── VLSM ──
  function vlsmForm() {
    return `<div class="card"><div class="vl-lbl" style="margin-top:0">${T('Διεύθυνση που σου δόθηκε', 'Address block you were given')}</div>
      <input type="text" data-k="base" value="${E(st.base)}" spellcheck="false">
      <div class="vl-lbl">${T('Δίκτυα που χρειάζεσαι (όνομα · hosts)', 'Networks you need (name · hosts)')}</div>
      <div id="vl-reqs">${st.reqs.map((r, i) => `<div class="vl-req"><span class="vl-dot" style="background:${COLS[i % COLS.length]}"></span><input type="text" data-r="${i}" data-f="name" value="${E(r.name)}" maxlength="24"><input type="number" min="1" max="16777214" data-r="${i}" data-f="hosts" value="${E(r.hosts)}"><button class="b" data-del="${i}" title="${T('Αφαίρεση', 'Remove')}">✕</button></div>`).join('')}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px"><button class="b" data-add>＋ ${T('δίκτυο', 'network')}</button><button class="b" data-sort>↕ ${T('ταξινόμηση', 'sort')}</button></div>
      <label class="vl-chk"><input type="checkbox" data-c="p31"${st.p31 ? ' checked' : ''}> ${T('Point-to-point με /31 (RFC 3021) αντί /30', 'Point-to-point links as /31 (RFC 3021) instead of /30')}</label>
      <div class="vl-lbl">${T('Έτοιμα παραδείγματα', 'Examples')}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap"><button class="b" data-pre="ccna">🎓 ${T('Άσκηση CCNA', 'CCNA exercise')}</button><button class="b" data-pre="home">🏠 ${T('Σπίτι με VLAN', 'Home with VLANs')}</button><button class="b" data-pre="office">🏢 ${T('Γραφείο', 'Office')}</button></div>
      <div class="vl-note">💡 ${T('Κάθε subnet χάνει 2 διευθύνσεις: τη <b>network</b> και τη <b>broadcast</b>. Γι’ αυτό 50 hosts θέλουν 52 → επόμενη δύναμη του 2 = 64 → <code>/26</code>.', 'Every subnet loses 2 addresses: the <b>network</b> and the <b>broadcast</b>. So 50 hosts need 52 → next power of 2 = 64 → <code>/26</code>.')}</div></div>`;
  }
  function bar(r) {
    const pc = n => (n / r.base.size * 100).toFixed(3) + '%';
    const segs = r.rows.map((row, k) => `<div data-row="${k}" title="${E(row.name)} ${n2ip(row.net)}/${row.p}" style="position:absolute;top:0;bottom:0;left:${pc(row.net - r.base.net)};width:max(2px,calc(${pc(row.size)} - 2px));background:${COLS[row.i % COLS.length]};opacity:${k === sel ? 1 : .8};border-radius:5px;cursor:pointer;overflow:hidden;white-space:nowrap;font:600 11px -apple-system,system-ui,sans-serif;color:#06101c;padding:0 6px;line-height:36px${k === sel ? ';box-shadow:0 0 0 2px #fff inset' : ''}">${E(row.name)} /${row.p}</div>`).join('');
    const free = r.free.map(f => `<div style="position:absolute;top:0;bottom:0;left:${pc(f.net - r.base.net)};width:calc(${pc(2 ** (32 - f.p))} - 2px);border-radius:5px;border:1px dashed rgb(255 255 255 / 22%);background:repeating-linear-gradient(45deg,rgb(255 255 255 / 4%) 0 6px,transparent 6px 12px)"></div>`).join('');
    return `<div style="position:relative;height:36px">${free}${segs}</div>
      <div style="display:flex;justify-content:space-between;font:11px ui-monospace,Menlo,monospace;color:var(--dim);margin-top:3px"><span>${n2ip(r.base.net)}</span><span>${n2ip(r.base.net + r.base.size - 1)}</span></div>`;
  }
  function why(x) {
    const need = x.hosts + 2, b = 32 - x.p;
    if (x.p >= 31) return T(`<b>${E(x.name)}</b>: point-to-point με ${x.hosts} συσκευές → <code>/${x.p}</code>. Το /31 δεν έχει network/broadcast (RFC 3021) — ${x.p === 31 ? 'και οι 2 διευθύνσεις χρησιμοποιούνται.' : ''}`,
      `<b>${E(x.name)}</b>: point-to-point with ${x.hosts} devices → <code>/${x.p}</code>. A /31 has no network/broadcast (RFC 3021) — ${x.p === 31 ? 'both addresses are usable.' : ''}`);
    return T(`<b>${E(x.name)}</b>: ${x.hosts} hosts + 2 (network, broadcast) = <b>${need}</b> → η επόμενη δύναμη του 2 είναι <b>2<sup>${b}</sup> = ${x.size}</b> → ${b} bits για hosts → <code>/${32 - b}</code> (μάσκα <code>${x.mask}</code>).<br>
      Network <code>${n2ip(x.net)}</code> · hosts <code>${n2ip(x.first)}</code>–<code>${n2ip(x.last)}</code> · broadcast <code>${n2ip(x.bc)}</code>. ${x.waste ? `Μένουν ${x.waste} ελεύθερες για μεγάλωμα.` : 'Ακριβώς όσες χρειάζεσαι — δεν περισσεύει καμία!'}<br>
      Wildcard για OSPF/ACL: <code>${x.wild}</code> (= 255.255.255.255 − μάσκα).`,
      `<b>${E(x.name)}</b>: ${x.hosts} hosts + 2 (network, broadcast) = <b>${need}</b> → next power of 2 is <b>2<sup>${b}</sup> = ${x.size}</b> → ${b} host bits → <code>/${32 - b}</code> (mask <code>${x.mask}</code>).<br>
      Network <code>${n2ip(x.net)}</code> · hosts <code>${n2ip(x.first)}</code>–<code>${n2ip(x.last)}</code> · broadcast <code>${n2ip(x.bc)}</code>. ${x.waste ? `${x.waste} spare addresses for growth.` : 'Exactly what you need — zero spare!'}<br>
      Wildcard for OSPF/ACLs: <code>${x.wild}</code> (= 255.255.255.255 − mask).`);
  }
  function vlsmOut() {
    const r = vlsm(st.base, st.reqs, { p31: st.p31 });
    if (r.error) return `<div class="card"><div class="vl-err">⚠ ${E(r.error)}</div></div>`;
    if (sel >= r.rows.length) sel = 0;
    const pct = Math.round(r.used / r.base.size * 100), x = r.rows[sel];
    return `<div class="card">${r.base.fixed ? `<div class="vl-note" style="margin:0 0 6px">ℹ️ ${T('Η διεύθυνση είχε host bits — χρησιμοποιώ το δίκτυο', 'The address had host bits set — using the network')} <code>${n2ip(r.base.net)}/${r.base.p}</code>.</div>` : ''}
      <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:baseline"><b>${n2ip(r.base.net)}/${r.base.p}</b><span class="vl-note" style="margin:0">${T(`Χρησιμοποιούνται <b>${r.used}</b> από ${r.base.size} διευθύνσεις (${pct}%)`, `Using <b>${r.used}</b> of ${r.base.size} addresses (${pct}%)`)}</span></div>
      <div style="margin-top:8px">${bar(r)}</div>
      ${r.fail.length ? `<div class="vl-err">⚠ ${T('Δεν χωράνε:', 'Does not fit:')} ${r.fail.map(f => `<b>${E(f.name)}</b> (${f.hosts} hosts → /${f.p})`).join(', ')}. ${T('Χρειάζεσαι μεγαλύτερο block (μικρότερο prefix) ή λιγότερους hosts.', 'You need a bigger block (shorter prefix) or fewer hosts.')}</div>` : ''}
      <div class="vl-wrap" style="margin-top:10px"><table class="vl-t"><tr><th></th><th>${T('Όνομα', 'Name')}</th><th>${T('Ζητάς', 'Need')}</th><th>${T('Χωράει', 'Fits')}</th><th>${T('Δίκτυο', 'Network')}</th><th>${T('Μάσκα', 'Mask')}</th><th>${T('Πρώτη', 'First')}</th><th>${T('Τελευταία', 'Last')}</th><th>Broadcast</th><th>Wildcard</th></tr>
      ${r.rows.map((y, k) => `<tr data-row="${k}" class="${k === sel ? 'sel' : ''}"><td><span class="vl-dot" style="display:inline-block;background:${COLS[y.i % COLS.length]}"></span></td><td class="nm">${E(y.name)}</td><td>${y.hosts}</td><td>${y.usable}</td><td>${n2ip(y.net)}/${y.p}</td><td>${y.mask}</td><td>${n2ip(y.first)}</td><td>${n2ip(y.last)}</td><td>${n2ip(y.bc)}</td><td>${y.wild}</td></tr>`).join('')}</table></div>
      ${r.free.length ? `<div class="vl-note">🟫 ${T('Ελεύθερα για το μέλλον:', 'Free for later:')} ${r.free.map(f => `<code>${n2ip(f.net)}/${f.p}</code>`).join(' ')}</div>` : ''}
      ${x ? `<div class="vl-why">🧠 ${why(x)}</div>` : ''}</div>
      <div class="card"><div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap"><b>🖧 ${T('Έτοιμο config για Cisco IOS', 'Ready Cisco IOS config')}</b>
        <span style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><label class="vl-chk" style="margin:0"><input type="checkbox" data-c="ospf"${st.ospf ? ' checked' : ''}> OSPF</label><label class="vl-chk" style="margin:0"><input type="checkbox" data-c="dhcp"${st.dhcp ? ' checked' : ''}> DHCP</label><button class="b" data-copycfg>📋 ${T('Αντιγραφή', 'Copy')}</button><button class="b" data-golab>🖧 Cisco Lab</button></span></div>
        <pre class="vl-cfg" id="vl-cfg">${E(iosConfig(r, st))}</pre>
        <div class="vl-note">${T('Gateway = η πρώτη διεύθυνση κάθε δικτύου. Τα interfaces είναι παράδειγμα — άλλαξέ τα ανάλογα με τον router σου.', 'Gateway = first address of each network. Interface names are examples — adjust them to your router.')}</div></div>`;
  }

  // ── υπολογιστής ──
  function calcOut() {
    const p = parse(st.calc); if (p.error) return `<div class="vl-err">⚠ ${E(p.error)}</div>`;
    const c = calc(p.ip, p.p), b = bin(p.ip), m = c.magic;
    const bits = b.split('').map((x, i) => `<span class="${i < p.p ? 'n' : 'h'}">${x}</span>${i % 8 === 7 && i < 31 ? '.' : ''}`).join('');
    const mb = bin(ip2n(c.mask)).replace(/(.{8})(?!$)/g, '$1.');
    return `<div class="vl-kv" style="margin-top:10px">${[[T('Δίκτυο', 'Network'), n2ip(c.net) + '/' + p.p], [T('Μάσκα', 'Mask'), c.mask], ['Wildcard', c.wild], [T('Πρώτη χρήσιμη', 'First usable'), n2ip(c.first)], [T('Τελευταία χρήσιμη', 'Last usable'), n2ip(c.last)], ['Broadcast', p.p >= 31 ? '—' : n2ip(c.bc)],
        [T('Χρήσιμοι hosts', 'Usable hosts'), c.usable.toLocaleString()], [T('Σύνολο διευθύνσεων', 'Total addresses'), c.size.toLocaleString()], [T('Κλάση / είδος', 'Class / kind'), c.cls + ' · ' + c.kind]]
      .map(([k, v]) => `<div><b>${k}</b><span>${E(v)}</span></div>`).join('')}</div>
      <div class="vl-lbl">${T('Σε δυαδικό', 'In binary')} — <span style="color:var(--cyan)">${T('network bits', 'network bits')} (${p.p})</span> · <span style="color:var(--orange)">${T('host bits', 'host bits')} (${32 - p.p})</span></div>
      <div class="vl-bin">IP&nbsp;&nbsp;&nbsp;${bits}<br><span style="color:var(--dim)">MASK ${mb}</span></div>
      ${m ? `<div class="vl-why">⚡ ${T(`<b>Γρήγορος τρόπος (magic number):</b> η μάσκα «σπάει» στο ${m.octet}ο octet → 256 − ${256 - m.block} = <b>${m.block}</b>. Τα δίκτυα πάνε ανά ${m.block} σε αυτό το octet (0, ${m.block}, ${m.block * 2}, ${m.block * 3}…). Η ${n2ip(p.ip)} πέφτει στο δίκτυο που ξεκινά από <b>${n2ip(c.net)}</b>, και το επόμενο ξεκινά από ${n2ip(c.bc + 1)} → broadcast = ${n2ip(c.bc)}.`,
        `<b>Quick way (magic number):</b> the mask “breaks” in octet ${m.octet} → 256 − ${256 - m.block} = <b>${m.block}</b>. Networks step by ${m.block} in that octet (0, ${m.block}, ${m.block * 2}, ${m.block * 3}…). ${n2ip(p.ip)} falls in the network starting at <b>${n2ip(c.net)}</b>; the next starts at ${n2ip(c.bc + 1)} → broadcast = ${n2ip(c.bc)}.`)}</div>` : ''}
      ${c.isNet && p.p < 31 ? `<div class="vl-note">ℹ️ ${T('Αυτή είναι η διεύθυνση δικτύου — δεν μπαίνει σε συσκευή.', 'This is the network address — it cannot be assigned to a device.')}</div>` : p.ip === c.bc && p.p < 31 ? `<div class="vl-note">ℹ️ ${T('Αυτή είναι η broadcast — δεν μπαίνει σε συσκευή.', 'This is the broadcast address — it cannot be assigned to a device.')}</div>` : ''}`;
  }

  // ── IPv6 ──
  function v6Out() {
    const a = v6parse(st.v6); let h = '';
    if (!a) h += `<div class="vl-err">⚠ ${T('Λάθος IPv6 — π.χ. 2001:db8:acad::/48', 'Invalid IPv6 — e.g. 2001:db8:acad::/48')}</div>`;
    else {
      const p = a.p == null ? 64 : a.p, net = a.n & (((1n << 128n) - 1n) ^ ((1n << BigInt(128 - p)) - 1n));
      h += `<div class="vl-kv" style="margin-top:10px">${[[T('Συμπτυγμένη', 'Compressed'), v6short(a.n)], [T('Πλήρης', 'Expanded'), v6full(a.n)], [T('Είδος', 'Type'), v6type(a.n)], [T('Πρόθεμα δικτύου', 'Network prefix'), v6short(net) + '/' + p]].map(([k, v]) => `<div><b>${k}</b><span>${E(v)}</span></div>`).join('')}</div>`;
      const np = Math.max(p, Math.min(128, +st.v6new || 64)), sn = v6subnets(a.n, p, np, 8);
      h += `<div class="vl-lbl">${T('Χώρισέ το σε', 'Split it into')} /<input type="number" data-k="v6new" value="${np}" min="${p}" max="128" style="width:70px;display:inline-block"> — ${T('σύνολο', 'total')} <b>${sn.total.toLocaleString()}</b> subnets</div>
        <table class="vl-t"><tr><th>Subnet ID</th><th>${T('Δίκτυο', 'Network')}</th></tr>${sn.list.map(s => `<tr><td>${s.id.toString(16)}</td><td>${E(s.net)}</td></tr>`).join('')}${sn.total > 8n ? '<tr><td>…</td><td>…</td></tr>' : ''}</table>
        ${p <= 64 && np === 64 ? `<div class="vl-note">💡 ${T(`Με /${p} και subnets /64 έχεις ${64 - p} bits για subnet ID. Τα LAN στο IPv6 είναι <b>πάντα /64</b> (το SLAAC το χρειάζεται).`, `With /${p} and /64 subnets you have ${64 - p} bits for the subnet ID. IPv6 LANs are <b>always /64</b> (SLAAC needs it).`)}</div>` : ''}`;
    }
    const e = eui64(st.mac);
    h += `<div class="vl-lbl" style="margin-top:16px">EUI-64 — ${T('από MAC σε interface ID', 'from MAC to interface ID')}</div><input type="text" data-k="mac" value="${E(st.mac)}" spellcheck="false" style="max-width:260px">`;
    h += e ? `<div class="vl-why">1️⃣ ${T('Χώρισε τη MAC στη μέση', 'Split the MAC in half')}: <code>${e.split}</code><br>2️⃣ ${T('Βάλε', 'Insert')} <code>FFFE</code> ${T('στη μέση', 'in the middle')}: <code>${e.withFffe}</code><br>
      3️⃣ ${T('Αναποδογύρισε το 7ο bit (U/L) του 1ου byte', 'Flip the 7th bit (U/L) of the first byte')}: <code>${e.first}</code> = <code>${e.bitBefore}</code> → <code>${e.bitAfter}</code> = <code>${e.flipped}</code><br>
      ✅ Interface ID: <code>${e.iid}</code> · link-local: <code>${e.ll}</code>${a ? ` · global: <code>${v6short((a.n & (((1n << 128n) - 1n) ^ ((1n << 64n) - 1n))) | v6parse('::' + e.iid).n)}</code>` : ''}</div>`
      : `<div class="vl-err">⚠ ${T('Γράψε MAC με 12 hex ψηφία', 'Enter a MAC with 12 hex digits')}</div>`;
    return h;
  }

  function results() {
    const o = box() && box().querySelector('#vl-out'); if (!o) return;
    o.innerHTML = st.mode === 'vlsm' ? vlsmOut() : st.mode === 'calc' ? calcOut() : v6Out();
  }
  function draw() {
    const b = box(); if (!b) return;
    b.setAttribute('data-noi18n', '');
    const head = `<div class="vl-note" style="margin:0 0 8px">🔒 ${T('Σχεδίασε διευθύνσεις για το δίκτυό σου ή λύσε ασκήσεις CCNA — με εξήγηση για κάθε βήμα. Όλα υπολογίζονται εδώ, τίποτα δεν στέλνεται στο δίκτυο.', 'Plan addressing for your network or solve CCNA exercises — with an explanation for every step. Everything is computed here; nothing is sent on the network.')}</div>`;
    if (st.mode === 'vlsm') b.innerHTML = head + tabs() + `<div class="vl-grid"><div>${vlsmForm()}</div><div id="vl-out"></div></div>`;
    else if (st.mode === 'calc') b.innerHTML = head + tabs() + `<div class="card"><div class="vl-lbl" style="margin-top:0">${T('IP και μάσκα', 'IP and mask')}</div><input type="text" data-k="calc" value="${E(st.calc)}" spellcheck="false" style="max-width:340px">
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px">${['192.168.10.77/27', '172.16.45.200 255.255.240.0', '10.1.1.1/30', '10.0.0.0/8'].map(x => `<button class="b" data-ex="${x}">${x}</button>`).join('')}</div><div id="vl-out"></div></div>`;
    else b.innerHTML = head + tabs() + `<div class="card"><div class="vl-lbl" style="margin-top:0">${T('IPv6 διεύθυνση ή πρόθεμα', 'IPv6 address or prefix')}</div><input type="text" data-k="v6" value="${E(st.v6)}" spellcheck="false" style="max-width:420px">
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px">${['2001:db8:acad::/48', 'fe80::1', '2001:0db8:0000:0000:0000:ff00:0042:8329', 'fd12:3456:789a::/48'].map(x => `<button class="b" data-ex6="${x}">${x}</button>`).join('')}</div><div id="vl-out"></div></div>`;
    results();
  }

  function bind() {
    const b = box(); if (!b || b._vl) return; b._vl = 1;
    b.addEventListener('input', e => {
      const t = e.target;
      if (t.dataset.k) st[t.dataset.k] = t.value;
      else if (t.dataset.r != null) st.reqs[+t.dataset.r][t.dataset.f] = t.dataset.f === 'hosts' ? t.value : t.value;
      else return;
      save(); clearTimeout(timer);
      // το πεδίο v6new είναι μέσα στα αποτελέσματα → μην το ξαναζωγραφίσεις όσο γράφεις
      timer = setTimeout(() => { if (t.dataset.k === 'v6new') { const pos = t.selectionStart; results(); const n = box().querySelector('[data-k=v6new]'); if (n) { n.focus(); try { n.setSelectionRange(pos, pos); } catch (er) {} } } else results(); }, 120);
    });
    b.addEventListener('change', e => { const t = e.target; if (t.dataset.c) { st[t.dataset.c] = t.checked; save(); results(); } });
    b.addEventListener('click', e => {
      const t = e.target.closest('button,[data-row]'); if (!t) return;
      if (t.dataset.vm) { st.mode = t.dataset.vm; save(); draw(); }
      else if (t.dataset.add != null) { st.reqs.push({ name: 'NET-' + (st.reqs.length + 1), hosts: 10 }); save(); draw(); const i = box().querySelectorAll('[data-f=name]'); i[i.length - 1].select(); }
      else if (t.dataset.del != null) { st.reqs.splice(+t.dataset.del, 1); save(); draw(); }
      else if (t.dataset.sort != null) { st.reqs.sort((a, c) => (+c.hosts || 0) - (+a.hosts || 0)); save(); draw(); }
      else if (t.dataset.pre) { const p = PRESETS[t.dataset.pre]; st.base = p.base; st.reqs = p.reqs.map(([name, hosts]) => ({ name, hosts })); sel = 0; save(); draw(); }
      else if (t.dataset.row != null) { sel = +t.dataset.row; results(); }
      else if (t.dataset.ex) { st.calc = t.dataset.ex; save(); draw(); }
      else if (t.dataset.ex6) { st.v6 = t.dataset.ex6; save(); draw(); }
      else if (t.dataset.copycfg != null) { const txt = box().querySelector('#vl-cfg').textContent; if (typeof copyText === 'function') copyText(txt); else navigator.clipboard && navigator.clipboard.writeText(txt); }
      else if (t.dataset.golab != null) { if (typeof window.showTab === 'function') window.showTab('cli'); }
    });
  }
  window.renderVlsm = () => { bind(); draw(); };
})();
