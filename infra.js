// NetWatch — «Υποδομή»: οθόνες σαν τα επαγγελματικά NMS (ntopng, LibreNMS/PRTG, Graylog, NetBox/phpIPAM, SmokePing, Uptime Kuma).
// Ροές NetFlow/sFlow · Θύρες & SNMP (+ τοπολογία LLDP) · Syslog · IPAM/απογραφή · Καθυστέρηση · Ταχύτητα & Wi‑Fi · Λειτουργία.
// Φορτώνεται πριν από τον κώδικα του index.html· χρησιμοποιεί τα κοινά του ($, esc, ico, fmtB, fmtT, post, tab, tabHover, S…) μόνο όταν καλείται.
(function () {
  'use strict';
  const IF = window.INFRA = { data: {}, at: {}, sel: {} };
  const now = () => Date.now() / 1000;
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const ago = s => s == null ? '—' : s < 90 ? Math.round(s) + '″' : s < 5400 ? Math.round(s / 60) + '′' : s < 172800 ? Math.round(s / 3600) + (EN() ? 'h' : 'ω') : Math.round(s / 86400) + (EN() ? 'd' : 'μ');
  const agoT = s => EN() ? ago(s) + ' ago' : 'πριν ' + ago(s);
  const bps = v => v == null ? '—' : v < 1e3 ? Math.round(v) + ' b/s' : v < 1e6 ? (v / 1e3).toFixed(1) + ' Kb/s' : v < 1e9 ? (v / 1e6).toFixed(1) + ' Mb/s' : (v / 1e9).toFixed(2) + ' Gb/s';
  const spd = v => !v ? '—' : v >= 1e9 ? (v / 1e9) + 'G' : v >= 1e6 ? (v / 1e6) + 'M' : v;
  const hn = ip => { const h = window.S && S.hosts.get(ip); const n = h && (aliasOf ? aliasOf(h) : '') || (h && hname(h)); return n ? `${esc(n)} <span class="sm">${esc(ip)}</span>` : esc(ip); };
  const pct = (v, col) => `<span class="ibar"><i style="width:${Math.max(0, Math.min(100, v || 0))}%;background:${col || (v > 90 ? 'var(--red)' : v > 70 ? 'var(--orange)' : 'var(--cyan)')}"></i></span>`;
  const head = (icon, title, txt, extra) => `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">${icon} ${title}</b>${extra || ''}</div><div class="sm" style="margin-top:4px">${txt}</div></div>`;
  const demoTag = d => d && d.demo ? ' <span class="tag">προσομοίωση</span>' : '';
  const snippet = (title, code) => `<details><summary>${title}</summary><pre class="snip">${esc(code)}</pre><button class="b" data-icopy="${esc(code)}">📋 Αντιγραφή</button></details>`;

  // φόρτωση με «πάτωμα» ανανέωσης· ξαναζωγραφίζει μόνο αν είναι ανοιχτή η καρτέλα και ο χρήστης δεν έχει το ποντίκι πάνω της
  function load(key, url, every, draw) {
    if (now() - (IF.at[key] || 0) > every) {
      IF.at[key] = now();
      fetch(url).then(r => r.json()).then(j => { IF.data[key] = j; if (tab === key && !tabHover()) draw(); }).catch(() => { });
    }
    if (IF.data[key]) { if (!tabHover()) draw(); } else $('t-' + key).innerHTML = '<div class="empty">φόρτωση…</div>';
  }
  function bind(el) {
    el.querySelectorAll('[data-icopy]').forEach(b => b.onclick = () => copyText(b.dataset.icopy));
    el.querySelectorAll('[data-ip]').forEach(r => r.onclick = e => { if (e.target.closest('button,a,input')) return; select(r.dataset.ip); });
  }

  // ---------- μικρά SVG γραφήματα ----------
  // γραμμές: series=[{v:[…], col, fill}] πάνω σε κοινό t[]
  function lineChart(t, series, o = {}) {
    const W = o.w || 900, H = o.h || 130, P = 4, n = t.length; if (n < 2) return '<div class="sm">λίγα δεδομένα ακόμα</div>';
    const all = series.flatMap(s => s.v).filter(x => x != null), mx = (o.max || Math.max(1e-9, ...all)) * 1.08;
    const X = i => P + (W - 2 * P) * i / (n - 1), Y = v => H - P - (H - 2 * P) * v / mx;
    let g = '';
    for (const s of series) {
      let d = '', pen = false; s.v.forEach((v, i) => { if (v == null) { pen = false; return; } d += (pen ? 'L' : 'M') + X(i).toFixed(1) + ',' + Y(v).toFixed(1); pen = true; });
      if (s.fill) g += `<path d="${d}L${X(n - 1)},${H - P}L${X(0)},${H - P}Z" fill="${s.col}" fill-opacity=".12" stroke="none"/>`;
      g += `<path d="${d}" fill="none" stroke="${s.col}" stroke-width="1.6" stroke-linejoin="round"/>`;
    }
    const lab = o.fmt ? `<text x="${W - 6}" y="12" text-anchor="end" class="fl">${esc(o.fmt(mx / 1.08))}</text>` : '';
    const t0 = new Date(t[0] * 1000), t1 = new Date(t[n - 1] * 1000), f = d => d.toLocaleTimeString(I18N && I18N.lang === 'en' ? 'en-GB' : 'el-GR', { hour: '2-digit', minute: '2-digit' });
    return `<svg class="ich" viewBox="0 0 ${W} ${H + 14}"><g class="grid">${[.25, .5, .75].map(k => `<line x1="0" x2="${W}" y1="${(H * k).toFixed(0)}" y2="${(H * k).toFixed(0)}"/>`).join('')}</g>${g}${lab}
      <text x="2" y="${H + 12}" class="fl">${f(t0)}</text><text x="${W - 2}" y="${H + 12}" text-anchor="end" class="fl">${f(t1)}</text></svg>`;
  }
  // SmokePing: λωρίδα min–max (ο «καπνός») + διάμεσος, χρωματισμένος από τις απώλειες
  function smokeChart(h, o = {}) {
    const t = h.t || [], n = t.length; if (n < 2) return '<div class="sm">λίγα δεδομένα ακόμα</div>';
    const W = o.w || 900, H = o.h || 140, P = 4;
    const vals = (h.max || []).concat(h.median || []).filter(x => x != null).sort((a, b) => a - b);
    const mx = Math.max(1, vals[Math.floor(vals.length * .98)] || 1) * 1.15;
    const X = i => P + (W - 2 * P) * i / (n - 1), Y = v => H - P - (H - 2 * P) * Math.min(v, mx) / mx;
    let band = '', g = '';
    for (let i = 0; i < n; i++) { const a = h.min[i], b = h.max[i]; if (a == null || b == null) continue; band += `<rect x="${(X(i) - (W / n) / 2).toFixed(1)}" y="${Y(b).toFixed(1)}" width="${Math.max(1, W / n).toFixed(1)}" height="${Math.max(1, Y(a) - Y(b)).toFixed(1)}"/>`; }
    for (let i = 1; i < n; i++) {
      const a = h.median[i - 1], b = h.median[i]; if (a == null || b == null) continue; const l = h.loss[i] || 0;
      const c = l >= 20 ? 'var(--red)' : l >= 5 ? 'var(--orange)' : l > 0 ? 'var(--yellow)' : 'var(--green)';
      g += `<line x1="${X(i - 1).toFixed(1)}" y1="${Y(a).toFixed(1)}" x2="${X(i).toFixed(1)}" y2="${Y(b).toFixed(1)}" stroke="${c}" stroke-width="1.8"/>`;
    }
    const lost = (h.loss || []).map((l, i) => l >= 100 ? `<rect x="${(X(i) - 1).toFixed(1)}" y="0" width="3" height="${H}" fill="var(--red)" fill-opacity=".25"/>` : '').join('');
    const f = s => new Date(s * 1000).toLocaleString(I18N && I18N.lang === 'en' ? 'en-GB' : 'el-GR', { weekday: o.days ? 'short' : undefined, hour: '2-digit', minute: '2-digit' });
    return `<svg class="ich" viewBox="0 0 ${W} ${H + 14}"><g class="grid">${[.25, .5, .75].map(k => `<line x1="0" x2="${W}" y1="${(H * k).toFixed(0)}" y2="${(H * k).toFixed(0)}"/>`).join('')}</g>
      ${lost}<g class="smoke">${band}</g>${g}<text x="${W - 6}" y="12" text-anchor="end" class="fl">${(mx / 1.15).toFixed(mx < 10 ? 1 : 0)} ms</text>
      <text x="2" y="${H + 12}" class="fl">${f(t[0])}</text><text x="${W - 2}" y="${H + 12}" text-anchor="end" class="fl">${f(t[n - 1])}</text></svg>`;
  }

  // =============== 🌊 Ροές (NetFlow / sFlow / IPFIX) ===============
  window.renderFlows = () => load('flows', '/api/flows', 5, drawFlows);
  function drawFlows() {
    const d = IF.data.flows, el = $('t-flows');
    if (d.off) { el.innerHTML = '<div class="empty">Δεν είναι διαθέσιμο σε αυτή τη λειτουργία (pcap).</div>'; return; }
    const T = d.totals || {}, C = d.counts || {};
    let h = head('🌊', 'Ροές από τον router (NetFlow / sFlow / IPFIX)' + demoTag(d),
      `Ο router/switch στέλνει περιλήψεις κάθε σύνδεσης (ποιος, προς ποιον, πόσα bytes) — έτσι βλέπεις την κίνηση <b>όλων</b> των συσκευών χωρίς port mirroring. Παράθυρο: τελευταία ${d.window_min || 30}′.`,
      d.enabled ? `<span class="tag g">ακούω UDP ${[d.listening?.netflow, d.listening?.sflow].filter(Boolean).join(' / ') || (d.demo ? 'demo' : '—')}</span>` : '<span class="tag">κλειστό</span>');
    if (d.error) h += `<div class="card" style="color:var(--redt)">${esc(d.error)}</div>`;
    if (!d.enabled) h += `<div class="card" style="white-space:normal">Άνοιξέ το στο <code>config.yaml</code> και ρύθμισε τον router να στέλνει ροές στον υπολογιστή του NetWatch:
      ${snippet('config.yaml', 'flows:\n  enabled: true\n  netflow_port: 2055\n  sflow_port: 6343\n  allow: ["192.168.1.1"]   # μόνο από τον router')}
      ${snippet('MikroTik (RouterOS)', '/ip traffic-flow set enabled=yes interfaces=all\n/ip traffic-flow target add dst-address=NETWATCH_IP port=2055 version=9')}
      ${snippet('OpenWrt (softflowd)', 'opkg install softflowd\nuci set softflowd.@softflowd[0].enabled=1\nuci set softflowd.@softflowd[0].host_port=NETWATCH_IP:2055\nuci commit && /etc/init.d/softflowd restart')}
      ${snippet('pfSense / OPNsense', 'pfSense: πακέτο softflowd → Host NETWATCH_IP, Port 2055, Version 9\nOPNsense: Reporting → NetFlow → Destinations NETWATCH_IP:2055')}
      ${snippet('Δοκιμή χωρίς router', 'python flows.py --send-test 127.0.0.1 2055')}</div>`;
    h += `<div class="kpis">${[[fmtB(T.bytes || 0), 'κίνηση στο παράθυρο'], [T.devices || 0, 'συσκευές LAN'], [T.destinations || 0, 'προορισμοί'], [T.conversations || 0, 'συνομιλίες'], [C.records || 0, 'εγγραφές ροών']].map(([v, l]) => `<div class="kpi"><b>${v}</b><span>${l}</span></div>`).join('')}</div>`;
    const sel = IF.sel.flow;
    h += `<h3>Ποιος μιλάει περισσότερο</h3><div class="card"><table><thead><tr><th>Συσκευή</th><th>Ανέβασμα</th><th>Κατέβασμα</th><th>Προορισμοί</th><th>Τελευταία</th></tr></thead><tbody>${(d.top_talkers || []).map(x => `<tr class="r${sel === x.ip ? ' on' : ''}" data-fdev="${esc(x.ip)}"><td>${hn(x.ip)}</td><td>${fmtB(x.bytes_out)}</td><td>${fmtB(x.bytes_in)}</td><td>${x.peers}</td><td>${ago(now() - x.last)}</td></tr>`).join('') || '<tr><td colspan="5" class="sm">καμία ροή ακόμα</td></tr>'}</tbody></table></div>`;
    if (sel && IF.data.fdev && IF.data.fdev.ip === sel) {
      const D = IF.data.fdev;
      h += `<div class="card"><div class="brow"><b class="ctitle">🔎 ${hn(sel)}</b><button class="b" data-fx>✕</button></div><table><thead><tr><th>Προορισμός</th><th>Θύρες</th><th>↑</th><th>↓</th><th>Τελευταία</th></tr></thead><tbody>${(D.destinations || []).slice(0, 40).map(x => `<tr class="r" data-ip="${esc(x.ip)}"><td>${x.local ? '🏠 ' : ''}${hn(x.ip)}</td><td>${(x.ports || []).join(', ')}</td><td>${fmtB(x.bytes_out)}</td><td>${fmtB(x.bytes_in)}</td><td>${ago(now() - x.last)}</td></tr>`).join('')}</tbody></table></div>`;
    }
    h += `<div class="g2"><div><h3>Κορυφαίοι προορισμοί (Internet)</h3><div class="card"><table><tbody>${(d.top_destinations || []).map(x => `<tr class="r" data-ip="${esc(x.ip)}"><td>${hn(x.ip)}<div class="sm">θύρες ${(x.ports || []).join(', ')} · από ${x.devices.length} συσκευ${x.devices.length === 1 ? 'ή' : 'ές'}</div></td><td style="text-align:right">${fmtB(x.bytes)}</td></tr>`).join('')}</tbody></table></div></div>
      <div><h3>Συνομιλίες</h3><div class="card"><table><tbody>${(d.top_conversations || []).map(x => `<tr class="r" data-ip="${esc(x.peer)}"><td>${hn(x.device)} → ${hn(x.peer)}<div class="sm">θύρες ${(x.ports || []).join(', ')}</div></td><td style="text-align:right">${fmtB(x.bytes)}</td></tr>`).join('')}</tbody></table></div></div></div>`;
    if ((d.exporters || []).length) h += `<h3>Εξαγωγείς (routers που στέλνουν)</h3><div class="card"><table><thead><tr><th>IP</th><th>Έκδοση</th><th>Πακέτα</th><th>Εγγραφές</th><th>Απορρίφθηκαν</th><th>Τελευταίο</th></tr></thead><tbody>${d.exporters.map(x => `<tr><td>${esc(x.ip)}</td><td>${esc(String(x.version))}</td><td>${x.datagrams}</td><td>${x.records}</td><td>${x.dropped}</td><td>${ago(now() - x.last)}</td></tr>`).join('')}</tbody></table>${C.rejected ? `<div class="sm" style="color:var(--redt)">⚠ ${C.rejected} πακέτα από μη επιτρεπόμενες IP: ${(d.rejected_from || []).map(x => esc(x.ip)).join(', ')}</div>` : ''}</div>`;
    el.innerHTML = h; bind(el);
    el.querySelectorAll('[data-fdev]').forEach(r => r.onclick = () => { const ip = r.dataset.fdev; IF.sel.flow = ip; fetch('/api/flows/device?ip=' + encodeURIComponent(ip)).then(x => x.json()).then(j => { IF.data.fdev = j; drawFlows(); }); });
    const fx = el.querySelector('[data-fx]'); if (fx) fx.onclick = () => { IF.sel.flow = null; drawFlows(); };
  }

  // =============== 🔌 Θύρες & SNMP (+ τοπολογία LLDP/CDP) ===============
  window.renderSnmp = () => load('snmp', '/api/snmp', 10, drawSnmp);
  function topo(targets) {
    const nodes = new Map(), edges = [];
    const key = s => String(s || '').toLowerCase();
    for (const t of targets) nodes.set(key(t.sys?.name || t.name), { id: key(t.sys?.name || t.name), l: t.name, sub: t.host, me: 1, ok: t.ok });
    for (const t of targets) for (const n of t.neighbours || []) {
      const a = key(t.sys?.name || t.name), b = key(n.remote_name);
      const known = [...nodes.values()].find(x => x.id === b || key(x.l) === b || x.sub === n.chassis);
      const bid = known ? known.id : b;
      if (!known) nodes.set(b, { id: b, l: n.remote_name || n.chassis || '?', sub: n.platform || n.proto.toUpperCase() });
      if (!edges.some(e => (e.a === a && e.b === bid) || (e.a === bid && e.b === a))) edges.push({ a, b: bid, la: n.local_port, lb: n.remote_port });
    }
    const L = [...nodes.values()]; if (L.length < 2) return '<div class="sm">Δεν βρέθηκαν γείτονες LLDP/CDP — άνοιξε το LLDP στον router/switch.</div>';
    // ιεραρχία: ρίζα = ο router (ή ο κόμβος με τις περισσότερες συνδέσεις), επίπεδα με BFS
    const deg = id => edges.filter(e => e.a === id || e.b === id).length;
    const root = (L.find(n => /router|gw|gateway/i.test(n.l)) || L.slice().sort((x, y) => deg(y.id) - deg(x.id))[0]).id;
    const lvl = new Map([[root, 0]]), qq = [root];
    while (qq.length) { const c = qq.shift(); for (const e of edges) { const o = e.a === c ? e.b : e.b === c ? e.a : null; if (o != null && !lvl.has(o)) { lvl.set(o, lvl.get(c) + 1); qq.push(o); } } }
    let mxl = Math.max(...lvl.values()); L.forEach(n => { if (!lvl.has(n.id)) lvl.set(n.id, ++mxl); });
    const rows = []; L.forEach(n => (rows[lvl.get(n.id)] = rows[lvl.get(n.id)] || []).push(n));
    const W = 900, RH = 110, H = rows.length * RH + 20;
    rows.forEach((r, k) => r.forEach((n, i) => { n.x = W * (i + 1) / (r.length + 1); n.y = 34 + k * RH; }));
    const P = id => L.find(n => n.id === id);
    const lab = (x, y, t, dx) => t ? `<text x="${(x + dx).toFixed(0)}" y="${y.toFixed(0)}" class="fl tp" text-anchor="${dx < 0 ? 'end' : 'start'}">${esc(t)}</text>` : '';
    let g = edges.map(e => { const a = P(e.a), b = P(e.b); if (!a || !b) return ''; const [u, v] = a.y <= b.y ? [a, b] : [b, a], [lu, lv] = a.y <= b.y ? [e.la, e.lb] : [e.lb, e.la];
      const dx = v.x >= u.x ? 6 : -6;
      return `<path d="M${u.x},${u.y} C${u.x},${(u.y + v.y) / 2} ${v.x},${(u.y + v.y) / 2} ${v.x},${v.y}" class="tl" fill="none"/>${lab(u.x, u.y + 26, lu, dx)}${lab(v.x, v.y - 18, lv, dx)}`; }).join('');
    g += L.map(n => `<g><circle cx="${n.x}" cy="${n.y}" r="${n.me ? 11 : 8}" class="tn${n.me ? ' me' : ''}${n.ok === false ? ' bad' : ''}"/><text x="${n.x + 16}" y="${n.y - 2}" class="fl tb">${esc(n.l)}</text><text x="${n.x + 16}" y="${n.y + 11}" class="fl">${esc(n.sub || '')}</text></g>`).join('');
    return `<svg class="topo" viewBox="0 0 ${W} ${H}" style="max-height:${H * 1.1}px">${g}</svg>`;
  }
  function drawSnmp() {
    const d = IF.data.snmp, el = $('t-snmp');
    if (d.off) {
      el.innerHTML = head('🔌', 'Θύρες & SNMP', 'Γραφήματα κίνησης ανά θύρα, σφάλματα, CPU/RAM και τοπολογία (LLDP) από router, switch και Proxmox — όπως LibreNMS / PRTG.') +
        `<div class="card" style="white-space:normal">Άνοιξέ το στο <code>config.yaml</code> (SNMP v2c, μόνο ανάγνωση):${snippet('config.yaml', 'snmp:\n  enabled: true\n  interval: 60\n  targets:\n    - {name: Router, host: 192.168.1.1, community: "public"}\n    - {name: Proxmox, host: 192.168.1.16, community: "public"}')}
        ${snippet('Proxmox / Linux (snmpd)', 'apt install snmpd\n# /etc/snmp/snmpd.conf\nagentaddress udp:161\nrocommunity public 192.168.1.0/24\nsystemctl restart snmpd')}
        ${snippet('Δοκιμή από τερματικό', 'python snmp.py 192.168.1.1 public')}<div class="sm">💡 CCNA: το SNMP v2c στέλνει το community σε καθαρό κείμενο — κράτα το μόνο στο LAN, με read‑only community και ACL.</div></div>`;
      bind(el); return;
    }
    let h = head('🔌', 'Θύρες & SNMP' + demoTag(d), `Κάθε ${d.interval}″ διαβάζω IF‑MIB (κίνηση, σφάλματα ανά θύρα), HOST‑RESOURCES (CPU/RAM) και LLDP (ποιος συνδέεται πού). Κλικ σε μια θύρα για γράφημα.`, '<button class="b" data-snpoll>↻ Τώρα</button>');
    for (const t of d.targets || []) {
      const s = t.sys || {};
      h += `<div class="card"><div class="brow"><b class="ctitle">${t.ok ? '🟢' : t.ok === false ? '🔴' : '⚪'} ${esc(t.name)} <span class="sm">${esc(t.host)}</span></b><span class="sm">${s.uptime != null ? 'uptime ' + esc(fmtUp(s.uptime)) : ''}${t.last_poll ? ' · ' + agoT(now() - t.last_poll) : ''}</span></div>
        <div class="sm"><span data-noi18n>${esc(s.descr || '')}</span>${s.location ? ' · 📍 <span>' + esc(s.location) + '</span>' : ''}</div>${t.error ? `<div style="color:var(--redt)">${esc(t.error)}</div>` : ''}
        ${t.cpu != null || t.ram != null ? `<div class="res">${t.cpu != null ? `<span>CPU ${pct(t.cpu)} ${t.cpu.toFixed(0)}%</span>` : ''}${t.ram != null ? `<span>RAM ${pct(t.ram)} ${t.ram.toFixed(0)}%</span>` : ''}</div>` : ''}
        ${(t.interfaces || []).length ? `<div class="iftw"><table class="ift"><thead><tr><th></th><th>Θύρα</th><th>Ταχύτητα</th><th>↓ Μέσα</th><th>↑ Έξω</th><th>Φόρτος</th><th>Σφάλματα/s</th><th>Τελευταία ώρα</th></tr></thead><tbody>${t.interfaces.map(i => {
          const up = i.oper === 'up', adm = i.admin === 'up', k = t.id + '#' + i.ifindex, on = IF.sel.ifc === k;
          return `<tr class="r${on ? ' on' : ''}" data-ifc="${esc(k)}"><td><span class="dot" style="background:${!adm ? 'var(--dim)' : up ? 'var(--green)' : 'var(--red)'}" title="${esc(i.admin + '/' + i.oper)}"></span></td><td><b>${esc(i.name)}</b>${i.alias ? ` <span class="sm">${esc(i.alias)}</span>` : ''}</td><td>${spd(i.speed)}</td><td>${bps(i.in_bps)}</td><td>${bps(i.out_bps)}</td><td>${i.util != null ? pct(i.util) + ' ' + i.util.toFixed(0) + '%' : '—'}</td><td style="color:${(i.err_s || 0) + (i.disc_s || 0) > 0 ? 'var(--orange)' : 'inherit'}">${i.err_s != null ? i.err_s.toFixed(1) : '—'}${i.disc_s ? ' / ' + i.disc_s.toFixed(1) : ''}</td><td>${miniIf(i.hist)}</td></tr>${on ? `<tr><td colspan="8">${bigIf(i)}</td></tr>` : ''}`;
        }).join('')}</tbody></table></div>` : ''}</div>`;
    }
    h += `<h3>Τοπολογία (LLDP / CDP)</h3><div class="card">${topo(d.targets || [])}</div>`;
    el.innerHTML = h; bind(el);
    el.querySelectorAll('[data-ifc]').forEach(r => r.onclick = () => { IF.sel.ifc = IF.sel.ifc === r.dataset.ifc ? null : r.dataset.ifc; drawSnmp(); });
    const p = el.querySelector('[data-snpoll]'); if (p) p.onclick = () => post('/api/snmp/poll', {}).then(() => { IF.at.snmp = 0; setTimeout(renderSnmp, 1500); });
  }
  const fmtUp = s => { const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60), [D, Hh] = EN() ? ['d', 'h'] : ['μ', 'ω']; return d ? `${d}${D} ${h}${Hh}` : h ? `${h}${Hh} ${m}′` : `${m}′`; };
  function miniIf(H) {
    if (!H || !(H.t || []).length) return '';
    const n = H.t.length, mx = Math.max(1, ...H.in.filter(x => x != null), ...H.out.filter(x => x != null)), W = 120, h = 22;
    const path = a => a.map((v, i) => v == null ? '' : `${i && a[i - 1] != null ? 'L' : 'M'}${(i * W / (n - 1)).toFixed(1)},${(h - v / mx * h).toFixed(1)}`).join('');
    return `<svg viewBox="0 0 ${W} ${h}" preserveAspectRatio="none" class="mif"><path d="${path(H.in)}" stroke="var(--cyan)"/><path d="${path(H.out)}" stroke="var(--purple)"/></svg>`;
  }
  function bigIf(i) {
    const H = i.hist || {}; if (!(H.t || []).length) return '';
    return `<div class="sm"><span style="color:var(--cyan)">━ μέσα</span> · <span style="color:var(--purple)">━ έξω</span> · ${esc(i.descr || i.name)} · ${spd(i.speed)}bps</div>` +
      lineChart(H.t, [{ v: H.in, col: 'var(--cyan)', fill: 1 }, { v: H.out, col: 'var(--purple)', fill: 1 }], { fmt: bps });
  }

  // =============== 📜 Syslog ===============
  const SEVN = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];
  const sevCol = s => s <= 2 ? 'var(--red)' : s === 3 ? 'var(--orange)' : s === 4 ? 'var(--yellow)' : s === 5 ? 'var(--cyan)' : 'var(--dim)';
  IF.slq = { q: '', host: '', sev: '' };
  const slUrl = () => '/api/syslog?' + new URLSearchParams({ q: IF.slq.q, host: IF.slq.host, sev: IF.slq.sev, limit: 300 }).toString();
  window.renderSyslog = () => load('syslog', slUrl(), 4, drawSyslog);
  function drawSyslog() {
    const d = IF.data.syslog, el = $('t-syslog');
    if (d.off) {
      el.innerHTML = head('📜', 'Syslog', 'Μαζεύει τα logs του router, του Proxmox, των ESP32 και του Mosquitto σε ένα σημείο, με αναζήτηση και κανόνες (όπως Graylog).') +
        `<div class="card" style="white-space:normal">${snippet('config.yaml', 'syslog:\n  enabled: true\n  port: 5514        # το 514 θέλει root\n  allow: ["192.168.1.0/24"]')}
        ${snippet('Proxmox / Linux (rsyslog)', 'echo "*.* @NETWATCH_IP:5514" > /etc/rsyslog.d/90-netwatch.conf\nsystemctl restart rsyslog')}
        ${snippet('OpenWrt', 'uci set system.@system[0].log_ip=NETWATCH_IP\nuci set system.@system[0].log_port=5514\nuci commit system && /etc/init.d/log restart')}
        ${snippet('MikroTik', '/system logging action add name=netwatch target=remote remote=NETWATCH_IP remote-port=5514\n/system logging add topics=info action=netwatch')}
        ${snippet('Δοκιμή', 'python syslogd.py --send-test 127.0.0.1 5514 "γεια"')}</div>`;
      bind(el); return;
    }
    const hosts = d.hosts || [], bs = d.by_sev || {};
    let h = head('📜', 'Syslog' + demoTag(d), `Ακούω σε UDP ${d.listen?.udp || '—'}${d.listen?.tcp ? ' / TCP ' + d.listen.tcp : ''} · ${d.total} μηνύματα (${d.rate_1m || 0}/λεπτό). Αναζήτηση: απλό κείμενο ή <code>re:</code> για regex.`);
    h += `<div class="card"><div class="slf"><input class="f" id="sl-q" placeholder="αναζήτηση… (π.χ. Failed password ή re:link (up|down))" value="${esc(IF.slq.q)}">
      <select class="f" id="sl-h"><option value="">όλες οι συσκευές</option>${hosts.map(x => `<option value="${esc(x.host)}"${IF.slq.host === x.host ? ' selected' : ''}>${esc(x.host)} (${x.count})</option>`).join('')}</select>
      <select class="f" id="sl-s"><option value="">κάθε σοβαρότητα</option>${SEVN.map((n, i) => `<option value="${i}"${String(IF.slq.sev) === String(i) ? ' selected' : ''}>≤ ${n}</option>`).join('')}</select></div>
      ${d.query_error ? `<div style="color:var(--redt)">${esc(d.query_error)}</div>` : ''}
      <div class="slsev">${SEVN.map((n, i) => bs[n] ? `<span class="tag" style="color:${sevCol(i)}">${n} ${bs[n]}</span>` : '').join('')}</div>
      <div class="sll">${(d.results || []).map(r => `<div class="slr"><span class="sm">${fmtT(r.t)}</span><span class="sv" style="color:${sevCol(r.severity)}">${esc(r.sev_name)}</span><b>${esc(r.host || r.src_ip)}</b><span class="sm">${esc(r.app || '')}</span><span class="msg" data-noi18n>${esc(r.msg)}</span></div>`).join('') || '<div class="sm">τίποτα</div>'}</div></div>`;
    if ((d.hits || []).length) h += `<h3>Κανόνες που χτύπησαν</h3><div class="card">${d.hits.slice(0, 12).map(x => `<div class="slr"><span class="sm">${fmtT(x.t)}</span><span class="sev ${x.sev}">${x.sev.toUpperCase()}</span><b>${esc(x.type)}</b><span class="sm">${esc(x.host || x.src_ip)} · ×${x.count}</span><span class="msg" data-noi18n>${esc(x.msg || '')}</span></div>`).join('')}</div>`;
    h += `<h3>Συσκευές</h3><div class="card"><table><thead><tr><th>Συσκευή</th><th>IP</th><th>Μηνύματα</th><th>Χειρότερο</th><th>Τελευταίο</th></tr></thead><tbody>${hosts.map(x => `<tr class="r" data-slh="${esc(x.host)}"><td>${esc(x.host)}</td><td>${esc(x.src_ip)}</td><td>${x.count}</td><td style="color:${sevCol(x.worst)}">${esc(x.worst_name)}</td><td>${ago(now() - x.last)}</td></tr>`).join('')}</tbody></table></div>`;
    el.innerHTML = h; bind(el);
    const go = () => { IF.at.syslog = 0; renderSyslog(); };
    const q = $('sl-q'); let tm; q.oninput = () => { IF.slq.q = q.value; clearTimeout(tm); tm = setTimeout(() => { go(); setTimeout(() => { const n = $('sl-q'); if (n) { n.focus(); n.setSelectionRange(n.value.length, n.value.length); } }, 300); }, 400); };
    $('sl-h').onchange = e => { IF.slq.host = e.target.value; go(); };
    $('sl-s').onchange = e => { IF.slq.sev = e.target.value; go(); };
    el.querySelectorAll('[data-slh]').forEach(r => r.onclick = () => { IF.slq.host = r.dataset.slh; go(); });
  }

  // =============== 🗂 IPAM / απογραφή ===============
  window.renderIpam = () => load('ipam', '/api/ipam', 15, drawIpam);
  const CELL = { network: 'var(--line)', broadcast: 'var(--line)', gateway: 'var(--cyan)', conflict: 'var(--red)', used: 'var(--green)', stale: 'var(--yellow)', reserved: 'var(--purple)', 'dhcp-pool': 'color-mix(in srgb,var(--cyan) 22%,transparent)', free: 'rgb(var(--w) / 6%)' };
  const CELLN = { network: 'δίκτυο', broadcast: 'broadcast', gateway: 'router', conflict: 'σύγκρουση', used: 'σε χρήση', stale: 'παλιά (>7 μέρες)', reserved: 'δεσμευμένη', 'dhcp-pool': 'DHCP pool (ελεύθερη)', free: 'ελεύθερη' };
  function drawIpam() {
    const d = IF.data.ipam, el = $('t-ipam');
    if (d.off) { el.innerHTML = '<div class="empty">Δεν είναι διαθέσιμο.</div>'; return; }
    let h = head('🗂', 'IPAM — διευθύνσεις & απογραφή', 'Ποιες IP είναι πιασμένες, ελεύθερες, στο DHCP pool ή δεσμευμένες· συγκρούσεις IP, στατικές μέσα στο pool, και σημειώσεις ανά συσκευή (όπως NetBox / phpIPAM).',
      `<span><a class="b" href="/api/ipam/export?fmt=csv" download>⬇ CSV</a> <a class="b" href="/api/ipam/export?fmt=json" download>⬇ JSON</a></span>`);
    if ((d.findings || []).length) h += `<h3>Ευρήματα</h3>${d.findings.map(f => `<div class="al ${f.sev === 'med' ? 'med' : 'low'}" style="white-space:normal"><span class="sev ${f.sev === 'med' ? 'med' : 'low'}">${f.sev.toUpperCase()}</span> <b>${esc(f.ip || '')}</b> <span>${esc(f.detail)}</span></div>`).join('')}`;
    for (const s of d.subnets || []) {
      h += `<div class="card"><div class="brow"><b class="ctitle">🧮 ${esc(s.name)} <span class="sm">${esc(s.cidr)}${s.vlan != null ? ' · VLAN ' + s.vlan : ''}${s.derived ? ' · αυτόματο' : ''}</span></b><span>${s.used}/${s.total} σε χρήση · ${s.free} ελεύθερες</span></div>
        <div style="margin:6px 0">${pct(s.pct)} <span class="sm">${s.pct}%</span>${s.dhcp ? ` <span class="sm">· DHCP <span data-noi18n>${esc(s.dhcp)}</span> <span>(${s.pool_used_pct}% γεμάτο)</span></span>` : ''}${s.next_free && s.next_free.length ? ' <span class="sm"><span>· επόμενες ελεύθερες:</span> <span data-noi18n>' + s.next_free.map(esc).join(', ') + '</span></span>' : ''}</div>
        ${s.map ? `<div class="ipg">${s.map.map(c => `<i style="background:${CELL[c.state] || CELL.free}" title="${esc(c.ip + ' · ' + (CELLN[c.state] || c.state) + (c.name ? ' · ' + c.name : '') + (c.mac ? ' · ' + c.mac : ''))}"${c.state === 'used' || c.state === 'conflict' || c.state === 'stale' ? ` data-ip="${esc(c.ip)}"` : ''}></i>`).join('')}</div>
        <div class="ipl">${Object.keys(CELL).filter(k => k !== 'broadcast').map(k => `<span><i style="background:${CELL[k]}"></i>${CELLN[k]}</span>`).join('')}</div>` : '<div class="sm">Πολύ μεγάλο subnet για χάρτη.</div>'}</div>`;
    }
    const inv = d.inventory || [];
    h += `<h3>Απογραφή (${inv.length})</h3><div class="card"><table><thead><tr><th>IP</th><th>Όνομα</th><th>MAC / κατασκευαστής</th><th>Κατάσταση</th><th>Σημειώσεις</th><th></th></tr></thead><tbody>${inv.map(r => {
      const key = r.mac || r.ip, ed = IF.sel.ipe === key;
      return `<tr class="r"><td>${esc(r.ip)}${r.in_pool ? ' <span class="tag">DHCP</span>' : ''}${r.reserved ? ' <span class="tag">δεσμ.</span>' : ''}</td><td>${esc(r.name || '')}</td><td class="sm">${esc(r.mac || '')}${r.vendor ? '<br>' + esc(r.vendor) : ''}</td><td><span class="tag ${r.status === 'online' ? 'g' : r.status === 'stale' ? 'y' : ''}">${esc(r.status)}</span></td>
        <td class="sm">${ed ? '' : esc([r.owner && '👤 ' + r.owner, r.location && '📍 ' + r.location, r.role, r.note].filter(Boolean).join(' · '))}${(r.tags || []).map(t => ` <span class="tag">${esc(t)}</span>`).join('')}</td>
        <td><button class="b" data-ipe="${esc(key)}">✏️</button></td></tr>${ed ? `<tr><td colspan="6"><div class="ipf">${['name', 'owner', 'location', 'role', 'note', 'tags'].map(f => `<label><span class="sm">${{ name: 'όνομα', owner: 'ιδιοκτήτης', location: 'τοποθεσία', role: 'ρόλος', note: 'σημείωση', tags: 'ετικέτες (,)' }[f]}</span><input class="f" data-nf="${f}" value="${esc(f === 'tags' ? (r.tags || []).join(', ') : r[f] || '')}"></label>`).join('')}<button class="b" data-ips="${esc(key)}">💾 Αποθήκευση</button><span class="sm" id="ipe-msg"></span></div></td></tr>` : ''}`;
    }).join('')}</tbody></table></div>`;
    el.innerHTML = h; bind(el);
    el.querySelectorAll('[data-ipe]').forEach(b => b.onclick = () => { IF.sel.ipe = IF.sel.ipe === b.dataset.ipe ? null : b.dataset.ipe; drawIpam(); });
    el.querySelectorAll('[data-ips]').forEach(b => b.onclick = () => {
      const f = {}; el.querySelectorAll('[data-nf]').forEach(i => f[i.dataset.nf] = i.dataset.nf === 'tags' ? i.value.split(',').map(x => x.trim()).filter(Boolean) : i.value.trim());
      post('/api/ipam/note', { key: b.dataset.ips, fields: f }).then(r => { if (r.error) { $('ipe-msg').textContent = r.error; return; } IF.sel.ipe = null; IF.at.ipam = 0; renderIpam(); });
    });
  }

  // =============== 📈 Καθυστέρηση (SmokePing) ===============
  IF.latH = 24;
  window.renderLat = () => {
    if (now() - (IF.at.lat || 0) > 20) {
      IF.at.lat = now();
      fetch('/api/latency').then(r => r.json()).then(st => {
        IF.data.lat = st; if (st.off) { if (tab === 'lat') drawLat(); return; }
        Promise.all((st.targets || []).map(t => fetch(`/api/latency?target=${encodeURIComponent(t.name)}&hours=${IF.latH}`).then(r => r.json()).then(j => [t.name, j.history]).catch(() => [t.name, null])))
          .then(rows => { IF.data.latH = Object.fromEntries(rows); if (tab === 'lat' && !tabHover()) drawLat(); });
      }).catch(() => { });
    }
    if (IF.data.lat) { if (!tabHover()) drawLat(); } else $('t-lat').innerHTML = '<div class="empty">φόρτωση…</div>';
  };
  function badSum(b) {
    const W = (b.worst || []).map(h => (b.hours || []).find(x => x.hour === h)).filter(Boolean);
    if (!W.length) return `<span>${esc(b.summary || '')}</span>`;
    return '<span>Χειρότερες ώρες:</span> ' + W.map(x => `<b>${String(x.hour).padStart(2, '0')}:00</b> <span>(${x.median != null ? `διάμεσος ${x.median} ms, ` : ''}απώλειες ${x.loss} %)</span>`).join(', ') +
      ` <span>— έναντι διάμεσου ${b.overall_median} ms συνολικά.</span>`;
  }
  function drawLat() {
    const d = IF.data.lat, el = $('t-lat');
    if (d.off || d.enabled === false) { el.innerHTML = '<div class="empty">Κλειστό (latency.enabled: false).</div>'; return; }
    let h = head('📈', 'Καθυστέρηση & απώλειες (SmokePing)' + demoTag(d), `Κάθε ${d.interval}″ στέλνω ${d.pings} ping σε κάθε στόχο και κρατάω ${d.keep_days} μέρες ιστορικό. Ο «καπνός» είναι το εύρος min–max, η γραμμή ο διάμεσος (πράσινη = χωρίς απώλειες, πορτοκαλί/κόκκινη = απώλειες). Ιδανικό για να αποδείξεις στον πάροχο ότι «κάθε βράδυ αργεί».`,
      `<div class="seg">${[[3, '3 ώρες'], [24, '24 ώρες'], [168, '7 μέρες']].map(([v, l]) => `<button data-lh="${v}" class="${IF.latH === v ? 'on' : ''}">${l}</button>`).join('')}</div>`);
    for (const t of d.targets || []) {
      const L = t.last || {}, H = (IF.data.latH || {})[t.name];
      h += `<div class="card"><div class="brow"><b class="ctitle">${(L.loss || 0) >= 20 ? '🔴' : (L.loss || 0) > 0 ? '🟡' : '🟢'} ${esc(t.name)} <span class="sm">${esc(t.host)}</span></b>
        <span class="lt">${L.med != null ? `<b>${L.med.toFixed(L.med < 10 ? 1 : 0)}</b> ms` : '—'} <span class="sm">jitter ${L.jitter != null ? L.jitter.toFixed(1) : '—'} · απώλειες ${L.loss != null ? L.loss.toFixed(0) : '—'}% · συνήθως ${t.baseline != null ? t.baseline.toFixed(1) : '—'} ms</span></span></div>
        ${H ? smokeChart(H, { days: IF.latH > 24 }) : '<div class="sm">φόρτωση…</div>'}
        ${t.bad_hours ? `<div class="bh">${(t.bad_hours.hours || []).map(x => `<i title="${String(x.hour).padStart(2, '0')}:00 · ${x.median ?? '—'} ms · ${x.loss ?? 0}%" style="background:${(t.bad_hours.worst || []).includes(x.hour) ? 'var(--orange)' : 'rgb(var(--w) / 10%)'};height:${Math.max(3, Math.min(26, (x.median || 0) / (t.bad_hours.overall_median || 1) * 13))}px"></i>`).join('')}</div><div class="sm">🕒 ${badSum(t.bad_hours)}</div>` : ''}</div>`;
    }
    el.innerHTML = h;
    el.querySelectorAll('[data-lh]').forEach(b => b.onclick = () => { IF.latH = +b.dataset.lh; IF.at.lat = 0; IF.data.latH = null; renderLat(); });
  }

  // =============== 🚀 Ταχύτητα & 📶 Wi‑Fi survey ===============
  window.renderSpeed = () => {
    load('speed', '/api/speed', 10, drawSpeed);
    if (now() - (IF.at.wsv || 0) > 120) { IF.at.wsv = now(); fetch('/api/wifisurvey').then(r => r.json()).then(j => { IF.data.wsv = j; if (tab === 'speed' && !tabHover()) drawSpeed(); }).catch(() => { }); }
  };
  function chanBars(occ, rec, own, band) {
    if (!occ || !occ.length) return '';
    const mx = Math.max(1, ...occ.map(x => x.score));
    return `<div class="chb">${occ.map(x => { const isRec = rec && (rec.channel === x.ch || (rec.block || []).includes(x.ch)), mine = own.includes(x.ch);
      return `<div title="κανάλι ${x.ch} · ${x.count} δίκτυα · φόρτος ${x.score}${x.dfs ? ' · DFS' : ''}"><i style="height:${(4 + x.score / mx * 56).toFixed(0)}px;background:${isRec ? 'var(--green)' : mine ? 'var(--cyan)' : x.score / mx > .66 ? 'var(--orange)' : 'rgb(var(--w) / 22%)'}"></i><span>${x.ch}</span></div>`; }).join('')}</div>`;
  }
  function drawSpeed() {
    const d = IF.data.speed, w = IF.data.wsv, el = $('t-speed');
    if (!d || d.off) { el.innerHTML = '<div class="empty">Δεν είναι διαθέσιμο.</div>'; return; }
    const LI = d.last_internet || {}, LP = d.last_iperf || {};
    let h = head('🚀', 'Ταχύτητα' + demoTag(d), 'Δύο μετρήσεις: <b>Internet</b> (κατέβασμα/ανέβασμα προς την Cloudflare) και <b>LAN</b> με iperf3 προς έναν υπολογιστή του σπιτιού (π.χ. VM στον Proxmox) — για να δεις αν φταίει το Wi‑Fi, το καλώδιο ή ο πάροχος.');
    h += `<div class="g2"><div class="card"><div class="brow"><b class="ctitle">🌍 Internet</b><button class="b" data-sprun="internet"${d.running ? ' disabled' : ''}>▶ Μέτρηση</button></div>
      <div class="spd"><div><b>${LI.down_mbps != null ? LI.down_mbps.toFixed(0) : '—'}</b><span>Mbps ↓</span></div><div><b>${LI.up_mbps != null ? LI.up_mbps.toFixed(0) : '—'}</b><span>Mbps ↑</span></div><div><b>${LI.latency_ms != null ? LI.latency_ms.toFixed(0) : '—'}</b><span>ms</span></div></div>
      <div class="sm">${LI.t ? agoT(now() - LI.t) + ' · ' : ''}<span>${esc(d.note || '')}</span></div>${LI.ok === false ? `<div style="color:var(--redt)">${esc(LI.error || '')}</div>` : ''}</div>
      <div class="card"><div class="brow"><b class="ctitle">🏠 LAN (iperf3)</b><span><input class="f" id="sp-host" placeholder="π.χ. 192.168.1.16" value="${esc(IF.sel.iperf || LP.target || '')}" style="width:150px"> <button class="b" data-sprun="iperf"${d.running || !d.iperf_available ? ' disabled' : ''}>▶</button></span></div>
      ${d.iperf_available ? `<div class="spd"><div><b>${LP.sent_mbps != null ? LP.sent_mbps.toFixed(0) : '—'}</b><span>Mbps αποστολή</span></div><div><b>${LP.recv_mbps != null ? LP.recv_mbps.toFixed(0) : '—'}</b><span>Mbps λήψη</span></div><div><b>${LP.retransmits ?? '—'}</b><span>επαναποστολές</span></div></div><div class="sm">${LP.t ? agoT(now() - LP.t) + ' · <span data-noi18n>' + esc(LP.target || '') + '</span>' : 'Στον στόχο τρέξε: '}<code>iperf3 -s</code></div>${LP.ok === false ? `<div style="color:var(--redt)">${esc(LP.error || '')}</div>` : ''}` : `<div class="sm" style="white-space:normal">${esc(d.iperf_help || '')}</div>`}</div></div>`;
    const hist = (d.history || []).filter(x => x.kind === 'internet' && x.ok);
    if (hist.length > 2) h += `<div class="card"><div class="sm"><span style="color:var(--cyan)">━ κατέβασμα</span> · <span style="color:var(--purple)">━ ανέβασμα</span> (Mbps)</div>${lineChart(hist.map(x => x.t), [{ v: hist.map(x => x.down_mbps), col: 'var(--cyan)', fill: 1 }, { v: hist.map(x => x.up_mbps), col: 'var(--purple)' }], { fmt: v => v.toFixed(0) + ' Mbps', h: 110 })}</div>`;
    // Wi‑Fi survey
    h += `<h3>📶 Wi‑Fi γύρω σου — κανάλια</h3>`;
    if (!w) h += '<div class="card sm">σάρωση… (5–10″)</div>';
    else if (w.error || w.ok === false) h += `<div class="card" style="color:var(--redt)">${esc(w.error || 'αποτυχία σάρωσης')}</div>`;
    else {
      const c = w.current || {}, R = w.recommendation || {}, own24 = (w.own || []).filter(x => x.band === '2.4').map(x => x.channel).concat(c.band === '2.4' ? [c.channel] : []), own5 = (w.own || []).filter(x => x.band === '5').map(x => x.channel).concat(c.band === '5' ? [c.channel] : []);
      h += `<div class="card"><div class="brow"><b class="ctitle">📡 ${esc(c.ssid || 'το δίκτυό σου')} <span class="sm">κανάλι ${c.channel ?? '—'} · ${c.band || '?'} GHz · ${c.width || '?'} MHz · ${esc(c.phy || '')}</span></b><span>${c.rssi != null ? `<b style="color:${c.rssi > -60 ? 'var(--green)' : c.rssi > -70 ? 'var(--yellow)' : 'var(--red)'}">${c.rssi} dBm</b>` : ''} <span class="sm">SNR ${c.snr ?? '—'} dB</span> <button class="b" data-wsv>↻</button></span></div>
        ${(w.issues || []).map(x => `<div class="wiss ${x.sev}">${x.sev === 'high' ? '⛔' : x.sev === 'med' ? '⚠️' : x.sev === 'low' ? '💡' : 'ℹ️'} ${esc(x.text)}</div>`).join('')}
        <div class="g2"><div><div class="sm">2,4 GHz · ${w.counts?.['2.4'] || 0} δίκτυα · προτείνεται <b style="color:var(--green)">${R['2.4']?.channel ?? '—'}</b> (20 MHz)</div>${chanBars(w.occupancy?.['2.4'], R['2.4'], own24)}</div>
        <div><div class="sm">5 GHz · ${w.counts?.['5'] || 0} δίκτυα · προτείνεται <b style="color:var(--green)">${R['5'] ? (R['5'].block || [R['5'].channel]).join('/') : '—'}</b>${R['5'] ? ` (${R['5'].width} MHz${R['5'].dfs ? ', DFS' : ''})` : ''}</div>${chanBars((w.occupancy?.['5'] || []).filter(x => x.count || (R['5']?.block || []).includes(x.ch)), R['5'], own5)}</div></div>
        <div class="ipl"><span><i style="background:var(--green)"></i>προτεινόμενο</span><span><i style="background:var(--cyan)"></i>το δικό σου</span><span><i style="background:var(--orange)"></i>φορτωμένο</span></div>
        ${w.note ? `<div class="sm" style="white-space:normal">ℹ️ ${esc(w.note)}</div>` : ''}</div>
        <details><summary>Όλα τα δίκτυα (${(w.networks || []).length})</summary><table><thead><tr><th>SSID</th><th>Κανάλι</th><th>Σήμα</th><th>Ασφάλεια</th><th>PHY</th></tr></thead><tbody>${(w.networks || []).map(n => `<tr><td data-noi18n>${n.current ? '⭐ ' : ''}${esc(n.ssid || (n.redacted ? '(κρυφό)' : '—'))}</td><td>${n.channel} <span class="sm">${n.band} GHz · ${n.width || '?'} MHz</span></td><td>${n.rssi ?? '—'} dBm</td><td style="color:${/^(open|wep|wpa)$/.test(n.security) ? 'var(--red)' : 'inherit'}">${esc(n.security || '?')}</td><td class="sm">${esc(n.phy || '')}</td></tr>`).join('')}</tbody></table></details>`;
    }
    el.innerHTML = h; bind(el);
    el.querySelectorAll('[data-sprun]').forEach(b => b.onclick = () => {
      const k = b.dataset.sprun, host = ($('sp-host') || {}).value || '';
      if (k === 'internet' && !confirm('Η μέτρηση κατεβάζει ~25 MB και ανεβάζει ~10 MB από/προς την Cloudflare (speed.cloudflare.com). Συνέχεια;')) return;
      if (k === 'iperf') IF.sel.iperf = host;
      post('/api/speed/' + k, k === 'iperf' ? { host } : {}).then(r => { if (r.error) toastMsg('⚠ ' + r.error); IF.at.speed = 0; renderSpeed(); });
    });
    const ws = el.querySelector('[data-wsv]'); if (ws) ws.onclick = () => { ws.disabled = true; post('/api/wifisurvey/scan', {}).then(j => { IF.data.wsv = j; drawSpeed(); }); };
  }

  // =============== 🛠 Λειτουργία: συντήρηση, ειδοποιήσεις, Prometheus, tokens, pcap ===============
  window.renderOps = () => {
    load('ops', '/api/maint', 10, drawOps);
    if (now() - (IF.at.pcap || 0) > 10) { IF.at.pcap = now(); fetch('/api/pcap').then(r => r.json()).then(j => { IF.data.pcap = j; }).catch(() => { }); }
  };
  function drawOps() {
    const d = IF.data.ops, el = $('t-ops'), P = IF.data.pcap, ch = (S.features && S.features.notify) || {};
    const base = location.origin;
    let h = head('🛠', 'Λειτουργία', 'Παράθυρα συντήρησης, κανάλια ειδοποιήσεων, εξαγωγή μετρικών για Grafana και καταγραφή πακέτων γύρω από κάθε ειδοποίηση — τα «εργαλεία βάρδιας» ενός NOC.');
    h += `<div class="card"><div class="brow"><b class="ctitle">🔧 Συντήρηση</b>${d.active ? `<span class="tag y">ενεργή: ${esc(d.active)}</span>` : '<span class="tag g">καμία τώρα</span>'}</div>
      <div class="sm" style="margin:4px 0 8px">Όσο τρέχει, οι ειδοποιήσεις φαίνονται εδώ αλλά <b>δεν</b> στέλνονται στο κινητό και δεν τρέχουν playbooks — για backups, αναβαθμίσεις ή τις δικές σου δοκιμές.</div>
      <div class="brow" style="justify-content:flex-start;gap:6px">${[[30, '30′'], [60, '1 ώρα'], [240, '4 ώρες']].map(([m, l]) => `<button class="b" data-mute="${m}">🔕 Σίγαση ${l}</button>`).join('')}</div>
      ${(d.mutes || []).map(m => `<div class="slr"><span>🔕</span><b>${esc(m.name)}</b><span class="sm">λήγει σε ${ago(m.left)}${m.hosts && m.hosts.length ? ' · μόνο ' + m.hosts.map(esc).join(', ') : ''}</span><button class="b" data-unmute="${m.id}">✕</button></div>`).join('')}
      ${(d.windows || []).length ? `<table style="margin-top:8px"><tbody>${d.windows.map(w => `<tr><td>${w.active ? '🟡' : '🗓'} <b>${esc(w.name)}</b></td><td class="sm">${w.kind === 'weekly' ? `${(w.days || []).length === 7 ? 'κάθε μέρα' : (w.days || []).join(', ')} ${w.start}–${w.end}` : fmtT(w.start) + ' → ' + fmtT(w.end)}${(w.hosts || []).length ? ' · ' + w.hosts.map(esc).join(', ') : ''}</td></tr>`).join('')}</tbody></table>` : ''}
      ${(d.errors || []).map(e => `<div style="color:var(--redt)">${esc(e)}</div>`).join('')}
      ${snippet('Προγραμματισμένα παράθυρα (config.yaml)', 'maintenance:\n  - {name: "Backup NAS", days: [mon, tue, wed, thu, fri, sat, sun], start: "02:00", end: "04:00"}\n  - {name: "Αναβάθμιση router", start: "2026-12-01 22:00", end: "2026-12-01 23:30", hosts: ["192.168.1.1"]}')}</div>`;
    const CH = [['macos', 'macOS'], ['telegram', 'Telegram'], ['ntfy', 'ntfy'], ['discord', 'Discord'], ['slack', 'Slack'], ['webhook', 'Webhook'], ['email', 'Email']];
    h += `<div class="card"><div class="brow"><b class="ctitle">🔔 Κανάλια ειδοποιήσεων</b><button class="b" data-ntest>📨 Δοκιμή</button></div>
      <div class="chips">${CH.map(([k, l]) => `<span class="tag ${ch[k] ? 'g' : ''}">${ch[k] ? '✓' : '○'} ${l}</span>`).join(' ')}</div><div id="ntest" class="sm"></div>
      ${snippet('config.yaml', 'notify:\n  min_severity: high\n  discord: {webhook: "https://discord.com/api/webhooks/…"}\n  slack:   {webhook: "https://hooks.slack.com/services/…"}\n  webhook: {url: "http://192.168.1.30:8123/api/webhook/netwatch"}\n  email:   {host: smtp.gmail.com, port: 587, user: "…", password: "app-password", to: ["…"]}')}
      <div class="sm">🔒 Τα webhooks και οι κωδικοί μένουν μόνο στο <code>config.yaml</code> (δεν ανεβαίνει ποτέ στο git).</div></div>`;
    const scrape = `scrape_configs:\n  - job_name: netwatch\n    metrics_path: /metrics\n    static_configs:\n      - targets: ["${location.host}"]`;
    h += `<div class="card"><div class="brow"><b class="ctitle">📊 Prometheus / Grafana</b><a class="b" href="/metrics" target="_blank" rel="noopener">/metrics ↗</a></div>
      <div class="sm">Πακέτα/s, κίνηση, hosts, ειδοποιήσεις ανά σοβαρότητα, homelab up/latency, ping (SmokePing) και αν τρέχει συντήρηση — σε μορφή Prometheus.</div>
      ${snippet('prometheus.yml', scrape)}</div>`;
    h += `<div class="card"><div class="brow"><b class="ctitle">🔑 Tokens μόνο-ανάγνωσης</b></div><div class="sm" style="white-space:normal">Σε λειτουργία agent (HTTPS στο LAN) δώσε σε μια οθόνη τοίχου ή στο Prometheus δικό του token που <b>μόνο βλέπει</b> — δεν μπορεί να σαρώσει, να μπλοκάρει ή να αλλάξει τίποτα. Άνοιγμα: <code>${esc(base)}/?token=…&amp;noc=1</code> ή header <code>Authorization: Bearer …</code>.</div>
      ${snippet('config.yaml', 'api_tokens:\n  - {name: "Οθόνη σαλονιού", token: "τουλάχιστον-16-τυχαίοι-χαρακτήρες", role: viewer}\n  - {name: Prometheus, token: "…", role: viewer}')}</div>`;
    if (P && !P.off) h += `<div class="card"><div class="brow"><b class="ctitle">🦈 Καταγραφή γύρω από τις ειδοποιήσεις</b><span class="tag ${P.enabled ? 'g' : ''}">${P.demo ? 'demo: συνθετικά pcap' : P.enabled ? 'ενεργή' : 'κλειστή'}</span></div>
      <div class="sm">Κρατάω στη μνήμη τα τελευταία ${Math.round(P.seconds / 60)}′ πακέτων (έως ${fmtB(P.max_bytes)}). Σε κάθε ειδοποίηση υπάρχει κουμπί <b>⬇ .pcap</b> με τα πακέτα από 60″ πριν έως 30″ μετά — ανοίγει στο Wireshark.</div>
      <div style="margin-top:6px">${pct(P.fill * 100)} <span class="sm">${P.packets} πακέτα · ${fmtB(P.bytes)} · ${P.span ? P.span.toFixed(0) + '″' : '—'}</span></div></div>`;
    el.innerHTML = h; bind(el);
    el.querySelectorAll('[data-mute]').forEach(b => b.onclick = () => post('/api/maint/mute', { minutes: +b.dataset.mute }).then(j => { IF.data.ops = j; drawOps(); }));
    el.querySelectorAll('[data-unmute]').forEach(b => b.onclick = () => post('/api/maint/unmute', { id: +b.dataset.unmute }).then(j => { IF.data.ops = j; drawOps(); }));
    const nt = el.querySelector('[data-ntest]'); if (nt) nt.onclick = () => post('/api/notify', {}).then(r => { $('ntest').textContent = Object.entries(r.result || r).map(([k, v]) => `${k}: ${v}`).join(' · '); });
  }
})();
