// 🔒 Ασφάλεια & ιδιωτικότητα — καρτέλες που δένουν με τα backend modules:
//   🧅 Tor (κύκλωμα 3 κόμβων), 🔒 VPN (WireGuard/Tailscale + kill-switch), 🔐 DNS (Pi-hole + κρυπτογραφημένο DNS ανά συσκευή),
//   📹 Κάμερες (έλεγχος έκθεσης — δικό σου δίκτυο, read-only), 📥 SIEM (Suricata/Zeek), 🔏 Πιστοποιητικά (Certificate Transparency)
// Φορτώνεται μετά το infra.js· χρησιμοποιεί τα κοινά του index.html ($, esc, ico, fmtB, fmtT, post, tab, tabHover, S, flag, hname).
(() => {
  'use strict';
  const E = s => (window.esc ? esc(s) : String(s == null ? '' : s));
  const now = () => Date.now() / 1000;
  const T = { data: {}, at: {}, sel: {} };
  const T2d = {};  // cache για το Pi-hole status της καρτέλας trackers
  window.SECT = T;
  const hn = ip => { const h = (typeof S !== 'undefined' && S) ? S.hosts.get(ip) : null, n = h && (window.hname ? hname(h) : '') || (h && h.name); return n ? `${E(n)} <span class="sm">${E(ip)}</span>` : `<span data-noi18n>${E(ip)}</span>`; };
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const ago = s => s == null ? '—' : s < 90 ? Math.round(s) + '″' : s < 5400 ? Math.round(s / 60) + '′' : s < 172800 ? Math.round(s / 3600) + (EN() ? 'h' : 'ω') : Math.round(s / 86400) + (EN() ? 'd' : 'μ');
  const agoT = s => EN() ? ago(s) + ' ago' : 'πριν ' + ago(s);
  function load(key, url, every, draw) {
    draw();
    if (now() - (T.at[key] || 0) > every) {
      T.at[key] = now();
      fetch(url).then(r => r.json()).then(j => { T.data[key] = j; if (!(window.tabHover && tabHover())) draw(); }).catch(() => { });
    }
  }
  const off = d => d && (d.off || d.enabled === false) && !d.demo;
  const offCard = (title, hint) => `<div class="card"><b style="color:var(--hi)">${title}</b><div class="sm" style="white-space:normal;margin-top:4px">${hint}</div></div>`;
  const sim = d => d && d.demo ? ' <span class="tag">προσομοίωση</span>' : '';

  // ───────────────────────── 🧅 Tor ─────────────────────────
  const CC_NAME = { DE: 'Γερμανία', NL: 'Ολλανδία', FR: 'Γαλλία', SE: 'Σουηδία', US: 'ΗΠΑ', CH: 'Ελβετία', RO: 'Ρουμανία', AT: 'Αυστρία', GB: 'Βρετανία', CA: 'Καναδάς', FI: 'Φινλανδία', LU: 'Λουξεμβ.', GR: 'Ελλάδα' };
  function torMap(circuit, w, h) {  // ισοαπέχουσα προβολή, προσαρμοσμένη στα σημεία του κυκλώματος ώστε να απλώνουν
    const hops = (circuit.hops || []).filter(x => x.lat != null);
    const all = [[39, 22]].concat(hops.map(x => [x.lat, x.lon]));
    const lats = all.map(a => a[0]), lons = all.map(a => a[1]);
    let la0 = Math.min(...lats), la1 = Math.max(...lats), lo0 = Math.min(...lons), lo1 = Math.max(...lons);
    const pad = Math.max(8, (la1 - la0) * 0.35, (lo1 - lo0) * 0.25);
    la0 -= pad; la1 += pad; lo0 -= pad; lo1 += pad;
    const pr = (lat, lon) => [(lon - lo0) / Math.max(1, lo1 - lo0) * w, (la1 - lat) / Math.max(1, la1 - la0) * h];
    const me = pr(39, 22);  // περίπου Ελλάδα — από εκεί «ξεκινάς»
    const pts = hops.map(x => ({ ...x, xy: pr(x.lat, x.lon) }));
    const col = { guard: 'var(--cyan)', middle: 'var(--purple)', exit: 'var(--red)' };
    let g = `<svg viewBox="0 0 ${w} ${h}" class="tor-map" preserveAspectRatio="none">`;
    for (let i = 0; i <= 6; i++) g += `<line x1="0" y1="${h * i / 6}" x2="${w}" y2="${h * i / 6}" class="grid"/><line x1="${w * i / 6}" y1="0" x2="${w * i / 6}" y2="${h}" class="grid"/>`;
    let prev = me;
    for (const p of pts) { g += `<path d="M${prev[0].toFixed(0)} ${prev[1].toFixed(0)} Q ${((prev[0] + p.xy[0]) / 2).toFixed(0)} ${(Math.min(prev[1], p.xy[1]) - 26).toFixed(0)} ${p.xy[0].toFixed(0)} ${p.xy[1].toFixed(0)}" class="hop ${p.role}"/>`; prev = p.xy; }
    g += `<circle cx="${me[0]}" cy="${me[1]}" r="4" class="me"/>`;
    for (const p of pts) g += `<circle cx="${p.xy[0].toFixed(0)}" cy="${p.xy[1].toFixed(0)}" r="4.5" style="fill:${col[p.role] || 'var(--mid)'}"/>`;
    return g + '</svg>';
  }
  function drawTor() {
    const el = document.getElementById('t-tor'), d = T.data.tor;
    if (!el) return;
    if (off(d)) return el.innerHTML = offCard('🧅 Tor', 'Δεν τρέχει Tor με ControlPort. Άνοιξε το <b>Tor Browser</b>, ή <code>brew install tor</code> και στο torrc: <code>ControlPort 9051</code> + <code>CookieAuthentication 1</code>.') + torHelp();
    let h = `<h3>🧅 Tor — το κύκλωμα των 3 κόμβων${sim(d)}</h3>`;
    if (!d) return el.innerHTML = h + '<div class="card sm">φόρτωση…</div>';
    if (d.error && !d.connected) h += offCard('Το Tor δεν απαντά', E(d.hint || d.error));
    if (d.connected) {
      h += `<div class="card"><div class="brow"><b class="ctitle">🟢 Συνδεδεμένο στο Tor <span class="sm">θύρα ${d.port} · ${E(d.version || '')} · ${E(d.auth || '')}</span></b>
        <span>${d.traffic ? `<span class="sm">↓ ${fmtB(d.traffic.read)} · ↑ ${fmtB(d.traffic.written)}</span> ` : ''}<button class="b" id="tor-nym" ${d.newnym_wait ? 'disabled' : ''}>🔄 Νέα ταυτότητα${d.newnym_wait ? ` (${d.newnym_wait}″)` : ''}</button></span></div>
        <div class="sm" style="white-space:normal">Κάθε σύνδεση περνά από 3 τυχαίους κόμβους με κρυπτογράφηση σε στρώσεις («κρεμμύδι»): ο <b style="color:var(--cyan)">guard</b> ξέρει ποιος είσαι μα όχι πού πας, ο <b style="color:var(--purple)">middle</b> τίποτα από τα δύο, ο <b style="color:var(--red)">exit</b> βγαίνει στο Internet μα δεν ξέρει ποιος είσαι.</div></div>`;
      for (const c of (d.circuits || []).slice(0, 6)) {
        h += `<div class="card"><div class="brow"><b class="ctitle">Κύκλωμα #${E(c.id)} <span class="tag g">${E(c.status)}</span></b><span class="sm">${E(c.purpose || '')} · ${ago(c.age_s)}</span></div>
          <div class="tor-chain">${chainNode('🙂', 'Εσύ', 'GR', '')}${(c.hops || []).map(hp => chainNode('🧅', hp.nick, hp.cc, hp.role)).join('')}${chainNode('🌐', 'Internet', '', '')}</div>
          ${torMap(c, 520, 150)}</div>`;
      }
      if (d.guard) h += `<div class="card sm" style="white-space:normal">🛡 Ο σταθερός σου <b>guard</b> αυτή τη στιγμή: <b data-noi18n>${E(d.guard.nick)}</b> (${flag(d.guard.cc)} ${E(CC_NAME[d.guard.cc] || d.guard.cc)}). Ο guard αλλάζει μόνο κάθε λίγους μήνες — έτσι δυσκολεύει μια παρακολούθηση.</div>`;
    }
    el.innerHTML = h + torHelp();
    const b = el.querySelector('#tor-nym'); if (b) b.onclick = () => post('/api/tor/newnym', {}).then(() => { T.at.tor = 0; setTimeout(() => load('tor', '/api/tor', 0, drawTor), 800); });
  }
  const chainNode = (ic, name, cc, role) => `<div class="tn ${role}"><div class="tn-i">${ic}</div><b data-noi18n>${E(name || '?')}</b>${cc ? `<span class="sm">${flag(cc)} ${E(CC_NAME[cc] || cc)}</span>` : ''}${role ? `<span class="tn-r ${role}">${role}</span>` : ''}</div>`;
  const torHelp = () => `<div class="sm" style="margin-top:8px;white-space:normal">🧅 Το NetWatch διαβάζει μόνο (ControlPort σε localhost) — δεν στέλνει και δεν αλλάζει τίποτα. Η «Νέα ταυτότητα» (NEWNYM) ζητά από το Tor καινούργιο κύκλωμα, όπως το κουμπί στο Tor Browser.</div>`;

  // ───────────────────────── 🔒 VPN / WireGuard ─────────────────────────
  function spark(hist, key, w = 90, h = 20) {
    const v = (hist || []).map(x => Array.isArray(x) ? x[key] : x).filter(x => x != null);
    if (v.length < 2) return '';
    const mx = Math.max(1, ...v);
    return `<svg viewBox="0 0 ${w} ${h}" class="mif" preserveAspectRatio="none"><path d="${v.map((x, i) => `${i ? 'L' : 'M'}${(i * w / (v.length - 1)).toFixed(1)},${(h - x / mx * h).toFixed(1)}`).join('')}" stroke="var(--cyan)"/></svg>`;
  }
  function drawVpn() {
    const el = document.getElementById('t-vpnm'); if (!el) return;
    const vg = T.data.vpnguard, wg = (T.data.vpn || {});
    let h = `<h3>🔒 VPN — kill-switch & split-tunnel${sim(vg)}</h3>`;
    if (vg && !off(vg)) {
      const modeTag = { full: '<span class="tag g">πλήρες τούνελ</span>', split: '<span class="tag y">split tunnel</span>', off: '<span class="tag">ανενεργό</span>' }[vg.mode] || '';
      h += `<div class="card"><div class="brow"><b class="ctitle">${vg.mode === 'off' ? '🔓' : '🔒'} VPN ${modeTag}</b>
        <button class="b" id="vpn-arm">🧪 Δοκιμή kill-switch</button></div>
        <div class="sm" style="white-space:normal">${vg.vpn && vg.vpn.iface ? `Τούνελ <b data-noi18n>${E(vg.vpn.iface)}</b> → ` : 'Χωρίς VPN. '}φυσική κάρτα <b data-noi18n>${E((vg.physical || {}).iface || '?')}</b>. ${vg.mode === 'full' ? 'Όλη η κίνηση περνά από το VPN.' : vg.mode === 'split' ? 'Προσοχή: μόνο μέρος της κίνησης περνά από το VPN.' : ''}</div>`;
      const ks = vg.killswitch || {};
      if (ks.armed) h += `<div class="ks on">🧪 Οπλισμένο — <b>κλείσε τώρα το VPN</b> για ${Math.max(0, Math.round((ks.watch_until || ks.until) - now()))}″· βλέπω αν διαρρεύσει κίνηση.</div>`;
      else if (ks.last) { const v = ks.last.verdict; h += `<div class="ks ${v}">${v === 'pass' || v === 'no-drop' ? '✅' : '❌'} Τελευταία δοκιμή: ${v === 'fail' ? `<b style="color:var(--redt)">χωρίς kill-switch — διέρρευσαν:</b> ${(ks.last.apps || []).map(a => E(a.name)).join(', ')}` : v === 'no-drop' ? 'το VPN δεν έπεσε' : 'κανένα app δεν βγήκε εκτός τούνελ — καλό'} <span class="sm">${agoT(now() - ks.last.t)}</span></div>`; }
      if (vg.note) h += `<div class="sm" style="white-space:normal;margin-top:4px">${E(vg.note)}</div>`;
      h += '</div>';
      if ((vg.apps || []).length) h += `<h3>Εφαρμογές εκτός τούνελ</h3><div class="card"><table><thead><tr><th>Εφαρμογή</th><th>Μέσω VPN</th><th>Εκτός</th><th></th></tr></thead><tbody>${vg.apps.map(a => `<tr><td><b data-noi18n>${E(a.name)}</b>${a.pid ? ` <span class="sm">pid ${a.pid}</span>` : ''}</td><td>${a.via_vpn || 0}</td><td style="color:${a.leak ? 'var(--redt)' : 'inherit'}">${a.outside || 0}</td><td>${a.leak ? '<span class="tag r">διαρροή</span>' : a.vpn_client ? '<span class="sm">πελάτης VPN</span>' : ''}</td></tr>`).join('')}</tbody></table></div>`;
      if ((vg.events || []).length) h += `<details class="card"><summary>Ιστορικό VPN (${vg.events.length})</summary><table><tbody>${vg.events.slice(0, 20).map(e => `<tr><td class="sm">${agoT(now() - e.t)}</td><td><span data-noi18n>${E(e.text)}</span></td></tr>`).join('')}</tbody></table></details>`;
    }
    // WireGuard / Tailscale
    const w = wg.wireguard, ts = wg.tailscale;
    if (w && w.available) for (const i of (w.interfaces || [])) {
      h += `<h3>🔗 WireGuard — <span data-noi18n>${E(i.name)}</span></h3><div class="card"><table><thead><tr><th>Peer</th><th>Endpoint</th><th>Handshake</th><th>↓ / ↑</th><th>Κίνηση</th></tr></thead><tbody>${(i.peers || []).map(p => `<tr><td><b data-noi18n>${E(p.name || p.key)}</b> ${stateTag(p.state)}</td><td class="sm" data-noi18n>${E(p.endpoint || '—')}</td><td>${p.handshake_ago == null ? '—' : agoT(p.handshake_ago)}</td><td class="sm">${fmtB(p.rx)} / ${fmtB(p.tx)}</td><td>${spark(p.hist, 0)}</td></tr>`).join('') || '<tr><td colspan="5" class="sm">κανένας peer</td></tr>'}</tbody></table></div>`;
    }
    if (ts && ts.available) h += `<h3>🧩 Tailscale${ts.self ? ` — <span class="sm" data-noi18n>${E(ts.self.name || '')}</span>` : ''}</h3><div class="card"><table><thead><tr><th>Συσκευή</th><th>IP</th><th>Σύνδεση</th><th>Τελευταία</th></tr></thead><tbody>${(ts.peers || []).map(p => `<tr><td><b data-noi18n>${E(p.name)}</b> ${p.online ? '<span class="tag g">online</span>' : '<span class="tag">offline</span>'}${p.exit_node ? ' <span class="tag y">exit</span>' : ''}</td><td class="sm" data-noi18n>${E((p.ip) || '')}</td><td class="sm">${p.direct ? '🔗 άμεση' : p.relay ? '↪ relay ' + E(p.relay) : '—'}</td><td class="sm">${p.online ? '—' : agoT(p.last_seen_ago)}</td></tr>`).join('')}</tbody></table></div>`;
    if (w && !w.available && w.error) h += `<div class="sm" style="white-space:normal">🔗 WireGuard: ${E(wg.hint || w.error)}</div>`;
    el.innerHTML = h;
    const ab = el.querySelector('#vpn-arm'); if (ab) ab.onclick = () => post('/api/vpnguard/arm', { seconds: 60 }).then(() => { T.at.vpnguard = 0; setTimeout(() => load('vpnguard', '/api/vpnguard', 0, drawVpn), 600); });
  }
  const stateTag = s => ({ active: '<span class="tag g">ενεργός</span>', idle: '<span class="tag y">αδρανής</span>', stale: '<span class="tag r">χαμένος</span>', never: '<span class="tag">ποτέ</span>' }[s] || '');

  // ───────────────────────── 🔐 DNS (Pi-hole + κρυπτογραφημένο) ─────────────────────────
  function drawDns() {
    const el = document.getElementById('t-dnsf'); if (!el) return;
    const df = T.data.dnsfilter, ed = T.data.encdns;
    let h = `<h3>🔐 DNS — φιλτράρισμα & κρυπτογράφηση${sim(df || ed)}</h3>`;
    if (df && !off(df)) {
      const pc = df.blocked_pct || 0;
      h += `<div class="card"><div class="brow"><b class="ctitle">${df.type === 'adguard' ? 'AdGuard Home' : 'Pi-hole'} <span class="sm" data-noi18n>${E(df.url || '')}</span> ${df.status === 'disabled' ? '<span class="tag r">φιλτράρισμα OFF</span>' : df.status === 'enabled' ? '<span class="tag g">ενεργό</span>' : ''}</b><span class="sm">${(df.queries_today || 0).toLocaleString('el-GR')} ερωτήματα σήμερα</span></div>
        <div class="dns-stat"><div><div class="dns-n" style="color:var(--red)">${pc.toFixed(1)}%</div><div class="sm">μπλοκαρίστηκαν</div></div><div><div class="dns-n">${(df.blocked_today || 0).toLocaleString('el-GR')}</div><div class="sm">φραγμένα σήμερα</div></div><div><div class="dns-n">${(df.domains_blocked || 0).toLocaleString('el-GR')}</div><div class="sm">domains στη λίστα</div></div>${df.avg_ms != null ? `<div><div class="dns-n">${df.avg_ms} ms</div><div class="sm">μέση απάντηση</div></div>` : ''}</div></div>`;
      if ((df.top_blocked || []).length) h += `<div class="g2"><div><h3>Πιο μπλοκαρισμένα</h3><div class="card"><table><tbody>${df.top_blocked.slice(0, 10).map(x => `<tr><td data-noi18n>${E(x.domain)}</td><td style="text-align:right">${x.count.toLocaleString('el-GR')}</td></tr>`).join('')}</tbody></table></div></div>
        <div><h3>Πιο ενεργές συσκευές</h3><div class="card"><table><tbody>${(df.top_clients || []).slice(0, 10).map(x => `<tr><td>${hn(x.client)}</td><td style="text-align:right">${(x.count || 0).toLocaleString('el-GR')}</td></tr>`).join('')}</tbody></table></div></div></div>`;
    } else if (df && off(df)) h += offCard('Pi-hole / AdGuard', 'Δεν έχει ρυθμιστεί. Στο <code>config.yaml</code>: <code>dns_filter: {type: pihole, url: "http://192.168.1.x", password: "…"}</code>.');
    // κρυπτογραφημένο DNS ανά συσκευή
    if (ed && !off(ed)) {
      const t = ed.totals || {};
      h += `<h3>🔎 Κρυπτογραφημένο DNS ανά συσκευή</h3><div class="card"><div class="sm" style="white-space:normal">Ποιες συσκευές στέλνουν DNS με <b>DoH/DoT</b> ή σε <b>ξένο</b> resolver — παρακάμπτοντας το Pi-hole/router σου. <span class="tag">DoH ${t.DoH || 0}</span> <span class="tag">DoT ${t.DoT || 0}</span> <span class="tag">DoQ ${t.DoQ || 0}</span> <span class="tag">DNS-ext ${t['DNS-ext'] || 0}</span></div>
        <table style="margin-top:6px"><thead><tr><th>Συσκευή</th><th>Μέθοδος</th><th>Πάροχος</th><th>Τελευταία</th></tr></thead><tbody>${(ed.devices || []).slice(0, 20).map(x => `<tr><td>${hn(x.ip)}</td><td>${Object.keys(x.methods || {}).map(m => `<span class="tag ${/ext/.test(m) ? 'r' : 'y'}">${E(m)}</span>`).join(' ')}</td><td class="sm" data-noi18n>${E(Object.keys(x.providers || {}).join(', '))}</td><td class="sm">${agoT(now() - x.last)}</td></tr>`).join('') || '<tr><td colspan="4" class="sm">καμία συσκευή δεν παρακάμπτει το DNS σου</td></tr>'}</tbody></table>
        ${ed.canary_note ? `<div class="sm" style="margin-top:6px;white-space:normal">👉 ${E(ed.canary_note)}</div>` : ''}</div>`;
    }
    el.innerHTML = h;
  }

  // ───────────────────────── 📹 Κάμερες ─────────────────────────
  function drawCams() {
    const el = document.getElementById('t-cams'); if (!el) return;
    const d = T.data.camexp;
    let h = `<h3>📹 Κάμερες — έλεγχος έκθεσης${sim(d)}</h3>`;
    h += `<div class="card"><div class="brow"><div class="sm" style="white-space:normal;min-width:0">Σαρώνει <b>μόνο το δικό σου δίκτυο</b> (ιδιωτικές IP) για κάμερες/DVR με ανοιχτό stream, UI χωρίς κωδικό, παλιό firmware ή P2P cloud — και λέει πώς να τα κλείσεις. <b>Δεν</b> δοκιμάζει κωδικούς, <b>δεν</b> επιτίθεται.</div><button class="b" id="cam-scan" ${d && d.scanning ? 'disabled' : ''}>${d && d.scanning ? '⏳ σάρωση…' : '🔍 Σάρωση τώρα'}</button></div>
      ${d && d.subnet ? `<div class="sm">δίκτυο: <span data-noi18n>${E(d.subnet)}</span>${d.last_scan ? ` · τελευταία ${agoT(now() - d.last_scan)}` : ''}</div>` : ''}</div>`;
    const V = { red: ['❌', 'var(--red)', 'Εκτεθειμένη'], orange: ['⚠️', 'var(--orange)', 'Προσοχή'], green: ['✅', 'var(--green)', 'Οκ'], unknown: ['⚪', 'var(--dim)', 'Δεν ελέγχθηκε'] };
    for (const c of (d && d.cameras || [])) {
      const v = V[c.verdict] || V.unknown;
      h += `<div class="card cam ${c.verdict}"><div class="brow"><b class="ctitle">${v[0]} ${hn(c.ip)} <span class="sm" data-noi18n>${E(c.vendor || 'κάμερα')}</span></b><span class="tag" style="background:color-mix(in srgb,${v[1]} 22%,transparent);color:${v[1]}">${v[2]}</span></div>
        <div class="cam-ports">${(c.ports || []).filter(p => p.open).map(p => `<span class="cp" title="${E(p.note || '')}">${p.port} <span class="sm">${E(p.label || '')}</span>${p.auth === false ? ' <b style="color:var(--redt)">χωρίς κωδικό!</b>' : p.auth ? ' 🔒' : ''}</span>`).join('') || '<span class="sm">καμία ανοιχτή θύρα</span>'}</div>
        ${(c.issues || []).length ? `<ul class="cam-iss">${c.issues.map(x => `<li>${E(x)}</li>`).join('')}</ul>` : ''}
        ${(c.fixes || []).length ? `<div class="sm" style="white-space:normal">👉 ${c.fixes.map(f => `<span>${E(f)}</span>`).join(' · ')}</div>` : ''}</div>`;
    }
    if (d && !(d.cameras || []).length && !d.scanning) h += `<div class="card sm">${d.demo === false ? 'Δεν βρέθηκαν κάμερες — πάτα «Σάρωση» για πλήρη έλεγχο.' : 'Καμία κάμερα.'}</div>`;
    if (d && (d.skipped_public || []).length) h += `<div class="sm" style="white-space:normal;color:var(--mid)">🛡 Παραλείφθηκαν ${d.skipped_public.length} δημόσιες IP — ο έλεγχος μένει αυστηρά στο δικό σου δίκτυο.</div>`;
    el.innerHTML = h;
    const b = el.querySelector('#cam-scan'); if (b) b.onclick = () => post('/api/camexp/scan', {}).then(() => { b.disabled = true; b.textContent = '⏳ σάρωση…'; setTimeout(() => { T.at.camexp = 0; load('camexp', '/api/camexp', 0, drawCams); }, 2500); });
  }

  // ───────────────────────── 📥 SIEM (Suricata / Zeek) ─────────────────────────
  function drawSiem() {
    const el = document.getElementById('t-siem'); if (!el) return;
    const d = T.data.logimport;
    let h = `<h3>📥 SIEM — Suricata & Zeek${sim(d)}</h3>`;
    h += `<div class="card"><div class="sm" style="white-space:normal">Φέρνει τις ειδοποιήσεις από <b>Suricata</b> (eve.json) και <b>Zeek</b> (notice/weird logs) μέσα στο NetWatch, στον ίδιο κατάλογο επιθέσεων. Ρύθμισε αρχεία στο <code>config.yaml</code> (<code>log_import</code>) ή ανέβασε ένα εδώ:</div>
      <label class="ex-drop" id="siem-drop" style="margin-top:8px"><input type="file" id="siem-in" accept=".json,.log,.txt" hidden>⬆ Ανέβασε eve.json ή Zeek log</label><div id="siem-msg" class="sm"></div></div>`;
    if (d && (d.files || []).length) h += `<div class="card"><table><thead><tr><th>Αρχείο</th><th>Τύπος</th><th>Γραμμές</th><th>Ειδοποιήσεις</th></tr></thead><tbody>${d.files.map(f => `<tr><td class="sm" data-noi18n>${E(f.path)}</td><td>${E(f.type)}</td><td>${f.lines || 0}</td><td>${f.alerts || 0}</td></tr>`).join('')}</tbody></table></div>`;
    if (d && (d.recent || []).length) h += `<h3>Πρόσφατα (${d.recent.length})</h3><div class="card"><table><thead><tr><th></th><th>Υπογραφή</th><th>Από → Προς</th><th></th></tr></thead><tbody>${d.recent.slice(0, 40).map(a => `<tr><td><span class="dot" style="background:${a.sev === 'high' ? 'var(--red)' : a.sev === 'med' ? 'var(--orange)' : 'var(--yellow)'}"></span></td><td><b data-noi18n>${E(a.signature)}</b><div class="sm">${E(a.category || a.log || '')}</div></td><td class="sm">${a.src ? hn(a.src) : ''}${a.dst ? ' → ' + hn(a.dst) : ''}</td><td class="sm">${agoT(now() - a.t)}</td></tr>`).join('')}</tbody></table></div>`;
    el.innerHTML = h;
    const inp = el.querySelector('#siem-in'), drop = el.querySelector('#siem-drop'), msg = el.querySelector('#siem-msg');
    const up = f => { if (!f) return; if (f.size > 20 * 1024 * 1024) { msg.textContent = 'Πολύ μεγάλο (όριο 20 MB).'; return; } msg.textContent = 'ανέβασμα…'; f.text().then(txt => fetch('/api/logimport/upload', { method: 'POST', body: txt }).then(r => r.json()).then(j => { msg.textContent = j.error ? j.error : `✓ ${j.total} ειδοποιήσεις (${E(j.kind)})`; T.at.logimport = 0; setTimeout(() => load('logimport', '/api/logimport', 0, drawSiem), 500); })); };
    if (inp) inp.onchange = () => up(inp.files[0]);
    if (drop) { drop.ondragover = e => { e.preventDefault(); drop.classList.add('on'); }; drop.ondragleave = () => drop.classList.remove('on'); drop.ondrop = e => { e.preventDefault(); drop.classList.remove('on'); up(e.dataTransfer.files[0]); }; }
  }

  // ───────────────────────── 🔏 Πιστοποιητικά (CT) ─────────────────────────
  function drawCt() {
    const el = document.getElementById('t-ct'); if (!el) return;
    const d = T.data.ctwatch;
    let h = `<h3>🔏 Πιστοποιητικά — Certificate Transparency${sim(d)}</h3>`;
    if (off(d)) return el.innerHTML = h + offCard('Παρακολούθηση domains', 'Γράψε τα δικά σου domains στο <code>config.yaml</code>: <code>ct_watch: {domains: ["to-site-sou.gr"]}</code>. Θα σε ειδοποιώ όταν εκδοθεί νέο πιστοποιητικό (crt.sh) — ειδικά αν δεν το περίμενες.');
    h += `<div class="card"><div class="sm" style="white-space:normal">Κάθε πιστοποιητικό TLS καταγράφεται δημόσια (Certificate Transparency). Αν κάποιος εκδώσει πιστοποιητικό για το domain σου (π.χ. phishing ή παραβίαση), θα φανεί εδώ. Πηγή: crt.sh.</div><button class="b" id="ct-check" style="margin-top:6px">↻ Έλεγχος τώρα</button></div>`;
    for (const dm of (d && d.domains || [])) {
      h += `<h3><span data-noi18n>${E(dm.domain)}</span> <span class="sm">${dm.total} πιστοποιητικά${dm.flagged ? ` · <span style="color:var(--orange)">${dm.flagged} προς έλεγχο</span>` : ''}</span></h3><div class="card"><table><thead><tr><th>Ονόματα</th><th>Εκδότης</th><th>Λήγει</th></tr></thead><tbody>${(dm.recent || []).slice(0, 15).map(c => `<tr class="${c.unexpected_issuer || c.new_names && c.new_names.length ? 'ct-flag' : ''}"><td data-noi18n>${E((c.names || []).join(', '))}${c.new ? ' <span class="tag y">νέο</span>' : ''}</td><td class="sm" data-noi18n>${E(c.issuer || '')}${c.unexpected_issuer ? ' <span class="tag r">απρόσμενος!</span>' : ''}</td><td class="sm">${E((c.not_after || '').slice(0, 10))} <a target="_blank" rel="noopener" href="${E(c.link)}">↗</a></td></tr>`).join('')}</tbody></table>
        ${(dm.subdomains || []).length ? `<div class="sm" style="margin-top:4px;white-space:normal">υποτομείς: <span data-noi18n>${E(dm.subdomains.join(', '))}</span></div>` : ''}</div>`;
    }
    el.innerHTML = h;
    const b = el.querySelector('#ct-check'); if (b) b.onclick = () => { b.textContent = '⏳…'; post('/api/ctwatch/check', {}).then(() => setTimeout(() => { T.at.ctwatch = 0; load('ctwatch', '/api/ctwatch', 0, drawCt); }, 3000)); };
  }

  // ───────────────────────── 📡 Τηλεμετρία & trackers ─────────────────────────
  // Ποια συσκευή «τηλεφωνάει» σε διαφημίσεις/analytics/τηλεμετρία — από τα ονόματα (SNI/DNS) που έμαθε το NetWatch.
  const TRACKERS = {
    'doubleclick.net': ['ads', 'Google Ads'], 'googlesyndication.com': ['ads', 'Google Ads'], 'googleadservices.com': ['ads', 'Google Ads'],
    'adservice.google.com': ['ads', 'Google Ads'], 'criteo.com': ['ads', 'Criteo'], 'criteo.net': ['ads', 'Criteo'], 'adnxs.com': ['ads', 'Xandr'],
    'taboola.com': ['ads', 'Taboola'], 'outbrain.com': ['ads', 'Outbrain'], 'rubiconproject.com': ['ads', 'Magnite'], 'pubmatic.com': ['ads', 'PubMatic'],
    'openx.net': ['ads', 'OpenX'], 'amazon-adsystem.com': ['ads', 'Amazon Ads'], 'ads.linkedin.com': ['ads', 'LinkedIn Ads'], 'bat.bing.com': ['ads', 'Microsoft Ads'],
    'ads-twitter.com': ['ads', 'X Ads'], 'moatads.com': ['ads', 'Oracle Moat'], 'casalemedia.com': ['ads', 'Index Exchange'],
    'google-analytics.com': ['analytics', 'Google Analytics'], 'googletagmanager.com': ['analytics', 'Google Tag Manager'], 'analytics.google.com': ['analytics', 'Google Analytics'],
    'app-measurement.com': ['analytics', 'Firebase'], 'connect.facebook.net': ['analytics', 'Meta Pixel'], 'graph.facebook.com': ['analytics', 'Meta SDK'],
    'analytics.tiktok.com': ['analytics', 'TikTok Pixel'], 'scorecardresearch.com': ['analytics', 'comScore'], 'hotjar.com': ['analytics', 'Hotjar'], 'hotjar.io': ['analytics', 'Hotjar'],
    'mixpanel.com': ['analytics', 'Mixpanel'], 'segment.io': ['analytics', 'Segment'], 'segment.com': ['analytics', 'Segment'], 'amplitude.com': ['analytics', 'Amplitude'],
    'clarity.ms': ['analytics', 'MS Clarity'], 'fullstory.com': ['analytics', 'FullStory'], 'mouseflow.com': ['analytics', 'Mouseflow'], 'quantserve.com': ['analytics', 'Quantcast'],
    'chartbeat.com': ['analytics', 'Chartbeat'], 'chartbeat.net': ['analytics', 'Chartbeat'], 'mc.yandex.ru': ['analytics', 'Yandex Metrica'], 'branch.io': ['analytics', 'Branch'],
    'adjust.com': ['analytics', 'Adjust'], 'appsflyer.com': ['analytics', 'AppsFlyer'], 'kochava.com': ['analytics', 'Kochava'], 'braze.com': ['analytics', 'Braze'],
    'optimizely.com': ['analytics', 'Optimizely'], 'heapanalytics.com': ['analytics', 'Heap'],
    'crashlytics.com': ['telemetry', 'Crashlytics'], 'sentry.io': ['telemetry', 'Sentry'], 'nr-data.net': ['telemetry', 'New Relic'], 'datadoghq.com': ['telemetry', 'Datadog'],
    'bugsnag.com': ['telemetry', 'Bugsnag'], 'vortex.data.microsoft.com': ['telemetry', 'MS telemetry'], 'events.data.microsoft.com': ['telemetry', 'MS telemetry'],
    'telemetry.mozilla.org': ['telemetry', 'Firefox telemetry'], 'xp.apple.com': ['telemetry', 'Apple analytics'], 'metrics.icloud.com': ['telemetry', 'Apple analytics'],
    'browser-intake-datadoghq.com': ['telemetry', 'Datadog'],
  };
  // Τι είναι κάθε tracker και τι στέλνει συνήθως (σύντομα, για τον χρήστη)
  const WHO = {
    'Google Ads': 'Διαφημιστικό δίκτυο της Google. Μετρά ποιες διαφημίσεις είδες/πάτησες και φτιάχνει προφίλ ενδιαφερόντων για στοχευμένες διαφημίσεις.',
    'Criteo': 'Retargeting: σε «ακολουθεί» με διαφημίσεις προϊόντων που κοίταξες σε e-shop.', 'Xandr': 'Πλατφόρμα δημοπρασίας διαφημίσεων (Microsoft). Η θέση της διαφήμισης «πουλιέται» σε χιλιοστά του δευτερολέπτου με βάση το προφίλ σου.',
    'Taboola': 'Τα «προτεινόμενα άρθρα» κάτω από ειδήσεις. Μετρά τι διαβάζεις.', 'Outbrain': 'Τα «προτεινόμενα άρθρα» κάτω από ειδήσεις. Μετρά τι διαβάζεις.',
    'Magnite': 'Δημοπρασία διαφημίσεων (ad exchange).', 'PubMatic': 'Δημοπρασία διαφημίσεων (ad exchange).', 'OpenX': 'Δημοπρασία διαφημίσεων (ad exchange).', 'Index Exchange': 'Δημοπρασία διαφημίσεων (ad exchange).',
    'Amazon Ads': 'Διαφημίσεις της Amazon, με βάση αγορές και αναζητήσεις.', 'LinkedIn Ads': 'Pixel του LinkedIn: λέει στο LinkedIn ποια sites επισκέφτηκες.', 'Microsoft Ads': 'Pixel του Bing Ads για μέτρηση μετατροπών (αγορών/εγγραφών).',
    'X Ads': 'Pixel του X (Twitter) για στοχευμένες διαφημίσεις.', 'Oracle Moat': 'Μετρά αν μια διαφήμιση «φάνηκε» στην οθόνη σου και για πόσο.',
    'Google Analytics': 'Στατιστικά επισκεψιμότητας: σελίδες, χρόνος, συσκευή, περίπου τοποθεσία. Το site βλέπει τι έκανες· η Google βλέπει σε ποια sites πας.',
    'Google Tag Manager': 'Φορτώνει άλλα scripts παρακολούθησης για λογαριασμό του site.', 'Firebase': 'Analytics της Google για εφαρμογές κινητού: ποιες οθόνες άνοιξες, πόσο, μοντέλο συσκευής.',
    'Meta Pixel': 'Pixel του Facebook/Instagram: λέει στη Meta ποια sites επισκέφτηκες και τι αγόρασες, ακόμα κι αν δεν έχεις λογαριασμό.', 'Meta SDK': 'SDK του Facebook μέσα σε εφαρμογές: στέλνει στη Meta ότι άνοιξες την εφαρμογή και τι έκανες.',
    'TikTok Pixel': 'Pixel του TikTok για διαφημίσεις και μετρήσεις αγορών.', 'comScore': 'Μέτρηση κοινού (ποιοι και πόσοι βλέπουν ένα site).', 'Hotjar': 'Καταγράφει κινήσεις ποντικιού, κλικ και κύλιση — «βίντεο» της επίσκεψής σου.',
    'Mixpanel': 'Analytics εφαρμογών: κάθε κουμπί που πατάς γίνεται «event».', 'Segment': 'Συλλέγει events και τα μοιράζει σε πολλά άλλα εργαλεία analytics.', 'Amplitude': 'Analytics εφαρμογών: πώς χρησιμοποιείς την app, βήμα-βήμα.',
    'MS Clarity': 'Καταγραφή συνεδρίας (κλικ, κύλιση, heatmaps) από τη Microsoft.', 'FullStory': 'Πλήρης καταγραφή συνεδρίας: ό,τι έκανες στη σελίδα.', 'Mouseflow': 'Καταγραφή κινήσεων ποντικιού και heatmaps.',
    'Quantcast': 'Μέτρηση κοινού και προφίλ για διαφημίσεις.', 'Chartbeat': 'Μετρά τι διαβάζουν οι αναγνώστες ειδησεογραφικών sites σε πραγματικό χρόνο.', 'Yandex Metrica': 'Analytics της Yandex (Ρωσία), με καταγραφή συνεδρίας.',
    'Branch': 'Deep links και μέτρηση «από ποια διαφήμιση ήρθε» η εγκατάσταση μιας app.', 'Adjust': 'Μετρά από ποια διαφήμιση εγκατέστησες μια app και πόσο τη χρησιμοποιείς.', 'AppsFlyer': 'Μετρά από ποια διαφήμιση εγκατέστησες μια app και πόσο τη χρησιμοποιείς.', 'Kochava': 'Μέτρηση εγκαταστάσεων εφαρμογών και διαφημίσεων.',
    'Braze': 'Ειδοποιήσεις push και marketing μέσα σε εφαρμογές.', 'Optimizely': 'A/B tests: σου δείχνει διαφορετική εκδοχή της σελίδας και μετρά τι κάνεις.', 'Heap': 'Αυτόματη καταγραφή κάθε κλικ σε σελίδες και εφαρμογές.',
    'Crashlytics': 'Αναφορές σφαλμάτων (crash) εφαρμογών της Google. Στέλνει μοντέλο συσκευής, έκδοση, τι έκανε η app πριν κολλήσει.', 'Sentry': 'Αναφορές σφαλμάτων λογισμικού προς τους προγραμματιστές.',
    'New Relic': 'Παρακολούθηση απόδοσης εφαρμογών (πόσο αργή είναι, σφάλματα).', 'Datadog': 'Υπηρεσία monitoring για προγραμματιστές: μια εφαρμογή ή site στέλνει μετρήσεις απόδοσης, logs και σφάλματα. Συνήθως όχι για διαφημίσεις — μάλλον κάποια app/site που χρησιμοποιείς.',
    'Bugsnag': 'Αναφορές σφαλμάτων εφαρμογών.', 'MS telemetry': 'Τηλεμετρία των Windows/Office: πληροφορίες για τη συσκευή, σφάλματα και χρήση.', 'Firefox telemetry': 'Στατιστικά χρήσης και σφαλμάτων του Firefox (απενεργοποιείται στις ρυθμίσεις).',
    'Apple analytics': 'Analytics και διαγνωστικά της Apple (απενεργοποιούνται στις Ρυθμίσεις → Απόρρητο → Ανάλυση).',
  };
  const CATX = { ads: 'Διαφημίσεις: φτιάχνουν προφίλ για να σου δείχνουν στοχευμένες διαφημίσεις.', analytics: 'Παρακολούθηση: μετρά τι κάνεις μέσα σε sites και εφαρμογές.', telemetry: 'Τηλεμετρία: διαγνωστικά, σφάλματα και στατιστικά χρήσης προς τον κατασκευαστή.' };
  const CAT = { ads: ['Διαφημίσεις', 'var(--red)', '📣'], analytics: ['Παρακολούθηση', 'var(--orange)', '👁'], telemetry: ['Τηλεμετρία', 'var(--purple)', '📊'] };
  function trackerFor(name) {
    if (!name) return null;
    const n = String(name).toLowerCase().replace(/\.$/, '');
    for (const dom in TRACKERS) if (n === dom || n.endsWith('.' + dom)) return { cat: TRACKERS[dom][0], who: TRACKERS[dom][1], domain: dom };
    return null;
  }
  function trackerData() {
    if (typeof S === 'undefined' || !S || !S.out) return { devices: [], cats: {}, whos: {}, total: 0 };
    const devices = [], cats = { ads: 0, analytics: 0, telemetry: 0 }, whos = {}; let total = 0;
    for (const [ip, m] of S.out) {
      const host = S.hosts.get(ip); if (!host || host.kind !== 'local') continue;
      const hits = {}; let dn = 0;
      for (const [dst, o] of m) {
        const dh = S.hosts.get(dst), nm = o.n || (dh && (window.hname ? hname(dh) : dh.name)) || (dh && dh.rdns);
        const tr = trackerFor(nm) || trackerFor(dst && dh && (dh.rdns));
        if (!tr) continue;
        cats[tr.cat] = (cats[tr.cat] || 0) + 1; total++; dn++;
        whos[tr.who] = whos[tr.who] || { cat: tr.cat, n: 0, devs: new Set() };
        whos[tr.who].n++; whos[tr.who].devs.add(ip);
        hits[tr.who] = hits[tr.who] || { cat: tr.cat, n: 0, c: [] }; hits[tr.who].n++;
        const c = { dev: ip, dst, name: nm || dst, o, geo: dh && dh.geo }; hits[tr.who].c.push(c);
        whos[tr.who].c = whos[tr.who].c || []; whos[tr.who].c.push(c);
      }
      if (dn) devices.push({ ip, name: host.name || (window.hname ? hname(host) : ip), hits, n: dn });
    }
    devices.sort((a, b) => b.n - a.n);
    return { devices, cats, whos, total };
  }
  function trackFlow(devices, cats) {
    const top = devices.slice(0, 6), order = ['ads', 'analytics', 'telemetry'].filter(c => cats[c] > 0);
    if (!top.length || !order.length) return '';
    const W = 520, rowH = 34, H = Math.max(top.length, order.length) * rowH + 16, nomo = document.documentElement.classList.contains('nomo');
    const lx = 150, rx = W - 150, ly = i => 20 + i * rowH + 10, ry = i => 20 + i * ((H - 30) / Math.max(1, order.length)) + 10;
    let paths = '', nodes = '', dots = '', pid = 0;
    top.forEach((d, i) => {
      nodes += `<text x="${lx - 14}" y="${ly(i) + 4}" text-anchor="end" class="tk-dev" data-noi18n>${E((d.name || d.ip).slice(0, 18))}</text><circle cx="${lx}" cy="${ly(i)}" r="4" class="tk-src"/>`;
      const dc = {}; for (const who in d.hits) dc[d.hits[who].cat] = (dc[d.hits[who].cat] || 0) + d.hits[who].n;
      for (const c in dc) {
        const j = order.indexOf(c); if (j < 0) continue;
        const id = 'tkp' + (pid++), y0 = ly(i), y1 = ry(j), d_ = `M${lx},${y0} C${(lx + rx) / 2},${y0} ${(lx + rx) / 2},${y1} ${rx},${y1}`;
        paths += `<path id="${id}" d="${d_}" class="tk-link" style="stroke:${CAT[c][1]};stroke-width:${Math.min(5, 1 + dc[c] * 0.6)}"/>`;
        if (!nomo) for (let k = 0; k < Math.min(3, Math.ceil(dc[c] / 2)); k++)
          dots += `<circle r="2.6" fill="${CAT[c][1]}"><animateMotion dur="${(1.6 + k * 0.5).toFixed(1)}s" repeatCount="indefinite" begin="${(k * 0.5).toFixed(1)}s"><mpath href="#${id}"/></animateMotion></circle>`;
      }
    });
    order.forEach((c, j) => {
      nodes += `<circle cx="${rx}" cy="${ry(j)}" r="6" style="fill:${CAT[c][1]}"/><text x="${rx + 12}" y="${ry(j) + 4}" class="tk-cat" style="fill:${CAT[c][1]}">${CAT[c][2]} ${E(CAT[c][0])} <tspan class="tk-n">${cats[c]}</tspan></text>`;
    });
    return `<svg viewBox="0 0 ${W} ${H}" class="tk-flow" preserveAspectRatio="xMidYMid meet">${paths}${dots}${nodes}</svg>`;
  }
  function drawTrackers() {
    const el = document.getElementById('t-trk'); if (!el) return;
    const T2 = trackerData(), df = T2d.dnsfilter;
    let h = `<h3>📡 Τηλεμετρία & trackers</h3><div class="card"><div class="sm" style="white-space:normal">Ποια συσκευή του δικτύου σου «τηλεφωνάει» σε <b style="color:var(--red)">διαφημίσεις</b>, <b style="color:var(--orange)">analytics</b> και <b style="color:var(--purple)">τηλεμετρία</b> — από τα ονόματα (SNI/DNS) που βλέπει το NetWatch, όσο είναι ανοιχτή η σελίδα. Παθητικό, δεν μπλοκάρει· για φράξιμο, δες το Pi-hole/AdGuard στην καρτέλα 🔐 DNS.</div></div>`;
    if (df && !off(df)) {
      const pc = df.blocked_pct || 0;
      h += `<div class="card tk-ph"><b style="color:var(--hi)">🛡 ${df.type === 'adguard' ? 'AdGuard' : 'Pi-hole'} μπλοκάρει ήδη</b> <span class="sm">${(df.blocked_today || 0).toLocaleString('el-GR')} από ${(df.queries_today || 0).toLocaleString('el-GR')} ερωτήματα σήμερα</span><div class="tk-phbar"><i style="width:${Math.min(100, pc)}%"></i></div><div class="sm">${pc.toFixed(1)}% της κίνησης DNS φράχτηκε πριν καν φύγει.</div></div>`;
    }
    if (!T2.total) { el.innerHTML = h + '<div class="card sm">Δεν έχω δει ακόμα επικοινωνία με γνωστούς trackers σε αυτή τη συνεδρία. Άσε τη σελίδα ανοιχτή ή περιηγήσου λίγο.</div>'; return; }
    h += `<div class="dns-stat"><div><div class="dns-n" style="color:var(--red)">${T2.cats.ads || 0}</div><div class="sm">📣 διαφημίσεις</div></div><div><div class="dns-n" style="color:var(--orange)">${T2.cats.analytics || 0}</div><div class="sm">👁 παρακολούθηση</div></div><div><div class="dns-n" style="color:var(--purple)">${T2.cats.telemetry || 0}</div><div class="sm">📊 τηλεμετρία</div></div><div><div class="dns-n">${T2.devices.length}</div><div class="sm">συσκευές</div></div></div>`;
    const flow = trackFlow(T2.devices, T2.cats);
    if (flow) h += `<div class="card"><div class="sm" style="margin-bottom:4px">Ροή: συσκευή → είδος tracker ${document.documentElement.classList.contains('nomo') ? '' : '(τα σημαδάκια είναι η κίνηση που φεύγει)'}</div>${flow}</div>`;
    h += `<h3>Ανά συσκευή</h3><div class="sm" style="margin:-4px 0 8px">Πάτα ένα tracker για να δεις κάθε επαφή: ποιο domain, πότε, πόσα δεδομένα — και τι είναι.</div>` + T2.devices.map(d => `<div class="card"><b class="ctitle">${hn(d.ip)}</b> <span class="sm">${d.n} επαφές με trackers</span><div class="tk-dl">${Object.entries(d.hits).sort((a, b) => b[1].n - a[1].n).map(([who, x]) => tkDet(d.ip + '|' + who, who, x.cat, x.c, false)).join('')}</div></div>`).join('');
    const whos = Object.entries(T2.whos).sort((a, b) => b[1].n - a[1].n).slice(0, 12);
    if (whos.length) h += `<h3>Κορυφαίοι trackers</h3><div class="card tk-dl">${whos.map(([who, x]) => tkDet('*|' + who, who, x.cat, x.c || [], true, x.devs.size)).join('')}</div>`;
    el.innerHTML = h;
    el.querySelectorAll('details.tk-d').forEach(dt => dt.addEventListener('toggle', () => { dt.open ? TKOPEN.add(dt.dataset.k) : TKOPEN.delete(dt.dataset.k); }));
  }
  // ανοιχτές λεπτομέρειες: μένουν ανοιχτές όταν ξαναζωγραφίζεται η καρτέλα
  const TKOPEN = new Set();
  const tkAgo = t => { const s = Date.now() / 1000 - t; return s < 60 ? Math.round(s) + '″' : s < 3600 ? Math.round(s / 60) + '′' : Math.round(s / 3600) + (window.I18N && I18N.lang === 'en' ? 'h' : 'ω'); };
  const tkB = b => b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(1) + ' MB';
  function tkDet(key, who, cat, cs, multi, ndev) {
    const col = CAT[cat][1], rows = cs.slice().sort((a, b) => (b.o.last || 0) - (a.o.last || 0));
    const doms = [...new Set(rows.map(c => c.name))];
    return `<details class="tk-d" data-k="${E(key)}"${TKOPEN.has(key) ? ' open' : ''} style="--c:${col}"><summary><span class="tk-chip" data-noi18n>${E(who)} <b>${cs.length}</b></span>
      <span class="tag" style="color:${col}">${CAT[cat][2]} ${E(CAT[cat][0])}</span>${multi ? ` <span class="sm">${ndev} ${ndev === 1 ? 'συσκευή' : 'συσκευές'}</span>` : ''} <span class="sm tk-dm" data-noi18n>${E(doms.slice(0, 2).join(', '))}${doms.length > 2 ? ' +' + (doms.length - 2) : ''}</span></summary>
      <div class="tk-body"><div class="tk-what">ℹ️ <span>${E(WHO[who] || CATX[cat])}</span></div>
      <table class="tk-ct"><thead><tr>${multi ? '<th>Συσκευή</th>' : ''}<th>Domain</th><th>IP</th><th>Θύρα</th><th>Πακέτα</th><th>Δεδομένα</th><th>Πρώτη φορά</th><th>Τελευταία</th></tr></thead><tbody>${rows.map(c => `<tr>${multi ? `<td data-noi18n>${hn(c.dev)}</td>` : ''}<td data-noi18n><b>${E(c.name)}</b></td>
        <td data-noi18n>${E(c.dst)}${c.geo && c.geo.countryCode ? ` <span title="${E(c.geo.country || '')}">${c.geo.countryCode.toUpperCase().replace(/./g, ch => String.fromCodePoint(127397 + ch.charCodeAt(0)))}</span>` : ''}</td>
        <td data-noi18n>${[...(c.o.ports || [])].join(', ') || '—'}${c.o.p ? ` <span class="sm">${E(c.o.p)}</span>` : ''}</td><td>${c.o.pk || 0}</td><td>${tkB(c.o.b || 0)}</td>
        <td>πριν ${tkAgo(c.o.first || 0)}</td><td>πριν ${tkAgo(c.o.last || c.o.first || 0)}</td></tr>`).join('')}</tbody></table></div></details>`;
  }


  // ───────────────────────── 🧱 Τείχος IoT (micro-segmentation) ─────────────────────────
  const FW = { sel: null, fmt: 'openwrt', lan: false, rules: {}, open: new Set() };
  const MODE = { learn: ['🎓', 'Μαθαίνει', 'var(--cyan)'], watch: ['👁', 'Φυλάει', 'var(--green)'], off: ['⏸', 'Ανενεργό', 'var(--dim)'] };
  const flagOf = cc => cc && cc.length === 2 ? cc.toUpperCase().replace(/./g, ch => String.fromCodePoint(127397 + ch.charCodeAt(0))) : '';
  const SEVC = { low: 'var(--yellow,#e3b341)', med: 'var(--orange)', high: 'var(--red)' };
  const HINTC = { bad: 'var(--red)', warn: 'var(--orange)', info: 'var(--cyan)', ok: 'var(--green)' };
  const pp = x => x.port == null ? E(x.proto || 'ICMP') : `${E(x.proto)}/${x.port}`;
  function fwRulesKey() { return `${FW.sel}|${FW.fmt}|${FW.lan ? 1 : 0}`; }
  function fwLoadRules(force) {
    const k = fwRulesKey(); if (!FW.sel || (FW.rules[k] && !force)) return;
    FW.rules[k] = { loading: 1 };
    fetch(`/api/iotfw/rules?dev=${encodeURIComponent(FW.sel)}&fmt=${FW.fmt}${FW.lan ? '&lan=1' : ''}`).then(r => r.json()).then(j => { FW.rules[k] = j; if (typeof tab !== 'undefined' && tab === 'iotfw') drawFw(); }).catch(() => { FW.rules[k] = { error: 'σφάλμα δικτύου' }; });
  }
  function fwPost(url, body) {
    return post0(url, body).then(j => { T.at.iotfw = 0; Object.keys(FW.rules).forEach(k => { if (k.startsWith(body.dev + '|')) delete FW.rules[k]; }); window.renderIotfw(); return j; });
  }
  function destRow(x, pend, dev) {
    const nm = x.domain ? `<b>${E(x.name)}</b>${x.names && x.names.length ? `<div class="sm">${E(x.names.slice(0, 3).join(', '))}${x.names.length > 3 ? ' +' + (x.names.length - 3) : ''}</div>` : ''}` : `<b>${E(x.name)}</b>`;
    return `<tr${pend ? ' class="fw-pend"' : ''}><td data-noi18n>${nm}</td><td data-noi18n class="sm">${E((x.ips || []).slice(0, 3).join(', '))}${(x.ips || []).length > 3 ? ' +' + (x.ips.length - 3) : ''}</td>
      <td data-noi18n>${pp(x)}</td><td>${x.cc ? `<span title="${E(x.country || '')}">${flagOf(x.cc)}</span> <span class="sm" data-noi18n>${E(x.cc)}</span>` : '—'}${x.intel ? ' <span class="tag r">intel</span>' : ''}</td>
      <td>${x.pkts || 0}</td><td>${agoT(now() - (x.last || x.first || now()))}</td>${pend ? `<td><button class="b" data-fwacc="${E(x.key)}" data-dev="${E(dev)}">✓ Αποδοχή</button></td>` : ''}</tr>`;
  }
  function drawFw() {
    const el = document.getElementById('t-iotfw'), d = T.data.iotfw;
    if (!el) return;
    if (off(d)) return el.innerHTML = offCard('🧱 Τείχος IoT', 'Το module είναι κλειστό. Στο <code>config.yaml</code>: <code>iot_firewall: {enabled: true}</code>.');
    let h = `<h3>🧱 Τείχος IoT — κάθε συσκευή μιλά μόνο με όσους πρέπει${sim(d)}</h3>`;
    if (!d) return el.innerHTML = h + '<div class="card sm">φόρτωση…</div>';
    const devs = d.devices || [], t = d.totals || {};
    if (!FW.sel || !devs.some(x => x.key === FW.sel)) FW.sel = (devs.find(x => x.iot) || devs[0] || {}).key || null;
    h += `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">Micro-segmentation για το σπίτι</b><span class="fw-tot">
        <span class="tag">${t.devices || 0} συσκευές</span> <span class="tag" style="color:var(--cyan)">🎓 ${t.learning || 0} μαθαίνουν</span> <span class="tag g">👁 ${t.watching || 0} φυλάνε</span>
        ${t.pending ? `<span class="tag r">⚠ ${t.pending} νέοι προορισμοί</span>` : ''}</span></div>
      <div class="sm" style="margin-top:6px">Μια κάμερα ή μια πρίζα μιλά πάντα με τους ίδιους 2–3 servers. Το NetWatch <b>μαθαίνει</b> αυτό το «προφίλ» (${d.learn_hours < 1 ? Math.round(d.learn_hours * 60) + ' λεπτά' : d.learn_hours + ' ώρες'}), μετά <b>φυλάει</b>: ό,τι καινούργιο → ειδοποίηση. Και σου φτιάχνει έτοιμους κανόνες τείχους για τον router σου (OpenWrt, pfSense, MikroTik, iptables).</div>
      <div class="sm" style="margin-top:4px;color:var(--dim)">ℹ️ <span>${E(d.note || '')}</span></div></div>`;
    h += `<div class="fw-grid"><div class="fw-list">${devs.map(x => {
      const m = MODE[x.mode] || MODE.off, lp = x.learning || {};
      return `<button class="fw-dev${x.key === FW.sel ? ' on' : ''}" data-fwdev="${E(x.key)}"><span class="fw-ic">${x.icon || '📟'}</span><span class="fw-dn"><b data-noi18n>${E(x.name || x.ip)}</b><span class="sm" data-noi18n>${E(x.ip)}${x.vendor ? ' · ' + E(x.vendor) : ''}</span>
        ${x.mode === 'learn' ? `<span class="fw-bar"><i style="width:${lp.pct || 0}%"></i></span>` : ''}</span>
        <span class="fw-m" style="color:${m[2]}">${m[0]}${x.counts && x.counts.pending ? ` <b class="fw-pc">${x.counts.pending}</b>` : ''}</span></button>`;
    }).join('') || '<div class="sm">Δεν υπάρχουν συσκευές ακόμη.</div>'}</div>`;
    const x = devs.find(v => v.key === FW.sel);
    if (x) {
      const m = MODE[x.mode] || MODE.off, lp = x.learning || {}, c = x.counts || {};
      h += `<div class="fw-det"><div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">${x.icon || '📟'} <span data-noi18n>${E(x.name || x.ip)}</span> <span class="tag">${E(x.kind_label || x.kind || '')}</span></b>
          <span class="fw-modes">${['learn', 'watch', 'off'].map(k => `<button class="b${x.mode === k ? ' on' : ''}" data-fwmode="${k}">${MODE[k][0]} ${MODE[k][1]}</button>`).join('')}<button class="b" data-fwreset title="σβήνει ό,τι έμαθε και ξεκινά από την αρχή">↺</button></span></div>
        <div class="sm" data-noi18n style="margin-top:2px">${E(x.ip)}${x.mac && x.mac !== x.ip ? ' · ' + E(x.mac) : ''}${x.vendor ? ' · ' + E(x.vendor) : ''}</div>
        ${x.mode === 'learn' ? `<div class="fw-lrn"><span class="fw-bar big"><i style="width:${lp.pct || 0}%"></i></span><span class="sm">🎓 ${lp.pct || 0}% · ${lp.left_s ? 'απομένουν ' + ago(lp.left_s) : 'σε λίγο τελειώνει'}${x.iot && d.auto_watch ? ' · μετά περνά αυτόματα σε «Φυλάει»' : ''}</span></div>` :
          x.mode === 'watch' ? `<div class="sm" style="margin-top:8px;color:var(--green)">👁 <span>Φυλάει: κάθε προορισμός εκτός προφίλ βγάζει ειδοποίηση.</span></div>` : `<div class="sm" style="margin-top:8px">⏸ <span>Δεν παρακολουθείται (π.χ. router ή αυτός ο υπολογιστής).</span></div>`}
        <div class="fw-kpi"><div><b>${c.dests || 0}</b><span>προορισμοί</span></div><div><b>${c.ips || 0}</b><span>IP</span></div><div><b>${c.countries || 0}</b><span>χώρες</span></div><div><b>${c.lan_peers || 0}</b><span>στο LAN</span></div><div${c.pending ? ' class="bad"' : ''}><b>${c.pending || 0}</b><span>νέοι</span></div></div>
        ${(x.countries || []).length ? `<div class="sm" style="margin-top:6px">Χώρες: <span data-noi18n>${x.countries.map(cc => flagOf(cc) + ' ' + E(cc)).join('  ')}</span></div>` : ''}
        ${(x.hints || []).map(hh => `<div class="fw-hint" style="--c:${HINTC[hh.level] || 'var(--cyan)'}">${hh.level === 'bad' ? '⛔' : hh.level === 'warn' ? '⚠️' : hh.level === 'ok' ? '✅' : 'ℹ️'} <span>${E(hh.text)}</span></div>`).join('')}</div>`;
      if ((x.pending || []).length) h += `<div class="card fw-pcard"><div class="brow"><b class="ctitle" style="color:var(--red)">⚠ Νέοι προορισμοί εκτός προφίλ</b><button class="b" data-fwacc="*" data-dev="${E(x.key)}">✓ Αποδοχή όλων</button></div>
        <div class="sm" style="white-space:normal">Αν τους αναγνωρίζεις (π.χ. αναβάθμιση firmware), πάτα «Αποδοχή» και μπαίνουν στο προφίλ και στους κανόνες. Αλλιώς ψάξε το: μια κάμερα που ξαφνικά μιλά με άγνωστη χώρα σε περίεργη θύρα είναι κλασικό σημάδι botnet.</div>
        <table class="fw-t"><thead><tr><th>Προορισμός</th><th>IP</th><th>Θύρα</th><th>Χώρα</th><th>Πακέτα</th><th>Τελευταία</th><th></th></tr></thead><tbody>${x.pending.map(v => destRow(v, 1, x.key)).join('')}</tbody></table></div>`;
      if ((x.violations || []).length) h += `<div class="card"><b class="ctitle">🚨 Παραβιάσεις</b>${x.violations.map(v => `<div class="fw-v"><span class="tag" style="color:${SEVC[v.sev] || 'var(--orange)'}">${E(v.sev)}</span> <b data-noi18n>${E(v.name)}</b> <span class="sm" data-noi18n>${pp(v)} ${flagOf(v.cc)}</span> <span class="sm">${agoT(now() - v.t)}</span>${(v.reasons || []).map(r => `<span class="fw-r">${E(r)}</span>`).join('')}${v.alerted === false ? ' <span class="sm">(χωρίς ειδοποίηση — όριο)</span>' : ''}</div>`).join('')}</div>`;
      h += `<div class="card"><b class="ctitle">✅ Προφίλ: με ποιους μιλά κανονικά</b>${(x.dests || []).length ? `<table class="fw-t"><thead><tr><th>Προορισμός</th><th>IP</th><th>Θύρα</th><th>Χώρα</th><th>Πακέτα</th><th>Τελευταία</th></tr></thead><tbody>${x.dests.map(v => destRow(v, 0, x.key)).join('')}</tbody></table>` : '<div class="sm">Δεν έχει μιλήσει ακόμη με κανέναν στο internet.</div>'}
        ${(x.lan || []).length ? `<div class="sm" style="margin-top:8px"><b>Στο τοπικό δίκτυο:</b> <span data-noi18n>${x.lan.map(l => `${E(l.ip)} ${pp(l)}${l.gw ? ' (router)' : l.me ? ' (εσύ)' : ''}`).join(' · ')}</span></div>` : ''}
        ${x.dns ? `<div class="sm" style="margin-top:4px"><b>DNS:</b> <span>μέσω router ${x.dns.gateway || 0}</span>${x.dns.lan ? ` · <span>τοπικό ${x.dns.lan}</span>` : ''}${(x.dns.external || []).map(e => ` · <span style="color:var(--orange)" data-noi18n>${E(e.ip)}${e.provider ? ' ' + E(e.provider) : ''} ×${e.n}</span>`).join('')}</div>` : ''}</div>`;
      fwLoadRules(); const R = FW.rules[fwRulesKey()] || {};
      h += `<div class="card"><div class="brow"><b class="ctitle">🧱 Κανόνες για τον router σου</b><span class="fw-fmts">${(d.formats || []).map(f => `<button class="b${FW.fmt === f.id ? ' on' : ''}" data-fwfmt="${f.id}">${E(f.label)}</button>`).join('')}</span></div>
        <label class="sm fw-lanc"><input type="checkbox" data-fwlan ${FW.lan ? 'checked' : ''}> <span>Κόψε και την επικοινωνία με άλλες συσκευές του LAN (εκτός από όσες έμαθε)</span></label>
        <div class="sm" style="white-space:normal;margin:4px 0 8px">Επιτρέπει μόνο τις IP του προφίλ + DNS προς τον router, και κόβει ό,τι άλλο πάει στο internet. Βάλε πρώτα <b>σταθερή IP (DHCP reservation)</b> στη συσκευή. Το NetWatch ΔΕΝ αγγίζει τον router — αντιγράφεις και επικολλάς εσύ.</div>
        ${R.loading ? '<div class="sm">φτιάχνω κανόνες…</div>' : R.error ? `<div class="sm" style="color:var(--red)">${E(R.error)}</div>` : R.text ? `<div class="fw-rh"><span class="sm" data-noi18n>📄 ${E(R.filename || '')}</span><span><button class="b" data-fwcopy>📋 Αντιγραφή</button> <button class="b" data-fwdl>⬇ Λήψη</button></span></div><pre class="fw-code" data-noi18n>${E(R.text)}</pre>` : ''}</div>`;
      h += '</div>';
    }
    h += '</div>';
    if ((d.recent_violations || []).length) h += `<div class="card"><b class="ctitle">🕓 Πρόσφατες παραβιάσεις (όλες οι συσκευές)</b>${d.recent_violations.slice(0, 12).map(v => `<div class="fw-v"><span class="tag" style="color:${SEVC[v.sev] || 'var(--orange)'}">${E(v.sev)}</span> <b data-noi18n>${E(v.dev_name || v.dev_ip)}</b> → <span data-noi18n>${E(v.name)} ${pp(v)} ${flagOf(v.cc)}</span> <span class="sm">${agoT(now() - v.t)}</span></div>`).join('')}</div>`;
    const sy = window.scrollY; el.innerHTML = h; if (Math.abs(window.scrollY - sy) > 2) window.scrollTo(0, sy);
    el.querySelectorAll('[data-fwdev]').forEach(b => b.onclick = () => { FW.sel = b.dataset.fwdev; drawFw(); });
    el.querySelectorAll('[data-fwmode]').forEach(b => b.onclick = () => fwPost('/api/iotfw/mode', { dev: FW.sel, mode: b.dataset.fwmode }));
    const rs = el.querySelector('[data-fwreset]'); if (rs) rs.onclick = () => { if (confirm(EN() ? 'Forget the learned profile and start learning again?' : 'Να ξεχάσει το προφίλ και να ξαναρχίσει να μαθαίνει;')) fwPost('/api/iotfw/reset', { dev: FW.sel }); };
    el.querySelectorAll('[data-fwacc]').forEach(b => b.onclick = () => fwPost('/api/iotfw/accept', { dev: b.dataset.dev, dest: b.dataset.fwacc }));
    el.querySelectorAll('[data-fwfmt]').forEach(b => b.onclick = () => { FW.fmt = b.dataset.fwfmt; drawFw(); });
    const lc = el.querySelector('[data-fwlan]'); if (lc) lc.onchange = () => { FW.lan = lc.checked; drawFw(); };
    const R = FW.rules[fwRulesKey()] || {};
    const cp = el.querySelector('[data-fwcopy]'); if (cp) cp.onclick = () => navigator.clipboard.writeText(R.text || '').then(() => { cp.textContent = '✓'; setTimeout(() => cp.textContent = '📋 ' + (EN() ? 'Copy' : 'Αντιγραφή'), 1200); });
    const dl = el.querySelector('[data-fwdl]'); if (dl) dl.onclick = () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([R.text || ''], { type: 'text/plain' })); a.download = R.filename || 'netwatch-iot.rules'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000); };
  }
  window.renderIotfw = () => load('iotfw', '/api/iotfw', 6, drawFw);

  window.renderTrackers = () => { if (now() - (T.at.tph || 0) > 15) { T.at.tph = now(); fetch('/api/dnsfilter').then(r => r.json()).then(j => { T2d.dnsfilter = j; if (typeof tab !== 'undefined' && tab === 'trk') drawTrackers(); }).catch(() => { }); } drawTrackers(); };
  window.renderTor = () => load('tor', '/api/tor', 5, drawTor);
  window.renderVpnm = () => { load('vpnguard', '/api/vpnguard', 5, drawVpn); load('vpn', '/api/vpn', 8, drawVpn); };
  window.renderDnsf = () => { load('dnsfilter', '/api/dnsfilter', 15, drawDns); load('encdns', '/api/encdns', 8, drawDns); };
  window.renderCams = () => load('camexp', '/api/camexp', 20, drawCams);
  window.renderSiem = () => load('logimport', '/api/logimport', 6, drawSiem);
  window.renderCt = () => load('ctwatch', '/api/ctwatch', 30, drawCt);
})();
