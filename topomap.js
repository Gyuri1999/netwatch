// ───────────────────────── 🗺 Διάγραμμα δικτύου (ένα κουμπί → σχέδιο + «πού είναι η βλάβη») ─────────────────────────
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const LT = x => x && typeof x === 'object' ? (EN() ? x.en : x.el) || x.el || x.en || '' : String(x == null ? '' : x);
  const TM = { d: null, msg: null, zoom: 1, sel: null, busy: false, fault: '' };
  const BW = 176, BH = 60, GAP = 26, ROW = 104, PW = 270, RH = 22, PAD = 30;
  const ICON = { internet: '☁️', dns: '🔤', isp: '🏢', modem: '📟', router: '🛜', switch: '🔀', ap: '📶', host: '💻', me: '🧑‍💻', more: '➕' };
  const ST = {
    ok: ['--green', 'απαντά', 'answers'], slow: ['--yellow', 'αργό / απώλειες', 'slow / loss'], down: ['--red', 'ΔΕΝ απαντά', 'NOT answering'],
    quiet: ['--cyan', 'σιωπηλό (κόβει το ping, η κίνηση περνά)', 'quiet (drops ping, traffic passes)'],
    unreach: ['--dim', 'πίσω από τη βλάβη (άγνωστο)', 'behind the fault (unknown)'], idle: ['--dim', 'δεν φάνηκε τελευταία', 'not seen lately'],
    unknown: ['--dim', 'άγνωστο', 'unknown'],
  };
  const FAULTS = [['', '✅ Κανονικά', '✅ Normal'], ['switch', '🔀 Πέφτει switch', '🔀 Switch down'], ['modem', '📟 Πέφτει modem', '📟 Modem down'],
    ['isp', '🏢 Πέφτει πάροχος', '🏢 ISP down'], ['dns', '🔤 Χαλάει DNS', '🔤 DNS broken'], ['slow', '🐢 Αργός πάροχος', '🐢 Slow ISP']];

  const css = document.createElement('style');
  css.textContent = `
#t-topo .tp-bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
#t-topo .tp-go{border-color:var(--green);color:var(--green);font-weight:600}
#t-topo .tp-chips{display:flex;gap:5px;flex-wrap:wrap;margin-top:10px;align-items:center;font-size:12px}
#t-topo .tp-chip{border:1px solid var(--line);border-radius:14px;padding:3px 10px;cursor:pointer;background:none;color:var(--txt);font:inherit}
#t-topo .tp-chip.on{border-color:var(--purple);background:color-mix(in srgb,var(--purple) 14%,transparent)}
#t-topo .tp-diag{border-left:4px solid var(--c);display:flex;gap:14px;align-items:flex-start}
#t-topo .tp-dico{font-size:30px;line-height:1}
#t-topo .tp-diag h3{margin:0 0 4px;font-size:16px}
#t-topo .tp-diag ol{margin:8px 0 0;padding-left:20px;font-size:13px;line-height:1.6}
#t-topo .tp-iss{margin:8px 0 0;padding:0;list-style:none;font-size:12.5px}#t-topo .tp-iss li{padding:3px 0 3px 8px;border-left:3px solid var(--c);margin-top:3px;cursor:pointer}
#t-topo .tp-wrap{position:relative;overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--bg);max-height:76vh;margin-top:10px}
#t-topo .tp-wrap svg{display:block;transform-origin:0 0}
#t-topo .tp-wrap svg .nd{cursor:pointer}
#t-topo .tp-wrap svg .nd:hover rect.box{stroke-width:2.5}
#t-topo .tp-leg{display:flex;gap:12px;flex-wrap:wrap;font-size:11.5px;color:var(--dim);margin-top:8px}
#t-topo .tp-leg i{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:4px;vertical-align:-1px;border:2px solid var(--c)}
#t-topo .tp-pop{position:absolute;z-index:3;min-width:220px;max-width:300px;background:var(--panel,#111a);backdrop-filter:blur(12px);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:12.5px;box-shadow:0 8px 30px rgb(0 0 0 / 35%)}
#t-topo .tp-pop .kv{display:grid;grid-template-columns:70px 1fr;gap:3px 8px;margin:6px 0}
#t-topo .tp-pop .kv span:nth-child(odd){color:var(--dim)}
#t-topo .tp-pop .b{margin:4px 4px 0 0;font-size:12px;padding:3px 8px}
@keyframes tpPulse{0%{stroke-opacity:.9;stroke-width:3}100%{stroke-opacity:0;stroke-width:16}}
#t-topo .tp-pulse{animation:tpPulse 1.3s ease-out infinite}
`;
  document.head.appendChild(css);

  const box = () => document.getElementById('t-topo');
  const isDark = () => { const m = (getComputedStyle(document.body).color || '').match(/\d+/g); return !m || (+m[0] + +m[1] + +m[2]) / 3 > 128; };
  const col = v => (getComputedStyle(document.documentElement).getPropertyValue(v) || '').trim() || '#888';

  function load(force) {
    fetch('/api/topomap').then(r => r.json()).then(j => {
      TM.d = j; if (j.fault != null && !TM.busy) TM.fault = j.fault || '';
      draw(); if (j.running) setTimeout(() => load(true), 1000);
    }).catch(e => { TM.msg = String(e); draw(); });
  }
  function run() {
    if (TM.busy) return;
    TM.busy = true; TM.msg = null; draw();
    fetch('/api/topomap/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ fault: TM.fault || null }) })
      .then(r => r.json()).then(j => { TM.busy = false; if (j.error) TM.msg = j.error; load(true); })
      .catch(e => { TM.busy = false; TM.msg = String(e); draw(); });
  }

  // ── διάταξη (δέντρο από πάνω προς τα κάτω, συσκευές ως «πάνελ θυρών» κάτω από κάθε switch) ──
  function layout(g) {
    const N = {}; g.nodes.forEach(n => { N[n.id] = Object.assign({}, n, { kids: [], hosts: [] }); });
    g.nodes.forEach(n => {
      const p = N[n.parent]; if (!p || n.id === 'dns') return;
      (['host', 'me', 'more'].includes(n.kind) ? p.hosts : p.kids).push(N[n.id]);
    });
    const up = []; let c = N.router;
    while (c && c.parent && N[c.parent]) { c = N[c.parent]; up.unshift(c); }   // internet … modem
    const order = n => n.kind === 'ap' ? 1 : 0;
    const measure = n => {
      n.kids.sort((a, b) => order(a) - order(b));
      n.hosts.sort((a, b) => (b.kind === 'me') - (a.kind === 'me') || String(a.port).localeCompare(String(b.port), undefined, { numeric: true }));
      n.kids.forEach(measure);
      const parts = n.kids.map(k => k.w).concat(n.hosts.length ? [PW] : []);
      const sum = parts.reduce((a, b) => a + b, 0) + GAP * Math.max(0, parts.length - 1);
      n.w = Math.max(BW, sum);
      const ph = n.hosts.length ? 30 + n.hosts.length * RH : 0;
      n.h = BH + (parts.length ? ROW - BH + Math.max(ph, ...n.kids.map(k => k.h), 0) : 0);
    };
    measure(N.router);
    const W = Math.max(N.router.w, BW * 2 + GAP * 2) + PAD * 2;
    const cx = PAD + (W - PAD * 2) / 2;
    let y = PAD;
    up.forEach(n => { n.x = cx - BW / 2; n.y = y; y += ROW; });
    if (N.dns && N.internet) { N.dns.x = N.internet.x + BW + 70; N.dns.y = N.internet.y; }
    const place = (n, x0, y0) => {
      n.x = x0 + n.w / 2 - BW / 2; n.y = y0;
      const parts = (n.hosts.length ? [{ panel: true, w: PW }] : []).concat(n.kids);
      const sum = parts.reduce((a, p) => a + p.w, 0) + GAP * Math.max(0, parts.length - 1);
      let x = x0 + (n.w - sum) / 2;
      parts.forEach(p => {
        if (p.panel) { n.panel = { x, y: y0 + ROW, w: PW, h: 30 + n.hosts.length * RH }; n.hosts.forEach((h, i) => { h.x = x; h.y = y0 + ROW + 30 + i * RH; h.inPanel = true; }); }
        else place(p, x, y0 + ROW);
        x += p.w + GAP;
      });
    };
    place(N.router, cx - N.router.w / 2, y);
    const H = y + N.router.h + PAD + 10;
    return { N, up, W: Math.max(W, (N.dns ? N.dns.x + BW + PAD : 0)), H };
  }

  function svgOf(d, opt) {
    opt = opt || {};
    const g = d.graph, diag = d.diag || {}, L = layout(g), N = L.N;
    const dark = opt.light ? false : isDark();
    const C = { txt: col('--txt'), dim: col('--dim'), line: dark ? '#2a3a52' : '#c9d4e3', bg: dark ? '#0b1322' : '#f5f8fc', panel: dark ? '#132036' : '#ffffff', cyan: col('--cyan'), red: col('--red') };
    const LP = { '--green': '#16a34a', '--yellow': '#ca8a04', '--red': '#dc2626', '--cyan': '#0891b2', '--dim': '#64748b' };
    const vc = v => opt.light ? LP[v] || '#334155' : col(v);
    const sc = s => vc((ST[s] || ST.unknown)[0]);
    if (opt.light) Object.assign(C, { txt: '#0f172a', dim: '#5b6b80', cyan: LP['--cyan'], red: LP['--red'] });
    const path = new Set(d.path || []);
    const out = [];
    const font = 'font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif"';
    const mono = 'font-family="ui-monospace,Menlo,monospace"';
    const trunc = (s, n) => { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
    out.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${L.W}" height="${L.H}" viewBox="0 0 ${L.W} ${L.H}" ${font}>`);
    out.push(`<rect width="100%" height="100%" fill="${C.bg}"/>`);
    // grid σαν χαρτί σχεδίου
    out.push(`<defs><pattern id="tpg" width="24" height="24" patternUnits="userSpaceOnUse"><path d="M24 0H0V24" fill="none" stroke="${C.line}" stroke-opacity=".35" stroke-width=".6"/></pattern></defs><rect width="100%" height="100%" fill="url(#tpg)"/>`);
    const brokenEdge = diag.level === 'bad' ? [diag.node, diag.prev] : null;
    // ακμές
    g.edges.forEach(e => {
      const a = N[e.a], b = N[e.b]; if (!a || !b || b.inPanel) return;
      if (e.side) { // internet ↔ DNS
        out.push(`<line x1="${a.x + BW}" y1="${a.y + BH / 2}" x2="${b.x}" y2="${b.y + BH / 2}" stroke="${C.dim}" stroke-dasharray="4 4" stroke-width="1.5"/>`);
        return;
      }
      const onp = path.has(a.id) && path.has(b.id);
      const s = e.status === 'down' ? C.red : e.status === 'slow' ? vc('--yellow') : onp ? C.cyan : C.dim;
      const x1 = a.x + BW / 2, y1 = a.y + BH, x2 = b.x + BW / 2, y2 = b.y, my = y1 + (y2 - y1) / 2;
      const dash = e.guess || e.status === 'unreach' ? ' stroke-dasharray="5 5"' : '';
      out.push(`<path d="M${x1} ${y1}V${my}H${x2}V${y2}" fill="none" stroke="${s}" stroke-width="${onp ? 3 : 1.8}"${dash} stroke-linejoin="round"/>`);
      if (e.label) out.push(`<text x="${x2 + 6}" y="${y2 - 8}" font-size="11" fill="${C.dim}" ${mono}>${E(trunc(e.label, 14))}</text>`);
      if (brokenEdge && ((e.a === brokenEdge[0] && e.b === brokenEdge[1]) || (e.b === brokenEdge[0] && e.a === brokenEdge[1]))) {
        const fx = x2, fy = my;
        out.push(`<g><circle cx="${fx}" cy="${fy}" r="13" fill="${C.red}"/><text x="${fx}" y="${fy + 5}" text-anchor="middle" font-size="15">⚡</text></g>`);
      }
    });
    // πάνελ συσκευών (σαν «patch panel»)
    Object.values(N).forEach(n => {
      if (!n.panel) return;
      const p = n.panel, x1 = n.x + BW / 2, y1 = n.y + BH, x2 = p.x + p.w / 2, my = y1 + (p.y - y1) / 2;
      const onp = n.hosts.some(h => path.has(h.id));
      out.push(`<path d="M${x1} ${y1}V${my}H${x2}V${p.y}" fill="none" stroke="${onp ? C.cyan : C.dim}" stroke-width="${onp ? 3 : 1.8}" stroke-linejoin="round"/>`);
      out.push(`<rect x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="10" fill="${C.panel}" fill-opacity=".92" stroke="${C.line}"/>`);
      out.push(`<text x="${p.x + 10}" y="${p.y + 19}" font-size="11.5" font-weight="700" fill="${C.dim}">${E(T('ΣΥΣΚΕΥΕΣ', 'DEVICES'))} · ${n.hosts.length}</text>`);
      n.hosts.forEach(h => {
        const y = h.y, me = h.kind === 'me', sel = TM.sel === h.id;
        out.push(`<g class="nd" data-id="${E(h.id)}">`);
        out.push(`<rect x="${p.x + 4}" y="${y}" width="${p.w - 8}" height="${RH - 2}" rx="5" fill="${me ? C.cyan : sel ? C.line : 'transparent'}" fill-opacity="${me ? .16 : .5}"/>`);
        out.push(`<text x="${p.x + 10}" y="${y + 14}" font-size="10.5" fill="${C.dim}" ${mono}>${E(trunc(h.port || '·', 7))}</text>`);
        out.push(`<circle cx="${p.x + 68}" cy="${y + 10}" r="4" fill="${sc(h.status)}"/>`);
        const vl = h.vlan != null ? ` · v${h.vlan}` : '';
        out.push(`<text x="${p.x + 78}" y="${y + 14}" font-size="11.5" fill="${C.txt}" font-weight="${me ? 700 : 400}">${E(trunc((me ? '🧑‍💻 ' : '') + LT(h.label), 17))}</text>`);
        out.push(`<text x="${p.x + p.w - 10}" y="${y + 14}" font-size="10" text-anchor="end" fill="${C.dim}" ${mono}>${E((h.ip || '').replace(/^\d+\.\d+\./, '…') + vl)}</text>`);
        out.push(`</g>`);
      });
    });
    // κόμβοι
    Object.values(N).forEach(n => {
      if (n.inPanel || n.x == null) return;
      const s = sc(n.status), onp = path.has(n.id), sel = TM.sel === n.id;
      const dash = ['quiet', 'unreach', 'unknown'].includes(n.status) ? ' stroke-dasharray="5 4"' : '';
      out.push(`<g class="nd" data-id="${E(n.id)}">`);
      if (diag.level === 'bad' && diag.node === n.id) out.push(`<rect class="tp-pulse" x="${n.x}" y="${n.y}" width="${BW}" height="${BH}" rx="12" fill="none" stroke="${C.red}"/>`);
      out.push(`<rect class="box" x="${n.x}" y="${n.y}" width="${BW}" height="${BH}" rx="12" fill="${C.panel}" stroke="${s}" stroke-width="${onp || sel ? 2.4 : 1.6}"${dash}/>`);
      out.push(`<rect x="${n.x}" y="${n.y}" width="6" height="${BH}" rx="3" fill="${s}"/>`);
      out.push(`<text x="${n.x + 16}" y="${n.y + 24}" font-size="17">${ICON[n.kind] || '•'}</text>`);
      out.push(`<text x="${n.x + 42}" y="${n.y + 23}" font-size="12.5" font-weight="700" fill="${C.txt}">${E(trunc(LT(n.label), 18))}</text>`);
      const sub = [n.ip, n.ms != null ? `${Math.round(n.ms * 10) / 10} ms` : '', n.loss ? `${Math.round(n.loss)}% ✗` : ''].filter(Boolean).join(' · ') || LT(n.sub);
      out.push(`<text x="${n.x + 42}" y="${n.y + 40}" font-size="10.5" fill="${C.dim}" ${mono}>${E(trunc(sub, 24))}</text>`);
      out.push(`<text x="${n.x + 42}" y="${n.y + 53}" font-size="10" fill="${s}">${E(trunc(T((ST[n.status] || ST.unknown)[1], (ST[n.status] || ST.unknown)[2]), 26))}</text>`);
      out.push(`</g>`);
    });
    out.push(`<text x="${L.W - 10}" y="${L.H - 10}" text-anchor="end" font-size="10" fill="${C.dim}">NetWatch · ${E(new Date((d.last_run || 0) * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR'))}</text>`);
    out.push('</svg>');
    return { svg: out.join(''), N };
  }

  function popHTML(n) {
    const st = ST[n.status] || ST.unknown;
    const kv = [[T('IP', 'IP'), n.ip], [T('Θύρα', 'Port'), n.port], ['VLAN', n.vlan], [T('Χρόνος', 'RTT'), n.ms != null ? `${n.ms} ms` : ''],
      [T('Απώλειες', 'Loss'), n.loss != null ? `${n.loss}%` : ''], [T('Τύπος', 'Type'), LT(n.sub)]].filter(x => x[1] !== '' && x[1] != null);
    const host = ['host', 'me'].includes(n.kind) && n.ip;
    const acts = [];
    if (n.ip) acts.push(`<button class="b" data-tpcp="${E(n.ip)}">📋 IP</button>`);
    if (n.ip && window.whereIs) acts.push(`<button class="b" data-tpwhere="${E(n.ip)}">🔌 ${T('Πού είναι', 'Where')}</button>`);
    if (host && window.showProfile) acts.push(`<button class="b" data-tpprof="${E(n.ip)}">👤 ${T('Προφίλ', 'Profile')}</button>`);
    if (['router', 'modem', 'isp', 'internet'].includes(n.kind)) acts.push(`<button class="b" data-tptab="lat">📈 ${T('Καθυστέρηση', 'Latency')}</button>`);
    if (n.kind === 'dns') acts.push(`<button class="b" data-tptab="dnsf">🔐 DNS</button>`);
    return `<b>${ICON[n.kind] || ''} ${E(LT(n.label))}</b><div style="color:${col(st[0])};font-size:12px;margin-top:2px">● ${E(T(st[1], st[2]))}</div>
      <div class="kv">${kv.map(([k, v]) => `<span>${E(k)}</span><span>${E(v)}</span>`).join('')}</div><div>${acts.join('')}</div>`;
  }

  // ── εξαγωγή: ο browser φτιάχνει το αρχείο, ο server το δίνει ως κανονικό «κατέβασμα» (δουλεύει και στο Mac app) ──
  function save(fmt, blob) {  // Content-Type json = ο έλεγχος CSRF του server· το σώμα είναι ακατέργαστο (pdf/png/svg)
    TM.msg = '⏳ ' + T('Ετοιμάζω το αρχείο…', 'Preparing the file…'); draw();
    fetch('/api/topomap/export?fmt=' + fmt, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: blob }).then(r => r.json()).then(j => {
      TM.msg = j.error || ('✓ ' + T('Κατέβηκε στα Λήψεις (Downloads).', 'Saved to Downloads.'));
      if (j.url) location.href = j.url;
      draw();
    }).catch(e => { TM.msg = String(e); draw(); });
  }
  const svgImg = svg => new Promise((ok, bad) => {
    const img = new Image(), url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
    img.onload = () => { URL.revokeObjectURL(url); ok(img); }; img.onerror = bad; img.src = url;
  });
  const dims = svg => { const m = svg.match(/width="(\d+(?:\.\d+)?)" height="(\d+(?:\.\d+)?)"/); return [+m[1], +m[2]]; };
  async function exportPNG() {
    const svg = svgOf(TM.d).svg, [W, H] = dims(svg), img = await svgImg(svg);
    const c = document.createElement('canvas'); c.width = W * 2; c.height = H * 2;
    const x = c.getContext('2d'); x.scale(2, 2); x.drawImage(img, 0, 0);
    c.toBlob(b => save('png', b), 'image/png');
  }

  // ── PDF (A4 οριζόντιο): σελ. 1 διάγνωση + διάγραμμα, σελ. 2+ πίνακας συσκευών. Κάθε σελίδα = εικόνα JPEG μέσα σε PDF. ──
  const PG = [2480, 1754], FONT = '-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif';
  function wrap(x, text, maxW) {
    const out = []; let line = '';
    String(text || '').split(/\s+/).forEach(w => { const t = line ? line + ' ' + w : w; if (x.measureText(t).width > maxW && line) { out.push(line); line = w; } else line = t; });
    if (line) out.push(line); return out;
  }
  function pageCanvas(n, total) {
    const c = document.createElement('canvas'); c.width = PG[0]; c.height = PG[1];
    const x = c.getContext('2d'); x.fillStyle = '#fff'; x.fillRect(0, 0, PG[0], PG[1]);
    x.fillStyle = '#0f172a'; x.font = `700 46px ${FONT}`; x.fillText('🗺 ' + T('Διάγραμμα δικτύου', 'Network diagram'), 90, 110);
    x.fillStyle = '#64748b'; x.font = `28px ${FONT}`;
    const when = new Date((TM.d.last_run || 0) * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR');
    x.fillText(`NetWatch · ${when}${TM.d.demo ? ' · demo' : ''}`, 90, 155);
    x.textAlign = 'right'; x.fillText(`${n} / ${total}`, PG[0] - 90, 110); x.textAlign = 'left';
    x.strokeStyle = '#e2e8f0'; x.lineWidth = 3; x.beginPath(); x.moveTo(90, 180); x.lineTo(PG[0] - 90, 180); x.stroke();
    return [c, x];
  }
  function tableRows() {
    const g = TM.d.graph, N = {}; g.nodes.forEach(n => { N[n.id] = n; });
    const rank = { internet: 0, isp: 1, modem: 2, router: 3, switch: 4, ap: 5, me: 6, host: 7, dns: 8, more: 9 };
    return g.nodes.filter(n => n.kind !== 'more').sort((a, b) => (rank[a.kind] - rank[b.kind]) || String(a.ip).localeCompare(String(b.ip), undefined, { numeric: true }))
      .map(n => { const p = N[n.parent]; const st = ST[n.status] || ST.unknown;
        return [(ICON[n.kind] || '') + ' ' + LT(n.label), n.ip || '—', LT(n.sub) || n.kind, p ? LT(p.label) : '—', n.port || '—', n.vlan != null ? String(n.vlan) : '—', T(st[1], st[2]), st[0], n.ms != null ? n.ms + ' ms' : '—']; });
  }
  async function exportPDF() {
    const d = TM.d, diag = d.diag || {}, rows = tableRows(), per = 30, tp = Math.ceil(rows.length / per), total = 1 + tp, pages = [];
    // σελίδα 1
    let [c, x] = pageCanvas(1, total);
    const col_ = { ok: '#16a34a', warn: '#ca8a04', bad: '#dc2626' }[diag.level] || '#64748b';
    const FW = PG[0] - 215;
    x.fillStyle = '#0f172a'; x.font = `700 36px ${FONT}`;
    let y = 255;
    wrap(x, ({ ok: '✅ ', warn: '⚠️ ', bad: '⚡ ' }[diag.level] || '') + LT(diag.title), FW).slice(0, 2).forEach(l => { x.fillText(l, 125, y); y += 46; });
    x.font = `27px ${FONT}`; x.fillStyle = '#334155';
    wrap(x, LT(diag.text), FW).slice(0, 2).forEach(l => { x.fillText(l, 125, y); y += 38; });
    x.font = `26px ${FONT}`;
    (diag.steps || []).slice(0, 4).forEach((st, i) => { x.fillText(wrap(x, `${i + 1}. ${LT(st)}`, FW)[0], 145, y); y += 36; });
    (d.issues || []).slice(0, 3).forEach(i => { x.fillStyle = i.level === 'bad' ? '#dc2626' : '#ca8a04'; x.fillText(wrap(x, '• ' + (EN() ? i.en : i.el), FW)[0], 145, y); y += 36; });
    x.fillStyle = col_; x.fillRect(90, 220, 10, y - 240);
    const sy = y;
    const top = Math.max(y, sy, 380) + 20;
    const svg = svgOf(d, { light: true }).svg, [W, H] = dims(svg), img = await svgImg(svg);
    const legY = PG[1] - 70, availH = legY - 30 - top, availW = PG[0] - 180, s = Math.min(availW / W, availH / H, 2.2);
    x.drawImage(img, 90 + (availW - W * s) / 2, top, W * s, H * s);
    x.font = `24px ${FONT}`; let lx = 90;
    ['ok', 'slow', 'down', 'quiet', 'unreach'].forEach(k => { const lp = { ok: '#16a34a', slow: '#ca8a04', down: '#dc2626', quiet: '#0891b2', unreach: '#64748b' }[k];
      x.strokeStyle = lp; x.lineWidth = 4; x.strokeRect(lx, legY - 20, 24, 24); x.fillStyle = '#334155'; const t = T(ST[k][1], ST[k][2]); x.fillText(t, lx + 34, legY); lx += 60 + x.measureText(t).width; });
    pages.push(c);
    // σελίδες πίνακα
    const cols = [[T('Συσκευή', 'Device'), 520], ['IP', 250], [T('Τύπος', 'Type'), 420], [T('Συνδέεται σε', 'Connected to'), 440], [T('Θύρα', 'Port'), 170], ['VLAN', 110], [T('Κατάσταση', 'Status'), 390]];
    for (let pi = 0; pi < tp; pi++) {
      [c, x] = pageCanvas(pi + 2, total);
      x.font = `700 32px ${FONT}`; x.fillStyle = '#0f172a'; x.fillText(T('Πίνακας συσκευών', 'Device inventory') + ` (${rows.length})`, 90, 240);
      let cx = 90, ty = 300; x.font = `700 24px ${FONT}`; x.fillStyle = '#64748b';
      cols.forEach(([h, w]) => { x.fillText(h.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase(), cx, ty); cx += w; });  // ελληνικά κεφαλαία χωρίς τόνους
      x.font = `25px ${FONT}`;
      rows.slice(pi * per, pi * per + per).forEach((r, i) => {
        const ry = 350 + i * 45; if (i % 2 === 0) { x.fillStyle = '#f1f5f9'; x.fillRect(80, ry - 31, PG[0] - 160, 45); }
        let cx2 = 90;
        cols.forEach(([, w], k) => {
          let v = k === 6 ? r[6] : r[k]; x.fillStyle = k === 6 ? ({ '--green': '#16a34a', '--yellow': '#ca8a04', '--red': '#dc2626', '--cyan': '#0891b2' }[r[7]] || '#64748b') : '#0f172a';
          if (k === 1 || k === 4) x.font = `24px ui-monospace,Menlo,monospace`; else x.font = `25px ${FONT}`;
          while (v.length > 3 && x.measureText(v).width > w - 20) v = v.slice(0, -2);
          if (v !== (k === 6 ? r[6] : r[k])) v += '…';
          x.fillText(v, cx2, ry); cx2 += w;
        });
      });
      pages.push(c);
    }
    save('pdf', makePDF(pages.map(p => { const b = atob(p.toDataURL('image/jpeg', 0.9).split(',')[1]); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return { bytes: u, w: p.width, h: p.height }; })));
  }
  // Ελάχιστο PDF 1.4: κάθε σελίδα μια εικόνα JPEG (DCTDecode) σε A4 οριζόντιο — χωρίς βιβλιοθήκες.
  function makePDF(pages) {
    const enc = new TextEncoder(), parts = [], offs = []; let len = 0;
    const push = v => { const b = typeof v === 'string' ? enc.encode(v) : v; parts.push(b); len += b.length; };
    const obj = (id, ...body) => { offs[id] = len; push(`${id} 0 obj\n`); body.forEach(push); push('\nendobj\n'); };
    const PW = 842, PH = 595;
    push('%PDF-1.4\n%âãÏÓ\n');
    const kids = pages.map((_, i) => `${3 + i * 3} 0 R`).join(' ');
    obj(1, '<< /Type /Catalog /Pages 2 0 R >>');
    obj(2, `<< /Type /Pages /Kids [${kids}] /Count ${pages.length} >>`);
    pages.forEach((p, i) => {
      const pid = 3 + i * 3, cid = pid + 1, iid = pid + 2, sc = Math.min(PW / p.w, PH / p.h), dw = p.w * sc, dh = p.h * sc;
      const cs = `q ${dw.toFixed(2)} 0 0 ${dh.toFixed(2)} ${((PW - dw) / 2).toFixed(2)} ${((PH - dh) / 2).toFixed(2)} cm /Im0 Do Q`;
      obj(pid, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PW} ${PH}] /Resources << /XObject << /Im0 ${iid} 0 R >> >> /Contents ${cid} 0 R >>`);
      obj(cid, `<< /Length ${cs.length} >>\nstream\n${cs}\nendstream`);
      obj(iid, `<< /Type /XObject /Subtype /Image /Width ${p.w} /Height ${p.h} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${p.bytes.length} >>\nstream\n`, p.bytes, '\nendstream');
    });
    const n = 3 + pages.length * 3, xref = len;
    push(`xref\n0 ${n}\n0000000000 65535 f \n`);
    for (let i = 1; i < n; i++) push(String(offs[i]).padStart(10, '0') + ' 00000 n \n');
    push(`trailer\n<< /Size ${n} /Root 1 0 R /Info << /Producer (NetWatch) >> >>\nstartxref\n${xref}\n%%EOF\n`);
    return new Blob(parts, { type: 'application/pdf' });
  }

  function draw() {
    const el = box(); if (!el) return;
    const d = TM.d || {}, en = EN(), diag = d.diag;
    const running = TM.busy || d.running;
    let h = `<div class="card" data-noi18n><div class="brow"><b class="ctitle">🗺 ${T('Διάγραμμα δικτύου', 'Network diagram')}</b>${d.demo ? '<span class="op-pill" style="--c:var(--purple)">demo</span>' : ''}</div>
      <div class="dim" style="font-size:13px;margin-top:4px">${T('Ένα κουμπί: traceroute + ping σε router, modem, πάροχο, switch/AP και DNS, και σχέδιο σαν τεχνικό διάγραμμα. Το πρώτο κόκκινο κουτί στη διαδρομή από εσένα προς το Internet = εκεί κοιτάς.',
        'One button: traceroute + ping to router, modem, ISP, switches/APs and DNS, drawn like a technical diagram. The first red box on the path from you to the Internet = where to look.')}</div>
      <div class="tp-bar"><button class="b tp-go" id="tp-go" ${running ? 'disabled' : ''}>${running ? '⏳ ' + T('Χαρτογραφώ…', 'Mapping…') : '▶ ' + T('Χαρτογράφησε', 'Map it')}</button>
      ${d.graph ? `<button class="b" id="tp-pdf" title="${T('Διάγνωση + διάγραμμα + πίνακας συσκευών, έτοιμο για εκτύπωση', 'Diagnosis + diagram + device table, ready to print')}">📄 PDF</button><button class="b" id="tp-png">🖼 PNG</button><button class="b" id="tp-svg" title="${T('Ανοίγει σε Illustrator/Inkscape/Figma', 'Opens in Illustrator/Inkscape/Figma')}">✏️ SVG</button><a class="b" href="/docs/network.drawio?lang=${en ? 'en' : 'el'}" style="text-decoration:none" title="${T('Επεξεργάσιμο στο draw.io / diagrams.net', 'Editable in draw.io / diagrams.net')}">📐 draw.io</a>
      <span style="flex:1"></span><button class="b" id="tp-zo">−</button><button class="b" id="tp-zr">${Math.round(TM.zoom * 100)}%</button><button class="b" id="tp-zi">+</button>` : ''}</div>
      ${(d.faults || []).length ? `<div class="tp-chips"><span class="dim">🧪 ${T('Εξάσκηση (demo) — προσομοίωσε βλάβη:', 'Practice (demo) — simulate a fault:')}</span>${FAULTS.map(([k, el_, en_]) => `<button class="tp-chip${TM.fault === k ? ' on' : ''}" data-tpf="${k}">${en ? en_ : el_}</button>`).join('')}</div>` : ''}
      ${TM.msg ? `<div class="dim" style="color:var(--yellow);margin-top:8px">${E(TM.msg)}</div>` : ''}</div>`;
    if (d.off) h += `<div class="card dim" data-noi18n>${T('Δεν είναι διαθέσιμο σε αυτή τη λειτουργία (pcap).', 'Not available in this mode (pcap).')}</div>`;
    else if (!d.graph) h += `<div class="card dim" data-noi18n style="text-align:center;padding:36px">🗺 ${T('Πάτα «▶ Χαρτογράφησε» για να σχεδιαστεί το δίκτυό σου (~10″).', 'Press “▶ Map it” to draw your network (~10″).')}</div>`;
    else {
      const lv = { ok: ['var(--green)', '✅'], warn: ['var(--yellow)', '⚠️'], bad: ['var(--red)', '⚡'] }[diag.level] || ['var(--dim)', '•'];
      h += `<div class="card tp-diag" data-noi18n style="--c:${lv[0]}"><div class="tp-dico">${lv[1]}</div><div style="flex:1;min-width:0"><h3>${E(LT(diag.title))}</h3>
        <div style="font-size:13.5px">${E(LT(diag.text))}</div>
        ${(diag.steps || []).length ? `<ol>${diag.steps.map(s => `<li>${E(LT(s))}</li>`).join('')}</ol>` : ''}
        ${(d.issues || []).length ? `<ul class="tp-iss">${d.issues.map(i => `<li data-tpsel="${E(i.node)}" style="--c:${i.level === 'bad' ? 'var(--red)' : 'var(--yellow)'}">${E(en ? i.en : i.el)}</li>`).join('')}</ul>` : ''}</div></div>`;
      const { svg } = svgOf(d);
      TM.svg = svg;
      h += `<div class="tp-wrap" id="tp-wrap" data-noi18n>${svg}</div>
        <div class="tp-leg" data-noi18n>${['ok', 'slow', 'down', 'quiet', 'unreach'].map(k => `<span><i style="--c:var(${ST[k][0]})"></i>${E(T(ST[k][1], ST[k][2]))}</span>`).join('')}
        <span><b style="color:var(--cyan)">━</b> ${T('η δική σου διαδρομή', 'your path')}</span><span>┅ ${T('σύνδεση που μαντέψαμε', 'guessed link')}</span></div>`;
    }
    el.innerHTML = h;
    const svgEl = el.querySelector('#tp-wrap svg');
    if (svgEl && !TM.fitted) { const w = +svgEl.getAttribute('width'), cw = svgEl.parentElement.clientWidth - 4; TM.zoom = Math.max(0.4, Math.min(1, cw / w)); TM.fitted = true; const zr = el.querySelector('#tp-zr'); if (zr) zr.textContent = Math.round(TM.zoom * 100) + '%'; }
    if (svgEl) { svgEl.style.transform = `scale(${TM.zoom})`; svgEl.parentElement.style.setProperty('--z', TM.zoom); fitSize(svgEl); }
    if (TM.sel && svgEl) showPop(TM.sel);
  }
  function fitSize(svgEl) {
    const w = +svgEl.getAttribute('width'), h = +svgEl.getAttribute('height');
    svgEl.style.width = w + 'px'; svgEl.style.height = h + 'px';
    svgEl.style.marginRight = `${w * (TM.zoom - 1)}px`; svgEl.style.marginBottom = `${h * (TM.zoom - 1)}px`;
  }
  function showPop(id) {
    const el = box(), wrap = el && el.querySelector('#tp-wrap'); if (!wrap || !TM.d || !TM.d.graph) return;
    wrap.querySelectorAll('.tp-pop').forEach(p => p.remove());
    const n = TM.d.graph.nodes.find(x => x.id === id); const g = wrap.querySelector(`.nd[data-id="${CSS.escape(id)}"]`);
    if (!n || !g) return;
    const r = g.getBoundingClientRect(), wr = wrap.getBoundingClientRect();
    const p = document.createElement('div'); p.className = 'tp-pop'; p.innerHTML = popHTML(n);
    p.style.left = Math.max(4, r.left - wr.left + wrap.scrollLeft) + 'px'; p.style.top = (r.bottom - wr.top + wrap.scrollTop + 6) + 'px';
    wrap.appendChild(p);
  }

  document.addEventListener('click', ev => {
    const el = box(); if (!el || !el.contains(ev.target)) return;
    const t = ev.target.closest('button,a,.nd,li[data-tpsel]'); if (!t) { if (TM.sel) { TM.sel = null; el.querySelectorAll('.tp-pop').forEach(p => p.remove()); } return; }
    if (t.id === 'tp-go') return run();
    if (t.dataset.tpf != null) { TM.fault = t.dataset.tpf; draw(); return run(); }
    if (t.id === 'tp-pdf' && TM.d && TM.d.graph) return exportPDF().catch(e => { TM.msg = String(e); draw(); });
    if (t.id === 'tp-png' && TM.d && TM.d.graph) return exportPNG().catch(e => { TM.msg = String(e); draw(); });
    if (t.id === 'tp-svg' && TM.d && TM.d.graph) return save('svg', new Blob([svgOf(TM.d, { light: true }).svg], { type: 'image/svg+xml' }));
    if (t.id === 'tp-zi' || t.id === 'tp-zo' || t.id === 'tp-zr') {
      TM.fitted = true; TM.zoom = t.id === 'tp-zr' ? 1 : Math.min(2, Math.max(0.4, TM.zoom + (t.id === 'tp-zi' ? 0.15 : -0.15)));
      const s = el.querySelector('#tp-wrap svg'); if (s) { s.style.transform = `scale(${TM.zoom})`; fitSize(s); }
      const zr = el.querySelector('#tp-zr'); if (zr) zr.textContent = Math.round(TM.zoom * 100) + '%';
      return;
    }
    if (t.dataset.tpcp) { navigator.clipboard && navigator.clipboard.writeText(t.dataset.tpcp); t.textContent = '✓'; return; }
    if (t.dataset.tpwhere) return window.whereIs(t.dataset.tpwhere);
    if (t.dataset.tpprof) return window.showProfile(t.dataset.tpprof);
    if (t.dataset.tptab) return typeof showTab === 'function' && showTab(t.dataset.tptab);
    if (t.dataset.tpsel) { TM.sel = t.dataset.tpsel; const g = el.querySelector(`.nd[data-id="${CSS.escape(TM.sel)}"]`); g && g.scrollIntoView({ block: 'center', inline: 'center', behavior: 'smooth' }); setTimeout(() => showPop(TM.sel), 350); return; }
    if (t.classList.contains('nd')) { TM.sel = t.dataset.id; showPop(TM.sel); }
  });

  window.renderTopo = () => { load(); if (!document.querySelector('#t-topo .ctitle')) draw(); };
  window.TOPO = TM;
})();
