// ⏱ Μηχανή του χρόνου (slider 24ώρου + γράφος «ποιος μιλά με ποιον»), 🧩 προσαρμόσιμη Αρχική και 🧭 ξενάγηση.
// Φορτώνεται μετά το index.html· χρησιμοποιεί τα κοινά του ($, esc, fmtB, showTab, tab, S, I18N).
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const FB = n => (window.fmtB ? fmtB(n) : (n > 1e6 ? (n / 1e6).toFixed(1) + ' MB' : n > 1e3 ? (n / 1e3).toFixed(1) + ' KB' : n + ' B'));
  const flag = cc => cc && cc.length === 2 ? cc.toUpperCase().replace(/./g, ch => String.fromCodePoint(127397 + ch.charCodeAt(0))) : '';
  const hm = t => { const d = new Date(t * 1000); return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0'); };
  const curTab = () => (typeof tab !== 'undefined' ? tab : null);

  // ───────────────────────── ⏱ Μηχανή του χρόνου ─────────────────────────
  const TM = { sum: null, at: null, t: null, span: 5, play: false, speed: 1, timer: null, loadingAt: false, live: true, sumAt: 0, hover: null };
  const SEVC = { high: 'var(--red)', med: 'var(--orange)', low: 'var(--yellow,#e3b341)' };
  function loadSum(force) {
    if (!force && Date.now() - TM.sumAt < 30000 && TM.sum) return;
    TM.sumAt = Date.now();
    fetch('/api/timeline?hours=24').then(r => r.json()).then(j => { TM.sum = j; if (TM.t == null || TM.live) TM.t = lastT(); drawTm(); loadAt(); }).catch(() => { });
  }
  const lastT = () => { const b = (TM.sum && TM.sum.buckets) || []; return b.length ? b[b.length - 1].t : Math.floor(Date.now() / 60000) * 60; };
  const firstT = () => { const b = (TM.sum && TM.sum.buckets) || []; return b.length ? b[0].t : lastT() - 86400; };
  let atSeq = 0;
  function loadAt() {
    if (TM.t == null) return;
    const my = ++atSeq;
    fetch(`/api/timeline/at?t=${TM.t}&span=${TM.span}`).then(r => r.json()).then(j => { if (my !== atSeq) return; TM.at = j; paintAt(); }).catch(() => { });
  }
  function setT(t, user) {
    const a = firstT(), b = lastT();
    TM.t = Math.max(a, Math.min(b, Math.round(t / 60) * 60));
    TM.live = TM.t >= b;
    if (user && TM.play && TM.live) stopPlay();
    const sl = document.querySelector('#t-tm .tm-range'); if (sl) sl.value = TM.t;
    paintHead(); paintCursor(); loadAt();
  }
  function stopPlay() { TM.play = false; clearInterval(TM.timer); TM.timer = null; const b = document.querySelector('#t-tm [data-tmplay]'); if (b) b.textContent = '▶'; }
  function togglePlay() {
    if (TM.play) return stopPlay();
    if (TM.live) setT(firstT());
    TM.play = true; const b = document.querySelector('#t-tm [data-tmplay]'); if (b) b.textContent = '⏸';
    TM.timer = setInterval(() => { if (curTab() !== 'tm') return stopPlay(); if (TM.t >= lastT()) return stopPlay(); setT(TM.t + 60 * TM.speed); }, 450);
  }

  // ── ταινία 24ώρου: μπάρες κίνησης + σημάδια ειδοποιήσεων ──
  const SW = 1000, SH = 86;
  function stripSVG() {
    const bs = (TM.sum && TM.sum.buckets) || []; if (!bs.length) return '<div class="sm">—</div>';
    const a = firstT(), b = lastT() + 60, W = b - a, per = 300, nb = Math.ceil(W / per), agg = new Array(nb).fill(0), al = new Array(nb).fill(null);
    const rank = { high: 3, med: 2, low: 1 };
    for (const x of bs) { const k = Math.min(nb - 1, Math.floor((x.t - a) / per)); agg[k] += x.bytes; if (x.alerts && (rank[x.sev] || 0) >= (rank[al[k]] || 0)) al[k] = x.sev || 'low'; }
    const mx = Math.max(...agg, 1), bw = SW / nb;
    let g = `<svg viewBox="0 0 ${SW} ${SH}" preserveAspectRatio="none" class="tm-svg">`;
    for (let h = 0; h <= 24; h += 3) { const t = a + h * 3600; const hr = new Date(Math.ceil(t / 3600) * 3600 * 1000); const x = ((hr / 1000 - a) / W) * SW; if (x < 0 || x > SW) continue; g += `<line x1="${x}" y1="0" x2="${x}" y2="${SH - 14}" class="tm-grid"/><text x="${x + 3}" y="${SH - 3}" class="tm-hl">${String(hr.getHours()).padStart(2, '0')}:00</text>`; }
    agg.forEach((v, i) => { const h = Math.max(v ? 1.5 : 0, Math.sqrt(v / mx) * (SH - 26)); g += `<rect x="${(i * bw + .4).toFixed(1)}" y="${(SH - 16 - h).toFixed(1)}" width="${Math.max(.6, bw - .8).toFixed(1)}" height="${h.toFixed(1)}" class="tm-bar"/>`; });
    al.forEach((s, i) => { if (s) g += `<rect x="${(i * bw).toFixed(1)}" y="1" width="${Math.max(2, bw).toFixed(1)}" height="6" rx="1" style="fill:${SEVC[s]}"/>`; });
    g += `<g class="tm-cur"><rect class="tm-win" y="0" height="${SH - 14}"/><line class="tm-cl" y1="0" y2="${SH - 14}"/></g>`;
    return g + '</svg>';
  }
  function paintCursor() {
    const svg = document.querySelector('#t-tm .tm-svg'); if (!svg || TM.t == null) return;
    const a = firstT(), W = lastT() + 60 - a, x = ((TM.t + 60 - a) / W) * SW, x0 = ((TM.t - (TM.span - 1) * 60 - a) / W) * SW;
    const l = svg.querySelector('.tm-cl'), r = svg.querySelector('.tm-win');
    l.setAttribute('x1', x); l.setAttribute('x2', x); r.setAttribute('x', x0); r.setAttribute('width', Math.max(1, x - x0));
  }
  function paintHead() {
    const el = document.querySelector('#t-tm .tm-when'); if (!el || TM.t == null) return;
    const ago = Math.round((lastT() - TM.t) / 60), d = new Date(TM.t * 1000), today = new Date().toDateString() === d.toDateString();
    el.innerHTML = `<b data-noi18n>${hm(TM.t - (TM.span - 1) * 60)}${TM.span > 1 ? '–' + hm(TM.t + 60) : ''}</b> <span class="sm">${today ? 'σήμερα' : 'χθες'}</span> ${TM.live ? '<span class="tag g">● ΖΩΝΤΑΝΑ</span>' : `<span class="sm">πριν ${ago >= 60 ? Math.floor(ago / 60) + 'ω ' + (ago % 60) + '′' : ago + '′'}</span>`}`;
  }

  // ── γράφος: router στο κέντρο, συσκευές σε εσωτερικό κύκλο, προορισμοί έξω ──
  const hash = s => { let h = 2166136261; for (const c of String(s)) h = Math.imul(h ^ c.charCodeAt(0), 16777619); return (h >>> 0) / 4294967296; };
  function graphSVG(at) {
    const W = 760, H = 520, cx = W / 2, cy = H / 2;
    const devs = (at.devices || []).filter(d => !d.gw).slice(0, 18), edges = at.edges || [];
    if (!devs.length && !edges.length) return `<svg viewBox="0 0 ${W} ${H}" class="tm-g"><text x="${cx}" y="${cy}" text-anchor="middle" class="tm-empty">Καμία κίνηση σε αυτό το λεπτό</text></svg>`;
    const order = devs.map(d => d.ip).sort((a, b) => hash(a) - hash(b)), pos = {}, R1 = 135, R2 = 238;
    order.forEach((ip, i) => { const a = (i / Math.max(1, order.length)) * Math.PI * 2 - Math.PI / 2; pos[ip] = [cx + R1 * Math.cos(a), cy + R1 * Math.sin(a), a]; });
    const peers = {}; for (const e of edges) { if (!pos[e.dev] && !e.lan) continue; if (e.lan && pos[e.peer]) continue; (peers[e.peer] = peers[e.peer] || { e, devs: [] }).devs.push(e.dev); }
    // κάθε προορισμός μπαίνει κοντά στη γωνία της (πρώτης) συσκευής του, με μικρή απόκλιση
    // κάθε προορισμός μπαίνει γύρω-γύρω, με τη σειρά της γωνίας της συσκευής του — ισαπέχοντες, ώστε να μη στριμώχνονται
    const ppos = {}, plist = Object.entries(peers).slice(0, 32).map(([ip, p]) => [ip, (pos[p.devs[0]] ? pos[p.devs[0]][2] : hash(ip) * Math.PI * 2) + hash(ip) * 0.01]);
    plist.sort((x, y) => x[1] - y[1]);
    const n0 = plist.length, off = n0 ? plist.reduce((s2, [, a]) => s2, 0) : 0;
    plist.forEach(([ip, base], k) => {
      const even = -Math.PI / 2 + (k + 0.5) / Math.max(1, n0) * Math.PI * 2;
      // λίγο προς τη γωνία της συσκευής, αλλά κυρίως ισαπέχοντα
      let d = ((base - even + Math.PI * 3) % (Math.PI * 2)) - Math.PI; const a = even + d * (n0 > 10 ? 0.0 : 0.35);
      ppos[ip] = [cx + R2 * Math.cos(a), cy + R2 * 0.88 * Math.sin(a), a];
    });
    const mx = Math.max(...edges.map(e => e.bytes), 1), w = b => 0.8 + 5 * Math.sqrt(b / mx);
    let g = `<svg viewBox="0 0 ${W} ${H}" class="tm-g"><defs><radialGradient id="tmglow"><stop offset="0" stop-color="var(--cyan)" stop-opacity=".25"/><stop offset="1" stop-color="var(--cyan)" stop-opacity="0"/></radialGradient></defs>`;
    g += `<circle cx="${cx}" cy="${cy}" r="${R1}" class="tm-ring"/><circle cx="${cx}" cy="${cy}" r="70" fill="url(#tmglow)"/>`;
    for (const ip of order) { const [x, y] = pos[ip]; g += `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" class="tm-spoke"/>`; }
    for (const e of edges) {
      const a = pos[e.dev], b = ppos[e.peer] || (e.lan ? pos[e.peer] : null); if (!a || !b) continue;
      const bad = e.cc && ['CN', 'RU', 'KP', 'IR'].includes(e.cc), mxp = (a[0] + b[0]) / 2 + (cx - (a[0] + b[0]) / 2) * (e.lan ? .5 : .12), myp = (a[1] + b[1]) / 2 + (cy - (a[1] + b[1]) / 2) * (e.lan ? .5 : .12);
      const dur = Math.max(.6, 3.2 - 2.6 * Math.sqrt(e.bytes / mx)).toFixed(2);
      g += `<path d="M${a[0].toFixed(1)} ${a[1].toFixed(1)} Q${mxp.toFixed(1)} ${myp.toFixed(1)} ${b[0].toFixed(1)} ${b[1].toFixed(1)}" class="tm-e${bad ? ' bad' : ''}${e.lan ? ' lan' : ''}" style="stroke-width:${w(e.bytes).toFixed(1)};animation-duration:${dur}s"><title>${E((e.name || e.peer) + ' · ' + FB(e.bytes) + ' · ' + (e.proto || ''))}</title></path>`;
    }
    g += `<g class="tm-n gw"><circle cx="${cx}" cy="${cy}" r="24"/><text x="${cx}" y="${cy + 5}" text-anchor="middle" class="tm-ic">📡</text><text x="${cx}" y="${cy + 40}" text-anchor="middle" class="tm-nl">router</text></g>`;
    const dv = Object.fromEntries(devs.map(d => [d.ip, d])), dmx = Math.max(...devs.map(d => d.bytes_in + d.bytes_out), 1);
    for (const ip of order) {
      const d = dv[ip], [x, y, a] = pos[ip], r = 15 + 9 * Math.sqrt((d.bytes_in + d.bytes_out) / dmx), lx = Math.cos(a), ly = Math.sin(a);
      g += `<g class="tm-n dev${d.me ? ' me' : ''}" data-tmip="${E(ip)}"><circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r.toFixed(1)}"/><text x="${x.toFixed(1)}" y="${(y + 5).toFixed(1)}" text-anchor="middle" class="tm-ic">${d.icon || '💻'}</text>
        <text x="${(x + lx * (r + 6) * (Math.abs(lx) > .35 ? 1 : 0)).toFixed(1)}" y="${(y + (Math.abs(lx) > .35 ? 4 : (r + 13) * Math.sign(ly || 1))).toFixed(1)}" text-anchor="${Math.abs(lx) <= .35 ? 'middle' : lx > 0 ? 'start' : 'end'}" class="tm-nl" data-noi18n>${E((d.name || ip).slice(0, 22))}</text><title>${E((d.name || ip) + ' · ↓' + FB(d.bytes_in) + ' ↑' + FB(d.bytes_out))}</title></g>`;
    }
    for (const [ip, [x, y, a]] of Object.entries(ppos)) {
      const e = peers[ip].e, bad = e.cc && ['CN', 'RU', 'KP', 'IR'].includes(e.cc), lx = Math.cos(a);
      g += `<g class="tm-n peer${bad ? ' bad' : ''}"><circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="5.5"/><text x="${(x + (lx >= 0 ? 9 : -9)).toFixed(1)}" y="${(y + 4).toFixed(1)}" text-anchor="${lx >= 0 ? 'start' : 'end'}" class="tm-pl" data-noi18n>${flag(e.cc)} ${E(String(e.name || ip).replace(/^www\./, '').slice(0, 24))}</text><title>${E(ip + (e.country ? ' · ' + e.country : '') + ' · ' + (e.proto || ''))}</title></g>`;
    }
    return g + '</svg>';
  }
  function paintAt() {
    const at = TM.at, el = document.querySelector('#t-tm .tm-body'); if (!el || !at) return;
    const devs = (at.devices || []).filter(d => !d.gw), mx = Math.max(...devs.map(d => d.bytes_in + d.bytes_out), 1);
    el.innerHTML = `<div class="card tm-gcard">${graphSVG(at)}</div>
      <div class="tm-side"><div class="card"><div class="brow"><b class="ctitle">📟 Ενεργές συσκευές</b><span class="sm">${FB(at.bytes)} · ${at.pkts} πακ.</span></div>
        ${devs.length ? devs.slice(0, 14).map(d => `<div class="tm-dr"><span>${d.icon || '💻'}</span><span class="tm-dn" data-noi18n>${E(d.name || d.ip)}</span><span class="tm-bb"><i style="width:${(100 * (d.bytes_in + d.bytes_out) / mx).toFixed(0)}%"></i></span><span class="sm tm-v">${FB(d.bytes_in + d.bytes_out)}</span></div>`).join('') : '<div class="sm">Καμία συσκευή δεν μίλησε.</div>'}</div>
        <div class="card"><b class="ctitle">🌍 Κορυφαίοι προορισμοί</b>${(at.edges || []).filter(e => !e.lan).slice(0, 8).map(e => `<div class="tm-dr"><span>${flag(e.cc) || '🌐'}</span><span class="tm-dn" data-noi18n>${E(e.name || e.peer)}</span><span class="sm" data-noi18n>${E(e.proto || '')}</span><span class="sm tm-v">${FB(e.bytes)}</span></div>`).join('') || '<div class="sm">—</div>'}</div>
        <div class="card"><b class="ctitle">⚠ Ειδοποιήσεις τη στιγμή αυτή</b>${(at.alerts || []).length ? at.alerts.slice(0, 8).map(a => `<div class="tm-al" style="--c:${SEVC[a.sev] || 'var(--cyan)'}"><b>${E(a.type)}</b> <span class="sm" data-noi18n>${E(a.actor || '')} → ${E(a.target || '')} · ${hm(a.t)}</span></div>`).join('') : '<div class="sm">Καμία — ήσυχο λεπτό.</div>'}</div></div>`;
  }
  function drawTm() {
    const el = document.getElementById('t-tm'); if (!el) return;
    const s = TM.sum;
    if (s && s.off) { el.innerHTML = '<div class="card"><b>⏱ Μηχανή του χρόνου</b><div class="sm">Δεν είναι διαθέσιμη σε ανάλυση pcap.</div></div>'; return; }
    el.innerHTML = `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">⏱ Μηχανή του χρόνου ${s && s.demo ? '<span class="tag">προσομοίωση</span>' : ''}</b><span class="tm-when"></span></div>
        <div class="sm" style="margin-top:4px">Γύρνα το δίκτυο σε οποιοδήποτε λεπτό του τελευταίου 24ώρου: ποια συσκευή μιλούσε, με ποιον και πόσο. Οι κόκκινες γραμμές πάνω είναι ειδοποιήσεις — κάνε κλικ για να πας εκεί, ή πάτα ▶ για να δεις τη μέρα σαν βίντεο.</div>
        <div class="tm-strip">${s ? stripSVG() : '<div class="sm">φόρτωση…</div>'}</div>
        <input type="range" class="tm-range" min="${firstT()}" max="${lastT()}" step="60" value="${TM.t || lastT()}">
        <div class="tm-ctl"><button class="b" data-tmj="-3600" title="−1 ώρα">⏮</button><button class="b" data-tmj="-60" title="−1 λεπτό">◀</button><button class="b tm-play" data-tmplay>${TM.play ? '⏸' : '▶'}</button><button class="b" data-tmj="60" title="+1 λεπτό">▶|</button><button class="b" data-tmnow>● Τώρα</button>
          <span class="tm-sp"></span><span class="sm">Παράθυρο</span>${[1, 5, 15, 60].map(k => `<button class="b${TM.span === k ? ' on' : ''}" data-tmspan="${k}">${k}′</button>`).join('')}
          <span class="sm" style="margin-left:8px">Ταχύτητα</span>${[1, 5, 15].map(k => `<button class="b${TM.speed === k ? ' on' : ''}" data-tmspeed="${k}">${k}×</button>`).join('')}
          <button class="b" data-tmnext title="Επόμενη ειδοποίηση">⚠ →</button></div></div>
      <div class="tm-body"></div>`;
    paintHead(); paintCursor(); paintAt();
    const sl = el.querySelector('.tm-range'); sl.oninput = () => setT(+sl.value, true);
    el.querySelectorAll('[data-tmj]').forEach(b => b.onclick = () => setT(TM.t + +b.dataset.tmj, true));
    el.querySelector('[data-tmplay]').onclick = togglePlay;
    el.querySelector('[data-tmnow]').onclick = () => { stopPlay(); loadSum(true); setT(lastT(), true); };
    el.querySelectorAll('[data-tmspan]').forEach(b => b.onclick = () => { TM.span = +b.dataset.tmspan; el.querySelectorAll('[data-tmspan]').forEach(x => x.classList.toggle('on', x === b)); setT(TM.t); });
    el.querySelectorAll('[data-tmspeed]').forEach(b => b.onclick = () => { TM.speed = +b.dataset.tmspeed; el.querySelectorAll('[data-tmspeed]').forEach(x => x.classList.toggle('on', x === b)); });
    el.querySelector('[data-tmnext]').onclick = () => { const n = ((TM.sum && TM.sum.buckets) || []).find(b => b.alerts && b.t > TM.t); if (n) { stopPlay(); setT(n.t, true); } };
    const svg = el.querySelector('.tm-svg');
    if (svg) {
      const pick = ev => { const r = svg.getBoundingClientRect(); return firstT() + ((ev.clientX - r.left) / r.width) * (lastT() + 60 - firstT()); };
      let drag = false;
      svg.onpointerdown = ev => { drag = true; svg.setPointerCapture(ev.pointerId); setT(pick(ev), true); };
      svg.onpointermove = ev => { if (drag) setT(pick(ev), true); };
      svg.onpointerup = () => { drag = false; };
    }
  }
  window.renderTm = () => {
    loadSum();
    if (!document.querySelector('#t-tm .tm-body')) drawTm();
    else if (TM.live && !TM.play && Date.now() - (TM.lastLive || 0) > 15000) { TM.lastLive = Date.now(); loadSum(true); }
  };

  // ───────────────────────── 🧩 Προσαρμόσιμη Αρχική ─────────────────────────
  // Οι κάρτες της Αρχικής (κάθε .card ή ενότητα με data-hw) μπορούν να μετακινηθούν (drag & drop) ή να κρυφτούν.
  // Η σειρά/ορατότητα αποθηκεύεται στον browser (localStorage) — δεν αλλάζει τίποτα στον server.
  const HKEY = 'nw-homelayout';
  let HL = {}; try { HL = JSON.parse(localStorage.getItem(HKEY) || '{}'); } catch (e) { HL = {}; }
  const saveHL = () => { try { localStorage.setItem(HKEY, JSON.stringify(HL)); } catch (e) { } };
  let editing = false;
  function cardKey(c, i) {
    if (c.dataset.hw) return c.dataset.hw;
    const t = c.querySelector('h3, .ctitle, b'); const s = t ? t.textContent.replace(/[\d\s.,:%·/+\-]+/g, ' ').trim().slice(0, 40) : '';
    return s.length > 3 ? s : 'card' + i;
  }
  function homeCards(root) {
    // παίρνουμε τα «μεγάλα» κουτιά: άμεσα παιδιά του κύριου πλέγματος της Αρχικής
    const kids = [...root.children].filter(c => c.id !== 'hw-btn' && c.tagName !== 'STYLE' && c.tagName !== 'SCRIPT');
    return kids.length === 1 && kids[0].children.length > 2 ? [...kids[0].children].filter(c => c.id !== 'hw-btn') : kids;
  }
  function applyHome() {
    const root = document.getElementById('t-home'); if (!root) return;
    const cards = homeCards(root); if (cards.length < 2) return;
    const parent = cards[0].parentElement, keys = cards.map((c, i) => { const k = cardKey(c, i); c.dataset.hwk = k; return k; });
    const order = HL.order || [];
    const sorted = cards.slice().sort((a, b) => { const ia = order.indexOf(a.dataset.hwk), ib = order.indexOf(b.dataset.hwk); return (ia < 0 ? 1e3 + keys.indexOf(a.dataset.hwk) : ia) - (ib < 0 ? 1e3 + keys.indexOf(b.dataset.hwk) : ib); });
    if (sorted.some((c, i) => c !== cards[i])) sorted.forEach(c => parent.appendChild(c));
    const hid = new Set(HL.hidden || []);
    sorted.forEach(c => { const h = hid.has(c.dataset.hwk); c.classList.toggle('hw-hid', h && !editing); c.classList.toggle('hw-off', h && editing); });
    root.classList.toggle('hw-edit', editing);
    if (editing) sorted.forEach(c => {
      c.draggable = true;
      if (!c.querySelector(':scope > .hw-bar')) { const bar = document.createElement('div'); bar.className = 'hw-bar'; bar.innerHTML = `<span class="hw-grip">⠿</span><button class="hw-eye" title="εμφάνιση/απόκρυψη">${hid.has(c.dataset.hwk) ? '🙈' : '👁'}</button>`; c.prepend(bar);
        bar.querySelector('.hw-eye').onclick = ev => { ev.stopPropagation(); const s = new Set(HL.hidden || []); s.has(c.dataset.hwk) ? s.delete(c.dataset.hwk) : s.add(c.dataset.hwk); HL.hidden = [...s]; saveHL(); bar.querySelector('.hw-eye').textContent = s.has(c.dataset.hwk) ? '🙈' : '👁'; c.classList.toggle('hw-off', s.has(c.dataset.hwk)); }; }
      c.ondragstart = ev => { c.classList.add('hw-drag'); ev.dataTransfer.effectAllowed = 'move'; ev.dataTransfer.setData('text/plain', c.dataset.hwk); };
      c.ondragend = () => { c.classList.remove('hw-drag'); HL.order = [...parent.children].filter(x => x.dataset.hwk).map(x => x.dataset.hwk); saveHL(); };
      c.ondragover = ev => { ev.preventDefault(); const d = parent.querySelector('.hw-drag'); if (!d || d === c) return; const r = c.getBoundingClientRect(); const after = (ev.clientY - r.top) > r.height / 2 || (ev.clientX - r.left) > r.width * 0.66; parent.insertBefore(d, after ? c.nextSibling : c); };
    });
    else sorted.forEach(c => { c.draggable = false; const b = c.querySelector(':scope > .hw-bar'); if (b) b.remove(); });
    let btn = document.getElementById('hw-btn');
    if (!btn) { btn = document.createElement('button'); btn.id = 'hw-btn'; btn.className = 'b hw-btn'; root.appendChild(btn); }
    else if (btn.parentElement !== root || btn !== root.lastElementChild) root.appendChild(btn);
    btn.innerHTML = editing ? '✓ <span>Τέλος</span> <button class="b hw-reset" type="button">↺ <span>Αρχική διάταξη</span></button>' : '🧩 <span>Προσάρμοσε την Αρχική</span>';
    btn.onclick = ev => { if (ev.target.closest('.hw-reset')) { HL = {}; saveHL(); editing = false; if (window.renderHome) renderHome(); return; } editing = !editing; applyHome(); };
  }
  // εφαρμόζεται κάθε φορά που ξαναζωγραφίζεται η Αρχική (το index.html ξαναγράφει το innerHTML)
  const wrapHome = () => {
    if (typeof window.renderHome !== 'function' || window.renderHome.__hw) return;
    const orig = window.renderHome;
    const f = function () { if (editing && document.querySelector('#t-home .hw-drag')) return; const r = orig.apply(this, arguments); try { applyHome(); } catch (e) { } return r; };
    f.__hw = 1; window.renderHome = f;
  };

  // ───────────────────────── 🧭 Ξενάγηση ─────────────────────────
  const TOUR = [
    { sel: '#rail, #rail-btn', t: 'Το μενού', d: 'Όλες οι ενότητες του NetWatch: Προστασία, το δίκτυό σου, εργαλεία, μάθηση. Στο κινητό ανοίγει από το ☰.' },
    { sel: '#pps', t: 'Ζωντανά νούμερα', d: 'Πακέτα ανά δευτερόλεπτο, κίνηση, πόσες συσκευές βλέπουμε και πόσες επιθέσεις πιάσαμε — ενημερώνονται συνέχεια.' },
    { tab: 'home', sel: '#t-home', t: 'Αρχική', d: 'Η σύνοψη: βαθμός ασφάλειας, τι έγινε πρόσφατα, νέες συσκευές. Με το «🧩 Προσάρμοσε» βάζεις τις κάρτες στη σειρά που θες.' },
    { tab: 'alerts', sel: '#t-alerts', t: 'Επιθέσεις', d: 'Κάθε ύποπτο γεγονός εξηγείται με απλά λόγια: τι έγινε, πόσο σοβαρό είναι και τι να κάνεις.' },
    { tab: 'tm', sel: '#t-tm .tm-strip', t: 'Μηχανή του χρόνου', d: 'Σύρε το slider για να δεις το δίκτυο όπως ήταν οποιοδήποτε λεπτό σήμερα — ή πάτα ▶ και δες τη μέρα σαν βίντεο.' },
    { tab: 'pentest', sel: '#t-pentest', t: 'Pentest & purple team', d: 'Σάρωσε το ΔΙΚΟ σου δίκτυο, τρέξε ασφαλείς προσομοιωμένες επιθέσεις και δες αν τις πιάνει η άμυνα.' },
    { tab: 'cli', sel: '#t-cli .cl-term', t: 'Cisco Lab', d: 'Εξάσκηση για CCNA: γράψε εντολές IOS σαν σε πραγματικό router και λύσε τις ασκήσεις.' },
    { sel: '#cmdk-btn', t: 'Γρήγορη αναζήτηση', d: 'Πάτα ⌘K (ή Ctrl+K) από παντού για να πας σε οποιαδήποτε ενότητα ή συσκευή.' },
  ];
  let TI = -1;
  function tourEl(s) { return s.sel.split(',').map(x => document.querySelector(x.trim())).find(e => e && e.getBoundingClientRect().width > 0); }
  function tourShow(i) {
    tourEnd(true);
    const step = TOUR[i]; if (!step) return tourEnd();
    TI = i;
    if (step.tab && window.showTab && curTab() !== step.tab) { try { showTab(step.tab); } catch (e) { } }
    setTimeout(() => {
      const el = tourEl(step);
      if (!el) { if (i + 1 < TOUR.length) return tourShow(i + 1); return tourEnd(); }
      el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      setTimeout(() => {
        // 🔠 με «μέγεθος γραμμάτων» το body έχει zoom: οι συντεταγμένες οθόνης ÷ zoom = μονάδες μέσα στο body
        const z = +getComputedStyle(document.body).zoom || 1, q = el.getBoundingClientRect(), pad = 6;
        const r = { left: q.left / z, top: q.top / z, right: q.right / z, bottom: q.bottom / z, width: q.width / z, height: q.height / z };
        const innerWidth = window.innerWidth / z, innerHeight = window.innerHeight / z;
        const ov = document.createElement('div'); ov.className = 'tour-ov'; ov.innerHTML = `<div class="tour-hole" style="left:${r.left - pad}px;top:${Math.max(0, r.top - pad)}px;width:${Math.min(innerWidth - r.left + pad, r.width + pad * 2)}px;height:${Math.min(innerHeight - Math.max(0, r.top - pad), r.height + pad * 2)}px"></div>`;
        const pop = document.createElement('div'); pop.className = 'tour-pop';
        pop.innerHTML = `<div class="tour-n">${i + 1} / ${TOUR.length}</div><b>${E(step.t)}</b><div class="tour-d">${E(step.d)}</div><div class="tour-b"><button class="b" data-tskip>Παράλειψη</button><span style="flex:1"></span>${i ? '<button class="b" data-tprev>←</button>' : ''}<button class="b tour-next" data-tnext>${i + 1 < TOUR.length ? 'Επόμενο →' : '✓ Τέλος'}</button></div>`;
        document.body.append(ov, pop);
        const pw = Math.min(330, innerWidth - 24), below = r.bottom + 12 + 170 < innerHeight;
        let left = Math.min(innerWidth - pw - 12, Math.max(12, r.left + r.width / 2 - pw / 2)), top = below ? Math.min(innerHeight - 180, r.bottom + 12) : Math.max(12, r.top - 12 - pop.offsetHeight);
        if (r.height > innerHeight * 0.6) { top = Math.min(innerHeight - pop.offsetHeight - 16, Math.max(16, r.top + 40)); left = r.right + pw + 28 < innerWidth && r.width < innerWidth * 0.4 ? r.right + 16 : Math.min(innerWidth - pw - 24, r.left + 24); }
        Object.assign(pop.style, { left: left + 'px', top: top + 'px', width: pw + 'px' });
        ov.onclick = () => tourShow(i + 1);
        pop.querySelector('[data-tnext]').onclick = () => tourShow(i + 1);
        pop.querySelector('[data-tskip]').onclick = () => tourEnd();
        const pv = pop.querySelector('[data-tprev]'); if (pv) pv.onclick = () => tourShow(i - 1);
        pop.querySelector('[data-tnext]').focus();
      }, 260);
    }, step.tab ? 350 : 0);
  }
  function tourEnd(keep) {
    document.querySelectorAll('.tour-ov,.tour-pop').forEach(e => e.remove());
    if (!keep) { TI = -1; try { localStorage.setItem('nw-tour', 'done'); } catch (e) { } }
  }
  window.startTour = () => tourShow(0);
  document.addEventListener('keydown', ev => {
    if (TI < 0) return;
    if (ev.key === 'Escape') tourEnd();
    else if (ev.key === 'ArrowRight' || ev.key === 'Enter') { ev.preventDefault(); tourShow(TI + 1); }
    else if (ev.key === 'ArrowLeft' && TI > 0) tourShow(TI - 1);
  });
  window.addEventListener('resize', () => { if (TI >= 0) tourShow(TI); });

  window.addEventListener('load', () => {
    wrapHome();
    setTimeout(() => { wrapHome(); if (curTab() === 'home') try { applyHome(); } catch (e) { } }, 800);
    let seen = null; try { seen = localStorage.getItem('nw-tour'); } catch (e) { }
    const qs = new URLSearchParams(location.search);
    if ((!seen && !qs.has('notour') && !navigator.webdriver) || qs.has('tour')) setTimeout(() => window.startTour(), 1800);
  });

  const css = `
  .tm-strip{margin-top:10px;position:relative}.tm-svg{width:100%;height:86px;display:block;cursor:crosshair;touch-action:none}
  .tm-bar{fill:color-mix(in srgb,var(--cyan) 55%,transparent)}.tm-grid{stroke:rgb(var(--w) / 8%);stroke-width:1;vector-effect:non-scaling-stroke}
  .tm-hl{fill:var(--dim);font-size:10px;font-family:ui-monospace,Menlo,Consolas,monospace}
  .tm-cl{stroke:var(--hi,#fff);stroke-width:2;vector-effect:non-scaling-stroke}.tm-win{fill:rgb(var(--w) / 10%)}
  .tm-range{width:100%;margin:6px 0 2px;accent-color:var(--cyan)}
  .tm-ctl{display:flex;flex-wrap:wrap;gap:4px;align-items:center}.tm-ctl .b.on{background:color-mix(in srgb,var(--cyan) 22%,transparent);border-color:var(--cyan)}
  .tm-play{min-width:42px;font-size:15px}.tm-sp{flex:1}
  .tm-when{display:flex;gap:8px;align-items:baseline}.tm-when b{font-size:20px;font-variant-numeric:tabular-nums}
  .tm-body{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:12px;align-items:start;margin-top:12px}
  @media (max-width:1100px){.tm-body{grid-template-columns:1fr}}
  .tm-gcard{padding:4px}.tm-g{width:100%;height:auto;display:block}
  .tm-ring{fill:none;stroke:rgb(var(--w) / 6%);stroke-dasharray:3 5}.tm-spoke{stroke:rgb(var(--w) / 10%);stroke-width:1}
  .tm-e{fill:none;stroke:color-mix(in srgb,var(--cyan) 60%,transparent);stroke-linecap:round;stroke-dasharray:3 9;animation:tmflow 2s linear infinite}
  .tm-e.lan{stroke:color-mix(in srgb,var(--purple) 70%,transparent)}.tm-e.bad{stroke:var(--red)}
  @keyframes tmflow{to{stroke-dashoffset:-24}}html.nomo .tm-e{animation:none;stroke-dasharray:none}
  .tm-n circle{fill:var(--bg2,#0d1420);stroke:rgb(var(--w) / 30%);stroke-width:1.5}.tm-n.dev.me circle{stroke:var(--cyan);stroke-width:2.5}.tm-n.gw circle{stroke:var(--cyan)}
  .tm-n.peer circle{fill:color-mix(in srgb,var(--cyan) 70%,transparent);stroke:none}.tm-n.peer.bad circle{fill:var(--red)}
  .tm-ic{font-size:15px;pointer-events:none}.tm-nl{fill:currentColor;font-size:11.5px;font-weight:600}.tm-pl{fill:var(--dim);font-size:10.5px}
  .tm-n.peer.bad .tm-pl{fill:var(--red);font-weight:700}.tm-empty{fill:var(--dim);font-size:14px}
  .tm-side{display:flex;flex-direction:column;gap:12px}.tm-side .card{margin:0}
  .tm-dr{display:flex;gap:8px;align-items:center;font-size:12.5px;padding:4px 0;border-top:1px solid rgb(var(--w) / 6%)}
  .tm-dn{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.tm-v{flex:none;min-width:60px;text-align:right;font-variant-numeric:tabular-nums}
  .tm-bb{flex:0 0 70px;height:5px;border-radius:3px;background:rgb(var(--w) / 8%);overflow:hidden}.tm-bb i{display:block;height:100%;background:var(--cyan)}
  .tm-al{padding:5px 8px;margin-top:6px;border-left:3px solid var(--c);background:color-mix(in srgb,var(--c) 9%,transparent);border-radius:0 6px 6px 0;font-size:12.5px}
  .hw-btn{margin:14px auto 4px;display:flex;gap:6px;align-items:center;opacity:.8}.hw-btn:hover{opacity:1}.hw-reset{margin-left:8px}
  .hw-hid{display:none!important}
  .hw-edit [data-hwk]{outline:1.5px dashed color-mix(in srgb,var(--cyan) 55%,transparent);outline-offset:3px;cursor:grab;position:relative}
  .hw-edit [data-hwk].hw-off{opacity:.35}.hw-edit [data-hwk].hw-drag{opacity:.5;cursor:grabbing}
  .hw-bar{position:absolute;top:4px;right:6px;z-index:5;display:flex;gap:6px;align-items:center;background:var(--bg2,#0d1420);border:1px solid var(--line);border-radius:8px;padding:2px 6px}
  .hw-grip{color:var(--dim);font-size:14px;cursor:grab}.hw-eye{background:none;border:0;cursor:pointer;font-size:14px;color:inherit;padding:0}
  .tour-ov{position:fixed;inset:0;z-index:9998}.tour-hole{position:fixed;border-radius:10px;box-shadow:0 0 0 9999px rgba(2,6,14,.62);outline:2px solid var(--cyan);transition:all .25s;pointer-events:none}
  .tour-pop{position:fixed;z-index:9999;background:var(--bg2,#0d1420);border:1px solid var(--cyan);border-radius:12px;padding:14px 16px;box-shadow:0 12px 40px rgba(0,0,0,.5);font-size:13.5px;animation:tourIn .25s ease}
  html.nomo .tour-pop{animation:none}@keyframes tourIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
  .tour-pop b{font-size:15px;display:block;margin-bottom:4px}.tour-d{color:var(--dim);line-height:1.5}.tour-n{font-size:11px;color:var(--cyan);margin-bottom:4px}
  .tour-b{display:flex;gap:6px;margin-top:12px;align-items:center}.tour-next{border-color:var(--cyan)}`;
  const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);
})();
