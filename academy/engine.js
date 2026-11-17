// NetWatch Ακαδημία — μηχανή μαθημάτων.
// Το περιεχόμενο (academy/*.js) καλεί ACADEMY.track({...}). Δες τη μορφή στο academy/FORMAT.md.
(function () {
  'use strict';
  const A = window.ACADEMY = { tracks: [], scenes: {}, _loaded: false };
  // ίδιο id σε δύο αρχεία (π.χ. ccna-1.js, ccna-2.js) → ενώνονται οι ενότητες, ταξινομημένες κατά `order`
  A.track = t => { const o = A.tracks.find(x => x.id === t.id);
    if (!o) { A.tracks.push(t); t.modules = t.modules || []; }
    else { for (const k in t) if (k !== 'modules' && t[k] != null && o[k] == null) o[k] = t[k]; o.modules = o.modules.concat(t.modules || []); }
    const tr = o || t; tr.modules.sort((a, b) => (a.order || 0) - (b.order || 0)); A.tracks.sort((a, b) => (a.order || 0) - (b.order || 0)); };
  A.scene = (id, sc) => { A.scenes[id] = sc; };

  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = id => document.getElementById(id);

  // ---------- πρόοδος ----------
  let P = {};
  try { P = JSON.parse(localStorage.getItem('nw-academy') || '{}'); } catch (e) { P = {}; }
  P.done = P.done || {}; P.quiz = P.quiz || {};
  const save = () => { try { localStorage.setItem('nw-academy', JSON.stringify(P)); } catch (e) { } };
  const lessonsOf = t => t.modules.flatMap(m => m.lessons);
  const pct = ls => ls.length ? Math.round(100 * ls.filter(l => P.done[l.id]).length / ls.length) : 0;

  // ---------- markdown-lite ----------
  function inline(s) {
    const codes = [];  // τα `code` φυλάγονται πρώτα, ώστε ένα * μέσα τους να μη γίνει πλάγιο
    return E(s).replace(/`([^`]+)`/g, (m, c) => { codes.push(c); return '\uE000' + (codes.length - 1) + '\uE001'; })
      .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/(^|[^*])\*([^*\s][^*]*)\*/g, '$1<i>$2</i>')
      .replace(/\uE000(\d+)\uE001/g, (m, i) => '<code>' + codes[i] + '</code>');
  }
  function md(src) {
    const out = []; let list = null;
    for (const raw of String(src || '').split('\n')) {
      const line = raw.trimEnd();
      const li = line.match(/^\s*(?:[-•]|\d+\.)\s+(.*)/);
      if (li) { if (!list) { list = []; } list.push('<li>' + inline(li[1]) + '</li>'); continue; }
      if (list) { out.push('<ul>' + list.join('') + '</ul>'); list = null; }
      if (!line.trim()) continue;
      const h = line.match(/^(#{2,4})\s+(.*)/);
      out.push(h ? `<h${h[1].length + 1} class="ac-h">${inline(h[2])}</h${h[1].length + 1}>` : '<p>' + inline(line) + '</p>');
    }
    if (list) out.push('<ul>' + list.join('') + '</ul>');
    return out.join('');
  }
  A.md = md;

  // ---------- απλό syntax highlighting ----------
  const KW = {
    cpp: /\b(void|int|bool|char|const|return|if|else|for|while|include|define|auto|static|uint8_t|uint16_t|uint32_t|String|true|false|nullptr|struct|class|public|private|unsigned|long|float|double)\b/g,
    python: /\b(def|return|if|elif|else|for|while|import|from|as|with|try|except|finally|class|True|False|None|and|or|not|in|is|lambda|yield|async|await|pass|raise)\b/g,
    bash: /\b(sudo|apt|echo|cd|ls|cat|grep|chmod|chown|systemctl|ufw|iptables|nmap|ssh|scp|nano|export|if|then|fi|for|do|done)\b/g,
    cisco: /\b(enable|configure|terminal|conf|interface|int|ip|address|no|shutdown|router|network|vlan|switchport|mode|access|trunk|show|exit|end|hostname|line|password|login|transport|crypto|username|secret|access-list|permit|deny|ospf|area|spanning-tree|channel-group|description|encapsulation|nat|inside|outside|overload|default-gateway|service|copy|running-config|startup-config|write|ping|traceroute|debug|ipv6|standby|dhcp|pool|default-router|dns-server|excluded-address|logging|ntp|snmp-server|aaa|vty|console|port-security|maximum|violation|sticky|native|allowed)\b/g,
  };
  KW.micropython = KW.python; KW.arduino = KW.cpp; KW.c = KW.cpp; KW.yaml = null; KW.json = null; KW.text = null;
  function hl(code, lang) {
    // Τα strings/σχόλια φυλάγονται σε placeholders (χαρακτήρες private-use) για να μην τα «χρωματίσουν» οι επόμενοι κανόνες
    const keep = [], ph = (html) => { keep.push(html); return String.fromCharCode(0xE000 + keep.length - 1); };
    let s = E(code);
    s = s.replace(/(&quot;.*?&quot;|&#39;.*?&#39;)/g, m => ph('<span class="ac-str">' + m + '</span>'));
    const cm = lang === 'cisco' ? /(^|\n)(!.*)/g : lang === 'cpp' || lang === 'arduino' || lang === 'c' ? /()(\/\/.*)/g : /()(#.*)/g;
    s = s.replace(cm, (m, a, b) => a + ph('<span class="ac-com">' + b + '</span>'));
    const kw = KW[lang]; if (kw) s = s.replace(kw, '<span class="ac-kw">$1</span>');
    s = s.replace(/(?<![&#\w-])(\d+(?:\.\d+)*)\b/g, '<span class="ac-num">$1</span>');
    return s.replace(/[\uE000-\uF8FF]/g, c => keep[c.charCodeAt(0) - 0xE000]);
  }

  // ---------- animation: τοπολογία + πακέτα που ταξιδεύουν, βήμα-βήμα ----------
  const MARK = { ok: '#3ddc97', bad: '#ff3b5c', hl: '#ffd23f', info: '#3ec5ff' };
  function Anim(host, sc) {
    if (typeof sc === 'string') sc = A.scenes[sc];
    if (!sc) { host.innerHTML = '<div class="sm">(λείπει το animation)</div>'; return; }
    const W = sc.w || 640, H = sc.h || 260, nodes = {};
    (sc.nodes || []).forEach(n => nodes[n.id] = n);
    host.innerHTML = `<div class="ac-anim"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet"></svg>
      <div class="ac-say"></div><div class="ac-tables"></div>
      <div class="ac-ctl"><button class="b" data-a="first">⏮</button><button class="b" data-a="prev">◀</button><button class="b ac-play" data-a="play">▶ Παίξε</button><button class="b" data-a="next">▶|</button><span class="ac-stepn"></span></div></div>`;
    const svg = host.querySelector('svg'), say = host.querySelector('.ac-say'), tbl = host.querySelector('.ac-tables'), stepn = host.querySelector('.ac-stepn');
    const NS = 'http://www.w3.org/2000/svg';
    const mk = (tag, at, parent) => { const e = document.createElementNS(NS, tag); for (const k in at) e.setAttribute(k, at[k]); (parent || svg).appendChild(e); return e; };
    const gL = mk('g', {}), gN = mk('g', {}), gP = mk('g', {});
    (sc.links || []).forEach(l => { const a = nodes[l[0]], b = nodes[l[1]]; if (!a || !b) return;
      mk('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: l[3] || '#2a4466', 'stroke-width': 2, 'stroke-dasharray': l[2] === 'wifi' ? '5 5' : '' }, gL);
      if (l[2] && l[2] !== 'wifi') { const t = mk('text', { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - 5, 'text-anchor': 'middle', fill: '#6d7f99', 'font-size': 10 }, gL); t.textContent = l[2]; } });
    const nEl = {};
    Object.values(nodes).forEach(n => {
      const g = mk('g', { transform: `translate(${n.x},${n.y})` }, gN);
      const r = mk('rect', { x: -(n.w || 64) / 2, y: -22, width: n.w || 64, height: 44, rx: 8, fill: '#101828', stroke: '#2a4466', 'stroke-width': 1.5 }, g);
      const ic = mk('text', { y: -2, 'text-anchor': 'middle', 'font-size': 18 }, g); ic.textContent = n.icon || '⬛';
      const lines = String(n.label || n.id).split('\n');
      lines.forEach((ln, i) => { const t = mk('text', { y: 36 + i * 12, 'text-anchor': 'middle', fill: i ? '#6d7f99' : '#cfe0f5', 'font-size': i ? 9.5 : 11 }, g); t.textContent = ln; });
      nEl[n.id] = r;
    });
    const steps = sc.steps || []; let i = -1, timer = null, anims = [];
    function tablesAt(k) { // κατάσταση πινάκων μέχρι και το βήμα k
      const T = {}; (sc.tables || []).forEach(t => T[t.id] = { ...t, rows: (t.rows || []).slice() });
      for (let j = 0; j <= k; j++) { const st = steps[j]; if (st && st.table) for (const id in st.table) if (T[id]) T[id].rows = st.table[id].slice(); }
      return Object.values(T);
    }
    function marksAt(k) { const M = {}; for (let j = 0; j <= k; j++) { const st = steps[j]; if (st && st.mark) Object.assign(M, st.mark); } return M; }
    function draw(k, animate) {
      anims.forEach(cancelAnimationFrame); anims = []; gP.innerHTML = '';
      const st = steps[k];
      say.innerHTML = k < 0 ? `<span class="sm">${md(sc.intro || 'Πάτα ▶ για να ξεκινήσει.')}</span>` : `<b style="color:#3ec5ff">${k + 1}.</b> ${md(st.say || '').replace(/^<p>|<\/p>$/g, '')}`;
      stepn.textContent = `${Math.max(0, k + 1)}/${steps.length}`;
      const M = marksAt(k);
      for (const id in nEl) { const m = M[id]; nEl[id].setAttribute('stroke', m ? MARK[m] || m : '#2a4466'); nEl[id].setAttribute('stroke-width', m ? 2.5 : 1.5); }
      tbl.innerHTML = tablesAt(k).map(t => `<div class="ac-tbl"><div class="sm">${E(t.title)}</div><table><thead><tr>${t.head.map(h => `<th>${E(h)}</th>`).join('')}</tr></thead><tbody>${t.rows.length ? t.rows.map(r => `<tr>${r.map(c => `<td>${E(c)}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${t.head.length}" class="sm">(κενός)</td></tr>`}</tbody></table></div>`).join('');
      if (!st || !st.from) return;
      const tos = Array.isArray(st.to) ? st.to : [st.to];
      tos.forEach(to => {
        const path = [st.from, ...(st.via || []), to].map(id => nodes[id]).filter(Boolean); if (path.length < 2) return;
        const col = st.color || '#3ec5ff';
        const g = mk('g', {}, gP); const c = mk('circle', { r: 7, fill: col }, g);
        const lb = mk('text', { y: -11, 'text-anchor': 'middle', fill: col, 'font-size': 10.5, 'font-weight': 700 }, g); lb.textContent = st.pkt || '';
        const seg = []; let tot = 0; for (let s = 0; s < path.length - 1; s++) { const d = Math.hypot(path[s + 1].x - path[s].x, path[s + 1].y - path[s].y); seg.push(d); tot += d; }
        const dur = animate ? Math.max(700, Math.min(2200, tot * 4)) : 0, t0 = performance.now();
        const place = f => { let d = f * tot, s = 0; while (s < seg.length - 1 && d > seg[s]) { d -= seg[s]; s++; }
          const a = path[s], b = path[s + 1], u = seg[s] ? Math.min(1, d / seg[s]) : 1, up = f >= 1 ? 34 : 0; /* στο τέλος ανεβαίνει πάνω από τον κόμβο για να μη τον κρύβει */ g.setAttribute('transform', `translate(${a.x + (b.x - a.x) * u},${a.y + (b.y - a.y) * u - up})`); };
        if (!dur) { place(1); return; }
        const tick = now => { const f = Math.min(1, (now - t0) / dur); place(f); if (f < 1) anims.push(requestAnimationFrame(tick)); else if (st.drop) { c.setAttribute('fill', '#ff3b5c'); lb.textContent = '✖ ' + (st.pkt || ''); } };
        anims.push(requestAnimationFrame(tick));
      });
    }
    function go(k, an) { i = Math.max(-1, Math.min(steps.length - 1, k)); draw(i, an); }
    function stop() { if (timer) { clearInterval(timer); timer = null; } host.querySelector('.ac-play').textContent = '▶ Παίξε'; }
    host.querySelector('.ac-ctl').onclick = e => {
      const a = e.target.dataset.a; if (!a) return;
      if (a === 'play') { if (timer) return stop(); if (i >= steps.length - 1) go(-1);
        e.target.textContent = '⏸ Παύση'; go(i + 1, true); timer = setInterval(() => { if (i >= steps.length - 1) return stop(); go(i + 1, true); }, sc.speed || 2600); return; }
      stop(); if (a === 'first') go(-1); if (a === 'prev') go(i - 1, true); if (a === 'next') go(i + 1, true);
    };
    go(-1);
  }
  A.Anim = Anim;

  // ---------- προσομοιωτής Cisco IOS (καθοδηγούμενος) ----------
  function Cli(host, b) {
    const steps = b.steps || []; let k = 0;
    host.innerHTML = `<div class="ac-cli"><div class="ac-term"></div><div class="ac-task"></div>
      <div style="display:flex;gap:6px;margin-top:6px"><span class="ac-prompt"></span><input class="ac-in" spellcheck="false" autocomplete="off" autocapitalize="off"><button class="b ac-hint">💡</button></div></div>`;
    const term = host.querySelector('.ac-term'), task = host.querySelector('.ac-task'), prompt = host.querySelector('.ac-prompt'), inp = host.querySelector('.ac-in');
    const print = (t, cls) => { const d = document.createElement('div'); if (cls) d.className = cls; d.textContent = t; term.appendChild(d); term.scrollTop = 1e9; };
    if (b.banner) print(b.banner, 'sm');
    let pr = b.prompt || 'Router>';
    const show = () => { prompt.textContent = pr;
      if (k >= steps.length) { task.innerHTML = '✅ <b>Το lab ολοκληρώθηκε!</b>' + (b.done ? ' ' + md(b.done) : ''); inp.disabled = true; return; }
      task.innerHTML = `<b style="color:#ffd23f">Βήμα ${k + 1}/${steps.length}:</b> ${inline(steps[k].task)}`; };
    host.querySelector('.ac-hint').onclick = () => { if (k < steps.length) task.innerHTML += `<div class="sm">Απάντηση: <code>${E(steps[k].ans || steps[k].expect)}</code></div>`; };
    inp.onkeydown = e => {
      if (e.key !== 'Enter') return; const v = inp.value.trim(); inp.value = ''; if (!v) return;
      print(pr + ' ' + v); const st = steps[k]; if (!st) return;
      let ok = false; try { ok = new RegExp(st.expect, 'i').test(v); } catch (er) { ok = v.toLowerCase() === String(st.ans || '').toLowerCase(); }
      if (ok) { if (st.out) print(st.out, 'ac-out'); if (st.next) pr = st.next; k++; }
      else print(st.err || '% Invalid input detected — δοκίμασε ξανά (💡 για βοήθεια)', 'ac-err');
      show();
    };
    show();
  }

  // ---------- εξάσκηση subnetting ----------
  function Subnet(host) {
    const ip2n = s => s.split('.').reduce((a, x) => a * 256 + (+x), 0), n2ip = n => [24, 16, 8, 0].map(b => Math.floor(n / 2 ** b) % 256).join('.');
    let q;
    function newQ() {
      const pre = [8, 12, 16, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30][Math.random() * 14 | 0];
      const ip = [10, 172, 192][Math.random() * 3 | 0] + '.' + (Math.random() * 256 | 0) + '.' + (Math.random() * 256 | 0) + '.' + (1 + Math.random() * 254 | 0);
      const size = 2 ** (32 - pre), net = Math.floor(ip2n(ip) / size) * size;
      q = { ip, pre, net: n2ip(net), bc: n2ip(net + size - 1), first: n2ip(net + 1), last: n2ip(net + size - 2), hosts: size - 2, mask: n2ip(2 ** 32 - size) };
      host.innerHTML = `<div class="ac-sub"><div style="font-size:15px;color:#fff;margin-bottom:6px">Διεύθυνση: <b>${q.ip}/${q.pre}</b></div>
        ${[['mask', 'Μάσκα (π.χ. 255.255.255.0)'], ['net', 'Διεύθυνση δικτύου'], ['bc', 'Broadcast'], ['first', 'Πρώτος host'], ['last', 'Τελευταίος host'], ['hosts', 'Πόσοι hosts']].map(([k, l]) => `<label class="ac-row"><span>${l}</span><input data-k="${k}" spellcheck="false"></label>`).join('')}
        <div style="margin-top:6px"><button class="b" data-a="chk">✔ Έλεγχος</button> <button class="b" data-a="new">↻ Νέα</button> <button class="b" data-a="show">👁 Λύση</button></div><div class="ac-subres"></div></div>`;
      host.querySelector('[data-a="new"]').onclick = newQ;
      host.querySelector('[data-a="chk"]').onclick = () => { let good = 0;
        host.querySelectorAll('input').forEach(x => { const ok = x.value.trim() === String(q[x.dataset.k]); x.style.borderColor = ok ? '#3ddc97' : '#ff3b5c'; good += ok; });
        host.querySelector('.ac-subres').innerHTML = good === 6 ? '✅ Τέλεια!' : `<span class="sm">${good}/6 σωστά</span>`; };
      host.querySelector('[data-a="show"]').onclick = () => {
        const bits = 32 - q.pre;
        host.querySelector('.ac-subres').innerHTML = md(`**Λύση:** /${q.pre} → ${bits} bits για hosts → μέγεθος μπλοκ **${2 ** bits}** διευθύνσεις.\n- Μάσκα: \`${q.mask}\`\n- Δίκτυο: \`${q.net}\` (στρογγυλεύουμε προς τα κάτω στο πολλαπλάσιο του μπλοκ)\n- Broadcast: \`${q.bc}\` (δίκτυο + μπλοκ − 1)\n- Hosts: \`${q.first}\` – \`${q.last}\` → **${q.hosts}** (2^${bits} − 2)`); };
    }
    newQ();
  }

  // ---------- blocks ----------
  function block(b, lid, n) {
    const id = `${lid}-${n}`;
    switch (b.t) {
      case 'text': return `<div class="ac-text">${md(b.md)}</div>`;
      case 'tip': return `<div class="ac-box ac-tip">💡 ${md(b.md)}</div>`;
      case 'warn': return `<div class="ac-box ac-warn">⚠️ ${md(b.md)}</div>`;
      case 'exam': return `<div class="ac-box ac-exam">🎯 <b>Για την εξέταση:</b> ${md(b.md)}</div>`;
      case 'table': return `<table class="ac-table"><thead><tr>${b.head.map(h => `<th>${inline(h)}</th>`).join('')}</tr></thead><tbody>${b.rows.map(r => `<tr>${r.map(c => `<td>${inline(c)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
      case 'code': return `<div class="ac-code"><div class="ac-codeh"><span>${E(b.title || b.lang || 'κώδικας')}</span><span class="sm">${E(b.lang || '')}</span><button class="b" data-copy="${id}">📋 Αντιγραφή</button></div><pre id="cp-${id}">${hl(b.code, b.lang)}</pre>${b.explain ? `<div class="ac-explain">${md(b.explain)}</div>` : ''}</div>`;
      case 'anim': return `<div class="ac-animh" data-anim="${id}"></div>${b.caption ? `<div class="sm" style="margin:-4px 0 10px">${inline(b.caption)}</div>` : ''}`;
      case 'cli': return `<div class="ac-blockt">🖥 ${E(b.title || 'Lab στον προσομοιωτή IOS')}</div><div data-cli="${id}"></div>`;
      case 'subnet': return `<div class="ac-blockt">🧮 Εξάσκηση subnetting</div><div data-subnet="${id}"></div>`;
      case 'netwatch': return `<div class="ac-box ac-nw">🛰 <b>Δες το στο NetWatch:</b> ${md(b.md)}<button class="b" data-gotab="${E(b.tab)}">Άνοιγμα →</button></div>`;
      case 'quiz': {
        const done = P.quiz[id];
        return `<div class="ac-quiz" data-quiz="${id}"><div class="ac-q">❓ ${inline(b.q)}</div>${b.opts.map((o, i) => `<button class="b ac-opt${done != null ? (i === b.ok ? ' ok' : i === done ? ' bad' : '') : ''}" data-i="${i}" ${done != null ? 'disabled' : ''}>${inline(o)}</button>`).join('')}<div class="ac-why">${done != null ? (done === b.ok ? '✅ ' : '❌ ') + md(b.why || '') : ''}</div></div>`;
      }
      default: return '';
    }
  }

  // ---------- UI ----------
  let view = { track: null };
  function load(cb) {
    if (A._loaded) return cb();
    fetch('/api/academy').then(r => r.json()).then(j => {
      let left = j.files.length; if (!left) { A._loaded = true; return cb(); }
      j.files.forEach(f => { const s = document.createElement('script'); s.async = false; s.src = '/academy/' + f; s.onload = s.onerror = () => { if (--left === 0) { A._loaded = true; cb(); } }; document.head.appendChild(s); });
    }).catch(() => { A._loaded = true; cb(); });
  }
  A.render = function (el) {
    if (!A._loaded) { el.innerHTML = '<div class="empty">φόρτωση μαθημάτων…</div>'; return load(() => A.render(el)); }
    if (!A.tracks.length) { el.innerHTML = '<div class="empty">Δεν βρέθηκαν μαθήματα στον φάκελο academy/</div>'; return; }
    const t = A.tracks.find(x => x.id === view.track);
    if (!t) {
      el.innerHTML = `<div class="card" style="white-space:normal"><b style="color:#fff">🎓 Ακαδημία</b><div class="sm" style="margin-top:3px">Μαθήματα βήμα-βήμα με animations, κώδικα, κουίζ και labs. Η πρόοδος αποθηκεύεται σε αυτόν τον browser.</div></div>` +
        A.tracks.map(t => { const ls = lessonsOf(t), p = pct(ls);
          return `<div class="card ac-track" data-track="${E(t.id)}" style="cursor:pointer;white-space:normal"><div style="display:flex;justify-content:space-between;gap:8px"><b style="color:#fff;font-size:13px">${E(t.title)}</b><span class="tag">${E(t.level || '')}</span></div>
          <div class="sm" style="margin:4px 0 6px">${E(t.desc || '')}</div>${bar(p)}<div class="sm" style="margin-top:3px">${t.modules.length} ενότητες · ${ls.length} μαθήματα · ${p}% ολοκληρωμένο</div></div>`; }).join('');
      el.querySelectorAll('[data-track]').forEach(c => c.onclick = () => { view.track = c.dataset.track; A.render(el); });
      return;
    }
    const all = lessonsOf(t), nextL = all.find(l => !P.done[l.id]);
    el.innerHTML = `<div style="display:flex;gap:6px;align-items:center;margin-bottom:8px"><button class="b" data-back>← Όλα τα μαθήματα</button>${nextL ? `<button class="b" data-open="${E(nextL.id)}" style="border-color:#3ddc97">▶ Συνέχεια: ${E(nextL.title.slice(0, 32))}</button>` : '<span class="tag g">✅ ολοκληρώθηκε</span>'}</div>
      <div class="card" style="white-space:normal"><b style="color:#fff;font-size:13px">${E(t.title)}</b><div class="sm" style="margin:3px 0 6px">${E(t.desc || '')}</div>${bar(pct(all))}</div>` +
      t.modules.map((m, mi) => { const p = pct(m.lessons);
        return `<div class="card" style="white-space:normal"><div style="display:flex;justify-content:space-between;gap:6px"><b style="color:#fff">${mi + 1}. ${E(m.title)}</b><span class="sm">${p}%</span></div>${m.exam ? `<div class="sm" style="color:#b388ff">🎯 ${E(m.exam)}</div>` : ''}${m.desc ? `<div class="sm" style="margin-top:2px">${E(m.desc)}</div>` : ''}
        <div style="margin-top:6px">${m.lessons.map((l, li) => `<div class="ac-li" data-open="${E(l.id)}">${P.done[l.id] ? '✅' : '○'} <span>${mi + 1}.${li + 1} ${E(l.title)}</span><span class="sm">${l.minutes ? l.minutes + "′" : ''}${l.blocks.some(b => b.t === 'anim') ? ' 🎬' : ''}${l.blocks.some(b => b.t === 'code') ? ' 💻' : ''}${l.blocks.some(b => b.t === 'cli') ? ' 🖥' : ''}</span></div>`).join('')}</div></div>`; }).join('');
    el.querySelector('[data-back]').onclick = () => { view.track = null; A.render(el); };
    el.querySelectorAll('[data-open]').forEach(x => x.onclick = () => openLesson(t, x.dataset.open, () => A.render(el)));
  };
  const bar = p => `<div style="height:6px;background:#1f3352;border-radius:3px;overflow:hidden"><div style="height:100%;width:${p}%;background:linear-gradient(90deg,#3ec5ff,#3ddc97)"></div></div>`;

  function openLesson(t, lid, onClose) {
    const all = lessonsOf(t), idx = all.findIndex(l => l.id === lid), l = all[idx];
    const m = t.modules.find(m => m.lessons.includes(l)), mi = t.modules.indexOf(m) + 1, li = m.lessons.indexOf(l) + 1;
    let ov = $('ac-overlay');
    if (!ov) { ov = document.createElement('div'); ov.id = 'ac-overlay'; document.body.appendChild(ov); }
    ov.innerHTML = `<div class="ac-win"><div class="ac-top"><span class="sm">${E(t.title)} › ${mi}. ${E(m.title)}</span><button class="b" data-x>✕ Κλείσιμο</button></div>
      <div class="ac-body"><h2 class="ac-title">${mi}.${li} ${E(l.title)}</h2>${l.goal ? `<div class="ac-box ac-goal">🎯 <b>Τι θα μάθεις:</b> ${md(l.goal)}</div>` : ''}
      ${l.blocks.map((b, n) => block(b, l.id, n)).join('')}
      <div class="ac-foot"><button class="b" data-nav="${idx - 1}" ${idx ? '' : 'disabled'}>← Προηγούμενο</button>
      <button class="b ac-done" data-done>${P.done[l.id] ? '✅ Ολοκληρώθηκε' : '✔ Το έμαθα'}</button>
      <button class="b" data-nav="${idx + 1}" ${idx < all.length - 1 ? '' : 'disabled'}>Επόμενο →</button></div></div></div>`;
    ov.style.display = 'flex';
    const body = ov.querySelector('.ac-body'); body.scrollTop = 0;
    const close = () => { ov.style.display = 'none'; ov.innerHTML = ''; document.removeEventListener('keydown', esc); onClose && onClose(); };
    const esc = e => { if (e.key === 'Escape' && !(e.target && e.target.classList.contains('ac-in'))) close(); };
    document.addEventListener('keydown', esc);
    ov.querySelector('[data-x]').onclick = close;
    ov.onclick = e => { if (e.target === ov) close(); };
    ov.querySelector('[data-done]').onclick = e => { P.done[l.id] = !P.done[l.id]; save(); e.target.textContent = P.done[l.id] ? '✅ Ολοκληρώθηκε' : '✔ Το έμαθα'; };
    ov.querySelectorAll('[data-nav]').forEach(b => b.onclick = () => { const n = +b.dataset.nav; if (all[n]) { P.done[l.id] = true; save(); document.removeEventListener('keydown', esc); openLesson(t, all[n].id, onClose); } });
    ov.querySelectorAll('[data-anim]').forEach(h => { const n = +h.dataset.anim.split('-').pop(); Anim(h, l.blocks[n].scene); });
    ov.querySelectorAll('[data-cli]').forEach(h => { const n = +h.dataset.cli.split('-').pop(); Cli(h, l.blocks[n]); });
    ov.querySelectorAll('[data-subnet]').forEach(h => Subnet(h));
    ov.querySelectorAll('[data-copy]').forEach(b => b.onclick = () => { const txt = $('cp-' + b.dataset.copy).innerText; navigator.clipboard && navigator.clipboard.writeText(txt).then(() => { b.textContent = '✔ Αντιγράφηκε'; setTimeout(() => b.textContent = '📋 Αντιγραφή', 1500); }); });
    ov.querySelectorAll('[data-gotab]').forEach(b => b.onclick = () => { close(); window.showTab && window.showTab(b.dataset.gotab); });
    ov.querySelectorAll('[data-quiz]').forEach(q => { const qid = q.dataset.quiz, n = +qid.split('-').pop(), bq = l.blocks[n];
      q.querySelectorAll('.ac-opt').forEach(o => o.onclick = () => { if (P.quiz[qid] != null) return; const i = +o.dataset.i; P.quiz[qid] = i; save();
        q.querySelectorAll('.ac-opt').forEach((x, j) => { x.disabled = true; if (j === bq.ok) x.classList.add('ok'); else if (j === i) x.classList.add('bad'); });
        q.querySelector('.ac-why').innerHTML = (i === bq.ok ? '✅ ' : '❌ ') + md(bq.why || ''); }); });
  }
  A.openLesson = (trackId, lid) => { const t = A.tracks.find(x => x.id === trackId); if (t) openLesson(t, lid); };

  // ---------- στυλ ----------
  const css = document.createElement('style');
  css.textContent = `
  #ac-overlay{position:fixed;inset:0;z-index:200;background:#000b;display:none;align-items:center;justify-content:center;padding:18px}
  .ac-win{width:min(980px,100%);height:100%;background:var(--panel,#0b111c);border:1px solid var(--line,#1c2638);border-radius:12px;display:flex;flex-direction:column;box-shadow:0 20px 60px #000c}
  .ac-top{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-bottom:1px solid var(--line,#1c2638)}
  .ac-body{flex:1;overflow:auto;padding:16px 22px 30px;font-size:13.5px;line-height:1.65;color:#cfe0f5}
  .ac-title{margin:0 0 12px;color:#fff;font-size:20px}
  .ac-text p{margin:0 0 10px}.ac-text ul,.ac-box ul{margin:4px 0 10px 18px;padding:0}.ac-h{color:#3ec5ff;margin:18px 0 6px}
  .ac-body code{background:#1a2538;padding:1px 5px;border-radius:4px;color:#ffd9a0;font-size:12.5px}
  .ac-box{border-radius:8px;padding:9px 12px;margin:10px 0;border-left:3px solid}.ac-box p{margin:0 0 4px;display:inline}
  .ac-tip{background:#3ec5ff12;border-color:#3ec5ff}.ac-warn{background:#ff9f4314;border-color:#ff9f43}.ac-exam{background:#b388ff14;border-color:#b388ff}
  .ac-goal{background:#3ddc9712;border-color:#3ddc97}.ac-nw{background:#3ec5ff0d;border-color:#3ec5ff;display:flex;gap:10px;align-items:center;flex-wrap:wrap}.ac-nw p{display:inline}
  .ac-table{border-collapse:collapse;margin:8px 0 12px;width:100%;font-size:12.5px}.ac-table th,.ac-table td{border:1px solid #1f3352;padding:5px 8px;text-align:left;vertical-align:top}.ac-table th{background:#101828;color:#3ec5ff}
  .ac-code{margin:10px 0;border:1px solid #1f3352;border-radius:8px;overflow:hidden}.ac-codeh{display:flex;gap:8px;align-items:center;justify-content:space-between;padding:5px 10px;background:#101828;font-size:12px;color:#fff}
  .ac-code pre{margin:0;padding:10px 12px;background:#060a12;overflow:auto;font:12.5px/1.55 ui-monospace,Menlo,monospace;color:#cfe0f5;max-height:520px}
  .ac-kw{color:#c792ea}.ac-str{color:#c3e88d}.ac-com{color:#6d7f99;font-style:italic}.ac-num{color:#f78c6c}
  .ac-explain{padding:8px 12px;border-top:1px solid #1f3352;background:#0b111c;font-size:12.5px}.ac-explain p{margin:0 0 6px}
  .ac-anim{background:#060a12;border:1px solid #1f3352;border-radius:10px;padding:8px;margin:10px 0}.ac-anim svg{width:100%;height:auto;display:block;max-height:340px}
  .ac-say{min-height:44px;padding:8px 10px;background:#0b111c;border-radius:6px;margin-top:6px}.ac-say p{margin:0}
  .ac-tables{display:flex;flex-wrap:wrap;gap:10px;margin-top:6px}.ac-tbl table{border-collapse:collapse;font-size:11.5px}.ac-tbl th,.ac-tbl td{border:1px solid #1f3352;padding:2px 7px}.ac-tbl th{color:#3ec5ff}
  .ac-ctl{display:flex;gap:6px;align-items:center;margin-top:8px}.ac-stepn{color:#6d7f99;font-size:12px;margin-left:6px}
  .ac-quiz{background:#101828;border:1px solid #1f3352;border-radius:8px;padding:10px 12px;margin:12px 0}.ac-q{color:#fff;margin-bottom:8px}
  .ac-opt{display:block;width:100%;text-align:left;margin:4px 0;padding:7px 10px;white-space:normal;font-size:12.5px}.ac-opt.ok{border-color:#3ddc97;background:#3ddc9722}.ac-opt.bad{border-color:#ff3b5c;background:#ff3b5c22}
  .ac-why{margin-top:6px;font-size:12.5px}.ac-why p{display:inline}
  .ac-blockt{color:#3ec5ff;font-weight:600;margin:14px 0 4px}
  .ac-cli{background:#05070b;border:1px solid #1f3352;border-radius:8px;padding:10px;font:12.5px/1.5 ui-monospace,Menlo,monospace}
  .ac-term{max-height:240px;overflow:auto;white-space:pre-wrap;color:#cfe0f5}.ac-out{color:#9fb4d0}.ac-err{color:#ff8da0}
  .ac-task{margin-top:8px;font-family:-apple-system,sans-serif;font-size:12.5px}.ac-prompt{color:#3ddc97;align-self:center}
  .ac-in{flex:1;background:#0b111c;border:1px solid #1f3352;border-radius:4px;color:#fff;padding:4px 6px;font:inherit}
  .ac-sub{background:#101828;border:1px solid #1f3352;border-radius:8px;padding:10px 12px}.ac-row{display:flex;gap:8px;align-items:center;margin:3px 0}.ac-row span{width:190px;font-size:12px;color:#9fb4d0}
  .ac-row input{flex:1;background:#060a12;border:1px solid #1f3352;border-radius:4px;color:#fff;padding:4px 6px;font:12.5px ui-monospace,Menlo,monospace}
  .ac-foot{display:flex;justify-content:space-between;gap:8px;margin-top:24px;padding-top:12px;border-top:1px solid #1f3352}.ac-done{border-color:#3ddc97}
  .ac-li{display:flex;gap:6px;align-items:baseline;padding:4px 6px;border-radius:5px;cursor:pointer;font-size:12px}.ac-li:hover{background:#ffffff08}.ac-li span:first-of-type{flex:1}
  #ac-overlay th{position:static;text-transform:none}#ac-overlay td{white-space:normal;max-width:none;overflow:visible;text-overflow:clip}
  @media (max-width:700px){.ac-body{padding:12px}.ac-row span{width:120px}}`;
  document.head.appendChild(css);
})();
