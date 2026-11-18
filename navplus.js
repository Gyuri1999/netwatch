// 🧭 Πλοήγηση+: ★ αγαπημένα & 🕘 πρόσφατα στο μενού, ομάδες που κλείνουν, συσκευές στο ⌘K
// και κάρτα «Θέλει προσοχή» στην Αρχική. Φορτώνεται μετά το index.html (χρησιμοποιεί showTab, buildRail,
// cmdItems, renderHome, SECT_NAME, S, ico, esc).
(() => {
const INIT = () => {
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const LS = {
    get(k, d) { try { const v = JSON.parse(localStorage.getItem(k)); return v == null ? d : v; } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
  };
  let FAV = LS.get('nw-fav', []), REC = LS.get('nw-recent', []), COL = LS.get('nw-railcol', {});
  const known = t => t === 'home' || (typeof SECT_NAME !== 'undefined' && SECT_NAME[t]);
  FAV = FAV.filter(known); REC = REC.filter(known);

  const css = document.createElement('style');
  css.textContent = `
#rail .rg.np-t{cursor:pointer;user-select:none;display:flex;align-items:center;gap:6px}
#rail .rg.np-t:hover{color:var(--txt)}
#rail .rg.np-t::after{content:'▾';margin-left:auto;font-size:9px;opacity:.7;transition:transform .15s}
#rail .rg.np-t.np-c::after{transform:rotate(-90deg)}
#rail button.np-h{display:none}
#rail button[data-r] .np-s{margin-left:auto;opacity:0;font-size:12px;color:var(--dim);padding:0 2px;line-height:1}
#rail button[data-r]:hover .np-s{opacity:.8}
#rail button[data-r] .np-s.on{opacity:1;color:var(--yellow)}
#rail button[data-r] .cnt+.np-s{margin-left:4px}
body.rail-mini #rail .np-s{display:none}
body.rail-mini #rail button.np-h{display:flex}
.np-attn{margin:0 0 12px;padding:12px 14px}
.np-attn .np-h2{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.np-attn .np-h2 b{font-size:13px;color:var(--hi)}
.np-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:8px}
.np-it{display:flex;gap:10px;align-items:flex-start;padding:9px 11px;border-radius:9px;background:rgb(var(--w) / 3%);border:1px solid var(--line);cursor:pointer;border-left:3px solid var(--c,var(--dim))}
.np-it:hover{background:rgb(var(--w) / 6%)}
.np-it .np-n{font-size:18px;font-weight:700;color:var(--c,var(--hi));min-width:26px;text-align:center;line-height:1.2}
.np-it .np-x{display:flex;flex-direction:column;gap:2px;min-width:0}
.np-it .np-x b{font-size:12.5px;color:var(--hi);font-weight:600}
.np-it .np-x span{font-size:11.5px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.np-ok{color:var(--green);font-size:12.5px}
`;
  document.head.appendChild(css);

  // ───────── μενού: ★ αγαπημένα, 🕘 πρόσφατα, ομάδες που κλείνουν ─────────
  const label = t => t === 'home' ? '🧭 Αρχική' : (SECT_NAME[t] || t);
  const split = n => { const m = String(n).match(/^(\S+)\s+(.+)$/); return m ? [m[1], m[2]] : ['•', n]; };
  const btn = t => { const [ic, lb] = split(label(t)); return `<button data-r="${t}" title="${E(lb)}"><span class="ic">${ico(t) || ic}</span><span class="lb">${E(lb)}</span></button>`; };

  function decorate() {
    const rail = document.getElementById('rail'); if (!rail) return;
    const home = rail.querySelector('[data-r="home"]');
    let extra = '';
    if (FAV.length) extra += `<div class="rg" data-g="fav">★ ${EN() ? 'Favourites' : 'Αγαπημένα'}</div>` + FAV.map(btn).join('');
    const rec = REC.filter(t => !FAV.includes(t) && t !== 'home').slice(0, 4);
    if (rec.length) extra += `<div class="rg" data-g="rec">🕘 ${EN() ? 'Recent' : 'Πρόσφατα'}</div>` + rec.map(t => btn(t).replace('<button ', '<button data-np="rec" ')).join('');
    if (extra && home) home.insertAdjacentHTML('afterend', extra);
    // κλικ στα νέα κουμπιά (ίδια συμπεριφορά με τα υπόλοιπα)
    rail.querySelectorAll('[data-g] ~ button[data-r]').forEach(b => {
      if (b._np) return; b._np = 1;
      if (!b.onclick) b.onclick = () => { const t = b.dataset.r; if (t !== 'map' && t !== 'lan' && typeof setView === 'function') setView('page'); showTab(t); document.body.classList.remove('rail-open'); };
    });
    // ☆ σε κάθε στοιχείο
    rail.querySelectorAll('button[data-r]').forEach(b => {
      const t = b.dataset.r; if (t === 'home' || t === 'map' || t === 'lan' || b.querySelector('.np-s')) return;
      const s = document.createElement('span'); s.className = 'np-s' + (FAV.includes(t) ? ' on' : '');
      s.textContent = FAV.includes(t) ? '★' : '☆';
      s.title = FAV.includes(t) ? (EN() ? 'Remove from favourites' : 'Αφαίρεση από τα αγαπημένα') : (EN() ? 'Add to favourites' : 'Στα αγαπημένα');
      s.onclick = e => { e.stopPropagation(); FAV = FAV.includes(t) ? FAV.filter(x => x !== t) : FAV.concat(t).slice(-10); LS.set('nw-fav', FAV); buildRail(); };
      b.appendChild(s);
    });
    // ομάδες που κλείνουν (η ομάδα της ανοιχτής οθόνης μένει πάντα ορατή)
    let gi = 0;
    rail.querySelectorAll('.rg').forEach(g => {
      const key = g.dataset.g || ('g' + (gi++) + ':' + g.textContent.trim());
      g.classList.add('np-t'); g.dataset.k = key;
      const items = []; let n = g.nextElementSibling;
      while (n && n.tagName === 'BUTTON' && !n.classList.contains('mini')) { items.push(n); n = n.nextElementSibling; }
      const closed = !!COL[key];
      g.classList.toggle('np-c', closed);
      items.forEach(b => b.classList.toggle('np-h', closed && !b.classList.contains('on')));
      g.onclick = () => { COL[key] = !COL[key]; if (!COL[key]) delete COL[key]; LS.set('nw-railcol', COL); decorate2(); };
      g.title = EN() ? 'Click to collapse / expand' : 'Κλικ για κλείσιμο / άνοιγμα';
    });
  }
  // μόνο ξανα-εφαρμογή του «κλειστό/ανοιχτό» (χωρίς νέα κουμπιά)
  function decorate2() {
    document.querySelectorAll('#rail .rg.np-t').forEach(g => {
      const closed = !!COL[g.dataset.k]; g.classList.toggle('np-c', closed);
      let n = g.nextElementSibling;
      while (n && n.tagName === 'BUTTON' && !n.classList.contains('mini')) { n.classList.toggle('np-h', closed && !n.classList.contains('on')); n = n.nextElementSibling; }
    });
  }
  if (typeof buildRail === 'function') {
    const orig = buildRail;
    window.buildRail = function () { const r = orig.apply(this, arguments); try { decorate(); } catch (e) { console.error(e); } return r; };
  }

  // ───────── πρόσφατα: κάθε showTab ─────────
  if (typeof showTab === 'function') {
    const origShow = showTab;
    window.showTab = function (t) {
      const r = origShow.apply(this, arguments);
      try {
        if (t && t !== 'map' && t !== 'lan' && known(t) && REC[0] !== t) {
          const was = REC.slice(0, 5).join();
          REC = [t].concat(REC.filter(x => x !== t)).slice(0, 8); LS.set('nw-recent', REC);
          // ξαναχτίζουμε το μενού μόνο αν άλλαξε ό,τι φαίνεται (όχι σε κάθε κλικ μέσα στα ίδια)
          if (REC.slice(0, 5).join() !== was && !document.querySelector('#rail [data-np="rec"][data-r="' + t + '"]')) buildRail();
        }
        decorate2();
      } catch (e) { console.error(e); }
      return r;
    };
  }

  // ───────── ⌘K: πρόσφατα όταν είναι άδειο, συσκευές όταν ψάχνεις ─────────
  if (typeof cmdItems === 'function') {
    const origItems = cmdItems;
    const WT = { rows: [], t: 0 };
    const loadWT = () => { if (Date.now() - WT.t < 60000) return; WT.t = Date.now(); fetch('/api/whereis/table').then(r => r.ok ? r.json() : null).then(j => { if (j && j.rows) WT.rows = j.rows; }).catch(() => {}); };
    loadWT();
    const fold = s => String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
    window.cmdItems = function (q) {
      const out = origItems.apply(this, arguments), qt = String(q || '').trim(), f = fold(qt);
      if (!qt) {
        const rec = REC.filter(t => t !== 'home').slice(0, 5).map(t => ({ t: label(t), d: EN() ? 'recent' : 'πρόσφατο', go: () => showTab(t) }));
        return rec.concat(out.filter(x => !rec.some(r => r.t === x.t))).slice(0, 40);
      }
      if (f.length < 2 || typeof S === 'undefined' || !S.hosts) return out;
      loadWT();
      const isMac = /^([0-9a-f]{2}[:-]){2,5}[0-9a-f]{0,2}$/i.test(qt), dev = [], seen = new Set();
      // συσκευές: ό,τι ξέρει το ζωντανό μοντέλο + ο πίνακας θυρών (όνομα, MAC, vendor, switch/θύρα)
      const rows = [];
      for (const h of S.hosts.values()) {
        if (h.kind !== 'local' || String(h.ip).includes(':')) continue;
        rows.push({ ip: h.ip, mac: h.mac, name: (typeof aliasOf === 'function' && aliasOf(h)) || (h.names && h.names[0]) || h.rdns || '', vendor: h.vendor, extra: h.dlabel });
      }
      for (const r of WT.rows) if (r.ip) rows.push({ ip: r.ip, mac: r.mac, name: r.name, vendor: r.vendor, port: r.switch && r.port ? `${r.switch} ${r.port}` : '' });
      const by = new Map();
      for (const r of rows) { const o = by.get(r.ip) || {}; by.set(r.ip, Object.fromEntries(Object.entries(Object.assign({}, r, o)).map(([k, v]) => [k, o[k] || r[k]]))); }
      const fq = f.replace(/-/g, ':');
      for (const r of by.values()) {
        if (!fold([r.ip, r.mac, r.name, r.vendor, r.port, r.extra].join(' ')).includes(fq)) continue;
        if (seen.has(r.ip)) continue; seen.add(r.ip);
        dev.push({ t: `📟 ${r.name || r.ip}`, d: [r.name ? r.ip : '', r.vendor, r.port, EN() ? 'profile' : 'προφίλ'].filter(Boolean).join(' · '), go: () => window.showProfile ? showProfile(r.ip) : showTab('det') });
        if (dev.length >= 6) break;
      }
      if ((isMac || /^\d{1,3}(\.\d{1,3}){3}$/.test(qt) || dev.length) && window.whereIs)
        dev.push({ t: `🔌 ${EN() ? 'Where is' : 'Πού είναι'} ${qt}?`, d: 'switch → ' + (EN() ? 'port' : 'θύρα') + ' → VLAN', go: () => whereIs(qt) });
      return dev.concat(out).slice(0, 40);
    };
  }

  // ───────── Αρχική: «Θέλει προσοχή» ─────────
  const AT = { html: '', t: 0, busy: false };
  const J = u => fetch(u).then(r => r.ok ? r.json() : null).catch(() => null);
  async function loadAttn() {
    if (AT.busy) return; AT.busy = true;
    try {
      const [cs, ex, cf, ch, tr, sg] = await Promise.all([J('/api/cases'), J('/api/expiry'), J('/api/configs'), J('/api/change'), J('/api/triage'), J('/api/segcheck')]);
      const en = EN(), it = [], now = Date.now() / 1000, tt = x => (en && window.I18N ? I18N.t(String(x)) : x);
      const add = (go, n, c, t, d) => it.push(`<div class="np-it" data-go="${go}" style="--c:${c}"><div class="np-n">${E(n)}</div><div class="np-x"><b>${E(t)}</b><span data-noi18n>${E(d)}</span></div></div>`);
      if (cs && cs.cases) {
        const open = cs.cases.filter(c => c.status !== 'closed' && c.status !== 'fp');
        const hi = open.filter(c => c.sev === 'high' && c.status === 'new');
        if (hi.length) add('cases', hi.length, 'var(--red)', en ? 'High cases nobody has picked up' : 'Σοβαρές υποθέσεις χωρίς χειρισμό', hi.slice(0, 2).map(c => '#' + c.id).join(', ') + (en ? ` · ${open.length} open in total` : ` · ${open.length} ανοιχτές συνολικά`));
      }
      if (sg && sg.rules) {
        const v = sg.rules.filter(r => r.verdict === 'violation');
        if (v.length) add('seg', v.length, 'var(--red)', en ? 'Zones that should be isolated are not' : 'Ζώνες που δεν είναι απομονωμένες', v.slice(0, 2).map(r => `${r.from} → ${r.to}`).join(' · '));
      }
      if (ex && ex.counts) {
        const n = (ex.counts.expired || 0) + (ex.counts.urgent || 0);
        if (n) add('expiry', n, ex.counts.expired ? 'var(--red)' : 'var(--orange)', en ? 'Expired or expiring within 7 days' : 'Έληξαν ή λήγουν σε ≤ 7 μέρες', (ex.items || []).filter(i => i.status === 'expired' || i.status === 'urgent').slice(0, 2).map(i => tt(i.name)).join(' · '));
      }
      if (cf && cf.devices) {
        const r = cf.devices.filter(d => (d.risky || []).length && d.last_change && now - d.last_change < 7 * 86400);
        if (r.length) add('cfg', r.length, 'var(--orange)', en ? 'Risky config changes (7 days)' : 'Επικίνδυνες αλλαγές ρυθμίσεων (7 μέρες)', r.map(d => tt(d.name)).join(' · '));
        const bad = cf.devices.filter(d => d.status === 'error');
        if (bad.length) add('cfg', bad.length, 'var(--yellow)', en ? 'Config backups failing' : 'Αποτυχημένα backup ρυθμίσεων', bad.map(d => tt(d.name)).join(' · '));
      }
      if (ch && ch.last_compare && ch.last_compare.verdict === 'bad' && now - ((ch.last_compare.b || {}).t || 0) < 86400)
        add('chg', '!', 'var(--orange)', en ? 'Before/after check found problems' : 'Ο έλεγχος Πριν/Μετά βρήκε πρόβλημα', tt(ch.last_compare.summary || ''));
      if (tr && tr.verdict && tr.verdict !== 'ok' && tr.finished && now - tr.finished < 6 * 3600)
        add('tri', '!', 'var(--orange)', en ? 'Last network check failed' : 'Ο τελευταίος έλεγχος δικτύου απέτυχε', String(tr.verdict));
      AT.html = `<div class="card np-attn"><div class="np-h2"><b>🎯 ${en ? 'Needs attention' : 'Θέλει προσοχή'}</b><span class="sm" style="margin-left:auto">${en ? 'from cases, expiries, configs, before/after and segmentation' : 'από υποθέσεις, λήξεις, configs, Πριν/Μετά και διαχωρισμό'}</span></div>` +
        (it.length ? `<div class="np-list">${it.join('')}</div>` : `<div class="np-ok">✓ ${en ? 'Nothing pending — all clear.' : 'Τίποτα εκκρεμές — όλα καθαρά.'}</div>`) + '</div>';
      AT.t = Date.now(); AT.lang = I18N && I18N.lang;
    } finally { AT.busy = false; }
    paintAttn();
  }
  function paintAttn() {
    const el = document.getElementById('t-home'); if (!el || !AT.html) return;
    let box = el.querySelector(':scope > .np-wrap');
    if (!box) { box = document.createElement('div'); box.className = 'np-wrap'; el.prepend(box); }
    if (box._h !== AT.html) { box.innerHTML = AT.html; box._h = AT.html; box.querySelectorAll('[data-go]').forEach(x => x.onclick = () => showTab(x.dataset.go)); }
  }
  window.NP_refreshAttn = () => { AT.t = 0; loadAttn(); };
  function hookHome() {
    if (typeof window.renderHome !== 'function' || window.renderHome.__np) return;
    const orig = window.renderHome;
    const f = function () {
      const r = orig.apply(this, arguments);
      try { paintAttn(); if (Date.now() - AT.t > 30000 || AT.lang !== (window.I18N && I18N.lang)) loadAttn(); } catch (e) { console.error(e); }
      return r;
    };
    f.__np = 1; window.renderHome = f;
  }
  hookHome();
  // το uiplus τυλίγει κι αυτό το renderHome αργότερα — ξανατυλίγουμε αν χρειαστεί
  setInterval(hookHome, 2000);

  try { buildRail(); } catch (e) {}
  window.NAVPLUS = { fav: () => FAV.slice(), recent: () => REC.slice() };
};
// οι συναρτήσεις του index.html ορίζονται στο inline script του body — περιμένουμε να τρέξει
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', INIT); else INIT();
})();
