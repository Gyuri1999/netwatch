// 🗂 Υποθέσεις (διαλογή ειδοποιήσεων, σαν το TheHive) + 🏹 Κυνήγι απειλών (Sqrrl/PEAK, Collins, Sanders) + 👤 προφίλ συσκευής.
// Φορτώνεται μετά το index.html· χρησιμοποιεί S, showTab, tab, I18N.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const curTab = () => (typeof tab !== 'undefined' ? tab : null);
  const P = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) }).then(r => r.json().then(j => (r.ok ? j : Object.assign(j, { error: j.error || ('HTTP ' + r.status) }))));
  const now = () => Date.now() / 1000;
  const since = t => { if (!t) return '—'; const s = Math.max(0, now() - t); return s < 90 ? Math.round(s) + '″' : s < 5400 ? Math.round(s / 60) + '′' : s < 172800 ? Math.round(s / 3600) + (EN() ? 'h' : 'ω') : Math.round(s / 86400) + (EN() ? 'd' : 'μ'); };
  const dur = s => s == null ? '—' : s < 90 ? Math.round(s) + '″' : s < 5400 ? Math.round(s / 60) + '′' : (s / 3600).toFixed(1) + (EN() ? 'h' : 'ω');
  const hm = t => new Date(t * 1000).toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  const SEVC = { high: 'var(--red)', med: 'var(--orange)', low: 'var(--yellow)' };
  const host = ip => (typeof S !== 'undefined' && S.hosts && S.hosts.get(ip)) || null;
  const hname = ip => { const h = host(ip); if (!h) return ''; return h.nick || h.label || h.name || h.vendor || h.rdns || ''; };
  const busyOn = () => { const a = document.activeElement; return a && (a.tagName === 'TEXTAREA' || a.tagName === 'INPUT' || a.tagName === 'SELECT'); };

  const css = document.createElement('style');
  css.textContent = `
  .cs-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(112px,1fr));gap:10px;margin:12px 0}.cs-k{margin:0;text-align:center;display:flex;flex-direction:column;gap:2px}.cs-k b{font-size:23px}.cs-k span{font-size:11.5px;color:var(--dim)}
  .cs-flt{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}.cs-flt button.on{border-color:var(--cyan);color:var(--cyan)}
  .cs-wrap{display:grid;grid-template-columns:minmax(280px,380px) 1fr;gap:12px;align-items:start}@media(max-width:900px){.cs-wrap{grid-template-columns:1fr}}
  .cs-list{display:flex;flex-direction:column;gap:6px;max-height:calc(100vh - 300px);overflow:auto;padding-right:2px}
  .cs-row{margin:0;padding:9px 11px;cursor:pointer;display:flex;flex-direction:column;gap:4px;border-left:3px solid var(--c);white-space:normal}.cs-row:hover{background:rgb(var(--w) / 4%)}.cs-row.sel{outline:2px solid color-mix(in srgb,var(--cyan) 55%,transparent)}
  .cs-row .r1{display:flex;gap:8px;align-items:center}.cs-row .r1 b{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}.cs-row .r2{display:flex;gap:8px;font-size:11.5px;color:var(--dim);flex-wrap:wrap}
  .cs-st{font-size:10.5px;font-weight:700;padding:2px 7px;border-radius:10px;white-space:nowrap;color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent)}
  .cs-det{margin:0;white-space:normal}.cs-acts{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}.cs-acts .on{border-color:var(--c);color:var(--c);background:color-mix(in srgb,var(--c) 12%,transparent)}
  .cs-chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}.cs-chip{font-size:12px;padding:3px 8px;border:1px solid var(--line);border-radius:12px;display:inline-flex;gap:6px;align-items:center}
  .cs-al{display:flex;flex-direction:column;gap:4px;margin-top:8px;max-height:260px;overflow:auto}.cs-al div{display:flex;gap:8px;font-size:12px;padding:5px 8px;border-radius:6px;background:rgb(var(--w) / 3%);border-left:3px solid var(--c)}.cs-al div .d{flex:1;min-width:0;color:var(--dim)}
  .cs-notes{display:flex;flex-direction:column;gap:6px;margin-top:8px}.cs-note{font-size:12.5px;padding:7px 10px;border-radius:8px;background:rgb(var(--w) / 4%)}.cs-note.auto{opacity:.75;font-style:italic}.cs-note .t{font-size:11px;color:var(--dim);margin-right:6px}
  .cs-add{display:flex;gap:6px;margin-top:8px}.cs-add textarea{flex:1;min-height:42px;resize:vertical;font:inherit;font-size:12.5px;padding:7px 9px;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--txt)}
  .cs-h{font-size:12px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.03em;margin-top:14px}
  .hu-loop{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:10px;font-size:12px}.hu-loop span{padding:4px 10px;border-radius:12px;background:color-mix(in srgb,var(--purple) 12%,transparent);border:1px solid color-mix(in srgb,var(--purple) 35%,transparent)}.hu-loop i{color:var(--dim);font-style:normal}
  .hu-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px;margin-top:12px}
  .hu-c{margin:0;display:flex;flex-direction:column;gap:6px;white-space:normal;cursor:pointer;border:1px solid transparent}.hu-c:hover{border-color:var(--line)}.hu-c.sel{border-color:var(--purple)}
  .hu-c .hy{font-size:12px;color:var(--dim);flex:1}.hu-c .ft{display:flex;gap:6px;align-items:center;flex-wrap:wrap;font-size:11px}
  .hu-n{margin-left:auto;font-weight:800;font-size:13px;color:var(--c)}
  .hu-f{margin:0;padding:0;white-space:normal}.hu-f>summary{display:flex;gap:10px;align-items:center;padding:9px 12px;cursor:pointer;list-style:none}.hu-f>summary::-webkit-details-marker{display:none}
  .hu-sc{flex:none;width:44px;text-align:center;font-weight:800;font-size:15px;color:var(--c)}.hu-bar{height:4px;border-radius:2px;background:var(--c);margin-top:2px}
  .hu-fb{padding:0 12px 12px 66px;font-size:12.5px;display:flex;flex-direction:column;gap:6px}.hu-ev{display:flex;gap:6px;flex-wrap:wrap}.hu-ev code{font-size:11px;padding:2px 6px;border-radius:5px;background:rgb(var(--w) / 6%)}
  .pf-ov{position:fixed;inset:0;background:#0009;z-index:9000;display:grid;place-items:center;padding:16px}.pf-box{width:min(760px,100%);max-height:90vh;overflow:auto;margin:0;white-space:normal}
  .pf-g{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}@media(max-width:640px){.pf-g{grid-template-columns:1fr}}
  .pf-t{width:100%;border-collapse:collapse;font-size:12px}.pf-t td{padding:3px 4px;border-bottom:1px solid rgb(var(--w) / 6%)}.pf-t td:last-child{text-align:right;color:var(--dim)}
  `;
  document.head.appendChild(css);

  // ───────────────────────── 🗂 Υποθέσεις ─────────────────────────
  const ST = {
    new: ['🆕 Νέα', 'var(--cyan)'], investigating: ['🔍 Υπό έρευνα', 'var(--orange)'],
    resolved: ['✅ Επιλύθηκε', 'var(--green)'], false_positive: ['🟢 Ψευδώς θετικό', 'var(--dim)']
  };
  const CS = { d: null, at: 0, sel: null, flt: 'open', fpMin: 1440, msg: null, draft: '' };
  function csLoad(force) {
    if (!force && Date.now() - CS.at < 4000) return;
    CS.at = Date.now();
    fetch('/api/cases').then(r => r.json()).then(j => { CS.d = j; if (curTab() === 'cases' && !busyOn() && !(window.tabHover && tabHover())) csDraw(); }).catch(() => { });
  }
  function csAct(url, body, ok) {
    return P(url, body).then(j => { CS.msg = j.error ? { bad: 1, t: j.error } : ok ? { t: ok } : null; CS.at = 0; csLoad(true); return j; });
  }
  function shown(c) {
    if (CS.flt === 'open') return c.status === 'new' || c.status === 'investigating';
    if (CS.flt === 'all') return true;
    return c.status === CS.flt;
  }
  function csDraw() {
    const el = document.getElementById('t-cases'); if (!el) return;
    const d = CS.d;
    if (!d) { el.innerHTML = '<div class="card sm">φόρτωση…</div>'; return; }
    const draft = el.querySelector('.cs-add textarea'); if (draft) CS.draft = draft.value;
    const k = d.kpi || {}, cases = (d.cases || []);
    const list = cases.filter(shown);
    if (CS.sel == null || !cases.some(c => c.id === CS.sel)) CS.sel = list.length ? list[0].id : null;
    const sel = cases.find(c => c.id === CS.sel);
    const flt = [['open', 'Ανοιχτές', (k.new || 0) + (k.investigating || 0)], ['all', 'Όλες', k.total], ['resolved', 'Επιλυμένες', k.resolved], ['false_positive', 'Ψευδώς θετικά', k.false_positive]];
    let h = `<div class="card" style="white-space:normal"><b class="ctitle">🗂 Υποθέσεις ${d.demo ? '<span class="tag">demo</span>' : ''}</b>
      <div class="sm" style="margin-top:6px">Σαν το <b>TheHive</b> ενός SOC: οι ειδοποιήσεις του ίδιου «δράστη» μέσα σε 30′ μαζεύονται σε μία υπόθεση. Τη διαλέγεις (νέα → υπό έρευνα → επιλύθηκε), κρατάς σημειώσεις, και αν ήταν ψευδώς θετικό, το NetWatch δεν θα ξαναχτυπήσει για το ίδιο πράγμα (για όσο ορίσεις).</div>
      ${d.off ? '<div class="sm" style="margin-top:6px;color:var(--orange)">Δεν είναι διαθέσιμο σε αυτή τη λειτουργία.</div>' : ''}
      <div class="cs-flt">${flt.map(([v, l, n]) => `<button class="b${CS.flt === v ? ' on' : ''}" data-flt="${v}">${l} <b>${n || 0}</b></button>`).join('')}</div></div>
    <div class="cs-kpis">
      <div class="card cs-k"><b style="color:var(--cyan)">${k.new || 0}</b><span>νέες</span></div>
      <div class="card cs-k"><b style="color:var(--orange)">${k.investigating || 0}</b><span>υπό έρευνα</span></div>
      <div class="card cs-k"><b style="color:var(--green)">${k.resolved || 0}</b><span>επιλυμένες</span></div>
      <div class="card cs-k"><b>${k.false_positive || 0}</b><span>ψευδώς θετικά</span></div>
      <div class="card cs-k"><b>${dur(k.mtta)}</b><span title="Mean Time To Acknowledge">MTTA · μέχρι να το δεις</span></div>
      <div class="card cs-k"><b>${dur(k.mttr)}</b><span title="Mean Time To Resolve">MTTR · μέχρι να κλείσει</span></div>
    </div>`;
    if (CS.msg) h += `<div class="card sm" style="color:${CS.msg.bad ? 'var(--red)' : 'var(--green)'}">${E(CS.msg.t)}</div>`;
    h += `<div class="cs-wrap"><div class="cs-list">`;
    if (!list.length) h += `<div class="card sm" style="white-space:normal">${CS.flt === 'open' ? '🎉 Καμία ανοιχτή υπόθεση — όλα έχουν διαλεχτεί.' : 'Τίποτα εδώ.'}</div>`;
    for (const c of list) {
      const s = ST[c.status] || ST.new;
      h += `<div class="card cs-row${c.id === CS.sel ? ' sel' : ''}" style="--c:${SEVC[c.sev] || 'var(--dim)'}" data-case="${c.id}">
        <div class="r1"><span class="sm" data-noi18n>#${c.id}</span><b>${ctitle(c)}</b><span class="cs-st" style="--c:${s[1]}">${s[0]}</span></div>
        <div class="r2"><span>${c.count} ειδοποιήσεις</span><span>πριν ${since(c.last)}</span>${(c.notes || []).filter(n => !n.auto).length ? `<span>📝 ${(c.notes || []).filter(n => !n.auto).length}</span>` : ''}${c.source === 'hunt' ? '<span>🏹 κυνήγι</span>' : ''}</div></div>`;
    }
    h += `</div><div>${sel ? caseDetail(sel, d) : ''}</div></div>`;
    const sup = d.suppressions || [];
    if (sup.length) h += `<div class="card" style="white-space:normal;margin-top:12px"><b>🔕 Σιγασμένα (ψευδώς θετικά)</b><div class="sm">Ειδοποιήσεις αυτού του τύπου από αυτή τη συσκευή φαίνονται ως «αναμενόμενες» και δεν ανοίγουν υπόθεση.</div>
      <div class="cs-chips">${sup.map(s => `<span class="cs-chip"><span>${E(s.type)}</span> · <span data-noi18n>${E(s.actor)}</span> · ${s.until ? 'έως ' + hm(s.until) : 'για πάντα'} <button class="b" style="padding:0 6px" data-unsup="${E(s.type)}" data-actor="${E(s.actor)}" title="Αναίρεση">✕</button></span>`).join('')}</div></div>`;
    el.innerHTML = h;
    const ta = el.querySelector('.cs-add textarea'); if (ta) ta.value = CS.draft;
    el.querySelectorAll('[data-flt]').forEach(b => b.onclick = () => { CS.flt = b.dataset.flt; CS.sel = null; csDraw(); });
    el.querySelectorAll('[data-case]').forEach(b => b.onclick = () => { CS.sel = +b.dataset.case; CS.draft = ''; CS.msg = null; csDraw(); });
    el.querySelectorAll('[data-st]').forEach(b => b.onclick = () => csAct('/api/cases/update', { id: CS.sel, status: b.dataset.st }));
    const fp = el.querySelector('[data-fp]');
    if (fp) fp.onclick = () => csAct('/api/cases/fp', { id: CS.sel, minutes: CS.fpMin }, 'Σημειώθηκε ψευδώς θετικό — δεν θα ξαναχτυπήσει.');
    const fs = el.querySelector('.cs-fpmin'); if (fs) fs.onchange = () => { CS.fpMin = +fs.value; };
    const nb = el.querySelector('[data-note]');
    if (nb) nb.onclick = () => { const v = (el.querySelector('.cs-add textarea').value || '').trim(); if (!v) return; CS.draft = ''; csAct('/api/cases/update', { id: CS.sel, note: v }); };
    el.querySelectorAll('[data-unsup]').forEach(b => b.onclick = () => csAct('/api/cases/delete-suppression', { type: b.dataset.unsup, actor: b.dataset.actor }, 'Η σίγαση αναιρέθηκε.'));
    el.querySelectorAll('[data-prof]').forEach(b => b.onclick = () => showProfile(b.dataset.prof));
    el.querySelectorAll('[data-tm]').forEach(b => b.onclick = () => showTab('tm'));
  }
  function ctitle(c) {
    if (c.source === 'hunt' || !(c.types || []).length) return E(c.title);
    const ip = (c.actors || [])[0] || '', nm = hname(ip);
    return `<span>${E(c.types[0])}</span> <span class="sm" data-noi18n>· ${E(nm && nm !== ip ? nm + ' (' + ip + ')' : ip)}</span>`;
  }
  function caseDetail(c, d) {
    const s = ST[c.status] || ST.new;
    const al = (typeof S !== 'undefined' ? S.alerts : []).filter(a => (c.alert_ids || []).includes(a.id)).slice(0, 60);
    const closed = c.status === 'resolved' || c.status === 'false_positive';
    let h = `<div class="card cs-det"><div class="brow"><b class="ctitle" style="color:${SEVC[c.sev] || 'inherit'}">${ctitle(c)}</b><span class="cs-st" style="--c:${s[1]}">${s[0]}</span></div>
      <div class="sm" style="margin-top:4px">🗂 <span data-noi18n>#${c.id}</span> · ${c.count} ειδοποιήσεις · από ${hm(c.first)} έως ${hm(c.last)}${c.acked ? ' · το είδες σε ' + dur(c.acked - c.created) : ''}${c.closed ? ' · έκλεισε σε ' + dur(c.closed - c.created) : ''}</div>
      <div class="cs-acts">
        ${[['investigating', '🔍 Το ερευνώ', 'var(--orange)'], ['resolved', '✅ Επιλύθηκε', 'var(--green)'], ['new', '↺ Ξανά νέα', 'var(--cyan)']].map(([v, l, col]) => `<button class="b${c.status === v ? ' on' : ''}" style="--c:${col}" data-st="${v}">${l}</button>`).join('')}
        <span style="display:inline-flex;gap:4px;align-items:center;margin-left:auto">
          <select class="cs-fpmin b" title="Για πόσο να μη ξαναχτυπήσει">${[[60, '1 ώρα'], [1440, '24 ώρες'], [10080, '7 μέρες'], [0, 'για πάντα']].map(([m, l]) => `<option value="${m}"${CS.fpMin === m ? ' selected' : ''}>${l}</option>`).join('')}</select>
          <button class="b${c.status === 'false_positive' ? ' on' : ''}" style="--c:var(--dim)" data-fp="1" title="Κλείνει την υπόθεση και σιγάζει τις ίδιες ειδοποιήσεις">🟢 Ψευδώς θετικό</button></span>
      </div>
      <div class="cs-h">Ποιοι εμπλέκονται</div><div class="cs-chips">${(c.actors || []).map(ip => `<span class="cs-chip"><b data-noi18n>${E(ip)}</b>${hname(ip) ? ` <span class="sm" data-noi18n>${E(hname(ip))}</span>` : ''}<button class="b" style="padding:0 6px" data-prof="${E(ip)}">👤 Προφίλ</button></span>`).join('')}
        ${(c.targets || []).length ? `<span class="sm" style="align-self:center">→ <span data-noi18n>${(c.targets || []).slice(0, 6).map(E).join(', ')}</span></span>` : ''}</div>
      ${(c.mitre || []).length ? `<div class="cs-chips">${c.mitre.map(m => `<a class="cs-chip" href="https://attack.mitre.org/techniques/${E(String(m.id).replace('.', '/'))}/" target="_blank" rel="noopener" style="text-decoration:none;color:var(--purple)"><span data-noi18n>${E(m.id)}</span> ${E(m.name || '')}</a>`).join('')}</div>` : ''}
      <div class="cs-h">Ειδοποιήσεις</div>
      <div class="cs-al">${al.length ? al.map(a => `<div style="--c:${SEVC[a.sev] || 'var(--dim)'}"><span class="sm" data-noi18n>${new Date(a.t * 1000).toLocaleTimeString()}</span><b>${E(a.type)}</b><span class="d">${E(a.detail || '')}</span></div>`).join('') : `<span class="sm">${(c.alert_ids || []).length ? 'Οι ειδοποιήσεις είναι παλιότερες από όσες κρατά η σελίδα — δες το 🕓 Ιστορικό.' : 'Χειροκίνητη υπόθεση (από κυνήγι απειλών).'}</span>`}</div>
      <div class="cs-acts" style="margin-top:6px"><button class="b" data-tm="1">⏱ Δες τι έγινε στη μηχανή του χρόνου</button></div>
      <div class="cs-h">Σημειώσεις</div>
      <div class="cs-notes">${(c.notes || []).map(n => `<div class="cs-note${n.auto ? ' auto' : ''}"><span class="t">${hm(n.t)}</span>${E(n.text)}</div>`).join('') || '<span class="sm">Καμία ακόμη. Γράψε τι έλεγξες — έτσι δουλεύει ένα SOC (και έτσι θυμάσαι σε 3 μήνες).</span>'}</div>
      ${closed && c.status === 'false_positive' ? '' : `<div class="cs-add"><textarea placeholder="π.χ. Ήταν το backup του NAS· έλεγξα το pcap…"></textarea><button class="b" data-note="1">📝 Πρόσθεσε</button></div>`}
    </div>`;
    return h;
  }
  window.renderCases = () => { csLoad(); if (!document.querySelector('#t-cases .cs-kpis')) csDraw(); };
  window.openCase = id => { CS.sel = +id; CS.flt = 'all'; showTab('cases'); csLoad(true); const t = document.getElementById('t-cases'); if (t) t.scrollIntoView({ block: 'start' }); };
  setInterval(() => { if (curTab() === 'cases') csLoad(); }, 2000);

  // ───────────────────────── 🏹 Κυνήγι απειλών ─────────────────────────
  const HU = { d: null, sel: null, res: {}, busy: new Set(), open: new Set(), msg: null };
  function huLoad() { fetch('/api/hunt').then(r => r.json()).then(j => { HU.d = j; if (HU.sel == null && (j.hunts || []).length) HU.sel = j.hunts[0].id; if (curTab() === 'hunt') huDraw(); }).catch(() => { }); }
  function huRun(id) {
    HU.busy.add(id); HU.sel = id; huDraw();
    return P('/api/hunt/run', { id }).then(j => { HU.busy.delete(id); if (j.error) HU.msg = { bad: 1, t: j.error }; else { HU.res[id] = j; HU.msg = null; } huLoad(); huDraw(); })
      .catch(e => { HU.busy.delete(id); HU.msg = { bad: 1, t: String(e) }; huDraw(); });
  }
  async function huAll() { for (const h of (HU.d && HU.d.hunts) || []) await huRun(h.id); }
  const scoreC = s => s >= 70 ? 'var(--red)' : s >= 40 ? 'var(--orange)' : 'var(--yellow)';
  function huDraw() {
    const el = document.getElementById('t-hunt'); if (!el) return;
    const d = HU.d; if (!d) { el.innerHTML = '<div class="card sm">φόρτωση…</div>'; return; }
    const hs = d.hunts || [], cur = hs.find(x => x.id === HU.sel), r = HU.res[HU.sel];
    let h = `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">🏹 Κυνήγι απειλών ${d.demo ? '<span class="tag">demo</span>' : ''}</b><button class="b pu-go" data-all="1"${HU.busy.size ? ' disabled' : ''}>▶ Τρέξε όλα</button></div>
      <div class="sm" style="margin-top:6px">Οι ανιχνευτές περιμένουν να χτυπήσει κανόνας. Ο <b>κυνηγός</b> ξεκινά από μια <b>υπόθεση</b> («αν κάτι κρύβεται, πώς θα φαινόταν;») και ψάχνει ενεργά στα δεδομένα για ό,τι έμεινε <b>κάτω από τα όρια</b>. Μέθοδοι από τα βιβλία του Collins (stack counting), του Sanders (προφίλ συσκευής) και εργαλεία όπως το RITA και το Zeek.</div>
      <div class="hu-loop"><span>1 · Υπόθεση</span><i>→</i><span>2 · Έρευνα στα δεδομένα</span><i>→</i><span>3 · Μοτίβα & ευρήματα</span><i>→</i><span>4 · Υπόθεση/κανόνας</span><i>↺</i></div>
      ${d.off ? '<div class="sm" style="margin-top:6px;color:var(--orange)">Δεν είναι διαθέσιμο σε αυτή τη λειτουργία.</div>' : ''}</div>`;
    if (HU.msg) h += `<div class="card sm" style="color:var(--red)">${E(HU.msg.t)}</div>`;
    h += `<div class="hu-grid">${hs.map(x => {
      const rr = HU.res[x.id], n = rr ? rr.findings.length : x.last_count, top = rr && rr.findings[0] ? rr.findings[0].score : 0;
      return `<div class="card hu-c${x.id === HU.sel ? ' sel' : ''}" data-h="${E(x.id)}"><b>${E(x.title)}</b><div class="hy">${E(x.hypothesis)}</div>
        <div class="ft">${x.mitre ? `<span class="tag" data-noi18n>${E(x.mitre.id)}</span>` : ''}<span class="sm">${E(x.method || '')}</span>
        <span class="hu-n" style="--c:${n ? scoreC(top || 50) : 'var(--green)'}">${HU.busy.has(x.id) ? '⏳' : n == null ? '' : n ? n + ' ⚑' : '✓ 0'}</span></div></div>`;
    }).join('')}</div>`;
    if (cur) {
      h += `<div class="card" style="white-space:normal;margin-top:12px"><div class="brow"><b class="ctitle">${E(cur.title)}</b><button class="b pu-go" data-run="${E(cur.id)}"${HU.busy.has(cur.id) ? ' disabled' : ''}>${HU.busy.has(cur.id) ? '⏳ Ψάχνω…' : '▶ Τρέξε το κυνήγι'}</button></div>
        <div style="margin-top:6px"><b>Υπόθεση:</b> ${E(cur.hypothesis)}</div>
        <div class="sm" style="margin-top:4px">${cur.mitre ? `MITRE <a href="https://attack.mitre.org/techniques/${E(String(cur.mitre.id).replace('.', '/'))}/" target="_blank" rel="noopener" data-noi18n>${E(cur.mitre.id)}</a> ${E(cur.mitre.name || '')} · ` : ''}<span>πηγή:</span> <span>${E(cur.source || '')}</span> · <span>δεδομένα:</span> <span>${E(cur.data || '')}</span></div>
        ${(cur.steps || []).length ? `<ol class="sm" style="margin:8px 0 0 18px;padding:0">${cur.steps.map(s => `<li>${E(s)}</li>`).join('')}</ol>` : ''}
        ${r ? `<div class="sm" style="margin-top:8px;padding:7px 9px;border-radius:7px;background:rgb(var(--w) / 4%)">💡 ${E(r.explain || '')}${r.stats && r.stats.note ? ' <b>' + E(r.stats.note) + '</b>' : ''}${r.stats ? ` <span data-noi18n>(${Object.entries(r.stats).filter(([k]) => k !== 'note').map(([k, v]) => E(k) + ': ' + E(v)).join(' · ')})</span>` : ''} · ${r.took_ms != null ? r.took_ms + ' ms' : ''}</div>` : ''}</div>`;
      if (r) {
        const fs = r.findings || [];
        if (!fs.length) h += `<div class="card sm" style="white-space:normal">✅ Τίποτα ύποπτο για αυτή την υπόθεση. Αυτό είναι κι αυτό αποτέλεσμα: ξέρεις πια ότι το δίκτυό σου «δεν έχει» αυτό το μοτίβο.</div>`;
        h += `<div style="display:flex;flex-direction:column;gap:6px;margin-top:8px">${fs.map((f, i) => {
          const key = cur.id + ':' + i, c = scoreC(f.score);
          return `<details class="card hu-f" data-k="${E(key)}"${HU.open.has(key) ? ' open' : ''}><summary><span class="hu-sc" style="--c:${c}">${f.score}<div class="hu-bar" style="--c:${c};width:${Math.max(6, f.score)}%"></div></span>
            <span style="flex:1;min-width:0"><b>${E(f.summary)}</b><div class="sm"><span data-noi18n>${E(f.actor || '')}</span>${f.actor_name ? ` <span data-noi18n>(${E(f.actor_name)})</span>` : ''}${f.target ? ` → <span data-noi18n>${E(f.target)}${f.target_name ? ' (' + E(f.target_name) + ')' : ''}</span>` : ''}</div></span></summary>
            <div class="hu-fb">${f.why ? `<div><b>Γιατί είναι ύποπτο:</b> ${E(f.why)}</div>` : ''}${f.next ? `<div><b>Επόμενο βήμα:</b> ${E(f.next)}</div>` : ''}
              ${f.evidence ? `<div class="hu-ev" data-noi18n>${Object.entries(f.evidence).map(([k, v]) => `<code>${E(k)}=${E(typeof v === 'object' ? JSON.stringify(v) : v)}</code>`).join('')}</div>` : ''}
              <div class="cs-acts" style="margin:4px 0 0">${f.actor ? `<button class="b" data-prof="${E(f.actor)}">👤 Προφίλ συσκευής</button>` : ''}<button class="b" data-promote="${i}">🗂 Άνοιξε υπόθεση</button></div></div></details>`;
        }).join('')}</div>`;
      } else h += `<div class="card sm">Πάτα «▶ Τρέξε το κυνήγι» για να ψάξεις.</div>`;
    }
    el.innerHTML = h;
    el.querySelectorAll('[data-h]').forEach(b => b.onclick = () => { HU.sel = b.dataset.h; huDraw(); });
    el.querySelectorAll('[data-run]').forEach(b => b.onclick = () => huRun(b.dataset.run));
    const all = el.querySelector('[data-all]'); if (all) all.onclick = huAll;
    el.querySelectorAll('details[data-k]').forEach(dt => dt.ontoggle = () => { dt.open ? HU.open.add(dt.dataset.k) : HU.open.delete(dt.dataset.k); });
    el.querySelectorAll('[data-prof]').forEach(b => b.onclick = ev => { ev.preventDefault(); showProfile(b.dataset.prof); });
    el.querySelectorAll('[data-promote]').forEach(b => b.onclick = () => {
      const f = (HU.res[HU.sel].findings || [])[+b.dataset.promote]; if (!f) return;
      const note = [f.summary, f.why, f.next].filter(Boolean).join(' — ') + (f.evidence ? ' [' + Object.entries(f.evidence).map(([k, v]) => k + '=' + (typeof v === 'object' ? JSON.stringify(v) : v)).join(', ') + ']' : '');
      P('/api/cases/new', { title: (cur ? cur.title + ': ' : '') + (f.actor_name || f.actor || ''), actors: [f.actor, f.target].filter(Boolean), sev: f.score >= 70 ? 'high' : f.score >= 40 ? 'med' : 'low', note })
        .then(j => { if (j.error) { HU.msg = { bad: 1, t: j.error }; huDraw(); } else { b.textContent = '✓ υπόθεση #' + (j.id || (j.case || {}).id || ''); b.onclick = () => openCase(j.id || (j.case || {}).id); } });
    });
  }
  window.renderHunt = () => { if (!HU.d) huLoad(); huDraw(); };

  // ───────────────────────── 👤 Προφίλ συσκευής (friendly intelligence) ─────────────────────────
  function hoursSvg(hs) {
    const mx = Math.max(1, ...hs), W = 336, H = 70, bw = W / 24;
    const bars = hs.map((v, i) => { const hh = Math.round((H - 14) * v / mx); return `<rect x="${(i * bw + 1).toFixed(1)}" y="${H - 12 - hh}" width="${(bw - 2).toFixed(1)}" height="${hh}" rx="2" fill="${i < 6 ? 'var(--purple)' : 'var(--cyan)'}" opacity="${v ? .85 : .15}"><title>${String(i).padStart(2, '0')}:00 — ${v}</title></rect>`; }).join('');
    const lab = [0, 6, 12, 18, 23].map(i => `<text x="${(i * bw + bw / 2).toFixed(1)}" y="${H - 1}" font-size="9" text-anchor="middle" fill="var(--dim)">${String(i).padStart(2, '0')}</text>`).join('');
    return `<svg viewBox="0 0 ${W} ${H}" width="100%" style="max-width:${W}px" data-noi18n>${bars}${lab}</svg>`;
  }
  function closeProfile() { const o = document.getElementById('pf-ov'); if (o) o.remove(); document.removeEventListener('keydown', pfKey); }
  function pfKey(e) { if (e.key === 'Escape') closeProfile(); }
  window.showProfile = ip => {
    closeProfile();
    const ov = document.createElement('div'); ov.id = 'pf-ov'; ov.className = 'pf-ov';
    ov.innerHTML = '<div class="card pf-box sm">φόρτωση…</div>';
    ov.onclick = e => { if (e.target === ov) closeProfile(); };
    document.body.appendChild(ov); document.addEventListener('keydown', pfKey);
    fetch('/api/hunt/profile?ip=' + encodeURIComponent(ip)).then(r => r.json()).then(p => {
      const box = ov.querySelector('.pf-box'); box.classList.remove('sm');
      if (p.error) { box.innerHTML = `<div class="brow"><b>👤 <span data-noi18n>${E(ip)}</span></b><button class="b" data-x>✕</button></div><div class="sm" style="margin-top:8px">${E(p.error)}</div>`; box.querySelector('[data-x]').onclick = closeProfile; return; }
      const fmt = typeof fmtB === 'function' ? fmtB : (b => b + ' B');
      box.innerHTML = `<div class="brow"><b class="ctitle">👤 ${E(p.name || p.ip)}</b><button class="b" data-x title="Κλείσιμο (Esc)">✕</button></div>
        <div class="sm" style="margin-top:2px" data-noi18n>${E(p.ip)}${p.mac ? ' · ' + E(p.mac) : ''}${p.kind ? ' · ' + E(p.kind) : ''}</div>
        <div style="margin-top:10px;padding:8px 10px;border-radius:8px;background:color-mix(in srgb,var(--cyan) 9%,transparent);border-left:3px solid var(--cyan)"><b>Τι είναι «κανονικό» για αυτή τη συσκευή:</b> <span data-noi18n>${E((EN() && p.normal_en) || p.normal || '—')}</span></div>
        <div class="sm" style="margin-top:6px">Η «friendly intelligence» του Chris Sanders: για να δεις το περίεργο, πρέπει πρώτα να ξέρεις το φυσιολογικό.</div>
        <div class="pf-g">
          <div><div class="cs-h" style="margin-top:0">Δραστηριότητα ανά ώρα (24ω)</div>${hoursSvg(p.hours && p.hours.length === 24 ? p.hours : new Array(24).fill(0))}<div class="sm">μωβ = νυχτερινές ώρες 00–06</div>
            <div class="cs-h">Κίνηση</div><div class="sm">⬇ ${fmt(p.bytes_in || 0)} · ⬆ ${fmt(p.bytes_out || 0)} · ειδοποιήσεις: ${p.alerts || 0}</div>
            ${(p.ports || []).length ? `<div class="cs-h">Θύρες</div><div class="cs-chips" data-noi18n>${p.ports.slice(0, 14).map(x => `<span class="cs-chip">${E(x.port)}${x.proto ? '/' + E(String(x.proto).toLowerCase()) : ''} <span class="sm">×${E(x.count)}</span></span>`).join('')}</div>` : ''}
            ${p.protos && Object.keys(p.protos).length ? `<div class="cs-h">Πρωτόκολλα</div><div class="cs-chips" data-noi18n>${Object.entries(p.protos).slice(0, 10).map(([k, v]) => `<span class="cs-chip">${E(k)} <span class="sm">×${E(v)}</span></span>`).join('')}</div>` : ''}</div>
          <div><div class="cs-h" style="margin-top:0">Με ποιους μιλά</div>
            <table class="pf-t">${(p.top_peers || []).slice(0, 10).map(x => `<tr><td data-noi18n>${E(x.name || x.peer)}${x.cc ? ' <span class="sm">' + E(x.cc) + '</span>' : ''}</td><td>${fmt(x.bytes || 0)}</td></tr>`).join('') || '<tr><td class="sm">—</td><td></td></tr>'}</table>
            ${(p.countries || []).length ? `<div class="cs-h">Χώρες που ξέρει</div><div class="cs-chips" data-noi18n>${p.countries.map(c => `<span class="cs-chip">${E(typeof c === 'object' ? (c.cc || c.country || JSON.stringify(c)) : c)}</span>`).join('')}</div>` : ''}
            ${(p.fingerprints || []).length ? `<div class="cs-h">TLS fingerprints (JA3/JA4)</div><div class="cs-chips" data-noi18n>${p.fingerprints.slice(0, 6).map(f => `<code style="font-size:10.5px">${E(typeof f === 'object' ? (f.ja4 || f.ja3 || f.fp || JSON.stringify(f)) + (f.sni ? ' · ' + f.sni : '') : f)}</code>`).join('')}</div>` : ''}</div>
        </div>`;
      box.querySelector('[data-x]').onclick = closeProfile;
    }).catch(e => { ov.querySelector('.pf-box').textContent = String(e); });
  };

  window.SOCUI = { CS, HU, csDraw, huDraw };
})();
