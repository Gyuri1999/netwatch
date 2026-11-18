// 🧰 Εργαλεία δουλειάς: 🔎 «Φταίει το δίκτυο;» (triage + κείμενο για ticket) · 📸 Πριν/Μετά από αλλαγή · 📑 αντίγραφα ρυθμίσεων + diff (σαν Oxidized).
// Φορτώνεται μετά το index.html· χρησιμοποιεί showTab, tab, I18N.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const curTab = () => (typeof tab !== 'undefined' ? tab : null);
  const P = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) }).then(r => r.json().then(j => (r.ok ? j : Object.assign(j, { error: j.error || ('HTTP ' + r.status) }))));
  const J = u => fetch(u).then(r => r.json());
  const now = () => Date.now() / 1000;
  const since = t => { if (!t) return '—'; const s = Math.max(0, now() - t); return s < 90 ? Math.round(s) + '″' : s < 5400 ? Math.round(s / 60) + '′' : s < 172800 ? Math.round(s / 3600) + (EN() ? 'h' : 'ω') : Math.round(s / 86400) + (EN() ? 'd' : 'μ'); };
  const hm = t => t ? new Date(t * 1000).toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '—';
  const busyOn = () => { const a = document.activeElement; return a && (a.tagName === 'TEXTAREA' || a.tagName === 'INPUT' || a.tagName === 'SELECT'); };
  const SEVC = { high: 'var(--red)', med: 'var(--orange)', low: 'var(--yellow)', info: 'var(--cyan)' };
  function copy(btn, txt) { navigator.clipboard.writeText(txt).then(() => { const o = btn.innerHTML; btn.textContent = '✓'; setTimeout(() => btn.innerHTML = o, 1200); }); }

  const css = document.createElement('style');
  css.textContent = `
  .wt-steps{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .wt-step{margin:0;display:flex;gap:12px;align-items:flex-start;padding:10px 12px;border-left:3px solid var(--c);white-space:normal}
  .wt-ic{flex:none;width:28px;height:28px;border-radius:50%;display:grid;place-items:center;font-weight:800;font-size:14px;color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent)}
  .wt-step .bd{flex:1;min-width:0}.wt-step .bd .d{font-size:12.5px;color:var(--dim);margin-top:2px}.wt-step .bd .f{font-size:12.5px;margin-top:4px}
  .wt-step .ms{font-size:11px;color:var(--dim);flex:none}
  .wt-step.running .wt-ic{animation:wtp 1s infinite}@keyframes wtp{50%{opacity:.35}}
  .wt-verd{margin-top:12px;padding:12px 14px;border-radius:10px;border:1px solid var(--c);background:color-mix(in srgb,var(--c) 9%,transparent);white-space:normal}
  .wt-verd b.l{font-size:18px;color:var(--c)}
  .wt-ticket{width:100%;min-height:200px;font:12px/1.45 ui-monospace,Menlo,monospace;padding:10px;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--txt);resize:vertical;box-sizing:border-box}
  .wt-layers{display:flex;gap:4px;flex-wrap:wrap;margin-top:10px;font-size:11px}.wt-layers span{padding:3px 8px;border-radius:10px;border:1px solid var(--line);color:var(--dim)}.wt-layers span.ok{color:var(--green);border-color:color-mix(in srgb,var(--green) 40%,transparent)}.wt-layers span.bad{color:var(--red);border-color:var(--red);font-weight:700}
  .wt-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px}
  .wt-in{font:inherit;font-size:13px;padding:6px 9px;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--txt)}
  .wt-snaps{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.wt-snap{margin:0;padding:8px 11px;display:flex;flex-direction:column;gap:2px;cursor:pointer;border:1px solid transparent;font-size:12.5px;white-space:normal}.wt-snap.a{border-color:var(--cyan)}.wt-snap.b{border-color:var(--purple)}
  .wt-big{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin:12px 0}.wt-big .card{margin:0;text-align:center;display:flex;flex-direction:column;gap:2px}.wt-big b{font-size:22px}.wt-big span{font-size:11.5px;color:var(--dim)}
  .wt-t{width:100%;border-collapse:collapse;font-size:12.5px}.wt-t th{text-align:left;font-size:11px;color:var(--dim);font-weight:600;padding:6px}.wt-t td{padding:6px;border-top:1px solid rgb(var(--w) / 6%);vertical-align:top}
  .wt-pill{font-size:10.5px;font-weight:700;padding:2px 7px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent);white-space:nowrap}
  .cb-wrap{display:grid;grid-template-columns:minmax(260px,330px) 1fr;gap:12px;align-items:start;margin-top:12px}@media(max-width:900px){.cb-wrap{grid-template-columns:1fr}}
  .cb-dev{margin:0;padding:10px 12px;cursor:pointer;display:flex;flex-direction:column;gap:3px;white-space:normal;border:1px solid transparent}.cb-dev.sel{border-color:var(--cyan)}.cb-dev .r1{display:flex;gap:8px;align-items:center}.cb-dev .r1 b{flex:1;min-width:0}
  .cb-vers{display:flex;flex-direction:column;gap:4px;margin-top:8px;max-height:300px;overflow:auto}.cb-ver{display:flex;gap:8px;align-items:center;font-size:12px;padding:5px 8px;border-radius:6px;background:rgb(var(--w) / 3%);cursor:pointer}.cb-ver.sel{outline:1px solid var(--cyan)}.cb-ver .a{color:var(--green)}.cb-ver .r{color:var(--red)}
  .cb-diff{margin-top:10px;font:12px/1.5 ui-monospace,Menlo,monospace;border-radius:8px;border:1px solid var(--line);overflow:auto;max-height:60vh;background:var(--panel2)}
  .cb-diff div{padding:0 10px;white-space:pre}.cb-diff .p{background:color-mix(in srgb,var(--green) 14%,transparent);color:var(--green)}.cb-diff .m{background:color-mix(in srgb,var(--red) 14%,transparent);color:var(--red)}.cb-diff .h{color:var(--purple);background:rgb(var(--w) / 4%);margin-top:4px}
  .cb-risk{margin-top:10px;padding:8px 11px;border-radius:8px;border-left:3px solid var(--red);background:color-mix(in srgb,var(--red) 8%,transparent);font-size:12.5px;white-space:normal}
  .cb-tabs{display:flex;gap:6px;margin-top:10px}.cb-tabs .on{border-color:var(--cyan);color:var(--cyan)}
  `;
  document.head.appendChild(css);

  // ───────────────────────── 🔎 Φταίει το δίκτυο; ─────────────────────────
  const TR = { d: null, scen: 'dns', timer: null };
  const STI = { ok: ['✓', 'var(--green)'], warn: ['!', 'var(--orange)'], fail: ['✗', 'var(--red)'], skip: ['–', 'var(--dim)'], running: ['…', 'var(--cyan)'], pending: ['·', 'var(--dim)'] };
  const LAYERS = ['L1/L2', 'DHCP', 'Gateway', 'DNS', 'Internet/ISP', 'Captive portal', 'MTU', 'Quality'];
  function trLoad() { return J('/api/triage').then(j => { TR.d = j; if (curTab() === 'tri') trDraw(); if (j.status === 'running') { clearTimeout(TR.timer); TR.timer = setTimeout(trLoad, 450); } }).catch(() => { }); }
  function trDraw() {
    const el = document.getElementById('t-tri'); if (!el) return;
    const d = TR.d; if (!d) { el.innerHTML = '<div class="card sm">φόρτωση…</div>'; return; }
    const run = d.status === 'running', v = d.verdict, sc = d.scenarios || [];
    let h = `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">🔎 Φταίει το δίκτυο; ${d.demo ? '<span class="tag">demo</span>' : ''}</b>
      <button class="b pu-go" data-tr="run"${run ? ' disabled' : ''}>${run ? '⏳ Ελέγχω…' : '▶ Έλεγξε τώρα'}</button></div>
      <div class="sm" style="margin-top:6px">Ο χρήστης λέει «δεν έχω Internet». Αντί για 20′ ερωτήσεις, ένα κλικ ελέγχει τα στρώματα με τη σειρά του μοντέλου OSI — καλώδιο/Wi‑Fi → DHCP → gateway → DNS → Internet → captive portal → MTU → ποιότητα — και σταματά στο πρώτο που χαλάει. Στο τέλος σου δίνει <b>έτοιμο κείμενο για το ticket</b>.</div>
      ${sc.length ? `<div class="wt-row"><span class="sm">Σενάριο demo:</span>${sc.map(s => `<button class="b${TR.scen === s ? ' on' : ''}" style="${TR.scen === s ? 'border-color:var(--cyan);color:var(--cyan)' : ''}" data-sc="${E(s)}" data-noi18n>${E(s)}</button>`).join('')}</div>` : ''}
      <div class="wt-layers">${LAYERS.map(l => `<span class="${v && v.layer === l ? 'bad' : v && v.layer === 'OK' ? 'ok' : ''}" data-noi18n>${E(l)}</span>`).join('')}</div></div>`;
    if (d.off) h += `<div class="card sm">Δεν είναι διαθέσιμο σε αυτή τη λειτουργία.</div>`;
    const steps = d.steps || [];
    if (!steps.length && !run) h += `<div class="card sm">Πάτα «▶ Έλεγξε τώρα».</div>`;
    h += `<div class="wt-steps">${steps.map(s => {
      const [ic, c] = STI[s.status] || STI.pending;
      return `<div class="card wt-step ${E(s.status)}" style="--c:${c}"><span class="wt-ic">${ic}</span><div class="bd"><b>${E(s.title)}</b>${s.detail ? `<div class="d">${E(s.detail)}</div>` : ''}${s.fix && (s.status === 'fail' || s.status === 'warn') ? `<div class="f">🔧 ${E(s.fix)}</div>` : ''}</div><span class="ms" data-noi18n>${s.ms != null ? s.ms + ' ms' : ''}</span></div>`;
    }).join('')}</div>`;
    if (v && d.status === 'done') {
      const c = v.layer === 'OK' ? 'var(--green)' : 'var(--red)';
      h += `<div class="wt-verd" style="--c:${c}"><b class="l">${v.layer === 'OK' ? '✅' : '🎯'} <span data-noi18n>${E(v.layer)}</span></b> — <b>${E(v.text)}</b>${v.fix ? `<div class="sm" style="margin-top:6px;color:var(--txt)">🔧 ${E(v.fix)}</div>` : ''}</div>`;
    }
    if (d.ticket) h += `<div class="card" style="white-space:normal;margin-top:12px"><div class="brow"><b>🎫 Κείμενο για το ticket</b><button class="b" data-tr="copy">📋 Αντιγραφή</button></div>
      <div class="sm" style="margin:4px 0 8px">Χωρίς κωδικούς και χωρίς MAC άλλων συσκευών — έτοιμο για Jira / ServiceNow / email.</div><textarea class="wt-ticket" readonly data-noi18n>${E(d.ticket)}</textarea></div>`;
    el.innerHTML = h;
    const rb = el.querySelector('[data-tr="run"]');
    if (rb) rb.onclick = () => { rb.disabled = true; P('/api/triage/run', { lang: EN() ? 'en' : 'el', scenario: sc.length ? TR.scen : undefined }).then(j => { if (j.error) alert(j.error); trLoad(); }); };
    el.querySelectorAll('[data-sc]').forEach(b => b.onclick = () => { TR.scen = b.dataset.sc; trDraw(); });
    const cb = el.querySelector('[data-tr="copy"]'); if (cb) cb.onclick = () => copy(cb, d.ticket);
  }
  window.renderTri = () => { trLoad(); if (!TR.d) trDraw(); };

  // ───────────────────────── 📸 Πριν / Μετά ─────────────────────────
  const CH = { d: null, a: null, b: null, cmp: null, label: '', msg: null, timer: null, flt: 'diff' };
  const STC = { lost: ['✗ χάθηκε', 'var(--red)'], new: ['+ νέο', 'var(--cyan)'], changed: ['≠ άλλαξε', 'var(--orange)'], slower: ['🐢 πιο αργό', 'var(--yellow)'], same: ['= ίδιο', 'var(--dim)'] };
  const KIND = { host: '🖥 Συσκευή', port: '🔌 Θύρα', gateway: '🚪 Gateway', dns: '🔤 DNS', internet: '🌍 Internet', local: '💻 Εδώ' };
  function chLoad() {
    return J('/api/change').then(j => {
      if (CH.wasRun && j.status !== 'running') { CH.a = CH.b = null; CH.cmp = null; }
      CH.wasRun = j.status === 'running';
      CH.d = j; const ss = j.snapshots || [];
      if (ss.length >= 2 && (CH.a == null || CH.b == null || !ss.some(s => s.id === CH.a) || !ss.some(s => s.id === CH.b))) {
        const srt = ss.slice().sort((x, y) => x.t - y.t); CH.a = srt[srt.length - 2].id; CH.b = srt[srt.length - 1].id; CH.cmp = null;
      }
      if (CH.a != null && CH.b != null && !CH.cmp) chCompare(); else if (curTab() === 'chg' && !busyOn()) chDraw();
      if (j.status === 'running') { clearTimeout(CH.timer); CH.timer = setTimeout(chLoad, 800); }
    }).catch(() => { });
  }
  function chCompare() { return J(`/api/change/compare?a=${encodeURIComponent(CH.a)}&b=${encodeURIComponent(CH.b)}`).then(j => { CH.cmp = j; if (curTab() === 'chg' && !busyOn()) chDraw(); }); }
  function chDraw() {
    const el = document.getElementById('t-chg'); if (!el) return;
    const d = CH.d; if (!d) { el.innerHTML = '<div class="card sm">φόρτωση…</div>'; return; }
    const run = d.status === 'running', ss = (d.snapshots || []).slice().sort((x, y) => x.t - y.t), c = CH.cmp;
    let h = `<div class="card" style="white-space:normal"><b class="ctitle">📸 Πριν / Μετά από αλλαγή ${d.demo ? '<span class="tag">demo</span>' : ''}</b>
      <div class="sm" style="margin-top:6px">Ο κανόνας κάθε μηχανικού δικτύων: <b>pre-check → αλλαγή → post-check</b>. Πριν πειράξεις VLAN, firewall ή router, τράβα «φωτογραφία» (ποιος απαντά, ποιες θύρες είναι ανοιχτές, gateway, DNS, Internet). Μετά την αλλαγή τράβα δεύτερη: βλέπεις αμέσως τι χάλασε — πριν σε πάρει τηλέφωνο ο χρήστης.</div>
      <div class="wt-row"><button class="b pu-go" data-snap="Πριν"${run ? ' disabled' : ''}>📸 Πριν</button><button class="b pu-go" data-snap="Μετά"${run ? ' disabled' : ''}>📸 Μετά</button>
        <input class="wt-in" placeholder="ή δικό σου όνομα, π.χ. «μετά το VLAN 30»" maxlength="40" value="${E(CH.label)}" style="flex:1;min-width:200px"><button class="b" data-snap="custom"${run ? ' disabled' : ''}>📸 Τράβα</button>
        ${run ? `<span class="sm">⏳ Τραβάω «${E(d.running_label || '')}»…</span>` : ''}</div>
      ${CH.msg ? `<div class="sm" style="margin-top:6px;color:${CH.msg.bad ? 'var(--red)' : 'var(--green)'}">${E(CH.msg.t)}</div>` : ''}</div>`;
    if (d.off) h += `<div class="card sm">Δεν είναι διαθέσιμο σε αυτή τη λειτουργία.</div>`;
    if (ss.length) {
      h += `<div class="card" style="white-space:normal"><b>Φωτογραφίες</b> <span class="sm">— κλικ = «Α» (πριν) · shift+κλικ = «Β» (μετά)</span><div class="wt-snaps">${ss.map(s => `<div class="card wt-snap${s.id === CH.a ? ' a' : ''}${s.id === CH.b ? ' b' : ''}" data-sid="${E(s.id)}"><b>${s.id === CH.a ? '🅰 ' : s.id === CH.b ? '🅱 ' : ''}${E(s.label)}</b><span class="sm">${hm(s.t)} · πριν ${since(s.t)}</span><span class="sm">${s.hosts || 0} συσκευές · ${s.ports || 0} θύρες</span><button class="b" style="align-self:flex-start;padding:0 6px;margin-top:2px" data-del="${E(s.id)}" title="Διαγραφή">🗑</button></div>`).join('')}</div></div>`;
    } else h += `<div class="card sm">Καμία φωτογραφία ακόμη — πάτα «📸 Πριν».</div>`;
    if (c && !c.error) {
      const vc = c.verdict === 'bad' ? 'var(--red)' : c.verdict === 'warn' ? 'var(--orange)' : 'var(--green)', k = c.counts || {};
      h += `<div class="wt-verd" style="--c:${vc}"><b class="l">${c.verdict === 'bad' ? '🚨 Κάτι χάλασε' : c.verdict === 'warn' ? '⚠ Θέλει ματιά' : '✅ Όλα ίδια'}</b> — <b>${String(c.summary || '').split(', ').map(x => '<span>' + E(x) + '</span>').join(', ')}</b><div class="sm" style="margin-top:4px">🅰 ${E((c.a || {}).label)} (${hm((c.a || {}).t)}) → 🅱 ${E((c.b || {}).label)} (${hm((c.b || {}).t)})</div></div>
      <div class="wt-big"><div class="card"><b style="color:var(--red)">${k.lost || 0}</b><span>χάθηκαν</span></div><div class="card"><b style="color:var(--orange)">${k.changed || 0}</b><span>άλλαξαν</span></div><div class="card"><b style="color:var(--yellow)">${k.slower || 0}</b><span>πιο αργά</span></div><div class="card"><b style="color:var(--cyan)">${k.new || 0}</b><span>νέα</span></div><div class="card"><b>${k.same || 0}</b><span>ίδια</span></div></div>`;
      const items = (c.items || []).filter(i => CH.flt === 'all' || i.status !== 'same');
      h += `<div class="card" style="white-space:normal"><div class="brow"><b>Τι άλλαξε</b><span class="cb-tabs" style="margin:0"><button class="b${CH.flt === 'diff' ? ' on' : ''}" data-flt="diff">Μόνο διαφορές</button><button class="b${CH.flt === 'all' ? ' on' : ''}" data-flt="all">Όλα</button><button class="b" data-copy="1" title="Αντιγραφή για το change ticket">📋</button></span></div>
        ${items.length ? `<table class="wt-t"><tr><th></th><th>Τι</th><th>Πριν</th><th>Μετά</th><th>Σημείωση</th></tr>${items.map(i => { const s = STC[i.status] || STC.same; return `<tr><td><span class="wt-pill" style="--c:${i.status === 'same' ? 'var(--dim)' : SEVC[i.sev] || s[1]}">${s[0]}</span></td><td>${E(KIND[i.kind] || i.kind)}<div class="sm" data-noi18n>${E(i.name ? i.name + ' · ' : '')}${E(i.key)}</div></td><td>${E(i.before == null ? '—' : i.before)}</td><td>${E(i.after == null ? '—' : i.after)}</td><td class="sm">${E(i.note || '')}</td></tr>`; }).join('')}</table>` : '<div class="sm" style="margin-top:6px">Καμία διαφορά. 🎉</div>'}</div>`;
    } else if (c && c.error) h += `<div class="card sm" style="color:var(--red)">${E(c.error)}</div>`;
    el.innerHTML = h;
    const inp = el.querySelector('.wt-in'); if (inp) inp.oninput = () => { CH.label = inp.value; };
    el.querySelectorAll('[data-snap]').forEach(b => b.onclick = () => {
      let label = b.dataset.snap; if (label === 'custom') { label = (CH.label || '').trim(); if (!label) { inp && inp.focus(); return; } }
      if (EN() && label === 'Πριν') label = 'Before'; if (EN() && label === 'Μετά') label = 'After';
      P('/api/change/snapshot', { label }).then(j => { CH.msg = j.error ? { bad: 1, t: j.error } : null; CH.a = CH.b = null; CH.cmp = null; CH.label = ''; chLoad(); });
    });
    el.querySelectorAll('[data-sid]').forEach(b => b.onclick = ev => { if (ev.target.closest('[data-del]')) return; if (ev.shiftKey) CH.b = +b.dataset.sid; else CH.a = +b.dataset.sid; if (CH.a === CH.b) return chDraw(); CH.cmp = null; chCompare(); });
    el.querySelectorAll('[data-del]').forEach(b => b.onclick = () => { if (!confirm(EN() ? 'Delete this snapshot?' : 'Διαγραφή αυτής της φωτογραφίας;')) return; P('/api/change/delete', { id: +b.dataset.del }).then(() => { CH.a = CH.b = null; CH.cmp = null; chLoad(); }); });
    el.querySelectorAll('[data-flt]').forEach(b => b.onclick = () => { CH.flt = b.dataset.flt; chDraw(); });
    const cp = el.querySelector('[data-copy]');
    if (cp && c) cp.onclick = () => copy(cp, [`${c.summary || ''}`, `A: ${(c.a || {}).label} ${hm((c.a || {}).t)}  →  B: ${(c.b || {}).label} ${hm((c.b || {}).t)}`, ''].concat((c.items || []).filter(i => i.status !== 'same').map(i => `[${String(i.status).toUpperCase()}] ${i.kind} ${i.name ? i.name + ' ' : ''}${i.key}: ${i.before == null ? '—' : i.before} → ${i.after == null ? '—' : i.after}${i.note ? '  (' + i.note + ')' : ''}`)).join('\n'));
  }
  window.renderChg = () => { chLoad(); if (!CH.d) chDraw(); };

  // ───────────────────────── 📑 Αντίγραφα ρυθμίσεων ─────────────────────────
  const CB = { d: null, sel: null, vers: null, view: 'diff', ver: null, diff: null, text: null, msg: null, timer: null, paste: false };
  const VEND = { cisco_ios: 'Cisco IOS', mikrotik: 'MikroTik', openwrt: 'OpenWrt', linux: 'Linux', generic: '—' };
  const STD = { ok: ['✓ ok', 'var(--green)'], error: ['✗ σφάλμα', 'var(--red)'], never: ['ποτέ', 'var(--dim)'], running: ['⏳ τώρα', 'var(--cyan)'] };
  function cbLoad() {
    return J('/api/configs').then(j => {
      CB.d = j; const ds = j.devices || [];
      if (!CB.sel && ds.length) { CB.sel = ds[0].id; cbDev(); }
      if (curTab() === 'cfg' && !busyOn()) cbDraw();
      if (ds.some(x => x.status === 'running')) { clearTimeout(CB.timer); CB.timer = setTimeout(() => cbLoad().then(() => CB.sel && cbDev()), 1000); }
    }).catch(() => { });
  }
  function cbDev() {
    const id = CB.sel; if (!id) return;
    CB.vers = null; CB.diff = null; CB.text = null; CB.ver = null;
    J('/api/configs/versions?id=' + encodeURIComponent(id)).then(j => { CB.vers = j; cbDraw(); });
    cbDiff();
  }
  function cbDiff(ts) {
    const id = CB.sel, vs = (CB.vers && CB.vers.versions) || [];
    let q = 'id=' + encodeURIComponent(id);
    if (ts) { const i = vs.findIndex(v => v.ts === ts); q += '&b=' + ts + (vs[i + 1] ? '&a=' + vs[i + 1].ts : ''); }
    J('/api/configs/diff?' + q).then(j => { CB.diff = j; if (curTab() === 'cfg') cbDraw(); });
  }
  function cbShow(ts) { J('/api/configs/show?id=' + encodeURIComponent(CB.sel) + (ts ? '&ts=' + ts : '')).then(j => { CB.text = j; if (curTab() === 'cfg') cbDraw(); }); }
  const unmaskLbl = t => EN() ? String(t).replace(/<κρυφό>/g, '<hidden>') : t;
  function cbDraw() {
    const el = document.getElementById('t-cfg'); if (!el) return;
    const d = CB.d; if (!d) { el.innerHTML = '<div class="card sm">φόρτωση…</div>'; return; }
    const ds = d.devices || [], dev = ds.find(x => x.id === CB.sel), vs = (CB.vers && CB.vers.versions) || [];
    let h = `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">📑 Αντίγραφα ρυθμίσεων ${d.demo ? '<span class="tag">demo</span>' : ''}</b>
      <span style="display:flex;gap:6px"><button class="b" data-cb="paste">📋 Επικόλληση config</button><button class="b pu-go" data-cb="all">⬇ Backup όλων</button></span></div>
      <div class="sm" style="margin-top:6px">Σαν το <b>Oxidized</b> / <b>RANCID</b>: κάθε ${d.every_hours || 24} ώρες κατεβάζει μέσω SSH το running-config από switches/routers και κρατά ιστορικό. Βλέπεις με χρώματα <b>τι άλλαξε, πότε</b> — και το NetWatch σε ειδοποιεί για επικίνδυνες αλλαγές (νέος χρήστης, telnet, SNMP community, port forward). Οι κωδικοί κρύβονται πάντα στην οθόνη.</div>
      ${!d.demo && d.ssh_available === false ? '<div class="sm" style="margin-top:6px;color:var(--orange)">Δεν βρέθηκε το πρόγραμμα ssh σε αυτόν τον υπολογιστή.</div>' : ''}
      ${!ds.length && !d.off ? `<div class="sm" style="margin-top:8px">Δεν υπάρχουν συσκευές. Πρόσθεσέ τες στο <code>config.yaml</code> → <code>config_backup.devices</code> (μόνο με κλειδί SSH — δες το config.example.yaml), ή πάτα «📋 Επικόλληση config».</div>` : ''}
      ${CB.msg ? `<div class="sm" style="margin-top:6px;color:${CB.msg.bad ? 'var(--red)' : 'var(--green)'}">${E(CB.msg.t)}</div>` : ''}</div>`;
    if (d.off) h += `<div class="card sm">Δεν είναι διαθέσιμο σε αυτή τη λειτουργία.</div>`;
    if (CB.paste) h += `<div class="card" style="white-space:normal"><b>📋 Επικόλληση config</b> <span class="sm">— για συσκευές χωρίς SSH: κάνε <code>show running-config</code> και επικόλλησε εδώ.</span>
      <div class="wt-row"><select class="wt-in cb-pid">${ds.map(x => `<option value="${E(x.id)}"${x.id === CB.sel ? ' selected' : ''}>${E(x.name)}</option>`).join('')}<option value="__new">+ νέα συσκευή…</option></select>
        <input class="wt-in cb-pname" placeholder="όνομα νέας συσκευής" style="display:none"><input class="wt-in cb-pnote" placeholder="σημείωση (π.χ. «πριν το VLAN 30»)" style="flex:1"></div>
      <textarea class="wt-ticket cb-ptext" placeholder="hostname core-sw&#10;!&#10;vlan 10&#10; name USERS&#10;…" style="margin-top:8px"></textarea>
      <div class="wt-row"><button class="b pu-go" data-cb="save">💾 Αποθήκευση έκδοσης</button><button class="b" data-cb="cancel">Άκυρο</button></div></div>`;
    h += `<div class="cb-wrap"><div style="display:flex;flex-direction:column;gap:6px">${ds.map(x => {
      const s = STD[x.status] || STD.never;
      return `<div class="card cb-dev${x.id === CB.sel ? ' sel' : ''}" data-dev="${E(x.id)}"><div class="r1"><b>${E(x.name)}</b><span class="wt-pill" style="--c:${s[1]}">${s[0]}</span></div>
        <div class="sm" data-noi18n>${E(x.host || '')} · ${E(VEND[x.vendor] || x.vendor || '')}</div>
        <div class="sm">${x.versions || 0} εκδόσεις · τελευταία αλλαγή πριν ${since(x.last_change)}${x.last_added || x.last_removed ? ` · <span style="color:var(--green)" data-noi18n>+${x.last_added || 0}</span> <span style="color:var(--red)" data-noi18n>−${x.last_removed || 0}</span>` : ''}</div>
        ${(x.risky || []).length ? `<div class="sm" style="color:var(--orange)">⚠ ${x.risky.length} αλλαγές προς έλεγχο</div>` : ''}${x.error ? `<div class="sm" style="color:var(--red)">${E(x.error)}</div>` : ''}</div>`;
    }).join('')}</div><div>`;
    if (dev) {
      h += `<div class="card" style="white-space:normal;margin:0"><div class="brow"><b class="ctitle">${E(dev.name)}</b><button class="b" data-cb="one"${dev.status === 'running' ? ' disabled' : ''}>⬇ Backup τώρα</button></div>
        <div class="sm" data-noi18n>${E(dev.host || '')} · ${E(VEND[dev.vendor] || dev.vendor || '')}</div>
        <div class="sm">τελευταίο backup: ${hm(dev.last_backup)}</div>
        <div class="cb-tabs"><button class="b${CB.view === 'diff' ? ' on' : ''}" data-view="diff">± Τι άλλαξε</button><button class="b${CB.view === 'text' ? ' on' : ''}" data-view="text">📄 Ολόκληρο</button></div>`;
      const df = CB.diff;
      if (CB.view === 'diff') {
        if (df && (df.risky || []).length) h += `<div class="cb-risk"><b>⚠ Αλλαγές προς έλεγχο</b><ul style="margin:4px 0 0 18px;padding:0">${df.risky.map(r => `<li>${E(r)}</li>`).join('')}</ul></div>`;
        if (df && !df.error) h += `<div class="sm" style="margin-top:8px">${hm(df.a)} → ${hm(df.b)} · <span style="color:var(--green)" data-noi18n>+${df.added || 0}</span> <span style="color:var(--red)" data-noi18n>−${df.removed || 0}</span></div>
          <div class="cb-diff" data-noi18n>${(df.lines || []).map(l => `<div class="${l.op === '+' ? 'p' : l.op === '-' ? 'm' : l.op === '@' ? 'h' : ''}">${E(unmaskLbl((l.op === '@' ? '' : l.op) + l.text))}</div>`).join('') || '<div>(καμία διαφορά)</div>'}</div>`;
        else if (df && df.error) h += `<div class="sm" style="margin-top:8px">${E(df.error)}</div>`;
        else h += `<div class="sm" style="margin-top:8px">φόρτωση…</div>`;
      } else {
        if (!CB.text) { cbShow(CB.ver); h += `<div class="sm" style="margin-top:8px">φόρτωση…</div>`; }
        else h += `<div class="brow" style="margin-top:8px"><span class="sm">${hm(CB.text.ts)}</span><button class="b" data-cb="copytext">📋 Αντιγραφή</button></div><div class="cb-diff" data-noi18n>${E(unmaskLbl(CB.text.text || '')).split('\n').map(l => `<div>${l || ' '}</div>`).join('')}</div>`;
      }
      h += `<div class="cs-h" style="font-size:12px;font-weight:700;color:var(--dim);text-transform:uppercase;margin-top:14px">Ιστορικό εκδόσεων</div><div class="cb-vers">${vs.map((v, i) => `<div class="cb-ver${(CB.ver || (vs[0] || {}).ts) === v.ts ? ' sel' : ''}" data-ver="${v.ts}"><span>${hm(v.ts)}</span><span class="a" data-noi18n>+${v.added || 0}</span><span class="r" data-noi18n>−${v.removed || 0}</span>${v.level === 'risk' ? '<span style="color:var(--red)" title="επικίνδυνη αλλαγή">⚠</span>' : v.level === 'info' ? '<span style="color:var(--cyan)" title="σημαντική αλλαγή">ℹ</span>' : ''}<span class="sm" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${E(v.note || '')}</span><span class="sm" data-noi18n>${E(v.sha || '')}</span>${i === vs.length - 1 ? '<span class="sm">πρώτη</span>' : ''}</div>`).join('') || '<span class="sm">—</span>'}</div></div>`;
    }
    h += `</div></div>`;
    el.innerHTML = h;
    el.querySelectorAll('[data-dev]').forEach(b => b.onclick = () => { CB.sel = b.dataset.dev; CB.view = 'diff'; cbDev(); cbDraw(); });
    el.querySelectorAll('[data-view]').forEach(b => b.onclick = () => { CB.view = b.dataset.view; if (CB.view === 'text') CB.text = null; cbDraw(); });
    el.querySelectorAll('[data-ver]').forEach(b => b.onclick = () => { CB.ver = +b.dataset.ver; CB.text = null; CB.diff = null; if (CB.view === 'diff') cbDiff(CB.ver); cbDraw(); });
    const act = (n, f) => { const b = el.querySelector(`[data-cb="${n}"]`); if (b) b.onclick = f; };
    act('all', () => P('/api/configs/backup', { id: 'all' }).then(j => { CB.msg = j.error ? { bad: 1, t: j.error } : { t: EN() ? 'Backup started.' : 'Το backup ξεκίνησε.' }; cbLoad(); }));
    act('one', () => P('/api/configs/backup', { id: CB.sel }).then(j => { CB.msg = j.error ? { bad: 1, t: j.error } : null; cbLoad(); }));
    act('paste', () => { CB.paste = !CB.paste; cbDraw(); });
    act('cancel', () => { CB.paste = false; cbDraw(); });
    act('copytext', () => copy(el.querySelector('[data-cb="copytext"]'), unmaskLbl((CB.text || {}).text || '')));
    const pid = el.querySelector('.cb-pid'), pn = el.querySelector('.cb-pname');
    if (pid) pid.onchange = () => { pn.style.display = pid.value === '__new' ? '' : 'none'; };
    act('save', () => {
      const text = el.querySelector('.cb-ptext').value, note = el.querySelector('.cb-pnote').value.trim();
      if (!text.trim()) return;
      let body = { id: pid.value, text, note: note || undefined };
      if (pid.value === '__new') { const nm = pn.value.trim(); if (!nm) { pn.focus(); return; } body = { id: nm.toLowerCase().replace(/[^a-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'device', name: nm, vendor: /^\s*\//m.test(text) ? 'mikrotik' : /^\s*(hostname|interface|!)/m.test(text) ? 'cisco_ios' : 'generic', text, note: note || undefined }; }
      P('/api/configs/upload', body).then(j => { if (j.error) { CB.msg = { bad: 1, t: j.error }; cbDraw(); return; } CB.paste = false; CB.msg = { t: EN() ? 'Version saved.' : 'Η έκδοση αποθηκεύτηκε.' }; CB.sel = body.id; cbLoad().then(cbDev); });
    });
  }
  window.renderCfg = () => { cbLoad(); if (!CB.d) cbDraw(); };

  window.WORKTOOLS = { TR, CH, CB, trDraw, chDraw, cbDraw };
})();
