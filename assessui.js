// ───────────────────────── 📋 Αναφορά «νέο δίκτυο» — βαθμός, «διόρθωσε πρώτα», ευρήματα, απογραφή, εξαγωγές ─────────────────────────
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const LANG = () => (EN() ? 'en' : 'el');
  const box = () => document.getElementById('t-assess');
  const SEVC = { high: 'var(--red)', med: 'var(--orange)', low: 'var(--yellow)', info: 'var(--cyan)' };
  const SEVL = () => ({ high: T('Υψηλό', 'High'), med: T('Μέτριο', 'Medium'), low: T('Χαμηλό', 'Low'), info: 'Info' });
  const GC = { A: '#3ddc97', B: '#9be15d', C: '#ffd23f', D: '#ff9f43', F: '#ff3b5c' };
  // 📈 ιστορικό βαθμού A–F στον χρόνο — καθαρό SVG sparkline
  function trendCard(hist) {
    hist = (hist || []).filter(x => x && typeof x.score === 'number');
    if (hist.length < 2) return '';
    const W = 320, H = 54, n = hist.length, max = 100;
    const x = i => n === 1 ? 0 : i * (W - 8) / (n - 1) + 4;
    const y = s => H - 6 - (s / max) * (H - 14);
    const pts = hist.map((p, i) => `${x(i).toFixed(1)},${y(p.score).toFixed(1)}`).join(' ');
    const first = hist[0], last = hist[n - 1], diff = last.score - first.score;
    const arrow = diff > 1 ? `▲ +${diff}` : diff < -1 ? `▼ ${diff}` : '→ 0';
    const col = diff > 1 ? 'var(--green,#3ddc97)' : diff < -1 ? 'var(--red)' : 'var(--dim)';
    const dots = hist.map((p, i) => `<circle cx="${x(i).toFixed(1)}" cy="${y(p.score).toFixed(1)}" r="2.4" fill="${GC[p.grade] || 'var(--dim)'}"><title>${E(p.day)} · ${p.grade} (${p.score})</title></circle>`).join('');
    return `<div class="card" style="margin-top:8px"><b>📈 ${T('Πώς πάει ο βαθμός στον χρόνο', 'How the score trends over time')}</b>
      <span class="dim" style="font-size:12.5px"> · ${n} ${T('μετρήσεις', 'samples')} · <span style="color:${col};font-weight:700">${arrow}</span> ${T('από την 1η', 'since the first')} (${E(first.grade)}→${E(last.grade)})</span>
      <svg viewBox="0 0 ${W} ${H}" width="100%" style="max-width:${W}px;margin-top:6px" role="img" aria-label="score trend">
        <polyline points="${pts}" fill="none" stroke="var(--cyan)" stroke-width="2"/>${dots}</svg>
      <div class="dim" style="font-size:12px">${T('Ένα σημείο τη μέρα, κάθε φορά που ανοίγεις αυτή την καρτέλα. Διόρθωσε ευρήματα → ανεβαίνει.', 'One point per day, each time you open this tab. Fix findings → it rises.')}</div></div>`;
  }
  let D = null, poll = null, filt = 'all';

  const css = document.createElement('style');
  css.textContent = `
#t-assess .as-hero{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
#t-assess .as-g{flex:none;width:84px;height:84px;border-radius:50%;border:6px solid var(--c);display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--c);box-shadow:0 0 18px color-mix(in srgb,var(--c) 35%,transparent)}
#t-assess .as-g b{font-size:30px;line-height:1}#t-assess .as-g span{font-size:11px}
#t-assess .as-kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));gap:8px;flex:1;min-width:240px}
#t-assess .as-kpi div{border:1px solid var(--line);border-radius:10px;padding:7px 9px;text-align:center}#t-assess .as-kpi b{display:block;font-size:20px}#t-assess .as-kpi span{font-size:11.5px;color:var(--dim)}
#t-assess .as-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
#t-assess .as-go{border-color:var(--cyan)!important;color:var(--cyan)!important;font-weight:600}
#t-assess .as-fix{margin:6px 0 0 20px;padding:0;font-size:13px}#t-assess .as-fix li{margin:5px 0}
#t-assess .as-pill{font-size:10.5px;font-weight:700;padding:2px 7px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap}
#t-assess .as-f{display:grid;grid-template-columns:80px minmax(0,1fr);gap:4px 10px;padding:9px 10px;border-left:3px solid var(--c);border-radius:8px;background:rgb(var(--w,255 255 255) / 3%);margin-top:6px;white-space:normal}
#t-assess .as-f .d{font-size:12.5px;color:var(--mid)}#t-assess .as-f .x{font-size:12.5px}#t-assess .as-f .ip{font:11.5px ui-monospace,Menlo,Consolas,monospace;color:var(--dim)}
#t-assess .as-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}#t-assess .as-tabs button.on{border-color:var(--cyan);color:var(--cyan)}
#t-assess .as-wrap{overflow:auto}#t-assess table{width:100%;border-collapse:collapse;font-size:12.5px}
#t-assess th{text-align:left;color:var(--dim);font-size:11px;font-weight:600;padding:6px;border-bottom:1px solid var(--line);white-space:nowrap}
#t-assess td{padding:6px;border-bottom:1px solid rgb(var(--w,255 255 255) / 6%)}#t-assess td.m{font-family:ui-monospace,Menlo,Consolas,monospace;white-space:nowrap}
#t-assess .as-ex{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:8px;margin-top:10px}
#t-assess .as-ex a{display:flex;flex-direction:column;gap:3px;text-decoration:none;color:inherit;border:1px solid var(--line);border-radius:10px;padding:9px 11px}
#t-assess .as-ex a:hover{border-color:var(--cyan)}#t-assess .as-ex span{font-size:11.5px;color:var(--dim)}
#t-assess .as-note{font-size:12px;color:var(--dim);margin-top:8px}
@media(max-width:600px){#t-assess .as-f{grid-template-columns:1fr}}
`;
  document.head.appendChild(css);

  const STEP = () => ({ l2guard: T('Rogue DHCP / ARP', 'Rogue DHCP / ARP'), triage: T('Φταίει το δίκτυο;', 'Is it the network?'), camexp: T('Κάμερες', 'Cameras') });

  function draw() {
    const b = box(); if (!b) return;
    b.setAttribute('data-noi18n', '');
    if (!D) { b.innerHTML = `<div class="card">${T('Φτιάχνω την αναφορά…', 'Building the report…')}</div>`; return; }
    if (D.error) { b.innerHTML = `<div class="card">⚠ ${E(D.error)}</div>`; return; }
    const S = D.summary || {}, C = D.counts || {}, N = D.network || {}, L = SEVL(), j = D.job || {};
    const running = j.state === 'running';
    let h = `<div class="card"><div class="as-hero"><div class="as-g" style="--c:${GC[D.grade] || 'var(--dim)'}"><b>${E(D.grade)}</b><span>${E(D.score)}/100</span></div>
      <div style="flex:2;min-width:220px"><b style="font-size:16px">📋 ${T('Αναφορά «νέο δίκτυο»', 'New-network assessment')}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${E(N.subnet || '—')} · gateway ${E(N.gateway || '—')} · ${T('από', 'from')} ${E(N.me || '—')}${D.demo ? ' · DEMO' : ''}</div>
      <div style="font-size:12.5px;margin-top:6px">${T('Μια σελίδα για τεχνικό ή πελάτη: τι υπάρχει στο δίκτυο, τι είναι επικίνδυνο και τι να διορθωθεί πρώτα.', 'One page for a technician or client: what is on the network, what is risky and what to fix first.')}</div></div>
      <div class="as-kpi"><div><b>${E(S.devices)}</b><span>${T('συσκευές', 'devices')}</span></div><div><b style="color:var(--red)">${E(C.high || 0)}</b><span>${L.high}</span></div>
      <div><b style="color:var(--orange)">${E(C.med || 0)}</b><span>${L.med}</span></div><div><b>${E(C.low || 0)}</b><span>${L.low}</span></div>
      <div><b>${E(S.new_24h)}</b><span>${T('νέες 24ώ', 'new 24h')}</span></div><div><b>${E(S.random_mac)}</b><span>${T('τυχαίες MAC', 'random MACs')}</span></div></div></div>
      ${trendCard(D.history)}
      <div class="as-row"><button class="b as-go" data-as="run"${running ? ' disabled' : ''}>${running ? '⏳ ' + T('Τρέχουν οι έλεγχοι…', 'Running checks…') : '▶ ' + T('Τρέξε τους ελέγχους', 'Run checks')}</button>
      <button class="b" data-as="reload">🔄 ${T('Ανανέωση', 'Refresh')}</button>
      <a class="b" href="/assess/report.html?lang=${LANG()}" target="_blank" rel="noopener">🖨 ${T('Αναφορά / PDF', 'Report / PDF')}</a></div>
      <div class="as-note">${T('Ο «Τρέξε τους ελέγχους» ξεκινά: rogue DHCP/ARP, «Φταίει το δίκτυο;» και σάρωση καμερών (αν είναι ενεργή) — μόνο σε ιδιωτικές διευθύνσεις. Τα υπόλοιπα έρχονται από ό,τι έχει ήδη δει το NetWatch.', '“Run checks” starts: rogue DHCP/ARP, “Is it the network?” and the camera scan (if enabled) — private addresses only. Everything else comes from what NetWatch has already seen.')}
      ${j.steps && j.steps.length ? '<br>' + j.steps.map(s => `${s.status === 'ok' ? '✅' : s.status === 'skip' ? '➖' : '⚠'} ${E(STEP()[s.id] || s.id)}`).join(' · ') : ''}</div></div>`;

    h += `<div class="card"><b>🛠 ${T('Διόρθωσε πρώτα αυτά', 'Fix these first')}</b>`;
    h += (D.fixes || []).length ? `<ol class="as-fix">${D.fixes.map(x => `<li><span class="as-pill" style="--c:${SEVC[x.sev]}">${E(L[x.sev])}</span> <b>${E(x.title)}</b> — ${E(x.fix)}</li>`).join('')}</ol>`
      : `<div style="margin-top:6px">✅ ${T('Τίποτα επείγον.', 'Nothing urgent.')}</div>`;
    h += `</div>`;

    const F = (D.findings || []).filter(f => filt === 'all' || f.sev === filt);
    h += `<div class="card"><b>🔎 ${T('Ευρήματα', 'Findings')} (${(D.findings || []).length})</b><div class="as-tabs">`
      + [['all', T('Όλα', 'All')], ['high', L.high], ['med', L.med], ['low', L.low], ['info', 'Info']].map(([k, t]) => `<button class="b${filt === k ? ' on' : ''}" data-as-f="${k}">${E(t)}</button>`).join('') + `</div>`;
    h += F.length ? F.map(f => `<div class="as-f" style="--c:${SEVC[f.sev]}"><div><span class="as-pill" style="--c:${SEVC[f.sev]}">${E(L[f.sev])}</span><div class="ip" style="margin-top:4px">${E(f.area)}</div></div>
      <div><b>${E(f.title)}</b>${f.detail ? `<div class="d">${E(f.detail)}</div>` : ''}${f.fix ? `<div class="x">→ ${E(f.fix)}</div>` : ''}${(f.ips || []).filter(Boolean).length ? `<div class="ip">${E(f.ips.filter(Boolean).slice(0, 8).join(', '))}</div>` : ''}</div></div>`).join('')
      : `<div style="margin-top:6px" class="dim">${T('Κανένα εύρημα σε αυτή την κατηγορία.', 'No findings in this category.')}</div>`;
    h += `</div>`;

    const inv = D.inventory || [];
    h += `<div class="card"><b>📟 ${T('Απογραφή συσκευών', 'Device inventory')} (${inv.length})</b><div class="as-wrap"><table><thead><tr><th>IP</th><th>MAC</th><th>${T('Όνομα', 'Name')}</th><th>${T('Κατασκευαστής', 'Vendor')}</th><th>${T('Τύπος', 'Type')}</th></tr></thead><tbody>`
      + inv.map(r => `<tr><td class="m">${E(r.ip)}</td><td class="m">${E(r.mac || '—')}${r.random_mac ? ' <span title="' + E(T('τυχαία (ιδιωτική) MAC', 'randomized (private) MAC')) + '">⚂</span>' : ''}</td>
        <td>${E((r.icon ? r.icon + ' ' : '') + (r.name || '—'))}${r.role === 'router' ? ' <span class="as-pill" style="--c:var(--cyan)">router</span>' : r.role === 'this' ? ` <span class="as-pill" style="--c:var(--green)">${T('εσύ', 'you')}</span>` : ''}</td>
        <td>${E(r.vendor || '—')}</td><td>${E(r.type || '—')}</td></tr>`).join('') + `</tbody></table></div></div>`;

    const q = '?lang=' + LANG();
    h += `<div class="card"><b>⬇ ${T('Εξαγωγή', 'Export')}</b><div class="as-ex">
      <a href="/assess/report.html${q}" target="_blank" rel="noopener"><b>🖨 HTML / PDF</b><span>${T('για τον πελάτη — «Εκτύπωση → Αποθήκευση ως PDF»', 'for the client — “Print → Save as PDF”')}</span></a>
      <a href="/assess/findings.csv${q}"><b>📑 ${T('Ευρήματα', 'Findings')} CSV</b><span>${T('για Excel / ticket', 'for Excel / tickets')}</span></a>
      <a href="/assess/inventory.csv${q}"><b>📟 ${T('Απογραφή', 'Inventory')} CSV</b><span>IP, MAC, ${T('όνομα, κατασκευαστής, τύπος', 'name, vendor, type')}</span></a>
      <a href="/assess/netbox-ip-addresses.csv${q}"><b>🗂 NetBox CSV</b><span>IPAM → IP Addresses → Import</span></a>
      <a href="/assess/report.json${q}"><b>{ } JSON</b><span>${T('για scripts / αυτοματισμούς', 'for scripts / automation')}</span></a></div>
      <div class="as-note">👁 ${E(D.visibility || '')}</div></div>`;
    b.innerHTML = h;
  }

  function load() {
    return fetch('/api/assess?lang=' + LANG()).then(r => r.json()).then(j => {
      D = j; draw();
      const running = j.job && j.job.state === 'running';
      if (running && !poll) poll = setInterval(() => { if (typeof tab !== 'undefined' && tab === 'assess') load(); else { clearInterval(poll); poll = null; } }, 1500);
      if (!running && poll) { clearInterval(poll); poll = null; }
    }).catch(() => { D = { error: T('Δεν φορτώθηκε η αναφορά.', 'Could not load the report.') }; draw(); });
  }

  document.addEventListener('click', e => {
    const f = e.target.closest('#t-assess [data-as-f]');
    if (f) { filt = f.dataset.asF; draw(); return; }
    const b = e.target.closest('#t-assess [data-as]'); if (!b) return;
    if (b.dataset.as === 'reload') { load(); return; }
    if (b.dataset.as === 'run') {
      b.disabled = true;
      fetch('/api/assess/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ lang: LANG() }) })
        .then(r => r.json()).then(() => load()).catch(() => load());
    }
  });
  window.renderAssess = () => load();
})();
