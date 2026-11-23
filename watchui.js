// ───────────────────────── 👁 Ποιος σε κοιτάζει; — trackers / ACR που «καλούν σπίτι» ─────────────────────────
// Παθητικό, μόνο ανάγνωση. Δείχνει ποιες γνωστές υπηρεσίες παρακολούθησης επικοινωνούν οι συσκευές σου (π.χ. η TV).
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const tr = x => (EN() && window.I18N && I18N.t ? I18N.t(String(x || '')) : String(x || ''));
  const box = () => document.getElementById('t-watch');
  const CATC = { acr: 'var(--red)', ads: 'var(--orange)', social: '#b86fd6', analytics: 'var(--cyan)' };
  const CATL = { acr: ['ACR — τι βλέπεις', 'ACR — what you watch'], ads: ['Διαφημίσεις', 'Ads'], social: ['Κοινωνικά', 'Social'], analytics: ['Τηλεμετρία', 'Analytics'] };
  let D = null, poll = null;

  const css = document.createElement('style');
  css.textContent = `
#t-watch .w-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-watch .w-big{font-size:34px}
#t-watch .w-dev{border-left:3px solid var(--c);border-radius:10px;background:rgb(var(--w,255 255 255) / 3%);padding:10px 12px;margin-top:10px}
#t-watch .w-pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap}
#t-watch .w-tr{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:3px 12px;padding:7px 0;border-top:1px solid rgb(var(--w,255 255 255) / 6%);font-size:13px}
#t-watch .w-tr:first-of-type{border-top:0}
#t-watch .w-meta{color:var(--dim);font-size:12px}
#t-watch .w-fix{background:color-mix(in srgb,var(--orange) 12%,transparent);border-left:3px solid var(--orange);padding:8px 10px;margin-top:8px;border-radius:0 8px 8px 0;font-size:13px}
#t-watch .w-score{font-weight:700}
#t-watch .w-chips{display:flex;flex-wrap:wrap;gap:6px;margin:4px 0}
#t-watch code{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px}
@media (max-width:600px){#t-watch .w-tr{grid-template-columns:1fr}}
`;
  document.head.appendChild(css);

  const ago = t => { if (!t) return ''; const s = Math.max(0, Date.now() / 1000 - t); return s < 90 ? T(`πριν ${Math.round(s)}″`, `${Math.round(s)}s ago`) : s < 5400 ? T(`πριν ${Math.round(s / 60)}′`, `${Math.round(s / 60)} min ago`) : T(`πριν ${Math.round(s / 3600)} ώρ.`, `${Math.round(s / 3600)} h ago`); };
  const scoreC = n => n >= 70 ? 'var(--green)' : n >= 40 ? 'var(--orange)' : 'var(--red)';

  function trRow(i) {
    const c = CATC[i.cat] || 'var(--dim)';
    return `<div class="w-tr"><div><b>${E(i.company)}</b> <span class="w-pill" style="--c:${c}">${T(...(CATL[i.cat] || [i.cat, i.cat]))}</span>
        <div class="w-meta"><code>${E(i.sample)}</code>${i.country ? ' · ' + E(i.country) : ''} · ${i.count}× ${i.last ? '· ' + ago(i.last) : ''}</div></div></div>`;
  }

  function devCard(d) {
    const c = d.acr ? 'var(--red)' : d.companies >= 3 ? 'var(--orange)' : 'var(--cyan)';
    return `<div class="card w-dev" style="--c:${c}"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <span style="font-size:20px">${E(d.icon || '❔')}</span><b>${E(d.name)}</b>
      <span class="dim" style="font-size:12px">${E(d.ip)}${d.type ? ' · ' + E(d.type) : ''}</span>
      ${d.acr ? `<span class="w-pill" style="--c:var(--red)">${T('ACR — «βλέπει» τι παρακολουθείς', 'ACR — sees what you watch')}</span>` : ''}
      <span style="flex:1"></span><span class="dim" style="font-size:12.5px">${T('Ιδιωτικότητα', 'Privacy')} <span class="w-score" style="color:${scoreC(d.score)}">${d.score}/100</span></span></div>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${T(`${d.companies} υπηρεσίες παρακολούθησης «καλεί σπίτι» αυτή η συσκευή`, `${d.companies} tracking services this device phones home to`)}</div>
      ${d.trackers.map(trRow).join('')}
      ${d.acr_fix ? `<div class="w-fix">📺 ${T('Κλείσε το ACR', 'Turn off ACR')} (${E(d.brand)}): ${E(tr(d.acr_fix))}</div>` : ''}</div>`;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error === 'off') { b.innerHTML = `<div class="card">${T('Διαθέσιμο σε Live και Demo.', 'Available in Live and Demo.')}</div>`; return; }
    const devs = D.devices || [];
    let h = `<div class="card"><div class="w-hero"><span class="w-big">${D.acr_devices ? '👁' : devs.length ? '🔎' : '✅'}</span><div style="flex:1;min-width:240px">
      <b style="font-size:16px">${devs.length ? T(`${D.companies} εταιρείες παρακολούθησης «ακούν» το δίκτυό σου`, `${D.companies} tracking companies are listening to your network`) : T('Καμία γνωστή υπηρεσία παρακολούθησης — προς το παρόν', 'No known tracking service — so far')}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${D.acr_devices ? T(`⚠ ${D.acr_devices} συσκευές με ACR (π.χ. TV που «βλέπει» τι παρακολουθείς)`, `⚠ ${D.acr_devices} devices with ACR (e.g. a TV that “sees” what you watch)`) : T('Παθητική παρατήρηση SNI/DNS', 'Passive SNI/DNS observation')}</div></div>
      <button class="b" data-wreport>🖨 ${T('Αναφορά / PDF', 'Report / PDF')}</button></div>
      ${D.demo ? `<div class="dim" style="font-size:12.5px;margin-top:8px">🧪 ${T('Demo: παράδειγμα με μια LG TV που καλεί υπηρεσίες ACR.', 'Demo: example with an LG TV calling ACR services.')}</div>` : ''}
      <div class="dim" style="font-size:12.5px;margin-top:8px;line-height:1.55">${T('Οι έξυπνες συσκευές — ιδίως οι <b>τηλεοράσεις</b> — «καλούν σπίτι»: στέλνουν σε διαφημιστικές εταιρείες τι κάνεις. Οι TV έχουν <b>ACR</b> που αναγνωρίζει τι παρακολουθείς, ακόμη κι από HDMI/USB. Εδώ βλέπω <b>παθητικά</b> (από το SNI των συνδέσεων και τα ονόματα DNS) σε ποιες γνωστές τέτοιες υπηρεσίες μιλάνε οι συσκευές σου. <b>Δεν μπλοκάρω τίποτα</b> — για μπλοκάρισμα: Pi-hole ή ο router σου.',
        'Smart devices — especially <b>TVs</b> — phone home: they send ad companies what you do. TVs have <b>ACR</b> that recognises what you watch, even from HDMI/USB. Here I passively see (from connection SNI and DNS names) which known such services your devices talk to. <b>I block nothing</b> — to block: Pi-hole or your router.')}</div></div>`;
    for (const d of devs) h += devCard(d);
    if ((D.top || []).length) {
      h += `<div class="card"><b>${T('Οι εταιρείες που «ακούν» πιο πολύ', 'The companies listening most')}</b><div class="w-chips" style="margin-top:8px">`;
      for (const t of D.top) h += `<span class="w-pill" style="--c:${CATC[t.cat] || 'var(--dim)'}">${E(t.company)} · ${t.count}×</span>`;
      h += `</div></div>`;
    }
    h += `<div class="dim" style="font-size:11.5px;margin:8px 4px">${T('Λίστα γνωστών trackers/ACR (Samba TV, LG/Samsung/Vizio ACR, Nielsen, Google/Amazon ads…). Σύγκριση τοπικά — τίποτα δεν φεύγει από το δίκτυό σου.', 'Known tracker/ACR list (Samba TV, LG/Samsung/Vizio ACR, Nielsen, Google/Amazon ads…). Matched locally — nothing leaves your network.')}</div>`;
    b.innerHTML = h;
  }

  function load() {
    return fetch('/api/watchers').then(r => r.json()).then(j => { D = j; draw(); }).catch(() => { D = { error: 'off' }; draw(); });
  }
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-watch [data-wreport]'); if (!b) return;
    window.open('/api/watchers/report.html?lang=' + (EN() ? 'en' : 'el'), '_blank', 'noopener');
  });
  window.renderWatch = () => { load(); clearInterval(poll); poll = setInterval(() => { if (box() && box().offsetParent) load(); }, 20000); };
})();
