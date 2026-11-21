// ───────────────────────── 🛡 Ευπάθειες για τις συσκευές σου (CISA KEV + EPSS) ─────────────────────────
// Ό,τι δείχνουμε είναι ευπάθειες που ΗΔΗ χρησιμοποιούν επιτιθέμενοι. Συνήθως ξέρουμε μόνο τον κατασκευαστή,
// γι' αυτό λέμε «πιθανόν σε αφορά — έλεγξε το μοντέλο σου», όχι «είσαι ευάλωτος».
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const tr = x => (EN() && window.I18N && I18N.t ? I18N.t(String(x || '')) : String(x || ''));
  const box = () => document.getElementById('t-vulns');
  const ICON = { router: '🌐', nas: '🗄', camera: '📷', printer: '🖨', iot: '💡', esp: '🔌', tv: '📺', speaker: '🔊', console: '🎮', pi: '🍓', vm: '🖥' };
  const EVI = { Apple: '🍎', Microsoft: '🪟', Google: '🤖', Android: '🤖', Samsung: '📱' };
  let D = null, poll = null;

  const css = document.createElement('style');
  css.textContent = `
#t-vulns .vw-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-vulns .vw-big{font-size:34px}
#t-vulns .vw-dev{border-left:3px solid var(--c);border-radius:10px;background:rgb(var(--w,255 255 255) / 3%);padding:10px 12px;margin-top:10px}
#t-vulns .vw-pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap}
#t-vulns .vw-v{display:grid;grid-template-columns:minmax(0,1fr) 110px;gap:4px 12px;padding:8px 0;border-top:1px solid rgb(var(--w,255 255 255) / 6%);font-size:13px}
#t-vulns .vw-v:first-of-type{border-top:0}
#t-vulns .vw-bar{height:6px;border-radius:99px;background:rgb(var(--w,255 255 255) / 8%);overflow:hidden;margin-top:3px}
#t-vulns .vw-bar i{display:block;height:100%;background:var(--c)}
#t-vulns .vw-desc{grid-column:1/-1;color:var(--dim);font-size:12px;line-height:1.5}
#t-vulns .vw-todo{margin:8px 0 0 18px;padding:0;font-size:13px}#t-vulns .vw-todo li{margin:3px 0}
#t-vulns code{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px}
@media (max-width:600px){#t-vulns .vw-v{grid-template-columns:1fr}}
`;
  document.head.appendChild(css);

  const when = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }) : T('ποτέ', 'never');
  const pct = x => x == null ? '' : (x * 100 < 1 ? '<1' : Math.round(x * 100)) + '%';
  const epssC = x => x == null ? 'var(--dim)' : x >= 0.5 ? 'var(--red)' : x >= 0.1 ? 'var(--orange)' : 'var(--yellow)';
  const nvd = c => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`;

  function vulnRow(v) {
    return `<div class="vw-v"><div><a href="${nvd(v.cveID)}" target="_blank" rel="noopener"><b>${E(v.cveID)}</b></a> · ${E(v.product)}
        ${v.model ? ` <span class="vw-pill" style="--c:var(--red)">${T('ταιριάζει το μοντέλο', 'model matches')}</span>` : ''}
        ${v.knownRansomwareCampaignUse === 'Known' ? ` <span class="vw-pill" style="--c:var(--red)">ransomware</span>` : ''}
        <div class="dim" style="font-size:12px">${E(v.vulnerabilityName)} · ${T('στη λίστα από', 'listed since')} ${E(v.dateAdded)}</div></div>
      <div style="--c:${epssC(v.epss)}">${v.epss != null ? `<span class="dim" style="font-size:11px">EPSS ${pct(v.epss)}</span><div class="vw-bar"><i style="width:${Math.max(3, Math.round(v.epss * 100))}%"></i></div>` : ''}</div>
      <div class="vw-desc">${E(v.shortDescription)}</div></div>`;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error === 'off') { b.innerHTML = `<div class="card">${T('Δεν είναι διαθέσιμο σε αυτή τη λειτουργία.', 'Not available in this mode.')}</div>`; return; }
    const devs = D.devices || [], ev = D.everyday || [];
    let h = `<div class="card"><div class="vw-hero"><span class="vw-big">${devs.length ? '⚠️' : '✅'}</span><div style="flex:1;min-width:240px">
      <b style="font-size:16px">${devs.length ? T(`${devs.length} συσκευές σου έχουν κατασκευαστή με ευπάθειες που ήδη εκμεταλλεύονται`, `${devs.length} of your devices are from a vendor with actively exploited vulnerabilities`) : T('Καμία συσκευή σου δεν ταιριάζει με τη λίστα', 'None of your devices match the list')}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">CISA KEV ${D.version ? 'v' + E(D.version) : ''} · ${D.count || 0} ${T('ευπάθειες', 'vulnerabilities')} · ${T('ενημέρωση', 'updated')} ${D.demo ? 'demo' : when(D.fetched)}</div></div>
      <button class="b" data-vw="refresh"${D.busy || D.demo ? ' disabled' : ''}>🔄 ${D.busy ? T('κατεβάζω…', 'downloading…') : T('Έλεγχος τώρα', 'Check now')}</button></div>
      ${D.demo ? `<div class="dim" style="font-size:12.5px;margin-top:8px">🧪 ${T('Demo: πραγματικές εγγραφές της CISA για τις συσκευές του demo (TP-Link, Hikvision, Apple).', 'Demo: real CISA entries for the demo devices (TP-Link, Hikvision, Apple).')}</div>` : ''}
      ${D.error ? `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${E(tr(D.error))}</div>` : ''}
      <div class="dim" style="font-size:12.5px;margin-top:8px;line-height:1.55">${T('Η <b>CISA KEV</b> είναι η λίστα της αμερικανικής υπηρεσίας κυβερνοασφάλειας με ευπάθειες που <b>ήδη</b> χρησιμοποιούνται σε επιθέσεις. Τη συγκρίνω τοπικά με τον <b>κατασκευαστή</b> κάθε συσκευής σου — δεν στέλνω τίποτα για το δίκτυό σου. Συνήθως δεν ξέρω το ακριβές μοντέλο ή το firmware, άρα «πιθανόν σε αφορά», όχι «είσαι ευάλωτος». Το <b>EPSS</b> είναι η πιθανότητα να χρησιμοποιηθεί η ευπάθεια σε επίθεση τις επόμενες 30 μέρες.',
        'The <b>CISA KEV</b> is the US cybersecurity agency’s list of vulnerabilities <b>already</b> used in attacks. I compare it locally with each device’s <b>vendor</b> — nothing about your network is sent. Usually I don’t know the exact model or firmware, so it means “may affect you”, not “you are vulnerable”. <b>EPSS</b> is the probability the vulnerability is used in an attack in the next 30 days.')}</div></div>`;
    for (const d of devs) {
      const c = d.model_match ? 'var(--red)' : d.gw ? 'var(--orange)' : 'var(--yellow)';
      h += `<div class="card vw-dev" style="--c:${c}"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <span style="font-size:20px">${d.gw ? '🌐' : ICON[d.dtype] || '❔'}</span><b>${E(d.name)}</b><span class="dim">${E(d.ip)} · ${E(d.vendor)}${d.gw ? ' · router' : ''}</span>
        <span class="vw-pill" style="--c:${c}">${d.model_match ? T('ταιριάζει και το μοντέλο — έλεγξε τώρα', 'model matches too — check now') : T('πιθανόν σε αφορά — έλεγξε το μοντέλο σου', 'may affect you — check your model')}</span>
        ${d.ransomware ? `<span class="vw-pill" style="--c:var(--red)">${T('χρησιμοποιείται από ransomware', 'used by ransomware')}</span>` : ''}</div>
        <div class="dim" style="font-size:12.5px;margin-top:4px">${T(`${d.count} ευπάθειες του κατασκευαστή ${d.vendor} στη λίστα`, `${d.count} ${d.vendor} vulnerabilities on the list`)}${d.count > d.vulns.length ? T(` · δείχνω τις ${d.vulns.length} πιο σημαντικές`, ` · showing the ${d.vulns.length} most important`) : ''} · <span>${T('περιγραφές από τη CISA (αγγλικά)', 'descriptions from CISA')}</span></div>
        ${d.vulns.map(vulnRow).join('')}
        <b style="font-size:13px;display:block;margin-top:8px">👉 ${T('Τι να κάνεις', 'What to do')}</b><ol class="vw-todo">
          <li>${T(`Βρες το <b>ακριβές μοντέλο</b> (ετικέτα κάτω από τη συσκευή ή σελίδα διαχείρισης) και σύγκρινέ το με τα «${E(d.vulns[0] && d.vulns[0].product)}» παραπάνω.`, `Find the <b>exact model</b> (label under the device or its admin page) and compare with “${E(d.vulns[0] && d.vulns[0].product)}” above.`)}</li>
          <li>${T('Αναβάθμισε το <b>firmware</b> από τη σελίδα υποστήριξης του κατασκευαστή.', 'Update the <b>firmware</b> from the vendor’s support page.')}</li>
          <li>${T('Αν δεν βγαίνουν πια ενημερώσεις (end-of-life), <b>αντικατάστησέ</b> το — ή τουλάχιστον κράτα το μακριά από το Internet.', 'If it gets no more updates (end-of-life), <b>replace</b> it — or at least keep it off the Internet.')}</li>
          <li>${T('Κλείσε port forwarding / UPnP / «απομακρυσμένη διαχείριση» προς αυτή τη συσκευή στον router.', 'Turn off port forwarding / UPnP / “remote management” to this device on the router.')}</li></ol></div>`;
    }
    if (ev.length) {
      h += `<div class="card"><b>💻 ${T('Υπολογιστές & κινητά', 'Computers & phones')}</b><div class="dim" style="font-size:12.5px;margin:3px 0 6px">${T('Εδώ δεν χρειάζεται να ψάξεις μοντέλα: κράτα το λειτουργικό και τον browser ενημερωμένα (αυτόματες ενημερώσεις ανοιχτές).', 'No need to hunt for models here: keep the OS and browser updated (automatic updates on).')}</div>`;
      for (const e of ev) {
        h += `<div class="vw-dev" style="--c:${e.recent ? 'var(--orange)' : 'var(--cyan)'}"><b>${EVI[e.vendor] || '💻'} ${E(e.vendor)}</b> <span class="vw-pill" style="--c:${e.recent ? 'var(--orange)' : 'var(--cyan)'}">${e.recent ? T(`${e.recent} νέες τις τελευταίες 30 μέρες`, `${e.recent} new in the last 30 days`) : T('καμία νέα τις τελευταίες 30 μέρες', 'none new in the last 30 days')}</span>
          <span class="dim" style="font-size:12px"> · ${T('σύνολο', 'total')} ${e.total} · ${E((e.devices || []).join(', '))}</span>
          <div style="margin-top:4px;font-size:12.5px">${(e.top || []).map(v => `<div>• <a href="${nvd(v.cveID)}" target="_blank" rel="noopener">${E(v.cveID)}</a> ${E(v.vulnerabilityName)} <span class="dim">(${E(v.dateAdded)})</span></div>`).join('')}</div>
          <div style="font-size:12.5px;margin-top:4px">👉 ${e.vendor === 'Apple' ? T('Ρυθμίσεις → Γενικά → Ενημέρωση λογισμικού (iPhone/iPad) · Ρυθμίσεις συστήματος → Γενικά → Ενημέρωση λογισμικού (Mac).', 'Settings → General → Software Update (iPhone/iPad) · System Settings → General → Software Update (Mac).')
            : e.vendor === 'Microsoft' ? T('Ρυθμίσεις → Windows Update → Έλεγχος για ενημερώσεις.', 'Settings → Windows Update → Check for updates.')
              : T('Ρυθμίσεις → Σύστημα → Ενημέρωση λογισμικού, και ενημέρωσε τις εφαρμογές από το store.', 'Settings → System → Software update, and update apps from the store.')}</div></div>`;
      }
      h += `</div>`;
    }
    h += `<div class="dim" style="font-size:11.5px;margin:8px 4px">${T('Πηγές', 'Sources')}: <a href="${E(D.source)}" target="_blank" rel="noopener">CISA KEV</a> · <a href="https://www.first.org/epss" target="_blank" rel="noopener">FIRST EPSS</a> · <a href="https://nvd.nist.gov/" target="_blank" rel="noopener">NVD</a>. ${E(D.attribution)}</div>`;
    b.innerHTML = h;
  }

  function load() {
    return fetch('/api/vulns').then(r => r.json()).then(j => {
      D = j; draw();
      if (D.busy && !poll) poll = setInterval(load, 1500);
      if (!D.busy && poll) { clearInterval(poll); poll = null; }
    }).catch(() => { D = { error: 'off' }; draw(); });
  }
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-vulns [data-vw]'); if (!b) return;
    b.disabled = true;
    fetch('/api/vulns/refresh', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
      .then(r => r.json()).then(j => { D = j; draw(); if (!poll) poll = setInterval(load, 1500); }).catch(() => { b.disabled = false; });
  });
  window.renderVulns = () => load();
})();
