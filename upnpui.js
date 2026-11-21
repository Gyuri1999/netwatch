// ───────────────────────── 🔓 Θύρες που άνοιξαν μόνες τους στο router (UPnP) ─────────────────────────
// Μόνο ανάγνωση: διαβάζουμε τον πίνακα του router (GetGenericPortMappingEntry). Το κλείσιμο γίνεται στο router.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const tr = x => (EN() && window.I18N && I18N.t ? I18N.t(String(x || '')) : String(x || ''));
  const box = () => document.getElementById('t-upnp');
  const COL = { high: 'var(--red)', med: 'var(--orange)', low: 'var(--cyan)', off: 'var(--dim)' };
  const LBL = { high: ['κλείσ\' την', 'close it'], med: ['έλεγξέ την', 'check it'], low: ['μάλλον εντάξει', 'probably fine'], off: ['ανενεργή', 'disabled'] };
  let D = null, poll = null;

  const css = document.createElement('style');
  css.textContent = `
#t-upnp .up-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-upnp .up-big{font-size:34px}
#t-upnp .up-row{display:grid;grid-template-columns:150px minmax(0,1fr) auto;gap:4px 14px;align-items:start;border-left:3px solid var(--c);border-radius:10px;background:rgb(var(--w,255 255 255) / 3%);padding:10px 12px;margin-top:8px;font-size:13px}
#t-upnp .up-port{font-family:var(--mono,ui-monospace,monospace);font-size:13px}
#t-upnp .up-port b{font-size:17px}
#t-upnp .up-pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap}
#t-upnp .up-flow{font-size:12px;color:var(--dim);margin-top:2px}
#t-upnp ol{margin:6px 0 0 18px;padding:0;font-size:13px}#t-upnp li{margin:3px 0}
@media (max-width:600px){#t-upnp .up-row{grid-template-columns:1fr}}
`;
  document.head.appendChild(css);

  const when = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : T('ποτέ', 'never');
  const lease = s => !s ? T('μόνιμα', 'permanent') : s >= 3600 ? T(`για ${Math.round(s / 3600)} ώρ.`, `for ${Math.round(s / 3600)} h`) : T(`για ${Math.round(s / 60)} λεπτά`, `for ${Math.round(s / 60)} min`);

  function row(m) {
    const c = COL[m.level] || 'var(--dim)', d = m.dev || {};
    const name = d.name || m.client;
    return `<div class="up-row" style="--c:${c}">
      <div class="up-port"><b>${E(m.ext)}</b> <span class="dim">${E(m.proto)}</span><div class="up-flow">Internet → ${T('router', 'router')} :${E(m.ext)}</div></div>
      <div><b>${E(d.dicon || '❔')} ${E(name)}</b> <span class="dim">${E(m.client)}:${E(m.int)}${d.vendor ? ' · ' + E(d.vendor) : ''}${d.me ? T(' · αυτός ο υπολογιστής', ' · this computer') : ''}</span>
        <div class="dim" style="font-size:12px;margin-top:2px">${m.desc ? `«${E(m.desc)}» · ` : ''}${lease(m.lease)} · ${m.anyone ? T('ανοιχτή σε όλο το Internet', 'open to the whole Internet') : T('μόνο από ', 'only from ') + E(m.remote)}${m.since ? ' · ' + T('την είδα πρώτη φορά', 'first seen') + ' ' + when(m.since) : ''}</div>
        <div style="margin-top:4px">${E(tr(m.why))}</div></div>
      <span class="up-pill" style="--c:${c}">${T(...LBL[m.level] || LBL.off)}</span></div>`;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error === 'off') { b.innerHTML = `<div class="card">${T('Δεν είναι διαθέσιμο σε αυτή τη λειτουργία (π.χ. ανάλυση pcap).', 'Not available in this mode (e.g. pcap analysis).')}</div>`; return; }
    const ms = D.mappings || [], c = D.counts || {};
    const bad = (c.high || 0) + (c.med || 0);
    const icon = !D.scanned ? '⏳' : !D.router ? '✅' : c.high ? '🚨' : c.med ? '⚠️' : '✅';
    const head = !D.scanned ? T('Ο πρώτος έλεγχος γίνεται λίγο μετά την εκκίνηση…', 'The first check runs shortly after start…')
      : !D.router ? T('Κανένα router δεν απαντά σε UPnP — καλά νέα', 'No router answers UPnP — good news')
        : D.noread ? T('Το router έχει UPnP, αλλά δεν μου δίνει τον πίνακα', 'The router has UPnP but won’t give me the table')
          : !ms.length ? T('Το UPnP είναι ανοιχτό, αλλά καμία συσκευή δεν έχει ανοίξει θύρα', 'UPnP is on, but no device has opened a port')
            : bad ? T(`${ms.length} θύρες ανοιχτές προς το Internet · ${bad} θέλουν προσοχή`, `${ms.length} ports open to the Internet · ${bad} need attention`)
              : T(`${ms.length} θύρες ανοιχτές προς το Internet · όλες μοιάζουν αναμενόμενες`, `${ms.length} ports open to the Internet · all look expected`);
    let h = `<div class="card"><div class="up-hero"><span class="up-big">${icon}</span><div style="flex:1;min-width:240px">
      <b style="font-size:16px">${head}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${D.router ? `router ${E(D.router)}${D.server ? ' · ' + E(D.server) : ''}${D.service ? ' · ' + E(D.service) : ''} · ` : ''}${T('έλεγχος', 'checked')} ${D.demo ? 'demo' : when(D.scanned)} · ${T('αυτόματα κάθε 15 λεπτά', 'automatically every 15 min')}</div></div>
      <button class="b" data-up="refresh"${D.busy || D.demo ? ' disabled' : ''}>🔄 ${D.busy ? T('διαβάζω…', 'reading…') : T('Έλεγχος τώρα', 'Check now')}</button></div>
      ${D.demo ? `<div class="dim" style="font-size:12.5px;margin-top:8px">🧪 ${T('Demo: παράδειγμα πίνακα από router με MiniUPnPd.', 'Demo: example table from a MiniUPnPd router.')}</div>` : ''}
      ${D.error ? `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${E(tr(D.error))}</div>` : ''}
      <div class="dim" style="font-size:12.5px;margin-top:8px;line-height:1.55">${T('Με το <b>UPnP</b> οποιαδήποτε συσκευή του σπιτιού μπορεί να πει στο router «άνοιξέ μου μια θύρα προς το Internet» — χωρίς να σε ρωτήσει. Έτσι μια κάμερα ή ένα έξυπνο gadget γίνεται ορατό σε όλο τον κόσμο. Εδώ <b>διαβάζω μόνο</b> τον πίνακα του router (δεν ανοίγω ούτε κλείνω τίποτα) και σε ειδοποιώ όταν εμφανιστεί νέα θύρα.',
        'With <b>UPnP</b> any device at home can tell the router “open a port to the Internet for me” — without asking you. That is how a camera or smart gadget becomes visible to the whole world. Here I <b>only read</b> the router’s table (I don’t open or close anything) and alert you when a new port appears.')}</div></div>`;
    if (ms.length) h += `<div class="card"><b>${T('Θύρες που άνοιξαν συσκευές σου', 'Ports your devices opened')}</b>${ms.map(row).join('')}</div>`;
    if (D.router) {
      h += `<div class="card"><b>👉 ${T('Τι να κάνεις', 'What to do')}</b><ol>
        ${bad ? `<li>${T('Για κάθε κόκκινη/πορτοκαλί θύρα: κλείσε το «remote access / P2P / cloud» στις ρυθμίσεις της συσκευής ή της εφαρμογής της. Οι περισσότερες κάμερες δουλεύουν και χωρίς ανοιχτή θύρα.', 'For each red/orange port: turn off “remote access / P2P / cloud” in the device or its app. Most cameras work without an open port.')}</li>` : ''}
        <li>${T(`Μπες στο router (<code>http://${E(D.router)}</code>) → <b>Advanced / NAT / UPnP</b> και κλείσε το UPnP αν δεν το χρειάζεσαι. Οι θύρες σβήνουν αμέσως ή με επανεκκίνηση του router.`, `Open the router (<code>http://${E(D.router)}</code>) → <b>Advanced / NAT / UPnP</b> and turn UPnP off if you don’t need it. The ports disappear at once or after a router reboot.`)}</li>
        <li>${T('Αν παίζεις online (PS5/Xbox/Switch) και θες UPnP, κράτα το — αλλά βάλε κάμερες και IoT σε <b>ξεχωριστό Wi‑Fi επισκεπτών / VLAN</b>, ώστε να μην μπορούν να ανοίξουν θύρες.', 'If you game online (PS5/Xbox/Switch) and want UPnP, keep it — but put cameras and IoT on a separate <b>guest Wi‑Fi / VLAN</b> so they can’t open ports.')}</li>
        <li>${T('Θέλεις πρόσβαση στην κάμερα από έξω; Προτίμησε VPN (π.χ. WireGuard στο router) αντί για ανοιχτή θύρα.', 'Need camera access from outside? Prefer a VPN (e.g. WireGuard on the router) over an open port.')}</li></ol>
        <div class="dim" style="font-size:12px;margin-top:6px">CCNA: ${T('αυτό είναι <b>δυναμικό PAT / port forwarding</b> — η στατική εκδοχή είναι το', 'this is dynamic <b>PAT / port forwarding</b> — the static version is')} <code>ip nat inside source static tcp 192.168.1.30 554 interface Gi0/0 554</code></div></div>`;
    }
    b.innerHTML = h;
  }

  function load() {
    return fetch('/api/upnp').then(r => r.json()).then(j => {
      D = j; draw();
      if (D.busy && !poll) poll = setInterval(load, 1500);
      if (!D.busy && poll) { clearInterval(poll); poll = null; }
    }).catch(() => { D = { error: 'off' }; draw(); });
  }
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-upnp [data-up]'); if (!b) return;
    b.disabled = true;
    fetch('/api/upnp/refresh', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
      .then(r => r.json()).then(j => { D = j; draw(); if (!poll) poll = setInterval(load, 1500); }).catch(() => { b.disabled = false; });
  });
  window.renderUpnp = () => load();
})();
