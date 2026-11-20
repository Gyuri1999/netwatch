// ───────────────────────── 🛡 Rogue DHCP / ARP spoofing — έλεγχος με ένα κουμπί + θεωρία CCNA ─────────────────────────
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const box = () => document.getElementById('t-l2g');
  let R = null, busy = false;
  const IC = { ok: '✅', warn: '⚠️', bad: '🚨', err: '✖' }, COL = { ok: 'green', warn: 'orange', bad: 'red', err: 'red' };

  const css = document.createElement('style');
  css.textContent = `
#t-l2g .lg-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-l2g .lg-big{font-size:40px}
#t-l2g .lg-chk{display:grid;grid-template-columns:28px minmax(0,1fr);gap:8px;padding:9px 10px;border-radius:10px;margin-top:6px;background:rgb(var(--w,255 255 255) / 4%);font-size:13.5px;line-height:1.5}
#t-l2g table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:6px}
#t-l2g th{text-align:left;color:var(--dim);font-size:11px;font-weight:600;padding:6px;border-bottom:1px solid var(--line)}
#t-l2g td{padding:6px;border-bottom:1px solid rgb(var(--w,255 255 255) / 6%);font-family:ui-monospace,Menlo,Consolas,monospace;white-space:nowrap}
#t-l2g tr.rogue td{background:color-mix(in srgb,var(--red) 12%,transparent)}
#t-l2g .lg-wrap{overflow:auto}
#t-l2g pre{background:#05080f;color:#d6e2f0;border-radius:10px;padding:10px 12px;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;overflow:auto;margin:8px 0 0}
#t-l2g .lg-th{font-size:13px;line-height:1.65}
#t-l2g .lg-th code{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px}
#t-l2g .lg-go{border-color:var(--cyan)!important;color:var(--cyan)!important;font-weight:600;padding:8px 16px!important;font-size:13.5px!important}
`;
  document.head.appendChild(css);

  function draw() {
    const b = box(); if (!b) return;
    b.setAttribute('data-noi18n', '');
    const r = R || {};
    let h = `<div class="dim" style="font-size:12.5px;margin-bottom:8px">🔒 ${T('Στέλνω ένα DHCPDISCOVER και ένα ARP «ποιος είναι ο router;» <b>μόνο στο τοπικό σου δίκτυο</b> και βλέπω ποιος απαντά. Δεν παίρνω διεύθυνση και δεν αλλάζω τίποτα.', 'I send one DHCPDISCOVER and one ARP “who is the router?” <b>only on your local network</b> and see who answers. I take no address and change nothing.')}</div>`;
    const v = r.verdict;
    h += `<div class="card"><div class="lg-hero"><span class="lg-big">${r.never || !v ? '🛡' : IC[v]}</span><div style="flex:1;min-width:220px"><b style="font-size:16px">${r.never || !v ? T('Υπάρχει «ψεύτικος» router ή DHCP στο δίκτυό μου;', 'Is there a fake router or DHCP server on my network?') : v === 'ok' ? T('Όλα καθαρά', 'All clear') : v === 'bad' ? T('Βρέθηκε πρόβλημα!', 'Problem found!') : T('Χρειάζεται προσοχή', 'Needs attention')}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${r.t ? T('Τελευταίος έλεγχος', 'Last check') + ': ' + new Date(r.t * 1000).toLocaleTimeString(EN() ? 'en-GB' : 'el-GR') + (r.iface ? ' · ' + E(r.iface) : '') + (r.gateway ? ' · router ' + E(r.gateway) : '') + (r.demo ? ' · demo' : '') : T('Πάτα «Έλεγχος» — παίρνει ~6 δευτερόλεπτα.', 'Press “Check” — takes ~6 seconds.')}</div></div>
      <button class="b lg-go" data-lg="run"${busy ? ' disabled' : ''}>${busy ? '⏳ ' + T('Ελέγχω…', 'Checking…') : '🔍 ' + T('Έλεγχος', 'Check')}</button></div>
      ${(r.checks || []).map(c => `<div class="lg-chk" style="border-left:3px solid var(--${COL[c.level]})"><span>${IC[c.level]}</span><span>${E(EN() ? c.en : c.el)}</span></div>`).join('')}`;
    if (r.offers && r.offers.length) h += `<div style="margin-top:12px"><b>📨 ${T('Ποιοι απάντησαν στο DHCP', 'Who answered DHCP')}</b><div class="lg-wrap"><table><tr><th>DHCP server</th><th>MAC</th><th>${T('Συσκευή', 'Device')}</th><th>${T('Προσφέρει IP', 'Offers IP')}</th><th>Gateway</th><th>DNS</th></tr>
      ${r.offers.map(o => `<tr class="${o.is_gw ? '' : 'rogue'}"><td>${o.is_gw ? '' : '🚨 '}${E(o.server)}</td><td>${E(o.mac)}</td><td style="font-family:inherit">${E(o.name || (o.is_gw ? 'router' : '—'))}</td><td>${E(o.offer)}</td><td>${E(o.router)}</td><td>${E((o.dns || []).join(', '))}</td></tr>`).join('')}</table></div></div>`;
    if (r.arp && r.arp.replies) h += `<div class="dim" style="font-size:12.5px;margin-top:10px">🔗 ARP router: ${T('απαντήσεις', 'replies')} <code>${E(r.arp.replies.join(', ') || '—')}</code> · ${T('πίνακας ARP', 'ARP table')} <code>${E(r.arp.cache || '—')}</code> · ${T('αρχική', 'first seen')} <code>${E(r.arp.trusted || '—')}</code></div>`;
    if (v === 'bad') h += `<div class="lg-chk" style="margin-top:12px;border-left:3px solid var(--cyan)"><span>🧭</span><span>${T('<b>Τι κάνω τώρα;</b> 1) Δες τη MAC/IP του ύποπτου στη λίστα συσκευών (📟) ή με «🔌 Πού είναι συνδεδεμένο;». 2) Συχνή αιτία στο σπίτι: <b>δεύτερος router / mesh (π.χ. Deco) σε λειτουργία router</b> αντί για Access Point, ή καλώδιο στη θύρα LAN αντί για WAN. 3) Αν δεν είναι δικό σου: αποσύνδεσέ το και άλλαξε τον κωδικό του Wi-Fi.', '<b>What now?</b> 1) Find the suspect’s MAC/IP in the device list (📟) or with “🔌 Where is it connected?”. 2) A common home cause: <b>a second router / mesh (e.g. Deco) in router mode</b> instead of Access Point, or a cable in a LAN port instead of WAN. 3) If it isn’t yours: disconnect it and change the Wi-Fi password.')}</span></div>`;
    h += `</div>`;
    h += `<div class="card lg-th"><b>📚 ${T('Πώς δουλεύουν οι επιθέσεις (CCNA 5.0)', 'How the attacks work (CCNA 5.0)')}</b>
      <div style="margin-top:6px">${T('<b>Rogue DHCP:</b> ο επιτιθέμενος απαντά στα DHCPDISCOVER πιο γρήγορα από τον router και δίνει <b>τον εαυτό του</b> ως gateway/DNS → όλη η κίνηση περνά από εκείνον (MITM). Άμυνα: <b>DHCP snooping</b> — το switch δέχεται OFFER/ACK μόνο από θύρες <code>trust</code> και κρατά πίνακα <i>IP ↔ MAC ↔ θύρα ↔ VLAN</i>.', '<b>Rogue DHCP:</b> the attacker answers DHCPDISCOVER faster than the router and hands out <b>itself</b> as gateway/DNS → all traffic goes through it (MITM). Defence: <b>DHCP snooping</b> — the switch accepts OFFER/ACK only on <code>trust</code> ports and builds an <i>IP ↔ MAC ↔ port ↔ VLAN</i> table.')}</div>
      <div style="margin-top:6px">${T('<b>ARP spoofing:</b> στέλνει ψεύτικα ARP replies «η IP του router είναι η δική μου MAC» → οι συσκευές στέλνουν σε εκείνον. Άμυνα: <b>Dynamic ARP Inspection (DAI)</b> — το switch ελέγχει κάθε ARP με τον πίνακα του DHCP snooping και πετά όσα δεν ταιριάζουν. Γι’ αυτό το DAI <b>χρειάζεται</b> DHCP snooping.', '<b>ARP spoofing:</b> it sends fake ARP replies “the router’s IP is my MAC” → devices send to it. Defence: <b>Dynamic ARP Inspection (DAI)</b> — the switch checks every ARP against the DHCP snooping table and drops mismatches. That is why DAI <b>needs</b> DHCP snooping.')}</div>
      <div style="margin-top:6px">${T('💡 Στις εξετάσεις: το <code>limit rate</code> βάζει τη θύρα σε <b>err-disabled</b> αν ξεπεράσει τα πακέτα/δευτ. Οι θύρες προς router/άλλα switches είναι <code>trust</code>, οι θύρες χρηστών μένουν untrusted (προεπιλογή).', '💡 For the exam: <code>limit rate</code> puts the port in <b>err-disabled</b> if it exceeds the packets/second. Ports toward the router/other switches are <code>trust</code>; user ports stay untrusted (default).')}</div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px"><b>🖧 ${T('Config για Cisco switch', 'Cisco switch config')}</b><button class="b" data-lg="copy">📋 ${T('Αντιγραφή', 'Copy')}</button></div>
      <pre id="lg-cfg">${E((EN() && r.config_en) || r.config || '')}</pre></div>`;
    b.innerHTML = h;
  }
  function load() { return fetch('/api/l2guard').then(x => x.json()).then(j => { R = j; draw(); }).catch(() => { R = { never: true }; draw(); }); }
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-l2g [data-lg]'); if (!b) return;
    if (b.dataset.lg === 'copy') { const t = document.getElementById('lg-cfg').textContent; if (typeof copyText === 'function') copyText(t); else navigator.clipboard && navigator.clipboard.writeText(t); return; }
    busy = true; draw();
    fetch('/api/l2guard/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(x => x.json())
      .then(j => { busy = false; if (j.error) { R = Object.assign({}, R, { checks: [{ level: 'err', el: j.error, en: j.error }] }); } else R = j; draw(); })
      .catch(() => { busy = false; draw(); });
  });
  window.renderL2g = () => load();
})();
