// ───────────────────────── 🌐 Έλεγχος IPv6: ξεχασμένο IPv6, ψεύτικα Router Advertisements, DHCPv6 ─────────────────────────
// Παθητικά: RA / DHCPv6 που είδε το NetWatch. Ενεργά (ένα κουμπί): Router Solicitation, διευθύνσεις, Internet με IPv6.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const L = o => (o ? (EN() ? o.en : o.el) : '');
  const box = () => document.getElementById('t-v6');
  const COL = { ok: 'var(--green,#3fb950)', warn: 'var(--orange)', bad: 'var(--red)', info: 'var(--cyan)', high: 'var(--red)', med: 'var(--orange)', low: 'var(--dim)' };
  const IC = { ok: '✅', warn: '⚠️', bad: '🚨', info: 'ℹ️' };
  let D = null, poll = null;

  const css = document.createElement('style');
  css.textContent = `
#t-v6 .v6-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-v6 .v6-big{font-size:36px}
#t-v6 .v6-chk{display:grid;grid-template-columns:26px minmax(0,1fr);gap:8px;padding:8px 10px;border-radius:10px;margin-top:6px;background:rgb(var(--w,255 255 255) / 4%);font-size:13.5px;line-height:1.5;border-left:3px solid var(--c)}
#t-v6 .v6-row{border-left:3px solid var(--c);border-radius:10px;background:rgb(var(--w,255 255 255) / 3%);padding:10px 12px;margin-top:8px;font-size:13px;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:6px 12px;align-items:start}
#t-v6 .v6-mono,#t-v6 code{font-family:var(--mono,ui-monospace,Menlo,Consolas,monospace);font-size:12px;word-break:break-all}
#t-v6 code{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px}
#t-v6 .v6-pill{display:inline-block;font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap;margin:1px 3px 1px 0}
#t-v6 .v6-wrap{overflow:auto}
#t-v6 table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:6px}
#t-v6 th{text-align:left;color:var(--dim);font-size:11px;font-weight:600;padding:6px;border-bottom:1px solid var(--line,rgb(255 255 255 / 12%))}
#t-v6 td{padding:6px;border-bottom:1px solid rgb(var(--w,255 255 255) / 6%);vertical-align:top}
#t-v6 pre{background:#05080f;color:#d6e2f0;border-radius:10px;padding:10px 12px;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;overflow:auto;margin:8px 0 0}
#t-v6 ol{margin:6px 0 0 18px;padding:0;font-size:13px;line-height:1.55}#t-v6 li{margin:4px 0}
#t-v6 .v6-go{border-color:var(--cyan)!important;color:var(--cyan)!important;font-weight:600;padding:8px 16px!important}
@media (max-width:600px){#t-v6 .v6-row{grid-template-columns:1fr}}
`;
  document.head.appendChild(css);

  const when = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : T('ποτέ', 'never');
  const pill = (txt, c) => `<span class="v6-pill" style="--c:${c || 'var(--dim)'}">${txt}</span>`;
  const SCOPE = { 'link-local': ['τοπική (link-local)', 'link-local'], ula: ['ιδιωτική (ULA)', 'private (ULA)'], global: ['δημόσια (global)', 'public (global)'] };
  const KIND = { eui64: ['EUI-64 · φαίνεται η MAC', 'EUI-64 · MAC visible', 'var(--orange)'], temp: ['προσωρινή (privacy)', 'temporary (privacy)', 'var(--green,#3fb950)'], stable: ['σταθερή, τυχαία', 'stable, random', 'var(--cyan)'] };
  const PREF = { high: ['προτίμηση High', 'preference High', 'var(--red)'], medium: ['προτίμηση Medium', 'preference Medium', 'var(--dim)'], low: ['προτίμηση Low', 'preference Low', 'var(--dim)'] };

  function router(r) {
    const c = r.trusted ? COL.ok : r.stub ? 'var(--dim)' : COL.bad;
    const pf = PREF[r.pref] || PREF.medium;
    const tags = [pill(r.trusted ? (r.by === 'user' ? T('έμπιστο (το όρισες εσύ)', 'trusted (set by you)') : r.by === 'gw' ? T('έμπιστο (ίδια MAC με το router IPv4)', 'trusted (same MAC as the IPv4 router)') : T('έμπιστο (το έμαθα αυτόματα)', 'trusted (learned automatically)')) : r.stub ? T('βοηθητικό (Thread/HomeKit) — όχι gateway', 'helper (Thread/HomeKit) — not a gateway') : T('ΑΓΝΩΣΤΟ router', 'UNKNOWN router'), c),
      pill(T(...pf), pf[2]), pill(r.lifetime ? T(`default gateway για ${r.lifetime} δευτ.`, `default gateway for ${r.lifetime} s`) : T('όχι default gateway (lifetime 0)', 'not a default gateway (lifetime 0)')),
      r.M ? pill('M: DHCPv6 ' + T('για διευθύνσεις', 'for addresses'), 'var(--cyan)') : '', r.O ? pill('O: DHCPv6 ' + T('για DNS κ.λπ.', 'for DNS etc.'), 'var(--cyan)') : '',
      r.mtu ? pill('MTU ' + E(r.mtu)) : '', r.vlan != null ? pill('VLAN ' + E(r.vlan)) : ''].join('');
    const px = (r.prefixes || []).map(p => `<code>${E(p.prefix)}</code> ${p.A ? T('(SLAAC: οι συσκευές φτιάχνουν μόνες τους διεύθυνση)', '(SLAAC: devices build their own address)') : T('(χωρίς SLAAC)', '(no SLAAC)')}`).join(' · ');
    const btn = D.demo ? '' : r.trusted ? `<button class="b" data-v6="untrust" data-mac="${E(r.mac)}">${T('Δεν το εμπιστεύομαι', 'Untrust')}</button>` : `<button class="b" data-v6="trust" data-mac="${E(r.mac)}">✔ ${T('Έμπιστο', 'Trusted')}</button>`;
    return `<div class="v6-row" style="--c:${c}"><div>
      <b>${r.trusted ? '🌐' : r.stub ? '🧩' : '🚨'} ${E(r.name || T('Router IPv6', 'IPv6 router'))}</b> <span class="v6-mono dim">${E(r.mac)} · ${E(r.src)}</span>
      <div style="margin-top:4px">${tags}</div>
      ${px ? `<div style="margin-top:4px">${T('Μοιράζει', 'Hands out')}: ${px}</div>` : ''}
      ${(r.rdnss || []).length ? `<div style="margin-top:3px">DNS (RDNSS): ${r.rdnss.map(x => `<code>${E(x)}</code>`).join(' ')}${(r.dnssl || []).length ? ' · ' + T('επίθημα', 'suffix') + ' ' + E(r.dnssl.join(', ')) : ''}</div>` : ''}
      ${(r.routes || []).length ? `<div style="margin-top:3px">${T('Διαδρομές', 'Routes')}: ${r.routes.map(x => `<code>${E(x.prefix)}</code>`).join(' ')}</div>` : ''}
      <div class="dim" style="font-size:12px;margin-top:3px">${T('πρώτη φορά', 'first seen')} ${when(r.first)} · ${T('τελευταία', 'last')} ${when(r.last)} · ${E(r.n)} RA${r.truncated ? ' · ' + T('είδα μόνο την αρχή του πακέτου', 'only saw the start of the packet') : ''}</div></div>
      <div>${btn}</div></div>`;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error === 'off' || D.error) { b.innerHTML = `<div class="card">${T('Ο έλεγχος IPv6 δεν είναι διαθέσιμος σε αυτή τη λειτουργία (π.χ. online demo ή ανάλυση pcap).', 'The IPv6 check is not available in this mode (e.g. online demo or pcap analysis).')}</div>`; return; }
    const v = D.verdict || {}, c = COL[v.level] || 'var(--dim)';
    const st = { unknown: ['Έχει το δίκτυο IPv6;', 'Does this network have IPv6?'], off: ['IPv6: κλειστό', 'IPv6: off'], managed: ['IPv6: ανοιχτό και ελεγμένο', 'IPv6: on and managed'], unmanaged: ['IPv6: ανοιχτό, χωρίς έλεγχο', 'IPv6: on, unmanaged'] }[D.status] || ['IPv6', 'IPv6'];
    let h = `<div class="card"><div class="v6-hero"><span class="v6-big">${D.status === 'unknown' ? '🌐' : IC[v.level] || '🌐'}</span><div style="flex:1;min-width:230px">
      <b style="font-size:16px">${T(...st)}</b><div style="font-size:13.5px;margin-top:3px;color:${c}">${E(L(v))}</div>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${T('ενεργός έλεγχος', 'active check')}: ${D.demo ? 'demo' : when(D.checked)}${D.iface ? ' · ' + E(D.iface) : ''}${D.learning ? ' · ' + T('μαθαίνω ποιο είναι το router (10 λεπτά)', 'learning which router is yours (10 min)') : ''}</div></div>
      <button class="b v6-go" data-v6="check"${D.busy ? ' disabled' : ''}>${D.busy ? '⏳ ' + T('Ελέγχω…', 'Checking…') : '🔍 ' + T('Έλεγχος', 'Check')}</button></div>
      ${D.demo ? `<div class="dim" style="font-size:12.5px;margin-top:8px">🧪 ${T('Demo: router παρόχου με ανοιχτό IPv6, 5 συσκευές με δημόσια διεύθυνση και ένα ψεύτικο Router Advertisement.', 'Demo: ISP router with IPv6 on, 5 devices with a public address and one rogue Router Advertisement.')}</div>` : ''}
      ${D.ra && D.ra.status !== 'ok' ? `<div style="font-size:13px;margin-top:8px;color:${D.ra.status === 'err' ? 'var(--orange)' : 'var(--dim)'}">${D.ra.status === 'err' ? '⚠ ' : ''}${E(L(D.ra))}</div>` : ''}
      ${(D.checklist || []).map(x => `<div class="v6-chk" style="--c:${COL[x.level] || 'var(--dim)'}"><span>${IC[x.level] || '•'}</span><span>${E(L(x))}</span></div>`).join('')}
      <div class="dim" style="font-size:12.5px;margin-top:10px;line-height:1.55">${T('Στο IPv4 το router «κρύβει» τις συσκευές πίσω από μία διεύθυνση (NAT). Στο <b>IPv6 κάθε συσκευή παίρνει δική της δημόσια διεύθυνση</b> — αν το IPv6 firewall του router είναι κλειστό, η κάμερα ή το NAS φαίνονται απευθείας από το Internet. Και όποιος στείλει ένα <b>Router Advertisement</b> γίνεται «router» για όλους. Εδώ στέλνω μόνο ένα Router Solicitation («ποιο router υπάρχει;») — δεν αλλάζω τίποτα.',
        'In IPv4 the router hides devices behind one address (NAT). In <b>IPv6 every device gets its own public address</b> — if the router’s IPv6 firewall is off, the camera or NAS is directly reachable from the Internet. And whoever sends a <b>Router Advertisement</b> becomes “the router” for everyone. Here I only send one Router Solicitation (“which router is there?”) — I change nothing.')}</div></div>`;

    if ((D.events || []).length) h += `<div class="card"><b>🚨 ${T('Τι είδα στο δίκτυο', 'What I saw on the network')}</b>${D.events.map(e => `<div class="v6-chk" style="--c:${COL[e.sev] || 'var(--dim)'}"><span>${e.sev === 'high' ? '🚨' : e.sev === 'med' ? '⚠️' : 'ℹ️'}</span><span>${E(L(e))}<div class="dim" style="font-size:12px">${when(e.t)} · <span class="v6-mono">${E(e.mac)}</span></div></span></div>`).join('')}
      <div class="v6-chk" style="--c:var(--cyan)"><span>🧭</span><span>${T('<b>Τι κάνω τώρα;</b> 1) Βρες τη συσκευή με αυτή τη MAC (📟 Συσκευές ή «🔌 Πού είναι συνδεδεμένο;»). 2) Συχνή αθώα αιτία: δεύτερο router/mesh σε λειτουργία router, ή υπολογιστής με «κοινή χρήση σύνδεσης». 3) Αν δεν είναι δικό σου: αποσύνδεσέ το. Αν είναι υπολογιστής της εταιρείας, έλεγξέ τον για κακόβουλο λογισμικό (mitm6).', '<b>What now?</b> 1) Find the device with this MAC (📟 Devices or “🔌 Where is it connected?”). 2) A common innocent cause: a second router/mesh in router mode, or a computer with “Internet sharing” on. 3) If it is not yours: unplug it. If it is a company PC, check it for malware (mitm6).')}</span></div></div>`;

    if ((D.routers || []).length || (D.dhcp6 || []).length) {
      h += `<div class="card"><b>📡 ${T('Router που μοιράζουν IPv6', 'Routers handing out IPv6')}</b>${(D.routers || []).map(router).join('')}`;
      if ((D.dhcp6 || []).length) h += `<div style="margin-top:12px"><b>DHCPv6 servers</b>${D.dhcp6.map(d => `<div class="v6-row" style="--c:${d.trusted ? COL.ok : COL.bad}"><div>${d.trusted ? '✅' : '🚨'} <span class="v6-mono">${E(d.mac)} · ${E(d.src)}</span> <span class="dim">${E(d.type || '')} ×${E(d.n)} · ${when(d.last)}</span></div><div>${D.demo || d.trusted ? '' : `<button class="b" data-v6="trust" data-mac="${E(d.mac)}">✔ ${T('Έμπιστο', 'Trusted')}</button>`}</div></div>`).join('')}</div>`;
      h += `</div>`;
    }

    if ((D.addrs || []).length || D.inet) {
      h += `<div class="card"><b>💻 ${T('Αυτός ο υπολογιστής', 'This computer')}</b>`;
      if ((D.addrs || []).length) h += `<div class="v6-wrap"><table><tr><th>${T('Διεύθυνση', 'Address')}</th><th>${T('Εμβέλεια', 'Scope')}</th><th>${T('Είδος', 'Kind')}</th></tr>${D.addrs.map(a => { const k = KIND[a.kind] || KIND.stable; return `<tr><td class="v6-mono">${E(a.addr)}${a.iface ? ` <span class="dim">${E(a.iface)}</span>` : ''}</td><td>${T(...(SCOPE[a.scope] || [a.scope, a.scope]))}</td><td>${pill(T(k[0], k[1]), k[2])}${a.deprecated ? pill(T('λήγει', 'deprecated')) : ''}</td></tr>`; }).join('')}</table></div>`;
      if (D.inet) h += `<div style="font-size:13px;margin-top:8px">${D.inet.ok ? '✅ ' + T('Βγαίνει στο Internet με IPv6', 'Reaches the Internet over IPv6') : '➖ ' + T('Δεν βγαίνει στο Internet με IPv6', 'Does not reach the Internet over IPv6')}: ${(D.inet.tcp || []).map(x => `<span class="v6-mono">${E(x.name)} ${x.ms == null ? '✖' : E(x.ms) + ' ms'}</span>`).join(' · ')} · DNS AAAA ${D.inet.aaaa ? '✔' : '✖'}</div>`;
      h += `</div>`;
    }

    const devs = D.devices || [];
    if (devs.length) h += `<div class="card"><b>📋 ${T('Συσκευές με δημόσια διεύθυνση IPv6', 'Devices with a public IPv6 address')} (${devs.length})</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${T('Αυτές οι διευθύνσεις είναι ορατές από όλο το Internet — μόνο το IPv6 firewall του router τις προστατεύει.', 'These addresses are visible to the whole Internet — only the router’s IPv6 firewall protects them.')}</div>
      <div class="v6-wrap"><table><tr><th>${T('Συσκευή', 'Device')}</th><th>${T('Διεύθυνση IPv6', 'IPv6 address')}</th><th>MAC</th><th></th></tr>
      ${devs.map(d => `<tr><td>${E(d.dicon || '')} ${E(d.name || '—')}${d.me ? ` <span class="dim">(${T('αυτός ο υπολογιστής', 'this computer')})</span>` : ''}${d.ip4 ? `<div class="dim v6-mono">${E(d.ip4)}</div>` : ''}</td><td class="v6-mono">${E(d.ip)}</td><td class="v6-mono">${E(d.mac || '—')}</td><td>${d.eui64 ? pill(T('EUI-64 · ανιχνεύσιμη', 'EUI-64 · trackable'), 'var(--orange)') : pill(T('τυχαία', 'randomised'), 'var(--green,#3fb950)')}</td></tr>`).join('')}</table></div></div>`;

    if (D.status !== 'off' && D.status !== 'unknown') {
      const ex = (D.ext_test && D.ext_test.addr) || '2a02:xxxx:…';
      h += `<div class="card"><b>👉 ${T('Τι να κάνεις', 'What to do')}</b><ol>
        <li>${T('<b>Η δοκιμή που δεν μπορώ να κάνω από μέσα:</b> από κινητό με <b>δεδομένα κινητής</b> (όχι Wi‑Fi) άνοιξε', '<b>The test I cannot run from inside:</b> from a phone on <b>mobile data</b> (not Wi‑Fi) open')} <code>http://[${E(ex)}]/</code> ${T('ή τρέξε από εξωτερικό υπολογιστή', 'or run from an outside computer')} <code>nc -6 -vz ${E(ex)} 80</code> ${T('(δοκίμασε και 443, 22, 554). <b>Αν συνδεθεί, το router ΔΕΝ κόβει τα εισερχόμενα IPv6.</b> Αν ο πάροχος κινητής δεν δίνει IPv6, χρησιμοποίησε ένα online «IPv6 port scanner».', '(also try 443, 22, 554). <b>If it connects, the router does NOT block inbound IPv6.</b> If the mobile carrier has no IPv6, use an online “IPv6 port scanner”.')}</li>
        <li>${T('Στο router ψάξε <b>IPv6 → Firewall / «Block incoming connections» / «IPv6 SPI»</b> και άφησέ το ανοιχτό. Fritz!Box: <i>Internet → Permit Access → IPv6</i>. MikroTik: <code>/ipv6 firewall filter</code> (drop στο forward από WAN, εκτός established/related). OpenWrt/pfSense: προεπιλογή «reject/deny» στο WAN.', 'On the router look for <b>IPv6 → Firewall / “Block incoming connections” / “IPv6 SPI”</b> and keep it on. Fritz!Box: <i>Internet → Permit Access → IPv6</i>. MikroTik: <code>/ipv6 firewall filter</code> (drop forward from WAN except established/related). OpenWrt/pfSense: default “reject/deny” on WAN.')}</li>
        <li>${T('Δεν χρειάζεσαι IPv6; Κλείσ’ το στο router (LAN → IPv6 → Disabled). Το χρειάζεσαι; Κράτα το, αλλά με firewall — και πάτα «Το έλεγξα» παρακάτω για να το θυμάμαι.', 'Don’t need IPv6? Turn it off on the router (LAN → IPv6 → Disabled). Need it? Keep it, but firewalled — and press “I tested it” below so I remember.')}</li>
        <li>${T('Συσκευές με <b>EUI-64</b> (κάμερες, NAS, IoT) έχουν σταθερή διεύθυνση που δεν αλλάζει ποτέ — είναι οι πρώτες που πρέπει να μπουν πίσω από firewall ή σε ξεχωριστό VLAN.', 'Devices with <b>EUI-64</b> (cameras, NAS, IoT) keep one address forever — put those behind the firewall or on a separate VLAN first.')}</li></ol>
        ${D.demo ? '' : `<div style="margin-top:8px"><button class="b" data-v6="confirm" data-on="${D.fw_ok ? '0' : '1'}">${D.fw_ok ? '↩ ' + T('Αναίρεση: δεν το έχω ελέγξει', 'Undo: not tested') : '✔ ' + T('Το έλεγξα από έξω: το router κόβει τα εισερχόμενα IPv6', 'I tested from outside: the router blocks inbound IPv6')}</button></div>`}</div>`;
    }

    h += `<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap"><b>🖧 ${T('Managed switch: RA Guard & DHCPv6 Guard', 'Managed switch: RA Guard & DHCPv6 Guard')}</b><button class="b" data-v6="copy">📋 ${T('Αντιγραφή', 'Copy')}</button></div>
      <div class="dim" style="font-size:12.5px;margin-top:4px;line-height:1.55">${T('Το αντίστοιχο του DHCP snooping για το IPv6: το switch δέχεται Router Advertisements και απαντήσεις DHCPv6 <b>μόνο από τη θύρα του πραγματικού router</b>. Σε switches χωρίς RA Guard (ή σε Wi‑Fi) βοηθά το «client isolation» και το κλείσιμο του IPv6 όπου δεν χρειάζεται.', 'The IPv6 counterpart of DHCP snooping: the switch accepts Router Advertisements and DHCPv6 replies <b>only on the real router’s port</b>. On switches without RA Guard (or on Wi‑Fi), client isolation and disabling IPv6 where it is not needed help.')}</div>
      <pre id="v6-cfg">${E((EN() && D.config_en) || D.config || '')}</pre></div>`;
    b.innerHTML = h;
  }

  function sync() {
    if (D && D.busy && !poll) poll = setInterval(load, 1500);
    if (D && !D.busy && poll) { clearInterval(poll); poll = null; }
  }
  function load() {
    return fetch('/api/kit/v6').then(r => r.json()).then(j => { D = j; draw(); sync(); }).catch(() => { D = { error: 'off' }; draw(); });
  }
  function post(sub, body) {
    return fetch('/api/kit/v6/' + sub, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })
      .then(r => r.json()).then(j => { if (j && !j.error) { D = j; draw(); sync(); } else load(); }).catch(() => load());
  }
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-v6 [data-v6]'); if (!b) return;
    const a = b.dataset.v6;
    if (a === 'copy') { const t = document.getElementById('v6-cfg').textContent; if (typeof copyText === 'function') copyText(t); else if (navigator.clipboard) navigator.clipboard.writeText(t); return; }
    b.disabled = true;
    if (a === 'check') { if (D) { D.busy = true; draw(); } post('check'); }
    else if (a === 'trust' || a === 'untrust') post(a, { mac: b.dataset.mac });
    else if (a === 'confirm') post('confirm', { fw: b.dataset.on === '1' });
  });
  window.renderV6 = () => load();
})();
