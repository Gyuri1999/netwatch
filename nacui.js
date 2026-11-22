// ───────────────────────── 🔐 802.1X & απομόνωση guest — έλεγχοι από τη μεριά του πελάτη ─────────────────────────
// 802.1X στη θύρα (EAPOL-Start), ασφάλεια του τρέχοντος Wi‑Fi, τεστ απομόνωσης δικτύου επισκεπτών με ιστορικό πριν/μετά.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const L = o => (o ? (EN() ? o.en : o.el) : '');
  const box = () => document.getElementById('t-nac');
  const COL = { pass: 'var(--green,#3fb950)', ok: 'var(--green,#3fb950)', fail: 'var(--red)', bad: 'var(--red)', warn: 'var(--orange)', untested: 'var(--dim)', info: 'var(--cyan)' };
  const IC = { pass: '✅', fail: '🚨', warn: '⚠️', untested: '❔', info: 'ℹ️' };
  const ST = { pass: ['περνά', 'pass'], fail: ['ΑΠΟΤΥΧΙΑ', 'FAIL'], warn: ['προσοχή', 'check'], untested: ['δεν ελέγχθηκε', 'not tested'], info: ['πληροφορία', 'info'] };
  const RULE = {
    clients: ['Οι επισκέπτες δεν βλέπουν ο ένας τον άλλον', 'Guests cannot see each other',
      'Ένας επισκέπτης με μολυσμένο laptop μπορεί να σαρώσει και να επιτεθεί στις συσκευές των άλλων επισκεπτών.', 'A guest with an infected laptop can scan and attack other guests’ devices.',
      'Άνοιξε «Client isolation / AP isolation / Guest policy» στο SSID των επισκεπτών (UniFi: Guest policy ή Client Device Isolation · Omada: Guest Network · MikroTik: client-isolation · Aruba: Deny inter-user bridging). Σε ενσύρματες θύρες: «switchport protected» / private VLAN.',
      'Enable “Client isolation / AP isolation / Guest policy” on the guest SSID (UniFi: Guest policy or Client Device Isolation · Omada: Guest Network · MikroTik: client-isolation · Aruba: Deny inter-user bridging). On wired ports: “switchport protected” / private VLAN.'],
    gw_mgmt: ['Οι επισκέπτες δεν φτάνουν τη διαχείριση του router', 'Guests cannot reach router management',
      'Ένας επισκέπτης μπορεί να δοκιμάσει κωδικούς στη σελίδα διαχείρισης / SSH / Winbox του router.', 'A guest can try passwords on the router’s admin page / SSH / Winbox.',
      'Κόψε στο firewall του router την είσοδο (input) από το δίκτυο επισκεπτών εκτός από DNS και DHCP — δες τα έτοιμα παραδείγματα παρακάτω. Κλείσε Telnet/HTTP διαχείρισης παντού.',
      'Block router input from the guest network except DNS and DHCP — see the ready-made examples below. Disable Telnet/HTTP management everywhere.'],
    internal: ['Οι επισκέπτες δεν φτάνουν τα εσωτερικά δίκτυα', 'Guests cannot reach internal networks',
      'Από το Wi‑Fi των επισκεπτών φτάνει κανείς υπολογιστές, ταμειακές, κάμερες ή NAS της επιχείρησης.', 'From guest Wi‑Fi someone can reach the business’s PCs, tills, cameras or NAS.',
      'Βάλε κανόνα «guest → RFC1918 = drop» στο router/firewall (παραδείγματα παρακάτω). Αν το guest είναι απλώς δεύτερο SSID στο ΙΔΙΟ δίκτυο, φτιάξε ξεχωριστό VLAN/subnet. Αν απαντά το modem του παρόχου (π.χ. 192.168.1.1) πίσω από το δικό σου router, κόψε και αυτό.',
      'Add a “guest → RFC1918 = drop” rule on the router/firewall (examples below). If guest is merely a second SSID on the SAME network, create a separate VLAN/subnet. If the ISP modem (e.g. 192.168.1.1) behind your own router answers, block that too.'],
    dns: ['Το DNS δουλεύει', 'DNS works', 'Οι επισκέπτες δεν θα ανοίγουν καμία σελίδα.', 'Guests will not be able to open any page.',
      'Επίτρεψε UDP/TCP 53 προς τον DNS που δίνει το DHCP (συχνό λάθος: ο κανόνας «κόψε τα πάντα προς το router» κόβει και το DNS).', 'Allow UDP/TCP 53 to the DNS server handed out by DHCP (common mistake: the “block everything to the router” rule also blocks DNS).'],
    internet: ['Το Internet δουλεύει', 'Internet works', 'Οι επισκέπτες δεν έχουν Internet.', 'Guests have no Internet.',
      'Έλεγξε NAT/masquerade για το subnet των επισκεπτών και ότι ο τελευταίος κανόνας της ACL είναι permit προς το Internet.', 'Check NAT/masquerade for the guest subnet and that the last ACL rule permits traffic to the Internet.'],
    captive: ['Captive portal', 'Captive portal', '', '', '', ''],
  };
  let D = null, poll = null, sel = 0, edit = null, msg = '';

  const css = document.createElement('style');
  css.textContent = `
#t-nac .na-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-nac .na-big{font-size:34px}
#t-nac .na-rule{display:grid;grid-template-columns:26px minmax(0,1fr) auto;gap:4px 10px;padding:10px 12px;border-radius:10px;margin-top:8px;background:rgb(var(--w,255 255 255) / 3%);border-left:3px solid var(--c);font-size:13.5px;line-height:1.5}
#t-nac .na-pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap;align-self:start}
#t-nac .na-fix{grid-column:2 / -1;font-size:12.5px;border-top:1px dashed rgb(var(--w,255 255 255) / 12%);padding-top:6px;margin-top:4px}
#t-nac .na-hist{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:7px 10px;border-radius:8px;margin-top:5px;cursor:pointer;border:1px solid transparent;background:rgb(var(--w,255 255 255) / 3%);font-size:12.5px}
#t-nac .na-hist.on{border-color:var(--cyan)}
#t-nac .na-dots span{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--c);margin-right:3px}
#t-nac code,#t-nac .na-mono{font-family:var(--mono,ui-monospace,Menlo,Consolas,monospace);font-size:12px}
#t-nac code{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px}
#t-nac pre{background:#05080f;color:#d6e2f0;border-radius:10px;padding:10px 12px;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;overflow:auto;margin:8px 0 0}
#t-nac textarea,#t-nac input[type=text],#t-nac input[type=number]{width:100%;box-sizing:border-box;background:rgb(var(--w,255 255 255) / 6%);color:inherit;border:1px solid rgb(var(--w,255 255 255) / 14%);border-radius:8px;padding:7px 9px;font:12.5px var(--mono,ui-monospace,monospace)}
#t-nac label{display:block;font-size:12px;color:var(--dim);margin:8px 0 3px}
#t-nac .na-go{border-color:var(--cyan)!important;color:var(--cyan)!important;font-weight:600;padding:8px 14px!important}
#t-nac .na-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
#t-nac ul{margin:6px 0 0 18px;padding:0;font-size:13px;line-height:1.55}
@media (max-width:600px){#t-nac .na-rule{grid-template-columns:26px minmax(0,1fr)}#t-nac .na-pill{grid-column:2;justify-self:start}}
`;
  document.head.appendChild(css);

  const when = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : T('ποτέ', 'never');
  const pill = (s, c) => `<span class="na-pill" style="--c:${c || 'var(--dim)'}">${s}</span>`;

  function ruleRow(r) {
    const c = COL[r.status] || 'var(--dim)', m = RULE[r.id] || [r.id, r.id, '', '', '', ''];
    const bad = r.status === 'fail' || r.status === 'warn';
    return `<div class="na-rule" style="--c:${c}"><span>${IC[r.status] || '•'}</span><div><b>${E(T(m[0], m[1]))}</b><div>${E(L(r))}</div></div>${pill(T(...(ST[r.status] || ST.info)), c)}
      ${bad && m[2] ? `<div class="na-fix"><b>${T('Τι σημαίνει', 'What it means')}:</b> ${E(T(m[2], m[3]))}<br><b>${T('Πώς διορθώνεται', 'How to fix')}:</b> ${E(T(m[4], m[5]))}</div>` : ''}</div>`;
  }

  function dot1xCard() {
    const r = D.dot1x, busy = D.busy === 'dot1x';
    const c = !r ? 'var(--dim)' : r.status === 'required' ? (r.have_ip ? COL.warn : COL.ok) : r.status === 'err' ? COL.warn : r.status === 'bypass' ? COL.warn : COL.info;
    const head = !r ? T('Ζητά η θύρα αυτή 802.1X;', 'Does this port require 802.1X?') : r.status === 'required' ? T('Η θύρα ζητά 802.1X', 'The port requires 802.1X') : r.status === 'bypass' ? T('802.1X υπάρχει, αλλά σε αφήνει να μπεις', '802.1X is present but lets you in') : r.status === 'err' ? T('Ο έλεγχος δεν έγινε', 'The check did not run') : T('Η θύρα ΔΕΝ ζητά 802.1X', 'The port does NOT require 802.1X');
    return `<div class="card"><div class="na-hero"><span class="na-big">🔌</span><div style="flex:1;min-width:220px"><b style="font-size:15px;color:${c}">${head}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${r ? T('έλεγχος', 'checked') + ' ' + (D.demo ? 'demo' : when(r.t)) + (r.iface ? ' · ' + E(r.iface) : '') : T('Σύνδεσε το καλώδιο στην πρίζα που θες να ελέγξεις και πάτα «Έλεγχος» (~5 δευτ.).', 'Plug the cable into the socket you want to test and press “Check” (~5 s).')}</div></div>
      <div style="display:flex;gap:6px;flex-wrap:wrap"><button class="b na-go" data-na="dot1x"${D.busy || D.demo ? ' disabled' : ''}>${busy ? '⏳ ' + T('Ακούω…', 'Listening…') : '🔍 ' + T('Έλεγχος', 'Check')}</button>
      <button class="b" data-na="dot1xm"${D.busy || D.demo ? ' disabled' : ''} title="${T('Στέλνει και ανώνυμη ταυτότητα για να δει ποια μέθοδο EAP προσφέρει ο server', 'Also sends an anonymous identity to see which EAP method the server offers')}">${T('+ μέθοδος EAP', '+ EAP method')}</button></div></div>
      ${r ? `<div style="font-size:13.5px;margin-top:8px;line-height:1.55">${E(L(r))}</div>` : ''}
      ${r && (r.frames || []).length ? `<div class="dim na-mono" style="margin-top:6px">${r.frames.map(f => `${E(f.src)} → ${E(f.ptype_name)} v${E(f.version)} · ${E(f.eap)}`).join('<br>')}</div>` : ''}
      <div class="dim" style="font-size:12.5px;margin-top:10px;line-height:1.55">${T('Στέλνω ένα πλαίσιο <b>EAPOL-Start</b> («θέλω να ταυτοποιηθώ») και βλέπω αν το switch απαντά <b>EAP-Request/Identity</b>. <b>MAB</b> = το switch, αν η συσκευή δεν μιλά 802.1X (εκτυπωτής, κάμερα), τη δέχεται από τη MAC της — βολικό, αλλά η MAC αντιγράφεται εύκολα. <b>Guest VLAN</b> = όποιος δεν ταυτοποιηθεί πέφτει σε απομονωμένο δίκτυο αντί να κοπεί. Το «+ μέθοδος EAP» στέλνει ταυτότητα «anonymous» (ποτέ κωδικό) και αφήνει μία αποτυχημένη προσπάθεια στο log του RADIUS.',
        'I send one <b>EAPOL-Start</b> frame (“I want to authenticate”) and see whether the switch answers <b>EAP-Request/Identity</b>. <b>MAB</b> = if a device cannot speak 802.1X (printer, camera) the switch admits it by its MAC — convenient, but a MAC is easy to copy. <b>Guest VLAN</b> = whoever fails to authenticate lands in an isolated network instead of being cut off. “+ EAP method” sends the identity “anonymous” (never a password) and leaves one failed attempt in the RADIUS log.')}
        <br>⚠ ${T('Σε θύρα όπου μπήκες με MAB, το EAPOL-Start μπορεί να κόψει τη σύνδεση αυτού του υπολογιστή για λίγα δευτερόλεπτα (το switch ξαναδοκιμάζει πρώτα 802.1X). Το τεστ αφορά ενσύρματη θύρα — στο Wi‑Fi δες την κάρτα δίπλα.', 'On a port you entered via MAB, the EAPOL-Start may drop this computer’s connection for a few seconds (the switch retries 802.1X first). The test is for a wired port — for Wi‑Fi see the next card.')}</div></div>`;
  }

  function wifiCard() {
    const w = D.wifi, busy = D.busy === 'wifi';
    const c = w ? (COL[w.level] || 'var(--dim)') : 'var(--dim)';
    const kind = { enterprise: 'Enterprise (802.1X)', psk: T('Κοινός κωδικός (PSK)', 'Shared password (PSK)'), open: T('Ανοιχτό', 'Open'), owe: 'OWE (Enhanced Open)', wep: 'WEP', unknown: T('Άγνωστη ασφάλεια', 'Unknown security'), none: T('Όχι σε Wi‑Fi', 'Not on Wi‑Fi') };
    return `<div class="card"><div class="na-hero"><span class="na-big">📶</span><div style="flex:1;min-width:200px"><b style="font-size:15px;color:${c}">${w ? E(kind[w.kind] || w.kind) + (w.ssid ? ' · «' + E(w.ssid) + '»' : '') : T('Ασφάλεια του Wi‑Fi που είσαι τώρα', 'Security of your current Wi‑Fi')}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${w ? (D.demo ? 'demo' : when(w.t)) + (w.channel ? ' · ' + T('κανάλι', 'channel') + ' ' + E(w.channel) : '') + (w.signal != null ? ' · ' + E(w.signal) + ' dBm' : '') : T('Διαβάζω ό,τι δίνει το λειτουργικό — δεν στέλνω τίποτα.', 'I read what the OS exposes — nothing is sent.')}</div></div>
      <button class="b" data-na="wifi"${D.busy || D.demo ? ' disabled' : ''}>${busy ? '⏳' : '🔄'} ${T('Ανάγνωση', 'Read')}</button></div>
      ${w ? `<div style="font-size:13.5px;margin-top:8px;line-height:1.55">${E(L(w))}</div><div style="margin-top:6px">${w.kind !== 'none' ? pill(w.wpa3 ? (w.transition ? T('WPA3 μεταβατικό (δέχεται και WPA2)', 'WPA3 transition (also accepts WPA2)') : 'WPA3') : T('όχι WPA3', 'no WPA3'), w.wpa3 ? COL.ok : 'var(--dim)') + ' ' + pill('PMF: ' + ({ required: T('υποχρεωτικό', 'required'), optional: T('προαιρετικό', 'optional'), unknown: T('δεν το δείχνει το λειτουργικό', 'not exposed by the OS') }[w.pmf] || w.pmf), w.pmf === 'required' ? COL.ok : 'var(--dim)') : ''}</div>` : ''}
      <div class="dim" style="font-size:12.5px;margin-top:10px;line-height:1.55">${T('<b>PMF (802.11w)</b> προστατεύει από «deauth» επιθέσεις που πετάνε τις συσκευές εκτός δικτύου· στο WPA3 είναι υποχρεωτικό. Για προσωπικό/εταιρικό δίκτυο προτίμησε Enterprise ή WPA3· για επισκέπτες αρκεί PSK <b>με απομόνωση</b> (το τεστ παρακάτω).', '<b>PMF (802.11w)</b> protects against “deauth” attacks that kick devices off the network; WPA3 makes it mandatory. For staff networks prefer Enterprise or WPA3; for guests a PSK is fine <b>with isolation</b> (the test below).')}</div></div>`;
  }

  function isoCard() {
    const hist = D.history || [], r = hist[Math.min(sel, Math.max(hist.length - 1, 0))], busy = D.busy === 'isolation';
    const vc = r ? ({ ok: COL.ok, warn: COL.warn, fail: COL.fail }[r.verdict]) : 'var(--dim)';
    const head = !r ? T('Είναι απομονωμένο το δίκτυο επισκεπτών;', 'Is the guest network isolated?') : r.verdict === 'ok' ? T('Η απομόνωση δουλεύει', 'Isolation works') : r.verdict === 'fail' ? T('Η απομόνωση ΔΕΝ δουλεύει', 'Isolation is NOT working') : T('Χρειάζεται προσοχή', 'Needs attention');
    const n = r && r.net || {};
    let h = `<div class="card"><div class="na-hero"><span class="na-big">${!r ? '🧱' : r.verdict === 'ok' ? '✅' : r.verdict === 'fail' ? '🚨' : '⚠️'}</span><div style="flex:1;min-width:220px"><b style="font-size:16px;color:${vc}">${head}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${r ? when(r.t) + ' · ' + T('εγώ', 'me') + ' <span class="na-mono">' + E(n.ip) + '</span> · ' + T('δίκτυο', 'network') + ' <span class="na-mono">' + E(n.cidr) + '</span>' + (n.gw ? ' · router <span class="na-mono">' + E(n.gw) + '</span>' : '') + (n.ssid ? ' · «' + E(n.ssid) + '»' : '') + ' · ' + E(r.probes) + ' ' + T('δοκιμές', 'probes') + (r.trigger === 'auto' ? ' · ' + T('αυτόματο', 'scheduled') : '') : T('Σύνδεσε ΑΥΤΟΝ τον υπολογιστή στο Wi‑Fi των επισκεπτών και πάτα «Τεστ» (~15 δευτ.).', 'Connect THIS computer to the guest Wi‑Fi and press “Test” (~15 s).')}</div></div>
      <button class="b na-go" data-na="isolation"${D.busy || D.demo ? ' disabled' : ''}>${busy ? '⏳ ' + T('Δοκιμάζω…', 'Testing…') : '▶ ' + T('Τεστ απομόνωσης', 'Isolation test')}</button></div>
      ${D.demo ? `<div class="dim" style="font-size:12.5px;margin-top:8px">🧪 ${T('Demo: χθες το δίκτυο «Cafe-Guest» περνούσε· σήμερα, μετά από αναβάθμιση του router, όχι. Πάτα μια γραμμή του ιστορικού για να τα συγκρίνεις.', 'Demo: yesterday “Cafe-Guest” passed; today, after a router upgrade, it does not. Click a history row to compare.')}</div>` : ''}
      ${D.regressed && sel === 0 ? `<div style="color:var(--red);font-size:13px;margin-top:8px">🚨 ${T('Το ίδιο δίκτυο περνούσε στο προηγούμενο τεστ — κάτι άλλαξε (αναβάθμιση, επαναφορά ρυθμίσεων, νέο AP).', 'This same network passed the previous test — something changed (upgrade, config reset, new AP).')}</div>` : ''}
      ${D.problem ? `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${E(L(D.problem))}</div>` : ''}
      ${r ? r.rules.map(ruleRow).join('') : ''}
      <div class="dim" style="font-size:12.5px;margin-top:10px;line-height:1.55">${T(`Δοκιμάζω <b>μόνο ιδιωτικές διευθύνσεις</b>, με timeout 1 δευτ. και το πολύ ${E((D.limits || {}).probes || 200)} δοκιμές: ping και λίγες θύρες σε άλλους πελάτες του ίδιου δικτύου, τις θύρες διαχείρισης του router (${E((D.gw_ports || []).join(', '))}), συνηθισμένα gateways άλλων ιδιωτικών δικτύων και τους δικούς σου «εσωτερικούς στόχους». Δεν στέλνω δεδομένα, μόνο ανοίγω και κλείνω τη σύνδεση. Για πλήρη πίνακα VLAN → VLAN δες το 🧱 «Έλεγχος διαχωρισμού».`,
        `I probe <b>private addresses only</b>, with a 1 s timeout and at most ${E((D.limits || {}).probes || 200)} probes: ping and a few ports on other clients of the same network, the router’s management ports (${E((D.gw_ports || []).join(', '))}), common gateways of other private networks and your own “internal targets”. No data is sent — connections are just opened and closed. For a full VLAN → VLAN matrix see 🧱 “Segmentation check”.`)}</div></div>`;
    if (hist.length) h += `<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><b>🕘 ${T('Ιστορικό (πριν / μετά)', 'History (before / after)')}</b>${D.demo ? '' : `<button class="b" data-na="clear">${T('Καθάρισμα', 'Clear')}</button>`}</div>
      ${hist.map((x, i) => `<div class="na-hist${i === sel ? ' on' : ''}" data-na="sel" data-i="${i}"><span>${x.verdict === 'ok' ? '✅' : x.verdict === 'fail' ? '🚨' : '⚠️'}</span><b>${when(x.t)}</b><span class="na-mono dim">${E((x.net || {}).cidr)}${(x.net || {}).ssid ? ' «' + E(x.net.ssid) + '»' : ''}</span><span class="na-dots" title="${T('πελάτες · router · εσωτερικά · DNS · Internet', 'clients · router · internal · DNS · Internet')}">${x.rules.slice(0, 5).map(q => `<span style="--c:${COL[q.status] || 'var(--dim)'}"></span>`).join('')}</span></div>`).join('')}
      <div class="dim" style="font-size:12px;margin-top:6px">${T(`Κρατάω τα τελευταία ${E((D.limits || {}).history || 20)} τεστ. Τρέξε ένα ΠΡΙΝ και ένα ΜΕΤΑ τη ρύθμιση για να το δείξεις στον πελάτη.`, `I keep the last ${E((D.limits || {}).history || 20)} tests. Run one BEFORE and one AFTER your change to show the customer.`)}</div></div>`;
    return h;
  }

  function cfgCard() {
    const c = D.config || {}, e = edit || { targets: (c.targets || []).join('\n'), peers: (c.peers || []).join('\n'), every_min: c.every_min || 0 };
    return `<div class="card"><b>🎯 ${T('Τι να δοκιμάσω επιπλέον', 'What else to probe')}</b>
      <div class="na-grid"><div><label>${T('Εσωτερικοί στόχοι που ΔΕΝ πρέπει να φτάνει ένας επισκέπτης (IP ή IP:θύρα, ένας ανά γραμμή)', 'Internal targets a guest must NOT reach (IP or IP:port, one per line)')}</label><textarea rows="4" data-f="targets" placeholder="192.168.1.10:445&#10;10.0.0.5:3389"${D.demo ? ' disabled' : ''}>${E(e.targets)}</textarea></div>
      <div><label>${T('Άλλος πελάτης στο ίδιο δίκτυο επισκεπτών (IP δεύτερου κινητού/laptop)', 'Another client on the same guest network (IP of a second phone/laptop)')}</label><textarea rows="2" data-f="peers" placeholder="192.168.50.40"${D.demo ? ' disabled' : ''}>${E(e.peers)}</textarea>
      <label>${T('Αυτόματο τεστ κάθε Ν λεπτά (0 = ποτέ· ελάχιστο 15)', 'Automatic test every N minutes (0 = never; minimum 15)')}</label><input type="number" min="0" max="1440" data-f="every_min" value="${E(e.every_min)}"${D.demo ? ' disabled' : ''}></div></div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:8px">${D.demo ? '' : `<button class="b" data-na="save">💾 ${T('Αποθήκευση', 'Save')}</button>`}<span style="font-size:12.5px;color:var(--orange)">${E(msg)}</span></div>
      <div class="dim" style="font-size:12.5px;margin-top:6px;line-height:1.55">${T('Δέχομαι μόνο ιδιωτικές διευθύνσεις (10.x, 172.16–31.x, 192.168.x). Το αυτόματο τεστ έχει νόημα όταν το NetWatch μένει μόνιμα συνδεδεμένο στο δίκτυο επισκεπτών (π.χ. ένα Raspberry Pi): θα ειδοποιήσει αν η απομόνωση που περνούσε χαλάσει.', 'Only private addresses are accepted (10.x, 172.16–31.x, 192.168.x). The automatic test makes sense when NetWatch stays connected to the guest network (e.g. a Raspberry Pi): it alerts if isolation that used to pass breaks.')}</div></div>`;
  }

  function fixCard() {
    const f = D.fix || {};
    return `<div class="card"><b>👉 ${T('Τι να κάνεις', 'What to do')}</b>
      <ul><li>${T('<b>Στο AP / controller:</b> ξεχωριστό SSID για επισκέπτες σε <b>δικό του VLAN</b>, με «client isolation / guest policy» ανοιχτό.', '<b>On the AP / controller:</b> a separate guest SSID on <b>its own VLAN</b>, with “client isolation / guest policy” enabled.')}</li>
      <li>${T('<b>Στο router / firewall:</b> επισκέπτες → μόνο Internet. Όχι προς το ίδιο το router (εκτός DNS/DHCP), όχι προς άλλα ιδιωτικά δίκτυα.', '<b>On the router / firewall:</b> guests → Internet only. Not to the router itself (except DNS/DHCP), not to other private networks.')}</li>
      <li>${T('Ξανατρέξε το τεστ μετά από κάθε αλλαγή ή αναβάθμιση firmware — οι ρυθμίσεις αυτές χάνονται εύκολα.', 'Re-run the test after every change or firmware upgrade — these settings are easily lost.')}</li></ul>
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-top:10px"><b>Cisco IOS — ACL ${E(f.cidr || '')}</b><button class="b" data-na="copy" data-id="na-cisco">📋 ${T('Αντιγραφή', 'Copy')}</button></div>
      <pre id="na-cisco">${E((EN() && f.cisco_en) || f.cisco || '')}</pre>
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-top:10px"><b>MikroTik RouterOS — firewall filter</b><button class="b" data-na="copy" data-id="na-mt">📋 ${T('Αντιγραφή', 'Copy')}</button></div>
      <pre id="na-mt">${E((EN() && f.mikrotik_en) || f.mikrotik || '')}</pre>
      <div class="dim" style="font-size:12px;margin-top:6px">${T('Παραδείγματα — προσαρμόσε ονόματα διεπαφών/VLAN και δοκίμασε σε ώρα χωρίς πελάτες.', 'Examples — adapt interface/VLAN names and test outside business hours.')}</div></div>`;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error || !D.history) { b.innerHTML = `<div class="card">${T('Οι έλεγχοι 802.1X / guest δεν είναι διαθέσιμοι σε αυτή τη λειτουργία (π.χ. online demo ή ανάλυση pcap).', 'The 802.1X / guest checks are not available in this mode (e.g. online demo or pcap analysis).')}</div>`; return; }
    const act = document.activeElement, keep = act && b.contains(act) && act.dataset && act.dataset.f ? { f: act.dataset.f, s: act.selectionStart } : null;
    b.innerHTML = isoCard() + cfgCard() + `<div class="na-grid">${dot1xCard()}${wifiCard()}</div>` + fixCard();
    if (keep) { const el = b.querySelector(`[data-f="${keep.f}"]`); if (el) { el.focus(); try { el.setSelectionRange(keep.s, keep.s); } catch (_) { /* number input */ } } }
  }

  function sync() {
    if (D && D.busy && !poll) poll = setInterval(load, 1500);
    if (D && !D.busy && poll) { clearInterval(poll); poll = null; }
  }
  function load() {
    return fetch('/api/kit/nac').then(r => r.json()).then(j => { D = j; draw(); sync(); }).catch(() => { D = { error: 'off' }; draw(); });
  }
  function post(sub, body) {
    return fetch('/api/kit/nac/' + sub, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })
      .then(r => r.json()).then(j => { if (j && j.history) { D = j; msg = ''; if (sub === 'config') edit = null; } else if (j && j.error) msg = String(j.error); draw(); sync(); }).catch(() => load());
  }
  document.addEventListener('input', e => {
    const f = e.target.closest && e.target.closest('#t-nac [data-f]'); if (!f || !D) return;
    const c = D.config || {};
    edit = edit || { targets: (c.targets || []).join('\n'), peers: (c.peers || []).join('\n'), every_min: c.every_min || 0 };
    edit[f.dataset.f] = f.value;
  });
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-nac [data-na]'); if (!b || !D) return;
    const a = b.dataset.na;
    if (a === 'sel') { sel = +b.dataset.i || 0; draw(); return; }
    if (a === 'copy') { const t = document.getElementById(b.dataset.id).textContent; if (typeof copyText === 'function') copyText(t); else if (navigator.clipboard) navigator.clipboard.writeText(t); return; }
    if (a === 'save') { const c = D.config || {}, x = edit || { targets: (c.targets || []).join('\n'), peers: (c.peers || []).join('\n'), every_min: c.every_min || 0 }; post('config', { targets: x.targets, peers: x.peers, every_min: +x.every_min || 0 }); return; }
    if (a === 'clear') { sel = 0; post('clear'); return; }
    if (a === 'isolation') { sel = 0; D.busy = 'isolation'; draw(); post('isolation'); return; }
    if (a === 'dot1x' || a === 'dot1xm') { D.busy = 'dot1x'; draw(); post('dot1x', { method: a === 'dot1xm' }); return; }
    if (a === 'wifi') { D.busy = 'wifi'; draw(); post('wifi'); }
  });
  window.renderNac = () => load();
})();
