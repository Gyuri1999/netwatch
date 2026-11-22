// ───────────────────────── ✅ Τεστ αποδοχής εγκατάστασης — λίστα ελέγχων ανά σημείο + αναφορά για υπογραφή ─────────────────────────
// Αυτόματοι έλεγχοι (ping/TCP/DNS/DHCP/gateway/ταχύτητα) μόνο προς ιδιωτικές IP· οι υπόλοιποι τσεκάρονται από τον τεχνικό.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const LANG = () => (EN() ? 'en' : 'el');
  const box = () => document.getElementById('t-accept');
  const API = '/api/kit/accept';
  const COL = { pass: '#3ddc97', fail: 'var(--red)', pending: 'var(--orange)', na: 'var(--dim)' };
  const LBL = () => ({ pass: T('πέρασε', 'pass'), fail: T('απέτυχε', 'fail'), pending: T('εκκρεμεί', 'pending'), na: T('δεν αφορά', 'n/a') });
  let D = null, J = null, msg = '', poll = null;
  const openP = new Set();

  const css = document.createElement('style');
  css.textContent = `
#t-accept .ac-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
#t-accept .ac-job{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;align-items:center;border-left:3px solid var(--c);border-radius:10px;background:rgb(var(--w,255 255 255) / 3%);padding:9px 12px;margin-top:8px;font-size:13px}
#t-accept .ac-pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap}
#t-accept .ac-kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(86px,1fr));gap:8px;margin-top:10px}
#t-accept .ac-kpi div{border:1px solid rgb(var(--w,255 255 255) / 10%);border-radius:10px;padding:6px 8px;text-align:center}#t-accept .ac-kpi b{display:block;font-size:19px}#t-accept .ac-kpi span{font-size:11px;color:var(--dim)}
#t-accept .ac-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin-top:8px;align-items:end}
#t-accept label{display:flex;flex-direction:column;gap:3px;font-size:11.5px;color:var(--dim)}#t-accept label.w{grid-column:1/-1}
#t-accept input[type=text],#t-accept input:not([type]),#t-accept select,#t-accept textarea{padding:7px 9px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 15%);background:transparent;color:inherit;font:inherit;font-size:13px;min-width:0;width:100%;box-sizing:border-box}
#t-accept select option{color:#111}#t-accept textarea{min-height:60px;resize:vertical}
#t-accept a.b{display:inline-block;text-decoration:none;color:inherit;border:1px solid rgb(var(--w,255 255 255) / 12%);border-radius:8px;padding:5px 11px;font-size:12px}
#t-accept .ac-go{border-color:var(--cyan)!important;color:var(--cyan)!important;font-weight:600}
#t-accept details.ac-p{border-left:3px solid var(--c);border-radius:10px;background:rgb(var(--w,255 255 255) / 3%);padding:8px 11px;margin-top:8px}
#t-accept summary{cursor:pointer;font-size:13.5px}
#t-accept .ac-c{display:grid;grid-template-columns:minmax(0,1.6fr) auto minmax(70px,.6fr) minmax(90px,1fr);gap:6px 8px;align-items:center;padding:7px 0;border-top:1px solid rgb(var(--w,255 255 255) / 7%);font-size:13px}
#t-accept .ac-c input{padding:5px 7px;font-size:12.5px}
#t-accept .ac-st{display:flex;gap:3px}#t-accept .ac-st button{min-width:34px;padding:5px 6px}
#t-accept .ac-st button.on{border-color:var(--c)!important;color:var(--c)!important;background:color-mix(in srgb,var(--c) 16%,transparent)!important;font-weight:700}
#t-accept .ac-dev{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:4px 10px;max-height:240px;overflow:auto;margin-top:8px;font-size:12.5px}
#t-accept .ac-dev label{flex-direction:row;align-items:center;gap:6px;color:inherit}
#t-accept .ac-msg{color:var(--orange);font-size:13px;margin-top:8px}#t-accept .mono{font-family:var(--mono,ui-monospace,monospace);font-size:12px}
#t-accept ol{margin:6px 0 0 18px;padding:0;font-size:13px}#t-accept li{margin:3px 0}
@media (max-width:640px){#t-accept .ac-c{grid-template-columns:1fr 1fr}#t-accept .ac-c>div:first-child{grid-column:1/-1}#t-accept .ac-job{grid-template-columns:1fr}}
`;
  document.head.appendChild(css);

  const when = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : '—';
  const typ = id => (D.types || []).find(t => t.id === id) || { icon: '❔', el: id, en: id };
  const typeSel = (name, pick) => `<select data-f="${name}">${(D.types || []).map(t => `<option value="${E(t.id)}"${t.id === pick ? ' selected' : ''}>${E(t.icon)} ${E(T(t.el, t.en))}</option>`).join('')}</select>`;
  const vals = root => { const o = {}; root.querySelectorAll('[data-f]').forEach(i => { o[i.dataset.f] = i.value; }); return o; };
  const pill = v => `<span class="ac-pill" style="--c:${COL[v]}">${LBL()[v]}</span>`;
  const verdictTxt = j => j.verdict === 'pass' ? T('✔ Όλα πέρασαν — έτοιμη για υπογραφή', '✔ Everything passed — ready to sign')
    : j.verdict === 'fail' ? T(`✘ ${j.pts.fail} σημεία με αποτυχία — διόρθωσε και ξανατρέξε`, `✘ ${j.pts.fail} point(s) failed — fix and re-run`)
      : T(`… ${j.checks.pending} έλεγχοι εκκρεμούν`, `… ${j.checks.pending} checks pending`);

  function check(p, c, ro) {
    const st = ['pass', 'fail', 'na', 'pending'], ic = { pass: '✔', fail: '✘', na: '—', pending: '↺' }, L = LBL();
    return `<div class="ac-c" data-p="${E(p.id)}" data-c="${E(c.id)}">
      <div>${c.kind === 'auto' ? '⚙' : '✍'} ${E(T(c.el, c.en))}${c.kind === 'auto' && !ro ? ` <button class="b" data-ac="run1" title="${T('Τρέξε αυτόν τον έλεγχο', 'Run this check')}">▶</button>` : ''}</div>
      <div class="ac-st">${st.map(s => `<button class="b${c.status === s ? ' on' : ''}" style="--c:${COL[s]}" data-ac="st" data-s="${s}" title="${L[s]}"${ro ? ' disabled' : ''}>${ic[s]}</button>`).join('')}</div>
      <input type="text" data-k="value" maxlength="80" value="${E(c.value)}" placeholder="${E(c.unit || T('τιμή', 'value'))}"${ro ? ' disabled' : ''}>
      <input type="text" data-k="note" maxlength="300" value="${E(c.note)}" placeholder="${T('σημείωση', 'note')}"${ro ? ' disabled' : ''}></div>`;
  }

  function jobCard() {
    if (!J) return '';
    const ro = !!J.closed, busy = J.busy;
    let h = `<div class="card" id="ac-job"><div class="ac-row" style="margin-top:0"><b style="font-size:15px;flex:1">📋 ${E(J.title)}</b>${J.site_name ? `<span class="dim">🏢 ${E(J.site_name)}</span>` : ''}
      ${ro ? `<span class="ac-pill" style="--c:var(--dim)">🔒 ${T('κλειστή', 'closed')} ${when(J.closed)}</span>` : ''}</div>
      <div style="margin-top:8px;font-weight:600;color:${COL[J.verdict]}">${E(verdictTxt(J))}</div>
      <div class="ac-kpi"><div><b>${J.total_points}</b><span>${T('σημεία', 'points')}</span></div><div><b style="color:${COL.pass}">${J.pts.pass}</b><span>${T('πέρασαν', 'passed')}</span></div>
      <div><b style="color:${COL.fail}">${J.pts.fail}</b><span>${T('απέτυχαν', 'failed')}</span></div><div><b style="color:${COL.pending}">${J.pts.pending}</b><span>${T('εκκρεμούν', 'pending')}</span></div>
      <div><b>${J.checks.pass}/${J.checks.fail}/${J.checks.pending}</b><span>${T('έλεγχοι ✔/✘/…', 'checks ✔/✘/…')}</span></div></div>
      <div class="ac-row">${ro ? '' : `<button class="b ac-go" data-ac="runall"${busy ? ' disabled' : ''}>${busy ? '⏳ ' + T('Τρέχουν…', 'Running…') : '▶ ' + T('Τρέξε όλους τους αυτόματους', 'Run all automatic checks')}</button>`}
      <a class="b" href="${API}/report?id=${encodeURIComponent(J.id)}&lang=${LANG()}" target="_blank" rel="noopener">🖨 ${T('Αναφορά αποδοχής / PDF', 'Acceptance report / PDF')}</a>
      <button class="b" data-ac="close">${ro ? '🔓 ' + T('Άνοιγμα ξανά', 'Reopen') : '🔒 ' + T('Κλείσιμο εργασίας', 'Close job')}</button>
      <button class="b" data-ac="jdel" style="color:var(--red)">🗑</button></div>`;
    if (!ro) {
      h += `<details style="margin-top:12px"${J.points.length ? '' : ' open'}><summary><b>➕ ${T('Πρόσθεσε σημεία', 'Add points')}</b></summary>
        <div class="ac-form" data-form="padd"><label>${T('Τύπος', 'Type')}${typeSel('type', 'socket')}</label>
          <label>${T('Όνομα / ετικέτα', 'Name / label')}<input type="text" data-f="label" maxlength="60" placeholder="A-01"></label>
          <label>IP (${T('για ping/θύρες', 'for ping/ports')})<input type="text" data-f="ip" maxlength="45" placeholder="192.168.1.50"></label>
          <label>${T('Τοποθεσία', 'Location')}<input type="text" data-f="location" maxlength="80"></label>
          <button class="b" data-ac="padd">➕ ${T('Ένα σημείο', 'One point')}</button></div>
        <div class="ac-form" data-form="pbulk"><label>${T('Τύπος', 'Type')}${typeSel('type', 'socket')}</label>
          <label>${T('Μαζικά με αρίθμηση', 'Bulk with numbering')}<input type="text" data-f="pattern" maxlength="200" placeholder="A-01..A-24"></label>
          <label>${T('Τοποθεσία', 'Location')}<input type="text" data-f="location" maxlength="80"></label>
          <button class="b" data-ac="pbulk">➕ ${T('Πολλά σημεία', 'Many points')}</button></div>
        ${(D.devices || []).length ? `<div style="margin-top:10px;font-size:12.5px" class="dim">${T('…ή διάλεξε από τις συσκευές που βλέπει το NetWatch:', '…or pick from the devices NetWatch sees:')}
          <button class="b" data-ac="pickcam">${T('όλες οι κάμερες', 'all cameras')}</button></div>
          <div class="ac-dev">${D.devices.map(d => `<label><input type="checkbox" data-ip="${E(d.ip)}" data-dt="${E(d.dtype)}"> ${E(d.icon || '')} ${E(d.name || d.ip)} <span class="dim mono">${E(d.ip)}</span></label>`).join('')}</div>
          <div class="ac-row"><button class="b" data-ac="pimport">➕ ${T('Πρόσθεσε τις επιλεγμένες', 'Add selected')}</button></div>` : ''}</details>`;
    }
    h += J.points.map(p => {
      const t = typ(p.type), auto = p.checks.some(c => c.kind === 'auto');
      return `<details class="ac-p" style="--c:${COL[p.verdict]}" data-pid="${E(p.id)}"${openP.has(p.id) ? ' open' : ''}><summary>${E(t.icon)} <b>${E(p.label)}</b> <span class="dim">${E(T(t.el, t.en))}${p.ip ? ' · ' + E(p.ip) : ''}${p.location ? ' · ' + E(p.location) : ''}</span> ${pill(p.verdict)}</summary>
        ${p.checks.map(c => check(p, c, ro)).join('')}
        ${ro ? '' : `<div class="ac-row" data-p="${E(p.id)}">${auto ? `<button class="b" data-ac="runp">▶ ${T('Αυτόματοι έλεγχοι σημείου', 'Run this point’s automatic checks')}</button>` : ''}
          <button class="b" data-ac="allpass">✔ ${T('Όλα τα εκκρεμή χειροκίνητα: πέρασαν', 'All pending manual: pass')}</button>
          <input type="text" data-k="extra" maxlength="160" placeholder="${T('δικός σου έλεγχος…', 'your own check…')}" style="flex:1;min-width:140px"><button class="b" data-ac="cadd">➕</button>
          <button class="b" data-ac="pdel" style="color:var(--red)">🗑</button></div>`}</details>`;
    }).join('') || `<div class="empty" style="margin-top:10px">${T('Κανένα σημείο ακόμη — πρόσθεσε πρίζες, κάμερες, access points…', 'No points yet — add sockets, cameras, access points…')}</div>`;
    h += `<div class="ac-form" data-form="jsave" style="margin-top:14px">
      <label>${T('Τίτλος εργασίας', 'Job title')}<input type="text" data-f="title" maxlength="100" value="${E(J.title)}"${ro ? ' disabled' : ''}></label>
      <label>${T('Τόπος', 'Place')}<input type="text" data-f="place" maxlength="100" value="${E(J.place)}"${ro ? ' disabled' : ''}></label>
      <label>${T('Τεχνικός', 'Technician')}<input type="text" data-f="tech" maxlength="80" value="${E(J.tech)}"${ro ? ' disabled' : ''}></label>
      <label>${T('Εκπρόσωπος πελάτη (υπογράφει)', 'Customer representative (signs)')}<input type="text" data-f="rep" maxlength="80" value="${E(J.rep)}"${ro ? ' disabled' : ''}></label>
      <label class="w">${T('Παρατηρήσεις / εκκρεμότητες (τυπώνονται στην αναφορά)', 'Remarks / outstanding items (printed on the report)')}<textarea data-f="remarks" maxlength="3000"${ro ? ' disabled' : ''}>${E(J.remarks)}</textarea></label></div>
      ${ro ? '' : `<div class="ac-row"><button class="b" data-ac="jsave">💾 ${T('Αποθήκευση στοιχείων', 'Save details')}</button></div>`}</div>`;
    return h;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error === 'off') { b.innerHTML = `<div class="card">${T('Τα «Τεστ αποδοχής» δεν είναι διαθέσιμα σε αυτή τη λειτουργία (π.χ. στατικό demo ή ανάλυση pcap).', '“Acceptance tests” is not available in this mode (e.g. static demo or pcap analysis).')}</div>`; return; }
    const sy = window.scrollY;
    let h = `<div class="card"><b style="font-size:16px">✅ ${T('Τεστ αποδοχής εγκατάστασης', 'Installation acceptance tests')}</b>${D.demo ? ' <span class="dim">DEMO</span>' : ''}
      <div class="dim" style="font-size:12.5px;margin-top:4px;line-height:1.5">${T('Μετά την εγκατάσταση: ένα σημείο για κάθε πρίζα, κάμερα, access point, switch. Το NetWatch τρέχει ό,τι μπορεί μόνο του (⚙) και εσύ τσεκάρεις τα υπόλοιπα (✍). Στο τέλος τυπώνεις την αναφορά και υπογράφετε και οι δύο.', 'After the installation: one point per socket, camera, access point, switch. NetWatch runs what it can by itself (⚙) and you tick the rest (✍). At the end you print the report and both sign.')}</div>
      <div class="ac-form" data-form="jnew"><label>${T('Νέα εργασία — τίτλος', 'New job — title')}<input type="text" data-f="title" maxlength="100" placeholder="${T('π.χ. Εγκατάσταση 8 καμερών & 12 πριζών', 'e.g. 8 cameras & 12 sockets installation')}"></label>
        <label>${T('Πελάτης', 'Customer')}<select data-f="site"><option value="">${T('— χωρίς πελάτη —', '— no customer —')}</option>${(D.sites || []).map(s => `<option value="${E(s.id)}"${s.id === D.site ? ' selected' : ''}>${E(s.name)}</option>`).join('')}</select></label>
        <button class="b ac-go" data-ac="jnew">➕ ${T('Νέα εργασία', 'New job')}</button></div>
      ${msg ? `<div class="ac-msg">⚠ ${E(msg)}</div>` : ''}</div>`;
    h += `<div class="card"><b>${T('Εργασίες', 'Jobs')} (${(D.jobs || []).length})</b>` + ((D.jobs || []).map(j => `<div class="ac-job" style="--c:${j.closed ? 'var(--dim)' : COL[j.verdict]}">
      <div><b>${E(j.title)}</b> ${pill(j.verdict)}${j.closed ? ` <span class="ac-pill" style="--c:var(--dim)">🔒</span>` : ''}
        <div class="dim" style="font-size:12px;margin-top:2px">${j.site_name ? '🏢 ' + E(j.site_name) + ' · ' : ''}${when(j.created)} · ${j.total_points} ${T('σημεία', 'points')} · ✔ ${j.checks.pass} · ✘ ${j.checks.fail} · … ${j.checks.pending}</div></div>
      <button class="b" data-ac="jopen" data-id="${E(j.id)}">${J && J.id === j.id ? '▾' : '▸'} ${T('Άνοιγμα', 'Open')}</button></div>`).join('')
      || `<div class="empty">${T('Καμία εργασία ακόμη.', 'No jobs yet.')}</div>`) + '</div>';
    h += jobCard();
    h += `<div class="card"><b>👉 ${T('Πώς δουλεύει', 'How to use it')}</b><ol>
      <li>${T('Φτιάξε <b>νέα εργασία</b> και πρόσθεσε τα σημεία: μαζικά με αρίθμηση (<code>A-01..A-24</code>) ή από τις συσκευές που ήδη βλέπει το NetWatch.', 'Create a <b>new job</b> and add the points: in bulk with numbering (<code>A-01..A-24</code>) or from the devices NetWatch already sees.')}</li>
      <li>${T('<b>Πρίζες:</b> σύνδεσε το laptop στην πρίζα, άνοιξε το σημείο και πάτησε ▶ — ελέγχει ταχύτητα ζεύξης, DHCP, router, Internet. <b>Κάμερες/AP/switch:</b> δώσε την IP και πάτησε ▶ (ping + θύρες).', '<b>Sockets:</b> plug the laptop into the socket, open the point and press ▶ — it checks link speed, DHCP, router, Internet. <b>Cameras/APs/switches:</b> enter the IP and press ▶ (ping + ports).')}</li>
      <li>${T('Τσέκαρε τα χειροκίνητα: ✔ πέρασε, ✘ απέτυχε, — δεν αφορά. Γράψε μετρήσεις (W, dBm, μέτρα) στο πεδίο τιμής.', 'Tick the manual ones: ✔ pass, ✘ fail, — n/a. Type measurements (W, dBm, metres) in the value field.')}</li>
      <li>${T('Όταν όλα είναι πράσινα: <b>Κλείσιμο εργασίας</b> → <b>Αναφορά αποδοχής</b> → Ctrl+P → δύο υπογραφές. Ό,τι έμεινε κόκκινο γράφεται αυτόματα στις «εκκρεμότητες».', 'When everything is green: <b>Close job</b> → <b>Acceptance report</b> → Ctrl+P → two signatures. Anything still red is listed under “outstanding items” automatically.')}</li></ol>
      <div class="dim" style="font-size:12px;margin-top:6px">🔒 ${T('Οι αυτόματοι έλεγχοι πάνε μόνο σε ιδιωτικές IP του τοπικού δικτύου (και στο 1.1.1.1 για το «έχω Internet;»). Τίποτα δεν γράφεται στις συσκευές.', 'Automatic checks only target private IPs on the local network (and 1.1.1.1 for “is there Internet?”). Nothing is written to devices.')}</div></div>`;
    b.innerHTML = h;
    window.scrollTo(0, sy);
  }

  const get = (sub = '') => fetch(API + sub).then(r => r.json());
  const post = (sub, body) => fetch(`${API}/${sub}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then(r => r.json());
  function watch() {
    const busy = J && J.busy;
    if (busy && !poll) poll = setInterval(() => get('/job?id=' + encodeURIComponent(J.id)).then(j => { if (!j.error) { J = j; draw(); watch(); } }).catch(() => {}), 1200);
    if (!busy && poll) { clearInterval(poll); poll = null; }
  }
  function done(j) {
    if (j.error) { msg = EN() ? (j.error_en || j.error) : j.error; draw(); return; }
    msg = ''; const job = j.job; delete j.job; D = j; if (job !== undefined) J = job; draw(); watch();
  }
  const openJob = id => get('/job?id=' + encodeURIComponent(id)).then(j => { J = j.error ? null : j; draw(); watch(); });
  function load() {
    return get().then(j => { if (j.error) { D = { error: 'off' }; draw(); return; } D = j; if (J) return openJob(J.id); draw(); }).catch(() => { D = { error: 'off' }; draw(); });
  }
  const formOf = name => box().querySelector(`[data-form="${name}"]`);

  document.addEventListener('toggle', e => {
    const d = e.target; if (!d.matches || !d.matches('#t-accept details.ac-p')) return;
    if (d.open) openP.add(d.dataset.pid); else openP.delete(d.dataset.pid);
  }, true);
  document.addEventListener('change', e => {
    const i = e.target.closest('#t-accept .ac-c input[data-k]'); if (!i || !J) return;
    const r = i.closest('.ac-c');
    post('check', { job: J.id, point: r.dataset.p, check: r.dataset.c, [i.dataset.k]: i.value }).then(done);
  });
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-accept [data-ac]'); if (!b || !D) return;
    const a = b.dataset.ac, job = J && J.id, row = b.closest('[data-p]'), point = row && row.dataset.p;
    if (a === 'jnew') post('job/new', vals(formOf('jnew'))).then(done);
    else if (a === 'jopen') { if (J && J.id === b.dataset.id) { J = null; draw(); } else { openP.clear(); openJob(b.dataset.id).then(() => { const d = document.getElementById('ac-job'); if (d && d.scrollIntoView) d.scrollIntoView({ block: 'start' }); }); } }
    else if (a === 'jsave') post('job/save', Object.assign({ job }, vals(formOf('jsave')))).then(done);
    else if (a === 'close') post('job/close', { job, closed: !J.closed }).then(done);
    else if (a === 'jdel') { if (confirm(T(`Να διαγραφεί η εργασία «${J.title}»;`, `Delete job “${J.title}”?`))) post('job/delete', { job }).then(j => { J = null; done(j); }); }
    else if (a === 'padd') post('point/add', Object.assign({ job }, vals(formOf('padd')))).then(done);
    else if (a === 'pbulk') post('point/bulk', Object.assign({ job }, vals(formOf('pbulk')))).then(done);
    else if (a === 'pickcam') box().querySelectorAll('.ac-dev input[data-dt="camera"]').forEach(c => { c.checked = true; });
    else if (a === 'pimport') { const ips = [...box().querySelectorAll('.ac-dev input:checked')].map(c => c.dataset.ip); if (ips.length) post('point/import', { job, ips }).then(done); }
    else if (a === 'pdel') { if (confirm(T('Να διαγραφεί το σημείο;', 'Delete this point?'))) post('point/delete', { job, point }).then(done); }
    else if (a === 'runall') post('run', { job }).then(done);
    else if (a === 'runp') post('run', { job, point }).then(done);
    else if (a === 'run1') post('run', { job, point, check: row.dataset.c }).then(done);
    else if (a === 'st') post('check', { job, point, check: row.dataset.c, status: b.dataset.s }).then(done);
    else if (a === 'cadd') { const el = row.querySelector('[data-k="extra"]').value.trim(); if (el) post('check/add', { job, point, el }).then(done); }
    else if (a === 'allpass') {
      const p = J.points.find(x => x.id === point); if (!p) return;
      p.checks.filter(c => c.kind === 'manual' && c.status === 'pending').reduce((q, c) => q.then(() => post('check', { job, point, check: c.id, status: 'pass' })), Promise.resolve({})).then(j => { if (j && j.jobs) done(j); });
    }
  });
  window.renderAccept = () => load();
})();
