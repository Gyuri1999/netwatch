// ───────────────────────── 📷 Βοηθός παράδοσης καμερών ─────────────────────────
// Backend: camcheck.py (/api/kit/camcheck). Μόνο ανάγνωση: ποτέ login, ποτέ δοκιμή κωδικών, ποτέ λήψη βίντεο.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const box = () => document.getElementById('t-camcheck');
  const COL = { pass: 'var(--green,#3ecf8e)', warn: 'var(--orange)', fail: 'var(--red)', skip: 'var(--dim)' };
  const ICO = { pass: '✓', warn: '!', fail: '✗', skip: '–' };
  let D = null, msg = '', poll = null, open = {};
  const LV = {};                       // 👁 ανά κάμερα: {open, img, err, busy, basic, kb, isOpen, t}
  const CRED = { user: 'admin', pass: '', same: true, per: {} };   // μόνο στη μνήμη της σελίδας — ποτέ σε δίσκο
  let autoT = null;

  const css = document.createElement('style');
  css.textContent = `
#t-camcheck{min-width:0}
#t-camcheck .card{min-width:0;max-width:100%}
#t-camcheck .cc-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-camcheck .cc-big{font-size:34px}
#t-camcheck .cc-chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
#t-camcheck .cc-chip{font-size:12px;padding:3px 9px;border-radius:10px;background:rgb(var(--w,255 255 255) / 6%)}
#t-camcheck .cc-cam{border-left:3px solid var(--c);border-radius:10px;background:rgb(var(--w,255 255 255) / 3%);padding:10px 12px;margin-top:8px}
#t-camcheck .cc-top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;cursor:pointer}
#t-camcheck .cc-pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap}
#t-camcheck .cc-ck{display:grid;grid-template-columns:18px minmax(0,1fr);gap:2px 8px;font-size:13px;margin-top:6px}
#t-camcheck .cc-ck b{color:var(--c)}
#t-camcheck .cc-fix{grid-column:2;font-size:12.5px;color:var(--dim)}
#t-camcheck .cc-alert{border-left:3px solid var(--red);border-radius:8px;background:color-mix(in srgb,var(--red) 8%,transparent);padding:9px 12px;margin-top:8px;font-size:13px}
#t-camcheck .cc-form{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
#t-camcheck input[type=text]{padding:7px 10px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 15%);background:transparent;color:inherit;font:inherit;min-width:130px}
#t-camcheck .cc-live{margin-top:10px;padding-top:10px;border-top:1px dashed rgb(var(--w,255 255 255) / 12%)}
#t-camcheck .cc-live img{display:block;max-width:100%;max-height:420px;border-radius:8px;background:#000}
#t-camcheck .cc-live input[type=password]{padding:7px 10px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 15%);background:transparent;color:inherit;font:inherit;min-width:130px}
#t-camcheck .mono{font-family:var(--mono,ui-monospace,monospace);font-size:12px}
#t-camcheck ol,#t-camcheck ul{margin:6px 0 0 18px;padding:0;font-size:13px}#t-camcheck li{margin:3px 0}
`;
  document.head.appendChild(css);

  const when = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : T('ποτέ', 'never');
  const post = (sub, body) => fetch('/api/kit/camcheck/' + sub, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then(r => r.json());
  const LBL = { pass: ['εντάξει', 'OK'], warn: ['παρατήρηση', 'remark'], fail: ['πρόβλημα', 'problem'] };

  function cam(c) {
    const r = c.result, lv = r ? r.level : 'skip', col = COL[lv], bad = r && r.level !== 'pass';
    const show = open[c.ip] == null ? bad : open[c.ip];
    return `<div class="cc-cam" style="--c:${col}"><div class="cc-top" data-cc="toggle" data-ip="${E(c.ip)}">
      <div style="flex:1;min-width:180px"><b>📷 ${E(c.name || c.ip)}</b> <span class="mono dim">${E(c.ip)}${c.mac ? ' · ' + E(c.mac) : ''}</span>
        <div class="dim" style="font-size:12px">${E([c.vendor, c.model, c.fw].filter(Boolean).join(' · '))}</div></div>
      <span class="cc-pill" style="--c:${col}">${r ? T(...LBL[lv]) : T('δεν ελέγχθηκε', 'not checked')}</span>
      <button class="b" data-cc="live" data-ip="${E(c.ip)}" title="${T('Δες τι βλέπει η κάμερα (με τον κωδικό της)', 'See what the camera sees (with its password)')}">👁</button>
      <button class="b" data-cc="one" data-ip="${E(c.ip)}"${D.busy || D.demo ? ' disabled' : ''} title="${T('Έλεγξε ξανά μόνο αυτήν', 'Re-check only this one')}">🔄</button>
      ${D.demo ? '' : `<button class="b" data-cc="remove" data-ip="${E(c.ip)}" title="${T('Αφαίρεση από τη λίστα', 'Remove from the list')}">🗑</button>`}</div>
      ${r && show ? `<div class="cc-ck">${r.checks.map(k => `<b style="--c:${COL[k.status]}">${ICO[k.status]}</b><span>${E(EN() ? k.en : k.el)}</span>${(k.status === 'fail' || k.status === 'warn') && k.fix ? `<div class="cc-fix">👉 ${E(EN() ? k.fix_en : k.fix)}</div>` : ''}`).join('')}</div>` : ''}${live(c)}</div>`;
  }

  function live(c) {
    const v = LV[c.ip]; if (!v || !v.open) return '';
    const cr = CRED.same ? CRED : (CRED.per[c.ip] || (CRED.per[c.ip] = { user: CRED.user, pass: '' }));
    return `<div class="cc-live" data-ip="${E(c.ip)}">
      ${D.demo ? '' : `<div class="cc-form" style="margin-top:0"><input type="text" class="cc-u" value="${E(cr.user)}" placeholder="${T('χρήστης', 'user')}" autocomplete="off" spellcheck="false" style="min-width:90px;width:110px">
        <input type="password" class="cc-p" value="${E(cr.pass)}" placeholder="${T('κωδικός της κάμερας', 'camera password')}" autocomplete="new-password">
        <button class="b" data-cc="snap" data-ip="${E(c.ip)}"${v.busy ? ' disabled' : ''}>${v.busy ? '⏳' : '📸'} ${T('Δείξε εικόνα', 'Show image')}</button>
        <label class="dim" style="display:inline-flex;gap:5px;align-items:center"><input type="checkbox" class="cc-same"${CRED.same ? ' checked' : ''}> ${T('ίδια στοιχεία για όλες', 'same login for all')}</label>
        ${v.img ? `<label class="dim" style="display:inline-flex;gap:5px;align-items:center"><input type="checkbox" class="cc-auto"${v.auto ? ' checked' : ''}> ${T('ανανέωση κάθε 5″', 'refresh every 5s')}</label>` : ''}
        ${v.basic ? `<label style="display:inline-flex;gap:5px;align-items:center;color:var(--orange)"><input type="checkbox" class="cc-basic"${v.allowBasic ? ' checked' : ''}> ${T('το επιτρέπω (ο κωδικός θα πάει χωρίς κρυπτογράφηση)', 'allow it (the password will travel unencrypted)')}</label>` : ''}</div>`}
      ${v.err ? `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${E(v.err)}</div>` : ''}
      ${v.img ? `<img alt="" src="${E(v.img)}" style="margin-top:8px"><div class="dim" style="font-size:12px;margin-top:4px">${v.t ? new Date(v.t).toLocaleTimeString(EN() ? 'en-GB' : 'el-GR') : ''}${v.kb ? ' · ' + v.kb + ' kB' : ''}${v.isOpen ? ` · <b style="color:var(--red)">${T('η κάμερα έδωσε εικόνα ΧΩΡΙΣ κωδικό', 'the camera served an image WITHOUT a password')}</b>` : ''}</div>` : ''}
      <div class="dim" style="font-size:12px;margin-top:6px">${T('Στιγμιότυπο, όχι βίντεο. Ο κωδικός δεν αποθηκεύεται πουθενά και γίνεται μία μόνο προσπάθεια σύνδεσης ανά πάτημα — το NetWatch δεν δοκιμάζει ποτέ κωδικούς μόνο του.', 'A snapshot, not video. The password is stored nowhere and only one login attempt is made per press — NetWatch never tries passwords on its own.')}</div></div>`;
  }

  function grab(ip) {                                   // διάβασε ό,τι έγραψε ο χρήστης πριν ξαναζωγραφίσουμε
    const el = box().querySelector(`.cc-live[data-ip="${CSS.escape(ip)}"]`); if (!el) return;
    const u = el.querySelector('.cc-u'), p = el.querySelector('.cc-p'), sm = el.querySelector('.cc-same'), au = el.querySelector('.cc-auto'), ba = el.querySelector('.cc-basic');
    if (sm) CRED.same = sm.checked;
    const cr = CRED.same ? CRED : (CRED.per[ip] || (CRED.per[ip] = { user: 'admin', pass: '' }));
    if (u) cr.user = u.value; if (p) cr.pass = p.value;
    if (au) LV[ip].auto = au.checked; if (ba) LV[ip].allowBasic = ba.checked;
  }
  function snap(ip, quiet) {
    const v = LV[ip]; if (!v || v.busy) return;
    const cr = CRED.same ? CRED : (CRED.per[ip] || CRED);
    v.busy = true; if (!quiet) draw();
    post('snapshot', { ip, user: cr.user, password: cr.pass, allow_basic: !!v.allowBasic }).then(j => {
      v.busy = false;
      if (j.error) { v.err = (EN() && j.error_en) || j.error; v.basic = !!j.need_basic; v.auto = false; }
      else { v.err = ''; v.img = j.img; v.kb = j.kb; v.isOpen = !!j.open; v.t = Date.now(); }
      const typing = document.activeElement && document.activeElement.closest && document.activeElement.closest('#t-camcheck .cc-live');
      if (!(quiet && typing)) { Object.keys(LV).forEach(k => LV[k].open && grab(k)); draw(); }
    }).catch(() => { v.busy = false; v.err = T('Δεν απάντησε το NetWatch.', 'NetWatch did not answer.'); draw(); });
  }
  function tick() {                                     // αυτόματη ανανέωση μόνο όσο φαίνεται η καρτέλα
    const b = box(); if (!b || !b.classList.contains('on') || document.hidden) return;
    Object.keys(LV).forEach(ip => { const v = LV[ip]; if (v.open && v.auto && v.img && !v.err) snap(ip, true); });
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error === 'off' || !D.counts) { b.innerHTML = `<div class="card">${T('Δεν είναι διαθέσιμο σε αυτή τη λειτουργία (π.χ. ανάλυση pcap ή online demo).', 'Not available in this mode (e.g. pcap analysis or the online demo).')}</div>`; return; }
    const c = D.counts, cams = D.cams || [];
    const ico = D.busy ? '⏳' : !c.total ? '📷' : c.fail || (D.conflicts || []).length ? '🚨' : c.warn || (D.stray || []).length ? '⚠️' : c.pending ? '📷' : '✅';
    const head = D.busy ? T('Ελέγχω τις κάμερες…', 'Checking the cameras…')
      : !c.total ? T('Καμία κάμερα στη λίστα ακόμα', 'No cameras in the list yet')
        : c.pending === c.total ? T(`${c.total} κάμερες — δεν έχουν ελεγχθεί`, `${c.total} cameras — not checked yet`)
          : c.fail ? T(`${c.fail} από ${c.total} κάμερες έχουν πρόβλημα`, `${c.fail} of ${c.total} cameras have a problem`)
            : c.warn ? T(c.warn === 1 ? 'Όλες απαντούν · 1 θέλει μια ματιά' : `Όλες απαντούν · ${c.warn} θέλουν μια ματιά`, c.warn === 1 ? 'All answer · 1 needs a look' : `All answer · ${c.warn} need a look`) : T(`Και οι ${c.total} κάμερες πέρασαν`, `All ${c.total} cameras passed`);
    let h = `<div class="card"><div class="cc-hero"><span class="cc-big">${ico}</span><div style="flex:1;min-width:220px">
      <b style="font-size:16px">${head}</b>${D.demo ? ' <span class="dim">DEMO</span>' : ''}
      <div class="dim" style="font-size:12.5px;margin-top:3px">${T('τελευταίος έλεγχος', 'last check')} ${when(D.scanned)}</div></div>
      <button class="b" data-cc="run"${D.busy || D.demo ? ' disabled' : ''}>🔎 ${T('Βρες και έλεγξε κάμερες', 'Find and check cameras')}</button>
      <a class="b" target="_blank" rel="noopener" href="/api/kit/camcheck/report?lang=${EN() ? 'en' : 'el'}">🖨 ${T('Φύλλο παράδοσης', 'Commissioning sheet')}</a>
      <a class="b" href="/api/kit/camcheck/csv">⬇ CSV</a></div>
      <div class="cc-chips"><span class="cc-chip">${c.total} ${T('κάμερες', 'cameras')}</span><span class="cc-chip" style="color:${COL.pass}">✓ ${c.pass}</span><span class="cc-chip" style="color:${COL.warn}">! ${c.warn}</span><span class="cc-chip" style="color:${COL.fail}">✗ ${c.fail}</span></div>
      <div class="dim" style="font-size:12.5px;margin-top:8px;line-height:1.55">${T('Πριν φύγεις από τον πελάτη: απαντά κάθε κάμερα χωρίς απώλειες; έχουν δύο την ίδια IP; είναι σωστή η ώρα; ζητά κωδικό η ροή; Όλα <b>μόνο με ανάγνωση</b> — δεν δοκιμάζω ποτέ κωδικούς και δεν κατεβάζω βίντεο.',
        'Before you leave the site: does every camera answer without loss? do two share an IP? is the clock right? does the stream ask for a password? All <b>read-only</b> — I never try passwords and never pull video.')}</div>
      ${D.error ? `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${E(D.error)}</div>` : ''}
      ${msg ? `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${E(msg)}</div>` : ''}
      ${D.demo ? '' : `<div class="cc-form"><input type="text" id="cc-ip" placeholder="192.168.1.64" autocomplete="off"><input type="text" id="cc-name" maxlength="60" placeholder="${T('Όνομα (π.χ. Είσοδος)', 'Name (e.g. Entrance)')}"><button class="b" data-cc="add">＋ ${T('Πρόσθεσε κάμερα', 'Add camera')}</button></div>`}</div>`;
    const conf = D.conflicts || [], stray = D.stray || [];
    if (conf.length || stray.length) {
      h += `<div class="card"><b>🚨 ${T('Θέλουν διόρθωση πριν από οτιδήποτε άλλο', 'Fix these before anything else')}</b>
        ${conf.map(x => `<div class="cc-alert"><b>${T('Σύγκρουση IP', 'IP conflict')}: ${E(x.ip)}</b> — ${T('την έχουν', 'held by')} <span class="mono">${E((x.macs || []).join(', '))}</span>
          <div class="dim" style="font-size:12.5px;margin-top:3px">${T('Σύνδεσε τις κάμερες μία-μία και δώσε σε καθεμία δική της IP πριν βάλεις την επόμενη.', 'Connect the cameras one at a time and give each its own IP before plugging in the next.')}</div></div>`).join('')}
        ${stray.map(x => `<div class="cc-alert" style="border-color:var(--orange);background:color-mix(in srgb,var(--orange) 8%,transparent)"><b>${T('Κάμερα σε άλλο subnet', 'Camera on another subnet')}: ${E(x.ip)}</b> <span class="mono dim">${E(x.mac || '')}</span> ${E(x.model || '')}
          <div class="dim" style="font-size:12.5px;margin-top:3px">${x.factory ? T(`Εργοστασιακή IP ${E(x.factory)}. `, `Factory IP of ${E(x.factory)}. `) : ''}${x.activated === false ? T('Δεν έχει ενεργοποιηθεί (χωρίς κωδικό). ', 'Not activated (no password). ') : ''}${T('Το καταγραφικό δεν τη φτάνει. Δώσε της IP του δικτύου από το εργαλείο του κατασκευαστή (SADP / ConfigTool) ή βάλε προσωρινά δεύτερη IP στον υπολογιστή σου.', 'The recorder cannot reach it. Give it an address on this network with the vendor tool (SADP / ConfigTool), or temporarily add a second IP to your computer.')}</div></div>`).join('')}</div>`;
    }
    if (cams.length) h += `<div class="card"><b>${T('Κάμερες', 'Cameras')}</b>${cams.map(cam).join('')}</div>`;
    h += `<div class="card"><b>👉 ${T('Σειρά που γλιτώνει τη δεύτερη επίσκεψη', 'An order that saves the second visit')}</b><ol>
      <li>${T('Σύνδεσε τις καινούργιες κάμερες <b>μία-μία</b>: όλες της ίδιας μάρκας βγαίνουν με την ίδια εργοστασιακή IP.', 'Plug in new cameras <b>one at a time</b>: all of the same brand come up on the same factory IP.')}</li>
      <li>${T('Ενεργοποίησε, δώσε στατική IP και σωστή πύλη, όρισε NTP (το router ή το καταγραφικό).', 'Activate, give a static IP and the right gateway, set NTP (the router or the recorder).')}</li>
      <li>${T('Πάτα «Βρες και έλεγξε κάμερες». Κόκκινο σε απώλειες = καλώδιο ή PoE· μέτρησε τη θύρα με τον 🔌 Tester πρίζας και το ρεύμα με τους 🧮 Υπολογιστές (PoE budget).', 'Press “Find and check cameras”. Red on loss = cable or PoE; measure the port with the 🔌 Socket tester and the power with the 🧮 Calculators (PoE budget).')}</li>
      <li>${T('Πρώτα να γράφει τοπικά το καταγραφικό, μετά η απομακρυσμένη θέαση — και με VPN, όχι ανοιχτές θύρες (δες 🔓 Θύρες router).', 'First make the recorder record locally, then set up remote viewing — over a VPN, not open ports (see 🔓 Router ports).')}</li>
      <li>${T('Τύπωσε το «Φύλλο παράδοσης» και βάλε τον πελάτη να υπογράψει.', 'Print the “Commissioning sheet” and have the customer sign it.')}</li></ol>
      <div class="dim" style="font-size:12px;margin-top:6px">${T('Η αναζήτηση χρησιμοποιεί ONVIF WS-Discovery και Hikvision SADP. Κάμερες άλλων μαρκών με κλειστό ONVIF πρόσθεσέ τες με την IP τους. Ο έλεγχος διπλής IP θέλει Live (δικαιώματα διαχειριστή).', 'Discovery uses ONVIF WS-Discovery and Hikvision SADP. Add other brands with ONVIF disabled by IP. The duplicate-IP check needs Live (admin rights).')}</div></div>`;
    b.innerHTML = h;
  }

  function load() {
    return fetch('/api/kit/camcheck').then(r => r.json()).then(j => {
      if (D && D.cams && box()) Object.keys(LV).forEach(k => LV[k].open && grab(k));
      D = j; draw();
      if (D.busy && !poll) poll = setInterval(load, 1500);
      if (!D.busy && poll) { clearInterval(poll); poll = null; }
    }).catch(() => { D = { error: 'off' }; draw(); });
  }
  document.addEventListener('click', e => {
    const t = e.target.closest('#t-camcheck [data-cc]'); if (!t) return;
    const a = t.dataset.cc, ip = t.dataset.ip;
    if (a === 'toggle') { if (e.target.closest('button')) return; Object.keys(LV).forEach(k => LV[k].open && grab(k)); const c = (D.cams || []).find(x => x.ip === ip); open[ip] = !(open[ip] == null ? !!(c && c.result && c.result.level !== 'pass') : open[ip]); return draw(); }
    if (a === 'live') { Object.keys(LV).forEach(k => LV[k].open && grab(k)); const v = LV[ip] || (LV[ip] = {}); v.open = !v.open; if (!v.open) v.auto = false; draw(); if (v.open && D.demo) snap(ip); return; }
    if (a === 'snap') { grab(ip); return snap(ip); }
    msg = '';
    const done = j => { if (j.error) { msg = (EN() && j.error_en) || j.error; draw(); } else { D = j; draw(); if (D.busy && !poll) poll = setInterval(load, 1500); } };
    if (a === 'run') return post('run', {}).then(done);
    if (a === 'one') return post('run', { ips: [ip] }).then(done);
    if (a === 'remove') return post('remove', { ip }).then(done);
    if (a === 'add') return post('add', { ip: box().querySelector('#cc-ip').value, name: box().querySelector('#cc-name').value }).then(done);
  });
  document.addEventListener('change', e => {
    const el = e.target.closest('#t-camcheck .cc-live'); if (!el) return;
    if (e.target.matches('.cc-same,.cc-auto,.cc-basic')) { grab(el.dataset.ip); draw(); }
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter') return;
    const el = e.target.closest && e.target.closest('#t-camcheck .cc-live'); if (!el) return;
    grab(el.dataset.ip); snap(el.dataset.ip);
  });
  window.renderCamcheck = () => { if (!autoT) autoT = setInterval(tick, 5000); return load(); };
})();
