// ───────────────────────── 🏢 Πελάτες / εγκαταστάσεις — μητρώο, επισκέψεις, μηνιαία αναφορά συντήρησης ─────────────────────────
// Ένα NetWatch σε πολλούς πελάτες: αναγνωρίζει το δίκτυο από τη MAC του router, κρατά ημερολόγιο επισκέψεων με στιγμιότυπο.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const LANG = () => (EN() ? 'en' : 'el');
  const box = () => document.getElementById('t-sites');
  const API = '/api/kit/sites';
  let D = null, S = null, sel = null, msg = '', adding = false;

  const css = document.createElement('style');
  css.textContent = `
#t-sites .si-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}#t-sites .si-big{font-size:34px}
#t-sites .si-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
#t-sites .si-site{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;align-items:center;border-left:3px solid var(--c,var(--dim));border-radius:10px;background:rgb(var(--w,255 255 255) / 3%);padding:9px 12px;margin-top:8px;font-size:13px}
#t-sites .si-pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap}
#t-sites .si-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-top:10px}
#t-sites label{display:flex;flex-direction:column;gap:3px;font-size:11.5px;color:var(--dim)}
#t-sites label.w{grid-column:1/-1}
#t-sites input,#t-sites select,#t-sites textarea{padding:7px 9px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 15%);background:transparent;color:inherit;font:inherit;font-size:13px;min-width:0;width:100%;box-sizing:border-box}
#t-sites select option{color:#111}#t-sites textarea{min-height:58px;resize:vertical}
#t-sites a.b{display:inline-block;text-decoration:none;color:inherit;border:1px solid rgb(var(--w,255 255 255) / 12%);border-radius:8px;padding:5px 11px;font-size:12px}
#t-sites a.b:hover{border-color:var(--cyan)}#t-sites .si-go{border-color:var(--cyan)!important;color:var(--cyan)!important;font-weight:600}
#t-sites .si-v{border:1px solid rgb(var(--w,255 255 255) / 8%);border-radius:10px;padding:8px 11px;margin-top:8px;font-size:13px;white-space:pre-wrap}
#t-sites .si-msg{color:var(--orange);font-size:13px;margin-top:8px}#t-sites .mono{font-family:var(--mono,ui-monospace,monospace);font-size:12px}
#t-sites ol{margin:6px 0 0 18px;padding:0;font-size:13px}#t-sites li{margin:3px 0}#t-sites summary{cursor:pointer;font-weight:600}
@media (max-width:600px){#t-sites .si-site{grid-template-columns:1fr}}
`;
  document.head.appendChild(css);

  const when = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : '—';
  const hm = m => `${Math.floor((m || 0) / 60)}:${String((m || 0) % 60).padStart(2, '0')}`;
  const F = (name, label, val, o = {}) => `<label${o.wide ? ' class="w"' : ''}>${label}${o.area
    ? `<textarea data-f="${name}" maxlength="${o.max || 1000}" placeholder="${E(o.ph || '')}">${E(val || '')}</textarea>`
    : `<input data-f="${name}" type="${o.type || 'text'}" maxlength="${o.max || 80}" value="${E(val || '')}" placeholder="${E(o.ph || '')}">`}</label>`;
  const vals = root => { const o = {}; root.querySelectorAll('[data-f]').forEach(i => { o[i.dataset.f] = i.value; }); return o; };
  const contract = id => { const c = (D.contracts || []).find(x => x.id === id); return c ? T(c.el, c.en) : id; };

  function siteForm(s, isNew) {
    const fp = s.fp || {};
    return `<div class="si-form" data-form="site">
      ${F('name', T('Όνομα πελάτη *', 'Customer name *'), s.name, { ph: T('π.χ. Καφέ «Θάλασσα»', 'e.g. Sea Café') })}
      ${F('address', T('Διεύθυνση', 'Address'), s.address, { max: 160 })}
      ${F('contact', T('Υπεύθυνος επικοινωνίας', 'Contact person'), s.contact)}
      ${F('phone', T('Τηλέφωνο', 'Phone'), s.phone, { type: 'tel', max: 40 })}
      ${F('email', 'Email', s.email, { type: 'email' })}
      <label>${T('Σύμβαση', 'Contract')}<select data-f="contract">${(D.contracts || []).map(c => `<option value="${E(c.id)}"${c.id === (s.contract || 'none') ? ' selected' : ''}>${E(T(c.el, c.en))}</option>`).join('')}</select></label>
      ${F('gw_ip', T('IP του router (gateway)', 'Router (gateway) IP'), fp.gw_ip, { max: 45, ph: '192.168.1.1' })}
      ${F('gw_mac', T('MAC του router', 'Router MAC'), fp.gw_mac, { max: 17, ph: 'aa:bb:cc:dd:ee:ff' })}
      ${F('subnet', 'Subnet', fp.subnet, { max: 43, ph: '192.168.1.0/24' })}
      ${F('ssid', T('SSID (προαιρετικά)', 'SSID (optional)'), fp.ssid, { max: 32 })}
      ${F('notes', T('Σημειώσεις (πού είναι το rack, ωράριο, ιδιαιτερότητες)', 'Notes (where the rack is, opening hours, quirks)'), s.notes, { area: 1, wide: 1 })}
    </div><div class="si-row"><button class="b si-go" data-si="${isNew ? 'create' : 'update'}">💾 ${isNew ? T('Δημιουργία πελάτη', 'Create customer') : T('Αποθήκευση', 'Save')}</button>
      ${isNew ? `<button class="b" data-si="cancel">${T('Άκυρο', 'Cancel')}</button>` : ''}</div>`;
  }

  function detail() {
    if (!S) return '';
    const open = S.open_visit, cur = D.current === S.id;
    let h = `<div class="card" id="si-detail"><b style="font-size:15px">🏢 ${E(S.name)}</b> <span class="dim mono">${E(S.id)}</span>
      ${cur ? `<span class="si-pill" style="--c:var(--cyan)">📍 ${T('είσαι εδώ', 'you are here')}</span>` : ''}
      <div class="si-row">`;
    h += open ? `<span>⏱ ${T('Επίσκεψη σε εξέλιξη από', 'Visit in progress since')} <b>${when(open)}</b></span>`
      : `<button class="b si-go" data-si="vstart">▶ ${T('Έναρξη επίσκεψης', 'Start visit')}</button>`;
    h += `<a class="b" href="${API}/visits.csv?id=${encodeURIComponent(S.id)}" target="_blank" rel="noopener">⬇ ${T('Επισκέψεις CSV', 'Visits CSV')}</a>
      ${cur ? '' : `<button class="b" data-si="select">📍 ${T('Είμαι σε αυτόν τον πελάτη', 'I am at this customer')}</button>`}
      ${D.network && D.network.gw_ip ? `<button class="b" data-si="bind" title="${T('Γράφει τη MAC/IP του router αυτού του δικτύου στον πελάτη', 'Stores this network’s router MAC/IP on the customer')}">🔗 ${T('Δέσε το τρέχον δίκτυο', 'Bind current network')}</button>` : ''}</div>`;
    const bl = S.baseline;
    h += `<div class="card" style="margin-top:10px;padding:9px 11px;background:rgb(var(--w,255 255 255) / 3%)"><b>🔒 ${T('Εγκεκριμένο δίκτυο', 'Approved network')}</b>`;
    if (!bl) {
      h += ` <span class="dim" style="font-size:12.5px">${T('Κλείδωσε τις τωρινές συσκευές ως «εγκεκριμένες». Μετά το NetWatch σε ειδοποιεί όταν εμφανιστεί κάτι καινούργιο σε αυτόν τον πελάτη.', 'Lock the current devices as “approved”. Then NetWatch alerts you when something new appears at this customer.')}</span>
        <div class="si-row"><button class="b" data-si="baseline"${cur ? '' : ' disabled'}>🔒 ${T('Κλείδωσε τις τωρινές συσκευές', 'Lock the current devices')}</button>${cur ? '' : `<span class="dim" style="font-size:12px">${T('Πρέπει να είσαι στο δίκτυο του πελάτη.', 'You must be on the customer network.')}</span>`}</div>`;
    } else {
      const nw = (bl.new || []), gn = (bl.gone || []);
      h += ` <span class="dim" style="font-size:12.5px">${bl.count} ${T('συσκευές, κλειδώθηκε', 'devices, locked')} ${when(bl.saved)}</span>`;
      if (bl.ok) h += `<div style="color:var(--green,#3ddc97);font-size:13px;margin-top:4px">✅ ${T('Καμία αλλαγή — ίδιες συσκευές με το εγκεκριμένο.', 'No change — same devices as approved.')}</div>`;
      else {
        if (nw.length) h += `<div style="font-size:13px;margin-top:4px"><b style="color:var(--orange)">🆕 ${nw.length} ${T('νέες συσκευές', 'new devices')}:</b> ${nw.map(d => `<span class="tag y" title="${E(d.mac || '')}">${E(d.icon || '')} ${E(d.name || d.vendor || d.ip)} <span class="mono">${E(d.ip)}</span></span>`).join(' ')}</div>`;
        if (gn.length) h += `<div style="font-size:13px;margin-top:4px"><b class="dim">👻 ${gn.length} ${T('λείπουν', 'missing')}:</b> ${gn.map(d => `<span class="tag" title="${E(d.mac || '')}">${E(d.name || d.ip)} <span class="mono">${E(d.ip)}</span></span>`).join(' ')}</div>`;
      }
      h += `<div class="si-row"><button class="b"${cur ? '' : ' disabled'} data-si="baseline" title="${T('Ξανακλείδωσε με τις τωρινές συσκευές', 'Re-lock with the current devices')}">🔄 ${T('Ενημέρωσε το εγκεκριμένο', 'Update the approved set')}</button><button class="b" data-si="baseclear">🗑 ${T('Κατάργηση', 'Remove')}</button></div>`;
    }
    h += `</div>`;
    if (open) {
      h += `<div class="si-form" data-form="vend">
        ${F('work', T('Τι έγινε (εργασίες)', 'Work done'), '', { area: 1, wide: 1, max: 2000, ph: T('π.χ. Ενημέρωση firmware router, έλεγχος αντιγράφων, νέα πρίζα στο γραφείο 2', 'e.g. Router firmware update, backup check, new socket in office 2') })}
        ${F('materials', T('Υλικά', 'Materials'), '', { area: 1, ph: T('π.χ. 2× patch cord 1 m, 1× RJ45', 'e.g. 2× 1 m patch cords, 1× RJ45') })}
        ${F('recs', T('Συστάσεις προς τον πελάτη (μία ανά γραμμή)', 'Recommendations to the customer (one per line)'), '', { area: 1 })}
        ${F('minutes', T('Λεπτά εργασίας (κενό = από το ρολόι)', 'Minutes worked (empty = from the clock)'), '', { type: 'number', max: 5 })}
      </div><div class="si-row"><button class="b si-go" data-si="vend">⏹ ${T('Λήξη επίσκεψης + στιγμιότυπο', 'End visit + snapshot')}</button>
      <span class="dim" style="font-size:12px">${cur ? T('Θα κρατηθεί στιγμιότυπο του δικτύου (συσκευές, ειδοποιήσεις).', 'A network snapshot (devices, alerts) will be stored.') : T('Δεν είσαι στο δίκτυο του πελάτη — η επίσκεψη θα κλείσει χωρίς στιγμιότυπο.', 'You are not on the customer network — the visit will close without a snapshot.')}</span></div>`;
    }
    h += `<div class="si-row"><b>🖨 ${T('Μηνιαία αναφορά συντήρησης', 'Monthly maintenance report')}</b>
      <select id="si-month" style="width:auto">${(S.months || []).map(m => `<option>${E(m)}</option>`).join('')}</select>
      <button class="b" data-si="report">${T('Άνοιγμα (εκτύπωση / PDF)', 'Open (print / PDF)')}</button></div>`;
    const vs = S.visit_list || [];
    h += `<details style="margin-top:12px"${vs.length ? ' open' : ''}><summary>📒 ${T('Επισκέψεις', 'Visits')} (${vs.length})</summary>`;
    h += vs.map(v => {
      const sn = v.snapshot, a = sn && sn.alerts && sn.alerts.sev || {};
      return `<div class="si-v"><b>${when(v.start)}</b> · ${v.end ? hm(v.minutes) + ' ' + T('ώρες', 'h') : '⏳ ' + T('ανοιχτή', 'open')}${v.tech ? ' · ' + E(v.tech) : ''}
        ${sn ? `<span class="dim"> · 📸 ${E(sn.count)} ${T('συσκευές', 'devices')} · ${T('ειδοποιήσεις', 'alerts')} ${E(a.high || 0)}/${E(a.med || 0)}/${E(a.low || 0)}</span>` : ''}
        <button class="b" data-si="vdel" data-v="${E(v.id)}" style="float:right" title="${T('Διαγραφή επίσκεψης', 'Delete visit')}">🗑</button>
        ${v.work ? `<div>${E(v.work)}</div>` : ''}${v.materials ? `<div class="dim">🧰 ${E(v.materials)}</div>` : ''}${v.recs ? `<div class="dim">💡 ${E(v.recs)}</div>` : ''}</div>`;
    }).join('') || `<div class="dim" style="font-size:13px;margin-top:6px">${T('Καμία επίσκεψη ακόμη.', 'No visits yet.')}</div>`;
    h += `<div class="si-form" data-form="vpast">${F('date', T('Παλιά επίσκεψη — ημερομηνία', 'Past visit — date'), '', { type: 'date', max: 10 })}
      ${F('minutes', T('Λεπτά', 'Minutes'), '', { type: 'number', max: 5 })}${F('work', T('Εργασίες', 'Work done'), '', { max: 2000 })}</div>
      <div class="si-row"><button class="b" data-si="vpast">➕ ${T('Καταχώριση παλιάς επίσκεψης', 'Add past visit')}</button></div></details>`;
    h += `<details style="margin-top:12px"><summary>✏️ ${T('Στοιχεία πελάτη & αποτύπωμα δικτύου', 'Customer details & network fingerprint')}</summary>${siteForm(S, false)}
      <div class="si-row"><button class="b" data-si="delete" style="color:var(--red)">🗑 ${T('Διαγραφή πελάτη', 'Delete customer')}</button>
      <span class="dim" style="font-size:12px">${T('Ο φάκελος με τα έγγραφά του μένει στον δίσκο.', 'The folder with their documents stays on disk.')}</span></div></details></div>`;
    return h;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error === 'off') { b.innerHTML = `<div class="card">${T('Οι «Πελάτες» δεν είναι διαθέσιμοι σε αυτή τη λειτουργία (π.χ. στατικό demo ή ανάλυση pcap).', '“Customers” is not available in this mode (e.g. static demo or pcap analysis).')}</div>`; return; }
    const n = D.network || {}, cur = (D.sites || []).find(s => s.id === D.current), co = D.company || {};
    const head = cur ? T(`Είσαι στον πελάτη: ${cur.name}`, `You are at: ${cur.name}`)
      : n.gw_ip ? T('Νέο δίκτυο — δεν ανήκει σε κανέναν πελάτη', 'New network — not linked to any customer')
        : T('Δεν βλέπω ακόμη το router αυτού του δικτύου', 'I can’t see this network’s router yet');
    let h = `<div class="card"><div class="si-hero"><span class="si-big">${cur ? '📍' : n.gw_ip ? '🆕' : '⏳'}</span><div style="flex:1;min-width:230px">
      <b style="font-size:16px">${E(head)}</b>
      <div class="dim mono" style="margin-top:3px">${n.gw_ip ? `gateway ${E(n.gw_ip)}${n.gw_mac ? ' · ' + E(n.gw_mac) : ''} · ${E(n.subnet)}` : '—'}${D.manual ? ' · ' + T('επιλογή με το χέρι', 'chosen manually') : ''}${D.demo ? ' · DEMO' : ''}</div></div>
      ${cur ? `<button class="b si-go" data-si="open" data-id="${E(cur.id)}">${T('Άνοιγμα καρτέλας', 'Open record')}</button>` : ''}
      ${D.new_network && !adding ? `<button class="b si-go" data-si="new-here">➕ ${T('Νέος πελάτης από αυτό το δίκτυο', 'New customer from this network')}</button>` : ''}
      ${D.manual ? `<button class="b" data-si="auto">${T('Αυτόματη αναγνώριση', 'Auto-detect')}</button>` : ''}</div>
      ${msg ? `<div class="si-msg">⚠ ${E(msg)}</div>` : ''}
      ${D.persist || D.demo ? '' : `<div class="si-msg">${T('Προσοχή: δεν υπάρχει φάκελος δεδομένων — οι αλλαγές δεν θα αποθηκευτούν.', 'Warning: no data folder — changes will not be saved.')}</div>`}</div>`;
    if (adding) h += `<div class="card"><b>➕ ${T('Νέος πελάτης', 'New customer')}</b>${siteForm(adding, true)}</div>`;
    h += `<div class="card"><div class="si-row" style="margin-top:0"><b style="flex:1">${T('Πελάτες', 'Customers')} (${(D.sites || []).length})</b>
      ${adding ? '' : `<button class="b" data-si="new">➕ ${T('Νέος πελάτης', 'New customer')}</button>`}
      <a class="b" href="${API}/sites.csv" target="_blank" rel="noopener">⬇ CSV</a></div>`;
    h += (D.sites || []).map(s => `<div class="si-site" style="--c:${s.id === D.current ? 'var(--cyan)' : s.open_visit ? 'var(--orange)' : 'var(--dim)'}">
      <div><b>${E(s.name)}</b> <span class="si-pill" style="--c:var(--dim)">${E(contract(s.contract))}</span>${s.open_visit ? ` <span class="si-pill" style="--c:var(--orange)">⏱ ${T('επίσκεψη ανοιχτή', 'visit open')}</span>` : ''}
        <div class="dim" style="font-size:12px;margin-top:2px">${E(s.address || '')}${s.contact ? ' · ' + E(s.contact) : ''}${s.phone ? ' · ' + E(s.phone) : ''}</div>
        <div class="dim" style="font-size:12px">${s.visits} ${T('επισκέψεις', 'visits')} · ${T('τελευταία', 'last')} ${when(s.last_visit)} · ${T('αυτόν τον μήνα', 'this month')} ${hm(s.month_minutes)} ${T('ώρες', 'h')}${s.fp && s.fp.gw_mac ? '' : ' · ⚠ ' + T('χωρίς MAC router', 'no router MAC')}</div></div>
      <button class="b" data-si="open" data-id="${E(s.id)}">${sel === s.id ? '▾' : '▸'} ${T('Άνοιγμα', 'Open')}</button></div>`).join('')
      || `<div class="empty">${T('Κανένας πελάτης ακόμη. Συνδέσου στο δίκτυό του και πάτησε «Νέος πελάτης από αυτό το δίκτυο».', 'No customers yet. Connect to their network and press “New customer from this network”.')}</div>`;
    h += '</div>' + detail();
    h += `<div class="card"><details><summary>🧾 ${T('Στοιχεία της επιχείρησής σου (μπαίνουν σε όλες τις εκτυπώσεις)', 'Your company details (used on every printout)')}</summary>
      <div class="si-form" data-form="company">${F('name', T('Επωνυμία', 'Company name'), co.name)}${F('tech', T('Τεχνικός', 'Technician'), co.tech)}${F('phone', T('Τηλέφωνο', 'Phone'), co.phone, { max: 40 })}
      ${F('email', 'Email', co.email)}${F('vat', T('ΑΦΜ', 'VAT number'), co.vat, { max: 20 })}${F('address', T('Διεύθυνση', 'Address'), co.address, { max: 160 })}
      <label>${T('Λογότυπο (PNG/JPEG έως 200 KB)', 'Logo (PNG/JPEG up to 200 KB)')}${co.has_logo ? ' ✅' : ''}<input type="file" id="si-logo" accept="image/png,image/jpeg"></label></div>
      <div class="si-row"><button class="b si-go" data-si="company">💾 ${T('Αποθήκευση', 'Save')}</button>${co.has_logo ? `<button class="b" data-si="nologo">${T('Αφαίρεση λογότυπου', 'Remove logo')}</button>` : ''}</div></details></div>`;
    h += `<div class="card"><b>👉 ${T('Πώς δουλεύει', 'How to use it')}</b><ol>
      <li>${T('Την πρώτη φορά σε έναν πελάτη: συνδέσου στο δίκτυό του και πάτησε <b>«Νέος πελάτης από αυτό το δίκτυο»</b>. Το NetWatch θυμάται τη MAC του router και την επόμενη φορά τον αναγνωρίζει μόνο του.', 'First time at a customer: connect to their network and press <b>“New customer from this network”</b>. NetWatch remembers the router’s MAC and recognises them next time.')}</li>
      <li>${T('Φτάνοντας πάτησε <b>«Έναρξη επίσκεψης»</b>· φεύγοντας γράψε τι έκανες και πάτησε <b>«Λήξη»</b>. Κρατιέται στιγμιότυπο: συσκευές και ειδοποιήσεις από την προηγούμενη φορά.', 'On arrival press <b>“Start visit”</b>; before leaving write what you did and press <b>“End”</b>. A snapshot is stored: devices and alerts since last time.')}</li>
      <li>${T('Στο τέλος του μήνα άνοιξε τη <b>μηνιαία αναφορά</b>, τύπωσέ τη ή σώσε τη ως PDF (Ctrl+P) και δώσ’ τη για υπογραφή.', 'At month end open the <b>monthly report</b>, print it or save it as PDF (Ctrl+P) and hand it over for signature.')}</li>
      <li>${T('Τα <b>Τεστ αποδοχής</b> και οι <b>Ετικέτες</b> αποθηκεύονται στον φάκελο του πελάτη στον οποίο βρίσκεσαι.', '<b>Acceptance tests</b> and <b>Labels</b> are stored in the folder of the customer you are at.')}</li></ol></div>`;
    b.innerHTML = h;
  }

  const get = (sub = '') => fetch(API + sub).then(r => r.json());
  const post = (sub, body) => fetch(`${API}/${sub}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then(r => r.json());
  const openSite = id => { sel = id; return id ? get('/site?id=' + encodeURIComponent(id)).then(j => { S = j.error ? null : j; draw(); }) : (S = null, draw()); };
  function done(j, keep) {
    if (j.error) { msg = EN() ? (j.error_en || j.error) : j.error; draw(); return false; }
    msg = ''; D = j; if (j.site) S = j.site; if (!keep) adding = false;
    if (j.saved && !j.site) return openSite(j.saved), true;
    if (sel && !j.site) return openSite(sel), true;
    draw(); return true;
  }
  function load() {
    return get().then(j => { D = j; if (D.error) { D = { error: 'off' }; draw(); return; } if (sel === null && D.current) return openSite(D.current); draw(); })
      .catch(() => { D = { error: 'off' }; draw(); });
  }
  const sitePayload = root => { const v = vals(root); return { name: v.name, address: v.address, contact: v.contact, phone: v.phone, email: v.email, contract: v.contract, notes: v.notes, fp: { gw_ip: v.gw_ip, gw_mac: v.gw_mac, subnet: v.subnet, ssid: v.ssid } }; };
  const formOf = name => box().querySelector(`[data-form="${name}"]`);

  document.addEventListener('click', e => {
    const b = e.target.closest('#t-sites [data-si]'); if (!b || !D) return;
    const a = b.dataset.si, id = S && S.id;
    if (a === 'open') { const t = b.dataset.id; openSite(sel === t ? '' : t).then(() => { const d = document.getElementById('si-detail'); if (d && d.scrollIntoView) d.scrollIntoView({ block: 'nearest' }); }); }
    else if (a === 'new') { adding = { fp: {} }; draw(); }
    else if (a === 'new-here') { adding = { fp: D.network || {} }; draw(); }
    else if (a === 'cancel') { adding = false; msg = ''; draw(); }
    else if (a === 'create') { adding = sitePayload(formOf('site')); post('save', adding).then(j => { if (!j.error) adding = false; done(j, true); }); }
    else if (a === 'update') post('save', Object.assign({ id }, sitePayload(box().querySelector('#si-detail [data-form="site"]')))).then(done);
    else if (a === 'delete') { if (confirm(T(`Να διαγραφεί ο πελάτης «${S.name}» από το μητρώο;`, `Remove customer “${S.name}” from the registry?`))) post('delete', { id }).then(j => { sel = ''; S = null; done(j); }); }
    else if (a === 'select') post('select', { id }).then(done);
    else if (a === 'auto') post('select', { id: '' }).then(done);
    else if (a === 'bind') post('bind', { id }).then(done);
    else if (a === 'baseline') post('baseline', { id }).then(done);
    else if (a === 'baseclear') { if (confirm(T('Να καταργηθεί το εγκεκριμένο δίκτυο αυτού του πελάτη;', 'Remove the approved network for this customer?'))) post('baseline/clear', { id }).then(done); }
    else if (a === 'vstart') post('visit/start', { id }).then(done);
    else if (a === 'vend') post('visit/end', Object.assign({ id }, vals(formOf('vend')))).then(done);
    else if (a === 'vpast') post('visit/save', Object.assign({ id }, vals(formOf('vpast')))).then(done);
    else if (a === 'vdel') { if (confirm(T('Να διαγραφεί η επίσκεψη;', 'Delete this visit?'))) post('visit/delete', { id, vid: b.dataset.v }).then(done); }
    else if (a === 'report') window.open(`${API}/report?id=${encodeURIComponent(id)}&month=${encodeURIComponent(document.getElementById('si-month').value)}&lang=${LANG()}`, '_blank', 'noopener');
    else if (a === 'nologo') post('company', { logo: '' }).then(done);
    else if (a === 'company') {
      const body = vals(formOf('company')), f = document.getElementById('si-logo').files[0];
      if (!f) return void post('company', body).then(done);
      if (!/^image\/(png|jpeg)$/.test(f.type) || f.size > 200 * 1024) { msg = T('Το λογότυπο πρέπει να είναι PNG ή JPEG έως 200 KB.', 'The logo must be a PNG or JPEG up to 200 KB.'); draw(); return; }
      const rd = new FileReader();
      rd.onload = () => { body.logo = String(rd.result); post('company', body).then(done); };
      rd.readAsDataURL(f);
    }
  });
  window.renderSites = () => load();
})();
