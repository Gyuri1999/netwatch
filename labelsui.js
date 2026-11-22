// ───────────────────────── 🏷 Ετικέτες & QR — φύλλα A4 και ταινίες για συσκευές, πρίζες, patch panel, καλώδια ─────────────────────────
// Το φύλλο βγαίνει ως αυτόνομη σελίδα HTML με ακριβή mm (@page) — τυπώνεται στο 100%. Το QR είναι ενσωματωμένο SVG.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const LANG = () => (EN() ? 'en' : 'el');
  const box = () => document.getElementById('t-labels');
  const API = '/api/kit/labels';
  const blank = () => ({ id: '', name: '', site: null, preset: 'a4-24', fields: ['name', '', ''], qr: 'none', url_tpl: '', offset: 0, len: '', items: [] });
  let D = null, W = blank(), src = 'pattern', msg = '', saved = '';
  const SV = {};

  const css = document.createElement('style');
  css.textContent = `
#t-labels .lb-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
#t-labels .lb-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin-top:8px;align-items:end}
#t-labels label{display:flex;flex-direction:column;gap:3px;font-size:11.5px;color:var(--dim)}#t-labels label.w{grid-column:1/-1}
#t-labels input,#t-labels select{padding:7px 9px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 15%);background:transparent;color:inherit;font:inherit;font-size:13px;min-width:0;width:100%;box-sizing:border-box}
#t-labels select option{color:#111}
#t-labels a.b{display:inline-block;text-decoration:none;color:inherit;border:1px solid rgb(var(--w,255 255 255) / 12%);border-radius:8px;padding:5px 11px;font-size:12px}
#t-labels .lb-go{border-color:var(--cyan)!important;color:var(--cyan)!important;font-weight:600}
#t-labels .lb-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}#t-labels .lb-tabs button.on{border-color:var(--cyan);color:var(--cyan)}
#t-labels .lb-set{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;align-items:center;border-left:3px solid var(--cyan);border-radius:10px;background:rgb(var(--w,255 255 255) / 3%);padding:9px 12px;margin-top:8px;font-size:13px}
#t-labels .lb-wrap{overflow:auto;max-height:300px;margin-top:8px}#t-labels table{width:100%;border-collapse:collapse;font-size:12.5px}
#t-labels th{text-align:left;color:var(--dim);font-size:11px;padding:5px 6px;border-bottom:1px solid rgb(var(--w,255 255 255) / 12%)}
#t-labels td{padding:5px 6px;border-bottom:1px solid rgb(var(--w,255 255 255) / 6%)}#t-labels td.m{font-family:var(--mono,ui-monospace,monospace);white-space:nowrap}
#t-labels .lb-prev{display:inline-flex;align-items:center;gap:6px;background:#fff;color:#000;border-radius:4px;padding:6px 10px;font:700 13px Arial,sans-serif;margin-top:8px;max-width:100%;overflow:hidden;white-space:nowrap}
#t-labels .lb-prev small{display:block;font-weight:400;font-size:11px}#t-labels .lb-prev i{width:30px;height:30px;flex:none;background:repeating-conic-gradient(#000 0 25%,#fff 0 50%) 0 0/8px 8px}
#t-labels .lb-msg{color:var(--orange);font-size:13px;margin-top:8px}
#t-labels ol{margin:6px 0 0 18px;padding:0;font-size:13px}#t-labels li{margin:3px 0}
@media (max-width:600px){#t-labels .lb-set{grid-template-columns:1fr}}
`;
  document.head.appendChild(css);

  const preset = id => (D.presets || []).find(p => p.id === id) || {};
  const fname = id => { const f = (D.fields || []).find(x => x.id === id); return f ? T(f.el, f.en) : id; };
  const opt = (v, label, pick) => `<option value="${E(v)}"${String(v) === String(pick) ? ' selected' : ''}>${E(label)}</option>`;
  const SRC = () => [['pattern', '🔢 ' + T('Αρίθμηση', 'Numbering')], ['cables', '🔌 ' + T('Καλώδια (2 άκρα)', 'Cables (2 ends)')], ['devices', '💻 ' + T('Συσκευές', 'Devices')],
    ...(D.sources && D.sources.ipam ? [['ipam', '📒 IPAM']] : []), ...(D.sources && (D.sources.jobs || []).length ? [['accept', '✅ ' + T('Εργασία αποδοχής', 'Acceptance job')]] : [])];
  const lineOf = (it, f) => f === 'cable' ? (it.b ? `${it.name || ''} ⇄ ${it.b}` : it.name || '') : f === 'vlan' ? (it.vlan ? 'VLAN ' + it.vlan : '') : (it[f] || '');

  function sourceForm() {
    const s = D.sources || {};
    if (src === 'pattern') return `<label class="w">${T('Μοτίβο αρίθμησης (χωρίζεις πολλά με κόμμα)', 'Numbering pattern (separate several with commas)')}<input data-s="pattern" maxlength="300" value="${E(SV.pattern || '')}" placeholder="PP1-01..PP1-24, PP2-01..PP2-24"></label>`;
    if (src === 'cables') return `<label>${T('Άκρο Α', 'End A')}<input data-s="pattern" maxlength="300" value="${E(SV.pattern || '')}" placeholder="A-01..A-12"></label><label>${T('Άκρο Β (ίδιο πλήθος)', 'End B (same count)')}<input data-s="pattern_b" maxlength="300" value="${E(SV.pattern_b || '')}" placeholder="SW1/01..SW1/12"></label>`;
    if (src === 'devices') return `<label>${T('Ποιες συσκευές', 'Which devices')} (${s.devices || 0})<select data-s="dtypes">${opt('', T('όλες', 'all'), SV.dtypes || '')}${Object.keys(s.dtypes || {}).sort().map(k => opt(k, `${k} (${s.dtypes[k]})`, SV.dtypes || '')).join('')}</select></label>`;
    if (src === 'accept') return `<label class="w">${T('Εργασία αποδοχής', 'Acceptance job')}<select data-s="job">${(s.jobs || []).map(j => opt(j.id, `${j.title} (${j.points})`, SV.job || '')).join('')}</select></label>`;
    return `<div class="dim" style="font-size:12.5px">${T('Όλες οι διευθύνσεις του IPAM με όνομα, τοποθεσία και VLAN.', 'Every IPAM address with name, location and VLAN.')}</div>`;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error === 'off') { b.innerHTML = `<div class="card">${T('Οι «Ετικέτες» δεν είναι διαθέσιμες σε αυτή τη λειτουργία (π.χ. στατικό demo ή ανάλυση pcap).', '“Labels” is not available in this mode (e.g. static demo or pcap analysis).')}</div>`; return; }
    const P = preset(W.preset), sheet = P.kind === 'sheet', n = W.items.length, f = W.fields.filter(Boolean), first = W.items[0];
    const pages = sheet && n ? Math.ceil((n + (+W.offset || 0)) / P.per) : 0;
    let h = `<div class="card"><b style="font-size:16px">🏷 ${T('Ετικέτες & QR', 'Labels & QR')}</b>${D.demo ? ' <span class="dim">DEMO</span>' : ''}
      <div class="dim" style="font-size:12.5px;margin-top:4px">${T('Τρία βήματα: τι θα γράφουν → σε τι χαρτί/ταινία → εκτύπωση στο 100%.', 'Three steps: what they say → which paper/tape → print at 100%.')}</div>
      <div style="margin-top:12px"><b>1 · ${T('Από πού', 'Source')}</b></div>
      <div class="lb-tabs">${SRC().map(([k, l]) => `<button class="b${src === k ? ' on' : ''}" data-lb="src" data-k="${k}">${l}</button>`).join('')}</div>
      <div class="lb-form" id="lb-src">${sourceForm()}</div>
      <div class="lb-row"><button class="b lb-go" data-lb="build">⚙ ${T('Φτιάξε τις ετικέτες', 'Build labels')}</button>
        ${n ? `<button class="b" data-lb="append">➕ ${T('Πρόσθεσε στις υπάρχουσες', 'Append to existing')}</button><button class="b" data-lb="clear">${T('Καθάρισμα', 'Clear')}</button>` : ''}
        <span class="dim" style="font-size:12.5px">${n} ${T('ετικέτες', 'labels')}${pages ? ` · ${pages} ${T('φύλλα', 'sheets')}` : ''}</span></div>
      ${msg ? `<div class="lb-msg">⚠ ${E(msg)}</div>` : ''}`;
    if (n) {
      h += `<div style="margin-top:14px"><b>2 · ${T('Μορφή', 'Layout')}</b></div><div class="lb-form">
        <label class="w">${T('Χαρτί / ταινία', 'Paper / tape')}<select data-w="preset">${(D.presets || []).map(p => opt(p.id, T(p.el, p.en), W.preset)).join('')}</select></label>
        ${[0, 1, 2].map(i => `<label>${T('Γραμμή', 'Line')} ${i + 1}<select data-w="f${i}">${i ? opt('', '—', W.fields[i]) : ''}${(D.fields || []).map(x => opt(x.id, T(x.el, x.en), W.fields[i])).join('')}</select></label>`).join('')}
        <label>QR<select data-w="qr">${opt('none', T('χωρίς QR', 'no QR'), W.qr)}${opt('id', T('όνομα (σκέτο κείμενο)', 'name (plain text)'), W.qr)}${opt('ip', 'IP', W.qr)}${opt('url', T('σύνδεσμος (URL)', 'link (URL)'), W.qr)}</select></label>
        ${sheet ? `<label>${T('Παράλειψε τις πρώτες Ν θέσεις (μισοχρησιμοποιημένο φύλλο)', 'Skip the first N positions (partly used sheet)')}<input data-w="offset" type="number" min="0" max="${(P.per || 1) - 1}" value="${E(W.offset || 0)}"></label>`
    : `<label>${T('Μήκος ετικέτας σε mm (κενό = ', 'Label length in mm (empty = ')}${E(P.w)})<input data-w="len" type="number" min="20" max="300" value="${E(W.len || '')}"></label>`}
        ${W.qr === 'url' ? `<label class="w">${T('Πρότυπο URL — {ip} {mac} {name} {id}', 'URL template — {ip} {mac} {name} {id}')}<input data-w="url_tpl" maxlength="200" value="${E(W.url_tpl)}" placeholder="${E(D.url_default)}"></label>` : ''}</div>
        <div class="lb-prev">${W.qr !== 'none' ? '<i></i>' : ''}<span>${E(lineOf(first, f[0] || 'name') || first.name || '')}${f.slice(1).map(x => lineOf(first, x)).filter(Boolean).map(x => `<small>${E(x)}</small>`).join('')}</span></div>
        <div class="dim" style="font-size:12px;margin-top:4px">${T('Πρόχειρη προεπισκόπηση της πρώτης ετικέτας', 'Rough preview of the first label')} · ${E(P.w)}×${E(P.h)} mm</div>
        <div class="lb-wrap"><table><tr><th>#</th><th>${fname('name')}</th><th>IP</th><th>${fname('location')}</th><th>VLAN</th><th></th></tr>
        ${W.items.slice(0, 120).map((it, i) => `<tr><td>${i + 1}</td><td>${E(it.name)}${it.b ? ' ⇄ ' + E(it.b) : ''}</td><td class="m">${E(it.ip)}</td><td>${E(it.location)}</td><td>${E(it.vlan)}</td><td><button class="b" data-lb="rm" data-i="${i}">✕</button></td></tr>`).join('')}
        </table>${n > 120 ? `<div class="dim" style="font-size:12px;padding:6px">… +${n - 120}</div>` : ''}</div>
        <div style="margin-top:14px"><b>3 · ${T('Αποθήκευση & εκτύπωση', 'Save & print')}</b></div><div class="lb-form">
        <label>${T('Όνομα σετ', 'Set name')}<input data-w="name" maxlength="80" value="${E(W.name)}" placeholder="${T('π.χ. Patch panel 1', 'e.g. Patch panel 1')}"></label>
        <label>${T('Πελάτης', 'Customer')}<select data-w="site">${opt('', T('— χωρίς πελάτη —', '— no customer —'), W.site === null ? (D.site || '') : W.site)}${(D.sites || []).map(s => opt(s.id, s.name, W.site === null ? (D.site || '') : W.site)).join('')}</select></label>
        <button class="b lb-go" data-lb="save">💾 ${W.id ? T('Αποθήκευση αλλαγών', 'Save changes') : T('Αποθήκευση σετ', 'Save set')}</button></div>
        ${saved ? `<div class="lb-row"><a class="b lb-go" href="${API}/sheet?id=${encodeURIComponent(saved)}&lang=${LANG()}" target="_blank" rel="noopener">🖨 ${T('Άνοιγμα φύλλου για εκτύπωση', 'Open sheet for printing')}</a>
          <span class="dim" style="font-size:12.5px">✅ ${T('Αποθηκεύτηκε. Στην εκτύπωση: κλίμακα 100%, περιθώρια «Κανένα».', 'Saved. When printing: scale 100%, margins “None”.')}</span></div>` : ''}`;
    }
    h += '</div>';
    h += `<div class="card"><b>${T('Αποθηκευμένα σετ', 'Saved sets')} (${(D.sets || []).length})</b>` + ((D.sets || []).map(s => `<div class="lb-set"><div><b>${E(s.name)}</b>
      <div class="dim" style="font-size:12px;margin-top:2px">${s.count} ${T('ετικέτες', 'labels')} · ${E(T(preset(s.preset).el, preset(s.preset).en))} · ${s.fields.map(fname).map(E).join(' / ')}${s.qr !== 'none' ? ' · QR' : ''}${s.site_name ? ' · 🏢 ' + E(s.site_name) : ''}</div></div>
      <div class="lb-row" style="margin-top:0"><a class="b" href="${API}/sheet?id=${encodeURIComponent(s.id)}&lang=${LANG()}" target="_blank" rel="noopener">🖨 ${T('Εκτύπωση', 'Print')}</a>
      <button class="b" data-lb="edit" data-id="${E(s.id)}">✏️</button><button class="b" data-lb="del" data-id="${E(s.id)}" style="color:var(--red)">🗑</button></div></div>`).join('')
      || `<div class="empty">${T('Κανένα σετ ακόμη.', 'No sets yet.')}</div>`) + '</div>';
    h += `<div class="card"><b>👉 ${T('Πώς δουλεύει', 'How to use it')}</b><ol>
      <li>${T('<b>Patch panel / πρίζες:</b> «Αρίθμηση» → <code>PP1-01..PP1-24</code> → A4 5×13 (μικρές ετικέτες).', '<b>Patch panel / sockets:</b> “Numbering” → <code>PP1-01..PP1-24</code> → A4 5×13 (small labels).')}</li>
      <li>${T('<b>Καλώδια:</b> «Καλώδια» με τα δύο άκρα → «Σημαία καλωδίου»: το κείμενο γράφεται δύο φορές, τυλίγεις τη μέση γύρω από το καλώδιο και κολλάς τα δύο άκρα πλάτη με πλάτη.', '<b>Cables:</b> “Cables” with both ends → “Cable flag”: the text is printed twice; wrap the middle around the cable and stick the two ends back to back.')}</li>
      <li>${T('<b>Συσκευές:</b> «Συσκευές» → γραμμές Όνομα / IP / Τοποθεσία + QR. Ο πελάτης (ή εσύ) σκανάρει το QR και βλέπει ποια συσκευή είναι.', '<b>Devices:</b> “Devices” → lines Name / IP / Location + QR. The customer (or you) scans the QR to see which device it is.')}</li>
      <li>${T('<b>Εκτύπωση:</b> Ctrl+P, κλίμακα <b>100%</b> (όχι «προσαρμογή στη σελίδα»), περιθώρια <b>Κανένα</b>. Δοκίμασε πρώτα σε απλό χαρτί. Για ταινία Brother διάλεξε τον εκτυπωτή ετικετών και το σωστό πλάτος ταινίας.', '<b>Printing:</b> Ctrl+P, scale <b>100%</b> (not “fit to page”), margins <b>None</b>. Try on plain paper first. For Brother tape pick the label printer and the right tape width.')}</li></ol>
      <div class="dim" style="font-size:12px;margin-top:6px">${T('Προεπιλεγμένος σύνδεσμος QR:', 'Default QR link:')} <code>${E(D.url_default)}</code></div></div>`;
    b.innerHTML = h;
  }

  const get = (sub = '') => fetch(API + sub).then(r => r.json());
  const post = (sub, body) => fetch(`${API}/${sub}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then(r => r.json());
  const fail = j => { if (!j.error) return false; msg = EN() ? (j.error_en || j.error) : j.error; draw(); return true; };
  function load() {
    return get().then(j => { D = j.error ? { error: 'off' } : j; draw(); }).catch(() => { D = { error: 'off' }; draw(); });
  }
  function build(append) {
    const body = { source: src };
    box().querySelectorAll('#lb-src [data-s]').forEach(i => { body[i.dataset.s] = i.value; });
    post('build', body).then(j => {
      if (fail(j)) return;
      msg = ''; saved = '';
      W.items = (append ? W.items : []).concat(j.items).slice(0, 1000);
      if (!append) {
        W.fields = src === 'cables' ? ['cable', '', ''] : src === 'devices' || src === 'ipam' ? ['name', 'ip', 'location'] : src === 'accept' ? ['name', 'location', ''] : ['name', '', ''];
        if (src === 'cables' && W.preset.indexOf('flag') !== 0) W.preset = 'flag-12';
        if (!W.name) W.name = body.pattern || '';
      }
      draw();
    });
  }
  function payload() {
    return { id: W.id || undefined, name: W.name, site: W.site === null ? (D.site || '') : W.site, preset: W.preset, fields: W.fields.filter(Boolean), qr: W.qr, url_tpl: W.url_tpl, offset: +W.offset || 0, len: W.len || null, items: W.items };
  }

  document.addEventListener('input', e => { const i = e.target.closest('#t-labels #lb-src [data-s]'); if (i) SV[i.dataset.s] = i.value; });
  document.addEventListener('change', e => {
    const i = e.target.closest('#t-labels [data-w]'); if (!i || !D) return;
    const k = i.dataset.w;
    if (/^f\d$/.test(k)) W.fields[+k[1]] = i.value; else W[k] = i.value;
    saved = '';
    if (k !== 'name') draw();
  });
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-labels [data-lb]'); if (!b || !D) return;
    const a = b.dataset.lb;
    if (a === 'src') { src = b.dataset.k; msg = ''; draw(); }
    else if (a === 'build') build(false);
    else if (a === 'append') build(true);
    else if (a === 'clear') { W = blank(); saved = ''; msg = ''; draw(); }
    else if (a === 'rm') { W.items.splice(+b.dataset.i, 1); saved = ''; draw(); }
    else if (a === 'save') post('save', payload()).then(j => { if (fail(j)) return; msg = ''; saved = j.saved; W.id = j.saved; delete j.saved; D = j; draw(); });
    else if (a === 'edit') get('/set?id=' + encodeURIComponent(b.dataset.id)).then(s => {
      if (fail(s)) return;
      W = Object.assign(blank(), s, { fields: [0, 1, 2].map(i => s.fields[i] || ''), len: s.len || '' }); saved = s.id; msg = ''; draw(); window.scrollTo(0, 0);
    });
    else if (a === 'del') { if (confirm(T('Να διαγραφεί το σετ ετικετών;', 'Delete this label set?'))) post('delete', { id: b.dataset.id }).then(j => { if (fail(j)) return; if (W.id === b.dataset.id) { W.id = ''; saved = ''; } D = j; draw(); }); }
  });
  window.renderLabels = () => load();
})();
