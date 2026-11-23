// ───────────────────────── 📅 «Άφησέ το μια βδομάδα»: παρακολούθηση ποιότητας γραμμής ─────────────────────────
// Backend: soak.py (/api/kit/soak). Διαβάζει ό,τι ήδη καταγράφουν οι 📈 Καθυστέρηση και 📈 Διαθεσιμότητα.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const box = () => document.getElementById('t-soak');
  const COL = { ok: 'var(--green,#3ecf8e)', warn: 'var(--orange)', bad: 'var(--red)' };
  let D = null, msg = '';

  const css = document.createElement('style');
  css.textContent = `
#t-soak{min-width:0}
#t-soak .card{min-width:0;max-width:100%}
#t-soak .sk-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-soak .sk-big{font-size:34px}
#t-soak .sk-kpis{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
#t-soak .sk-kpi{border:1px solid rgb(var(--w,255 255 255) / 12%);border-radius:10px;padding:7px 12px;min-width:92px}
#t-soak .sk-kpi b{display:block;font-size:19px}
#t-soak .sk-kpi span{font-size:11px;color:var(--dim)}
#t-soak .sk-f{border-left:3px solid var(--c);border-radius:8px;background:rgb(var(--w,255 255 255) / 3%);padding:8px 11px;margin-top:7px;font-size:13px}
#t-soak .sk-f .dim{font-size:12.5px;margin-top:3px}
#t-soak .sk-bars{display:grid;grid-template-columns:repeat(24,1fr);gap:2px;align-items:end;height:96px;margin-top:10px}
#t-soak .sk-bar{background:var(--c);border-radius:2px 2px 0 0;min-height:2px}
#t-soak .sk-hrs{display:grid;grid-template-columns:repeat(24,1fr);gap:2px;font-size:9.5px;color:var(--dim);text-align:center;margin-top:2px}
#t-soak .sk-wrap{overflow-x:auto;margin-top:8px}
#t-soak table{border-collapse:collapse;width:100%;font-size:12.5px}
#t-soak th,#t-soak td{text-align:left;padding:5px 8px;border-bottom:1px solid rgb(var(--w,255 255 255) / 8%);white-space:nowrap}
#t-soak th{color:var(--dim);font-weight:600;font-size:11.5px}
#t-soak td.r,#t-soak th.r{text-align:right}
#t-soak .sk-form{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
#t-soak input[type=text],#t-soak input[type=number]{padding:7px 10px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 15%);background:transparent;color:inherit;font:inherit}
#t-soak input[type=text]{flex:1;min-width:180px}
#t-soak input[type=number]{width:74px}
#t-soak .sk-prog{height:6px;border-radius:3px;background:rgb(var(--w,255 255 255) / 10%);overflow:hidden;margin-top:6px}
#t-soak .sk-prog i{display:block;height:100%;background:var(--cyan)}
#t-soak .sk-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:8px 0;border-bottom:1px solid rgb(var(--w,255 255 255) / 8%)}
#t-soak ol{margin:6px 0 0 18px;padding:0;font-size:13px}#t-soak li{margin:3px 0}
`;
  document.head.appendChild(css);

  const loc = () => EN() ? 'en-GB' : 'el-GR';
  const when = t => t ? new Date(t * 1000).toLocaleString(loc(), { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : '—';
  const dash = v => v == null ? '—' : v;
  const post = (sub, body) => fetch('/api/kit/soak/' + sub, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then(r => r.json());

  function summary(s) {
    const i = s.internet, c = COL[s.level] || 'var(--dim)';
    const head = !s.has_data ? T('Δεν υπάρχουν ακόμα μετρήσεις', 'No measurements yet')
      : s.level === 'ok' ? T('Η γραμμή είναι σταθερή', 'The line is stable')
        : s.level === 'warn' ? T('Υπάρχουν σημεία που θέλουν προσοχή', 'Some points need attention') : T('Η γραμμή έχει πρόβλημα', 'The line has a problem');
    let h = `<div class="card"><div class="sk-hero"><span class="sk-big">${!s.has_data ? '⏳' : s.level === 'ok' ? '✅' : s.level === 'warn' ? '⚠️' : '🚨'}</span>
      <div style="flex:1;min-width:220px"><b style="font-size:16px;color:${c}">${head}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${when(s.start)} → ${when(s.end)}</div></div></div>
      <div class="sk-kpis">
        <div class="sk-kpi"><b>${i.uptime == null ? '—' : i.uptime + '%'}</b><span>${T('διαθεσιμότητα Internet', 'Internet uptime')}</span></div>
        <div class="sk-kpi"><b>${i.outages}</b><span>${T('διακοπές', 'outages')}</span></div>
        <div class="sk-kpi"><b>${i.down_min}′</b><span>${T('σύνολο εκτός', 'total down')}</span></div>
        <div class="sk-kpi"><b>${i.longest_min}′</b><span>${T('μεγαλύτερη', 'longest')}</span></div>
        <div class="sk-kpi"><b>${s.coverage}%</b><span>${T('κάλυψη μετρήσεων', 'measurement coverage')}</span></div>
      </div>
      ${(s.findings || []).map(f => `<div class="sk-f" style="--c:${COL[f.sev] || 'var(--dim)'}">${E(EN() ? f.en : f.el)}${(EN() ? f.fix_en : f.fix) ? `<div class="dim">👉 ${E(EN() ? f.fix_en : f.fix)}</div>` : ''}</div>`).join('')}</div>`;
    if (!s.has_data) return h;
    const top = Math.max(5, ...s.hours.map(x => x.loss || 0));
    h += `<div class="card"><b>${T('Ανά ώρα της ημέρας — μέση απώλεια πακέτων', 'By hour of day — average packet loss')}</b>
      <div class="sk-bars">${s.hours.map(x => `<div class="sk-bar" title="${String(x.h).padStart(2, '0')}:00 · ${x.loss == null ? '—' : x.loss + '%'} · ${x.med == null ? '—' : x.med + ' ms'}" style="height:${x.loss == null ? 2 : Math.max(3, 100 * x.loss / top)}%;--c:${x.loss == null ? 'rgb(var(--w,255 255 255) / 12%)' : x.loss >= 5 ? 'var(--red)' : x.loss >= 1 ? 'var(--orange)' : 'var(--green,#3ecf8e)'}"></div>`).join('')}</div>
      <div class="sk-hrs">${s.hours.map(x => `<span>${x.h % 3 ? '' : String(x.h).padStart(2, '0')}</span>`).join('')}</div>
      <div class="dim" style="font-size:12px;margin-top:6px">${T('Κόκκινο = πάνω από 5% (φαίνεται σε βιντεοκλήσεις και VoIP). Πέρνα τον δείκτη πάνω από μια μπάρα για λεπτομέρειες.', 'Red = above 5% (noticeable on video calls and VoIP). Hover a bar for details.')}</div></div>`;
    h += `<div class="card"><b>${T('Ανά ημέρα', 'By day')}</b><div class="sk-wrap"><table><thead><tr><th>${T('Ημέρα', 'Day')}</th><th class="r">${T('Απώλεια %', 'Loss %')}</th><th class="r">${T('Διάμεση ms', 'Median ms')}</th><th class="r">${T('Διακοπές', 'Outages')}</th><th class="r">${T('Λεπτά εκτός', 'Min down')}</th></tr></thead><tbody>
      ${s.days.map(d => `<tr><td>${E(d.day)}</td><td class="r">${dash(d.loss)}</td><td class="r">${dash(d.med)}</td><td class="r"${d.outages ? ' style="color:var(--red);font-weight:700"' : ''}>${d.outages}</td><td class="r">${d.down_min}</td></tr>`).join('')}</tbody></table></div></div>`;
    h += `<div class="card"><b>${T('Στόχοι μέτρησης', 'Measured targets')}</b><div class="sk-wrap"><table><thead><tr><th>${T('Στόχος', 'Target')}</th><th class="r">${T('Απώλεια %', 'Loss %')}</th><th class="r">${T('Διάμεση ms', 'Median ms')}</th><th class="r">95% ms</th><th class="r">Jitter ms</th><th class="r">${T('Διακοπές', 'Outages')}</th></tr></thead><tbody>
      ${s.targets.map(x => `<tr><td>${E(x.name)} <span class="dim">${E(x.host || '')}</span></td><td class="r">${dash(x.loss)}</td><td class="r">${dash(x.med)}</td><td class="r">${dash(x.p95)}</td><td class="r">${dash(x.jitter)}</td><td class="r">${x.outages}</td></tr>`).join('')}</tbody></table></div></div>`;
    if (s.outages.length) {
      const cause = { isp: T('γραμμή / πάροχος', 'line / ISP'), local: T('τοπικό δίκτυο', 'local network'), unknown: T('άγνωστο', 'unknown') };
      h += `<div class="card"><b>${T('Διακοπές Internet', 'Internet outages')}</b><div class="sk-wrap"><table><thead><tr><th>${T('Από', 'From')}</th><th>${T('Έως', 'To')}</th><th class="r">${T('Διάρκεια', 'Duration')}</th><th>${T('Πού ήταν το πρόβλημα', 'Where the problem was')}</th></tr></thead><tbody>
        ${s.outages.slice(-30).reverse().map(o => `<tr><td>${when(o.start)}</td><td>${when(o.end)}</td><td class="r">${o.min}′</td><td>${E(cause[o.cause] || o.cause)}</td></tr>`).join('')}</tbody></table></div></div>`;
    }
    if (s.devices.length) {
      h += `<div class="card"><b>${T('Συσκευές που χάθηκαν από το δίκτυο', 'Devices that dropped off the network')}</b><div class="sk-wrap"><table><thead><tr><th>${T('Συσκευή', 'Device')}</th><th class="r">Online %</th><th class="r">${T('Φορές', 'Times')}</th><th class="r">${T('Μεγαλύτερη (λεπτά)', 'Longest (min)')}</th></tr></thead><tbody>
        ${s.devices.map(d => `<tr><td>${E(d.icon)} ${E(d.name)} <span class="dim">${E(d.ip || '')}</span></td><td class="r">${E(d.pct)}</td><td class="r">${E(d.outages)}</td><td class="r">${E(d.longest_min)}</td></tr>`).join('')}</tbody></table></div></div>`;
    }
    return h;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error) { b.innerHTML = `<div class="card">${T('Δεν είναι διαθέσιμο σε αυτή τη λειτουργία (π.χ. ανάλυση pcap ή online demo).', 'Not available in this mode (e.g. pcap analysis or the online demo).')}</div>`; return; }
    const ws = D.watches || [], src = D.sources || {};
    let h = `<div class="card"><b style="font-size:16px">📅 ${T('«Μου κόβεται πού και πού»', '“It drops every now and then”')}</b>${D.demo ? ' <span class="dim">DEMO</span>' : ''}
      <div class="dim" style="font-size:12.5px;margin-top:5px;line-height:1.55">${T('Άφησε το NetWatch (ιδανικά το κουτί Raspberry Pi) στο δίκτυο του πελάτη για μερικές μέρες. Στο τέλος τυπώνεις αναφορά: πόσες φορές έπεσε η γραμμή, πότε, αν έφταιγε ο πάροχος ή το τοπικό δίκτυο, και ποιες ώρες είναι οι χειρότερες.',
        'Leave NetWatch (ideally the Raspberry Pi box) on the customer’s network for a few days. At the end you print a report: how often the line dropped, when, whether it was the ISP or the local network, and which hours are worst.')}</div>
      ${!src.latency ? `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${T('Η 📈 Καθυστέρηση είναι κλειστή — χωρίς αυτήν δεν υπάρχουν μετρήσεις γραμμής. Άνοιξέ τη στο config.yaml (latency: enabled: true).', 'The 📈 Latency monitor is off — without it there are no line measurements. Enable it in config.yaml (latency: enabled: true).')}</div>` : ''}
      <div class="sk-form"><input type="text" id="sk-name" maxlength="80" placeholder="${T('Όνομα, π.χ. Καφέ Στέκι — διακοπές το βράδυ', 'Name, e.g. Café — evening dropouts')}">
        <label class="dim">${T('μέρες', 'days')} <input type="number" id="sk-days" min="1" max="${D.max_days}" value="7"></label>
        <label class="dim" title="${T('Συμπερίλαβε και μετρήσεις που υπάρχουν ήδη πριν από σήμερα', 'Also include measurements already recorded before today')}">${T('+ προηγούμενες', '+ previous')} <input type="number" id="sk-back" min="0" max="${D.max_days}" value="0"></label>
        <button class="b" data-sk="start">▶ ${T('Ξεκίνα παρακολούθηση', 'Start watching')}</button></div>
      ${msg ? `<div style="color:var(--orange);font-size:13px;margin-top:8px">${E(msg)}</div>` : ''}</div>`;
    if (ws.length) {
      h += `<div class="card"><b>${T('Παρακολουθήσεις', 'Watches')}</b>${ws.map(w => `<div class="sk-row">
        <div style="flex:1;min-width:200px"><b>${w.running ? '🟢' : '⚪'} ${E(w.name)}</b>
          <div class="dim" style="font-size:12px">${when(w.span[0])} → ${when(w.span[1])}${w.running ? ' · ' + T('λήγει', 'ends') + ' ' + when(w.until) : ''}</div>
          ${w.running ? `<div class="sk-prog"><i style="width:${Math.round(100 * w.progress)}%"></i></div>` : ''}
          ${w.note ? `<div class="dim" style="font-size:12px;margin-top:3px">${E(w.note)}</div>` : ''}</div>
        <button class="b" data-sk="show" data-id="${E(w.id)}">${T('Δες', 'View')}</button>
        <a class="b" target="_blank" rel="noopener" href="/api/kit/soak/report?id=${encodeURIComponent(w.id)}&lang=${EN() ? 'en' : 'el'}">🖨 ${T('Αναφορά', 'Report')}</a>
        ${w.running ? `<button class="b" data-sk="stop" data-id="${E(w.id)}">⏹ ${T('Τέλος', 'Stop')}</button>` : `<button class="b" data-sk="delete" data-id="${E(w.id)}">🗑</button>`}</div>`).join('')}</div>`;
    }
    if (D.summary) h += summary(D.summary);
    h += `<div class="card"><b>👉 ${T('Πώς το χρησιμοποιείς', 'How to use it')}</b><ol>
      <li>${T('Σύνδεσε το κουτί <b>με καλώδιο</b> δίπλα στο router του πελάτη (όχι Wi-Fi: θα μετράς το Wi-Fi, όχι τη γραμμή).', 'Connect the box <b>by cable</b> next to the customer’s router (not Wi-Fi: you would measure the Wi-Fi, not the line).')}</li>
      <li>${T('Πάτα «Ξεκίνα παρακολούθηση» και άφησέ το 3–7 μέρες. Αν έχεις ρυθμίσει 🛰 Απομακρυσμένη πρόσβαση, βλέπεις την πρόοδο από το γραφείο.', 'Press “Start watching” and leave it for 3–7 days. With 🛰 Remote access set up you can follow progress from the office.')}</li>
      <li>${T('Τύπωσε την αναφορά. Αν οι διακοπές είναι «γραμμή / πάροχος», τη δίνεις στον πελάτη για τη δήλωση βλάβης· αν είναι «τοπικό δίκτυο», ξέρεις πού να ψάξεις.', 'Print the report. If the outages say “line / ISP”, the customer attaches it to the fault report; if “local network”, you know where to look.')}</li></ol>
      <div class="dim" style="font-size:12px;margin-top:6px">${T('«Διακοπή» = κανένας δημόσιος server δεν απάντησε σε έναν ολόκληρο γύρο ping. Αν την ίδια ώρα το router απαντούσε, το πρόβλημα ήταν έξω από το κτίριο.', '“Outage” = no public server answered a whole ping round. If the router kept answering at that time, the problem was outside the building.')}</div></div>`;
    b.innerHTML = h;
  }

  function load() {
    return fetch('/api/kit/soak').then(r => r.json()).then(j => { D = j; draw(); }).catch(() => { D = { error: 'off' }; draw(); });
  }
  document.addEventListener('click', e => {
    const t = e.target.closest('#t-soak [data-sk]'); if (!t) return;
    const a = t.dataset.sk, id = t.dataset.id;
    msg = '';
    if (a === 'show') {
      return fetch('/api/kit/soak/summary?id=' + encodeURIComponent(id)).then(r => r.json()).then(j => { if (!j.error) { D.summary = j; draw(); } });
    }
    if (a === 'delete' && !confirm(T('Να σβηστεί αυτή η παρακολούθηση; (οι μετρήσεις μένουν)', 'Delete this watch? (the measurements stay)'))) return;
    const body = a === 'start' ? { name: box().querySelector('#sk-name').value, days: +box().querySelector('#sk-days').value || 7, back_days: +box().querySelector('#sk-back').value || 0 } : { id };
    t.disabled = true;
    post(a, body).then(j => { if (j.error) { msg = j.error; draw(); } else { D = j; if (j.note === 'demo') msg = T('Στο demo οι παρακολουθήσεις δεν αλλάζουν.', 'Watches cannot be changed in demo mode.'); draw(); } }).catch(() => { t.disabled = false; });
  });
  window.renderSoak = () => load();
})();
