// ───────────────────────── 🧐 «Γιατί χτύπησε;» + 🔕 σίγαση με λήξη + 📊 θόρυβος ─────────────────────────
// Συνδέεται με το alertHTML/renderAlerts του index.html μέσω window.ALWHY (buttons, panel, header, visible).
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const why = new Map();      // id → δεδομένα «γιατί» (ή 'loading')
  const openWhy = new Set(), openMute = new Set();
  let hyg = null, hygOpen = false, hideQuiet = false;
  try { hideQuiet = localStorage.getItem('nw-hide-quiet') === '1'; } catch (e) { /* */ }

  const css = document.createElement('style');
  css.textContent = `
.aw-box{margin-top:8px;padding:9px 11px;border-radius:8px;background:rgb(var(--w,255 255 255) / 4%);border-left:3px solid var(--cyan);font-size:12.5px;line-height:1.55;white-space:normal}
.aw-box h4{margin:8px 0 3px;font-size:12px;color:var(--cyan);text-transform:none;letter-spacing:0}
.aw-box h4:first-child{margin-top:0}
.aw-kv{display:grid;grid-template-columns:auto minmax(0,1fr);gap:2px 10px;font-size:12px}
.aw-kv b{color:var(--dim);font-weight:500}
.aw-th{font:12px ui-monospace,Menlo,Consolas,monospace;background:rgb(var(--w,255 255 255) / 6%);border-radius:5px;padding:1px 6px;margin:0 4px 3px 0;display:inline-block}
.aw-pat{display:inline-block;border-radius:999px;padding:1px 9px;font-weight:600;font-size:11.5px}
.aw-mute{margin-top:8px;padding:9px 11px;border-radius:8px;background:rgb(var(--w,255 255 255) / 4%);border-left:3px solid var(--yellow);font-size:12.5px;white-space:normal}
.aw-mute .row{display:flex;gap:6px;flex-wrap:wrap;margin:5px 0}
.aw-mute label{display:flex;gap:6px;align-items:center;cursor:pointer;margin:3px 0}
.aw-mute input[type=text]{flex:1;min-width:160px;background:var(--bg,#0b111c);border:1px solid var(--line,#24324a);border-radius:6px;color:var(--txt);padding:5px 8px;font:inherit}
.aw-mute .b.on{border-color:var(--yellow);color:var(--yellow)}
.aw-hdr{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
.aw-noise{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:6px}
.aw-noise td,.aw-noise th{padding:5px 6px;border-bottom:1px solid rgb(var(--w,255 255 255) / 6%);text-align:left;vertical-align:top;white-space:normal}
.aw-noise th{color:var(--dim);font-size:11px;font-weight:600;position:static;text-transform:none}
.aw-bar{height:6px;border-radius:3px;background:var(--orange);min-width:2px}
`;
  document.head.appendChild(css);

  const fmtAgo = t => { if (!t) return '—'; const s = Date.now() / 1000 - t; return s < 90 ? T('μόλις τώρα', 'just now') : s < 5400 ? Math.round(s / 60) + T('′ πριν', 'm ago') : s < 129600 ? Math.round(s / 3600) + T(' ώρ. πριν', 'h ago') : Math.round(s / 86400) + T(' μέρες πριν', 'd ago'); };
  const nDev = n => n + ' ' + (n === 1 ? T('συσκευή', 'device') : T('συσκευές', 'devices'));
  const fmtUntil = u => u ? new Date(u * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : T('για πάντα', 'forever');
  const rerender = () => { if (typeof renderTab === 'function') renderTab(); };
  const post = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }).then(r => r.json());
  const thTxt = (k, v) => {
    if (v && typeof v === 'object') return Object.entries(v).map(([a, b]) => `<span class="aw-th">${E(k)}.${E(a)} = ${E(b)}</span>`).join('');
    return `<span class="aw-th">${E(k)} = ${E(v)}</span>`;
  };
  function dev(d) {
    if (!d) return '—';
    if (d.label != null) return E(d.label);
    if (!d.known) return `${E(d.ip)} <span class="dim">· ${T('άγνωστη στο NetWatch', 'unknown to NetWatch')}</span>`;
    const bits = [];
    if (d.me) bits.push(T('ΕΣΥ (αυτός ο υπολογιστής)', 'YOU (this computer)'));
    if (d.gw) bits.push('router');
    if (d.vendor) bits.push(E(d.vendor));
    if (d.mac) bits.push(`<code>${E(d.mac)}</code>`);
    if (d.random_mac) bits.push(T('τυχαία MAC (κινητό/laptop με private address)', 'random MAC (phone/laptop with private address)'));
    if (d.geo && d.geo.country) bits.push(E([d.geo.country, d.geo.isp].filter(Boolean).join(' · ')));
    if (d.first) bits.push(T('πρώτη φορά', 'first seen') + ' ' + fmtAgo(d.first));
    let s = `${E(d.icon || '')} <b>${E(d.name || d.ip)}</b> ${d.name ? `<span class="dim">${E(d.ip)}</span>` : ''}${bits.length ? '<div class="dim" style="font-size:11.5px">' + bits.join(' · ') + '</div>' : ''}`;
    if (d.intel && d.intel.length) s += `<div style="color:var(--red);font-size:11.5px">⚠ ${T('σε λίστα κακόβουλων', 'on threat lists')}: ${E(d.intel.map(x => x.feed || x.name || x).join(', '))}</div>`;
    return s;
  }

  function whyHTML(id) {
    const w = why.get(id);
    if (w === 'loading') return `<div class="aw-box">⏳ ${T('Συγκεντρώνω τα στοιχεία…', 'Gathering the evidence…')}</div>`;
    if (!w) return '';
    if (w.error) return `<div class="aw-box" style="border-left-color:var(--red)">✖ ${E(w.error)}</div>`;
    const f = w.freq || {};
    const pat = w.pattern === 'first' ? ['var(--red)', T('ΠΡΩΤΗ ΦΟΡΑ', 'FIRST TIME'), T('Δεν το έχουμε ξαναδεί από αυτή τη συσκευή — αξίζει έλεγχο.', 'Never seen from this device before — worth checking.')]
      : w.pattern === 'constant' ? ['var(--green)', T('ΣΥΝΕΧΕΣ', 'CONSTANT'), T('Συμβαίνει συνέχεια — πιθανότατα κανονική συμπεριφορά της συσκευής. Αν το αναγνωρίζεις, σίγασέ το.', 'Happens all the time — most likely normal for this device. If you recognise it, mute it.')]
        : ['var(--yellow)', T('ΕΠΑΝΑΛΑΜΒΑΝΕΤΑΙ', 'REPEATS'), T('Έχει ξαναγίνει μερικές φορές — δες αν ταιριάζει με κάτι που κάνεις.', 'Has happened a few times — see if it matches something you do.')];
    let h = `<div class="aw-box" data-noi18n>`;
    if (w.benign || w.maint || w.selftest) h += `<div style="margin-bottom:6px">🟢 ${E(w.benign || (w.maint ? T('Παράθυρο συντήρησης', 'Maintenance window') + ': ' + w.maint : w.selftest))}</div>`;
    h += `<h4>🧠 ${T('Πώς το κατάλαβα', 'How I detected it')}</h4><div>${E(EN() ? w.how.en : w.how.el)}</div>`;
    if (w.rule) h += `<div style="margin-top:4px">🧩 ${T('Κανόνας', 'Rule')} <code>${E(w.rule.id)}</code>${w.rule.description ? ' — ' + E(w.rule.description) : ''}${w.rule.match ? `<div><code style="white-space:pre-wrap">${E(JSON.stringify(w.rule.match))}</code></div>` : ''}${w.rule.threshold ? `<div>${thTxt('threshold', w.rule.threshold)}</div>` : ''}</div>`;
    const ths = Object.entries(w.thresholds || {});
    h += `<h4>📏 ${T('Όρια που ξεπεράστηκαν (από το config.yaml)', 'Thresholds crossed (from config.yaml)')}</h4><div>${ths.length ? ths.map(([k, v]) => thTxt(k, v)).join('') : '<span class="dim">' + T('Δεν βασίζεται σε αριθμητικό όριο — χτυπά σε κάθε εμφάνιση.', 'Not based on a numeric threshold — fires on every occurrence.') + '</span>'}${thTxt('alert_cooldown', w.cooldown + 's')}</div>`;
    if (w.detail) h += `<div class="dim" style="margin-top:2px">${T('Τι μετρήθηκε', 'What was measured')}: ${E(w.detail)}</div>`;
    h += `<h4>🔁 ${T('Πόσο συχνά', 'How often')}</h4><div><span class="aw-pat" style="background:color-mix(in srgb,${pat[0]} 18%,transparent);color:${pat[0]}">${pat[1]}</span> ${pat[2]}</div>
      <div class="aw-kv" style="margin-top:4px"><b>${T('Ίδιο, ίδια συσκευή', 'Same, same device')}</b><span>${f.same_24h} ${T('σε 24ώ', 'in 24h')} · ${f.same_7d} ${T('σε 7 μέρες', 'in 7 days')}${f.first_ever ? ' · ' + T('πρώτη φορά', 'first') + ' ' + fmtAgo(f.first_ever) : ''}</span>
      <b>${T('Αυτός ο τύπος γενικά', 'This type overall')}</b><span>${f.type_7d} ${T('σε 7 μέρες από', 'in 7 days from')} ${nDev(f.type_actors_7d)}</span></div>`;
    h += `<h4>🖥 ${T('Ποιοι', 'Who')}</h4><div class="aw-kv"><b>${T('Από', 'From')}</b><span>${dev(w.actor)}</span><b>${T('Προς', 'To')}</b><span>${dev(w.target)}</span></div>`;
    if (w.related && w.related.length) h += `<h4>🕒 ${T('Γύρω στην ίδια ώρα (±15′)', 'Around the same time (±15′)')}</h4><div>${w.related.map(r => `<div><span class="sev ${E(r.sev)}" style="font-size:10px">${E(r.sev.toUpperCase())}</span> ${E(r.type)} <span class="dim">· ${fmtAgo(r.t)}</span></div>`).join('')}</div>`;
    h += `<h4>🟢 ${T('Συνηθισμένες αθώες εξηγήσεις', 'Common innocent explanations')}</h4><div>${E(EN() ? w.fp.en : w.fp.el)}</div>`;
    if (w.mutes && w.mutes.length) h += `<div style="margin-top:6px">🔕 ${T('Ενεργή σίγαση έως', 'Muted until')} ${fmtUntil(w.mutes[0].until)}</div>`;
    if (w.detector_on === false) h += `<div style="margin-top:6px;color:var(--yellow)">${T('Ο ανιχνευτής είναι απενεργοποιημένος στο config.', 'This detector is disabled in config.')}</div>`;
    return h + `</div>`;
  }

  function muteHTML(a) {
    const sc = muteScope.get(a.id) || 'pair', dur = muteDur.get(a.id) || 1440;
    const local = (a.actor || '').match(/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/);
    return `<div class="aw-mute" data-noi18n data-mutebox="${a.id}">
      <b>🔕 ${T('Σίγαση — θα φαίνεται αχνά ως «αναμενόμενο», χωρίς ειδοποίηση και χωρίς υπόθεση', 'Mute — will show faded as “expected”, with no notification and no case')}</b>
      <label><input type="radio" name="aws${a.id}" value="pair"${sc === 'pair' ? ' checked' : ''}> ${T('Αυτό το είδος από', 'This kind from')} <b>${E(a.actor)}</b> (${T('προτείνεται', 'recommended')})</label>
      <label><input type="radio" name="aws${a.id}" value="type"${sc === 'type' ? ' checked' : ''}> ${T('Αυτό το είδος από ΟΛΕΣ τις συσκευές', 'This kind from ALL devices')}</label>
      <label><input type="radio" name="aws${a.id}" value="actor"${sc === 'actor' ? ' checked' : ''}> ${T('Οτιδήποτε από', 'Anything from')} <b>${E(a.actor)}</b>${local ? '' : ' <span class="dim">(' + T('εξωτερική IP — προσοχή', 'external IP — careful') + ')</span>'}</label>
      <div class="row">${[[60, T('1 ώρα', '1 hour')], [1440, T('24 ώρες', '24 hours')], [10080, T('7 μέρες', '7 days')], [0, T('για πάντα', 'forever')]].map(([m, l]) => `<button class="b${dur === m ? ' on' : ''}" data-awdur="${m}" data-aid="${a.id}">${l}</button>`).join('')}</div>
      <div class="row"><input type="text" maxlength="200" data-awnote="${a.id}" placeholder="${T('Γιατί; π.χ. «Fing στο κινητό μου»', 'Why? e.g. “Fing on my phone”')}" value="${E(muteNote.get(a.id) || '')}">
      <button class="b" data-awgo="${a.id}" style="border-color:var(--yellow);color:var(--yellow)">🔕 ${T('Σίγαση', 'Mute')}</button><button class="b" data-awcancel="${a.id}">${T('Άκυρο', 'Cancel')}</button></div>
      <div class="dim" data-awmsg="${a.id}" style="font-size:11.5px">${T('Οι σιγάσεις φαίνονται και αίρονται από το «🔕 Θόρυβος & σιγάσεις» στην κορυφή των ειδοποιήσεων.', 'Mutes are listed and removed under “🔕 Noise & mutes” at the top of the alerts.')}</div></div>`;
  }
  const muteScope = new Map(), muteDur = new Map(), muteNote = new Map();
  let typing = null;

  function headerHTML() {
    let h = `<div class="aw-hdr" data-noi18n><button class="b" data-awhyg>${hygOpen ? '▾' : '🔕'} ${T('Θόρυβος & σιγάσεις', 'Noise & mutes')}${hyg && hyg.mutes.length ? ` (${hyg.mutes.length})` : ''}</button>
      <label style="display:flex;gap:6px;align-items:center;font-size:12.5px;cursor:pointer"><input type="checkbox" data-awhide${hideQuiet ? ' checked' : ''}> ${T('Κρύψε τα σιγασμένα/αναμενόμενα', 'Hide muted/expected')}</label></div>`;
    if (!hygOpen) return h;
    if (!hyg) return h + `<div class="card">⏳</div>`;
    const n = hyg.noise, max = Math.max(1, ...n.types.map(x => x.count));
    h += `<div class="card" data-noi18n style="white-space:normal"><b>📊 ${T('Ποιες ειδοποιήσεις χτυπούν πιο συχνά (24 ώρες)', 'Which alerts fire most (24 hours)')}</b> <span class="dim">· ${n.total} ${T('συνολικά', 'total')}</span>
      <div class="dim" style="font-size:12px;margin-top:2px">${T('Αν ένας τύπος είναι πάνω από ~30% και τον αναγνωρίζεις (π.χ. η εφαρμογή σάρωσης στο κινητό σου), σίγασέ τον για αυτή τη συσκευή. Έτσι οι πραγματικές ειδοποιήσεις ξεχωρίζουν.', 'If one type is above ~30% and you recognise it (e.g. the scanner app on your phone), mute it for that device. Real alerts then stand out.')}</div>`;
    if (!n.types.length) h += `<div class="dim" style="padding:10px 0">${T('Καμία ειδοποίηση στις τελευταίες 24 ώρες. 🎉', 'No alerts in the last 24 hours. 🎉')}</div>`;
    else h += `<table class="aw-noise"><tr><th>${T('Τύπος', 'Type')}</th><th style="width:28%">${T('Πλήθος', 'Count')}</th><th>${T('Κυρίως από', 'Mostly from')}</th><th></th></tr>` +
      n.types.map((x, i) => `<tr><td><b>${E(x.type)}</b>${x.muted ? ' 🔕' : ''}</td><td><div style="display:flex;gap:6px;align-items:center"><div class="aw-bar" style="width:${Math.round(100 * x.count / max)}%"></div><span>${x.count} · ${x.share}%</span></div><span class="dim" style="font-size:11px">${nDev(x.actors)}</span></td>
        <td>${x.top.map(tp => `<div>${E(tp.name || tp.actor)} <span class="dim">${tp.name ? E(tp.actor) + ' · ' : ''}${tp.count}×</span></div>`).join('')}</td>
        <td style="white-space:nowrap"><button class="b" data-awtop="${i}" title="${T('Σίγαση 24ώ για την κύρια συσκευή', 'Mute 24h for the main device')}">🔕 ${T('κύρια, 24ώ', 'top, 24h')}</button></td></tr>`).join('') + `</table>`;
    h += `</div><div class="card" data-noi18n style="white-space:normal"><b>🔕 ${T('Ενεργές σιγάσεις', 'Active mutes')}</b>`;
    if (!hyg.mutes.length) h += `<div class="dim" style="padding:6px 0">${T('Καμία. Σίγαση βάζεις από το κουμπί «🔕 Σίγαση» κάθε ειδοποίησης.', 'None. Add one with the “🔕 Mute” button on any alert.')}</div>`;
    else h += hyg.mutes.map(m => `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:5px 0;border-top:1px solid rgb(var(--w,255 255 255) / 6%)">
        <span style="flex:1;min-width:200px">${m.type ? '<b>' + E(m.type) + '</b>' : T('<b>Οτιδήποτε</b>', '<b>Anything</b>')} ${m.actor ? T('από', 'from') + ' <b>' + E(m.name || m.actor) + '</b> <span class="dim">' + (m.name ? E(m.actor) : '') + '</span>' : T('από όλες τις συσκευές', 'from all devices')}${m.note ? `<div class="dim" style="font-size:11.5px">“${E(m.note)}”</div>` : ''}</span>
        <span class="dim" style="font-size:12px">${T('έως', 'until')} ${fmtUntil(m.until)}</span><button class="b" data-awun="${m.id}">${T('Άρση', 'Remove')}</button></div>`).join('');
    return h + `</div>`;
  }

  function loadHyg() { return fetch('/api/alerts/hygiene').then(r => r.json()).then(j => { if (!j.error) { hyg = j; rerender(); } }).catch(() => { }); }
  function loadWhy(id) {
    why.set(id, 'loading'); rerender();
    fetch('/api/alerts/why?id=' + id).then(r => r.json()).then(j => { why.set(id, j); rerender(); })
      .catch(() => { why.set(id, { error: T('Δεν απάντησε το NetWatch.', 'NetWatch did not answer.') }); rerender(); });
  }
  function doMute(a) {
    const sc = muteScope.get(a.id) || 'pair', dur = muteDur.has(a.id) ? muteDur.get(a.id) : 1440;
    const body = { type: sc === 'actor' ? null : a.type, actor: sc === 'type' ? null : a.actor, minutes: dur, note: muteNote.get(a.id) || null };
    post('/api/alerts/mute', body).then(j => {
      const msg = document.querySelector(`[data-awmsg="${a.id}"]`);
      if (j.error) { if (msg) { msg.style.color = 'var(--red)'; msg.textContent = '✖ ' + j.error; } return; }
      openMute.delete(a.id); typing = null; a.benign = a.benign || '🔕 ' + T('Σίγαση', 'Muted');
      why.delete(a.id); loadHyg(); rerender();
    });
  }
  const findAlert = id => ((typeof S !== 'undefined' && S.alerts) || []).find(x => x.id === id);

  document.addEventListener('click', e => {
    const t = e.target.closest('[data-awwhy],[data-awmute],[data-awdur],[data-awgo],[data-awcancel],[data-awhyg],[data-awun],[data-awtop]');
    if (!t) return;
    e.stopPropagation();
    if (t.dataset.awwhy) { const id = +t.dataset.awwhy; if (openWhy.has(id)) { openWhy.delete(id); rerender(); } else { openWhy.add(id); if (!why.has(id) || (why.get(id) || {}).error) loadWhy(id); else rerender(); } return; }
    if (t.dataset.awmute) { const id = +t.dataset.awmute; openMute.has(id) ? openMute.delete(id) : openMute.add(id); rerender(); return; }
    if (t.dataset.awdur) { muteDur.set(+t.dataset.aid, +t.dataset.awdur); rerender(); return; }
    if (t.dataset.awcancel) { openMute.delete(+t.dataset.awcancel); typing = null; rerender(); return; }
    if (t.dataset.awgo) { const a = findAlert(+t.dataset.awgo); if (a) doMute(a); return; }
    if (t.hasAttribute('data-awhyg')) { hygOpen = !hygOpen; if (hygOpen) loadHyg(); rerender(); return; }
    if (t.dataset.awun) { post('/api/alerts/unmute', { id: +t.dataset.awun }).then(() => loadHyg()); return; }
    if (t.dataset.awtop != null && hyg) {
      const x = hyg.noise.types[+t.dataset.awtop], tp = x && x.top[0]; if (!tp) return;
      post('/api/alerts/mute', { type: x.type, actor: tp.actor, minutes: 1440, note: T('από τον πίνακα θορύβου', 'from the noise table') }).then(() => loadHyg());
    }
  }, true);
  document.addEventListener('change', e => {
    const r = e.target;
    if (r.matches('[data-mutebox] input[type=radio]')) muteScope.set(+r.closest('[data-mutebox]').dataset.mutebox, r.value);
    if (r.matches('[data-awhide]')) { hideQuiet = r.checked; try { localStorage.setItem('nw-hide-quiet', hideQuiet ? '1' : ''); } catch (er) { /* */ } rerender(); }
  });
  document.addEventListener('input', e => { if (e.target.matches('[data-awnote]')) { muteNote.set(+e.target.dataset.awnote, e.target.value); typing = e.target.dataset.awnote; } });
  // Η λίστα ξαναζωγραφίζεται με κάθε νέα ειδοποίηση· κρατάμε το focus/κέρσορα στη σημείωση σίγασης
  document.addEventListener('focusin', e => { if (e.target.matches('[data-awnote]')) typing = e.target.dataset.awnote; });
  document.addEventListener('focusout', e => { if (e.target.matches('[data-awnote]')) setTimeout(() => { if (!document.activeElement || !document.activeElement.matches('[data-awnote]')) typing = null; }, 0); });
  new MutationObserver(() => {
    if (!typing) return;
    const el = document.querySelector(`[data-awnote="${typing}"]`);
    if (el && document.activeElement !== el) { const n = el.value.length; el.focus(); try { el.setSelectionRange(n, n); } catch (er) { /* */ } }
  }).observe(document.documentElement, { childList: true, subtree: true });

  window.ALWHY = {
    buttons: a => a.lab ? '' : `<button class="b" data-awwhy="${a.id}" data-noi18n>${openWhy.has(a.id) ? '▾' : '🧐'} ${T('Γιατί;', 'Why?')}</button>` +
      (a.selftest ? '' : `<button class="b" data-awmute="${a.id}" data-noi18n>🔕 ${T('Σίγαση', 'Mute')}</button>`),
    panel: a => (openWhy.has(a.id) ? whyHTML(a.id) : '') + (openMute.has(a.id) ? muteHTML(a) : ''),
    header: () => headerHTML(),
    visible: a => !(hideQuiet && (a.benign || a.selftest || a.maint)),
    _test: { whyHTML, muteHTML, headerHTML, set: (id, w) => why.set(id, w), open: id => openWhy.add(id), hyg: v => { hyg = v; hygOpen = true; } },
  };
})();
