// ───────────────────────── 🔌 Tester πρίζας / κουτί τεχνικού + 📶 εφεδρική γραμμή LTE ─────────────────────────
// Καρτέλα «sock» (το id «field» το έχει ήδη το 📱 Field mode). Backend: fieldbox.py (/api/kit/field) + uplink.py (/api/kit/uplink).
// Πρώτα για κινητό: τεράστιο συμπέρασμα, βήματα με ✓/✗ ζωντανά, «ετικέτα → Τεστ → Επόμενη πρίζα».
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const B = (o, k) => (EN() && o && o[k + '_en']) || (o && o[k]) || '';   // κείμενο από το backend: el / *_en
  const box = () => document.getElementById('t-sock');
  const COL = { ok: 'var(--green,#3ecf8e)', warn: 'var(--orange)', fail: 'var(--red)', skip: 'var(--dim)', pending: 'var(--dim)', running: 'var(--cyan)' };
  const ICO = { ok: '✓', warn: '!', fail: '✗', skip: '–', pending: '·', running: '…' };
  let D = null, poll = null, lbl = null, note = '', speed = false, showAll = false;

  const css = document.createElement('style');
  css.textContent = `
#t-sock .sk-verdict{font-size:clamp(22px,6.2vw,38px);font-weight:800;line-height:1.18;border-left:6px solid var(--c);padding:6px 0 6px 14px;word-break:break-word}
#t-sock .sk-fix{font-size:14px;margin-top:10px;line-height:1.5}
#t-sock .sk-go{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.4fr);gap:8px;margin-top:12px}
#t-sock .sk-go input[type=text]{font-size:20px;padding:12px;border-radius:10px;border:1px solid rgb(var(--w,255 255 255) / 18%);background:rgb(var(--w,255 255 255) / 5%);color:inherit;min-width:0;width:100%;box-sizing:border-box}
#t-sock .sk-btns{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}
#t-sock .sk-btns .b{font-size:18px;padding:16px 8px;font-weight:700}
#t-sock .sk-step{display:grid;grid-template-columns:28px minmax(0,1fr) auto;gap:2px 8px;padding:7px 0;border-top:1px solid rgb(var(--w,255 255 255) / 7%);font-size:13.5px;align-items:start}
#t-sock .sk-ico{width:24px;height:24px;border-radius:50%;display:grid;place-items:center;font-weight:800;color:var(--c);background:color-mix(in srgb,var(--c) 16%,transparent)}
#t-sock .sk-run{animation:skp 1s ease-in-out infinite}
@keyframes skp{50%{opacity:.35}}
#t-sock .sk-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(138px,1fr));gap:8px;margin-top:10px}
#t-sock .sk-fact{background:rgb(var(--w,255 255 255) / 4%);border-radius:10px;padding:8px 10px;min-width:0}
#t-sock .sk-fact b{display:block;font-size:17px;word-break:break-word}
#t-sock .sk-fact span{font-size:11.5px;color:var(--dim)}
#t-sock table{width:100%;border-collapse:collapse;font-size:13px}
#t-sock td,#t-sock th{padding:6px 6px;text-align:left;border-top:1px solid rgb(var(--w,255 255 255) / 7%);vertical-align:top}
#t-sock th{font-size:11.5px;color:var(--dim);font-weight:600;border-top:0}
#t-sock .sk-pill{font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap}
#t-sock .sk-set{display:flex;gap:10px 16px;flex-wrap:wrap;align-items:center;font-size:13px;margin-top:8px}
#t-sock .sk-set input[type=number],#t-sock .sk-set select{width:92px;padding:6px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 18%);background:rgb(var(--w,255 255 255) / 5%);color:inherit}
#t-sock .sk-up{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:4px 10px;align-items:center;padding:7px 0;border-top:1px solid rgb(var(--w,255 255 255) / 7%);font-size:13.5px}
#t-sock .sk-bar{height:8px;border-radius:5px;background:rgb(var(--w,255 255 255) / 9%);overflow:hidden;margin-top:4px}
#t-sock .sk-bar i{display:block;height:100%;background:var(--c)}
#t-sock ol{margin:6px 0 0 18px;padding:0;font-size:13px}#t-sock li{margin:3px 0}
#t-sock .sk-x{background:none;border:0;color:var(--dim);cursor:pointer;font-size:15px;padding:2px 6px}
@media (max-width:600px){#t-sock .sk-hide{display:none}#t-sock .sk-go{grid-template-columns:1fr}}
`;
  document.head.appendChild(css);

  const when = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : '—';
  const spd = m => !m ? '—' : m >= 1000 ? (m / 1000) + ' Gbps' : m + ' Mbps';
  const pill = (lv, txt) => `<span class="sk-pill" style="--c:${COL[lv] || 'var(--dim)'}">${E(txt)}</span>`;
  const LV = { ok: ['ΟΚ', 'OK'], warn: ['προσοχή', 'check'], fail: ['πρόβλημα', 'fail'] };

  function steps(list) {
    return (list || []).map(s => `<div class="sk-step"><span class="sk-ico${s.status === 'running' ? ' sk-run' : ''}" style="--c:${COL[s.status] || 'var(--dim)'}">${ICO[s.status] || '·'}</span>
      <div><b>${E(T(s.el, s.en) || s.id)}</b><div class="dim" style="font-size:12.5px;word-break:break-word">${E(B(s, 'detail'))}</div></div>
      <span class="dim" style="font-size:11.5px">${s.ms != null && s.status !== 'pending' && s.status !== 'skip' ? E(s.ms) + ' ms' : ''}</span></div>`).join('');
  }

  function facts(r) {
    const f = (k, v) => v ? `<div class="sk-fact"><span>${k}</span><b>${v}</b></div>` : '';
    const poe = r.poe === true ? 'PoE ' + (r.poe_w ? E(r.poe_w) + ' W' : T('ενεργό', 'on')) + (r.poe_class != null ? ` <span>class ${E(r.poe_class)}</span>` : '')
      : r.poe === false ? T('όχι', 'no') : '';
    return `<div class="sk-facts">
      ${f('Switch' + (r.proto ? ' · ' + E(r.proto) : ''), E(r.sw))}
      ${f(T('Θύρα', 'Port'), E(r.port))}
      ${f('VLAN', r.vlan ? E(r.vlan) + (r.vlan_name ? ` <span>${E(r.vlan_name)}</span>` : '') : '')}
      ${f(T('Ταχύτητα', 'Speed'), r.carrier ? E(spd(r.speed)) + (r.duplex ? ` <span>${E(r.duplex)}</span>` : '') : T('χωρίς link', 'no link'))}
      ${f('PoE', poe)}
      ${f('DHCP', r.dhcp_ms != null ? (r.dhcp_ms / 1000).toFixed(2) + ' s' : '')}
      ${f(T('IP που προσφέρθηκε', 'Offered IP'), r.ip ? E(r.ip) + (r.prefix ? '/' + E(r.prefix) : '') : '')}
      ${f('Gateway', E(r.gw))}
      ${f('DNS', E((r.dns || []).join(' ')))}
      ${f(T('IP διαχείρισης switch', 'Switch mgmt IP'), E(r.mgmt))}
      ${f('Voice VLAN', r.voice_vlan ? E(r.voice_vlan) : '')}
      ${f(T('VLAN με tag (trunk)', 'Tagged VLANs (trunk)'), E((r.tagged || []).join(', ')))}
      ${f(T('Λήψη', 'Download'), r.down_mbps ? E(r.down_mbps) + ' Mbps' : '')}
    </div>${(EN() ? r.hints_en : r.hints || []).length ? `<div class="dim" style="font-size:12.5px;margin-top:8px">ℹ ${(EN() ? r.hints_en : r.hints).map(E).join(' · ')}</div>` : ''}`;
  }

  function uplink(u) {
    if (!u) return '';
    const c = { ok: COL.ok, backup: COL.warn, cellular: COL.warn, down: COL.fail, unknown: COL.skip }[u.state] || COL.skip;
    const K = { wired: ['🔌', T('ενσύρματη', 'wired')], wifi: ['📡', 'Wi‑Fi'], cellular: ['📶', 'LTE / 4G'] };
    const R = { primary: T('κύρια', 'primary'), backup: T('εφεδρική', 'backup'), other: '' };
    const m = u.modem, d = u.data || {};
    let h = `<div class="card"><b>📶 Uplink / LTE</b>
      <div style="font-size:19px;font-weight:800;margin-top:8px;border-left:5px solid ${c};padding-left:10px">${E(T(u.el, u.en))}</div>
      ${u.on_backup ? `<div style="color:var(--orange);font-size:13px;margin-top:6px">💾 ${T('Οικονομία δεδομένων: τα βαριά downloads αναβάλλονται όσο δουλεύω από κινητή.', 'Data saver: heavy downloads are postponed while on mobile data.')}</div>` : ''}`;
    h += (u.uplinks || []).map(x => `<div class="sk-up"><span style="font-size:20px">${(K[x.kind] || ['❔'])[0]}</span>
      <div><b>${E(x.dev)}</b> <span class="dim">${E((K[x.kind] || ['', x.kind])[1])}${R[x.role] ? ' · ' + R[x.role] : ''} · gw ${E(x.gw || '—')} · metric ${E(x.metric)}</span>
        ${x.label ? `<div class="dim" style="font-size:12px">${E(B(x, 'label'))}</div>` : ''}</div>
      ${x.ok == null ? pill('skip', '—') : x.ok ? pill('ok', 'Internet ✓' + (x.ms != null ? ' ' + Math.round(x.ms) + ' ms' : '')) : pill('fail', T('δεν βγαίνει', 'no Internet'))}</div>`).join('');
    if (!(u.uplinks || []).length && !u.demo) h += `<div class="dim" style="font-size:13px;margin-top:8px">${u.checked ? T('Δεν βρέθηκε default route.', 'No default route found.') : T('Ο πρώτος έλεγχος γίνεται ~20 s μετά την εκκίνηση.', 'The first check runs ~20 s after start.')}</div>`;
    if (m) h += `<div class="dim" style="font-size:13px;margin-top:8px">📡 <b style="color:inherit">${E(m.operator || '?')}</b> · ${E(m.tech || '')}${m.signal != null ? ' · ' + T('σήμα', 'signal') + ' ' + E(m.signal) + '%' : ''}${m.rsrp ? ' · RSRP ' + E(m.rsrp) : ''}${m.model ? ' · ' + E(m.model) : ''} <span>(${E(m.source || '')})</span></div>`;
    if (u.has_backup || d.bytes) {
      h += `<div style="font-size:13px;margin-top:8px">${T('Δεδομένα κινητής αυτόν τον μήνα (εκτίμηση)', 'Mobile data this month (estimate)')}: <b>${E(d.text || '0')}</b>${d.cap_gb ? ' / ' + E(d.cap_gb) + ' GB' : ''}
        ${d.pct != null ? `<div class="sk-bar" style="--c:${d.pct > 80 ? COL.fail : d.pct > 50 ? COL.warn : COL.ok}"><i style="width:${Math.min(100, Math.max(0, Number(d.pct) || 0))}%"></i></div>` : ''}</div>`;
    }
    h += `<div style="font-size:13px;margin-top:10px">👉 ${E(B(u, 'hint'))}</div>`;
    if ((u.events || []).length) {
      h += `<details style="margin-top:8px"${u.demo ? ' open' : ''}><summary class="dim" style="font-size:12.5px;cursor:pointer">${T('Ιστορικό αλλαγών γραμμής', 'Line change history')} (${u.events.length})</summary>
        ${u.events.slice(0, 12).map(e => `<div style="font-size:12.5px;margin-top:5px"><span class="dim">${when(e.t)}</span> ${pill(e.sev === 'high' ? 'fail' : e.sev === 'med' ? 'warn' : 'ok', e.sev === 'high' ? '▼' : e.sev === 'med' ? '!' : '▲')} ${E(T(e.el, e.en))}</div>`).join('')}</details>`;
    }
    h += `<div style="margin-top:10px"><button class="b" data-sk="upcheck"${u.demo || u.busy ? ' disabled' : ''}>🔄 ${T('Έλεγχος γραμμών τώρα', 'Check lines now')}</button>
      <span class="dim" style="font-size:12px;margin-left:8px">${u.demo ? 'demo' : T('τελευταίος', 'last') + ' ' + when(u.checked)}</span></div></div>`;
    return h;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error === 'off') {
      b.innerHTML = `<div class="card"><b>🔌 ${T('Tester πρίζας', 'Socket tester')}</b><div class="dim" style="margin-top:6px">${T('Δεν είναι διαθέσιμο σε αυτή τη λειτουργία (π.χ. online demo ή ανάλυση pcap). Τρέξε το NetWatch τοπικά: <code>./run.sh --demo</code>.', 'Not available in this mode (e.g. the online demo or pcap analysis). Run NetWatch locally: <code>./run.sh --demo</code>.')}</div></div>`;
      return;
    }
    const run = D.run, last = D.last, s = D.settings || {};
    const cur = lbl == null ? (D.next_label || 'A-01') : lbl;
    let h = '<div class="card">';
    if (run) {
      h += `<div class="sk-verdict" style="--c:${COL.running}">⏳ ${T('Τεστ', 'Testing')} ${E(run.label)}… <span class="dim" style="font-size:.6em">${Math.round(run.elapsed || 0)} s</span></div>
        <div class="sk-fix dim">${run.nbr ? '🔎 ' + E(run.nbr.name || run.nbr.chassis || '') + ' · ' + E(run.nbr.port_desc && run.nbr.port_sub === 3 ? run.nbr.port_desc : run.nbr.port || '') + (run.nbr.pvid ? ' · VLAN ' + E(run.nbr.pvid) : '')
          : T(`Ακούω για LLDP/CDP (έως ${Math.round(D.listen_s || 35)} s — τα switch το στέλνουν κάθε 30 s)…`, `Listening for LLDP/CDP (up to ${Math.round(D.listen_s || 35)} s — switches send it every 30 s)…`)}</div>`;
    } else if (last) {
      h += `<div class="dim" style="font-size:12.5px;margin-bottom:6px">${T('Πρίζα', 'Socket')} <b style="color:inherit;font-size:15px">${E(last.label)}</b>${last.note ? ' · ' + E(last.note) : ''} · ${when(last.t)}</div>
        <div class="sk-verdict" style="--c:${COL[last.level] || COL.skip}">${E(B(last, 'verdict'))}</div>
        ${B(last, 'fix') ? `<div class="sk-fix">👉 ${E(B(last, 'fix'))}</div>` : ''}`;
    } else {
      h += `<div class="sk-verdict" style="--c:var(--cyan)">🔌 ${T('Βάλε το καλώδιο στην πρίζα και πάτα «Τεστ»', 'Plug the cable into the socket and press “Test”')}</div>
        <div class="sk-fix dim">${T('Σε ~30 δευτερόλεπτα: σε ποιο switch και θύρα καταλήγει, VLAN, ταχύτητα, PoE, DHCP, Internet.', 'In ~30 seconds: which switch and port it lands on, VLAN, speed, PoE, DHCP, Internet.')}</div>`;
    }
    if (D.error) h += `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${E(B(D, 'error'))}</div>`;
    const dis = D.busy ? ' disabled' : '';
    h += `<div class="sk-go"><input type="text" data-sk-in="label" maxlength="40" value="${E(cur)}" placeholder="${T('Ετικέτα πρίζας (π.χ. A-01)', 'Socket label (e.g. A-01)')}" aria-label="${T('Ετικέτα πρίζας', 'Socket label')}"${dis}>
        <input type="text" data-sk-in="note" maxlength="200" value="${E(note)}" placeholder="${T('Σημείωση (π.χ. Γραφείο 2, δίπλα στο παράθυρο)', 'Note (e.g. Office 2, by the window)')}" style="font-size:15px"${dis}></div>
      <div class="sk-btns"><button class="b" data-sk="test"${dis}>▶ ${D.busy ? T('τρέχει…', 'running…') : T('Τεστ', 'Test')}</button>
        <button class="b" data-sk="next"${dis || (last ? '' : ' disabled')}>⏭ ${T('Επόμενη πρίζα', 'Next socket')}${last && !D.busy ? ' (' + E(D.next_label) + ')' : ''}</button></div>
      <label class="dim" style="display:flex;gap:6px;align-items:center;font-size:12.5px;margin-top:8px"><input type="checkbox" data-sk-in="speed"${speed ? ' checked' : ''}${dis}> ${T('και σύντομο τεστ ταχύτητας (5 MB από Cloudflare)', 'also a quick throughput test (5 MB from Cloudflare)')}</label>
      <div class="dim" style="font-size:12px;margin-top:6px">${T('Διεπαφή', 'Interface')}: <code>${E(D.iface || '—')}</code>${D.demo ? ' · 🧪 demo: ' + T('προσομοίωση, δεν αγγίζω το δίκτυο', 'simulated, the network is not touched') : ''}</div></div>`;

    const st = run ? run.steps : last ? last.steps : null;
    if (st && st.length) h += `<div class="card"><b>${run ? T('Βήματα (ζωντανά)', 'Steps (live)') : T('Βήματα τελευταίου τεστ', 'Steps of the last test')}</b>${steps(st.map(x => Object.assign({ el: (TITLES[x.id] || [x.id])[0], en: (TITLES[x.id] || [0, x.id])[1] }, x)))}
      ${!run && last ? facts(last) : ''}</div>`;

    h += `<div class="card"><b>🎯 ${T('Τι περιμένω σε αυτές τις πρίζες', 'What these sockets should have')}</b>
      <div class="dim" style="font-size:12.5px;margin-top:4px">${T('Αν τα συμπληρώσεις, κάθε πρίζα με άλλο VLAN, χωρίς PoE ή πιο αργή βγαίνει πορτοκαλί.', 'If you fill these in, any socket with another VLAN, no PoE or a slower link turns orange.')}</div>
      <div class="sk-set"><label>VLAN <input type="number" min="1" max="4094" data-sk-set="vlan" value="${E(s.vlan || '')}"></label>
        <label><input type="checkbox" data-sk-set="poe"${s.poe ? ' checked' : ''}> PoE</label>
        <label>${T('Ταχύτητα', 'Speed')} <select data-sk-set="speed">${[['', '—'], [100, '100 Mbps'], [1000, '1 Gbps'], [2500, '2.5 Gbps'], [10000, '10 Gbps']].map(o => `<option value="${o[0]}"${String(s.speed || '') === String(o[0]) ? ' selected' : ''}>${o[1]}</option>`).join('')}</select></label>
        <button class="b" data-sk="save"${D.demo ? ' disabled' : ''}>${T('Αποθήκευση', 'Save')}</button></div></div>`;

    const hist = D.history || [], c = D.counts || {};
    if (hist.length) {
      const rows = showAll ? hist : hist.slice(0, 12);
      h += `<div class="card"><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><b style="flex:1;min-width:180px">📋 ${T('Πρίζες που δοκιμάστηκαν', 'Tested sockets')} (${E(D.count)})</b>
        ${pill('ok', (c.ok || 0) + ' ✓')} ${c.warn ? pill('warn', c.warn + ' !') : ''} ${c.fail ? pill('fail', c.fail + ' ✗') : ''}
        <a class="b" href="/api/kit/field/csv" download="netwatch-sockets.csv">⬇ CSV</a></div>
        <div style="overflow-x:auto;margin-top:6px"><table><tr><th>${T('Πρίζα', 'Socket')}</th><th></th><th>Switch · ${T('θύρα', 'port')}</th><th>VLAN</th><th>${T('Ταχ.', 'Speed')}</th><th>PoE</th><th class="sk-hide">DHCP</th><th class="sk-hide">${T('Ώρα', 'Time')}</th><th></th></tr>
        ${rows.map(r => `<tr title="${E(B(r, 'verdict'))}"><td><b>${E(r.label)}</b>${r.note ? `<div class="dim" style="font-size:11.5px">${E(r.note)}</div>` : ''}</td>
          <td>${pill(r.level, T(...(LV[r.level] || ['?', '?'])))}</td>
          <td>${E(r.sw || '—')}${r.port ? ' · ' + E(r.port) : ''}${r.level !== 'ok' ? `<div style="font-size:11.5px;color:${COL[r.level]}">${E(B(r, 'verdict').replace(/ — .*/, ''))}</div>` : ''}</td>
          <td>${E(r.vlan || '—')}</td><td>${r.carrier ? E(spd(r.speed)) : '✗'}</td>
          <td>${r.poe === true ? (r.poe_w ? E(r.poe_w) + ' W' : '✓') : r.poe === false ? '✗' : '—'}</td>
          <td class="sk-hide">${r.dhcp_ms != null ? (r.dhcp_ms / 1000).toFixed(1) + ' s' : '—'}</td><td class="sk-hide dim">${when(r.t)}</td>
          <td><button class="sk-x" data-sk="del" data-id="${E(r.id)}" title="${T('Διαγραφή', 'Delete')}" aria-label="${T('Διαγραφή', 'Delete')}"${D.demo ? ' disabled' : ''}>🗑</button></td></tr>`).join('')}</table></div>
        ${hist.length > 12 ? `<button class="b" data-sk="all" style="margin-top:8px">${showAll ? T('Λιγότερες', 'Fewer') : T(`Όλες (${hist.length})`, `All (${hist.length})`)}</button>` : ''}
        <div class="dim" style="font-size:12px;margin-top:8px">${T('Τα αποτελέσματα μπαίνουν αυτόματα στο πρωτόκολλο παράδοσης (καρτέλα παράδοσης) με βάση την ετικέτα.', 'Results feed the acceptance report (acceptance tab) by label.')}</div></div>`;
    }
    h += uplink(D.uplink);
    h += `<div class="card"><b>👉 ${T('Τι να κάνεις', 'What to do')}</b><ol>
      <li>${T('Γράψε την ετικέτα της πρώτης πρίζας (όπως στο patch panel, π.χ. <b>A-01</b>), βάλε το καλώδιο και πάτα <b>Τεστ</b>. Για την επόμενη απλώς άλλαξε πρίζα και πάτα <b>Επόμενη πρίζα</b> — η ετικέτα ανεβαίνει μόνη της.', 'Type the first socket’s label (as on the patch panel, e.g. <b>A-01</b>), plug in and press <b>Test</b>. For the next one just move the cable and press <b>Next socket</b> — the label increments itself.')}</li>
      <li>${T('<b>Μόνο 100 Mbps</b> σε gigabit switch = ένα από τα 4 ζεύγη δεν κάνει επαφή. Ξανατερμάτισε την πρίζα ή το patch panel (T568B) πριν κλείσεις το ψευδοτάβανο.', '<b>Only 100 Mbps</b> on a gigabit switch = one of the 4 pairs has no contact. Re-terminate the socket or patch panel (T568B) before the ceiling is closed.')}</li>
      <li>${T('<b>Δεν βλέπω switch/θύρα;</b> Το switch είναι unmanaged ή έχει κλειστό LLDP. Σε Cisco: <code>lldp run</code> (ή CDP, ανοιχτό από προεπιλογή). Το PoE και το VLAN τα μαθαίνω μόνο από αυτά που διαφημίζει το switch.', '<b>No switch/port shown?</b> The switch is unmanaged or has LLDP off. On Cisco: <code>lldp run</code> (or CDP, on by default). PoE and VLAN are known only from what the switch advertises.')}</li>
      <li>${T('<b>Link ΟΚ αλλά όχι DHCP</b> = σχεδόν πάντα λάθος VLAN στη θύρα. Με το όνομα switch/θύρας από πάνω το διορθώνεις χωρίς να ψάχνεις καλώδια.', '<b>Link OK but no DHCP</b> = almost always the wrong VLAN on the port. With the switch/port name above you fix it without tracing cables.')}</li>
      <li>${T('Στο τέλος κατέβασε το <b>CSV</b> ή φτιάξε το πρωτόκολλο παράδοσης και τύπωσε ετικέτες για τις πρίζες.', 'When done download the <b>CSV</b> or build the acceptance report and print labels for the sockets.')}</li></ol>
      <div class="dim" style="font-size:12px;margin-top:6px">${T('Μόνο ανάγνωση: ακούω LLDP/CDP, στέλνω ένα DHCPDISCOVER (ποτέ REQUEST) και pings. Οδηγός για το κουτί (Raspberry Pi + οθόνη OLED + LTE): <code>tools/fieldbox/README.md</code>', 'Read-only: I listen for LLDP/CDP, send one DHCPDISCOVER (never a REQUEST) and pings. Guide for the box (Raspberry Pi + OLED + LTE): <code>tools/fieldbox/README.md</code>')}</div></div>`;
    b.innerHTML = h;
  }
  const TITLES = { link: ['Καλώδιο / link', 'Cable / link'], nbr: ['Switch & θύρα (LLDP/CDP)', 'Switch & port (LLDP/CDP)'], dhcp: ['DHCP', 'DHCP'], gateway: ['Router (gateway)', 'Router (gateway)'], dns: ['DNS', 'DNS'], internet: ['Internet', 'Internet'], captive: ['Captive portal', 'Captive portal'], mtu: ['MTU 1500', 'MTU 1500'], speed: ['Ταχύτητα (σύντομο τεστ)', 'Throughput (quick test)'] };

  function got(j) {
    const was = D && D.busy;
    D = j && typeof j === 'object' ? j : { error: 'off' };
    if (was && !D.busy && D.error !== 'off') { lbl = null; note = ''; }      // τελείωσε → έτοιμη η επόμενη ετικέτα
    draw();
    if (D.busy && !poll) poll = setInterval(load, 1000);
    if (!D.busy && poll) { clearInterval(poll); poll = null; }
  }
  function load() {
    return fetch('/api/kit/field').then(r => r.json()).then(got).catch(() => { if (!D || !D.busy) { D = { error: 'off' }; draw(); } });
  }
  const post = (sub, body) => fetch('/api/kit/' + sub, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then(r => r.json());
  function start(label) {
    post('field/test', { label: label, note: note, lang: EN() ? 'en' : 'el', speed: speed }).then(got).catch(() => load());
  }

  document.addEventListener('input', e => {
    const i = e.target.closest && e.target.closest('#t-sock [data-sk-in]'); if (!i) return;
    const k = i.getAttribute('data-sk-in');
    if (k === 'label') lbl = i.value; else if (k === 'note') note = i.value; else if (k === 'speed') speed = i.checked;
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' || !e.target.closest || !e.target.closest('#t-sock [data-sk-in]') || !D || D.busy) return;
    start(lbl == null ? D.next_label : lbl);
  });
  document.addEventListener('click', e => {
    const b = e.target.closest && e.target.closest('#t-sock [data-sk]'); if (!b || !D) return;
    const a = b.getAttribute('data-sk');
    if (a === 'test') { b.disabled = true; start(lbl == null ? D.next_label : lbl); }
    else if (a === 'next') { b.disabled = true; lbl = null; note = ''; start(D.next_label); }
    else if (a === 'all') { showAll = !showAll; draw(); }
    else if (a === 'save') {
      const q = k => box().querySelector(`[data-sk-set="${k}"]`);
      post('field/settings', { vlan: q('vlan').value || null, poe: q('poe').checked, speed: q('speed').value || null }).then(got).catch(() => load());
    } else if (a === 'del') {
      if (!window.confirm(T('Να σβηστεί αυτό το τεστ από το ιστορικό;', 'Delete this test from the history?'))) return;
      post('field/delete', { id: b.getAttribute('data-id') }).then(got).catch(() => load());
    } else if (a === 'upcheck') {
      b.disabled = true;
      post('uplink/check', {}).then(() => setTimeout(load, 2500)).catch(() => load());
    }
  });
  window.renderSock = () => load();
})();
