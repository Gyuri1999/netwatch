// 🧰 Εργαλεία δουλειάς (2): 🔌 Πού είναι συνδεδεμένο; · 📘 Τεκμηρίωση · 🔁 Παράδοση βάρδιας · ⏰ Λήξεις · 📱 Field mode.
// Φορτώνεται μετά το index.html· χρησιμοποιεί showTab, tab, I18N, fmtB.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const LANG = () => (EN() ? 'en' : 'el');
  const curTab = () => (typeof tab !== 'undefined' ? tab : null);
  const P = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) }).then(r => r.json().then(j => (r.ok ? j : Object.assign(j, { error: j.error || ('HTTP ' + r.status) }))));
  const J = u => fetch(u).then(r => r.json().then(j => (r.ok ? j : Object.assign(j, { error: j.error || ('HTTP ' + r.status) }))));
  const now = () => Date.now() / 1000;
  const since = t => { if (!t) return '—'; const s = Math.max(0, now() - t); return s < 90 ? Math.round(s) + '″' : s < 5400 ? Math.round(s / 60) + '′' : s < 172800 ? Math.round(s / 3600) + (EN() ? 'h' : 'ω') : Math.round(s / 86400) + (EN() ? 'd' : 'μ'); };
  const hm = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { hour12: false,  day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '—';
  const busyOn = () => { const a = document.activeElement; return a && (a.tagName === 'TEXTAREA' || a.tagName === 'INPUT' || a.tagName === 'SELECT'); };
  const SEVC = { high: 'var(--red)', med: 'var(--orange)', low: 'var(--yellow)', info: 'var(--cyan)' };
  function copy(btn, txt) { navigator.clipboard.writeText(txt).then(() => { const o = btn.innerHTML; btn.textContent = '✓'; setTimeout(() => btn.innerHTML = o, 1200); }); }

  const css = document.createElement('style');
  css.textContent = `
  .op-in{font:inherit;font-size:14px;padding:8px 11px;border-radius:9px;border:1px solid var(--line);background:var(--panel2);color:var(--txt);min-width:0}
  .op-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px}
  .op-loc{margin-top:12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.op-loc .card{margin:0;display:flex;flex-direction:column;gap:3px}.op-loc .card span{font-size:11.5px;color:var(--dim)}.op-loc .card b{font-size:18px}
  .op-path{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:12px;font-size:13px}.op-path .n{padding:6px 10px;border-radius:9px;border:1px solid var(--line);background:rgb(var(--w) / 3%)}.op-path .n.e{border-color:var(--green);color:var(--green);font-weight:700}.op-path i{color:var(--dim);font-style:normal}
  .op-t{width:100%;border-collapse:collapse;font-size:12.5px}.op-t th{text-align:left;font-size:11px;color:var(--dim);font-weight:600;padding:6px;cursor:pointer;white-space:nowrap}.op-t td{padding:6px;border-top:1px solid rgb(var(--w) / 6%)}.op-t tr:hover td{background:rgb(var(--w) / 3%)}
  .op-pill{font-size:10.5px;font-weight:700;padding:2px 7px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent);white-space:nowrap}
  .op-fmt{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-top:12px}.op-fmt a{margin:0;text-decoration:none;color:inherit;display:flex;flex-direction:column;gap:4px;border:1px solid transparent}.op-fmt a:hover{border-color:var(--cyan)}.op-fmt a b{font-size:15px}
  .op-pre{font:12px/1.5 ui-monospace,Menlo,monospace;white-space:pre-wrap;max-height:55vh;overflow:auto;padding:10px 12px;border-radius:8px;border:1px solid var(--line);background:var(--panel2);margin-top:10px}
  .op-kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(105px,1fr));gap:10px;margin:12px 0}.op-kpi .card{margin:0;text-align:center;display:flex;flex-direction:column;gap:2px}.op-kpi b{font-size:22px}.op-kpi span{font-size:11.5px;color:var(--dim)}
  .op-sec{margin:0 0 10px;white-space:normal;border-left:3px solid var(--c)}.op-sec ul{margin:6px 0 0 18px;padding:0;font-size:13px}.op-sec li{margin:2px 0}
  .op-note{font-size:12.5px;padding:7px 10px;border-radius:8px;background:rgb(var(--w) / 4%);display:flex;gap:8px;align-items:flex-start}.op-note .t{font-size:11px;color:var(--dim);flex:none}
  .op-ta{width:100%;min-height:200px;font:12px/1.45 ui-monospace,Menlo,monospace;padding:10px;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--txt);resize:vertical;box-sizing:border-box}
  .ex-list{display:flex;flex-direction:column;gap:6px;margin-top:10px}.ex-i{margin:0;display:flex;gap:12px;align-items:center;padding:10px 12px;border-left:3px solid var(--c);white-space:normal}
  .ex-d{flex:none;width:64px;text-align:center}.ex-d b{display:block;font-size:20px;color:var(--c)}.ex-d span{font-size:10.5px;color:var(--dim)}
  .ex-b{flex:1;min-width:0}.ex-b .s{font-size:12px;color:var(--dim)}
  .fd-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:12px;margin-top:12px}
  .fd-c{margin:0;display:flex;flex-direction:column;gap:8px;white-space:normal}.fd-c h3{margin:0;font-size:16px}
  .fd-go{font-size:16px;padding:12px 14px;border-radius:12px;font-weight:700;border-color:var(--cyan);color:var(--cyan)}
  .fd-res{font-size:13.5px;padding:10px 12px;border-radius:10px;background:rgb(var(--w) / 4%);min-height:20px}
  .fd-res b.big{font-size:26px;display:block}
  @media(max-width:700px){.op-t thead{display:none}.op-t tr{display:block;border-top:1px solid rgb(var(--w) / 8%);padding:6px 0}.op-t td{display:inline-block;border:0;padding:2px 6px}}
  `;
  document.head.appendChild(css);

  // ───────────────────────── 🔌 Πού είναι συνδεδεμένο; ─────────────────────────
  const WH = { q: '', r: null, tbl: null, busy: false, sort: 'switch', flt: '', all: false };
  function whTable() { return J('/api/whereis/table' + (WH.all ? '?all=1' : '')).then(j => { WH.tbl = j; if (curTab() === 'where' && !busyOn()) whDraw(); }); }
  function whFind(q) {
    WH.q = q; if (!q) { WH.r = null; whDraw(); return; }
    WH.busy = true; whDraw();
    return J('/api/whereis?q=' + encodeURIComponent(q)).then(j => { WH.busy = false; WH.r = j; whDraw(); }).catch(e => { WH.busy = false; WH.r = { error: String(e) }; whDraw(); });
  }
  function locHtml(r) {
    if (!r) return '';
    if (r.error) return `<div class="card sm" style="color:var(--red)">${E(r.error)}</div>`;
    if (!r.found) return `<div class="card" style="white-space:normal"><b>❓ Δεν βρέθηκε</b><div class="sm" style="margin-top:4px">${E(r.note || '')}</div>${(r.candidates || []).length ? `<div class="op-row">${r.candidates.map(c => `<button class="b" data-q="${E(c.mac || c.ip)}" data-noi18n>${E(c.name || c.ip || c.mac)} · ${E(c.ip || '')}</button>`).join('')}</div>` : ''}</div>`;
    const l = r.location || {}, conf = { high: ['υψηλή', 'var(--green)'], medium: ['μέτρια', 'var(--orange)'], low: ['χαμηλή', 'var(--red)'] }[l.confidence] || ['—', 'var(--dim)'];
    return `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">📍 <span data-noi18n>${E(r.name || r.ip || r.mac)}</span></b><span class="op-pill" style="--c:${conf[1]}"><span>βεβαιότητα</span>: <span>${conf[0]}</span></span></div>
      <div class="sm" data-noi18n>${E(r.ip || '')}${r.mac ? ' · ' + E(r.mac) : ''}${r.vendor ? ' · ' + E(r.vendor) : ''}</div>
      <div class="op-loc"><div class="card"><span>Switch</span><b data-noi18n>${E(l.switch || '—')}</b><span data-noi18n>${E(l.switch_host || '')}</span></div>
        <div class="card"><span>Θύρα</span><b data-noi18n>${E(l.port || '—')}</b><span data-noi18n>${E(l.alias || '')}</span></div>
        <div class="card"><span>VLAN</span><b data-noi18n>${E(l.vlan == null ? '—' : l.vlan)}</b></div>
        <div class="card"><span>MAC στη θύρα</span><b data-noi18n>${E(l.macs_on_port == null ? '—' : l.macs_on_port)}</b><span>${l.macs_on_port > 1 ? 'μάλλον switch/AP πίσω της' : ''}</span></div></div>
      ${(r.path || []).length ? `<div class="op-path"><span class="sm">Διαδρομή:</span>${r.path.map((p, i) => `${i ? '<i>→</i>' : ''}<span class="n${p.kind === 'edge' ? ' e' : ''}" data-noi18n>${E(p.switch)} ${E(p.port)}</span>`).join('')}<i>→</i><span class="n e" data-noi18n>${E(r.name || r.ip || r.mac)}</span></div>` : ''}
      ${r.note ? `<div class="sm" style="margin-top:8px">${E(r.note)}</div>` : ''}
      <div class="sm" style="margin-top:6px">${EN() ? 'MAC table: ' + since(r.refreshed) + ' ago' : 'πίνακας MAC: πριν ' + since(r.refreshed)}</div></div>`;
  }
  function whDraw() {
    const el = document.getElementById('t-where'); if (!el) return;
    const fi = document.activeElement && document.activeElement.classList.contains('wh-q');
    const t = WH.tbl || {}, sw = t.switches || [];
    let rows = (t.rows || []).slice();
    if (WH.flt) { const f = WH.flt.toLowerCase(); rows = rows.filter(r => [r.mac, r.ip, r.name, r.vendor, r.switch, r.port, r.vlan].join(' ').toLowerCase().includes(f)); }
    const k = WH.sort; rows.sort((a, b) => String(a[k] == null ? '' : a[k]).localeCompare(String(b[k] == null ? '' : b[k]), undefined, { numeric: true }));
    let h = `<div class="card" style="white-space:normal"><b class="ctitle">🔌 Πού είναι συνδεδεμένο; ${t.demo ? '<span class="tag">demo</span>' : ''}</b>
      <div class="sm" style="margin-top:6px" data-noi18n>${EN() ? 'Type a <b>MAC, IP or name</b> and NetWatch tells you which <b>switch → port → VLAN</b> it is on — from the switches\' MAC tables (BRIDGE-MIB / Q-BRIDGE via SNMP), following uplinks with LLDP. No more “half an hour searching the rack”.' : 'Γράψε <b>MAC, IP ή όνομα</b> και το NetWatch σου λέει σε ποιο <b>switch → θύρα → VLAN</b> είναι — από τον πίνακα MAC των switches (BRIDGE-MIB / Q-BRIDGE μέσω SNMP), ακολουθώντας τα uplinks με LLDP. Τέλος στο «ψάχνω μισή ώρα στο rack».'}</div>
      <div class="op-row"><input class="op-in wh-q" placeholder="π.χ. 192.168.1.33 · aa:bb:cc:dd:ee:ff · printer" value="${E(WH.q)}" style="flex:1;min-width:220px"><button class="b pu-go" data-wh="find">${WH.busy ? '⏳' : '🔎 Βρες'}</button><button class="b" data-wh="refresh" title="Ξαναδιάβασε τους πίνακες MAC">↻</button></div>
      ${sw.length ? `<div class="op-row">${sw.map(s => `<span class="op-pill" style="--c:${s.ok === false ? 'var(--red)' : 'var(--green)'}" data-noi18n>${E(s.name)} · ${s.macs || 0} MAC${s.error ? ' · ' + E(s.error) : ''}</span>`).join('')}</div>` : (WH.tbl && !t.off ? `<div class="sm" style="margin-top:8px">Δεν υπάρχουν switches με SNMP. Πρόσθεσέ τα στο <code>config.yaml</code> → <code>snmp.targets</code>.</div>` : '')}</div>`;
    h += locHtml(WH.r);
    h += `<div class="card" style="white-space:normal"><div class="brow"><b>Όλες οι συσκευές ανά θύρα</b><span style="display:flex;gap:6px;align-items:center"><input class="op-in wh-f" placeholder="φίλτρο…" value="${E(WH.flt)}" style="width:160px;padding:5px 9px;font-size:12.5px"><label class="sm"><input type="checkbox" class="wh-all"${WH.all ? ' checked' : ''}> και uplinks</label></span></div>
      <table class="op-t"><thead><tr>${[['name', 'Συσκευή'], ['ip', 'IP'], ['mac', 'MAC'], ['switch', 'Switch'], ['port', 'Θύρα'], ['vlan', 'VLAN'], ['seen', 'Είδα']].map(([c, l]) => `<th data-sort="${c}">${l}${WH.sort === c ? ' ▾' : ''}</th>`).join('')}</tr></thead>
      <tbody>${rows.slice(0, 400).map(r => `<tr data-q="${E(r.mac)}" style="cursor:pointer"><td data-noi18n>${E(r.name || '—')}${r.vendor ? ` <span class="sm">${E(r.vendor)}</span>` : ''}</td><td data-noi18n>${E(r.ip || '—')}</td><td data-noi18n class="sm">${E(r.mac)}</td><td data-noi18n>${E(r.switch)}</td><td data-noi18n><b>${E(r.port)}</b>${r.uplink ? ' <span class="op-pill" style="--c:var(--purple)">uplink</span>' : ''}</td><td data-noi18n>${E(r.vlan == null ? '—' : r.vlan)}</td><td class="sm">${since(r.seen)}</td></tr>`).join('') || '<tr><td colspan="7" class="sm">—</td></tr>'}</tbody></table></div>`;
    el.innerHTML = h;
    const q = el.querySelector('.wh-q'); if (fi && q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); }
    q.onkeydown = e => { if (e.key === 'Enter') whFind(q.value.trim()); };
    el.querySelector('[data-wh="find"]').onclick = () => whFind(q.value.trim());
    el.querySelector('[data-wh="refresh"]').onclick = () => P('/api/whereis/refresh', {}).then(() => setTimeout(whTable, 1500));
    el.querySelectorAll('[data-q]').forEach(b => b.onclick = () => { whFind(b.dataset.q); el.scrollIntoView({ block: 'start' }); });
    el.querySelectorAll('[data-sort]').forEach(b => b.onclick = () => { WH.sort = b.dataset.sort; whDraw(); });
    const f = el.querySelector('.wh-f'); f.oninput = () => { WH.flt = f.value; clearTimeout(WH.ft); WH.ft = setTimeout(() => { whDraw(); const g = document.querySelector('#t-where .wh-f'); if (g) { g.focus(); g.setSelectionRange(g.value.length, g.value.length); } }, 250); };
    el.querySelector('.wh-all').onchange = e => { WH.all = e.target.checked; whTable(); };
  }
  window.renderWhere = () => { if (!WH.tbl) { whDraw(); whTable(); } else whDraw(); };
  window.whereIs = q => { showTab('where'); whFind(q); };

  // ───────────────────────── 📘 Τεκμηρίωση ─────────────────────────
  const DC = { d: null, lang: null };
  function dcLoad() { DC.lang = LANG(); return J('/api/docs?lang=' + DC.lang).then(j => { DC.d = j; if (curTab() === 'docs') dcDraw(); }); }
  function dcDraw() {
    const el = document.getElementById('t-docs'); if (!el) return;
    const d = DC.d; if (!d) { el.innerHTML = '<div class="card sm">φόρτωση…</div>'; return; }
    const c = d.counts || {};
    const FM = { md: ['📝 Markdown', 'για wiki, Git, Confluence, Obsidian'], html: ['🖨 HTML / PDF', 'άνοιξέ το και «Εκτύπωση → PDF»'], drawio: ['🗺 draw.io', 'διάγραμμα τοπολογίας για diagrams.net / Visio'] };
    let h = `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">📘 Τεκμηρίωση δικτύου ${d.demo ? '<span class="tag">demo</span>' : ''}</b><button class="b" data-dc="reload">↻ Ανανέωση</button></div>
      <div class="sm" style="margin-top:6px">Η τεκμηρίωση που κανείς δεν προλαβαίνει να γράψει — φτιαγμένη αυτόματα από ό,τι ήδη ξέρει το NetWatch: υποδίκτυα & VLAN, router/switches, συνδέσεις LLDP, κάθε συσκευή με θύρα/VLAN, υπηρεσίες, πρόσφατες αλλαγές, ανοιχτές υποθέσεις και λήξεις. Χωρίς κωδικούς και SNMP communities. <span>Δημιουργήθηκε</span>: <span data-noi18n>${hm(d.generated)}</span></div></div>
      <div class="op-kpi">${[['devices', 'συσκευές'], ['subnets', 'υποδίκτυα'], ['vlans', 'VLAN'], ['switches', 'switches/AP'], ['links', 'συνδέσεις LLDP'], ['configs', 'configs'], ['cases_open', 'ανοιχτές υποθέσεις'], ['expiring', 'λήξεις ≤30μ']].map(([k, l]) => `<div class="card"><b>${c[k] || 0}</b><span>${l}</span></div>`).join('')}</div>
      <div class="op-fmt">${(d.formats || []).map(f => { const m = FM[f.id] || [f.id, '']; return `<a class="card" href="${E(f.url)}" ${f.id === 'html' ? 'target="_blank" rel="noopener"' : 'download'}><b>${m[0]}</b><span class="sm">${m[1]}</span><span class="sm" style="color:var(--cyan)">${f.id === 'html' ? '↗ άνοιγμα' : '⬇ κατέβασμα'}</span></a>`; }).join('')}</div>`;
    if (d.preview_md) h += `<div class="card" style="white-space:normal;margin-top:12px"><div class="brow"><b>Προεπισκόπηση (Markdown)</b><button class="b" data-dc="copy">📋 Αντιγραφή</button></div><div class="op-pre" data-noi18n>${E(d.preview_md)}</div></div>`;
    el.innerHTML = h;
    const r = el.querySelector('[data-dc="reload"]'); if (r) r.onclick = () => { DC.d = null; dcDraw(); dcLoad(); };
    const cp = el.querySelector('[data-dc="copy"]'); if (cp) cp.onclick = () => copy(cp, d.preview_md);
  }
  window.renderDocs = () => { if (!DC.d || DC.lang !== LANG()) { dcDraw(); dcLoad(); } else dcDraw(); };

  // ───────────────────────── 🔁 Παράδοση βάρδιας ─────────────────────────
  const SH = { d: null, hours: 8, draft: '', msg: null };
  function shLoad() { return J(`/api/handover?hours=${SH.hours}&lang=${LANG()}`).then(j => { SH.d = j; if (curTab() === 'shift' && !busyOn()) shDraw(); }); }
  function shDraw() {
    const el = document.getElementById('t-shift'); if (!el) return;
    const d = SH.d; if (!d) { el.innerHTML = '<div class="card sm">φόρτωση…</div>'; return; }
    const ta = el.querySelector('.sh-note'); if (ta) SH.draft = ta.value;
    const s = d.stats || {};
    let h = `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">🔁 Παράδοση βάρδιας ${d.demo ? '<span class="tag">demo</span>' : ''}</b>
        <span style="display:flex;gap:6px;align-items:center">${[4, 8, 12, 24].map(x => `<button class="b${SH.hours === x ? ' on' : ''}" style="${SH.hours === x ? 'border-color:var(--cyan);color:var(--cyan)' : ''}" data-h="${x}" data-noi18n>${x}${EN() ? 'h' : 'ω'}</button>`).join('')}</span></div>
      <div class="sm" style="margin-top:6px">Σαν σε NOC/SOC: πριν φύγεις, ο επόμενος παίρνει μια σύνοψη — τι χτύπησε, ποιες υποθέσεις είναι ανοιχτές, τι άλλαξε στα configs, τι χάλασε, τι λήγει. Ένα κλικ και πάει στο Teams/Slack/email.</div>
      <div class="sm" style="margin-top:4px">${hm(d.from)} → ${hm(d.to)}</div></div>
      <div class="op-kpi">${[['alerts_high', 'σοβαρές ειδοποιήσεις', 'var(--red)'], ['alerts_med', 'μεσαίες', 'var(--orange)'], ['cases_open', 'ανοιχτές υποθέσεις', 'var(--cyan)'], ['cases_closed', 'έκλεισαν', 'var(--green)'], ['config_changes', 'αλλαγές config', ''], ['risky_changes', 'επικίνδυνες', 'var(--red)'], ['expiring', 'λήξεις', 'var(--orange)']].map(([k, l, c]) => `<div class="card"><b style="${c ? 'color:' + c : ''}">${s[k] || 0}</b><span>${l}</span></div>`).join('')}</div>
      <div style="display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;align-items:start" class="sh-g">
      <div>${(d.sections || []).map(x => `<div class="card op-sec" style="--c:${SEVC[x.sev] || 'var(--dim)'}"><b>${E(x.title)}</b><ul>${(x.items || []).map(i => `<li>${E(i)}</li>`).join('') || '<li class="sm">—</li>'}</ul></div>`).join('')}</div>
      <div><div class="card" style="white-space:normal;margin:0 0 10px"><b>📝 Σημειώσεις βάρδιας</b>
        <div style="display:flex;flex-direction:column;gap:6px;margin-top:8px">${(d.notes || []).map(n => `<div class="op-note"><span class="t">${hm(n.t)}</span><span style="flex:1">${E(n.text)}</span><button class="b" style="padding:0 6px" data-del="${n.t}" title="Διαγραφή">✕</button></div>`).join('') || '<span class="sm">Καμία ακόμη.</span>'}</div>
        <div class="op-row"><textarea class="op-in sh-note" placeholder="π.χ. Ο πελάτης στο 2ο όροφο περιμένει τηλέφωνο για το Wi‑Fi" style="flex:1;min-height:44px;resize:vertical;font-size:13px"></textarea><button class="b" data-sh="add">📝 Πρόσθεσε</button></div>
        ${SH.msg ? `<div class="sm" style="color:var(--red)">${E(SH.msg)}</div>` : ''}</div>
      <div class="card" style="white-space:normal;margin:0"><div class="brow"><b>📤 Κείμενο για Teams / Slack / email</b><button class="b pu-go" data-sh="copy">📋 Αντιγραφή</button></div><textarea class="op-ta" readonly data-noi18n style="margin-top:8px">${E(d.text || '')}</textarea></div></div></div>`;
    el.innerHTML = h;
    const nt = el.querySelector('.sh-note'); if (nt) nt.value = SH.draft;
    el.querySelectorAll('[data-h]').forEach(b => b.onclick = () => { SH.hours = +b.dataset.h; shLoad(); });
    el.querySelector('[data-sh="copy"]').onclick = e => copy(e.currentTarget, d.text || '');
    el.querySelector('[data-sh="add"]').onclick = () => { const v = (nt.value || '').trim(); if (!v) return; P('/api/handover/note', { text: v }).then(j => { SH.msg = j.error || null; if (!j.error) SH.draft = ''; shLoad(); }); };
    el.querySelectorAll('[data-del]').forEach(b => b.onclick = () => P('/api/handover/note/delete', { t: +b.dataset.del }).then(shLoad));
  }
  const shCss = document.createElement('style'); shCss.textContent = '@media(max-width:900px){.sh-g{grid-template-columns:1fr!important}}'; document.head.appendChild(shCss);
  window.renderShift = () => { if (!SH.d || SH.d.lang !== LANG()) { shDraw(); shLoad(); } else { shDraw(); shLoad(); } };

  // ───────────────────────── ⏰ Λήξεις ─────────────────────────
  const EX = { d: null, add: false, msg: null };
  const EXS = { expired: ['έληξε', 'var(--red)'], urgent: ['≤ 7 μέρες', 'var(--red)'], soon: ['≤ 30 μέρες', 'var(--orange)'], ok: ['εντάξει', 'var(--green)'] };
  const EXK = { cert: '🔒 Πιστοποιητικό', domain: '🌐 Domain', license: '🔑 Άδεια', warranty: '🛡 Εγγύηση', contract: '📄 Συμβόλαιο', firmware: '💾 Firmware', other: '📌 Άλλο' };
  function exLoad() { return J('/api/expiry').then(j => { EX.d = j; if (curTab() === 'expiry' && !busyOn()) exDraw(); }); }
  function exDraw() {
    const el = document.getElementById('t-expiry'); if (!el) return;
    const d = EX.d; if (!d) { el.innerHTML = '<div class="card sm">φόρτωση…</div>'; return; }
    const c = d.counts || {};
    let h = `<div class="card" style="white-space:normal"><div class="brow"><b class="ctitle">⏰ Λήξεις ${d.demo ? '<span class="tag">demo</span>' : ''}</b><span style="display:flex;gap:6px"><button class="b" data-ex="refresh">↻</button><button class="b pu-go" data-ex="add">+ Πρόσθεσε</button></span></div>
      <div class="sm" style="margin-top:6px">Το πιστοποιητικό που έληξε Σάββατο βράδυ, το domain που ξέχασες να ανανεώσεις, η εγγύηση του switch, η μπαταρία του UPS — όλα σε μία λίστα. Ειδοποίηση στις 30, 7 και 1 μέρα πριν.</div></div>
      <div class="op-kpi"><div class="card"><b style="color:var(--red)">${c.expired || 0}</b><span>έληξαν</span></div><div class="card"><b style="color:var(--red)">${c.urgent || 0}</b><span>σε ≤ 7 μέρες</span></div><div class="card"><b style="color:var(--orange)">${c.soon || 0}</b><span>σε ≤ 30 μέρες</span></div><div class="card"><b style="color:var(--green)">${c.ok || 0}</b><span>εντάξει</span></div></div>`;
    if (EX.add) h += `<div class="card" style="white-space:normal"><b>+ Νέα λήξη</b><div class="op-row"><input class="op-in ex-n" placeholder="π.χ. Άδεια FortiGate" maxlength="80" style="flex:1;min-width:180px"><select class="op-in ex-k">${Object.entries(EXK).filter(([k]) => k !== 'cert').map(([k, l]) => `<option value="${k}">${l}</option>`).join('')}</select><input class="op-in ex-dt" type="date"><input class="op-in ex-no" placeholder="σημείωση" maxlength="200" style="flex:1;min-width:140px"><button class="b pu-go" data-ex="save">💾</button><button class="b" data-ex="cancel">Άκυρο</button></div>${EX.msg ? `<div class="sm" style="color:var(--red);margin-top:6px">${E(EX.msg)}</div>` : ''}</div>`;
    h += `<div class="ex-list">${(d.items || []).map(i => {
      const s = EXS[i.status] || EXS.ok, dl = i.days_left;
      return `<div class="card ex-i" style="--c:${s[1]}"><div class="ex-d"><b>${dl == null ? '—' : dl < 0 ? '−' + Math.abs(dl) : dl}</b><span>${dl != null && dl < 0 ? 'μέρες πριν' : 'μέρες'}</span></div>
        <div class="ex-b"><b>${E(i.name)}</b> <span class="op-pill" style="--c:${s[1]}">${s[0]}</span><div class="s"><span>${E(EXK[i.kind] || i.kind)}</span> · <span data-noi18n>${E(i.date || '')}</span>${i.host ? ` · <span data-noi18n>${E(i.host)}</span>` : ''} · ${i.source === 'auto' ? 'αυτόματο' : i.source === 'config' ? 'config.yaml' : 'χειροκίνητο'}</div>${i.detail ? `<div class="s">${E(i.detail)}</div>` : ''}</div>
        ${i.source === 'manual' ? `<button class="b" data-exdel="${E(i.id)}" title="Διαγραφή">🗑</button>` : ''}</div>`;
    }).join('') || '<div class="card sm">Τίποτα ακόμη — πρόσθεσε άδειες, εγγυήσεις και domains, ή βάλε <code>expiry</code> στο config.yaml.</div>'}</div>`;
    el.innerHTML = h;
    const act = (n, f) => { const b = el.querySelector(`[data-ex="${n}"]`); if (b) b.onclick = f; };
    act('add', () => { EX.add = !EX.add; EX.msg = null; exDraw(); });
    act('cancel', () => { EX.add = false; exDraw(); });
    act('refresh', () => P('/api/expiry/refresh', {}).then(() => setTimeout(exLoad, 800)));
    act('save', () => {
      const name = el.querySelector('.ex-n').value.trim(), date = el.querySelector('.ex-dt').value;
      if (!name || !date) { EX.msg = EN() ? 'Name and date are required.' : 'Χρειάζονται όνομα και ημερομηνία.'; return exDraw(); }
      P('/api/expiry/add', { name, kind: el.querySelector('.ex-k').value, date, note: el.querySelector('.ex-no').value.trim() || undefined }).then(j => { if (j.error) { EX.msg = j.error; exDraw(); } else { EX.add = false; exLoad(); } });
    });
    el.querySelectorAll('[data-exdel]').forEach(b => b.onclick = () => { if (confirm(EN() ? 'Delete?' : 'Διαγραφή;')) P('/api/expiry/delete', { id: b.dataset.exdel }).then(exLoad); });
  }
  window.renderExpiry = () => { exDraw(); exLoad(); };

  // ───────────────────────── 📱 Field mode ─────────────────────────
  const FD = { tri: null, where: null, speed: null, ping: null, wol: null, busy: {} };
  function fdBusy(k, v) { FD.busy[k] = v; fdDraw(); }
  function fdTri() {
    fdBusy('tri', true);
    P('/api/triage/run', { lang: LANG() }).then(j => {
      if (j.error && !/Τρέχει|running/i.test(j.error)) { FD.tri = { error: j.error }; fdBusy('tri', false); return; }
      const poll = () => J('/api/triage').then(v => { FD.tri = v; if (v.status === 'running') { fdDraw(); setTimeout(poll, 600); } else fdBusy('tri', false); });
      poll();
    });
  }
  function fdDraw() {
    const el = document.getElementById('t-field'); if (!el) return;
    const f = document.activeElement, fcls = f && f.dataset && f.dataset.fd, fval = f && f.value;
    const t = FD.tri, w = FD.where, sp = FD.speed, pg = FD.ping, wl = FD.wol, B = FD.busy;
    const stepsDone = t && t.steps ? t.steps.filter(s => s.status !== 'pending' && s.status !== 'running').length : 0;
    const vd = t && t.status === 'done' && t.verdict;
    let h = `<div class="card" style="white-space:normal"><b class="ctitle">📱 Field mode</b><div class="sm" style="margin-top:6px">Για όταν είσαι σε πελάτη ή μπροστά στο rack με το κινητό: τα 5 πράγματα που χρειάζεσαι, με μεγάλα κουμπιά. Άνοιξε το NetWatch από το κινητό (ίδιο Wi‑Fi) και πρόσθεσέ το στην αρχική οθόνη.</div></div>
    <div class="fd-grid">
      <div class="card fd-c"><h3>🔎 Φταίει το δίκτυο;</h3><button class="b fd-go" data-fd-go="tri"${B.tri ? ' disabled' : ''}>${B.tri ? `⏳ ${stepsDone}/9…` : '▶ Έλεγξε'}</button>
        <div class="fd-res">${t && t.error ? `<span style="color:var(--red)">${E(t.error)}</span>` : vd ? `<b class="big" style="color:${vd.layer === 'OK' ? 'var(--green)' : 'var(--red)'}" data-noi18n>${vd.layer === 'OK' ? '✅' : '🎯'} ${E(vd.layer)}</b>${E(vd.text)}${vd.fix ? `<div class="sm" style="margin-top:4px">🔧 ${E(vd.fix)}</div>` : ''}<div class="op-row" style="margin-top:6px"><button class="b" data-fd-copy="tri">📋 Ticket</button><button class="b" data-fd-open="tri">Λεπτομέρειες →</button></div>` : '<span class="sm">DHCP · gateway · DNS · Internet · captive portal · MTU</span>'}</div></div>
      <div class="card fd-c"><h3>🔌 Πού είναι συνδεδεμένο;</h3><div class="op-row" style="margin:0"><input class="op-in" data-fd="where" placeholder="IP, MAC ή όνομα" style="flex:1"><button class="b fd-go" data-fd-go="where">🔎</button></div>
        <div class="fd-res">${B.where ? '⏳' : w ? (w.error ? `<span style="color:var(--red)">${E(w.error)}</span>` : w.found ? `<b class="big" data-noi18n>${E((w.location || {}).switch || '')} · ${E((w.location || {}).port || '')}</b><span data-noi18n>VLAN ${E((w.location || {}).vlan == null ? '—' : w.location.vlan)} · ${E(w.name || w.ip || w.mac)}</span>` : `❓ ${E(w.note || (EN() ? 'Not found' : 'Δεν βρέθηκε'))}`) : '<span class="sm">switch → θύρα → VLAN</span>'}</div></div>
      <div class="card fd-c"><h3>⚡ Ταχύτητα Internet</h3><button class="b fd-go" data-fd-go="speed"${B.speed ? ' disabled' : ''}>${B.speed ? '⏳ μετράω…' : '▶ Speed test'}</button>
        <div class="fd-res">${sp ? (sp.ok === false || sp.error ? `<span style="color:var(--red)">${E(sp.error || 'error')}</span>` : `<b class="big" data-noi18n>⬇ ${E(sp.down_mbps)} · ⬆ ${E(sp.up_mbps)} Mbps</b><span data-noi18n>ping ${E(sp.latency_ms)} ms · jitter ${E(sp.jitter_ms)} ms</span>`) : '<span class="sm">Cloudflare speed test</span>'}</div></div>
      <div class="card fd-c"><h3>📶 Ping</h3><div class="op-row" style="margin:0"><input class="op-in" data-fd="ping" placeholder="π.χ. 192.168.1.1" style="flex:1"><button class="b fd-go" data-fd-go="ping">▶</button></div>
        <div class="fd-res">${B.ping ? '⏳' : pg ? (pg.error ? `<span style="color:var(--red)">${E(pg.error)}</span>` : `<b class="big" style="color:${pg.loss_pct ? 'var(--orange)' : 'var(--green)'}" data-noi18n>${pg.avg == null ? '✗' : E(pg.avg) + ' ms'}</b><span data-noi18n>${E(pg.received)}/${E(pg.sent)} · loss ${E(pg.loss_pct)}% · jitter ${E(pg.jitter == null ? '—' : pg.jitter)} ms${pg.os_guess ? ' · ' + E(pg.os_guess) : ''}</span>`) : '<span class="sm">απώλειες · καθυστέρηση · jitter</span>'}</div></div>
      <div class="card fd-c"><h3>💡 Wake-on-LAN</h3><div class="op-row" style="margin:0"><input class="op-in" data-fd="wol" placeholder="MAC, π.χ. aa:bb:cc:dd:ee:ff" style="flex:1"><button class="b fd-go" data-fd-go="wol">⏻</button></div>
        <div class="fd-res">${wl ? (wl.error ? `<span style="color:var(--red)">${E(wl.error)}</span>` : `✅ <span data-noi18n>${E(wl.mac)} → ${E(wl.broadcast)}:${E(wl.port)}</span>`) : '<span class="sm">ξύπνα έναν υπολογιστή από μακριά</span>'}</div></div>
    </div>`;
    el.innerHTML = h;
    if (fcls) { const g = el.querySelector(`[data-fd="${fcls}"]`); if (g) { g.value = fval; g.focus(); } }
    const val = k => (el.querySelector(`[data-fd="${k}"]`) || {}).value || '';
    const go = {
      tri: fdTri,
      where: () => { const q = val('where').trim(); if (!q) return; fdBusy('where', true); J('/api/whereis?q=' + encodeURIComponent(q)).then(j => { FD.where = j; fdBusy('where', false); }); },
      speed: () => { fdBusy('speed', true); P('/api/speed/internet', {}).then(j => { FD.speed = j; fdBusy('speed', false); }).catch(e => { FD.speed = { error: String(e) }; fdBusy('speed', false); }); },
      ping: () => { const host = val('ping').trim(); if (!host) return; fdBusy('ping', true); P('/api/netkit', { tool: 'ping', host, count: 5 }).then(j => { FD.ping = j; fdBusy('ping', false); }); },
      wol: () => { const mac = val('wol').trim(); if (!mac) return; P('/api/netkit', { tool: 'wol', mac }).then(j => { FD.wol = j; fdDraw(); }); },
    };
    el.querySelectorAll('[data-fd-go]').forEach(b => b.onclick = () => go[b.dataset.fdGo]());
    el.querySelectorAll('[data-fd]').forEach(i => i.onkeydown = e => { if (e.key === 'Enter') go[i.dataset.fd](); });
    const cp = el.querySelector('[data-fd-copy="tri"]'); if (cp) cp.onclick = () => copy(cp, (FD.tri || {}).ticket || '');
    const op = el.querySelector('[data-fd-open="tri"]'); if (op) op.onclick = () => showTab('tri');
  }
  window.renderField = () => fdDraw();

  window.OPSTOOLS = { WH, DC, SH, EX, FD, whDraw, dcDraw, shDraw, exDraw, fdDraw };
})();
