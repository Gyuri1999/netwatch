// ───────────────────────── 🧩 Οι συσκευές μου: αισθητήρες ESP32 / Raspberry Pi / υπολογιστές ─────────────────────────
// Σύζευξη με κωδικό ή QR (το token φαίνεται μία φορά), κατάσταση, γεγονότα, αφαίρεση.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const tr = x => (EN() && window.I18N && I18N.t ? I18N.t(String(x || '')) : String(x || ''));
  const box = () => document.getElementById('t-fleet');
  const ST = { online: ['var(--green)', 'online', 'online'], offline: ['var(--red)', 'εκτός', 'offline'], waiting: ['var(--yellow)', 'περιμένει πρώτη αναφορά', 'waiting for first report'] };
  let D = null, P = null, pick = null, timer = null, reveal = false;

  const css = document.createElement('style');
  css.textContent = `
#t-fleet .fl-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-fleet .fl-big{font-size:34px}
#t-fleet .fl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px;margin-top:10px}
#t-fleet .fl-kind{border:1px solid rgb(var(--w,255 255 255) / 10%);border-radius:12px;padding:10px 12px;background:rgb(var(--w,255 255 255) / 3%);cursor:pointer;text-align:left;color:inherit;font:inherit}
#t-fleet .fl-kind:hover,#t-fleet .fl-kind.on{border-color:var(--cyan);background:color-mix(in srgb,var(--cyan) 8%,transparent)}
#t-fleet .fl-kind[disabled]{cursor:default;opacity:.85}
#t-fleet .fl-ico{font-size:22px}
#t-fleet .fl-pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap}
#t-fleet .fl-dev{border-left:3px solid var(--c);border-radius:10px;background:rgb(var(--w,255 255 255) / 3%);padding:10px 12px;margin-top:10px}
#t-fleet .fl-chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
#t-fleet .fl-chip{font-size:12px;padding:2px 8px;border-radius:8px;background:rgb(var(--w,255 255 255) / 7%)}
#t-fleet .fl-ev{font-size:12.5px;margin-top:3px}
#t-fleet .fl-pair{display:grid;grid-template-columns:auto minmax(0,1fr);gap:16px;align-items:start;margin-top:10px}
#t-fleet .fl-qr{background:#fff;border-radius:10px;padding:6px;line-height:0}
#t-fleet .fl-qr svg{width:220px;height:220px}
#t-fleet .fl-code{font-family:var(--mono,ui-monospace,monospace);font-size:11.5px;word-break:break-all;background:rgb(var(--w,255 255 255) / 6%);padding:8px;border-radius:8px;max-height:110px;overflow:auto}
#t-fleet ol{margin:6px 0 0 18px;padding:0;font-size:13px}#t-fleet li{margin:4px 0}
#t-fleet code{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px}
#t-fleet input[type=text]{padding:6px 10px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 15%);background:transparent;color:inherit;min-width:220px}
@media (max-width:640px){#t-fleet .fl-pair{grid-template-columns:1fr}}
`;
  document.head.appendChild(css);

  const ago = t => { if (!t) return T('ποτέ', 'never'); const s = Math.max(0, Date.now() / 1000 - t); return s < 90 ? T(`πριν ${Math.round(s)}″`, `${Math.round(s)}s ago`) : s < 5400 ? T(`πριν ${Math.round(s / 60)}′`, `${Math.round(s / 60)} min ago`) : s < 172800 ? T(`πριν ${Math.round(s / 3600)} ώρ.`, `${Math.round(s / 3600)} h ago`) : T(`πριν ${Math.round(s / 86400)} μέρες`, `${Math.round(s / 86400)} days ago`); };
  const dur = s => s == null ? '' : s >= 86400 ? `${Math.floor(s / 86400)}${T('μ', 'd')} ${Math.floor(s % 86400 / 3600)}${T('ώ', 'h')}` : `${Math.floor(s / 3600)}${T('ώ', 'h')} ${Math.floor(s % 3600 / 60)}′`;
  const kind = k => (D && D.kinds && D.kinds[k]) || { icon: '❔', title: k };
  const MET = { gw_ms: ['router', v => v == null ? '✖' : v + ' ms'], gw_ok: null, load: [T('φόρτος', 'load'), v => v], mem_free_mb: [T('ελεύθερη RAM', 'free RAM'), v => v + ' MB'],
    lan_reachable: [T('φτάνει στο LAN', 'reaches LAN'), v => v ? T('ΝΑΙ ⚠', 'YES ⚠') : T('όχι ✔', 'no ✔')], door: [T('πόρτα', 'door'), v => v === 'closed' ? T('κλειστή', 'closed') : v === 'open' ? T('ανοιχτή', 'open') : v] };

  function chips(st) {
    const c = [];
    if (st.hw) c.push(E(st.hw));
    if (st.ip) c.push('IP ' + E(st.ip));
    if (st.fw) c.push('fw ' + E(st.fw));
    if (st.uptime != null) c.push('⏱ ' + dur(st.uptime));
    if (st.rssi != null) c.push('📶 ' + E(st.rssi) + ' dBm');
    if (st.temp != null) c.push('🌡 ' + E(st.temp) + '°C');
    if (st.hum != null) c.push('💧 ' + E(st.hum) + '%');
    if (st.batt != null) c.push('🔋 ' + E(st.batt) + '%');
    if (st.heap != null) c.push(T('μνήμη ', 'heap ') + Math.round(st.heap / 1024) + ' KB');
    for (const [k, v] of Object.entries(st.metrics || {})) { const m = MET[k]; if (m === null) continue; c.push(m ? `${m[0]} ${E(m[1](v))}` : `${E(k)} ${E(v)}`); }
    for (const [k, v] of Object.entries(st.link || {})) c.push(`${E(k)} ${E(v)}`);
    return c.map(x => `<span class="fl-chip">${x}</span>`).join('');
  }

  function devCard(p) {
    const k = kind(p.kind), s = ST[p.state] || ST.waiting;
    return `<div class="fl-dev" style="--c:${s[0]}"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <span style="font-size:20px">${k.icon}</span><b>${E(p.name)}</b><span class="fl-pill" style="--c:${s[0]}">● ${T(s[1], s[2])}</span>
      <span class="dim" style="font-size:12px">${E(tr(k.title))} · ${T('τελευταία αναφορά', 'last report')} ${ago(p.seen)}${p.ip ? ' · ' + E(p.ip) : ''}</span>
      <span style="flex:1"></span><button class="b" data-fl="rename" data-id="${E(p.id)}" title="${T('Μετονομασία', 'Rename')}">✏</button><button class="b" data-fl="remove" data-id="${E(p.id)}" title="${T('Αφαίρεση (ακυρώνει το token)', 'Remove (revokes the token)')}">🗑</button></div>
      ${p.state === 'waiting' ? `<div class="dim" style="font-size:12.5px;margin-top:6px">${T('Περάστε τον κωδικό σύζευξης στη συσκευή — θα εμφανιστεί εδώ με την πρώτη αναφορά.', 'Enter the pairing code on the device — it appears here with its first report.')}</div>` : ''}
      <div class="fl-chips">${chips(p.status || {})}</div>
      ${(p.events || []).length ? `<div style="margin-top:6px">${p.events.map(e => `<div class="fl-ev"><span class="dim">${ago(e.t)}</span> · <b>${E(e.type)}</b> ${E(tr(e.detail))}</div>`).join('')}</div>` : ''}</div>`;
  }

  function steps(kd, code) {
    if (kd === 'pc') return `<ol>
      <li>${T('Στον Pi / υπολογιστή κατέβασε το', 'On the Pi / computer get')} <code>tools/netwatch_probe.py</code> ${T('(ένα αρχείο, χωρίς εξαρτήσεις — Python 3).', '(single file, no dependencies — Python 3).')}</li>
      <li>${T('Πάτα <b>📋 Αντιγραφή</b> εδώ και μετά τρέξε', 'Press <b>📋 Copy</b> here, then run')} <code>python3 netwatch_probe.py pair</code> ${T('— παίρνει μόνο του τον κωδικό από το clipboard (σε άλλο υπολογιστή: σου ζητά να τον επικολλήσεις).', '— it takes the code from the clipboard by itself (on another computer it asks you to paste it).')}</li>
      <li>${T('Για να τρέχει πάντα:', 'To keep it running:')} <code>python3 netwatch_probe.py --systemd</code> ${T('και ακολούθησε τη γραμμή στο τέλος.', 'and follow the last line.')}</li></ol>`;
    return `<ol><li>${T('Το firmware για αυτή τη συσκευή είναι το επόμενο βήμα του NetWatch. Κράτα τον κωδικό — θα τον περάσεις στη σελίδα ρύθμισης του ESP32 (Wi-Fi «NetWatch-Setup»).', 'The firmware for this device is NetWatch’s next step. Keep the code — you will enter it on the ESP32 setup page (Wi-Fi “NetWatch-Setup”).')}</li>
      <li>${T('Μέχρι τότε μπορείς να δοκιμάσεις με το', 'Until then you can test with')} <code>tools/netwatch_probe.py</code> ${T('σε οποιονδήποτε υπολογιστή.', 'on any computer.')}</li></ol>`;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error === 'off') { b.innerHTML = `<div class="card">${T('Διαθέσιμο σε Live και Demo.', 'Available in Live and Demo.')}</div>`; return; }
    const ps = D.probes || [], mq = D.mqtt || [], c = D.counts || {};
    const off = ps.filter(p => p.state === 'offline').length;
    let h = `<div class="card"><div class="fl-hero"><span class="fl-big">${!c.total ? '🧩' : off ? '⚠️' : '✅'}</span><div style="flex:1;min-width:240px">
      <b style="font-size:16px">${!c.total ? T('Δεν έχεις συνδέσει ακόμα αισθητήρες', 'No sensors connected yet') : T(`${c.online} από ${c.total} συσκευές online`, `${c.online} of ${c.total} devices online`)}${off ? T(` · ${off} εκτός`, ` · ${off} offline`) : ''}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${D.listening ? `🟢 ${T('Θύρα αισθητήρων', 'Sensor port')} HTTPS :${E(D.port)}${(D.urls || []).length ? ' · ' + D.urls.map(E).join(', ') : ''}` : `⚪ ${T('Η θύρα αισθητήρων είναι κλειστή — ανοίγει με την πρώτη σύζευξη', 'The sensor port is closed — it opens with the first pairing')}`}</div>
      ${D.fp ? `<div class="dim" style="font-size:11px;margin-top:2px;word-break:break-all">${T('Αποτύπωμα πιστοποιητικού', 'Certificate fingerprint')} SHA-256: <code>${E(D.fp)}</code></div>` : ''}</div>
      <label style="display:flex;gap:6px;align-items:center;font-size:13px"><input type="checkbox" data-fl="enable"${D.enabled ? ' checked' : ''}${D.demo ? ' disabled' : ''}> ${T('Δέξου αισθητήρες από το LAN', 'Accept sensors from the LAN')}</label></div>
      ${D.demo ? `<div class="dim" style="font-size:12.5px;margin-top:8px">🧪 ${T('Demo: τρεις φανταστικοί αισθητήρες. Η σύζευξη δουλεύει, αλλά δεν ανοίγει πραγματική θύρα.', 'Demo: three imaginary sensors. Pairing works, but no real port is opened.')}</div>` : ''}
      ${D.error ? `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${E(tr(D.error))}</div>` : ''}
      <div class="dim" style="font-size:12.5px;margin-top:8px;line-height:1.55">${T('Το NetWatch είναι το <b>κέντρο</b>· ESP32, Raspberry Pi και υπολογιστές γίνονται <b>αισθητήρες</b> σε άλλα δωμάτια, VLAN ή κτίρια. Όλοι μιλούν με τον ίδιο τρόπο: HTTPS με έλεγχο αποτυπώματος και <b>δικό τους token</b> (κρατάω μόνο το hash του — αν χαθεί μια συσκευή, την αφαιρείς και το token της παύει να ισχύει).',
        'NetWatch is the <b>hub</b>; ESP32s, Raspberry Pis and computers become <b>sensors</b> in other rooms, VLANs or buildings. They all talk the same way: HTTPS with fingerprint pinning and <b>their own token</b> (I keep only its hash — if a device is lost, remove it and its token stops working).')}</div></div>`;

    h += `<div class="card"><b>➕ ${T('Πρόσθεσε συσκευή', 'Add a device')}</b><div class="dim" style="font-size:12.5px;margin-top:3px">${T('Διάλεξε τι θα συνδέσεις — με κάθε κομμάτι hardware που ήδη έχεις.', 'Pick what to connect — with whatever hardware you already have.')}</div><div class="fl-grid">`;
    for (const [id, k] of Object.entries(D.kinds || {})) {
      const can = (D.pairable || []).includes(id);
      h += `<button class="fl-kind${pick === id ? ' on' : ''}" ${can ? `data-fl="pick" data-k="${E(id)}"` : 'disabled'}><div style="display:flex;gap:8px;align-items:center"><span class="fl-ico">${k.icon}</span><b style="font-size:13.5px">${E(tr(k.title))}</b></div>
        <div class="dim" style="font-size:12px;margin-top:4px">${E(tr(k.what))}</div>
        <div style="font-size:11.5px;margin-top:6px">🛒 ${E(tr(k.hw))} · <b>${E(tr(k.price))}</b></div>
        <div style="margin-top:6px">${k.mqtt ? `<span class="fl-pill" style="--c:var(--cyan)">${T('έτοιμο · μέσω MQTT', 'ready · via MQTT')}</span>` : k.ready ? `<span class="fl-pill" style="--c:var(--green)">${T('έτοιμο', 'ready')}</span>` : `<span class="fl-pill" style="--c:var(--yellow)">${T('firmware σύντομα · η σύζευξη δουλεύει', 'firmware soon · pairing works')}</span>`}</div></button>`;
    }
    h += `</div>`;
    if (pick && !P) {
      h += `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px"><span>${kind(pick).icon}</span><input type="text" id="fl-name" maxlength="40" placeholder="${T('όνομα, π.χ. Pi Zero · γραφείο', 'name, e.g. Pi Zero · office')}">
        <button class="b" data-fl="pair">🔑 ${T('Δημιουργία κωδικού σύζευξης', 'Create pairing code')}</button><button class="b" data-fl="cancel">${T('Άκυρο', 'Cancel')}</button></div>`;
    }
    if (P) {
      h += `<div class="fl-pair"><div class="fl-qr">${P.qr}</div><div><b>✔ ${T('Έτοιμο', 'Ready')}: ${E(P.name)}</b>
        <div style="color:var(--orange);font-size:12.5px;margin-top:4px">🔐 ${T('Ο κωδικός περιέχει το μυστικό token της συσκευής και <b>φαίνεται μόνο τώρα</b>. Μην τον μοιραστείς· αν χαθεί, αφαίρεσε τη συσκευή και ξαναφτιάξε.', 'The code contains the device’s secret token and is <b>shown only now</b>. Don’t share it; if it leaks, remove the device and pair again.')}</div>
        <div class="fl-code" style="margin-top:6px">${reveal ? E(P.code) : E(P.code.slice(0, 8)) + '•'.repeat(40)}</div>
        <div style="display:flex;gap:6px;margin-top:6px"><button class="b" data-fl="reveal">${reveal ? '🙈 ' + T('Κρύψε', 'Hide') : '👁 ' + T('Δείξε', 'Show')}</button><button class="b" data-fl="copy">📋 ${T('Αντιγραφή', 'Copy')}</button><button class="b" data-fl="done">${T('Τέλος', 'Done')}</button></div>
        ${steps(P.kind, P.code)}</div></div>`;
    }
    h += `</div>`;

    if (ps.length || mq.length) {
      h += `<div class="card"><b>${T('Οι συσκευές σου', 'Your devices')}</b>${ps.map(devCard).join('')}`;
      for (const s of mq) {
        const k = kind(s.kind), col = s.online ? 'var(--green)' : 'var(--red)';
        h += `<div class="fl-dev" style="--c:${col}"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><span style="font-size:20px">${k.icon}</span><b>${E(s.id)}</b>
          <span class="fl-pill" style="--c:${col}">● ${s.online ? 'online' : T('εκτός', 'offline')}</span><span class="dim" style="font-size:12px">${E(tr(k.title))} · MQTT · ${T('δες', 'see')} 📡 ${T('Αισθητήρες', 'Sensors')}</span></div>
          <div class="fl-chips">${s.ip ? `<span class="fl-chip">IP ${E(s.ip)}</span>` : ''}${s.fw ? `<span class="fl-chip">fw ${E(s.fw)}</span>` : ''}${s.rssi != null ? `<span class="fl-chip">📶 ${E(s.rssi)} dBm</span>` : ''}</div></div>`;
      }
      h += `</div>`;
    }
    b.innerHTML = h;
  }

  function load() {
    return fetch('/api/probes').then(r => r.json()).then(j => { D = j; draw(); }).catch(() => { D = { error: 'off' }; draw(); });
  }
  const post = (a, body) => fetch('/api/probes/' + a, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then(r => r.json());

  document.addEventListener('click', e => {
    const b = e.target.closest('#t-fleet [data-fl]'); if (!b || b.tagName === 'INPUT') return;
    const a = b.dataset.fl;
    if (a === 'pick') { pick = b.dataset.k; P = null; draw(); const i = document.getElementById('fl-name'); if (i) i.focus(); return; }
    if (a === 'cancel') { pick = null; draw(); return; }
    if (a === 'done') { P = null; pick = null; reveal = false; load(); return; }
    if (a === 'reveal') { reveal = !reveal; draw(); return; }
    if (a === 'copy') { if (P) navigator.clipboard.writeText(P.code).then(() => { b.textContent = '✔ ' + T('Αντιγράφηκε', 'Copied'); }).catch(() => { reveal = true; draw(); }); return; }
    if (a === 'pair') {
      const name = (document.getElementById('fl-name') || {}).value || '';
      b.disabled = true;
      post('pair', { name, kind: pick }).then(j => { if (j.error) { alert(tr(j.error)); b.disabled = false; return; } P = j; reveal = false; load(); });
      return;
    }
    if (a === 'remove') {
      if (!confirm(T('Να αφαιρεθεί η συσκευή; Το token της παύει να ισχύει αμέσως.', 'Remove this device? Its token stops working immediately.'))) return;
      post('remove', { id: b.dataset.id }).then(load); return;
    }
    if (a === 'rename') {
      const n = prompt(T('Νέο όνομα:', 'New name:')); if (!n) return;
      post('rename', { id: b.dataset.id, name: n }).then(load);
    }
  });
  document.addEventListener('change', e => {
    const c = e.target.closest('#t-fleet input[data-fl="enable"]'); if (!c) return;
    post('enable', { on: c.checked }).then(j => { if (j.error) alert(tr(j.error)); load(); });
  });
  window.renderFleet = () => { load(); clearInterval(timer); timer = setInterval(() => { if (!P && !pick && box() && box().offsetParent) load(); }, 15000); };
})();
