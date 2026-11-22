// ───────────────────────── 📦 Απογραφή έξυπνων συσκευών (Zigbee2MQTT · Tasmota · Shelly · ESPHome) ─────────────────────────
// Μόνο ανάγνωση: ό,τι λένε οι συσκευές στον MQTT broker (μέσω του φύλακα 🦟 MQTT) → μοντέλο, firmware, μπαταρία, σήμα, online.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const L = o => E(EN() ? (o.en || o.el) : o.el);
  const box = () => document.getElementById('t-iotinv');
  const COL = { med: 'var(--orange)', low: 'var(--yellow)', info: 'var(--cyan)' };
  let D = null, timer = null, F = { q: '', src: '', prob: '' }, S = { k: 'rank', d: 1 };

  const css = document.createElement('style');
  css.textContent = `
#t-iotinv .ii-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-iotinv .ii-big{font-size:34px}
#t-iotinv a.ii-csv{display:inline-block;padding:5px 11px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 12%);background:rgb(var(--w,255 255 255) / 4%);color:inherit;text-decoration:none;font-size:12px;font-weight:500;white-space:nowrap}
#t-iotinv .ii-chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
#t-iotinv .ii-chip{font:inherit;font-size:12px;padding:3px 10px;border-radius:9px;border:1px solid transparent;background:rgb(var(--w,255 255 255) / 7%);color:inherit;cursor:pointer}
#t-iotinv .ii-chip b{font-size:13px}
#t-iotinv .ii-chip.on{border-color:var(--cyan);background:color-mix(in srgb,var(--cyan) 12%,transparent)}
#t-iotinv .ii-pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap;display:inline-block}
#t-iotinv{min-width:0}
#t-iotinv .card{min-width:0;max-width:100%}
#t-iotinv .ii-wrap{overflow-x:auto;margin-top:8px}
#t-iotinv table{border-collapse:collapse;width:100%;font-size:12.5px;min-width:640px}
#t-iotinv th{text-align:left;font-weight:600;color:var(--dim);font-size:11.5px;padding:4px 8px;border-bottom:1px solid rgb(var(--w,255 255 255) / 12%);white-space:nowrap}
#t-iotinv th[data-ii]{cursor:pointer}
#t-iotinv td{padding:6px 8px;border-bottom:1px solid rgb(var(--w,255 255 255) / 6%);vertical-align:top}
#t-iotinv tr.ii-hot td:first-child{box-shadow:inset 3px 0 0 var(--c)}
#t-iotinv .ii-mono{font-family:var(--mono,ui-monospace,monospace);font-size:11.5px}
#t-iotinv .ii-flag{font-size:12px;margin-top:2px;color:var(--c)}
#t-iotinv .ii-bat{display:inline-block;width:34px;height:8px;border-radius:2px;border:1px solid var(--c);vertical-align:middle;margin-right:5px;overflow:hidden}
#t-iotinv .ii-bat i{display:block;height:100%;background:var(--c)}
#t-iotinv .ii-adv{border-left:3px solid var(--c);border-radius:8px;background:rgb(var(--w,255 255 255) / 3%);padding:8px 10px;margin-top:8px;font-size:13px;line-height:1.5}
#t-iotinv ol{margin:6px 0 0 18px;padding:0;font-size:13px}#t-iotinv li{margin:3px 0}
#t-iotinv input[type=search]{padding:6px 10px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 15%);background:transparent;color:inherit;min-width:200px;flex:1;max-width:320px}
#t-iotinv code,#t-iotinv pre{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px}
#t-iotinv pre{padding:8px 10px;font-size:12px;overflow-x:auto;margin:6px 0 0}
#t-iotinv .ii-shop{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;margin-top:8px}
#t-iotinv .ii-shop>div{border:1px solid rgb(var(--w,255 255 255) / 10%);border-radius:10px;padding:8px 10px;font-size:12.5px}
`;
  document.head.appendChild(css);

  const ago = t => { if (!t) return '—'; const s = Math.max(0, Date.now() / 1000 - t); return s < 90 ? T(`πριν ${Math.round(s)}″`, `${Math.round(s)}s ago`) : s < 5400 ? T(`πριν ${Math.round(s / 60)}′`, `${Math.round(s / 60)} min ago`) : s < 172800 ? T(`πριν ${Math.round(s / 3600)} ώρ.`, `${Math.round(s / 3600)} h ago`) : T(`πριν ${Math.round(s / 86400)} μέρες`, `${Math.round(s / 86400)} days ago`); };
  const has = (r, c) => (r.problems || []).some(p => p.code === c);
  const sigv = r => r.lqi != null ? r.lqi / 255 * 100 : r.rssi != null ? (r.rssi + 100) / 60 * 100 : -1;
  const SORT = { rank: r => r.rank, name: r => String(r.name).toLowerCase(), src: r => r.src, batt: r => r.batt == null ? 999 : r.batt, sig: r => { const v = sigv(r); return v < 0 ? 999 : v; }, last: r => -(r.last || 0), fw: r => String(r.fw || '~') };

  function rowsNow() {
    const q = F.q.trim().toLowerCase();
    let rs = (D.devices || []).filter(r => (!F.src || r.src === F.src) && (!F.prob || (F.prob === 'any' ? (r.problems || []).length : has(r, F.prob)))
      && (!q || [r.name, r.model, r.vendor, r.ip, r.mac, r.ieee, r.fw, r.src_label].some(x => String(x || '').toLowerCase().includes(q))));
    const f = SORT[S.k] || SORT.rank;
    rs = rs.map((r, i) => [r, i]).sort((a, b) => { const x = f(a[0]), y = f(b[0]); return (x < y ? -1 : x > y ? 1 : a[1] - b[1]) * (x === y ? 1 : S.d); }).map(x => x[0]);
    return rs;
  }

  function table() {
    const rs = rowsNow();
    const th = (k, el, en) => `<th data-ii="sort" data-k="${k}">${T(el, en)}${S.k === k ? (S.d > 0 ? ' ▲' : ' ▼') : ''}</th>`;
    let h = `<table><thead><tr>${th('name', 'Συσκευή', 'Device')}${th('src', 'Πηγή', 'Source')}<th>${T('Διεύθυνση', 'Address')}</th>${th('fw', 'Firmware', 'Firmware')}${th('batt', 'Μπαταρία', 'Battery')}${th('sig', 'Σήμα', 'Signal')}${th('last', 'Τελευταία φορά', 'Last seen')}</tr></thead><tbody>`;
    for (const r of rs) {
      const worst = (r.problems || []).length ? COL[r.problems.reduce((a, p) => ({ med: 0, low: 1, info: 2 }[p.sev] < { med: 0, low: 1, info: 2 }[a] ? p.sev : a), 'info')] : '';
      const st = r.online === true ? ['var(--green)', 'online'] : r.online === false ? ['var(--red)', T('εκτός', 'offline')] : null;
      const bc = r.batt == null ? '' : r.batt <= 15 ? 'var(--red)' : r.batt <= 30 ? 'var(--orange)' : 'var(--green)';
      const sv = sigv(r), sc = sv < 0 ? '' : (r.lqi != null ? r.lqi < 40 : r.rssi < -80) ? 'var(--orange)' : 'var(--green)';
      h += `<tr class="${worst ? 'ii-hot' : ''}" style="--c:${worst || 'transparent'}"><td><b>${E(r.name)}</b> ${st ? `<span class="ii-pill" style="--c:${st[0]}">● ${st[1]}</span>` : ''}
          <div class="dim" style="font-size:11.5px">${E([r.vendor, r.model].filter(Boolean).join(' · ') || '—')}${r.type ? ' · ' + E(r.type) : ''}${r.power === 'battery' ? ' · 🔋' : r.power === 'mains' ? ' · 🔌' : ''}</div>
          ${(r.problems || []).map(p => `<div class="ii-flag" style="--c:${COL[p.sev] || 'var(--dim)'}">${p.sev === 'info' ? 'ℹ' : '⚠'} ${L(p)}</div>`).join('')}</td>
        <td style="white-space:nowrap">${E(r.icon)} ${E(r.src_label)}</td>
        <td class="ii-mono">${r.ip ? E(r.ip) : ''}${r.host && r.host.name ? `<div class="dim">${E(r.host.name)}</div>` : ''}${r.mac ? `<div class="dim">${E(r.mac)}</div>` : ''}${r.ieee ? `<div class="dim">${E(r.ieee)}</div>` : ''}${!r.ip && !r.mac && !r.ieee ? '<span class="dim">—</span>' : ''}</td>
        <td>${E(r.fw || '—')}${r.update ? `<div><span class="ii-pill" style="--c:var(--cyan)">⬆ ${r.update_to ? E(r.update_to) : T('νέα έκδοση', 'update')}</span></div>` : ''}</td>
        <td style="white-space:nowrap">${r.batt == null ? '<span class="dim">—</span>' : `<span class="ii-bat" style="--c:${bc}"><i style="width:${Math.max(4, Math.min(100, r.batt))}%"></i></span>${E(Math.round(r.batt))}%`}${r.btype ? `<div class="dim" style="font-size:11.5px">${E(r.btype)}</div>` : ''}</td>
        <td style="white-space:nowrap">${sv < 0 ? '<span class="dim">—</span>' : `<span style="color:${sc}">${r.lqi != null ? 'LQI ' + E(Math.round(r.lqi)) : E(Math.round(r.rssi)) + ' dBm'}</span>`}</td>
        <td style="white-space:nowrap">${ago(r.last)}</td></tr>`;
    }
    if (!rs.length) h += `<tr><td colspan="7" class="dim">${(D.devices || []).length ? T('Καμία συσκευή με αυτά τα φίλτρα.', 'No device matches these filters.') : T('Δεν έχω δει ακόμα καμία συσκευή στον broker.', 'I have not seen any device on the broker yet.')}</td></tr>`;
    return h + '</tbody></table>';
  }

  function setup(m) {
    return `<div class="card"><b>🔧 ${T('Πώς φτάνουν εδώ τα δεδομένα', 'How the data gets here')}</b>
      <div style="font-size:13px;margin-top:6px;line-height:1.55">${T('Η απογραφή δεν ρωτά καμία συσκευή: διαβάζει ό,τι δημοσιεύουν οι συσκευές στον <b>MQTT broker</b> σου, μέσω του φύλακα της καρτέλας <b>🦟 MQTT</b>. Χρειάζεται λοιπόν ο φύλακας να είναι ρυθμισμένος στο <code>config.yaml</code>, με χρήστη που <b>μόνο διαβάζει</b>:', 'The inventory never queries a device: it reads what devices publish to your <b>MQTT broker</b>, through the guard of the <b>🦟 MQTT</b> tab. So the guard must be configured in <code>config.yaml</code>, with a <b>read-only</b> user:')}</div>
      <pre>mqtt_guard:
  host: 192.168.1.17
  port: 8883            # TLS
  username: netwatch
  password: "…"
  ca_file: ~/iot-ca/ca.crt</pre>
      <div class="dim" style="font-size:12.5px;margin-top:6px">${m && m.configured ? (m.connected ? `🟢 ${T('Ο φύλακας MQTT είναι συνδεδεμένος', 'The MQTT guard is connected')} · ${E(m.msgs || 0)} ${T('μηνύματα', 'messages')}${m.last ? ' · ' + T('τελευταίο', 'last') + ' ' + ago(m.last) : ''}` : `🟠 ${T('Ο φύλακας MQTT είναι ρυθμισμένος αλλά όχι συνδεδεμένος — δες την καρτέλα 🦟 MQTT.', 'The MQTT guard is configured but not connected — see the 🦟 MQTT tab.')}`) : `⚪ ${T('Ο φύλακας MQTT δεν είναι ρυθμισμένος ακόμα (<code>mqtt_guard</code> στο config.yaml) — γι’ αυτό ο πίνακας είναι άδειος.', 'The MQTT guard is not configured yet (<code>mqtt_guard</code> in config.yaml) — that is why the table is empty.')}`}</div>
      <div class="dim" style="font-size:12.5px;margin-top:6px">${T('Αναγνωρίζω: <b>Zigbee2MQTT</b> (<code>zigbee2mqtt/#</code> — βάλε <code>availability: true</code> και <code>last_seen: ISO_8601</code>), <b>Tasmota</b> (<code>tele/#</code>, <code>stat/#</code>), <b>Shelly</b> (Gen1 <code>shellies/#</code>, Gen2+ με ενεργό MQTT και «Generic status update»), <b>ESPHome</b> και ό,τι δημοσιεύει <b>Home-Assistant discovery</b> (<code>homeassistant/#</code>).', 'I recognise: <b>Zigbee2MQTT</b> (<code>zigbee2mqtt/#</code> — set <code>availability: true</code> and <code>last_seen: ISO_8601</code>), <b>Tasmota</b> (<code>tele/#</code>, <code>stat/#</code>), <b>Shelly</b> (Gen1 <code>shellies/#</code>, Gen2+ with MQTT and “Generic status update” enabled), <b>ESPHome</b> and anything that publishes <b>Home-Assistant discovery</b> (<code>homeassistant/#</code>).')}</div></div>`;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error) { b.innerHTML = `<div class="card">${T('Η απογραφή IoT δεν είναι διαθέσιμη σε αυτή τη λειτουργία (π.χ. στατικό demo ή ανάλυση pcap).', 'The IoT inventory is not available in this mode (e.g. static demo or pcap analysis).')}</div>`; return; }
    const c = D.counts || {}, m = D.mqtt || {}, z = D.z2m || {}, th = D.thresholds || {};
    const bad = (c.offline || 0) + (c.batt || 0);
    const fchip = (k, v, n, txt, col) => `<button class="ii-chip${F[k] === v ? ' on' : ''}" data-ii="f" data-k="${k}" data-v="${E(v)}"${col && n ? ` style="color:${col}"` : ''}><b>${E(n)}</b> ${txt}</button>`;
    let h = `<div class="card"><div class="ii-hero"><span class="ii-big">${!c.total ? '📦' : bad ? '⚠️' : '✅'}</span><div style="flex:1;min-width:240px">
      <b style="font-size:16px">${!c.total ? T('Καμία έξυπνη συσκευή ακόμα', 'No smart device yet') : bad ? T(`${c.total} συσκευές · ${bad} θέλουν προσοχή`, `${c.total} devices · ${bad} need attention`) : T(`${c.total} συσκευές · όλες εντάξει`, `${c.total} devices · all fine`)}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${Object.entries(c.by_src || {}).map(([s, n]) => `${E(((D.sources || {})[s] || {}).icon || '')} ${E(((D.sources || {})[s] || {}).label || s)} ${E(n)}`).join(' · ') || T('Zigbee2MQTT · Tasmota · Shelly · ESPHome', 'Zigbee2MQTT · Tasmota · Shelly · ESPHome')}${z.version ? ` · Z2M ${E(z.version)}${z.channel ? ' · ' + T('κανάλι', 'channel') + ' ' + E(z.channel) : ''}` : ''}</div></div>
      ${c.total ? `<a class="ii-csv" href="/api/kit/iotinv/csv" download="iot-inventory.csv">⬇ CSV</a>` : ''}</div>
      ${D.demo ? `<div class="dim" style="font-size:12.5px;margin-top:8px">🧪 ${T('Demo: 16 συσκευές από Zigbee2MQTT, Tasmota, Shelly και ESPHome — με χαμηλές μπαταρίες, μία πρίζα εκτός δικτύου, έναν αισθητήρα που σιώπησε και διαθέσιμες ενημερώσεις.', 'Demo: 16 devices from Zigbee2MQTT, Tasmota, Shelly and ESPHome — with low batteries, one plug offline, one sensor gone silent and updates available.')}</div>` : ''}
      ${z.permit_join ? `<div class="ii-adv" style="--c:var(--orange)">⚠ ${T('Το Zigbee2MQTT έχει ανοιχτό το <b>permit join</b>: οποιαδήποτε συσκευή Zigbee κοντά μπορεί να μπει στο δίκτυο. Κλείσ’ το μόλις τελειώσεις τη σύζευξη.', 'Zigbee2MQTT has <b>permit join</b> open: any Zigbee device nearby can join the network. Close it as soon as you finish pairing.')}</div>` : ''}
      ${z.state === 'offline' ? `<div class="ii-adv" style="--c:var(--red)">⚠ ${T('Η γέφυρα Zigbee2MQTT δηλώνει <b>offline</b> — όλες οι συσκευές Zigbee είναι «τυφλές» μέχρι να ξαναξεκινήσει.', 'The Zigbee2MQTT bridge reports <b>offline</b> — every Zigbee device is blind until it restarts.')}</div>` : ''}`;
    if (c.total) {
      h += `<div class="ii-chips">${fchip('prob', '', c.total, T('όλες', 'all'))}${fchip('prob', 'off', c.offline || 0, T('εκτός δικτύου', 'offline'), 'var(--orange)')}${fchip('prob', 'batt', c.batt || 0, T('χαμηλή μπαταρία', 'low battery'), 'var(--yellow)')}${fchip('prob', 'weak', c.weak || 0, T('αδύναμο σήμα', 'weak signal'), 'var(--cyan)')}${fchip('prob', 'update', c.update || 0, T('με νέο firmware', 'firmware updates'), 'var(--cyan)')}</div>
        <div class="ii-chips" style="align-items:center"><input type="search" id="ii-q" placeholder="${T('αναζήτηση: όνομα, μοντέλο, IP, MAC…', 'search: name, model, IP, MAC…')}" value="${E(F.q)}">${Object.entries(c.by_src || {}).map(([s, n]) => fchip('src', s, n, E(((D.sources || {})[s] || {}).label || s))).join('')}</div>
        <div class="ii-wrap" id="ii-tbl">${table()}</div>`;
    }
    h += `</div>`;
    const shop = D.shopping || [];
    if (shop.length) {
      h += `<div class="card"><b>🛒 ${T('Μπαταρίες για αγορά', 'Batteries to buy')}</b><div class="dim" style="font-size:12.5px;margin-top:3px">${T('Συσκευές με μπαταρία ≤ 25% ή που σιώπησαν, ανά τύπο μπαταρίας.', 'Devices at ≤ 25% battery or gone silent, by battery type.')}</div><div class="ii-shop">`;
      for (const g of shop) h += `<div><b style="font-size:15px">${g.type ? E(g.qty) + '× ' + E(g.type) : T('Άγνωστος τύπος', 'Unknown type')}</b>${g.type ? '' : `<div class="dim" style="font-size:11.5px">${T('δες το εγχειρίδιο της συσκευής', 'check the device manual')}</div>`}
        ${g.devices.map(d => `<div style="margin-top:3px">${E(d.name)} <span class="dim">${d.batt == null ? '' : E(Math.round(d.batt)) + '%'}${d.model ? ' · ' + E(d.model) : ''}${g.type && d.qty > 1 ? ' · ' + E(d.qty) + '×' : ''}</span></div>`).join('')}</div>`;
      h += `</div></div>`;
    }
    if (c.total) {
      h += `<div class="card"><b>👉 ${T('Τι να κάνεις', 'What to do')}</b><ol>
        ${c.offline ? `<li>${T('<b>Εκτός δικτύου:</b> συσκευή με ρεύμα → έλεγξε πρίζα/ασφάλεια και αν πιάνει Wi-Fi εκεί· συσκευή μπαταρίας που σιωπά πάνω από ' + E(th.silent_h || 25) + ' ώρες → άλλαξε μπαταρία και πάτησε το κουμπί της για να ξαναμιλήσει.', '<b>Offline:</b> mains device → check the socket/breaker and Wi-Fi coverage there; battery device silent for over ' + E(th.silent_h || 25) + ' hours → replace the battery and press its button so it reports again.')}</li>` : ''}
        ${c.batt ? `<li>${T('<b>Χαμηλή μπαταρία (≤ ' + E(th.batt || 15) + '%):</b> άλλαξέ την τώρα — οι αισθητήρες Zigbee πεθαίνουν απότομα και ένας αισθητήρας διαρροής/πόρτας που σιωπά δεν σε προστατεύει. Η λίστα αγορών είναι παραπάνω.', '<b>Low battery (≤ ' + E(th.batt || 15) + '%):</b> replace it now — Zigbee sensors die abruptly and a silent leak/door sensor protects nothing. The shopping list is above.')}</li>` : ''}
        ${c.weak ? `<li>${T('<b>Αδύναμο σήμα:</b> Zigbee με LQI κάτω από ' + E(th.lqi || 40) + ' → βάλε έναν <b>router Zigbee</b> (πρίζα ή λάμπα με ρεύμα) ανάμεσα στη συσκευή και τον coordinator· οι συσκευές μπαταρίας δεν αναμεταδίδουν. Wi-Fi κάτω από ' + E(th.rssi || -80) + ' dBm → πιο κοντινό access point ή εξωτερική κεραία. Δες και την καρτέλα 📻 Ασύρματα IoT για συγκρούσεις Zigbee ↔ Wi-Fi.', '<b>Weak signal:</b> Zigbee with LQI below ' + E(th.lqi || 40) + ' → add a <b>Zigbee router</b> (mains plug or bulb) between the device and the coordinator; battery devices don’t repeat. Wi-Fi below ' + E(th.rssi || -80) + ' dBm → a closer access point or an external antenna. See also the 📻 Wireless IoT tab for Zigbee ↔ Wi-Fi collisions.')}</li>` : ''}
        ${c.update ? `<li>${T('<b>Νέο firmware:</b> πέρασέ το σε ώρα συντήρησης, μία συσκευή τη φορά (Zigbee2MQTT → OTA, Tasmota → Firmware Upgrade, Shelly → εφαρμογή/σελίδα της συσκευής). Κράτα πρώτα αντίγραφο ρυθμίσεων.', '<b>New firmware:</b> apply it in a maintenance window, one device at a time (Zigbee2MQTT → OTA, Tasmota → Firmware Upgrade, Shelly → app/device page). Back up the settings first.')}</li>` : ''}
        <li>${T('Ο broker πρέπει να έχει <b>TLS και χρήστη/κωδικό ανά συσκευή</b> (όχι anonymous, όχι κοινό κωδικό) και ACL ώστε κάθε συσκευή να γράφει μόνο στα δικά της topics — δες την καρτέλα <b>🦟 MQTT</b> για άγνωστους clients και νέα topics.', 'The broker must use <b>TLS and a user/password per device</b> (no anonymous, no shared password) plus ACLs so each device writes only to its own topics — see the <b>🦟 MQTT</b> tab for unknown clients and new topics.')}</li>
        <li>${T('Βάλε τα IoT σε <b>δικό τους VLAN / Wi-Fi</b> και κράτα αυτό το CSV στον φάκελο του πελάτη: μοντέλα, firmware και τύποι μπαταριών είναι το μισό συμβόλαιο συντήρησης.', 'Put IoT on <b>its own VLAN / Wi-Fi</b> and keep this CSV in the customer file: models, firmware and battery types are half of a maintenance contract.')}</li></ol></div>`;
    }
    if (!c.total || !m.connected) h += setup(m);
    const sel = document.activeElement && document.activeElement.id === 'ii-q' ? document.activeElement.selectionStart : null;
    b.innerHTML = h;
    if (sel != null) { const i = document.getElementById('ii-q'); if (i) { i.focus(); try { i.setSelectionRange(sel, sel); } catch (_) { /* ok */ } } }
  }
  const redrawTable = () => { const t = document.getElementById('ii-tbl'); if (t && D) t.innerHTML = table(); };

  function load() {
    return fetch('/api/kit/iotinv').then(r => r.json()).then(j => { D = j && typeof j === 'object' ? j : { error: 'off' }; draw(); }).catch(() => { D = { error: 'off' }; draw(); });
  }
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-iotinv [data-ii]'); if (!b || !D) return;
    if (b.dataset.ii === 'f') { const k = b.dataset.k, v = b.dataset.v; F[k] = F[k] === v ? '' : v; draw(); return; }
    if (b.dataset.ii === 'sort') { const k = b.dataset.k; S = S.k === k ? { k, d: -S.d } : { k, d: 1 }; redrawTable(); }
  });
  document.addEventListener('input', e => { if (e.target && e.target.id === 'ii-q') { F.q = e.target.value; redrawTable(); } });
  window.renderIotinv = () => { load(); clearInterval(timer); timer = setInterval(() => { const b = box(); if (b && b.offsetParent) load(); }, 30000); };
})();
