// ───────────────────────── 🏭 Αυτοματισμοί (OT): Modbus TCP · BACnet/IP · KNXnet/IP ─────────────────────────
// Μόνο ανάγνωση: βρίσκουμε ποιες συσκευές μιλούν αυτά τα πρωτόκολλα, και ειδοποιούμε όταν κάποιος ΓΡΑΦΕΙ σε αυτές.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const box = () => document.getElementById('t-ot');
  const API = '/api/kit/ot';
  const COL = { high: 'var(--red)', med: 'var(--orange)', low: 'var(--cyan)' };
  const LBL = { high: ['ανοιχτό σε όλους', 'open to anyone'], med: ['θέλει έλεγχο', 'needs a check'], low: ['χαμηλός κίνδυνος', 'low risk'] };
  const PROTO = {
    modbus: ['⚡', 'Modbus TCP', 'θύρα 502 · inverters, μετρητές ενέργειας, PLC', 'port 502 · inverters, energy meters, PLCs'],
    bacnet: ['🏢', 'BACnet/IP', 'UDP 47808 · κλιματισμός, ελεγκτές κτιρίου (BMS)', 'UDP 47808 · HVAC, building controllers (BMS)'],
    knx: ['💡', 'KNXnet/IP', 'UDP 3671 · φώτα, ρολά, πόρτες, θερμοστάτες', 'UDP 3671 · lights, blinds, doors, thermostats'] };
  let D = null, poll = null, R = null, reading = false;
  const F = { ip: '', unit: '1', kind: 'holding', addr: '0', count: '10' };

  const css = document.createElement('style');
  css.textContent = `
#t-ot .ot-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-ot .ot-big{font-size:34px}
#t-ot .ot-chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
#t-ot .ot-chip{font-size:12px;padding:3px 9px;border-radius:10px;background:rgb(var(--w,255 255 255) / 6%);white-space:nowrap}
#t-ot .ot-chip b{font-size:13px}
#t-ot .ot-grp{margin-top:12px;font-size:13px}
#t-ot .ot-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;align-items:start;border-left:3px solid var(--c);border-radius:10px;background:rgb(var(--w,255 255 255) / 3%);padding:10px 12px;margin-top:8px;font-size:13px}
#t-ot .ot-pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap}
#t-ot .ot-meta{font-size:12px;color:var(--dim);margin-top:2px;overflow-wrap:anywhere}
#t-ot .ot-mono{font-family:var(--mono,ui-monospace,monospace);font-size:12px}
#t-ot .ot-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-top:8px;align-items:end}
#t-ot .ot-form label{display:block;font-size:11.5px;color:var(--dim)}
#t-ot .ot-form input,#t-ot .ot-form select{width:100%;box-sizing:border-box;padding:6px 8px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 15%);background:transparent;color:inherit;font:inherit;font-size:13px}
#t-ot .ot-tw{overflow-x:auto;margin-top:10px}
#t-ot table{border-collapse:collapse;font-family:var(--mono,ui-monospace,monospace);font-size:12px;min-width:100%}
#t-ot th,#t-ot td{padding:3px 8px;text-align:right;white-space:nowrap;border-bottom:1px solid rgb(var(--w,255 255 255) / 6%)}
#t-ot th{color:var(--dim);font-weight:600}
#t-ot ol{margin:6px 0 0 18px;padding:0;font-size:13px}#t-ot li{margin:4px 0}
#t-ot details{margin-top:8px;font-size:13px}#t-ot summary{cursor:pointer;font-weight:600}
#t-ot details div{margin:6px 0 0 4px;line-height:1.55;color:var(--dim)}
@media (max-width:600px){#t-ot .ot-row{grid-template-columns:1fr}}
`;
  document.head.appendChild(css);

  const when = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : T('ποτέ', 'never');

  function devRow(d) {
    const c = COL[d.level] || 'var(--dim)', h = d.dev || {};
    const bits = [];
    if (d.proto === 'modbus') {
      if (d.unit != null) bits.push('unit ' + E(d.unit));
      if (d.rev) bits.push(T('έκδοση ', 'version ') + E(d.rev));
      if (d.serial) bits.push('S/N ' + E(d.serial));
      if (d.sunspec) bits.push('SunSpec');
      if (d.gateway) bits.push(T('πύλη Modbus (RTU πίσω της)', 'Modbus gateway (RTU behind it)'));
      if (d.passive) bits.push(T('φάνηκε στην κίνηση (χωρίς σάρωση)', 'seen in traffic (no scan)'));
      if (d.confirmed && !d.vendor && !d.passive) bits.push(T('Modbus ανοιχτό, δεν δίνει ταυτότητα', 'Modbus open, no identification'));
    } else if (d.proto === 'bacnet') {
      bits.push('device instance ' + E(d.instance), 'max APDU ' + E(d.max_apdu), T('τμηματοποίηση: ', 'segmentation: ') + E(d.seg), 'vendor id ' + E(d.vendor_id));
      if (d.snet != null) bits.push(T(`πίσω από router BACnet (δίκτυο ${E(d.snet)}, MAC ${E(d.sadr)})`, `behind a BACnet router (network ${E(d.snet)}, MAC ${E(d.sadr)})`));
    } else {
      bits.push(T('διεύθυνση KNX ', 'KNX address ') + E(d.addr), E(d.medium), 'S/N ' + E(d.serial), 'MAC ' + E(d.mac));
      bits.push('tunnelling: ' + (d.tunnelling ? T('ΝΑΙ', 'YES') : T('όχι', 'no')), 'routing: ' + (d.routing ? T('ΝΑΙ', 'YES') + ' (' + E(d.mcast) + ')' : T('όχι', 'no')), 'KNX Secure: ' + (d.secure ? T('υποστηρίζεται', 'supported') : T('όχι', 'no')));
      if (d.prog) bits.push(T('⚠ σε κατάσταση προγραμματισμού', '⚠ in programming mode'));
    }
    const who = h.name && h.name !== d.ip ? ` · ${E(h.dicon || '')} ${E(h.name)}${h.vendor ? ' (' + E(h.vendor) + ')' : ''}` : (h.vendor ? ' · ' + E(h.vendor) : '');
    return `<div class="ot-row" style="--c:${c}">
      <div><b>${E(d.title)}</b> <span class="dim ot-mono">${E(d.ip)}:${E(d.port)}</span><span class="dim">${who}</span>
        <div class="ot-meta">${bits.join(' · ')}</div>
        <div class="ot-meta">${T('πρώτη φορά', 'first seen')} ${when(d.since)}${d.stale ? ' · <span style="color:var(--orange)">' + T('δεν απάντησε στην τελευταία σάρωση', 'did not answer the last scan') + '</span>' : ''}</div>
        <div style="margin-top:4px">${E(T(d.why, d.why_en))}</div>
        ${d.proto === 'modbus' && d.confirmed ? `<button class="b" style="margin-top:6px" data-ot="pick" data-ip="${E(d.ip)}" data-unit="${E(d.unit == null ? 1 : d.unit)}">📖 ${T('Διάβασε registers', 'Read registers')}</button>` : ''}</div>
      <span class="ot-pill" style="--c:${c}">${T(...LBL[d.level] || LBL.low)}</span></div>`;
  }

  function writeRow(w) {
    const c = w.new ? 'var(--red)' : 'var(--dim)';
    const nm = (ip, n) => n && n !== ip ? `${E(n)} <span class="dim ot-mono">${E(ip)}</span>` : `<span class="ot-mono">${E(ip)}</span>`;
    return `<div class="ot-row" style="--c:${c}">
      <div>✍️ ${nm(w.src, w.src_name)} → ${nm(w.dst, w.dst_name)} <span class="dim">· ${w.proto === 'bacnet' ? 'BACnet' : 'Modbus'}</span>
        <div class="ot-meta ot-mono">${E(T(w.what, w.what_en))}</div>
        <div class="ot-meta">${T('τελευταία', 'last')} ${when(w.t)} · ${E(w.n || 1)}× ${T('από', 'since')} ${when(w.first)}</div></div>
      <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap"><span class="ot-pill" style="--c:${c}">${w.new ? T('νέος συγγραφέας', 'new writer') : T('γνωστός', 'known')}</span>
        ${D.demo ? '' : `<button class="b" data-ot="forget" data-src="${E(w.src)}" data-dst="${E(w.dst)}" title="${T('Ξέχασέ τον: θα ειδοποιήσω ξανά αν ξαναγράψει', 'Forget: I will alert again if it writes again')}">🗑</button>`}</div></div>`;
  }

  const num = v => v == null ? '—' : E(v);
  function readResult() {
    if (reading) return `<div class="dim" style="margin-top:8px">${T('διαβάζω…', 'reading…')}</div>`;
    if (!R) return '';
    if (!R.ok) return `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${E(T(R.error, R.error_en) || T('Η ανάγνωση απέτυχε.', 'The read failed.'))}</div>`;
    const head = `<div class="ot-meta" style="margin-top:8px">${E(R.ip)} · unit ${E(R.unit)} · FC ${E(R.fc)} · ${T('διεύθυνση', 'address')} ${E(R.addr)} · ${E(R.count)} ${R.demo ? '· demo' : ''}</div>`;
    if (R.bits) return head + `<div class="ot-tw"><table><tr><th>${T('διεύθ.', 'addr')}</th><th>bit</th></tr>${R.bits.map(b => `<tr><td>${E(b.addr)}</td><td>${b.bit ? '1 ●' : '0 ○'}</td></tr>`).join('')}</table></div>`;
    return head + `<div class="ot-tw"><table><tr><th>${T('διεύθ.', 'addr')}</th><th>hex</th><th>uint16</th><th>int16</th><th>float32 AB·CD</th><th>float32 CD·AB</th><th>int32 AB·CD</th><th>int32 CD·AB</th><th>uint32 AB·CD</th><th>uint32 CD·AB</th></tr>
      ${(R.rows || []).map(r => `<tr><td>${E(r.addr)}</td><td>${E(r.hex)}</td><td>${E(r.u16)}</td><td>${E(r.s16)}</td><td>${num(r.f32)}</td><td>${num(r.f32_sw)}</td><td>${num(r.s32)}</td><td>${num(r.s32_sw)}</td><td>${num(r.u32)}</td><td>${num(r.u32_sw)}</td></tr>`).join('')}</table></div>
      <div class="ot-meta" style="margin-top:6px">${T('Οι στήλες 32-bit ενώνουν αυτόν τον register με τον επόμενο. «AB·CD» = πρώτα η υψηλή λέξη (big-endian), «CD·AB» = ανάποδα (word swap) — δες ποια βγάζει λογική τιμή (π.χ. 230 V, 50 Hz).', 'The 32-bit columns join this register with the next one. “AB·CD” = high word first (big-endian), “CD·AB” = swapped — see which gives a sensible value (e.g. 230 V, 50 Hz).')}</div>`;
  }

  function readCard() {
    const ips = (D.devices || []).filter(d => d.proto === 'modbus').map(d => d.ip);
    const opt = (v, el, en) => `<option value="${v}"${F.kind === v ? ' selected' : ''}>${T(el, en)}</option>`;
    return `<div class="card" id="ot-read"><b>📖 ${T('Διάβασε registers (Modbus)', 'Read registers (Modbus)')}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${T('Μόνο ανάγνωση (FC 1–4), μόνο σε ιδιωτική IP, έως 125 τιμές. Δεν γράφω ποτέ στη συσκευή.', 'Read-only (FC 1–4), private IPs only, up to 125 values. I never write to the device.')}</div>
      <div class="ot-form">
        <div><label>IP</label><input data-of="ip" list="ot-ips" value="${E(F.ip)}" placeholder="192.168.1.60" inputmode="decimal" autocomplete="off"><datalist id="ot-ips">${ips.map(i => `<option value="${E(i)}">`).join('')}</datalist></div>
        <div><label>Unit ID</label><input data-of="unit" type="number" min="0" max="255" value="${E(F.unit)}"></div>
        <div><label>${T('Τύπος', 'Type')}</label><select data-of="kind">${opt('holding', 'Holding registers (FC 3)', 'Holding registers (FC 3)')}${opt('input', 'Input registers (FC 4)', 'Input registers (FC 4)')}${opt('coil', 'Coils (FC 1)', 'Coils (FC 1)')}${opt('discrete', 'Discrete inputs (FC 2)', 'Discrete inputs (FC 2)')}</select></div>
        <div><label>${T('Διεύθυνση (από 0)', 'Address (0-based)')}</label><input data-of="addr" type="number" min="0" max="65535" value="${E(F.addr)}"></div>
        <div><label>${T('Πλήθος (1–125)', 'Count (1–125)')}</label><input data-of="count" type="number" min="1" max="125" value="${E(F.count)}"></div>
        <div><button class="b" data-ot="read"${reading ? ' disabled' : ''}>📖 ${T('Διάβασε', 'Read')}</button></div>
      </div>
      <div class="ot-meta" style="margin-top:6px">${T('Συμβουλή: τα εγχειρίδια γράφουν συχνά «40001» για τον πρώτο holding register — εδώ είναι διεύθυνση 0 (40071 → 70). Inverters με SunSpec: διεύθυνση 40000, unit 1.', 'Tip: manuals often write “40001” for the first holding register — here that is address 0 (40071 → 70). SunSpec inverters: address 40000, unit 1.')}</div>
      <div id="ot-res">${readResult()}</div></div>`;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error === 'off' || !D.counts) { b.innerHTML = `<div class="card">${T('Δεν είναι διαθέσιμο σε αυτή τη λειτουργία (π.χ. ανάλυση pcap ή στατικό demo).', 'Not available in this mode (e.g. pcap analysis or the static demo).')}</div>`; return; }
    const ds = D.devices || [], c = D.counts || {}, ws = D.writes || [];
    const newW = ws.filter(w => w.new).length;
    const icon = D.busy ? '⏳' : !D.scanned && !ds.length ? '🏭' : newW ? '🚨' : c.high ? '⚠️' : ds.length ? '🏭' : '✅';
    const head = D.busy ? T('Ψάχνω συσκευές αυτοματισμού…', 'Looking for automation devices…')
      : !D.scanned && !ds.length ? T('Δεν έχει γίνει ακόμη σάρωση — πάτα «Σάρωση τώρα»', 'No scan yet — press “Scan now”')
        : !ds.length ? T('Καμία συσκευή Modbus / BACnet / KNX σε αυτό το δίκτυο', 'No Modbus / BACnet / KNX device on this network')
          : T(`${ds.length} συσκευές αυτοματισμού · ${c.high || 0} ανοιχτές σε όποιον είναι στο δίκτυο`, `${ds.length} automation devices · ${c.high || 0} open to anyone on the network`);
    let h = `<div class="card"><div class="ot-hero"><span class="ot-big">${icon}</span><div style="flex:1;min-width:230px">
      <b style="font-size:16px">${head}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${T('σάρωση', 'scanned')} ${D.demo ? 'demo' : when(D.scanned)}${D.hosts ? ' · ' + T(`${E(D.hosts)} γνωστές συσκευές θα ερωτηθούν στη θύρα 502`, `${E(D.hosts)} known devices will be asked on port 502`) : ''}</div>
      <div class="ot-chips"><span class="ot-chip">⚡ Modbus <b>${E(c.modbus || 0)}</b></span><span class="ot-chip">🏢 BACnet <b>${E(c.bacnet || 0)}</b></span><span class="ot-chip">💡 KNX <b>${E(c.knx || 0)}</b></span>
        <span class="ot-chip" style="color:var(--red)">${T('υψηλός κίνδυνος', 'high risk')} <b>${E(c.high || 0)}</b></span><span class="ot-chip" style="color:var(--orange)">${T('μέτριος', 'medium')} <b>${E(c.med || 0)}</b></span>
        <span class="ot-chip">✍️ ${T('γνωστοί «συγγραφείς»', 'known writers')} <b>${E(D.writers || 0)}</b></span></div></div>
      <button class="b" data-ot="scan"${D.busy ? ' disabled' : ''}>🔍 ${D.busy ? T('σαρώνω…', 'scanning…') : T('Σάρωση τώρα', 'Scan now')}</button></div>
      ${D.demo ? `<div class="dim" style="font-size:12.5px;margin-top:8px">🧪 ${T('Demo: παράδειγμα από μικρό κτίριο με φωτοβολταϊκά, μετρητή ενέργειας, κλιματισμό και KNX.', 'Demo: example from a small building with PV, an energy meter, HVAC and KNX.')}</div>` : ''}
      ${D.error ? `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${E(D.error)}</div>` : ''}
      <div class="dim" style="font-size:12.5px;margin-top:8px;line-height:1.55">${T('Inverters, μετρητές, PLC, κλιματιστικά και ελεγκτές κτιρίου μιλούν πρωτόκολλα που φτιάχτηκαν για κλειστά δίκτυα: <b>δεν έχουν κωδικό</b>. Εδώ <b>μόνο ρωτάω</b> «ποιος είσαι;» (ποτέ εγγραφή) και παρακολουθώ την κίνηση: αν κάποιος στείλει <b>εντολή εγγραφής</b> σε PLC ή ελεγκτή, θα σε ειδοποιήσω — μία φορά για κάθε νέο ζεύγος «ποιος → σε ποιον».',
        'Inverters, meters, PLCs, HVAC units and building controllers speak protocols built for closed networks: they have <b>no password</b>. Here I <b>only ask</b> “who are you?” (never a write) and watch the traffic: if someone sends a <b>write command</b> to a PLC or controller I alert you — once for every new “who → to whom” pair.')}</div></div>`;

    if (ds.length) {
      h += `<div class="card"><b>${T('Συσκευές αυτοματισμού που βρήκα', 'Automation devices found')}</b>`;
      for (const p of ['modbus', 'bacnet', 'knx']) {
        const g = ds.filter(d => d.proto === p); if (!g.length) continue;
        h += `<div class="ot-grp"><b>${PROTO[p][0]} ${PROTO[p][1]}</b> <span class="dim">· ${T(PROTO[p][2], PROTO[p][3])} · ${g.length}</span></div>${g.map(devRow).join('')}`;
      }
      h += '</div>';
    }

    h += `<div class="card"><b>✍️ ${T('Ποιος γράφει σε PLC / ελεγκτές', 'Who writes to PLCs / controllers')}</b>
      ${ws.length ? ws.map(writeRow).join('') : `<div class="empty" style="margin-top:8px">${T('Δεν έχω δει καμία εντολή εγγραφής. (Βλέπω μόνο όση κίνηση περνά από αυτόν τον υπολογιστή — για πλήρη εικόνα βάλε το NetWatch σε mirror/SPAN port του switch του OT.)', 'No write command seen. (I only see traffic passing this computer — for the full picture put NetWatch on a mirror/SPAN port of the OT switch.)')}</div>`}
      <div class="ot-meta" style="margin-top:8px">👉 ${T('Κόκκινο = πρώτη φορά που αυτή η πηγή γράφει εκεί. Αν είναι το SCADA/HMI/BMS σου, άφησέ το (δεν θα ξαναειδοποιήσω). Αν ΔΕΝ το αναγνωρίζεις: βρες τη συσκευή στην καρτέλα Συσκευές, αποσύνδεσέ τη και βάλε ACL στη θύρα 502 / 47808.', 'Red = the first time this source writes there. If it is your SCADA/HMI/BMS, leave it (I will not alert again). If you do NOT recognise it: find the device in the Devices tab, unplug it and put an ACL on port 502 / 47808.')}</div></div>`;

    h += readCard();

    h += `<div class="card"><b>👉 ${T('Τι να κάνεις', 'What to do')}</b><ol>
      <li>${T('Βάλε όλα τα OT (inverters, μετρητές, PLC, BMS, KNX IP) σε <b>ξεχωριστό VLAN</b> — όχι στο ίδιο δίκτυο με PC, Wi‑Fi επισκεπτών ή κάμερες.', 'Put all OT (inverters, meters, PLCs, BMS, KNX IP) on a <b>separate VLAN</b> — not on the same network as PCs, guest Wi‑Fi or cameras.')}</li>
      <li>${T('Στο router/L3 switch: <b>ACL</b> που αφήνει μόνο το SCADA/HMI/BMS να μιλά στη θύρα 502 (και UDP 47808 / 3671) — όλα τα άλλα κόβονται.', 'On the router/L3 switch: an <b>ACL</b> that lets only the SCADA/HMI/BMS talk to port 502 (and UDP 47808 / 3671) — everything else is dropped.')} <code class="ot-mono">permit tcp host 192.168.1.10 192.168.50.0 0.0.0.255 eq 502</code></li>
      <li>${T('<b>Ποτέ port forwarding</b> των 502, 47808 ή 3671 προς το Internet (ούτε «προσωρινά» για τον εγκαταστάτη). Για απομακρυσμένη πρόσβαση: VPN (π.χ. WireGuard).', '<b>Never port-forward</b> 502, 47808 or 3671 to the Internet (not even “temporarily” for the installer). For remote access: a VPN (e.g. WireGuard).')}</li>
      <li>${T('Modbus: αν πρέπει να το διαβάζουν πολλοί, βάλε <b>Modbus gateway / firewall</b> που επιτρέπει μόνο ανάγνωση (FC 1–4) και κόβει τις εγγραφές — ή χρησιμοποίησε τη «read-only» ρύθμιση της συσκευής, αν έχει.', 'Modbus: if many systems must read it, add a <b>Modbus gateway / firewall</b> that allows reads only (FC 1–4) and blocks writes — or use the device’s “read-only” setting if it has one.')}</li>
      <li>${T('BACnet: σε νέες εγκαταστάσεις ζήτα <b>BACnet/SC</b> (TLS με πιστοποιητικά). Στις παλιές: BBMD μόνο όπου χρειάζεται, και κλείδωσε το 47808 στο VLAN του BMS.', 'BACnet: on new installations ask for <b>BACnet/SC</b> (TLS with certificates). On old ones: BBMD only where needed, and confine 47808 to the BMS VLAN.')}</li>
      <li>${T('KNX: ενεργοποίησε <b>KNX IP Secure</b> στο ETS (κωδικός tunnelling + backbone key) και, αν η συσκευή δεν το υποστηρίζει, άλλαξέ τη ή απομόνωσέ τη — ένα ανοιχτό tunnelling είναι «κλειδί» για φώτα και πόρτες.', 'KNX: enable <b>KNX IP Secure</b> in ETS (tunnelling password + backbone key); if the device does not support it, replace or isolate it — open tunnelling is a “key” to lights and doors.')}</li></ol></div>`;

    h += `<div class="card"><b>🎓 ${T('Με δυο λόγια, για όποιον τα βλέπει πρώτη φορά', 'In a nutshell, if you are new to these')}</b>
      <details><summary>⚡ Modbus TCP</summary><div>${T('Το πιο απλό βιομηχανικό πρωτόκολλο (1979). Ένας <b>client</b> (SCADA, logger) ρωτά έναν <b>server</b> (inverter, μετρητή, PLC) στη θύρα TCP 502. Τα δεδομένα είναι αριθμημένα κουτάκια: <b>coils</b> (1 bit, γράφονται), <b>discrete inputs</b> (1 bit, μόνο ανάγνωση), <b>holding registers</b> (16 bit, γράφονται), <b>input registers</b> (16 bit, μόνο ανάγνωση). Το <b>unit id</b> λέει σε ποια συσκευή πίσω από μια πύλη RS‑485 απευθύνεσαι (1–247· 255 = η ίδια η συσκευή TCP). Τιμές 32 bit (float, kWh) πιάνουν δύο registers — και κάθε κατασκευαστής διαλέγει σειρά λέξεων. Δεν υπάρχει login: όποιος φτάνει στη θύρα 502 μπορεί να γράψει.',
        'The simplest industrial protocol (1979). A <b>client</b> (SCADA, logger) asks a <b>server</b> (inverter, meter, PLC) on TCP port 502. Data are numbered boxes: <b>coils</b> (1 bit, writable), <b>discrete inputs</b> (1 bit, read-only), <b>holding registers</b> (16 bit, writable), <b>input registers</b> (16 bit, read-only). The <b>unit id</b> selects which device behind an RS‑485 gateway you address (1–247; 255 = the TCP device itself). 32-bit values (float, kWh) take two registers — and each vendor picks its own word order. There is no login: whoever reaches port 502 can write.')}</div></details>
      <details><summary>🏢 BACnet/IP</summary><div>${T('Το πρωτόκολλο των κτιρίων (κλιματισμός, αερισμός, φωτισμός, μετρητές). Κάθε συσκευή έχει μοναδικό <b>device instance</b> και μια λίστα <b>objects</b> (analog-input = αισθητήρας, analog-value = setpoint, binary-output = ρελέ, schedule = πρόγραμμα) με <b>properties</b> (π.χ. present-value). Η ανακάλυψη γίνεται με broadcast <b>Who‑Is</b> → <b>I‑Am</b> στο UDP 47808. Οι εντολές που αλλάζουν κάτι είναι <b>WriteProperty</b>, <b>ReinitializeDevice</b> (επανεκκίνηση) και <b>DeviceCommunicationControl</b> (σίγαση). Το κλασικό BACnet/IP δεν έχει ταυτοποίηση· η ασφαλής εκδοχή λέγεται <b>BACnet/SC</b>.',
        'The building protocol (HVAC, ventilation, lighting, meters). Every device has a unique <b>device instance</b> and a list of <b>objects</b> (analog-input = sensor, analog-value = setpoint, binary-output = relay, schedule) with <b>properties</b> (e.g. present-value). Discovery is a broadcast <b>Who‑Is</b> → <b>I‑Am</b> on UDP 47808. The commands that change things are <b>WriteProperty</b>, <b>ReinitializeDevice</b> (restart) and <b>DeviceCommunicationControl</b> (silence). Classic BACnet/IP has no authentication; the secure flavour is <b>BACnet/SC</b>.')}</div></details>
      <details><summary>💡 KNXnet/IP</summary><div>${T('Το KNX είναι ο ευρωπαϊκός δίαυλος για φώτα, ρολά, θερμοστάτες και πόρτες (πράσινο καλώδιο TP). Μια συσκευή <b>KNX IP interface/router</b> το ενώνει με το Ethernet στο UDP 3671. <b>Tunnelling</b> = ένας υπολογιστής (ETS, εφαρμογή κινητού) «μπαίνει» στον δίαυλο μέσω IP· <b>Routing</b> = τα τηλεγραφήματα ταξιδεύουν με multicast 224.0.23.12 ανάμεσα σε γραμμές. Κάθε συσκευή έχει <b>φυσική διεύθυνση</b> (π.χ. 1.1.250) και οι λειτουργίες έχουν <b>group addresses</b> (π.χ. 1/2/3 = «φως σαλονιού»). Χωρίς <b>KNX Secure</b>, όποιος φτάνει στο 3671 μπορεί να στείλει οποιοδήποτε τηλεγράφημα.',
        'KNX is the European bus for lights, blinds, thermostats and doors (green TP cable). A <b>KNX IP interface/router</b> joins it to Ethernet on UDP 3671. <b>Tunnelling</b> = a computer (ETS, a phone app) “enters” the bus over IP; <b>Routing</b> = telegrams travel by multicast 224.0.23.12 between lines. Each device has an <b>individual address</b> (e.g. 1.1.250) and functions have <b>group addresses</b> (e.g. 1/2/3 = “living-room light”). Without <b>KNX Secure</b>, whoever reaches 3671 can send any telegram.')}</div></details></div>`;
    const open = [...b.querySelectorAll('details')].map(d => d.open);
    b.innerHTML = h;
    b.querySelectorAll('details').forEach((d, i) => { d.open = !!open[i]; });
  }

  const post = (sub, body) => fetch(`${API}/${sub}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then(r => r.json());
  const typing = () => { const a = document.activeElement; return !!(a && a.closest && a.closest('#t-ot .ot-form')); };

  function load() {
    return fetch(API).then(r => r.json()).then(j => {
      D = j; if (!typing()) draw();
      if (D.busy && !poll) poll = setInterval(load, 1500);
      if (!D.busy && poll) { clearInterval(poll); poll = null; draw(); }
    }).catch(() => { D = { error: 'off' }; if (poll) { clearInterval(poll); poll = null; } draw(); });
  }

  function doRead() {
    reading = true; R = null; draw();
    post('read', { ip: F.ip.trim(), unit: Number(F.unit), kind: F.kind, addr: Number(F.addr), count: Number(F.count) })
      .then(j => { R = j && typeof j === 'object' ? j : { ok: false }; })
      .catch(() => { R = { ok: false, error: 'Δεν έφτασα στο NetWatch.', error_en: 'Could not reach NetWatch.' }; })
      .then(() => { reading = false; draw(); });
  }

  document.addEventListener('input', e => {
    const i = e.target.closest && e.target.closest('#t-ot [data-of]'); if (i) F[i.dataset.of] = i.value;
  });
  document.addEventListener('change', e => {
    const i = e.target.closest && e.target.closest('#t-ot [data-of]'); if (i) F[i.dataset.of] = i.value;
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.target.closest && e.target.closest('#t-ot .ot-form input') && !reading) { e.preventDefault(); doRead(); }
  });
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-ot [data-ot]'); if (!b || !D) return;
    const a = b.dataset.ot;
    if (a === 'scan') {
      b.disabled = true;
      post('scan').then(j => { D = j; draw(); if (D.busy && !poll) poll = setInterval(load, 1500); }).catch(() => { b.disabled = false; });
    } else if (a === 'pick') {
      F.ip = b.dataset.ip || ''; F.unit = b.dataset.unit || '1'; R = null; draw();
      const c = document.getElementById('ot-read'); if (c && c.scrollIntoView) c.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } else if (a === 'read') {
      doRead();
    } else if (a === 'forget') {
      b.disabled = true;
      post('forget', { src: b.dataset.src, dst: b.dataset.dst }).then(j => { if (j && j.counts) { D = j; draw(); } }).catch(() => { b.disabled = false; });
    }
  });
  window.renderOt = () => load();
})();
