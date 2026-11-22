// ───────────────────────── 📻 Ασύρματα IoT: Bluetooth LE · Zigbee/Thread (802.15.4) · LoRa ─────────────────────────
// Μόνο ανάγνωση: ό,τι «ακούνε» οι αισθητήρες της καρτέλας 🧩 Οι συσκευές μου (σαρωτής BLE, sniffer nRF52840, πύλη LoRa).
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const L = o => E(EN() ? (o.en || o.el) : o.el);
  const box = () => document.getElementById('t-radio');
  const COL = { med: 'var(--orange)', low: 'var(--yellow)', info: 'var(--cyan)', high: 'var(--red)' };
  let D = null, timer = null, showAll = false;

  const css = document.createElement('style');
  css.textContent = `
#t-radio .rd-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-radio .rd-big{font-size:34px}
#t-radio .rd-chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
#t-radio .rd-chip{font-size:12px;padding:3px 9px;border-radius:9px;background:rgb(var(--w,255 255 255) / 7%)}
#t-radio .rd-chip b{font-size:13px}
#t-radio .rd-pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);white-space:nowrap;display:inline-block;margin:1px 0}
#t-radio{min-width:0}
#t-radio .card{min-width:0;max-width:100%}
#t-radio .rd-wrap{overflow-x:auto;margin-top:8px}
#t-radio table{border-collapse:collapse;width:100%;font-size:12.5px;min-width:520px}
#t-radio th{text-align:left;font-weight:600;color:var(--dim);font-size:11.5px;padding:4px 8px;border-bottom:1px solid rgb(var(--w,255 255 255) / 12%);white-space:nowrap}
#t-radio td{padding:6px 8px;border-bottom:1px solid rgb(var(--w,255 255 255) / 6%);vertical-align:top}
#t-radio tr.rd-hot td:first-child{box-shadow:inset 3px 0 0 var(--orange)}
#t-radio tr.rd-off{opacity:.55}
#t-radio .rd-mono{font-family:var(--mono,ui-monospace,monospace);font-size:11.5px}
#t-radio .rd-flag{font-size:12px;margin-top:2px;color:var(--c)}
#t-radio .rd-sig{display:inline-block;width:46px;height:6px;border-radius:3px;background:rgb(var(--w,255 255 255) / 10%);vertical-align:middle;margin-right:6px;overflow:hidden}
#t-radio .rd-sig i{display:block;height:100%;background:var(--c)}
#t-radio .rd-adv{border-left:3px solid var(--c);border-radius:8px;background:rgb(var(--w,255 255 255) / 3%);padding:8px 10px;margin-top:8px;font-size:13px;line-height:1.5}
#t-radio ol{margin:6px 0 0 18px;padding:0;font-size:13px}#t-radio li{margin:3px 0}
#t-radio svg.rd-chart{width:100%;height:auto;margin-top:8px;display:block}
#t-radio svg.rd-chart text{font-size:10px;fill:var(--dim);font-family:inherit}
#t-radio input[type=text]{padding:5px 9px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 15%);background:transparent;color:inherit;width:130px}
#t-radio .rd-h{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
#t-radio .rd-h b{font-size:15px}
#t-radio .b.rd-s{padding:2px 7px;font-size:11.5px}
#t-radio code{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px}
`;
  document.head.appendChild(css);

  const ago = t => { if (!t) return T('ποτέ', 'never'); const s = Math.max(0, Date.now() / 1000 - t); return s < 90 ? T(`πριν ${Math.round(s)}″`, `${Math.round(s)}s ago`) : s < 5400 ? T(`πριν ${Math.round(s / 60)}′`, `${Math.round(s / 60)} min ago`) : s < 172800 ? T(`πριν ${Math.round(s / 3600)} ώρ.`, `${Math.round(s / 3600)} h ago`) : T(`πριν ${Math.round(s / 86400)} μέρες`, `${Math.round(s / 86400)} days ago`); };
  const secs = s => s == null ? '—' : s < 90 ? `${Math.round(s)}″` : s < 5400 ? `${Math.round(s / 60)}′` : T(`${Math.round(s / 3600)} ώρ.`, `${Math.round(s / 3600)} h`);
  const chip = (n, txt, col) => `<span class="rd-chip"${col ? ` style="color:${col}"` : ''}><b>${E(n)}</b> ${txt}</span>`;
  // μπάρα σήματος: lo…hi dBm → 0…100%
  const sig = (v, lo, hi, unit) => {
    if (v == null) return '<span class="dim">—</span>';
    const p = Math.max(4, Math.min(100, (v - lo) / (hi - lo) * 100)), c = p < 30 ? 'var(--red)' : p < 55 ? 'var(--orange)' : 'var(--green)';
    return `<span class="rd-sig" style="--c:${c}"><i style="width:${p.toFixed(0)}%"></i></span>${E(v)}${unit ? ' ' + unit : ''}`;
  };
  const flags = fs => (fs || []).map(f => `<div class="rd-flag" style="--c:${COL[f.sev] || 'var(--dim)'}">${f.sev === 'info' ? 'ℹ' : '⚠'} ${L(f)}</div>`).join('');
  const sensors = (list, el, en) => (list || []).length ? `<span class="dim" style="font-size:12px">${(list || []).map(s => `${s.fresh ? '🟢' : '⚪'} ${E(s.name)} · ${ago(s.seen)}`).join(' &nbsp; ')}</span>` : `<span class="dim" style="font-size:12px">${T(el, en)}</span>`;
  const fleet = () => `<b>🧩 ${T('Οι συσκευές μου', 'My devices')}</b>`;

  // ── Bluetooth ──
  function ble(b) {
    const c = b.counts || {}, all = b.devices || [];
    const rows = showAll ? all : all.filter(d => d.now || d.unknown).slice(0, 40);
    let h = `<div class="card"><div class="rd-h"><b>🔵 Bluetooth LE</b>${sensors(b.scanners, 'κανένας σαρωτής BLE ακόμα', 'no BLE scanner yet')}</div>`;
    if (!(b.scanners || []).length && !all.length) {
      return h + `<div class="empty" style="margin-top:8px">${T('Σύζευξε έναν <b>Σαρωτή Bluetooth (ESP32)</b> στην καρτέλα', 'Pair a <b>Bluetooth scanner (ESP32)</b> in the')} ${fleet()}${EN() ? ' tab' : ''} ${T('— firmware <code>firmware/esp32-ble</code>. Με έναν ανά δωμάτιο βλέπεις και «πού περίπου» είναι κάθε συσκευή.', '— firmware <code>firmware/esp32-ble</code>. With one per room you also see roughly where each device is.')}</div></div>`;
    }
    h += `<div class="rd-chips">${chip(c.now || 0, T('κοντά τώρα', 'nearby now'))}${chip(c.trackers || 0, 'trackers')}${c.unknown_trackers ? chip(c.unknown_trackers, T('άγνωστα trackers', 'unknown trackers'), c.staying ? 'var(--orange)' : 'var(--yellow)') : ''}${c.pairing ? chip(c.pairing, T('σε pairing;', 'pairing?'), 'var(--cyan)') : ''}${chip(c.churn || 0, T('κινητά/λάπτοπ με τυχαία διεύθυνση (δεν τα απαριθμώ)', 'phones/laptops with random addresses (not listed)'))}</div>`;
    h += `<div class="rd-wrap"><table><thead><tr><th>${T('Τι είναι', 'What')}</th><th>${T('Όνομα / διεύθυνση', 'Name / address')}</th><th>${T('Σήμα', 'Signal')}</th><th>${T('Πού (περίπου)', 'Where (roughly)')}</th><th>${T('Το βλέπω', 'Seen')}</th><th></th></tr></thead><tbody>`;
    for (const d of rows) {
      const known = d.mode === 'known', ign = d.mode === 'ignored';
      h += `<tr class="${d.stays ? 'rd-hot' : ''}${d.now ? '' : ' rd-off'}"><td>${E(d.icon)} ${E(EN() ? d.kind_en : d.kind_el)}${d.vendor ? `<div class="dim" style="font-size:11.5px">${E(d.vendor)}</div>` : ''}</td>
        <td><b>${E(d.label || d.name || '—')}</b>${d.label && d.name ? ` <span class="dim">(${E(d.name)})</span>` : ''}${known ? ` <span class="rd-pill" style="--c:var(--green)">${T('δικό μου', 'mine')}</span>` : ign ? ` <span class="rd-pill" style="--c:var(--dim)">${T('αγνοείται', 'ignored')}</span>` : ''}
          <div class="rd-mono dim">${E(d.mac)}${d.rnd ? ' · ' + T('τυχαία', 'random') : ''}</div>${flags(d.flags)}</td>
        <td style="white-space:nowrap">${d.now ? sig(d.rssi, -100, -40, 'dBm') : '<span class="dim">' + T('όχι τώρα', 'not now') + '</span>'}</td>
        <td>${d.now ? E(d.where) + (d.scanners > 1 ? ` <span class="dim">(+${d.scanners - 1})</span>` : '') : ''}</td>
        <td style="white-space:nowrap">${T('από', 'since')} ${ago(d.first)}<div class="dim" style="font-size:11.5px">${E(d.hits)}× · ${T('τελευταία', 'last')} ${ago(d.last)}</div></td>
        <td style="white-space:nowrap">${d.mode ? `<button class="b rd-s" data-rd="known" data-mode="" data-mac="${E(d.mac)}" title="${T('Ξανά άγνωστο', 'Mark unknown again')}">↩</button>` : `<button class="b rd-s" data-rd="known" data-mode="known" data-mac="${E(d.mac)}" title="${T('Είναι δικό μου / γνωστό', 'It is mine / known')}">✔ ${T('γνωστό', 'known')}</button> <button class="b rd-s" data-rd="known" data-mode="ignored" data-mac="${E(d.mac)}" title="${T('Αγνόησέ το (π.χ. του γείτονα)', 'Ignore it (e.g. the neighbour’s)')}">🔕</button>`}</td></tr>`;
    }
    if (!rows.length) h += `<tr><td colspan="6" class="dim">${T('Καμία συσκευή κοντά αυτή τη στιγμή.', 'No device nearby right now.')}</td></tr>`;
    h += `</tbody></table></div>`;
    if (all.length > rows.length || showAll) h += `<div style="margin-top:6px"><button class="b rd-s" data-rd="all">${showAll ? T('Μόνο όσα είναι κοντά τώρα', 'Only those nearby now') : T(`Δείξε και τα ${all.length - rows.length} που δεν είναι κοντά τώρα`, `Also show the ${all.length - rows.length} not nearby now`)}</button></div>`;
    const th = b.thresholds || {};
    h += `<div class="rd-adv" style="--c:var(--cyan)"><b>👉 ${T('Τι να κάνεις', 'What to do')}</b><ol>
      <li>${T(`Σημείωσε ως <b>✔ γνωστό</b> τα trackers που ανήκουν σε ανθρώπους του χώρου (κλειδιά, τσάντες). Για ό,τι άγνωστο tracker μείνει κοντά πάνω από ${E(th.hours || 2)} ώρες βγαίνει ειδοποίηση — μία φορά ανά συσκευή.`, `Mark trackers that belong to people on site (keys, bags) as <b>✔ known</b>. Any unknown tracker that stays nearby for more than ${E(th.hours || 2)} hours raises an alert — once per device.`)}</li>
      <li>${T('Άγνωστο tracker που «μένει»; Η στήλη <b>Πού</b> δείχνει ποιος σαρωτής το ακούει πιο δυνατά — ψάξε εκεί (rack, ψευδοροφή, όχημα, δέμα). Ένα AirTag χωρισμένο από τον ιδιοκτήτη του χτυπάει μόνο του μετά από ώρες· με iPhone/Android το βρίσκεις από «Εύρεση» / «Ανιχνευτής άγνωστων trackers».', 'An unknown tracker that stays? The <b>Where</b> column shows which scanner hears it loudest — look there (rack, ceiling void, vehicle, parcel). An AirTag separated from its owner chirps by itself after some hours; an iPhone/Android finds it via “Find My” / “Unknown tracker alerts”.')}</li>
      <li>${T('<b>«σε λειτουργία pairing;»</b> = συσκευή που μόλις εμφανίστηκε και δέχεται σύνδεση από οποιονδήποτε. Για κλειδαριές, θερμοστάτες, POS και ιατρικά: ολοκλήρωσε τη σύζευξη ή κλείσε το Bluetooth αν δεν χρειάζεται.', '<b>“in pairing mode?”</b> = a device that just appeared and accepts a connection from anyone. For locks, thermostats, POS and medical gear: finish pairing, or turn Bluetooth off if it isn’t needed.')}</li>
      <li class="dim">${T('Τα κινητά αλλάζουν διεύθυνση κάθε ~15 λεπτά για ιδιωτικότητα — γι’ αυτό μετριούνται, δεν απαριθμούνται. Το RSSI είναι ένδειξη, όχι απόσταση.', 'Phones rotate their address every ~15 minutes for privacy — so they are counted, not listed. RSSI is a hint, not a distance.')}</li></ol></div></div>`;
    return h;
  }

  // ── 802.15.4: ραβδόγραμμα καναλιών με σκιασμένες τις ζώνες Wi-Fi ──
  function chart(z) {
    const W = 640, H = 170, x0 = 14, x1 = W - 14, top = 26, base = H - 30;
    const X = mhz => x0 + (mhz - 2400) / (2485 - 2400) * (x1 - x0);
    const chs = z.channels || [], max = Math.max(1, ...chs.map(c => c.frames));
    const clean = new Set(z.clean || []);
    let s = `<svg class="rd-chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${T('Κίνηση ανά κανάλι Zigbee και ζώνες Wi-Fi', 'Activity per Zigbee channel and Wi-Fi bands')}">`;
    for (const w of (z.wifi || {}).channels || []) {
      const c = w.ch === 14 ? 2484 : 2407 + 5 * w.ch, a = X(c - w.width / 2), b = X(c + w.width / 2);
      s += `<rect x="${a.toFixed(1)}" y="${top - 12}" width="${(b - a).toFixed(1)}" height="${base - top + 12}" rx="4" style="fill:${w.own ? 'var(--orange)' : 'var(--dim)'};opacity:${w.own ? .2 : .13}"/>`
        + `<text x="${((a + b) / 2).toFixed(1)}" y="${top - 15}" text-anchor="middle" style="fill:${w.own ? 'var(--orange)' : 'var(--dim)'}">Wi-Fi ${E(w.ch)}${w.ssid ? ' · ' + E(String(w.ssid).slice(0, 14)) : ''}</text>`;
    }
    s += `<line x1="${x0}" y1="${base}" x2="${x1}" y2="${base}" style="stroke:var(--dim);opacity:.4"/>`;
    for (const c of chs) {
      const x = X(c.mhz), bw = (X(2) - X(0)) * 1.5, h = c.frames ? Math.max(3, c.frames / max * (base - top - 4)) : 0;
      const col = c.frames && c.wifi.length ? 'var(--orange)' : 'var(--cyan)';
      if (h) s += `<rect x="${(x - bw / 2).toFixed(1)}" y="${(base - h).toFixed(1)}" width="${bw.toFixed(1)}" height="${h.toFixed(1)}" rx="2" style="fill:${col}"><title>${T('κανάλι', 'channel')} ${c.ch} · ${c.mhz} MHz · ${c.frames} ${T('πλαίσια', 'frames')}</title></rect>`
        + `<text x="${x.toFixed(1)}" y="${(base - h - 3).toFixed(1)}" text-anchor="middle">${c.frames}</text>`;
      s += `<text x="${x.toFixed(1)}" y="${base + 12}" text-anchor="middle" style="${clean.has(c.ch) ? 'fill:var(--green);font-weight:700' : ''}">${c.ch}</text>`;
      if (clean.has(c.ch)) s += `<circle cx="${x.toFixed(1)}" cy="${base + 20}" r="2.2" style="fill:var(--green)"/>`;
    }
    return s + `</svg><div class="dim" style="font-size:11.5px">${T('Μπάρες = πλαίσια 802.15.4 ανά κανάλι στο τελευταίο πέρασμα · σκιασμένο = κανάλι Wi-Fi 2.4 GHz · <span style="color:var(--green)">● πράσινο</span> = κανάλι Zigbee χωρίς Wi-Fi από πάνω', 'Bars = 802.15.4 frames per channel in the last sweep · shaded = 2.4 GHz Wi-Fi channel · <span style="color:var(--green)">● green</span> = Zigbee channel with no Wi-Fi on top')}</div>`;
  }

  function zb(z) {
    let h = `<div class="card"><div class="rd-h"><b>🐝 Zigbee / Thread (802.15.4)</b>${sensors(z.sniffers, 'κανένας sniffer ακόμα', 'no sniffer yet')}</div>`;
    if (!(z.sniffers || []).length) {
      return h + `<div class="empty" style="margin-top:8px">${T('Σύζευξε έναν <b>Sniffer Zigbee / Thread</b> (nRF52840 dongle σε Raspberry Pi) στην καρτέλα', 'Pair a <b>Zigbee / Thread sniffer</b> (nRF52840 dongle on a Raspberry Pi) in the')} ${fleet()}${EN() ? ' tab' : ''} ${T('και τρέξε', 'and run')} <code>tools/zigbee_sniff.py</code>. ${T('Θα δεις ποια κανάλια είναι γεμάτα και αν το Zigbee σου κάθεται κάτω από το Wi-Fi.', 'You will see which channels are busy and whether your Zigbee sits under the Wi-Fi.')}</div></div>`;
    }
    h += chart(z);
    const w = z.wifi || {};
    h += `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px;font-size:12.5px"><span>${T('Κανάλια Wi-Fi 2.4 GHz σε χρήση', '2.4 GHz Wi-Fi channels in use')}: <b>${(w.channels || []).map(c => E(c.ch)).join(', ') || '—'}</b> <span class="dim">(${w.source === 'manual' ? T('τα έγραψες εσύ', 'entered by you') : w.source === 'survey' ? T('από τη χαρτογράφηση Wi-Fi', 'from the Wi-Fi survey') : T('άγνωστα', 'unknown')})</span></span>
      <input type="text" id="rd-wifi" maxlength="40" placeholder="${T('π.χ. 1, 6, 11', 'e.g. 1, 6, 11')}" value="${E((w.manual || []).join(', '))}"><button class="b rd-s" data-rd="wifi">${T('Ορισμός', 'Set')}</button>${(w.manual || []).length ? `<button class="b rd-s" data-rd="wifi-auto">${T('Αυτόματα', 'Automatic')}</button>` : ''}</div>`;
    const pans = z.pans || [];
    if (pans.length) {
      h += `<div class="rd-wrap"><table><thead><tr><th>PAN</th><th>${T('Κανάλι', 'Channel')}</th><th>${T('Κόμβοι', 'Nodes')}</th><th>${T('Πλαίσια', 'Frames')}</th><th>LQI</th><th>RSSI</th><th>${T('Κατάσταση', 'Status')}</th></tr></thead><tbody>`;
      for (const p of pans) {
        h += `<tr class="${p.under.length ? 'rd-hot' : ''}"><td class="rd-mono"><b>0x${E(p.pan)}</b></td><td>${E(p.ch)} <span class="dim">· ${2405 + 5 * (p.ch - 11)} MHz</span></td><td>${E(p.devices)}</td><td>${E(p.frames)}</td>
          <td style="white-space:nowrap">${sig(p.lqi, 0, 255, '')}</td><td style="white-space:nowrap">${sig(p.rssi, -100, -40, 'dBm')}</td>
          <td>${p.under.length ? `<span class="rd-pill" style="--c:var(--orange)">${T('κάτω από Wi-Fi', 'under Wi-Fi')} ${p.under.map(u => E(u.ch)).join(', ')}</span>` : (w.channels || []).length ? `<span class="rd-pill" style="--c:var(--green)">${T('καθαρό κανάλι', 'clean channel')}</span>` : ''}
            ${p.weak.length ? `<span class="rd-pill" style="--c:var(--yellow)">${p.weak.length} ${T('αδύναμοι κόμβοι', 'weak nodes')}</span><div class="rd-mono dim" style="margin-top:2px">${p.weak.slice(0, 6).map(d => `${E(d.src)} (${d.rssi != null ? E(d.rssi) + ' dBm' : 'LQI ' + E(d.lqi)})`).join(' · ')}</div>` : ''}</td></tr>`;
      }
      h += `</tbody></table></div>`;
    } else h += `<div class="dim" style="font-size:13px;margin-top:8px">${T('Δεν ακούστηκε κανένα δίκτυο 802.15.4 στο τελευταίο πέρασμα.', 'No 802.15.4 network was heard in the last sweep.')}</div>`;
    for (const a of z.advice || []) h += `<div class="rd-adv" style="--c:${COL[a.sev] || 'var(--cyan)'}">${a.sev === 'info' ? 'ℹ' : '⚠'} ${L(a)}</div>`;
    h += `<div class="rd-adv" style="--c:var(--cyan)"><b>👉 ${T('Τι να κάνεις', 'What to do')}</b><ol>
      <li>${T(`Κράτα το Wi-Fi 2.4 GHz σε <b>20 MHz</b> και στα κανάλια <b>1 / 6 / 11</b>· τότε τα κανάλια Zigbee <b>15, 20, 25</b> (και 26) μένουν καθαρά.${(z.clean || []).length ? ' Καθαρά τώρα: <b>' + z.clean.slice(0, 5).map(E).join(', ') + '</b>.' : ''}`, `Keep 2.4 GHz Wi-Fi at <b>20 MHz</b> on channels <b>1 / 6 / 11</b>; then Zigbee channels <b>15, 20, 25</b> (and 26) stay clean.${(z.clean || []).length ? ' Clean now: <b>' + z.clean.slice(0, 5).map(E).join(', ') + '</b>.' : ''}`)}</li>
      <li>${T('Το κανάλι 26 είναι καθαρό αλλά αρκετές συσκευές εκπέμπουν εκεί με μειωμένη ισχύ ή δεν το υποστηρίζουν — προτίμησε 15, 20 ή 25.', 'Channel 26 is clean, but quite a few devices transmit there at reduced power or don’t support it — prefer 15, 20 or 25.')}</li>
      <li>${T('Αδύναμοι κόμβοι; Πρόσθεσε <b>router</b> Zigbee (πρίζα ή λάμπα με ρεύμα) στη μέση· κράτα τον coordinator μακριά από USB 3.0, router Wi-Fi και μεταλλικά ντουλάπια (καλώδιο προέκτασης USB 1 m).', 'Weak nodes? Add a Zigbee <b>router</b> (mains plug or bulb) halfway; keep the coordinator away from USB 3.0 ports, Wi-Fi routers and metal cabinets (use a 1 m USB extension).')}</li>
      <li class="dim">${T('Ο sniffer βλέπει μόνο επικεφαλίδες (PAN, διευθύνσεις, σήμα) από τη δική του θέση — δεν αποκρυπτογραφεί τίποτα. Το LQI/RSSI είναι όπως ακούγεται ΕΚΕΙ, όχι στον coordinator.', 'The sniffer only sees headers (PAN, addresses, signal) from where it sits — it decrypts nothing. LQI/RSSI is as heard THERE, not at the coordinator.')}</li></ol></div></div>`;
    return h;
  }

  // ── LoRa ──
  function lora(l) {
    let h = `<div class="card"><div class="rd-h"><b>🛰 LoRa</b>${sensors(l.gateways, 'καμία πύλη LoRa ακόμα', 'no LoRa gateway yet')}</div>`;
    if (!(l.gateways || []).length) {
      return h + `<div class="empty" style="margin-top:8px">${T('Σύζευξε μια <b>Πύλη LoRa (ESP32)</b> στην καρτέλα', 'Pair a <b>LoRa gateway (ESP32)</b> in the')} ${fleet()}${EN() ? ' tab' : ''} ${T('— firmware <code>firmware/esp32-lora-gw</code> για την πύλη και <code>firmware/esp32-lora-node</code> για τους κόμβους.', '— firmware <code>firmware/esp32-lora-gw</code> for the gateway and <code>firmware/esp32-lora-node</code> for the nodes.')}</div></div>`;
    }
    const c = l.counts || {}, th = l.thresholds || {};
    h += `<div class="rd-chips">${chip(c.nodes || 0, T('κόμβοι', 'nodes'))}${c.weak ? chip(c.weak, T('αδύναμη ζεύξη', 'weak link'), 'var(--orange)') : ''}${c.batt ? chip(c.batt, T('χαμηλή μπαταρία', 'low battery'), 'var(--yellow)') : ''}${c.silent ? chip(c.silent, T('σιωπούν', 'silent'), 'var(--orange)') : ''}</div>`;
    h += `<div class="rd-wrap"><table><thead><tr><th>${T('Κόμβος', 'Node')}</th><th>RSSI</th><th>SNR</th><th>${T('Περιθώριο', 'Margin')}</th><th>${T('Μπαταρία', 'Battery')}</th><th>${T('Μετρήσεις', 'Readings')}</th><th>${T('Τελευταίο πακέτο', 'Last packet')}</th></tr></thead><tbody>`;
    for (const n of l.nodes || []) {
      const m = n.margin, mc = m == null ? 'var(--dim)' : m < 3 ? 'var(--red)' : m < (th.margin || 10) ? 'var(--orange)' : 'var(--green)';
      const read = [n.temp != null ? `🌡 ${E(n.temp)}°C` : '', n.hum != null ? `💧 ${E(n.hum)}%` : '', n.door === true ? '🚪 ' + T('ανοιχτή', 'open') : n.door === false ? '🚪 ' + T('κλειστή', 'closed') : ''].filter(Boolean).join(' · ');
      h += `<tr class="${(n.flags || []).length ? 'rd-hot' : ''}"><td><b>${E(n.node)}</b><div class="dim" style="font-size:11.5px">${E(n.gw)} · SF${E(n.sf)}</div>${flags(n.flags)}</td>
        <td style="white-space:nowrap">${sig(n.rssi, -135, -60, 'dBm')}</td><td>${n.snr == null ? '—' : E(n.snr) + ' dB'}</td>
        <td><span class="rd-pill" style="--c:${mc}">${m == null ? '—' : (m > 0 ? '+' : '') + E(m) + ' dB'}</span></td>
        <td>${n.batt == null ? '—' : E(n.batt) + ' V'}</td><td>${read || '<span class="dim">—</span>'}</td>
        <td style="white-space:nowrap">${n.age == null ? '—' : T('πριν ', '') + secs(n.age) + T('', ' ago')}${n.seq != null ? `<div class="dim" style="font-size:11.5px">#${E(n.seq)}</div>` : ''}</td></tr>`;
    }
    if (!(l.nodes || []).length) h += `<tr><td colspan="7" class="dim">${T('Η πύλη δεν έχει ακούσει ακόμα κανέναν κόμβο.', 'The gateway has not heard any node yet.')}</td></tr>`;
    h += `</tbody></table></div>
      <div class="rd-adv" style="--c:var(--cyan)"><b>👉 ${T('Τι να κάνεις', 'What to do')}</b><ol>
      <li>${T(`<b>Περιθώριο</b> = πόσα dB πάνω από το όριο του δέκτη φτάνει ο κόμβος (το μικρότερο από RSSI και SNR για το SF του). Κάτω από <b>${E(th.margin || 10)} dB</b> η ζεύξη θα κόβεται με βροχή, φύλλωμα ή ένα παρκαρισμένο φορτηγό.`, `<b>Margin</b> = how many dB above the receiver limit the node arrives (the lower of RSSI and SNR for its SF). Below <b>${E(th.margin || 10)} dB</b> the link will drop with rain, foliage or a parked lorry.`)}</li>
      <li>${T('Αδύναμη ζεύξη: πρώτα <b>κεραία</b> (ψηλά, κατακόρυφη, έξω από μεταλλικό κουτί, σωστή για 868 MHz), μετά <b>μεγαλύτερο SF</b> (κάθε βήμα ≈ +2.5 dB αλλά διπλάσιος χρόνος εκπομπής και μπαταρία), τέλος δεύτερη πύλη.', 'Weak link: first the <b>antenna</b> (high, vertical, outside any metal box, right for 868 MHz), then a <b>higher SF</b> (each step ≈ +2.5 dB but double airtime and battery), finally a second gateway.')}</li>
      <li>${T(`Μπαταρία κάτω από <b>${E(th.batt || 3.3)} V</b> (Li-ion): άλλαξε/φόρτισε πριν σιωπήσει. Κόμβος που σιωπά πάνω από ${Math.round((th.silent || 3600) / 60)}′: έλεγξε μπαταρία και αν άλλαξε κάτι στη διαδρομή.`, `Battery below <b>${E(th.batt || 3.3)} V</b> (Li-ion): replace/charge before it goes silent. A node silent for over ${Math.round((th.silent || 3600) / 60)} min: check the battery and whether something changed along the path.`)}</li></ol></div></div>`;
    return h;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error) { b.innerHTML = `<div class="card">${T('Τα Ασύρματα IoT δεν είναι διαθέσιμα σε αυτή τη λειτουργία (π.χ. στατικό demo ή ανάλυση pcap).', 'Wireless IoT is not available in this mode (e.g. static demo or pcap analysis).')}</div>`; return; }
    const hv = D.have || {}, n = (hv.ble || 0) + (hv.zigbee || 0) + (hv.lora || 0);
    const bc = (D.ble || {}).counts || {}, za = ((D.zb || {}).advice || []).filter(a => a.sev === 'med').length, lc = (D.lora || {}).counts || {};
    const warn = (bc.staying || 0) + za + (lc.weak || 0) + (lc.silent || 0);
    const keep = document.activeElement && document.activeElement.id === 'rd-wifi' ? document.activeElement.value : null;
    b.innerHTML = `<div class="card"><div class="rd-hero"><span class="rd-big">${!n ? '📻' : warn ? '⚠️' : '✅'}</span><div style="flex:1;min-width:240px">
      <b style="font-size:16px">${!n ? T('Κανένας ασύρματος αισθητήρας ακόμα', 'No wireless sensor yet') : warn ? T(`${warn} πράγματα θέλουν προσοχή στον αέρα`, `${warn} things need attention on the air`) : T('Ο αέρας γύρω από το δίκτυο δείχνει εντάξει', 'The air around the network looks fine')}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${T(`${hv.ble || 0} σαρωτές Bluetooth · ${hv.zigbee || 0} sniffer Zigbee/Thread · ${hv.lora || 0} πύλες LoRa`, `${hv.ble || 0} Bluetooth scanners · ${hv.zigbee || 0} Zigbee/Thread sniffers · ${hv.lora || 0} LoRa gateways`)}</div></div></div>
      ${D.demo ? `<div class="dim" style="font-size:12.5px;margin-top:8px">🧪 ${T('Demo: ένα άγνωστο tracker που μένει ώρες, ένα Zigbee PAN στο κανάλι 11 κάτω από το Wi-Fi 1, και τρεις κόμβοι LoRa (ο ένας οριακός).', 'Demo: an unknown tracker staying for hours, a Zigbee PAN on channel 11 under Wi-Fi 1, and three LoRa nodes (one marginal).')}</div>` : ''}
      <div class="dim" style="font-size:12.5px;margin-top:8px;line-height:1.55">${T('Το IoT δεν περνά μόνο από Wi-Fi και καλώδιο. Εδώ βλέπεις ό,τι <b>ακούνε</b> οι αισθητήρες σου στα 2.4 GHz και 868 MHz — χωρίς να εκπέμπουν και χωρίς να διαβάζουν περιεχόμενο. Για να προσθέσεις σαρωτή, sniffer ή πύλη: καρτέλα', 'IoT doesn’t only travel over Wi-Fi and cable. Here you see what your sensors <b>hear</b> at 2.4 GHz and 868 MHz — without transmitting and without reading any content. To add a scanner, sniffer or gateway: the')} ${fleet()}${EN() ? ' tab' : ''} → ➕ → ${T('κωδικός σύζευξης', 'pairing code')}.</div></div>`
      + ble(D.ble || {}) + zb(D.zb || {}) + lora(D.lora || {});
    if (keep != null) { const i = document.getElementById('rd-wifi'); if (i) { i.value = keep; i.focus(); } }
  }

  function load() {
    return fetch('/api/kit/radio').then(r => r.json()).then(j => { D = j && typeof j === 'object' ? j : { error: 'off' }; draw(); }).catch(() => { D = { error: 'off' }; draw(); });
  }
  const post = (sub, body) => fetch('/api/kit/radio/' + sub, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })
    .then(r => r.json()).then(j => { if (j && j.error && !j.ble) { alert(j.error); return load(); } D = j; draw(); }).catch(load);

  document.addEventListener('click', e => {
    const b = e.target.closest('#t-radio [data-rd]'); if (!b) return;
    const a = b.dataset.rd;
    if (a === 'all') { showAll = !showAll; draw(); return; }
    if (a === 'wifi') { post('wifi', { channels: (document.getElementById('rd-wifi') || {}).value || '' }); return; }
    if (a === 'wifi-auto') { post('wifi', { channels: [] }); return; }
    if (a === 'known') {
      const mode = b.dataset.mode;
      let label = '';
      if (mode === 'known') { label = prompt(T('Τι είναι; (π.χ. «Κλειδιά Μαρίας») — προαιρετικό', 'What is it? (e.g. “Maria’s keys”) — optional'), ''); if (label === null) return; }
      post('known', { mac: b.dataset.mac, mode, label });
    }
  });
  document.addEventListener('keydown', e => { if (e.key === 'Enter' && e.target && e.target.id === 'rd-wifi') post('wifi', { channels: e.target.value }); });
  window.renderRadio = () => { load(); clearInterval(timer); timer = setInterval(() => { const b = box(); if (b && b.offsetParent && !(document.activeElement && document.activeElement.id === 'rd-wifi')) load(); }, 20000); };
})();
