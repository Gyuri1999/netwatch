// ───────────────────────── 📈 Διαθεσιμότητα ανά συσκευή (online %, διακοπές, 7 μέρες) ─────────────────────────
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const box = () => document.getElementById('t-avail');
  let V = null, days = 7, onlyAlways = false, open = null, detail = null;

  const css = document.createElement('style');
  css.textContent = `
#t-avail .av-top{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
#t-avail .av-top button.on{border-color:var(--cyan);color:var(--cyan)}
#t-avail .av-row{display:grid;grid-template-columns:30px minmax(120px,1.1fr) 70px minmax(160px,2.4fr) 120px;gap:10px;align-items:center;padding:8px 6px;border-top:1px solid rgb(var(--w,255 255 255) / 6%);cursor:pointer}
#t-avail .av-row:hover{background:rgb(var(--w,255 255 255) / 3%)}
@media(max-width:760px){#t-avail .av-row{grid-template-columns:30px minmax(0,1fr) 64px}#t-avail .av-row .bar,#t-avail .av-row .out{grid-column:2/-1}}
#t-avail .ic{font-size:20px;text-align:center;position:relative}
#t-avail .ic i{position:absolute;right:-2px;bottom:0;width:8px;height:8px;border-radius:50%;background:#3a4a63}
#t-avail .ic i.on{background:var(--green);box-shadow:0 0 6px var(--green)}
#t-avail .nm b{display:block;font-size:13.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}#t-avail .nm span{font:11.5px ui-monospace,Menlo,monospace;color:var(--dim)}
#t-avail .pct{font:700 15px ui-monospace,Menlo,monospace;text-align:right}
#t-avail .bar{display:flex;height:22px;gap:1px;align-items:stretch}
#t-avail .bar s{flex:1;text-decoration:none;border-radius:1px;min-width:1px}
#t-avail .out{font-size:12px;color:var(--dim);line-height:1.35}
#t-avail .out b{color:var(--txt)}
#t-avail .av-det{padding:8px 10px 12px 46px;font-size:12.5px}
#t-avail .av-det div{padding:3px 0;font-family:ui-monospace,Menlo,monospace}
#t-avail .av-note{font-size:12.5px;color:var(--dim);line-height:1.55;margin-top:8px}
`;
  document.head.appendChild(css);

  const col = v => v == null ? 'rgb(255 255 255 / 5%)' : v >= .99 ? 'var(--green)' : v >= .75 ? '#9be36a' : v >= .4 ? 'var(--yellow)' : v > 0 ? 'var(--orange)' : 'var(--red)';
  const dur = m => m >= 1440 ? (m / 1440).toFixed(1) + T(' μ.', 'd') : m >= 60 ? (m / 60).toFixed(1) + T(' ώρ.', 'h') : m + '′';
  const dt = t => new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });

  function bar(hours) {
    // πάνω από 72 ώρες → ομαδοποίηση ανά 2/4 ώρες, για να χωράει
    const step = hours.length > 168 ? 4 : hours.length > 72 ? 2 : 1, out = [];
    for (let i = 0; i < hours.length; i += step) {
      const g = hours.slice(i, i + step).filter(x => x != null);
      out.push(g.length ? g.reduce((a, b) => a + b, 0) / g.length : null);
    }
    return out.map((v, i) => `<s style="background:${col(v)}" title="${v == null ? T('NetWatch κλειστό', 'NetWatch off') : Math.round(v * 100) + '%'}"></s>`).join('');
  }
  function draw() {
    const b = box(); if (!b || !V) return;
    b.setAttribute('data-noi18n', '');
    if (V.off) { b.innerHTML = `<div class="card">${T('Το ιστορικό διαθεσιμότητας δεν είναι διαθέσιμο σε αυτή τη λειτουργία.', 'Availability history is not available in this mode.')}</div>`; return; }
    const list = V.devices.filter(d => !onlyAlways || d.always_on);
    const flaky = V.devices.filter(d => d.always_on && d.outages_24h);
    let h = `<div class="av-top">${[1, 7, 30].map(d => `<button class="b${d === days ? ' on' : ''}" data-days="${d}">${d === 1 ? T('24 ώρες', '24 hours') : d + T(' μέρες', ' days')}</button>`).join('')}
      <label style="display:flex;gap:6px;align-items:center;font-size:12.5px;cursor:pointer;margin-left:6px"><input type="checkbox" data-always${onlyAlways ? ' checked' : ''}> ${T('μόνο «πάντα ανοιχτές» (κάμερες, router, NAS, IoT…)', 'only “always-on” (cameras, router, NAS, IoT…)')}</label>
      <span class="dim" style="margin-left:auto;font-size:12px">${T('NetWatch ενεργό', 'NetWatch active')} ${V.coverage}% ${T('του χρόνου', 'of the time')}</span></div>`;
    if (flaky.length) h += `<div class="card" style="border-left:3px solid var(--orange)">⚠️ ${T('Τις τελευταίες 24 ώρες «έπεσαν»:', 'Went offline in the last 24 hours:')} ${flaky.map(d => `<b>${E(d.icon)} ${E(d.name || d.ip)}</b> (${d.outages_24h}×)`).join(', ')}. ${T('Για συσκευή που πρέπει να είναι πάντα ανοιχτή, αυτό σημαίνει κακό Wi-Fi, τροφοδοσία ή κόλλημα.', 'For a device that should always be on, this points to bad Wi-Fi, power, or a hang.')}</div>`;
    h += `<div class="card" style="padding:4px 8px">`;
    if (!list.length) h += `<div class="dim" style="padding:20px;text-align:center">${T('Δεν υπάρχουν ακόμα δεδομένα — το NetWatch καταγράφει κάθε 5 λεπτά.', 'No data yet — NetWatch records every 5 minutes.')}</div>`;
    for (const d of list) {
      h += `<div class="av-row" data-key="${E(d.key)}"><div class="ic">${E(d.icon || '❔')}<i class="${d.online ? 'on' : ''}"></i></div>
        <div class="nm"><b>${E(d.name || d.ip)}</b><span>${E(d.ip)}${d.always_on ? '' : ' · ' + T('έρχεται-φεύγει', 'comes & goes')}</span></div>
        <div class="pct" style="color:${col(d.pct / 100)}">${d.pct}%</div><div class="bar">${bar(d.hours)}</div>
        <div class="out">${d.outages ? `<b>${d.outages}</b> ${T('διακοπές', 'outages')}${d.outages_24h ? ` · <b>${d.outages_24h}</b> ${T('σε 24ώ', 'in 24h')}` : ''}<br>${T('μεγαλύτερη', 'longest')} ${dur(d.longest_min)}` : T('χωρίς διακοπές', 'no outages')}</div></div>`;
      if (open === d.key) h += `<div class="av-det">${detail && detail.list ? (detail.list.length ? detail.list.map(o => `<div>⛔ ${dt(o.start)} → ${o.end ? dt(o.end) : '<b>' + T('ακόμα εκτός', 'still offline') + '</b>'} · ${dur(o.min)}</div>`).join('') : T('Καμία διακοπή.', 'No outages.')) : '⏳'}</div>`;
    }
    h += `</div><div class="av-note">ℹ️ ${T('Κάθε 5′ σημειώνω ποιες συσκευές «ακούστηκαν» στο δίκτυο (παθητικά: ARP, mDNS, DHCP, κίνηση). Διακοπή = εκτός για ≥10′. Όταν το NetWatch ήταν κλειστό, δεν μετράει (γκρι). Κινητά/laptop φυσιολογικά φεύγουν· σημασία έχουν οι «πάντα ανοιχτές». Πολύ ήσυχες συσκευές (π.χ. σε sleep) μπορεί να φαίνονται εκτός ενώ είναι συνδεδεμένες.', 'Every 5′ I note which devices were “heard” on the network (passively: ARP, mDNS, DHCP, traffic). Outage = offline for ≥10′. Time when NetWatch was off does not count (grey). Phones/laptops naturally come and go; what matters are the “always-on” ones. Very quiet devices (e.g. asleep) may look offline while still connected.')}</div>`;
    b.innerHTML = h;
  }
  function load() { return fetch('/api/presence?days=' + days).then(r => r.json()).then(j => { V = j; draw(); }).catch(() => { V = { off: true }; draw(); }); }
  document.addEventListener('click', e => {
    const b = box(); if (!b || !b.contains(e.target)) return;
    const dd = e.target.closest('[data-days]'); if (dd) { days = +dd.dataset.days; open = null; load(); return; }
    const r = e.target.closest('.av-row'); if (!r) return;
    if (open === r.dataset.key) { open = null; draw(); return; }
    open = r.dataset.key; detail = null; draw();
    fetch('/api/presence?days=' + days + '&key=' + encodeURIComponent(open)).then(x => x.json()).then(j => { detail = (j.devices || [])[0] || { list: [] }; draw(); });
  });
  document.addEventListener('change', e => { if (e.target.matches('#t-avail [data-always]')) { onlyAlways = e.target.checked; draw(); } });
  window.renderAvail = () => load();
})();
