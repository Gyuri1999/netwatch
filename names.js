// ───────────────────────── 🏷 Ονόματα συσκευών (στον server — φαίνονται παντού) ─────────────────────────
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const N = { types: [], devices: {}, ready: false };
  const TYPE_EN = { router: 'Router / AP', computer: 'Computer', phone: 'Phone / tablet', esp: 'ESP32 / ESP8266', pi: 'Raspberry Pi', vm: 'VM / server', nas: 'NAS',
    printer: 'Printer', tv: 'TV / media', camera: 'Camera', console: 'Console', speaker: 'Speaker / assistant', iot: 'Smart device' };
  const tl = t => EN() ? TYPE_EN[t.id] || t.label : t.label;
  const post = b => fetch('/api/names', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }).then(r => r.json());
  const keyOf = h => h.mac ? h.mac.toLowerCase() : 'ip:' + h.ip;
  const HS = () => { try { return S.hosts; } catch (e) { return null; } };  // S = const του index.html (όχι στο window)
  const hostsArr = () => HS() ? [...HS().values()] : [];
  const fmtAgo = t => { if (!t) return ''; const s = Date.now() / 1000 - t; return s < 90 ? T('τώρα', 'now') : s < 3600 ? Math.round(s / 60) + T('′ πριν', 'm ago') : s < 86400 ? Math.round(s / 3600) + T(' ώρ. πριν', 'h ago') : Math.round(s / 86400) + T(' μ. πριν', 'd ago'); };

  const css = document.createElement('style');
  css.textContent = `
.nm-ov{position:fixed;inset:0;z-index:9000;background:rgb(0 0 0 / 45%);backdrop-filter:blur(3px);display:flex;align-items:flex-start;justify-content:center;padding:6vh 16px;overflow:auto}
.nm-box{width:min(560px,100%);background:var(--panel2,#101828);color:var(--txt);border:1px solid var(--line);border-radius:16px;box-shadow:0 20px 60px rgb(0 0 0 / 45%);padding:18px 18px 14px}
.nm-box.wide{width:min(980px,100%)}
.nm-box h3{margin:0 0 4px;font-size:17px}
.nm-in{width:100%;box-sizing:border-box;background:var(--bg);color:var(--txt);border:1px solid var(--line);border-radius:10px;padding:9px 11px;font:14px inherit}
.nm-types{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.nm-t{border:1px solid var(--line);background:rgb(var(--w,255 255 255) / 3%);color:var(--txt);border-radius:10px;padding:6px 9px;cursor:pointer;font:12.5px inherit;display:flex;gap:5px;align-items:center}
.nm-t.on{border-color:var(--cyan);background:color-mix(in srgb,var(--cyan) 14%,transparent)}
.nm-lbl{font-size:12px;color:var(--dim);margin:12px 0 4px;font-weight:600}
.nm-row{display:grid;grid-template-columns:34px minmax(0,1.1fr) minmax(0,1.3fr) 150px;gap:8px;align-items:center;padding:8px 6px;border-top:1px solid rgb(var(--w,255 255 255) / 7%)}
@media(max-width:700px){.nm-row{grid-template-columns:30px 1fr;}.nm-row .nm-in,.nm-row select{grid-column:2}}
.nm-row .ic{font-size:20px;text-align:center;position:relative}
.nm-row .ic i{position:absolute;right:0;top:0;width:8px;height:8px;border-radius:50%;background:#3a4a63}
.nm-row .ic i.live{background:var(--green);box-shadow:0 0 8px var(--green)}
.nm-row .meta b{display:block;font:600 13px ui-monospace,Menlo,Consolas,monospace}.nm-row .meta span{font-size:11.5px;color:var(--dim)}
.nm-row select{background:var(--bg);color:var(--txt);border:1px solid var(--line);border-radius:10px;padding:8px;font:13px inherit;min-width:0}
.nm-tip{font-size:12.5px;line-height:1.55;background:rgb(var(--w,255 255 255) / 4%);border-radius:10px;padding:10px 12px;margin-top:10px}
.nm-foot{display:flex;gap:8px;justify-content:flex-end;align-items:center;margin-top:14px}
.nm-save{border-color:var(--green)!important;color:var(--green)!important;font-weight:600}
.nm-list{max-height:58vh;overflow:auto;margin-top:8px}
`;
  document.head.appendChild(css);

  function load() {
    return fetch('/api/names').then(r => r.json()).then(j => { N.types = j.types || []; N.devices = j.devices || {}; N.ready = true; }).catch(() => {});
  }
  // παλιά ονόματα του browser (localStorage «nw-names») → στον server, μία φορά
  function migrate() {
    let old = {}; try { old = JSON.parse(localStorage.getItem('nw-names') || '{}'); } catch (e) { return; }
    const items = Object.entries(old).filter(([, v]) => v).map(([k, v]) => /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(k) ? { mac: k, name: v } : { ip: k, name: v });
    if (!items.length) return;
    post({ items }).then(j => { if (j.ok) { try { localStorage.removeItem('nw-names'); } catch (e) {} load(); } });
  }
  function apply(h, e) {  // άμεση ενημέρωση στον browser (ο server θα στείλει τα ίδια στην επόμενη ενημέρωση)
    if (!h) return;
    h.alias = e && e.name || undefined;
    const t = e && e.type && N.types.find(x => x.id === e.type);
    if (t) { h.dtype = t.id; h.dicon = t.icon; h.dlabel = t.label; }
    h.note = e && e.note || undefined;
  }
  function rerender() {
    try { if (typeof renderTab === 'function') renderTab(); } catch (e) {}
    try { if (window.LP) LP.gof = null; } catch (e) {}
  }

  // ── ένα όνομα ──
  function edit(ip, done) {
    const h = HS() && HS().get(ip) || { ip };
    const cur = N.devices[keyOf(h)] || {};
    let typ = cur.type || (h.dtype && h.dtype !== 'unknown' ? h.dtype : '');
    const ov = document.createElement('div'); ov.className = 'nm-ov'; ov.setAttribute('data-noi18n', '');
    const draw = () => {
      ov.innerHTML = `<div class="nm-box" role="dialog" aria-modal="true"><h3>🏷 ${T('Όνομα συσκευής', 'Device name')}</h3>
        <div class="dim" style="font:12px ui-monospace,Menlo,Consolas,monospace">${E(h.ip)}${h.mac ? ' · ' + E(h.mac) : ''}${h.vendor ? ' · ' + E(h.vendor === 'τυχαία MAC' ? T(h.vendor, 'random MAC') : h.vendor) : ''}</div>
        <div class="nm-lbl">${T('Όνομα', 'Name')}</div><input class="nm-in" id="nm-name" maxlength="40" placeholder="${T('π.χ. Κινητό Μαρίας, TV σαλονιού', 'e.g. Maria’s phone, Living-room TV')}" value="${E(cur.name || h.alias || '')}">
        <div class="nm-lbl">${T('Τι είναι;', 'What is it?')}</div><div class="nm-types">${N.types.map(t => `<button class="nm-t${t.id === typ ? ' on' : ''}" data-nmt="${t.id}">${t.icon} ${E(tl(t))}</button>`).join('')}</div>
        <div class="nm-lbl">${T('Σημείωση (προαιρετικά)', 'Note (optional)')}</div><input class="nm-in" id="nm-note" maxlength="200" placeholder="${T('π.χ. στο γραφείο, θύρα 4 του switch', 'e.g. in the office, switch port 4')}" value="${E(cur.note || '')}">
        <div class="dim" style="font-size:11.5px;margin-top:10px">💾 ${T('Αποθηκεύεται στο NetWatch (όχι μόνο σε αυτόν τον browser) και φαίνεται παντού: χάρτης, διάγραμμα, συσκευές, τεκμηρίωση.', 'Saved in NetWatch (not just this browser) and shown everywhere: map, diagram, devices, documentation.')}</div>
        <div class="nm-foot">${cur.name || cur.type ? `<button class="b" data-nmdel style="margin-right:auto">🗑 ${T('Αφαίρεση', 'Remove')}</button>` : ''}<button class="b" data-nmx>${T('Άκυρο', 'Cancel')}</button><button class="b nm-save" data-nmok>✓ ${T('Αποθήκευση', 'Save')}</button></div></div>`;
      const inp = ov.querySelector('#nm-name'); inp.focus(); inp.select();
    };
    const close = () => { ov.remove(); document.removeEventListener('keydown', key); };
    const save = del => {
      const body = del ? { mac: h.mac, ip: h.ip } : { mac: h.mac, ip: h.ip, name: ov.querySelector('#nm-name').value, type: typ, note: ov.querySelector('#nm-note').value };
      post(body).then(j => {
        if (j.error) { alert(j.error); return; }
        if (j.entry) N.devices[j.key] = j.entry; else delete N.devices[j.key];
        apply(HS() && HS().get(ip), j.entry); close(); rerender(); done && done(j.entry);
      });
    };
    const key = e => { if (e.key === 'Escape') close(); if (e.key === 'Enter' && e.target.tagName === 'INPUT') save(false); };
    ov.addEventListener('click', e => {
      if (e.target === ov) return close();
      const b = e.target.closest('button'); if (!b) return;
      if (b.dataset.nmt) { typ = typ === b.dataset.nmt ? '' : b.dataset.nmt; const nm = ov.querySelector('#nm-name').value, nt = ov.querySelector('#nm-note').value; draw(); ov.querySelector('#nm-name').value = nm; ov.querySelector('#nm-note').value = nt; return; }
      if (b.dataset.nmx != null) return close();
      if (b.dataset.nmok != null) return save(false);
      if (b.dataset.nmdel != null) return save(true);
    });
    document.addEventListener('keydown', key);
    document.body.appendChild(ov);
    (N.ready ? Promise.resolve() : load()).then(draw);
  }

  // ── οδηγός: ονόμασε όλες τις άγνωστες μαζί ──
  const unnamed = () => hostsArr().filter(h => h.kind === 'local' && !h.me && !h.gw && !h.ip.includes(':') && !h.alias && !N.devices[keyOf(h)])
    .sort((a, b) => (b.last || 0) - (a.last || 0));
  function wizard() {
    const list = unnamed();
    const ov = document.createElement('div'); ov.className = 'nm-ov'; ov.setAttribute('data-noi18n', '');
    const prev = new Map(list.map(h => [h.ip, (h.bytes_in || 0) + (h.bytes_out || 0)]));
    ov.innerHTML = `<div class="nm-box wide" role="dialog" aria-modal="true"><h3>🏷 ${T('Δώσε ονόματα στις άγνωστες συσκευές', 'Name your unknown devices')} <span class="dim" style="font-weight:400">(${list.length})</span></h3>
      <div class="nm-tip">💡 <b>${T('Πώς βρίσκω ποια είναι ποια;', 'How do I tell which is which?')}</b><br>
        ${T('• <b>Κινητό:</b> Ρυθμίσεις → Wi-Fi → (i) δίπλα στο δίκτυο → εκεί γράφει τη διεύθυνση IP.<br>• <b>Ζωντανά:</b> κάνε κάτι σε μια συσκευή (π.χ. βάλε YouTube στην TV) — η τελεία της δίπλα ανάβει <span style="color:var(--green)">●</span> όταν μιλάει.<br>• <b>Router/Deco app:</b> η λίστα «Clients» δείχνει ονόματα και IP.<br>• <b>Κλείσε</b> μια συσκευή και δες ποια σβήνει (θα πει «πριν από λίγο»).',
        '• <b>Phone:</b> Settings → Wi-Fi → (i) next to the network → shows its IP address.<br>• <b>Live:</b> use a device (e.g. play YouTube on the TV) — its dot lights up <span style="color:var(--green)">●</span> while it talks.<br>• <b>Router/Deco app:</b> the “Clients” list shows names and IPs.<br>• <b>Turn off</b> a device and see which one goes quiet.')}</div>
      <div class="nm-list">${list.map(h => `<div class="nm-row" data-ip="${E(h.ip)}"><div class="ic">${E(h.dicon || '❔')}<i></i></div>
          <div class="meta"><b>${E(h.ip)}</b><span>${E([h.vendor && h.vendor !== 'τυχαία MAC' ? h.vendor : (h.mac && /^.[26ae]/i.test(h.mac) ? T('τυχαία MAC → μάλλον κινητό', 'random MAC → likely a phone') : ''), h.dlabel && h.dtype !== 'unknown' ? h.dlabel : '', fmtAgo(h.last)].filter(Boolean).join(' · '))}</span></div>
          <input class="nm-in" maxlength="40" placeholder="${T('όνομα…', 'name…')}">
          <select><option value="">${T('— τύπος —', '— type —')}</option>${N.types.map(t => `<option value="${t.id}"${t.id === h.dtype ? ' selected' : ''}>${t.icon} ${E(tl(t))}</option>`).join('')}</select></div>`).join('') ||
        `<div class="dim" style="padding:24px;text-align:center">🎉 ${T('Όλες οι συσκευές έχουν όνομα!', 'Every device has a name!')}</div>`}</div>
      <div class="nm-foot"><span class="dim" id="nm-st" style="margin-right:auto;font-size:12.5px"></span><button class="b" data-nmx>${T('Κλείσιμο', 'Close')}</button>${list.length ? `<button class="b nm-save" data-nmall>✓ ${T('Αποθήκευση', 'Save')}</button>` : ''}</div></div>`;
    const close = () => { clearInterval(tick); ov.remove(); document.removeEventListener('keydown', key); };
    const key = e => { if (e.key === 'Escape') close(); };
    const tick = setInterval(() => {  // «ποια μιλάει τώρα;» — ανάβει η τελεία όταν αλλάζουν τα bytes
      ov.querySelectorAll('.nm-row').forEach(r => {
        const h = HS() && HS().get(r.dataset.ip); if (!h) return;
        const b = (h.bytes_in || 0) + (h.bytes_out || 0), live = b > (prev.get(h.ip) || 0) || (h._flash && performance.now() - h._flash < 1500);
        prev.set(h.ip, b); const i = r.querySelector('.ic i'); if (i) i.className = live ? 'live' : '';
      });
    }, 1000);
    ov.addEventListener('click', e => {
      if (e.target === ov) return close();
      const b = e.target.closest('button'); if (!b) return;
      if (b.dataset.nmx != null) return close();
      if (b.dataset.nmall != null) {
        const items = [...ov.querySelectorAll('.nm-row')].map(r => {
          const h = HS().get(r.dataset.ip) || { ip: r.dataset.ip }, name = r.querySelector('input').value.trim(), type = r.querySelector('select').value;
          const guessed = type && type === h.dtype && !name;  // ίδια εκτίμηση χωρίς όνομα → τίποτα να σωθεί
          return name || (type && !guessed) ? { mac: h.mac, ip: h.ip, name, type } : null;
        }).filter(Boolean);
        if (!items.length) { ov.querySelector('#nm-st').textContent = T('Γράψε τουλάχιστον ένα όνομα.', 'Type at least one name.'); return; }
        post({ items }).then(j => {
          if (j.error) { ov.querySelector('#nm-st').textContent = j.error; return; }
          load().then(() => { for (const it of items) { const h = HS().get(it.ip); if (h) apply(h, N.devices[keyOf(h)]); } rerender(); close(); });
        });
      }
    });
    document.addEventListener('keydown', key);
    document.body.appendChild(ov);
  }

  window.NAMES_UI = { edit, wizard, unnamed, load, data: N };
  const init = () => {
    window.setAlias = ip => edit(ip);  // το παλιό «✏️ Όνομα» ανοίγει πλέον τον νέο επεξεργαστή
    load().then(migrate);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
