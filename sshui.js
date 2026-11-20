// ───────────────────────── 🖥 SSH Explorer (μόνο κλειδιά, μόνο ανάγνωση) ─────────────────────────
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const tr = x => (EN() && window.I18N && I18N.t ? I18N.t(String(x || '')) : String(x || ''));  // μηνύματα του server
  const S = { d: null, cur: null, view: 'files', path: {}, ls: null, file: null, info: null, key: null, msg: null, busy: false, add: false };
  const box = () => document.getElementById('t-ssh');
  const post = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) }).then(r => r.json());
  const size = n => n == null ? '' : n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1073741824).toFixed(1) + ' GB';
  const when = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : '';
  const fic = e => e.type === 'd' ? '📁' : e.type === 'l' ? '🔗' : /\.(jpe?g|png|gif|webp|heic)$/i.test(e.name) ? '🖼' : /\.(sh|py|js|ts|c|go|rs)$/i.test(e.name) ? '📜' :
    /\.(ya?ml|json|conf|cfg|ini|toml|env)$/i.test(e.name) ? '⚙️' : /\.(log)$/i.test(e.name) || /log$/.test(e.name) ? '🧾' : /\.(zip|tar|gz|xz|7z)$/i.test(e.name) ? '📦' : /\.(md|txt)$/i.test(e.name) ? '📄' : '📄';

  const css = document.createElement('style');
  css.textContent = `
#t-ssh .sx{display:grid;grid-template-columns:260px minmax(0,1fr);gap:12px;align-items:start}
@media(max-width:900px){#t-ssh .sx{grid-template-columns:1fr}}
#t-ssh .sx-h{display:flex;flex-direction:column;gap:6px}
#t-ssh .sx-host{display:flex;gap:10px;align-items:center;padding:10px 12px;border:1px solid var(--line);border-radius:12px;cursor:pointer;background:rgb(var(--w) / 3%)}
#t-ssh .sx-host.on{border-color:var(--cyan);background:color-mix(in srgb,var(--cyan) 10%,transparent)}
#t-ssh .sx-host b{display:block;font-size:13.5px}#t-ssh .sx-host span{font:11.5px ui-monospace,Menlo,Consolas,monospace;color:var(--dim)}
#t-ssh .sx-host i{font-style:normal;font-size:22px}
#t-ssh .sx-form{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:6px}
#t-ssh .sx-form input{background:var(--bg);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:7px 9px;font:13px inherit;min-width:0}
#t-ssh .sx-form .full{grid-column:1/-1}
#t-ssh .sx-sug{display:flex;gap:5px;flex-wrap:wrap;margin-top:6px}
#t-ssh .sx-sug button{font-size:11.5px;padding:3px 9px}
#t-ssh .sx-tabs{display:flex;gap:4px;margin:10px 0 0}
#t-ssh .sx-tabs button.on{border-color:var(--cyan);color:var(--cyan)}
#t-ssh .sx-crumb{display:flex;gap:2px;flex-wrap:wrap;align-items:center;font:12.5px ui-monospace,Menlo,Consolas,monospace;margin:10px 0 6px}
#t-ssh .sx-crumb a{cursor:pointer;color:var(--cyan);padding:2px 5px;border-radius:5px}#t-ssh .sx-crumb a:hover{background:rgb(var(--w) / 8%)}
#t-ssh .sx-quick{display:flex;gap:5px;flex-wrap:wrap}#t-ssh .sx-quick button{font-size:11.5px;padding:3px 9px}
#t-ssh .sx-ls{width:100%;border-collapse:collapse;font-size:13px}
#t-ssh .sx-ls td{padding:6px 8px;border-top:1px solid rgb(var(--w) / 6%);white-space:nowrap}
#t-ssh .sx-ls tr.r{cursor:pointer}#t-ssh .sx-ls tr.r:hover td{background:rgb(var(--w) / 4%)}
#t-ssh .sx-ls tr.sel td{background:color-mix(in srgb,var(--cyan) 10%,transparent)}
#t-ssh .sx-ls td.n{white-space:normal;word-break:break-all;width:100%}#t-ssh .sx-ls td.m{color:var(--dim);font:11.5px ui-monospace,Menlo,Consolas,monospace}
#t-ssh .sx-pre{max-height:60vh;overflow:auto;background:#05080f;color:#d6e2f0;border-radius:10px;padding:10px 12px;font:12px/1.55 ui-monospace,Menlo,Consolas,monospace;white-space:pre;margin-top:8px;counter-reset:ln}
#t-ssh .sx-pre span{display:block}#t-ssh .sx-pre span:before{counter-increment:ln;content:counter(ln);display:inline-block;width:3em;margin-right:12px;text-align:right;color:#4b5b70}
#t-ssh .sx-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:10px}
#t-ssh .sx-k{margin:0;display:flex;flex-direction:column;gap:3px}#t-ssh .sx-k b{font-size:20px}#t-ssh .sx-k span{font-size:11.5px;color:var(--dim)}
#t-ssh .sx-bar{height:7px;border-radius:4px;background:rgb(var(--w) / 8%);overflow:hidden;margin-top:4px}#t-ssh .sx-bar i{display:block;height:100%;background:var(--c)}
#t-ssh .sx-chk{border-left:3px solid var(--c);padding:6px 10px;margin-top:6px;font-size:13px;background:rgb(var(--w) / 3%);border-radius:0 8px 8px 0}
#t-ssh .sx-chk code{display:block;margin-top:4px;font-size:11.5px;white-space:pre-wrap;color:var(--dim)}
#t-ssh .sx-cmd{display:flex;gap:6px;align-items:center;margin-top:6px}#t-ssh .sx-cmd code{flex:1;min-width:0;background:#05080f;color:#d6e2f0;border-radius:7px;padding:7px 10px;font-size:12px;overflow-x:auto;white-space:pre}
#t-ssh .sx-err{border-left:4px solid var(--yellow);}
#t-ssh .sx-fp{font:12.5px ui-monospace,Menlo,Consolas,monospace;background:rgb(var(--w) / 5%);padding:6px 9px;border-radius:7px;margin-top:6px;word-break:break-all}
`;
  document.head.appendChild(css);

  const cmd = (c, note) => `<div class="sx-cmd"><code>${E(c)}</code><button class="b" data-sxcp="${E(c)}">📋</button></div>${note ? `<div class="dim" style="font-size:12px;margin-top:3px">${note}</div>` : ''}`;
  const host = () => S.d && S.d.hosts.find(h => h.id === S.cur);

  function load() {
    fetch('/api/ssh').then(r => r.json()).then(j => {
      S.d = j; if (!S.cur && j.hosts.length) select(j.hosts[0].id, true); else draw();
    }).catch(e => { S.msg = String(e); draw(); });
  }
  function select(id, quiet) {
    S.cur = id; S.ls = S.file = S.info = S.key = S.err = null;
    if (!quiet || true) go(S.path[id] || '~');
  }
  function go(p) {
    const h = host(); if (!h) return draw();
    S.busy = true; S.file = null; draw();
    post('/api/ssh/ls', { id: h.id, path: p }).then(j => {
      S.busy = false;
      if (j.error) { S.err = j; S.ls = null; } else { S.err = null; S.ls = j; S.path[h.id] = j.path; }
      draw();
    });
  }
  function open(name) {
    const h = host(), p = (S.ls.path.replace(/\/$/, '') || '') + '/' + name;
    S.busy = true; draw();
    post('/api/ssh/cat', { id: h.id, path: p }).then(j => { S.busy = false; S.file = Object.assign({ name, full: p }, j); draw(); const f = document.getElementById('sx-file'); f && f.scrollIntoView({ block: 'nearest' }); });
  }
  function info() {
    const h = host(); S.busy = true; draw();
    post('/api/ssh/info', { id: h.id }).then(j => { S.busy = false; if (j.error) S.err = j; else { S.err = null; S.info = j; } draw(); });
  }
  function hostkey() {
    const h = host(); S.busy = true; draw();
    post('/api/ssh/hostkey', { id: h.id }).then(j => { S.busy = false; S.key = j; draw(); });
  }

  function hostsHTML() {
    const d = S.d, hs = d.hosts || [];
    return `<div class="card" style="margin:0"><b>🖥 ${T('Συσκευές', 'Devices')}</b>
      <div class="sx-h" style="margin-top:8px">${hs.map(h => `<div class="sx-host${h.id === S.cur ? ' on' : ''}" data-sxh="${E(h.id)}"><i>${/pi|rasp/i.test(h.name + h.user) ? '🍓' : '🗄'}</i><div style="min-width:0;flex:1"><b>${E(h.name)}</b><span>${E(h.user)}@${E(h.host)}${h.port !== 22 ? ':' + h.port : ''}</span></div></div>`).join('') ||
        `<div class="dim" style="font-size:12.5px">${T('Καμία ακόμα — πρόσθεσε το Raspberry Pi σου.', 'None yet — add your Raspberry Pi.')}</div>`}</div>
      ${(d.suggestions || []).length ? `<div class="dim" style="font-size:11.5px;margin-top:10px">${T('Βρέθηκαν στο δίκτυο:', 'Found on your network:')}</div><div class="sx-sug">${d.suggestions.map(s => `<button class="b" data-sxsug='${E(JSON.stringify(s))}'>＋ ${E(s.name)}</button>`).join('')}</div>` : ''}
      ${S.add ? `<div class="sx-form"><input id="sx-n" class="full" placeholder="${T('Όνομα (π.χ. Raspberry Pi)', 'Name (e.g. Raspberry Pi)')}" value="${E(S.add.name || '')}"><input id="sx-ip" placeholder="IP (192.168.1.50)" value="${E(S.add.host || '')}"><input id="sx-u" placeholder="${T('χρήστης (pi)', 'user (pi)')}" value="${E(S.add.user || 'pi')}"><input id="sx-p" placeholder="22" value="22"><button class="b" id="sx-save" style="border-color:var(--green);color:var(--green)">✓ ${T('Αποθήκευση', 'Save')}</button></div>
        <div class="dim" style="font-size:11.5px;margin-top:6px">🔑 ${T('Χωρίς κωδικό — η σύνδεση γίνεται μόνο με κλειδί SSH.', 'No password — connections use SSH keys only.')}</div>`
        : `<button class="b" id="sx-add" style="margin-top:10px;width:100%">＋ ${T('Πρόσθεσε συσκευή', 'Add device')}</button>`}
    </div>${keysHTML()}`;
  }
  function keysHTML() {
    const k = (S.d.keys || {}).keys || [], h = host() || { user: 'pi', host: '192.168.1.50', port: 22 };
    if (k.length) return `<div class="card dim" style="margin:10px 0 0;font-size:12px">🔑 ${T('Τα κλειδιά σου', 'Your keys')}: ${k.map(x => `<div style="margin-top:4px"><b style="color:var(--txt)">${E(x.file)}</b> · ${E(x.type)}<br><span style="font:11px ui-monospace,Menlo,Consolas,monospace">${E(x.fp)}</span></div>`).join('')}</div>`;
    return `<div class="card" style="margin:10px 0 0;border-left:4px solid var(--yellow)"><b>🔑 ${T('Δεν έχεις κλειδί SSH ακόμα', 'You have no SSH key yet')}</b>
      <div style="font-size:12.5px;margin-top:4px">${T('Δύο εντολές στο Terminal, μία φορά (τις τρέχεις εσύ — το NetWatch δεν αγγίζει κωδικούς):', 'Two commands in Terminal, once (you run them — NetWatch never touches passwords):')}</div>
      ${cmd('ssh-keygen -t ed25519', T('Πάτα Enter στις ερωτήσεις (καλό είναι να βάλεις passphrase).', 'Press Enter at the prompts (a passphrase is a good idea).'))}
      ${cmd(`ssh-copy-id ${h.port !== 22 ? '-p ' + h.port + ' ' : ''}${h.user}@${h.host}`, T('Θα ζητήσει τον κωδικό του Pi μία τελευταία φορά.', 'It asks for the Pi password one last time.'))}</div>`;
  }

  function errHTML(e) {
    return `<div class="card sx-err"><b>⚠ ${E(tr(e.error))}</b>${e.hint ? `<div style="font-size:13px;margin-top:4px">${/^(Βάλε|Put|Στο|On)/.test(e.hint) && /ssh-copy-id|raspi-config/.test(e.hint) ? E(tr(e.hint.split(': ')[0] + ':')) + cmd(e.hint.split(': ').slice(1).join(': ')) : E(tr(e.hint))}</div>` : ''}
      ${/κλειδί του host|host key/i.test(e.error + (e.hint || '')) ? `<button class="b" id="sx-hk" style="margin-top:8px">🔐 ${T('Έλεγχος κλειδιού host', 'Check host key')}</button>` : ''}${keyHTML()}</div>`;
  }
  function keyHTML() {
    const k = S.key; if (!k) return '';
    if (k.error) return `<div style="margin-top:8px;color:var(--yellow)">${E(tr(k.error))} ${E(tr(k.hint || ''))}</div>`;
    return `<div style="margin-top:10px;font-size:13px">${k.known ? '✅ ' + T('Το κλειδί είναι ήδη γνωστό.', 'Key already known.') : T('Αυτό είναι το «δαχτυλικό αποτύπωμα» του host. Αν θες απόλυτη σιγουριά, σύγκρινέ το στο Pi με: <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>', 'This is the host fingerprint. To be certain, compare it on the Pi with: <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>')}</div>
      ${(k.fingerprints || []).map(f => `<div class="sx-fp">${E(f.type)} · ${E(f.fp)}</div>`).join('')}
      ${!k.known && (k.fingerprints || []).length ? `<button class="b" id="sx-trust" data-fp="${E((k.fingerprints.find(f => /ED25519/i.test(f.type)) || k.fingerprints[0]).fp)}" style="margin-top:8px;border-color:var(--green);color:var(--green)">✓ ${T('Εμπιστεύομαι αυτή τη συσκευή', 'I trust this device')}</button>` : ''}`;
  }

  function filesHTML() {
    const ls = S.ls; if (!ls) return S.busy ? `<div class="dim" style="padding:20px">⏳ ${T('Σύνδεση…', 'Connecting…')}</div>` : '';
    const parts = ls.path.split('/').filter(Boolean);
    const crumb = `<a data-sxgo="/">/</a>` + parts.map((p, i) => `<a data-sxgo="${E('/' + parts.slice(0, i + 1).join('/'))}">${E(p)}</a><span class="dim">/</span>`).join('');
    const rows = ls.entries.map(e => `<tr class="r${S.file && S.file.name === e.name ? ' sel' : ''}" data-sx${e.type === 'd' || e.type === 'l' ? 'dir' : 'file'}="${E(e.name)}"><td>${fic(e)}</td><td class="n">${E(e.name)}</td><td class="m">${e.type === 'd' ? '' : size(e.size)}</td><td class="m">${when(e.mtime)}</td><td class="m">${E(e.mode)}</td></tr>`).join('');
    return `<div class="sx-crumb">${crumb}</div>
      <div class="sx-quick">${[['~', '🏠 home'], ['/', '/'], ['/etc', '/etc'], ['/var/log', '📜 /var/log'], ['/home', '/home']].map(([p, l]) => `<button class="b" data-sxgo="${p}">${l}</button>`).join('')}${parts.length ? `<button class="b" data-sxgo="${E('/' + parts.slice(0, -1).join('/'))}">⬆ ${T('Πάνω', 'Up')}</button>` : ''}</div>
      <div style="max-height:52vh;overflow:auto;margin-top:8px"><table class="sx-ls">${rows || `<tr><td class="dim">${T('Άδειος φάκελος', 'Empty folder')}</td></tr>`}</table></div>
      ${ls.truncated ? `<div class="dim" style="font-size:12px">${T('Δείχνω τα πρώτα 1500.', 'Showing the first 1500.')}</div>` : ''}
      ${fileHTML()}`;
  }
  function fileHTML() {
    const f = S.file; if (!f) return '';
    const head = `<div class="brow" style="margin-top:12px"><b>${fic({ name: f.name, type: 'f' })} ${E(f.full)}</b><span class="dim" style="font-size:12px">${size(f.size)}</span><span style="flex:1"></span>
      ${f.error ? '' : `<button class="b" id="sx-dl">⬇ ${T('Κατέβασμα', 'Download')}</button>`}<button class="b" id="sx-fx">✕</button></div>`;
    if (f.error) return `<div id="sx-file">${head}<div class="sx-chk" style="--c:var(--yellow)">${E(tr(f.error))}</div></div>`;
    if (f.binary) return `<div id="sx-file">${head}<div class="dim" style="margin-top:6px">${T('Δυαδικό αρχείο — δεν προβάλλεται. Μπορείς να το κατεβάσεις.', 'Binary file — no preview. You can download it.')}</div></div>`;
    const lines = f.text.split('\n'); if (lines[lines.length - 1] === '') lines.pop();
    return `<div id="sx-file">${head}<div class="sx-pre">${lines.slice(0, 5000).map(l => `<span>${E(l) || ' '}</span>`).join('')}</div>${f.truncated ? `<div class="dim" style="font-size:12px">${T('Δείχνω τα πρώτα 256 KB — κατέβασέ το για όλο.', 'Showing the first 256 KB — download for the rest.')}</div>` : ''}</div>`;
  }
  function infoHTML() {
    const i = S.info; if (!i) return S.busy ? `<div class="dim" style="padding:20px">⏳ ${T('Διαβάζω την κατάσταση…', 'Reading status…')}</div>` : '';
    const up = i.uptime_s != null ? (i.uptime_s >= 86400 ? Math.floor(i.uptime_s / 86400) + T(' μέρες', ' days') : Math.floor(i.uptime_s / 3600) + T(' ώρες', ' hours')) : '—';
    const m = i.mem || {}, mp = m.total ? Math.round(100 * (1 - m.avail / m.total)) : null;
    const tc = i.temp_c == null ? 'var(--dim)' : i.temp_c >= 80 ? 'var(--red)' : i.temp_c >= 70 ? 'var(--yellow)' : 'var(--green)';
    const bar = (p, c) => `<div class="sx-bar" style="--c:${c || (p >= 90 ? 'var(--red)' : p >= 80 ? 'var(--yellow)' : 'var(--green)')}"><i style="width:${p}%"></i></div>`;
    const lv = { ok: 'var(--green)', info: 'var(--cyan)', warn: 'var(--yellow)', bad: 'var(--red)' };
    return `<div style="margin-top:10px;font-size:13px"><b>${E(i.model || i.hostname)}</b> · ${E(i.os)} · <span class="dim">${E(i.kernel)}</span></div>
      <div class="sx-grid">
        <div class="card sx-k"><span>⏱ ${T('Σε λειτουργία', 'Uptime')}</span><b>${up}</b></div>
        <div class="card sx-k"><span>🌡 ${T('Θερμοκρασία', 'Temperature')}</span><b style="color:${tc}">${i.temp_c != null ? i.temp_c + '°C' : '—'}</b></div>
        <div class="card sx-k"><span>⚙️ ${T('Φόρτος', 'Load')} (${i.cpus || '?'} CPU)</span><b>${(i.load || []).map(x => x.toFixed(2)).join(' · ') || '—'}</b></div>
        <div class="card sx-k"><span>🧠 RAM</span><b>${mp != null ? mp + '%' : '—'}</b><span>${size(m.total - m.avail)} / ${size(m.total)}</span>${mp != null ? bar(mp) : ''}</div>
      </div>
      <div class="sx-grid">
        <div class="card" style="margin:0"><b>💽 ${T('Δίσκοι', 'Disks')}</b>${(i.disks || []).map(d => `<div style="margin-top:8px;font-size:12.5px"><span style="font-family:ui-monospace,Menlo,Consolas,monospace">${E(d.mount)}</span> <span class="dim">${size(d.used)} / ${size(d.size)} · ${d.pct}%</span>${bar(d.pct)}</div>`).join('')}</div>
        <div class="card" style="margin:0"><b>🔥 ${T('Πιο «βαριές» διεργασίες', 'Top processes')}</b>${(i.procs || []).map(p => `<div style="display:flex;gap:8px;font-size:12.5px;margin-top:5px"><span style="flex:1;font-family:ui-monospace,Menlo,Consolas,monospace">${E(p.cmd)}</span><span class="dim">${p.cpu}% CPU · ${p.mem}% RAM</span></div>`).join('')}</div>
        <div class="card" style="margin:0"><b>🔌 ${T('Ανοιχτές θύρες', 'Listening ports')}</b><div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:8px">${(i.ports || []).map(p => `<span class="tag">${p}</span>`).join('') || '—'}</div>
          <div class="dim" style="font-size:12px;margin-top:8px">IP: ${E((i.ips || []).join(', '))}</div></div>
      </div>
      <div class="card" style="margin-top:10px"><b>🛡 ${T('Γρήγορος έλεγχος', 'Quick check')}</b>${(i.checks || []).map(c => `<div class="sx-chk" style="--c:${lv[c.level]}">${E(EN() ? c.en : c.el)}${c.fix ? `<code>${E(c.fix)}</code>` : ''}</div>`).join('')}
        <div class="dim" style="font-size:11.5px;margin-top:8px">${T('Οι διορθώσεις είναι προτάσεις — τις τρέχεις εσύ στο Pi. Το NetWatch μόνο διαβάζει.', 'Fixes are suggestions — you run them on the Pi. NetWatch only reads.')}</div></div>`;
  }

  function draw() {
    const el = box(); if (!el) return;
    const d = S.d;
    if (!d) { el.innerHTML = `<div class="card dim" data-noi18n>⏳</div>`; return; }
    if (d.off) { el.innerHTML = `<div class="card dim" data-noi18n>${T('Δεν είναι διαθέσιμο σε αυτή τη λειτουργία.', 'Not available in this mode.')}</div>`; return; }
    const h = host();
    let main = '';
    if (!h) main = `<div class="card dim" style="text-align:center;padding:40px">🍓 ${T('Πρόσθεσε μια συσκευή αριστερά (π.χ. το Raspberry Pi σου) για να δεις τα αρχεία και την κατάστασή της.', 'Add a device on the left (e.g. your Raspberry Pi) to browse its files and status.')}</div>`;
    else {
      main = `<div class="card" style="margin:0"><div class="brow"><b class="ctitle">🍓 ${E(h.name)}</b><span class="dim" style="font:12px ui-monospace,Menlo,Consolas,monospace">${E(h.user)}@${E(h.host)}</span>${d.demo ? '<span class="op-pill" style="--c:var(--purple)">demo</span>' : ''}<span style="flex:1"></span>
        <button class="b" data-sxcp="ssh ${h.port !== 22 ? '-p ' + h.port + ' ' : ''}${E(h.user)}@${E(h.host)}" title="${T('Αντιγραφή εντολής για το Terminal', 'Copy command for Terminal')}">⌨️ Terminal</button><button class="b" id="sx-del" title="${T('Αφαίρεση', 'Remove')}">🗑</button></div>
        <div class="sx-tabs"><button class="b${S.view === 'files' ? ' on' : ''}" data-sxv="files">📁 ${T('Αρχεία', 'Files')}</button><button class="b${S.view === 'info' ? ' on' : ''}" data-sxv="info">📊 ${T('Κατάσταση', 'Status')}</button>
        ${S.busy ? '<span class="dim" style="margin-left:8px;align-self:center">⏳</span>' : ''}</div>
        ${S.err ? errHTML(S.err) : S.view === 'files' ? filesHTML() : infoHTML()}</div>`;
    }
    el.innerHTML = `<div data-noi18n><div class="card"><div class="brow"><b class="ctitle">🖥 SSH Explorer</b></div>
      <div class="dim" style="font-size:13px;margin-top:4px">${T('Δες τα αρχεία και την υγεία του Raspberry Pi ή του server σου. Με το OpenSSH του Mac, <b>μόνο με κλειδί</b> (ποτέ κωδικός), <b>μόνο ανάγνωση</b>, μόνο στο δικό σου δίκτυο.', 'Browse the files and health of your Raspberry Pi or server. Uses the Mac’s OpenSSH, <b>keys only</b> (never a password), <b>read-only</b>, local network only.')}</div>
      ${S.msg ? `<div style="color:var(--yellow);margin-top:6px">${E(S.msg)}</div>` : ''}</div>
      <div class="sx"><div>${hostsHTML()}</div><div>${main}</div></div></div>`;
  }

  document.addEventListener('click', ev => {
    const el = box(); if (!el || !el.contains(ev.target)) return;
    const t = ev.target.closest('button,[data-sxh],[data-sxgo],tr[data-sxdir],tr[data-sxfile]'); if (!t) return;
    const ds = t.dataset;
    if (ds.sxh) { S.view = 'files'; return select(ds.sxh); }
    if (ds.sxgo) return go(ds.sxgo);
    if (ds.sxdir != null) return go((S.ls.path.replace(/\/$/, '') || '') + '/' + ds.sxdir);
    if (ds.sxfile != null) return open(ds.sxfile);
    if (ds.sxv) { S.view = ds.sxv; if (ds.sxv === 'info' && !S.info && !S.err) return info(); if (ds.sxv === 'files' && !S.ls && !S.err) return go(S.path[S.cur] || '~'); return draw(); }
    if (ds.sxcp) { navigator.clipboard && navigator.clipboard.writeText(ds.sxcp); const o = t.textContent; t.textContent = '✓'; setTimeout(() => { t.textContent = o; }, 900); return; }
    if (ds.sxsug) { S.add = JSON.parse(ds.sxsug); return draw(); }
    if (t.id === 'sx-add') { S.add = {}; return draw(); }
    if (t.id === 'sx-save') {
      const v = id => (document.getElementById(id) || {}).value || '';
      return post('/api/ssh/host', { name: v('sx-n'), host: v('sx-ip'), user: v('sx-u'), port: +v('sx-p') || 22 }).then(j => {
        if (j.error) { S.msg = tr(j.error); return draw(); }
        S.add = false; S.msg = null; S.cur = j.host.id; S.err = null; load(); go('~');
      });
    }
    if (t.id === 'sx-del' && confirm(T('Να αφαιρεθεί η συσκευή από τη λίστα; (Δεν αγγίζει τη συσκευή.)', 'Remove this device from the list? (Does not touch the device.)')))
      return post('/api/ssh/host', { id: S.cur, delete: true }).then(() => { S.cur = null; S.ls = S.info = S.err = null; load(); });
    if (t.id === 'sx-hk') return hostkey();
    if (t.id === 'sx-trust') return post('/api/ssh/trust', { id: S.cur, fp: ds.fp }).then(j => { if (j.error) { S.key = { error: j.error }; return draw(); } S.key = null; S.err = null; S.view === 'info' ? info() : go(S.path[S.cur] || '~'); });
    if (t.id === 'sx-fx') { S.file = null; return draw(); }
    if (t.id === 'sx-dl' && S.file) {
      t.textContent = '⏳';
      return post('/api/ssh/fetch', { id: S.cur, path: S.file.full }).then(j => { if (j.error) { S.file.error = j.error; return draw(); } location.href = j.url; t.textContent = '✓'; });
    }
  });

  window.renderSsh = () => { if (!S.d) draw(); load(); };
})();
