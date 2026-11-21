// ───────────────────────── 🔄 Ενημερώσεις από GitHub (έλεγχος + ασφαλής εγκατάσταση με κλικ) ─────────────────────────
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const tr = x => (EN() && window.I18N && I18N.t ? I18N.t(String(x || '')) : String(x || ''));
  const post = u => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(r => r.json());
  const box = () => document.getElementById('t-upd');
  let V = null, poll = null, busy = false;

  const css = document.createElement('style');
  css.textContent = `
#upd-pill{display:none;border-radius:999px;border:1px solid var(--green)!important;color:var(--green)!important;font-weight:600;white-space:nowrap}
#upd-pill.on{display:inline-flex;align-items:center;gap:4px}
#t-upd .up-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-upd .up-ic{font-size:34px}
#t-upd .up-ver{font:600 13px ui-monospace,Menlo,Consolas,monospace;background:rgb(var(--w,255 255 255) / 6%);border-radius:8px;padding:3px 8px}
#t-upd .up-notes{font-size:13px;line-height:1.6;max-height:320px;overflow:auto;background:rgb(var(--w,255 255 255) / 4%);border-radius:10px;padding:10px 14px;margin-top:10px}
#t-upd .up-notes h1,#t-upd .up-notes h2,#t-upd .up-notes h3{font-size:14px;margin:8px 0 4px}
#t-upd .up-bar{height:8px;border-radius:99px;background:rgb(var(--w,255 255 255) / 8%);overflow:hidden;margin-top:8px}
#t-upd .up-bar i{display:block;height:100%;background:var(--cyan);transition:width .3s}
#t-upd .up-steps{display:grid;gap:6px;margin-top:8px;font-size:13px}
#t-upd .up-steps div{display:flex;gap:8px}
#t-upd .up-go{border-color:var(--green)!important;color:var(--green)!important;font-weight:600}
#t-upd .up-warn{color:var(--orange);font-size:13px;margin-top:8px}
#t-upd .up-err{color:var(--red);font-size:13px;margin-top:8px}
#t-upd code{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px}
`;
  document.head.appendChild(css);

  // λίγο markdown από τις σημειώσεις του release (χωρίς HTML)
  const md = s => E(s).split('\n').map(l => {
    const il = x => x.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>');
    if (/^#{1,3}\s/.test(l)) return `<h3>${il(l.replace(/^#+\s*/, ''))}</h3>`;
    if (/^\s*[-*]\s/.test(l)) return `<div>• ${il(l.replace(/^\s*[-*]\s*/, ''))}</div>`;
    return l.trim() ? `<div>${il(l)}</div>` : '';
  }).join('');
  const when = t => t ? new Date(t * 1000).toLocaleString(EN() ? 'en-GB' : 'el-GR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : T('ποτέ', 'never');
  const KIND = () => ({ app: T('Mac app (NetWatch.app)', 'Mac app (NetWatch.app)'), git: T('κώδικας από git clone', 'source from git clone'), docker: 'Docker', winapp: T('Windows app (NetWatch.exe)', 'Windows app (NetWatch.exe)'), files: T('αρχεία', 'files') });

  function pill() {
    let p = document.getElementById('upd-pill');
    if (!p) {
      const ref = document.getElementById('mode-btn'); if (!ref) return;
      p = document.createElement('button'); p.id = 'upd-pill'; p.className = 'b hbtn'; p.setAttribute('data-noi18n', '');
      p.onclick = () => window.showTab && showTab('upd');
      ref.parentNode.insertBefore(p, ref);
    }
    const on = V && V.available;
    p.classList.toggle('on', !!on);
    if (on) { p.textContent = '🆕 ' + (V.latest ? V.latest.tag : T('ενημέρωση', 'update')); p.title = T('Βγήκε νέα έκδοση του NetWatch', 'A new NetWatch version is out'); }
  }

  function draw() {
    const b = box(); if (!b || !V) return;
    b.setAttribute('data-noi18n', '');
    if (V.off) { b.innerHTML = `<div class="card">${T('Οι ενημερώσεις δεν είναι διαθέσιμες σε αυτή τη λειτουργία.', 'Updates are not available in this mode.')}</div>`; return; }
    const L = V.latest, j = V.job || {}, g = V.git;
    let h = `<div class="card"><div class="up-hero"><span class="up-ic">${V.available ? '🆕' : '✅'}</span><div style="flex:1;min-width:220px">
      <b style="font-size:16px">${V.available ? T('Υπάρχει νέα έκδοση!', 'A new version is available!') : V.error ? T('Έλεγχος ενημερώσεων', 'Update check') : T('Έχεις την πιο πρόσφατη έκδοση', 'You are up to date')}</b>
      <div class="dim" style="font-size:12.5px;margin-top:3px">${T('Τώρα', 'Now')}: <span class="up-ver">v${E(V.version)}</span>${L && L.tag ? ` · ${T('στο GitHub', 'on GitHub')}: <span class="up-ver">${E(L.tag)}</span>` : ''} · ${E(KIND()[V.kind] || V.kind)} · ${T('τελευταίος έλεγχος', 'last checked')} ${when(V.checked)}</div></div>
      <button class="b" data-up="check"${busy ? ' disabled' : ''}>🔄 ${T('Έλεγχος τώρα', 'Check now')}</button></div>`;
    if (V.sim) h += `<div class="up-warn">🧪 ${T('Demo: η «νέα έκδοση» εδώ είναι προσομοίωση, όχι πραγματική.', 'Demo: the “new version” shown here is simulated, not real.')}</div>`;
    if (V.error) h += `<div class="up-warn">⚠ ${E(tr(V.error))}</div>`;
    if (g && g.error) h += `<div class="up-warn">⚠ ${E(tr(g.error))}</div>`;
    if (V.kind === 'git' && g && !g.error) h += `<div class="dim" style="font-size:12.5px;margin-top:8px">🌿 ${E(g.branch)} → ${E(g.upstream)} · ${g.behind ? T(`${g.behind} νέα commits`, `${g.behind} new commits`) : T('ενημερωμένο', 'up to date')}${g.dirty ? ' · ⚠ ' + T('τοπικές αλλαγές', 'local changes') : ''}</div>`
      + (g.commits && g.commits.length ? `<div class="up-notes">${g.commits.map(c => `<div><code>${E(c.slice(0, 7))}</code> ${E(c.slice(8))}</div>`).join('')}</div>` : '');
    if (L && V.available && V.kind !== 'git') h += `<div class="up-notes"><b>${E(L.name || L.tag)}</b>${L.date ? ` <span class="dim">· ${E(L.date.slice(0, 10))}</span>` : ''}${md(L.notes || '') || `<div class="dim">${T('(χωρίς σημειώσεις)', '(no release notes)')}</div>`}</div>`;
    if (V.available) {
      if (j.state === 'running') h += `<div style="margin-top:12px"><b>⏳ ${E(tr(j.step || ''))}</b><div class="up-bar"><i style="width:${Math.round((j.pct || 0) * 100)}%"></i></div></div>`;
      else if (j.state === 'done') h += `<div style="margin-top:12px;color:var(--green)"><b>✔ ${E(tr(j.step))}</b></div><div style="margin-top:8px"><button class="b up-go" data-up="restart">↻ ${T('Επανεκκίνηση τώρα', 'Restart now')}</button></div>`;
      else {
        if (j.state === 'error') h += `<div class="up-err">✖ ${E(tr(j.step))}</div>`;
        h += V.can_install ? `<div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap"><button class="b up-go" data-up="install">⬇ ${V.kind === 'git' ? T('Ενημέρωση (git pull)', 'Update (git pull)') : T('Εγκατάσταση', 'Install')} ${E(V.kind === 'git' ? '' : L.tag)}</button><a class="b" href="${E(L && L.url || V.page)}" target="_blank" rel="noopener">GitHub ↗</a></div>`
          : `<div class="up-warn">ℹ️ ${E(tr(V.why_not))}</div><div style="margin-top:8px"><a class="b" href="${E(L && L.url || V.page)}" target="_blank" rel="noopener">⬇ ${T('Άνοιγμα στο GitHub', 'Open on GitHub')} ↗</a></div>`;
      }
    }
    h += `</div>`;
    h += `<div class="card"><b>🔐 ${T('Πώς προστατεύεσαι', 'How you are protected')}</b><div class="up-steps">
      <div>1️⃣ <span>${T('Ρωτάω μόνο το <code>api.github.com</code> για το repo του NetWatch — δεν στέλνω τίποτα για εσένα ή το δίκτυό σου. Αυτόματα μόνο <b>ενημερώνω</b>· ποτέ δεν εγκαθιστώ μόνο μου.', 'I only ask <code>api.github.com</code> about the NetWatch repo — nothing about you or your network is sent. Automatically I only <b>notify</b>; I never install by myself.')}</span></div>
      <div>2️⃣ <span>${T('Ελέγχω την <b>ψηφιακή υπογραφή</b> του <code>SHA256SUMS</code> με το κλειδί που είναι ήδη μέσα στο app σου (<code>ssh-keygen -Y verify</code>). Λάθος ή καθόλου υπογραφή → δεν αλλάζει τίποτα.', 'I verify the <b>digital signature</b> of <code>SHA256SUMS</code> against the key already inside your app (<code>ssh-keygen -Y verify</code>). Wrong or missing signature → nothing changes.')}</span></div>
      ${V.kind === 'app' ? `<div>3️⃣ <span>${T('Ελέγχω το <b>SHA-256</b> του αρχείου, το bundle id, την έκδοση και το <code>codesign</code>.', 'I check the file’s <b>SHA-256</b>, the bundle id, the version and <code>codesign</code>.')}</span></div>
      <div>4️⃣ <span>${T('Κρατάω την παλιά έκδοση ως <code>NetWatch.app.previous</code> — αν κάτι πάει στραβά, γυρνάω πίσω.', 'I keep the old version as <code>NetWatch.app.previous</code> — if anything goes wrong, I roll back.')}</span></div>`
      : V.kind === 'winapp' ? `<div>3️⃣ <span>${T('Ελέγχω το <b>SHA-256</b> του <code>NetWatch-windows-x64.zip</code>, ότι περιέχει <code>NetWatch.exe</code> και ότι η έκδοση ταιριάζει με το tag.', 'I check the <b>SHA-256</b> of <code>NetWatch-windows-x64.zip</code>, that it contains <code>NetWatch.exe</code> and that its version matches the tag.')}</span></div>
      <div>4️⃣ <span>${T('Στην «Επανεκκίνηση» το NetWatch κλείνει, ο φάκελος αλλάζει και ανοίγει η νέα έκδοση. Η παλιά μένει ως <code>NetWatch.previous</code> δίπλα του· ρυθμίσεις και δεδομένα (στο %LOCALAPPDATA%) δεν πειράζονται.', 'On “Restart” NetWatch closes, the folder is swapped and the new version opens. The old one stays next to it as <code>NetWatch.previous</code>; settings and data (in %LOCALAPPDATA%) are untouched.')}</span></div>`
      : V.os === 'win32' ? `<div>3️⃣ <span>${T('Στα Windows <b>δεν</b> εγκαθιστώ μόνο μου: κατεβάζεις το <code>NetWatch-windows-x64.zip</code> από το GitHub (και αν θες ελέγχεις το SHA-256 με <code>Get-FileHash</code> απέναντι στο <code>SHA256SUMS</code>).', 'On Windows I do <b>not</b> install by myself: you download <code>NetWatch-windows-x64.zip</code> from GitHub (optionally check its SHA-256 with <code>Get-FileHash</code> against <code>SHA256SUMS</code>).')}</span></div>
      <div>4️⃣ <span>${T('Κλείσε το NetWatch (ασπίδα δίπλα στο ρολόι → Έξοδος), αντικατέστησε τον φάκελο και άνοιξέ το ξανά. Οι ρυθμίσεις και τα δεδομένα σου είναι στο %LOCALAPPDATA% και μένουν.', 'Quit NetWatch (shield next to the clock → Έξοδος / Exit), replace the folder and start it again. Your settings and data live in %LOCALAPPDATA% and are kept.')}</span></div>`
      : `<div>3️⃣ <span>${T('Ελέγχω το <b>SHA-256</b> κάθε αρχείου πριν το χρησιμοποιήσω.', 'I check every file’s <b>SHA-256</b> before using it.')}</span></div>`}</div>
      <div class="dim" style="font-size:12px;margin-top:10px">${V.auto ? T('Αυτόματος έλεγχος: μία φορά τη μέρα (κλείνει με <code>updates: {auto_check: false}</code> στο config.yaml).', 'Automatic check: once a day (turn off with <code>updates: {auto_check: false}</code> in config.yaml).') : T('Αυτόματος έλεγχος: κλειστός.', 'Automatic check: off.')}</div></div>`;
    b.innerHTML = h;
  }

  function load() { return fetch('/api/update').then(r => r.json()).then(j => { V = j; pill(); draw(); watch(); }).catch(() => { V = { off: true }; draw(); }); }
  function watch() {
    const running = V && V.job && V.job.state === 'running';
    if (running && !poll) poll = setInterval(load, 1000);
    if (!running && poll) { clearInterval(poll); poll = null; }
  }
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-upd [data-up]'); if (!b) return;
    const a = b.dataset.up;
    if (a === 'restart' && !confirm(T('Να κλείσει και να ξανανοίξει το NetWatch στη νέα έκδοση;', 'Close and reopen NetWatch on the new version?'))) return;
    busy = true; draw();
    post('/api/update/' + a).then(j => {
      busy = false;
      if (a === 'check') { V = j; pill(); draw(); return; }
      if (j.error) { alert(tr(j.error)); }
      if (a === 'restart' && j.ok && j.closing) { box().innerHTML = `<div class="card">↻ ${T('Το NetWatch κλείνει και ανοίγει ξανά στη νέα έκδοση σε λίγα δευτερόλεπτα…', 'NetWatch is closing and will reopen on the new version in a few seconds…')}</div>`; setTimeout(() => { try { window.close(); } catch (e) { /* */ } }, 6000); return; }
      if (a === 'restart' && j.ok) { box().innerHTML = `<div class="card">↻ ${j.demo ? T('Demo: εδώ θα γινόταν επανεκκίνηση.', 'Demo: this is where it would restart.') : T('Επανεκκίνηση… το NetWatch θα ανοίξει ξανά σε λίγα δευτερόλεπτα.', 'Restarting… NetWatch will reopen in a few seconds.')}</div>`; return; }
      load();
    }).catch(() => { busy = false; draw(); });
  });

  window.renderUpd = () => load();
  const init = () => { load(); setInterval(() => { if (!poll) load(); }, 30 * 60 * 1000); };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
