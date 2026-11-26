// ───────────────────────── 🟢 «Πώς περνάω σε Live;» — οδηγίες όταν η εφαρμογή ανοίγει σε Demo ─────────────────────────
// Εμφανίζεται μία φορά ανά εκκίνηση όταν το backend τρέχει σε Demo (όχι CTF / pcap / στατικό demo του site).
// Ξανανοίγει με κλικ στο σήμα «DEMO» πάνω αριστερά. «Να μην ξαναεμφανιστεί» → localStorage.
(() => {
  'use strict';
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const KEY = 'nw-golive-hide';
  let host = null, shown = false;
  const get = k => { try { return localStorage.getItem(k); } catch (e) { return null; } };
  const set = (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* ιδιωτικό παράθυρο */ } };

  const css = document.createElement('style');
  css.textContent = `
#gl-back{position:fixed;inset:0;z-index:9000;background:rgb(0 0 0 / 55%);display:flex;align-items:center;justify-content:center;padding:16px}
#gl-box{background:#0d1524;color:var(--txt,#e6edf6);border:1px solid var(--line,#24324a);border-radius:16px;max-width:560px;width:100%;max-height:calc(100vh - 32px);overflow:auto;padding:20px 22px;box-shadow:0 20px 60px rgb(0 0 0 / 50%)}
html.light #gl-box{background:#fff}
#gl-box h3{margin:0 0 4px;font-size:18px}
#gl-box .gl-sub{color:var(--dim);font-size:13px;margin-bottom:12px;line-height:1.5}
#gl-box ol{margin:0;padding-left:22px;font-size:14px;line-height:1.6}
#gl-box li{margin:6px 0}
#gl-box code{background:rgb(127 127 127 / 18%);padding:1px 5px;border-radius:4px;font-size:12.5px}
#gl-box pre{background:#05080f;color:#d6e2f0;border-radius:8px;padding:8px 10px;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;overflow:auto;margin:6px 0 0;white-space:pre-wrap;word-break:break-all}
#gl-box .gl-ok{border-left:3px solid var(--green);padding:6px 10px;margin-top:12px;font-size:13px;line-height:1.5;background:rgb(127 127 127 / 8%);border-radius:6px}
#gl-box .gl-foot{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-top:16px}
#gl-box label{font-size:12.5px;color:var(--dim);display:flex;gap:6px;align-items:center;cursor:pointer}
#mode.demo,#mode.gl-sw{cursor:pointer}
#gl-box .gl-sw{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
#gl-box .gl-sw .b{padding:8px 14px}
#gl-box .gl-go{border-color:var(--green)!important;color:var(--green)!important;font-weight:700}
#gl-box .gl-msg{margin-top:8px;font-size:13px}
`;
  document.head.appendChild(css);

  const NPCAP = '<a href="https://npcap.com/#download" target="_blank" rel="noopener">npcap.com</a>';
  const SHIELD = () => T('την ασπίδα 🛡 NetWatch κάτω δεξιά (αν δεν φαίνεται, πάτα το βελάκι <b>^</b> δίπλα στο ρολόι)',
    'the 🛡 NetWatch shield at the bottom right (if hidden, click the <b>^</b> arrow next to the clock)');

  function steps(h) {
    const os = (h && h.os) || '';
    if (os === 'win32') {
      const s = [];
      if (!h.npcap && h.npcap_get) s.push(T('Χρειάζεται το δωρεάν <b>Npcap</b> (χωρίς αυτό τα Windows δεν αφήνουν κανένα πρόγραμμα να «ακούει» το δίκτυο). Πάτα το κουμπί: το κατεβάζω από το επίσημο npcap.com, ελέγχω την ψηφιακή του υπογραφή και ανοίγω την εγκατάσταση. Εκεί πάτα «Ναι», τσέκαρε <b>«WinPcap API-compatible Mode»</b> και «Install».',
        'You need the free <b>Npcap</b> (without it Windows lets no program listen to the network). Click the button: I download it from the official npcap.com, check its digital signature and open the installer. There click “Yes”, tick <b>“WinPcap API-compatible Mode”</b> and “Install”.') +
        `<div class="gl-sw"><button class="b gl-go" data-npcap>⬇ ${T('Κατέβασε & εγκατάστησε το Npcap', 'Download & install Npcap')}</button></div><div class="gl-msg" id="gl-np"></div>`);
      else if (!h.npcap) s.push(T(`Κατέβασε και εγκατάστησε το δωρεάν <b>Npcap</b> από ${NPCAP}. Στην εγκατάσταση τσέκαρε το <b>«Install Npcap in WinPcap API-compatible Mode»</b>. Χωρίς αυτό τα Windows δεν αφήνουν κανένα πρόγραμμα να «ακούει» το δίκτυο.`,
        `Download and install the free <b>Npcap</b> from ${NPCAP}. During setup tick <b>“Install Npcap in WinPcap API-compatible Mode”</b>. Without it, Windows lets no program listen to the network.`));
      else s.push(T('✅ Το Npcap είναι ήδη εγκατεστημένο.', '✅ Npcap is already installed.'));
      if (h.app_switch) {
        s.push(T('Πάτα <b>«🟢 Πέρασε σε Live τώρα»</b> εδώ κάτω. Για μπλοκάρισμα IP και τον έλεγχο Rogue DHCP/ARP πάτα <b>«🛡 Live ως διαχειριστής»</b> (τα Windows θα ζητήσουν άδεια).',
          'Click <b>“🟢 Switch to Live now”</b> below. For IP blocking and the Rogue DHCP/ARP check click <b>“🛡 Live as administrator”</b> (Windows will ask for permission).'));
        return s;
      }
      s.push(T(`Κάνε <b>δεξί κλικ</b> σε ${SHIELD()}.`, `<b>Right-click</b> ${SHIELD()}.`));
      s.push(T('Διάλεξε <b>«Live — πραγματική κίνηση»</b>. Για μπλοκάρισμα IP και τον έλεγχο Rogue DHCP/ARP διάλεξε <b>«Live ως διαχειριστής»</b> (τα Windows θα ζητήσουν άδεια).',
        'Choose <b>“Live — πραγματική κίνηση”</b> (Live — real traffic). For IP blocking and the Rogue DHCP/ARP check choose <b>“Live ως διαχειριστής”</b> (Live as administrator); Windows will ask for permission.'));
      if (!h.npcap) s.push(T('Αν μετά την εγκατάσταση μένει σε Demo, κλείσε το NetWatch (δεξί κλικ στην ασπίδα → Έξοδος) και άνοιξέ το ξανά.',
        'If it stays in Demo after installing, quit NetWatch (right-click the shield → Exit) and open it again.'));
      return s;
    }
    if (os === 'darwin' && h.app_switch) return [
      T('Πάτα <b>«🟢 Πέρασε σε Live τώρα»</b> εδώ κάτω (ή το εικονίδιο του NetWatch στη γραμμή μενού → «Live»).', 'Click <b>“🟢 Switch to Live now”</b> below (or the NetWatch icon in the menu bar → “Live”).'),
      T('Βάλε τον κωδικό του Mac όταν σου τον ζητήσει το macOS. Τον ζητά το ίδιο το σύστημα, γιατί η καταγραφή πακέτων θέλει δικαιώματα διαχειριστή. Το NetWatch δεν βλέπει και δεν αποθηκεύει τον κωδικό.',
        'Enter your Mac password when macOS asks. The system itself asks, because packet capture needs admin rights. NetWatch never sees or stores the password.'),
    ];
    if (os === 'darwin') return [
      T('Πάτα το εικονίδιο του NetWatch στη <b>γραμμή μενού</b> πάνω δεξιά.', 'Click the NetWatch icon in the <b>menu bar</b> at the top right.'),
      T('Διάλεξε <b>«Live — πραγματική κίνηση»</b>.', 'Choose <b>“Live — πραγματική κίνηση”</b> (Live — real traffic).'),
      T('Βάλε τον κωδικό του Mac όταν σου τον ζητήσει το macOS. Τον ζητά το ίδιο το σύστημα, γιατί η καταγραφή πακέτων θέλει δικαιώματα διαχειριστή. Το NetWatch δεν βλέπει και δεν αποθηκεύει τον κωδικό.',
        'Enter your Mac password when macOS asks. The system itself asks, because packet capture needs admin rights. NetWatch never sees or stores the password.'),
    ];
    if (h && h.docker) return [
      T('Σταμάτα το container και ξεκίνα το <b>χωρίς</b> <code>--demo</code>, στο δίκτυο του host και με δικαίωμα καταγραφής:', 'Stop the container and start it <b>without</b> <code>--demo</code>, on the host network and with capture rights:') +
        '<pre>docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN netwatch</pre>',
      T('Στο Docker Desktop (Mac/Windows) το container δεν βλέπει το πραγματικό σου δίκτυο. Εκεί χρησιμοποίησε την εφαρμογή για Mac ή Windows.',
        'On Docker Desktop (Mac/Windows) the container cannot see your real network. Use the Mac or Windows app there instead.'),
    ];
    return [
      T('Σταμάτα το NetWatch (Ctrl+C στο τερματικό).', 'Stop NetWatch (Ctrl+C in the terminal).'),
      T('Ξεκίνα το <b>χωρίς</b> <code>--demo</code> και με δικαιώματα καταγραφής:', 'Start it <b>without</b> <code>--demo</code> and with capture rights:') +
        '<pre>sudo .venv/bin/python netwatch.py</pre>',
    ];
  }

  // Windows: ο launcher (ασπίδα) διαβάζει το αίτημα, ξεκινά νέο backend και ανοίγει νέο παράθυρο
  function switchTo(mode) {
    const msg = document.getElementById('gl-msg');
    document.querySelectorAll('#gl-box [data-glmode]').forEach(b => { b.disabled = true; });
    fetch('/api/app/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }) })
      .then(r => r.json()).then(j => {
        if (j.error) throw new Error(j.error);
        if (msg && host && host.os === 'darwin') { msg.innerHTML = '⏳ ' + (mode === 'demo' ? T('Ξεκινά το Demo…', 'Starting Demo…') : T('Ξεκινά το Live — <b>βάλε τον κωδικό του Mac</b> όταν τον ζητήσει το macOS.', 'Starting Live — <b>enter your Mac password</b> when macOS asks.')); return; }
        if (msg) msg.innerHTML = '⏳ ' + (mode === 'demo' ? T('Ξεκινά το Demo…', 'Starting Demo…') : mode === 'live-admin'
          ? T('Ξεκινά το Live. <b>Πάτα «Ναι»</b> όταν τα Windows ζητήσουν άδεια διαχειριστή.', 'Starting Live. <b>Click “Yes”</b> when Windows asks for administrator permission.')
          : T('Ξεκινά το Live…', 'Starting Live…')) + ' ' + T('Θα ανοίξει νέο παράθυρο και αυτό θα κλείσει.', 'A new window will open and this one will close.');
        setTimeout(() => { try { window.close(); } catch (e) { /* */ } }, 9000);
      }).catch(e => {
        document.querySelectorAll('#gl-box [data-glmode]').forEach(b => { b.disabled = false; });
        if (msg) msg.textContent = '✖ ' + e.message;
      });
  }
  // σε Live: κλικ στο σήμα → μικρό παράθυρο για επιστροφή σε Demo / Live ως διαχειριστής
  function openSwitch() {
    close();
    const d = document.createElement('div');
    d.id = 'gl-back';
    d.setAttribute('data-noi18n', '');
    d.innerHTML = `<div id="gl-box" role="dialog" aria-modal="true" aria-labelledby="gl-t" style="max-width:440px">
      <h3 id="gl-t">● ${T('Λειτουργία NetWatch', 'NetWatch mode')}</h3>
      <div class="gl-sub">${T('Τώρα βλέπεις την <b>πραγματική</b> κίνηση του δικτύου σου.', 'You are now watching your <b>real</b> network traffic.')}</div>
      <div class="gl-sw"><button class="b" data-glmode="demo">🎭 ${T('Πέρασε σε Demo', 'Switch to Demo')}</button>${host && host.os === 'darwin' ? '' : `<button class="b" data-glmode="live-admin">🛡 ${T('Live ως διαχειριστής', 'Live as administrator')}</button><button class="b" data-glmode="live">🟢 ${T('Live (κανονικό)', 'Live (normal)')}</button>`}</div>
      <div class="gl-msg dim" id="gl-msg">${host && host.os === 'darwin' ? '' : T('Το «ως διαχειριστής» χρειάζεται για μπλοκάρισμα IP και τον έλεγχο Rogue DHCP/ARP.', '“As administrator” is needed for IP blocking and the Rogue DHCP/ARP check.')}</div>
      <div class="gl-foot"><span></span><button class="b" id="gl-ok">${T('Κλείσιμο', 'Close')}</button></div></div>`;
    document.body.appendChild(d);
    d.addEventListener('click', e => {
      if (e.target === d || e.target.id === 'gl-ok') return close();
      const sw = e.target.closest('[data-glmode]'); if (sw) switchTo(sw.dataset.glmode);
    });
  }

  // ⬇ Npcap (Windows): το backend το κατεβάζει από npcap.com, ελέγχει υπογραφή και ανοίγει τον installer
  function npcap(btn) {
    const m = document.getElementById('gl-np');
    btn.disabled = true;
    const tr = x => (EN() && window.I18N && I18N.t ? I18N.t(String(x || '')) : String(x || ''));
    const show = j => { if (m) m.innerHTML = (j.state === 'error' ? '✖ ' : j.state === 'done' ? '✅ ' : '⏳ ') + tr(j.step || '') + (j.state === 'running' && j.pct ? ` ${Math.round(j.pct * 100)}%` : ''); };
    const poll = () => fetch('/api/npcap').then(r => r.json()).then(v => {
      const j = v.job || {}; show(j);
      if (j.state === 'running') setTimeout(poll, 800);
      else btn.disabled = j.state === 'done';
    }).catch(() => { btn.disabled = false; });
    fetch('/api/npcap/install', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
      .then(r => r.json()).then(j => { if (j.error) { show({ state: 'error', step: j.error }); btn.disabled = false; } else poll(); })
      .catch(() => { btn.disabled = false; });
  }

  function close() { const b = document.getElementById('gl-back'); if (b) b.remove(); }
  function open() {
    close();
    const h = host || {};
    const d = document.createElement('div');
    d.id = 'gl-back';
    d.setAttribute('data-noi18n', '');
    d.innerHTML = `<div id="gl-box" role="dialog" aria-modal="true" aria-labelledby="gl-t">
      <h3 id="gl-t">🎭 ${T('Βλέπεις το Demo', 'You are in Demo mode')}</h3>
      <div class="gl-sub">${T('Ό,τι βλέπεις τώρα είναι <b>προσομοίωση</b>: ψεύτικες συσκευές και επιθέσεις για να γνωρίσεις την εφαρμογή. Για να δεις το <b>δικό σου</b> δίκτυο, πέρασε σε <b>Live</b>:',
        'Everything you see now is a <b>simulation</b>: fake devices and attacks to get to know the app. To see <b>your own</b> network, switch to <b>Live</b>:')}</div>
      <ol>${steps(h).map(s => `<li>${s}</li>`).join('')}</ol>
      ${h.app_switch && h.os === 'darwin' ? `<div class="gl-sw"><button class="b gl-go" data-glmode="live">🟢 ${T('Πέρασε σε Live τώρα', 'Switch to Live now')}</button></div><div class="gl-msg dim" id="gl-msg"></div>` : ''}
      ${h.app_switch && h.os !== 'darwin' ? `<div class="gl-sw"><button class="b gl-go" data-glmode="live">🟢 ${T('Πέρασε σε Live τώρα', 'Switch to Live now')}</button><button class="b" data-glmode="live-admin">🛡 ${T('Live ως διαχειριστής', 'Live as administrator')}</button></div><div class="gl-msg dim" id="gl-msg">${T('Το ίδιο κάνεις και από την ασπίδα 🛡 κάτω δεξιά (δεξί κλικ· αν δεν φαίνεται, πάτα το βελάκι ^ δίπλα στο ρολόι).', 'You can also do it from the 🛡 shield at the bottom right (right-click; if hidden, click the ^ arrow next to the clock).')}</div>` : ''}
      <div class="gl-ok">${T('Πώς καταλαβαίνω ότι πέτυχε; Πάνω αριστερά το σήμα γίνεται <b>● LIVE</b> και στο «interface» βλέπεις την πραγματική σου κάρτα δικτύου και IP.',
        'How do I know it worked? At the top left the badge turns <b>● LIVE</b> and “interface” shows your real network card and IP.')}<br>
        🔒 ${T('Το NetWatch μόνο παρακολουθεί. Δεν στέλνει πουθενά το περιεχόμενο της κίνησής σου ούτε κωδικούς. Προς τα έξω πάνε μόνο οι δημόσιες IP για τον χάρτη (γεωεντοπισμός) και ο έλεγχος για νέα έκδοση.', 'NetWatch only watches. It never sends your traffic contents or passwords anywhere. Only public IP addresses for the map (geolocation) and the check for a new version go out.')}</div>
      <div class="gl-foot"><label><input type="checkbox" id="gl-hide"${get(KEY) ? ' checked' : ''}> ${T('Να μην εμφανίζεται στην εκκίνηση', 'Don’t show at startup')}</label>
        <span style="display:flex;gap:8px"><button class="b" id="gl-ok">${T('Εντάξει, συνεχίζω στο Demo', 'OK, stay in Demo')}</button></span></div></div>`;
    document.body.appendChild(d);
    d.addEventListener('click', e => {
      if (e.target === d || e.target.id === 'gl-ok') return close();
      if (e.target.closest('[data-npcap]')) return npcap(e.target.closest('[data-npcap]'));
      const sw = e.target.closest('[data-glmode]'); if (sw) switchTo(sw.dataset.glmode);
    });
    d.querySelector('#gl-hide').addEventListener('change', e => set(KEY, e.target.checked ? '1' : ''));
    const ok = d.querySelector('#gl-ok'); if (ok) ok.focus();
  }
  document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });
  // κλικ στο σήμα DEMO → ξανά οι οδηγίες
  document.addEventListener('click', e => {
    if (!e.target.closest || !e.target.closest('#mode') || !host) return;
    if (window.__nwMode === 'demo') open();
    else if (window.__nwMode === 'live' && host.app_switch) openSwitch();
  });

  // καλείται από το handle(snapshot) του index.html
  window.goLiveCheck = m => {
    host = m.host || null;
    window.__nwMode = m.feed === 'ctf' ? 'ctf' : m.mode;
    const b = document.getElementById('mode');
    const sw = !!(host && host.app_switch && window.__nwMode === 'live');
    if (b) {
      b.classList.toggle('gl-sw', sw);
      b.title = window.__nwMode === 'demo' && host ? T('Demo — πάτα για οδηγίες για Live', 'Demo — click for Live instructions') : sw ? T('Live — πάτα για αλλαγή λειτουργίας', 'Live — click to change mode') : '';
    }
    if (shown || !host || window.__nwMode !== 'demo' || get(KEY)) return;
    if (/[?&](notour|nolive)\b/.test(location.search) && !/[?&]golive\b/.test(location.search)) return;
    shown = true;
    setTimeout(() => { if (!document.querySelector('.tour,.nw-tour,#tour')) open(); else shown = false; }, 1200);
  };
  window.showGoLive = open;
})();
