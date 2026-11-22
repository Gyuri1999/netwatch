// ───────────────────────── 🛰 Απομακρυσμένη πρόσβαση στο κουτί (WireGuard) ─────────────────────────
// Backend: remote.py (/api/kit/remote). Το ιδιωτικό κλειδί δεν φτάνει ποτέ στον browser — μένει στο data/remote/nw0.conf.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const box = () => document.getElementById('t-remote');
  let D = null, msg = '', edit = false, draft = null;

  const css = document.createElement('style');
  css.textContent = `
#t-remote{min-width:0}
#t-remote .card{min-width:0;max-width:100%}
#t-remote .rm-hero{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
#t-remote .rm-big{font-size:34px}
#t-remote .rm-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px;margin-top:10px}
#t-remote label{display:block;font-size:12px;color:var(--dim)}
#t-remote input[type=text]{width:100%;margin-top:3px;padding:7px 10px;border-radius:8px;border:1px solid rgb(var(--w,255 255 255) / 15%);background:transparent;color:inherit;font:inherit;box-sizing:border-box}
#t-remote pre{padding:9px 11px;border-radius:8px;background:rgb(var(--w,255 255 255) / 5%);font-size:12px;overflow-x:auto;margin:6px 0 0;white-space:pre-wrap;word-break:break-all}
#t-remote .rm-step{border-left:3px solid var(--cyan);border-radius:8px;background:rgb(var(--w,255 255 255) / 3%);padding:9px 12px;margin-top:9px;font-size:13px}
#t-remote .rm-step b.n{display:inline-block;width:20px;height:20px;line-height:20px;text-align:center;border-radius:50%;background:var(--cyan);color:#000;font-size:12px;margin-right:6px}
#t-remote .rm-chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
#t-remote .rm-chip{font-size:12px;padding:3px 9px;border-radius:10px;background:rgb(var(--w,255 255 255) / 6%)}
#t-remote ol,#t-remote ul{margin:6px 0 0 18px;padding:0;font-size:13px}#t-remote li{margin:3px 0}
`;
  document.head.appendChild(css);

  const mb = n => n >= 1e9 ? (n / 1e9).toFixed(1) + ' GB' : n >= 1e6 ? (n / 1e6).toFixed(1) + ' MB' : Math.round((n || 0) / 1e3) + ' kB';
  const ago = s => s == null ? T('ποτέ', 'never') : s < 90 ? T(`πριν ${s}″`, `${s}s ago`) : s < 5400 ? T(`πριν ${Math.round(s / 60)}′`, `${Math.round(s / 60)} min ago`) : T(`πριν ${Math.round(s / 3600)} ώρες`, `${Math.round(s / 3600)} h ago`);
  const post = (sub, body) => fetch('/api/kit/remote/' + sub, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then(r => r.json());

  function status(l) {
    const S = {
      up: ['🟢', 'var(--green,#3ecf8e)', T('Το τούνελ είναι όρθιο', 'The tunnel is up')],
      stale: ['🔴', 'var(--red)', T('Το τούνελ έπεσε — κανένα handshake τα τελευταία 5′', 'The tunnel is down — no handshake in the last 5 min')],
      never: ['🟠', 'var(--orange)', T('Το τούνελ ξεκίνησε, αλλά ο server δεν έχει απαντήσει ποτέ', 'The tunnel is started, but the server has never answered')],
      down: ['🟠', 'var(--orange)', T('Η διεπαφή nw0 υπάρχει, αλλά χωρίς τον server σου ως peer', 'Interface nw0 exists, but your server is not a peer')],
      ready: ['⚪', 'var(--dim)', T('Η ρύθμιση είναι έτοιμη — δεν έχει εγκατασταθεί ακόμα στο σύστημα', 'The configuration is ready — not installed on the system yet')],
      none: ['🛰', 'var(--dim)', T('Δεν έχει ρυθμιστεί απομακρυσμένη πρόσβαση', 'Remote access is not set up')],
    };
    return S[l.state] || S.none;
  }

  function form(c) {
    c = c || {};
    const f = (id, lbl, val, ph) => `<label>${lbl}<input type="text" id="rm-${id}" value="${E(val || '')}" placeholder="${E(ph || '')}" autocomplete="off" spellcheck="false"></label>`;
    return `<div class="rm-grid">
      ${f('host', T('Δημόσια διεύθυνση του server σου', 'Public address of your server'), c.host, 'vpn.example.gr')}
      ${f('port', T('Θύρα UDP', 'UDP port'), c.port || 51820, '51820')}
      ${f('hub_key', T('Δημόσιο κλειδί του server', 'Server public key'), c.hub_key, 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=')}
      ${f('subnet', T('Δίκτυο του τούνελ', 'Tunnel network'), c.subnet || '10.99.0.0/24', '10.99.0.0/24')}
      ${f('hub_ip', T('Διεύθυνση server στο τούνελ', 'Server address in the tunnel'), c.hub_ip, '10.99.0.1')}
      ${f('box_ip', T('Διεύθυνση αυτού του κουτιού', 'Address of this box'), c.box_ip, '10.99.0.10')}
      ${f('name', T('Όνομα κουτιού (για τον server)', 'Box name (for the server)'), c.name, 'box-pelatis-1')}
    </div>
    <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <button class="b" data-rm="save">🔑 ${D.configured ? T('Αποθήκευση', 'Save') : T('Φτιάξε κλειδιά και ρύθμιση', 'Create keys and configuration')}</button>
      ${D.configured ? `<label style="display:inline-flex;gap:6px;align-items:center"><input type="checkbox" id="rm-newkey"> ${T('νέο ζεύγος κλειδιών', 'new key pair')}</label><button class="b" data-rm="cancel">${T('Άκυρο', 'Cancel')}</button>` : ''}
    </div>`;
  }

  function draw() {
    const b = box(); if (!b || !D) return;
    b.setAttribute('data-noi18n', '');
    if (D.error && !D.link) { b.innerHTML = `<div class="card">${T('Δεν είναι διαθέσιμο σε αυτή τη λειτουργία (π.χ. ανάλυση pcap ή online demo).', 'Not available in this mode (e.g. pcap analysis or the online demo).')}</div>`; return; }
    const l = D.link || { state: 'none' }, c = D.cfg, [ico, col, head] = status(l);
    let h = `<div class="card"><div class="rm-hero"><span class="rm-big">${ico}</span><div style="flex:1;min-width:220px">
      <b style="font-size:16px;color:${col}">${head}</b>${D.demo ? ' <span class="dim">DEMO</span>' : ''}
      <div class="dim" style="font-size:12.5px;margin-top:3px">${c ? `${E(c.name)} · ${E(c.box_ip)} → ${E(c.host)}:${E(c.port)}` : T('WireGuard από το κουτί προς τον δικό σου server', 'WireGuard from the box to your own server')}</div></div>
      <button class="b" data-rm="refresh">🔄</button></div>
      ${l.state === 'up' || l.state === 'stale' ? `<div class="rm-chips"><span class="rm-chip">handshake ${ago(l.ago)}</span><span class="rm-chip">↓ ${mb(l.rx)}</span><span class="rm-chip">↑ ${mb(l.tx)}</span>${l.endpoint ? `<span class="rm-chip">${E(l.endpoint)}</span>` : ''}${D.on_backup ? `<span class="rm-chip" style="color:var(--orange)">📶 ${T('μέσω εφεδρικής γραμμής LTE', 'over the LTE backup line')}</span>` : ''}</div>` : ''}
      ${l.why === 'nowg' ? `<div class="dim" style="font-size:12.5px;margin-top:8px">${T('Το <code>wg</code> δεν είναι εγκατεστημένο — το βάζει το script του βήματος 2.', '<code>wg</code> is not installed — the script in step 2 installs it.')}</div>` : ''}
      ${l.why === 'perm' ? `<div class="dim" style="font-size:12.5px;margin-top:8px">${T('Δεν έχω δικαίωμα να διαβάσω το <code>wg show</code> — το NetWatch πρέπει να τρέχει με sudo (όπως στο Live).', 'No permission to read <code>wg show</code> — NetWatch must run with sudo (as in Live).')}</div>` : ''}
      <div class="dim" style="font-size:12.5px;margin-top:8px;line-height:1.55">${T('Το κουτί ανοίγει <b>αυτό</b> τη σύνδεση προς τον server σου, άρα δεν χρειάζεται port forwarding ούτε καμία αλλαγή στο router του πελάτη, και δουλεύει και πάνω από LTE. Μέσα από το τούνελ περνά <b>μόνο</b> η δική σου πρόσβαση στο NetWatch — όχι η κίνηση του πελάτη.',
        'The box opens the connection to <b>your</b> server itself, so no port forwarding or any change on the customer’s router is needed, and it works over LTE too. <b>Only</b> your access to NetWatch travels through the tunnel — not the customer’s traffic.')}</div>
      ${msg ? `<div style="color:var(--orange);font-size:13px;margin-top:8px">⚠ ${E(msg)}</div>` : ''}</div>`;

    if (!c || edit) {
      h += `<div class="card"><b>${c ? T('Αλλαγή ρύθμισης', 'Change configuration') : T('Ρύθμιση', 'Setup')}</b>
        <div class="dim" style="font-size:12.5px;margin-top:4px">${T('Χρειάζεσαι έναν WireGuard server με δημόσια διεύθυνση: το router του γραφείου σου (MikroTik, OpenWrt, FRITZ!Box), ή ένα μικρό VPS. Το δημόσιο κλειδί του το βλέπεις με <code>sudo wg show wg0 public-key</code> ή στο MikroTik: <code>/interface wireguard print</code>.',
          'You need a WireGuard server with a public address: your office router (MikroTik, OpenWrt, FRITZ!Box) or a small VPS. Its public key: <code>sudo wg show wg0 public-key</code>, or on MikroTik: <code>/interface wireguard print</code>.')}</div>
        ${D.demo ? `<div class="dim" style="margin-top:8px">🧪 ${T('Στο demo δεν φτιάχνονται κλειδιά.', 'No keys are generated in demo mode.')}</div>` : form(draft || c)}</div>`;
    }
    if (c && !edit) {
      h += `<div class="card"><b>${T('Τρία βήματα', 'Three steps')}</b>
        <div class="rm-step"><b class="n">1</b>${T('Στον <b>server σου</b>, πρόσθεσε το κουτί ως peer. Αυτό είναι το <b>δημόσιο</b> κλειδί του κουτιού — δεν είναι μυστικό.', 'On <b>your server</b>, add the box as a peer. This is the box’s <b>public</b> key — it is not secret.')}
          <div class="dim" style="font-size:12px;margin-top:6px">wg-quick (/etc/wireguard/wg0.conf):</div><pre>${E(D.hub.wg)}</pre>
          <div class="dim" style="font-size:12px;margin-top:6px">${T('ή χωρίς επανεκκίνηση:', 'or without a restart:')}</div><pre>${E(D.hub.wg_live)}</pre>
          <div class="dim" style="font-size:12px;margin-top:6px">MikroTik:</div><pre>${E(D.hub.mikrotik)}</pre></div>
        <div class="rm-step"><b class="n">2</b>${T('Στο <b>κουτί</b> (μία φορά, με sudo) εγκατέστησε το τούνελ. Η ρύθμιση με το ιδιωτικό κλειδί είναι ήδη στο', 'On the <b>box</b> (once, with sudo) install the tunnel. The configuration with the private key is already at')} <code>${E(D.conf || 'data/remote/nw0.conf')}</code>.
          <pre>${E(D.install)}</pre></div>
        <div class="rm-step"><b class="n">3</b>${T('Από τον υπολογιστή σου (συνδεδεμένος στον server σου) άνοιξε το NetWatch του κουτιού. Το κουτί τρέχει σε λειτουργία agent: HTTPS και token.', 'From your computer (connected to your server) open the box’s NetWatch. The box runs in agent mode: HTTPS and a token.')}
          <pre>${E(D.url)}?token=…</pre>
          <div class="dim" style="font-size:12px;margin-top:6px">${D.agent ? T('✓ Αυτό το NetWatch τρέχει ήδη με --agent. Το token είναι στο data/agent-token.', '✓ This NetWatch already runs with --agent. The token is in data/agent-token.') : T('Αυτό το NetWatch ΔΕΝ τρέχει με --agent, άρα ακούει μόνο τοπικά. Η υπηρεσία του κουτιού (tools/fieldbox) το ξεκινά σωστά· με το χέρι:', 'This NetWatch is NOT running with --agent, so it only listens locally. The box service (tools/fieldbox) starts it correctly; by hand:')}</div>
          ${D.agent ? '' : `<pre>${E(D.run)}</pre>`}</div>
        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">${D.demo ? '' : `<button class="b" data-rm="edit">✏️ ${T('Αλλαγή', 'Change')}</button><button class="b" data-rm="forget">🗑 ${T('Σβήσε κλειδιά και ρύθμιση', 'Delete keys and configuration')}</button>`}</div></div>`;
    }
    h += `<div class="card"><b>👉 ${T('Καλό να ξέρεις', 'Good to know')}</b><ul>
      <li>${T('Το ιδιωτικό κλειδί του κουτιού γράφεται μόνο στο <code>data/remote/nw0.conf</code> (δικαιώματα 600) και δεν εμφανίζεται ποτέ εδώ. Αν χαθεί ή κλαπεί το κουτί, σβήσε το peer του από τον server σου — αυτό αρκεί.', 'The box’s private key is written only to <code>data/remote/nw0.conf</code> (mode 600) and is never shown here. If the box is lost or stolen, delete its peer on your server — that is enough.')}</li>
      <li>${T('Στο server σου δώσε στο κουτί <b>μόνο</b> τη δική του διεύθυνση (/32) και μην επιτρέψεις κίνηση από κουτί σε κουτί: έτσι ο ένας πελάτης δεν βλέπει τον άλλον.', 'On your server give the box <b>only</b> its own address (/32) and do not allow box-to-box traffic: that way one customer cannot see another.')}</li>
      <li>${T('Ενημέρωσε τον πελάτη (γραπτά) ότι η συσκευή σου έχει απομακρυσμένη πρόσβαση και για πόσο καιρό.', 'Tell the customer (in writing) that your device has remote access, and for how long.')}</li>
      <li>${T('Δεν έχεις δημόσια IP (CGNAT); Χρησιμοποίησε ένα φτηνό VPS ως server, ή το Tailscale — το NetWatch το βλέπει στην καρτέλα 🔐 VPN.', 'No public IP (CGNAT)? Use a cheap VPS as the server, or Tailscale — NetWatch shows it under the 🔐 VPN tab.')}</li></ul></div>`;
    b.innerHTML = h;
  }

  function load() {
    return fetch('/api/kit/remote').then(r => r.json()).then(j => { D = j; draw(); }).catch(() => { D = { error: 'off' }; draw(); });
  }
  document.addEventListener('click', e => {
    const t = e.target.closest('#t-remote [data-rm]'); if (!t) return;
    const a = t.dataset.rm, v = id => (box().querySelector('#rm-' + id) || {}).value || '';
    msg = '';
    if (a === 'refresh') return load();
    if (a === 'edit') { edit = true; return draw(); }
    if (a === 'cancel') { edit = false; draft = null; return draw(); }
    if (a === 'forget') {
      if (!confirm(T('Να σβηστούν τα κλειδιά και η ρύθμιση; Το τούνελ στο σύστημα σταματά με: sudo tools/fieldbox/wg-setup.sh --remove', 'Delete the keys and configuration? Stop the system tunnel with: sudo tools/fieldbox/wg-setup.sh --remove'))) return;
      return post('forget', { confirm: true }).then(j => { D = j; edit = false; draw(); });
    }
    if (a === 'save') {
      const nk = box().querySelector('#rm-newkey');
      t.disabled = true;
      draft = { host: v('host'), port: v('port'), hub_key: v('hub_key'), subnet: v('subnet'), hub_ip: v('hub_ip'), box_ip: v('box_ip'), name: v('name') };
      return post('setup', Object.assign({ new_key: !!(nk && nk.checked) }, draft))
        .then(j => { if (j.error) { msg = (EN() && j.error_en) || j.error; draw(); } else { D = j; edit = false; draft = null; draw(); } }).catch(() => { t.disabled = false; });
    }
  });
  window.renderRemote = () => load();
})();
