// 🧅 Εργαλεία ανωνυμίας στην καρτέλα Tor: «Πόσο ασφαλές είναι αυτό το site για την ανωνυμία μου;» (sitecheck.py)
// και «Ποιον browser έχω;» — βαθμός αποτυπώματος (fingerprint) ανά browser + τι να ρυθμίσεις.
// Ζωγραφίζει στο #tor-extra (το δημιουργεί το sectools.js) · ελληνικά/αγγλικά ενσωματωμένα (data-noi18n).
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const L = (el, en) => EN() ? en : el;
  const LK = (o, k) => o ? (EN() ? o[k + '_en'] : o[k + '_el']) || o[k + '_el'] || o[k + '_en'] || '' : '';
  const LS = { get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : v; } catch (e) { return d; } }, set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} } };

  const css = document.createElement('style');
  css.textContent = `
#tor-extra .ax-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px}
#tor-extra .ax-in{flex:1;min-width:240px;background:var(--panel3,rgb(var(--w) / 5%));border:1px solid var(--line);color:var(--hi);border-radius:8px;padding:8px 10px;font:inherit;font-family:var(--mono)}
#tor-extra .ax-grade{font-size:38px;font-weight:800;line-height:1;width:64px;height:64px;border-radius:16px;display:flex;align-items:center;justify-content:center;color:#fff;background:var(--c);flex:none}
#tor-extra .ax-head{display:flex;gap:14px;align-items:center}
#tor-extra .ax-chk{display:flex;gap:9px;padding:7px 0;border-top:1px solid var(--line);white-space:normal}
#tor-extra .ax-chk:first-child{border-top:0}
#tor-extra .ax-chk .i{flex:none;width:20px;text-align:center}
#tor-extra .ax-chk b{color:var(--hi);font-weight:600}
#tor-extra .ax-chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}
#tor-extra .ax-chips span{border:1px solid var(--c,var(--line));color:var(--c,var(--txt));border-radius:7px;padding:1px 7px;font-size:11.5px;font-family:var(--mono)}
#tor-extra .ax-br{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
#tor-extra .ax-br button{display:flex;gap:6px;align-items:center}
#tor-extra .ax-br button.on{border-color:var(--cyan);color:var(--hi);box-shadow:inset 0 0 0 1px var(--cyan)}
#tor-extra .ax-br button .now{font-size:10px;color:var(--green)}
#tor-extra .ax-bars{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:10px}
#tor-extra .ax-bar span{font-size:11.5px;color:var(--dim)}
#tor-extra .ax-bar i{display:block;height:7px;border-radius:4px;background:rgb(var(--w) / 8%);margin-top:4px;overflow:hidden}
#tor-extra .ax-bar i b{display:block;height:100%;background:var(--c)}
#tor-extra .ax-cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-top:10px}
#tor-extra ol,#tor-extra ul{margin:6px 0 0;padding-left:20px;white-space:normal}
#tor-extra li{margin:3px 0}
#tor-extra .ax-hist{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
#tor-extra .ax-hist button{font-family:var(--mono);font-size:11.5px}`;
  document.head.appendChild(css);

  const GC = { A: 'var(--green)', B: '#4caf50', C: 'var(--yellow)', D: 'var(--orange)', F: 'var(--red)' };
  const SI = { ok: '✅', warn: '⚠️', bad: '⛔', info: 'ℹ️' };
  const KC = { tracker: 'var(--orange)', fingerprint: 'var(--red)', replay: 'var(--red)', telemetry: 'var(--orange)', captcha: 'var(--yellow)', login: 'var(--yellow)', embed: 'var(--yellow)', cdn: 'var(--dim)', other: 'var(--txt)' };
  const KL = { tracker: ['tracker', 'tracker'], fingerprint: ['fingerprint', 'fingerprint'], replay: ['καταγραφή οθόνης', 'session replay'], cdn: ['CDN', 'CDN'], telemetry: ['τηλεμετρία', 'telemetry'], captcha: ['captcha', 'captcha'], login: ['σύνδεση λογαριασμού', 'social login'], embed: ['ενσωμάτωση (YouTube κ.λπ.)', 'embed (YouTube etc.)'], other: ['τρίτος', 'third party'] };

  // ───────── browsers ─────────
  // fp = αντίσταση στο fingerprint, trk = μπλοκάρισμα trackers, ip = κρύβει την IP · 0–5
  const BR = {
    tor: { n: 'Tor Browser', ic: '🧅', fp: 5, trk: 4, ip: 5,
      el: { sum: 'Ο πιο ανώνυμος: όλοι οι χρήστες μοιάζουν ίδιοι (ίδιο μέγεθος παραθύρου, UTC, αγγλικά) και η IP σου κρύβεται πίσω από 3 κόμβους.',
        good: ['Κρύβει την IP σου (3 κόμβοι Tor)', 'Όλοι ίδιοι στο fingerprint — δεν ξεχωρίζεις', 'Σβήνει τα πάντα όταν κλείνει', 'Απομονώνει κάθε site σε δικό του κύκλωμα'],
        bad: ['Πιο αργός· κάποια sites (Cloudflare) βάζουν captcha', 'Αν κάνεις login, το site ξέρει ποιος είσαι — ό,τι κι αν κάνει το Tor'],
        set: ['Ασπίδα → Ρυθμίσεις ασφαλείας → «Ασφαλέστερο» (Safer) ή «Ασφαλέστατο» (Safest: κλείνει τη JavaScript)', 'ΜΗΝ μεγιστοποιείς το παράθυρο — το letterboxing σε κρατά ίδιο με τους άλλους', 'ΜΗΝ εγκαθιστάς επεκτάσεις και μην αλλάζεις γραμματοσειρές/γλώσσα — σε κάνουν μοναδικό', 'Προτίμησε τις διευθύνσεις .onion όταν υπάρχουν', 'Μην ανοίγεις αρχεία που κατέβασες (PDF/DOC) όσο είσαι online — μπορεί να «τηλεφωνήσουν» εκτός Tor'] },
      en: { sum: 'The most anonymous: every user looks the same (same window size, UTC, English) and your IP is hidden behind 3 relays.',
        good: ['Hides your IP (3 Tor relays)', 'Everyone looks identical — you blend in', 'Wipes everything when closed', 'Isolates each site on its own circuit'],
        bad: ['Slower; some sites (Cloudflare) show captchas', 'If you log in, the site knows who you are — whatever Tor does'],
        set: ['Shield → Security Settings → "Safer" or "Safest" (Safest disables JavaScript)', "DON'T maximise the window — letterboxing keeps you identical to others", "DON'T install extensions or change fonts/language — they make you unique", 'Prefer .onion addresses when available', "Don't open downloaded files (PDF/DOC) while online — they can 'phone home' outside Tor"] } },
    mullvad: { n: 'Mullvad Browser', ic: '🦔', fp: 5, trk: 4, ip: 1,
      el: { sum: 'Το Tor Browser χωρίς το Tor: ίδια προστασία fingerprint, αλλά η IP σου φαίνεται — φτιαγμένος για χρήση μαζί με VPN.',
        good: ['Ίδια αντίσταση στο fingerprint με το Tor Browser', 'uBlock Origin ενσωματωμένο', 'Γρήγορος (χωρίς Tor)'],
        bad: ['Δεν κρύβει την IP — χρειάζεται VPN (οποιοδήποτε, όχι μόνο Mullvad)'],
        set: ['Άνοιξε VPN πριν τον χρησιμοποιήσεις', 'Μην μεγιστοποιείς το παράθυρο και μην προσθέτεις επεκτάσεις', 'Κράτα την «ιδιωτική λειτουργία πάντα» (προεπιλογή)'] },
      en: { sum: 'Tor Browser without Tor: the same fingerprint protection, but your IP is visible — built to be used with a VPN.',
        good: ['Same fingerprint resistance as Tor Browser', 'uBlock Origin built in', 'Fast (no Tor)'],
        bad: ["Doesn't hide your IP — needs a VPN (any, not only Mullvad)"],
        set: ['Turn on a VPN before using it', "Don't maximise the window and don't add extensions", 'Keep "always private mode" (the default)'] } },
    brave: { n: 'Brave', ic: '🦁', fp: 4, trk: 4, ip: 1,
      el: { sum: 'Καλός καθημερινός: μπλοκάρει trackers και «ανακατεύει» (randomize) το fingerprint ώστε να μη σε ακολουθεί από site σε site.',
        good: ['Shields: μπλοκάρει trackers και διαφημίσεις', 'Τυχαίο fingerprint ανά site (canvas, audio, WebGL)', 'Ιδιωτικό παράθυρο με Tor (για απλή χρήση)'],
        bad: ['Το «Private window with Tor» δεν είναι Tor Browser — το fingerprint του είναι του Brave, όχι «όλοι ίδιοι»', 'Η IP σου φαίνεται (εκτός Tor παραθύρου)'],
        set: ['brave://settings/shields → Trackers & ads: «Aggressive»', 'Block fingerprinting: ενεργό · Block third-party cookies', 'brave://settings/privacy → WebRTC IP handling: «Disable non-proxied UDP»', 'Κλείσε Brave Rewards/News/Wallet αν δεν τα θες', 'Για πραγματική ανωνυμία: Tor Browser'] },
      en: { sum: 'A good daily driver: blocks trackers and randomises your fingerprint so it can’t follow you across sites.',
        good: ['Shields block trackers and ads', 'Per-site randomised fingerprint (canvas, audio, WebGL)', 'Private window with Tor (for casual use)'],
        bad: ['"Private window with Tor" is not Tor Browser — its fingerprint is Brave’s, not "everyone identical"', 'Your IP is visible (outside the Tor window)'],
        set: ['brave://settings/shields → Trackers & ads: "Aggressive"', 'Block fingerprinting on · Block third-party cookies', 'brave://settings/privacy → WebRTC IP handling: "Disable non-proxied UDP"', 'Turn off Rewards/News/Wallet if unused', 'For real anonymity: Tor Browser'] } },
    librewolf: { n: 'LibreWolf', ic: '🐺', fp: 4, trk: 4, ip: 1,
      el: { sum: 'Firefox «σκληρυμένος» από πριν: resistFingerprinting ενεργό, uBlock Origin, χωρίς τηλεμετρία.',
        good: ['resistFingerprinting από προεπιλογή', 'uBlock Origin ενσωματωμένο', 'Χωρίς τηλεμετρία της Mozilla'],
        bad: ['Λιγότεροι χρήστες από το Tor Browser — λιγότερο «πλήθος» για να κρυφτείς', 'Η IP σου φαίνεται'],
        set: ['Μην αλλάζεις πολλές ρυθμίσεις — κάθε αλλαγή σε ξεχωρίζει', 'Μαζί με VPN αν θες να κρύψεις την IP'] },
      en: { sum: 'Firefox pre-hardened: resistFingerprinting on, uBlock Origin, no telemetry.',
        good: ['resistFingerprinting by default', 'uBlock Origin built in', 'No Mozilla telemetry'],
        bad: ['Fewer users than Tor Browser — a smaller crowd to hide in', 'Your IP is visible'],
        set: ["Don't change many settings — every tweak makes you stand out", 'Pair it with a VPN to hide your IP'] } },
    firefox: { n: 'Firefox', ic: '🦊', fp: 3, trk: 3, ip: 1,
      el: { sum: 'Καλή βάση αν τον ρυθμίσεις: η Αυστηρή προστασία και το resistFingerprinting κόβουν πολλά.',
        good: ['Enhanced Tracking Protection (Αυστηρό)', 'Total Cookie Protection: κάθε site στο δικό του «κουτί»', 'DNS over HTTPS'],
        bad: ['Από προεπιλογή το fingerprint είναι αρκετά μοναδικό', 'Η IP σου φαίνεται'],
        set: ['Ρυθμίσεις → Απόρρητο → Ενισχυμένη προστασία: «Αυστηρή»', 'about:config → privacy.resistFingerprinting = true (θα δεις UTC και στρογγυλά μεγέθη παραθύρου)', 'about:config → media.peerconnection.enabled = false (κλείνει το WebRTC → καμία διαρροή IP)', 'Ρυθμίσεις → DNS over HTTPS: «Μέγιστη προστασία»', 'Επέκταση uBlock Origin'] },
      en: { sum: 'A good base once configured: Strict protection and resistFingerprinting cut a lot.',
        good: ['Enhanced Tracking Protection (Strict)', 'Total Cookie Protection: each site in its own jar', 'DNS over HTTPS'],
        bad: ['Out of the box your fingerprint is fairly unique', 'Your IP is visible'],
        set: ['Settings → Privacy → Enhanced Tracking Protection: "Strict"', 'about:config → privacy.resistFingerprinting = true (UTC, rounded window sizes)', 'about:config → media.peerconnection.enabled = false (disables WebRTC → no IP leak)', 'Settings → DNS over HTTPS: "Max Protection"', 'Install uBlock Origin'] } },
    safari: { n: 'Safari', ic: '🧭', fp: 3, trk: 3, ip: 2,
      el: { sum: 'Αξιοπρεπής στο Mac: κρύβει μέρος του fingerprint και, με iCloud+, το Private Relay κρύβει την IP από τα sites.',
        good: ['Intelligent Tracking Prevention', 'Προηγμένη προστασία από αποτυπώματα (στο Safari 26 σε όλη την περιήγηση)', 'iCloud Private Relay: 2 κόμβοι, κρύβει την IP (iCloud+)'],
        bad: ['Το Private Relay δεν είναι Tor: η Apple/οι συνεργάτες της ξέρουν ότι είσαι εσύ', 'Λίγες επεκτάσεις για μπλοκάρισμα'],
        set: ['Ρυθμίσεις Safari → Απόρρητο → «Αποτροπή παρακολούθησης μεταξύ ιστότοπων»', 'Για προχωρημένους → «Προηγμένη προστασία από ίχνη και αποτυπώματα»: Σε όλη την περιήγηση', 'Ρυθμίσεις συστήματος → Apple ID → iCloud → Ιδιωτική αναμετάδοση: ενεργή', 'Κρύψε τη διεύθυνση IP: από trackers και ιστότοπους'] },
      en: { sum: 'Decent on a Mac: hides part of the fingerprint and, with iCloud+, Private Relay hides your IP from sites.',
        good: ['Intelligent Tracking Prevention', 'Advanced fingerprinting protection (Safari 26: in all browsing)', 'iCloud Private Relay: 2 hops, hides your IP (iCloud+)'],
        bad: ['Private Relay is not Tor: Apple and its partners know it’s you', 'Few blocking extensions'],
        set: ['Safari Settings → Privacy → "Prevent cross-site tracking"', 'Advanced → "Use advanced tracking and fingerprinting protection": in all browsing', 'System Settings → Apple ID → iCloud → Private Relay: on', 'Hide IP address: from trackers and websites'] } },
    chrome: { n: 'Chrome', ic: '🟡', fp: 1, trk: 1, ip: 1,
      el: { sum: 'Ο λιγότερο ιδιωτικός: η Google βλέπει πολλά, και το fingerprint είναι από τα πιο εύκολα να σε ξεχωρίσουν.',
        good: ['Γρήγορες ενημερώσεις ασφαλείας'],
        bad: ['Συγχρονισμός με τον λογαριασμό Google (ιστορικό, κωδικοί)', 'Περιορισμένα ad-blockers (Manifest V3)', 'Δεν προστατεύει το fingerprint'],
        set: ['Αν μείνεις σε Chrome: chrome://settings/privacy → Third-party cookies: Block', 'Κλείσε τον συγχρονισμό με τον λογαριασμό Google', 'Επέκταση uBlock Origin Lite', 'Καλύτερα: Brave (ίδια μηχανή, πολύ πιο ιδιωτικός) ή Firefox'] },
      en: { sum: 'The least private: Google sees a lot, and the fingerprint is among the easiest to single you out.',
        good: ['Fast security updates'],
        bad: ['Syncs with your Google account (history, passwords)', 'Limited ad blockers (Manifest V3)', "Doesn't protect the fingerprint"],
        set: ['If you stay on Chrome: chrome://settings/privacy → Third-party cookies: Block', 'Turn off Google account sync', 'Install uBlock Origin Lite', 'Better: Brave (same engine, far more private) or Firefox'] } },
    edge: { n: 'Edge', ic: '🌀', fp: 2, trk: 2, ip: 1,
      el: { sum: 'Λίγο καλύτερος από τον Chrome χάρη στην «Αυστηρή» προστασία, αλλά στέλνει πολλά στη Microsoft.',
        good: ['Tracking prevention: Αυστηρή'],
        bad: ['Τηλεμετρία προς Microsoft', 'Δεν προστατεύει το fingerprint'],
        set: ['edge://settings/privacy → Tracking prevention: «Strict»', 'Κλείσε «Personalization & advertising»', 'Καλύτερα: Brave ή Firefox'] },
      en: { sum: 'A little better than Chrome thanks to "Strict" protection, but sends a lot to Microsoft.',
        good: ['Tracking prevention: Strict'],
        bad: ['Telemetry to Microsoft', "Doesn't protect the fingerprint"],
        set: ['edge://settings/privacy → Tracking prevention: "Strict"', 'Turn off "Personalization & advertising"', 'Better: Brave or Firefox'] } },
  };
  function detect() {
    const ua = navigator.userAgent || '';
    if (navigator.brave) return 'brave';
    if (/Edg\//.test(ua)) return 'edge';
    if (/LibreWolf/i.test(ua)) return 'librewolf';
    if (/Firefox\//.test(ua)) return 'firefox';
    if (/Chrome\//.test(ua) && !/Chromium|OPR\//.test(ua)) return 'chrome';
    if (/Safari\//.test(ua) && /Version\//.test(ua)) return 'safari';
    return null;
  }
  const NOW = detect();

  const A = { url: '', res: null, hist: [], busy: false, err: null, needTor: false, br: LS.get('nw-anon-br', NOW || 'tor'), dirty: true, polls: 0 };

  function siteHTML() {
    const r = A.res, en = EN();
    let h = `<div class="card"><b class="ctitle">🔎 ${L('Πόσο ασφαλές είναι ένα site για την ανωνυμία σου;', 'How safe is a site for your anonymity?')}</b>
      <div class="sm" style="margin-top:4px;white-space:normal">${L('Γράψε μια διεύθυνση (ή .onion). Το NetWatch κατεβάζει μόνο αυτή τη σελίδα — μέσα από το Tor όταν τρέχει, ώστε ούτε ο έλεγχος να μη σε προδίδει — και βλέπει trackers, fingerprinting, καταγραφή οθόνης, cookies, HTTPS και αν υπάρχει έκδοση .onion.', 'Type an address (or .onion). NetWatch fetches only that page — through Tor when it’s running, so even the check doesn’t give you away — and looks for trackers, fingerprinting, session replay, cookies, HTTPS and whether an .onion version exists.')}</div>
      <div class="ax-row"><input class="ax-in" id="ax-url" placeholder="${L('π.χ. https://example.com ή ...onion', 'e.g. https://example.com or ...onion')}" value="${E(A.url)}" spellcheck="false" autocomplete="off" data-noi18n>
      <button class="b pu-go" id="ax-go" ${A.busy ? 'disabled' : ''}>${A.busy ? L('⏳ ελέγχω…', '⏳ checking…') : L('▶ Έλεγξε', '▶ Check')}</button></div>`;
    if (A.err) h += `<div class="sm" style="color:var(--red);margin-top:6px" data-noi18n>${E(A.err)}</div>`;
    if (A.needTor && A.res && A.res.onion) h += `<div class="sm" style="margin-top:8px;white-space:normal;color:var(--orange)">⚠️ ${L('Οι διευθύνσεις .onion ανοίγουν μόνο μέσα από Tor. Άνοιξε το Tor Browser και ξαναδοκίμασε.', '.onion addresses only open through Tor. Open Tor Browser and try again.')}</div>`;
    else if (A.needTor) h += `<div class="sm" style="margin-top:8px;white-space:normal;color:var(--orange)">⚠️ ${L('Δεν βρέθηκε Tor (θύρες 9150/9050). Άνοιξε το Tor Browser — ή έλεγξε απευθείας, αλλά τότε το site βλέπει την πραγματική σου IP.', 'No Tor found (ports 9150/9050). Open Tor Browser — or check directly, but then the site sees your real IP.')}
      <button class="b" id="ax-direct" style="margin-left:6px">${L('Έλεγξε απευθείας', 'Check directly')}</button></div>`;
    if (A.hist.length) h += `<div class="ax-hist">${A.hist.slice(0, 8).map(x => `<button class="b" data-axh="${E(x.url)}" data-noi18n><b style="color:${GC[x.grade] || 'var(--dim)'}">${E(x.grade || '?')}</b> ${E(x.host || x.url)}</button>`).join('')}</div>`;
    h += '</div>';
    if (r && !r.error && r.grade) {
      const tp = r.third_party || [];
      h += `<div class="card"><div class="ax-head"><div class="ax-grade" style="--c:${GC[r.grade] || 'var(--dim)'}">${E(r.grade)}</div>
        <div style="min-width:0"><b style="color:var(--hi);font-size:15px" data-noi18n>${E(r.host || r.url)}</b>
        <div data-noi18n style="white-space:normal;margin-top:2px">${E(LK(r, 'verdict'))}</div>
        <div class="sm" data-noi18n style="margin-top:2px">${r.score != null ? E(r.score) + '/100 · ' : ''}${r.via ? (String(r.via).startsWith('tor') ? '🧅 ' + L('μέσω Tor', 'via Tor') : '⚠️ ' + L('απευθείας', 'direct')) : ''}${r.ms ? ' · ' + E(r.ms) + ' ms' : ''}${r.final_url && r.final_url !== r.url ? ' · → ' + E(r.final_url) : ''}</div></div></div>
        ${r.partial ? `<div class="sm" style="margin-top:8px;white-space:normal;color:var(--orange)">⚠️ ${L('Το site έδειξε σελίδα ελέγχου (captcha) αντί για το περιεχόμενο — ο βαθμός αφορά μόνο αυτή.', 'The site showed a challenge page (captcha) instead of the content — the grade covers only that page.')}</div>` : ''}
        ${r.onion_location ? `<div style="margin-top:10px;white-space:normal">🧅 ${L('Έχει έκδοση .onion — προτίμησέ τη στο Tor Browser:', 'Has an .onion version — prefer it in Tor Browser:')} <code data-noi18n>${E(r.onion_location)}</code></div>` : ''}
        <div style="margin-top:10px">${(r.checks || []).slice().sort((a, b) => ({ bad: 0, warn: 1, info: 2, ok: 3 }[a.status] ?? 9) - ({ bad: 0, warn: 1, info: 2, ok: 3 }[b.status] ?? 9)).map(c => `<div class="ax-chk"><span class="i">${SI[c.status] || '•'}</span><div data-noi18n><b>${E(LK(c, 'title'))}</b>${c.weight ? ` <span class="sm">−${E(c.weight)}</span>` : ''}<div class="sm" style="white-space:normal">${E(LK(c, 'detail'))}</div></div></div>`).join('')}</div>
        ${tp.length ? `<div style="margin-top:10px"><b>${L('Τρίτοι που βλέπουν την επίσκεψή σου', 'Third parties that see your visit')} (${tp.length})</b><div class="ax-chips">${tp.map(x => `<span style="--c:${KC[x.kind] || 'var(--line)'}" title="${E((KL[x.kind] || KL.other)[en ? 1 : 0])}${x.who ? ' · ' + E(x.who) : ''}">${E(x.host)}</span>`).join('')}</div>
          <div class="sm" style="margin-top:4px"><span style="color:var(--red)">■</span> fingerprint / ${L('καταγραφή οθόνης', 'session replay')} · <span style="color:var(--orange)">■</span> tracker / ${L('τηλεμετρία', 'telemetry')} · <span style="color:var(--yellow)">■</span> captcha / login / embed · <span style="color:var(--dim)">■</span> CDN</div></div>` : ''}
        ${(LK(r, 'advice') || []).length ? `<div style="margin-top:10px"><b>👉 ${L('Τι να κάνεις', 'What to do')}</b><ul data-noi18n>${(EN() ? r.advice_en : r.advice_el || r.advice_en).map(a => `<li>${E(a)}</li>`).join('')}</ul></div>` : ''}
      </div>`;
    } else if (r && r.error && !A.needTor) h += `<div class="card sm" style="color:var(--red)" data-noi18n>${E(LK(r, 'error') || r.error)}</div>`;
    return h;
  }

  function brHTML() {
    const k = BR[A.br] ? A.br : 'tor', b = BR[k], t = EN() ? b.en : b.el;
    const bar = (v, l) => `<div class="ax-bar"><span>${l}</span><i><b style="width:${v * 20}%;--c:${v >= 4 ? 'var(--green)' : v >= 3 ? 'var(--yellow)' : v >= 2 ? 'var(--orange)' : 'var(--red)'}"></b></i></div>`;
    return `<div class="card"><b class="ctitle">🖐 ${L('Ποιον browser χρησιμοποιείς;', 'Which browser do you use?')}</b>
      <div class="sm" style="margin-top:4px;white-space:normal">${L('Η IP δεν είναι το μόνο που σε προδίδει: γραμματοσειρές, οθόνη, ζώνη ώρας, κάρτα γραφικών φτιάχνουν ένα «αποτύπωμα» (fingerprint) που σε ξεχωρίζει ακόμα και χωρίς cookies. Διάλεξε τον browser σου για να δεις πόσο σε προστατεύει και τι να ρυθμίσεις.', 'Your IP isn’t the only giveaway: fonts, screen, time zone and graphics card form a “fingerprint” that singles you out even without cookies. Pick your browser to see how well it protects you and what to change.')}</div>
      <div class="ax-br">${Object.entries(BR).map(([id, x]) => `<button class="b${id === k ? ' on' : ''}" data-axbr="${id}"><span>${x.ic}</span><span data-noi18n>${E(x.n)}</span>${id === NOW ? `<span class="now">● ${L('αυτός τώρα', 'this one')}</span>` : ''}</button>`).join('')}</div>
      <div style="margin-top:12px;white-space:normal" data-noi18n><b style="color:var(--hi)">${b.ic} ${E(b.n)}</b> — ${E(t.sum)}</div>
      <div class="ax-bars" data-noi18n>${bar(b.fp, L('Αντίσταση στο fingerprint', 'Fingerprint resistance'))}${bar(b.trk, L('Μπλοκάρισμα trackers', 'Tracker blocking'))}${bar(b.ip, L('Κρύβει την IP', 'Hides your IP'))}</div>
      <div class="ax-cols" data-noi18n>
        <div><b style="color:var(--green)">✓ ${L('Προστατεύει', 'Protects')}</b><ul>${t.good.map(x => `<li>${E(x)}</li>`).join('')}</ul></div>
        <div><b style="color:var(--orange)">✗ ${L('Δεν προστατεύει', "Doesn't protect")}</b><ul>${t.bad.map(x => `<li>${E(x)}</li>`).join('')}</ul></div></div>
      <div style="margin-top:10px" data-noi18n><b>⚙️ ${L('Ρύθμισέ το έτσι', 'Set it up like this')}</b><ol>${t.set.map(x => `<li>${E(x)}</li>`).join('')}</ol></div>
      <div class="ax-row">${k === NOW || (!NOW && k !== 'tor') ? `<button class="b" id="ax-fp">🖐 ${L('Μέτρα το fingerprint αυτού του browser', "Measure this browser's fingerprint")}</button>` : ''}
        <span class="sm" style="white-space:normal">${k === 'tor' || k === 'mullvad' ? L('Το Tor/Mullvad Browser δεν ανοίγουν το localhost, οπότε δεν μετριούνται από εδώ· δοκίμασε το coveryourtracks.eff.org μέσα από αυτούς.', "Tor/Mullvad Browser don't open localhost, so they can't be measured from here; try coveryourtracks.eff.org inside them.") : k !== NOW ? L('Για μέτρηση, άνοιξε το NetWatch μέσα σε αυτόν τον browser.', 'To measure it, open NetWatch in that browser.') : ''}</span></div>
    </div>`;
  }

  function draw() {
    const box = document.getElementById('tor-extra'); if (!box) return;
    const ae = document.activeElement, typing = ae && ae.id === 'ax-url', val = typing ? ae.value : null, pos = typing ? ae.selectionStart : 0;
    box.innerHTML = `<h3 style="margin-top:18px">🛡 ${L('Εργαλεία ανωνυμίας', 'Anonymity tools')}</h3>` + siteHTML() + brHTML();
    A.dirty = false; A.lang = EN();
    const inp = box.querySelector('#ax-url');
    if (typing && inp) { inp.value = val; inp.focus(); try { inp.setSelectionRange(pos, pos); } catch (e) {} }
    if (inp) { inp.oninput = () => { A.url = inp.value; }; inp.onkeydown = e => { if (e.key === 'Enter') run(false); }; }
    const g = box.querySelector('#ax-go'); if (g) g.onclick = () => run(false);
    const d = box.querySelector('#ax-direct'); if (d) d.onclick = () => run(true);
    box.querySelectorAll('[data-axh]').forEach(b => b.onclick = () => { A.url = b.dataset.axh; run(false); });
    box.querySelectorAll('[data-axbr]').forEach(b => b.onclick = () => { A.br = b.dataset.axbr; LS.set('nw-anon-br', A.br); draw(); });
    const fp = box.querySelector('#ax-fp'); if (fp) fp.onclick = () => { if (typeof showTab === 'function') showTab('priv'); setTimeout(() => { const t = document.querySelector('#t-priv [data-fp-run], #t-priv #fp-run'); if (t) { t.scrollIntoView({ block: 'center' }); t.click(); } }, 600); };
  }

  const J = (u, o) => fetch(u, o).then(r => r.json().then(j => (r.ok ? j : Object.assign(j, { error: j.error || ('HTTP ' + r.status) }))));
  function hist() { J('/api/sitecheck').then(j => { if (j && Array.isArray(j.history)) { A.hist = j.history; if (!A.res && j.latest) A.res = j.latest; A.dirty = true; if (!A.busy) draw(); } }).catch(() => {}); }
  function poll(id) {
    J('/api/sitecheck?id=' + encodeURIComponent(id)).then(j => {
      if (j && (j.running || j.status === 'running') && A.polls++ < 60) return setTimeout(() => poll(id), 1000);
      A.busy = false; A.res = j; A.needTor = !!(j && j.needs_tor); hist(); draw();
    }).catch(e => { A.busy = false; A.err = String(e); draw(); });
  }
  function run(direct) {
    const u = (A.url || '').trim(); if (!u) return;
    A.busy = true; A.err = null; A.needTor = false; A.polls = 0; draw();
    J('/api/sitecheck', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: u, direct: !!direct, lang: EN() ? 'en' : 'el' }) }).then(j => {
      if (j.needs_tor) { A.busy = false; A.needTor = true; A.res = j; return draw(); }
      if (j.error && !j.id) { A.busy = false; A.err = LK(j, 'error') || j.error; return draw(); }
      if (j.result && j.result.grade) { A.busy = false; A.res = j.result; hist(); return draw(); }
      if (j.grade) { A.busy = false; A.res = j; hist(); return draw(); }
      if (j.retry_in) { A.busy = false; A.err = L(`Περίμενε ${Math.ceil(j.retry_in)} δευτ. πριν τον επόμενο έλεγχο.`, `Wait ${Math.ceil(j.retry_in)} s before the next check.`); return draw(); }
      poll(j.id);
    }).catch(e => { A.busy = false; A.err = String(e); draw(); });
  }

  window.renderAnon = () => {
    const box = document.getElementById('tor-extra'); if (!box) return;
    if (!A.loaded) { A.loaded = true; hist(); }
    if (A.dirty || !box.firstChild || A.lang !== EN()) draw();
  };
  window.ANON = { BR, detect };
})();
