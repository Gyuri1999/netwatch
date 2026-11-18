// 🕵 Εργαλεία ιδιωτικότητας που τρέχουν ΜΟΝΟ στον browser σου (τίποτα δεν στέλνεται πουθενά):
//   🖐 Δακτυλικό αποτύπωμα browser (σαν το Cover Your Tracks του EFF / AmIUnique) — πόσο «μοναδικός» είσαι
//   📷 Μεταδεδομένα φωτογραφίας (EXIF/GPS) — τι μαρτυρά μια φωτογραφία και καθάρισμα πριν τη στείλεις
// Φορτώνεται μετά το index.html· το drawPriv() καλεί PRIVT.html() και PRIVT.bind(el).
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const st = { fp: null, fpRun: false, exif: null };

  // ───────────── 🖐 fingerprint ─────────────
  async function sha(s) {
    try {
      const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
      return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
    } catch (e) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return (h >>> 0).toString(16).padStart(8, '0'); }
  }
  function canvasFp() {
    try {
      const c = document.createElement('canvas'); c.width = 280; c.height = 60;
      const x = c.getContext('2d');
      x.textBaseline = 'top'; x.font = "16px 'Arial'"; x.fillStyle = '#f60'; x.fillRect(120, 5, 70, 22);
      x.fillStyle = '#069'; x.fillText('NetWatch 🛰 Ψ ж 漢 <canvas>', 4, 8);
      x.fillStyle = 'rgba(102,204,0,.7)'; x.font = '18px serif'; x.fillText('fingerprint ✓', 6, 32);
      x.globalCompositeOperation = 'multiply';
      x.fillStyle = 'rgb(255,0,255)'; x.beginPath(); x.arc(220, 30, 22, 0, Math.PI * 2); x.fill();
      return c.toDataURL();
    } catch (e) { return 'blocked'; }
  }
  function webglFp() {
    try {
      const c = document.createElement('canvas'), g = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!g) return null;
      const d = g.getExtension('WEBGL_debug_renderer_info');
      return { vendor: d ? g.getParameter(d.UNMASKED_VENDOR_WEBGL) : g.getParameter(g.VENDOR),
               renderer: d ? g.getParameter(d.UNMASKED_RENDERER_WEBGL) : g.getParameter(g.RENDERER),
               ext: (g.getSupportedExtensions() || []).length, maxTex: g.getParameter(g.MAX_TEXTURE_SIZE) };
    } catch (e) { return null; }
  }
  async function audioFp() {
    try {
      const A = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!A) return null;
      const ctx = new A(1, 5000, 44100), o = ctx.createOscillator(), comp = ctx.createDynamicsCompressor();
      o.type = 'triangle'; o.frequency.value = 10000;
      [['threshold', -50], ['knee', 40], ['ratio', 12], ['attack', 0], ['release', .25]].forEach(([k, v]) => { if (comp[k]) comp[k].value = v; });
      o.connect(comp); comp.connect(ctx.destination); o.start(0);
      const buf = await Promise.race([ctx.startRendering(), new Promise((_, r) => setTimeout(() => r(new Error('t')), 1500))]);
      const d = buf.getChannelData(0); let s = 0;
      for (let i = 4500; i < 5000; i++) s += Math.abs(d[i]);
      return s.toFixed(6);
    } catch (e) { return null; }
  }
  const FONTS = ['Arial', 'Arial Black', 'Avenir', 'Avenir Next', 'Baskerville', 'Calibri', 'Cambria', 'Candara', 'Century Gothic', 'Comic Sans MS',
    'Consolas', 'Courier New', 'Didot', 'Franklin Gothic Medium', 'Futura', 'Garamond', 'Geneva', 'Georgia', 'Gill Sans', 'Helvetica Neue',
    'Hoefler Text', 'Impact', 'Lucida Console', 'Lucida Grande', 'Menlo', 'Monaco', 'Optima', 'Palatino', 'Roboto', 'Segoe UI', 'SF Pro Text',
    'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Ubuntu', 'Verdana', 'Noto Sans', 'DejaVu Sans', 'Liberation Sans', 'Source Code Pro',
    'Fira Code', 'JetBrains Mono', 'Microsoft YaHei', 'PingFang SC', 'Hiragino Sans', 'MS Gothic', 'Wingdings', 'Papyrus', 'Copperplate', 'Rockwell'];
  function fontsFp() {
    try {
      const c = document.createElement('canvas').getContext('2d'), txt = 'mmmmmmmmmmlli1WΨж漢', base = {};
      for (const b of ['monospace', 'serif', 'sans-serif']) { c.font = `72px ${b}`; base[b] = c.measureText(txt).width; }
      return FONTS.filter(f => ['monospace', 'serif', 'sans-serif'].some(b => { c.font = `72px '${f}',${b}`; return c.measureText(txt).width !== base[b]; }));
    } catch (e) { return []; }
  }
  // Περίπου πόσα bits ταυτότητας δίνει κάθε χαρακτηριστικό (από δημοσιευμένα στοιχεία Panopticlick / AmIUnique)
  async function fingerprint() {
    const n = navigator, scr = window.screen || {}, wg = webglFp(), fonts = fontsFp(), au = await audioFp(), cv = canvasFp();
    const tz = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { return '?'; } })();
    const mm = q => { try { return matchMedia(q).matches; } catch (e) { return false; } };
    const F = [
      ['ua', 'User-Agent', n.userAgent, 10, 'Ποιος browser, ποια έκδοση, ποιο λειτουργικό. Ανεβαίνει με κάθε ενημέρωση — συνδυασμένο με τα υπόλοιπα, σε ξεχωρίζει.'],
      ['canvas', 'Canvas', cv === 'blocked' ? 'μπλοκαρισμένο ✓' : (await sha(cv)).slice(0, 16), cv === 'blocked' ? 0.5 : 8.5, 'Ζωγραφίζω αόρατα κείμενο και σχήματα: η κάρτα γραφικών, οι γραμματοσειρές και το antialiasing δίνουν ελάχιστα διαφορετικά pixels σε κάθε υπολογιστή.'],
      ['webgl', 'WebGL (κάρτα γραφικών)', wg ? `${wg.vendor} · ${wg.renderer}` : 'κλειστό ✓', wg ? 6.5 : 0.5, 'Το όνομα της κάρτας γραφικών σου, όπως το δίνει ο driver.'],
      ['audio', 'Ήχος (AudioContext)', au == null ? 'κλειστό ✓' : au, au == null ? 0.5 : 5, 'Ένας αόρατος ήχος περνά από τον επεξεργαστή ήχου· το αποτέλεσμα διαφέρει ελάχιστα ανά σύστημα.'],
      ['fonts', 'Γραμματοσειρές', `${fonts.length} από ${FONTS.length}: ${fonts.slice(0, 8).join(', ')}${fonts.length > 8 ? '…' : ''}`, Math.min(9, 2 + fonts.length * 0.22), 'Ποιες γραμματοσειρές έχεις εγκατεστημένες (μετριέται το πλάτος του κειμένου).'],
      ['screen', 'Οθόνη', `${scr.width}×${scr.height} @${window.devicePixelRatio || 1}x · ${scr.colorDepth}-bit`, 4.8, 'Ανάλυση, πυκνότητα (Retina) και βάθος χρώματος.'],
      ['tz', 'Ζώνη ώρας', `${tz} (UTC${-new Date().getTimezoneOffset() / 60 >= 0 ? '+' : ''}${-new Date().getTimezoneOffset() / 60})`, tz === 'UTC' ? 0.5 : 3.5, 'Λέει περίπου πού βρίσκεσαι, ακόμα και πίσω από VPN.'],
      ['lang', 'Γλώσσες', (n.languages || [n.language]).join(', '), 5.5, 'Η σειρά των γλωσσών (π.χ. el-GR, en) είναι σπάνια εκτός Ελλάδας.'],
      ['hw', 'Επεξεργαστής / μνήμη', `${n.hardwareConcurrency || '?'} πυρήνες${n.deviceMemory ? ` · ${n.deviceMemory} GB` : ''}`, 3, 'Πόσους πυρήνες και (σε Chrome) πόση μνήμη έχει ο υπολογιστής.'],
      ['plat', 'Πλατφόρμα', `${n.platform || '?'}${n.maxTouchPoints ? ` · αφή ${n.maxTouchPoints}` : ''}`, 2, 'Mac / Windows / Linux / κινητό, και αν έχει οθόνη αφής.'],
      ['prefs', 'Προτιμήσεις', [mm('(prefers-color-scheme: dark)') ? 'σκούρο θέμα' : 'ανοιχτό θέμα', mm('(prefers-reduced-motion: reduce)') ? 'λιγότερη κίνηση' : '', n.doNotTrack === '1' ? 'DNT' : '', n.globalPrivacyControl ? 'GPC' : ''].filter(Boolean).join(' · '), 2, 'Σκούρο θέμα, λιγότερη κίνηση, Do Not Track… Ειρωνικά, το DNT κάνει τον browser πιο σπάνιο.'],
      ['misc', 'Διάφορα', `cookies ${n.cookieEnabled ? 'ναι' : 'όχι'} · pdf ${n.pdfViewerEnabled ? 'ναι' : 'όχι'} · plugins ${(n.plugins || []).length}`, 1.5, 'Μικρές λεπτομέρειες που προσθέτουν λίγα bits η καθεμιά.'],
    ].map(([id, name, value, bits, why]) => ({ id, name, value: String(value), bits, why }));
    const total = Math.round(F.reduce((s, f) => s + f.bits, 0) * 0.62);  // τα χαρακτηριστικά συσχετίζονται: δεν προστίθενται πλήρως
    const id = (await sha(F.map(f => f.value).join('|'))).slice(0, 12);
    const tor = (n.userAgent || '').includes('Firefox') && tz === 'UTC' && (n.languages || []).join() === 'en-US,en' && !wg;
    return { features: F, bits: total, id, tor, t: Date.now() };
  }
  const oneIn = b => b >= 33 ? 'μοναδικός σε όλο τον κόσμο (πάνω από 8 δισ. συσκευές)' : `1 στους ~${Math.round(2 ** b).toLocaleString('el-GR')} browsers`;

  function fpHTML() {
    const f = st.fp;
    let h = `<h3>🖐 Δακτυλικό αποτύπωμα browser</h3><div class="card"><div class="brow"><div style="min-width:0">
      <div class="sm" style="white-space:normal">Ακόμα και χωρίς cookies και με VPN, ένα site μπορεί να σε αναγνωρίσει από τον <b>συνδυασμό</b> μικρών λεπτομερειών του browser σου (σαν το <i>Cover Your Tracks</i> του EFF). Ο έλεγχος γίνεται <b>μόνο εδώ</b>, τίποτα δεν στέλνεται.</div></div>
      <button class="b" id="fp-run" ${st.fpRun ? 'disabled' : ''}>${st.fpRun ? '⏳ μετράω…' : f ? '↻ Ξανά' : '▶ Πόσο μοναδικός είμαι;'}</button></div>`;
    if (f) {
      const col = f.tor ? 'var(--green)' : f.bits >= 30 ? 'var(--red)' : f.bits >= 18 ? 'var(--orange)' : 'var(--green)';
      h += `<div class="fp-head"><div class="fp-num" style="color:${col}">${f.bits}<small> bits</small></div><div style="min-width:0">
        <b style="color:var(--hi)">${f.tor ? 'Μοιάζεις με όλους τους χρήστες Tor Browser ✓' : 'Ο browser σου είναι ' + oneIn(f.bits)}</b>
        <div class="sm">αναγνωριστικό: <code data-noi18n>${E(f.id)}</code> — ένα site που το μετρήσει ξανά αύριο θα πάρει το ίδιο, χωρίς cookies</div>
        <div class="fp-bar"><i style="width:${Math.min(100, f.bits / 40 * 100)}%;background:${col}"></i></div></div></div>
        <table class="fp-t"><thead><tr><th>Χαρακτηριστικό</th><th>Τι βλέπει το site</th><th>Bits</th></tr></thead><tbody>${f.features.slice().sort((a, b) => b.bits - a.bits).map(x => `<tr title="${E(x.why)}"><td><b>${E(x.name)}</b><div class="sm">${E(x.why)}</div></td><td class="fp-v" data-noi18n>${E(x.value)}</td><td><span class="fp-b" style="--w:${Math.min(100, x.bits * 10)}%">${x.bits.toFixed(1)}</span></td></tr>`).join('')}</tbody></table>
        <div class="sm" style="margin-top:8px;white-space:normal">👉 <b>Τι βοηθά:</b> Tor Browser (όλοι ίδιοι: ίδιο μέγεθος παραθύρου, UTC, αγγλικά) · Firefox με <code>privacy.resistFingerprinting = true</code> · Brave (θόρυβος στο canvas/audio) · Safari (κρύβει μέρος των γραμματοσειρών). Τα blockers διαφημίσεων <b>δεν</b> βοηθούν εδώ — συχνά σε κάνουν πιο σπάνιο.</div>`;
    }
    return h + '</div>';
  }

  // ───────────── 📷 EXIF / GPS ─────────────
  const TAGS = { 0x010F: 'Κατασκευαστής', 0x0110: 'Μοντέλο', 0x0131: 'Λογισμικό', 0x0132: 'Ημ/νία αλλαγής', 0x013B: 'Δημιουργός', 0x8298: 'Copyright',
    0x9003: 'Ημ/νία λήψης', 0xA434: 'Φακός', 0xA433: 'Κατασκευαστής φακού', 0xA430: 'Ιδιοκτήτης κάμερας', 0xA431: 'Σειριακός κάμερας', 0xA435: 'Σειριακός φακού',
    0x9010: 'Ζώνη ώρας', 0x829A: 'Έκθεση', 0x829D: 'Διάφραγμα', 0x8827: 'ISO' };
  function readExif(buf) {
    const v = new DataView(buf), u8 = new Uint8Array(buf), out = { tags: {}, gps: null, segments: [] };
    if (v.getUint16(0) !== 0xFFD8) return null;
    let p = 2, tiff = -1;
    while (p + 4 < v.byteLength) {
      if (v.getUint8(p) !== 0xFF) break;
      const m = v.getUint8(p + 1), len = v.getUint16(p + 2);
      if (m === 0xDA) break;
      const name = m >= 0xE0 && m <= 0xEF ? 'APP' + (m - 0xE0) : m === 0xFE ? 'COM' : null;
      if (name) out.segments.push(name);
      if (m === 0xE1 && String.fromCharCode(...u8.subarray(p + 4, p + 8)) === 'Exif') tiff = p + 10;
      if (m === 0xED) out.iptc = true;
      if (m === 0xE1 && String.fromCharCode(...u8.subarray(p + 4, p + 32)).startsWith('http://ns.adobe.com/xap')) out.xmp = true;
      p += 2 + len;
    }
    if (tiff < 0) return out;
    const le = v.getUint16(tiff) === 0x4949, g16 = o => v.getUint16(tiff + o, le), g32 = o => v.getUint32(tiff + o, le);
    const val = (type, cnt, off) => {
      const sz = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 }[type] || 1, at = sz * cnt > 4 ? g32(off) : off;
      if (type === 2) { let s = ''; for (let i = 0; i < cnt - 1 && tiff + at + i < v.byteLength; i++) s += String.fromCharCode(v.getUint8(tiff + at + i)); return s.trim(); }
      if (type === 3) return g16(at);
      if (type === 4) return g32(at);
      if (type === 5 || type === 10) { const r = []; for (let i = 0; i < cnt; i++) { const a = g32(at + i * 8), b = g32(at + i * 8 + 4); r.push(b ? a / b : 0); } return cnt === 1 ? r[0] : r; }
      return null;
    };
    const ifd = (off, cb) => { if (off <= 0 || tiff + off + 2 > v.byteLength) return; const n = g16(off); for (let i = 0; i < n && i < 400; i++) { const e = off + 2 + i * 12; if (tiff + e + 12 > v.byteLength) break; cb(g16(e), g16(e + 2), g32(e + 4), e + 8); } };
    let exifOff = 0, gpsOff = 0;
    const grab = (tag, type, cnt, o) => { try { if (tag === 0x8769) exifOff = g32(o); else if (tag === 0x8825) gpsOff = g32(o); else if (TAGS[tag]) out.tags[TAGS[tag]] = val(type, cnt, o); } catch (e) { /* χαλασμένο πεδίο */ } };
    ifd(g32(4), grab); ifd(exifOff, grab);
    if (gpsOff) {
      const G = {};
      ifd(gpsOff, (tag, type, cnt, o) => { try { G[tag] = val(type, cnt, o); } catch (e) { /* */ } });
      const dms = a => Array.isArray(a) ? a[0] + a[1] / 60 + a[2] / 3600 : null;
      const lat = dms(G[2]), lon = dms(G[4]);
      if (lat != null && lon != null && (lat || lon)) out.gps = { lat: (G[1] === 'S' ? -1 : 1) * lat, lon: (G[3] === 'W' ? -1 : 1) * lon, alt: typeof G[6] === 'number' ? G[6] : null };
    }
    return out;
  }
  // Καθάρισμα χωρίς επανασυμπίεση: πετάμε τα APP1 (EXIF/XMP), APP13 (IPTC) και COM· κρατάμε APP0 (JFIF) και APP2 (χρωματικό προφίλ).
  function stripJpeg(buf) {
    const v = new DataView(buf), u8 = new Uint8Array(buf), parts = [u8.subarray(0, 2)];
    let p = 2;
    while (p + 4 < v.byteLength && v.getUint8(p) === 0xFF) {
      const m = v.getUint8(p + 1);
      if (m === 0xDA) break;
      const len = v.getUint16(p + 2), seg = u8.subarray(p, p + 2 + len);
      if (!(m === 0xE1 || m === 0xED || m === 0xFE || (m >= 0xE3 && m <= 0xEF))) parts.push(seg);
      p += 2 + len;
    }
    parts.push(u8.subarray(p));
    return new Blob(parts, { type: 'image/jpeg' });
  }
  function exifHTML() {
    const x = st.exif;
    let h = `<h3>📷 Τι μαρτυρά μια φωτογραφία</h3><div class="card"><div class="sm" style="white-space:normal">Οι φωτογραφίες του κινητού κρατούν μέσα τους <b>πού</b> τραβήχτηκαν (GPS), <b>πότε</b> και <b>με ποιο κινητό</b>. Ρίξε εδώ ένα JPEG για να δεις τι θα έβλεπε όποιος το λάβει — το αρχείο <b>δεν φεύγει</b> από τον υπολογιστή σου.</div>
      <label class="ex-drop" id="ex-drop"><input type="file" id="ex-in" accept="image/jpeg,.jpg,.jpeg" hidden>⬆ Διάλεξε ή σύρε μια φωτογραφία (JPEG)</label>`;
    if (x) {
      if (x.error) h += `<div style="color:var(--redt)">${E(x.error)}</div>`;
      else {
        const t = Object.entries(x.info.tags || {}).filter(([, v]) => v !== '' && v != null);
        const risky = !!x.info.gps || t.some(([k]) => /Σειριακός|Ιδιοκτήτης|Δημιουργός/.test(k));
        h += `<div class="brow" style="margin-top:8px"><b style="color:var(--hi)">${risky ? '⚠️' : t.length ? 'ℹ️' : '✅'} <span data-noi18n>${E(x.name)}</span> <span class="sm">${(x.size / 1024).toFixed(0)} KB</span></b>
          ${x.clean ? `<a class="b" download="${E(x.cleanName)}" href="${x.clean}">⬇ Καθαρό αντίγραφο (${(x.cleanSize / 1024).toFixed(0)} KB)</a>` : ''}</div>`;
        if (x.info.gps) {
          const { lat, lon, alt } = x.info.gps;
          h += `<div class="ex-gps">📍 <b>Τοποθεσία μέσα στη φωτογραφία:</b> <span data-noi18n>${lat.toFixed(5)}, ${lon.toFixed(5)}</span>${alt != null ? ` · υψόμετρο ${alt.toFixed(0)} m` : ''} — <a target="_blank" rel="noopener" href="https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=17/${lat}/${lon}">δες στον χάρτη ↗</a>
            <div class="sm">Αν τη στείλεις έτσι, όποιος τη λάβει ξέρει πού ήσουν — ή πού μένεις, αν τραβήχτηκε στο σπίτι.</div></div>`;
        }
        h += t.length ? `<table style="margin-top:6px"><tbody>${t.map(([k, v]) => `<tr><td>${E(k)}</td><td data-noi18n>${E(Array.isArray(v) ? v.map(n => +n.toFixed(4)).join(', ') : typeof v === 'number' ? +v.toFixed(4) : v)}</td></tr>`).join('')}</tbody></table>`
          : '<div class="sm" style="margin-top:6px">Κανένα μεταδεδομένο EXIF — η φωτογραφία είναι καθαρή.</div>';
        if (x.info.xmp || x.info.iptc) h += `<div class="sm">Έχει επίσης ${[x.info.xmp && 'XMP', x.info.iptc && 'IPTC'].filter(Boolean).join(' και ')} (επεξεργασία, λέξεις-κλειδιά, συντάκτης).</div>`;
        h += `<div class="sm" style="margin-top:6px;white-space:normal">👉 Το «Καθαρό αντίγραφο» αφαιρεί EXIF, GPS, XMP και IPTC <b>χωρίς</b> να ξανασυμπιέσει την εικόνα. Στο iPhone: Κοινοποίηση → Επιλογές → «Τοποθεσία» off. Τα WhatsApp/Signal αφαιρούν το GPS, το email και το AirDrop <b>όχι</b>.</div>`;
      }
    }
    return h + '</div>';
  }
  function loadFile(f) {
    if (!f) return;
    if (st.exif && st.exif.clean) URL.revokeObjectURL(st.exif.clean);
    if (f.size > 60 * 1024 * 1024) { st.exif = { error: 'Πολύ μεγάλο αρχείο (όριο 60 MB).' }; return redraw(); }
    f.arrayBuffer().then(buf => {
      const info = readExif(buf);
      if (!info) { st.exif = { error: 'Δεν είναι JPEG (τα HEIC του iPhone: Κοινοποίηση → «Αποθήκευση ως JPEG», ή Ρυθμίσεις → Κάμερα → Μορφές → «Πιο συμβατό»).' }; return redraw(); }
      const clean = stripJpeg(buf);
      st.exif = { name: f.name, size: f.size, info, clean: URL.createObjectURL(clean), cleanSize: clean.size, cleanName: f.name.replace(/(\.jpe?g)?$/i, '-καθαρό.jpg') };
      redraw();
    }).catch(e => { st.exif = { error: String(e).slice(0, 100) }; redraw(); });
  }

  function redraw() { if (window.tab === 'priv' && typeof window.drawPriv === 'function') window.drawPriv(); else if (typeof drawPriv === 'function') drawPriv(); }
  function bind(el) {
    const b = el.querySelector('#fp-run');
    if (b) b.onclick = () => { st.fpRun = true; redraw(); fingerprint().then(r => { st.fp = r; }).catch(() => { }).finally(() => { st.fpRun = false; redraw(); }); };
    const inp = el.querySelector('#ex-in'), drop = el.querySelector('#ex-drop');
    if (inp) inp.onchange = () => loadFile(inp.files[0]);
    if (drop) {
      drop.ondragover = e => { e.preventDefault(); drop.classList.add('on'); };
      drop.ondragleave = () => drop.classList.remove('on');
      drop.ondrop = e => { e.preventDefault(); drop.classList.remove('on'); loadFile(e.dataTransfer.files[0]); };
    }
  }
  window.PRIVT = { html: () => fpHTML() + exifHTML(), bind, _test: { readExif, stripJpeg, fingerprint } };
})();
