// ───────────────────────── 🧮 Υπολογιστές τεχνικού: PoE, κάμερες/αποθήκευση, UPS, RF, πτώση τάσης ─────────────────────────
// Όλα τα μαθηματικά είναι στο NWCalc (καθαρές συναρτήσεις, χωρίς DOM) → window.NWCalc και module.exports για το node
// (tests/js/calc_check.js). Το UI είναι από κάτω και τρέχει μόνο όταν υπάρχει document. Τίποτα δεν φεύγει από τον browser.
(() => {
  'use strict';

  // ══════════════ Πίνακες (όλοι εδώ, με μονάδες) ══════════════
  const RHO_CU = 0.017241;          // Ω·mm²/m — χαλκός 100% IACS στους 20 °C
  const CCA_FACTOR = 1.55;          // αλουμίνιο με επίστρωση χαλκού (CCA): ~55% περισσότερη αντίσταση από καθαρό χαλκό
  const C_LIGHT = 299792458;        // m/s
  // PoE (IEEE 802.3af/at/bt): pse = W που δίνει η θύρα, pd = W που φτάνουν εγγυημένα στη συσκευή στα 100 m,
  // vMin = ελάχιστη τάση στη θύρα του switch (V), vPdMin = ελάχιστη τάση στη συσκευή (V), pairs = ζεύγη που κουβαλούν ρεύμα
  const POE_STD = [
    { id: 'af', name: '802.3af (PoE)', type: 1, pse: 15.4, pd: 12.95, vMin: 44, vPdMin: 37, pairs: 2 },
    { id: 'at', name: '802.3at (PoE+)', type: 2, pse: 30, pd: 25.5, vMin: 50, vPdMin: 42.5, pairs: 2 },
    { id: 'bt3', name: '802.3bt Type 3 (PoE++)', type: 3, pse: 60, pd: 51, vMin: 50, vPdMin: 42.5, pairs: 4 },
    { id: 'bt4', name: '802.3bt Type 4 (PoE++)', type: 4, pse: 90, pseMax: 100, pd: 71.3, vMin: 52, vPdMin: 41.1, pairs: 4 },
  ];
  // τυπική κατανάλωση συσκευών (W στη συσκευή) — πάντα έλεγξε το φυλλάδιο του κατασκευαστή
  const POE_DEVICES = [
    { id: 'cam', el: 'Κάμερα IP σταθερή', en: 'IP camera, fixed', w: 6 },
    { id: 'camir', el: 'Κάμερα IP με IR / θέρμανση', en: 'IP camera with IR / heater', w: 13 },
    { id: 'ptz', el: 'Κάμερα PTZ', en: 'PTZ camera', w: 24 },
    { id: 'ap5', el: 'Access Point Wi‑Fi 5', en: 'Access point Wi‑Fi 5', w: 12 },
    { id: 'ap6', el: 'Access Point Wi‑Fi 6', en: 'Access point Wi‑Fi 6', w: 18 },
    { id: 'ap6e', el: 'Access Point Wi‑Fi 6E', en: 'Access point Wi‑Fi 6E', w: 28 },
    { id: 'ap7', el: 'Access Point Wi‑Fi 7', en: 'Access point Wi‑Fi 7', w: 40 },
    { id: 'voip', el: 'Τηλέφωνο VoIP', en: 'VoIP phone', w: 6 },
    { id: 'door', el: 'Ελεγκτής πόρτας / θυροτηλέφωνο', en: 'Door controller / intercom', w: 12 },
    { id: 'iot', el: 'IoT gateway', en: 'IoT gateway', w: 8 },
    { id: 'custom', el: 'Άλλο (γράψε W)', en: 'Custom (enter W)', w: 10 },
  ];
  // καλώδια δικτύου: AWG του αγωγού
  const CABLES = [
    { id: 'cat5e', name: 'Cat5e (24 AWG)', awg: 24 }, { id: 'cat6', name: 'Cat6 (23 AWG)', awg: 23 }, { id: 'cat6a', name: 'Cat6A (23 AWG)', awg: 23 },
    { id: 'cat7', name: 'Cat7 (22 AWG)', awg: 22 }, { id: 'slim', name: 'Slim / patch (28 AWG)', awg: 28 }, { id: 'cca', name: 'Cat5e CCA (24 AWG)', awg: 24, cca: true },
  ];
  const POE_BUDGETS = [65, 124, 185, 250, 370, 500, 740, 1000, 1440, 2000];   // συνηθισμένα συνολικά PoE budget switch (W)
  // Κάμερες — ΕΚΤΙΜΗΣΗ: kbps για H.264, 25 fps, μέτρια κίνηση (κοντά στις προτάσεις των κατασκευαστών)
  const CAM_RES = [
    { id: '1mp', name: '1 MP (720p)', kbps: 2048 }, { id: '2mp', name: '2 MP (1080p)', kbps: 4096 }, { id: '3mp', name: '3 MP', kbps: 5120 },
    { id: '4mp', name: '4 MP (1440p)', kbps: 6144 }, { id: '5mp', name: '5 MP', kbps: 8192 }, { id: '6mp', name: '6 MP', kbps: 9216 },
    { id: '8mp', name: '8 MP (4K)', kbps: 12288 }, { id: '12mp', name: '12 MP', kbps: 16384 },
  ];
  const CAM_CODEC = { h264: { name: 'H.264', f: 1 }, 'h264+': { name: 'H.264+', f: 0.6 }, h265: { name: 'H.265', f: 0.5 }, 'h265+': { name: 'H.265+', f: 0.3 }, mjpeg: { name: 'MJPEG', f: 6, linear: true } };
  const CAM_ACTIVITY = { low: 0.7, medium: 1, high: 1.4 };
  const DISK_TB = [1, 2, 3, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22];
  const RAID_MIN = { single: 1, raid0: 2, raid1: 2, raid5: 3, raid6: 4, raid10: 4 };
  const HEADROOM = 0.2;             // 20% περιθώριο παντού

  // ══════════════ Μαθηματικά ══════════════
  const round = (x, d) => { const k = Math.pow(10, d == null ? 2 : d); return Math.round((x + Number.EPSILON) * k) / k; };
  const num = (x, def) => { const v = typeof x === 'string' ? parseFloat(x.replace(',', '.')) : +x; return isFinite(v) ? v : (def == null ? 0 : def); };

  // AWG → διάμετρος (mm) = 0.127 · 92^((36−n)/39) · εμβαδόν (mm²) · αντίσταση (Ω/m)
  const awgDiameter = n => 0.127 * Math.pow(92, (36 - n) / 39);
  const awgArea = n => Math.PI / 4 * Math.pow(awgDiameter(n), 2);
  const mm2OhmPerM = (a, cca) => (a > 0 ? RHO_CU / a * (cca ? CCA_FACTOR : 1) : Infinity);
  const awgOhmPerM = (n, cca) => mm2OhmPerM(awgArea(n), cca);

  // Αντίσταση βρόχου PoE: σε κάθε ζεύγος οι 2 αγωγοί είναι παράλληλα (r/2)· 2 ζεύγη = πήγαινε+έλα → r·L· 4 ζεύγη → r·L/2
  const poeLoopOhm = (lenM, awg, pairs, cca) => awgOhmPerM(awg, cca) * lenM * 2 / (pairs === 4 ? 4 : 2);

  // Η συσκευή θέλει pdW· το switch δίνει τάση vPse· το καλώδιο έχει rLoop.  P_pd = V·I − I²·R  →  I = (V − √(V² − 4·R·P)) / 2R
  function poeLine(pdW, vPse, rLoop) {
    if (!(pdW > 0)) return { ok: true, i: 0, loss: 0, pse: 0, vPd: vPse };
    if (!(rLoop > 0)) return { ok: true, i: pdW / vPse, loss: 0, pse: pdW, vPd: vPse };
    const disc = vPse * vPse - 4 * rLoop * pdW;
    if (disc < 0) return { ok: false, i: NaN, loss: NaN, pse: NaN, vPd: NaN };   // το καλώδιο δεν μπορεί να μεταφέρει τόση ισχύ
    const i = (vPse - Math.sqrt(disc)) / (2 * rLoop), loss = i * i * rLoop;
    return { ok: true, i, loss, pse: pdW + loss, vPd: vPse - i * rLoop };
  }
  const poeStd = id => POE_STD.find(s => s.id === id) || POE_STD[1];
  const poeClassFor = w => POE_STD.find(s => w <= s.pd) || null;          // το μικρότερο πρότυπο που καλύπτει τη συσκευή

  // rows: [{w, qty, len}] · std: id θύρας switch · cable: id καλωδίου · budgetW: συνολικό PoE budget του switch (προαιρετικό)
  function poeBudget(o) {
    const std = poeStd(o.std), cab = CABLES.find(c => c.id === o.cable) || CABLES[0];
    const rows = (o.rows || []).map(r => {
      const w = Math.max(0, num(r.w)), qty = Math.max(0, Math.round(num(r.qty, 1))), len = Math.max(0, num(r.len, 0));
      const rLoop = poeLoopOhm(len, cab.awg, std.pairs, cab.cca), line = poeLine(w, std.vMin, rLoop), need = poeClassFor(w);
      const warn = [];
      if (!need) warn.push('over_bt'); else if (w > std.pd) warn.push('over_std');
      if (len > 100) warn.push('too_long');
      if (!line.ok) warn.push('cable_cannot'); else { if (line.vPd < std.vPdMin) warn.push('vdrop'); if (line.pse > (std.pseMax || std.pse) + 1e-9) warn.push('over_port'); }
      return { w, qty, len, rLoop, need: need ? need.id : null, i: line.i, lossEach: line.loss, pseEach: line.pse, vPd: line.vPd, ok: line.ok, warn,
        pd: w * qty, pse: line.ok ? line.pse * qty : NaN, loss: line.ok ? line.loss * qty : NaN };
    });
    const sum = k => rows.reduce((a, r) => a + (isFinite(r[k]) ? r[k] : 0), 0);
    const totalPd = sum('pd'), totalPse = sum('pse'), loss = sum('loss'), ports = rows.reduce((a, r) => a + r.qty, 0);
    const want = totalPse * (1 + HEADROOM);
    const suggest = totalPse > 0 ? (POE_BUDGETS.find(b => b >= want) || null) : null;
    const budget = num(o.budgetW, 0);
    const headroom = budget > 0 ? (budget - totalPse) / budget * 100 : null;
    return { std, cable: cab, rows, ports, totalPd, totalPse, loss, lossPct: totalPse > 0 ? loss / totalPse * 100 : 0, want, suggest, budget,
      headroom, headroomOk: headroom == null ? null : headroom >= HEADROOM * 100, warn: rows.some(r => r.warn.length) };
  }

  // Κάμερες: kbps ανά κάμερα. Codecs με πρόβλεψη (H.26x): 40% του ρυθμού είναι «σταθερό» (I-frames) και 60% ακολουθεί τα fps.
  function camBitrate(o) {
    const res = CAM_RES.find(r => r.id === o.res) || CAM_RES[1], codec = CAM_CODEC[o.codec] || CAM_CODEC.h264;
    const fps = Math.max(1, num(o.fps, 25)), act = CAM_ACTIVITY[o.activity] || 1;
    const fpsF = codec.linear ? fps / 25 : 0.4 + 0.6 * fps / 25;
    return Math.round(res.kbps * codec.f * fpsF * act);
  }
  // cams × kbps → Mbps συνολικά, GB/ημέρα (δεκαδικά: 1 GB = 10⁹ bytes, όπως γράφουν οι δίσκοι), TB για N ημέρες
  function camStorage(o) {
    const cams = Math.max(0, num(o.cams, 1)), kbps = Math.max(0, num(o.kbps)), days = Math.max(0, num(o.days, 30));
    const duty = o.mode === 'motion' ? Math.min(100, Math.max(0, num(o.motionPct, 30))) / 100 : 1;
    const mbps = cams * kbps / 1000;                                   // ταυτόχρονη ροή προς τον καταγραφέα
    const gbDay = cams * kbps * 1000 / 8 * 86400 * duty / 1e9;
    const tb = gbDay * days / 1000;
    return { cams, kbps, duty, mbps, gbDay, tb, tbWithHeadroom: tb * (1 + HEADROOM), tib: tb * 1e12 / Math.pow(2, 40) };
  }
  function raidUsable(level, n, sizeTB) {
    n = Math.floor(n);
    if (!(n >= (RAID_MIN[level] || 1)) || !(sizeTB > 0)) return 0;
    if (level === 'single' || level === 'raid0') return n * sizeTB;
    if (level === 'raid1') return sizeTB;                              // καθρέφτης: όσο ένας δίσκος
    if (level === 'raid5') return (n - 1) * sizeTB;
    if (level === 'raid6') return (n - 2) * sizeTB;
    if (level === 'raid10') return Math.floor(n / 2) * sizeTB;
    return 0;
  }
  // Μικρότερη διάταξη (λιγότερα ακατέργαστα TB, μετά λιγότεροι δίσκοι) που δίνει usable ≥ needTB · maxDisks = θέσεις του NVR/NAS
  function recommendDisks(needTB, level, maxDisks) {
    const min = RAID_MIN[level] || 1, max = level === 'raid1' ? 2 : Math.max(min, maxDisks || 8);
    let best = null;
    for (let n = min; n <= max; n += (level === 'raid10' ? 2 : 1)) {
      for (const size of DISK_TB) {
        const usable = raidUsable(level, n, size);
        if (usable + 1e-9 < needTB) continue;
        const cand = { level, n, size, usable, raw: n * size };
        if (!best || cand.raw < best.raw || (cand.raw === best.raw && cand.n < best.n)) best = cand;
        break;
      }
    }
    return best;
  }
  const retentionDays = (usableTB, gbDay) => (gbDay > 0 ? usableTB * 1000 / gbDay : Infinity);

  // UPS: Wh μπαταρίας × βάθος εκφόρτισης × απόδοση inverter ÷ φορτίο. Εκτίμηση — αγνοεί Peukert, ηλικία, θερμοκρασία.
  function upsRuntime(o) {
    const load = num(o.loadW), wh = num(o.v, 12) * num(o.ah, 7) * Math.max(1, num(o.count, 1));
    const eff = Math.min(1, Math.max(0.01, num(o.eff, 0.85))), dod = Math.min(1, Math.max(0.01, num(o.dod, 0.8)));
    const usable = wh * dod * eff;
    return { wh, usableWh: usable, minutes: load > 0 ? usable / load * 60 : Infinity };
  }

  // RF
  const dbmToMw = dbm => Math.pow(10, dbm / 10);
  const mwToDbm = mw => (mw > 0 ? 10 * Math.log10(mw) : -Infinity);
  // Απώλεια ελεύθερου χώρου (dB) = 20·log10(d_km) + 20·log10(f_MHz) + 32.44
  const fspl = (distM, fMHz) => (distM > 0 && fMHz > 0 ? 20 * Math.log10(distM / 1000) + 20 * Math.log10(fMHz) + 32.44 : NaN);
  function linkBudget(o) {
    const loss = fspl(num(o.distM), num(o.fMHz));
    const eirp = num(o.txDbm) + num(o.txGain) - num(o.txCable);
    const rssi = eirp - loss - num(o.extraLoss) + num(o.rxGain) - num(o.rxCable);
    const sens = o.rxSens === '' || o.rxSens == null ? null : num(o.rxSens);
    return { fspl: loss, eirp, rssi, margin: sens == null ? null : rssi - sens };
  }
  // Ακτίνα 1ης ζώνης Fresnel (m) στο σημείο d1 από το ένα άκρο: r = √(λ·d1·d2/(d1+d2)) · στη μέση: √(λ·d/4)
  function fresnel(distM, fMHz, d1) {
    if (!(distM > 0) || !(fMHz > 0)) return NaN;
    const lam = C_LIGHT / (fMHz * 1e6), a = d1 == null ? distM / 2 : Math.min(Math.max(d1, 0), distM);
    return Math.sqrt(lam * a * (distM - a) / distM);
  }

  // Πτώση τάσης DC: R = 2·L·(Ω/m) (πήγαινε + έλα) · ΔV = I·R
  function vdrop(o) {
    const v = num(o.v, 12), i = Math.max(0, num(o.i)), len = Math.max(0, num(o.lenM));
    const rpm = o.mm2 ? mm2OhmPerM(num(o.mm2), o.cca) : awgOhmPerM(num(o.awg, 18), o.cca);
    const r = 2 * len * rpm, drop = i * r;
    return { ohmPerM: rpm, r, drop, pct: v > 0 ? drop / v * 100 : NaN, vEnd: v - drop, lossW: i * i * r };
  }
  // Ελάχιστη διατομή (mm²) για να μείνει η πτώση ≤ maxPct
  const vdropMinMm2 = (v, i, lenM, maxPct) => (v > 0 && maxPct > 0 ? 2 * lenM * i * RHO_CU / (v * maxPct / 100) : NaN);

  const NWCalc = { RHO_CU, CCA_FACTOR, POE_STD, POE_DEVICES, CABLES, POE_BUDGETS, CAM_RES, CAM_CODEC, CAM_ACTIVITY, DISK_TB, RAID_MIN, HEADROOM,
    round, num, awgDiameter, awgArea, awgOhmPerM, mm2OhmPerM, poeLoopOhm, poeLine, poeStd, poeClassFor, poeBudget, camBitrate, camStorage,
    raidUsable, recommendDisks, retentionDays, upsRuntime, dbmToMw, mwToDbm, fspl, linkBudget, fresnel, vdrop, vdropMinMm2 };
  if (typeof module !== 'undefined' && module.exports) module.exports = NWCalc;
  if (typeof window !== 'undefined') window.NWCalc = NWCalc;
  if (typeof document === 'undefined') return;

  // ══════════════ UI ══════════════
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => EN() ? en : el;
  const box = () => document.getElementById('t-calc');
  const F = (x, d) => (isFinite(x) ? round(x, d == null ? 1 : d).toLocaleString(EN() ? 'en-GB' : 'el-GR', { maximumFractionDigits: d == null ? 1 : d }) : '—');
  const KEY = 'nw.calc.v1';
  const DEF = {
    tab: 'poe',
    poe: { std: 'at', cable: 'cat5e', budgetW: '', rows: [{ dev: 'cam', w: 6, qty: 8, len: 60 }, { dev: 'ap6', w: 18, qty: 2, len: 40 }] },
    cam: { cams: 8, res: '4mp', fps: 15, codec: 'h265', activity: 'medium', kbps: '', mode: 'cont', motionPct: 30, days: 30, raid: 'raid5', bays: 4, diskTB: 8, diskN: 4 },
    ups: { loadW: 120, v: 12, ah: 9, count: 2, eff: 85, dod: 80 },
    rf: { dbm: 20, mw: 100, distM: 100, fMHz: 5500, txDbm: 20, txGain: 3, txCable: 0, rxGain: 3, rxCable: 0, extraLoss: 0, rxSens: -75 },
    vd: { v: 12, i: 2, lenM: 20, unit: 'awg', awg: 18, mm2: 1.5, cca: false },
  };
  let S = JSON.parse(JSON.stringify(DEF));
  try { const j = JSON.parse(localStorage.getItem(KEY) || 'null'); if (j && typeof j === 'object') for (const k of Object.keys(DEF)) if (j[k] != null && typeof j[k] === typeof DEF[k]) S[k] = typeof DEF[k] === 'object' ? Object.assign({}, DEF[k], j[k]) : j[k]; } catch (_) { /* ιδιωτική περιήγηση */ }
  if (!Array.isArray(S.poe.rows) || !S.poe.rows.length) S.poe.rows = JSON.parse(JSON.stringify(DEF.poe.rows));
  const save = () => { try { localStorage.setItem(KEY, JSON.stringify(S)); } catch (_) { /* δεν πειράζει */ } };

  const css = document.createElement('style');
  css.textContent = `
#t-calc .cc-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
#t-calc .cc-tabs .b.on{border-color:var(--cyan);color:var(--cyan);font-weight:600}
#t-calc .cc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px 12px;margin-top:8px}
#t-calc label{display:block;font-size:11.5px;color:var(--dim);margin-bottom:2px}
#t-calc input,#t-calc select{width:100%;box-sizing:border-box;background:rgb(var(--w,255 255 255) / 6%);color:inherit;border:1px solid rgb(var(--w,255 255 255) / 14%);border-radius:8px;padding:6px 8px;font:13px inherit}
#t-calc input[type=checkbox]{width:auto}
#t-calc .cc-row{display:grid;grid-template-columns:minmax(130px,2fr) 70px 60px 70px 30px;gap:6px;margin-top:6px;align-items:end}
#t-calc .cc-res{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-top:10px}
#t-calc .cc-kpi{background:rgb(var(--w,255 255 255) / 4%);border-radius:10px;padding:9px 11px;border-left:3px solid var(--c,var(--cyan))}
#t-calc .cc-kpi b{font-size:19px;display:block;font-family:var(--mono,ui-monospace,monospace)}
#t-calc .cc-kpi span{font-size:11.5px;color:var(--dim)}
#t-calc .cc-warn{font-size:13px;margin-top:6px;padding:7px 10px;border-radius:8px;border-left:3px solid var(--c,var(--orange));background:rgb(var(--w,255 255 255) / 4%);line-height:1.5}
#t-calc .cc-exp{font-size:12.5px;color:var(--dim);line-height:1.6;margin-top:10px}
#t-calc .cc-exp b{color:inherit}
#t-calc table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:8px}
#t-calc th{text-align:left;color:var(--dim);font-size:11px;font-weight:600;padding:5px 6px;border-bottom:1px solid var(--line,rgb(255 255 255 / 12%))}
#t-calc td{padding:5px 6px;border-bottom:1px solid rgb(var(--w,255 255 255) / 6%);font-family:var(--mono,ui-monospace,monospace);white-space:nowrap}
#t-calc .cc-wrap{overflow:auto}
#t-calc code{background:rgb(var(--w,255 255 255) / 8%);padding:0 4px;border-radius:4px;font-family:var(--mono,ui-monospace,monospace);font-size:12px}
@media (max-width:520px){#t-calc .cc-row{grid-template-columns:1fr 1fr 1fr 1fr 30px}#t-calc .cc-row>div:first-child{grid-column:1 / -1}}
`;
  document.head.appendChild(css);

  const TABS = [['poe', '⚡ PoE budget', '⚡ PoE budget'], ['cam', '📹 Κάμερες & δίσκοι', '📹 Cameras & disks'], ['ups', '🔋 UPS', '🔋 UPS'], ['rf', '📡 Wi‑Fi / RF', '📡 Wi‑Fi / RF'], ['vd', '🔌 Πτώση τάσης DC', '🔌 DC voltage drop']];
  const inp = (k, label, extra) => `<div><label>${label}</label><input data-k="${k}" value="${E(k.split('.').reduce((a, p) => (a == null ? a : a[p]), S))}" inputmode="decimal" ${extra || ''}></div>`;
  const sel = (k, label, opts) => { const cur = String(k.split('.').reduce((a, p) => (a == null ? a : a[p]), S)); return `<div><label>${label}</label><select data-k="${k}">${opts.map(o => `<option value="${E(o[0])}"${String(o[0]) === cur ? ' selected' : ''}>${E(o[1])}</option>`).join('')}</select></div>`; };
  const kpi = (v, label, c) => `<div class="cc-kpi" style="--c:${c || 'var(--cyan)'}"><b>${v}</b><span>${label}</span></div>`;
  const warn = (txt, c) => `<div class="cc-warn" style="--c:${c || 'var(--orange)'}">${txt}</div>`;

  // ── PoE ──
  function poeForm() {
    const rows = S.poe.rows.map((r, i) => `<div class="cc-row"><div>${i ? '' : `<label>${T('Συσκευή', 'Device')}</label>`}<select data-row="${i}" data-rk="dev">${POE_DEVICES.map(d => `<option value="${d.id}"${d.id === r.dev ? ' selected' : ''}>${E(T(d.el, d.en))}</option>`).join('')}</select></div>
      <div>${i ? '' : '<label>W</label>'}<input data-row="${i}" data-rk="w" value="${E(r.w)}" inputmode="decimal"></div>
      <div>${i ? '' : `<label>${T('Τεμ.', 'Qty')}</label>`}<input data-row="${i}" data-rk="qty" value="${E(r.qty)}" inputmode="numeric"></div>
      <div>${i ? '' : `<label>${T('Καλώδιο m', 'Cable m')}</label>`}<input data-row="${i}" data-rk="len" value="${E(r.len)}" inputmode="decimal"></div>
      <div><button class="b" data-cc="delrow" data-i="${i}" title="${T('Αφαίρεση', 'Remove')}">✕</button></div></div>`).join('');
    return `<div class="cc-grid">${sel('poe.std', T('Πρότυπο θυρών του switch', 'Switch port standard'), POE_STD.map(s => [s.id, `${s.name} · ${s.pse} W`]))}
      ${sel('poe.cable', T('Καλώδιο', 'Cable'), CABLES.map(c => [c.id, c.name]))}
      ${inp('poe.budgetW', T('PoE budget του switch (W) — προαιρετικό', 'Switch PoE budget (W) — optional'))}</div>
      ${rows}<div style="margin-top:8px"><button class="b" data-cc="addrow">＋ ${T('Συσκευή', 'Device')}</button></div>`;
  }
  function poeOut() {
    const r = poeBudget(S.poe), st = r.std;
    const W = { over_std: T('θέλει περισσότερα W από όσα δίνει αυτό το πρότυπο θύρας', 'needs more W than this port standard delivers'), over_bt: T('πάνω από 71 W: δεν τροφοδοτείται με τυπικό PoE', 'above 71 W: cannot be powered by standard PoE'),
      too_long: T('καλώδιο πάνω από 100 m (εκτός προδιαγραφής Ethernet)', 'cable over 100 m (outside the Ethernet spec)'), vdrop: T('η τάση στη συσκευή πέφτει κάτω από το ελάχιστο', 'voltage at the device falls below the minimum'),
      over_port: T('η θύρα πρέπει να δώσει περισσότερα W από το όριό της', 'the port must supply more W than its limit'), cable_cannot: T('το καλώδιο δεν μπορεί να μεταφέρει τόση ισχύ', 'the cable cannot carry this much power') };
    const hc = r.headroom == null ? 'var(--cyan)' : r.headroomOk ? 'var(--green,#3fb950)' : r.headroom >= 0 ? 'var(--orange)' : 'var(--red)';
    let h = `<div class="cc-res">${kpi(F(r.totalPd) + ' W', T('σύνολο στις συσκευές', 'total at the devices'))}${kpi(F(r.totalPse) + ' W', T('σύνολο από το switch (με απώλειες)', 'total from the switch (with losses)'))}
      ${kpi(F(r.loss) + ' W', T(`χάνονται στα καλώδια (${F(r.lossPct)}%)`, `lost in the cables (${F(r.lossPct)}%)`), 'var(--dim)')}
      ${r.headroom == null ? kpi(r.suggest ? '≥ ' + r.suggest + ' W' : (r.totalPse > 0 ? '> 2000 W' : '—'), T('προτεινόμενο PoE budget (με 20% περιθώριο)', 'suggested PoE budget (with 20% headroom)'), 'var(--green,#3fb950)') : kpi(F(r.headroom) + '%', T('περιθώριο στο switch (θέλουμε ≥ 20%)', 'switch headroom (aim for ≥ 20%)'), hc)}
      ${kpi(r.ports, T('θύρες PoE', 'PoE ports'), 'var(--dim)')}</div>`;
    h += `<div class="cc-wrap"><table><tr><th>${T('Συσκευή', 'Device')}</th><th>${T('Θέλει', 'Needs')}</th><th>${T('Ω βρόχου', 'Loop Ω')}</th><th>mA</th><th>${T('Απώλεια/θύρα', 'Loss/port')}</th><th>${T('W από θύρα', 'W from port')}</th><th>${T('V στη συσκευή', 'V at device')}</th></tr>
      ${r.rows.map((x, i) => { const d = POE_DEVICES.find(q => q.id === S.poe.rows[i].dev) || POE_DEVICES[0]; const need = x.need ? poeStd(x.need).name.split(' ')[0] : '—'; return `<tr><td style="font-family:inherit">${x.warn.length ? '⚠ ' : ''}${E(x.qty)}× ${E(T(d.el, d.en))}</td><td>${E(need)}</td><td>${F(x.rLoop, 2)}</td><td>${F(x.i * 1000, 0)}</td><td>${F(x.lossEach, 2)} W</td><td>${F(x.pseEach, 1)} W</td><td>${F(x.vPd, 1)} V</td></tr>`; }).join('')}</table></div>`;
    r.rows.forEach((x, i) => { if (x.warn.length) { const d = POE_DEVICES.find(q => q.id === S.poe.rows[i].dev) || POE_DEVICES[0]; h += warn(`⚠ <b>${E(T(d.el, d.en))} (${F(x.w)} W, ${F(x.len, 0)} m)</b>: ${x.warn.map(w => W[w]).join(' · ')}${x.need && x.warn.includes('over_std') ? ' → ' + T('χρειάζεται θύρα', 'needs a port with') + ' ' + E(poeStd(x.need).name) : ''}.`, x.warn.includes('too_long') && x.warn.length === 1 ? 'var(--orange)' : 'var(--red)'); } });
    if (r.headroom != null && !r.headroomOk) h += warn(r.headroom < 0 ? '🚨 ' + T(`Το switch δεν φτάνει: ζητούνται ${F(r.totalPse)} W από ${F(r.budget)} W. Κάποιες θύρες θα μείνουν χωρίς ρεύμα.`, `The switch is not enough: ${F(r.totalPse)} W requested of ${F(r.budget)} W. Some ports will stay unpowered.`) : '⚠ ' + T(`Περιθώριο κάτω από 20%. Στην εκκίνηση (IR τη νύχτα, PTZ σε κίνηση, θέρμανση) η κατανάλωση ανεβαίνει — προτίμησε switch ≥ ${F(r.want, 0)} W.`, `Headroom below 20%. Consumption rises at start-up (IR at night, PTZ moving, heater) — prefer a switch ≥ ${F(r.want, 0)} W.`), r.headroom < 0 ? 'var(--red)' : 'var(--orange)');
    if (r.cable.cca) h += warn('⚠ ' + T('Καλώδιο CCA (αλουμίνιο με επίστρωση χαλκού): ~55% περισσότερη αντίσταση, ζεσταίνεται και δεν επιτρέπεται από τα πρότυπα για PoE. Χρησιμοποίησε καθαρό χαλκό.', 'CCA cable (copper-clad aluminium): ~55% more resistance, it heats up and the standards do not allow it for PoE. Use solid copper.'), 'var(--red)');
    h += `<div class="cc-exp">${T(`<b>Πώς υπολογίζεται:</b> το switch δίνει τουλάχιστον <code>${st.vMin} V</code> στη θύρα (${E(st.name)}, ρεύμα σε ${st.pairs} ζεύγη). Το καλώδιο έχει αντίσταση βρόχου <code>R = Ω/m × μήκος × ${st.pairs === 4 ? '½' : '1'}</code> και «τρώει» <code>I²·R</code> watt ως θερμότητα — γι’ αυτό το switch δίνει περισσότερα από όσα φτάνουν. Όρια προτύπων (θύρα / συσκευή): af 15,4 / 12,95 W · at 30 / 25,5 W · bt Type 3 60 / 51 W · bt Type 4 90–100 / 71,3 W. Οι τιμές συσκευών είναι τυπικές — δες το φυλλάδιο. Κράτα <b>20% περιθώριο</b> στο συνολικό budget.`,
      `<b>How it is computed:</b> the switch supplies at least <code>${st.vMin} V</code> at the port (${E(st.name)}, current on ${st.pairs} pairs). The cable has a loop resistance <code>R = Ω/m × length × ${st.pairs === 4 ? '½' : '1'}</code> and burns <code>I²·R</code> watts as heat — which is why the switch supplies more than what arrives. Standard limits (port / device): af 15.4 / 12.95 W · at 30 / 25.5 W · bt Type 3 60 / 51 W · bt Type 4 90–100 / 71.3 W. Device figures are typical — check the datasheet. Keep <b>20% headroom</b> on the total budget.`)}</div>`;
    return h;
  }

  // ── Κάμερες ──
  function camForm() {
    return `<div class="cc-grid">${inp('cam.cams', T('Κάμερες', 'Cameras'))}${sel('cam.res', T('Ανάλυση', 'Resolution'), CAM_RES.map(r => [r.id, r.name]))}${inp('cam.fps', 'fps')}
      ${sel('cam.codec', 'Codec', Object.keys(CAM_CODEC).map(k => [k, CAM_CODEC[k].name]))}
      ${sel('cam.activity', T('Κίνηση στη σκηνή', 'Scene activity'), [['low', T('λίγη (αποθήκη, διάδρομος)', 'low (storeroom, corridor)')], ['medium', T('μέτρια (είσοδος, γραφείο)', 'medium (entrance, office)')], ['high', T('πολλή (δρόμος, ταμείο)', 'high (street, checkout)')]])}
      ${inp('cam.kbps', T('Δικό σου bitrate (kbps) — προαιρετικό', 'Your own bitrate (kbps) — optional'))}
      ${sel('cam.mode', T('Εγγραφή', 'Recording'), [['cont', T('συνεχής 24/7', 'continuous 24/7')], ['motion', T('μόνο με κίνηση', 'motion only')]])}
      ${S.cam.mode === 'motion' ? inp('cam.motionPct', T('Κίνηση: % της ημέρας', 'Motion: % of the day')) : ''}
      ${inp('cam.days', T('Ημέρες αρχείου', 'Days of retention'))}
      ${sel('cam.raid', 'RAID', [['single', T('ένας δίσκος / JBOD', 'single disk / JBOD')], ['raid1', 'RAID 1'], ['raid5', 'RAID 5'], ['raid6', 'RAID 6'], ['raid10', 'RAID 10']])}
      ${inp('cam.bays', T('Θέσεις δίσκων στον καταγραφέα', 'Disk bays in the recorder'))}</div>
      <div style="margin-top:12px;font-size:13px"><b>${T('Ανάποδα: έχω ήδη δίσκους — πόσες μέρες χωράνε;', 'Reverse: I already have disks — how many days fit?')}</b></div>
      <div class="cc-grid">${inp('cam.diskN', T('Πλήθος δίσκων', 'Number of disks'))}${inp('cam.diskTB', T('Μέγεθος δίσκου (TB)', 'Disk size (TB)'))}</div>`;
  }
  function camOut() {
    const c = S.cam, est = camBitrate(c), own = num(c.kbps, 0) > 0, kbps = own ? num(c.kbps) : est;
    const s = camStorage({ cams: c.cams, kbps, days: c.days, mode: c.mode, motionPct: c.motionPct });
    const rec = recommendDisks(s.tbWithHeadroom, c.raid, Math.max(1, Math.round(num(c.bays, 4))));
    const have = raidUsable(c.raid, num(c.diskN, 0), num(c.diskTB, 0)), days = retentionDays(have, s.gbDay);
    const RN = { single: T('χωρίς RAID', 'no RAID'), raid0: 'RAID 0', raid1: 'RAID 1', raid5: 'RAID 5', raid6: 'RAID 6', raid10: 'RAID 10' };
    let h = `<div class="cc-res">${kpi(F(kbps, 0) + ' kbps', own ? T('bitrate ανά κάμερα (δικό σου)', 'bitrate per camera (yours)') : T('bitrate ανά κάμερα (εκτίμηση)', 'bitrate per camera (estimate)'))}
      ${kpi(F(s.mbps, 1) + ' Mbps', T('συνολική ροή προς τον καταγραφέα', 'total stream to the recorder'))}${kpi(F(s.gbDay, 0) + ' GB', T('ανά ημέρα', 'per day'), 'var(--dim)')}
      ${kpi(F(s.tb, 2) + ' TB', T(`για ${F(num(c.days), 0)} ημέρες`, `for ${F(num(c.days), 0)} days`))}${kpi(F(s.tbWithHeadroom, 2) + ' TB', T('με 20% περιθώριο', 'with 20% headroom'), 'var(--green,#3fb950)')}</div>`;
    h += warn(rec ? '💽 ' + T(`Πρόταση: <b>${rec.n} × ${rec.size} TB</b> σε ${RN[c.raid]} → ${F(rec.usable, 0)} TB ωφέλιμα (${F(rec.raw, 0)} TB ακατέργαστα).`, `Suggestion: <b>${rec.n} × ${rec.size} TB</b> in ${RN[c.raid]} → ${F(rec.usable, 0)} TB usable (${F(rec.raw, 0)} TB raw).`)
      : '⚠ ' + T(`Δεν χωρά σε ${E(c.bays)} θέσεις με ${RN[c.raid]} και δίσκους έως 22 TB — θέλει περισσότερες θέσεις, λιγότερες μέρες ή H.265.`, `Does not fit in ${E(c.bays)} bays with ${RN[c.raid]} and disks up to 22 TB — needs more bays, fewer days or H.265.`), rec ? 'var(--green,#3fb950)' : 'var(--red)');
    h += warn(have > 0 ? '⏪ ' + T(`${E(c.diskN)} × ${E(c.diskTB)} TB σε ${RN[c.raid]} = ${F(have, 0)} TB ωφέλιμα → <b>${F(days, 1)} ημέρες</b> αρχείου (χωρίς περιθώριο).`, `${E(c.diskN)} × ${E(c.diskTB)} TB in ${RN[c.raid]} = ${F(have, 0)} TB usable → <b>${F(days, 1)} days</b> of retention (no headroom).`)
      : '⏪ ' + T(`Αυτό το RAID θέλει τουλάχιστον ${RAID_MIN[c.raid]} δίσκους.`, `This RAID level needs at least ${RAID_MIN[c.raid]} disks.`), 'var(--cyan)');
    if (s.mbps > 80) h += warn('⚠ ' + T('Πάνω από 80 Mbps: το uplink προς τον καταγραφέα πρέπει να είναι Gigabit (όχι 100 Mbps).', 'Above 80 Mbps: the uplink to the recorder must be Gigabit (not 100 Mbps).'));
    h += `<div class="cc-exp">${T(`<b>Πίνακας εκτίμησης</b> (kbps, H.264, 25 fps, μέτρια κίνηση): ${CAM_RES.map(r => r.name.split(' (')[0] + ' ' + r.kbps).join(' · ')}. Συντελεστές codec: H.264 ×1 · H.264+ ×0,6 · H.265 ×0,5 · H.265+ ×0,3 · MJPEG ×6. Κίνηση: λίγη ×0,7 · μέτρια ×1 · πολλή ×1,4. fps: <code>0,4 + 0,6 × fps/25</code> (στο MJPEG γραμμικά). Είναι <b>εκτίμηση</b> — το πραγματικό bitrate φαίνεται στη σελίδα της κάμερας· γράψ’ το στο «δικό σου bitrate». Αποθήκευση: <code>kbps × 1000 ÷ 8 × 86.400 s × κάμερες</code>. 1 TB δίσκου = 10¹² bytes (το λειτουργικό το δείχνει ως ${F(1e12 / Math.pow(2, 40), 3)} TiB). RAID 1 = ένας δίσκος ωφέλιμος · RAID 5 = n−1 · RAID 6 = n−2 · RAID 10 = n/2. Για καταγραφή προτίμησε δίσκους «surveillance».`,
      `<b>Estimation table</b> (kbps, H.264, 25 fps, medium activity): ${CAM_RES.map(r => r.name.split(' (')[0] + ' ' + r.kbps).join(' · ')}. Codec factors: H.264 ×1 · H.264+ ×0.6 · H.265 ×0.5 · H.265+ ×0.3 · MJPEG ×6. Activity: low ×0.7 · medium ×1 · high ×1.4. fps: <code>0.4 + 0.6 × fps/25</code> (linear for MJPEG). This is an <b>estimate</b> — the real bitrate is on the camera’s page; enter it under “your own bitrate”. Storage: <code>kbps × 1000 ÷ 8 × 86,400 s × cameras</code>. 1 TB of disk = 10¹² bytes (the OS shows it as ${F(1e12 / Math.pow(2, 40), 3)} TiB). RAID 1 = one disk usable · RAID 5 = n−1 · RAID 6 = n−2 · RAID 10 = n/2. Prefer “surveillance” disks for recording.`)}</div>`;
    return h;
  }

  // ── UPS ──
  const upsForm = () => `<div class="cc-grid">${inp('ups.loadW', T('Φορτίο (W)', 'Load (W)'))}${inp('ups.v', T('Τάση μπαταρίας (V)', 'Battery voltage (V)'))}${inp('ups.ah', T('Χωρητικότητα (Ah)', 'Capacity (Ah)'))}${inp('ups.count', T('Πλήθος μπαταριών', 'Number of batteries'))}${inp('ups.eff', T('Απόδοση inverter (%)', 'Inverter efficiency (%)'))}${inp('ups.dod', T('Βάθος εκφόρτισης (%)', 'Depth of discharge (%)'))}</div>`;
  function upsOut() {
    const u = S.ups, r = upsRuntime({ loadW: u.loadW, v: u.v, ah: u.ah, count: u.count, eff: num(u.eff, 85) / 100, dod: num(u.dod, 80) / 100 });
    const m = r.minutes, txt = !isFinite(m) ? '—' : m >= 120 ? F(m / 60, 1) + ' ' + T('ώρες', 'h') : F(m, 0) + ' ' + T('λεπτά', 'min');
    return `<div class="cc-res">${kpi('≈ ' + txt, T('αυτονομία (εκτίμηση)', 'runtime (estimate)'), 'var(--green,#3fb950)')}${kpi(F(r.wh, 0) + ' Wh', T('ονομαστική ενέργεια μπαταριών', 'nominal battery energy'), 'var(--dim)')}${kpi(F(r.usableWh, 0) + ' Wh', T('αξιοποιήσιμη', 'usable'))}</div>
      ${m < 5 ? warn('⚠ ' + T('Κάτω από 5 λεπτά: φτάνει μόνο για κανονικό κλείσιμο, όχι για να «περάσει» μια διακοπή.', 'Under 5 minutes: enough only for a clean shutdown, not to ride through an outage.')) : ''}
      <div class="cc-exp">${T('<b>Είναι εκτίμηση:</b> <code>V × Ah × μπαταρίες × βάθος εκφόρτισης × απόδοση ÷ φορτίο</code>. <b>Δεν</b> υπολογίζει το φαινόμενο Peukert (οι μπαταρίες μολύβδου δίνουν αισθητά λιγότερη ενέργεια σε γρήγορη εκφόρτιση — σε αυτονομία κάτω της 1 ώρας περίμενε 30–50% λιγότερο), την ηλικία και τη θερμοκρασία. Μολύβδου: βάθος 50–80%· LiFePO₄: 80–90%. Μέτρα το πραγματικό φορτίο σε W (όχι τα VA της ετικέτας) και δες τον πίνακα αυτονομίας του κατασκευαστή πριν υποσχεθείς χρόνο στον πελάτη.',
        '<b>This is an estimate:</b> <code>V × Ah × batteries × depth of discharge × efficiency ÷ load</code>. It does <b>not</b> model the Peukert effect (lead-acid batteries deliver noticeably less energy at fast discharge — for runtimes under 1 hour expect 30–50% less), ageing or temperature. Lead-acid: 50–80% depth; LiFePO₄: 80–90%. Measure the real load in W (not the VA on the label) and check the vendor’s runtime chart before promising a time to the customer.')}</div>`;
  }

  // ── RF ──
  const rfForm = () => `<div class="cc-grid">${inp('rf.dbm', 'dBm → mW')}${inp('rf.mw', 'mW → dBm')}</div>
    <div class="cc-grid">${inp('rf.distM', T('Απόσταση (m)', 'Distance (m)'))}${inp('rf.fMHz', T('Συχνότητα (MHz)', 'Frequency (MHz)'))}${inp('rf.txDbm', T('Ισχύς πομπού (dBm)', 'TX power (dBm)'))}${inp('rf.txGain', T('Κεραία πομπού (dBi)', 'TX antenna (dBi)'))}${inp('rf.txCable', T('Απώλειες καλωδίου πομπού (dB)', 'TX cable loss (dB)'))}${inp('rf.rxGain', T('Κεραία δέκτη (dBi)', 'RX antenna (dBi)'))}${inp('rf.rxCable', T('Απώλειες καλωδίου δέκτη (dB)', 'RX cable loss (dB)'))}${inp('rf.extraLoss', T('Τοίχοι / εμπόδια (dB)', 'Walls / obstacles (dB)'))}${inp('rf.rxSens', T('Ευαισθησία δέκτη (dBm)', 'RX sensitivity (dBm)'))}</div>`;
  function rfOut() {
    const r = S.rf, lb = linkBudget(r), fz = fresnel(num(r.distM), num(r.fMHz));
    const q = lb.rssi >= -60 ? [T('πολύ καλό', 'very good'), 'var(--green,#3fb950)'] : lb.rssi >= -70 ? [T('καλό', 'good'), 'var(--green,#3fb950)'] : lb.rssi >= -80 ? [T('οριακό', 'marginal'), 'var(--orange)'] : [T('αδύναμο', 'weak'), 'var(--red)'];
    return `<div class="cc-res">${kpi(F(dbmToMw(num(r.dbm)), 3) + ' mW', E(r.dbm) + ' dBm =', 'var(--dim)')}${kpi(F(mwToDbm(num(r.mw)), 2) + ' dBm', E(r.mw) + ' mW =', 'var(--dim)')}
      ${kpi(F(lb.fspl, 1) + ' dB', T('απώλεια ελεύθερου χώρου (FSPL)', 'free-space path loss (FSPL)'))}${kpi(F(lb.eirp, 1) + ' dBm', 'EIRP', 'var(--dim)')}
      ${kpi(F(lb.rssi, 1) + ' dBm', T('αναμενόμενο σήμα (RSSI) · ', 'expected signal (RSSI) · ') + q[0], q[1])}
      ${lb.margin == null ? '' : kpi(F(lb.margin, 1) + ' dB', T('περιθώριο (fade margin)', 'fade margin'), lb.margin >= 15 ? 'var(--green,#3fb950)' : lb.margin >= 8 ? 'var(--orange)' : 'var(--red)')}
      ${kpi(F(fz, 2) + ' m', T('ακτίνα 1ης ζώνης Fresnel (στη μέση)', '1st Fresnel zone radius (midpoint)'))}${kpi(F(fz * 0.6, 2) + ' m', T('ελάχιστο καθαρό (60%)', 'minimum clearance (60%)'), 'var(--dim)')}</div>
      ${isFinite(lb.eirp) && lb.eirp > (num(r.fMHz) < 3000 ? 20 : 30) ? warn('⚠ ' + T(`EIRP ${F(lb.eirp, 1)} dBm: πάνω από το συνηθισμένο όριο στην ΕΕ (20 dBm στα 2,4 GHz · 23–30 dBm στα 5 GHz ανάλογα με τη ζώνη). Χαμήλωσε την ισχύ όταν βάζεις κεραία με κέρδος.`, `EIRP ${F(lb.eirp, 1)} dBm: above the usual EU limit (20 dBm at 2.4 GHz · 23–30 dBm at 5 GHz depending on the band). Lower TX power when you fit a gain antenna.`)) : ''}
      <div class="cc-exp">${T('<b>dBm ↔ mW:</b> <code>mW = 10^(dBm/10)</code> — κάθε +3 dB διπλασιάζει την ισχύ, κάθε +10 dB τη δεκαπλασιάζει (0 dBm = 1 mW, 20 dBm = 100 mW). <b>FSPL</b> = <code>20·log₁₀(km) + 20·log₁₀(MHz) + 32,44</code>: διπλάσια απόσταση ή διπλάσια συχνότητα = −6 dB. <b>RSSI</b> = ισχύς + κεραίες − καλώδια − FSPL − εμπόδια. Για σταθερό Wi‑Fi θέλεις καλύτερα από −67 dBm· για ζεύξη σημείο-προς-σημείο περιθώριο ≥ 15 dB. Τυπικά εμπόδια: γυψοσανίδα 3 dB · τούβλο 6–8 dB · μπετόν 10–15 dB. <b>Fresnel:</b> η ζεύξη θέλει «καθαρό» όχι μόνο την ευθεία αλλά και έναν όγκο γύρω της — κράτα ελεύθερο τουλάχιστον το 60% της ακτίνας (δέντρα, στέγες, έδαφος).',
        '<b>dBm ↔ mW:</b> <code>mW = 10^(dBm/10)</code> — every +3 dB doubles the power, every +10 dB multiplies it by ten (0 dBm = 1 mW, 20 dBm = 100 mW). <b>FSPL</b> = <code>20·log₁₀(km) + 20·log₁₀(MHz) + 32.44</code>: double the distance or the frequency = −6 dB. <b>RSSI</b> = power + antennas − cables − FSPL − obstacles. For solid Wi‑Fi aim better than −67 dBm; for a point-to-point link keep ≥ 15 dB margin. Typical obstacles: drywall 3 dB · brick 6–8 dB · concrete 10–15 dB. <b>Fresnel:</b> a link needs not just the straight line clear but a volume around it — keep at least 60% of the radius free (trees, roofs, ground).')}</div>`;
  }

  // ── Πτώση τάσης ──
  const AWGS = [10, 12, 14, 16, 18, 20, 22, 23, 24, 26];
  const MM2 = [0.22, 0.5, 0.75, 1, 1.5, 2.5, 4, 6, 10];
  function vdForm() {
    const u = S.vd.unit === 'mm2';
    return `<div class="cc-grid">${sel('vd.v', T('Τάση τροφοδοτικού', 'Supply voltage'), [[12, '12 V'], [24, '24 V'], [48, '48 V'], [5, '5 V']])}${inp('vd.i', T('Ρεύμα (A)', 'Current (A)'))}${inp('vd.lenM', T('Μήκος καλωδίου (m, μία διαδρομή)', 'Cable length (m, one way)'))}
      ${sel('vd.unit', T('Διατομή σε', 'Conductor size in'), [['awg', 'AWG'], ['mm2', 'mm²']])}
      ${u ? sel('vd.mm2', 'mm²', MM2.map(x => [x, x + ' mm²'])) : sel('vd.awg', 'AWG', AWGS.map(x => [x, `${x} AWG (${round(awgArea(x), 2)} mm²)`]))}
      <div><label>${T('Υλικό', 'Material')}</label><select data-k="vd.cca"><option value=""${S.vd.cca ? '' : ' selected'}>${T('χαλκός', 'copper')}</option><option value="1"${S.vd.cca ? ' selected' : ''}>CCA</option></select></div></div>`;
  }
  function vdOut() {
    const d = S.vd, r = vdrop({ v: d.v, i: d.i, lenM: d.lenM, awg: d.unit === 'mm2' ? null : d.awg, mm2: d.unit === 'mm2' ? d.mm2 : null, cca: !!d.cca });
    const c = r.pct <= 5 ? 'var(--green,#3fb950)' : r.pct <= 10 ? 'var(--orange)' : 'var(--red)';
    const need = vdropMinMm2(num(d.v), num(d.i), num(d.lenM), 5) * (d.cca ? CCA_FACTOR : 1), nm = MM2.find(x => x >= need);
    return `<div class="cc-res">${kpi(F(r.drop, 2) + ' V', T('πτώση τάσης', 'voltage drop'), c)}${kpi(F(r.pct, 1) + '%', T('της τάσης (στόχος ≤ 5%)', 'of the supply (target ≤ 5%)'), c)}${kpi(F(r.vEnd, 2) + ' V', T('φτάνουν στη συσκευή', 'arrive at the device'))}${kpi(F(r.r, 3) + ' Ω', T('αντίσταση (πήγαινε + έλα)', 'resistance (out + back)'), 'var(--dim)')}${kpi(F(r.lossW, 2) + ' W', T('χάνονται στο καλώδιο', 'lost in the cable'), 'var(--dim)')}</div>
      ${r.pct > 5 ? warn((r.pct > 10 ? '🚨 ' : '⚠ ') + T(`Πτώση ${F(r.pct, 1)}%: η συσκευή μπορεί να κάνει επανεκκινήσεις (ειδικά κάμερες τη νύχτα με IR). Για ≤ 5% θέλεις τουλάχιστον <b>${F(need, 2)} mm²</b>${nm ? ` (τυποποιημένο: ${nm} mm²)` : ''}, ή πήγαινε σε 24/48 V ή PoE.`, `Drop of ${F(r.pct, 1)}%: the device may reboot (especially cameras at night with IR). For ≤ 5% you need at least <b>${F(need, 2)} mm²</b>${nm ? ` (standard size: ${nm} mm²)` : ''}, or move to 24/48 V or PoE.`), r.pct > 10 ? 'var(--red)' : 'var(--orange)') : ''}
      <div class="cc-exp">${T('<b>Πώς υπολογίζεται:</b> <code>ΔV = I × R</code> με <code>R = 2 × μήκος × Ω/m</code> (το ρεύμα πάει ΚΑΙ γυρίζει). Χαλκός στους 20 °C: <code>Ω/m = 0,017241 ÷ mm²</code>. Η ίδια ισχύς σε διπλάσια τάση θέλει το μισό ρεύμα → το ¼ της ποσοστιαίας πτώσης: γι’ αυτό οι μεγάλες αποστάσεις γίνονται με 24/48 V ή PoE και όχι με 12 V. Το καλώδιο συναγερμού/UTP είναι λεπτό (0,22 mm² / 24 AWG) — για τροφοδοσία κάμερας 12 V πάνω από ~15 m δεν φτάνει.',
        '<b>How it is computed:</b> <code>ΔV = I × R</code> with <code>R = 2 × length × Ω/m</code> (current goes out AND comes back). Copper at 20 °C: <code>Ω/m = 0.017241 ÷ mm²</code>. The same power at twice the voltage draws half the current → ¼ of the percentage drop: this is why long runs use 24/48 V or PoE rather than 12 V. Alarm/UTP cable is thin (0.22 mm² / 24 AWG) — for powering a 12 V camera beyond ~15 m it is not enough.')}</div>`;
  }

  const FORM = { poe: poeForm, cam: camForm, ups: upsForm, rf: rfForm, vd: vdForm }, OUT = { poe: poeOut, cam: camOut, ups: upsOut, rf: rfOut, vd: vdOut };
  const TITLE = { poe: ['Φτάνει το PoE του switch;', 'Is the switch’s PoE enough?'], cam: ['Πόσο δίσκο και πόσο δίκτυο θέλουν οι κάμερες;', 'How much disk and network do the cameras need?'], ups: ['Πόση ώρα κρατάει το UPS;', 'How long does the UPS last?'], rf: ['Γρήγορα μαθηματικά ασύρματης ζεύξης', 'Quick wireless link maths'], vd: ['Πόση τάση χάνεται στο καλώδιο (DC);', 'How much voltage is lost in the cable (DC)?'] };

  function out() { const o = document.getElementById('cc-out'); if (o) { try { o.innerHTML = OUT[S.tab](); } catch (e) { o.innerHTML = warn('⚠ ' + E(e.message)); } } }
  function draw() {
    const b = box(); if (!b) return;
    b.setAttribute('data-noi18n', '');
    if (!FORM[S.tab]) S.tab = 'poe';
    b.innerHTML = `<div class="cc-tabs">${TABS.map(t => `<button class="b${S.tab === t[0] ? ' on' : ''}" data-cc="tab" data-t="${t[0]}">${T(t[1], t[2])}</button>`).join('')}</div>
      <div class="card"><div style="display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap"><b style="font-size:15px">${T(...TITLE[S.tab])}</b><button class="b" data-cc="reset">↺ ${T('Αρχικές τιμές', 'Reset')}</button></div>
      ${FORM[S.tab]()}</div><div class="card"><b>${T('Αποτέλεσμα', 'Result')}</b><div id="cc-out"></div></div>
      <div class="dim" style="font-size:12px;margin-top:6px">🔒 ${T('Όλοι οι υπολογισμοί γίνονται στον browser σου. Είναι βοήθημα μελέτης — δεν αντικαθιστούν τα φυλλάδια των κατασκευαστών.', 'All calculations run in your browser. They are a planning aid — they do not replace vendor datasheets.')}</div>`;
    out();
  }
  function change(el) {
    if (el.dataset.row != null) {
      const r = S.poe.rows[+el.dataset.row]; if (!r) return;
      r[el.dataset.rk] = el.value;
      if (el.dataset.rk === 'dev') { const d = POE_DEVICES.find(x => x.id === el.value); if (d) r.w = d.w; save(); draw(); return; }
    } else if (el.dataset.k) {
      const [a, k] = el.dataset.k.split('.');
      S[a][k] = el.type === 'checkbox' ? el.checked : (k === 'cca' ? !!el.value : el.value);
      if (el.tagName === 'SELECT' && (k === 'mode' || k === 'unit')) { save(); draw(); return; }   // αλλάζουν τα πεδία της φόρμας
    } else return;
    save(); out();
  }
  document.addEventListener('input', e => { const el = e.target.closest && e.target.closest('#t-calc [data-k],#t-calc [data-row]'); if (el && el.tagName !== 'SELECT') change(el); });
  document.addEventListener('change', e => { const el = e.target.closest && e.target.closest('#t-calc select'); if (el) change(el); });
  document.addEventListener('click', e => {
    const b = e.target.closest('#t-calc [data-cc]'); if (!b) return;
    const a = b.dataset.cc;
    if (a === 'tab') S.tab = b.dataset.t;
    else if (a === 'addrow') { if (S.poe.rows.length < 24) S.poe.rows.push({ dev: 'cam', w: 6, qty: 1, len: 50 }); }
    else if (a === 'delrow') { S.poe.rows.splice(+b.dataset.i, 1); if (!S.poe.rows.length) S.poe.rows.push({ dev: 'cam', w: 6, qty: 1, len: 50 }); }
    else if (a === 'reset') S[S.tab] = JSON.parse(JSON.stringify(DEF[S.tab]));
    save(); draw();
  });
  window.renderCalc = () => draw();
})();
