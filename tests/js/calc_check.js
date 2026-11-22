// Έλεγχος των υπολογιστών τεχνικού (calcui.js → NWCalc) με τιμές υπολογισμένες στο χέρι / από τα πρότυπα.
const C = require('../../calcui.js'); const bad = []; let n = 0;
const eq = (a, b, m) => { n++; if (JSON.stringify(a) !== JSON.stringify(b)) bad.push(`${m}: ${JSON.stringify(a)} ≠ ${JSON.stringify(b)}`); };
const near = (a, b, tol, m) => { n++; if (!(Math.abs(a - b) <= tol)) bad.push(`${m}: ${a} ≉ ${b} (±${tol})`); };

// ── όρια προτύπων PoE (IEEE 802.3af/at/bt) ──
const std = id => C.POE_STD.find(s => s.id === id);
eq([std('af').pse, std('af').pd], [15.4, 12.95], '802.3af');
eq([std('at').pse, std('at').pd], [30, 25.5], '802.3at');
eq([std('bt3').pse, std('bt3').pd], [60, 51], '802.3bt type 3');
eq([std('bt4').pse, std('bt4').pseMax, std('bt4').pd], [90, 100, 71.3], '802.3bt type 4');
eq([std('af').pairs, std('at').pairs, std('bt3').pairs, std('bt4').pairs], [2, 2, 4, 4], 'pairs');
eq([6, 12.95, 13, 25.5, 26, 51, 60, 71.3, 72].map(w => (C.poeClassFor(w) || { id: null }).id), ['af', 'af', 'at', 'at', 'bt3', 'bt3', 'bt4', 'bt4', null], 'class for W');

// ── I²R στο χέρι: 802.3at στο χειρότερο κανάλι (50 V, 12,5 Ω): I = (50 − √(2500 − 1275)) / 25 = 0,6 A → 0,36·12,5 = 4,5 W ──
let l = C.poeLine(25.5, 50, 12.5);
near(l.i, 0.6, 1e-9, 'at current'); near(l.loss, 4.5, 1e-9, 'at I²R loss'); near(l.pse, 30, 1e-9, 'at PSE power'); near(l.vPd, 42.5, 1e-9, 'at V at PD');
// 802.3af (44 V, 20 Ω): I = (44 − √(1936 − 1036)) / 40 = 0,35 A → 0,1225·20 = 2,45 W → 12,95 + 2,45 = 15,4 W
l = C.poeLine(12.95, 44, 20);
near(l.i, 0.35, 1e-9, 'af current'); near(l.loss, 2.45, 1e-9, 'af loss'); near(l.pse, 15.4, 1e-9, 'af PSE'); near(l.vPd, 37, 1e-9, 'af V at PD');
eq(C.poeLine(90, 50, 12.5).ok, false, 'cable cannot carry');
eq([C.poeLine(0, 50, 10).pse, C.poeLine(10, 50, 0).loss], [0, 0], 'zero cases');

// ── αντίσταση αγωγών ──
near(C.awgDiameter(24), 0.5106, 0.0005, 'AWG24 diameter mm'); near(C.awgArea(24), 0.2047, 0.0005, 'AWG24 area mm²');
near(C.awgOhmPerM(24) * 1000, 84.22, 0.15, 'AWG24 Ω/km'); near(C.awgOhmPerM(18) * 1000, 20.95, 0.05, 'AWG18 Ω/km'); near(C.awgOhmPerM(23) * 1000, 66.8, 0.15, 'AWG23 Ω/km');
near(C.mm2OhmPerM(1.5), 0.017241 / 1.5, 1e-12, 'mm² Ω/m'); near(C.awgOhmPerM(24, true) / C.awgOhmPerM(24), 1.55, 1e-9, 'CCA factor');
near(C.poeLoopOhm(100, 24, 2), 8.42, 0.02, 'loop 2-pair 100 m Cat5e'); near(C.poeLoopOhm(100, 24, 4), 4.21, 0.01, 'loop 4-pair');

// ── PoE budget: 2 × 25,5 W στα 100 m Cat5e, θύρες at ──
let b = C.poeBudget({ std: 'at', cable: 'cat5e', rows: [{ w: 25.5, qty: 2, len: 100 }] });
near(b.totalPd, 51, 1e-9, 'budget PD'); near(b.rows[0].i, 0.5635, 0.001, 'budget current'); near(b.totalPse, 56.35, 0.05, 'budget PSE'); near(b.loss, 5.35, 0.05, 'budget loss');
eq([b.suggest, b.headroom, b.rows[0].warn, b.ports], [124, null, [], 2], 'budget suggest');
b = C.poeBudget({ std: 'at', cable: 'cat5e', budgetW: 65, rows: [{ w: 25.5, qty: 2, len: 100 }] });
near(b.headroom, (65 - b.totalPse) / 65 * 100, 1e-9, 'headroom %'); eq(b.headroomOk, false, 'headroom < 20%');
eq(C.poeBudget({ std: 'at', cable: 'cat5e', budgetW: 124, rows: [{ w: 25.5, qty: 2, len: 100 }] }).headroomOk, true, 'headroom ok');
b = C.poeBudget({ std: 'at', cable: 'cat5e', rows: [{ w: 40, qty: 1, len: 30 }, { w: 6, qty: 4, len: 120 }] });
eq([b.rows[0].warn.includes('over_std'), b.rows[0].need, b.rows[1].warn, b.warn], [true, 'bt3', ['too_long'], true], 'warnings');
eq(C.poeBudget({ std: 'bt4', cable: 'cat6', rows: [{ w: 95, qty: 1, len: 10 }] }).rows[0].warn.includes('over_bt'), true, 'over bt');
eq(C.poeBudget({ std: 'af', cable: 'slim', rows: [{ w: 12.95, qty: 1, len: 100 }] }).rows[0].warn.includes('vdrop'), true, 'voltage drop on 28 AWG');
eq(C.poeBudget({ std: 'at', cable: 'cat5e', rows: [] }).suggest, null, 'empty');

// ── κάμερες ──
eq(C.camBitrate({ res: '2mp', fps: 25, codec: 'h264', activity: 'medium' }), 4096, 'bitrate base');
eq(C.camBitrate({ res: '2mp', fps: 15, codec: 'h264', activity: 'medium' }), 3113, 'bitrate 15 fps (4096 × 0,76)');
eq(C.camBitrate({ res: '4mp', fps: 25, codec: 'h265', activity: 'high' }), 4301, 'bitrate h265 high (6144 × 0,5 × 1,4)');
eq(C.camBitrate({ res: '2mp', fps: 12.5, codec: 'mjpeg', activity: 'medium' }), 12288, 'bitrate mjpeg linear fps');
eq(C.camBitrate({ res: '8mp', fps: 25, codec: 'h265+', activity: 'low' }), Math.round(12288 * 0.3 * 0.7), 'bitrate h265+ low');
// 4096 kbps = 512.000 bytes/s × 86.400 s = 44,2368 GB/ημέρα · × 8 κάμερες × 30 ημέρες = 10.616,832 GB = 10,616832 TB
let s = C.camStorage({ cams: 8, kbps: 4096, days: 30, mode: 'cont' });
near(s.gbDay, 353.8944, 1e-6, 'GB/day'); near(s.tb, 10.616832, 1e-9, 'TB 30 days'); near(s.mbps, 32.768, 1e-9, 'Mbps'); near(s.tbWithHeadroom, 12.7401984, 1e-9, '+20%');
near(s.tib, 10.616832e12 / 2 ** 40, 1e-9, 'TiB');
near(C.camStorage({ cams: 8, kbps: 4096, days: 30, mode: 'motion', motionPct: 25 }).tb, 10.616832 / 4, 1e-9, 'motion 25%');
near(C.retentionDays(24, 353.8944), 67.817, 0.001, 'retention days');
eq(C.retentionDays(8, 0), Infinity, 'retention no data');

// ── RAID ──
eq([C.raidUsable('raid1', 2, 8), C.raidUsable('raid5', 4, 8), C.raidUsable('raid6', 6, 10), C.raidUsable('raid10', 4, 4), C.raidUsable('single', 1, 6), C.raidUsable('raid0', 2, 4)], [8, 24, 40, 8, 6, 8], 'raid usable');
eq([C.raidUsable('raid5', 2, 8), C.raidUsable('raid6', 3, 8), C.raidUsable('raid1', 1, 8), C.raidUsable('raid10', 5, 4)], [0, 0, 0, 8], 'raid minimums');
let r = C.recommendDisks(12.74, 'raid5', 4); eq([r.n, r.size, r.usable, r.raw], [3, 8, 16, 24], 'recommend raid5');
r = C.recommendDisks(10, 'raid1'); eq([r.n, r.size], [2, 10], 'recommend raid1');
r = C.recommendDisks(30, 'raid6', 8); eq(r.usable >= 30 && r.n >= 4, true, 'recommend raid6');
eq(C.recommendDisks(100, 'raid1'), null, 'raid1 too big'); eq(C.recommendDisks(500, 'raid5', 4), null, 'does not fit');

// ── UPS: 12 V × 100 Ah × 0,5 × 0,9 = 540 Wh ÷ 270 W = 2 h ──
let u = C.upsRuntime({ loadW: 270, v: 12, ah: 100, count: 1, eff: 0.9, dod: 0.5 });
near(u.minutes, 120, 1e-9, 'ups minutes'); near(u.wh, 1200, 1e-9, 'ups Wh'); near(u.usableWh, 540, 1e-9, 'ups usable');
near(C.upsRuntime({ loadW: 120, v: 12, ah: 9, count: 2, eff: 0.85, dod: 0.8 }).minutes, 216 * 0.68 / 120 * 60, 1e-9, 'ups 2×9Ah');
eq(C.upsRuntime({ loadW: 0, v: 12, ah: 7 }).minutes, Infinity, 'ups no load');

// ── RF ──
near(C.dbmToMw(0), 1, 1e-12, '0 dBm'); near(C.dbmToMw(20), 100, 1e-9, '20 dBm'); near(C.dbmToMw(30), 1000, 1e-9, '30 dBm'); near(C.dbmToMw(23), 199.526, 0.001, '23 dBm'); near(C.dbmToMw(-10), 0.1, 1e-12, '-10 dBm');
near(C.mwToDbm(1), 0, 1e-12, '1 mW'); near(C.mwToDbm(100), 20, 1e-12, '100 mW'); near(C.mwToDbm(50), 16.99, 0.005, '50 mW'); eq(C.mwToDbm(0), -Infinity, '0 mW');
near(C.fspl(100, 2412), 80.1, 0.1, 'FSPL 2.4 GHz ch1 100 m'); near(C.fspl(100, 2437), 80.1, 0.1, 'FSPL 2.4 GHz ch6 100 m'); near(C.fspl(100, 2437), 80.18, 0.01, 'FSPL exact');
near(C.fspl(1000, 5800), 107.71, 0.01, 'FSPL 5.8 GHz 1 km'); near(C.fspl(200, 2437) - C.fspl(100, 2437), 6.02, 0.01, 'double distance = +6 dB');
eq(Number.isNaN(C.fspl(0, 2400)), true, 'FSPL zero distance');
let lb = C.linkBudget({ distM: 100, fMHz: 2437, txDbm: 20, txGain: 3, txCable: 0, rxGain: 3, rxCable: 0, extraLoss: 0, rxSens: -75 });
near(lb.eirp, 23, 1e-9, 'EIRP'); near(lb.rssi, 26 - 80.18, 0.01, 'RSSI'); near(lb.margin, 75 + 26 - 80.18, 0.01, 'margin');
eq(C.linkBudget({ distM: 100, fMHz: 2437, txDbm: 20, rxSens: '' }).margin, null, 'no sensitivity');
near(C.fresnel(1000, 5800), 3.595, 0.002, 'Fresnel 1 km 5.8 GHz'); near(C.fresnel(1000, 2400), 5.588, 0.003, 'Fresnel 1 km 2.4 GHz'); near(C.fresnel(1000, 5800, 0), 0, 1e-12, 'Fresnel at the end');

// ── πτώση τάσης DC: 20 m AWG18, 2 A → R = 2·20·0,020945 = 0,8378 Ω → 1,676 V = 13,96% στα 12 V ──
let v = C.vdrop({ v: 12, i: 2, lenM: 20, awg: 18 });
near(v.r, 0.8378, 0.002, 'vdrop R'); near(v.drop, 1.6756, 0.004, 'vdrop V'); near(v.pct, 13.96, 0.04, 'vdrop %'); near(v.vEnd, 12 - v.drop, 1e-12, 'vdrop end V');
v = C.vdrop({ v: 12, i: 2, lenM: 20, mm2: 1.5 });
near(v.r, 0.45976, 1e-5, 'vdrop mm² R'); near(v.pct, 7.6627, 0.001, 'vdrop mm² %');
near(C.vdrop({ v: 48, i: 0.5, lenM: 20, mm2: 1.5 }).pct, 7.6627 / 16, 0.001, '4× voltage, ¼ current → 1/16 %');
near(C.vdropMinMm2(12, 2, 20, 5), 2 * 20 * 2 * 0.017241 / 0.6, 1e-9, 'min mm² for 5%');
eq([C.round(1.005, 2), C.round(2.5, 0), C.num('3,5'), C.num('x', 7)], [1.01, 3, 3.5, 7], 'helpers');

if (bad.length) { console.error(bad.join('\n')); console.error(`${bad.length}/${n} απέτυχαν`); process.exit(1); }
console.log(`OK ${n}`);
