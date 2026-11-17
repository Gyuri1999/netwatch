// Ελέγχει ότι τα μαθήματα της Ακαδημίας φορτώνουν και είναι συνεπή (τρέχει και στο CI).
//   node tools/check_academy.js
const fs = require('fs'), path = require('path'), vm = require('vm');
const dir = path.join(__dirname, '..', 'academy');
const tracks = {}, scenes = {}, decks = [];
const ACADEMY = {
  track: t => { const o = tracks[t.id]; if (o) o.modules.push(...t.modules); else tracks[t.id] = { ...t, modules: [...t.modules] }; },
  scene: (id, sc) => { scenes[id] = sc; },
  deck: d => decks.push(d),
};
const ctx = vm.createContext({ ACADEMY, window: { ACADEMY }, console });
for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.js') && f !== 'engine.js').sort())
  vm.runInContext(fs.readFileSync(path.join(dir, f), 'utf8'), ctx, { filename: f });
new vm.Script(fs.readFileSync(path.join(dir, 'engine.js'), 'utf8'), { filename: 'engine.js' });  // μόνο σύνταξη

const errs = [], ids = new Set(), TABS = new Set(['home', 'alerts', 'wifi', 'priv', 'audit', 'honey', 'block', 'iot', 'sensor', 'mqtt', 'pb', 'health', 'devs', 'hosts', 'apps', 'stats', 'feed', 'det', 'hist', 'academy', 'learn', 'tips', 'quiz', 'pentest', 'rules', 'ctf']);
let lessons = 0, quizzes = 0, labs = 0;
for (const t of Object.values(tracks)) for (const m of t.modules) for (const l of m.lessons) {
  lessons++;
  if (ids.has(l.id)) errs.push(`διπλό id μαθήματος: ${l.id}`); ids.add(l.id);
  l.blocks.forEach((b, n) => {
    const at = `${l.id}#${n}`;
    if (b.t === 'quiz') { quizzes++; if (!(b.ok >= 0 && b.ok < b.opts.length)) errs.push(`${at}: λάθος ok`); }
    if (b.t === 'anim' && typeof b.scene === 'string' && !scenes[b.scene]) errs.push(`${at}: λείπει το scene ${b.scene}`);
    if (b.t === 'netwatch' && !TABS.has(b.tab)) errs.push(`${at}: άγνωστη καρτέλα ${b.tab}`);
    if (b.t === 'cli') { labs++; b.steps.forEach((s, k) => { try { if (!new RegExp(s.expect, 'i').test(s.ans || '')) errs.push(`${at} βήμα ${k + 1}: το ans δεν ταιριάζει στο expect`); } catch (e) { errs.push(`${at}: κακό regex ${s.expect}`); } }); }
  });
}
for (const [id, sc] of Object.entries(scenes)) {
  const nodes = new Set((sc.nodes || []).map(n => n.id));
  (sc.steps || []).forEach((s, k) => [s.from, ...(s.via || []), ...[].concat(s.to || [])].filter(Boolean).forEach(x => { if (!nodes.has(x)) errs.push(`scene ${id} βήμα ${k + 1}: άγνωστος κόμβος ${x}`); }));
}
let cards = 0;
for (const d of decks) { const seen = new Set(); for (const c of d.cards) { cards++; if (seen.has(c.id)) errs.push(`κάρτα διπλή: ${c.id}`); seen.add(c.id); if (c.lesson && !ids.has(c.lesson)) errs.push(`κάρτα ${c.id}: άγνωστο μάθημα ${c.lesson}`); } }
// Αγγλική έκδοση (academy/en/): ίδια δομή με την ελληνική — ίδια id, ίδια σειρά blocks, ίδιες σωστές απαντήσεις
const enDir = path.join(dir, 'en');
const enFiles = fs.existsSync(enDir) ? fs.readdirSync(enDir).filter(f => f.endsWith('.js')).sort() : [];
let enLessons = 0, enCards = 0;
if (enFiles.length) {
  const T = {}, S = {}, D = [];
  const EA = { track: t => { const o = T[t.id]; if (o) o.modules.push(...t.modules); else T[t.id] = { ...t, modules: [...t.modules] }; }, scene: (id, sc) => { S[id] = sc; }, deck: d => D.push(d) };
  const c2 = vm.createContext({ ACADEMY: EA, window: { ACADEMY: EA }, console });
  for (const f of enFiles) { try { vm.runInContext(fs.readFileSync(path.join(enDir, f), 'utf8'), c2, { filename: 'en/' + f }); } catch (e) { errs.push(`en/${f}: ${e.message}`); } }
  const elL = {}; for (const t of Object.values(tracks)) for (const m of t.modules) for (const l of m.lessons) elL[l.id] = l;
  const enL = {}; for (const t of Object.values(T)) for (const m of t.modules) for (const l of m.lessons) enL[l.id] = l;
  const full = new Set(Object.values(T).map(t => t.id));
  for (const [id, l] of Object.entries(enL)) {
    enLessons++;
    const g = elL[id]; if (!g) { errs.push(`en: άγνωστο μάθημα ${id}`); continue; }
    if (g.blocks.length !== l.blocks.length) { errs.push(`en ${id}: ${l.blocks.length} blocks αντί για ${g.blocks.length}`); continue; }
    l.blocks.forEach((b, i) => {
      const gb = g.blocks[i], at = `en ${id} block ${i}`;
      if (b.t !== gb.t) return errs.push(`${at}: τύπος ${b.t} αντί για ${gb.t}`);
      if (b.t === 'quiz' && (b.ok !== gb.ok || b.opts.length !== gb.opts.length)) errs.push(`${at}: άλλη σωστή απάντηση/πλήθος επιλογών`);
      if (b.t === 'anim' && typeof b.scene === 'string' && !S[b.scene]) errs.push(`${at}: λείπει το scene ${b.scene}`);
      if (b.t === 'netwatch' && b.tab !== gb.tab) errs.push(`${at}: άλλη καρτέλα`);
      if (b.t === 'cli') {
        if (b.steps.length !== gb.steps.length) errs.push(`${at}: άλλο πλήθος βημάτων`);
        b.steps.forEach((st, k) => { try { if (!new RegExp(st.expect, 'i').test(st.ans || '')) errs.push(`${at} βήμα ${k + 1}: το ans δεν ταιριάζει στο expect`); } catch (e) { errs.push(`${at}: κακό regex`); } });
      }
    });
  }
  // ένα track που μεταφράστηκε πρέπει να είναι πλήρες (αλλιώς ο αγγλόφωνος θα έβλεπε μισή διαδρομή)
  for (const tid of full) for (const m of tracks[tid] ? tracks[tid].modules : []) for (const l of m.lessons) if (!enL[l.id]) errs.push(`en: λείπει το μάθημα ${l.id} (${tid})`);
  for (const d of D) for (const c of d.cards) { enCards++; const g = decks.flatMap(x => x.cards).find(x => x.id === c.id); if (!g) errs.push(`en: άγνωστη κάρτα ${c.id}`); else if (g.d !== c.d) errs.push(`en κάρτα ${c.id}: άλλος τομέας`); }
  if (D.length) for (const g of decks.flatMap(x => x.cards)) if (!D.flatMap(x => x.cards).some(c => c.id === g.id)) errs.push(`en: λείπει η κάρτα ${g.id}`);
}
// PWA (academy.html στο κινητό): manifest έγκυρο, εικονίδια και αρχεία του service worker υπάρχουν
const root = path.join(__dirname, '..');
try {
  const man = JSON.parse(fs.readFileSync(path.join(root, 'manifest.webmanifest'), 'utf8'));
  for (const ic of man.icons || []) if (!fs.existsSync(path.join(root, ic.src))) errs.push(`manifest: λείπει ${ic.src}`);
  if (!fs.existsSync(path.join(root, man.start_url.split('?')[0]))) errs.push(`manifest: λείπει ${man.start_url}`);
  const sw = fs.readFileSync(path.join(root, 'sw.js'), 'utf8'); new vm.Script(sw, { filename: 'sw.js' });
  const core = JSON.parse(sw.match(/const CORE = (\[[^\]]*\])/)[1].replace(/'/g, '"'));
  for (const f of core) if (f !== 'academy/files.json' && !fs.existsSync(path.join(root, f))) errs.push(`sw.js: λείπει ${f}`);
} catch (e) { errs.push('PWA: ' + e.message); }
if (enFiles.length) console.log(`en: ${enLessons} μαθήματα · ${enCards} κάρτες`);
console.log(`${Object.keys(tracks).length} διαδρομές · ${lessons} μαθήματα · ${quizzes} κουίζ · ${labs} labs · ${Object.keys(scenes).length} animations · ${cards} κάρτες`);
if (errs.length) { console.error(errs.join('\n')); process.exit(1); }
console.log('✔ όλα εντάξει');
