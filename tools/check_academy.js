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

const errs = [], ids = new Set(), TABS = new Set(['home', 'alerts', 'wifi', 'priv', 'audit', 'honey', 'block', 'iot', 'sensor', 'mqtt', 'devs', 'hosts', 'apps', 'stats', 'feed', 'det', 'hist', 'academy', 'learn', 'tips', 'quiz', 'pentest', 'rules', 'ctf']);
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
console.log(`${Object.keys(tracks).length} διαδρομές · ${lessons} μαθήματα · ${quizzes} κουίζ · ${labs} labs · ${Object.keys(scenes).length} animations · ${cards} κάρτες`);
if (errs.length) { console.error(errs.join('\n')); process.exit(1); }
console.log('✔ όλα εντάξει');
