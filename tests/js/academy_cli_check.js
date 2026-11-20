// Ελέγχει τον προσομοιωτή IOS των μαθημάτων: κάθε βήμα κάθε lab δέχεται τη σωστή απάντηση και τις συνηθισμένες γραφές της.
const fs = require('fs'), vm = require('vm'), path = require('path');
const R = path.join(__dirname, '..', '..', 'academy');
const el = () => ({ appendChild() {}, style: {}, set textContent(v) {} });
const ctx = { window: {}, document: { getElementById: () => null, createElement: el, head: el(), addEventListener() {}, readyState: 'complete' }, console, setTimeout, localStorage: { getItem: () => null, setItem() {} } };
ctx.window = ctx; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(R, 'engine.js'), 'utf8'), ctx);
for (const f of fs.readdirSync(R).filter(f => /^(ccna|iot)-.*\.js$/.test(f))) vm.runInContext(fs.readFileSync(path.join(R, f), 'utf8'), ctx);
for (const f of fs.readdirSync(path.join(R, 'en')).filter(f => /^(ccna|iot)-.*\.js$/.test(f))) vm.runInContext(fs.readFileSync(path.join(R, 'en', f), 'utf8'), ctx);
const A = ctx.ACADEMY, IOS = A.IOS; let n = 0, bad = [];
const abbr = s => s.replace(/^$/, '').replace(/^show /, 'sh ').replace(/interfaces? /, 'int ').replace(/fastethernet ?/i, 'fa').replace(/gigabitethernet ?/i, 'gi').replace(/configure terminal/, 'conf t');
const full = (s, m) => IOS.expand(s, m).text;
for (const t of A.tracks) for (const mo of t.modules) for (const l of mo.lessons) for (const b of l.blocks.filter(b => b.t === 'cli')) {
  let pr = b.prompt || 'Router>';
  for (const st of b.steps) {
    const m = IOS.modeOf(pr), re = new RegExp(st.expect, 'i'), ans = st.ans || '';
    const ok = v => { const ex = IOS.expand(v, m), c = [v, ex.text]; if (ex.toks[0] === 'do') c.push(v.replace(/^\s*do?\s+/i, ''), ex.toks.slice(1).join(' ')); return c.some(x => re.test(x)); };
    for (const v of m === 'sh' ? [ans] : [ans, full(ans, m), abbr(ans), abbr(full(ans, m))]) { n++; if (v && !ok(v)) bad.push(`${l.id} [${pr}] «${v}» ✗ /${st.expect}/`); }
    const ex = IOS.expand(ans, m); if (ans && (ex.bad >= 0 || ex.amb >= 0)) bad.push(`${l.id} [${pr}] «${ans}» άγνωστη/διφορούμενη λέξη #${Math.max(ex.bad, ex.amb)} (${ex.raw[Math.max(ex.bad, ex.amb)]})`);
    if (st.next) pr = st.next;
  }
}
// συγκεκριμένα: τα παραδείγματα του χρήστη
const E2 = (v, m) => IOS.expand(v, m).text;
if (IOS.modeOf('pi@raspberrypi:~ $') !== 'sh' || IOS.modeOf('R1(config-if)#') !== 'if') bad.push('modeOf');
const want = [['sh int f0/1', 'priv', 'show interfaces fastethernet0/1'], ['conf t', 'priv', 'configure terminal'], ['int fa0/1', 'cfg', 'interface fastethernet0/1'],
  ['do sh run', 'cfg', 'do show run'], ['sh ip int br', 'priv', 'show ip interface brief'], ['no shut', 'if', 'no shutdown'], ['sw mode acc', 'if', 'switchport mode access']];
for (const [v, m, w] of want) { n++; if (E2(v, m) !== w) bad.push(`expand «${v}» → «${E2(v, m)}» αντί «${w}»`); }
for (const [v, m] of [['show interfaces', 'priv'], ['show running-config', 'priv'], ['show vlan brief', 'priv']]) { n++; const x = IOS.expand(v, m); if (x.bad >= 0 || x.amb >= 0) bad.push('γνωστή εντολή απορρίφθηκε: ' + v); }
for (const [v, m] of [['shw run', 'priv'], ['foo', 'cfg']]) { n++; if (IOS.expand(v, m).bad < 0) bad.push('έπρεπε άκυρη: ' + v); }
console.log(bad.length ? bad.join('\n') : `OK ${n} checks`); process.exit(bad.length ? 1 : 0);
