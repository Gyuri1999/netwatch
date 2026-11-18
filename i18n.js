// NetWatch — γλώσσα διεπαφής (Ελληνικά / English).
//
// Η διεπαφή γράφτηκε στα ελληνικά. Στα αγγλικά τη μεταφράζουμε «πάνω στην οθόνη»: ένας MutationObserver
// βλέπει κάθε κείμενο που εμφανίζεται και το αντικαθιστά από τα λεξικά i18n/*.js:
//   I18N.add({ exact: { "Ελληνικό κείμενο": "English text" },
//              patterns: [["^Βρέθηκαν (\\d+) συσκευές$", "Found $1 devices"]] });
// Τα patterns είναι regex κοινά σε JS και Python (το i18n.py τα χρησιμοποιεί για τις ειδοποιήσεις).
// Δεν μεταφράζονται ποτέ: <code>, <pre>, <textarea>, <input>, <script>, <style> και ό,τι έχει data-noi18n
// (κώδικας, ονόματα συσκευών, περιεχόμενο πακέτων).
// Εργαλείο για μεταφραστές: I18N.dump() → τα ελληνικά κείμενα που εμφανίστηκαν χωρίς μετάφραση.
(function () {
  'use strict';
  const KEY = 'nw-lang', GREEK = /[Ͱ-Ͽἀ-῿]/, PREFIX = /^([^0-9A-Za-zͰ-Ͽἀ-῿«("]+\s)(.+)$/;
  let lang = null;
  try { lang = localStorage.getItem(KEY); } catch (e) { }
  const q = (location.search.match(/[?&]lang=(en|el)\b/) || [])[1];
  if (q) { lang = q; try { localStorage.setItem(KEY, q); } catch (e) { } }
  if (lang !== 'en' && lang !== 'el') lang = /^el\b/i.test(navigator.language || '') ? 'el' : 'en';

  const exact = new Map(), pats = [], missing = new Map();
  const I = window.I18N = { lang, exact, pats, missing };
  I.add = d => {
    for (const [k, v] of Object.entries(d.exact || {})) exact.set(norm(k), v);
    for (const [re, to] of d.patterns || []) { try { pats.push([new RegExp(re), to]); } catch (e) { console.warn('i18n: κακό regex', re); } }
  };
  I.set = l => { try { localStorage.setItem(KEY, l); } catch (e) { } location.reload(); };
  const norm = s => s.replace(/\s+/g, ' ').trim();

  // μετάφραση ενός κειμένου: ολόκληρο → patterns → αλλιώς ίδιο
  I.t = function (s) {
    if (lang !== 'en' || s == null) return s;
    s = String(s);
    if (!GREEK.test(s)) return s;
    const k = norm(s);
    let out = exact.get(k);
    // pattern: και τα κομμάτια που «πιάνει» ($1, $2…) μεταφράζονται αν είναι ελληνικά (π.χ. ονόματα από το demo, λέξεις όπως «ανοιχτό»)
    if (out == null) for (const [re, to] of pats) { const m = k.match(re); if (m) { out = k.replace(re, () => to.replace(/\$(\d)/g, (_, i) => { const g = m[+i]; return g == null ? '' : GREEK.test(g) && g !== k ? I.t(g) : g; })); break; } }
    if (out == null) {
      // «Κείμενο: τιμή» / «τιμή — κείμενο»: δοκίμασε κομμάτια χωρισμένα με σημεία στίξης
      const parts = k.split(/(\s[—–·|]\s|:\s|\s\(|\)\s?)/);
      if (parts.length > 1) {
        let hit = false;
        out = parts.map(p => { if (!GREEK.test(p)) return p; const x = exact.get(norm(p)); if (x != null) { hit = true; return x; } return p; }).join('');
        if (!hit || GREEK.test(out)) out = hit ? out : null;
      }
    }
    if (out == null) {
      // «⚠ Κείμενο», «— κείμενο», «💡 υπόδειξη»: σύμβολο κολλημένο μπροστά σε γνωστό κείμενο
      const m = k.match(PREFIX);
      if (m) { const x = I.t(m[2]); if (x !== m[2] && !GREEK.test(x)) out = m[1] + x.trim(); }
    }
    if (out == null || GREEK.test(out)) { if (k.length < 400) missing.set(k, (missing.get(k) || 0) + 1); if (out == null) return s; }
    const lead = s.match(/^\s*/)[0], tail = s.match(/\s*$/)[0];
    return lead + out + tail;
  };
  I.dump = () => [...missing.entries()].sort((a, b) => b[1] - a[1]).map(x => x[0]);

  if (lang !== 'en') { document.documentElement.lang = 'el'; return; }
  document.documentElement.lang = 'en';

  // λεξικά: φορτώνονται συγχρονισμένα δίπλα σε αυτό το αρχείο, πριν από τον κώδικα της σελίδας
  const me = document.currentScript && document.currentScript.getAttribute('src') || 'i18n.js';
  const base = me.replace(/i18n\.js(\?.*)?$/, '');
  for (const f of ['en-ui', 'en-backend', 'en-academy-ui', 'edu-en']) document.write(`<script src="${base}i18n/${f}.js"><\/script>`);

  const SKIP = new Set(['CODE', 'PRE', 'TEXTAREA', 'INPUT', 'SCRIPT', 'STYLE', 'KBD', 'SAMP']);
  const skip = el => { for (let e = el; e && e.nodeType === 1; e = e.parentNode) { if (SKIP.has(e.tagName) || (e.hasAttribute && e.hasAttribute('data-noi18n'))) return true; } return false; };
  const FORM = new Set(['INPUT', 'TEXTAREA']);  // το περιεχόμενό τους όχι, το placeholder/title ναι
  const ATTRS = ['title', 'placeholder', 'aria-label', 'alt', 'data-tip'];
  function fixEl(el) {
    for (const a of ATTRS) { const v = el.getAttribute && el.getAttribute(a); if (v && GREEK.test(v)) { const t = I.t(v); if (t !== v) el.setAttribute(a, t); } }
    if (el.tagName === 'INPUT' && /^(button|submit)$/i.test(el.type) && GREEK.test(el.value)) el.value = I.t(el.value);
  }
  function walk(root) {
    if (root.nodeType === 3) { fixText(root); return; }
    if (root.nodeType !== 1) return;
    if (FORM.has(root.tagName)) { if (!skip(root.parentNode)) fixEl(root); return; }
    if (skip(root)) return;
    fixEl(root);
    const tw = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
      acceptNode: n => n.nodeType === 1 ? (FORM.has(n.tagName) && !n.hasAttribute('data-noi18n') && fixEl(n), SKIP.has(n.tagName) || n.hasAttribute('data-noi18n') ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT) : NodeFilter.FILTER_ACCEPT
    });
    let n; while ((n = tw.nextNode())) { if (n.nodeType === 3) fixText(n); else fixEl(n); }
  }
  function fixText(n) {
    const v = n.nodeValue;
    if (!v || !GREEK.test(v) || (n.parentNode && skip(n.parentNode))) return;
    const t = I.t(v);
    if (t !== v) n.nodeValue = t;
  }
  const mo = new MutationObserver(ms => {
    for (const m of ms) {
      if (m.type === 'characterData') fixText(m.target);
      else if (m.type === 'attributes') fixEl(m.target);
      else m.addedNodes.forEach(walk);
    }
  });
  const start = () => {
    walk(document.body); document.title = I.t(document.title);
    mo.observe(document.body, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS });
  };
  if (document.body) start(); else document.addEventListener('DOMContentLoaded', start);
  // και τα παράθυρα του browser
  const tl = msg => msg == null ? msg : String(msg).split('\n').map(l => I.t(l)).join('\n');  // κράτα τις αλλαγές γραμμής
  for (const f of ['alert', 'confirm', 'prompt']) { const o = window[f]; window[f] = function (msg, ...r) { return o.call(window, tl(msg), ...r); }; }
  // κείμενο που ζωγραφίζεται σε <canvas> (χάρτες): δεν το βλέπει ο observer — μεταφράζεται στο fillText/measureText
  if (window.CanvasRenderingContext2D) {
    const P = CanvasRenderingContext2D.prototype, memo = new Map();
    const ct = t => { if (typeof t !== 'string' || !GREEK.test(t)) return t; let x = memo.get(t); if (x == null) { x = I.t(t); if (memo.size > 3000) memo.clear(); memo.set(t, x); } return x; };
    for (const f of ['fillText', 'strokeText', 'measureText']) { const o = P[f]; P[f] = function (t, ...r) { return o.call(this, ct(t), ...r); }; }
  }
})();

// Κουμπί αλλαγής γλώσσας: <button data-langswitch></button> οπουδήποτε στη σελίδα.
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-langswitch]').forEach(b => {
    b.setAttribute('data-noi18n', '');
    b.textContent = I18N.lang === 'en' ? '🇬🇷 ΕΛ' : '🇬🇧 EN';
    b.title = I18N.lang === 'en' ? 'Ελληνικά' : 'English';
    b.onclick = () => I18N.set(I18N.lang === 'en' ? 'el' : 'en');
  });
});
