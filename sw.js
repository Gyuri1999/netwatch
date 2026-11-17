// Service worker της Ακαδημίας: όλα τα μαθήματα κρατιούνται τοπικά, ώστε να δουλεύει στο μετρό/αεροπλάνο.
// Στρατηγική: «πρώτα το δίκτυο, αλλιώς από την cache» για να παίρνεις αμέσως νέα μαθήματα όταν έχεις σύνδεση.
const CACHE = 'nw-academy-v2';
const CORE = ['academy.html', 'manifest.webmanifest', 'academy/engine.js', 'academy/files.json',
  'academy/icon.svg', 'academy/icon-180.png', 'academy/icon-192.png', 'academy/icon-512.png',
  'i18n.js', 'i18n/en-ui.js', 'i18n/en-backend.js', 'i18n/en-academy-ui.js', 'i18n/edu-en.js'];

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    await c.addAll(CORE);
    try {  // και τα αρχεία μαθημάτων που αναφέρει το files.json
      const j = await (await fetch('academy/files.json', { cache: 'no-store' })).json();
      await c.addAll(j.files.map(f => 'academy/' + f));
    } catch (err) { }
    try {  // και η αγγλική έκδοση
      const j = await (await fetch('academy/en/files.json', { cache: 'no-store' })).json();
      await c.addAll(['academy/en/files.json', ...j.files.map(f => 'academy/en/' + f)]);
    } catch (err) { }
    self.skipWaiting();
  })());
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin) return;
  const scope = new URL(self.registration.scope).pathname;
  const rel = u.pathname.startsWith(scope) ? u.pathname.slice(scope.length) : '';
  if (!(rel === 'academy.html' || rel === 'manifest.webmanifest' || rel.startsWith('academy/') || rel === 'i18n.js' || rel.startsWith('i18n/'))) return;  // μόνο η Ακαδημία (όχι το dashboard)
  e.respondWith((async () => {
    const c = await caches.open(CACHE);
    try {
      const r = await fetch(e.request);
      if (r.ok) c.put(e.request, r.clone());
      return r;
    } catch (err) {
      return (await c.match(e.request, { ignoreSearch: true })) || Response.error();
    }
  })());
});
