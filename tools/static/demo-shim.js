/* NetWatch — online demo shim (GitHub Pages, χωρίς backend).
 *
 * Φορτώνεται ΠΡΙΝ από τα scripts της εφαρμογής, μετά το demo-data.js (window.NETWATCH_DEMO,
 * καταγραφή από `netwatch.py --demo` με το tools/record_static_demo.py). Κάνει τρία πράγματα:
 *   1. fetch('/api/…') → απαντά με τα καταγεγραμμένα JSON (POST → φιλικές «demo» απαντήσεις)
 *   2. new EventSource('/events') → ψεύτικο stream που ξαναπαίζει την καταγραφή σε βρόχο
 *   3. μικρό banner «Online demo».
 * Όλοι οι χρόνοι epoch (t, first, last, seen, …) μετατοπίζονται ώστε να φαίνονται «τώρα».
 */
(function () {
  'use strict';
  var D = window.NETWATCH_DEMO;
  if (!D) { console.warn('NetWatch demo: λείπει το demo-data.js'); return; }

  var NA = 'Μη διαθέσιμο στο online demo — κατέβασε το NetWatch για να το τρέξεις στον υπολογιστή σου.';
  var SHELL = 'Στο online demo το τερματικό δεν τρέχει εντολές — κατέβασε το NetWatch για να τις δοκιμάσεις στο Mac/Linux σου.';

  // ---------- χρόνος: ό,τι μοιάζει με epoch της καταγραφής μετατοπίζεται ----------
  var LO = D.t0 - 200 * 86400, HI = D.recorded_at + 86400;
  function shift(o, d) {
    if (typeof o === 'number') return (o > LO && o < HI) ? o + d : o;
    if (Array.isArray(o)) return o.map(function (x) { return shift(x, d); });
    if (o && typeof o === 'object') { var r = {}; for (var k in o) r[k] = shift(o[k], d); return r; }
    return o;
  }
  function nowS() { return Date.now() / 1000; }
  function staticShift() { return nowS() - D.recorded_at; }  // τα GET καταγράφηκαν στο τέλος

  // ---------- fetch ----------
  var realFetch = window.fetch.bind(window);
  function apiPath(u) {
    var i = u.pathname.indexOf('/api/');
    if (i >= 0) return u.pathname.slice(i);
    return /\/report$/.test(u.pathname) ? '/report' : null;
  }
  function json(obj, status) {
    return new Promise(function (res) {
      setTimeout(function () {
        res(new Response(JSON.stringify(obj), { status: status || 200, headers: { 'Content-Type': 'application/json' } }));
      }, 60 + Math.random() * 120);
    });
  }
  function rec(p) { return D.api[p] !== undefined ? shift(D.api[p], staticShift()) : undefined; }

  // Λίγη «κατάσταση» για να μην είναι νεκρά τα κουμπιά.
  var blocked = null, honeyOn = null;

  function handleGet(p, q) {
    if (p === '/api/packet') {
      var src = q.get('src'), dst = q.get('dst'), ip = q.get('ip');
      if (src && dst) return rec('/api/packet?src=' + src + '&dst=' + dst) ||
        { error: 'Στο online demo έχω αποθηκευμένα πακέτα μόνο για λίγες συνδέσεις — δοκίμασε άλλη.' };
      return rec('/api/packet?ip=' + ip) || { flows: [] };
    }
    if (p === '/api/history') {
      var h = parseFloat(q.get('hours')) || 24, best = null, bd = Infinity;
      Object.keys(D.api).forEach(function (k) {
        var m = /^\/api\/history\?hours=([\d.]+)$/.exec(k);
        if (m && Math.abs(+m[1] - h) < bd) { bd = Math.abs(+m[1] - h); best = k; }
      });
      return best ? rec(best) : { error: NA };
    }
    if (p === '/api/latency' && q.get('target')) {
      var t = q.get('target'), lh = parseFloat(q.get('hours')) || 24, lb = null, ld = Infinity;
      Object.keys(D.api).forEach(function (k) {
        if (k.indexOf('/api/latency?target=' + t + '&hours=') !== 0) return;
        var hh = +k.split('&hours=')[1];
        if (Math.abs(hh - lh) < ld) { ld = Math.abs(hh - lh); lb = k; }
      });
      return lb ? rec(lb) : { error: NA };
    }
    if (p === '/api/iotfw/rules') return rec('/api/iotfw/rules?dev=' + q.get('dev') + '&fmt=' + (q.get('fmt') || 'openwrt')) || { error: NA };
    if (p === '/api/flows/device') return rec('/api/flows/device?ip=' + q.get('ip')) || { error: NA };
    if (p === '/api/hunt/profile') return rec('/api/hunt/profile?ip=' + q.get('ip')) || { error: NA };
    if (p === '/api/syslog') {
      var sl = rec(p);
      if (!sl || !sl.results) return sl || { error: NA };
      var qq = (q.get('q') || '').toLowerCase(), host = q.get('host') || '', sev = parseInt(q.get('sev'), 10);
      sl.results = sl.results.filter(function (m) {
        return (!qq || JSON.stringify(m).toLowerCase().indexOf(qq) >= 0) && (!host || m.host === host || m.src_ip === host) &&
          (isNaN(sev) || m.severity <= sev);
      });
      return sl;
    }
    if (p === '/api/block' && blocked) { var b = rec(p) || {}; b.blocked = blocked; return b; }
    if (p === '/api/honeypot' && honeyOn === false) return honeyOff();
    if (p === '/api/whois') return { ip: q.get('ip'), text: NA };
    var r = rec(p);
    return r !== undefined ? r : { error: NA };
  }
  function honeyOff() { var h = rec('/api/honeypot') || {}; h.running = false; h.listening = []; h.ports = []; return h; }

  function handlePost(p, body) {
    switch (p) {
      case '/api/shell': return { ok: false, blocked: true, out: SHELL };
      case '/api/iot': case '/api/mqtt': case '/api/wifi': case '/api/privacy':
        return rec(p) || { error: NA };
      case '/api/exposure': return D.post[p] || { error: NA };
      case '/api/purple/run': case '/api/tlsaudit/run': return D.post[p] || { ok: true };
      case '/api/purple/stop': return { ok: true, stopped: false };
      case '/api/hunt/run': return rec('/api/hunt/run?id=' + body.id) || { error: NA };
      case '/api/scan': return { ok: true };
      case '/api/honeypot':
        honeyOn = !!body.enable;
        return honeyOn ? rec(p) : honeyOff();
      case '/api/block': {
        if (!blocked) blocked = (rec(p) || {}).blocked || [];
        if (body.unblock) blocked = blocked.filter(function (x) { return x.ip !== body.unblock; });
        else if (body.ip) {
          blocked = blocked.filter(function (x) { return x.ip !== body.ip; });
          blocked.unshift({ ip: String(body.ip), t: nowS(), why: String(body.why || '') });
        }
        var b = rec(p) || {}; b.blocked = blocked; b.demo = true; return b;
      }
      case '/api/rules/toggle': return { ok: true };
      case '/api/notify': return { channels: [], result: NA };
      case '/api/ctf/answer': case '/api/ctf/rule': return { correct: false, error: NA };
      case '/api/ctf/exit': return { ok: true };
      default: return { error: NA };
    }
  }

  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : (input && input.url) || String(input);
    var u;
    try { u = new URL(url, location.href); } catch (e) { return realFetch(input, init); }
    var p = u.origin === location.origin ? apiPath(u) : null;
    if (!p) {  // π.χ. '/academy/en/files.json' → σχετικό, για το /<repo>/ του Pages
      if (typeof input === 'string' && /^\/(?!\/)/.test(input)) input = input.slice(1);
      return realFetch(input, init);
    }
    var method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
    if (method === 'GET') return json(handleGet(p, u.searchParams));
    var body = {};
    try { body = JSON.parse((init && init.body) || '{}'); } catch (e) { /* κενό */ }
    return json(handlePost(p, body));
  };

  // Η αναφορά (/report) είναι στατικό report.html δίπλα στη σελίδα.
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest && e.target.closest('a[href]');
    if (!a) return;
    var href = a.getAttribute('href');
    if (/^\/?report(\?|$)/.test(href)) { e.preventDefault(); window.open('report.html', a.target || '_blank'); }
    if (/^\/?pentest-report(\?|$)/.test(href)) { e.preventDefault(); window.open('pentest-report.html', a.target || '_blank'); }
  }, true);

  // Scripts με απόλυτο path (π.χ. '/academy/x.js' από το engine.js) → σχετικό, για το /<repo>/ του Pages.
  var sd = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
  if (sd && sd.set) {
    Object.defineProperty(HTMLScriptElement.prototype, 'src', {
      configurable: true, enumerable: sd.enumerable, get: sd.get,
      set: function (v) { v = String(v); if (/^\/(?!\/)/.test(v)) v = v.slice(1); sd.set.call(this, v); }
    });
  }

  // ---------- EventSource('/events') → αναπαραγωγή ----------
  var RealES = window.EventSource;
  var msgs = D.sse || [];
  var snapIdx = msgs.findIndex(function (m) { return m.msg.type === 'snapshot'; });
  var firstIdx = snapIdx + 1;
  var LOOP = msgs.length ? msgs[msgs.length - 1].dt + 0.5 : 1;
  var lastStats = null;
  for (var i = msgs.length - 1; i >= 0 && !lastStats; i--) if (msgs[i].msg.stats) lastStats = msgs[i].msg.stats;

  function forLoop(m, k) {  // ο k-οστός γύρος: μοναδικά ids alert, μετρητές που συνεχίζουν να ανεβαίνουν
    if (!k) return m;
    if (m.type === 'alert' && m.alert && typeof m.alert.id === 'number') m.alert.id += k * 100000;
    if (m.stats && lastStats) {
      ['pkts', 'bytes', 'alerts'].forEach(function (f) { if (typeof m.stats[f] === 'number') m.stats[f] += k * (lastStats[f] || 0); });
      if (typeof m.stats.uptime === 'number') m.stats.uptime += Math.round(k * LOOP);
    }
    return m;
  }

  function FakeES(url) {
    var self = this;
    this.url = url; this.readyState = 0; this.withCredentials = false;
    this.onopen = this.onmessage = this.onerror = null;
    this._l = {};
    var start = nowS(), k = 0, idx = firstIdx;
    function emit(data) {
      var ev = new MessageEvent('message', { data: JSON.stringify(data) });
      if (self.onmessage) self.onmessage(ev);
      (self._l.message || []).forEach(function (f) { f.call(self, ev); });
    }
    setTimeout(function () {
      if (self.readyState === 2) return;
      self.readyState = 1;
      var ev = new Event('open');
      if (self.onopen) self.onopen(ev);
      (self._l.open || []).forEach(function (f) { f.call(self, ev); });
      if (snapIdx >= 0) emit(shift(msgs[snapIdx].msg, start - D.t0));
      self._timer = setInterval(tick, 100);
    }, 50);
    function tick() {
      if (idx >= msgs.length) { k++; idx = firstIdx; if (idx >= msgs.length) return; }
      var el = nowS() - start;
      var guard = 0;
      while (idx < msgs.length && msgs[idx].dt + k * LOOP <= el && guard++ < 400) {
        var m = msgs[idx++];
        // Σε κρυφό tab οι timers καθυστερούν· μην ρίξεις όλα τα πακέτα μαζί, μόνο τα alerts.
        if (m.msg.type === 'pkts' && el - (m.dt + k * LOOP) > 3) {
          if (m.msg.hosts) emit({ type: 'pkts', items: [], hosts: shift(m.msg.hosts, start + k * LOOP - D.t0) });
          continue;
        }
        emit(forLoop(shift(m.msg, start + k * LOOP - D.t0), k));
        if (idx >= msgs.length) { k++; idx = firstIdx; }
      }
    }
  }
  FakeES.prototype.addEventListener = function (t, f) { (this._l[t] = this._l[t] || []).push(f); };
  FakeES.prototype.removeEventListener = function (t, f) { this._l[t] = (this._l[t] || []).filter(function (x) { return x !== f; }); };
  FakeES.prototype.close = function () { this.readyState = 2; clearInterval(this._timer); };
  FakeES.CONNECTING = 0; FakeES.OPEN = 1; FakeES.CLOSED = 2;

  window.EventSource = function (url, opts) {
    var u = new URL(url, location.href);
    if (u.origin === location.origin && /\/events$/.test(u.pathname)) return new FakeES(url);
    return new RealES(url, opts);
  };
  window.EventSource.CONNECTING = 0; window.EventSource.OPEN = 1; window.EventSource.CLOSED = 2;

  // ---------- banner ----------
  function repoUrl() {
    if (D.repo_url) return D.repo_url;
    var m = /^([\w-]+)\.github\.io$/i.exec(location.hostname), seg = location.pathname.split('/')[1];
    return m && seg ? 'https://github.com/' + m[1] + '/' + seg + '#readme' : 'https://github.com/';
  }
  function banner() {
    var b = document.createElement('div');
    b.id = 'nw-demo-banner';
    b.setAttribute('role', 'note');
    b.style.cssText = 'position:fixed;left:50%;bottom:10px;transform:translateX(-50%);z-index:2147483000;' +
      'background:#0b1424f2;color:#cfe0f5;border:1px solid #3ec5ff;border-radius:999px;padding:6px 10px 6px 14px;' +
      'font:13px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;box-shadow:0 4px 18px #0008;' +
      'display:flex;gap:8px;align-items:center;max-width:calc(100vw - 32px);box-sizing:border-box';
    b.innerHTML = '<span>🧪 Online demo — προσομοιωμένη κίνηση · <a target="_blank" rel="noopener" ' +
      'style="color:#3ec5ff;font-weight:600" href="' + repoUrl() + '">Κατέβασε το NetWatch</a>' +
      ' · <a href="academy.html" style="color:#3ec5ff" title="Η Ακαδημία ως εφαρμογή (PWA) για κινητό, και offline">📱 Ακαδημία στο κινητό</a></span>' +
      '<button aria-label="Κλείσιμο" title="Κλείσιμο" style="background:none;border:0;color:#8aa0b8;cursor:pointer;font-size:15px;padding:0 4px">×</button>';
    b.querySelector('button').onclick = function () { b.remove(); };
    document.body.appendChild(b);
  }
  if (document.body) banner(); else document.addEventListener('DOMContentLoaded', banner);
})();
