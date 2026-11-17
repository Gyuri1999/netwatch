"""📄 Εβδομαδιαία αναφορά: μία σελίδα HTML (εκτυπώνεται σε PDF από τον browser) με βαθμό ασφάλειας,
τι έγινε, νέες συσκευές, IoT, MQTT και «τι να κάνεις αυτή την εβδομάδα»."""
import collections
import html
import time

SEV_GR = {"high": "σοβαρές", "med": "μέτριες", "low": "χαμηλές"}
SEV_C = {"high": "#d6334f", "med": "#d99a00", "low": "#3b82c4"}


def e(x):
    return html.escape(str(x if x is not None else ""))


def day_bars(alerts, since, days):
    per = collections.Counter()
    for a in alerts:
        per[int((a["t"] - since) // 86400)] += 1
    mx = max([1, *per.values()])
    w, h, gap = 34, 90, 8
    bars = []
    for i in range(days):
        n = per.get(i, 0)
        bh = round(n / mx * (h - 18))
        x = i * (w + gap)
        d = time.strftime("%a %d/%m", time.localtime(since + i * 86400 + 3600))
        bars.append(f'<rect x="{x}" y="{h - 14 - bh}" width="{w}" height="{bh}" rx="3" fill="var(--acc)"/>'
                    f'<text x="{x + w / 2}" y="{h - 16 - bh}" text-anchor="middle" font-size="10">{n or ""}</text>'
                    f'<text x="{x + w / 2}" y="{h}" text-anchor="middle" font-size="8.5" fill="var(--mut)">{e(d)}</text>')
    return f'<svg viewBox="0 0 {days * (w + gap)} {h + 2}" style="width:100%;max-width:{days * (w + gap) * 1.6}px">{"".join(bars)}</svg>'


def build(state, days=7, now=None):
    now = now or time.time()
    since = now - days * 86400
    try:
        q = state.history.query(hours=days * 24, ref=now)
    except Exception:
        q = {"alerts": [], "devices": []}
    alerts = [a for a in q["alerts"] if a.get("mode") in (None, "live", state.mode)]
    try:
        aud = state.audit()
    except Exception:
        aud = {"score": None, "grade": "?", "checks": []}
    sev = collections.Counter(a["sev"] for a in alerts)
    types = collections.Counter(a["type"] for a in alerts).most_common(8)
    actors = collections.Counter(a["actor"] for a in alerts if a["sev"] != "low").most_common(6)
    newdev = [d for d in q.get("devices", []) if (d.get("first_seen") or 0) >= since]
    todo = []
    for c in aud.get("checks", []):
        if c["status"] in ("bad", "warn") and c.get("advice"):
            todo.append((2 if c["status"] == "bad" else 1, c["title"], c["advice"]))
    iot = (getattr(state, "iot", None) and state.iot.result) or []
    for d in iot:
        for f in d.get("findings", []):
            if f["status"] in ("bad", "warn") and f.get("fix"):
                todo.append((2 if f["status"] == "bad" else 1, f"{d.get('name') or d['ip']}: {f['title']}", f["fix"]))
    todo.sort(key=lambda x: -x[0])
    seen, uniq = set(), []
    for t in todo:
        if t[1] not in seen:
            seen.add(t[1])
            uniq.append(t)
    mq = state.mqtt.status() if getattr(state, "mqtt", None) and state.mqtt.configured else None
    bl = state.baseline.view() if getattr(state, "baseline", None) else []

    score = aud.get("score")
    sc = "#1f9d61" if (score or 0) >= 80 else "#d99a00" if (score or 0) >= 60 else "#d6334f"
    period = f"{time.strftime('%d/%m/%Y', time.localtime(since))} – {time.strftime('%d/%m/%Y %H:%M', time.localtime(now))}"
    out = [f"""<!doctype html><html lang="el"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch — αναφορά</title><script src="i18n.js"></script><style>
:root{{--bg:#fff;--fg:#14202e;--mut:#5d6b7c;--line:#dde3ea;--card:#f6f8fb;--acc:#2b7fff}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0b1220;--fg:#e3ecf7;--mut:#8ea3bd;--line:#1f3352;--card:#111b2e;--acc:#4c95ff}}}}
@media print{{:root{{--bg:#fff;--fg:#14202e;--mut:#5d6b7c;--line:#dde3ea;--card:#f6f8fb;--acc:#2b7fff}} .noprint{{display:none}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,system-ui,sans-serif;max-width:860px;margin:0 auto;padding:24px 16px}}
h1{{margin:0;font-size:24px}} h2{{font-size:17px;margin:26px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}}
.mut{{color:var(--mut)}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}}
.box{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}} .big{{font-size:28px;font-weight:700}}
table{{width:100%;border-collapse:collapse}} td,th{{text-align:left;padding:5px 6px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{font-size:12px;color:var(--mut);font-weight:600}} svg text{{fill:var(--fg)}} li{{margin:4px 0}}
.pill{{display:inline-block;border-radius:10px;padding:0 7px;font-size:12px;color:#fff}}
</style></head><body>
<div class="noprint" style="text-align:right"><button onclick="print()">🖨 Εκτύπωση / PDF</button></div>
<h1>🛡 NetWatch — αναφορά {days} ημερών</h1><div class="mut">{e(period)} · λειτουργία {e(state.mode)}</div>
<div class="grid" style="margin-top:16px">
<div class="box"><div class="mut">Βαθμός ασφάλειας</div><div class="big" style="color:{sc}">{e(score if score is not None else '—')}<span style="font-size:15px">/100</span></div><div class="mut">βαθμίδα {e(aud.get('grade'))}</div></div>
<div class="box"><div class="mut">Ειδοποιήσεις</div><div class="big">{len(alerts)}</div><div class="mut">{' · '.join(f'{sev[k]} {SEV_GR[k]}' for k in ('high', 'med', 'low') if sev[k]) or 'καμία'}</div></div>
<div class="box"><div class="mut">Νέες συσκευές</div><div class="big">{len(newdev)}</div><div class="mut">πρώτη φορά στο δίκτυο</div></div>
<div class="box"><div class="mut">IoT που ελέγχθηκαν</div><div class="big">{len(iot)}</div><div class="mut">{sum(1 for d in iot if d.get('level') == 'bad')} με σοβαρό πρόβλημα</div></div>
</div>"""]
    out.append("<h2>✅ Τι να κάνεις αυτή την εβδομάδα</h2>")
    out.append("<ol>" + "".join(f"<li><b>{e(t)}</b> — {e(a)}</li>" for _, t, a in uniq[:7]) + "</ol>" if uniq else
               '<p class="mut">Τίποτα επείγον. 👌 Κράτα τις ενημερώσεις και ξανακοίτα την επόμενη εβδομάδα.</p>')
    out.append(f"<h2>📊 Ειδοποιήσεις ανά μέρα</h2>{day_bars(alerts, since, days)}")
    if types:
        out.append("<h2>🔎 Τι είδους</h2><table><tr><th>Τύπος</th><th>Πλήθος</th><th>Σοβαρότερη</th></tr>" + "".join(
            f"<tr><td>{e(t)}</td><td>{n}</td><td>{''.join(f'<span class=pill style=background:{SEV_C[s]}>{SEV_GR[s]}</span>' for s in ('high', 'med', 'low') if any(a['type'] == t and a['sev'] == s for a in alerts))[:200]}</td></tr>"
            for t, n in types) + "</table>")
    if actors:
        out.append("<h2>👤 Ποιοι προκάλεσαν τις περισσότερες (μέτριες/σοβαρές)</h2><table><tr><th>IP</th><th>Ειδοποιήσεις</th></tr>" +
                   "".join(f"<tr><td>{e(a)}</td><td>{n}</td></tr>" for a, n in actors) + "</table>")
    if newdev:
        out.append("<h2>📟 Νέες συσκευές</h2><table><tr><th>MAC</th><th>IP</th><th>Πρώτη φορά</th></tr>" + "".join(
            f"<tr><td>{e(d['mac'])}</td><td>{e(d['ip'])}</td><td>{e(time.strftime('%d/%m %H:%M', time.localtime(d['first_seen'])))}</td></tr>"
            for d in newdev[:30]) + "</table><p class='mut'>Αν κάποια δεν την αναγνωρίζεις, άλλαξε τον κωδικό του Wi‑Fi.</p>")
    if iot:
        out.append("<h2>🔌 IoT συσκευές</h2><table><tr><th>Συσκευή</th><th>Βαθμός</th><th>Προβλήματα</th></tr>" + "".join(
            f"<tr><td>{e(d.get('name') or d['ip'])}<div class=mut>{e(d['ip'])}</div></td><td>{d['score']}/100</td><td>"
            f"{'<br>'.join(e(f['title']) for f in d['findings'] if f['status'] in ('bad', 'warn')) or '—'}</td></tr>" for d in iot) + "</table>")
    if mq:
        silent = [d["id"] for d in mq["devices"] if d.get("silent")]
        out.append(f"<h2>📨 MQTT broker</h2><p>{e(mq.get('info', {}).get('version') or '')} · {len(mq['clients'])} γνωστοί clients · "
                   f"{len(mq['devices'])} συσκευές από τα topics{' · σιωπούν: ' + e(', '.join(silent)) if silent else ''}</p>")
    if bl:
        out.append("<h2>🌍 Με ποιες χώρες μιλάει κάθε συσκευή</h2><table><tr><th>Συσκευή</th><th>Χώρες</th></tr>" + "".join(
            f"<tr><td>{e(d['ip'])}<div class=mut>{e(d['key'])}</div></td><td>{e(', '.join(d['countries']))}{' <span class=mut>(μαθαίνω ακόμα)</span>' if d['learning'] else ''}</td></tr>"
            for d in bl[:30]) + "</table>")
    out.append(f'<p class="mut" style="margin-top:30px">Φτιάχτηκε από το NetWatch στις {e(time.strftime("%d/%m/%Y %H:%M", time.localtime(now)))}. '
               'Περιέχει IP και MAC του δικτύου σου — μην τη μοιραστείς δημόσια.</p></body></html>')
    return "".join(out)
