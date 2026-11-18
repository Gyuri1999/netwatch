"""🔄 Παράδοση βάρδιας (SOC/NOC shift handover) — τι έγινε στις τελευταίες N ώρες, σε ένα κείμενο για Teams/Slack/email.

Μαζεύει από τα υπόλοιπα modules (χωρίς δικά του δεδομένα, εκτός από τις σημειώσεις βάρδιας):
  • σοβαρές ειδοποιήσεις στο παράθυρο (ομαδοποιημένες «τύπος — δράστης ×N»)
  • υποθέσεις: νέες / κλειστές στο παράθυρο, ανοιχτές τώρα (cases)
  • αλλαγές ρυθμίσεων στο παράθυρο, οι επικίνδυνες πρώτες (configbak)
  • έλεγχος πριν/μετά (changecheck), τελευταία διάγνωση «Φταίει το δίκτυο;» (triage)
  • υπηρεσίες εκτός τώρα (health), λήξεις ≤ 14 μέρες (expiry, αν υπάρχει), σφάλματα του ίδιου του NetWatch (sensor)
  • «Εκκρεμότητες»: υποθέσεις υπό διερεύνηση + νέες σοβαρές + λήξεις ≤ 7 μέρες (υπάρχει πάντα)

Σημειώσεις βάρδιας: ελεύθερο κείμενο ≤ 1000 χαρακτήρες, κρατάμε τις 200 τελευταίες (live: JSON στον δίσκο,
ατομική εγγραφή· demo: στη μνήμη, με 2 έτοιμες σημειώσεις).

API
---
Handover(state, sim=False, path=None, clock=time.time)
  .summary(hours=8, lang="el") → {from, to, hours, lang, sections:[{id,title,sev,items}], stats, notes, text, demo}
  .add_note(text) → {ok, note, notes} | {error}
  .delete_note(t) → {ok, notes} | {error}
parse_hours(v) → int 1–72 (ValueError αλλιώς)
"""
import collections
import json
import os
import threading
import time

LANGS = ("el", "en")
MAX_NOTES = 200
MAX_NOTE = 1000
MIN_HOURS, MAX_HOURS = 1, 72
EXPIRY_SECTION_DAYS = 14
EXPIRY_PENDING_DAYS = 7
RANK = {"high": 3, "med": 2, "low": 1, "info": 0}


def _L(lang, el, en):
    return en if lang == "en" else el


def parse_hours(v, default=8):
    """Ώρες βάρδιας: ακέραιος 1–72 (None/"" → default)."""
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        raise ValueError("hours")
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise ValueError("hours")
    if f != int(f) or not MIN_HOURS <= int(f) <= MAX_HOURS:
        raise ValueError("hours")
    return int(f)


def _hm(t):
    try:
        return time.strftime("%H:%M", time.localtime(float(t)))
    except (TypeError, ValueError, OverflowError):
        return "—"


def _dt(t):
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(t)))
    except (TypeError, ValueError, OverflowError):
        return "—"


def _safe(fn, default=None):
    try:
        r = fn()
        return default if r is None else r
    except Exception:
        return default


class Handover:
    def __init__(self, state, sim=False, path=None, clock=time.time):
        self.st, self.sim, self.clock = state, sim, clock
        self.path = None if sim else path
        self.lock = threading.Lock()
        self.notes = []          # [{t, text}] παλαιότερη πρώτη
        self.on_save = None
        if sim:
            now = clock()
            self.notes = [{"t": round(now - 5.2 * 3600, 3), "text": "Ο εκτυπωτής του 2ου ορόφου θέλει έλεγχο μετά την αλλαγή VLAN"},
                          {"t": round(now - 1.4 * 3600, 3), "text": "Αναμένεται ενημέρωση firmware στο MikroTik απόψε 22:00"}]
        elif self.path:
            self._load()

    # ───────── σημειώσεις βάρδιας ─────────
    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        out = []
        for n in (data.get("notes") if isinstance(data, dict) else None) or []:
            if isinstance(n, dict) and isinstance(n.get("t"), (int, float)) and isinstance(n.get("text"), str):
                out.append({"t": float(n["t"]), "text": n["text"][:MAX_NOTE]})
        self.notes = sorted(out, key=lambda n: n["t"])[-MAX_NOTES:]

    def save(self):
        if not self.path:
            return
        with self.lock:
            raw = json.dumps({"v": 1, "notes": self.notes}, ensure_ascii=False, indent=1)
        tmp = self.path + ".tmp"
        try:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(raw)
            os.replace(tmp, self.path)
            if self.on_save:
                try:
                    self.on_save(self.path)
                except Exception:
                    pass
        except OSError:
            pass

    def add_note(self, text):
        if not isinstance(text, str) or not text.strip():
            return {"error": "Γράψε μια σημείωση. / Write a note."}
        text = text.strip()
        if len(text) > MAX_NOTE:
            return {"error": f"Έως {MAX_NOTE} χαρακτήρες. / Up to {MAX_NOTE} characters."}
        with self.lock:
            t = round(self.clock(), 3)
            while any(n["t"] == t for n in self.notes):  # μοναδικό t (χρησιμοποιείται για διαγραφή)
                t = round(t + 0.001, 3)
            note = {"t": t, "text": text}
            self.notes.append(note)
            self.notes = self.notes[-MAX_NOTES:]
            notes = [dict(n) for n in self.notes]
        self.save()
        return {"ok": True, "note": dict(note), "notes": notes}

    def delete_note(self, t):
        if isinstance(t, bool) or not isinstance(t, (int, float, str)):
            return {"error": "Μη έγκυρο t. / Invalid t."}
        try:
            t = float(t)
        except ValueError:
            return {"error": "Μη έγκυρο t. / Invalid t."}
        with self.lock:
            keep = [n for n in self.notes if abs(n["t"] - t) > 0.0005]
            if len(keep) == len(self.notes):
                return {"error": "Δεν βρέθηκε η σημείωση. / Note not found."}
            self.notes = keep
            notes = [dict(n) for n in self.notes]
        self.save()
        return {"ok": True, "notes": notes}

    # ───────── συλλογή ─────────
    def _name(self, ip):
        st = self.st
        h = (_safe(lambda: st.hosts.get(ip), None) if st is not None else None) or {}
        names = sorted(h.get("names") or ()) if isinstance(h, dict) else []
        n = names[0] if names else (h.get("rdns") if isinstance(h, dict) else None)
        return f"{n} ({ip})" if n and n != ip else str(ip)

    def _alerts(self, t0, t1):
        st = self.st
        lk = getattr(st, "lock", None)
        try:
            if lk:
                with lk:
                    al = list(getattr(st, "alerts", None) or [])
            else:
                al = list(getattr(st, "alerts", None) or [])
        except Exception:
            al = []
        out = [a for a in al if isinstance(a, dict) and t0 <= (a.get("t") or 0) <= t1
               and not a.get("lab") and not a.get("selftest") and not a.get("benign")]
        if self.sim and sum(1 for a in out if a.get("sev") == "high") < 2:
            out += self._demo_alerts(t1)
        return out

    def _demo_alerts(self, now):
        """Demo: λίγες «παλιότερες» ειδοποιήσεις, ώστε η βάρδια των 8 ωρών να έχει ιστορία."""
        rows = [(6.6, "Port scan", "high", "192.168.1.77"), (6.55, "Port scan", "high", "192.168.1.77"),
                (6.5, "Port scan", "high", "192.168.1.77"), (4.1, "Brute force", "high", "45.155.205.10"),
                (2.3, "Σύνδεση σε κακόβουλη IP", "high", "192.168.1.77"), (3.0, "Beaconing (πιθανό C2)", "med", "192.168.1.77"),
                (1.2, "Νέα συσκευή", "low", "192.168.1.99"), (0.8, "Ύποπτη εξερχόμενη θύρα", "low", "192.168.1.23")]
        return [{"t": now - h * 3600, "type": typ, "sev": sev, "actor": ip, "demo": True} for h, typ, sev, ip in rows]

    def _cases(self):
        cs = getattr(self.st, "cases", None)
        v = _safe(lambda: cs.view(), {}) if cs else {}
        out = [c for c in v.get("cases") or [] if isinstance(c, dict)]
        if self.sim and not out:
            now = self.clock()
            out = [{"id": 1, "title": "Port scan από 192.168.1.77", "status": "investigating", "sev": "high",
                    "created": now - 6.5 * 3600, "updated": now - 5 * 3600, "closed": None},
                   {"id": 2, "title": "Brute force από 45.155.205.10", "status": "new", "sev": "high",
                    "created": now - 4.1 * 3600, "updated": now - 4.1 * 3600, "closed": None},
                   {"id": 3, "title": "Νέα συσκευή 192.168.1.99", "status": "resolved", "sev": "low",
                    "created": now - 1.2 * 3600, "updated": now - 0.9 * 3600, "closed": now - 0.9 * 3600}]
        return out

    def _configs(self, t0, t1):
        cb = getattr(self.st, "configbak", None)
        if not cb:
            return []
        out = []
        for d in (_safe(lambda: cb.view(), {}) or {}).get("devices") or []:
            vs = (_safe(lambda d=d: cb.versions(d["id"]), {}) or {}).get("versions") or []
            for k, v in enumerate(vs):
                if k == len(vs) - 1:  # η πρώτη έκδοση της συσκευής δεν είναι «αλλαγή»
                    continue
                if t0 <= (v.get("ts") or 0) <= t1:
                    out.append({"device": d.get("name") or d.get("id"), "ts": v["ts"], "added": v.get("added") or 0,
                                "removed": v.get("removed") or 0, "risky": list(v.get("risky") or []),
                                "risk": v.get("level") == "risk"})
        out.sort(key=lambda c: (not c["risk"], -c["ts"]))
        return out

    def summary(self, hours=8, lang="el"):
        hours = parse_hours(hours)
        lang = lang if lang in LANGS else "el"
        L = lambda el, en: _L(lang, el, en)  # noqa: E731
        t1 = self.clock()
        t0 = t1 - hours * 3600
        st = self.st
        sections = []

        def add(sid, title, sev, items, force=False):
            if items or force:
                sections.append({"id": sid, "title": title, "sev": sev, "items": items})

        # — ειδοποιήσεις —
        al = self._alerts(t0, t1)
        by = collections.Counter(a.get("sev") for a in al)
        grp = collections.OrderedDict()
        for a in sorted((a for a in al if a.get("sev") == "high"), key=lambda a: -(a.get("t") or 0)):
            k = (a.get("type"), a.get("actor"))
            g = grp.setdefault(k, {"n": 0, "last": a.get("t"), "first": a.get("t")})
            g["n"] += 1
            g["first"] = a.get("t")
        items = []
        for (typ, actor), g in list(grp.items())[:15]:
            when = _hm(g["last"]) if g["n"] == 1 else f"{_hm(g['first'])}–{_hm(g['last'])}"
            items.append(f"{typ} — {self._name(actor)}" + (f" ×{g['n']}" if g["n"] > 1 else "") + f" ({when})")
        if len(grp) > 15:
            items.append(L(f"…και {len(grp) - 15} ακόμα ομάδες", f"…and {len(grp) - 15} more groups"))
        if by.get("med"):
            top = collections.Counter(a.get("type") for a in al if a.get("sev") == "med").most_common(3)
            items.append(L(f"+ {by['med']} μεσαίες", f"+ {by['med']} medium") + ": " + ", ".join(f"{t} ×{n}" for t, n in top))
        add("alerts", L("Σοβαρές ειδοποιήσεις", "High-severity alerts"), "high" if by.get("high") else "med", items)

        # — υποθέσεις —
        cases = self._cases()
        opened = [c for c in cases if t0 <= (c.get("created") or 0) <= t1]
        closed = [c for c in cases if c.get("closed") and t0 <= c["closed"] <= t1]
        still = [c for c in cases if c.get("status") in ("new", "investigating")]
        stv = {"new": L("νέα", "new"), "investigating": L("υπό διερεύνηση", "investigating"),
               "resolved": L("επιλύθηκε", "resolved"), "false_positive": L("ψευδώς θετικό", "false positive")}
        items = []
        for c in sorted(opened, key=lambda c: (-RANK.get(c.get("sev"), 0), -(c.get("created") or 0)))[:8]:
            items.append(L("Νέα", "Opened") + f" #{c.get('id')} [{c.get('sev')}] {c.get('title')} ({stv.get(c.get('status'), c.get('status'))})")
        for c in [c for c in closed if c not in opened][:8]:  # όσες άνοιξαν και έκλεισαν στη βάρδια φαίνονται ήδη πάνω
            items.append(L("Έκλεισε", "Closed") + f" #{c.get('id')} {c.get('title')} ({stv.get(c.get('status'), c.get('status'))})")
        rest = [c for c in still if c not in opened]
        if rest:
            items.append(L(f"Ανοιχτές από πριν: {len(rest)}", f"Still open from before: {len(rest)}") + " — " +
                         ", ".join(f"#{c.get('id')} {c.get('title')}" for c in rest[:5]))
        add("cases", L("Υποθέσεις", "Cases"), "high" if any(c.get("sev") == "high" for c in still) else ("med" if still else "info"), items)

        # — αλλαγές ρυθμίσεων —
        cfgs = self._configs(t0, t1)
        items = []
        for c in cfgs[:10]:
            s = f"{c['device']} {_hm(c['ts'])} (+{c['added']}/−{c['removed']})"
            if c["risky"]:
                s += (" ⚠ " if c["risk"] else ": ") + "; ".join(c["risky"][:3])
            items.append(s)
        add("configs", L("Αλλαγές ρυθμίσεων", "Config changes"),
            "high" if any(c["risk"] for c in cfgs) else ("med" if cfgs else "info"), items)

        # — έλεγχος πριν/μετά —
        ch = getattr(st, "changecheck", None)
        lc = (_safe(lambda: ch.view(), {}) or {}).get("last_compare") if ch else None
        checks = 0
        items = []
        if isinstance(lc, dict) and not lc.get("error") and t0 <= ((lc.get("b") or {}).get("t") or 0) <= t1:
            checks = 1
            vd = {"ok": L("εντάξει", "ok"), "warn": L("προσοχή", "warning"), "bad": L("ΠΡΟΒΛΗΜΑ", "PROBLEM")}
            items.append(f"{(lc.get('a') or {}).get('label')} → {(lc.get('b') or {}).get('label')} ({_hm((lc.get('b') or {}).get('t'))}): "
                         f"{vd.get(lc.get('verdict'), lc.get('verdict'))} — {lc.get('summary') or ''}")
        verdict = (lc or {}).get("verdict") if checks else None
        add("change_check", L("Έλεγχος πριν/μετά", "Before/after check"),
            {"bad": "high", "warn": "med"}.get(verdict, "info"), items)

        # — διάγνωση —
        tr = getattr(st, "triage", None)
        tv = _safe(lambda: tr.view(), {}) if tr else {}
        triage_runs = 0
        items = []
        if tv.get("finished") and t0 <= tv["finished"] <= t1 and tv.get("verdict"):
            triage_runs = 1
            v = tv["verdict"]
            items.append(f"{_hm(tv['finished'])} [{v.get('layer')}] {v.get('text')}" + (f" — {v['fix']}" if v.get("fix") else ""))
        add("triage", L("Τελευταία διάγνωση «Φταίει το δίκτυο;»", "Last \"Is it the network?\" triage"),
            "info" if (tv.get("verdict") or {}).get("layer") == "OK" else "med", items)

        # — υπηρεσίες —
        he = getattr(st, "health", None)
        hv = _safe(lambda: he.status(), {}) if he else {}
        down = [t for t in hv.get("targets") or [] if isinstance(t, dict) and t.get("up") is False]
        items = [f"{t.get('name')} ({t.get('host') or t.get('url') or ''})" + (f" " + L("εκτός από", "down since") + f" {_hm(t['since'])}" if t.get("since") else "")
                 + (f": {t['err']}" if t.get("err") else "") for t in down]
        add("health", L("Υπηρεσίες εκτός τώρα", "Services down now"), "high", items)

        # — λήξεις —
        ex = getattr(st, "expiry", None)
        xv = _safe(lambda: ex.view(), {}) if ex else {}
        exp = []
        for it in (xv.get("items") if isinstance(xv, dict) else None) or []:
            try:
                dl = int(it.get("days_left"))
            except (TypeError, ValueError, AttributeError):
                continue
            if dl <= EXPIRY_SECTION_DAYS:
                exp.append((dl, str(it.get("name") or ""), str(it.get("kind") or "")))
        exp.sort()
        items = [(f"{n} ({k}) — " if k else f"{n} — ") + (L(f"έληξε πριν {-d} μέρες", f"expired {-d} days ago") if d < 0 else
                                                       L(f"σε {d} μέρες", f"in {d} days")) for d, n, k in exp]
        add("expiry", L(f"Λήξεις ≤ {EXPIRY_SECTION_DAYS} μέρες", f"Expiring ≤ {EXPIRY_SECTION_DAYS} days"),
            "high" if any(d <= 3 for d, _, _ in exp) else "med", items)

        # — το ίδιο το NetWatch —
        items = []
        se = getattr(st, "sensor", None)
        ss = _safe(lambda: se.status(), {}) if se else {}
        if isinstance(ss, dict) and ss.get("configured") and ss.get("error") and not self.sim:
            items.append(L("Αισθητήρες (MQTT): ", "Sensors (MQTT): ") + str(ss["error"])[:160])
        sn = getattr(st, "snmp", None)
        for t in (_safe(lambda: sn.status(), {}) or {}).get("targets") or [] if sn else []:
            if t.get("ok") is False:
                items.append(f"SNMP {t.get('name')}: " + str(t.get("error") or L("χωρίς απάντηση", "no response"))[:120])
        add("self", L("NetWatch (αισθητήρες/συλλογή)", "NetWatch (sensors/collection)"), "med", items)

        # — εκκρεμότητες (πάντα) —
        pend = []
        for c in [c for c in still if c.get("status") == "investigating"][:8]:
            pend.append(L("Υπό διερεύνηση", "Investigating") + f": #{c.get('id')} {c.get('title')}")
        for c in [c for c in still if c.get("status") == "new" and c.get("sev") == "high"][:8]:
            pend.append(L("Νέα σοβαρή, χωρίς ανάθεση", "New high, unassigned") + f": #{c.get('id')} {c.get('title')}")
        for d, n, k in exp:
            if d <= EXPIRY_PENDING_DAYS:
                pend.append(L("Λήγει", "Expires") + f": {n} " + (L(f"(έληξε)", "(expired)") if d < 0 else L(f"σε {d} μέρες", f"in {d} days")))
        if any(c["risk"] for c in cfgs):
            pend.append(L("Επιβεβαίωσε τις επικίνδυνες αλλαγές ρυθμίσεων με τον υπεύθυνο", "Confirm the risky config changes with their owner"))
        sections.append({"id": "pending", "title": L("Εκκρεμότητες", "Pending"), "sev": "med" if pend else "info",
                         "items": pend or [L("Τίποτα σε εκκρεμότητα.", "Nothing pending.")]})

        with self.lock:
            notes = [dict(n) for n in self.notes if n["t"] >= t0]
        stats = {"alerts_high": by.get("high", 0), "alerts_med": by.get("med", 0), "alerts_low": by.get("low", 0),
                 "cases_open": len(still), "cases_new": len(opened), "cases_closed": len(closed),
                 "config_changes": len(cfgs), "risky_changes": sum(1 for c in cfgs if c["risk"]), "change_checks": checks,
                 "triage_runs": triage_runs, "expiring": len(exp)}
        res = {"from": t0, "to": t1, "hours": hours, "lang": lang, "sections": sections, "stats": stats, "notes": notes,
               "demo": bool(self.sim)}
        res["text"] = self._text(res, pend)
        return res

    def _text(self, r, pend):
        lang = r["lang"]
        L = lambda el, en: _L(lang, el, en)  # noqa: E731
        s = r["stats"]
        out = [L(f"NetWatch — Παράδοση βάρδιας ({r['hours']} ώρες)", f"NetWatch — Shift handover ({r['hours']} hours)"),
               L("Περίοδος", "Period") + f": {_dt(r['from'])} → {_dt(r['to'])}",
               L("Σύνοψη", "Summary") + ": " + L(f"{s['alerts_high']} σοβαρές / {s['alerts_med']} μεσαίες ειδοποιήσεις · "
                                                 f"{s['cases_open']} ανοιχτές υποθέσεις ({s['cases_new']} νέες, {s['cases_closed']} έκλεισαν) · "
                                                 f"{s['config_changes']} αλλαγές ρυθμίσεων ({s['risky_changes']} επικίνδυνες)",
                                                 f"{s['alerts_high']} high / {s['alerts_med']} medium alerts · "
                                                 f"{s['cases_open']} open cases ({s['cases_new']} new, {s['cases_closed']} closed) · "
                                                 f"{s['config_changes']} config changes ({s['risky_changes']} risky)")]
        mark = {"high": "[!]", "med": "[*]", "low": "[-]", "info": "[i]"}
        for sec in r["sections"]:
            if sec["id"] == "pending":
                continue
            out += ["", f"{mark.get(sec['sev'], '[*]')} {sec['title']}"]
            out += [f"  • {x}" for x in sec["items"]]
        out += ["", L("Σημειώσεις βάρδιας", "Shift notes")]
        out += [f"  • {_hm(n['t'])} {n['text']}" for n in r["notes"]] or ["  • " + L("(καμία)", "(none)")]
        out += ["", L("Εκκρεμεί για την επόμενη βάρδια", "Pending for the next shift")]
        out += [f"  • {x}" for x in pend] or ["  • " + L("Τίποτα σε εκκρεμότητα.", "Nothing pending.")]
        if r.get("demo"):
            out += ["", L("(δεδομένα προσομοίωσης — demo)", "(simulated data — demo)")]
        return "\n".join(out)
