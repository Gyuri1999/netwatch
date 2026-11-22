"""📅 «Άφησέ το μια βδομάδα»: παρακολούθηση ποιότητας γραμμής και αναφορά για τον πελάτη.

Ο πελάτης λέει «μου κόβεται πού και πού». Αφήνεις το κουτί (ή ένα laptop) με το NetWatch στο δίκτυό του, πατάς
«Ξεκίνα» και μετά από μερικές μέρες τυπώνεις μια αναφορά: πόσες φορές έπεσε η γραμμή, πότε, για πόσο, αν έφταιγε
ο πάροχος ή το τοπικό δίκτυο, ποιες ώρες είναι οι χειρότερες και ποιες συσκευές χάνονται.

Δεν μετράει τίποτα μόνο του — διαβάζει ό,τι ήδη καταγράφουν:
  • 📈 Καθυστέρηση (latency.py): γύροι ping ανά λεπτό προς router / πάροχο / Internet
  • 📈 Διαθεσιμότητα (presence.py): ποιες συσκευές ήταν online ανά 5′
  • ⚠ Ιστορικό ειδοποιήσεων (storage.History) και 📶 αλλαγές γραμμής (uplink.py)

Έτσι η αναφορά βγαίνει και για διάστημα πριν πατήσεις «Ξεκίνα», όσο υπάρχουν δεδομένα (30 μέρες).
"""
import os
import secrets
import statistics
import threading
import time

import sites
from sites import L, clean, esc

MAX_WATCHES = 60
MAX_DAYS = 30
GAP = 300          # κενό > 5′ ανάμεσα σε γύρους = το NetWatch δεν μετρούσε (κλειστό / χωρίς ρεύμα)
DOWN_LOSS = 100.0  # γύρος χωρίς καμία απάντηση
BAD_LOSS = 5.0     # μέση απώλεια ώρας που «φαίνεται» στον χρήστη (βίντεο-κλήσεις, VoIP)
BAD_JITTER = 30.0  # ms
MAX_OUTAGES = 200


def _pct(vals, p):
    v = sorted(x for x in vals if x is not None)
    if not v:
        return None
    return v[min(len(v) - 1, int(round(p / 100.0 * (len(v) - 1))))]


def outages(rows, gap=GAP):
    """Γύροι ping (t, min, med, max, loss, jitter) → διαστήματα χωρίς καμία απάντηση [(αρχή, τέλος, γύροι)].
    Το τέλος είναι ο πρώτος γύρος που απάντησε ξανά (ή ο τελευταίος χαμένος, αν μετά σταμάτησαν οι μετρήσεις)."""
    out, start, last, n = [], None, None, 0
    for r in rows:
        t, loss = r[0], r[4]
        down = loss is not None and loss >= DOWN_LOSS
        if start is not None and (not down or t - last > gap):
            out.append((start, t if (not down and t - last <= gap) else last, n))
            start = None
        if down and start is None:
            start, n = t, 0
        if down:
            n += 1
            last = t
    if start is not None:
        out.append((start, last, n))
    return out


def coverage(rows, start, end, gap=GAP):
    """Πόσο από το διάστημα καλύπτουν οι μετρήσεις (0–100) και τα κενά [(από, έως)] όπου το NetWatch δεν μετρούσε."""
    span = max(1.0, end - start)
    if not rows:
        return 0.0, [(start, end)]
    gaps, prev = [], start
    for r in rows:
        if r[0] - prev > gap:
            gaps.append((prev, r[0]))
        prev = r[0]
    if end - prev > gap:
        gaps.append((prev, end))
    lost = sum(b - a for a, b in gaps)
    return round(100.0 * max(0.0, span - lost) / span, 1), gaps


def stats(rows):
    """Σύνοψη ενός στόχου για το διάστημα."""
    med = [r[2] for r in rows if r[2] is not None]
    loss = [r[4] for r in rows if r[4] is not None]
    jit = [r[5] for r in rows if r[5] is not None]
    return {"rounds": len(rows), "loss": round(statistics.mean(loss), 2) if loss else None,
            "med": round(statistics.median(med), 1) if med else None, "p95": round(_pct(med, 95), 1) if med else None,
            "max": round(max(r[3] for r in rows if r[3] is not None), 1) if med else None,
            "jitter": round(statistics.mean(jit), 1) if jit else None}


def by_hour_of_day(rows):
    """24 κουβάδες (τοπική ώρα): μέση απώλεια %, διάμεση καθυστέρηση, jitter, πλήθος γύρων."""
    b = [[[], [], []] for _ in range(24)]
    for r in rows:
        h = time.localtime(r[0]).tm_hour
        if r[4] is not None:
            b[h][0].append(r[4])
        if r[2] is not None:
            b[h][1].append(r[2])
        if r[5] is not None:
            b[h][2].append(r[5])
    return [{"h": h, "n": len(x[0]), "loss": round(statistics.mean(x[0]), 1) if x[0] else None,
             "med": round(statistics.median(x[1]), 1) if x[1] else None,
             "jitter": round(statistics.mean(x[2]), 1) if x[2] else None} for h, x in enumerate(b)]


def by_day(rows, outs):
    """Ανά ημερολογιακή μέρα: απώλεια %, διάμεση ms, διακοπές και λεπτά εκτός."""
    days = {}
    for r in rows:
        k = time.strftime("%Y-%m-%d", time.localtime(r[0]))
        d = days.setdefault(k, {"day": k, "loss": [], "med": [], "outages": 0, "down_min": 0.0, "n": 0})
        d["n"] += 1
        if r[4] is not None:
            d["loss"].append(r[4])
        if r[2] is not None:
            d["med"].append(r[2])
    for a, b, _n in outs:
        k = time.strftime("%Y-%m-%d", time.localtime(a))
        if k in days:
            days[k]["outages"] += 1
            days[k]["down_min"] += max(1.0, (b - a) / 60.0)
    return [{"day": k, "n": d["n"], "loss": round(statistics.mean(d["loss"]), 2) if d["loss"] else None,
             "med": round(statistics.median(d["med"]), 1) if d["med"] else None, "outages": d["outages"],
             "down_min": int(round(d["down_min"]))} for k, d in sorted(days.items())]


def overlaps(a, b, slack=90):
    return a[0] <= b[1] + slack and b[0] <= a[1] + slack


def blame(inet_out, gw_outs, gw_measured):
    """Ποιος φταίει για μια διακοπή Internet; «local» αν την ίδια ώρα δεν απαντούσε ούτε το router, «isp» αν το router
    απαντούσε κανονικά, «unknown» αν δεν μετράμε το router."""
    if not gw_measured:
        return "unknown"
    return "local" if any(overlaps(inet_out, g) for g in gw_outs) else "isp"


def worst_window(hours, key="loss", thr=BAD_LOSS):
    """Το μεγαλύτερο συνεχόμενο «κακό» παράθυρο ωρών (π.χ. 20:00–23:00) ή None."""
    bad = [h["h"] for h in hours if h.get(key) is not None and h[key] >= thr and h["n"] >= 3]
    if not bad:
        return None
    best, cur = [], []
    for h in bad + [x + 24 for x in bad]:  # δύο γύροι του ρολογιού: το παράθυρο μπορεί να περνά τα μεσάνυχτα
        if cur and h == cur[-1] + 1:
            cur.append(h)
        else:
            best = cur if len(cur) > len(best) else best
            cur = [h]
    best = (cur if len(cur) > len(best) else best)[:24]
    return (best[0] % 24, (best[-1] + 1) % 24)


class Soak:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time, site_reg=None):
        self.state, self.demo, self.clock = state, demo, clock
        self.sites = site_reg  # sites.Sites ή None
        self.path = os.path.join(data_dir, "soak.json") if data_dir else None
        self.on_save = None
        self.lock = threading.RLock()
        self.watches = []
        if demo:
            now = self.clock()
            self.watches = [{"id": "w-demo01", "name": "Καφέ «Το Στέκι» — «κόβεται τα βράδια»", "site": "", "start": now - 6.9 * 86400,
                             "days": 7, "end": None, "note": "Ο πελάτης παραπονιέται για διακοπές στο POS και στο Wi-Fi πελατών μετά τις 20:00."}]
        elif self.path:
            j = sites.read_json(self.path, {})
            self.watches = [w for w in (j.get("watches") or []) if isinstance(w, dict) and w.get("id")][-MAX_WATCHES:]

    def _save(self):
        if self.path:
            sites.write_json(self.path, {"watches": self.watches}, self.on_save)

    # ── πηγές δεδομένων (όλες προαιρετικές) ──
    def _targets(self):
        lt = getattr(self.state, "latency", None)
        return list(getattr(lt, "targets", None) or []) if lt is not None else []

    def _rows(self, name, a, b):
        lt = getattr(self.state, "latency", None)
        try:
            return lt.store.rows(name, a, b) if lt is not None else []
        except Exception:  # noqa: BLE001
            return []

    def _alerts(self, a, b):
        h = getattr(self.state, "history", None)
        try:
            q = h.query(hours=max(1, int((b - a) / 3600) + 1), ref=b) if h is not None else {}
        except Exception:  # noqa: BLE001
            q = {}
        rows = [x for x in (q.get("alerts") or []) if a <= (x.get("t") or 0) <= b and (not x.get("mode") or self.demo or x.get("mode") == "live")]
        sev = {"high": 0, "med": 0, "low": 0}
        types = {}
        for x in rows:
            sev[x.get("sev")] = sev.get(x.get("sev"), 0) + 1
            types[x.get("type")] = types.get(x.get("type"), 0) + 1
        return {"total": len(rows), "sev": sev, "top": sorted(types.items(), key=lambda kv: -kv[1])[:8]}

    def _devices(self, days):
        p = getattr(self.state, "presence", None)
        try:
            v = p.view(days=days) if p is not None else {}
        except Exception:  # noqa: BLE001
            v = {}
        devs = [d for d in (v.get("devices") or []) if d.get("outages")]
        devs.sort(key=lambda d: (not d.get("always_on"), -d.get("outages", 0)))
        return [{"name": d.get("name") or d.get("ip") or d.get("key"), "ip": d.get("ip"), "icon": d.get("icon") or "", "pct": d.get("pct"),
                 "outages": d.get("outages"), "longest_min": d.get("longest_min"), "always_on": bool(d.get("always_on"))} for d in devs[:10]]

    def _uplink(self, a, b):
        u = getattr(self.state, "uplink", None)
        ev = [e for e in (getattr(u, "events", None) or []) if isinstance(e, dict) and a <= (e.get("t") or 0) <= b]
        return ev[-20:]

    # ── η σύνοψη ──
    def summary(self, start, end):
        end = min(end, self.clock())
        tg = self._targets()
        per, gw_outs, gw_measured, ref_rows = [], [], False, []
        for t in tg:
            rows = self._rows(t["name"], start, end)
            outs = outages(rows)
            s = stats(rows)
            s.update(name=t["name"], host=t.get("host"), role=t.get("role"), outages=len(outs),
                     down_min=int(round(sum(max(1.0, (b - a) / 60.0) for a, b, _ in outs))))
            per.append((t, rows, outs, s))
            if t.get("role") == "gateway" and rows:
                gw_outs, gw_measured = outs, True
        # «Internet» = οι δημόσιοι στόχοι· διακοπή όταν ΟΛΟΙ όσοι μετριούνται είναι κάτω την ίδια στιγμή
        pub = [(t, rows, outs, s) for t, rows, outs, s in per if t.get("role") not in ("gateway", "isp") and rows]
        inet = []
        if pub:
            first = pub[0]
            ref_rows = first[1]
            for o in first[2]:
                if all(any(overlaps(o, x) for x in other[2]) for other in pub[1:]):
                    inet.append(o)
        cov, gaps = coverage(ref_rows or (per[0][1] if per else []), start, end)
        hours = by_hour_of_day(ref_rows)
        ilist = [{"start": a, "end": b, "min": max(1, int(round((b - a) / 60.0))), "cause": blame((a, b), gw_outs, gw_measured)} for a, b, _ in inet]
        ilist.sort(key=lambda x: x["start"])
        tot = {"outages": len(ilist), "down_min": sum(x["min"] for x in ilist), "isp": sum(1 for x in ilist if x["cause"] == "isp"),
               "local": sum(1 for x in ilist if x["cause"] == "local"), "longest_min": max([x["min"] for x in ilist] or [0])}
        measured = (end - start) * cov / 100.0
        tot["uptime"] = round(100.0 * max(0.0, measured - tot["down_min"] * 60) / measured, 3) if measured > 0 else None
        res = {"start": start, "end": end, "coverage": cov, "gaps": [{"start": a, "end": b, "min": int((b - a) / 60)} for a, b in gaps[:20]],
               "targets": [s for _, _, _, s in per], "internet": tot, "outages": ilist[-MAX_OUTAGES:], "hours": hours,
               "days": by_day(ref_rows, inet), "window": worst_window(hours), "jitter_window": worst_window(hours, "jitter", BAD_JITTER),
               "devices": self._devices(max(1, min(30, int((end - start) / 86400) + 1))), "alerts": self._alerts(start, end),
               "uplink": self._uplink(start, end), "has_data": bool(ref_rows)}
        res["findings"] = self._findings(res)
        res["level"] = "bad" if any(f["sev"] == "bad" for f in res["findings"]) else "warn" if any(f["sev"] == "warn" for f in res["findings"]) else "ok"
        return res

    @staticmethod
    def _findings(r):
        """Συμπεράσματα σε απλά λόγια (el/en) + τι να κάνεις."""
        f = []

        def add(sev, el, en, fix_el="", fix_en=""):
            f.append({"sev": sev, "el": el, "en": en, "fix": fix_el, "fix_en": fix_en})

        hh = lambda h: f"{h:02d}:00"  # noqa: E731
        if not r["has_data"]:
            add("warn", "Δεν υπάρχουν μετρήσεις για αυτό το διάστημα.", "There are no measurements for this period.",
                "Άφησε το NetWatch ανοιχτό σε Live με την καρτέλα 📈 Καθυστέρηση ενεργή και ξαναδές σε λίγες ώρες.",
                "Leave NetWatch running in Live with the 📈 Latency tab enabled and check again in a few hours.")
            return f
        i = r["internet"]
        if r["coverage"] < 90:
            add("warn", f"Το NetWatch μετρούσε μόνο το {r['coverage']}% του διαστήματος — τα υπόλοιπα είναι άγνωστα (κλειστό ή χωρίς ρεύμα).",
                f"NetWatch was measuring only {r['coverage']}% of the period — the rest is unknown (off or unpowered).",
                "Βάλε το κουτί σε UPS ή σε πρίζα που δεν κλείνει με τον διακόπτη του χώρου.", "Put the box on a UPS or on a socket that is not switched off with the room.")
        if i["outages"]:
            sev = "bad" if i["down_min"] >= 10 or i["outages"] >= 3 else "warn"
            add(sev, f"Το Internet έπεσε {i['outages']} {'φορά' if i['outages'] == 1 else 'φορές'}, συνολικά {i['down_min']}′ (μεγαλύτερη διακοπή {i['longest_min']}′).",
                f"The Internet went down {i['outages']} time{'' if i['outages'] == 1 else 's'}, {i['down_min']} min in total (longest outage {i['longest_min']} min).")
            if i["isp"] and i["isp"] >= i["local"]:
                add(sev, f"Σε {i['isp']} από αυτές το router απαντούσε κανονικά — το πρόβλημα ήταν στη γραμμή ή στον πάροχο, όχι στο τοπικό δίκτυο.",
                    f"In {i['isp']} of them the router kept answering — the problem was the line or the ISP, not the local network.",
                    "Δήλωσε βλάβη στον πάροχο με αυτή την αναφορά (ώρες και διάρκειες). Έλεγξε καλώδιο/φίλτρο/οπτική ίνα ως το modem και το log του modem (SNR, αποσυγχρονισμοί).",
                    "Report a fault to the ISP with this report (times and durations). Check the cable/filter/fibre to the modem and the modem log (SNR, resyncs).")
            if i["local"]:
                add(sev, f"Σε {i['local']} διακοπές δεν απαντούσε ούτε το router — το πρόβλημα ήταν τοπικό (router, switch, καλώδιο, Wi-Fi ή ρεύμα).",
                    f"In {i['local']} outages the router did not answer either — the problem was local (router, switch, cable, Wi-Fi or power).",
                    "Δες αν το router κάνει επανεκκίνηση (uptime, θερμοκρασία, τροφοδοτικό), άλλαξε το καλώδιο ως το router και έλεγξε το log του για reboot.",
                    "Check whether the router reboots (uptime, temperature, power supply), swap the cable to the router and look for reboots in its log.")
        else:
            add("ok", "Καμία διακοπή Internet στο διάστημα που μετρήθηκε.", "No Internet outage in the measured period.")
        w = r["window"]
        if w:
            add("warn", f"Η απώλεια πακέτων ανεβαίνει σταθερά {hh(w[0])}–{hh(w[1])} (πάνω από {BAD_LOSS:.0f}%).",
                f"Packet loss rises consistently {hh(w[0])}–{hh(w[1])} (above {BAD_LOSS:.0f}%).",
                "Ώρες αιχμής: είτε συμφόρηση στον πάροχο είτε γεμάτη γραμμή από τον ίδιο τον χώρο (backup, κάμερες στο cloud, streaming). Δες τις 🌊 Ροές εκείνη την ώρα και βάλε QoS/όριο στο upload.",
                "Peak hours: either ISP congestion or the site's own traffic filling the line (backup, cloud cameras, streaming). Check 🌊 Flows at that time and add QoS / an upload limit.")
        jw = r["jitter_window"]
        if jw and jw != w:
            add("warn", f"Το jitter είναι υψηλό {hh(jw[0])}–{hh(jw[1])} (πάνω από {BAD_JITTER:.0f} ms) — ακούγεται σε VoIP και βιντεοκλήσεις.",
                f"Jitter is high {hh(jw[0])}–{hh(jw[1])} (above {BAD_JITTER:.0f} ms) — audible on VoIP and video calls.",
                "Βάλε προτεραιότητα (QoS/DSCP EF) στην τηλεφωνία και έλεγξε αν οι συσκευές είναι σε Wi-Fi με κακό σήμα.",
                "Prioritise telephony (QoS/DSCP EF) and check whether the devices sit on Wi-Fi with poor signal.")
        gw = next((t for t in r["targets"] if t.get("role") == "gateway" and t.get("rounds")), None)
        if gw and gw.get("loss") is not None and gw["loss"] >= 1.0:
            add("warn", f"Χάνονται πακέτα ήδη ως το router ({gw['loss']}% κατά μέσο όρο) — πριν καν βγούμε στο Internet.",
                f"Packets are lost already on the way to the router ({gw['loss']}% on average) — before even reaching the Internet.",
                "Αν το κουτί είναι σε Wi-Fi, σύνδεσέ το με καλώδιο και ξαναμέτρα. Με καλώδιο: έλεγξε καλώδιο/θύρα switch (CRC errors στο 🔌 Θύρες & SNMP).",
                "If the box is on Wi-Fi, wire it and measure again. If wired: check the cable / switch port (CRC errors under 🔌 Ports & SNMP).")
        flaky = [d for d in r["devices"] if d["always_on"] and d["outages"] >= 3]
        if flaky:
            names = ", ".join(str(d["name"]) for d in flaky[:4])
            add("warn", f"Συσκευές που έπρεπε να είναι πάντα online χάθηκαν επανειλημμένα: {names}.",
                f"Devices that should always be online dropped repeatedly: {names}.",
                "Δες σήμα Wi-Fi / καλώδιο και τροφοδοσία (PoE budget) στη συγκεκριμένη συσκευή.", "Check Wi-Fi signal / cable and power (PoE budget) for that device.")
        if r["alerts"]["sev"].get("high"):
            add("warn", f"{r['alerts']['sev']['high']} σοβαρές ειδοποιήσεις ασφαλείας στο διάστημα.", f"{r['alerts']['sev']['high']} high-severity security alerts in the period.",
                "Δες την καρτέλα ⚠ Επιθέσεις — δεν αφορούν την ποιότητα γραμμής, αλλά αξίζουν έλεγχο.", "See the ⚠ Attacks tab — unrelated to line quality, but worth a look.")
        return f

    # ── UI ──
    def _find(self, wid):
        return next((w for w in self.watches if w.get("id") == wid), None)

    def _span(self, w):
        end = w.get("end") or min(self.clock(), w["start"] + w["days"] * 86400)
        return w["start"], end

    def view(self):
        now = self.clock()
        with self.lock:
            ws = [dict(w) for w in self.watches]
        out = []
        for w in ws:
            a, b = self._span(w)
            w["running"] = not w.get("end") and now < w["start"] + w["days"] * 86400
            w["until"] = w["start"] + w["days"] * 86400
            w["progress"] = round(min(1.0, (now - w["start"]) / max(1.0, w["days"] * 86400)), 3)
            w["span"] = [a, b]
            out.append(w)
        out.sort(key=lambda w: (not w["running"], -w["start"]))
        live = next((w for w in out if w["running"]), out[0] if out else None)
        lt = getattr(self.state, "latency", None)
        return {"demo": self.demo, "watches": out, "now": now, "max_days": MAX_DAYS,
                "sources": {"latency": bool(lt is not None and getattr(lt, "enabled", True) and self._targets()),
                            "presence": getattr(self.state, "presence", None) is not None,
                            "history": getattr(self.state, "history", None) is not None},
                "summary": dict(self.summary(*live["span"]), id=live["id"]) if live else None}

    def api(self, method, sub, q, body):
        if method == "GET" and sub == "":
            return 200, self.view()
        if method == "GET" and sub == "summary":
            w = self._find(q.get("id"))
            return (200, dict(self.summary(*self._span(w)), id=w["id"])) if w else (404, {"error": "not found"})
        if method == "GET" and sub == "report":
            w = self._find(q.get("id"))
            if not w:
                return 404, {"error": "not found"}
            lang = "en" if q.get("lang") == "en" else "el"
            return sites.raw(self.report(w, lang), f"netwatch-quality-{w['id']}.html")
        if method != "POST":
            return 404, {"error": "not found"}
        if self.demo and sub in ("start", "stop", "delete"):
            return 200, dict(self.view(), note="demo")
        if sub == "start":
            try:
                days = max(1, min(MAX_DAYS, int(body.get("days") or 7)))
                back = max(0, min(MAX_DAYS, int(body.get("back_days") or 0)))  # «συμπερίλαβε και τις προηγούμενες Ν μέρες»
            except (TypeError, ValueError):
                return 400, {"error": "Οι μέρες πρέπει να είναι αριθμός."}
            name = clean(body.get("name"), 80) or "Παρακολούθηση"
            sid = body.get("site") if isinstance(body.get("site"), str) and self.sites is not None and self.sites.get(body.get("site")) else ""
            if not sid and self.sites is not None:
                try:
                    sid = self.sites.detect() or ""
                except Exception:  # noqa: BLE001
                    sid = ""
            with self.lock:
                if len(self.watches) >= MAX_WATCHES:
                    return 400, {"error": f"Έως {MAX_WATCHES} παρακολουθήσεις — σβήσε κάποια παλιά."}
                now = self.clock()
                self.watches.append({"id": "w-" + secrets.token_hex(4), "name": name, "site": sid, "start": now - back * 86400,
                                     "days": days + back, "end": None, "note": clean(body.get("note"), 400)})
                self._save()
            return 200, self.view()
        if sub in ("stop", "delete"):
            with self.lock:
                w = self._find(body.get("id"))
                if not w:
                    return 404, {"error": "not found"}
                if sub == "stop":
                    w["end"] = w.get("end") or min(self.clock(), w["start"] + w["days"] * 86400)
                else:
                    self.watches.remove(w)
                self._save()
            return 200, self.view()
        return 404, {"error": "not found"}

    # ── εκτυπώσιμη αναφορά ──
    def report(self, w, lang="el"):
        a, b = self._span(w)
        r = self.summary(a, b)
        t = lambda el, en: L(lang, el, en)  # noqa: E731
        ts, i = sites.ts, r["internet"]
        co = self.sites.company() if self.sites is not None else {}
        site = self.sites.get(w.get("site")) if self.sites is not None and w.get("site") else None
        col = {"ok": "#0a7a3d", "warn": "#9a6a00", "bad": "#c0182d"}[r["level"]]
        head = {"ok": t("Η γραμμή ήταν σταθερή", "The line was stable"), "warn": t("Υπάρχουν σημεία που θέλουν προσοχή", "Some points need attention"),
                "bad": t("Η γραμμή έχει πρόβλημα", "The line has a problem")}[r["level"]]
        h = [sites.doc_open(t("Αναφορά ποιότητας δικτύου", "Network quality report"), lang, self.demo),
             sites.doc_header(co, lang, w["id"], self.clock()),
             f'<h1>{t("Αναφορά ποιότητας δικτύου", "Network quality report")}</h1>',
             f'<div class="sub">{esc(w["name"])} · {esc(ts(a, lang))} → {esc(ts(b, lang))} ({max(1, round((b - a) / 86400))} {t("ημέρες", "days")})</div>',
             '<div class="grid">', sites.customer_block(site, lang) if site else f'<div class="boxx"><div class="k">{t("Σημείωση", "Note")}</div>{esc(w.get("note") or "—")}</div>',
             f'<div class="boxx"><div class="k">{t("Πώς μετρήθηκε", "How it was measured")}</div>'
             + t("Ping κάθε λεπτό προς το router, τον πάροχο και δύο δημόσιους server. «Διακοπή» = κανένας δημόσιος server δεν απάντησε.",
                 "A ping every minute to the router, the ISP and two public servers. “Outage” = no public server answered.") + '</div></div>',
             f'<div class="verdict" style="--c:{col}">{esc(head)}</div>',
             '<div class="kpis">',
             f'<div><b>{i["uptime"] if i["uptime"] is not None else "—"}%</b><span>{t("διαθεσιμότητα Internet", "Internet uptime")}</span></div>',
             f'<div><b>{i["outages"]}</b><span>{t("διακοπές", "outages")}</span></div>',
             f'<div><b>{i["down_min"]}′</b><span>{t("σύνολο εκτός", "total down")}</span></div>',
             f'<div><b>{i["longest_min"]}′</b><span>{t("μεγαλύτερη", "longest")}</span></div>',
             f'<div><b>{r["coverage"]}%</b><span>{t("κάλυψη μετρήσεων", "measurement coverage")}</span></div></div>',
             f'<h2>{t("Συμπεράσματα", "Findings")}</h2><ul>']
        for f in r["findings"]:
            cls = {"ok": "pass", "warn": "pend", "bad": "fail"}[f["sev"]]
            fix = f["fix_en"] if lang == "en" else f["fix"]
            h.append(f'<li><span class="{cls}">{"✓" if f["sev"] == "ok" else "!"}</span> {esc(f["en"] if lang == "en" else f["el"])}'
                     + (f'<div class="sub">→ {esc(fix)}</div>' if fix else "") + '</li>')
        h.append("</ul>")
        if r["has_data"]:
            h.append(f'<h2>{t("Ανά ώρα της ημέρας (μέση απώλεια πακέτων)", "By hour of day (average packet loss)")}</h2>' + self._hour_svg(r["hours"]))
            h.append(f'<h2>{t("Ανά ημέρα", "By day")}</h2><table><tr><th>{t("Ημέρα", "Day")}</th><th class="r">{t("Απώλεια %", "Loss %")}</th>'
                     f'<th class="r">{t("Διάμεση ms", "Median ms")}</th><th class="r">{t("Διακοπές", "Outages")}</th><th class="r">{t("Λεπτά εκτός", "Minutes down")}</th></tr>')
            for d in r["days"]:
                h.append(f'<tr><td>{esc(d["day"])}</td><td class="r">{"—" if d["loss"] is None else d["loss"]}</td><td class="r">{"—" if d["med"] is None else d["med"]}</td>'
                         f'<td class="r{" fail" if d["outages"] else ""}">{d["outages"]}</td><td class="r">{d["down_min"]}</td></tr>')
            h.append("</table>")
            h.append(f'<h2>{t("Στόχοι μέτρησης", "Measured targets")}</h2><table><tr><th>{t("Στόχος", "Target")}</th><th class="r">{t("Απώλεια %", "Loss %")}</th>'
                     f'<th class="r">{t("Διάμεση ms", "Median ms")}</th><th class="r">95% ms</th><th class="r">Jitter ms</th><th class="r">{t("Διακοπές", "Outages")}</th></tr>')
            for x in r["targets"]:
                dash = lambda v: "—" if v is None else v  # noqa: E731
                h.append(f'<tr><td>{esc(x["name"])} <span class="sub mono">{esc(x.get("host") or "")}</span></td><td class="r">{dash(x["loss"])}</td>'
                         f'<td class="r">{dash(x["med"])}</td><td class="r">{dash(x["p95"])}</td><td class="r">{dash(x["jitter"])}</td><td class="r">{x["outages"]}</td></tr>')
            h.append("</table>")
        if r["outages"]:
            cause = {"isp": t("γραμμή / πάροχος", "line / ISP"), "local": t("τοπικό δίκτυο", "local network"), "unknown": t("άγνωστο", "unknown")}
            h.append(f'<h2>{t("Διακοπές Internet", "Internet outages")}</h2><table><tr><th>{t("Από", "From")}</th><th>{t("Έως", "To")}</th>'
                     f'<th class="r">{t("Διάρκεια", "Duration")}</th><th>{t("Πού ήταν το πρόβλημα", "Where the problem was")}</th></tr>')
            for o in r["outages"][-60:]:
                h.append(f'<tr><td>{esc(ts(o["start"], lang))}</td><td>{esc(ts(o["end"], lang))}</td><td class="r">{o["min"]}′</td><td>{esc(cause[o["cause"]])}</td></tr>')
            h.append("</table>")
        if r["devices"]:
            h.append(f'<h2>{t("Συσκευές που χάθηκαν από το δίκτυο", "Devices that dropped off the network")}</h2><table><tr><th>{t("Συσκευή", "Device")}</th>'
                     f'<th class="r">{t("Online %", "Online %")}</th><th class="r">{t("Φορές", "Times")}</th><th class="r">{t("Μεγαλύτερη (λεπτά)", "Longest (min)")}</th></tr>')
            for d in r["devices"]:
                h.append(f'<tr><td>{esc(d["icon"])} {esc(d["name"])} <span class="sub mono">{esc(d.get("ip") or "")}</span></td><td class="r">{esc(d["pct"])}</td>'
                         f'<td class="r">{esc(d["outages"])}</td><td class="r">{esc(d["longest_min"])}</td></tr>')
            h.append("</table>")
        al = r["alerts"]
        if al["total"]:
            h.append(f'<h2>{t("Ειδοποιήσεις στο διάστημα", "Alerts in the period")}</h2><div class="sub">{al["total"]} {t("συνολικά", "in total")} · '
                     f'{al["sev"].get("high", 0)} {t("σοβαρές", "high")} · {al["sev"].get("med", 0)} {t("μέτριες", "medium")}</div><ul>'
                     + "".join(f'<li>{esc(k)} × {n}</li>' for k, n in al["top"]) + "</ul>")
        if r["gaps"] and r["coverage"] < 99:
            h.append(f'<h2>{t("Διαστήματα χωρίς μετρήσεις", "Periods without measurements")}</h2><ul>'
                     + "".join(f'<li>{esc(ts(g["start"], lang))} → {esc(ts(g["end"], lang))} ({g["min"]}′)</li>' for g in r["gaps"][:12]) + "</ul>")
        h.append(sites.signatures(lang, t("Ο τεχνικός", "Technician"), t("Ο πελάτης (έλαβα γνώση)", "Customer (acknowledged)")))
        h.append(sites.doc_close(lang))
        return "".join(h)

    @staticmethod
    def _hour_svg(hours):
        """24 μπάρες (απώλεια %) — καθαρό SVG, χωρίς scripts."""
        top = max([h["loss"] or 0 for h in hours] + [BAD_LOSS])
        bars = []
        for h in hours:
            v = h["loss"]
            x = 8 + h["h"] * 28
            if v is None:
                bars.append(f'<rect x="{x}" y="88" width="22" height="2" fill="#cfd6df"/>')
            else:
                hh = max(1.5, 80 * v / top)
                fill = "#c0182d" if v >= BAD_LOSS else "#d9a400" if v >= 1 else "#4a9d6a"
                bars.append(f'<rect x="{x}" y="{90 - hh:.1f}" width="22" height="{hh:.1f}" rx="2" fill="{fill}"/>'
                            + (f'<text x="{x + 11}" y="{86 - hh:.1f}" font-size="8" text-anchor="middle" fill="#4a5665">{v:g}</text>' if v >= 1 else ""))
            if h["h"] % 3 == 0:
                bars.append(f'<text x="{x + 11}" y="102" font-size="9" text-anchor="middle" fill="#4a5665">{h["h"]:02d}</text>')
        return f'<svg viewBox="0 0 688 106" width="100%" role="img" aria-label="loss by hour">{"".join(bars)}</svg>'
