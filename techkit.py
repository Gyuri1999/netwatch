"""🧰 Εργαλειοθήκη τεχνικού: ένας δρομολογητής για τα /api/kit/<όνομα>/<ενέργεια>.

Κάθε module (OT, τεστ αποδοχής, πελάτες, ετικέτες, IPv6, 802.1X/guest, απογραφή IoT, ασύρματα IoT, tester πρίζας,
εφεδρική γραμμή) έχει την ίδια μικρή διεπαφή:

    view()                          → dict για το UI
    api(method, sub, q, body)       → (http status, dict)   ή   (200, {"_raw": bytes, "_type": mime, "_name": "αρχείο"})
    observe(P, t)      (προαιρετικό) → παθητικά, για κάθε πακέτο
    run_forever()      (προαιρετικό) → περιοδικός έλεγχος σε δικό του thread

Έτσι το server.py χρειάζεται μόνο δύο γραμμές (GET/POST) και το netwatch.py μία (setup).
"""
import os
import threading
from urllib.parse import parse_qs

from core import log

MAX_BODY = 512 * 1024  # POST JSON (π.χ. λογότυπο εταιρείας ως data URL)
# όνομα στο URL → χαρακτηριστικό στο state
NAMES = {"ot": "ot", "accept": "accept", "sites": "sites", "labels": "labels", "v6": "v6", "nac": "nac",
         "iotinv": "iotinv", "radio": "radio", "field": "field", "uplink": "uplink", "soak": "soak", "remote": "remote"}
OBSERVERS = ("ot", "v6")  # όσα κοιτάνε πακέτα (φθηνά: γυρνάνε αμέσως αν δεν είναι η θύρα τους)
# έγγραφα για εκτύπωση: ποτέ scripts, ποτέ εξωτερικοί πόροι — ό,τι κι αν γράφει μέσα το όνομα μιας συσκευής
DOC_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"


def handle(state, method, path, query="", body=None):
    """→ (status, obj). Δεν πετάει ποτέ: λάθος ενός module δεν ρίχνει τον server."""
    rest = path[len("/api/kit/"):] if path.startswith("/api/kit/") else path
    name, _, sub = rest.partition("/")
    attr = NAMES.get(name)
    if not attr:
        return 404, {"error": "not found"}
    obj = getattr(state, attr, None)
    if obj is None:  # π.χ. ανάλυση pcap: το UI δείχνει «μη διαθέσιμο σε αυτή τη λειτουργία»
        return (200 if method == "GET" else 400), {"error": "off"}
    q = {k: v[0] for k, v in parse_qs(query or "").items() if v}
    try:
        r = obj.api(method, sub.strip("/"), q, body if isinstance(body, dict) else {})
    except Exception as e:  # noqa: BLE001
        log(f"kit/{name}:", e)
        return 500, {"error": str(e)[:200]}
    if not (isinstance(r, tuple) and len(r) == 2 and isinstance(r[0], int) and isinstance(r[1], dict)):
        return 500, {"error": "bad module reply"}
    return r


def respond(h, state, method, u, body=None):
    """Γράφει την απάντηση στον HTTP handler `h` (JSON ή έγγραφο)."""
    code, obj = handle(state, method, u.path, u.query, body)
    if "_raw" not in obj:
        return h._json(obj, code)
    raw = obj["_raw"]
    raw = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    ctype = str(obj.get("_type") or "application/octet-stream")
    name = "".join(c for c in str(obj.get("_name") or "") if (c.isascii() and c.isalnum()) or c in "._-")[:80]
    h.send_response(code)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(raw)))
    h.send_header("Cache-Control", "no-store")
    h.send_header("X-Content-Type-Options", "nosniff")
    h.send_header("Content-Security-Policy", DOC_CSP)
    if name:  # η σελίδα HTML ανοίγει για εκτύπωση· όλα τα άλλα (CSV…) κατεβαίνουν
        kind = "inline" if ctype.startswith("text/html") else "attachment"
        h.send_header("Content-Disposition", f'{kind}; filename="{name}"')
    h.end_headers()
    h.wfile.write(raw)


def observe(state, P, t):
    """Καλείται από το detect() για κάθε πακέτο (εκτός ARP)."""
    for attr in OBSERVERS:
        o = getattr(state, attr, None)
        if o is not None:
            try:
                o.observe(P, t)
            except Exception:  # noqa: BLE001
                pass


def _bg(obj):
    if obj is not None and hasattr(obj, "run_forever"):
        threading.Thread(target=obj.run_forever, daemon=True).start()
    return obj


def setup(state, cfg, mode, data, on_save=None):
    """Φτιάχνει όλα τα modules της εργαλειοθήκης. mode: live / demo / pcap."""
    demo, live = mode == "demo", mode == "live"
    for attr in set(NAMES.values()):
        setattr(state, attr, None)
    if mode == "pcap":
        return
    d = data if live else None
    cfg = cfg or {}

    def make(attr, factory, run=True):
        try:
            o = factory()
            if o is not None and on_save and live and hasattr(o, "on_save"):
                o.on_save = on_save
            setattr(state, attr, _bg(o) if (live and run) else o)
        except Exception as e:  # noqa: BLE001
            log(f"kit/{attr}: δεν ξεκίνησε —", e)

    import sites
    make("sites", lambda: sites.Sites(state, d, demo=demo))
    import accept
    make("accept", lambda: accept.Accept(state, d, demo=demo, sites=state.sites))
    import labels
    make("labels", lambda: labels.Labels(state, d, demo=demo, sites=state.sites))
    import otwatch
    make("ot", lambda: otwatch.OtWatch(state, d, demo=demo))
    import v6guard
    make("v6", lambda: v6guard.V6Guard(state, d, demo=demo))
    import nacheck
    make("nac", lambda: nacheck.NacCheck(state, d, demo=demo))
    import iotinv
    make("iotinv", lambda: iotinv.IotInv(state, d, demo=demo))
    import radio
    make("radio", lambda: radio.Radio(state, d, demo=demo))
    import uplink
    make("uplink", lambda: uplink.Uplink(state, cfg.get("uplink"), demo=demo, data_dir=d))
    import fieldbox
    make("field", lambda: fieldbox.FieldBox(state, d, demo=demo, triage=getattr(state, "triage", None)))
    import soak
    make("soak", lambda: soak.Soak(state, d, demo=demo, site_reg=state.sites), run=False)
    import remote
    make("remote", lambda: remote.Remote(state, d, demo=demo))
    if d:
        os.makedirs(d, exist_ok=True)
