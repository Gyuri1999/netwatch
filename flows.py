"""🌊 Συλλέκτης ροών (NetFlow v5/v9, IPFIX, sFlow v5): βλέπεις την κίνηση ΟΛΩΝ των συσκευών του LAN χωρίς port mirroring.

Ο router/switch εξάγει εγγραφές ροών (ποιος μίλησε με ποιον, πόσα bytes) και το NetWatch τις λαμβάνει με UDP.

config.yaml:
flows:
  enabled: true
  bind: "0.0.0.0"
  netflow_port: 2055     # NetFlow v5 / v9 / IPFIX
  sflow_port: 6343       # sFlow v5
  allow: ["192.168.1.1"] # μόνο από αυτούς τους exporters (κενό = από όλους)
  upload_mb: 500         # «Μεγάλη έξοδος δεδομένων» αν μια συσκευή ανεβάσει > τόσα MB σε 10′

Δοκιμή χωρίς router:  python flows.py --send-test 127.0.0.1 2055
Τι στέλνει ο router σου: python flows.py --listen 2055
Μόνο stdlib (struct/socket/ipaddress). Κάθε parser αντέχει κομμένα/κακόβουλα πακέτα: δεν πετάει ποτέ εξαίρεση έξω από τον βρόχο λήψης.
"""
import collections
import functools
import ipaddress
import random
import select
import socket
import struct
import sys
import threading
import time

DEFAULTS = {"enabled": False, "bind": "0.0.0.0", "netflow_port": 2055, "sflow_port": 6343,
            "allow": ["192.168.1.1"], "upload_mb": 500, "window_min": 30}

MAX_TEMPLATES = 1024        # συνολικά templates (όλοι οι exporters μαζί)
MAX_FIELDS = 128            # πεδία ανά template
MAX_RECORDS = 4096          # εγγραφές ανά datagram
MAX_EXPORTERS = 256
MAX_CONV_PER_BUCKET = 5000  # ζεύγη (συσκευή, ομότιμος) ανά λεπτό
MAX_PORTS = 8
MAX_SFLOW_SAMPLES = 512
MAX_SFLOW_RECORDS = 64
UPLOAD_WINDOW = 600         # 10′
SUSPICIOUS_PORTS = {23: "Telnet", 2323: "Telnet", 445: "SMB", 3389: "RDP"}
IOT_TYPES = {"esp", "iot", "camera", "tv", "speaker", "printer", "pi"}
ALERT_COOLDOWN = 3600

T_PORT = "Ροή προς ύποπτη θύρα"
T_UPLOAD = "Μεγάλη έξοδος δεδομένων"

_LOCAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


@functools.lru_cache(maxsize=8192)
def is_local(ip):
    """RFC1918 / ULA: «δική μας» συσκευή."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in _LOCAL_NETS)


@functools.lru_cache(maxsize=8192)
def is_global(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _ip(b):
    if len(b) == 4:
        return str(ipaddress.IPv4Address(b))
    if len(b) == 16:
        return str(ipaddress.IPv6Address(b))
    return None


def _int(b):
    return int.from_bytes(b, "big") if b and len(b) <= 8 else 0


def record(exporter, src, dst, sport=0, dport=0, proto=0, nbytes=0, pkts=0, start=None, end=None,
           tcp_flags=0, in_if=0, out_if=0):
    return {"exporter": exporter, "src": src, "dst": dst, "sport": int(sport or 0), "dport": int(dport or 0),
            "proto": int(proto or 0), "bytes": int(nbytes or 0), "pkts": int(pkts or 0),
            "start": start, "end": end, "tcp_flags": int(tcp_flags or 0) & 0xFF,
            "in_if": int(in_if or 0), "out_if": int(out_if or 0)}


# ---------------------------------------------------------------- NetFlow v5

V5_HDR = struct.Struct("!HHIIIIBBH")
V5_REC = struct.Struct("!4s4s4sHHIIIIHHxBBBHHBBxx")


def _rel_time(base_secs, uptime_ms, t_ms):
    """Χρόνος από ms «uptime» του router → epoch. Αν βγει παράλογος, κρατάμε τον χρόνο εξαγωγής."""
    t = base_secs - (uptime_ms - t_ms) / 1000.0
    return t if base_secs - 7 * 86400 <= t <= base_secs + 60 else float(base_secs)


def parse_v5(data, exporter):
    """→ (records, ok). Το datagram ξεκινά με version=5."""
    if len(data) < V5_HDR.size:
        return [], False
    _v, count, uptime, secs, _ns, _seq, _et, _ei, samp = V5_HDR.unpack_from(data, 0)
    rate = samp & 0x3FFF
    rate = rate if rate > 1 else 1
    n = min(count, (len(data) - V5_HDR.size) // V5_REC.size, 30)  # το πρότυπο: έως 30 εγγραφές
    out = []
    for i in range(n):
        (s, d, _nh, inp, outp, pk, by, first, last, sp, dp, flags, proto, _tos, _sas, _das, _sm, _dm) = \
            V5_REC.unpack_from(data, V5_HDR.size + i * V5_REC.size)
        out.append(record(exporter, _ip(s), _ip(d), sp, dp, proto, by * rate, pk * rate,
                          _rel_time(secs, uptime, first), _rel_time(secs, uptime, last), flags, inp, outp))
    return out, n == count


# ---------------------------------------------------------------- NetFlow v9 / IPFIX

# πεδία που μας ενδιαφέρουν (enterprise 0 — ίδια αρίθμηση σε v9 και IPFIX)
F_BYTES, F_PKTS, F_PROTO, F_FLAGS, F_SPORT, F_SRC4, F_IN, F_DPORT, F_DST4, F_OUT = 1, 2, 4, 6, 7, 8, 10, 11, 12, 14
F_LAST, F_FIRST, F_OUT_BYTES, F_OUT_PKTS, F_SRC6, F_DST6, F_SAMP = 21, 22, 23, 24, 27, 28, 34
F_TOT_BYTES, F_TOT_PKTS = 85, 86
F_START_S, F_END_S, F_START_MS, F_END_MS, F_SYSINIT, F_SAMP2 = 150, 151, 152, 153, 160, 305
WANTED = {F_BYTES, F_PKTS, F_PROTO, F_FLAGS, F_SPORT, F_SRC4, F_IN, F_DPORT, F_DST4, F_OUT, F_LAST, F_FIRST,
          F_OUT_BYTES, F_OUT_PKTS, F_SRC6, F_DST6, F_SAMP, F_TOT_BYTES, F_TOT_PKTS, F_START_S, F_END_S,
          F_START_MS, F_END_MS, F_SYSINIT, F_SAMP2}
VARLEN = 65535


class Templates:
    """Cache templates ανά (exporter, έκδοση, source_id/observation domain, template id), με όριο μεγέθους."""

    def __init__(self, cap=MAX_TEMPLATES):
        self.cap, self.d = cap, collections.OrderedDict()

    def put(self, key, tpl):
        self.d.pop(key, None)
        self.d[key] = tpl
        while len(self.d) > self.cap:
            self.d.popitem(last=False)

    def get(self, key):
        return self.d.get(key)

    def drop(self, key):
        self.d.pop(key, None)

    def count(self, exporter=None):
        return sum(1 for k in self.d if exporter is None or k[0] == exporter)

    def __len__(self):
        return len(self.d)


def _mk_template(fields, options=False):
    """fields: [(id, enterprise, length)]. None αν το template είναι άκυρο/επικίνδυνο."""
    if not fields or len(fields) > MAX_FIELDS:
        return None
    minlen = 0
    for _fid, _ent, ln in fields:
        if ln == 0:
            return None
        minlen += 1 if ln == VARLEN else ln
    return {"fields": tuple(fields), "minlen": minlen, "options": options}


def _data_records(body, tpl):
    """Αποκωδικοποίηση εγγραφών ενός data set → λίστα dict {field_id: bytes} (μόνο τα WANTED, enterprise 0)."""
    out, off, n, minlen = [], 0, len(body), tpl["minlen"]
    while n - off >= minlen and len(out) < MAX_RECORDS:
        rec, ok = {}, True
        for fid, ent, ln in tpl["fields"]:
            if ln == VARLEN:
                if off >= n:
                    ok = False
                    break
                ln = body[off]
                off += 1
                if ln == 255:
                    if off + 2 > n:
                        ok = False
                        break
                    ln = struct.unpack_from("!H", body, off)[0]
                    off += 2
            if off + ln > n:
                ok = False
                break
            if ent == 0 and fid in WANTED:
                rec[fid] = body[off:off + ln]
            off += ln
        if not ok:
            break
        out.append(rec)
    return out


def _norm_fields(exporter, f, export_secs, uptime_ms=None, sampling=1):
    """{field_id: bytes} → κανονικοποιημένη εγγραφή (None αν λείπουν διευθύνσεις)."""
    src = _ip(f.get(F_SRC4) or b"") or _ip(f.get(F_SRC6) or b"")
    dst = _ip(f.get(F_DST4) or b"") or _ip(f.get(F_DST6) or b"")
    if not src or not dst:
        return None
    nbytes = _int(f.get(F_BYTES)) or _int(f.get(F_TOT_BYTES)) or _int(f.get(F_OUT_BYTES))
    pkts = _int(f.get(F_PKTS)) or _int(f.get(F_TOT_PKTS)) or _int(f.get(F_OUT_PKTS))
    rate = _int(f.get(F_SAMP)) or _int(f.get(F_SAMP2)) or sampling or 1
    start = end = None
    if F_START_MS in f or F_END_MS in f:
        start = _int(f.get(F_START_MS)) / 1000.0 or None
        end = _int(f.get(F_END_MS)) / 1000.0 or None
    elif F_START_S in f or F_END_S in f:
        start = float(_int(f.get(F_START_S))) or None
        end = float(_int(f.get(F_END_S))) or None
    elif (F_FIRST in f or F_LAST in f):
        if uptime_ms is not None:  # v9: σχετικά με το uptime της κεφαλίδας
            start = _rel_time(export_secs, uptime_ms, _int(f.get(F_FIRST))) if F_FIRST in f else None
            end = _rel_time(export_secs, uptime_ms, _int(f.get(F_LAST))) if F_LAST in f else None
        elif F_SYSINIT in f:  # IPFIX: σχετικά με το systemInitTimeMilliseconds
            init = _int(f[F_SYSINIT]) / 1000.0
            start = init + _int(f.get(F_FIRST)) / 1000.0 if F_FIRST in f else None
            end = init + _int(f.get(F_LAST)) / 1000.0 if F_LAST in f else None
    lo, hi = export_secs - 7 * 86400, export_secs + 3600
    start = start if start is None or lo <= start <= hi else float(export_secs)
    end = end if end is None or lo <= end <= hi else float(export_secs)
    start = start if start is not None else (end if end is not None else float(export_secs))
    end = end if end is not None else start
    return record(exporter, src, dst, _int(f.get(F_SPORT)), _int(f.get(F_DPORT)), _int(f.get(F_PROTO)),
                  nbytes * rate, pkts * rate, start, end, _int(f.get(F_FLAGS)), _int(f.get(F_IN)), _int(f.get(F_OUT)))


def parse_v9(data, exporter, templates, stats=None):
    """NetFlow v9 → (records, dropped). stats: dict του exporter (για το sampling από options)."""
    if len(data) < 20:
        return [], 1
    _v, _count, uptime, secs, _seq, src_id = struct.unpack_from("!HHIIII", data, 0)
    return _parse_sets(data, 20, len(data), exporter, templates, 9, src_id, secs, uptime, stats)


def parse_ipfix(data, exporter, templates, stats=None):
    """IPFIX (v10) → (records, dropped)."""
    if len(data) < 16:
        return [], 1
    _v, length, secs, _seq, dom = struct.unpack_from("!HHIII", data, 0)
    end = min(length, len(data)) if length >= 16 else len(data)
    return _parse_sets(data, 16, end, exporter, templates, 10, dom, secs, None, stats)


def _parse_sets(data, off, end, exporter, templates, ver, dom, secs, uptime, stats):
    recs, dropped = [], 0
    tmpl_id, opt_id = (0, 1) if ver == 9 else (2, 3)
    sampling = (stats or {}).get("sampling") or 1
    while off + 4 <= end and len(recs) < MAX_RECORDS:
        sid, slen = struct.unpack_from("!HH", data, off)
        if slen < 4 or off + slen > end:
            dropped += 1
            break
        body = data[off + 4:off + slen]
        off += slen
        if sid == tmpl_id:
            _parse_templates(body, exporter, templates, ver, dom, False)
        elif sid == opt_id:
            _parse_templates(body, exporter, templates, ver, dom, True)
        elif sid >= 256:
            tpl = templates.get((exporter, ver, dom, sid))
            if tpl is None:  # δεδομένα πριν από το template: δεν μπορούμε να τα διαβάσουμε
                dropped += 1
                continue
            for f in _data_records(body, tpl):
                if tpl["options"]:
                    rate = _int(f.get(F_SAMP)) or _int(f.get(F_SAMP2))
                    if rate and stats is not None and rate < 1 << 24:
                        stats["sampling"] = sampling = rate
                    continue
                r = _norm_fields(exporter, f, secs, uptime, sampling)
                if r:
                    recs.append(r)
                if len(recs) >= MAX_RECORDS:
                    break
        # άλλα set ids (4..255): αγνοούνται
    return recs, dropped


def _parse_templates(body, exporter, templates, ver, dom, options):
    off, n = 0, len(body)
    while off + 4 <= n:
        tid, cnt = struct.unpack_from("!HH", body, off)
        off += 4
        key = (exporter, ver, dom, tid)
        if ver == 9 and options:
            # v9 options: template_id, scope_length(bytes), option_length(bytes)
            if off + 2 > n:
                return
            olen = struct.unpack_from("!H", body, off)[0]
            off += 2
            nf = (cnt + olen) // 4
            if (cnt + olen) % 4 or nf > MAX_FIELDS or off + nf * 4 > n:
                return
            fields = [(a, 0, b) for a, b in (struct.unpack_from("!HH", body, off + 4 * i) for i in range(nf))]
            off += nf * 4
        else:
            if ver == 10 and options:
                if off + 2 > n:
                    return
                off += 2  # scope field count — δεν μας χρειάζεται
            if ver == 10 and cnt == 0:  # IPFIX template withdrawal
                templates.drop(key)
                continue
            if cnt == 0 or cnt > MAX_FIELDS:
                return
            fields = []
            for _ in range(cnt):
                if off + 4 > n:
                    return
                fid, ln = struct.unpack_from("!HH", body, off)
                off += 4
                ent = 0
                if ver == 10 and fid & 0x8000:
                    if off + 4 > n:
                        return
                    ent = struct.unpack_from("!I", body, off)[0]
                    fid &= 0x7FFF
                    off += 4
                if ver == 9 and ln == VARLEN:  # το v9 δεν έχει μεταβλητό μήκος
                    return
                fields.append((fid, ent, ln))
        if tid < 256:
            return
        tpl = _mk_template(fields, options)
        if tpl is None:
            return
        templates.put(key, tpl)


# ---------------------------------------------------------------- sFlow v5

def parse_l3(hdr, proto_hint=1):
    """Αποκωδικοποίηση δειγματοληπτημένης κεφαλίδας: Ethernet(+VLAN)/IPv4/IPv6/TCP/UDP.
    → dict(src, dst, proto, sport, dport, tcp_flags) ή None."""
    off, n = 0, len(hdr)
    if proto_hint == 1:  # Ethernet
        if n < 14:
            return None
        et = struct.unpack_from("!H", hdr, 12)[0]
        off = 14
        for _ in range(2):  # 802.1Q / QinQ
            if et in (0x8100, 0x88A8, 0x9100):
                if off + 4 > n:
                    return None
                et = struct.unpack_from("!H", hdr, off + 2)[0]
                off += 4
        ver = 4 if et == 0x0800 else 6 if et == 0x86DD else None
    elif proto_hint == 11:
        ver = 4
    elif proto_hint == 12:
        ver = 6
    else:
        return None
    if ver == 4:
        if off + 20 > n:
            return None
        ihl = (hdr[off] & 0x0F) * 4
        if hdr[off] >> 4 != 4 or ihl < 20:
            return None
        frag = struct.unpack_from("!H", hdr, off + 6)[0] & 0x1FFF
        proto = hdr[off + 9]
        src, dst = _ip(hdr[off + 12:off + 16]), _ip(hdr[off + 16:off + 20])
        l4 = off + ihl if not frag else None
    elif ver == 6:
        if off + 40 > n or hdr[off] >> 4 != 6:
            return None
        proto = hdr[off + 6]
        src, dst = _ip(hdr[off + 8:off + 24]), _ip(hdr[off + 24:off + 40])
        l4 = off + 40
        for _ in range(4):  # λίγες επεκτάσεις κεφαλίδας
            if proto in (0, 43, 60) and l4 + 2 <= n:
                proto, l4 = hdr[l4], l4 + (hdr[l4 + 1] + 1) * 8
            elif proto == 44 and l4 + 8 <= n:
                fo = struct.unpack_from("!H", hdr, l4 + 2)[0] >> 3
                proto, l4 = hdr[l4], (l4 + 8 if fo == 0 else None)
                if l4 is None:
                    break
            else:
                break
    else:
        return None
    r = {"src": src, "dst": dst, "proto": proto, "sport": 0, "dport": 0, "tcp_flags": 0}
    if l4 is not None and proto in (6, 17) and l4 + 4 <= n:
        r["sport"], r["dport"] = struct.unpack_from("!HH", hdr, l4)
        if proto == 6 and l4 + 14 <= n:
            r["tcp_flags"] = hdr[l4 + 13]
    return r


def parse_sflow(data, exporter, now=None, stats=None):
    """sFlow v5 → (records, dropped). Τα bytes/πακέτα πολλαπλασιάζονται με τον ρυθμό δειγματοληψίας."""
    now = now or time.time()
    n = len(data)
    if n < 28:
        return [], 1
    ver, atype = struct.unpack_from("!II", data, 0)
    if ver != 5 or atype not in (1, 2):
        return [], 1
    off = 8 + (4 if atype == 1 else 16)
    if off + 16 > n:
        return [], 1
    _sub, _seq, _up, nsamp = struct.unpack_from("!IIII", data, off)
    off += 16
    recs, dropped = [], 0
    for _ in range(min(nsamp, MAX_SFLOW_SAMPLES)):
        if off + 8 > n:
            dropped += 1
            break
        fmt, slen = struct.unpack_from("!II", data, off)
        body_off, off = off + 8, off + 8 + slen
        if off > n:
            dropped += 1
            break
        ent, f = fmt >> 12, fmt & 0xFFF
        if ent != 0:
            continue
        if f in (2, 4):  # counter samples
            if stats is not None:
                stats["counter_samples"] = stats.get("counter_samples", 0) + 1
            continue
        if f not in (1, 3):
            continue
        r = _sflow_flow_sample(data[body_off:off], f == 3, exporter, now)
        if r is None:
            dropped += 1
        elif r:
            recs.extend(r)
    return recs, dropped


def _sflow_flow_sample(b, expanded, exporter, now):
    n = len(b)
    if expanded:
        if n < 44:
            return None
        _seq, _st, _si, rate, _pool, _drops, _if, inp, _of, outp, nrec = struct.unpack_from("!IIIIIIIIIII", b, 0)
        off = 44
    else:
        if n < 32:
            return None
        _seq, _src, rate, _pool, _drops, inp, outp, nrec = struct.unpack_from("!IIIIIIII", b, 0)
        off = 32
        inp, outp = inp & 0x3FFFFFFF, outp & 0x3FFFFFFF
    rate = rate if 0 < rate < 1 << 24 else 1
    best = None
    for _ in range(min(nrec, MAX_SFLOW_RECORDS)):
        if off + 8 > n:
            return None
        rfmt, rlen = struct.unpack_from("!II", b, off)
        roff, off = off + 8, off + 8 + rlen
        if off > n:
            return None
        if rfmt >> 12 != 0 or best is not None:
            continue
        rf = rfmt & 0xFFF
        if rf == 1 and rlen >= 16:  # raw packet header
            hp, flen, _strip, hlen = struct.unpack_from("!IIII", b, roff)
            if hlen > rlen - 16:
                continue
            p = parse_l3(b[roff + 16:roff + 16 + hlen], hp)
            if p:
                best = (p, flen)
        elif rf == 3 and rlen >= 32:  # sampled IPv4
            ln, pr, s, d, sp, dp, fl, _tos = struct.unpack_from("!II4s4sIIII", b, roff)
            best = ({"src": _ip(s), "dst": _ip(d), "proto": pr & 0xFF, "sport": sp & 0xFFFF,
                     "dport": dp & 0xFFFF, "tcp_flags": fl & 0xFF}, ln)
        elif rf == 4 and rlen >= 56:  # sampled IPv6
            ln, pr, s, d, sp, dp, fl, _pri = struct.unpack_from("!II16s16sIIII", b, roff)
            best = ({"src": _ip(s), "dst": _ip(d), "proto": pr & 0xFF, "sport": sp & 0xFFFF,
                     "dport": dp & 0xFFFF, "tcp_flags": fl & 0xFF}, ln)
    if best is None:
        return []  # δείγμα χωρίς IP (π.χ. ARP): όχι σφάλμα
    p, flen = best
    return [record(exporter, p["src"], p["dst"], p["sport"], p["dport"], p["proto"], flen * rate, rate,
                   now, now, p["tcp_flags"], inp, outp)]


# ---------------------------------------------------------------- dispatcher

def parse_datagram(data, exporter, templates, now=None, stats=None):
    """Οποιοδήποτε datagram → (version, records, dropped). Δεν πετάει ΠΟΤΕ εξαίρεση."""
    try:
        if len(data) < 4:
            return None, [], 1
        v16 = struct.unpack_from("!H", data, 0)[0]
        if v16 == 5:
            recs, ok = parse_v5(data, exporter)
            return 5, recs, 0 if ok else 1
        if v16 == 9:
            r, d = parse_v9(data, exporter, templates, stats)
            return 9, r, d
        if v16 == 10:
            r, d = parse_ipfix(data, exporter, templates, stats)
            return 10, r, d
        if struct.unpack_from("!I", data, 0)[0] == 5:
            r, d = parse_sflow(data, exporter, now, stats)
            return "sflow5", r, d
        return None, [], 1
    except Exception:  # struct.error, ValueError, … — ποτέ έξω από τον βρόχο λήψης
        return None, [], 1


# ---------------------------------------------------------------- συλλέκτης + συσσώρευση

class Flows:
    def __init__(self, state=None, cfg=None, sim=False):
        c = dict(DEFAULTS)
        c.update(cfg or {})
        self.cfg, self.state, self.sim = c, state, sim
        self.enabled = bool(c.get("enabled")) or sim
        self.allow = {str(a).strip() for a in (c.get("allow") or []) if str(a).strip()}
        self.window = max(2, int(c.get("window_min") or 30)) * 60
        self.upload_limit = float(c.get("upload_mb") or 500) * 1024 * 1024
        self.lock = threading.Lock()
        self.templates = Templates()
        self.exporters = {}
        self.buckets = collections.OrderedDict()  # λεπτό → {"conv": {(dev, peer): [...]}, "up": {dev: bytes}, ...}
        self.recent_recs = collections.deque(maxlen=200)
        self.counts = {"datagrams": 0, "records": 0, "dropped": 0, "rejected": 0, "overflow": 0}
        self.rejected_from = collections.OrderedDict()
        self.mqtt_devs = set()   # συσκευές που μιλούν MQTT → «IoT-άκιδες»
        self._cool = {}
        self.listening = {"netflow": None, "sflow": None}
        self.error = None
        self._stop = False
        self._sim_t = 0

    # ---------- λήψη ----------
    def ingest(self, data, addr, now=None):
        """Ένα UDP datagram από τον exporter addr (ip ή (ip, port)). → πλήθος εγγραφών που κρατήθηκαν."""
        now = now or time.time()
        ip = addr[0] if isinstance(addr, (tuple, list)) else str(addr)
        alerts = []
        with self.lock:
            self.counts["datagrams"] += 1
            if self.allow and ip not in self.allow:
                self.counts["rejected"] += 1
                self.rejected_from[ip] = self.rejected_from.pop(ip, 0) + 1
                while len(self.rejected_from) > 50:
                    self.rejected_from.popitem(last=False)
                return 0
            st = self._exporter(ip)
            ver, recs, dropped = parse_datagram(bytes(data), ip, self.templates, now, st)
            if st is not None:
                st["datagrams"] += 1
                st["last"] = now
                st["dropped"] += dropped
                if ver is not None:
                    st["version"] = ver
                st["records"] += len(recs)
            self.counts["dropped"] += dropped
            for r in recs:
                alerts.extend(self._add(r, now))
        self._raise(alerts)
        return len(recs)

    def ingest_records(self, recs, now=None, exporter="sim", version="sim"):
        """Έτοιμες κανονικοποιημένες εγγραφές (demo / tests)."""
        now = now or time.time()
        alerts = []
        with self.lock:
            st = self._exporter(exporter)
            if st is not None:
                st["datagrams"] += 1
                st["last"], st["version"] = now, version
                st["records"] += len(recs)
            for r in recs:
                alerts.extend(self._add(r, now))
        self._raise(alerts)
        return len(recs)

    def _exporter(self, ip):
        st = self.exporters.get(ip)
        if st is None:
            if len(self.exporters) >= MAX_EXPORTERS:
                return None
            st = self.exporters[ip] = {"ip": ip, "version": None, "datagrams": 0, "records": 0, "dropped": 0,
                                       "last": None, "first": time.time(), "sampling": None, "counter_samples": 0}
        return st

    def _bucket(self, now):
        m = int(now // 60)
        b = self.buckets.get(m)
        if b is None:
            b = self.buckets[m] = {"conv": {}, "up": collections.Counter(), "bytes": 0, "pkts": 0, "records": 0}
            self._prune(now)
        return b

    def _prune(self, now):
        lo = int((now - self.window) // 60)
        for m in [m for m in self.buckets if m <= lo]:
            del self.buckets[m]

    def _add(self, r, now):
        """Μία εγγραφή → buckets. Καλείται με το lock. → λίστα ειδοποιήσεων προς έκδοση."""
        self.counts["records"] += 1
        self.recent_recs.append(r)
        b = self._bucket(now)
        b["bytes"] += r["bytes"]
        b["pkts"] += r["pkts"]
        b["records"] += 1
        src, dst, sp, dp = r["src"], r["dst"], r["sport"], r["dport"]
        out = []
        sides = []
        if is_local(src):
            sides.append((src, dst, True, sp, dp))
        if is_local(dst):
            sides.append((dst, src, False, dp, sp))
        for dev, peer, outbound, lport, rport in sides:
            k = (dev, peer)
            e = b["conv"].get(k)
            if e is None:
                if len(b["conv"]) >= MAX_CONV_PER_BUCKET:
                    self.counts["overflow"] += 1
                    continue
                e = b["conv"][k] = [0, 0, 0, set(), now, now]  # out, in, pkts, ports, first, last
            e[0 if outbound else 1] += r["bytes"]
            e[2] += r["pkts"]
            svc = _svc_port(lport, rport)
            if svc and len(e[3]) < MAX_PORTS:
                e[3].add(svc)
            e[5] = now
            if rport in (1883, 8883) or lport in (1883, 8883):
                if len(self.mqtt_devs) < 4096:
                    self.mqtt_devs.add(dev)
            if outbound and is_global(peer):
                b["up"][dev] += r["bytes"]
                a = self._check_upload(dev, now)
                if a:
                    out.append(a)
            if outbound and r["proto"] in (6, 17) and rport in SUSPICIOUS_PORTS and lport not in SUSPICIOUS_PORTS:
                a = self._check_port(dev, peer, rport, now)
                if a:
                    out.append(a)
        return out

    # ---------- ειδοποιήσεις ----------
    def _cooled(self, key, now):
        t = self._cool.get(key)
        if t is not None and now - t < ALERT_COOLDOWN:
            return False
        self._cool[key] = now
        if len(self._cool) > 2000:
            for k in sorted(self._cool, key=self._cool.get)[:500]:
                del self._cool[k]
        return True

    def _check_upload(self, dev, now):
        if self.state is None:
            return None
        lo = int((now - UPLOAD_WINDOW) // 60)
        tot = sum(b["up"].get(dev, 0) for m, b in self.buckets.items() if m > lo)
        if tot < self.upload_limit or not self._cooled((T_UPLOAD, dev), now):
            return None
        peers = collections.Counter()
        for m, b in self.buckets.items():
            if m > lo:
                for (d, p), e in b["conv"].items():
                    if d == dev and is_global(p):
                        peers[p] += e[0]
        top = peers.most_common(1)[0][0] if peers else "?"
        mb = tot / 1048576
        return (T_UPLOAD, "med", dev, top,
                f"Η συσκευή {dev} έστειλε {mb:.0f} MB προς το Internet μέσα σε 10′ (κυρίως προς {top}). "
                "Αν δεν περιμένεις backup/ανέβασμα αρχείων, έλεγξε τι τρέχει σε αυτή.", (T_UPLOAD, dev))

    def _iotish(self, dev):
        if dev in self.mqtt_devs:
            return True
        st = self.state
        try:
            h = st.hosts.get(dev) if st is not None and hasattr(st, "hosts") else None
            if h is not None and hasattr(st, "_dtype"):
                return st._dtype(h).get("dtype") in IOT_TYPES
        except Exception:
            pass
        return False

    def _check_port(self, dev, peer, port, now):
        if self.state is None:
            return None
        pub = is_global(peer)
        if not pub and not self._iotish(dev):
            return None  # SMB/RDP μέσα στο LAN από υπολογιστή: φυσιολογικό
        if not self._cooled((T_PORT, dev, port), now):
            return None
        svc = SUSPICIOUS_PORTS[port]
        where = "στο Internet" if pub else "στο LAN"
        return (T_PORT, "med" if pub or port in (23, 2323) else "low", dev, f"{peer}:{port}",
                f"Η συσκευή {dev} άνοιξε ροή προς {peer}:{port} ({svc}) {where}. "
                f"Το {svc} είναι συνηθισμένος στόχος/φορέας κακόβουλου λογισμικού (π.χ. botnet τύπου Mirai) — "
                "έλεγξε αν το περιμένεις.", (T_PORT, dev, port))

    def _raise(self, alerts):
        if not alerts or self.state is None:
            return
        lk = getattr(self.state, "lock", None)
        for typ, sev, actor, target, detail, key in alerts:
            try:
                if lk is not None:
                    with lk:
                        self.state.alert(typ, sev, actor, target, detail, time.time(), key=key, cooldown=ALERT_COOLDOWN)
                else:
                    self.state.alert(typ, sev, actor, target, detail, time.time(), key=key, cooldown=ALERT_COOLDOWN)
            except Exception:
                pass

    # ---------- αναφορές ----------
    def _merged(self, now):
        """Συγχώνευση των buckets του παραθύρου → {(dev, peer): [out, in, pkts, ports, first, last]}."""
        lo = int((now - self.window) // 60)
        conv, tot = {}, {"bytes": 0, "pkts": 0, "records": 0}
        for m, b in self.buckets.items():
            if m <= lo:
                continue
            for k in tot:
                tot[k] += b[k]
            for k, e in b["conv"].items():
                c = conv.get(k)
                if c is None:
                    conv[k] = [e[0], e[1], e[2], set(e[3]), e[4], e[5]]
                else:
                    c[0] += e[0]
                    c[1] += e[1]
                    c[2] += e[2]
                    if len(c[3]) < MAX_PORTS:
                        c[3].update(sorted(e[3])[:MAX_PORTS - len(c[3])])
                    c[4], c[5] = min(c[4], e[4]), max(c[5], e[5])
        return conv, tot

    def status(self, now=None, top=10):
        now = now or time.time()
        with self.lock:
            self._prune(now)
            conv, tot = self._merged(now)
            exps = [{k: e[k] for k in ("ip", "version", "datagrams", "records", "dropped", "last", "sampling",
                                       "counter_samples")} for e in self.exporters.values()]
            for e in exps:
                e["templates"] = self.templates.count(e["ip"])
                e["last"] = round(e["last"], 1) if e["last"] else None
            counts = dict(self.counts)
            rej = [{"ip": k, "count": v} for k, v in self.rejected_from.items()]
        devs, dests = {}, {}
        for (dev, peer), e in conv.items():
            d = devs.setdefault(dev, {"ip": dev, "bytes": 0, "bytes_out": 0, "bytes_in": 0, "pkts": 0, "peers": 0,
                                      "last": 0})
            d["bytes_out"] += e[0]
            d["bytes_in"] += e[1]
            d["bytes"] += e[0] + e[1]
            d["pkts"] += e[2]
            d["peers"] += 1
            d["last"] = max(d["last"], e[5])
            if not is_local(peer):
                x = dests.setdefault(peer, {"ip": peer, "bytes": 0, "pkts": 0, "devices": set(), "ports": set()})
                x["bytes"] += e[0] + e[1]
                x["pkts"] += e[2]
                x["devices"].add(dev)
                if len(x["ports"]) < MAX_PORTS:
                    x["ports"].update(sorted(e[3])[:MAX_PORTS - len(x["ports"])])
        talkers = sorted(devs.values(), key=lambda d: -d["bytes"])[:top]
        for d in talkers:
            d["last"] = round(d["last"], 1)
        tdest = sorted(dests.values(), key=lambda d: -d["bytes"])[:top]
        for d in tdest:
            d["devices"], d["ports"] = sorted(d["devices"]), sorted(d["ports"])
        tconv = sorted(conv.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:top]
        return {
            "enabled": self.enabled, "demo": self.sim, "listening": dict(self.listening), "error": self.error,
            "window_min": self.window // 60,
            "exporters": sorted(exps, key=lambda e: -(e["records"] or 0)),
            "totals": {**tot, "devices": len(devs), "destinations": len(dests), "conversations": len(conv)},
            "counts": counts,
            "rejected_from": rej,
            "top_talkers": talkers,
            "top_destinations": tdest,
            "top_conversations": [{"device": d, "peer": p, "bytes": e[0] + e[1], "bytes_out": e[0], "bytes_in": e[1],
                                   "pkts": e[2], "ports": sorted(e[3]), "first": round(e[4], 1),
                                   "last": round(e[5], 1)} for (d, p), e in tconv],
        }

    def device(self, ip, now=None, limit=200):
        now = now or time.time()
        with self.lock:
            conv, _ = self._merged(now)
        rows = [{"ip": p, "local": is_local(p), "bytes": e[0] + e[1], "bytes_out": e[0], "bytes_in": e[1],
                 "pkts": e[2], "ports": sorted(e[3]), "first": round(e[4], 1), "last": round(e[5], 1)}
                for (d, p), e in conv.items() if d == ip]
        rows.sort(key=lambda r: -r["bytes"])
        return {"ip": ip, "bytes": sum(r["bytes"] for r in rows), "bytes_out": sum(r["bytes_out"] for r in rows),
                "bytes_in": sum(r["bytes_in"] for r in rows), "pkts": sum(r["pkts"] for r in rows),
                "destinations": rows[:limit]}

    def recent(self, n=50):
        with self.lock:
            return list(self.recent_recs)[-n:][::-1]

    # ---------- demo ----------
    SIM_DEVS = [
        # (συσκευή, ομότιμος, θύρα, proto, bytes έξω ανά tick, bytes μέσα ανά tick, πιθανότητα)
        ("192.168.1.20", "192.168.1.17", 1883, 6, 900, 400, 1.0),        # ESP32 → MQTT broker
        ("192.168.1.20", "52.57.104.21", 8883, 6, 1500, 800, 0.3),       # ESP32 → cloud (AWS IoT)
        ("192.168.1.10", "23.246.2.141", 443, 6, 40000, 3500000, 1.0),   # TV → CDN (streaming)
        ("192.168.1.10", "151.101.66.217", 443, 6, 8000, 400000, 0.5),   # TV → Fastly CDN
        ("192.168.1.10", "142.250.185.110", 443, 6, 5000, 150000, 0.3),  # TV → Google
        ("192.168.1.30", "192.168.1.17", 1883, 6, 2500, 3000, 1.0),      # Home Assistant → broker
        ("192.168.1.30", "192.168.1.20", 80, 6, 600, 1800, 0.4),         # HA → ESP32 web
        ("192.168.1.30", "140.82.112.4", 443, 6, 3000, 60000, 0.1),      # HA → GitHub (ενημερώσεις)
        ("192.168.1.30", "192.168.1.1", 53, 17, 300, 600, 0.8),          # HA → DNS
        ("192.168.1.42", "93.184.215.14", 80, 6, 1200, 25000, 0.15),     # λάπτοπ, λίγο HTTP
        ("192.168.1.42", "1.1.1.1", 443, 6, 4000, 9000, 0.4),
    ]

    def sim_tick(self, now=None):
        now = now or time.time()
        recs = []
        for dev, peer, port, proto, bo, bi, p in self.SIM_DEVS:
            if random.random() > p:
                continue
            sp = random.randint(32768, 60999)
            k = random.uniform(0.6, 1.4)
            ob, ib = int(bo * k), int(bi * k)
            op, ip_ = max(1, ob // 700), max(1, ib // 1200)
            fl = 0x1B if proto == 6 else 0
            recs.append(record("192.168.1.1", dev, peer, sp, port, proto, ob, op, now - 5, now, fl, 3, 1))
            recs.append(record("192.168.1.1", peer, dev, port, sp, proto, ib, ip_, now - 5, now, fl, 1, 3))
        self.ingest_records(recs, now, exporter="192.168.1.1", version="demo")
        return recs

    # ---------- βρόχος ----------
    def _socks(self):
        socks = []
        bind = self.cfg.get("bind") or "0.0.0.0"
        fam = socket.AF_INET6 if ":" in bind else socket.AF_INET
        for name in ("netflow", "sflow"):
            port = self.cfg.get(name + "_port")
            if not port:
                continue
            try:
                s = socket.socket(fam, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
                except OSError:
                    pass
                s.bind((bind, int(port)))
                socks.append(s)
                self.listening[name] = int(port)
            except OSError as e:
                self.error = f"Δεν άνοιξε η θύρα UDP {port} ({name}): {e}"[:200]
        return socks

    def run_forever(self):
        if self.sim:
            while not self._stop:
                try:
                    self.sim_tick()
                except Exception:
                    pass
                time.sleep(3)
            return
        if not self.enabled:
            return
        socks = self._socks()
        if not socks:
            return
        last_prune = 0
        while not self._stop:
            try:
                ready, _, _ = select.select(socks, [], [], 1.0)
            except (OSError, ValueError):
                break
            for s in ready:
                try:
                    data, addr = s.recvfrom(65535)
                except OSError:
                    continue
                try:
                    self.ingest(data, addr)
                except Exception:  # ποτέ δεν πέφτει ο βρόχος
                    with self.lock:
                        self.counts["dropped"] += 1
            if time.time() - last_prune > 30:
                last_prune = time.time()
                with self.lock:
                    self._prune(last_prune)
        for s in socks:
            try:
                s.close()
            except OSError:
                pass

    def stop(self):
        self._stop = True


def _svc_port(lport, rport):
    """Η «θύρα υπηρεσίας» μιας ροής: η μικρότερη από τις δύο (συνήθως η γνωστή), αν υπάρχει."""
    ps = [p for p in (rport, lport) if p]
    if not ps:
        return None
    if rport and (rport < 1024 or rport <= lport or not lport):
        return rport
    return min(ps)


# ---------------------------------------------------------------- συνθετικά πακέτα (δοκιμές / README)

def build_v5(recs, secs=None, uptime=100000, sampling=0):
    """recs: [(src, dst, sport, dport, proto, bytes, pkts)] → NetFlow v5 datagram."""
    secs = int(secs or time.time())
    out = V5_HDR.pack(5, len(recs), uptime, secs, 0, 1, 0, 0, sampling)
    for s, d, sp, dp, pr, by, pk in recs:
        out += V5_REC.pack(ipaddress.IPv4Address(s).packed, ipaddress.IPv4Address(d).packed, b"\0" * 4, 1, 2,
                           pk, by, uptime - 5000, uptime - 100, sp, dp, 0x1B if pr == 6 else 0, pr, 0, 0, 0, 24, 24)
    return out


def build_ipfix(recs, secs=None, domain=1, tid=256):
    """IPFIX με template (+ ένα μεταβλητού μήκους πεδίο και ένα enterprise πεδίο) και τα δεδομένα."""
    secs = int(secs or time.time())
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 8), (2, 8), (152, 8), (153, 8), (82, VARLEN)]
    tpl = struct.pack("!HH", tid, len(fields) + 1)
    for fid, ln in fields:
        tpl += struct.pack("!HH", fid, ln)
    tpl += struct.pack("!HHI", 0x8000 | 100, 4, 29305)  # enterprise πεδίο (αγνοείται)
    tset = struct.pack("!HH", 2, 4 + len(tpl)) + tpl
    body = b""
    for s, d, sp, dp, pr, by, pk in recs:
        name = b"eth0"
        body += (ipaddress.IPv4Address(s).packed + ipaddress.IPv4Address(d).packed +
                 struct.pack("!HHBQQQQ", sp, dp, pr, by, pk, (secs - 5) * 1000, secs * 1000) +
                 bytes([len(name)]) + name + b"\xde\xad\xbe\xef")
    dset = struct.pack("!HH", tid, 4 + len(body)) + body
    msg = tset + dset
    return struct.pack("!HHIII", 10, 16 + len(msg), secs, 1, domain) + msg


def send_test(host, port):
    v5 = build_v5([("192.168.1.20", "192.168.1.17", 50123, 1883, 6, 4200, 12),
                   ("192.168.1.10", "23.246.2.141", 51515, 443, 6, 120000, 90)])
    ipfix = build_ipfix([("192.168.1.30", "140.82.112.4", 40000, 443, 6, 9000, 20),
                         ("192.168.1.42", "93.184.215.14", 45678, 80, 6, 1500, 6)])
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.sendto(v5, (host, port))
        s.sendto(ipfix, (host, port))
    print(f"Στάλθηκαν 2 πακέτα (NetFlow v5: {len(v5)} B, IPFIX: {len(ipfix)} B) στο {host}:{port}.")


def _listen(port, bind="0.0.0.0"):
    f = Flows(None, {"enabled": True, "bind": bind, "netflow_port": port, "sflow_port": None, "allow": []})
    socks = f._socks()
    if not socks:
        print(f.error or "Δεν άνοιξε η θύρα.")
        return
    print(f"Ακούω στο UDP {bind}:{port} — Ctrl+C για έξοδο.")
    try:
        while True:
            data, addr = socks[0].recvfrom(65535)
            ver, recs, dropped = parse_datagram(data, addr[0], f.templates, time.time(), f._exporter(addr[0]))
            print(f"{addr[0]}: έκδοση {ver}, {len(recs)} εγγραφές" + (f", {dropped} απορρίφθηκαν" if dropped else ""))
            for r in recs[:20]:
                print(f"   {r['src']}:{r['sport']} → {r['dst']}:{r['dport']} proto {r['proto']} "
                      f"{r['bytes']} B / {r['pkts']} πακ.")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 3 and a[0] == "--send-test":
        send_test(a[1], int(a[2]))
    elif len(a) in (2, 3) and a[0] == "--listen":
        _listen(int(a[1]), a[2] if len(a) == 3 else "0.0.0.0")
    else:
        print("Χρήση: python flows.py --send-test HOST PORT   |   python flows.py --listen PORT [BIND]")
        sys.exit(2)
