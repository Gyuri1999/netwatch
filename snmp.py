"""📡 SNMP v2c poller (σαν ένα μικρό LibreNMS/PRTG): θύρες router/switch, κίνηση, σφάλματα, CPU/RAM, γείτονες LLDP/CDP.

Χωρίς εξωτερικές βιβλιοθήκες: ο ελάχιστος κωδικοποιητής/αποκωδικοποιητής BER/ASN.1 και τα GET, GETNEXT, GETBULK
πάνω από UDP είναι γραμμένα εδώ.

config.yaml:
snmp:
  enabled: true
  interval: 60
  targets:
    - {name: Router, host: 192.168.1.1, community: public, port: 161}
    - {name: Switch, host: 192.168.1.2, community: public}
Προαιρετικά: timeout (2″), retries (1), err_threshold (1 σφάλμα/s), disc_threshold (10 απορρίψεις/s),
util_threshold (90%), history (120 δείγματα ανά θύρα), max_rows (2000 γραμμές ανά walk). Ανά στόχο: bulk: false
για συσκευές που δεν καταλαβαίνουν GETBULK.
Το community είναι «κωδικός»: μένει μόνο στο config.yaml (που δεν μπαίνει στο git) και δεν γράφεται ποτέ σε log/status.

Δοκιμή από τη γραμμή εντολών:  python snmp.py 192.168.1.1 public
"""
import collections
import math
import random
import socket
import sys
import threading
import time

# ───────────────────────────── BER / ASN.1 ─────────────────────────────

INTEGER, OCTET_STRING, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30
IPADDRESS, COUNTER32, GAUGE32, TIMETICKS, OPAQUE, COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x46
NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW = 0x80, 0x81, 0x82
GET, GETNEXT, RESPONSE, SET, GETBULK, INFORM, TRAP2, REPORT = 0xA0, 0xA1, 0xA2, 0xA3, 0xA5, 0xA6, 0xA7, 0xA8

CONSTRUCTED = {SEQUENCE, GET, GETNEXT, RESPONSE, SET, GETBULK, INFORM, TRAP2, REPORT}
UNSIGNED_BITS = {COUNTER32: 32, GAUGE32: 32, TIMETICKS: 32, COUNTER64: 64}
EXCEPTIONS = {NO_SUCH_OBJECT: "noSuchObject", NO_SUCH_INSTANCE: "noSuchInstance", END_OF_MIB_VIEW: "endOfMibView"}
ERROR_STATUS = {0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr", 6: "noAccess",
                7: "wrongType", 8: "wrongLength", 9: "wrongEncoding", 10: "wrongValue", 11: "noCreation",
                12: "inconsistentValue", 13: "resourceUnavailable", 14: "commitFailed", 15: "undoFailed",
                16: "authorizationError", 17: "notWritable", 18: "inconsistentName"}
MAX_DEPTH = 12  # ένα πακέτο SNMP έχει το πολύ ~5 επίπεδα· βαθύτερα = κακόβουλο/χαλασμένο


class BerError(ValueError):
    """Χαλασμένο ή άκυρο BER — ο poller το αγνοεί, δεν «πέφτει»."""


class SnmpError(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status = status


class SnmpTimeout(SnmpError):
    pass


def parse_oid(oid):
    if isinstance(oid, (tuple, list)):
        return tuple(int(x) for x in oid)
    return tuple(int(x) for x in str(oid).strip().strip(".").split("."))


def oid_str(oid):
    return ".".join(str(x) for x in oid)


def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _enc_int(v):
    v = int(v)
    n = ((v if v >= 0 else ~v).bit_length() + 8) // 8
    return v.to_bytes(n, "big", signed=True)


def _enc_oid(oid):
    oid = parse_oid(oid)
    if len(oid) < 2 or oid[0] > 2 or (oid[0] < 2 and oid[1] >= 40) or min(oid) < 0:
        raise BerError("άκυρο OID")
    out = bytearray()
    for sub in (oid[0] * 40 + oid[1],) + oid[2:]:
        chunk = [sub & 0x7F]
        sub >>= 7
        while sub:
            chunk.append(0x80 | (sub & 0x7F))
            sub >>= 7
        out += bytes(reversed(chunk))
    return bytes(out)


def encode(tag, value=None):
    """(tag, value) → bytes. Σύνθετοι τύποι (SEQUENCE/PDU): value = λίστα από (tag, value)."""
    if tag in CONSTRUCTED:
        body = b"".join(encode(t, v) for t, v in value)
    elif tag == INTEGER:
        body = _enc_int(value)
    elif tag in UNSIGNED_BITS:
        v = int(value)
        if v < 0 or v >= 1 << UNSIGNED_BITS[tag]:
            raise BerError("τιμή εκτός ορίων")
        body = _enc_int(v)
    elif tag in (OCTET_STRING, OPAQUE):
        body = value.encode() if isinstance(value, str) else bytes(value or b"")
    elif tag == IPADDRESS:
        body = socket.inet_aton(value) if isinstance(value, str) else bytes(value)
        if len(body) != 4:
            raise BerError("άκυρη IpAddress")
    elif tag == OID:
        body = _enc_oid(value)
    elif tag in (NULL, NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
        body = b""
    else:
        body = bytes(value or b"")
    return bytes([tag]) + _enc_len(len(body)) + body


def _dec_len(data, pos, limit):
    if pos >= limit:
        raise BerError("κομμένο μήκος")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7F
    if n == 0 or n > 4:
        raise BerError("μη υποστηριζόμενο μήκος")
    if pos + n > limit:
        raise BerError("κομμένο μήκος")
    return int.from_bytes(data[pos:pos + n], "big"), pos + n


def _dec_oid(body):
    if not body:
        raise BerError("κενό OID")
    subs, cur = [], 0
    for i, b in enumerate(body):
        if cur == 0 and b == 0x80:
            raise BerError("άκυρη κωδικοποίηση OID")
        cur = (cur << 7) | (b & 0x7F)
        if not b & 0x80:
            subs.append(cur)
            cur = 0
        elif i == len(body) - 1:
            raise BerError("κομμένο OID")
    first = subs[0]
    head = (0, first) if first < 40 else (1, first - 40) if first < 80 else (2, first - 80)
    return head + tuple(subs[1:])


def decode(data, pos=0, depth=0, limit=None):
    """bytes → (tag, value, νέα θέση). Ρίχνει μόνο BerError."""
    limit = len(data) if limit is None else limit
    if depth > MAX_DEPTH:
        raise BerError("υπερβολικό βάθος")
    if pos >= limit:
        raise BerError("κομμένο πακέτο")
    tag = data[pos]
    ln, pos = _dec_len(data, pos + 1, limit)
    end = pos + ln
    if end > limit:
        raise BerError("κομμένο πακέτο")
    body = data[pos:end]
    if tag in CONSTRUCTED:
        items, p = [], pos
        while p < end:
            t, v, p = decode(data, p, depth + 1, end)
            items.append((t, v))
        return tag, items, end
    if tag == INTEGER:
        if not body:
            raise BerError("κενός INTEGER")
        return tag, int.from_bytes(body, "big", signed=True), end
    if tag in UNSIGNED_BITS:
        if not body or len(body) > 9:
            raise BerError("άκυρος μετρητής")
        # μερικά agents στέλνουν μετρητές «με πρόσημο» — κρατάμε τα κάτω bits
        return tag, int.from_bytes(body, "big") & ((1 << UNSIGNED_BITS[tag]) - 1), end
    if tag == OID:
        return tag, _dec_oid(body), end
    if tag == IPADDRESS:
        if len(body) != 4:
            raise BerError("άκυρη IpAddress")
        return tag, socket.inet_ntoa(body), end
    if tag in (NULL, NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
        return tag, None, end
    return tag, bytes(body), end  # OCTET STRING, Opaque, άγνωστοι τύποι: ακατέργαστα bytes


def encode_message(community, pdu_tag, reqid, varbinds, a=0, b=0):
    """varbinds: [(oid, (tag, value))] — για αιτήματα (tag, value) = (NULL, None).
    a/b = error-status/error-index ή, στο GETBULK, non-repeaters/max-repetitions."""
    vbl = [(SEQUENCE, [(OID, parse_oid(o)), tv]) for o, tv in varbinds]
    pdu = (pdu_tag, [(INTEGER, reqid), (INTEGER, a), (INTEGER, b), (SEQUENCE, vbl)])
    return encode(SEQUENCE, [(INTEGER, 1), (OCTET_STRING, community), pdu])


def decode_message(data):
    """bytes → {version, community, pdu, reqid, a, b, varbinds: [(oid, tag, value)]}. Ρίχνει μόνο BerError."""
    try:
        tag, msg, end = decode(bytes(data))
        if tag != SEQUENCE or len(msg) != 3:
            raise BerError("δεν είναι μήνυμα SNMP")
        (vt, ver), (ct, comm), (pt, pdu) = msg
        if vt != INTEGER or ct != OCTET_STRING or pt not in CONSTRUCTED or pt == SEQUENCE or len(pdu) != 4:
            raise BerError("δεν είναι μήνυμα SNMP")
        (t1, reqid), (t2, a), (t3, b), (t4, vbl) = pdu
        if (t1, t2, t3, t4) != (INTEGER, INTEGER, INTEGER, SEQUENCE):
            raise BerError("άκυρο PDU")
        vbs = []
        for t, vb in vbl:
            if t != SEQUENCE or len(vb) != 2 or vb[0][0] != OID:
                raise BerError("άκυρο varbind")
            vbs.append((vb[0][1], vb[1][0], vb[1][1]))
        return {"version": ver, "community": comm, "pdu": pt, "reqid": reqid, "a": a, "b": b, "varbinds": vbs}
    except BerError:
        raise
    except (ValueError, TypeError, IndexError, OSError) as e:  # ό,τι κι αν στείλει, ποτέ crash
        raise BerError(f"άκυρο πακέτο: {e.__class__.__name__}")


# ───────────────────────────── Πελάτης SNMP v2c ─────────────────────────────

MAX_ROWS = 2000


class SnmpClient:
    def __init__(self, host, community="public", port=161, timeout=2.0, retries=1, bulk=True, max_rep=25):
        self.host, self.community, self.port = host, community, int(port)
        self.timeout, self.retries, self.max_rep = float(timeout), max(0, int(retries)), int(max_rep)
        self.bulk_ok, self._bulk_proven = bool(bulk), False

    def __repr__(self):  # χωρίς community
        return f"SnmpClient({self.host}:{self.port})"

    def _request(self, pdu_tag, oids, a=0, b=0):
        reqid = random.randint(1, 0x7FFFFFFF)
        msg = encode_message(self.community, pdu_tag, reqid, [(o, (NULL, None)) for o in oids], a, b)
        fam, _, _, _, addr = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_DGRAM)[0]
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            sock.connect(addr)  # «συνδεδεμένο» UDP: δεχόμαστε απαντήσεις μόνο από τον στόχο
            for _ in range(self.retries + 1):
                sock.send(msg)
                deadline = time.monotonic() + self.timeout
                while True:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        break
                    sock.settimeout(left)
                    try:
                        data = sock.recv(65535)
                    except socket.timeout:
                        break
                    except ConnectionRefusedError:
                        raise SnmpTimeout("η θύρα SNMP είναι κλειστή")
                    try:
                        resp = decode_message(data)
                    except BerError:
                        continue  # σκουπίδια: περιμένουμε την κανονική απάντηση
                    if resp["pdu"] != RESPONSE or resp["reqid"] != reqid:
                        continue  # καθυστερημένη απάντηση σε παλιότερο αίτημα
                    if resp["a"]:
                        raise SnmpError("σφάλμα SNMP: " + ERROR_STATUS.get(resp["a"], str(resp["a"])), resp["a"])
                    return resp["varbinds"]
            raise SnmpTimeout("δεν απάντησε (timeout)")
        except OSError as e:
            raise SnmpTimeout(f"σφάλμα δικτύου: {e.strerror or e.__class__.__name__}")
        finally:
            sock.close()

    def get(self, oids):
        """{oid tuple: τιμή} — None για noSuchObject/noSuchInstance."""
        return {o: (None if t in EXCEPTIONS else v) for o, t, v in self._request(GET, [parse_oid(x) for x in oids])}

    def getnext(self, oids):
        return [(o, t, v) for o, t, v in self._request(GETNEXT, [parse_oid(x) for x in oids])]

    def getbulk(self, oids, non_repeaters=0, max_rep=None):
        return self._request(GETBULK, [parse_oid(x) for x in oids], non_repeaters, max_rep or self.max_rep)

    def walk(self, root, max_rows=MAX_ROWS):
        """[(oid tuple, τιμή)] κάτω από το root. GETBULK, αλλιώς (αν η συσκευή δεν το υποστηρίζει) GETNEXT."""
        root = parse_oid(root)
        out, cur = [], root
        while len(out) < max_rows:
            if self.bulk_ok:
                try:
                    vbs = self.getbulk([cur], 0, max(1, min(self.max_rep, max_rows - len(out))))
                    self._bulk_proven = True
                except SnmpError:
                    if out or self._bulk_proven:
                        raise
                    self.bulk_ok = False  # π.χ. παλιό agent που αγνοεί/απορρίπτει το GETBULK
                    continue
            else:
                try:
                    vbs = self.getnext([cur])
                except SnmpError as e:
                    if e.status == 2:  # noSuchName (στυλ v1) = τέλος του δέντρου
                        break
                    raise
            if not vbs:
                break
            done = False
            for oid, tag, val in vbs:
                if tag == END_OF_MIB_VIEW or oid[:len(root)] != root or oid <= cur:
                    done = True  # τέλος υποδέντρου ή agent που δεν προχωρά (προστασία από ατέρμονο βρόχο)
                    break
                if tag not in EXCEPTIONS:
                    out.append((oid, val))
                cur = oid
                if len(out) >= max_rows:
                    break
            if done:
                break
        return out


def walk(host, oid, community="public", port=161, timeout=2.0, retries=1, max_rows=MAX_ROWS, bulk=True):
    return SnmpClient(host, community, port, timeout, retries, bulk).walk(oid, max_rows)


# ───────────────────────────── MIBs ─────────────────────────────

SYS = {"descr": "1.3.6.1.2.1.1.1.0", "uptime": "1.3.6.1.2.1.1.3.0", "name": "1.3.6.1.2.1.1.5.0", "location": "1.3.6.1.2.1.1.6.0"}
IF_COLS = {  # IF-MIB ifTable (1.3.6.1.2.1.2.2.1) και ifXTable (1.3.6.1.2.1.31.1.1.1)
    "descr": "1.3.6.1.2.1.2.2.1.2", "type": "1.3.6.1.2.1.2.2.1.3", "speed": "1.3.6.1.2.1.2.2.1.5",
    "admin": "1.3.6.1.2.1.2.2.1.7", "oper": "1.3.6.1.2.1.2.2.1.8",
    "in32": "1.3.6.1.2.1.2.2.1.10", "in_disc": "1.3.6.1.2.1.2.2.1.13", "in_err": "1.3.6.1.2.1.2.2.1.14",
    "out32": "1.3.6.1.2.1.2.2.1.16", "out_disc": "1.3.6.1.2.1.2.2.1.19", "out_err": "1.3.6.1.2.1.2.2.1.20",
    "name": "1.3.6.1.2.1.31.1.1.1.1", "in64": "1.3.6.1.2.1.31.1.1.1.6", "out64": "1.3.6.1.2.1.31.1.1.1.10",
    "high_speed": "1.3.6.1.2.1.31.1.1.1.15", "alias": "1.3.6.1.2.1.31.1.1.1.18",
}
HR_CPU = "1.3.6.1.2.1.25.3.3.1.2"            # hrProcessorLoad
HR_STORAGE = "1.3.6.1.2.1.25.2.3.1"          # hrStorageTable: .2 type .4 units .5 size .6 used
HR_RAM_TYPE = (1, 3, 6, 1, 2, 1, 25, 2, 1, 2)  # hrStorageRam
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"          # .5 chassisId .7 portId .8 portDesc .9 sysName (index: timeMark.localPort.remIndex)
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1"     # .3 portId .4 portDesc (index: localPort)
CDP_CACHE = "1.3.6.1.4.1.9.9.23.1.2.1.1"     # .6 deviceId .7 devicePort .8 platform (index: ifIndex.devIndex)
OPER = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}


def _txt(v):
    """OCTET STRING → κείμενο (ή MAC/hex αν δεν είναι εκτυπώσιμο)."""
    if v is None:
        return ""
    if not isinstance(v, (bytes, bytearray)):
        return str(v)
    try:
        s = bytes(v).decode("utf-8").rstrip("\x00")
        if all(c.isprintable() or c in "\r\n\t" for c in s):
            return s.strip()
    except UnicodeDecodeError:
        pass
    if len(v) == 6:
        return ":".join(f"{b:02x}" for b in v)
    return bytes(v).hex()


def _num(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _col(client, oid, max_rows):
    """Μια στήλη πίνακα → {index tuple: τιμή}. Προαιρετικά MIB: αν λείπουν ή «κολλήσουν», απλώς κενό."""
    root = parse_oid(oid)
    try:
        return {o[len(root):]: v for o, v in client.walk(root, max_rows)}
    except SnmpTimeout:
        raise
    except SnmpError:
        return {}


def collect(client, max_rows=MAX_ROWS):
    """Ένας πλήρης έλεγχος μιας συσκευής → «ωμά» δεδομένα (ίδια μορφή με τον προσομοιωτή)."""
    s = client.get(list(SYS.values()))
    if all(v is None for v in s.values()):
        raise SnmpError("η συσκευή δεν δίνει το MIB-2 system")
    g = {k: s.get(parse_oid(o)) for k, o in SYS.items()}
    raw = {"sys": {"descr": _txt(g["descr"]), "name": _txt(g["name"]), "location": _txt(g["location"]),
                   "uptime": _num(g["uptime"])}, "ifs": {}, "cpu": None, "ram": None, "neigh": []}
    cols = {k: _col(client, o, max_rows) for k, o in IF_COLS.items()}
    idxs = set(cols["descr"]) | set(cols["oper"]) | set(cols["name"])
    for idx in sorted(i for i in idxs if len(i) == 1):
        r = {k: cols[k].get(idx) for k in IF_COLS}
        for k in ("descr", "name", "alias"):
            r[k] = _txt(r[k])
        for k in IF_COLS:
            if k not in ("descr", "name", "alias"):
                r[k] = _num(r[k])
        raw["ifs"][idx[0]] = r
    try:
        loads = [v for v in _col(client, HR_CPU, max_rows).values() if _num(v) is not None]
        raw["cpu"] = round(sum(loads) / len(loads), 1) if loads else None
        st = {k: _col(client, f"{HR_STORAGE}.{c}", max_rows) for k, c in (("type", 2), ("units", 4), ("size", 5), ("used", 6))}
        for idx, typ in st["type"].items():
            size, used = _num(st["size"].get(idx)), _num(st["used"].get(idx))
            if typ == HR_RAM_TYPE and size and used is not None:
                raw["ram"] = round(100.0 * used / size, 1)
                break
        rem = {k: _col(client, f"{LLDP_REM}.{c}", max_rows) for k, c in (("chassis", 5), ("port", 7), ("port_desc", 8), ("name", 9))}
        loc = {k: _col(client, f"{LLDP_LOC_PORT}.{c}", max_rows) for k, c in (("id", 3), ("desc", 4))} if rem["name"] or rem["port"] else {}
        for idx in sorted(set(rem["name"]) | set(rem["port"])):
            if len(idx) < 3:
                continue
            lp = idx[1]
            local = _txt(loc["id"].get((lp,))) or _txt(loc["desc"].get((lp,))) or (raw["ifs"].get(lp) or {}).get("name") or str(lp)
            raw["neigh"].append({"proto": "lldp", "local_port": local, "local_ifindex": lp if lp in raw["ifs"] else None,
                                 "remote_name": _txt(rem["name"].get(idx)), "remote_port": _txt(rem["port"].get(idx)),
                                 "remote_port_desc": _txt(rem["port_desc"].get(idx)), "chassis": _txt(rem["chassis"].get(idx))})
        cdp = {k: _col(client, f"{CDP_CACHE}.{c}", max_rows) for k, c in (("name", 6), ("port", 7), ("platform", 8))}
        for idx in sorted(cdp["name"]):
            if len(idx) < 2:
                continue
            i = (raw["ifs"].get(idx[0]) or {})
            raw["neigh"].append({"proto": "cdp", "local_port": i.get("name") or i.get("descr") or str(idx[0]),
                                 "local_ifindex": idx[0] if i else None, "remote_name": _txt(cdp["name"].get(idx)),
                                 "remote_port": _txt(cdp["port"].get(idx)), "remote_port_desc": "",
                                 "chassis": "", "platform": _txt(cdp["platform"].get(idx))})
    except SnmpTimeout:
        pass  # τα βασικά τα έχουμε· τα προαιρετικά θα ξαναδοκιμαστούν στον επόμενο γύρο
    return raw


# ───────────────────────────── Υπολογισμοί ─────────────────────────────

def counter_delta(prev, cur, bits):
    """Διαφορά μετρητή με αναδίπλωση 32-bit. Counter64 που «γύρισε προς τα πίσω» = μηδενισμός → None."""
    if prev is None or cur is None:
        return None
    if cur >= prev:
        return cur - prev
    if bits == 32:
        return cur + (1 << 32) - prev
    return None


def uptime_reset(prev_ticks, cur_ticks, dt):
    """Έπεσε το sysUpTime; (λαμβάνει υπόψη την αναδίπλωση των TimeTicks κάθε ~497 μέρες)."""
    if prev_ticks is None or cur_ticks is None or cur_ticks >= prev_ticks:
        return False
    return not (prev_ticks > (1 << 32) - (dt + 120) * 100 * 2 and cur_ticks < (dt + 120) * 100 * 2)


def fmt_bps(v):
    if v is None:
        return "–"
    for unit, div in (("Gbps", 1e9), ("Mbps", 1e6), ("kbps", 1e3)):
        if v >= div:
            return f"{v / div:.1f} {unit}"
    return f"{int(v)} bps"


def fmt_uptime(sec):
    if sec is None:
        return "–"
    sec = int(sec)
    d, h, m = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    return f"{d}μ {h}ω {m}′" if d else f"{h}ω {m}′"


# ───────────────────────────── Ρυθμίσεις ─────────────────────────────

DEFAULTS = {"enabled": False, "interval": 60, "timeout": 2.0, "retries": 1, "err_threshold": 1.0, "disc_threshold": 10.0,
            "util_threshold": 90.0, "history": 120, "max_rows": MAX_ROWS, "targets": []}
FAILS_FOR_DOWN = 3
UTIL_POLLS = 3


def normalize(cfg):
    c = dict(DEFAULTS)
    c.update({k: v for k, v in dict(cfg or {}).items() if k in DEFAULTS and v is not None})
    targets, seen = [], set()
    for t in list(c.get("targets") or []):
        if not isinstance(t, dict) or not t.get("host"):
            continue
        t = dict(t)
        t["host"] = str(t["host"]).strip()
        t["port"] = int(t.get("port") or 161)
        t["community"] = str(t.get("community") or "public")
        t["name"] = str(t.get("name") or t["host"])[:40]
        t["id"] = f"{t['name']}|{t['host']}|{t['port']}"
        if t["id"] not in seen:
            seen.add(t["id"])
            targets.append(t)
    c["targets"] = targets
    return c


# ───────────────────────────── Προσομοίωση (demo) ─────────────────────────────

def _diurnal(now):
    lt = time.localtime(now)
    h = lt.tm_hour + lt.tm_min / 60
    return 0.08 + 0.6 * math.exp(-((h - 21) / 2.5) ** 2) + 0.3 * math.exp(-((h - 13) / 3) ** 2)


def _flap(now):
    return int(now // 300) % 8 == 5  # 5′ κάτω κάθε 40′: «χαλαρό καλώδιο»


SIM = [
    {"name": "Router", "host": "192.168.1.1", "descr": "RouterOS 7.16 (RB5009)", "sysname": "gw", "location": "Ντουλάπι δικτύου",
     "days": 23.4, "cpu": lambda f: 3 + 9 * f, "ram": lambda f: 31 + 2 * f,
     "ports": [  # idx, όνομα, alias, Mbps, admin, κατάσταση, μέγ. in/out Mbps, σφάλματα/s, 64-bit
         (1, "ether1", "WAN (ISP)", 1000, 1, "up", 300, 40, 0.0, True),
         (2, "ether2", "Switch uplink", 1000, 1, "up", 45, 260, 0.0, True),
         (3, "ether3", "AP σαλόνι", 1000, 1, "up", 12, 70, 0.0, True),
         (4, "ether4", "IoT VLAN", 100, 1, "up", 0.4, 0.6, 0.0, False),
         (5, "ether5", "εφεδρική", 1000, 2, "down", 0, 0, 0.0, True)],
     "neigh": [("ether2", 2, "switch", "Port 1", "Uplink router"), ("ether3", 3, "AP-Salon", "eth0", "")]},
    {"name": "Switch", "host": "192.168.1.2", "descr": "8-Port Gigabit Smart Managed Switch, firmware 1.0.3", "sysname": "sw-core",
     "location": "Ντουλάπι δικτύου", "days": 61.2, "cpu": None, "ram": None,
     "ports": [
         (1, "Port 1", "Uplink router", 1000, 1, "up", 260, 45, 0.0, True),
         (2, "Port 2", "Proxmox", 1000, 1, "up", 90, 160, 0.0, True),
         (3, "Port 3", "NAS", 1000, 1, "up", 120, 60, 0.0, True),
         (4, "Port 4", "PC γραφείου", 1000, 1, "up", 8, 40, 0.0, True),
         (5, "Port 5", "AP γραφείου", 1000, 1, "up", 6, 35, 0.0, True),
         (6, "Port 6", "Τηλεόραση", 100, 1, "flap", 1, 25, 0.3, True),
         (7, "Port 7", "Εκτυπωτής", 100, 1, "down", 0, 0, 0.0, True),
         (8, "Port 8", "", 1000, 2, "down", 0, 0, 0.0, True)],
     "neigh": [("Port 1", 1, "gw", "ether2", "Switch uplink"), ("Port 2", 2, "pve", "enp1s0", "enp1s0"),
               ("Port 5", 5, "AP-Office", "eth0", "")]},
    {"name": "Proxmox", "host": "192.168.1.16", "descr": "Linux pve 6.8.12-4-pve #1 SMP PREEMPT_DYNAMIC x86_64", "sysname": "pve",
     "location": "Ράφι", "days": 9.7, "cpu": lambda f: 10 + 30 * f, "ram": lambda f: 58 + 6 * f,
     "ports": [
         (1, "lo", "", 10, 1, "up", 2, 2, 0.0, True),
         (2, "enp1s0", "", 1000, 1, "up", 160, 90, 0.0, True),
         (3, "vmbr0", "Γέφυρα VM", 1000, 1, "up", 150, 85, 0.0, True),
         (4, "tap100i0", "Home Assistant", 10000, 1, "up", 4, 3, 0.0, True)],
     "neigh": [("enp1s0", 2, "sw-core", "Port 2", "Proxmox")]},
]


class _SimDev:
    def __init__(self, spec, now):
        self.spec, self.boot, self.last = spec, now - spec["days"] * 86400, None
        self.ctr = {p[0]: [random.randint(1, 1 << 40), random.randint(1, 1 << 40), 0.0, 0.0, 0.0, 0.0] for p in spec["ports"]}

    def sample(self, now):
        dt = 0 if self.last is None else max(0.0, now - self.last)
        self.last = now
        f = _diurnal(now)
        sp, ifs = self.spec, {}
        for idx, name, alias, mbps, admin, state, rin, rout, err, hc in sp["ports"]:
            up = admin == 1 and (state == "up" or (state == "flap" and not _flap(now)))
            c = self.ctr[idx]
            if up and dt:
                noise = random.uniform(0.85, 1.15)
                c[0] += rin * 1e6 * f * noise * dt / 8
                c[1] += rout * 1e6 * f * random.uniform(0.85, 1.15) * dt / 8
                c[2] += err * dt * random.uniform(0.5, 1.5)
                c[4] += err * 3 * dt * random.random()
            ifs[idx] = {"descr": name, "name": name, "alias": alias, "type": 24 if name == "lo" else 6,
                        "speed": min(mbps * 1000000, (1 << 32) - 1), "high_speed": mbps, "admin": admin,
                        "oper": 1 if up else 2,
                        "in64": int(c[0]) % (1 << 64) if hc else None, "out64": int(c[1]) % (1 << 64) if hc else None,
                        "in32": int(c[0]) % (1 << 32), "out32": int(c[1]) % (1 << 32),
                        "in_err": int(c[2]) % (1 << 32), "out_err": int(c[3]) % (1 << 32),
                        "in_disc": int(c[4]) % (1 << 32), "out_disc": int(c[5]) % (1 << 32)}
        neigh = [{"proto": "lldp", "local_port": lp, "local_ifindex": li, "remote_name": rn, "remote_port": rp,
                  "remote_port_desc": rd, "chassis": ""} for lp, li, rn, rp, rd in sp["neigh"]]
        return {"sys": {"descr": sp["descr"], "name": sp["sysname"], "location": sp["location"],
                        "uptime": int((now - self.boot) * 100) % (1 << 32)},
                "ifs": ifs, "neigh": neigh,
                "cpu": round(sp["cpu"](f) + random.uniform(-2, 2), 1) if sp["cpu"] else None,
                "ram": round(sp["ram"](f) + random.uniform(-0.5, 0.5), 1) if sp["ram"] else None}


# ───────────────────────────── Poller ─────────────────────────────

class Snmp:
    def __init__(self, state=None, cfg=None, sim=False):
        self.state, self.sim = state, sim
        self.cfg = normalize(cfg)
        self.lock = threading.Lock()
        self._quiet = False
        now = time.time()
        if sim:
            self.cfg["interval"] = 30
            self.cfg["targets"] = normalize({"targets": [{"name": s["name"], "host": s["host"]} for s in SIM]})["targets"]
            self._simdev = {t["id"]: _SimDev(s, now) for t, s in zip(self.cfg["targets"], SIM)}
        self.targets = self.cfg["targets"]
        self.res = {t["id"]: self._blank() for t in self.targets}
        self.clients = {}
        if sim:  # γέμισε το ιστορικό ώστε τα γραφήματα να έχουν κάτι από την αρχή
            self._quiet = True
            n, every = self.cfg["history"], self.cfg["interval"]
            for k in range(n, 0, -1):
                self.round(now=now - k * every)
            self._quiet = False

    @staticmethod
    def _blank():
        return {"ok": None, "error": None, "last_poll": None, "fails": 0, "sys": {}, "uptime_ticks": None,
                "cpu": None, "ram": None, "ifs": {}, "neigh": [], "poll_ms": None}

    # — συλλογή —
    def _client(self, t):
        c = self.clients.get(t["id"])
        if c is None:
            c = self.clients[t["id"]] = SnmpClient(t["host"], t["community"], t["port"], t.get("timeout", self.cfg["timeout"]),
                                                   t.get("retries", self.cfg["retries"]), t.get("bulk", True))
        return c

    def fetch(self, t, now):
        if self.sim:
            return self._simdev[t["id"]].sample(now)
        return collect(self._client(t), int(self.cfg["max_rows"]))

    def round(self, now=None):
        events = []
        for t in self.targets:
            ts = time.time() if now is None else now
            t0 = time.monotonic()
            try:
                raw, err = self.fetch(t, ts), None
            except Exception as e:  # SnmpError, DNS, οτιδήποτε: ποτέ crash του poller
                raw, err = None, (str(e)[:120] or e.__class__.__name__)
            ms = round((time.monotonic() - t0) * 1000, 1)
            with self.lock:
                if raw is None:
                    events += self._fail(t, err, ts)
                else:
                    try:
                        events += self.ingest(t, raw, ts)
                        self.res[t["id"]]["poll_ms"] = ms
                    except Exception as e:
                        events += self._fail(t, f"άκυρα δεδομένα: {e.__class__.__name__}", ts)
        for ev in events:
            self._alert(*ev)
        return events

    def _fail(self, t, err, now):
        r = self.res[t["id"]]
        r["ok"], r["error"], r["fails"] = False, err, r["fails"] + 1
        if r["fails"] == FAILS_FOR_DOWN:
            return [("SNMP χωρίς απάντηση", "med", t, f"Το «{t['name']}» ({t['host']}:{t['port']}) δεν απαντά σε SNMP εδώ και "
                     f"{FAILS_FOR_DOWN} ελέγχους: {err}. Έλεγξε IP, community και ότι το SNMP v2c είναι ενεργό.", (), 3600, now)]
        return []

    def ingest(self, t, raw, now):
        """Νέο δείγμα → ρυθμοί, ιστορικό, ειδοποιήσεις. Επιστρέφει λίστα γεγονότων (καλείται με self.lock)."""
        c, r, ev = self.cfg, self.res[t["id"]], []
        name = t["name"]
        prev_t = r["last_poll"]
        dt = (now - prev_t) if prev_t is not None else None
        up = _num((raw.get("sys") or {}).get("uptime"))
        reboot = bool(dt and dt > 0 and uptime_reset(r["uptime_ticks"], up, dt))
        if reboot:
            ev.append(("Συσκευή επανεκκινήθηκε", "low", t, f"Το «{name}» ({t['host']}) επανεκκινήθηκε: uptime "
                       f"{fmt_uptime(r['uptime_ticks'] / 100)} → {fmt_uptime(up / 100)}.", (), 600, now))
        r.update(ok=True, error=None, fails=0, last_poll=now, uptime_ticks=up, cpu=raw.get("cpu"), ram=raw.get("ram"),
                 neigh=list(raw.get("neigh") or []))
        s = raw.get("sys") or {}
        r["sys"] = {"descr": s.get("descr") or "", "name": s.get("name") or "", "location": s.get("location") or "",
                    "uptime": None if up is None else up // 100}
        hist_n = int(c["history"])
        seen = set()
        for idx, x in sorted((raw.get("ifs") or {}).items()):
            seen.add(idx)
            p = r["ifs"].get(idx)
            if p is None:
                p = r["ifs"][idx] = {"prev": None, "hist": collections.deque(maxlen=hist_n), "util_n": 0,
                                     "down_alerted": False, "since": None, "cur": {}}
            hc = x.get("in64") is not None and x.get("out64") is not None
            bits = 64 if hc else 32
            cin, cout = (x.get("in64"), x.get("out64")) if hc else (x.get("in32"), x.get("out32"))
            errs = [x.get(k) for k in ("in_err", "out_err", "in_disc", "out_disc")]
            hs = x.get("high_speed")
            speed = hs * 1000000 if hs else x.get("speed")
            pv = p["prev"]
            rin = rout = err_s = disc_s = None
            if pv and dt and dt > 0 and not reboot and pv["bits"] == bits:
                di, do = counter_delta(pv["in"], cin, bits), counter_delta(pv["out"], cout, bits)
                rin = None if di is None else di * 8 / dt
                rout = None if do is None else do * 8 / dt
                if speed:  # «αναδίπλωση» που στην πραγματικότητα ήταν μηδενισμός μετρητή: εξωπραγματικός ρυθμός
                    rin = None if rin is not None and rin > speed * 2 else rin
                    rout = None if rout is not None and rout > speed * 2 else rout
                # μετρητής σφαλμάτων που μίκρυνε = «clear counters», όχι αναδίπλωση (4 δισ. σφάλματα δεν γίνονται σε ένα λεπτό)
                de = [counter_delta(a, b, 64) for a, b in zip(pv["errs"], errs)]
                if de[0] is not None or de[1] is not None:
                    err_s = ((de[0] or 0) + (de[1] or 0)) / dt
                if de[2] is not None or de[3] is not None:
                    disc_s = ((de[2] or 0) + (de[3] or 0)) / dt
            p["prev"] = {"in": cin, "out": cout, "bits": bits, "errs": errs}
            ui = round(100.0 * rin / speed, 1) if speed and rin is not None else None
            uo = round(100.0 * rout / speed, 1) if speed and rout is not None else None
            util = max([u for u in (ui, uo) if u is not None], default=None)
            ifn = x.get("name") or x.get("descr") or str(idx)
            old_oper = (p["cur"] or {}).get("oper")
            oper, admin = x.get("oper"), x.get("admin")
            p["cur"] = {"ifindex": idx, "name": ifn, "descr": x.get("descr") or "", "alias": x.get("alias") or "",
                        "type": x.get("type"), "admin": OPER.get(admin, admin and str(admin)), "oper": OPER.get(oper, oper and str(oper)),
                        "speed": speed, "hc": hc, "in_bps": None if rin is None else int(rin),
                        "out_bps": None if rout is None else int(rout), "util_in": ui, "util_out": uo, "util": util,
                        "err_s": None if err_s is None else round(err_s, 2), "disc_s": None if disc_s is None else round(disc_s, 2)}
            p["cur"]["oper_code"], p["cur"]["admin_code"] = oper, admin
            p["hist"].append((round(now, 1), p["cur"]["in_bps"], p["cur"]["out_bps"], p["cur"]["err_s"], p["cur"]["disc_s"], util))
            # — ειδοποιήσεις —
            if old_oper is not None and old_oper != oper:
                if old_oper == "up" and oper in (2, 6, 7) and admin == 1:
                    p["down_alerted"], p["since"] = True, now
                    ev.append(("Θύρα δικτύου έπεσε", "med", t, f"Η θύρα «{ifn}»{' (' + x['alias'] + ')' if x.get('alias') else ''} "
                               f"του «{name}» ({t['host']}) έπεσε (κατάσταση: {OPER.get(oper, oper)}).", (idx,), 300, now))
                elif oper == 1 and p["down_alerted"]:
                    p["down_alerted"] = False
                    ev.append(("Θύρα δικτύου επανήλθε", "low", t, f"Η θύρα «{ifn}» του «{name}» λειτουργεί ξανά "
                               f"(ήταν κάτω {int((now - (p['since'] or now)) / 60)}′).", (idx,), 300, now))
            if (err_s is not None and err_s > c["err_threshold"]) or (disc_s is not None and disc_s > c["disc_threshold"]):
                ev.append(("Σφάλματα σε θύρα", "med", t, f"Η θύρα «{ifn}» του «{name}» έχει {err_s or 0:.1f} σφάλματα/s και "
                           f"{disc_s or 0:.1f} απορρίψεις/s. Έλεγξε καλώδιο, duplex ή υπερφόρτωση.", (idx,), 1800, now))
            p["util_n"] = p["util_n"] + 1 if util is not None and util > c["util_threshold"] else 0
            if p["util_n"] == UTIL_POLLS:
                ev.append(("Θύρα κοντά στο όριο", "low", t, f"Η θύρα «{ifn}» του «{name}» είναι στο {util:.0f}% της ταχύτητάς της "
                           f"({fmt_bps(speed)}) για {UTIL_POLLS} συνεχόμενους ελέγχους.", (idx,), 3600, now))
        for idx in [i for i in r["ifs"] if i not in seen]:
            del r["ifs"][idx]  # η θύρα δεν υπάρχει πια (π.χ. VM που σβήστηκε)
        return ev

    def _alert(self, typ, sev, t, detail, key, cooldown, now):
        if self.state is None or self._quiet:
            return
        try:
            self.state.alert(typ, sev, t["host"], t["name"], detail, now, key=(typ, t["id"]) + tuple(key),
                             cooldown=cooldown, mark=False)
        except Exception:
            pass

    # — για το UI —
    def _find(self, target):
        for t in self.targets:
            if target in (t["id"], t["name"], t["host"]):
                return t
        return None

    def status(self):
        with self.lock:
            out = []
            for t in self.targets:
                r = self.res[t["id"]]
                ifs = []
                for idx, p in sorted(r["ifs"].items()):
                    d = {k: v for k, v in p["cur"].items() if k not in ("oper_code", "admin_code")}
                    d["hist"] = {"t": [h[0] for h in p["hist"]], "in": [h[1] for h in p["hist"]], "out": [h[2] for h in p["hist"]]}
                    ifs.append(d)
                out.append({"id": t["id"], "name": t["name"], "host": t["host"], "port": t["port"], "ok": r["ok"],
                            "error": r["error"], "fails": r["fails"], "last_poll": r["last_poll"], "poll_ms": r["poll_ms"],
                            "sys": dict(r["sys"]), "cpu": r["cpu"], "ram": r["ram"], "interfaces": ifs,
                            "neighbours": [dict(n) for n in r["neigh"]]})
            return {"enabled": bool(self.cfg["enabled"]) or self.sim, "demo": self.sim, "interval": self.cfg["interval"],
                    "targets": out}

    def iface_history(self, target, ifindex):
        t = self._find(target)
        if t is None:
            return None
        with self.lock:
            p = self.res[t["id"]]["ifs"].get(int(ifindex))
            if p is None:
                return None
            h = list(p["hist"])
            return {"target": t["name"], "ifindex": int(ifindex), "name": p["cur"].get("name"), "speed": p["cur"].get("speed"),
                    "t": [x[0] for x in h], "in": [x[1] for x in h], "out": [x[2] for x in h],
                    "err": [x[3] for x in h], "disc": [x[4] for x in h], "util": [x[5] for x in h]}

    def run_forever(self, every=None):
        while True:
            try:
                self.round()
            except Exception:
                pass
            time.sleep(every or self.cfg["interval"])


# ───────────────────────────── CLI ─────────────────────────────

def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Γρήγορη δοκιμή SNMP v2c: sysDescr και πίνακας θυρών.")
    ap.add_argument("host")
    ap.add_argument("community", nargs="?", default="public")
    ap.add_argument("--port", type=int, default=161)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--no-bulk", action="store_true", help="μόνο GETNEXT (για παλιές συσκευές)")
    a = ap.parse_args(argv)
    cl = SnmpClient(a.host, a.community, a.port, a.timeout, 1, not a.no_bulk)
    try:
        raw = collect(cl)
    except SnmpError as e:
        print(f"✗ {a.host}:{a.port}: {e}")
        return 1
    s = raw["sys"]
    print(f"{s['name'] or a.host} — {s['descr']}")
    print(f"Τοποθεσία: {s['location'] or '–'}   Uptime: {fmt_uptime(None if s['uptime'] is None else s['uptime'] / 100)}"
          f"   CPU: {raw['cpu'] if raw['cpu'] is not None else '–'}%   RAM: {raw['ram'] if raw['ram'] is not None else '–'}%"
          f"   ({'GETBULK' if cl.bulk_ok else 'GETNEXT'})")
    print(f"\n{'#':>4}  {'Όνομα':<20} {'Alias':<20} {'Admin':<6} {'Oper':<8} {'Ταχύτητα':>10}  {'In bytes':>16} {'Out bytes':>16}  64b")
    for idx, x in sorted(raw["ifs"].items()):
        hs = x.get("high_speed")
        sp = hs * 1000000 if hs else x.get("speed")
        hc = x.get("in64") is not None
        print(f"{idx:>4}  {(x['name'] or x['descr'])[:20]:<20} {x['alias'][:20]:<20} {OPER.get(x['admin'], '?'):<6} "
              f"{OPER.get(x['oper'], '?'):<8} {fmt_bps(sp):>10}  {str(x['in64'] if hc else x['in32']):>16} "
              f"{str(x['out64'] if hc else x['out32']):>16}  {'✓' if hc else ''}")
    if raw["neigh"]:
        print("\nΓείτονες:")
        for n in raw["neigh"]:
            print(f"  {n['local_port']} → {n['remote_name']} ({n['remote_port_desc'] or n['remote_port']}) [{n['proto'].upper()}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
