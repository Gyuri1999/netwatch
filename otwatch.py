"""🏭 Αυτοματισμοί στο δίκτυο (OT): Modbus TCP, BACnet/IP, KNXnet/IP — εντοπισμός και «ποιος γράφει;».

Inverters φωτοβολταϊκών, μετρητές ενέργειας, PLC, κλιματισμός και ελεγκτές κτιρίου μιλούν πρωτόκολλα που
ΔΕΝ έχουν κωδικό: όποιος βρίσκεται στο ίδιο VLAN μπορεί να αλλάξει setpoints ή να ανοίξει μια πόρτα. Εδώ:
  1. Modbus TCP (502): για κάθε γνωστή τοπική συσκευή δοκιμάζουμε σύνδεση και ρωτάμε «ποιος είσαι;»
     (Read Device Identification, FC 0x2B / MEI 0x0E) — και, αν δεν απαντήσει, το SunSpec block (40000) των inverters.
  2. BACnet/IP (UDP 47808): ΕΝΑ Who-Is στο τοπικό broadcast· διαβάζουμε τα I-Am.
  3. KNXnet/IP (UDP 3671): ΕΝΑ SEARCH_REQUEST στο multicast 224.0.23.12· διαβάζουμε τα SEARCH_RESPONSE.
  4. Παθητικά (observe): όταν κάποιος ΓΡΑΦΕΙ σε PLC (Modbus FC 5/6/15/16/22/23) ή σε ελεγκτή BACnet
     (WriteProperty, WritePropertyMultiple, ReinitializeDevice, DeviceCommunicationControl) → ειδοποίηση,
     μία φορά για κάθε νέο ζεύγος «ποιος → σε ποιον» (το SCADA που γράφει κάθε δευτερόλεπτο δεν ενοχλεί).
ΜΟΝΟ ΑΝΑΓΝΩΣΗ: στέλνουμε μόνο FC 1/2/3/4 και 0x2B, ποτέ εγγραφή· μόνο προς ιδιωτικές IP του LAN· timeouts παντού·
ό,τι έρχεται από το δίκτυο ελέγχεται σε μήκος πριν διαβαστεί.
Πηγές: Modbus Application Protocol V1.1b3 + Messaging on TCP/IP V1.0b, ASHRAE 135 Annex J (BVLC) + κεφ. 6/20
(NPDU/APDU), KNX Standard 03_08_02 Core (KNXnet/IP).
"""
import ipaddress
import json
import os
import socket
import struct
import threading
import time

MB_PORT, BAC_PORT, KNX_PORT = 502, 47808, 3671
KNX_MCAST = "224.0.23.12"
MAX_HOSTS = 254
MB_TIMEOUT = 1.2
UNITS = (255, 1, 0)          # 255 = «η ίδια η συσκευή TCP», 1 = το συνηθισμένο, 0 = μερικές συσκευές
POOL = 24
EVERY = 6 * 3600             # αυτόματη επανάληψη (μόνο αφού ο χρήστης κάνει την πρώτη σάρωση)
MAX_DEVICES, MAX_WRITERS, MAX_WRITES, MAX_REPLIES = 500, 2000, 60, 512
PROTOS = ("modbus", "bacnet", "knx")
PLABEL = {"modbus": "Modbus TCP", "bacnet": "BACnet/IP", "knx": "KNXnet/IP"}

# ── Modbus ──
SAFE_FC = frozenset((1, 2, 3, 4, 0x2B))    # ό,τι επιτρέπεται να ΣΤΕΙΛΟΥΜΕ (όλα ανάγνωση)
READ_FC = frozenset((1, 2, 3, 4))
WRITE_FC = {5: ("Write Single Coil", "εγγραφή ενός coil"),
            6: ("Write Single Register", "εγγραφή ενός register"),
            15: ("Write Multiple Coils", "εγγραφή πολλών coils"),
            16: ("Write Multiple Registers", "εγγραφή πολλών registers"),
            22: ("Mask Write Register", "αλλαγή bits ενός register"),
            23: ("Read/Write Multiple Registers", "ανάγνωση + εγγραφή registers")}
KINDS = {"coil": 1, "discrete": 2, "holding": 3, "input": 4}
MB_EXC = {1: "illegal function", 2: "illegal data address", 3: "illegal data value", 4: "server device failure",
          5: "acknowledge", 6: "server device busy", 8: "memory parity error", 10: "gateway path unavailable",
          11: "gateway target device failed to respond"}
DEVID_REQ = bytes((0x2B, 0x0E, 0x01, 0x00))  # Read Device Identification, basic, από το object 0
DEVID_OBJ = {0: "vendor", 1: "product", 2: "rev", 3: "url", 4: "name", 5: "model", 6: "app"}

# ── BACnet ──
WHOIS = bytes.fromhex("810b000c0120ffff00ff1008")  # BVLC original-broadcast · NPDU προς όλα τα δίκτυα · Who-Is
BAC_SEG = {0: "both", 1: "transmit", 2: "receive", 3: "none"}
# από τη λίστα «Assigned Vendor IDs» του bacnet.org (οι πιο συνηθισμένοι σε κτίρια)
BAC_VENDORS = {
    2: "Trane", 3: "Daikin Applied", 5: "Johnson Controls", 6: "ABB (American Auto-Matrix)", 7: "Siemens", 8: "Delta Controls",
    9: "Siemens", 10: "Schneider Electric", 14: "Cimetrics", 16: "Carrier", 17: "Honeywell", 18: "Alerton / Honeywell",
    22: "Siemens", 24: "Automated Logic", 28: "KMC Controls", 35: "Reliable Controls", 36: "Tridium (Niagara)",
    39: "Kieback & Peter", 53: "Daikin", 73: "ABB", 77: "Carel", 80: "Sauter", 82: "Mitsubishi Electric", 85: "Yamatake (Azbil)",
    89: "Saia-Burgess", 90: "Hitachi", 91: "Trend (Novar)", 98: "Toshiba", 99: "Mitsubishi Electric (κλιματισμός)", 105: "Priva",
    112: "Fujitsu", 127: "ABB", 129: "Carrier Japan", 144: "Fujitsu General", 171: "ABB (Cylon)", 178: "LOYTEC",
    190: "Danfoss Drives", 191: "Eaton", 197: "Bosch", 222: "WAGO", 226: "Phoenix Contact", 227: "Grundfos",
    245: "Contemporary Controls", 251: "WILO", 255: "Lennox", 260: "BACnet Stack (ανοιχτός κώδικας)", 264: "Regin",
    284: "Belimo", 300: "Swegon", 313: "Siemens Industry", 332: "Distech Controls", 333: "Novar / Honeywell",
    335: "Schneider Electric", 364: "Distech Controls", 402: "Delta Controls", 415: "Beckhoff", 423: "Belimo",
    432: "LG Electronics", 435: "Delta Electronics", 502: "EasyIO", 767: "Viessmann"}
BAC_WRITE = {15: ("WriteProperty", "εγγραφή ιδιότητας"),
             16: ("WritePropertyMultiple", "εγγραφή πολλών ιδιοτήτων"),
             17: ("DeviceCommunicationControl", "σίγαση/ενεργοποίηση επικοινωνίας της συσκευής"),
             20: ("ReinitializeDevice", "επανεκκίνηση / επαναφορά της συσκευής")}
BAC_ALWAYS = (17, 20)   # αυτά είναι σπάνια και σοβαρά — ειδοποίηση ακόμη κι από γνωστό «συγγραφέα»
BAC_OBJ = {0: "analog-input", 1: "analog-output", 2: "analog-value", 3: "binary-input", 4: "binary-output",
           5: "binary-value", 6: "calendar", 8: "device", 10: "file", 12: "loop", 13: "multi-state-input",
           14: "multi-state-output", 15: "notification-class", 17: "schedule", 19: "multi-state-value", 20: "trend-log"}
BAC_PROP = {85: "present-value", 81: "out-of-service", 87: "priority-array", 104: "relinquish-default", 77: "object-name",
            28: "description", 123: "weekly-schedule", 38: "exception-schedule", 59: "low-limit", 45: "high-limit"}
BAC_REINIT = {0: "coldstart", 1: "warmstart", 2: "start-backup", 3: "end-backup", 4: "start-restore", 5: "end-restore",
              6: "abort-restore", 7: "activate-changes"}
BAC_DCC = {0: "enable", 1: "disable", 2: "disable-initiation"}

# ── KNX ──
KNX_FAMILIES = {2: "Core", 3: "Device Management", 4: "Tunnelling", 5: "Routing", 6: "Remote Logging",
                7: "Remote Configuration", 8: "Object Server", 9: "Security"}
KNX_MEDIUM = {0x01: "reserved", 0x02: "TP1", 0x04: "PL110", 0x10: "RF", 0x20: "KNX IP"}


def is_private(ip):
    """Μόνο ιδιωτική/link-local IPv4 του LAN (όχι loopback, multicast, broadcast, 0.0.0.0)."""
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return (a.version == 4 and a.is_private and not a.is_loopback and not a.is_multicast and not a.is_unspecified
            and not a.is_reserved)


def _clean(b, cap=64):
    """Κείμενο από συσκευή: χωρίς χαρακτήρες ελέγχου, με όριο."""
    s = b.decode("latin-1", "replace") if isinstance(b, (bytes, bytearray)) else str(b)
    return "".join(c if 32 <= ord(c) < 127 or ord(c) > 160 else " " for c in s.split("\x00", 1)[0]).strip()[:cap]


# ═════════════════════════════ Modbus: πλαίσια ═════════════════════════════
def mbap(tid, unit, pdu):
    """PDU → ADU με επικεφαλίδα MBAP (transaction, protocol=0, length=unit+PDU, unit). ΜΟΝΟ function codes ανάγνωσης."""
    if not pdu or pdu[0] not in SAFE_FC or len(pdu) > 253:
        raise ValueError("μόνο ανάγνωση (FC 1/2/3/4/0x2B)")
    return struct.pack(">HHHB", tid & 0xFFFF, 0, len(pdu) + 1, unit & 0xFF) + bytes(pdu)


def parse_mbap(data, tid=None):
    """ADU → (transaction, unit, PDU) ή None. Αυστηρά: protocol 0, length 2…254, ολόκληρο το PDU παρόν."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 8:
        return None
    t, pid, ln, unit = struct.unpack(">HHHB", bytes(data[:7]))
    if pid != 0 or ln < 2 or ln > 254 or len(data) < 6 + ln:
        return None
    if tid is not None and t != tid & 0xFFFF:
        return None
    return t, unit, bytes(data[7:6 + ln])


def read_req(fc, addr, count):
    if fc not in READ_FC:
        raise ValueError("μόνο FC 1/2/3/4")
    if not (0 <= addr <= 0xFFFF and 1 <= count <= 125 and addr + count <= 0x10000):
        raise ValueError("διεύθυνση/πλήθος εκτός ορίων")
    return struct.pack(">BHH", fc, addr, count)


def parse_read(fc, pdu, count):
    """Απάντηση FC 1/2/3/4 → λίστα τιμών (bits 0/1 ή registers 0…65535) ή None αν το μήκος δεν ταιριάζει."""
    if not pdu or len(pdu) < 2 or pdu[0] != fc:
        return None
    bc = pdu[1]
    if fc in (1, 2):
        if bc != (count + 7) // 8 or len(pdu) != 2 + bc:
            return None
        return [pdu[2 + i // 8] >> (i % 8) & 1 for i in range(count)]
    if bc != 2 * count or len(pdu) != 2 + bc:
        return None
    return list(struct.unpack(">%dH" % count, pdu[2:]))


def parse_exception(pdu):
    """PDU σφάλματος (FC|0x80, κωδικός) → κωδικός ή None."""
    if pdu and len(pdu) == 2 and pdu[0] & 0x80:
        return pdu[1]
    return None


def parse_devid(pdu):
    """Απάντηση Read Device Identification → {"vendor","product","rev",…} ή None."""
    # FC, MEI, ReadDevId code, conformity, more follows, next object id, number of objects, [id, len, value]…
    if not pdu or len(pdu) < 7 or pdu[0] != 0x2B or pdu[1] != 0x0E:
        return None
    n, o, out = pdu[6], 7, {}
    for _ in range(min(n, 16)):
        if o + 2 > len(pdu):
            break
        oid, ln = pdu[o], pdu[o + 1]
        if o + 2 + ln > len(pdu):
            break
        if oid in DEVID_OBJ:
            v = _clean(pdu[o + 2:o + 2 + ln])
            if v:
                out[DEVID_OBJ[oid]] = v
        o += 2 + ln
    return out


def parse_sunspec(regs):
    """Registers 40000… (SunS + Common Model 1) → {"vendor","model","rev","serial"} ή None."""
    if not regs or len(regs) < 68 or regs[0] != 0x5375 or regs[1] != 0x6E53 or regs[2] != 1:
        return None

    def s(a, n):
        return _clean(struct.pack(">%dH" % n, *regs[a:a + n]), 32)
    out = {"vendor": s(4, 16), "model": s(20, 16), "rev": s(44, 8), "serial": s(52, 16)}
    return {k: v for k, v in out.items() if v} or None


def decode_registers(addr, regs):
    """Registers → γραμμές (unsigned, signed, hex) και ζεύγη 32-bit (int/float, και με τις δύο σειρές λέξεων)."""
    def flt(hi, lo):
        x = struct.unpack(">f", struct.pack(">HH", hi, lo))[0]
        return float("%.7g" % x) if x == x and abs(x) != float("inf") else None

    rows = []
    for i, v in enumerate(regs):
        r = {"addr": addr + i, "u16": v, "s16": v - 0x10000 if v & 0x8000 else v, "hex": "%04X" % v}
        if i + 1 < len(regs):
            w = regs[i + 1]
            be, le = v << 16 | w, w << 16 | v
            r.update(u32=be, u32_sw=le, s32=be - (1 << 32) if be >> 31 else be, s32_sw=le - (1 << 32) if le >> 31 else le,
                     f32=flt(v, w), f32_sw=flt(w, v))
        rows.append(r)
    return rows


def mb_sniff(pl, plen=None):
    """Αίτημα Modbus (πρώτο ADU ενός TCP segment προς :502) → {"unit","fc","write",…} ή None.
    `pl` μπορεί να είναι κομμένο (128 bytes πλαισίου)· `plen` = το πραγματικό μήκος του TCP payload."""
    if len(pl) < 8:
        return None
    _tid, pid, ln, unit, fc = struct.unpack(">HHHBB", bytes(pl[:8]))
    if pid != 0 or ln < 2 or ln > 254:
        return None
    if (len(pl) if plen is None else plen) < 6 + ln:
        return None
    d = bytes(pl[8:])
    if fc in READ_FC:
        if ln != 6 or len(d) < 4:
            return None
        a, q = struct.unpack(">HH", d[:4])
        return {"unit": unit, "fc": fc, "write": False, "addr": a, "qty": q}
    if fc not in WRITE_FC:
        return None
    out = {"unit": unit, "fc": fc, "write": True}
    if fc in (5, 6):
        if ln != 6 or len(d) < 4:
            return None
        a, v = struct.unpack(">HH", d[:4])
        if fc == 5 and v not in (0x0000, 0xFF00):
            return None
        out.update(addr=a, qty=1, value=v)
    elif fc in (15, 16):
        if len(d) < 5:
            return None
        a, q, bc = struct.unpack(">HHB", d[:5])
        ok = (1 <= q <= 1968 and bc == (q + 7) // 8) if fc == 15 else (1 <= q <= 123 and bc == 2 * q)
        if not ok or ln != 7 + bc:
            return None
        out.update(addr=a, qty=q)
        if fc == 16 and q == 1 and len(d) >= 7:
            out["value"] = d[5] << 8 | d[6]
    elif fc == 22:
        if ln != 8 or len(d) < 6:
            return None
        a, am, om = struct.unpack(">HHH", d[:6])
        out.update(addr=a, qty=1, and_mask=am, or_mask=om)
    else:  # 23: read addr, read qty, write addr, write qty, byte count
        if len(d) < 9:
            return None
        _ra, rq, wa, wq, bc = struct.unpack(">HHHHB", d[:9])
        if not (1 <= rq <= 125 and 1 <= wq <= 121 and bc == 2 * wq and ln == 11 + bc):
            return None
        out.update(addr=wa, qty=wq)
    return out


# ═════════════════════════════ BACnet/IP: πλαίσια ═════════════════════════════
def _bac_apdu(data, plen=None):
    """BVLC + NPDU → (APDU, snet, sadr) ή None. Το μήκος του BVLC πρέπει να ταιριάζει ακριβώς με το UDP payload."""
    n = len(data)
    if n < 8 or data[0] != 0x81:
        return None
    fn, ln = data[1], data[2] << 8 | data[3]
    if ln != (n if plen is None else plen):
        return None
    if fn == 0x04:              # Forwarded-NPDU: 6 bytes αρχική διεύθυνση B/IP
        o = 10
    elif fn in (0x0A, 0x0B, 0x09):  # Original-Unicast / Original-Broadcast / Distribute-Broadcast-To-Network
        o = 4
    else:
        return None
    if n < o + 2 or data[o] != 0x01:
        return None
    ctl = data[o + 1]
    o += 2
    if ctl & 0x80:              # μήνυμα επιπέδου δικτύου, όχι APDU
        return None
    snet, sadr = None, ""
    if ctl & 0x20:              # DNET(2) DLEN(1) DADR(DLEN)
        if n < o + 3:
            return None
        o += 3 + data[o + 2]
    if ctl & 0x08:              # SNET(2) SLEN(1) SADR(SLEN)
        if n < o + 3:
            return None
        sl = data[o + 2]
        if n < o + 3 + sl:
            return None
        snet, sadr = data[o] << 8 | data[o + 1], bytes(data[o + 3:o + 3 + sl]).hex()
        o += 3 + sl
    if ctl & 0x20:
        o += 1                  # hop count
    if o >= n:
        return None
    return bytes(data[o:]), snet, sadr


def _bac_tag(b, o, tag, maxlen=4):
    """Application tag με μικρό μήκος → (ακέραια τιμή, επόμενη θέση) ή None."""
    if o >= len(b):
        return None
    t = b[o]
    ln = t & 7
    if t >> 4 != tag or t & 8 or not 1 <= ln <= maxlen or o + 1 + ln > len(b):
        return None
    return int.from_bytes(b[o + 1:o + 1 + ln], "big"), o + 1 + ln


def parse_iam(data):
    """Πακέτο BACnet/IP με I-Am → {"instance","max_apdu","seg","vendor_id","vendor","snet","sadr"} ή None."""
    try:
        r = _bac_apdu(data)
        if not r:
            return None
        a, snet, sadr = r
        if len(a) < 2 or a[0] != 0x10 or a[1] != 0x00:  # Unconfirmed-Request, service 0 = I-Am
            return None
        t = _bac_tag(a, 2, 12)                           # ObjectIdentifier (πάντα 4 bytes)
        if not t or a[2] != 0xC4 or t[0] >> 22 != 8:     # τύπος 8 = device
            return None
        inst = t[0] & 0x3FFFFF
        m = _bac_tag(a, t[1], 2)                         # max APDU length accepted (Unsigned)
        s = m and _bac_tag(a, m[1], 9, 1)                # segmentation supported (Enumerated)
        v = s and _bac_tag(a, s[1], 2, 2)                # vendor id (Unsigned16)
        if not v or s[0] > 3:
            return None
        return {"instance": inst, "max_apdu": m[0], "seg": BAC_SEG[s[0]], "vendor_id": v[0],
                "vendor": BAC_VENDORS.get(v[0]) or "vendor #%d" % v[0], "snet": snet, "sadr": sadr}
    except Exception:  # noqa: BLE001 — πακέτο από το δίκτυο
        return None


def bac_sniff(pl, plen=None):
    """Confirmed-Request που αλλάζει κάτι (WriteProperty κ.λπ.) → {"svc","obj","prop","arg"} ή None."""
    r = _bac_apdu(pl, plen)
    if not r:
        return None
    a = r[0]
    if len(a) < 4 or a[0] & 0xF0:        # PDU type 0 = Confirmed-Request
        return None
    o = 3
    if a[0] & 0x08:                      # segmented: sequence number, proposed window size
        if len(a) < 6 or a[3] != 0:      # μόνο το πρώτο κομμάτι έχει τις παραμέτρους
            return None
        o = 5
    svc = a[o]
    if svc not in BAC_WRITE:
        return None
    out, p = {"svc": svc, "obj": "", "prop": "", "arg": ""}, a[o + 1:]
    if svc in (15, 16) and len(p) >= 5 and p[0] == 0x0C:          # [0] ObjectIdentifier
        oid = int.from_bytes(p[1:5], "big")
        out["obj"] = "%s %d" % (BAC_OBJ.get(oid >> 22) or "object-type-%d" % (oid >> 22), oid & 0x3FFFFF)
        if svc == 15 and len(p) >= 7 and p[5] in (0x19, 0x1A):    # [1] PropertyIdentifier
            pid = p[6] if p[5] == 0x19 else (int.from_bytes(p[6:8], "big") if len(p) >= 8 else None)
            if pid is not None:
                out["prop"] = BAC_PROP.get(pid) or "property-%d" % pid
    elif svc == 20 and len(p) >= 2 and p[0] == 0x09:              # [0] reinitialized-state-of-device
        out["arg"] = BAC_REINIT.get(p[1]) or "state-%d" % p[1]
    elif svc == 17:                                              # [0] time-duration (προαιρετικό), [1] enable-disable
        q = p[2:] if len(p) >= 2 and p[0] == 0x09 else p[3:] if len(p) >= 3 and p[0] == 0x0A else p
        if len(q) >= 2 and q[0] == 0x19:
            out["arg"] = BAC_DCC.get(q[1]) or "mode-%d" % q[1]
    return out


# ═════════════════════════════ KNXnet/IP: πλαίσια ═════════════════════════════
def knx_search_req(ip, port):
    """SEARCH_REQUEST (0x0201): header 6 bytes + HPAI «πού να απαντήσεις» (IPv4 UDP, ip, port) = 14 bytes."""
    return (bytes((0x06, 0x10, 0x02, 0x01, 0x00, 0x0E, 0x08, 0x01)) + socket.inet_aton(ip)
            + struct.pack(">H", port & 0xFFFF))


def parse_knx_search(data):
    """SEARCH_RESPONSE (0x0202) → {"addr","name","serial","mac","medium","families",…} ή None."""
    try:
        n = len(data)
        if n < 14 + 54 or data[0] != 0x06 or data[1] != 0x10 or data[2] != 0x02 or data[3] != 0x02:
            return None
        if data[4] << 8 | data[5] != n or data[6] != 0x08:   # συνολικό μήκος ακριβώς · HPAI control endpoint
            return None
        out, o = {"ctrl_ip": socket.inet_ntoa(bytes(data[8:12])), "ctrl_port": data[12] << 8 | data[13],
                  "families": []}, 14
        seen = False
        for _ in range(8):                                   # DIBs: μήκος, τύπος, δεδομένα
            if o + 2 > n:
                break
            ln, typ = data[o], data[o + 1]
            if ln < 2 or o + ln > n:
                return None
            d = bytes(data[o + 2:o + ln])
            if typ == 0x01 and ln == 54:                     # DEVICE_INFO
                ia = d[2] << 8 | d[3]
                out.update(medium=KNX_MEDIUM.get(d[0]) or "0x%02x" % d[0], prog=bool(d[1] & 1),
                           addr="%d.%d.%d" % (ia >> 12, ia >> 8 & 15, ia & 255), project=d[4] << 8 | d[5],
                           serial=d[6:12].hex(), mcast=socket.inet_ntoa(d[12:16]),
                           mac=":".join("%02x" % x for x in d[16:22]), name=_clean(d[22:52], 30))
                seen = True
            elif typ == 0x02:                                # SUPP_SVC_FAMILIES: ζεύγη (οικογένεια, έκδοση)
                for i in range(0, min(len(d) - 1, 32), 2):
                    out["families"].append({"id": d[i], "ver": d[i + 1], "name": KNX_FAMILIES.get(d[i]) or "0x%02x" % d[i]})
            o += ln
        if not seen:
            return None
        ids = {f["id"] for f in out["families"]}
        out.update(tunnelling=4 in ids, routing=5 in ids, secure=9 in ids)
        return out
    except Exception:  # noqa: BLE001 — πακέτο από το δίκτυο
        return None


# ═════════════════════════════ πού αρχίζει το payload μέσα στο πλαίσιο ═════════════════════════════
def _try_ip(raw, o, proto, sp, dp):
    n = len(raw)
    if n < o + 20:
        return None
    v = raw[o] >> 4
    if v == 4:
        ihl = (raw[o] & 15) * 4
        if ihl < 20 or raw[o + 9] != proto or (raw[o + 6] & 0x1F) << 8 | raw[o + 7]:  # όχι 2ο+ κομμάτι fragment
            return None
        tot = raw[o + 2] << 8 | raw[o + 3]
        l4, l4len = o + ihl, (tot - ihl) if tot else None    # tot=0: segmentation offload → άγνωστο
    elif v == 6:
        if n < o + 40 or raw[o + 6] != proto:                 # χωρίς extension headers
            return None
        l4, l4len = o + 40, (raw[o + 4] << 8 | raw[o + 5]) or None
    else:
        return None
    hl = 20 if proto == 6 else 8
    if n < l4 + hl:
        return None
    if raw[l4] << 8 | raw[l4 + 1] != sp or raw[l4 + 2] << 8 | raw[l4 + 3] != dp:  # οι θύρες επιβεβαιώνουν τη θέση
        return None
    if proto == 6:
        hl = (raw[l4 + 12] >> 4) * 4
        if hl < 20:
            return None
    else:
        ul = raw[l4 + 4] << 8 | raw[l4 + 5]
        if ul < 8 or (l4len is not None and ul > l4len):
            return None
        l4len = ul
    if l4len is None:
        return bytes(raw[l4 + hl:]), None
    plen = l4len - hl
    if plen <= 0:
        return None
    return bytes(raw[l4 + hl:l4 + hl + plen]), plen


def l4_payload(raw, proto, sp, dp):
    """Πρώτα bytes ενός πλαισίου (το P["_raw"] του capture.py) → (payload, πραγματικό μήκος payload) ή None.
    Ethernet II (και με 802.1Q/QinQ), αλλιώς σκέτο IP / Linux cooked / BSD loopback. `proto`: 6=TCP, 17=UDP.
    Το πραγματικό μήκος βγαίνει από την επικεφαλίδα IP (όχι από το padding του Ethernet ή το κόψιμο στα 128)."""
    if not raw or sp is None or dp is None:
        return None
    n, cands = len(raw), []
    if n >= 14:
        o = 12
        for _ in range(3):
            et = raw[o] << 8 | raw[o + 1]
            if et in (0x8100, 0x88A8, 0x9100) and n >= o + 6:
                o += 4
                continue
            if et in (0x0800, 0x86DD):
                cands.append(o + 2)
            break
    for o in cands + [0, 16, 4]:
        r = _try_ip(raw, o, proto, sp, dp)
        if r:
            return r
    return None


# ═════════════════════════════ πραγματικό δίκτυο ═════════════════════════════
class _MbConn:
    def __init__(self, sock, timeout):
        self.s, self.timeout = sock, timeout

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            c = self.s.recv(n - len(buf))
            if not c:
                raise OSError("η σύνδεση έκλεισε")
            buf += c
        return buf

    def xfer(self, frame):
        """Στέλνει ένα ADU και επιστρέφει την απάντηση με το ίδιο transaction id (b"" αν δεν ήρθε)."""
        self.s.sendall(frame)
        try:
            for _ in range(3):  # προσπερνάμε καθυστερημένες απαντήσεις σε προηγούμενο αίτημα
                h = self._recv(7)
                ln = h[4] << 8 | h[5]
                if h[2] or h[3] or ln < 2 or ln > 254:
                    raise OSError("όχι Modbus")
                data = h + self._recv(ln - 1)
                if data[:2] == frame[:2]:
                    return data
        except socket.timeout:
            pass
        return b""

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


class Net:
    """Τα πραγματικά πακέτα — μόνο προς το τοπικό LAN."""

    def modbus_open(self, ip, timeout=MB_TIMEOUT):
        if not is_private(ip):
            raise ValueError("μόνο ιδιωτική IP")
        s = socket.create_connection((ip, MB_PORT), timeout=timeout)
        s.settimeout(timeout)
        return _MbConn(s, timeout)

    def broadcasts(self):
        """Διευθύνσεις broadcast των δικών μας ιδιωτικών υποδικτύων (αλλιώς το τοπικό 255.255.255.255)."""
        out = []
        try:
            import netkit
            for i in netkit.iface_info().get("interfaces") or []:
                if not i.get("up", True):
                    continue
                for a in i.get("ipv4") or []:
                    if not is_private(a.get("addr")):
                        continue
                    b = a.get("broadcast")
                    if not b and a.get("prefix") is not None:
                        b = str(ipaddress.ip_network("%s/%s" % (a["addr"], a["prefix"]), strict=False).broadcast_address)
                    if b and b not in out and (is_private(b) or b == "255.255.255.255"):
                        out.append(b)
        except Exception:  # noqa: BLE001
            pass
        return out[:8] or ["255.255.255.255"]

    @staticmethod
    def _collect(s, timeout):
        out, end = [], time.time() + timeout
        while time.time() < end and len(out) < MAX_REPLIES:
            try:
                data, addr = s.recvfrom(1500)
            except socket.timeout:
                continue
            except OSError:
                break
            out.append((addr[0], data))
        return out

    def bacnet_whois(self, timeout=2.5):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                s.bind(("", BAC_PORT))  # τα I-Am συνήθως έρχονται ως broadcast στη θύρα 47808, όχι στη δική μας
            except OSError:
                s.bind(("", 0))
            s.settimeout(0.4)
            for b in self.broadcasts():
                try:
                    s.sendto(WHOIS, (b, BAC_PORT))
                except OSError:
                    pass
            return self._collect(s, timeout)
        finally:
            s.close()

    def knx_search(self, timeout=2.5):
        local = None
        try:  # ποια δική μας IP «βλέπει» το multicast (δεν στέλνει πακέτο)
            p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                p.connect((KNX_MCAST, KNX_PORT))
                local = p.getsockname()[0]
            finally:
                p.close()
        except OSError:
            pass
        if not is_private(local):
            return []
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)  # δεν φεύγει από το τοπικό δίκτυο
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
            except OSError:
                pass
            s.bind((local, 0))
            s.settimeout(0.4)
            s.sendto(knx_search_req(local, s.getsockname()[1]), (KNX_MCAST, KNX_PORT))
            return self._collect(s, timeout)
        finally:
            s.close()


# ═════════════════════════════ κίνδυνος ═════════════════════════════
def risk(d):
    """→ (high/med/low, γιατί στα ελληνικά, why in English)."""
    p = d.get("proto")
    if p == "modbus":
        if not d.get("confirmed"):
            return ("med", "Η θύρα 502 είναι ανοιχτή αλλά η συσκευή δεν απάντησε σε Modbus. Αν είναι PLC/μετρητής, ισχύει ό,τι "
                    "και για το Modbus: καμία προστασία. Έλεγξε τι είναι.",
                    "Port 502 is open but the device did not answer Modbus. If it is a PLC/meter, the same applies as for "
                    "Modbus: no protection. Check what it is.")
        return ("high", "Το Modbus δεν έχει ΚΑΘΟΛΟΥ κωδικό ή κρυπτογράφηση: όποιος βρίσκεται σε αυτό το VLAN μπορεί να διαβάσει "
                "μετρήσεις και να αλλάξει setpoints, όρια ισχύος ή να σταματήσει τη συσκευή.",
                "Modbus has NO password or encryption at all: anyone on this VLAN can read values and change setpoints, "
                "power limits or stop the device.")
    if p == "bacnet":
        return ("med", "BACnet/IP χωρίς BACnet/SC: δεν υπάρχει ταυτοποίηση — όποιος βρίσκεται στο δίκτυο μπορεί να διαβάσει όλα "
                "τα σημεία και να στείλει WriteProperty (θερμοκρασίες, προγράμματα, εντολές) ή επανεκκίνηση.",
                "BACnet/IP without BACnet/SC: there is no authentication — anyone on the network can read every point and "
                "send WriteProperty (temperatures, schedules, commands) or a restart.")
    if p == "knx":
        if (d.get("tunnelling") or d.get("routing")) and not d.get("secure"):
            how = "tunnelling" if d.get("tunnelling") else "routing"
            return ("high", f"Το KNX {how} είναι ανοιχτό χωρίς KNX Secure: όποιος βρίσκεται στο LAN μπορεί με το ETS ή ένα "
                    "κινητό να ανάψει/σβήσει φώτα, να κινήσει ρολά και να ανοίξει πόρτες — και να αναπρογραμματίσει συσκευές.",
                    f"KNX {how} is open without KNX Secure: anyone on the LAN can use ETS or a phone to switch lights, move "
                    "blinds and open doors — and reprogram devices.")
        if d.get("tunnelling") or d.get("routing"):
            return ("med", "Η συσκευή υποστηρίζει KNX Secure — βεβαιώσου στο ETS ότι το ασφαλές tunnelling/routing είναι "
                    "ΥΠΟΧΡΕΩΤΙΚΟ και ότι το απλό (χωρίς κωδικό) είναι κλειστό.",
                    "The device supports KNX Secure — make sure in ETS that secure tunnelling/routing is REQUIRED and the "
                    "plain (password-less) mode is off.")
        return ("low", "Συσκευή KNX IP χωρίς tunnelling/routing — μόνο διαχείριση. Κράτα τη σε ξεχωριστό VLAN.",
                "KNX IP device without tunnelling/routing — management only. Keep it on a separate VLAN.")
    return "low", "", ""


def title(d):
    p = d.get("proto")
    if p == "modbus":
        t = " ".join(x for x in (d.get("vendor"), d.get("model") or d.get("product") or d.get("name")) if x)
        return t or ("Συσκευή Modbus (χωρίς ταυτότητα)" if d.get("confirmed") else "Θύρα 502 ανοιχτή")
    if p == "bacnet":
        return "%s · device %s" % (d.get("vendor") or "BACnet", d.get("instance"))
    return d.get("name") or "KNX IP"


def _dev(key, proto, ip, port, **kw):
    return dict({"key": key, "proto": proto, "ip": ip, "port": port}, **kw)


DEMO_DEVICES = [
    _dev("modbus:192.168.1.60", "modbus", "192.168.1.60", 502, confirmed=True, unit=1, vendor="Fronius", model="Symo 10.0-3-M",
         rev="3.28.1-3", serial="29301000987654321", sunspec=True),
    _dev("modbus:192.168.1.61", "modbus", "192.168.1.61", 502, confirmed=True, unit=1, vendor="Carlo Gavazzi Controls",
         product="EM24-DIN AV2", rev="1.4"),
    _dev("modbus:192.168.1.64", "modbus", "192.168.1.64", 502, confirmed=True, unit=255),
    _dev("bacnet:192.168.1.70:120001", "bacnet", "192.168.1.70", 47808, instance=120001, max_apdu=1476, seg="both",
         vendor_id=7, vendor="Siemens", snet=None, sadr=""),
    _dev("bacnet:192.168.1.71:4001", "bacnet", "192.168.1.71", 47808, instance=4001, max_apdu=480, seg="none",
         vendor_id=53, vendor="Daikin", snet=None, sadr=""),
    _dev("knx:192.168.1.80", "knx", "192.168.1.80", 3671, addr="1.1.250", name="KNX IP Interface 731", serial="00c501023a7f",
         mac="00:24:6d:01:3a:7f", medium="TP1", prog=False, mcast="224.0.23.12", tunnelling=True, routing=False, secure=False,
         families=[{"id": 2, "ver": 1, "name": "Core"}, {"id": 3, "ver": 1, "name": "Device Management"},
                   {"id": 4, "ver": 1, "name": "Tunnelling"}]),
]
DEMO_FLOATS = (230.4, 229.8, 231.1, 4.52, 3.98, 5.07, 2874.0, 50.01)


class OtWatch:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time, net=None):
        self.state, self.demo, self.clock = state, demo, clock
        self.net = net or Net()
        self.path = os.path.join(data_dir, "ot.json") if data_dir else None
        self.on_save = None
        self.lock = threading.Lock()
        self.rlock = threading.Lock()   # ένα «διάβασε registers» τη φορά
        self.busy = False
        self.error = None
        self.scanned = 0
        self.devices = {}    # κλειδί → εγγραφή συσκευής (με "last")
        self.known = {}      # κλειδί → πρώτη φορά που την είδαμε
        self.writers = {}    # "proto|src|dst" → πρώτη φορά που είδαμε αυτή την πηγή να γράφει εκεί
        self.writes = []     # πρόσφατες εγγραφές (συγκεντρωμένες ανά πηγή/στόχο/εντολή)
        self._dirty, self._saved = False, None
        if demo:
            self._demo()
        else:
            self._load()

    # ── αποθήκευση ──
    def _demo(self):
        now = self.clock()
        self.scanned = now
        for i, d in enumerate(DEMO_DEVICES):
            self.devices[d["key"]] = dict(d, last=now)
            self.known[d["key"]] = now - (40 - 6 * i) * 86400
        self.known["modbus:192.168.1.64"] = now - 2 * 3600
        ev = self._mb_event("192.168.1.23", "192.168.1.60", {"unit": 1, "fc": 16, "addr": 40232, "qty": 2}, now - 1500, True)
        ev2 = self._bac_event("192.168.1.10", "192.168.1.70", {"svc": 15, "obj": "analog-value 3", "prop": "present-value",
                                                              "arg": ""}, now - 40, False)
        ev2.update(n=412, first=now - 5 * 86400)
        self.writes = [ev, ev2]
        self.writers = {"bacnet|192.168.1.10|192.168.1.70": now - 5 * 86400, "modbus|192.168.1.23|192.168.1.60": now - 1500}

    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                j = json.load(f)
            self.known = {str(k): float(v) for k, v in list((j.get("known") or {}).items())[:MAX_DEVICES * 4]}
            self.writers = {str(k): float(v) for k, v in list((j.get("writers") or {}).items())[:MAX_WRITERS]}
            self.scanned = float(j.get("scanned") or 0)
            for k, d in list((j.get("devices") or {}).items())[:MAX_DEVICES]:
                if isinstance(d, dict) and d.get("proto") in PROTOS and is_private(d.get("ip")):
                    self.devices[str(k)] = d
            self.writes = [w for w in (j.get("writes") or []) if isinstance(w, dict) and "src" in w and "dst" in w][-MAX_WRITES:]
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save(self):
        self._dirty, self._saved = False, self.clock()
        if not self.path or self.demo:
            return
        try:
            with self.lock:
                blob = json.dumps({"known": self.known, "writers": self.writers, "scanned": self.scanned,
                                   "devices": self.devices, "writes": self.writes}, ensure_ascii=False)
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(blob)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except Exception:  # noqa: BLE001 — ο δίσκος δεν πρέπει να ρίξει τη σύλληψη πακέτων
            pass

    def flush(self, force=True):
        """Γράφει στον δίσκο ό,τι έμαθε η παθητική παρακολούθηση (το πολύ μία φορά ανά 2s όταν force=False)."""
        if not self._dirty:
            return
        now = self.clock()
        if force or self._saved is None or now - self._saved >= 2 or now < self._saved:
            self._save()

    # ── συσκευές από το state ──
    def _hosts(self):
        st = self.state
        if st is None:
            return []
        lock = getattr(st, "lock", None)
        try:
            if lock:
                lock.acquire()
            return [dict(h) for h in (getattr(st, "hosts", None) or {}).values() if isinstance(h, dict) and h.get("kind") == "local"]
        finally:
            if lock:
                lock.release()

    def _devices(self):
        st, out = self.state, {}
        for h in self._hosts():
            try:
                dt = st._dtype(h) if hasattr(st, "_dtype") else {}
            except Exception:  # noqa: BLE001
                dt = {}
            names = sorted(h.get("names") or ())
            out[h.get("ip")] = {"name": dt.get("alias") or (names[0] if names else h.get("rdns") or h.get("ip")),
                                "dtype": dt.get("dtype") or "", "dicon": dt.get("dicon") or "", "vendor": dt.get("vendor") or "",
                                "me": bool(h.get("me"))}
        return out

    def _name(self, ip, devs=None):
        d = (devs if devs is not None else self._devices()).get(ip) or {}
        n = d.get("name")
        return f"{n} ({ip})" if n and n != ip else str(ip)

    # ── Modbus: ενεργή ανάγνωση ──
    @staticmethod
    def _txn(conn, tid, unit, pdu):
        """Ένα αίτημα ανάγνωσης → PDU απάντησης (κανονικό ή σφάλματος) ή None."""
        r = parse_mbap(conn.xfer(mbap(tid, unit, pdu)), tid)  # το mbap() αρνείται οτιδήποτε δεν είναι ανάγνωση
        if not r or not r[2] or r[2][0] & 0x7F != pdu[0]:
            return None
        return r[2]

    def _probe_modbus(self, ip):
        if not is_private(ip):
            return None
        try:
            c = self.net.modbus_open(ip, MB_TIMEOUT)
        except Exception:  # noqa: BLE001 — κλειστή θύρα / δεν απαντά
            return None
        d = _dev("modbus:" + ip, "modbus", ip, MB_PORT, confirmed=False)
        try:
            tid = 1
            for unit in UNITS:
                pdu = self._txn(c, tid, unit, DEVID_REQ)
                tid += 1
                if pdu is None:
                    continue
                d.update(confirmed=True, unit=unit)  # και μια απάντηση σφάλματος αποδεικνύει ότι μιλάει Modbus
                exc = parse_exception(pdu)
                if exc in (10, 11):                  # πύλη Modbus χωρίς συσκευή σε αυτό το unit → δοκίμασε το επόμενο
                    d["gateway"] = True
                    continue
                if exc is None:
                    d.update(parse_devid(pdu) or {})
                break
            if d["confirmed"] and not d.get("vendor"):
                pdu = self._txn(c, tid, d["unit"], read_req(3, 40000, 68))
                ss = parse_sunspec(parse_read(3, pdu, 68)) if pdu else None
                if ss:
                    d.update(ss, sunspec=True)
        except Exception:  # noqa: BLE001 — η σύνδεση έσπασε στη μέση: κράτα ό,τι μάθαμε
            pass
        finally:
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass
        return d

    def _targets(self):
        ips = {h.get("ip") for h in self._hosts() if not h.get("me")}
        ips = [ip for ip in ips if is_private(ip)]
        return sorted(ips, key=lambda x: tuple(int(p) for p in x.split(".")))[:MAX_HOSTS]

    def _discover(self):
        """→ (λίστα συσκευών, λίστα σφαλμάτων). Μόνο ανάγνωση."""
        found, errs = [], []
        try:
            ips = self._targets()
            if ips:
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=min(POOL, len(ips))) as ex:
                    found += [d for d in ex.map(self._probe_modbus, ips) if d]
        except Exception as e:  # noqa: BLE001
            errs.append("Modbus: " + str(e)[:120])
        try:
            seen = set()
            for ip, data in list(self.net.bacnet_whois())[:MAX_REPLIES]:
                if not is_private(ip):
                    continue
                r = parse_iam(data)
                k = r and "bacnet:%s:%d" % (ip, r["instance"])
                if r and k not in seen:
                    seen.add(k)
                    found.append(_dev(k, "bacnet", ip, BAC_PORT, **r))
        except Exception as e:  # noqa: BLE001
            errs.append("BACnet: " + str(e)[:120])
        try:
            seen = set()
            for ip, data in list(self.net.knx_search())[:MAX_REPLIES]:
                if not is_private(ip) or ip in seen:
                    continue
                r = parse_knx_search(data)
                if r:
                    seen.add(ip)
                    found.append(_dev("knx:" + ip, "knx", ip, KNX_PORT, **r))
        except Exception as e:  # noqa: BLE001
            errs.append("KNX: " + str(e)[:120])
        return found, errs

    def scan(self):
        """Πλήρης σάρωση (Modbus + BACnet + KNX), αποθήκευση, ειδοποίηση για νέες συσκευές. → view()."""
        with self.lock:
            was, self.busy = self.busy, True
        if was:
            return self.view()
        try:
            now = self.clock()
            if self.demo:
                self.scanned = now
                return self.view()
            found, errs = self._discover()
            now = self.clock()
            first = not self.scanned
            fresh = []
            with self.lock:
                for d in found[:MAX_DEVICES]:
                    old = self.devices.get(d["key"]) or {}
                    if d["proto"] == "modbus" and not d.get("vendor") and old.get("vendor"):
                        d = dict(old, **d)          # κράτα την ταυτότητα από προηγούμενη σάρωση
                    d["last"] = now
                    d.pop("passive", None)
                    self.devices[d["key"]] = d
                    if d["key"] not in self.known:
                        self.known[d["key"]] = now
                        fresh.append(d)
                while len(self.devices) > MAX_DEVICES:  # κράτα τις πιο πρόσφατες
                    self.devices.pop(min(self.devices, key=lambda k: self.devices[k].get("last") or 0))
                self.scanned = now
                self.error = ("Κάποιος έλεγχος απέτυχε — " + " · ".join(errs)) if errs else None
            if not first:
                self._alert_new(fresh, now)
            self._save()
        except Exception as e:  # noqa: BLE001
            self.error = "Η σάρωση OT απέτυχε: " + str(e)[:160]
        finally:
            self.busy = False
        return self.view()

    def _alert_new(self, fresh, now):
        st = self.state
        if self.demo or st is None or not hasattr(st, "alert"):
            return
        devs = self._devices()
        for d in fresh:
            lvl, why, _en = risk(d)
            try:
                st.alert("Νέα συσκευή αυτοματισμού (OT)", "med", d["ip"], PLABEL[d["proto"]],
                         f"Νέα συσκευή {PLABEL[d['proto']]} στο δίκτυο: {title(d)} στο {self._name(d['ip'], devs)}. {why}",
                         now, key=("ot", d["key"]), cooldown=24 * 3600, mark=False)
            except Exception:  # noqa: BLE001
                pass

    # ── παθητικά: ποιος γράφει; ──
    def observe(self, P, t=None):
        """Κλήση για κάθε πακέτο. Πολύ φθηνό για ό,τι δεν είναι προς 502/47808· ποτέ δεν πετάει εξαίρεση."""
        try:
            dp = P.get("dp")
            if dp != MB_PORT and dp != BAC_PORT:
                return
            proto = P.get("proto")
            if dp == MB_PORT and proto == "TCP":
                self._obs_modbus(P, t)
            elif dp == BAC_PORT and proto == "UDP":
                self._obs_bacnet(P, t)
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _raw(P):
        """Τα πρώτα bytes του πλαισίου: P["_raw"] (capture.py) — αλλιώς, επειδή το NetState.process() το αφαιρεί πριν
        από το detect(), το ίδιο πακέτο (ίδιο _id) από τη μνήμη του packets.py."""
        raw = P.get("_raw")
        if raw is None and P.get("_id") is not None:
            import packets
            it = packets.get(P.get("src"), P.get("dst"), pid=P["_id"])
            if it and not it.get("approx"):
                raw = it.get("raw")
        return raw

    def _obs_modbus(self, P, t):
        r = l4_payload(self._raw(P), 6, P.get("sp"), MB_PORT)
        if not r or not r[0]:
            return
        m = mb_sniff(r[0], r[1])
        if not m:
            return
        src, dst = P.get("src"), P.get("dst")
        if not src or not dst:
            return
        t = t if t is not None else (P.get("t") or self.clock())
        key = "modbus:" + dst
        if key not in self.devices and is_private(dst):   # συσκευή που φάνηκε στην κίνηση, χωρίς καμία σάρωση
            self._passive(_dev(key, "modbus", dst, MB_PORT, confirmed=True, unit=m["unit"], passive=True), t)
        if m["write"]:
            new = self._writer("modbus", src, dst, t)
            ev = self._mb_event(src, dst, m, t, new)
            self._log_write(ev)
            if new:
                self._alert_write("Εγγραφή σε PLC (Modbus)", "high", ev, t)

    def _obs_bacnet(self, P, t):
        r = l4_payload(self._raw(P), 17, P.get("sp"), BAC_PORT)
        if not r or not r[0]:
            return
        m = bac_sniff(r[0], r[1])
        if not m:
            return
        src, dst = P.get("src"), P.get("dst")
        if not src or not dst:
            return
        t = t if t is not None else (P.get("t") or self.clock())
        new = self._writer("bacnet", src, dst, t)
        ev = self._bac_event(src, dst, m, t, new)
        self._log_write(ev)
        if new:
            self._alert_write("Εγγραφή σε ελεγκτή κτιρίου (BACnet)", "high", ev, t)
        elif m["svc"] in BAC_ALWAYS:
            self._alert_write("Εγγραφή σε ελεγκτή κτιρίου (BACnet)", "med", ev, t, cooldown=600, sub=m["svc"])

    def _passive(self, d, t):
        with self.lock:
            if d["key"] in self.devices or len(self.devices) >= MAX_DEVICES:
                return
            d["last"] = t
            self.devices[d["key"]] = d
            fresh = d["key"] not in self.known
            if fresh:
                self.known[d["key"]] = t
            self._dirty = True
        if fresh and self.scanned:
            self._alert_new([d], t)
        self.flush(False)

    def _writer(self, proto, src, dst, t):
        """True αν αυτή η πηγή δεν έχει ξαναγράψει σε αυτόν τον στόχο (και τη μαθαίνει)."""
        k = f"{proto}|{src}|{dst}"
        if k in self.writers:
            return False
        with self.lock:
            if k in self.writers:
                return False
            if len(self.writers) >= MAX_WRITERS:  # πλημμύρα από ψεύτικες πηγές: δεν μαθαίνουμε άλλες
                return True
            self.writers[k] = t
            self._dirty = True
        return True

    def _mb_event(self, src, dst, m, t, new):
        fc = m["fc"]
        en, el = WRITE_FC[fc]
        what = f"διεύθυνση {m.get('addr')}, πλήθος {m.get('qty')}"
        what_en = f"address {m.get('addr')}, quantity {m.get('qty')}"
        if "value" in m:
            what += f", τιμή {m['value']}"
            what_en += f", value {m['value']}"
        if fc == 22:
            what += " (AND 0x%04X, OR 0x%04X)" % (m.get("and_mask", 0), m.get("or_mask", 0))
            what_en += " (AND 0x%04X, OR 0x%04X)" % (m.get("and_mask", 0), m.get("or_mask", 0))
        return {"t": t, "first": t, "n": 1, "new": bool(new), "proto": "modbus", "src": src, "dst": dst, "fc": fc, "fn": en,
                "unit": m.get("unit"), "addr": m.get("addr"), "qty": m.get("qty"),
                "what": f"{en} (FC {fc}, {el}) · unit {m.get('unit')} · {what}",
                "what_en": f"{en} (FC {fc}) · unit {m.get('unit')} · {what_en}"}

    def _bac_event(self, src, dst, m, t, new):
        en, el = BAC_WRITE[m["svc"]]
        extra = " · ".join(x for x in (m.get("obj"), m.get("prop"), m.get("arg")) if x)
        return {"t": t, "first": t, "n": 1, "new": bool(new), "proto": "bacnet", "src": src, "dst": dst, "fc": m["svc"], "fn": en,
                "what": f"{en} ({el})" + (f" · {extra}" if extra else ""),
                "what_en": en + (f" · {extra}" if extra else "")}

    def _log_write(self, ev):
        with self.lock:
            for w in reversed(self.writes):
                if w.get("src") == ev["src"] and w.get("dst") == ev["dst"] and w.get("proto") == ev["proto"] \
                        and w.get("fc") == ev["fc"]:
                    w.update(t=ev["t"], n=int(w.get("n") or 1) + 1, what=ev["what"], what_en=ev["what_en"],
                             addr=ev.get("addr"), qty=ev.get("qty"), unit=ev.get("unit"))
                    break
            else:
                self.writes.append(ev)
                del self.writes[:-MAX_WRITES]
                self._dirty = True
        if ev["new"]:
            self.flush(False)

    def _alert_write(self, typ, sev, ev, t, cooldown=3600, sub=""):
        st = self.state
        if self.demo or st is None or not hasattr(st, "alert"):
            return
        devs = self._devices()
        src, dst = ev["src"], ev["dst"]
        if ev["proto"] == "modbus":
            det = (f"Η συσκευή {self._name(src, devs)} έστειλε εντολή εγγραφής Modbus στο {self._name(dst, devs)}: {ev['what']}. "
                   "Πρώτη φορά βλέπω αυτή την πηγή να γράφει σε αυτή τη συσκευή. Το Modbus δεν έχει κωδικό — αν δεν είναι το "
                   "SCADA/HMI ή ο τεχνικός σου, βρες ποιος είναι και κλείσε τη θύρα 502 με ACL.")
        elif ev["new"]:
            det = (f"Η συσκευή {self._name(src, devs)} έστειλε εντολή BACnet που αλλάζει κάτι στο {self._name(dst, devs)}: "
                   f"{ev['what']}. Πρώτη φορά βλέπω αυτή την πηγή να γράφει σε αυτόν τον ελεγκτή. Το BACnet/IP δεν έχει "
                   "ταυτοποίηση — αν δεν είναι το BMS ή ο τεχνικός σου, βρες ποιος είναι.")
        else:
            det = (f"Η συσκευή {self._name(src, devs)} έστειλε στο {self._name(dst, devs)} την εντολή BACnet {ev['what']}. "
                   "Η πηγή είναι γνωστή, αλλά η εντολή αυτή σταματά ή επανεκκινεί τον ελεγκτή — βεβαιώσου ότι ήταν προγραμματισμένη.")
        try:
            st.alert(typ, sev, src, dst, det, t, key=("otw", ev["proto"], src, dst, sub), cooldown=cooldown)
        except Exception:  # noqa: BLE001
            pass

    def forget(self, src, dst):
        """Ξέχνα έναν «γνωστό συγγραφέα» (την επόμενη φορά που θα γράψει θα ξαναειδοποιήσει)."""
        n = 0
        with self.lock:
            for p in ("modbus", "bacnet"):
                n += self.writers.pop(f"{p}|{src}|{dst}", None) is not None
            self.writes = [w for w in self.writes if not (w.get("src") == src and w.get("dst") == dst)]
            self._dirty = True
        self.flush()
        return n

    # ── «διάβασε registers» ──
    @staticmethod
    def _int(v, lo, hi, what):
        if isinstance(v, bool) or isinstance(v, float) and v != int(v):
            raise ValueError(what)
        try:
            n = int(v, 0) if isinstance(v, str) else int(v)
        except (TypeError, ValueError):
            raise ValueError(what)
        if not lo <= n <= hi:
            raise ValueError(what)
        return n

    def read(self, ip, unit=1, kind="holding", addr=0, count=10):
        """Ανάγνωση registers/coils από ιδιωτική IP. → dict με "ok" (και "error"/"error_en" αν απέτυχε)."""
        def bad(el, en):
            return {"ok": False, "invalid": True, "error": el, "error_en": en}
        if not isinstance(ip, str) or not is_private(ip.strip()):
            return bad("Μόνο ιδιωτική IP του τοπικού δικτύου (π.χ. 192.168.1.60).", "Private LAN IP only (e.g. 192.168.1.60).")
        ip = ip.strip()
        if kind not in KINDS:
            return bad("Τύπος: holding, input, coil ή discrete.", "Type: holding, input, coil or discrete.")
        try:
            unit = self._int(unit, 0, 255, "unit")
            addr = self._int(addr, 0, 65535, "addr")
            count = self._int(count, 1, 125, "count")
        except ValueError as e:
            lim = {"unit": "0–255", "addr": "0–65535", "count": "1–125"}[str(e)]
            return bad(f"Το πεδίο {e} πρέπει να είναι ακέραιος {lim}.", f"Field {e} must be an integer {lim}.")
        if addr + count > 65536:
            return bad("Διεύθυνση + πλήθος ξεπερνούν το 65535.", "Address + count exceed 65535.")
        fc = KINDS[kind]
        base = {"ok": True, "ip": ip, "unit": unit, "kind": kind, "fc": fc, "addr": addr, "count": count, "demo": self.demo}
        if self.demo:
            vals = self._demo_values(fc, addr, count)
        else:
            if not self.rlock.acquire(False):
                return {"ok": False, "error": "Γίνεται ήδη άλλη ανάγνωση — δοκίμασε σε λίγο.", "error_en": "Another read is running — try again shortly."}
            try:
                try:
                    c = self.net.modbus_open(ip, 1.5)
                except Exception:  # noqa: BLE001
                    return {"ok": False, "error": f"Δεν συνδέθηκα στο {ip}:502 (κλειστή θύρα ή δεν απαντά).",
                            "error_en": f"Could not connect to {ip}:502 (port closed or no answer)."}
                try:
                    pdu = self._txn(c, 1, unit, read_req(fc, addr, count))
                except Exception:  # noqa: BLE001
                    pdu = None
                finally:
                    try:
                        c.close()
                    except Exception:  # noqa: BLE001
                        pass
            finally:
                self.rlock.release()
            if pdu is None:
                return {"ok": False, "error": f"Η συσκευή δεν απάντησε για unit {unit} — δοκίμασε άλλο unit id (1, 255, ή τη διεύθυνση του slave πίσω από την πύλη).",
                        "error_en": f"No answer for unit {unit} — try another unit id (1, 255, or the slave address behind the gateway)."}
            exc = parse_exception(pdu)
            if exc is not None:
                nm = MB_EXC.get(exc) or "unknown"
                hint = {2: (" Αυτή η διεύθυνση δεν υπάρχει — δες τον πίνακα registers του κατασκευαστή (προσοχή: 40001 στο εγχειρίδιο = διεύθυνση 0).",
                            " That address does not exist — check the vendor's register map (note: 40001 in the manual = address 0)."),
                        1: (" Η συσκευή δεν υποστηρίζει αυτόν τον τύπο ανάγνωσης.", " The device does not support this read type.")}.get(exc, ("", ""))
                return {"ok": False, "exception": exc, "error": f"Η συσκευή απάντησε με σφάλμα Modbus {exc:02d} ({nm}).{hint[0]}",
                        "error_en": f"The device answered with Modbus exception {exc:02d} ({nm}).{hint[1]}"}
            vals = parse_read(fc, pdu, count)
            if vals is None:
                return {"ok": False, "error": "Η απάντηση είχε λάθος μήκος — την αγνόησα.", "error_en": "The reply had the wrong length — ignored."}
        if fc in (1, 2):
            base["bits"] = [{"addr": addr + i, "bit": v} for i, v in enumerate(vals)]
        else:
            base["rows"] = decode_registers(addr, vals)
        return base

    @staticmethod
    def _demo_values(fc, addr, count):
        if fc in (1, 2):
            return [1 if (addr + i) % 3 == 0 else 0 for i in range(count)]
        words = []
        for x in DEMO_FLOATS:
            words += struct.unpack(">HH", struct.pack(">f", x))
        return [words[(addr + i) % len(words)] for i in range(count)]

    # ── προβολή ──
    def view(self):
        devs = self._devices()
        with self.lock:
            items = [dict(d) for d in self.devices.values()]
            writes = [dict(w) for w in self.writes]
            nwr = len(self.writers)
        rows = []
        for d in items:
            lvl, why, why_en = risk(d)
            d.update(level=lvl, why=why, why_en=why_en, title=title(d), since=self.known.get(d["key"]),
                     dev=devs.get(d["ip"]), stale=bool(self.scanned and not d.get("passive") and (d.get("last") or 0) < self.scanned))
            rows.append(d)
        order = {"high": 0, "med": 1, "low": 2}
        rows.sort(key=lambda x: (PROTOS.index(x["proto"]), order.get(x["level"], 3),
                                 tuple(int(p) for p in x["ip"].split(".")), x["key"]))
        for w in writes:
            w["src_name"], w["dst_name"] = (devs.get(w["src"]) or {}).get("name") or "", (devs.get(w["dst"]) or {}).get("name") or ""
        writes.sort(key=lambda w: -(w.get("t") or 0))
        counts = {p: sum(1 for x in rows if x["proto"] == p) for p in PROTOS}
        counts.update({k: sum(1 for x in rows if x["level"] == k) for k in ("high", "med")})
        return {"demo": self.demo, "scanned": self.scanned, "busy": self.busy, "devices": rows, "counts": counts,
                "writes": writes[:30], "writers": nwr, "hosts": len(self._targets()) if not self.demo else 0,
                "error": self.error}

    def api(self, method, sub, q, body):
        body = body if isinstance(body, dict) else {}
        if method == "GET":
            return (200, self.view()) if sub == "" else (404, {"error": "not found"})
        if method != "POST":
            return 404, {"error": "not found"}
        if sub == "scan":
            if self.demo:
                return 200, self.scan()
            if not self.busy:
                threading.Thread(target=self.scan, daemon=True, name="ot-scan").start()
            return 200, dict(self.view(), busy=True)
        if sub == "read":
            r = self.read(body.get("ip"), body.get("unit", 1), body.get("kind", "holding"), body.get("addr", 0),
                          body.get("count", 10))
            return (400 if r.pop("invalid", False) else 200), r
        if sub == "forget":
            src, dst = body.get("src"), body.get("dst")
            if not isinstance(src, str) or not isinstance(dst, str):
                return 400, {"error": "src/dst"}
            self.forget(src[:64], dst[:64])
            return 200, self.view()
        return 404, {"error": "not found"}

    def run_forever(self):
        """Γράφει κάθε 30s ό,τι έμαθε η παθητική παρακολούθηση· ξανασαρώνει κάθε 6 ώρες ΜΟΝΟ αφού ο χρήστης έχει
        πατήσει μία φορά «Σάρωση» (δεν ξεκινάμε μόνοι μας να ρωτάμε PLC που δεν μας ζήτησε κανείς)."""
        while True:
            time.sleep(30)
            try:
                self.flush()
                if not self.demo and self.scanned and self.clock() - self.scanned >= EVERY:
                    self.scan()
            except Exception:  # noqa: BLE001
                pass
