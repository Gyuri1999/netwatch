"""🔎 Ασφαλής απαρίθμηση υπηρεσιών (service enumeration) — μόνο ιδιωτικές IP, ΧΩΡΙΣ κωδικούς, ΧΩΡΙΣ exploit.

Για ανοιχτές θύρες που ήδη βρήκε ο σαρωτής κάνουμε μία «χειραψία» πρωτοκόλλου (negotiate) και διαβάζουμε ΜΟΝΟ
τι υποστηρίζει ο server — όπως τα nmap scripts smb-protocols / rdp-ntlm-info, που είναι «safe». Δεν συνδεόμαστε,
δεν στέλνουμε διαπιστευτήρια, δεν στέλνουμε payload. Τα ευρήματα μπαίνουν στο ίδιο (sev, μήνυμα) format με τα TLS.

  • SMB (445):  SMBv1 ενεργό; (EternalBlue/WannaCry) · απαιτείται υπογραφή SMB; (NTLM relay)
  • RDP (3389): απαιτείται NLA; (BlueKeep / brute force στη σελίδα σύνδεσης)
"""
import ipaddress
import socket
import struct


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not a.is_loopback and not a.is_multicast


def _exchange(ip, port, payload, timeout, read=2048):
    """Στέλνει ΕΝΑ πακέτο, διαβάζει την απάντηση, κλείνει. Επιστρέφει bytes ή b""."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(payload)
        chunks, got = [], 0
        while got < read:
            b = s.recv(read - got)
            if not b:
                break
            chunks.append(b)
            got += len(b)
            if got >= 4:  # αρκεί η επικεφαλίδα για να αποφασίσουμε
                break
        return b"".join(chunks)
    except (OSError, socket.timeout):
        return b""
    finally:
        s.close()


# ── SMB (445) ─────────────────────────────────────────────────────────────────
_SMB_DIALECTS = (b"PC NETWORK PROGRAM 1.0", b"LANMAN1.0", b"Windows for Workgroups 3.1a",
                 b"LM1.2X002", b"LANMAN2.1", b"NT LM 0.12", b"SMB 2.002", b"SMB 2.???")


def smb_negotiate_packet():
    body = b"".join(b"\x02" + d + b"\x00" for d in _SMB_DIALECTS)
    smb = (b"\xffSMB" + b"\x72" + b"\x00\x00\x00\x00" + b"\x18" + b"\x01\x28"
           + b"\x00\x00" + b"\x00" * 8 + b"\x00\x00" + b"\xff\xff" + b"\x2f\x4b" + b"\x00\x00" + b"\x00\x00")
    smb += b"\x00" + struct.pack("<H", len(body)) + body  # WordCount=0, ByteCount, dialects
    return struct.pack(">I", len(smb)) + smb  # NetBIOS session header (4 bytes)


def read_smb(resp):
    """→ λίστα ευρημάτων (sev, μήνυμα). resp = ό,τι απάντησε ο server στο negotiate."""
    if len(resp) < 9:
        return []
    body = resp[4:]  # πέρα από το NetBIOS header
    out = []
    if body[:4] == b"\xffSMB":  # ο server απάντησε σε SMBv1
        # WordCount (1 byte) στη θέση 32· αν >0, το πρώτο word είναι ο DialectIndex
        if len(body) >= 37 and body[32] != 0:
            idx = struct.unpack("<H", body[33:35])[0]
            if idx != 0xFFFF:
                out.append(("high", "SMBv1 ενεργό — το παλιό πρωτόκολλο του WannaCry/EternalBlue. Κλείσ' το "
                                    "(Windows: «SMB 1.0/CIFS» · NAS: ρυθμίσεις SMB → ελάχιστο SMBv2)."))
    elif body[:4] == b"\xfeSMB" and len(body) >= 68:  # SMB2/3 negotiate response
        # SMB2 header 64 bytes· NEGOTIATE response: StructureSize(2) μετά SecurityMode(2) → offset 66
        sec = struct.unpack("<H", body[66:68])[0]  # SecurityMode: 0x01 enabled, 0x02 required
        if not (sec & 0x02):
            out.append(("med", "Η υπογραφή SMB δεν είναι υποχρεωτική — επιτρέπει επιθέσεις «NTLM relay». "
                               "Ενεργοποίησε «απαιτείται υπογραφή» (require signing) στον server."))
    return out


def smb_probe(ip, port=445, timeout=1.5, exchange=None):
    ex = exchange or _exchange
    resp = ex(ip, port, smb_negotiate_packet(), timeout)
    return read_smb(resp)


# ── RDP (3389) ────────────────────────────────────────────────────────────────
def rdp_negotiate_packet():
    neg = b"\x01\x00\x08\x00" + struct.pack("<I", 0x03)  # TYPE_RDP_NEG_REQ, requested = TLS|CredSSP
    x224 = b"\xe0" + b"\x00\x00" + b"\x00\x00" + b"\x00" + neg  # CR TPDU
    x224 = bytes([len(x224)]) + x224
    tpkt = b"\x03\x00" + struct.pack(">H", 4 + len(x224))
    return tpkt + x224


def read_rdp(resp):
    if len(resp) < 11 or resp[:2] != b"\x03\x00":
        return []
    neg = resp[11:]  # μετά το TPKT(4)+X.224 CC(7)
    if len(neg) < 8:
        return []
    typ = neg[0]
    val = struct.unpack("<I", neg[4:8])[0]
    if typ == 0x02:  # TYPE_RDP_NEG_RSP: selectedProtocol
        if val == 0x00:
            return [("med", "Το RDP δέχεται «standard RDP security» χωρίς NLA — ευάλωτο σε BlueKeep και σε δοκιμές "
                           "κωδικών. Ενεργοποίησε το «Network Level Authentication» στις ρυθμίσεις απομακρυσμένης επιφάνειας.")]
    elif typ == 0x03 and val == 0x00000002:  # SSL_NOT_ALLOWED_BY_SERVER → μόνο παλιό RDP
        return [("med", "Ο RDP server δεν δέχεται TLS/NLA — μόνο παλιό «standard RDP security». Αναβάθμισε και "
                       "ενεργοποίησε το «Network Level Authentication».")]
    return []


def rdp_probe(ip, port=3389, timeout=1.5, exchange=None):
    ex = exchange or _exchange
    resp = ex(ip, port, rdp_negotiate_packet(), timeout)
    return read_rdp(resp)


PROBES = {445: smb_probe, 3389: rdp_probe}


def enrich_hosts(hosts, timeout=1.5, exchange=None):
    """Για κάθε host με ανοιχτή 445/3389 τρέχει το αντίστοιχο probe και προσθέτει ευρήματα στη service."""
    for h in hosts or ():
        ip = h.get("ip")
        if not ip or not is_private(ip):
            continue
        for sv in h.get("services") or ():
            if sv.get("proto", "tcp") != "tcp":
                continue
            fn = PROBES.get(sv.get("port"))
            if not fn:
                continue
            try:
                found = fn(ip, sv["port"], timeout, exchange)
            except Exception:  # noqa: BLE001 — δικτυακό/parse· η απαρίθμηση δεν πρέπει να ρίξει τη σάρωση
                found = []
            if found:
                sv.setdefault("findings", []).extend(found)
    return hosts
