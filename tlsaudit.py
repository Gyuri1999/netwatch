"""NetWatch — 🔐 Έλεγχος ρυθμίσεων TLS / SSH των συσκευών του LAN (ιδέα: testssl.sh / ssh-audit).

* SSH: διαβάζουμε το banner, στέλνουμε το δικό μας KEXINIT και διαβάζουμε το KEXINIT του server
  (λίστες αλγορίθμων kex / host key / ciphers / MACs). Κλείνουμε πριν από οποιαδήποτε ανταλλαγή κλειδιών.
* TLS: ποιες εκδόσεις (1.0 / 1.1 / 1.2 / 1.3) δέχεται, πιστοποιητικό (θέμα, εκδότης, λήξη, self-signed,
  τύπος/μέγεθος κλειδιού, αλγόριθμος υπογραφής, SAN).
* Βαθμός A–F ανά υπηρεσία με αιτιολόγηση στα ελληνικά.

Μόνο ιδιωτικές IPv4 (ίδιοι κανόνες με τον σαρωτή: pentest.check_target). Καμία εκμετάλλευση —
μόνο οι ίδιες χειραψίες που κάνει κάθε κανονικός client.
"""
import json
import os
import re
import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from core import log

SSH_PORTS = {22, 2222}
TLS_PORTS = {443, 465, 636, 853, 993, 995, 5001, 5986, 8006, 8443, 8883, 9443, 10000}
MAX_TARGETS = 64
TIMEOUT = 3.0
CLIENT_BANNER = b"SSH-2.0-NetWatch_audit\r\n"
SEV_PTS = {"high": 40, "med": 10, "low": 5, "info": 0}

# ---------------- SSH ----------------
WEAK_KEX = {
    "diffie-hellman-group1-sha1": ("high", "Ανταλλαγή κλειδιών με ομάδα 1024-bit και SHA-1 (σπασμένη — Logjam)"),
    "diffie-hellman-group14-sha1": ("med", "Ανταλλαγή κλειδιών με SHA-1"),
    "diffie-hellman-group-exchange-sha1": ("med", "Group exchange με SHA-1 (ο server μπορεί να δώσει μικρή ομάδα)"),
    "rsa1024-sha1": ("high", "RSA 1024-bit με SHA-1"),
    "gss-gex-sha1-": ("med", "GSS με SHA-1"),
    "gss-group1-sha1-": ("high", "GSS με ομάδα 1024-bit"),
}
WEAK_HOSTKEY = {
    "ssh-dss": ("high", "Κλειδί DSA (1024-bit, καταργημένο από το OpenSSH 7.0)"),
    "ssh-rsa": ("med", "Υπογραφές ssh-rsa με SHA-1 (καταργημένες από το OpenSSH 8.8)"),
    "ssh-rsa-cert-v01@openssh.com": ("med", "Πιστοποιητικά ssh-rsa με SHA-1"),
    "ssh-dss-cert-v01@openssh.com": ("high", "Πιστοποιητικά DSA"),
}
WEAK_CIPHER_EXACT = {
    "none": ("high", "Χωρίς κρυπτογράφηση (none)"),
    "3des-cbc": ("high", "3DES (64-bit block — Sweet32)"),
    "des-cbc": ("high", "DES (σπασμένο)"),
    "des-cbc@ssh.com": ("high", "DES (σπασμένο)"),
    "blowfish-cbc": ("high", "Blowfish (64-bit block)"),
    "cast128-cbc": ("high", "CAST-128 (64-bit block)"),
    "idea-cbc": ("high", "IDEA (64-bit block)"),
}
WEAK_MAC_EXACT = {
    "hmac-md5": ("high", "MAC με MD5"), "hmac-md5-96": ("high", "MAC με MD5 (96-bit)"),
    "hmac-md5-etm@openssh.com": ("high", "MAC με MD5"), "hmac-md5-96-etm@openssh.com": ("high", "MAC με MD5"),
    "hmac-sha1-96": ("med", "MAC με SHA-1 κομμένο στα 96 bit"), "hmac-sha1-96-etm@openssh.com": ("med", "MAC με SHA-1 (96-bit)"),
    "hmac-ripemd160": ("low", "MAC με RIPEMD-160 (παλιό)"), "hmac-ripemd160@openssh.com": ("low", "MAC με RIPEMD-160"),
    "umac-64@openssh.com": ("low", "MAC 64-bit (μικρό tag)"), "umac-64-etm@openssh.com": ("low", "MAC 64-bit (μικρό tag)"),
    "hmac-sha1": ("low", "MAC με SHA-1 (ακόμα ασφαλές ως HMAC, αλλά παλιό)"),
    "none": ("high", "Χωρίς έλεγχο ακεραιότητας (none)"),
}


def weak_cipher(name):
    if name in WEAK_CIPHER_EXACT:
        return WEAK_CIPHER_EXACT[name]
    if name.startswith("arcfour"):
        return ("high", "RC4 / arcfour (σπασμένο)")
    if name.endswith("-cbc") or name == "rijndael-cbc@lysator.liu.se":
        return ("med", "Λειτουργία CBC (ευάλωτη σε επιθέσεις τύπου plaintext recovery)")
    return None


def weak_kex(name):
    for k, v in WEAK_KEX.items():
        if name == k or (k.endswith("-") and name.startswith(k)):
            return v
    return None


def _string(buf, off):
    (n,) = struct.unpack_from(">I", buf, off)
    off += 4
    if off + n > len(buf):
        raise ValueError("κομμένο πακέτο SSH")
    return buf[off:off + n], off + n


def parse_kexinit(payload):
    """payload SSH_MSG_KEXINIT (ξεκινά με το byte 20) → dict με τις λίστες αλγορίθμων."""
    if not payload or payload[0] != 20:
        raise ValueError("δεν είναι KEXINIT")
    off = 17  # 1 byte τύπος + 16 bytes cookie
    keys = ("kex", "hostkey", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c", "lang_c2s", "lang_s2c")
    out = {}
    for k in keys:
        raw, off = _string(payload, off)
        out[k] = [x for x in raw.decode("ascii", "replace").split(",") if x]
    return out


def packet_payload(data):
    """Ακατέργαστα bytes (μετά το banner) → payload του πρώτου binary packet ή None αν δεν έφτασε ολόκληρο."""
    if len(data) < 5:
        return None
    plen, pad = struct.unpack_from(">IB", data, 0)
    if plen > 35000 or plen < pad + 1:
        raise ValueError("μη έγκυρο πακέτο SSH")
    if len(data) < 4 + plen:
        return None
    return data[5:4 + plen - pad]


def build_kexinit():
    """Το KEXINIT του client (σύγχρονοι αλγόριθμοι — δεν θα φτάσουμε ποτέ σε πραγματική ανταλλαγή κλειδιών)."""
    lists = ["curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,"
             "diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
             "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss",
             "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,3des-cbc",
             "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,3des-cbc",
             "hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-md5",
             "hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-md5",
             "none", "none", "", ""]
    body = bytes([20]) + os.urandom(16)
    for s in lists:
        b = s.encode()
        body += struct.pack(">I", len(b)) + b
    body += b"\x00" + b"\x00\x00\x00\x00"
    pad = 8 - ((len(body) + 5) % 8)
    if pad < 4:
        pad += 8
    return struct.pack(">IB", len(body) + pad + 1, pad) + body + os.urandom(pad)


def ssh_software(banner):
    """'SSH-2.0-OpenSSH_7.4p1 Debian' → ('OpenSSH', '7.4p1'), 'SSH-2.0-dropbear_2017.75' → ('Dropbear', '2017.75')."""
    m = re.match(r"SSH-[\d.]+-([^\s]+)", banner or "")
    soft = m.group(1) if m else ""
    m = re.match(r"(?i)openssh[_-]([\w.]+)", soft)
    if m:
        return "OpenSSH", m.group(1)
    m = re.match(r"(?i)dropbear[_-]?([\d.]+)", soft)
    if m:
        return "Dropbear", m.group(1)
    if "_" in soft:
        a, b = soft.split("_", 1)
        return a, b
    return (soft or None), None


def _vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3])


def version_findings(product, version):
    out = []
    if not product or not version:
        return out
    v = _vtuple(version)
    if product == "OpenSSH":
        if v < (7, 4):
            out.append(("high", f"Πολύ παλιό OpenSSH {version} — πολλές γνωστές ευπάθειες (π.χ. CVE-2016-6210, CVE-2018-15473)", "ssh_old"))
        elif v < (8, 8):
            out.append(("low", f"OpenSSH {version}: παλιά έκδοση — ενημέρωσέ το (π.χ. CVE-2023-38408, Terrapin)", "ssh_old"))
        if (8, 5) <= v < (9, 8) and re.search(r"\dp\d", version):  # μόνο portable (Linux/glibc)· όχι OpenBSD
            out.append(("med", f"OpenSSH {version}: στο εύρος του regreSSHion (CVE-2024-6387) — έλεγχος μόνο από την "
                               "έκδοση· ο κατασκευαστής μπορεί να έχει ήδη διορθώσει (backport)", "ssh_regresshion"))
    elif product == "Dropbear":
        if v < (2016, 74):
            out.append(("high", f"Πολύ παλιό Dropbear {version} — γνωστές ευπάθειες εκτέλεσης κώδικα (CVE-2016-7406/7407)", "ssh_old"))
        elif v < (2022, 83):
            out.append(("med", f"Παλιό Dropbear {version} — ενημέρωσε το firmware της συσκευής", "ssh_old"))
    return out


def grade_ssh(info):
    """info: banner + λίστες αλγορίθμων → findings, weak, score, grade."""
    findings = []
    weak = {"kex": [], "hostkey": [], "ciphers": [], "macs": []}

    def add(sev, text, fid):
        findings.append({"sev": sev, "text": text, "id": fid})
    prod, ver = ssh_software(info.get("banner"))
    info["software"], info["version"] = prod, ver
    if (info.get("banner") or "").startswith("SSH-1."):
        add("high", "Ο server δέχεται SSH πρωτόκολλο 1 (σπασμένο)", "ssh_v1")
    for sev, text, fid in version_findings(prod, ver):
        add(sev, text, fid)
    kexes = info.get("kex") or []
    for name in kexes:
        w = weak_kex(name)
        if w:
            weak["kex"].append(name)
            add(w[0], f"kex {name}: {w[1]}", "ssh_weak_kex")
    for name in info.get("hostkey") or []:
        w = WEAK_HOSTKEY.get(name)
        if w:
            weak["hostkey"].append(name)
            add(w[0], f"host key {name}: {w[1]}", "ssh_weak_hostkey")
    ciphers = sorted(set(info.get("ciphers") or []), key=(info.get("ciphers") or []).index)
    for name in ciphers:
        w = weak_cipher(name)
        if w:
            weak["ciphers"].append(name)
            add(w[0], f"cipher {name}: {w[1]}", "ssh_weak_cipher")
    macs = sorted(set(info.get("macs") or []), key=(info.get("macs") or []).index)
    for name in macs:
        w = WEAK_MAC_EXACT.get(name)
        if w:
            weak["macs"].append(name)
            add(w[0], f"MAC {name}: {w[1]}", "ssh_weak_mac")
    if kexes and "kex-strict-s-v00@openssh.com" not in kexes and (
            "chacha20-poly1305@openssh.com" in ciphers or any(m.endswith("-etm@openssh.com") for m in macs)):
        add("med", "Ευάλωτο στο Terrapin (CVE-2023-48795): chacha20-poly1305/EtM χωρίς «strict kex»", "ssh_terrapin")
    if info.get("compression") and "zlib" in info["compression"]:
        add("info", "Συμπίεση zlib πριν από τον έλεγχο ταυτότητας", "ssh_zlib")
    info["weak"] = weak
    return _finish(info, findings)


def _finish(info, findings):
    # ταξινόμηση: σοβαρότερα πρώτα · βαθμός από 100 μείον ποινές (όπως τα testssl.sh / ssh-audit, απλοποιημένα)
    findings.sort(key=lambda f: -SEV_PTS.get(f["sev"], 0))
    # ποινή ανά ΚΑΤΗΓΟΡΙΑ (π.χ. «αδύναμοι ciphers»): η χειρότερη μετρά ολόκληρη, κάθε επιπλέον +3
    cat = {}
    for f in findings:
        cat.setdefault(f["id"], []).append(SEV_PTS.get(f["sev"], 0))
    pen = sum(max(p) + 3 * sum(1 for x in p[1:] if x) for p in cat.values())
    score = max(0, 100 - pen)
    high = len({f["id"] for f in findings if f["sev"] == "high"})
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"
    if high and grade in ("A", "B", "C"):
        grade = "D"  # ένα σοβαρό εύρημα δεν «σβήνεται» από τα υπόλοιπα
    if high >= 2:
        grade = "F"
    info["findings"], info["score"], info["grade"] = findings, score, grade
    return info


def _recv_line(s, buf, limit=8192):
    while b"\n" not in buf:
        chunk = s.recv(1024)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            break
    return buf


def ssh_probe(ip, port, timeout=TIMEOUT):
    """Banner + KEXINIT του server. Επιστρέφει dict (ακατέργαστα στοιχεία, χωρίς βαθμό)."""
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.settimeout(timeout)
        buf = b""
        banner = None
        for _ in range(20):  # RFC 4253: πριν από το banner επιτρέπονται άλλες γραμμές
            buf = _recv_line(s, buf)
            if b"\n" not in buf:
                break
            line, buf = buf.split(b"\n", 1)
            line = line.rstrip(b"\r").decode("utf-8", "replace")
            if line.startswith("SSH-"):
                banner = line[:255]
                break
        if not banner:
            raise ValueError("δεν απάντησε με banner SSH")
        info = {"banner": banner}
        if banner.startswith("SSH-1.") and not banner.startswith("SSH-1.99"):
            return info
        s.sendall(CLIENT_BANNER + build_kexinit())
        end = time.time() + timeout
        payload = None
        while time.time() < end:
            payload = packet_payload(buf)
            if payload is not None:
                break
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        if payload is None:
            raise ValueError("δεν ήρθε KEXINIT από τον server")
        kx = parse_kexinit(payload)
        info.update(kex=kx["kex"], hostkey=kx["hostkey"],
                    ciphers=list(dict.fromkeys(kx["enc_s2c"] + kx["enc_c2s"])),
                    macs=list(dict.fromkeys(kx["mac_s2c"] + kx["mac_c2s"])),
                    compression=list(dict.fromkeys(kx["comp_s2c"] + kx["comp_c2s"])))
        return info


# ---------------- TLS ----------------
TLS_VERSIONS = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
OIDS = {
    "1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
    "1.2.840.10040.4.1": "DSA",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption", "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10040.4.3": "dsa-with-SHA1",
}
CURVES = {"1.2.840.10045.3.1.7": ("P-256", 256), "1.3.132.0.34": ("P-384", 384), "1.3.132.0.35": ("P-521", 521),
          "1.3.132.0.33": ("P-224", 224), "1.2.840.10045.3.1.1": ("P-192", 192)}


def _tlv(b, off):
    tag = b[off]
    ln = b[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[off:off + n], "big")
        off += n
    return tag, b[off:off + ln], off + ln


def _children(b):
    out, off = [], 0
    while off < len(b):
        tag, val, off = _tlv(b, off)
        out.append((tag, val))
    return out


def _oid(v):
    first = v[0]
    parts = [first // 40, first % 40]
    n = 0
    for c in v[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def cert_key_info(der):
    """DER πιστοποιητικό → {key_type, key_bits, curve, sig_alg} με έναν μικρό αναλυτή ASN.1 (χωρίς βιβλιοθήκες)."""
    _, cert, _ = _tlv(der, 0)
    parts = _children(cert)
    tbs = _children(parts[0][1])
    sig_alg = OIDS.get(_oid(_children(parts[1][1])[0][1]), _oid(_children(parts[1][1])[0][1]))
    i = 1 if tbs[0][0] == 0xA0 else 0  # [0] version (λείπει στα v1 πιστοποιητικά)
    spki = _children(tbs[i + 5][1])
    alg = _children(spki[0][1])
    koid = _oid(alg[0][1])
    ktype = OIDS.get(koid, koid)
    out = {"key_type": ktype, "key_bits": None, "curve": None, "sig_alg": sig_alg}
    bits = spki[1][1][1:]  # BIT STRING: πρώτο byte = αχρησιμοποίητα bits
    if ktype == "RSA":
        mod = _children(_children(bits)[0][1])[0][1].lstrip(b"\x00")
        out["key_bits"] = len(mod) * 8 - (8 - mod[0].bit_length()) if mod else None
    elif ktype == "EC" and len(alg) > 1 and alg[1][0] == 0x06:
        name, size = CURVES.get(_oid(alg[1][1]), (_oid(alg[1][1]), None))
        out["curve"], out["key_bits"] = name, size
    elif ktype == "Ed25519":
        out["key_bits"] = 256
    elif ktype == "Ed448":
        out["key_bits"] = 456
    return out


def _ctx(version):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    v = getattr(ssl.TLSVersion, version.replace("TLSv", "TLSv").replace(".", "_"), None)
    if v is None:
        return None
    try:
        c.minimum_version = c.maximum_version = v
    except (ValueError, ssl.SSLError):
        return None
    if version in ("TLSv1", "TLSv1.1"):  # παλιές συσκευές: δέξου και παλιούς ciphers (μόνο για να δούμε τι δέχονται)
        for spec in ("ALL:@SECLEVEL=0", "ALL"):
            try:
                c.set_ciphers(spec)
                break
            except ssl.SSLError:
                continue
    return c


def local_support():
    """Ποιες εκδόσεις μπορεί να δοκιμάσει η τοπική βιβλιοθήκη SSL (αλλιώς: «άγνωστο», όχι «απορρίπτεται»)."""
    has = {"TLSv1": getattr(ssl, "HAS_TLSv1", False), "TLSv1.1": getattr(ssl, "HAS_TLSv1_1", False),
           "TLSv1.2": getattr(ssl, "HAS_TLSv1_2", True), "TLSv1.3": getattr(ssl, "HAS_TLSv1_3", False)}
    return {v: bool(has[v]) and _ctx(v) is not None for v in TLS_VERSIONS}


def tls_probe(ip, port, timeout=TIMEOUT, sni=None):
    """Δοκιμάζει κάθε έκδοση TLS χωριστά + διαβάζει το πιστοποιητικό. Ακατέργαστα στοιχεία, χωρίς βαθμό."""
    import pentest
    sup = local_support()
    versions, der, neg, cipher, errs = {}, None, None, None, []
    for v in reversed(TLS_VERSIONS):
        if not sup[v]:
            versions[v] = None
            continue
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s, \
                    _ctx(v).wrap_socket(s, server_hostname=sni) as ss:
                versions[v] = True
                if der is None:
                    der = ss.getpeercert(binary_form=True)
                    neg, cipher = ss.version(), (ss.cipher() or (None,))[0]
        except (ssl.SSLError, ConnectionResetError, ssl.SSLEOFError) as e:
            versions[v] = False
            errs.append(str(e)[:80])
        except OSError as e:
            if not any(versions.values()):
                raise ValueError(f"δεν απαντά: {str(e)[:80]}")
            versions[v] = False
    if not any(versions.values()):
        raise ValueError("δεν μιλάει TLS" + (f" ({errs[0]})" if errs else ""))
    info = {"versions": versions, "negotiated": neg, "cipher": cipher, "cert": None}
    if der:
        cert = {}
        try:
            c = pentest._decode_cert(der)
            flat = lambda x: ", ".join("=".join(kv) for rdn in x for kv in rdn)  # noqa: E731
            cert.update(subject=flat(c.get("subject", ())), issuer=flat(c.get("issuer", ())),
                        not_after=c.get("notAfter"), not_before=c.get("notBefore"),
                        sans=[v for k, v in c.get("subjectAltName", ()) if k in ("DNS", "IP Address")][:50])
            cert["days_left"] = int((ssl.cert_time_to_seconds(c["notAfter"]) - time.time()) // 86400)
        except Exception:
            pass
        try:
            cert.update(cert_key_info(der))
        except Exception:
            pass
        info["cert"] = cert
    return info


def grade_tls(info):
    findings = []

    def add(sev, text, fid):
        findings.append({"sev": sev, "text": text, "id": fid})
    v = info.get("versions") or {}
    if v.get("TLSv1"):
        add("high", "Δέχεται TLS 1.0 (σπασμένο — BEAST/POODLE, καταργημένο από RFC 8996)", "tls_old")
    if v.get("TLSv1.1"):
        add("med", "Δέχεται TLS 1.1 (καταργημένο από RFC 8996)", "tls_old")
    if not v.get("TLSv1.2") and not v.get("TLSv1.3") and (v.get("TLSv1.2") is False or v.get("TLSv1.3") is False):
        add("high", "Δεν υποστηρίζει TLS 1.2 ή 1.3 — μόνο παλιά πρωτόκολλα", "tls_no_modern")
    if v.get("TLSv1.3") is False:
        add("info", "Δεν υποστηρίζει TLS 1.3", "tls_no13")
    ci = (info.get("cipher") or "").upper()
    if any(w in ci for w in ("RC4", "DES-CBC3", "3DES", "NULL", "EXPORT", "MD5")):
        add("high", f"Αδύναμος cipher {info.get('cipher')}", "tls_weak_cipher")
    c = info.get("cert") or {}
    if c:
        dl = c.get("days_left")
        if dl is not None and dl < 0:
            add("high", f"Το πιστοποιητικό έληξε πριν {-dl} μέρες", "tls_cert_expired")
        elif dl is not None and dl < 30:
            add("low", f"Το πιστοποιητικό λήγει σε {dl} μέρες", "tls_cert_expiring")
        ss = bool(c.get("subject")) and c.get("subject") == c.get("issuer")
        c["self_signed"] = ss
        if ss:
            add("low", "Self-signed πιστοποιητικό — ο browser δεν μπορεί να επιβεβαιώσει τη συσκευή (κίνδυνος MITM)",
                "tls_self_signed")
        kt, kb = c.get("key_type"), c.get("key_bits")
        if kt in ("RSA", "DSA") and kb:
            if kb < 1024:
                add("high", f"Κλειδί {kt} μόλις {kb} bit", "tls_weak_key")
            elif kb < 2048:
                add("med", f"Κλειδί {kt} {kb} bit — χρειάζεται τουλάχιστον 2048", "tls_weak_key")
        elif kt == "EC" and kb and kb < 256:
            add("med", f"Κλειδί EC {kb} bit — χρειάζεται τουλάχιστον 256", "tls_weak_key")
        sa = (c.get("sig_alg") or "").lower()
        if "md5" in sa:
            add("high", f"Υπογραφή με MD5 ({c['sig_alg']})", "tls_weak_sig")
        elif "sha1" in sa:
            add("med", f"Υπογραφή με SHA-1 ({c['sig_alg']}) — δεν γίνεται δεκτή από τους browsers", "tls_weak_sig")
        if not c.get("sans"):
            add("info", "Χωρίς Subject Alternative Name (οι browsers αγνοούν το CN)", "tls_no_san")
    return _finish(info, findings)


# ---------------- στόχοι ----------------
def parse_target(s):
    """'192.168.1.1:443' → ('192.168.1.1', 443). Σκέτη IP → θύρα 443. Μόνο ιδιωτικές IPv4 (pentest.check_target)."""
    import pentest
    s = str(s or "").strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s):
        s += ":443"  # σκέτη IP: το πιο συνηθισμένο, η σελίδα HTTPS
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", s)
    if not m:
        raise ValueError(f"Μη έγκυρος στόχος «{s[:40]}» — γράψε ip ή ip:θύρα, π.χ. 192.168.1.1:443")
    ip, port = m.group(1), int(m.group(2))
    if not 1 <= port <= 65535:
        raise ValueError(f"Μη έγκυρη θύρα στο «{s[:40]}»")
    if "/" in ip or len(pentest.check_target(ip)) != 1:
        raise ValueError("Ένας στόχος τη φορά")
    return ip, port


def targets_from_scan(scan):
    """Υπηρεσίες SSH/TLS από την τελευταία σάρωση → [(ip, port, kind)]."""
    out = []
    for h in (scan or {}).get("hosts") or ():
        for sv in h.get("services") or ():
            if sv.get("proto", "tcp") != "tcp":
                continue
            p, banner = sv.get("port"), sv.get("banner") or ""
            if banner.startswith("SSH-") or (p in SSH_PORTS and not banner):
                out.append((h["ip"], p, "ssh"))
            elif p in TLS_PORTS or sv.get("tls"):
                out.append((h["ip"], p, "tls"))
    return out[:MAX_TARGETS]


def sniff_kind(ip, port, timeout=1.0):
    """SSH servers μιλούν πρώτοι· TLS servers περιμένουν. Έτσι ξεχωρίζουμε χωρίς να στείλουμε τίποτα."""
    try:
        with socket.create_connection((ip, port), timeout=max(timeout, 1.0) * 3) as s:
            s.settimeout(timeout)
            try:
                first = s.recv(512)
            except socket.timeout:
                return "tls"
            return "ssh" if first.startswith(b"SSH-") or b"\nSSH-" in first else "tls"
    except OSError as e:
        raise ValueError(f"δεν απαντά: {str(e)[:80]}")


def audit_one(ip, port, kind=None, timeout=TIMEOUT):
    res = {"target": f"{ip}:{port}", "ip": ip, "port": port, "kind": kind, "grade": None, "score": None,
           "findings": [], "error": None}
    try:
        if not kind:
            kind = res["kind"] = "ssh" if port in SSH_PORTS else sniff_kind(ip, port, timeout=min(1.0, timeout))
        if kind == "ssh":
            res["ssh"] = grade_ssh(ssh_probe(ip, port, timeout=timeout))
        else:
            res["tls"] = grade_tls(tls_probe(ip, port, timeout=timeout))
        body = res.get("ssh") or res.get("tls")
        res["grade"], res["score"], res["findings"] = body.pop("grade"), body.pop("score"), body.pop("findings")
    except Exception as e:
        res["error"] = str(e)[:160] or e.__class__.__name__
    return res


# ---------------- demo ----------------
_NOW = lambda: time.time()  # noqa: E731


def _cert_date(days):
    return time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(_NOW() + days * 86400))


def demo_raw():
    """Ρεαλιστικά (εικονικά) δεδομένα για το demo — περνούν από τους ίδιους βαθμολογητές."""
    modern_kex = ["sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org",
                  "ecdh-sha2-nistp256", "diffie-hellman-group16-sha512", "kex-strict-s-v00@openssh.com"]
    modern_c = ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
                "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"]
    modern_m = ["umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"]
    return [
        ("192.168.1.1", 443, "tls", {"versions": {"TLSv1": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": False},
                                     "negotiated": "TLSv1.2", "cipher": "AES128-SHA",
                                     "cert": {"subject": "commonName=router.home", "issuer": "commonName=router.home",
                                              "not_after": "Jan  1 00:00:00 2021 GMT", "not_before": "Jan  1 00:00:00 2011 GMT",
                                              "days_left": int((time.mktime((2021, 1, 1, 0, 0, 0, 0, 0, 0)) - _NOW()) // 86400),
                                              "sans": [], "key_type": "RSA", "key_bits": 1024, "curve": None,
                                              "sig_alg": "sha1WithRSAEncryption"}}),
        ("192.168.1.1", 22, "ssh", {"banner": "SSH-2.0-dropbear_2017.75",
                                    "kex": ["curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha1",
                                            "diffie-hellman-group1-sha1", "kexguess2@matt.ucc.asn.au"],
                                    "hostkey": ["ssh-rsa", "ssh-dss"],
                                    "ciphers": ["aes128-ctr", "aes256-ctr", "aes128-cbc", "aes256-cbc", "3des-ctr", "3des-cbc"],
                                    "macs": ["hmac-sha1-96", "hmac-sha1", "hmac-sha2-256", "hmac-md5"],
                                    "compression": ["zlib@openssh.com", "none"]}),
        ("192.168.1.30", 22, "ssh", {"banner": "SSH-2.0-dropbear_2014.63",
                                     "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"],
                                     "hostkey": ["ssh-rsa", "ssh-dss"],
                                     "ciphers": ["aes128-ctr", "3des-ctr", "aes128-cbc", "3des-cbc", "blowfish-cbc", "arcfour"],
                                     "macs": ["hmac-sha1-96", "hmac-sha1", "hmac-md5"], "compression": ["none"]}),
        ("192.168.1.30", 443, "tls", {"versions": {"TLSv1": True, "TLSv1.1": False, "TLSv1.2": False, "TLSv1.3": False},
                                      "negotiated": "TLSv1", "cipher": "DES-CBC3-SHA",
                                      "cert": {"subject": "commonName=IPCAM", "issuer": "commonName=IPCAM",
                                               "not_after": _cert_date(2400), "not_before": "Mar  4 00:00:00 2015 GMT",
                                               "days_left": 2400, "sans": [], "key_type": "RSA", "key_bits": 1024,
                                               "curve": None, "sig_alg": "md5WithRSAEncryption"}}),
        ("192.168.1.16", 5001, "tls", {"versions": {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
                                       "negotiated": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                                       "cert": {"subject": "commonName=nas.example-home.net", "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=E6",
                                                "not_after": _cert_date(61), "not_before": _cert_date(-29), "days_left": 61,
                                                "sans": ["nas.example-home.net"], "key_type": "EC", "key_bits": 256,
                                                "curve": "P-256", "sig_alg": "ecdsa-with-SHA384"}}),
        ("192.168.1.16", 22, "ssh", {"banner": "SSH-2.0-OpenSSH_9.8", "kex": modern_kex,
                                     "hostkey": ["rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"],
                                     "ciphers": modern_c, "macs": modern_m, "compression": ["none", "zlib@openssh.com"]}),
        ("192.168.1.23", 22, "ssh", {"banner": "SSH-2.0-OpenSSH_9.6", "kex": modern_kex,
                                     "hostkey": ["rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"],
                                     "ciphers": modern_c, "macs": modern_m + ["hmac-sha1"], "compression": ["none"]}),
        ("192.168.1.77", 22, "ssh", {"banner": "SSH-2.0-OpenSSH_7.4",
                                     "kex": ["curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
                                             "diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1",
                                             "diffie-hellman-group14-sha1"],
                                     "hostkey": ["ssh-rsa", "rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"],
                                     "ciphers": ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com",
                                                 "aes256-gcm@openssh.com", "aes128-cbc"],
                                     "macs": ["umac-64-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha1-etm@openssh.com",
                                              "umac-64@openssh.com", "hmac-sha2-256", "hmac-sha1"],
                                     "compression": ["none", "zlib@openssh.com"]}),
    ]


def demo_audit(targets=None):
    by = {(ip, port): (kind, raw) for ip, port, kind, raw in demo_raw()}
    if targets is None:
        targets = [(ip, port, kind) for (ip, port), (kind, _) in by.items()]
    out = []
    for ip, port, _kind in targets:
        res = {"target": f"{ip}:{port}", "ip": ip, "port": port, "kind": None, "grade": None, "score": None,
               "findings": [], "error": None}
        if (ip, port) not in by:
            res["error"] = "δεν απαντά: timed out"
        else:
            kind, raw = by[(ip, port)]
            res["kind"] = kind
            body = json.loads(json.dumps(raw))
            body = grade_ssh(body) if kind == "ssh" else grade_tls(body)
            res[kind] = body
            res["grade"], res["score"], res["findings"] = body.pop("grade"), body.pop("score"), body.pop("findings")
        out.append(res)
    return out


# ---------------- εκτελεστής ----------------
def summarize(results):
    grades = {g: 0 for g in "ABCDF"}
    for r in results or ():
        if r.get("grade") in grades:
            grades[r["grade"]] += 1
    order = "ABCDF"
    worst = max((r["grade"] for r in results or () if r.get("grade")), key=order.index, default=None)
    return {"services": len(results or ()), "ok": sum(1 for r in results or () if not r.get("error")),
            "errors": sum(1 for r in results or () if r.get("error")), "grades": grades, "worst": worst,
            "high": sum(1 for r in results or () for f in r.get("findings") or () if f["sev"] == "high")}


class TlsAudit:
    """sim=True: εικονικά αποτελέσματα (demo). scan: συνάρτηση που επιστρέφει την τελευταία σάρωση (για προεπιλεγμένους στόχους).
    path: data/tlsaudit.json (live) για να θυμάται τα τελευταία αποτελέσματα."""

    def __init__(self, sim=False, scan=None, path=None, workers=8, timeout=TIMEOUT):
        self.sim = sim
        self.timeout = max(0.5, min(float(timeout), 15.0))
        self.scan = scan or (lambda: None)
        self.path = path
        self.workers = workers
        self.lock = threading.Lock()
        self.on_save = None
        self.state = {"status": "idle", "results": []}
        if path:
            try:
                with open(path, encoding="utf-8") as f:
                    d = json.load(f)
                if isinstance(d, dict) and isinstance(d.get("results"), list):
                    d["status"] = "done"
                    self.state = d
            except (OSError, ValueError):
                pass

    def default_targets(self):
        if self.sim:
            return [f"{ip}:{p}" for ip, p, _k, _r in demo_raw()]
        try:
            return [f"{ip}:{p}" for ip, p, _k in targets_from_scan(self.scan())]
        except Exception:
            return []

    def status(self):
        with self.lock:
            st = json.loads(json.dumps({k: v for k, v in self.state.items() if k != "prev"}))
        st["sim"] = bool(self.sim)
        st["default_targets"] = self.default_targets()
        st["summary"] = summarize(st.get("results"))
        st["local_support"] = {v: True for v in TLS_VERSIONS} if self.sim else local_support()
        return st

    def last_results(self):
        with self.lock:
            if self.state.get("status") == "running":
                return list(self.state.get("prev") or [])
            return list(self.state.get("results") or [])

    def start(self, targets=None):
        if targets:
            if not isinstance(targets, (list, tuple)):
                raise ValueError("targets: λίστα από «ip:θύρα»")
            if len(targets) > MAX_TARGETS:
                raise ValueError(f"Το πολύ {MAX_TARGETS} στόχοι")
            tl = []
            for t in targets:
                ip, port = parse_target(t)
                tl.append((ip, port, None))
            tl = list(dict.fromkeys(tl))
        elif self.sim:
            tl = [(ip, p, k) for ip, p, k, _r in demo_raw()]
        else:
            tl = targets_from_scan(self.scan())
            for ip, _p, _k in tl:  # ό,τι ήρθε από τη σάρωση περνά κι αυτό τον έλεγχο «μόνο ιδιωτικές»
                parse_target(f"{ip}:{_p}")
        if not tl:
            raise ValueError("Δεν υπάρχουν στόχοι SSH/TLS — κάνε πρώτα σάρωση LAN ή δώσε στόχους ip:θύρα")
        with self.lock:
            if self.state.get("status") == "running":
                raise ValueError("Τρέχει ήδη έλεγχος")
            prev = self.state.get("results") or []
            self.state = {"status": "running", "started": time.time(), "finished": None, "total": len(tl), "done": 0,
                          "progress": 0, "targets": [f"{ip}:{p}" for ip, p, _ in tl], "results": [], "prev": prev}
        threading.Thread(target=self._run, args=(tl,), daemon=True).start()
        return {"ok": True, "total": len(tl)}

    def wait(self, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                if self.state.get("status") != "running":
                    return self.state
            time.sleep(0.02)
        return None

    def _tick(self, res):
        with self.lock:
            self.state["results"].append(res)
            self.state["done"] += 1
            self.state["progress"] = int(100 * self.state["done"] / max(1, self.state["total"]))

    def _run(self, tl):
        try:
            if self.sim:
                for res in demo_audit(tl):
                    time.sleep(0.15)
                    self._tick(res)
            else:
                with ThreadPoolExecutor(self.workers) as ex:
                    for res in ex.map(lambda x: audit_one(*x, timeout=self.timeout), tl):
                        self._tick(res)
            with self.lock:
                order = {t: i for i, t in enumerate(self.state["targets"])}
                self.state["results"].sort(key=lambda r: order.get(r["target"], 0))
                snap = {k: v for k, v in json.loads(json.dumps(self.state)).items() if k != "prev"}
                snap.update(status="done", finished=time.time(), progress=100)
            self._save(snap)  # πρώτα στο δίσκο, μετά «done» (όποιος περιμένει βρίσκει και το αρχείο)
            with self.lock:
                self.state = snap
            s = summarize(snap["results"])
            log(f"🔐 έλεγχος TLS/SSH: {s['ok']}/{s['services']} υπηρεσίες, χειρότερος βαθμός {s['worst'] or '-'}")
        except Exception as e:
            with self.lock:
                self.state.update(status="error", error=str(e)[:200], finished=time.time())

    def _save(self, snap):
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snap, f, ensure_ascii=False)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError as e:
            log("tlsaudit: αποθήκευση απέτυχε:", e)
