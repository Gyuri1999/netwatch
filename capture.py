"""NetWatch — Ανάλυση πακέτων (TLS/JA3, cleartext), live capture, PCAP replay και CTF."""
import base64
import collections
import hashlib
import os
import re
import subprocess
import threading
import time
import urllib.parse
import urllib.request

from core import HERE, ip_kind, log, norm_mac
from storage import History
from detect import NetState


# ---------------- live capture ----------------
GREASE = {0x0a0a + 0x1010 * i for i in range(16)}


def parse_client_hello(b):
    """TLS ClientHello → SNI + JA3 fingerprint (https://github.com/salesforce/ja3)."""
    try:
        if len(b) < 43 or b[0] != 0x16 or b[5] != 0x01:
            return None
        complete = len(b) >= 5 + int.from_bytes(b[3:5], "big")
        ver = int.from_bytes(b[9:11], "big")
        i = 43
        i += 1 + b[i]
        cl = int.from_bytes(b[i:i + 2], "big")
        ciphers = [int.from_bytes(b[j:j + 2], "big") for j in range(i + 2, min(len(b), i + 2 + cl) - 1, 2)]
        i += 2 + cl
        i += 1 + b[i]
        end = min(len(b), i + 2 + int.from_bytes(b[i:i + 2], "big"))
        i += 2
        exts, curves, pfs, sni = [], [], [], None
        has_sni, alpn, sver, sigs = False, None, [], []
        while i + 4 <= end:
            et, el = int.from_bytes(b[i:i + 2], "big"), int.from_bytes(b[i + 2:i + 4], "big")
            i += 4
            data = b[i:i + el]
            exts.append(et)
            if et == 0:
                has_sni = True
            if et == 0 and len(data) >= 5:
                nl = int.from_bytes(data[3:5], "big")
                sni = data[5:5 + nl].decode("ascii", "ignore") or None
            elif et == 16 and len(data) >= 3 and alpn is None:
                alpn = bytes(data[3:3 + data[2]])
            elif et == 43 and len(data) >= 1:
                sver = [int.from_bytes(data[k:k + 2], "big") for k in range(1, min(len(data), 1 + data[0]) - 1, 2)]
            elif et == 13 and len(data) >= 2:
                ll = int.from_bytes(data[0:2], "big")
                sigs = [int.from_bytes(data[k:k + 2], "big") for k in range(2, min(len(data), 2 + ll) - 1, 2)]
            elif et == 10 and len(data) >= 2:
                ll = int.from_bytes(data[0:2], "big")
                curves = [int.from_bytes(data[k:k + 2], "big") for k in range(2, min(len(data), 2 + ll) - 1, 2)]
            elif et == 11 and len(data) >= 1:
                pfs = list(data[1:1 + data[0]])
            i += el
    except Exception:
        return None
    g = lambda xs: "-".join(str(x) for x in xs if x not in GREASE)  # noqa: E731
    ja3_str = f"{ver},{g(ciphers)},{g(exts)},{g(curves)},{'-'.join(map(str, pfs))}"
    return {"sni": sni, "ja3": hashlib.md5(ja3_str.encode()).hexdigest() if complete else None, "ja3_str": ja3_str,
            "ja4": ja4(ver, ciphers, exts, has_sni, alpn, sver, sigs) if complete else None}


JA4_VER = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
           0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}


def ja4(ver, ciphers, exts, has_sni, alpn, sver, sigs, proto="t"):
    """JA4 (FoxIO, https://github.com/FoxIO-LLC/ja4): «t13d1516h2_<ciphers>_<extensions>».

    a: πρωτόκολλο + έκδοση TLS (η μεγαλύτερη μη‑GREASE του supported_versions, αλλιώς η legacy) + d/i (υπάρχει SNI ή όχι)
       + πλήθος ciphers και extensions (2 ψηφία, χωρίς GREASE, max 99) + 1ος/τελευταίος χαρακτήρας του 1ου ALPN («00» αν λείπει).
    b: sha256[:12] των ciphers ταξινομημένων (4 hex πεζά, με κόμματα)· «000000000000» αν δεν υπάρχουν.
    c: sha256[:12] των extensions ταξινομημένων χωρίς SNI/ALPN + «_» + signature algorithms με τη σειρά τους
       (χωρίς «_» αν δεν υπάρχουν)· «000000000000» αν δεν μένει καμία extension.
    """
    cs = [c for c in ciphers if c not in GREASE]
    es = [e for e in exts if e not in GREASE]
    vs = [v for v in (sver or []) if v not in GREASE]
    v = JA4_VER.get(max(vs) if vs else ver, "00")
    if alpn:
        f, l_ = alpn[:1], alpn[-1:]
        if f.isalnum() and l_.isalnum() and f.isascii() and l_.isascii():
            al = (f + l_).decode()
        else:  # μη αλφαριθμητικό: 1ος και τελευταίος χαρακτήρας της δεκαεξαδικής μορφής
            hx = alpn.hex()
            al = hx[0] + hx[-1]
    else:
        al = "00"
    a = f"{proto}{v}{'d' if has_sni else 'i'}{min(len(cs), 99):02d}{min(len(es), 99):02d}{al}"
    h = lambda s: hashlib.sha256(s.encode()).hexdigest()[:12]  # noqa: E731
    b = h(",".join(sorted(f"{c:04x}" for c in cs))) if cs else "000000000000"
    ce = sorted(f"{e:04x}" for e in es if e not in (0x0000, 0x0010))
    sg = ",".join(f"{x:04x}" for x in sigs if x not in GREASE)
    c = h(",".join(ce) + ("_" + sg if sg else "")) if ce else "000000000000"
    return f"{a}_{b}_{c}"


def parse_sni(b):
    r = parse_client_hello(b)
    return r["sni"] if r else None


HTTP_HOST = re.compile(rb"\r\nHost:\s*([^\r\n:]+)", re.I)
BASIC_AUTH = re.compile(rb"\r\nAuthorization:\s*Basic\s+([A-Za-z0-9+/=]{4,})", re.I)
FORM_PASS = re.compile(rb"(?:^|&)(?:pass|passwd|password|pwd|pin)=[^&]", re.I)
FORM_USER = re.compile(rb"(?:^|&)(?:user|username|login|email|uname|usr)=([^&\s]{1,64})", re.I)


def _txt(b):
    return b.decode("utf-8", "ignore").strip()[:64]


def parse_mqtt_connect(b):
    """MQTT 3.1.1 / 5 CONNECT με username/password (bits 0x80/0x40 του connect flags) → {proto, field, user}."""
    if len(b) < 12 or b[0] != 0x10:
        return None
    i, mult, rem = 1, 1, 0
    while i < 5 and i < len(b):  # remaining length (varint)
        rem += (b[i] & 0x7F) * mult
        mult *= 128
        i += 1
        if not b[i - 1] & 0x80:
            break
    pos = i

    def u16(p):
        return int.from_bytes(b[p:p + 2], "big") if p + 2 <= len(b) else None

    n = u16(pos)
    if n is None or b[pos + 2:pos + 2 + n] not in (b"MQTT", b"MQIsdp"):
        return None
    pos += 2 + n
    if pos + 4 > len(b):
        return None
    level, flags = b[pos], b[pos + 1]
    pos += 4  # level, flags, keepalive
    if not flags & 0xC0:
        return None  # χωρίς username/password: τίποτα να «κλαπεί» (αλλά ο broker μάλλον δέχεται ανώνυμους)
    if level == 5:  # MQTT 5: properties (varint μήκος)
        plen, mult = 0, 1
        while pos < len(b):
            plen += (b[pos] & 0x7F) * mult
            mult *= 128
            pos += 1
            if not b[pos - 1] & 0x80:
                break
        pos += plen
    vals = []  # client id, (will props/topic/payload αν will flag), username
    n = u16(pos)
    if n is None:
        return None
    vals.append(b[pos + 2:pos + 2 + n])  # client id
    pos += 2 + n
    if flags & 0x04:  # will
        if level == 5:
            plen, mult = 0, 1
            while pos < len(b):
                plen += (b[pos] & 0x7F) * mult
                mult *= 128
                pos += 1
                if not b[pos - 1] & 0x80:
                    break
            pos += plen
        for _ in range(2):
            n = u16(pos)
            if n is None:
                return None
            pos += 2 + n
    user = None
    if flags & 0x80:
        n = u16(pos)
        if n is not None:
            user = _txt(b[pos + 2:pos + 2 + n])
    return {"proto": "MQTT", "field": "pass" if flags & 0x40 else "user_only", "user": user,
            "client": _txt(vals[0]) if vals else None}


def parse_cleartext(sp, dp, pl):
    """Εντοπίζει login που στέλνεται χωρίς κρυπτογράφηση (FTP, POP3, IMAP, SMTP, Telnet, HTTP).
    Επιστρέφει {proto, field, user}. Τον κωδικό τον αναγνωρίζει αλλά ΔΕΝ τον κρατά ποτέ."""
    if not pl:
        return None
    head = pl[:2048]
    try:
        if dp in (21, 110):
            proto, cmd = ("FTP" if dp == 21 else "POP3"), head[:5].upper()
            if cmd == b"USER ":
                return {"proto": proto, "field": "user", "user": _txt(head[5:].split(b"\r")[0])}
            if cmd == b"PASS ":
                return {"proto": proto, "field": "pass"}
            return None
        if dp == 143:
            parts = head.split(None, 3)
            if len(parts) >= 4 and parts[1].upper() == b"LOGIN":
                return {"proto": "IMAP", "field": "pass", "user": _txt(parts[2].strip(b'"'))}
            return None
        if dp in (25, 587):
            up = head.upper()
            if up.startswith(b"AUTH PLAIN"):
                user = None
                arg = head[10:].strip().split(b"\r")[0]
                if arg:
                    bits = base64.b64decode(arg + b"==", validate=False).split(b"\0")
                    user = _txt(bits[1]) if len(bits) >= 3 else None
                return {"proto": "SMTP", "field": "pass", "user": user}
            if up.startswith(b"AUTH LOGIN"):
                return {"proto": "SMTP", "field": "pass"}
            return None
        if dp == 23:
            return {"proto": "Telnet", "field": "session"}
        if dp == 1883:
            return parse_mqtt_connect(head)
        if head[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD"):
            m = BASIC_AUTH.search(head)
            if m:
                cred = base64.b64decode(m.group(1) + b"==", validate=False)
                return {"proto": "HTTP Basic", "field": "pass", "user": _txt(cred.split(b":")[0])}
            if head[:4] == b"POST" and b"\r\n\r\n" in pl:
                body = pl.split(b"\r\n\r\n", 1)[1][:4096]
                if FORM_PASS.search(body):
                    m = FORM_USER.search(body)
                    user = urllib.parse.unquote_plus(m.group(1).decode("ascii", "ignore")) if m else None
                    return {"proto": "HTTP φόρμα", "field": "pass", "user": user and user[:64]}
    except Exception:
        return None
    return None


def make_parser():
    from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, IPv6
    from scapy.layers.dhcp import BOOTP  # noqa: F401  (registers DHCP dissector)

    def parse(pkt):
        P = {"t": time.time(), "len": len(pkt)}
        if Ether in pkt:
            P["smac"] = pkt[Ether].src
        if ARP in pkt:
            a = pkt[ARP]
            P.update(src=a.psrc, dst=a.pdst, proto="ARP",
                     arp=dict(op=int(a.op), psrc=a.psrc, pdst=a.pdst, hwsrc=a.hwsrc))
            return P
        if IP in pkt:
            P["src"], P["dst"] = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            P["src"], P["dst"] = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return None
        if TCP in pkt:
            tcp = pkt[TCP]
            P.update(proto="TCP", sp=int(tcp.sport), dp=int(tcp.dport), flags=str(tcp.flags))
            pl = bytes(tcp.payload)
            if pl:
                cred = parse_cleartext(P["sp"], P["dp"], pl)
                if cred:
                    P["cred"] = cred
                if pl[0] == 0x16:
                    ch = parse_client_hello(pl)
                    if ch:
                        P["sni"], P["ja3"], P["ja4"] = ch["sni"], ch["ja3"], ch["ja4"]
                elif pl[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                    m = HTTP_HOST.search(pl[:2048])
                    if m:
                        P["http_host"] = m.group(1).decode("ascii", "ignore")
        elif UDP in pkt:
            udp = pkt[UDP]
            P.update(proto="UDP", sp=int(udp.sport), dp=int(udp.dport))
            if DNS in pkt:
                d = pkt[DNS]
                try:
                    qd = d.qd[0] if isinstance(d.qd, list) else d.qd
                    qn = qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname)
                    if d.qr == 0:
                        P["dns_q"] = (qn.rstrip("."), int(qd.qtype))
                    elif int(d.rcode) == 3:
                        P["nx"] = qn.rstrip(".")
                except Exception:
                    pass
            if DNS in pkt and pkt[DNS].qr == 1 and pkt[DNS].ancount:
                d = pkt[DNS]
                try:
                    rrs = d.an if isinstance(d.an, list) else [d.an[i] for i in range(d.ancount)]
                    ans = []
                    for rr in rrs:
                        if getattr(rr, "type", 0) in (1, 28):
                            name = rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname)
                            ans.append((name.rstrip("."), str(rr.rdata)))
                    P["dns"] = ans
                except Exception:
                    pass
        elif ICMP in pkt:
            P.update(proto="ICMP", icmp_type=int(pkt[ICMP].type))
        elif IPv6 in pkt and pkt[IPv6].nh == 58:
            P["proto"] = "ICMPv6"
        else:
            P["proto"] = "IP"
        return P
    return parse


def live_capture(state, iface, bpf):
    from scapy.all import sniff
    parse = make_parser()

    def cb(pkt):
        if state.feed != "live":
            return
        ring = getattr(state, "pcap_ring", None)
        if ring:  # «καταγραφή γύρω από την ειδοποίηση»: τα τελευταία λεπτά σε μνήμη, για .pcap ανά ειδοποίηση
            try:
                ring.add(float(pkt.time), bytes(pkt))
            except Exception:
                pass
        try:
            P = parse(pkt)
            if P:
                P["_raw"] = bytes(pkt)[:128]
                state.process(P)
        except Exception as e:
            log("parse error:", e)
    log(f"Καταγραφή στο {iface}{' με φίλτρο ' + bpf if bpf else ''} …")
    try:
        sniff(iface=iface, prn=cb, store=False, filter=bpf or None)
    except PermissionError:
        log("✖ Χρειάζεται sudo για καταγραφή πακέτων. Τρέξε: sudo .venv/bin/python netwatch.py  (ή --demo)")
        os._exit(1)
    except Exception as e:
        if os.name != "nt":
            raise
        # Windows: συνήθως λείπει το Npcap, ή εγκαταστάθηκε με «μόνο για διαχειριστές»
        log(f"✖ Η καταγραφή στο «{iface}» απέτυχε: {e}")
        log("   Έλεγξε ότι είναι εγκατεστημένο το Npcap (https://npcap.com). Αν το εγκατέστησες με "
            "«Restrict Npcap driver's access to Administrators only», τρέξε το NetWatch ως διαχειριστής "
            "(run.bat -Admin). Δες τις διεπαφές με: python netwatch.py --list-ifaces")
        os._exit(1)


# ---------------- CTF ----------------
def ctf_load(state, level_id, speed=20):
    import ctf
    lv = ctf.level(level_id)
    path = os.path.join(HERE, lv["pcap"])
    if not os.path.exists(path):
        raise ValueError(f"Λείπει το {lv['pcap']} — τρέξε: python tools/make_ctf.py")
    state.reset("pcap", f"CTF · {lv['title']}", [lv["me"]], lv["gw"], History(":memory:"), feed="ctf")
    state.ctf_level = level_id
    state.publish(state.snapshot())
    threading.Thread(target=pcap_replay, args=(state, path, speed), daemon=True).start()
    log(f"🚩 CTF: φορτώθηκε το επίπεδο «{lv['title']}»")


def ctf_exit(state):
    o = state.origin
    state.reset(o["mode"], o["iface"], o["me"], o["gw"], o["history"], feed=o["mode"], notifier=o["notifier"])
    if o.get("seed"):
        o["seed"]()
    if o.get("start"):
        threading.Thread(target=o["start"], daemon=True).start()
    log("🚩 CTF: επιστροφή στην κανονική παρακολούθηση")


def ctf_check_rule(level_id, qid, text):
    """Τρέχει τον κανόνα του παίκτη σε ένα «καθαρό» NetWatch πάνω στο pcap του επιπέδου."""
    import ctf
    import rules as R
    lv = ctf.level(level_id)
    rs = R.parse_rules(text, "ctf")
    if not rs:
        raise R.RuleError("Κενός κανόνας")
    s = NetState("pcap", "ctf-check", [lv["me"]], lv["gw"], geo=False, rdns=False)
    s.rules.set_rules(rs)
    s.cfg["thresholds"]["alert_cooldown"] = 0
    pcap_replay(s, os.path.join(HERE, lv["pcap"]), speed=0)
    hits = [a for a in s.alerts if a["type"].startswith("Κανόνας:")]
    actors = sorted({a["actor"] for a in hits})
    return {"correct": ctf.check_rule_actors(level_id, qid, actors), "actors": actors,
            "alerts": [{"actor": a["actor"], "target": a["target"], "detail": a["detail"]} for a in hits[:10]],
            "count": len(hits)}


def seed_arp(state):
    try:
        if os.name == "nt":
            import winplat
            pairs = winplat.arp_table()
        else:
            out = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=5).stdout
            pairs = re.findall(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)", out)
        for ip, mac in pairs:
            state.arp_table[ip] = state.arp_first[ip] = norm_mac(mac)
            state.mac_ips[norm_mac(mac)].add(ip)
        log(f"ARP πίνακας: {len(state.arp_table)} εγγραφές (router MAC: {state.arp_table.get(state.gateway, '?')})")
    except Exception:
        pass


# ---------------- PCAP replay ----------------
def pcap_guess(path, limit=20000):
    """Μαντεύει ποιος είναι ο «δικός μας» υπολογιστής και ο router μέσα σε ένα pcap."""
    from scapy.all import ARP, IP, Ether, PcapReader
    out_cnt, gw_macs, mac_ip = collections.Counter(), collections.Counter(), {}
    with PcapReader(path) as rd:
        for i, p in enumerate(rd):
            if i >= limit:
                break
            if ARP in p and int(p[ARP].op) == 2:
                mac_ip[norm_mac(p[ARP].hwsrc)] = p[ARP].psrc
            if IP in p:
                s, d = p[IP].src, p[IP].dst
                if ip_kind(s) == "local" and ip_kind(d) == "public":
                    out_cnt[s] += 1
                    if Ether in p:
                        gw_macs[norm_mac(p[Ether].dst)] += 1
                if Ether in p and ip_kind(s) == "local":
                    mac_ip.setdefault(norm_mac(p[Ether].src), s)
    me = out_cnt.most_common(1)[0][0] if out_cnt else None
    gw = mac_ip.get(gw_macs.most_common(1)[0][0]) if gw_macs else None
    if not gw and me and "." in me:
        gw = me.rsplit(".", 1)[0] + ".1"
    return me, gw


def pcap_replay(state, path, speed=1.0, loop=False, done=None):
    """Ξαναπαίζει ένα pcap μέσα από την ίδια μηχανή ανίχνευσης.
    speed=1 πραγματικός χρόνος, 10 = 10x πιο γρήγορα, 0 = όσο πιο γρήγορα γίνεται.
    Οι ανιχνευτές βλέπουν τις αρχικές χρονοσφραγίδες της καταγραφής (forensics),
    ενώ τα μεγάλα κενά στην αναπαραγωγή «πηδιούνται»."""
    from scapy.all import PcapReader
    parse = make_parser()
    shift, rnd = 0.0, 0
    token = state.feed_token
    while True:
        wall0, first, last, n = time.time(), None, None, 0
        with PcapReader(path) as rd:
            for pkt in rd:
                if state.feed_token != token:  # άλλαξε η πηγή (π.χ. φορτώθηκε επίπεδο CTF)
                    return
                pt = float(pkt.time)
                if first is None:
                    first = pt
                if speed > 0:
                    delay = wall0 + (pt - first) / speed - time.time()
                    if delay > 2:  # μεγάλο κενό στην καταγραφή → το πηδάμε
                        wall0 -= delay - 2
                        delay = 2
                    if delay > 0:
                        time.sleep(delay)
                elif n % 200 == 0:
                    time.sleep(0.005)
                try:
                    P = parse(pkt)
                except Exception:
                    P = None
                if P:
                    P["t"] = pt + shift
                    P["_raw"] = bytes(pkt)[:128]
                    state.process(P)
                    n += 1
                last = pt
        log(f"PCAP: τέλος αναπαραγωγής #{rnd + 1} ({n} πακέτα, {state.alert_seq} ειδοποιήσεις)")
        if not loop:
            break
        rnd += 1
        shift += (last or 0) - (first or 0) + 3600  # κάθε επανάληψη «μετά» την προηγούμενη
        time.sleep(3)
    if done:
        done()
