"""📼 Δακτύλιος πακέτων: κρατά στη μνήμη τα τελευταία N δευτερόλεπτα / M MB κίνησης, για να βγάλεις pcap «γύρω από τον συναγερμό».

Σαν ένα μικρό Arkime: όταν χτυπήσει ειδοποίηση, εξάγεις τι έγινε 60″ πριν και 30″ μετά, μόνο για τις IP που εμπλέκονται,
και το ανοίγεις στο Wireshark.

config.yaml:
pcap_ring: {enabled: true, seconds: 300, max_mb: 64}

Η μνήμη είναι φραγμένη: όταν γεμίσει (ή περάσει ο χρόνος), πετιούνται τα παλαιότερα πακέτα.
Το φιλτράρισμα ανά IP γίνεται με struct (Ethernet + VLAN + IPv4/IPv6), χωρίς scapy — για να είναι γρήγορο.
Στο demo δεν υπάρχουν πραγματικά πακέτα: το synth_for_alert φτιάχνει ένα μικρό, εμφανώς συνθετικό pcap (…-demo.pcap).
"""
import collections
import ipaddress
import os
import random
import struct
import threading
import time

PCAP_MAGIC = 0xA1B2C3D4
SNAPLEN = 262144
LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LOOP, LINKTYPE_SLL = 0, 1, 101, 108, 113
VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)
DEFAULTS = {"enabled": True, "seconds": 300, "max_mb": 64}
REC_OVERHEAD = 64  # περίπου ό,τι κοστίζει στη μνήμη κάθε εγγραφή πέρα από τα bytes του πακέτου


def pcap_header(linktype=LINKTYPE_ETHERNET, snaplen=SNAPLEN):
    return struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, snaplen, linktype)


def pcap_record(ts, raw, orig_len=None):
    sec = int(ts)
    usec = int(round((ts - sec) * 1e6))
    if usec >= 1000000:
        sec, usec = sec + 1, usec - 1000000
    return struct.pack("<IIII", sec, usec, len(raw), orig_len or len(raw)) + raw


def build_pcap(packets, linktype=LINKTYPE_ETHERNET):
    """packets: [(ts, raw_bytes)] → bytes ενός κλασικού pcap."""
    return pcap_header(linktype) + b"".join(pcap_record(ts, raw) for ts, raw in packets)


def _ip_layer(raw, linktype):
    """(έκδοση IP, offset της κεφαλίδας IP) ή None — ελάχιστη ανάλυση, ανεκτική σε κομμένα πακέτα."""
    if linktype == LINKTYPE_ETHERNET:
        if len(raw) < 14:
            return None
        off, et = 14, struct.unpack_from("!H", raw, 12)[0]
        for _ in range(3):  # VLAN / QinQ
            if et not in VLAN_TPIDS or len(raw) < off + 4:
                break
            et, off = struct.unpack_from("!H", raw, off + 2)[0], off + 4
        if et == 0x0800:
            return 4, off
        if et == 0x86DD:
            return 6, off
        return None
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):  # BSD loopback: 4 bytes οικογένεια διευθύνσεων
        if len(raw) < 5:
            return None
        v = raw[4] >> 4
        return (v, 4) if v in (4, 6) else None
    if linktype == LINKTYPE_SLL:
        if len(raw) < 16:
            return None
        et = struct.unpack_from("!H", raw, 14)[0]
        return (4, 16) if et == 0x0800 else (6, 16) if et == 0x86DD else None
    if linktype in (LINKTYPE_RAW, 12, 228, 229):
        if not raw:
            return None
        v = raw[0] >> 4
        return (v, 0) if v in (4, 6) else None
    return None


def packet_ips(raw, linktype=LINKTYPE_ETHERNET):
    """(src, dst) ως packed bytes (4 ή 16), ή None αν δεν είναι IP."""
    lay = _ip_layer(raw, linktype)
    if not lay:
        return None
    v, off = lay
    if v == 4 and len(raw) >= off + 20:
        return raw[off + 12:off + 16], raw[off + 16:off + 20]
    if v == 6 and len(raw) >= off + 40:
        return raw[off + 8:off + 24], raw[off + 24:off + 40]
    return None


class IpMatcher:
    """Ταιριάζει packed διευθύνσεις με λίστα από IP ή δίκτυα (π.χ. "192.168.1.0/24")."""

    def __init__(self, ips):
        self.exact, self.nets = set(), []
        for x in ips or ():
            try:
                if "/" in str(x):
                    self.nets.append(ipaddress.ip_network(str(x).strip(), strict=False))
                else:
                    self.exact.add(ipaddress.ip_address(str(x).strip()).packed)
            except ValueError:
                continue

    def __bool__(self):
        return bool(self.exact or self.nets)

    def match(self, packed):
        if packed in self.exact:
            return True
        if self.nets:
            a = ipaddress.ip_address(packed)
            return any(a.version == n.version and a in n for n in self.nets)
        return False


def valid_ips(*vals):
    out = []
    for v in vals:
        try:
            out.append(str(ipaddress.ip_address(str(v).strip())))
        except ValueError:
            continue
    return out


def _fname(t, ips, demo=False):
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(t or time.time()))
    who = "_".join(i.replace(":", "-") for i in ips[:2]) or "all"
    return f"netwatch-{stamp}-{who}{'-demo' if demo else ''}.pcap"


class PcapRing:
    def __init__(self, cfg=None, sim=False):
        c = {**DEFAULTS, **(cfg or {})}
        self.enabled = bool(c.get("enabled", True))
        self.seconds = max(1.0, float(c.get("seconds") or DEFAULTS["seconds"]))
        self.max_bytes = max(1, int(float(c.get("max_mb") or DEFAULTS["max_mb"]) * 1024 * 1024))
        self.sim = sim
        self.lock = threading.Lock()
        self.buf = collections.deque()  # (ts, raw, linktype)
        self.bytes = 0
        self.total = 0
        self.dropped = 0

    # ── γέμισμα ──
    def add(self, ts, raw_bytes, linktype=LINKTYPE_ETHERNET):
        """Το καλεί ο βρόχος σύλληψης για κάθε πακέτο. Φθηνό: append + πέταγμα των παλαιότερων."""
        if not self.enabled or not raw_bytes:
            return
        raw = bytes(raw_bytes[:SNAPLEN])
        with self.lock:
            self.buf.append((float(ts), raw, int(linktype)))
            self.bytes += len(raw) + REC_OVERHEAD
            self.total += 1
            self._evict(float(ts))

    def _evict(self, now):
        cut = now - self.seconds
        b = self.buf
        while b and (self.bytes > self.max_bytes or b[0][0] < cut):
            _, raw, _ = b.popleft()
            self.bytes -= len(raw) + REC_OVERHEAD
            self.dropped += 1

    def clear(self):
        with self.lock:
            self.buf.clear()
            self.bytes = 0

    # ── εξαγωγή ──
    def select(self, start, end, ips=None):
        """Λίστα [(ts, raw, linktype)] στο παράθυρο [start, end], προαιρετικά μόνο για τις ips (src ή dst)."""
        m = IpMatcher(ips) if ips else None
        with self.lock:
            snap = [p for p in self.buf if start <= p[0] <= end]
        if not m:
            return snap
        out = []
        for p in snap:
            pr = packet_ips(p[1], p[2])
            if pr and (m.match(pr[0]) or m.match(pr[1])):
                out.append(p)
        return out

    def export(self, start, end, ips=None, path=None):
        """bytes ενός έγκυρου pcap με τα πακέτα του παραθύρου. Ένα pcap έχει έναν τύπο link: κρατάμε τον πιο συχνό."""
        pk = self.select(start, end, ips)
        lts = collections.Counter(p[2] for p in pk)
        lt = lts.most_common(1)[0][0] if lts else LINKTYPE_ETHERNET
        data = build_pcap([(p[0], p[1]) for p in pk if p[2] == lt], lt)
        if path:
            d = os.path.dirname(os.path.abspath(path))
            os.makedirs(d, exist_ok=True)
            with open(path, "wb") as f:
                f.write(data)
        return data

    def export_for_alert(self, alert, before=60, after=30, path=None):
        """pcap γύρω από έναν συναγερμό (t − before … t + after), μόνο για actor/target αν είναι IP.
        Στο demo (ή χωρίς ενεργό δακτύλιο σε demo) επιστρέφει συνθετικό pcap."""
        if self.sim:
            return self.synth_for_alert(alert)
        t = float(alert.get("t") or time.time())
        ips = valid_ips(alert.get("actor"), alert.get("target"))
        start, end = t - before, t + after
        data = self.export(start, end, ips or None, path=path)
        n = self._count(data)
        return {"pcap": data, "filename": _fname(t, ips), "count": n, "bytes": len(data), "start": start, "end": end,
                "ips": ips, "synthetic": False,
                "note": None if n else "Δεν βρέθηκαν πακέτα στο παράθυρο — ίσως είναι παλαιότερα από τον δακτύλιο ή ο δακτύλιος είναι ανενεργός."}

    @staticmethod
    def _count(data):
        n, off = 0, 24
        while off + 16 <= len(data):
            off += 16 + struct.unpack_from("<I", data, off + 8)[0]
            n += 1
        return n

    # ── demo ──
    def synth_for_alert(self, alert):
        """Μικρό, εύλογο pcap για το demo (φτιαγμένο με scapy). ΣΥΝΘΕΤΙΚΟ — το όνομα αρχείου τελειώνει σε -demo.pcap."""
        from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw  # βαρύ import μόνο όταν χρειαστεί

        t0 = float(alert.get("t") or time.time()) - 5
        typ = str(alert.get("type") or "")
        ips = valid_ips(alert.get("actor"), alert.get("target"))
        a = ips[0] if ips else "192.168.1.66"
        b = ips[1] if len(ips) > 1 else ("192.168.1.10" if a != "192.168.1.10" else "192.168.1.1")
        if ":" in a or ":" in b:  # κρατάμε το demo απλό: IPv4
            a, b = "192.168.1.66", "192.168.1.10"
        ma, mb = "02:00:00:00:00:66", "02:00:00:00:00:10"
        rnd = random.Random(f"{typ}|{a}|{b}")
        pk, ts = [], t0

        def put(p, dt=0.002):
            nonlocal ts
            ts += dt * rnd.uniform(0.5, 1.5)
            pk.append((ts, bytes(p)))

        sport = rnd.randint(40000, 60000)
        low = typ.lower()
        if "scan" in low or "sweep" in low or "flood" in low:
            if "udp" in low:
                for port in (53, 67, 123, 137, 161, 500, 1900, 5353):
                    put(Ether(src=ma, dst=mb) / IP(src=a, dst=b) / UDP(sport=sport, dport=port))
                    put(Ether(src=mb, dst=ma) / IP(src=b, dst=a) / ICMP(type=3, code=3) / IP(src=a, dst=b) / UDP(sport=sport, dport=port))
            elif "ping" in low or "icmp" in low:
                base = b.rsplit(".", 1)[0]
                for i in range(1, 40):
                    put(Ether(src=ma, dst=mb) / IP(src=a, dst=f"{base}.{i}") / ICMP(id=0x4e57, seq=i))
            else:
                for port in [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900, 8080, 8443] + rnd.sample(range(1024, 65535), 24):
                    put(Ether(src=ma, dst=mb) / IP(src=a, dst=b) / TCP(sport=sport, dport=port, flags="S", seq=rnd.getrandbits(32)), 0.001)
                    if port in (22, 80, 443):
                        put(Ether(src=mb, dst=ma) / IP(src=b, dst=a) / TCP(sport=port, dport=sport, flags="SA", ack=1, seq=rnd.getrandbits(32)))
                        put(Ether(src=ma, dst=mb) / IP(src=a, dst=b) / TCP(sport=sport, dport=port, flags="R"))
                    else:
                        put(Ether(src=mb, dst=ma) / IP(src=b, dst=a) / TCP(sport=port, dport=sport, flags="RA"))
        elif "dns" in low or "dga" in low:
            for i in range(12):
                name = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rnd.randint(12, 30))) + ".example-demo.net"
                put(Ether(src=ma, dst=mb) / IP(src=a, dst=b) / UDP(sport=rnd.randint(30000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=name)), 0.3)
        else:
            dport = 22 if "brute" in low else 1883 if "κωδικ" in low else 443
            seq, ack = rnd.getrandbits(31), rnd.getrandbits(31)
            put(Ether(src=ma, dst=mb) / IP(src=a, dst=b) / TCP(sport=sport, dport=dport, flags="S", seq=seq))
            put(Ether(src=mb, dst=ma) / IP(src=b, dst=a) / TCP(sport=dport, dport=sport, flags="SA", seq=ack, ack=seq + 1))
            put(Ether(src=ma, dst=mb) / IP(src=a, dst=b) / TCP(sport=sport, dport=dport, flags="A", seq=seq + 1, ack=ack + 1))
            seq, ack = seq + 1, ack + 1
            for i in range(6):
                body = f"NETWATCH-DEMO synthetic payload {i}\n".encode()
                put(Ether(src=ma, dst=mb) / IP(src=a, dst=b) / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack) / Raw(body), 0.05)
                seq += len(body)
                reply = f"NETWATCH-DEMO reply {i}\n".encode()
                put(Ether(src=mb, dst=ma) / IP(src=b, dst=a) / TCP(sport=dport, dport=sport, flags="PA", seq=ack, ack=seq) / Raw(reply))
                ack += len(reply)
            put(Ether(src=ma, dst=mb) / IP(src=a, dst=b) / TCP(sport=sport, dport=dport, flags="FA", seq=seq, ack=ack), 0.05)
            put(Ether(src=mb, dst=ma) / IP(src=b, dst=a) / TCP(sport=dport, dport=sport, flags="FA", seq=ack, ack=seq + 1))
            put(Ether(src=ma, dst=mb) / IP(src=a, dst=b) / TCP(sport=sport, dport=dport, flags="A", seq=seq + 1, ack=ack + 1))
        data = build_pcap(pk, LINKTYPE_ETHERNET)
        t = float(alert.get("t") or time.time())
        return {"pcap": data, "filename": _fname(t, [a, b], demo=True), "count": len(pk), "bytes": len(data),
                "start": pk[0][0] if pk else t, "end": pk[-1][0] if pk else t, "ips": [a, b], "synthetic": True,
                "note": "Συνθετικό pcap του demo — δεν είναι πραγματική κίνηση."}

    def stats(self):
        with self.lock:
            oldest = self.buf[0][0] if self.buf else None
            newest = self.buf[-1][0] if self.buf else None
            lts = dict(collections.Counter(p[2] for p in self.buf))
            return {"enabled": self.enabled, "demo": self.sim, "packets": len(self.buf), "bytes": self.bytes,
                    "max_bytes": self.max_bytes, "seconds": self.seconds, "oldest": oldest, "newest": newest,
                    "span": round(newest - oldest, 3) if oldest is not None else 0.0,
                    "fill": round(self.bytes / self.max_bytes, 4), "total": self.total, "dropped": self.dropped,
                    "linktypes": {str(k): v for k, v in lts.items()}}

    status = stats
