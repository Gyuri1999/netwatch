"""Επιθέσεις στο ίδιο το DNS: amplification, flood, NXDOMAIN flood / random subdomain, rebinding, και ο έλεγχος
DNSSEC του Wi‑Fi Guard. Κάθε ανιχνευτής έχει και «αρνητικό» test: η κανονική κίνηση δεν πρέπει να τον ενεργοποιεί."""
import os
import struct
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import netwatch as nw  # noqa: E402
import wifiguard  # noqa: E402

ME, GW = "192.168.1.50", "192.168.1.1"


@pytest.fixture
def state():
    return nw.NetState("test", "test0", [ME], GW, geo=False, rdns=False)


class Clock:
    def __init__(self):
        self.t = 1_700_000_000.0

    def __call__(self, dt=0.01):
        self.t += dt
        return self.t


def feed(s, clock, **P):
    P.setdefault("len", 80)
    P["t"] = clock(P.pop("dt", 0.01))
    s.process(P)


def alerts(s, typ):
    return [a for a in s.alerts if a["type"].startswith(typ)]


def query(s, c, client, server, txid, name="www.example.com", sp=40000):
    feed(s, c, src=client, dst=server, proto="UDP", sp=sp, dp=53, dns_id=txid, dns_q=(name, 1))


def answer(s, c, server, client, txid, sp=40000, **kw):
    feed(s, c, src=server, dst=client, proto="UDP", sp=53, dp=sp, dns_id=txid, dns_resp=True, **kw)


# ---------------- κανονικό DNS ----------------
def test_normal_dns_raises_nothing(state):
    c = Clock()
    names = ["www.google.com", "i.ytimg.com", "graph.facebook.com", "api.github.com", "plex.tv"]
    for i in range(400):
        n = names[i % 5]
        query(state, c, ME, GW, i, n, sp=40000 + i)
        answer(state, c, GW, ME, i, sp=40000 + i, len=180, dns=[(n, f"142.250.184.{i % 50 + 1}")])
    assert not [a for a in state.alerts if a["type"].startswith(("DNS", "NXDOMAIN"))]


# ---------------- amplification ----------------
def test_unsolicited_big_answers_are_amplification(state):
    c = Clock()
    resolvers = [f"45.33.32.{i}" for i in range(1, 9)]
    for i in range(60):  # ΚΑΝΕΝΑ ερώτημα από εμάς, μεγάλες απαντήσεις ANY/TXT από πολλούς resolvers
        answer(state, c, resolvers[i % 8], ME, 1000 + i, sp=80, len=3000)
    a = alerts(state, "DNS amplification")
    assert len(a) == 1 and a[0]["target"] == ME and a[0]["sev"] == "high"
    assert a[0]["mitre"]["id"] == "T1498.002"


def test_answers_to_our_own_queries_are_not_amplification(state):
    c = Clock()
    resolvers = [f"45.33.32.{i}" for i in range(1, 9)]
    for i in range(80):  # πολλά μεγάλα, αλλά τα ζητήσαμε (π.χ. DNSSEC/ TXT records)
        query(state, c, ME, resolvers[i % 8], i, sp=40000 + i)
        answer(state, c, resolvers[i % 8], ME, i, sp=40000 + i, len=3000)
    assert not alerts(state, "DNS amplification")


def test_open_resolver_on_lan_used_as_reflector(state):
    c = Clock()
    pi = "192.168.1.5"  # Pi-hole ανοιχτό στο Internet
    for i in range(25):
        victim = f"93.184.216.{i + 1}"
        feed(state, c, src=victim, dst=pi, proto="UDP", sp=4444, dp=53, dns_id=i, dns_q=("isc.org", 255))
        answer(state, c, pi, victim, i, sp=4444, len=3500)
    a = alerts(state, "DNS amplification (ανοιχτός resolver)")
    assert len(a) == 1 and a[0]["actor"] == pi


# ---------------- flood ----------------
def test_dns_query_flood(state):
    c = Clock()
    for i in range(1100):
        query(state, c, "192.168.1.66", GW, i % 65536, f"x{i}.example.com", sp=1024 + i % 60000)
    a = alerts(state, "DNS flood")
    assert len(a) == 1 and a[0]["actor"] == "192.168.1.66" and a[0]["target"] == GW
    assert a[0]["mitre"]["id"] == "T1499.002"


def test_busy_but_normal_resolver_is_not_flood(state):
    c = Clock()
    for i in range(600):  # 60 ερωτήματα/δευτ. από 10 συσκευές: πολύ, αλλά κάτω από το όριο
        query(state, c, f"192.168.1.{20 + i % 10}", GW, i, "www.example.com", sp=40000 + i)
    assert not alerts(state, "DNS flood")


# ---------------- NXDOMAIN flood / random subdomain ----------------
def test_random_subdomain_water_torture(state):
    c = Clock()
    for i in range(220):
        answer(state, c, GW, f"192.168.1.{20 + i % 30}", i, sp=40000 + i, nx=f"q{i * 7919 % 100000:05d}zz.victim-bank.com")
    a = alerts(state, "NXDOMAIN flood (random subdomain)")
    assert len(a) == 1 and a[0]["target"] == "victim-bank.com"


def test_nxdomain_flood_many_domains(state):
    c = Clock()
    for i in range(220):
        answer(state, c, GW, ME, i, sp=40000 + i, nx=f"host{i}.example{i % 50}.net")
    a = alerts(state, "NXDOMAIN flood")
    assert a and a[0]["type"] == "NXDOMAIN flood" and a[0]["target"] == GW


def test_few_nxdomains_are_fine(state):
    c = Clock()
    for i in range(40):
        answer(state, c, GW, ME, i, sp=40000 + i, nx=f"typo{i}.example.com")
    assert not alerts(state, "NXDOMAIN flood")


# ---------------- rebinding ----------------
def test_dns_rebinding_public_then_private(state):
    c = Clock()
    answer(state, c, "45.33.32.53", ME, 1, dns=[("rebind.attacker.example", "45.33.32.80")])
    answer(state, c, "45.33.32.53", ME, 2, dt=5, dns=[("rebind.attacker.example", "192.168.1.1")])
    a = alerts(state, "DNS rebinding")
    assert len(a) == 1 and a[0]["target"] == "rebind.attacker.example" and a[0]["mitre"]["id"] == "T1189"


@pytest.mark.parametrize("name,ip", [
    ("ads.tracker.example", "0.0.0.0"),        # Pi-hole / AdGuard μπλοκάρουν έτσι
    ("192-168-1-20.abcd.plex.direct", "192.168.1.20"),  # σχεδιασμένο να δείχνει στο LAN
    ("nas.local", "192.168.1.20"),
])
def test_not_rebinding(state, name, ip):
    c = Clock()
    answer(state, c, GW, ME, 1, dns=[(name, "45.33.32.80")])
    answer(state, c, GW, ME, 2, dt=5, dns=[(name, ip)])
    assert not alerts(state, "DNS rebinding")


def test_private_answer_without_public_history_is_not_rebinding(state):
    c = Clock()  # split-horizon DNS: το όνομα του homelab δείχνει πάντα στο LAN
    answer(state, c, GW, ME, 1, dns=[("home.mydomain.example", "192.168.1.10")])
    assert not alerts(state, "DNS rebinding")


def test_detectors_can_be_disabled():
    s = nw.NetState("test", "test0", [ME], GW, geo=False, rdns=False)
    s.cfg["detectors"]["dns_rebinding"] = False
    c = Clock()
    answer(s, c, "45.33.32.53", ME, 1, dns=[("rebind.attacker.example", "45.33.32.80")])
    answer(s, c, "45.33.32.53", ME, 2, dns=[("rebind.attacker.example", "127.0.0.1")])
    assert not alerts(s, "DNS rebinding")


# ---------------- parser: ο txid και η «απάντηση» φτάνουν στη μηχανή ----------------
def test_parser_exposes_txid_and_response_flag():
    from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether
    import capture
    parse = capture.make_parser()
    q = Ether() / IP(src=ME, dst=GW) / UDP(sport=40000, dport=53) / DNS(id=4242, rd=1, qd=DNSQR(qname="a.example"))
    r = Ether() / IP(src=GW, dst=ME) / UDP(sport=53, dport=40000) / DNS(
        id=4242, qr=1, qd=DNSQR(qname="a.example"), an=DNSRR(rrname="a.example", rdata="45.33.32.7"))
    pq, pr = parse(Ether(bytes(q))), parse(Ether(bytes(r)))  # όπως από το καλώδιο: μετρητές (ancount) υπολογισμένοι
    assert pq["dns_id"] == 4242 and not pq.get("dns_resp") and pq["dns_q"][0] == "a.example"
    assert pr["dns_id"] == 4242 and pr["dns_resp"] and pr["dns"] == [("a.example", "45.33.32.7")]


# ---------------- DNSSEC (Wi‑Fi Guard) ----------------
def fake_resolver(signed_ad=True, bogus_rcode=2, bogus_answers=0, signed_ok=True):
    def q(server, name):
        if name in wifiguard.DNSSEC_SIGNED:
            return {"rcode": 0 if signed_ok else 2, "ad": signed_ad, "answers": 2 if signed_ok else 0}
        return {"rcode": bogus_rcode, "ad": False, "answers": bogus_answers}
    return q


def test_dnssec_validating():
    r = wifiguard.dnssec_check("9.9.9.9", fake_resolver())
    assert r["validating"] is True and not r["bypass"] and not r["ad_stripped"]


def test_dnssec_validated_upstream_router_strips_ad():
    r = wifiguard.dnssec_check("192.168.1.1", fake_resolver(signed_ad=False))
    assert r["validating"] is True and r["ad_stripped"]


def test_dnssec_not_validating():
    r = wifiguard.dnssec_check("10.0.0.1", fake_resolver(signed_ad=False, bogus_rcode=0, bogus_answers=1))
    assert r["validating"] is False and not r["bypass"]
    c = {x["id"]: x for x in wifiguard.evaluate({"dnssec": r, "public": True})["checks"]}
    assert c["dnssec"]["status"] == "warn"


def test_dnssec_bypass_claims_ad_but_accepts_bogus():
    r = wifiguard.dnssec_check("10.0.0.1", fake_resolver(signed_ad=True, bogus_rcode=0, bogus_answers=1))
    assert r["validating"] is False and r["bypass"]
    c = {x["id"]: x for x in wifiguard.evaluate({"dnssec": r, "public": True})["checks"]}
    assert c["dnssec"]["status"] == "bad" and wifiguard.ALERT_FOR["dnssec"][0] == "DNSSEC bypass στο Wi‑Fi"


def test_dnssec_unknown_when_nothing_resolves():
    assert wifiguard.dnssec_check("10.0.0.1", lambda s, n: None)["validating"] is None
    assert wifiguard.dnssec_check("10.0.0.1", fake_resolver(signed_ok=False))["validating"] is None


def test_dns_query_wire_format_and_flags():
    # ο parser των flags: rcode στα 4 χαμηλά bits, AD = 0x20
    hdr = struct.pack(">HHHHHH", 7, 0x81A0, 1, 2, 0, 1)
    assert wifiguard.parse_dns_flags(hdr) == {"rcode": 0, "ad": True, "answers": 2}
    hdr = struct.pack(">HHHHHH", 7, 0x8182, 1, 0, 0, 1)
    assert wifiguard.parse_dns_flags(hdr) == {"rcode": 2, "ad": False, "answers": 0}


def test_dns_query_against_local_fake_server():
    """Πραγματικό UDP: ένας ψεύτικος DNS server στο 127.0.0.1 απαντά — δουλεύει ίδια σε macOS/Linux/Windows."""
    import socket
    import threading
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    got = {}

    def serve():
        data, addr = srv.recvfrom(2048)
        got["q"] = data
        txid = data[:2]
        srv.sendto(txid + struct.pack(">HHHHH", 0x81A0, 1, 1, 0, 0), addr)
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    try:
        r = wifiguard.dns_query("127.0.0.1", "sigok.verteiltesysteme.net", timeout=2, port=port)
    finally:
        srv.close()
    assert r == {"rcode": 0, "ad": True, "answers": 1}
    q = got["q"]
    flags, ar = struct.unpack(">H", q[2:4])[0], struct.unpack(">H", q[10:12])[0]
    assert flags & 0x0100 and flags & 0x0020 and ar == 1  # RD + AD, και EDNS0 (OPT)
    assert b"\x05sigok\x10verteiltesysteme\x03net\x00" in q
    assert q[-11:-8] == b"\x00\x00\x29" and struct.unpack(">I", q[-6:-2])[0] == 0x8000  # OPT με DO=1


# ---------------- όλα τα νέα κείμενα έχουν αγγλική μετάφραση ----------------
def test_new_alerts_and_checks_are_translated(monkeypatch):
    import re
    import i18n
    monkeypatch.setattr(i18n, "_cache", i18n.load(os.path.join(ROOT, "i18n")))
    greek = re.compile("[Ͱ-Ͽἀ-῿]")
    s = nw.NetState("test", "test0", [ME], GW, geo=False, rdns=False)
    c = Clock()
    for i in range(60):
        answer(s, c, f"45.33.32.{i % 8 + 1}", ME, 1000 + i, sp=80, len=3000)
    for i in range(25):
        answer(s, c, "192.168.1.5", f"93.184.216.{i + 1}", i, sp=4444, len=3500)
    for i in range(1100):
        query(s, c, f"192.168.1.{60 + i % 3}", GW, i, f"x{i}.example.com", sp=1024 + i)
    for i in range(220):
        answer(s, c, GW, ME, i, sp=40000 + i, nx=f"q{i:05d}zz.victim-bank.com")
        answer(s, c, "192.168.1.2", ME, i, sp=40000 + i, nx=f"host{i}.example{i % 50}.net")
    answer(s, c, "45.33.32.53", ME, 1, dns=[("rebind.attacker.example", "45.33.32.80")])
    answer(s, c, "45.33.32.53", ME, 2, dt=5, dns=[("rebind.attacker.example", "192.168.1.1")])
    new = [a for a in s.alerts if a["type"].startswith(("DNS", "NXDOMAIN"))]
    assert {a["type"] for a in new} >= {"DNS amplification", "DNS amplification (ανοιχτός resolver)", "DNS flood",
                                        "NXDOMAIN flood", "NXDOMAIN flood (random subdomain)", "DNS rebinding"}
    texts = [x for a in new for x in (a["type"], a["detail"], a["actor"])]
    for ad in (True, False):
        for r in (wifiguard.dnssec_check("10.0.0.1", fake_resolver(signed_ad=ad)),
                  wifiguard.dnssec_check("10.0.0.1", fake_resolver(signed_ad=ad, bogus_rcode=0, bogus_answers=1))):
            ck = {x["id"]: x for x in wifiguard.evaluate({"dnssec": r, "public": True})["checks"]}["dnssec"]
            texts += [ck["detail"]] + ([ck["fix"]] if ck.get("fix") else [])
    texts.append(wifiguard.ALERT_FOR["dnssec"][0])
    for t in texts:
        assert not greek.search(i18n.tr(t, "en")), t
