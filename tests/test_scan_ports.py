"""🔴 Σάρωση θυρών: ήπια ανά συσκευή, με μία αργή επανάληψη — βρέθηκε σε πραγματικό δίκτυο."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_scan_ports_survives_devices_that_choke_on_bursts():
    """Πραγματικό router και καταγραφικό έδειχναν ΚΑΜΙΑ ανοιχτή θύρα: με 16+ ταυτόχρονες συνδέσεις απλώς δεν απαντούσαν.
    Ο σαρωτής κρατά έως PER_HOST συνδέσεις ανά συσκευή και ξαναδοκιμάζει μία φορά, αργά, ό,τι έμεινε σιωπηλό."""
    import threading
    import time
    import pentest
    lock, live, peak, calls = threading.Lock(), {}, {}, []
    OPEN = {("192.168.1.1", 80), ("192.168.1.1", 443), ("192.168.1.100", 8000)}

    def probe(ip, p, timeout):
        with lock:
            live[ip] = live.get(ip, 0) + 1
            peak[ip] = max(peak.get(ip, 0), live[ip])
            n = live[ip]
            calls.append((ip, p, timeout))
        time.sleep(0.002)
        with lock:
            live[ip] -= 1
        if ip == "192.168.1.9":                 # συσκευή με firewall: δεν απαντά ποτέ
            return pentest.TIMED_OUT
        if n > pentest.PER_HOST:                # «πνίγηκε»: θα έριχνε τη σύνδεση
            return pentest.TIMED_OUT
        if ip == "192.168.1.100" and p == 8000 and timeout < 1:
            return pentest.TIMED_OUT            # αργή συσκευή: απαντά μόνο στη 2η, πιο υπομονετική προσπάθεια
        return "HTTP/1.1 200 OK" if (ip, p) in OPEN else None

    ports = list(range(1, 200)) + [443, 8000]
    r = pentest.scan_ports(["192.168.1.1", "192.168.1.100", "192.168.1.9"], ports, probe=probe)
    assert [p for p, _ in r["192.168.1.1"]] == [80, 443] and [p for p, _ in r["192.168.1.100"]] == [8000] and "192.168.1.9" not in r
    assert max(peak.values()) <= pentest.PER_HOST
    # η συσκευή που δεν απαντά ποτέ (201 θύρες > RETRY_MAX) ξαναδοκιμάζεται ΜΟΝΟ στις γνωστές θύρες — όχι σε όλες
    again9 = {c[1] for c in calls if c[0] == "192.168.1.9" and c[2] > 1}
    assert again9 and again9 <= pentest.COMMON_RETRY
    assert [c for c in calls if c[0] == "192.168.1.100" and c[1] == 8000 and c[2] > 1]


def test_firewalled_router_keeps_open_ports_that_answered_late():
    """Πραγματικό DrayTek: «καταπίνει» 999 κλειστές θύρες (καμία απάντηση) και υπό φόρτο το SSH άργησε >0,6″.
    Πριν: >RETRY_MAX σιωπηλές → καμία επανάληψη → το 22 χανόταν. Τώρα ξαναδοκιμάζονται οι γνωστές θύρες."""
    import pentest
    OPEN = {21, 22, 23, 443, 1723}

    def probe(ip, p, timeout):
        if p == 22 and timeout < 1:
            return pentest.TIMED_OUT           # άργησε στο 1ο πέρασμα
        return "x" if p in OPEN else pentest.TIMED_OUT

    r = pentest.scan_ports(["192.168.1.1"], list(range(1, 1001)) + [1723], probe=probe)
    assert [p for p, _ in r["192.168.1.1"]] == [21, 22, 23, 443, 1723]


def test_grab_tells_timeout_from_refused(monkeypatch):
    import socket
    import pentest
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(socket.timeout()))
    assert pentest.grab("192.168.1.1", 80) is None and pentest.grab("192.168.1.1", 80, tell_timeout=True) is pentest.TIMED_OUT
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError()))
    assert pentest.grab("192.168.1.1", 80, tell_timeout=True) is None


def test_same_mac_on_several_ips_is_a_repeater_not_a_phone():
    """Βρέθηκε live: 4 διευθύνσεις με την ίδια MAC έβγαιναν όλες «τυχαία MAC (κινητό/laptop)».
    Ήταν ένας αναμεταδότης Wi‑Fi (η IP με SSH/HTTP) και οι συσκευές πίσω του."""
    import pentest
    rand = "τυχαία MAC (κινητό/laptop με ιδιωτικότητα)"
    hosts = [{"ip": "192.168.1.236", "mac": "4a:22:54:00:ae:08", "vendor": rand, "services": [{"port": 22}, {"port": 80}]},
             {"ip": "192.168.1.181", "mac": "4A:22:54:00:AE:08", "vendor": rand, "services": []},
             {"ip": "192.168.1.197", "mac": "4a:22:54:00:ae:08", "vendor": rand, "services": []},
             {"ip": "192.168.1.250", "mac": "28:d1:27:1a:c9:6a", "vendor": "Xiaomi", "services": []},
             {"ip": "192.168.1.254", "mac": "48:4c:29:2e:a7:b3", "vendor": "Huawei", "gw": True, "services": [{"port": 80}]}]
    pentest.mark_shared_macs(hosts)
    by = {h["ip"]: h for h in hosts}
    assert by["192.168.1.236"]["shared_mac"]["role"] == "repeater" and "αναμεταδότης" in by["192.168.1.236"]["vendor"]
    assert by["192.168.1.181"]["shared_mac"] == {"role": "behind", "ips": ["192.168.1.181", "192.168.1.197", "192.168.1.236"], "via": "192.168.1.236"}
    assert "πίσω από τον αναμεταδότη 192.168.1.236" in by["192.168.1.197"]["vendor"]
    assert "shared_mac" not in by["192.168.1.250"] and by["192.168.1.250"]["vendor"] == "Xiaomi"   # μοναδική MAC: ανέγγιχτη
    assert "shared_mac" not in by["192.168.1.254"]                                                 # ο router δεν πειράζεται


def test_shared_mac_without_a_clear_repeater_says_so():
    import pentest
    hosts = [{"ip": "10.0.0.5", "mac": "aa:aa:aa:00:00:01", "services": []}, {"ip": "10.0.0.6", "mac": "aa:aa:aa:00:00:01", "services": []}]
    pentest.mark_shared_macs(hosts)
    assert all(h["shared_mac"]["role"] == "unknown" and "ή συσκευή με πολλές IP" in h["vendor"] for h in hosts)
