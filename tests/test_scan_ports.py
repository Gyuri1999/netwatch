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
    # η συσκευή που δεν απαντά ποτέ (201 θύρες > RETRY_MAX) ΔΕΝ ξαναδοκιμάζεται — αλλιώς μια πλήρης σάρωση δεν θα τελείωνε
    assert not [c for c in calls if c[0] == "192.168.1.9" and c[2] > 1]
    assert [c for c in calls if c[0] == "192.168.1.100" and c[1] == 8000 and c[2] > 1]


def test_grab_tells_timeout_from_refused(monkeypatch):
    import socket
    import pentest
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(socket.timeout()))
    assert pentest.grab("192.168.1.1", 80) is None and pentest.grab("192.168.1.1", 80, tell_timeout=True) is pentest.TIMED_OUT
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError()))
    assert pentest.grab("192.168.1.1", 80, tell_timeout=True) is None
