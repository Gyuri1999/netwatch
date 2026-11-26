"""can_capture(): «μπορώ να πιάνω πακέτα;» — root, ή στο macOS πρόσβαση στις /dev/bpf* (Live χωρίς κωδικό)."""
import core
import pentest


def _as_user(monkeypatch, platform, bpf_ok):
    monkeypatch.setattr(core.os, "geteuid", lambda: 501, raising=False)
    monkeypatch.setattr(core.sys, "platform", platform)
    monkeypatch.setattr(core.os, "access", lambda p, m: bpf_ok and p == "/dev/bpf0")


def test_root_can_capture(monkeypatch):
    monkeypatch.setattr(core.os, "geteuid", lambda: 0, raising=False)
    assert core.can_capture()


def test_mac_user_with_bpf_access_can_capture(monkeypatch):
    _as_user(monkeypatch, "darwin", True)
    assert core.can_capture()


def test_mac_user_without_bpf_access_cannot(monkeypatch):
    _as_user(monkeypatch, "darwin", False)
    assert not core.can_capture()


def test_linux_user_is_not_fooled_by_bpf_path(monkeypatch):
    _as_user(monkeypatch, "linux", True)
    assert not core.can_capture()


def test_pentest_uses_arp_when_capture_allowed(monkeypatch):
    """Χωρίς root αλλά με /dev/bpf*, η ARP ανακάλυψη τρέχει (πριν έλεγχε μόνο «είμαι root;»)."""
    _as_user(monkeypatch, "darwin", True)
    called = []
    monkeypatch.setattr(pentest, "arp_discover", lambda cidr, *a, **k: called.append(cidr) or {})
    try:
        pentest.LanScanner._real(pentest.LanScanner.__new__(pentest.LanScanner), "192.168.1.0/30", [], {})
    except Exception:
        pass  # μας ενδιαφέρει μόνο αν κλήθηκε η ARP ανακάλυψη (το υπόλοιπο σκανάρισμα δεν τρέχει εδώ)
    assert called == ["192.168.1.0/30"]


def test_scan_adds_sleepy_devices_from_os_arp_cache(monkeypatch):
    """Το Pi δεν απάντησε στο ARP broadcast, αλλά ο υπολογιστής το έχει στον πίνακα ARP: μπαίνει στη σάρωση."""
    _as_user(monkeypatch, "darwin", True)
    monkeypatch.setattr(pentest, "arp_discover", lambda cidr, *a, **k: {"192.168.1.1": "00:1d:aa:04:14:fc"})
    monkeypatch.setattr(pentest, "os_arp_cache", lambda: {"192.168.1.13": "2c:cf:67:83:56:37",
                                                          "10.0.0.9": "aa:bb:cc:dd:ee:01"})  # εκτός στόχου: αγνοείται
    scanned = []
    monkeypatch.setattr(pentest, "scan_ports", lambda cand, ports, progress=None: scanned.extend(cand) or {})
    sc = pentest.LanScanner.__new__(pentest.LanScanner)
    monkeypatch.setattr(sc, "_set", lambda **k: None, raising=False)
    monkeypatch.setattr(sc, "_enrich", lambda hosts, udp: None, raising=False)
    ips = [f"192.168.1.{i}" for i in range(1, 255)]
    hosts = sc._real("192.168.1.0/24", ips, {})
    assert scanned == ["192.168.1.1", "192.168.1.13"]
    assert {h["ip"]: h["mac"] for h in hosts} == {"192.168.1.1": "00:1d:aa:04:14:fc", "192.168.1.13": "2c:cf:67:83:56:37"}


def test_os_arp_cache_skips_incomplete_and_broadcast(monkeypatch):
    out = ("? (192.168.1.1) at 0:1d:aa:4:14:fc on en0 ifscope [ethernet]\n"
           "? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]\n"
           "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
           "? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n")
    monkeypatch.setattr(pentest.os, "name", "posix")
    monkeypatch.setattr(pentest.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": out})())
    assert pentest.os_arp_cache() == {"192.168.1.1": "00:1d:aa:04:14:fc"}
