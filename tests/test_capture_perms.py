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
