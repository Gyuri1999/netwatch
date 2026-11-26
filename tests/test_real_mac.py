"""🩺 Ποτέ πακέτο με την «κρυμμένη» MAC του macOS (02:00:00:00:00:00): δηλητηριάζει τον router (βρέθηκε live)."""
import pytest

import core
import pentest

scapy_all = pytest.importorskip("scapy.all")


@pytest.fixture(autouse=True)
def _clear():
    core._real_mac_cache.clear()
    yield
    core._real_mac_cache.clear()


def test_placeholder_mac_is_never_used(monkeypatch):
    monkeypatch.setattr(scapy_all, "get_if_hwaddr", lambda i: "02:00:00:00:00:00")
    monkeypatch.setattr(core, "_mac_from_own_frame", lambda iface, gw, timeout=1.5: "56:e5:fa:0e:66:7d")
    monkeypatch.setattr(scapy_all.conf.route, "route", lambda dst: ("en0", "192.168.1.10", "192.168.1.1"))
    assert core.real_mac("en0") == "56:e5:fa:0e:66:7d"


def test_no_real_mac_means_no_arp_sent(monkeypatch):
    monkeypatch.setattr(scapy_all, "get_if_hwaddr", lambda i: "02:00:00:00:00:00")
    monkeypatch.setattr(core, "_mac_from_own_frame", lambda iface, gw, timeout=1.5: None)
    monkeypatch.setattr(scapy_all.conf.route, "route", lambda dst: ("en0", "192.168.1.10", "192.168.1.1"))
    sent = []
    monkeypatch.setattr(scapy_all, "srp", lambda *a, **k: sent.append(a) or ([], []))
    with pytest.raises(RuntimeError):
        core.arp_request("192.168.1.0/24", iface="en0")
    assert sent == [] and pentest.arp_discover("192.168.1.0/24") == {}  # η ανακάλυψη απλώς δεν γίνεται


def test_arp_uses_real_mac_as_sender(monkeypatch):
    monkeypatch.setattr(scapy_all, "get_if_hwaddr", lambda i: "02:00:00:00:00:00")
    monkeypatch.setattr(core, "_mac_from_own_frame", lambda iface, gw, timeout=1.5: "56:e5:fa:0e:66:7d")
    monkeypatch.setattr(scapy_all.conf.route, "route", lambda dst: ("en0", "192.168.1.10", "192.168.1.1"))
    sent = []
    monkeypatch.setattr(scapy_all, "srp", lambda pkt, **k: sent.append(pkt) or ([], []))
    core.arp_request("192.168.1.1", iface="en0")
    pkt = sent[0]
    assert pkt[scapy_all.Ether].src == "56:e5:fa:0e:66:7d" and pkt[scapy_all.ARP].hwsrc == "56:e5:fa:0e:66:7d"


def test_public_gateway_is_never_probed(monkeypatch):
    monkeypatch.setattr(scapy_all, "get_if_hwaddr", lambda i: "02:00:00:00:00:00")
    called = []
    monkeypatch.setattr(core, "_mac_from_own_frame", lambda iface, gw, timeout=1.5: called.append(gw))
    monkeypatch.setattr(scapy_all.conf.route, "route", lambda dst: ("en0", "1.2.3.4", "8.8.8.8"))
    assert core.real_mac("en0") is None and called == []


def test_norm_mac():
    assert core._norm_mac("0:1d:aa:4:14:fc") == "00:1d:aa:04:14:fc"
    for bad in ("02:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb", "", None, "zz:00:00:00:00:00"):
        assert core._norm_mac(bad) is None
