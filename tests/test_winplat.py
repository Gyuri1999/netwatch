"""Οι parsers των Windows (winplat) — με πραγματικές εξόδους, και σε ελληνικά Windows."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import latency  # noqa: E402
import netkit  # noqa: E402
import winplat as w  # noqa: E402

PING_EN = """
Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=12ms TTL=57
Reply from 1.1.1.1: bytes=32 time<1ms TTL=57
Request timed out.
Reply from 1.1.1.1: bytes=32 time=14ms TTL=57

Ping statistics for 1.1.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 14ms, Average = 8ms
"""

PING_EL = """
Λειτουργία Ping 192.168.1.1 με 32 byte δεδομένων:
Απάντηση από 192.168.1.1: byte=32 χρόνος=3ms TTL=64
Απάντηση από 192.168.1.1: byte=32 χρόνος=2ms TTL=64

Στατιστικά στοιχεία Ping για 192.168.1.1:
    Πακέτα: Απεσταλμένα = 2, Ληφθέντα = 2, Απολεσθέντα = 0 (0% απώλεια),
Κατά προσέγγιση χρόνοι μετάβασης μετ' επιστροφής σε χιλιοστά του δευτερολέπτου:
    Ελάχιστος = 2ms, Μέγιστος = 3ms, Μέσος όρος = 2ms
"""

PING_UNREACH = """
Pinging 192.168.1.77 with 32 bytes of data:
Reply from 192.168.1.49: Destination host unreachable.
Reply from 192.168.1.49: Destination host unreachable.
"""

PING_V6 = """
Pinging ::1 with 32 bytes of data:
Reply from ::1: time<1ms
Reply from ::1: time<1ms
"""


def test_ping_english_to_unix_parsers():
    out = w.ping_to_unix(PING_EN, "1.1.1.1", 4)
    r = netkit.parse_ping(out)
    assert r["sent"] == 4 and r["received"] == 3 and r["loss_pct"] == 25.0
    assert r["rtts"] == [12.0, 1.0, 14.0] and r["ttl"] == 57
    rtts, sent = latency.parse_ping(out, 4)
    assert rtts == [12.0, 1.0, 14.0] and sent == 4


def test_ping_greek_windows():
    r = netkit.parse_ping(w.ping_to_unix(PING_EL, "192.168.1.1", 2))
    assert r["rtts"] == [3.0, 2.0] and r["ttl"] == 64 and r["loss_pct"] == 0.0


def test_ping_unreachable_counts_as_loss():
    # «Reply from <η δική μου IP>: Destination host unreachable» — δεν είναι απάντηση του στόχου
    r = netkit.parse_ping(w.ping_to_unix(PING_UNREACH, "192.168.1.77", 2))
    assert r["received"] == 0 and r["loss_pct"] == 100.0


def test_ping_ipv6_without_ttl():
    r = netkit.parse_ping(w.ping_to_unix(PING_V6, "::1", 2))
    assert r["received"] == 2 and r["ttl"] is None


def test_ping_cmd():
    assert w.ping_cmd("1.1.1.1", 3, 1500) == ["ping", "-4", "-n", "3", "-w", "1500", "1.1.1.1"]
    assert w.ping_cmd("::1")[1] == "-6"


ARP_A = """
Interface: 192.168.1.49 --- 0x12
  Internet Address      Physical Address      Type
  192.168.1.1           08-aa-89-41-26-04     dynamic
  192.168.1.20          3c-71-bf-00-11-22     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
"""

ARP_EL = """
Διασύνδεση: 192.168.1.49 --- 0x12
  Διεύθυνση Internet    Φυσική διεύθυνση      Τύπος
  192.168.1.1           08-aa-89-41-26-04     δυναμική
"""


def test_arp():
    assert w.parse_arp(ARP_A) == [("192.168.1.1", "08:aa:89:41:26:04"), ("192.168.1.20", "3c:71:bf:00:11:22")]
    assert w.parse_arp(ARP_EL) == [("192.168.1.1", "08:aa:89:41:26:04")]


ROUTE_PRINT = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.49     35
          0.0.0.0          0.0.0.0         10.0.0.1        10.0.0.5     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
"""


def test_route_print_lowest_metric():
    assert w.parse_route_print(ROUTE_PRINT) == ("10.0.0.1", "10.0.0.5")
    assert w.parse_route_print("") == (None, None)


def test_net_json_single_values_and_lists():
    # Το ConvertTo-Json του PowerShell 5.1 «ξετυλίγει» λίστες με ένα στοιχείο σε σκέτο αντικείμενο
    d = {"gateway": "192.168.1.1", "gateway_index": 12, "dns": "192.168.1.1",
         "interfaces": [
             {"name": "Wi-Fi", "index": 12, "up": True, "mtu": 1500, "mac": "08-AA-89-41-26-05",
              "desc": "Intel(R) Wi-Fi 6 AX201", "ipv4": {"addr": "192.168.1.49", "prefix": 24},
              "ipv6": [{"addr": "fe80::1%12", "prefix": 64}, {"addr": "2a02::5", "prefix": 64}]},
             {"name": "Ethernet", "index": 7, "up": False, "mtu": 1500, "mac": "", "ipv4": [], "ipv6": None}]}
    v = w.parse_net_json(json.dumps(d))
    assert v["gateway"] == "192.168.1.1" and v["gateway_iface"] == "Wi-Fi" and v["dns"] == ["192.168.1.1"]
    wifi = v["interfaces"][0]
    assert wifi["mac"] == "08:aa:89:41:26:05"
    assert wifi["ipv4"] == [{"addr": "192.168.1.49", "prefix": 24, "broadcast": None}]
    assert [a["addr"] for a in wifi["ipv6"]] == ["fe80::1", "2a02::5"]
    assert v["interfaces"][1]["up"] is False and v["interfaces"][1]["mac"] is None
    assert w.parse_net_json("") is None and w.parse_net_json("[1]") is None


def test_detect_net_uses_gateway_iface(monkeypatch):
    v = {"interfaces": [{"name": "Wi-Fi", "ipv4": [{"addr": "192.168.1.49"}], "ipv6": [{"addr": "fe80::1"}]},
                        {"name": "Ethernet", "ipv4": [{"addr": "10.0.0.2"}], "ipv6": []}],
         "gateway": "192.168.1.1", "gateway_iface": "Wi-Fi", "dns": []}
    monkeypatch.setattr(w, "net_info", lambda max_age=10: v)
    assert w.detect_net() == ("Wi-Fi", "192.168.1.1", {"192.168.1.49", "fe80::1"})
    assert w.detect_net("Ethernet")[2] == {"10.0.0.2"}


NETSH_EN = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 1b2c3d4e-0000-1111-2222-333344445555
    Physical address       : 08:aa:89:41:26:05
    State                  : connected
    SSID                   : HomeNet
    BSSID                  : 08:aa:89:41:26:99
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Channel                : 36
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1201
    Signal                 : 80%
    Profile                : HomeNet
"""

NETSH_EL = """
    Όνομα                  : Wi-Fi
    Κατάσταση              : συνδεδεμένο
    SSID                   : Καφέ Free
    BSSID                  : 08:aa:89:41:26:99
    Τύπος ραδιοσυχνότητας  : 802.11n
    Έλεγχος ταυτότητας     : Ανοιχτό
    Κανάλι                 : 6
    Σήμα                   : 54%
"""


def test_netsh_wifi_english():
    i = w.parse_netsh_interfaces(NETSH_EN)
    assert i["ssid"] == "HomeNet" and i["bssid"] == "08:aa:89:41:26:99"
    assert i["security"] == "wpa2_personal" and i["channel"] == "36" and i["signal"] == -60 and i["phy"] == "802.11ax"


def test_netsh_wifi_greek_open():
    i = w.parse_netsh_interfaces(NETSH_EL)
    assert i["ssid"] == "Καφέ Free" and i["security"] == "none" and i["channel"] == "6" and i["signal"] == -73


def test_netsh_not_connected():
    assert w.parse_netsh_interfaces("There is no wireless interface on the system.") is None


def test_firewall_cmds():
    add = w.firewall_cmds("203.0.113.9")
    assert [c[4] for c in add] == ["rule"] * 2
    assert "dir=in" in add[0] and "dir=out" in add[1] and "remoteip=203.0.113.9" in add[0]
    assert w.firewall_cmds("203.0.113.9", add=False) == [
        ["netsh", "advfirewall", "firewall", "delete", "rule", "name=NetWatch block 203.0.113.9"]]


def test_blocker_windows_commands():
    import blocker
    cmds = blocker.commands({"203.0.113.9"}, platform="win32")
    assert len(cmds) == 2 and cmds[0].startswith("netsh advfirewall firewall add rule") and '"name=NetWatch block' in cmds[0]


def test_vpn_names_on_windows():
    import privacy
    assert privacy.vpn_full_tunnel("NordLynx") and privacy.vpn_full_tunnel("WireGuard Tunnel")
    assert privacy.vpn_full_tunnel("utun3") and not privacy.vpn_full_tunnel("Wi-Fi")


def test_shellrun_ping_translated_for_windows(monkeypatch):
    import shellrun
    monkeypatch.setattr(shellrun.sys, "platform", "win32")
    monkeypatch.setattr(shellrun.shutil, "which", lambda c: "C:\\Windows\\System32\\" + c + ".exe")
    parts, why = shellrun.check("ping -c 2 -i 0.5 1.1.1.1")
    assert why is None and parts == [["ping", "-n", "2", "1.1.1.1"]]
    parts, _ = shellrun.check("ping 1.1.1.1")
    assert parts == [["ping", "-n", "4", "1.1.1.1"]]


def test_subprocess_defaults_noop_off_windows():
    w.install_subprocess_defaults()  # σε macOS/Linux δεν αλλάζει τίποτα
    import subprocess
    assert not getattr(subprocess.Popen, "_netwatch_patched", False) or w.IS_WIN
