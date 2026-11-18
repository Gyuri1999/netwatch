"""Tests για την αυτόματη τεκμηρίωση δικτύου (netdocs.py) — χωρίς πραγματικό δίκτυο."""
import os
import re
import sys
import threading
import types
import xml.etree.ElementTree as ET

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import netwatch as nw  # noqa: E402
import cases  # noqa: E402
import changecheck  # noqa: E402
import configbak  # noqa: E402
import ipam  # noqa: E402
import netdocs  # noqa: E402
import snmp  # noqa: E402

T0 = 1_795_000_000.0
CISCO = """hostname core
enable secret 5 $1$TOPSECRETHASH
username admin privilege 15 password 0 Pa55w0rdX
snmp-server community s3cr3t RO
vlan 10
 name LAN
!
vlan 30
 name IOT
!
interface Vlan10
 ip address 192.168.1.2 255.255.255.0
!
"""


def host(ip, mac=None, name=None, kind="local"):
    return {"ip": ip, "kind": kind, "me": False, "gw": ip == "192.168.1.1", "first": T0, "last": T0 + 60, "mac": mac,
            "names": {name} if name else set(), "rdns": None, "ports": {}}


def fake_state(n_hosts=3, name="printer.local"):
    s = types.SimpleNamespace(mode="live", gateway="192.168.1.1", me={"192.168.1.23"}, lock=threading.RLock(), arp_table={})
    s.hosts = {"192.168.1.255": host("192.168.1.255", kind="bcast"), "8.8.8.8": host("8.8.8.8", kind="public"),
               "224.0.0.251": host("224.0.0.251", kind="bcast")}
    for i in range(n_hosts):
        ip = f"192.168.1.{10 + i}"
        s.hosts[ip] = host(ip, f"aa:bb:cc:00:00:{i % 256:02x}", name if i == 0 else None)
    # SNMP με community «s3cr3t» που δεν πρέπει να φανεί πουθενά
    sn = snmp.Snmp(None, {"enabled": True, "targets": [{"name": "Router", "host": "192.168.1.1", "community": "s3cr3t"},
                                                       {"name": "Switch", "host": "192.168.1.2", "community": "s3cr3t"}]})
    raws = [{"sys": {"descr": "RouterOS 7.16", "name": "gw", "location": "rack", "uptime": 360000 * 100},
             "ifs": {}, "neigh": [{"proto": "lldp", "local_port": "ether2", "remote_name": "sw-core", "remote_port": "Port 1",
                                   "remote_port_desc": "Port 1", "chassis": ""}]},
            {"sys": {"descr": "Smart Managed Switch", "name": "sw-core", "location": "rack", "uptime": 7200 * 100},
             "ifs": {}, "neigh": [{"proto": "lldp", "local_port": "Port 1", "remote_name": "gw", "remote_port": "ether2",
                                   "remote_port_desc": "ether2", "chassis": ""}]}]
    with sn.lock:
        for t, raw in zip(sn.targets, raws):
            sn.ingest(t, raw, T0)
    s.snmp = sn
    cb = configbak.ConfigBackup(None, {"devices": []})
    assert cb.upload("core", CISCO, name="Core switch", vendor="cisco_ios")["ok"]
    s.configbak = cb
    return s


@pytest.fixture
def demo_state(tmp_path):
    s = nw.NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False)
    s.cases = cases.Cases(s, sim=True)
    s.configbak = configbak.ConfigBackup(s, None, sim=True)
    s.changecheck = changecheck.ChangeCheck(s, sim=True)
    s.snmp = snmp.Snmp(s, None, sim=True)
    s.ipam = ipam.Ipam({"subnets": [{"cidr": "192.168.1.0/24", "name": "LAN", "vlan": 1, "gateway": "192.168.1.1"}]},
                       str(tmp_path / "ipam.json"))
    for ip, mac in (("192.168.1.10", "f0:de:f1:10:10:10"), ("192.168.1.40", "00:1e:0b:40:40:40")):
        s.host(ip, T0)["mac"] = mac
    return s


def all_outputs(doc):
    return [netdocs.to_markdown(doc), netdocs.to_html(doc), netdocs.to_drawio(doc)]


def test_build_minimal_state_lan_only():
    d = netdocs.build(fake_state(), "el")
    ips = [h["ip"] for h in d["hosts"]]
    assert ips == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]  # χωρίς broadcast/multicast/δημόσιες
    roles = {x["name"]: x["role"] for x in d["devices"]}
    assert roles["Router"] == "router" and roles["Core switch"] == "switch"
    assert len(d["links"]) == 1 and d["links"][0]["a_port"] == "ether2"  # η αμφίδρομη LLDP σύνδεση μετράει μία φορά
    assert {v["id"] for v in d["vlans"]} == {10, 30}
    c = d["counts"]
    assert c["devices"] == 3 and c["vlans"] == 2 and c["switches"] == 2 and c["links"] == 1 and c["configs"] == 1
    assert c["cases_open"] == 0 and c["expiring"] == 0


def test_empty_state_does_not_crash():
    s = types.SimpleNamespace(mode="pcap", gateway=None, hosts={})
    d = netdocs.build(s, "en")
    assert d["counts"]["devices"] == 0
    md = netdocs.to_markdown(d)
    assert "No devices seen yet" in md
    ET.fromstring(netdocs.to_drawio(d))


def test_markdown_headers_el_en(demo_state):
    el = netdocs.to_markdown(netdocs.build(demo_state, "el"))
    for h in ("# Τεκμηρίωση δικτύου", "## Subnets & VLAN", "## Δικτυακές συσκευές", "## Συνδέσεις τοπολογίας",
              "## Τελικές συσκευές", "## Υπηρεσίες / διαθεσιμότητα", "## Πρόσφατες αλλαγές", "## Ανοιχτές υποθέσεις"):
        assert h in el
    assert "| 192.168.1.10 |" in el and "IOT" in el
    en = netdocs.to_markdown(netdocs.build(demo_state, "en"))
    for h in ("# Network documentation", "## Subnets & VLANs", "## Network devices", "## Topology links", "## End devices",
              "## Services / health", "## Recent changes", "## Open cases", "## Expiring soon"):
        assert h in en


def test_html_self_contained_and_escaped():
    s = fake_state(name="<script>alert(1)</script>")
    h = netdocs.to_html(netdocs.build(s, "el"))
    assert h.startswith("<!doctype html>") and "</html>" in h and "@media print" in h
    assert "<title>Τεκμηρίωση δικτύου" in h
    assert "<script" not in h and "&lt;script&gt;alert(1)&lt;/script&gt;" in h
    assert not re.search(r"(src|href)=[\"']?(https?:)?//", h) and "@import" not in h
    assert "<title>Network documentation" in netdocs.to_html(netdocs.build(s, "en"), "en")
    assert "<script>" not in netdocs.to_markdown(netdocs.build(s, "el"))


def test_drawio_structure(demo_state):
    x = netdocs.to_drawio(netdocs.build(demo_state, "el"))
    root = ET.fromstring(x.split("\n", 1)[1])
    assert root.tag == "mxfile" and root.find("diagram/mxGraphModel/root") is not None
    cells = root.findall(".//mxCell")
    vals = [c.get("value") or "" for c in cells if c.get("vertex") == "1"]
    assert "Internet" in vals
    assert any(v.startswith("Router MikroTik hEX\n192.168.1.1") for v in vals)
    assert any(v.startswith("Core switch (Cisco 2960)") for v in vals)
    edges = [c for c in cells if c.get("edge") == "1"]
    ids = {c.get("id") for c in cells}
    assert edges and all(e.get("source") in ids and e.get("target") in ids for e in edges)
    assert any("ether2" in (e.get("value") or "") for e in edges)  # ετικέτα με θύρες από LLDP


def test_drawio_caps_devices():
    d = netdocs.build(fake_state(n_hosts=80), "en")
    root = ET.fromstring(netdocs.to_drawio(d).split("\n", 1)[1])
    hosts = [c for c in root.iter("mxCell") if c.get("vertex") == "1" and "192.168.1." in (c.get("value") or "")
             and c.get("parent") != "1"]
    assert len(hosts) == netdocs.DRAWIO_MAX
    assert any((c.get("value") or "").startswith("+20 more") for c in root.iter("mxCell"))


def test_no_secrets_leak():
    d = netdocs.build(fake_state(), "el")
    for out in all_outputs(d) + [repr(d)]:
        for secret in ("s3cr3t", "Pa55w0rdX", "TOPSECRETHASH"):
            assert secret not in out


def test_demo_counts_and_changes(demo_state):
    d = netdocs.build(demo_state, "el")
    c = d["counts"]
    assert c["configs"] == 3 and c["switches"] >= 2 and c["links"] >= 3 and c["vlans"] >= 3 and c["subnets"] >= 2
    assert d["changes"] and len(d["changes"]) <= 10
    assert d["changes"] == sorted(d["changes"], key=lambda x: -x["ts"])
    assert d["change_check"]["verdict"] == "bad"
    assert "hEx-m0n1t0r" not in "".join(all_outputs(d))  # MikroTik SNMP community του demo
    assert netdocs.filename("md", T0).startswith("netwatch-network-") and netdocs.filename("md", T0).endswith(".md")


def test_whereis_and_expiry_optional():
    s = fake_state()

    class WI:
        def table(self):
            return {"rows": [{"mac": "aa:bb:cc:00:00:00", "ip": "192.168.1.10", "name": "", "vendor": "HP", "switch": "sw-core",
                              "port": "Gi0/5", "vlan": 30},
                             {"mac": "11:22:33:44:55:66", "ip": "192.168.1.1", "name": "gw", "vendor": "", "switch": "sw-core",
                              "port": "Gi0/1", "vlan": 1}]}

    class EX:
        def view(self):
            return {"items": [{"name": "cert", "kind": "tls", "days_left": 3, "status": "warn"},
                              {"name": "far", "kind": "tls", "days_left": 300, "status": "ok"}]}
    s.whereis, s.expiry = WI(), EX()
    d = netdocs.build(s, "en")
    h = next(x for x in d["hosts"] if x["ip"] == "192.168.1.10")
    assert (h["switch"], h["port"], h["vlan"], h["vendor"]) == ("Switch", "Gi0/5", 30, "HP")
    assert d["counts"]["expiring"] == 1 and d["expiring"][0]["name"] == "cert"
    x = netdocs.to_drawio(d)
    assert "VLAN 30" in x and "IOT" in x
    s.whereis = types.SimpleNamespace(table=lambda: 1 / 0)  # χαλασμένο module → απλώς αγνοείται
    assert netdocs.build(s, "el")["counts"]["devices"] == 3
