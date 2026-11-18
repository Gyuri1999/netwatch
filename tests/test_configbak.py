"""Tests για τα αντίγραφα ρυθμίσεων συσκευών & τις διαφορές (configbak.py)."""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import configbak as cb  # noqa: E402

T0 = 1_700_000_000.0

BASE = """Building configuration...

Current configuration : 1200 bytes
!
! Last configuration change at 10:00:00 UTC Mon Nov 9 2026 by admin
version 15.2
service password-encryption
hostname sw1
!
enable secret 9 $9$TOPSECRETHASH
username admin privilege 15 secret 9 $9$ADMINHASH
!
vlan 10
 name LAN
!
interface FastEthernet0/1
 switchport access vlan 10
!
interface FastEthernet0/2
 switchport access vlan 10
!
ip access-list standard MGMT
 permit 192.168.1.0 0.0.0.255
!
interface Vlan10
 ip address 192.168.1.2 255.255.255.0
 ip access-group MGMT in
!
snmp-server community S3cr3tComm RO
line vty 0 4
 transport input ssh
ntp clock-period 36028797
end
"""


class FakeState:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append(dict(type=typ, sev=sev, actor=actor, target=target, detail=detail, t=t, **kw))


def mk(tmp_path=None, devices=None, clock=None):
    clock = clock or [T0]
    st = FakeState()
    cfg = {"devices": devices if devices is not None else
           [{"id": "sw1", "name": "Switch", "host": "192.168.1.2", "vendor": "cisco_ios", "user": "backup"}]}
    c = cb.ConfigBackup(st, cfg, path=str(tmp_path) if tmp_path else None, clock=lambda: clock[0])
    return c, st, clock


def put(c, clock, text, did="sw1", dt=3600):
    clock[0] += dt
    return c._record(did, text)


# ───────── μυστικά ─────────
SECRETS = [
    ("enable secret 5 $1$abcd$EnableHash", "$1$abcd$EnableHash"),
    ("username bob privilege 15 password 0 Hunter2pw", "Hunter2pw"),
    ("username alice secret 9 $9$AliceHash", "$9$AliceHash"),
    ("snmp-server community Comm1unity RW", "Comm1unity"),
    ("crypto isakmp key IsakmpK3y address 10.0.0.1", "IsakmpK3y"),
    (" pre-shared-key Psk-Value-1", "Psk-Value-1"),
    (" key-string 7 0822455D0A16", "0822455D0A16"),
    (" wpa-psk ascii 0 WifiPass99", "WifiPass99"),
    ("    wpa-psk HomeWifiPsk", "HomeWifiPsk"),
    ('/ppp secret add name=vpn password="Mik rotik!" service=l2tp', "Mik rotik!"),
    ("set [ find ] wpa2-pre-shared-key=MtWifiKey authentication-types=wpa2-psk", "MtWifiKey"),
    ("\toption key 'OwrtWifiKey'", "OwrtWifiKey"),
    ("\toption password 'OwrtPass'", "OwrtPass"),
    ('      password: "NetplanPw"', "NetplanPw"),
    ("<password>XmlPw</password>", "XmlPw"),
]


@pytest.mark.parametrize("line,secret", SECRETS)
def test_mask_each_secret_kind(line, secret):
    out = cb.mask(line)
    assert secret not in out and cb.MASK in out


def test_mask_keeps_harmless_lines():
    for ln in ("no service password-encryption", "crypto key generate rsa modulus 2048", "hostname sw1",
               "service password-encryption", "/ip service set telnet disabled=yes"):
        assert cb.mask(ln) == ln


def test_mikrotik_snmp_community_section_masked():
    out = cb.mask("/snmp community\nset [ find default=yes ] name=MyComm addresses=192.168.1.0/24\n/system identity\nset name=hEX")
    assert "MyComm" not in out and "name=hEX" in out


def test_diff_and_show_never_leak_secrets():
    c, st, clock = mk()
    put(c, clock, BASE)
    changed = BASE.replace("$9$ADMINHASH", "$9$NEWADMINHASH").replace("S3cr3tComm RO", "S3cr3tComm RO MGMT")
    v = put(c, clock, changed)
    assert v is not None
    d = c.diff("sw1")
    blob = json.dumps(d) + json.dumps(c.show("sw1")) + json.dumps(c.versions("sw1")) + json.dumps(c.view())
    for s in ("TOPSECRETHASH", "ADMINHASH", "NEWADMINHASH", "S3cr3tComm"):
        assert s not in blob
    # η αλλαγή μόνο του κωδικού δεν φαίνεται στο diff (υπολογίζεται στο κρυμμένο κείμενο)
    assert all("username" not in ln["text"] for ln in d["lines"] if ln["op"] in "+-")
    # το αρχείο στη μνήμη/δίσκο κρατά το πρωτότυπο
    assert "NEWADMINHASH" in c._text("sw1", v["ts"])


# ───────── πτητικές γραμμές ─────────
def test_volatile_lines_do_not_create_version():
    c, st, clock = mk()
    assert put(c, clock, BASE) is not None
    noisy = (BASE.replace("10:00:00 UTC Mon Nov 9", "23:59:59 UTC Tue Nov 10").replace("1200 bytes", "1234 bytes")
             .replace("ntp clock-period 36028797", "ntp clock-period 36028123").replace("\n", "\r\n") + "\n\n")
    assert put(c, clock, noisy) is None
    assert c.view()["devices"][0]["versions"] == 1
    assert c.view()["devices"][0]["last_backup"] == clock[0]
    mt = "# 2026-11-10 10:00:00 by RouterOS 7.16\n/system identity\nset name=r1\n"
    assert cb.normalize(mt) == cb.normalize(mt.replace("2026-11-10 10:00:00", "2026-11-17 03:00:01"))
    assert st.alerts == []


# ───────── ανάλυση κινδύνου ─────────
def risky(old, new):
    return [t for _, t in cb.analyze(cb.normalize(old), cb.normalize(new))]


def has(items, *words):
    return any(all(w in t for w in words) for t in items)


def test_risk_patterns_cisco():
    r = risky(BASE, BASE.replace("!\nvlan 10", "username evil privilege 15 secret 9 $9$x\n!\nvlan 10"))
    assert has(r, "Νέος τοπικός χρήστης", "evil", "privilege 15")
    assert has(risky(BASE, BASE.replace("transport input ssh", "transport input telnet")), "telnet")
    assert has(risky(BASE, BASE.replace("transport input ssh", "transport input all")), "telnet")
    r = risky(BASE, BASE.replace("line vty", "snmp-server community public RW\nline vty"))
    assert has(r, "SNMP", "public", "RW")
    assert has(risky(BASE, BASE.replace("service password-encryption", "no service password-encryption")), "κρυπτογράφηση κωδικών")
    r = risky(BASE, BASE.replace("ip access-list standard MGMT\n permit 192.168.1.0 0.0.0.255\n!\n", "").replace(" ip access-group MGMT in\n", ""))
    assert has(r, "Αφαιρέθηκε η ACL «MGMT»") and has(r, "Αφαιρέθηκε η εφαρμογή")
    assert has(risky(BASE, BASE.replace("line vty", "ip http server\nline vty")), "ip http server")
    assert has(risky(BASE, BASE.replace("line vty", "ip nat inside source static tcp 192.168.1.20 80 interface Gi0/0 8080\nline vty")), "NAT")
    r = risky(BASE, BASE.replace("interface FastEthernet0/2\n switchport access vlan 10\n", "interface FastEthernet0/2\n switchport access vlan 10\n shutdown\n"))
    assert has(r, "FastEthernet0/2", "shutdown")
    r = risky(BASE, BASE.replace("!\nvlan 10\n name LAN\n", "!\nvlan 10\n name LAN\n!\nvlan 30\n name IOT\n"))
    assert has(r, "Προστέθηκε VLAN 30")
    assert has(risky(BASE.replace("!\nvlan 10\n name LAN\n", "!\nvlan 10\n name LAN\n!\nvlan 30\n"), BASE), "Αφαιρέθηκε VLAN 30")
    assert risky(BASE, BASE.replace("hostname sw1", "hostname sw2")) == []


def test_risk_patterns_mikrotik_openwrt():
    mt = "/ip firewall nat\nadd action=masquerade chain=srcnat\n/ip service\nset telnet disabled=yes\n"
    r = risky(mt, mt.replace("chain=srcnat\n", "chain=srcnat\nadd action=dst-nat chain=dstnat dst-port=8080 protocol=tcp to-addresses=192.168.30.20 to-ports=80\n"))
    assert has(r, "dst-nat", "8080", "192.168.30.20")
    assert has(risky(mt, mt.replace("set telnet disabled=yes", "set telnet disabled=no")), "telnet")
    assert has(risky(mt, mt + "/ip service enable telnet\n"), "telnet")
    assert has(risky(mt, mt + "/snmp community\nadd name=public\n"), "SNMP", "public")
    assert has(risky(mt, mt + "/user\nadd group=full name=hacker\n"), "Νέος τοπικός χρήστης", "hacker")
    ow = "config wifi-iface 'a'\n\toption ssid 'Home'\n"
    assert has(risky(ow, ow + "\nconfig redirect\n\toption target 'DNAT'\n"), "port forward")


def test_alert_sev_and_first_backup_silent():
    c, st, clock = mk()
    put(c, clock, BASE)
    assert st.alerts == []  # πρώτο αντίγραφο: χωρίς ειδοποίηση
    put(c, clock, BASE.replace("hostname sw1", "hostname sw-core"))
    assert st.alerts[-1]["sev"] == "low" and st.alerts[-1]["type"] == "Αλλαγή ρυθμίσεων"
    assert st.alerts[-1]["actor"] == "192.168.1.2" and st.alerts[-1]["target"] == "Switch"
    put(c, clock, BASE.replace("hostname sw1", "hostname sw-core").replace("transport input ssh", "transport input telnet"))
    assert st.alerts[-1]["sev"] == "med" and "telnet" in st.alerts[-1]["detail"]
    assert len(st.alerts) == 2


# ───────── σχήματα API ─────────
def test_versions_diff_shapes():
    c, st, clock = mk()
    put(c, clock, BASE)
    put(c, clock, BASE.replace("transport input ssh", "transport input telnet"))
    vs = c.versions("sw1")
    assert vs["id"] == "sw1" and vs["name"] == "Switch" and len(vs["versions"]) == 2
    newest, oldest = vs["versions"]
    assert newest["ts"] > oldest["ts"]
    assert set(newest) >= {"ts", "size", "sha", "added", "removed", "risky", "note"} and len(newest["sha"]) == 12
    assert newest["added"] == 1 and newest["removed"] == 1 and newest["risky"]
    d = c.diff("sw1")
    assert d["a"] == oldest["ts"] and d["b"] == newest["ts"] and d["added"] == 1 and d["removed"] == 1
    assert d["lines"][0]["op"] == "@" and d["lines"][0]["text"].startswith("@@")
    assert {"op": "+", "text": " transport input telnet"} in d["lines"]
    assert {"op": "-", "text": " transport input ssh"} in d["lines"]
    assert all(ln["op"] in ("@", "+", "-", " ") for ln in d["lines"])
    assert c.diff("sw1", a=newest["ts"], b=oldest["ts"])["added"] == 1
    assert c.show("sw1")["ts"] == newest["ts"] and c.show("sw1", oldest["ts"])["ts"] == oldest["ts"]
    assert "error" in c.show("sw1", 123) and "error" in c.diff("nope")
    dv = c.view()["devices"][0]
    assert dv["status"] == "ok" and dv["versions"] == 2 and dv["last_change"] == newest["ts"] and dv["risky"]
    assert set(c.view()) >= {"devices", "every_hours", "ssh_available", "demo"}


def test_upload_creates_version_and_manual_device():
    c, st, clock = mk()
    assert "error" in c.upload("sw1", "x" * (cb.MAX_TEXT + 1))
    assert "error" in c.upload("Bad ID!", "hostname x")
    assert "error" in c.upload("newdev", "hostname x")  # άγνωστο id χωρίς name
    r = c.upload("sw1", BASE)
    assert r["ok"] and r["changed"]
    clock[0] += 60
    r = c.upload("sw1", BASE.replace("line vty", "username tmp privilege 15 secret 0 x\nline vty"), note="από τον τεχνικό")
    assert r["changed"] and any("tmp" in t for t in r["risky"])
    assert st.alerts[-1]["sev"] == "med" and st.alerts[-1]["mitre"]["id"] == "T1098"
    assert c.versions("sw1")["versions"][0]["note"] == "από τον τεχνικό"
    r = c.upload("fw1", "set system host-name fw1", name="Firewall", vendor="generic")
    assert r["changed"]
    d = next(x for x in c.view()["devices"] if x["id"] == "fw1")
    assert d["manual"] and d["versions"] == 1 and "error" in c.backup("fw1")


# ───────── ασφάλεια: host, id, ssh ─────────
def test_private_host_enforcement_and_invalid_devices():
    for h in ("8.8.8.8", "1.1.1.1", "0.0.0.0"):
        with pytest.raises(ValueError):
            cb.check_host(h)
    for h in ("192.168.1.1", "10.0.0.5", "127.0.0.1", "fe80::1"):
        assert cb.check_host(h)
    c, st, _ = mk(devices=[{"id": "pub", "name": "x", "host": "8.8.8.8", "vendor": "linux", "user": "u"},
                           {"id": "BAD ID", "host": "192.168.1.5", "user": "u"},
                           {"id": "pw", "host": "192.168.1.5", "user": "u", "vendor": "linux", "password": "hunter2"},
                           {"id": "gen", "host": "192.168.1.6", "user": "u", "vendor": "generic"},
                           {"id": "opt", "host": "-oProxyCommand=x", "user": "u", "vendor": "linux"},
                           {"id": "usr", "host": "192.168.1.7", "user": "-oProxy", "vendor": "linux"}])
    devs = {d["id"]: d for d in c.view()["devices"]}
    assert "BAD ID" not in devs
    for k in ("pub", "pw", "gen", "opt", "usr"):
        assert devs[k]["status"] == "error" and devs[k]["error"]
    assert "hunter2" not in json.dumps(c.view())
    assert "error" in c.backup("pub") and "error" in c.backup("nope")


def test_ssh_command_construction(monkeypatch):
    dev = {"id": "r1", "host": "192.168.1.1", "user": "backup", "vendor": "mikrotik", "port": 2222,
           "identity_file": "~/.ssh/id_backup"}
    argv = cb.ssh_argv(dev)
    assert argv[:7] == ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new"]
    assert "-i" in argv and argv[argv.index("-i") + 1].endswith("/.ssh/id_backup") and "~" not in argv[argv.index("-i") + 1]
    assert argv[-2:] == ["backup@192.168.1.1", "/export hide-sensitive"]
    assert argv[argv.index("-p") + 1] == "2222"
    assert cb.ssh_argv({**dev, "vendor": "cisco_ios", "identity_file": None})[-1] == "show running-config"
    assert cb.ssh_argv({**dev, "vendor": "openwrt"})[-1] == "uci export"
    with pytest.raises(ValueError):
        cb.ssh_argv({**dev, "vendor": "generic"})
    # εκτέλεση: monkeypatch subprocess.run — κανένα πραγματικό ssh
    monkeypatch.delenv("SUDO_USER", raising=False)
    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, stdout=BASE.encode(), stderr=b"")
    monkeypatch.setattr(cb.subprocess, "run", fake_run)
    c, st, clock = mk()
    c._run_one("sw1")
    assert calls and calls[0][0][0] == "ssh" and calls[0][0][-1] == "show running-config"
    assert calls[0][1]["timeout"] == cb.TIMEOUT and "shell" not in calls[0][1]
    assert c.view()["devices"][0]["versions"] == 1 and c.view()["devices"][0]["status"] == "ok"

    def fail_run(argv, **kw):
        return subprocess.CompletedProcess(argv, 255, stdout=b"", stderr=b"backup@192.168.1.2: Permission denied (publickey).")
    monkeypatch.setattr(cb.subprocess, "run", fail_run)
    c._run_one("sw1")
    d = c.view()["devices"][0]
    assert d["status"] == "error" and "Permission denied" in d["error"] and "ssh-copy-id" in d["error"]


# ───────── αποθήκευση ─────────
def test_persistence_roundtrip(tmp_path):
    c, st, clock = mk(tmp_path)
    put(c, clock, BASE)
    v2 = put(c, clock, BASE.replace("hostname sw1", "hostname sw2"))
    c.upload("man1", "hostname man1", name="Manual box", vendor="cisco_ios")
    files = sorted(os.listdir(tmp_path / "sw1"))
    assert "index.json" in files and f"{v2['ts']}.txt" in files and not any(f.endswith(".tmp") for f in files)
    assert "$9$ADMINHASH" in (tmp_path / "sw1" / f"{v2['ts']}.txt").read_text()  # ο δίσκος κρατά το πρωτότυπο
    c2, _, _ = mk(tmp_path, clock=clock)
    assert c2.versions("sw1")["versions"] == c.versions("sw1")["versions"]
    assert c2.diff("sw1")["lines"] == c.diff("sw1")["lines"]
    assert "man1" in {d["id"] for d in c2.view()["devices"]}
    assert put(c2, clock, BASE.replace("hostname sw1", "hostname sw2")) is None  # ίδιο με το τελευταίο


def test_keep_limit(tmp_path):
    c, st, clock = mk(tmp_path)
    c.keep = 3
    for i in range(5):
        put(c, clock, BASE.replace("hostname sw1", f"hostname sw{i}"))
    assert len(c.versions("sw1")["versions"]) == 3
    assert len([f for f in os.listdir(tmp_path / "sw1") if f.endswith(".txt")]) == 3


# ───────── demo ─────────
def test_demo_devices_and_flagged_change(monkeypatch):
    monkeypatch.setattr(cb, "DEMO_BACKUP_SECONDS", 0)
    ran = []
    monkeypatch.setattr(cb.subprocess, "run", lambda *a, **k: ran.append(a))
    st = FakeState()
    c = cb.ConfigBackup(st, sim=True)
    v = c.view()
    assert v["demo"] and len(v["devices"]) >= 3
    assert all(d["versions"] >= 3 for d in v["devices"])
    core = next(d for d in v["devices"] if d["id"] == "core-sw")
    assert has(core["risky"], "backup", "privilege 15") and has(core["risky"], "telnet")
    mt = next(d for d in v["devices"] if d["id"] == "mikrotik")
    assert has(mt["risky"], "dst-nat", "8080")
    for d in v["devices"]:
        assert "<κρυφό>" in c.show(d["id"])["text"]
        assert c.diff(d["id"])["lines"]
    assert "Kalokairi" not in json.dumps([c.show("ap-living"), c.diff("ap-living")])
    n = core["versions"]
    assert c.backup("all") == {"ok": True}
    import time as _t
    for _ in range(100):
        if all(d["status"] != "running" for d in c.view()["devices"]):
            break
        _t.sleep(0.02)
    assert c.view()["devices"][0]["versions"] == n and not ran and st.alerts == []


def test_real_netstate_alert_accepts_config_change():
    import netwatch as nw
    s = nw.NetState("test", "test0", ["192.168.1.50"], "192.168.1.1", geo=False, rdns=False)
    c = cb.ConfigBackup(s, {"devices": [{"id": "sw1", "name": "Switch", "host": "192.168.1.2", "vendor": "cisco_ios", "user": "b"}]})
    c._record("sw1", BASE)
    c._record("sw1", BASE.replace("transport input ssh", "transport input telnet"), now=s.alerts[0]["t"] + 5 if s.alerts else None)
    a = next(a for a in s.alerts if a["type"] == "Αλλαγή ρυθμίσεων")
    assert a["sev"] == "med" and a["mitre"]["id"] == "T1562"
