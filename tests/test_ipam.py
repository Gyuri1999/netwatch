import csv
import io
import json
import os

import pytest

import ipam

NOW = 1_700_000_000.0
DAY = 86400
CFG = {"subnets": [{"cidr": "192.168.1.0/24", "name": "LAN", "vlan": 1, "gateway": "192.168.1.1",
                    "dhcp": "192.168.1.100-192.168.1.199"}],
       "reserved": [{"ip": "192.168.1.16", "name": "Proxmox", "mac": "bc:24:11:aa:bb:cc"},
                    {"ip": "192.168.1.150", "name": "Εκτυπωτής", "mac": "00:11:22:33:44:55"},
                    {"ip": "192.168.1.40", "name": "NAS"}]}


def H(ip, mac, name="", last=NOW - 60, **kw):
    return {"ip": ip, "mac": mac, "names": [name] if name else [], "vendor": kw.get("vendor", ""), "dlabel": "",
            "last": last, "first": last - DAY}


HOSTS = [H("192.168.1.1", "aa:aa:aa:aa:aa:01", "router"),
         H("192.168.1.16", "de:ad:be:ef:00:01", "intruder"),       # δεσμευμένη για άλλη MAC
         H("192.168.1.20", "a4:cf:12:8e:31:07", "esp32-kipos"),
         H("192.168.1.30", "11:11:11:11:11:30", "ha", last=NOW - 10 * DAY),  # ξεχασμένη
         H("192.168.1.120", "22:22:22:22:22:20", "phone"),
         H("192.168.1.130", "33:33:33:33:33:30", "static-cam"),   # μέσα στο pool χωρίς μίσθωση
         H("10.9.9.9", "44:44:44:44:44:44", "lost")]


def test_parse_range_and_subnet_maths():
    import ipaddress
    net = ipaddress.ip_network("192.168.1.0/24")
    assert ipam.parse_range("192.168.1.100-192.168.1.199", net) == (3232235876, 3232235975)
    assert ipam.parse_range(["192.168.1.10", "192.168.1.5"], net) is None
    assert ipam.parse_range("192.168.2.1-192.168.2.9", net) is None
    rep = ipam.analyze({"subnets": [{"cidr": "10.0.0.0/30"}, {"cidr": "10.1.0.0/25", "dhcp": "10.1.0.10-10.1.0.19"}]}, [], now=NOW)
    s30, s25 = rep["subnets"]
    assert s30["total"] == 2 and s30["free"] == 2 and [c["state"] for c in s30["map"]] == ["network", "free", "free", "broadcast"]
    assert s25["total"] == 126 and len(s25["map"]) == 128 and s25["pool_size"] == 10
    assert s25["next_free"] == ["10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4", "10.1.0.5"]
    assert ipam.analyze({"subnets": [{"cidr": "10.0.0.0/16"}]}, [], now=NOW)["subnets"][0]["map"] is None


def test_map_states_and_counts():
    leases = [{"ip": "192.168.1.120", "mac": "22:22:22:22:22:20", "name": "phone", "expires": NOW + 3600, "active": True},
              {"ip": "192.168.1.121", "mac": "55:55:55:55:55:55", "name": "tablet", "expires": NOW + 3600, "active": True}]
    rep = ipam.analyze(CFG, HOSTS, leases=leases, now=NOW)
    s = rep["subnets"][0]
    st = {c["i"]: c["state"] for c in s["map"]}
    assert len(s["map"]) == 256
    assert st[0] == "network" and st[255] == "broadcast" and st[1] == "gateway"
    assert st[16] == "conflict"  # δεσμευμένη για bc:24:..., τη χρησιμοποιεί άλλη
    assert st[20] == "used" and st[30] == "stale" and st[40] == "reserved"
    assert st[120] == "used" and st[121] == "used" and st[130] == "used"
    assert st[150] == "reserved" and st[100] == "dhcp-pool" and st[2] == "free"
    assert s["total"] == 254
    # used: gw, .16, .20, .30(stale), .120, .121, .130
    assert s["used"] == 7 and s["in_dhcp"] == 3 and s["static"] == 4 and s["stale"] == 1
    assert s["free"] == 254 - 7 - 2  # .40 και .150 δεσμευμένες
    assert s["pct"] == round(700 / 254, 1)
    assert s["next_free"][0] == "192.168.1.2" and all(not (100 <= int(x.split(".")[-1]) <= 199) for x in s["next_free"])
    kinds = {(f["kind"], f["ip"]) for f in rep["findings"]}
    assert ("reserved_mismatch", "192.168.1.16") in kinds
    assert ("static_in_pool", "192.168.1.150") in kinds   # δεσμευμένη μέσα στο pool
    assert ("static_in_pool", "192.168.1.130") in kinds   # στατική μέσα στο pool χωρίς μίσθωση
    assert ("static_in_pool", "192.168.1.120") not in kinds
    assert ("outside", "10.9.9.9") in kinds and rep["outside"] == ["10.9.9.9"]
    assert rep["findings"][0]["sev"] == "med"


def test_conflicts_and_multi_ip_and_alerts():
    obs = [("192.168.1.20", "a4:cf:12:8e:31:07", NOW - 100), ("192.168.1.20", "66:66:66:66:66:66", NOW - 50),
           ("192.168.1.21", "66:66:66:66:66:66", NOW - 40),
           ("192.168.1.22", "77:77:77:77:77:77", NOW - 3 * DAY), ("192.168.1.22", "88:88:88:88:88:88", NOW - 60),  # παλιά: όχι
           ("bad", "zz", "x")]
    rep = ipam.analyze(CFG, HOSTS, observations=obs, now=NOW)
    conf = [f for f in rep["findings"] if f["kind"] == "conflict"]
    assert [c["ip"] for c in conf] == ["192.168.1.20"] and conf[0]["macs"] == ["66:66:66:66:66:66", "a4:cf:12:8e:31:07"]
    assert {c["state"] for c in rep["subnets"][0]["map"] if c["ip"] == "192.168.1.20"} == {"conflict"}
    multi = [f for f in rep["findings"] if f["kind"] == "multi_ip"]
    assert multi and multi[0]["mac"] == "66:66:66:66:66:66" and multi[0]["ips"] == ["192.168.1.20", "192.168.1.21"]

    class St:
        def __init__(self):
            self.calls, self.cd = [], {}

        def alert(self, typ, sev, actor, target, detail, t, key=None, cooldown=None, mark=True):
            if key in self.cd and t - self.cd[key] < cooldown:
                return
            self.cd[key] = t
            self.calls.append((typ, sev, actor, target, mark))

    st = St()
    assert ipam.conflicts_to_alerts(st, rep["findings"], now=NOW) == 1
    ipam.conflicts_to_alerts(st, rep["findings"], now=NOW + 60)
    assert st.calls == [("Σύγκρουση IP", "med", "192.168.1.20", "66:66:66:66:66:66, a4:cf:12:8e:31:07", False)]


def test_derived_subnets_without_config():
    rep = ipam.analyze({}, [("192.168.5.10", "aa-bb-cc-dd-ee-ff", "x", "", NOW), ("192.168.5.11", "AABBCCDDEE00", "y", "", NOW),
                            ("8.8.8.8", "", "", "", NOW)], now=NOW, local_net="10.0.0.0/24")
    assert [s["cidr"] for s in rep["subnets"]] == ["10.0.0.0/24", "192.168.5.0/24"]
    assert rep["subnets"][1]["derived"] and rep["subnets"][1]["used"] == 2
    cell = rep["subnets"][1]["map"][11]
    assert cell["mac"] == "aa:bb:cc:dd:ee:00" and cell["name"] == "y"


DNSMASQ = """1700003600 a4:cf:12:8e:31:07 192.168.1.120 esp32-kipos 01:a4:cf:12:8e:31:07
1699990000 3c:22:fb:91:aa:10 192.168.1.121 * *
0 dc:a6:32:4b:1e:9f 192.168.1.122 raspberrypi *
duid 00:01:00:01:2c:aa:bb:cc
1700003600 1234 fd00::5 host6 00:01
"""

ISC = """# The format of this file is documented in the dhcpd.leases(5) manual page.
lease 192.168.1.140 {
  starts 4 2023/11/14 21:00:00;
  ends 4 2023/11/14 23:00:00;
  binding state active;
  next binding state free;
  hardware ethernet 3c:22:fb:91:aa:10;
  client-hostname "iphone-maria";
}
lease 192.168.1.141 {
  starts 4 2023/11/14 20:00:00;
  ends 4 2023/11/14 21:00:00;
  binding state free;
  hardware ethernet 00:11:22:33:44:55;
}
lease 192.168.1.140 {
  starts 4 2023/11/14 22:00:00;
  ends never;
  binding state active;
  hardware ethernet 3c:22:fb:91:aa:11;
  uid "\\001<\\"\\373";
}
"""


def test_parse_leases_dnsmasq_and_isc(tmp_path):
    ls = {l["ip"]: l for l in ipam.parse_leases(DNSMASQ, now=NOW)}
    assert set(ls) == {"192.168.1.120", "192.168.1.121", "192.168.1.122"}
    assert ls["192.168.1.120"]["active"] and ls["192.168.1.120"]["name"] == "esp32-kipos"
    assert not ls["192.168.1.121"]["active"] and ls["192.168.1.121"]["name"] == ""
    assert ls["192.168.1.122"]["active"] and ls["192.168.1.122"]["expires"] is None
    assert all(l["source"] == "dnsmasq" for l in ls.values())
    li = {l["ip"]: l for l in ipam.parse_leases(ISC, now=NOW)}
    assert set(li) == {"192.168.1.140", "192.168.1.141"}
    assert li["192.168.1.140"]["mac"] == "3c:22:fb:91:aa:11" and li["192.168.1.140"]["active"]  # η τελευταία κερδίζει
    assert li["192.168.1.140"]["expires"] is None and li["192.168.1.140"]["source"] == "isc"
    assert not li["192.168.1.141"]["active"]
    li2 = {l["ip"]: l for l in ipam.parse_leases(ISC.split("lease 192.168.1.140 {\n  starts 4 2023/11/14 22")[0], now=NOW)}
    assert li2["192.168.1.140"]["name"] == "iphone-maria" and li2["192.168.1.140"]["expires"] == 1700002800
    p = tmp_path / "dnsmasq.leases"
    p.write_text(DNSMASQ)
    assert len(ipam.load_leases(str(p), now=NOW)) == 3
    assert ipam.load_leases(str(tmp_path / "nope")) == []


def test_notes_save_load_validation(tmp_path):
    path = str(tmp_path / "sub" / "ipam.json")
    n = ipam.Notes(path)
    assert n.all() == {}
    v = n.set("A4-CF-12-8E-31-07", {"name": "Κήπος", "owner": "Μαρία", "location": "μπαλκόνι", "role": "sensor",
                                    "note": "ESP32 υγρασίας", "tags": "iot, κήπος, iot", "junk": "x"})
    assert v["tags"] == ["iot", "κήπος"] and "junk" not in v
    n.set("192.168.1.16", {"role": "hypervisor"})
    assert not [f for f in os.listdir(tmp_path / "sub") if f.startswith(".ipam-")]  # χωρίς προσωρινά αρχεία
    data = json.loads(open(path, encoding="utf-8").read())
    assert data["version"] == 1 and set(data["devices"]) == {"a4:cf:12:8e:31:07", "192.168.1.16"}
    n2 = ipam.Notes(path)
    assert n2.get("a4:cf:12:8e:31:07")["owner"] == "Μαρία" and n2.get("192.168.1.16")["role"] == "hypervisor"
    with pytest.raises(ValueError):
        n2.set("a4:cf:12:8e:31:07", {"note": "x" * 501})
    with pytest.raises(ValueError):
        n2.set("a4:cf:12:8e:31:07", {"tags": [f"t{i}" for i in range(11)]})
    with pytest.raises(ValueError):
        n2.set("not-a-key", {"name": "x"})
    assert n2.get("a4:cf:12:8e:31:07")["owner"] == "Μαρία"  # η αποτυχία δεν άλλαξε τίποτα
    assert n2.delete("192.168.1.16") and not n2.delete("192.168.1.16")
    n2.set("a4:cf:12:8e:31:07", {"name": ""})  # όλα κενά = διαγραφή
    assert ipam.Notes(path).all() == {}
    open(path, "w").write("{χαλασμένο")
    assert ipam.Notes(path).all() == {}


def test_inventory_and_csv_json_export(tmp_path):
    notes = {"a4:cf:12:8e:31:07": {"name": "Κήπος", "owner": "=cmd|' /C calc'!A0", "tags": ["iot", "κήπος"]}}
    leases = ipam.parse_leases(DNSMASQ, now=NOW)
    rows = ipam.inventory(CFG, HOSTS, leases, notes, now=NOW)
    by = {r["ip"]: r for r in rows}
    assert [r["ip"] for r in rows][:3] == ["10.9.9.9", "192.168.1.1", "192.168.1.16"]
    assert by["192.168.1.20"]["name"] == "Κήπος" and by["192.168.1.20"]["tags"] == ["iot", "κήπος"]
    assert by["192.168.1.30"]["status"] == "stale" and by["192.168.1.20"]["status"] == "online"
    assert by["192.168.1.122"]["source"] == "lease" and by["192.168.1.122"]["in_pool"]
    assert by["192.168.1.40"]["source"] == "reserved" and by["192.168.1.40"]["reserved"]
    assert "192.168.1.121" not in by  # ληγμένη μίσθωση
    text = ipam.to_csv(rows)
    parsed = list(csv.DictReader(io.StringIO(text)))
    assert list(parsed[0].keys()) == ipam.CSV_COLUMNS and len(parsed) == len(rows)
    garden = next(r for r in parsed if r["ip"] == "192.168.1.20")
    assert garden["owner"].startswith("'=") and garden["tags"] == "iot;κήπος" and garden["vlan"] == "1"
    assert garden["in_pool"] == "no" and garden["subnet"] == "192.168.1.0/24"
    j = json.loads(ipam.to_json(rows))
    assert j["version"] == 1 and len(j["devices"]) == len(rows)
    # το «όλα μαζί»
    lf = tmp_path / "leases"
    lf.write_text(DNSMASQ)
    ip = ipam.Ipam({**CFG, "leases_file": str(lf)}, notes_path=str(tmp_path / "ipam.json"))
    ip.notes.set("192.168.1.20", {"owner": "Γιώργος"})
    rep = ip.report(HOSTS, now=NOW)
    assert rep["leases"] == 2 and any(r["owner"] == "Γιώργος" for r in rep["inventory"])
    assert ip.export(HOSTS, "csv", now=NOW).startswith("ip,mac,name")
