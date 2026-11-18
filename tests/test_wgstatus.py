import json

import wgstatus

PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
PSK = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
P1 = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
P2 = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="
NOW = 1_800_000_000


def dump(hs1, hs2, rx1=1000, tx1=500):
    return (f"wg0\t{PRIV}\tHIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\t51820\toff\n"
            f"wg0\t{P1}\t{PSK}\t85.74.211.9:51820\t10.8.0.2/32\t{hs1}\t{rx1}\t{tx1}\t25\n"
            f"wg0\t{P2}\t(none)\t(none)\t10.8.0.3/32,fd00::3/128\t{hs2}\t0\t0\toff\n")


TS = {
    "BackendState": "Running",
    "Self": {"PublicKey": "nodekey:self", "HostName": "mac", "DNSName": "mac.tail.ts.net.", "OS": "macOS",
             "TailscaleIPs": ["100.64.0.1", "fd7a::1"], "Online": True, "CurAddr": "", "Relay": "fra"},
    "Peer": {
        "nodekey:a": {"PublicKey": "nodekey:a", "HostName": "nas", "DNSName": "nas.tail.ts.net.", "OS": "linux",
                      "TailscaleIPs": ["100.64.0.2"], "Online": True, "CurAddr": "192.168.1.20:41641", "Relay": "fra",
                      "LastSeen": "0001-01-01T00:00:00Z", "LastHandshake": "2027-01-15T08:00:00.123456789Z",
                      "RxBytes": 10, "TxBytes": 20, "ExitNode": False, "ExitNodeOption": True},
        "nodekey:b": {"PublicKey": "nodekey:b", "HostName": "phone", "DNSName": "phone.tail.ts.net.", "OS": "android",
                      "TailscaleIPs": ["100.64.0.3"], "Online": False, "CurAddr": "", "Relay": "ams",
                      "LastSeen": "2027-01-15T07:00:00+02:00", "RxBytes": 0, "TxBytes": 0},
    }}


class St:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, kw.get("key"), kw.get("cooldown")))


def runner_for(box):
    def run(argv):
        if argv[1:] == ["show", "all", "dump"]:
            return box.get("wg", (0, "", ""))
        return box.get("ts", (1, "", "not running"))
    return run


def test_dump_parsing_drops_secrets():
    ifs = wgstatus.parse_wg_dump(dump(NOW - 10, 0))
    assert len(ifs) == 1 and ifs[0]["name"] == "wg0" and ifs[0]["listen_port"] == 51820 and ifs[0]["fwmark"] is None
    p1, p2 = ifs[0]["peers"]
    assert p1["endpoint"] == "85.74.211.9:51820" and p1["keepalive"] == 25 and p1["rx"] == 1000 and p1["handshake"] == NOW - 10
    assert p2["endpoint"] is None and p2["allowed_ips"] == ["10.8.0.3/32", "fd00::3/128"] and p2["keepalive"] is None
    blob = json.dumps(ifs)
    assert PRIV not in blob and PSK not in blob


def test_status_never_contains_keys(monkeypatch):
    monkeypatch.setattr(wgstatus, "find_exe", lambda name, extra=(): "/usr/bin/" + name)
    box = {"wg": (0, dump(NOW - 10, 0), "")}
    w = wgstatus.WgStatus(None, {"names": {P1: "Κινητό"}}, runner=runner_for(box))
    w.poll(now=NOW)
    box["wg"] = (0, dump(NOW - 5, 0, rx1=31000, tx1=3500), "")
    w.poll(now=NOW + 30)
    s = w.status()
    blob = json.dumps(s, ensure_ascii=False)
    for secret in (PRIV, PSK, P1, P2):
        assert secret not in blob
    peers = s["wireguard"]["interfaces"][0]["peers"]
    assert peers[0]["name"] == "Κινητό" and peers[0]["key"] == P1[:8] + "…" and peers[0]["state"] == "active"
    assert peers[0]["rx_rate"] == 1000.0 and peers[0]["tx_rate"] == 100.0 and peers[0]["hist"] == [[1000.0, 100.0]]
    assert peers[1]["state"] == "never" and peers[1]["handshake_ago"] is None
    assert s["wireguard"]["available"] and s["tailscale"]["available"] is False and s["tailscale"]["error"]


def test_peer_states():
    assert wgstatus.peer_state(0, NOW) == "never"
    assert wgstatus.peer_state(NOW - 60, NOW) == "active"
    assert wgstatus.peer_state(NOW - 200, NOW) == "idle"
    assert wgstatus.peer_state(NOW - 301, NOW, stale_min=5) == "stale"


def test_permission_hint(monkeypatch):
    monkeypatch.setattr(wgstatus, "find_exe", lambda name, extra=(): "/usr/bin/" + name if name == "wg" else None)
    box = {"wg": (1, "", "Unable to access interface: Operation not permitted")}
    w = wgstatus.WgStatus(None, {}, runner=runner_for(box))
    w.poll(now=NOW)
    s = w.status()
    assert s["hint"] == wgstatus.HINT_PERM and s["error"] and not s["wireguard"]["available"]
    assert s["tailscale"]["available"] is False


def test_tailscale_parsing():
    p = wgstatus.parse_tailscale(json.dumps(TS))
    assert p["backend"] == "Running" and p["self"]["ip"] == "100.64.0.1" and p["self"]["online"]
    nas, phone = p["peers"]
    assert nas["name"] == "nas" and nas["direct"] and nas["cur_addr"] == "192.168.1.20:41641" and nas["exit_node_option"]
    assert nas["last_seen"] is None and nas["last_handshake"] == wgstatus.parse_ts_time("2027-01-15T08:00:00Z")
    assert phone["online"] is False and phone["direct"] is False and phone["relay"] == "ams"
    assert phone["last_seen"] == wgstatus.parse_ts_time("2027-01-15T05:00:00Z")


def test_transitions_alert(monkeypatch):
    monkeypatch.setattr(wgstatus, "find_exe", lambda name, extra=(): "/usr/bin/" + name)
    st = St()
    ts = json.loads(json.dumps(TS))
    box = {"wg": (0, dump(NOW - 10, NOW - 9999), ""), "ts": (0, json.dumps(ts), "")}
    w = wgstatus.WgStatus(st, {"names": {P1: "Κινητό"}, "stale_min": 5}, runner=runner_for(box))
    w.poll(now=NOW)
    assert st.alerts == []  # όχι στον πρώτο έλεγχο (ούτε για τον ήδη stale P2)
    box["wg"] = (0, dump(NOW - 10, NOW - 9999), "")
    w.poll(now=NOW + 200)  # P1 idle → καμία ειδοποίηση ακόμη
    assert st.alerts == []
    ts["Peer"]["nodekey:a"]["Online"] = False
    box["ts"] = (0, json.dumps(ts), "")
    w.poll(now=NOW + 400)  # P1 stale → χάθηκε· nas offline
    typ = [a[0] for a in st.alerts]
    assert typ == ["WireGuard peer χάθηκε", "Tailscale συσκευή εκτός"]
    assert st.alerts[0][1] == "med" and st.alerts[0][2] == "85.74.211.9" and st.alerts[0][3] == "Κινητό"
    assert st.alerts[0][5] == 1800 and st.alerts[0][4] == ("WireGuard peer χάθηκε", P1)
    st.alerts.clear()
    ts["Peer"]["nodekey:a"]["Online"] = True
    box["ts"] = (0, json.dumps(ts), "")
    box["wg"] = (0, dump(NOW + 590, NOW + 595), "")  # και οι δύο ενεργοί ξανά
    w.poll(now=NOW + 600)
    typ = sorted(a[0] for a in st.alerts)
    assert typ == ["Tailscale συσκευή επανήλθε", "WireGuard peer επανήλθε", "WireGuard peer επανήλθε"]
    assert all(a[1] == "low" for a in st.alerts)


def test_tailscale_stopped(monkeypatch):
    monkeypatch.setattr(wgstatus, "find_exe", lambda name, extra=(): "/usr/bin/" + name if name == "tailscale" else None)
    ts = dict(TS, BackendState="Stopped")
    w = wgstatus.WgStatus(None, {}, runner=runner_for({"ts": (1, json.dumps(ts), "")}))
    w.poll(now=NOW)
    s = w.status()
    assert s["hint"] == wgstatus.HINT_TS and "Stopped" in s["tailscale"]["error"] and not s["wireguard"]["available"]


def test_sim_shape(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("καμία εκτέλεση εντολών στο demo")
    monkeypatch.setattr(wgstatus.subprocess, "run", boom)
    st = St()
    w = wgstatus.WgStatus(st, {}, sim=True)
    w.poll(now=NOW)
    w.poll(now=NOW + 30)
    s = w.status()
    json.dumps(s)
    for k in ("enabled", "demo", "error", "hint", "wireguard", "tailscale"):
        assert k in s
    assert s["demo"] and s["error"] is None
    peers = s["wireguard"]["interfaces"][0]["peers"]
    assert [p["name"] for p in peers] == ["Κινητό", "Laptop", "VPS Hetzner"]
    assert peers[2]["state"] == "stale" and peers[0]["state"] == "active"
    assert peers[0]["rx_rate"] > 0 and len(peers[0]["hist"]) == 1
    assert "(hidden)" not in json.dumps(s)
    tp = s["tailscale"]["peers"]
    assert len(tp) == 4 and sum(not p["online"] for p in tp) == 1
    assert any(p["online"] and not p["direct"] and p["relay"] for p in tp)
    for p in tp:
        assert set(p) >= {"name", "ip", "os", "online", "direct", "relay", "last_seen_ago", "rx", "tx", "exit_node"}
    # το Laptop «χάνεται» για λίγο κάθε μισάωρο στο demo
    base = NOW - NOW % 1800
    w.poll(now=base + 1400)
    w.poll(now=base + 1700)
    assert "WireGuard peer χάθηκε" in [a[0] for a in st.alerts]
