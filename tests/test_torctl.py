import binascii
import hashlib
import hmac
import json
import os
import socket
import threading

import pytest

import torctl

FP1, FP2, FP3 = "A" * 40, "B" * 40, "C" * 40


class St:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, kw.get("key"), kw.get("cooldown")))


def test_reply_parser_with_data_block():
    blob = (b"250-version=0.4.8.13\r\n"
            b"250+circuit-status=\r\n"
            b"1 BUILT $" + FP1.encode() + b"~a BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL\r\n"
            b"..dotted line\r\n"
            b".\r\n"
            b"250 OK\r\n")
    rep = torctl.parse_reply(blob)
    assert rep[0] == ("250", "version=0.4.8.13", None)
    assert rep[1][1] == "circuit-status=" and rep[1][2][1] == ".dotted line" and rep[1][2][0].startswith("1 BUILT")
    assert rep[-1] == ("250", "OK", None)
    assert torctl.parse_reply(b"552 Unrecognized key\r\n") == [("552", "Unrecognized key", None)]
    with pytest.raises(torctl.TorCtlError):
        torctl.parse_reply(b"250-half\r\n")
    with pytest.raises(torctl.TorCtlError):
        torctl.parse_reply(b"garbage\r\n")


def test_protocolinfo_parse():
    rep = torctl.parse_reply(b'250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/var/lib/tor/control auth"\r\n'
                             b'250-VERSION Tor="0.4.8.13"\r\n250 OK\r\n')
    info = torctl.parse_protocolinfo(rep)
    assert info == {"methods": {"COOKIE", "SAFECOOKIE"}, "cookiefile": "/var/lib/tor/control auth", "version": "0.4.8.13"}


def test_safecookie_vector():
    cookie, cn, sn = bytes(range(32)), b"\x01" * 32, b"\x02" * 32
    s, c = torctl.safecookie_hashes(cookie, cn, sn)
    msg = cookie + cn + sn
    assert s == hmac.new(b"Tor safe cookie authentication server-to-controller hash", msg, hashlib.sha256).digest()
    assert c == hmac.new(b"Tor safe cookie authentication controller-to-server hash", msg, hashlib.sha256).digest()
    # σταθερό διάνυσμα (υπολογισμένο μία φορά) — πιάνει αλλαγή σειράς/κλειδιών
    assert binascii.hexlify(s).decode() == SERVER_VEC and binascii.hexlify(c).decode() == CLIENT_VEC


SERVER_VEC = "18bf4049ee4f5be22254e66ded2c3778d180b1eb268e8e41fcbdd10d64538030"
CLIENT_VEC = "e396c96ac795e44f88cc8bfdebd8517eadc1a9872cb9c6b01c244cf065abbcdb"


def test_circuit_status_parsing():
    txt = (f"1 BUILT ${FP1}~guardy,${FP2}~middly,${FP3}~exity BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY "
           f"PURPOSE=GENERAL TIME_CREATED=2026-11-18T10:00:00.500000\n"
           f"2 LAUNCHED BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2026-11-18T10:01:00.000000\n"
           f"3 BUILT ${FP1}=old,${FP2} PURPOSE=HS_CLIENT_REND\n")
    c = torctl.parse_circuit_status(txt)
    assert [x["id"] for x in c] == ["1", "2", "3"]
    assert c[0]["path"] == [(FP1, "guardy"), (FP2, "middly"), (FP3, "exity")]
    assert c[0]["flags"] == ["IS_INTERNAL", "NEED_CAPACITY"] and c[0]["purpose"] == "GENERAL"
    assert c[0]["created"] == 1794996000.5
    assert c[1]["path"] == [] and c[1]["status"] == "LAUNCHED"
    assert c[2]["path"] == [(FP1, "old"), (FP2, None)] and c[2]["purpose"] == "HS_CLIENT_REND"


def test_ns_and_guards_parsing():
    ns = "r moria1 lpXfw1/+uGEym58asExGOXAgzjE IpcU7dolas8+Q+oAzwgvZIWx7PA 2026-11-18 09:00:00 128.31.0.34 9101 9131\ns Fast Running"
    assert torctl.parse_ns_r(ns) == {"nick": "moria1", "ip": "128.31.0.34", "orport": 9101}
    g = torctl.parse_entry_guards(f"${FP1}~down1 down\n${FP2}~up1 up\n${FP3}~up2 up")
    assert torctl.primary_guard(g) == (FP2, "up1", "up")


def test_refuses_non_loopback():
    for bad in ("192.168.1.10", "8.8.8.8", "example.com", "10.0.0.1", ""):
        with pytest.raises(ValueError):
            torctl.check_host(bad)
    assert torctl.check_host("127.0.0.1") == "127.0.0.1" and torctl.check_host("::1") == "::1"
    assert torctl.check_host("localhost") == "127.0.0.1"
    with pytest.raises(ValueError):
        torctl.ControlConn(9051, host="1.2.3.4")
    with pytest.raises(ValueError):
        torctl.TorCtl(None, {"host": "192.168.1.1"})


# ── ψεύτικος Tor σε localhost ──
class FakeTor(threading.Thread):
    def __init__(self, cookie_path, cookie, methods="SAFECOOKIE,COOKIE", guard=FP1):
        super().__init__(daemon=True)
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.port = self.srv.getsockname()[1]
        self.cookie, self.cookie_path, self.methods, self.guard = cookie, cookie_path, methods, guard
        self.commands = []
        self.stop = False

    def run(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.session, args=(c,), daemon=True).start()

    def session(self, c):
        f = c.makefile("rb")
        authed, cnonce, snonce = False, None, os.urandom(32)
        relays = {FP1: ("Guardian", "185.220.101.34", "de"), FP2: ("Midway", "93.95.230.165", "se"),
                  FP3: ("Exodus", "192.42.116.16", "nl")}

        def send(s):
            c.sendall(s.encode())
        while True:
            line = f.readline()
            if not line:
                break
            cmd = line.decode().strip()
            self.commands.append(cmd)
            if cmd.startswith("PROTOCOLINFO"):
                send(f'250-PROTOCOLINFO 1\r\n250-AUTH METHODS={self.methods} COOKIEFILE="{self.cookie_path}"\r\n'
                     '250-VERSION Tor="0.4.8.13"\r\n250 OK\r\n')
            elif cmd.startswith("AUTHCHALLENGE SAFECOOKIE "):
                cnonce = binascii.unhexlify(cmd.split()[-1])
                sh, _ = torctl.safecookie_hashes(self.cookie, cnonce, snonce)
                send(f"250 AUTHCHALLENGE SERVERHASH={sh.hex().upper()} SERVERNONCE={snonce.hex().upper()}\r\n")
            elif cmd.startswith("AUTHENTICATE"):
                arg = cmd[13:]
                ok = (cnonce is not None and arg == torctl.safecookie_hashes(self.cookie, cnonce, snonce)[1].hex()) or \
                     (cnonce is None and arg == self.cookie.hex()) or (self.methods == "NULL" and not arg)
                if ok:
                    authed = True
                    send("250 OK\r\n")
                else:
                    send("515 Authentication failed\r\n")
                    break
            elif not authed:
                send("514 Authentication required.\r\n")
                break
            elif cmd == "GETINFO version":
                send("250-version=0.4.8.13 (git-abc)\r\n250 OK\r\n")
            elif cmd == "GETINFO circuit-status":
                send(f"250+circuit-status=\r\n7 BUILT ${FP1}~Guardian,${FP2}~Midway,${FP3}~Exodus "
                     "BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2026-11-18T10:00:00.000000\r\n"
                     f"8 EXTENDED ${FP1}~Guardian PURPOSE=GENERAL\r\n.\r\n250 OK\r\n")
            elif cmd.startswith("GETINFO ns/id/"):
                fp = cmd.split("/")[-1]
                n, ip, _ = relays[fp]
                send(f"250+ns/id/{fp}=\r\nr {n} AAAA BBBB 2026-11-18 09:00:00 {ip} 9001 0\r\ns Fast Guard Running\r\n.\r\n250 OK\r\n")
            elif cmd.startswith("GETINFO ip-to-country/"):
                ip = cmd.split("/")[-1]
                cc = next((r[2] for r in relays.values() if r[1] == ip), "??")
                send(f"250-ip-to-country/{ip}={cc}\r\n250 OK\r\n")
            elif cmd in ("GETINFO traffic/read", "GETINFO traffic/written"):
                k = cmd.split()[-1]
                send(f"250-{k}={1000 if k.endswith('read') else 200}\r\n250 OK\r\n")
            elif cmd == "GETINFO entry-guards":
                send(f"250+entry-guards=\r\n${self.guard}~{relays[self.guard][0]} up\r\n.\r\n250 OK\r\n")
            elif cmd == "SIGNAL NEWNYM":
                send("250 OK\r\n")
            else:
                send("510 Unrecognized command\r\n")
        c.close()

    def close(self):
        self.stop = True
        self.srv.close()


@pytest.fixture
def fake(tmp_path):
    cookie = os.urandom(32)
    p = tmp_path / "control_auth_cookie"
    p.write_bytes(cookie)
    t = FakeTor(str(p), cookie)
    t.start()
    yield t
    t.close()


def test_live_poll_against_fake_tor(fake):
    st = St()
    tc = torctl.TorCtl(st, {"control_port": fake.port})
    tc.poll(now=1794996060.0)
    s = tc.status()
    assert s["connected"] and s["error"] is None and s["auth"] == "SAFECOOKIE"
    assert s["version"] == "0.4.8.13" and s["port"] == fake.port
    assert s["traffic"] == {"read": 1000, "written": 200}
    c = s["circuits"][0]
    assert c["id"] == "7" and c["age_s"] == 60 and [h["role"] for h in c["hops"]] == ["guard", "middle", "exit"]
    assert c["hops"][2] == {"fp": "CCCCCCCC", "nick": "Exodus", "ip": "192.42.116.16", "cc": "NL",
                            "lat": 52.2, "lon": 5.5, "role": "exit"}
    assert s["circuits"][1]["status"] == "EXTENDED"
    assert s["guard"] == {"nick": "Guardian", "ip": "185.220.101.34", "cc": "DE"}
    json.dumps(s)
    assert not any(x.startswith(("SETCONF", "SAVECONF", "SIGNAL")) for x in fake.commands)
    # αλλαγή guard → ειδοποίηση
    fake.guard = FP2
    tc.poll(now=1794996070.0)
    assert [a[0] for a in st.alerts] == ["Άλλαξε ο Tor guard"] and st.alerts[0][1] == "low" and st.alerts[0][5] == 86400
    # NEWNYM με όριο ρυθμού
    assert tc.newnym(now=1000.0)["ok"] is True
    r = tc.newnym(now=1005.0)
    assert r["ok"] is False and r["wait"] == 5.0
    assert fake.commands.count("SIGNAL NEWNYM") == 1


def test_cookie_auth_and_bad_cookie(tmp_path, fake):
    fake.methods = "COOKIE"
    with torctl.ControlConn(fake.port, cookie_file=fake.cookie_path) as c:
        c.open()
        assert c.authenticate() == "COOKIE"
        assert c.getinfo("version").startswith("0.4.8.13")
    bad = tmp_path / "bad"
    bad.write_bytes(b"x" * 32)
    fake.methods = "SAFECOOKIE"
    with torctl.ControlConn(fake.port, cookie_file=str(bad)) as c:
        c.open()
        with pytest.raises(torctl.TorCtlError):
            c.authenticate()


def test_password_only_and_unreachable(fake):
    fake.methods = "HASHEDPASSWORD"
    tc = torctl.TorCtl(None, {"control_port": fake.port})
    tc.poll()
    s = tc.status()
    assert not s["connected"] and "HashedControlPassword" in s["hint"]
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    free = s.getsockname()[1]
    s.close()
    tc = torctl.TorCtl(None, {"control_port": free})
    tc.poll()
    st = tc.status()
    assert not st["connected"] and "ControlPort" in st["hint"] and st["error"]


def test_sim_status_shape():
    tc = torctl.TorCtl(None, {}, sim=True)
    tc.poll()
    s = tc.status()
    json.dumps(s)
    for k in ("enabled", "demo", "connected", "port", "version", "error", "hint", "circuits", "traffic", "guard"):
        assert k in s
    assert s["demo"] and s["connected"] and 3 <= len(s["circuits"]) <= 4
    for c in s["circuits"]:
        assert c["status"] == "BUILT" and [h["role"] for h in c["hops"]] == ["guard", "middle", "exit"]
        for h in c["hops"]:
            assert h["cc"] in torctl.CENTROIDS and h["lat"] is not None and len(h["fp"]) == 8
    before = [c["id"] for c in s["circuits"]]
    assert tc.newnym()["ok"]
    assert [c["id"] for c in tc.status()["circuits"]] != before
    assert len(torctl.CENTROIDS) >= 80
