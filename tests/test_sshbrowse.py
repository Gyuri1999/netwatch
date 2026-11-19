"""Tests για το SSH Explorer (sshbrowse.py). Το «απομακρυσμένο» shell είναι ένα τοπικό sh — ποτέ πραγματικό ssh."""
import os
import subprocess
import sys
import threading
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import sshbrowse  # noqa: E402


def local_runner(calls):
    def run(argv, timeout=15, stdin=None):
        calls.append(argv)
        assert argv[0] in ("ssh", "sudo")
        assert "BatchMode=yes" in argv and "StrictHostKeyChecking=yes" in argv and "ForwardAgent=no" in argv
        remote = argv[-1]
        p = subprocess.run(["sh", "-c", remote], capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr.decode()
    return run


def make(tmp_path, runner=None):
    st = types.SimpleNamespace(lock=threading.RLock(), hosts={})
    calls = []
    sb = sshbrowse.SshBrowse(st, path=str(tmp_path / "ssh_hosts.json"), known=str(tmp_path / "kh"),
                             runner=runner or local_runner(calls))
    assert sb.add_host({"name": "Pi", "host": "192.168.1.17", "user": "pi"})["ok"]
    return sb, calls


def test_hosts_validation_and_no_passwords(tmp_path):
    sb, _ = make(tmp_path)
    assert "error" in sb.add_host({"name": "x", "host": "8.8.8.8", "user": "pi"})
    assert "error" in sb.add_host({"name": "x", "host": "192.168.1.5", "user": "pi", "password": "hunter2"})
    assert "error" in sb.add_host({"name": "x", "host": "-oProxyCommand=x", "user": "pi"})
    assert "error" in sb.add_host({"name": "x", "host": "192.168.1.5", "user": "pi;rm"})
    saved = open(tmp_path / "ssh_hosts.json").read()
    assert "hunter2" not in saved and "192.168.1.17" in saved
    sb2 = sshbrowse.SshBrowse(types.SimpleNamespace(lock=threading.RLock(), hosts={}), path=str(tmp_path / "ssh_hosts.json"))
    assert [h["host"] for h in sb2.hosts.values()] == ["192.168.1.17"]
    assert sb.delete_host("pi")["ok"] and not sb.hosts


def test_ls_cat_and_quoting(tmp_path):
    d = tmp_path / "remote dir"
    d.mkdir()
    (d / "a.txt").write_text("hello\nworld\n")
    (d / "sub").mkdir()
    (d / "evil $(touch pwned) ;.txt").write_text("x")
    (d / "id_ed25519").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
    (d / "bin.dat").write_bytes(b"\x00\x01\x02" * 100)
    sb, calls = make(tmp_path)
    r = sb.ls("pi", str(d))
    names = [e["name"] for e in r["entries"]]
    assert r["path"] == str(d) and names[0] == "sub" and "a.txt" in names and r["entries"][0]["type"] == "d"
    c = sb.cat("pi", str(d / "a.txt"))
    assert c["text"] == "hello\nworld\n" and c["size"] == 12 and not c["truncated"]
    c = sb.cat("pi", str(d / "evil $(touch pwned) ;.txt"))
    assert c["text"] == "x" and not os.path.exists("pwned")
    assert sb.cat("pi", str(d / "id_ed25519")).get("private")
    assert sb.cat("pi", str(d / "bin.dat"))["binary"]
    f = sb.fetch("pi", str(d / "a.txt"))
    got = sb.get_file(f["url"].split("=")[1])
    assert got["data"] == b"hello\nworld\n" and got["name"] == "a.txt"
    assert sb.get_file(f["url"].split("=")[1]) is None          # μία φορά
    assert "error" in sb.fetch("pi", str(d / "id_ed25519"))
    assert all(a[-1].count("\n") < 60 for a in calls)


def test_errors_are_explained(tmp_path):
    def denied(argv, timeout=15, stdin=None):
        return 255, b"", "pi@192.168.1.17: Permission denied (publickey,password).\n"
    sb, _ = make(tmp_path, runner=denied)
    r = sb.ls("pi", "~")
    assert "κωδικ" in r["error"] and "ssh-copy-id" in r["hint"]
    assert "κλειδί του host" in sshbrowse.explain("Host key verification failed.")[0]
    assert "ΑΛΛΑΞΕ" in sshbrowse.explain("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!")[0]
    assert "raspi-config" in sshbrowse.explain("connect to host 1.2.3.4 port 22: Connection refused")[1]
    assert "error" in sb.ls("nope", "~")
    assert "error" in sb.ls("pi", "a\x00b")


def test_trust_needs_matching_scan(tmp_path):
    sb, _ = make(tmp_path)
    assert "error" in sb.trust("pi", "SHA256:x")
    sb.scans["pi"] = (sb.clock(), ["192.168.1.17 ssh-ed25519 AAAAC3Nz"], ["SHA256:good"])
    assert "error" in sb.trust("pi", "SHA256:bad")
    assert sb.trust("pi", "SHA256:good")["ok"]
    assert "ssh-ed25519" in open(tmp_path / "kh").read()


def test_info_parse_and_checks():
    r = sshbrowse.parse_info(sshbrowse.DEMO_INFO)
    assert r["model"].startswith("Raspberry Pi 4") and r["temp_c"] == 58.4 and r["cpus"] == 4
    assert r["disks"][1]["pct"] == 79 and 1883 in r["ports"] and r["updates"] == 14
    lv = [c["el"] for c in r["checks"]]
    assert any("κωδικούς" in x for x in lv) and any("ενημερώσεις" in x for x in lv)


def test_demo_never_runs_ssh(tmp_path):
    def boom(*a, **k):
        raise AssertionError("ssh in demo")
    st = types.SimpleNamespace(lock=threading.RLock(), hosts={})
    sb = sshbrowse.SshBrowse(st, sim=True, runner=boom)
    assert sb.ls("pi", "~")["path"] == "/home/pi"
    assert "κλειδί του host" in sb.ls("pve", "~")["error"]
    fp = sb.hostkey("pve")["fingerprints"][0]["fp"]
    assert sb.trust("pve", fp)["ok"] and "κωδικ" in sb.ls("pve", "~")["error"]
    assert sb.info("pi")["checks"]
    assert sb.cat("pi", "~/.ssh/id_ed25519").get("private")
