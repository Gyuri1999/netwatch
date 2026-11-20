"""Tests για τις ενημερώσεις (updater.py). Ποτέ πραγματικό δίκτυο: το «GitHub» είναι ένα dict στη μνήμη."""
import hashlib
import io
import json
import os
import plistlib
import shutil
import subprocess
import sys
import time
import zipfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import updater  # noqa: E402

HAS_SIG = bool(shutil.which("ssh-keygen")) and subprocess.run(["ssh-keygen", "-Y", "sign"], capture_output=True).returncode != 127


def test_versions_and_kind(tmp_path):
    assert updater.newer("v1.2.0", "1.1.9") and updater.newer("1.10", "1.9.5") and not updater.newer("v1.0", "1.0.0")
    assert not updater.newer("latest", "1.0") and updater.vtuple("v2.3") == (2, 3, 0)
    app = os.path.join(os.sep, "Users", "x", "Applications", "NetWatch.app")
    assert updater.bundle_of(os.path.join(app, "Contents", "Resources", "netwatch")) == app
    assert updater.bundle_of(os.path.join(os.sep, "Users", "x", "netwatch")) is None
    (tmp_path / ".git").mkdir()
    assert updater.detect_kind(str(tmp_path)) == "git"
    (tmp_path / "VERSION").write_text("1.4.2\n")
    assert updater.read_version(str(tmp_path)) == "1.4.2"
    (tmp_path / "VERSION").write_text("hello")
    assert updater.read_version(str(tmp_path)) == "0.0.0"


def test_parse_sums_and_zip_slip(tmp_path):
    h = "a" * 64
    assert updater.parse_sums(f"{h}  NetWatch.zip\n{'b' * 64} *dist/NetWatch.dmg\njunk\n") == {"NetWatch.zip": h, "NetWatch.dmg": "b" * 64}
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("../../etc/x", "boom")
    with pytest.raises(ValueError):
        updater.safe_extract(str(z), str(tmp_path / "out"))


def test_check_notifies_but_never_installs_unsigned(tmp_path):
    rel = {"tag_name": "v9.0.0", "name": "NetWatch v9", "body": "- new", "html_url": "https://github.com/x",
           "assets": [{"name": "NetWatch.zip", "browser_download_url": "https://github.com/z"}, {"name": "SHA256SUMS", "browser_download_url": "https://github.com/s"}]}
    calls = []

    def fetch(url, **k):
        calls.append(url)
        assert url == updater.API
        return json.dumps(rel).encode()
    u = updater.Updater(here=str(tmp_path), fetch=fetch)
    v = u.check(force=True)
    assert v["available"] and v["latest"]["tag"] == "v9.0.0" and "_dl" not in v["latest"]
    assert u.check()["checked"] and len(calls) == 1          # όχι ξανά μέσα σε 60″
    u.kind = "app"
    assert not u.view()["can_install"] and "υπογεγραμμένη" in u.view()["why_not"]
    assert "error" in u.install()


def test_check_handles_no_release(tmp_path):
    def fetch(url, **k):
        raise OSError("HTTP Error 404: Not Found")
    v = updater.Updater(here=str(tmp_path), fetch=fetch).check(force=True)
    assert not v["available"] and "release" in v["error"]


def _bundle(root, version, bid="com.netwatch.app"):
    app = root / "NetWatch.app"
    res = app / "Contents" / "Resources" / "netwatch"
    res.mkdir(parents=True)
    (res / "VERSION").write_text(version)
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({"CFBundleIdentifier": bid}, f)
    return app, res


@pytest.mark.skipif(not HAS_SIG, reason="χρειάζεται ssh-keygen -Y")
def test_signed_install_end_to_end_and_tampering(tmp_path):
    key = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    pub = " ".join(open(str(key) + ".pub").read().split()[:2])

    inst = tmp_path / "Applications"
    app, res = _bundle(inst, "1.0.0")
    (res / "update_signers").write_text(f'netwatch-release namespaces="netwatch-update" {pub}\n')
    (res / "old.txt").write_text("old")

    build = tmp_path / "build"
    new_app, new_res = _bundle(build, "1.1.0")
    (new_res / "new.txt").write_text("new")
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        for d, _, files in os.walk(build):
            for n in files:
                p = os.path.join(d, n)
                z.write(p, os.path.relpath(p, build))
    zdata = zbuf.getvalue()
    sums = f"{hashlib.sha256(zdata).hexdigest()}  NetWatch.zip\n".encode()
    (tmp_path / "SUMS").write_bytes(sums)
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "netwatch-update", str(tmp_path / "SUMS")], check=True, capture_output=True)
    sig = (tmp_path / "SUMS.sig").read_bytes()

    files = {"https://github.com/dl/NetWatch.zip": zdata, "https://github.com/dl/SHA256SUMS": sums, "https://github.com/dl/SHA256SUMS.sig": sig}
    rel = {"tag_name": "v1.1.0", "assets": [{"name": n, "browser_download_url": "https://github.com/dl/" + n} for n in ("NetWatch.zip", "SHA256SUMS", "SHA256SUMS.sig")]}

    def fetch(url, limit=0, dest=None, progress=None):
        if url == updater.API:
            return json.dumps(rel).encode()
        data = files[url]
        if dest:
            open(dest, "wb").write(data)
            return hashlib.sha256(data).hexdigest()
        return data

    def runner(argv, timeout=60, stdin=None, cwd=None):
        if argv[0] == "codesign":
            return 0, "", ""
        return updater._run(argv, timeout=timeout, stdin=stdin, cwd=cwd)

    def go():
        u = updater.Updater(here=str(res), fetch=fetch, runner=runner)
        assert u.kind == "app" and u.version == "1.0.0"
        assert u.check(force=True)["can_install"]
        assert u.install()["ok"]
        for _ in range(200):
            if u.job["state"] != "running":
                break
            time.sleep(0.05)
        return u

    # 1) πειραγμένο zip → ο έλεγχος SHA-256 το σταματά, τίποτα δεν αλλάζει
    files["https://github.com/dl/NetWatch.zip"] = zdata + b"x"
    u = go()
    assert u.job["state"] == "error" and "SHA-256" in u.job["step"] and (res / "old.txt").exists()
    # 2) υπογραφή από ξένο κλειδί → σταματά
    files["https://github.com/dl/NetWatch.zip"] = zdata
    other = tmp_path / "other"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other)], check=True)
    shutil.copy(tmp_path / "SUMS", tmp_path / "S2")
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(other), "-n", "netwatch-update", str(tmp_path / "S2")], check=True, capture_output=True)
    files["https://github.com/dl/SHA256SUMS.sig"] = (tmp_path / "S2.sig").read_bytes()
    u = go()
    assert u.job["state"] == "error" and "υπογραφή" in u.job["step"] and (res / "old.txt").exists()
    # 3) σωστά → αντικατάσταση, το παλιό μένει ως .previous
    files["https://github.com/dl/SHA256SUMS.sig"] = sig
    u = go()
    assert u.job["state"] == "done", u.job
    assert (res / "new.txt").exists() and not (res / "old.txt").exists()
    assert (inst / "NetWatch.app.previous" / "Contents" / "Resources" / "netwatch" / "old.txt").exists()
    assert u.version == "1.1.0" and not [d for d in os.listdir(inst) if d.startswith(".nw-update-")]


def test_verify_sig_without_signers(tmp_path):
    p = tmp_path / "s"
    p.write_text("# only comments\n")
    ok, why = updater.verify_sig(b"x", b"y", str(p))
    assert not ok and "κλειδί" in why


def test_git_kind_refuses_dirty_tree(tmp_path):
    def runner(argv, timeout=60, stdin=None, cwd=None):
        a = " ".join(argv)
        if "rev-parse --abbrev-ref HEAD" in a:
            return 0, "main\n", ""
        if "@{u}" in a and "rev-parse" in a:
            return 0, "origin/main\n", ""
        if "rev-list" in a:
            return 0, "3\n", ""
        if "log" in a:
            return 0, "abc1234 Add thing\n", ""
        if "status" in a:
            return 0, " M x.py\n", ""
        return 0, "", ""
    (tmp_path / ".git").mkdir()
    u = updater.Updater(here=str(tmp_path), fetch=lambda *a, **k: b"{}", runner=runner)
    v = u.check(force=True)
    assert v["kind"] == "git" and v["available"] and v["git"]["behind"] == 3 and not v["can_install"]
    assert "error" in u.install()


def test_demo_simulates(tmp_path):
    u = updater.Updater(sim=True, fetch=lambda *a, **k: (_ for _ in ()).throw(AssertionError("network in demo")))
    v = u.check(force=True)
    assert v["available"] and v["can_install"]
    assert u.restart()["demo"]


def test_view_reports_sim_and_windows_hint(monkeypatch):
    u = updater.Updater(sim=True)
    u.check(force=True)
    assert u.view()["sim"] is True
    w = updater.Updater(fetch=lambda *a, **k: json.dumps({"tag_name": "v99.0.0", "assets": []}))
    w.kind = "files"
    monkeypatch.setattr(updater.sys, "platform", "win32")
    w.check(force=True)
    v = w.view()
    assert v["sim"] is False and v["available"] and not v["can_install"] and "NetWatch-windows-x64.zip" in v["why_not"]
