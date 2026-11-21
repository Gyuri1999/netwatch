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


@pytest.mark.skipif(not HAS_SIG, reason="χρειάζεται ssh-keygen -Y")
def test_windows_app_install_stages_signed_update(tmp_path, monkeypatch):
    """Windows app: υπογεγραμμένο SHA256SUMS-windows → κατέβασμα/έλεγχος/αποσυμπίεση στο …/NetWatch/update + ready.json·
    η αλλαγή φακέλων γίνεται από το launcher στην επανεκκίνηση."""
    # «Windows» μόνο για τον εντοπισμό εγκατάστασης — όχι sys.platform (θα χαλούσε το subprocess σε Linux/Mac)
    monkeypatch.setattr(updater, "detect_kind", lambda here, ppid=None: "winapp" if updater.win_bundle(here) else "files")
    key = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    pub = " ".join(open(str(key) + ".pub").read().split()[:2])
    sup = tmp_path / "LocalAppData" / "NetWatch"
    here = sup / "app"
    here.mkdir(parents=True)
    (here / "VERSION").write_text("1.2.6")
    (here / "update_signers").write_text(f'netwatch-release namespaces="netwatch-update" {pub}\n')
    bundle = tmp_path / "Downloads" / "NetWatch"
    bundle.mkdir(parents=True)
    (bundle / "NetWatch.exe").write_text("old")
    (sup / "bundle.json").write_text(json.dumps({"bundle": str(bundle)}))

    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("NetWatch/NetWatch.exe", "new")
        z.writestr("NetWatch/python/python.exe", "py")
        z.writestr("NetWatch/app/VERSION", "1.3.0")
    zdata = zbuf.getvalue()
    sums = f"{hashlib.sha256(zdata).hexdigest()}  NetWatch-windows-x64.zip\n".encode()
    (tmp_path / "SUMS").write_bytes(sums)
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "netwatch-update", str(tmp_path / "SUMS")], check=True, capture_output=True)
    names = ("NetWatch-windows-x64.zip", "SHA256SUMS-windows", "SHA256SUMS-windows.sig", "NetWatch.zip", "SHA256SUMS", "SHA256SUMS.sig")
    files = {"https://github.com/dl/NetWatch-windows-x64.zip": zdata, "https://github.com/dl/SHA256SUMS-windows": sums,
             "https://github.com/dl/SHA256SUMS-windows.sig": (tmp_path / "SUMS.sig").read_bytes()}
    rel = {"tag_name": "v1.3.0", "assets": [{"name": n, "browser_download_url": "https://github.com/dl/" + n} for n in names]}

    def fetch(url, limit=0, dest=None, progress=None):
        if url == updater.API:
            return json.dumps(rel).encode()
        data = files[url]
        if dest:
            open(dest, "wb").write(data)
            return hashlib.sha256(data).hexdigest()
        return data

    def go():
        u = updater.Updater(here=str(here), fetch=fetch)
        assert u.kind == "winapp" and u.bundle == str(bundle)
        v = u.check(force=True)
        assert v["can_install"], v["why_not"]
        assert u.install()["ok"]
        for _ in range(200):
            if u.job["state"] != "running":
                break
            time.sleep(0.05)
        return u

    files["https://github.com/dl/NetWatch-windows-x64.zip"] = zdata + b"x"  # πειραγμένο
    u = go()
    assert u.job["state"] == "error" and "SHA-256" in u.job["step"] and not (sup / "update" / "ready.json").exists()
    assert u.restart()["error"]
    files["https://github.com/dl/NetWatch-windows-x64.zip"] = zdata
    u = go()
    assert u.job["state"] == "done", u.job
    ready = json.loads((sup / "update" / "ready.json").read_text())
    assert ready["version"] == "1.3.0" and open(os.path.join(ready["dir"], "NetWatch.exe")).read() == "new"
    assert (bundle / "NetWatch.exe").read_text() == "old"  # ο φάκελος της εφαρμογής δεν αγγίζεται ακόμα
    r = u.restart()
    assert r["ok"] and r["closing"] and json.loads((sup / "update-request.json").read_text())["action"] == "apply"


def test_windows_app_without_signed_package_is_manual(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "detect_kind", lambda here, ppid=None: "winapp" if updater.win_bundle(here) else "files")
    sup = tmp_path / "NetWatch"
    (sup / "app").mkdir(parents=True)
    b = tmp_path / "B"
    b.mkdir()
    (b / "NetWatch.exe").write_text("x")
    (sup / "bundle.json").write_text(json.dumps({"bundle": str(b)}))
    rel = {"tag_name": "v9.0.0", "assets": [{"name": "NetWatch-windows-x64.zip", "browser_download_url": "https://github.com/x"}]}
    u = updater.Updater(here=str(sup / "app"), fetch=lambda *a, **k: json.dumps(rel).encode())
    v = u.check(force=True)
    assert v["kind"] == "winapp" and v["available"] and not v["can_install"] and "GitHub" in v["why_not"]


def _auto_updater(tmp_path, hour=12):
    rel = {"tag_name": "v9.0.0", "assets": []}
    u = updater.Updater(here=str(tmp_path), fetch=lambda *a, **k: json.dumps(rel).encode(), hour=lambda: hour_box[0])
    hour_box[0] = hour
    u.kind, u.bundle = "winapp", str(tmp_path)
    u._can_install = lambda: (u.available(), "")
    calls = []
    u._install_win = lambda: calls.append("install") or "έτοιμη"
    u.restart = lambda: calls.append("restart") or {"ok": True}
    return u, calls


hour_box = [12]


def test_auto_install_downloads_then_applies_only_at_night(tmp_path, monkeypatch):
    monkeypatch.setattr(updater.Updater, "auto_ok", lambda self: True)
    u, calls = _auto_updater(tmp_path)
    assert u.view()["auto_install"] is True
    assert u.tick() == "install" and calls == ["install"]
    assert u.job["state"] == "done" and u.job["auto"] and u.job["tag"] == "v9.0.0"
    assert u.tick() is None and calls == ["install"]  # μεσημέρι: δεν κλείνει την εφαρμογή, ούτε ξανακατεβάζει
    hour_box[0] = 3
    assert u.tick() == "restart" and calls == ["install", "restart"]


def test_auto_install_off_and_failures_are_not_retried(tmp_path, monkeypatch):
    monkeypatch.setattr(updater.Updater, "auto_ok", lambda self: True)
    u, calls = _auto_updater(tmp_path)
    assert u.set_auto(False)["auto_install"] is False
    assert u.tick() is None and calls == [] and u.view()["available"]  # μόνο ειδοποίηση
    u2, calls2 = _auto_updater(tmp_path)
    assert u2.auto_install is False  # η επιλογή μένει (data/update.json)
    u2.set_auto(True)

    def boom():
        raise RuntimeError("υπογραφή ✖")
    u2._install_win = boom
    assert u2.tick() is None and u2.job["state"] == "error" and u2.auto_failed == "v9.0.0"
    u2._install_win = lambda: calls2.append("install") or "ok"
    assert u2.tick() is None and calls2 == []  # ίδια έκδοση: όχι ξανά αυτόματα
    assert u2.install()["ok"]  # με κλικ όμως ναι
    for _ in range(100):
        if u2.job["state"] != "running":
            break
        time.sleep(0.02)
    assert calls2 == ["install"]


def test_auto_install_skips_version_launcher_could_not_apply(tmp_path, monkeypatch):
    monkeypatch.setattr(updater.Updater, "auto_ok", lambda self: True)
    here = tmp_path / "NetWatch" / "app"
    here.mkdir(parents=True)
    (tmp_path / "NetWatch" / "update-failed.json").write_text(json.dumps({"version": "9.0.0"}))
    u, calls = _auto_updater(here)
    assert u.tick() is None and calls == []


def test_auto_never_for_git_docker_files_or_demo(tmp_path):
    rel = {"tag_name": "v9.0.0", "assets": []}
    for kind in ("git", "docker", "files"):
        u = updater.Updater(here=str(tmp_path), fetch=lambda *a, **k: json.dumps(rel).encode())
        u.kind = kind
        assert not u.auto_ok()
    assert not updater.Updater(here=str(tmp_path), sim=True).auto_ok()


def test_mac_bundle_from_parent_process(tmp_path, monkeypatch):
    monkeypatch.setattr(updater.sys, "platform", "darwin")
    app = tmp_path / "Applications" / "NetWatch.app"
    (app / "Contents" / "Resources" / "netwatch").mkdir(parents=True)
    here = tmp_path / "Library" / "Application Support" / "NetWatch" / "app"
    exe = str(app / "Contents" / "MacOS" / "NetWatch")
    run = lambda argv, timeout=0: (0, exe + "\n", "")
    assert updater.mac_bundle(str(here), 123, run) == str(app)
    assert updater.mac_bundle(str(here), None, run) is None
    assert updater.mac_bundle(str(tmp_path / "other"), 123, run) is None
    assert updater.mac_bundle(str(here), 123, lambda argv, timeout=0: (0, "/usr/bin/python3\n", "")) is None
