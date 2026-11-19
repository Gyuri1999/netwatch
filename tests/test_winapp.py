"""winapp/launcher.py — η εφαρμογή Windows: αναβάθμιση κώδικα χωρίς να χαθούν δεδομένα, εικονίδιο, ορίσματα backend."""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("launcher", os.path.join(HERE, "winapp", "launcher.py"))
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def _w(p, s):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(s)


def _r(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_sync_copies_updates_and_keeps_user_files(tmp_path):
    src, dst = str(tmp_path / "bundle"), str(tmp_path / "local")
    _w(os.path.join(src, ".build_id"), "a")
    _w(os.path.join(src, "netwatch.py"), "v1")
    _w(os.path.join(src, "old.py"), "x")
    _w(os.path.join(src, "rules", "default.yaml"), "r1")
    assert launcher.sync_app(src, dst) is True
    assert _r(os.path.join(dst, "netwatch.py")) == "v1"
    assert launcher.sync_app(src, dst) is False  # ίδιο build → τίποτα

    # ο χρήστης έχει ιστορικό, config και δικούς του κανόνες
    _w(os.path.join(dst, "data", "netwatch.db"), "history")
    _w(os.path.join(dst, "config.yaml"), "mine")
    _w(os.path.join(dst, "rules", "local.yaml"), "my rules")

    # νέο build: αλλάζει το netwatch.py, φεύγει το old.py
    _w(os.path.join(src, ".build_id"), "b")
    _w(os.path.join(src, "netwatch.py"), "v2")
    os.remove(os.path.join(src, "old.py"))
    _w(os.path.join(src, "config.yaml"), "should not overwrite")
    assert launcher.sync_app(src, dst) is True
    assert _r(os.path.join(dst, "netwatch.py")) == "v2"
    assert not os.path.exists(os.path.join(dst, "old.py"))
    assert _r(os.path.join(dst, "data", "netwatch.db")) == "history"
    assert _r(os.path.join(dst, "config.yaml")) == "mine"
    assert _r(os.path.join(dst, "rules", "local.yaml")) == "my rules"
    assert _r(os.path.join(dst, "rules", "default.yaml")) == "r1"


def test_backend_args():
    a = launcher.backend_args("demo", parent=42)
    assert a[:2] == ["-c", launcher.BOOT] and a[2].endswith("netwatch.py") and "--no-open" in a and "--demo" in a
    assert a[a.index("--parent-pid") + 1] == "42" and a[a.index("--port-file") + 1] == launcher.PORTFILE
    p = launcher.backend_args("pcap", "C:\\x y\\a.pcap")
    assert p[-3:] == ["--pcap", "C:\\x y\\a.pcap", "--loop"]
    assert "--demo" not in launcher.backend_args("live")


def test_bootstrap_runs_script_with_its_folder_on_path(tmp_path):
    import subprocess
    import sys
    _w(str(tmp_path / "helper.py"), "X = 41\n")
    _w(str(tmp_path / "main.py"), "import sys, helper\nprint(helper.X + 1, sys.argv[1:], __name__)\n")
    # -I: όπως η embeddable με ._pth, ο φάκελος του script ΔΕΝ μπαίνει μόνος του στο path
    out = subprocess.run([sys.executable, "-I", "-c", launcher.BOOT, str(tmp_path / "main.py"), "--demo"],
                         capture_output=True, text=True, cwd=str(tmp_path.parent)).stdout
    assert out.strip() == "42 ['--demo'] __main__"


def test_level_of():
    assert launcher.level_of({}) == "idle"
    assert launcher.level_of({"high": 1, "med": 3}) == "bad"
    assert launcher.level_of({"high": 0, "med": 2}) == "warn"
    assert launcher.level_of({"high": 0, "med": 0}) == "ok"
    assert launcher.level_of({"high": 0, "med": 0, "wifi": {"level": "warn"}}) == "warn"
    assert launcher.level_of({"high": 0, "med": 1, "wifi": {"level": "bad"}}) == "bad"


def test_shield_icon():
    pytest.importorskip("PIL")
    for lvl, n in (("idle", 0), ("ok", 0), ("warn", 7), ("bad", 123)):
        im = launcher.shield(lvl, n)
        assert im.size == (64, 64) and im.mode == "RGBA"
        assert im.getpixel((32, 30))[3] == 255  # η ασπίδα είναι γεμάτη στο κέντρο
        assert im.getpixel((1, 62))[3] == 0  # διάφανη γωνία
