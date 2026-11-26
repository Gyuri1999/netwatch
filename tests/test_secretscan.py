"""🔑 Ξεχασμένα κλειδιά: βρίσκει, κρύβει, δεν ξεφεύγει από τον φάκελο, ψάχνει και στο git ιστορικό."""
import json
import os
import shutil
import subprocess

import pytest

import netkit
import secretscan

# Ψεύτικα αλλά «σωστού σχήματος» μυστικά (φτιάχνονται εδώ, για να μη μοιάζει το ίδιο το test με διαρροή)
GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"   # 36 χαρακτήρες μετά το ghp_
AWS = "AKIA" + "QWERTYUIOPASDFGH"
TG = "123456789:AA" + "x" * 10 + "Y" * 10 + "z" * 13
WIFI = "Kal0Kair1!2024"


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setattr(secretscan, "_home", lambda: os.path.realpath(str(h)))
    return h


def _project(home, files):
    p = home / "proj"
    for name, text in files.items():
        f = p / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return p


def test_finds_esp32_style_secrets_and_masks_them(home):
    p = _project(home, {
        "src/main.cpp": f'const char* ssid = "Home";\nconst char* password = "{WIFI}";\n'
                        f'#define MQTT_PASSWORD "{WIFI}x"\nString broker = "mqtt://pi:{WIFI}y@192.168.1.17";\n',
        "tools/bot.py": f'TOKEN = "{TG}"\nGITHUB = "{GH}"\nAWS = "{AWS}"\n'})
    r = secretscan.scan(str(p), history=False)
    kinds = {f["kind"] for f in r["findings"]}
    assert {"assign", "define", "url_creds", "telegram", "github", "aws"} <= kinds
    assert r["counts"]["high"] == 3 and r["counts"]["med"] == 3
    dump = json.dumps(r)
    for secret in (WIFI, TG, GH, AWS):
        assert secret not in dump  # ποτέ η πλήρης τιμή στην απάντηση
    wifi = next(f for f in r["findings"] if f["kind"] == "assign")
    assert wifi["masked"] == WIFI[:4] + f"…({len(WIFI)})" and wifi["file"] == "src/main.cpp" and wifi["line"] == 2


def test_placeholders_and_env_lookups_are_ignored(home):
    p = _project(home, {"a.ino": 'password = "your_password";\npwd = "changeme";\ntoken = "${TOKEN}";\n'
                                 'api_key = os.getenv("KEY");\nsecret = "xxxxxxxx";\npassword = "change-me-long-random";\n'
                                 'password = "μακρύς-τυχαίος-κωδικός";\n#define WIFI_PASS "********"\n'
                                 'smtp_password = "app-password";\npassword = "your-app-password"\n'})
    assert secretscan.scan(str(p), history=False)["findings"] == []


def test_private_key_needs_a_real_body(home):
    body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"
    p = _project(home, {"detect.py": 'if "-----BEGIN OPENSSH PRIVATE KEY-----" in data:\n    warn()\n',
                        "deploy/id_ed25519": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"})
    r = secretscan.scan(str(p), history=False)
    assert [f["file"] for f in r["findings"]] == ["deploy/id_ed25519"]
    assert r["findings"][0]["masked"] == f"…({len(body)})"  # ούτε οι πρώτοι χαρακτήρες του κλειδιού


def test_same_secret_many_places_is_one_finding_and_tests_are_examples(home):
    p = _project(home, {"a.py": f'token = "{GH}"\n', "b.py": f'token = "{GH}"\n',
                        "tests/test_x.py": f'AWS = "{AWS}"\n'})
    r = secretscan.scan(str(p), history=False)
    gh = next(f for f in r["findings"] if f["kind"] == "github")
    assert gh["more"] == 1 and gh["also"] == ["b.py:1"]
    aws = next(f for f in r["findings"] if f["kind"] == "aws")
    assert aws["example"] is True and r["counts"]["examples"] == 1
    assert r["findings"][-1] is aws  # τα παραδείγματα στο τέλος


def test_only_inside_home_and_never_home_itself(home, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with pytest.raises(ValueError):
        secretscan.check_path(str(outside))
    with pytest.raises(ValueError):
        secretscan.check_path(str(home))
    with pytest.raises(ValueError):
        secretscan.check_path("")
    p = _project(home, {"x.txt": "hi"})
    (p / "link").symlink_to(outside)  # symlink προς έξω: δεν το ακολουθούμε
    (outside / "leak.py").write_text(f'token = "{GH}"\n')
    assert secretscan.scan(str(p), history=False)["findings"] == []
    assert secretscan.check_path("~/proj") == os.path.realpath(str(p))


@pytest.mark.skipif(shutil.which("git") is None, reason="χρειάζεται git")
def test_secret_deleted_later_is_still_found_in_history(home):
    p = _project(home, {"bot.py": f'TOKEN = "{TG}"\n'})
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    run = lambda *a: subprocess.run(["git", "-C", str(p), *a], check=True, capture_output=True, env=env)  # noqa: E731
    run("init", "-q")
    run("add", ".")
    run("commit", "-qm", "oops")
    (p / "bot.py").write_text('TOKEN = os.getenv("TOKEN")\n')
    run("commit", "-qam", "remove token")
    r = secretscan.scan(str(p))
    assert r["history"]["scanned"] and r["history"]["commits"] == 2 and r["history"]["only_in_history"] == 1
    f = r["findings"][0]
    assert f["where"] == "history" and f["kind"] == "telegram" and f["file"] == "bot.py" and f["commit"]
    assert TG not in json.dumps(r)


def test_netkit_tool_and_demo():
    r = netkit.run_tool({"tool": "secrets", "path": "~/x"}, sim=True)
    assert r["sim"] and r["counts"]["high"] == 1 and any(f["where"] == "history" for f in r["findings"])
