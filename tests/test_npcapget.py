"""⬇ Npcap με ένα κλικ: μόνο από npcap.com, μόνο με σωστή ψηφιακή υπογραφή, ποτέ σιωπηλή εγκατάσταση."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import npcapget  # noqa: E402

HTML = ('<a href="https://npcap.com/dist/npcap-1.79.exe">old</a> <a href="https://npcap.com/dist/npcap-1.80.exe">new</a>'
        ' <a href="https://evil.example/dist/npcap-9.99.exe">x</a>')


class P:
    def __init__(self, out):
        self.stdout = out.encode()


def test_latest_url_only_official():
    assert npcapget.latest_url(HTML) == "https://npcap.com/dist/npcap-1.80.exe"
    assert npcapget.latest_url("nothing") is None


def test_signature_must_be_valid_and_from_npcap_makers():
    ok = lambda argv: P("Valid|CN=Nmap Software LLC, O=Nmap Software LLC, L=Seattle")  # noqa: E731
    assert npcapget.check_signature("x.exe", runner=ok)[0]
    assert not npcapget.check_signature("x.exe", runner=lambda a: P("HashMismatch|CN=Nmap Software LLC"))[0]
    assert not npcapget.check_signature("x.exe", runner=lambda a: P("Valid|CN=Someone Else LLC"))[0]
    assert not npcapget.check_signature("x.exe", runner=lambda a: P(""))[0]


def _get(url, limit, dest=None, progress=None):
    if dest:
        open(dest, "wb").write(b"MZ installer")
        return 12
    return HTML.encode()


def test_download_verify_launch(tmp_path):
    launched = []
    g = npcapget.NpcapGet(str(tmp_path), get=_get, sig=lambda p: (True, "ok"), launch=launched.append, platform="win32")
    assert g.start(wait=True)["ok"]
    assert g.job["state"] == "done" and launched == [str(tmp_path / "npcap-1.80.exe")]


def test_bad_signature_deletes_and_never_launches(tmp_path):
    launched = []
    g = npcapget.NpcapGet(str(tmp_path), get=_get, sig=lambda p: (False, "κακή υπογραφή"), launch=launched.append, platform="win32")
    g.start(wait=True)
    assert g.job["state"] == "error" and not launched and not os.listdir(tmp_path)


def test_only_windows_and_only_npcap_host(tmp_path):
    assert "error" in npcapget.NpcapGet(str(tmp_path), platform="darwin").start()
    try:
        npcapget._get("https://evil.example/npcap-1.80.exe", 10)
        raise AssertionError("έπρεπε να αρνηθεί")
    except RuntimeError as e:
        assert "npcap.com" in str(e)
