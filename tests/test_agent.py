import os
import stat
import shutil
import ssl

import pytest

import agent


def test_token_is_created_private_and_reused(tmp_path):
    t1 = agent.load_token(str(tmp_path))
    assert len(t1) >= 20
    assert os.name == "nt" or stat.S_IMODE(os.stat(tmp_path / "agent-token").st_mode) == 0o600  # Windows: ACL, όχι mode bits
    assert agent.load_token(str(tmp_path)) == t1
    assert agent.load_token(str(tmp_path), "from-config-token-xxxxxx") == "from-config-token-xxxxxx"


def test_authorized_cookie_or_bearer():
    tok = "s3cret-token-0123456789"
    assert agent.authorized({"Cookie": f"a=1; nwtok={tok}"}, tok)
    assert agent.authorized({"Authorization": f"Bearer {tok}"}, tok)
    assert not agent.authorized({"Cookie": "nwtok=wrong"}, tok)
    assert not agent.authorized({}, tok)


def test_same_origin():
    assert agent.same_origin({"Host": "192.168.1.30:8765"})
    assert agent.same_origin({"Host": "192.168.1.30:8765", "Origin": "https://192.168.1.30:8765"})
    assert not agent.same_origin({"Host": "192.168.1.30:8765", "Origin": "https://evil.example"})
    assert not agent.same_origin({"Host": "192.168.1.30:8765", "Origin": "http://192.168.1.30:8765"})


@pytest.mark.skipif(not shutil.which("openssl"), reason="χρειάζεται openssl")
def test_cert_with_openssl_command(tmp_path, monkeypatch):
    import builtins
    real = builtins.__import__

    def no_crypto(name, *a, **kw):  # σαν να μην υπάρχει η cryptography → πέφτει στην εντολή openssl
        if name.startswith("cryptography"):
            raise ImportError(name)
        return real(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", no_crypto)
    crt, key, fp = agent.ensure_cert(str(tmp_path))
    assert len(fp.split(":")) == 32
    agent.tls_context(crt, key)


def test_cert_without_openssl_needs_cryptography(tmp_path, monkeypatch):
    """Windows 10/11: δεν υπάρχει openssl στο PATH. Με την cryptography (μέσα στο NetWatch.exe) δουλεύει κανονικά."""
    pytest.importorskip("cryptography")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    crt, key, fp = agent.ensure_cert(str(tmp_path / "data"))
    ctx = agent.tls_context(crt, key)
    assert len(fp.split(":")) == 32 and (os.name == "nt" or stat.S_IMODE(os.stat(key).st_mode) == 0o600)
    # πραγματικό TLS handshake με το πιστοποιητικό, και το fingerprint ταιριάζει με αυτό που βλέπει ο client
    import hashlib
    import socket
    import threading
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        try:
            with ctx.wrap_socket(c, server_side=True) as t:
                t.recv(1)
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    cli = ssl.create_default_context()
    cli.check_hostname, cli.verify_mode = False, ssl.CERT_NONE
    with cli.wrap_socket(socket.create_connection(srv.getsockname(), timeout=5)) as t:
        der = t.getpeercert(binary_form=True)
        t.sendall(b"x")
    srv.close()
    got = hashlib.sha256(der).hexdigest().upper()
    assert ":".join(got[i:i + 2] for i in range(0, len(got), 2)) == fp


def test_cert_clear_error_without_either(tmp_path, monkeypatch):
    import builtins
    real = builtins.__import__
    monkeypatch.setattr(builtins, "__import__", lambda n, *a, **kw: (_ for _ in ()).throw(ImportError(n))
                        if n.startswith("cryptography") else real(n, *a, **kw))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    with pytest.raises(RuntimeError, match="cryptography"):
        agent.ensure_cert(str(tmp_path / "data"))


@pytest.mark.skipif(not shutil.which("openssl"), reason="χρειάζεται openssl")
def test_cert_and_tls_context(tmp_path):
    crt, key, fp = agent.ensure_cert(str(tmp_path))
    assert len(fp.split(":")) == 32 and (os.name == "nt" or stat.S_IMODE(os.stat(key).st_mode) == 0o600)
    agent.tls_context(crt, key)
    assert agent.ensure_cert(str(tmp_path))[2] == fp  # δεν ξαναφτιάχνεται
