import os
import stat
import shutil

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
def test_cert_and_tls_context(tmp_path):
    crt, key, fp = agent.ensure_cert(str(tmp_path))
    assert len(fp.split(":")) == 32 and (os.name == "nt" or stat.S_IMODE(os.stat(key).st_mode) == 0o600)
    agent.tls_context(crt, key)
    assert agent.ensure_cert(str(tmp_path))[2] == fp  # δεν ξαναφτιάχνεται
