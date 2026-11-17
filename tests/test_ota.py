"""Signed OTA: tools/ota/ota_sign.py, tools/ota/ota_server.py και συμβατότητα με το firmware.

Χρειάζεται το `openssl` (υπάρχει σε macOS και ubuntu). Το τεστ συμβατότητας με
το firmware/common/signed_ota_core.h χρειάζεται και C++ compiler (αλλιώς skip).
"""
import base64
import hashlib
import http.client
import importlib.util
import json
import os
import shutil
import ssl
import stat
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OTA_DIR = os.path.join(ROOT, "tools", "ota")
COMMON = os.path.join(ROOT, "firmware", "common")

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="χρειάζεται openssl")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(OTA_DIR, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ota_sign = _load("ota_sign")
ota_server = _load("ota_server")


def _fw(path, n=50000, seed=b"fw"):
    data = bytes([0xE9]) + hashlib.sha256(seed).digest() * (n // 32)
    with open(path, "wb") as f:
        f.write(data)
    return data


@pytest.fixture()
def keys(tmp_path):
    key, pub, hdr = ota_sign.genkey(str(tmp_path / "keys"))
    return key, pub, hdr


# --------------------------------------------------------------------------- genkey
def test_genkey_permissions_header_and_no_overwrite(keys):
    key, pub, hdr = keys
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    with open(key) as f:
        assert "PRIVATE KEY" in f.read()
    with open(hdr) as f:
        h = f.read()
    assert 'static const char OTA_PUBKEY_PEM[] = R"PEM(' in h and "-----BEGIN PUBLIC KEY-----" in h
    assert "PRIVATE KEY" not in h
    with pytest.raises(ota_sign.OtaError):
        ota_sign.genkey(os.path.dirname(key))   # δεν αντικαθιστά υπάρχον κλειδί
    with open(key) as f:
        old = f.read()
    ota_sign.genkey(os.path.dirname(key), force=True)   # αλλαγή κλειδιού: το παλιό κρατιέται
    baks = [n for n in os.listdir(os.path.dirname(key)) if n.startswith("ota_signing.pem.bak-")]
    assert len(baks) == 1
    with open(os.path.join(os.path.dirname(key), baks[0])) as f:
        assert f.read() == old
    with open(key) as f:
        assert f.read() != old


# --------------------------------------------------------------------------- sign / verify
def test_sign_manifest_fields_and_openssl_roundtrip(tmp_path, keys):
    key, pub, _ = keys
    data = _fw(str(tmp_path / "fw.bin"))
    bin_out, man_path, m = ota_sign.sign_firmware(str(tmp_path / "fw.bin"), key, "1.2.0", "canary",
                                                  str(tmp_path / "repo"))
    assert bin_out.endswith(os.path.join("canary", "1.2.0.bin")) and man_path.endswith(os.path.join("canary", "manifest.json"))
    with open(man_path) as f:
        disk = json.load(f)
    assert disk == m
    assert set(m) == {"format", "class", "version", "size", "sha256", "sig"}
    assert m["format"] == 1 and m["class"] == "canary" and m["version"] == "1.2.0"
    assert m["size"] == len(data) and m["sha256"] == hashlib.sha256(data).hexdigest()
    with open(bin_out, "rb") as f:
        assert f.read() == data

    sig = base64.b64decode(m["sig"], validate=True)
    assert sig[0] == 0x30 and len(sig) <= 72   # DER SEQUENCE, P-256

    # (α) Όπως το openssl: ECDSA-SHA256 πάνω στο signed statement
    st = ota_sign.statement("canary", "1.2.0", len(data), m["sha256"])
    assert st == ("netwatch-ota/1\ncanary\n1.2.0\n%d\n%s\n" % (len(data), m["sha256"])).encode()
    assert ota_sign.verify_bytes(pub, st, sig)

    # (β) Όπως το mbedtls_pk_verify(MBEDTLS_MD_SHA256, hash32, sig_der): επαλήθευση
    #     πάνω στο ΗΔΗ υπολογισμένο hash των 32 bytes (pkeyutl δεν ξανακάνει hash).
    (tmp_path / "h.bin").write_bytes(hashlib.sha256(st).digest())
    (tmp_path / "s.der").write_bytes(sig)
    p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-in", str(tmp_path / "h.bin"),
                        "-sigfile", str(tmp_path / "s.der")], capture_output=True, text=True)
    assert p.returncode == 0 and "Verified Successfully" in p.stdout

    assert ota_sign.verify_manifest(man_path, pub)["version"] == "1.2.0"
    assert ota_sign.main(["--verify", man_path, "--pub", pub]) == 0


def test_tampering_is_detected(tmp_path, keys):
    key, pub, _ = keys
    _fw(str(tmp_path / "fw.bin"))
    bin_out, man_path, m = ota_sign.sign_firmware(str(tmp_path / "fw.bin"), key, "1.2.0", "sentinel",
                                                  str(tmp_path / "repo"))
    sig = base64.b64decode(m["sig"])
    # ένα byte του firmware άλλαξε
    with open(bin_out, "r+b") as f:
        f.seek(100)
        f.write(b"\x00")
    with pytest.raises(ota_sign.OtaError):
        ota_sign.verify_manifest(man_path, pub)
    # "μετονομασία" του ίδιου υπογεγραμμένου .bin σε νεότερη έκδοση ή άλλη κατηγορία
    assert not ota_sign.verify_bytes(pub, ota_sign.statement("sentinel", "9.9.9", m["size"], m["sha256"]), sig)
    assert not ota_sign.verify_bytes(pub, ota_sign.statement("canary", "1.2.0", m["size"], m["sha256"]), sig)
    # άλλο κλειδί
    _, other_pub, _ = ota_sign.genkey(str(tmp_path / "other"))
    assert not ota_sign.verify_bytes(other_pub, ota_sign.statement("sentinel", "1.2.0", m["size"], m["sha256"]), sig)


def test_signer_refuses_rollback_bad_version_and_wrong_files(tmp_path, keys):
    key, _, _ = keys
    _fw(str(tmp_path / "fw.bin"))
    repo = str(tmp_path / "repo")
    ota_sign.sign_firmware(str(tmp_path / "fw.bin"), key, "1.2.0", "canary", repo)
    for v in ("1.2.0", "1.1.9", "0.9.0"):
        with pytest.raises(ota_sign.OtaError):
            ota_sign.sign_firmware(str(tmp_path / "fw.bin"), key, v, "canary", repo)
    ota_sign.sign_firmware(str(tmp_path / "fw.bin"), key, "1.10.0", "canary", repo)   # αριθμητική, όχι αλφαβητική σύγκριση
    for v in ("1.2", "1.2.0-beta", "01.2.0", "1.2.0 ", "v1.2.0", "70000.0.0"):
        with pytest.raises(ota_sign.OtaError):
            ota_sign.parse_version(v)
    (tmp_path / "merged.bin").write_bytes(b"\xff" * 5000)
    with pytest.raises(ota_sign.OtaError):
        ota_sign.sign_firmware(str(tmp_path / "merged.bin"), key, "2.0.0", "canary", repo)
    with pytest.raises(ota_sign.OtaError):
        ota_sign.sign_firmware(str(tmp_path / "fw.bin"), key, "2.0.0", "../etc", repo)


# --------------------------------------------------------------------------- firmware compatibility
HARNESS = textwrap.dedent(r"""
    #include <stdio.h>
    #include <stdlib.h>
    #include "signed_ota_core.h"
    using namespace signed_ota_core;
    int main(int argc, char **argv) {
      if (argc == 4 && !strcmp(argv[1], "ver")) {
        uint32_t a[3], b[3];
        if (!parseVersion(argv[2], a) || !parseVersion(argv[3], b)) { puts("BAD"); return 0; }
        printf("%d\n", compareVersion(a, b));
        return 0;
      }
      static char buf[4096];
      size_t n = fread(buf, 1, sizeof buf - 1, stdin);
      buf[n] = 0;
      Manifest m;
      if (!parseManifest(buf, m)) { fputs("REJECT", stdout); return 0; }
      char st[160];
      int k = buildStatement(st, sizeof st, m);
      if (k < 0 || (size_t)k >= sizeof st) { fputs("REJECT", stdout); return 0; }
      fwrite(st, 1, (size_t)k, stdout);
      return 0;
    }
""")


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    cxx = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
    if not cxx:
        pytest.skip("χωρίς C++ compiler")
    d = tmp_path_factory.mktemp("harness")
    src, exe = d / "h.cpp", d / "h"
    src.write_text(HARNESS)
    p = subprocess.run([cxx, "-std=c++11", "-Wall", "-Wextra", "-Werror", "-I", COMMON, str(src), "-o", str(exe)],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return str(exe)


def _run(exe, stdin=b"", *args):
    return subprocess.run([exe] + list(args), input=stdin, capture_output=True).stdout


def test_firmware_parser_rebuilds_exact_signed_statement(tmp_path, keys, harness):
    """Το C++ του firmware (signed_ota_core.h) διαβάζει το manifest του ota_sign.py
    και ξαναφτιάχνει ΑΚΡΙΒΩΣ τα bytes που υπογράφηκαν -> η υπογραφή επαληθεύεται."""
    key, pub, _ = keys
    _fw(str(tmp_path / "fw.bin"), n=123457)
    _, man_path, m = ota_sign.sign_firmware(str(tmp_path / "fw.bin"), key, "65535.0.12", "sentinel",
                                            str(tmp_path / "repo"))
    with open(man_path, "rb") as f:
        st = _run(harness, f.read())
    assert st == ota_sign.statement(m["class"], m["version"], m["size"], m["sha256"])
    assert ota_sign.verify_bytes(pub, st, base64.b64decode(m["sig"]))


@pytest.mark.parametrize("doc", [
    b'',
    b'[]',
    b'{}',
    b'{"format":1,"class":"canary","version":"1.2.0","size":5000,"sha256":"' + b"a" * 64 + b'"}',              # χωρίς sig
    b'{"format":1,"class":"canary","version":"1.2.0","size":5000,"sha256":"' + b"a" * 64 + b'","sig":"x"} x',  # σκουπίδια μετά
    b'{"format":1,"class":"canary","class":"sentinel","version":"1.2.0","size":5000,"sha256":"' + b"a" * 64 + b'","sig":"x"}',
    b'{"format":1,"class":"can\\"ary","version":"1.2.0","size":5000,"sha256":"' + b"a" * 64 + b'","sig":"x"}',
    b'{"format":1,"class":"canary","version":"1.2.0","size":-5,"sha256":"' + b"a" * 64 + b'","sig":"x"}',
    b'{"format":1,"class":"canary","version":"1.2.0","size":99999999999,"sha256":"' + b"a" * 64 + b'","sig":"x"}',
    b'{"format":1,"class":"canary","version":"1.2.0","size":5000,"sha256":"' + b"a" * 64 + b'","sig":"' + b"A" * 300 + b'"}',
    b'{"format":1,"class":{"x":1},"version":"1.2.0","size":5000,"sha256":"' + b"a" * 64 + b'","sig":"x"}',
    b'{"format":1,"class":"canary","version":"1.2.0","size":5000,"sha256":"' + b"a" * 64 + b'","sig":"x",',
])
def test_firmware_parser_rejects_malformed(harness, doc):
    assert _run(harness, doc) == b"REJECT"


def test_firmware_version_compare_matches_python(harness):
    for a, b in [("1.2.0", "1.10.0"), ("1.2.0", "1.2.0"), ("2.0.0", "1.99.99"), ("0.0.1", "0.0.0")]:
        want = (ota_sign.parse_version(a) > ota_sign.parse_version(b)) - (ota_sign.parse_version(a) < ota_sign.parse_version(b))
        assert int(_run(harness, b"", "ver", a, b)) == want
    for bad in ("1.2", "1.2.0-rc1", "01.2.0", "1.2.0.0", "70000.0.0", "", "a.b.c"):
        assert _run(harness, b"", "ver", bad, "1.0.0").strip() == b"BAD"


# --------------------------------------------------------------------------- server
def _openssl(*args, cwd):
    subprocess.run(["openssl"] + list(args), cwd=cwd, check=True, capture_output=True)


@pytest.fixture()
def tls_files(tmp_path):
    """CA + πιστοποιητικό server (SAN localhost/127.0.0.1), όπως το tools/mosquitto-tls.sh."""
    d = tmp_path / "ca"
    d.mkdir()
    (d / "ca.cnf").write_text("[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\n"
                              "keyUsage=critical,keyCertSign,cRLSign\n")
    (d / "srv.ext").write_text("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyAgreement\n"
                               "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
    c = str(d)
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key", cwd=c)
    _openssl("req", "-x509", "-new", "-key", "ca.key", "-sha256", "-days", "2", "-subj", "/CN=Test CA",
             "-config", "ca.cnf", "-extensions", "v3_ca", "-out", "ca.crt", cwd=c)
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "srv.key", cwd=c)
    _openssl("req", "-new", "-key", "srv.key", "-subj", "/CN=localhost", "-config", "ca.cnf", "-out", "srv.csr", cwd=c)
    _openssl("x509", "-req", "-in", "srv.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-sha256",
             "-days", "2", "-extfile", "srv.ext", "-out", "srv.crt", cwd=c)
    return str(d / "ca.crt"), str(d / "srv.crt"), str(d / "srv.key")


@pytest.fixture()
def server(tmp_path, keys, tls_files):
    key, _, _ = keys
    ca, crt, skey = tls_files
    repo = tmp_path / "srv"
    _fw(str(tmp_path / "fw.bin"), n=200000)
    ota_sign.sign_firmware(str(tmp_path / "fw.bin"), key, "1.2.0", "canary", str(repo))
    (repo / "canary" / "notes.txt").write_text("δεν σερβίρεται")
    (repo / ".hidden").mkdir()
    (repo / ".hidden" / "manifest.json").write_text("{}")
    (tmp_path / "secret.bin").write_bytes(b"\xe9secret")
    os.symlink(str(tmp_path / "secret.bin"), str(repo / "canary" / "6.6.6.bin"))   # symlink έξω από το root
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "manifest.json").write_text('{"leak": true}')
    srv = ota_server.make_server(str(repo), "127.0.0.1", 0, crt, skey)
    ota_server.serve_in_thread(srv)
    ctx = ssl.create_default_context(cafile=ca)
    yield srv.server_address[1], ctx, repo
    srv.shutdown()
    srv.server_close()


def _req(port, ctx, path, method="GET"):
    c = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=10)
    try:
        c.putrequest(method, path, skip_host=False, skip_accept_encoding=True)
        c.endheaders()
        r = c.getresponse()
        return r.status, r.read(), r
    finally:
        c.close()


def test_server_serves_manifest_and_firmware(server):
    port, ctx, repo = server
    st, body, r = _req(port, ctx, "/canary/manifest.json")
    assert st == 200 and json.loads(body)["version"] == "1.2.0"
    assert r.getheader("Content-Type") == "application/json" and r.getheader("Content-Length") == str(len(body))
    st, body, r = _req(port, ctx, "/canary/1.2.0.bin")
    assert st == 200 and body == (repo / "canary" / "1.2.0.bin").read_bytes() and len(body) > 100000
    assert r.getheader("Cache-Control") == "no-store"


@pytest.mark.parametrize("path", [
    "/canary/../../outside/manifest.json",
    "/../outside/manifest.json",
    "/canary/%2e%2e/%2e%2e/outside/manifest.json",
    "/canary/..%2f..%2foutside/manifest.json",
    "/canary/%2e%2e%2f%2e%2e%2foutside%2fmanifest.json",
    "/canary/..\\..\\outside\\manifest.json",
    "//etc/passwd",
    "/etc/passwd",
    "/canary/6.6.6.bin",          # symlink που βγαίνει έξω
    "/canary/notes.txt",          # μη επιτρεπτός τύπος
    "/.hidden/manifest.json",
    "/canary/manifest.json%00.bin",
    "/canary/1.2.0.bin.tmp",
    "/canary/1.3.0.bin",          # δεν υπάρχει
])
def test_server_refuses_traversal_and_unknown_files(server, path):
    port, ctx, _ = server
    st, body, _ = _req(port, ctx, path)
    assert st == 404 and b"leak" not in body and b"secret" not in body


@pytest.mark.parametrize("path", ["/", "/canary", "/canary/", "/canary/."])
def test_server_has_no_directory_listing(server, path):
    port, ctx, _ = server
    st, body, _ = _req(port, ctx, path)
    assert st == 404 and b"manifest" not in body


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
def test_server_get_only(server, method):
    port, ctx, _ = server
    st, _, r = _req(port, ctx, "/canary/manifest.json", method)
    assert st == 405 and r.getheader("Allow") == "GET"


def test_server_rejects_plain_http(server):
    port, _, _ = server
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    with pytest.raises((http.client.HTTPException, ConnectionError, OSError)):
        c.request("GET", "/canary/manifest.json")
        c.getresponse().read()
    c.close()


def test_resolve_unit(tmp_path):
    (tmp_path / "canary").mkdir()
    (tmp_path / "canary" / "manifest.json").write_text("{}")
    r = str(tmp_path)
    assert ota_server.resolve(r, "/canary/manifest.json") == os.path.realpath(str(tmp_path / "canary" / "manifest.json"))
    assert ota_server.resolve(r, "/canary/manifest.json?x=1") is not None
    for p in ("/canary", "/canary/", "canary/manifest.json", "/canary/../canary/manifest.json",
              "/Canary/manifest.json", "/canary/manifest.JSON", "/canary/%ff.bin", "/a/b/manifest.json"):
        assert ota_server.resolve(r, p) is None, p


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX")
def test_server_refuses_to_start_with_signing_key_in_root(tmp_path, keys, tls_files):
    key, _, _ = keys
    _, crt, skey = tls_files
    shutil.copy(key, str(tmp_path / "ota_signing.pem"))
    assert ota_server.main(["--root", str(tmp_path), "--cert", crt, "--key", skey, "--port", "0"]) == 2
