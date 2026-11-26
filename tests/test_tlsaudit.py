"""Tests για τον έλεγχο TLS/SSH (tlsaudit.py). Οι «servers» τρέχουν μόνο στο 127.0.0.1 μέσα στο test."""
import base64
import os
import socket
import ssl
import struct
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import tlsaudit  # noqa: E402

# Πιστοποιητικά μόνο για τα tests (self-signed, φτιαγμένα με openssl για αυτό το αρχείο)
RSA1024_SHA1 = base64.b64decode(
    "MIIBozCCAQwCCQCzkPci2R7gpjANBgkqhkiG9w0BAQUFADAWMRQwEgYDVQQDDAtyb3V0ZXIuaG9tZTAeFw0yNjExMTgxNTU3MzRaFw0zNjEx"
    "MTUxNTU3MzRaMBYxFDASBgNVBAMMC3JvdXRlci5ob21lMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYjNaxhLvGOfkSUhUaDaiCf2xN"
    "MF1seLMJUuQCAQ0EWTxKtZdqrktu6/w3e2Ue6tnWvrrqzwQwS2xA24LjgZRuRKhVi8xkl3wroO2rj7b9bdpyq5RNjC5PRz1rCoQrwWBRWYoJ"
    "OnTtjW6lWr0EtnQR5T5xeXazX56suTU8VteHowIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAA05fgxlfAelWxGfizah0v/V1CnN6vxTNxj2HehN"
    "Z5cRw+dQvZI1AAr3AflbKsuRo+rIEBTzKEytasccLwue+M0gujIt0kVViJ+42/Hq0OHf23QaCnGfb2kN0P6TbDyJy99jfkmFDdPCfgh/jKzR"
    "bWUBUyFcrr7Z4d5OvJFGXefA")
EC_KEY = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKusA6Los9oue4emiNQ6/0n3SrEBUgslpXdgI4FOGrCGoAoGCCqGSM49
AwEHoUQDQgAEVEZ911CLO6QcmaNWJUGWpPTinKbAqakY+JxAwjt8rvDqlTBD8jQL
IyKZ/CurT583iCbeY/bPQvpmXC1hWUOAdw==
-----END EC PRIVATE KEY-----
"""
EC_CERT = """-----BEGIN CERTIFICATE-----
MIIBFTCBvAIJAJfMEGmJkyjlMAoGCCqGSM49BAMCMBMxETAPBgNVBAMMCG5hcy5o
b21lMB4XDTI2MTExODE1NTczNFoXDTM2MTExNTE1NTczNFowEzERMA8GA1UEAwwI
bmFzLmhvbWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARURn3XUIs7pByZo1Yl
QZak9OKcpsCpqRj4nEDCO3yu8OqVMEPyNAsjIpn8K6tPnzeIJt5j9s9C+mZcLWFZ
Q4B3MAoGCCqGSM49BAMCA0gAMEUCIQDlI2LAKTwK9NVykV6PP+NRuqrpd+IEJMB1
JJ9qnQX8TgIgAnPvnOPMnaVOIE0/+qjzMS0hjuXLwALgmc624e1gcQY=
-----END CERTIFICATE-----
"""


def kexinit_payload(kex, hostkey, ciphers, macs, comp=("none",)):
    body = bytes([20]) + b"\x11" * 16
    for lst in (kex, hostkey, ciphers, ciphers, macs, macs, comp, comp, (), ()):
        b = ",".join(lst).encode()
        body += struct.pack(">I", len(b)) + b
    return body + b"\x00" + b"\x00" * 4


def packet(payload):
    pad = 8 - ((len(payload) + 5) % 8)
    if pad < 4:
        pad += 8
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


WEAK = dict(kex=["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"], hostkey=["ssh-rsa", "ssh-dss"],
            ciphers=["aes128-ctr", "3des-cbc", "arcfour", "aes128-cbc"], macs=["hmac-md5", "hmac-sha1-96", "hmac-sha2-256"])


def test_parse_canned_kexinit():
    raw = packet(kexinit_payload(**WEAK))
    pl = tlsaudit.packet_payload(raw)
    kx = tlsaudit.parse_kexinit(pl)
    assert kx["kex"] == WEAK["kex"] and kx["hostkey"] == WEAK["hostkey"]
    assert kx["enc_s2c"] == WEAK["ciphers"] and kx["mac_c2s"] == WEAK["macs"] and kx["comp_c2s"] == ["none"]
    assert tlsaudit.packet_payload(raw[:10]) is None  # δεν ήρθε ολόκληρο
    with pytest.raises(ValueError):
        tlsaudit.parse_kexinit(b"\x15" + pl[1:])
    # το δικό μας KEXINIT είναι κι αυτό έγκυρο πακέτο
    own = tlsaudit.build_kexinit()
    assert len(own) % 8 == 0
    assert "curve25519-sha256" in tlsaudit.parse_kexinit(tlsaudit.packet_payload(own))["kex"]


def test_grade_ssh_weak_and_good():
    info = dict(WEAK, banner="SSH-2.0-dropbear_2014.63", compression=["none"])
    g = tlsaudit.grade_ssh(info)
    ids = {f["id"] for f in g["findings"]}
    assert {"ssh_weak_kex", "ssh_weak_hostkey", "ssh_weak_cipher", "ssh_weak_mac", "ssh_old"} <= ids
    assert g["grade"] == "F" and g["software"] == "Dropbear" and g["version"] == "2014.63"
    assert set(g["weak"]["ciphers"]) == {"3des-cbc", "arcfour", "aes128-cbc"}
    assert "hmac-sha2-256" not in g["weak"]["macs"]
    good = tlsaudit.grade_ssh({"banner": "SSH-2.0-OpenSSH_9.8", "compression": ["none"],
                               "kex": ["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
                               "hostkey": ["ssh-ed25519", "rsa-sha2-512"],
                               "ciphers": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
                               "macs": ["hmac-sha2-256-etm@openssh.com"]})
    assert good["grade"] == "A" and good["findings"] == []
    terr = tlsaudit.grade_ssh({"banner": "SSH-2.0-OpenSSH_9.8", "kex": ["curve25519-sha256"], "hostkey": ["ssh-ed25519"],
                               "ciphers": ["chacha20-poly1305@openssh.com"], "macs": ["hmac-sha2-256-etm@openssh.com"]})
    assert any(f["id"] == "ssh_terrapin" for f in terr["findings"])


def test_ssh_versions():
    assert tlsaudit.ssh_software("SSH-2.0-OpenSSH_7.4p1 Debian-10") == ("OpenSSH", "7.4p1")
    assert tlsaudit.ssh_software("SSH-2.0-dropbear_2017.75") == ("Dropbear", "2017.75")
    assert tlsaudit.version_findings("OpenSSH", "6.6.1p1")[0][0] == "high"
    assert any(f[2] == "ssh_regresshion" for f in tlsaudit.version_findings("OpenSSH", "9.6p1"))
    assert not any(f[2] == "ssh_regresshion" for f in tlsaudit.version_findings("OpenSSH", "9.6"))  # όχι portable
    assert tlsaudit.version_findings("OpenSSH", "9.9p1") == []


def test_grade_tls_fake_data():
    bad = tlsaudit.grade_tls({"versions": {"TLSv1": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": False},
                              "cipher": "DES-CBC3-SHA",
                              "cert": {"subject": "commonName=router.home", "issuer": "commonName=router.home",
                                       "days_left": -30, "sans": [], "key_type": "RSA", "key_bits": 1024,
                                       "sig_alg": "sha1WithRSAEncryption"}})
    ids = {f["id"] for f in bad["findings"]}
    assert {"tls_old", "tls_weak_cipher", "tls_cert_expired", "tls_self_signed", "tls_weak_key", "tls_weak_sig"} <= ids
    assert bad["grade"] == "F" and bad["cert"]["self_signed"]
    good = tlsaudit.grade_tls({"versions": {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
                               "cipher": "TLS_AES_256_GCM_SHA384",
                               "cert": {"subject": "commonName=nas", "issuer": "commonName=R11", "days_left": 60,
                                        "sans": ["nas"], "key_type": "EC", "key_bits": 256, "sig_alg": "ecdsa-with-SHA256"}})
    assert good["grade"] == "A" and good["findings"] == []
    only_old = tlsaudit.grade_tls({"versions": {"TLSv1": True, "TLSv1.1": False, "TLSv1.2": False, "TLSv1.3": None}})
    assert any(f["id"] == "tls_no_modern" for f in only_old["findings"]) and only_old["grade"] == "F"
    unknown13 = tlsaudit.grade_tls({"versions": {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": None}})
    assert unknown13["grade"] == "A" and not any(f["id"] == "tls_no13" for f in unknown13["findings"])


def test_cert_key_info_parser():
    k = tlsaudit.cert_key_info(RSA1024_SHA1)
    assert k == {"key_type": "RSA", "key_bits": 1024, "curve": None, "sig_alg": "sha1WithRSAEncryption"}
    k = tlsaudit.cert_key_info(ssl.PEM_cert_to_DER_cert(EC_CERT))
    assert k["key_type"] == "EC" and k["curve"] == "P-256" and k["key_bits"] == 256 and k["sig_alg"] == "ecdsa-with-SHA256"


def test_private_only_targets():
    assert tlsaudit.parse_target("192.168.1.1:443") == ("192.168.1.1", 443)
    assert tlsaudit.parse_target(" 10.0.0.5:22 ") == ("10.0.0.5", 22)
    assert tlsaudit.parse_target("192.168.1.1") == ("192.168.1.1", 443)  # σκέτη IP → HTTPS
    for bad in ("8.8.8.8:443", "127.0.0.1:22", "169.254.1.1:22", "192.168.1.0/24:443", "router:443",
                "8.8.8.8", "192.168.1.1:0", "192.168.1.1:70000", "224.0.0.1:443"):
        with pytest.raises(ValueError):
            tlsaudit.parse_target(bad)
    a = tlsaudit.TlsAudit(sim=False, scan=lambda: None)
    with pytest.raises(ValueError):
        a.start(["1.1.1.1:443"])
    with pytest.raises(ValueError):
        a.start()  # χωρίς σάρωση και χωρίς στόχους


def test_targets_from_scan():
    scan = {"hosts": [{"ip": "192.168.1.1", "services": [
        {"port": 22, "banner": "SSH-2.0-dropbear_2017.75"}, {"port": 443, "banner": ""}, {"port": 80, "banner": "HTTP/1.0"},
        {"port": 2222, "banner": "SSH-2.0-OpenSSH_9.8"}, {"port": 161, "proto": "udp"}, {"port": 9999, "tls": {"version": "TLSv1.2"}}]}]}
    assert tlsaudit.targets_from_scan(scan) == [("192.168.1.1", 22, "ssh"), ("192.168.1.1", 443, "tls"),
                                                ("192.168.1.1", 2222, "ssh"), ("192.168.1.1", 9999, "tls")]


def _serve(handler, ctx=None):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    stop = threading.Event()

    def loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                c.settimeout(3)
                handler(ctx.wrap_socket(c, server_side=True) if ctx else c)
            except Exception:
                pass
            finally:
                try:
                    c.close()
                except Exception:
                    pass
    threading.Thread(target=loop, daemon=True).start()
    return srv, stop


def test_ssh_probe_against_local_fake_server():
    def h(c):
        c.sendall(b"Welcome\r\nSSH-2.0-dropbear_2017.75\r\n")
        c.sendall(packet(kexinit_payload(**WEAK)))
        c.recv(4096)
    srv, stop = _serve(h)
    try:
        port = srv.getsockname()[1]
        info = tlsaudit.ssh_probe("127.0.0.1", port, timeout=3)
        assert info["banner"] == "SSH-2.0-dropbear_2017.75" and info["kex"] == WEAK["kex"]
        res = tlsaudit.audit_one("127.0.0.1", port, "ssh")
        assert res["grade"] == "F" and res["ssh"]["software"] == "Dropbear" and not res["error"]
        assert tlsaudit.sniff_kind("127.0.0.1", port) == "ssh"
    finally:
        stop.set()
        srv.close()


def test_tls_probe_against_local_server(tmp_path):
    (tmp_path / "k.pem").write_text(EC_KEY)
    (tmp_path / "c.pem").write_text(EC_CERT)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    def h(c):
        c.recv(100)
    srv, stop = _serve(h, ctx)
    try:
        port = srv.getsockname()[1]
        info = tlsaudit.tls_probe("127.0.0.1", port, timeout=3)
        assert info["versions"]["TLSv1.2"] is True
        sup = tlsaudit.local_support()
        for v in ("TLSv1", "TLSv1.1"):
            assert info["versions"][v] is (False if sup[v] else None)
        c = info["cert"]
        assert c["subject"] == c["issuer"] == "commonName=nas.home"
        assert c["key_type"] == "EC" and c["key_bits"] == 256 and c["days_left"] > 3000
        g = tlsaudit.grade_tls(info)
        assert g["cert"]["self_signed"] and any(f["id"] == "tls_self_signed" for f in g["findings"])
        assert tlsaudit.sniff_kind("127.0.0.1", port, timeout=0.3) == "tls"
    finally:
        stop.set()
        srv.close()


def test_demo_audit_runner():
    a = tlsaudit.TlsAudit(sim=True)
    st = a.status()
    assert st["status"] == "idle" and st["default_targets"]
    a.start()
    with pytest.raises(ValueError):
        a.start()
    r = a.wait(10)
    assert r["status"] == "done" and r["progress"] == 100
    by = {x["target"]: x for x in a.status()["results"]}
    assert by["192.168.1.1:443"]["grade"] == "F"
    assert by["192.168.1.16:5001"]["grade"] == "A"
    assert by["192.168.1.30:22"]["grade"] == "F" and "dropbear" in by["192.168.1.30:22"]["ssh"]["banner"]
    s = a.status()["summary"]
    assert s["services"] == len(by) and s["worst"] == "F" and s["grades"]["A"] >= 2
    a.start(["192.168.1.1:22", "192.168.1.99:443"])
    a.wait(10)
    res = a.status()["results"]
    assert res[0]["grade"] == "F" and res[1]["error"]


def test_results_persisted(tmp_path):
    path = str(tmp_path / "tls.json")
    a = tlsaudit.TlsAudit(sim=True, path=path)
    a.start(["192.168.1.16:22"])
    a.wait(10)
    b = tlsaudit.TlsAudit(sim=True, path=path)
    assert b.status()["status"] == "done" and b.last_results()[0]["target"] == "192.168.1.16:22"
