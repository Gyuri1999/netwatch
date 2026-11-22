"""🛰 Απομακρυσμένη πρόσβαση: X25519, έλεγχος ρυθμίσεων, αρχείο WireGuard, κατάσταση τούνελ — χωρίς δίκτυο."""
import base64
import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import remote  # noqa: E402

H = bytes.fromhex
HUB = base64.b64encode(bytes(range(32))).decode()
OK = {"host": "vpn.example.gr", "port": "51820", "hub_key": HUB}


def test_x25519_rfc7748_vectors():
    assert remote.x25519(H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                         H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")).hex() == \
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    assert remote.x25519(H("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                         H("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")).hex() == \
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
    # §6.1: δημόσια κλειδιά Alice / Bob και κοινό μυστικό
    a, b = H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), H("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    pa, pb = remote.x25519(a), remote.x25519(b)
    assert pa.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert pb.hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    assert remote.x25519(a, pb) == remote.x25519(b, pa) == H("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    with pytest.raises(ValueError):
        remote.x25519(b"short")


def test_keypair_format_and_clamping():
    priv, pub = remote.keypair(rand=lambda n: b"\xff" * n)
    raw = base64.b64decode(priv)
    assert len(priv) == len(pub) == 44 and raw[0] & 7 == 0 and raw[31] & 0x80 == 0 and raw[31] & 0x40
    assert remote.pubkey_of(priv) == pub and remote.valid_key(pub)
    p1, _ = remote.keypair()
    p2, _ = remote.keypair()
    assert p1 != p2
    for bad in ("", "abc", HUB[:-1], HUB + "=", "!" * 44, None, 5):
        assert not remote.valid_key(bad)


def test_check_validates_everything():
    c, err = remote.check(OK)
    assert err is None and c == {"host": "vpn.example.gr", "port": 51820, "hub_key": HUB, "subnet": "10.99.0.0/24",
                                 "hub_ip": "10.99.0.1", "box_ip": "10.99.0.10", "name": "netwatch-box"}
    assert remote.check(dict(OK, host="203.0.113.7"))[1] is None and remote.check(dict(OK, host="2001:db8::1"))[1] is None
    bad = [dict(OK, host=""), dict(OK, host="vpn"), dict(OK, host="a b.gr"), dict(OK, host="x.gr; rm -rf /"), dict(OK, host="x.gr\nPostUp = id"),
           dict(OK, port="0"), dict(OK, port="70000"), dict(OK, port="x"), dict(OK, hub_key="nope"),
           dict(OK, subnet="8.8.8.0/24"), dict(OK, subnet="10.0.0.0/8"), dict(OK, subnet="10.99.0.1/24"), dict(OK, subnet="fd00::/64"),
           dict(OK, box_ip="10.98.0.5"), dict(OK, box_ip="10.99.0.1"), dict(OK, box_ip="10.99.0.255"), dict(OK, hub_ip="10.99.0.0"), None, "x"]
    for b in bad:
        assert remote.check(b)[0] is None and remote.check(b)[1], b
    assert remote.check(dict(OK, name='box"; evil\n[Peer]'))[0]["name"] == "boxevilPeer"


def test_setup_writes_private_conf_and_never_returns_key(tmp_path):
    r = remote.Remote(None, str(tmp_path), runner=lambda argv: (1, "", "Unable to access interface: No such device"))
    assert r.view()["configured"] is False and r.api("GET", "", {}, {})[1]["link"]["state"] == "none"
    assert r.api("POST", "setup", {}, dict(OK, hub_key="x"))[0] == 400
    code, v = r.api("POST", "setup", {}, dict(OK, name="box-1"))
    conf = tmp_path / "remote" / "nw0.conf"
    text = conf.read_text(encoding="utf-8")
    assert code == 200 and v["configured"] and v["link"]["state"] == "ready"
    if os.name != "nt":
        assert stat.S_IMODE(conf.stat().st_mode) == 0o600 and stat.S_IMODE((tmp_path / "remote" / "remote.json").stat().st_mode) == 0o600
    priv = [ln.split(" = ")[1] for ln in text.splitlines() if ln.startswith("PrivateKey")][0]
    assert remote.pubkey_of(priv) == v["pub"] and priv not in repr(v) and priv not in (tmp_path / "remote" / "remote.json").read_text()
    assert f"PublicKey = {HUB}" in text and "Endpoint = vpn.example.gr:51820" in text and "PersistentKeepalive = 25" in text
    # μόνο ΜΙΑ διεύθυνση περνά από το τούνελ — ποτέ όλο το Internet ή το δίκτυο του πελάτη
    assert "AllowedIPs = 10.99.0.1/32" in text and "0.0.0.0/0" not in text and "PostUp" not in text and "DNS" not in text
    assert v["hub"]["wg"] == f"# box-1\n[Peer]\nPublicKey = {v['pub']}\nAllowedIPs = 10.99.0.10/32\n"
    assert v["pub"] in v["hub"]["mikrotik"] and v["url"] == "https://10.99.0.10:8765/"
    # αλλαγή διεύθυνσης κρατά τα ίδια κλειδιά· «νέο ζεύγος» τα αλλάζει
    _, v2 = r.api("POST", "setup", {}, dict(OK, box_ip="10.99.0.20"))
    assert v2["pub"] == v["pub"] and "Address = 10.99.0.20/32" in conf.read_text()
    _, v3 = r.api("POST", "setup", {}, dict(OK, new_key=True))
    assert v3["pub"] != v["pub"]
    # επανεκκίνηση: διαβάζει ξανά τη ρύθμιση· σβήσιμο: δεν μένει τίποτα στον δίσκο
    assert remote.Remote(None, str(tmp_path)).view()["pub"] == v3["pub"]
    assert r.api("POST", "forget", {}, {})[0] == 400
    assert r.api("POST", "forget", {}, {"confirm": True})[1]["configured"] is False and not conf.exists()
    assert remote.Remote(None, str(tmp_path)).view()["configured"] is False


def test_ipv6_endpoint_is_bracketed():
    c, _ = remote.check(dict(OK, host="2001:db8::1"))
    assert "Endpoint = [2001:db8::1]:51820" in remote.box_conf(c, "PRIV")


class State:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, detail, kw))


def dump(handshake, hub=HUB):
    # `wg show nw0 dump`: 1η γραμμή = ιδιωτικό, δημόσιο, θύρα, fwmark· μετά ένα peer ανά γραμμή
    return (0, f"PRIVATEKEYMUSTNOTLEAK\tPUB\t51820\toff\n{hub}\t(none)\t203.0.113.7:51820\t10.99.0.1/32\t{handshake}\t1000\t2000\t25\n", "")


def test_link_state_and_alert_once(tmp_path):
    now, out, st = [1000.0], [dump(990)], State()
    r = remote.Remote(st, str(tmp_path), clock=lambda: now[0], runner=lambda argv: out[0])
    r.setup(OK)
    link = r.poll()
    assert link == {"state": "up", "handshake": 990, "ago": 10, "rx": 1000, "tx": 2000, "endpoint": "203.0.113.7:51820"}
    assert "PRIVATEKEYMUSTNOTLEAK" not in repr(r.view())
    now[0] = 990 + remote.STALE_S + 60
    assert r.poll()["state"] == "stale" and len(st.alerts) == 1 and st.alerts[0][0] == remote.ALERT and st.alerts[0][1] == "med"
    r.poll()
    assert len(st.alerts) == 1                      # όχι ξανά όσο μένει κάτω
    out[0] = dump(int(now[0]) - 5)
    assert r.poll()["state"] == "up"
    out[0] = (1, "", "Unable to access interface: No such device")
    assert r.poll() == {"state": "ready", "why": "noiface"} and len(st.alerts) == 2   # έπεσε ξανά → νέα ειδοποίηση
    out[0] = dump(0)
    assert r.poll()["state"] == "never"
    out[0] = dump(int(now[0]), hub=base64.b64encode(b"\x07" * 32).decode())
    assert r.poll() == {"state": "down", "why": "nopeer"}
    out[0] = (-2, "", "no wg")
    assert r.poll() == {"state": "ready", "why": "nowg"}
    out[0] = (1, "", "Operation not permitted")
    assert r.poll()["why"] == "perm"


def test_never_up_never_alerts(tmp_path):
    st = State()
    r = remote.Remote(st, str(tmp_path), runner=lambda argv: dump(0))
    r.setup(OK)
    r.poll()
    r.poll()
    assert st.alerts == []


def test_demo_is_read_only():
    r = remote.Remote(None, demo=True)
    v = r.view()
    assert v["demo"] and v["configured"] and v["link"]["state"] == "up" and remote.valid_key(v["pub"])
    assert r.api("POST", "setup", {}, OK)[0] == 400 and r.api("POST", "forget", {}, {"confirm": True})[1]["configured"]
    assert r.api("GET", "nope", {}, {})[0] == 404


def test_setup_script_refuses_wide_tunnels():
    """Το wg-setup.sh δέχεται μόνο AllowedIPs /32 και καμία εντολή PostUp (τρέχουν ως root)."""
    p = os.path.join(os.path.dirname(__file__), "..", "tools", "fieldbox", "wg-setup.sh")
    s = open(p, encoding="utf-8").read()
    assert "set -euo pipefail" in s and "/32$" in s and "PostUp|PostDown|PreUp|PreDown|DNS|Table" in s and "--dry-run" in s
