"""JA4 (FoxIO) από ClientHello φτιαγμένο με το χέρι.

Παράδειγμα του README του FoxIO (Chrome): t13d1516h2_8daaf6152771_e5627efa2ab1

Παραγωγή βήμα-βήμα για το CHROME_HELLO πιο κάτω:
  a) «t»   — TCP
     «13»  — supported_versions = [GREASE 0x3a3a, 0x0304, 0x0303] → μέγιστη μη-GREASE 0x0304 = TLS 1.3
             (η legacy έκδοση του ClientHello είναι 0x0303, αλλά υπερισχύει το supported_versions)
     «d»   — υπάρχει extension SNI (0x0000)
     «15»  — 16 ciphers στο πακέτο, ο ένας GREASE (0x0a0a) → 15
     «16»  — 17 extensions στο πακέτο, η μία GREASE (0x1a1a) → 16 (μετράνε και οι SNI/ALPN)
     «h2»  — 1η τιμή ALPN «h2» → πρώτος «h» + τελευταίος «2»
  b) ciphers ταξινομημένοι, 4 hex πεζά, με κόμματα:
     "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
     sha256 → 8daaf6152771…
  c) extensions ταξινομημένες χωρίς GREASE, SNI (0000) και ALPN (0010):
     "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"
     + "_" + signature algorithms με την αρχική τους σειρά:
     "0403,0804,0401,0503,0805,0501,0806,0601"
     sha256 → e5627efa2ab1…
"""
import hashlib

import capture
from capture import parse_client_hello


def u16(n):
    return n.to_bytes(2, "big")


def ext(t, data=b""):
    return u16(t) + u16(len(data)) + data


def client_hello(ciphers, exts, legacy=0x0303):
    body = u16(legacy) + b"\x11" * 32 + b"\x00"  # version, random, session id (κενό)
    cs = b"".join(u16(c) for c in ciphers)
    body += u16(len(cs)) + cs + b"\x01\x00"      # ciphers, compression: null
    ex = b"".join(exts)
    body += u16(len(ex)) + ex
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + u16(len(hs)) + hs


def sni_ext(name):
    n = name.encode()
    entry = b"\x00" + u16(len(n)) + n
    return ext(0x0000, u16(len(entry)) + entry)


def alpn_ext(*protos):
    lst = b"".join(bytes([len(p)]) + p for p in protos)
    return ext(0x0010, u16(len(lst)) + lst)


def u16list_ext(t, vals):
    d = b"".join(u16(v) for v in vals)
    return ext(t, u16(len(d)) + d)


def sver_ext(vals):
    d = b"".join(u16(v) for v in vals)
    return ext(0x002b, bytes([len(d)]) + d)


SIGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
CHROME_CIPHERS = [0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                  0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]


def chrome_exts(sni="www.example.com", alpn=(b"h2", b"http/1.1")):
    e = [ext(0x1a1a), ext(0x0012), ext(0x002d, b"\x01\x01"), ext(0x0023), ext(0x0017), ext(0xff01, b"\x00"),
         u16list_ext(0x000a, [0x001d, 0x0017, 0x0018]), ext(0x000b, b"\x01\x00"), u16list_ext(0x000d, SIGS),
         ext(0x0005, b"\x01\x00\x00\x00\x00"), ext(0x001b, b"\x02\x00\x02"), ext(0x0033, b"\x00\x00"),
         sver_ext([0x3a3a, 0x0304, 0x0303]), ext(0x4469, b"\x00\x03\x02h2"), ext(0x0015, b"\x00" * 8)]
    if sni:
        e.insert(1, sni_ext(sni))
    if alpn:
        e.insert(2, alpn_ext(*alpn))
    return e


CHROME_HELLO = client_hello(CHROME_CIPHERS, chrome_exts())


def sha12(s):
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def test_chrome_ja4_matches_foxio_example():
    r = parse_client_hello(CHROME_HELLO)
    assert r["sni"] == "www.example.com"
    assert r["ja4"] == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    # τα ενδιάμεσα strings του σχολίου
    assert sha12("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9") == "8daaf6152771"
    assert sha12("0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_"
                 "0403,0804,0401,0503,0805,0501,0806,0601") == "e5627efa2ab1"


def test_ja3_unchanged_and_present():
    r = parse_client_hello(CHROME_HELLO)
    assert r["ja3"] and len(r["ja3"]) == 32
    assert r["ja3_str"].startswith("771,4865-4866-4867-")  # GREASE εκτός και στο JA3


def test_grease_never_counted_or_hashed():
    no_grease = client_hello([c for c in CHROME_CIPHERS if c != 0x0a0a],
                             [e for e in chrome_exts() if e[:2] != b"\x1a\x1a"])
    more_grease = client_hello([0xfafa] + CHROME_CIPHERS + [0x2a2a], chrome_exts() + [ext(0xdada, b"\x00")])
    j = parse_client_hello(CHROME_HELLO)["ja4"]
    assert parse_client_hello(no_grease)["ja4"] == j
    assert parse_client_hello(more_grease)["ja4"] == j


def test_cipher_and_extension_order_does_not_matter_for_hashes():
    shuffled = client_hello(list(reversed(CHROME_CIPHERS)), list(reversed(chrome_exts())))
    a, b = parse_client_hello(CHROME_HELLO)["ja4"], parse_client_hello(shuffled)["ja4"]
    assert a.split("_")[1:] == b.split("_")[1:]


def test_no_sni_no_alpn():
    r = parse_client_hello(client_hello(CHROME_CIPHERS, chrome_exts(sni=None, alpn=None)))
    # 14 extensions, «i» (χωρίς SNI), «00» (χωρίς ALPN)· το c δεν αλλάζει γιατί SNI/ALPN εξαιρούνται ούτως ή άλλως
    assert r["ja4"] == "t13i151400_8daaf6152771_e5627efa2ab1"
    assert r["sni"] is None


def test_legacy_version_without_supported_versions_and_no_sigalgs():
    hello = client_hello([0x002f, 0x0035], [sni_ext("a.gr"), alpn_ext(b"http/1.1"), ext(0x0017)], legacy=0x0303)
    r = parse_client_hello(hello)
    # TLS 1.2 από τη legacy έκδοση· ALPN http/1.1 → «h1»· χωρίς signature algorithms → χωρίς «_» στο c
    assert r["ja4"] == f"t12d0203h1_{sha12('002f,0035')}_{sha12('0017')}"


def test_empty_cases_and_non_alnum_alpn():
    hello = client_hello([], [sni_ext("x.gr"), alpn_ext(b"\xabzz\xcd")], legacy=0x0301)
    r = parse_client_hello(hello)
    # χωρίς ciphers και χωρίς extensions εκτός από SNI/ALPN → μηδενικά· μη αλφαριθμητικό ALPN → hex «ab…cd» → «ad»
    assert r["ja4"] == "t10d0002ad_000000000000_000000000000"


def test_ja4_function_direct():
    assert capture.ja4(0x0303, [0x1301], [0x002b], False, b"h2", [0x0304], [0x0403]) == \
        f"t13i0101h2_{sha12('1301')}_{sha12('002b_0403')}"


def test_truncated_hello_has_no_ja4():
    r = parse_client_hello(CHROME_HELLO[:120])
    assert r is None or r["ja4"] is None
