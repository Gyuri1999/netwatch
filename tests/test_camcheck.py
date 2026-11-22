"""📷 Βοηθός παράδοσης καμερών: αναλυτές ONVIF / SADP / RTSP, σύγκρουση IP, κανόνες «μόνο ανάγνωση» — χωρίς δίκτυο."""
import calendar
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import camcheck as cc  # noqa: E402

NOW = 1_800_000_000.0


def onvif_time(utc, kind="NTP"):
    t = time.gmtime(utc)
    return (f'HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\n\r\n<SOAP-ENV:Envelope><SOAP-ENV:Body><tds:GetSystemDateAndTimeResponse>'
            f'<tds:SystemDateAndTime><tt:DateTimeType>{kind}</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings>'
            f'<tt:TimeZone><tt:TZ>EET-2EEST</tt:TZ></tt:TimeZone><tt:UTCDateTime><tt:Time><tt:Hour>{t.tm_hour}</tt:Hour><tt:Minute>{t.tm_min}</tt:Minute>'
            f'<tt:Second>{t.tm_sec}</tt:Second></tt:Time><tt:Date><tt:Year>{t.tm_year}</tt:Year><tt:Month>{t.tm_mon}</tt:Month><tt:Day>{t.tm_mday}</tt:Day></tt:Date>'
            f'</tt:UTCDateTime><tt:LocalDateTime><tt:Time><tt:Hour>1</tt:Hour><tt:Minute>1</tt:Minute><tt:Second>1</tt:Second></tt:Time>'
            f'<tt:Date><tt:Year>1999</tt:Year><tt:Month>1</tt:Month><tt:Day>1</tt:Day></tt:Date></tt:LocalDateTime></tds:SystemDateAndTime>'
            f'</tds:GetSystemDateAndTimeResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>').encode()


WSD = (b'<?xml version="1.0"?><SOAP-ENV:Envelope><SOAP-ENV:Body><d:ProbeMatches><d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter</d:Types>'
       b'<d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/hardware/DS-2CD2143G2-I onvif://www.onvif.org/name/HIKVISION%20DS-2CD2143G2-I '
       b'onvif://www.onvif.org/location/</d:Scopes><d:XAddrs>http://192.168.1.64/onvif/device_service http://[fe80::1]/onvif/device_service</d:XAddrs>'
       b'</d:ProbeMatch></d:ProbeMatches></SOAP-ENV:Body></SOAP-ENV:Envelope>')


def sadp(ip="192.168.1.64", mac="44-19-b6-aa-01-07", act="false", dhcp="false", gw="192.168.1.1"):
    return (f'<?xml version="1.0" encoding="UTF-8"?><ProbeMatch><Uuid>X</Uuid><Types>inquiry</Types><DeviceType>1</DeviceType>'
            f'<DeviceDescription>DS-2CD2143G2-I</DeviceDescription><DeviceSN>DS-2CD2143G2-I20230101AAWRL0000</DeviceSN><CommandPort>8000</CommandPort>'
            f'<HttpPort>80</HttpPort><MAC>{mac}</MAC><IPv4Address>{ip}</IPv4Address><IPv4SubnetMask>255.255.255.0</IPv4SubnetMask>'
            f'<IPv4Gateway>{gw}</IPv4Gateway><DHCP>{dhcp}</DHCP><SoftwareVersion>V5.7.3build 220112</SoftwareVersion><Activated>{act}</Activated></ProbeMatch>').encode()


def test_parsers():
    w = cc.parse_wsd(WSD, "192.168.1.64")
    assert w == {"ip": "192.168.1.64", "src": "192.168.1.64", "xaddrs": [("192.168.1.64", 80, "/onvif/device_service")],
                 "name": "HIKVISION DS-2CD2143G2-I", "hardware": "DS-2CD2143G2-I"}
    assert cc.parse_wsd(b"<nope/>", "1.2.3.4") is None and cc.parse_wsd(b"\xff" * 50000, "x") is None
    s = cc.parse_sadp(sadp())
    assert s["ip"] == "192.168.1.64" and s["mac"] == "44:19:b6:aa:01:07" and s["activated"] is False and s["dhcp"] is False
    assert s["model"] == "DS-2CD2143G2-I" and s["gw"] == "192.168.1.1" and s["fw"].startswith("V5.7.3")
    assert cc.parse_sadp(b"<Probe><Types>inquiry</Types></Probe>") is None and cc.parse_sadp(b"") is None
    t = cc.parse_onvif_time(onvif_time(NOW, "Manual"))
    assert t == {"utc": int(NOW), "ntp": False} and cc.parse_onvif_time(onvif_time(NOW))["ntp"] is True
    for bad in (b"", b"HTTP/1.1 401 Unauthorized\r\n\r\n", b"<UTCDateTime><Year>99999</Year></UTCDateTime>", b"<tt:UTCDateTime>" + b"x" * 40000):
        assert cc.parse_onvif_time(bad) is None
    assert cc.parse_rtsp(b'RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\nWWW-Authenticate: Digest realm="x"\r\n\r\n') == {"code": 401, "auth": True, "codec": ""}
    assert cc.parse_rtsp(b"RTSP/1.0 200 OK\r\n\r\nv=0\r\na=rtpmap:96 HEVC/90000\r\n") == {"code": 200, "auth": False, "codec": "H265"}
    assert cc.parse_rtsp(b"HTTP/1.1 200 OK\r\n\r\n") is None and cc.parse_rtsp(b"") is None


def test_requests_never_carry_credentials():
    for req in (cc.rtsp_request("192.168.1.64", 554, "OPTIONS"), cc.rtsp_request("192.168.1.64", 554, "DESCRIBE", 2),
                cc.onvif_time_request("192.168.1.64", 80), cc.wsd_probe(), cc.sadp_probe()):
        low = req.lower()
        assert b"authorization" not in low and b"password" not in low and b"usernametoken" not in low and b"admin" not in low
    assert b"GetSystemDateAndTime" in cc.onvif_time_request("10.0.0.5", 8000) and b"<Types>inquiry</Types>" in cc.sadp_probe()
    assert cc.rtsp_request("10.0.0.5", 554).startswith(b"OPTIONS rtsp://10.0.0.5:554/ RTSP/1.0\r\nCSeq: 1\r\n")


class Net:
    """Ψεύτικο δίκτυο: καταγράφει ΚΑΘΕ στόχο που αγγίζουμε."""
    def __init__(self, **kw):
        self.kw, self.touched = kw, []

    def local(self):
        return {"ip": "10.20.0.23", "prefix": 24, "gateway": "10.20.0.1"}

    def ping(self, ip):
        self.touched.append(ip)
        return self.kw.get("ping", {"ok": True, "loss": 0.0, "ms": 1.0, "err": None})

    def arp_macs(self, ip):
        self.touched.append(ip)
        return self.kw.get("arp", ["aa:bb:cc:00:00:01"])

    def onvif_time(self, ip, port, path):
        self.touched.append(ip)
        return self.kw.get("time", onvif_time(NOW))

    def rtsp(self, ip, port, method):
        self.touched.append(ip)
        if port != 554:
            return None
        return self.kw.get("describe" if method == "DESCRIBE" else "options", b'RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm="x"\r\n\r\n'
                           if method == "DESCRIBE" else b"RTSP/1.0 200 OK\r\nPublic: OPTIONS\r\n\r\n")

    def discover_onvif(self):
        return self.kw.get("wsd", [])

    def discover_sadp(self):
        return self.kw.get("sadp", [])


def checks(r):
    return {c["id"]: c["status"] for c in r["checks"]}


def mk(net, **kw):
    return cc.CamCheck(None, clock=lambda: NOW, net=net, **kw)


def test_healthy_camera_passes():
    r = mk(Net()).check_one("10.20.0.101")
    assert r["level"] == "pass" and checks(r) == {"ping": "pass", "conflict": "pass", "clock": "pass", "rtsp": "pass"}


def test_each_failure_mode():
    assert checks(mk(Net(arp=["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"])).check_one("10.20.0.101"))["conflict"] == "fail"
    assert checks(mk(Net(arp=None)).check_one("10.20.0.101"))["conflict"] == "skip"         # χωρίς root: δεν «περνάει» ψευδώς
    assert checks(mk(Net(ping={"ok": False, "loss": 100.0, "ms": None, "err": None})).check_one("10.20.0.101"))["ping"] == "fail"
    assert checks(mk(Net(ping={"ok": True, "loss": 2.0, "ms": 3.0, "err": None})).check_one("10.20.0.101"))["ping"] == "warn"
    assert checks(mk(Net(ping={"ok": True, "loss": 20.0, "ms": 3.0, "err": None})).check_one("10.20.0.101"))["ping"] == "fail"
    assert checks(mk(Net(ping={"ok": False, "err": "noping"})).check_one("10.20.0.101"))["ping"] == "skip"
    r = mk(Net(time=onvif_time(NOW - 3 * 3600, "Manual"))).check_one("10.20.0.101")
    assert checks(r)["clock"] == "fail" and checks(r)["ntp"] == "warn" and "3 ώρες πίσω" in [c for c in r["checks"] if c["id"] == "clock"][0]["el"]
    assert checks(mk(Net(time=onvif_time(NOW + 45))).check_one("10.20.0.101"))["clock"] == "warn"
    assert checks(mk(Net(time=b"HTTP/1.1 401 Unauthorized\r\n\r\n")).check_one("10.20.0.101"))["clock"] == "skip"
    r = mk(Net(describe=b"RTSP/1.0 200 OK\r\n\r\na=rtpmap:96 H264/90000\r\n")).check_one("10.20.0.101")
    assert checks(r)["rtsp"] == "fail" and r["level"] == "fail"
    assert checks(mk(Net(options=b"", describe=b"")).check_one("10.20.0.101"))["rtsp"] == "warn"
    # εργοστασιακή IP, DHCP, λάθος πύλη, μη ενεργοποιημένη (από το SADP)
    r = mk(Net()).check_one("192.168.1.64", found={"dhcp": True, "gw": "192.168.1.1", "activated": False})
    c = checks(r)
    assert c["factory"] == "warn" and c["dhcp"] == "warn" and c["gw"] == "warn" and c["active"] == "fail"


def test_private_targets_only():
    net = Net()
    c = mk(net)
    for bad in ("8.8.8.8", "1.1.1.1", "169.254.1.5", "127.0.0.1", "224.0.0.1", "fe80::1", "example.com", "", None, "10.0.0.1; id"):
        assert c.add(bad).get("error"), bad
        assert c.check_one(bad)["level"] == "fail"
    assert net.touched == [] and c.cams == {}
    assert c.api("POST", "add", {}, {"ip": "8.8.8.8"})[0] == 400
    assert c.add("10.20.0.101", "Είσοδος\x00<b>")["ok"] and "\x00" not in c.cams["10.20.0.101"]["name"]
    # απάντηση ανακάλυψης που δείχνει σε δημόσια IP αγνοείται
    c2 = mk(Net(sadp=[(sadp(ip="8.8.8.8"), "8.8.8.8")], wsd=[(WSD.replace(b"192.168.1.64", b"8.8.4.4"), "8.8.4.4")]))
    assert c2.discover() == [] and c2.cams == {}


def test_discovery_finds_conflicts_and_wrong_subnet():
    net = Net(sadp=[(sadp(mac="44-19-b6-aa-01-07"), "192.168.1.64"), (sadp(mac="44-19-b6-aa-01-08"), "192.168.1.64"),
                    (sadp(ip="10.20.0.110", mac="44-19-b6-aa-01-09", act="true", gw="10.20.0.1"), "10.20.0.110")],
              wsd=[(WSD.replace(b"192.168.1.64", b"10.20.0.111"), "10.20.0.111")])
    c = mk(net)
    c.discover()
    v = c.view()
    assert {x["ip"] for x in v["stray"]} == {"192.168.1.64"} and len(v["stray"]) == 2 and v["stray"][0]["factory"] == "Hikvision"
    assert v["conflicts"] == [{"ip": "192.168.1.64", "macs": ["44:19:b6:aa:01:07", "44:19:b6:aa:01:08"], "why": "discovery"}]
    assert sorted(c.cams) == ["10.20.0.110", "10.20.0.111"]            # οι εκτός subnet δεν μπαίνουν στη λίστα ελέγχου
    assert c.cams["10.20.0.110"]["model"] == "DS-2CD2143G2-I" and c.cams["10.20.0.111"]["name"] == "HIKVISION DS-2CD2143G2-I"


def test_run_persists_and_reports(tmp_path):
    net = Net(arp=["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"])
    c = cc.CamCheck(None, str(tmp_path), clock=lambda: NOW, net=net)
    c.add("10.20.0.101", "<script>alert(1)</script>")
    c.busy = True
    c.run()
    v = c.view()
    assert v["busy"] is False and v["counts"] == {"total": 1, "pass": 0, "warn": 0, "fail": 1, "pending": 0} and v["scanned"] == NOW
    assert v["conflicts"][0]["ip"] == "10.20.0.101" and v["conflicts"][0]["why"] == "arp"
    c2 = cc.CamCheck(None, str(tmp_path), clock=lambda: NOW, net=net)
    assert c2.view()["cams"][0]["result"]["level"] == "fail"
    code, doc = c2.api("GET", "report", {"lang": "en"}, {})
    html = doc["_raw"].decode()
    assert code == 200 and "<script" not in html and "&lt;script&gt;" in html and "TWO devices answer" in html and "never tries passwords" in html
    assert c2.api("GET", "csv", {}, {})[1]["_raw"].decode().splitlines()[1].startswith("10.20.0.101,")
    assert c2.api("POST", "remove", {}, {"ip": "10.20.0.101"})[1]["cams"] == [] and c2.api("POST", "x", {}, {})[0] == 404


def test_module_error_does_not_stick_busy():
    class Boom(Net):
        def ping(self, ip):
            raise RuntimeError("x")
    c = mk(Boom())
    c.add("10.20.0.101")
    c.busy = True
    c.run()
    assert c.busy is False and c.view()["cams"][0]["result"]["checks"][0]["id"] == "error"


def test_demo_is_rich_and_read_only():
    c = cc.CamCheck(None, demo=True)
    v = c.view()
    assert v["demo"] and v["counts"]["total"] == 6 and v["counts"]["fail"] == 2 and v["counts"]["warn"] == 1 and len(v["stray"]) == 2 and v["conflicts"]
    assert c.api("POST", "run", {}, {})[1]["busy"] is False and len(c.api("POST", "remove", {}, {"ip": "10.20.0.101"})[1]["cams"]) == 6
    assert "Φύλλο παράδοσης καμερών" in c.report("el")


def test_utc_helper_matches_calendar():
    assert cc.parse_onvif_time(onvif_time(calendar.timegm((2026, 11, 23, 9, 30, 0))))["utc"] == calendar.timegm((2026, 11, 23, 9, 30, 0))


# ───────────────────────── 👁 στιγμιότυπο με κωδικό που δίνει ο χρήστης ─────────────────────────
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 300
DIG = 'Digest realm="IP Camera", qop="auth", nonce="abc123", opaque="op"'


class Web(Net):
    """Ψεύτικη κάμερα: καταγράφει κάθε αίτημα και αν είχε Authorization."""
    def __init__(self, pages, **kw):
        super().__init__(**kw)
        self.pages, self.calls, self.ports = pages, [], []

    def http_get(self, ip, scheme, path, auth=None, port=None):
        self.calls.append((scheme, path, auth))
        if port:
            self.ports.append(port)
        f = self.pages.get((scheme, path) if not port else (scheme, path, port))
        return f(auth) if f else ((404, "", b"") if any(k[0] == scheme for k in self.pages) else None)


def cam_with(web, vendor="Hikvision"):
    c = mk(web)
    c.add("10.20.0.101", "Είσοδος", vendor=vendor)
    return c


def test_digest_matches_rfc2617_example():
    ch = cc.parse_challenge('Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
                            'opaque="5ccc069c403ebaf9f0171e9517f40e41"')
    h = cc.digest_header("Mufasa", "Circle Of Life", "GET", "/dir/index.html", ch["digest"], cnonce="0a4f113b")
    assert 'response="6629fae49393a05397450978507c4ef1"' in h and 'nc=00000001' in h and "Circle" not in h
    assert cc.digest_header("u", "p", "GET", "/", dict(ch["digest"], algorithm="MD5-sess")) is None
    assert cc.parse_challenge('Basic realm="x"') == {"digest": None, "basic": True}
    assert cc.parse_challenge("") == {"digest": None, "basic": False}


def test_snapshot_digest_one_attempt_and_no_password_leak():
    hik = "/ISAPI/Streaming/channels/101/picture"
    web = Web({("http", hik): lambda a: (200, "", JPEG) if a and a.startswith("Digest ") and 'username="admin"' in a else (401, DIG, b"")})
    c = cam_with(web)
    r = c.snapshot("10.20.0.101", "admin", "S3cret!pass")
    assert r["ok"] and r["img"].startswith("data:image/jpeg;base64,") and r["via"] == "http" and r["open"] is False
    with_auth = [x for x in web.calls if x[2]]
    assert len(with_auth) == 1 and with_auth[0][:2] == ("http", hik)        # ΜΙΑ προσπάθεια, μόνο στη διεύθυνση που ζήτησε κωδικό
    assert "S3cret!pass" not in repr(web.calls) and "S3cret!pass" not in repr(c.view()) and "S3cret!pass" not in repr(r)
    assert web.calls[0][1] == hik                                            # η μάρκα καθορίζει ποια διεύθυνση δοκιμάζεται πρώτη


def test_snapshot_wrong_password_stops_immediately():
    web = Web({("http", "/cgi-bin/snapshot.cgi?channel=1"): lambda a: (401, DIG, b"")})
    c = cam_with(web, vendor="Dahua")
    r = c.snapshot("10.20.0.101", "admin", "wrong")
    assert "Λάθος όνομα ή κωδικός" in r["error"] and len([x for x in web.calls if x[2]]) == 1
    # χωρίς στοιχεία: καμία προσπάθεια σύνδεσης
    web.calls.clear()
    assert "ζητά όνομα" in c.snapshot("10.20.0.101", "", "")["error"] and not [x for x in web.calls if x[2]]


def test_snapshot_refuses_basic_over_plain_http_unless_allowed():
    page = lambda a: (200, "", JPEG) if a == "Basic YWRtaW46cHc=" else (401, 'Basic realm="cam"', b"")  # noqa: E731
    web = Web({("http", "/snap.jpg"): page})
    c = cam_with(web, vendor="")
    r = c.snapshot("10.20.0.101", "admin", "pw")
    assert r.get("need_basic") and "χωρίς κρυπτογράφηση" in r["error"] and not [x for x in web.calls if x[2]]   # ο κωδικός ΔΕΝ στάλθηκε
    assert c.snapshot("10.20.0.101", "admin", "pw", allow_basic=True)["ok"]
    # μέσα από HTTPS το Basic επιτρέπεται χωρίς ερώτηση
    web2 = Web({("https", "/snap.jpg"): page})
    assert cam_with(web2, vendor="").snapshot("10.20.0.101", "admin", "pw")["ok"] and web2.calls[-1][0] == "https"


def test_snapshot_open_camera_and_guards():
    web = Web({("http", "/snap.jpg"): lambda a: (200, "", JPEG)})
    c = cam_with(web, vendor="")
    r = c.snapshot("10.20.0.101", "", "")
    assert r["ok"] and r["open"] is True and not [x for x in web.calls if x[2]]      # εικόνα χωρίς κωδικό → το λέμε
    assert c.snapshot("10.20.0.99", "a", "b")["error"]                                 # όχι στη λίστα
    assert c.snapshot("8.8.8.8", "a", "b")["error"] and c.snapshot("10.20.0.101", "a", "b", path="http://evil/x")["error"]
    assert c.snapshot("10.20.0.101", "a", "b", path="/../../etc/passwd\n")["error"]
    # όχι εικόνα / τεράστια απάντηση / καμία γνωστή διεύθυνση
    assert "όχι με εικόνα" in cam_with(Web({("http", "/snap.jpg"): lambda a: (200, "", b"<html>") if a else (401, DIG, b"")}), "").snapshot("10.20.0.101", "a", "b")["error"]
    big = Web({("http", "/snap.jpg"): lambda a: (200, "", JPEG + b"\x00" * cc.MAX_JPEG)})
    assert "πολύ μεγάλη" in cam_with(big, "").snapshot("10.20.0.101", "", "")["error"]
    assert "Δεν βρήκα" in cam_with(Web({("http", "/x"): lambda a: (404, "", b"")}), "").snapshot("10.20.0.101", "a", "b")["error"]
    code, r = c.api("POST", "snapshot", {}, {"ip": "10.20.0.99"})
    assert code == 400 and r["error_en"]


def test_snapshot_demo_needs_no_credentials():
    c = cc.CamCheck(None, demo=True)
    code, r = c.api("POST", "snapshot", {}, {"ip": "10.20.0.101"})
    assert code == 200 and r["img"].startswith("data:image/svg+xml;base64,") and r["via"] == "demo"


def test_real_ping_is_slow_enough_for_icmp_rate_limits(monkeypatch):
    """Πραγματικό NVR (TVT) έδειχνε 40–70% «απώλεια» με ping ανά 0,2″ και 0% με ανά 1″: περιορίζει το ICMP."""
    import changecheck
    seen = {}
    monkeypatch.setattr(changecheck, "ping", lambda ip, **kw: seen.update(kw) or {"ok": True, "loss_pct": 0.0, "avg": 6.0, "err": None})
    assert cc.RealNet().ping("192.168.1.100") == {"ok": True, "loss": 0.0, "ms": 6.0, "err": None}
    assert seen["interval"] >= 1.0 and seen["count"] >= 4


def test_snapshot_uses_web_port_announced_by_the_device():
    """Πραγματικό καταγραφικό είχε το web UI στην 8000 (όχι 80/443) — η θύρα έρχεται από το ONVIF XAddr."""
    wsd = WSD.replace(b"http://192.168.1.64/onvif", b"http://10.20.0.150:8000/onvif")
    web = Web({("http", "/snap.jpg", 8000): lambda a: (200, "", JPEG)}, wsd=[(wsd, "10.20.0.150")])
    c = mk(web)
    c.discover()
    assert c.cams["10.20.0.150"]["web"] == 8000
    assert c.snapshot("10.20.0.150", "", "")["ok"] and 8000 in web.ports
