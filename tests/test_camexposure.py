import camexposure as cx


# ── fixtures: raw banners (όπως θα τα διάβαζε το probe) ──
HTTP_OPEN = b"HTTP/1.1 200 OK\r\nServer: uc-httpd 1.0.0\r\n\r\n<html><title>WEB SERVICE</title></html>"
HTTP_AUTH = b'HTTP/1.1 401 Unauthorized\r\nServer: webserver\r\nWWW-Authenticate: Digest realm="Hikvision"\r\n\r\n'
HTTP_REDIR = b"HTTP/1.1 301 Moved Permanently\r\nServer: webserver\r\nLocation: https://x/\r\n\r\n"
RTSP_OPEN = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Rtsp Server\r\nPublic: OPTIONS, DESCRIBE, PLAY\r\n\r\n"
RTSP_AUTH = b'RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: Rtsp Server\r\nWWW-Authenticate: Digest realm="ONVIF"\r\n\r\n'


class St:
    """Ψεύτικο state: καταγράφει alerts και εκθέτει hosts."""
    def __init__(self, hosts=None):
        self.alerts = []
        self.hosts = hosts or {}

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append({"typ": typ, "sev": sev, "actor": actor, "target": target,
                            "mark": kw.get("mark"), "key": kw.get("key"), "cooldown": kw.get("cooldown")})


# ── ΣΚΛΗΡΟΣ ΚΑΝΟΝΑΣ: δημόσιες IP δεν αγγίζονται ποτέ ──
def test_public_ip_never_probed():
    assert cx.is_private("192.168.1.10") and cx.is_private("10.0.0.5") and cx.is_private("172.16.3.9")
    assert not cx.is_private("8.8.8.8") and not cx.is_private("203.0.113.5")

    calls = []

    def conn(ip, port):
        calls.append((ip, port))
        return HTTP_OPEN

    res = cx.probe_host("8.8.8.8", _conn=conn)
    assert res["skipped"] is True and res["reason"] == "public" and res["ports"] == {}
    assert calls == []  # το _conn δεν κλήθηκε ΠΟΤΕ για δημόσια IP


def test_scan_skips_public_target():
    st = St(hosts={"8.8.8.8": {"kind": "public"}})
    cam = cx.CamExposure(st, {"subnet": None}, sim=False)
    # στόχοι χειροκίνητα: ένας ιδιωτικός (κλειστός) + μία δημόσια
    cam.subnet_cfg = None
    seen = []

    def conn(ip, port):
        seen.append(ip)
        return None

    # δοκιμάζουμε απευθείας probe_host στη δημόσια
    assert cx.probe_host("203.0.113.9", _conn=conn)["skipped"]
    assert "203.0.113.9" not in seen


# ── parsing ──
def test_parse_http():
    p = cx.parse_http(HTTP_OPEN)
    assert p["status"] == 200 and p["auth"] is False and p["title"] == "WEB SERVICE"
    assert "uc-httpd" in p["server"]
    a = cx.parse_http(HTTP_AUTH)
    assert a["status"] == 401 and a["auth"] is True and a["realm"] == "Hikvision"
    r = cx.parse_http(HTTP_REDIR)
    assert r["status"] == 301 and r["location"] == "https://x/"


def test_parse_rtsp():
    o = cx.parse_rtsp(RTSP_OPEN)
    assert o["status"] == 200 and o["auth"] is False and "OPTIONS" in o["public"]
    a = cx.parse_rtsp(RTSP_AUTH)
    assert a["status"] == 401 and a["auth"] is True


# ── vendor ──
def test_vendor_detection():
    f = {80: cx._finding(80, HTTP_OPEN, None)}
    assert cx.detect_vendor(f) == "Dahua"  # uc-httpd
    f = {443: cx._finding(443, HTTP_AUTH, None)}
    assert cx.detect_vendor(f) == "Hikvision"  # realm
    f = {554: cx._finding(554, RTSP_AUTH, None)}
    assert cx.detect_vendor(f) == "Γενική ONVIF κάμερα"
    # αποτύπωμα θύρας όταν δεν μιλάει το banner
    f = {37777: cx._finding(37777, b"", None)}
    assert cx.detect_vendor(f) == "Dahua"


# ── ετυμηγορία ──
def test_verdict_red_http_no_auth():
    f = {80: cx._finding(80, HTTP_OPEN, None)}
    v, issues, fixes, no_auth = cx.verdict(f)
    assert v == "red" and no_auth is True and issues and fixes


def test_verdict_red_rtsp_no_auth():
    f = {554: cx._finding(554, RTSP_OPEN, None)}
    v, _i, _fx, no_auth = cx.verdict(f)
    assert v == "red" and no_auth is True


def test_verdict_orange_plain_http_auth():
    f = {80: cx._finding(80, HTTP_AUTH, None)}  # απλό HTTP αλλά με auth
    v, _i, _fx, no_auth = cx.verdict(f)
    assert v == "orange" and no_auth is False


def test_verdict_orange_old_tls():
    f = {443: cx._finding(443, HTTP_AUTH, "TLSv1")}
    v, _i, _fx, _n = cx.verdict(f)
    assert v == "orange"


def test_verdict_green_https_auth():
    f = {443: cx._finding(443, HTTP_AUTH, "TLSv1.2")}
    v, _i, _fx, no_auth = cx.verdict(f)
    assert v == "green" and no_auth is False


def test_redirect_http_not_orange():
    # σκέτη ανακατεύθυνση HTTP→HTTPS δεν «χρεώνεται» ως απλό HTTP
    f = {80: cx._finding(80, HTTP_REDIR, None), 443: cx._finding(443, HTTP_AUTH, "TLSv1.2")}
    v, _i, _fx, _n = cx.verdict(f)
    assert v == "green"


# ── no-login invariant: κανένα credential δεν φεύγει ποτέ ──
def test_no_login_invariant():
    for data in (cx.http_request("1.2.3.4", "GET"), cx.http_request("1.2.3.4", "HEAD"),
                 cx.rtsp_request("1.2.3.4", 554)):
        low = data.lower()
        assert b"authorization" not in low
        assert b"password" not in low and b"passwd" not in low
        assert b"admin" not in low and b"12345" not in low


def test_probe_sends_no_credentials():
    sent = []

    class FakeSock:
        def settimeout(self, *a):
            pass

        def sendall(self, b):
            sent.append(b)

        def recv(self, n):
            return b""

        def close(self):
            pass

    # Παρακολουθούμε τι στέλνει το _grab μέσω μιας εικονικής σύνδεσης
    import socket as _s
    orig = _s.create_connection
    _s.create_connection = lambda *a, **k: FakeSock()
    try:
        cx._grab("192.168.1.50", 80, "http", 1)
        cx._grab("192.168.1.50", 554, "rtsp", 1)
    finally:
        _s.create_connection = orig
    blob = b"".join(sent).lower()
    assert b"authorization" not in blob and b"password" not in blob and b"12345" not in blob


# ── sim: σχήμα και ετυμηγορίες ──
def test_sim_shape_and_verdicts():
    cam = cx.CamExposure(None, {}, sim=True)
    cam.scan()
    st = cam.status()
    assert st["demo"] is True and st["enabled"] is True
    for k in ("enabled", "demo", "error", "scanning", "last_scan", "subnet", "cameras",
              "skipped_public", "summary"):
        assert k in st
    by_ip = {c["ip"]: c for c in st["cameras"]}
    assert by_ip["192.168.1.64"]["verdict"] == "green"
    assert by_ip["192.168.1.108"]["verdict"] == "red"
    assert by_ip["192.168.1.70"]["verdict"] == "orange"
    assert st["summary"] == {"red": 1, "orange": 1, "green": 1}
    # ο φραγμός δημόσιων IP φαίνεται
    assert cx.SIM_PUBLIC_SKIPPED in st["skipped_public"]
    # δομή θύρας / vendor
    dahua = by_ip["192.168.1.108"]
    assert dahua["vendor"] and dahua["issues"] and dahua["fixes"]
    port = next(p for p in dahua["ports"] if p["port"] == 80)
    assert set(port) >= {"port", "label", "open", "banner", "server", "auth", "note"}


# ── alert: μόνο για τον RED host, live ──
def test_alert_only_for_red_live():
    st = St()
    cam = cx.CamExposure(st, {"enabled": True}, sim=False)
    results = {
        "192.168.1.108": {"verdict": "red", "no_auth_open": True, "vendor": "Dahua",
                          "issues": ["ανοιχτό"], "fixes": [], "ports": {}},
        "192.168.1.70": {"verdict": "orange", "no_auth_open": False, "vendor": "ONVIF",
                         "issues": [], "fixes": [], "ports": {}},
        "192.168.1.64": {"verdict": "green", "no_auth_open": False, "vendor": "Hikvision",
                         "issues": [], "fixes": [], "ports": {}},
    }
    cam._maybe_alert(results, now=1000.0)
    assert len(st.alerts) == 1
    a = st.alerts[0]
    assert a["actor"] == "192.168.1.108" and a["sev"] == "high"
    assert a["typ"] == "Κάμερα εκτεθειμένη στο δίκτυο"
    assert a["mark"] is False and a["cooldown"] == 6 * 3600 and a["key"] == ("cam-exposed", "192.168.1.108")


def test_no_alert_in_sim():
    st = St()
    cam = cx.CamExposure(st, {}, sim=True)
    cam.scan()
    assert st.alerts == []


def test_alert_med_when_auth_but_red():
    st = St()
    cam = cx.CamExposure(st, {}, sim=False)
    results = {"192.168.1.108": {"verdict": "red", "no_auth_open": False, "vendor": "X",
                                 "issues": ["x"], "fixes": [], "ports": {}}}
    cam._maybe_alert(results, now=1.0)
    assert st.alerts[0]["sev"] == "med"


# ── known cameras από το state.hosts (χωρίς scan) ──
def test_known_cameras_from_state():
    hosts = {"192.168.1.90": {"kind": "local", "names": {"hikvision-cam"}, "mac": None,
                              "ports": {80: 1}, "gw": False, "me": False, "rdns": None}}
    st = St(hosts=hosts)
    cam = cx.CamExposure(st, {}, sim=False)
    status = cam.status()
    ips = [c["ip"] for c in status["cameras"]]
    assert "192.168.1.90" in ips
    row = next(c for c in status["cameras"] if c["ip"] == "192.168.1.90")
    assert row["verdict"] == "unknown"  # δεν έχει σαρωθεί ακόμη
