import apps

LSOF = """COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Google\\x20Chrome 501 me   23u  IPv4 0x1      0t0  TCP 192.168.1.23:52344->142.250.181.238:443 (ESTABLISHED)
Google\\x20Chrome 501 me   24u  IPv4 0x2      0t0  TCP 192.168.1.23:52345->142.250.181.238:443 (ESTABLISHED)
Spotify     600 me   30u  IPv6 0x3      0t0  TCP [2a00:1450::1]:5000->[2a00:1450:4001::200e]:443 (ESTABLISHED)
rapportd    300 me    4u  IPv4 0x4      0t0  TCP *:49152 (LISTEN)
Slack       700 me    9u  IPv4 0x5      0t0  TCP 127.0.0.1:5555->127.0.0.1:6666 (ESTABLISHED)
Mail        800 me    9u  IPv4 0x6      0t0  TCP 192.168.1.23:5000->17.42.251.41:993 (TIME_WAIT)
mDNSRespo   100 me    9u  IPv4 0x7      0t0  UDP 192.168.1.23:5353->224.0.0.251:5353
Discord     900 me    9u  IPv4 0x8      0t0  UDP 192.168.1.23:5000->162.159.135.232:50001
"""


def test_parse_lsof_conns():
    c = apps.parse_lsof_conns(LSOF)
    assert [(x["app"], x["ip"], x["port"]) for x in c] == [
        ("Google Chrome", "142.250.181.238", 443), ("Google Chrome", "142.250.181.238", 443),
        ("Spotify", "2a00:1450:4001::200e", 443), ("Discord", "162.159.135.232", 50001)]


def test_tracker_for():
    assert apps.tracker_for("www.google-analytics.com")["who"] == "Google Analytics"
    assert apps.tracker_for("stats.g.doubleclick.net.")["cat"] == "ads"
    assert apps.tracker_for("o1.ingest.sentry.io")["cat"] == "telemetry"
    assert apps.tracker_for("www.google.com") is None
    assert apps.tracker_for("notdoubleclick.net") is None  # μόνο ολόκληρα labels
    assert apps.tracker_for(None) is None


def test_summarize_groups_and_flags():
    c = apps.parse_lsof_conns(LSOF)
    res = apps.summarize(c, lambda ip: ["www.google-analytics.com"] if ip == "142.250.181.238" else [])
    chrome = res[0]
    assert chrome["app"] == "Google Chrome" and chrome["trackers"] == ["Google Analytics"]
    assert len(chrome["dests"]) == 1 and chrome["dests"][0]["n"] == 2


def test_demo_watcher():
    v = apps.Watcher(lambda ip: [], demo=True).view()
    assert v["demo"] and v["apps"][0]["trackers"] and v["cats"]["ads"] >= 1


def test_windows_connections_parsing():
    import apps
    sample = ("chrome\t4321\t142.250.185.78\t443\n"
              "spotify\t5000\t35.186.224.47\t443\n"
              "System\t4\t192.168.1.40\t445\n"
              "\t0\t127.0.0.1\t9000\n"      # loopback → αγνοείται
              "garbage line\n")
    c = apps.parse_win_conns(sample)
    assert [x["ip"] for x in c] == ["142.250.185.78", "35.186.224.47", "192.168.1.40"]
    assert c[0]["app"] == "chrome.exe" and c[0]["pid"] == 4321 and c[0]["local"] is False
    assert c[2]["local"] is True
    # η σύνοψη δέχεται τα ίδια dicts με το lsof path
    assert apps.summarize(c, lambda ip: None)
