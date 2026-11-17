import report
from storage import History


class St:
    mode = "live"
    iot = mqtt = baseline = None

    def __init__(self):
        self.history = History(":memory:")

    def audit(self):
        return {"score": 71, "grade": "C", "checks": [{"status": "bad", "title": "Telnet <ανοιχτό>", "advice": "Κλείσ' το"},
                                                      {"status": "ok", "title": "ok", "advice": ""}]}


def test_report_contents_and_escaping():
    st = St()
    now = 1_800_000_000
    st.history.add_alert({"t": now - 3600, "type": "Port scan", "sev": "high", "actor": "192.168.1.66", "target": "x",
                          "detail": "<script>", "mitre": None}, "live")
    st.history.device_seen("24:ec:4a:cb:05:d8", "192.168.1.20", now - 7200)
    h = report.build(st, days=7, now=now)
    assert "71" in h and "Port scan" in h and "192.168.1.66" in h and "24:ec:4a:cb:05:d8" in h
    assert "Telnet &lt;ανοιχτό&gt;" in h and "<script>" not in h
    assert "Τι να κάνεις" in h
