import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import upnpwatch as u  # noqa: E402

DESC = b"""<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceList><device><deviceList><device>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></deviceList></device></root>"""


def entry(ext, client, proto="TCP", inte=None, desc="x"):
    return (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
            f'<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
            f'<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort><NewProtocol>{proto}</NewProtocol>'
            f'<NewInternalPort>{inte or ext}</NewInternalPort><NewInternalClient>{client}</NewInternalClient>'
            f'<NewEnabled>1</NewEnabled><NewPortMappingDescription>{desc}</NewPortMappingDescription>'
            f'<NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>').encode()


class FakeNet:
    def __init__(self, entries, responders=None):
        self.entries = entries
        self.responders = responders if responders is not None else [("192.168.1.1", b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\nSERVER: MiniUPnPd/2.1\r\n\r\n")]
        self.calls = []

    def discover(self, timeout=3.0):
        return self.responders

    def get(self, url):
        self.calls.append(("GET", url))
        return 200, DESC

    def soap(self, url, service, action, args):
        self.calls.append((action, url, args))
        i = args["NewPortMappingIndex"]
        return (200, self.entries[i]) if i < len(self.entries) else (500, b"<err>713</err>")


class State:
    gateway = "192.168.1.1"

    def __init__(self):
        self.hosts = {"192.168.1.30": {"ip": "192.168.1.30", "kind": "local", "names": {"ipcam.local"}},
                      "192.168.1.50": {"ip": "192.168.1.50", "kind": "local", "names": {"ps5.local"}}}
        self.alerts = []

    def _dtype(self, h):
        return {"dtype": "camera" if h["ip"].endswith(".30") else "console"}

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target, detail))


def test_reads_table_read_only_and_classifies():
    net = FakeNet([entry(554, "192.168.1.30"), entry(3074, "192.168.1.50", "UDP")])
    w = u.UpnpWatch(State(), net=net, clock=lambda: 1000.0)
    v = w.refresh()
    assert v["router"] == "192.168.1.1" and v["service"] == "WANIPConnection:1"
    assert [m["level"] for m in v["mappings"]] == ["high", "low"]
    assert v["mappings"][0]["anyone"] is True
    actions = {c[0] for c in net.calls}
    assert actions <= {"GET", "GetGenericPortMappingEntry"}  # ποτέ Add/Delete
    assert all(c[1].startswith("http://192.168.1.1:5000/") for c in net.calls)


def test_first_scan_alerts_only_high_then_new_ones():
    st = State()
    net = FakeNet([entry(554, "192.168.1.30"), entry(3074, "192.168.1.50", "UDP")])
    w = u.UpnpWatch(st, net=net, clock=lambda: 1000.0)
    w.refresh()
    assert [(a[1], a[2]) for a in st.alerts] == [("high", "192.168.1.30")]
    w.refresh()
    assert len(st.alerts) == 1  # τίποτα νέο
    net.entries.append(entry(51413, "192.168.1.50", "UDP"))
    w.refresh()
    assert len(st.alerts) == 2 and st.alerts[-1][1] == "low" and "51413" in st.alerts[-1][3]


def test_known_persisted(tmp_path):
    st = State()
    net = FakeNet([entry(554, "192.168.1.30")])
    u.UpnpWatch(st, str(tmp_path), net=net).refresh()
    st2 = State()
    u.UpnpWatch(st2, str(tmp_path), net=net).refresh()
    assert len(st.alerts) == 1 and st2.alerts == []


def test_rejects_public_responder_and_foreign_location():
    net = FakeNet([], responders=[
        ("8.8.8.8", b"HTTP/1.1 200 OK\r\nLOCATION: http://8.8.8.8/d.xml\r\n\r\n"),
        ("192.168.1.1", b"HTTP/1.1 200 OK\r\nLOCATION: http://10.9.9.9/d.xml\r\n\r\n")])
    v = u.UpnpWatch(State(), net=net).refresh()
    assert v["router"] is None and net.calls == []


def test_control_url_must_stay_on_same_host():
    evil = DESC.replace(b"/ctl/IPConn", b"http://10.0.0.5/ctl")
    assert u.control_url(evil, "http://192.168.1.1:5000/rootDesc.xml") is None
    assert u.control_url(DESC, "http://192.168.1.1:5000/rootDesc.xml")[1] == "http://192.168.1.1:5000/ctl/IPConn"


def test_xml_doctype_rejected():
    bomb = b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa">]><root>&a;</root>'
    try:
        u._safe_xml(bomb)
    except ValueError:
        pass
    else:
        raise AssertionError("DOCTYPE accepted")


def test_risk_levels():
    assert u.risk({"int": 23, "ext": 23}, {"dtype": "pc"})[0] == "high"
    assert u.risk({"int": 8080, "ext": 8080}, {"dtype": "pc"})[0] == "med"
    assert u.risk({"int": 9999, "ext": 9999}, None)[0] == "med"
    assert u.risk({"int": 9999, "ext": 9999}, {"dtype": "iot"})[0] == "med"
    assert u.risk({"int": 3074, "ext": 3074}, {"dtype": "console"})[0] == "low"


def test_no_router():
    v = u.UpnpWatch(State(), net=FakeNet([], responders=[])).refresh()
    assert v["router"] is None and v["mappings"] == [] and v["scanned"]


def test_demo():
    w = u.UpnpWatch(None, demo=True)
    v = w.refresh()
    assert v["demo"] and v["router"] == "192.168.1.1" and len(v["mappings"]) == 5
