import socket
import threading

import health


class St:
    def __init__(self):
        self.alerts = []

    def alert(self, typ, sev, actor, target, detail, t, **kw):
        self.alerts.append((typ, sev, actor, target))


def test_normalize_and_auto_dedup():
    t = health.normalize([{"name": "HA", "url": "https://192.168.1.30:8123/"}, {"host": "192.168.1.17", "port": 1883},
                          {"url": "ftp://x"}, {"name": "nothing"}],
                         auto=[{"name": "MQTT broker", "host": "192.168.1.17", "port": 1883}, {"name": "Router", "host": "192.168.1.1", "ping": True}])
    assert [(x["name"], x["kind"]) for x in t] == [("HA", "http"), ("192.168.1.17", "tcp"), ("Router", "ping")]
    assert t[0]["tls"] and t[0]["port"] == 8123


def test_down_after_two_fails_then_back():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    def serve():
        try:
            while True:
                srv.accept()[0].close()
        except OSError:  # το socket έκλεισε στο τέλος του test
            pass
    threading.Thread(target=serve, daemon=True).start()
    st = St()
    h = health.Health(st, [{"name": "svc", "host": "127.0.0.1", "port": port}])
    h.round(now=100)
    assert h.status()["targets"][0]["up"] is True and h.status()["targets"][0]["ms"] is not None
    h.targets[0]["port"] = 9  # κλειστή
    h.round(now=160)
    assert st.alerts == []  # μία αποτυχία δεν αρκεί
    h.round(now=220)
    assert st.alerts[-1][:2] == ("Υπηρεσία εκτός", "med")
    h.targets[0]["port"] = port
    h.round(now=400)
    assert st.alerts[-1][0] == "Υπηρεσία επανήλθε" and h.status()["targets"][0]["hist"][-3:][0] is None
    srv.close()
    srv.close()


def test_demo_cert_warning():
    st = St()
    h = health.Health(st, [{"name": "Proxmox", "host": "192.168.1.16", "port": 8006, "tls": True}], sim=True)
    h.round()
    assert st.alerts and st.alerts[0][0] == "Πιστοποιητικό λήγει"
