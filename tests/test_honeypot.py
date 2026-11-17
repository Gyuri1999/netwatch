import socket
import time

import honeypot



def test_clean():
    assert honeypot.clean(b"root\r\nxc3511\x00\r\n") == "root ⏎ xc3511·"


def test_real_listener_records_hit(monkeypatch):
    hits = []
    monkeypatch.setitem(honeypot.SERVICES, 23999, ("Test", b"hello\r\n", "test"))
    hp = honeypot.Honeypot(hits.append, bind="127.0.0.1")
    st = hp.start([23999])
    assert st["listening"] == [23999] and st["running"]
    c = socket.create_connection(("127.0.0.1", 23999), timeout=2)
    assert c.recv(16) == b"hello\r\n"
    c.sendall(b"admin admin\n")
    c.close()
    for _ in range(50):
        if hits:
            break
        time.sleep(0.05)
    hp.stop()
    assert hits and hits[0]["data"] == "admin admin" and hits[0]["self"] and hits[0]["port"] == 23999
    assert not hp.status()["running"]


def test_unknown_ports_ignored_and_demo():
    hits = []
    hp = honeypot.Honeypot(hits.append, sim=True)
    st = hp.start([1, 2323, 99999])
    assert st["ports"] == [2323] and st["running"]
    hp._demo_hit()
    assert hits[0]["ip"] == "192.168.1.66" and "xc3511" in hits[0]["data"]
