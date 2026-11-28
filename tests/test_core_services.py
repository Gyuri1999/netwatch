"""Ονόματα και κίνδυνος γνωστών θυρών."""
import core


def test_pptp_is_named_and_flagged():
    assert core.SERVICES[1723] == "PPTP" and core.SERVICES[1701] == "L2TP"
    sev, why = core.RISKY_SERVICES[1723]
    assert sev == "med" and "PPTP" in why


def test_home_iot_and_printer_ports_have_names():
    """Βρέθηκαν live σε οικιακό δίκτυο ως «?»: 6668 σε 5 έξυπνες συσκευές, 515/631 στον εκτυπωτή."""
    for port, name in ((6668, "Tuya"), (515, "LPD"), (631, "IPP"), (9100, "JetDirect"), (554, "RTSP"), (1883, "MQTT")):
        assert core.SERVICES[port] == name
    assert core.RISKY_SERVICES[6668][0] == "low" and "Tuya" in core.RISKY_SERVICES[6668][1]
    assert core.RISKY_SERVICES[515][0] == "low"


def test_tuya_port_means_smart_device():
    import devtype
    assert devtype.classify(None, (), [6668])[0] == "iot"
    assert devtype.classify(None, (), [])[0] == "unknown"
