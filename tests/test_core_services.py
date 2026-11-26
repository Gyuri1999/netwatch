"""Ονόματα και κίνδυνος γνωστών θυρών."""
import core


def test_pptp_is_named_and_flagged():
    assert core.SERVICES[1723] == "PPTP" and core.SERVICES[1701] == "L2TP"
    sev, why = core.RISKY_SERVICES[1723]
    assert sev == "med" and "PPTP" in why
