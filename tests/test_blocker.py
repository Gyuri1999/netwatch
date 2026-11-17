import pytest

import blocker


def test_validate():
    assert blocker.validate(" 8.8.8.8 ") == "8.8.8.8"
    assert blocker.validate("2001:4860::8888") == "2001:4860::8888"
    for bad in ("nope", "127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1"):
        with pytest.raises(ValueError):
            blocker.validate(bad)
    with pytest.raises(ValueError, match="router"):
        blocker.validate("192.168.1.1", protect=["192.168.1.23", "192.168.1.1"])


def test_pf_rules():
    r = blocker.pf_rules({"5.6.7.8", "1.2.3.4"})
    assert "table <netwatch_block> persist { 1.2.3.4 5.6.7.8 }" in r
    assert "block drop in quick from <netwatch_block> to any" in r
    assert "block drop out quick from any to <netwatch_block>" in r
    assert blocker.pf_rules(set()).startswith("#")


def test_commands():
    mac = blocker.commands({"1.2.3.4"}, "darwin")
    assert "pfctl -a com.apple/netwatch -f /tmp/netwatch.pf" in mac[1] and mac[2] == "sudo pfctl -E"
    lin = blocker.commands({"1.2.3.4", "::5"}, "linux")
    assert "sudo iptables -I INPUT -s 1.2.3.4 -j DROP -m comment --comment netwatch" in lin
    assert any(c.startswith("sudo ip6tables -I OUTPUT -d ::5") for c in lin)


def test_sim_block_unblock(monkeypatch):
    called = []
    monkeypatch.setattr(blocker, "_run", lambda c: called.append(c) or (0, ""))
    b = blocker.Blocker(protect=lambda: ["192.168.1.1"], sim=True, platform="darwin")
    st = b.block("45.33.32.156", "port scan")
    assert st["blocked"][0]["ip"] == "45.33.32.156" and "45.33.32.156" in st["rules"]
    assert b.unblock("45.33.32.156")["blocked"] == []
    assert called == []  # στην προσομοίωση δεν αγγίζει ποτέ το τείχος


def test_pf_apply_uses_anchor_and_token(monkeypatch):
    calls = []

    def fake(c):
        calls.append(c)
        return (0, "Token : 12345") if c == ["pfctl", "-E"] else (0, "")
    monkeypatch.setattr(blocker, "_run", fake)
    b = blocker.Blocker(platform="darwin")
    monkeypatch.setattr(blocker.Blocker, "can_apply", property(lambda s: True))
    b.block("1.2.3.4")
    assert calls[0][:3] == ["pfctl", "-a", "com.apple/netwatch"] and calls[1] == ["pfctl", "-E"] and b.token == "12345"
    b.unblock("1.2.3.4")
    assert ["pfctl", "-a", "com.apple/netwatch", "-F", "all"] in calls and ["pfctl", "-X", "12345"] in calls and b.token is None
