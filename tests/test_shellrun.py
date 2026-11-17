import pytest

import shellrun as sr


@pytest.fixture(autouse=True)
def tools_installed(monkeypatch):
    # τα τεστ ελέγχουν τους κανόνες, όχι ποια εργαλεία (nmap, ifconfig…) έχει αυτό το μηχάνημα — στο CI (Ubuntu) λείπουν
    monkeypatch.setattr(sr.shutil, "which", lambda c, *a, **k: "/usr/bin/" + c)


def blocked(c):
    parts, why = sr.check(c)
    return parts is None and bool(why)


def test_blocks_dangerous():
    for c in ("rm -rf ~", "ls; rm x", "echo hi > f", "cat < x", "echo `id`", "echo $(id)", "ls && id",
              "sudo nmap 192.168.1.1", "awk 'BEGIN{system(\"id\")}'", "curl -o x http://a", "openssl genrsa -out k 2048",
              "nmap -sT 8.8.8.8", "nmap --script=vuln 192.168.1.1", "nmap -oN out 192.168.1.1", "nmap -sS 192.168.1.0/24",
              "cat ~/.ssh/id_rsa", "python3 -c 'print(1)'", "scutil --set HostName x", "sort -o f x"):
        assert blocked(c), c


def test_linux_hints():
    assert "ifconfig" in sr.check("ip -4 addr show | grep inet")[1]
    assert "brew" in sr.check("sudo apt install nmap")[1]
    assert "-sT" in sr.check("sudo nmap -sS -p 23 192.168.1.0/24")[1]


def test_allows_and_ping_count():
    parts, why = sr.check("ifconfig | grep inet")
    assert why is None and parts[0] == ["ifconfig"] and parts[1] == ["grep", "inet"]
    parts, _ = sr.check("ping 127.0.0.1")
    assert parts[0][:3] == ["ping", "-c", "4"]
    assert sr.check("nmap -sT -p 22,80 192.168.1.0/24")[1] is None
    assert sr.check("nmap -sT scanme.nmap.org")[1] is None


def test_run_pipe():
    r = sr.run("echo hello netwatch | tr a-z A-Z")
    assert r["ok"] and r["out"].strip() == "HELLO NETWATCH"
    r = sr.run("rm -rf /tmp/x")
    assert not r["ok"] and r["blocked"]


def test_suggest():
    assert sr.suggest("sudo nmap -sS -p 23,80 --open 192.168.1.0/24") == "nmap -sT -p 23,80 --open 192.168.1.0/24"
    assert sr.suggest("ip -4 addr show | grep inet") == "ifconfig | grep 'inet '"
    assert sr.suggest("sudo nmap -sn 192.168.1.0/24") == "nmap -sn 192.168.1.0/24"
    assert sr.suggest("sudo apt install nmap") is None
    assert sr.suggest("rm -rf /") is None
