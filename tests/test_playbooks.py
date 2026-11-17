import threading

import playbooks


class Blk:
    def __init__(self):
        self.blocked = set()

    def block(self, ip, why=""):
        if ip == "192.168.1.1":
            raise ValueError("Δεν μπλοκάρω τον router")
        self.blocked.add(ip)
        return {"can_apply": True, "error": None}

    def unblock(self, ip):
        self.blocked.discard(ip)


class St:
    def __init__(self):
        self.blocker, self.notifier, self.hass, self.cfg = Blk(), None, None, {}
        self.sent = []

    def _allowed(self, ip):
        return ip == "192.168.1.5"


A = {"type": "Καναρίνι ESP32", "sev": "high", "actor": "192.168.1.66", "target": "c", "detail": "", "t": 1000}
BOOK = [{"name": "kan", "when": {"type": "Καναρίνι"}, "do": ["block"], "block_minutes": 10, "max_per_hour": 2}]


def test_clean_rejects_bad_playbooks():
    ok, errs = playbooks.clean([{"name": "a", "when": {}, "do": ["block"]}, {"name": "b", "when": {"sev": "high"}, "do": ["rm -rf"]},
                                {"name": "c", "when": {"sev": "high"}, "do": "notify"}])
    assert [p["name"] for p in ok] == ["c"] and len(errs) == 2


def test_matches():
    loc = lambda ip: ip.startswith("192.168.")  # noqa: E731
    assert playbooks.matches({"type": ["Port", "Καναρίνι"]}, A, loc)
    assert not playbooks.matches({"type": "Port"}, A, loc)
    assert playbooks.matches({"sev": "med"}, A, loc) and not playbooks.matches({"sev": "high"}, {**A, "sev": "med"}, loc)
    assert not playbooks.matches({"sev": "low", "local": False}, A, loc)
    assert not playbooks.matches({}, A, loc)


def test_block_expiry_undo_and_rate_limit():
    st = St()
    p = playbooks.Playbooks(st, BOOK, sync=True)
    p.on_alert(A)
    assert "192.168.1.66" in st.blocker.blocked and p.status()["runs"][0]["ok"]
    assert p.expire(now=1000 + 599) == [] and p.expire(now=1000 + 601) == ["192.168.1.66"]
    assert not st.blocker.blocked
    p.on_alert({**A, "actor": "192.168.1.67"})
    p.on_alert({**A, "actor": "192.168.1.68"})  # 3η μέσα στην ώρα → όριο 2
    assert st.blocker.blocked == {"192.168.1.67"}
    rid = p.status()["runs"][0]["id"]
    assert p.undo(rid) and not st.blocker.blocked and not p.undo(rid)


def test_never_blocks_router_allowlist_benign_or_dry_run():
    st = St()
    p = playbooks.Playbooks(st, BOOK + [{"name": "dry", "when": {"sev": "high"}, "do": ["block"], "dry_run": True}], sync=True)
    p.on_alert({**A, "actor": "192.168.1.1"})
    p.on_alert({**A, "actor": "192.168.1.5"})
    p.on_alert({**A, "actor": "192.168.1.70", "benign": "δικό σου"})
    assert not st.blocker.blocked
    runs = p.status()["runs"]
    assert any("router" in r["result"] for r in runs) and any("allowlist" in r["result"] for r in runs)
    assert any(r["dry"] and r["result"].startswith("(δοκιμή)") for r in runs)
