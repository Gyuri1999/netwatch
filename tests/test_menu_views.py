"""👁 Προβολές μενού: κάθε id υπάρχει στις οθόνες, χωρίς διπλά, και κάθε προβολή είναι μικρότερη από την επόμενη."""
import os
import re

HTML = open(os.path.join(os.path.dirname(__file__), "..", "index.html"), encoding="utf-8").read()


def _tabs():
    blk = HTML[HTML.index("const SECTIONS=["):HTML.index("const SECT_NAME")]
    return re.findall(r"\['([a-z0-9_]+)','[^']+','", blk)


def _views():
    v = HTML[HTML.index("const VIEW_ADD={"):HTML.index("const VIEW_ORDER")]
    return {k: re.findall(r"'([a-z0-9_]+)'", re.search(k + r":\[(.*?)\]", v, flags=re.S).group(1))
            for k in ("home", "student", "tech")}


def test_view_ids_are_real_screens_without_duplicates():
    tabs, seen = _tabs(), []
    for ids in _views().values():
        for t in ids:
            assert t in tabs, f"άγνωστη οθόνη στις προβολές: {t}"
            assert t not in seen, f"η οθόνη {t} είναι σε δύο προβολές"
            seen.append(t)


def test_views_grow_and_stay_small():
    v, tabs = _views(), _tabs()
    home, student, tech = len(v["home"]), len(v["home"]) + len(v["student"]), sum(map(len, v.values()))
    assert home <= 12 and student <= 30 and home < student < tech < len(tabs)
    assert {"alerts", "devs", "wifi"} <= set(v["home"])           # τα βασικά του σπιτιού
    assert {"feed", "academy", "cli"} <= set(v["student"])        # 📦 Πακέτα + μάθηση για CCNA


def test_packets_screen_is_reachable_from_the_menu():
    """Το 📦 Πακέτα έλειπε από το μενού (υπήρχε μόνο το 🦈 Wireshark) και ο χρήστης έμπαινε στη λάθος οθόνη."""
    assert "t!=='feed'" not in HTML[HTML.index("function railHTML"):HTML.index("function buildRail")]


def test_every_menu_group_is_in_the_rail_order():
    """Η ομάδα «Μάθηση» είχε χαθεί από το μενού όταν προστέθηκε νέα ομάδα και οι δείκτες έμειναν παλιοί."""
    n = len(re.findall(r"^  \['[^']+',\[\[", HTML[HTML.index("const SECTIONS=["):HTML.index("const SECT_NAME")], flags=re.M))
    order = re.search(r"const RAIL_ORDER=\{tech:\[(.*?)\],learn:\[(.*?)\]\}", HTML)
    for part in order.groups():
        idx = sorted(int(x) for x in re.findall(r"\b(\d+)\b", part))
        assert idx == list(range(n)), f"λείπει ή περισσεύει ομάδα: {idx} (υπάρχουν {n})"
