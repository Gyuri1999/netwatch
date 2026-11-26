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


def test_wireshark_guide_lives_inside_packets():
    """🦈 Wireshark δεν είναι πια ξεχωριστή οθόνη: είναι καρτέλα μέσα στα 📦 Πακέτα, και οι παλιοί σύνδεσμοι δουλεύουν."""
    assert "ws" not in _tabs() and "feed" in _tabs()
    feed = HTML[HTML.index('id="t-feed"'):HTML.index('id="t-det"')]
    assert 'id="t-ws"' in feed and 'data-fv="live"' in feed and 'data-fv="guide"' in feed
    assert "if(t==='ws'){FEEDV='guide';t='feed'" in HTML          # ?tab=ws, ⌘K και παλιά κουμπιά
    assert "FEEDV='live';showTab('feed')" in HTML                 # «▶ Στα πακέτα» γυρνά στα ζωντανά


def test_menu_view_has_its_own_storage_key():
    """Το «nw-view» κρατά την τελευταία οθόνη· η προβολή μενού δεν πρέπει να το πατάει (χανόταν η επιλογή)."""
    assert "getItem('nw-menuview')" in HTML and "setItem('nw-menuview',VIEWM)" in HTML
    assert "setItem('nw-view',VIEWM)" not in HTML


def _groups():
    blk = HTML[HTML.index("const TAB_GROUPS={"):HTML.index("const GROUP_OF")]
    return {h: re.findall(r"\['([a-z0-9_]+)','", body) for h, body in re.findall(r"(\w+):\[(\[.*?\])\]", blk)}


def test_screen_groups_are_one_menu_entry_with_tabs():
    """Όμοιες οθόνες είναι μία γραμμή στο μενού με καρτέλες· οι οθόνες μένουν και ανοίγουν από εκεί."""
    g = _groups()
    assert g["devs"] == ["devs", "fleet", "iot", "iotinv", "ipam"]
    assert g["wifi"] == ["wifi", "speed", "radio"] and g["hist"] == ["hist", "tm", "stats"]
    assert g["cams"] == ["cams", "camcheck"] and g["academy"] == ["academy", "learn", "tips", "quiz"]
    seen = []
    for head, ids in g.items():
        assert ids[0] == head                                      # η κεφαλή είναι πρώτη (αυτή φαίνεται στο μενού)
        for t in ids:
            assert t in _tabs() and f'id="t-{t}"' in HTML          # καμία οθόνη δεν χάθηκε
            assert t not in seen, f"η οθόνη {t} είναι σε δύο ομάδες"
            seen.append(t)
    rail = HTML[HTML.index("function railHTML"):HTML.index("function buildRail")]
    assert "inMenu(t)" in rail and 'id="ph-seg"' in HTML
    assert "#ph-seg[hidden]{display:none}" in HTML                # το .seg είναι flex: χωρίς αυτό δεν κρύβεται


def test_every_view_can_reach_its_group_heads():
    """Κάθε κεφαλή ομάδας ανήκει σε κάποια προβολή — αλλιώς η ομάδα θα φαινόταν μόνο στο «Όλα»."""
    in_views = {t for ids in _views().values() for t in ids}
    assert set(_groups()) <= in_views


def test_every_screen_has_its_own_emoji():
    """Ένα εικονίδιο = μία οθόνη: το ίδιο emoji σε 3–4 οθόνες (π.χ. 🔌, 🛡, 🔎) μπέρδευε όποιον ψάχνει με το μάτι."""
    blk = HTML[HTML.index("const SECTIONS=["):HTML.index("const SECT_NAME")]
    names = re.findall(r"\['[a-z0-9_]+','([^']+)','", blk)
    emoji = [n.split(" ")[0] for n in names]
    dup = sorted({e for e in emoji if emoji.count(e) > 1})
    assert not dup, f"emoji σε πάνω από μία οθόνη: {dup}"
    assert all(" " in n and len(n.split(" ", 1)[1]) >= 3 for n in names)   # emoji + όνομα


def test_group_tabs_use_the_same_emoji_as_their_screen():
    blk = HTML[HTML.index("const SECTIONS=["):HTML.index("const SECT_NAME")]
    screen = {t: n.split(" ")[0] for t, n in re.findall(r"\['([a-z0-9_]+)','([^']+)','", blk)}
    grp = HTML[HTML.index("const TAB_GROUPS={"):HTML.index("const GROUP_OF")]
    for t, label in re.findall(r"\['([a-z0-9_]+)','([^']+)'\]", grp):
        assert label.split(" ")[0] == screen[t], f"η καρτέλα {t} έχει άλλο emoji από την οθόνη της"


def test_every_menu_group_has_its_own_colour():
    """🎨 Χρώμα ανά ομάδα: κάθε ομάδα του μενού έχει δικό της --gc, σε σκοτεινό και φωτεινό θέμα."""
    n = len(re.findall(r"^  \['[^']+',\[\[", HTML[HTML.index("const SECTIONS=["):HTML.index("const SECT_NAME")], flags=re.M))
    dark = dict(re.findall(r"(?<!\] )\.gc-(\d)\{--gc:(#[0-9a-f]{6})\}", HTML))
    light = dict(re.findall(r"html\[data-theme=light\] \.gc-(\d)\{--gc:(#[0-9a-f]{6})\}", HTML))
    for cols in (dark, light):
        assert sorted(cols) == [str(i) for i in range(n)]
        assert len(set(cols.values())) == n                      # κανένα χρώμα δύο φορές
    rail = HTML[HTML.index("function railHTML"):HTML.index("function buildRail")]
    assert 'class="rg gc-${gi}"' in rail and "grp(SECTIONS[o],o)" in rail
    assert "TAB_GC[gh]" in HTML                                   # ο τίτλος της σελίδας παίρνει το χρώμα της ομάδας


def test_page_tabs_have_their_own_style_not_the_generic_segment():
    """🗂 Οι καρτέλες σελίδας είναι .ptabs (γραμμή κάτω από την ενεργή)· το emoji χωριστά από το κείμενο."""
    assert 'class="ptabs" id="ph-seg"' in HTML and 'class="ptabs" id="feed-seg"' in HTML
    assert ".ptabs button.on::after{transform:scaleX(1)}" in HTML
    assert '<span class="te" aria-hidden="true">📦</span><span>Ζωντανά πακέτα</span>' in HTML
    assert "html.nomo .ptabs button::after{transition:none}" in HTML   # «λιγότερη κίνηση»
