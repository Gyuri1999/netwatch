"""🏠 Απλή Αρχική (λειτουργία «Μαθαίνω»): 3 μεγάλα πράγματα πάνω, όλα τα άλλα στο «Περισσότερα»."""
import os

HERE = os.path.join(os.path.dirname(__file__), "..")
HTML = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()
NAV = open(os.path.join(HERE, "navplus.js"), encoding="utf-8").read()
LEARN = HTML[HTML.index("function renderHomeLearn()"):HTML.index("function routeHTML(")]
TECH = HTML[HTML.index("function renderHomeTech()"):HTML.index("function renderHomeTech()") + 6000]


def test_three_big_blocks_come_first_then_more():
    big, today, learn, more = (LEARN.index(x) for x in ('class="card home-big"', 'class="card home-today"', "+learnCardHTML()+", 'class="home-more"'))
    assert big < today < learn < more
    assert LEARN.count("learnCardHTML()") == 1                    # η κάρτα μάθησης μία φορά (πάνω, όχι και μέσα)


def test_nothing_is_removed_only_moved_under_more():
    inside = LEARN[LEARN.index('class="home-more"'):LEARN.index("'</details>'")]
    for old in ('class="home-snapshot"', "Από πού ξεκινάω;", "step(7,", "Τελευταίες ειδοποιήσεις", "Δες ζωντανά", 'id="route-h"', "data-attn-slot"):
        assert old in inside, f"χάθηκε από την Αρχική: {old}"


def test_today_list_is_short_and_ordered_by_urgency():
    todo = LEARN[LEARN.index("const todo=[];"):LEARN.index("const top=")]
    order = [todo.index(x) for x in ("if(hi)", "if(w&&w.level!=='ok')", "if(newD)", "if(!w)", "if(me)", "if(au&&au.score<75)")]
    assert order == sorted(order)                                # σοβαρά πρώτα
    assert "todo.slice(0,3)" in LEARN and "data-ht-all" in LEARN  # 3 στην αρχή, «Δείξε και τα άλλα» για τα υπόλοιπα
    assert "Τίποτα επείγον σήμερα" in LEARN                       # και όταν δεν υπάρχει τίποτα


def test_more_remembers_open_state_and_attention_card_moves_inside():
    assert "localStorage.getItem('nw-homemore')" in LEARN and "localStorage.setItem('nw-homemore'" in LEARN
    assert "el.querySelector('[data-attn-slot]') || el" in NAV    # «Θέλει προσοχή»: μέσα στα Περισσότερα, αλλιώς πάνω


def test_technician_home_is_untouched():
    assert "home-big" not in TECH and "home-more" not in TECH
