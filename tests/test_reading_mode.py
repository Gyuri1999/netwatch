"""🔠 Μέγεθος γραμμάτων και 📖 λειτουργία ανάγνωσης (Εμφάνιση → Προσβασιμότητα)."""
import os
import re

HERE = os.path.join(os.path.dirname(__file__), "..")
HTML = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()
UIPLUS = open(os.path.join(HERE, "uiplus.js"), encoding="utf-8").read()


def test_settings_live_in_the_existing_appearance_panel():
    """Όχι νέα οθόνη/κουμπί: μπαίνουν στον πίνακα «Εμφάνιση», κάτω από «Προσβασιμότητα»."""
    panel = HTML[HTML.index("function drawAp()"):HTML.index("function apClose()")]
    assert panel.index("Προσβασιμότητα") < panel.index("Μέγεθος γραμμάτων") < panel.index("Λειτουργία ανάγνωσης")
    assert "seg('size',[['1','Α'],['1.15','Α+'],['1.3','Α++']])" in panel and "$('ap-read').onchange" in panel
    assert "size:'1',read:false" in HTML                       # προεπιλογή: όπως πριν


def test_applied_before_first_paint_and_remembered():
    early = HTML[:HTML.index("d3.min.js")]
    assert "p.read" in early and "'--z'" in early and "classList.add('zoom')" in early   # χωρίς «πήδημα» στην εκκίνηση
    look = HTML[HTML.index("function applyLook"):HTML.index("function drawAp()")]
    assert "toggle('read'" in look and "setProperty('--z'" in look and "removeProperty('--z')" in look
    assert "localStorage.setItem('nw-look'" in look


def test_zoom_scales_whole_ui_and_keeps_layout_inside_the_window():
    assert "body{zoom:var(--z,1)}" in HTML
    assert "html.zoom header .chip:has(#iface){display:none}" in HTML          # η πάνω μπάρα χωρά τα κουμπιά
    assert "body.v-page aside{min-width:0}" in HTML                            # το περιεχόμενο στενεύει, δεν βγαίνει έξω
    assert re.search(r"#ap\{max-height:calc\(\(100vh - \d+px\)/var\(--z,1\)\);overflow-y:auto\}", HTML)


def test_screen_coordinates_are_divided_by_the_zoom():
    """Tooltip χάρτη και ξενάγηση τοποθετούνται με συντεταγμένες οθόνης: με zoom θα έπεφταν «δίπλα»."""
    assert "const ZF=()=>+getComputedStyle(document.body).zoom||1" in HTML
    tip = HTML[HTML.index("function placeTip"):HTML.index("function placeTip") + 400]
    assert "ZF()" in tip and "x/=z;y/=z" in tip
    assert "getComputedStyle(document.body).zoom" in UIPLUS and "q.left / z" in UIPLUS


def test_reading_mode_spacing_and_no_italics():
    assert "html.read body{letter-spacing:.03em;word-spacing:.12em}" in HTML
    assert "html.read i,html.read em{font-style:normal" in HTML
    assert re.search(r"html\.read [^{]*\{line-height:1\.8\}", HTML)
