"""🔌 Όταν χαθεί η σύνδεση με τον server, η σελίδα το λέει — όχι «✓ Όλα καλά» πάνω από παλιά δεδομένα."""
import os
import re

HTML = open(os.path.join(os.path.dirname(__file__), "..", "index.html"), encoding="utf-8").read()
CONN = HTML[HTML.index("var CONN="):HTML.index("setInterval(connTick,1000);")]


def test_status_never_says_all_good_while_offline():
    upd = HTML[HTML.index("function updStatus()"):HTML.index("function updStatus()") + 500]
    off, ok = upd.index("CONN.down"), upd.index("Όλα καλά")
    assert off < ok and "Χωρίς σύνδεση" in upd[off:ok] and "return" in upd[off:ok]   # ελέγχεται ΠΡΙΝ από το «Όλα καλά»
    assert "typeof CONN!=='undefined'" in upd                                        # το updStatus τρέχει και πριν οριστεί


def test_banner_appears_after_a_short_grace_and_explains():
    assert ">=3000" in CONN                                   # όχι μπάρα για στιγμιαία διακοπή
    assert "Χάθηκε η σύνδεση με το NetWatch" in CONN and "μπορεί να είναι παλιά" in CONN
    assert "role','alert'" in CONN and "Δοκίμασε τώρα" in CONN
    assert "#conn-bar[hidden]{display:none}" in HTML and "body.conn-down main{padding-top" in HTML


def test_reconnects_alone_with_backoff_and_says_so():
    assert "es.onopen=connUp" in CONN and "Συνδέθηκε ξανά" in CONN
    assert re.search(r"setTimeout\(connect,Math\.min\(10000,2000\+CONN\.tries\*1000\)\)", CONN)   # 3″, 4″ … έως 10″
    assert "CONN.es.close()" in CONN and "clearTimeout(CONN.timer)" in CONN                       # ποτέ δύο συνδέσεις μαζί
    assert "if(CONN.since)connUp()" in CONN                   # και όταν έρθει δεδομένο χωρίς «open» (π.χ. online demo)
