"""Οι υπολογιστές τεχνικού (calcui.js → NWCalc) δίνουν τις γνωστές τιμές: όρια PoE, I²R, FSPL, dBm/mW, αποθήκευση, RAID (τρέχει σε node)."""
import os
import shutil
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


@pytest.mark.skipif(not shutil.which("node"), reason="χρειάζεται node")
def test_calc_known_values():
    p = subprocess.run(["node", os.path.join(HERE, "js", "calc_check.js")], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stdout + p.stderr
    assert p.stdout.startswith("OK ")


@pytest.mark.skipif(not shutil.which("node"), reason="χρειάζεται node")
def test_calc_module_loads_without_dom():
    js = "const C=require(process.argv[1]);if(typeof C.poeBudget!=='function'||typeof window!=='undefined')process.exit(2);console.log(Object.keys(C).length)"
    p = subprocess.run(["node", "-e", js, os.path.join(HERE, "..", "calcui.js")], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0 and int(p.stdout.strip()) > 20, p.stdout + p.stderr
