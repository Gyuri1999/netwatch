"""Ο προσομοιωτής IOS της Ακαδημίας δέχεται σε κάθε βήμα τη σωστή εντολή και τις συντομογραφίες της (τρέχει σε node)."""
import os
import shutil
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


@pytest.mark.skipif(not shutil.which("node"), reason="χρειάζεται node")
def test_every_lab_step_accepts_answer_and_abbreviations():
    p = subprocess.run(["node", os.path.join(HERE, "js", "academy_cli_check.js")], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stdout + p.stderr
    assert p.stdout.startswith("OK")


@pytest.mark.skipif(not shutil.which("node"), reason="χρειάζεται node")
def test_vlsm_planner_math():
    p = subprocess.run(["node", os.path.join(HERE, "js", "vlsm_check.js")], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stdout + p.stderr


@pytest.mark.skipif(not shutil.which("node"), reason="χρειάζεται node")
def test_acl_tester_logic():
    p = subprocess.run(["node", os.path.join(HERE, "js", "acl_check.js")], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stdout + p.stderr
