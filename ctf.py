"""NetWatch CTF — ασκήσεις ανάλυσης κίνησης πάνω σε pcap.

Οι απαντήσεις αποθηκεύονται μόνο ως SHA-256 (ctf/challenges.json), ώστε να μην «προδίδονται»
αν κάποιος ανοίξει το αρχείο. Τα επίπεδα φτιάχνονται με: python tools/make_ctf.py
"""
import hashlib
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
CTF_FILE = os.path.join(HERE, "ctf", "challenges.json")


def normalize(ans):
    s = str(ans).strip().lower()
    s = re.sub(r"\s+", "", s)
    return s.rstrip(".")


def answer_hash(level, qid, ans):
    return hashlib.sha256(f"netwatch-ctf:{level}:{qid}:{normalize(ans)}".encode()).hexdigest()


def load():
    with open(CTF_FILE, encoding="utf-8") as f:
        return json.load(f)


def level(level_id):
    lv = next((lv for lv in load()["levels"] if lv["id"] == level_id), None)
    if not lv:
        raise ValueError("Άγνωστο επίπεδο")
    return lv


def public():
    """Τα επίπεδα χωρίς τις απαντήσεις (για τον browser)."""
    out = []
    for lv in load()["levels"]:
        lv = dict(lv)
        lv["questions"] = [{k: v for k, v in q.items() if k != "answers"} for q in lv["questions"]]
        lv["total"] = sum(q["points"] for q in lv["questions"])
        out.append(lv)
    return out


def question(level_id, qid):
    q = next((q for q in level(level_id)["questions"] if q["id"] == qid), None)
    if not q:
        raise ValueError("Άγνωστη ερώτηση")
    return q


def check(level_id, qid, ans):
    q = question(level_id, qid)
    if q.get("type") == "rule":
        raise ValueError("Αυτή η ερώτηση θέλει κανόνα, όχι κείμενο")
    return answer_hash(level_id, qid, ans) in q["answers"]


def check_rule_actors(level_id, qid, actors):
    """Ο κανόνας πέρασε αν «χτύπησε» ΜΟΝΟ τον σωστό στόχο."""
    q = question(level_id, qid)
    good = {a for a in actors if answer_hash(level_id, qid, a) in q["answers"]}
    return bool(good) and good == set(actors)
