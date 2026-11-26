"""NetWatch — 🔑 Ξεχασμένα κλειδιά: ψάχνει κωδικούς, κλειδιά API και tokens σε ΔΙΚΟ σου φάκελο κώδικα
(π.χ. ένα project ESP32 ή ένα git repo) — και στο git ιστορικό του, γιατί ένα κλειδί που σβήστηκε μένει εκεί.

Κανόνες:
  • Μόνο διάβασμα, μόνο τοπικά αρχεία μέσα στον φάκελο χρήστη (~). Δεν στέλνει τίποτα πουθενά.
  • ΔΕΝ δοκιμάζει ποτέ αν ένα κλειδί «δουλεύει» (αυτό θα ήταν χρήση κλεμμένου κλειδιού).
  • Οι τιμές ΔΕΝ επιστρέφονται ποτέ ολόκληρες: μόνο κρυμμένες (π.χ. «ghp_…(40)») και ένα σύντομο αποτύπωμα
    (hash) για να ξεχωρίζουμε το ίδιο κλειδί σε αρχείο και ιστορικό.

scan(path, sim=False, history=True)
  → {path, files, findings:[{file, line, kind, label, sev, masked, fp, where:"file"|"history", commit?}],
     counts:{high, med}, history:{scanned, commits, only_in_history}, truncated, sim}
"""
import hashlib
import os
import re
import subprocess

MAX_FILES = 20000
MAX_FILE_BYTES = 1024 * 1024
MAX_FINDINGS = 500
MAX_HISTORY_BYTES = 40 * 1024 * 1024
MAX_COMMITS = 3000
SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", "build", "dist", ".pio", ".idea",
             ".gradle", ".tox", ".mypy_cache", ".pytest_cache", "Pods", "DerivedData", ".next", "target", ".cache"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z",
            ".bin", ".elf", ".hex", ".o", ".a", ".so", ".dylib", ".dll", ".exe", ".class", ".jar", ".pyc", ".woff",
            ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".mov", ".wav", ".pcap", ".pcapng", ".sqlite", ".db", ".lock"}

# (είδος, ετικέτα, regex, σοβαρότητα). Η ομάδα 1 (αν υπάρχει) είναι η «μυστική» τιμή, αλλιώς όλο το ταίριασμα.
PATTERNS = [
    ("private_key", "Ιδιωτικό κλειδί (SSH/TLS)", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----", "high"),
    ("aws", "Κλειδί AWS", r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b", "high"),
    ("github", "Token GitHub", r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b", "high"),
    ("anthropic", "Κλειδί Anthropic (Claude)", r"\b(sk-ant-[A-Za-z0-9_\-]{20,})", "high"),
    ("openai", "Κλειδί OpenAI", r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})", "high"),
    ("stripe", "Κλειδί Stripe (live)", r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b", "high"),
    ("slack", "Token Slack", r"\b(xox[abposr]-[A-Za-z0-9-]{10,})", "high"),
    ("slack_webhook", "Slack webhook", r"(https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,})", "high"),
    ("discord_webhook", "Discord webhook", r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]{20,})", "high"),
    ("telegram", "Token Telegram bot", r"\b(\d{8,10}:AA[0-9A-Za-z_\-]{33})\b", "high"),
    ("google", "Κλειδί Google API", r"\b(AIza[0-9A-Za-z_\-]{35})\b", "med"),
    ("jwt", "JWT token", r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", "med"),
    ("url_creds", "Κωδικός μέσα σε URL", r"\b[a-z][a-z0-9+.-]{1,15}://[^\s:/@'\"<>]{1,64}:([^\s@/'\"<>]{3,128})@[\w.-]+", "med"),
    ("define", "Κωδικός σε #define", r"#define\s+\w*(?:PASS|PASSWORD|PSK|TOKEN|SECRET|API_?KEY)\w*\s+\"([^\"]{4,})\"", "med"),
    ("assign", "Κωδικός γραμμένος στον κώδικα",
     r"(?i)\b(?:wifi_?pass(?:word)?|wlan_?pass|ssid_?pass(?:word)?|password|passwd|pwd|psk|mqtt_?pass(?:word)?|"
     r"api_?key|apikey|secret(?:_?key)?|client_?secret|auth_?token|access_?token|token)\b[\w\]\[]*\s*[:=]\s*[\"']([^\"'\s]{4,})[\"']", "med"),
]
_RX = [(k, label, re.compile(rx), sev) for k, label, rx, sev in PATTERNS]
# Τιμές που είναι προφανώς παραδείγματα / placeholders — όχι πραγματικά μυστικά
PLACEHOLDER = re.compile(r"(?i)^(?:x+|\*+|\.+|-+|0+|1234\w*|password\d*|passwd|pass|secret|changeme|change_me|example\w*|"
                         r"your[_-]?\w*|my[_-]?\w*|<[^>]*>|\$\{[^}]*\}|\$\w+|%\w+%|\{\{[^}]*\}\}|todo|fixme|none|null|"
                         r"test\w*|dummy\w*|placeholder|replace\w*|enter\w*|insert\w*|xxx\w*|abc\w*|foo\w*|bar)$")
# …και «οδηγίες» αντί για τιμή: change-me-…, long-random-…, put-your-…, ή ελληνικά («μακρύς-τυχαίος-κωδικός»)
PLACEHOLDER_PREFIX = re.compile(r"(?i)^(?:change[-_]?me|app[-_]?pass\w*|long|random|put|set|generate|replace|your|my|some|one|new|insert|enter)(?:[-_ ]|$)")
GREEK = re.compile(r"[Ͱ-Ͽἀ-῿]")
CODE_REF = re.compile(r"(?i)(?:os\.environ|getenv|process\.env|env\(|settings\.|config\[|\.get\()")


def mask(v):
    """Ποτέ η πλήρης τιμή: λίγοι πρώτοι χαρακτήρες + μήκος."""
    v = str(v)
    if len(v) >= 40 and KEY_BODY.fullmatch(v):
        return f"…({len(v)})"  # σώμα κλειδιού/μεγάλο base64: ούτε οι πρώτοι χαρακτήρες
    keep = 4 if len(v) >= 12 else 2 if len(v) >= 6 else 0
    return f"{v[:keep]}…({len(v)})"


def fingerprint(v):
    return hashlib.sha256(str(v).encode("utf-8", "replace")).hexdigest()[:10]


KEY_BODY = re.compile(r"[A-Za-z0-9+/=]{40,}")
EXAMPLE_DIRS = {"test", "tests", "spec", "specs", "fixtures", "fixture", "examples", "example", "samples", "sample",
                "docs", "doc", "mock", "mocks", "testdata", "__tests__"}


def looks_like_example(path):
    """Αρχείο που μάλλον έχει ΠΑΡΑΔΕΙΓΜΑΤΑ (tests, docs, *.example.*) — εμφανίζεται, αλλά χαμηλότερα."""
    parts = re.split(r"[\\/]", str(path).lower())
    name = parts[-1] if parts else ""
    return bool(EXAMPLE_DIRS & set(parts[:-1])) or name.startswith("test_") or name.endswith(("_test.py", ".test.js", ".spec.js")) \
        or re.search(r"(?:^|[._-])(?:example|sample|template|dist)(?:[._-]|$)", name) is not None


def scan_text(text):
    """Ευρήματα σε ένα κείμενο: [(γραμμή, είδος, ετικέτα, σοβαρότητα, τιμή)]. Μία φορά ανά τιμή και γραμμή."""
    out = []
    lines = text.splitlines()
    for n, line in enumerate(lines, 1):
        if len(line) > 4000:
            line = line[:4000]
        seen = set()
        for kind, label, rx, sev in _RX:
            for m in rx.finditer(line):
                val = m.group(1) if rx.groups else m.group(0)
                if kind == "private_key":
                    # μόνο αν ακολουθεί ΠΡΑΓΜΑΤΙΚΟ σώμα κλειδιού (όχι σκέτη επικεφαλίδα, π.χ. σε κώδικα που την ψάχνει)
                    after = line[m.end():] + "\n" + "\n".join(lines[n:n + 2])
                    body = KEY_BODY.search(after)
                    if not body:
                        continue
                    val = body.group(0)
                elif kind in ("assign", "define", "url_creds"):
                    if PLACEHOLDER.match(val) or PLACEHOLDER_PREFIX.match(val) or GREEK.search(val) \
                            or CODE_REF.search(val) or len(set(val)) < 3:
                        continue
                if any(val in x or x in val for x in seen):
                    continue  # π.χ. ένα sk-ant-… να μη μετρηθεί και ως OpenAI ή ως «token = …»
                seen.add(val)
                out.append((n, kind, label, sev, val))
    return out


def _home():
    """Ο φάκελος του ΚΑΝΟΝΙΚΟΥ χρήστη (και όταν το NetWatch τρέχει με sudo)."""
    user = os.environ.get("SUDO_USER")
    if user and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            import pwd
            return os.path.realpath(pwd.getpwnam(user).pw_dir)
        except (ImportError, KeyError):
            pass
    return os.path.realpath(os.path.expanduser("~"))


def check_path(path):
    """Μόνο υπο-φάκελος του ~ (όχι όλο το ~, όχι αρχεία συστήματος). Επιστρέφει την πραγματική διαδρομή."""
    p = str(path or "").strip()
    if not p:
        raise ValueError("Δώσε τον φάκελο του project, π.χ. ~/smart-city-poles")
    home = _home()
    if p.startswith("~"):
        p = home + p[1:]
    real = os.path.realpath(p)
    if not os.path.isdir(real):
        raise ValueError("Δεν βρέθηκε αυτός ο φάκελος")
    if real == home or os.path.commonpath([real, home]) != home:
        raise ValueError("Διάλεξε έναν φάκελο project μέσα στον φάκελο χρήστη σου (π.χ. ~/netwatch), όχι όλο το ~ ή αρχεία συστήματος")
    return real


def _files(root):
    count = 0
    for d, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not os.path.islink(os.path.join(d, x)))
        for f in sorted(files):
            fp = os.path.join(d, f)
            if os.path.islink(fp) or os.path.splitext(f)[1].lower() in SKIP_EXT:
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield fp


def _read(fp):
    try:
        if os.path.getsize(fp) > MAX_FILE_BYTES:
            return None
        with open(fp, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None  # δυαδικό
    return data.decode("utf-8", "replace")


def _history(root):
    """Γραμμές που ΠΡΟΣΤΕΘΗΚΑΝ σε όλο το git ιστορικό: [(commit, αρχείο, κείμενο)]. Μόνο τοπικό git, χωρίς δίκτυο."""
    if not os.path.isdir(os.path.join(root, ".git")):
        return None, 0
    try:
        p = subprocess.Popen(["git", "-C", root, "log", "--all", "-p", "--no-color", "--no-ext-diff", "-U0",
                              f"--max-count={MAX_COMMITS}", "--format=commit %h"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"})
    except OSError:
        return None, 0
    out, read, commit, fname, commits = [], 0, "", "", 0
    try:
        for raw in p.stdout:
            read += len(raw)
            if read > MAX_HISTORY_BYTES:
                break
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if line.startswith("commit "):
                commit, commits = line[7:].strip(), commits + 1
            elif line.startswith("+++ "):
                fname = line[6:] if line.startswith("+++ b/") else line[4:]
            elif line.startswith("+") and not line.startswith("+++"):
                out.append((commit, fname, line[1:]))
    finally:
        p.kill()
        p.wait()
    return out, commits


def scan(path, sim=False, history=True):
    if sim:
        return _sim()
    root = check_path(path)
    findings, files, truncated, by_fp = [], 0, False, {}
    for fp in _files(root):
        files += 1
        text = _read(fp)
        if not text:
            continue
        rel = os.path.relpath(fp, root)
        for n, kind, label, sev, val in scan_text(text):
            f = fingerprint(val)
            if f in by_fp:  # το ίδιο κλειδί και αλλού: μία γραμμή, «+N σημεία»
                prev = by_fp[f]
                prev["more"] += 1
                if len(prev["also"]) < 10:
                    prev["also"].append(f"{rel}:{n}")
                prev["example"] = prev["example"] and looks_like_example(rel)
                continue
            if len(findings) >= MAX_FINDINGS:
                truncated = True
                break
            item = {"file": rel, "line": n, "kind": kind, "label": label, "sev": sev,
                    "masked": mask(val), "fp": f, "where": "file", "example": looks_like_example(rel), "more": 0, "also": []}
            by_fp[f] = item
            findings.append(item)
    if files > MAX_FILES:
        truncated = True
    hist = {"scanned": False, "commits": 0, "only_in_history": 0}
    if history:
        added, commits = _history(root)
        if added is not None:
            hist.update(scanned=True, commits=commits)
            seen = set()
            for commit, fname, text in added:
                for _, kind, label, sev, val in scan_text(text):
                    f = fingerprint(val)
                    if f in by_fp or f in seen:
                        continue  # ήδη στα αρχεία ή ήδη αναφέρθηκε
                    seen.add(f)
                    if len(findings) >= MAX_FINDINGS:
                        truncated = True
                        break
                    hist["only_in_history"] += 1
                    findings.append({"file": fname, "line": None, "kind": kind, "label": label, "sev": sev,
                                     "masked": mask(val), "fp": f, "where": "history", "commit": commit,
                                     "example": looks_like_example(fname), "more": 0, "also": []})
    findings.sort(key=lambda x: (x["example"], x["sev"] != "high", x["where"] != "file", x["file"], x["line"] or 0))
    real = [x for x in findings if not x["example"]]
    return {"path": root, "files": files, "findings": findings, "truncated": truncated, "history": hist, "sim": False,
            "counts": {"high": sum(1 for x in real if x["sev"] == "high"), "med": sum(1 for x in real if x["sev"] == "med"),
                       "examples": len(findings) - len(real)}}


def _sim():
    """Demo: ένα project ESP32 όπως τα συνηθισμένα λάθη (ψεύτικες, κρυμμένες τιμές)."""
    f = [
        {"file": "src/main.cpp", "line": 12, "kind": "assign", "label": "Κωδικός γραμμένος στον κώδικα", "sev": "med",
         "masked": "Hom…(12)", "fp": "a1b2c3d4e5", "where": "file", "example": False, "more": 1, "also": ["src/config.h:3"]},
        {"file": "src/main.cpp", "line": 15, "kind": "url_creds", "label": "Κωδικός μέσα σε URL", "sev": "med",
         "masked": "mq…(9)", "fp": "b2c3d4e5f6", "where": "file", "example": False, "more": 0, "also": []},
        {"file": "tools/notify.py", "line": 4, "kind": "telegram", "label": "Token Telegram bot", "sev": "high",
         "masked": "6123…(46)", "fp": "c3d4e5f6a7", "where": "history", "commit": "9f3e2a1", "example": False, "more": 0, "also": []},
    ]
    f.sort(key=lambda x: (x["sev"] != "high", x["where"] != "file"))
    return {"path": "~/demo-esp32", "files": 23, "findings": f, "truncated": False, "sim": True,
            "history": {"scanned": True, "commits": 41, "only_in_history": 1},
            "counts": {"high": 1, "med": 2, "examples": 0}}
