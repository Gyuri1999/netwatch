"""🔄 Ενημερώσεις από το GitHub — έλεγχος για νέα έκδοση και ασφαλής εγκατάσταση με ένα κλικ.

Πώς βρίσκει τι είναι «εγκατάσταση»:
  app    → τρέχει μέσα από NetWatch.app (…/NetWatch.app/Contents/Resources/netwatch)
  git    → τρέχει από git clone (υπάρχει .git) → `git pull --ff-only`
  docker → μέσα σε container → μόνο οδηγίες (docker pull)
  winapp → Windows app (NetWatch.exe): το launcher γράφει %LOCALAPPDATA%/NetWatch/bundle.json με τον φάκελό του
  files  → σκέτα αρχεία → μόνο σύνδεσμος για κατέβασμα

Windows: ίδιοι έλεγχοι (υπογεγραμμένο SHA256SUMS-windows, SHA-256 του zip, έκδοση = tag). Ο φάκελος του app δεν
αλλάζει όσο τρέχει (κλειδωμένα .exe/.dll): ετοιμάζουμε τη νέα έκδοση στο %LOCALAPPDATA%/NetWatch/update και στην
«Επανεκκίνηση» το launcher κλείνει, ένα μικρό script κάνει την αλλαγή φακέλων (το παλιό μένει ως <φάκελος>.previous)
και ανοίγει τη νέα έκδοση.

Ασφάλεια (το NetWatch τρέχει ως root — μια «πειραγμένη» ενημέρωση θα ήταν καταστροφή):
  • Ρωτάμε ΜΟΝΟ το api.github.com για το δικό μας repo. Δεν στέλνουμε τίποτα για εσένα ή το δίκτυό σου.
  • Το app εγκαθίσταται ΜΟΝΟ αν το SHA256SUMS έχει έγκυρη υπογραφή (ssh-keygen -Y verify) από κλειδί που
    υπάρχει ήδη μέσα στο app σου (update_signers). Χωρίς κλειδί ή με λάθος υπογραφή → καμία αλλαγή.
  • Μετά: SHA-256 του zip, ίδιο bundle id, ίδια έκδοση με το tag, codesign --verify. Μόνο τότε αλλαγή,
    και το παλιό μένει ως NetWatch.app.previous (επιστροφή αν κάτι πάει στραβά).
  • Ποτέ αυτόματη εγκατάσταση: ο αυτόματος έλεγχος μόνο ενημερώνει· εγκαθιστάς εσύ με κλικ.
"""
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile

from core import HERE

REPO = "Gyuri1999/netwatch"
API = f"https://api.github.com/repos/{REPO}/releases/latest"
PAGE = f"https://github.com/{REPO}/releases/latest"
NS, IDENT = "netwatch-update", "netwatch-release"
ZIP, SUMS, SIG = "NetWatch.zip", "SHA256SUMS", "SHA256SUMS.sig"
WINZIP, WSUMS, WSIG = "NetWatch-windows-x64.zip", "SHA256SUMS-windows", "SHA256SUMS-windows.sig"
MAX_ZIP = 400 * 1024 * 1024
DAY = 86400
CHECK_EVERY = 6 * 3600  # αυτόματος έλεγχος
NIGHT = (3, 5)  # τοπική ώρα: εφαρμογή έτοιμης ενημέρωσης όταν δεν τη χρησιμοποιείς
VER_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?$")
ASSET_HOSTS = ("https://github.com/", "https://objects.githubusercontent.com/", "https://release-assets.githubusercontent.com/")


def vtuple(v):
    m = VER_RE.match(str(v or "").strip())
    return tuple(int(x or 0) for x in m.groups()) if m else None


def newer(a, b):
    """Είναι η a νεότερη από τη b;"""
    ta, tb = vtuple(a), vtuple(b)
    return bool(ta and tb and ta > tb)


def read_version(here=HERE):
    try:
        with open(os.path.join(here, "VERSION"), encoding="utf-8") as f:
            v = f.read().strip()
        return v if vtuple(v) else "0.0.0"
    except OSError:
        return "0.0.0"


def bundle_of(here):
    """…/NetWatch.app/Contents/Resources/netwatch → …/NetWatch.app (αλλιώς None)."""
    p = os.path.normpath(here).split(os.sep)
    if len(p) >= 4 and p[-1] == "netwatch" and p[-2] == "Resources" and p[-3] == "Contents" and p[-4].endswith(".app"):
        return os.sep.join(p[:-3])
    return None


def win_support(here):
    """%LOCALAPPDATA%/NetWatch — ο backend των Windows τρέχει από …/NetWatch/app."""
    return os.path.dirname(os.path.normpath(here))


def win_bundle(here):
    """Ο φάκελος του NetWatch.exe, όπως τον γράφει το launcher (None αν δεν τρέχουμε από το Windows app)."""
    try:
        with open(os.path.join(win_support(here), "bundle.json"), encoding="utf-8") as f:
            b = json.load(f).get("bundle")
    except (OSError, ValueError, AttributeError):
        return None
    return b if isinstance(b, str) and os.path.isfile(os.path.join(b, "NetWatch.exe")) else None


def ssh_keygen():
    """Στα Windows 10/11 το OpenSSH Client είναι ενσωματωμένο (System32/OpenSSH)."""
    if sys.platform == "win32":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        for d in ("System32", "Sysnative"):
            p = os.path.join(root, d, "OpenSSH", "ssh-keygen.exe")
            if os.path.isfile(p):
                return p
    return shutil.which("ssh-keygen")


def mac_bundle(here, ppid, runner=None):
    """Το Mac app τρέχει τον backend από ~/Library/Application Support/NetWatch/app (αντίγραφο)·
    το ίδιο το NetWatch.app το βρίσκουμε από τη διεργασία-γονέα (--parent-pid)."""
    if sys.platform != "darwin" or not ppid:
        return None
    p = os.path.normpath(here).split(os.sep)
    if p[-3:] != ["Application Support", "NetWatch", "app"]:
        return None
    rc, out, _ = (runner or _run)(["/bin/ps", "-o", "comm=", "-p", str(int(ppid))], timeout=5)
    exe = out.strip().split(os.sep) if not rc else []
    if len(exe) < 4 or exe[-2:-1] != ["MacOS"] or exe[-3] != "Contents" or not exe[-4].endswith(".app"):
        return None
    b = os.sep.join(exe[:-3])
    return b if os.path.isdir(os.path.join(b, "Contents", "Resources", "netwatch")) else None


def detect_kind(here, ppid=None):
    if bundle_of(here) or mac_bundle(here, ppid):
        return "app"
    if sys.platform == "win32" and win_bundle(here):
        return "winapp"
    if os.path.isdir(os.path.join(here, ".git")):
        return "git"
    if os.path.exists("/.dockerenv"):
        return "docker"
    return "files"


def _as_user(argv):
    user = os.environ.get("SUDO_USER")
    if user and hasattr(os, "geteuid") and os.geteuid() == 0 and re.match(r"^[a-z_][a-z0-9_.-]{0,31}$", user):
        return ["sudo", "-n", "-u", user, "--"] + argv
    return argv


def _run(argv, timeout=60, stdin=None, cwd=None):
    p = subprocess.run(argv, capture_output=True, timeout=timeout, input=stdin, cwd=cwd)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def _fetch(url, limit=2 * 1024 * 1024, dest=None, progress=None):
    """GET με όριο μεγέθους. dest=None → bytes, αλλιώς γράφει στο αρχείο και επιστρέφει το sha256."""
    req = urllib.request.Request(url, headers={"User-Agent": "NetWatch-updater", "Accept": "application/vnd.github+json" if "api.github.com" in url else "*/*"})
    with urllib.request.urlopen(req, timeout=30) as r:  # nosec — μόνο github.com (ελέγχεται πριν)
        total = int(r.headers.get("Content-Length") or 0)
        if total > limit:
            raise ValueError("πολύ μεγάλο αρχείο")
        h, got, buf = hashlib.sha256(), 0, []
        f = open(dest, "wb") if dest else None
        try:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                got += len(chunk)
                if got > limit:
                    raise ValueError("πολύ μεγάλο αρχείο")
                h.update(chunk)
                (f.write(chunk) if f else buf.append(chunk))
                if progress and total:
                    progress(got / total)
        finally:
            if f:
                f.close()
    return h.hexdigest() if dest else b"".join(buf)


def parse_sums(text):
    out = {}
    for line in str(text).splitlines():
        m = re.match(r"^([0-9a-f]{64})\s+\*?(\S+)$", line.strip())
        if m:
            out[os.path.basename(m.group(2))] = m.group(1)
    return out


def verify_sig(data, sig, signers, runner=_run):
    """ssh-keygen -Y verify: η υπογραφή του SHA256SUMS από κλειδί του update_signers;"""
    if not signers or not os.path.exists(signers) or not any(l.strip() and not l.startswith("#") for l in open(signers, encoding="utf-8")):
        return False, "Δεν υπάρχει κλειδί υπογραφής στο app (update_signers) — δεν γίνεται ασφαλής αυτόματη εγκατάσταση."
    with tempfile.TemporaryDirectory() as d:
        sp = os.path.join(d, "s.sig")
        with open(sp, "wb") as f:
            f.write(sig)
        sg = os.path.join(d, "signers")  # αντίγραφο με \n (στα Windows το git checkout μπορεί να το κάνει CRLF)
        with open(signers, "rb") as f, open(sg, "wb") as g:
            g.write(f.read().replace(b"\r\n", b"\n"))
        rc, out, err = runner([ssh_keygen() or "ssh-keygen", "-Y", "verify", "-f", sg, "-I", IDENT, "-n", NS, "-s", sp], timeout=20, stdin=data)
    if rc == 0 and "Good" in (out + err):
        return True, ""
    return False, "Η υπογραφή της ενημέρωσης ΔΕΝ είναι έγκυρη — δεν εγκαταστάθηκε τίποτα. " + (err or out).strip()[:200]


def safe_extract(zpath, dest):
    """Αποσυμπίεση χωρίς «../» και απόλυτα paths. Στο macOS με ditto (κρατά symlinks & δικαιώματα)."""
    with zipfile.ZipFile(zpath) as z:
        for n in z.namelist():
            if n.startswith("/") or ".." in n.split("/"):
                raise ValueError("ύποπτο path μέσα στο zip: " + n[:80])
    if shutil.which("ditto") and sys.platform == "darwin":
        rc, _, err = _run(["ditto", "-x", "-k", zpath, dest], timeout=300)
        if rc:
            raise ValueError("ditto: " + err[:200])
        return
    with zipfile.ZipFile(zpath) as z:
        for info in z.infolist():
            z.extract(info, dest)
            mode = info.external_attr >> 16
            if mode & 0o111:
                os.chmod(os.path.join(dest, info.filename), mode & 0o755)


class Updater:
    def __init__(self, state=None, sim=False, here=HERE, cfg=None, fetch=None, runner=None, clock=time.time, ppid=None, hour=None):
        cfg = cfg if isinstance(cfg, dict) else {}
        self.state, self.sim, self.here, self.clock = state, sim, here, clock
        self.fetch, self.runner = fetch or _fetch, runner or _run
        self.hour = hour or (lambda: time.localtime(self.clock()).tm_hour)
        self.kind = "app" if sim else detect_kind(here, ppid)
        self.bundle = (bundle_of(here) or mac_bundle(here, ppid, self.runner)) if self.kind == "app" and not sim else \
            (win_bundle(here) if self.kind == "winapp" else None)
        self.version = read_version(here)
        self.auto = bool(cfg.get("auto_check", True))
        # αυτόματη εγκατάσταση: μόνο στα apps (Mac/Windows) με υπογραφή· η επιλογή μένει στο data/ (δεν σβήνεται στην αναβάθμιση)
        self.prefs_path = os.path.join(here, "data", "update.json")
        self.auto_install = bool(self._prefs().get("auto_install", cfg.get("auto_install", True)))
        self.auto_failed = None  # tag που απέτυχε αυτόματα — δεν ξαναδοκιμάζουμε στην ίδια εκτέλεση
        self.signers = os.path.join(here, "update_signers")
        self.lock = threading.Lock()
        self.latest, self.err, self.checked = None, None, 0
        self.job = {"state": "idle"}  # idle | running | done | error
        self.git = None

    # ── έλεγχος ──
    def check(self, force=False):
        with self.lock:
            if not force and self.checked and self.clock() - self.checked < 60:
                return self.view()
            self.checked = self.clock()
        if self.sim:
            t = vtuple(self.version) or (1, 0, 0)
            self.latest = {"tag": f"v{t[0]}.{t[1] + 1}.0", "name": f"NetWatch v{t[0]}.{t[1] + 1}.0", "url": PAGE, "date": "2026-11-18T10:00:00Z",
                           "notes": "## Τι νέο\n- 🧮 Subnet / VLSM planner\n- 🏷 Ονόματα συσκευών\n- 🖥 Καλύτερος προσομοιωτής IOS στα labs", "assets": [ZIP, SUMS, SIG]}
            self.err = None
            return self.view()
        try:
            j = json.loads(self.fetch(API))
            assets = [a for a in j.get("assets") or [] if isinstance(a, dict)]
            self.latest = {"tag": str(j.get("tag_name") or "")[:40], "name": str(j.get("name") or "")[:120], "url": str(j.get("html_url") or PAGE)[:300],
                           "date": str(j.get("published_at") or "")[:40], "notes": str(j.get("body") or "")[:6000],
                           "assets": [a.get("name") for a in assets][:30], "_dl": {a.get("name"): a.get("browser_download_url") for a in assets}}
            self.err = None
        except Exception as e:  # noqa: BLE001 — δίκτυο/404/JSON: απλά το δείχνουμε
            msg = str(e)
            self.err = ("Δεν υπάρχει ακόμα καμία έκδοση (release) στο GitHub." if "404" in msg else "Δεν μπόρεσα να ρωτήσω το GitHub: " + msg[:160])
        if self.kind == "git":
            self.git = self._git_status()
        return self.view()

    def _git_status(self):
        r = self.runner
        rc, _, err = r(_as_user(["git", "-C", self.here, "fetch", "--quiet", "origin"]), timeout=60)
        if rc:
            return {"error": "git fetch: " + err.strip()[:200]}
        rc, br, _ = r(["git", "-C", self.here, "rev-parse", "--abbrev-ref", "HEAD"], timeout=10)
        rc2, up, _ = r(["git", "-C", self.here, "rev-parse", "--abbrev-ref", "@{u}"], timeout=10)
        if rc or rc2:
            return {"error": "Το branch δεν παρακολουθεί κάποιο remote (git branch -u origin/main)."}
        _, cnt, _ = r(["git", "-C", self.here, "rev-list", "--count", "HEAD..@{u}"], timeout=10)
        _, log, _ = r(["git", "-C", self.here, "log", "--format=%h %s", "-n", "30", "HEAD..@{u}"], timeout=10)
        _, dirty, _ = r(["git", "-C", self.here, "status", "--porcelain", "--untracked-files=no"], timeout=10)
        return {"branch": br.strip(), "upstream": up.strip(), "behind": int(cnt.strip() or 0), "commits": [l for l in log.splitlines() if l][:30], "dirty": bool(dirty.strip())}

    def available(self):
        if self.kind == "git":
            return bool(self.git and self.git.get("behind"))
        return bool(self.latest and newer(self.latest.get("tag"), self.version))

    def view(self):
        lt = {k: v for k, v in (self.latest or {}).items() if not k.startswith("_")} or None
        return {"version": self.version, "kind": self.kind, "latest": lt, "available": self.available(), "error": self.err,
                "checked": self.checked, "auto": self.auto, "git": self.git, "job": dict(self.job), "page": PAGE,
                "auto_install": self.auto_install, "auto_ok": self.auto_ok(),
                "sim": bool(self.sim), "os": sys.platform,
                "signed": bool(lt and SIG in (lt.get("assets") or [])), "can_install": self._can_install()[0], "why_not": self._can_install()[1]}

    def _can_install(self):
        if not self.available():
            return False, ""
        if self.kind == "app":
            a = (self.latest or {}).get("assets") or []
            if ZIP not in a or SUMS not in a:
                return False, "Αυτή η έκδοση δεν έχει NetWatch.zip / SHA256SUMS — κατέβασέ τη από τη σελίδα του GitHub."
            if SIG not in a:
                return False, "Αυτή η έκδοση δεν είναι υπογεγραμμένη — για ασφάλεια δεν εγκαθίσταται αυτόματα."
            return True, ""
        if self.kind == "winapp":
            a = (self.latest or {}).get("assets") or []
            if WINZIP not in a or WSUMS not in a or WSIG not in a:
                return False, "Αυτή η έκδοση δεν έχει υπογεγραμμένο πακέτο για Windows — κατέβασέ τη από τη σελίδα του GitHub."
            if not ssh_keygen():
                return False, "Λείπει το OpenSSH Client των Windows (χρειάζεται για τον έλεγχο υπογραφής): Ρυθμίσεις → Εφαρμογές → Προαιρετικές δυνατότητες → OpenSSH Client. Ή κατέβασέ τη με το χέρι από το GitHub."
            return True, ""
        if self.kind == "git":
            if self.git and self.git.get("dirty"):
                return False, "Έχεις τοπικές αλλαγές στον κώδικα — κάνε commit/stash πρώτα (δεν τις πειράζω)."
            return True, ""
        if self.kind == "docker":
            return False, "Σε Docker: docker compose pull && docker compose up -d"
        if sys.platform == "win32":
            return False, "Στα Windows: κατέβασε το NetWatch-windows-x64.zip από το GitHub, κλείσε το NetWatch (εικονίδιο ασπίδας → Έξοδος) και αντικατέστησε τον παλιό φάκελο. Οι ρυθμίσεις σου μένουν."
        return False, "Κατέβασε τη νέα έκδοση από τη σελίδα του GitHub."

    # ── αυτόματα ──
    def _prefs(self):
        try:
            with open(self.prefs_path, encoding="utf-8") as f:
                j = json.load(f)
            return j if isinstance(j, dict) else {}
        except (OSError, ValueError):
            return {}

    def set_auto(self, on):
        self.auto_install = bool(on)
        try:
            os.makedirs(os.path.dirname(self.prefs_path), exist_ok=True)
            with open(self.prefs_path, "w", encoding="utf-8") as f:
                json.dump({**self._prefs(), "auto_install": self.auto_install}, f)
        except OSError as e:
            return {"error": "Δεν αποθηκεύτηκε η ρύθμιση: " + str(e)[:160]}
        return self.view()

    def auto_ok(self):
        """Μπορεί αυτή η εγκατάσταση να ενημερώνεται μόνη της; (μόνο υπογεγραμμένα apps, όχι git/docker/αρχεία/demo)"""
        if self.sim or self.kind not in ("app", "winapp") or not self.bundle:
            return False
        # Mac σε live με κωδικό διαχειριστή (root χωρίς SUDO_UID): το νέο app θα γινόταν του root → μόνο με κλικ
        if hasattr(os, "geteuid") and os.geteuid() == 0 and not os.environ.get("SUDO_UID"):
            return False
        return True

    def tick(self):
        """Ένας γύρος του αυτόματου: έλεγχος κάθε 6 ώρες → κατέβασμα + έλεγχος υπογραφής → εφαρμογή τη νύχτα."""
        if self.auto and (not self.checked or self.clock() - self.checked > CHECK_EVERY):
            self.check(force=True)
        if not (self.auto_install and self.auto_ok()):
            return None
        tag = (self.latest or {}).get("tag")
        st = self.job.get("state")
        if st in ("idle", "error") and tag and tag != self.auto_failed and not self._win_failed(tag) and self._can_install()[0]:
            self.install(auto=True)  # τρέχει εδώ (σύγχρονα)· αποτυχία → δεν ξαναδοκιμάζεται αυτόματα
            return "install" if self.job.get("state") == "done" else None
        if st == "done" and self.job.get("auto") and NIGHT[0] <= self.hour() < NIGHT[1]:
            r = self.restart()
            return "restart" if r.get("ok") else None
        return None

    def _win_failed(self, tag):
        """Το launcher δεν μπόρεσε να εφαρμόσει αυτή την έκδοση (π.χ. φάκελος σε χρήση) → όχι ξανά αυτόματα."""
        if self.kind != "winapp":
            return False
        try:
            with open(os.path.join(win_support(self.here), "update-failed.json"), encoding="utf-8") as f:
                v = json.load(f).get("version")
        except (OSError, ValueError, AttributeError):
            return False
        return bool(v) and vtuple(v) == vtuple(tag)

    def run_forever(self):
        time.sleep(30)  # άσε την εκκίνηση να τελειώσει
        while True:
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(600)

    # ── εγκατάσταση ──
    def install(self, auto=False, wait=False):
        ok, why = self._can_install()
        if not ok:
            return {"error": why or "Δεν υπάρχει νεότερη έκδοση."}
        with self.lock:
            if self.job.get("state") == "running":
                return {"error": "Η ενημέρωση τρέχει ήδη."}
            if self.job.get("state") == "done":
                return {"error": "Η νέα έκδοση είναι ήδη έτοιμη — πάτα «Επανεκκίνηση τώρα»."}
            self.job = {"state": "running", "step": "ξεκινάω…", "pct": 0, "auto": auto}
        if auto or wait:  # ο αυτόματος γύρος τρέχει ήδη σε δικό του thread
            self._install_bg(auto)
        else:
            threading.Thread(target=self._install_bg, daemon=True).start()
        return {"ok": True}

    def _step(self, s, pct=None):
        self.job.update({"step": s, **({"pct": round(pct, 3)} if pct is not None else {})})

    def _install_bg(self, auto=False):
        tag = (self.latest or {}).get("tag")
        try:
            msg = (self._install_sim() if self.sim else self._install_git() if self.kind == "git"
                   else self._install_win() if self.kind == "winapp" else self._install_app())
            self.job = {"state": "done", "step": msg, "pct": 1, "restart": True, "auto": auto, "tag": tag}
        except Exception as e:  # noqa: BLE001
            if auto:
                self.auto_failed = tag
            self.job = {"state": "error", "step": str(e)[:400], "auto": auto}

    def _install_sim(self):
        for i, s in enumerate(["κατέβασμα SHA256SUMS", "έλεγχος υπογραφής ✔", "κατέβασμα NetWatch.zip", "έλεγχος SHA-256 ✔", "έλεγχος app ✔", "αντικατάσταση"]):
            self._step(s, i / 6)
            time.sleep(0.4)
        return "Demo: η νέα έκδοση «εγκαταστάθηκε» (στο demo δεν αλλάζει τίποτα)."

    def _install_git(self):
        self._step("git pull --ff-only", 0.3)
        rc, out, err = self.runner(_as_user(["git", "-C", self.here, "pull", "--ff-only"]), timeout=180)
        if rc:
            raise RuntimeError("git pull απέτυχε: " + (err or out).strip()[:300])
        self.version = read_version(self.here)
        self.git = self._git_status()
        return "Ο κώδικας ενημερώθηκε (git pull). Κάνε επανεκκίνηση για να φορτώσει."

    def _dl_url(self, name):
        u = ((self.latest or {}).get("_dl") or {}).get(name) or ""
        if not u.startswith(ASSET_HOSTS):
            raise RuntimeError("Ύποπτος σύνδεσμος κατεβάσματος — σταματάω.")
        return u

    def _install_app(self):
        tag = self.latest["tag"]
        want = ".".join(map(str, vtuple(tag)))
        self._step("κατέβασμα SHA256SUMS + υπογραφής", 0.02)
        sums = self.fetch(self._dl_url(SUMS), limit=65536)
        sig = self.fetch(self._dl_url(SIG), limit=65536)
        self._step("έλεγχος υπογραφής", 0.05)
        ok, why = verify_sig(sums, sig, self.signers, self.runner)
        if not ok:
            raise RuntimeError(why)
        h = parse_sums(sums.decode("utf-8", "replace")).get(ZIP)
        if not h:
            raise RuntimeError("Το SHA256SUMS δεν περιέχει το NetWatch.zip.")
        parent = os.path.dirname(self.bundle)
        work = tempfile.mkdtemp(prefix=".nw-update-", dir=parent)  # ίδιος δίσκος → ατομικό rename
        try:
            zp = os.path.join(work, ZIP)
            got = self.fetch(self._dl_url(ZIP), limit=MAX_ZIP, dest=zp, progress=lambda f: self._step("κατέβασμα NetWatch.zip", 0.08 + 0.7 * f))
            if got != h:
                raise RuntimeError("Το SHA-256 του NetWatch.zip δεν ταιριάζει — δεν εγκαταστάθηκε τίποτα.")
            self._step("αποσυμπίεση", 0.8)
            out = os.path.join(work, "x")
            os.makedirs(out)
            safe_extract(zp, out)
            new = os.path.join(out, os.path.basename(self.bundle))
            if not os.path.isdir(new):
                apps = [d for d in os.listdir(out) if d.endswith(".app")]
                if len(apps) != 1:
                    raise RuntimeError("Το zip δεν περιέχει ένα NetWatch.app.")
                new = os.path.join(out, apps[0])
            self._step("έλεγχος του νέου app", 0.86)
            self._check_bundle(new, want)
            self._step("αντικατάσταση", 0.93)
            prev = self.bundle + ".previous"
            if os.path.exists(prev):
                shutil.rmtree(prev)
            os.rename(self.bundle, prev)
            try:
                os.rename(new, self.bundle)
            except OSError:
                os.rename(prev, self.bundle)  # επιστροφή στο παλιό
                raise
            self._chown_tree(self.bundle)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        self.version = want
        return f"Εγκαταστάθηκε η {tag}. Το παλιό κρατήθηκε ως {os.path.basename(self.bundle)}.previous. Κάνε επανεκκίνηση του NetWatch."

    def _install_win(self):
        """Κατεβάζει/ελέγχει/αποσυμπιέζει στο …/NetWatch/update· η αλλαγή φακέλων γίνεται στην επανεκκίνηση."""
        tag = self.latest["tag"]
        want = ".".join(map(str, vtuple(tag)))
        self._step("κατέβασμα SHA256SUMS + υπογραφής", 0.02)
        sums = self.fetch(self._dl_url(WSUMS), limit=65536)
        sig = self.fetch(self._dl_url(WSIG), limit=65536)
        self._step("έλεγχος υπογραφής", 0.05)
        ok, why = verify_sig(sums, sig, self.signers, self.runner)
        if not ok:
            raise RuntimeError(why)
        h = parse_sums(sums.decode("utf-8", "replace")).get(WINZIP)
        if not h:
            raise RuntimeError("Το SHA256SUMS-windows δεν περιέχει το " + WINZIP + ".")
        upd = os.path.join(win_support(self.here), "update")
        shutil.rmtree(upd, ignore_errors=True)
        os.makedirs(upd)
        zp = os.path.join(upd, WINZIP)
        got = self.fetch(self._dl_url(WINZIP), limit=MAX_ZIP, dest=zp, progress=lambda f: self._step("κατέβασμα " + WINZIP, 0.08 + 0.7 * f))
        if got != h:
            shutil.rmtree(upd, ignore_errors=True)
            raise RuntimeError("Το SHA-256 του " + WINZIP + " δεν ταιριάζει — δεν εγκαταστάθηκε τίποτα.")
        self._step("αποσυμπίεση", 0.8)
        out = os.path.join(upd, "x")
        os.makedirs(out)
        safe_extract(zp, out)
        os.remove(zp)
        new = os.path.join(out, "NetWatch")
        self._step("έλεγχος της νέας έκδοσης", 0.9)
        if not os.path.isfile(os.path.join(new, "NetWatch.exe")) or not os.path.isdir(os.path.join(new, "python")):
            shutil.rmtree(upd, ignore_errors=True)
            raise RuntimeError("Το zip δεν περιέχει φάκελο NetWatch με NetWatch.exe.")
        nv = read_version(os.path.join(new, "app"))
        if nv != want:
            shutil.rmtree(upd, ignore_errors=True)
            raise RuntimeError(f"Η έκδοση μέσα στο zip ({nv}) δεν ταιριάζει με το tag ({want}).")
        with open(os.path.join(upd, "ready.json"), "w", encoding="utf-8") as f:
            json.dump({"dir": new, "version": want, "t": self.clock()}, f)
        return f"Η {tag} κατέβηκε και ελέγχθηκε. Πάτα «Επανεκκίνηση τώρα»: το NetWatch θα κλείσει και θα ανοίξει ξανά στη νέα έκδοση (το παλιό μένει ως .previous)."

    def _check_bundle(self, new, want):
        def bid(p):
            with open(os.path.join(p, "Contents", "Info.plist"), "rb") as f:
                return plistlib.load(f).get("CFBundleIdentifier")
        if bid(new) != bid(self.bundle):
            raise RuntimeError("Το νέο app έχει άλλο bundle id — σταματάω.")
        nv = read_version(os.path.join(new, "Contents", "Resources", "netwatch"))
        if nv != want:
            raise RuntimeError(f"Η έκδοση μέσα στο zip ({nv}) δεν ταιριάζει με το tag ({want}).")
        if shutil.which("codesign"):
            rc, _, err = self.runner(["codesign", "--verify", "--deep", "--strict", new], timeout=120)
            if rc:
                raise RuntimeError("codesign --verify απέτυχε: " + err.strip()[:200])

    @staticmethod
    def _chown_tree(root):
        uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        if not (uid and gid):
            return
        for d, dirs, files in os.walk(root):
            for n in [d] + [os.path.join(d, x) for x in dirs + files]:
                try:
                    os.lchown(n, int(uid), int(gid))
                except OSError:
                    pass

    def restart(self):
        """Επανεκκίνηση στη νέα έκδοση."""
        if self.sim:
            return {"ok": True, "demo": True}
        if self.kind == "app" and self.bundle:
            with open(os.path.join(self.bundle, "Contents", "Info.plist"), "rb") as f:
                bid = plistlib.load(f).get("CFBundleIdentifier") or "NetWatch"
            if not re.match(r"^[\w.-]+$", bid):
                return {"error": "bundle id"}
            script = f"sleep 1; osascript -e 'tell application id \"{bid}\" to quit'; sleep 4; open \"$0\""
            subprocess.Popen(_as_user(["/bin/sh", "-c", script, self.bundle]), start_new_session=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return {"ok": True}
        if self.kind == "git":
            threading.Timer(1.0, lambda: os.execv(sys.executable, [sys.executable] + sys.argv)).start()
            return {"ok": True}
        if self.kind == "winapp":
            sup = win_support(self.here)
            if not os.path.exists(os.path.join(sup, "update", "ready.json")):
                return {"error": "Δεν υπάρχει έτοιμη ενημέρωση — πάτα πρώτα «Εγκατάσταση»."}
            with open(os.path.join(sup, "update-request.json"), "w", encoding="utf-8") as f:
                json.dump({"t": time.time(), "action": "apply"}, f)  # το launcher το βλέπει σε ~2″
            return {"ok": True, "closing": True}
        return {"error": "Κάνε επανεκκίνηση με το χέρι."}
