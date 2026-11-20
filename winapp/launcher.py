"""NetWatch για Windows — η «εφαρμογή»: εικονίδιο στο system tray + παράθυρο, όπως το NetWatch.app στο Mac.

Ο φάκελος της εφαρμογής (φτιάχνεται από το winapp/build.ps1):
    NetWatch.exe        αυτό το πρόγραμμα (PyInstaller)
    python/             ενσωματωμένη Python (embeddable) + scapy/pyyaml/paho
    app/                ο κώδικας του NetWatch

Στην πρώτη εκκίνηση (και μετά από κάθε αναβάθμιση) ο κώδικας αντιγράφεται στο %LOCALAPPDATA%\\NetWatch\\app,
όπου μένουν και το ιστορικό (data/) και το config.yaml. Έτσι ο φάκελος της εφαρμογής μπορεί να είναι και
μόνο για ανάγνωση (π.χ. Program Files). Το backend τρέχει ως ξεχωριστή διεργασία (python netwatch.py) και κλείνει
μόνο του όταν κλείσει αυτό το πρόγραμμα (--parent-pid).

Ο πίνακας ανοίγει στο Edge σε «app mode» (δικό του παράθυρο, χωρίς γραμμή διευθύνσεων). Το Edge υπάρχει σε κάθε
Windows 10/11. Αν λείπει, ανοίγει ο προεπιλεγμένος browser.

    NetWatch.exe              κανονική εκκίνηση
    NetWatch.exe --selftest   για το CI: αντιγραφή κώδικα, backend σε demo, GET /api/status, τέλος (κωδικός 0 = OK)
"""
import ctypes
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser

IS_WIN = os.name == "nt"
FROZEN = getattr(sys, "frozen", False)
BUNDLE = os.environ.get("NETWATCH_BUNDLE") or (os.path.dirname(sys.executable) if FROZEN else
                                               os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dist", "NetWatch"))
SRC = os.path.join(BUNDLE, "app")
SUPPORT = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "NetWatch")
APPDIR = os.path.join(SUPPORT, "app")
LOG = os.path.join(SUPPORT, "netwatch.log")
PORTFILE = os.path.join(SUPPORT, "port")
SETTINGS = os.path.join(SUPPORT, "settings.json")
KEEP = {"data", "config.yaml", os.path.join("rules", "local.yaml")}  # δικά σου — δεν τα πειράζει η αναβάθμιση
NPCAP_URL = "https://npcap.com/#download"
CREATE_NO_WINDOW = 0x08000000
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def python_exe():
    for name in ("python.exe",):
        p = os.path.join(BUNDLE, "python", name)
        if os.path.isfile(p):
            return p
    return sys.executable if not FROZEN else None  # σε ανάπτυξη: η ίδια Python


# ---------------- ρυθμίσεις ----------------
def load_settings():
    try:
        with open(SETTINGS, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_settings(**kw):
    s = load_settings()
    s.update(kw)
    os.makedirs(SUPPORT, exist_ok=True)
    with open(SETTINGS, "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=1)


# ---------------- αντιγραφή κώδικα (όπως το rsync --delete του Mac) ----------------
def _kept(rel):
    rel = os.path.normpath(rel)
    return any(rel == k or rel.startswith(k + os.sep) for k in KEEP)


def sync_app(src=SRC, dst=APPDIR):
    """Αντιγράφει τον κώδικα αν άλλαξε το build. Δεν αγγίζει data/, config.yaml, rules/local.yaml."""
    stamp = os.path.join(src, ".build_id")
    mine = os.path.join(dst, ".build_id")
    try:
        new = open(stamp, encoding="utf-8").read().strip()
    except OSError:
        new = str(time.time())
    try:
        if open(mine, encoding="utf-8").read().strip() == new:
            return False
    except OSError:
        pass
    os.makedirs(dst, exist_ok=True)
    wanted = set()
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        rel_root = os.path.relpath(root, src)
        os.makedirs(os.path.join(dst, rel_root), exist_ok=True)
        for f in files:
            rel = os.path.normpath(os.path.join(rel_root, f))
            wanted.add(rel)
            if not _kept(rel):
                shutil.copy2(os.path.join(src, rel), os.path.join(dst, rel))
    for root, dirs, files in os.walk(dst, topdown=False):
        rel_root = os.path.relpath(root, dst)
        if _kept(rel_root) and rel_root != ".":
            continue
        for f in files:
            rel = os.path.normpath(os.path.join(rel_root, f))
            if rel not in wanted and not _kept(rel) and "__pycache__" not in rel:
                try:
                    os.remove(os.path.join(dst, rel))
                except OSError:
                    pass
    return True


# ---------------- backend ----------------
def npcap_installed():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    # Npcap: System32\Npcap\wpcap.dll · σε «WinPcap API-compatible Mode» και System32\wpcap.dll
    # (Sysnative: αν τρέχουμε 32-bit σε 64-bit Windows, το System32 «ανακατευθύνεται» στο SysWOW64)
    return any(os.path.exists(os.path.join(root, d, *f)) for d in ("System32", "Sysnative")
               for f in (("Npcap", "wpcap.dll"), ("wpcap.dll",)))


# Η embeddable Python έχει αρχείο ._pth: τότε ΔΕΝ βάζει τον φάκελο του script στο sys.path και αγνοεί το PYTHONPATH.
# Γι' αυτό ξεκινάμε με αυτό το μικρό bootstrap, που προσθέτει τον φάκελο του NetWatch και τρέχει το netwatch.py.
BOOT = ("import os, runpy, sys; p = sys.argv[1]; sys.path.insert(0, os.path.dirname(p)); "
        "sys.argv = sys.argv[1:]; runpy.run_path(p, run_name='__main__')")


def backend_args(mode, pcap=None, parent=None):
    a = ["-c", BOOT, os.path.join(APPDIR, "netwatch.py"), "--no-open", "--port-file", PORTFILE,
         "--parent-pid", str(parent or os.getpid())]
    if mode == "demo":
        a.append("--demo")
    elif mode == "pcap":
        a += ["--pcap", pcap or "", "--loop"]
    return a


class Backend:
    def __init__(self):
        self.proc = None
        self.port = None
        self.mode = None
        self.admin_pid = None

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}" if self.port else None

    def start(self, mode, pcap=None, admin=False):
        self.stop()
        self.mode, self.port = mode, None
        try:
            os.remove(PORTFILE)
        except OSError:
            pass
        py = python_exe()
        if not py:
            raise RuntimeError("Λείπει η ενσωματωμένη Python (φάκελος python\\ δίπλα στο NetWatch.exe).")
        args = ["-X", "utf8"] + backend_args(mode, pcap)
        env = {**os.environ, "PYTHONUTF8": "1", "NETWATCH_NO_REEXEC": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        if admin:
            self.admin_pid = run_as_admin(py, args, APPDIR)
            return
        log = open(LOG, "ab")
        self.proc = subprocess.Popen([py] + args, cwd=APPDIR, env=env, stdin=subprocess.DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT, creationflags=CREATE_NO_WINDOW if IS_WIN else 0)
        log.close()

    def wait_ready(self, timeout=90):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                with open(PORTFILE, encoding="utf-8") as f:
                    self.port = int(f.read().strip())
                return True
            except (OSError, ValueError):
                pass
            if self.proc is not None and self.proc.poll() is not None:
                return False
            time.sleep(0.25)
        return False

    def get(self, path, timeout=3):
        with urllib.request.urlopen(self.base + path, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def post(self, path, body=None, timeout=3):
        req = urllib.request.Request(self.base + path, data=json.dumps(body or {}).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()

    def stop(self):
        if self.port:
            try:
                self.post("/api/shutdown", timeout=1.5)
            except Exception:
                pass
        if self.proc is not None:
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc, self.port = None, None


def run_as_admin(exe, args, cwd):
    """Το backend ως διαχειριστής (UAC). Η έξοδος πάει στο netwatch.log μέσω cmd /c."""
    line = subprocess.list2cmdline([exe] + args) + f' >> "{LOG}" 2>&1'
    r = ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f'/d /c "{line}"', cwd, 0)
    if r <= 32:
        raise RuntimeError("Δεν δόθηκαν δικαιώματα διαχειριστή.")
    return True


# ---------------- παράθυρο ----------------
def find_edge():
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")):
        if base:
            p = os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe")
            if os.path.isfile(p):
                return p
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe") as k:
            return winreg.QueryValue(k, None)
    except Exception:
        return None


def open_window(url):
    edge = find_edge()
    if edge:
        prof = os.path.join(SUPPORT, "window")
        subprocess.Popen([edge, f"--app={url}", f"--user-data-dir={prof}", "--no-first-run",
                          "--no-default-browser-check", "--window-size=1440,920"], creationflags=CREATE_NO_WINDOW)
    else:
        webbrowser.open(url)


def message(text, title="NetWatch", yesno=False):
    if not IS_WIN:
        print(f"{title}: {text}")
        return False
    flags = (0x04 if yesno else 0x00) | 0x40  # MB_YESNO | MB_ICONINFORMATION
    return ctypes.windll.user32.MessageBoxW(None, text, title, flags) == 6  # IDYES


# ---------------- εκκίνηση με τα Windows ----------------
def autostart(enable=None):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
        if enable is None:
            try:
                winreg.QueryValueEx(k, "NetWatch")
                return True
            except OSError:
                return False
        if enable:
            winreg.SetValueEx(k, "NetWatch", 0, winreg.REG_SZ, f'"{sys.executable}"')
        else:
            try:
                winreg.DeleteValue(k, "NetWatch")
            except OSError:
                pass
        return enable


# ---------------- εικονίδιο ----------------
COLORS = {"ok": (34, 160, 90), "warn": (230, 170, 20), "bad": (220, 50, 50), "idle": (120, 128, 140)}


def shield(level="idle", count=0, size=64):
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size / 64
    pts = [(32, 4), (56, 12), (56, 30), (50, 46), (32, 60), (14, 46), (8, 30), (8, 12)]
    d.polygon([(x * s, y * s) for x, y in pts], fill=COLORS.get(level, COLORS["idle"]) + (255,))
    if count:
        txt = str(count) if count < 100 else "99+"
        try:
            font = ImageFont.truetype("segoeuib.ttf", int((30 if len(txt) < 3 else 20) * s))
        except OSError:
            try:
                font = ImageFont.load_default(size=int(28 * s))  # Pillow ≥ 10.1
            except TypeError:
                font = ImageFont.load_default()
        box = d.textbbox((0, 0), txt, font=font)
        w, h = box[2] - box[0], box[3] - box[1]
        d.text(((size - w) / 2 - box[0], (size - h) / 2 - box[1]), txt, fill="white", font=font)
    elif level == "ok":
        d.line([(20 * s, 32 * s), (29 * s, 41 * s), (45 * s, 23 * s)], fill="white", width=int(6 * s))
    return img


def level_of(st):
    if not st:
        return "idle"
    lvl = "bad" if st.get("high") else "warn" if st.get("med") else "ok"
    wl = (st.get("wifi") or {}).get("level")
    if wl == "bad" or (wl == "warn" and lvl == "ok"):
        lvl = wl
    return lvl


# ---------------- η εφαρμογή ----------------
class App:
    MODES = {"live": "Live (πραγματική κίνηση)", "demo": "Demo (προσομοίωση)", "pcap": "Αρχείο pcap"}

    def __init__(self):
        self.backend = Backend()
        s = load_settings()
        self.mode = s.get("mode") or "live"   # 1η φορά: Live (αν λείπει το Npcap, το launch ρωτά και πέφτει σε Demo)
        # Αν είχε πέσει σε Demo ΜΟΝΟ επειδή έλειπε το Npcap και τώρα εγκαταστάθηκε → πίσω σε Live αυτόματα
        if s.get("no_npcap") and npcap_installed():
            self.mode = "live"
        self.pcap = s.get("pcap")
        self.admin = bool(s.get("admin"))
        self.status = {}
        self.msg = "Ξεκινά…"
        self.icon = None
        self.opened = False

    # --- backend ---
    def launch(self, mode=None, pcap=None, admin=None, open_after=True):
        mode = mode or self.mode
        admin = self.admin if admin is None else admin
        no_npcap = mode == "live" and not npcap_installed()
        if no_npcap:
            if message("Για Live καταγραφή χρειάζεται το δωρεάν Npcap.\n\nΝα ανοίξει η σελίδα λήψης; "
                       "(Στην εγκατάσταση άφησε τσεκαρισμένο το «WinPcap API-compatible Mode».)\n\n"
                       "Μέχρι τότε ξεκινά σε Demo.", yesno=True):
                webbrowser.open(NPCAP_URL)
            mode = "demo"
        if mode == "pcap" and not (pcap and os.path.isfile(pcap)):
            mode = "demo"
        self.mode, self.pcap, self.admin = mode, pcap, admin and mode == "live"
        save_settings(mode=mode, pcap=pcap, admin=self.admin, no_npcap=no_npcap)
        self.status, self.msg = {}, "Ξεκινά…"
        self.refresh_icon()

        def run():
            try:
                self.backend.start(mode, pcap, admin=self.admin)
            except Exception as e:
                self.msg = str(e)
                self.refresh_icon()
                message(f"Το NetWatch δεν ξεκίνησε:\n{e}")
                return
            if self.backend.wait_ready():
                self.msg = ""
                if open_after:
                    self.open()
                self.poll()
            else:
                self.msg = "Το backend δεν ξεκίνησε"
                self.refresh_icon()
                if message("Το NetWatch δεν ξεκίνησε.\n\n" + tail(LOG, 6) + "\n\nΝα ανοίξει το αρχείο καταγραφής;", yesno=True):
                    os.startfile(LOG)
        threading.Thread(target=run, daemon=True).start()

    def poll(self):
        try:
            self.status = self.backend.get("/api/status") if self.backend.port else {}
        except Exception:
            self.status = {}
        self.refresh_icon()

    def poller(self):
        while True:
            time.sleep(3)
            if self.backend.port:
                self.poll()

    # --- tray ---
    def refresh_icon(self):
        if not self.icon:
            return
        st = self.status
        self.icon.icon = shield(level_of(st) if st else "idle", int(st.get("alerts") or 0) if st else 0)
        mode = self.MODES.get(self.mode, self.mode)
        if self.msg:
            self.icon.title = f"NetWatch — {self.msg}"[:127]
        else:
            self.icon.title = f"NetWatch · {mode} · {st.get('alerts', 0)} ειδοποιήσεις"[:127]
        self.icon.update_menu()

    def open(self, *_):
        if self.backend.base:
            open_window(self.backend.base)

    def open_browser(self, *_):
        if self.backend.base:
            webbrowser.open(self.backend.base)

    def pick_pcap(self, *_):
        def ask():
            import tkinter
            from tkinter import filedialog
            root = tkinter.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            p = filedialog.askopenfilename(title="Άνοιγμα καταγραφής", filetypes=[("Καταγραφές", "*.pcap *.pcapng *.cap"), ("Όλα", "*.*")],
                                           initialdir=os.path.join(APPDIR, "samples"))
            root.destroy()
            if p:
                self.launch("pcap", os.path.normpath(p))
        threading.Thread(target=ask, daemon=True).start()

    def quit(self, *_):
        self.msg = "Κλείνει…"
        self.backend.stop()
        self.icon.stop()

    def menu(self):
        import pystray
        I = pystray.MenuItem  # noqa: E741
        st = self.status

        def header(_):
            if self.msg:
                return self.msg
            return f"{st.get('alerts', 0)} ειδοποιήσεις · {st.get('high', 0)} υψηλές · {st.get('med', 0)} μεσαίες"

        def mode_item(m, label):
            return I(label, lambda *_: self.launch(m, admin=False), checked=lambda _: self.mode == m and not self.admin, radio=True)

        return pystray.Menu(
            I("Άνοιγμα NetWatch", self.open, default=True),
            I(header, None, enabled=False),
            pystray.Menu.SEPARATOR,
            mode_item("live", "Live — πραγματική κίνηση"),
            I("Live ως διαχειριστής (μπλοκάρισμα IP)", lambda *_: self.launch("live", admin=True),
              checked=lambda _: self.mode == "live" and self.admin, radio=True),
            mode_item("demo", "Demo — προσομοίωση επιθέσεων"),
            I("Άνοιγμα αρχείου pcap…", self.pick_pcap, checked=lambda _: self.mode == "pcap", radio=True),
            pystray.Menu.SEPARATOR,
            I("Άνοιγμα στον browser", self.open_browser),
            I("Φάκελος δεδομένων", lambda *_: os.startfile(SUPPORT)),
            I("Αρχείο καταγραφής", lambda *_: os.path.exists(LOG) and os.startfile(LOG)),
            I("Εκκίνηση μαζί με τα Windows", lambda *_: autostart(not autostart()), checked=lambda _: autostart()),
            pystray.Menu.SEPARATOR,
            I("Έξοδος", self.quit),
        )

    def run(self):
        import pystray
        self.icon = pystray.Icon("NetWatch", shield(), "NetWatch", menu=self.menu())

        def setup(icon):
            icon.visible = True
            try:
                sync_app()
            except Exception as e:
                message(f"Δεν μπόρεσα να ετοιμάσω τον φάκελο {APPDIR}:\n{e}")
                icon.stop()
                return
            self.launch()
            threading.Thread(target=self.poller, daemon=True).start()
        self.icon.run(setup)


def tail(path, n):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[-n:]).strip()
    except OSError:
        return ""


def single_instance():
    """True αν είμαστε οι πρώτοι. Αλλιώς το NetWatch τρέχει ήδη: ανοίγουμε απλώς το παράθυρό του."""
    if not IS_WIN:
        return True
    ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\NetWatchTray")
    if ctypes.windll.kernel32.GetLastError() != 183:  # ERROR_ALREADY_EXISTS
        return True
    try:
        with open(PORTFILE, encoding="utf-8") as f:
            open_window(f"http://127.0.0.1:{int(f.read().strip())}")
    except (OSError, ValueError):
        pass
    return False


def selftest():
    """Για το CI: αντιγραφή κώδικα → backend σε demo → /api/status → τέλος. Γράφει το αποτέλεσμα στο selftest.txt."""
    out = os.path.join(SUPPORT, "selftest.txt")
    os.makedirs(SUPPORT, exist_ok=True)
    b = Backend()
    ok, info = False, ""
    try:
        sync_app()
        b.start("demo")
        if b.wait_ready(120):
            for _ in range(20):
                st = b.get("/api/status", timeout=5)
                if st.get("mode") == "demo":
                    ok, info = True, f"port {b.port}, mode {st.get('mode')}, alerts {st.get('alerts')}"
                    break
                time.sleep(0.5)
        else:
            info = "το backend δεν ξεκίνησε:\n" + tail(LOG, 20)
    except Exception as e:
        info = f"{type(e).__name__}: {e}\n" + tail(LOG, 20)
    finally:
        b.stop()
    with open(out, "w", encoding="utf-8") as f:
        f.write(("OK " if ok else "FAIL ") + info + "\n")
    return 0 if ok else 1


def main():
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    os.makedirs(SUPPORT, exist_ok=True)
    if not single_instance():
        return
    App().run()


if __name__ == "__main__":
    main()
