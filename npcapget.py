"""⬇ Npcap με ένα κλικ (Windows): κατεβάζει τον επίσημο installer από το npcap.com, ελέγχει την ψηφιακή υπογραφή
(Authenticode, υπογράφων Nmap Software LLC / Insecure.Com LLC) και τον ανοίγει.

Η εγκατάσταση γίνεται από τον ίδιο τον installer του Npcap: τα Windows ζητούν άδεια διαχειριστή (UAC) και ο χρήστης
πατά «Install». Η δωρεάν άδεια του Npcap δεν επιτρέπει «σιωπηλή» εγκατάσταση ή να το πακετάρουμε μέσα στο NetWatch,
γι' αυτό το κατεβάζουμε από την πηγή του, τη στιγμή που ο χρήστης το ζητάει.
"""
import os
import re
import subprocess
import sys
import threading
import urllib.parse
import urllib.request

HOME = "https://npcap.com/"
HOST = "npcap.com"
URL_RE = re.compile(r"https://npcap\.com/dist/npcap-(\d+)\.(\d+)\.exe")
SIGNERS = ("Nmap Software LLC", "Insecure.Com LLC")
MAX = 15 * 1024 * 1024


def _get(url, limit, dest=None, progress=None):
    if urllib.parse.urlsplit(url).hostname != HOST:
        raise RuntimeError("Κατεβάζω μόνο από το npcap.com.")
    req = urllib.request.Request(url, headers={"User-Agent": "NetWatch"})
    with urllib.request.urlopen(req, timeout=30) as r:  # nosec — μόνο npcap.com (ελέγχεται πριν και μετά)
        if urllib.parse.urlsplit(r.geturl()).hostname != HOST:
            raise RuntimeError("Το npcap.com με έστειλε αλλού — σταματάω.")
        total = int(r.headers.get("Content-Length") or 0)
        if total > limit:
            raise RuntimeError("Πολύ μεγάλο αρχείο.")
        got, buf = 0, []
        f = open(dest, "wb") if dest else None
        try:
            while True:
                c = r.read(65536)
                if not c:
                    break
                got += len(c)
                if got > limit:
                    raise RuntimeError("Πολύ μεγάλο αρχείο.")
                if f:
                    f.write(c)
                    if progress and total:
                        progress(got / total)
                else:
                    buf.append(c)
        finally:
            if f:
                f.close()
    return b"".join(buf) if not dest else got


def latest_url(html):
    """Ο νεότερος installer που αναφέρει η σελίδα του npcap.com."""
    best = None
    for m in URL_RE.finditer(html):
        v = (int(m.group(1)), int(m.group(2)))
        if not best or v > best[0]:
            best = (v, m.group(0))
    return best[1] if best else None


def check_signature(path, runner=None):
    """→ (ok, μήνυμα). PowerShell Get-AuthenticodeSignature: έγκυρη υπογραφή ΚΑΙ σωστός υπογράφων."""
    ps = ("$s=Get-AuthenticodeSignature -LiteralPath $env:NW_FILE; "
          "Write-Output ([string]$s.Status + '|' + [string]$s.SignerCertificate.Subject)")
    run = runner or (lambda argv: subprocess.run(argv, capture_output=True, timeout=60, env={**os.environ, "NW_FILE": path}))
    p = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps])
    out = (p.stdout.decode("utf-8", "replace") if isinstance(p.stdout, bytes) else str(p.stdout)).strip()
    status, _, subject = out.partition("|")
    if status != "Valid":
        return False, f"Η ψηφιακή υπογραφή του installer δεν είναι έγκυρη ({status or '—'}) — δεν τον ανοίγω."
    if not any(f"O={s}" in subject or f"CN={s}" in subject for s in SIGNERS):
        return False, "Ο installer είναι υπογεγραμμένος από άλλον (όχι από τους δημιουργούς του Npcap) — δεν τον ανοίγω."
    return True, subject


class NpcapGet:
    def __init__(self, folder, get=None, sig=None, launch=None, platform=None):
        self.folder = folder
        self.get, self.sig = get or _get, sig or check_signature
        self.launch = launch or (lambda p: os.startfile(p))  # noqa: S606 — ανοίγει τον υπογεγραμμένο installer (UAC)
        self.platform = platform or sys.platform
        self.job = {"state": "idle"}
        self.lock = threading.Lock()

    def view(self):
        return {"job": dict(self.job), "available": self.platform == "win32"}

    def start(self, wait=False):
        if self.platform != "win32":
            return {"error": "Το Npcap χρειάζεται μόνο στα Windows."}
        with self.lock:
            if self.job.get("state") == "running":
                return {"error": "Τρέχει ήδη."}
            self.job = {"state": "running", "step": "Ψάχνω την τελευταία έκδοση στο npcap.com…", "pct": 0}
        if wait:
            self._run()
        else:
            threading.Thread(target=self._run, daemon=True).start()
        return {"ok": True}

    def _step(self, s, pct):
        self.job.update(step=s, pct=round(pct, 3))

    def _run(self):
        try:
            html = self.get(HOME, 2 * 1024 * 1024).decode("utf-8", "replace")
            url = latest_url(html)
            if not url:
                raise RuntimeError("Δεν βρήκα τον installer στη σελίδα του npcap.com — κατέβασέ τον από εκεί με το χέρι.")
            os.makedirs(self.folder, exist_ok=True)
            dest = os.path.join(self.folder, url.rsplit("/", 1)[1])
            self._step("Κατεβάζω " + os.path.basename(dest), 0.05)
            self.get(url, MAX, dest=dest, progress=lambda f: self._step("Κατεβάζω " + os.path.basename(dest), 0.05 + 0.8 * f))
            self._step("Ελέγχω την ψηφιακή υπογραφή…", 0.9)
            ok, why = self.sig(dest)
            if not ok:
                os.remove(dest)
                raise RuntimeError(why)
            self._step("Ανοίγω την εγκατάσταση…", 0.97)
            self.launch(dest)
            self.job = {"state": "done", "pct": 1, "file": os.path.basename(dest),
                        "step": "Άνοιξε η εγκατάσταση του Npcap. Πάτα «Ναι» στα Windows, τσέκαρε «WinPcap API-compatible Mode» "
                                "και «Install». Μετά πάτα «🟢 Πέρασε σε Live τώρα»."}
        except Exception as e:  # noqa: BLE001
            self.job = {"state": "error", "step": str(e)[:300]}
