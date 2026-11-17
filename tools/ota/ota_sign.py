#!/usr/bin/env python3
"""Υπογραφή firmware για το υπογεγραμμένο OTA του NetWatch (ESP32 sentinel / canary).

ΤΡΕΧΕΙ ΣΤΟΝ ΥΠΟΛΟΓΙΣΤΗ ΣΟΥ (π.χ. το Mac), ΟΧΙ στον OTA server: το ιδιωτικό
κλειδί δεν πρέπει να βρεθεί ποτέ στον server.

  # μία φορά: νέο ζεύγος κλειδιών (προεπιλογή: ~/.netwatch-ota, ΕΞΩ από το repository)
  python3 tools/ota/ota_sign.py --genkey [--keydir ~/.netwatch-ota]
      -> ota_signing.pem (ΙΔΙΩΤΙΚΟ, chmod 600), ota_public.pem, ota_public.h

  # σε κάθε έκδοση
  python3 tools/ota/ota_sign.py build/esp32-canary.ino.bin --version 1.2.0 --device-class canary \\
      [--key ~/.netwatch-ota/ota_signing.pem] [--out ~/.netwatch-ota/repo]
      -> <out>/canary/1.2.0.bin + <out>/canary/manifest.json

  # έλεγχος (π.χ. πριν ανεβάσεις, ή ό,τι βρίσκεται ήδη στον server)
  python3 tools/ota/ota_sign.py --verify ~/.netwatch-ota/repo/canary/manifest.json [--pub ...]

Κρυπτογραφία: καλεί το εργαλείο γραμμής εντολών `openssl` (subprocess), ώστε να
μη χρειάζεται καμία νέα εξάρτηση Python (το .venv του NetWatch δεν έχει το
πακέτο `cryptography`). Δουλεύει με OpenSSL 1.1/3.x και με το LibreSSL του macOS.

Τι υπογράφεται (ίδια μορφή με το firmware/common/signed_ota.cpp):

    b"netwatch-ota/1\\n<class>\\n<version>\\n<size>\\n<sha256 hex του .bin>\\n"

ECDSA P-256 με SHA-256 (`openssl dgst -sha256 -sign`), υπογραφή DER σε base64.
Το firmware κάνει ακριβώς το αντίστροφο: SHA-256 του κειμένου (32 bytes) και
mbedtls_pk_verify(MBEDTLS_MD_SHA256, hash, 32, sig_der). Η έκδοση και η κατηγορία
είναι ΜΕΣΑ στην υπογραφή, ώστε ένας παραβιασμένος server να μην μπορεί να
"μετονομάσει" ένα παλιό υπογεγραμμένο .bin σε νεότερη έκδοση (rollback).
"""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

FORMAT = 1
MAGIC = "netwatch-ota/1"
CLASSES = ("canary", "sentinel")
VERSION_RX = re.compile(r"^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$")
ESP_IMAGE_MAGIC = 0xE9
APP_PARTITION_DEFAULT = 1310720   # 1.25 MB: το app partition του "Default 4MB with spiffs"
MIN_SIZE = 1024
HOME_DIR = os.path.join(os.path.expanduser("~"), ".netwatch-ota")


class OtaError(Exception):
    pass


# --------------------------------------------------------------------------- βοηθητικά
def parse_version(v):
    m = VERSION_RX.match(v or "")
    if not m:
        raise OtaError(f"μη έγκυρη έκδοση {v!r}: θέλω MAJOR.MINOR.PATCH, μόνο αριθμούς (π.χ. 1.2.0)")
    t = tuple(int(x) for x in m.groups())
    if any(x > 65535 for x in t):
        raise OtaError(f"μη έγκυρη έκδοση {v!r}: κάθε μέρος <= 65535")
    return t


def statement(cls, version, size, sha256_hex):
    """Τα bytes που υπογράφονται. ΠΡΕΠΕΙ να ταιριάζει με το buildStatement() του firmware."""
    return f"{MAGIC}\n{cls}\n{version}\n{int(size)}\n{sha256_hex}\n".encode("ascii")


def openssl_bin():
    exe = shutil.which("openssl")
    if not exe:
        raise OtaError("δεν βρέθηκε το `openssl` στο PATH")
    return exe


def run_openssl(args, data=None):
    p = subprocess.run([openssl_bin()] + args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise OtaError(f"openssl {args[0]} απέτυχε: {p.stderr.decode(errors='replace').strip()}")
    return p.stdout


def public_pem_from_private(key_path):
    return run_openssl(["ec", "-in", key_path, "-pubout"]).decode("ascii")


def check_key_is_p256(key_path):
    text = run_openssl(["ec", "-in", key_path, "-noout", "-text"]).decode(errors="replace")
    if "prime256v1" not in text and "P-256" not in text:
        raise OtaError(f"{key_path}: το κλειδί δεν είναι EC P-256 (prime256v1)")


def sign_bytes(key_path, data):
    """ECDSA-SHA256 υπογραφή DER."""
    return run_openssl(["dgst", "-sha256", "-sign", key_path], data)


def verify_bytes(pub_pem_path, data, sig_der):
    """True αν η υπογραφή DER είναι έγκυρη για τα data (ECDSA-SHA256)."""
    with tempfile.TemporaryDirectory() as td:
        sp = os.path.join(td, "sig.der")
        with open(sp, "wb") as f:
            f.write(sig_der)
        p = subprocess.run([openssl_bin(), "dgst", "-sha256", "-verify", pub_pem_path, "-signature", sp],
                           input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return p.returncode == 0 and b"Verified OK" in p.stdout


def c_header(pub_pem):
    return (
        "// NetWatch OTA: ΔΗΜΟΣΙΟ κλειδί υπογραφής (ECDSA P-256), φτιαγμένο από tools/ota/ota_sign.py --genkey\n"
        "// Επικόλλησέ το στο secrets.h του sketch (OTA_PUBKEY_PEM). Δεν είναι μυστικό: μόνο ΕΛΕΓΧΕΙ υπογραφές.\n"
        "// Το ιδιωτικό ota_signing.pem ΔΕΝ μπαίνει ποτέ σε firmware, repository ή server.\n"
        "static const char OTA_PUBKEY_PEM[] = R\"PEM(\n" + pub_pem.strip() + "\n)PEM\";\n"
    )


# --------------------------------------------------------------------------- genkey
def inside_git_repo(path):
    d = os.path.abspath(path)
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def genkey(keydir, force=False):
    os.makedirs(keydir, mode=0o700, exist_ok=True)
    key = os.path.join(keydir, "ota_signing.pem")
    pub = os.path.join(keydir, "ota_public.pem")
    hdr = os.path.join(keydir, "ota_public.h")
    if os.path.exists(key) and not force:
        raise OtaError(f"{key} υπάρχει ήδη. Δεν το αντικαθιστώ (οι συσκευές εμπιστεύονται το δημόσιο κλειδί του). "
                       "Για αλλαγή κλειδιού δες «Αλλαγή κλειδιού» στο README (και --force).")
    if os.path.exists(key):   # --force: κρατάμε αντίγραφο, ΧΩΡΙΣ αυτό οι υπάρχουσες συσκευές μένουν "ορφανές"
        import time
        bak = f"{key}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
        os.replace(key, bak)
        print(f"⚠ το παλιό κλειδί μετακινήθηκε στο {bak}: θα το χρειαστείς για να υπογράψεις το firmware "
              "που φέρνει το ΝΕΟ δημόσιο κλειδί στις συσκευές (README: «Αλλαγή κλειδιού»)", file=sys.stderr)
    old = os.umask(0o077)
    try:
        tmp = key + ".tmp"
        run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", tmp])
        os.chmod(tmp, 0o600)
        os.replace(tmp, key)
    finally:
        os.umask(old)
    os.chmod(key, 0o600)
    pem = public_pem_from_private(key)
    with open(pub, "w") as f:
        f.write(pem)
    with open(hdr, "w") as f:
        f.write(c_header(pem))
    return key, pub, hdr


# --------------------------------------------------------------------------- sign
def read_manifest(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def sign_firmware(bin_path, key_path, version, cls, out_dir, allow_any_bin=False, max_size=APP_PARTITION_DEFAULT):
    if cls not in CLASSES:
        raise OtaError(f"άγνωστη κατηγορία {cls!r} (επιτρέπονται: {', '.join(CLASSES)})")
    ver = parse_version(version)
    with open(bin_path, "rb") as f:
        data = f.read()
    size = len(data)
    if size < MIN_SIZE:
        raise OtaError(f"{bin_path}: πολύ μικρό ({size} bytes) για firmware")
    if not allow_any_bin and data[0] != ESP_IMAGE_MAGIC:
        raise OtaError(f"{bin_path}: δεν ξεκινά με 0xE9 (ESP app image). Μήπως είναι το *.merged.bin ή "
                       "*.bootloader.bin; Θέλω το <sketch>.ino.bin")
    if size > max_size:
        raise OtaError(f"{bin_path}: {size} bytes > {max_size} (μέγεθος app partition)")
    check_key_is_p256(key_path)

    cls_dir = os.path.join(out_dir, cls)
    man_path = os.path.join(cls_dir, "manifest.json")
    if os.path.exists(man_path):
        try:
            prev = str(read_manifest(man_path).get("version", "0.0.0"))
            prev_t = parse_version(prev)
        except (ValueError, OtaError):   # χαλασμένο παλιό manifest: απλώς το αντικαθιστούμε
            prev_t = None
        if prev_t is not None and prev_t >= ver:
            raise OtaError(f"η έκδοση {version} δεν είναι μεγαλύτερη από την τωρινή {prev} στο {man_path}. "
                           "Οι συσκευές δέχονται μόνο ΑΥΣΤΗΡΑ νεότερη έκδοση (anti-rollback): ανέβασε τον αριθμό.")

    sha = hashlib.sha256(data).hexdigest()
    msg = statement(cls, version, size, sha)
    sig = sign_bytes(key_path, msg)

    # Αυτοέλεγχος: επαληθεύουμε αμέσως με το δημόσιο κλειδί, όπως θα κάνει η συσκευή.
    with tempfile.TemporaryDirectory() as td:
        pub = os.path.join(td, "pub.pem")
        with open(pub, "w") as f:
            f.write(public_pem_from_private(key_path))
        if not verify_bytes(pub, msg, sig):
            raise OtaError("η υπογραφή δεν επαληθεύτηκε αμέσως μετά τη δημιουργία της (;!)")

    manifest = {
        "format": FORMAT,
        "class": cls,
        "version": version,
        "size": size,
        "sha256": sha,
        "sig": base64.b64encode(sig).decode("ascii"),
    }
    os.makedirs(cls_dir, exist_ok=True)
    bin_out = os.path.join(cls_dir, f"{version}.bin")
    tmp_bin, tmp_man = bin_out + ".tmp", man_path + ".tmp"
    with open(tmp_bin, "wb") as f:
        f.write(data)
    with open(tmp_man, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    # Πρώτα το .bin, μετά το manifest: μια συσκευή δεν βλέπει ποτέ manifest χωρίς το .bin του.
    os.replace(tmp_bin, bin_out)
    os.replace(tmp_man, man_path)
    return bin_out, man_path, manifest


# --------------------------------------------------------------------------- verify
def verify_manifest(man_path, pub_path, bin_path=None):
    """Ελέγχει manifest (+ το .bin δίπλα του) όπως η συσκευή. Επιστρέφει το manifest ή OtaError."""
    m = read_manifest(man_path)
    for k in ("format", "class", "version", "size", "sha256", "sig"):
        if k not in m:
            raise OtaError(f"λείπει το πεδίο {k!r}")
    if m["format"] != FORMAT:
        raise OtaError(f"άγνωστο format {m['format']!r}")
    parse_version(m["version"])
    if bin_path is None:
        bin_path = os.path.join(os.path.dirname(man_path), f"{m['version']}.bin")
    with open(bin_path, "rb") as f:
        data = f.read()
    if len(data) != m["size"]:
        raise OtaError(f"μέγεθος {len(data)} != {m['size']} του manifest")
    if hashlib.sha256(data).hexdigest() != m["sha256"]:
        raise OtaError("το sha256 του .bin δεν ταιριάζει με το manifest")
    sig = base64.b64decode(m["sig"], validate=True)
    if not verify_bytes(pub_path, statement(m["class"], m["version"], m["size"], m["sha256"]), sig):
        raise OtaError("ΜΗ ΕΓΚΥΡΗ υπογραφή")
    return m


# --------------------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(description="Υπογραφή firmware για το NetWatch signed OTA (openssl subprocess).")
    ap.add_argument("firmware", nargs="?", help="το <sketch>.ino.bin (ΟΧΙ το merged.bin)")
    ap.add_argument("--genkey", action="store_true", help="νέο ζεύγος κλειδιών ECDSA P-256")
    ap.add_argument("--keydir", default=HOME_DIR, help=f"φάκελος για --genkey (προεπιλογή: {HOME_DIR})")
    ap.add_argument("--force", action="store_true", help="με --genkey: αντικατάσταση υπάρχοντος κλειδιού")
    ap.add_argument("--key", default=os.path.join(HOME_DIR, "ota_signing.pem"), help="ιδιωτικό κλειδί (ota_signing.pem)")
    ap.add_argument("--version", dest="fw_version", help="έκδοση firmware, π.χ. 1.2.0 (= FW_VERSION του sketch)")
    ap.add_argument("--device-class", choices=CLASSES, help="canary | sentinel")
    ap.add_argument("--out", default=os.path.join(HOME_DIR, "repo"), help="φάκελος εξόδου (αυτόν ανεβάζεις στον server)")
    ap.add_argument("--max-size", type=int, default=APP_PARTITION_DEFAULT, help="μέγιστο μέγεθος (app partition)")
    ap.add_argument("--verify", metavar="MANIFEST", help="έλεγχος manifest.json + .bin με το δημόσιο κλειδί")
    ap.add_argument("--pub", default=os.path.join(HOME_DIR, "ota_public.pem"), help="δημόσιο κλειδί για --verify")
    a = ap.parse_args(argv)
    try:
        if a.genkey:
            repo = inside_git_repo(a.keydir)
            if repo:
                print(f"⚠ ο φάκελος {a.keydir} είναι μέσα στο git repository {repo}: πρόσεξε να μη γίνει ποτέ "
                      "commit το ota_signing.pem (καλύτερα: --keydir ~/.netwatch-ota)", file=sys.stderr)
            key, pub, hdr = genkey(a.keydir, a.force)
            print(f"✔ ιδιωτικό κλειδί: {key}  (chmod 600, ΜΗΝ το ανεβάσεις πουθενά, κράτα αντίγραφο offline)")
            print(f"✔ δημόσιο κλειδί:  {pub}")
            print(f"✔ για το firmware: {hdr}  -> επικόλλησέ το στο secrets.h (OTA_PUBKEY_PEM)")
            return 0
        if a.verify:
            m = verify_manifest(a.verify, a.pub, a.firmware)
            print(f"✔ έγκυρο: {m['class']} {m['version']}, {m['size']} bytes, sha256 {m['sha256'][:16]}…")
            return 0
        if not (a.firmware and a.fw_version and a.device_class):
            ap.error("χρειάζονται: <firmware.bin> --version --device-class [--key]  (ή --genkey / --verify)")
        bin_out, man_path, m = sign_firmware(a.firmware, a.key, a.fw_version, a.device_class, a.out,
                                             max_size=a.max_size)
        print(f"✔ {bin_out}  ({m['size']} bytes, sha256 {m['sha256'][:16]}…)")
        print(f"✔ {man_path}")
        print(f"  Ανέβασε ΜΟΝΟ αυτά τα δύο στον server, π.χ.:  rsync -av {a.out}/ <χρήστης>@<server>:/srv/ota/")
        return 0
    except (OtaError, OSError) as e:
        print(f"✘ {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
