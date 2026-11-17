"""Λειτουργία «agent»: το NetWatch τρέχει σε server του σπιτιού (π.χ. VM/LXC στο Proxmox ή Raspberry Pi)
και το ανοίγεις από τον Mac/κινητό μέσα από το LAN.

Επειδή πια δεν ακούει μόνο στο 127.0.0.1:
- HTTPS με δικό του (self-signed) πιστοποιητικό· τυπώνεται το SHA-256 fingerprint για να το επιβεβαιώσεις στον browser·
- κάθε αίτημα θέλει το μυστικό token (μία φορά: https://<agent>:8765/?token=… → cookie HttpOnly/Secure/SameSite=Strict)·
- POST μόνο από την ίδια τη σελίδα (Origin == Host) — προστασία από CSRF·
- το τερματικό της Ακαδημίας και το «κλείσιμο» είναι απενεργοποιημένα (θα έτρεχαν στον server).
"""
import hashlib
import hmac
import os
import secrets
import ssl
import subprocess

COOKIE = "nwtok"
DENY = {"/api/shell", "/api/shutdown"}


def _private_write(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def load_token(data_dir, cfg_token=None):
    if cfg_token:
        return str(cfg_token)
    path = os.path.join(data_dir, "agent-token")
    if os.path.exists(path):
        with open(path) as f:
            tok = f.read().strip()
        if len(tok) >= 20:
            return tok
    tok = secrets.token_urlsafe(24)
    os.makedirs(data_dir, exist_ok=True)
    _private_write(path, tok + "\n")
    return tok


def ensure_cert(data_dir, cn="netwatch-agent"):
    crt, key = os.path.join(data_dir, "agent.crt"), os.path.join(data_dir, "agent.key")
    if not (os.path.exists(crt) and os.path.exists(key)):
        os.makedirs(data_dir, exist_ok=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "825", "-subj", f"/CN={cn}", "-keyout", key, "-out", crt],
                       check=True, capture_output=True, timeout=30)
        os.chmod(key, 0o600)
    with open(crt) as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    fp = hashlib.sha256(der).hexdigest().upper()
    return crt, key, ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


def tls_context(crt, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(crt, key)
    return ctx


def token_from(headers):
    auth = headers.get("Authorization") or ""
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    for part in (headers.get("Cookie") or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE:
            return v
    return None


def authorized(headers, token):
    got = token_from(headers)
    return bool(got) and hmac.compare_digest(got.encode(), token.encode())


def same_origin(headers):
    """Αν υπάρχει Origin, πρέπει να είναι ο ίδιος host:port με το Host (η σελίδα του agent)."""
    from urllib.parse import urlparse
    origin = headers.get("Origin")
    if origin is None:
        return True
    o = urlparse(origin)
    return o.scheme == "https" and o.netloc == (headers.get("Host") or "")


LOGIN_PAGE = """<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch agent</title><body style="background:#0b1220;color:#cfe0f5;font:15px system-ui;display:grid;place-items:center;min-height:90vh">
<form method="get" action="/" style="background:#111b2e;padding:22px;border-radius:10px;max-width:360px">
<h2 style="margin:0 0 8px;color:#fff">🔐 NetWatch agent</h2>
<p style="margin:0 0 12px">Γράψε το token που τύπωσε ο agent στην εκκίνηση (ή <code>cat data/agent-token</code> στον server).</p>
<input name="token" type="password" autofocus style="width:100%;padding:8px;border-radius:6px;border:1px solid #1f3352;background:#060a12;color:#fff">
<button style="margin-top:10px;padding:8px 14px;border-radius:6px;border:0;background:#2b7fff;color:#fff">Είσοδος</button></form></body>"""
