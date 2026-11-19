"""Windows 10/11: ό,τι στο macOS/Linux κάνουν τα route / ifconfig / arp / ping / osascript.

Όλοι οι parsers είναι καθαρές συναρτήσεις (δοκιμάζονται και σε macOS/Linux, βλ. tests/test_winplat.py).
Στα Windows η έξοδος των εργαλείων είναι μεταφρασμένη (π.χ. «Απάντηση από …»), οπότε δεν στηριζόμαστε σε
λέξεις: μόνο σε IP, MAC, «ms», «TTL=» και «%», που μένουν ίδια σε κάθε γλώσσα.

Η καταγραφή πακέτων θέλει Npcap (https://npcap.com) — το scapy το χρησιμοποιεί αυτόματα.
"""
import json
import os
import re
import subprocess
import sys
import time

IS_WIN = os.name == "nt"
NPCAP_URL = "https://npcap.com/#download"
CREATE_NO_WINDOW = 0x08000000


# ---------------- subprocess: κωδικοσελίδα + χωρίς παράθυρο κονσόλας ----------------
def install_subprocess_defaults():
    """Στα Windows τα ping/arp/route/netsh γράφουν στην κωδικοσελίδα OEM (π.χ. cp737 για ελληνικά), όχι UTF-8.
    Με text=True η Python θα τα αποκωδικοποιούσε ως UTF-8 και θα έριχνε UnicodeDecodeError σε κάθε ελληνικό
    γράμμα. Εδώ βάζουμε ως προεπιλογή encoding="oem" + errors="replace" (μόνο όταν ο καλών δεν όρισε δικό του),
    και CREATE_NO_WINDOW ώστε να μην «αναβοσβήνει» παράθυρο κονσόλας σε κάθε εντολή."""
    if not IS_WIN or getattr(subprocess.Popen, "_netwatch_patched", False):
        return
    orig = subprocess.Popen.__init__

    def init(self, *a, **kw):
        if kw.get("text") or kw.get("universal_newlines"):
            if kw.get("encoding") is None:
                kw["encoding"] = "oem"
            if kw.get("errors") is None:
                kw["errors"] = "replace"
        kw["creationflags"] = kw.get("creationflags", 0) | CREATE_NO_WINDOW
        orig(self, *a, **kw)

    subprocess.Popen.__init__ = init
    subprocess.Popen._netwatch_patched = True


def run(cmd, timeout=8):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout or ""
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""


def powershell(script, timeout=15):
    """PowerShell χωρίς προφίλ· επιστρέφει stdout ('' αν αποτύχει). Η έξοδος βγαίνει σε UTF-8, ώστε ονόματα
    διεπαφών/δικτύων με ελληνικά να μη γίνονται «?» όταν η κωδικοσελίδα OEM δεν τα έχει."""
    try:
        return subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                               "-Command", "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n" + script],
                              capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


# ---------------- δικαιώματα / διεργασίες ----------------
def is_admin():
    if not IS_WIN:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def pid_alive(pid):
    """Στα Windows το os.kill(pid, 0) ΔΕΝ ελέγχει απλώς — στέλνει CTRL_C_EVENT (=0). Ρωτάμε το Win32 API."""
    import ctypes
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return ctypes.GetLastError() == 5  # ACCESS_DENIED = υπάρχει, αλλά δεν είναι δική μας
    try:
        code = ctypes.c_ulong()
        if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
            return True
        return code.value == 259  # STILL_ACTIVE
    finally:
        k32.CloseHandle(h)


# ---------------- Npcap ----------------
def npcap_installed():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return any(os.path.exists(os.path.join(root, d, "Npcap", "wpcap.dll")) for d in ("System32", "SysWOW64"))


# ---------------- δίκτυο: διεπαφές, προεπιλεγμένη διαδρομή, DNS ----------------
_PS_NET = r"""
$ErrorActionPreference = 'SilentlyContinue'
$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
     Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
$ifs = @(foreach ($a in Get-NetAdapter) {
  $ip = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex)
  [pscustomobject]@{
    name = $a.Name; index = [int]$a.ifIndex; up = ($a.Status -eq 'Up'); mtu = [int]$a.MtuSize
    mac = $a.MacAddress; desc = $a.InterfaceDescription
    ipv4 = @($ip | Where-Object { $_.AddressFamily -eq 'IPv4' } | ForEach-Object { @{ addr = $_.IPAddress; prefix = [int]$_.PrefixLength } })
    ipv6 = @($ip | Where-Object { $_.AddressFamily -eq 'IPv6' } | ForEach-Object { @{ addr = $_.IPAddress; prefix = [int]$_.PrefixLength } })
  }
})
$dns = @(Get-DnsClientServerAddress -InterfaceIndex $r.ifIndex | ForEach-Object { $_.ServerAddresses })
[pscustomobject]@{ gateway = $r.NextHop; gateway_index = $r.ifIndex; interfaces = $ifs; dns = $dns } |
  ConvertTo-Json -Depth 6 -Compress
"""


def _aslist(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def norm_mac(m):
    """'08-AA-89-41-26-04' → '08:aa:89:41:26:04'."""
    if not m:
        return None
    parts = re.split(r"[-:]", str(m).strip().lower())
    return ":".join(p.zfill(2) for p in parts) if len(parts) == 6 else None


def parse_net_json(text):
    """Η έξοδος του _PS_NET → {"interfaces": [σχήμα όπως netkit.parse_ifconfig], "gateway", "gateway_iface", "dns"}."""
    try:
        d = json.loads(text or "")
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    ifs, gw_if = [], None
    for a in _aslist(d.get("interfaces")):
        if not isinstance(a, dict) or not a.get("name"):
            continue
        cur = {"name": a["name"], "up": bool(a.get("up")), "mtu": a.get("mtu") or None, "mac": norm_mac(a.get("mac")),
               "desc": a.get("desc") or "", "index": a.get("index"),
               "ipv4": [{"addr": x.get("addr"), "prefix": x.get("prefix"), "broadcast": None}
                        for x in _aslist(a.get("ipv4")) if isinstance(x, dict) and x.get("addr")],
               "ipv6": [{"addr": str(x.get("addr")).split("%")[0], "prefix": x.get("prefix")}
                        for x in _aslist(a.get("ipv6")) if isinstance(x, dict) and x.get("addr")]}
        ifs.append(cur)
        if d.get("gateway_index") is not None and a.get("index") == d.get("gateway_index"):
            gw_if = a["name"]
    gw = d.get("gateway")
    if gw in ("0.0.0.0", ""):
        gw = None
    return {"interfaces": ifs, "gateway": gw, "gateway_iface": gw_if,
            "dns": [s for s in _aslist(d.get("dns")) if isinstance(s, str)]}


_ROUTE_DEFAULT = re.compile(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)", re.M)


def parse_route_print(text):
    """`route print -4` (εφεδρικό, αν λείπει το PowerShell) → (gateway, η IP μου) με τη μικρότερη μετρική."""
    best = None
    for gw, me, metric in _ROUTE_DEFAULT.findall(text or ""):
        if best is None or int(metric) < best[2]:
            best = (gw, me, int(metric))
    return (best[0], best[1]) if best else (None, None)


_cache = {"t": 0.0, "v": None}


def net_info(max_age=10):
    """Διεπαφές + προεπιλεγμένη διαδρομή (με cache: το PowerShell κάνει ~1 δευτ. να ξεκινήσει)."""
    if _cache["v"] is not None and time.time() - _cache["t"] < max_age:
        return _cache["v"]
    v = parse_net_json(powershell(_PS_NET))
    if not v or not v.get("interfaces"):
        gw, me = parse_route_print(run(["route", "print", "-4"]))
        v = {"interfaces": [], "gateway": gw, "gateway_iface": None, "dns": [], "my_ip": me}
        if me:
            v["interfaces"] = [{"name": _scapy_iface_for(me) or "?", "up": True, "mtu": None, "mac": None, "desc": "",
                                "index": None, "ipv4": [{"addr": me, "prefix": None, "broadcast": None}], "ipv6": []}]
            v["gateway_iface"] = v["interfaces"][0]["name"]
    _cache.update(t=time.time(), v=v)
    return v


def _scapy_iface_for(ip):
    try:
        from scapy.all import conf
        for i in conf.ifaces.values():
            if ip in (getattr(i, "ips", {}) or {}).get(4, []) or getattr(i, "ip", None) == ip:
                return i.name
    except Exception:
        pass
    return None


def detect_net(iface=None):
    """Όπως core.detect_net: (όνομα διεπαφής, router, {οι IP μου})."""
    v = net_info()
    name = iface or v.get("gateway_iface")
    me = set()
    for i in v.get("interfaces", []):
        if i["name"] == name:
            me |= {a["addr"] for a in i["ipv4"]} | {a["addr"] for a in i["ipv6"]}
    if not me and v.get("my_ip"):
        me.add(v["my_ip"])
    return name, v.get("gateway"), me


# ---------------- ARP ----------------
_ARP = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s", re.M)


def parse_arp(text):
    """`arp -a` → [(ip, mac)]. Χωρίς broadcast/multicast (ff-ff-…, 01-00-5e-…)."""
    out = []
    for ip, mac in _ARP.findall(text or ""):
        m = norm_mac(mac)
        if m == "ff:ff:ff:ff:ff:ff" or m.startswith("01:00:5e") or m.startswith("33:33"):
            continue
        if ip.endswith(".255") or int(ip.split(".")[0]) >= 224:
            continue
        out.append((ip, m))
    return out


def arp_table():
    return parse_arp(run(["arp", "-a"]))


# ---------------- ping ----------------
def ping_cmd(host, count=1, timeout_ms=2000):
    """Το ping των Windows: -n πλήθος, -w χρονικό όριο (ms) ανά πακέτο· δεν έχει διάστημα (στέλνει ανά ~1 δευτ.)."""
    return ["ping", "-6" if ":" in host else "-4", "-n", str(int(count)), "-w", str(int(timeout_ms)), host]


_RTT = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.I)
_TTL = re.compile(r"\bTTL=(\d+)", re.I)


def ping_to_unix(text, host, count):
    """Η (μεταφρασμένη) έξοδος του ping των Windows → γραμμές όπως του Linux, ώστε να δουλεύουν οι υπάρχοντες parsers.

    Απάντηση = γραμμή που περιέχει «<host>:» και χρόνο «=12ms» ή «<1ms». Οι γραμμές «Destination host
    unreachable» έχουν την IP αλλά όχι χρόνο, οπότε σωστά δεν μετράνε. Η σύνοψη (Minimum = 1ms…) δεν έχει «host:».
    """
    lines, n = [], 0
    for line in (text or "").splitlines():
        if f"{host}:" not in line and f"[{host}]:" not in line:
            continue
        m = _RTT.search(line)
        if not m:
            continue
        t = m.group(1).replace(",", ".")
        ttl = _TTL.search(line)
        lines.append(f"64 bytes from {host}: icmp_seq={n} " + (f"ttl={ttl.group(1)} " if ttl else "") + f"time={t} ms")
        n += 1
    lines.append(f"{int(count)} packets transmitted, {n} packets received")
    return "\n".join(lines)


def ping(host, count=1, timeout_ms=2000):
    """Τρέχει ping και επιστρέφει έξοδο σε μορφή Linux."""
    out = run(ping_cmd(host, count, timeout_ms), timeout=count * (timeout_ms / 1000 + 1) + 5)
    return ping_to_unix(out, host, count)


# ---------------- Wi-Fi (netsh) ----------------
def _sec(v):
    s = (v or "").lower()
    if "wpa3" in s or "sae" in s:
        return "wpa3_personal" if "enterprise" not in s else "wpa3_enterprise"
    if "wpa2" in s:
        return "wpa2_enterprise" if "enterprise" in s else "wpa2_personal"
    if "wpa" in s:
        return "wpa_personal"
    if "wep" in s:
        return "wep"
    return "none" if s else "unknown"


def _kv(text):
    for line in (text or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            yield k.strip(), v.strip()


def parse_netsh_interfaces(text):
    """`netsh wlan show interfaces` → {ssid, security, signal(dBm≈), channel, iface, phy, bssid} ή None.
    Οι ετικέτες μεταφράζονται, οπότε κοιτάμε «SSID»/«BSSID» (ίδια παντού) και αναγνωρίζουμε τις τιμές."""
    cur = {}
    for k, v in _kv(text):
        kl = k.lower()
        if kl == "ssid" and "ssid" not in cur:
            cur["ssid"] = v
        elif kl == "bssid" and "bssid" not in cur:
            cur["bssid"] = norm_mac(v)
        elif re.fullmatch(r"\d{1,3}\s*%", v) and "signal" not in cur:
            q = int(v.rstrip("% "))
            cur["signal"] = q // 2 - 100  # ίδια προσέγγιση με το nmcli
        elif re.search(r"(wpa|wep|open|ανοιχτ|ouvert|offen)", v, re.I) and "security" not in cur and kl != "ssid":
            cur["security"] = _sec(v) if not re.search(r"open|ανοιχτ|ouvert|offen", v, re.I) else "none"
        elif re.fullmatch(r"802\.11\w+", v) and "phy" not in cur:
            cur["phy"] = v
        elif re.fullmatch(r"\d{1,3}", v) and "channel" not in cur and (kl == "channel" or "κανάλι" in kl):
            cur["channel"] = v
    if not cur.get("ssid"):
        return None
    return {"ssid": cur["ssid"], "security": cur.get("security", "unknown"), "channel": cur.get("channel"),
            "signal": cur.get("signal"), "iface": "Wi-Fi", "phy": cur.get("phy"), "bssid": cur.get("bssid"),
            "others": []}


def wifi_info():
    return parse_netsh_interfaces(run(["netsh", "wlan", "show", "interfaces"]))


# ---------------- τείχος προστασίας (μπλοκάρισμα IP) ----------------
RULE_PREFIX = "NetWatch block"


def firewall_cmds(ip, add=True):
    name = f"{RULE_PREFIX} {ip}"
    if not add:
        return [["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]]
    return [["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={d}", "action=block",
             f"remoteip={ip}", "enable=yes", "profile=any"] for d in ("in", "out")]


# ---------------- ειδοποιήσεις (toast) ----------------
_PS_TOAST = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml('<toast><visual><binding template="ToastGeneric"><text/><text/></binding></visual><audio src="ms-winsoundevent:Notification.Default"/></toast>')
$t = $x.GetElementsByTagName('text')
$t.Item(0).AppendChild($x.CreateTextNode($env:NW_TITLE)) > $null
$t.Item(1).AppendChild($x.CreateTextNode($env:NW_BODY)) > $null
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($x))
"""


def toast(title, body):
    """Ειδοποίηση στο Κέντρο ειδοποιήσεων. Το κείμενο περνά από μεταβλητές περιβάλλοντος (όχι μέσα στο script)."""
    env = {**os.environ, "NW_TITLE": str(title)[:120], "NW_BODY": str(body)[:220]}
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _PS_TOAST],
                   capture_output=True, timeout=15, env=env)


def open_url(url):
    os.startfile(url)  # noqa: S606 — ανοίγει τον προεπιλεγμένο browser


def ensure_utf8_mode():
    """Τα αρχεία του NetWatch (κανόνες, μαθήματα, config) είναι UTF-8 με ελληνικά· στα Windows η Python ανοίγει
    αρχεία με την κωδικοσελίδα του συστήματος (cp1253). Αν δεν τρέχουμε σε UTF-8 mode, ξαναξεκινάμε με -X utf8."""
    if IS_WIN and not sys.flags.utf8_mode and not os.environ.get("NETWATCH_NO_REEXEC"):
        import subprocess as sp
        env = {**os.environ, "PYTHONUTF8": "1", "NETWATCH_NO_REEXEC": "1"}
        try:
            rc = sp.call([sys.executable, "-X", "utf8", *sys.argv], env=env)
        except KeyboardInterrupt:
            rc = 130
        sys.exit(rc)
