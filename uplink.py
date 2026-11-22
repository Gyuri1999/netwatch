"""📶 Εφεδρική γραμμή LTE — «έπεσε η γραμμή του πελάτη; εγώ συνεχίζω από το 4G και σε ειδοποιώ».

Το κουτί (ή οποιοσδήποτε υπολογιστής με NetWatch) μπορεί να έχει USB modem 4G/LTE ή tethering κινητού ως δεύτερη
έξοδο. Εδώ:
  1. Βρίσκουμε τις default routes με τα metrics τους (Linux `ip -j route`, macOS `netstat -rn`) και χαρακτηρίζουμε
     κάθε έξοδο: wired / wifi / cellular (wwan*, ppp*, usb* με RNDIS/ECM/NCM, ModemManager, tethering iPhone/Android).
  2. Κάθε ~30 s ελέγχουμε αν η ΚΥΡΙΑ (μικρότερο metric, όχι cellular) βγάζει Internet — με σύνδεση δεμένη στη
     συγκεκριμένη διεπαφή (SO_BINDTODEVICE σε Linux, IP_BOUND_IF σε macOS, αλλιώς bind στη διεύθυνση πηγής).
     Η εφεδρική ελέγχεται αραιά (κάθε 5′) για να μην τρώει δεδομένα· συνεχώς μόνο όταν έχει πέσει η κύρια.
  3. Αλλαγές κατάστασης → state.alert → ο υπάρχων notifier (ntfy/Telegram) φεύγει από όποια γραμμή δουλεύει.
  4. `on_backup()` = «οικονομία δεδομένων»: τα άλλα modules μπορούν να το ρωτούν και να αναβάλλουν βαριά downloads.
Μόνο ανάγνωση: δεν αλλάζουμε routes/metrics (αυτό το κάνει το tools/fieldbox/lte-setup.sh, μία φορά, από εσένα).

Uplink(state, cfg=None, demo=False, clock=time.time, net=None, data_dir=None)
  cfg (config.yaml → uplink:): expect_cellular, interval, backup_every, cap_gb, cellular_ifaces [..], hilink
"""
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

EVERY = 30
BACKUP_EVERY = 300
CONFIRM = 2                      # τόσοι συνεχόμενοι έλεγχοι πριν αλλάξει η κατάσταση (όχι ειδοποίηση για ένα χαμένο πακέτο)
TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 443))
MAX_EVENTS = 100
CELL_DRIVERS = ("rndis_host", "ipheth", "qmi_wwan", "cdc_mbim", "huawei_cdc_ncm", "sierra_net", "option", "hso", "cdc_wdm")
AMBIG_DRIVERS = ("cdc_ether", "cdc_ncm")      # modem σε λειτουργία HiLink ΑΛΛΑ και κανονικοί αντάπτορες USB‑Ethernet
TETHER_GW = ("192.168.8.1",       # Huawei HiLink
             "192.168.42.129",    # Android USB tethering
             "192.168.43.1",      # Android Wi‑Fi hotspot (παλιότερα)
             "172.20.10.1",       # iPhone Personal Hotspot (USB και Wi‑Fi)
             "192.168.225.1")     # modules Quectel/SIMCom (ECM/RNDIS)
ST = {"ok": ("Κύρια γραμμή ΟΚ", "Primary line OK"),
      "backup": ("Η κύρια γραμμή έπεσε — δουλεύω από LTE", "Primary line down — running on LTE"),
      "cellular": ("Μόνο LTE (δεν υπάρχει ενσύρματη γραμμή)", "LTE only (no wired line)"),
      "down": ("Χωρίς Internet — έπεσαν όλες οι γραμμές", "No Internet — all lines are down"),
      "unknown": ("Δεν έχει γίνει ακόμη έλεγχος", "Not checked yet")}


# ═════════════════════════════ καθαρές συναρτήσεις ═════════════════════════════
def parse_ip_route_json(text):
    """`ip -j route show default` → [{"dev","gw","metric","src"}] (metric 0 αν λείπει)."""
    try:
        rows = json.loads(text or "[]")
    except ValueError:
        return []
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict) or r.get("dst") != "default" or not r.get("dev"):
            continue
        try:
            metric = int(r.get("metric") or 0)
        except (TypeError, ValueError):
            metric = 0
        out.append({"dev": str(r["dev"])[:32], "gw": str(r.get("gateway") or ""), "metric": metric, "src": str(r.get("prefsrc") or "")})
    return sorted(out, key=lambda x: x["metric"])[:16]


def parse_ip_route(text):
    """`ip route show default` (κείμενο): «default via 192.168.1.1 dev eth0 proto dhcp metric 100»."""
    out = []
    for line in (text or "").splitlines():
        if not line.startswith("default"):
            continue
        dev = re.search(r"\bdev (\S+)", line)
        if not dev:
            continue
        via, met, src = re.search(r"\bvia (\S+)", line), re.search(r"\bmetric (\d+)", line), re.search(r"\bsrc (\S+)", line)
        out.append({"dev": dev.group(1)[:32], "gw": via.group(1) if via else "", "metric": int(met.group(1)) if met else 0,
                    "src": src.group(1) if src else ""})
    return sorted(out, key=lambda x: x["metric"])[:16]


def parse_netstat(text):
    """macOS `netstat -rn -f inet` → default routes. Δεν έχει metrics: η σειρά είναι η προτεραιότητα και η σημαία «I»
    (RTF_IFSCOPE) σημαίνει δευτερεύουσα — δίνουμε metric 0 στην κύρια και 100, 200… στις υπόλοιπες."""
    rows = []
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) < 4 or p[0] != "default":
            continue
        gw, flags, dev = p[1], p[2], p[3]
        if not re.match(r"^[A-Za-z]+\d+$", dev):
            continue
        rows.append({"dev": dev[:32], "gw": gw if re.match(r"^\d+\.\d+\.\d+\.\d+$", gw) else "", "scoped": "I" in flags, "src": ""})
    rows.sort(key=lambda r: r["scoped"])          # σταθερή ταξινόμηση: πρώτα η μη‑scoped
    out = []
    for i, r in enumerate(rows[:16]):
        out.append({"dev": r["dev"], "gw": r["gw"], "metric": 0 if not r["scoped"] and i == 0 else i * 100 or 100, "src": ""})
    return out


def classify(name, driver="", hw="", gw="", wireless=False, mm=False):
    """→ "cellular" | "wifi" | "wired" | "vpn" | "other". Καθαρή συνάρτηση.
    name: διεπαφή · driver: Linux driver · hw: όνομα θύρας macOS · gw: gateway · mm: τη διαχειρίζεται το ModemManager."""
    n, d, h = str(name or "").lower(), str(driver or "").lower(), str(hw or "").lower()
    if re.match(r"^(lo\d*$|docker|br-|veth|virbr|bridge|awdl|llw|anpi|ap\d)", n):
        return "other"
    if re.match(r"^(tun|tap|wg|utun|ipsec|tailscale|zt|gif|stf)", n):
        return "vpn"
    if mm or re.match(r"^(wwan|wwp|ppp|rmnet|ccmni)", n) or d in CELL_DRIVERS:
        return "cellular"
    if re.search(r"iphone|ipad|android|modem|lte|\b[45]g\b|huawei|zte|hilink|rndis|mobile broadband", h):
        return "cellular"
    if gw in TETHER_GW:                       # tethering από κινητό (ακόμη και μέσω Wi‑Fi) = δεδομένα κινητής
        return "cellular"
    if n.startswith("usb"):                   # usb0: RNDIS/ECM gadget — σχεδόν πάντα κινητό ή modem stick
        return "cellular"
    if wireless or re.match(r"^(wl|wlan|ath|ra\d)", n) or re.search(r"wi-?fi|airport", h):
        return "wifi"
    if d in AMBIG_DRIVERS and not re.match(r"^(eth|en)", n):
        return "cellular"
    if re.match(r"^(eth|en|em\d|bond|vlan)", n) or d:
        return "wired"
    return "other"


def parse_mmcli_list(text):
    """`mmcli -L` → [αριθμοί modem]."""
    return [int(x) for x in re.findall(r"/Modem/(\d+)", text or "")][:4]


def parse_mmcli_kv(text):
    """`mmcli -m N --output-keyvalue` → {"operator","signal","tech","state","model","ports": [διεπαφές net]}."""
    kv = {}
    for line in (text or "").splitlines()[:400]:
        k, sep, v = line.partition(":")
        if sep:
            kv.setdefault(k.strip(), v.strip()[:80])

    def g(key):
        v = kv.get(key, "")
        return "" if v in ("--", "") else v
    techs = [v for k, v in kv.items() if k.startswith("modem.generic.access-technologies.value[") and v not in ("--", "")]
    ports = []
    for k, v in kv.items():
        m = re.match(r"^(\S+) \(net\)$", v)
        if k.startswith("modem.generic.ports.value[") and m:
            ports.append(m.group(1))
    sig = g("modem.generic.signal-quality.value")
    return {"operator": g("modem.3gpp.operator-name"), "signal": int(sig) if sig.isdigit() and int(sig) <= 100 else None,
            "tech": "/".join(techs)[:20].upper(), "state": g("modem.generic.state"), "model": g("modem.generic.model"),
            "ports": ports[:4], "source": "ModemManager"}


_HILINK_NET = {"1": "2G", "2": "2G", "3": "2G", "41": "3G", "44": "3G", "45": "3G", "46": "3G", "19": "LTE", "101": "LTE"}


def parse_hilink(*xmls):
    """Απαντήσεις XML του Huawei HiLink (monitoring/status, net/current-plmn, device/signal) → ίδιο σχήμα με το mmcli."""
    kv = {}
    for x in xmls:
        for k, v in re.findall(r"<(\w{1,40})>([^<]{0,64})</\1>", str(x or "")[:8192]):
            kv.setdefault(k, v.strip())
    if not kv or "code" in kv and len(kv) <= 2:
        return None
    icon = kv.get("SignalIcon", "")
    sig = int(icon) * 20 if icon.isdigit() and int(icon) <= 5 else None
    nt = kv.get("CurrentNetworkType", "")
    out = {"operator": kv.get("FullName") or kv.get("ShortName") or "", "signal": sig, "tech": _HILINK_NET.get(nt, nt),
           "state": {"901": "connected", "902": "disconnected", "900": "connecting"}.get(kv.get("ConnectionStatus", ""), ""),
           "model": "", "ports": [], "source": "HiLink"}
    for k in ("rsrp", "rsrq", "rssi", "sinr"):
        if kv.get(k):
            out[k] = kv[k][:16]
    return out


def month_key(t):
    return time.strftime("%Y-%m", time.localtime(t))


def fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def fmt_dur(s):
    s = int(max(0, s))
    if s < 90:
        return f"{s} s"
    if s < 5400:
        return f"{s // 60} min"
    return f"{s / 3600:.1f} h"


# ═════════════════════════════ πραγματικό I/O ═════════════════════════════
def _run(cmd, timeout=4):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, "LC_ALL": "C", "LANG": "C"}).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


class Net:
    def __init__(self):
        self._hw, self._hw_t = {}, 0
        self._mm, self._mm_t = None, 0

    def routes(self):
        if sys.platform == "darwin":
            return parse_netstat(_run(["netstat", "-rn", "-f", "inet"]))
        if sys.platform.startswith("linux"):
            return parse_ip_route_json(_run(["ip", "-j", "-4", "route", "show", "default"])) or \
                parse_ip_route(_run(["ip", "-4", "route", "show", "default"]))
        return []

    def _hwports(self):
        if time.time() - self._hw_t > 60:
            self._hw_t = time.time()
            self._hw = {}
            for block in _run(["networksetup", "-listallhardwareports"]).split("\n\n"):
                p, d = re.search(r"Hardware Port:\s*(.+)", block), re.search(r"Device:\s*(\S+)", block)
                if p and d:
                    self._hw[d.group(1)] = p.group(1).strip()
        return self._hw

    def mm(self):
        """Στοιχεία από το ModemManager (αν υπάρχει) — κρατιούνται 60 s."""
        import shutil
        if time.time() - self._mm_t > 60:
            self._mm_t, self._mm = time.time(), None
            if shutil.which("mmcli"):
                ids = parse_mmcli_list(_run(["mmcli", "-L"]))
                if ids:
                    self._mm = parse_mmcli_kv(_run(["mmcli", "-m", str(ids[0]), "--output-keyvalue"]))
        return self._mm

    def info(self, dev):
        out = {"driver": "", "hw": "", "wireless": False, "ip": "", "rx": None, "tx": None, "mm": False}
        if not re.match(r"^[\w.:-]{1,32}$", dev or ""):
            return out
        base = f"/sys/class/net/{dev}"
        if os.path.isdir(base):
            try:
                out["driver"] = os.path.basename(os.readlink(base + "/device/driver"))
            except OSError:
                pass
            out["wireless"] = os.path.exists(base + "/wireless")
            for k, f in (("rx", "rx_bytes"), ("tx", "tx_bytes")):
                try:
                    with open(f"{base}/statistics/{f}") as fh:
                        out[k] = int(fh.read(32).strip())
                except (OSError, ValueError):
                    pass
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", _run(["ip", "-4", "-o", "addr", "show", "dev", dev]))
            out["ip"] = m.group(1) if m else ""
            mm = self.mm()
            out["mm"] = bool(mm and dev in (mm.get("ports") or []))
        elif sys.platform == "darwin":
            out["hw"] = self._hwports().get(dev, "")
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", _run(["ifconfig", dev]))
            out["ip"] = m.group(1) if m else ""
            for line in _run(["netstat", "-ibn", "-I", dev]).splitlines():
                p = line.split()
                if len(p) >= 10 and p[0] == dev and "<Link#" in line:
                    try:
                        out["rx"], out["tx"] = int(p[-5]), int(p[-2])
                    except ValueError:
                        pass
                    break
        return out

    def probe(self, dev, src="", timeout=3.0):
        """Βγαίνει Internet ΑΠΟ ΑΥΤΗ τη διεπαφή; Μία χειραψία TCP (λίγα bytes) → (ok, ms)."""
        for ip, port in TARGETS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                bound = False
                try:
                    if sys.platform.startswith("linux"):
                        s.setsockopt(socket.SOL_SOCKET, 25, dev.encode() + b"\0")      # SO_BINDTODEVICE (θέλει root/CAP_NET_RAW)
                        bound = True
                    elif sys.platform == "darwin":
                        s.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(dev))   # IP_BOUND_IF
                        bound = True
                except OSError:
                    bound = False
                if not bound:
                    if not src:
                        return False, None
                    s.bind((src, 0))
                t0 = time.monotonic()
                s.connect((ip, port))
                return True, round((time.monotonic() - t0) * 1000, 1)
            except OSError:
                continue
            finally:
                try:
                    s.close()
                except OSError:
                    pass
        return False, None

    def modem(self, up, hilink=True):
        mm = self.mm()
        if mm:
            return mm
        if hilink and up.get("gw") == "192.168.8.1":
            return self._hilink("192.168.8.1")
        return None

    def _hilink(self, ip):
        """Huawei HiLink: μόνο GET (SesTokInfo → status/plmn/signal). Τίποτα δεν αλλάζει στο modem."""
        import http.client

        def get(path, headers=None):
            c = http.client.HTTPConnection(ip, 80, timeout=3)
            try:
                c.request("GET", path, headers=headers or {})
                r = c.getresponse()
                return r.read(8192).decode("utf-8", "replace") if r.status == 200 else ""
            finally:
                c.close()
        try:
            tok = get("/api/webserver/SesTokInfo")
            ses, tk = re.search(r"<SesInfo>([^<]{1,256})</SesInfo>", tok), re.search(r"<TokInfo>([^<]{1,256})</TokInfo>", tok)
            h = {"Cookie": ses.group(1), "__RequestVerificationToken": tk.group(1)} if ses and tk else {}
            return parse_hilink(get("/api/monitoring/status", h), get("/api/net/current-plmn", h), get("/api/device/signal", h))
        except Exception:  # noqa: BLE001
            return None


# ═════════════════════════════ η κλάση ═════════════════════════════
class Uplink:
    def __init__(self, state, cfg=None, demo=False, clock=time.time, net=None, data_dir=None):
        self.state, self.demo, self.clock = state, demo, clock
        self.cfg = dict(cfg or {})
        self.net = net or Net()
        self.path = os.path.join(data_dir, "uplink.json") if data_dir else None
        self.on_save = None
        self.lock = threading.RLock()
        self.interval = max(10, int(self.cfg.get("interval") or EVERY))
        self.backup_every = max(self.interval, int(self.cfg.get("backup_every") or BACKUP_EVERY))
        self.status = "unknown"
        self.since = None                 # από πότε είμαστε στην τωρινή κατάσταση
        self.down_since = None            # από πότε είναι κάτω η κύρια
        self._pend, self._pend_n = None, 0
        self.ups = []
        self.checked = 0
        self.busy = False
        self.seen_primary = False
        self.seen_cell = False
        self._b_last, self._b_ok, self._b_ms = 0, None, None
        self._b_fail, self._b_alerted = 0, False
        self.modem = None
        self.events = []
        self.data = {"month": "", "bytes": 0, "last": {}}
        if demo:
            self._seed()
        else:
            self._load()

    # ── αποθήκευση ──
    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                j = json.load(f)
            self.events = [e for e in (j.get("events") or []) if isinstance(e, dict)][-MAX_EVENTS:]
            d = j.get("data") or {}
            self.data = {"month": str(d.get("month") or ""), "bytes": int(d.get("bytes") or 0),
                         "last": {str(k): int(v) for k, v in (d.get("last") or {}).items()}}
            self.seen_cell = bool(j.get("seen_cell"))
            self.seen_primary = bool(j.get("seen_primary"))
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save(self):
        if not self.path or self.demo:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"events": self.events, "data": self.data, "seen_cell": self.seen_cell,
                           "seen_primary": self.seen_primary}, f, ensure_ascii=False)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    def _seed(self):
        now = self.clock()
        self.status, self.since, self.checked = "ok", now - 2 * 86400 + 37 * 60, now - 12
        self.seen_primary = self.seen_cell = True
        self.ups = [{"dev": "eth0", "gw": "192.168.1.1", "metric": 100, "kind": "wired", "role": "primary", "ok": True, "ms": 11.4,
                     "ip": "192.168.1.50", "label": "Οπτική ίνα (router πελάτη)", "label_en": "Fibre (customer router)"},
                    {"dev": "wwan0", "gw": "10.64.64.64", "metric": 700, "kind": "cellular", "role": "backup", "ok": True, "ms": 48.0,
                     "ip": "10.64.64.65", "label": "LTE USB modem", "label_en": "LTE USB modem"}]
        self._b_ok, self._b_ms, self._b_last = True, 48.0, now - 140
        self.modem = {"operator": "COSMOTE", "signal": 71, "tech": "LTE", "state": "connected", "model": "E3372h", "ports": ["wwan0"],
                      "source": "ModemManager"}
        self.data = {"month": month_key(now), "bytes": 412 * 1024 * 1024, "last": {}}
        self.cfg.setdefault("cap_gb", 5)
        t0 = now - 2 * 86400
        self.events = [
            {"t": t0, "from": "ok", "to": "backup", "sev": "high", "el": "Έπεσε η κύρια γραμμή (eth0) — δουλεύω από LTE (wwan0, COSMOTE)",
             "en": "Primary line (eth0) went down — running on LTE (wwan0, COSMOTE)"},
            {"t": t0 + 37 * 60, "from": "backup", "to": "ok", "sev": "low", "el": "Η κύρια γραμμή (eth0) επανήλθε μετά από 37 min· πέρασαν 18.4 MB από LTE",
             "en": "Primary line (eth0) is back after 37 min; 18.4 MB went over LTE"}]

    # ── για τα άλλα modules ──
    def on_backup(self):
        """True όταν η κίνηση φεύγει από κινητή (ακριβά δεδομένα) → ανάβαλε βαριά downloads."""
        return self.status in ("backup", "cellular")

    # ── έλεγχος ──
    def _uplinks(self):
        forced = {str(x) for x in (self.cfg.get("cellular_ifaces") or [])}
        seen, out = set(), []
        for r in sorted(self.net.routes() or [], key=lambda x: x.get("metric") or 0):
            dev = r.get("dev")
            if not dev or dev in seen:
                continue
            seen.add(dev)
            try:
                inf = self.net.info(dev) or {}
            except Exception:  # noqa: BLE001
                inf = {}
            kind = "cellular" if dev in forced else classify(dev, inf.get("driver"), inf.get("hw"), r.get("gw"),
                                                             bool(inf.get("wireless")), bool(inf.get("mm")))
            if kind in ("vpn", "other"):
                continue
            out.append({"dev": dev, "gw": r.get("gw") or "", "metric": r.get("metric") or 0, "kind": kind, "role": "other",
                        "ok": None, "ms": None, "ip": inf.get("ip") or r.get("src") or "", "rx": inf.get("rx"), "tx": inf.get("tx"),
                        "driver": inf.get("driver") or "", "hw": inf.get("hw") or ""})
        prim = next((u for u in out if u["kind"] != "cellular"), None)
        back = next((u for u in out if u["kind"] == "cellular"), None)
        if prim:
            prim["role"] = "primary"
        if back:
            back["role"] = "backup"
        return out, prim, back

    def tick(self):
        """Ένας κύκλος ελέγχου. Επιστρέφει την κατάσταση."""
        if self.demo:
            return self.status
        now = self.clock()
        ups, prim, back = self._uplinks()
        if prim:
            try:
                prim["ok"], prim["ms"] = self.net.probe(prim["dev"], prim["ip"])
            except Exception:  # noqa: BLE001
                prim["ok"], prim["ms"] = False, None
        p_ok = bool(prim and prim["ok"])
        if back:
            if not p_ok or self._b_ok is None or now - self._b_last >= self.backup_every:
                try:
                    self._b_ok, self._b_ms = self.net.probe(back["dev"], back["ip"])
                except Exception:  # noqa: BLE001
                    self._b_ok, self._b_ms = False, None
                self._b_last = now
                try:
                    self.modem = self.net.modem(back, bool(self.cfg.get("hilink", True))) or self.modem
                except Exception:  # noqa: BLE001
                    pass
            back["ok"], back["ms"] = self._b_ok, self._b_ms
        else:
            self._b_ok, self._b_ms = None, None
        b_ok = bool(back and back["ok"])
        with self.lock:
            self.seen_primary = self.seen_primary or bool(prim)
            self.seen_cell = self.seen_cell or bool(back)
            self._count(ups, now)
            raw = "ok" if p_ok else ("backup" if self.seen_primary else "cellular") if b_ok else "down"
            self.ups, self.checked = ups, now
            self._transition(raw, prim, back, now)
            self._backup_health(prim, back, b_ok, now)
        self._save()
        return self.status

    def _count(self, ups, now):
        """Εκτίμηση δεδομένων κινητής αυτόν τον μήνα από τους μετρητές της διεπαφής (μηδενίζουν σε reboot/επανασύνδεση)."""
        mk = month_key(now)
        if self.data.get("month") != mk:
            self.data.update(month=mk, bytes=0)
        last = self.data.setdefault("last", {})
        for u in ups:
            if u["kind"] != "cellular" or u.get("rx") is None:
                continue
            cur = int(u["rx"] or 0) + int(u.get("tx") or 0)
            prev = last.get(u["dev"])
            if prev is not None:
                self.data["bytes"] += cur - prev if cur >= prev else cur
            last[u["dev"]] = cur

    def _alert(self, typ, sev, actor, detail, now, key, cooldown):
        st = self.state
        if st is None or not hasattr(st, "alert"):
            return
        try:
            st.alert(typ, sev, actor or "uplink", "Internet", detail, now, key=("uplink", key), cooldown=cooldown, mark=False)
        except Exception:  # noqa: BLE001
            pass

    def _event(self, frm, to, sev, el, en, now):
        self.events = (self.events + [{"t": now, "from": frm, "to": to, "sev": sev, "el": el, "en": en}])[-MAX_EVENTS:]

    def _transition(self, raw, prim, back, now):
        old = self.status
        if old == "unknown":              # πρώτος έλεγχος: υιοθετούμε χωρίς ειδοποίηση
            self.status, self.since = raw, now
            self.down_since = now if raw != "ok" else None
            self._bytes0 = self.data["bytes"]
            return
        if raw == old:
            self._pend, self._pend_n = None, 0
            return
        if raw == self._pend:
            self._pend_n += 1
        else:
            self._pend, self._pend_n = raw, 1
        if self._pend_n < CONFIRM:
            return
        self._pend, self._pend_n = None, 0
        self.status, self.since = raw, now
        pdev = (prim or {}).get("dev") or "—"
        bdev = (back or {}).get("dev") or "LTE"
        op = (self.modem or {}).get("operator") or ""
        via = bdev + (f", {op}" if op else "")
        if raw in ("backup", "cellular") and old in ("ok", "down"):
            if old == "ok":
                self.down_since, self._bytes0 = now, self.data["bytes"]
            el = f"Έπεσε η κύρια γραμμή ({pdev}) — δουλεύω από LTE ({via})"
            en = f"Primary line ({pdev}) went down — running on LTE ({via})"
            self._event(old, raw, "high", el, en, now)
            self._alert("Έπεσε η κύρια γραμμή — δουλεύω από LTE", "high", pdev,
                        f"Η κύρια γραμμή ({pdev}) δεν βγάζει Internet. Οι ειδοποιήσεις φεύγουν τώρα από την εφεδρική ({via}). "
                        "Έλεγξε το router/τη γραμμή του παρόχου.", now, "failover", 120)
        elif raw == "down":
            if old == "ok":
                self.down_since, self._bytes0 = now, self.data["bytes"]
            el = "Χωρίς Internet — έπεσαν όλες οι γραμμές" + ("" if back else " (δεν υπάρχει εφεδρική)")
            en = "No Internet — all lines are down" + ("" if back else " (there is no backup)")
            self._event(old, raw, "high", el, en, now)
            self._alert("Χωρίς Internet — έπεσαν όλες οι γραμμές", "high", pdev,
                        f"Ούτε η κύρια γραμμή ({pdev}) ούτε η εφεδρική βγάζουν Internet. Η ειδοποίηση θα σταλεί όταν επανέλθει κάποια γραμμή.",
                        now, "alldown", 120)
        elif raw == "ok" and old == "cellular":
            self._event(old, raw, "low", f"Βρέθηκε κύρια γραμμή ({pdev}) — το LTE γίνεται εφεδρεία",
                        f"Primary line found ({pdev}) — LTE becomes the backup", now)
        elif raw == "ok":
            dur =fmt_dur(now - self.down_since) if self.down_since else "?"
            used = max(0, self.data["bytes"] - getattr(self, "_bytes0", self.data["bytes"]))
            extra_el = f"· πέρασαν {fmt_bytes(used)} από LTE" if used and old != "down" else ""
            extra_en = f"; {fmt_bytes(used)} went over LTE" if used and old != "down" else ""
            el = f"Η κύρια γραμμή ({pdev}) επανήλθε μετά από {dur}{extra_el}"
            en = f"Primary line ({pdev}) is back after {dur}{extra_en}"
            self._event(old, raw, "low", el, en, now)
            self._alert("Η κύρια γραμμή επανήλθε", "low", pdev,
                        f"Η κύρια γραμμή ({pdev}) βγάζει ξανά Internet μετά από {dur}." + (f" Από την εφεδρική πέρασαν {fmt_bytes(used)}." if extra_el else ""),
                        now, "restored", 60)
            self.down_since = None

    def _backup_health(self, prim, back, b_ok, now):
        expect = bool(self.cfg.get("expect_cellular")) or self.seen_cell
        if not expect:
            return
        if b_ok:
            if self._b_alerted:
                self._event("backup_down", "backup_ok", "low", "Η εφεδρική γραμμή LTE δουλεύει ξανά", "The LTE backup line works again", now)
            self._b_fail, self._b_alerted = 0, False
            return
        self._b_fail += 1
        if self._b_fail < CONFIRM or self._b_alerted:
            return
        self._b_alerted = True
        why_el = "το modem δεν φαίνεται (χωρίς default route)" if not back else "δεν βγάζει Internet"
        why_en = "the modem is not visible (no default route)" if not back else "it cannot reach the Internet"
        self._event("backup_ok", "backup_down", "med", f"Η εφεδρική γραμμή LTE δεν δουλεύει: {why_el}",
                    f"The LTE backup line is not working: {why_en}", now)
        self._alert("Η εφεδρική γραμμή LTE δεν δουλεύει", "med", (back or {}).get("dev") or "LTE",
                    f"Η εφεδρική γραμμή LTE δεν δουλεύει: {why_el}. Έλεγξε SIM/υπόλοιπο δεδομένων, σήμα και το «mmcli -m 0». "
                    "Αν πέσει η κύρια γραμμή δεν θα λάβεις ειδοποιήσεις.", now, "backupdown", 6 * 3600)

    # ── προβολή ──
    def view(self):
        with self.lock:
            el, en = ST.get(self.status, ST["unknown"])
            ups = [{k: v for k, v in u.items() if k not in ("rx", "tx")} for u in self.ups]
            back = next((u for u in ups if u["role"] == "backup"), None)
            expect = bool(self.cfg.get("expect_cellular")) or self.seen_cell
            cap = self.cfg.get("cap_gb")
            try:
                cap = float(cap) if cap else None
            except (TypeError, ValueError):
                cap = None
            used = int(self.data.get("bytes") or 0)
            if self.status == "down":
                hint = ("Έλεγξε το router του πελάτη και την τροφοδοσία του modem. Οι ειδοποιήσεις θα φύγουν μόλις επανέλθει μια γραμμή.",
                        "Check the customer's router and the modem's power. Alerts will go out once a line returns.")
            elif self.status == "backup":
                hint = ("Δουλεύω από LTE: οι ειδοποιήσεις φτάνουν κανονικά, τα βαριά downloads αναβάλλονται. Έλεγξε router/γραμμή παρόχου.",
                        "Running on LTE: alerts still arrive, heavy downloads are postponed. Check the router / ISP line.")
            elif not back and not expect:
                hint = ("Δεν υπάρχει εφεδρική γραμμή. Με ένα USB modem 4G (~35 €) οι ειδοποιήσεις φτάνουν ακόμη κι όταν πέσει η γραμμή: tools/fieldbox/lte-setup.sh",
                        "There is no backup line. With a 4G USB modem (~€35) alerts still arrive when the line dies: tools/fieldbox/lte-setup.sh")
            elif expect and (not back or back.get("ok") is False):
                hint = ("Η εφεδρική LTE δεν δουλεύει: έλεγξε SIM/υπόλοιπο, σήμα, και «nmcli connection show» / «mmcli -m 0».",
                        "The LTE backup is not working: check SIM/balance, signal, and “nmcli connection show” / “mmcli -m 0”.")
            else:
                hint = ("Όλα καλά. Βεβαιώσου ότι το LTE έχει μεγαλύτερο metric από την κύρια (ip route) ώστε να είναι μόνο εφεδρεία.",
                        "All good. Make sure LTE has a higher metric than the primary (ip route) so it is backup only.")
            return {"demo": self.demo, "state": self.status, "el": el, "en": en, "on_backup": self.on_backup(), "since": self.since,
                    "down_since": self.down_since, "checked": self.checked, "busy": self.busy, "uplinks": ups,
                    "has_backup": bool(back), "expect_cellular": expect, "backup_ok": self._b_ok, "backup_checked": self._b_last or None,
                    "modem": dict(self.modem) if self.modem else None,
                    "data": {"month": self.data.get("month") or month_key(self.clock()), "bytes": used, "text": fmt_bytes(used),
                             "cap_gb": cap, "pct": round(100 * used / (cap * 1024 ** 3), 1) if cap else None},
                    "events": list(reversed(self.events[-30:])), "interval": self.interval,
                    "hint": hint[0], "hint_en": hint[1]}

    def _check_bg(self):
        try:
            self.tick()
        finally:
            self.busy = False

    def api(self, method, sub, q, body):
        if method == "GET" and sub == "":
            return 200, self.view()
        if method == "POST" and sub == "check":
            with self.lock:
                start = not self.busy and not self.demo
                if start:
                    self.busy = True
            if start:
                threading.Thread(target=self._check_bg, daemon=True, name="nw-uplink").start()
            return 200, self.view()
        return 404, {"error": "not found"}

    def run_forever(self):
        if self.demo:
            return
        time.sleep(20)
        while True:
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(self.interval)
