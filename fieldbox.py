"""🔌 Tester πρίζας / κουτί τεχνικού — «τι είναι αυτή η πρίζα;» σε ~30 δευτερόλεπτα.

Ένα Raspberry Pi (Zero 2 W + USB‑Ethernet ή Pi 4) με NetWatch που το κουβαλά ο τεχνικός: το βάζει στην πρίζα
του τοίχου και βλέπει σε μικρή οθόνη ή στο κινητό:
  1 link      carrier, ταχύτητα/duplex που διαπραγματεύτηκε (10/100 ή half σε γραμμή gigabit → χαλασμένο ζεύγος)
  2 nbr       LLDP / CDP: σε ποιο switch και σε ποια θύρα καταλήγει η πρίζα, VLAN, PoE, LAG (+ 802.1Q tags → trunk)
  3 dhcp      ΕΝΑ DHCPDISCOVER με χρονομέτρηση (όπως το l2guard: ποτέ REQUEST → δεν δεσμεύει διεύθυνση)
  4 L3        gateway, DNS, Internet, captive portal, MTU — τα τρέχει το nettriage (δεν αντιγράφουμε κώδικα)
  5 speed     προαιρετικά, σύντομη λήψη μέσω speed.py (παραλείπεται όταν δουλεύουμε από LTE)
Συμπέρασμα με μεγάλα γράμματα και ιστορικό ανά ετικέτα πρίζας (A-01 → A-02 …) για το πρωτόκολλο παράδοσης.

Μόνο ανάγνωση: ακούμε LLDP/CDP, στέλνουμε ένα DISCOVER και pings· δεν γράφουμε ποτέ σε switch.
Οι αναλυτές TLV (LLDP: IEEE 802.1AB, org TLVs 802.1/802.3, LLDP‑MED ANSI/TIA‑1057 · CDP v2) είναι καθαρές
συναρτήσεις με όρια μεγέθους — δεν σκάνε ποτέ σε κομμένο/κακόβουλο πλαίσιο.

API
---
FieldBox(state, data_dir=None, demo=False, clock=time.time, net=None, triage=None)
  .view() · .api(method, sub, q, body) · .run_test(label, …) (σύγχρονο) · .results(labels=None) · .oled()
"""
import csv
import io
import json
import os
import re
import struct
import subprocess
import sys
import threading
import time

MAX_HIST = 500
VIEW_HIST = 120
MAX_TLVS = 128
MAX_STR = 120
LISTEN_S = 35.0          # το LLDP στέλνεται συνήθως κάθε 30 s
DHCP_S = 3.0
OLED_W = 21              # SSD1306 128x64, γραμματοσειρά 6 px → 21 χαρακτήρες
BPF = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc or vlan"
STEP_IDS = ["link", "nbr", "dhcp", "gateway", "dns", "internet", "captive", "mtu", "speed"]
TITLES = {
    "link": ("Καλώδιο / link", "Cable / link"),
    "nbr": ("Switch & θύρα (LLDP/CDP)", "Switch & port (LLDP/CDP)"),
    "dhcp": ("DHCP", "DHCP"),
    "gateway": ("Router (gateway)", "Router (gateway)"),
    "dns": ("DNS", "DNS"),
    "internet": ("Internet", "Internet"),
    "captive": ("Captive portal", "Captive portal"),
    "mtu": ("MTU 1500", "MTU 1500"),
    "speed": ("Ταχύτητα (σύντομο τεστ)", "Throughput (quick test)"),
}
POE_CLASS_W = {0: 15.4, 1: 4.0, 2: 7.0, 3: 15.4, 4: 30.0}   # IEEE 802.3af/at: μέγιστη ισχύς PSE ανά class


# ═════════════════════════════ καθαρές συναρτήσεις: πλαίσια ═════════════════════════════
def _txt(b, n=MAX_STR):
    s = bytes(b[:255]).decode("utf-8", "replace")
    return re.sub(r"[\x00-\x1f\x7f�]", " ", s).strip()[:n]


def _mac(b):
    return ":".join(f"{x:02x}" for x in b[:6])


def _ip(b):
    if len(b) == 4:
        return ".".join(str(x) for x in b)
    if len(b) == 16:
        import ipaddress
        return str(ipaddress.IPv6Address(bytes(b)))
    return ""


def _id(sub, val, mac_sub, ip_sub):
    """Chassis ID / Port ID: MAC, διεύθυνση δικτύου (IANA family + διεύθυνση) ή κείμενο."""
    if sub == mac_sub and len(val) == 6:
        return _mac(val)
    if sub == ip_sub and len(val) >= 2:
        return _ip(val[1:]) or val[1:].hex()
    return _txt(val)


def parse_lldp(data):
    """LLDPDU (ό,τι ακολουθεί το ethertype 0x88cc) → dict ή None.
    TLV: 7 bit τύπος + 9 bit μήκος. Κομμένο TLV → σταματάμε και κρατάμε ό,τι διαβάστηκε (truncated=True).
    Έγκυρο μόνο αν υπάρχουν Chassis ID και Port ID."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    out = {"proto": "LLDP"}
    i, n, count = 0, len(data), 0
    while i + 2 <= n and count < MAX_TLVS:
        count += 1
        hdr = (data[i] << 8) | data[i + 1]
        typ, ln = hdr >> 9, hdr & 0x1FF
        i += 2
        if typ == 0:
            break
        if i + ln > n:
            out["truncated"] = True
            break
        v = data[i:i + ln]
        i += ln
        if typ == 1 and ln >= 2:          # Chassis ID: subtype 4 = MAC, 5 = network address
            out["chassis"], out["chassis_sub"] = _id(v[0], v[1:], 4, 5), v[0]
        elif typ == 2 and ln >= 2:        # Port ID: subtype 3 = MAC, 4 = network address, 5 = ifName, 7 = local
            out["port"], out["port_sub"] = _id(v[0], v[1:], 3, 4), v[0]
        elif typ == 3 and ln >= 2:
            out["ttl"] = (v[0] << 8) | v[1]
        elif typ == 4:
            out["port_desc"] = _txt(v)
        elif typ == 5:
            out["name"] = _txt(v)
        elif typ == 6:
            out["descr"] = _txt(v, 200)
        elif typ == 7 and ln >= 4:        # δυνατότητες / ενεργές: bit2 bridge, bit4 router, bit3 WLAN AP, bit5 phone
            out["caps"] = (v[2] << 8) | v[3]
        elif typ == 8 and ln >= 2:        # Management Address: μήκος(1) [subtype(1) διεύθυνση] …
            al = v[0]
            if 2 <= al <= 32 and 1 + al <= ln and "mgmt" not in out:
                fam, addr = v[1], v[2:1 + al]
                if (fam == 1 and len(addr) == 4) or (fam == 2 and len(addr) == 16):
                    out["mgmt"] = _ip(addr)
        elif typ == 127 and ln >= 4:
            _lldp_org(out, bytes(v[:3]), v[3], v[4:])
    if "chassis" not in out or "port" not in out:
        return None
    return out


def _lldp_org(out, oui, sub, v):
    if oui == b"\x00\x80\xc2":            # IEEE 802.1
        if sub == 1 and len(v) >= 2:      # Port VLAN ID (0 = δεν υποστηρίζεται)
            pv = (v[0] << 8) | v[1]
            if 0 < pv < 4095:
                out["pvid"] = pv
        elif sub == 3 and len(v) >= 3:    # VLAN Name: VLAN id(2) μήκος(1) όνομα
            vid, ln = (v[0] << 8) | v[1], v[2]
            if 0 < vid < 4095 and 3 + ln <= len(v) and len(out.setdefault("vlans", {})) < 64:
                out["vlans"][vid] = _txt(v[3:3 + ln], 32)
        elif sub == 7 and len(v) >= 5:    # Link Aggregation (802.1AB‑2009): status(1) port id(4)
            _lag(out, v)
    elif oui == b"\x00\x12\x0f":          # IEEE 802.3
        if sub == 2 and len(v) >= 3:      # Power via MDI
            sup = v[0]
            poe = out.setdefault("poe", {})
            poe.update(pse=bool(sup & 1), supported=bool(sup & 2), enabled=bool(sup & 4))
            if 1 <= v[2] <= 5:            # 1 = class 0 … 5 = class 4
                poe["class"] = v[2] - 1
            if len(v) >= 8:               # επέκταση 802.3at: type/source/priority(1) requested(2) allocated(2), μονάδα 0.1 W
                poe["type"] = {0: "Type 2 PSE", 1: "Type 2 PD", 2: "Type 1 PSE", 3: "Type 1 PD"}[v[3] >> 6]
                req, alloc = ((v[4] << 8) | v[5]) / 10.0, ((v[6] << 8) | v[7]) / 10.0
                if 0 < alloc <= 99.9:
                    poe["w"], poe["src"] = alloc, "802.3at"
                if 0 < req <= 99.9:
                    poe["req_w"] = req
        elif sub == 3 and len(v) >= 5:    # Link Aggregation (παλιά θέση, 802.3)
            _lag(out, v)
        elif sub == 1 and len(v) >= 5:    # MAC/PHY: autoneg(1) advertised(2) operational MAU type(2)
            out["mau"] = (v[3] << 8) | v[4]
        elif sub == 4 and len(v) >= 2:
            out["mfs"] = (v[0] << 8) | v[1]
    elif oui == b"\x00\x12\xbb":          # LLDP‑MED (ANSI/TIA‑1057)
        if sub == 4 and len(v) >= 3:      # Extended Power‑via‑MDI: type(2b) source(2b) priority(4b) · ισχύς(2) σε 0.1 W
            poe = out.setdefault("poe", {})
            ptype = v[0] >> 6             # 0 = PSE, 1 = PD
            w = ((v[1] << 8) | v[2]) / 10.0
            poe["med_type"] = {0: "PSE", 1: "PD"}.get(ptype, "?")
            if ptype == 0:
                poe.setdefault("pse", True)
                if 0 < w <= 102.3 and "w" not in poe:
                    poe["w"], poe["src"] = w, "MED"
                poe.setdefault("enabled", True)
        elif sub == 2 and len(v) >= 4:    # Network Policy: app(1) · U T X VLAN(12) L2prio(3) DSCP(6)
            vid = ((v[1] & 0x1F) << 7) | (v[2] >> 1)
            if v[0] == 1 and 0 < vid < 4095:   # 1 = Voice
                out["voice_vlan"] = vid
        elif sub == 1 and len(v) >= 3:
            out["med"] = True


def _lag(out, v):
    port = struct.unpack(">I", bytes(v[1:5]))[0]
    out["lag"] = {"capable": bool(v[0] & 1), "enabled": bool(v[0] & 2), "id": port}


def parse_cdp(data):
    """CDP (ό,τι ακολουθεί το LLC/SNAP 00‑00‑0C / 0x2000): version(1) ttl(1) checksum(2) + TLV type(2) len(2) value.
    Το μήκος περιλαμβάνει την 4‑byte κεφαλίδα του TLV."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 8 or data[0] not in (1, 2):
        return None
    out = {"proto": "CDP", "ttl": data[1]}
    i, n, count = 4, len(data), 0
    while i + 4 <= n and count < MAX_TLVS:
        count += 1
        typ, ln = struct.unpack(">HH", bytes(data[i:i + 4]))
        if ln < 4:
            out["truncated"] = True
            break
        if i + ln > n:
            out["truncated"] = True
            break
        v = data[i + 4:i + ln]
        i += ln
        if typ == 0x0001:
            out["name"] = out["chassis"] = _txt(v)
        elif typ == 0x0003:
            out["port"] = _txt(v)
        elif typ == 0x0005:
            out["descr"] = _txt(v, 200)
        elif typ == 0x0006:
            out["platform"] = _txt(v)
        elif typ == 0x000A and len(v) >= 2:
            pv = (v[0] << 8) | v[1]
            if 0 < pv < 4095:
                out["pvid"] = pv
        elif typ == 0x000B and len(v) >= 1:
            out["duplex"] = "full" if v[0] else "half"
        elif typ == 0x000E and len(v) >= 3:     # VoIP VLAN reply: data(1) vlan(2)
            vid = (v[1] << 8) | v[2]
            if 0 < vid < 4095:
                out["voice_vlan"] = vid
        elif typ == 0x0010 and len(v) >= 2:     # Power Consumption (mW) — το στέλνει η τροφοδοτούμενη συσκευή
            out["power_use_w"] = ((v[0] << 8) | v[1]) / 1000.0
        elif typ == 0x001A and len(v) >= 8:     # Power Available: request id(2) mgmt id(2) διαθέσιμη ισχύς(4, mW)
            w = struct.unpack(">I", bytes(v[4:8]))[0] / 1000.0
            if 0 < w <= 100:
                out["poe"] = {"pse": True, "supported": True, "enabled": True, "w": round(w, 1), "src": "CDP"}
        elif typ in (0x0002, 0x0016) and len(v) >= 4 and "mgmt" not in out:   # Addresses / Management Addresses
            cnt = struct.unpack(">I", bytes(v[:4]))[0]
            j = 4
            for _ in range(min(cnt, 4)):
                if j + 2 > len(v):
                    break
                pt, pl = v[j], v[j + 1]
                j += 2
                proto = bytes(v[j:j + pl])
                j += pl
                if j + 2 > len(v):
                    break
                al = (v[j] << 8) | v[j + 1]
                j += 2
                addr = v[j:j + al]
                j += al
                if pt == 1 and proto == b"\xcc" and len(addr) == 4:   # NLPID 0xCC = IPv4
                    out["mgmt"] = _ip(addr)
                    break
    if "name" not in out or "port" not in out:
        return None
    return out


def parse_frame(raw):
    """Πλαίσιο Ethernet → {"src", "vlans": [802.1Q ids], "nbr": dict LLDP/CDP ή None}. Ποτέ εξαίρεση."""
    out = {"src": "", "vlans": [], "nbr": None}
    try:
        if not isinstance(raw, (bytes, bytearray)) or len(raw) < 14:
            return out
        dst, out["src"] = bytes(raw[:6]), _mac(raw[6:12])
        i = 12
        et = (raw[i] << 8) | raw[i + 1]
        while et in (0x8100, 0x88A8) and len(out["vlans"]) < 2 and i + 6 <= len(raw):
            vid = ((raw[i + 2] << 8) | raw[i + 3]) & 0x0FFF
            if vid:                       # VLAN 0 = μόνο προτεραιότητα (802.1p), όχι VLAN
                out["vlans"].append(vid)
            i += 4
            et = (raw[i] << 8) | raw[i + 1]
        body = raw[i + 2:]
        if et == 0x88CC:
            out["nbr"] = parse_lldp(body)
        elif et <= 1500 and dst == b"\x01\x00\x0c\xcc\xcc\xcc" and bytes(body[:8]) == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00":
            out["nbr"] = parse_cdp(body[8:8 + et - 8] if et >= 8 else b"")
    except Exception:  # noqa: BLE001 — πακέτο από το καλώδιο: ό,τι και να έχει
        pass
    return out


def parse_dhcp(data):
    """Μήνυμα BOOTP/DHCP (payload του UDP) → dict ή None. Επιλογές που μας νοιάζουν: 1,3,6,15,51,53,54 + 43/66/67/150."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 240 or bytes(data[236:240]) != b"\x63\x82\x53\x63":
        return None
    out = {"op": data[0], "xid": struct.unpack(">I", bytes(data[4:8]))[0], "offer": _ip(data[16:20]),
           "siaddr": _ip(data[20:24]), "dns": [], "opts": [], "type": 0}
    i, n, count = 240, len(data), 0
    while i < n and count < 96:
        count += 1
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 2 > n or i + 2 + data[i + 1] > n:
            out["truncated"] = True
            break
        v = data[i + 2:i + 2 + data[i + 1]]
        i += 2 + len(v)
        if code not in out["opts"]:
            out["opts"].append(code)
        if code == 53 and len(v) == 1:
            out["type"] = v[0]
        elif code == 54 and len(v) == 4:
            out["server"] = _ip(v)
        elif code == 1 and len(v) == 4:
            out["mask"] = _ip(v)
            bits = bin(struct.unpack(">I", bytes(v))[0])[2:].zfill(32)
            if "01" not in bits:
                out["prefix"] = bits.count("1")
        elif code == 3 and len(v) >= 4:
            out["gw"] = _ip(v[:4])
        elif code == 6:
            out["dns"] = [_ip(v[k:k + 4]) for k in range(0, min(len(v), 16) - 3, 4)]
        elif code == 15:
            out["domain"] = _txt(v.rstrip(b"\x00"), 64)
        elif code == 51 and len(v) == 4:
            out["lease"] = struct.unpack(">I", bytes(v))[0]
        elif code == 66:
            out["tftp"] = _txt(v.rstrip(b"\x00"), 64)
        elif code == 67:
            out["bootfile"] = _txt(v.rstrip(b"\x00"), 64)
        elif code == 150:
            out["tftp150"] = [_ip(v[k:k + 4]) for k in range(0, min(len(v), 16) - 3, 4)]
    out["opts"].sort()
    out.setdefault("server", "")
    return out


def dhcp_hints(o):
    """Τι «λένε» οι επιλογές για το δίκτυο → [(el, en)]."""
    opts, out = set(o.get("opts") or []), []
    if 150 in opts or (66 in opts and 67 not in opts):
        out.append(("VoIP: δίνει TFTP server για τηλέφωνα (option 150/66)", "VoIP: hands out a TFTP server for phones (option 150/66)"))
    if 67 in opts or (o.get("siaddr") not in (None, "", "0.0.0.0") and 66 in opts):
        out.append(("PXE: δίνει αρχείο εκκίνησης από το δίκτυο (option 67)", "PXE: hands out a network boot file (option 67)"))
    if 43 in opts:
        out.append(("Option 43 (vendor): συνήθως controller για access points", "Option 43 (vendor): usually an access-point controller"))
    return out


# ═════════════════════════════ καθαρές συναρτήσεις: link ═════════════════════════════
def _mode_max(block):
    sp = [int(x) for x in re.findall(r"(\d+)base", block or "")]
    return max(sp) if sp else None


def parse_ethtool(text):
    """Έξοδος `ethtool <if>` → {speed, duplex, carrier, sup_max, partner_max}."""
    t = text or ""
    out = {"speed": None, "duplex": None, "carrier": None, "sup_max": None, "partner_max": None}
    m = re.search(r"Speed:\s*(\d+)\s*Mb/s", t)
    if m:
        out["speed"] = int(m.group(1))
    m = re.search(r"Duplex:\s*(Full|Half)", t, re.I)
    if m:
        out["duplex"] = m.group(1).lower()
    m = re.search(r"Link detected:\s*(yes|no)", t, re.I)
    if m:
        out["carrier"] = m.group(1).lower() == "yes"
    m = re.search(r"Supported link modes:(.*?)(?:\n\s*[A-Z][A-Za-z ]+:)", t, re.S)
    if m:
        out["sup_max"] = _mode_max(m.group(1))
    m = re.search(r"Link partner advertised link modes:(.*?)(?:\n\s*[A-Z][A-Za-z ]+:)", t, re.S)
    if m:
        out["partner_max"] = _mode_max(m.group(1))
    return out


def parse_ifconfig_media(text):
    """macOS `ifconfig en0` → {speed, duplex, carrier}: «media: autoselect (1000baseT <full-duplex>)», «status: active»."""
    t = text or ""
    out = {"speed": None, "duplex": None, "carrier": None, "sup_max": None, "partner_max": None}
    m = re.search(r"status:\s*(\w+)", t)
    if m:
        out["carrier"] = m.group(1) == "active"
    m = re.search(r"media:[^\n]*\((\d+)(G?)base[\w-]*\s*(?:<([^>]*)>)?", t, re.I)
    if m:
        out["speed"] = int(m.group(1)) * (1000 if m.group(2) else 1)
        fl = m.group(3) or ""
        out["duplex"] = "half" if "half-duplex" in fl else "full" if "full-duplex" in fl else None
    return out


def speed_txt(mbps):
    if not mbps:
        return "?"
    if mbps >= 1000:
        return f"{mbps / 1000:g} Gbps"
    return f"{mbps} Mbps"


# ═════════════════════════════ ετικέτες ═════════════════════════════
def clean_label(s):
    return re.sub(r"[\x00-\x1f\x7f]", "", str(s or "")).strip()[:40]


def next_label(label):
    """A-09 → A-10 · 12 → 13 · PP1-24 → PP1-25 · «Γραφείο» → «Γραφείο-2». Κρατά τα μηδενικά μπροστά."""
    label = clean_label(label)
    if not label:
        return "A-01"
    m = re.search(r"(\d+)$", label)
    if not m:
        return (label[:37] + "-2")
    d = m.group(1)
    return (label[:m.start()] + str(int(d) + 1).zfill(len(d)))[:40]


# ═════════════════════════════ συμπέρασμα ═════════════════════════════
def _poe(nbr):
    """→ {"on": bool|None, "w": float|None, "class": int|None, "src"} από ό,τι διαφήμισε το switch (None = άγνωστο)."""
    p = (nbr or {}).get("poe")
    if not p:
        return {"on": None, "w": None, "class": None, "src": None}
    on = bool(p.get("pse", True) and p.get("enabled"))
    w, src = p.get("w"), p.get("src")
    if on and w is None and p.get("class") is not None:
        w, src = POE_CLASS_W.get(p["class"]), "class"
    return {"on": on, "w": w if on else None, "class": p.get("class"), "src": src if on else None}


def _port_name(nbr):
    """Όνομα θύρας για άνθρωπο: αν το Port ID είναι MAC, προτίμησε την περιγραφή."""
    if not nbr:
        return ""
    p, d = nbr.get("port") or "", nbr.get("port_desc") or ""
    if nbr.get("port_sub") == 3 and d:
        return d
    return p or d


def verdict(r, expect=None):
    """r = {"link", "nbr", "tagged", "dhcp", "l3"} → {"level": ok|warn|fail, "el", "en", "fix", "fix_en", "issues": […]}.
    Καθαρή συνάρτηση: το πρώτο βήμα που αποτυγχάνει δίνει το κείμενο και το «τι να ελέγξεις»."""
    ex = expect or {}
    link, nbr, dh, l3 = r.get("link") or {}, r.get("nbr"), r.get("dhcp"), r.get("l3") or {}
    tagged = sorted(r.get("tagged") or [])
    sw = (nbr or {}).get("name") or (nbr or {}).get("chassis") or ""
    port = _port_name(nbr)
    where = f"{sw} θύρα {port}" if sw and port else sw
    where_en = f"{sw} port {port}" if sw and port else sw
    at, at_en = (f" ({where})" if where else ""), (f" ({where_en})" if where_en else "")
    iss = []

    def add(level, code, el, en, fix, fix_en):
        iss.append({"level": level, "code": code, "el": el, "en": en, "fix": fix, "fix_en": fix_en})

    if not link.get("carrier"):
        add("fail", "nolink", "Νεκρή πρίζα — δεν υπάρχει link", "Dead socket — no link",
            "Έλεγξε: patch cord, τερματισμό στην πρίζα και στο patch panel, αν είναι πατσαρισμένη στο switch και αν η θύρα είναι ενεργή (no shutdown).",
            "Check: patch cord, termination at the socket and patch panel, whether it is patched to the switch and the port is enabled (no shutdown).")
    else:
        offers = (dh or {}).get("offers") or []
        servers = sorted({o.get("server") or o.get("ip_src") or "?" for o in offers})
        gw_ok = l3.get("gateway") in ("ok", "warn")
        if dh is not None and not dh.get("err") and not offers:
            if gw_ok:
                add("warn", "dhcp_none", "Κανένας DHCP δεν απάντησε (στατικές IP;)", "No DHCP server answered (static IPs?)",
                    "Αν το δίκτυο θέλει DHCP: έλεγξε το VLAN της θύρας" + at + " και το DHCP pool / ip helper-address.",
                    "If this network should have DHCP: check the port VLAN" + at_en + " and the DHCP pool / ip helper-address.")
            else:
                add("fail", "dhcp_none", "Link ΟΚ αλλά κανένας DHCP δεν απαντά", "Link OK but no DHCP server answers",
                    "Η θύρα" + at + " είναι μάλλον σε λάθος/κενό VLAN ή έχει γεμίσει το DHCP pool. Έλεγξε switchport access vlan, ip helper-address, DHCP snooping trust.",
                    "The port" + at_en + " is probably in a wrong/empty VLAN or the DHCP pool is full. Check switchport access vlan, ip helper-address, DHCP snooping trust.")
        elif len(servers) > 1:
            add("fail", "dhcp_rogue", f"{len(servers)} DHCP servers απαντούν: {', '.join(servers[:4])} — rogue DHCP",
                f"{len(servers)} DHCP servers answer: {', '.join(servers[:4])} — rogue DHCP",
                "Βρες τον δεύτερο DHCP (συνήθως router/access point συνδεδεμένο ανάποδα) και βγάλ' τον· ενεργοποίησε DHCP snooping.",
                "Find the second DHCP server (usually a router/AP plugged in backwards) and remove it; enable DHCP snooping.")
        if l3.get("gateway") == "fail":
            add("fail", "gateway", "Ο router (gateway) δεν απαντά", "The router (gateway) does not answer",
                "Έλεγξε το VLAN της θύρας" + at + " και το uplink του switch προς τον router.",
                "Check the port VLAN" + at_en + " and the switch uplink to the router.")
        if l3.get("captive") == "fail":
            add("warn", "captive", "Captive portal — θέλει login πριν ανοίξει το Internet", "Captive portal — login needed before Internet access",
                "Δίκτυο επισκεπτών; Για συσκευές/IoT ζήτα εξαίρεση (MAC bypass) ή άλλο VLAN.",
                "Guest network? For devices/IoT ask for a MAC bypass or another VLAN.")
        elif l3.get("internet") == "fail":
            add("fail", "internet", "Το τοπικό δίκτυο δουλεύει, αλλά δεν βγαίνει στο Internet", "The LAN works but there is no Internet",
                "Έλεγξε τον router/WAN ή αν το VLAN αυτό επιτρέπεται να βγει έξω (ACL/firewall).",
                "Check the router/WAN or whether this VLAN is allowed out (ACL/firewall).")
        elif l3.get("dns") == "fail":
            add("fail", "dns", "Το DNS δεν απαντά (το Internet δουλεύει)", "DNS does not answer (the Internet works)",
                "Έλεγξε τους DNS servers που δίνει το DHCP σε αυτό το VLAN.", "Check the DNS servers handed out by DHCP on this VLAN.")
        sp, dup = link.get("speed"), link.get("duplex")
        want = int(ex.get("speed") or 0) or (1000 if (link.get("partner_max") or 0) >= 1000 and (link.get("sup_max") or 1000) >= 1000 else 0)
        if link.get("kind") != "wifi":
            if sp and sp < 1000 and (want >= 1000 or sp <= 100):
                sure = (link.get("partner_max") or 0) >= 1000
                add("warn", "slow", f"Μόνο {speed_txt(sp)} αντί για 1 Gbps — χαλασμένο ζεύγος ή κακός τερματισμός" if sure or want >= 1000
                    else f"Μόνο {speed_txt(sp)} — αν το switch είναι gigabit: χαλασμένο ζεύγος ή κακός τερματισμός",
                    f"Only {speed_txt(sp)} instead of 1 Gbps — bad pair or bad termination" if sure or want >= 1000
                    else f"Only {speed_txt(sp)} — if the switch is gigabit: bad pair or bad termination",
                    "Το gigabit θέλει και τα 4 ζεύγη. Ξανατερμάτισε (T568B και στις δύο άκρες), δοκίμασε άλλο patch cord, μέτρησε με cable tester τα ζεύγη 4‑5 και 7‑8.",
                    "Gigabit needs all 4 pairs. Re-terminate (T568B on both ends), try another patch cord, test pairs 4‑5 and 7‑8 with a cable tester.")
            if dup == "half":
                add("warn", "half", "Half duplex — ασυμφωνία duplex (collisions, αργό δίκτυο)", "Half duplex — duplex mismatch (collisions, slow network)",
                    "Βάλε και τις δύο πλευρές σε auto‑negotiation (όχι κλειδωμένο 100/full στη μία μόνο άκρη).",
                    "Set both sides to auto-negotiation (not forced 100/full on one end only).")
        pv = (nbr or {}).get("pvid")
        if ex.get("vlan") and pv and int(ex["vlan"]) != pv:
            add("warn", "vlan", f"Λάθος VLAN: {pv} αντί για {int(ex['vlan'])}", f"Wrong VLAN: {pv} instead of {int(ex['vlan'])}",
                f"Στο switch{at}: switchport access vlan {int(ex['vlan'])}.", f"On the switch{at_en}: switchport access vlan {int(ex['vlan'])}.")
        poe = _poe(nbr)
        if ex.get("poe") and nbr and poe["on"] is not True:
            add("warn", "poe", "Χωρίς PoE σε αυτή τη θύρα", "No PoE on this port",
                "Το switch δεν διαφημίζει ενεργό PoE" + at + ": έλεγξε power inline auto, το PoE budget, ή αν είναι θύρα χωρίς PoE.",
                "The switch does not advertise active PoE" + at_en + ": check power inline auto, the PoE budget, or whether it is a non‑PoE port.")
        if tagged:
            vl = ", ".join(str(x) for x in tagged[:8])
            add("warn", "trunk", f"Θύρα trunk: περνούν VLAN με tag ({vl})", f"Trunk port: tagged VLANs on the wire ({vl})",
                "Για πρίζα χρήστη θέλεις access port: switchport mode access. Αν είναι για access point/τηλέφωνο, είναι αναμενόμενο.",
                "A user socket should be an access port: switchport mode access. Expected if it feeds an access point/phone.")
        if l3.get("mtu") == "fail":
            add("warn", "mtu", "Πρόβλημα MTU: δεν περνούν πακέτα 1500 bytes", "MTU problem: 1500-byte packets do not pass",
                "Έλεγξε MTU στο switch/router (VLAN tagging, PPPoE, VPN).", "Check MTU on the switch/router (VLAN tagging, PPPoE, VPN).")
    fails = [x for x in iss if x["level"] == "fail"]
    warns = [x for x in iss if x["level"] == "warn"]
    if fails:
        f = fails[0]
        return {"level": "fail", "el": "❌ " + f["el"], "en": "❌ " + f["en"], "fix": f["fix"], "fix_en": f["fix_en"], "issues": iss}
    # σύνοψη: switch/θύρα, VLAN, ταχύτητα, PoE, DHCP
    bits, bits_en = [], []
    if where:
        bits.append(where)
        bits_en.append(where_en)
    pv = (nbr or {}).get("pvid")
    if pv:
        bits.append(f"VLAN {pv}")
        bits_en.append(f"VLAN {pv}")
    if link.get("speed"):
        bits.append(speed_txt(link["speed"]))
        bits_en.append(speed_txt(link["speed"]))
    poe = _poe(nbr)
    if poe["on"]:
        s = "PoE" + (f" {poe['w']:g} W" if poe["w"] else "")
        bits.append(s)
        bits_en.append(s)
    ms = (dh or {}).get("ms")
    if ms is not None and (dh or {}).get("offers"):
        bits.append(f"DHCP σε {ms / 1000:.1f} s")
        bits_en.append(f"DHCP in {ms / 1000:.1f} s")
    tail, tail_en = (" — " + ", ".join(bits) if bits else ""), (" — " + ", ".join(bits_en) if bits_en else "")
    if warns:
        w = warns[0]
        more = f" (+{len(warns) - 1})" if len(warns) > 1 else ""
        return {"level": "warn", "el": "⚠️ " + w["el"] + more + tail, "en": "⚠️ " + w["en"] + more + tail_en,
                "fix": w["fix"], "fix_en": w["fix_en"], "issues": iss}
    fix = fix_en = ""
    if link.get("kind") == "wifi":  # δεν δοκιμάστηκε πρίζα: το «Πρίζα ΟΚ» θα ήταν ψέμα
        return {"level": "warn", "el": "📶 Είσαι σε Wi‑Fi — δεν ελέγχθηκε πρίζα (το δίκτυο απαντά)", "en": "📶 You are on Wi‑Fi — no socket was tested (the network answers)",
                "fix": "Σύνδεσε καλώδιο Ethernet στην πρίζα που θες να ελέγξεις (ή USB‑Ethernet) και ξαναπάτα Τεστ.",
                "fix_en": "Plug an Ethernet cable into the socket you want to test (or a USB‑Ethernet adapter) and press Test again.", "issues": iss}
    if (dh or {}).get("err"):
        return {"level": "warn", "el": "⚠️ Μερικός έλεγχος: το δίκτυο απαντά, αλλά DHCP και switch/θύρα δεν ελέγχθηκαν" + tail,
                "en": "⚠️ Partial test: the network answers, but DHCP and switch/port were not checked" + tail_en,
                "fix": "Οι έλεγχοι DHCP/LLDP θέλουν δικαιώματα διαχειριστή: τρέξε το NetWatch σε Live (sudo) ή με CAP_NET_RAW (δες tools/fieldbox/netwatch-fieldbox.service).",
                "fix_en": "The DHCP/LLDP checks need admin rights: run NetWatch in Live (sudo) or with CAP_NET_RAW (see tools/fieldbox/netwatch-fieldbox.service).", "issues": iss}
    if link.get("carrier") and not nbr and (r.get("nbr_done") or r.get("nbr_done") is None):
        fix = "Το switch δεν έστειλε LLDP/CDP (απλό unmanaged switch ή κλειστό LLDP) — δεν ξέρω θύρα/VLAN. Σε managed switch: lldp run."
        fix_en = "The switch sent no LLDP/CDP (plain unmanaged switch or LLDP off) — port/VLAN unknown. On a managed switch: lldp run."
    return {"level": "ok", "el": "✅ Πρίζα ΟΚ" + tail, "en": "✅ Socket OK" + tail_en, "fix": fix, "fix_en": fix_en, "issues": iss}


def build_record(label, note, t, r, expect=None, steps=None, rid=None):
    """Επίπεδη εγγραφή ιστορικού — αυτό διαβάζει και το πρωτόκολλο παράδοσης (accept)."""
    v = verdict(r, expect)
    link, nbr, dh = r.get("link") or {}, r.get("nbr") or {}, r.get("dhcp") or {}
    offers = dh.get("offers") or []
    o = offers[0] if offers else {}
    poe = _poe(nbr)
    l3 = r.get("l3") or {}
    return {
        "id": rid or f"{int(t * 1000):x}", "t": t, "label": clean_label(label), "note": str(note or "")[:200],
        "level": v["level"], "ok": v["level"] == "ok", "verdict": v["el"], "verdict_en": v["en"],
        "fix": v["fix"], "fix_en": v["fix_en"], "issues": [x["code"] for x in v["issues"]],
        "iface": link.get("iface") or "", "carrier": bool(link.get("carrier")), "speed": link.get("speed"),
        "duplex": link.get("duplex"), "kind": link.get("kind"),
        "proto": nbr.get("proto"), "sw": nbr.get("name") or nbr.get("chassis") or "", "chassis": nbr.get("chassis") or "",
        "port": _port_name(nbr), "port_desc": nbr.get("port_desc") or "", "platform": nbr.get("platform") or (nbr.get("descr") or "")[:60],
        "mgmt": nbr.get("mgmt") or "", "vlan": nbr.get("pvid"), "vlan_name": (nbr.get("vlans") or {}).get(nbr.get("pvid")) or "",
        "voice_vlan": nbr.get("voice_vlan"), "lag": bool((nbr.get("lag") or {}).get("enabled")),
        "tagged": sorted(r.get("tagged") or [])[:16],
        "poe": poe["on"], "poe_w": poe["w"], "poe_class": poe["class"], "poe_src": poe["src"],
        "dhcp_ms": dh.get("ms") if offers else None, "dhcp_err": bool(dh.get("err")), "dhcp_server": o.get("server") or "",
        "dhcp_servers": sorted({x.get("server") or x.get("ip_src") or "?" for x in offers})[:6],
        "ip": o.get("offer") or "", "mask": o.get("mask") or "", "prefix": o.get("prefix"), "gw": o.get("gw") or "",
        "dns": (o.get("dns") or [])[:4], "domain": o.get("domain") or "", "lease": o.get("lease"),
        "dhcp_opts": [c for c in (o.get("opts") or []) if c in (43, 66, 67, 150)],
        "hints": [h[0] for h in dhcp_hints(o)], "hints_en": [h[1] for h in dhcp_hints(o)],
        "l3": {k: l3.get(k) for k in ("gateway", "dns", "internet", "captive", "mtu") if l3.get(k)},
        "down_mbps": r.get("down_mbps"),
        "steps": [{"id": s["id"], "status": s["status"], "detail": s.get("detail") or "", "detail_en": s.get("detail_en") or "",
                   "ms": s.get("ms")} for s in (steps or [])],
    }


def _ascii(s, n=OLED_W):
    s = str(s or "").replace("—", "-").replace("·", "-").replace("→", ">")
    return re.sub(r"[^\x20-\x7e]", "?", s).strip()[:n]


def oled_lines(rec=None, run=None, idle=None):
    """≤6 γραμμές ASCII, ≤21 χαρακτήρες, για οθόνη 128x64. Αγγλικά/σύμβολα — η μικρή οθόνη δεν έχει ελληνικά."""
    if run:
        done = [s for s in run.get("steps") or [] if s["status"] not in ("pending", "running")]
        cur = next((s for s in run.get("steps") or [] if s["status"] == "running"), None)
        nbr = run.get("nbr") or {}
        lines = [f"{run.get('label') or '?'} TEST {int(run.get('elapsed') or 0)}s",
                 f"step {len(done)}/{len(run.get('steps') or [])}" + (f" {cur['id']}" if cur else ""),
                 (nbr.get("name") or nbr.get("chassis") or "listening LLDP...")]
        if nbr:
            lines.append(f"{_port_name(nbr)}" + (f" VLAN {nbr['pvid']}" if nbr.get("pvid") else ""))
        lk = run.get("link") or {}
        if lk:
            lines.append(("link " + speed_txt(lk.get("speed")).replace(" ", "") if lk.get("carrier") else "NO LINK"))
        return [_ascii(x) for x in lines if x][:6]
    if rec:
        tag = {"ok": "OK", "warn": "WARN", "fail": "FAIL"}.get(rec.get("level"), "?")
        lines = [f"{rec.get('label') or '?'} {tag}"]
        if not rec.get("carrier"):
            return [_ascii(x) for x in lines + ["NO LINK", "check patch/termination"]]
        lines.append(rec.get("sw") or "no LLDP/CDP")
        if rec.get("port") or rec.get("vlan"):
            lines.append(f"{rec.get('port') or ''}" + (f" VLAN {rec['vlan']}" if rec.get("vlan") else ""))
        sp = speed_txt(rec.get("speed")).replace(" Gbps", "G").replace(" Mbps", "M")
        poe = ("PoE " + (f"{rec['poe_w']:g}W" if rec.get("poe_w") else "on")) if rec.get("poe") else ("no PoE" if rec.get("poe") is False else "")
        lines.append(f"{'' if sp == '?' else sp} {rec.get('duplex') or ''} {poe}".replace("  ", " "))
        if rec.get("dhcp_ms") is not None:
            lines.append(f"DHCP {rec['dhcp_ms'] / 1000:.1f}s {rec.get('ip') or ''}")
        else:
            lines.append("DHCP: not run" if rec.get("dhcp_err") else "DHCP: no offer")
        l3 = rec.get("l3") or {}
        code = (rec.get("issues") or [""])[0]
        lines.append(f"! {code}" if rec.get("level") != "ok" and code else
                     f"GW {'ok' if l3.get('gateway') in ('ok', 'warn') else '-'} NET {'ok' if l3.get('internet') in ('ok', 'warn') else '-'}")
        return [_ascii(x) for x in lines if x.strip()][:6]
    idle = idle or {}
    return [_ascii(x) for x in ["NetWatch field box", "ready - press button", f"if {idle.get('iface') or '?'}",
                                f"next {idle.get('next') or 'A-01'}"]]


def to_csv(rows):
    cols = ["time", "label", "result", "verdict", "switch", "port", "vlan", "speed_mbps", "duplex", "poe", "poe_w",
            "dhcp_ms", "dhcp_server", "ip", "gateway", "dns", "tagged_vlans", "note"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)

    def safe(x):                          # όχι τύποι στο Excel από ό,τι ήρθε από το δίκτυο
        s = "" if x is None else str(x)
        return "'" + s if s[:1] in ("=", "+", "-", "@", "\t") else s

    for r in rows:
        w.writerow([safe(x) for x in (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("t") or 0)), r.get("label"), r.get("level"),
            re.sub(r"^[^\w]+\s*", "", r.get("verdict") or ""), r.get("sw"), r.get("port"), r.get("vlan"), r.get("speed"),
            r.get("duplex"), {True: "yes", False: "no"}.get(r.get("poe"), ""), r.get("poe_w"), r.get("dhcp_ms"),
            r.get("dhcp_server"), r.get("ip"), r.get("gw"), " ".join(r.get("dns") or []),
            " ".join(str(x) for x in r.get("tagged") or []), r.get("note"))])
    return buf.getvalue().encode("utf-8-sig")


# ═════════════════════════════ πραγματικό I/O (αντικαθίσταται στα tests) ═════════════════════════════
def _run(cmd, timeout=4):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, "LC_ALL": "C", "LANG": "C"}).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _read(path):
    try:
        with open(path) as f:
            return f.read(64).strip()
    except OSError:
        return ""


class Net:
    """Τα πραγματικά πακέτα/αρχεία. Όλα τοπικά· το scapy φορτώνεται μόνο όταν χρειαστεί (θέλει root / CAP_NET_RAW)."""

    def link(self, iface):
        import shutil
        out = {"iface": iface, "carrier": None, "speed": None, "duplex": None, "sup_max": None, "partner_max": None, "kind": "ethernet"}
        if not iface or not re.match(r"^[\w.:-]{1,32}$", iface):
            return out
        base = f"/sys/class/net/{iface}"
        if os.path.isdir(base):
            if os.path.exists(base + "/wireless"):
                out["kind"] = "wifi"
            c = _read(base + "/carrier")
            out["carrier"] = c == "1" if c else False     # κατεβασμένη διεπαφή → δεν διαβάζεται → χωρίς link
            sp = _read(base + "/speed")
            if re.match(r"^\d+$", sp) and int(sp) > 0:
                out["speed"] = int(sp)
            dp = _read(base + "/duplex")
            if dp in ("full", "half"):
                out["duplex"] = dp
            if shutil.which("ethtool") and out["kind"] != "wifi":
                e = parse_ethtool(_run(["ethtool", iface]))
                for k, v in e.items():
                    if v is not None and (out.get(k) is None or k in ("sup_max", "partner_max")):
                        out[k] = v
        elif sys.platform == "darwin":
            m = parse_ifconfig_media(_run(["ifconfig", iface]))
            out.update({k: v for k, v in m.items() if v is not None})
            try:
                import changecheck
                out["kind"] = changecheck.iface_kind(iface) or "ethernet"
            except Exception:  # noqa: BLE001
                pass
        return out

    def listen(self, iface, timeout, on_frame, should_stop):
        from scapy.all import AsyncSniffer
        sn = AsyncSniffer(iface=iface, filter=BPF, store=False, prn=lambda p: on_frame(bytes(p)))
        sn.start()
        end = time.monotonic() + timeout
        try:
            while time.monotonic() < end and not should_stop():
                time.sleep(0.2)
        finally:
            try:
                sn.stop()
            except Exception:  # noqa: BLE001 — δεν πρόλαβε να ξεκινήσει / χωρίς δικαιώματα
                pass
        ex = getattr(sn, "exception", None)
        if ex:
            raise ex

    def dhcp(self, iface, timeout=DHCP_S):
        """Ένα DISCOVER (όπως l2guard.ScapyProber) + χρόνος μέχρι κάθε OFFER. Ποτέ REQUEST."""
        import random
        from scapy.all import BOOTP, DHCP, IP, UDP, Ether, conf, get_if_hwaddr, srp
        conf.checkIPaddr = False
        mac = get_if_hwaddr(iface)
        xid = random.randint(1, 0xFFFFFFFF)
        pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
               / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")) + b"\x00" * 10, xid=xid, flags=0x8000)
               / DHCP(options=[("message-type", "discover"), ("param_req_list", [1, 3, 6, 15, 43, 51, 54, 66, 67, 150]), "end"]))
        ans, _ = srp(pkt, iface=iface, multi=True, timeout=timeout, verbose=0)
        out = []
        for s, r in ans:
            if not r.haslayer(UDP):
                continue
            o = parse_dhcp(bytes(r[UDP].payload))
            if not o or o["xid"] != xid or o["type"] != 2:
                continue
            o["mac"], o["ip_src"] = r[Ether].src, r[IP].src if r.haslayer(IP) else ""
            o["server"] = o["server"] or o["ip_src"]
            # χρόνος DISCOVER→OFFER μόνο όταν το scapy κράτησε ώρα αποστολής και η διαφορά βγαίνει θετική (αλλιώς «άγνωστο», όχι 0)
            sent = getattr(s, "sent_time", None)
            dt = (float(r.time) - float(sent)) * 1000 if sent else None
            o["ms"] = int(round(dt)) if dt is not None and dt >= 1 else None
            out.append(o)
        return out[:8]

    def local(self):
        import changecheck
        return changecheck.local_info()

    def speedtest(self):
        import speed
        return speed.internet_test(down_bytes=5_000_000, up_bytes=0, timeout=8)


# ═════════════════════════════ demo ═════════════════════════════
def _demo_r(sw="SW-OFFICE-1", port="Gi1/0/14", vlan=20, speed=1000, duplex="full", poe_w=15.4, ms=410, ip="10.20.0.57",
            carrier=True, tagged=(), l3="ok", partner=1000):
    nbr = None
    if sw:
        nbr = {"proto": "LLDP", "chassis": "00:1b:54:aa:10:00", "chassis_sub": 4, "port": port, "port_sub": 5, "name": sw,
               "port_desc": "Office socket", "descr": "Cisco IOS Software, C2960X", "mgmt": "10.99.0.11", "pvid": vlan,
               "vlans": {vlan: {20: "OFFICE", 30: "GUEST", 40: "VOICE"}.get(vlan, "DATA")},
               "poe": {"pse": True, "supported": True, "enabled": bool(poe_w), "class": 3 if poe_w else 0,
                       **({"w": poe_w, "src": "802.3at"} if poe_w else {})}}
    net3 = f"10.{vlan}.0" if vlan else "192.168.1"
    offers = [{"server": f"{net3}.1", "ip_src": f"{net3}.1", "mac": "00:1b:54:aa:10:01", "offer": ip, "mask": "255.255.255.0",
               "prefix": 24, "gw": f"{net3}.1", "dns": [f"{net3}.1", "1.1.1.1"], "domain": "office.lan", "lease": 28800,
               "opts": [1, 3, 6, 15, 51, 53, 54] + ([150] if vlan == 40 else []), "ms": ms, "type": 2}] if ms else []
    return {"link": {"iface": "eth0", "carrier": carrier, "speed": speed if carrier else None, "duplex": duplex if carrier else None,
                     "sup_max": 1000, "partner_max": partner, "kind": "ethernet"},
            "nbr": nbr, "tagged": list(tagged), "dhcp": {"offers": offers, "ms": ms or None} if carrier else None,
            "l3": {k: l3 for k in ("gateway", "dns", "internet", "captive", "mtu")} if carrier else {}, "nbr_done": True}


DEMO_EXPECT = {"vlan": 20, "poe": True, "speed": 1000}
DEMO_SOCKETS = [   # (ετικέτα, σημείωση, παράμετροι) — 8 πρίζες ενός γραφείου
    ("A-01", "Υποδοχή", dict(port="Gi1/0/1", ms=380, ip="10.20.0.51")),
    ("A-02", "Γραφείο 1", dict(port="Gi1/0/2", ms=420, ip="10.20.0.52")),
    ("A-03", "Γραφείο 1 (παράθυρο)", dict(port="Gi1/0/3", speed=100, ms=450, ip="10.20.0.53")),          # χαλασμένο ζεύγος
    ("A-04", "Γραφείο 2", dict(port="Gi1/0/4", ms=390, ip="10.20.0.54")),
    ("A-05", "Αίθουσα συσκέψεων", dict(port="Gi1/0/5", vlan=30, ms=610, ip="10.30.0.23")),               # λάθος VLAN
    ("A-06", "Εκτυπωτής", dict(port="Gi1/0/6", ms=400, ip="10.20.0.56")),
    ("A-07", "Κάμερα εισόδου", dict(port="Gi1/0/7", poe_w=0, ms=430, ip="10.20.0.58")),                  # χωρίς PoE
    ("A-08", "Access point οροφής", dict(port="Gi1/0/8", poe_w=30.0, ms=370, ip="10.20.0.59")),
]


# ═════════════════════════════ η κλάση ═════════════════════════════
class FieldBox:
    def __init__(self, state, data_dir=None, demo=False, clock=time.time, net=None, triage=None):
        self.state, self.demo, self.clock = state, demo, clock
        self.net = net or Net()
        self.triage = triage
        self.path = os.path.join(data_dir, "field.json") if data_dir else None
        self.on_save = None
        self.sleep = time.sleep           # τα tests το αντικαθιστούν
        self.listen_s = LISTEN_S
        self.lock = threading.RLock()
        self.busy = False
        self.run = None                   # τρέχον τεστ (ζωντανή πρόοδος)
        self.hist = []                    # παλιότερο → νεότερο
        self.settings = {"vlan": None, "poe": False, "speed": None, "iface": None}
        self.error = None
        self._thread = None
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
            self.hist = [x for x in (j.get("history") or []) if isinstance(x, dict) and "label" in x][-MAX_HIST:]
            self._set_settings(j.get("settings") or {})
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save(self):
        if not self.path or self.demo:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"history": self.hist, "settings": self.settings}, f, ensure_ascii=False)
            os.replace(tmp, self.path)
            if self.on_save:
                self.on_save(self.path)
        except OSError:
            pass

    def _seed(self):
        self.settings.update(DEMO_EXPECT)
        now = self.clock()
        for i, (label, note, kw) in enumerate(DEMO_SOCKETS):
            t = now - 3600 + i * 95
            self.hist.append(build_record(label, note, t, _demo_r(**kw), self.settings, rid=f"demo{i + 1}"))

    def _set_settings(self, b):
        s = self.settings
        if "vlan" in b:
            try:
                v = int(b["vlan"]) if b["vlan"] not in (None, "", 0, "0") else None
            except (TypeError, ValueError):
                v = None
            s["vlan"] = v if v is None or 0 < v < 4095 else None
        if "poe" in b:
            s["poe"] = bool(b["poe"])
        if "speed" in b:
            try:
                v = int(b["speed"]) if b["speed"] else None
            except (TypeError, ValueError):
                v = None
            s["speed"] = v if v in (None, 100, 1000, 2500, 10000) else None
        if "iface" in b:
            v = str(b["iface"] or "").strip()
            s["iface"] = v if re.match(r"^[\w.:-]{1,32}$", v) else None

    # ── βοηθητικά ──
    def _iface(self):
        return self.settings.get("iface") or getattr(self.state, "iface", None) or ""

    def next_label(self):
        with self.lock:
            return next_label(self.hist[-1]["label"]) if self.hist else "A-01"

    def _step(self, sid, **kw):
        with self.lock:
            if not self.run:
                return
            s = next(x for x in self.run["steps"] if x["id"] == sid)
            if kw.get("status") == "running":
                s["_t0"] = time.monotonic()
            elif "status" in kw and "ms" not in kw and s.get("_t0"):
                kw["ms"] = int((time.monotonic() - s["_t0"]) * 1000)
            s.update(kw)

    def _both(self, sid, status, el, en):
        self._step(sid, status=status, detail=el, detail_en=en)

    def _data_saver(self):
        up = getattr(self.state, "uplink", None)
        try:
            return bool(up and up.on_backup())
        except Exception:  # noqa: BLE001
            return False

    # ── το τεστ ──
    def start(self, label=None, note="", lang="el", speed=False):
        """Ξεκινά τεστ στο παρασκήνιο → view()."""
        with self.lock:
            if self.busy:
                return dict(self.view(), error="Τρέχει ήδη ένα τεστ — περίμενε να τελειώσει.", error_en="A test is already running — please wait.")
            self._begin(label, note)
        self._thread = threading.Thread(target=self._work, args=(lang, speed), daemon=True, name="nw-field")
        self._thread.start()
        return self.view()

    def run_test(self, label=None, note="", lang="el", speed=False):
        """Σύγχρονο τεστ → εγγραφή ιστορικού (χρήσιμο σε tests και scripts)."""
        with self.lock:
            if self.busy:
                return None
            self._begin(label, note)
        return self._work(lang, speed)

    def _begin(self, label, note):
        label = clean_label(label) or self.next_label()
        self.busy, self.error = True, None
        self.run = {"label": label, "note": str(note or "")[:200], "started": self.clock(), "_m0": time.monotonic(),
                    "iface": self._iface(), "link": None, "nbr": None, "tagged": [], "dhcp": None, "l3": {},
                    "steps": [{"id": s, "el": TITLES[s][0], "en": TITLES[s][1], "status": "pending", "detail": "",
                               "detail_en": "", "ms": None} for s in STEP_IDS]}

    def _work(self, lang, speed):
        rec = None
        try:
            r = self._demo_run() if self.demo else self._live(lang if lang in ("el", "en") else "el", bool(speed))
            with self.lock:
                run = self.run
                steps = [dict(s) for s in run["steps"]]
                rec = build_record(run["label"], run["note"], run["started"], r, self.settings, steps)
                while any(x["id"] == rec["id"] for x in self.hist):
                    rec["id"] += "x"
                self.hist = (self.hist + [rec])[-MAX_HIST:]
        except Exception as e:  # noqa: BLE001 — ποτέ να μη μείνει «busy»
            self.error = "Το τεστ διακόπηκε: " + str(e)[:160]
        finally:
            with self.lock:
                self.busy, self.run = False, None
        self._save()
        return rec

    def _on_frame(self, raw):
        f = parse_frame(raw)
        with self.lock:
            run = self.run
            if not run:
                return
            for v in f["vlans"]:
                if v not in run["tagged"] and len(run["tagged"]) < 32:
                    run["tagged"].append(v)
            n = f["nbr"]
            if n:
                cur = run["nbr"]
                if cur is None or (cur.get("proto") == "CDP" and n["proto"] == "LLDP"):
                    merged = dict(n)
                    for k, v in (cur or {}).items():     # ό,τι έλεγε το CDP και λείπει από το LLDP (native VLAN, ισχύς)
                        merged.setdefault(k, v)
                    run["nbr"] = merged
                elif cur.get("proto") == "LLDP" and n["proto"] == "CDP":
                    for k, v in n.items():
                        cur.setdefault(k, v)
                elif cur.get("proto") == n["proto"] and cur.get("chassis") == n.get("chassis"):
                    cur.update(n)

    def _nbr_step(self, final=False):
        with self.lock:
            n, tagged = (self.run or {}).get("nbr"), sorted((self.run or {}).get("tagged") or [])
        tg = (" · tags: " + ", ".join(str(x) for x in tagged[:8])) if tagged else ""
        if n:
            poe = _poe(n)
            bits = [f"{n.get('name') or n.get('chassis')}", _port_name(n)]
            if n.get("pvid"):
                bits.append(f"VLAN {n['pvid']}" + (f" «{n['vlans'][n['pvid']]}»" if (n.get("vlans") or {}).get(n["pvid"]) else ""))
            if poe["on"]:
                bits.append("PoE" + (f" {poe['w']:g} W" if poe["w"] else ""))
            elif poe["on"] is False:
                bits.append("PoE: όχι")
            if (n.get("lag") or {}).get("enabled"):
                bits.append("LAG")
            if n.get("mgmt"):
                bits.append(n["mgmt"])
            d = f"{n['proto']}: " + " · ".join(b for b in bits if b) + tg
            self._both("nbr", "warn" if tagged else "ok", d, d.replace("PoE: όχι", "PoE: no"))
        elif final:
            self._both("nbr", "warn" if tagged else "skip",
                       "Κανένα LLDP/CDP σε " + f"{int(self.listen_s)} s (unmanaged switch ή κλειστό LLDP)" + tg,
                       f"No LLDP/CDP in {int(self.listen_s)} s (unmanaged switch or LLDP disabled)" + tg)

    def _live(self, lang, speed):
        net, iface = self.net, self.run["iface"]
        r = {"link": {}, "nbr": None, "tagged": [], "dhcp": None, "l3": {}, "nbr_done": False}
        # ── 1. link ──
        self._step("link", status="running")
        try:
            link = dict(net.link(iface) or {})
        except Exception as e:  # noqa: BLE001
            link = {"iface": iface, "carrier": None, "err": str(e)[:120]}
        link.setdefault("iface", iface)
        if link.get("carrier") is None and not link.get("err"):
            link["carrier"] = True if link.get("speed") else None
        r["link"] = link
        with self.lock:
            self.run["link"] = link
        if link.get("carrier") is False or (not iface):
            self._both("link", "fail", f"{iface or '—'}: δεν υπάρχει link (carrier)", f"{iface or '—'}: no link (carrier)")
            link["carrier"] = False
            for s in STEP_IDS[1:]:
                self._both(s, "skip", "παραλείφθηκε — δεν υπάρχει link", "skipped — no link")
            return r
        if link.get("carrier") is None:
            link["carrier"] = True       # δεν ξέρουμε (π.χ. άγνωστη πλατφόρμα) — συνεχίζουμε, θα φανεί στο DHCP
            self._both("link", "warn", f"{iface}: δεν μπορώ να διαβάσω την κατάσταση του link", f"{iface}: cannot read the link state")
        else:
            sp, dup = link.get("speed"), link.get("duplex")
            bad = link.get("kind") != "wifi" and ((sp and sp < 1000) or dup == "half")
            dtx = f"{iface}: {speed_txt(sp)}" + (f" {dup} duplex" if dup else "") + (" (Wi‑Fi — όχι πρίζα)" if link.get("kind") == "wifi" else "")
            self._both("link", "warn" if bad else "ok", dtx, dtx.replace("όχι πρίζα", "not a wall socket"))
        # ── 2. ακρόαση LLDP/CDP στο παρασκήνιο, όσο τρέχουν τα υπόλοιπα ──
        others_done = threading.Event()
        lerr = []

        def listen():
            try:
                net.listen(iface, self.listen_s, self._on_frame,
                           lambda: others_done.is_set() and bool((self.run or {}).get("nbr")))
            except Exception as e:  # noqa: BLE001 — χωρίς root / χωρίς scapy
                lerr.append(str(e)[:140] or type(e).__name__)

        self._step("nbr", status="running")
        lt = threading.Thread(target=listen, daemon=True, name="nw-field-lldp")
        lt.start()
        # ── 3. DHCP ──
        self._step("dhcp", status="running")
        try:
            offers = [o for o in (net.dhcp(iface, DHCP_S) or []) if isinstance(o, dict)]
            ms = min((o.get("ms") for o in offers if o.get("ms") is not None), default=None)
            r["dhcp"] = {"offers": offers, "ms": ms}
            servers = sorted({o.get("server") or o.get("ip_src") or "?" for o in offers})
            if not offers:
                self._both("dhcp", "fail", f"Κανένα DHCPOFFER σε {DHCP_S:g} s", f"No DHCPOFFER within {DHCP_S:g} s")
            else:
                o = offers[0]
                d = (f"{o.get('offer')}/{o.get('prefix') or '?'} από {o.get('server')}"
                     + (f" σε {ms / 1000:.2f} s" if ms is not None else "")
                     + f" · gw {o.get('gw') or '—'} · DNS {', '.join(o.get('dns') or []) or '—'}"
                     + (f" · {o['domain']}" if o.get("domain") else "")
                     + (f" · lease {int(o['lease']) // 3600} h" if o.get("lease") else ""))
                en = d.replace(" από ", " from ").replace(" σε ", " in ")
                for h_el, h_en in dhcp_hints(o):
                    d, en = d + " · " + h_el, en + " · " + h_en
                if len(servers) > 1:
                    d, en = f"ΠΡΟΣΟΧΗ {len(servers)} servers ({', '.join(servers[:4])}) · " + d, f"WARNING {len(servers)} servers ({', '.join(servers[:4])}) · " + en
                slow = ms is not None and ms > 2000
                self._both("dhcp", "fail" if len(servers) > 1 else "warn" if slow else "ok", d, en)
        except Exception as e:  # noqa: BLE001
            r["dhcp"] = {"offers": [], "ms": None, "err": str(e)[:140] or type(e).__name__}
            self._both("dhcp", "skip", "Δεν έγινε ο έλεγχος DHCP (θέλει root/CAP_NET_RAW): " + r["dhcp"]["err"],
                       "DHCP check not run (needs root/CAP_NET_RAW): " + r["dhcp"]["err"])
        with self.lock:
            self.run["dhcp"] = r["dhcp"]
        # ── 4. L3 μέσω nettriage ──
        self._l3(r, lang)
        # ── 5. προαιρετικό τεστ ταχύτητας ──
        if not speed:
            self._both("speed", "skip", "δεν ζητήθηκε", "not requested")
        elif self._data_saver():
            self._both("speed", "skip", "παραλείφθηκε — δουλεύω από LTE (οικονομία δεδομένων)", "skipped — running on LTE (data saver)")
        elif r["l3"].get("internet") not in ("ok", "warn"):
            self._both("speed", "skip", "παραλείφθηκε — δεν υπάρχει Internet", "skipped — no Internet")
        else:
            self._step("speed", status="running")
            try:
                s = net.speedtest() or {}
                r["down_mbps"] = s.get("down_mbps")
                d = f"↓ {s.get('down_mbps')} Mbps · {s.get('latency_ms')} ms (Cloudflare, 5 MB)"
                self._both("speed", "ok" if s.get("down_mbps") else "warn", d, d)
            except Exception as e:  # noqa: BLE001
                self._both("speed", "warn", "απέτυχε: " + str(e)[:100], "failed: " + str(e)[:100])
        # ── τέλος ακρόασης ──
        others_done.set()
        self._nbr_step()
        lt.join(self.listen_s + 5)
        with self.lock:
            r["nbr"], r["tagged"] = self.run.get("nbr"), sorted(self.run.get("tagged") or [])
        r["nbr_done"] = not lerr
        if lerr and not r["nbr"]:
            self._both("nbr", "skip", "Δεν έγινε ακρόαση LLDP/CDP (θέλει root/CAP_NET_RAW): " + lerr[0],
                       "LLDP/CDP listen not run (needs root/CAP_NET_RAW): " + lerr[0])
        else:
            self._nbr_step(final=True)
        return r

    def _triage(self):
        if self.triage is None:
            tr = getattr(self.state, "triage", None)
            if tr is None or not hasattr(tr, "run"):
                import nettriage
                tr = nettriage.Triage(self.state)
            self.triage = tr
        return self.triage

    def _l3(self, r, lang):
        """Gateway/DNS/Internet/captive/MTU: τα κάνει το nettriage — εδώ μόνο αντιστοιχίζουμε τα βήματα."""
        mine = ("gateway", "dns", "internet", "captive", "mtu")
        for s in mine:
            self._step(s, status="running")
        # το λειτουργικό θέλει λίγο να πάρει IP μετά το βύσμα
        has_offer = bool((r.get("dhcp") or {}).get("offers"))
        for _ in range(24 if has_offer else 4):
            try:
                info = self.net.local() or {}
            except Exception:  # noqa: BLE001
                info = {}
            if info.get("ip") and not str(info["ip"]).startswith("169.254."):
                break
            self.sleep(0.5)
        try:
            tri = self._triage()
            v = tri.run(lang=lang)
            waited = 0.0
            while isinstance(v, dict) and v.get("error") and waited < 40:   # τρέχει ήδη από την καρτέλα 🩺
                self.sleep(0.5)
                waited += 0.5
                v = tri.run(lang=lang) if tri.view().get("status") != "running" else v
            waited = 0.0
            while True:
                v = tri.view()
                by = {s["id"]: s for s in v.get("steps") or []}
                self._map_triage(r, by)
                if v.get("status") == "done" or waited > 75:
                    break
                self.sleep(0.3)
                waited += 0.3
            pre = next((by[s] for s in ("link", "dhcp") if (by.get(s) or {}).get("status") == "fail"), None)
            if pre:      # ο υπολογιστής δεν έχει IP/gateway → τα L3 δεν έχουν νόημα
                r["l3"]["gateway"] = "fail"
                self._step("gateway", status="fail", detail=pre.get("detail") or "", detail_en=pre.get("detail") or "")
            for s in mine:
                cur = next(x for x in self.run["steps"] if x["id"] == s)
                if cur["status"] in ("running", "pending"):
                    self._both(s, "skip", "δεν ολοκληρώθηκε", "did not complete")
        except Exception as e:  # noqa: BLE001
            for s in mine:
                cur = next(x for x in self.run["steps"] if x["id"] == s)
                if cur["status"] in ("running", "pending"):
                    self._both(s, "skip", "ο έλεγχος απέτυχε: " + str(e)[:100], "check failed: " + str(e)[:100])

    def _map_triage(self, r, by):
        def take(mine, sid):
            s = by.get(sid)
            if not s or s.get("status") in ("pending", "running", None):
                return None
            r["l3"][mine] = s["status"]
            self._step(mine, status=s["status"], detail=s.get("detail") or "", detail_en=s.get("detail") or "", ms=s.get("ms"))
            return s["status"]

        take("gateway", "gateway")
        take("internet", "internet")
        take("captive", "captive")
        take("mtu", "mtu")
        loc, pub = by.get("dns_local") or {}, by.get("dns_public") or {}
        if loc.get("status") not in ("pending", "running", None) and pub.get("status") not in ("pending", "running", None):
            if loc["status"] == "skip" and pub["status"] != "skip":
                take("dns", "dns_public")
            else:
                take("dns", "dns_local")

    def _demo_run(self):
        """Ρεαλιστική προοδευτική εκτέλεση χωρίς δίκτυο (σύντομες παύσεις για να φανεί η πρόοδος στο UI)."""
        n = len(self.hist)
        r = _demo_r(port=f"Gi1/0/{(n % 24) + 1}", ms=360 + (n * 37) % 180, ip=f"10.20.0.{60 + n % 100}")
        seq = [("link", 0.3, "eth0: 1 Gbps full duplex", "eth0: 1 Gbps full duplex"),
               ("dhcp", 0.5, None, None),
               ("gateway", 0.4, "10.20.0.1 απαντά · απώλειες 0% · μέσο 1.2 ms", "10.20.0.1 replies · loss 0% · avg 1.2 ms"),
               ("dns", 0.3, "google.com → 10.20.0.1: 142.250.184.110 (6.1 ms)", "google.com → 10.20.0.1: 142.250.184.110 (6.1 ms)"),
               ("internet", 0.3, "1.1.1.1:443 OK 12.4 ms · 8.8.8.8:443 OK 15.0 ms", "1.1.1.1:443 OK 12.4 ms · 8.8.8.8:443 OK 15.0 ms"),
               ("captive", 0.2, "Κανένα captive portal (204 / «Success»)", "No captive portal (204 / \"Success\")"),
               ("mtu", 0.2, "1472 bytes με DF περνούν (MTU 1500)", "1472 bytes with DF pass (MTU 1500)")]
        self._step("nbr", status="running")
        for sid, d, el, en in seq:
            self._step(sid, status="running")
            self.sleep(d)
            if sid == "link":
                with self.lock:
                    self.run["link"] = r["link"]
            if sid == "dhcp":
                o = r["dhcp"]["offers"][0]
                el = f"{o['offer']}/24 από {o['server']} σε {o['ms'] / 1000:.2f} s · gw {o['gw']} · DNS {', '.join(o['dns'])} · office.lan · lease 8 h"
                en = el.replace(" από ", " from ").replace(" σε ", " in ")
                with self.lock:
                    self.run["dhcp"] = r["dhcp"]
            if sid == "gateway":     # το LLDP «έρχεται» στη μέση
                with self.lock:
                    self.run["nbr"] = r["nbr"]
                self._nbr_step()
            self._both(sid, "ok", el, en)
        self._both("speed", "skip", "δεν ζητήθηκε", "not requested")
        return r

    # ── προβολή ──
    @staticmethod
    def _slim(x):
        return {k: v for k, v in x.items() if k != "steps"}

    def results(self, labels=None):
        """Τελευταίο αποτέλεσμα ανά ετικέτα (πλήρεις εγγραφές, με τη σειρά που δοκιμάστηκαν).
        labels=None → όλες· αλλιώς μόνο όσες ζητήθηκαν (όσες δεν έχουν τεστ απλώς λείπουν)."""
        want = None if labels is None else {clean_label(x) for x in labels}
        with self.lock:
            last = {}
            for x in self.hist:
                if want is None or x["label"] in want:
                    last.pop(x["label"], None)
                    last[x["label"]] = dict(x)
        return list(last.values())

    def oled(self):
        with self.lock:
            if self.run:
                run = dict(self.run, elapsed=time.monotonic() - self.run.get("_m0", time.monotonic()))
                return {"lines": oled_lines(run=run), "busy": True, "label": self.run["label"]}
            rec = self.hist[-1] if self.hist else None
            return {"lines": oled_lines(rec=rec, idle={"iface": self._iface(), "next": self.next_label()}), "busy": False,
                    "label": rec["label"] if rec else "", "next": self.next_label()}

    def view(self):
        with self.lock:
            run = None
            if self.run:
                run = {k: v for k, v in self.run.items() if not k.startswith("_")}
                run["steps"] = [{k: v for k, v in s.items() if not k.startswith("_")} for s in self.run["steps"]]
                run["tagged"] = sorted(self.run["tagged"])
                run["elapsed"] = round(time.monotonic() - self.run.get("_m0", time.monotonic()), 1)
            hist = [self._slim(x) for x in reversed(self.hist[-VIEW_HIST:])]
            last = dict(self.hist[-1]) if self.hist else None
            counts = {k: sum(1 for x in self.hist if x.get("level") == k) for k in ("ok", "warn", "fail")}
            out = {"demo": self.demo, "busy": self.busy, "run": run, "last": last, "history": hist, "count": len(self.hist),
                   "counts": counts, "next_label": self.next_label(), "settings": dict(self.settings), "iface": self._iface(),
                   "error": self.error, "listen_s": self.listen_s}
        up = getattr(self.state, "uplink", None)
        try:
            out["uplink"] = up.view() if up is not None else None
        except Exception:  # noqa: BLE001
            out["uplink"] = None
        return out

    def api(self, method, sub, q, body):
        q, body = q or {}, body or {}
        if method == "GET":
            if sub == "":
                return 200, self.view()
            if sub == "oled":
                return 200, self.oled()
            if sub == "results":
                labels = [x for x in str(q.get("labels") or "").split(",") if x.strip()] or None
                return 200, {"results": self.results(labels)}
            if sub == "csv":
                with self.lock:
                    rows = list(self.hist)
                return 200, {"_raw": to_csv(rows), "_type": "text/csv; charset=utf-8", "_name": "netwatch-sockets.csv"}
            return 404, {"error": "not found"}
        if method == "POST":
            if sub == "test":
                return 200, self.start(body.get("label"), body.get("note") or "", str(body.get("lang") or "el"), bool(body.get("speed")))
            if sub == "settings":
                with self.lock:
                    self._set_settings(body)
                self._save()
                return 200, self.view()
            if sub == "delete":
                with self.lock:
                    n = len(self.hist)
                    self.hist = [x for x in self.hist if x.get("id") != str(body.get("id") or "")]
                    changed = len(self.hist) != n
                if changed:
                    self._save()
                return 200, self.view()
            if sub == "clear":
                if body.get("confirm") is not True:
                    return 400, {"error": "Χρειάζεται επιβεβαίωση (confirm: true).", "error_en": "Confirmation needed (confirm: true)."}
                with self.lock:
                    self.hist = []
                self._save()
                return 200, self.view()
        return 404, {"error": "not found"}
