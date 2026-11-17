"""Τι είδους συσκευή είναι; Από τον κατασκευαστή (MAC/OUI), τα ονόματα και τις θύρες της.

Χρησιμοποιείται από τον χάρτη του LAN (εικονίδιο + όνομα αντί για σκέτο «συσκευή»).
Είναι εκτίμηση: μια «άγνωστη» συσκευή μένει «άγνωστη» — καλύτερα αυτό παρά λάθος ετικέτα.
"""
import functools
import re

import iotcheck

# τύπος → (εικονίδιο, ετικέτα)
TYPES = {
    "router": ("🌐", "Router / AP"),
    "computer": ("💻", "Υπολογιστής"),
    "phone": ("📱", "Κινητό / tablet"),
    "esp": ("🔌", "ESP32 / ESP8266"),
    "pi": ("🍓", "Raspberry Pi"),
    "vm": ("🖥", "VM / server"),
    "nas": ("🗄", "NAS"),
    "printer": ("🖨", "Εκτυπωτής"),
    "tv": ("📺", "TV / media"),
    "camera": ("📷", "Κάμερα"),
    "console": ("🎮", "Κονσόλα"),
    "speaker": ("🔊", "Ηχείο / assistant"),
    "iot": ("💡", "Έξυπνη συσκευή"),
    "unknown": ("❔", "Άγνωστη"),
}

# (regex στον κατασκευαστή, τύπος) — η σειρά μετράει
VENDOR_RULES = [
    (r"espressif", "esp"),
    (r"raspberry", "pi"),
    (r"proxmox|vmware|qemu|xensource|parallels|virtualbox|microsoft corporation.*hyper|docker", "vm"),
    (r"synology|qnap|western digital|buffalo|asustor", "nas"),
    (r"hikvision|dahua|reolink|axis comm|ubiquiti.*cam|wyze|eufy|arlo", "camera"),
    (r"brother|epson|canon|lexmark|kyocera|xerox|ricoh|hp inc|hewlett", "printer"),
    (r"sonos|bose|amazon technologies|google.*nest|harman", "speaker"),
    (r"roku|lg electronics|samsung electronics.*visual|tcl|hisense|vizio|sony.*visual|philips.*tv|nvidia", "tv"),
    (r"nintendo|sony interactive|microsoft.*xbox", "console"),
    (r"tp-link|netgear|ubiquiti|mikrotik|cisco|juniper|aruba|zyxel|technicolor|sagemcom|huawei technologies|zte|avm|fritz|d-link|linksys|tenda|arris|sercomm|askey|mitrastar", "router"),
    (r"tuya|shelly|sonoff|itead|xiaomi.*iot|lifx|signify|philips lighting|meross|broadlink", "iot"),
    (r"samsung|xiaomi|oneplus|oppo|vivo|motorola|huawei device|honor|realme|google", "phone"),
    (r"apple|intel|dell|lenovo|asustek|micro-star|gigabyte|acer|hp |liteon|azurewave|realtek|qualcomm|microsoft", "computer"),
]
NAME_RULES = [
    (r"iphone|ipad|android|galaxy|pixel|redmi|oneplus", "phone"),
    (r"macbook|imac|mac-?mini|desktop|laptop|-pc\b|windows|thinkpad", "computer"),
    (r"esp32|esp8266|esphome|tasmota|wled", "esp"),
    (r"raspberrypi|raspberry", "pi"),
    (r"proxmox|pve|\bvm\b|docker|ubuntu|debian|server", "vm"),
    (r"printer|laserjet|officejet|deskjet|epson|brother", "printer"),
    (r"chromecast|appletv|apple-tv|roku|firetv|bravia|webos|tv\b", "tv"),
    (r"homepod|echo|alexa|sonos|nest", "speaker"),
    (r"synology|diskstation|qnap|nas\b", "nas"),
    (r"cam\b|camera|ipcam|hikvision|reolink", "camera"),
]
PORT_RULES = [
    ({631, 9100, 515}, "printer"),
    ({554}, "camera"),
    ({62078}, "phone"),
    ({8008, 8009}, "tv"),
    ({8006}, "vm"),
    ({1883, 8883}, "iot"),
]


@functools.lru_cache(maxsize=4096)
def vendor(mac):
    """Κατασκευαστής από τη MAC (βάση OUI του scapy, ~50.000 εγγραφές). None αν δεν βρεθεί."""
    m = iotcheck.norm_mac(mac)
    if not m:
        return None
    if int(m[:2], 16) & 2:
        return "τυχαία MAC"
    try:
        from scapy.all import conf
        v = conf.manufdb._get_long_manuf(m) if hasattr(conf.manufdb, "_get_long_manuf") else None
        v = v or conf.manufdb._get_manuf(m)
    except Exception:
        return None
    return None if not v or v == m or re.fullmatch(r"[0-9a-f:]+", v, re.I) else v


def classify(mac=None, names=(), ports=(), gw=False, me=False):
    """→ (τύπος, εικονίδιο, ετικέτα, κατασκευαστής)."""
    v = vendor(mac)
    if gw:
        t = "router"
    elif me:
        t = "computer"
    else:
        t = None
        m = iotcheck.norm_mac(mac) or ""
        k = iotcheck.kind_of(mac, names)
        if m[:8] in iotcheck.VIRT:
            t = "vm"
            v = iotcheck.VIRT[m[:8]]
        elif k in ("esp", "pi"):
            t = k
        text = " ".join(names or ()).lower()
        if not t and text:
            t = next((ty for rx, ty in NAME_RULES if re.search(rx, text)), None)
        if not t and v and v != "τυχαία MAC":
            t = next((ty for rx, ty in VENDOR_RULES if re.search(rx, v.lower())), None)
        if not t:
            ps = set(ports or ())
            t = next((ty for s, ty in PORT_RULES if ps & s), None)
        if not t and v == "τυχαία MAC":
            t = "phone"  # iOS/Android βάζουν τυχαία MAC ανά δίκτυο
        t = t or "unknown"
    icon, label = TYPES[t]
    return t, icon, label, v
