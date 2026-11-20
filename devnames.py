"""🏷 Ονόματα & τύποι συσκευών που δίνεις εσύ («192.168.68.59 = κινητό της Μαρίας»).

Κρατιούνται στον server (data/devnames.json), όχι μόνο στον browser, άρα φαίνονται παντού: χάρτης, διάγραμμα
δικτύου, τεκμηρίωση, συσκευές, Mac app και browser μαζί.

Κλειδί = η MAC (σταθερή ανά δίκτυο, ακόμα και η «ιδιωτική» MAC του iPhone/Android για το ίδιο Wi-Fi).
Αν δεν ξέρουμε MAC, κλειδί η IP («ip:192.168.1.50»).
Ο τύπος είναι ένας από τους τύπους του devtype.TYPES (π.χ. phone, tv, camera) → αλλάζει εικονίδιο και ομάδα.

API
---
DevNames(path=None, on_save=None)
  .get(mac, ip)            → {name, type, note, t} | None
  .set(d)                  → {ok, key, entry} | {error}      (κενό όνομα + τύπος + σημείωση = διαγραφή)
  .bulk(items)             → {ok, saved, errors}
  .all()                   → {key: entry}
"""
import ipaddress
import json
import os
import re
import threading
import time

import devtype

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
MAX = 1000
NAME_MAX = 40
NOTE_MAX = 200
CTRL = re.compile(r"[\x00-\x1f\x7f]")


def norm_mac(m):
    m = str(m or "").strip().lower().replace("-", ":")
    return m if MAC_RE.match(m) and m != "00:00:00:00:00:00" and m != "ff:ff:ff:ff:ff:ff" else None


def key_for(mac=None, ip=None):
    m = norm_mac(mac)
    if m:
        return m
    try:
        a = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return None
    return f"ip:{a}" if a.is_private else None


def _clean_text(s, n):
    return CTRL.sub("", str(s or "")).strip()[:n]


class DevNames:
    def __init__(self, path=None, on_save=None, clock=time.time):
        self.path, self.on_save, self.clock = path, on_save, clock
        self.lock = threading.RLock()
        self.data = {}
        if path:
            self._load()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            return
        for k, v in (raw.get("devices") or {}).items() if isinstance(raw, dict) else []:
            if isinstance(v, dict) and (norm_mac(k) or str(k).startswith("ip:")):
                e = self._entry(v)
                if e:
                    self.data[k] = e

    def _save(self):
        if not self.path:
            return
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"devices": self.data}, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)
        if self.on_save:
            self.on_save(self.path)

    def _entry(self, d):
        name = _clean_text(d.get("name"), NAME_MAX)
        typ = str(d.get("type") or "").strip()
        typ = typ if typ in devtype.TYPES and typ != "unknown" else ""
        note = _clean_text(d.get("note"), NOTE_MAX)
        if not (name or typ or note):
            return None
        return {"name": name, "type": typ, "note": note, "t": d.get("t") or self.clock()}

    def get(self, mac=None, ip=None):
        with self.lock:
            m = norm_mac(mac)
            if m and m in self.data:
                return self.data[m]
            k = key_for(None, ip)
            return self.data.get(k) if k else None

    def set(self, d, save=True):
        d = d if isinstance(d, dict) else {}
        k = d.get("key")
        k = k if k and (norm_mac(k) or (str(k).startswith("ip:") and key_for(None, str(k)[3:]))) else key_for(d.get("mac"), d.get("ip"))
        if not k:
            return {"error": "Χρειάζεται MAC ή ιδιωτική IP."}
        e = self._entry(d)
        with self.lock:
            if e is None:
                self.data.pop(k, None)
                # αν τώρα ξέρουμε MAC, σβήσε και το παλιό κλειδί IP
                ipk = key_for(None, d.get("ip"))
                if ipk and ipk != k:
                    self.data.pop(ipk, None)
            else:
                if k not in self.data and len(self.data) >= MAX:
                    return {"error": f"Έως {MAX} ονόματα."}
                self.data[k] = e
                ipk = key_for(None, d.get("ip"))
                if ipk and ipk != k:  # μετακόμιση από «ip:» σε MAC
                    self.data.pop(ipk, None)
            if save:
                self._save()
        return {"ok": True, "key": k, "entry": e}

    def bulk(self, items):
        saved, errors = 0, []
        for it in (items or [])[:MAX] if isinstance(items, list) else []:
            r = self.set(it, save=False)
            if r.get("error"):
                errors.append(r["error"])
            else:
                saved += 1
        with self.lock:
            self._save()
        return {"ok": True, "saved": saved, "errors": errors[:5]}

    def all(self):
        with self.lock:
            return {k: dict(v) for k, v in self.data.items()}

    def view(self):
        return {"devices": self.all(), "types": [{"id": k, "icon": v[0], "label": v[1]} for k, v in devtype.TYPES.items() if k != "unknown"]}
