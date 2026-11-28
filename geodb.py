"""🗺 Τοπικός γεωεντοπισμός IP — καμία IP δεν φεύγει από τον υπολογιστή.

Πριν: κάθε δημόσια IP με την οποία μιλούσε το δίκτυο στελνόταν (χωρίς κρυπτογράφηση) στο ip-api.com.
Τώρα: αναζήτηση στο vendor/geo/dbip-lite.zip (DB-IP Lite, CC BY 4.0 — https://db-ip.com), που έρχεται μαζί με την εφαρμογή.

Τι δίνει: χώρα και πάροχο/ASN. Όχι πόλη: οι συντεταγμένες είναι της χώρας (με μικρή, σταθερή ανά IP μετατόπιση,
ώστε οι κουκκίδες στον χάρτη να μην πέφτουν η μία πάνω στην άλλη) και το αποτέλεσμα έχει `approx: True`.
Η μορφή του αποτελέσματος είναι ίδια με του ip-api (countryCode, country, lat, lon, isp, org, as, query, status).
"""
import array
import bisect
import hashlib
import ipaddress
import json
import os
import sys
import threading
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "vendor", "geo", "dbip-lite.zip")
ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com)"
SPREAD = 1.6  # μοίρες: πόσο απλώνονται οι κουκκίδες γύρω από το σημείο της χώρας


class GeoDB:
    def __init__(self, path=DB_PATH):
        self.path = path
        self._lock = threading.Lock()
        self._loaded = False
        self.ok = False
        self.meta, self.countries, self.asnames = {}, {}, {}
        self._t = {}

    def _load(self):
        with self._lock:
            if self._loaded:
                return
            self._loaded = True
            try:
                with zipfile.ZipFile(self.path) as z:
                    self.meta = json.loads(z.read("meta.json"))
                    self.countries = json.loads(z.read("countries.json"))
                    self.asnames = json.loads(z.read("asnames.json"))
                    for v, code in ((4, "I"), (6, "Q")):
                        for kind, vals in (("country", None), ("asn", "I")):
                            starts = array.array(code)
                            starts.frombytes(z.read(f"{kind}{v}.start"))
                            if sys.byteorder == "big":
                                starts.byteswap()
                            if vals:
                                nums = array.array(vals)
                                nums.frombytes(z.read(f"asn{v}.num"))
                                if sys.byteorder == "big":
                                    nums.byteswap()
                                self._t[(kind, v)] = (starts, nums)
                            else:
                                self._t[(kind, v)] = (starts, z.read(f"country{v}.cc"))
                self.ok = True
            except Exception:  # noqa: BLE001  (λείπει/χαλασμένο αρχείο: απλώς χωρίς γεωεντοπισμό)
                self.ok = False

    def _find(self, kind, v, key):
        starts, vals = self._t[(kind, v)]
        i = bisect.bisect_right(starts, key) - 1
        if i < 0:
            return None
        return vals[2 * i:2 * i + 2].decode("ascii").strip() if kind == "country" else vals[i]

    def lookup(self, ip):
        """→ dict σαν του ip-api, ή None (ιδιωτική/άγνωστη διεύθυνση, ή δεν υπάρχει βάση)."""
        if not self._loaded:
            self._load()
        if not self.ok:
            return None
        try:
            a = ipaddress.ip_address(str(ip).split("%")[0])
        except ValueError:
            return None
        if not a.is_global:
            return None
        v, key = (4, int(a)) if a.version == 4 else (6, int(a) >> 64)
        cc, asn = self._find("country", v, key), self._find("asn", v, key)
        if not cc and not asn:
            return None
        name, lat, lon = self.countries.get(cc, [cc or None, None, None])
        org = self.asnames.get(str(asn), "") if asn else ""
        out = {"status": "success", "query": str(a), "countryCode": cc or None, "country": name, "regionName": None, "city": None,
               "isp": org or None, "org": org or None, "as": f"AS{asn} {org}".strip() if asn else None, "asname": org or None,
               "approx": True, "source": "db-ip-lite"}
        if lat is not None:
            h = hashlib.blake2s(str(a).encode(), digest_size=4).digest()   # σταθερή μετατόπιση ανά IP (όχι τυχαία σε κάθε εκκίνηση)
            out["lat"] = round(max(-85.0, min(85.0, lat + (h[0] / 255 - 0.5) * SPREAD)), 3)
            out["lon"] = round(lon + (h[1] / 255 - 0.5) * SPREAD * 1.5, 3)
        return out

    def info(self):
        if not self._loaded:
            self._load()
        return {"ok": self.ok, "month": self.meta.get("month"), "source": self.meta.get("source"), "attribution": ATTRIBUTION}


DB = GeoDB()
lookup = DB.lookup
info = DB.info
