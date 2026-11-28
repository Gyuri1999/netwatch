#!/usr/bin/env python3
"""Φτιάχνει το vendor/geo/dbip-lite.zip από τα CSV της DB-IP Lite (χώρα + πάροχος/ASN).

    python tools/geo/build_geodb.py dbip-country-lite-YYYY-MM.csv.gz dbip-asn-lite-YYYY-MM.csv.gz

Τα CSV (https://db-ip.com/db/lite.php, άδεια CC BY 4.0) είναι ~11 MB συμπιεσμένα και 1,2 εκατ. γραμμές. Εδώ γίνονται
συμπαγείς πίνακες για δυαδική αναζήτηση: «αρχή περιοχής» → τιμή. Οι γειτονικές περιοχές με ίδια τιμή ενώνονται και τα
κενά γεμίζουν με «άγνωστο», ώστε να αρκεί ΜΙΑ στήλη (η αρχή). IPv6: μόνο τα πρώτα 64 bit της διεύθυνσης.

Ονόματα χωρών και συντεταγμένες (της κύριας ζώνης ώρας κάθε χώρας) έρχονται από τη βάση tz, που είναι δημόσιος τομέας
(iso3166.tab, zone.tab) — όχι από την DB-IP.
"""
import array
import csv
import gzip
import io
import ipaddress
import json
import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "vendor", "geo", "dbip-lite.zip")
# Ονόματα της βάσης tz που διαβάζονται περίεργα σε χάρτη («Britain (UK)», «Korea (South)»)
NICER = {"GB": "United Kingdom", "KR": "South Korea", "KP": "North Korea", "CZ": "Czechia", "BQ": "Caribbean Netherlands",
         "CC": "Cocos Islands", "CD": "DR Congo", "CG": "Republic of the Congo", "FM": "Micronesia", "MF": "Saint Martin",
         "AS": "American Samoa", "MM": "Myanmar", "SZ": "Eswatini", "WS": "Samoa", "PS": "Palestine", "SX": "Sint Maarten", "VA": "Vatican City", "VG": "British Virgin Islands", "VI": "U.S. Virgin Islands"}
TZ_DIRS = ("/usr/share/zoneinfo", "/usr/share/zoneinfo.default", "/usr/share/lib/zoneinfo")


def _rows(path):
    with gzip.open(path, "rt", encoding="utf-8", newline="") as f:
        yield from csv.reader(f)


def _key(ip):
    """IPv4 → (4, ακέραιος 32 bit) · IPv6 → (6, τα πρώτα 64 bit)."""
    a = ipaddress.ip_address(ip)
    return (4, int(a)) if a.version == 4 else (6, int(a) >> 64)


def ranges(path, value, empty):
    """→ {4: [(αρχή, τιμή)…], 6: […]} ταξινομημένα, ενωμένα, με τα κενά γεμισμένα με `empty`."""
    out = {4: [], 6: []}
    last_end = {4: -1, 6: -1}
    for row in _rows(path):
        (v, start), (v2, end) = _key(row[0]), _key(row[1])
        if v != v2 or end < start:
            continue
        val, lst = value(row), out[v]
        if start <= last_end[v]:            # IPv6: πολλές περιοχές μέσα στο ίδιο /64 → κρατάμε την πρώτη
            continue
        if start > last_end[v] + 1 and (not lst or lst[-1][1] != empty):
            lst.append((last_end[v] + 1, empty))          # κενό ανάμεσα σε δύο περιοχές
        if not lst or lst[-1][1] != val:
            lst.append((start, val))
        last_end[v] = end
    for v, top in ((4, 2 ** 32 - 1), (6, 2 ** 64 - 1)):
        if out[v] and last_end[v] < top and out[v][-1][1] != empty:
            out[v].append((last_end[v] + 1, empty))
    return out


def countries():
    """{«GR»: [«Greece», 37.97, 23.72]} από τη βάση tz (δημόσιος τομέας)."""
    d = next((x for x in TZ_DIRS if os.path.isfile(os.path.join(x, "iso3166.tab"))), None)
    if not d:
        sys.exit("δεν βρήκα τη βάση tz (iso3166.tab) — τρέξε το σε macOS/Linux")
    names, zones = {}, {}
    for line in open(os.path.join(d, "iso3166.tab"), encoding="utf-8"):
        if not line.startswith("#") and "\t" in line:
            cc, name = line.rstrip("\n").split("\t")[:2]
            names[cc] = NICER.get(cc, name)
    for line in open(os.path.join(d, "zone.tab"), encoding="utf-8"):
        if line.startswith("#") or "\t" not in line:
            continue
        cc, coord = line.split("\t")[:2]
        m = re.fullmatch(r"([+-])(\d{2})(\d{2})(\d{2})?([+-])(\d{3})(\d{2})(\d{2})?", coord)
        if m:
            lat = (int(m[2]) + int(m[3]) / 60) * (-1 if m[1] == "-" else 1)
            lon = (int(m[6]) + int(m[7]) / 60) * (-1 if m[5] == "-" else 1)
            zones.setdefault(cc, []).append((lat, lon))
    pos = {}
    for cc, zs in zones.items():
        # η ΜΕΣΑΙΑ ζώνη (διάμεσος πλάτους και μήκους), όχι η πρώτη: η πρώτη της Αυστραλίας είναι το νησί Lord Howe,
        # της Ρωσίας το Καλίνινγκραντ. Η διάμεσος πέφτει στο κύριο σώμα της χώρας.
        lats, lons = sorted(z[0] for z in zs), sorted(z[1] for z in zs)
        pos[cc] = (round(lats[len(lats) // 2], 2), round(lons[len(lons) // 2], 2))
    return {cc: [names[cc], *pos.get(cc, (None, None))] for cc in sorted(names)}


def _arr(code, values):
    a = array.array(code, values)
    if sys.byteorder == "big":
        a.byteswap()                           # το αρχείο είναι πάντα little-endian
    return a.tobytes()


def main(country_csv, asn_csv):
    cc = ranges(country_csv, lambda r: r[2] if re.fullmatch(r"[A-Z]{2}", r[2]) and r[2] != "ZZ" else "", "")
    asn = ranges(asn_csv, lambda r: int(r[2]), 0)
    names = {}
    for row in _rows(asn_csv):
        names.setdefault(row[2], row[3][:80])
    src = [os.path.basename(country_csv), os.path.basename(asn_csv)]
    meta = {"format": 1, "source": "DB-IP Lite (https://db-ip.com), CC BY 4.0", "files": src,
            "month": (re.search(r"(\d{4}-\d{2})", src[0]) or [None, None])[1],
            "ranges": {"country4": len(cc[4]), "country6": len(cc[6]), "asn4": len(asn[4]), "asn6": len(asn[6])}, "asns": len(names)}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        def put(name, data):                   # σταθερή ημερομηνία: ίδια είσοδος → ίδιο αρχείο byte προς byte
            z.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), data, zipfile.ZIP_DEFLATED, 9)
        put("meta.json", json.dumps(meta, ensure_ascii=False, sort_keys=True))
        put("countries.json", json.dumps(countries(), ensure_ascii=False, sort_keys=True))
        put("asnames.json", json.dumps(names, ensure_ascii=False, sort_keys=True))
        for v, code in ((4, "I"), (6, "Q")):
            put(f"country{v}.start", _arr(code, [s for s, _ in cc[v]]))
            put(f"country{v}.cc", "".join((c or "  ") for _, c in cc[v]).encode("ascii"))
            put(f"asn{v}.start", _arr(code, [s for s, _ in asn[v]]))
            put(f"asn{v}.num", _arr("I", [n for _, n in asn[v]]))
    print(json.dumps(meta, ensure_ascii=False), f"→ {OUT} ({os.path.getsize(OUT) / 1048576:.1f} MB)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
