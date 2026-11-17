"""Ποια εφαρμογή μιλάει με ποιον — και ποιοι από αυτούς είναι trackers.

Χρησιμοποιεί `lsof` (macOS/Linux) για να δει τις ανοιχτές συνδέσεις κάθε διεργασίας.
Χωρίς root βλέπει μόνο τις διεργασίες του χρήστη (που είναι και οι εφαρμογές του).
Τα ονόματα των προορισμών έρχονται από το NetState (DNS που είδαμε στο δίκτυο / reverse DNS).
"""
import ipaddress
import re
import subprocess
import threading
import time

# domain suffix → (κατηγορία, ποιος)
TRACKERS = {
    # διαφημίσεις
    "doubleclick.net": ("ads", "Google Ads"), "googlesyndication.com": ("ads", "Google Ads"),
    "googleadservices.com": ("ads", "Google Ads"), "adservice.google.com": ("ads", "Google Ads"),
    "criteo.com": ("ads", "Criteo"), "criteo.net": ("ads", "Criteo"), "adnxs.com": ("ads", "Xandr/AppNexus"),
    "taboola.com": ("ads", "Taboola"), "outbrain.com": ("ads", "Outbrain"), "rubiconproject.com": ("ads", "Magnite"),
    "pubmatic.com": ("ads", "PubMatic"), "openx.net": ("ads", "OpenX"), "amazon-adsystem.com": ("ads", "Amazon Ads"),
    "ads.linkedin.com": ("ads", "LinkedIn Ads"), "bat.bing.com": ("ads", "Microsoft Ads"), "ads-twitter.com": ("ads", "X Ads"),
    "moatads.com": ("ads", "Oracle Moat"), "casalemedia.com": ("ads", "Index Exchange"),
    # analytics / παρακολούθηση συμπεριφοράς
    "google-analytics.com": ("analytics", "Google Analytics"), "googletagmanager.com": ("analytics", "Google Tag Manager"),
    "analytics.google.com": ("analytics", "Google Analytics"), "app-measurement.com": ("analytics", "Firebase Analytics"),
    "connect.facebook.net": ("analytics", "Meta Pixel"), "graph.facebook.com": ("analytics", "Meta SDK"),
    "analytics.tiktok.com": ("analytics", "TikTok Pixel"), "scorecardresearch.com": ("analytics", "comScore"),
    "hotjar.com": ("analytics", "Hotjar"), "hotjar.io": ("analytics", "Hotjar"), "mixpanel.com": ("analytics", "Mixpanel"),
    "segment.io": ("analytics", "Segment"), "segment.com": ("analytics", "Segment"), "amplitude.com": ("analytics", "Amplitude"),
    "clarity.ms": ("analytics", "Microsoft Clarity"), "fullstory.com": ("analytics", "FullStory"), "mouseflow.com": ("analytics", "Mouseflow"),
    "quantserve.com": ("analytics", "Quantcast"), "chartbeat.com": ("analytics", "Chartbeat"), "chartbeat.net": ("analytics", "Chartbeat"),
    "mc.yandex.ru": ("analytics", "Yandex Metrica"), "branch.io": ("analytics", "Branch"), "adjust.com": ("analytics", "Adjust"),
    "appsflyer.com": ("analytics", "AppsFlyer"), "kochava.com": ("analytics", "Kochava"), "braze.com": ("analytics", "Braze"),
    "optimizely.com": ("analytics", "Optimizely"), "heapanalytics.com": ("analytics", "Heap"),
    # τηλεμετρία / crash reports
    "crashlytics.com": ("telemetry", "Firebase Crashlytics"), "sentry.io": ("telemetry", "Sentry"),
    "nr-data.net": ("telemetry", "New Relic"), "datadoghq.com": ("telemetry", "Datadog"), "bugsnag.com": ("telemetry", "Bugsnag"),
    "vortex.data.microsoft.com": ("telemetry", "Microsoft telemetry"), "events.data.microsoft.com": ("telemetry", "Microsoft telemetry"),
    "telemetry.mozilla.org": ("telemetry", "Firefox telemetry"), "xp.apple.com": ("telemetry", "Apple analytics"),
    "metrics.icloud.com": ("telemetry", "Apple analytics"), "browser-intake-datadoghq.com": ("telemetry", "Datadog"),
}
CAT_LABEL = {"ads": "διαφημίσεις", "analytics": "παρακολούθηση", "telemetry": "τηλεμετρία"}


def tracker_for(name):
    """Επιστρέφει {"cat","who","domain"} αν το όνομα ανήκει σε γνωστό tracker."""
    if not name:
        return None
    n = name.lower().rstrip(".")
    for dom, (cat, who) in TRACKERS.items():
        if n == dom or n.endswith("." + dom):
            return {"cat": cat, "who": who, "domain": dom}
    return None


_CONN = re.compile(r"^(?P<l>\[?[0-9a-fA-F:.%\w]*\]?):(?P<lp>\d+|\*)->(?P<r>\[?[0-9a-fA-F:.%\w]+\]?):(?P<rp>\d+)")


def parse_lsof_conns(text):
    """`lsof -nP -i` → [{app,pid,proto,ip,port}] για συνδέσεις προς έξω (όχι localhost, όχι LISTEN)."""
    out = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 9:
            continue
        proto = cols[7].upper()
        if proto not in ("TCP", "UDP"):
            continue
        m = _CONN.match(cols[8])
        if not m:
            continue
        state = cols[9].strip("()") if len(cols) > 9 else ""
        if proto == "TCP" and state and state not in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"):
            continue
        ip = m.group("r").strip("[]").split("%")[0]
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_loopback or a.is_unspecified or a.is_multicast:
            continue
        out.append({"app": cols[0].replace("\\x20", " "), "pid": int(cols[1]) if cols[1].isdigit() else 0,
                    "proto": proto, "ip": ip, "port": int(m.group("rp")), "local": not a.is_global})
    return out


def summarize(conns, name_of=lambda ip: None):
    """Ομαδοποίηση ανά εφαρμογή, με όνομα προορισμού και σήμανση trackers."""
    apps = {}
    for c in conns:
        a = apps.setdefault(c["app"], {"app": c["app"], "pids": set(), "dests": {}})
        a["pids"].add(c["pid"])
        key = (c["ip"], c["port"])
        d = a["dests"].get(key)
        if not d:
            names = name_of(c["ip"]) or []
            if isinstance(names, str):
                names = [names]
            tr = next((t for t in map(tracker_for, names) if t), None)
            d = a["dests"][key] = {"ip": c["ip"], "port": c["port"], "proto": c["proto"], "name": names[0] if names else None,
                                   "tracker": tr, "local": c.get("local", False), "n": 0}
        d["n"] += 1
    res = []
    for a in apps.values():
        dests = sorted(a["dests"].values(), key=lambda d: (not d["tracker"], d["local"], d["name"] or "~", d["ip"]))
        trk = sorted({d["tracker"]["who"] for d in dests if d["tracker"]})
        res.append({"app": a["app"], "pids": sorted(a["pids"]), "dests": dests, "trackers": trk,
                    "hosts": len({d["ip"] for d in dests})})
    res.sort(key=lambda a: (-len(a["trackers"]), -a["hosts"], a["app"].lower()))
    return res


def run_lsof():
    try:
        return subprocess.run(["lsof", "-nP", "-i"], capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return ""


DEMO = [  # (app, ip, port, όνομα)
    ("Google Chrome", "142.250.185.78", 443, "www.google.com"),
    ("Google Chrome", "142.250.181.238", 443, "www.google-analytics.com"),
    ("Google Chrome", "216.58.212.162", 443, "stats.g.doubleclick.net"),
    ("Google Chrome", "157.240.0.35", 443, "connect.facebook.net"),
    ("Google Chrome", "104.244.42.1", 443, "x.com"),
    ("Google Chrome", "35.186.224.25", 443, "script.hotjar.com"),
    ("Spotify", "35.186.224.47", 443, "spclient.wg.spotify.com"),
    ("Spotify", "34.98.75.36", 443, "app-measurement.com"),
    ("Slack", "52.89.214.238", 443, "wss-primary.slack.com"),
    ("Slack", "35.190.12.41", 443, "o1158.ingest.sentry.io"),
    ("Mail", "17.42.251.41", 993, "imap.mail.me.com"),
    ("Discord", "162.159.135.232", 443, "gateway.discord.gg"),
    ("python3.9", "140.82.112.3", 443, "api.github.com"),
    ("AirPlayXPCHelper", "192.168.1.40", 7000, "Living-Room-TV.local"),
]


def demo_conns():
    names = {ip: n for _, ip, _, n in DEMO}
    conns = [{"app": a, "pid": 1000 + i, "proto": "TCP", "ip": ip, "port": p, "local": ip.startswith("192.168.")}
             for i, (a, ip, p, _) in enumerate(DEMO)]
    return conns, (lambda ip: [names[ip]] if ip in names else [])


class Watcher:
    """Κρατά μια μικρή cache (για να μη τρέχει lsof σε κάθε αίτημα)."""

    def __init__(self, name_of, demo=False, ttl=4):
        self.name_of, self.demo, self.ttl = name_of, demo, ttl
        self.lock, self.t, self.data = threading.Lock(), 0, None

    def view(self):
        with self.lock:
            if self.data and time.time() - self.t < self.ttl:
                return self.data
        if self.demo:
            conns, nm = demo_conns()
        else:
            conns, nm = parse_lsof_conns(run_lsof()), self.name_of
        apps = summarize(conns, nm)
        cats = {}
        for a in apps:
            for d in a["dests"]:
                if d["tracker"]:
                    cats[d["tracker"]["cat"]] = cats.get(d["tracker"]["cat"], 0) + 1
        data = {"t": time.time(), "demo": self.demo, "apps": apps, "cats": cats, "cat_label": CAT_LABEL,
                "total": sum(len(a["dests"]) for a in apps)}
        with self.lock:
            self.t, self.data = time.time(), data
        return data
