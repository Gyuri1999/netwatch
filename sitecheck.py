"""NetWatch — 🧅 «Πόσο ασφαλές είναι αυτό το site για την ανωνυμία μου;»

Ο χρήστης δίνει ένα URL (http/https ή .onion). Το NetWatch κατεβάζει ΜΟΝΟ αυτή τη μία σελίδα, όπως θα
έκανε ένας browser (ένα GET της HTML, έως 5 ανακατευθύνσεις) — χωρίς crawling, χωρίς σάρωση, χωρίς
δοκιμές θυρών, χωρίς να κατεβάζει τα scripts/εικόνες της σελίδας — και αξιολογεί τον κίνδυνο για την
ανωνυμία: trackers, session replay, fingerprinting, Cloudflare/captcha για χρήστες Tor, cookies,
ενσωματώσεις τρίτων, HTTPS/HSTS, Onion-Location… Βαθμός A–F με εξηγήσεις σε el/en.

Η λήψη γίνεται ΠΡΟΤΙΜΗΤΕΑ μέσω Tor (SOCKS5 9150 = Tor Browser, μετά 9050 = tor daemon), ώστε ο ίδιος ο
έλεγχος να είναι ανώνυμος. Χωρίς Tor γίνεται απευθείας ΜΟΝΟ αν το ζητήσει ρητά ο χρήστης (direct:true).
Ποτέ cookies, ουδέτερο User-Agent τύπου Tor Browser. Τα URL που ελέγχεις μένουν μόνο στη μνήμη (όχι στον
δίσκο): ποια sites σε ενδιαφέρουν είναι κι αυτό ευαίσθητη πληροφορία.
"""
import gzip
import ipaddress
import re
import socket
import ssl
import threading
import time
import zlib
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

UA = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
TOR_PORTS = (9150, 9050)  # Tor Browser, tor daemon
MAX_REDIRECTS = 5
BODY_CAP = 2 * 1024 * 1024
TIMEOUT = 25.0
MIN_INTERVAL = 5.0       # 1 νέος έλεγχος ανά 5″
CACHE_TTL = 600.0        # αποτέλεσμα ανά URL για 10′
HISTORY = 10
ALLOWED_PORTS = (80, 443, 8080, 8443)  # για clearnet· τα .onion σε οποιαδήποτε θύρα
REDIRECT_CODES = (301, 302, 303, 307, 308)
ONION_RE = re.compile(r"^(?:[a-z0-9-]+\.)*([a-z2-7]{56})\.onion$")
LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet", ".corp", ".localdomain")

# ---------------- registrable domain (απλό eTLD+1) ----------------
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "nhs.uk", "police.uk",
    "com.gr", "gov.gr", "edu.gr", "org.gr", "net.gr", "co.gr",
    "com.cy", "gov.cy", "ac.cy", "org.cy", "net.cy",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.tw", "com.hk", "com.sg", "com.my", "co.in", "net.in", "org.in", "gov.in", "co.id", "co.th",
    "com.br", "net.br", "org.br", "gov.br", "com.ar", "com.mx", "com.co", "com.pe", "com.tr", "gov.tr",
    "co.za", "org.za", "co.il", "org.il", "com.ua", "com.ru", "com.pl", "com.es", "com.pt", "co.at", "or.at",
    "com.eg", "com.sa", "com.vn", "com.ph", "com.pk", "com.ng", "co.ke",
    # «ιδιωτικά» suffixes όπου κάθε υποτομέας είναι άλλος ιδιοκτήτης
    "github.io", "gitlab.io", "blogspot.com", "herokuapp.com", "netlify.app", "vercel.app", "pages.dev",
    "workers.dev", "web.app", "firebaseapp.com", "azurewebsites.net", "cloudfront.net", "appspot.com",
    "s3.amazonaws.com", "wordpress.com", "substack.com",
}


def registrable(host):
    """example.co.uk / a.b.example.com → example.co.uk / example.com (IP → η ίδια)."""
    h = (host or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(h.strip("[]"))
        return h
    except ValueError:
        pass
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    for n in (3, 2):  # π.χ. s3.amazonaws.com (3 μέρη) πριν από amazonaws.com
        if len(parts) > n and ".".join(parts[-n:]) in MULTI_SUFFIXES:
            return ".".join(parts[-(n + 1):])
    return ".".join(parts[-2:])


def _match(host, table):
    """Βρίσκει το πιο συγκεκριμένο suffix του host στο table (dict ή iterable)."""
    h = (host or "").lower().rstrip(".")
    best = None
    for dom in table:
        if (h == dom or h.endswith("." + dom)) and (best is None or len(dom) > len(best)):
            best = dom
    return best


# ---------------- γνωστοί τρίτοι ----------------
def _base_trackers():
    try:
        import apps
        return {d: who for d, (_cat, who) in apps.TRACKERS.items()
                if not d.endswith((".microsoft.com", ".mozilla.org", ".apple.com", ".icloud.com"))}
    except Exception:  # pragma: no cover
        return {}


TRACKERS = _base_trackers()
TRACKERS.update({
    "google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Tag Manager",
    "doubleclick.net": "Google Ads (DoubleClick)", "googlesyndication.com": "Google AdSense",
    "facebook.net": "Meta Pixel", "connect.facebook.net": "Meta Pixel", "facebook.com/tr": "Meta Pixel",
    "segment.com": "Segment", "cdn.segment.com": "Segment", "api.segment.io": "Segment",
    "mixpanel.com": "Mixpanel", "mxpnl.com": "Mixpanel", "amplitude.com": "Amplitude", "cdn.amplitude.com": "Amplitude",
    "analytics.tiktok.com": "TikTok Pixel", "snap.licdn.com": "LinkedIn Insight", "px.ads.linkedin.com": "LinkedIn Insight",
    "static.ads-twitter.com": "X (Twitter) Ads", "ads-twitter.com": "X (Twitter) Ads", "analytics.twitter.com": "X (Twitter) Ads",
    "t.co": "X (Twitter) Ads", "mc.yandex.ru": "Yandex Metrica", "mc.yandex.com": "Yandex Metrica",
    "criteo.com": "Criteo", "criteo.net": "Criteo", "taboola.com": "Taboola", "outbrain.com": "Outbrain",
    "quantserve.com": "Quantcast", "quantcount.com": "Quantcast", "scorecardresearch.com": "comScore",
    "bat.bing.com": "Microsoft Ads", "sc-static.net": "Snap Pixel", "pinimg.com/ct": "Pinterest Tag",
    "ct.pinterest.com": "Pinterest Tag", "adnxs.com": "Xandr", "amazon-adsystem.com": "Amazon Ads",
    "chartbeat.com": "Chartbeat", "chartbeat.net": "Chartbeat", "parsely.com": "Parse.ly", "parsely.net": "Parse.ly",
    "hubspot.com": "HubSpot", "hs-scripts.com": "HubSpot", "hs-analytics.net": "HubSpot", "hsforms.net": "HubSpot",
    "intercom.io": "Intercom", "intercomcdn.com": "Intercom", "heapanalytics.com": "Heap", "optimizely.com": "Optimizely",
    "googleadservices.com": "Google Ads", "adsrvr.org": "The Trade Desk", "rlcdn.com": "LiveRamp",
    "demdex.net": "Adobe Audience Manager", "omtrdc.net": "Adobe Analytics", "2o7.net": "Adobe Analytics",
    "everesttech.net": "Adobe Ads", "addthis.com": "AddThis", "sharethis.com": "ShareThis",
    "onesignal.com": "OneSignal", "cookielaw.org": "OneTrust", "branch.io": "Branch",
})
# τηλεμετρία σφαλμάτων/απόδοσης: όχι διαφημίσεις, αλλά βλέπει την επίσκεψη (info)
TELEMETRY = {"sentry.io": "Sentry", "sentry-cdn.com": "Sentry", "browser.sentry-cdn.com": "Sentry",
             "nr-data.net": "New Relic", "newrelic.com": "New Relic", "js-agent.newrelic.com": "New Relic",
             "datadoghq.com": "Datadog", "browser-intake-datadoghq.com": "Datadog", "bugsnag.com": "Bugsnag"}
for _d in TELEMETRY:
    TRACKERS.pop(_d, None)
# καταγράφουν ό,τι πληκτρολογείς/κάνεις κλικ
REPLAY = {"hotjar.com": "Hotjar", "hotjar.io": "Hotjar", "clarity.ms": "Microsoft Clarity", "fullstory.com": "FullStory",
          "logrocket.com": "LogRocket", "logrocket.io": "LogRocket", "lr-ingest.io": "LogRocket", "lr-in.com": "LogRocket",
          "smartlook.com": "Smartlook", "smartlook.cloud": "Smartlook", "mouseflow.com": "Mouseflow",
          "inspectlet.com": "Inspectlet", "luckyorange.com": "Lucky Orange", "luckyorange.net": "Lucky Orange",
          "contentsquare.net": "Contentsquare", "quantummetric.com": "Quantum Metric", "sessioncam.com": "SessionCam",
          "yandex.ru/metrika/tag_webvisor": "Yandex Webvisor"}
for _d in REPLAY:
    TRACKERS.pop(_d, None)
# fingerprinting / «bot management» (μετρούν τον browser σου για να σε αναγνωρίσουν)
FINGERPRINT = {"fpjs.io": "FingerprintJS", "fpcdn.io": "FingerprintJS", "fingerprint.com": "FingerprintJS",
               "openfpcdn.io": "FingerprintJS", "online-metrix.net": "ThreatMetrix", "threatmetrix.com": "ThreatMetrix",
               "iovation.com": "iovation", "iesnare.com": "iovation", "px-cdn.net": "PerimeterX (HUMAN)",
               "perimeterx.net": "PerimeterX (HUMAN)", "px-cloud.net": "PerimeterX (HUMAN)", "pxchk.net": "PerimeterX (HUMAN)",
               "captcha-delivery.com": "DataDome", "datadome.co": "DataDome", "forter.com": "Forter",
               "sift.com": "Sift", "siftscience.com": "Sift", "kaxsdc.com": "Kount", "seon.io": "SEON",
               "nudatasecurity.com": "Mastercard NuData", "biocatch.com": "BioCatch"}
CAPTCHA = {"recaptcha.net": "Google reCAPTCHA", "google.com/recaptcha": "Google reCAPTCHA",
           "gstatic.com/recaptcha": "Google reCAPTCHA", "hcaptcha.com": "hCaptcha",
           "challenges.cloudflare.com": "Cloudflare Turnstile", "arkoselabs.com": "Arkose Labs (FunCaptcha)",
           "funcaptcha.com": "Arkose Labs (FunCaptcha)"}
# μάρκες σε ονόματα/διαδρομές scripts και σε inline κώδικα
FP_MARKERS = (("@fingerprintjs", "FingerprintJS"), ("fingerprintjs", "FingerprintJS"), ("fpjs", "FingerprintJS"),
              ("clientjs", "ClientJS"), ("new clientjs", "ClientJS"), ("threatmetrix", "ThreatMetrix"),
              ("iovation", "iovation"), ("perimeterx", "PerimeterX (HUMAN)"), ("_pxappid", "PerimeterX (HUMAN)"),
              ("datadome", "DataDome"), ("/akam/", "Akamai Bot Manager"), ("_abck", "Akamai Bot Manager"),
              ("bm_sz", "Akamai Bot Manager"), ("evercookie", "evercookie"))
CDNS = {"cdnjs.cloudflare.com": "cdnjs (Cloudflare)", "cdn.jsdelivr.net": "jsDelivr", "unpkg.com": "unpkg",
        "ajax.googleapis.com": "Google Hosted Libraries", "fonts.googleapis.com": "Google Fonts",
        "fonts.gstatic.com": "Google Fonts", "gstatic.com": "Google (gstatic)", "code.jquery.com": "jQuery CDN",
        "stackpath.bootstrapcdn.com": "BootstrapCDN", "maxcdn.bootstrapcdn.com": "BootstrapCDN",
        "use.fontawesome.com": "Font Awesome", "kit.fontawesome.com": "Font Awesome", "cloudfront.net": "Amazon CloudFront",
        "akamaihd.net": "Akamai", "akamaized.net": "Akamai", "fastly.net": "Fastly", "azureedge.net": "Azure CDN",
        "use.typekit.net": "Adobe Fonts", "p.typekit.net": "Adobe Fonts", "cdn.shopify.com": "Shopify CDN",
        "wp.com": "WordPress.com CDN", "imgix.net": "imgix", "cloudinary.com": "Cloudinary", "b-cdn.net": "bunny.net"}
# σύνδεση με λογαριασμό τρίτου / ενσωματώσεις: η εταιρεία βλέπει την επίσκεψη (και ξέρει ποιος είσαι αν είσαι συνδεδεμένος)
SOCIAL = {"accounts.google.com/gsi": ("login", "Google Sign-In"), "apis.google.com/js/platform": ("login", "Google Sign-In"),
          "apis.google.com": ("login", "Google APIs"), "connect.facebook.net/en_us/sdk": ("login", "Facebook SDK"),
          "/sdk.js": ("login", "Facebook SDK"), "appleid.cdn-apple.com": ("login", "Sign in with Apple"),
          "youtube.com/embed": ("embed", "YouTube"), "youtube.com/iframe_api": ("embed", "YouTube"),
          "youtube-nocookie.com": ("embed", "YouTube (nocookie)"), "player.vimeo.com": ("embed", "Vimeo"),
          "platform.twitter.com": ("embed", "X (Twitter)"), "platform.x.com": ("embed", "X (Twitter)"),
          "facebook.com/plugins": ("embed", "Facebook"), "instagram.com/embed": ("embed", "Instagram"),
          "tiktok.com/embed": ("embed", "TikTok"), "disqus.com": ("embed", "Disqus"),
          "open.spotify.com/embed": ("embed", "Spotify"), "maps.google.com": ("embed", "Google Maps"),
          "google.com/maps": ("embed", "Google Maps"), "maps.googleapis.com": ("embed", "Google Maps"),
          "linkedin.com/embed": ("embed", "LinkedIn"), "reddit.com/embed": ("embed", "Reddit")}
INLINE_TRACKERS = (("gtag(", "Google Analytics"), ("googleanalyticsobject", "Google Analytics"),
                   ("fbq(", "Meta Pixel"), ("_hjsettings", "Hotjar"), ("mixpanel.init", "Mixpanel"),
                   ("amplitude.getinstance", "Amplitude"), ("_linkedin_partner_id", "LinkedIn Insight"),
                   ("ttq.load", "TikTok Pixel"), ("twq(", "X (Twitter) Ads"), ("ym(", "Yandex Metrica"),
                   ("_fs_org", "FullStory"), ("__lo_site_id", "Lucky Orange"), ("_mfq", "Mouseflow"),
                   ("smartlook(", "Smartlook"), ("_linkedin_data_partner", "LinkedIn Insight"),
                   ("uetq", "Microsoft Ads"), ("pintrk(", "Pinterest Tag"), ("snaptr(", "Snap Pixel"))
REPLAY_WHO = set(REPLAY.values()) | {"FullStory", "Lucky Orange", "Mouseflow", "Smartlook", "Hotjar"}
TRACKING_COOKIES = re.compile(r"^(_ga|_gid|_gat|_gcl_|__utm|_fbp|_fbc|fr$|_hj|_clck|_clsk|_uet|ide$|nid$|"
                              r"ajs_|mp_|amplitude_id|_pin_unauth|_tt_|_ttp|_scid|muid$|anonymousid|"
                              r"_pk_id|_cio|hubspotutk|__hs|_vwo|optimizely|_abck|bm_sz|_px|datadome|incap_ses|visid_incap)",
                              re.I)
ID_LIKE = re.compile(r"^[A-Za-z0-9+/=_.:-]{16,}$")


# ---------------- επικύρωση URL ----------------
def _bad_ip(ip):
    ip = ipaddress.ip_address(ip)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
            or ip.is_unspecified or not ip.is_global)


def _literal_ip(host):
    """IP σε οποιαδήποτε μορφή (και 127.1, 0x7f000001, 2130706433) → ipaddress ή None."""
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if re.fullmatch(r"(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}", h, re.I):
        try:
            return ipaddress.ip_address(socket.inet_aton(h))
        except OSError:
            return None
    return None


class UrlError(ValueError):
    def __init__(self, el, en):
        super().__init__(el)
        self.el, self.en = el, en


def normalize_url(raw):
    """Ελέγχει και κανονικοποιεί το URL. Επιστρέφει (url, host, onion). Σφάλμα → UrlError (el/en)."""
    s = str(raw or "").strip()
    if not s:
        raise UrlError("Γράψε μια διεύθυνση (URL).", "Enter an address (URL).")
    if len(s) > 2048:
        raise UrlError("Πολύ μεγάλη διεύθυνση (έως 2048 χαρακτήρες).", "Address too long (max 2048 characters).")
    if any(c in s for c in "\r\n\t\x00 "):
        raise UrlError("Μη έγκυρη διεύθυνση.", "Invalid address.")
    if "://" not in s:
        if re.match(r"^[a-z][a-z0-9+.-]*:", s, re.I) and not re.match(r"^[^:/]+:\d+(/|$)", s):
            raise UrlError("Επιτρέπονται μόνο διευθύνσεις http:// και https://.", "Only http:// and https:// addresses are allowed.")
        host_guess = s.split("/", 1)[0].split(":", 1)[0].lower()
        s = ("http://" if host_guess.endswith(".onion") else "https://") + s
    u = urlsplit(s)
    if u.scheme.lower() not in ("http", "https"):
        raise UrlError("Επιτρέπονται μόνο διευθύνσεις http:// και https://.", "Only http:// and https:// addresses are allowed.")
    if "@" in u.netloc or u.username or u.password:
        raise UrlError("Η διεύθυνση περιέχει όνομα χρήστη/κωδικό — δεν τη στέλνω πουθενά. Αφαίρεσέ τα.",
                       "The address contains a username/password — I won't send it anywhere. Remove them.")
    host = (u.hostname or "").lower().rstrip(".")
    if not host:
        raise UrlError("Λείπει το όνομα του site.", "The site name is missing.")
    try:
        port = u.port
    except ValueError:
        raise UrlError("Μη έγκυρη θύρα.", "Invalid port.")
    onion = host.endswith(".onion")
    if onion:
        if not ONION_RE.match(host):
            raise UrlError("Μη έγκυρη διεύθυνση .onion (χρειάζεται v3: 56 χαρακτήρες πριν το .onion· οι παλιές v2 δεν "
                           "λειτουργούν πια).", "Invalid .onion address (v3 needed: 56 characters before .onion; old v2 "
                           "addresses no longer work).")
    else:
        if host == "localhost" or host.endswith(LOCAL_SUFFIXES) or "." not in host.strip("[]") and not _literal_ip(host):
            raise UrlError("Μόνο δημόσια sites — όχι τοπικές διευθύνσεις (localhost, .local, ονόματα χωρίς τελεία).",
                           "Public sites only — not local addresses (localhost, .local, dotless names).")
        ip = _literal_ip(host)
        if ip is not None and _bad_ip(ip):
            raise UrlError("Μόνο δημόσια sites — όχι ιδιωτικές/τοπικές IP (192.168.x, 10.x, 127.x, link-local…).",
                           "Public sites only — not private/local IPs (192.168.x, 10.x, 127.x, link-local…).")
        if port is not None and port not in ALLOWED_PORTS:
            raise UrlError(f"Θύρα {port}: επιτρέπονται μόνο οι 80, 443, 8080, 8443 (δεν είναι εργαλείο σάρωσης).",
                           f"Port {port}: only 80, 443, 8080, 8443 are allowed (this is not a scanner).")
        try:
            host.encode("idna")
        except UnicodeError:
            raise UrlError("Μη έγκυρο όνομα site.", "Invalid site name.")
    netloc = (f"[{host}]" if ":" in host else host) + (f":{port}" if port else "")
    url = urlunsplit((u.scheme.lower(), netloc, u.path or "/", u.query, ""))
    return url, host, onion


def resolve_public(host, port):
    """Για απευθείας λήψη: επιλύει το όνομα και επιστρέφει ΜΙΑ δημόσια IP (αλλιώς UrlError).
    Συνδεόμαστε σε αυτή ακριβώς την IP (όχι ξανά επίλυση) ώστε να μη γίνεται DNS rebinding."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UrlError("Το όνομα δεν βρέθηκε (DNS).", "The name could not be resolved (DNS).")
    addrs = [i[4][0] for i in infos]
    if not addrs or any(_bad_ip(a.split("%")[0]) for a in addrs):
        raise UrlError("Το όνομα δείχνει σε ιδιωτική/τοπική IP — δεν το ελέγχω.",
                       "The name points to a private/local IP — not checking it.")
    return addrs[0]


# ---------------- HTTP/1.1 client (μέσω Tor ή απευθείας) ----------------
class FetchError(Exception):
    def __init__(self, el, en):
        super().__init__(en)
        self.el, self.en = el, en


def parse_response(raw, cap=BODY_CAP):
    """Ακατέργαστη απάντηση → (status, [(header, value)], body bytes, truncated)."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        raise FetchError("Μη έγκυρη απάντηση HTTP.", "Invalid HTTP response.")
    lines = head.decode("latin-1").split("\r\n")
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
    if not m:
        raise FetchError("Μη έγκυρη απάντηση HTTP.", "Invalid HTTP response.")
    status = int(m.group(1))
    headers = []
    for ln in lines[1:]:
        if ":" in ln and not ln[:1].isspace():
            k, v = ln.split(":", 1)
            headers.append((k.strip().lower(), v.strip()))
    hd = {k: v for k, v in headers}
    truncated = False
    if "chunked" in hd.get("transfer-encoding", "").lower():
        out, i = bytearray(), 0
        while i < len(body):
            j = body.find(b"\r\n", i)
            if j < 0:
                truncated = True
                break
            try:
                n = int(body[i:j].split(b";")[0].strip() or b"0", 16)
            except ValueError:
                break
            if n == 0:
                break
            chunk = body[j + 2:j + 2 + n]
            out += chunk
            if len(chunk) < n:
                truncated = True
                break
            i = j + 2 + n + 2
        body = bytes(out)
    enc = hd.get("content-encoding", "").lower().strip()
    if enc in ("gzip", "x-gzip", "deflate"):
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS)
            body = d.decompress(body, cap)
        except zlib.error:
            try:
                body = gzip.decompress(body)[:cap] if "gzip" in enc else zlib.decompress(body, -zlib.MAX_WBITS)[:cap]
            except Exception:
                body = b""
    elif enc and enc != "identity":
        body = b""  # π.χ. br — δεν το ζητήσαμε (Accept-Encoding: identity)
    if len(body) >= cap:
        body, truncated = body[:cap], True
    return status, headers, body, truncated


def _read_all(s, deadline, cap):
    data = bytearray()
    while len(data) < cap + 65536:
        left = deadline - time.monotonic()
        if left <= 0:
            if data:
                break
            raise FetchError("Λήξη χρόνου — το site άργησε πολύ να απαντήσει.", "Timed out — the site took too long to answer.")
        s.settimeout(min(left, 10))
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            if data:
                break
            raise FetchError("Λήξη χρόνου — το site άργησε πολύ να απαντήσει.", "Timed out — the site took too long to answer.")
        if not chunk:
            break
        data += chunk
    return bytes(data)


def http_get(url, connect, timeout=TIMEOUT, cap=BODY_CAP):
    """Ένα GET (χωρίς ανακατευθύνσεις). connect(host, port, timeout) → socket. Ποτέ cookies."""
    u = urlsplit(url)
    host, tls = u.hostname, u.scheme == "https"
    port = u.port or (443 if tls else 80)
    deadline = time.monotonic() + timeout
    s = connect(host, port, timeout)
    try:
        if tls:
            ctx = ssl.create_default_context()
            try:
                s = ctx.wrap_socket(s, server_hostname=host)
            except ssl.SSLCertVerificationError as e:
                raise FetchError(f"Μη έγκυρο πιστοποιητικό HTTPS ({e.verify_message}) — ένας browser θα σε προειδοποιούσε.",
                                 f"Invalid HTTPS certificate ({e.verify_message}) — a browser would warn you.")
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        hosthdr = host + (f":{u.port}" if u.port else "")
        req = (f"GET {path} HTTP/1.1\r\nHost: {hosthdr}\r\nUser-Agent: {UA}\r\n"
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
               "Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n"
               "Upgrade-Insecure-Requests: 1\r\nConnection: close\r\n\r\n")
        s.sendall(req.encode())
        raw = _read_all(s, deadline, cap)
    finally:
        try:
            s.close()
        except OSError:
            pass
    return parse_response(raw, cap)


def tor_connector(socks_port):
    import privacy

    def connect(host, port, timeout):
        try:
            return privacy.socks_connect(host, port, socks_port, timeout)
        except privacy.SocksError as e:
            if e.code == 4:
                raise FetchError("Το Tor δεν βρήκε το site (μη προσβάσιμο ή ανύπαρκτο όνομα/onion).",
                                 "Tor could not reach the site (unreachable or non-existent name/onion).")
            if e.code == 5:
                raise FetchError("Το site αρνήθηκε τη σύνδεση.", "The site refused the connection.")
            if e.code == 6:
                raise FetchError("Λήξη χρόνου μέσα στο Tor.", "Timed out inside Tor.")
            raise FetchError(f"Αποτυχία σύνδεσης μέσω Tor (SOCKS {e.code}).", f"Connection through Tor failed (SOCKS {e.code}).")
    return connect


def direct_connector():
    def connect(host, port, timeout):
        ip = resolve_public(host, port)
        return socket.create_connection((ip, port), timeout=timeout)
    return connect


def fetch(url, via, connect, timeout=TIMEOUT):
    """GET με έως 5 ανακατευθύνσεις (ίδιοι κανόνες σε κάθε βήμα). Επιστρέφει dict με τα στοιχεία."""
    deadline = time.monotonic() + timeout
    cur, hops, cookies = url, [], []
    for _ in range(MAX_REDIRECTS + 1):
        left = deadline - time.monotonic()
        if left <= 0:
            raise FetchError("Λήξη χρόνου.", "Timed out.")
        status, headers, body, trunc = http_get(cur, connect, timeout=left)
        hops.append({"url": cur, "status": status})
        cookies += [v for k, v in headers if k == "set-cookie"]
        loc = next((v for k, v in headers if k == "location"), None)
        if status in REDIRECT_CODES and loc:
            nxt = urljoin(cur, loc)
            nurl, nhost, nonion = normalize_url(nxt)
            if nonion and via == "direct":
                raise FetchError("Ανακατεύθυνση σε .onion — χρειάζεται Tor.", "Redirects to a .onion — Tor is needed.")
            cur = nurl
            continue
        return {"final_url": cur, "status": status, "headers": headers, "body": body, "truncated": trunc,
                "redirects": hops[:-1], "set_cookies": cookies}
    raise FetchError("Πάρα πολλές ανακατευθύνσεις (>5).", "Too many redirects (>5).")


def tor_port(ports=TOR_PORTS):
    for p in ports:
        try:
            with socket.create_connection(("127.0.0.1", p), timeout=0.5):
                return p
        except OSError:
            pass
    return None


# ---------------- ανάλυση HTML ----------------
class _Page(HTMLParser):
    TEXT_SKIP = {"script", "style", "noscript", "template", "svg", "head", "title"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.resources = []   # (tag, url, rel)
        self.inline = []      # κείμενο inline scripts
        self.meta = []        # (http-equiv/name, content)
        self.noscript = []
        self.text_len = 0
        self.scripts = 0
        self.title = ""
        self._stack = []
        self._cur_script = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag not in ("meta", "link", "img", "br", "hr", "input", "source", "embed", "base", "area", "wbr", "col", "track"):
            self._stack.append(tag)
        if tag == "script":
            self.scripts += 1
            if a.get("src"):
                self.resources.append(("script", a["src"], ""))
                self._cur_script = None
            else:
                self._cur_script = []
        elif tag in ("iframe", "frame", "embed", "audio", "video", "source", "track") and a.get("src"):
            self.resources.append((tag, a["src"], ""))
        elif tag == "img":
            if a.get("src"):
                self.resources.append(("img", a["src"], ""))
        elif tag == "object" and a.get("data"):
            self.resources.append(("object", a["data"], ""))
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower()
            if any(r in rel.split() for r in ("stylesheet", "preconnect", "dns-prefetch", "preload", "prefetch",
                                              "modulepreload", "icon")):
                self.resources.append(("link", a["href"], rel))
        elif tag == "form" and a.get("action"):
            self.resources.append(("form", a["action"], ""))
        elif tag == "meta":
            k = (a.get("http-equiv") or a.get("name") or a.get("property") or "").lower()
            if k:
                self.meta.append((k, a.get("content", "")))
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "script" and self._cur_script is not None:
            self.inline.append("".join(self._cur_script))
            self._cur_script = None
        if tag == "title":
            self._in_title = False
        if tag in self._stack:
            while self._stack and self._stack.pop() != tag:
                pass

    def handle_data(self, data):
        if self._cur_script is not None:
            self._cur_script.append(data)
            return
        if self._in_title:
            self.title += data
            return
        if "noscript" in self._stack:
            self.noscript.append(data)
            return
        if not any(t in self.TEXT_SKIP for t in self._stack):
            self.text_len += len(" ".join(data.split()))


URL_IN_JS = re.compile(r"(?:https?:)?//([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+)"
                       r"(/[^\s'\"<>()\\]*)?", re.I)


def _hsts(v):
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v or "", re.I)
    return (int(m.group(1)) if m else 0), "preload" in (v or "").lower(), "includesubdomains" in (v or "").lower()


def _cookie_info(raw, now=None):
    now = now or time.time()
    parts = [p.strip() for p in raw.split(";")]
    name, _, val = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    life = None
    if "max-age" in attrs:
        try:
            life = int(attrs["max-age"])
        except ValueError:
            pass
    elif "expires" in attrs:
        from email.utils import parsedate_to_datetime
        try:
            life = parsedate_to_datetime(attrs["expires"]).timestamp() - now
        except (TypeError, ValueError, IndexError):
            pass
    name = name.strip()
    return {"name": name[:64], "days": None if life is None else round(life / 86400),
            "long": life is not None and life > 365 * 86400,
            "tracking": bool(TRACKING_COOKIES.match(name)) or (life is not None and life > 180 * 86400 and bool(ID_LIKE.match(val.strip()))),
            "samesite_none": attrs.get("samesite", "").lower() == "none",
            "secure": "secure" in attrs, "httponly": "httponly" in attrs}


def _check(cid, status, weight, title_el, title_en, detail_el, detail_en, **extra):
    c = {"id": cid, "status": status, "weight": weight, "title_el": title_el, "title_en": title_en,
         "detail_el": detail_el, "detail_en": detail_en}
    c.update(extra)
    return c


def _join(items, n=6):
    items = list(items)
    return ", ".join(items[:n]) + (f" (+{len(items) - n})" if len(items) > n else "")


def detect_challenge(status, headers, body_text):
    """Cloudflare/Akamai/Imperva/DataDome/PerimeterX/Sucuri challenge ή μπλοκάρισμα → όνομα ή None."""
    hd = {}
    for k, v in headers:
        hd.setdefault(k, v)
    t = (body_text or "")[:200000].lower()
    server = hd.get("server", "").lower()
    if hd.get("cf-mitigated", "").lower() == "challenge":
        return "Cloudflare"
    if "cloudflare" in server or "cf-ray" in hd:
        if status in (403, 429, 503) and any(m in t for m in ("just a moment", "cf-chl", "challenge-platform", "cf_chl_opt",
                                                                 "attention required", "checking your browser",
                                                                 "enable javascript and cookies to continue")):
            return "Cloudflare"
        if "<title>just a moment...</title>" in t:
            return "Cloudflare"
    if status in (403, 429) and ("akamaighost" in server or ("access denied" in t and "reference #" in t and "edgesuite" in t)):
        return "Akamai"
    if "_incapsula_resource" in t or "incapsula incident id" in t or (status in (403, 503) and "x-iinfo" in hd):
        return "Imperva (Incapsula)"
    if "captcha-delivery.com" in t or (status in (403, 429) and ("x-datadome" in hd or "x-dd-b" in hd)):
        return "DataDome"
    if "px-captcha" in t or "_pxcaptcha" in t or (status in (403, 429) and "press & hold" in t):
        return "PerimeterX (HUMAN)"
    if status in (403, 503) and ("x-sucuri-id" in hd or "sucuri website firewall" in t):
        return "Sucuri"
    if status in (403, 429, 503) and ("captcha" in t or "are you a robot" in t or "verify you are human" in t):
        return "captcha"
    return None


def analyze(url, fetched, via, now=None):
    """Ανάλυση μίας σελίδας. fetched = έξοδος fetch(). Επιστρέφει (checks, third_party, extra)."""
    final = fetched["final_url"]
    fu = urlsplit(final)
    host = (fu.hostname or "").lower()
    onion = host.endswith(".onion")
    status = fetched["status"]
    headers = fetched["headers"]
    hd = {}
    for k, v in headers:
        hd.setdefault(k, v)
    ctype = hd.get("content-type", "").lower()
    m = re.search(r"charset=([\w-]+)", ctype)
    try:
        text = fetched["body"].decode(m.group(1) if m else "utf-8", "replace")
    except LookupError:
        text = fetched["body"].decode("utf-8", "replace")
    page = _Page()
    try:
        page.feed(text)
        page.close()
    except Exception:  # pragma: no cover — το HTMLParser είναι ανεκτικό, αλλά για σιγουριά
        pass
    inline = "\n".join(page.inline)
    inline_l = inline.lower()
    site = registrable(host)
    via_tor = via.startswith("tor")
    checks = []

    # ---- 1. μεταφορά: HTTPS / HSTS ----
    downgraded = any(h["url"].startswith("https://") for h in fetched["redirects"]) and fu.scheme == "http"
    if onion:
        checks.append(_check("transport", "ok", 0, "Σύνδεση .onion (κρυπτογραφημένη από άκρο σε άκρο)",
                             "Onion connection (end-to-end encrypted)",
                             "Η κίνηση μένει μέσα στο Tor μέχρι το ίδιο το site — δεν υπάρχει «έξοδος» (exit node) που να τη "
                             "βλέπει. Το HTTPS εδώ δεν είναι απαραίτητο.",
                             "Traffic stays inside Tor all the way to the site — no exit node can see it. HTTPS isn't needed here."))
    elif fu.scheme == "http":
        checks.append(_check("transport", "bad", 25 if not downgraded else 30,
                             "Χωρίς HTTPS" + (" (υποβάθμιση από https σε http!)" if downgraded else ""),
                             "No HTTPS" + (" (downgraded from https to http!)" if downgraded else ""),
                             "Η σελίδα φτάνει χωρίς κρυπτογράφηση: όποιος είναι στη διαδρομή (Wi-Fi, πάροχος, ή ο exit node "
                             "του Tor) βλέπει και μπορεί να αλλάξει ό,τι διαβάζεις και στέλνεις.",
                             "The page arrives unencrypted: anyone on the path (Wi-Fi, ISP, or the Tor exit node) can read "
                             "and modify what you read and send."))
    else:
        age, pre, sub = _hsts(hd.get("strict-transport-security"))
        if age >= 180 * 86400:
            checks.append(_check("transport", "ok", 0, "HTTPS με HSTS", "HTTPS with HSTS",
                                 f"HSTS max-age {age // 86400} ημέρες" + (", preload" if pre else "") +
                                 (", includeSubDomains" if sub else "") + ": ο browser δεν θα ξαναμπεί ποτέ με απλό http.",
                                 f"HSTS max-age {age // 86400} days" + (", preload" if pre else "") +
                                 (", includeSubDomains" if sub else "") + ": the browser will never fall back to plain http.",
                                 hsts={"max_age": age, "preload": pre, "include_subdomains": sub}))
        else:
            checks.append(_check("transport", "warn", 5, "HTTPS χωρίς (επαρκές) HSTS", "HTTPS without (sufficient) HSTS",
                                 ("Το HSTS είναι πολύ σύντομο (" + str(age // 86400) + " ημέρες)." if age else
                                  "Δεν στέλνει Strict-Transport-Security.") +
                                 " Η πρώτη επίσκεψη με http:// μπορεί να υποκλαπεί (SSL stripping) — γράφε πάντα https://.",
                                 ("HSTS is too short (" + str(age // 86400) + " days)." if age else
                                  "No Strict-Transport-Security header.") +
                                 " A first visit over http:// can be intercepted (SSL stripping) — always type https://.",
                                 hsts={"max_age": age, "preload": pre, "include_subdomains": sub}))

    # ---- 2. Onion-Location ----
    onion_loc = hd.get("onion-location") or next((c for k, c in page.meta if k == "onion-location"), None)
    onion_loc_addr = None
    if onion_loc:
        try:
            ou = urlsplit(onion_loc.strip())
            if (ou.hostname or "").endswith(".onion"):
                onion_loc_addr = urlunsplit((ou.scheme or "http", ou.netloc, ou.path or "/", ou.query, ""))
        except ValueError:
            pass
    if onion:
        pass
    elif onion_loc_addr:
        checks.append(_check("onion_location", "ok", 0, "Έχει έκδοση .onion", "Has an onion version",
                             f"Το site προσφέρει διεύθυνση .onion: {onion_loc_addr} — προτίμησέ τη στο Tor Browser (καμία "
                             "έξοδος Tor, λιγότερα μπλοκαρίσματα).",
                             f"The site offers an onion address: {onion_loc_addr} — prefer it in Tor Browser (no Tor exit, "
                             "fewer blocks).", address=onion_loc_addr))
    else:
        checks.append(_check("onion_location", "info", 0, "Χωρίς έκδοση .onion", "No onion version",
                             "Δεν δηλώνει Onion-Location. Μέσω Tor θα περάσεις από exit node (ορατός ο προορισμός, όχι το περιεχόμενο αν είναι HTTPS).",
                             "No Onion-Location advertised. Over Tor you'll go through an exit node (it sees the destination, "
                             "not the content if HTTPS)."))

    # ---- 3. μπλοκάρει / ζητά captcha από Tor ----
    challenge = detect_challenge(status, headers, text)
    cf = "cloudflare" in hd.get("server", "").lower() or "cf-ray" in hd
    if challenge:
        who = "Cloudflare" if challenge == "Cloudflare" else challenge
        checks.append(_check("tor_blocking", "warn", 12,
                             f"Μπλοκάρει ή ζητά captcha ({who})" + (" από χρήστες Tor" if via_tor else ""),
                             f"Blocks or challenges {'Tor users' if via_tor else 'visitors'} ({who})",
                             f"HTTP {status}: αντί για τη σελίδα ήρθε σελίδα ελέγχου «είσαι άνθρωπος;». Οι χρήστες Tor θα "
                             "βλέπουν συνεχώς captcha ή θα κόβονται — και κάθε captcha τρέχει JavaScript που μετρά τον browser "
                             "σου. Η ανάλυση παρακάτω αφορά τη σελίδα ελέγχου, όχι το ίδιο το site.",
                             f"HTTP {status}: a \"are you human?\" check page came back instead of the site. Tor users will "
                             "keep seeing captchas or be blocked — and every challenge runs JavaScript that measures your "
                             "browser. The analysis below is of the challenge page, not the site itself.", provider=who))
    elif via_tor:
        checks.append(_check("tor_blocking", "ok", 0, "Δέχεται χρήστες Tor", "Accepts Tor users",
                             f"Η σελίδα ήρθε κανονικά μέσω Tor (HTTP {status})." +
                             (" Περνά από Cloudflare: η Cloudflare βλέπει όλη την κίνηση αποκρυπτογραφημένη." if cf else ""),
                             f"The page loaded normally over Tor (HTTP {status})." +
                             (" It's behind Cloudflare: Cloudflare sees all traffic decrypted." if cf else "")))
    else:
        checks.append(_check("tor_blocking", "info", 0, "Δεν δοκιμάστηκε μέσω Tor", "Not tested over Tor",
                             "Ο έλεγχος έγινε απευθείας (χωρίς Tor), οπότε δεν ξέρουμε αν το site μπλοκάρει χρήστες Tor." +
                             (" Περνά από Cloudflare — συχνά ζητά captcha από Tor." if cf else ""),
                             "The check ran directly (no Tor), so we don't know whether the site blocks Tor users." +
                             (" It's behind Cloudflare — it often challenges Tor." if cf else "")))

    # ---- 4. τρίτοι (hosts) ----
    res_urls = []
    for tag, ru, rel in page.resources:
        ru = ru.strip()
        if not ru or ru.startswith(("data:", "blob:", "javascript:", "#", "about:", "mailto:")):
            continue
        try:
            absu = urljoin(final, ru)
        except ValueError:
            continue
        res_urls.append((tag, absu, rel))
    for mm in URL_IN_JS.finditer(inline):
        h = mm.group(1).lower()
        if "." in h and not re.fullmatch(r"[\d.]+", h) and re.search(r"\.[a-z]{2,}$", h):
            res_urls.append(("inline", "https://" + h + (mm.group(2) or "/"), ""))
    hosts = {}
    mixed = []
    for tag, absu, rel in res_urls:
        try:
            ru = urlsplit(absu)
        except ValueError:
            continue
        rh = (ru.hostname or "").lower()
        if not rh:
            continue
        if fu.scheme == "https" and ru.scheme == "http" and tag in ("script", "iframe", "frame", "img", "link", "audio",
                                                                     "video", "source", "object", "embed", "form"):
            mixed.append((tag, absu))
        if registrable(rh) == site or ru.scheme not in ("http", "https"):
            continue
        e = hosts.setdefault(rh, {"host": rh, "tags": set(), "paths": []})
        e["tags"].add(tag)
        if len(e["paths"]) < 5:
            e["paths"].append((rh + (ru.path or "/")).lower())

    def classify(h, paths):
        hp = [h] + paths
        for table, kind in ((REPLAY, "replay"), (FINGERPRINT, "fingerprint")):
            for p in hp:
                d = _match(p, table) or next((k for k in table if "/" in k and k in p), None)
                if d:
                    return kind, table[d]
        for p in hp:
            low = p.lower()
            for mk, who in FP_MARKERS:
                if mk in low and mk not in ("_abck", "bm_sz"):
                    return "fingerprint", who
        for p in hp:
            d = next((k for k in CAPTCHA if "/" in k and k in p), None) or _match(h, {k for k in CAPTCHA if "/" not in k})
            if d:
                return "captcha", CAPTCHA[d]
        d = _match(h, {k for k in TRACKERS if "/" not in k}) or next((k for k in TRACKERS if "/" in k and any(k in p for p in hp)), None)
        if d:
            return "tracker", TRACKERS[d]
        d = _match(h, TELEMETRY)
        if d:
            return "telemetry", TELEMETRY[d]
        for p in hp:
            d = next((k for k in SOCIAL if k in p and ("/" in k or _match(h, [k]))), None)
            if d:
                return SOCIAL[d][0], SOCIAL[d][1]
        d = _match(h, CDNS)
        if d:
            return "cdn", CDNS[d]
        return "other", None

    third = []
    for h, e in hosts.items():
        kind, who = classify(h, e["paths"])
        third.append({"host": h, "kind": kind, "who": who, "seen_in": sorted(e["tags"])})
    # inline μάρκες (snippets χωρίς URL ή με URL που δεν φαίνεται)
    inline_who = set()
    for mk, who in INLINE_TRACKERS:
        if mk in inline_l:
            inline_who.add(who)
    inline_fp = {who for mk, who in FP_MARKERS if mk in inline_l and mk not in ("/akam/",)}
    order = {"replay": 0, "fingerprint": 1, "tracker": 2, "captcha": 3, "login": 4, "embed": 5, "telemetry": 6, "cdn": 7, "other": 8}
    third.sort(key=lambda t: (order.get(t["kind"], 9), t["host"]))
    n3 = len(third)

    # ---- trackers ----
    tracker_who = {t["who"] for t in third if t["kind"] == "tracker"}
    replay_who = {t["who"] for t in third if t["kind"] == "replay"}
    for w in inline_who:
        if w in REPLAY_WHO:
            replay_who.add(w)
        else:
            tracker_who.add(w)
    replay_who = {w for w in replay_who if w}
    tracker_who = {w for w in tracker_who if w and w not in replay_who}
    telemetry_who = {t["who"] for t in third if t["kind"] == "telemetry"}

    if n3 == 0:
        checks.append(_check("third_party", "ok", 0, "Κανένας τρίτος", "No third parties",
                             "Η σελίδα δεν φορτώνει τίποτα από άλλους τομείς — μόνο το ίδιο το site ξέρει ότι μπήκες.",
                             "The page loads nothing from other domains — only the site itself knows you visited."))
    else:
        st, w = ("info", 2) if n3 <= 5 else ("warn", 6) if n3 <= 15 else ("warn", 10)
        names = [t["host"] for t in third]
        checks.append(_check("third_party", st, w, f"{n3} τρίτοι τομείς", f"{n3} third-party domains",
                             f"Ο browser σου θα μιλήσει και με: {_join(names)}. Ο καθένας βλέπει την IP σου (ή του Tor) και "
                             "συνήθως ποια σελίδα διαβάζεις (Referer).",
                             f"Your browser will also talk to: {_join(names)}. Each one sees your IP (or Tor's) and usually "
                             "which page you're reading (Referer).", count=n3))

    if tracker_who:
        nt = len(tracker_who)
        checks.append(_check("trackers", "bad" if nt >= 3 else "warn", min(20, 5 * nt),
                             f"{nt} trackers διαφημίσεων/στατιστικών", f"{nt} ad/analytics trackers",
                             f"{_join(sorted(tracker_who))}. Σε ακολουθούν από site σε site και φτιάχνουν προφίλ σου — εκτός αν "
                             "τους μπλοκάρεις (uBlock Origin) ή χρησιμοποιείς Tor Browser.",
                             f"{_join(sorted(tracker_who))}. They follow you from site to site and build a profile — unless "
                             "you block them (uBlock Origin) or use Tor Browser.", who=sorted(tracker_who)))
    else:
        checks.append(_check("trackers", "ok", 0, "Χωρίς γνωστούς trackers", "No known trackers",
                             "Δεν βρέθηκε γνωστός tracker στη σελίδα (ελέγχθηκε μόνο η HTML, όχι τα scripts που φορτώνει).",
                             "No known tracker found on the page (only the HTML was checked, not the scripts it loads)."))
    if telemetry_who:
        checks.append(_check("telemetry", "info", 1, "Τηλεμετρία σφαλμάτων/απόδοσης", "Error/performance telemetry",
                             f"{_join(sorted(telemetry_who))}: στέλνει σφάλματα και χρόνους φόρτωσης — όχι διαφημίσεις, αλλά "
                             "μαθαίνει για την επίσκεψη.",
                             f"{_join(sorted(telemetry_who))}: sends errors and load timings — not ads, but it learns about "
                             "the visit.", who=sorted(telemetry_who)))

    # ---- session replay ----
    if replay_who:
        checks.append(_check("session_replay", "bad", 15, "Καταγραφή συνεδρίας (session replay)", "Session replay",
                             f"{_join(sorted(replay_who))}: καταγράφει ό,τι κάνεις στη σελίδα — κινήσεις ποντικιού, κλικ, ό,τι "
                             "πληκτρολογείς (ακόμα κι αν δεν πατήσεις «αποστολή») — και το ξαναπαίζει σαν βίντεο.",
                             f"{_join(sorted(replay_who))}: records everything you do on the page — mouse moves, clicks, "
                             "what you type (even if you never press \"send\") — and replays it like a video.",
                             who=sorted(replay_who)))
    else:
        checks.append(_check("session_replay", "ok", 0, "Χωρίς session replay", "No session replay",
                             "Δεν βρέθηκε Hotjar, Clarity, FullStory, LogRocket κ.ά.",
                             "No Hotjar, Clarity, FullStory, LogRocket etc. found."))

    # ---- fingerprinting ----
    fp_libs = {t["who"] for t in third if t["kind"] == "fingerprint"} | inline_fp
    if any(k == "_abck" or k == "bm_sz" for k in (c.split("=", 1)[0].strip().lower() for c in fetched["set_cookies"])):
        fp_libs.add("Akamai Bot Manager")
    captchas = {t["who"] for t in third if t["kind"] == "captcha"}
    if "grecaptcha" in inline_l or "g-recaptcha" in text.lower():
        captchas.add("Google reCAPTCHA")
    if "h-captcha" in text.lower() or "hcaptcha.com" in inline_l:
        captchas.add("hCaptcha")
    heur = []
    if "todataurl(" in inline_l and ("getcontext(" in inline_l or "canvas" in inline_l):
        heur.append("canvas")
    if "getimagedata(" in inline_l:
        heur.append("getImageData")
    if ("audiocontext" in inline_l) and "createoscillator" in inline_l:
        heur.append("AudioContext")
    if "navigator.plugins" in inline_l:
        heur.append("navigator.plugins")
    if "webgl_debug_renderer_info" in inline_l:
        heur.append("WEBGL_debug_renderer_info")
    strong_heur = bool({"AudioContext", "WEBGL_debug_renderer_info"} & set(heur)) or len(heur) >= 2
    if fp_libs or strong_heur or captchas:
        w = (15 if fp_libs else 0) + (8 if strong_heur else 0)
        w += 6 if "Google reCAPTCHA" in captchas else 3 if captchas else 0
        w = min(25, w)
        st = "bad" if fp_libs else "warn"
        el, en = [], []
        if fp_libs:
            el.append(f"Βιβλιοθήκη fingerprinting: {_join(sorted(fp_libs))} — μετρά δεκάδες ιδιότητες του browser σου "
                      "(γραμματοσειρές, κάρτα γραφικών, οθόνη…) για να σε αναγνωρίζει ακόμα και χωρίς cookies.")
            en.append(f"Fingerprinting library: {_join(sorted(fp_libs))} — measures dozens of browser properties (fonts, "
                      "GPU, screen…) to recognise you even without cookies.")
        if strong_heur:
            el.append(f"Inline κώδικας που μοιάζει με fingerprinting: {', '.join(heur)}.")
            en.append(f"Inline code that looks like fingerprinting: {', '.join(heur)}.")
        if captchas:
            g = "Google reCAPTCHA" in captchas
            el.append(f"Captcha: {_join(sorted(captchas))}" + (" — η Google βλέπει την επίσκεψη και τη συνδέει με ό,τι "
                                                               "ξέρει για σένα." if g else "."))
            en.append(f"Captcha: {_join(sorted(captchas))}" + (" — Google sees the visit and links it to what it knows "
                                                               "about you." if g else "."))
        checks.append(_check("fingerprinting", st, w,
                             "Fingerprinting / bot detection" if fp_libs or strong_heur else "Captcha τρίτου",
                             "Fingerprinting / bot detection" if fp_libs or strong_heur else "Third-party captcha",
                             " ".join(el), " ".join(en), libs=sorted(fp_libs), heuristics=heur, captcha=sorted(captchas)))
    else:
        checks.append(_check("fingerprinting", "ok" if not heur else "info", 0, "Χωρίς γνωστό fingerprinting",
                             "No known fingerprinting",
                             "Δεν βρέθηκε γνωστή βιβλιοθήκη fingerprinting στην HTML." +
                             (f" (Ασθενές σημάδι: {', '.join(heur)}.)" if heur else ""),
                             "No known fingerprinting library found in the HTML." +
                             (f" (Weak signal: {', '.join(heur)}.)" if heur else ""), heuristics=heur))

    # ---- cookies ----
    cks = [_cookie_info(c, now) for c in fetched["set_cookies"][:50]]
    if not cks:
        checks.append(_check("cookies", "ok", 0, "Κανένα cookie στην πρώτη επίσκεψη", "No cookies on first visit",
                             "Δεν έστειλε Set-Cookie. (Cookies που βάζουν scripts/τρίτοι δεν φαίνονται από εδώ.)",
                             "No Set-Cookie sent. (Cookies set by scripts/third parties aren't visible from here.)",
                             cookies=[]))
    else:
        long_ = [c["name"] for c in cks if c["long"]]
        track = [c["name"] for c in cks if c["tracking"]]
        ssn = [c["name"] for c in cks if c["samesite_none"]]
        w = 2 + (6 if (long_ or track) else 0) + (2 if ssn else 0)
        st = "warn" if (long_ or track or ssn) else "info"
        el = [f"{len(cks)} cookie(s) πριν καν κάνεις κάτι: {_join(c['name'] for c in cks)}."]
        en = [f"{len(cks)} cookie(s) before you do anything: {_join(c['name'] for c in cks)}."]
        if track:
            el.append(f"Μοιάζουν με αναγνωριστικά παρακολούθησης: {_join(track)}.")
            en.append(f"Look like tracking identifiers: {_join(track)}.")
        if long_:
            el.append(f"Διαρκούν πάνω από 1 χρόνο: {_join(long_)}.")
            en.append(f"Last more than 1 year: {_join(long_)}.")
        if ssn:
            el.append(f"SameSite=None (στέλνονται και από άλλα sites): {_join(ssn)}.")
            en.append(f"SameSite=None (sent from other sites too): {_join(ssn)}.")
        checks.append(_check("cookies", st, min(8, w), f"{len(cks)} cookies", f"{len(cks)} cookies", " ".join(el), " ".join(en),
                             cookies=[{k: c[k] for k in ("name", "days", "tracking", "samesite_none")} for c in cks[:20]]))

    # ---- JavaScript ----
    ns = " ".join(page.noscript).lower()
    needs_js = (page.text_len < 200 and page.scripts > 0) or any(
        m in ns for m in ("enable javascript", "javascript is required", "requires javascript", "turn on javascript",
                          "javascript enabled", "ενεργοποιήστε τη javascript", "ενεργοποίησε τη javascript"))
    if needs_js and not challenge:
        checks.append(_check("js_required", "info", 2, "Χρειάζεται JavaScript", "Needs JavaScript",
                             "Χωρίς JavaScript η σελίδα είναι (σχεδόν) άδεια. Στο Tor Browser με επίπεδο «Safest» δεν θα "
                             "λειτουργεί — θα πρέπει να κατεβάσεις την προστασία, και η JavaScript είναι η κύρια πηγή "
                             "fingerprinting και exploits.",
                             "Without JavaScript the page is (nearly) empty. In Tor Browser at the \"Safest\" level it won't "
                             "work — you'd have to lower protection, and JavaScript is the main source of fingerprinting and "
                             "exploits."))
    elif not challenge:
        checks.append(_check("js_required", "ok", 0, "Διαβάζεται χωρίς JavaScript", "Readable without JavaScript",
                             "Υπάρχει περιεχόμενο στην HTML — πιθανότατα δουλεύει και στο επίπεδο «Safest» του Tor Browser.",
                             "There's content in the HTML — it likely works at Tor Browser's \"Safest\" level too."))

    # ---- σύνδεση με τρίτους / ενσωματώσεις ----
    soc = sorted({t["who"] for t in third if t["kind"] in ("login", "embed")})
    if "fb.init(" in inline_l or "fbasyncinit" in inline_l:
        soc = sorted(set(soc) | {"Facebook SDK"})
    if "google.accounts.id" in inline_l:
        soc = sorted(set(soc) | {"Google Sign-In"})
    if soc:
        checks.append(_check("social", "warn", min(12, 4 * len(soc)), "Σύνδεση/ενσωματώσεις μεγάλων εταιρειών",
                             "Big-tech sign-in / embeds",
                             f"{_join(soc)}: αυτές οι εταιρείες βλέπουν την επίσκεψη· αν είσαι συνδεδεμένος σε αυτές στον ίδιο "
                             "browser, ξέρουν ΠΟΙΟΣ είσαι. Μην κάνεις «Σύνδεση με Google/Facebook».",
                             f"{_join(soc)}: these companies see the visit; if you're logged in to them in the same browser "
                             "they know WHO you are. Don't use \"Sign in with Google/Facebook\".", who=soc))

    # ---- WebRTC ----
    if "rtcpeerconnection" in inline_l:
        checks.append(_check("webrtc", "warn", 5, "Χρησιμοποιεί WebRTC", "Uses WebRTC",
                             "Ο κώδικας της σελίδας ανοίγει RTCPeerConnection: σε κανονικό browser με VPN/proxy μπορεί να "
                             "διαρρεύσει την πραγματική ή την τοπική σου IP. (Το Tor Browser απενεργοποιεί το WebRTC.)",
                             "The page's code opens an RTCPeerConnection: in a normal browser with VPN/proxy it can leak your "
                             "real or local IP. (Tor Browser disables WebRTC.)"))

    # ---- μικτό περιεχόμενο ----
    if mixed:
        act = any(t in ("script", "iframe", "frame", "object", "embed", "link", "form") for t, _ in mixed)
        checks.append(_check("mixed_content", "warn", 10 if act else 4, "Μικτό περιεχόμενο (http μέσα σε https)",
                             "Mixed content (http inside https)",
                             f"{len(mixed)} πόροι φορτώνουν με απλό http:// ({_join(u for _, u in mixed[:5])}) — όποιος είναι "
                             "στη διαδρομή τους βλέπει" + (" και μπορεί να εισάγει κώδικα." if act else "."),
                             f"{len(mixed)} resources load over plain http:// ({_join(u for _, u in mixed[:5])}) — anyone on "
                             "the path can see them" + (" and inject code." if act else "."), count=len(mixed)))

    # ---- επικεφαλίδες ασφαλείας ----
    rp = (hd.get("referrer-policy") or next((c for k, c in page.meta if k == "referrer"), "")).lower().split(",")[-1].strip()
    csp = "content-security-policy" in hd
    pp = "permissions-policy" in hd
    good_rp = rp in ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin")
    if rp in ("unsafe-url", "no-referrer-when-downgrade"):
        st, w = "warn", 3
    elif good_rp and csp:
        st, w = "ok", 0
    else:
        st, w = "info", 1
    checks.append(_check("headers", st, w, "Επικεφαλίδες ιδιωτικότητας", "Privacy headers",
                         f"Referrer-Policy: {rp or '— (προεπιλογή browser: strict-origin-when-cross-origin)'}"
                         + (" — στέλνει ΟΛΟ το URL σε τρίτους!" if rp == "unsafe-url" else "")
                         + f"; Content-Security-Policy: {'ναι' if csp else 'όχι'}; Permissions-Policy: {'ναι' if pp else 'όχι'}.",
                         f"Referrer-Policy: {rp or '— (browser default: strict-origin-when-cross-origin)'}"
                         + (" — sends the FULL URL to third parties!" if rp == "unsafe-url" else "")
                         + f"; Content-Security-Policy: {'yes' if csp else 'no'}; Permissions-Policy: {'yes' if pp else 'no'}.",
                         referrer_policy=rp or None, csp=csp, permissions_policy=pp))

    extra = {"title": " ".join(page.title.split())[:120], "onion_location": onion_loc_addr, "challenge": challenge,
             "trackers_count": len(tracker_who) + len(replay_who) + len(fp_libs),
             "tracker_names": sorted(tracker_who | replay_who | fp_libs), "cloudflare": cf}
    return checks, third[:30], extra


# ---------------- βαθμός, ετυμηγορία, συμβουλές ----------------
def grade_for(score):
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


VERDICT = {
    "A": ("Πολύ φιλικό για την ανωνυμία σου — ελάχιστοι ή κανένας τρίτος σε παρακολουθεί.",
          "Very anonymity-friendly — few or no third parties watch you."),
    "B": ("Σχετικά καλό· λίγοι τρίτοι ή μικρά θέματα. Με Tor Browser είσαι εντάξει.",
          "Fairly good; a few third parties or minor issues. With Tor Browser you're fine."),
    "C": ("Μέτριο: αρκετοί τρίτοι ή εμπόδια για χρήστες Tor. Πρόσεχε τι κάνεις εκεί.",
          "Mediocre: several third parties or hurdles for Tor users. Be careful what you do there."),
    "D": ("Κακό για την ανωνυμία: trackers και καταγραφή/fingerprinting. Μπες μόνο με Tor Browser και μη συνδεθείς.",
          "Bad for anonymity: trackers and recording/fingerprinting. Visit only with Tor Browser and don't log in."),
    "F": ("Πολύ κακό: σε παρακολουθούν από πολλές μεριές ή χωρίς κρυπτογράφηση. Απόφυγέ το ή χρησιμοποίησε Tor Browser στο «Safest».",
          "Very bad: watched from many sides or unencrypted. Avoid it, or use Tor Browser at \"Safest\"."),
}


def advice(checks, extra, onion, via):
    by = {c["id"]: c for c in checks}
    el, en = [], []

    def add(a, b):
        el.append(a)
        en.append(b)
    if extra.get("onion_location"):
        add(f"Χρησιμοποίησε τη διεύθυνση .onion: {extra['onion_location']}", f"Use the onion address: {extra['onion_location']}")
    if by.get("transport", {}).get("status") == "bad":
        add("Μην πληκτρολογείς κωδικούς ή προσωπικά στοιχεία εδώ — δεν υπάρχει κρυπτογράφηση.",
            "Don't type passwords or personal data here — there's no encryption.")
    if any(by.get(k, {}).get("status") in ("bad", "warn") for k in ("trackers", "session_replay", "fingerprinting", "social")):
        add("Άνοιξέ το με Tor Browser στο επίπεδο «Safer» ή «Safest» (λιγότερη JavaScript = λιγότερο fingerprinting).",
            "Open it in Tor Browser at the \"Safer\" or \"Safest\" level (less JavaScript = less fingerprinting).")
        add("Μπλόκαρε τους τρίτους με uBlock Origin (ενσωματωμένο σε Brave/Mullvad Browser).",
            "Block third parties with uBlock Origin (built into Brave/Mullvad Browser).")
    if by.get("session_replay", {}).get("status") == "bad":
        add("Μην πληκτρολογείς σε φόρμες ό,τι δεν θέλεις να καταγραφεί — το session replay το βλέπει ακόμα κι αν δεν το στείλεις.",
            "Don't type into forms anything you don't want recorded — session replay sees it even if you never submit.")
    if by.get("tor_blocking", {}).get("status") == "warn":
        add("Αν σε μπλοκάρει: «New Tor circuit for this site» στο Tor Browser, ή δοκίμασε την έκδοση .onion/αρχειοθετημένη σελίδα.",
            "If it blocks you: \"New Tor circuit for this site\" in Tor Browser, or try the onion/archived version.")
    if by.get("js_required", {}).get("status") == "info":
        add("Χρειάζεται JavaScript: αν το εμπιστεύεσαι, χαμήλωσε το επίπεδο μόνο για αυτό το site — αλλιώς ψάξε εναλλακτική.",
            "Needs JavaScript: if you trust it, lower the level only for this site — otherwise look for an alternative.")
    add("Μη συνδεθείς σε λογαριασμό — η σύνδεση δένει την επίσκεψη με εσένα, όσο ανώνυμη κι αν είναι η σύνδεσή σου.",
        "Don't log in — logging in ties the visit to you, however anonymous your connection is.")
    if by.get("webrtc"):
        add("Σε κανονικό browser απενεργοποίησε το WebRTC (ή χρησιμοποίησε Tor/Mullvad Browser).",
            "In a normal browser disable WebRTC (or use Tor/Mullvad Browser).")
    if via == "direct":
        add("Ο έλεγχος έγινε χωρίς Tor: το site είδε την IP του NetWatch. Άνοιξε το Tor Browser για ανώνυμους ελέγχους.",
            "This check ran without Tor: the site saw NetWatch's IP. Open Tor Browser for anonymous checks.")
    if not onion and not extra.get("onion_location") and by.get("transport", {}).get("status") != "bad":
        add("Μέσω Tor ο exit node βλέπει σε ποιο site πας (όχι τι διαβάζεις, χάρη στο HTTPS).",
            "Over Tor the exit node sees which site you visit (not what you read, thanks to HTTPS).")
    return el, en


def score_result(checks):
    score = max(0, 100 - sum(c["weight"] for c in checks))
    return score, grade_for(score)


# ---------------- demo (καθόλου δίκτυο) ----------------
DDG_ONION = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"
_LOREM = ("<p>" + "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore. " * 4
          + "</p>") * 3
DEMO_SITES = {
    "news": {
        "status": 200,
        "headers": [("server", "nginx"), ("content-type", "text/html; charset=utf-8"),
                    ("strict-transport-security", "max-age=31536000"), ("referrer-policy", "strict-origin-when-cross-origin"),
                    ("set-cookie", "_ga=GA1.2.1873462910.1731990000; Max-Age=63072000; Path=/; SameSite=None; Secure"),
                    ("set-cookie", "sessid=8f2a; Path=/; HttpOnly; Secure")],
        "html": ("<html><head><title>Daily News — Breaking stories</title>"
                 "<script async src='https://www.googletagmanager.com/gtag/js?id=G-XYZ123'></script>"
                 "<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}gtag('config','G-XYZ123');</script>"
                 "<script>(function(h,o,t,j,a,r){h.hj=h.hj||function(){};h._hjSettings={hjid:1234567,hjsv:6};"
                 "r=o.createElement('script');r.src='https://static.hotjar.com/c/hotjar-'+h._hjSettings.hjid+'.js';})(window,document);</script>"
                 "<script src='https://fpcdn.io/v3/abc123/loader.js'></script>"
                 "<link rel='stylesheet' href='https://fonts.googleapis.com/css2?family=Inter'>"
                 "<link rel='preconnect' href='https://fonts.gstatic.com'>"
                 "<script src='https://cdn.jsdelivr.net/npm/swiper@11/swiper-bundle.min.js'></script>"
                 "</head><body><h1>Today's headlines</h1>" + _LOREM +
                 "<img src='https://news-static.example-cdn.com/hero.jpg'></body></html>"),
    },
    "ddg": {
        "status": 200,
        "headers": [("server", "nginx"), ("content-type", "text/html; charset=UTF-8"),
                    ("strict-transport-security", "max-age=31536000; includeSubDomains; preload"),
                    ("onion-location", DDG_ONION), ("referrer-policy", "origin"),
                    ("content-security-policy", "default-src 'none'; connect-src https://duckduckgo.com"),
                    ("permissions-policy", "interest-cohort=()")],
        "html": ("<html><head><title>DuckDuckGo — Privacy, simplified.</title>"
                 "<link rel='stylesheet' href='/dist/s.css'><script src='/dist/lib.js'></script></head>"
                 "<body><form action='/html/'><input name='q'></form><h1>Search privately</h1>" + _LOREM + "</body></html>"),
    },
    "onion": {
        "status": 200,
        "headers": [("server", "nginx"), ("content-type", "text/html; charset=utf-8"), ("referrer-policy", "no-referrer"),
                    ("content-security-policy", "default-src 'self'")],
        "html": ("<html><head><title>Hidden service</title><link rel='stylesheet' href='/style.css'></head><body>"
                 "<h1>Welcome</h1>" + _LOREM + "</body></html>"),
    },
    "shop": {
        "status": 403,
        "headers": [("server", "cloudflare"), ("cf-ray", "8e1f2a3b4c5d6e7f-FRA"), ("cf-mitigated", "challenge"),
                    ("content-type", "text/html; charset=UTF-8"), ("referrer-policy", "same-origin"),
                    ("set-cookie", "__cf_bm=kq2nX0.abc; Max-Age=1800; Path=/; HttpOnly; Secure; SameSite=None")],
        "html": ("<!DOCTYPE html><html><head><title>Just a moment...</title>"
                 "<script>window._cf_chl_opt={cvId:'3',cZone:'shop',cType:'managed'};</script>"
                 "<script src='/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=8e1f'></script>"
                 "<script src='https://challenges.cloudflare.com/turnstile/v0/api.js' async defer></script></head>"
                 "<body><noscript>Enable JavaScript and cookies to continue</noscript>"
                 "<div>Verifying you are human. This may take a few seconds.</div></body></html>"),
    },
    "generic": {
        "status": 200,
        "headers": [("server", "Apache"), ("content-type", "text/html; charset=utf-8"),
                    ("strict-transport-security", "max-age=63072000"), ("referrer-policy", "strict-origin-when-cross-origin")],
        "html": ("<html><head><title>Welcome</title>"
                 "<script async src='https://www.googletagmanager.com/gtag/js?id=G-ABC'></script>"
                 "<link rel='stylesheet' href='https://fonts.googleapis.com/css2?family=Roboto'>"
                 "<script src='https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js'></script>"
                 "<script>!function(f,b,e,v,n,t,s){n=f.fbq=function(){};t=b.createElement(e);"
                 "t.src='https://connect.facebook.net/en_US/fbevents.js'}(window,document,'script');fbq('init','1234');</script></head>"
                 "<body><h1>About us</h1>" + _LOREM + "</body></html>"),
    },
}


def demo_kind(host):
    h = host.lower()
    if h.endswith(".onion"):
        return "onion"
    if "duckduckgo" in h:
        return "ddg"
    if any(k in h for k in ("news", "times", "post", "daily", "herald", "kathimerini", "protothema", "iefimerida", "cnn", "bbc")):
        return "news"
    if any(k in h for k in ("shop", "store", "cart", "buy", "eshop", "skroutz", "amazon", "market")):
        return "shop"
    return "generic"


def demo_fetch(url, host):
    k = demo_kind(host)
    d = DEMO_SITES[k]
    u = urlsplit(url)
    final = url
    redirects = []
    if k != "onion" and u.scheme == "http":  # ο demo server ανακατευθύνει σε https
        final = urlunsplit(("https", u.netloc, u.path, u.query, ""))
        redirects = [{"url": url, "status": 301}]
    return {"final_url": final, "status": d["status"], "headers": list(d["headers"]), "body": d["html"].encode(),
            "truncated": False, "redirects": redirects, "set_cookies": [v for kk, v in d["headers"] if kk == "set-cookie"]}


# ---------------- ο runner ----------------
def _summary(r):
    keys = ("id", "url", "host", "onion", "via", "grade", "score", "fetched_at", "trackers_count", "error", "needs_tor", "demo")
    return {k: r[k] for k in keys if k in r}


class SiteCheck:
    def __init__(self, sim=False, tor_ports=TOR_PORTS, clock=time.time, fetcher=None, tor_probe=None,
                 min_interval=MIN_INTERVAL, cache_ttl=CACHE_TTL, sim_delay=1.2, background=True):
        self.sim = sim
        self.tor_ports = tuple(tor_ports)
        self.clock = clock
        self.fetcher = fetcher            # για tests: fetcher(url, via) → dict όπως το fetch()
        self.tor_probe = tor_probe or (lambda: tor_port(self.tor_ports))
        self.min_interval = min_interval
        self.cache_ttl = cache_ttl
        self.sim_delay = sim_delay
        self.background = background
        self.lock = threading.Lock()
        self.results = {}                 # id → αποτέλεσμα (μόνο τα τελευταία HISTORY + τρέχον)
        self.order = []                   # ids, νεότερο τελευταίο
        self.cache = {}                   # url → (t, id)
        self.running = None               # id
        self.last_start = 0.0
        self.seq = 0
        self._tor = (0.0, None)

    # -- Tor --
    def tor_status(self):
        if self.sim:
            return 9150
        t, p = self._tor
        if self.clock() - t > 10:
            p = self.tor_probe()
            self._tor = (self.clock(), p)
        return p

    # -- API --
    def start(self, url, direct=False, lang=None):
        lang = "en" if str(lang or "").lower().startswith("en") else "el"
        try:
            nurl, host, onion = normalize_url(url)
        except UrlError as e:
            return {"ok": False, "error": e.en if lang == "en" else e.el, "error_el": e.el, "error_en": e.en, "code": 400}
        now = self.clock()
        with self.lock:
            c = self.cache.get(nurl)
            if c and now - c[0] < self.cache_ttl and c[1] in self.results:
                r = self.results[c[1]]
                if not direct or r.get("via") == "direct" or onion:
                    return {"ok": True, "id": r["id"], "running": False, "cached": True, "result": r}
            if self.running:
                return {"ok": False, "code": 429, "retry_in": 2,
                        "error": "Another check is running — wait a moment." if lang == "en" else "Τρέχει ήδη ένας έλεγχος — περίμενε λίγο.",
                        "running_id": self.running}
            wait = self.min_interval - (now - self.last_start)
            if wait > 0:
                return {"ok": False, "code": 429, "retry_in": round(wait, 1),
                        "error": (f"Wait {wait:.0f}s between checks." if lang == "en" else f"Περίμενε {wait:.0f}″ ανάμεσα στους ελέγχους.")}
        port = self.tor_status()
        if port:
            via = f"tor:{port}"
        elif onion:
            return {"ok": False, "needs_tor": True, "onion": True, "code": 200,
                    "note_el": "Οι διευθύνσεις .onion ανοίγουν μόνο μέσω Tor. Άνοιξε το Tor Browser (θύρα 9150) ή τρέξε "
                               "`brew services start tor` (θύρα 9050) και ξαναδοκίμασε.",
                    "note_en": "Onion addresses only open over Tor. Start Tor Browser (port 9150) or run "
                               "`brew services start tor` (port 9050) and try again."}
        elif direct:
            via = "direct"
        else:
            return {"ok": False, "needs_tor": True, "onion": False, "code": 200,
                    "note_el": "Δεν βρέθηκε Tor (θύρες 9150/9050). Για να μη μάθει το site ποιος ρωτάει, άνοιξε το Tor "
                               "Browser και ξαναδοκίμασε — ή έλεγξε απευθείας (το site θα δει την IP σου).",
                    "note_en": "No Tor found (ports 9150/9050). So the site can't learn who's asking, start Tor Browser and "
                               "try again — or check directly (the site will see your IP)."}
        with self.lock:
            if self.running:
                return {"ok": False, "code": 429, "retry_in": 2, "error": "busy"}
            self.seq += 1
            rid = f"sc{int(now)}-{self.seq}"
            self.running = rid
            self.last_start = now
            self.results[rid] = {"id": rid, "url": nurl, "host": host, "onion": onion, "via": via, "running": True,
                                 "started_at": now}
        if self.background:
            threading.Thread(target=self._run, args=(rid, nurl, host, onion, via), daemon=True, name="sitecheck").start()
        else:
            self._run(rid, nurl, host, onion, via)
        return {"ok": True, "id": rid, "running": self.running == rid, "via": via}

    def _run(self, rid, url, host, onion, via):
        t0 = time.monotonic()
        r = {"id": rid, "url": url, "host": host, "onion": onion, "via": via}
        try:
            if self.fetcher:
                f = self.fetcher(url, via)
            elif self.sim:
                if self.sim_delay:
                    time.sleep(self.sim_delay)
                f = demo_fetch(url, host)
            else:
                conn = direct_connector() if via == "direct" else tor_connector(int(via.split(":")[1]))
                f = fetch(url, via, conn)
            checks, third, extra = analyze(url, f, via, now=self.clock())
            score, grade = score_result(checks)
            el, en = advice(checks, extra, onion, via)
            fh = (urlsplit(f["final_url"]).hostname or host).lower()
            r.update({"final_url": f["final_url"], "host": fh, "onion": fh.endswith(".onion"), "status": f["status"],
                      "redirects": f["redirects"], "truncated": f["truncated"], "bytes": len(f["body"]),
                      "title": extra["title"], "grade": grade, "score": score,
                      "verdict_el": VERDICT[grade][0], "verdict_en": VERDICT[grade][1], "checks": checks,
                      "third_party": third, "third_party_count": len({t["host"] for t in third}),
                      "trackers_count": extra["trackers_count"], "trackers": extra["tracker_names"],
                      "onion_location": extra["onion_location"], "challenge": extra["challenge"],
                      "partial": bool(extra["challenge"]), "advice_el": el, "advice_en": en})
        except (FetchError, UrlError) as e:
            r.update({"error": e.el, "error_el": e.el, "error_en": e.en})
        except (OSError, ssl.SSLError) as e:
            r.update({"error": f"Αποτυχία λήψης: {str(e)[:160]}", "error_el": f"Αποτυχία λήψης: {str(e)[:160]}",
                      "error_en": f"Fetch failed: {str(e)[:160]}"})
        except Exception as e:  # pragma: no cover
            r.update({"error": f"Σφάλμα ανάλυσης: {str(e)[:160]}", "error_el": f"Σφάλμα ανάλυσης: {str(e)[:160]}",
                      "error_en": f"Analysis error: {str(e)[:160]}"})
        r.update({"fetched_at": self.clock(), "ms": int((time.monotonic() - t0) * 1000), "running": False})
        if self.sim:
            r["demo"] = True
        with self.lock:
            self.results[rid] = r
            self.order.append(rid)
            if "error" not in r:
                self.cache[url] = (self.clock(), rid)
            while len(self.order) > HISTORY:
                old = self.order.pop(0)
                if old != self.running:
                    self.results.pop(old, None)
            self.cache = {u: v for u, v in self.cache.items() if v[1] in self.results}
            if self.running == rid:
                self.running = None

    def get(self, rid):
        with self.lock:
            r = self.results.get(rid)
            return dict(r) if r else None

    def view(self):
        with self.lock:
            latest = self.results.get(self.order[-1]) if self.order else None
            hist = [_summary(self.results[i]) for i in reversed(self.order) if i in self.results]
            running = self.results.get(self.running) if self.running else None
        return {"running": bool(running), "running_id": running and running["id"],
                "running_url": running and running["url"], "tor": self.tor_status(), "demo": bool(self.sim),
                "latest": latest, "history": hist}
