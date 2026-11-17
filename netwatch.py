#!/usr/bin/env python3
"""NetWatch — ζωντανή οπτικοποίηση κίνησης δικτύου & ανίχνευση επιθέσεων.

Live:  sudo .venv/bin/python netwatch.py            (χρειάζεται root για capture)
Demo:  .venv/bin/python netwatch.py --demo           (προσομοίωση, χωρίς root)
Μετά άνοιξε  http://127.0.0.1:8765
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer

# Συμβατότητα: όλα τα ονόματα των modules είναι διαθέσιμα και ως netwatch.<όνομα> (π.χ. για τα tests/CI).
from core import *  # noqa: F401,F403
from storage import *  # noqa: F401,F403
from detect import *  # noqa: F401,F403
from osint import *  # noqa: F401,F403
from capture import *  # noqa: F401,F403
from demo import *  # noqa: F401,F403
from server import *  # noqa: F401,F403
from core import HERE, RULES_DIR, chown_to_user, detect_net, load_config, log, quit_now
from storage import History, Intel, Notifier
from detect import NetState
from osint import fetch_home, geo_worker
from capture import live_capture, pcap_guess, pcap_replay, seed_arp
from demo import demo_run, demo_scan
from server import make_handler


def vpn_watch(state, interval=10):
    """Live: ποια διεπαφή έχει την προεπιλεγμένη διαδρομή — αν είναι VPN, ψάχνουμε διαρροές εκτός τούνελ."""
    import privacy
    import wifiguard
    while True:
        try:
            di = wifiguard.default_iface()
            new = di if privacy.vpn_full_tunnel(di) else None
            if new != state.vpn_iface:
                log(f"🔒 VPN ενεργό ({new}) — παρακολουθώ για διαρροές" if new else "🔓 VPN ανενεργό")
                state.vpn_iface = new
                state.leak_dns.clear()
        except Exception:
            pass
        time.sleep(interval)


def watch_parent(pid):
    """Η εφαρμογή του Mac ξεκινά το NetWatch (και με sudo): όταν εκείνη κλείσει, κλείνουμε κι εμείς."""
    while True:
        time.sleep(1)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            log("Η εφαρμογή έκλεισε — τέλος.")
            quit_now()
        except PermissionError:
            pass


def open_browser(url):
    """Ανοίγει τον browser ως ο κανονικός χρήστης, ακόμα κι αν τρέχουμε με sudo."""
    time.sleep(1.5)
    cmd = ["open", url] if sys.platform == "darwin" else ["xdg-open", url]
    user = os.environ.get("SUDO_USER")
    if user and os.geteuid() == 0:
        cmd = ["sudo", "-u", user] + cmd
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="NetWatch — live network map & attack detector")
    ap.add_argument("--demo", action="store_true", help="προσομοίωση κίνησης & επιθέσεων (χωρίς root)")
    ap.add_argument("-i", "--iface", help="interface (π.χ. en0)")
    ap.add_argument("-f", "--filter", default="", help="BPF φίλτρο (π.χ. 'not port 22')")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-open", action="store_true", help="να μην ανοίξει αυτόματα ο browser")
    ap.add_argument("--no-geo", action="store_true", help="χωρίς γεωεντοπισμό μέσω ip-api.com")
    ap.add_argument("--no-rdns", action="store_true", help="χωρίς reverse DNS")
    ap.add_argument("--pcap", help="αναπαραγωγή αρχείου .pcap/.pcapng αντί για live (χωρίς root)")
    ap.add_argument("--speed", type=float, default=1.0, help="ταχύτητα pcap (1 = πραγματική, 0 = μέγιστη)")
    ap.add_argument("--loop", action="store_true", help="επανάληψη του pcap")
    ap.add_argument("--me", help="η IP του «δικού μας» υπολογιστή στο pcap (αλλιώς μαντεύει)")
    ap.add_argument("--gw", help="η IP του router στο pcap (αλλιώς μαντεύει)")
    ap.add_argument("--config", help="αρχείο ρυθμίσεων YAML (προεπιλογή: config.yaml δίπλα στο netwatch.py)")
    ap.add_argument("--history", help="αρχείο SQLite ιστορικού (live: data/netwatch.db, αλλιώς στη μνήμη)")
    ap.add_argument("--notify", action="store_true", help="ειδοποιήσεις macOS/Telegram και σε demo/pcap")
    ap.add_argument("--port-file", help=argparse.SUPPRESS)  # η εφαρμογή Mac διαβάζει από εδώ τη θύρα
    ap.add_argument("--parent-pid", type=int, help=argparse.SUPPRESS)  # τερματισμός όταν κλείσει η εφαρμογή
    ap.add_argument("--agent", action="store_true",
                    help="λειτουργία agent: ακούει στο LAN με HTTPS + token (για server στο Proxmox / Raspberry Pi)")
    ap.add_argument("--bind", help="διεύθυνση ακρόασης (προεπιλογή 127.0.0.1· με --agent: 0.0.0.0)")
    ap.add_argument("--no-intel", action="store_true", help="χωρίς κατέβασμα blocklists (threat intel)")
    args = ap.parse_args()

    cfg_path = args.config or (os.path.join(HERE, "config.yaml") if os.path.exists(os.path.join(HERE, "config.yaml")) else None)
    cfg = load_config(cfg_path)
    cfg["_path"] = cfg_path
    if cfg_path:
        log(f"Ρυθμίσεις: {cfg_path}")
    mode = "pcap" if args.pcap else "demo" if args.demo else "live"
    hist_path = args.history or (os.path.join(HERE, cfg["history"]["path"]) if mode == "live" else ":memory:")
    history = History(hist_path)
    intel = Intel(cfg["intel"], os.path.join(HERE, "data", "intel"))
    common = dict(cfg=cfg, history=history, intel=intel)

    if args.pcap:
        if not os.path.exists(args.pcap):
            sys.exit(f"Δεν βρέθηκε το αρχείο {args.pcap}")
        g_me, g_gw = pcap_guess(args.pcap)
        me, gw = args.me or g_me, args.gw or g_gw
        state = NetState("pcap", os.path.basename(args.pcap), [me] if me else [], gw,
                         geo=not args.no_geo, rdns=not args.no_rdns, **common)
        log(f"PCAP {args.pcap} | «εγώ» = {me} | router = {gw} | ταχύτητα {args.speed or 'max'}")
        if state.geo_enabled:
            threading.Thread(target=geo_worker, args=(state,), daemon=True).start()
            threading.Thread(target=fetch_home, args=(state,), daemon=True).start()
        start_replay = lambda: pcap_replay(state, args.pcap, args.speed, args.loop)  # noqa: E731
    elif args.demo:
        state = NetState("demo", "demo0", ["192.168.1.23"], "192.168.1.1", geo=False, rdns=False, **common)
        demo_run(state)
    else:
        iface, gw, me = detect_net(args.iface)
        if not iface:
            sys.exit("Δεν βρέθηκε interface — δώσε -i en0")
        state = NetState("live", iface, me, gw, geo=not args.no_geo, rdns=not args.no_rdns, **common)
        log(f"Interface {iface} | οι IP μου {', '.join(sorted(me))} | router {gw} | ιστορικό {hist_path}")
        seed_arp(state)
        if state.geo_enabled:
            threading.Thread(target=geo_worker, args=(state,), daemon=True).start()
            threading.Thread(target=fetch_home, args=(state,), daemon=True).start()
        threading.Thread(target=live_capture, args=(state, iface, args.filter), daemon=True).start()

    state.reload_rules()
    log(f"Κανόνες: {len(state.rules.rules)} από {RULES_DIR}")
    import pentest
    state.scanner = pentest.LanScanner(sim=demo_scan if mode == "demo" else None)
    state.scanner.on_result = state.scan_result
    state.lab = pentest.Lab(state)
    import wifiguard
    state.wifi = wifiguard.Guard(state, sim=wifiguard.demo_check if mode == "demo" else None,
                                 trusted_path=os.path.join(HERE, "data", "wifi_trusted.json") if mode == "live" else None)
    state.wifi.on_save = chown_to_user
    import privacy
    state.privacy = privacy.Runner(sim=privacy.demo_check if mode == "demo" else None,
                                   vpn=lambda: privacy.vpn_full_tunnel(wifiguard.default_iface()))
    import honeypot

    def honey_hit(h):
        me = sorted(state.me)[0] if state.me else "εσύ"
        what = f"θύρα {h['port']} ({h['service']})" + (f" — έστειλε: «{h['data'][:80]}»" if h["data"] else "")
        state.alert(f"Παγίδα: σύνδεση σε ψεύτικο {h['service']}", "high", h["ip"], me, what, h["t"],
                    key=f"{h['ip']}:{h['port']}", cooldown=30,
                    benign="Ήταν δοκιμή από τον ίδιο σου τον υπολογιστή." if h["self"] else None)
    state.honeypot = honeypot.Honeypot(honey_hit, sim=mode == "demo") if mode != "pcap" else None
    if state.honeypot and cfg["detectors"].get("honeypot", False):  # ΚΛΕΙΣΤΟ αν δεν το ζητήσεις
        state.honeypot.start(cfg.get("honeypot_ports"))
    import atexit
    import blocker
    state.blocker = blocker.Blocker(protect=lambda: list(state.me) + [state.gateway], sim=mode == "demo") if mode != "pcap" else None
    if state.blocker and not state.blocker.sim:
        atexit.register(state.blocker.clear)  # κλείνεις το NetWatch → φεύγουν και οι κανόνες
    import sensor
    state.sensor = sensor.Bridge(state, cfg.get("sensor"), sim=mode == "demo") if mode != "pcap" else None
    if state.sensor:
        state.sensor.start()
    import mqttwatch
    state.mqtt = mqttwatch.Guard(state, cfg.get("mqtt_guard"), sim=mode == "demo",
                                 path=os.path.join(HERE, "data", "mqttguard.json") if mode == "live" else None) if mode != "pcap" else None
    if state.mqtt:
        state.mqtt.start()
    import baseline
    state.baseline = baseline.Baseline(state, os.path.join(HERE, "data", "baseline.json") if mode == "live" else None,
                                       learn=baseline.LEARN if mode == "live" else 60) if mode != "pcap" else None
    if state.baseline:
        threading.Thread(target=state.baseline.run, daemon=True).start()
    import hass
    state.hass = hass.HomeAssistant(state, cfg.get("homeassistant"), sim=False) if mode != "pcap" else None
    if state.hass:
        state.hass.start()
    import iotcheck

    def lan_devices():
        with state.lock:
            return [{"ip": ip, "mac": h.get("mac"), "names": sorted(h.get("names") or ()) + ([h["rdns"]] if h.get("rdns") else [])}
                    for ip, h in state.hosts.items() if h.get("kind") == "local" and not h.get("me") and ":" not in ip]
    state.iot = iotcheck.IotCheck(lan_devices, sim=mode == "demo", my_ips=lambda: set(state.me),
                                  broker=lambda: ((state.mqtt.cfg.get("host"), state.mqtt.broker.get("version")) if state.mqtt else (None, None))) if mode != "pcap" else None
    import apps
    state.apps = apps.Watcher(state.names_for, demo=mode == "demo") if mode != "pcap" else None
    if mode == "live" and cfg["detectors"].get("privacy_leaks", True):
        threading.Thread(target=vpn_watch, args=(state,), daemon=True).start()
    if cfg["detectors"].get("wifi_guard", True):
        if mode == "live":
            threading.Thread(target=state.wifi.watch, daemon=True).start()
        elif mode == "demo":
            tm = threading.Timer(8, state.wifi.start, args=("startup",))
            tm.daemon = True
            tm.start()
    if mode == "live" or args.notify:
        state.notifier = Notifier(cfg["notify"])
    if cfg["intel"].get("enabled", True) and cfg["detectors"].get("threat_intel", True) \
            and not args.no_intel and mode != "demo":
        intel_thread = threading.Thread(target=intel.load, args=(state.recheck_intel,), daemon=True)
        intel_thread.start()
        if mode == "pcap":  # στο pcap φόρτωσε πρώτα τις λίστες ώστε να «πιάσει» και τα πρώτα πακέτα
            intel_thread.join(timeout=30)
    if mode == "pcap":
        threading.Thread(target=start_replay, daemon=True).start()

    threading.Thread(target=state.flusher, daemon=True).start()
    state.origin = {"mode": mode, "iface": state.iface, "me": sorted(state.me), "gw": state.gateway,
                    "history": history, "notifier": state.notifier,
                    "start": start_replay if mode == "pcap" else None,
                    "seed": getattr(state, "demo_seed", None) if mode == "demo" else
                    (lambda: seed_arp(state)) if mode == "live" else None}
    srv = None
    acfg = cfg.get("agent") or {}
    bind = args.bind or acfg.get("bind") or ("0.0.0.0" if args.agent else "127.0.0.1")
    state.agent = None
    if args.agent or bind not in ("127.0.0.1", "localhost", "::1"):
        import agent
        ddir = os.path.join(HERE, "data")
        crt, key, fp = agent.ensure_cert(ddir)
        state.agent = {"token": agent.load_token(ddir, acfg.get("token")), "fingerprint": fp}
    for port in range(args.port, args.port + 20):
        try:
            srv = ThreadingHTTPServer((bind, port), make_handler(state))
            break
        except OSError:
            log(f"Η θύρα {port} είναι πιασμένη (τρέχει ήδη άλλο NetWatch;) — δοκιμάζω την {port + 1}")
    if srv is None:
        log(f"✖ Καμία ελεύθερη θύρα από {args.port} έως {args.port + 19}. Δώσε --port.")
        os._exit(1)
    srv.daemon_threads = True
    url = f"http://127.0.0.1:{port}"
    if state.agent:
        import socket as _s
        srv.socket = agent.tls_context(crt, key).wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
        try:
            lan = detect_net()[2]
            host_ip = next((ip for ip in sorted(lan) if "." in ip and not ip.startswith("127.")), None) or _s.gethostname()
        except Exception:
            host_ip = _s.gethostname()
        url = f"https://{host_ip}:{port}"
        log(f"🛰  Λειτουργία agent: άνοιξε {url}/?token={state.agent['token']}")
        log(f"   Πιστοποιητικό SHA-256 (σύγκρινέ το στον browser): {state.agent['fingerprint']}")
        args.no_open = True
    if args.port_file:
        with open(args.port_file, "w") as f:
            f.write(str(port))
        chown_to_user(args.port_file)
    import signal
    signal.signal(signal.SIGTERM, lambda *_: quit_now())
    if args.parent_pid:
        threading.Thread(target=watch_parent, args=(args.parent_pid,), daemon=True).start()
    log(f"NetWatch ({state.mode}) → {url}")
    if not args.no_open:
        threading.Thread(target=open_browser, args=(url,), daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("Τέλος.")


if __name__ == "__main__":
    main()
