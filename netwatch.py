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

import winplat

if __name__ == "__main__":
    winplat.ensure_utf8_mode()  # Windows: ελληνικά αρχεία/έξοδος σε UTF-8 (ξαναξεκινά με -X utf8 αν χρειάζεται)
winplat.install_subprocess_defaults()

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
        if winplat.IS_WIN:  # εκεί το os.kill(pid, 0) στέλνει Ctrl+C αντί να ελέγχει
            if not winplat.pid_alive(pid):
                log("Η εφαρμογή έκλεισε — τέλος.")
                quit_now()
            continue
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
    if winplat.IS_WIN:
        try:
            winplat.open_url(url)
        except OSError:
            pass
        return
    cmd = ["open", url] if sys.platform == "darwin" else ["xdg-open", url]
    user = os.environ.get("SUDO_USER")
    if user and os.geteuid() == 0:
        cmd = ["sudo", "-u", user] + cmd
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def list_ifaces():
    """Οι διεπαφές όπως τις βλέπει το scapy (στα Windows: «Wi-Fi», «Ethernet»… μέσω Npcap)."""
    from scapy.all import conf
    default = detect_net()[0]
    for i in sorted(conf.ifaces.values(), key=lambda i: str(i.name)):
        ips = ", ".join((getattr(i, "ips", {}) or {}).get(4, []) or [getattr(i, "ip", "") or ""])
        mark = "  ← προεπιλογή" if i.name == default else ""
        print(f"{i.name:<28} {ips:<18} {getattr(i, 'description', '') or ''}{mark}")
    print("\nΧρήση: netwatch.py -i \"<όνομα>\"")


class _Server(ThreadingHTTPServer):
    # Στα Windows το SO_REUSEADDR επιτρέπει σε ΔΕΥΤΕΡΟ πρόγραμμα να «κλέψει» μια θύρα που ήδη ακούει —
    # τότε δεν θα βλέπαμε ποτέ «πιασμένη θύρα» και δύο NetWatch θα μοιράζονταν την 8765.
    allow_reuse_address = not winplat.IS_WIN


def main():
    # Η καταγραφή πακέτων κρατά συνέχεια το GIL· με μικρότερο διάστημα εναλλαγής τα αιτήματα του UI
    # (κουμπιά/καρτέλες) παίρνουν σειρά γρηγορότερα αντί να περιμένουν 5ms σε κάθε βήμα.
    sys.setswitchinterval(0.001)
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
    ap.add_argument("--list-ifaces", action="store_true", help="δείξε τις διεπαφές που βλέπει η καταγραφή και τέλος")
    args = ap.parse_args()
    if args.list_ifaces:
        list_ifaces()
        return

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
        if winplat.IS_WIN and not winplat.npcap_installed():
            sys.exit("✖ Για live καταγραφή στα Windows χρειάζεται το Npcap: " + winplat.NPCAP_URL +
                     "\n  (στην εγκατάσταση άφησε ενεργό το «WinPcap API-compatible Mode»)\n"
                     "  Χωρίς Npcap δουλεύουν τα --demo και --pcap αρχείο.pcap")
        iface, gw, me = detect_net(args.iface)
        if not iface:
            sys.exit("Δεν βρέθηκε interface — δώσε -i " + ('"Wi-Fi"' if winplat.IS_WIN else "en0"))
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
    state.scanner = pentest.LanScanner(sim=demo_scan if mode == "demo" else None,
                                       scan_dir=os.path.join(HERE, "data", "scans") if mode == "live" else None)
    state.scanner.on_save = chown_to_user
    import netkit

    def scan_done(hosts):
        state.scan_result(hosts)
        netkit.merge_names(state, {h["ip"]: h.get("names") or [] for h in hosts})  # ονόματα → χάρτης
    state.scanner.on_result = scan_done
    state.lab = pentest.Lab(state)
    # 🟣 purple-team καμπάνιες (ATT&CK κάλυψη) και 🔐 έλεγχος TLS/SSH (ιστορικό/αποτελέσματα στο data/ μόνο στο live)
    import purple
    import tlsaudit
    pcfg, tcfg = cfg.get("purple") or {}, cfg.get("tls_audit") or {}
    state.purple = purple.Purple(state, os.path.join(HERE, "data", "purple.json") if mode == "live" else None,
                                 pace=float(pcfg.get("pace", 1.0)))
    state.purple.on_save = chown_to_user
    state.tlsaudit = tlsaudit.TlsAudit(sim=mode == "demo", scan=state.scanner.last_result,
                                       path=os.path.join(HERE, "data", "tlsaudit.json") if mode == "live" else None,
                                       workers=int(tcfg.get("workers", 8)), timeout=float(tcfg.get("timeout", 3)))
    state.tlsaudit.on_save = chown_to_user
    # 📷 NetCam Lab: ευάλωτη εικονική κάμερα ΜΟΝΟ στο 127.0.0.1, ξεκινά μόνο με POST /api/vulnlab/start
    import atexit
    import vulnlab
    try:
        state.vulnlab = vulnlab.VulnLab(state, cfg.get("vulnlab"), sim=mode == "demo",
                                        path=os.path.join(HERE, "data", "vulnlab.json") if mode == "live" else None)
        state.vulnlab.on_save = chown_to_user
        atexit.register(state.vulnlab.stop, "shutdown")
    except (ValueError, TypeError) as e:
        log("📷 vulnlab:", e)
        state.vulnlab = None
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
    import health
    auto = [{"name": "Router", "host": state.gateway, "ping": True}] if state.gateway else []
    for key, hk, pk in (("mqtt_guard", "host", "port"), ("sensor", "mqtt_host", "mqtt_port")):
        c = cfg.get(key) or {}
        if c.get(hk):
            auto.append({"name": "MQTT broker", "host": c[hk], "port": int(c.get(pk) or (1883 if key == "mqtt_guard" else 8883)),
                         "tls": int(c.get(pk) or 0) == 8883})
    hcfg = cfg.get("health")
    if mode == "demo" and not hcfg:
        hcfg = [{"name": "Proxmox", "host": "192.168.1.16", "port": 8006, "tls": True}, {"name": "MQTT broker", "host": "192.168.1.17", "port": 1883},
                {"name": "Home Assistant", "url": "http://192.168.1.30:8123/"}, {"name": "ESP32 κήπου", "host": "192.168.1.20", "ping": True}]
        auto = []
    state.health = health.Health(state, hcfg, auto if mode == "live" else [], sim=mode == "demo") if mode != "pcap" else None
    if state.health:
        threading.Thread(target=state.health.run_forever, daemon=True).start()
    # ---- υποδομή (όπως στα επαγγελματικά NMS): NetFlow/sFlow, SNMP, syslog, IPAM, latency, ταχύτητα, Wi‑Fi, pcap ----
    DATA = os.path.join(HERE, "data")
    import devnames  # 🏷 ονόματα/τύποι συσκευών που δίνεις εσύ (data/devnames.json· στο demo μόνο μνήμη)
    state.devnames = devnames.DevNames(None if mode == "demo" else os.path.join(DATA, "devnames.json"),
                                       on_save=chown_to_user if mode != "demo" else None)
    demo, live = mode == "demo", mode == "live"
    import presence  # 📈 ιστορικό διαθεσιμότητας ανά συσκευή (κάθε 5′, data/presence.sqlite, 30 μέρες)
    state.presence = None if mode == "pcap" else presence.Presence(state, sim=demo, path=os.path.join(DATA, "presence.sqlite") if live else None,
                                                                   on_save=chown_to_user if live else None)
    if live:
        threading.Thread(target=state.presence.run_forever, daemon=True).start()
    import alerthyg  # 🔕 σίγαση ειδοποιήσεων με λήξη + 🧐 «γιατί χτύπησε;» (data/mutes.json· στο demo μόνο μνήμη)
    state.hygiene = alerthyg.AlertHygiene(state, path=os.path.join(DATA, "mutes.json") if live else None,
                                          on_save=chown_to_user if live else None)
    import assess
    state.assess = assess.Assess(state)  # 📋 αναφορά «νέο δίκτυο»
    import vulnwatch  # 🛡 ευπάθειες για τις συσκευές σου (CISA KEV + EPSS, μία φορά τη μέρα· demo: ενσωματωμένο δείγμα)
    state.vulns = vulnwatch.VulnWatch(state, DATA if live else None, demo=demo)
    if live:
        threading.Thread(target=state.vulns.run_forever, daemon=True).start()
    import upnpwatch  # 🔓 θύρες που άνοιξαν μόνες τους στο router (UPnP) — μόνο ανάγνωση, κάθε 15'
    state.upnp = upnpwatch.UpnpWatch(state, DATA if live else None, demo=demo) if mode != "pcap" else None
    if demo:
        state.upnp.refresh()
    elif live and state.upnp:
        threading.Thread(target=state.upnp.run_forever, daemon=True).start()
    import l2guard  # 🛡 rogue DHCP / ARP spoofing με ένα κουμπί (DHCPDISCOVER + ARP μόνο στο τοπικό LAN)
    state.l2guard = l2guard.L2Guard(state, sim=demo) if mode != "pcap" else None
    import updater  # 🔄 ενημερώσεις από GitHub (υπογεγραμμένες· στα apps μπαίνουν και μόνες τους)
    # Προσομοίωση μόνο στο dev demo (git checkout)· σε εγκατεστημένο app (Mac/Windows/Docker) το demo
    # κάνει κανονικό (read-only) έλεγχο στο GitHub — αλλιώς έδειχνε ψεύτικη «v1.1.0».
    state.updater = updater.Updater(state, sim=demo and updater.detect_kind(updater.HERE) == "git", cfg=cfg.get("updates"),
                                    ppid=args.parent_pid)
    if state.updater.sim:
        state.updater.check(force=True)  # dev demo: ψεύτικη νέα έκδοση, χωρίς δίκτυο
    elif live or demo:  # έλεγχος κάθε 6 ώρες· στα apps και κατέβασμα/εφαρμογή μόνο του (με υπογραφή)
        threading.Thread(target=state.updater.run_forever, daemon=True).start()

    def bg(obj):
        if obj is not None and hasattr(obj, "run_forever"):
            threading.Thread(target=obj.run_forever, daemon=True).start()
        return obj
    import flows
    import snmp
    import syslogd
    import ipam
    import latency
    import speed
    import wifisurvey
    import pcapring
    if mode != "pcap":
        state.flows = bg(flows.Flows(state, cfg.get("flows"), sim=demo))
        state.snmp = bg(snmp.Snmp(state, cfg.get("snmp"), sim=demo)) if demo or (cfg.get("snmp") or {}).get("enabled") else None
        state.syslog = bg(syslogd.Syslogd(state, cfg.get("syslog"), sim=demo)) if demo or (cfg.get("syslog") or {}).get("enabled") else None
        lcfg = cfg.get("latency") or {}
        state.latency = bg(latency.Latency(state, lcfg, sim=demo, gateway=state.gateway,
                                           db_path=None if demo else os.path.join(DATA, "latency.db"))) if lcfg.get("enabled", True) else None
        state.speed = bg(speed.Speed(cfg.get("speed"), sim=demo, path=os.path.join(DATA, "speed.json")))
        state.wifisurvey = wifisurvey.WifiSurvey(cfg.get("wifisurvey"), sim=demo)
        state.pcap_ring = pcapring.PcapRing(cfg.get("pcap_ring"), sim=demo) if demo or (cfg.get("pcap_ring") or {}).get("enabled", True) else None
    else:
        state.flows = state.snmp = state.syslog = state.latency = state.speed = state.wifisurvey = state.pcap_ring = None
    # ---- 🕵 ιδιωτικότητα & homelab (Tor, VPN/WireGuard, κρυπτογραφημένο DNS, Pi-hole/AdGuard, logs SIEM, Certificate Transparency, κάμερες) ----
    import torctl, wgstatus, vpnguard, encdns, dnsfilter, logimport, ctwatch, iotfw
    try:
        import camexposure
    except ImportError:
        camexposure = None
    if mode != "pcap":
        gw = [state.gateway] if state.gateway else []
        state.tor = bg(torctl.TorCtl(state, cfg.get("tor"), sim=demo)) if demo or (cfg.get("tor") or {}).get("enabled", True) else None
        state.wg = bg(wgstatus.WgStatus(state, cfg.get("wireguard"), sim=demo)) if demo or (cfg.get("wireguard") or {}).get("enabled", True) else None
        state.vpnguard = bg(vpnguard.VpnGuard(state, cfg.get("vpnguard"), sim=demo)) if demo or live else None
        ecfg = dict(cfg.get("encrypted_dns") or {})
        ecfg.setdefault("local_dns", gw)
        state.encdns = bg(encdns.EncDns(state, ecfg, sim=demo)) if demo or ecfg.get("enabled", True) else None
        state.dnsfilter = bg(dnsfilter.DnsFilter(state, cfg.get("dns_filter"), sim=demo)) if demo or (cfg.get("dns_filter") or {}).get("url") else None
        state.logimport = bg(logimport.LogImport(state, cfg.get("log_import"), sim=demo)) if demo or (cfg.get("log_import") or {}).get("files") else None
        state.ctwatch = bg(ctwatch.CtWatch(state, cfg.get("ct_watch"), sim=demo)) if demo or (cfg.get("ct_watch") or {}).get("domains") else None
        ccfg = cfg.get("camera_scan")
        state.camexp = (bg(camexposure.CamExposure(state, ccfg, sim=demo)) if demo or (ccfg or {}).get("enabled")
                        else camexposure.CamExposure(state, ccfg, sim=False)) if camexposure else None
        fcfg = cfg.get("iot_firewall") or {}  # 🧱 μικρο-τμηματοποίηση IoT (μαθαίνει προφίλ, βγάζει κανόνες firewall)
        state.iotfw = bg(iotfw.IotFw(state, fcfg, sim=demo, path=os.path.join(DATA, "iotfw.json") if live else None)) \
            if demo or fcfg.get("enabled", True) else None
        import timeline  # ⏱ μηχανή του χρόνου: ποιος μίλησε με ποιον, ανά λεπτό, για 24 ώρες
        state.timeline = bg(timeline.Timeline(state, sim=demo, path=os.path.join(DATA, "timeline.json.gz") if live else None))
        if live:
            atexit.register(state.timeline.save)
        import hunt  # 🎯 κυνήγι απειλών: υποθέσεις (long tail, beaconing με jitter, exfil…) + προφίλ συσκευών
        state.hunt = hunt.Hunt(state, sim=demo)
        import cases  # 🗂 διαλογή ειδοποιήσεων & υποθέσεις (TheHive-style)
        state.cases = bg(cases.Cases(state, sim=demo, path=os.path.join(DATA, "cases.json") if live else None))
        if live:
            state.cases.on_save = chown_to_user
            atexit.register(state.cases.save)
        import changecheck  # 🔁 έλεγχος πριν/μετά από αλλαγή (στιγμιότυπα δικτύου + διαφορές)
        state.changecheck = changecheck.ChangeCheck(state, sim=demo, path=os.path.join(DATA, "changecheck.json") if live else None)
        if live:
            state.changecheck.on_save = chown_to_user
        import nettriage  # 🩺 «Φταίει το δίκτυο;» — διάγνωση με ένα κλικ + κείμενο για ticket
        state.triage = nettriage.Triage(state, sim=demo)
        import configbak  # 💾 αντίγραφα ρυθμίσεων συσκευών (Oxidized/RANCID-style) μέσω ssh με κλειδιά + διαφορές
        state.configbak = configbak.ConfigBackup(state, cfg.get("config_backup"), sim=demo,
                                                 path=os.path.join(DATA, "configs") if live else None)
        if live:
            state.configbak.on_save = chown_to_user
        bg(state.configbak)
        import whereis  # 🔌 «Πού είναι συνδεδεμένο;» MAC → switch → θύρα → VLAN (από τους στόχους του snmp.targets)
        state.whereis = bg(whereis.WhereIs(state, sim=demo))
        import expiry  # ⏳ υπενθυμίσεις λήξης: πιστοποιητικά, domains, άδειες, εγγυήσεις, firmware
        state.expiry = expiry.Expiry(state, cfg.get("expiry"), sim=demo, path=os.path.join(DATA, "expiry.json") if live else None)
        for err in state.expiry.errors:
            log("⏳ expiry:", err)
        if live:
            state.expiry.on_save = chown_to_user
        bg(state.expiry)
        import segcheck  # 🧱 έλεγχος διαχωρισμού: φτάνουν οι ζώνες (VLAN) που πρέπει να είναι απομονωμένες;
        state.segcheck = segcheck.SegCheck(state, cfg.get("segmentation"), sim=demo,
                                           path=os.path.join(DATA, "segcheck.json") if live else None)
        for err in state.segcheck.errors:
            log("🧱 segmentation:", err)
        if live:
            state.segcheck.on_save = chown_to_user
        bg(state.segcheck)
        import sitecheck  # 🧅 «Πόσο ασφαλές είναι αυτό το site για την ανωνυμία μου;» (μόνο μνήμη, ποτέ δίσκος)
        state.sitecheck = sitecheck.SiteCheck(sim=demo)
        import topomap  # 🗺 διάγραμμα δικτύου με ένα κουμπί + «πού είναι η βλάβη» (ping/traceroute, μόνο μνήμη)
        state.topomap = topomap.TopoMap(state, sim=demo)
        import sshbrowse  # 🖥 SSH Explorer: αρχεία & κατάσταση Raspberry Pi/server (μόνο κλειδιά, μόνο ανάγνωση)
        state.ssh = sshbrowse.SshBrowse(state, sim=demo, path=os.path.join(DATA, "ssh_hosts.json") if live else None,
                                        known=os.path.join(DATA, "ssh_known_hosts") if live else None)
        if live:
            state.ssh.on_save = chown_to_user
        import handover  # 🔄 παράδοση βάρδιας (SOC/NOC): σύνοψη N ωρών + σημειώσεις βάρδιας
        state.handover = handover.Handover(state, sim=demo, path=os.path.join(DATA, "handover.json") if live else None)
        if live:
            state.handover.on_save = chown_to_user
    else:
        state.tor = state.wg = state.vpnguard = state.encdns = state.dnsfilter = state.logimport = state.ctwatch = state.camexp = None
        state.iotfw = None
        state.timeline = None
        state.hunt = None
        state.cases = None
        state.changecheck = state.triage = None
        state.configbak = None
        state.whereis = state.expiry = None
        state.segcheck = None
        state.handover = None
        state.sitecheck = None
        state.topomap = None
        state.ssh = None
    icfg = cfg.get("ipam")
    if demo and not icfg:
        icfg = {"subnets": [{"cidr": "192.168.1.0/24", "name": "Σπίτι (LAN)", "vlan": 1, "gateway": "192.168.1.1", "dhcp": "192.168.1.100-192.168.1.199"}],
                "reserved": [{"ip": "192.168.1.16", "name": "Proxmox"}, {"ip": "192.168.1.17", "name": "MQTT broker"},
                             {"ip": "192.168.1.20", "name": "ESP32 κήπου"}, {"ip": "192.168.1.30", "name": "Home Assistant"},
                             {"ip": "192.168.1.150", "name": "Εκτυπωτής"}]}
    state.ipam = ipam.Ipam(icfg, os.path.join(DATA, "ipam.json") if live else os.path.join(DATA, "ipam-demo.json"))
    import ops
    mw = cfg.get("maintenance")
    if mode == "demo" and not mw:
        mw = [{"name": "Νυχτερινό backup NAS", "start": "02:00", "end": "04:00"}]
    state.maint = ops.Maintenance(mw, os.path.join(HERE, "data", "maint.json") if mode == "live" else None)
    for err in state.maint.errors:
        log("🔧 maintenance:", err)
    import playbooks
    pb_cfg = cfg.get("playbooks")
    if mode == "demo" and not pb_cfg:  # παράδειγμα για να φαίνεται η καρτέλα (το μπλοκ στο demo είναι εικονικό)
        pb_cfg = [{"name": "Παγίδα/καναρίνι → μπλόκαρε 30′", "when": {"type": ["Παγίδα", "Καναρίνι ESP32"]}, "do": ["block"], "block_minutes": 30},
                  {"name": "Σοβαρή επίθεση από το LAN → κινητό", "when": {"sev": "high", "local": True}, "do": ["notify"], "dry_run": True}]
    state.playbooks = playbooks.Playbooks(state, pb_cfg) if mode != "pcap" else None
    if state.playbooks:
        threading.Thread(target=state.playbooks.run_forever, daemon=True).start()
        for err in state.playbooks.errors:
            log("⚡ playbook:", err)
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
        state.notifier = Notifier({**cfg["notify"], "lang": cfg.get("lang", "el")})
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
            srv = _Server((bind, port), make_handler(state))
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
    # Windows (ασπίδα) και Mac app (γραμμή μενού): διαβάζουν από τον ίδιο φάκελο αιτήματα αλλαγής Live/Demo από τον πίνακα
    state.app_ctl = os.path.dirname(os.path.abspath(args.port_file)) if args.port_file and sys.platform in ("win32", "darwin") else None
    if state.app_ctl and sys.platform == "win32":  # ⬇ Npcap με ένα κλικ από το npcap.com (με έλεγχο υπογραφής)
        import npcapget
        state.npcap = npcapget.NpcapGet(os.path.join(state.app_ctl, "npcap"))
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
