// NetWatch Academy (English) — 🔌 IoT Security: ESP32 & Raspberry Pi — module 4
// Defensive use only, and only on YOUR OWN devices. Format: academy/FORMAT.md
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

  const M = [];

  M.push({
    id: 'iot-4', order: 4, title: 'Secure communication: MQTT and TLS',
    desc: 'Mosquitto on the Pi with users, ACLs and TLS on 8883 with your own CA. Clients in Arduino, MicroPython and Python. HTTPS and certificate pinning.',
    lessons: [
      {
        id: 'iot-4-1', title: 'MQTT from scratch: broker, topics, pub/sub', minutes: 15,
        goal: 'Understand how **MQTT** works (broker, topics, wildcards, QoS, retained), set up **Mosquitto** on the Pi and send your first messages, local only for now.',
        blocks: [
          text(
            '**MQTT** is the most widely used IoT protocol: lightweight, simple, and ideal for devices with little memory such as the ESP32.',
            '',
            '- **Broker**: the "mail carrier". Everyone connects to it (here: Mosquitto on the Raspberry Pi).',
            '- **Publish**: "send this message to the topic `home/esp1/temp`".',
            '- **Subscribe**: "I want everything that arrives on `home/+/temp`".',
            '- **Topic**: a hierarchical name with `/`. Wildcards: `+` = one level, `#` = everything below (only at the end).',
            '- **QoS**: 0 = once, "best effort", 1 = at least once (with ACK), 2 = exactly once.',
            '- **Retained**: the broker keeps the last message of the topic and hands it immediately to anyone who subscribes later.',
            '- **Last Will (LWT)**: a message the broker publishes if a client disappears abruptly.'
          ),
          anim('iot-mqtt-pubsub', 'Devices don\'t know each other; they only know the broker and the topics.'),
          code('bash', 'Install Mosquitto on the Raspberry Pi', R`
sudo apt update
sudo apt install -y mosquitto mosquitto-clients
mosquitto -h | head -1                 # version (Bookworm: 2.0.x)
sudo systemctl enable --now mosquitto
sudo ss -tlnp | grep mosquitto         # which address is it listening on?
`, L(
            '- `mosquitto`: the broker. `mosquitto-clients`: the `mosquitto_pub` and `mosquitto_sub` tools.',
            '- In **Mosquitto 2.x**, if you define **no** `listener`, it listens **only** on `127.0.0.1:1883` and allows anonymous only there. You will see `127.0.0.1:1883` in `ss`.',
            '- This is a safe default: nobody on the network can connect yet.'
          )),
          code('bash', 'First test (two terminals on the Pi)', R`
# Terminal 1: listen to ALL topics under home/
mosquitto_sub -h localhost -t 'home/#' -v

# Terminal 2: send a reading
mosquitto_pub -h localhost -t 'home/esp1/temp' -m '22.5'

# Retained: the broker will remember it
mosquitto_pub -h localhost -t 'home/esp1/status' -m 'online' -r
`, L(
            '- `-t \'home/#\'`: subscribe to all topics under `home/`. The single quotes stop the shell from "touching" the `#`.',
            '- `-v` (verbose): prints the topic too, not just the message.',
            '- `-r`: retained. Stop and restart `mosquitto_sub`: `online` appears immediately.'
          )),
          text('### Python subscriber on the Pi (paho-mqtt 2.x)'),
          code('bash', 'Virtual environment for the Python tools in this track', R`
sudo apt install -y python3-venv
python3 -m venv ~/iot-venv
~/iot-venv/bin/pip install --upgrade pip
~/iot-venv/bin/pip install "paho-mqtt>=2.0"
`, L(
            '- On Bookworm, `pip install` outside a venv is blocked (PEP 668), so it can\'t break the system packages.',
            '- The apt package `python3-paho-mqtt` is 1.6.x; we want the **2.x** API.'
          )),
          code('python', 'sub_basic.py', R`
import paho.mqtt.client as mqtt

def on_connect(client, userdata, flags, reason_code, properties):
    print("Connected:", reason_code)
    client.subscribe("home/#", qos=1)          # subscribe INSIDE on_connect

def on_message(client, userdata, msg):
    print(f"{msg.topic} → {msg.payload.decode(errors='replace')} (retained={msg.retain})")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="pi-logger")
client.on_connect = on_connect
client.on_message = on_message
client.connect("localhost", 1883, keepalive=60)
client.loop_forever()
`, L(
            '- `CallbackAPIVersion.VERSION2`: mandatory in paho 2.x. It defines the shape of the callbacks (with `reason_code` and `properties`).',
            '- `subscribe` goes inside `on_connect`, so it happens again automatically after a disconnect/reconnect.',
            '- `decode(errors=\'replace\')`: if invalid bytes arrive (e.g. from an attacker), the script doesn\'t crash.',
            '- `loop_forever()`: handles the network, keepalive and reconnects.',
            '- Run it with `~/iot-venv/bin/python sub_basic.py`.'
          )),
          tip('Design your topics with the **device in the name**: `home/<device>/state`, `home/<device>/cmd`. That way you can write simple ACLs like "sensor01 writes only under `home/sensor01/`".'),
          quiz('Which topic matches the subscription `home/+/temp`?',
            ['`home/temp`', '`home/esp1/temp`', '`home/esp1/room/temp`', '`office/esp1/temp`'], 1,
            '`+` matches **exactly one** level. For several levels you need `#`.'),
          quiz('Mosquitto 2.x was just installed with no config of your own. Can an ESP32 on the LAN connect?',
            ['Yes, without a password', 'No, the broker listens only on localhost until you define a listener', 'Yes, but only with TLS', 'Only with QoS 2'], 1,
            'Since 2.0 Mosquitto is "secure by default": without an explicit `listener` it listens only locally.'),
        ],
      },
      {
        id: 'iot-4-2', title: 'Users and ACLs: who writes where', minutes: 16,
        goal: 'See with your own eyes why plaintext MQTT is dangerous, and configure **allow_anonymous false**, a **password_file** and a per-device **ACL** in Mosquitto.',
        blocks: [
          anim('iot-mqtt-sniff', 'Without TLS the MQTT password travels "in the open". With TLS the attacker sees only noise.'),
          text(
            'Try it on **your own** network: if you have even a temporary listener on 1883 on the LAN, run this on the Pi:'
          ),
          code('bash', 'What shows up on the wire (only on YOUR OWN network)', R`
sudo apt install -y tcpdump
# -A: print the payload as ASCII. You will see user/pass and readings!
sudo tcpdump -i any -n -A 'tcp port 1883'

# Compare later with TLS: only unintelligible bytes
sudo tcpdump -i any -n -X 'tcp port 8883' | head -40
`, L(
            '- `-i any`: all interfaces. `-n`: no DNS lookups.',
            '- In the MQTT **CONNECT** packet you will see the client id, the username and the password as plain text.',
            '- `-X`: hex + ASCII. On 8883 you will see TLS records (`17 03 03 …`) that make no sense.'
          )),
          text(
            '### Step 1: users and passwords',
            'Every device and every application gets **its own** user. `mosquitto_passwd` stores passwords as a **hash** (PBKDF2-SHA512 in 2.x), not as plain text.'
          ),
          code('bash', 'Create the password file', R`
# -c CREATES a new file (deletes the old one!). Only the first time.
sudo mosquitto_passwd -c /etc/mosquitto/passwd sensor01

# The next users WITHOUT -c
sudo mosquitto_passwd /etc/mosquitto/passwd sensor02
sudo mosquitto_passwd /etc/mosquitto/passwd dashboard

# Delete a user (e.g. a device was stolen)
sudo mosquitto_passwd -D /etc/mosquitto/passwd sensor02

# Only the mosquitto user reads the file
sudo chown mosquitto:mosquitto /etc/mosquitto/passwd
sudo chmod 600 /etc/mosquitto/passwd
sudo cat /etc/mosquitto/passwd     # you will see sensor01:$7$101$....
`, L(
            '- `-c`: create. If you run it again with `-c`, all the other users are **lost**.',
            '- The password is asked interactively, so it doesn\'t stay in the shell `history`. (`-b user pass` leaves it in the history: avoid it.)',
            '- `-D`: delete a user. Afterwards: `sudo systemctl reload mosquitto`.',
            '- `$7$`: the PBKDF2-SHA512 hash format of Mosquitto 2.x.',
            '- Newer 2.0.x versions warn if the file is readable by everyone.'
          )),
          text(
            '### Step 2: ACL (Access Control List)',
            'The password says **who** you are. The ACL says **what** you are allowed to do. Without an ACL, `sensor01` could send `ON` to the neighbouring sensor\'s relay or read all the data.'
          ),
          code('text', '/etc/mosquitto/acl', R`
# "topic" lines BEFORE any "user" apply to anonymous (we have no anonymous)

# --- Dashboard: read-only access to everything ---
user dashboard
topic read home/#

# --- Monitor: reads everything, writes only alerts ---
user monitor
topic read home/#
topic write alerts/#

# --- Sensor 1 ---
user sensor01
topic write home/sensor01/state
topic write home/sensor01/status
topic write home/sensor01/heartbeat
topic read  home/sensor01/cmd

# --- Alternatively, ONE rule for all sensors ---
# %u is replaced by the client's username.
# pattern write home/%u/state
# pattern write home/%u/status
# pattern write home/%u/heartbeat
# pattern read  home/%u/cmd
`, L(
            '- `user X`: all the `topic` lines below apply to user X, until the next `user`.',
            '- `topic read|write|readwrite <topic>`: what is allowed. Anything **not** listed is denied.',
            '- `sensor01` can write only its own topics and read only its own commands.',
            '- `pattern … %u`: applies to **all** users, with `%u` = username (`%c` = client id). Handy for many devices.',
            '- When a publish is rejected because of the ACL, the broker simply drops it (in MQTT v3.1.1 the client learns nothing).'
          )),
          code('text', '/etc/mosquitto/conf.d/10-auth.conf (temporary, no TLS yet)', R`
# These settings apply to all listeners
per_listener_settings false

allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl

# Local listener for tools on the Pi itself
listener 1883 127.0.0.1
`, L(
            '- On Debian the main `/etc/mosquitto/mosquitto.conf` already has `include_dir /etc/mosquitto/conf.d`, so it is enough to put your own file here.',
            '- `allow_anonymous false`: in 2.x it is already the default once you define a listener, but we write it explicitly for clarity.',
            '- `listener 1883 127.0.0.1`: even with a password, we do **not** open plaintext MQTT on the network. In the next lesson we add a TLS listener on 8883.'
          )),
          code('bash', 'Apply and test', R`
sudo chown mosquitto:mosquitto /etc/mosquitto/acl && sudo chmod 600 /etc/mosquitto/acl
sudo systemctl restart mosquitto
sudo journalctl -u mosquitto -n 20 --no-pager      # config errors show up here

# Without a password → rejected
mosquitto_pub -h localhost -t home/sensor01/state -m test
# Error: Connection refused: not authorised.

# With a password, on an allowed topic → OK
mosquitto_pub -h localhost -u sensor01 -P 'your-password' -t home/sensor01/state -m '{"t":22.5}'

# On ANOTHER topic → the broker silently drops it. Check the log:
mosquitto_pub -h localhost -u sensor01 -P 'your-password' -t home/sensor02/cmd -m ON
sudo journalctl -u mosquitto -n 5 --no-pager
`, L(
            '- `journalctl -u mosquitto`: if Mosquitto doesn\'t start, here you see which config line is to blame.',
            '- `not authorised`: `allow_anonymous false` works.',
            '- The last command "succeeds" from the client\'s point of view, but the message is delivered to nobody. Confirm it with a `mosquitto_sub -u dashboard … -t \'home/#\'` in another terminal.',
            '- The password in `-P` shows up in `ps` and in the history. For tests that is OK; for scripts use a config file with 600 permissions.'
          )),
          tip('Watch live who connects and who is rejected: `sudo tail -f /var/log/mosquitto/mosquitto.log`. `not authorised` lines from an unknown IP mean someone is trying passwords.'),
          cli('Lab: users in Mosquitto', 'maria@raspberrypi:~ $', 'Mosquitto 2.0 (simulation).', [
            { task: 'Create a new password file `/etc/mosquitto/passwd` with `sensor01` as the first user.', expect: '^sudo\\s+mosquitto_passwd\\s+-c\\s+/etc/mosquitto/passwd\\s+sensor01$', ans: 'sudo mosquitto_passwd -c /etc/mosquitto/passwd sensor01', out: 'Password: \nReenter password: ' },
            { task: 'Add the user `dashboard` (careful: **without** -c!).', expect: '^sudo\\s+mosquitto_passwd\\s+/etc/mosquitto/passwd\\s+dashboard$', ans: 'sudo mosquitto_passwd /etc/mosquitto/passwd dashboard', out: 'Password: \nReenter password: ', err: 'Remember: without -c, otherwise you delete sensor01.' },
            { task: 'Give ownership of the file to the user/group `mosquitto`.', expect: '^sudo\\s+chown\\s+mosquitto(:mosquitto|:)?\\s+/etc/mosquitto/passwd$', ans: 'sudo chown mosquitto:mosquitto /etc/mosquitto/passwd', out: '' },
            { task: 'Set permissions 600 on the file.', expect: '^sudo\\s+chmod\\s+(0)?600\\s+/etc/mosquitto/passwd$', ans: 'sudo chmod 600 /etc/mosquitto/passwd', out: '' },
            { task: 'Restart the broker.', expect: '^sudo\\s+systemctl\\s+restart\\s+mosquitto(\\.service)?$', ans: 'sudo systemctl restart mosquitto', out: '' },
            { task: 'Try a publish **without** a user to `home/test` (it should fail).', expect: '^mosquitto_pub\\s+.*-t\\s+\\S+.*-m\\s+\\S+', ans: 'mosquitto_pub -h localhost -t home/test -m hi', out: 'Connection error: Connection Refused: not authorised.\nError: The connection was refused.' },
          ], 'Now nobody gets in without a password and every user has their own permissions.'),
          quiz('`sensor01` has the ACL `topic write home/sensor01/state`. What happens if it publishes to `home/relay/set`?',
            ['The broker delivers it normally', 'The broker silently rejects it (delivers it to nobody)', 'The broker closes all connections', 'The IP gets banned'], 1,
            'Anything not explicitly allowed in the ACL is denied. In MQTT 3.1.1 the client is not informed; the broker simply doesn\'t forward it.'),
          quiz('What happens if you run `mosquitto_passwd -c /etc/mosquitto/passwd sensor03` again?',
            ['sensor03 is added', 'The file is recreated with only sensor03: all the others are lost', 'Nothing', 'Everyone\'s password changes'], 1,
            '`-c` means create/overwrite. To add a user: no `-c`.'),
        ],
      },
      {
        id: 'iot-4-3', title: 'Your own CA and TLS on 8883', minutes: 20,
        goal: 'Create your own Certificate Authority with **openssl**, sign a certificate for the broker with a correct **SAN**, and enable TLS in Mosquitto (port 8883).',
        blocks: [
          text(
            '**TLS** does three things:',
            '1. **Encryption**: nobody reads the data.',
            '1. **Integrity**: nobody changes it on the way.',
            '1. **Server authentication**: the client is sure it is talking to **your own** broker.',
            '',
            'For (3) the client must trust someone who signed the server\'s certificate. For home devices, the simplest and strongest solution is **your own CA**: the ESP32s trust **only** it, and therefore only the broker you signed.'
          ),
          anim('iot-tls-handshake', 'The ESP32 checks the certificate signature with `ca.crt` and the name in the SAN.'),
          code('bash', 'Step 1: the CA (on your computer or on the Pi, somewhere safe)', R`
mkdir -p ~/iot-ca && cd ~/iot-ca
chmod 700 ~/iot-ca

# The CA's private key: THE MOST VALUABLE FILE. Password-protected (AES-256).
openssl genrsa -aes256 -out ca.key 4096

# Self-signed CA certificate, 10 years
openssl req -x509 -new -key ca.key -sha256 -days 3650 \
  -subj "/CN=Home IoT Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.crt

openssl x509 -in ca.crt -noout -subject -dates
`, L(
            '- `genrsa -aes256 … 4096`: a 4096-bit RSA key, encrypted with a password. Without the password, the file is useless to whoever steals it.',
            '- `req -x509 -new`: directly creates a **self-signed** certificate (the CA signs itself).',
            '- `basicConstraints=CA:TRUE`: declares that this certificate **may** sign others.',
            '- `keyUsage=keyCertSign,cRLSign`: only for signing certificates/CRLs.',
            '- `ca.crt` is **public**: it goes into every ESP32. `ca.key` never leaves here (ideally offline, on a USB stick).'
          )),
          code('bash', 'Step 2: certificate for the broker with SAN', R`
cd ~/iot-ca

# The server's key (no password, because Mosquitto must start on its own)
openssl genrsa -out server.key 2048

# Certificate signing request (CSR)
openssl req -new -key server.key -subj "/CN=pi-broker.local" -out server.csr

# Extensions: ALL the names/IPs the clients will connect with
cat > server.ext <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:pi-broker.local, DNS:pi-broker, DNS:localhost, IP:192.168.1.50, IP:127.0.0.1
EOF

# The CA signs (it will ask for the ca.key password)
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile server.ext

# Check
openssl verify -CAfile ca.crt server.crt
openssl x509 -in server.crt -noout -ext subjectAltName
`, L(
            '- `server.key` 2048 bit: enough and fast for the ESP32 handshake.',
            '- **CN** (Common Name): the old way. Modern clients look at the **SAN** (subjectAltName). If the name you pass to `connect()` is not in the SAN, the connection **fails** (and rightly so!).',
            '- Put in the SAN the mDNS name (`pi-broker.local`), the hostname, and the Pi\'s fixed IP.',
            '- `extendedKeyUsage = serverAuth`: the certificate can be used only by a server.',
            '- `-days 825`: ~2 years. Set a reminder to renew!',
            '- `openssl verify`: should print `server.crt: OK`.'
          )),
          code('bash', 'Step 3: install on the Pi', R`
sudo mkdir -p /etc/mosquitto/certs
sudo cp ~/iot-ca/ca.crt ~/iot-ca/server.crt ~/iot-ca/server.key /etc/mosquitto/certs/
sudo chown -R mosquitto:mosquitto /etc/mosquitto/certs
sudo chmod 600 /etc/mosquitto/certs/server.key
sudo chmod 644 /etc/mosquitto/certs/ca.crt /etc/mosquitto/certs/server.crt
`, L(
            '- Only the `mosquitto` user reads `server.key`.',
            '- We **never** copy `ca.key` into `/etc/mosquitto`: the broker doesn\'t need it.'
          )),
          code('text', '/etc/mosquitto/conf.d/10-auth.conf (final form)', R`
per_listener_settings false
allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl

# 1) Local, without TLS: only for tools on the Pi itself
listener 1883 127.0.0.1

# 2) For the network: TLS ONLY
listener 8883
certfile /etc/mosquitto/certs/server.crt
keyfile  /etc/mosquitto/certs/server.key
cafile   /etc/mosquitto/certs/ca.crt
tls_version tlsv1.2
`, L(
            '- `listener 8883` without an address: listens on all interfaces. The firewall (ufw) decides who gets through (Modules 2, 7).',
            '- `certfile`/`keyfile`: the broker\'s identity.',
            '- `cafile`: needed if you later also require **client certificates** (`require_certificate true`, mutual TLS).',
            '- `tls_version tlsv1.2`: **minimum** TLS version 1.2 (1.3 is accepted too). No old, vulnerable version.'
          )),
          code('bash', 'Step 4: test', R`
sudo systemctl restart mosquitto
sudo ss -tlnp | grep mosquitto        # 127.0.0.1:1883 and 0.0.0.0:8883

# Check the TLS with openssl
openssl s_client -connect pi-broker.local:8883 -CAfile ~/iot-ca/ca.crt \
  -servername pi-broker.local -verify_return_error </dev/null | grep -E 'Verify return|Protocol|Cipher'

# Subscribe over TLS (from a laptop or the Pi)
mosquitto_sub -h pi-broker.local -p 8883 --cafile ~/iot-ca/ca.crt \
  -u dashboard -P 'password' -t 'home/#' -v

# And a negative test: without the CA it must FAIL
mosquitto_sub -h pi-broker.local -p 8883 --capath /etc/ssl/certs -u dashboard -P 'password' -t '#'
`, L(
            '- `s_client`: the "Swiss army knife" for TLS. We want `Verify return code: 0 (ok)`.',
            '- `-verify_return_error`: if verification fails, it drops the connection instead of carrying on.',
            '- The negative test matters: the system\'s public CAs must **not** trust your broker. This proves the check works.'
          )),
          warn('If `ca.key` is lost or stolen, the thief can sign "legitimate" fake brokers and your ESP32s will trust them. Keep it **offline**, password-protected, with a backup on a second medium.'),
          tip('You can go one step further with **mutual TLS**: each ESP32 has its own client certificate (`require_certificate true` and `use_identity_as_username true`). Then you don\'t even need the MQTT password.'),
          quiz('The ESP32 connects to `192.168.1.50` but the certificate\'s SAN has only `DNS:pi-broker.local`. What will happen?',
            ['It will work normally', 'Name verification fails: add `IP:192.168.1.50` to the SAN or connect by name', 'It will connect without encryption', 'It will use the CN'], 1,
            'The client checks that the name (or IP) it asked for is in the SAN. This stops an attacker from using a valid certificate of **another** server.'),
          quiz('Which file should go onto every ESP32?',
            ['`ca.key`', '`ca.crt`', '`server.key`', '`server.csr`'], 1,
            'The ESP32 only needs the CA\'s **public** certificate to verify the broker. The `.key` files never leave the place they belong.'),
        ],
      },
      {
        id: 'iot-4-4', title: 'ESP32 (Arduino): MQTT over TLS with WiFiClientSecure', minutes: 20,
        goal: 'Write a complete sketch that connects to the broker over **TLS** with your own CA (`setCACert`), with username/password, Last Will and a safe reconnect.',
        blocks: [
          text(
            'You will need:',
            '- **Arduino core for ESP32** (Espressif, version 3.x, based on ESP-IDF 5).',
            '- The **PubSubClient** library (Nick O’Leary) from the Library Manager.',
            '- The `ca.crt` from the previous lesson.',
            '',
            '`WiFiClientSecure` does the TLS (with mbedTLS) and `PubSubClient` speaks MQTT "on top", as if it were plain TCP.'
          ),
          code('cpp', '❌ The mistake you see everywhere on the Internet', R`
WiFiClientSecure net;
net.setInsecure();          // ❌ encryption WITHOUT authentication
PubSubClient mqtt(net);
`, L(
            '- `setInsecure()` does TLS, but **doesn\'t check** the server\'s certificate.',
            '- A MITM (e.g. an evil twin) presents its own certificate, the ESP32 accepts it, and the attacker reads the MQTT password.',
            '- It\'s like locking the door but handing the key to whoever knocks.'
          )),
          code('cpp', '✅ secrets.h with the CA', R`
#pragma once
#define WIFI_SSID  "IoT-Net"
#define WIFI_PASS  "long-random-password"
#define MQTT_HOST  "pi-broker.local"     // MUST be in the SAN of server.crt
#define MQTT_PORT  8883
#define MQTT_USER  "sensor01"
#define MQTT_PASS  "8f2K-vQ9x-Lm3p-Tz7w"

// Contents of ca.crt (cat ~/iot-ca/ca.crt). C++ raw string literal.
static const char CA_CERT[] = R"PEM(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIUQx...  (paste your ENTIRE ca.crt here)
-----END CERTIFICATE-----
)PEM";
`, L(
            '- `R"PEM( … )PEM"`: a C++ raw string. You don\'t need `\\n` and quotes on every line.',
            '- `MQTT_HOST` is the name that will be checked against the SAN.',
            '- The CA is not secret, but we put it together with the other connection details so everything is in one place.'
          )),
          code('cpp', '✅ mqtt_tls.ino: complete sketch', R`
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <time.h>
#include "secrets.h"

const char* DEVICE_ID   = "sensor01";
const char* T_STATE     = "home/sensor01/state";
const char* T_STATUS    = "home/sensor01/status";
const char* T_CMD       = "home/sensor01/cmd";

WiFiClientSecure net;
PubSubClient mqtt(net);
uint32_t lastPub = 0;
uint32_t backoffMs = 2000;

void connectWiFi() {
  WiFi.persistent(false);
  WiFi.setHostname(DEVICE_ID);
  WiFi.mode(WIFI_STA);
  WiFi.setMinSecurity(WIFI_AUTH_WPA2_PSK);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED) {
    if (millis() - t0 > 20000) ESP.restart();
    delay(250);
  }
  Serial.printf("[WiFi] %s\n", WiFi.localIP().toString().c_str());
}

void syncTime() {
  // Correct time: for timestamps, logs and for certificate expiry checks where enabled
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
  struct tm tm;
  if (getLocalTime(&tm, 10000)) Serial.println("[NTP] time OK");
  else Serial.println("[NTP] failed (continuing)");
}

void onMessage(char* topic, byte* payload, unsigned int len) {
  char buf[16];
  if (len == 0 || len >= sizeof(buf)) return;          // length limit
  memcpy(buf, payload, len);
  buf[len] = '\0';
  if (strcmp(buf, "ping") == 0) mqtt.publish(T_STATUS, "pong");
  else Serial.println("[MQTT] unknown command");       // whitelist
}

bool connectMqtt() {
  Serial.print("[MQTT] TLS connecting... ");
  // client id, user, pass, willTopic, willQos, willRetain, willMessage
  if (mqtt.connect(DEVICE_ID, MQTT_USER, MQTT_PASS, T_STATUS, 1, true, "offline")) {
    Serial.println("OK");
    mqtt.publish(T_STATUS, "online", true);           // retained
    mqtt.subscribe(T_CMD, 1);
    backoffMs = 2000;
    return true;
  }
  Serial.printf("failed, state=%d\n", mqtt.state());
  char err[128];
  int code = net.lastError(err, sizeof(err));        // detail from mbedTLS
  if (code) Serial.printf("[TLS] %d: %s\n", code, err);
  return false;
}

void setup() {
  Serial.begin(115200);
  connectWiFi();
  syncTime();

  net.setCACert(CA_CERT);          // ✅ we trust ONLY our own CA
  net.setHandshakeTimeout(15);     // seconds
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMessage);
  mqtt.setBufferSize(512);
  mqtt.setKeepAlive(30);
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) connectWiFi();

  if (!mqtt.connected()) {
    static uint32_t lastTry = 0;
    if (millis() - lastTry > backoffMs) {
      lastTry = millis();
      if (!connectMqtt()) backoffMs = min<uint32_t>(backoffMs * 2, 60000);   // exponential backoff
    }
    return;
  }
  mqtt.loop();

  if (millis() - lastPub > 30000) {
    lastPub = millis();
    char json[64];
    snprintf(json, sizeof(json), "{\"uptime\":%lu,\"rssi\":%d}", millis() / 1000, WiFi.RSSI());
    mqtt.publish(T_STATE, json);
  }
}
`, L(
            '- `net.setCACert(CA_CERT)`: the key to security. mbedTLS accepts only a certificate signed by **this** CA, and checks that `MQTT_HOST` is in the SAN.',
            '- `configTime` / `getLocalTime`: time sync with NTP. In ESP-IDF the certificate date check is usually **disabled** by default (`CONFIG_MBEDTLS_HAVE_TIME_DATE`), but the correct time is needed for logs and for when you enable it.',
            '- `mqtt.connect(id, user, pass, willTopic, 1, true, "offline")`: connect with a **Last Will**. If the ESP32 disappears, the broker publishes `offline` (retained).',
            '- `publish(T_STATUS, "online", true)`: retained, so anyone who subscribes later knows the state.',
            '- `net.lastError()`: when TLS fails, here you see the reason (e.g. `X509 - Certificate verification failed`).',
            '- `setBufferSize(512)`: the default 256 bytes is small for JSON. Messages larger than the buffer are dropped.',
            '- **Exponential backoff** (2s → 4s → … → 60s): if the broker goes down, the devices don\'t "bombard" it all at once.',
            '- `snprintf(json, sizeof(json), …)`: never `sprintf` without a limit.'
          )),
          table(['Error', 'Likely cause'], [
            ['`state=-2` and `X509 - Certificate verification failed`', 'Wrong CA in `CA_CERT`, or the name in `MQTT_HOST` is not in the SAN'],
            ['`state=5` (not authorized)', 'Wrong user/pass or the user is not in the password_file'],
            ['`state=-2` without a TLS error', 'The name doesn\'t resolve (DNS/mDNS), or the firewall blocks 8883'],
            ['Connects and is immediately dropped', 'Duplicate client id (two devices with the same `DEVICE_ID`)'],
          ]),
          tip('If `pi-broker.local` doesn\'t resolve from the ESP32, add a static DNS entry on the router (e.g. `pi-broker.lan`), put that name in the SAN, and reissue `server.crt`.'),
          quiz('Which line makes the ESP32 reject a broker with a certificate from another CA?',
            ['`mqtt.setServer(MQTT_HOST, 8883)`', '`net.setCACert(CA_CERT)`', '`net.setInsecure()`', '`mqtt.setKeepAlive(30)`'], 1,
            '`setCACert` defines which CA we trust. Without it (or with `setInsecure`) there is no authentication.'),
          quiz('Why do we use exponential backoff when reconnecting?',
            ['To use more battery', 'So that all the devices don\'t bombard the broker when it comes back, and for less noise/consumption', 'Because TLS requires it', 'To change the Wi‑Fi channel'], 1,
            'With a fixed short delay, 20 devices would do a TLS handshake every 2 seconds. Backoff calms the system down.'),
        ],
      },
      {
        id: 'iot-4-5', title: 'MicroPython (umqtt + ssl) and Python (paho) with TLS', minutes: 18,
        goal: 'Connect an ESP32 running **MicroPython** to the broker over TLS with CA verification, and write a Python client on the Pi that also verifies the broker.',
        blocks: [
          text(
            'In MicroPython (version **1.23+**) TLS is done with an `ssl.SSLContext`, which we pass to `umqtt.simple`. The CA is loaded in **DER** (binary) format for maximum compatibility.'
          ),
          code('bash', 'Preparation on your computer', R`
pip install mpremote

# Convert the CA from PEM to DER
openssl x509 -in ~/iot-ca/ca.crt -outform der -out ca.der

# Install umqtt.simple: mpremote downloads it and copies it to the device
mpremote mip install umqtt.simple

# Upload the files
mpremote cp ca.der :ca.der
mpremote cp secrets.py :secrets.py
mpremote cp wifi.py :wifi.py
mpremote cp main.py :main.py
mpremote reset
`, L(
            '- `mpremote`: the official tool for files and the REPL in MicroPython.',
            '- `-outform der`: the same CA, in binary form.',
            '- `mip install umqtt.simple`: downloads the library from micropython-lib onto the device (`/lib`).',
            '- `wifi.py` is the one from lesson 3.2.'
          )),
          code('micropython', 'main.py: MQTT over TLS with CA verification', R`
import time
import ssl
import machine
import ntptime
from umqtt.simple import MQTTClient
import secrets
import wifi                      # connects on import (lesson 3.2)

DEVICE = b"sensor02"
T_STATE = b"home/sensor02/state"
T_STATUS = b"home/sensor02/status"
T_CMD = b"home/sensor02/cmd"

try:
    ntptime.settime()            # UTC time from NTP
except OSError:
    print("NTP failed, continuing")

# --- TLS context: we trust ONLY our own CA ---
with open("ca.der", "rb") as f:
    ca = f.read()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.load_verify_locations(cadata=ca)


def on_msg(topic, msg):
    if len(msg) > 16:            # length limit
        return
    if msg == b"ping":
        client.publish(T_STATUS, b"pong")
    else:
        print("unknown command")  # whitelist


client = MQTTClient(
    client_id=DEVICE,
    server=secrets.MQTT_HOST,    # MUST be in the SAN
    port=8883,
    user=secrets.MQTT_USER,
    password=secrets.MQTT_PASS,
    keepalive=60,
    ssl=ctx,
)
client.set_last_will(T_STATUS, b"offline", retain=True, qos=1)
client.set_callback(on_msg)


def connect():
    client.connect()
    client.publish(T_STATUS, b"online", retain=True)
    client.subscribe(T_CMD, qos=1)
    print("MQTT/TLS OK")


connect()
last = 0
while True:
    try:
        client.check_msg()                       # non-blocking check for commands
        if time.ticks_diff(time.ticks_ms(), last) > 30000:
            last = time.ticks_ms()
            payload = '{"uptime":%d}' % (time.ticks_ms() // 1000)
            client.publish(T_STATE, payload.encode())
    except OSError as e:
        print("Connection error:", e, "→ reset in 10s")
        time.sleep(10)
        machine.reset()
    time.sleep_ms(100)
`, L(
            '- `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)`: the new MicroPython API (1.23+), the same in spirit as CPython.',
            '- `verify_mode = ssl.CERT_REQUIRED`: **mandatory** verification. Without this line some versions check nothing, so you have the same problem as with `setInsecure()`.',
            '- `load_verify_locations(cadata=ca)`: the CA as DER bytes.',
            '- `ssl=ctx`: `umqtt.simple` does `wrap_socket(…, server_hostname=server)`, so a **name check** against the SAN happens too.',
            '- `set_last_will`: like in Arduino. It must be called **before** `connect()`.',
            '- `check_msg()`: doesn\'t block. If there is a message, it calls `on_msg`.',
            '- `umqtt.simple` doesn\'t reconnect automatically. The simplest reliable pattern: on `OSError`, reset.'
          )),
          warn('If you see an example with `MQTTClient(..., ssl=True)` and no context, it is the old API and does **not** verify the certificate. Always use an `SSLContext` with `CERT_REQUIRED`.'),
          text('### Python client on the Pi (paho-mqtt 2.x) with TLS'),
          code('python', 'sub_tls.py', R`
import json
import os
import ssl
import paho.mqtt.client as mqtt

BROKER = "pi-broker.local"
CA = "/etc/mosquitto/certs/ca.crt"


def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code.is_failure:
        print("Connection failed:", reason_code)
        return
    print("Connected with TLS")
    client.subscribe("home/#", qos=1)


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload)
    except ValueError:
        data = msg.payload.decode(errors="replace")[:100]   # cut off very long ones
    print(msg.topic, data)


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="dashboard")
client.username_pw_set("dashboard", os.environ["MQTT_PASS"])
client.tls_set(ca_certs=CA, cert_reqs=ssl.CERT_REQUIRED)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, 8883, keepalive=60)
client.loop_forever()
`, L(
            '- `os.environ["MQTT_PASS"]`: the password comes from an environment variable, not from the code. Run: `MQTT_PASS=\'…\' ~/iot-venv/bin/python sub_tls.py`.',
            '- `tls_set(ca_certs=CA, cert_reqs=ssl.CERT_REQUIRED)`: verifies the broker with our own CA. The name check happens automatically.',
            '- **Never** use `client.tls_insecure_set(True)`: it is Python\'s `setInsecure()`.',
            '- `reason_code.is_failure`: in paho 2.x the reason code is an object, not a plain number.',
            '- `json.loads` inside `try`: data from the network can be corrupted or malicious.'
          )),
          quiz('In MicroPython, which line is required for the broker\'s certificate to be **verified**?',
            ['`ssl=True`', '`ctx.verify_mode = ssl.CERT_REQUIRED` together with `load_verify_locations`', '`keepalive=60`', '`ntptime.settime()`'], 1,
            'Without `CERT_REQUIRED` and the CA, you have encryption without authentication, so you are open to MITM.'),
          quiz('Which is the "bad" equivalent of `setInsecure()` in paho-mqtt?',
            ['`client.tls_set(ca_certs=CA)`', '`client.tls_insecure_set(True)`', '`client.username_pw_set()`', '`client.loop_forever()`'], 1,
            '`tls_insecure_set(True)` turns off the server name check. For tests only, never in real use.'),
        ],
      },
      {
        id: 'iot-4-6', title: 'HTTPS from the ESP32 and certificate pinning', minutes: 16,
        goal: 'Make HTTPS requests from the ESP32 with proper verification, understand what **certificate pinning** is (CA pin, leaf/fingerprint pin) and when it "bites" you.',
        blocks: [
          text(
            'The ESP32 often speaks **HTTP(S)** too: for OTA, for APIs (weather, time), for webhooks. The same rule as for MQTT applies: **never** `setInsecure()`.',
            '',
            '**Pinning** means: "I don\'t trust any valid CA in the world, only **this** specific CA, or only **this** specific certificate".'
          ),
          table(['Type', 'What it checks', 'Advantage', 'Risk'], [
            ['**CA pinning**', 'That the cert was signed by CA X', 'Survives renewals of the server cert', 'If the provider changes CA, it breaks'],
            ['**Leaf / fingerprint pinning**', 'The SHA-256 of the exact certificate', 'Very strict', 'Breaks on **every** renewal (Let’s Encrypt: every 60–90 days)'],
            ['**Your own CA** (Module 4.3)', 'Only what you signed', 'Full control, long-lived', 'You must protect `ca.key`'],
          ]),
          code('cpp', 'https_get.ino: HTTPS with CA pinning (HTTPClient)', R`
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include "secrets.h"     // WIFI_SSID, WIFI_PASS, CA_CERT (your own CA)

// Local server on the Pi with a cert signed by your own CA
const char* URL = "https://pi-broker.local:8443/api/config";

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(250);

  WiFiClientSecure client;
  client.setCACert(CA_CERT);                  // ✅ CA pinning

  HTTPClient https;
  https.setTimeout(10000);
  if (!https.begin(client, URL)) {
    Serial.println("begin() failed");
    return;
  }
  int code = https.GET();
  if (code == HTTP_CODE_OK) {
    String body = https.getString();
    if (body.length() > 2048) {               // size limit
      Serial.println("Response too large, ignored");
    } else {
      Serial.println(body);
    }
  } else {
    Serial.printf("HTTP error: %d (%s)\n", code, https.errorToString(code).c_str());
  }
  https.end();
}

void loop() {}
`, L(
            '- `HTTPClient` + `WiFiClientSecure`: HTTPClient uses the secure client you give it, and therefore its CA check.',
            '- `https.begin(client, URL)`: always the form **with** a client. The old form with a fingerprint string is for ESP8266.',
            '- Check `code` and the response **size**: the ESP32 has little memory. A huge response (malicious or not) can crash it.',
            '- `errorToString(code)`: a friendly message for negative codes (e.g. `connection refused`).'
          )),
          code('cpp', 'Fingerprint pinning with WiFiClientSecure::verify()', R`
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "secrets.h"

// SHA-256 of server.crt:
//   openssl x509 -in server.crt -noout -fingerprint -sha256
const char* HOST = "pi-broker.local";
const char* FP_SHA256 =
  "3A:1F:9C:44:...:7B";      // PUT YOUR OWN (32 bytes in hex)

void setup() {
  Serial.begin(115200);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(250);

  WiFiClientSecure c;
  c.setCACert(CA_CERT);                       // 1st layer: the CA
  if (!c.connect(HOST, 8443)) {
    Serial.println("TLS failure");
    return;
  }
  if (!c.verify(FP_SHA256, HOST)) {           // 2nd layer: the exact cert
    Serial.println("❌ Fingerprint doesn't match, closing");
    c.stop();
    return;
  }
  c.print("GET /api/config HTTP/1.1\r\nHost: pi-broker.local\r\nConnection: close\r\n\r\n");
  while (c.connected() || c.available()) {
    if (c.available()) Serial.write(c.read());
  }
  c.stop();
}

void loop() {}
`, L(
            '- `openssl x509 … -fingerprint -sha256`: gives the fingerprint of the server\'s certificate.',
            '- First `setCACert` (the normal check), then `verify(fp, host)`: compares the SHA-256 of the certificate the server sent with yours.',
            '- If you renew `server.crt`, you must update the firmware **beforehand**. Otherwise the device gets cut off. That is why, for your own devices, your own CA is usually enough.',
            '- Manual HTTP request: useful to see what happens "under the hood".'
          )),
          code('python', 'The same in Python (e.g. a script on the Pi that talks to an ESP32 web server)', R`
import hashlib
import socket
import ssl

HOST, PORT = "pi-broker.local", 8443
PIN = "3a1f9c44...7b"        # SHA-256 of the cert, lowercase hex without ':'

ctx = ssl.create_default_context(cafile="ca.crt")    # CA pinning
with socket.create_connection((HOST, PORT), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname=HOST) as tls:
        der = tls.getpeercert(binary_form=True)
        fp = hashlib.sha256(der).hexdigest()
        if fp != PIN:
            raise SystemExit(f"❌ pin mismatch: {fp}")
        print("✅ TLS", tls.version(), "pin OK")

# Or simply with requests (CA pinning only):
# requests.get(f"https://{HOST}:{PORT}/api/config", verify="ca.crt", timeout=5)
`, L(
            '- `create_default_context(cafile=…)`: trusts **only** your own CA and checks the name.',
            '- `getpeercert(binary_form=True)`: the certificate in DER, so we can hash it.',
            '- `verify="ca.crt"` in `requests`: never `verify=False`.'
          )),
          tip('For **public** sites (e.g. a weather API) the Arduino core 3.x also has `setCACertBundle()`, with a bundle of the well-known root CAs. It is better than `setInsecure()`, but less strict than pinning.'),
          quiz('You do **leaf pinning** on a server with Let’s Encrypt. What happens in ~60–90 days?',
            ['Nothing', 'The certificate is renewed, the fingerprint changes and the device stops connecting', 'The device becomes more secure', 'The ESP32 updates itself'], 1,
            'That is why leaf pinning needs a **renewal plan** (two pins: current and next) or you prefer CA/public-key pinning.'),
          quiz('What is the correct order of checks for fingerprint pinning with `WiFiClientSecure`?',
            ['`setInsecure()` and then `verify()`', '`setCACert()`, `connect()`, then `verify(fp, host)` before sending data', 'Only `verify()` after the request', 'Only `connect()`'], 1,
            'You check **before** sending anything sensitive. `setCACert` gives the basic check, `verify` the extra pin.'),
        ],
      },
      {
        id: 'iot-4-7', title: 'Watch the MQTT password go by', minutes: 20,
        goal: 'Capture a **CONNECT** packet on port 1883 of your own broker with **tcpdump/Wireshark**, find the username and password inside it **byte by byte**, then move to **TLS on 8883** and see that the same capture no longer shows anything useful.',
        blocks: [
          text(
            'In your lab, **Mosquitto** runs in a **Proxmox** VM, on port **1883**, with a password but **without TLS**. The password protects against anyone who *doesn\'t* know it. The problem: anyone who sees the traffic **learns** it.',
            '',
            'In this lab you won\'t believe it just because I say so. You will **see** it with your own eyes, on **your own** network, and then fix it.'
          ),
          anim('iot-mqtt-sniff', 'The same CONNECT: on 1883 the password is visible, on 8883 you only see encrypted bytes.'),
          warn('Capture traffic **only** on a network and devices that are **your own**. Intercepting other people\'s traffic is illegal.'),
          text(
            '### Step 1: start the capture',
            'The best place is **the broker itself** (the VM), because every connection definitely passes through it. Alternatively, on the **Proxmox host** on the `vmbr0` bridge, where you see the traffic of all the VMs.'
          ),
          code('bash', 'Capture on port 1883 (in the broker VM)', R`
# Which is the interface? (on Proxmox VMs usually ens18)
ip -br addr

# Live, with hex + ASCII
sudo tcpdump -i ens18 -n -X 'tcp port 1883'

# Or to a file, to open later in Wireshark
sudo tcpdump -i ens18 -n -w mqtt-1883.pcap 'tcp port 1883'
`, L(
            '- `tcp port 1883`: a **capture filter** (BPF syntax). Keeps only what goes to or comes from port 1883.',
            '- `-X`: shows each packet in **hex** and **ASCII** side by side.',
            '- `-w file.pcap`: writes the packets to a file. You open it in Wireshark on the laptop (`scp` from the VM).',
            '- On the Proxmox host: `sudo tcpdump -i vmbr0 -n -X \'tcp port 1883\'`.'
          )),
          text(
            '### Step 2: send a message with a password',
            'From **another** machine (e.g. the laptop or a Pi), send a test message with a **test** user. We also add `-i lab-test` so the client id is known.'
          ),
          code('bash', 'A publish with username/password', R`
mosquitto_pub -h 192.168.1.17 -p 1883 -i lab-test -u user -P pass -t test -m hi
`, L(
            '- `-h`: the broker\'s IP (the VM on Proxmox). `-p 1883`: plaintext MQTT.',
            '- `-i lab-test`: client id. `-u` / `-P`: username and password.',
            '- `-t test -m hi`: topic and message.',
            '- Use a **test** user, not the password of a real device: you will see it printed on the screen.'
          )),
          text(
            '### Step 3: read the CONNECT packet',
            'In the tcpdump output, after the TCP handshake, you will see something like this (only the MQTT part):'
          ),
          code('text', 'The CONNECT in hex (MQTT 3.1.1)', R`
10 20                         fixed header: type CONNECT, remaining length = 32
00 04 4d 51 54 54             protocol name: length 4, "MQTT"
04                            protocol level: 4 = MQTT 3.1.1
c2                            connect flags = 1100 0010
00 3c                         keep alive = 60 s
00 08 6c 61 62 2d 74 65 73 74 client id: "lab-test"
00 04 75 73 65 72             username:  "user"
00 04 70 61 73 73             password:  "pass"   <-- here!
`, L(
            '- **Fixed header `0x10`**: the top 4 bits are the packet type (1 = CONNECT), the bottom 4 are flags (0 for CONNECT). Then comes the **remaining length** (here `0x20` = 32 bytes).',
            '- **Protocol name/level**: `MQTT` and `04` = version 3.1.1. (MQTT 5 has `05` and extra properties.)',
            '- **Connect flags `0xC2`**: bit 7 (`0x80`) = **username present**, bit 6 (`0x40`) = **password present**, bit 1 (`0x02`) = clean session. Bits 2–5 concern the Will message.',
            '- **Payload**: each field is preceded by a **2-byte length** and then its bytes, in order: client id, (Will), **username**, **password**.',
            '- There is **no** encryption or hash: the password is the same bytes you typed.'
          )),
          table(['Bit', 'Mask', 'Meaning in the connect flags'], [
            ['7', '`0x80`', '**User Name Flag**: a username follows in the payload'],
            ['6', '`0x40`', '**Password Flag**: a password follows in the payload'],
            ['5', '`0x20`', 'Will Retain'],
            ['4–3', '`0x18`', 'Will QoS (0, 1 or 2)'],
            ['2', '`0x04`', 'Will Flag'],
            ['1', '`0x02`', 'Clean Session'],
            ['0', '`0x01`', 'Reserved (must be 0)'],
          ]),
          text(
            '### The same in Wireshark',
            'Open `mqtt-1883.pcap`. Wireshark recognises MQTT on port 1883 by itself.',
            '- Display filter `mqtt`: only the MQTT packets.',
            '- Display filter `mqtt.msgtype == 1`: only the CONNECTs.',
            '- Open **MQ Telemetry Transport Protocol → Connect Command**: you will see *User Name* and *Password* as fields, ready to copy.',
            '',
            'Mind the difference: `tcp port 1883` is a **capture filter** (what gets recorded), while `mqtt` is a **display filter** (what Wireshark shows from what was recorded).'
          ),
          code('bash', 'The same from the command line with tshark', R`
tshark -r mqtt-1883.pcap -Y 'mqtt.msgtype == 1' -T fields -e ip.src -e mqtt.clientid -e mqtt.username -e mqtt.passwd
`, L(
            '- `-r`: reads the file. `-Y`: display filter.',
            '- `-T fields -e …`: prints only the fields you ask for. One line per connection: IP, client id, user, **password**.',
            '- This is exactly what an attacker on the same network would do. In seconds.'
          )),
          nw('alerts', '**NetWatch** automatically does what you just did by hand: when it sees an MQTT CONNECT with the `0x80`/`0x40` bits in clear text, it raises a **"Password sent unencrypted (cleartext)"** alert with protocol **MQTT**, the device\'s IP and the username (the password itself is not stored). Open **Alerts** after the `mosquitto_pub`.'),
          quiz('In the connect flags of a CONNECT you see `0x82`. What travels in the payload?',
            ['Username and password', 'Only a username (no password), with a clean session', 'Only a password', 'Neither'], 1,
            '`0x82` = `0x80` (username) + `0x02` (clean session). The `0x40` bit (password) is 0. For username **and** password you would see `0xC2`.'),
          text(
            '### Step 4: move to TLS on 8883',
            'If you don\'t have a CA and certificates yet, create them as in the lesson **"Your own CA and TLS on 8883"**. `server.crt` must have in its **SAN** the name or IP the clients connect with (e.g. `IP:192.168.1.17`).'
          ),
          code('text', '/etc/mosquitto/conf.d/20-tls.conf', R`
per_listener_settings false
allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl

# Plaintext ONLY for tools on the same VM
listener 1883 127.0.0.1

# TLS for the whole network
listener 8883
cafile   /etc/mosquitto/certs/ca.crt
certfile /etc/mosquitto/certs/server.crt
keyfile  /etc/mosquitto/certs/server.key
tls_version tlsv1.2
`, L(
            '- `listener 8883`: a new listener on all addresses.',
            '- `cafile`: your CA. `certfile` / `keyfile`: the broker\'s certificate and private key (`server.key` owned by `mosquitto` with mode 600).',
            '- `tls_version tlsv1.2`: minimum TLS version 1.2 (TLS 1.3 is allowed too).',
            '- `listener 1883 127.0.0.1`: 1883 no longer listens on the network. Before you do this, switch the ESP32s to 8883, otherwise they will be cut off.'
          )),
          code('bash', 'Restart and the same publish, now with TLS', R`
sudo systemctl restart mosquitto
sudo ss -tlnp | grep mosquitto        # 127.0.0.1:1883 and 0.0.0.0:8883

# In the VM: capture on the new port
sudo tcpdump -i ens18 -n -X 'tcp port 8883'

# From the laptop: the same message, inside TLS
mosquitto_pub --cafile ca.crt -h 192.168.1.17 -p 8883 -i lab-test -u user -P pass -t test -m hi
`, L(
            '- `ss -tlnp`: you confirm that 1883 listens **only** on localhost.',
            '- `--cafile ca.crt`: the client trusts **only** your own CA and checks that the name/IP of `-h` is in the SAN.',
            '- If you see `certificate verify failed`, `-h` doesn\'t match the SAN or `ca.crt` is wrong. **Never** `--insecure` just to "get it through".'
          )),
          text(
            'Now tcpdump shows only **TLS records**: a *ClientHello* / *ServerHello* and then lines starting with `17 03 03` (Application Data) followed by random bytes. In Wireshark the `mqtt` filter finds **nothing**, and the `tls` filter shows only encrypted data.',
            '',
            'What can someone still see? The **IPs**, the **ports**, the **size** and the **timing** of the packets (and maybe the server name in the ClientHello SNI). But not passwords, topics or readings.'
          ),
          table(['', '1883 (no TLS)', '8883 (TLS)'], [
            ['Display filter `mqtt`', 'CONNECT, PUBLISH, SUBSCRIBE…', 'nothing'],
            ['Username / password', 'plain text', 'encrypted'],
            ['Topics and readings', 'plain text', 'encrypted'],
            ['Who talks to whom (IP/port)', 'visible', 'visible'],
            ['NetWatch alert', '"Password sent unencrypted (cleartext)" (MQTT)', 'none'],
          ]),
          tip('Final test: run `mosquitto_pub` again on **1883** from the laptop. You should get `Connection refused`. If it goes through, some listener is still listening on the network.'),
          quiz('In Wireshark you type the display filter `mqtt` on a capture of port 8883 and see nothing. Why?',
            ['Wireshark doesn\'t support MQTT', 'MQTT travels inside TLS: Wireshark sees only encrypted TLS records', 'The broker sent nothing', '8883 is UDP'], 1,
            'Without the session keys, Wireshark can\'t decrypt. That is exactly the point of TLS.'),
          quiz('Which is a **capture** filter and which a **display** filter?',
            ['`mqtt` = capture, `tcp port 1883` = display', '`tcp port 1883` = capture (BPF, tcpdump/Wireshark while capturing), `mqtt` = display (Wireshark, afterwards)', 'Both are display filters', 'Both are capture filters'], 1,
            'Capture filters (BPF syntax) decide what gets **recorded**. Wireshark display filters decide what is **shown** and understand protocols such as `mqtt`.'),
        ],
      },
      {
        id: 'iot-4-8', title: 'A guard for your broker', minutes: 18,
        goal: 'Set up the NetWatch **MQTT guard**: a **read-only** user, an ACL, `log_dest topic` in Mosquitto, and understand which alerts it raises. And apply **least privilege**: every ESP32 gets its own user and writes only to its own topics.',
        blocks: [
          text(
            'TLS hides the traffic. Passwords and the ACL keep strangers out. One question remains: **how will you notice** that something changed? A new device that connected, an ESP32 that suddenly writes to a topic it never wrote to, a command to the relay at 3 in the morning.',
            '',
            'The NetWatch **MQTT guard** connects to your broker like one more client, **read-only**, and watches.'
          ),
          table(['Alert', 'When', 'Why you care'], [
            ['**Unknown client on the MQTT broker**', 'A client id connects that it has never seen before (from the broker log)', 'A stolen password, or a new device you didn\'t add'],
            ['**New MQTT topic**', 'A topic (pattern) appears that had never been used', 'Changed firmware, or someone testing the ACL'],
            ['**MQTT command at an unusual time**', 'A publish to a command topic (`…/set`, `…/cmd`, `relay`, `switch`) between 00:00 and 06:00', 'Someone is switching things on/off without you'],
            ['**IoT device stopped sending**', 'A device doesn\'t send for more than 5× its usual interval (at least 5′)', 'It crashed, lost Wi‑Fi, or someone cut it off (deauth)'],
          ]),
          text(
            'For the first **15 minutes** the guard only **learns**: which clients exist, which topics are used and how often each device sends (it tells devices apart by the first two levels of the topic, e.g. `home/garden`). What it learns it remembers even after a restart; the "↺ relearn" button starts from scratch. After that it alerts on anything that **deviates** from this picture.',
            '',
            '### How it sees connections: `$SYS/broker/log`',
            'A normal client sees only **messages**, not who connects. But Mosquitto can publish **its own log** to topics, with the `log_dest topic` setting. The lines go to `$SYS/broker/log/<level>` (e.g. `N` for notice), and among them are the connections:'
          ),
          code('text', 'What the guard reads from $SYS/broker/log/N', R`
New client connected from 192.168.1.20:5123 as esp32-garden (p2, c1, k60, u'garden').
Client esp32-garden disconnected.
New client connected from 192.168.1.66:40112 as kali-test (p2, c1, k60, u'garden').
`, L(
            '- `from 192.168.1.20:5123`: the client\'s IP and port. `as esp32-garden`: the client id.',
            '- `p2` = MQTT 3.1.1 (`p5` = MQTT 5), `c1` = clean session, `k60` = keep alive 60 s, `u\'garden\'` = username.',
            '- The third line: the user `garden` from **another IP** and with **another client id**. The ESP32\'s password is being used from elsewhere: exactly what you want to know right away.'
          )),
          text('### Step 1: a `netwatch` user in Mosquitto'),
          code('bash', 'In the broker VM', R`
# WITHOUT -c: the file already exists!
sudo mosquitto_passwd /etc/mosquitto/passwd netwatch
`, L(
            '- It asks for the password interactively (it doesn\'t stay in the history).',
            '- Give a **long, random** password, only for NetWatch (e.g. `openssl rand -base64 24`).'
          )),
          text('### Step 2: a read-only ACL'),
          code('text', '/etc/mosquitto/acl (addition)', R`
# --- NetWatch: reads everything, writes NOTHING ---
user netwatch
topic read #
topic read $SYS/#
`, L(
            '- `topic read #`: all the normal topics.',
            '- `topic read $SYS/#`: needs a **separate** line. According to the MQTT standard, a wildcard at the start (`#`) does **not** match topics starting with `$`.',
            '- No `write` line: if someone steals NetWatch\'s password, they **can\'t** send commands.'
          )),
          text('### Step 3: the broker log to a topic'),
          code('text', '/etc/mosquitto/conf.d/30-netwatch.conf', R`
# Also publish the log to $SYS/broker/log/#
# (this keeps the existing log_dest file of mosquitto.conf)
log_dest topic

# Default, written for certainty: log every connection/disconnection
connection_messages true
`, L(
            '- `log_dest topic`: every log line becomes a message on `$SYS/broker/log/E|W|N|I…` (error, warning, notice, information).',
            '- You can have **several** `log_dest` lines: the file `/var/log/mosquitto/mosquitto.log` keeps being written.',
            '- The log contains IPs, client ids and usernames. That is why `$SYS/#` is read **only** by `netwatch` and no other user.'
          )),
          code('bash', 'Apply and check', R`
sudo systemctl restart mosquitto
sudo journalctl -u mosquitto -n 20 --no-pager

# See what the guard will see (in another terminal restart an ESP32)
mosquitto_sub -h 192.168.1.17 -u netwatch -P 'the-password' -v -t '$SYS/broker/log/#'

# netwatch must NOT be able to write. With MQTT 5 and QoS 1 the broker says so explicitly:
mosquitto_pub -h 192.168.1.17 -u netwatch -P 'the-password' -V mqttv5 -q 1 -t home/garden/set -m ON
`, L(
            '- The single quotes in `\'$SYS/broker/log/#\'` stop the shell from "eating" `$SYS`.',
            '- `-v`: prints the topic of each message too.',
            '- On the last one: with MQTT 3.1.1 the broker just silently drops the message. With `-V mqttv5 -q 1` you get a **not authorized** reply. Confirm that the relay did **not** change.'
          )),
          text('### Step 4: configuration in NetWatch'),
          code('yaml', 'NetWatch config.yaml', R`
mqtt_guard:
  host: 192.168.1.17
  port: 1883        # 8883 + ca_file once you add TLS
  username: netwatch
  password: "..."
  # ca_file: ~/netwatch/mqtt-ca.crt
`, L(
            '- `host`: your broker (the VM on Proxmox).',
            '- `port`: 1883 as long as you don\'t have TLS. Once you move to TLS: `port: 8883` and uncomment `ca_file` with your CA\'s `ca.crt`.',
            '- `username` / `password`: the read-only user. `config.yaml` with `chmod 600`, because it contains a password.',
            '- Remember the earlier lesson: while the guard talks on 1883, **its own** password also travels in clear text.'
          )),
          nw('mqtt', 'Open the **MQTT** tab in NetWatch: you will see the clients the guard knows, each device\'s topics and when it last spoke. Restart an ESP32 and watch the connection appear.'),
          text(
            '### Least privilege: every ESP32 gets its own user',
            'The guard **sees**. The ACL **prevents**. You need both. The rule is simple: every client gets **the fewest permissions** it needs to do its job.',
            '- **One user per device** (`garden`, `boiler`…), never one shared `esp32` for everything. If an ESP32 is stolen, you delete **only** that user.',
            '- Each device **writes only** to its own topics and **reads only** its own commands.',
            '- Only the dashboard or Home Assistant writes to command topics.',
            '- NetWatch only **reads**.'
          ),
          code('text', '/etc/mosquitto/acl with one user per ESP32', R`
user garden
topic write home/garden/state
topic write home/garden/status
topic read  home/garden/set

user boiler
topic write home/boiler/state
topic write home/boiler/status
topic read  home/boiler/set

user dashboard
topic read  home/#
topic write home/+/set

user netwatch
topic read #
topic read $SYS/#
`, L(
            '- `garden` can\'t switch on `boiler`, even if someone extracts the password from the ESP32\'s flash.',
            '- `home/+/set`: `+` matches **one** level, so the dashboard sends commands only to `home/<device>/set`.',
            '- With many devices, the same with one rule: `pattern write home/%u/state` and `pattern read home/%u/set` (`%u` = username).'
          )),
          tip('With `use_username_as_clientid true` on the listener, Mosquitto uses the **username as the client id**. That way nobody can connect with an ESP32\'s client id and "kick" it out (the broker drops the old connection when a new one with the same client id arrives).'),
          quiz('Why does NetWatch\'s ACL need **both** `topic read #` **and** `topic read $SYS/#`?',
            ['It doesn\'t: `#` covers everything', 'Because topics starting with `$` don\'t match a wildcard at the start of the filter', 'Because `$SYS` is write-only', 'Because `#` matches only one level'], 1,
            'The MQTT standard says filters starting with `#` or `+` don\'t match topics starting with `$`. That is why `$SYS/#` is declared explicitly.'),
          quiz('The guard alerts: "New client `kali-test` from 192.168.1.66 with user `garden`". The garden ESP32 is online from 192.168.1.20. What do you do first?',
            ['Nothing, it\'s the ESP32 that changed IP', 'Change the password of the user `garden` (or delete it), update the ESP32 and find out which device is 192.168.1.66', 'Restart the broker', 'Give `garden` `topic readwrite #`'], 1,
            'The same user from two IPs and with another client id means the password **leaked**. Revoke it and find the device (the Devices tab). Because `garden` writes only to its own topics, the damage is limited.'),
        ],
      },
    ],
  });

  ACADEMY.track({ id: 'iot', order: 2, title: '🔌 IoT Security: ESP32 & Raspberry Pi', level: 'Beginner → Advanced', desc: 'Secure your own ESP32 and Raspberry Pi projects step by step, with code that runs: hardening, MQTT with TLS, Secure Boot, segmentation, monitoring and a final project.', modules: M });
})();
