// NetWatch Academy — 🔌 IoT Security: ESP32 & Raspberry Pi (English, modules 5-7)
(function () {
  'use strict';
  const fx = s => s;  // (the engine now protects * inside `code`)
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

  // ====================================================================
  // MODULE 5 — Firmware security
  // ====================================================================
  const EFUSE_WARN = warn(
    '**WARNING: eFuses are burned ONCE and forever.** There is no undo and no “factory reset”. One mistake (a lost signing key, the wrong mode, a power cut on the first boot) can make the chip **permanently useless** (bricked) or unable to ever accept new firmware again.',
    '- Try **first** on a cheap board you are willing to lose.',
    '- Keep a **backup** of the signing key in two safe places (not in Git!).',
    '- Read the official ESP-IDF documentation for **your own** chip (ESP32, S2, S3, C3, C6…): the details differ.',
    '- Start in **Development mode** and move to Release only when everything works.'
  );

  M.push({
    id: 'iot-5', order: 5, title: 'Firmware security: Secure Boot, Flash Encryption, OTA',
    desc: 'Secure Boot v2, Flash Encryption, signed OTA (ArduinoOTA, HTTPS OTA) and disabling JTAG/UART. With ESP-IDF v5.',
    lessons: [
      {
        id: 'iot-5-1', title: 'Secure Boot v2: only your own firmware runs', minutes: 18,
        goal: 'Understand the **chain of trust** of Secure Boot v2 (ROM → bootloader → app), what gets written to the eFuses, and how to enable it with `idf.py`/`espsecure.py` without destroying the chip.',
        blocks: [
          text(
            'Without Secure Boot, anyone with access (USB or an open OTA) can write **any** firmware to your ESP32 and it will run. With Secure Boot, the chip runs **only** firmware signed with **your own** private key.',
            '',
            '### How it works (Secure Boot v2)',
            '1. You create a **signing key** (RSA-3072, or ECDSA on newer chips). The private key stays with you.',
            '1. The build **signs** the bootloader and the app. The signature and the public key go into a *signature block* at the end of each image.',
            '1. On the first boot, the bootloader writes the **SHA-256 of the public key** to the **eFuses** and turns Secure Boot on.',
            '1. On every boot: the **ROM** (immutable code inside the chip) checks the bootloader, and the bootloader checks the app. If anything does not match, it **does not boot**.'
          ),
          anim('iot-secure-boot', 'The root of trust is the hash in the eFuses. It cannot be changed, so it cannot be “fooled”.'),
          table(['Chip', 'Secure Boot v2', 'Algorithm', 'Keys'], [
            ['ESP32', 'Only from revision **v3.0** (ECO3) onward', 'RSA-3072 (RSA-PSS)', '1'],
            ['ESP32-S2 / S3 / C3', 'Yes', 'RSA-3072', 'Up to 3 (with the ability to revoke)'],
            ['ESP32-C6 / H2 and newer', 'Yes', 'RSA-3072 or ECDSA (P-256)', 'Up to 3'],
          ]),
          text('Check which chip and revision you have, and the state of the eFuses, **before** you change anything:'),
          code('bash', 'Identify the chip and eFuses (safe, read-only)', R`
# In ESP-IDF v5 (with the environment active: . $HOME/esp/esp-idf/export.sh)
esptool.py -p /dev/ttyUSB0 chip_id          # chip type, revision, MAC
espefuse.py -p /dev/ttyUSB0 summary         # ALL eFuses and their values
espefuse.py -p /dev/ttyUSB0 summary | grep -Ei 'secure_boot|abs_done|flash_crypt|spi_boot_crypt|jtag|download'
`, L(
            '- `chip_id`: e.g. `Chip is ESP32-D0WD-V3 (revision v3.1)`. For Secure Boot v2 on the classic ESP32 you need v3.x.',
            '- `espefuse.py summary`: read-only, changes nothing. Keep a copy of the output as your “before”.',
            '- In **esptool v5** the commands are called `esptool`, `espefuse`, `espsecure` (without `.py`) with dashes (`chip-id`). The old forms still work, with a warning.'
          )),
          EFUSE_WARN,
          code('bash', 'Enabling Secure Boot v2 in an ESP-IDF v5 project', R`
cd ~/esp/my_sensor
idf.py set-target esp32s3            # or esp32, esp32c3 …

# 1) Signing key (KEEP IT SECRET AND BACK IT UP)
espsecure.py generate_signing_key --version 2 --scheme rsa3072 secure_boot_signing_key.pem
chmod 600 secure_boot_signing_key.pem

# 2) menuconfig → Security features
#    [*] Enable hardware Secure Boot in bootloader
#        Select secure boot version → Enable Secure Boot version 2
#    [*] Sign binaries during build
#        (secure_boot_signing_key.pem) Secure boot private signing key
idf.py menuconfig

# 3) Build (the bootloader and the app get signed)
idf.py build

# 4) The bootloader is NOT written by the plain "flash" when Secure Boot is on.
idf.py -p /dev/ttyUSB0 bootloader-flash
idf.py -p /dev/ttyUSB0 flash monitor

# 5) After the first boot: verify
espefuse.py -p /dev/ttyUSB0 summary | grep -Ei 'secure_boot_en|abs_done_1|key_purpose'
`, L(
            '- `generate_signing_key --version 2 --scheme rsa3072`: creates the private key. Without it you will **never be able** to reprogram the device.',
            '- In menuconfig for the classic ESP32 you must also set *Component config → Hardware Settings → Chip revision → Minimum Supported ESP32 Revision = Rev v3.0*.',
            '- `idf.py build`: produces signed `bootloader.bin` and `app.bin`.',
            '- `bootloader-flash`: the bootloader is written separately, on purpose, so you do not overwrite it by accident.',
            '- On the **first boot** the bootloader burns the eFuses (key digest, `SECURE_BOOT_EN` or `ABS_DONE_1` on the ESP32). Do not cut the power!',
            '- From then on, every new app must be signed with **the same** key.'
          )),
          code('text', 'sdkconfig.defaults (to make the build reproducible)', R`
CONFIG_SECURE_BOOT=y
CONFIG_SECURE_BOOT_V2_ENABLED=y
CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y
CONFIG_SECURE_BOOT_SIGNING_KEY="secure_boot_signing_key.pem"
# Classic ESP32 only:
# CONFIG_ESP32_REV_MIN_3=y
# For development, BEFORE release, you can temporarily use:
# CONFIG_SECURE_BOOT_INSECURE=y   (leaves JTAG/ROM download enabled. NOT for production)
`, L(
            '- `sdkconfig.defaults` goes into Git (it has no secrets). The `.pem` does **not**.',
            '- `CONFIG_SECURE_BOOT_INSECURE`: useful during development; in production you keep the defaults, which close JTAG and other “doors”.'
          )),
          code('bash', 'Checking the signature of an image on your computer', R`
espsecure.py verify_signature --version 2 --keyfile secure_boot_signing_key.pem build/my_sensor.bin
# Signature block 0 verification successful using the supplied key (RSA).
`, L(
            '- Useful before you upload an OTA: you make sure the file is signed with the right key.'
          )),
          tip('Using the **Arduino IDE**? Secure Boot and Flash Encryption need a build with your own bootloader and sdkconfig, which the Arduino IDE does not do. Your options: **ESP-IDF** directly, **Arduino as an ESP-IDF component**, or **PlatformIO** with `framework = arduino, espidf`.'),
          quiz('Where is the “root of trust” of Secure Boot v2 stored?',
            ['In the SPI flash, in the nvs partition', 'In the chip’s eFuses, as the SHA-256 of the public key', 'In the bootloader', 'In Espressif’s cloud'], 1,
            'eFuses are bits that can be burned only once. Because they cannot change, an attacker cannot put in their own key.'),
          quiz('You lose `secure_boot_signing_key.pem` after enabling Secure Boot. What does that mean?',
            ['Nothing, you make a new one', 'You can no longer boot new firmware on this device (unless you have a second key on a chip with several slots)', 'The device turns Secure Boot off', 'You download it from Espressif'], 1,
            'Every new image must be signed with a key whose hash is in the eFuses. Without the key, the device stays on its current firmware forever.'),
        ],
      },
      {
        id: 'iot-5-2', title: 'Flash Encryption and NVS Encryption', minutes: 17,
        goal: 'Understand what **Flash Encryption** protects (and what it does not), the difference between Development and Release mode, and how to encrypt the NVS where your passwords live.',
        blocks: [
          text(
            'Secure Boot prevents foreign code from **running**. It does not stop someone from **reading** the flash and finding your passwords (we will see this in Module 6). That is why **Flash Encryption** exists:',
            '- On the first boot, the bootloader **creates a random key** inside the chip and writes it to an eFuse that **software cannot read**.',
            '- It encrypts the bootloader, the partition table, the app partitions and any partition flagged `encrypted` **in place**.',
            '- Decryption happens **transparently** in hardware when reading. Your code does not change.',
            '- Algorithm: AES-256 (ESP32) or **XTS-AES** (S2/S3/C3/C6…).'
          ),
          table(['', 'Development mode', 'Release mode'], [
            ['New firmware over USB', '✅ with `idf.py encrypted-flash`', '❌ OTA only'],
            ['Turning encryption off', 'A limited number of times (counter in an eFuse)', '❌ never'],
            ['Suitable for', 'Testing on your desk', 'Devices that leave your hands'],
          ]),
          EFUSE_WARN,
          code('text', 'partitions.csv with NVS encryption and OTA', R`
# Name,    Type, SubType,  Offset, Size,   Flags
nvs,       data, nvs,      ,       0x6000,
nvs_keys,  data, nvs_keys, ,       0x1000, encrypted
otadata,   data, ota,      ,       0x2000,
phy_init,  data, phy,      ,       0x1000,
ota_0,     app,  ota_0,    ,       1500K,
ota_1,     app,  ota_1,    ,       1500K,
`, L(
            '- The **app** partitions are always encrypted when flash encryption is on.',
            '- The **nvs** is not encrypted by the same mechanism (NVS is written often and needs a different method). That is why **NVS Encryption** exists.',
            '- `nvs_keys … encrypted`: this is where the NVS keys live, protected by flash encryption.',
            '- `ota_0`/`ota_1`: two slots for firmware, so OTA can write to one while the other is running (Lesson 5.3).',
            '- Empty offset = ESP-IDF calculates it (app partitions are aligned to 64 KB).'
          )),
          code('text', 'sdkconfig.defaults', R`
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"

CONFIG_SECURE_FLASH_ENC_ENABLED=y
CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y
# For production (ONLY when everything has been tested):
# CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y

CONFIG_NVS_ENCRYPTION=y
`, L(
            '- `SECURE_FLASH_ENC_ENABLED`: turns on at the next boot.',
            '- **Always** start with `DEVELOPMENT`. `RELEASE` permanently closes flashing over USB.',
            '- `NVS_ENCRYPTION`: the data of `Preferences`/NVS gets encrypted. On chips with an HMAC peripheral (S3, C3, C6) there is also a scheme with a key from an HMAC eFuse, without `nvs_keys`.'
          )),
          code('bash', 'First enabling and later flashes (Development mode)', R`
# First time: normal flash. The bootloader will encrypt at boot.
idf.py -p /dev/ttyUSB0 flash monitor
#   You will see: "Generating new flash encryption key..." and
#                 "Encrypting partition ..." → DO NOT CUT THE POWER (1-2 minutes)

# Check
espefuse.py -p /dev/ttyUSB0 summary | grep -Ei 'flash_crypt_cnt|spi_boot_crypt_cnt'
#   Odd number of set bits = enabled

# From here on (Development mode): ALWAYS encrypted-flash
idf.py -p /dev/ttyUSB0 encrypted-flash monitor
idf.py -p /dev/ttyUSB0 encrypted-app-flash          # app only, faster
`, L(
            '- The first boot encrypts the whole content **in place**. A power cut at that moment can leave the flash half-encrypted.',
            '- `FLASH_CRYPT_CNT` (ESP32) / `SPI_BOOT_CRYPT_CNT` (S2/S3/C3…): a counter in an eFuse. An odd number of set bits = encryption enabled.',
            '- If you later write with a plain `idf.py flash`, the bootloader will see **unencrypted** data, “decrypt” it into garbage, and the device will not boot (until you flash correctly again).'
          )),
          table(['Protects against…', 'Yes/No'], [
            ['Reading the flash with esptool or a clip on the flash chip', '✅ the attacker sees only encrypted data'],
            ['Copying the firmware to another device', '✅ the key is unique per chip'],
            ['Running foreign firmware', '❌ that is why you need Secure Boot **too**'],
            ['Bugs in your code (e.g. a buffer overflow via MQTT)', '❌ the firmware runs normally, decrypted'],
            ['Passwords you print to Serial', '❌ do not print them'],
          ]),
          tip('Rule of thumb: **Secure Boot + Flash Encryption together**, in Release mode, for every device that will end up where other people have access (garden, shed, shop, customer).'),
          quiz('You have only Flash Encryption (no Secure Boot). Which attack do you **not** stop?',
            ['Reading Wi‑Fi passwords from a flash dump', 'Running the attacker’s firmware on the device', 'Copying the firmware to another chip', 'Reading with a clip on the flash chip'], 1,
            'Flash Encryption protects **confidentiality**. For deciding which code **runs** you need Secure Boot. The two together do the job.'),
          quiz('In Development mode with flash encryption, how do you upload new firmware over USB?',
            ['`idf.py flash`', '`idf.py encrypted-flash`', '`esptool.py erase_flash`', 'You cannot'], 1,
            '`encrypted-flash` asks the ROM to encrypt the data with the chip’s key as it writes it. In Release mode even this is not allowed.'),
        ],
      },
      {
        id: 'iot-5-3', title: 'Secure OTA updates: password, HTTPS, signature, rollback', minutes: 22,
        goal: 'Set up **ArduinoOTA** with a password (and know its limits), do **HTTPS OTA** on Arduino and ESP-IDF (`esp_https_ota`), and add **signing** and **rollback**.',
        blocks: [
          text(
            'OTA lets you fix bugs and vulnerabilities without going to each device with a cable. Without OTA, a vulnerability stays forever (OWASP **I4**). An **insecure** OTA, however, is a backdoor: whoever finds it uploads their own firmware.',
            '',
            '### The 4 levels of OTA security',
            '1. **Authentication**: who is allowed to start an update? (OTA password)',
            '1. **Transport**: does the file arrive encrypted from the right server? (HTTPS + CA)',
            '1. **Integrity/Authenticity**: did **I** build this firmware? (digital signature)',
            '1. **Recovery**: if the new firmware breaks, does it go back to the old one? (rollback) And does it refuse old vulnerable versions? (anti-rollback)'
          ),
          anim('iot-ota-signed', 'From open ArduinoOTA to signed HTTPS OTA with anti-rollback.'),
          code('cpp', 'Level 1: ArduinoOTA with a password and an activation “window”', R`
#include <WiFi.h>
#include <ArduinoOTA.h>
#include "secrets.h"        // WIFI_SSID, WIFI_PASS, OTA_PASS

bool otaEnabled = false;
uint32_t otaUntil = 0;

void enableOtaFor(uint32_t ms) {
  if (!otaEnabled) {
    ArduinoOTA.setHostname("sensor01");
    ArduinoOTA.setPassword(OTA_PASS);       // ✅ without this: open to the whole LAN
    ArduinoOTA.onStart([]() { Serial.println("[OTA] start"); });
    ArduinoOTA.onEnd([]()   { Serial.println("[OTA] end"); });
    ArduinoOTA.onError([](ota_error_t e) {
      Serial.printf("[OTA] error %u%s\n", e, e == OTA_AUTH_ERROR ? " (wrong password)" : "");
    });
    ArduinoOTA.begin();
    otaEnabled = true;
  }
  otaUntil = millis() + ms;
  Serial.printf("[OTA] open for %lus\n", ms / 1000);
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(250);
  pinMode(0, INPUT_PULLUP);
}

void loop() {
  // OTA opens ONLY if you press BOOT (or via an MQTT command from an authorized user)
  if (digitalRead(0) == LOW) enableOtaFor(5UL * 60 * 1000);
  if (otaEnabled) {
    ArduinoOTA.handle();
    if ((int32_t)(millis() - otaUntil) > 0) {
      ArduinoOTA.end();
      otaEnabled = false;
      Serial.println("[OTA] closed");
    }
  }
  delay(10);
}
`, L(
            '- `setPassword(OTA_PASS)`: the Arduino IDE/`espota.py` must know the password. Authentication uses challenge-response, so the password does not travel in clear text. There is also `setPasswordHash()` so the password is not inside the firmware.',
            '- **Limits of ArduinoOTA:** the firmware travels **unencrypted** and **unsigned**, and port 3232 is announced via mDNS. It is a development tool for the LAN, not a production solution.',
            '- **5-minute window:** OTA opens only when you ask for it and closes by itself. The rest of the time 3232 is closed.',
            '- `(int32_t)(millis() - otaUntil) > 0`: a comparison that survives the `millis()` overflow after ~49 days.'
          )),
          text('### Level 2: HTTPS OTA (Arduino core)'),
          code('cpp', 'https_ota.ino: check for a new version and update over HTTPS', R`
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPUpdate.h>
#include "secrets.h"          // WIFI_SSID, WIFI_PASS, CA_CERT

#define FW_VERSION "1.4.0"
const char* OTA_URL = "https://pi-broker.local:8443/fw/sensor01.bin";

void checkForUpdate() {
  WiFiClientSecure client;
  client.setCACert(CA_CERT);            // ✅ only our own server
  httpUpdate.rebootOnUpdate(true);
  httpUpdate.onProgress([](int cur, int total) {
    Serial.printf("[OTA] %d%%\r", total ? cur * 100 / total : 0);
  });

  // Sends the x-ESP32-version header: the server answers 304 if there is nothing newer
  t_httpUpdate_return r = httpUpdate.update(client, OTA_URL, FW_VERSION);
  switch (r) {
    case HTTP_UPDATE_FAILED:
      Serial.printf("[OTA] failed (%d): %s\n", httpUpdate.getLastError(),
                    httpUpdate.getLastErrorString().c_str());
      break;
    case HTTP_UPDATE_NO_UPDATES:
      Serial.println("[OTA] no new version");
      break;
    case HTTP_UPDATE_OK:
      Serial.println("[OTA] OK, restarting");   // never reached with rebootOnUpdate(true)
      break;
  }
}

void setup() {
  Serial.begin(115200);
  Serial.printf("Firmware %s\n", FW_VERSION);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(250);
  checkForUpdate();
}

void loop() {
  static uint32_t last = 0;
  if (millis() - last > 6UL * 3600 * 1000) {   // every 6 hours
    last = millis();
    checkForUpdate();
  }
}
`, L(
            '- The **device** asks the server (pull). It does not listen on any port, so nobody can “push” an update to it.',
            '- `setCACert(CA_CERT)`: the firmware is downloaded only from a server with a certificate from your own CA.',
            '- `httpUpdate.update(client, url, version)`: writes the new image to the **inactive** OTA partition and, if all goes well, makes it active.',
            '- The Update library checks the size and the **SHA-256 digest** of the image. This detects corruption in transit, **not** who made the file. That is why we also need a signature (below).'
          )),
          code('python', 'ota_server.py: a small HTTPS server on the Pi for the .bin files', R`
#!/usr/bin/env python3
"""HTTPS server for OTA. Serves only files from /srv/ota."""
import functools
import http.server
import ssl

ROOT = "/srv/ota"
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain("/etc/mosquitto/certs/server.crt", "/etc/ota/server.key")
Handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=ROOT)
httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print("OTA server at https://0.0.0.0:8443/ from", ROOT)
httpd.serve_forever()
`, L(
            '- `PROTOCOL_TLS_SERVER` + `minimum_version`: TLS 1.2+ only.',
            '- The same `server.crt` as the broker (the SAN covers `pi-broker.local`). Keep the key in a file that **only** the service user can read.',
            '- `directory=ROOT`: it serves nothing outside `/srv/ota`.',
            '- Open the port in ufw **only** for the IoT subnet: `sudo ufw allow from 192.168.30.0/24 to any port 8443 proto tcp`.',
            '- This server does not answer 304 to the version header; for a simple “check” you can keep a `/fw/sensor01.version` file.'
          )),
          text(
            '### Levels 3 and 4: signing and rollback with ESP-IDF',
            'In ESP-IDF, if you have Secure Boot v2, every OTA image is **checked automatically** before it becomes active. If you do not want Secure Boot (yet), you can ask for **signature checking on updates only**: `CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT=y` and `CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT=y`.'
          ),
          code('cpp', 'main/ota.c: HTTPS OTA with esp_https_ota and rollback (ESP-IDF v5)', R`
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_https_ota.h"
#include "esp_http_client.h"
#include "esp_system.h"

static const char *TAG = "ota";

// Embedded with EMBED_TXTFILES ca_cert.pem in CMakeLists.txt
extern const char ca_cert_pem_start[] asm("_binary_ca_cert_pem_start");

esp_err_t do_ota(const char *url)
{
    esp_http_client_config_t http_cfg = {
        .url = url,
        .cert_pem = ca_cert_pem_start,      // ✅ CA pinning
        .timeout_ms = 15000,
        .keep_alive_enable = true,
    };
    esp_https_ota_config_t ota_cfg = {
        .http_config = &http_cfg,
    };
    ESP_LOGI(TAG, "Downloading from %s", url);
    esp_err_t err = esp_https_ota(&ota_cfg);   // download + verify + set boot partition
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "OK, restarting");
        esp_restart();
    }
    ESP_LOGE(TAG, "OTA failed: %s", esp_err_to_name(err));
    return err;
}

// Called early in app_main(): confirms that the new firmware works
void ota_confirm_or_rollback(bool self_test_ok)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;
    if (esp_ota_get_state_partition(running, &state) == ESP_OK &&
        state == ESP_OTA_IMG_PENDING_VERIFY) {
        if (self_test_ok) {
            ESP_LOGI(TAG, "New firmware OK, cancelling rollback");
            esp_ota_mark_app_valid_cancel_rollback();
        } else {
            ESP_LOGE(TAG, "Self-test failed, going back to the previous one");
            esp_ota_mark_app_invalid_rollback_and_reboot();
        }
    }
}
`, L(
            '- `extern … asm("_binary_ca_cert_pem_start")`: ESP-IDF embeds the file `ca_cert.pem` into the binary and provides this symbol. In `main/CMakeLists.txt`: `idf_component_register(SRCS "main.c" "ota.c" INCLUDE_DIRS "." EMBED_TXTFILES ca_cert.pem)`.',
            '- `.cert_pem`: the HTTP client accepts only a server with this CA.',
            '- `esp_https_ota()`: downloads, writes to the next OTA partition, **verifies** the image (and the signature if enabled) and sets it for boot.',
            '- **Rollback** (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`): the new firmware starts in the `PENDING_VERIFY` state. If it does not call `esp_ota_mark_app_valid_cancel_rollback()` (e.g. it crashed first), on the next reset the bootloader goes back to the old one.',
            '- A good self-test: “I connected to Wi‑Fi **and** to the MQTT broker within 60s”.',
            '- **Anti-rollback** (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y`): every image has a `secure_version`. The bootloader refuses an image with a lower number than the one burned into the eFuses, so nobody can “roll you back” to an old vulnerable version.'
          )),
          code('bash', 'Signing an app image by hand', R`
# If you do NOT have CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES, you sign it yourself:
espsecure.py sign_data --version 2 --keyfile secure_boot_signing_key.pem \
  --output build/my_sensor-signed.bin build/my_sensor.bin

espsecure.py verify_signature --version 2 --keyfile secure_boot_signing_key.pem \
  build/my_sensor-signed.bin

# Upload to the OTA server
scp build/my_sensor-signed.bin maria@pi-broker.local:/srv/ota/fw/sensor01.bin
`, L(
            '- `sign_data --version 2`: adds a signature block at the end of the image.',
            '- Keep the signing process on **one** computer (or an HSM). Never put the key on the OTA server.'
          )),
          warn('**Never** leave ArduinoOTA without a password on a device that stays permanently on the network. And never put the OTA server or the signing key on a machine reachable from the Internet.'),
          quiz('Is HTTPS OTA with `setCACert` and a SHA-256 digest **enough** to be sure that you built the firmware?',
            ['Yes, always', 'No: if the OTA server is compromised, the attacker uploads their own .bin with a correct digest. You need a digital signature with a key that is not on the server', 'Yes, if the .bin is small', 'No, because HTTPS does not encrypt'], 1,
            'TLS protects the **transport**, and the digest the **integrity**. Only the **signature** proves **who** made it.'),
          quiz('The new firmware crashes before connecting to Wi‑Fi. With rollback enabled, what happens?',
            ['The device stays “dead”', 'On the next reset the bootloader goes back to the previous, working firmware', 'It downloads new firmware by itself', 'It erases the flash'], 1,
            'The image was in `PENDING_VERIFY` and was never confirmed, so the bootloader rejects it.'),
          quiz('What does **anti-rollback** prevent?',
            ['The firmware crashing', 'Installing an older (possibly vulnerable) signed version', 'OTA in general', 'Wi‑Fi'], 1,
            'An attacker could upload an **old, legitimately signed** version with a known vulnerability. The `secure_version` counter in the eFuses forbids it.'),
        ],
      },
      {
        id: 'iot-5-4', title: 'JTAG, UART and debug: close the developer’s doors', minutes: 14,
        goal: 'Know which debug interfaces the ESP32 has (JTAG, USB-Serial-JTAG, UART download mode, logs) and how to close them on a production device, with menuconfig and eFuses.',
        blocks: [
          text(
            'Debug interfaces are a blessing while you write code and a curse once the device is on the wall:',
            '- **JTAG**: the debugger halts the processor and reads/writes **memory and registers**. On some chips (S3, C3, C6) there is **USB-Serial-JTAG** on the USB port itself!',
            '- **UART download mode** (ROM): with GPIO0 LOW, `esptool` reads and writes the whole flash.',
            '- **Serial logs**: `ESP_LOGI`, `Serial.print`. They often print IPs, topics, even passwords.'
          ),
          table(['Interface', 'How to close it', 'Automatically with…'], [
            ['JTAG (pins)', 'eFuse `JTAG_DISABLE` (ESP32) / `DIS_PAD_JTAG` (S2/S3/C3…)', 'Secure Boot v2 or Flash Encryption in Release mode'],
            ['USB-Serial-JTAG', 'eFuse `DIS_USB_JTAG` (S3/C3/C6…)', 'Release mode (not always everything; check the summary)'],
            ['UART download', 'menuconfig: *UART ROM download mode* → Secure mode or Permanently disabled', '—'],
            ['ROM BASIC console (ESP32)', 'eFuse `CONSOLE_DEBUG_DISABLE`', 'Secure Boot'],
            ['Logs', '`CONFIG_LOG_DEFAULT_LEVEL_WARN` / Core Debug Level: None', '—'],
          ]),
          EFUSE_WARN,
          code('bash', 'Checking and burning eFuses for debug (IRREVERSIBLE)', R`
# 1) FIRST, ALWAYS: what is already set?
espefuse.py -p /dev/ttyUSB0 summary | grep -Ei 'jtag|download|console'

# 2a) Classic ESP32: close JTAG
espefuse.py -p /dev/ttyUSB0 burn_efuse JTAG_DISABLE 1

# 2b) ESP32-S3 / C3: JTAG from the pins and from USB
espefuse.py -p /dev/ttyUSB0 burn_efuse DIS_PAD_JTAG 1
espefuse.py -p /dev/ttyUSB0 burn_efuse DIS_USB_JTAG 1

# 3) Secure Download Mode (S2/S3/C3…): the ROM accepts only basic commands
#    (no read_flash, no memory reads). esptool asks you to confirm with "BURN".
espefuse.py -p /dev/ttyUSB0 burn_efuse ENABLE_SECURITY_DOWNLOAD 1
`, L(
            '- `espefuse.py` always asks you to type `BURN` before it burns anything. Read what it says **twice**.',
            '- After `DIS_USB_JTAG` on the S3/C3, the USB port keeps working as serial (for logs), but not as JTAG.',
            '- With **Secure Download Mode**, `esptool read_flash` fails. You can still write (encrypted) firmware if your mode allows it.',
            '- For the classic ESP32 (v3+), the equivalent is `UART_DOWNLOAD_DIS`, which **closes download mode completely** (no recovery over USB afterward!).'
          )),
          code('text', 'sdkconfig.defaults for production', R`
# Fewer logs: only warnings and errors
CONFIG_LOG_DEFAULT_LEVEL_WARN=y
CONFIG_BOOTLOADER_LOG_LEVEL_WARN=y

# UART ROM download mode: permanently in Secure mode
# (Security features → UART ROM download mode; shown when you have Secure Boot or Flash Encryption)
CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE=y

# Panic: reboot instead of a GDB stub waiting for a debugger
CONFIG_ESP_SYSTEM_PANIC_PRINT_REBOOT=y
`, L(
            '- `LOG_DEFAULT_LEVEL_WARN`: the `ESP_LOGI`/`ESP_LOGD` calls are not even included in the binary.',
            '- `SECURE_ENABLE_SECURE_ROM_DL_MODE`: the bootloader burns the matching eFuse at startup (on chips that support it).',
            '- `PANIC_PRINT_REBOOT`: on a crash, it prints a backtrace and reboots. `GDBSTUB` leaves a “door” for a debugger.'
          )),
          code('cpp', 'Arduino: debug only in debug builds', R`
// Define DEBUG_BUILD only while testing (or -DDEBUG_BUILD in PlatformIO)
#ifdef DEBUG_BUILD
  #define DBG(...) Serial.printf(__VA_ARGS__)
#else
  #define DBG(...) do {} while (0)
#endif

#include "esp_log.h"

void setup() {
  Serial.begin(115200);
  esp_log_level_set("*", ESP_LOG_WARN);        // less “chatty” libraries
  DBG("[dbg] heap=%u\n", ESP.getFreeHeap());   // vanishes in release
  // Never, not even in debug: DBG("pass=%s", WIFI_PASS);
}

void loop() {}
`, L(
            '- The `DBG` macro becomes **empty** in a release build: no strings are left in the binary.',
            '- `esp_log_level_set("*", ESP_LOG_WARN)`: for the logs of the core libraries. In the Arduino IDE also set *Tools → Core Debug Level → None*.',
            '- `do {} while (0)`: the classic trick to make the macro behave like a normal statement inside `if/else`.'
          )),
          tip('On the PCB: **do not** put a UART/JTAG header on the production device, or leave them as test pads under the board. It is not security on its own, but it raises the cost for the attacker.'),
          quiz('On an ESP32-S3 you burned `DIS_PAD_JTAG`, but the attacker connects a debugger through the USB port. What did you forget?',
            ['`JTAG_DISABLE`', '`DIS_USB_JTAG`: USB-Serial-JTAG is a separate path', 'Wi‑Fi', 'Nothing, it is not possible'], 1,
            'On the S3/C3/C6 the USB peripheral has a built-in JTAG. It needs its own eFuse.'),
          quiz('Why are informational log lines (e.g. IPs, topics) a problem in production?',
            ['They slow things down a lot', 'They give information to anyone who connects a UART, and often contain secrets by mistake', 'They fill up the flash', 'It is not a problem'], 1,
            'Every log is a potential leak. In release: only WARN/ERROR, and never secrets at any level.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 6 — Hardware and physical attacks (defensive view)
  // ====================================================================
  M.push({
    id: 'iot-6', order: 6, title: 'Hardware and physical attacks (defensive view)',
    desc: 'What someone holding the device can do: UART, JTAG, a dump of the SPI flash. Why flash encryption matters and how to build tamper detection.',
    lessons: [
      {
        id: 'iot-6-1', title: 'UART, JTAG and SPI flash: read your own ESP32', minutes: 18,
        goal: 'Make a **dump** of the flash of **your own** ESP32 with `esptool`, find the secrets inside yourself (strings, partition table) with Python, and see the difference with flash encryption.',
        blocks: [
          text(
            'The best way to understand why flash encryption is needed is to see **what someone sees** without it. We will do it on **your own** ESP32, with the firmware from the previous lessons (with passwords in the NVS or in `secrets.h`).',
            '',
            'Three roads to the flash:',
            '- **UART (ROM download mode)**: GPIO0 LOW at reset, and the ROM executes `esptool` commands. You do not even need to open the device if it has USB.',
            '- **JTAG**: you halt the CPU and read memory/flash with OpenOCD.',
            '- **Directly on the SPI flash chip**: on boards with a separate flash chip (8 pins), a clip and a cheap programmer read it **without** asking the ESP32. That is why secure download mode **alone** is not enough.'
          ),
          anim('iot-uart-dump', 'Without flash encryption: passwords in plain text. With flash encryption: noise.'),
          code('bash', 'Dumping the flash (ONLY on your own device)', R`
pip install esptool

# Which chip and how much flash does it have?
esptool.py -p /dev/ttyUSB0 flash_id
#   Detected flash size: 4MB

# Read ALL of the flash (4MB = 0x400000)
esptool.py -p /dev/ttyUSB0 -b 921600 read_flash 0 0x400000 dump.bin

# Quick look: readable strings of ≥ 8 characters
strings -n 8 dump.bin | grep -iE 'ssid|pass|mqtt|wifi|BEGIN|\.local' | head -30
`, L(
            '- `flash_id`: shows the flash size. On 8MB/16MB modules change the size (`0x800000`, `0x1000000`).',
            '- `-b 921600`: faster baud rate. If you get errors, lower it to `460800`.',
            '- `read_flash 0 0x400000`: from address 0, 4MB. (esptool v5: `esptool read-flash 0 ALL dump.bin`.)',
            '- `strings -n 8`: shows runs of printable characters. Inside you will see the SSID, maybe the password, the `MQTT_HOST`, the PEM of the CA, etc.'
          )),
          code('python', 'flash_audit.py: partition table and suspicious strings', R`
#!/usr/bin/env python3
"""Defensive check of a dump of YOUR OWN ESP32: which secrets are “visible”?"""
import math
import re
import struct
import sys

data = open(sys.argv[1], "rb").read()
print(f"Dump size: {len(data) // 1024} KB")

# --- 1) Partition table at 0x8000: 32-byte entries, magic 0xAA 0x50 ---
print("\n== Partition table ==")
TYPES = {0: "app", 1: "data"}
for off in range(0x8000, 0x8000 + 0xC00, 32):
    entry = data[off:off + 32]
    if entry[:2] != b"\xaa\x50":
        break
    ptype, subtype, start, size = struct.unpack_from("<BBII", entry, 2)
    label = entry[12:28].split(b"\x00")[0].decode(errors="replace")
    flags = struct.unpack_from("<I", entry, 28)[0]
    enc = " [encrypted]" if flags & 1 else ""
    print(f"{label:<10} {TYPES.get(ptype, ptype)!s:<5} sub=0x{subtype:02x} "
          f"@0x{start:06x} {size // 1024:>5} KB{enc}")

if data[0x8000:0x8002] != b"\xaa\x50":
    print("(magic not found: the flash is most likely ENCRYPTED ✅)")

# --- 2) Strings and “suspicious” patterns ---
PATTERNS = {
    "PEM private key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "PEM certificate": re.compile(rb"-----BEGIN CERTIFICATE-----"),
    "mqtt/wifi word":  re.compile(rb"(?i)(ssid|passw|mqtt|token|apikey)"),
}
print("\n== Findings ==")
for name, rx in PATTERNS.items():
    hits = [m.start() for m in rx.finditer(data)]
    if hits:
        print(f"⚠️  {name}: {len(hits)} times (e.g. at 0x{hits[0]:06x})")


# --- 3) High-entropy strings = likely passwords/keys ---
def entropy(s: bytes) -> float:
    counts = {b: s.count(b) for b in set(s)}
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


print("\n== High-entropy strings (12-64 characters) ==")
seen = 0
for m in re.finditer(rb"[\x21-\x7e]{12,64}", data):
    s = m.group()
    if entropy(s) > 3.8 and not s.startswith(b"MII"):   # ignore the base64 of PEMs
        print(f"0x{m.start():06x}: {s.decode()}")
        seen += 1
        if seen >= 15:
            break
`, L(
            '- Run it: `python3 flash_audit.py dump.bin`.',
            '- **Partition table**: at `0x8000`, 32-byte entries that start with `AA 50`. You see where the `nvs` is (where `Preferences` live) and whether any partition has the `encrypted` flag.',
            '- `struct.unpack_from("<BBII", …)`: little-endian: type, subtype, offset, size.',
            '- If the flash is encrypted, even the `AA 50` magic is not visible: it is encrypted too.',
            '- **Shannon entropy**: how “random” a string is. Words like `temperature` have low entropy, passwords like `8f2K-vQ9x-Lm3p` have high entropy.',
            '- This is exactly what an attacker would do in 5 minutes. If your script finds your passwords, so will they.'
          )),
          tip('ESP-IDF also has a tool to read the NVS from a dump: `nvs_tool.py` (in `components/nvs_flash/nvs_partition_tool`). You will see every namespace/key of `Preferences` with its values, if it is not encrypted.'),
          text(
            '### Now compare',
            'If you have a “sacrificial” board with flash encryption (Lesson 5.2), make the same dump. `strings` finds nothing useful, the partition table is not recognized, and the script finds no PEM or passwords. That is the whole difference.'
          ),
          warn('Do the above **only on devices that belong to you**. Reading the firmware of other people’s devices may violate laws (intellectual property, unauthorized access) and license terms.'),
          quiz('Your board has Secure Download Mode but **no** flash encryption. Can someone read the passwords?',
            ['No, download mode is closed', 'Yes: with a clip directly on the SPI flash chip, they read it without going through the ESP32', 'Only with JTAG', 'Only if they have the Wi‑Fi password'], 1,
            'Secure download mode closes one door (the ROM). But the data is still in plain text on the flash chip. Only **flash encryption** protects it.'),
          quiz('`flash_audit.py` does not find the `AA 50` magic at `0x8000`. What does it most likely mean?',
            ['The dump is corrupted', 'The flash is encrypted (and so is the partition table)', 'The ESP32 has no partitions', 'The dump is from an ESP8266'], 1,
            'With flash encryption on, the partition table is encrypted too. “Garbage” at `0x8000` is a good sign.'),
        ],
      },
      {
        id: 'iot-6-2', title: 'Tamper resistance: when someone opens the box', minutes: 15,
        goal: 'Design physical protection for the ESP32 and the Raspberry Pi: a **tamper switch** that erases secrets and sends an alert, and what to do about the Pi’s SD card.',
        blocks: [
          text(
            'No device is “impossible” to compromise if someone has it in their hands for long enough. The goal is to:',
            '1. **Raise the cost** (time, tools, knowledge).',
            '1. **Detect** the compromise (tamper detection).',
            '1. **Limit the damage**: the device’s secrets should not open anything else.'
          ),
          table(['Measure', 'Cost', 'What it achieves'], [
            ['Security screws (Torx with a pin)', '€', 'Stops the casual curious person'],
            ['No UART/JTAG headers, test pads only', '€', 'Needs soldering'],
            ['Epoxy/potting over the chip and the flash', '€€', 'Hard access to the flash chip'],
            ['ESP32 with built-in flash (e.g. PICO, S3 with in-package flash)', '€€', 'No separate flash chip to clip onto'],
            ['Tamper switch → secret wipe + alert', '€', 'Detection + damage limitation'],
            ['Secure Boot + Flash Encryption (Release)', '0 (time)', 'The most important defense'],
            ['Unique credentials per device', '0', 'A stolen device ≠ a stolen home'],
          ]),
          code('cpp', 'tamper.ino: a lid switch that wipes secrets and sends an alert', R`
#include <Preferences.h>
#include <WiFi.h>
#include <PubSubClient.h>

// Microswitch/reed: lid CLOSED = pin to ground (LOW).
// Lid opens → the pull-up raises it to HIGH.
const int TAMPER_PIN = 33;
volatile bool tampered = false;

extern PubSubClient mqtt;          // from the main sketch (Lesson 4.4)

void IRAM_ATTR onTamper() {
  tampered = true;                 // ISR: just a flag, nothing heavy
}

void wipeSecrets() {
  Preferences p;
  p.begin("creds", false);
  p.clear();                       // erases all keys of the namespace
  p.end();
}

void tamperSetup() {
  pinMode(TAMPER_PIN, INPUT_PULLUP);
  if (digitalRead(TAMPER_PIN) == HIGH) tampered = true;     // already open at boot
  attachInterrupt(digitalPinToInterrupt(TAMPER_PIN), onTamper, RISING);
}

void tamperLoop() {
  if (!tampered) return;
  // 1) Alert BEFORE we wipe the credentials
  if (mqtt.connected()) {
    mqtt.publish("home/sensor01/alert", "TAMPER: the lid was opened", false);
    mqtt.loop();
    delay(300);
  }
  // 2) Wipe the secrets and restart in an “empty” state
  wipeSecrets();
  WiFi.disconnect(true, true);     // and whatever the Wi‑Fi driver has kept
  ESP.restart();
}
`, L(
            '- `INPUT_PULLUP` + switch to ground: if the switch wire is cut, the pin goes HIGH, so it “fails safe” (fail-secure).',
            '- `IRAM_ATTR`: the ISR stays in RAM and runs even while the flash is being written.',
            '- In the ISR we only set a flag. MQTT and NVS are **not** allowed inside an interrupt.',
            '- Check at **boot** too: in case the attacker opened the box while the device was off.',
            '- `Preferences::clear()`: erases the keys of the namespace. After that the device needs new provisioning.',
            '- `WiFi.disconnect(true, true)`: disconnects and deletes the credentials stored by the driver.',
            '- The alert goes **first**, so you know which device to revoke in Mosquitto (`mosquitto_passwd -D`).'
          )),
          tip('On a battery device that sleeps (deep sleep), use `esp_sleep_enable_ext0_wakeup(GPIO_NUM_33, 1)`: opening the lid **wakes** the ESP32 so it can react.'),
          text(
            '### Raspberry Pi: the SD card is an open book',
            'Anyone who pulls out the SD card and puts it in their laptop reads **everything**: the Wi‑Fi password (`/etc/NetworkManager/system-connections/`), the Mosquitto hashes, `server.key`, the SSH host keys. What you can do:'
          ),
          code('bash', 'Which secrets are on the Pi’s card?', R`
# Wi‑Fi passwords (stored by NetworkManager in plain text, root-only)
sudo grep -r '^psk=' /etc/NetworkManager/system-connections/

# Private keys on the system
sudo find / -xdev \( -name '*.key' -o -name '*.pem' -o -name 'id_*' \) \
  -not -path '/proc/*' -not -path '/usr/share/*' 2>/dev/null

# THE MOST IMPORTANT: ca.key must NOT be here
sudo find / -xdev -name 'ca.key' 2>/dev/null && echo "⚠️ move it offline!"
`, L(
            '- The files are protected by **permissions** only while Linux is running. With the card in another computer, permissions mean nothing.',
            '- `-xdev`: does not search other filesystems (e.g. USB, network).',
            '- If you find `ca.key` or `secure_boot_signing_key.pem` on the Pi: **move them** to offline media and delete them from there (`shred -u`).'
          )),
          text(
            '**Measures for the Pi:**',
            '- Put the Pi in a **locked** room/box. A case with security screws hides the SD card.',
            '- Keep **only** the secrets the Pi needs (server key yes, CA key **no**).',
            '- The Pi 4/5 can boot from a **USB SSD**, which goes inside the box.',
            '- For sensitive data: partition encryption with **LUKS** (needs unlocking on every boot, so it does not suit every scenario).',
            '- The **Compute Module 4/5** and the Pi 5 support **signed boot** via EEPROM (an advanced topic, with its own irreversible OTP bits).'
          ),
          quiz('Why is the tamper switch wired so that a **closed** lid gives LOW?',
            ['Only for lower power use', 'If the wire is cut, the pull-up gives HIGH and the device sees it as tampering (fail-secure)', 'Because the ESP32 cannot read HIGH', 'It does not matter'], 1,
            'An attacker who cuts the switch wire would **trigger** the detection instead of bypassing it.'),
          quiz('Which file should **not** be on the Raspberry Pi that acts as the broker?',
            ['`/etc/mosquitto/certs/server.key`', '`ca.key` of your own CA', '`/etc/mosquitto/passwd`', '`/etc/mosquitto/certs/ca.crt`'], 1,
            '`ca.key` signs certificates that **all** your devices trust. If it is stolen along with the Pi, the thief can create “legitimate” fake brokers.'),
        ],
      },
    ],
  });

  // ====================================================================
  // MODULE 7 — Network segmentation for IoT
  // ====================================================================
  M.push({
    id: 'iot-7', order: 7, title: 'Network segmentation: IoT on its own network',
    desc: 'A separate VLAN/SSID for IoT, firewall rules, the Raspberry Pi as an IoT gateway with nftables/ufw, and the risks of mDNS and UPnP.',
    lessons: [
      {
        id: 'iot-7-1', title: 'Why segmentation: VLANs and a separate SSID', minutes: 15,
        goal: 'Understand how a separate network for IoT **limits the damage** when a device is compromised, and write “who talks to whom” rules.',
        blocks: [
          text(
            'On a “flat” home network, everything sees everything: the cheap camera from the Internet is on the same network as the laptop where you do your online banking and the NAS with your photos. If the camera is compromised, the attacker has a **stepping stone** to the whole house (*lateral movement*).',
            '',
            '**Segmentation** means splitting the network into zones of different trust, with a **firewall** in between that allows only what is needed.'
          ),
          anim('iot-vlan-segmentation', 'The compromised camera reaches neither the laptop nor the NAS. The ESP32 reaches only the broker.'),
          table(['Zone', 'Example', 'Subnet', 'Trust'], [
            ['**LAN** (VLAN 10)', 'Laptops, phones, NAS', '192.168.1.0/24', 'High'],
            ['**IoT** (VLAN 30)', 'ESP32, cameras, smart plugs', '192.168.30.0/24', 'Low'],
            ['**Guest** (VLAN 40)', 'Visitors', '192.168.40.0/24', 'None'],
          ]),
          text(
            '### The rules (policy)',
            'Before you touch any settings, write on paper **who needs to talk to whom**:',
            '- **LAN → IoT**: ✅ (you view the camera, you send commands to the broker).',
            '- **IoT → LAN**: ❌ except to the **broker:8883** (if the broker is on the LAN).',
            '- **IoT → Internet**: only what is needed (NTP, OTA server). Ideally nothing else.',
            '- **IoT → IoT**: ❌ if possible (client isolation on the AP). ESP32s do not need to talk to each other, they talk to the broker.',
            '- **IoT → router**: only DHCP (67/udp) and DNS (53).'
          ),
          text(
            '### Option 1: the router’s “Guest network” (the easiest)',
            'Many home routers have a guest Wi‑Fi with **isolation** from the main network. It is not a full VLAN, but it is a huge improvement. The catch: the ESP32s will not see the broker on the LAN. Solutions: put the Pi on the guest network too, or use the Pi as a gateway (next lesson).',
            '',
            '### Option 2: A router with VLANs (e.g. OpenWrt)'
          ),
          code('text', 'OpenWrt: /etc/config/network (excerpt, DSA switch)', R`
config bridge-vlan
        option device 'br-lan'
        option vlan '10'
        list ports 'lan1:u*'
        list ports 'lan2:u*'

config bridge-vlan
        option device 'br-lan'
        option vlan '30'
        list ports 'lan3:u*'

config interface 'lan'
        option device 'br-lan.10'
        option proto 'static'
        option ipaddr '192.168.1.1'
        option netmask '255.255.255.0'

config interface 'iot'
        option device 'br-lan.30'
        option proto 'static'
        option ipaddr '192.168.30.1'
        option netmask '255.255.255.0'
`, L(
            '- `bridge-vlan`: which switch ports belong to which VLAN. `u*` = untagged and the port’s primary VLAN (PVID).',
            '- `lan3` goes to VLAN 30: that is where you connect e.g. a second AP just for IoT, or the Pi broker.',
            '- `interface \'iot\'`: a new L3 network `192.168.30.0/24` with the router at `.1`. It also needs a `dhcp` section to hand out addresses.'
          )),
          code('text', 'OpenWrt: /etc/config/wireless and /etc/config/firewall (excerpt)', R`
# --- Separate SSID for IoT, WPA2/WPA3 mixed, PMF, client isolation ---
config wifi-iface 'iot_ap'
        option device 'radio0'          # 2.4 GHz (the ESP32 has no 5 GHz)
        option mode 'ap'
        option network 'iot'
        option ssid 'IoT-Net'
        option encryption 'sae-mixed'
        option key 'ONE-LONG-RANDOM-PASSWORD'
        option ieee80211w '1'
        option isolate '1'

# --- Firewall zone for IoT: nothing unless explicitly allowed ---
config zone
        option name 'iot'
        list network 'iot'
        option input 'REJECT'
        option output 'ACCEPT'
        option forward 'REJECT'

# LAN → IoT is allowed (stateful: replies come back)
config forwarding
        option src 'lan'
        option dest 'iot'

config rule
        option name 'IoT-DHCP-DNS'
        option src 'iot'
        option proto 'tcp udp'
        option dest_port '53 67'
        option target 'ACCEPT'

config rule
        option name 'IoT-to-broker'
        option src 'iot'
        option dest 'lan'
        option dest_ip '192.168.1.50'
        option proto 'tcp'
        option dest_port '8883'
        option target 'ACCEPT'

config rule
        option name 'IoT-NTP'
        option src 'iot'
        option dest 'wan'
        option proto 'udp'
        option dest_port '123'
        option target 'ACCEPT'
`, L(
            '- `encryption \'sae-mixed\'`: WPA2-PSK + WPA3-SAE. `ieee80211w \'1\'`: PMF optional (protection from deauth for those that support it).',
            '- `isolate \'1\'`: the Wi‑Fi clients of the IoT network cannot see each other. An infected device does not scan the others.',
            '- `zone iot`: `input REJECT` (it does not talk to the router except for explicit rules), `forward REJECT` (it goes nowhere except for explicit rules).',
            '- `forwarding lan → iot`: the LAN opens connections to IoT. The reverse does **not** hold.',
            '- `IoT-to-broker`: the **only** hole from IoT to the LAN: TCP 8883 to the Pi.',
            '- Without an `iot → wan` rule for other ports, the devices do not “phone home” to unknown clouds.',
            '- To apply: `uci commit && service network reload && service firewall reload`.'
          )),
          nw('devs', 'After segmentation, the **📟 Devices** tab of NetWatch (on your laptop) should no longer see any IoT device in the same broadcast domain.'),
          tip('No router with VLANs? A **Raspberry Pi with a second Wi‑Fi** can be both the IoT network and the firewall. That is what we do in the next lesson.'),
          quiz('A camera on the IoT VLAN is compromised. With the rules above, what **can** it do?',
            ['Scan the laptop on the LAN', 'Connect only to 192.168.1.50:8883 (and need a valid user/pass + ACL there)', 'Get into the NAS', 'Open a port to the Internet through the router'], 1,
            'The only hole is the broker, which is protected with TLS, a per-device password and an ACL. The damage stays **limited**.'),
          quiz('Why is `isolate` (client isolation) useful on the IoT SSID?',
            ['It increases speed', 'IoT devices cannot attack each other inside the same network', 'It encrypts the traffic', 'It hides the SSID'], 1,
            'The firewall controls traffic **between** networks. Inside the same Wi‑Fi, only client isolation stops device-to-device traffic.'),
        ],
      },
      {
        id: 'iot-7-2', title: 'The Raspberry Pi as an IoT gateway (nftables / ufw)', minutes: 20,
        goal: 'Turn a Pi into an **access point for IoT** (NetworkManager) and a firewall between IoT and your home, with **nftables** or with **ufw route** rules.',
        blocks: [
          text(
            'The topology:',
            '- `eth0` → cable to the home router (LAN and Internet).',
            '- `wlan0` → a **new Wi‑Fi “IoT-Net”** just for ESP32s (10.42.0.0/24).',
            '- The Pi does DHCP, NAT, runs Mosquitto, and **filters** whatever goes from IoT to the home.',
            '',
            'The ESP32s see only the Pi. And as a bonus, everything they send passes through the Pi, so you can monitor it (Lesson 8).'
          ),
          code('bash', 'Step 1: access point with NetworkManager (Raspberry Pi OS Bookworm)', R`
sudo nmcli con add type wifi ifname wlan0 con-name IoT-AP autoconnect yes ssid IoT-Net \
  802-11-wireless.mode ap 802-11-wireless.band bg 802-11-wireless.channel 6 \
  ipv4.method shared ipv4.addresses 10.42.0.1/24 ipv6.method disabled \
  wifi-sec.key-mgmt wpa-psk wifi-sec.proto rsn wifi-sec.pairwise ccmp wifi-sec.group ccmp \
  wifi-sec.psk 'ONE-LONG-RANDOM-PASSWORD-24+'

sudo nmcli con up IoT-AP
nmcli -f GENERAL.STATE,IP4.ADDRESS dev show wlan0

# Which devices got an IP?
cat /var/lib/NetworkManager/dnsmasq-wlan0.leases
`, L(
            '- `mode ap`: the Pi becomes an access point. `band bg` + channel 6: 2.4 GHz, where the ESP32 talks.',
            '- `ipv4.method shared`: NetworkManager automatically starts **dnsmasq** (DHCP/DNS) for wlan0, turns on **IP forwarding** and **NAT** toward eth0.',
            '- `proto rsn` + `ccmp`: **WPA2-AES only**, not the old WPA/TKIP.',
            '- The Pi’s Wi‑Fi in AP mode usually does **not** support WPA3-SAE, so use WPA2 with a very long password.',
            '- Add `IP:10.42.0.1` to the SAN of the broker’s `server.crt`, since the ESP32s will connect there (Lesson 4.3).'
          )),
          text('### Step 2a: firewall with nftables'),
          code('text', '/etc/nftables.conf', R`
#!/usr/sbin/nft -f
# Pi as an IoT gateway. eth0 = home/Internet, wlan0 = IoT (10.42.0.0/24)
# We do NOT do "flush ruleset": that keeps NetworkManager's NAT tables.

table inet iotfw
delete table inet iotfw

table inet iotfw {
    set private_nets {
        type ipv4_addr; flags interval
        elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }
    }

    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop
        iif "lo" accept
        meta l4proto { icmp, ipv6-icmp } accept

        # From the home: SSH and MQTT/TLS
        iifname "eth0" tcp dport { 22, 8883 } accept

        # From IoT: DHCP, DNS and the broker. NOTHING else (e.g. no SSH!)
        iifname "wlan0" udp dport { 53, 67 } accept
        iifname "wlan0" tcp dport { 53, 8883 } accept

        log prefix "nft-in-drop " limit rate 10/minute
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop

        # IoT → home (private IPs): NEVER
        iifname "wlan0" oifname "eth0" ip daddr @private_nets log prefix "iot-to-lan " drop

        # IoT → Internet: only NTP (and HTTPS if you do OTA from an external server)
        iifname "wlan0" oifname "eth0" udp dport 123 accept
        # iifname "wlan0" oifname "eth0" tcp dport 443 accept

        # Home → IoT: allowed (e.g. for debugging from the laptop)
        iifname "eth0" oifname "wlan0" accept

        log prefix "nft-fwd-drop " limit rate 10/minute
    }
}
`, L(
            '- `table inet`: one table for IPv4 **and** IPv6.',
            '- `table … / delete table … / table … { }`: a trick so the file can be reloaded without errors, deleting **only** our own table.',
            '- `policy drop`: whatever is not explicitly allowed is dropped.',
            '- `ct state established,related accept`: stateful. Replies to connections we allowed go through.',
            '- `meta l4proto { icmp, ipv6-icmp }`: ping and ICMPv6 (without ICMPv6, IPv6 does not work properly).',
            '- **Input from wlan0:** only DHCP, DNS, 8883. An infected device cannot even try SSH on the Pi.',
            '- `set private_nets`: all private addresses. IoT reaches **no** machine in the home, not even the router.',
            '- NAT (masquerade) is already done by NetworkManager (`ipv4.method shared`). In nftables, a packet must be accepted by **all** base chains of the hook, so our `drop` applies whatever NM allows.',
            '- `log … limit rate`: logs the drops without filling up the journal.'
          )),
          code('bash', 'Applying and checking', R`
sudo nft -c -f /etc/nftables.conf          # syntax check (dry run)
sudo nft -f /etc/nftables.conf
sudo systemctl enable nftables             # load at every boot
sudo nft list table inet iotfw

# What gets dropped? (live)
sudo journalctl -kf | grep -E 'iot-to-lan|nft-'
`, L(
            '- `nft -c`: check mode, changes nothing.',
            '- Debian’s `nftables.service` loads `/etc/nftables.conf` at boot.',
            '- From an ESP32 on IoT-Net, try opening a connection to your laptop: you will see an `iot-to-lan` line in the journal.'
          )),
          warn('**Pick ONE firewall tool.** If you have **ufw** active (Lesson 2.4) **and** your own nftables ruleset, both apply: a packet passes only if **all** of them allow it. This is very confusing when debugging. If you prefer ufw, use option 2b.'),
          text('### Step 2b: the same with ufw (if you already use it)'),
          code('bash', 'ufw: rules for the IoT interface', R`
# Input from IoT: only DHCP, DNS, broker
sudo ufw allow in on wlan0 to any port 67 proto udp comment 'IoT DHCP'
sudo ufw allow in on wlan0 to any port 53 comment 'IoT DNS'
sudo ufw allow in on wlan0 to any port 8883 proto tcp comment 'IoT MQTT TLS'

# Forward: ufw's default policy for routed traffic is DROP (/etc/default/ufw)
# We allow ONLY NTP outward
sudo ufw route allow in on wlan0 out on eth0 to any port 123 proto udp comment 'IoT NTP'

sudo ufw reload
sudo ufw status verbose          # look for: "Default: deny (incoming), allow (outgoing), deny (routed)"
`, L(
            '- `allow in on wlan0`: a rule only for traffic arriving from the IoT interface.',
            '- `ufw route`: rules for traffic that **passes through** the Pi (forward), not for the Pi itself.',
            '- With `DEFAULT_FORWARD_POLICY="DROP"`, whatever is not allowed with `route allow` is dropped, so IoT → LAN too.'
          )),
          cli('Lab: the Pi becomes an IoT gateway', 'maria@raspberrypi:~ $', 'Raspberry Pi OS Bookworm (simulation). eth0 = home, wlan0 = free.', [
            { task: 'Activate the `IoT-AP` connection (it has already been created with `nmcli con add`).', expect: '^sudo\\s+nmcli\\s+(con|connection)\\s+up\\s+IoT-AP$', ans: 'sudo nmcli con up IoT-AP', out: 'Connection successfully activated (D-Bus active path: /org/freedesktop/NetworkManager/ActiveConnection/5)' },
            { task: 'Check the syntax of `/etc/nftables.conf` without applying it.', expect: '^sudo\\s+nft\\s+-c\\s+-f\\s+/etc/nftables\\.conf$', ans: 'sudo nft -c -f /etc/nftables.conf', out: '' },
            { task: 'Load the rules.', expect: '^sudo\\s+nft\\s+-f\\s+/etc/nftables\\.conf$', ans: 'sudo nft -f /etc/nftables.conf', out: '' },
            { task: 'Enable the `nftables` service for every boot.', expect: '^sudo\\s+systemctl\\s+enable\\s+(--now\\s+)?nftables(\\.service)?$', ans: 'sudo systemctl enable nftables', out: 'Created symlink /etc/systemd/system/sysinit.target.wants/nftables.service → /lib/systemd/system/nftables.service.' },
            { task: 'View the `inet iotfw` table.', expect: '^sudo\\s+nft\\s+list\\s+table\\s+inet\\s+iotfw$', ans: 'sudo nft list table inet iotfw', out: 'table inet iotfw {\n  chain input { type filter hook input priority filter; policy drop; ... }\n  chain forward { type filter hook forward priority filter; policy drop; ... }\n}' },
            { task: 'See which IoT devices got an IP (the leases file of NM’s dnsmasq for wlan0).', expect: '^(sudo\\s+)?cat\\s+/var/lib/NetworkManager/dnsmasq-wlan0\\.leases$', ans: 'cat /var/lib/NetworkManager/dnsmasq-wlan0.leases', out: '1763400000 24:6f:28:aa:bb:cc 10.42.0.23 sensor01 01:24:6f:28:aa:bb:cc' },
          ], 'The Pi is now AP + DHCP + firewall + broker for your ESP32s.'),
          quiz('Why do we not put `flush ruleset` at the start of `/etc/nftables.conf` in this setup?',
            ['Because it is slow', 'Because it would also delete the NAT tables that NetworkManager created for the shared connection', 'Because it is forbidden on the Pi', 'Because it deletes the logs'], 1,
            '`flush ruleset` deletes **all** tables. We delete only our own (`delete table inet iotfw`).'),
          quiz('A compromised ESP32 on IoT-Net tries `ssh 10.42.0.1`. What happens?',
            ['It asks for a password', 'It is dropped in the input chain: from wlan0 only 53, 67 and 8883 are allowed', 'It goes through because it is the gateway', 'It goes through because it is a private IP'], 1,
            'The SSH rule applies only to `eth0`. From IoT the Pi exposes only the 3 services the devices need.'),
        ],
      },
      {
        id: 'iot-7-3', title: 'mDNS, UPnP and other “helpful” risks', minutes: 14,
        goal: 'See what your devices **announce** on the network (mDNS, SSDP), check whether your router opens ports by itself with **UPnP**, and shut them down.',
        blocks: [
          text(
            '“Zero configuration” protocols make life easy. For the attacker too:',
            '- **mDNS / DNS-SD** (`.local`, port 5353/udp): every device shouts “I am `sensor01`, I have OTA on 3232, web on 80”. A free map of your network.',
            '- **SSDP / UPnP** (1900/udp): devices describe themselves (model, firmware version) and, worse, ask the router to **open ports to the Internet** (UPnP IGD) without asking you.',
            '',
            'Many cameras were “found” on Shodan exactly this way: they opened port forwarding by themselves with UPnP.'
          ),
          code('bash', 'What is announced on your network (mDNS)', R`
sudo apt install -y avahi-utils
# All services, resolved to IP/port, and exit when done
avahi-browse -art | grep -E '^=|hostname|address|port|txt' | head -60

# ArduinoOTA devices only
avahi-browse -rt _arduino._tcp
`, L(
            '- `-a` all service types, `-r` resolve (IP/port), `-t` terminate after the initial scan.',
            '- `_arduino._tcp`: this is how ArduinoOTA advertises that it accepts firmware. The TXT record also shows whether it wants a password (`auth_upload=yes`).',
            '- On the ESP32 you can turn it off: `ArduinoOTA.setMdnsEnabled(false);` before `begin()`. The Arduino IDE then will not find the device automatically, but you give the IP by hand.'
          )),
          code('python', 'ssdp_scan.py: who answers UPnP discovery (on YOUR OWN LAN)', R`
#!/usr/bin/env python3
import socket

MSG = "\r\n".join([
    "M-SEARCH * HTTP/1.1",
    "HOST: 239.255.255.250:1900",
    'MAN: "ssdp:discover"',
    "MX: 2",
    "ST: ssdp:all",
    "", ""]).encode()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
s.settimeout(4)
s.sendto(MSG, ("239.255.255.250", 1900))

found = {}
try:
    while True:
        data, (ip, _) = s.recvfrom(65507)
        headers = {}
        for line in data.decode(errors="replace").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().upper()] = v.strip()
        found.setdefault(ip, set()).add((headers.get("SERVER", "?"), headers.get("ST", "?")))
except socket.timeout:
    pass

for ip, items in sorted(found.items()):
    print(f"\n{ip}")
    for server, st in sorted(items):
        flag = "🔴 UPnP IGD (a router that opens ports!)" if "InternetGatewayDevice" in st else ""
        print(f"   {st[:60]:<60} {server[:40]} {flag}")
`, L(
            '- **SSDP** sends an HTTP-like `M-SEARCH` message to the multicast address `239.255.255.250:1900`.',
            '- `ST: ssdp:all`: “everyone who speaks UPnP, answer”.',
            '- The `SERVER` header often reveals the **operating system and version** (e.g. `Linux/3.10 UPnP/1.0 …`): useful to know what needs updating.',
            '- If your router answers as `InternetGatewayDevice`, it has **UPnP IGD enabled**: any device on the LAN can ask it for port forwarding.'
          )),
          code('bash', 'Which ports has UPnP already opened on your router?', R`
sudo apt install -y miniupnpc
upnpc -l
# If you see lines like:  TCP  8080->192.168.1.77:80  'IPCam'
# a camera has opened a port to the Internet by itself!
`, L(
            '- `upnpc -l`: asks the router (IGD) for the active port mappings.',
            '- Every line is a port of your home **open to the Internet**.',
            '- **Fix:** turn off UPnP in the router settings and set up port forwarding by hand only for what you really need (ideally: nothing, and a VPN for remote access).'
          )),
          table(['Protocol', 'Port', 'Risk', 'What you do'], [
            ['mDNS', '5353/udp', 'Reveals services, spoofing of `.local` names', 'Turn off on devices that do not need it, do not “bridge” it between VLANs'],
            ['SSDP/UPnP', '1900/udp', 'Reveals models/versions', 'Disable on the devices if possible'],
            ['UPnP IGD', 'router', 'Automatic port forwarding', '**Disable on the router**'],
            ['LLMNR/NetBIOS', '5355, 137', 'Name poisoning (mostly Windows)', 'Disable'],
          ]),
          warn('Do not enable an **mDNS reflector** (e.g. `enable-reflector=yes` in avahi, or an “mDNS repeater” on the router) between the LAN and IoT without a serious reason. It joins the networks again at the service-discovery level and cancels part of the segmentation.'),
          nw('devs', 'The NetWatch **devices** list shows which devices are on the network and their manufacturer from the MAC. Compare it with what `avahi-browse` found.'),
          nw('priv', 'In the **🕵 Anonymity** tab see your public IP. Then try Shodan (Pentest tab) to make sure that **no** IoT port is visible on the Internet.'),
          quiz('`upnpc -l` shows `TCP 554->192.168.1.77:554 \'IPCam\'`. What does it mean?',
            ['The camera is offline', 'The camera opened the RTSP port to the Internet by itself, via UPnP: anyone who finds your IP can view (or try to view) its stream', 'It is normal and safe', 'The camera uses a VPN'], 1,
            'This is exactly what botnets exploit. Turn off UPnP on the router and delete the mapping.'),
          quiz('How do you stop an ESP32 with ArduinoOTA from advertising the OTA service via mDNS?',
            ['`WiFi.setHostname("")`', '`ArduinoOTA.setMdnsEnabled(false)` before `begin()`', 'You cannot', 'With `setMinSecurity`'], 1,
            'Without mDNS the service does not “shout” on the network. Combine it with an OTA password and an activation window (Lesson 5.3).'),
        ],
      },
    ],
  });

  ACADEMY.track({ id: 'iot', order: 2, title: '🔌 IoT Security: ESP32 & Raspberry Pi', level: 'Beginner → Advanced', desc: 'Secure your own ESP32 and Raspberry Pi projects step by step, with code that runs: hardening, MQTT with TLS, Secure Boot, segmentation, monitoring and a final project.', modules: M });
})();
