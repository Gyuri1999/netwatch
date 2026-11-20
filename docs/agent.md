# NetWatch agent σε Proxmox / Raspberry Pi

Από τον Mac, το NetWatch βλέπει μόνο τη **δική του** κίνηση και ό,τι εκπέμπεται σε όλους (ARP, mDNS, DHCP). Η κίνηση
ESP32 → broker ή κάμερα → cloud δεν περνάει από τον Mac. Για να τη δει, το NetWatch πρέπει να τρέχει σε σημείο από το οποίο περνάει
αυτή η κίνηση. Αυτό είναι η **λειτουργία agent**.

```
 ESP32 ─┐                      ┌──────────── Proxmox ─────────────┐
 κάμερα ─┼── switch (mirror) ──┼─▶ vmbr1 ──▶ LXC/VM «netwatch»     │
 κινητό ─┘        │            │             (--agent, HTTPS:8765) │
                 router         └──────────────────────────────────┘
                                         ▲
             Mac / κινητό ── https://<agent>:8765 ──┘
```

## 1. Στήσιμο (LXC ή VM με Debian/Ubuntu)

```bash
apt install -y git docker.io docker-compose-v2
git clone <το repo σου> netwatch && cd netwatch
cp config.example.yaml config.yaml      # βάλε εδώ mqtt_guard, notify.ntfy κ.λπ.
docker compose up -d --build
docker compose logs | grep -A1 "agent"  # δείχνει το URL με το token και το fingerprint
```

Χωρίς Docker:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
sudo .venv/bin/python netwatch.py --agent -i eth1
```

Σε **LXC** η καταγραφή πακέτων θέλει container privileged ή, σε unprivileged, `lxc.cap.keep`/`features: nesting=1` και
πρόσβαση στη συσκευή δικτύου. Σε VM δουλεύει χωρίς πρόσθετες ρυθμίσεις.

## 2. Άνοιγμα από τον Mac

1. Άνοιξε `https://<IP του agent>:8765/?token=…`. Το token το τυπώνει ο agent στην εκκίνηση, και υπάρχει και στο `data/agent-token`.
2. Ο browser θα προειδοποιήσει για το πιστοποιητικό, γιατί είναι self-signed. **Σύγκρινε το SHA-256 fingerprint** με αυτό που
   τύπωσε ο agent. Αν ταιριάζει, συνέχισε.
3. Ο browser κρατάει το token σε cookie (HttpOnly, Secure, SameSite=Strict) για 30 μέρες.

Ασφάλεια στη λειτουργία agent:

- **HTTPS και token:** όλη η επικοινωνία είναι κρυπτογραφημένη, και κάθε αίτημα θέλει το token.
- **Προστασία από CSRF:** τα POST γίνονται δεκτά μόνο από την ίδια τη σελίδα του agent (`Origin == Host`).
- **Απενεργοποιημένες λειτουργίες:** το τερματικό της Ακαδημίας και το «κλείσιμο» δεν δουλεύουν, γιατί θα έτρεχαν στον server.
- **Πρόσβαση από έξω:** μην ανοίξεις ποτέ τη θύρα 8765 προς το Internet. Για πρόσβαση από έξω, χρησιμοποίησε VPN (WireGuard ή Tailscale)
  ή onion service με client authorization (μάθημα στην Ακαδημία: IoT → «Πρόσβαση από έξω χωρίς port forwarding»).

### Από το κινητό (Android)

Εγκατέστησε το [`NetWatch-android.apk`](https://github.com/Gyuri1999/netwatch/releases/latest/download/NetWatch-android.apk)
(Android 10 ή νεότερο· «Εγκατάσταση από άγνωστες πηγές» μία φορά). Στην πρώτη εκκίνηση:

1. Επικόλλησε όλο τον σύνδεσμο `https://<IP>:8765/?token=…` που τύπωσε ο agent.
2. Η εφαρμογή δείχνει το SHA-256 fingerprint του πιστοποιητικού. **Σύγκρινέ το** με αυτό που τύπωσε ο agent και πάτα «Ταιριάζει».
3. Από εκεί και πέρα η εφαρμογή δέχεται **μόνο** αυτό το πιστοποιητικό (pinning). Αν αλλάξει, η σύνδεση κόβεται πριν σταλεί το token.

Κάθε 15 λεπτά, όσο το κινητό είναι στο ίδιο δίκτυο, ελέγχει για νέες σοβαρές ειδοποιήσεις και τις δείχνει ως ειδοποιήσεις
του Android. Έξω από το σπίτι δουλεύει μέσα από το ίδιο VPN (WireGuard/Tailscale) που θα χρησιμοποιούσες για τον browser.

## 3. Πώς φτάνει η κίνηση στον agent: port mirroring

Ο agent βλέπει **μόνο** ό,τι φτάνει στην κάρτα δικτύου του. Υπάρχουν τρεις επιλογές, από την καλύτερη προς τη χειρότερη:

| Τρόπος | Τι βλέπεις | Τι χρειάζεσαι |
|---|---|---|
| **Managed switch με SPAN/mirror** της θύρας του router προς μια δεύτερη κάρτα του Proxmox | **Όλη** την κίνηση του σπιτιού προς και από το Internet, και ό,τι περνάει από το switch | switch με port mirroring (π.χ. TP-Link TL-SG105E/108E) |
| **Mirror μέσα στο Proxmox** (`tc mirred`) από τη φυσική κάρτα προς το tap του agent | Ό,τι περνάει από την κάρτα του Proxmox (τα VM/LXC σου, π.χ. ο broker στο .17) | τίποτα επιπλέον |
| **Bridge σε λειτουργία hub** (`bridge-ageing 0`) | Την κίνηση μεταξύ των VM στο ίδιο bridge | τίποτα (αλλά επιβαρύνει λίγο την απόδοση) |

### Managed switch

1. Στη σελίδα του switch: Port Mirroring → **mirrored port** = η θύρα του router (ingress και egress), **mirroring port** = η θύρα όπου
   συνδέεις τη δεύτερη κάρτα του Proxmox.
2. Στο Proxmox, φτιάξε ένα bridge **χωρίς IP** πάνω στη δεύτερη κάρτα:
   ```
   auto vmbr1
   iface vmbr1 inet manual
       bridge-ports enp2s0
       bridge-stp off
       bridge-fd 0
       bridge-ageing 0
   ```
3. Δώσε στο VM του agent μια δεύτερη κάρτα στο `vmbr1`, και τρέξε τον agent με `-i <αυτή η κάρτα>`.

### Mirror μέσα στο Proxmox (`tc`)

Στον host του Proxmox, όπου `enp1s0` είναι η φυσική κάρτα και `tap105i1` η δεύτερη κάρτα του VM 105:

```bash
tc qdisc add dev enp1s0 handle ffff: ingress
tc filter add dev enp1s0 parent ffff: matchall action mirred egress mirror dev tap105i1
tc qdisc add dev enp1s0 handle 1: root prio
tc filter add dev enp1s0 parent 1: matchall action mirred egress mirror dev tap105i1
```

Οι κανόνες `tc` χάνονται στο reboot ή όταν ξαναξεκινήσει το VM. Βάλ' τους σε hookscript του Proxmox (`post-start`).

## 4. Τι κερδίζεις

Με τον agent και τον MQTT broker στο ίδιο δίκτυο:

- **«Κωδικός σε καθαρό κείμενο (MQTT)»:** βλέπεις τον κωδικό MQTT των ESP32 σου να περνάει ανοιχτά στο 1883. Είναι η καλύτερη απόδειξη ότι χρειάζεσαι TLS.
- **«Tor από συσκευή του δικτύου»:** αν κάποιο IoT αρχίσει να μιλάει με το δίκτυο Tor, το βλέπεις αμέσως.
- **Ανιχνευτές για όλο το σπίτι:** beaconing, DGA και κακόβουλες IP ελέγχονται για όλες τις συσκευές, όχι μόνο για τον Mac.
