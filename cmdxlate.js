// 🔀 Μεταφραστής εντολών: η ίδια δουλειά σε Cisco IOS · NX-OS · MikroTik (RouterOS v7) · Junos · Linux · Windows.
// Cheat-sheet για CCNA / καθημερινή δουλειά. Καθαρά frontend: καμία κλήση δικτύου, καμία εξωτερική βιβλιοθήκη.
// Τα κείμενα έχουν ήδη el/en μέσα στα δεδομένα· όλο το δέντρο σημαδεύεται data-noi18n.
(() => {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const EN = () => !!(window.I18N && I18N.lang === 'en');
  const T = (el, en) => (EN() ? en : el);
  const curTab = () => (typeof tab !== 'undefined' ? tab : null);

  const VEND = [
    { k: 'ios', n: 'Cisco IOS', s: 'IOS' },
    { k: 'nxos', n: 'NX-OS', s: 'NX-OS' },
    { k: 'mikrotik', n: 'MikroTik v7', s: 'MikroTik' },
    { k: 'junos', n: 'Junos', s: 'Junos' },
    { k: 'linux', n: 'Linux', s: 'Linux' },
    { k: 'windows', n: 'Windows', s: 'Windows' },
  ];
  const VK = VEND.map(v => v.k);

  const CATS = [
    { id: 'ip', el: 'Interfaces & IP', en: 'Interfaces & IP', tip_el: 'Στο IOS το «up/down» σημαίνει Layer 1 ok αλλά Layer 2 (protocol) όχι· το «administratively down» θέλει no shutdown.', tip_en: 'On IOS "up/down" means Layer 1 is fine but the Layer 2 protocol is not; "administratively down" needs no shutdown.' },
    { id: 'route', el: 'Δρομολόγηση', en: 'Routing', tip_el: 'Longest prefix match πρώτα, μετά administrative distance (connected 0, static 1, OSPF 110), μετά metric.', tip_en: 'Longest prefix match first, then administrative distance (connected 0, static 1, OSPF 110), then metric.' },
    { id: 'vlan', el: 'VLAN & trunk', en: 'VLAN & trunk', tip_el: 'Η native VLAN πρέπει να ταιριάζει στις δύο άκρες του trunk· βάλε μια αχρησιμοποίητη (π.χ. 99) αντί για 1.', tip_en: 'The native VLAN must match on both ends of a trunk; use an unused one (e.g. 99) instead of 1.' },
    { id: 'sw', el: 'Switching / MAC & ARP', en: 'Switching / MAC & ARP', tip_el: 'MAC table = Layer 2 (σε ποια θύρα), ARP = Layer 3→2 (ποιο MAC έχει το IP). Ψάξε πρώτα ARP, μετά MAC.', tip_en: 'MAC table = Layer 2 (which port), ARP = Layer 3→2 (which MAC owns the IP). Look up ARP first, then MAC.' },
    { id: 'nei', el: 'Γείτονες (CDP/LLDP)', en: 'Neighbours (CDP/LLDP)', tip_el: 'Το CDP είναι Cisco-only· το LLDP (802.1AB) είναι το πολυ-vendor. Κλείσ’ τα σε θύρες προς χρήστες/internet.', tip_en: 'CDP is Cisco-only; LLDP (802.1AB) is the multi-vendor one. Disable them on user/internet-facing ports.' },
    { id: 'stp', el: 'Spanning tree', en: 'Spanning tree', tip_el: 'Root = χαμηλότερο bridge ID (priority + MAC). PortFast/edge μόνο σε θύρες προς hosts, πάντα μαζί με BPDU Guard.', tip_en: 'Root = lowest bridge ID (priority + MAC). PortFast/edge only on host ports, always with BPDU Guard.' },
    { id: 'dhcp', el: 'DHCP', en: 'DHCP', tip_el: 'DORA: Discover → Offer → Request → Ack. Σε άλλο subnet από τον server χρειάζεσαι relay (ip helper-address).', tip_en: 'DORA: Discover → Offer → Request → Ack. A server in another subnet needs a relay (ip helper-address).' },
    { id: 'dns', el: 'DNS', en: 'DNS', tip_el: 'Αν το ping σε IP δουλεύει αλλά σε όνομα όχι, φταίει το DNS — όχι η δρομολόγηση.', tip_en: 'If ping to an IP works but to a name fails, it is DNS — not routing.' },
    { id: 'nat', el: 'NAT', en: 'NAT', tip_el: 'Inside local → inside global. PAT (overload / masquerade) = πολλά ιδιωτικά IP πίσω από ένα δημόσιο, με ports.', tip_en: 'Inside local → inside global. PAT (overload / masquerade) = many private IPs behind one public, using ports.' },
    { id: 'acl', el: 'ACL / firewall', en: 'ACL / firewall', tip_el: 'Τα ACL διαβάζονται από πάνω προς τα κάτω και τελειώνουν με σιωπηλό «deny any». Standard κοντά στον προορισμό, extended κοντά στην πηγή.', tip_en: 'ACLs are read top-down and end with an implicit "deny any". Standard near the destination, extended near the source.' },
    { id: 'aaa', el: 'Χρήστες & AAA', en: 'Users & AAA', tip_el: 'Πάντα «secret» (hash), ποτέ «password» στο IOS. Κράτα τοπικό χρήστη ως εφεδρεία όταν βάζεις RADIUS/TACACS+.', tip_en: 'Always "secret" (hashed), never "password" on IOS. Keep a local user as fallback when you add RADIUS/TACACS+.' },
    { id: 'mgmt', el: 'SSH & διαχείριση', en: 'SSH & management', tip_el: 'Για SSH στο IOS χρειάζονται: hostname, domain name, RSA κλειδί ≥ 2048, τοπικός χρήστης, transport input ssh.', tip_en: 'SSH on IOS needs: hostname, domain name, RSA key ≥ 2048, a local user, transport input ssh.' },
    { id: 'ntp', el: 'NTP / ώρα / logging / SNMP', en: 'NTP / time / logging / SNMP', tip_el: 'Χωρίς σωστή ώρα τα logs δεν συγκρίνονται και τα πιστοποιητικά αποτυγχάνουν. NTP stratum: μικρότερο = πιο κοντά στην πηγή.', tip_en: 'Without correct time logs cannot be correlated and certificates fail. NTP stratum: lower = closer to the source.' },
    { id: 'save', el: 'Αποθήκευση / backup / reload', en: 'Save / backup / reload', tip_el: 'Στο IOS η running-config χάνεται στο reload αν δεν κάνεις copy run start. Στο Junos τίποτα δεν ισχύει πριν το commit.', tip_en: 'On IOS the running-config is lost on reload unless you copy run start. On Junos nothing applies before commit.' },
    { id: 'ts', el: 'Αντιμετώπιση προβλημάτων', en: 'Troubleshooting', tip_el: 'Πήγαινε ανά layer: link/errors → VLAN/MAC → IP/ARP → route → DNS → εφαρμογή (port).', tip_en: 'Work layer by layer: link/errors → VLAN/MAC → IP/ARP → route → DNS → application (port).' },
    { id: 'wifi', el: 'Ασύρματα', en: 'Wireless', tip_el: '2.4 GHz: μόνο τα κανάλια 1/6/11 δεν επικαλύπτονται. Το RSSI πάνω από −67 dBm είναι καλό για φωνή/βίντεο.', tip_en: '2.4 GHz: only channels 1/6/11 do not overlap. RSSI better than −67 dBm is good for voice/video.' },
    { id: 'ospf', el: 'Πρωτόκολλα δρομολόγησης (OSPF)', en: 'Routing protocols (OSPF)', tip_el: 'Για γειτονία OSPF πρέπει να ταιριάζουν: area, subnet/mask, hello/dead timers, authentication, MTU, όχι ίδιο router-id.', tip_en: 'For an OSPF adjacency these must match: area, subnet/mask, hello/dead timers, authentication, MTU; router-IDs must differ.' },
  ];

  // X(id, cat, el, en, note_el, note_en, ios, nxos, mikrotik, junos, linux, windows)
  const X = (id, cat, el, en, note_el, note_en, ios, nxos, mikrotik, junos, linux, windows) =>
    ({ id, cat, el, en, note_el: note_el || null, note_en: note_en || null, cmds: { ios, nxos, mikrotik, junos, linux, windows } });
  const N = null;

  const DATA = [
    // ── Interfaces & IP ──
    X('ip-brief', 'ip', 'Σύνοψη interfaces και IP', 'Interface & IP summary',
      'Η πρώτη εντολή σε κάθε συσκευή. Linux: ip a = ip address.', 'The first command on any box. Linux: ip a = ip address.',
      'show ip interface brief', 'show ip interface brief', '/ip/address/print', 'show interfaces terse', 'ip -br address', 'ipconfig'),
    X('if-status', 'ip', 'Κατάσταση θυρών (up/down, ταχύτητα, duplex, VLAN)', 'Port status (up/down, speed, duplex, VLAN)',
      N, N,
      'show interfaces status', 'show interface status', '/interface/print', 'show interfaces terse', 'ip -br link', 'Get-NetAdapter'),
    X('if-detail', 'ip', 'Λεπτομέρειες μίας θύρας', 'Details of one interface',
      N, N,
      'show interfaces GigabitEthernet0/1', 'show interface Ethernet1/1', '/interface/ethernet/monitor ether1 once', 'show interfaces ge-0/0/1 detail', 'ip -d address show dev eth0', 'Get-NetAdapter -Name "Ethernet" | Format-List *'),
    X('ip-set', 'ip', 'Βάλε στατικό IP σε interface', 'Set a static IP on an interface',
      'Linux: το ip address add χάνεται στο reboot — για μόνιμο χρησιμοποίησε nmcli ή netplan.', 'Linux: ip address add is lost on reboot — use nmcli or netplan for a permanent change.',
      ['configure terminal', 'interface GigabitEthernet0/1', 'ip address 192.168.10.1 255.255.255.0', 'no shutdown', 'end'],
      ['configure terminal', 'interface Ethernet1/1', 'no switchport', 'ip address 192.168.10.1/24', 'no shutdown', 'end'],
      '/ip/address/add address=192.168.10.1/24 interface=ether1',
      ['configure', 'set interfaces ge-0/0/1 unit 0 family inet address 192.168.10.1/24', 'commit'],
      ['sudo nmcli connection modify eth0 ipv4.method manual ipv4.addresses 192.168.10.1/24', 'sudo nmcli connection up eth0'],
      'New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.10.1 -PrefixLength 24'),
    X('if-shut', 'ip', 'Κλείσε / άνοιξε μια θύρα', 'Disable / enable a port',
      N, N,
      ['configure terminal', 'interface GigabitEthernet0/1', 'shutdown', 'no shutdown'],
      ['configure terminal', 'interface Ethernet1/1', 'shutdown', 'no shutdown'],
      ['/interface/disable ether1', '/interface/enable ether1'],
      ['configure', 'set interfaces ge-0/0/1 disable', 'commit', 'delete interfaces ge-0/0/1 disable', 'commit'],
      ['sudo ip link set eth0 down', 'sudo ip link set eth0 up'],
      ['Disable-NetAdapter -Name "Ethernet" -Confirm:$false', 'Enable-NetAdapter -Name "Ethernet"']),
    X('if-desc', 'ip', 'Περιγραφή (description) σε θύρα', 'Interface description',
      'Γράφε πάντα πού πάει το καλώδιο — σώζει ώρες στο troubleshooting.', 'Always note where the cable goes — saves hours when troubleshooting.',
      ['configure terminal', 'interface GigabitEthernet0/1', 'description UPLINK-to-CORE1-Gi1/0/48'],
      ['configure terminal', 'interface Ethernet1/1', 'description UPLINK-to-CORE1'],
      '/interface/set ether1 comment="UPLINK-to-CORE1"',
      ['configure', 'set interfaces ge-0/0/1 description "UPLINK-to-CORE1"', 'commit'],
      'sudo ip link set dev eth0 alias "UPLINK-to-CORE1"',
      'Rename-NetAdapter -Name "Ethernet" -NewName "UPLINK"'),
    X('dhcp-client', 'ip', 'Πάρε IP με DHCP (client)', 'Get an IP via DHCP (client)',
      N, N,
      ['configure terminal', 'interface GigabitEthernet0/0', 'ip address dhcp', 'no shutdown'],
      N,
      '/ip/dhcp-client/add interface=ether1',
      ['configure', 'set interfaces ge-0/0/0 unit 0 family inet dhcp', 'commit'],
      ['sudo nmcli connection modify eth0 ipv4.method auto', 'sudo nmcli connection up eth0'],
      ['netsh interface ip set address name="Ethernet" source=dhcp', 'ipconfig /renew']),
    X('ipv6', 'ip', 'Διευθύνσεις IPv6', 'IPv6 addresses',
      N, N,
      'show ipv6 interface brief', 'show ipv6 interface brief', '/ipv6/address/print', 'show interfaces terse | match inet6', 'ip -6 address show', 'Get-NetIPAddress -AddressFamily IPv6'),
    X('mtu', 'ip', 'Αλλαγή MTU (jumbo frames)', 'Change MTU (jumbo frames)',
      'Σε πολλά Catalyst switches το MTU είναι global: system mtu jumbo 9000 (+ reload).', 'On many Catalyst switches MTU is global: system mtu jumbo 9000 (+ reload).',
      ['configure terminal', 'interface GigabitEthernet0/1', 'mtu 9000'],
      ['configure terminal', 'interface Ethernet1/1', 'mtu 9216'],
      '/interface/set ether1 mtu=9000 l2mtu=9100',
      ['configure', 'set interfaces ge-0/0/1 mtu 9192', 'commit'],
      'sudo ip link set dev eth0 mtu 9000',
      'netsh interface ipv4 set subinterface "Ethernet" mtu=9000 store=persistent'),
    X('speed', 'ip', 'Σταθερή ταχύτητα / duplex', 'Hard-set speed / duplex',
      'Duplex mismatch = late collisions και CRC errors. Αν κλειδώσεις τη μία άκρη, κλείδωσε και την άλλη.', 'Duplex mismatch = late collisions and CRC errors. If you hard-set one end, hard-set the other too.',
      ['configure terminal', 'interface GigabitEthernet0/1', 'speed 100', 'duplex full'],
      ['configure terminal', 'interface Ethernet1/1', 'speed 1000', 'duplex full'],
      '/interface/ethernet/set ether1 auto-negotiation=no speed=100M-baseT-full',
      N,
      'sudo ethtool -s eth0 speed 100 duplex full autoneg off',
      N),

    // ── Routing ──
    X('rt-show', 'route', 'Πίνακας δρομολόγησης', 'Routing table',
      N, N,
      'show ip route', 'show ip route', '/ip/route/print', 'show route', 'ip route show', 'route print'),
    X('rt-lookup', 'route', 'Ποια route παίρνει ένα συγκεκριμένο IP', 'Which route is used for an IP',
      N, N,
      'show ip route 8.8.8.8', 'show ip route 8.8.8.8', '/ip/route/print where 8.8.8.8 in dst-address', 'show route 8.8.8.8', 'ip route get 8.8.8.8', 'Find-NetRoute -RemoteIPAddress 8.8.8.8'),
    X('rt-default', 'route', 'Default route (gateway of last resort)', 'Default route (gateway of last resort)',
      N, N,
      ['configure terminal', 'ip route 0.0.0.0 0.0.0.0 192.168.1.1'],
      ['configure terminal', 'ip route 0.0.0.0/0 192.168.1.1'],
      '/ip/route/add dst-address=0.0.0.0/0 gateway=192.168.1.1',
      ['configure', 'set routing-options static route 0.0.0.0/0 next-hop 192.168.1.1', 'commit'],
      'sudo ip route add default via 192.168.1.1',
      'New-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias "Ethernet" -NextHop 192.168.1.1'),
    X('rt-static', 'route', 'Στατική route προς δίκτυο', 'Static route to a network',
      'Windows: το -p την κάνει μόνιμη (persistent).', 'Windows: -p makes it persistent.',
      ['configure terminal', 'ip route 10.20.0.0 255.255.0.0 10.0.0.2'],
      ['configure terminal', 'ip route 10.20.0.0/16 10.0.0.2'],
      '/ip/route/add dst-address=10.20.0.0/16 gateway=10.0.0.2',
      ['configure', 'set routing-options static route 10.20.0.0/16 next-hop 10.0.0.2', 'commit'],
      'sudo ip route add 10.20.0.0/16 via 10.0.0.2',
      'route -p add 10.20.0.0 mask 255.255.0.0 10.0.0.2'),
    X('rt-float', 'route', 'Εφεδρική (floating) static route', 'Backup (floating) static route',
      'Μεγαλύτερο AD/distance από την κύρια, ώστε να μπαίνει μόνο όταν πέσει εκείνη.', 'Higher AD/distance than the primary, so it is installed only when the primary fails.',
      ['configure terminal', 'ip route 0.0.0.0 0.0.0.0 10.99.0.1 250'],
      ['configure terminal', 'ip route 0.0.0.0/0 10.99.0.1 250'],
      '/ip/route/add dst-address=0.0.0.0/0 gateway=10.99.0.1 distance=250',
      ['configure', 'set routing-options static route 0.0.0.0/0 qualified-next-hop 10.99.0.1 preference 250', 'commit'],
      'sudo ip route add default via 10.99.0.1 metric 250',
      'New-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias "Ethernet 2" -NextHop 10.99.0.1 -RouteMetric 250'),
    X('ip-fwd', 'route', 'Ενεργοποίηση IP routing / forwarding', 'Enable IP routing / forwarding',
      'Τα L3 Catalyst switches δεν δρομολογούν μέχρι να δώσεις ip routing. MikroTik/Junos δρομολογούν πάντα.', 'L3 Catalyst switches do not route until you enter ip routing. MikroTik/Junos always route.',
      ['configure terminal', 'ip routing'],
      N, N, N,
      'sudo sysctl -w net.ipv4.ip_forward=1',
      'Set-NetIPInterface -Forwarding Enabled'),

    // ── VLAN & trunk ──
    X('vlan-show', 'vlan', 'Λίστα VLAN και θύρες τους', 'List VLANs and their ports',
      'Οι trunk θύρες ΔΕΝ εμφανίζονται στο show vlan brief — δες show interfaces trunk.', 'Trunk ports do NOT appear in show vlan brief — see show interfaces trunk.',
      'show vlan brief', 'show vlan brief', '/interface/bridge/vlan/print', 'show vlans', 'bridge vlan show', N),
    X('vlan-create', 'vlan', 'Δημιουργία VLAN', 'Create a VLAN',
      N, N,
      ['configure terminal', 'vlan 10', 'name USERS', 'exit'],
      ['configure terminal', 'vlan 10', 'name USERS', 'exit'],
      '/interface/bridge/vlan/add bridge=bridge1 vlan-ids=10 tagged=bridge1',
      ['configure', 'set vlans USERS vlan-id 10', 'commit'],
      'sudo ip link add link eth0 name eth0.10 type vlan id 10',
      N),
    X('vlan-access', 'vlan', 'Access θύρα σε VLAN', 'Access port in a VLAN',
      'MikroTik: το VLAN filtering δουλεύει μόνο με /interface/bridge/set bridge1 vlan-filtering=yes (προσοχή να μη χάσεις τη διαχείριση).', 'MikroTik: VLAN filtering only works with /interface/bridge/set bridge1 vlan-filtering=yes (careful not to lose management).',
      ['configure terminal', 'interface GigabitEthernet0/1', 'switchport mode access', 'switchport access vlan 10'],
      ['configure terminal', 'interface Ethernet1/1', 'switchport', 'switchport mode access', 'switchport access vlan 10'],
      ['/interface/bridge/port/set [find interface=ether2] pvid=10', '/interface/bridge/vlan/set [find vlan-ids=10] untagged=ether2'],
      ['configure', 'set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access', 'set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members USERS', 'commit'],
      ['sudo bridge vlan add dev eth1 vid 10 pvid untagged', 'sudo bridge vlan del dev eth1 vid 1'],
      N),
    X('vlan-trunk', 'vlan', 'Trunk θύρα (802.1Q)', 'Trunk port (802.1Q)',
      'Το «switchport trunk encapsulation dot1q» χρειάζεται μόνο σε παλιά switches που υποστηρίζουν και ISL.', '"switchport trunk encapsulation dot1q" is needed only on older switches that also support ISL.',
      ['configure terminal', 'interface GigabitEthernet0/24', 'switchport trunk encapsulation dot1q', 'switchport mode trunk', 'switchport trunk allowed vlan 10,20,30', 'switchport trunk native vlan 99'],
      ['configure terminal', 'interface Ethernet1/49', 'switchport', 'switchport mode trunk', 'switchport trunk allowed vlan 10,20,30', 'switchport trunk native vlan 99'],
      ['/interface/bridge/vlan/add bridge=bridge1 vlan-ids=20,30 tagged=bridge1,ether24', '/interface/bridge/vlan/set [find vlan-ids=10] tagged=bridge1,ether24', '/interface/bridge/set bridge1 vlan-filtering=yes'],
      ['configure', 'set interfaces ge-0/0/23 unit 0 family ethernet-switching interface-mode trunk', 'set interfaces ge-0/0/23 unit 0 family ethernet-switching vlan members [ USERS VOICE MGMT ]', 'set interfaces ge-0/0/23 native-vlan-id 99', 'commit'],
      ['sudo bridge vlan add dev eth1 vid 10', 'sudo bridge vlan add dev eth1 vid 20', 'sudo bridge vlan add dev eth1 vid 30'],
      N),
    X('trunk-show', 'vlan', 'Έλεγχος trunk (allowed / native VLAN)', 'Verify trunks (allowed / native VLAN)',
      N, N,
      'show interfaces trunk', 'show interface trunk', '/interface/bridge/vlan/print', 'show ethernet-switching interface', 'bridge -d vlan show', N),
    X('vlan-port', 'vlan', 'Σε ποιο VLAN / mode είναι μια θύρα', 'Which VLAN / mode a port is in',
      N, N,
      'show interfaces GigabitEthernet0/1 switchport', 'show interface Ethernet1/1 switchport', '/interface/bridge/port/print where interface=ether2', 'show ethernet-switching interface ge-0/0/1', 'bridge vlan show dev eth1', N),
    X('trunk-remove', 'vlan', 'Αφαίρεση VLAN από trunk', 'Remove a VLAN from a trunk',
      'ΠΡΟΣΟΧΗ: «allowed vlan 30» χωρίς add/remove αντικαθιστά όλη τη λίστα!', 'CAREFUL: "allowed vlan 30" without add/remove replaces the whole list!',
      ['configure terminal', 'interface GigabitEthernet0/24', 'switchport trunk allowed vlan remove 30'],
      ['configure terminal', 'interface Ethernet1/49', 'switchport trunk allowed vlan remove 30'],
      '/interface/bridge/vlan/set [find vlan-ids=30] tagged=bridge1',
      ['configure', 'delete interfaces ge-0/0/23 unit 0 family ethernet-switching vlan members MGMT', 'commit'],
      'sudo bridge vlan del dev eth1 vid 30',
      N),
    X('vlan-voice', 'vlan', 'Voice VLAN για IP τηλέφωνα', 'Voice VLAN for IP phones',
      N, N,
      ['configure terminal', 'interface GigabitEthernet0/5', 'switchport mode access', 'switchport access vlan 10', 'switchport voice vlan 20'],
      N,
      '/interface/bridge/vlan/add bridge=bridge1 vlan-ids=20 tagged=bridge1,ether5',
      ['configure', 'set switch-options voip interface ge-0/0/5.0 vlan VOICE', 'commit'],
      N, N),
    X('rt-stick', 'vlan', 'Router-on-a-stick (subinterfaces 802.1Q)', 'Router-on-a-stick (802.1Q subinterfaces)',
      N, N,
      ['configure terminal', 'interface GigabitEthernet0/0.10', 'encapsulation dot1Q 10', 'ip address 192.168.10.1 255.255.255.0'],
      ['configure terminal', 'interface Ethernet1/1.10', 'encapsulation dot1q 10', 'ip address 192.168.10.1/24', 'no shutdown'],
      ['/interface/vlan/add name=vlan10 vlan-id=10 interface=ether1', '/ip/address/add address=192.168.10.1/24 interface=vlan10'],
      ['configure', 'set interfaces ge-0/0/0 vlan-tagging', 'set interfaces ge-0/0/0 unit 10 vlan-id 10', 'set interfaces ge-0/0/0 unit 10 family inet address 192.168.10.1/24', 'commit'],
      ['sudo ip link add link eth0 name eth0.10 type vlan id 10', 'sudo ip address add 192.168.10.1/24 dev eth0.10', 'sudo ip link set eth0.10 up'],
      N),
    X('svi', 'vlan', 'SVI: IP gateway σε VLAN (L3 switch)', 'SVI: IP gateway on a VLAN (L3 switch)',
      N, N,
      ['configure terminal', 'ip routing', 'interface Vlan10', 'ip address 192.168.10.1 255.255.255.0', 'no shutdown'],
      ['configure terminal', 'feature interface-vlan', 'interface Vlan10', 'ip address 192.168.10.1/24', 'no shutdown'],
      ['/interface/vlan/add name=vlan10 vlan-id=10 interface=bridge1', '/ip/address/add address=192.168.10.1/24 interface=vlan10'],
      ['configure', 'set vlans USERS l3-interface irb.10', 'set interfaces irb unit 10 family inet address 192.168.10.1/24', 'commit'],
      N, N),

    // ── Switching / MAC & ARP ──
    X('mac-table', 'sw', 'Πίνακας MAC (MAC address table)', 'MAC address table',
      N, N,
      'show mac address-table', 'show mac address-table', '/interface/bridge/host/print', 'show ethernet-switching table', 'bridge fdb show', N),
    X('mac-find', 'sw', 'Σε ποια θύρα είναι ένα MAC', 'Which port a MAC address is on',
      'Το IOS θέλει τη μορφή aaaa.bbbb.cccc. Αν βγει σε trunk, συνέχισε στο επόμενο switch (CDP/LLDP).', 'IOS wants the aaaa.bbbb.cccc format. If it shows on a trunk, continue on the next switch (CDP/LLDP).',
      'show mac address-table address 0011.2233.4455', 'show mac address-table address 0011.2233.4455', '/interface/bridge/host/print where mac-address=00:11:22:33:44:55', 'show ethernet-switching table | match 00:11:22:33:44:55', 'bridge fdb show | grep -i 00:11:22:33:44:55', N),
    X('mac-clear', 'sw', 'Καθάρισμα δυναμικών MAC', 'Clear dynamic MAC entries',
      N, N,
      'clear mac address-table dynamic', 'clear mac address-table dynamic', N, 'clear ethernet-switching table', 'sudo ip link set dev br0 type bridge fdb_flush', N),
    X('arp', 'sw', 'Πίνακας ARP (IP ↔ MAC)', 'ARP table (IP ↔ MAC)',
      N, N,
      'show ip arp', 'show ip arp', '/ip/arp/print', 'show arp no-resolve', 'ip neigh show', 'arp -a'),
    X('arp-clear', 'sw', 'Καθάρισμα ARP cache', 'Clear the ARP cache',
      N, N,
      'clear arp-cache', 'clear ip arp', N, 'clear arp', 'sudo ip neigh flush all', 'netsh interface ip delete arpcache'),
    X('portsec', 'sw', 'Port security (όριο MAC ανά θύρα)', 'Port security (MAC limit per port)',
      'Violation: protect (σιωπηλά drop) · restrict (drop + log) · shutdown (err-disabled, default).', 'Violation: protect (silent drop) · restrict (drop + log) · shutdown (err-disabled, default).',
      ['configure terminal', 'interface GigabitEthernet0/1', 'switchport mode access', 'switchport port-security', 'switchport port-security maximum 2', 'switchport port-security mac-address sticky', 'switchport port-security violation restrict'],
      ['configure terminal', 'feature port-security', 'interface Ethernet1/1', 'switchport port-security', 'switchport port-security maximum 2', 'switchport port-security violation restrict'],
      N,
      ['configure', 'set switching-options interface ge-0/0/1 interface-mac-limit 2 packet-action drop', 'commit'],
      N, N),
    X('portsec-show', 'sw', 'Έλεγχος port security / err-disabled', 'Check port security / err-disabled',
      'Θύρα err-disabled: διόρθωσε την αιτία και μετά shutdown / no shutdown.', 'err-disabled port: fix the cause, then shutdown / no shutdown.',
      ['show port-security', 'show port-security interface GigabitEthernet0/1', 'show interfaces status err-disabled'],
      ['show port-security', 'show interface status err-disabled'],
      N,
      'show ethernet-switching interface ge-0/0/1 detail',
      N, N),
    X('lag', 'sw', 'EtherChannel / LACP (bond)', 'EtherChannel / LACP (bond)',
      'Windows: NIC teaming μόνο σε Windows Server.', 'Windows: NIC teaming only on Windows Server.',
      ['configure terminal', 'interface range GigabitEthernet0/1 - 2', 'channel-group 1 mode active', 'exit', 'interface Port-channel1', 'switchport mode trunk'],
      ['configure terminal', 'feature lacp', 'interface Ethernet1/1-2', 'channel-group 1 mode active', 'exit', 'interface port-channel1', 'switchport mode trunk'],
      '/interface/bonding/add name=bond1 slaves=ether1,ether2 mode=802.3ad',
      ['configure', 'set chassis aggregated-devices ethernet device-count 1', 'set interfaces ge-0/0/1 ether-options 802.3ad ae0', 'set interfaces ge-0/0/2 ether-options 802.3ad ae0', 'set interfaces ae0 aggregated-ether-options lacp active', 'commit'],
      ['sudo nmcli connection add type bond con-name bond0 ifname bond0 bond.options "mode=802.3ad,miimon=100"', 'sudo nmcli connection add type ethernet slave-type bond con-name bond0-p1 ifname eth1 master bond0', 'sudo nmcli connection add type ethernet slave-type bond con-name bond0-p2 ifname eth2 master bond0'],
      'New-NetLbfoTeam -Name Team1 -TeamMembers "Ethernet","Ethernet 2" -TeamingMode Lacp'),
    X('lag-show', 'sw', 'Έλεγχος EtherChannel / LACP', 'Verify EtherChannel / LACP',
      'IOS: (SU) = OK, (P) = bundled. (s) ή (D) = πρόβλημα.', 'IOS: (SU) = OK, (P) = bundled. (s) or (D) = problem.',
      'show etherchannel summary', 'show port-channel summary', '/interface/bonding/monitor bond1 once', 'show lacp interfaces', 'cat /proc/net/bonding/bond0', 'Get-NetLbfoTeam'),

    // ── Neighbours ──
    X('cdp', 'nei', 'Γείτονες CDP (ποιος είναι στην άλλη άκρη)', 'CDP neighbours (who is on the other end)',
      'Junos δεν έχει CDP — μόνο LLDP. Στο Linux χρειάζεται το πακέτο lldpd.', 'Junos has no CDP — LLDP only. Linux needs the lldpd package.',
      'show cdp neighbors', 'show cdp neighbors', '/ip/neighbor/print', 'show lldp neighbors', 'sudo lldpcli show neighbors', N),
    X('cdp-detail', 'nei', 'Γείτονες με λεπτομέρειες (IP, μοντέλο, έκδοση)', 'Neighbours in detail (IP, model, version)',
      N, N,
      'show cdp neighbors detail', 'show cdp neighbors detail', '/ip/neighbor/print detail', 'show lldp neighbors interface ge-0/0/1', 'sudo lldpcli show neighbors details', N),
    X('lldp-show', 'nei', 'Γείτονες LLDP', 'LLDP neighbours',
      N, N,
      'show lldp neighbors', 'show lldp neighbors', '/ip/neighbor/print where discovered-by~"lldp"', 'show lldp neighbors', 'sudo lldpcli show neighbors', N),
    X('lldp-on', 'nei', 'Ενεργοποίηση LLDP', 'Enable LLDP',
      N, N,
      ['configure terminal', 'lldp run'],
      ['configure terminal', 'feature lldp'],
      '/ip/neighbor/discovery-settings/set protocol=cdp,lldp,mndp',
      ['configure', 'set protocols lldp interface all', 'commit'],
      ['sudo apt install lldpd', 'sudo systemctl enable --now lldpd'],
      N),
    X('cdp-off', 'nei', 'Κλείσε discovery σε θύρες προς χρήστες/internet', 'Disable discovery on user/internet ports',
      'Το CDP/LLDP διαρρέει μοντέλο, έκδοση και IP σε όποιον ακούει.', 'CDP/LLDP leaks model, version and IP to anyone listening.',
      ['configure terminal', 'interface GigabitEthernet0/1', 'no cdp enable', 'no lldp transmit'],
      ['configure terminal', 'interface Ethernet1/1', 'no cdp enable', 'no lldp transmit'],
      '/ip/neighbor/discovery-settings/set discover-interface-list=LAN',
      ['configure', 'set protocols lldp interface ge-0/0/1 disable', 'commit'],
      N, N),

    // ── Spanning tree ──
    X('stp-show', 'stp', 'Κατάσταση spanning tree', 'Spanning tree status',
      N, N,
      'show spanning-tree', 'show spanning-tree', '/interface/bridge/monitor bridge1 once', 'show spanning-tree bridge', 'bridge -d link show', N),
    X('stp-root', 'stp', 'Ποιος είναι ο root bridge', 'Who is the root bridge',
      N, N,
      'show spanning-tree root', 'show spanning-tree root', '/interface/bridge/monitor bridge1 once', 'show spanning-tree bridge', 'ip -d link show type bridge', N),
    X('stp-prio', 'stp', 'Κάνε αυτό το switch root (priority)', 'Make this switch root (priority)',
      'Priority σε βήματα των 4096· μικρότερο κερδίζει.', 'Priority in steps of 4096; lower wins.',
      ['configure terminal', 'spanning-tree vlan 10 priority 4096'],
      ['configure terminal', 'spanning-tree vlan 10 priority 4096'],
      '/interface/bridge/set bridge1 priority=0x1000',
      ['configure', 'set protocols rstp bridge-priority 4k', 'commit'],
      'sudo ip link set dev br0 type bridge priority 4096',
      N),
    X('stp-edge', 'stp', 'PortFast / edge + BPDU Guard', 'PortFast / edge + BPDU Guard',
      N, N,
      ['configure terminal', 'interface GigabitEthernet0/1', 'spanning-tree portfast', 'spanning-tree bpduguard enable'],
      ['configure terminal', 'interface Ethernet1/1', 'spanning-tree port type edge', 'spanning-tree bpduguard enable'],
      '/interface/bridge/port/set [find interface=ether2] edge=yes bpdu-guard=yes',
      ['configure', 'set protocols rstp interface ge-0/0/1 edge', 'set protocols layer2-control bpdu-block interface ge-0/0/1', 'commit'],
      N, N),
    X('stp-mode', 'stp', 'Ρύθμιση έκδοσης STP (Rapid)', 'Set STP mode (Rapid)',
      N, N,
      ['configure terminal', 'spanning-tree mode rapid-pvst'],
      ['configure terminal', 'spanning-tree mode rapid-pvst'],
      '/interface/bridge/set bridge1 protocol-mode=rstp',
      ['configure', 'set protocols rstp', 'commit'],
      'sudo ip link set dev br0 type bridge stp_state 1',
      N),

    // ── DHCP ──
    X('dhcp-server', 'dhcp', 'DHCP server για ένα subnet', 'DHCP server for a subnet',
      'Windows: μόνο σε Windows Server με τον ρόλο DHCP.', 'Windows: only on Windows Server with the DHCP role.',
      ['configure terminal', 'ip dhcp excluded-address 192.168.10.1 192.168.10.10', 'ip dhcp pool USERS', 'network 192.168.10.0 255.255.255.0', 'default-router 192.168.10.1', 'dns-server 1.1.1.1 8.8.8.8', 'lease 1'],
      N,
      ['/ip/pool/add name=pool10 ranges=192.168.10.100-192.168.10.200', '/ip/dhcp-server/network/add address=192.168.10.0/24 gateway=192.168.10.1 dns-server=1.1.1.1', '/ip/dhcp-server/add name=dhcp10 interface=vlan10 address-pool=pool10'],
      ['configure', 'set access address-assignment pool P10 family inet network 192.168.10.0/24', 'set access address-assignment pool P10 family inet range R1 low 192.168.10.100 high 192.168.10.200', 'set access address-assignment pool P10 family inet dhcp-attributes router 192.168.10.1', 'set system services dhcp-local-server group LAN interface irb.10', 'commit'],
      'sudo dnsmasq --interface=eth1 --dhcp-range=192.168.10.100,192.168.10.200,12h',
      'Add-DhcpServerv4Scope -Name USERS -StartRange 192.168.10.100 -EndRange 192.168.10.200 -SubnetMask 255.255.255.0'),
    X('dhcp-leases', 'dhcp', 'Ποιοι πήραν IP (leases / bindings)', 'Who got an IP (leases / bindings)',
      N, N,
      'show ip dhcp binding', N, '/ip/dhcp-server/lease/print', 'show dhcp server binding', 'cat /var/lib/misc/dnsmasq.leases', 'Get-DhcpServerv4Lease -ScopeId 192.168.10.0'),
    X('dhcp-relay', 'dhcp', 'DHCP relay (helper-address)', 'DHCP relay (helper-address)',
      N, N,
      ['configure terminal', 'interface Vlan10', 'ip helper-address 10.0.0.5'],
      ['configure terminal', 'feature dhcp', 'interface Vlan10', 'ip dhcp relay address 10.0.0.5'],
      '/ip/dhcp-relay/add name=relay10 interface=vlan10 dhcp-server=10.0.0.5 local-address=192.168.10.1 disabled=no',
      ['configure', 'set forwarding-options dhcp-relay server-group SG 10.0.0.5', 'set forwarding-options dhcp-relay group G active-server-group SG', 'set forwarding-options dhcp-relay group G interface irb.10', 'commit'],
      N, N),
    X('dhcp-snoop', 'dhcp', 'DHCP snooping (κόψε rogue DHCP servers)', 'DHCP snooping (block rogue DHCP servers)',
      'Trusted μόνο η θύρα προς τον πραγματικό DHCP server / uplink.', 'Trust only the port towards the real DHCP server / uplink.',
      ['configure terminal', 'ip dhcp snooping', 'ip dhcp snooping vlan 10', 'no ip dhcp snooping information option', 'interface GigabitEthernet0/24', 'ip dhcp snooping trust'],
      ['configure terminal', 'feature dhcp', 'ip dhcp snooping', 'ip dhcp snooping vlan 10', 'interface Ethernet1/49', 'ip dhcp snooping trust'],
      ['/interface/bridge/set bridge1 dhcp-snooping=yes', '/interface/bridge/port/set [find interface=ether1] trusted=yes'],
      ['configure', 'set vlans USERS forwarding-options dhcp-security', 'set vlans USERS forwarding-options dhcp-security group UPLINK overrides trusted', 'set vlans USERS forwarding-options dhcp-security group UPLINK interface ge-0/0/23.0', 'commit'],
      N, N),
    X('dhcp-renew', 'dhcp', 'Ανανέωση IP από DHCP (release / renew)', 'Release / renew a DHCP address',
      N, N,
      'renew dhcp GigabitEthernet0/0', N, '/ip/dhcp-client/renew [find interface=ether1]', 'request dhcp client renew interface ge-0/0/0.0', ['sudo dhclient -r eth0', 'sudo dhclient eth0'], ['ipconfig /release', 'ipconfig /renew']),

    // ── DNS ──
    X('dns-lookup', 'dns', 'Ερώτημα DNS (lookup)', 'DNS lookup',
      N, N,
      N, N, ':put [:resolve example.com]', 'show host example.com', 'dig +short example.com', 'Resolve-DnsName example.com'),
    X('dns-set', 'dns', 'Ρύθμιση DNS servers', 'Set DNS servers',
      'IOS: «no ip domain-lookup» σταματά την αναμονή όταν γράψεις λάθος εντολή (στο lab).', 'IOS: "no ip domain-lookup" stops the hang when you mistype a command (in labs).',
      ['configure terminal', 'ip domain lookup', 'ip name-server 1.1.1.1 8.8.8.8'],
      ['configure terminal', 'ip domain-lookup', 'ip name-server 1.1.1.1 8.8.8.8'],
      '/ip/dns/set servers=1.1.1.1,8.8.8.8',
      ['configure', 'set system name-server 1.1.1.1', 'set system name-server 8.8.8.8', 'commit'],
      ['sudo nmcli connection modify eth0 ipv4.dns "1.1.1.1 8.8.8.8"', 'sudo nmcli connection up eth0'],
      'Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 1.1.1.1,8.8.8.8'),
    X('dns-cache', 'dns', 'Δες / άδειασε την DNS cache', 'Show / flush the DNS cache',
      N, N,
      N, N, ['/ip/dns/cache/print', '/ip/dns/cache/flush'], N, ['resolvectl statistics', 'resolvectl flush-caches'], ['ipconfig /displaydns', 'ipconfig /flushdns']),
    X('dns-show', 'dns', 'Ποιους DNS servers χρησιμοποιώ', 'Which DNS servers am I using',
      N, N,
      'show hosts', 'show hosts', '/ip/dns/print', 'show configuration system name-server', 'resolvectl status', 'Get-DnsClientServerAddress'),

    // ── NAT ──
    X('nat-pat', 'nat', 'PAT / NAT overload / masquerade (LAN → internet)', 'PAT / NAT overload / masquerade (LAN → internet)',
      'Junos: για SRX (security zones). Windows: New-NetNat κυρίως για Hyper-V/containers.', 'Junos: for SRX (security zones). Windows: New-NetNat is mainly for Hyper-V/containers.',
      ['configure terminal', 'access-list 1 permit 192.168.10.0 0.0.0.255', 'ip nat inside source list 1 interface GigabitEthernet0/0 overload', 'interface GigabitEthernet0/0', 'ip nat outside', 'interface GigabitEthernet0/1', 'ip nat inside'],
      N,
      '/ip/firewall/nat/add chain=srcnat out-interface=ether1 action=masquerade',
      ['configure', 'set security nat source rule-set LAN-WAN from zone trust', 'set security nat source rule-set LAN-WAN to zone untrust', 'set security nat source rule-set LAN-WAN rule R1 match source-address 192.168.10.0/24', 'set security nat source rule-set LAN-WAN rule R1 then source-nat interface', 'commit'],
      'sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE',
      'New-NetNat -Name LabNAT -InternalIPInterfaceAddressPrefix 192.168.10.0/24'),
    X('nat-pf', 'nat', 'Port forwarding (static NAT με port)', 'Port forwarding (static NAT with port)',
      N, N,
      ['configure terminal', 'ip nat inside source static tcp 192.168.10.20 80 interface GigabitEthernet0/0 8080'],
      N,
      '/ip/firewall/nat/add chain=dstnat in-interface=ether1 protocol=tcp dst-port=8080 action=dst-nat to-addresses=192.168.10.20 to-ports=80',
      ['configure', 'set security nat destination pool WEB address 192.168.10.20/32 port 80', 'set security nat destination rule-set IN from zone untrust', 'set security nat destination rule-set IN rule R1 match destination-address 203.0.113.10/32', 'set security nat destination rule-set IN rule R1 match destination-port 8080', 'set security nat destination rule-set IN rule R1 then destination-nat pool WEB', 'commit'],
      'sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 8080 -j DNAT --to-destination 192.168.10.20:80',
      'netsh interface portproxy add v4tov4 listenport=8080 connectaddress=192.168.10.20 connectport=80'),
    X('nat-show', 'nat', 'Δες τις μεταφράσεις NAT', 'Show NAT translations',
      N, N,
      ['show ip nat translations', 'show ip nat statistics'], N, '/ip/firewall/nat/print stats', ['show security nat source rule all', 'show security flow session'], 'sudo conntrack -L', 'Get-NetNatSession'),
    X('nat-static', 'nat', 'Static NAT 1:1', 'Static 1:1 NAT',
      N, N,
      ['configure terminal', 'ip nat inside source static 192.168.10.20 203.0.113.20'],
      N,
      ['/ip/firewall/nat/add chain=dstnat dst-address=203.0.113.20 action=dst-nat to-addresses=192.168.10.20', '/ip/firewall/nat/add chain=srcnat src-address=192.168.10.20 action=src-nat to-addresses=203.0.113.20'],
      ['configure', 'set security nat static rule-set ST from zone untrust', 'set security nat static rule-set ST rule R1 match destination-address 203.0.113.20/32', 'set security nat static rule-set ST rule R1 then static-nat prefix 192.168.10.20/32', 'commit'],
      ['sudo iptables -t nat -A PREROUTING -d 203.0.113.20 -j DNAT --to-destination 192.168.10.20', 'sudo iptables -t nat -A POSTROUTING -s 192.168.10.20 -j SNAT --to-source 203.0.113.20'],
      N),

    // ── ACL / firewall ──
    X('acl-mgmt', 'acl', 'Επέτρεψε διαχείριση (SSH) μόνο από ένα subnet', 'Allow management (SSH) only from one subnet',
      'Junos: φίλτρο στο lo0 προστατεύει το Routing Engine — μην ξεχάσεις OSPF/BGP/NTP terms αλλιώς τα κόβεις.', 'Junos: a filter on lo0 protects the Routing Engine — add OSPF/BGP/NTP terms or you will cut them.',
      ['configure terminal', 'ip access-list standard MGMT', 'permit 192.168.99.0 0.0.0.255', 'deny any log', 'line vty 0 15', 'access-class MGMT in'],
      ['configure terminal', 'ip access-list MGMT', 'permit ip 192.168.99.0/24 any', 'deny ip any any log', 'line vty', 'access-class MGMT in'],
      ['/ip/service/set ssh address=192.168.99.0/24', '/ip/service/set winbox address=192.168.99.0/24'],
      ['configure', 'set firewall family inet filter MGMT term ALLOW from source-address 192.168.99.0/24', 'set firewall family inet filter MGMT term ALLOW from protocol tcp', 'set firewall family inet filter MGMT term ALLOW from destination-port ssh', 'set firewall family inet filter MGMT term ALLOW then accept', 'set firewall family inet filter MGMT term SSH-DENY from protocol tcp', 'set firewall family inet filter MGMT term SSH-DENY from destination-port ssh', 'set firewall family inet filter MGMT term SSH-DENY then discard', 'set firewall family inet filter MGMT term REST then accept', 'set interfaces lo0 unit 0 family inet filter input MGMT', 'commit confirmed 5'],
      'sudo ufw allow from 192.168.99.0/24 to any port 22 proto tcp',
      'New-NetFirewallRule -DisplayName "SSH from mgmt" -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress 192.168.99.0/24 -Action Allow'),
    X('acl-ext', 'acl', 'Extended ACL: μπλόκαρε ένα port', 'Extended ACL: block a port',
      'Το «permit ip any any» στο τέλος χρειάζεται — αλλιώς το implicit deny κόβει όλα τα υπόλοιπα.', 'The trailing "permit ip any any" is required — otherwise the implicit deny drops everything else.',
      ['configure terminal', 'ip access-list extended BLOCK-TELNET', 'deny tcp any any eq 23', 'permit ip any any', 'interface GigabitEthernet0/1', 'ip access-group BLOCK-TELNET in'],
      ['configure terminal', 'ip access-list BLOCK-TELNET', 'deny tcp any any eq 23', 'permit ip any any', 'interface Ethernet1/1', 'ip access-group BLOCK-TELNET in'],
      '/ip/firewall/filter/add chain=forward protocol=tcp dst-port=23 action=drop',
      ['configure', 'set firewall family inet filter BLOCK-TELNET term T1 from protocol tcp', 'set firewall family inet filter BLOCK-TELNET term T1 from destination-port 23', 'set firewall family inet filter BLOCK-TELNET term T1 then discard', 'set firewall family inet filter BLOCK-TELNET term ALL then accept', 'set interfaces ge-0/0/1 unit 0 family inet filter input BLOCK-TELNET', 'commit'],
      'sudo iptables -A FORWARD -p tcp --dport 23 -j DROP',
      'New-NetFirewallRule -DisplayName "Block Telnet" -Direction Outbound -Protocol TCP -RemotePort 23 -Action Block'),
    X('acl-show', 'acl', 'Δες ACL / κανόνες firewall με μετρητές', 'Show ACLs / firewall rules with counters',
      N, N,
      ['show access-lists', 'show ip interface GigabitEthernet0/1 | include access list'],
      'show ip access-lists',
      '/ip/firewall/filter/print stats',
      ['show firewall', 'show configuration firewall'],
      ['sudo iptables -L -n -v --line-numbers', 'sudo nft list ruleset'],
      'Get-NetFirewallRule -Enabled True | Select-Object DisplayName, Direction, Action'),
    X('fw-stateful', 'acl', 'Stateful βάση: δέξου established, κόψε τα υπόλοιπα', 'Stateful baseline: accept established, drop the rest',
      'Linux: βάλε πρώτα κανόνα για το SSH σου πριν το policy DROP! IOS: το «established» ταιριάζει μόνο TCP με ACK/RST.', 'Linux: allow your own SSH before policy DROP! IOS: "established" only matches TCP with ACK/RST.',
      ['configure terminal', 'ip access-list extended FROM-WAN', 'permit tcp any any established', 'deny ip any any log', 'interface GigabitEthernet0/0', 'ip access-group FROM-WAN in'],
      N,
      ['/ip/firewall/filter/add chain=input connection-state=established,related action=accept', '/ip/firewall/filter/add chain=input connection-state=invalid action=drop', '/ip/firewall/filter/add chain=input in-interface-list=!LAN action=drop'],
      N,
      ['sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT', 'sudo iptables -A INPUT -i lo -j ACCEPT', 'sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT', 'sudo iptables -P INPUT DROP'],
      'Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow'),

    // ── Users & AAA ──
    X('user-add', 'aaa', 'Δημιουργία τοπικού χρήστη admin', 'Create a local admin user',
      'Junos/Windows ζητούν τον κωδικό interactive — δεν μένει στο ιστορικό.', 'Junos/Windows prompt for the password — it does not end up in history.',
      ['configure terminal', 'username netadmin privilege 15 secret <password>', 'line vty 0 15', 'login local'],
      ['configure terminal', 'username netadmin password <password> role network-admin'],
      '/user/add name=netadmin group=full password=<password>',
      ['configure', 'set system login user netadmin class super-user authentication plain-text-password', 'commit'],
      ['sudo adduser netadmin', 'sudo usermod -aG sudo netadmin'],
      ['net user netadmin * /add', 'net localgroup Administrators netadmin /add']),
    X('pw-enc', 'aaa', 'Enable secret / κρυπτογράφηση κωδικών', 'Enable secret / password encryption',
      'Το service password-encryption (type 7) αντιστρέφεται εύκολα — είναι μόνο για «να μη φαίνεται». Χρησιμοποίησε secret (type 8/9).', 'service password-encryption (type 7) is trivially reversible — it only hides from shoulder-surfing. Use secret (type 8/9).',
      ['configure terminal', 'enable algorithm-type scrypt secret <password>', 'service password-encryption', 'security passwords min-length 10'],
      ['configure terminal', 'password strength-check'],
      N,
      ['configure', 'set system login password format sha512', 'set system root-authentication plain-text-password', 'commit'],
      'sudo passwd netadmin',
      N),
    X('users-show', 'aaa', 'Ποιοι χρήστες υπάρχουν / είναι συνδεδεμένοι', 'Which users exist / are logged in',
      N, N,
      ['show users', 'show running-config | include username'],
      ['show users', 'show user-account'],
      ['/user/print', '/user/active/print'],
      ['show system users', 'show configuration system login'],
      ['who', 'getent passwd | cut -d: -f1'],
      ['query user', 'Get-LocalUser']),
    X('radius', 'aaa', 'Login μέσω RADIUS (με τοπικό fallback)', 'Login via RADIUS (with local fallback)',
      N, N,
      ['configure terminal', 'aaa new-model', 'radius server RAD1', 'address ipv4 10.0.0.10 auth-port 1812 acct-port 1813', 'key <shared-secret>', 'exit', 'aaa authentication login default group radius local', 'aaa authorization exec default group radius local'],
      ['configure terminal', 'radius-server host 10.0.0.10 key <shared-secret> authentication accounting', 'aaa group server radius RAD', 'server 10.0.0.10', 'exit', 'aaa authentication login default group RAD'],
      ['/radius/add service=login address=10.0.0.10 secret=<shared-secret>', '/user/aaa/set use-radius=yes'],
      ['configure', 'set system radius-server 10.0.0.10 secret "<shared-secret>"', 'set system authentication-order [ radius password ]', 'commit'],
      N, N),
    X('dot1x', 'aaa', '802.1X σε θύρα switch', '802.1X on a switch port',
      N, N,
      ['configure terminal', 'aaa new-model', 'aaa authentication dot1x default group radius', 'dot1x system-auth-control', 'interface GigabitEthernet0/1', 'switchport mode access', 'authentication port-control auto', 'dot1x pae authenticator'],
      N,
      '/interface/dot1x/server/add interface=ether2 auth-types=dot1x',
      ['configure', 'set access profile RAD authentication-order radius', 'set access profile RAD radius authentication-server 10.0.0.10', 'set protocols dot1x authenticator authentication-profile-name RAD', 'set protocols dot1x authenticator interface ge-0/0/1 supplicant single', 'commit'],
      N, N),

    // ── SSH & management ──
    X('ssh-on', 'mgmt', 'Ενεργοποίηση SSH (και κλείσιμο Telnet)', 'Enable SSH (and disable Telnet)',
      N, N,
      ['configure terminal', 'hostname R1', 'ip domain name lab.local', 'crypto key generate rsa modulus 2048', 'ip ssh version 2', 'line vty 0 15', 'transport input ssh', 'login local'],
      ['configure terminal', 'feature ssh', 'no feature telnet', 'ssh key rsa 2048 force'],
      ['/ip/service/set ssh disabled=no', '/ip/service/set telnet disabled=yes'],
      ['configure', 'set system services ssh root-login deny', 'delete system services telnet', 'commit'],
      ['sudo apt install openssh-server', 'sudo systemctl enable --now ssh'],
      ['Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0', 'Start-Service sshd', 'Set-Service -Name sshd -StartupType Automatic']),
    X('ssh-to', 'mgmt', 'SSH από τη συσκευή σε άλλη', 'SSH from the device to another',
      N, N,
      'ssh -l admin 10.0.0.1', 'ssh admin@10.0.0.1 vrf management', '/system/ssh address=10.0.0.1 user=admin', 'ssh admin@10.0.0.1', 'ssh admin@10.0.0.1', 'ssh admin@10.0.0.1'),
    X('banner', 'mgmt', 'Banner / μήνυμα σύνδεσης', 'Login banner',
      'Γράψε «Authorised access only» — ποτέ «Welcome».', 'Write "Authorised access only" — never "Welcome".',
      ['configure terminal', 'banner motd ^Authorised access only. Activity is logged.^'],
      ['configure terminal', 'banner motd #Authorised access only. Activity is logged.#'],
      '/system/note/set note="Authorised access only. Activity is logged." show-at-login=yes',
      ['configure', 'set system login message "Authorised access only. Activity is logged."', 'commit'],
      ['echo "Authorised access only." | sudo tee /etc/issue.net', 'echo "Banner /etc/issue.net" | sudo tee /etc/ssh/sshd_config.d/banner.conf', 'sudo systemctl reload ssh'],
      N),
    X('hostname', 'mgmt', 'Όνομα συσκευής (hostname)', 'Device name (hostname)',
      N, N,
      ['configure terminal', 'hostname SW1'],
      ['configure terminal', 'hostname SW1'],
      '/system/identity/set name=SW1',
      ['configure', 'set system host-name SW1', 'commit'],
      'sudo hostnamectl set-hostname sw1',
      'Rename-Computer -NewName SW1 -Restart'),
    X('version', 'mgmt', 'Έκδοση λογισμικού, μοντέλο, uptime', 'Software version, model, uptime',
      N, N,
      'show version', 'show version', ['/system/resource/print', '/system/routerboard/print'], ['show version', 'show chassis hardware'], ['uname -a', 'cat /etc/os-release', 'uptime'], 'systeminfo'),
    X('timeout', 'mgmt', 'Αυτόματη αποσύνδεση (exec timeout)', 'Idle session timeout (exec timeout)',
      'IOS: το logging synchronous σταματά τα logs να «κόβουν» αυτό που γράφεις.', 'IOS: logging synchronous stops log messages breaking your typing.',
      ['configure terminal', 'line console 0', 'exec-timeout 10 0', 'logging synchronous', 'line vty 0 15', 'exec-timeout 10 0'],
      ['configure terminal', 'line console', 'exec-timeout 10', 'line vty', 'exec-timeout 10'],
      N,
      ['configure', 'set system login class ADMIN idle-timeout 10', 'set system login class ADMIN permissions all', 'commit'],
      'echo "TMOUT=600; readonly TMOUT; export TMOUT" | sudo tee /etc/profile.d/timeout.sh',
      N),

    // ── NTP / time / logging / SNMP ──
    X('ntp-set', 'ntp', 'Ρύθμιση NTP και ζώνης ώρας', 'Configure NTP and time zone',
      'IOS: για όνομα (pool.ntp.org) χρειάζεται DNS — αλλιώς δώσε IP.', 'IOS: a hostname (pool.ntp.org) needs DNS — otherwise give an IP.',
      ['configure terminal', 'ntp server 10.0.0.1', 'clock timezone EET 2', 'clock summer-time EEST recurring last Sun Mar 3:00 last Sun Oct 4:00'],
      ['configure terminal', 'ntp server 10.0.0.1 use-vrf management', 'clock timezone EET 2 0'],
      ['/system/ntp/client/set enabled=yes servers=0.pool.ntp.org,1.pool.ntp.org', '/system/clock/set time-zone-name=Europe/Athens'],
      ['configure', 'set system ntp server 10.0.0.1', 'set system time-zone Europe/Athens', 'commit'],
      ['sudo timedatectl set-timezone Europe/Athens', 'sudo timedatectl set-ntp true'],
      ['w32tm /config /manualpeerlist:"0.pool.ntp.org" /syncfromflags:manual /update', 'w32tm /resync']),
    X('ntp-status', 'ntp', 'Κατάσταση NTP / συγχρονισμός ώρας', 'NTP status / time sync',
      N, N,
      ['show ntp status', 'show ntp associations', 'show clock detail'],
      ['show ntp peer-status', 'show clock'],
      ['/system/ntp/client/print', '/system/clock/print'],
      ['show ntp associations', 'show ntp status', 'show system uptime'],
      ['timedatectl', 'chronyc tracking'],
      ['w32tm /query /status', 'w32tm /query /peers']),
    X('clock-set', 'ntp', 'Χειροκίνητη ρύθμιση ώρας', 'Set the clock manually',
      'MikroTik v7.10+: ημερομηνία ως YYYY-MM-DD (παλιότερα nov/18/2026).', 'MikroTik v7.10+: date as YYYY-MM-DD (older: nov/18/2026).',
      'clock set 14:30:00 18 Nov 2026', 'clock set 14:30:00 18 November 2026', '/system/clock/set date=2026-11-18 time=14:30:00', 'set date 202611181430.00', 'sudo timedatectl set-time "2026-11-18 14:30:00"', 'Set-Date -Date "2026-11-18 14:30"'),
    X('logs', 'ntp', 'Δες τα logs της συσκευής', 'Show the device logs',
      N, N,
      'show logging', 'show logging logfile', '/log/print', 'show log messages', 'sudo journalctl -n 100 --no-pager', 'Get-WinEvent -LogName System -MaxEvents 50'),
    X('logs-live', 'ntp', 'Ζωντανά logs στην οθόνη (σε SSH)', 'Live logs on screen (over SSH)',
      'IOS/NX-OS: σε SSH/Telnet τα logs δεν εμφανίζονται χωρίς terminal monitor.', 'IOS/NX-OS: over SSH/Telnet logs are not shown without terminal monitor.',
      'terminal monitor', 'terminal monitor', '/log/print follow', 'monitor start messages', 'sudo journalctl -f', 'Get-Content C:\\Windows\\Logs\\CBS\\CBS.log -Wait -Tail 20'),
    X('syslog', 'ntp', 'Αποστολή logs σε syslog server', 'Send logs to a syslog server',
      'Βάλε και timestamps με ms + σωστή ώρα (NTP), αλλιώς τα logs είναι άχρηστα.', 'Also enable ms timestamps + correct time (NTP), otherwise logs are useless.',
      ['configure terminal', 'service timestamps log datetime msec localtime show-timezone', 'logging host 10.0.0.50', 'logging trap informational'],
      ['configure terminal', 'logging server 10.0.0.50 6 use-vrf management', 'logging timestamp milliseconds'],
      ['/system/logging/action/add name=remote target=remote remote=10.0.0.50', '/system/logging/add topics=info action=remote'],
      ['configure', 'set system syslog host 10.0.0.50 any info', 'commit'],
      ['echo "*.* @10.0.0.50:514" | sudo tee /etc/rsyslog.d/90-remote.conf', 'sudo systemctl restart rsyslog'],
      N),
    X('snmp', 'ntp', 'SNMP read-only (για monitoring)', 'SNMP read-only (for monitoring)',
      'Προτίμησε SNMPv3 σε παραγωγή· v2c community = κωδικός σε καθαρό κείμενο. Linux στήλη: δοκιμή από τον server.', 'Prefer SNMPv3 in production; a v2c community is a cleartext password. Linux column: test from the server.',
      ['configure terminal', 'ip access-list standard SNMP-RO', 'permit 10.0.0.50', 'snmp-server community <ro-community> RO SNMP-RO', 'snmp-server location Athens-Lab'],
      ['configure terminal', 'snmp-server community <ro-community> group network-operator', 'snmp-server location Athens-Lab'],
      ['/snmp/community/set [find default=yes] name=<ro-community> addresses=10.0.0.50/32', '/snmp/set enabled=yes'],
      ['configure', 'set snmp community <ro-community> authorization read-only', 'set snmp community <ro-community> clients 10.0.0.50/32', 'commit'],
      'snmpwalk -v2c -c <ro-community> 10.0.0.1 1.3.6.1.2.1.1',
      N),

    // ── Save / backup / reload ──
    X('save', 'save', 'Αποθήκευση ρυθμίσεων (copy run start / write memory)', 'Save the configuration (copy run start / write memory)',
      'IOS: «write memory» (wr) κάνει το ίδιο. MikroTik: σώζει αυτόματα. Linux: τα nmcli/netplan είναι ήδη μόνιμα.', 'IOS: "write memory" (wr) does the same. MikroTik: saves automatically. Linux: nmcli/netplan are already persistent.',
      'copy running-config startup-config', 'copy running-config startup-config', N, ['commit check', 'commit'], 'sudo netfilter-persistent save', N),
    X('show-run', 'save', 'Δες όλη την τρέχουσα ρύθμιση', 'Show the running configuration',
      N, N,
      'show running-config', 'show running-config', '/export', 'show configuration | display set', ['ip -d address show', 'cat /etc/netplan/*.yaml'], 'netsh interface ip show config'),
    X('show-run-if', 'save', 'Ρύθμιση μόνο ενός τμήματος / θύρας', 'Configuration of one section / interface',
      N, N,
      ['show running-config interface GigabitEthernet0/1', 'show running-config | section router ospf'],
      'show running-config interface Ethernet1/1',
      '/interface/export',
      'show configuration interfaces ge-0/0/1',
      'nmcli connection show eth0',
      'Get-NetIPConfiguration -InterfaceAlias "Ethernet"'),
    X('startup', 'save', 'Δες την αποθηκευμένη (startup) ρύθμιση', 'Show the saved (startup) configuration',
      N, N,
      'show startup-config', 'show startup-config', '/system/backup/print', 'show system rollback 0', 'cat /etc/netplan/*.yaml', N),
    X('backup', 'save', 'Backup ρυθμίσεων σε server', 'Back up the config to a server',
      'MikroTik: το /export είναι κείμενο (για diff), το .backup είναι binary για την ίδια συσκευή.', 'MikroTik: /export is text (diff-able), .backup is binary for the same device.',
      'copy running-config tftp://10.0.0.50/r1-confg',
      'copy running-config scp://admin@10.0.0.50/sw1.cfg vrf management',
      ['/export file=config-backup', '/system/backup/save name=full-backup'],
      'file copy /config/juniper.conf.gz scp://admin@10.0.0.50/',
      'sudo tar czf netcfg-backup.tgz /etc/netplan /etc/NetworkManager',
      'netsh dump > netcfg-backup.txt'),
    X('reboot', 'save', 'Επανεκκίνηση', 'Reboot',
      N, N,
      'reload', 'reload', '/system/reboot', 'request system reboot', 'sudo reboot', 'Restart-Computer'),
    X('safety', 'save', 'Δίχτυ ασφαλείας πριν από ριψοκίνδυνη αλλαγή', 'Safety net before a risky change',
      'IOS: αν κλειδωθείς έξω, κάνει reload στην αποθηκευμένη ρύθμιση. MikroTik: Ctrl+X = Safe Mode (αναιρεί αν πέσει η σύνδεση).', 'IOS: if you lock yourself out it reloads to the saved config. MikroTik: Ctrl+X = Safe Mode (undoes if the session drops).',
      ['reload in 10', 'configure terminal', '! ... risky change ...', 'end', 'reload cancel'],
      ['checkpoint before-change', 'configure terminal', '! ... risky change ...', 'end', 'rollback running-config checkpoint before-change'],
      N,
      ['commit confirmed 10', 'commit'],
      'sudo netplan try',
      N),
    X('diff', 'save', 'Τι άλλαξε; (σύγκριση ρυθμίσεων)', 'What changed? (compare configs)',
      N, N,
      'show archive config differences nvram:startup-config system:running-config',
      'show diff rollback-patch checkpoint before-change running-config',
      ['/system/history/print', '/undo'],
      ['show | compare rollback 1', 'rollback 1'],
      'diff -u netcfg-old.yaml /etc/netplan/01-netcfg.yaml',
      N),
    X('erase', 'save', 'Επαναφορά εργοστασιακών ρυθμίσεων', 'Factory reset',
      'ΠΡΟΣΟΧΗ: σβήνει τα πάντα. Στο IOS switch σβήσε και το vlan.dat.', 'CAREFUL: wipes everything. On IOS switches also delete vlan.dat.',
      ['write erase', 'delete flash:vlan.dat', 'reload'],
      ['write erase', 'reload'],
      '/system/reset-configuration no-defaults=yes',
      ['configure', 'load factory-default', 'set system root-authentication plain-text-password', 'commit'],
      N, N),
    X('files', 'save', 'Αρχεία στη flash / δίσκο', 'Files on flash / disk',
      N, N,
      'dir flash:', 'dir bootflash:', '/file/print', 'file list /var/tmp', 'ls -l', 'dir'),

    // ── Troubleshooting ──
    X('ping', 'ts', 'Ping', 'Ping',
      'IOS: «!» = απάντηση, «.» = timeout, «U» = unreachable.', 'IOS: "!" = reply, "." = timeout, "U" = unreachable.',
      'ping 8.8.8.8 repeat 10', 'ping 8.8.8.8 count 10', '/ping 8.8.8.8 count=10', 'ping 8.8.8.8 count 10', 'ping -c 10 8.8.8.8', 'ping -n 10 8.8.8.8'),
    X('ping-src', 'ts', 'Ping από συγκεκριμένη πηγή / interface', 'Ping from a specific source / interface',
      'Ελέγχει αν ο απέναντι έχει route ΠΙΣΩ προς το δικό σου δίκτυο.', 'Checks that the far end has a route BACK to your network.',
      'ping 10.20.0.1 source Loopback0', 'ping 10.20.0.1 source 10.0.0.1', '/ping 10.20.0.1 src-address=10.0.0.1', 'ping 10.20.0.1 source 10.0.0.1', 'ping -I eth0 10.20.0.1', 'ping -S 10.0.0.1 10.20.0.1'),
    X('ping-mtu', 'ts', 'Έλεγχος MTU με ping (DF bit)', 'MTU test with ping (DF bit)',
      'IOS μετράει όλο το πακέτο (1500)· οι άλλοι μόνο το payload (1472 = 1500 − 28).', 'IOS counts the whole packet (1500); others count only the payload (1472 = 1500 − 28).',
      'ping 10.20.0.1 size 1500 df-bit', 'ping 10.20.0.1 packet-size 1472 df-bit', '/ping 10.20.0.1 size=1500 do-not-fragment', 'ping 10.20.0.1 size 1472 do-not-fragment', 'ping -M do -s 1472 10.20.0.1', 'ping -f -l 1472 10.20.0.1'),
    X('trace', 'ts', 'Traceroute (από πού περνάει)', 'Traceroute (which path)',
      N, N,
      'traceroute 8.8.8.8', 'traceroute 8.8.8.8', '/tool/traceroute 8.8.8.8', 'traceroute 8.8.8.8 no-resolve', 'traceroute -n 8.8.8.8', 'tracert -d 8.8.8.8'),
    X('mtr', 'ts', 'Συνεχές traceroute με απώλειες (mtr / pathping)', 'Continuous traceroute with loss (mtr / pathping)',
      N, N,
      N, N, '/tool/traceroute 8.8.8.8 count=20', 'traceroute monitor 8.8.8.8', 'mtr -rwc 100 8.8.8.8', 'pathping 8.8.8.8'),
    X('port-test', 'ts', 'Είναι ανοιχτό ένα TCP port;', 'Is a TCP port open?',
      N, N,
      'telnet 10.0.0.5 443', 'telnet 10.0.0.5 443', '/system/telnet 10.0.0.5 port=443', 'telnet 10.0.0.5 port 443', 'nc -zv 10.0.0.5 443', 'Test-NetConnection 10.0.0.5 -Port 443'),
    X('capture', 'ts', 'Καταγραφή πακέτων (packet capture, χωρίς debug)', 'Packet capture (no debug needed)',
      'IOS-XE: Embedded Packet Capture. NX-OS ethanalyzer βλέπει μόνο κίνηση προς/από το CPU. Άνοιξε το .pcap στο Wireshark.', 'IOS-XE: Embedded Packet Capture. NX-OS ethanalyzer sees only traffic to/from the CPU. Open the .pcap in Wireshark.',
      ['monitor capture CAP interface GigabitEthernet0/1 both', 'monitor capture CAP match ipv4 host 10.0.0.5 any', 'monitor capture CAP start', 'monitor capture CAP stop', 'show monitor capture CAP buffer brief', 'monitor capture CAP export flash:cap.pcap'],
      'ethanalyzer local interface inband capture-filter "host 10.0.0.5" limit-captured-frames 100',
      ['/tool/sniffer/set filter-interface=ether1 filter-ip-address=10.0.0.5/32 file-name=cap.pcap', '/tool/sniffer/start', '/tool/sniffer/stop'],
      'monitor traffic interface ge-0/0/1 matching "host 10.0.0.5" no-resolve',
      'sudo tcpdump -ni eth0 host 10.0.0.5 -w cap.pcap',
      ['pktmon filter add -i 10.0.0.5', 'pktmon start --capture --pkt-size 0', 'pktmon stop', 'pktmon etl2pcap PktMon.etl --out cap.pcapng']),
    X('span', 'ts', 'Port mirroring (SPAN) για Wireshark', 'Port mirroring (SPAN) for Wireshark',
      N, N,
      ['configure terminal', 'monitor session 1 source interface GigabitEthernet0/1 both', 'monitor session 1 destination interface GigabitEthernet0/24'],
      ['configure terminal', 'interface Ethernet1/48', 'switchport monitor', 'monitor session 1', 'source interface Ethernet1/1 both', 'destination interface Ethernet1/48', 'no shut'],
      '/interface/ethernet/switch/set switch1 mirror-source=ether2 mirror-target=ether5',
      ['configure', 'set forwarding-options analyzer SPAN input ingress interface ge-0/0/1.0', 'set forwarding-options analyzer SPAN input egress interface ge-0/0/1.0', 'set forwarding-options analyzer SPAN output interface ge-0/0/23.0', 'commit'],
      N, N),
    X('errors', 'ts', 'Μετρητές σφαλμάτων θύρας (CRC, drops, errors)', 'Interface error counters (CRC, drops, errors)',
      'Αυξανόμενα CRC = καλώδιο/πομπός/duplex. Output drops = συμφόρηση.', 'Rising CRC = cable/optic/duplex. Output drops = congestion.',
      ['show interfaces GigabitEthernet0/1 | include error|CRC|drops', 'show interfaces counters errors'],
      'show interface counters errors',
      '/interface/ethernet/print stats',
      'show interfaces ge-0/0/1 extensive | match "error|drop|CRC"',
      ['ip -s -s link show eth0', 'sudo ethtool -S eth0'],
      'Get-NetAdapterStatistics -Name "Ethernet" | Format-List *'),
    X('clear-cnt', 'ts', 'Μηδενισμός μετρητών θύρας', 'Clear interface counters',
      'Μηδένισε και ξαναδές σε 5 λεπτά: αυξάνονται τα errors ΤΩΡΑ;', 'Clear, then check again in 5 minutes: are errors increasing NOW?',
      'clear counters GigabitEthernet0/1', 'clear counters interface Ethernet1/1', '/interface/reset-counters ether1', 'clear interfaces statistics ge-0/0/1', N, N),
    X('rate', 'ts', 'Ζωντανή κίνηση (bps/pps) σε θύρα', 'Live traffic rate (bps/pps) on a port',
      N, N,
      'show interfaces GigabitEthernet0/1 | include rate', 'show interface Ethernet1/1 | include rate', '/interface/monitor-traffic ether1', 'monitor interface ge-0/0/1', 'sar -n DEV 1 5', 'Get-Counter "\\Network Interface(*)\\Bytes Total/sec" -Continuous'),
    X('cable', 'ts', 'Έλεγχος καλωδίου (TDR)', 'Cable test (TDR)',
      N, N,
      ['test cable-diagnostics tdr interface GigabitEthernet0/1', 'show cable-diagnostics tdr interface GigabitEthernet0/1'],
      N,
      '/interface/ethernet/cable-test ether1',
      'request diagnostics tdr start interface ge-0/0/1',
      'sudo ethtool --cable-test eth0',
      N),
    X('optics', 'ts', 'SFP / οπτικά: ισχύς Tx/Rx', 'SFP / optics: Tx/Rx power',
      N, N,
      'show interfaces transceiver detail', 'show interface Ethernet1/49 transceiver details', '/interface/ethernet/monitor sfp-sfpplus1 once', 'show interfaces diagnostics optics xe-0/0/0', 'sudo ethtool -m eth0', N),
    X('listen', 'ts', 'Ανοιχτά ports / συνδέσεις στη συσκευή', 'Listening ports / connections on the device',
      N, N,
      'show control-plane host open-ports', N, '/ip/service/print', 'show system connections', 'ss -tulpn', 'Get-NetTCPConnection -State Listen'),
    X('cpu', 'ts', 'CPU και μνήμη', 'CPU and memory',
      N, N,
      ['show processes cpu sorted', 'show processes memory sorted'], 'show system resources', '/system/resource/print', 'show chassis routing-engine', 'top', 'Get-Counter "\\Processor(_Total)\\% Processor Time"'),

    // ── Wireless ──
    X('wifi-scan', 'wifi', 'Σάρωση δικτύων Wi-Fi (κανάλια, σήμα)', 'Scan Wi-Fi networks (channels, signal)',
      'MikroTik v7 με το πακέτο wifi· με το παλιό wireless: /interface/wireless/scan wlan1.', 'MikroTik v7 with the wifi package; with legacy wireless: /interface/wireless/scan wlan1.',
      N, N, '/interface/wifi/scan wifi1', N, 'nmcli device wifi list', 'netsh wlan show networks mode=bssid'),
    X('wifi-clients', 'wifi', 'Συνδεδεμένοι Wi-Fi clients', 'Connected Wi-Fi clients',
      'IOS = Catalyst 9800 WLC (IOS-XE).', 'IOS = Catalyst 9800 WLC (IOS-XE).',
      'show wireless client summary', N, '/interface/wifi/registration-table/print', N, 'iw dev wlan0 station dump', N),
    X('wifi-link', 'wifi', 'Σήμα / ταχύτητα της δικής μου σύνδεσης', 'Signal / rate of my own connection',
      N, N,
      N, N, '/interface/wifi/monitor wifi1 once', N, 'iw dev wlan0 link', 'netsh wlan show interfaces'),
    X('wifi-ap', 'wifi', 'Λίστα access points / SSID', 'List access points / SSIDs',
      N, N,
      ['show ap summary', 'show wlan summary'], N, ['/interface/wifi/print', '/interface/wifi/capsman/remote-cap/print'], N, 'nmcli -f SSID,BSSID,CHAN,SIGNAL device wifi', 'netsh wlan show profiles'),

    // ── OSPF ──
    X('ospf-cfg', 'ospf', 'Βασικό OSPF (area 0)', 'Basic OSPF (area 0)',
      'Linux = FRRouting (vtysh). Passive στις θύρες χρηστών: διαφημίζεται το δίκτυο χωρίς hellos.', 'Linux = FRRouting (vtysh). Passive on user ports: the network is advertised without hellos.',
      ['configure terminal', 'router ospf 1', 'router-id 1.1.1.1', 'network 10.0.0.0 0.0.0.255 area 0', 'passive-interface GigabitEthernet0/1'],
      ['configure terminal', 'feature ospf', 'router ospf 1', 'router-id 1.1.1.1', 'interface Ethernet1/1', 'ip router ospf 1 area 0.0.0.0'],
      ['/routing/ospf/instance/add name=default-v2 version=2 router-id=1.1.1.1', '/routing/ospf/area/add name=backbone area-id=0.0.0.0 instance=default-v2', '/routing/ospf/interface-template/add area=backbone networks=10.0.0.0/24'],
      ['configure', 'set routing-options router-id 1.1.1.1', 'set protocols ospf area 0.0.0.0 interface ge-0/0/0.0', 'set protocols ospf area 0.0.0.0 interface lo0.0 passive', 'commit'],
      ['sudo vtysh', 'configure terminal', 'router ospf', 'ospf router-id 1.1.1.1', 'network 10.0.0.0/24 area 0'],
      N),
    X('ospf-nei', 'ospf', 'Γείτονες OSPF', 'OSPF neighbours',
      'Θέλεις FULL (ή 2WAY μεταξύ DROTHER). Κόλλημα σε EXSTART/EXCHANGE = συνήθως MTU mismatch.', 'You want FULL (or 2WAY between DROTHERs). Stuck in EXSTART/EXCHANGE = usually MTU mismatch.',
      'show ip ospf neighbor', 'show ip ospf neighbors', '/routing/ospf/neighbor/print', 'show ospf neighbor', 'sudo vtysh -c "show ip ospf neighbor"', N),
    X('ospf-if', 'ospf', 'Interfaces OSPF (cost, area, DR/BDR)', 'OSPF interfaces (cost, area, DR/BDR)',
      N, N,
      'show ip ospf interface brief', 'show ip ospf interface brief', '/routing/ospf/interface/print', 'show ospf interface', 'sudo vtysh -c "show ip ospf interface"', N),
    X('ospf-routes', 'ospf', 'Routes που έμαθα από OSPF', 'Routes learned via OSPF',
      N, N,
      'show ip route ospf', 'show ip route ospf', '/ip/route/print where ospf', 'show route protocol ospf', 'sudo vtysh -c "show ip route ospf"', N),
    X('ospf-db', 'ospf', 'Βάση LSA (link-state database)', 'Link-state database (LSAs)',
      N, N,
      'show ip ospf database', 'show ip ospf database', '/routing/ospf/lsa/print', 'show ospf database', 'sudo vtysh -c "show ip ospf database"', N),
    X('ospf-default', 'ospf', 'Διαφήμιση default route μέσα στο OSPF', 'Advertise a default route into OSPF',
      N, N,
      ['configure terminal', 'router ospf 1', 'default-information originate'],
      ['configure terminal', 'router ospf 1', 'default-information originate always'],
      '/routing/ospf/instance/set default-v2 originate-default=always',
      ['configure', 'set policy-options policy-statement DEF term 1 from route-filter 0.0.0.0/0 exact', 'set policy-options policy-statement DEF term 1 then accept', 'set protocols ospf export DEF', 'commit'],
      ['sudo vtysh', 'configure terminal', 'router ospf', 'default-information originate'],
      N),
    X('ospf-proto', 'ospf', 'Σύνοψη πρωτοκόλλων δρομολόγησης', 'Routing protocol overview',
      N, N,
      'show ip protocols', 'show ip ospf', '/routing/ospf/instance/print', 'show ospf overview', 'sudo vtysh -c "show ip ospf"', N),
  ];

  // Συνώνυμα / συντομεύσεις που μετρούν στην αναζήτηση (δεν εμφανίζονται ως ξεχωριστές εντολές).
  const ALIAS = {
    'ip-brief': { linux: ['ip a', 'ip addr show'], windows: ['Get-NetIPAddress', 'ipconfig /all'], mikrotik: ['/ip address print'], junos: ['show interfaces terse | match inet'] },
    'save': { ios: ['write memory', 'wr'], nxos: ['copy run start'] },
    'mac-table': { ios: ['show mac-address-table'] },
    'arp': { ios: ['show arp'], linux: ['arp -n'], windows: ['Get-NetNeighbor'] },
    'rt-show': { linux: ['ip r', 'netstat -rn'], windows: ['Get-NetRoute'] },
    'listen': { linux: ['netstat -tulpn'], windows: ['netstat -ano'] },
    'dns-lookup': { linux: ['nslookup', 'host'], windows: ['nslookup'] },
    'trace': { mikrotik: ['/tool traceroute'] },
  };
  for (const t of DATA) t.alias = ALIAS[t.id] || null;

  // ─── Αναζήτηση ───
  const norm = s => String(s == null ? '' : s).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/ς/g, 'σ').replace(/\s+/g, ' ').trim();
  const toks = s => norm(s).split(/[\s\/=,|"'()\[\]{}:;!^#*~<>]+/).filter(Boolean);
  const lines = c => (c == null ? [] : Array.isArray(c) ? c : [c]);

  function scoreLine(qt, qn, line) {
    const lt = toks(line);
    if (!lt.length) return 0;
    let best = 0;
    // 1) Συνεχόμενη ακολουθία token-prefix (π.χ. «sh ip int br» → «show ip interface brief»)
    for (let i = 0; i < lt.length; i++) {
      let k = i, ex = 0, ok = true;
      for (let j = 0; j < qt.length; j++) {
        while (k < lt.length && lt[k][0] === '-' && qt[j][0] !== '-' && !lt[k].startsWith(qt[j])) k++;
        if (k >= lt.length || !lt[k].startsWith(qt[j])) { ok = false; break; }
        if (lt[k] === qt[j]) ex++;
        k++;
      }
      if (ok) {
        const extra = lt.length - (k - i);
        const s = 100 + (i === 0 ? 25 : 0) + ex * 3 - extra * 2 - i * 2;
        if (s > best) best = s;
        break;
      }
    }
    if (best) return Math.max(best, 50);
    // 2) Υποσυμβολοσειρά όλου του ερωτήματος
    if (qn.length >= 3 && norm(line).includes(qn)) return 45;
    // 3) Όλα τα tokens ως prefix, με οποιαδήποτε σειρά
    if (qt.every(q => lt.some(t => t.startsWith(q)))) return Math.max(25, 40 - (lt.length - qt.length));
    return 0;
  }
  function scoreText(qt, qn, txt, hi) {
    if (!txt) return 0;
    const n = norm(txt), tt = toks(txt);
    if (qn.length >= 2 && n.includes(qn)) return hi;
    if (qt.every(q => tt.some(t => t.startsWith(q)))) return hi - 8;
    return 0;
  }
  function search(q) {
    const qn = norm(q), qt = toks(q);
    if (!qt.length) return DATA.map(t => ({ id: t.id, task: t, score: 0, hits: [] }));
    const out = [];
    for (const t of DATA) {
      const hits = [];
      let cmd = 0;
      for (const v of VK) {
        let vs = 0;
        for (const l of lines(t.cmds[v]).concat(t.alias && t.alias[v] ? t.alias[v] : [])) vs = Math.max(vs, scoreLine(qt, qn, l));
        if (vs) { hits.push(v); cmd = Math.max(cmd, vs); }
      }
      const txt = Math.max(scoreText(qt, qn, t.el, 70), scoreText(qt, qn, t.en, 70), scoreText(qt, qn, t.note_el, 30), scoreText(qt, qn, t.note_en, 30));
      const score = Math.max(cmd, txt) + hits.length * 0.5 + (cmd && txt ? 5 : 0);
      if (score > 0 && (cmd || txt)) out.push({ id: t.id, task: t, score, hits });
    }
    out.sort((a, b) => b.score - a.score);
    return out;
  }

  // ─── Κατάσταση UI ───
  const LSK = 'nw-xlate-vendors';
  const ST = { q: '', cat: 'all', vend: null, copies: [] };
  function loadVend() {
    if (ST.vend) return ST.vend;
    let v = null;
    try { v = JSON.parse(localStorage.getItem(LSK) || 'null'); } catch (e) { v = null; }
    ST.vend = Array.isArray(v) && v.some(x => VK.includes(x)) ? VK.filter(k => v.includes(k)) : VK.slice();
    return ST.vend;
  }
  function saveVend() { try { localStorage.setItem(LSK, JSON.stringify(ST.vend)); } catch (e) { /* ignore */ } }

  function copyTxt(btn, txt) {
    const done = () => { const o = btn.innerHTML; btn.textContent = '✓'; setTimeout(() => { btn.innerHTML = o; }, 1200); };
    const fb = () => { try { const ta = document.createElement('textarea'); ta.value = txt; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); done(); } catch (e) { /* ignore */ } };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(txt).then(done, fb); else fb();
  }

  const css = document.createElement('style');
  css.textContent = `
  .cx-hd p{margin:4px 0 10px;color:var(--dim);font-size:12.5px;white-space:normal}
  .cx-q{width:100%;box-sizing:border-box;font:15px/1.3 ui-monospace,Menlo,Consolas,monospace;padding:11px 14px;border-radius:10px;border:1px solid var(--line);background:var(--panel2);color:var(--txt);outline:none}
  .cx-q:focus{border-color:var(--cyan)}
  .cx-chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px;align-items:center}
  .cx-chip{font:inherit;font-size:11.5px;padding:3px 10px;border-radius:999px;border:1px solid var(--line);background:rgb(var(--w) / 3%);color:var(--dim);cursor:pointer}
  .cx-chip.on{color:var(--cyan);border-color:var(--cyan);background:color-mix(in srgb,var(--cyan) 10%,transparent)}
  .cx-chip.hit{box-shadow:0 0 0 2px color-mix(in srgb,var(--green) 45%,transparent)}
  .cx-lbl{font-size:11px;color:var(--dim);margin-right:2px}
  .cx-meta{font-size:11.5px;color:var(--dim);margin:10px 2px 6px}
  .cx-grid{display:flex;flex-direction:column;gap:0;border:1px solid var(--line);border-radius:10px;overflow:hidden}
  .cx-row{display:grid;grid-template-columns:minmax(150px,1.05fr) repeat(var(--n),minmax(0,1fr));border-top:1px solid rgb(var(--w) / 6%)}
  .cx-row:first-child{border-top:0}
  .cx-row>div{padding:8px 9px;min-width:0;white-space:normal}
  .cx-row>div+div{border-left:1px solid rgb(var(--w) / 5%)}
  .cx-head{background:var(--panel2);font-size:11px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.03em}
  .cx-head .hit{color:var(--green)}
  .cx-cat{background:rgb(var(--w) / 4%);padding:8px 10px;font-size:12px;font-weight:700;color:var(--purple);border-top:1px solid var(--line);white-space:normal}
  .cx-cat .tip{display:block;font-weight:400;color:var(--dim);font-size:11.5px;margin-top:2px}
  .cx-t b{font-size:12.5px;display:block}
  .cx-t .n{font-size:11.5px;color:var(--dim);margin-top:3px}
  .cx-t .tag{margin-top:4px}
  .cx-t .mh{font-size:11px;color:var(--green);margin-top:4px}
  .cx-c.hit{background:color-mix(in srgb,var(--green) 8%,transparent);box-shadow:inset 3px 0 0 var(--green)}
  .cx-c .vl{display:none;font-size:10.5px;font-weight:700;color:var(--dim);text-transform:uppercase;margin-bottom:3px}
  .cx-c.hit .vl{color:var(--green)}
  .cx-cmd{position:relative;display:flex;gap:4px;align-items:flex-start}
  .cx-cmd code{flex:1;min-width:0;display:block;font:11.5px/1.45 ui-monospace,Menlo,Consolas,monospace;background:var(--panel2);border:1px solid rgb(var(--w) / 6%);border-radius:6px;padding:5px 7px;color:var(--txt);overflow-wrap:anywhere;white-space:pre-wrap}
  .cx-cmd code span{display:block}
  .cx-cmd code span.cm{color:var(--dim)}
  .cx-cp{flex:none;font:inherit;font-size:11px;padding:2px 5px;border-radius:6px;border:1px solid var(--line);background:rgb(var(--w) / 3%);color:var(--txt);cursor:pointer;opacity:.75}
  .cx-cp:hover{opacity:1;border-color:var(--cyan)}
  .cx-na{color:var(--dim)}
  .cx-empty{padding:18px;text-align:center;color:var(--dim);font-size:13px}
  .cx-kbd{font:11px ui-monospace,Menlo,Consolas,monospace;padding:0 5px;border:1px solid var(--line);border-radius:4px;color:var(--dim)}
  @media(max-width:700px){
    .cx-grid{border:0;gap:10px;overflow:visible}
    .cx-head{display:none}
    .cx-row{grid-template-columns:1fr;border:1px solid var(--line);border-radius:10px;background:rgb(var(--w) / 2%)}
    .cx-row>div+div{border-left:0;border-top:1px solid rgb(var(--w) / 5%)}
    .cx-c .vl{display:block}
    .cx-cat{border:0;border-radius:8px}
  }`;
  document.head.appendChild(css);

  const host = () => document.getElementById('t-xlate');

  function codeBlock(c) {
    const ls = lines(c);
    const i = ST.copies.push(ls.join('\n')) - 1;
    return `<div class="cx-cmd"><code>${ls.map(l => `<span${/^\s*(!|#)/.test(l) ? ' class="cm"' : ''}>${E(l)}</span>`).join('')}</code><button class="cx-cp" data-ci="${i}" title="${E(T('Αντιγραφή', 'Copy'))}">📋</button></div>`;
  }

  function rowHtml(t, hits, vs, showCat) {
    const cat = CATS.find(c => c.id === t.cat);
    const note = EN() ? t.note_en : t.note_el;
    const hidden = hits.filter(h => !vs.includes(h));
    let h = `<div class="cx-row"><div class="cx-t"><b>${E(EN() ? t.en : t.el)}</b>${note ? `<div class="n">💡 ${E(note)}</div>` : ''}${showCat && cat ? `<span class="tag">${E(EN() ? cat.en : cat.el)}</span>` : ''}${hidden.length ? `<div class="mh">${E(T('ταιριάζει και σε', 'also matches in'))}: ${hidden.map(k => E(VEND.find(v => v.k === k).s)).join(', ')}</div>` : ''}</div>`;
    for (const k of vs) {
      const v = VEND.find(x => x.k === k), c = t.cmds[k];
      h += `<div class="cx-c${hits.includes(k) ? ' hit' : ''}"><div class="vl">${E(v.n)}</div>${c == null ? '<span class="cx-na">—</span>' : codeBlock(c)}</div>`;
    }
    return h + '</div>';
  }

  function drawResults() {
    const el = host(); if (!el) return;
    const box = el.querySelector('.cx-res'); if (!box) return;
    const vs = loadVend();
    ST.copies = [];
    const q = ST.q.trim();
    let res = search(q);
    if (ST.cat !== 'all') res = res.filter(r => r.task.cat === ST.cat);
    const allHits = new Set(); res.forEach(r => r.hits.forEach(x => allHits.add(x)));
    el.querySelectorAll('[data-vk]').forEach(b => b.classList.toggle('hit', !!q && allHits.has(b.dataset.vk)));
    const head = `<div class="cx-row cx-head"><div>${E(T('Εργασία', 'Task'))}</div>${vs.map(k => `<div class="${q && allHits.has(k) ? 'hit' : ''}">${E(VEND.find(v => v.k === k).n)}</div>`).join('')}</div>`;
    let h = '';
    if (!res.length) h = `<div class="cx-empty">${E(T('Τίποτα δεν ταιριάζει. Δοκίμασε λιγότερες λέξεις ή συντομογραφίες (π.χ. «sh ip ro»).', 'Nothing matches. Try fewer words or abbreviations (e.g. "sh ip ro").'))}</div>`;
    else if (q) h = head + res.map(r => rowHtml(r.task, r.hits, vs, true)).join('');
    else {
      h = head;
      for (const c of CATS) {
        const rs = res.filter(r => r.task.cat === c.id);
        if (!rs.length) continue;
        h += `<div class="cx-cat">${E(EN() ? c.en : c.el)}${c.tip_el ? `<span class="tip">🎓 CCNA: ${E(EN() ? c.tip_en : c.tip_el)}</span>` : ''}</div>`;
        h += rs.map(r => rowHtml(r.task, [], vs, false)).join('');
      }
    }
    el.querySelector('.cx-meta').textContent = q
      ? T(`${res.length} αποτελέσματα για «${q}»`, `${res.length} results for "${q}"`)
      : T(`${res.length} εργασίες · ${vs.length} πλατφόρμες`, `${res.length} tasks · ${vs.length} platforms`);
    box.innerHTML = `<div class="cx-grid" style="--n:${vs.length}">${h}</div>`;
    box.querySelectorAll('[data-ci]').forEach(b => { b.onclick = () => copyTxt(b, ST.copies[+b.dataset.ci] || ''); });
  }

  function drawShell() {
    const el = host(); if (!el) return;
    const vs = loadVend();
    el.innerHTML = `<div data-noi18n>
      <div class="card cx-hd"><div class="ctitle">🔀 ${E(T('Μεταφραστής εντολών', 'Command translator'))}</div>
        <p>${E(T('Η ίδια δουλειά σε Cisco IOS, NX-OS, MikroTik (RouterOS v7), Junos, Linux και Windows. Γράψε μια εντολή από οποιονδήποτε vendor ή μια φράση — δέχεται και συντομογραφίες τύπου Cisco.', 'The same job on Cisco IOS, NX-OS, MikroTik (RouterOS v7), Junos, Linux and Windows. Type a command from any vendor or a phrase — Cisco-style abbreviations work too.'))}</p>
        <input class="cx-q" type="search" autocomplete="off" spellcheck="false" placeholder="${E(T('π.χ. sh ip int br · /ip address print · ip a · vlan · mac table', 'e.g. sh ip int br · /ip address print · ip a · vlan · mac table'))}" value="${E(ST.q)}">
        <div class="cx-chips"><span class="cx-lbl">${E(T('Πλατφόρμες', 'Platforms'))}:</span>${VEND.map(v => `<button class="cx-chip${vs.includes(v.k) ? ' on' : ''}" data-vk="${v.k}">${E(v.n)}</button>`).join('')}</div>
        <div class="cx-chips"><span class="cx-lbl">${E(T('Κατηγορία', 'Category'))}:</span><button class="cx-chip${ST.cat === 'all' ? ' on' : ''}" data-cat="all">${E(T('Όλες', 'All'))}</button>${CATS.map(c => `<button class="cx-chip${ST.cat === c.id ? ' on' : ''}" data-cat="${c.id}">${E(EN() ? c.en : c.el)}</button>`).join('')}</div>
        <div class="sm" style="margin-top:8px;color:var(--dim)"><span class="cx-kbd">/</span> ${E(T('αναζήτηση', 'search'))} · <span class="cx-kbd">Esc</span> ${E(T('καθάρισμα', 'clear'))} · ${E(T('MikroTik σε σύνταξη RouterOS v7 (/ip/address/print)· το v6 «/ip address print» ταιριάζει επίσης.', 'MikroTik in RouterOS v7 syntax (/ip/address/print); v6 "/ip address print" matches too.'))}</div>
      </div>
      <div class="cx-meta"></div>
      <div class="cx-res"></div>
    </div>`;
    const inp = el.querySelector('.cx-q');
    inp.oninput = () => { ST.q = inp.value; drawResults(); };
    inp.onkeydown = e => { if (e.key === 'Escape') { e.preventDefault(); inp.value = ''; ST.q = ''; drawResults(); } };
    el.querySelectorAll('[data-vk]').forEach(b => b.onclick = () => {
      const k = b.dataset.vk, cur = loadVend();
      let nv = cur.includes(k) ? cur.filter(x => x !== k) : VK.filter(x => x === k || cur.includes(x));
      if (!nv.length) nv = [k];
      ST.vend = nv; saveVend();
      el.querySelectorAll('[data-vk]').forEach(x => x.classList.toggle('on', nv.includes(x.dataset.vk)));
      drawResults();
    });
    el.querySelectorAll('[data-cat]').forEach(b => b.onclick = () => {
      ST.cat = b.dataset.cat;
      el.querySelectorAll('[data-cat]').forEach(x => x.classList.toggle('on', x.dataset.cat === ST.cat));
      drawResults();
    });
    drawResults();
  }

  let drawnLang = null;
  window.renderXlate = () => {
    const el = host(); if (!el) return;
    const lang = EN() ? 'en' : 'el';
    // Ξαναζωγράφισε το shell μόνο αν λείπει ή άλλαξε η γλώσσα — έτσι δεν χάνεται το focus του input.
    if (!el.querySelector('.cx-q') || drawnLang !== lang) { drawnLang = lang; drawShell(); }
  };

  document.addEventListener('keydown', e => {
    const el = host();
    if (!el || !(curTab() === 'xlate' || el.offsetParent !== null)) return;
    const a = document.activeElement;
    if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey && !(a && (a.tagName === 'INPUT' || a.tagName === 'TEXTAREA' || a.tagName === 'SELECT' || a.isContentEditable))) {
      const inp = el.querySelector('.cx-q');
      if (inp) { e.preventDefault(); inp.focus(); inp.select(); }
    }
  });

  window.CMDX = { DATA, CATS, VEND, search };
})();
