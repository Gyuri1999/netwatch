// NetWatch Academy — CCNA 200-301 (v1.1), part 1a (English): Start here, 1.0 Network Fundamentals.
// Format: see academy/FORMAT.md. Translation of academy/ccna-1.js (up to and including M1).
(function () {
  'use strict';

  // ---------- helpers for the lab regexes (they are JS strings → double backslashes) ----------
  const SP = '\\s+';
  const SH = 'sh(ow?)?\\s+';                                   // sh / sho / show
  const ip = s => s.replace(/\./g, '\\.');                     // 10.0.0.1 → 10\.0\.0\.1
  const GI = p => 'int(erface)?\\s*g(i(g(abit(ethernet)?)?)?)?\\s*' + p;   // int g0/0, interface GigabitEthernet0/0
  const FA = p => 'int(erface)?\\s*f(a(st(ethernet)?)?)?\\s*' + p;         // int f0/1, interface FastEthernet0/1
  const RX = {
    en: '^en(a(b(le?)?)?)?$',
    conf: '^conf(ig(ure)?)?\\s+t(erm(inal)?)?$',
    end: '^end$',
    exit: '^exit$',
    endx: '^(end|exit)$',
    noshut: '^no\\s+shut(down)?$',
    wr: '^(copy\\s+run(ning-config)?\\s+start(up-config)?|wr(ite)?(\\s+mem(ory)?)?)$',
    sacc: '^sw(itchport)?\\s+mode\\s+acc(ess)?$',
    strunk: '^sw(itchport)?\\s+mode\\s+tr(unk)?$',
  };

  // =====================================================================
  //                               SCENES
  // =====================================================================

  ACADEMY.scene('ccna-osi-encap', {
    w: 640, h: 290, speed: 2900,
    intro: 'The **sender** (top row) "dresses" the data in headers as it goes down the layers. The **receiver** (bottom row) "undresses" it on the way up. Press ▶.',
    nodes: [
      { id: 'a7', x: 70, y: 60, icon: '📝', label: 'Application\nL7–L5' },
      { id: 'a4', x: 190, y: 60, icon: '📦', label: 'Transport\nL4' },
      { id: 'a3', x: 310, y: 60, icon: '🧭', label: 'Network\nL3' },
      { id: 'a2', x: 430, y: 60, icon: '🔗', label: 'Data Link\nL2' },
      { id: 'a1', x: 560, y: 60, icon: '⚡', label: 'Physical\nL1' },
      { id: 'b1', x: 560, y: 220, icon: '⚡', label: 'Physical\nL1' },
      { id: 'b2', x: 430, y: 220, icon: '🔗', label: 'Data Link\nL2' },
      { id: 'b3', x: 310, y: 220, icon: '🧭', label: 'Network\nL3' },
      { id: 'b4', x: 190, y: 220, icon: '📦', label: 'Transport\nL4' },
      { id: 'b7', x: 70, y: 220, icon: '📝', label: 'Application\nL7–L5' },
    ],
    links: [['a7', 'a4'], ['a4', 'a3'], ['a3', 'a2'], ['a2', 'a1'], ['a1', 'b1', 'cable'], ['b1', 'b2'], ['b2', 'b3'], ['b3', 'b4'], ['b4', 'b7']],
    tables: [{ id: 'pdu', title: 'PDU (name of the "unit" at each layer)', head: ['Layer', 'PDU', 'What was added'], rows: [] }],
    steps: [
      { from: 'a7', to: 'a4', pkt: 'DATA', color: '#c3e88d', mark: { a7: 'hl' }, say: 'The application (e.g. a browser) creates **data**: an HTTP request.', table: { pdu: [['L7', 'Data', '—']] } },
      { from: 'a4', to: 'a3', pkt: 'TCP|DATA', color: '#ffd23f', mark: { a4: 'hl' }, say: 'Transport adds a **TCP header** (source/destination port, sequence numbers) → **segment**.', table: { pdu: [['L7', 'Data', '—'], ['L4', 'Segment', 'TCP/UDP header (ports)']] } },
      { from: 'a3', to: 'a2', pkt: 'IP|TCP|DATA', color: '#3ec5ff', mark: { a3: 'hl' }, say: 'Network adds an **IP header** (source/destination IP, TTL) → **packet**.', table: { pdu: [['L7', 'Data', '—'], ['L4', 'Segment', 'TCP/UDP header (ports)'], ['L3', 'Packet', 'IP header (IP addresses)']] } },
      { from: 'a2', to: 'a1', pkt: 'ETH|IP|TCP|DATA|FCS', color: '#b388ff', mark: { a2: 'hl' }, say: 'Data Link adds an **Ethernet header** (MAC addresses) and a **trailer (FCS)** for error checking → **frame**.', table: { pdu: [['L7', 'Data', '—'], ['L4', 'Segment', 'TCP/UDP header (ports)'], ['L3', 'Packet', 'IP header (IP addresses)'], ['L2', 'Frame', 'Ethernet header + FCS trailer']] } },
      { from: 'a1', to: 'b1', pkt: '0101101…', color: '#ff9f43', mark: { a1: 'hl', b1: 'hl' }, say: 'Physical sends the **bits** as electrical signals, light or radio waves.', table: { pdu: [['L7', 'Data', '—'], ['L4', 'Segment', 'TCP/UDP header (ports)'], ['L3', 'Packet', 'IP header (IP addresses)'], ['L2', 'Frame', 'Ethernet header + FCS trailer'], ['L1', 'Bits', 'signal on the medium']] } },
      { from: 'b1', to: 'b2', pkt: 'ETH|IP|TCP|DATA|FCS', color: '#b388ff', mark: { b2: 'ok' }, say: 'The receiver checks the **FCS**. If it is damaged, the frame is dropped. If it is fine and the destination MAC is its own, it removes the L2 header.' },
      { from: 'b2', to: 'b3', pkt: 'IP|TCP|DATA', color: '#3ec5ff', mark: { b3: 'ok' }, say: 'The destination IP is its own, so it removes the IP header. The **Protocol** field (6 = TCP) says which L4 protocol to hand it to.' },
      { from: 'b3', to: 'b4', pkt: 'TCP|DATA', color: '#ffd23f', mark: { b4: 'ok' }, say: 'TCP sees **destination port 80/443** and knows which application to deliver the data to.' },
      { from: 'b4', to: 'b7', pkt: 'DATA', color: '#c3e88d', mark: { b7: 'ok' }, say: 'The web server receives the plain HTTP request. This is **de-encapsulation**.' },
    ],
  });

  ACADEMY.scene('ccna-tcp-handshake', {
    w: 640, h: 230, speed: 2800,
    intro: '**TCP** is connection-oriented: before sending data it performs a **three-way handshake**. Watch the sequence (seq) and acknowledgment (ack) numbers.',
    nodes: [
      { id: 'c', x: 110, y: 110, icon: '💻', label: 'Client\n192.168.1.10:51000', w: 80 },
      { id: 's', x: 530, y: 110, icon: '🖥', label: 'Web server\n93.184.216.34:443', w: 80 },
    ],
    links: [['c', 's', 'Internet']],
    tables: [{ id: 'st', title: 'Connection state', head: ['Client', 'Server'], rows: [['CLOSED', 'LISTEN']] }],
    steps: [
      { from: 'c', to: 's', pkt: 'SYN seq=100', color: '#3ec5ff', say: '**SYN**: "I want to talk. I start counting from seq=100".', table: { st: [['SYN-SENT', 'LISTEN']] } },
      { from: 's', to: 'c', pkt: 'SYN-ACK seq=300 ack=101', color: '#ffd23f', say: '**SYN-ACK**: "OK, I am waiting for byte 101 (ack=101). I start from seq=300".', table: { st: [['SYN-SENT', 'SYN-RECEIVED']] } },
      { from: 'c', to: 's', pkt: 'ACK ack=301', color: '#3ddc97', say: '**ACK**: "Received". The connection is now **ESTABLISHED** on both sides.', table: { st: [['ESTABLISHED', 'ESTABLISHED']] }, mark: { c: 'ok', s: 'ok' } },
      { from: 'c', to: 's', pkt: 'DATA seq=101 (500 B)', color: '#c3e88d', say: 'The client sends 500 bytes of data.' },
      { from: 's', to: 'c', pkt: 'ACK ack=601', color: '#3ddc97', say: 'The server acknowledges: "I got everything up to 600, send 601 next". If a segment is lost, no ACK arrives and there is a **retransmission**: this is TCP reliability.' },
      { from: 'c', to: 's', pkt: 'FIN', color: '#ff9f43', say: 'Closing: the client sends **FIN**. The server replies with an ACK and its own FIN, and the client answers with an ACK (usually 4 messages).', table: { st: [['FIN-WAIT', 'CLOSE-WAIT']] } },
      { from: 's', to: 'c', pkt: 'FIN-ACK', color: '#ff9f43', say: 'After the last ACK the connection closes. A **RST**, by contrast, cuts the connection abruptly.', table: { st: [['TIME-WAIT → CLOSED', 'CLOSED']] } },
    ],
  });

  ACADEMY.scene('ccna-arp', {
    w: 640, h: 280, speed: 2800,
    intro: 'PC-A knows the **IP** of PC-B (192.168.1.20) but not its **MAC**. Without a MAC it cannot build an Ethernet frame. Solution: **ARP**.',
    nodes: [
      { id: 'a', x: 100, y: 200, icon: '💻', label: 'PC-A .10\naaaa.aaaa.aaaa', w: 80 },
      { id: 'sw', x: 320, y: 70, icon: '🔀', label: 'SW1' },
      { id: 'c', x: 320, y: 215, icon: '🖨', label: 'Printer .30\ncccc.cccc.cccc', w: 80 },
      { id: 'b', x: 540, y: 200, icon: '💻', label: 'PC-B .20\nbbbb.bbbb.bbbb', w: 80 },
    ],
    links: [['a', 'sw', 'Fa0/1'], ['sw', 'c', 'Fa0/3'], ['sw', 'b', 'Fa0/2']],
    tables: [{ id: 'arp', title: 'ARP cache of PC-A (arp -a)', head: ['IP', 'MAC', 'Type'], rows: [] }],
    steps: [
      { from: 'a', to: 'sw', pkt: 'ARP Request', color: '#ffd23f', mark: { a: 'hl' }, say: 'PC-A sends an **ARP Request**: "Who has 192.168.1.20? Tell .10". Destination MAC = **ffff.ffff.ffff** (broadcast).' },
      { from: 'sw', to: ['b', 'c'], pkt: 'broadcast', color: '#ffd23f', say: 'The switch **floods** the broadcast out of all ports in the VLAN, except the one it arrived on.' },
      { from: 'c', to: 'sw', pkt: '(ignores)', color: '#6d7f99', drop: true, mark: { c: 'info' }, say: 'The printer sees that the requested IP is not its own and **ignores** the message.' },
      { from: 'b', via: ['sw'], to: 'a', pkt: 'ARP Reply', color: '#3ddc97', mark: { b: 'ok' }, say: 'PC-B answers with an **ARP Reply** by **unicast**: "I am .20, my MAC is bbbb.bbbb.bbbb".' },
      { from: 'a', via: ['sw'], to: 'b', pkt: 'ICMP Echo', color: '#3ec5ff', mark: { a: 'ok' }, table: { arp: [['192.168.1.20', 'bbbb.bbbb.bbbb', 'dynamic']] }, say: 'PC-A stores the mapping in its **ARP cache** and now sends the ping normally. If the destination were **on another network**, it would ARP for the MAC of the **default gateway**.' },
    ],
  });

  ACADEMY.scene('ccna-switch-learning', {
    w: 640, h: 280, speed: 2900,
    intro: 'The switch starts with an **empty MAC address table**. It learns from the **source MAC** of every frame and forwards based on the **destination MAC**.',
    nodes: [
      { id: 'sw', x: 320, y: 65, icon: '🔀', label: 'SW1' },
      { id: 'a', x: 100, y: 205, icon: '💻', label: 'PC-A\nMAC …AAAA' },
      { id: 'b', x: 245, y: 215, icon: '💻', label: 'PC-B\nMAC …BBBB' },
      { id: 'c', x: 395, y: 215, icon: '💻', label: 'PC-C\nMAC …CCCC' },
      { id: 'd', x: 540, y: 205, icon: '💻', label: 'PC-D\nMAC …DDDD' },
    ],
    links: [['sw', 'a', 'Fa0/1'], ['sw', 'b', 'Fa0/2'], ['sw', 'c', 'Fa0/3'], ['sw', 'd', 'Fa0/4']],
    tables: [{ id: 'mac', title: 'MAC address table of SW1', head: ['VLAN', 'MAC', 'Port'], rows: [] }],
    steps: [
      { from: 'a', to: 'sw', pkt: 'A→C', color: '#3ec5ff', mark: { a: 'hl' }, say: 'PC-A sends a frame to PC-C. The switch looks at the **source MAC** (AAAA) and records it in the table: it is behind Fa0/1.', table: { mac: [['1', 'AAAA', 'Fa0/1']] } },
      { from: 'sw', to: ['b', 'c', 'd'], pkt: 'flood', color: '#ffd23f', say: 'It does not know the **destination MAC** (CCCC) yet: it is an **unknown unicast**, so it **floods** it out of all ports except Fa0/1.' },
      { from: 'c', via: ['sw'], to: 'a', pkt: 'C→A', color: '#3ddc97', mark: { c: 'hl' }, say: 'PC-C replies. The switch learns that CCCC is on Fa0/3. It already knows AAAA, so it **forwards** only out of Fa0/1, with no flooding.', table: { mac: [['1', 'AAAA', 'Fa0/1'], ['1', 'CCCC', 'Fa0/3']] } },
      { from: 'a', via: ['sw'], to: 'c', pkt: 'A→C', color: '#3ec5ff', mark: { a: 'ok', c: 'ok' }, say: 'From now on, A↔C traffic is **known unicast** and goes only to the right port.' },
      { from: 'd', to: 'sw', pkt: 'D→ffff (bcast)', color: '#ff9f43', mark: { d: 'hl' }, say: 'PC-D sends a **broadcast** (e.g. ARP). The switch learns DDDD on Fa0/4…', table: { mac: [['1', 'AAAA', 'Fa0/1'], ['1', 'CCCC', 'Fa0/3'], ['1', 'DDDD', 'Fa0/4']] } },
      { from: 'sw', to: ['a', 'b', 'c'], pkt: 'flood', color: '#ff9f43', say: '…and broadcasts are **always flooded** throughout the VLAN. Entries expire after **300 seconds** of inactivity (MAC aging, the Cisco default).' },
    ],
  });

  ACADEMY.scene('ccna-dhcp-dora', {
    w: 640, h: 230, speed: 2800,
    intro: 'A laptop connects and **has no IP**. DHCP provides an IP, mask, default gateway and DNS in 4 steps: **D-O-R-A**.',
    nodes: [
      { id: 'pc', x: 90, y: 110, icon: '💻', label: 'Laptop\n0.0.0.0' },
      { id: 'sw', x: 320, y: 110, icon: '🔀', label: 'SW1' },
      { id: 'srv', x: 550, y: 110, icon: '🗄', label: 'DHCP server\n192.168.1.1', w: 80 },
    ],
    links: [['pc', 'sw'], ['sw', 'srv']],
    tables: [{ id: 'lease', title: 'Laptop settings', head: ['Field', 'Value'], rows: [['IP', '—']] }],
    steps: [
      { from: 'pc', via: ['sw'], to: 'srv', pkt: 'DISCOVER', color: '#ffd23f', say: '**Discover** (broadcast, src 0.0.0.0 → dst 255.255.255.255, UDP 68→67): "Is there a DHCP server here?"' },
      { from: 'srv', via: ['sw'], to: 'pc', pkt: 'OFFER .50', color: '#3ec5ff', say: '**Offer**: "I offer you 192.168.1.50/24, gateway .1, DNS 1.1.1.1, lease 1 day".' },
      { from: 'pc', via: ['sw'], to: 'srv', pkt: 'REQUEST .50', color: '#ffd23f', say: '**Request** (broadcast, so that any other servers also learn that it picked this offer): "I want .50".' },
      { from: 'srv', via: ['sw'], to: 'pc', pkt: 'ACK', color: '#3ddc97', mark: { pc: 'ok' }, say: '**Ack**: "It is yours". The laptop configures its network card.', table: { lease: [['IP', '192.168.1.50/24'], ['Gateway', '192.168.1.1'], ['DNS', '1.1.1.1'], ['Lease', '24h']] } },
    ],
  });

  ACADEMY.scene('ccna-ipv6-slaac', {
    w: 640, h: 230, speed: 3000,
    intro: 'In IPv6 a host can build its **own** address with **SLAAC**, using **NDP** (ICMPv6) messages. There is no ARP and no broadcast.',
    nodes: [
      { id: 'pc', x: 100, y: 110, icon: '💻', label: 'PC\nfe80::…', w: 72 },
      { id: 'r1', x: 540, y: 110, icon: '📡', label: 'R1\n2001:db8:1::1/64', w: 80 },
    ],
    links: [['pc', 'r1', 'Gi0/0']],
    tables: [{ id: 'v6', title: 'Addresses of the PC', head: ['Type', 'Address'], rows: [['Link-local', 'fe80::…/64 (automatic)']] }],
    steps: [
      { from: 'pc', to: 'r1', pkt: 'RS → ff02::2', color: '#ffd23f', say: '**Router Solicitation** to the multicast address **ff02::2** (all-routers): "Is there a router? What prefix does this link use?"' },
      { from: 'r1', to: 'pc', pkt: 'RA 2001:db8:1::/64', color: '#3ec5ff', say: '**Router Advertisement** (to ff02::1 or directly): "The prefix is **2001:db8:1::/64**, I am the gateway (my link-local address)".' },
      { from: 'pc', to: 'pc', pkt: 'EUI-64 / random', color: '#b388ff', mark: { pc: 'hl' }, say: 'The PC builds the **interface ID** (64 bits): with **EUI-64** from its MAC or, on modern operating systems, a random one for privacy.' },
      { from: 'pc', to: 'r1', pkt: 'NS (DAD)', color: '#ff9f43', say: '**Duplicate Address Detection**: it sends a **Neighbor Solicitation** for its own address. If nobody answers, the address is unique.' },
      { from: 'pc', to: 'r1', pkt: 'ping 2001:db8:1::1', color: '#3ddc97', mark: { pc: 'ok' }, say: 'Ready. It finds the router\'s MAC with **NS/NA** (the IPv6 equivalent of ARP).', table: { v6: [['Link-local', 'fe80::…/64 (automatic)'], ['Global unicast', '2001:db8:1::a8bb:ccff:fe00:10/64'], ['Gateway', 'fe80::1 (link-local of R1)']] } },
    ],
  });

  ACADEMY.scene('ccna-vlan-trunk', {
    w: 640, h: 280, speed: 2900,
    intro: 'Two switches, two VLANs: **10 (Sales)** and **20 (Accounting)**. An **802.1Q trunk** carries both VLANs over a single cable, adding a **tag** to every frame.',
    nodes: [
      { id: 'sw1', x: 220, y: 70, icon: '🔀', label: 'SW1' },
      { id: 'sw2', x: 420, y: 70, icon: '🔀', label: 'SW2' },
      { id: 'p1', x: 90, y: 210, icon: '💻', label: 'PC1\nVLAN 10' },
      { id: 'p2', x: 250, y: 215, icon: '💻', label: 'PC2\nVLAN 20' },
      { id: 'p3', x: 390, y: 215, icon: '💻', label: 'PC3\nVLAN 10' },
      { id: 'p4', x: 550, y: 210, icon: '💻', label: 'PC4\nVLAN 20' },
    ],
    links: [['sw1', 'sw2', 'trunk 802.1Q'], ['sw1', 'p1', 'access 10'], ['sw1', 'p2', 'access 20'], ['sw2', 'p3', 'access 10'], ['sw2', 'p4', 'access 20']],
    steps: [
      { from: 'p1', to: 'sw1', pkt: 'frame (untagged)', color: '#3ec5ff', mark: { p1: 'info', p3: 'info' }, say: 'PC1 sends a normal Ethernet frame. It knows nothing about VLANs. The **access port** on SW1 belongs to VLAN 10.' },
      { from: 'sw1', to: 'sw2', pkt: '[802.1Q VID=10]', color: '#3ec5ff', say: 'To cross the **trunk**, SW1 inserts a **4-byte tag** with **VLAN ID = 10** between the source MAC and the EtherType.' },
      { from: 'sw2', to: 'p3', pkt: 'frame (untagged)', color: '#3ec5ff', mark: { p3: 'ok' }, say: 'SW2 reads the tag, **removes** it and sends the frame only out of VLAN 10 ports. PC4 never sees it.' },
      { from: 'p2', to: 'sw1', pkt: 'broadcast', color: '#ffd23f', mark: { p2: 'hl', p4: 'hl', p1: null, p3: null }, say: 'PC2 (VLAN 20) sends a **broadcast**. Each VLAN is a separate **broadcast domain**…' },
      { from: 'sw1', to: 'sw2', pkt: '[802.1Q VID=20]', color: '#ffd23f', say: '…so the broadcast crosses the trunk with **tag 20**…' },
      { from: 'sw2', to: 'p4', pkt: 'broadcast', color: '#ffd23f', mark: { p4: 'ok' }, say: '…and reaches **only** PC4. PC1/PC3 (VLAN 10) do not receive it. For VLAN 10 to talk to VLAN 20 you need a **router or L3 switch** (inter-VLAN routing).' },
      { from: 'sw1', to: 'sw2', pkt: 'native VLAN: untagged', color: '#b388ff', say: 'Exception: frames of the **native VLAN** (VLAN 1 by default) cross the trunk **without a tag**. Both ends must have the same native VLAN.' },
    ],
  });

  ACADEMY.scene('ccna-stp-block', {
    w: 640, h: 290, speed: 3000,
    intro: 'Three switches in a triangle: we get **redundancy**, but also a **loop**. Without STP a broadcast would circulate forever (broadcast storm). Watch how STP blocks **one** port.',
    nodes: [
      { id: 'sw1', x: 320, y: 55, icon: '🔀', label: 'SW1\nprio 24586', w: 72 },
      { id: 'sw2', x: 140, y: 215, icon: '🔀', label: 'SW2\nprio 32778', w: 72 },
      { id: 'sw3', x: 500, y: 215, icon: '🔀', label: 'SW3\nprio 32778', w: 72 },
    ],
    links: [['sw1', 'sw2', 'Gi0/1 – Gi0/1'], ['sw1', 'sw3', 'Gi0/2 – Gi0/1'], ['sw2', 'sw3', 'Gi0/2 – Gi0/2']],
    tables: [{ id: 'roles', title: 'Port roles (VLAN 10)', head: ['Switch', 'Port', 'Role', 'State'], rows: [] }],
    steps: [
      { from: 'sw2', to: ['sw1', 'sw3'], pkt: 'BPDU: root=me', color: '#ffd23f', say: 'At the start **every switch considers itself the root** and sends BPDUs with its own Bridge ID.' },
      { from: 'sw1', to: ['sw2', 'sw3'], pkt: 'BPDU root=SW1', color: '#3ddc97', mark: { sw1: 'ok' }, say: 'SW1 has the **lowest Bridge ID** (priority 24576 + VLAN 10 = 24586), so it becomes the **root bridge**. All ports of the root are **designated**.', table: { roles: [['SW1', 'Gi0/1', 'Designated', 'Forwarding'], ['SW1', 'Gi0/2', 'Designated', 'Forwarding']] } },
      { from: 'sw2', to: 'sw1', pkt: 'cost 4 → root', color: '#3ec5ff', mark: { sw2: 'info', sw3: 'info' }, say: 'Every non-root switch picks **one root port**: the port with the lowest cost to the root. For SW2 and SW3 the direct 1 Gbps link has a cost of **4**.', table: { roles: [['SW1', 'Gi0/1', 'Designated', 'Forwarding'], ['SW1', 'Gi0/2', 'Designated', 'Forwarding'], ['SW2', 'Gi0/1', 'Root', 'Forwarding'], ['SW3', 'Gi0/1', 'Root', 'Forwarding']] } },
      { from: 'sw2', to: 'sw3', pkt: 'BPDU cost 4', color: '#ffd23f', say: 'On the SW2–SW3 link one side must become **designated**. Both advertise a root cost of 4: a tie, so the **lowest Bridge ID** wins. The priority is the same, so the lower MAC decides, which here is SW2\'s.' },
      { from: 'sw2', to: 'sw3', pkt: 'data frame', color: '#ff3b5c', drop: true, mark: { sw3: 'bad' }, say: 'Gi0/2 on SW3 becomes **Alternate (blocking/discarding)**: it does not forward data, but keeps **listening for BPDUs**. The loop is broken!', table: { roles: [['SW1', 'Gi0/1', 'Designated', 'Forwarding'], ['SW1', 'Gi0/2', 'Designated', 'Forwarding'], ['SW2', 'Gi0/1', 'Root', 'Forwarding'], ['SW2', 'Gi0/2', 'Designated', 'Forwarding'], ['SW3', 'Gi0/1', 'Root', 'Forwarding'], ['SW3', 'Gi0/2', 'Alternate', 'Blocking']] } },
      { from: 'sw1', to: 'sw3', pkt: '✖ link down', color: '#ff3b5c', drop: true, mark: { sw3: 'hl' }, say: 'If the SW1–SW3 link goes down, SW3 unblocks Gi0/2, which becomes the new root port. With **RSTP** convergence takes about 1–2 s instead of the 30–50 s of classic STP.', table: { roles: [['SW1', 'Gi0/1', 'Designated', 'Forwarding'], ['SW2', 'Gi0/1', 'Root', 'Forwarding'], ['SW2', 'Gi0/2', 'Designated', 'Forwarding'], ['SW3', 'Gi0/2', 'Root', 'Forwarding']] } },
    ],
  });

  ACADEMY.scene('ccna-etherchannel', {
    w: 640, h: 270, speed: 2900,
    intro: 'Two 1 Gbps cables between SW1 and SW2. **Without** EtherChannel, STP would block one of them. **With** EtherChannel (LACP) they become one logical link, **Port-channel 1**.',
    nodes: [
      { id: 'sw1', x: 110, y: 130, icon: '🔀', label: 'SW1' },
      { id: 'l1', x: 320, y: 55, icon: '🔗', label: 'Gi0/1 ↔ Gi0/1', w: 96 },
      { id: 'l2', x: 320, y: 205, icon: '🔗', label: 'Gi0/2 ↔ Gi0/2', w: 96 },
      { id: 'sw2', x: 530, y: 130, icon: '🔀', label: 'SW2' },
    ],
    links: [['sw1', 'l1'], ['l1', 'sw2'], ['sw1', 'l2'], ['l2', 'sw2']],
    tables: [{ id: 'po', title: 'show etherchannel summary (SW1)', head: ['Group', 'Port-channel', 'Protocol', 'Ports'], rows: [] }],
    steps: [
      { from: 'sw1', via: ['l2'], to: 'sw2', pkt: 'STP: blocked', color: '#ff3b5c', drop: true, mark: { l2: 'bad' }, say: 'Without EtherChannel: two parallel links mean a loop, so STP **blocks** one. You pay for 2 Gbps and use 1.' },
      { from: 'sw1', via: ['l1'], to: 'sw2', pkt: 'LACPDU (active)', color: '#ffd23f', mark: { l2: null }, say: 'We configure `channel-group 1 mode active`. SW1 sends **LACPDUs** on every member.' },
      { from: 'sw2', via: ['l2'], to: 'sw1', pkt: 'LACPDU', color: '#ffd23f', say: 'SW2 (active or passive) answers. They check that the settings **match**: speed, duplex, access VLAN or trunk/allowed/native VLANs.' },
      { from: 'sw1', to: 'sw2', pkt: 'Po1 UP', color: '#3ddc97', mark: { sw1: 'ok', sw2: 'ok', l1: 'ok', l2: 'ok' }, say: '**Po1** is created. STP sees it as **one** link, so it blocks nothing.', table: { po: [['1', 'Po1(SU)', 'LACP', 'Gi0/1(P) Gi0/2(P)']] } },
      { from: 'sw1', via: ['l1'], to: 'sw2', pkt: 'flow A (hash→1)', color: '#3ec5ff', say: '**Load balancing** is done per flow using a **hash** (e.g. src-dst IP or MAC). Flow A always goes over link 1…' },
      { from: 'sw1', via: ['l2'], to: 'sw2', pkt: 'flow B (hash→2)', color: '#b388ff', say: '…and flow B over link 2. A single download does **not** exceed 1 Gbps: the gain is in aggregate, not per flow.' },
      { from: 'sw1', via: ['l2'], to: 'sw2', pkt: 'flow A (moved)', color: '#3ec5ff', mark: { l1: 'bad' }, say: 'Link 1 goes down: traffic moves to link 2 **without** an STP recalculation. Po1 stays up.', table: { po: [['1', 'Po1(SU)', 'LACP', 'Gi0/1(D) Gi0/2(P)']] } },
    ],
  });

  ACADEMY.scene('ccna-capwap', {
    w: 640, h: 280, speed: 3000,
    intro: 'A **lightweight AP** does not work on its own: it gets its configuration from a **WLC** through a **CAPWAP** tunnel. This is the **split-MAC** model.',
    nodes: [
      { id: 'cl', x: 70, y: 215, icon: '📱', label: 'Client\nSSID Corp' },
      { id: 'ap', x: 210, y: 215, icon: '📶', label: 'LAP\n(local mode)' },
      { id: 'sw', x: 360, y: 215, icon: '🔀', label: 'Access SW\naccess port' },
      { id: 'wlc', x: 540, y: 75, icon: '🎛', label: 'WLC\n10.0.99.10' },
      { id: 'core', x: 560, y: 215, icon: '🔀', label: 'Core\nVLANs 10,20' },
    ],
    links: [['cl', 'ap', 'wifi'], ['ap', 'sw'], ['sw', 'core'], ['core', 'wlc', 'trunk / LAG']],
    steps: [
      { from: 'ap', via: ['sw', 'core'], to: 'wlc', pkt: 'Discovery', color: '#ffd23f', mark: { ap: 'hl' }, say: 'The AP gets an IP via DHCP and looks for a WLC (e.g. DHCP **option 43**, DNS `CISCO-CAPWAP-CONTROLLER`, or a broadcast on the same subnet).' },
      { from: 'wlc', via: ['core', 'sw'], to: 'ap', pkt: 'Join (DTLS)', color: '#3ec5ff', say: 'Join: the AP and the WLC set up an **encrypted (DTLS) control tunnel** on **UDP 5246**. The WLC sends firmware, SSIDs, channels and power.' },
      { from: 'cl', to: 'ap', pkt: 'Association', color: '#b388ff', mark: { wlc: 'ok', ap: 'ok' }, say: 'The client connects to the SSID. The **real-time** parts (beacons, ACKs, over-the-air encryption) are handled by the AP.' },
      { from: 'ap', via: ['sw', 'core'], to: 'wlc', pkt: 'CAPWAP data :5247', color: '#3ddc97', say: 'In **local mode** the client\'s traffic goes into a **CAPWAP data tunnel (UDP 5247)** all the way to the WLC. That is why the AP only needs an **access port**.' },
      { from: 'wlc', to: 'core', pkt: 'VLAN 10', color: '#3ddc97', mark: { cl: 'ok' }, say: 'The WLC puts the traffic onto the **VLAN** mapped to the SSID, over a **trunk** (often a LAG) to the core. With **FlexConnect** the AP would drop it off locally at the switch.' },
    ],
  });

  ACADEMY.scene('ccna-routing-lookup', {
    w: 640, h: 280, speed: 3000,
    intro: 'R1 receives a packet for **10.2.2.50**. Watch how it picks a route using **longest prefix match** in the routing table.',
    nodes: [
      { id: 'pc', x: 70, y: 140, icon: '💻', label: 'PC\n192.168.1.10' },
      { id: 'r1', x: 230, y: 140, icon: '📡', label: 'R1' },
      { id: 'r2', x: 420, y: 60, icon: '📡', label: 'R2\n10.0.12.2' },
      { id: 'r3', x: 420, y: 220, icon: '📡', label: 'R3\n10.0.13.3' },
      { id: 'srv', x: 575, y: 60, icon: '🗄', label: 'Server\n10.2.2.50' },
      { id: 'isp', x: 575, y: 220, icon: '☁️', label: 'ISP' },
    ],
    links: [['pc', 'r1', 'Gi0/0'], ['r1', 'r2', 'Gi0/1'], ['r1', 'r3', 'Gi0/2'], ['r2', 'srv'], ['r3', 'isp']],
    tables: [{ id: 'rt', title: 'show ip route (R1)', head: ['Code', 'Prefix', 'AD/metric', 'Next hop'], rows: [
      ['C', '192.168.1.0/24', '—', 'Gi0/0'], ['S', '10.2.0.0/16', '1/0', '10.0.13.3'], ['O', '10.2.2.0/24', '110/2', '10.0.12.2'], ['S*', '0.0.0.0/0', '1/0', '10.0.13.3']] }],
    steps: [
      { from: 'pc', to: 'r1', pkt: 'dst 10.2.2.50', color: '#3ec5ff', mark: { r1: 'hl' }, say: 'The packet reaches R1. The router looks **only at the destination IP** and searches for the entries that match it.' },
      { from: 'r1', to: 'r1', pkt: '3 matches', color: '#ffd23f', say: '**Three** match: 0.0.0.0/0 (everything), 10.2.0.0/16 and 10.2.2.0/24. 192.168.1.0/24 does not match.' },
      { from: 'r1', to: 'r1', pkt: '/24 wins', color: '#3ddc97', say: 'The **longest prefix (/24)** wins, i.e. the most specific one, **even though** the static /16 has a better AD (1 vs 110). AD and metric are compared only for the **same** prefix.' },
      { from: 'r1', via: ['r2'], to: 'srv', pkt: 'via 10.0.12.2', color: '#3ddc97', mark: { r2: 'ok', srv: 'ok' }, say: 'Forwarded out **Gi0/1 to R2**. R1 rewrites the L2 header (new MACs) and decrements the **TTL** by 1. The IPs stay the same.' },
      { from: 'pc', via: ['r1', 'r3'], to: 'isp', pkt: 'dst 8.8.8.8', color: '#b388ff', mark: { r3: 'info', isp: 'info' }, say: 'A packet for 8.8.8.8: **only** 0.0.0.0/0 matches, so it leaves via the **gateway of last resort** (R3). Without a default route it would be dropped (ICMP unreachable).' },
    ],
  });

  ACADEMY.scene('ccna-ospf-neighbors', {
    w: 640, h: 250, speed: 3000,
    intro: 'Two routers running OSPF on the same link. Watch the **neighbor states**, from Down to **Full**.',
    nodes: [
      { id: 'r1', x: 120, y: 120, icon: '📡', label: 'R1\nRID 1.1.1.1' },
      { id: 'r2', x: 520, y: 120, icon: '📡', label: 'R2\nRID 2.2.2.2' },
    ],
    links: [['r1', 'r2', 'Gi0/0 10.0.12.0/30 area 0']],
    tables: [{ id: 'nb', title: 'show ip ospf neighbor', head: ['On', 'Neighbor ID', 'State'], rows: [['R1', '—', 'DOWN']] }],
    steps: [
      { from: 'r1', to: 'r2', pkt: 'Hello → 224.0.0.5', color: '#ffd23f', say: 'R1 sends a **Hello** to the multicast address **224.0.0.5** (every 10 s on Ethernet). It contains the router-id, area, timers, mask and priority.', table: { nb: [['R2', '1.1.1.1', 'INIT']] } },
      { from: 'r2', to: 'r1', pkt: 'Hello (seen 1.1.1.1)', color: '#ffd23f', say: 'R2 replies with a Hello that **contains R1\'s RID** in its neighbor list. R1 sees itself, so the state is **2-WAY**. This is where area, subnet, hello/dead timers and authentication are checked for a match.', table: { nb: [['R1', '2.2.2.2', '2WAY'], ['R2', '1.1.1.1', '2WAY']] } },
      { from: 'r2', to: 'r1', pkt: 'DBD (master?)', color: '#3ec5ff', say: '**ExStart**: they decide who is master (the higher RID, here R2) for the exchange.', table: { nb: [['R1', '2.2.2.2', 'EXSTART'], ['R2', '1.1.1.1', 'EXSTART']] } },
      { from: 'r1', to: 'r2', pkt: 'DBD (LSDB summary)', color: '#3ec5ff', say: '**Exchange**: they swap **DBDs** (Database Description packets), i.e. a "table of contents" of the LSDB without the details.', table: { nb: [['R1', '2.2.2.2', 'EXCHANGE'], ['R2', '1.1.1.1', 'EXCHANGE']] } },
      { from: 'r1', to: 'r2', pkt: 'LSR', color: '#b388ff', say: '**Loading**: R1 sees LSAs it does not have and requests them with an **LSR** (Link-State Request).', table: { nb: [['R1', '2.2.2.2', 'LOADING'], ['R2', '1.1.1.1', 'EXCHANGE']] } },
      { from: 'r2', to: 'r1', pkt: 'LSU (LSAs)', color: '#b388ff', say: 'R2 sends the full LSAs in an **LSU** (Link-State Update). R1 acknowledges with an **LSAck**.' },
      { from: 'r1', to: 'r2', pkt: 'LSAck', color: '#3ddc97', mark: { r1: 'ok', r2: 'ok' }, say: '**FULL**: the LSDBs are identical. Each router runs **SPF (Dijkstra)** and installs the best routes in the routing table with code **O**.', table: { nb: [['R1', '2.2.2.2', 'FULL'], ['R2', '1.1.1.1', 'FULL']] } },
      { from: 'r1', to: 'r2', pkt: 'Hello (keepalive)', color: '#ffd23f', say: 'Hellos continue. If the **dead interval** (40 s, i.e. 4× hello) passes without a Hello, the adjacency goes down.' },
    ],
  });

  ACADEMY.scene('ccna-hsrp-failover', {
    w: 640, h: 290, speed: 3000,
    intro: 'The PCs use gateway **192.168.1.254**: a **virtual** IP shared by two routers using **HSRP**. What happens when the active router fails?',
    nodes: [
      { id: 'pc', x: 70, y: 145, icon: '💻', label: 'PC\nGW .254' },
      { id: 'sw', x: 210, y: 145, icon: '🔀', label: 'SW1' },
      { id: 'r1', x: 380, y: 60, icon: '📡', label: 'R1 .1\nprio 110' },
      { id: 'r2', x: 380, y: 230, icon: '📡', label: 'R2 .2\nprio 100' },
      { id: 'net', x: 565, y: 145, icon: '☁️', label: 'Internet' },
    ],
    links: [['pc', 'sw'], ['sw', 'r1'], ['sw', 'r2'], ['r1', 'net'], ['r2', 'net']],
    tables: [{ id: 'hs', title: 'show standby brief', head: ['Router', 'Grp', 'Prio', 'State', 'Virtual IP'], rows: [['R1', '1', '110', 'Active', '192.168.1.254'], ['R2', '1', '100', 'Standby', '192.168.1.254']] }],
    steps: [
      { from: 'r1', via: ['sw'], to: 'r2', pkt: 'Hello (Active)', color: '#ffd23f', mark: { r1: 'ok', r2: 'info' }, say: 'The routers exchange **HSRP Hellos** (every 3 s). R1 has the higher priority, so it is **Active** and answers for .254 and the virtual MAC **0000.0c07.ac01**.' },
      { from: 'pc', via: ['sw', 'r1'], to: 'net', pkt: 'dst MAC 0000.0c07.ac01', color: '#3ec5ff', say: 'The PC sends to its gateway: the ARP for .254 returned the **virtual MAC**, so traffic goes to the Active router (R1).' },
      { from: 'r1', to: 'sw', pkt: '✖ R1 down', color: '#ff3b5c', drop: true, mark: { r1: 'bad' }, say: 'R1 fails. Its Hellos stop.' },
      { from: 'r2', to: 'sw', pkt: 'Hello (Active) + GARP', color: '#ffd23f', mark: { r2: 'ok' }, say: 'After the **hold time (10 s)** R2 becomes **Active** and takes over the same virtual IP and MAC. It sends a gratuitous ARP so the switches update their MAC tables.', table: { hs: [['R1', '1', '110', 'Init (down)', '192.168.1.254'], ['R2', '1', '100', 'Active', '192.168.1.254']] } },
      { from: 'pc', via: ['sw', 'r2'], to: 'net', pkt: 'same GW, new path', color: '#3ddc97', mark: { pc: 'ok' }, say: 'The PC **changed nothing**: same gateway IP, same MAC. That is the point of a **FHRP**. When R1 comes back it becomes Active again **only** if `standby 1 preempt` is configured.' },
    ],
  });


  // =====================================================================
  //                     MODULE 0 — Start here
  // =====================================================================
  const M0 = {
    id: 'ccna-0', order: 0, title: 'Start here', exam: 'Preparation: the 200-301 exam and a study plan',
    desc: 'What the CCNA is, what the exam looks like, how to study, and your first lab in Cisco IOS.',
    lessons: [
      {
        id: 'ccna-0-1', title: 'What the CCNA is and what the 200-301 exam looks like', minutes: 12,
        goal: 'Know what the CCNA certifies, the 6 exam domains with their weights, the exam format and what to expect on exam day.',
        blocks: [
          { t: 'text', md: 'The **CCNA (Cisco Certified Network Associate)** is the best-known networking certification for beginners and intermediates. It proves that you can **set up, configure and troubleshoot** a small-to-medium network: switches, routers, Wi-Fi, IP addressing, basic security and automation.\n\nTo earn it you pass **one** exam, the **200-301 CCNA**. There are no formal prerequisites: you start from zero, just like here.\n\nThink of the network as a **city post office**: the **switches** deliver letters within the neighborhood, the **routers** send them from city to city, and the **addresses** (MAC, IP) are the home address and the recipient\'s address. Throughout the course we will come back to this picture.' },
          { t: 'text', md: '### The 6 exam domains (blueprint v1.1)' },
          { t: 'table', head: ['Domain', 'Weight', 'What it covers', 'Where here'], rows: [
            ['1.0 Network Fundamentals', '20%', 'OSI/TCP-IP, cabling, IPv4/IPv6, subnetting, Wi-Fi basics, virtualization, switching', 'Module 1'],
            ['2.0 Network Access', '20%', 'VLANs, trunks, CDP/LLDP, EtherChannel, STP/RSTP, WLAN architectures', 'Module 2'],
            ['3.0 IP Connectivity', '25%', 'Routing table, static routes, OSPFv2, FHRP', 'Module 3'],
            ['4.0 IP Services', '10%', 'NAT, NTP, DHCP, DNS, SNMP, Syslog, QoS, SSH, TFTP/FTP', 'Later modules'],
            ['5.0 Security Fundamentals', '15%', 'ACLs, port security, DHCP snooping, DAI, AAA, WPA2/WPA3, VPN', 'Later modules'],
            ['6.0 Automation & Programmability', '10%', 'SDN, controllers, REST APIs, JSON, Ansible/Terraform, AI/ML in network operations', 'Later modules'],
          ] },
          { t: 'tip', md: '**IP Connectivity (25%)** together with **Fundamentals** and **Network Access** make up **65%** of the exam. If you master them, you have done most of the work.' },
          { t: 'text', md: '### The exam format\n- **Duration:** 120 minutes.\n- **Questions:** about 100, but the number **varies** from exam to exam. Cisco does not commit to a fixed number.\n- **Language:** English (also available in Japanese). That is why we keep the technical terms in English throughout.\n- **Where:** at a **Pearson VUE** test center or online from home (**OnVUE**, with a camera and a proctor).\n- **Cost:** about 300 USD + taxes. Check the current price on Cisco\'s website.\n- **Validity:** 3 years. Renewed with a new exam or with **Continuing Education credits**.' },
          { t: 'table', head: ['Question type', 'What it is', 'Tip'], rows: [
            ['Multiple choice (single answer)', 'The classic question', 'Eliminate the obviously wrong answers first'],
            ['Multiple choice (multiple answers)', '"Choose two/three"', 'The question tells you **how many** to pick'],
            ['Drag and drop', 'Match terms to definitions or put steps in order', 'Very common for definitions: AP modes, port roles, AD'],
            ['Simulation / simlet', 'Simulated CLI: you configure or read `show` commands', 'Practice the CLI, not just theory'],
            ['Testlet', 'A scenario with several questions', 'Read the diagram carefully'],
          ] },
          { t: 'warn', md: 'In the Cisco exam you **cannot go back** to a previous question. Once you press Next, the answer is locked. Do not leave blanks: there is **no negative marking**.' },
          { t: 'exam', md: 'The score is on a scale (roughly 300–1000). Cisco **does not publish the passing score** and it may change. Something around **825/1000** is often quoted, but it is an **unofficial estimate**. Aim for **85%+** on practice tests to have a safety margin.' },
          { t: 'quiz', q: 'Which exam domain has the **greatest** weight in the 200-301?', opts: ['Network Fundamentals', 'Network Access', 'IP Connectivity', 'Security Fundamentals'], ok: 2, why: '**3.0 IP Connectivity** is 25%. Fundamentals and Access are 20% each, Security 15%.' },
          { t: 'quiz', q: 'What is true about the 200-301 passing score?', opts: ['It is exactly 700/1000 and is published', 'Cisco does not publish it, and ~825 is an unofficial estimate', 'You need 100% on the simulations', 'It is 50% of the questions'], ok: 1, why: 'Cisco does **not** officially announce the passing score and may change it. ~825 circulates as an estimate.' },
        ],
      },
      {
        id: 'ccna-0-2', title: 'How to study: Packet Tracer, a plan and your first IOS lab', minutes: 18,
        goal: 'Set up practice tools (Packet Tracer), have a realistic 12–16 week plan and find your way around the basic modes of Cisco IOS.',
        blocks: [
          { t: 'text', md: 'You **cannot** pass the CCNA by reading alone. The exam has simulations and questions that show the output of `show` commands. You need **hands on the keyboard**.\n\n### Practice tools\n- **Cisco Packet Tracer**: a free simulator from the Cisco Networking Academy (NetAcad). It needs a free account. It covers almost all CCNA labs. **Start here.**\n- **Cisco Modeling Labs (CML)**: real IOS images, paid (there is also a free edition with limited nodes).\n- **GNS3 / EVE-NG**: free emulators. They need your own images and more setup.\n- **Used hardware** (e.g. 2960 switches, ISR routers): optional, not required.\n- The **guided labs** in this course (🖥) for quick practice of the syntax.' },
          { t: 'table', head: ['Week', 'Topic', 'Practice'], rows: [
            ['1', 'Start here, OSI/TCP-IP, cabling', 'Install Packet Tracer, first router lab'],
            ['2–3', 'IPv4 & **subnetting** (every day!)', '15 minutes of subnetting every day until the exam'],
            ['4', 'IPv6, Wi-Fi basics, virtualization, switching', 'MAC table, ARP in Packet Tracer'],
            ['5–6', 'VLANs, trunks, inter-VLAN, CDP/LLDP, EtherChannel', 'Network with 2 switches + router-on-a-stick'],
            ['7', 'STP / RSTP, WLAN', 'Blocked port, changing the root bridge'],
            ['8–9', 'Routing, static, OSPF, HSRP', 'Network with 3 routers running OSPF'],
            ['10–11', 'IP Services, Security, Automation', 'NAT, ACLs, SSH, DHCP'],
            ['12+', 'Review, practice exams, weak spots', 'Full timed practice tests'],
          ] },
          { t: 'tip', md: '**Method:** read the lesson → do the lab → write numbers and definitions on flashcards (e.g. Anki): AD values, port numbers, STP costs. A little **every day** pays off far more than 8 hours on Saturday.' },
          { t: 'text', md: '### Cisco IOS modes\nIOS has "floors" with different privileges. The **prompt** tells you where you are:\n- `Router>`: **User EXEC**. Only basic viewing commands, like ping.\n- `Router#`: **Privileged EXEC** (enter with `enable`). All `show`, `copy`, `reload`.\n- `Router(config)#`: **Global configuration** (`configure terminal`). Changes for the whole device.\n- `Router(config-if)#`: **Interface configuration** (`interface g0/0`). Changes for one port.\n- `Router(config-line)#`, `Router(config-router)#` etc. for access lines and routing protocols.\n\nWith `exit` you go up one level. With `end` or **Ctrl+Z** you go straight back to `#`. **?** shows help and **Tab** completes commands. Commands accept **abbreviations** as long as they are not ambiguous: `conf t`, `int g0/0`, `sh ip int br`.' },
          { t: 'code', lang: 'cisco', title: 'Basic router configuration', code: 'enable\nconfigure terminal\nhostname R1\nenable secret Cl@ss123\nno ip domain-lookup\ninterface GigabitEthernet0/0\n description LAN\n ip address 192.168.1.1 255.255.255.0\n no shutdown\nexit\nline console 0\n password cisco\n login\nend\ncopy running-config startup-config',
            explain: '- `enable`: from `>` to `#`.\n- `configure terminal`: enter global config.\n- `hostname R1`: the device name, which also changes the prompt.\n- `enable secret …`: password for `enable`, stored as a hash. Preferred over the old `enable password`.\n- `no ip domain-lookup`: if you mistype a command, the router will not try to "resolve" it as a hostname through DNS (saves you waiting).\n- `interface …` / `ip address …`: IP and mask on the port.\n- `no shutdown`: **router** ports are **administratively down** by default. Without this, nothing works!\n- `line console 0` + `password` + `login`: password on the console.\n- `copy running-config startup-config`: the **running-config** lives in RAM and is lost on reload. The **startup-config** is in NVRAM.' },
          { t: 'cli', title: 'Lab: your first router', prompt: 'Router>', banner: 'Cisco IOS Software, ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M)\nPress RETURN to get started!',
            steps: [
              { task: 'Enter **privileged EXEC** mode.', expect: RX.en, ans: 'enable', next: 'Router#' },
              { task: 'Enter **global configuration** mode.', expect: RX.conf, ans: 'configure terminal', out: 'Enter configuration commands, one per line.  End with CNTL/Z.', next: 'Router(config)#' },
              { task: 'Name the router **R1**.', expect: '^host(name)?\\s+R1$', ans: 'hostname R1', next: 'R1(config)#' },
              { task: 'Enter the configuration of port **GigabitEthernet0/0**.', expect: '^' + GI('0/0') + '$', ans: 'interface g0/0', next: 'R1(config-if)#' },
              { task: 'Give it IP **192.168.1.1** with mask **/24**.', expect: '^ip\\s+add(r(ess)?)?\\s+' + ip('192.168.1.1') + '\\s+' + ip('255.255.255.0') + '$', ans: 'ip address 192.168.1.1 255.255.255.0' },
              { task: 'Enable the port.', expect: RX.noshut, ans: 'no shutdown', out: '%LINK-5-CHANGED: Interface GigabitEthernet0/0, changed state to up\n%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0, changed state to up' },
              { task: 'Go straight back to privileged EXEC.', expect: RX.end, ans: 'end', out: '%SYS-5-CONFIG_I: Configured from console by console', next: 'R1#' },
              { task: 'View a summary of the interfaces (`show ip interface brief`).', expect: '^' + SH + 'ip\\s+int(erface)?\\s+br(ief)?$', ans: 'show ip interface brief',
                out: 'Interface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet0/0     192.168.1.1     YES manual up                    up\nGigabitEthernet0/1     unassigned      YES unset  administratively down down\nGigabitEthernet0/2     unassigned      YES unset  administratively down down' },
              { task: 'Save the configuration so it survives a reload.', expect: RX.wr, ans: 'copy running-config startup-config', out: 'Destination filename [startup-config]?\nBuilding configuration...\n[OK]' },
            ], done: 'You just did the most common procedure in the Cisco world. Notice in the output: Gi0/1 is **administratively down** because we did not give it `no shutdown`.' },
          { t: 'exam', md: 'Learn to read the **Status/Protocol** columns of `show ip interface brief`:\n- `up/up`: all good.\n- `administratively down/down`: `no shutdown` is missing.\n- `down/down`: a problem at **L1** (cable, the other end is shut down).\n- `up/down`: a problem at **L2** (e.g. encapsulation mismatch on a serial link, keepalives).' },
          { t: 'quiz', q: 'Which mode are you in when the prompt is `R1(config-if)#`?', opts: ['User EXEC', 'Privileged EXEC', 'Global configuration', 'Interface configuration'], ok: 3, why: '`(config-if)` means settings for one specific port.' },
          { t: 'quiz', q: 'You made changes and the router reloaded. Everything was lost. What did you forget?', opts: ['`no shutdown`', '`copy running-config startup-config`', '`enable secret`', '`end`'], ok: 1, why: 'The **running-config** is in RAM. Without saving to the **startup-config** (NVRAM) it is lost on reload.' },
        ],
      },
    ],
  };

  // =====================================================================
  //              MODULE 1 — 1.0 Network Fundamentals (20%)
  // =====================================================================
  const M1 = {
    id: 'ccna-1', order: 1, title: '1.0 Network Fundamentals (20%)', exam: '1.0 Network Fundamentals (20%)',
    desc: 'The foundations: devices, the OSI/TCP-IP models, cabling, topologies, TCP/UDP, IPv4 & subnetting, IPv6, Wi-Fi, virtualization and switching.',
    lessons: [
      {
        id: 'ccna-1-1', title: 'The building blocks of a network', minutes: 12,
        goal: 'Recognize the role of each device: router, L2/L3 switch, next-gen firewall & IPS, access point, WLC, endpoints, servers, and know what PoE is.',
        blocks: [
          { t: 'text', md: 'Before the protocols, let\'s meet the "players". In the city analogy:\n- **Endpoints** (PCs, phones, IP phones, cameras, IoT): the **residents** who send and receive.\n- **Servers**: the **shops** that serve requests (web, email, files, DHCP, DNS).\n- **Switch (L2)**: the **neighborhood mail carrier**. It connects devices on the **same LAN** and forwards frames based on the **MAC**.\n- **Router (L3)**: the **sorting center** that sends packets **between networks** based on the **IP**. It is also the **default gateway** of the hosts.\n- **L3 switch (multilayer)**: a switch that can also route (e.g. between VLANs) in hardware, at high speed.' },
          { t: 'table', head: ['Device', 'OSI layer', 'Decides based on', 'Main role'], rows: [
            ['Hub (legacy)', 'L1', 'nothing: repeats bits', 'One collision domain for everyone'],
            ['Switch', 'L2', 'Destination **MAC**', 'Each port = a separate collision domain'],
            ['Router', 'L3', 'Destination **IP**', 'Separates broadcast domains, routing between networks'],
            ['L3 switch', 'L2 + L3', 'MAC and IP', 'Switching + inter-VLAN routing'],
            ['Next-gen firewall (NGFW)', 'L3–L7', 'Rules, applications, users', 'Stateful filtering, application awareness, IPS, URL filtering'],
            ['IPS', 'L3–L7', 'Signatures & anomalies', 'Detects **and blocks** attacks inline (an IDS only alerts)'],
            ['Access Point (AP)', 'L1–L2', 'MAC (802.11)', 'Connects wireless clients to the wired network'],
            ['WLC', '—', '—', 'Central management of many APs'],
          ] },
          { t: 'text', md: '### Firewall: stateful\nA **stateful firewall** remembers connections that were started from the inside and automatically lets their replies back in. It blocks anything started from the outside unless explicitly allowed. A **NGFW** also performs **deep packet inspection**: it recognizes applications (e.g. "this is Netflix, not just TCP 443"), integrates an **IPS**, and filters URLs and malware.\n\n### PoE (Power over Ethernet)\n**PoE** delivers **power over the same Ethernet cable** to APs, IP phones and cameras. The switch is the **PSE** (Power Sourcing Equipment) and the device is the **PD** (Powered Device). No need for power outlets in the ceiling!' },
          { t: 'table', head: ['Standard', 'Name', 'Power at the switch port (approx.)'], rows: [
            ['802.3af', 'PoE', '15.4 W'], ['802.3at', 'PoE+', '30 W'], ['802.3bt', 'UPoE / PoE++ (Type 3/4)', '60 W / ~90–100 W'],
          ] },
          { t: 'exam', md: 'Classic trap: **a switch separates collision domains, a router separates broadcast domains**. A 24-port switch (one VLAN) = 24 collision domains, **1** broadcast domain. Also: **IDS** = passive (a copy of the traffic, only alerts), **IPS** = inline (blocks).' },
          { t: 'quiz', q: 'A router has 3 interfaces on 3 different LANs. Each LAN has one switch. How many broadcast domains are there?', opts: ['1', '3', '6', 'As many as the switch ports'], ok: 1, why: 'Each router interface defines a separate broadcast domain → **3**. Switches (without VLANs) do not separate broadcasts.' },
          { t: 'quiz', q: 'Which device can **stop** an attack in real time because it sits inline?', opts: ['IDS', 'IPS', 'Hub', 'WLC'], ok: 1, why: 'The **IPS** is in the path of the traffic and can drop malicious packets. An IDS sees a copy and only alerts.' },
        ],
      },
      {
        id: 'ccna-1-2', title: 'The OSI & TCP/IP models and encapsulation', minutes: 15,
        goal: 'Know the 7 OSI layers, the 4 (or 5) TCP/IP layers, the PDU of each layer and how encapsulation/de-encapsulation works.',
        blocks: [
          { t: 'text', md: 'Layered models split the huge problem "send data from here to there" into **smaller jobs**. Each layer does its own job and serves the layer above it.\n\nAnalogy: you send a parcel. You write the **letter** (application). You put it in an **envelope with an apartment number** (ports, L4). You add the **city address** (IP, L3). The courier sticks on a **label for the next stop** (MAC, L2). And the truck is the **road** (L1).' },
          { t: 'table', head: ['#', 'OSI', 'TCP/IP', 'PDU', 'Examples'], rows: [
            ['7', 'Application', 'Application', 'Data', 'HTTP, DNS, DHCP, SSH, SMTP'],
            ['6', 'Presentation', 'Application', 'Data', 'Encoding, encryption (TLS*), compression'],
            ['5', 'Session', 'Application', 'Data', 'Opening/closing sessions'],
            ['4', 'Transport', 'Transport', '**Segment** (TCP) / datagram (UDP)', 'TCP, UDP, port numbers'],
            ['3', 'Network', 'Internet', '**Packet**', 'IPv4, IPv6, ICMP, OSPF, routers'],
            ['2', 'Data Link', 'Link (Network Access)', '**Frame**', 'Ethernet, 802.11, MAC, switches'],
            ['1', 'Physical', 'Link / Physical', '**Bits**', 'Cables, connectors, radio frequencies'],
          ] },
          { t: 'tip', md: 'Mnemonic from the bottom up: **P**lease **D**o **N**ot **T**hrow **S**ausage **P**izza **A**way = Physical, Data Link, Network, Transport, Session, Presentation, Application. (*TLS does not sit cleanly in one layer; in practice it is considered something between L4 and L7.)' },
          { t: 'anim', scene: 'ccna-osi-encap', caption: 'Encapsulation at the sender, de-encapsulation at the receiver.' },
          { t: 'text', md: '### Two rules to remember\n1. **Same-layer interaction**: each layer "talks" to the **same** layer on the other side through its header. The client\'s TCP is read by the server\'s TCP.\n2. **Adjacent-layer interaction**: each layer provides a service to the layer above it. IP carries the TCP segments.\n\nAt every **router** along the path, the L2 header is **removed and rewritten** (new source/destination MAC), while the L3 header (IP addresses) stays the same, unless NAT is involved. Only the **TTL** is decremented.' },
          { t: 'netwatch', tab: 'feed', md: 'In the **Packets** tab you can see live packets from your computer, split into layers: MAC (L2), IP (L3), port (L4), application protocol (L7).' },
          { t: 'exam', md: 'You will be asked to match **PDU ↔ layer** (drag-and-drop) and **device/protocol ↔ layer**. Remember: switch = L2, router = L3, TCP/UDP = L4, IP/ICMP = L3, Ethernet/MAC = L2. In TCP/IP the Application layer combines OSI L5–L7.' },
          { t: 'quiz', q: 'What is the PDU of the **Transport** layer when TCP is used?', opts: ['Frame', 'Packet', 'Segment', 'Bit'], ok: 2, why: 'L4 = **segment** (for UDP it is often called a datagram). L3 = packet, L2 = frame.' },
          { t: 'quiz', q: 'A packet passes through 3 routers. What changes at each hop (without NAT)?', opts: ['Source and destination IP', 'Source/destination MAC and TTL', 'The port numbers', 'Nothing'], ok: 1, why: 'Each router builds a **new L2 frame** (new MACs) and decrements the **TTL**. The IPs and ports stay the same.' },
        ],
      },
      {
        id: 'ccna-1-3', title: 'Cabling, interfaces and port problems', minutes: 16,
        goal: 'Tell UTP, single-mode and multimode fiber apart, understand straight-through/crossover, know the distance limits and spot duplex/speed mismatches and interface errors.',
        blocks: [
          { t: 'text', md: '### Copper (UTP)\n**UTP** (Unshielded Twisted Pair) has 4 pairs of twisted wires and an **RJ-45** connector. The twisting reduces interference (crosstalk, EMI). The limit for copper Ethernet is **100 meters**.\n\n- **Straight-through**: the same wire order at both ends. For **different** devices (PC↔switch, router↔switch).\n- **Crossover**: crossed pairs. For **like** devices (switch↔switch, PC↔PC, router↔router, and PC↔router!).\n- Today most interfaces have **Auto-MDIX** and adapt on their own, but the exam may ask about the "classic" rule.' },
          { t: 'table', head: ['Standard', 'Speed', 'Medium', 'Distance (approx.)'], rows: [
            ['100BASE-TX', '100 Mbps', 'UTP Cat5', '100 m'],
            ['1000BASE-T', '1 Gbps', 'UTP Cat5e/6', '100 m'],
            ['10GBASE-T', '10 Gbps', 'UTP Cat6a (Cat6 up to ~55 m)', '100 m'],
            ['1000BASE-SX / 10GBASE-SR', '1 / 10 Gbps', '**Multimode** fiber', 'hundreds of meters'],
            ['1000BASE-LX / 10GBASE-LR', '1 / 10 Gbps', '**Single-mode** fiber', '~5–10 km and more'],
          ] },
          { t: 'text', md: '### Optical fiber\nIt sends **light** instead of electricity, so it is immune to electromagnetic interference and reaches much farther.\n- **Multimode (MMF)**: a **wider core** (50/62.5 µm). The light takes many paths (modes). Cheaper transmitters (LED/VCSEL), **shorter distances** (inside a building). Usually orange or aqua.\n- **Single-mode (SMF)**: a **very narrow core** (~9 µm), a single path with a **laser**. **Long distances** (between buildings, WAN), more expensive transmitters. Usually yellow.\n\nOn switches, fiber connects through pluggable **SFP/SFP+** modules.\n\n### Shared media vs point-to-point\nIn old Ethernet with **hubs** everyone shared the same medium (**shared media**, half-duplex, **CSMA/CD**, collisions). Today every switch port is **point-to-point** and **full-duplex**: it sends and receives at the same time, with no collisions. Wi-Fi is still a shared medium (half-duplex, **CSMA/CA**).' },
          { t: 'text', md: '### Port problems (blueprint 1.4)\n`show interfaces` is your doctor. The main counters:\n- **Runts**: frames smaller than 64 bytes (often caused by collisions).\n- **Giants**: frames larger than the maximum (1518 bytes, untagged).\n- **CRC errors**: the FCS does not match, so bits were corrupted. Suspects: bad cable, interference, duplex mismatch.\n- **Input errors**: total input errors (runts, giants, CRC, etc.).\n- **Collisions / late collisions**: on full-duplex they should be **0**. **Late collisions** almost always mean a **duplex mismatch**.\n\n**Duplex mismatch**: one side is full and the other half (e.g. one was configured manually and the other was left on auto). The half side sees **late collisions** and the full side sees **CRC errors/runts**. Result: the link "works" but is very slow.\n\n**Speed mismatch**: if the speeds differ, the link **does not come up** at all (down/down).' },
          { t: 'code', lang: 'cisco', title: 'show interfaces (excerpt with a duplex mismatch)', code: 'SW1# show interfaces FastEthernet0/1\nFastEthernet0/1 is up, line protocol is up (connected)\n  Hardware is Fast Ethernet, address is 0011.2233.4401\n  MTU 1500 bytes, BW 100000 Kbit/sec, DLY 100 usec,\n  Half-duplex, 100Mb/s, media type is 10/100BaseTX\n     5 minute input rate 1200 bits/sec, 2 packets/sec\n     1854 input errors, 1630 CRC, 0 frame, 0 overrun, 0 ignored\n     212 runts, 0 giants, 0 throttles\n     0 output errors, 3210 collisions, 0 interface resets\n     118 late collision, 0 deferred',
            explain: '- `up, line protocol is up`: L1 and L2 are fine.\n- `Half-duplex, 100Mb/s`: **suspicious**. On a modern link we want full-duplex.\n- `CRC`, `runts`: corrupted or truncated frames.\n- `late collision`: the "signature" of a **duplex mismatch**.\n- Fix: the same setting at both ends. Ideally `speed auto` / `duplex auto` on both, or the same manual value on both.' },
          { t: 'cli', title: 'Lab: fix a duplex mismatch', prompt: 'SW1#', banner: 'Users on Fa0/1 are complaining that the network is very slow.',
            steps: [
              { task: 'Check the status of port **FastEthernet0/1**.', expect: '^' + SH + 'int(erfaces?)?\\s*f(a(st(ethernet)?)?)?\\s*0/1$', ans: 'show interfaces f0/1', out: 'FastEthernet0/1 is up, line protocol is up (connected)\n  Half-duplex, 100Mb/s, media type is 10/100BaseTX\n     1854 input errors, 1630 CRC, 0 frame\n     118 late collision, 0 deferred' },
              { task: 'Enter global configuration.', expect: RX.conf, ans: 'conf t', next: 'SW1(config)#' },
              { task: 'Enter port **Fa0/1**.', expect: '^' + FA('0/1') + '$', ans: 'interface f0/1', next: 'SW1(config-if)#' },
              { task: 'Set **full duplex** (the other side is locked to full).', expect: '^dup(lex)?\\s+full$', ans: 'duplex full', out: '%LINK-3-UPDOWN: Interface FastEthernet0/1, changed state to down\n%LINK-3-UPDOWN: Interface FastEthernet0/1, changed state to up' },
              { task: 'Set the speed to **100** Mbps.', expect: '^speed\\s+100$', ans: 'speed 100' },
              { task: 'Go back to privileged EXEC.', expect: RX.end, ans: 'end', next: 'SW1#' },
              { task: 'Reset the counters to see whether new errors appear: `clear counters f0/1`.', expect: '^clear\\s+counters(\\s+f(a(st(ethernet)?)?)?\\s*0/1)?$', ans: 'clear counters f0/1', out: 'Clear "show interface" counters on this interface [confirm]\n%CLEAR-5-COUNTERS: Clear counter on interface FastEthernet0/1 by console' },
            ], done: 'After a few minutes, a new `show interfaces f0/1` should show **Full-duplex** and **0** late collisions.' },
          { t: 'exam', md: 'If a Cisco interface has a **manually set** speed and duplex, it does **not** autonegotiate. The other side, if on auto, detects the speed but **assumes half-duplex** for 10/100 Mbps. This is how most duplex mismatches are born.' },
          { t: 'quiz', q: 'Which fiber do you use for a **20 km** link between two buildings?', opts: ['Multimode with LED', 'Single-mode with laser', 'UTP Cat6a', 'Any fiber'], ok: 1, why: 'Long distances are covered by **single-mode** (narrow core, laser). Multimode is for hundreds of meters and UTP for 100 m.' },
          { t: 'quiz', q: 'One side of a link shows **late collisions**. What is the most likely cause?', opts: ['Speed mismatch', 'Duplex mismatch', 'Wrong VLAN', 'Wrong IP'], ok: 1, why: '**Late collisions** appear on the **half-duplex** side of a duplex mismatch. A speed mismatch would bring the link down completely.' },
        ],
      },
      {
        id: 'ccna-1-4', title: 'Topologies: 2-tier, 3-tier, spine-leaf, WAN, SOHO, cloud', minutes: 14,
        goal: 'Recognize campus (2-tier collapsed core, 3-tier), data center (spine-leaf), WAN and SOHO architectures, and the difference between on-premises and cloud.',
        blocks: [
          { t: 'text', md: '### Campus LAN: hierarchical design\nThink of an office building with many floors.\n- **Access layer**: the switches **on each floor** where PCs, phones and APs connect. This is where PoE, port security and user VLANs live.\n- **Distribution layer**: "collects" the access switches. This is where routing between VLANs happens, policies (ACLs, QoS) are applied and the boundaries of the broadcast domains are set.\n- **Core layer**: the **backbone**. Very fast and reliable switching between buildings and distribution blocks. No heavy policies, because the goal is speed.\n\n**3-tier** = access + distribution + core (large campuses).\n**2-tier (collapsed core)** = access + one layer that does **both** distribution **and** core. Ideal for smaller sites: fewer devices, lower cost.' },
          { t: 'text', md: '### Data center: spine-leaf\nIn modern data centers the traffic is mostly **east-west** (server ↔ server), not just north-south (user ↔ server). **Spine-leaf** solves this problem:\n- Every **leaf** switch (where servers connect, usually top-of-rack) connects to **every spine**.\n- The **spines** do not connect to each other and the **leafs** do not connect to each other.\n- So **any server reaches any other in the same number of hops** (leaf → spine → leaf): predictable latency. For more capacity you add spines, for more ports you add leafs.' },
          { t: 'table', head: ['Topology', 'Where', 'Characteristic'], rows: [
            ['3-tier', 'Large campus', 'Access / Distribution / Core'],
            ['2-tier (collapsed core)', 'Small-to-medium campus', 'Access + Distribution/Core combined'],
            ['Spine-leaf', 'Data center', 'Every leaf to every spine, constant hops, east-west traffic'],
            ['WAN', 'Connecting sites over long distances', 'Point-to-point, hub-and-spoke, full/partial mesh, MPLS, Internet VPN, SD-WAN'],
            ['SOHO', 'Home / small office', 'One "all-in-one" router: router + switch + AP + firewall + DHCP + NAT'],
          ] },
          { t: 'text', md: '### WAN topologies\n- **Point-to-point**: two sites with one circuit.\n- **Hub-and-spoke**: all branches (spokes) talk to the central site (hub). Cheap, but the hub is a single point of failure.\n- **Full mesh**: everyone to everyone. Maximum reliability, maximum cost (n(n−1)/2 links).\n- **Partial mesh**: a compromise.\n- **Single-homed / dual-homed / multihomed**: how many connections a site has to the provider (or to how many providers).\n\n### On-premises vs cloud\n- **On-premises**: the servers are **yours**, in your own data center. You have full control and full responsibility.\n- **Cloud** (AWS, Azure, GCP…): you rent infrastructure. Models: **IaaS** (VMs), **PaaS** (platform), **SaaS** (ready-made application, e.g. Microsoft 365). Accessed over the Internet, VPN or a private connection.' },
          { t: 'exam', md: 'In spine-leaf the rule is strict: **leaf only to spine**, **spine only to leaf**. If you see a question "which connection violates spine-leaf", look for leaf↔leaf or spine↔spine. In a collapsed core, "collapsed" means that **distribution and core are merged**.' },
          { t: 'quiz', q: 'In a **spine-leaf** architecture, where do the servers connect?', opts: ['To the spine switches', 'To the leaf switches', 'To the core router', 'Directly to each other'], ok: 1, why: 'Servers, firewalls and other devices connect to the **leafs**. The spines just interconnect the leafs.' },
          { t: 'quiz', q: 'Which layer is merged with the core in a **2-tier collapsed core** design?', opts: ['Access', 'Distribution', 'Physical', 'Application'], ok: 1, why: '2-tier = **access** + **distribution/core** combined.' },
        ],
      },
      {
        id: 'ccna-1-5', title: 'TCP vs UDP and port numbers', minutes: 14,
        goal: 'Compare TCP and UDP (reliability, connection, overhead), explain the three-way handshake and windowing, and know the basic well-known ports.',
        blocks: [
          { t: 'text', md: 'Both are **Transport (L4)** protocols and they use **port numbers** so the computer knows **which application** each segment belongs to. The IP takes you to the right building, the port to the right apartment.\n\n- **TCP** = **registered mail**: delivery confirmation, numbering, resending if lost, correct order.\n- **UDP** = **postcard**: you drop it in the mailbox and hope. Fast, lightweight, no guarantees.' },
          { t: 'table', head: ['', 'TCP', 'UDP'], rows: [
            ['Connection', '**Connection-oriented** (three-way handshake)', '**Connectionless**'],
            ['Reliability', 'Acknowledgments, retransmission', 'None: if needed, the application provides it'],
            ['Ordering', 'Sequence numbers: correct order', 'No'],
            ['Flow control', '**Windowing** (sliding window)', 'No'],
            ['Header', '20 bytes (minimum)', '8 bytes'],
            ['Use', 'Web, email, files, SSH', 'Voice/video (VoIP), DNS queries, DHCP, SNMP, TFTP, streaming'],
          ] },
          { t: 'anim', scene: 'ccna-tcp-handshake', caption: 'Three-way handshake (SYN, SYN-ACK, ACK), data transfer and closing.' },
          { t: 'text', md: '### Windowing\nTCP does not wait for an ACK for **every** segment. The receiver announces a **window size**: "you can send me this many bytes before waiting for an ACK". If all goes well, the window grows (**sliding window**). If segments are lost, it shrinks. This is how TCP adapts to the capacity of the network (flow control).\n\n### Why does voice use UDP?\nIn a call, a word that was lost 200 ms ago is **pointless** to resend. It would be heard out of order. We prefer low latency over perfect reliability.' },
          { t: 'table', head: ['Port', 'Protocol', 'L4'], rows: [
            ['20, 21', 'FTP (data, control)', 'TCP'], ['22', 'SSH / SCP / SFTP', 'TCP'], ['23', 'Telnet', 'TCP'], ['25', 'SMTP', 'TCP'],
            ['53', 'DNS', 'UDP (queries) & TCP (zone transfers/large responses)'], ['67, 68', 'DHCP (server, client)', 'UDP'], ['69', 'TFTP', 'UDP'],
            ['80', 'HTTP', 'TCP'], ['110', 'POP3', 'TCP'], ['123', 'NTP', 'UDP'], ['161, 162', 'SNMP (agent, traps)', 'UDP'], ['443', 'HTTPS', 'TCP (and UDP for HTTP/3 – QUIC)'], ['514', 'Syslog', 'UDP'],
          ] },
          { t: 'netwatch', tab: 'stats', md: 'The **Stats** tab shows which protocols and ports your computer is using right now. Look for TCP 443 (HTTPS) and UDP 53 (DNS).' },
          { t: 'exam', md: 'Memorize the port table **and** whether each is TCP or UDP. Favorite traps: **TFTP = UDP 69** (FTP is TCP), **DHCP = UDP 67/68**, **SNMP = UDP 161/162**, **Syslog = UDP 514**, **NTP = UDP 123**. TCP has **flow control through windowing** and UDP does **not**.' },
          { t: 'quiz', q: 'Which order is correct for the TCP three-way handshake?', opts: ['SYN → ACK → SYN-ACK', 'SYN → SYN-ACK → ACK', 'ACK → SYN → FIN', 'SYN → FIN → ACK'], ok: 1, why: 'Client **SYN**, server **SYN-ACK**, client **ACK**.' },
          { t: 'quiz', q: 'Which of the following uses **UDP**?', opts: ['SSH', 'HTTP', 'TFTP', 'SMTP'], ok: 2, why: '**TFTP** (UDP 69) is the "trivial" sibling of FTP, with no connection. The others are TCP.' },
          { t: 'quiz', q: 'Which TCP mechanism controls how much data is sent before an acknowledgment is required?', opts: ['Sequencing', 'Windowing', 'Checksum', 'Port numbers'], ok: 1, why: 'The **window size** (sliding window) is TCP\'s flow control mechanism.' },
        ],
      },
      {
        id: 'ccna-1-6', title: 'IPv4 addresses, binary, masks and ARP', minutes: 18,
        goal: 'Convert decimal ↔ binary, understand what the subnet mask and prefix (/24) do, know the classes, the address types and how a MAC is found with ARP.',
        blocks: [
          { t: 'text', md: 'An IPv4 address has **32 bits**, written as 4 **octets** (8 bits each) in decimal form: `192.168.1.10`. Each octet takes values 0–255.\n\nThe address has **two parts**, like a phone number with an area code:\n- **Network part**: which network it belongs to (the "street").\n- **Host part**: which device inside the network (the "house number").\n\nWhere they are **split** is told by the **subnet mask**: bits set to **1** are network, bits set to **0** are host. The mask `255.255.255.0` = 24 ones = **/24** (prefix length, CIDR notation).' },
          { t: 'table', head: ['Bit', '128', '64', '32', '16', '8', '4', '2', '1'], rows: [
            ['192 =', '1', '1', '0', '0', '0', '0', '0', '0'],
            ['168 =', '1', '0', '1', '0', '1', '0', '0', '0'],
            ['10 =', '0', '0', '0', '0', '1', '0', '1', '0'],
            ['255 =', '1', '1', '1', '1', '1', '1', '1', '1'],
          ] },
          { t: 'tip', md: 'To convert decimal to binary, subtract the values 128, 64, 32, 16, 8, 4, 2, 1 from the left, as long as they "fit". Example 200: 200−128=72 (1), 72−64=8 (1), 32 no (0), 16 no (0), 8 yes (1) → `11001000`.' },
          { t: 'table', head: ['Mask octet values', '1 bits'], rows: [['128', '1'], ['192', '2'], ['224', '3'], ['240', '4'], ['248', '5'], ['252', '6'], ['254', '7'], ['255', '8']] },
          { t: 'text', md: '### The old classes (classful)\nBefore CIDR, the size of the network was determined by the **first octet**. They are no longer used for routing, but the exam asks about them:\n- **Class A**: 1–126, default /8 (127 is loopback)\n- **Class B**: 128–191, default /16\n- **Class C**: 192–223, default /24\n- **Class D**: 224–239, **multicast**\n- **Class E**: 240–255, experimental\n\n### Three kinds of communication\n- **Unicast**: to one recipient.\n- **Broadcast**: to everyone in the subnet (e.g. 192.168.1.255 or 255.255.255.255). Routers do **not** forward broadcasts.\n- **Multicast**: to a group that "subscribed" (224.0.0.0/4), e.g. 224.0.0.5 for OSPF.\n\nIn every subnet the **first** address (all host bits 0) is the **network address** and the **last** (all 1) is the **broadcast**. Neither is assigned to a host.' },
          { t: 'text', md: '### Default gateway and ARP\nA host compares its own address+mask with the destination address:\n- **Same subnet** → it sends **directly**. It needs the MAC of the destination.\n- **Different subnet** → it sends to the **default gateway** (router). It needs the MAC of the gateway.\n\nIn both cases it finds the MAC with **ARP** (Address Resolution Protocol).' },
          { t: 'anim', scene: 'ccna-arp', caption: 'ARP Request (broadcast) and ARP Reply (unicast).' },
          { t: 'exam', md: 'The **ARP Request** is a **broadcast** (ffff.ffff.ffff) and the **ARP Reply** is **unicast**. A host does **not** ARP for a remote IP, but for the **default gateway**. On a router view the ARP table with `show ip arp` or `show arp`, and on Windows with `arp -a`.' },
          { t: 'quiz', q: 'How many bits does the mask `255.255.240.0` have?', opts: ['/18', '/20', '/22', '/24'], ok: 1, why: '255 (8) + 255 (8) + 240 (4) + 0 = **20** bits.' },
          { t: 'quiz', q: 'PC 10.1.1.5/24 wants to send to 10.1.2.9. Which IP will it ARP for?', opts: ['10.1.2.9', 'Its default gateway', '255.255.255.255', 'No ARP is needed'], ok: 1, why: '10.1.2.9 is on a **different /24**. The packet goes to the **gateway**, so it needs the gateway\'s MAC.' },
          { t: 'quiz', q: 'Which class does 172.20.5.1 belong to (classful)?', opts: ['A', 'B', 'C', 'D'], ok: 1, why: 'First octet 172 → 128–191 → **Class B**.' },
        ],
      },
      {
        id: 'ccna-1-7', title: 'Subnetting I: the "block" method', minutes: 25,
        goal: 'Quickly find, **without** binary, the network address, broadcast, host range and number of hosts for any IP/prefix.',
        blocks: [
          { t: 'text', md: '**Subnetting** is the part that scares most people, but with a method it becomes a mechanical 20-second job. You will meet it in **many** questions, often "hidden" inside other topics (routing, ACLs, OSPF).\n\n### The method in 4 steps\n1. Find the **interesting octet**: the one where the mask is **neither** 255 **nor** 0.\n2. **Block size** = 256 − (mask value in that octet). Alternatively: 2^(host bits in that octet).\n3. **Network** = the largest multiple of the block that is ≤ the IP value in that octet. The octets after it become 0.\n4. **Broadcast** = (next network) − 1. Hosts = from network+1 to broadcast−1. **Number of hosts = 2^h − 2** (h = host bits).' },
          { t: 'text', md: '### Example 1: 192.168.10.77/27\n- /27 → mask 255.255.255.**224** → the interesting octet is the 4th.\n- Block = 256 − 224 = **32** → networks: .0, .32, **.64**, .96, …\n- 77 falls between 64 and 96 → **network 192.168.10.64**.\n- Broadcast = 96 − 1 = **192.168.10.95**.\n- Hosts: **.65 – .94** → 2^5 − 2 = **30** hosts.\n\n### Example 2: 172.16.45.200/20\n- /20 → 255.255.**240**.0 → the interesting octet is the 3rd.\n- Block = 256 − 240 = **16** → 0, 16, **32**, 48…\n- 45 falls in the block 32–47 → **network 172.16.32.0**.\n- Broadcast = **172.16.47.255** (next network 172.16.48.0 minus 1).\n- Hosts: 172.16.32.1 – 172.16.47.254 → 2^12 − 2 = **4094**.' },
          { t: 'table', head: ['Prefix', 'Mask', 'Block', 'Hosts'], rows: [
            ['/24', '255.255.255.0', '256', '254'], ['/25', '255.255.255.128', '128', '126'], ['/26', '255.255.255.192', '64', '62'], ['/27', '255.255.255.224', '32', '30'],
            ['/28', '255.255.255.240', '16', '14'], ['/29', '255.255.255.248', '8', '6'], ['/30', '255.255.255.252', '4', '2'], ['/31', '255.255.255.254', '2', '2 (point-to-point only, RFC 3021)'], ['/32', '255.255.255.255', '1', '1 (host route, loopback)'],
          ] },
          { t: 'text', md: '### How many subnets?\nIf you "borrow" **s** bits from the host part, you create **2^s** subnets. Example: 10.0.0.0/8 split into /12 → you borrowed 4 bits → **16** subnets, each with 2^20 − 2 hosts.\n\n### The other way around: "I need X hosts"\nFind the smallest h such that 2^h − 2 ≥ X. For 50 hosts: 2^6 − 2 = 62 ≥ 50 → h = 6 → prefix /26.' },
          { t: 'subnet' },
          { t: 'warn', md: 'The "−2" applies to **hosts**, not to subnets (the old "subnet zero" rules no longer apply: all subnets are used). /31 is an exception: on point-to-point links both **2** addresses are usable.' },
          { t: 'exam', md: 'In the exam you have no calculator, but you get a **whiteboard/marker**. As soon as you sit down, write the table **128-192-224-240-248-252-254-255** and the powers of 2. Questions like "which IP is **valid for a host** in subnet X" want you to check that it is **not** the network or the broadcast address.' },
          { t: 'quiz', q: 'What is the broadcast address of **10.20.30.100/26**?', opts: ['10.20.30.63', '10.20.30.127', '10.20.30.255', '10.20.30.64'], ok: 1, why: '/26 → block 64 → networks .0, .64, .128 → 100 belongs to **.64** → broadcast **.127**.' },
          { t: 'quiz', q: 'Which IP is **valid for a host** in 192.168.5.32/28?', opts: ['192.168.5.32', '192.168.5.47', '192.168.5.45', '192.168.5.50'], ok: 2, why: '/28 → block 16 → .32 to .47. .32 is the network, .47 the broadcast, .50 is in another subnet → **.45** ✔.' },
          { t: 'quiz', q: 'You need a subnet for **25 hosts** with the least possible waste. Which prefix?', opts: ['/26', '/27', '/28', '/29'], ok: 1, why: '/28 → 14 hosts (too few). **/27 → 30** hosts ≥ 25 ✔. /26 (62) wastes addresses.' },
        ],
      },
      {
        id: 'ccna-1-8', title: 'Subnetting II: VLSM and address planning', minutes: 22,
        goal: 'Design with **VLSM** an address plan for several LANs and point-to-point links, without overlaps, starting from the largest.',
        blocks: [
          { t: 'text', md: 'With **VLSM** (Variable Length Subnet Masking) every subnet is **as large as it needs to be**, instead of all being the same. It is like cutting a pizza into **different-sized** slices: the big ones first, then the small ones in the gaps that remain.\n\n### The rule\n1. Sort the requirements from **largest** to **smallest**.\n2. Give each the **smallest** prefix that fits.\n3. Each new subnet starts **right after** the previous one. Because you go from large to small, it will always land on a correct block boundary.' },
          { t: 'text', md: '### Example: 192.168.50.0/24\nRequirements: LAN-A **100** hosts, LAN-B **50**, LAN-C **20**, and 2 point-to-point WAN links (2 hosts each).' },
          { t: 'table', head: ['Requirement', 'Prefix (hosts)', 'Subnet', 'Host range', 'Broadcast'], rows: [
            ['LAN-A 100', '/25 (126)', '192.168.50.0/25', '.1 – .126', '.127'],
            ['LAN-B 50', '/26 (62)', '192.168.50.128/26', '.129 – .190', '.191'],
            ['LAN-C 20', '/27 (30)', '192.168.50.192/27', '.193 – .222', '.223'],
            ['WAN-1', '/30 (2)', '192.168.50.224/30', '.225 – .226', '.227'],
            ['WAN-2', '/30 (2)', '192.168.50.228/30', '.229 – .230', '.231'],
            ['(free)', '—', '192.168.50.232 – .255', '—', 'for future use'],
          ] },
          { t: 'tip', md: 'For overlap checks: two subnets overlap if one "fits" inside the other. E.g. 10.1.0.0/16 and 10.1.5.0/24 **overlap**. A Cisco router will **not** let you put overlapping subnets on two of its interfaces (`% 10.1.5.0 overlaps with GigabitEthernet0/0`).' },
          { t: 'subnet' },
          { t: 'exam', md: 'A typical question: you get a diagram with a "LAN with 60 hosts" and 4 candidate subnets, and you are asked which is the **correct and most efficient**. Check: (1) does it fit? (2) does it not overlap with others? (3) is the gateway IP inside the range? For point-to-point links between routers the answer is usually **/30** (or /31).' },
          { t: 'quiz', q: 'With VLSM in 10.10.0.0/24 you have already assigned 10.10.0.0/25 and 10.10.0.128/26. What is the next free /27?', opts: ['10.10.0.160/27', '10.10.0.192/27', '10.10.0.128/27', '10.10.0.224/27'], ok: 1, why: 'The /26 at .128 covers .128–.191, so the next free one starts at **.192**.' },
          { t: 'quiz', q: 'Which prefix gives **exactly** 2 usable addresses with the classic 2^h−2 rule?', opts: ['/29', '/30', '/31', '/32'], ok: 1, why: '/30 → 4 addresses − 2 = **2** hosts. /31 gives 2 only as an exception for point-to-point links.' },
        ],
      },
      {
        id: 'ccna-1-9', title: 'Private addresses, DHCP and checking IP settings on clients', minutes: 16,
        goal: 'Know the RFC 1918 private ranges and why NAT is needed, the special addresses, the DHCP process (DORA), and how to check IP settings on Windows, macOS and Linux.',
        blocks: [
          { t: 'text', md: 'There are ~4.3 billion IPv4 addresses and they have **run out**. The solution: internal devices use **private** addresses, which are **not routed on the Internet**. When they go out, the router translates them into a single **public** IP with **NAT/PAT**. Every home in the world can have the same 192.168.1.0/24, just as every apartment building has an "apartment 1".' },
          { t: 'table', head: ['Range (RFC 1918)', 'Prefix', 'Classful equivalent'], rows: [
            ['10.0.0.0 – 10.255.255.255', '10.0.0.0/8', '1 Class A network'],
            ['172.16.0.0 – 172.31.255.255', '172.16.0.0/12', '16 Class B networks'],
            ['192.168.0.0 – 192.168.255.255', '192.168.0.0/16', '256 Class C networks'],
          ] },
          { t: 'table', head: ['Special address', 'Meaning'], rows: [
            ['127.0.0.0/8 (127.0.0.1)', 'Loopback: "myself"'],
            ['169.254.0.0/16', '**APIPA** / link-local: the host did **not** find a DHCP server'],
            ['0.0.0.0', '"No/unknown address" (e.g. the source in a DHCP Discover) or the default route 0.0.0.0/0'],
            ['255.255.255.255', 'Limited broadcast'],
            ['100.64.0.0/10', 'Shared address space for Carrier-Grade NAT (RFC 6598)'],
          ] },
          { t: 'exam', md: 'Watch out for **172.16.0.0/12**: it goes up to **172.31**.255.255. 172.32.1.1 is **public**! If a PC has **169.254.x.x**, the problem is **DHCP** (server down, wrong VLAN, missing `ip helper-address`).' },
          { t: 'anim', scene: 'ccna-dhcp-dora', caption: 'DHCP: Discover, Offer, Request, Ack.' },
          { t: 'text', md: 'If the DHCP server is **on a different subnet**, broadcasts do not cross the router. In that case, on the router interface facing the clients you configure `ip helper-address <server IP>`: the router becomes a **DHCP relay agent** and forwards the messages as unicast. (The details of DHCP belong to domain 4.0 IP Services.)\n\n### Checking IP settings on clients (blueprint 1.10)' },
          { t: 'table', head: ['OS', 'IP / mask / MAC', 'Gateway / routes', 'DNS'], rows: [
            ['Windows', '`ipconfig` / `ipconfig /all`', '`ipconfig`, `route print`', '`ipconfig /all`, `nslookup`'],
            ['macOS', '`ifconfig en0`, `ipconfig getifaddr en0`', '`netstat -rn`, `route -n get default`', '`scutil --dns`'],
            ['Linux', '`ip addr` (`ip a`), `ifconfig`', '`ip route`', '`cat /etc/resolv.conf`, `resolvectl status`'],
          ] },
          { t: 'code', lang: 'text', title: 'ipconfig /all (Windows, excerpt)', code: 'Ethernet adapter Ethernet:\n   Physical Address. . . . . . . . . : 3C-52-82-1A-2B-3C\n   DHCP Enabled. . . . . . . . . . . : Yes\n   IPv4 Address. . . . . . . . . . . : 192.168.1.50(Preferred)\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n   Lease Obtained. . . . . . . . . . : Monday 10:02:11\n   Default Gateway . . . . . . . . . : 192.168.1.1\n   DHCP Server . . . . . . . . . . . : 192.168.1.1\n   DNS Servers . . . . . . . . . . . : 1.1.1.1',
            explain: '- **Physical Address**: the MAC of the network card.\n- **DHCP Enabled: Yes** and **DHCP Server**: the IP came from DHCP.\n- Check that the **Default Gateway** is in the same subnet as the IPv4 Address. Otherwise the host cannot leave its LAN.' },
          { t: 'netwatch', tab: 'devs', md: 'The **Devices** tab shows the devices on your own LAN with IP and MAC: effectively the "ARP table" of your network. See which private address range your router uses.' },
          { t: 'quiz', q: 'Which of these is a **public** address?', opts: ['10.200.1.1', '172.20.0.5', '172.33.4.4', '192.168.100.1'], ok: 2, why: 'The private range is 172.16.0.0–**172.31**.255.255. **172.33.4.4** is outside it.' },
          { t: 'quiz', q: 'A user has the IP 169.254.12.7. What is most likely?', opts: ['Wrong DNS', 'The computer got no answer from a DHCP server', 'The router did NAT', 'The IP is static'], ok: 1, why: '169.254.0.0/16 = **APIPA**: the OS assigns it on its own when DHCP fails.' },
          { t: 'quiz', q: 'In what order do the DHCP messages occur?', opts: ['Request, Offer, Discover, Ack', 'Discover, Offer, Request, Ack', 'Discover, Request, Offer, Ack', 'Offer, Discover, Ack, Request'], ok: 1, why: '**DORA**: Discover → Offer → Request → Ack.' },
        ],
      },
      {
        id: 'ccna-1-10', title: 'IPv6: format, shortening, address types, EUI-64', minutes: 22,
        goal: 'Write and shorten IPv6 addresses correctly, recognize global unicast, unique local, link-local, multicast and anycast, calculate EUI-64 and configure IPv6 on a router.',
        blocks: [
          { t: 'text', md: '**IPv6** has **128 bits**: 340 undecillion addresses, enough for every grain of sand. It is written as **8 groups** (hextets) of 16 bits in **hexadecimal**, separated by `:`:\n\n`2001:0db8:0000:0000:0000:ff00:0042:8329`\n\n### Two shortening rules\n1. **Remove the leading zeros** in each group: `0db8` → `db8`, `0042` → `42`, `0000` → `0`.\n2. **Only once**, replace the longest consecutive run of all-zero groups with `::`.\n\nResult: `2001:db8::ff00:42:8329`\n\nThe `::` can be used only **once**, otherwise nobody would know how many zeros each one "hides".' },
          { t: 'table', head: ['Type', 'Prefix', 'IPv4 equivalent / meaning'], rows: [
            ['**Global unicast (GUA)**', '2000::/3 (starts with 2 or 3)', 'Public addresses, routed on the Internet'],
            ['**Unique local (ULA)**', 'fc00::/7 (in practice fd00::/8)', 'Like the private RFC 1918 addresses'],
            ['**Link-local**', 'fe80::/10', 'Local link only, **not routed**. Every IPv6 interface must have one. Routers use it as the next hop'],
            ['**Multicast**', 'ff00::/8', 'Replaces broadcast (which **does not exist** in IPv6). ff02::1 = all nodes, ff02::2 = all routers'],
            ['**Anycast**', '(regular unicast)', 'The same address on several devices. The packet goes to the **nearest** one'],
            ['Loopback / unspecified', '::1/128 and ::/128', '127.0.0.1 and 0.0.0.0'],
          ] },
          { t: 'text', md: '### Structure of a global unicast\nUsually: **/48** from the provider (global routing prefix) + **16 bits of subnet ID** (65,536 subnets per site!) + **64 bits of interface ID**. LANs are almost always **/64**.\n\n### Modified EUI-64: interface ID from the MAC\n1. Split the MAC (48 bits) in the middle: `001A.2B` | `3C.4D5E`.\n2. Insert **FFFE** in the middle → `001A:2BFF:FE3C:4D5E`.\n3. **Flip the 7th bit** (U/L bit) of the first byte: `00` = 0000 0000 → 0000 00**1**0 = `02`.\n4. Interface ID = `021A:2BFF:FE3C:4D5E`. With prefix 2001:db8:acad:1::/64 → **2001:db8:acad:1:21a:2bff:fe3c:4d5e**.' },
          { t: 'tip', md: 'A quick trick for the 7th bit: the **second hex digit** of the MAC changes by ±2. 0↔2, 4↔6, 8↔A, C↔E (and 1↔3, 5↔7, 9↔B, D↔F). The MAC `aa…` becomes `a8…`.' },
          { t: 'anim', scene: 'ccna-ipv6-slaac', caption: 'SLAAC with NDP: Router Solicitation, Router Advertisement, DAD.' },
          { t: 'text', md: 'Ways for a host to get an IPv6 address: **static**, **SLAAC** (prefix from the RA, interface ID from the host), **stateless DHCPv6** (SLAAC + DNS etc. from DHCPv6) or **stateful DHCPv6** (everything from the server). **NDP** (ICMPv6) replaces ARP: **NS/NA** (Neighbor Solicitation/Advertisement) and **RS/RA** (Router Solicitation/Advertisement). Every unicast address also has a **solicited-node multicast** address (ff02::1:ffXX:XXXX, built from the last 24 bits of the address) to which NS messages are sent.' },
          { t: 'code', lang: 'cisco', title: 'IPv6 on a router', code: 'ipv6 unicast-routing\n!\ninterface GigabitEthernet0/0\n ipv6 address 2001:db8:acad:1::1/64\n ipv6 address fe80::1 link-local\n no shutdown\n!\ninterface GigabitEthernet0/1\n ipv6 address 2001:db8:acad:2::/64 eui-64\n no shutdown',
            explain: '- `ipv6 unicast-routing`: **without it the router does not route IPv6** or send RAs. A common trap!\n- `ipv6 address …/64`: a static GUA. The link-local address is created automatically (EUI-64).\n- `ipv6 address fe80::1 link-local`: a manual link-local address, easier to read as a gateway.\n- `eui-64`: you give only the prefix and the router builds the interface ID from its MAC.\n- Verification: `show ipv6 interface brief`.' },
          { t: 'cli', title: 'Lab: enable IPv6 on R1', prompt: 'R1#',
            steps: [
              { task: 'Enter global configuration.', expect: RX.conf, ans: 'configure terminal', next: 'R1(config)#' },
              { task: 'Enable IPv6 routing.', expect: '^ipv6\\s+unicast-rout(ing)?$', ans: 'ipv6 unicast-routing' },
              { task: 'Enter **Gi0/0**.', expect: '^' + GI('0/0') + '$', ans: 'interface g0/0', next: 'R1(config-if)#' },
              { task: 'Assign the address **2001:db8:acad:1::1/64**.', expect: '^ipv6\\s+add(r(ess)?)?\\s+2001:0?db8:acad:0{0,3}1::0{0,3}1/64$', ans: 'ipv6 address 2001:db8:acad:1::1/64' },
              { task: 'Assign the link-local **fe80::1**.', expect: '^ipv6\\s+add(r(ess)?)?\\s+fe80::0{0,3}1\\s+link-local$', ans: 'ipv6 address fe80::1 link-local' },
              { task: 'Enable the port.', expect: RX.noshut, ans: 'no shutdown', out: '%LINK-5-CHANGED: Interface GigabitEthernet0/0, changed state to up' },
              { task: 'Go back to `#`.', expect: RX.end, ans: 'end', next: 'R1#' },
              { task: 'Verify: `show ipv6 interface brief`.', expect: '^' + SH + 'ipv6\\s+int(erface)?\\s+br(ief)?$', ans: 'show ipv6 interface brief',
                out: 'GigabitEthernet0/0     [up/up]\n    FE80::1\n    2001:DB8:ACAD:1::1\nGigabitEthernet0/1     [administratively down/down]\n    unassigned' },
            ], done: 'R1 will start sending **Router Advertisements** on Gi0/0 and the PCs can do SLAAC.' },
          { t: 'exam', md: 'Frequent questions: (1) which shortening is **valid** (two `::` = invalid), (2) **EUI-64** calculation (remember FFFE + flipping the 7th bit), (3) **fe80::/10 = link-local**, **fc00::/7 = ULA**, **2000::/3 = global**, **ff00::/8 = multicast**, (4) IPv6 has **no broadcast**.' },
          { t: 'quiz', q: 'What is a correct shortening of `2001:0db8:0000:0000:0001:0000:0000:0001`?', opts: ['2001:db8::1::1', '2001:db8::1:0:0:1', '2001:db8:0:0:1::1', 'Both b and c'], ok: 3, why: 'The two runs of zeros are the **same length** (2 groups), so the `::` can go in either one, but only in **one**. RFC 5952 recommends the first (b) as the canonical form, but both are valid. Option a is invalid.' },
          { t: 'quiz', q: 'What is the EUI-64 interface ID for the MAC **0C1A.2B3C.4D5E**?', opts: ['0C1A:2BFF:FE3C:4D5E', '0E1A:2BFF:FE3C:4D5E', '0C1A:2BFE:FF3C:4D5E', '0E1A:2B3C:FFFE:4D5E'], ok: 1, why: 'FFFE in the middle and flip the 7th bit: 0C (0000 1100) → 0E (0000 1110). Result **0E1A:2BFF:FE3C:4D5E**.' },
          { t: 'quiz', q: 'Which address type starts with **fe80**?', opts: ['Global unicast', 'Unique local', 'Link-local', 'Multicast'], ok: 2, why: 'fe80::/10 = **link-local**: it exists on every IPv6 interface and does not cross a router.' },
        ],
      },
      {
        id: 'ccna-1-11', title: 'Wireless basics: RF, channels, SSID, encryption', minutes: 16,
        goal: 'Explain the 2.4/5/6 GHz bands, why channels 1, 6, 11 are the non-overlapping ones, what SSID/BSSID/BSS/ESS are, and which encryption is secure (WPA2/WPA3).',
        blocks: [
          { t: 'text', md: '**Wi-Fi (IEEE 802.11)** sends frames over **radio waves** instead of a cable. The air is a **shared medium**: only one device talks at a time on the same channel (half-duplex). To avoid collisions it uses **CSMA/CA** (Collision **Avoidance**): "listen, wait a random time, send, wait for an ACK".\n\n### Frequencies and channels\n- **2.4 GHz**: longer range and better penetration through walls, but only **3 non-overlapping channels (1, 6, 11)** at 20 MHz and a lot of interference (Bluetooth, microwave ovens).\n- **5 GHz**: many more non-overlapping channels, higher speeds, shorter range.\n- **6 GHz** (Wi-Fi 6E/7): even more "clean" spectrum.' },
          { t: 'table', head: ['Standard', 'Marketing name', 'Bands'], rows: [
            ['802.11b / g', '—', '2.4 GHz'], ['802.11a', '—', '5 GHz'], ['802.11n', 'Wi-Fi 4', '2.4 & 5 GHz'], ['802.11ac', 'Wi-Fi 5', '5 GHz'], ['802.11ax', 'Wi-Fi 6 / 6E', '2.4, 5 (& 6 GHz for 6E)'], ['802.11be', 'Wi-Fi 7', '2.4, 5, 6 GHz'],
          ] },
          { t: 'text', md: '### Terminology\n- **SSID**: the **name** of the network (e.g. "Corp-WiFi").\n- **BSSID**: the **MAC** of the AP\'s radio for this SSID.\n- **BSS** (Basic Service Set): one AP and its clients. The coverage area is called the **BSA** (cell).\n- **ESS** (Extended Service Set): several APs with **the same SSID**, connected to the same wired network. The client **roams** from AP to AP.\n- **IBSS** (ad hoc): devices directly connected to each other, without an AP.\n- **Distribution System (DS)**: the wired network behind the APs.\n- Other AP roles: **repeater**, **workgroup bridge**, **outdoor bridge**, **mesh**.\n\n### Security\n- **WEP**: broken, **never**.\n- **WPA**: old (TKIP), avoid.\n- **WPA2**: **AES-CCMP**. Personal (PSK, shared password) or Enterprise (**802.1X/EAP** with a RADIUS server).\n- **WPA3**: **SAE** instead of PSK (protection against offline dictionary attacks), **PMF** mandatory, a stronger Enterprise version (192-bit).' },
          { t: 'netwatch', tab: 'wifi', md: 'The **Wi-Fi** tab shows the SSID, channel, encryption and signal strength of your network. See whether you are on 2.4 or 5 GHz and whether you use WPA2 or WPA3.' },
          { t: 'exam', md: 'Memorize: **2.4 GHz non-overlapping = 1, 6, 11**. **WPA2 = AES/CCMP**, **WPA3 = SAE**. **Personal = PSK**, **Enterprise = 802.1X + RADIUS**. Wi-Fi uses **CSMA/CA**, old half-duplex Ethernet **CSMA/CD**.' },
          { t: 'quiz', q: 'You are designing 3 neighboring APs on 2.4 GHz. Which channels do you pick?', opts: ['1, 2, 3', '1, 6, 11', '1, 5, 9', '6, 6, 6'], ok: 1, why: 'On 2.4 GHz with 20 MHz channels the only **non-overlapping** ones are **1, 6, 11**.' },
          { t: 'quiz', q: 'Which security measure does **WPA3-Personal** introduce in place of the PSK handshake?', opts: ['TKIP', 'WEP', 'SAE', 'MAC filtering'], ok: 2, why: '**SAE** (Simultaneous Authentication of Equals) protects the password against offline dictionary attacks.' },
          { t: 'quiz', q: 'Several APs with the **same SSID** that allow roaming make up an…', opts: ['BSS', 'IBSS', 'ESS', 'BSSID'], ok: 2, why: '**ESS** = multiple BSSs with a common SSID, joined by the distribution system.' },
        ],
      },
      {
        id: 'ccna-1-12', title: 'Virtualization: VMs, containers, VRFs and cloud', minutes: 12,
        goal: 'Explain what a hypervisor (Type 1/2), virtual machines, virtual switches, containers and VRFs are, and how they relate to the cloud.',
        blocks: [
          { t: 'text', md: 'In the past: **one server = one operating system = one application**, usually with 10% CPU usage. A waste. With **virtualization** one physical server runs **many virtual machines (VMs)**, each with its own OS, like an apartment building with many apartments on the same foundation.\n\n### Hypervisor\nThe software that shares CPU, RAM, disk and network among the VMs.\n- **Type 1 (bare-metal)**: runs **directly on the hardware** (VMware ESXi, Microsoft Hyper-V, KVM). For data centers.\n- **Type 2 (hosted)**: runs **on top of a regular OS** (VirtualBox, VMware Workstation). For labs and desktops.\n\n### Virtual switch (vSwitch)\nVMs have **virtual NICs** connected to a **virtual switch** inside the hypervisor, which connects to the server\'s physical NICs. The vSwitch supports **VLANs**, so the physical switch port toward the server is usually a **trunk**.' },
          { t: 'table', head: ['', 'Virtual machine', 'Container'], rows: [
            ['What it virtualizes', 'The entire hardware', 'The **operating system** (shares the host\'s kernel)'],
            ['Has its own OS?', 'Yes, a full guest OS', 'No, only the application + libraries'],
            ['Size / startup', 'GB / minutes', 'MB / seconds'],
            ['Examples', 'ESXi, Hyper-V, KVM', 'Docker, Kubernetes (orchestration)'],
          ] },
          { t: 'text', md: '### VRF (Virtual Routing and Forwarding)\nVirtualization of a **router**: one physical router keeps **several independent routing tables**. Each interface belongs to a VRF and traffic does not "cross" from one VRF to another. This way two customers can use **the same (overlapping) IP addresses** on the same router. It is widely used by providers (MPLS VPNs) and to separate management/production traffic.\n\n### Cloud\nThe cloud (by the NIST definition) has: **on-demand self-service**, **broad network access**, **resource pooling**, **rapid elasticity** and **measured service** (you pay for what you use). Underneath, it runs on virtualization.' },
          { t: 'exam', md: 'Remember: **Type 1 = bare-metal**, **Type 2 = hosted**. **Containers share the kernel** of the host and have no guest OS of their own. A **VRF** allows **overlapping IPs** on one router through separate routing tables.' },
          { t: 'quiz', q: 'Which technology lets a router have two interfaces with the **same** IP 10.1.1.1/24, for two different customers?', opts: ['VLAN', 'VRF', 'HSRP', 'EtherChannel'], ok: 1, why: '**VRFs** create separate routing tables, so overlaps are allowed.' },
          { t: 'quiz', q: 'What runs underneath the VMs on a **Type 1** hypervisor?', opts: ['Windows 11', 'The hardware directly', 'Docker', 'Another Type 2 hypervisor'], ok: 1, why: 'Type 1 (bare-metal) is installed **directly on the hardware**, with no intermediate host OS.' },
        ],
      },
      {
        id: 'ccna-1-13', title: 'Switching: MAC learning, aging, flooding, forwarding', minutes: 16,
        goal: 'Explain step by step how a switch learns MAC addresses, when it forwards, floods or filters, and read `show mac address-table`.',
        blocks: [
          { t: 'text', md: 'A switch is like a **doorman** who at first knows nobody. Every time someone passes through a door, he notes "A lives behind door 1". Later, when a letter arrives for A, he knows where to take it.\n\n### The switch\'s three decisions\n1. **Learn**: it reads the **source MAC** of the incoming frame and updates the **MAC address table** (MAC → port, per VLAN). The table is also called the **CAM table**.\n2. **Forward / Filter**: it looks up the **destination MAC**.\n   - Known on a **different** port → **forward** only there.\n   - Known on the **same** port it arrived on → **filter** (dropped).\n3. **Flood**: if the destination is **unknown (unknown unicast)**, a **broadcast** or (without IGMP snooping) a **multicast** → it sends it out of **all** ports in the VLAN except the one it came in on.\n\n**Aging**: dynamic entries are removed after **300 s** of inactivity (the default). If a MAC appears on another port (e.g. the laptop was moved), the entry is updated.' },
          { t: 'anim', scene: 'ccna-switch-learning', caption: 'The MAC table fills up step by step: learning, flooding, forwarding.' },
          { t: 'text', md: '### Switching methods\n- **Store-and-forward**: receives the **whole** frame, checks the **FCS**, then forwards. It drops damaged frames. It is the most common method today.\n- **Cut-through**: starts forwarding as soon as it has read the destination MAC. Faster, but errors pass through too.\n- **Fragment-free**: waits for the first 64 bytes (where collisions show up) and then forwards.' },
          { t: 'cli', title: 'Lab: read the MAC table', prompt: 'SW1#',
            steps: [
              { task: 'View the MAC address table: `show mac address-table`.', expect: '^' + SH + 'mac\\s+add(ress)?-?\\s*table$', ans: 'show mac address-table',
                out: '          Mac Address Table\n-------------------------------------------\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n   1    0050.7966.6800    DYNAMIC     Fa0/1\n   1    0050.7966.6801    DYNAMIC     Fa0/2\n  10    0050.7966.6802    DYNAMIC     Fa0/3\n  10    00d0.ba11.2201    DYNAMIC     Gi0/1\n  10    00d0.ba11.3301    DYNAMIC     Gi0/1\nTotal Mac Addresses for this criterion: 5' },
              { task: 'Filter only the entries of port **Gi0/1**: `show mac address-table interface g0/1`.', expect: '^' + SH + 'mac\\s+add(ress)?-?\\s*table\\s+int(erface)?\\s*g(i(g(abit(ethernet)?)?)?)?\\s*0/1$', ans: 'show mac address-table interface g0/1',
                out: 'Vlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n  10    00d0.ba11.2201    DYNAMIC     Gi0/1\n  10    00d0.ba11.3301    DYNAMIC     Gi0/1' },
              { task: 'Check the aging time: `show mac address-table aging-time`.', expect: '^' + SH + 'mac\\s+add(ress)?-?\\s*table\\s+aging(-time)?$', ans: 'show mac address-table aging-time', out: 'Global Aging Time:  300\nVlan    Aging Time\n----    ----------' },
              { task: 'Clear the dynamic entries: `clear mac address-table dynamic`.', expect: '^clear\\s+mac\\s+add(ress)?-?\\s*table\\s+dyn(amic)?$', ans: 'clear mac address-table dynamic' },
            ], done: 'Did you notice that **Gi0/1** has **many** MACs? That means there is **another switch** behind it (an uplink), not a PC.' },
          { t: 'netwatch', tab: 'feed', md: 'In **Packets** look for ARP broadcasts (destination ff:ff:ff:ff:ff:ff): these are the frames your network\'s switches **flood**.' },
          { t: 'exam', md: 'The switch learns from the **source** MAC and forwards based on the **destination** MAC. It **floods** unknown unicast, broadcast and multicast. The MAC table is **per VLAN**. Many MACs on one port = most likely a trunk/uplink to another switch.' },
          { t: 'quiz', q: 'A switch receives a frame whose destination MAC is **not** in its table. What does it do?', opts: ['Drops it', 'Sends an ARP request', 'Floods it out of all ports in the VLAN except the incoming one', 'Sends it to the default gateway'], ok: 2, why: 'Unknown unicast → **flood**. Switches do not ARP: hosts do that.' },
          { t: 'quiz', q: 'Which field of the frame does the switch **learn** from?', opts: ['Destination MAC', 'Source MAC', 'Source IP', 'FCS'], ok: 1, why: 'Learning = **source MAC** + ingress port. The destination is used for forwarding.' },
          { t: 'quiz', q: 'Which switching method checks the FCS **before** forwarding?', opts: ['Cut-through', 'Fragment-free', 'Store-and-forward', 'Flooding'], ok: 2, why: 'Only **store-and-forward** receives the whole frame, so it can check the FCS.' },
        ],
      },
    ],
  };

  ACADEMY.track({ id: 'ccna', order: 1, title: '🎓 CCNA 200-301 (Cisco)', level: 'Beginner → Certification', desc: 'From zero to the Cisco CCNA 200-301 (v1.1) exam: theory, animations, Cisco IOS labs, subnetting and exam-style quizzes.', modules: [M0, M1] });
})();
