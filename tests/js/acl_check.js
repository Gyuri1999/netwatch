// Έλεγχος του ACL tester (acl.js): parser, first-match, implicit deny, established, σκιασμένες γραμμές.
const A = require('../../acl.js'); const bad = []; let n = 0;
const eq = (a, b, m) => { n++; if (JSON.stringify(a) !== JSON.stringify(b)) bad.push(`${m}: ${JSON.stringify(a)} ≠ ${JSON.stringify(b)}`); };
const pk = (proto, src, dst, sport = 0, dport = 0, est = false) => ({ proto, src: A.ip2n(src), dst: A.ip2n(dst), sport, dport, est });
let P = A.parse(`ip access-list extended IOT-IN
 10 permit udp 192.168.30.0 0.0.0.255 host 192.168.30.1 eq domain
 20 deny ip 192.168.30.0 0.0.0.255 192.168.1.0 0.0.0.255
 permit ip 192.168.30.0 0.0.0.255 any
interface g0/0
 ip access-group IOT-IN in`);
eq([P.errors.length, P.acls.length, P.acls[0].aces.length, P.acls[0].type], [0, 1, 3, 'extended'], 'named parse');
const io = P.acls[0];
let r = A.evaluate(io, pk('tcp', '192.168.30.12', '192.168.1.10', 50000, 445)); eq([r.action, r.hit], ['deny', 1], 'iot→lan deny');
r = A.evaluate(io, pk('udp', '192.168.30.12', '192.168.30.1', 5353, 53)); eq([r.action, r.hit], ['permit', 0], 'dns permit');
r = A.evaluate(io, pk('tcp', '192.168.30.12', '1.1.1.1', 50000, 443)); eq([r.action, r.hit], ['permit', 2], 'internet permit');
r = A.evaluate(io, pk('tcp', '10.9.9.9', '1.1.1.1', 1, 80)); eq([r.action, r.hit, r.implicit], ['deny', -1, true], 'implicit deny');
eq(A.analyze(io).issues.length, 0, 'no shadowing');
// κλασικό λάθος σειράς
P = A.parse(`access-list 110 permit ip 10.0.0.0 0.0.0.255 any
access-list 110 deny tcp host 10.0.0.66 any eq telnet
access-list 110 deny tcp 10.0.0.0 0.0.0.255 any eq 23
access-list 110 permit tcp 10.0.0.0 0.0.0.255 any eq www`);
const b = P.acls[0];
eq(A.evaluate(b, pk('tcp', '10.0.0.66', '8.8.8.8', 4000, 23)).hit, 0, 'telnet hits line 1');
eq(A.analyze(b).issues.map(x => [x.j, x.i, x.kind]), [[1, 0, 'shadowed'], [2, 0, 'shadowed'], [3, 0, 'redundant']], 'shadow analysis');
// standard + host + wildcard
P = A.parse(`access-list 10 deny host 192.168.1.66
access-list 10 permit 192.168.1.0 0.0.0.255`);
const s = P.acls[0];
eq([s.type, A.evaluate(s, pk('ip', '192.168.1.66', '10.0.0.1')).action, A.evaluate(s, pk('ip', '192.168.1.7', '10.0.0.1')).action, A.evaluate(s, pk('ip', '192.168.2.7', '10.0.0.1')).action], ['standard', 'deny', 'permit', 'deny'], 'standard');
// ports: range, gt, neq, established, icmp
P = A.parse(`access-list 120 permit tcp any any range 8000 8080
access-list 120 permit tcp any any gt 60000
access-list 120 permit tcp any eq 443 any established
access-list 120 permit udp any any neq 53
access-list 120 permit icmp any any echo-reply`);
const p = P.acls[0];
eq([8000, 8080, 8081, 60001, 60000].map(d => A.evaluate(p, pk('tcp', '1.1.1.1', '2.2.2.2', 1, d)).action), ['permit', 'permit', 'deny', 'permit', 'deny'], 'tcp ports');
eq([A.evaluate(p, pk('tcp', '1.1.1.1', '2.2.2.2', 443, 5555, true)).hit, A.evaluate(p, pk('tcp', '1.1.1.1', '2.2.2.2', 443, 5555, false)).hit], [2, -1], 'established');
eq([A.evaluate(p, pk('udp', '1.1.1.1', '2.2.2.2', 1, 53)).action, A.evaluate(p, pk('udp', '1.1.1.1', '2.2.2.2', 1, 54)).action], ['deny', 'permit'], 'neq');
// σφάλματα & προειδοποιήσεις
P = A.parse(`access-list 300 permit ip any any
access-list 101 allow ip any any
access-list 101 permit tcp 192.168.1.5 0.0.0.255 any eq 22
access-list 101 permit ip 10.0.0.0 255.255.255.0 any
access-list 101 permit foo any any
access-list 101 permit tcp any any eq 99999`);
eq(P.errors.map(e => e.line), [1, 2, 5, 6], 'errors');
const w = P.acls[0].aces.map(a => a.warn.length);
eq([w, A.n2ip(P.acls[0].aces[0].src.addr)], [[1, 1], '192.168.1.0'], 'warnings + normalize');
// μόνο deny → προειδοποίηση
P = A.parse('access-list 5 deny host 1.2.3.4'); eq(/τα πάντα|everything/.test(A.analyze(P.acls[0]).tips.join()), true, 'only-deny tip');
console.log(bad.length ? bad.join('\n') : `OK ${n} checks`); process.exit(bad.length ? 1 : 0);
