# Μορφή μαθημάτων της Ακαδημίας

Κάθε αρχείο `academy/*.js` (εκτός από `engine.js`) φορτώνεται αυτόματα από τη σελίδα. Είναι απλό JavaScript που καλεί:

```js
ACADEMY.scene('arp', { ...scene... });   // προαιρετικό: animation με όνομα, για επαναχρήση
ACADEMY.track({ ...track... });          // μια διαδρομή μαθημάτων
```

Δύο αρχεία μπορούν να καλέσουν `ACADEMY.track` με το **ίδιο `id`**: οι ενότητές τους ενώνονται και ταξινομούνται κατά `order` (αριθμός σε κάθε module). Τα υπόλοιπα πεδία (title, desc…) τα δίνει όποιο αρχείο φορτωθεί πρώτο. Τα tracks ταξινομούνται επίσης κατά `order`.
Τα `id` μαθημάτων πρέπει να είναι μοναδικά σε όλη την εφαρμογή (π.χ. `ccna-1-3`, `iot-2-1`), γιατί σε αυτά αποθηκεύεται η πρόοδος.

## Track

```js
{
  id: 'ccna', order: 1, title: '🎓 CCNA 200-301', level: 'Αρχάριος → Πιστοποίηση', desc: 'Μία πρόταση.',
  modules: [{
    id: 'ccna-1', order: 1, title: 'Θεμελιώδη δικτύων', exam: '1.0 Network Fundamentals (20%)', desc: 'προαιρετικό',
    lessons: [{ id: 'ccna-1-1', title: 'Τι είναι δίκτυο', minutes: 10, goal: 'markdown', blocks: [ ... ] }]
  }]
}
```

## Blocks

| t | πεδία | τι κάνει |
|---|---|---|
| `text` | `md` | Κείμενο. Markdown-lite: `**έντονα**`, `*πλάγια*`, `` `κώδικας` ``, γραμμές `- ` ή `1. ` για λίστες, `### Τίτλος`. Κενή γραμμή = νέα παράγραφος. |
| `tip` / `warn` / `exam` | `md` | Πλαίσιο συμβουλής / προειδοποίησης / «Για την εξέταση». |
| `table` | `head:[..], rows:[[..]]` | Πίνακας (τα κελιά δέχονται inline markdown). |
| `code` | `lang, title, code, explain` | Κώδικας με χρώματα και κουμπί αντιγραφής. `lang`: `cisco`, `cpp` (Arduino/ESP32), `micropython`, `python`, `bash`, `yaml`, `json`, `text`. `explain` = markdown από κάτω (γραμμή-γραμμή εξήγηση). |
| `anim` | `scene, caption` | Animation. `scene` = όνομα από `ACADEMY.scene` ή αντικείμενο scene. |
| `quiz` | `q, opts:[..], ok:index, why` | Ερώτηση πολλαπλής επιλογής (μία σωστή). `why` = εξήγηση που φαίνεται μετά. |
| `cli` | `title, prompt, banner, steps:[{task, expect, ans, out, next, err}], done` | Καθοδηγούμενο lab Cisco IOS. `expect` = regex (string, case-insensitive) για την εντολή του χρήστη, `ans` = η σωστή εντολή (για το 💡), `out` = τι τυπώνει ο «router», `next` = νέο prompt (π.χ. `R1(config)#`). |
| `subnet` | — | Γεννήτρια ασκήσεων subnetting (άπειρες ερωτήσεις). |
| `netwatch` | `tab, md` | Σύνδεσμος σε καρτέλα του NetWatch (`home`, `alerts`, `wifi`, `priv`, `devs`, `hosts`, `apps`, `feed`, `stats`, `pentest`, `rules`, `honey`, `iot`, `sensor`, `mqtt`…). Η πλήρης λίστα είναι το `TABS` στο `tools/check_academy.js`. |

## Scene (animation)

```js
{
  w: 640, h: 260, intro: 'markdown πριν πατήσει ▶', speed: 2600,
  nodes: [{ id:'pc', x:80, y:130, icon:'💻', label:'PC-A\n192.168.1.10', w:64 }],
  links: [['pc','sw'], ['sw','r1','Gi0/1'], ['ap','esp','wifi']],   // 3ο στοιχείο: ετικέτα ή 'wifi' (διακεκομμένη)
  tables: [{ id:'mac', title:'MAC table του SW1', head:['Port','MAC'], rows:[] }],
  steps: [
    { from:'pc', to:'sw', pkt:'ARP?', color:'#ffd23f', say:'Το PC ρωτάει…' },
    { from:'sw', to:['pc2','pc3'], pkt:'ARP?', say:'Broadcast: πάει σε όλους' },  // πίνακας = broadcast
    { from:'pc', via:['sw'], to:'r1', pkt:'IP', say:'…', table:{ mac:[['Fa0/1','aaaa.bbbb.cccc']] } },  // table: νέα κατάσταση πίνακα
    { from:'att', to:'pc', pkt:'ψεύτικο ARP', color:'#ff3b5c', drop:true, mark:{ att:'bad', pc:'hl' } } // drop=κόβεται, mark: ok|bad|hl|info
  ]
}
```

Οι συντεταγμένες είναι μέσα στο `w×h`. Κράτα τα nodes ≥ 90px μεταξύ τους και τις ετικέτες σύντομες (2 γραμμές το πολύ).
