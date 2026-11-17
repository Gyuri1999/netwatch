# NetWatch translations (Greek → English)

The UI and the Academy were written in Greek. English is a second language selected with the
🇬🇧 EN / 🇬🇷 ΕΛ button (stored in `localStorage['nw-lang']`, or `?lang=en` in the URL).

## How it works

| What | Where | How |
|---|---|---|
| UI text (index.html, engine.js, academy.html, demo banner) | `i18n/en-ui.js`, `i18n/en-academy-ui.js` | `i18n.js` watches the DOM and replaces Greek text nodes / `title` / `placeholder` using these dictionaries |
| Text produced by the Python backend (alert types and details, audit checks, IoT findings, Wi‑Fi verdicts…) | `i18n/en-backend.js` | same mechanism in the browser; `i18n.py` uses the same file for macOS/Telegram/ntfy notifications when `lang: en` |
| Alert explanations, verdicts, ports, glossary, tips (`edu.js`) | `i18n/edu-en.js` | `window.NW_EDU_EN = { EDU, VERDICT, … }` with the **same keys**; applied at the end of `edu.js` |
| Academy lessons and flashcards | `academy/en/*.js` | the engine loads `academy/en/` instead of `academy/` (same lesson/card ids → same progress) |

Dictionary file format (must stay valid JSON between the first `{` and the last `}` — `i18n.py` parses it):

```js
I18N.add({
  "exact": {
    "Όλα καλά": "All good"
  },
  "patterns": [
    ["^(\\d+) συσκευές$", "$1 devices"],
    ["^Ο (\\S+) σκανάρει (\\d+) θύρες του (\\S+)\\.$", "$1 is scanning $2 ports on $3."]
  ]
});
```

* Keys are matched after collapsing whitespace and trimming. Patterns are tested against the same normalized text,
  must be anchored (`^…$`) and use only syntax common to JavaScript and Python `re` (groups `( )`, `(?: )`, `\\d`, `\\S`,
  `.+?`, character classes). Replacement uses `$1`…`$9`.
* A text node that is only partly Greek (e.g. `"6 συσκευές"`) needs a pattern, not an exact entry.
* Text split by inline tags (`<b>3</b> συσκευές`) arrives as separate text nodes: translate the fragment (`"συσκευές"`).
* `<code>`, `<pre>`, `<input>`, `<textarea>` and anything with `data-noi18n` are never touched.
* **Never change the Greek source text to make translation easier**, and never translate alert *type* keys inside
  Python/JS logic (`EDU['…']`, MITRE table, playbook `when.type`) — they are identifiers. Only the displayed text changes.

Finding untranslated text: open the app with `?lang=en`, click around, then run `I18N.dump()` in the console.

## Style and glossary

Plain, friendly English for a home user who is not a security expert, matching the Greek tone (short sentences,
"you"). Keep emoji, numbers, IPs, ports, product names and Markdown (`**bold**`, `` `code` ``, lists) exactly.

| Greek | English |
|---|---|
| ειδοποίηση | alert |
| επίθεση / επιθέσεις | attack / attacks |
| συσκευή | device |
| δίκτυο / το δίκτυό σου | network / your network |
| Ακαδημία | Academy |
| μάθημα / ενότητα / διαδρομή | lesson / module / track |
| κάρτες | flashcards |
| κουίζ / διαγώνισμα | quiz / mock exam |
| καναρίνι | canary |
| παγίδα (honeypot) | honeypot |
| φύλακας MQTT | MQTT guard |
| αισθητήρας | sensor |
| μπλόκαρε / μπλοκ | block |
| αναμενόμενο (benign) | expected |
| σοβαρή / μέτρια / χαμηλή | high / medium / low |
| Έλεγχος (καρτέλα 🛡) | Audit |
| εργαστήριο (lab) | lab |
| ζωντανά | live |
| «10λεπτο της ημέρας» / «10′ σήμερα» | "Daily 10 minutes" / "10′ today" |
| σερί | streak |
| Αρχάριος → Πιστοποίηση | Beginner → Certification |
| Αρχάριος → Προχωρημένος | Beginner → Advanced |
